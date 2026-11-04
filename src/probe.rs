use crate::{
    client::outbound_ip,
    config::{ProbeConfig, ProbeMode, ProbeTarget},
    state,
};
use anyhow::{bail, Context, Result};
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr},
    process::Stdio,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{net::TcpSocket, process::Command, task::JoinSet};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct ProbeResult {
    pub checked_at: u64,
    pub reachable: bool,
    pub detail: String,
}

// Check local link/address before sending any probes or credentials.
pub fn link(interface: Option<&str>) -> Result<Ipv4Addr> {
    if let Some(name) = interface {
        let mut present = false;
        let mut connected = false;
        let mut addresses = Vec::new();
        for entry in getifaddrs().context("无法检查网卡")? {
            if entry.interface_name != name {
                continue;
            }
            present = true;
            connected |= entry
                .flags
                .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING);
            if let Some(ip) = entry
                .address
                .and_then(|a| a.as_sockaddr_in().map(|v| v.ip()))
            {
                if !ip.is_unspecified() {
                    addresses.push(ip);
                }
            }
        }
        if !present {
            bail!("指定网卡 {name} 不存在");
        }
        if !connected {
            bail!("指定网卡 {name} 未连接");
        }
        let first = *addresses.first().context("指定网卡没有可用 IPv4")?;
        // A campus-only route can still work without a public default route.
        // Linux may also select another interface's source for a loopback route.
        let routed = outbound_ip(SocketAddr::from(([223, 5, 5, 5], 80)), interface).ok();
        return Ok(routed.filter(|ip| addresses.contains(ip)).unwrap_or(first));
    }
    outbound_ip(SocketAddr::from(([223, 5, 5, 5], 80)), interface)
        .context("指定出口没有可用 IPv4 路由")
}

async fn target(config: &ProbeConfig, interface: Option<&str>, target: &ProbeTarget) -> Result<()> {
    let seconds = if target.mode == ProbeMode::Https {
        config.https_timeout_secs
    } else {
        config.timeout_secs
    };
    tokio::time::timeout(Duration::from_secs(seconds), async {
        if target.mode == ProbeMode::Icmp {
            return icmp(config, interface, &target.address).await;
        }
        let addresses: Vec<_> = tokio::net::lookup_host((target.address.as_str(), target.port()))
            .await
            .context("DNS 解析失败")?
            .filter(SocketAddr::is_ipv4)
            .collect();
        if addresses.is_empty() {
            bail!("目标没有可用 IPv4 地址");
        }
        let mut last_error = None;
        for address in addresses {
            let result: Result<()> = async {
                let socket = TcpSocket::new_v4()?;
                if let Some(interface) = interface {
                    socket2::SockRef::from(&socket)
                        .bind_device(Some(interface.as_bytes()))
                        .context("无法绑定指定网卡")?;
                }
                let stream = socket.connect(address).await.context("TCP 连接失败")?;
                if target.mode == ProbeMode::Https {
                    static TLS: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
                    let config = TLS.get_or_init(|| {
                        let roots = rustls::RootCertStore::from_iter(
                            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                        );
                        Arc::new(
                            rustls::ClientConfig::builder()
                                .with_root_certificates(roots)
                                .with_no_client_auth(),
                        )
                    });
                    let name =
                        ServerName::try_from(target.address.clone()).context("HTTPS 域名无效")?;
                    TlsConnector::from(config.clone())
                        .connect(name, stream)
                        .await
                        .context("TLS 握手或证书校验失败")?;
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap())
    })
    .await
    .context("目标探测超时（含解析、连接与握手）")?
}

async fn icmp(config: &ProbeConfig, interface: Option<&str>, address: &str) -> Result<()> {
    let mut command = Command::new("/usr/bin/ping");
    command
        .args(["-4", "-n", "-c", "1", "-W"])
        .arg(config.timeout_secs.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(interface) = interface {
        command.args(["-I", interface]);
    }
    let status = command
        .arg("--")
        .arg(address)
        .status()
        .await
        .context("无法执行 /usr/bin/ping，请安装 iputils-ping")?;
    if !status.success() {
        bail!("ICMP 无响应或网卡不可用");
    }
    Ok(())
}

pub async fn check(config: &ProbeConfig, interface: Option<&str>) -> ProbeResult {
    let mut errors = match target(config, interface, &config.primary).await {
        Ok(()) => return success(&config.primary, false),
        Err(error) => vec![format!("{}: {error:#}", config.primary.label())],
    };
    let mut backups = JoinSet::new();
    for entry in config.backups.iter().cloned() {
        let config = config.clone();
        let interface = interface.map(str::to_owned);
        backups.spawn(async move {
            let result = target(&config, interface.as_deref(), &entry).await;
            (entry, result)
        });
    }
    while let Some(result) = backups.join_next().await {
        match result {
            Ok((target, Ok(()))) => {
                backups.abort_all();
                while backups.join_next().await.is_some() {}
                return success(&target, true);
            }
            Ok((target, Err(error))) => errors.push(format!("{}: {error:#}", target.label())),
            Err(error) => errors.push(format!("备用探测任务异常：{error}")),
        }
    }
    ProbeResult {
        checked_at: state::now(),
        reachable: false,
        detail: errors.join("；"),
    }
}

fn success(target: &ProbeTarget, backup: bool) -> ProbeResult {
    ProbeResult {
        checked_at: state::now(),
        reachable: true,
        detail: format!(
            "{} {} 可达",
            if backup { "备用目标" } else { "主目标" },
            target.label()
        ),
    }
}

use crate::{
    config::{Config, ProbeConfig, ProbeMode},
    state,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr},
    process::Stdio,
    time::Duration,
};
use tokio::{net::TcpSocket, process::Command, task::JoinSet};

#[derive(Deserialize, Serialize)]
pub struct ProbeResult {
    pub checked_at: u64,
    pub reachable: bool,
    pub detail: String,
}

// No hostname lookup: a DNS outage must not prevent connectivity checks.
async fn target(config: &ProbeConfig, interface: Option<&str>, ip: Ipv4Addr) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(config.timeout_secs), async {
        match config.mode {
            ProbeMode::Tcp => {
                let socket = TcpSocket::new_v4()?;
                if let Some(interface) = interface {
                    socket2::SockRef::from(&socket)
                        .bind_device(Some(interface.as_bytes()))
                        .context("无法绑定指定网卡")?;
                }
                socket
                    .connect(SocketAddr::from((ip, config.tcp_port)))
                    .await?;
            }
            ProbeMode::Icmp => {
                icmp(config, interface, ip).await?;
            }
        }
        Ok(())
    })
    .await
    .context("探测超时")?
}

async fn icmp(config: &ProbeConfig, interface: Option<&str>, ip: Ipv4Addr) -> Result<()> {
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
        .arg(ip.to_string())
        .status()
        .await
        .context("无法执行 /usr/bin/ping，请安装 iputils-ping")?;
    if !status.success() {
        bail!("ICMP 无响应或网卡不可用");
    }
    Ok(())
}

pub async fn check(config: &Config) -> ProbeResult {
    let primary = config.probe.primary;
    let mut errors = match target(&config.probe, config.interface.as_deref(), primary).await {
        Ok(()) => return success(primary, false),
        Err(error) => vec![format!("{primary}: {error:#}")],
    };
    let mut backups = JoinSet::new();
    for ip in config.probe.backups.iter().copied() {
        let probe = config.probe.clone();
        let interface = config.interface.clone();
        backups.spawn(async move { (ip, target(&probe, interface.as_deref(), ip).await) });
    }
    while let Some(result) = backups.join_next().await {
        match result {
            Ok((ip, Ok(()))) => {
                // Abort and reap the other probes, including any ping subprocesses.
                backups.abort_all();
                while backups.join_next().await.is_some() {}
                return success(ip, true);
            }
            Ok((ip, Err(error))) => errors.push(format!("{ip}: {error:#}")),
            Err(error) => errors.push(format!("备用探测任务异常：{error}")),
        }
    }
    ProbeResult {
        checked_at: state::now(),
        reachable: false,
        detail: errors.join("；"),
    }
}

fn success(ip: Ipv4Addr, backup: bool) -> ProbeResult {
    ProbeResult {
        checked_at: state::now(),
        reachable: true,
        detail: format!("{} {ip} 可达", if backup { "备用目标" } else { "主目标" }),
    }
}

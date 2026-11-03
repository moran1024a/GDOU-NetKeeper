use crate::{
    config::{Config, ProbeConfig, ProbeMode},
    state,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{net::TcpSocket, process::Command, task::JoinSet};

#[derive(Debug, Deserialize, Serialize)]
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
                icmp(config, interface, ip, Path::new("/usr/bin/ping")).await?;
            }
        }
        Ok(())
    })
    .await
    .context("探测超时")?
}

async fn icmp(
    config: &ProbeConfig,
    interface: Option<&str>,
    ip: Ipv4Addr,
    program: &Path,
) -> Result<()> {
    let mut command = Command::new(program);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_an_icmp_probe_terminates_its_child() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("ping");
        std::fs::write(&executable, "#!/usr/bin/python3\nimport os, pathlib, time\npathlib.Path(__file__).with_suffix('.pid').write_text(str(os.getpid()))\ntime.sleep(30)\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pid_file = executable.with_extension("pid");
        let task = tokio::spawn(async move {
            icmp(
                &ProbeConfig::default(),
                None,
                Ipv4Addr::LOCALHOST,
                &executable,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !pid_file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid = std::fs::read_to_string(pid_file).unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            while Path::new(&format!("/proc/{pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("ping process left running after cancellation");
    }

    #[tokio::test]
    async fn tcp_primary_fallback_and_interface_binding() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.probe.mode = ProbeMode::Tcp;
        config.probe.tcp_port = listener.local_addr().unwrap().port();
        config.probe.primary = Ipv4Addr::LOCALHOST;
        config.probe.backups = vec![];
        config.interface = Some("lo".into());
        assert!(check(&config).await.reachable);
        config.probe.primary = Ipv4Addr::new(127, 0, 0, 2);
        assert!(!check(&config).await.reachable);
        config.probe.backups = vec![Ipv4Addr::LOCALHOST];
        let result = check(&config).await;
        assert!(result.reachable && result.detail.contains("备用"));
        config.interface = Some("missing-test0".into());
        assert!(!check(&config).await.reachable);
    }

    #[tokio::test]
    async fn icmp_loopback_and_invalid_interface() {
        let mut config = Config::default();
        config.probe.primary = Ipv4Addr::LOCALHOST;
        config.probe.backups.clear();
        config.interface = Some("lo".into());
        assert!(check(&config).await.reachable);
        config.interface = Some("missing-test0".into());
        assert!(!check(&config).await.reachable);
    }
}

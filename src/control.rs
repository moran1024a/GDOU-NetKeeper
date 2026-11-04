use crate::{
    config::{AuthMode, Config, CONFIG_PATH},
    daemon::START_TIMEOUT,
    session::Session,
    state::{self, Phase, State, STATE_DIR},
};
use anyhow::{bail, Context, Result};
use std::{future::Future, path::Path, time::Duration};
use tokio::process::Command;

const UNIT: &str = "netkeeper.service";

pub struct Controller;

#[derive(Default)]
pub struct Service {
    pub active: String,
    pub pid: u32,
    pub exec_pid: u32,
    pub text: String,
    pub loaded: String,
    pub state: Option<State>,
}

impl Service {
    pub fn running(&self) -> bool {
        matches!(self.active.as_str(), "active" | "activating" | "reloading")
    }
}

impl Controller {
    pub async fn logout(&self) -> Result<&'static str> {
        let snapshot = Session::read();
        self.stop().await.context("停止服务失败，未发送注销请求")?;
        let snapshot = snapshot.context("服务已停止，无法确认原会话，未发送注销请求")?;
        // Stop may finish an in-flight state update. The persistent record survives it.
        let snapshot = Session::read()?.or(snapshot);
        let mut config = match &snapshot {
            Some(record) => record.config(),
            None => Config::load(Path::new(CONFIG_PATH))
                .context("服务已停止；没有会话记录且配置不可用")?,
        };
        // An already-online takeover may not know its AC. Explicit manual input
        // may fill missing parameters, but must not replace the recorded outlet/account.
        if let Some(record) = snapshot.as_ref().filter(|s| s.ac_id.is_none()) {
            if let Ok(manual) = Config::load(Path::new(CONFIG_PATH)) {
                if manual.auth_mode == AuthMode::Manual
                    && manual.interface == record.interface
                    && manual.username == record.username
                    && (record.portal_url.is_empty() || manual.portal_url == record.portal_url)
                {
                    config.portal_url = manual.portal_url;
                    config.ac_id = manual.ac_id;
                }
            }
        }
        if snapshot.is_none() && config.auth_mode == AuthMode::Auto {
            config.ac_id = 0;
        }
        if config.portal_url.is_empty() {
            bail!("服务已停止；当前会话 Portal 尚未确认，未发送注销请求，请手动确认当前认证参数");
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            let client = crate::client::SrunClient::new(&config).await?;
            if snapshot.as_ref().is_some_and(|s| s.local_ip != client.ip) {
                bail!("出口 IP 与原会话记录不同，无法确认原登录，未发送注销请求");
            }
            let message = client.logout().await?;
            Session::clear()?;
            Ok(message)
        })
        .await
        .context("服务已停止，但注销操作超时，无法确认注销结果")?
        .context("服务已停止，不会自动重连")
    }

    async fn command(&self, arguments: &[&str]) -> Result<String> {
        let mut command = Command::new("/usr/bin/systemctl");
        command.arg("--system").args(arguments).kill_on_drop(true);
        let result = tokio::time::timeout(Duration::from_secs(8), command.output())
            .await
            .context("systemd 管理请求超时")?
            .context("无法调用 systemctl")?;
        if !result.status.success() {
            bail!(
                "systemd 操作失败：{}",
                String::from_utf8_lossy(&result.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&result.stdout).into_owned())
    }

    pub async fn inspect(&self) -> Result<Service> {
        let raw = self
            .command(&[
                "show",
                UNIT,
                "--property=LoadState,ActiveState,MainPID,ExecMainPID,StatusText",
            ])
            .await?;
        let mut service = Service::default();
        for line in raw.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "LoadState" => service.loaded = value.into(),
                    "ActiveState" => service.active = value.into(),
                    "MainPID" => service.pid = value.parse().unwrap_or(0),
                    "ExecMainPID" => service.exec_pid = value.parse().unwrap_or(0),
                    "StatusText" => service.text = value.into(),
                    _ => {}
                }
            }
        }
        if let Ok(state) = serde_json::from_str::<State>(&service.text) {
            service.text = state.detail.clone();
            service.state = Some(state);
        }
        Ok(service)
    }

    pub async fn status(&self) -> Result<String> {
        let service = self.inspect().await?;
        let label = match service.active.as_str() {
            "active" => "运行中",
            "activating" => "正在启动",
            "deactivating" => "正在停止",
            "failed" => "启动失败或进程异常",
            _ => "已停止",
        };
        if service.loaded == "not-found" {
            return Ok("服务尚未安装，请先安装 .deb 包".into());
        }
        let mut text = format!("服务：{label}\n进程：{}", service.pid);
        let snapshot = State::read(Path::new(STATE_DIR));
        if let Some(state) = snapshot.as_ref().or(service.state.as_ref()) {
            text.push_str(&format!(
                "\n网卡：{}\n最近记录（{} 秒前）：{}",
                state.interface.as_deref().unwrap_or("跟随系统路由"),
                state::now().saturating_sub(state.checked_at),
                state.detail
            ));
            if let Some(portal) = &state.portal_url {
                text.push_str(&format!(
                    "\n实际 Portal：{portal}\n实际 ac_id：{}",
                    state
                        .ac_id
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "待确认".into())
                ));
            }
            if service.running() && state.pid != service.pid {
                text.push_str("\n当前进程尚未更新状态，上述为历史记录");
            }
            if let Some(probe) = &state.probe {
                text.push_str(&format!(
                    "\n公网探测（{} 秒前）：{}\n连续失败：{} 轮",
                    state::now().saturating_sub(probe.checked_at),
                    probe.detail,
                    state.probe_failures
                ));
            }
            if let Some(probe) = &state.campus_probe {
                text.push_str(&format!(
                    "\n内网探测（{} 秒前）：{}\n内网连续失败：{} 轮",
                    state::now().saturating_sub(probe.checked_at),
                    probe.detail,
                    state.campus_failures
                ));
            }
            text.push_str(&format!("\n恢复尝试：{} 次", state.recovery_attempts));
            if service.running() && state.pid == service.pid {
                if let Some(at) = state.next_retry_at {
                    text.push_str(&format!(
                        "\n下次重试：约 {} 秒后",
                        at.saturating_sub(state::now())
                    ));
                }
            }
        } else if !service.text.is_empty() {
            text.push_str(&format!("\n最近结果：{}", service.text));
        }
        if !service.running() {
            text.push_str("\n当前联网状态未检测");
        }
        Ok(text)
    }

    pub async fn stop(&self) -> Result<()> {
        let service = self.inspect().await?;
        if service.loaded == "not-found" {
            return Ok(());
        }
        self.command(&["stop", UNIT]).await?;
        let after = self.inspect().await?;
        if after.running() || after.active == "deactivating" || after.pid != 0 {
            bail!("服务尚未完全停止");
        }
        Ok(())
    }

    pub async fn start(
        &self,
        cancel: impl Future<Output = ()>,
        mut progress: impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        let before = self.inspect().await?;
        if before.loaded != "loaded" {
            bail!("服务尚未安装或 unit 无效，请先安装 .deb 包");
        }
        let owned = !before.running();
        let baseline = State::read(Path::new(STATE_DIR));
        let refresh = before.active == "active";
        let mut start_requested = false;
        let waiting = async {
            if owned {
                if before.active == "failed" {
                    self.command(&["reset-failed", UNIT]).await?;
                }
                // systemd may accept the job even if systemctl later fails or times out.
                start_requested = true;
                self.command(&["--no-block", "start", UNIT]).await?;
            } else if refresh {
                self.command(&["kill", "--signal=SIGUSR1", "--kill-whom=main", UNIT])
                    .await?;
            }
            let mut previous = String::new();
            let mut seen_running = before.running();
            loop {
                let service = self.inspect().await?;
                let state = State::read(Path::new(STATE_DIR));
                let fresh = state.as_ref().is_some_and(|s| {
                    s.pid == service.pid
                        && (!refresh
                            || baseline.as_ref().is_none_or(|old| {
                                old.pid != s.pid || s.generation > old.generation
                            }))
                });
                if service.active == "active"
                    && fresh
                    && state
                        .as_ref()
                        .is_some_and(|s| matches!(s.phase, Phase::Online | Phase::Degraded))
                {
                    return Ok(());
                }
                if refresh && fresh {
                    if let Some(state) = state.as_ref().filter(|s| {
                        matches!(s.phase, Phase::Retrying | Phase::Paused | Phase::Waiting)
                    }) {
                        bail!("在线确认失败：{}；原有服务仍在运行", state.detail);
                    }
                }
                if service.active == "failed" {
                    let detail = state
                        .filter(|s| s.phase == Phase::Failed && s.pid == service.exec_pid)
                        .map(|s| s.detail)
                        .unwrap_or_else(|| {
                            if !service.text.is_empty() {
                                service.text.clone()
                            } else {
                                "服务启动失败，请查看 journalctl -u netkeeper".into()
                            }
                        });
                    bail!("{detail}");
                }
                if seen_running && service.active == "inactive" {
                    bail!("服务已停止，启动未完成");
                }
                seen_running |= service.running();
                let text = if service.text.is_empty() {
                    "等待首次确认在线".into()
                } else {
                    service.text
                };
                if text != previous {
                    progress(&text)?;
                    previous = text;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let result = tokio::select! {
            biased;
            _ = cancel => Err(anyhow::anyhow!("启动已取消")),
            result = tokio::time::timeout(START_TIMEOUT, waiting) => result.unwrap_or_else(|_| Err(anyhow::anyhow!("等待在线超时，启动未成功"))),
        };
        if result.is_err() && start_requested {
            self.stop()
                .await
                .context("启动失败后停止服务失败，请执行 netkeeper stop")?;
        }
        result
    }
}

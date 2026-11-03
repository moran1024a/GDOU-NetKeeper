use crate::{
    daemon::START_TIMEOUT,
    state::{self, Phase, State, STATE_DIR},
};
use anyhow::{bail, Context, Result};
use std::{future::Future, path::PathBuf, time::Duration};
use tokio::process::Command;

const UNIT: &str = "netkeeper.service";

pub struct Controller {
    pub executable: PathBuf,
    pub state_dir: PathBuf,
    pub timeout: Duration,
}

impl Default for Controller {
    fn default() -> Self {
        Self {
            executable: "/usr/bin/systemctl".into(),
            state_dir: STATE_DIR.into(),
            timeout: START_TIMEOUT,
        }
    }
}

#[derive(Default)]
pub struct Service {
    pub active: String,
    pub sub: String,
    pub pid: u32,
    pub exec_pid: u32,
    pub text: String,
    pub loaded: String,
}

impl Service {
    pub fn running(&self) -> bool {
        matches!(self.active.as_str(), "active" | "activating" | "reloading")
    }
}

impl Controller {
    async fn command(&self, arguments: &[&str]) -> Result<String> {
        let mut command = Command::new(&self.executable);
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
                "--property=LoadState,ActiveState,SubState,MainPID,ExecMainPID,StatusText",
            ])
            .await?;
        let mut service = Service::default();
        for line in raw.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "LoadState" => service.loaded = value.into(),
                    "ActiveState" => service.active = value.into(),
                    "SubState" => service.sub = value.into(),
                    "MainPID" => service.pid = value.parse().unwrap_or(0),
                    "ExecMainPID" => service.exec_pid = value.parse().unwrap_or(0),
                    "StatusText" => service.text = value.into(),
                    _ => {}
                }
            }
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
        if let Some(state) = State::read(&self.state_dir) {
            text.push_str(&format!(
                "\n网卡：{}\n最近记录（{} 秒前）：{}",
                state.interface.as_deref().unwrap_or("跟随系统路由"),
                state::now().saturating_sub(state.checked_at),
                state.detail
            ));
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
        let baseline = State::read(&self.state_dir);
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
                let state = State::read(&self.state_dir);
                let fresh = state.as_ref().is_some_and(|s| {
                    s.pid == service.pid
                        && (!refresh
                            || baseline.as_ref().is_none_or(|old| {
                                old.pid != s.pid || s.generation > old.generation
                            }))
                });
                if service.active == "active"
                    && fresh
                    && state.as_ref().is_some_and(|s| s.phase == Phase::Online)
                {
                    return Ok(());
                }
                if refresh && fresh {
                    if let Some(state) = state
                        .as_ref()
                        .filter(|s| matches!(s.phase, Phase::Retrying | Phase::Paused))
                    {
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
            result = tokio::time::timeout(self.timeout, waiting) => result.unwrap_or_else(|_| Err(anyhow::anyhow!("等待在线超时，启动未成功"))),
        };
        if result.is_err() && start_requested {
            self.stop()
                .await
                .context("启动失败后停止服务失败，请执行 netkeeper stop")?;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(mode: &str) -> (tempfile::TempDir, Controller) {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("systemctl");
        let source = r#"#!/usr/bin/python3
import json, pathlib, sys, time
root = pathlib.Path(__file__).parent
args = sys.argv[1:]
with (root / 'calls').open('a') as file: file.write(' '.join(args) + '\n')
stage = root / 'stage'
value = stage.read_text() if stage.exists() else 'inactive'
mode = (root / 'mode').read_text()
if 'start' in args:
    stage.write_text('activating')
    if mode in ['start_error', 'start_timeout']:
        stage.write_text('active')
        if mode == 'start_error':
            print('start request failed after acceptance', file=sys.stderr)
            sys.exit(1)
        time.sleep(12)
elif 'stop' in args:
    stage.write_text('inactive')
elif 'kill' in args:
    if mode == 'refresh_error':
        print('refresh request failed', file=sys.stderr)
        sys.exit(1)
    path = root / 'status.json'
    if path.exists():
        state = json.loads(path.read_text())
        if mode != 'probe_only':
            state['generation'] = state.get('generation', 0) + 1
        if mode == 'refresh_failed':
            state.update(phase='retrying', detail='password_error')
        path.write_text(json.dumps(state))
elif 'show' in args:
    if value == 'activating':
        value = {'ready': 'active', 'stale': 'active', 'failed': 'failed'}.get(mode, 'activating')
        stage.write_text(value)
        if value == 'active':
            (root / 'status.json').write_text(json.dumps(dict(pid=999 if mode=='stale' else 123, phase='online', interface='test0', checked_at=int(time.time()), detail='已确认在线')))
    print('LoadState=loaded\nActiveState=' + value + '\nSubState=' + value)
    print('MainPID=' + ('123' if value in ['active','activating'] else '0'))
    print('StatusText=' + ('password_error' if value=='failed' else '等待认证'))
"#;
        std::fs::write(&script, source).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(directory.path().join("mode"), mode).unwrap();
        let controller = Controller {
            executable: script,
            state_dir: directory.path().into(),
            timeout: Duration::from_millis(500),
        };
        (directory, controller)
    }

    #[tokio::test]
    async fn waits_for_readiness_and_repeated_start_does_not_start_twice() {
        let (directory, controller) = fixture("ready");
        for _ in 0..2 {
            controller
                .start(std::future::pending(), |_| Ok(()))
                .await
                .unwrap();
        }
        let calls = std::fs::read_to_string(directory.path().join("calls")).unwrap();
        assert_eq!(
            calls
                .lines()
                .filter(|line| line.contains("--no-block start"))
                .count(),
            1
        );
        assert!(controller.status().await.unwrap().contains("已确认在线"));
        assert!(calls.contains("--signal=SIGUSR1"));
        controller.stop().await.unwrap();
        assert!(controller
            .status()
            .await
            .unwrap()
            .contains("当前联网状态未检测"));
    }

    #[tokio::test]
    async fn repeated_start_requires_a_fresh_online_result() {
        let (directory, controller) = fixture("ready");
        controller
            .start(std::future::pending(), |_| Ok(()))
            .await
            .unwrap();
        std::fs::write(directory.path().join("mode"), "refresh_failed").unwrap();
        let error = controller
            .start(std::future::pending(), |_| Ok(()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("password_error"));
        assert!(controller.inspect().await.unwrap().running());
    }

    #[tokio::test]
    async fn probe_updates_cannot_satisfy_repeated_start() {
        let (directory, controller) = fixture("ready");
        controller
            .start(std::future::pending(), |_| Ok(()))
            .await
            .unwrap();
        std::fs::write(directory.path().join("mode"), "probe_only").unwrap();
        assert!(controller
            .start(std::future::pending(), |_| Ok(()))
            .await
            .unwrap_err()
            .to_string()
            .contains("超时"));
        assert!(controller.inspect().await.unwrap().running());
    }

    #[tokio::test]
    async fn failed_timed_out_and_stale_starts_are_stopped() {
        for mode in ["failed", "waiting", "stale"] {
            let (directory, controller) = fixture(mode);
            let error = controller
                .start(std::future::pending(), |_| Ok(()))
                .await
                .unwrap_err();
            if mode == "failed" {
                assert!(error.to_string().contains("password_error"));
            }
            let calls = std::fs::read_to_string(directory.path().join("calls")).unwrap_or_else(
                |read_error| panic!("mode={mode}; start error={error:#}; call log={read_error}"),
            );
            assert!(calls.contains("--system stop netkeeper.service"));
            assert!(!controller.inspect().await.unwrap().running());
        }
    }

    #[tokio::test]
    async fn cancellation_stops_only_the_process_started_by_this_request() {
        let (directory, controller) = fixture("waiting");
        assert!(controller
            .start(tokio::time::sleep(Duration::from_millis(40)), |_| Ok(()))
            .await
            .is_err());
        assert!(!controller.inspect().await.unwrap().running());
        std::fs::write(directory.path().join("stage"), "active").unwrap();
        assert!(controller
            .start(std::future::ready(()), |_| Ok(()))
            .await
            .is_err());
        assert!(controller.inspect().await.unwrap().running());
    }

    #[tokio::test]
    async fn accepted_start_request_errors_and_command_timeouts_are_stopped() {
        for (mode, message) in [
            ("start_error", "start request failed after acceptance"),
            ("start_timeout", "systemd 管理请求超时"),
        ] {
            let (directory, mut controller) = fixture(mode);
            controller.timeout = Duration::from_secs(10);
            let error = controller
                .start(std::future::pending(), |_| Ok(()))
                .await
                .unwrap_err();
            assert!(error.to_string().contains(message), "{mode}: {error:#}");
            let calls = std::fs::read_to_string(directory.path().join("calls")).unwrap();
            assert!(calls.contains("--system stop netkeeper.service"));
            assert!(!controller.inspect().await.unwrap().running());
        }
    }

    #[tokio::test]
    async fn cancellation_and_overall_timeout_during_start_request_are_stopped() {
        for cancelled in [true, false] {
            let (directory, controller) = fixture("start_timeout");
            let cancel = async {
                if !cancelled {
                    std::future::pending::<()>().await;
                }
                while std::fs::read_to_string(directory.path().join("stage")).unwrap_or_default()
                    != "active"
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            let error = controller.start(cancel, |_| Ok(())).await.unwrap_err();
            assert!(error.to_string().contains(if cancelled {
                "启动已取消"
            } else {
                "等待在线超时"
            }));
            let calls = std::fs::read_to_string(directory.path().join("calls")).unwrap();
            assert!(calls.contains("--system stop netkeeper.service"));
            assert!(!controller.inspect().await.unwrap().running());
        }
    }

    #[tokio::test]
    async fn cancellation_before_start_request_does_not_start_or_stop_service() {
        let (directory, controller) = fixture("ready");
        let error = controller
            .start(std::future::ready(()), |_| Ok(()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("启动已取消"));
        let calls = std::fs::read_to_string(directory.path().join("calls")).unwrap();
        assert!(!calls.contains(" start "));
        assert!(!calls.contains(" stop "));
    }

    #[tokio::test]
    async fn refresh_request_error_preserves_existing_service() {
        let (directory, controller) = fixture("ready");
        controller
            .start(std::future::pending(), |_| Ok(()))
            .await
            .unwrap();
        std::fs::write(directory.path().join("mode"), "refresh_error").unwrap();
        let error = controller
            .start(std::future::pending(), |_| Ok(()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("refresh request failed"));
        assert!(controller.inspect().await.unwrap().running());
        let calls = std::fs::read_to_string(directory.path().join("calls")).unwrap();
        assert!(!calls.contains(" stop "));
    }

    #[tokio::test]
    async fn status_reads_full_snapshot_and_handles_removed_runtime_directory() {
        let (directory, mut controller) = fixture("ready");
        std::fs::write(directory.path().join("stage"), "active").unwrap();
        controller.state_dir = directory.path().join("runtime");
        std::fs::create_dir(&controller.state_dir).unwrap();
        let mut state = State::new(Some("test0".into()));
        state.pid = 123;
        state.probe = Some(crate::probe::ProbeResult {
            checked_at: state::now(),
            reachable: false,
            detail: "全部目标不可达".into(),
        });
        state.probe_failures = 3;
        state.recovery_attempts = 2;
        state.next_retry_at = Some(state::now() + 30);
        state
            .update(&controller.state_dir, Phase::Retrying, "等待恢复")
            .unwrap();
        assert_eq!(
            std::fs::metadata(controller.state_dir.join("status.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        let status = controller.status().await.unwrap();
        for expected in [
            "网卡：test0",
            "等待恢复",
            "全部目标不可达",
            "连续失败：3 轮",
            "恢复尝试：2 次",
            "下次重试：约",
        ] {
            assert!(status.contains(expected), "{status}");
        }
        controller.stop().await.unwrap();
        std::fs::remove_dir_all(&controller.state_dir).unwrap();
        let stopped = controller.status().await.unwrap();
        assert!(stopped.contains("服务：已停止"));
        assert!(stopped.contains("当前联网状态未检测"));
        assert!(!stopped.contains("下次重试"));
    }
}

use crate::{
    client::CredentialRejected,
    config::Config,
    probe,
    session::Authentication,
    state::{Phase, State},
};
use anyhow::{Context, Result};
use std::{
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
    path::Path,
    time::Duration,
};
use tokio::{
    signal::unix::{signal, SignalKind},
    time::{Instant, MissedTickBehavior},
};

pub const START_TIMEOUT: Duration = Duration::from_secs(45);
pub const START_FAILED: u8 = 78;

// Only systemd launches the daemon. Readiness is sent after the first online check.
fn notify(message: &str) -> Result<()> {
    let address = std::env::var_os("NOTIFY_SOCKET").context("请通过 netkeeper start 启动服务")?;
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    let bytes = address.as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        socket.send_to_addr(message.as_bytes(), &SocketAddr::from_abstract_name(name)?)?;
    } else {
        socket.send_to(message.as_bytes(), Path::new(&address))?;
    }
    Ok(())
}

fn report(state: &mut State, directory: &Path, phase: Phase, detail: &str) -> Result<()> {
    state.update(directory, phase, detail)?;
    notify(&format!("STATUS={}", detail.replace(['\n', '\r'], " ")))?;
    eprintln!("{detail}");
    Ok(())
}

pub async fn run(config_path: &Path, directory: &Path) -> Result<()> {
    notify("STATUS=正在读取配置")?;
    let mut state = State::new(None);
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            report(
                &mut state,
                directory,
                Phase::Failed,
                &format!("配置无效：{error:#}"),
            )?;
            return Err(error);
        }
    };
    state.interface = config.interface.clone();
    report(
        &mut state,
        directory,
        Phase::Starting,
        "正在检查网络并进行首次认证",
    )?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut refresh = signal(SignalKind::user_defined1())?;
    let shutdown = async {
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
    };
    tokio::pin!(shutdown);
    let mut authentication = Authentication::new(&config);

    let first = tokio::select! {
        biased;
        _ = &mut shutdown => {
            report(&mut state, directory, Phase::Stopped, "启动已取消")?;
            return Ok(());
        },
        result = tokio::time::timeout(START_TIMEOUT, authentication.cycle()) => {
            match result {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("首次认证超过 45 秒，启动已终止")),
            }
        }
    };
    (state.portal_url, state.ac_id) = authentication.parameters();
    let detail = match first {
        Err(error) => {
            report(
                &mut state,
                directory,
                Phase::Failed,
                &format!("启动失败：{error:#}"),
            )?;
            return Err(error);
        }
        Ok(detail) => detail,
    };
    report(&mut state, directory, Phase::Online, &detail)?;
    notify("READY=1")?;

    let interval = Duration::from_secs(config.probe.interval_secs);
    let mut probes = tokio::time::interval_at(Instant::now() + interval, interval);
    probes.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut portal_due = Instant::now() + Duration::from_secs(config.online_interval_secs);
    let mut retry_due = None;
    loop {
        let recovering = retry_due.is_some();
        let paused = state.phase == Phase::Paused;
        let deadline = retry_due.unwrap_or(portal_due);
        // One event loop serializes all work. During recovery only the retry
        // deadline can trigger network I/O; signals cannot bypass backoff.
        let check_probe = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = refresh.recv() => {
                if recovering || paused {
                    let phase = state.phase;
                    let detail = state.detail.clone();
                    report(&mut state, directory, phase, &detail)?;
                    continue;
                }
                false
            },
            _ = tokio::time::sleep_until(deadline), if !paused => false,
            _ = probes.tick(), if !recovering && !paused => true,
        };
        if check_probe {
            let result = tokio::select! {
                biased;
                _ = &mut shutdown => break,
                result = probe::check(&config) => result,
            };
            record_probe(&mut state, result);
            state.save(directory)?;
            if state.probe_failures < config.probe.failure_threshold {
                continue;
            }
        }

        let result = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            result = authentication.cycle() => result,
        };
        (state.portal_url, state.ac_id) = authentication.parameters();
        // If probes triggered recovery, Portal's online flag alone must not
        // reset the outage: verify the public path after the authentication.
        let result = if result.is_ok()
            && (recovering || state.probe_failures >= config.probe.failure_threshold)
        {
            let probe = tokio::select! {
                biased;
                _ = &mut shutdown => break,
                result = probe::check(&config) => result,
            };
            let reachable = probe.reachable;
            record_probe(&mut state, probe);
            if reachable {
                result
            } else {
                Err(anyhow::anyhow!(
                    "Portal 报告在线，但公网探测仍失败；不会重复登录，等待复查"
                ))
            }
        } else {
            result
        };

        probes.reset();
        match result {
            Ok(detail) => {
                state.recovery_attempts = 0;
                state.next_retry_at = None;
                retry_due = None;
                portal_due = Instant::now() + Duration::from_secs(config.online_interval_secs);
                report(&mut state, directory, Phase::Online, &detail)?;
            }
            Err(error) => {
                state.recovery_attempts = state.recovery_attempts.saturating_add(1);
                if error.downcast_ref::<CredentialRejected>().is_some() {
                    retry_due = None;
                    state.next_retry_at = None;
                    report(
                        &mut state,
                        directory,
                        Phase::Paused,
                        &format!("认证已暂停：{error:#}；请修改配置并重启服务"),
                    )?;
                } else {
                    let delay = retry_delay(&config, state.recovery_attempts);
                    retry_due = Some(Instant::now() + Duration::from_secs(delay));
                    state.next_retry_at = Some(crate::state::now() + delay);
                    report(
                        &mut state,
                        directory,
                        Phase::Retrying,
                        &format!("等待重试（{delay} 秒）：{error:#}"),
                    )?;
                }
            }
        }
    }
    state.next_retry_at = None;
    report(
        &mut state,
        directory,
        Phase::Stopped,
        "服务已停止，不再巡检或重试",
    )?;
    notify("STOPPING=1")?;
    Ok(())
}

fn record_probe(state: &mut State, probe: probe::ProbeResult) {
    state.probe_failures = if probe.reachable {
        0
    } else {
        state.probe_failures.saturating_add(1)
    };
    state.probe = Some(probe);
}

fn retry_delay(config: &Config, failed_attempts: u32) -> u64 {
    let stage = match failed_attempts {
        0..=3 => 0,
        4..=6 => 1,
        _ => 2,
    };
    config.retry_intervals_secs[stage]
}

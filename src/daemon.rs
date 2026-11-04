use crate::{
    client::CredentialRejected,
    config::Config,
    probe,
    session::{Authentication, EnvironmentUnavailable},
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

#[derive(Debug)]
pub struct StartupFailed(String);
impl std::fmt::Display for StartupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StartupFailed {}

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

fn publish(state: &State, directory: &Path) -> Result<()> {
    state.save(directory)?;
    // RuntimeDirectoryPreserve + DynamicUser makes the snapshot private. Expose a
    // password-free summary through systemd so unprivileged status still works.
    notify(&format!("STATUS={}", serde_json::to_string(state)?))
}

fn report(state: &mut State, directory: &Path, phase: Phase, detail: &str) -> Result<()> {
    state.update(directory, phase, detail)?;
    publish(state, directory)?;
    eprintln!("{detail}");
    Ok(())
}

fn record_probe(state: &mut State, result: probe::ProbeResult, campus: bool) {
    let (count, slot) = if campus {
        (&mut state.campus_failures, &mut state.campus_probe)
    } else {
        (&mut state.probe_failures, &mut state.probe)
    };
    *count = if result.reachable {
        0
    } else {
        count.saturating_add(1)
    };
    *slot = Some(result);
}

async fn evaluate(
    config: &Config,
    authentication: &mut Authentication<'_>,
    state: &mut State,
) -> Result<String> {
    let ip = probe::link(config.interface.as_deref()).map_err(|error| {
        state.local_ip = None;
        state.probe = None;
        state.campus_probe = None;
        EnvironmentUnavailable(format!("{error:#}"))
    })?;
    state.local_ip = Some(ip);
    let (public, campus) = tokio::join!(
        probe::check(&config.probe, config.interface.as_deref()),
        probe::check(&config.campus_probe, config.interface.as_deref())
    );
    record_probe(state, public.clone(), false);
    record_probe(state, campus.clone(), true);
    let outcome = authentication.cycle(ip, &public, &campus).await?;
    if outcome.logged_in {
        let (public, campus) = tokio::join!(
            probe::check(&config.probe, config.interface.as_deref()),
            probe::check(&config.campus_probe, config.interface.as_deref())
        );
        record_probe(state, public, false);
        record_probe(state, campus, true);
    }
    Ok(outcome.detail)
}

fn retry_delay(config: &Config, attempts: u32) -> u64 {
    config.retry_intervals_secs[match attempts {
        0..=3 => 0,
        4..=6 => 1,
        _ => 2,
    }]
}

fn finish_cycle(
    config: &Config,
    state: &mut State,
    directory: &Path,
    result: Result<String>,
) -> Result<()> {
    let (phase, detail) = match result {
        Ok(detail) => {
            state.started = true;
            state.recovery_attempts = 0;
            if state.probe.as_ref().is_some_and(|p| p.reachable) {
                state.next_retry_at = None;
                (Phase::Online, detail)
            } else {
                state.next_retry_at = Some(crate::state::now() + config.environment_interval_secs);
                (
                    Phase::Degraded,
                    format!("校园网已在线，公网出口异常；不重复登录，等待复查；{detail}"),
                )
            }
        }
        Err(error) if error.downcast_ref::<CredentialRejected>().is_some() => {
            state.next_retry_at = None;
            (
                Phase::Paused,
                format!("认证已暂停：{error:#}；请修改配置并重启服务"),
            )
        }
        Err(error) if error.downcast_ref::<EnvironmentUnavailable>().is_some() => {
            state.next_retry_at = Some(crate::state::now() + config.environment_interval_secs);
            (
                Phase::Waiting,
                format!(
                    "等待网络环境（{} 秒）：{error:#}",
                    config.environment_interval_secs
                ),
            )
        }
        Err(error) => {
            state.recovery_attempts = state.recovery_attempts.saturating_add(1);
            let delay = retry_delay(config, state.recovery_attempts);
            state.next_retry_at = Some(crate::state::now() + delay);
            (
                Phase::Retrying,
                format!("等待认证恢复（{delay} 秒）：{error:#}"),
            )
        }
    };
    report(state, directory, phase, &detail)
}

pub async fn run(config_path: &Path, directory: &Path) -> Result<()> {
    let previous = State::read(directory).filter(|s| s.started);
    let resumed = previous.is_some();
    let mut state = previous.unwrap_or_else(|| State::new(None));
    state.pid = std::process::id();
    let config = match Config::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            let detail = format!("配置无效：{error:#}");
            report(&mut state, directory, Phase::Failed, &detail)?;
            return Err(if resumed {
                error
            } else {
                StartupFailed(detail).into()
            });
        }
    };
    state.interface = config.interface.clone();
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut refresh = signal(SignalKind::user_defined1())?;
    let shutdown = async {
        tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
    };
    tokio::pin!(shutdown);
    let mut authentication = Authentication::new(&config);
    if resumed {
        let phase = if state.phase == Phase::Paused {
            Phase::Paused
        } else {
            Phase::Waiting
        };
        let detail = format!(
            "进程已恢复；{}",
            state.detail.trim_start_matches("进程已恢复；")
        );
        report(&mut state, directory, phase, &detail)?;
        // Recovery may wait for a disconnected interface; readiness here means
        // the already-armed worker is restored, not that the old online flag is valid.
        notify("READY=1")?;
    } else {
        report(
            &mut state,
            directory,
            Phase::Starting,
            "正在检查校园网环境并确认首次在线",
        )?;
        let first = tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            result = tokio::time::timeout(START_TIMEOUT, evaluate(&config, &mut authentication, &mut state)) =>
                result.unwrap_or_else(|_| Err(anyhow::anyhow!("首次认证超过 45 秒"))),
        };
        (state.portal_url, state.ac_id) = authentication.parameters();
        if let Err(error) = first {
            let detail = format!("启动失败：{error:#}");
            report(&mut state, directory, Phase::Failed, &detail)?;
            return Err(StartupFailed(detail).into());
        }
        finish_cycle(&config, &mut state, directory, first)?;
        notify("READY=1")?;
    }

    let interval = Duration::from_secs(config.probe.interval_secs);
    let mut probes = tokio::time::interval_at(Instant::now() + interval, interval);
    probes.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut campus_due = Instant::now() + Duration::from_secs(config.campus_probe.interval_secs);
    let mut portal_due = Instant::now() + Duration::from_secs(config.online_interval_secs);
    let mut retry_due = state
        .next_retry_at
        .map(|at| Instant::now() + Duration::from_secs(at.saturating_sub(crate::state::now())));
    if resumed && state.phase != Phase::Paused && retry_due.is_none() {
        retry_due = Some(Instant::now());
    }
    loop {
        let waiting = retry_due.is_some();
        let paused = state.phase == Phase::Paused;
        let deadline = retry_due.unwrap_or(portal_due);
        let event = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = refresh.recv() => {
                if waiting || paused {
                    let phase = state.phase;
                    let detail = state.detail.clone();
                    report(&mut state, directory, phase, &detail)?;
                    continue;
                }
                0
            },
            _ = tokio::time::sleep_until(deadline), if !paused => 0,
            _ = tokio::time::sleep_until(campus_due), if !waiting && !paused => 2,
            _ = probes.tick(), if !waiting && !paused => 1,
        };
        if event != 0 {
            let unchanged = probe::link(config.interface.as_deref())
                .ok()
                .is_some_and(|ip| Some(ip) == state.local_ip);
            if unchanged {
                let campus = event == 2;
                let group = if campus {
                    &config.campus_probe
                } else {
                    &config.probe
                };
                let result = tokio::select! {
                    biased;
                    _ = &mut shutdown => break,
                    result = probe::check(group, config.interface.as_deref()) => result,
                };
                record_probe(&mut state, result, campus);
                publish(&state, directory)?;
                if campus {
                    campus_due = Instant::now() + Duration::from_secs(group.interval_secs);
                }
                let failures = if campus {
                    state.campus_failures
                } else {
                    state.probe_failures
                };
                if failures < group.failure_threshold {
                    continue;
                }
            }
        }
        // Reserve a deadline before network I/O, so an abrupt death cannot
        // bypass recovery backoff. Replace it with the actual deadline on completion.
        state.next_retry_at = Some(
            crate::state::now()
                + START_TIMEOUT.as_secs()
                + retry_delay(&config, state.recovery_attempts.saturating_add(1)),
        );
        publish(&state, directory)?;
        let result = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            result = tokio::time::timeout(START_TIMEOUT, evaluate(&config, &mut authentication, &mut state)) =>
                result.unwrap_or_else(|_| Err(anyhow::anyhow!("网络检查与认证超过 45 秒，等待重试"))),
        };
        (state.portal_url, state.ac_id) = authentication.parameters();
        finish_cycle(&config, &mut state, directory, result)?;
        retry_due = state
            .next_retry_at
            .map(|at| Instant::now() + Duration::from_secs(at.saturating_sub(crate::state::now())));
        probes.reset();
        campus_due = Instant::now() + Duration::from_secs(config.campus_probe.interval_secs);
        portal_due = Instant::now() + Duration::from_secs(config.online_interval_secs);
    }
    // systemctl stop removes /run; direct SIGTERM preserves the prior recovery state.
    notify("STOPPING=1")?;
    Ok(())
}

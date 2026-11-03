use crate::{
    client::SrunClient,
    config::Config,
    state::{Phase, State},
};
use anyhow::{bail, Context, Result};
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
use tokio::signal::unix::{signal, SignalKind};

pub const START_TIMEOUT: Duration = Duration::from_secs(30);
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

    let first = tokio::select! {
        biased;
        _ = &mut shutdown => {
            report(&mut state, directory, Phase::Stopped, "启动已取消")?;
            return Ok(());
        },
        result = tokio::time::timeout(START_TIMEOUT, cycle(&config)) => {
            match result {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("首次认证超过 30 秒，启动已终止")),
            }
        }
    };
    if let Err(error) = first {
        report(
            &mut state,
            directory,
            Phase::Failed,
            &format!("启动失败：{error:#}"),
        )?;
        return Err(error);
    }
    report(&mut state, directory, Phase::Online, "已确认在线")?;
    notify("READY=1")?;

    let mut online = true;
    loop {
        let interval = if online {
            config.online_interval_secs
        } else {
            config.retry_interval_secs
        };
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = refresh.recv() => {},
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
        }
        let result = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            result = cycle(&config) => result,
        };
        match result {
            Ok(()) => {
                online = true;
                report(&mut state, directory, Phase::Online, "已确认在线")?;
            }
            Err(error) => {
                online = false;
                report(
                    &mut state,
                    directory,
                    Phase::Retrying,
                    &format!("等待重试：{error:#}"),
                )?;
            }
        }
    }
    report(
        &mut state,
        directory,
        Phase::Stopped,
        "服务已停止，不再巡检或重试",
    )?;
    notify("STOPPING=1")?;
    Ok(())
}

async fn cycle(config: &Config) -> Result<()> {
    if !SrunClient::new(config).await?.cycle().await? {
        bail!("登录已被接受，但尚未确认在线");
    }
    Ok(())
}

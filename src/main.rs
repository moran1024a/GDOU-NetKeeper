#[cfg(not(target_os = "linux"))]
compile_error!("netkeeper currently supports Linux only");

mod client;
mod config;
mod protocol;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use std::{path::PathBuf, process::ExitCode, time::Duration};
use tokio::signal::unix::{signal, SignalKind};

#[derive(Parser)]
#[command(
    name = "netkeeper",
    version,
    about = "Linux 校园网自动认证服务（SRUN）"
)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "/etc/netkeeper/config.toml")]
    config: PathBuf,
    /// 只校验配置，不发送网络请求
    #[arg(long, conflicts_with = "once")]
    check: bool,
    /// 执行一轮检查和必要的认证，确认在线后返回成功
    #[arg(long)]
    once: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("错误：{error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<()> {
    let config = Config::load(&args.config)?;
    if args.check {
        println!("配置有效（未检查网络、网卡是否存在或账号是否可登录）");
        return Ok(());
    }

    let mut terminate = signal(SignalKind::terminate()).context("无法监听 SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("无法监听 SIGINT")?;
    let shutdown = async {
        tokio::select! {
            _ = terminate.recv() => {},
            _ = interrupt.recv() => {},
        }
    };
    tokio::pin!(shutdown);
    let mut previous_online = None;
    eprintln!("服务启动，开始检查网络");
    loop {
        // Recreate the client each round so changed DHCP addresses and routes are not cached.
        let result = tokio::select! {
            biased;
            _ = &mut shutdown => break,
            result = async { client::SrunClient::new(&config).await?.cycle().await } => result,
        };
        let online = match result {
            Ok(online) => online,
            Err(error) => {
                if args.once {
                    return Err(error);
                }
                eprintln!("本轮未完成，将重试：{error:#}");
                false
            }
        };
        if previous_online != Some(online) {
            eprintln!(
                "{}",
                if online {
                    "已确认在线"
                } else {
                    "尚未确认在线，等待重试"
                }
            );
            previous_online = Some(online);
        }
        if args.once {
            anyhow::ensure!(online, "本轮结束后仍未确认在线");
            return Ok(());
        }
        let interval = if online {
            config.online_interval_secs
        } else {
            config.retry_interval_secs
        };
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {},
        }
    }
    eprintln!("服务已停止");
    Ok(())
}

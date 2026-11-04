#[cfg(not(target_os = "linux"))]
compile_error!("netkeeper currently supports Linux only");

mod client;
mod config;
mod control;
mod daemon;
mod discovery;
mod probe;
mod protocol;
mod state;
mod tui;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use config::{Config, CONFIG_PATH};
use control::Controller;
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "netkeeper",
    version,
    about = "Linux 校园网认证与服务管理；无参数打开 TUI"
)]
struct Args {
    #[command(subcommand)]
    command: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    /// 启动服务，确认首次在线后返回
    Start,
    /// 停止服务及所有巡检、重试
    Stop,
    /// 停止服务并注销当前校园网登录（可能断开远程连接）
    Logout,
    /// 查看服务和最近认证状态（不请求网络）
    Status,
    /// 交互修改网卡、账号、密码及认证参数
    Settings,
    #[command(hide = true)]
    Run {
        #[arg(long, default_value = CONFIG_PATH)]
        config: PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    let backend = matches!(args.command, Some(Action::Run { .. }));
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("错误：{error:#}");
            ExitCode::from(if backend { daemon::START_FAILED } else { 1 })
        }
    }
}

fn require_admin() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        bail!("此操作需要管理员权限，请使用 sudo netkeeper；查看状态可使用 netkeeper status");
    }
    Ok(())
}

async fn ensure_configured() -> Result<()> {
    if let Err(error) = Config::load(Path::new(CONFIG_PATH)) {
        if !tui::available() {
            bail!("配置无效：{error:#}；请先在交互终端运行 sudo netkeeper settings");
        }
        if !tui::settings(Path::new(CONFIG_PATH)).await? {
            bail!("设置已取消，未启动服务");
        }
    }
    Ok(())
}

async fn start(controller: &Controller) -> Result<()> {
    ensure_configured().await?;
    let interactive = tui::available();
    let mut ui = if interactive {
        Some(tui::Ui::new()?)
    } else {
        None
    };
    let result = controller
        .start(tui::cancel(interactive), |message| {
            if let Some(ui) = &mut ui {
                ui.page(
                    "正在启动 NetKeeper",
                    &[message.to_owned()],
                    "等待首次在线，最多 30 秒 · Esc / Ctrl+C 取消",
                )
            } else {
                eprintln!("{message}");
                Ok(())
            }
        })
        .await;
    drop(ui);
    result?;
    println!("已确认在线，后台服务正在运行");
    Ok(())
}

// Returns true when the user restarted the service after saving.
async fn settings(controller: &Controller) -> Result<bool> {
    if !tui::settings(Path::new(CONFIG_PATH)).await? {
        println!("设置已取消，原配置保持不变");
        return Ok(false);
    }
    if controller.inspect().await.is_ok_and(|s| s.running()) {
        let choice = tui::Ui::new()?.select(
            "配置已保存，何时应用？",
            &["稍后应用".into(), "立即重启服务".into()],
            0,
        )?;
        if choice == Some(1) {
            controller.stop().await?;
            start(controller).await?;
            return Ok(true);
        }
        println!("配置已保存；服务仍使用原配置，下次启动生效");
    } else {
        println!("配置已保存；运行 netkeeper start 启动");
    }
    Ok(false)
}

async fn logout(controller: &Controller) -> Result<()> {
    let config = Config::load(Path::new(CONFIG_PATH))?;
    println!("正在停止服务并注销校园网，此出口的远程连接可能断开");
    let message = controller.logout(&config).await?;
    println!("{message}；服务保持停止，不会自动重连");
    Ok(())
}

async fn run(args: Args) -> Result<()> {
    let controller = Controller;
    match args.command {
        Some(Action::Run { config }) => {
            return daemon::run(&config, Path::new(state::STATE_DIR)).await;
        }
        Some(Action::Status) => {
            println!("{}", controller.status().await?);
            return Ok(());
        }
        _ => require_admin()?,
    }
    match args.command {
        Some(Action::Start) => start(&controller).await,
        Some(Action::Logout) => logout(&controller).await,
        Some(Action::Stop) => {
            controller.stop().await?;
            println!("服务已停止，不再巡检或重试");
            Ok(())
        }
        Some(Action::Settings) => {
            settings(&controller).await?;
            Ok(())
        }
        None => {
            if Config::load(Path::new(CONFIG_PATH)).is_err() {
                return start(&controller).await;
            }
            let mut selected = 0;
            loop {
                let choice = tui::Ui::new()?.select(
                    "GDOU NetKeeper",
                    &[
                        "启动服务".into(),
                        "停止服务".into(),
                        "查看状态".into(),
                        "修改设置".into(),
                        "注销校园网".into(),
                        "退出".into(),
                    ],
                    selected,
                )?;
                match choice {
                    Some(0) => return start(&controller).await,
                    Some(1) => {
                        controller.stop().await?;
                        tui::Ui::new()?.message("服务管理", "服务已停止，不再巡检或重试")?;
                    }
                    Some(2) => {
                        let status = controller.status().await?;
                        tui::Ui::new()?.message("当前状态", &status)?;
                    }
                    Some(3) => {
                        if settings(&controller).await? {
                            return Ok(());
                        }
                    }
                    Some(4) => {
                        if tui::Ui::new()?.select(
                            "注销校园网：将停止服务，并可能断开远程连接",
                            &["取消".into(), "确认注销，保持服务停止".into()],
                            0,
                        )? == Some(1)
                        {
                            return logout(&controller).await;
                        }
                    }
                    _ => return Ok(()),
                }
                selected = choice.unwrap_or(0);
            }
        }
        _ => unreachable!(),
    }
}

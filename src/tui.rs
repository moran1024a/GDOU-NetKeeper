use crate::config::{Config, ProbeMode};
use crate::discovery;
use anyhow::{ensure, Context, Result};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute, queue,
    style::{Attribute, Print, SetAttribute},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use std::{
    collections::BTreeMap,
    io::{self, IsTerminal, Write},
    path::Path,
    time::Duration,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub fn available() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

pub struct Ui;

impl Ui {
    pub fn new() -> Result<Self> {
        ensure!(
            available(),
            "需要交互终端，请在终端运行 sudo netkeeper settings 配置后再启动"
        );
        terminal::enable_raw_mode()?;
        let ui = Self;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableBracketedPaste,
            Hide
        )?;
        Ok(ui)
    }

    pub fn page(&mut self, title: &str, lines: &[String], hint: &str) -> Result<()> {
        let (width, height) = terminal::size()?;
        let mut out = io::stdout();
        queue!(
            out,
            Hide,
            MoveTo(0, 0),
            Clear(ClearType::All),
            Print(clip(title, width as usize))
        )?;
        for (index, line) in lines
            .iter()
            .take(height.saturating_sub(4) as usize)
            .enumerate()
        {
            queue!(
                out,
                MoveTo(0, index as u16 + 2),
                Print(clip(line, width as usize))
            )?;
        }
        queue!(
            out,
            MoveTo(0, height.saturating_sub(1)),
            Print(clip(hint, width as usize))
        )?;
        out.flush()?;
        Ok(())
    }

    pub fn select(
        &mut self,
        title: &str,
        choices: &[String],
        initial: usize,
    ) -> Result<Option<usize>> {
        ensure!(!choices.is_empty(), "没有可选择的项目");
        let mut selected = initial.min(choices.len() - 1);
        loop {
            let (width, height) = terminal::size()?;
            let visible = usize::from(height.saturating_sub(4)).max(1);
            let offset = selected.saturating_sub(visible - 1);
            self.page(title, &[], "↑↓/Tab 选择 · Enter 确认 · Esc 返回")?;
            let mut out = io::stdout();
            for (row, choice) in choices.iter().skip(offset).take(visible).enumerate() {
                queue!(out, MoveTo(0, row as u16 + 2))?;
                if row + offset == selected {
                    queue!(out, SetAttribute(Attribute::Reverse))?;
                }
                queue!(
                    out,
                    Print(clip(
                        &format!(
                            "{} {choice}",
                            if row + offset == selected { "›" } else { " " }
                        ),
                        width as usize
                    )),
                    SetAttribute(Attribute::Reset)
                )?;
            }
            out.flush()?;
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                if cancelled_key(key.code, key.modifiers) {
                    return Ok(None);
                }
                match key.code {
                    KeyCode::Up | KeyCode::BackTab => {
                        selected = (selected + choices.len() - 1) % choices.len()
                    }
                    KeyCode::Down | KeyCode::Tab => selected = (selected + 1) % choices.len(),
                    KeyCode::Home => selected = 0,
                    KeyCode::End => selected = choices.len() - 1,
                    KeyCode::Enter => return Ok(Some(selected)),
                    _ => {}
                }
            }
        }
    }

    // Every field, including the password, is edited as visible plain text.
    pub fn input(&mut self, title: &str, initial: &str) -> Result<Option<String>> {
        let mut text: Vec<char> = initial.chars().collect();
        let mut cursor = text.len();
        loop {
            let width = usize::from(terminal::size()?.0.saturating_sub(2)).max(1);
            let mut start = cursor;
            let mut used = 0;
            while start > 0 {
                let size = text[start - 1].width().unwrap_or(0);
                if used + size >= width {
                    break;
                }
                start -= 1;
                used += size;
            }
            let line: String = text[start..].iter().collect();
            self.page(
                title,
                &[clip(&line, width)],
                "←→ 移动 · Ctrl+U 清空 · Enter 保存 · Esc 取消",
            )?;
            execute!(io::stdout(), MoveTo(used as u16, 2), Show)?;
            match event::read()? {
                Event::Paste(paste) => {
                    let chars: Vec<_> = paste.chars().filter(|c| !c.is_control()).collect();
                    let count = chars.len();
                    text.splice(cursor..cursor, chars);
                    cursor += count;
                }
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if cancelled_key(key.code, key.modifiers) {
                        return Ok(None);
                    }
                    match key.code {
                        KeyCode::Enter => return Ok(Some(text.iter().collect())),
                        KeyCode::Left => cursor = cursor.saturating_sub(1),
                        KeyCode::Right => cursor = (cursor + 1).min(text.len()),
                        KeyCode::Home => cursor = 0,
                        KeyCode::End => cursor = text.len(),
                        KeyCode::Backspace if cursor > 0 => {
                            cursor -= 1;
                            text.remove(cursor);
                        }
                        KeyCode::Delete if cursor < text.len() => {
                            text.remove(cursor);
                        }
                        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            text.clear();
                            cursor = 0;
                        }
                        KeyCode::Char(c)
                            if !c.is_control()
                                && !key
                                    .modifiers
                                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                        {
                            text.insert(cursor, c);
                            cursor += 1;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    pub fn message(&mut self, title: &str, message: &str) -> Result<()> {
        let lines: Vec<String> = message.lines().map(str::to_owned).collect();
        loop {
            self.page(title, &lines, "Enter / Esc 返回")?;
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Release
                    && (key.code == KeyCode::Enter || cancelled_key(key.code, key.modifiers))
                {
                    return Ok(());
                }
            }
        }
    }
}

impl Drop for Ui {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            SetAttribute(Attribute::Reset),
            Show,
            DisableBracketedPaste,
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

fn clip(text: &str, width: usize) -> String {
    let mut result = String::new();
    for c in text.chars().filter(|c| !c.is_control()) {
        if result.width() + c.width().unwrap_or(0) > width {
            break;
        }
        result.push(c);
    }
    result
}

fn cancelled_key(code: KeyCode, modifiers: KeyModifiers) -> bool {
    code == KeyCode::Esc
        || (code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL))
}

pub async fn cancel(interactive: bool) {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("SIGINT handler");
    loop {
        if interactive {
            match event::poll(Duration::ZERO) {
                Ok(true) => {
                    if let Ok(Event::Key(key)) = event::read() {
                        if cancelled_key(key.code, key.modifiers) {
                            return;
                        }
                    }
                }
                Err(_) => return,
                _ => {}
            }
        }
        tokio::select! {
            _ = terminate.recv() => return,
            _ = interrupt.recv() => return,
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
}

fn choose_interface(ui: &mut Ui, current: Option<&str>) -> Result<Option<Option<String>>> {
    let mut interfaces: BTreeMap<String, (bool, Vec<String>)> = BTreeMap::new();
    for address in getifaddrs().context("无法读取网卡列表")? {
        if address.flags.contains(InterfaceFlags::IFF_LOOPBACK) {
            continue;
        }
        let entry = interfaces.entry(address.interface_name).or_default();
        entry.0 |= address.flags.contains(InterfaceFlags::IFF_RUNNING);
        if let Some(ip) = address
            .address
            .and_then(|a| a.as_sockaddr_in().map(|v| v.ip()))
        {
            let ip = ip.to_string();
            if !entry.1.contains(&ip) {
                entry.1.push(ip);
            }
        }
    }
    let mut names = vec![None];
    let mut labels = vec!["跟随系统路由".into()];
    for (name, (connected, addresses)) in interfaces {
        labels.push(format!(
            "{name}  {}  {}",
            if connected { "已连接" } else { "未连接" },
            if addresses.is_empty() {
                "无 IPv4".into()
            } else {
                addresses.join(", ")
            }
        ));
        names.push(Some(name));
    }
    if let Some(name) = current {
        if !names.iter().any(|n| n.as_deref() == Some(name)) {
            names.push(Some(name.to_owned()));
            labels.push(format!("{name}  当前不存在（保留配置）"));
        }
    }
    let selected = names
        .iter()
        .position(|n| n.as_deref() == current)
        .unwrap_or(0);
    Ok(ui
        .select("选择校园网网卡", &labels, selected)?
        .map(|index| names[index].clone()))
}

pub async fn settings(path: &Path) -> Result<bool> {
    let mut ui = Ui::new()?;
    let mut config = Config::for_edit(path);
    let mut selected = 0;
    loop {
        let choices = vec![
            format!(
                "网卡：{}",
                config.interface.as_deref().unwrap_or("跟随系统路由")
            ),
            format!("账号：{}", config.username),
            format!("密码：{}", config.password),
            format!("Portal：{}", config.portal_url),
            format!("接入点 ac_id：{}", config.ac_id),
            format!("Portal 巡检间隔（秒）：{}", config.online_interval_secs),
            "公网探测设置".into(),
            "分阶段重试设置".into(),
            "自动识别 Portal / ac_id".into(),
            "从认证页面链接导入".into(),
            "保存配置".into(),
            "取消".into(),
        ];
        let Some(index) = ui.select("NetKeeper 设置", &choices, selected)? else {
            return Ok(false);
        };
        selected = index;
        match index {
            0 => {
                if let Some(value) = choose_interface(&mut ui, config.interface.as_deref())? {
                    config.interface = value;
                    if config.portal_url.is_empty() || config.ac_id == 0 {
                        discover_settings(&mut ui, &mut config).await?;
                    }
                }
            }
            1..=5 => {
                let (label, value) = choices[index].split_once('：').expect("field label");
                if let Some(value) = ui.input(label, value)? {
                    match index {
                        1 => config.username = value,
                        2 => config.password = value,
                        3 => config.portal_url = value,
                        4 => match value.parse() {
                            Ok(value) => config.ac_id = value,
                            Err(_) => ui.message("输入无效", "接入点编号必须是正整数")?,
                        },
                        5 => match value.parse::<u64>() {
                            Ok(value) => config.online_interval_secs = value,
                            Err(_) => ui.message("输入无效", "间隔必须是正整数秒数")?,
                        },
                        _ => unreachable!(),
                    }
                }
            }
            6 => probe_settings(&mut ui, &mut config)?,
            7 => retry_settings(&mut ui, &mut config)?,
            8 => discover_settings(&mut ui, &mut config).await?,
            9 => {
                if let Some(value) = ui.input("完整认证页面链接（含 ac_id）", "")? {
                    match discovery::from_link(&value) {
                        Ok(found) => apply_discovery(&mut ui, &mut config, found)?,
                        Err(error) => ui.message("无法导入", &format!("{error:#}"))?,
                    }
                }
            }
            10 => match config.save(path) {
                Ok(()) => return Ok(true),
                Err(error) => ui.message("配置未保存", &format!("{error:#}"))?,
            },
            _ => return Ok(false),
        }
    }
}

fn apply_discovery(ui: &mut Ui, config: &mut Config, found: discovery::Parameters) -> Result<()> {
    if ui.select(
        "认证参数（回填后仍需保存配置）",
        &[
            format!("使用 {}，ac_id={}", found.portal_url, found.ac_id),
            "取消，保留原参数".into(),
        ],
        0,
    )? == Some(0)
    {
        config.portal_url = found.portal_url;
        config.ac_id = found.ac_id;
    }
    Ok(())
}

async fn discover_settings(ui: &mut Ui, config: &mut Config) -> Result<()> {
    ui.page(
        "正在自动识别认证参数",
        &[
            format!(
                "网卡：{}",
                config.interface.as_deref().unwrap_or("跟随系统路由")
            ),
            "只读取认证页面，不会登录或注销".into(),
        ],
        "最多 10 秒 · Esc / Ctrl+C 取消",
    )?;
    let result = tokio::select! {
        biased;
        _ = cancel(true) => return Ok(()),
        result = discovery::discover(config.interface.as_deref(), &config.portal_url) => result,
    };
    match result {
        Ok(found) => apply_discovery(ui, config, found)?,
        Err(error) => ui.message("未能自动识别（原参数保留）", &format!("{error:#}"))?,
    }
    Ok(())
}

fn number<T: std::str::FromStr + std::fmt::Display>(
    ui: &mut Ui,
    label: &str,
    current: &mut T,
) -> Result<()> {
    if let Some(value) = ui.input(label, &current.to_string())? {
        match value.parse() {
            Ok(value) => *current = value,
            Err(_) => ui.message("输入无效", "请输入有效的非负整数")?,
        }
    }
    Ok(())
}

fn probe_settings(ui: &mut Ui, config: &mut Config) -> Result<()> {
    let mut selected = 0;
    loop {
        let probe = &mut config.probe;
        let mut choices = vec![
            format!(
                "方式：{}",
                if probe.mode == ProbeMode::Icmp {
                    "ICMP"
                } else {
                    "TCP"
                }
            ),
            format!("主目标 IPv4：{}", probe.primary),
        ];
        for i in 0..3 {
            choices.push(format!(
                "备用目标 {}：{}",
                i + 1,
                probe
                    .backups
                    .get(i)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "未配置".into())
            ));
        }
        choices.extend([
            format!("TCP 端口：{}", probe.tcp_port),
            format!("轮询间隔（秒）：{}", probe.interval_secs),
            format!("单目标超时（秒）：{}", probe.timeout_secs),
            format!("连续失败门槛（轮）：{}", probe.failure_threshold),
            "返回设置（主菜单保存后生效）".into(),
        ]);
        let Some(index) = ui.select("公网探测设置", &choices, selected)? else {
            return Ok(());
        };
        selected = index;
        match index {
            0 => {
                if let Some(mode) = ui.select(
                    "探测方式",
                    &["ICMP".into(), "TCP".into()],
                    usize::from(probe.mode == ProbeMode::Tcp),
                )? {
                    probe.mode = if mode == 0 {
                        ProbeMode::Icmp
                    } else {
                        ProbeMode::Tcp
                    };
                }
            }
            1..=4 => {
                let current = if index == 1 {
                    probe.primary.to_string()
                } else {
                    probe
                        .backups
                        .get(index - 2)
                        .map(ToString::to_string)
                        .unwrap_or_default()
                };
                let label = if index == 1 {
                    "主目标 IPv4"
                } else {
                    "备用目标 IPv4（清空可移除）"
                };
                if let Some(value) = ui.input(label, &current)? {
                    if value.is_empty() && index > 1 {
                        if index - 2 < probe.backups.len() {
                            probe.backups.remove(index - 2);
                        }
                    } else {
                        match value.parse() {
                            Ok(ip) => {
                                if index == 1 {
                                    probe.primary = ip;
                                } else if let Some(target) = probe.backups.get_mut(index - 2) {
                                    *target = ip;
                                } else {
                                    probe.backups.push(ip);
                                }
                            }
                            Err(_) => ui.message("输入无效", "请输入 IPv4 地址，例如 223.5.5.5")?,
                        }
                    }
                }
            }
            5 => number(ui, "TCP 端口", &mut probe.tcp_port)?,
            6 => number(ui, "轮询间隔（秒）", &mut probe.interval_secs)?,
            7 => number(ui, "单目标超时（秒）", &mut probe.timeout_secs)?,
            8 => number(ui, "连续失败门槛（轮）", &mut probe.failure_threshold)?,
            _ => return Ok(()),
        }
    }
}

fn retry_settings(ui: &mut Ui, config: &mut Config) -> Result<()> {
    let mut selected = 0;
    loop {
        let values = config.retry_intervals_secs;
        let choices = vec![
            format!("前 3 次重试间隔（秒）：{}", values[0]),
            format!("接下来 3 次重试间隔（秒）：{}", values[1]),
            format!("后续重试间隔（秒）：{}", values[2]),
            "返回设置（主菜单保存后生效）".into(),
        ];
        let Some(index) = ui.select("分阶段重试设置", &choices, selected)? else {
            return Ok(());
        };
        if index == 3 {
            return Ok(());
        }
        selected = index;
        number(
            ui,
            "重试间隔（秒）",
            &mut config.retry_intervals_secs[index],
        )?;
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    #[ignore = "driven through a PTY by tests/behavior.py"]
    async fn interactive_settings_fixture() {
        let path = std::path::PathBuf::from(std::env::var_os("NETKEEPER_UI_TEST_CONFIG").unwrap());
        let expected = std::env::var("NETKEEPER_UI_TEST_SAVED").unwrap() == "yes";
        assert_eq!(super::settings(&path).await.unwrap(), expected);
    }
}

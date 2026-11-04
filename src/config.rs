use anyhow::{bail, Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

pub const CONFIG_PATH: &str = "/etc/netkeeper/config.toml";

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub auth_mode: AuthMode,
    pub portal_url: String,
    pub ac_id: u32,
    pub interface: Option<String>,
    pub online_interval_secs: u64,
    // Accepted for old configurations; staged retries replace this setting.
    #[serde(skip_serializing, rename = "retry_interval_secs")]
    pub _legacy_retry_interval_secs: Option<u64>,
    pub retry_intervals_secs: [u64; 3],
    pub probe: ProbeConfig,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Auto,
    Manual,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMode {
    Icmp,
    Tcp,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProbeConfig {
    pub mode: ProbeMode,
    pub primary: Ipv4Addr,
    pub backups: Vec<Ipv4Addr>,
    pub tcp_port: u16,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub failure_threshold: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            mode: ProbeMode::Icmp,
            primary: Ipv4Addr::new(223, 5, 5, 5),
            backups: vec![
                Ipv4Addr::new(119, 29, 29, 29),
                Ipv4Addr::new(180, 76, 76, 76),
                Ipv4Addr::new(223, 6, 6, 6),
            ],
            tcp_port: 53,
            interval_secs: 2,
            timeout_secs: 1,
            failure_threshold: 3,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            auth_mode: AuthMode::Auto,
            portal_url: String::new(),
            ac_id: 0,
            interface: None,
            online_interval_secs: 300,
            _legacy_retry_interval_secs: None,
            retry_intervals_secs: [5, 15, 30],
            probe: ProbeConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).context("无法读取配置文件")?;
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self> {
        // TOML errors can contain the source line, including a plaintext password.
        let config: Self = toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("配置格式错误、字段缺失或存在未知字段，请参照 config.example.toml")
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn for_edit(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path.parent().context("配置文件缺少父目录")?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        temporary.write_all(toml::to_string_pretty(self)?.as_bytes())?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .context("保存配置失败")?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() || self.username.trim() != self.username {
            bail!("username 不能为空或包含首尾空白，请保留完整账号后缀");
        }
        if self.password.is_empty() {
            bail!("password 不能为空");
        }
        if !self.portal_url.is_empty() || self.auth_mode == AuthMode::Manual {
            let url = Url::parse(&self.portal_url).context("portal_url 不是有效 URL")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                bail!("portal_url 只接受 http(s)://主机[:端口]，不要带账号、页面路径或查询参数");
            }
        }
        if self.auth_mode == AuthMode::Manual && self.ac_id == 0 {
            bail!("ac_id 必须大于 0");
        }
        if let Some(interface) = &self.interface {
            if interface.is_empty()
                || interface.len() > 15
                || interface
                    .bytes()
                    .any(|c| c.is_ascii_whitespace() || matches!(c, 0 | b'/' | b':'))
            {
                bail!("interface 必须是有效的 Linux 网卡名称；不绑定时请删除此配置项");
            }
        }
        for interval in [self.online_interval_secs]
            .into_iter()
            .chain(self.retry_intervals_secs)
        {
            if !(1..=86400).contains(&interval) {
                bail!("检查和重试间隔必须在 1 到 86400 秒之间");
            }
        }
        if self
            .retry_intervals_secs
            .windows(2)
            .any(|pair| pair[0] > pair[1])
        {
            bail!("三个阶段的重试间隔必须依次不减");
        }
        let probe = &self.probe;
        if !(1..=3600).contains(&probe.interval_secs)
            || !(1..=30).contains(&probe.timeout_secs)
            || !(1..=10).contains(&probe.failure_threshold)
        {
            bail!("探测间隔须为 1–3600 秒，超时为 1–30 秒，失败门槛为 1–10 轮");
        }
        if probe.backups.len() > 3 || probe.tcp_port == 0 {
            bail!("最多配置 3 个备用目标，TCP 端口必须大于 0");
        }
        for ip in std::iter::once(&probe.primary).chain(&probe.backups) {
            if ip.is_unspecified() || ip.is_multicast() || *ip == Ipv4Addr::BROADCAST {
                bail!("探测目标必须是单播 IPv4 地址");
            }
        }
        Ok(())
    }
}

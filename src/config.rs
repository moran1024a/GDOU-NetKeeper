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
    #[serde(
        default = "ProbeConfig::campus",
        deserialize_with = "ProbeConfig::deserialize_campus"
    )]
    pub campus_probe: ProbeConfig,
    pub environment_interval_secs: u64,
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
    Https,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeTarget {
    pub mode: ProbeMode,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl ProbeTarget {
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(if self.mode == ProbeMode::Https {
            443
        } else {
            53
        })
    }

    pub fn label(&self) -> String {
        match self.mode {
            ProbeMode::Icmp => format!("ICMP {}", self.address),
            ProbeMode::Tcp => format!("TCP {}:{}", self.address, self.port()),
            ProbeMode::Https => format!("HTTPS {}:{}", self.address, self.port()),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Ok(ip) = self.address.parse::<Ipv4Addr>() {
            if ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST {
                bail!("探测目标必须是单播 IPv4 地址");
            }
        } else {
            if self.mode == ProbeMode::Icmp {
                bail!("ICMP 目标必须填写 IPv4 地址");
            }
            if self.address.len() > 253
                || !self.address.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                })
            {
                bail!("TCP / HTTPS 目标须填写 IPv4 或域名，不含协议、路径或端口");
            }
        }
        if self.port() == 0 {
            bail!("探测端口必须大于 0");
        }
        Ok(())
    }
}

#[derive(Clone, Serialize)]
pub struct ProbeConfig {
    pub primary: ProbeTarget,
    pub backups: Vec<ProbeTarget>,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub https_timeout_secs: u64,
    pub failure_threshold: u32,
}

// Accept legacy IPv4 strings and a group-wide mode/port; always save the new format.
#[derive(Deserialize)]
#[serde(untagged)]
enum TargetInput {
    Legacy(Ipv4Addr),
    Target(ProbeTarget),
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ProbeInput {
    mode: Option<ProbeMode>,
    tcp_port: Option<u16>,
    primary: Option<TargetInput>,
    backups: Option<Vec<TargetInput>>,
    interval_secs: Option<u64>,
    timeout_secs: Option<u64>,
    https_timeout_secs: Option<u64>,
    failure_threshold: Option<u32>,
}

impl ProbeInput {
    fn apply(self, mut base: ProbeConfig) -> ProbeConfig {
        let mode = self.mode.unwrap_or(ProbeMode::Icmp);
        let convert = |value| match value {
            TargetInput::Target(value) => value,
            TargetInput::Legacy(ip) => ProbeTarget {
                mode,
                address: ip.to_string(),
                port: if mode == ProbeMode::Icmp {
                    None
                } else {
                    Some(self.tcp_port.unwrap_or(53))
                },
            },
        };
        // A legacy group can override mode/port without listing its default addresses.
        if self.mode.is_some() || self.tcp_port.is_some() {
            for target in std::iter::once(&mut base.primary).chain(base.backups.iter_mut()) {
                target.mode = mode;
                target.port = if mode == ProbeMode::Icmp {
                    None
                } else {
                    Some(self.tcp_port.unwrap_or(53))
                };
            }
        }
        if let Some(value) = self.primary {
            base.primary = convert(value);
        }
        if let Some(value) = self.backups {
            base.backups = value.into_iter().map(convert).collect();
        }
        if let Some(value) = self.interval_secs {
            base.interval_secs = value;
        }
        if let Some(value) = self.timeout_secs {
            base.timeout_secs = value;
        }
        if let Some(value) = self.https_timeout_secs {
            base.https_timeout_secs = value;
        }
        if let Some(value) = self.failure_threshold {
            base.failure_threshold = value;
        }
        base
    }
}

impl<'de> Deserialize<'de> for ProbeConfig {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(ProbeInput::deserialize(deserializer)?.apply(Self::default()))
    }
}

impl ProbeConfig {
    fn deserialize_campus<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Ok(ProbeInput::deserialize(deserializer)?.apply(Self::campus()))
    }

    pub fn campus() -> Self {
        Self {
            primary: ProbeTarget {
                mode: ProbeMode::Tcp,
                address: "210.38.139.41".into(),
                port: Some(8081),
            },
            backups: ["jw.gdou.edu.cn", "kjcrms.gdou.edu.cn"]
                .into_iter()
                .map(|address| ProbeTarget {
                    mode: ProbeMode::Https,
                    address: address.into(),
                    port: Some(443),
                })
                .collect(),
            interval_secs: 30,
            failure_threshold: 1,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !(1..=3600).contains(&self.interval_secs)
            || !(1..=30).contains(&self.timeout_secs)
            || !(1..=30).contains(&self.https_timeout_secs)
            || !(1..=10).contains(&self.failure_threshold)
        {
            bail!("探测间隔须为 1–3600 秒，超时为 1–30 秒，失败门槛为 1–10 轮");
        }
        if self.backups.len() > 3 {
            bail!("最多配置 3 个备用目标");
        }
        for target in std::iter::once(&self.primary).chain(&self.backups) {
            target.validate()?;
        }
        Ok(())
    }
}

impl Default for ProbeConfig {
    fn default() -> Self {
        let target = |address: &str| ProbeTarget {
            mode: ProbeMode::Icmp,
            address: address.into(),
            port: None,
        };
        Self {
            primary: target("223.5.5.5"),
            backups: ["119.29.29.29", "180.76.76.76", "223.6.6.6"]
                .into_iter()
                .map(target)
                .collect(),
            interval_secs: 2,
            timeout_secs: 1,
            https_timeout_secs: 3,
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
            campus_probe: ProbeConfig::campus(),
            environment_interval_secs: 30,
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
        for interval in [self.online_interval_secs, self.environment_interval_secs]
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
        self.probe.validate()?;
        self.campus_probe.validate()?;
        Ok(())
    }
}

use anyhow::{bail, Context, Result};
use reqwest::Url;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub username: String,
    pub password: String,
    pub portal_url: String,
    pub ac_id: u32,
    pub interface: Option<String>,
    #[serde(default = "online_interval")]
    pub online_interval_secs: u64,
    #[serde(default = "retry_interval")]
    pub retry_interval_secs: u64,
}

fn online_interval() -> u64 {
    60
}

fn retry_interval() -> u64 {
    15
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

    fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() || self.username.trim() != self.username {
            bail!("username 不能为空或包含首尾空白，请保留完整账号后缀");
        }
        if self.password.is_empty() {
            bail!("password 不能为空");
        }
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
        if self.ac_id == 0 {
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
        for interval in [self.online_interval_secs, self.retry_interval_secs] {
            if !(1..=86400).contains(&interval) {
                bail!("检查和重试间隔必须在 1 到 86400 秒之间");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "username = 'student@campus'\npassword = 'secret'\nportal_url = 'http://10.0.0.1'\nac_id = 17\n";

    #[test]
    fn defaults_and_invalid_config() {
        let config = Config::parse(CONFIG).unwrap();
        assert_eq!(config.online_interval_secs, 60);
        assert_eq!(config.retry_interval_secs, 15);
        assert!(config.interface.is_none());
        for extra in [
            "retry_interval_secs = 0",
            "interface = ''",
            "unknown = true",
        ] {
            assert!(Config::parse(&format!("{CONFIG}{extra}")).is_err());
        }
        assert!(Config::parse(&CONFIG.replace("http://10.0.0.1", "file:///etc/passwd")).is_err());
        assert!(
            Config::parse(&CONFIG.replace("http://10.0.0.1", "http://10.0.0.1/?ac_id=2")).is_err()
        );
    }

    #[test]
    fn malformed_config_does_not_echo_password() {
        let error = Config::parse(&CONFIG.replace("'secret'", "'very-private-password"))
            .err()
            .unwrap();
        assert!(!format!("{error:#}").contains("very-private-password"));
    }
}

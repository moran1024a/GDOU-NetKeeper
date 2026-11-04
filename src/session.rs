use crate::{
    client::{outbound_ip, AccessRejected, SrunClient},
    config::{AuthMode, Config},
    discovery::{self, Detection, Parameters},
    probe,
    protocol::{self, Status},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
    time::Duration,
};
use tokio::time::Instant;

pub const SESSION_PATH: &str = "/var/lib/netkeeper/session.json";

// Private, password-free context of the connection actually maintained by the service.
// It survives stop so settings saved for the next start cannot change logout's target.
#[derive(Clone, Deserialize, Serialize)]
pub struct Session {
    pub pid: u32,
    pub interface: Option<String>,
    pub local_ip: Ipv4Addr,
    pub portal_url: String,
    pub ac_id: Option<u32>,
    pub username: String,
}

impl Session {
    pub fn clear() -> Result<()> {
        match std::fs::remove_file(SESSION_PATH) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("注销已确认，但清理会话记录失败"),
        }
    }

    pub fn read() -> Result<Option<Self>> {
        match std::fs::read(SESSION_PATH) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("会话记录损坏，无法确认原连接参数")?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("无法读取实际会话记录"),
        }
    }

    fn save(&self) -> Result<()> {
        let parent = Path::new(SESSION_PATH).parent().unwrap();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.as_file().sync_all()?;
        file.persist(SESSION_PATH)
            .map_err(|error| error.error)
            .context("保存实际会话失败")?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn config(&self) -> Config {
        Config {
            interface: self.interface.clone(),
            username: self.username.clone(),
            portal_url: self.portal_url.clone(),
            ac_id: self.ac_id.unwrap_or(0),
            auth_mode: AuthMode::Manual,
            ..Config::default()
        }
    }
}

pub struct Authentication<'a> {
    config: &'a Config,
    cached: Option<Session>,
    parameters: Option<Parameters>,
    local_ip: Option<Ipv4Addr>,
    last_discovery: Option<Instant>,
    refresh_parameters: bool,
}

impl<'a> Authentication<'a> {
    pub fn new(config: &'a Config) -> Self {
        let cached = match Session::read() {
            Ok(value) => value.filter(|s| {
                s.interface == config.interface
                    && s.username == config.username
                    && (config.auth_mode == AuthMode::Auto
                        || (s.portal_url == config.portal_url && s.ac_id == Some(config.ac_id)))
            }),
            Err(error) => {
                eprintln!("忽略不可用的历史会话：{error:#}");
                None
            }
        };
        Self {
            config,
            cached,
            parameters: None,
            local_ip: None,
            last_discovery: None,
            refresh_parameters: false,
        }
    }

    fn effective(&self) -> Config {
        let mut config = self.config.clone();
        if config.auth_mode == AuthMode::Auto {
            config.ac_id = 0;
            if let Some(parameters) = &self.parameters {
                config.portal_url = parameters.portal_url.clone();
                config.ac_id = parameters.ac_id;
            } else if let Some(cached) = &self.cached {
                config.portal_url = cached.portal_url.clone();
            }
        }
        config
    }

    pub fn parameters(&self) -> (Option<String>, Option<u32>) {
        let config = self.effective();
        let id = (config.ac_id > 0)
            .then_some(config.ac_id)
            .or_else(|| self.cached.as_ref().and_then(|s| s.ac_id));
        (
            (!config.portal_url.is_empty()).then_some(config.portal_url),
            id,
        )
    }

    fn observe_ip(&mut self, ip: Ipv4Addr) {
        if self.local_ip.is_some_and(|old| old != ip) {
            self.parameters = None;
            self.last_discovery = None;
            self.refresh_parameters = false;
        }
        if self.cached.as_ref().is_some_and(|s| s.local_ip != ip) {
            self.cached = None;
        }
        self.local_ip = Some(ip);
    }

    fn remember(&mut self, config: &Config, ip: Ipv4Addr, confirmed: bool) -> Result<()> {
        self.observe_ip(ip);
        let ac_id = if confirmed && config.ac_id > 0 {
            Some(config.ac_id)
        } else {
            self.cached
                .as_ref()
                .filter(|s| s.portal_url == config.portal_url)
                .and_then(|s| s.ac_id)
        };
        let record = Session {
            pid: std::process::id(),
            interface: config.interface.clone(),
            local_ip: ip,
            portal_url: config.portal_url.clone(),
            ac_id,
            username: config.username.clone(),
        };
        record.save()?;
        self.cached = Some(record);
        // A later confirmed outage must start with fresh parameters, not this cache.
        self.parameters = None;
        self.last_discovery = None;
        self.refresh_parameters = false;
        Ok(())
    }

    fn public_online(&mut self, config: &Config) -> Result<String> {
        let ip = outbound_ip(
            SocketAddr::from((config.probe.primary, 80)),
            config.interface.as_deref(),
        )?;
        self.remember(config, ip, false)?;
        Ok("公网可达；Portal 状态未确认，接入参数以实际会话记录为准，不重复登录".into())
    }

    pub async fn cycle(&mut self) -> Result<String> {
        let result = self.check().await;
        let (portal, id) = self.parameters();
        let context = format!(
            "网卡={}，Portal={}，ac_id={}",
            self.config.interface.as_deref().unwrap_or("跟随系统路由"),
            portal.as_deref().unwrap_or("待识别"),
            id.map(|v| v.to_string()).unwrap_or_else(|| "待确认".into())
        );
        result
            .map(|detail| format!("{detail}；{context}"))
            .with_context(|| format!("认证流程失败（{context}）"))
    }

    async fn check(&mut self) -> Result<String> {
        let mut effective = self.effective();
        let mut offline = false;
        let mut status_error = "尚无可用 Portal".to_owned();
        if !effective.portal_url.is_empty() {
            match SrunClient::new(&effective).await {
                Ok(client) => {
                    self.observe_ip(client.ip);
                    match client.status().await {
                        Ok(state) => match protocol::status(&state) {
                            Status::Online => {
                                client.check_account(&state)?;
                                // IP changes invalidate a previously selected access point.
                                let mut confirmed = effective.clone();
                                if self.config.auth_mode == AuthMode::Auto {
                                    confirmed.ac_id =
                                        self.parameters.as_ref().map(|p| p.ac_id).unwrap_or(0);
                                }
                                self.remember(&confirmed, client.ip, true)?;
                                return Ok("已确认在线".into());
                            }
                            Status::Offline => offline = true,
                            Status::Unknown => {
                                status_error = format!(
                                    "状态接口返回无法识别的认证状态：{}",
                                    client.status_detail(&state)
                                )
                            }
                        },
                        Err(error) => status_error = format!("{error:#}"),
                    }
                }
                Err(error) => status_error = format!("{error:#}"),
            }
        }
        effective = self.effective();
        if !offline && probe::check(&effective).await.reachable {
            let message = self.public_online(&effective)?;
            return Ok(format!("{message}；{status_error}"));
        }

        let auto = self.config.auth_mode == AuthMode::Auto;
        let need_discovery =
            !offline || (auto && (self.parameters.is_none() || self.refresh_parameters));
        if need_discovery {
            if auto && self.refresh_parameters {
                if let Some(last) = self.last_discovery {
                    if last.elapsed() < Duration::from_secs(30) {
                        bail!("接入点或认证设备拒绝请求，等待下一次参数识别（两次识别至少间隔 30 秒）");
                    }
                }
            }
            // Clear unusable candidates before discovery; failures cannot fall back to an old ID.
            if auto {
                self.parameters = None;
            }
            self.last_discovery = Some(Instant::now());
            let detected = discovery::detect(self.config.interface.as_deref())
                .await
                .with_context(|| format!("参数识别失败；此前状态：{status_error}"))?;
            match detected {
                Detection::Online => return self.public_online(&effective),
                Detection::Captive(parameters) => {
                    if auto {
                        self.parameters = Some(parameters);
                    }
                    self.refresh_parameters = false;
                }
            }
        }

        effective = self.effective();
        let client = SrunClient::new(&effective)
            .await
            .context("准备认证出口失败")?;
        // Keep a newly discovered candidate attached to the address used to authenticate.
        if !need_discovery && self.local_ip.is_some_and(|old| old != client.ip) {
            self.observe_ip(client.ip);
            if auto {
                bail!("参数识别期间出口 IP 已改变，等待重新识别");
            }
        }
        if self
            .cached
            .as_ref()
            .is_some_and(|s| s.local_ip != client.ip)
        {
            self.cached = None;
        }
        self.local_ip = Some(client.ip);
        if let Err(error) = client.login().await {
            if auto && error.downcast_ref::<AccessRejected>().is_some() {
                self.refresh_parameters = true;
            }
            return Err(error).context("提交认证失败");
        }
        client.confirm_online().await.context("确认在线失败")?;
        self.remember(&effective, client.ip, true)?;
        Ok("已确认在线".into())
    }
}

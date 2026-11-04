use crate::{
    config::Config,
    protocol::{self, Status},
};
use anyhow::{bail, Context, Result};
use reqwest::{redirect::Policy, Client, Response, Url};
use serde_json::Value;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_BODY: usize = 64 * 1024;

#[derive(Debug)]
pub struct CredentialRejected(String);

impl std::fmt::Display for CredentialRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CredentialRejected {}

#[derive(Debug)]
pub struct AccessRejected(String);

impl std::fmt::Display for AccessRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AccessRejected {}

fn rejection(value: &Value, config: &Config, secrets: &[&str]) -> anyhow::Error {
    let detail = portal_error(value, config, secrets);
    // Only explicit, known account errors pause authentication. Unknown server
    // errors remain retryable; free-form messages are never used to guess.
    match value["error"].as_str().unwrap_or_default() {
        "password_error" | "username_error" | "user_not_exist" | "user_disabled"
        | "account_disabled" => CredentialRejected(detail).into(),
        "login_error"
            if matches!(
                value["error_msg"].as_str(),
                Some("Nas type not found." | "CHALLENGE failed, BAS respond timeout.")
            ) =>
        {
            AccessRejected(detail).into()
        }
        _ => anyhow::anyhow!(detail),
    }
}

pub struct SrunClient<'a> {
    config: &'a Config,
    http: Client,
    pub ip: Ipv4Addr,
}

impl<'a> SrunClient<'a> {
    pub async fn new(config: &'a Config) -> Result<Self> {
        let portal = Url::parse(&config.portal_url)?;
        let (http, ip) = bound_http(&portal, config.interface.as_deref()).await?;
        Ok(Self { config, http, ip })
    }

    pub async fn status(&self) -> Result<Value> {
        self.api("rad_user_info", &[], PROBE_TIMEOUT)
            .await
            .context("查询在线状态失败")
    }

    pub fn status_detail(&self, state: &Value) -> String {
        portal_error(state, self.config, &[])
    }

    pub fn check_account(&self, state: &Value) -> Result<()> {
        if let Some(username) = state["user_name"].as_str().filter(|s| !s.is_empty()) {
            if username != self.config.username {
                bail!("在线账号与当前会话账号不一致，未切换或注销账号");
            }
        }
        Ok(())
    }

    pub async fn confirm_online(&self) -> Result<Value> {
        let mut detail = String::new();
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            match self.status().await {
                Ok(state) => match protocol::status(&state) {
                    Status::Online => {
                        self.check_account(&state)?;
                        return Ok(state);
                    }
                    Status::Offline => detail = "状态接口仍报告离线".into(),
                    Status::Unknown => detail = portal_error(&state, self.config, &[]),
                },
                Err(error) => detail = format!("{error:#}"),
            }
        }
        bail!("登录已被接受，但三次确认仍未证实在线：{detail}")
    }

    pub async fn logout(&self) -> Result<&'static str> {
        let state = self
            .api("rad_user_info", &[], PROBE_TIMEOUT)
            .await
            .context("无法查询登录状态，未发送注销请求")?;
        match protocol::status(&state) {
            Status::Offline => return Ok("当前已经离线，无需注销"),
            Status::Unknown => bail!("认证状态无法识别，未发送注销请求"),
            Status::Online => {}
        }
        self.check_account(&state)?;
        if state["user_name"].as_str().is_none_or(|s| s.is_empty()) {
            bail!("状态接口缺少在线账号，未发送注销请求");
        }
        if self.config.ac_id == 0 {
            bail!("当前会话的 ac_id 尚未确认，未发送注销请求；请手动确认当前认证参数");
        }
        // The Portal may see a translated address when the selected link uses NAT.
        let ip = match state.get("online_ip").and_then(Value::as_str) {
            Some(value) if !value.is_empty() => value
                .parse::<Ipv4Addr>()
                .context("服务器返回的在线 IPv4 无效，未发送注销请求")?,
            _ => self.ip,
        };
        if ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST {
            bail!("服务器返回的在线 IPv4 无效，未发送注销请求");
        }
        let ip = ip.to_string();
        let ac_id = self.config.ac_id.to_string();
        let response = self
            .api(
                "srun_portal",
                &[
                    ("action", "logout"),
                    ("username", &self.config.username),
                    ("ip", &ip),
                    ("ac_id", &ac_id),
                    ("os", "linux"),
                    ("name", "linux"),
                ],
                AUTH_TIMEOUT,
            )
            .await;
        // A disconnected response does not tell us whether the server accepted logout.
        // Send logout only once; allow a short delay for the session state to settle.
        let mut confirmed_online = false;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            let result = self.api("rad_user_info", &[], PROBE_TIMEOUT).await;
            match result.as_ref().map(protocol::status) {
                Ok(Status::Offline) => return Ok("已确认注销校园网"),
                Ok(Status::Online) => confirmed_online = true,
                _ => confirmed_online = false,
            }
        }
        let detail = match response {
            Ok(value) if value["error"] != "ok" => portal_error(&value, self.config, &[]),
            Err(error) => format!("{error:#}"),
            _ => "服务器未确认下线".into(),
        };
        if confirmed_online {
            bail!("注销后仍显示在线：{detail}");
        }
        bail!("无法确认注销结果：{detail}")
    }

    pub async fn login(&self) -> Result<()> {
        if self.config.ac_id == 0 {
            bail!("接入点参数尚未确认，未发送登录请求");
        }
        let ip = self.ip.to_string();
        let ac_id = self.config.ac_id.to_string();
        let challenge = self
            .api(
                "get_challenge",
                &[
                    ("username", &self.config.username),
                    ("ip", &ip),
                    ("ac_id", &ac_id),
                ],
                AUTH_TIMEOUT,
            )
            .await?;
        if challenge.get("error").is_some_and(|v| v != "ok" && v != "") {
            return Err(rejection(&challenge, self.config, &[]).context("Challenge 请求被拒绝"));
        }
        let token = challenge["challenge"]
            .as_str()
            .context("Challenge 响应缺少令牌")?;
        let params = protocol::auth_params(
            &self.config.username,
            &self.config.password,
            &ip,
            self.config.ac_id,
            token,
        )?;
        let secrets = [
            params.password.as_str(),
            params.info.as_str(),
            params.chksum.as_str(),
            token,
        ];
        let response = self
            .api(
                "srun_portal",
                &[
                    ("action", "login"),
                    ("username", &self.config.username),
                    ("password", &params.password),
                    ("info", &params.info),
                    ("chksum", &params.chksum),
                    ("ac_id", &ac_id),
                    ("ip", &ip),
                    ("n", "200"),
                    ("type", "1"),
                    ("double_stack", "0"),
                    ("os", "linux"),
                    ("name", "linux"),
                ],
                AUTH_TIMEOUT,
            )
            .await?;
        if response["error"] != "ok" {
            return Err(rejection(&response, self.config, &secrets).context("Portal 拒绝登录"));
        }
        Ok(())
    }

    async fn api(
        &self,
        endpoint: &str,
        params: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<Value> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string();
        let callback = format!("jQuery1124_{timestamp}");
        let response = self
            .http
            .get(format!(
                "{}/cgi-bin/{endpoint}",
                self.config.portal_url.trim_end_matches('/')
            ))
            .query(params)
            .query(&[("callback", callback.as_str()), ("_", timestamp.as_str())])
            .timeout(timeout)
            .send()
            .await
            // reqwest errors otherwise include the full URL, including login secrets.
            .map_err(reqwest::Error::without_url)
            .with_context(|| format!("{endpoint} 请求失败"))?;
        let body = read_body(response)
            .await
            .with_context(|| format!("{endpoint} 响应读取失败"))?;
        protocol::parse_response(&body, &callback)
            .with_context(|| format!("{endpoint} 响应解析失败"))
    }
}

fn portal_error(value: &Value, config: &Config, secrets: &[&str]) -> String {
    let mut details = Vec::new();
    for field in ["error", "error_msg", "res", "ecode"] {
        let text = match &value[field] {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            _ => continue,
        };
        if text.is_empty() || text == "0" {
            continue;
        }
        let mut text = text;
        for secret in [config.password.as_str(), config.username.as_str()]
            .into_iter()
            .chain(secrets.iter().copied())
        {
            if !secret.is_empty() {
                text = text.replace(secret, "[已省略]");
            }
        }
        let clean: String = text.chars().filter(|c| !c.is_control()).take(200).collect();
        details.push(format!("{field}={clean}"));
    }
    if details.is_empty() {
        "服务器未提供具体原因".into()
    } else {
        details.join("；")
    }
}

pub(crate) async fn bound_http(
    portal: &Url,
    interface: Option<&str>,
) -> Result<(Client, Ipv4Addr)> {
    let host = portal.host_str().context("Portal 缺少主机名")?;
    let port = portal.port_or_known_default().context("Portal 缺少端口")?;
    let address = tokio::time::timeout(AUTH_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .context("Portal DNS 解析超时")?
        .context("Portal DNS 解析失败")?
        .find(SocketAddr::is_ipv4)
        .context("Portal 没有可用 IPv4 地址")?;
    let ip = outbound_ip(address, interface)?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(AUTH_TIMEOUT)
        .local_address(IpAddr::V4(ip))
        // Pin the address selected for this request to the same local route.
        .resolve(host, address);
    if let Some(interface) = interface {
        builder = builder.interface(interface);
    }
    Ok((builder.build().context("无法创建 HTTP 客户端")?, ip))
}

pub(crate) fn outbound_ip(destination: SocketAddr, interface: Option<&str>) -> Result<Ipv4Addr> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if let Some(interface) = interface {
        socket
            .bind_device(Some(interface.as_bytes()))
            .context("无法绑定指定网卡，请检查名称及绑定权限")?;
    }
    // UDP connect selects a local route/address without sending a packet.
    socket
        .connect(&destination.into())
        .context("网卡或通往 Portal 的路由尚未就绪")?;
    match socket.local_addr()?.as_socket().map(|addr| addr.ip()) {
        Some(IpAddr::V4(ip)) if !ip.is_unspecified() => Ok(ip),
        _ => bail!("无法确定当前出口的 IPv4 地址"),
    }
}

pub(crate) async fn read_body(mut response: Response) -> Result<String> {
    if !response.status().is_success() || response.headers().contains_key(reqwest::header::LOCATION)
    {
        bail!(
            "HTTP 响应异常或发生认证跳转（状态 {}）",
            response.status().as_u16()
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(reqwest::Error::without_url)?
    {
        if bytes.len() + chunk.len() > MAX_BODY {
            bail!("响应超过 64 KiB 限制");
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).context("响应不是有效 UTF-8")
}

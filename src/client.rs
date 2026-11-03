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
const PROBE_URL: &str = "http://www.msftconnecttest.com/connecttest.txt";

#[derive(Debug)]
pub struct CredentialRejected(String);

impl std::fmt::Display for CredentialRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CredentialRejected {}

fn rejection(value: &Value, config: &Config, secrets: &[String]) -> anyhow::Error {
    let detail = portal_error(value, config, secrets);
    // Only explicit, known account errors pause authentication. Unknown server
    // errors remain retryable; free-form messages are never used to guess.
    match value["error"].as_str().unwrap_or_default() {
        "password_error" | "username_error" | "user_not_exist" | "user_disabled"
        | "account_disabled" => CredentialRejected(detail).into(),
        _ => anyhow::anyhow!(detail),
    }
}

pub struct SrunClient<'a> {
    config: &'a Config,
    http: Client,
    ip: Ipv4Addr,
    probe_url: String,
}

impl<'a> SrunClient<'a> {
    pub async fn new(config: &'a Config) -> Result<Self> {
        let portal = Url::parse(&config.portal_url)?;
        let host = portal.host_str().context("Portal 缺少主机名")?;
        let port = portal.port_or_known_default().context("Portal 缺少端口")?;
        let address = tokio::time::timeout(AUTH_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .context("Portal DNS 解析超时")?
            .context("Portal DNS 解析失败")?
            .find(SocketAddr::is_ipv4)
            .context("Portal 没有可用 IPv4 地址")?;
        let ip = outbound_ip(address, config.interface.as_deref())?;
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(AUTH_TIMEOUT)
            .local_address(IpAddr::V4(ip))
            // Pin the address used for route selection for this round, avoiding a second DNS result.
            .resolve(host, address);
        if let Some(interface) = &config.interface {
            builder = builder.interface(interface);
        }
        let http = builder.build().context("无法创建 HTTP 客户端")?;
        Ok(Self {
            config,
            http,
            ip,
            probe_url: PROBE_URL.to_owned(),
        })
    }

    pub async fn cycle(&self) -> Result<bool> {
        if self.online().await {
            return Ok(true);
        }
        self.login().await?;
        // The login response alone does not prove the connection is online.
        Ok(self.online().await)
    }

    async fn online(&self) -> bool {
        match self.api("rad_user_info", vec![], PROBE_TIMEOUT).await {
            Ok(value) => match protocol::status(&value) {
                Status::Online => return true,
                Status::Offline => return false,
                Status::Unknown => {}
            },
            Err(error) => eprintln!("状态接口暂不可用：{error:#}"),
        }
        // Only fall back on an unknown/error status. A captive portal's HTTP 200 is not enough.
        let response = self
            .http
            .get(&self.probe_url)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await;
        match response {
            Ok(response) => read_body(response)
                .await
                .is_ok_and(|body| body.trim() == "Microsoft Connect Test"),
            Err(_) => false,
        }
    }

    async fn login(&self) -> Result<()> {
        let ip = self.ip.to_string();
        let ac_id = self.config.ac_id.to_string();
        let challenge = self
            .api(
                "get_challenge",
                vec![
                    ("username", self.config.username.clone()),
                    ("ip", ip.clone()),
                    ("ac_id", ac_id.clone()),
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
            params.password.clone(),
            params.info.clone(),
            params.chksum.clone(),
            token.to_owned(),
        ];
        let response = self
            .api(
                "srun_portal",
                vec![
                    ("action", "login".into()),
                    ("username", self.config.username.clone()),
                    ("password", params.password),
                    ("info", params.info),
                    ("chksum", params.chksum),
                    ("ac_id", ac_id),
                    ("ip", ip),
                    ("n", "200".into()),
                    ("type", "1".into()),
                    ("double_stack", "0".into()),
                    ("os", "linux".into()),
                    ("name", "linux".into()),
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
        mut params: Vec<(&str, String)>,
        timeout: Duration,
    ) -> Result<Value> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string();
        let callback = format!("jQuery1124_{timestamp}");
        params.push(("callback", callback.clone()));
        params.push(("_", timestamp));
        let response = self
            .http
            .get(format!(
                "{}/cgi-bin/{endpoint}",
                self.config.portal_url.trim_end_matches('/')
            ))
            .query(&params)
            .timeout(timeout)
            .send()
            .await
            // reqwest errors otherwise include the full URL, including login secrets.
            .map_err(reqwest::Error::without_url)
            .with_context(|| format!("{endpoint} 请求失败"))?;
        let body = read_body(response).await?;
        protocol::parse_response(&body, &callback)
    }
}

fn portal_error(value: &Value, config: &Config, secrets: &[String]) -> String {
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
        for secret in [&config.password, &config.username]
            .into_iter()
            .chain(secrets)
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

fn outbound_ip(destination: SocketAddr, interface: Option<&str>) -> Result<Ipv4Addr> {
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

async fn read_body(mut response: Response) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    #[tokio::test]
    async fn rejection_reason_is_reported_without_credentials() {
        let (config, server) = mock_portal(vec![]).await;
        let value = serde_json::json!({"error": "password_error", "error_msg": format!("bad password for {}: {}\u{1b}", config.username, config.password), "ecode": 42});
        let detail = portal_error(&value, &config, &[]);
        assert!(detail.contains("password_error") && detail.contains("ecode=42"));
        assert!(!detail.contains(&config.password) && !detail.contains(&config.username));
        assert!(!detail.contains('\u{1b}'));
        assert!(rejection(&value, &config, &[]).is::<CredentialRejected>());
        let unknown = serde_json::json!({"error": "unknown", "error_msg": "password_error"});
        assert!(!rejection(&unknown, &config, &[]).is::<CredentialRejected>());
        requests(server).await;
    }

    // Loopback only; replies are supplied by each test, never by the campus network.
    async fn mock_portal(replies: Vec<(u16, &'static str)>) -> (Config, JoinHandle<Vec<Url>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in replies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0u8; 2048];
                    let size = stream.read(&mut buffer).await.unwrap();
                    assert!(size > 0 && request.len() < MAX_BODY);
                    request.extend_from_slice(&buffer[..size]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8(request).unwrap();
                let path = text.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&format!("http://{addr}{path}")).unwrap();
                let callback = url
                    .query_pairs()
                    .find(|(key, _)| key == "callback")
                    .map(|(_, value)| value.into_owned());
                let body = if body.starts_with('{') {
                    format!("{}({body});", callback.unwrap())
                } else {
                    body.to_owned()
                };
                requests.push(url);
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        let config = Config {
            username: "student@campus".into(),
            password: "p+&=/密".into(),
            portal_url: format!("http://{addr}"),
            ac_id: 17,
            ..Config::default()
        };
        (config, server)
    }

    async fn cycle(config: &Config) -> Result<bool> {
        let mut client = SrunClient::new(config).await?;
        client.probe_url = format!("{}/connecttest.txt", config.portal_url);
        tokio::time::timeout(Duration::from_secs(3), client.cycle())
            .await
            .unwrap()
    }

    async fn requests(server: JoinHandle<Vec<Url>>) -> Vec<Url> {
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn already_online_skips_login() {
        let (config, server) = mock_portal(vec![(200, r#"{"error":"ok"}"#)]).await;
        assert!(cycle(&config).await.unwrap());
        let requests = requests(server).await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].path(), "/cgi-bin/rad_user_info");
    }

    #[tokio::test]
    async fn login_encodes_query_once_and_confirms_online() {
        let (config, server) = mock_portal(vec![
            (200, r#"{"error":"not_online"}"#),
            (
                200,
                r#"{"error":"ok","challenge":"0123456789abcdef0123456789abcdef"}"#,
            ),
            (200, r#"{"error":"ok","res":0}"#),
            (200, r#"{"error":"ok"}"#),
        ])
        .await;
        assert!(cycle(&config).await.unwrap());
        let requests = requests(server).await;
        assert_eq!(
            requests.iter().map(|r| r.path()).collect::<Vec<_>>(),
            [
                "/cgi-bin/rad_user_info",
                "/cgi-bin/get_challenge",
                "/cgi-bin/srun_portal",
                "/cgi-bin/rad_user_info",
            ]
        );
        let params: std::collections::HashMap<_, _> =
            requests[2].query_pairs().into_owned().collect();
        let auth = protocol::auth_params(
            &config.username,
            &config.password,
            "127.0.0.1",
            17,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(params["info"], auth.info);
        assert_eq!(params["chksum"], auth.chksum);
        assert_eq!(params["username"], config.username);
        assert_eq!(params["ip"], "127.0.0.1");
        assert_eq!(params["password"], auth.password);
    }

    #[tokio::test]
    async fn login_acceptance_without_online_status_is_not_success() {
        let (config, server) = mock_portal(vec![
            (200, r#"{"error":"offline"}"#),
            (200, r#"{"challenge":"0123456789abcdef"}"#),
            (200, r#"{"error":"ok"}"#),
            (200, r#"{"error":"notonline"}"#),
        ])
        .await;
        assert!(!cycle(&config).await.unwrap());
        assert_eq!(requests(server).await.len(), 4);
    }

    #[tokio::test]
    async fn unknown_status_falls_back_to_exact_probe_body() {
        let (config, server) = mock_portal(vec![
            (200, r#"{"error":"busy"}"#),
            (200, "Microsoft Connect Test\n"),
        ])
        .await;
        assert!(cycle(&config).await.unwrap());
        assert_eq!(requests(server).await[1].path(), "/connecttest.txt");
    }

    #[tokio::test]
    async fn captive_http_200_and_redirect_do_not_confirm_online() {
        for probe in [(200, "<html>login</html>"), (302, "Microsoft Connect Test")] {
            let (config, server) = mock_portal(vec![
                (503, "busy"),
                probe,
                (
                    200,
                    r#"{"error":"challenge_error","error_msg":"private-server-text"}"#,
                ),
            ])
            .await;
            let error = cycle(&config).await.unwrap_err();
            assert!(format!("{error:#}").contains("challenge_error"));
            assert_eq!(requests(server).await[2].path(), "/cgi-bin/get_challenge");
        }
    }

    #[tokio::test]
    async fn each_retry_obtains_a_new_challenge() {
        let (config, server) = mock_portal(vec![
            (200, r#"{"error":"offline"}"#),
            (200, r#"{"challenge":"1111111111111111"}"#),
            (200, r#"{"error":"denied"}"#),
            (200, r#"{"error":"offline"}"#),
            (200, r#"{"challenge":"2222222222222222"}"#),
            (200, r#"{"error":"ok"}"#),
            (200, r#"{"error":"ok"}"#),
        ])
        .await;
        assert!(cycle(&config).await.is_err());
        assert!(cycle(&config).await.unwrap());
        let requests = requests(server).await;
        let info = |index: usize| {
            requests[index]
                .query_pairs()
                .find(|(key, _)| key == "info")
                .unwrap()
                .1
                .into_owned()
        };
        assert_ne!(info(2), info(5));
    }

    #[tokio::test]
    async fn nonexistent_interface_never_falls_back_to_default_route() {
        let (mut config, server) = mock_portal(vec![]).await;
        config.interface = Some("nk-missing0".into());
        assert!(SrunClient::new(&config).await.is_err());
        requests(server).await;
    }
}

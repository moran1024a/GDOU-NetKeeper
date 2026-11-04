use crate::client::{bound_http, read_body};
use anyhow::{bail, Context, Result};
use reqwest::Url;
use std::{
    collections::{HashSet, VecDeque},
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_LIMIT: usize = 6;
const PROBES: [(&str, &str); 2] = [
    ("www.msftconnecttest.com", "/connecttest.txt"),
    ("neverssl.com", "/"),
];

#[derive(Clone)]
pub struct Parameters {
    pub portal_url: String,
    pub ac_id: u32,
}

pub enum Detection {
    Captive(Parameters),
    Online,
}

// Discovery only reads pages. Never follow authentication actions or run page scripts.
fn page_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).context("请输入完整的 http(s) 认证页面地址")?;
    let path = url.path().to_ascii_lowercase();
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || path.contains("/cgi-bin/")
        || path.contains("logout")
        || path.contains("logoff")
        || url.query_pairs().any(|(key, _)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "action" | "password" | "username" | "info" | "chksum"
            )
        })
    {
        bail!("只接受认证页面地址，不能包含账号、密码或登录/注销操作");
    }
    url.set_fragment(None);
    Ok(url)
}

fn query_id(url: &Url) -> Option<u32> {
    if probe_host(url) {
        return None;
    }
    let mut found = None;
    for (_, value) in url.query_pairs().filter(|(key, _)| key == "ac_id") {
        let id = value.parse::<u32>().ok().filter(|id| *id > 0)?;
        if found.is_some_and(|previous| previous != id) {
            return None;
        }
        found = Some(id);
    }
    found
}

fn probe_host(url: &Url) -> bool {
    PROBES.iter().any(|(host, _)| url.host_str() == Some(*host))
}

fn parameters(url: &Url, ac_id: u32) -> Parameters {
    Parameters {
        portal_url: url.origin().ascii_serialization(),
        ac_id,
    }
}

pub fn from_link(value: &str) -> Result<Parameters> {
    let url = page_url(value.trim())?;
    let ac_id = query_id(&url).context("链接中没有唯一有效的 ac_id，请手动填写")?;
    Ok(parameters(&url, ac_id))
}

fn inline_id(body: &str) -> Option<u32> {
    let tokens = body
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|s| !s.is_empty());
    let mut previous = "";
    let mut found = None;
    for token in tokens {
        if previous == "ac_id" {
            if let Some(id) = token.parse::<u32>().ok().filter(|id| *id > 0) {
                if found.is_some_and(|previous| previous != id) {
                    return None;
                }
                found = Some(id);
            }
        }
        previous = token;
    }
    found
}

fn page_links(base: &Url, body: &str) -> Vec<Url> {
    let decoded = body
        .replace("&amp;", "&")
        .replace("&#38;", "&")
        .replace("\\/", "/");
    let lower = decoded.to_ascii_lowercase();
    let mut values = Vec::new();
    // Common meta-refresh and literal JavaScript redirects, parsed as text only.
    for marker in [
        "url=",
        "location.href",
        "location.replace(",
        "location.assign(",
        "location =",
        "location=",
    ] {
        for (index, _) in lower.match_indices(marker) {
            let rest = decoded[index + marker.len()..].trim_start_matches(|c: char| {
                c.is_ascii_whitespace() || matches!(c, '=' | '(' | '\'' | '"')
            });
            values.push(
                rest.split(|c: char| {
                    c.is_ascii_whitespace() || matches!(c, '\'' | '"' | '<' | '>' | ')')
                })
                .next()
                .unwrap_or(""),
            );
        }
    }
    // Authentication links may appear inside an HTML attribute or a JS string.
    values.extend(
        decoded
            .split(['\'', '"', '<', '>', '\n', '\r'])
            .map(str::trim)
            .filter(|value| {
                value.contains("ac_id=")
                    && (value.starts_with("http://")
                        || value.starts_with("https://")
                        || value.starts_with('/')
                        || value.starts_with('?'))
            }),
    );
    values
        .into_iter()
        .filter_map(|value| base.join(value).ok())
        .filter_map(|url| page_url(url.as_str()).ok())
        .collect()
}

pub async fn discover(interface: Option<&str>) -> Result<Parameters> {
    match detect(interface).await? {
        Detection::Captive(parameters) => Ok(parameters),
        Detection::Online => {
            bail!("公网已连通，没有未认证跳转；接入参数将在掉认证后确认，也可手动导入当前认证链接")
        }
    }
}

pub async fn detect(interface: Option<&str>) -> Result<Detection> {
    // Only a fresh redirect from this interface's public path identifies its AC.
    // A saved Portal root may redirect to a generic, unrelated access point.
    let seeds = PROBES
        .iter()
        .map(|(host, path)| Url::parse(&format!("http://{host}{path}")).expect("probe URL"))
        .collect();
    tokio::time::timeout(TIMEOUT, discover_at(interface, seeds))
        .await
        .context("自动识别超过 10 秒，请粘贴认证页面链接或手动填写")?
}

async fn discover_at(interface: Option<&str>, seeds: Vec<Url>) -> Result<Detection> {
    let mut pending: VecDeque<_> = seeds.into();
    let mut visited = HashSet::new();
    let mut last_error = None;
    while visited.len() < REQUEST_LIMIT {
        let Some(url) = pending.pop_front() else {
            break;
        };
        if !visited.insert(url.to_string()) {
            continue;
        }
        if let Some(ac_id) = query_id(&url) {
            return Ok(Detection::Captive(parameters(&url, ac_id)));
        }
        let response = async {
            let (http, _) = bound_http(&url, interface).await?;
            http.get(url.clone())
                .timeout(Duration::from_secs(2))
                .send()
                .await
                .map_err(reqwest::Error::without_url)
                .context("读取认证页面失败")
        }
        .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if response.status().is_redirection() {
            if let Some(target) = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| url.join(value).ok())
                .and_then(|url| page_url(url.as_str()).ok())
            {
                if let Some(ac_id) = query_id(&target) {
                    return Ok(Detection::Captive(parameters(&target, ac_id)));
                }
                pending.push_front(target);
            }
            continue;
        }
        let body = match read_body(response).await {
            Ok(body) => body,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        if url.host_str() == Some(PROBES[0].0) && body.trim() == "Microsoft Connect Test" {
            return Ok(Detection::Online);
        }
        let links = page_links(&url, &body);
        let mut found = None;
        for candidate in links
            .iter()
            .filter_map(|link| query_id(link).map(|id| (link.origin().ascii_serialization(), id)))
        {
            if found
                .as_ref()
                .is_some_and(|previous| *previous != candidate)
            {
                bail!("发现多组认证参数，请粘贴当前认证页面链接确认");
            }
            found = Some(candidate);
        }
        if let Some((portal_url, ac_id)) = found {
            return Ok(Detection::Captive(Parameters { portal_url, ac_id }));
        }
        // An intercepted HTTP 200 does not make the public probe host a Portal.
        if !probe_host(&url) && body.to_ascii_lowercase().contains("srun") {
            if let Some(ac_id) = inline_id(&body) {
                return Ok(Detection::Captive(parameters(&url, ac_id)));
            }
        }
        for link in links.into_iter().rev().take(REQUEST_LIMIT) {
            pending.push_front(link);
        }
    }
    let detail = last_error
        .map(|e| format!("；最近错误：{e:#}"))
        .unwrap_or_default();
    bail!("未从当前网卡的认证跳转取得完整参数；请检查网络，或切换手动模式填写当前认证参数{detail}")
}

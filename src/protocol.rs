// SRUN authentication parameters and JSON/JSONP response parsing.
use anyhow::{bail, Context, Result};
use base64::{
    alphabet::Alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use hmac::{Hmac, Mac};
use md5::Md5;
use serde_json::Value;
use sha1::{Digest, Sha1};

const ALPHABET: &str = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

pub struct AuthParams {
    pub password: String,
    pub info: String,
    pub chksum: String,
}

pub fn auth_params(
    username: &str,
    password: &str,
    ip: &str,
    ac_id: u32,
    token: &str,
) -> Result<AuthParams> {
    if token.is_empty() {
        bail!("Challenge 令牌为空");
    }
    let mut mac = Hmac::<Md5>::new_from_slice(token.as_bytes()).context("无法初始化 HMAC")?;
    mac.update(password.as_bytes());
    let hmd5 = format!("{:x}", mac.finalize().into_bytes());
    // serde_json's default map sorts keys: acid, enc_ver, ip, password, username.
    let json = serde_json::json!({
        "acid": ac_id.to_string(), "enc_ver": "srun_bx1", "ip": ip,
        "password": password, "username": username,
    })
    .to_string();
    let engine = GeneralPurpose::new(
        &Alphabet::new(ALPHABET).expect("valid alphabet"),
        GeneralPurposeConfig::new(),
    );
    let info = format!(
        "{{SRBX1}}{}",
        engine.encode(encode_info(json.as_bytes(), token.as_bytes()))
    );
    let chksum = format!(
        "{:x}",
        Sha1::digest(
            format!(
        "{token}{username}{token}{hmd5}{token}{ac_id}{token}{ip}{token}200{token}1{token}{info}"
    )
            .as_bytes()
        )
    );
    Ok(AuthParams {
        password: format!("{{MD5}}{hmd5}"),
        info,
        chksum,
    })
}

fn encode_info(payload: &[u8], token: &[u8]) -> Vec<u8> {
    // Pack UTF-8 bytes into little-endian words and append the unpadded byte length.
    let mut words = vec![0u32; payload.len().div_ceil(4)];
    for (offset, byte) in payload.iter().enumerate() {
        words[offset / 4] |= u32::from(*byte) << (8 * (offset % 4));
    }
    words.push(payload.len() as u32);
    let count = words.len();
    let mut secret = [0u32; 4];
    for (offset, byte) in token.iter().take(16).enumerate() {
        secret[offset / 4] |= u32::from(*byte) << (8 * (offset % 4));
    }

    let mut previous = words[count - 1];
    for round in 1..=(6 + 52 / count) {
        let sum = 0x9e3779b9u32.wrapping_mul(round as u32);
        let selector = ((sum >> 2) & 3) as usize;
        let mut index = 0;
        while index < count {
            let next = words[if index + 1 == count { 0 } else { index + 1 }];
            let shifts = (previous >> 5) ^ next.wrapping_shl(2);
            let cross = (next >> 3) ^ previous.wrapping_shl(4) ^ sum ^ next;
            let keyed = secret[(index % 4) ^ selector] ^ previous;
            words[index] = words[index]
                .wrapping_add(shifts)
                .wrapping_add(cross)
                .wrapping_add(keyed);
            previous = words[index];
            index += 1;
        }
    }
    let mut output = Vec::with_capacity(count * 4);
    for word in words {
        output.extend_from_slice(&word.to_le_bytes());
    }
    output
}

pub fn parse_response(raw: &str, callback: &str) -> Result<Value> {
    let raw = raw.trim();
    let json = if raw.starts_with('{') {
        raw
    } else {
        raw.strip_prefix(callback)
            .and_then(|s| s.trim_start().strip_prefix('('))
            .and_then(|s| {
                s.trim_end()
                    .trim_end_matches(';')
                    .trim_end()
                    .strip_suffix(')')
            })
            .context("Portal 响应不是预期的 JSON/JSONP")?
    };
    let value: Value = serde_json::from_str(json).context("Portal JSON 解析失败")?;
    if !value.is_object() {
        bail!("Portal 响应必须是 JSON 对象");
    }
    Ok(value)
}

pub enum Status {
    Online,
    Offline,
    Unknown,
}

pub fn status(value: &Value) -> Status {
    match value["error"]
        .as_str()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "ok" => Status::Online,
        "not_online" | "not_online_error" | "notonline" | "offline" => Status::Offline,
        _ => Status::Unknown,
    }
}

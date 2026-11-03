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

#[derive(Debug, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_protocol_vectors_including_utf8_and_padding() {
        // Fixed vectors cover UTF-8, special characters and Base64 padding.
        let cases = [
            ("student@campus", "password123", "{MD5}e0f9482af0422eecc1d12f18fe0cad89",
             "{SRBX1}DTkrWWUhPMTGapLZmNzOG/PwWw9vmcFEPPG2mVx1xekcbfvZU116v1hyfb8AXBOtDSl2OlxzW7jzNIerejG77RsSZlxxUxhDUB3HToALZ+S7BfAkn6QRxgxhv5EUI6ZaH++WPefSwB5yapPzL8yXhv==",
             "c0afeb9e6078b363e46a7e689eccaa8525386497"),
            ("测试@campus", "p+&=/密", "{MD5}ffae8140404782529394022f0b728f0f",
             "{SRBX1}5dqxkKc5501dcs173W1PHz3+WQJ9LLuy2rhdKgYbEuYNmGHCRNUhtUFeQH6huC+uqtFmxMqK8tctYzzPCXCc/uskIdsRLJC6P7FpEQVf1Eg6LCLujJUPyMrHB1pg2ak0cKUT0q8tdmPLrovP",
             "18971b729d05c89fbb6451ebf76ec9b2d3763941"),
        ];
        for (username, password, expected_password, expected_info, expected_checksum) in cases {
            let actual = auth_params(
                username,
                password,
                "10.20.30.40",
                17,
                "0123456789abcdef0123456789abcdef",
            )
            .unwrap();
            assert_eq!(actual.password, expected_password);
            assert_eq!(actual.info, expected_info);
            assert_eq!(actual.chksum, expected_checksum);
        }
    }

    #[test]
    fn jsonp_and_status_variants() {
        for text in [
            r#"{"error":"ok","res":0}"#,
            r#"cb({"error":"ok","res":0});"#,
        ] {
            assert_eq!(status(&parse_response(text, "cb").unwrap()), Status::Online);
        }
        for code in ["not_online", "not_online_error", "notonline", "offline"] {
            assert_eq!(status(&serde_json::json!({"error": code})), Status::Offline);
        }
        assert_eq!(
            status(&serde_json::json!({"error":"server_busy"})),
            Status::Unknown
        );
        for text in ["cb({});evil()", "other({})", "cb([])", "<html>login</html>"] {
            assert!(parse_response(text, "cb").is_err());
        }
        assert!(auth_params("user", "password", "10.0.0.2", 1, "").is_err());
    }
}

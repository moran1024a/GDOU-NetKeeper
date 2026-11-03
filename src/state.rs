use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const STATE_DIR: &str = "/run/netkeeper";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Starting,
    Online,
    Retrying,
    Failed,
    Stopped,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct State {
    pub pid: u32,
    pub phase: Phase,
    pub interface: Option<String>,
    pub checked_at: u64,
    #[serde(default)]
    pub generation: u64,
    pub detail: String,
}

impl State {
    pub fn new(interface: Option<String>) -> Self {
        Self {
            pid: std::process::id(),
            phase: Phase::Starting,
            interface,
            checked_at: 0,
            generation: 0,
            detail: "正在启动".into(),
        }
    }

    pub fn update(&mut self, directory: &Path, phase: Phase, detail: &str) -> Result<()> {
        self.phase = phase;
        self.checked_at = now();
        self.generation += 1;
        self.detail = detail.to_owned();
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))?;
        file.write_all(&serde_json::to_vec(self)?)?;
        file.persist(directory.join("status.json"))
            .map_err(|error| error.error)
            .context("写入运行状态失败")?;
        Ok(())
    }

    pub fn read(directory: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(directory.join("status.json")).ok()?).ok()
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

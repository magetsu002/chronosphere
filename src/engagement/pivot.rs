use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    #[default]
    Local,
    Remote,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionMode::Local => "local",
            ExecutionMode::Remote => "remote",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "local" => Some(ExecutionMode::Local),
            "remote" => Some(ExecutionMode::Remote),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Pivot {
    /// Short label (e.g. `web01`, `foothold`).
    pub name: String,
    pub ssh_host: Option<String>,
    pub ssh_user: Option<String>,
    pub ssh_port: Option<u16>,
    pub ssh_identity: Option<String>,
    /// Plaintext SSH password (optional; remote exec uses sshpass when set).
    pub ssh_password: Option<String>,
    /// ligolo-ng TUN interface on operator (e.g. `ligolo`).
    pub ligolo_interface: Option<String>,
    /// Operator listener (e.g. `0.0.0.0:11601`).
    pub ligolo_server_addr: Option<String>,
    #[serde(default)]
    pub ligolo_routes: Vec<String>,
    /// Path to agent binary on foothold.
    pub agent_path: Option<String>,
    pub notes: Option<String>,
}

impl Pivot {
    pub fn has_ssh(&self) -> bool {
        self.ssh_host.as_deref().is_some_and(|s| !s.is_empty())
            && self.ssh_user.as_deref().is_some_and(|s| !s.is_empty())
    }

    pub fn ssh_spec(&self) -> Option<String> {
        if !self.has_ssh() {
            return None;
        }
        let user = self.ssh_user.as_deref()?;
        let host = self.ssh_host.as_deref()?;
        Some(format!("{}@{}", user, host))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PivotStore {
    pub pivots: Vec<Pivot>,
    /// Pivot whose ligolo tunnel routes are marked active.
    pub active_tunnel: Option<String>,
    /// Pivot that receives scp/ssh remote scripts.
    pub active_remote: Option<String>,
    #[serde(default)]
    pub execution_mode: ExecutionMode,
}

impl PivotStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let v: Self = serde_json::from_str(&s).context("parse pivots.json")?;
        Ok(v)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self).context("serialize pivots")?;
        crate::security::write_private_atomic(path, s.as_bytes())
    }

    pub fn upsert(&mut self, p: Pivot) {
        if let Some(slot) = self.pivots.iter_mut().find(|x| x.name == p.name) {
            *slot = p;
        } else {
            let name = p.name.clone();
            self.pivots.push(p);
            if self.active_tunnel.is_none() {
                self.active_tunnel = Some(name.clone());
            }
            if self.active_remote.is_none() {
                self.active_remote = Some(name);
            }
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.pivots.retain(|p| p.name != name);
        if self.active_tunnel.as_deref() == Some(name) {
            self.active_tunnel = self.pivots.first().map(|p| p.name.clone());
        }
        if self.active_remote.as_deref() == Some(name) {
            self.active_remote = self.pivots.first().map(|p| p.name.clone());
        }
    }

    pub fn set_active_tunnel(&mut self, name: &str) -> bool {
        if self.pivots.iter().any(|p| p.name == name) {
            self.active_tunnel = Some(name.to_string());
            true
        } else {
            false
        }
    }

    pub fn set_active_remote(&mut self, name: &str) -> bool {
        if self.pivots.iter().any(|p| p.name == name) {
            self.active_remote = Some(name.to_string());
            true
        } else {
            false
        }
    }

    pub fn clear_active_tunnel(&mut self) {
        self.active_tunnel = None;
    }

    pub fn active_tunnel(&self) -> Option<&Pivot> {
        let n = self.active_tunnel.as_ref()?;
        self.pivots.iter().find(|p| &p.name == n)
    }

    pub fn active_remote(&self) -> Option<&Pivot> {
        let n = self.active_remote.as_ref()?;
        self.pivots.iter().find(|p| &p.name == n)
    }

    pub fn is_tunnel_active(&self) -> bool {
        self.active_tunnel.is_some()
    }

    pub fn is_remote_execution(&self) -> bool {
        self.execution_mode == ExecutionMode::Remote
    }
}

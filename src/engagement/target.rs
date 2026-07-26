use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Target {
    /// Short label used by the user (e.g. `dc01`, `web01`).
    pub name: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub dc_name: Option<String>,
    pub lhost: Option<String>,
    pub lport: Option<u16>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetStore {
    pub targets: Vec<Target>,
    /// Name of the active target (must match one of `targets[i].name`).
    pub active: Option<String>,
}

impl TargetStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let v: Self = serde_json::from_str(&s).context("parse targets.json")?;
        Ok(v)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self).context("serialize targets")?;
        crate::security::write_private_atomic(path, s.as_bytes())
    }

    pub fn upsert(&mut self, t: Target) {
        if let Some(slot) = self.targets.iter_mut().find(|x| x.name == t.name) {
            *slot = t;
        } else {
            let name = t.name.clone();
            self.targets.push(t);
            if self.active.is_none() {
                self.active = Some(name);
            }
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.targets.retain(|t| t.name != name);
        if self.active.as_deref() == Some(name) {
            self.active = self.targets.first().map(|t| t.name.clone());
        }
    }

    pub fn set_active(&mut self, name: &str) -> bool {
        if self.targets.iter().any(|t| t.name == name) {
            self.active = Some(name.to_string());
            true
        } else {
            false
        }
    }

    pub fn active(&self) -> Option<&Target> {
        let n = self.active.as_ref()?;
        self.targets.iter().find(|t| &t.name == n)
    }

    pub fn active_mut(&mut self) -> Option<&mut Target> {
        let n = self.active.clone()?;
        self.targets.iter_mut().find(|t| t.name == n)
    }
}

/// Best-effort autodetect of the tun0 IPv4 address (typical for HTB / VPN engagements).
/// Returns None if the interface doesn't exist or parsing fails.
pub fn detect_tun0_ip() -> Option<String> {
    // Try `ip -4 addr show tun0` first (Linux), fall back to `ifconfig tun0` (macOS).
    let try_ip = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", "tun0"])
        .output();
    if let Ok(out) = try_ip {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(ip) = parse_ip_addr_output(&s) {
                return Some(ip);
            }
        }
    }
    let try_ifc = std::process::Command::new("ifconfig").arg("tun0").output();
    if let Ok(out) = try_ifc {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(ip) = parse_ifconfig_output(&s) {
                return Some(ip);
            }
        }
    }
    None
}

fn parse_ip_addr_output(s: &str) -> Option<String> {
    // e.g. `12: tun0    inet 10.10.14.5/23 brd ...`
    s.split_whitespace()
        .skip_while(|t| *t != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next().map(|s| s.to_string()))
}

fn parse_ifconfig_output(s: &str) -> Option<String> {
    for line in s.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            if let Some(ip) = rest.split_whitespace().next() {
                if !ip.starts_with("127.") {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

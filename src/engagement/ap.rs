use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessPoint {
    /// Short label (e.g. `htw`, `guest`).
    pub name: String,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub channel: Option<String>,
    /// Client MAC when targeting a station (deauth, etc.).
    pub station: Option<String>,
    /// Cracked WPA/WPA2 PSK or hex key from WPS/reaver/OneShot.
    pub wpa_psk: Option<String>,
    pub wps_pin: Option<String>,
    /// Base path for captures/handshakes (e.g. `captures/htw`).
    pub capture: Option<String>,
    pub vendor: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApStore {
    pub aps: Vec<AccessPoint>,
    /// Name of the active AP (must match one of `aps[i].name`).
    pub active: Option<String>,
}

impl ApStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let v: Self = serde_json::from_str(&s).context("parse aps.json")?;
        Ok(v)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self).context("serialize aps")?;
        crate::security::write_private_atomic(path, s.as_bytes())
    }

    pub fn upsert(&mut self, ap: AccessPoint) {
        if let Some(slot) = self.aps.iter_mut().find(|x| x.name == ap.name) {
            *slot = ap;
        } else {
            let name = ap.name.clone();
            self.aps.push(ap);
            if self.active.is_none() {
                self.active = Some(name);
            }
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.aps.retain(|a| a.name != name);
        if self.active.as_deref() == Some(name) {
            self.active = self.aps.first().map(|a| a.name.clone());
        }
    }

    pub fn set_active(&mut self, name: &str) -> bool {
        if self.aps.iter().any(|a| a.name == name) {
            self.active = Some(name.to_string());
            true
        } else {
            false
        }
    }

    pub fn active(&self) -> Option<&AccessPoint> {
        let n = self.active.as_ref()?;
        self.aps.iter().find(|a| &a.name == n)
    }

    pub fn active_mut(&mut self) -> Option<&mut AccessPoint> {
        let n = self.active.clone()?;
        self.aps.iter_mut().find(|a| a.name == n)
    }
}

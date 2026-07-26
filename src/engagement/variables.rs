use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Engagement-scoped template placeholders (`{wordlist}`, `{bssid}`, …).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VariableStore {
    pub values: BTreeMap<String, String>,
}

impl VariableStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let v: Self = serde_json::from_str(&s).context("parse variables.json")?;
        Ok(v)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self).context("serialize variables")?;
        crate::security::write_private_atomic(path, s.as_bytes())
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(|s| s.as_str())
    }

    pub fn set(&mut self, name: String, value: String) {
        if value.is_empty() {
            self.values.remove(&name);
        } else {
            self.values.insert(name, value);
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.values.remove(name);
    }
}

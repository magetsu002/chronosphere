use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CredKind {
    Plaintext,
    Ntlm,
    Kerberos,
    /// Unauthenticated / placeholder profile (e.g. "guest").
    None,
}

impl CredKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CredKind::Plaintext => "plaintext",
            CredKind::Ntlm => "ntlm",
            CredKind::Kerberos => "kerberos",
            CredKind::None => "none",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProfile {
    pub name: String,
    pub username: String,
    pub domain: Option<String>,
    pub kind: CredKind,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    pub ticket_path: Option<String>,
    pub notes: Option<String>,
}

impl CredentialProfile {
    pub fn placeholder_guest() -> Self {
        Self {
            name: "guest".to_string(),
            username: "guest".to_string(),
            domain: None,
            kind: CredKind::None,
            password: None,
            nt_hash: None,
            ticket_path: None,
            notes: Some("unauthenticated baseline".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileStore {
    pub profiles: Vec<CredentialProfile>,
    pub active: Option<String>,
}

impl ProfileStore {
    pub fn new() -> Self {
        let mut s = Self::default();
        let guest = CredentialProfile::placeholder_guest();
        s.active = Some(guest.name.clone());
        s.profiles.push(guest);
        s
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let v: Self = serde_json::from_str(&s).context("parse creds.json")?;
        Ok(v)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self).context("serialize profiles")?;
        crate::security::write_private_atomic(path, s.as_bytes())
    }

    pub fn upsert(&mut self, profile: CredentialProfile) {
        let name = profile.name.clone();
        if let Some(slot) = self.profiles.iter_mut().find(|p| p.name == name) {
            *slot = profile;
        } else {
            self.profiles.push(profile);
        }
        if self.active.is_none() {
            self.active = Some(name);
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.profiles.retain(|p| p.name != name);
        if self.active.as_deref() == Some(name) {
            self.active = self.profiles.first().map(|p| p.name.clone());
        }
    }

    pub fn set_active(&mut self, name: &str) -> bool {
        if self.profiles.iter().any(|p| p.name == name) {
            self.active = Some(name.to_string());
            true
        } else {
            false
        }
    }

    pub fn active(&self) -> Option<&CredentialProfile> {
        let n = self.active.as_ref()?;
        self.profiles.iter().find(|p| &p.name == n)
    }
}

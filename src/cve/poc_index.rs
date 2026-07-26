//! Optional first-party PoC index from the private chrono-pocs tree.
//!
//! Resolution:
//!   1. `$CHRONO_POC_ROOT` if set
//!   2. `~/pocs` (kali mount / local checkout)
//!
//! Reads `index.toml` and maps CVE ids → curated PoC metadata. Only statuses
//! `lab-pass` and `htb-used` are treated as ready for blood (shown in UI/CLI).

use directories::UserDirs;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static INDEX: OnceLock<PocIndex> = OnceLock::new();

/// Statuses that surface as "[POC:…]" in CVE search/show.
const READY_STATUSES: &[&str] = &["lab-pass", "htb-used"];

#[derive(Debug, Clone, Default)]
pub struct PocIndex {
    pub root: PathBuf,
    by_cve: HashMap<String, PocEntry>,
}

#[derive(Debug, Clone)]
pub struct PocEntry {
    pub path: String,
    pub status: String,
    pub chronosphere_id: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IndexFile {
    #[serde(default)]
    poc: Vec<IndexPoc>,
}

#[derive(Debug, Deserialize)]
struct IndexPoc {
    cve: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    status: String,
    chronosphere_id: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

impl PocIndex {
    pub fn global() -> &'static PocIndex {
        INDEX.get_or_init(Self::load)
    }

    /// Force reload (tests / after mount).
    #[cfg(test)]
    pub fn load_from(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self::from_index_path(root.clone(), &root.join("index.toml"))
    }

    pub fn load() -> Self {
        let root = poc_root();
        let index_path = root.join("index.toml");
        Self::from_index_path(root, &index_path)
    }

    fn from_index_path(root: PathBuf, index_path: &Path) -> Self {
        let mut by_cve = HashMap::new();
        if let Ok(raw) = fs::read_to_string(index_path) {
            if let Ok(parsed) = toml::from_str::<IndexFile>(&raw) {
                for p in parsed.poc {
                    let cve = p.cve.trim().to_uppercase();
                    if cve.is_empty() || cve == "CVE-TEMPLATE" {
                        continue;
                    }
                    let status = p.status.trim().to_string();
                    if !READY_STATUSES
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(&status))
                    {
                        continue;
                    }
                    by_cve.insert(
                        cve,
                        PocEntry {
                            path: p.path,
                            status,
                            chronosphere_id: p.chronosphere_id,
                            notes: p.notes,
                        },
                    );
                }
            }
        }
        Self { root, by_cve }
    }

    pub fn get(&self, cve_id: &str) -> Option<&PocEntry> {
        self.by_cve.get(&cve_id.trim().to_uppercase())
    }

    pub fn len(&self) -> usize {
        self.by_cve.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_cve.is_empty()
    }

    /// Ready CVE ids (uppercase), for SQL `IN` filters.
    pub fn cve_ids(&self) -> Vec<String> {
        self.by_cve.keys().cloned().collect()
    }
}

pub fn poc_root() -> PathBuf {
    if let Ok(p) = std::env::var("CHRONO_POC_ROOT") {
        let pb = PathBuf::from(p);
        if !pb.as_os_str().is_empty() {
            return expand_home(pb);
        }
    }
    expand_home(PathBuf::from("~/pocs"))
}

fn expand_home(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs_home() {
            return home.join(rest);
        }
    } else if s == "~" {
        if let Some(home) = dirs_home() {
            return home;
        }
    }
    path
}

fn dirs_home() -> Option<PathBuf> {
    UserDirs::new().map(|u| u.home_dir().to_path_buf())
}

impl PocEntry {
    /// Compact badge for search lines: `[POC:lab-pass]`
    pub fn badge(&self) -> String {
        format!("[POC:{}]", self.status)
    }

    pub fn absolute_path(&self, root: &Path) -> PathBuf {
        root.join(&self.path)
    }
}

/// Lookup helper used by CLI/TUI.
pub fn lookup(cve_id: &str) -> Option<&'static PocEntry> {
    PocIndex::global().get(cve_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn loads_ready_pocs_only() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("chrono-poc-index-{stamp}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("index.toml"),
            r#"
[[poc]]
cve = "CVE-TEMPLATE"
status = "template"
path = "web/_template"

[[poc]]
cve = "CVE-2025-21624"
path = "web/CVE-2025-21624"
product = "clipbucket"
status = "lab-pass"
chronosphere_id = "poc.clipbucket.playlist_cover.check"

[[poc]]
cve = "CVE-2024-0001"
path = "web/CVE-2024-0001"
status = "draft"
"#,
        )
        .unwrap();

        let index = PocIndex::load_from(&dir);
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(index.len(), 1);
        let e = index.get("cve-2025-21624").unwrap();
        assert_eq!(e.status, "lab-pass");
        assert_eq!(
            e.chronosphere_id.as_deref(),
            Some("poc.clipbucket.playlist_cover.check")
        );
        assert!(index.get("CVE-2024-0001").is_none());
        assert!(index.get("CVE-TEMPLATE").is_none());
    }
}

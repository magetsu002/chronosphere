pub mod ap;
pub mod creds;
pub mod history;
pub mod pivot;
pub mod target;
pub mod variables;

pub use ap::{AccessPoint, ApStore};
pub use creds::{CredKind, CredentialProfile, ProfileStore};
pub use history::{HistoryStore, JobRecord, JobStatus};
pub use pivot::{ExecutionMode, Pivot, PivotStore};
pub use target::{Target, TargetStore};
pub use variables::VariableStore;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementMeta {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub notes: Option<String>,
}

/// A loaded engagement: targets, APs, pivots, cred profiles, variables, and job history.
pub struct Engagement {
    pub meta: EngagementMeta,
    pub dir: PathBuf,
    pub targets: TargetStore,
    pub aps: ApStore,
    pub pivots: PivotStore,
    pub profiles: ProfileStore,
    pub variables: VariableStore,
    pub history: HistoryStore,
}

impl Engagement {
    pub fn meta_path(dir: &Path) -> PathBuf {
        dir.join("engagement.toml")
    }
    pub fn targets_path(dir: &Path) -> PathBuf {
        dir.join("targets.json")
    }
    pub fn aps_path(dir: &Path) -> PathBuf {
        dir.join("aps.json")
    }
    pub fn pivots_path(dir: &Path) -> PathBuf {
        dir.join("pivots.json")
    }
    pub fn ssh_dir(dir: &Path) -> PathBuf {
        dir.join(".ssh")
    }
    pub fn creds_path(dir: &Path) -> PathBuf {
        dir.join("creds.json")
    }
    pub fn variables_path(dir: &Path) -> PathBuf {
        dir.join("variables.json")
    }
    pub fn history_path(dir: &Path) -> PathBuf {
        dir.join("jobs.jsonl")
    }
    pub fn jobs_dir(dir: &Path) -> PathBuf {
        dir.join("jobs")
    }
    pub fn overrides_dir(dir: &Path) -> PathBuf {
        dir.join("commands")
    }

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.starts_with('.')
    {
        anyhow::bail!("invalid engagement name '{}'", name);
    }
    Ok(())
}

pub fn load_named(root: &Path, name: &str) -> Result<Self> {
    Self::validate_name(name)?;
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("canonicalize engagement root {}", root.display()))?;
    let requested = root.join(name);
    let canonical_dir = requested
        .canonicalize()
        .with_context(|| format!("resolve engagement {}", requested.display()))?;
    if !canonical_dir.starts_with(&canonical_root) {
        anyhow::bail!("engagement '{}' escapes configured root", name);
    }
    Self::load(canonical_dir)
}

pub fn create(root: &Path, name: &str) -> Result<Self> {
    Self::validate_name(name)?;
    let dir = root.join(name);
        if dir.exists() {
            anyhow::bail!("engagement '{}' already exists", name);
        }
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        fs::create_dir_all(Self::jobs_dir(&dir)).ok();
        fs::create_dir_all(Self::overrides_dir(&dir)).ok();

        let meta = EngagementMeta {
            name: name.to_string(),
            created_at: Utc::now(),
            notes: None,
        };
        fs::write(
            Self::meta_path(&dir),
            toml::to_string_pretty(&meta).context("serialize engagement meta")?,
        )?;
        let targets = TargetStore::new();
        targets.save(&Self::targets_path(&dir))?;
        let aps = ApStore::new();
        aps.save(&Self::aps_path(&dir))?;
        let pivots = PivotStore::new();
        pivots.save(&Self::pivots_path(&dir))?;
        let profiles = ProfileStore::new();
        profiles.save(&Self::creds_path(&dir))?;
        let variables = VariableStore::new();
        variables.save(&Self::variables_path(&dir))?;

        let history = HistoryStore::open(&Self::history_path(&dir))?;
        Ok(Self {
            meta,
            dir,
            targets,
            aps,
            pivots,
            profiles,
            variables,
            history,
        })
    }

    pub fn load(dir: PathBuf) -> Result<Self> {
        let meta_path = Self::meta_path(&dir);
        let meta_str = fs::read_to_string(&meta_path)
            .with_context(|| format!("read {}", meta_path.display()))?;
        let meta: EngagementMeta =
            toml::from_str(&meta_str).context("parse engagement.toml")?;
        let targets = TargetStore::load(&Self::targets_path(&dir)).unwrap_or_else(|err| {
            tracing::warn!(?err, "could not load targets.json; starting fresh");
            TargetStore::new()
        });
        let aps = ApStore::load(&Self::aps_path(&dir)).unwrap_or_else(|err| {
            tracing::warn!(?err, "could not load aps.json; starting fresh");
            ApStore::new()
        });
        let pivots = PivotStore::load(&Self::pivots_path(&dir)).unwrap_or_else(|err| {
            tracing::warn!(?err, "could not load pivots.json; starting fresh");
            PivotStore::new()
        });
        let profiles = ProfileStore::load(&Self::creds_path(&dir)).unwrap_or_else(|err| {
            tracing::warn!(?err, "could not load creds.json; starting fresh");
            ProfileStore::new()
        });
        let variables = VariableStore::load(&Self::variables_path(&dir)).unwrap_or_else(|err| {
            tracing::warn!(?err, "could not load variables.json; starting fresh");
            VariableStore::new()
        });
let mut history = HistoryStore::open(&Self::history_path(&dir))?;
let secrets = crate::security::store_secrets(&profiles, &aps, &pivots, &variables);
if history.redact_values(&secrets) {
    tracing::warn!("redacted sensitive values from legacy job history");
}
        fs::create_dir_all(Self::jobs_dir(&dir)).ok();
        fs::create_dir_all(Self::overrides_dir(&dir)).ok();
        Ok(Self {
            meta,
            dir,
            targets,
            aps,
            pivots,
            profiles,
            variables,
            history,
        })
    }

    pub fn list(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(root) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() && Self::meta_path(&p).exists() {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn active_target(&self) -> Option<&Target> {
        self.targets.active()
    }
    pub fn active_ap(&self) -> Option<&AccessPoint> {
        self.aps.active()
    }
    pub fn active_pivot_tunnel(&self) -> Option<&Pivot> {
        self.pivots.active_tunnel()
    }
    pub fn active_pivot_remote(&self) -> Option<&Pivot> {
        self.pivots.active_remote()
    }
    pub fn active_profile(&self) -> Option<&CredentialProfile> {
        self.profiles.active()
    }

    pub fn save_targets(&self) -> Result<()> {
        self.targets.save(&Self::targets_path(&self.dir))
    }
    pub fn save_aps(&self) -> Result<()> {
        self.aps.save(&Self::aps_path(&self.dir))
    }
    pub fn save_pivots(&self) -> Result<()> {
        self.pivots.save(&Self::pivots_path(&self.dir))
    }
    pub fn save_profiles(&self) -> Result<()> {
        self.profiles.save(&Self::creds_path(&self.dir))
    }
    pub fn save_variables(&self) -> Result<()> {
        self.variables.save(&Self::variables_path(&self.dir))
    }
}

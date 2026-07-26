use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    Killed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub id: String,
    pub command_id: Option<String>,
    pub command_title: String,
    pub resolved: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: JobStatus,
    pub exit_code: Option<i32>,
    pub tmux_window: Option<String>,
    pub log_path: Option<PathBuf>,
    pub target: Option<String>,
    pub profile: Option<String>,
    #[serde(default)]
    pub ap: Option<String>,
    #[serde(default)]
    pub pivot: Option<String>,
    #[serde(default)]
    pub execution: Option<String>,
}

pub struct HistoryStore {
    path: PathBuf,
    file: Mutex<File>,
    pub recent: Vec<JobRecord>,
}

impl HistoryStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        let mut recent = Vec::new();
        if path.exists() {
            let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
            for line in BufReader::new(file).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(_) => continue,
                };
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<JobRecord>(&line) {
                    Ok(record) => recent.push(record),
                    Err(err) => tracing::warn!(?err, "skipping malformed jobs.jsonl line"),
                }
            }
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .with_context(|| format!("open append {}", path.display()))?;
        crate::security::secure_existing_file(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            file: Mutex::new(file),
            recent,
        })
    }

    pub fn append(&mut self, record: &JobRecord) -> Result<()> {
        let line = serde_json::to_string(record).context("serialize JobRecord")?;
        let mut guard = self.file.lock().expect("history file mutex");
        writeln!(guard, "{}", line).with_context(|| format!("write {}", self.path.display()))?;
        guard.flush().ok();
        drop(guard);
        self.recent.push(record.clone());
        Ok(())
    }

    pub fn update(&mut self, record: &JobRecord) {
        if let Some(slot) = self.recent.iter_mut().find(|item| item.id == record.id) {
            *slot = record.clone();
        }
        self.rewrite_all();
    }

    pub fn redact_values(&mut self, secrets: &[String]) -> bool {
        let mut changed = false;
        for record in &mut self.recent {
            let redacted = crate::security::redact_values(&record.resolved, secrets);
            if redacted != record.resolved {
                record.resolved = redacted;
                changed = true;
            }
        }
        if changed {
            self.rewrite_all();
        }
        changed
    }

    fn rewrite_all(&mut self) {
        let mut contents = String::new();
        for record in &self.recent {
            match serde_json::to_string(record) {
                Ok(line) => {
                    contents.push_str(&line);
                    contents.push('\n');
                }
                Err(err) => {
                    tracing::warn!(?err, "rewrite history: serialize failed");
                    return;
                }
            }
        }

        if let Err(err) = crate::security::write_private_atomic(&self.path, contents.as_bytes()) {
            tracing::warn!(?err, "rewrite history: atomic replacement failed");
            return;
        }

        let mut options = OpenOptions::new();
        options.append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        if let Ok(file) = options.open(&self.path) {
            *self.file.lock().expect("history file mutex") = file;
        }
    }

    pub fn last_n(&self, n: usize) -> &[JobRecord] {
        let start = self.recent.len().saturating_sub(n);
        &self.recent[start..]
    }
}

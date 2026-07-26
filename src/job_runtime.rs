use crate::engagement::{HistoryStore, JobStatus};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const JOB_ID_ENV: &str = "CHRONOSPHERE_JOB_ID";
pub const JOB_TOKEN_ENV: &str = "CHRONOSPHERE_JOB_TOKEN";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeIdentity {
    pub job_id: String,
    pub pid: u32,
    pub process_group_id: Option<u32>,
    pub token: String,
    pub started_at: DateTime<Utc>,
}

impl RuntimeIdentity {
    pub fn new(job_id: String, pid: u32, token: String) -> Self {
        Self {
            job_id,
            pid,
            process_group_id: if cfg!(unix) { Some(pid) } else { None },
            token,
            started_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunningProcess {
    pub identity: RuntimeIdentity,
    pub recovered: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityState {
    Alive,
    Gone,
    Mismatch,
    Unsupported,
}

#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub recovered: Vec<RuntimeIdentity>,
    pub stale_jobs: Vec<String>,
    pub completed_jobs: Vec<String>,
}

pub fn runtime_path(jobs_dir: &Path, job_id: &str) -> PathBuf {
    jobs_dir.join(format!("{job_id}.runtime.json"))
}

pub fn persist(jobs_dir: &Path, identity: &RuntimeIdentity) -> Result<()> {
    let body = serde_json::to_vec_pretty(identity).context("serialize process identity")?;
    crate::security::write_private_atomic(&runtime_path(jobs_dir, &identity.job_id), &body)
}

pub fn load(jobs_dir: &Path, job_id: &str) -> Result<Option<RuntimeIdentity>> {
    let path = runtime_path(jobs_dir, job_id);
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let identity = serde_json::from_slice(&body)
        .with_context(|| format!("parse runtime identity {}", path.display()))?;
    Ok(Some(identity))
}

pub fn remove(jobs_dir: &Path, job_id: &str) {
    let path = runtime_path(jobs_dir, job_id);
    if let Err(err) = std::fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(?err, path = %path.display(), "remove runtime identity failed");
        }
    }
}

pub fn reconcile_history(history: &mut HistoryStore, jobs_dir: &Path) -> ReconcileReport {
    let mut report = ReconcileReport::default();
    let running = history
        .recent
        .iter()
        .filter(|record| record.status == JobStatus::Running)
        .cloned()
        .collect::<Vec<_>>();

    for record in running {
        let status_path = jobs_dir.join(format!("{}.status", record.id));
        if let Ok(raw) = std::fs::read_to_string(&status_path) {
            if let Ok(code) = raw.trim().parse::<i32>() {
                let mut updated = record.clone();
                updated.finished_at = Some(Utc::now());
                updated.exit_code = Some(code);
                updated.status = if code == 0 {
                    JobStatus::Completed
                } else {
                    JobStatus::Failed
                };
                history.update(&updated);
                remove(jobs_dir, &record.id);
                report.completed_jobs.push(record.id);
                continue;
            }
        }

        match load(jobs_dir, &record.id) {
            Ok(Some(identity)) => match identity_state(&identity) {
                IdentityState::Alive => report.recovered.push(identity),
                IdentityState::Gone | IdentityState::Mismatch | IdentityState::Unsupported => {
                    mark_unknown(history, &record);
                    remove(jobs_dir, &record.id);
                    report.stale_jobs.push(record.id);
                }
            },
            Ok(None) if record.tmux_window.is_some() => {}
            Ok(None) => {
                mark_unknown(history, &record);
                report.stale_jobs.push(record.id);
            }
            Err(err) => {
                tracing::warn!(?err, job_id = %record.id, "runtime identity unreadable");
                mark_unknown(history, &record);
                remove(jobs_dir, &record.id);
                report.stale_jobs.push(record.id);
            }
        }
    }
    report
}

pub fn recover_running_map(
    history: &mut HistoryStore,
    jobs_dir: &Path,
) -> HashMap<String, RunningProcess> {
    reconcile_history(history, jobs_dir)
        .recovered
        .into_iter()
        .map(|identity| {
            (
                identity.job_id.clone(),
                RunningProcess {
                    identity,
                    recovered: true,
                },
            )
        })
        .collect()
}

fn mark_unknown(history: &mut HistoryStore, record: &crate::engagement::JobRecord) {
    let mut updated = record.clone();
    updated.status = JobStatus::Unknown;
    updated.finished_at = Some(Utc::now());
    updated.exit_code = None;
    history.update(&updated);
}

pub fn identity_state(identity: &RuntimeIdentity) -> IdentityState {
    #[cfg(target_os = "linux")]
    {
        linux_identity_state(identity)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = identity;
        IdentityState::Unsupported
    }
}

#[cfg(target_os = "linux")]
fn linux_identity_state(identity: &RuntimeIdentity) -> IdentityState {
    let proc_dir = PathBuf::from(format!("/proc/{}", identity.pid));
    if !proc_dir.exists() {
        return IdentityState::Gone;
    }

    let stat = match std::fs::read_to_string(proc_dir.join("stat")) {
        Ok(stat) => stat,
        Err(_) => return IdentityState::Unsupported,
    };
    let Some(close) = stat.rfind(')') else {
        return IdentityState::Mismatch;
    };
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    let process_group_id = fields.get(2).and_then(|value| value.parse::<u32>().ok());
    if identity.process_group_id.is_some() && process_group_id != identity.process_group_id {
        return IdentityState::Mismatch;
    }

    let environment = match std::fs::read(proc_dir.join("environ")) {
        Ok(environment) => environment,
        Err(_) => return IdentityState::Unsupported,
    };
    let expected_job = format!("{JOB_ID_ENV}={}", identity.job_id);
    let expected_token = format!("{JOB_TOKEN_ENV}={}", identity.token);
    let mut has_job = false;
    let mut has_token = false;
    for item in environment.split(|byte| *byte == 0) {
        has_job |= item == expected_job.as_bytes();
        has_token |= item == expected_token.as_bytes();
    }
    if has_job && has_token {
        IdentityState::Alive
    } else {
        IdentityState::Mismatch
    }
}

pub fn signal_process_group(
    identity: &RuntimeIdentity,
    signal: &str,
    require_verified_identity: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        if require_verified_identity && identity_state(identity) != IdentityState::Alive {
            bail!(
                "refusing to signal job '{}': process identity no longer matches",
                identity.job_id
            );
        }
        let group = identity.process_group_id.unwrap_or(identity.pid);
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(format!("-{group}"))
            .status()
            .with_context(|| format!("send {signal} to process group {group}"))?;
        if !status.success() {
            bail!("failed to send {signal} to process group {group}");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (identity, signal, require_verified_identity);
        bail!("process-group signalling is unsupported on this platform")
    }
}

pub fn process_group_exists(identity: &RuntimeIdentity) -> bool {
    #[cfg(unix)]
    {
        let group = identity.process_group_id.unwrap_or(identity.pid);
        Command::new("kill")
            .arg("-0")
            .arg(format!("-{group}"))
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = identity;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn verifies_owned_process_and_rejects_pid_reuse() {
        use std::os::unix::process::CommandExt;

        let job_id = uuid::Uuid::new_v4().to_string();
        let token = uuid::Uuid::new_v4().to_string();
        let mut command = Command::new("bash");
        command
            .arg("-lc")
            .arg("sleep 30")
            .env(JOB_ID_ENV, &job_id)
            .env(JOB_TOKEN_ENV, &token);
        command.process_group(0);
        let mut child = command.spawn().expect("spawn test child");
        let identity = RuntimeIdentity::new(job_id, child.id(), token);
        assert_eq!(identity_state(&identity), IdentityState::Alive);

        let mut wrong = identity.clone();
        wrong.token = "wrong-token".into();
        assert_eq!(identity_state(&wrong), IdentityState::Mismatch);

        signal_process_group(&identity, "TERM", true).expect("terminate test child");
        let _ = child.wait();
        assert_ne!(identity_state(&identity), IdentityState::Alive);
    }

    #[test]
    fn reconciles_stale_runtime_sidecars_without_signalling() {
        let root = std::env::temp_dir().join(format!("chrono-runtime-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let history_path = root.join("jobs.jsonl");
        let jobs_dir = root.join("jobs");
        std::fs::create_dir_all(&jobs_dir).unwrap();
        let mut history = HistoryStore::open(&history_path).unwrap();
        let job_id = uuid::Uuid::new_v4().to_string();
        history
            .append(&crate::engagement::JobRecord {
                id: job_id.clone(),
                command_id: Some("test".into()),
                command_title: "test".into(),
                resolved: "sleep 30".into(),
                started_at: Utc::now(),
                finished_at: None,
                status: JobStatus::Running,
                exit_code: None,
                tmux_window: None,
                log_path: None,
                target: None,
                profile: None,
                ap: None,
                pivot: None,
                execution: Some("local".into()),
            })
            .unwrap();
        let identity = RuntimeIdentity {
            job_id: job_id.clone(),
            pid: u32::MAX,
            process_group_id: Some(u32::MAX),
            token: "stale".into(),
            started_at: Utc::now(),
        };
        persist(&jobs_dir, &identity).unwrap();
        let report = reconcile_history(&mut history, &jobs_dir);
        assert_eq!(report.stale_jobs, vec![job_id.clone()]);
        assert_eq!(history.recent[0].status, JobStatus::Unknown);
        assert!(!runtime_path(&jobs_dir, &job_id).exists());
        let _ = std::fs::remove_dir_all(root);
    }
}

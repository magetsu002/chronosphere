use crate::engagement::{Engagement, JobStatus};
use crate::job_runtime::{self, IdentityState};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ToolHealth {
    pub present: Vec<String>,
    pub missing: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct EngagementHealth {
    pub engagement: String,
    pub running_jobs: Vec<String>,
    pub unknown_jobs: Vec<String>,
    pub orphan_files: Vec<String>,
    pub removed_files: Vec<String>,
    pub archived_logs: Vec<String>,
}

pub fn check_tools(tools: impl IntoIterator<Item = String>) -> ToolHealth {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for tool in tools {
        if which::which(&tool).is_ok() {
            present.push(tool);
        } else {
            missing.push(tool);
        }
    }
    present.sort();
    missing.sort();
    ToolHealth { present, missing }
}

pub fn inspect_engagement(engagement: &mut Engagement, repair: bool) -> Result<EngagementHealth> {
    let jobs_dir = Engagement::jobs_dir(&engagement.dir);
    std::fs::create_dir_all(&jobs_dir).ok();
    let reconciliation = job_runtime::reconcile_history(&mut engagement.history, &jobs_dir);
    let known_jobs = engagement
        .history
        .recent
        .iter()
        .map(|record| record.id.clone())
        .collect::<HashSet<_>>();
    let running_jobs = engagement
        .history
        .recent
        .iter()
        .filter(|record| record.status == JobStatus::Running)
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    let mut unknown_jobs = engagement
        .history
        .recent
        .iter()
        .filter(|record| record.status == JobStatus::Unknown)
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    unknown_jobs.extend(reconciliation.stale_jobs);
    unknown_jobs.sort();
    unknown_jobs.dedup();

    let mut report = EngagementHealth {
        engagement: engagement.meta.name.clone(),
        running_jobs,
        unknown_jobs,
        ..EngagementHealth::default()
    };

    for entry in
        std::fs::read_dir(&jobs_dir).with_context(|| format!("read {}", jobs_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some((job_id, kind)) = classify_artifact(name) else {
            continue;
        };
        let record = engagement
            .history
            .recent
            .iter()
            .find(|record| record.id == job_id);
        let disposable = matches!(
            kind,
            ArtifactKind::Runtime
                | ArtifactKind::Password
                | ArtifactKind::RemoteScript
                | ArtifactKind::Status
        );
        let orphan = !known_jobs.contains(job_id)
            || record.is_some_and(|record| {
                record.status != JobStatus::Running
                    && (disposable
                        || matches!(kind, ArtifactKind::Log) && record.log_path.is_none())
            })
            || matches!(kind, ArtifactKind::Runtime)
                && job_runtime::load(&jobs_dir, job_id)
                    .ok()
                    .flatten()
                    .is_some_and(|identity| identity_state_not_alive(&identity));
        if !orphan {
            continue;
        }
        report.orphan_files.push(name.to_string());
        if repair {
            if matches!(kind, ArtifactKind::Log) {
                archive_log(&jobs_dir, &path, &mut report)?;
            } else {
                std::fs::remove_file(&path)
                    .with_context(|| format!("remove orphan {}", path.display()))?;
                report.removed_files.push(name.to_string());
            }
        }
    }
    report.orphan_files.sort();
    report.removed_files.sort();
    report.archived_logs.sort();
    Ok(report)
}

fn identity_state_not_alive(identity: &job_runtime::RuntimeIdentity) -> bool {
    !matches!(job_runtime::identity_state(identity), IdentityState::Alive)
}

#[derive(Debug, Clone, Copy)]
enum ArtifactKind {
    Runtime,
    Password,
    RemoteScript,
    Status,
    Log,
}

fn classify_artifact(name: &str) -> Option<(&str, ArtifactKind)> {
    for (suffix, kind) in [
        (".runtime.json", ArtifactKind::Runtime),
        (".sshpass", ArtifactKind::Password),
        (".remote.sh", ArtifactKind::RemoteScript),
        (".status", ArtifactKind::Status),
        (".log", ArtifactKind::Log),
    ] {
        if let Some(job_id) = name.strip_suffix(suffix) {
            return Some((job_id, kind));
        }
    }
    None
}

fn archive_log(jobs_dir: &Path, source: &Path, report: &mut EngagementHealth) -> Result<()> {
    let archive = jobs_dir.join("orphaned");
    std::fs::create_dir_all(&archive)?;
    let name = source
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("orphan log has no filename"))?;
    let mut destination = archive.join(name);
    if destination.exists() {
        destination = archive.join(format!(
            "{}-{}",
            uuid::Uuid::new_v4(),
            name.to_string_lossy()
        ));
    }
    std::fs::rename(source, &destination).with_context(|| {
        format!(
            "archive orphan log {} -> {}",
            source.display(),
            destination.display()
        )
    })?;
    report
        .archived_logs
        .push(destination.to_string_lossy().into_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_archives_orphan_logs_and_removes_sensitive_artifacts() {
        let root = std::env::temp_dir().join(format!("chrono-health-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut engagement = Engagement::create(&root, "lab").unwrap();
        let jobs = Engagement::jobs_dir(&engagement.dir);
        std::fs::write(jobs.join("orphan.log"), "evidence").unwrap();
        std::fs::write(jobs.join("orphan.sshpass"), "secret").unwrap();
        let report = inspect_engagement(&mut engagement, true).unwrap();
        assert_eq!(report.removed_files, vec!["orphan.sshpass"]);
        assert_eq!(report.archived_logs.len(), 1);
        assert!(!jobs.join("orphan.sshpass").exists());
        assert!(!jobs.join("orphan.log").exists());
        let _ = std::fs::remove_dir_all(root);
    }
}

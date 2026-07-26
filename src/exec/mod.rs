pub mod remote;
pub mod ssh;
pub mod tmux;

use crate::config::TMUX_SESSION;
use crate::engagement::{Engagement, ExecutionMode, JobRecord, JobStatus, Pivot};
use crate::exec::remote::wrap_for_remote;
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SpawnRequest {
    pub command_id: Option<String>,
    pub command_title: String,
    pub resolved: String,
    pub interactive: bool,
    pub target: Option<String>,
    pub profile: Option<String>,
    pub ap: Option<String>,
    pub pivot: Option<String>,
    pub execution: Option<String>,
    pub execution_mode: ExecutionMode,
    pub remote_pivot: Option<Pivot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmuxAvailability {
    InSession,
    SessionBootstrapped,
    Unavailable,
}

pub struct Executor {
    pub availability: TmuxAvailability,
    pub jobs_dir: PathBuf,
    pub engagement_dir: PathBuf,
    secrets: Vec<String>,
}

impl Executor {
    pub fn init(engagement: &Engagement) -> Self {
        let jobs_dir = Engagement::jobs_dir(&engagement.dir);
        fs::create_dir_all(&jobs_dir).ok();
        fs::create_dir_all(Engagement::ssh_dir(&engagement.dir)).ok();

        let availability = if std::env::var("TMUX").is_ok() {
            TmuxAvailability::InSession
        } else if tmux::has_tmux() {
            match tmux::ensure_session(TMUX_SESSION) {
                Ok(_) => TmuxAvailability::SessionBootstrapped,
                Err(err) => {
                    tracing::warn!(?err, "could not bootstrap tmux session");
                    TmuxAvailability::Unavailable
                }
            }
        } else {
            TmuxAvailability::Unavailable
        };
Self {
    availability,
    jobs_dir,
    engagement_dir: engagement.dir.clone(),
    secrets: crate::security::store_secrets(
        &engagement.profiles,
        &engagement.aps,
        &engagement.pivots,
        &engagement.variables,
    ),
}
    }

    /// Spawn a command. Non-interactive → tmux new-window detached + tee to log. Interactive →
    /// either a foreground tmux window (if we're inside tmux) or an external terminal.
pub fn spawn(&self, req: SpawnRequest) -> Result<JobRecord> {
    let unresolved = crate::render::find_unresolved(&req.resolved);
    if !unresolved.is_empty() {
        anyhow::bail!(
            "command has unresolved placeholders: {}",
            unresolved.join(", ")
        );
    }
    let id = Uuid::new_v4().to_string();
        let log_path = self.jobs_dir.join(format!("{}.log", id));
        let status_path = self.jobs_dir.join(format!("{}.status", id));
        let _ = crate::security::create_private_file(&log_path)?;

        let log_str = log_path.to_string_lossy().to_string();
        let status_str = status_path.to_string_lossy().to_string();

        let resolved = if req.execution_mode == ExecutionMode::Remote {
            let pivot = req
                .remote_pivot
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("remote execution requires an active pivot with SSH"))?;
            if !pivot.has_ssh() {
                anyhow::bail!("pivot '{}' missing ssh_user/ssh_host", pivot.name);
            }
            wrap_for_remote(
                &req.resolved,
                pivot,
                &self.engagement_dir,
                req.target.as_deref(),
                &self.jobs_dir,
                &id,
                &log_str,
                &status_str,
                req.interactive,
            )?
        } else {
            req.resolved.clone()
        };

        let window_name = window_name_for(&req);

        let tmux_window = if self.availability != TmuxAvailability::Unavailable {
            let wrapped = if req.interactive {
                interactive_wrapper(&resolved, &log_str, &status_str)
            } else {
                background_wrapper(&resolved, &log_str, &status_str)
            };
            let opts = tmux::NewWindowOpts {
                session: tmux_session_name(self.availability),
                window_name: &window_name,
                detached: !req.interactive || self.availability == TmuxAvailability::SessionBootstrapped,
                command: &wrapped,
            };
            match tmux::new_window(opts) {
                Ok(wid) => Some(wid),
                Err(err) => {
                    tracing::error!(?err, "tmux new-window failed, falling back to external terminal");
                    spawn_external_terminal(&resolved, &log_str, &status_str)?;
                    None
                }
            }
        } else {
            spawn_external_terminal(&resolved, &log_str, &status_str)?;
            None
        };

        Ok(JobRecord {
            id,
            command_id: req.command_id,
            command_title: req.command_title,
            resolved: crate::security::redact_values(&req.resolved, &self.secrets),
            started_at: Utc::now(),
            finished_at: None,
            status: JobStatus::Running,
            exit_code: None,
            tmux_window,
            log_path: Some(log_path),
            target: req.target,
            profile: req.profile,
            ap: req.ap,
            pivot: req.pivot,
            execution: req.execution,
        })
    }

    /// Examine status files + tmux window list. Returns updated jobs (call sites overwrite
    /// status/finished_at/exit_code in the history store).
    pub fn poll(&self, jobs: &[JobRecord]) -> Vec<JobRecord> {
        let mut updated = Vec::new();
        let windows = if self.availability != TmuxAvailability::Unavailable {
            tmux::list_windows(tmux_session_name(self.availability)).unwrap_or_default()
        } else {
            Vec::new()
        };
        for job in jobs {
            if job.status != JobStatus::Running {
                continue;
            }
            let status_path = self.jobs_dir.join(format!("{}.status", job.id));
            if status_path.exists() {
                if let Ok(s) = fs::read_to_string(&status_path) {
                    let code: i32 = s.trim().parse().unwrap_or(-1);
                    let mut copy = job.clone();
                    copy.finished_at = Some(Utc::now());
                    copy.exit_code = Some(code);
                    copy.status = if code == 0 {
                        JobStatus::Completed
                    } else {
                        JobStatus::Failed
                    };
                    updated.push(copy);
                    continue;
                }
            }
            // window vanished but no status file → assume killed
            if let Some(wid) = job.tmux_window.as_deref() {
                if !windows.iter().any(|w| w.id == wid) {
                    let mut copy = job.clone();
                    copy.finished_at = Some(Utc::now());
                    copy.status = JobStatus::Killed;
                    updated.push(copy);
                }
            }
        }
        updated
    }

    pub fn kill_job(&self, job: &JobRecord) -> Result<()> {
        if let Some(w) = job.tmux_window.as_deref() {
            tmux::kill_window(tmux_session_name(self.availability), w)
                .context("tmux kill-window")?;
        }
        Ok(())
    }

    pub fn focus_job(&self, job: &JobRecord) -> Result<FocusResult> {
        match (self.availability, job.tmux_window.as_deref()) {
            (TmuxAvailability::InSession, Some(w)) => {
                tmux::select_window(tmux_session_name(self.availability), w)?;
                Ok(FocusResult::Focused)
            }
            (TmuxAvailability::SessionBootstrapped, Some(w)) => {
                Ok(FocusResult::AttachCommand(format!(
                    "tmux attach -t {} \\; select-window -t {}",
                    TMUX_SESSION, w
                )))
            }
            _ => Ok(FocusResult::Unfocusable),
        }
    }

    /// Open an interactive tmux view of a job:
    /// - inside tmux: selects the window
    /// - outside tmux but session exists: opens a new terminal and attaches
    pub fn open_job_interactive(&self, job: &JobRecord) -> Result<()> {
        let Some(w) = job.tmux_window.as_deref() else {
            anyhow::bail!("job has no tmux window");
        };
        match self.availability {
            TmuxAvailability::InSession => {
                tmux::select_window(tmux_session_name(self.availability), w)?;
                Ok(())
            }
            TmuxAvailability::SessionBootstrapped => {
                let cmd = format!("tmux attach -t {} \\; select-window -t {}", TMUX_SESSION, w);
                spawn_external_terminal_simple(&cmd)
            }
            TmuxAvailability::Unavailable => anyhow::bail!("tmux not available"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum FocusResult {
    Focused,
    AttachCommand(String),
    Unfocusable,
}

fn tmux_session_name(av: TmuxAvailability) -> Option<&'static str> {
    match av {
        TmuxAvailability::InSession => None, // use current
        TmuxAvailability::SessionBootstrapped => Some(TMUX_SESSION),
        TmuxAvailability::Unavailable => None,
    }
}

fn window_name_for(req: &SpawnRequest) -> String {
    let title = req
        .command_title
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let truncated: String = title.chars().take(30).collect();
    if truncated.is_empty() {
        "chrono".into()
    } else {
        truncated
    }
}

fn background_wrapper(cmd: &str, log_path: &str, status_path: &str) -> String {
    // Run under a pseudo-TTY via `script` so tools like ffuf line-buffer progress instead of
    // block-buffering when piped through `tee`. Fall back to tee when script is unavailable.
    let inner = shell_escape(&format!("{{ {cmd}; }}"));
    format!(
        r#"if command -v script >/dev/null 2>&1; then
  script -q -c {inner} {log}
else
  {{ {cmd}; }} 2>&1 | tee -a {log}
fi
ec=$?
echo "$ec" > {status}
echo
echo '[chronosphere] command finished (exit '"$ec"'). Press Up to recall.'
exec ${{SHELL:-bash}}"#,
        cmd = cmd,
        inner = inner,
        log = shell_escape(log_path),
        status = shell_escape(status_path),
    )
}

fn interactive_wrapper(cmd: &str, _log_path: &str, status_path: &str) -> String {
    // Don't tee stdout — interactive tools hate piping. Still drop a status file when they exit.
    format!(
        "{{ {cmd}; }}; echo $? > {status}; echo; echo '[chronosphere] interactive command finished.'; exec ${{SHELL:-bash}}",
        cmd = cmd,
        status = shell_escape(status_path),
    )
}

fn shell_escape(s: &str) -> String {
    shell_words::quote(s).to_string()
}

fn spawn_external_terminal(cmd: &str, log_path: &str, status_path: &str) -> Result<()> {
    let wrapped = background_wrapper(cmd, log_path, status_path);
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "tell application \"Terminal\" to do script \"{}\"",
            wrapped.replace('\\', "\\\\").replace('"', "\\\"")
        );
        std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .spawn()
            .context("osascript spawn")?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let candidates: &[&[&str]] = &[
            &["x-terminal-emulator", "-e", "bash", "-c"],
            &["gnome-terminal", "--", "bash", "-c"],
            &["konsole", "-e", "bash", "-c"],
            &["xterm", "-e", "bash", "-c"],
            &["alacritty", "-e", "bash", "-c"],
            &["kitty", "bash", "-c"],
            &["wezterm", "start", "--", "bash", "-c"],
        ];
        for argv in candidates {
            if which::which(argv[0]).is_ok() {
                let mut cmd = std::process::Command::new(argv[0]);
                for a in &argv[1..] {
                    cmd.arg(a);
                }
                cmd.arg(&wrapped);
                if cmd.spawn().is_ok() {
                    return Ok(());
                }
            }
        }
        anyhow::bail!("no terminal emulator found in $PATH");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (cmd, log_path, status_path, wrapped);
        anyhow::bail!("external terminal spawn not implemented for this platform");
    }
}

fn spawn_external_terminal_simple(cmd: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // Run in a fresh Terminal window/tab.
        let script = format!(
            "tell application \"Terminal\" to do script \"{}\"",
            cmd.replace('\\', "\\\\").replace('"', "\\\"")
        );
        std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .spawn()
            .context("osascript spawn")?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let candidates: &[&[&str]] = &[
            &["x-terminal-emulator", "-e", "bash", "-lc"],
            &["gnome-terminal", "--", "bash", "-lc"],
            &["konsole", "-e", "bash", "-lc"],
            &["xterm", "-e", "bash", "-lc"],
            &["alacritty", "-e", "bash", "-lc"],
            &["kitty", "bash", "-lc"],
            &["wezterm", "start", "--", "bash", "-lc"],
        ];
        for argv in candidates {
            if which::which(argv[0]).is_ok() {
                let mut c = std::process::Command::new(argv[0]);
                for a in &argv[1..] {
                    c.arg(a);
                }
                c.arg(cmd);
                if c.spawn().is_ok() {
                    return Ok(());
                }
            }
        }
        anyhow::bail!("no terminal emulator found in $PATH");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = cmd;
        anyhow::bail!("external terminal spawn not implemented for this platform");
    }
}

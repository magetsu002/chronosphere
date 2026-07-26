//! SSH/scp helpers for remote pivot execution and deploy.

use crate::engagement::Pivot;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Slug for default engagement SSH key filenames (`id_{slug}`), aligned with `{pivot_ssh_key}`.
pub fn slugify_key_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() { "pivot".into() } else { s }
}

/// Default private key path when `ssh_identity` is unset: `engagement/.ssh/id_{target_or_pivot}`.
pub fn default_ssh_key_path(
    engagement_dir: &Path,
    target_name: Option<&str>,
    pivot_name: &str,
) -> PathBuf {
    let slug = target_name
        .map(slugify_key_name)
        .unwrap_or_else(|| slugify_key_name(pivot_name));
    engagement_dir.join(".ssh").join(format!("id_{slug}"))
}

/// Resolve private key: explicit `ssh_identity`, else default path if the file exists.
pub fn resolve_ssh_identity(
    pivot: &Pivot,
    engagement_dir: &Path,
    target_name: Option<&str>,
) -> Option<PathBuf> {
    if let Some(id) = pivot.ssh_identity.as_ref().filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(id));
    }
    let default = default_ssh_key_path(engagement_dir, target_name, &pivot.name);
    default.exists().then_some(default)
}

/// Whether remote mode can be enabled (host/user plus password or a usable key).
pub fn pivot_ssh_auth_available(
    pivot: &Pivot,
    engagement_dir: &Path,
    target_name: Option<&str>,
) -> bool {
    if pivot.ssh_password.as_deref().is_some_and(|s| !s.is_empty()) {
        return true;
    }
    resolve_ssh_identity(pivot, engagement_dir, target_name).is_some_and(|p| p.exists())
}

/// Pick key auth when a key file exists; otherwise password. Never combine sshpass with `-i`.
pub fn resolve_ssh_auth(
    pivot: &Pivot,
    engagement_dir: &Path,
    target_name: Option<&str>,
) -> Result<(Option<PathBuf>, Option<String>)> {
    if let Some(id) = pivot.ssh_identity.as_ref().filter(|s| !s.is_empty()) {
        let path = PathBuf::from(id);
        if !path.exists() {
            bail!(
                "pivot '{}' ssh_identity not found: {}",
                pivot.name,
                path.display()
            );
        }
        return Ok((Some(path), None));
    }

    if let Some(path) = resolve_ssh_identity(pivot, engagement_dir, target_name) {
        return Ok((Some(path), None));
    }

    if let Some(pw) = pivot
        .ssh_password
        .as_ref()
        .filter(|s| !s.is_empty())
        .cloned()
    {
        ensure_sshpass()?;
        return Ok((None, Some(pw)));
    }

    let hint = default_ssh_key_path(engagement_dir, target_name, &pivot.name);
    bail!(
        "pivot '{}' has no SSH auth: set ssh_password, set ssh_identity, or create {}",
        pivot.name,
        hint.display()
    );
}

#[derive(Debug, Clone)]
pub struct SshConn {
    pub target: String,
    pub port: u16,
    pub identity: Option<PathBuf>,
    pub password: Option<String>,
    pub control_path: PathBuf,
}

impl SshConn {
    pub fn from_pivot(
        pivot: &Pivot,
        engagement_dir: &Path,
        target_name: Option<&str>,
    ) -> Result<Self> {
        let target = pivot
            .ssh_spec()
            .ok_or_else(|| anyhow::anyhow!("pivot '{}' missing ssh_user/ssh_host", pivot.name))?;
        let (identity, password) = resolve_ssh_auth(pivot, engagement_dir, target_name)?;
        let ssh_dir = engagement_dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).ok();
        let control_path = ssh_dir.join(format!("cm-{}", pivot.name.replace('/', "_")));
        Ok(Self {
            target,
            port: pivot.ssh_port.unwrap_or(22),
            identity,
            password,
            control_path,
        })
    }

    pub fn uses_password(&self) -> bool {
        self.password.is_some()
    }

    fn connection_opts(&self) -> Vec<String> {
        let cp = self.control_path.to_string_lossy().to_string();
        vec![
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ControlMaster=auto".into(),
            "-o".into(),
            format!("ControlPath={}", cp),
            "-o".into(),
            "ControlPersist=10m".into(),
            "-o".into(),
            "ServerAliveInterval=30".into(),
        ]
    }

    fn identity_args(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(id) = &self.identity {
            v.push("-i".into());
            v.push(id.to_string_lossy().into_owned());
        }
        v
    }

    /// OpenSSH `ssh` port flag is lowercase `-p`.
    fn base_ssh_args(&self) -> Vec<String> {
        let mut v = vec!["-p".into(), self.port.to_string()];
        v.extend(self.connection_opts());
        v.extend(self.identity_args());
        v
    }

    /// OpenSSH `scp` port flag is uppercase `-P` (lowercase `-p` means preserve mtimes).
    fn base_scp_args(&self) -> Vec<String> {
        let mut v = vec!["-P".into(), self.port.to_string()];
        v.extend(self.connection_opts());
        v.extend(self.identity_args());
        v
    }

    fn wrap_prog(
        &self,
        prog: &str,
        args: &[String],
        password_file: Option<&Path>,
    ) -> Result<String> {
        let mut command = String::new();
        if self.password.is_some() {
            let Some(password_file) = password_file else {
                bail!("password-backed SSH wrapper requires a private password file");
            };
            command.push_str("sshpass -f ");
            command.push_str(&shell_escape(password_file.to_string_lossy().as_ref()));
            command.push(' ');
        }
        command.push_str(prog);
        for argument in args {
            command.push(' ');
            command.push_str(&shell_escape(argument));
        }
        Ok(command)
    }

    pub fn scp_to_remote(&self, local: &Path, remote_path: &str) -> Result<()> {
        let mut command = if let Some(password) = &self.password {
            ensure_sshpass()?;
            let mut command = Command::new("sshpass");
            command.arg("-e").arg("scp");
            command.env("SSHPASS", password);
            command
        } else {
            Command::new("scp")
        };
        for argument in self.base_scp_args() {
            command.arg(argument);
        }
        command
            .arg(local)
            .arg(format!("{}:{}", self.target, remote_path));
        let status = command
            .status()
            .with_context(|| format!("scp to {}", remote_path))?;
        if !status.success() {
            bail!("scp failed with status {:?}", status.code());
        }
        Ok(())
    }

    /// Build a shell command that scp's a script, runs it on the pivot, logs locally, writes status.
    pub fn remote_script_wrapper(
        &self,
        local_script: &Path,
        remote_script: &str,
        log_path: &str,
        status_path: &str,
        password_file: Option<&Path>,
        interactive: bool,
    ) -> Result<String> {
        if self.password.is_some() && password_file.is_none() {
            bail!("password-backed SSH wrapper requires a private password file");
        }

        let log = shell_escape(log_path);
        let status = shell_escape(status_path);
        let target = shell_escape(&self.target);

        let mut scp_args = self.base_scp_args();
        scp_args.push(local_script.to_string_lossy().into_owned());
        scp_args.push(format!("{}:{}", self.target, remote_script));
        let scp_cmd = self.wrap_prog("scp", &scp_args, password_file)?;

        let remote_exec = shell_escape(&format!(
            "chmod +x {remote_script} && bash {remote_script}; ec=$?; rm -f {remote_script}; exit $ec"
        ));
        let mut ssh_cmd = if let Some(password_file) = password_file {
            format!(
                "sshpass -f {} ssh",
                shell_escape(password_file.to_string_lossy().as_ref())
            )
        } else {
            "ssh".into()
        };
        if interactive {
            ssh_cmd.push_str(" -tt");
        }
        for argument in self.base_ssh_args() {
            ssh_cmd.push(' ');
            ssh_cmd.push_str(&shell_escape(&argument));
        }
        ssh_cmd.push(' ');
        ssh_cmd.push_str(&target);
        ssh_cmd.push(' ');
        ssh_cmd.push_str(&remote_exec);

        let (trap, cleanup) = if let Some(password_file) = password_file {
            let remove = format!(
                "rm -f -- {}",
                shell_escape(password_file.to_string_lossy().as_ref())
            );
            (
                format!("trap {} EXIT INT TERM; ", shell_escape(&remove)),
                format!("{}; trap - EXIT INT TERM", remove),
            )
        } else {
            (String::new(), ":".to_string())
        };

        let command = if interactive {
            format!(
                r#"{trap}{scp_cmd} && {ssh_cmd}; ec=$?; echo "$ec" > {status}; {cleanup}"#,
                trap = trap,
                scp_cmd = scp_cmd,
                ssh_cmd = ssh_cmd,
                status = status,
                cleanup = cleanup,
            )
        } else {
            format!(
                r#"{trap}{scp_cmd} && {ssh_cmd} 2>&1 | tee -a {log}; ec=${{PIPESTATUS[0]}}; echo "$ec" > {status}; {cleanup}; echo; echo '[chronosphere] remote command finished (exit '"$ec"'). Press Up to recall.'; exec ${{SHELL:-bash}}"#,
                trap = trap,
                scp_cmd = scp_cmd,
                ssh_cmd = ssh_cmd,
                log = log,
                status = status,
                cleanup = cleanup,
            )
        };
        Ok(command)
    }
}

pub fn ensure_sshpass() -> Result<()> {
    if which::which("sshpass").is_err() {
        bail!(
            "sshpass not installed (apt install sshpass / brew install sshpass).\n\
             Set ssh_identity on the pivot for key-based auth, or install sshpass for password auth."
        );
    }
    Ok(())
}

pub fn write_remote_script(local_path: &Path, user_command: &str) -> Result<()> {
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let body = format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n{user_command}\n",
        user_command = user_command
    );
    std::fs::write(local_path, body)
        .with_context(|| format!("write remote script {}", local_path.display()))?;
    Ok(())
}

pub fn remote_script_path(job_id: &str) -> String {
    format!("/tmp/chrono-{}.sh", job_id)
}

pub fn shell_escape(s: &str) -> String {
    shell_words::quote(s).to_string()
}

/// Simple ssh/scp runner for deploy (pubkey, identity file, or sshpass password).
#[derive(Debug, Clone)]
pub struct SshDeploySession {
    pub port: u16,
    pub identity: Option<PathBuf>,
    pub password: Option<String>,
}

impl SshDeploySession {
    pub fn run_scp(&self, local: &Path, remote: &str) -> Result<()> {
        let mut cmd = self.base_cmd("scp", "-P");
        cmd.arg(local).arg(remote);
        let status = cmd.status().with_context(|| "scp")?;
        if !status.success() {
            bail!("scp failed with status {:?}", status.code());
        }
        Ok(())
    }

    pub fn run_ssh(&self, host: &str, remote_cmd: &str) -> Result<()> {
        let mut cmd = self.base_cmd("ssh", "-p");
        cmd.arg(host).arg(remote_cmd);
        let status = cmd.status().with_context(|| "ssh")?;
        if !status.success() {
            bail!(
                "ssh '{}' failed with status {:?}",
                remote_cmd,
                status.code()
            );
        }
        Ok(())
    }

    fn base_cmd(&self, prog: &str, port_flag: &str) -> Command {
        let mut command = if let Some(password) = &self.password {
            let mut command = Command::new("sshpass");
            command.arg("-e").arg(prog);
            command.env("SSHPASS", password);
            command
        } else {
            Command::new(prog)
        };
        command.arg(port_flag).arg(self.port.to_string());
        command.arg("-o").arg("StrictHostKeyChecking=accept-new");
        if let Some(identity) = &self.identity {
            command.arg("-i").arg(identity);
        }
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_session_keeps_password_out_of_arguments() {
        let session = SshDeploySession {
            port: 2222,
            identity: None,
            password: Some("s3cret".into()),
        };
        let command = session.base_cmd("ssh", "-p");
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|arg| arg == "s3cret"));
        assert_eq!(args.first().map(String::as_str), Some("-e"));
        let password = command
            .get_envs()
            .find(|(key, _)| key.to_string_lossy() == "SSHPASS")
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned());
        assert_eq!(password.as_deref(), Some("s3cret"));
    }

    #[test]
    fn remote_wrapper_contains_scp_and_ssh() {
        let conn = SshConn {
            target: "user@10.0.0.5".into(),
            port: 22,
            identity: None,
            password: None,
            control_path: PathBuf::from("/tmp/cm-test"),
        };
        let w = conn
            .remote_script_wrapper(
                Path::new("/tmp/a.sh"),
                "/tmp/chrono-id.sh",
                "/tmp/id.log",
                "/tmp/id.status",
                None,
                false,
            )
            .unwrap();
        assert!(w.contains("scp"));
        assert!(w.contains("ssh"));
        assert!(w.contains("tee"));
        assert!(
            w.contains("scp -P 22") || w.contains("scp -P '22'") || w.contains("scp -P \"22\"")
        );
        assert!(
            w.contains("ssh -p 22") || w.contains("ssh -p '22'") || w.contains("ssh -p \"22\"")
        );
    }

    #[test]
    fn remote_wrapper_uses_private_password_file() {
        let conn = SshConn {
            target: "user@10.0.0.5".into(),
            port: 22,
            identity: None,
            password: Some("s3cret".into()),
            control_path: PathBuf::from("/tmp/cm-test"),
        };
        let password_file = Path::new("/tmp/chrono-sshpass-test");
        let wrapper = conn
            .remote_script_wrapper(
                Path::new("/tmp/a.sh"),
                "/tmp/chrono-id.sh",
                "/tmp/id.log",
                "/tmp/id.status",
                Some(password_file),
                false,
            )
            .unwrap();
        assert!(wrapper.contains("sshpass -f"));
        assert!(wrapper.contains("/tmp/chrono-sshpass-test"));
        assert!(wrapper.contains("rm -f"));
        assert!(!wrapper.contains("s3cret"));
        assert!(!wrapper.contains("SSHPASS="));
    }

    #[test]
    fn resolve_ssh_auth_prefers_key_over_password() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("chrono-ssh-auth-{n}"));
        let ssh_dir = dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        let key = ssh_dir.join("id_mytarget");
        std::fs::write(&key, "fake-key").unwrap();

        let pivot = Pivot {
            name: "web01".into(),
            ssh_host: Some("10.0.0.5".into()),
            ssh_user: Some("user".into()),
            ssh_password: Some("secret".into()),
            ..Pivot::default()
        };
        let (identity, password) = resolve_ssh_auth(&pivot, &dir, Some("mytarget")).unwrap();
        assert!(identity.is_some());
        assert!(password.is_none());
        let w = SshConn::from_pivot(&pivot, &dir, Some("mytarget"))
            .unwrap()
            .remote_script_wrapper(
                Path::new("/tmp/a.sh"),
                "/tmp/chrono-id.sh",
                "/tmp/id.log",
                "/tmp/id.status",
                None,
                false,
            )
            .unwrap();
        assert!(!w.contains("sshpass"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_ssh_auth_uses_default_key_path() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("chrono-ssh-key-{n}"));
        let ssh_dir = dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("id_htb-box"), "fake-key").unwrap();

        let pivot = Pivot {
            name: "foothold".into(),
            ssh_host: Some("10.0.0.5".into()),
            ssh_user: Some("user".into()),
            ..Pivot::default()
        };
        let path = resolve_ssh_identity(&pivot, &dir, Some("htb-box")).unwrap();
        assert_eq!(path, ssh_dir.join("id_htb-box"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deploy_uses_correct_port_flags_for_ssh_and_scp() {
        let session = SshDeploySession {
            port: 2222,
            identity: None,
            password: None,
        };

        let ssh_cmd = session.base_cmd("ssh", "-p");
        let ssh_args: Vec<String> = ssh_cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(ssh_args.windows(2).any(|w| w[0] == "-p" && w[1] == "2222"));
        assert!(!ssh_args.iter().any(|a| a == "-P"));

        let scp_cmd = session.base_cmd("scp", "-P");
        let scp_args: Vec<String> = scp_cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(scp_args.windows(2).any(|w| w[0] == "-P" && w[1] == "2222"));
    }
}

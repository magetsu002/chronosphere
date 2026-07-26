#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


def replace_once(source: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, source, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError(f"{label}: expected one replacement, found {count}")
    return updated


ssh_path = Path("src/exec/ssh.rs")
ssh = ssh_path.read_text()

ssh = replace_once(
    ssh,
    r'''    fn wrap_prog\(&self, prog: &str, args: &\[String\]\) -> String \{.*?
    \}

    pub fn scp_to_remote\(&self, local: &Path, remote_path: &str\) -> Result<\(\)> \{.*?
    \}

    /// Build a shell command''',
    r'''    fn wrap_prog(
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

    /// Build a shell command''',
    "replace SSH command construction",
)

ssh = replace_once(
    ssh,
    r'''    pub fn remote_script_wrapper\(
        &self,
        local_script: &Path,
        remote_script: &str,
        log_path: &str,
        status_path: &str,
        interactive: bool,
    \) -> String \{.*?
    \}
\}

pub fn ensure_sshpass''',
    r'''    pub fn remote_script_wrapper(
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

pub fn ensure_sshpass''',
    "replace remote wrapper",
)

old_key_call = r'''        let w = conn.remote_script_wrapper(
            Path::new("/tmp/a.sh"),
            "/tmp/chrono-id.sh",
            "/tmp/id.log",
            "/tmp/id.status",
            false,
        );'''
new_key_call = r'''        let w = conn
            .remote_script_wrapper(
                Path::new("/tmp/a.sh"),
                "/tmp/chrono-id.sh",
                "/tmp/id.log",
                "/tmp/id.status",
                None,
                false,
            )
            .unwrap();'''
if ssh.count(old_key_call) != 1:
    raise RuntimeError(f"key wrapper test call: expected one match, found {ssh.count(old_key_call)}")
ssh = ssh.replace(old_key_call, new_key_call, 1)

ssh = replace_once(
    ssh,
    r'''    #\[test\]
    fn remote_wrapper_uses_sshpass_when_password_set\(\) \{.*?
    \}

    #\[test\]
    fn resolve_ssh_auth_prefers_key_over_password''',
    r'''    #[test]
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
    fn resolve_ssh_auth_prefers_key_over_password''',
    "replace SSH password regression test",
)

old_prefer_key_call = r'''        let w = SshConn::from_pivot(&pivot, &dir, Some("mytarget"))
            .unwrap()
            .remote_script_wrapper(
                Path::new("/tmp/a.sh"),
                "/tmp/chrono-id.sh",
                "/tmp/id.log",
                "/tmp/id.status",
                false,
            );'''
new_prefer_key_call = r'''        let w = SshConn::from_pivot(&pivot, &dir, Some("mytarget"))
            .unwrap()
            .remote_script_wrapper(
                Path::new("/tmp/a.sh"),
                "/tmp/chrono-id.sh",
                "/tmp/id.log",
                "/tmp/id.status",
                None,
                false,
            )
            .unwrap();'''
if ssh.count(old_prefer_key_call) != 1:
    raise RuntimeError(
        f"preferred-key wrapper test call: expected one match, found {ssh.count(old_prefer_key_call)}"
    )
ssh = ssh.replace(old_prefer_key_call, new_prefer_key_call, 1)

if "SSHPASS={} sshpass -e ssh" in ssh or 'cmd.push_str("SSHPASS=")' in ssh:
    raise RuntimeError("password remains embedded in a remote shell command")
if 'assert!(w.contains("s3cret"))' in ssh:
    raise RuntimeError("secret-exposure regression assertion remains")
ssh_path.write_text(ssh)

remote_path = Path("src/exec/remote.rs")
remote = remote_path.read_text()
remote = replace_once(
    remote,
    r'''    let remote_script = remote_script_path\(job_id\);
    Ok\(conn\.remote_script_wrapper\(
        &local_script,
        &remote_script,
        log_path,
        status_path,
        interactive,
    \)\)''',
    r'''    let remote_script = remote_script_path(job_id);
    let password_file = if let Some(password) = conn.password.as_deref() {
        let path = jobs_dir.join(format!("{}.sshpass", job_id));
        let contents = format!("{password}\n");
        crate::security::write_private_atomic(&path, contents.as_bytes())?;
        Some(path)
    } else {
        None
    };
    conn.remote_script_wrapper(
        &local_script,
        &remote_script,
        log_path,
        status_path,
        password_file.as_deref(),
        interactive,
    )''',
    "wire private password file into remote execution",
)
remote_path.write_text(remote)

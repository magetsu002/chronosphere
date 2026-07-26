#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_BRANCH = "fix/trust-and-reliability-v3"
FINAL_BRANCH = "fix/trust-and-reliability-final"
MILESTONES = [
    "fix: enforce explicit and safe execution context",
    "fix: redact secrets from storage and output",
    "fix: add reliable job cancellation and timeout handling",
    "fix: harden ssh deployment and authentication",
    "fix: validate templates before command execution",
    "fix: make engagement and cve persistence resilient",
    "ci: finish strict validation and release gates",
]


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(args), flush=True)
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="", flush=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args)}")
    return result


def exact_milestone_commits() -> dict[str, str]:
    log = run(
        "git",
        "log",
        "--format=%H%x09%s",
        f"origin/main..origin/{REPO_BRANCH}",
    ).stdout
    found: dict[str, list[str]] = {message: [] for message in MILESTONES}
    for line in log.splitlines():
        if "\t" not in line:
            continue
        sha, subject = line.split("\t", 1)
        if subject in found:
            found[subject].append(sha)
    bad = {message: shas for message, shas in found.items() if len(shas) != 1}
    if bad:
        raise RuntimeError(f"expected one V3 commit for each milestone, got: {bad}")
    return {message: shas[0] for message, shas in found.items()}


def cherry_pick(sha: str, message: str) -> None:
    result = run("git", "cherry-pick", sha, check=False)
    if result.returncode == 0:
        return

    conflicts = run("git", "diff", "--name-only", "--diff-filter=U").stdout.splitlines()
    allowed = [
        path
        for path in conflicts
        if path.startswith(".github/")
        and any(token in path for token in ("replay", "failure", "resolve-main", "hardening"))
    ]
    if conflicts and sorted(conflicts) == sorted(allowed):
        for path in allowed:
            run("git", "rm", "-f", "--ignore-unmatch", "--", path)
        run("git", "cherry-pick", "--continue")
        return

    run("git", "cherry-pick", "--abort", check=False)
    raise RuntimeError(f"conflict while replaying {message}: {conflicts}")


def replace_once(source: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, source, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError(f"{label}: expected one replacement, got {count}")
    return updated


def patch_remote_ssh_password_handling() -> None:
    ssh_path = Path("src/exec/ssh.rs")
    ssh = ssh_path.read_text()

    ssh = replace_once(
        ssh,
        r'''    fn wrap_prog\(&self, prog: &str, args: &\[String\]\) -> String \{.*?
    \}

    pub fn scp_to_remote\(&self, local: &Path, remote_path: &str\) -> Result<\(\)> \{.*?
    \}

    /// Build a shell command''',
        '''    fn wrap_prog(
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
        "replace SSH wrapper and SCP execution",
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
        '''    pub fn remote_script_wrapper(
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
                "{trap}{scp_cmd} && {ssh_cmd}; ec=$?; echo \"$ec\" > {status}; {cleanup}",
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
        "replace remote SSH wrapper",
    )

    ssh = ssh.replace(
        '''            "/tmp/id.status",
            false,
        );''',
        '''            "/tmp/id.status",
            None,
            false,
        )
        .unwrap();''',
    )
    ssh = ssh.replace(
        '''                "/tmp/id.status",
                false,
            );''',
        '''                "/tmp/id.status",
                None,
                false,
            )
            .unwrap();''',
    )

    ssh = replace_once(
        ssh,
        r'''    #\[test\]
    fn remote_wrapper_uses_sshpass_when_password_set\(\) \{.*?
    \}

    #\[test\]
    fn resolve_ssh_auth_prefers_key_over_password''',
        '''    #[test]
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
        "replace password wrapper regression test",
    )

    if "SSHPASS={} sshpass -e ssh" in ssh or 'cmd.push_str("SSHPASS=")' in ssh:
        raise RuntimeError("remote SSH command still embeds SSHPASS in a shell string")
    if 'assert!(w.contains("s3cret"))' in ssh:
        raise RuntimeError("old secret-exposure test remains")
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
        '''    let remote_script = remote_script_path(job_id);
    let password_file = if let Some(password) = conn.password.as_deref() {
        let path = jobs_dir.join(format!("{}.sshpass", job_id));
        let contents = format!("{password}\\n");
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
        "wire private SSH password file",
    )
    remote_path.write_text(remote)


def remove_bootstrap_artifacts() -> None:
    tracked = run("git", "ls-files", ".github").stdout.splitlines()
    disposable = [
        path
        for path in tracked
        if any(token in path for token in ("replay", "failure", "resolve-main", "finalize_hardening"))
    ]
    if disposable:
        run("git", "rm", "-f", "--", *disposable)
        run("git", "commit", "--amend", "--no-edit")


def main() -> None:
    run("git", "config", "user.name", "Chronosphere Hardening")
    run("git", "config", "user.email", "actions@users.noreply.github.com")
    run("git", "fetch", "--prune", "origin", "main", REPO_BRANCH)

    exists = run(
        "git",
        "ls-remote",
        "--exit-code",
        "--heads",
        "origin",
        f"refs/heads/{FINAL_BRANCH}",
        check=False,
    )
    if exists.returncode == 0:
        raise RuntimeError(f"refusing to overwrite existing branch {FINAL_BRANCH}")

    commits = exact_milestone_commits()
    run("git", "switch", "--detach", "origin/main")
    run("git", "switch", "-c", FINAL_BRANCH)

    for index, message in enumerate(MILESTONES, start=1):
        cherry_pick(commits[message], message)
        if index == 4:
            patch_remote_ssh_password_handling()
            run("cargo", "fmt")
            run("git", "add", "src/exec/ssh.rs", "src/exec/remote.rs")
            run("git", "commit", "--amend", "--no-edit")

    remove_bootstrap_artifacts()

    run("cargo", "fmt", "--check")
    run(
        "cargo",
        "clippy",
        "--locked",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "clippy::correctness",
        "-D",
        "clippy::suspicious",
    )
    run("cargo", "test", "--locked", "--all-targets")
    run("cargo", "build", "--locked", "--release")
    run("git", "diff", "--check")

    count = int(run("git", "rev-list", "--count", "origin/main..HEAD").stdout.strip())
    if count != 7:
        raise RuntimeError(f"expected exactly 7 milestone commits, found {count}")

    changed = run("git", "status", "--porcelain").stdout.strip()
    if changed:
        raise RuntimeError(f"working tree is not clean:\n{changed}")

    run("git", "push", "origin", f"HEAD:refs/heads/{FINAL_BRANCH}")


if __name__ == "__main__":
    main()

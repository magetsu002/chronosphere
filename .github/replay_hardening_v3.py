#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import traceback
from pathlib import Path

BRANCH = "fix/trust-and-reliability-v3"
V1 = "origin/fix/trust-and-reliability-v1"
ROOT = Path.cwd()
LOG: list[str] = []


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    LOG.append("$ " + " ".join(args))
    result = subprocess.run(args, text=True, capture_output=True)
    if result.stdout:
        LOG.append(result.stdout)
    if result.stderr:
        LOG.append(result.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args)}")
    return result


def read(path: str) -> str:
    return Path(path).read_text()


def write(path: str, content: str) -> None:
    Path(path).write_text(content)


def apply_commit(sha: str) -> None:
    result = run("git", "cherry-pick", "--no-commit", "-X", "ours", sha, check=False)
    if result.returncode == 0:
        return
    conflicts = run("git", "diff", "--name-only", "--diff-filter=U").stdout.splitlines()
    for path in conflicts:
        checkout = run("git", "checkout", "--ours", "--", path, check=False)
        if checkout.returncode != 0:
            run("git", "rm", "-f", "--", path)
    run("git", "add", "-A")
    run("git", "cherry-pick", "--quit")
    unresolved = run("git", "diff", "--name-only", "--diff-filter=U").stdout.strip()
    if unresolved:
        raise RuntimeError(f"unresolved cherry-pick paths: {unresolved}")


def commit_phase(message: str) -> None:
    run("cargo", "fmt")
    run("git", "add", "-A")
    if run("git", "diff", "--cached", "--quiet", check=False).returncode == 0:
        raise RuntimeError(f"milestone produced no changes: {message}")
    run("git", "commit", "-m", message)


def patch_context() -> None:
    path = Path("src/cli.rs")
    source = path.read_text()
    source = source.replace(
        '    Engagement::load(root.join(&pick)).with_context(|| format!("load engagement {}", pick))',
        '    Engagement::load_named(root, &pick).with_context(|| format!("load engagement {}", pick))',
    )
    old = "    if let Some(name) = engagement {\n        let dir = root.join(name);"
    new = "    if let Some(name) = engagement {\n        Engagement::validate_name(name)?;\n        let dir = root.join(name);"
    if old in source:
        source = source.replace(old, new, 1)

    start = source.index("fn build_context(")
    end = source.index("\nfn resolve(", start)
    replacement = '''fn build_context(
    engagement: &Engagement,
    target_override: &Option<String>,
    ap_override: &Option<String>,
    cred_override: &Option<String>,
    extra_vars: &[String],
) -> Result<RenderContext> {
    let mut ctx = RenderContext::default();
    let target = match target_override.as_deref() {
        Some(name) => Some(
            engagement
                .targets
                .targets
                .iter()
                .find(|target| target.name == name)
                .ok_or_else(|| anyhow!("no target named {}", name))?,
        ),
        None => engagement.targets.active(),
    };
    if let Some(target) = target {
        ctx.target = Some(target.clone());
    }

    let ap = match ap_override.as_deref() {
        Some(name) => Some(
            engagement
                .aps
                .aps
                .iter()
                .find(|ap| ap.name == name)
                .ok_or_else(|| anyhow!("no access point named {}", name))?,
        ),
        None => engagement.aps.active(),
    };
    if let Some(ap) = ap {
        ctx.ap = Some(ap.clone());
    }

    let profile = match cred_override.as_deref() {
        Some(name) => Some(
            engagement
                .profiles
                .profiles
                .iter()
                .find(|profile| profile.name == name)
                .ok_or_else(|| anyhow!("no credential profile named {}", name))?,
        ),
        None => engagement.profiles.active(),
    };
    if let Some(profile) = profile {
        ctx.profile = Some(profile.clone());
    }

    ctx.pivot_tunnel = engagement.pivots.active_tunnel().cloned();
    ctx.pivot_remote = engagement.pivots.active_remote().cloned();
    ctx.execution_mode = engagement.pivots.execution_mode;
    ctx.engagement_dir = Some(engagement.dir.clone());
    ctx.globals = engagement.variables.values.clone();
    for value in extra_vars {
        if let Some((key, value)) = value.split_once('=') {
            ctx.globals
                .insert(key.trim().to_string(), value.to_string());
        }
    }
    Ok(ctx)
}
'''
    source = source[:start] + replacement + source[end:]
    old_call = '''    let ctx = build_context(
        &e,
        target_override,
        ap_override,
        cred_override,
        extra_vars,
    );'''
    new_call = '''    let ctx = build_context(
        &e,
        target_override,
        ap_override,
        cred_override,
        extra_vars,
    )?;'''
    if old_call in source:
        source = source.replace(old_call, new_call, 1)
    elif new_call not in source:
        raise RuntimeError("resolve context call not found")
    path.write_text(source)


def patch_secrets() -> None:
    main = Path("src/main.rs")
    source = main.read_text()
    if "mod security;" not in source:
        marker = "mod render;\n"
        if marker not in source:
            raise RuntimeError("render module marker not found")
        source = source.replace(marker, marker + "mod security;\n", 1)
    main.write_text(source)

    cli = Path("src/cli.rs")
    source = cli.read_text()
    raw = '        let val = value.filter(|v| !v.is_empty()).map(|s| s.as_str()).unwrap_or("-");'
    replacement = '''        let val = if is_set && crate::security::is_sensitive_key(&name) {
            "<redacted>"
        } else {
            value
                .filter(|value| !value.is_empty())
                .map(String::as_str)
                .unwrap_or("-")
        };'''
    if raw in source:
        source = source.replace(raw, replacement, 1)
    if "let redacted = crate::security::redact_for_engagement(resolved, &e);" not in source:
        marker = '    eprintln!("[chrono] $ {}", resolved);'
        if marker not in source:
            raise RuntimeError("CLI execution print marker not found")
        source = source.replace(
            marker,
            '    let redacted = crate::security::redact_for_engagement(resolved, &e);\n    eprintln!("[chrono] $ {}", redacted);',
            1,
        )
        source = source.replace("        resolved: resolved.to_string(),", "        resolved: redacted,", 1)
    cli.write_text(source)


def patch_ssh() -> None:
    path = Path("src/exec/ssh.rs")
    source = path.read_text()
    old = '''    fn base_cmd(&self, prog: &str, port_flag: &str) -> Command {
        let mut cmd = if let Some(pw) = &self.password {
            let mut c = Command::new("sshpass");
            c.arg("-p").arg(pw).arg(prog);
            c
        } else {
            Command::new(prog)
        };
        cmd.arg(port_flag).arg(self.port.to_string());
        cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
        if let Some(id) = &self.identity {
            cmd.arg("-i").arg(id);
        }
        cmd
    }
'''
    new = '''    fn base_cmd(&self, prog: &str, port_flag: &str) -> Command {
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
'''
    if old in source:
        source = source.replace(old, new, 1)
    source = source.replace(
        '''        if let Some(pw) = &self.password {
            cmd.push_str("sshpass -p ");
            cmd.push_str(&shell_escape(pw));
            cmd.push(' ');
        }
        cmd.push_str(prog);''',
        '''        if let Some(password) = &self.password {
            cmd.push_str("SSHPASS=");
            cmd.push_str(&shell_escape(password));
            cmd.push_str(" sshpass -e ");
        }
        cmd.push_str(prog);''',
    )
    source = source.replace(
        '''            format!(
                "sshpass -p {} ssh",
                shell_escape(self.password.as_ref().unwrap())
            )''',
        '''            format!(
                "SSHPASS={} sshpass -e ssh",
                shell_escape(self.password.as_ref().unwrap())
            )''',
    )
    marker = "mod tests {\n    use super::*;\n"
    if "deploy_session_keeps_password_out_of_arguments" not in source:
        tests = '''mod tests {
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
    fn deploy_session_uses_protocol_specific_port_flags() {
        let session = SshDeploySession {
            port: 2222,
            identity: None,
            password: None,
        };
        let ssh_args: Vec<String> = session
            .base_cmd("ssh", "-p")
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let scp_args: Vec<String> = session
            .base_cmd("scp", "-P")
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(ssh_args.first().map(String::as_str), Some("-p"));
        assert_eq!(scp_args.first().map(String::as_str), Some("-P"));
    }
'''
        if marker not in source:
            raise RuntimeError("SSH test module marker not found")
        source = source.replace(marker, tests, 1)
    if "sshpass -p " in source:
        raise RuntimeError("plaintext sshpass command construction remains")
    path.write_text(source)

    cargo = Path("Cargo.toml")
    content = cargo.read_text()
    if 'rpassword = "7"' not in content:
        content = content.replace('flate2 = "1"\n', 'flate2 = "1"\nrpassword = "7"\n', 1)
    cargo.write_text(content)


def patch_templates() -> None:
    path = Path("src/cli.rs")
    source = path.read_text()
    if "has unresolved placeholders" not in source:
        old = '''            if dry_run {
                println!("{}", resolved);
                return Ok(true);
            }
            run_with_history(&root, cli.opts.engagement.as_deref(), &id, &resolved).await?;'''
        new = '''            if dry_run {
                println!("{}", resolved);
                return Ok(true);
            }
            let unresolved = crate::render::find_unresolved(&resolved);
            if !unresolved.is_empty() {
                bail!(
                    "command '{}' has unresolved placeholders: {}",
                    id,
                    unresolved.join(", ")
                );
            }
            run_with_history(&root, cli.opts.engagement.as_deref(), &id, &resolved).await?;'''
        if old not in source:
            raise RuntimeError("latest CLI run block not found")
        source = source.replace(old, new, 1)
    path.write_text(source)


def patch_cve_transaction() -> None:
    current_path = Path("src/cve/store.rs")
    current = current_path.read_text()
    hardened = run("git", "show", f"{V1}:src/cve/store.rs").stdout
    start_token = "    pub fn upsert(&mut self, record: &CveRecord) -> Result<bool> {"
    end_token = "\n    fn replace_children"
    old_start = hardened.index(start_token)
    old_end = hardened.index(end_token, old_start)
    new_start = current.index(start_token)
    new_end = current.index(end_token, new_start)
    current_path.write_text(current[:new_start] + hardened[old_start:old_end] + current[new_end:])


def patch_ci() -> None:
    write(".github/workflows/rust.yml", run("git", "show", f"{V1}:.github/workflows/rust.yml").stdout)
    write(".github/workflows/release.yml", run("git", "show", f"{V1}:.github/workflows/release.yml").stdout)
    cargo = Path("Cargo.toml")
    source = cargo.read_text()
    if 'rust-version = "1.88"' not in source:
        source = source.replace('edition = "2024"\n', 'edition = "2024"\nrust-version = "1.88"\n', 1)
    if 'repository = "https://github.com/magetsu002/chronosphere"' not in source:
        description = 'description = "Vim-flavored TUI for browsing, templating, and firing pentest commands from a per-engagement project directory."\n'
        source = source.replace(
            description,
            description + 'repository = "https://github.com/magetsu002/chronosphere"\nreadme = "README.md"\n',
            1,
        )
    cargo.write_text(source)
    readme = Path("README.md")
    readme.write_text(readme.read_text().replace("Rust 1.83+", "Rust 1.88+").replace("Rust 1.85+", "Rust 1.88+"))


def main() -> None:
    start = run("git", "rev-parse", "HEAD").stdout.strip()
    run("git", "config", "user.name", "Chronosphere Hardening")
    run("git", "config", "user.email", "actions@users.noreply.github.com")
    try:
        run("git", "fetch", "origin", "fix/trust-and-reliability-v1")

        apply_commit("a74ff8e7bd47abc5e2471d90f58fb767509ac37a")
        patch_context()
        commit_phase("fix: enforce explicit and safe execution context")

        apply_commit("27cdf8d242b47086fc905b6bb391b456980f51af")
        apply_commit("a830dbe03f8bd185cd74bf92ebaddf2c05f57236")
        patch_secrets()
        commit_phase("fix: redact secrets from storage and output")

        apply_commit("f770bad6e78f3a6fdcd6a0318ce9a07235321af4")
        apply_commit("be75b1f39c9b8a468a050877a21d8149a557c68f")
        apply_commit("91f516ebe2273b0fcccf056113c02bfdda9100a2")
        commit_phase("fix: add reliable job cancellation and timeout handling")

        apply_commit("ec0b38503022eb39475fed3a23f4d71a26546e63")
        apply_commit("3edd2d6abaacd65d98a1c8dc4655356ab62b897f")
        patch_ssh()
        run("cargo", "generate-lockfile")
        commit_phase("fix: harden ssh deployment and authentication")

        apply_commit("219ffb073762f7d66bae10724ab672281046d5a7")
        apply_commit("33ea82916ff43882e60a6b16178cc3b5295376ae")
        patch_templates()
        commit_phase("fix: validate templates before command execution")

        apply_commit("ac8fe981ec5fe92c12d53fdcd08d34370fb80057")
        patch_cve_transaction()
        commit_phase("fix: make engagement and cve persistence resilient")

        patch_ci()
        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)
        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)
        run("cargo", "generate-lockfile")
        commit_phase("ci: finish strict validation and release gates")

        run("cargo", "fmt", "--check")
        run("cargo", "clippy", "--locked", "--all-targets", "--all-features", "--", "-D", "clippy::correctness", "-D", "clippy::suspicious")
        run("cargo", "test", "--locked", "--all-targets")
        run("cargo", "build", "--locked", "--release")
        run("git", "push", "origin", f"HEAD:{BRANCH}")
    except Exception:
        LOG.append(traceback.format_exc())
        run("git", "reset", "--hard", start, check=False)
        Path(".github/replay_hardening_v3.py").unlink(missing_ok=True)
        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)
        failure = Path(".github/v3-replay-failure.log")
        failure.write_text("\n".join(LOG)[-120000:])
        run("git", "add", "-A", check=False)
        run("git", "commit", "-m", "chore: capture clean hardening replay failure", check=False)
        run("git", "push", "origin", f"HEAD:{BRANCH}", check=False)


if __name__ == "__main__":
    main()

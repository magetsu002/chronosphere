#!/usr/bin/env python3
from pathlib import Path

path = Path("/tmp/replay_hardening_v3.py")
source = path.read_text()

jobs_old = '''        apply_commit("f770bad6e78f3a6fdcd6a0318ce9a07235321af4")
        apply_commit("be75b1f39c9b8a468a050877a21d8149a557c68f")
        apply_commit("91f516ebe2273b0fcccf056113c02bfdda9100a2")
        commit_phase("fix: add reliable job cancellation and timeout handling")
'''
jobs_new = '''        apply_commit("f770bad6e78f3a6fdcd6a0318ce9a07235321af4")
        apply_commit("be75b1f39c9b8a468a050877a21d8149a557c68f")
        apply_commit("91f516ebe2273b0fcccf056113c02bfdda9100a2")
        for module in (
            "src/mcp/tools.rs",
            "src/mcp/mod.rs",
            "src/engagement/history.rs",
            "src/exec/mod.rs",
        ):
            write(module, run("git", "show", f"{V1}:{module}").stdout)
        commit_phase("fix: add reliable job cancellation and timeout handling")
'''
if source.count(jobs_old) != 1:
    raise SystemExit("job milestone block not found exactly once")
source = source.replace(jobs_old, jobs_new, 1)

start = source.index("def patch_ssh() -> None:")
end = source.index("\n\ndef patch_templates()", start)
patch_ssh = '''def patch_ssh() -> None:
    path = Path("src/exec/ssh.rs")
    source = run("git", "show", "origin/main:src/exec/ssh.rs").stdout
    source = source.replace(
        ''' + '"""' + '''        if let Some(pw) = &self.password {
            cmd.push_str("sshpass -p ");
            cmd.push_str(&shell_escape(pw));
            cmd.push(' ');
        }
        cmd.push_str(prog);''' + '"""' + ''',
        ''' + '"""' + '''        if let Some(password) = &self.password {
            cmd.push_str("SSHPASS=");
            cmd.push_str(&shell_escape(password));
            cmd.push_str(" sshpass -e ");
        }
        cmd.push_str(prog);''' + '"""' + ''',
    )
    source = source.replace(
        ''' + '"""' + '''            format!(
                "sshpass -p {} ssh",
                shell_escape(self.password.as_ref().unwrap())
            )''' + '"""' + ''',
        ''' + '"""' + '''            format!(
                "SSHPASS={} sshpass -e ssh",
                shell_escape(self.password.as_ref().unwrap())
            )''' + '"""' + ''',
    )
    old = ''' + '"""' + '''    fn base_cmd(&self, prog: &str, port_flag: &str) -> Command {
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
''' + '"""' + '''
    new = ''' + '"""' + '''    fn base_cmd(&self, prog: &str, port_flag: &str) -> Command {
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
''' + '"""' + '''
    if source.count(old) != 1:
        raise RuntimeError("latest-main SSH deploy constructor not found exactly once")
    source = source.replace(old, new, 1)

    marker = "mod tests {\\n    use super::*;\\n"
    if "deploy_session_keeps_password_out_of_arguments" not in source:
        password_test = ''' + '"""' + '''mod tests {
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
''' + '"""' + '''
        if marker not in source:
            raise RuntimeError("SSH test module marker not found")
        source = source.replace(marker, password_test, 1)
    if "sshpass -p " in source:
        raise RuntimeError("plaintext sshpass command construction remains")
    path.write_text(source)

    cargo = Path("Cargo.toml")
    content = cargo.read_text()
    if 'rpassword = "7"' not in content:
        content = content.replace('flate2 = "1"\\n', 'flate2 = "1"\\nrpassword = "7"\\n', 1)
    cargo.write_text(content)
'''
source = source[:start] + patch_ssh + source[end:]

source = source.replace(
    '        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)',
    '        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/fix_replay_v3_compile.py").unlink(missing_ok=True)\n        Path(".github/v3-replay-failure.txt").unlink(missing_ok=True)',
    1,
)
source = source.replace(
    '        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    '        Path(".github/fix_replay_v3_context.py").unlink(missing_ok=True)\n        Path(".github/fix_replay_v3_compile.py").unlink(missing_ok=True)\n        Path(".github/workflows/replay-hardening-v3.yml").unlink(missing_ok=True)',
    1,
)
path.write_text(source)

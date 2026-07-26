//! `chronosphere deploy <host>` — ship the binary to a remote (Pwnbox / lab box)
//! over scp, then bootstrap it. Supports both pubkey and password auth.
//!
//! Auth strategy:
//!   - Default: use the system SSH agent / `~/.ssh/config` (pubkey).
//!   - `--identity <key>`: pass `-i <key>` to ssh/scp.
//!   - `--password <pw>`: shell out via `sshpass -p` if installed.
//!   - `--ask-password`: prompt once on the controlling terminal, then use sshpass.
//!
//! We deliberately avoid linking an SSH library (libssh2/russh) to keep the
//! binary small for Pwnbox use — calling out to ssh/scp is universally available.

use crate::exec::ssh::{shell_escape, SshDeploySession};
use anyhow::{Context, Result, bail};
use clap::Args;
use std::path::{Path, PathBuf};

#[derive(Args, Debug, Clone)]
pub struct DeployArgs {
    /// Target host. Either `user@host` or an alias from `~/.ssh/config`.
    pub host: String,

    /// SSH port.
    #[arg(short = 'p', long, default_value_t = 22)]
    pub port: u16,

    /// SSH user (overrides whatever's in `host` / ssh_config).
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// Pubkey to use for auth.
    #[arg(short = 'i', long)]
    pub identity: Option<PathBuf>,

    /// Plaintext password (uses sshpass under the hood — insecure on shared hosts).
    #[arg(long)]
    pub password: Option<String>,

    /// Prompt for the password once and reuse it for ssh + scp calls.
    #[arg(long)]
    pub ask_password: bool,

    /// Path to a pre-built linux binary to ship. Defaults to the running binary
    /// (only useful if you're already on Linux).
    #[arg(long)]
    pub binary: Option<PathBuf>,

    /// Where to drop the binary on the remote.
    #[arg(long, default_value = "/usr/local/bin/chronosphere")]
    pub remote_path: String,

    /// Skip running `chronosphere update-templates` on the remote after copy.
    #[arg(long)]
    pub no_extract: bool,

    /// Use sudo on the remote when writing the binary / extracting templates.
    #[arg(long)]
    pub sudo: bool,

    /// Print what would happen without actually doing it.
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(args: DeployArgs) -> Result<()> {
    let binary = pick_binary(args.binary.as_deref())?;
    warn_if_not_elf(&binary)?;
    let auth = resolve_auth(&args)?;
    let host_spec = host_spec(&args);

    println!("[chronosphere] deploying {} → {}:{}", binary.display(), host_spec.display, args.remote_path);

    let remote_tmp = format!("/tmp/chronosphere.deploy.{}", uuid::Uuid::new_v4());

    if args.dry_run {
        println!("[dry-run] scp {} :{}", binary.display(), remote_tmp);
        println!("[dry-run] ssh {} 'install {} → {}'", host_spec.display, remote_tmp, args.remote_path);
        if !args.no_extract {
            println!("[dry-run] ssh {} '{} update-templates --force'", host_spec.display, args.remote_path);
        }
        return Ok(());
    }

    // 1) scp binary to /tmp on remote
    let ssh = deploy_session(&args, &auth);
    ssh.run_scp(&binary, &format!("{}:{}", host_spec.target, remote_tmp))?;

    // 2) install into remote_path (with sudo if asked) + chmod +x
    let install_cmd = build_install_cmd(&remote_tmp, &args.remote_path, args.sudo);
    ssh.run_ssh(&host_spec.target, &install_cmd)?;

    // 3) extract embedded templates (so the remote has the command library)
    if !args.no_extract {
        let extract_cmd = format!("{} update-templates --force >/dev/null", args.remote_path);
        ssh.run_ssh(&host_spec.target, &extract_cmd)?;
    }

    // 4) sanity check version
    let version_cmd = format!("{} --version", args.remote_path);
    ssh.run_ssh(&host_spec.target, &version_cmd)?;

    println!("[chronosphere] deploy complete. Try:");
    println!("    ssh {} {} list categories", host_spec.display, args.remote_path);
    println!("    ssh {} {} mcp-serve   # (the MCP endpoint for cursor-agent)", host_spec.display, args.remote_path);
    Ok(())
}

struct HostSpec {
    /// What we hand to ssh/scp (`user@host` or alias).
    target: String,
    /// What we print to the user (may include port note).
    display: String,
}

fn host_spec(args: &DeployArgs) -> HostSpec {
    let target = match &args.user {
        Some(u) if !args.host.contains('@') => format!("{}@{}", u, args.host),
        _ => args.host.clone(),
    };
    let display = if args.port == 22 {
        target.clone()
    } else {
        format!("{} (port {})", target, args.port)
    };
    HostSpec { target, display }
}

fn pick_binary(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.exists() {
            bail!("binary not found: {}", p.display());
        }
        return Ok(p.to_path_buf());
    }
    let cur = std::env::current_exe().context("current_exe")?;
    Ok(cur)
}

/// Check the magic bytes of `path`. Pwnbox is Linux/x86_64 so we want an ELF
/// binary; warn loudly if the user is about to scp a macOS Mach-O.
fn warn_if_not_elf(path: &Path) -> Result<()> {
    let mut buf = [0u8; 4];
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    use std::io::Read;
    let n = f.read(&mut buf).context("read magic")?;
    if n < 4 {
        return Ok(());
    }
    let is_elf = buf == [0x7f, b'E', b'L', b'F'];
    let is_macho = buf == [0xcf, 0xfa, 0xed, 0xfe] || buf == [0xfe, 0xed, 0xfa, 0xcf]
        || buf == [0xce, 0xfa, 0xed, 0xfe] || buf == [0xca, 0xfe, 0xba, 0xbe];
    if !is_elf {
        eprintln!(
            "[chronosphere] warning: {} is not an ELF binary ({})",
            path.display(),
            if is_macho { "looks like Mach-O / macOS" } else { "unknown format" }
        );
        eprintln!("[chronosphere] Pwnbox expects Linux x86_64 (ELF). On macOS, plain");
        eprintln!("  cargo build --target … will fail — you need a Linux linker.");
        eprintln!("Option A (Zig):  brew install zig && cargo install cargo-zigbuild");
        eprintln!("  cargo zigbuild --release --target x86_64-unknown-linux-musl");
        eprintln!("Option B (Docker): cross build --release --target x86_64-unknown-linux-gnu");
        eprintln!("See README.md § Cross-compile for Pwnbox.");
        eprintln!("Then: chronosphere deploy <host> --binary target/.../release/chronosphere");
        eprintln!();
    }
    Ok(())
}

enum Auth {
    Agent,
    Identity(PathBuf),
    Password(String),
}

fn resolve_auth(args: &DeployArgs) -> Result<Auth> {
    if args.password.is_some() && args.ask_password {
        bail!("--password and --ask-password are mutually exclusive");
    }
    if let Some(pw) = &args.password {
        ensure_sshpass()?;
        return Ok(Auth::Password(pw.clone()));
    }
    if args.ask_password {
        ensure_sshpass()?;
        let pw = prompt_password("SSH password: ")?;
        return Ok(Auth::Password(pw));
    }
    if let Some(id) = &args.identity {
        if !id.exists() {
            bail!("identity file not found: {}", id.display());
        }
        return Ok(Auth::Identity(id.clone()));
    }
    Ok(Auth::Agent)
}

fn ensure_sshpass() -> Result<()> {
    if which::which("sshpass").is_err() {
        bail!(
            "sshpass not installed (apt install sshpass / brew install sshpass).\n\
             Or use pubkey auth: `ssh-copy-id <host>` then re-run without --password."
        );
    }
    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("read password")
}

fn deploy_session(args: &DeployArgs, auth: &Auth) -> SshDeploySession {
    SshDeploySession {
        port: args.port,
        identity: match auth {
            Auth::Identity(id) => Some(id.clone()),
            _ => args.identity.clone(),
        },
        password: match auth {
            Auth::Password(pw) => Some(pw.clone()),
            _ => None,
        },
    }
}

fn build_install_cmd(src: &str, dest: &str, sudo: bool) -> String {
    let sudo_prefix = if sudo { "sudo " } else { "" };
    format!(
        "set -e; \
         {sudo}install -m 0755 {src} {dest} 2>/dev/null \
         || {sudo}cp {src} {dest} && {sudo}chmod 0755 {dest}; \
         rm -f {src}",
        sudo = sudo_prefix,
        src = shell_escape(src),
        dest = shell_escape(dest),
    )
}

/// Helper for `chronosphere mcp-config` — emit a snippet pointing at a remote host.
pub fn mcp_config_ssh_snippet(host: &str, port: u16, remote_path: &str, identity: Option<&Path>) -> String {
    let mut args = vec![
        "-o", "ControlMaster=auto",
        "-o", "ControlPath=~/.ssh/cm-%r@%h:%p",
        "-o", "ControlPersist=10m",
        "-o", "ServerAliveInterval=30",
    ];
    let port_str;
    if port != 22 {
        port_str = port.to_string();
        args.extend_from_slice(&["-p", &port_str]);
    }
    let id_str;
    if let Some(id) = identity {
        id_str = id.to_string_lossy().to_string();
        args.extend_from_slice(&["-i", &id_str]);
    }
    let args_json: Vec<String> = args
        .into_iter()
        .map(|s| format!("\"{}\"", s))
        .chain(std::iter::once(format!("\"{}\"", host)))
        .chain(std::iter::once(format!("\"{}\"", remote_path)))
        .chain(std::iter::once("\"mcp-serve\"".to_string()))
        .collect();
    format!(
        r#"{{
  "mcpServers": {{
    "chronosphere-{}": {{
      "command": "ssh",
      "args": [{}]
    }}
  }}
}}"#,
        host_alias(host),
        args_json.join(", ")
    )
}

pub fn mcp_config_local_snippet(bin_path: &str) -> String {
    format!(
        r#"{{
  "mcpServers": {{
    "chronosphere": {{
      "command": "{}",
      "args": ["mcp-serve"]
    }}
  }}
}}"#,
        bin_path
    )
}

fn host_alias(host: &str) -> String {
    host.split('@')
        .last()
        .unwrap_or(host)
        .replace('.', "-")
        .replace(':', "-")
}

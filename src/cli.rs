//! Headless CLI surface. The TUI remains the default mode; subcommands are for
//! scripting and CI-friendly use (`chronosphere render`, `chronosphere doctor`,
//! `chronosphere new pl-zephyr`, etc.).

use crate::config;
use crate::engagement::{
    AccessPoint, CredKind, CredentialProfile, Engagement, ExecutionMode, JobRecord, JobStatus,
    Pivot, Target,
};
use crate::library::CommandLibrary;
use crate::render::{self, RenderContext};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

// Engagement / targeting flags shared by library and CRUD subcommands.
#[derive(Args, Debug, Clone, Default)]
#[command(next_help_heading = "Engagement")]
pub struct EngagementOpts {
    /// Engagement name (defaults to last-used or single existing one).
    #[arg(short = 'e', long, global = true)]
    pub engagement: Option<String>,

    /// Override the engagement root directory.
    #[arg(long, global = true)]
    pub root: Option<PathBuf>,

    /// Target name to apply for this invocation.
    #[arg(short = 't', long, global = true)]
    pub target: Option<String>,

    /// Credential profile name to apply for this invocation.
    #[arg(short = 'c', long, global = true)]
    pub creds: Option<String>,

    /// Access point name to apply for this invocation.
    #[arg(short = 'a', long, global = true)]
    pub ap: Option<String>,
}

impl EngagementOpts {
    pub fn engagements_root(&self) -> PathBuf {
        self.root.clone().unwrap_or_else(config::engagements_root)
    }
}

#[derive(Parser, Debug)]
#[command(name = "chronosphere", version, about = "Vim TUI + CLI for pentest engagement commands", long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub opts: EngagementOpts,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Launch the TUI (default when no subcommand given).
    Tui,

    /// Create a new engagement directory.
    New {
        name: String,
        #[arg(long)]
        notes: Option<String>,
    },

    /// List engagements / categories / commands.
    List(ListArgs),

    /// Show a command (resolved with current target/creds).
    Show {
        id: String,
        #[arg(short = 'v', long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
    },

    /// Print the resolved command (shell-safe, single line).
    Render {
        id: String,
        #[arg(short = 'v', long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
    },

    /// Render and copy a command to the clipboard.
    Yank {
        id: String,
        /// Copy the raw template instead of the resolved command.
        #[arg(long)]
        raw: bool,
    },

    /// Execute a command (runs in current shell, prints output).
    Run {
        id: String,
        /// Replace `KEY=VALUE` placeholders for this run only.
        #[arg(short = 'v', long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Don't execute; print the fully substituted command instead.
        #[arg(long, visible_alias = "expand")]
        dry_run: bool,
    },

    /// Search the command library.
    Search { query: String },

    /// Target CRUD.
    #[command(subcommand)]
    Targets(TargetCmd),

    /// WiFi access point CRUD.
    #[command(subcommand)]
    Aps(ApCmd),

    /// Foothold pivot CRUD (ligolo tunnel + SSH remote exec).
    #[command(subcommand)]
    Pivots(PivotCmd),

    /// Credential CRUD.
    #[command(subcommand)]
    Creds(CredsCmd),

    /// Template variable placeholders for the active engagement.
    #[command(subcommand)]
    Variables(VariableCmd),

    /// Check installed tools referenced by the library.
    Doctor {
        /// Only print missing tools (script-friendly).
        #[arg(long)]
        missing: bool,
    },

    /// Extract embedded built-in commands to the user data dir.
    UpdateTemplates {
        /// Overwrite local edits (default: keep local changes).
        #[arg(long)]
        force: bool,
    },

    /// Print where chronosphere stores things.
    Where,

    /// Print an `eval $(chronosphere path-install)` snippet for shell setup.
    PathInstall,

    /// Run as a Model Context Protocol server on stdio (for cursor-agent etc).
    McpServe,

    /// Print an mcp.json snippet to wire chronosphere into Cursor / Claude clients.
    McpConfig {
        /// Generate an SSH-wrapped server config for the named host (uses ControlMaster).
        #[arg(long)]
        ssh: Option<String>,
        /// SSH port for the remote (default 22).
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Path to the remote chronosphere binary.
        #[arg(long, default_value = "/usr/local/bin/chronosphere")]
        remote_path: String,
        /// Identity file for SSH (optional).
        #[arg(long)]
        identity: Option<PathBuf>,
    },

    /// Ship the chronosphere binary to a remote host via scp (Pwnbox, lab box, etc).
    Deploy(crate::deploy::DeployArgs),

    /// Local CVE index: sync, search, and browse vulnerability data.
    #[command(subcommand)]
    Cve(CveCmd),
}

#[derive(Subcommand, Debug)]
pub enum CveCmd {
    /// Sync CVE data from NVD feeds, CISA KEV, EPSS, and OSV.
    Sync {
        /// Import all year feeds (not just modified/recent). Mutually exclusive with `--month`.
        #[arg(long, conflicts_with = "month")]
        full: bool,
        /// Year range or list (e.g. 2024-2026 or 2025,2026). Implies `--full`. Ignored when `--month` is set.
        #[arg(long, conflicts_with = "month")]
        years: Option<String>,
        /// Sync one calendar month via NVD API (e.g. 2026-05). Smaller than `--full`.
        #[arg(long, value_name = "YYYY-MM")]
        month: Option<String>,
        /// With `--month`, match on last-modified date instead of publish date.
        #[arg(long)]
        by_modified: bool,
        /// Skip OSV enrichment.
        #[arg(long)]
        no_osv: bool,
        /// Skip EPSS score merge.
        #[arg(long)]
        no_epss: bool,
        /// Providers to sync (default: nvd,kev).
        #[arg(long, value_delimiter = ',')]
        provider: Vec<String>,
    },
    /// Fetch a single CVE on demand (NVD API + optional enrichment).
    Fetch {
        cve_id: String,
        #[arg(long)]
        enrich: bool,
    },
    /// Search the local CVE index.
    Search {
        query: Option<String>,
        #[arg(long)]
        product: Option<String>,
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long)]
        cwe: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        kev: bool,
        /// Only CVEs with a ready first-party PoC (lab-pass / htb-used in ~/pocs).
        #[arg(long)]
        poc: bool,
        #[arg(long)]
        min_epss: Option<f64>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show one CVE record from the local index.
    Show {
        cve_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Print CVE database status.
    Status,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// What to list.
    #[arg(value_enum, default_value_t = ListKind::Categories)]
    pub kind: ListKind,
    /// Category id (when listing `commands`).
    pub category: Option<String>,
    /// Output JSON instead of text.
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum ListKind {
    Engagements,
    Categories,
    Commands,
    Tools,
    Jobs,
}

#[derive(Subcommand, Debug)]
pub enum TargetCmd {
    List,
    Add {
        name: String,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        dc: Option<String>,
        #[arg(long)]
        lhost: Option<String>,
        #[arg(long)]
        lport: Option<u16>,
        #[arg(long)]
        notes: Option<String>,
    },
    Use {
        name: String,
    },
    Remove {
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ApCmd {
    List,
    Add {
        name: String,
        #[arg(long)]
        ssid: Option<String>,
        #[arg(long)]
        bssid: Option<String>,
        #[arg(long)]
        channel: Option<String>,
        #[arg(long)]
        station: Option<String>,
        #[arg(long)]
        wpa_psk: Option<String>,
        #[arg(long)]
        wps_pin: Option<String>,
        #[arg(long)]
        capture: Option<String>,
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    Use {
        name: String,
    },
    Remove {
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PivotCmd {
    List,
    Add {
        name: String,
        #[arg(long)]
        ssh_host: Option<String>,
        #[arg(long)]
        ssh_user: Option<String>,
        #[arg(long)]
        ssh_port: Option<u16>,
        #[arg(long)]
        ssh_identity: Option<String>,
        #[arg(long)]
        ssh_password: Option<String>,
        #[arg(long)]
        ligolo_iface: Option<String>,
        #[arg(long)]
        ligolo_server: Option<String>,
        #[arg(long)]
        ligolo_routes: Option<String>,
        #[arg(long)]
        agent_path: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    Use {
        name: String,
        /// Set active tunnel pivot only.
        #[arg(long, conflicts_with = "remote")]
        tunnel: bool,
        /// Set active remote pivot only.
        #[arg(long, conflicts_with = "tunnel")]
        remote: bool,
    },
    Remove {
        name: String,
    },
    /// Toggle local vs remote script execution.
    Exec {
        /// `local` or `remote`.
        mode: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum CredsCmd {
    List,
    Add {
        name: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        domain: Option<String>,
        /// One of: none|plaintext|ntlm|kerberos.
        #[arg(long, default_value = "plaintext")]
        kind: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        nt_hash: Option<String>,
        #[arg(long)]
        ticket: Option<PathBuf>,
        #[arg(long)]
        notes: Option<String>,
    },
    Use {
        name: String,
    },
    Remove {
        name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum VariableCmd {
    /// List template variables (library placeholders + engagement overrides).
    List {
        /// Only show variables with no value set.
        #[arg(long)]
        unset_only: bool,
    },
    Set {
        name: String,
        value: String,
    },
    Unset {
        name: String,
    },
}

// --- Per-subcommand parsers (clean `--help` without unrelated root flags) ---

macro_rules! engagement_cli {
    ($(#[$meta:meta])* $name:ident, $sub:literal, $($field:tt)*) => {
        $(#[$meta])*
        pub struct $name {
            #[command(flatten)]
            pub engagement: EngagementOpts,
            $($field)*
        }
    };
}

macro_rules! standalone_cli {
    ($(#[$meta:meta])* $name:ident, $sub:literal, $($field:tt)*) => {
        $(#[$meta])*
        pub struct $name {
            $($field)*
        }
    };
}

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere list", about = "List engagements / categories / commands", disable_version_flag = true)]
    ListCli, "list",
    #[command(flatten)]
    pub args: ListArgs,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere show", about = "Show a command (resolved with current target/creds)", disable_version_flag = true)]
    ShowCli, "show",
    pub id: String,
    #[arg(short = 'v', long = "var", value_name = "KEY=VALUE")]
    pub vars: Vec<String>,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere render", about = "Print the resolved command (shell-safe, single line)", disable_version_flag = true)]
    RenderCli, "render",
    pub id: String,
    #[arg(short = 'v', long = "var", value_name = "KEY=VALUE")]
    pub vars: Vec<String>,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere yank", about = "Render and copy a command to the clipboard", disable_version_flag = true)]
    YankCli, "yank",
    pub id: String,
    #[arg(long)]
    pub raw: bool,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere run", about = "Execute a command (runs in current shell, prints output)", disable_version_flag = true)]
    RunCli, "run",
    pub id: String,
    #[arg(short = 'v', long = "var", value_name = "KEY=VALUE")]
    pub vars: Vec<String>,
    /// Don't execute; print the fully substituted command instead.
    #[arg(long, visible_alias = "expand")]
    pub dry_run: bool,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere search", about = "Search the command library", disable_version_flag = true)]
    SearchCli, "search",
    pub query: String,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere targets",
        about = "Target CRUD",
        disable_version_flag = true,
        subcommand_required = true,
        arg_required_else_help = true,
    )]
    TargetsCli, "targets",
    #[command(subcommand)]
    pub command: TargetCmd,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere aps",
        about = "WiFi access point CRUD",
        disable_version_flag = true,
        subcommand_required = true,
        arg_required_else_help = true,
    )]
    ApsCli, "aps",
    #[command(subcommand)]
    pub command: ApCmd,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere pivots",
        about = "Foothold pivot CRUD (ligolo tunnel + SSH remote exec)",
        disable_version_flag = true,
        subcommand_required = true,
        arg_required_else_help = true,
    )]
    PivotsCli, "pivots",
    #[command(subcommand)]
    pub command: PivotCmd,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere creds",
        about = "Credential CRUD",
        disable_version_flag = true,
        subcommand_required = true,
        arg_required_else_help = true,
    )]
    CredsCli, "creds",
    #[command(subcommand)]
    pub command: CredsCmd,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere variables",
        about = "Template variable placeholders for the active engagement",
        disable_version_flag = true,
        subcommand_required = true,
        arg_required_else_help = true,
    )]
    VariablesCli, "variables",
    #[command(subcommand)]
    pub command: VariableCmd,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere doctor", about = "Check installed tools referenced by the library", disable_version_flag = true)]
    DoctorCli, "doctor",
    #[arg(long)]
    pub missing: bool,
);

engagement_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere mcp-serve",
        about = "Run as a Model Context Protocol server on stdio (for cursor-agent etc)",
        disable_version_flag = true
    )]
    McpServeCli,
    "mcp-serve",
);

standalone_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere new", about = "Create a new engagement directory", disable_version_flag = true)]
    NewCli, "new",
    #[arg(long)]
    pub root: Option<PathBuf>,
    pub name: String,
    #[arg(long)]
    pub notes: Option<String>,
);

standalone_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere update-templates", about = "Extract embedded built-in commands to the user data dir", disable_version_flag = true)]
    UpdateTemplatesCli, "update-templates",
    #[arg(long)]
    pub force: bool,
);

standalone_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere where",
        about = "Print where chronosphere stores things",
        disable_version_flag = true
    )]
    WhereCli,
    "where",
);

standalone_cli!(
    #[derive(Parser, Debug)]
    #[command(
        name = "chronosphere path-install",
        about = "Print an `eval $(chronosphere path-install)` snippet for shell setup",
        disable_version_flag = true
    )]
    PathInstallCli,
    "path-install",
);

standalone_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere mcp-config", about = "Print an mcp.json snippet to wire chronosphere into Cursor / Claude clients", disable_version_flag = true)]
    McpConfigCli, "mcp-config",
    #[arg(long)]
    pub ssh: Option<String>,
    #[arg(long, default_value_t = 22)]
    pub port: u16,
    #[arg(long, default_value = "/usr/local/bin/chronosphere")]
    pub remote_path: String,
    #[arg(long)]
    pub identity: Option<PathBuf>,
);

standalone_cli!(
    #[derive(Parser, Debug)]
    #[command(name = "chronosphere deploy", about = "Ship the chronosphere binary to a remote host via scp (Pwnbox, lab box, etc)", disable_version_flag = true)]
    DeployCli, "deploy",
    #[command(flatten)]
    pub args: crate::deploy::DeployArgs,
);

#[derive(Parser, Debug)]
#[command(
    name = "chronosphere cve",
    about = "Local CVE index: sync, search, and browse vulnerability data",
    long_about = None,
    disable_version_flag = true,
    subcommand_required = true,
    arg_required_else_help = true,
    after_help = "Examples:
  chronosphere cve sync                         Incremental sync (modified + recent feeds)
  chronosphere cve sync --month 2026-03         One month via NVD API
  chronosphere cve sync --years 2025            Full year feed (implies --full)
  chronosphere cve search nginx rce --limit 20
  chronosphere cve search --poc
  chronosphere cve show CVE-2024-3400

Run `chronosphere cve sync --help` for all sync flags."
)]
pub struct CveCli {
    #[command(subcommand)]
    pub command: CveCmd,
}

const TOP_LEVEL_SUBCOMMANDS: &[&str] = &[
    "new",
    "list",
    "show",
    "render",
    "yank",
    "run",
    "search",
    "targets",
    "aps",
    "pivots",
    "creds",
    "variables",
    "doctor",
    "update-templates",
    "where",
    "path-install",
    "mcp-serve",
    "mcp-config",
    "deploy",
    "cve",
    "tui",
];

fn engagement_flag_takes_value(flag: &str) -> bool {
    matches!(
        flag,
        "-e" | "--engagement" | "--root" | "-t" | "--target" | "-c" | "--creds" | "-a" | "--ap"
    )
}

fn is_engagement_flag(arg: &str) -> bool {
    engagement_flag_takes_value(arg)
}

fn find_top_level_subcommand() -> Option<(usize, &'static str)> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return None;
        }
        if a.starts_with('-') {
            if engagement_flag_takes_value(a) && i + 1 < args.len() {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        for sub in TOP_LEVEL_SUBCOMMANDS {
            if a == *sub {
                return Some((i, sub));
            }
        }
        return None;
    }
    None
}

fn build_subcommand_argv(sub_idx: usize, sub: &str) -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut out = vec![format!("chronosphere {sub}")];
    let mut i = 1;
    while i < sub_idx {
        if is_engagement_flag(&args[i]) {
            out.push(args[i].clone());
            if engagement_flag_takes_value(&args[i]) && i + 1 < sub_idx {
                i += 1;
                out.push(args[i].clone());
            }
        }
        i += 1;
    }
    out.extend(args[sub_idx + 1..].iter().cloned());
    out
}

fn cli_from(opts: EngagementOpts, command: Command) -> Cli {
    Cli {
        opts,
        command: Some(command),
    }
}

/// Parse and run when argv names a top-level subcommand (clean per-command `--help`).
pub async fn try_early_dispatch() -> Result<bool> {
    let Some((sub_idx, sub)) = find_top_level_subcommand() else {
        return Ok(false);
    };
    if sub == "tui" {
        return Ok(false);
    }

    let argv = build_subcommand_argv(sub_idx, sub);
    let handled = match sub {
        "new" => {
            let c = NewCli::parse_from(&argv);
            let mut opts = EngagementOpts::default();
            opts.root = c.root;
            dispatch(cli_from(
                opts,
                Command::New {
                    name: c.name,
                    notes: c.notes,
                },
            ))
            .await?
        }
        "list" => {
            let c = ListCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::List(c.args))).await?
        }
        "show" => {
            let c = ShowCli::parse_from(&argv);
            dispatch(cli_from(
                c.engagement,
                Command::Show {
                    id: c.id,
                    vars: c.vars,
                },
            ))
            .await?
        }
        "render" => {
            let c = RenderCli::parse_from(&argv);
            dispatch(cli_from(
                c.engagement,
                Command::Render {
                    id: c.id,
                    vars: c.vars,
                },
            ))
            .await?
        }
        "yank" => {
            let c = YankCli::parse_from(&argv);
            dispatch(cli_from(
                c.engagement,
                Command::Yank {
                    id: c.id,
                    raw: c.raw,
                },
            ))
            .await?
        }
        "run" => {
            let c = RunCli::parse_from(&argv);
            dispatch(cli_from(
                c.engagement,
                Command::Run {
                    id: c.id,
                    vars: c.vars,
                    dry_run: c.dry_run,
                },
            ))
            .await?
        }
        "search" => {
            let c = SearchCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::Search { query: c.query })).await?
        }
        "targets" => {
            let c = TargetsCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::Targets(c.command))).await?
        }
        "aps" => {
            let c = ApsCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::Aps(c.command))).await?
        }
        "pivots" => {
            let c = PivotsCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::Pivots(c.command))).await?
        }
        "creds" => {
            let c = CredsCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::Creds(c.command))).await?
        }
        "variables" => {
            let c = VariablesCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::Variables(c.command))).await?
        }
        "doctor" => {
            let c = DoctorCli::parse_from(&argv);
            dispatch(cli_from(
                c.engagement,
                Command::Doctor { missing: c.missing },
            ))
            .await?
        }
        "update-templates" => {
            let c = UpdateTemplatesCli::parse_from(&argv);
            dispatch(cli_from(
                EngagementOpts::default(),
                Command::UpdateTemplates { force: c.force },
            ))
            .await?
        }
        "where" => {
            let _c = WhereCli::parse_from(&argv);
            dispatch(cli_from(EngagementOpts::default(), Command::Where)).await?
        }
        "path-install" => {
            let _c = PathInstallCli::parse_from(&argv);
            dispatch(cli_from(EngagementOpts::default(), Command::PathInstall)).await?
        }
        "mcp-serve" => {
            let c = McpServeCli::parse_from(&argv);
            dispatch(cli_from(c.engagement, Command::McpServe)).await?
        }
        "mcp-config" => {
            let c = McpConfigCli::parse_from(&argv);
            dispatch(cli_from(
                EngagementOpts::default(),
                Command::McpConfig {
                    ssh: c.ssh,
                    port: c.port,
                    remote_path: c.remote_path,
                    identity: c.identity,
                },
            ))
            .await?
        }
        "deploy" => {
            let c = DeployCli::parse_from(&argv);
            dispatch(cli_from(EngagementOpts::default(), Command::Deploy(c.args))).await?
        }
        "cve" => {
            let c = CveCli::parse_from(&argv);
            dispatch_cve(c.command).await?;
            true
        }
        _ => return Ok(false),
    };
    Ok(handled)
}

/// Returns true if dispatching consumed the run (CLI mode); false to fall through to TUI.
pub async fn dispatch(cli: Cli) -> Result<bool> {
    let cmd = match cli.command {
        Some(c) => c,
        None => return Ok(false),
    };
    if let Command::Tui = cmd {
        return Ok(false);
    }

    crate::builtin::ensure_user_dir().context("ensure user templates")?;

    let root = cli.opts.engagements_root();

    match cmd {
        Command::Tui => Ok(false),
        Command::New { name, notes } => {
            fs::create_dir_all(&root).ok();
            let mut e = Engagement::create(&root, &name)?;
            if let Some(n) = notes {
                e.meta.notes = Some(n);
                fs::write(
                    Engagement::meta_path(&e.dir),
                    toml::to_string_pretty(&e.meta)?,
                )?;
            }
            println!("created engagement: {}", e.dir.display());
            if let Some(parent) = config::last_engagement_marker().parent() {
                fs::create_dir_all(parent).ok();
            }
            let _ = fs::write(config::last_engagement_marker(), &name);
            Ok(true)
        }
        Command::Where => {
            println!("data:        {}", config::data_dir().display());
            println!("config:      {}", config::config_dir().display());
            println!("log:         {}", config::log_file_path().display());
            println!("engagements: {}", root.display());
            println!("builtins:    {}", config::builtin_commands_dir().display());
            println!("user lib:    {}", config::user_commands_dir().display());
            println!(
                "cve db:      {} ({})",
                config::cve_db_path().display(),
                config::format_storage_size(config::cve_storage_size_bytes()),
            );
            let poc = crate::cve::PocIndex::global();
            let poc_idx = poc.root.join("index.toml");
            if poc_idx.is_file() {
                println!("poc root:    {} ({} ready)", poc.root.display(), poc.len());
            } else {
                println!(
                    "poc root:    {} (no index.toml — set CHRONO_POC_ROOT or mount ~/pocs)",
                    poc.root.display()
                );
            }
            Ok(true)
        }
        Command::PathInstall => {
            let bin = std::env::current_exe()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| "chronosphere".to_string());
            println!(
                r#"# add to ~/.zshrc or ~/.bashrc:
alias chronosphere='{bin}'
# or symlink:
#   sudo ln -sf '{bin}' /usr/local/bin/chronosphere
# tab completion for bash:
#   source <(chronosphere completions bash)"#
            );
            Ok(true)
        }
        Command::McpServe => {
            let opts = crate::mcp::ServerOpts {
                engagement: cli.opts.engagement.clone(),
                root: root.clone(),
            };
            crate::mcp::serve(opts).await.context("mcp serve")?;
            Ok(true)
        }
        Command::McpConfig {
            ssh,
            port,
            remote_path,
            identity,
        } => {
            if let Some(host) = ssh {
                println!(
                    "{}",
                    crate::deploy::mcp_config_ssh_snippet(
                        &host,
                        port,
                        &remote_path,
                        identity.as_deref()
                    )
                );
            } else {
                let bin = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.to_str().map(String::from))
                    .unwrap_or_else(|| "chronosphere".to_string());
                println!("{}", crate::deploy::mcp_config_local_snippet(&bin));
            }
            println!("\n# Paste the inner mcpServers entry into ~/.cursor/mcp.json");
            println!("# (or merge into an existing mcpServers object).");
            Ok(true)
        }
        Command::Deploy(deploy_args) => {
            crate::deploy::run(deploy_args).context("deploy")?;
            Ok(true)
        }
        Command::UpdateTemplates { force } => {
            let dir = config::user_commands_dir();
            let n = crate::builtin::extract_to(&dir, force)?;
            println!("extracted {} template files -> {}", n, dir.display());
            Ok(true)
        }
        Command::Variables(c) => {
            let mut e = open_engagement(&root, cli.opts.engagement.as_deref())?;
            let sources = library_sources(&root, Some(&e.meta.name))?;
            let lib = load_library(&sources)?;
            match c {
                VariableCmd::List { unset_only } => {
                    print_variables(&e, &lib, unset_only);
                }
                VariableCmd::Set { name, value } => {
                    e.variables.set(name.clone(), value);
                    e.save_variables()?;
                    println!("set {}", name);
                }
                VariableCmd::Unset { name } => {
                    e.variables.remove(&name);
                    e.save_variables()?;
                    println!("unset {}", name);
                }
            }
            Ok(true)
        }
        Command::Doctor { missing } => {
            let sources = library_sources(root.as_path(), cli.opts.engagement.as_deref())?;
            let lib = load_library(&sources)?;
            let tools = lib.all_tools_referenced();
            let mut found = 0usize;
            let mut not_found = Vec::new();
            for tool in &tools {
                if which::which(tool).is_ok() {
                    found += 1;
                } else {
                    not_found.push(tool.clone());
                }
            }
            not_found.sort();
            if missing {
                for t in &not_found {
                    println!("{}", t);
                }
            } else {
                println!("present: {} / {}", found, tools.len());
                println!("missing:");
                for t in &not_found {
                    println!("  - {}", t);
                }
            }
            Ok(true)
        }
        Command::List(args) => {
            let sources = library_sources(root.as_path(), cli.opts.engagement.as_deref())?;
            let lib = load_library(&sources)?;
            match args.kind {
                ListKind::Engagements => {
                    for name in Engagement::list(&root) {
                        println!("{}", name);
                    }
                }
                ListKind::Categories => {
                    for cat in &lib.categories {
                        println!("{:<14}  {}", cat.id, cat.display_name);
                    }
                }
                ListKind::Commands => {
                    let filter = args.category.as_deref();
                    for cat in &lib.categories {
                        if filter.is_some_and(|f| f != cat.id) {
                            continue;
                        }
                        for cmd in &cat.commands {
                            println!("{:<18}  {}", cmd.id, cmd.title);
                        }
                    }
                }
                ListKind::Tools => {
                    let mut t: Vec<String> = lib.all_tools_referenced().into_iter().collect();
                    t.sort();
                    for tool in t {
                        println!("{}", tool);
                    }
                }
                ListKind::Jobs => {
                    let e = open_engagement(&root, cli.opts.engagement.as_deref())?;
                    for job in e.history.recent.iter().rev() {
                        println!(
                            "{} {:?}  {}  ({}/{})",
                            job.id,
                            job.status,
                            job.command_id.as_deref().unwrap_or("-"),
                            job.target.as_deref().unwrap_or("?"),
                            job.ap.as_deref().unwrap_or("-"),
                        );
                    }
                }
            }
            Ok(true)
        }
        Command::Search { query } => {
            let sources = library_sources(root.as_path(), cli.opts.engagement.as_deref())?;
            let lib = load_library(&sources)?;
            let needle = query.to_lowercase();
            for cat in &lib.categories {
                for cmd in &cat.commands {
                    let hay = format!(
                        "{} {} {} {}",
                        cmd.id,
                        cmd.title,
                        cmd.tags.join(" "),
                        cmd.template,
                    )
                    .to_lowercase();
                    if hay.contains(&needle) {
                        println!("{:<18}  [{}]  {}", cmd.id, cat.id, cmd.title);
                    }
                }
            }
            Ok(true)
        }
        Command::Show { id, vars } | Command::Render { id, vars } => {
            let resolved = resolve(
                &root,
                cli.opts.engagement.as_deref(),
                &cli.opts.target,
                &cli.opts.ap,
                &cli.opts.creds,
                &id,
                &vars,
            )?;
            println!("{}", resolved);
            Ok(true)
        }
        Command::Yank { id, raw } => {
            let text = if raw {
                raw_template(&root, cli.opts.engagement.as_deref(), &id)?
            } else {
                resolve(
                    &root,
                    cli.opts.engagement.as_deref(),
                    &cli.opts.target,
                    &cli.opts.ap,
                    &cli.opts.creds,
                    &id,
                    &[],
                )?
            };
            let r = crate::clipboard::copy_report(&text)?;
            println!("{}", crate::clipboard::format_yank_message(&r));
            if !r.any() {
                anyhow::bail!("clipboard copy failed");
            }
            println!("id: {}", id);
            Ok(true)
        }
        Command::Run { id, vars, dry_run } => {
            let resolved = resolve(
                &root,
                cli.opts.engagement.as_deref(),
                &cli.opts.target,
                &cli.opts.ap,
                &cli.opts.creds,
                &id,
                &vars,
            )?;
            if dry_run {
                println!("{}", resolved);
                return Ok(true);
            }
            run_with_history(&root, cli.opts.engagement.as_deref(), &id, &resolved).await?;
            Ok(true)
        }
        Command::Targets(c) => {
            let mut e = open_engagement(&root, cli.opts.engagement.as_deref())?;
            match c {
                TargetCmd::List => {
                    let active = e.targets.active().map(|t| t.name.clone());
                    for t in &e.targets.targets {
                        let star = if Some(&t.name) == active.as_ref() {
                            "*"
                        } else {
                            " "
                        };
                        println!(
                            "{} {:<14}  ip={}  host={}  dc={}",
                            star,
                            t.name,
                            t.ip.as_deref().unwrap_or("-"),
                            t.hostname.as_deref().unwrap_or("-"),
                            t.dc_name.as_deref().unwrap_or("-"),
                        );
                    }
                }
                TargetCmd::Add {
                    name,
                    ip,
                    hostname,
                    dc,
                    lhost,
                    lport,
                    notes,
                } => {
                    let activate = name.clone();
                    e.targets.upsert(Target {
                        name,
                        ip,
                        hostname,
                        dc_name: dc,
                        lhost,
                        lport,
                        notes,
                    });
                    e.targets.set_active(&activate);
                    e.save_targets()?;
                }
                TargetCmd::Use { name } => {
                    if !e.targets.set_active(&name) {
                        bail!("no target named {}", name);
                    }
                    e.save_targets()?;
                }
                TargetCmd::Remove { name } => {
                    e.targets.remove(&name);
                    e.save_targets()?;
                }
            }
            Ok(true)
        }
        Command::Aps(c) => {
            let mut e = open_engagement(&root, cli.opts.engagement.as_deref())?;
            match c {
                ApCmd::List => {
                    let active = e.aps.active().map(|a| a.name.clone());
                    for a in &e.aps.aps {
                        let star = if Some(&a.name) == active.as_ref() {
                            "*"
                        } else {
                            " "
                        };
                        println!(
                            "{} {:<12}  ssid={}  bssid={}  psk={}",
                            star,
                            a.name,
                            a.ssid.as_deref().unwrap_or("-"),
                            a.bssid.as_deref().unwrap_or("-"),
                            if a.wpa_psk.as_deref().is_some_and(|s| !s.is_empty()) {
                                "set"
                            } else {
                                "-"
                            },
                        );
                    }
                }
                ApCmd::Add {
                    name,
                    ssid,
                    bssid,
                    channel,
                    station,
                    wpa_psk,
                    wps_pin,
                    capture,
                    vendor,
                    notes,
                } => {
                    let activate = name.clone();
                    e.aps.upsert(AccessPoint {
                        name,
                        ssid,
                        bssid,
                        channel,
                        station,
                        wpa_psk,
                        wps_pin,
                        capture,
                        vendor,
                        notes,
                    });
                    e.aps.set_active(&activate);
                    e.save_aps()?;
                }
                ApCmd::Use { name } => {
                    if !e.aps.set_active(&name) {
                        bail!("no AP named {}", name);
                    }
                    e.save_aps()?;
                }
                ApCmd::Remove { name } => {
                    e.aps.remove(&name);
                    e.save_aps()?;
                }
            }
            Ok(true)
        }
        Command::Pivots(c) => {
            let mut e = open_engagement(&root, cli.opts.engagement.as_deref())?;
            match c {
                PivotCmd::List => {
                    let tun = e.pivots.active_tunnel.clone();
                    let rem = e.pivots.active_remote.clone();
                    println!(
                        "execution_mode={}  active_tunnel={}  active_remote={}",
                        e.pivots.execution_mode.as_str(),
                        tun.as_deref().unwrap_or("-"),
                        rem.as_deref().unwrap_or("-"),
                    );
                    for p in &e.pivots.pivots {
                        let t = if tun.as_deref() == Some(p.name.as_str()) {
                            "T"
                        } else {
                            " "
                        };
                        let r = if rem.as_deref() == Some(p.name.as_str()) {
                            "R"
                        } else {
                            " "
                        };
                        println!(
                            "{}{} {:>10}  user={}  ssh={}  host={}  tun={}  routes={}",
                            t,
                            r,
                            p.name,
                            p.ssh_user.as_deref().unwrap_or("-"),
                            if p.has_ssh() { "yes" } else { "no" },
                            p.ssh_host.as_deref().unwrap_or("-"),
                            p.ligolo_interface.as_deref().unwrap_or("-"),
                            p.ligolo_routes.join(","),
                        );
                    }
                }
                PivotCmd::Add {
                    name,
                    ssh_host,
                    ssh_user,
                    ssh_port,
                    ssh_identity,
                    ssh_password,
                    ligolo_iface,
                    ligolo_server,
                    ligolo_routes,
                    agent_path,
                    notes,
                } => {
                    let routes: Vec<String> = ligolo_routes
                        .as_deref()
                        .map(|s| {
                            s.split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();
                    let activate = name.clone();
                    e.pivots.upsert(Pivot {
                        name,
                        ssh_host,
                        ssh_user,
                        ssh_port,
                        ssh_identity,
                        ssh_password,
                        ligolo_interface: ligolo_iface,
                        ligolo_server_addr: ligolo_server,
                        ligolo_routes: routes,
                        agent_path,
                        notes,
                    });
                    if e.pivots.active_tunnel.is_none() {
                        e.pivots.active_tunnel = Some(activate.clone());
                    }
                    if e.pivots.active_remote.is_none() {
                        e.pivots.active_remote = Some(activate);
                    }
                    e.save_pivots()?;
                }
                PivotCmd::Use {
                    name,
                    tunnel,
                    remote,
                } => {
                    if !e.pivots.pivots.iter().any(|p| p.name == name) {
                        bail!("no pivot named {}", name);
                    }
                    if tunnel {
                        e.pivots.set_active_tunnel(&name);
                    } else if remote {
                        e.pivots.set_active_remote(&name);
                    } else {
                        e.pivots.set_active_tunnel(&name);
                        e.pivots.set_active_remote(&name);
                    }
                    e.save_pivots()?;
                }
                PivotCmd::Remove { name } => {
                    e.pivots.remove(&name);
                    e.save_pivots()?;
                }
                PivotCmd::Exec { mode } => {
                    let m = ExecutionMode::parse(&mode)
                        .ok_or_else(|| anyhow!("mode must be local or remote"))?;
                    if m == ExecutionMode::Remote {
                        let pivot = e
                            .pivots
                            .active_remote()
                            .or_else(|| e.pivots.active_tunnel())
                            .filter(|p| p.has_ssh())
                            .ok_or_else(|| {
                                anyhow!("set a remote pivot with ssh_user and ssh_host first")
                            })?;
                        let target = e.active_target().map(|t| t.name.as_str());
                        if !crate::exec::ssh::pivot_ssh_auth_available(pivot, &e.dir, target) {
                            bail!(
                                "remote pivot needs ssh_password or an SSH key (ssh_identity or engagement/.ssh/id_*)"
                            );
                        }
                    }
                    e.pivots.execution_mode = m;
                    e.save_pivots()?;
                    println!("execution mode: {}", m.as_str());
                }
            }
            Ok(true)
        }
        Command::Creds(c) => {
            let mut e = open_engagement(&root, cli.opts.engagement.as_deref())?;
            match c {
                CredsCmd::List => {
                    let active = e.profiles.active().map(|p| p.name.clone());
                    for p in &e.profiles.profiles {
                        let star = if Some(&p.name) == active.as_ref() {
                            "*"
                        } else {
                            " "
                        };
                        println!(
                            "{} {:<12} {}  ({}/{})  user={}",
                            star,
                            p.name,
                            p.kind.as_str(),
                            p.domain.as_deref().unwrap_or("-"),
                            p.username,
                            p.username,
                        );
                    }
                }
                CredsCmd::Add {
                    name,
                    username,
                    domain,
                    kind,
                    password,
                    nt_hash,
                    ticket,
                    notes,
                } => {
                    let kind = match kind.to_lowercase().as_str() {
                        "none" => CredKind::None,
                        "plaintext" | "pw" | "password" => CredKind::Plaintext,
                        "ntlm" | "hash" | "nt" => CredKind::Ntlm,
                        "kerberos" | "krb" => CredKind::Kerberos,
                        other => bail!(
                            "unknown cred kind '{}' (none|plaintext|ntlm|kerberos)",
                            other
                        ),
                    };
                    let activate = name.clone();
                    e.profiles.upsert(CredentialProfile {
                        name,
                        username,
                        domain,
                        kind,
                        password,
                        nt_hash,
                        ticket_path: ticket.map(|p| p.to_string_lossy().into_owned()),
                        notes,
                    });
                    e.profiles.set_active(&activate);
                    e.save_profiles()?;
                }
                CredsCmd::Use { name } => {
                    if !e.profiles.set_active(&name) {
                        bail!("no profile named {}", name);
                    }
                    e.save_profiles()?;
                }
                CredsCmd::Remove { name } => {
                    e.profiles.remove(&name);
                    e.save_profiles()?;
                }
            }
            Ok(true)
        }
        Command::Cve(c) => {
            dispatch_cve(c).await?;
            Ok(true)
        }
    }
}

async fn dispatch_cve(cmd: CveCmd) -> Result<()> {
    use crate::cve::{
        CveFilter, SyncOptions, fetch_one, parse_month, parse_since_days, parse_years, search,
        show, status, sync,
    };

    match cmd {
        CveCmd::Sync {
            full,
            years,
            month,
            by_modified,
            no_osv,
            no_epss,
            provider,
        } => {
            if full && month.is_some() {
                bail!("--full and --month are mutually exclusive");
            }
            let month = month.map(|m| parse_month(&m, by_modified)).transpose()?;
            let years = years
                .map(|y| parse_years(&y))
                .transpose()?
                .unwrap_or_default();
            let opts = SyncOptions {
                full,
                years,
                month,
                providers: provider,
                enrich_osv: !no_osv,
                enrich_epss: !no_epss,
                progress: true,
            };
            let result = sync(opts).await?;
            println!(
                "sync complete: {} added, {} updated",
                result.added, result.updated
            );
            for err in &result.errors {
                eprintln!("warning: {err}");
            }
        }
        CveCmd::Fetch { cve_id, enrich } => match fetch_one(&cve_id, enrich).await? {
            Some(rec) => print_cve_record(&rec, false),
            None => bail!("CVE not found: {cve_id}"),
        },
        CveCmd::Search {
            query,
            product,
            vendor,
            cwe,
            severity,
            kev,
            poc,
            min_epss,
            since,
            tag,
            limit,
            json,
        } => {
            let since_days = since.map(|s| parse_since_days(&s)).transpose()?;
            let filter = CveFilter {
                query,
                product,
                vendor,
                cwe,
                severity,
                kev_only: kev,
                poc_only: poc,
                min_epss,
                since_days,
                tag,
                limit,
                offset: 0,
            };
            let hits = search(filter)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&hits)?);
            } else if hits.is_empty() {
                println!("no matches");
            } else {
                for rec in &hits {
                    print_cve_summary(rec);
                }
            }
        }
        CveCmd::Show { cve_id, json } => match show(&cve_id)? {
            Some(rec) => {
                if json {
                    println!("{}", serde_json::to_string_pretty(&rec)?);
                } else {
                    print_cve_record(&rec, true);
                }
            }
            None => {
                bail!("CVE not in local index: {cve_id} (try: chronosphere cve fetch {cve_id})")
            }
        },
        CveCmd::Status => {
            let st = status()?;
            println!("database:  {}", st.db_path);
            println!(
                "size:      {} ({} bytes)",
                config::format_storage_size(st.db_size_bytes),
                st.db_size_bytes
            );
            println!("total:     {}", st.total);
            println!("kev:       {}", st.kev_count);
            if let Some(t) = st.last_sync {
                println!("last sync: {}", t);
            }
            if let Some(f) = st.last_nvd_feed {
                println!("last feed: {}", f);
            }
        }
    }
    Ok(())
}

fn print_cve_summary(rec: &crate::cve::CveRecord) {
    let kev = if rec.in_kev { " [KEV]" } else { "" };
    let poc = crate::cve::poc_index::lookup(&rec.id)
        .map(|e| format!(" {}", e.badge()))
        .unwrap_or_default();
    let sev = rec.severity.as_deref().unwrap_or("-");
    let score = rec
        .cvss_v31
        .map(|s| format!("{s:.1}"))
        .unwrap_or_else(|| "-".into());
    let desc: String = rec.description.chars().take(80).collect();
    println!(
        "{:<18} {:>8} CVSS {}  {}{}{}",
        rec.id, sev, score, desc, kev, poc
    );
}

fn print_cve_record(rec: &crate::cve::CveRecord, verbose: bool) {
    println!("{}", rec.id);
    if let Some(p) = &rec.published {
        println!("  published: {p}");
    }
    if let Some(m) = &rec.modified {
        println!("  modified:  {m}");
    }
    if let Some(s) = &rec.severity {
        let cvss = rec
            .cvss_v31
            .map(|v| format!(" (CVSS {v:.1})"))
            .unwrap_or_default();
        println!("  severity:  {s}{cvss}");
    }
    if rec.in_kev {
        println!(
            "  KEV:       added {} due {}",
            rec.kev_date_added.as_deref().unwrap_or("-"),
            rec.kev_due_date.as_deref().unwrap_or("-"),
        );
    }
    if let Some(e) = rec.epss_score {
        println!(
            "  EPSS:      {:.4} (percentile {:.1}%)",
            e,
            rec.epss_percentile.unwrap_or(0.0) * 100.0
        );
    }
    if let Some(poc) = crate::cve::poc_index::lookup(&rec.id) {
        let root = &crate::cve::PocIndex::global().root;
        println!(
            "  local PoC: {}  {}",
            poc.status,
            poc.absolute_path(root).display()
        );
        if let Some(id) = &poc.chronosphere_id {
            println!("  run:       chronosphere run {id}");
        }
        if let Some(notes) = &poc.notes {
            let short: String = notes.chars().take(120).collect();
            println!("  poc notes: {short}");
        }
    }
    if !rec.sources.is_empty() {
        println!(
            "  sources:   {}",
            rec.sources.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    println!("  description:");
    for line in rec.description.lines().take(8) {
        println!("    {line}");
    }
    if verbose {
        if !rec.products.is_empty() {
            println!("  products:");
            for p in rec.products.iter().take(10) {
                println!("    {}/{}", p.vendor, p.product);
            }
        }
        if !rec.cwes.is_empty() {
            println!("  CWEs:      {}", rec.cwes.join(", "));
        }
        if !rec.references.is_empty() {
            println!("  references:");
            for r in rec.references.iter().take(8) {
                println!("    {}", r.url);
            }
        }
    }
}

fn library_sources(root: &Path, engagement: Option<&str>) -> Result<Vec<PathBuf>> {
    let mut v = vec![config::builtin_commands_dir()];
    if let Some(name) = engagement {
        Engagement::validate_name(name)?;
        let dir = root.join(name);
        if dir.exists() {
            let overrides = Engagement::overrides_dir(&dir);
            if overrides.exists() {
                v.push(overrides);
            }
        }
    }
    Ok(v)
}

fn load_library(sources: &[PathBuf]) -> Result<CommandLibrary> {
    let paths: Vec<&Path> = sources.iter().map(|p| p.as_path()).collect();
    CommandLibrary::load(&paths)
}

fn open_engagement(root: &Path, name: Option<&str>) -> Result<Engagement> {
    let pick = match name {
        Some(n) => n.to_string(),
        None => {
            let candidates = Engagement::list(root);
            if candidates.len() == 1 {
                candidates.into_iter().next().unwrap()
            } else if candidates.is_empty() {
                bail!(
                    "no engagement found in {} (create one with `chronosphere new <name>`)",
                    root.display()
                )
            } else {
                bail!(
                    "ambiguous engagement (use -e to pick): {}",
                    candidates.join(", ")
                )
            }
        }
    };
    Engagement::load_named(root, &pick).with_context(|| format!("load engagement {}", pick))
}

fn build_context(
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

fn resolve(
    root: &Path,
    engagement: Option<&str>,
    target_override: &Option<String>,
    ap_override: &Option<String>,
    cred_override: &Option<String>,
    id: &str,
    extra_vars: &[String],
) -> Result<String> {
    let e = open_engagement(root, engagement)?;
    let sources = library_sources(root, Some(&e.meta.name))?;
    let lib = load_library(&sources)?;
    let cmd = lib
        .categories
        .iter()
        .flat_map(|c| c.commands.iter())
        .find(|c| c.id == id)
        .ok_or_else(|| anyhow!("command id '{}' not found", id))?;
    let ctx = build_context(&e, target_override, ap_override, cred_override, extra_vars)?;
    let tmpl = cmd.applicable_template(&|w| crate::render::condition::evaluate(w, &ctx));
    let result = render::render(tmpl, &ctx)?;
    Ok(result.resolved)
}

fn print_variables(e: &Engagement, lib: &CommandLibrary, unset_only: bool) {
    use crate::render::placeholders::collect_library_custom_placeholders;
    use std::collections::BTreeSet;

    let library = collect_library_custom_placeholders(lib);
    let mut names: BTreeSet<String> = library.clone();
    for k in e.variables.values.keys() {
        names.insert(k.clone());
    }
    for name in names {
        let value = e.variables.values.get(&name);
        let is_set = value.is_some_and(|v| !v.is_empty());
        if unset_only && is_set {
            continue;
        }
        let status = if is_set { "set" } else { "unset" };
        let val = value
            .filter(|v| !v.is_empty())
            .map(|s| s.as_str())
            .unwrap_or("-");
        let tag = if library.contains(&name) {
            ""
        } else {
            " (custom)"
        };
        println!("{:<8}  {:<20}  {}{}", status, name, val, tag);
    }
}

fn raw_template(root: &Path, engagement: Option<&str>, id: &str) -> Result<String> {
    let sources = library_sources(root, engagement)?;
    let lib = load_library(&sources)?;
    let cmd = lib
        .categories
        .iter()
        .flat_map(|c| c.commands.iter())
        .find(|c| c.id == id)
        .ok_or_else(|| anyhow!("command id '{}' not found", id))?;
    Ok(cmd.template.clone())
}

async fn run_with_history(
    root: &Path,
    engagement: Option<&str>,
    id: &str,
    resolved: &str,
) -> Result<()> {
    use tokio::process::Command;
    let mut e = open_engagement(root, engagement)?;
    let target = e.targets.active().map(|t| t.name.clone());
    let ap = e.aps.active().map(|a| a.name.clone());
    let pivot = e
        .pivots
        .active_remote()
        .or_else(|| e.pivots.active_tunnel())
        .map(|p| p.name.clone());
    let execution = if e.pivots.execution_mode == ExecutionMode::Remote {
        Some(format!(
            "remote@{}",
            e.pivots
                .active_remote()
                .map(|p| p.name.as_str())
                .unwrap_or("?")
        ))
    } else {
        Some("local".into())
    };
    let profile = e.profiles.active().map(|p| p.name.clone());
    let started_at = Utc::now();
    let job_id = format!("{}", uuid::Uuid::new_v4());
    let log_path = Engagement::jobs_dir(&e.dir).join(format!("{job_id}.log"));
    fs::create_dir_all(Engagement::jobs_dir(&e.dir)).ok();
    let redacted = crate::security::redact_for_engagement(resolved, &e);
    eprintln!("[chrono] $ {}", redacted);
    let status = Command::new("bash")
        .arg("-lc")
        .arg(resolved)
        .status()
        .await
        .with_context(|| "spawn bash")?;
    let exit_code = status.code();
    let record = JobRecord {
        id: job_id,
        command_id: Some(id.to_string()),
        command_title: id.to_string(),
        resolved: redacted,
        target,
        profile,
        ap,
        pivot,
        execution,
        started_at,
        finished_at: Some(Utc::now()),
        status: if status.success() {
            JobStatus::Completed
        } else {
            JobStatus::Failed
        },
        exit_code,
        log_path: Some(log_path),
        tmux_window: None,
    };
    e.history.append(&record)?;
    Ok(())
}

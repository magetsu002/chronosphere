//! Tool registry + dispatch for the MCP server. Each tool maps to a small async
//! function that mutates/reads `State` (engagement + library) and returns a JSON
//! `result` object the agent can read.

use super::protocol::McpError;
use crate::engagement::{CredKind, CredentialProfile, Engagement, JobRecord, JobStatus, Target};
use crate::job_runtime::{RunningProcess, RuntimeIdentity};
use crate::library::CommandLibrary;
use crate::render::{self, RenderContext};
use crate::{builtin, config};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Server-side state for the MCP session. Holds the engagement (mutable) and the
/// engagement-root path (so we can switch engagements without restarting the server).
pub struct State {
    pub root: PathBuf,
    pub engagement: Option<Engagement>,
    pub library: CommandLibrary,
    pub running_jobs: HashMap<String, RunningProcess>,
}

impl State {
    pub fn new(root: PathBuf, engagement_name: Option<String>) -> Result<Self> {
        std::fs::create_dir_all(&root).ok();
        let _ = builtin::ensure_user_dir();
        let engagement = match engagement_name {
            Some(name) => Some(
                Engagement::load_named(&root, &name)
                    .with_context(|| format!("load engagement '{}'", name))?,
            ),
            None => {
                let available = Engagement::list(&root);
                match available.as_slice() {
                    [] => None,
                    [name] => Some(
                        Engagement::load_named(&root, name)
                            .with_context(|| format!("load engagement '{}'", name))?,
                    ),
                    _ => {
                        return Err(anyhow!(
                            "multiple engagements available; start mcp-serve with an explicit engagement: {}",
                            available.join(", ")
                        ));
                    }
                }
            }
        };
        let mut engagement = engagement;
        let running_jobs = engagement
            .as_mut()
            .map(|engagement| {
                crate::job_runtime::recover_running_map(
                    &mut engagement.history,
                    &Engagement::jobs_dir(&engagement.dir),
                )
            })
            .unwrap_or_default();
        let lib_sources = library_sources(&root, engagement.as_ref());
        let paths: Vec<&Path> = lib_sources.iter().map(|p| p.as_path()).collect();
        let library = CommandLibrary::load(&paths).context("load library")?;
        Ok(Self {
            root,
            engagement,
            library,
            running_jobs,
        })
    }

    fn render_ctx(
        &self,
        target_override: Option<&str>,
        ap_override: Option<&str>,
        cred_override: Option<&str>,
        extra_vars: &serde_json::Map<String, Value>,
    ) -> Result<RenderContext> {
        let mut ctx = RenderContext::default();
        if let Some(engagement) = &self.engagement {
            let target = match target_override {
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

            let ap = match ap_override {
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

            let profile = match cred_override {
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
        }
        for (key, value) in extra_vars {
            let value = value
                .as_str()
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| value.to_string());
            ctx.globals.insert(key.clone(), value);
        }
        Ok(ctx)
    }

    fn reload_library(&mut self) {
        let lib_sources = library_sources(&self.root, self.engagement.as_ref());
        let paths: Vec<&Path> = lib_sources.iter().map(|p| p.as_path()).collect();
        if let Ok(lib) = CommandLibrary::load(&paths) {
            self.library = lib;
        }
    }
}

fn library_sources(root: &Path, engagement: Option<&Engagement>) -> Vec<PathBuf> {
    let mut v = vec![config::builtin_commands_dir()];
    if let Some(e) = engagement {
        let overrides = Engagement::overrides_dir(&e.dir);
        if overrides.exists() {
            v.push(overrides);
        }
    }
    let _ = root;
    v
}

/// MCP `tools/list` response. JSON Schemas are hand-rolled (no schemars dep) — keeps
/// the binary small. Each schema must be a valid JSON Schema Draft 2020-12 object.
pub fn list_tools() -> Value {
    json!({
        "tools": [
            {
                "name": "engagement_info",
                "description": "Return info about the currently loaded engagement, active target, and active credential profile. Call this first to orient yourself.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
            },
            {
                "name": "list_categories",
                "description": "List all command categories with their display name and command counts.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
            },
            {
                "name": "list_commands",
                "description": "List commands, optionally filtered by category id or tag.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Category id (e.g. 'impacket', 'adcs')."},
                        "tag": {"type": "string", "description": "Filter to commands carrying this tag (e.g. 'kerberoast')."}
                    },
                    "additionalProperties": false
                }
            },
            {
                "name": "search",
                "description": "Fuzzy-search the command library (matches id, title, tags, and template).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": false
                }
            },
            {
                "name": "show_command",
                "description": "Show a command by ID. Returns raw template, resolved (with active target/creds), and any unresolved placeholders.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "target": {"type": "string", "description": "Override target for this call."},
                        "ap": {"type": "string", "description": "Override access point for this call."},
                        "creds": {"type": "string", "description": "Override credential profile for this call."},
                        "vars": {"type": "object", "description": "Extra KEY=VALUE placeholder overrides.", "additionalProperties": {"type": "string"}}
                    },
                    "required": ["id"],
                    "additionalProperties": false
                }
            },
            {
                "name": "render_command",
                "description": "Render a command's template with active target/creds and return the resolved shell-safe string. Does not execute.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "target": {"type": "string"},
                        "ap": {"type": "string"},
                        "creds": {"type": "string"},
                        "vars": {"type": "object", "additionalProperties": {"type": "string"}}
                    },
                    "required": ["id"],
                    "additionalProperties": false
                }
            },
            {
                "name": "run_command",
                "description": "Execute a command by ID in the background. Returns job_id immediately; poll tail_job to read output. Set dry_run=true to render only.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "target": {"type": "string"},
                        "ap": {"type": "string"},
                        "creds": {"type": "string"},
                        "vars": {"type": "object", "additionalProperties": {"type": "string"}},
                        "dry_run": {"type": "boolean", "default": false},
                        "timeout_seconds": {"type": "integer", "minimum": 1, "default": 600}
                    },
                    "required": ["id"],
                    "additionalProperties": false
                }
            },
            {
                "name": "tail_job",
                "description": "Read the tail of a job's output log. Default lines=200. Use this after run_command to inspect what happened.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "lines": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 200}
                    },
                    "required": ["job_id"],
                    "additionalProperties": false
                }
            },
            {
                "name": "grep_job",
                "description": "Grep a job's output log for a regex. Returns matching lines (max 200).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "pattern": {"type": "string"},
                        "ignore_case": {"type": "boolean", "default": true}
                    },
                    "required": ["job_id", "pattern"],
                    "additionalProperties": false
                }
            },
            {
                "name": "list_jobs",
                "description": "List recent jobs in this engagement.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"limit": {"type": "integer", "default": 20}},
                    "additionalProperties": false
                }
            },
            {
                "name": "kill_job",
                "description": "Send SIGTERM to a running job by id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string"}},
                    "required": ["job_id"],
                    "additionalProperties": false
                }
            },
            {
                "name": "targets_list",
                "description": "List engagement targets; the active one is flagged.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
            },
            {
                "name": "targets_add",
                "description": "Add or update a target. Automatically becomes active.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "ip": {"type": "string"},
                        "hostname": {"type": "string"},
                        "dc": {"type": "string"},
                        "lhost": {"type": "string"},
                        "lport": {"type": "integer"},
                        "notes": {"type": "string"}
                    },
                    "required": ["name"],
                    "additionalProperties": false
                }
            },
            {
                "name": "targets_use",
                "description": "Switch the active target to the named one.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                    "additionalProperties": false
                }
            },
            {
                "name": "creds_list",
                "description": "List engagement credential profiles; the active one is flagged.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
            },
            {
                "name": "creds_add",
                "description": "Add or update a credential profile. Automatically becomes active.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "username": {"type": "string"},
                        "domain": {"type": "string"},
                        "kind": {"type": "string", "enum": ["none", "plaintext", "ntlm", "kerberos"]},
                        "password": {"type": "string"},
                        "nt_hash": {"type": "string"},
                        "ticket": {"type": "string"},
                        "notes": {"type": "string"}
                    },
                    "required": ["name", "username"],
                    "additionalProperties": false
                }
            },
            {
                "name": "creds_use",
                "description": "Switch the active credential profile to the named one.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                    "additionalProperties": false
                }
            },
            {
                "name": "engagement_switch",
                "description": "Switch the loaded engagement to another name in the engagements root.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                    "additionalProperties": false
                }
            },
            {
                "name": "engagement_new",
                "description": "Create a new engagement directory and load it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "notes": {"type": "string"}
                    },
                    "required": ["name"],
                    "additionalProperties": false
                }
            },
            {
                "name": "doctor",
                "description": "Check which tools referenced by the library are installed (via `which`). Useful for picking commands that will actually work on this host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"missing_only": {"type": "boolean", "default": false}},
                    "additionalProperties": false
                }
            }
        ]
    })
}

pub async fn dispatch(
    name: &str,
    args: Value,
    state: Arc<Mutex<State>>,
) -> Result<Value, McpError> {
    let result = match name {
        "engagement_info" => tool_engagement_info(state).await,
        "list_categories" => tool_list_categories(state).await,
        "list_commands" => tool_list_commands(args, state).await,
        "search" => tool_search(args, state).await,
        "show_command" => tool_show_command(args, state).await,
        "render_command" => tool_render_command(args, state).await,
        "run_command" => tool_run_command(args, state).await,
        "tail_job" => tool_tail_job(args, state).await,
        "grep_job" => tool_grep_job(args, state).await,
        "list_jobs" => tool_list_jobs(args, state).await,
        "kill_job" => tool_kill_job(args, state).await,
        "targets_list" => tool_targets_list(state).await,
        "targets_add" => tool_targets_add(args, state).await,
        "targets_use" => tool_targets_use(args, state).await,
        "creds_list" => tool_creds_list(state).await,
        "creds_add" => tool_creds_add(args, state).await,
        "creds_use" => tool_creds_use(args, state).await,
        "engagement_switch" => tool_engagement_switch(args, state).await,
        "engagement_new" => tool_engagement_new(args, state).await,
        "doctor" => tool_doctor(args, state).await,
        other => Err(anyhow!("unknown tool: {}", other)),
    };
    match result {
        Ok(v) => Ok(tool_result(v, false)),
        Err(e) => Ok(tool_result(json!({"error": format!("{:#}", e)}), true)),
    }
}

/// Wrap a JSON body in the MCP tool-call result envelope.
fn tool_result(body: Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string());
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
        "structuredContent": body,
    })
}

// ──────────────── tool implementations ────────────────

async fn tool_engagement_info(state: Arc<Mutex<State>>) -> Result<Value> {
    let s = state.lock().await;
    let info = match &s.engagement {
        Some(e) => json!({
            "engagement": e.meta.name,
            "dir": e.dir.to_string_lossy(),
            "active_target": e.targets.active().map(|t| json!({
                "name": t.name,
                "ip": t.ip,
                "hostname": t.hostname,
                "dc": t.dc_name,
                "lhost": t.lhost,
                "lport": t.lport,
            })),
            "active_ap": e.aps.active().map(|a| json!({
                "name": a.name,
                "ssid": a.ssid,
                "bssid": a.bssid,
                "channel": a.channel,
                "wpa_psk": a.wpa_psk.as_ref().map(|_| "<set>"),
                "wps_pin": a.wps_pin.as_ref().map(|_| "<set>"),
                "capture": a.capture,
            })),
            "active_tunnel_pivot": e.pivots.active_tunnel().map(|p| json!({
                "name": p.name,
                "ssh_host": p.ssh_host,
                "ligolo_interface": p.ligolo_interface,
                "ligolo_routes": p.ligolo_routes,
            })),
            "active_remote_pivot": e.pivots.active_remote().map(|p| json!({
                "name": p.name,
                "ssh_host": p.ssh_host,
                "ssh_user": p.ssh_user,
                "ssh_identity": p.ssh_identity,
                "ssh_password": p.ssh_password.as_ref().map(|_| "<set>"),
                "has_ssh": p.has_ssh(),
            })),
            "execution_mode": e.pivots.execution_mode.as_str(),
            "tunnel_active": e.pivots.is_tunnel_active(),
            "active_creds": e.profiles.active().map(|p| json!({
                "name": p.name,
                "kind": p.kind.as_str(),
                "username": p.username,
                "domain": p.domain,
            })),
            "target_count": e.targets.targets.len(),
            "ap_count": e.aps.aps.len(),
            "pivot_count": e.pivots.pivots.len(),
            "creds_count": e.profiles.profiles.len(),
            "variables_set": e.variables.values.values().filter(|v| !v.is_empty()).count(),
            "variables_total": e.variables.values.len(),
            "recent_jobs": e.history.recent.len(),
        }),
        None => json!({"engagement": null, "engagements_available": Engagement::list(&s.root)}),
    };
    Ok(info)
}

async fn tool_list_categories(state: Arc<Mutex<State>>) -> Result<Value> {
    let s = state.lock().await;
    let cats: Vec<Value> = s
        .library
        .categories
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "display_name": c.display_name,
                "command_count": c.commands.len(),
            })
        })
        .collect();
    Ok(json!({"categories": cats}))
}

#[derive(Deserialize)]
struct ListCommandsArgs {
    category: Option<String>,
    tag: Option<String>,
}

async fn tool_list_commands(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: ListCommandsArgs = serde_json::from_value(args).unwrap_or(ListCommandsArgs {
        category: None,
        tag: None,
    });
    let s = state.lock().await;
    let mut out = Vec::new();
    for cat in &s.library.categories {
        if let Some(c) = &args.category {
            if &cat.id != c {
                continue;
            }
        }
        for cmd in &cat.commands {
            if let Some(t) = &args.tag {
                if !cmd.tags.iter().any(|x| x == t) {
                    continue;
                }
            }
            out.push(json!({
                "id": cmd.id,
                "category": cat.id,
                "title": cmd.title,
                "tags": cmd.tags,
                "requires": cmd.requires,
                "interactive": cmd.interactive,
            }));
        }
    }
    Ok(json!({"commands": out, "count": out.len()}))
}

#[derive(Deserialize)]
struct SearchArgs {
    query: String,
}

async fn tool_search(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: SearchArgs = serde_json::from_value(args).map_err(|e| anyhow!("{}", e))?;
    let needle = args.query.to_lowercase();
    let s = state.lock().await;
    let mut hits = Vec::new();
    for cat in &s.library.categories {
        for cmd in &cat.commands {
            let hay = format!(
                "{} {} {} {}",
                cmd.id,
                cmd.title,
                cmd.tags.join(" "),
                cmd.template
            )
            .to_lowercase();
            if hay.contains(&needle) {
                hits.push(json!({
                    "id": cmd.id,
                    "category": cat.id,
                    "title": cmd.title,
                    "tags": cmd.tags,
                }));
            }
        }
    }
    Ok(json!({"matches": hits, "count": hits.len()}))
}

#[derive(Deserialize, Default)]
struct RenderArgs {
    id: String,
    target: Option<String>,
    ap: Option<String>,
    creds: Option<String>,
    vars: Option<serde_json::Map<String, Value>>,
}

async fn tool_show_command(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: RenderArgs = serde_json::from_value(args).map_err(|e| anyhow!("{}", e))?;
    let s = state.lock().await;
    let (cat_id, cmd) = find_command(&s, &args.id)?;
    let extra = args.vars.unwrap_or_default();
    let ctx = s.render_ctx(
        args.target.as_deref(),
        args.ap.as_deref(),
        args.creds.as_deref(),
        &extra,
    )?;
    let tmpl = cmd.applicable_template(&|w| crate::render::condition::evaluate(w, &ctx));
    let rendered = render::render(tmpl, &ctx).map_err(|e| anyhow!("{}", e))?;
    let redacted = crate::security::redact_command(&rendered.resolved, &ctx);
    Ok(json!({
        "id": cmd.id,
        "category": cat_id,
        "title": cmd.title,
        "tags": cmd.tags,
        "requires": cmd.requires,
        "interactive": cmd.interactive,
        "when": cmd.when,
        "raw_template": cmd.template,
        "resolved": redacted,
        "unresolved_placeholders": rendered.unresolved,
    }))
}

async fn tool_render_command(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: RenderArgs = serde_json::from_value(args).map_err(|e| anyhow!("{}", e))?;
    let s = state.lock().await;
    let (_, cmd) = find_command(&s, &args.id)?;
    let extra = args.vars.unwrap_or_default();
    let ctx = s.render_ctx(
        args.target.as_deref(),
        args.ap.as_deref(),
        args.creds.as_deref(),
        &extra,
    )?;
    let tmpl = cmd.applicable_template(&|w| crate::render::condition::evaluate(w, &ctx));
    let rendered = render::render(tmpl, &ctx).map_err(|e| anyhow!("{}", e))?;
    let redacted = crate::security::redact_command(&rendered.resolved, &ctx);
    Ok(json!({
        "resolved": redacted,
        "unresolved_placeholders": rendered.unresolved,
    }))
}

#[derive(Deserialize, Default)]
struct RunArgs {
    id: String,
    target: Option<String>,
    ap: Option<String>,
    creds: Option<String>,
    vars: Option<serde_json::Map<String, Value>>,
    dry_run: Option<bool>,
    timeout_seconds: Option<u64>,
}

async fn tool_run_command(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: RunArgs = serde_json::from_value(args).map_err(|err| anyhow!("{}", err))?;
    let dry_run = args.dry_run.unwrap_or(false);
    let timeout = std::time::Duration::from_secs(args.timeout_seconds.unwrap_or(600));

    let (
        resolved,
        redacted,
        job_id,
        log_path,
        engagement_dir,
        target_name,
        ap_name,
        profile_name,
        command_id,
        command_title,
        runtime_token,
    ) = {
        let state = state.lock().await;
        let engagement = state
            .engagement
            .as_ref()
            .ok_or_else(|| anyhow!("no engagement loaded"))?;
        let (_, command) = find_command(&state, &args.id)?;
        let extra = args.vars.clone().unwrap_or_default();
        let context = state.render_ctx(
            args.target.as_deref(),
            args.ap.as_deref(),
            args.creds.as_deref(),
            &extra,
        )?;
        let template =
            command.applicable_template(&|when| crate::render::condition::evaluate(when, &context));
        let rendered = render::render(template, &context).map_err(|err| anyhow!("{}", err))?;
        if !rendered.unresolved.is_empty() {
            return Err(anyhow!(
                "command '{}' has unresolved placeholders: {}",
                command.id,
                rendered.unresolved.join(", ")
            ));
        }
        let redacted = crate::security::redact_command(&rendered.resolved, &context);
        let job_id = uuid::Uuid::new_v4().to_string();
        let runtime_token = uuid::Uuid::new_v4().to_string();
        let log_path = Engagement::jobs_dir(&engagement.dir).join(format!("{}.log", job_id));
        (
            rendered.resolved,
            redacted,
            job_id,
            log_path,
            engagement.dir.clone(),
            context.target.as_ref().map(|target| target.name.clone()),
            context.ap.as_ref().map(|ap| ap.name.clone()),
            context.profile.as_ref().map(|profile| profile.name.clone()),
            command.id.clone(),
            command.title.clone(),
            runtime_token,
        )
    };

    if dry_run {
        return Ok(json!({"resolved": redacted, "dry_run": true}));
    }

    std::fs::create_dir_all(Engagement::jobs_dir(&engagement_dir))?;
    {
        let mut state = state.lock().await;
        let engagement = state
            .engagement
            .as_mut()
            .ok_or_else(|| anyhow!("no engagement"))?;
        let pivot_name = engagement
            .pivots
            .active_remote()
            .or_else(|| engagement.pivots.active_tunnel())
            .map(|pivot| pivot.name.clone());
        let execution_label =
            if engagement.pivots.execution_mode == crate::engagement::ExecutionMode::Remote {
                format!(
                    "remote@{}",
                    engagement
                        .pivots
                        .active_remote()
                        .map(|pivot| pivot.name.as_str())
                        .unwrap_or("?")
                )
            } else {
                "local".into()
            };
        let record = JobRecord {
            id: job_id.clone(),
            command_id: Some(command_id.clone()),
            command_title: command_title.clone(),
            resolved: redacted.clone(),
            started_at: Utc::now(),
            finished_at: None,
            status: JobStatus::Running,
            exit_code: None,
            tmux_window: None,
            log_path: Some(log_path.clone()),
            target: target_name.clone(),
            profile: profile_name.clone(),
            ap: ap_name.clone(),
            pivot: pivot_name,
            execution: Some(execution_label),
        };
        engagement.history.append(&record)?;
    }

    let log_file = crate::security::create_private_file(&log_path)?;
    let log_clone = log_file.try_clone().ok();
    let mut command = Command::new("bash");
    command
        .arg("-lc")
        .arg(&resolved)
        .env(crate::job_runtime::JOB_ID_ENV, &job_id)
        .env(crate::job_runtime::JOB_TOKEN_ENV, &runtime_token);
    command.stdout(log_file);
    if let Some(stderr) = log_clone {
        command.stderr(stderr);
    }
    command.kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            let mut state = state.lock().await;
            update_job(&mut state, &job_id, JobStatus::Failed, None);
            return Err(err).context("spawn command");
        }
    };
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("spawned command did not expose a process id"))?;
    let identity = RuntimeIdentity::new(job_id.clone(), pid, runtime_token);
    if let Err(err) = crate::job_runtime::persist(&Engagement::jobs_dir(&engagement_dir), &identity)
    {
        terminate_child(&mut child, &identity).await;
        let mut state = state.lock().await;
        update_job(&mut state, &job_id, JobStatus::Failed, None);
        return Err(err).context("persist runtime identity");
    }
    {
        let mut state = state.lock().await;
        state.running_jobs.insert(
            job_id.clone(),
            RunningProcess {
                identity: identity.clone(),
                recovered: false,
            },
        );
    }

    let state_for_task = state.clone();
    let job_id_for_task = job_id.clone();
    let identity_for_task = identity.clone();
    let jobs_dir_for_task = Engagement::jobs_dir(&engagement_dir);
    tokio::spawn(async move {
        let outcome = tokio::time::timeout(timeout, child.wait()).await;
        let (status, exit_code) = match outcome {
            Ok(Ok(exit)) => (
                if exit.success() {
                    JobStatus::Completed
                } else {
                    JobStatus::Failed
                },
                exit.code(),
            ),
            Ok(Err(err)) => {
                tracing::error!(?err, "job wait failed");
                (JobStatus::Failed, None)
            }
            Err(_) => {
                terminate_child(&mut child, &identity_for_task).await;
                (JobStatus::TimedOut, None)
            }
        };
        let mut state = state_for_task.lock().await;
        state.running_jobs.remove(&job_id_for_task);
        crate::job_runtime::remove(&jobs_dir_for_task, &job_id_for_task);
        update_job(&mut state, &job_id_for_task, status, exit_code);
    });

    Ok(json!({
        "job_id": job_id,
        "resolved": redacted,
        "log_path": log_path.to_string_lossy(),
        "status": "running",
    }))
}

fn update_job(state: &mut State, job_id: &str, status: JobStatus, code: Option<i32>) {
    let is_running = state
        .engagement
        .as_ref()
        .and_then(|engagement| {
            engagement
                .history
                .recent
                .iter()
                .find(|record| record.id == job_id)
        })
        .is_some_and(|record| record.status == JobStatus::Running);
    if is_running {
        force_update_job(state, job_id, status, code);
    }
}

fn force_update_job(state: &mut State, job_id: &str, status: JobStatus, code: Option<i32>) {
    if let Some(engagement) = state.engagement.as_mut() {
        if let Some(record) = engagement
            .history
            .recent
            .iter()
            .find(|record| record.id == job_id)
            .cloned()
        {
            let mut updated = record;
            updated.status = status;
            updated.exit_code = code;
            updated.finished_at = Some(Utc::now());
            engagement.history.update(&updated);
        }
    }
}

async fn terminate_child(child: &mut tokio::process::Child, identity: &RuntimeIdentity) {
    #[cfg(unix)]
    {
        let _ = crate::job_runtime::signal_process_group(identity, "TERM", false);
        if tokio::time::timeout(std::time::Duration::from_secs(2), child.wait())
            .await
            .is_err()
        {
            let _ = crate::job_runtime::signal_process_group(identity, "KILL", false);
            let _ = child.wait().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = identity;
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

#[cfg(unix)]
async fn send_process_group_signal(pid: u32, signal: &str) -> Result<()> {
    let status = Command::new("kill")
        .arg(format!("-{}", signal))
        .arg(format!("-{}", pid))
        .status()
        .await
        .with_context(|| format!("send {} to process group {}", signal, pid))?;
    if !status.success() {
        return Err(anyhow!(
            "failed to send {} to process group {}",
            signal,
            pid
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
struct TailArgs {
    job_id: String,
    lines: Option<usize>,
}

async fn tool_tail_job(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: TailArgs = serde_json::from_value(args).map_err(|err| anyhow!("{}", err))?;
    let lines_requested = args.lines.unwrap_or(200).clamp(1, 5000);
    let (log_path, status, exit_code, secrets) = {
        let state = state.lock().await;
        let engagement = state
            .engagement
            .as_ref()
            .ok_or_else(|| anyhow!("no engagement"))?;
        let job = engagement
            .history
            .recent
            .iter()
            .find(|job| job.id == args.job_id)
            .ok_or_else(|| anyhow!("no such job: {}", args.job_id))?;
        (
            job.log_path.clone(),
            job.status,
            job.exit_code,
            crate::security::store_secrets(
                &engagement.profiles,
                &engagement.aps,
                &engagement.pivots,
                &engagement.variables,
            ),
        )
    };
    let body = match log_path {
        Some(path) if path.exists() => fs::read_to_string(&path).await.unwrap_or_default(),
        _ => String::new(),
    };
    let body = crate::security::redact_values(&body, &secrets);
    let lines: Vec<&str> = body.lines().collect();
    let start = lines.len().saturating_sub(lines_requested);
    let tail: Vec<String> = lines[start..].iter().map(|line| line.to_string()).collect();
    Ok(json!({
        "job_id": args.job_id,
        "status": format!("{:?}", status).to_lowercase(),
        "exit_code": exit_code,
        "shown_lines": tail.len(),
        "total_lines": lines.len(),
        "tail": tail.join("
    "),
    }))
}

#[derive(Deserialize)]
struct GrepArgs {
    job_id: String,
    pattern: String,
    ignore_case: Option<bool>,
}

async fn tool_grep_job(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: GrepArgs = serde_json::from_value(args).map_err(|err| anyhow!("{}", err))?;
    let ignore_case = args.ignore_case.unwrap_or(true);
    let needle = if ignore_case {
        args.pattern.to_lowercase()
    } else {
        args.pattern.clone()
    };
    let (log_path, secrets) = {
        let state = state.lock().await;
        let engagement = state
            .engagement
            .as_ref()
            .ok_or_else(|| anyhow!("no engagement"))?;
        let log_path = engagement
            .history
            .recent
            .iter()
            .find(|job| job.id == args.job_id)
            .and_then(|job| job.log_path.clone())
            .ok_or_else(|| anyhow!("no such job: {}", args.job_id))?;
        (
            log_path,
            crate::security::store_secrets(
                &engagement.profiles,
                &engagement.aps,
                &engagement.pivots,
                &engagement.variables,
            ),
        )
    };
    let body = fs::read_to_string(&log_path).await.unwrap_or_default();
    let body = crate::security::redact_values(&body, &secrets);
    let mut matches = Vec::new();
    for (index, line) in body.lines().enumerate() {
        let haystack = if ignore_case {
            line.to_lowercase()
        } else {
            line.to_string()
        };
        if haystack.contains(&needle) {
            matches.push(json!({"line": index + 1, "text": line}));
            if matches.len() >= 200 {
                break;
            }
        }
    }
    Ok(json!({"matches": matches, "count": matches.len()}))
}

async fn tool_list_jobs(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let s = state.lock().await;
    let eng = s
        .engagement
        .as_ref()
        .ok_or_else(|| anyhow!("no engagement"))?;
    let mut jobs: Vec<&JobRecord> = eng.history.recent.iter().collect();
    jobs.reverse();
    let truncated: Vec<Value> = jobs
        .into_iter()
        .take(limit)
        .map(|j| {
            json!({
                "id": j.id,
                "command_id": j.command_id,
                "title": j.command_title,
                "status": format!("{:?}", j.status).to_lowercase(),
                "exit_code": j.exit_code,
                "started_at": j.started_at.to_rfc3339(),
                "finished_at": j.finished_at.map(|t| t.to_rfc3339()),
                "target": j.target,
                "ap": j.ap,
                "profile": j.profile,
                "resolved": j.resolved,
            })
        })
        .collect();
    Ok(json!({"jobs": truncated, "count": truncated.len()}))
}

async fn tool_kill_job(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let job_id = args
        .get("job_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing job_id"))?
        .to_string();
    let pid = {
        let state = state.lock().await;
        state
            .running_jobs
            .get(&job_id)
            .map(|process| process.identity.pid)
            .ok_or_else(|| anyhow!("job '{}' is not running in this MCP session", job_id))?
    };

    #[cfg(unix)]
    {
        send_process_group_signal(pid, "TERM").await?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let alive = Command::new("kill")
            .arg("-0")
            .arg(format!("-{}", pid))
            .status()
            .await
            .map(|status| status.success())
            .unwrap_or(false);
        if alive {
            send_process_group_signal(pid, "KILL").await?;
        }
    }
    #[cfg(not(unix))]
    {
        return Err(anyhow!(
            "job cancellation is not supported on this platform yet"
        ));
    }

    let mut state = state.lock().await;
    state.running_jobs.remove(&job_id);
    force_update_job(&mut state, &job_id, JobStatus::Cancelled, None);
    Ok(json!({"job_id": job_id, "status": "cancelled"}))
}

async fn tool_targets_list(state: Arc<Mutex<State>>) -> Result<Value> {
    let s = state.lock().await;
    let eng = s
        .engagement
        .as_ref()
        .ok_or_else(|| anyhow!("no engagement"))?;
    let active = eng.targets.active().map(|t| t.name.clone());
    let list: Vec<Value> = eng
        .targets
        .targets
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "ip": t.ip,
                "hostname": t.hostname,
                "dc": t.dc_name,
                "lhost": t.lhost,
                "lport": t.lport,
                "active": active.as_deref() == Some(t.name.as_str()),
            })
        })
        .collect();
    Ok(json!({"targets": list, "active": active}))
}

#[derive(Deserialize)]
struct TargetsAddArgs {
    name: String,
    ip: Option<String>,
    hostname: Option<String>,
    dc: Option<String>,
    lhost: Option<String>,
    lport: Option<u16>,
    notes: Option<String>,
}

async fn tool_targets_add(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: TargetsAddArgs = serde_json::from_value(args).map_err(|e| anyhow!("{}", e))?;
    let mut s = state.lock().await;
    let eng = s
        .engagement
        .as_mut()
        .ok_or_else(|| anyhow!("no engagement"))?;
    let activate = args.name.clone();
    eng.targets.upsert(Target {
        name: args.name,
        ip: args.ip,
        hostname: args.hostname,
        dc_name: args.dc,
        lhost: args.lhost,
        lport: args.lport,
        notes: args.notes,
    });
    eng.targets.set_active(&activate);
    eng.save_targets()?;
    Ok(json!({"ok": true, "active": activate}))
}

async fn tool_targets_use(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing name"))?
        .to_string();
    let mut s = state.lock().await;
    let eng = s
        .engagement
        .as_mut()
        .ok_or_else(|| anyhow!("no engagement"))?;
    if !eng.targets.set_active(&name) {
        return Err(anyhow!("no target named {}", name));
    }
    eng.save_targets()?;
    Ok(json!({"ok": true, "active": name}))
}

async fn tool_creds_list(state: Arc<Mutex<State>>) -> Result<Value> {
    let s = state.lock().await;
    let eng = s
        .engagement
        .as_ref()
        .ok_or_else(|| anyhow!("no engagement"))?;
    let active = eng.profiles.active().map(|p| p.name.clone());
    let list: Vec<Value> = eng
        .profiles
        .profiles
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "username": p.username,
                "domain": p.domain,
                "kind": p.kind.as_str(),
                "has_password": p.password.is_some(),
                "has_hash": p.nt_hash.is_some(),
                "active": active.as_deref() == Some(p.name.as_str()),
            })
        })
        .collect();
    Ok(json!({"profiles": list, "active": active}))
}

#[derive(Deserialize)]
struct CredsAddArgs {
    name: String,
    username: String,
    domain: Option<String>,
    kind: Option<String>,
    password: Option<String>,
    nt_hash: Option<String>,
    ticket: Option<String>,
    notes: Option<String>,
}

async fn tool_creds_add(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let args: CredsAddArgs = serde_json::from_value(args).map_err(|e| anyhow!("{}", e))?;
    let kind = match args.kind.as_deref().unwrap_or("plaintext") {
        "none" => CredKind::None,
        "plaintext" | "pw" => CredKind::Plaintext,
        "ntlm" | "hash" => CredKind::Ntlm,
        "kerberos" | "krb" => CredKind::Kerberos,
        other => return Err(anyhow!("unknown kind '{}'", other)),
    };
    let mut s = state.lock().await;
    let eng = s
        .engagement
        .as_mut()
        .ok_or_else(|| anyhow!("no engagement"))?;
    let activate = args.name.clone();
    eng.profiles.upsert(CredentialProfile {
        name: args.name,
        username: args.username,
        domain: args.domain,
        kind,
        password: args.password,
        nt_hash: args.nt_hash,
        ticket_path: args.ticket,
        notes: args.notes,
    });
    eng.profiles.set_active(&activate);
    eng.save_profiles()?;
    Ok(json!({"ok": true, "active": activate}))
}

async fn tool_creds_use(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing name"))?
        .to_string();
    let mut s = state.lock().await;
    let eng = s
        .engagement
        .as_mut()
        .ok_or_else(|| anyhow!("no engagement"))?;
    if !eng.profiles.set_active(&name) {
        return Err(anyhow!("no profile named {}", name));
    }
    eng.save_profiles()?;
    Ok(json!({"ok": true, "active": name}))
}

async fn tool_engagement_switch(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing name"))?
        .to_string();
    let mut s = state.lock().await;
    let eng = Engagement::load_named(&s.root, &name)
        .with_context(|| format!("load engagement '{}'", name))?;
    s.engagement = Some(eng);
    s.reload_library();
    Ok(json!({"ok": true, "engagement": name}))
}

async fn tool_engagement_new(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("missing name"))?
        .to_string();
    let notes = args
        .get("notes")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let mut s = state.lock().await;
    let mut eng = Engagement::create(&s.root, &name)?;
    if let Some(n) = notes {
        eng.meta.notes = Some(n);
        std::fs::write(
            Engagement::meta_path(&eng.dir),
            toml::to_string_pretty(&eng.meta)?,
        )?;
    }
    s.engagement = Some(eng);
    s.reload_library();
    Ok(json!({"ok": true, "engagement": name}))
}

async fn tool_doctor(args: Value, state: Arc<Mutex<State>>) -> Result<Value> {
    let missing_only = args
        .get("missing_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let s = state.lock().await;
    let tools = s.library.all_tools_referenced();
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for t in tools {
        if which::which(&t).is_ok() {
            present.push(t);
        } else {
            missing.push(t);
        }
    }
    present.sort();
    missing.sort();
    if missing_only {
        Ok(json!({"missing": missing, "missing_count": missing.len()}))
    } else {
        Ok(json!({
            "present": present,
            "missing": missing,
            "present_count": present.len(),
            "missing_count": missing.len(),
        }))
    }
}

fn find_command<'a>(s: &'a State, id: &str) -> Result<(String, &'a crate::library::CommandEntry)> {
    for cat in &s.library.categories {
        if let Some(cmd) = cat.commands.iter().find(|c| c.id == id) {
            return Ok((cat.id.clone(), cmd));
        }
    }
    Err(anyhow!("no command with id '{}'", id))
}

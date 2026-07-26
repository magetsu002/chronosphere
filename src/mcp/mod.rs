//! Minimal MCP (Model Context Protocol) server over stdio.
//!
//! Implements the subset of MCP we need to drive chronosphere from agents like
//! `cursor-agent`, Claude Desktop, or any MCP-aware client:
//!   - `initialize` handshake
//!   - `tools/list` — descriptive surface
//!   - `tools/call` — invocation
//!   - `ping`
//!
//! Spec reference: https://modelcontextprotocol.io/specification (2024-11-05 schema).
//! We deliberately do not pull in `rmcp` — the protocol surface we need is small,
//! and avoiding the dependency keeps the binary lean for `scp`-to-Pwnbox use.

pub mod protocol;
pub mod tools;

use anyhow::{Context, Result};
use protocol::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

pub struct ServerOpts {
    pub engagement: Option<String>,
    pub root: PathBuf,
}

pub async fn serve(opts: ServerOpts) -> Result<()> {
    let state = Arc::new(Mutex::new(tools::State::new(opts.root, opts.engagement)?));

    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .context("read stdin line")?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(?err, bytes = trimmed.len(), "mcp: malformed request");
                continue;
            }
        };

        // Notifications (no id) -> just observe, no response.
        if req.id.is_none() {
            tracing::debug!(method = %req.method, "mcp: notification");
            continue;
        }

        let resp = handle_request(req, state.clone()).await;
        let line = serde_json::to_string(&resp).context("serialize response")?;
        stdout
            .write_all(line.as_bytes())
            .await
            .context("write response")?;
        stdout.write_all(b"\n").await.context("write newline")?;
        stdout.flush().await.context("flush stdout")?;
    }
    Ok(())
}

async fn handle_request(req: Request, state: Arc<Mutex<tools::State>>) -> Response {
    let id = req.id.clone();
    let result = match req.method.as_str() {
        "initialize" => Ok(initialize_response()),
        "ping" => Ok(serde_json::json!({})),
        "tools/list" => Ok(tools::list_tools()),
        "tools/call" => {
            let params: ToolCallParams = match req
                .params
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .unwrap_or_else(|| Err(serde_json::Error::custom("missing params")))
            {
                Ok(p) => p,
                Err(e) => {
                    return Response::error(id, -32602, format!("invalid params: {}", e));
                }
            };
            tools::dispatch(&params.name, params.arguments.unwrap_or(serde_json::json!({})), state).await
        }
        // Cursor / Claude sometimes probe these; respond with empty rather than erroring.
        "resources/list" => Ok(serde_json::json!({"resources": []})),
        "prompts/list" => Ok(serde_json::json!({"prompts": []})),
        other => Err(McpError::method_not_found(other)),
    };

    match result {
        Ok(v) => Response::ok(id, v),
        Err(McpError { code, message }) => Response::error(id, code, message),
    }
}

fn initialize_response() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": "chronosphere",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

// serde_json::Error doesn't have ::custom directly; tiny helper trait.
trait JsonErrorExt {
    fn custom<T: std::fmt::Display>(msg: T) -> serde_json::Error;
}
impl JsonErrorExt for serde_json::Error {
    fn custom<T: std::fmt::Display>(msg: T) -> serde_json::Error {
        serde::de::Error::custom(msg)
    }
}

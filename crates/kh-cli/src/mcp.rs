//! Minimal MCP server over stdio (JSON-RPC 2.0, newline-delimited).
//! Tools map 1:1 onto MCP Keyholder pipe methods; this process never stores secrets.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use kh_core::protocol::methods as m;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex};

use crate::conn::{Conn, DISCONNECTED};

const SUPPORTED: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "MCP Keyholder stores the user's API keys and secrets. \
Never ask the user to paste secrets into the chat and never print secret values in chat, code, logs or commits. \
Workflow: list_secrets → request_grant (one request with every key you need and an honest reason) → \
get_secret for keys in `reveal` mode, or prepare_run + `kh run` for keys in `env` mode. \
OTP approvals happen in the MCP Keyholder window on the user's screen; never ask the user to tell you the code. \
If a secret value ever ends up somewhere it shouldn't (your context, output, a file, a commit), call report_leak right away — that is the expected behaviour. \
Use check_leak on text before committing or sharing it.";

fn tools() -> Value {
    json!([
        {
            "name": "list_secrets",
            "description": "List the secrets stored in MCP Keyholder: name, description, group, tier (auto | soft | otp), delivery mode (reveal | env), status and whether your current grant covers it. Never returns values. Call this first to find the keys you need.",
            "inputSchema": { "type": "object", "properties": {
                "query": { "type": "string", "description": "Optional filter by name, description, group or tag." }
            } },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "request_grant",
            "description": "Ask the human for access to specific keys for a limited time. Tier auto is granted immediately; tier soft shows an Allow/Deny window; tier otp requires the human to type a code from their authenticator app into the MCP Keyholder window (do NOT ask the user for the code — MCP Keyholder never accepts codes from agents). Blocks until the human decides (up to ~3 minutes). Put every key you need into ONE request with a short, honest reason: each OTP approval consumes a fresh code. Keys not in your grant are always refused.",
            "inputSchema": { "type": "object", "required": ["reason"], "properties": {
                "reason": { "type": "string", "description": "Why you need these keys, shown to the human (max 200 chars)." },
                "keys": { "type": "array", "maxItems": 32, "items": { "type": "object", "required": ["name"], "properties": {
                    "name": { "type": "string" },
                    "mode": { "type": "string", "enum": ["reveal", "env"], "description": "Optional; must match the key's delivery mode." }
                } } },
                "preset": { "type": "string", "description": "Optional permission preset saved by the human: its keys and default lifetime are added to this request." },
                "ttl_minutes": { "type": "integer", "minimum": 1, "description": "How long you need access. Capped by the user's settings." }
            } }
        },
        {
            "name": "my_grants",
            "description": "Show the grants active for this session: keys, modes and expiry.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "readOnlyHint": true }
        },
        {
            "name": "get_secret",
            "description": "Return the value of a key in `reveal` mode that your grant covers (tier auto keys are granted automatically). The value enters your context and is marked as exposed. Keys in `env` mode are never returned — use prepare_run. Never print the value anywhere.",
            "inputSchema": { "type": "object", "required": ["name"], "properties": { "name": { "type": "string" } } }
        },
        {
            "name": "prepare_run",
            "description": "For keys in `env` mode: get a one-time ticket and the exact command line that runs your program with those keys as environment variables (`kh run --ticket ... -- <command>`). You never see the values. The ticket works once and expires in 60 seconds.",
            "inputSchema": { "type": "object", "required": ["keys"], "properties": {
                "keys": { "type": "array", "minItems": 1, "items": { "type": "string" } },
                "command": { "type": "string", "description": "The command to run, e.g. `git push origin main`." }
            } }
        },
        {
            "name": "report_leak",
            "description": "Report that a secret value appeared somewhere it should not: in your context unexpectedly, in command output, a log, a file, a commit or a message. This is the correct, expected behaviour — the key gets marked as leaked and the human rotates it. Describe what happened.",
            "inputSchema": { "type": "object", "required": ["name", "comment"], "properties": {
                "name": { "type": "string", "description": "Key name (see list_secrets)." },
                "comment": { "type": "string", "description": "What happened and where the value appeared." }
            } }
        },
        {
            "name": "check_leak",
            "description": "Check a piece of text (up to 1 MB) for any secret value stored in MCP Keyholder — exact matches, also base64 / hex / URL-encoded. Use before committing, sharing logs or posting output. Matching keys are marked as leaked and the human is notified. Returns key names only, never values. Values shorter than 16 characters are not checked.",
            "inputSchema": { "type": "object", "required": ["text"], "properties": { "text": { "type": "string" } } },
            "annotations": { "readOnlyHint": false }
        }
    ])
}

struct Server {
    out: mpsc::UnboundedSender<String>,
    conn: Mutex<Option<Arc<Conn>>>,
    token: Option<String>,
    client_info: std::sync::Mutex<Option<(String, String)>>,
}

impl Server {
    fn send(&self, v: Value) {
        let _ = self.out.send(v.to_string());
    }

    async fn conn(&self) -> Result<Arc<Conn>, String> {
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref() {
            if c.is_alive() {
                return Ok(c.clone());
            }
        }
        let c = Conn::connect("mcp", self.token.clone(), true).await?;
        if let Some((n, v)) = self.client_info.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            c.send_client_info(&n, &v);
        }
        *g = Some(c.clone());
        Ok(c)
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let c = self.conn().await?;
        match c.call(method, params.clone()).await {
            Err(e) if e == DISCONNECTED => {
                // MCP Keyholder restarted: reconnect once (grants of the old session are gone).
                let c = self.conn().await?;
                c.call(method, params).await
            }
            r => r,
        }
    }
}

fn tool_result(r: Result<Value, String>) -> Value {
    match r {
        Ok(v) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }],
            "isError": false
        }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": format!("MCP Keyholder: {e}") }],
            "isError": true
        }),
    }
}

async fn handle(srv: Arc<Server>, msg: Value) {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("").to_string();
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let reply = |result: Value| json!({ "jsonrpc": "2.0", "id": id, "result": result });
    let error = |code: i64, message: &str| json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } });

    match method.as_str() {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version = if SUPPORTED.contains(&requested) { requested } else { SUPPORTED[1] };
            if let Some(ci) = params.get("clientInfo") {
                let name = ci.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                let ver = ci.get("version").and_then(Value::as_str).unwrap_or("").to_string();
                *srv.client_info.lock().unwrap_or_else(|e| e.into_inner()) = Some((name.clone(), ver.clone()));
                if let Some(c) = srv.conn.lock().await.as_ref() {
                    c.send_client_info(&name, &ver);
                }
            }
            srv.send(reply(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "keyholder", "title": "MCP Keyholder", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS
            })));
        }
        "ping" => srv.send(reply(json!({}))),
        "tools/list" => srv.send(reply(json!({ "tools": tools() }))),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let pipe_method = match name.as_str() {
                "list_secrets" => m::LIST_SECRETS,
                "request_grant" => m::REQUEST_GRANT,
                "my_grants" => m::MY_GRANTS,
                "get_secret" => m::GET_SECRET,
                "prepare_run" => m::PREPARE_RUN,
                "report_leak" => m::REPORT_LEAK,
                "check_leak" => m::CHECK_LEAK,
                _ => {
                    srv.send(error(-32602, &format!("unknown tool: {name}")));
                    return;
                }
            };
            // Keep long waits alive for clients that reset timeouts on progress.
            let progress = params.get("_meta").and_then(|m| m.get("progressToken")).cloned();
            let ticker = (name == "request_grant").then_some(()).and(progress).map(|tok| {
                let srv2 = srv.clone();
                tokio::spawn(async move {
                    let mut n = 0;
                    loop {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        n += 1;
                        srv2.send(json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": {
                            "progressToken": tok, "progress": n, "message": "Ждём решения человека в окне MCP Keyholder…"
                        } }));
                    }
                })
            });
            let r = srv.call(pipe_method, args).await;
            if let Some(t) = ticker {
                t.abort();
            }
            srv.send(reply(tool_result(r)));
        }
        _ if id.is_none() => {} // notifications (initialized, cancelled, ...)
        _ => srv.send(error(-32601, &format!("method not found: {method}"))),
    }
}

pub async fn run() -> ExitCode {
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(mut line) = out_rx.recv().await {
            line.push('\n');
            if stdout.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    });
    let srv = Arc::new(Server {
        out: out_tx,
        conn: Mutex::new(None),
        token: std::env::var("KH_TOKEN").ok().filter(|t| !t.trim().is_empty()),
        client_info: std::sync::Mutex::new(None),
    });

    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(trimmed) else {
            srv.send(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": "parse error" } }));
            continue;
        };
        let batch = match msg {
            Value::Array(items) => items,
            other => vec![other],
        };
        for item in batch {
            tokio::spawn(handle(srv.clone(), item));
        }
    }
    drop(srv);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    ExitCode::SUCCESS
}

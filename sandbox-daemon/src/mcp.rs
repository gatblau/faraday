//! C16 — MCP front door (`faradayd mcp-stdio`), ADR-028.
//!
//! A thin **MCP JSON-RPC 2.0 server over stdin/stdout** that an MCP client (Claude
//! Code / IDE) launches per session. It exposes exactly **one** tool, `python_sandbox`,
//! and translates each `tools/call` into a `connect`+`run` on the daemon's control
//! socket — i.e. it is on the **untrusted client side** of the ADR-024 boundary. It
//! reads the user's `0600` connection-token file, holds no tokens itself, and relays
//! only `{code, requestedCapabilities}` out and sanitised JSON back. It is the same
//! binary as the daemon (version-locked, ADR-026).
//!
//! Transport: line-delimited JSON (one JSON-RPC message per line; messages never
//! contain embedded newlines). **stdout is reserved for the protocol** — all
//! diagnostics go to stderr, and the connection token is never logged (XC3).

use faradayd_ipc::Connection;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The MCP protocol version echoed when the client does not request one.
const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

/// Resolve the daemon socket + connection-token paths, mirroring `config.rs` defaults
/// (the front door must not require the daemon's full configuration).
fn daemon_paths() -> (String, String) {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().into_owned());
    let socket =
        std::env::var("PYS_SOCKET_PATH").unwrap_or_else(|_| format!("{runtime_dir}/faradayd.sock"));
    let token = std::env::var("PYS_CONNECTION_TOKEN_PATH")
        .unwrap_or_else(|_| format!("{runtime_dir}/faradayd.token"));
    (socket, token)
}

/// Entry point for the `mcp-stdio` sub-mode. Serves MCP over stdio until EOF.
pub async fn run_stdio() -> std::io::Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = stdin.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                // Malformed JSON with no id we can echo — parse error, null id.
                write_msg(
                    &mut stdout,
                    &error_response(Value::Null, -32700, "parse error"),
                )
                .await?;
                continue;
            }
        };
        // A request has an `id`; a notification does not (no response is sent).
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        match (id, method) {
            (None, _) => { /* notification (e.g. notifications/initialized) — ignore */ }
            (Some(id), "initialize") => {
                let requested = msg
                    .get("params")
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEFAULT_PROTOCOL_VERSION)
                    .to_string();
                write_msg(&mut stdout, &ok_response(id, initialize_result(&requested))).await?;
            }
            (Some(id), "ping") => {
                write_msg(&mut stdout, &ok_response(id, json!({}))).await?;
            }
            (Some(id), "tools/list") => {
                write_msg(
                    &mut stdout,
                    &ok_response(id, json!({ "tools": [tool_descriptor()] })),
                )
                .await?;
            }
            (Some(id), "tools/call") => {
                let result = handle_tools_call(msg.get("params")).await;
                write_msg(&mut stdout, &ok_response(id, result)).await?;
            }
            (Some(id), other) => {
                write_msg(
                    &mut stdout,
                    &error_response(id, -32601, &format!("method not found: {other}")),
                )
                .await?;
            }
        }
    }
    Ok(())
}

fn initialize_result(protocol_version: &str) -> Value {
    json!({
        "protocolVersion": protocol_version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "faradayd", "version": env!("CARGO_PKG_VERSION") }
    })
}

/// The single advertised tool — never per-API tools (ADR-001/ADR-023).
fn tool_descriptor() -> Value {
    json!({
        "name": "python_sandbox",
        "description": "Run Python in the sandbox. Call pre-approved APIs via api.<name>.get/post/...; \
                        the daemon brokers the call and returns sanitised data — credentials never enter the sandbox.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": { "type": "string", "description": "Python source to execute in the sandbox." },
                "requestedCapabilities": {
                    "type": "array", "items": { "type": "string" },
                    "description": "Capability names the code may call via api.<name>."
                },
                "dryRun": { "type": "boolean", "description": "Plan the calls without executing." }
            },
            "required": ["code"]
        }
    })
}

/// Translate a `tools/call python_sandbox` into a daemon `connect`+`run`, mapping the
/// outcome to an MCP tool result. Daemon/transport failures become an `isError` tool
/// result (the protocol call itself succeeded).
async fn handle_tools_call(params: Option<&Value>) -> Value {
    let params = match params {
        Some(p) => p,
        None => return tool_error("VAL_ERR: missing params"),
    };
    if params.get("name").and_then(|n| n.as_str()) != Some("python_sandbox") {
        return tool_error("VAL_ERR: unknown tool (only python_sandbox is available)");
    }
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let code = args.get("code").and_then(|c| c.as_str()).unwrap_or("");
    if code.trim().is_empty() {
        return tool_error("VAL_ERR: 'code' is required and must be non-empty");
    }
    let requested = args
        .get("requestedCapabilities")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let dry_run = args
        .get("dryRun")
        .and_then(|d| d.as_bool())
        .unwrap_or(false);

    let request = json!({
        "code": code,
        "requestedCapabilities": requested,
        "dryRun": dry_run,
        "workspaceId": "default"
    });

    match relay_run(&request).await {
        Ok(reply) => reply,
        Err(e) => tool_error(&e),
    }
}

/// Connect to the daemon control socket as an authenticated client and run `request`.
/// Returns an MCP tool-result `Value`, or an `Err(message)` for transport/auth failures.
async fn relay_run(request: &Value) -> Result<Value, String> {
    let (socket_path, token_path) = daemon_paths();

    let token = std::fs::read_to_string(&token_path).map_err(|_| {
        "DAEMON_UNAVAILABLE: cannot read the connection-token file (is the daemon running?)"
            .to_string()
    })?;
    let token = token.trim().to_string();

    let mut conn = faradayd_ipc::connect(&socket_path)
        .await
        .map_err(|_| "DAEMON_UNAVAILABLE: cannot reach the daemon control socket".to_string())?;

    // Handshake: connect with the connection token (ADR-024). The MCP front door is a client.
    write_frame(
        &mut conn,
        &json!({ "type": "connect", "clientLabel": "mcp", "token": token, "workspaceId": "default" }),
    )
    .await
    .map_err(|_| "DAEMON_UNAVAILABLE: connect write failed".to_string())?;

    let connected = read_frame(&mut conn)
        .await
        .map_err(|_| "DAEMON_UNAVAILABLE: no connect response".to_string())?
        .ok_or_else(|| "DAEMON_UNAVAILABLE: daemon closed the connection".to_string())?;
    if connected.get("type").and_then(|t| t.as_str()) != Some("connected") {
        return Err(wire_error_string(&connected));
    }

    // Run.
    write_frame(&mut conn, &json!({ "type": "run", "request": request }))
        .await
        .map_err(|_| "DAEMON_UNAVAILABLE: run write failed".to_string())?;

    // Read frames until a terminal one (result / dryRun / error), ignoring stream chunks.
    loop {
        let frame = read_frame(&mut conn)
            .await
            .map_err(|_| "DAEMON_UNAVAILABLE: read failed".to_string())?
            .ok_or_else(|| "DAEMON_UNAVAILABLE: daemon closed before a result".to_string())?;
        match frame.get("type").and_then(|t| t.as_str()) {
            Some("result") => {
                let result = frame.get("result").cloned().unwrap_or(Value::Null);
                let is_error = result.get("exitCode").and_then(|c| c.as_i64()).unwrap_or(0) != 0;
                return Ok(tool_result_json(&result, is_error));
            }
            Some("dryRun") => {
                let result = frame.get("result").cloned().unwrap_or(Value::Null);
                return Ok(tool_result_json(&result, false));
            }
            Some("error") => return Ok(tool_error(&wire_error_string(&frame))),
            Some("chunk") => continue, // streamed stdout; the final result carries the full output
            _ => continue,
        }
    }
}

/// Render a daemon `{ error, code }` envelope as `CODE: message` (no internal state).
fn wire_error_string(v: &Value) -> String {
    let code = v.get("code").and_then(|c| c.as_str()).unwrap_or("ERROR");
    let msg = v
        .get("error")
        .and_then(|m| m.as_str())
        .unwrap_or("request failed");
    format!("{code}: {msg}")
}

/// A successful tool result: the daemon's RunResult/DryRunResult JSON as a text block.
fn tool_result_json(result: &Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(result).unwrap_or_else(|_| result.to_string());
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

/// An error tool result (the operation failed; the protocol call did not).
fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

fn ok_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Write one JSON-RPC message as a single line to stdout (the MCP transport).
async fn write_msg(stdout: &mut tokio::io::Stdout, v: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_string(v).unwrap_or_else(|_| "{}".to_string());
    line.push('\n');
    stdout.write_all(line.as_bytes()).await?;
    stdout.flush().await
}

// ---- daemon control-socket framing (4-byte big-endian length prefix + JSON) ----
// The length-prefix framing lives in the faradayd-ipc seam; these helpers only map
// between JSON values and the seam's byte frames.

async fn write_frame(conn: &mut Connection, v: &Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    conn.write_frame(&bytes).await
}

async fn read_frame(conn: &mut Connection) -> std::io::Result<Option<Value>> {
    Ok(conn
        .read_frame()
        .await?
        .and_then(|buf| serde_json::from_slice(&buf).ok()))
}

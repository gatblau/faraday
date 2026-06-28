//! C17 — McpUpstreamClient (ADR-034). Issues an MCP JSON-RPC `tools/call` to one
//! allowlisted downstream MCP server over HTTP/SSE transport, with the broker-held
//! credential applied. The MCP analogue of C10 (DownstreamClient): no cross-origin
//! redirect is ever followed (AS-17: a 3xx is not followed, so the credential is never
//! re-sent to another host), the body is read under a hard size cap, and a per-call
//! timeout is enforced.
//!
//! Egress is HTTPS-only, with one bounded dev exception (ADR-032): a `http://127.0.0.1`
//! loopback origin is permitted only when plaintext loopback egress is enabled. A remote
//! `http` origin is refused, so a forwarded credential never leaves the machine in
//! cleartext. stdio transport is out of scope (ADR-034 / threat-model RR-10).
//!
//! This module is the outbound MCP *client*; it is distinct from C16 (`mcp.rs`), the
//! inbound MCP *server* front door. It holds no credentials of its own: the broker (C11)
//! attaches the credential via the `apply` closure and never lets it reach the guest.

use crate::errors::WireError;
use crate::types::{McpContentPart, McpToolResult, ResolvedCapability};
use serde_json::{json, Value};
use std::time::Duration;

/// Default per-call timeout (mirrors C10). Injectable via [`McpUpstreamClient::new`] so it
/// is never a hidden constant at the call site.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// MCP protocol version this client advertises at `initialize`.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Typed failure of an MCP upstream call (Phase-4 XC2 registry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpError {
    /// The per-call timeout elapsed.
    Timeout,
    /// Connection / TLS / transport error, a non-2xx HTTP status, or a refused
    /// (non-HTTPS, non-loopback) server URL.
    Unavailable,
    /// A malformed JSON-RPC message, a JSON-RPC error response, or a failed handshake.
    Protocol,
}

impl McpError {
    /// The wire/registry code for this failure (Phase-4 XC2 registry).
    pub fn code(&self) -> &'static str {
        match self {
            McpError::Timeout => "MCP_UPSTREAM_TIMEOUT",
            McpError::Unavailable => "MCP_UPSTREAM_UNAVAILABLE",
            McpError::Protocol => "MCP_PROTOCOL_ERROR",
        }
    }

    /// Map to the single wire-error envelope.
    pub fn to_wire(&self) -> WireError {
        let msg = match self {
            McpError::Timeout => "mcp upstream timed out",
            McpError::Unavailable => "mcp upstream unavailable",
            McpError::Protocol => "mcp protocol error",
        };
        WireError::new(self.code(), msg)
    }
}

/// The outcome of one HTTP POST to the MCP endpoint: any session id the server assigned,
/// the response content-type, the size-capped body, and whether the read hit the cap.
struct HttpOutcome {
    session_id: Option<String>,
    content_type: String,
    body: Vec<u8>,
    truncated: bool,
}

pub struct McpUpstreamClient {
    http: reqwest::Client,
    max_bytes: u64,
    /// ADR-032: when set, a `http://127.0.0.1` loopback origin is dialled over plaintext;
    /// every other host stays HTTPS and a remote `http` origin is refused.
    allow_plaintext_loopback: bool,
}

impl McpUpstreamClient {
    /// Production constructor: HTTPS-only by default. When `allow_plaintext_loopback` is
    /// set (ADR-032, `PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS`), a `127.0.0.1` server origin —
    /// and only that — may be reached over plaintext `http`; every other host stays HTTPS.
    pub fn new(
        max_bytes: u64,
        timeout: Duration,
        allow_plaintext_loopback: bool,
    ) -> Result<McpUpstreamClient, WireError> {
        let http = reqwest::Client::builder()
            // Never follow a redirect: a cross-origin 3xx must not be followed so the
            // credential is never replayed to another host (AS-17).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| WireError::new("INTERNAL", "mcp upstream client build"))?;
        Ok(McpUpstreamClient {
            http,
            max_bytes,
            allow_plaintext_loopback,
        })
    }

    /// Call one tool on the allowlisted downstream MCP server. The origin comes from policy
    /// (`cap.server_url`), never caller input; `apply` attaches the broker-held credential.
    /// Performs the MCP handshake (`initialize` + `notifications/initialized`) then
    /// `tools/call`, and returns the raw [`McpToolResult`] for the sanitizer (C5).
    pub async fn call_tool(
        &self,
        cap: &ResolvedCapability,
        tool: &str,
        arguments: &Value,
        apply: impl Fn(&mut reqwest::Request),
    ) -> Result<McpToolResult, McpError> {
        let raw = cap.server_url.as_deref().ok_or(McpError::Unavailable)?;
        let url = validate_server_url(raw, self.allow_plaintext_loopback)?;

        // 1. initialize — open the MCP session and capture any server-assigned id.
        let init = self
            .post_rpc(
                &url,
                None,
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": { "name": "faradayd", "version": env!("CARGO_PKG_VERSION") }
                    }
                }),
                &apply,
            )
            .await?;
        // The initialize response must itself be a well-formed JSON-RPC result.
        let init_env = extract_jsonrpc(&init.content_type, &init.body)?;
        if init_env.get("result").is_none() {
            return Err(McpError::Protocol);
        }
        let session = init.session_id.as_deref();

        // 2. notifications/initialized — best-effort; only a transport error aborts.
        self.post_notification(
            &url,
            session,
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            &apply,
        )
        .await?;

        // 3. tools/call — the actual tool invocation.
        let call = self
            .post_rpc(
                &url,
                session,
                &json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": { "name": tool, "arguments": arguments }
                }),
                &apply,
            )
            .await?;
        parse_tool_result(&call.content_type, &call.body, call.truncated)
    }

    /// POST a JSON-RPC request that expects a response; enforce a 2xx status and return the
    /// size-capped body. A non-2xx status (including an un-followed 3xx) → `Unavailable`.
    async fn post_rpc(
        &self,
        url: &reqwest::Url,
        session_id: Option<&str>,
        payload: &Value,
        apply: &impl Fn(&mut reqwest::Request),
    ) -> Result<HttpOutcome, McpError> {
        let outcome = self.send(url, session_id, payload, apply).await?;
        Ok(outcome)
    }

    /// POST a JSON-RPC notification (no response is required). Only a transport/timeout
    /// failure aborts the run; any HTTP status the server returns is accepted (a compliant
    /// server answers a notification with `202 Accepted` or an empty `200`).
    async fn post_notification(
        &self,
        url: &reqwest::Url,
        session_id: Option<&str>,
        payload: &Value,
        apply: &impl Fn(&mut reqwest::Request),
    ) -> Result<(), McpError> {
        match self
            .send_inner(url, session_id, payload, apply, false)
            .await
        {
            Ok(_) => Ok(()),
            Err(e @ (McpError::Timeout | McpError::Unavailable)) => Err(e),
            // A protocol-level oddity on the notification is tolerated.
            Err(McpError::Protocol) => Ok(()),
        }
    }

    /// `send` with the 2xx-enforcing read path (used by `post_rpc`).
    async fn send(
        &self,
        url: &reqwest::Url,
        session_id: Option<&str>,
        payload: &Value,
        apply: &impl Fn(&mut reqwest::Request),
    ) -> Result<HttpOutcome, McpError> {
        self.send_inner(url, session_id, payload, apply, true).await
    }

    async fn send_inner(
        &self,
        url: &reqwest::Url,
        session_id: Option<&str>,
        payload: &Value,
        apply: &impl Fn(&mut reqwest::Request),
        enforce_2xx: bool,
    ) -> Result<HttpOutcome, McpError> {
        let mut builder = self
            .http
            .post(url.clone())
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .json(payload);
        if let Some(sid) = session_id {
            builder = builder.header("Mcp-Session-Id", sid);
        }
        let mut req = builder.build().map_err(|_| McpError::Unavailable)?;
        apply(&mut req);

        let mut resp = self.http.execute(req).await.map_err(map_send_error)?;

        if enforce_2xx && !resp.status().is_success() {
            // A non-2xx status, or an un-followed cross-origin 3xx, is not a usable MCP
            // response. The credential was never re-sent (redirect policy is `none`).
            return Err(McpError::Unavailable);
        }

        let session_id = resp
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        // Read up to max_bytes + 1 so truncation can be flagged without ever buffering an
        // unbounded hostile response.
        let mut buf: Vec<u8> = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = resp.chunk().await.map_err(map_send_error)? {
            buf.extend_from_slice(&chunk);
            if buf.len() as u64 > self.max_bytes {
                buf.truncate(self.max_bytes as usize);
                truncated = true;
                break;
            }
        }

        Ok(HttpOutcome {
            session_id,
            content_type,
            body: buf,
            truncated,
        })
    }
}

/// Resolve and validate the MCP server origin. Pure (no I/O) so the ADR-032 boundary is
/// unit-testable: `https` is always allowed; plaintext `http` is allowed only for the
/// literal loopback host `127.0.0.1` and only when the dev toggle is set; every other
/// combination is refused, so a forwarded credential can never leave the machine in
/// cleartext and a remote origin is never downgraded.
fn validate_server_url(
    raw: &str,
    allow_plaintext_loopback: bool,
) -> Result<reqwest::Url, McpError> {
    let url = reqwest::Url::parse(raw).map_err(|_| McpError::Unavailable)?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if allow_plaintext_loopback && is_loopback_host(&url) => Ok(url),
        _ => Err(McpError::Unavailable),
    }
}

/// True only for the literal loopback IP `127.0.0.1`. A DNS name — `localhost`, or a
/// `127.0.0.1.evil.com` trick — is never loopback (the URL host parses to that name), so
/// ADR-032's plaintext exception can never apply to a remote host.
fn is_loopback_host(url: &reqwest::Url) -> bool {
    url.host_str() == Some("127.0.0.1")
}

/// Extract the JSON-RPC message from a response body. Streamable HTTP returns either a
/// single `application/json` body or a `text/event-stream` (SSE) sequence; for SSE the
/// JSON-RPC message is the payload of a `data:` line. Returns the last well-formed JSON
/// object found, or `Protocol` if none parses.
fn extract_jsonrpc(content_type: &str, body: &[u8]) -> Result<Value, McpError> {
    if content_type.contains("text/event-stream") {
        let text = std::str::from_utf8(body).map_err(|_| McpError::Protocol)?;
        let mut last: Option<Value> = None;
        let mut data = String::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            } else if line.is_empty() {
                if let Ok(v) = serde_json::from_str::<Value>(&data) {
                    last = Some(v);
                }
                data.clear();
            }
        }
        if !data.is_empty() {
            if let Ok(v) = serde_json::from_str::<Value>(&data) {
                last = Some(v);
            }
        }
        last.ok_or(McpError::Protocol)
    } else {
        serde_json::from_slice(body).map_err(|_| McpError::Protocol)
    }
}

/// Parse a `tools/call` JSON-RPC response into the raw [`McpToolResult`]. A JSON-RPC error
/// or a missing `result` is a `Protocol` failure; a tool-level `isError` is carried on the
/// result (it is a tool signal, not a transport error — ADR-034). A `resource_link` is
/// carried as a uri only and is never dereferenced here.
fn parse_tool_result(
    content_type: &str,
    body: &[u8],
    truncated: bool,
) -> Result<McpToolResult, McpError> {
    let env = extract_jsonrpc(content_type, body)?;
    if env.get("error").is_some() {
        return Err(McpError::Protocol);
    }
    let result = env.get("result").ok_or(McpError::Protocol)?;

    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let content = match result.get("content") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(map_content_item)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(McpError::Protocol),
    };

    let structured_content = match result.get("structuredContent") {
        None | Some(Value::Null) => None,
        Some(v) => Some(serde_json::to_vec(v).map_err(|_| McpError::Protocol)?),
    };

    Ok(McpToolResult {
        is_error,
        content,
        structured_content,
        truncated,
    })
}

/// Map one MCP content item to an [`McpContentPart`]. Unknown content types are a
/// `Protocol` failure rather than silently dropped.
fn map_content_item(item: &Value) -> Result<McpContentPart, McpError> {
    let kind = item
        .get("type")
        .and_then(Value::as_str)
        .ok_or(McpError::Protocol)?;
    match kind {
        "text" => {
            let text = item.get("text").and_then(Value::as_str).unwrap_or_default();
            Ok(McpContentPart::Text {
                content_type: "text/plain".to_string(),
                body: text.as_bytes().to_vec(),
            })
        }
        "image" | "audio" => {
            let data = item
                .get("data")
                .and_then(Value::as_str)
                .ok_or(McpError::Protocol)?;
            let mime_type = item
                .get("mimeType")
                .and_then(Value::as_str)
                .unwrap_or("application/octet-stream")
                .to_string();
            let body = decode_base64(data)?;
            Ok(McpContentPart::Image { mime_type, body })
        }
        "resource_link" => {
            let uri = item
                .get("uri")
                .and_then(Value::as_str)
                .ok_or(McpError::Protocol)?;
            Ok(McpContentPart::ResourceLink {
                uri: uri.to_string(),
                mime_type: item
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        }
        "resource" => {
            let res = item.get("resource").ok_or(McpError::Protocol)?;
            let uri = res
                .get("uri")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let mime_type = res
                .get("mimeType")
                .and_then(Value::as_str)
                .map(str::to_string);
            let body = if let Some(text) = res.get("text").and_then(Value::as_str) {
                text.as_bytes().to_vec()
            } else if let Some(blob) = res.get("blob").and_then(Value::as_str) {
                decode_base64(blob)?
            } else {
                Vec::new()
            };
            Ok(McpContentPart::EmbeddedResource {
                uri,
                mime_type,
                body,
            })
        }
        _ => Err(McpError::Protocol),
    }
}

fn decode_base64(s: &str) -> Result<Vec<u8>, McpError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| McpError::Protocol)
}

fn map_send_error(e: reqwest::Error) -> McpError {
    if e.is_timeout() {
        McpError::Timeout
    } else {
        McpError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- URL / scheme validation (ADR-032 egress boundary) ----

    #[test]
    fn https_origin_is_always_allowed() {
        assert!(validate_server_url("https://mcp.example.com/mcp", false).is_ok());
        assert!(validate_server_url("https://mcp.example.com/mcp", true).is_ok());
        // The loopback IP over https is fine too.
        assert!(validate_server_url("https://127.0.0.1:8443/mcp", false).is_ok());
    }

    #[test]
    fn loopback_http_allowed_only_when_enabled() {
        assert!(validate_server_url("http://127.0.0.1:8080/mcp", true).is_ok());
        // Disabled: even the loopback IP must stay refused over plaintext.
        assert_eq!(
            validate_server_url("http://127.0.0.1:8080/mcp", false),
            Err(McpError::Unavailable)
        );
    }

    #[test]
    fn remote_and_name_http_origins_are_refused_even_when_enabled() {
        // Security boundary: only the literal loopback IP may use plaintext. A public host,
        // a DNS name (`localhost`), and a prefix trick are all refused — a forwarded
        // credential can never leave the machine in cleartext.
        for raw in [
            "http://mcp.example.com/mcp",
            "http://localhost:8080/mcp",
            "http://127.0.0.1.evil.com/mcp",
            "http://10.0.0.1/mcp",
        ] {
            assert_eq!(
                validate_server_url(raw, true),
                Err(McpError::Unavailable),
                "origin {raw} must not be dialled over plaintext"
            );
        }
    }

    #[test]
    fn malformed_url_is_refused() {
        assert_eq!(
            validate_server_url("not a url", true),
            Err(McpError::Unavailable)
        );
    }

    // ---- tools/call result parsing ----

    #[test]
    fn parses_text_part() {
        let body =
            br#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hello"}]}}"#;
        let r = parse_tool_result("application/json", body, false).expect("parse");
        assert!(!r.is_error);
        assert_eq!(r.content.len(), 1);
        assert_eq!(
            r.content[0],
            McpContentPart::Text {
                content_type: "text/plain".to_string(),
                body: b"hello".to_vec()
            }
        );
    }

    #[test]
    fn parses_image_part_base64() {
        // "hi" base64-encoded is "aGk=".
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"image","data":"aGk=","mimeType":"image/png"}]}}"#;
        let r = parse_tool_result("application/json", body, false).expect("parse");
        assert_eq!(
            r.content[0],
            McpContentPart::Image {
                mime_type: "image/png".to_string(),
                body: b"hi".to_vec()
            }
        );
    }

    #[test]
    fn resource_link_is_carried_not_dereferenced() {
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"resource_link","uri":"file:///x","mimeType":"text/plain"}]}}"#;
        let r = parse_tool_result("application/json", body, false).expect("parse");
        assert_eq!(
            r.content[0],
            McpContentPart::ResourceLink {
                uri: "file:///x".to_string(),
                mime_type: Some("text/plain".to_string())
            }
        );
    }

    #[test]
    fn carries_structured_content_and_is_error() {
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"isError":true,"content":[],"structuredContent":{"k":1}}}"#;
        let r = parse_tool_result("application/json", body, false).expect("parse");
        assert!(r.is_error, "tool-level isError must be surfaced");
        assert!(r.content.is_empty());
        assert!(r.structured_content.is_some());
    }

    #[test]
    fn jsonrpc_error_is_protocol_failure() {
        let body = br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"no such tool"}}"#;
        assert_eq!(
            parse_tool_result("application/json", body, false),
            Err(McpError::Protocol)
        );
    }

    #[test]
    fn missing_result_is_protocol_failure() {
        let body = br#"{"jsonrpc":"2.0","id":2}"#;
        assert_eq!(
            parse_tool_result("application/json", body, false),
            Err(McpError::Protocol)
        );
    }

    #[test]
    fn malformed_json_is_protocol_failure() {
        assert_eq!(
            parse_tool_result("application/json", b"not json", false),
            Err(McpError::Protocol)
        );
    }

    #[test]
    fn unknown_content_type_is_protocol_failure() {
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"hologram"}]}}"#;
        assert_eq!(
            parse_tool_result("application/json", body, false),
            Err(McpError::Protocol)
        );
    }

    #[test]
    fn truncation_flag_is_carried_through() {
        let body = br#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"x"}]}}"#;
        let r = parse_tool_result("application/json", body, true).expect("parse");
        assert!(r.truncated);
    }

    #[test]
    fn extracts_jsonrpc_from_sse_stream() {
        // Streamable-HTTP SSE: the JSON-RPC message is the payload of a `data:` line.
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"sse\"}]}}\n\n";
        let r = parse_tool_result("text/event-stream; charset=utf-8", sse.as_bytes(), false)
            .expect("parse sse");
        assert_eq!(
            r.content[0],
            McpContentPart::Text {
                content_type: "text/plain".to_string(),
                body: b"sse".to_vec()
            }
        );
    }

    // ---- error code mapping (XC2 registry) ----

    #[test]
    fn error_codes_match_registry() {
        assert_eq!(McpError::Timeout.code(), "MCP_UPSTREAM_TIMEOUT");
        assert_eq!(McpError::Unavailable.code(), "MCP_UPSTREAM_UNAVAILABLE");
        assert_eq!(McpError::Protocol.code(), "MCP_PROTOCOL_ERROR");
        assert_eq!(McpError::Timeout.to_wire().code, "MCP_UPSTREAM_TIMEOUT");
        assert_eq!(McpError::Timeout.to_wire().status(), 504);
        assert_eq!(McpError::Unavailable.to_wire().status(), 502);
        assert_eq!(McpError::Protocol.to_wire().status(), 502);
    }
}

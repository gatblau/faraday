//! C5 — ResponseSanitizer. Reduces a raw downstream response to the typed
//! `UntrustedResponse` envelope (ADR-017): only the content-type header survives,
//! the body is size-capped with a truncation flag, and `untrusted` is always set.
//! For an MCP `tools/call` result it produces the multi-part `UntrustedMcpResult`
//! envelope (ADR-034): each part is carried under the untrusted marker, size-capped per
//! part and in aggregate, and a resource link is never dereferenced.

use crate::types::{
    McpContentPart, McpToolResult, UntrustedMcpResult, UntrustedPart, UntrustedResponse,
};

/// Build the untrusted envelope. Every response header except `Content-Type` is
/// dropped (so `Set-Cookie`/`Authorization`/`WWW-Authenticate` can never leak back),
/// and the body is capped at `max_bytes`.
pub fn sanitize(
    status: u16,
    raw: &[u8],
    headers: &[(String, String)],
    max_bytes: usize,
) -> UntrustedResponse {
    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let truncated = raw.len() > max_bytes;
    let body = if truncated {
        raw[..max_bytes].to_vec()
    } else {
        raw.to_vec()
    };

    UntrustedResponse {
        untrusted: true,
        status,
        content_type,
        body,
        truncated,
    }
}

/// Build the untrusted MCP envelope (ADR-034). Each content part is carried under the
/// untrusted marker; body-bearing parts are size-capped against the aggregate `max_bytes`
/// budget (overflow shortened or dropped, `truncated` flagged); a `ResourceLink` carries
/// only its uri and is never dereferenced. The tool-level `is_error` is propagated, not
/// treated as a sanitiser failure; `structuredContent` becomes a trailing `Json` part.
pub fn sanitize_mcp(result: &McpToolResult, max_bytes: usize) -> UntrustedMcpResult {
    let mut parts = Vec::with_capacity(result.content.len() + 1);
    let mut total = 0usize;
    let mut truncated = result.truncated;

    for part in &result.content {
        match part {
            McpContentPart::Text { content_type, body } => {
                if let Some(b) = cap_body(body, max_bytes, &mut total, &mut truncated) {
                    parts.push(UntrustedPart::Text {
                        content_type: content_type.clone(),
                        body: b,
                    });
                }
            }
            McpContentPart::Image { mime_type, body } => {
                if let Some(b) = cap_body(body, max_bytes, &mut total, &mut truncated) {
                    parts.push(UntrustedPart::Image {
                        mime_type: mime_type.clone(),
                        body: b,
                    });
                }
            }
            McpContentPart::ResourceLink { uri, mime_type } => {
                // A link carries no body — always preserved, never dereferenced.
                parts.push(UntrustedPart::ResourceLink {
                    uri: uri.clone(),
                    mime_type: mime_type.clone(),
                });
            }
            McpContentPart::EmbeddedResource {
                uri,
                mime_type,
                body,
            } => {
                if let Some(b) = cap_body(body, max_bytes, &mut total, &mut truncated) {
                    parts.push(UntrustedPart::EmbeddedResource {
                        uri: uri.clone(),
                        mime_type: mime_type.clone(),
                        body: b,
                    });
                }
            }
        }
    }

    if let Some(json) = &result.structured_content {
        if let Some(b) = cap_body(json, max_bytes, &mut total, &mut truncated) {
            parts.push(UntrustedPart::Json { body: b });
        }
    }

    UntrustedMcpResult {
        untrusted: true,
        is_error: result.is_error,
        parts,
        truncated,
    }
}

/// Size-cap a body against the remaining aggregate budget. Returns the (possibly
/// shortened) bytes to keep, or `None` when no budget remains and the body is non-empty
/// (the part is dropped). Sets `truncated` whenever bytes are shortened or dropped.
fn cap_body(
    body: &[u8],
    max_bytes: usize,
    total: &mut usize,
    truncated: &mut bool,
) -> Option<Vec<u8>> {
    let remaining = max_bytes.saturating_sub(*total);
    if body.len() <= remaining {
        *total += body.len();
        return Some(body.to_vec());
    }
    *truncated = true;
    if remaining == 0 {
        return None; // no budget left — drop the part entirely
    }
    *total = max_bytes;
    Some(body[..remaining].to_vec())
}

#[cfg(test)]
mod mcp_tests {
    use super::*;

    fn raw(content: Vec<McpContentPart>, is_error: bool) -> McpToolResult {
        McpToolResult {
            is_error,
            content,
            structured_content: None,
            truncated: false,
        }
    }

    #[test]
    fn maps_parts_and_marks_untrusted() {
        let r = raw(
            vec![McpContentPart::Text {
                content_type: "text/plain".into(),
                body: b"hello".to_vec(),
            }],
            false,
        );
        let out = sanitize_mcp(&r, 1024);
        assert!(out.untrusted);
        assert!(!out.is_error);
        assert_eq!(out.parts.len(), 1);
        assert!(!out.truncated);
    }

    #[test]
    fn propagates_is_error_and_structured_content() {
        let mut r = raw(Vec::new(), true);
        r.structured_content = Some(br#"{"k":1}"#.to_vec());
        let out = sanitize_mcp(&r, 1024);
        assert!(out.is_error);
        assert_eq!(out.parts.len(), 1);
        assert!(matches!(out.parts[0], UntrustedPart::Json { .. }));
    }

    #[test]
    fn resource_link_is_preserved_without_a_body() {
        let r = raw(
            vec![McpContentPart::ResourceLink {
                uri: "file:///x".into(),
                mime_type: None,
            }],
            false,
        );
        let out = sanitize_mcp(&r, 0);
        // A link survives even a zero byte-budget — it carries no body to cap.
        assert_eq!(
            out.parts[0],
            UntrustedPart::ResourceLink {
                uri: "file:///x".into(),
                mime_type: None
            }
        );
    }

    #[test]
    fn aggregate_cap_truncates_and_flags() {
        let r = raw(
            vec![
                McpContentPart::Text {
                    content_type: "text/plain".into(),
                    body: vec![b'a'; 8],
                },
                McpContentPart::Text {
                    content_type: "text/plain".into(),
                    body: vec![b'b'; 8],
                },
            ],
            false,
        );
        // Budget of 10: first part (8) fits, second is capped to 2 then flagged.
        let out = sanitize_mcp(&r, 10);
        assert!(out.truncated);
        let total: usize = out
            .parts
            .iter()
            .map(|p| match p {
                UntrustedPart::Text { body, .. } => body.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(total, 10, "aggregate body must not exceed the cap");
    }

    #[test]
    fn carries_raw_truncation_flag() {
        let mut r = raw(Vec::new(), false);
        r.truncated = true;
        assert!(sanitize_mcp(&r, 1024).truncated);
    }
}

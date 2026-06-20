//! C5 — ResponseSanitizer. Reduces a raw downstream response to the typed
//! `UntrustedResponse` envelope (ADR-017): only the content-type header survives,
//! the body is size-capped with a truncation flag, and `untrusted` is always set.

use crate::types::UntrustedResponse;

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

//! C2 — WireError + canonical code→status registry + panic-recovery boundary (XC2).
//!
//! Every component emits errors as a single `{ error, code }` envelope. The registry
//! maps each code to a status; an unknown code falls back to `INTERNAL`/500. The
//! recovery boundary maps a panic to `INTERNAL`/500 with no stack trace on the wire
//! (the panic is logged server-side, never serialised into the body).

use std::fmt;

/// The single wire error envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    pub error: String,
    pub code: String,
}

impl WireError {
    /// Build a `WireError`, truncating the human message to 200 chars and never
    /// carrying internal state, tokens, or stack traces.
    pub fn new(code: &str, msg: &str) -> WireError {
        let mut error = msg.to_string();
        if error.len() > 200 {
            error.truncate(200);
        }
        WireError {
            error,
            code: code.to_string(),
        }
    }

    /// The HTTP-style status this error maps to (registry).
    pub fn status(&self) -> u16 {
        status_for(&self.code)
    }

    /// Serialise to the canonical JSON body `{ "error": …, "code": … }`.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"error\":{},\"code\":{}}}",
            json_string(&self.error),
            json_string(&self.code)
        )
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code, self.error)
    }
}

impl std::error::Error for WireError {}

/// Canonical code → status registry (phase-4 XC2). Unknown codes fall back to 500.
pub fn status_for(code: &str) -> u16 {
    match code {
        "VAL_ERR" | "POLICY_PATH_REJECTED" => 400,
        "TOKEN_INVALID" | "STEP_UP_REQUIRED" | "SIGN_IN_FAILED" | "INTERACTION_UNAVAILABLE" => 401,
        "CAP_UNKNOWN"
        | "POLICY_PATH_DENIED"
        | "POLICY_METHOD_DENIED"
        | "CAP_INVALID"
        | "INTERACTION_DENIED" => 403,
        "RATE_LIMITED" => 429,
        "INTERNAL" | "RUNTIME_ARTIFACT_MISMATCH" | "RUNTIME_LIMIT" => 500,
        "EXCHANGE_FAILED" | "OBO_UNAVAILABLE" | "DOWNSTREAM_UNAVAILABLE" => 502,
        "IDP_UNAVAILABLE" => 503,
        "DOWNSTREAM_TIMEOUT" => 504,
        _ => 500, // registry miss → INTERNAL (XC2)
    }
}

/// Run `f`, mapping any panic to `WireError { code: "INTERNAL" }` (status 500) with
/// no stack trace in the body. The panic detail is left to the server-side panic
/// hook / logger; it never reaches the wire.
pub fn recover<T>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> Result<T, WireError> {
    match std::panic::catch_unwind(f) {
        Ok(value) => Ok(value),
        Err(_) => Err(WireError::new("INTERNAL", "internal error")),
    }
}

/// Minimal JSON string escaper (control chars + quotes/backslash) — avoids a serde
/// dependency for the error path, which must never itself fail.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

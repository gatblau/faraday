//! XC3 — structured logging + redaction. Builds one JSON object per line with the
//! required fields (`ts`, `level`, `msg`, `run_id`, `component`, `code` on error) and a
//! redaction layer that **drops sensitive field names** (`token`, `authorization`,
//! `id_token`, `secret`, `cert`, `connection_token`, `bearer`) and **masks token-shaped
//! values** (JWTs, `Bearer …`) anywhere in strings — extending the never-leak-a-token
//! guarantee (ADR-007) to the log surface. `PYS_LOG_LEVEL` selects the level; `debug` is
//! never the production default.

use serde_json::{Map, Value};

const SENSITIVE_KEYS: &[&str] = &[
    "token",
    "authorization",
    "id_token",
    "secret",
    "cert",
    "connection_token",
    "bearer",
];

/// Build a redacted structured JSON log line. `component`/`run_id` are required context;
/// `code` is included on error. Extra `fields` are redacted (sensitive keys masked,
/// token-shaped values scrubbed) before emission. The `ts` field is supplied by the
/// caller (monotonic/clock injection) to keep this pure and testable.
pub fn log_line(
    ts: i64,
    level: &str,
    msg: &str,
    run_id: &str,
    component: &str,
    code: Option<&str>,
    fields: &Map<String, Value>,
) -> String {
    let mut obj = Map::new();
    obj.insert("ts".into(), Value::from(ts));
    obj.insert("level".into(), Value::String(level.to_string()));
    obj.insert("msg".into(), Value::String(redact_str(msg)));
    obj.insert("run_id".into(), Value::String(run_id.to_string()));
    obj.insert("component".into(), Value::String(component.to_string()));
    if let Some(c) = code {
        obj.insert("code".into(), Value::String(c.to_string()));
    }
    for (k, v) in fields {
        if is_sensitive_key(k) {
            obj.insert(k.clone(), Value::String("[REDACTED]".into()));
        } else {
            obj.insert(k.clone(), redact_value(v));
        }
    }
    serde_json::to_string(&Value::Object(obj))
        .unwrap_or_else(|_| r#"{"level":"error","msg":"log-encode-failed"}"#.to_string())
}

fn is_sensitive_key(k: &str) -> bool {
    let kl = k.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|s| kl == *s)
}

fn redact_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(redact_str(s)),
        Value::Object(m) => {
            let mut o = Map::new();
            for (k, val) in m {
                if is_sensitive_key(k) {
                    o.insert(k.clone(), Value::String("[REDACTED]".into()));
                } else {
                    o.insert(k.clone(), redact_value(val));
                }
            }
            Value::Object(o)
        }
        Value::Array(a) => Value::Array(a.iter().map(redact_value).collect()),
        other => other.clone(),
    }
}

/// Mask token-shaped substrings (JWTs and `Bearer …`) in a string.
pub fn redact_str(s: &str) -> String {
    let re = regex::Regex::new(
        r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+|Bearer\s+[A-Za-z0-9._\-]+",
    )
    .expect("static redaction regex");
    re.replace_all(s, "[REDACTED]").into_owned()
}

//! Phase 11 XC3 gate: structured-log redaction. A token-shaped value or a sensitive
//! field name (`token`/`authorization`/`id_token`/`secret`/`cert`) must never reach a
//! built log line — the code is shown, the token is not.

use faradayd::log::{log_line, redact_str};
use serde_json::{json, Map, Value};

#[test]
fn xc3_redacts_sensitive_fields_and_token_shaped_values() {
    let mut fields = Map::new();
    fields.insert("token".into(), json!("supersecret-value"));
    fields.insert("authorization".into(), json!("Bearer abc.def"));
    fields.insert("id_token".into(), json!("eyJhbGc.eyJzdWI.sig123"));
    fields.insert(
        "note".into(),
        json!("see Bearer leaked-token-123 and eyJaaa.bbb.ccc here"),
    );
    fields.insert("status".into(), json!(200));

    let line = log_line(
        0,
        "error",
        "call failed token=eyJaaa.bbb.ccc",
        "r-1",
        "broker",
        Some("EXCHANGE_FAILED"),
        &fields,
    );
    let v: Value = serde_json::from_str(&line).unwrap();

    // Sensitive field names are masked.
    assert_eq!(v["token"], json!("[REDACTED]"));
    assert_eq!(v["authorization"], json!("[REDACTED]"));
    assert_eq!(v["id_token"], json!("[REDACTED]"));
    // The error code is shown; a non-sensitive field is preserved.
    assert_eq!(v["code"], json!("EXCHANGE_FAILED"));
    assert_eq!(v["status"], json!(200));
    // Token-shaped values in free text are masked.
    let note = v["note"].as_str().unwrap();
    assert!(note.contains("[REDACTED]"), "note={note}");
    assert!(!note.contains("eyJaaa"), "JWT scrubbed from note: {note}");
    assert!(
        !v["msg"].as_str().unwrap().contains("eyJaaa"),
        "JWT scrubbed from msg"
    );
    // No token material anywhere in the emitted line.
    assert!(!line.contains("supersecret-value"));
    assert!(!line.contains("eyJaaa"));
    assert!(!line.contains("leaked-token-123"));
}

#[test]
fn xc3_redact_str_masks_jwt_and_bearer_only() {
    assert_eq!(redact_str("x eyJa.bBb.cCc y"), "x [REDACTED] y");
    assert_eq!(redact_str("auth Bearer tok-123 end"), "auth [REDACTED] end");
    assert_eq!(
        redact_str("clean text, no secrets"),
        "clean text, no secrets"
    );
}

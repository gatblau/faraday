//! C3 — AuditLogger. Emits one `AuditEntry` per outbound call through a pluggable
//! sink. The user identifier is a keyed HMAC (never the raw subject); the entry
//! carries sizes only — never tokens or bodies (ADR-016).

use crate::types::AuditEntry;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Where audit records are emitted (OTLP in production; an in-process sink in tests).
pub trait AuditSink: Send + Sync {
    fn emit(&self, entry: &AuditEntry);
}

pub struct AuditLogger {
    hmac_key: Vec<u8>,
    sink: Box<dyn AuditSink>,
}

impl AuditLogger {
    pub fn new(hmac_key: Vec<u8>, sink: Box<dyn AuditSink>) -> Self {
        AuditLogger { hmac_key, sink }
    }

    /// Keyed-HMAC user identifier (hex) — resists offline reversal, unlike a bare hash.
    pub fn user_hmac(&self, subject: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.hmac_key).expect("HMAC accepts any key length");
        mac.update(subject.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Record one audit entry. Never blocks the caller on the sink's behalf beyond
    /// the emit call; a failing sink must not fail the request (handled by the sink).
    pub fn record(&self, entry: AuditEntry) {
        self.sink.emit(&entry);
    }
}

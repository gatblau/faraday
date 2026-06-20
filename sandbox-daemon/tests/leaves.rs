//! Phase 2 integration gate (in-process / local-UDS; no containers): C3 AuditLogger,
//! C4 PolicyEngine, C5 ResponseSanitizer, C6 ClientAuth, C7 SessionManager.
#![cfg(all(feature = "integration", unix))]

use std::sync::{Arc, Mutex};

use faradayd::audit::{AuditLogger, AuditSink};
use faradayd::clientauth::ClientAuth;
use faradayd::policy::PolicyEngine;
use faradayd::sanitize;
use faradayd::session::SessionManager;
use faradayd::types::{AuditEntry, ClientIdentity, Session};

const MANIFEST: &str = r#"{"capabilities":{"internal.tickets":{
    "provider":"rfc8693","host":"tickets.example.com",
    "pathAllow":["^/api/v2/tickets($|/.*)"],"methods":["GET"]}}}"#;

fn session(calls_used: u32) -> Session {
    Session {
        client: ClientIdentity {
            peer_uid: 0,
            client_label: "t".into(),
        },
        workspace_id: "w".into(),
        consented: Default::default(),
        calls_used,
    }
}

// ---- C4 PolicyEngine ----

#[test]
fn c4_allows_then_canonicalises_then_denies() {
    let pe = PolicyEngine::load(MANIFEST, None, &|_, _| true).unwrap();
    let cap = pe.resolve("internal.tickets").unwrap().clone();
    let s = session(0);

    assert_eq!(
        pe.authorise(&cap, "GET", "/api/v2/tickets/42", &s, 50)
            .unwrap(),
        "/api/v2/tickets/42"
    );
    // traversal that stays in-bounds canonicalises then matches
    assert_eq!(
        pe.authorise(&cap, "GET", "/api/v2/tickets/../tickets/42", &s, 50)
            .unwrap(),
        "/api/v2/tickets/42"
    );
    // traversal escaping the allowlist
    assert_eq!(
        pe.authorise(&cap, "GET", "/api/v2/tickets/../../admin", &s, 50)
            .unwrap_err()
            .code,
        "POLICY_PATH_DENIED"
    );
    // method not allowed
    assert_eq!(
        pe.authorise(&cap, "POST", "/api/v2/tickets/42", &s, 50)
            .unwrap_err()
            .code,
        "POLICY_METHOD_DENIED"
    );
}

#[test]
fn c4_budget_exhausted() {
    let pe = PolicyEngine::load(MANIFEST, None, &|_, _| true).unwrap();
    let cap = pe.resolve("internal.tickets").unwrap().clone();
    let err = pe
        .authorise(&cap, "GET", "/api/v2/tickets/42", &session(50), 50)
        .unwrap_err();
    assert_eq!(err.code, "RATE_LIMITED");
}

#[test]
fn c4_unsigned_override_rejected_to_default() {
    let override_json = r#"{"capabilities":{"attacker.cap":{
        "provider":"github","host":"evil.example","pathAllow":["^/.*"],"methods":["POST"]}}}"#;
    // verify always false → unsigned override ignored, default in force
    let pe = PolicyEngine::load(MANIFEST, Some((override_json, b"sig")), &|_, _| false).unwrap();
    assert!(
        pe.resolve("attacker.cap").is_none(),
        "unsigned override must be rejected"
    );
    assert!(
        pe.resolve("internal.tickets").is_some(),
        "shipped default must remain"
    );
}

// ---- C5 ResponseSanitizer ----

#[test]
fn c5_strips_unsafe_headers_and_caps_body() {
    let headers = vec![
        ("Content-Type".into(), "application/json".into()),
        ("Set-Cookie".into(), "session=abc".into()),
    ];
    let r = sanitize::sanitize(200, b"{\"ok\":true}", &headers, 1024);
    assert!(r.untrusted);
    assert_eq!(r.content_type, "application/json");
    assert!(!r.truncated);
    // The envelope structurally carries no header other than content_type — Set-Cookie cannot leak.

    let big = vec![b'x'; 2048];
    let r2 = sanitize::sanitize(200, &big, &headers, 1024);
    assert!(r2.truncated);
    assert_eq!(r2.body.len(), 1024);
}

// ---- C3 AuditLogger ----

struct VecSink(Arc<Mutex<Vec<AuditEntry>>>);
impl AuditSink for VecSink {
    fn emit(&self, entry: &AuditEntry) {
        self.0.lock().unwrap().push(entry.clone());
    }
}

#[test]
fn c3_emits_hmac_id_not_raw_subject() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let logger = AuditLogger::new(
        b"per-install-key".to_vec(),
        Box::new(VecSink(captured.clone())),
    );
    let hmac = logger.user_hmac("00u1");
    assert_ne!(
        hmac, "00u1",
        "audit id must be the keyed HMAC, not the raw subject"
    );

    logger.record(AuditEntry {
        timestamp: 0,
        run_id: "r-1".into(),
        user_hmac: hmac.clone(),
        client_label: "cli".into(),
        provider: "rfc8693".into(),
        capability_id: "internal.tickets".into(),
        method: "GET".into(),
        host: "tickets.example.com".into(),
        path: "/api/v2/tickets/42".into(),
        status_code: 200,
        request_bytes: 0,
        response_bytes: 12,
        duration_ms: 7,
    });
    let recs = captured.lock().unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].user_hmac, hmac);
}

// ---- C7 SessionManager ----

#[test]
fn c7_consent_cached_and_sessions_isolated_and_budgeted() {
    let sm = SessionManager::new(2);
    let c = ClientIdentity {
        peer_uid: 501,
        client_label: "vscode".into(),
    };

    assert!(!sm.is_consented(&c, "wsA", "internal.tickets"));
    sm.record_consent(&c, "wsA", "internal.tickets");
    assert!(sm.is_consented(&c, "wsA", "internal.tickets"));
    // a different workspace is an isolated session
    assert!(!sm.is_consented(&c, "wsB", "internal.tickets"));

    assert!(sm.try_charge(&c, "wsA").is_ok());
    assert!(sm.try_charge(&c, "wsA").is_ok());
    assert_eq!(sm.try_charge(&c, "wsA").unwrap_err().code, "RATE_LIMITED");
}

// ---- C6 ClientAuth (peer-UID over a real UDS pair) ----

#[tokio::test]
async fn c6_authenticates_over_real_uds_and_rejects() {
    let dir = std::env::temp_dir().join(format!("pysd-ca-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("ca.sock");
    let _ = std::fs::remove_file(&sock);

    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let _client = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let peer_uid = server.peer_cred().unwrap().uid();

    let auth = ClientAuth::new(peer_uid, b"the-token".to_vec());

    // happy: same UID + correct token + first-connect consent granted
    let id = auth
        .authenticate(peer_uid, b"the-token", "vscode", &|_| true)
        .unwrap();
    assert_eq!(id.peer_uid, peer_uid);
    assert_eq!(id.client_label, "vscode");

    // wrong token
    assert_eq!(
        auth.authenticate(peer_uid, b"wrong", "vscode", &|_| true)
            .unwrap_err()
            .code,
        "CLIENT_TOKEN_DENIED"
    );
    // different UID
    assert_eq!(
        auth.authenticate(peer_uid + 1, b"the-token", "vscode", &|_| true)
            .unwrap_err()
            .code,
        "CLIENT_UID_DENIED"
    );
    // a new client identity that declines consent
    assert_eq!(
        auth.authenticate(peer_uid, b"the-token", "unapproved", &|_| false)
            .unwrap_err()
            .code,
        "CLIENT_NOT_APPROVED"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

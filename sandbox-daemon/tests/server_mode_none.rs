//! Plan 06 / Phase 1 integration gate (server-mode `none`). Assembles the real daemon
//! pipeline — ControlEndpoint → SandboxController → IdentityBroker → real DownstreamClient
//! → real SandboxRuntime/RustPython — and runs an agent that calls a public endpoint
//! through an `authMode: none` capability against a real `mockserver` container, with NO
//! OIDC configured and an interactor that fails any interaction. A successful run proves
//! the headless public path: no sign-in, no consent, and no `Authorization` header sent
//! (ADR-037 / ADR-038 / ADR-039).
#![cfg(all(feature = "integration", unix))]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use faradayd::audit::{AuditLogger, AuditSink};
use faradayd::broker::{BrokerCall, CredentialSource, IdentityBroker};
use faradayd::config::{Config, CredentialMode};
use faradayd::controller::{CapabilityMinter, IdTokenSink, Interactor, SandboxController};
use faradayd::downstream::DownstreamClient;
use faradayd::endpoint::Daemon;
use faradayd::health::HealthCheck;
use faradayd::interaction::{InteractionError, InteractionOutcome};
use faradayd::obo::OboClient;
use faradayd::policy::PolicyEngine;
use faradayd::runtime::{Limits, SandboxRuntime};
use faradayd::session::SessionManager;
use faradayd::types::{AuditEntry, ClientIdentity, InteractionRequired};
use testcontainers::{core::IntoContainerPort, core::WaitFor, runners::AsyncRunner, GenericImage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");
const MOCKSERVER_PORT: u16 = 1080;

// An interactor that refuses every interaction. A successful run therefore proves the
// controller raised neither sign-in nor consent (the server-mode headless path).
struct NoSignInInteractor;
impl Interactor for NoSignInInteractor {
    fn require_boxed<'a>(
        &'a self,
        _who: &'a ClientIdentity,
        _what: InteractionRequired,
    ) -> Pin<Box<dyn Future<Output = Result<InteractionOutcome, InteractionError>> + Send + 'a>>
    {
        Box::pin(async { Err(InteractionError::Unavailable) })
    }
}

// No held credentials — a `none` capability needs none.
struct NoCreds;
impl CredentialSource for NoCreds {
    fn id_token(&self) -> Option<String> {
        None
    }
    fn access_token(&self) -> Option<String> {
        None
    }
}
impl IdTokenSink for NoCreds {
    fn set_id_token(&self, _t: String) {}
    fn set_access_token(&self, _t: String) {}
}

struct VecSink(Arc<Mutex<Vec<AuditEntry>>>);
impl AuditSink for VecSink {
    fn emit(&self, e: &AuditEntry) {
        self.0.lock().unwrap().push(e.clone());
    }
}

fn test_config(socket: String, token: String) -> Config {
    Config {
        socket_path: socket,
        token_path: token,
        require_first_connect_consent: false,
        oidc_issuer: None,
        oidc_client_id: None,
        oidc_scopes: "openid profile email".into(),
        obo_endpoint: None,
        policy_path: "unused".into(),
        admin_signing_key: None,
        consent_ui_mode: "auto".into(),
        max_calls_per_run: 50,
        max_calls_per_session: 50,
        response_max_bytes: 1_048_576,
        allow_plaintext_loopback_egress: false,
        wasm_fuel: None,
        wasm_max_memory_bytes: 536_870_912,
        wasm_deadline_seconds: 60,
        guest_artifact_digest: "unused".into(),
        otlp_endpoint: None,
        audit_hmac_key: vec![9, 9, 9],
        log_level: "info".into(),
        credential_mode: CredentialMode::Mock,
    }
}

async fn start_mockserver() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new("mockserver/mockserver", "5.15.0")
        .with_exposed_port(MOCKSERVER_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("started on port"))
        .start()
        .await
        .expect("start mockserver");
    let port = container
        .get_host_port_ipv4(MOCKSERVER_PORT.tcp())
        .await
        .expect("mockserver port");
    (container, format!("http://127.0.0.1:{port}"))
}

async fn put_expectation(http: &reqwest::Client, base: &str, body: serde_json::Value) {
    for attempt in 0..40u32 {
        if let Ok(r) = http
            .put(format!("{base}/mockserver/expectation"))
            .json(&body)
            .send()
            .await
        {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        if attempt == 39 {
            panic!("mockserver never ready");
        }
    }
}

async fn send(stream: &mut UnixStream, v: serde_json::Value) {
    let b = serde_json::to_vec(&v).unwrap();
    stream
        .write_all(&(b.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&b).await.unwrap();
}
async fn recv(stream: &mut UnixStream) -> serde_json::Value {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.unwrap();
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await.unwrap();
    serde_json::from_slice(&buf).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn none_capability_public_call_headless() {
    let (_ms, base) = start_mockserver().await;
    let host = base.trim_start_matches("http://").to_string();
    let admin = reqwest::Client::new();

    // Higher-priority expectation: if ANY Authorization header is present, return a marker
    // body so the assertion fails. A `none` call must never carry one.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "priority": 10,
            "httpRequest": {"method": "GET", "path": "/public/data",
                "headers": {"Authorization": [".*"]}},
            "httpResponse": {"statusCode": 401, "body": "leaked-auth"}
        }),
    )
    .await;
    // Default expectation: no credential → the public body.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "priority": 0,
            "httpRequest": {"method": "GET", "path": "/public/data"},
            "httpResponse": {"statusCode": 200, "body": "public-ok"}
        }),
    )
    .await;

    // One `none` capability pointed at the mockserver; no provider/audience/scopes.
    let manifest = format!(
        r#"{{"capabilities":{{
            "holidays":{{"authMode":"none","host":"{host}",
                "pathAllow":["^/public/data$"],"methods":["GET"]}}
        }}}}"#
    );
    let policy = Arc::new(PolicyEngine::load(&manifest, None, &|_, _| true).unwrap());
    assert!(
        !policy.has_oidc_capability(),
        "manifest has no OIDC capability"
    );

    let audit_records = Arc::new(Mutex::new(Vec::new()));
    let audit = Arc::new(AuditLogger::new(
        vec![9, 9, 9],
        Box::new(VecSink(audit_records.clone())),
    ));
    let obo = Arc::new(OboClient::new(base.clone()).unwrap());
    let downstream =
        Arc::new(DownstreamClient::new_plaintext(1_048_576, Duration::from_secs(10)).unwrap());
    let creds = Arc::new(NoCreds);
    let broker = Arc::new(IdentityBroker::new(
        policy.clone(),
        audit,
        obo,
        downstream,
        creds.clone() as Arc<dyn CredentialSource>,
        1_048_576,
        Arc::new(std::collections::HashMap::<String, String>::new())
            as Arc<dyn faradayd::broker::ApiKeyStore>,
    ));
    let runtime = Arc::new(
        SandboxRuntime::new(
            &SandboxRuntime::digest_of(GUEST),
            GUEST,
            broker.clone() as Arc<dyn BrokerCall>,
        )
        .unwrap(),
    );
    let controller = Arc::new(SandboxController::new(
        policy,
        Arc::new(NoSignInInteractor),
        broker as Arc<dyn CapabilityMinter>,
        runtime,
        Arc::new(SessionManager::new(50)),
        creds as Arc<dyn IdTokenSink>,
        String::new(),
        Limits {
            fuel: Some(u64::MAX),
            epoch_deadline: Duration::from_secs(60),
            ..Limits::default()
        },
    ));

    let dir = std::env::temp_dir().join(format!("pysd-srvmode-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("d.sock").to_string_lossy().into_owned();
    let token_path = dir.join("d.token").to_string_lossy().into_owned();
    let daemon = Daemon::bind(
        test_config(socket.clone(), token_path),
        controller,
        Arc::new(HealthCheck::new(String::new(), None)),
    )
    .expect("daemon binds");
    let token = daemon.connection_token().to_string();
    tokio::spawn(async move {
        let _ = daemon.serve().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut s = UnixStream::connect(&socket).await.unwrap();
    send(
        &mut s,
        serde_json::json!({ "type": "connect", "clientLabel": "agent", "token": token, "workspaceId": "ws" }),
    )
    .await;
    assert_eq!(recv(&mut s).await["type"], serde_json::json!("connected"));

    let req = serde_json::json!({
        "code": "print(api.holidays.get('/public/data').decode())",
        "requestedCapabilities": ["holidays"], "workspaceId": "ws", "dryRun": false
    });
    send(&mut s, serde_json::json!({ "type": "run", "request": req })).await;
    let r = recv(&mut s).await;

    // The run completed (no sign-in / no consent was required — the interactor would have
    // failed it) and returned the public body via the no-credential path.
    assert_eq!(r["type"], serde_json::json!("result"), "got {r}");
    let stdout = r["result"]["stdout"].as_str().unwrap_or("");
    assert!(stdout.contains("public-ok"), "stdout={stdout:?}");
    assert!(
        !stdout.contains("leaked-auth"),
        "no Authorization header may be sent on a none call; stdout={stdout:?}"
    );

    // The call was audited (sizes + keyed-HMAC id; the entry type carries no token field).
    assert_eq!(audit_records.lock().unwrap().len(), 1, "one call audited");

    let _ = std::fs::remove_dir_all(&dir);
}

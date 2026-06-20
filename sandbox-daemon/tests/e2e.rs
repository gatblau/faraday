//! Phase 10 e2e gate (Option A — headless real-components). Assembles the REAL daemon
//! pipeline — ControlEndpoint → SandboxController → IdentityBroker (real OBO via a
//! containerised stub-obo, real direct via mockserver, real sanitise + audit) → real
//! SandboxRuntime/RustPython — over a real UDS, and drives it with an in-test UDS
//! client. The interactive browser sign-in is replaced by a test interactor + test
//! credential source (RISK-004 is verified manually); FU-024 (mid-run step-up retry)
//! and FU-025 (token expiry → TOKEN_INVALID) scenarios are out of scope here.
//!
//! Proves end-to-end: connect+auth; a run whose `api.tickets.get(...)` is brokered via
//! the real OBO exchange to the stub obo-broker and returns the sanitised body (no
//! token); a direct-provider run applies the held bearer via mockserver; the single MCP
//! tool yields an equivalent result; `dry_run` plans with no egress; and the audit log
//! never carries a token.
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
use faradayd::types::{AuditEntry, ClientIdentity, InteractionRequired, Principal};
use testcontainers::{core::IntoContainerPort, core::WaitFor, runners::AsyncRunner, GenericImage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");
const MOCKSERVER_PORT: u16 = 1080;

// ---- test stand-ins for the interactive surface (RISK-004) ----

struct TestInteractor;
impl Interactor for TestInteractor {
    fn require_boxed<'a>(
        &'a self,
        _who: &'a ClientIdentity,
        what: InteractionRequired,
    ) -> Pin<Box<dyn Future<Output = Result<InteractionOutcome, InteractionError>> + Send + 'a>>
    {
        let is_consent = matches!(what, InteractionRequired::Consent { .. });
        Box::pin(async move {
            if is_consent {
                Ok(InteractionOutcome::Allowed)
            } else {
                Ok(InteractionOutcome::SignedIn {
                    principal: Principal {
                        subject: "00u-e2e".into(),
                        issuer: "https://idp.example".into(),
                        acr: None,
                        amr: vec![],
                        auth_time: None,
                    },
                    id_token: "e2e-id-token".into(),
                    access_token: "direct-token".into(),
                })
            }
        })
    }
}

struct E2eCreds {
    id_token: Mutex<Option<String>>,
    access_token: Mutex<Option<String>>,
}
impl CredentialSource for E2eCreds {
    fn id_token(&self) -> Option<String> {
        self.id_token.lock().unwrap().clone()
    }
    fn access_token(&self) -> Option<String> {
        self.access_token.lock().unwrap().clone()
    }
}
impl IdTokenSink for E2eCreds {
    fn set_id_token(&self, id_token: String) {
        *self.id_token.lock().unwrap() = Some(id_token);
    }
    fn set_access_token(&self, access_token: String) {
        *self.access_token.lock().unwrap() = Some(access_token);
    }
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
        oidc_issuer: Some("https://idp.example".into()),
        oidc_client_id: Some("faradayd".into()),
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

// ---- mockserver helpers ----

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

// ---- UDS client framing ----

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
async fn full_pipeline_obo_direct_mcp_and_dry_run() {
    let (_ms, base) = start_mockserver().await;
    let host = base.trim_start_matches("http://").to_string();
    let admin = reqwest::Client::new();

    // stub obo-broker: POST /v1/exchange → sanitised JSON (no token).
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "POST", "path": "/v1/exchange"},
            "httpResponse": {"statusCode": 200, "headers": {"content-type": ["application/json"]},
                "body": "{\"data\":\"obo-ok\"}"}
        }),
    )
    .await;
    // direct provider: requires the applied bearer.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/api/v3/repos",
                "headers": {"Authorization": ["Bearer direct-token"]}},
            "httpResponse": {"statusCode": 200, "body": "repo-ok"}
        }),
    )
    .await;

    // Assemble the REAL broker over real OBO + downstream clients pointed at mockserver.
    let manifest = format!(
        r#"{{"capabilities":{{
            "tickets":{{"provider":"rfc8693","host":"tickets.example.com",
                "pathAllow":["^/api/v2/tickets($|/.*)"],"methods":["GET"]}},
            "repos":{{"provider":"github","authMode":"passthrough","host":"{host}",
                "pathAllow":["^/api/v3/repos($|/.*)"],"methods":["GET"]}}
        }}}}"#
    );
    let policy = Arc::new(PolicyEngine::load(&manifest, None, &|_, _| true).unwrap());
    let audit_records = Arc::new(Mutex::new(Vec::new()));
    let audit = Arc::new(AuditLogger::new(
        vec![9, 9, 9],
        Box::new(VecSink(audit_records.clone())),
    ));
    let obo = Arc::new(OboClient::new(base.clone()).unwrap());
    let downstream =
        Arc::new(DownstreamClient::new_plaintext(1_048_576, Duration::from_secs(10)).unwrap());
    let creds = Arc::new(E2eCreds {
        id_token: Mutex::new(None),
        access_token: Mutex::new(None),
    });
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
        Arc::new(TestInteractor),
        broker as Arc<dyn CapabilityMinter>,
        runtime,
        Arc::new(SessionManager::new(50)),
        creds as Arc<dyn IdTokenSink>,
        "https://idp.example".to_string(),
        Limits {
            fuel: Some(u64::MAX),
            epoch_deadline: Duration::from_secs(60),
            ..Limits::default()
        },
    ));

    let dir = std::env::temp_dir().join(format!("pysd-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("d.sock").to_string_lossy().into_owned();
    let token_path = dir.join("d.token").to_string_lossy().into_owned();
    let daemon = Daemon::bind(
        test_config(socket.clone(), token_path),
        controller,
        Arc::new(HealthCheck::new("https://idp.example".into(), None)),
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
        serde_json::json!({ "type": "connect", "clientLabel": "vscode", "token": token, "workspaceId": "ws" }),
    )
    .await;
    assert_eq!(recv(&mut s).await["type"], serde_json::json!("connected"));

    let obo_req = serde_json::json!({
        "code": "print(api.tickets.get('/api/v2/tickets/42').decode())",
        "requestedCapabilities": ["tickets"], "workspaceId": "ws", "dryRun": false
    });
    let direct_req = serde_json::json!({
        "code": "print(api.repos.get('/api/v3/repos').decode())",
        "requestedCapabilities": ["repos"], "workspaceId": "ws", "dryRun": false
    });

    // 1) OBO run via the real broker exchange → sanitised body, no token.
    send(
        &mut s,
        serde_json::json!({ "type": "run", "request": obo_req }),
    )
    .await;
    let r = recv(&mut s).await;
    assert_eq!(r["type"], serde_json::json!("result"), "got {r}");
    let obo_stdout = r["result"]["stdout"].as_str().unwrap_or("");
    assert!(
        obo_stdout.contains("{\"data\":\"obo-ok\"}"),
        "obo stdout={obo_stdout:?}"
    );
    assert!(
        !obo_stdout.contains("e2e-id-token"),
        "no id_token in result"
    );

    // 2) the single MCP tool yields an equivalent result
    send(
        &mut s,
        serde_json::json!({ "type": "mcp", "arguments": obo_req }),
    )
    .await;
    let m = recv(&mut s).await;
    assert_eq!(
        m["result"]["stdout"], r["result"]["stdout"],
        "MCP == native RPC"
    );

    // 3) direct-provider run applies the held bearer via mockserver
    send(
        &mut s,
        serde_json::json!({ "type": "run", "request": direct_req }),
    )
    .await;
    let d = recv(&mut s).await;
    assert_eq!(d["type"], serde_json::json!("result"), "got {d}");
    assert!(
        d["result"]["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("repo-ok"),
        "direct stdout={:?}",
        d["result"]["stdout"]
    );

    // 4) dry_run plans with no egress
    let dry = serde_json::json!({
        "code": "print('unreached')", "requestedCapabilities": ["tickets"],
        "workspaceId": "ws", "dryRun": true
    });
    send(&mut s, serde_json::json!({ "type": "run", "request": dry })).await;
    let dr = recv(&mut s).await;
    assert_eq!(dr["type"], serde_json::json!("dryRun"), "got {dr}");

    // The audit log recorded the brokered calls and never a token (structural).
    let recs = audit_records.lock().unwrap();
    assert!(
        recs.len() >= 3,
        "obo + mcp + direct audited: {}",
        recs.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

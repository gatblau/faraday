//! End-to-end gate closing the RISK-004 automation gap: the **full daemon pipeline driven
//! with a REAL interactive sign-in**. Unlike `e2e.rs` (which stubs the interactor), this
//! wires the production `ConsentUI` against a real `dexidp/dex` and lets a run trigger the
//! actual OIDC authorization-code + PKCE loopback flow (ADR-029). A scripted surface stands
//! in only for the human at the Dex login form; everything else — ControlEndpoint → C6 auth
//! → SandboxController → C8 ConsentUI (real Dex discover/authorize/capture/exchange/JWKS) →
//! IdentityBroker → C9 OBO exchange → SandboxRuntime/RustPython → sanitise → UDS reply — is
//! the real pipeline.
//!
//! Proves the join the other e2e tests cannot: the token obtained by a real sign-in flows
//! through the broker to the wire. The stub obo-broker records the `/v1/exchange` request,
//! and the test asserts its `userIdToken` is a genuine Dex-issued JWT (header.payload.sig),
//! not an injected fixture.
#![cfg(all(feature = "integration", unix))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use faradayd::audit::{AuditLogger, AuditSink};
use faradayd::broker::{BrokerCall, CredentialSource, IdentityBroker};
use faradayd::config::{Config, CredentialMode};
use faradayd::controller::{CapabilityMinter, IdTokenSink, Interactor, SandboxController};
use faradayd::downstream::DownstreamClient;
use faradayd::endpoint::Daemon;
use faradayd::health::HealthCheck;
use faradayd::interaction::{ConsentSummary, ConsentUI, InteractionSurface};
use faradayd::obo::OboClient;
use faradayd::policy::PolicyEngine;
use faradayd::runtime::{Limits, SandboxRuntime};
use faradayd::session::SessionManager;
use faradayd::types::AuditEntry;
use testcontainers::{
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");
const MOCKSERVER_PORT: u16 = 1080;
// Distinct fixed port from tests/consent.rs (5556) and tests/signin_real_dex.rs (5557) so
// the real-Dex gates run concurrently without colliding on the host port.
const DEX_ISSUER: &str = "http://127.0.0.1:5558/dex";

// ---- the scripted "human": drives the Dex login so the auth code redirects to the
// daemon's transient 127.0.0.1 listener (the same technique as tests/signin_real_dex.rs),
// and auto-approves the per-session consent prompt. ----

struct ScriptedDexBrowser;
impl InteractionSurface for ScriptedDexBrowser {
    fn available(&self) -> bool {
        true
    }
    fn open(&self, url: &str) {
        let url = url.to_string();
        tokio::spawn(async move {
            let http = reqwest::Client::new(); // follows redirects by default
            let form_url = match http.get(&url).send().await {
                Ok(r) => r.url().clone(),
                Err(e) => {
                    eprintln!("scripted-browser: authorize GET failed: {e}");
                    return;
                }
            };
            if let Err(e) = http
                .post(form_url)
                .form(&[("login", "test@example.com"), ("password", "password")])
                .send()
                .await
            {
                eprintln!("scripted-browser: login POST failed: {e}");
            }
        });
    }
    fn confirm_consent(&self, _summary: &ConsentSummary) -> bool {
        true
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
        oidc_issuer: Some(DEX_ISSUER.into()),
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

// ---- Dex (real OIDC), public client with NO redirectURIs (RFC 8252 loopback exemption). ----

async fn start_dex() -> testcontainers::ContainerAsync<GenericImage> {
    // bcrypt("password"); a test-only fixture for the ephemeral Dex container, not a secret.
    let hash = "$2y$10$N/3FzpIqyUXPz0mTY0k6NO0R7TMcPWUkRgp/Zt1UEVbKynGlqUjTW";
    let config = format!(
        r#"issuer: {DEX_ISSUER}
storage:
  type: memory
web:
  http: 0.0.0.0:5558
enablePasswordDB: true
oauth2:
  passwordConnector: local
  skipApprovalScreen: true
staticPasswords:
- email: "test@example.com"
  hash: "{hash}"
  username: "test"
  userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
staticClients:
- id: faradayd
  name: faradayd
  public: true
"#
    );
    let dir = std::env::temp_dir().join(format!("pysd-dex-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.yaml");
    std::fs::write(&cfg_path, config).unwrap();

    GenericImage::new("dexidp/dex", "v2.45.1")
        .with_exposed_port(5558.tcp())
        .with_mapped_port(5558, 5558.tcp())
        .with_mount(Mount::bind_mount(
            cfg_path.to_string_lossy().to_string(),
            "/etc/dex/config.yaml",
        ))
        .with_cmd(["dex", "serve", "/etc/dex/config.yaml"])
        .start()
        .await
        .expect("start dex container")
}

async fn wait_dex_ready(http: &reqwest::Client) {
    for attempt in 0..60u32 {
        if let Ok(r) = http
            .get(format!("{DEX_ISSUER}/.well-known/openid-configuration"))
            .send()
            .await
        {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        if attempt == 59 {
            panic!("dex discovery never became ready");
        }
    }
}

// ---- mockserver (stub obo-broker) ----

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

/// Pull the `userIdToken` the broker sent to the stub obo-broker's `/v1/exchange`, tolerant
/// of how mockserver records the body (parsed JSON vs raw string).
fn recorded_user_id_token(recorded: &serde_json::Value) -> Option<String> {
    for req in recorded.as_array()? {
        let path = req.get("path").and_then(|p| p.as_str()).unwrap_or("");
        if !path.contains("/v1/exchange") {
            continue;
        }
        let body = req.get("body")?;
        let parsed = body
            .get("json")
            .cloned()
            .or_else(|| {
                body.get("string")
                    .and_then(|s| s.as_str())
                    .and_then(|s| serde_json::from_str(s).ok())
            })
            .or_else(|| Some(body.clone()))?;
        if let Some(tok) = parsed.get("userIdToken").and_then(|t| t.as_str()) {
            return Some(tok.to_string());
        }
    }
    None
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
async fn full_chain_with_real_dex_signin() {
    let _dex = start_dex().await;
    let (_ms, base) = start_mockserver().await;
    let admin = reqwest::Client::new();
    wait_dex_ready(&admin).await;

    // Stub obo-broker: POST /v1/exchange → sanitised JSON (no token).
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

    // One OBO (rfc8693) capability — no `audience`, so sign-in needs no IdP trusted-peer.
    let manifest = r#"{"capabilities":{
        "tickets":{"provider":"rfc8693","host":"tickets.example.com",
            "pathAllow":["^/api/v2/tickets($|/.*)"],"methods":["GET"]}
    }}"#;
    let policy = Arc::new(PolicyEngine::load(manifest, None, &|_, _| true).unwrap());
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
    // THE point of this test: the REAL ConsentUI against real Dex, not a stub interactor.
    let consent: Arc<dyn Interactor> = Arc::new(
        ConsentUI::new(
            DEX_ISSUER.to_string(),
            "faradayd".to_string(),
            "openid profile email".to_string(),
            "auto".to_string(),
            Box::new(ScriptedDexBrowser),
        )
        .expect("construct ConsentUI"),
    );
    let controller = Arc::new(SandboxController::new(
        policy,
        consent,
        broker as Arc<dyn CapabilityMinter>,
        runtime,
        Arc::new(SessionManager::new(50)),
        creds as Arc<dyn IdTokenSink>,
        DEX_ISSUER.to_string(),
        Limits {
            fuel: Some(u64::MAX),
            epoch_deadline: Duration::from_secs(60),
            ..Limits::default()
        },
    ));

    let dir = std::env::temp_dir().join(format!("pysd-e2e-signin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("d.sock").to_string_lossy().into_owned();
    let token_path = dir.join("d.token").to_string_lossy().into_owned();
    let daemon = Daemon::bind(
        test_config(socket.clone(), token_path),
        controller,
        Arc::new(HealthCheck::new(DEX_ISSUER.into(), None)),
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

    // A run with no token yet → triggers the real consent + real Dex sign-in → broker OBO
    // exchange → sanitised body. If the loopback redirect or PKCE exchange failed, sign-in
    // fails closed and no result comes back.
    let obo_req = serde_json::json!({
        "code": "print(api.tickets.get('/api/v2/tickets/42').decode())",
        "requestedCapabilities": ["tickets"], "workspaceId": "ws", "dryRun": false
    });
    send(
        &mut s,
        serde_json::json!({ "type": "run", "request": obo_req }),
    )
    .await;
    let r = recv(&mut s).await;
    assert_eq!(r["type"], serde_json::json!("result"), "got {r}");
    let stdout = r["result"]["stdout"].as_str().unwrap_or("");
    assert!(
        stdout.contains("{\"data\":\"obo-ok\"}"),
        "stdout={stdout:?}"
    );
    assert!(
        !stdout.contains("eyJ"),
        "no token leaks into the guest output"
    );

    // The decisive assertion: the token the broker exchanged was a GENUINE Dex-issued JWT
    // from the live sign-in — header.payload.signature, all base64url — not a fixture.
    let recorded: serde_json::Value = admin
        .put(format!(
            "{base}/mockserver/retrieve?type=requests&format=json"
        ))
        .send()
        .await
        .expect("retrieve recorded requests")
        .json()
        .await
        .expect("recorded requests json");
    let user_id_token = recorded_user_id_token(&recorded)
        .expect("the broker called /v1/exchange with a userIdToken");
    assert_eq!(
        user_id_token.split('.').count(),
        3,
        "userIdToken must be a real 3-part Dex JWT, got: {user_id_token}"
    );
    assert!(
        user_id_token.starts_with("eyJ"),
        "userIdToken must be a base64url Dex JWT, got: {user_id_token}"
    );

    let recs = audit_records.lock().unwrap();
    assert!(!recs.is_empty(), "the brokered call was audited");

    let _ = std::fs::remove_dir_all(&dir);
}

//! Phase 9 integration gate: C14 ControlEndpoint and C15 HealthCheck over a real UDS,
//! container-free. The daemon is assembled with a stubbed controller (stub interactor
//! auto-approves consent/sign-in, stub broker mints and answers calls, real
//! PolicyEngine, real SandboxRuntime/RustPython guest, real SessionManager). It proves
//! a secure 0600 socket and token; connect+auth (peer-UID and connection token); that a
//! `run` and the single `python_sandbox` MCP tool return an equivalent result over the
//! socket; that a `dry_run` plans with no egress; that health answers without auth; and
//! that a wrong token is refused before any run.
#![cfg(all(feature = "integration", unix))]

use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use faradayd::broker::{BrokerCall, BrokerError};
use faradayd::config::{Config, CredentialMode};
use faradayd::controller::{CapabilityMinter, IdTokenSink, Interactor, SandboxController};
use faradayd::endpoint::Daemon;
use faradayd::health::HealthCheck;
use faradayd::interaction::{InteractionError, InteractionOutcome};
use faradayd::policy::PolicyEngine;
use faradayd::runtime::{Limits, SandboxRuntime};
use faradayd::session::SessionManager;
use faradayd::types::{
    CapabilityHandle, ClientIdentity, InteractionRequired, Params, Principal, ResolvedCapability,
    UntrustedResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");

const MANIFEST: &str = r#"{"capabilities":{
    "tickets":{"provider":"github","host":"tickets.example.com",
        "pathAllow":["^/api/v2/tickets($|/.*)"],"methods":["GET"]}
}}"#;

// ---- stub controller dependencies (same shape as the Phase-8 controller harness) ----

struct StubInteractor;
impl Interactor for StubInteractor {
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
                        subject: "u-1".into(),
                        issuer: "https://idp.example".into(),
                        acr: None,
                        amr: vec![],
                        auth_time: None,
                    },
                    id_token: "id-tok".into(),
                    access_token: "access-tok".into(),
                })
            }
        })
    }
}

struct StubBroker {
    body: Vec<u8>,
}
impl CapabilityMinter for StubBroker {
    fn mint_caps(
        &self,
        _p: &Principal,
        _run_id: &str,
        _client_label: &str,
        caps: &[ResolvedCapability],
    ) -> Vec<CapabilityHandle> {
        caps.iter()
            .enumerate()
            .map(|(i, c)| CapabilityHandle {
                cap_id: [i as u8; 16],
                capability_id: c.id.clone(),
                expires_at: i64::MAX,
            })
            .collect()
    }
}
impl BrokerCall for StubBroker {
    fn call_boxed<'a>(
        &'a self,
        _cap_id: &'a [u8; 16],
        _verb: &'a str,
        _path: &'a str,
        _params: &'a Params,
        _body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<UntrustedResponse, BrokerError>> + Send + 'a>> {
        let body = self.body.clone();
        Box::pin(async move {
            Ok(UntrustedResponse {
                untrusted: true,
                status: 200,
                content_type: "application/json".into(),
                body,
                truncated: false,
            })
        })
    }
}

struct StubSink;
impl IdTokenSink for StubSink {
    fn set_id_token(&self, _id_token: String) {}
    fn set_access_token(&self, _access_token: String) {}
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
        audit_hmac_key: vec![1, 2, 3, 4],
        log_level: "info".into(),
        credential_mode: CredentialMode::Mock,
    }
}

fn controller() -> Arc<SandboxController> {
    let broker = Arc::new(StubBroker {
        body: b"{\"data\":\"ok\"}".to_vec(),
    });
    let runtime = Arc::new(
        SandboxRuntime::new(
            &SandboxRuntime::digest_of(GUEST),
            GUEST,
            broker.clone() as Arc<dyn BrokerCall>,
        )
        .expect("runtime builds"),
    );
    Arc::new(SandboxController::new(
        Arc::new(PolicyEngine::load(MANIFEST, None, &|_, _| true).unwrap()),
        Arc::new(StubInteractor),
        broker as Arc<dyn CapabilityMinter>,
        runtime,
        Arc::new(SessionManager::new(50)),
        Arc::new(StubSink),
        "https://idp.example".to_string(),
        Limits {
            fuel: Some(u64::MAX),
            epoch_deadline: Duration::from_secs(60),
            ..Limits::default()
        },
    ))
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

fn run_req(dry_run: bool) -> serde_json::Value {
    serde_json::json!({
        "code": "print(api.tickets.get('/api/v2/tickets/42').decode())",
        "requestedCapabilities": ["tickets"],
        "workspaceId": "ws",
        "dryRun": dry_run
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c14_connect_auth_run_mcp_dryrun_health_and_reject() {
    let dir = std::env::temp_dir().join(format!("pysd-ep-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("d.sock").to_string_lossy().into_owned();
    let token_path = dir.join("d.token").to_string_lossy().into_owned();

    let daemon = Daemon::bind(
        test_config(socket.clone(), token_path.clone()),
        controller(),
        Arc::new(HealthCheck::new("https://idp.example".into(), None)),
    )
    .expect("daemon binds");
    let token = daemon.connection_token().to_string();

    // Boot/perms checks (folded in from the Phase-0 boot gate).
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600,
        "socket is 0600"
    );
    assert_eq!(
        std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
        0o600,
        "token file is 0600"
    );

    tokio::spawn(async move {
        let _ = daemon.serve().await;
    });
    // Give the listener a moment.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 1) Health answers without authentication.
    {
        let mut s = UnixStream::connect(&socket).await.unwrap();
        send(&mut s, serde_json::json!({ "type": "health" })).await;
        let r = recv(&mut s).await;
        assert_eq!(r["live"], serde_json::json!(true));
    }

    // 2) A wrong token is refused before any run.
    {
        let mut s = UnixStream::connect(&socket).await.unwrap();
        send(
            &mut s,
            serde_json::json!({ "type": "connect", "clientLabel": "vscode", "token": "WRONG", "workspaceId": "ws" }),
        )
        .await;
        let r = recv(&mut s).await;
        assert_eq!(
            r["code"],
            serde_json::json!("CLIENT_TOKEN_DENIED"),
            "got {r}"
        );
    }

    // 3) Authenticated connection: connect → run → MCP tool → dry_run.
    let mut s = UnixStream::connect(&socket).await.unwrap();
    send(
        &mut s,
        serde_json::json!({ "type": "connect", "clientLabel": "vscode", "token": token, "workspaceId": "ws" }),
    )
    .await;
    assert_eq!(recv(&mut s).await["type"], serde_json::json!("connected"));

    // native-RPC run → result with the sanitised body, no token
    send(
        &mut s,
        serde_json::json!({ "type": "run", "request": run_req(false) }),
    )
    .await;
    let native = recv(&mut s).await;
    assert_eq!(native["type"], serde_json::json!("result"), "got {native}");
    let native_stdout = native["result"]["stdout"].as_str().unwrap_or("");
    assert!(
        native_stdout.contains("{\"data\":\"ok\"}"),
        "stdout={native_stdout:?}"
    );
    assert!(!native_stdout.contains("id-tok"), "no token over the wire");

    // the single MCP tool yields an equivalent result
    send(
        &mut s,
        serde_json::json!({ "type": "mcp", "arguments": run_req(false) }),
    )
    .await;
    let mcp = recv(&mut s).await;
    assert_eq!(mcp["type"], serde_json::json!("result"), "got {mcp}");
    assert_eq!(
        mcp["result"]["stdout"], native["result"]["stdout"],
        "MCP equivalent to native RPC"
    );

    // dry_run → plan only, no egress
    send(
        &mut s,
        serde_json::json!({ "type": "run", "request": run_req(true) }),
    )
    .await;
    let dry = recv(&mut s).await;
    assert_eq!(dry["type"], serde_json::json!("dryRun"), "got {dry}");
    assert_eq!(dry["result"]["plannedCalls"].as_array().unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c14_input_validation_and_graceful_drain() {
    let dir = std::env::temp_dir().join(format!("pysd-drain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("d.sock").to_string_lossy().into_owned();
    let token_path = dir.join("d.token").to_string_lossy().into_owned();
    let daemon = Daemon::bind(
        test_config(socket.clone(), token_path.clone()),
        controller(),
        Arc::new(HealthCheck::new("https://idp.example".into(), None)),
    )
    .expect("daemon binds");
    let token = daemon.connection_token().to_string();
    assert!(
        std::path::Path::new(&token_path).exists(),
        "bind wrote the connection token"
    );

    // Shutdown fires ~1.5s in — while a ~10s real run is in-flight — so serve must DRAIN; then
    // serve_and_cleanup removes the connection token (ADR-024) — the FU-004 graceful-shutdown path
    // both platforms route through (`main` builds the SIGTERM / console-control trigger).
    let serve = {
        let token_path = token_path.clone();
        tokio::spawn(async move {
            faradayd::endpoint::serve_and_cleanup(
                daemon,
                async { tokio::time::sleep(Duration::from_millis(1500)).await },
                &token_path,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut s = UnixStream::connect(&socket).await.unwrap();
    send(
        &mut s,
        serde_json::json!({ "type": "connect", "clientLabel": "vscode", "token": token, "workspaceId": "ws" }),
    )
    .await;
    assert_eq!(recv(&mut s).await["type"], serde_json::json!("connected"));

    // XC9 — an empty-code request is rejected (VAL_ERR).
    send(
        &mut s,
        serde_json::json!({ "type": "run", "request": {
            "code": "   ", "requestedCapabilities": ["tickets"], "workspaceId": "ws", "dryRun": false
        }}),
    )
    .await;
    assert_eq!(recv(&mut s).await["code"], serde_json::json!("VAL_ERR"));

    // XC10 — start a real run; the shutdown fires mid-run; it must complete (drained).
    send(
        &mut s,
        serde_json::json!({ "type": "run", "request": run_req(false) }),
    )
    .await;
    let r = recv(&mut s).await;
    assert_eq!(
        r["type"],
        serde_json::json!("result"),
        "in-flight run drained: {r}"
    );
    assert!(r["result"]["stdout"]
        .as_str()
        .unwrap_or("")
        .contains("{\"data\":\"ok\"}"));

    // serve_with_shutdown returns once the in-flight run has drained.
    let joined = tokio::time::timeout(Duration::from_secs(15), serve).await;
    assert!(joined.is_ok(), "serve drained and returned");

    // FU-004 — the connection token is removed once serve drains and returns (the cleanup the
    // Windows path previously skipped by never returning from `serve()`).
    assert!(
        !std::path::Path::new(&token_path).exists(),
        "connection token removed on graceful shutdown"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

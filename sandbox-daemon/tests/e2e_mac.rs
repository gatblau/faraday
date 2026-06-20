//! Plan 04 Phase 4 gate — the macOS demo acceptance (the M7 developer-machine chain).
//! Drives the full path **MCP client → `faradayd mcp-stdio` → daemon → IdentityBroker
//! → dummy REST API** against a real `go-httpbin` container, and confirms the demo's
//! sample policy loads. The real Dex browser sign-in is the manual step (RISK-004),
//! documented in `examples/demo/README.md`; the loopback sign-in mechanism is covered by
//! `tests/signin.rs` and the front door by `tests/mcp.rs`.
#![cfg(all(feature = "integration", target_os = "macos"))]

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, Command};

const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");
const HTTPBIN_PORT: u16 = 8080;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn demo_policy_is_valid() {
    let path = repo_root().join("examples/demo/pysandbox.policy.json");
    let json = std::fs::read_to_string(&path).expect("read demo policy");
    PolicyEngine::load(&json, None, &|_, _| true).expect("demo policy loads cleanly");
}

// ---- daemon stand-ins (mirror tests/mcp.rs); direct-provider credential injected ----

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
                        subject: "00u-demo".into(),
                        issuer: "https://idp.example".into(),
                        acr: None,
                        amr: vec![],
                        auth_time: None,
                    },
                    id_token: "demo-id-token".into(),
                    access_token: "demo-access-token".into(),
                })
            }
        })
    }
}

struct DemoCreds;
impl CredentialSource for DemoCreds {
    fn id_token(&self) -> Option<String> {
        Some("demo-id-token".into())
    }
    fn access_token(&self) -> Option<String> {
        // The broker forwards this bearer on the pass-through call; the sandbox never sees it.
        Some("demo-direct-token".into())
    }
}
impl IdTokenSink for DemoCreds {
    fn set_id_token(&self, _id_token: String) {}
    fn set_access_token(&self, _access_token: String) {}
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

async fn rpc(
    cin: &mut ChildStdin,
    cout: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    id: i64,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let req = serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    cin.write_all(line.as_bytes()).await.unwrap();
    cin.flush().await.unwrap();
    let resp = cout.next_line().await.unwrap().expect("mcp response");
    serde_json::from_str(&resp).unwrap()
}

/// Shut the child down gracefully instead of SIGKILL-ing it. Closing stdin makes
/// the `mcp-stdio` read loop (src/mcp.rs) see EOF and return, which lets the child
/// run its normal exit path — the LLVM coverage runtime only flushes its `.profraw`
/// on a clean exit, never on a kill. Falls back to a kill if it does not exit.
async fn shutdown_gracefully(mut child: tokio::process::Child, cin: ChildStdin) {
    drop(cin); // close the write half → mcp-stdio sees EOF and returns
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn demo_chain_mcp_to_dummy_api() {
    // The dummy REST API: go-httpbin (GET /json → a fixed JSON document).
    let httpbin = GenericImage::new("mccutchen/go-httpbin", "v2.15.0")
        .with_exposed_port(HTTPBIN_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr("listening"))
        .start()
        .await
        .expect("start go-httpbin");
    let port = httpbin
        .get_host_port_ipv4(HTTPBIN_PORT.tcp())
        .await
        .expect("httpbin port");
    let host = format!("127.0.0.1:{port}");

    // A "dummy" pass-through capability pointing at the dummy API.
    let manifest = format!(
        r#"{{"capabilities":{{
            "dummy":{{"provider":"dummy","authMode":"passthrough","host":"{host}",
                "pathAllow":["^/json$"],"methods":["GET"]}}
        }}}}"#
    );
    let policy = Arc::new(PolicyEngine::load(&manifest, None, &|_, _| true).unwrap());
    let audit = Arc::new(AuditLogger::new(
        vec![9, 9, 9],
        Box::new(VecSink(Arc::new(Mutex::new(Vec::new())))),
    ));
    let obo = Arc::new(OboClient::new("http://unused".into()).unwrap());
    let downstream =
        Arc::new(DownstreamClient::new_plaintext(1_048_576, Duration::from_secs(10)).unwrap());
    let broker = Arc::new(IdentityBroker::new(
        policy.clone(),
        audit,
        obo,
        downstream,
        Arc::new(DemoCreds) as Arc<dyn CredentialSource>,
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
        Arc::new(DemoCreds) as Arc<dyn IdTokenSink>,
        "https://idp.example".to_string(),
        Limits {
            fuel: Some(u64::MAX),
            epoch_deadline: Duration::from_secs(60),
            ..Limits::default()
        },
    ));

    let dir = std::env::temp_dir().join(format!("pysd-mac-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("d.sock").to_string_lossy().into_owned();
    let token_path = dir.join("d.token").to_string_lossy().into_owned();
    let daemon = Daemon::bind(
        test_config(socket.clone(), token_path.clone()),
        controller,
        Arc::new(HealthCheck::new("https://idp.example".into(), None)),
    )
    .expect("daemon binds");
    tokio::spawn(async move {
        let _ = daemon.serve().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Drive the real mcp-stdio front door, as Claude Code would.
    let mut child = Command::new(env!("CARGO_BIN_EXE_faradayd"))
        .arg("mcp-stdio")
        .env("PYS_SOCKET_PATH", &socket)
        .env("PYS_CONNECTION_TOKEN_PATH", &token_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn mcp-stdio");
    let mut cin = child.stdin.take().unwrap();
    let mut cout = BufReader::new(child.stdout.take().unwrap()).lines();

    let _ = rpc(
        &mut cin,
        &mut cout,
        1,
        "initialize",
        serde_json::json!({ "protocolVersion": "2024-11-05", "capabilities": {} }),
    )
    .await;
    let call = rpc(
        &mut cin,
        &mut cout,
        2,
        "tools/call",
        serde_json::json!({
            "name": "python_sandbox",
            "arguments": {
                "code": "print(api.dummy.get('/json').decode())",
                "requestedCapabilities": ["dummy"]
            }
        }),
    )
    .await;

    let result = &call["result"];
    assert_eq!(
        result["isError"],
        serde_json::json!(false),
        "tool call: {call}"
    );
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("slideshow"),
        "dummy API JSON returned through the sandbox: {text}"
    );
    // Token custody: no credential of any kind reaches the MCP client / the sandbox output.
    assert!(
        !text.contains("demo-direct-token") && !text.contains("demo-id-token"),
        "no token in the result: {text}"
    );

    shutdown_gracefully(child, cin).await;
    let _ = std::fs::remove_dir_all(&dir);
}

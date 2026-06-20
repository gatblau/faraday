//! Plan 04 Phase 1 gate (C16 MCP front door, ADR-028). Spawns the **real
//! `faradayd mcp-stdio` sub-mode** as a child process and drives it with an MCP
//! client over stdio (`initialize` / `tools/list` / `tools/call python_sandbox`),
//! against an in-process daemon bound to a real UDS with a stub-obo (mockserver)
//! backend. Proves: exactly one tool is advertised; a tool call relays through the
//! sandbox and returns the brokered body with **no token**; a missing daemon yields
//! a `DAEMON_UNAVAILABLE` tool error.
#![cfg(all(feature = "integration", unix))]

use std::future::Future;
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
const MOCKSERVER_PORT: u16 = 1080;

// ---- daemon test stand-ins (mirror tests/e2e.rs) ----

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
                        subject: "00u-mcp".into(),
                        issuer: "https://idp.example".into(),
                        acr: None,
                        amr: vec![],
                        auth_time: None,
                    },
                    id_token: "mcp-id-token".into(),
                    access_token: "mcp-access-token".into(),
                })
            }
        })
    }
}

struct McpCreds {
    id_token: Mutex<Option<String>>,
}
impl CredentialSource for McpCreds {
    fn id_token(&self) -> Option<String> {
        self.id_token.lock().unwrap().clone()
    }
    fn access_token(&self) -> Option<String> {
        None // this test exercises only the exchange path
    }
}
impl IdTokenSink for McpCreds {
    fn set_id_token(&self, id_token: String) {
        *self.id_token.lock().unwrap() = Some(id_token);
    }
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

// ---- MCP-over-stdio client driving the child `faradayd mcp-stdio` ----

/// Send one JSON-RPC request line and read one response line.
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
    let resp = cout
        .next_line()
        .await
        .unwrap()
        .expect("mcp-stdio response line");
    serde_json::from_str(&resp).unwrap()
}

fn spawn_mcp_stdio(socket: &str, token_path: &str) -> tokio::process::Child {
    Command::new(env!("CARGO_BIN_EXE_faradayd"))
        .arg("mcp-stdio")
        .env("PYS_SOCKET_PATH", socket)
        .env("PYS_CONNECTION_TOKEN_PATH", token_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn faradayd mcp-stdio")
}

/// Shut the child down gracefully instead of SIGKILL-ing it. Closing stdin makes
/// the `mcp-stdio` read loop (src/mcp.rs) see EOF and return, which lets the child
/// run its normal exit path — the LLVM coverage runtime only flushes its `.profraw`
/// on a clean exit, never on a kill. Falls back to a kill if it does not exit.
async fn shutdown_gracefully(mut child: tokio::process::Child, cin: tokio::process::ChildStdin) {
    drop(cin); // close the write half → mcp-stdio sees EOF and returns
    if tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_front_door_lists_one_tool_and_relays_run() {
    let (_ms, base) = start_mockserver().await;
    let admin = reqwest::Client::new();
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
    let creds = Arc::new(McpCreds {
        id_token: Mutex::new(None),
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

    let dir = std::env::temp_dir().join(format!("pysd-mcp-{}", std::process::id()));
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

    // Spawn the REAL mcp-stdio sub-mode and drive it.
    let mut child = spawn_mcp_stdio(&socket, &token_path);
    let mut cin = child.stdin.take().unwrap();
    let mut cout = BufReader::new(child.stdout.take().unwrap()).lines();

    // initialize
    let init = rpc(
        &mut cin,
        &mut cout,
        1,
        "initialize",
        serde_json::json!({ "protocolVersion": "2024-11-05", "capabilities": {} }),
    )
    .await;
    assert_eq!(
        init["result"]["serverInfo"]["name"],
        serde_json::json!("faradayd"),
        "init: {init}"
    );

    // tools/list — exactly one tool, python_sandbox
    let list = rpc(&mut cin, &mut cout, 2, "tools/list", serde_json::json!({})).await;
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 1, "exactly one tool: {list}");
    assert_eq!(tools[0]["name"], serde_json::json!("python_sandbox"));

    // tools/call — relays through the sandbox to the brokered (obo) backend
    let call = rpc(
        &mut cin,
        &mut cout,
        3,
        "tools/call",
        serde_json::json!({
            "name": "python_sandbox",
            "arguments": {
                "code": "print(api.tickets.get('/api/v2/tickets/42').decode())",
                "requestedCapabilities": ["tickets"]
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
    assert!(text.contains("obo-ok"), "brokered body returned: {text}");
    // No token of any kind reaches the MCP client.
    assert!(
        !text.contains("mcp-id-token") && !text.to_lowercase().contains("bearer"),
        "no token in the MCP result: {text}"
    );

    shutdown_gracefully(child, cin).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_front_door_reports_daemon_unavailable() {
    let dir = std::env::temp_dir().join(format!("pysd-mcp-down-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("d.token");
    std::fs::write(&token_path, "dummy-token").unwrap();
    let bogus_socket = dir.join("nope.sock").to_string_lossy().into_owned();

    let mut child = spawn_mcp_stdio(&bogus_socket, &token_path.to_string_lossy());
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
            "arguments": { "code": "print(1)" }
        }),
    )
    .await;
    let result = &call["result"];
    assert_eq!(
        result["isError"],
        serde_json::json!(true),
        "should be a tool error: {call}"
    );
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("DAEMON_UNAVAILABLE"),
        "expected DAEMON_UNAVAILABLE: {text}"
    );

    shutdown_gracefully(child, cin).await;
    let _ = std::fs::remove_dir_all(&dir);
}

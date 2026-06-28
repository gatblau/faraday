//! Phase 5 integration gate: C11 IdentityBroker against a real `mockserver/mockserver`
//! standing in for both the obo-broker (`/v1/exchange`) and a direct provider. Proves
//! OBO routing, direct-token application, capId expiry, step-up surfacing — and that no
//! token ever appears in the returned envelope.
#![cfg(feature = "integration")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use faradayd::audit::{AuditLogger, AuditSink};
use faradayd::broker::{ApiKeyStore, BrokerError, CredentialSource, IdentityBroker};
use faradayd::downstream::DownstreamClient;
use faradayd::mcp_upstream::McpUpstreamClient;
use faradayd::obo::OboClient;
use faradayd::policy::PolicyEngine;
use faradayd::types::{AuditEntry, Principal};
use testcontainers::{core::IntoContainerPort, core::WaitFor, runners::AsyncRunner, GenericImage};

const MOCKSERVER_PORT: u16 = 1080;

struct StubCreds;
impl CredentialSource for StubCreds {
    fn id_token(&self) -> Option<String> {
        Some("the-id-token".into())
    }
    fn access_token(&self) -> Option<String> {
        Some("direct-token".into())
    }
}

struct VecSink(Arc<Mutex<Vec<AuditEntry>>>);
impl AuditSink for VecSink {
    fn emit(&self, e: &AuditEntry) {
        self.0.lock().unwrap().push(e.clone());
    }
}

fn principal() -> Principal {
    Principal {
        subject: "00u-test".into(),
        issuer: "https://idp.example".into(),
        acr: None,
        amr: vec![],
        auth_time: None,
    }
}

async fn start_mockserver() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new("mockserver/mockserver", "5.15.0")
        .with_exposed_port(MOCKSERVER_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("started on port"))
        .start()
        .await
        .expect("start mockserver container");
    let port = container
        .get_host_port_ipv4(MOCKSERVER_PORT.tcp())
        .await
        .expect("mockserver host port");
    (container, format!("http://127.0.0.1:{port}"))
}

async fn put_expectation(http: &reqwest::Client, base: &str, body: serde_json::Value) {
    for attempt in 0..40u32 {
        let r = http
            .put(format!("{base}/mockserver/expectation"))
            .json(&body)
            .send()
            .await;
        match r {
            Ok(resp) if resp.status().is_success() => return,
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
        if attempt == 39 {
            panic!("mockserver expectation API never became ready");
        }
    }
}

async fn reset(http: &reqwest::Client, base: &str) {
    http.put(format!("{base}/mockserver/reset"))
        .send()
        .await
        .expect("mockserver reset");
}

/// Build the shared PolicyEngine + a broker over it, wired to the mockserver.
fn broker(
    base: &str,
    host: &str,
    sink: Arc<Mutex<Vec<AuditEntry>>>,
    ttl: i64,
) -> (IdentityBroker, PolicyEngine) {
    let manifest = format!(
        r#"{{"capabilities":{{
            "internal.tickets":{{"provider":"rfc8693","authMode":"exchange","host":"tickets.example.com",
                "pathAllow":["^/api/v2/tickets($|/.*)"],"methods":["GET"]}},
            "gh.repos":{{"provider":"github","authMode":"passthrough","host":"{host}",
                "pathAllow":["^/api/v3/repos($|/.*)"],"methods":["GET"]}}
        }}}}"#
    );
    let policy = Arc::new(PolicyEngine::load(&manifest, None, &|_, _| true).unwrap());
    let lookup = PolicyEngine::load(&manifest, None, &|_, _| true).unwrap();
    let audit = Arc::new(AuditLogger::new(b"k".to_vec(), Box::new(VecSink(sink))));
    let obo = Arc::new(OboClient::new(base.to_string()).unwrap());
    let downstream =
        Arc::new(DownstreamClient::new_plaintext(1_048_576, Duration::from_secs(5)).unwrap());
    let creds: Arc<dyn CredentialSource> = Arc::new(StubCreds);
    let b = IdentityBroker::new_with_ttl(
        policy,
        audit,
        obo,
        downstream,
        creds,
        1_048_576,
        ttl,
        Arc::new(std::collections::HashMap::<String, String>::new())
            as Arc<dyn faradayd::broker::ApiKeyStore>,
    );
    (b, lookup)
}

#[tokio::test]
async fn c11_routes_exchange_and_direct_expiry_and_stepup() {
    let (_guard, base) = start_mockserver().await;
    let host = base.trim_start_matches("http://").to_string();
    let admin = reqwest::Client::new();
    let captured = Arc::new(Mutex::new(Vec::new()));

    // /v1/exchange (OBO) → sanitised JSON; /api/v3/repos (direct) requires the bearer.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "POST", "path": "/v1/exchange"},
            "httpResponse": {"statusCode": 200, "headers": {"content-type": ["application/json"]},
                "body": "{\"data\":\"ok\"}"}
        }),
    )
    .await;
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/api/v3/repos",
                "headers": {"Authorization": ["Bearer direct-token"]}},
            "httpResponse": {"statusCode": 200, "body": "repo-data"}
        }),
    )
    .await;

    let (b, lookup) = broker(&base, &host, captured.clone(), 300);
    let exchange_cap = lookup.resolve("internal.tickets").unwrap().clone();
    let direct_cap = lookup.resolve("gh.repos").unwrap().clone();
    let handles = b.mint_caps(
        &principal(),
        "run-test-1",
        "cli-test",
        &[exchange_cap, direct_cap],
    );
    assert_eq!(handles.len(), 2);

    // 1) Exchange capability proxied via the stub obo-broker → sanitised, no token.
    let r = b
        .call(
            &handles[0].cap_id,
            "GET",
            "/api/v2/tickets/42",
            &vec![],
            b"",
        )
        .await
        .expect("exchange call");
    assert!(r.untrusted);
    assert_eq!(r.body, b"{\"data\":\"ok\"}");
    let body_str = String::from_utf8_lossy(&r.body);
    assert!(
        !body_str.contains("the-id-token"),
        "no id_token in the result"
    );

    // 2) Direct capability applies the held bearer (200 only if the header arrived);
    //    the token never appears in the sanitised result.
    let r = b
        .call(&handles[1].cap_id, "GET", "/api/v3/repos", &vec![], b"")
        .await
        .expect("direct call");
    assert_eq!(r.status, 200, "direct call must succeed (bearer applied)");
    assert_eq!(r.body, b"repo-data");
    assert!(
        !String::from_utf8_lossy(&r.body).contains("direct-token"),
        "no credential in the result"
    );

    // Audit recorded both calls; AuditEntry structurally carries no token/body.
    assert_eq!(captured.lock().unwrap().len(), 2);
    // …and each call is attributed to its run: the server-minted run_id and the
    // client-asserted label bound at mint time reach the audit entry (Finding 2 fix).
    {
        let entries = captured.lock().unwrap();
        for e in entries.iter() {
            assert_eq!(e.run_id, "run-test-1", "audit entry carries the run_id");
            assert_eq!(
                e.client_label, "cli-test",
                "audit entry carries the client label"
            );
        }
    }

    // 3) Step-up surfaced from OBO (not auto-asserted).
    reset(&admin, &base).await;
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "POST", "path": "/v1/exchange"},
            "httpResponse": {"statusCode": 401, "headers": {"WWW-Authenticate":
                ["Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:loa:high\""]}}
        }),
    )
    .await;
    let err = b
        .call(
            &handles[0].cap_id,
            "GET",
            "/api/v2/tickets/42",
            &vec![],
            b"",
        )
        .await
        .expect_err("step-up");
    assert_eq!(err.code(), "STEP_UP_REQUIRED");

    // 4) Expired capId → CAP_INVALID, no outbound call (broker returns before routing).
    let (expired_broker, lookup2) = broker(&base, &host, captured.clone(), -1);
    let cap = lookup2.resolve("internal.tickets").unwrap().clone();
    let expired = expired_broker.mint_caps(&principal(), "run-test-1", "cli-test", &[cap]);
    let err = expired_broker
        .call(
            &expired[0].cap_id,
            "GET",
            "/api/v2/tickets/42",
            &vec![],
            b"",
        )
        .await
        .expect_err("expired capId");
    assert_eq!(err, BrokerError::CapInvalid);
}

// ---- C11 call_tool: MCP routing (ADR-034) ----

/// Build a broker over an mcp-only manifest, wired to the outbound MCP client (C17).
fn mcp_broker(
    server_url: &str,
    sink: Arc<Mutex<Vec<AuditEntry>>>,
) -> (IdentityBroker, PolicyEngine) {
    let manifest = format!(
        r#"{{"capabilities":{{
            "tickets.mcp":{{"kind":"mcp","authMode":"none","serverUrl":"{server_url}","toolAllow":["search_tickets"]}}
        }}}}"#
    );
    let policy = Arc::new(PolicyEngine::load(&manifest, None, &|_, _| true).unwrap());
    let lookup = PolicyEngine::load(&manifest, None, &|_, _| true).unwrap();
    let audit = Arc::new(AuditLogger::new(b"k".to_vec(), Box::new(VecSink(sink))));
    let obo = Arc::new(OboClient::new("http://127.0.0.1:1".to_string()).unwrap());
    let downstream =
        Arc::new(DownstreamClient::new_plaintext(1_048_576, Duration::from_secs(5)).unwrap());
    let creds: Arc<dyn CredentialSource> = Arc::new(StubCreds);
    let mcp = Arc::new(McpUpstreamClient::new(1_048_576, Duration::from_secs(2), true).unwrap());
    let b = IdentityBroker::new(
        policy,
        audit,
        obo,
        downstream,
        creds,
        1_048_576,
        Arc::new(std::collections::HashMap::<String, String>::new()) as Arc<dyn ApiKeyStore>,
    )
    .with_mcp_upstream(mcp);
    (b, lookup)
}

#[tokio::test]
async fn c11_call_tool_routes_mcp_and_denies_unlisted_tool() {
    let (_guard, base) = start_mockserver().await;
    let admin = reqwest::Client::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let server_url = format!("{base}/mcp");
    let (broker, lookup) = mcp_broker(&server_url, captured.clone());

    let cap = lookup.resolve("tickets.mcp").unwrap().clone();
    let handles = broker.mint_caps(&principal(), "run-mcp-1", "cli", &[cap]);
    let cap_id = handles[0].cap_id;

    // Program the MCP handshake: initialize → result; initialized → 202; tools/call → result.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method":"POST","path":"/mcp","body":{"type":"JSON","json":{"method":"initialize"},"matchType":"ONLY_MATCHING_FIELDS"}},
            "httpResponse": {"statusCode":200,"headers":{"content-type":["application/json"]},
                "body":"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{}}}"}
        }),
    )
    .await;
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method":"POST","path":"/mcp","body":{"type":"JSON","json":{"method":"notifications/initialized"},"matchType":"ONLY_MATCHING_FIELDS"}},
            "httpResponse": {"statusCode":202}
        }),
    )
    .await;
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method":"POST","path":"/mcp","body":{"type":"JSON","json":{"method":"tools/call"},"matchType":"ONLY_MATCHING_FIELDS"}},
            "httpResponse": {"statusCode":200,"headers":{"content-type":["application/json"]},
                "body":"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}"}
        }),
    )
    .await;

    // Happy: the allowed tool routes to C17 and returns an untrusted envelope, no token.
    let r = broker
        .call_tool(&cap_id, "search_tickets", &serde_json::json!({"q":"open"}))
        .await
        .expect("mcp call_tool");
    assert!(r.untrusted);
    assert!(!r.is_error);
    assert_eq!(r.parts.len(), 1);

    // An audit entry was written with MCP semantics (method = mcp.tools/call, path = tool).
    {
        let entries = captured.lock().unwrap();
        assert!(entries
            .iter()
            .any(|e| e.method == "mcp.tools/call" && e.path == "search_tickets"));
    }

    // A tool not in toolAllow is denied before any network call (C4 authorise_tool).
    let err = broker
        .call_tool(&cap_id, "delete_ticket", &serde_json::json!({}))
        .await
        .expect_err("tool not allowed");
    assert_eq!(err.code(), "MCP_TOOL_DENIED");
}

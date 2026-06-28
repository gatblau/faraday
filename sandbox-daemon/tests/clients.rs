//! Phase 3 integration gate: C9 OboClient + C10 DownstreamClient against a real
//! `mockserver/mockserver` brought up via testcontainers. No OIDC here (that is C8,
//! Phase 4) — both clients speak plain HTTP to the stub.
#![cfg(feature = "integration")]

use std::time::Duration;

use faradayd::downstream::DownstreamClient;
use faradayd::mcp_upstream::McpUpstreamClient;
use faradayd::obo::{OboClient, OboError};
use faradayd::types::{AuthMode, CapabilityKind, ResolvedCapability};
use testcontainers::{core::IntoContainerPort, core::WaitFor, runners::AsyncRunner, GenericImage};

const MOCKSERVER_IMAGE: &str = "mockserver/mockserver";
const MOCKSERVER_TAG: &str = "5.15.0";
const MOCKSERVER_PORT: u16 = 1080;

/// A minimal `ResolvedCapability` — `do_call` only reads `host`; policy checks (C4)
/// are exercised elsewhere.
fn cap(host: &str) -> ResolvedCapability {
    ResolvedCapability {
        id: "internal.tickets".into(),
        provider: "github".into(),
        audience: None,
        scopes: vec![],
        host: host.into(),
        path_allow: vec![],
        methods: vec!["GET".into()],
        require_step_up: false,
        auth_mode: AuthMode::Passthrough,
        allow_write: false,
        secret_ref: None,
        key_placement: None,
        kind: CapabilityKind::Rest,
        server_url: None,
        tool_allow: vec![],
    }
}

/// A minimal MCP-kind `ResolvedCapability` — `call_tool` reads `server_url`/`tool_allow`.
fn mcp_cap(server_url: &str) -> ResolvedCapability {
    ResolvedCapability {
        id: "tickets.mcp".into(),
        provider: "github".into(),
        audience: None,
        scopes: vec![],
        host: String::new(),
        path_allow: vec![],
        methods: vec![],
        require_step_up: false,
        auth_mode: AuthMode::Passthrough,
        allow_write: false,
        secret_ref: None,
        key_placement: None,
        kind: CapabilityKind::Mcp,
        server_url: Some(server_url.into()),
        tool_allow: vec!["search_tickets".into(), "get_ticket".into()],
    }
}

/// Start mockserver and return (container guard, base URL). The guard must be kept
/// alive for the duration of the test.
async fn start_mockserver() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new(MOCKSERVER_IMAGE, MOCKSERVER_TAG)
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

/// Program one mockserver expectation, retrying until the control API is live.
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

/// Clear all programmed expectations between sub-cases.
async fn reset(http: &reqwest::Client, base: &str) {
    http.put(format!("{base}/mockserver/reset"))
        .send()
        .await
        .expect("mockserver reset");
}

// ---- C9 OboClient ----

#[tokio::test]
async fn c9_happy_stepup_and_unavailable() {
    let (_guard, base) = start_mockserver().await;
    let admin = reqwest::Client::new();
    let cap = cap("ignored-for-obo");

    // Happy: 2xx → sanitized JSON, untrusted envelope, no token.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "POST", "path": "/v1/exchange"},
            "httpResponse": {
                "statusCode": 200,
                "headers": {"content-type": ["application/json"]},
                "body": "{\"data\":\"ok\"}"
            }
        }),
    )
    .await;

    let client = OboClient::new(base.clone()).unwrap();
    let resp = client
        .exchange(
            "the-id-token",
            &cap,
            "GET",
            "/api/v2/tickets/42",
            &vec![],
            b"",
        )
        .await
        .expect("happy exchange");
    assert!(resp.untrusted);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"{\"data\":\"ok\"}");
    assert!(
        !String::from_utf8_lossy(&resp.body).contains("the-id-token"),
        "no token may appear in the returned envelope"
    );

    // Step-up: 401 insufficient_user_authentication → STEP_UP_REQUIRED{acr_values}.
    reset(&admin, &base).await;
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "POST", "path": "/v1/exchange"},
            "httpResponse": {
                "statusCode": 401,
                "headers": {
                    "WWW-Authenticate": [
                        "Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:acme:loa:high urn:acme:mfa\""
                    ]
                }
            }
        }),
    )
    .await;

    let err = client
        .exchange(
            "the-id-token",
            &cap,
            "GET",
            "/api/v2/tickets/42",
            &vec![],
            b"",
        )
        .await
        .expect_err("step-up challenge");
    assert_eq!(err.code(), "STEP_UP_REQUIRED");
    match err {
        OboError::StepUpRequired { acr_values, .. } => {
            assert_eq!(acr_values, vec!["urn:acme:loa:high", "urn:acme:mfa"]);
        }
        other => panic!("expected StepUpRequired, got {other:?}"),
    }

    // Unavailable: backend down (dead port) → OBO_UNAVAILABLE.
    let dead = OboClient::new("http://127.0.0.1:1".into()).unwrap();
    let err = dead
        .exchange("the-id-token", &cap, "GET", "/x", &vec![], b"")
        .await
        .expect_err("unreachable backend");
    assert_eq!(err, OboError::Unavailable);
    assert_eq!(err.code(), "OBO_UNAVAILABLE");
}

// ---- C10 DownstreamClient ----

#[tokio::test]
async fn c10_happy_redirect_timeout_and_cap() {
    let (_guard, base) = start_mockserver().await;
    let admin = reqwest::Client::new();
    // base is http://127.0.0.1:<port>; cap.host carries host:port for plaintext mode.
    let host = base.trim_start_matches("http://").to_string();
    let cap = cap(&host);

    let client = DownstreamClient::new_plaintext(1024, Duration::from_secs(1)).unwrap();
    let bearer = |req: &mut reqwest::Request| {
        req.headers_mut().insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer downstream-token"),
        );
    };

    // Happy GET.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/api/v2/tickets/42"},
            "httpResponse": {"statusCode": 200, "body": "hello"}
        }),
    )
    .await;
    let r = client
        .do_call(&cap, "GET", "/api/v2/tickets/42", &vec![], b"", bearer)
        .await
        .expect("happy GET");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"hello");
    assert!(!r.truncated);

    // Cross-origin 302 returned as-is (redirect not followed → Authorization never
    // re-sent to the other host).
    reset(&admin, &base).await;
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/redir"},
            "httpResponse": {
                "statusCode": 302,
                "headers": {"Location": ["https://other.example/elsewhere"]}
            }
        }),
    )
    .await;
    let r = client
        .do_call(&cap, "GET", "/redir", &vec![], b"", bearer)
        .await
        .expect("redirect call");
    assert_eq!(
        r.status, 302,
        "the 302 must be returned as-is, not followed"
    );

    // Size cap: a body larger than max_bytes is truncated and flagged.
    reset(&admin, &base).await;
    let big = "x".repeat(4096);
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/big"},
            "httpResponse": {"statusCode": 200, "body": big}
        }),
    )
    .await;
    let r = client
        .do_call(&cap, "GET", "/big", &vec![], b"", bearer)
        .await
        .expect("oversize call");
    assert!(r.truncated, "oversize body must be flagged truncated");
    assert_eq!(r.body.len(), 1024, "body must be capped at max_bytes");

    // Timeout: response delayed past the per-call timeout → DOWNSTREAM_TIMEOUT.
    reset(&admin, &base).await;
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/slow"},
            "httpResponse": {
                "statusCode": 200,
                "body": "slow",
                "delay": {"timeUnit": "SECONDS", "value": 3}
            }
        }),
    )
    .await;
    let err = client
        .do_call(&cap, "GET", "/slow", &vec![], b"", bearer)
        .await
        .expect_err("timeout");
    assert_eq!(err.code(), "DOWNSTREAM_TIMEOUT");
}

// ---- C17 McpUpstreamClient (ADR-034) ----

#[tokio::test]
async fn c17_happy_call_unreachable_and_remote_refused() {
    let (_guard, base) = start_mockserver().await;
    let admin = reqwest::Client::new();
    // base is http://127.0.0.1:<port>; the MCP endpoint is /mcp on the loopback stub.
    let server_url = format!("{base}/mcp");
    let cap = mcp_cap(&server_url);

    // allow_plaintext_loopback = true so the 127.0.0.1 stub is reachable over http (ADR-032).
    let client = McpUpstreamClient::new(65536, Duration::from_secs(1), true).unwrap();
    let bearer = |req: &mut reqwest::Request| {
        req.headers_mut().insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_static("Bearer downstream-token"),
        );
    };

    // initialize → a well-formed JSON-RPC result + a session id header.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {
                "method": "POST",
                "path": "/mcp",
                "body": {"type": "JSON", "json": {"method": "initialize"}, "matchType": "ONLY_MATCHING_FIELDS"}
            },
            "httpResponse": {
                "statusCode": 200,
                "headers": {"content-type": ["application/json"], "Mcp-Session-Id": ["sess-1"]},
                "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{}}}"
            }
        }),
    )
    .await;
    // notifications/initialized → 202 Accepted (no body).
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {
                "method": "POST",
                "path": "/mcp",
                "body": {"type": "JSON", "json": {"method": "notifications/initialized"}, "matchType": "ONLY_MATCHING_FIELDS"}
            },
            "httpResponse": {"statusCode": 202}
        }),
    )
    .await;
    // tools/call → a result carrying a text part.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {
                "method": "POST",
                "path": "/mcp",
                "body": {"type": "JSON", "json": {"method": "tools/call"}, "matchType": "ONLY_MATCHING_FIELDS"}
            },
            "httpResponse": {
                "statusCode": 200,
                "headers": {"content-type": ["application/json"]},
                "body": "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}"
            }
        }),
    )
    .await;

    // Happy path: the allowed tool returns an McpToolResult with no token in it.
    let r = client
        .call_tool(
            &cap,
            "search_tickets",
            &serde_json::json!({"q": "open"}),
            bearer,
        )
        .await
        .expect("happy tools/call");
    assert!(!r.is_error);
    assert_eq!(r.content.len(), 1);

    // Unavailable: a dead port → MCP_UPSTREAM_UNAVAILABLE.
    let dead = mcp_cap("http://127.0.0.1:1/mcp");
    let err = client
        .call_tool(&dead, "search_tickets", &serde_json::json!({}), bearer)
        .await
        .expect_err("unreachable server");
    assert_eq!(err.code(), "MCP_UPSTREAM_UNAVAILABLE");

    // Security: a remote http origin is refused before any network attempt — a forwarded
    // credential can never leave the machine in cleartext.
    let remote = mcp_cap("http://mcp.example.com/mcp");
    let err = client
        .call_tool(&remote, "search_tickets", &serde_json::json!({}), bearer)
        .await
        .expect_err("remote http refused");
    assert_eq!(err.code(), "MCP_UPSTREAM_UNAVAILABLE");
}

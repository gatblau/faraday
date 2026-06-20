//! Phase 3 integration gate: C9 OboClient + C10 DownstreamClient against a real
//! `mockserver/mockserver` brought up via testcontainers. No OIDC here (that is C8,
//! Phase 4) — both clients speak plain HTTP to the stub.
#![cfg(feature = "integration")]

use std::time::Duration;

use faradayd::downstream::DownstreamClient;
use faradayd::obo::{OboClient, OboError};
use faradayd::types::{AuthMode, ResolvedCapability};
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

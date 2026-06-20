//! Plan 06 / Phase 2 integration gate (server-mode `api_key`). Drives the real
//! IdentityBroker against a real `mockserver` container and asserts that a per-capability
//! static key is applied at its configured placement (header and query), that the key
//! never appears in the returned envelope, and that an unresolved key fails closed with
//! `API_KEY_UNAVAILABLE` (ADR-036).
#![cfg(all(feature = "integration", unix))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use faradayd::audit::{AuditLogger, AuditSink};
use faradayd::broker::{ApiKeyStore, BrokerError, CredentialSource, IdentityBroker};
use faradayd::downstream::DownstreamClient;
use faradayd::obo::OboClient;
use faradayd::policy::PolicyEngine;
use faradayd::types::{AuditEntry, CapabilityHandle, Principal};
use testcontainers::{core::IntoContainerPort, core::WaitFor, runners::AsyncRunner, GenericImage};

const MOCKSERVER_PORT: u16 = 1080;
const KEY: &str = "secret-xyz";

struct NoCreds;
impl CredentialSource for NoCreds {
    fn id_token(&self) -> Option<String> {
        None
    }
    fn access_token(&self) -> Option<String> {
        None
    }
}

struct VecSink(Arc<Mutex<Vec<AuditEntry>>>);
impl AuditSink for VecSink {
    fn emit(&self, e: &AuditEntry) {
        self.0.lock().unwrap().push(e.clone());
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

fn principal() -> Principal {
    Principal {
        subject: "svc".into(),
        issuer: String::new(),
        acr: None,
        amr: vec![],
        auth_time: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_key_header_and_query_placement_and_missing_key() {
    let (_ms, base) = start_mockserver().await;
    let host = base.trim_start_matches("http://").to_string();
    let admin = reqwest::Client::new();

    // header placement: only matched when X-API-Key carries the key.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/v1/header",
                "headers": {"X-API-Key": [KEY]}},
            "httpResponse": {"statusCode": 200, "body": "header-ok"}
        }),
    )
    .await;
    // query placement: only matched when ?api_key carries the key.
    put_expectation(
        &admin,
        &base,
        serde_json::json!({
            "httpRequest": {"method": "GET", "path": "/v1/query",
                "queryStringParameters": {"api_key": [KEY]}},
            "httpResponse": {"statusCode": 200, "body": "query-ok"}
        }),
    )
    .await;

    let manifest = format!(
        r#"{{"capabilities":{{
            "kheader":{{"authMode":"api_key","host":"{host}","pathAllow":["^/v1/header$"],
                "methods":["GET"],"secretRef":"ref1",
                "keyPlacement":{{"header":{{"name":"X-API-Key"}}}}}},
            "kquery":{{"authMode":"api_key","host":"{host}","pathAllow":["^/v1/query$"],
                "methods":["GET"],"secretRef":"ref1",
                "keyPlacement":{{"query":{{"param":"api_key"}}}}}},
            "kmissing":{{"authMode":"api_key","host":"{host}","pathAllow":["^/v1/missing$"],
                "methods":["GET"],"secretRef":"refX",
                "keyPlacement":{{"header":{{"name":"X-API-Key"}}}}}}
        }}}}"#
    );
    let policy = Arc::new(PolicyEngine::load(&manifest, None, &|_, _| true).unwrap());
    assert_eq!(
        policy.api_key_secret_refs(),
        vec!["ref1".to_string(), "refX".to_string()]
    );

    // The startup-frozen key store resolves only "ref1".
    let mut keymap: HashMap<String, String> = HashMap::new();
    keymap.insert("ref1".into(), KEY.into());
    let api_keys: Arc<dyn ApiKeyStore> = Arc::new(keymap);

    let audit_records = Arc::new(Mutex::new(Vec::new()));
    let audit = Arc::new(AuditLogger::new(
        vec![9, 9, 9],
        Box::new(VecSink(audit_records.clone())),
    ));
    let obo = Arc::new(OboClient::new(base.clone()).unwrap());
    let downstream =
        Arc::new(DownstreamClient::new_plaintext(1_048_576, Duration::from_secs(10)).unwrap());
    let broker = IdentityBroker::new(
        policy.clone(),
        audit,
        obo,
        downstream,
        Arc::new(NoCreds) as Arc<dyn CredentialSource>,
        1_048_576,
        api_keys,
    );

    let caps: Vec<_> = ["kheader", "kquery", "kmissing"]
        .iter()
        .map(|id| policy.resolve(id).unwrap().clone())
        .collect();
    let handles: Vec<CapabilityHandle> = broker.mint_caps(&principal(), "run-1", "agent", &caps);
    let by_id = |id: &str| {
        handles
            .iter()
            .find(|h| h.capability_id == id)
            .unwrap()
            .cap_id
    };

    // header placement → the stub matched X-API-Key=secret-xyz.
    let r = broker
        .call(&by_id("kheader"), "GET", "/v1/header", &vec![], &[])
        .await
        .expect("header call ok");
    assert!(
        String::from_utf8_lossy(&r.body).contains("header-ok"),
        "header placement applied; body={:?}",
        String::from_utf8_lossy(&r.body)
    );

    // query placement → the stub matched ?api_key=secret-xyz.
    let q = broker
        .call(&by_id("kquery"), "GET", "/v1/query", &vec![], &[])
        .await
        .expect("query call ok");
    assert!(
        String::from_utf8_lossy(&q.body).contains("query-ok"),
        "query placement applied; body={:?}",
        String::from_utf8_lossy(&q.body)
    );

    // unresolved key → fail closed.
    let miss = broker
        .call(&by_id("kmissing"), "GET", "/v1/missing", &vec![], &[])
        .await;
    assert_eq!(miss, Err(BrokerError::KeyUnavailable));

    // The key never appears in a returned envelope, and the two successful calls were
    // audited (the audit entry type carries no token/key field).
    assert!(!String::from_utf8_lossy(&r.body).contains(KEY));
    assert!(!String::from_utf8_lossy(&q.body).contains(KEY));
    assert_eq!(audit_records.lock().unwrap().len(), 2, "two calls audited");
}

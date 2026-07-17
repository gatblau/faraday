//! Plan 02 / FU-004 — ADR-040 keychain end-to-end round-trip.
//!
//! Stitches the whole ADR-040 chain as one flow: **enrol** a per-capability `api_key` key
//! via the `credential` CLI core (`run_credential`), **resolve** it from the *same* keychain
//! via `KeychainSecretResolver` + `broker::freeze_api_keys`, and confirm the real
//! `IdentityBroker` **applies** it at the capability's `keyPlacement` to a real `mockserver`
//! container — with the key absent from the returned envelope and the audit trail.
//!
//! The keychain is a local in-memory `KeychainStore` (a materialised stub — the OS keychain
//! is not containerisable; the real-backend smoke is FU-001). The downstream is real.
#![cfg(all(feature = "integration", unix))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use faradayd::audit::{AuditLogger, AuditSink};
use faradayd::broker::{freeze_api_keys, ApiKeyStore, CredentialSource, IdentityBroker};
use faradayd::credential::{run_credential, CredentialCmd};
use faradayd::downstream::DownstreamClient;
use faradayd::keychain::{KeychainError, KeychainSecretResolver, KeychainStore};
use faradayd::obo::OboClient;
use faradayd::policy::PolicyEngine;
use faradayd::types::{AuditEntry, CapabilityHandle, Principal};
use testcontainers::{core::IntoContainerPort, core::WaitFor, runners::AsyncRunner, GenericImage};

const MOCKSERVER_PORT: u16 = 1080;
const KEY: &str = "secret-xyz";
const SVC: &str = "faradayd-e2e";

/// A local in-memory `KeychainStore`, shared (via `Arc`) between the CLI write and the
/// resolver read — the materialised stub for the OS secure store.
type Entries = Mutex<HashMap<(String, String), Vec<u8>>>;

#[derive(Clone, Default)]
struct MemKeychain(Arc<Entries>);

impl KeychainStore for MemKeychain {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(&(service.to_string(), account.to_string()))
            .cloned())
    }
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.0
            .lock()
            .unwrap()
            .insert((service.to_string(), account.to_string()), secret.to_vec());
        Ok(())
    }
    fn delete(&self, service: &str, account: &str) -> Result<bool, KeychainError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .remove(&(service.to_string(), account.to_string()))
            .is_some())
    }
}

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
async fn enrolled_keychain_key_is_resolved_and_applied_end_to_end() {
    let (_ms, base) = start_mockserver().await;
    let host = base.trim_start_matches("http://").to_string();
    let admin = reqwest::Client::new();

    // The mock matches GET /v1/header ONLY when X-API-Key carries the enrolled key.
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

    // One api_key capability whose key comes from the keychain (secretRef = "weather.key").
    let manifest = format!(
        r#"{{"capabilities":{{
            "weather":{{"authMode":"api_key","host":"{host}","pathAllow":["^/v1/header$"],
                "methods":["GET"],"secretRef":"weather.key",
                "keyPlacement":{{"header":{{"name":"X-API-Key"}}}}}}
        }}}}"#
    );
    let policy = Arc::new(PolicyEngine::load(&manifest, None, &|_, _| true).unwrap());

    // 1) ENROL — the CLI core writes the token (a trailing newline is trimmed) to the store.
    let store = MemKeychain::default();
    let out = run_credential(
        CredentialCmd::Set {
            secret_ref: "weather.key".to_string(),
            token: b"secret-xyz\n".to_vec(),
        },
        SVC,
        &policy,
        &store,
    )
    .expect("enrol");
    assert!(!out.join(" ").contains(KEY), "enrol output leaks no key");

    // 2) RESOLVE — the daemon freezes the api_key store from the SAME keychain via the resolver.
    let api_keys: Arc<dyn ApiKeyStore> = Arc::new(
        freeze_api_keys(
            policy.api_key_secret_refs(),
            &KeychainSecretResolver::new(Box::new(store.clone()), SVC),
        )
        .expect("freeze from keychain"),
    );

    // 3) APPLY — the real broker applies the resolved key at the capability's keyPlacement.
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

    let cap = policy.resolve("weather").unwrap().clone();
    let handles: Vec<CapabilityHandle> = broker.mint_caps(&principal(), "run-1", "agent", &[cap]);
    let cap_id = handles[0].cap_id;

    let r = broker
        .call(&cap_id, "GET", "/v1/header", &vec![], &[])
        .await
        .expect("call ok");

    // The mock matched only because the enrolled keychain key was applied as X-API-Key.
    assert!(
        String::from_utf8_lossy(&r.body).contains("header-ok"),
        "enrolled keychain key applied at header placement; body={:?}",
        String::from_utf8_lossy(&r.body)
    );
    // The key never appears in the returned envelope; exactly one call was audited (no key field).
    assert!(!String::from_utf8_lossy(&r.body).contains(KEY));
    assert_eq!(audit_records.lock().unwrap().len(), 1, "one call audited");
}

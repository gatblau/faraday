//! Phase 7 integration gate: C12 SandboxRuntime running the **real RustPython
//! `wasm32-wasip1` guest** in-process on Wasmtime + the deny-by-default WASI subset.
//! Proves: agent Python `api.tickets.get(...)` reaches the broker via the single
//! capability import and the sanitised body returns to the guest (printed → captured
//! stdout, no token); a Python infinite loop is terminated as RUNTIME_LIMIT (epoch);
//! a tiny fuel budget terminates as RUNTIME_LIMIT (fuel); a digest mismatch fails
//! closed (RUNTIME_ARTIFACT_MISMATCH).
#![cfg(feature = "integration")]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use faradayd::broker::{BrokerCall, BrokerError};
use faradayd::runtime::{
    CapabilityBundle, Limits, RuntimeError, SandboxRuntime, RUNTIME_LIMIT_EXIT,
};
use faradayd::types::UntrustedResponse;

/// The pinned RustPython guest artefact (digest in ../CHECKSUMS.txt).
const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");

struct StubBroker {
    body: Vec<u8>,
    status: u16,
}
impl BrokerCall for StubBroker {
    fn call_boxed<'a>(
        &'a self,
        _cap_id: &'a [u8; 16],
        _verb: &'a str,
        _path: &'a str,
        _params: &'a faradayd::types::Params,
        _body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<UntrustedResponse, BrokerError>> + Send + 'a>> {
        let body = self.body.clone();
        let status = self.status;
        Box::pin(async move {
            Ok(UntrustedResponse {
                untrusted: true,
                status,
                content_type: "application/json".into(),
                body,
                truncated: false,
            })
        })
    }
}

/// A broker that always fails the call with a fixed error — exercises the shim's
/// error arm (the real `dummy`/passthrough symptom: an empty body with no signal).
struct FailingBroker {
    error: BrokerError,
}
impl BrokerCall for FailingBroker {
    fn call_boxed<'a>(
        &'a self,
        _cap_id: &'a [u8; 16],
        _verb: &'a str,
        _path: &'a str,
        _params: &'a faradayd::types::Params,
        _body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<UntrustedResponse, BrokerError>> + Send + 'a>> {
        let error = self.error.clone();
        Box::pin(async move { Err(error) })
    }
}

fn bundle() -> CapabilityBundle {
    let mut mappings = HashMap::new();
    mappings.insert("tickets".to_string(), [1u8; 16]);
    CapabilityBundle { mappings }
}

fn runtime(broker: Arc<dyn BrokerCall>) -> SandboxRuntime {
    let digest = SandboxRuntime::digest_of(GUEST);
    SandboxRuntime::new(&digest, GUEST, broker).expect("runtime builds")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c12_real_python_broker_round_trip() {
    let broker = Arc::new(StubBroker {
        body: b"{\"data\":\"ok\"}".to_vec(),
        status: 200,
    });
    let rt = runtime(broker);
    // fuel huge so the (heavy) RustPython init never trips fuel; epoch is the deadline.
    let limits = Limits {
        fuel: Some(u64::MAX),
        epoch_deadline: Duration::from_secs(60),
        ..Limits::default()
    };
    let code = "print(api.tickets.get('/api/v2/tickets/42').decode())";
    let r = rt.run(code, &bundle(), &limits).await;

    assert_eq!(
        r.exit_code, 0,
        "guest exited cleanly; stderr={:?}",
        r.stderr
    );
    assert!(
        r.stdout.contains("{\"data\":\"ok\"}"),
        "guest received the broker body; stdout={:?}",
        r.stdout
    );
    assert!(!r.stdout.contains("token"), "no token reaches the guest");
    assert_eq!(r.api_calls.len(), 1, "one brokered call");
    assert_eq!(r.api_calls[0].method, "GET");
    assert_eq!(r.api_calls[0].path, "/api/v2/tickets/42");
    assert_eq!(r.api_calls[0].status, Some(200));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c12_broker_error_surfaces_on_stderr() {
    // Regression: a failed brokered call must be observable. Before the fix the shim
    // dropped the BrokerError, the guest received empty bytes, and stderr was empty —
    // indistinguishable from a call that legitimately returned an empty body. The call
    // must now record status=None AND surface the broker-error code on stderr.
    let broker = Arc::new(FailingBroker {
        error: BrokerError::NoCredential,
    });
    let rt = runtime(broker);
    let limits = Limits {
        fuel: Some(u64::MAX),
        epoch_deadline: Duration::from_secs(60),
        ..Limits::default()
    };
    let code = "print(api.tickets.get('/api/v2/tickets/42').decode())";
    let r = rt.run(code, &bundle(), &limits).await;

    // The guest still runs cleanly — the failure is the broker's, not a guest trap.
    assert_eq!(
        r.exit_code, 0,
        "guest exited cleanly; stderr={:?}",
        r.stderr
    );
    // The error code reaches stderr (NoCredential → IDP_UNAVAILABLE, broker.rs).
    assert!(
        r.stderr.contains("IDP_UNAVAILABLE"),
        "broker-error code surfaces on stderr; stderr={:?}",
        r.stderr
    );
    // The call is recorded as failed (no status), not silently dropped.
    assert_eq!(r.api_calls.len(), 1, "one attempted call");
    assert_eq!(r.api_calls[0].method, "GET");
    assert_eq!(r.api_calls[0].path, "/api/v2/tickets/42");
    assert_eq!(r.api_calls[0].status, None, "failed call carries no status");
}

#[test]
fn c12_digest_mismatch_fails_closed() {
    let broker = Arc::new(StubBroker {
        body: vec![],
        status: 200,
    });
    match SandboxRuntime::new(&"0".repeat(64), GUEST, broker) {
        Err(e) => {
            assert_eq!(e, RuntimeError::ArtifactMismatch);
            assert_eq!(e.code(), "RUNTIME_ARTIFACT_MISMATCH");
        }
        Ok(_) => panic!("expected ArtifactMismatch for a wrong digest"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c12_python_infinite_loop_hits_epoch_limit() {
    let broker = Arc::new(StubBroker {
        body: vec![],
        status: 200,
    });
    let rt = runtime(broker);
    let limits = Limits {
        fuel: Some(u64::MAX), // epoch must win
        epoch_deadline: Duration::from_millis(500),
        ..Limits::default()
    };
    let r = rt.run("while True:\n    pass\n", &bundle(), &limits).await;
    assert_eq!(r.exit_code, RUNTIME_LIMIT_EXIT, "stdout={:?}", r.stdout);
    assert_eq!(r.stderr, "RUNTIME_LIMIT");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c12_tiny_fuel_hits_fuel_limit() {
    let broker = Arc::new(StubBroker {
        body: vec![],
        status: 200,
    });
    let rt = runtime(broker);
    // A tiny fuel budget is exhausted during interpreter startup → terminated.
    let limits = Limits {
        fuel: Some(1_000_000),
        epoch_deadline: Duration::from_secs(30),
        ..Limits::default()
    };
    let r = rt.run("print('unreached')", &bundle(), &limits).await;
    assert_eq!(r.exit_code, RUNTIME_LIMIT_EXIT, "stdout={:?}", r.stdout);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c12_stdlib_modules_available() {
    // FU-022 Phase 1: the ADR-014 stdlib modules that the corrected wiring makes
    // importable (frozen rustpython-pylib + native rustpython-stdlib modules) run
    // in the real guest on Wasmtime. `re`/`json` remain Phase-2 work and are not
    // asserted here.
    let broker = Arc::new(StubBroker {
        body: vec![],
        status: 200,
    });
    let rt = runtime(broker);
    // Init with the full stdlib is heavy; let epoch be the only deadline (mirrors
    // the broker round-trip test).
    let limits = Limits {
        fuel: Some(u64::MAX),
        epoch_deadline: Duration::from_secs(60),
        ..Limits::default()
    };
    let code = "\
import datetime, base64, collections, itertools
print('DT', datetime.date(2020, 1, 1).isoformat())
print('B64', base64.b64encode(b'hi').decode())
print('CO', collections.OrderedDict([('a', 1)]).get('a'))
print('IT', list(itertools.islice(itertools.count(), 3)))
";
    let r = rt.run(code, &bundle(), &limits).await;
    assert_eq!(
        r.exit_code, 0,
        "guest exited cleanly; stderr={:?}",
        r.stderr
    );
    assert!(
        r.stdout.contains("DT 2020-01-01"),
        "datetime; stdout={:?}",
        r.stdout
    );
    assert!(
        r.stdout.contains("B64 aGk="),
        "base64; stdout={:?}",
        r.stdout
    );
    assert!(
        r.stdout.contains("CO 1"),
        "collections; stdout={:?}",
        r.stdout
    );
    assert!(
        r.stdout.contains("IT [0, 1, 2]"),
        "itertools; stdout={:?}",
        r.stdout
    );
}

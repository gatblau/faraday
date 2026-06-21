//! Phase 8 integration gate: C13 SandboxController orchestration, in-process against
//! the real PolicyEngine + real SandboxRuntime/RustPython guest + SessionManager, with
//! a stub Interactor (consent/sign-in/step-up) and a stub broker (mint + call). Proves
//! the full run pipeline: resolve → consent → dry-run → sign-in/step-up → mint → run →
//! budget → redact, never returning a token.
#![cfg(feature = "integration")]

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use faradayd::broker::{BrokerCall, BrokerError};
use faradayd::controller::{
    CapabilityMinter, ControllerError, IdTokenSink, Interactor, RunOutcome, SandboxController,
};
use faradayd::interaction::{InteractionError, InteractionOutcome};
use faradayd::policy::PolicyEngine;
use faradayd::runtime::{Limits, SandboxRuntime};
use faradayd::session::SessionManager;
use faradayd::types::{
    CapabilityHandle, ClientIdentity, InteractionRequired, Params, Principal, ResolvedCapability,
    RunRequest, SessionHandle, UntrustedResponse,
};

const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");

const MANIFEST: &str = r#"{"capabilities":{
    "tickets":{"provider":"github","host":"tickets.example.com",
        "pathAllow":["^/api/v2/tickets($|/.*)"],"methods":["GET"]},
    "secure":{"provider":"github","host":"secure.example.com",
        "pathAllow":["^/.*"],"methods":["GET"],"requireStepUpAuth":true}
}}"#;

/// Records the interactions raised and returns programmed outcomes.
struct StubInteractor {
    consent: bool,
    seen: Arc<Mutex<Vec<&'static str>>>,
}
impl Interactor for StubInteractor {
    fn require_boxed<'a>(
        &'a self,
        _who: &'a ClientIdentity,
        what: InteractionRequired,
    ) -> Pin<Box<dyn Future<Output = Result<InteractionOutcome, InteractionError>> + Send + 'a>>
    {
        let label = match &what {
            InteractionRequired::Consent { .. } => "consent",
            InteractionRequired::SignIn { .. } => "signin",
            InteractionRequired::StepUp { .. } => "stepup",
        };
        self.seen.lock().unwrap().push(label);
        let is_consent = matches!(what, InteractionRequired::Consent { .. });
        let consent = self.consent;
        Box::pin(async move {
            if is_consent {
                if consent {
                    Ok(InteractionOutcome::Allowed)
                } else {
                    Err(InteractionError::Denied)
                }
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

/// Stub broker: mints handles and answers calls with a fixed body; counts calls.
struct StubBroker {
    body: Vec<u8>,
    calls: Arc<Mutex<u32>>,
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
        let calls = self.calls.clone();
        Box::pin(async move {
            *calls.lock().unwrap() += 1;
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

struct StubSink(Arc<Mutex<Option<String>>>);
impl IdTokenSink for StubSink {
    fn set_id_token(&self, id_token: String) {
        *self.0.lock().unwrap() = Some(id_token);
    }
    fn set_access_token(&self, _access_token: String) {}
}

struct Harness {
    controller: SandboxController,
    seen: Arc<Mutex<Vec<&'static str>>>,
    calls: Arc<Mutex<u32>>,
    installed_token: Arc<Mutex<Option<String>>>,
}

fn harness(budget: u32, consent: bool, body: &[u8]) -> Harness {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(Mutex::new(0));
    let installed_token = Arc::new(Mutex::new(None));
    let broker = Arc::new(StubBroker {
        body: body.to_vec(),
        calls: calls.clone(),
    });
    let runtime = Arc::new(
        SandboxRuntime::new(
            &SandboxRuntime::digest_of(GUEST),
            GUEST,
            broker.clone() as Arc<dyn BrokerCall>,
        )
        .expect("runtime builds"),
    );
    let controller = SandboxController::new(
        Arc::new(PolicyEngine::load(MANIFEST, None, &|_, _| true).unwrap()),
        Arc::new(StubInteractor {
            consent,
            seen: seen.clone(),
        }),
        broker.clone() as Arc<dyn CapabilityMinter>,
        runtime,
        Arc::new(SessionManager::new(budget)),
        Arc::new(StubSink(installed_token.clone())),
        "https://idp.example".to_string(),
        Limits {
            fuel: Some(u64::MAX),
            epoch_deadline: Duration::from_secs(60),
            ..Limits::default()
        },
    );
    Harness {
        controller,
        seen,
        calls,
        installed_token,
    }
}

fn session() -> SessionHandle {
    SessionHandle {
        client: ClientIdentity {
            principal: "501".into(),
            client_label: "vscode".into(),
        },
        workspace_id: "ws".into(),
    }
}

fn req(caps: &[&str], dry_run: bool, code: &str) -> RunRequest {
    RunRequest {
        code: code.into(),
        requested_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        timeout_ms: None,
        dry_run,
        workspace_id: "ws".into(),
        run_id: Some("r-1".into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_consented_run_returns_redacted_result_no_token() {
    let h = harness(50, true, b"{\"data\":\"ok\"}");
    let out = h
        .controller
        .run(
            req(
                &["tickets"],
                false,
                "print(api.tickets.get('/api/v2/tickets/42').decode())",
            ),
            session(),
        )
        .await
        .expect("run ok");
    match out {
        RunOutcome::Run(r) => {
            assert_eq!(r.exit_code, 0, "stderr={:?}", r.stderr);
            assert!(
                r.stdout.contains("{\"data\":\"ok\"}"),
                "stdout={:?}",
                r.stdout
            );
            assert!(!r.stdout.contains("id-tok"), "no token in result");
            assert_eq!(*h.calls.lock().unwrap(), 1, "one brokered call");
        }
        other => panic!("expected Run, got {other:?}"),
    }
    // Sign-in happened and the token was installed for the broker (never returned).
    assert_eq!(h.seen.lock().unwrap().as_slice(), ["consent", "signin"]);
    assert_eq!(h.installed_token.lock().unwrap().as_deref(), Some("id-tok"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_dry_run_plans_without_egress() {
    let h = harness(50, true, b"x");
    let out = h
        .controller
        .run(req(&["tickets"], true, "print('unreached')"), session())
        .await
        .expect("dry-run ok");
    match out {
        RunOutcome::DryRun(d) => {
            assert_eq!(d.planned_calls.len(), 1);
            assert_eq!(d.planned_calls[0].method, "GET");
        }
        other => panic!("expected DryRun, got {other:?}"),
    }
    assert_eq!(*h.calls.lock().unwrap(), 0, "dry-run makes no egress");
    assert!(
        h.installed_token.lock().unwrap().is_none(),
        "no token use on dry-run"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_consent_declined_fails_closed() {
    let h = harness(50, false, b"x");
    let err = h
        .controller
        .run(req(&["tickets"], false, "print('x')"), session())
        .await
        .expect_err("declined");
    assert_eq!(err, ControllerError::InteractionDenied);
    assert_eq!(err.code(), "INTERACTION_DENIED");
    assert_eq!(*h.calls.lock().unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_unknown_capability() {
    let h = harness(50, true, b"x");
    let err = h
        .controller
        .run(req(&["nope"], false, "print('x')"), session())
        .await
        .expect_err("unknown");
    assert_eq!(err, ControllerError::CapUnknown);
    assert_eq!(err.code(), "CAP_UNKNOWN");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_over_budget_rate_limited() {
    // Per-session budget 0 → the per-run charge fails closed.
    let h = harness(0, true, b"x");
    let err = h
        .controller
        .run(req(&["tickets"], false, "print('x')"), session())
        .await
        .expect_err("over budget");
    assert_eq!(err, ControllerError::RateLimited);
    assert_eq!(*h.calls.lock().unwrap(), 0, "no run when over budget");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_step_up_capability_raises_step_up_then_runs() {
    let h = harness(50, true, b"x");
    let out = h
        .controller
        .run(req(&["secure"], false, "print('done')"), session())
        .await
        .expect("run ok");
    assert!(matches!(out, RunOutcome::Run(_)));
    let seen = h.seen.lock().unwrap();
    assert!(seen.contains(&"stepup"), "step-up was raised: {seen:?}");
    assert_eq!(seen.as_slice(), ["consent", "signin", "stepup"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_redacts_token_shaped_output() {
    let h = harness(50, true, b"x");
    // The guest prints a JWT-shaped string; the controller must redact it.
    let out = h
        .controller
        .run(
            req(
                &["tickets"],
                false,
                "print('eyJhbGciOi.eyJzdWIiOi.s1gnatur3')",
            ),
            session(),
        )
        .await
        .expect("run ok");
    match out {
        RunOutcome::Run(r) => {
            assert!(r.stdout.contains("[REDACTED]"), "stdout={:?}", r.stdout);
            assert!(
                !r.stdout.contains("eyJhbGciOi"),
                "JWT redacted; stdout={:?}",
                r.stdout
            );
        }
        other => panic!("expected Run, got {other:?}"),
    }
}

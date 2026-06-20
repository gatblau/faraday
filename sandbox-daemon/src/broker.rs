//! C11 — IdentityBroker. The single source of truth for credentials: it holds the
//! user `id_token` and provider credentials, maintains the per-run capability table,
//! routes a `{capId, verb, path}` call to OBO token-exchange (C9) or a direct provider
//! (C10), sanitises (C5), and audits (C3). **Tokens never leave this module** — they
//! are applied to outbound requests and never serialised into the returned envelope.

use crate::audit::AuditLogger;
use crate::downstream::{DownstreamClient, DownstreamError};
use crate::obo::{OboClient, OboError};
use crate::policy::PolicyEngine;
use crate::sanitize;
use crate::types::{
    AuditEntry, AuthMode, CapabilityHandle, ClientIdentity, Credential, KeyPlacement, Params,
    Principal, ResolvedCapability, Session, UntrustedResponse,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Default capability-handle validity (ADR: ≤5 minutes).
const DEFAULT_CAP_TTL_SECS: i64 = 300;

/// The OIDC-session token source. Every downstream token is derived from the OIDC
/// provider — the broker holds no static provider secrets. Injected so the broker
/// stays testable; the session-aware credential source is the production implementor.
pub trait CredentialSource: Send + Sync {
    /// The user's current `id_token`, the subject token for OBO exchange (`Exchange`).
    fn id_token(&self) -> Option<String>;
    /// The user's current OIDC `access_token`, forwarded to a `Passthrough` provider.
    fn access_token(&self) -> Option<String>;
}

/// Resolves an `api_key` capability's `secretRef` to its key string (server-mode, ADR-036).
/// Built once at daemon startup from the manifest's distinct `secretRef`s via the
/// `SecretResolver` and frozen thereafter; the key is applied to outbound requests and
/// never serialised into the returned envelope or the audit trail.
pub trait ApiKeyStore: Send + Sync {
    /// The key for a resolver reference, or `None` if it was not resolved at startup.
    fn lookup(&self, secret_ref: &str) -> Option<String>;
}

/// A frozen in-memory key store: `secretRef` → key. The daemon bootstrap populates this
/// once (file-backed via the `SecretResolver`) and injects it as `Arc<dyn ApiKeyStore>`.
impl ApiKeyStore for HashMap<String, String> {
    fn lookup(&self, secret_ref: &str) -> Option<String> {
        self.get(secret_ref).cloned()
    }
}

/// Typed broker failure (Phase-4 XC2 registry codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// capId unknown or past its validity window.
    CapInvalid,
    /// Step-up required (surfaced from OBO); the Controller drives C8 and retries once.
    StepUpRequired {
        acr_values: Vec<String>,
        max_age: Option<u64>,
    },
    /// OBO exchange failure (unavailable / rejected).
    Obo(OboError),
    /// Direct downstream failure (timeout / unavailable).
    Downstream(DownstreamError),
    /// No held credential / id_token available to satisfy the call.
    NoCredential,
    /// An `api_key` capability whose `secretRef` was not resolved at startup (ADR-036).
    KeyUnavailable,
}

impl BrokerError {
    pub fn code(&self) -> &'static str {
        match self {
            BrokerError::CapInvalid => "CAP_INVALID",
            BrokerError::StepUpRequired { .. } => "STEP_UP_REQUIRED",
            BrokerError::Obo(e) => e.code(),
            BrokerError::Downstream(e) => e.code(),
            BrokerError::NoCredential => "IDP_UNAVAILABLE",
            BrokerError::KeyUnavailable => "API_KEY_UNAVAILABLE",
        }
    }
}

/// Object-safe broker-call seam consumed by the SandboxRuntime host shim (C12). The
/// runtime forwards a guest call to `IdentityBroker.call` through this trait so the
/// runtime can be tested against a stub; `IdentityBroker` is the production implementor.
pub trait BrokerCall: Send + Sync {
    fn call_boxed<'a>(
        &'a self,
        cap_id: &'a [u8; 16],
        verb: &'a str,
        path: &'a str,
        params: &'a Params,
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<UntrustedResponse, BrokerError>> + Send + 'a>>;
}

impl BrokerCall for IdentityBroker {
    fn call_boxed<'a>(
        &'a self,
        cap_id: &'a [u8; 16],
        verb: &'a str,
        path: &'a str,
        params: &'a Params,
        body: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<UntrustedResponse, BrokerError>> + Send + 'a>> {
        Box::pin(self.call(cap_id, verb, path, params, body))
    }
}

struct Entry {
    cap: ResolvedCapability,
    principal: Principal,
    expires_at: i64,
    /// Server-minted run correlator + client-asserted label, bound at mint time so each
    /// outbound call attributes its `AuditEntry` to the run that minted it (C3) without
    /// the broker holding mutable per-run state shared across concurrent runs.
    run_id: String,
    client_label: String,
}

pub struct IdentityBroker {
    table: Mutex<HashMap<[u8; 16], Entry>>,
    cap_ttl_secs: i64,
    policy: Arc<PolicyEngine>,
    audit: Arc<AuditLogger>,
    obo: Arc<OboClient>,
    downstream: Arc<DownstreamClient>,
    creds: Arc<dyn CredentialSource>,
    max_response_bytes: usize,
    api_keys: Arc<dyn ApiKeyStore>,
}

impl IdentityBroker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: Arc<PolicyEngine>,
        audit: Arc<AuditLogger>,
        obo: Arc<OboClient>,
        downstream: Arc<DownstreamClient>,
        creds: Arc<dyn CredentialSource>,
        max_response_bytes: usize,
        api_keys: Arc<dyn ApiKeyStore>,
    ) -> IdentityBroker {
        Self::with_ttl(
            policy,
            audit,
            obo,
            downstream,
            creds,
            max_response_bytes,
            api_keys,
            DEFAULT_CAP_TTL_SECS,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_ttl(
        policy: Arc<PolicyEngine>,
        audit: Arc<AuditLogger>,
        obo: Arc<OboClient>,
        downstream: Arc<DownstreamClient>,
        creds: Arc<dyn CredentialSource>,
        max_response_bytes: usize,
        api_keys: Arc<dyn ApiKeyStore>,
        cap_ttl_secs: i64,
    ) -> IdentityBroker {
        IdentityBroker {
            table: Mutex::new(HashMap::new()),
            cap_ttl_secs,
            policy,
            audit,
            obo,
            downstream,
            creds,
            max_response_bytes,
            api_keys,
        }
    }

    /// Integration-test constructor that pins the capability TTL (e.g. a negative TTL
    /// mints an already-expired handle to exercise the `CAP_INVALID` path).
    #[cfg(feature = "integration")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ttl(
        policy: Arc<PolicyEngine>,
        audit: Arc<AuditLogger>,
        obo: Arc<OboClient>,
        downstream: Arc<DownstreamClient>,
        creds: Arc<dyn CredentialSource>,
        max_response_bytes: usize,
        cap_ttl_secs: i64,
        api_keys: Arc<dyn ApiKeyStore>,
    ) -> IdentityBroker {
        Self::with_ttl(
            policy,
            audit,
            obo,
            downstream,
            creds,
            max_response_bytes,
            api_keys,
            cap_ttl_secs,
        )
    }

    /// Mint a 128-bit `capId` per capability, valid for `cap_ttl_secs`, bound to this
    /// instance; store `capId → (capability, principal, run context)` in the in-memory
    /// table. `run_id` is the server-minted run correlator and `client_label` the
    /// client-asserted label — both bound here so each call's `AuditEntry` (C3) is
    /// attributed to its run.
    pub fn mint_caps(
        &self,
        principal: &Principal,
        run_id: &str,
        client_label: &str,
        caps: &[ResolvedCapability],
    ) -> Vec<CapabilityHandle> {
        let now = unix_now();
        let mut table = self.table.lock().unwrap();
        let mut handles = Vec::with_capacity(caps.len());
        for cap in caps {
            let mut cap_id = [0u8; 16];
            if getrandom::getrandom(&mut cap_id).is_err() {
                continue; // never mint a handle from a weak/failed CSPRNG draw
            }
            let expires_at = now + self.cap_ttl_secs;
            table.insert(
                cap_id,
                Entry {
                    cap: cap.clone(),
                    principal: principal.clone(),
                    expires_at,
                    run_id: run_id.to_string(),
                    client_label: client_label.to_string(),
                },
            );
            handles.push(CapabilityHandle {
                cap_id,
                capability_id: cap.id.clone(),
                expires_at,
            });
        }
        handles
    }

    /// Resolve `capId`, re-check policy, route to OBO or direct, sanitise, audit.
    pub async fn call(
        &self,
        cap_id: &[u8; 16],
        verb: &str,
        path: &str,
        params: &Params,
        body: &[u8],
    ) -> Result<UntrustedResponse, BrokerError> {
        // Look up + expiry check; clone out so the lock is not held across .await.
        let (cap, principal, run_id, client_label) = {
            let table = self.table.lock().unwrap();
            let entry = table.get(cap_id).ok_or(BrokerError::CapInvalid)?;
            if unix_now() >= entry.expires_at {
                return Err(BrokerError::CapInvalid);
            }
            (
                entry.cap.clone(),
                entry.principal.clone(),
                entry.run_id.clone(),
                entry.client_label.clone(),
            )
        };

        // Re-check host/path/method via PolicyEngine. The per-run budget is the
        // Controller's concern (C7/C13), so authorise is given a permissive budget
        // here; the returned canonical path is what we actually call.
        let throwaway = Session {
            client: ClientIdentity {
                peer_uid: 0,
                client_label: String::new(),
            },
            workspace_id: String::new(),
            consented: Default::default(),
            calls_used: 0,
        };
        let canon = self
            .policy
            .authorise(&cap, verb, path, &throwaway, u32::MAX)
            .map_err(|_| BrokerError::CapInvalid)?;

        let started = Instant::now();
        let (resp, status) = match cap.auth_mode {
            // C9 — token exchange: the user `id_token` is the subject token; the
            // obo-broker mints the downstream token server-side and it never enters
            // this process.
            AuthMode::Exchange => {
                let id_token = self.creds.id_token().ok_or(BrokerError::NoCredential)?;
                match self
                    .obo
                    .exchange(&id_token, &cap, verb, &canon, params, body)
                    .await
                {
                    Ok(r) => {
                        let s = r.status;
                        (r, s)
                    }
                    Err(OboError::StepUpRequired {
                        acr_values,
                        max_age,
                    }) => {
                        return Err(BrokerError::StepUpRequired {
                            acr_values,
                            max_age,
                        })
                    }
                    Err(e) => return Err(BrokerError::Obo(e)),
                }
            }
            // C10 — pass-through: forward the user's own OIDC access token directly to
            // the service. Valid only because the token is audienced for the provider
            // (a same-trust-domain capability, gated to admin-signed manifests).
            AuthMode::Passthrough => {
                let access_token = self.creds.access_token().ok_or(BrokerError::NoCredential)?;
                let cred = Credential::Bearer(access_token);
                let raw = self
                    .downstream
                    .do_call(&cap, verb, &canon, params, body, |req| {
                        apply_credential(req, &cred)
                    })
                    .await
                    .map_err(BrokerError::Downstream)?;
                let status = raw.status;
                let sanitised = sanitize::sanitize(
                    raw.status,
                    &raw.body,
                    &raw.headers,
                    self.max_response_bytes,
                );
                (sanitised, status)
            }
            // C10 — api_key: apply the per-capability static key at its configured
            // placement (ADR-036). The key is looked up in the startup-frozen ApiKeyStore
            // and never serialised into the returned envelope or the audit trail.
            AuthMode::ApiKey => {
                let secret_ref = cap.secret_ref.as_deref().unwrap_or_default();
                let key = self
                    .api_keys
                    .lookup(secret_ref)
                    .ok_or(BrokerError::KeyUnavailable)?;
                // key_placement is guaranteed Some for ApiKey by the C4 load validation.
                let placement = cap
                    .key_placement
                    .as_ref()
                    .ok_or(BrokerError::KeyUnavailable)?;
                let raw = match placement {
                    KeyPlacement::Header { name, scheme } => {
                        let value = match scheme {
                            Some(s) => format!("{s} {key}"),
                            None => key.clone(),
                        };
                        let mut headers = HashMap::new();
                        headers.insert(name.clone(), value);
                        let cred = Credential::Headers(headers);
                        self.downstream
                            .do_call(&cap, verb, &canon, params, body, |req| {
                                apply_credential(req, &cred)
                            })
                            .await
                            .map_err(BrokerError::Downstream)?
                    }
                    KeyPlacement::Query { param } => {
                        let mut q = params.clone();
                        q.push((param.clone(), key.clone()));
                        self.downstream
                            .do_call(&cap, verb, &canon, &q, body, |_req| {})
                            .await
                            .map_err(BrokerError::Downstream)?
                    }
                };
                let status = raw.status;
                let sanitised = sanitize::sanitize(
                    raw.status,
                    &raw.body,
                    &raw.headers,
                    self.max_response_bytes,
                );
                (sanitised, status)
            }
            // C10 — unauthenticated: a public endpoint (ADR-037). No credential is built
            // or applied; the call is still host/path/method-allowlisted and audited.
            AuthMode::Unauthenticated => {
                let raw = self
                    .downstream
                    .do_call(&cap, verb, &canon, params, body, |_req| {})
                    .await
                    .map_err(BrokerError::Downstream)?;
                let status = raw.status;
                let sanitised = sanitize::sanitize(
                    raw.status,
                    &raw.body,
                    &raw.headers,
                    self.max_response_bytes,
                );
                (sanitised, status)
            }
        };

        // Audit the call. The entry carries sizes + a keyed-HMAC user id — never a
        // token or a body. `run_id` (server-minted) and `client_label` (client-asserted
        // hint) were bound to the capId at mint time, so the call is attributed to its run.
        self.audit.record(AuditEntry {
            timestamp: unix_now(),
            run_id,
            user_hmac: self.audit.user_hmac(&principal.subject),
            client_label,
            provider: cap.provider.clone(),
            capability_id: cap.id.clone(),
            method: verb.to_string(),
            host: cap.host.clone(),
            path: canon,
            status_code: status,
            request_bytes: body.len() as u64,
            response_bytes: resp.body.len() as u64,
            duration_ms: started.elapsed().as_millis() as u64,
        });

        Ok(resp)
    }
}

/// Apply the held credential to the outbound request (Bearer or custom headers).
fn apply_credential(req: &mut reqwest::Request, cred: &Credential) {
    match cred {
        Credential::Bearer(token) => {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
                req.headers_mut()
                    .insert(reqwest::header::AUTHORIZATION, value);
            }
        }
        Credential::Headers(headers) => {
            for (name, value) in headers {
                if let (Ok(n), Ok(v)) = (
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                    reqwest::header::HeaderValue::from_str(value),
                ) {
                    req.headers_mut().insert(n, v);
                }
            }
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

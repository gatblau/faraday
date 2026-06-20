//! C13 — SandboxController. Orchestrates one `run`: resolve requested capabilities,
//! gather per-session consent, plan a dry-run, ensure a valid `id_token` (sign-in +
//! step-up), mint the capability bundle, execute on the runtime, charge the per-run
//! budget, and redact token-shaped strings from output. **Never returns a token.**
//!
//! Dependencies are abstracted behind small traits (`Interactor`, `CapabilityMinter`,
//! `IdTokenSink`) so the orchestration is gated in-process; `ConsentUI` and
//! `IdentityBroker` are the production implementors.

use crate::interaction::{ConsentUI, InteractionError, InteractionOutcome};
use crate::policy::PolicyEngine;
use crate::runtime::{CapabilityBundle, Limits, SandboxRuntime};
use crate::session::SessionManager;
use crate::types::{
    AuthMode, CallSummary, CapabilityHandle, ClientIdentity, DryRunResult, InteractionRequired,
    Principal, ResolvedCapability, RunRequest, RunResult, SessionHandle,
};

/// SPEC-GAP-1: a headless server-mode run (no OIDC capability) has no human principal,
/// yet `mint_caps`/audit (C3/C11) need a subject. Such runs are attributed to a fixed
/// single-tenant service subject (ADR-034: one daemon per agent). The exact subject value
/// is not pinned by the LLD — confirm in spec (tracked as a follow-up on plan 06).
const SERVER_MODE_SUBJECT: &str = "faradayd:server-mode";
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// The daemon-owned interaction surface (sign-in / consent / step-up), object-safe so
/// the controller can be tested with a stub. `ConsentUI` (C8) is the production impl.
pub trait Interactor: Send + Sync {
    fn require_boxed<'a>(
        &'a self,
        who: &'a ClientIdentity,
        what: InteractionRequired,
    ) -> Pin<Box<dyn Future<Output = Result<InteractionOutcome, InteractionError>> + Send + 'a>>;
}

impl Interactor for ConsentUI {
    fn require_boxed<'a>(
        &'a self,
        who: &'a ClientIdentity,
        what: InteractionRequired,
    ) -> Pin<Box<dyn Future<Output = Result<InteractionOutcome, InteractionError>> + Send + 'a>>
    {
        Box::pin(self.require(who, what))
    }
}

/// Mints per-run capability handles. `IdentityBroker` (C11) is the production impl;
/// the same broker instance also backs the runtime's `broker_call` shim.
pub trait CapabilityMinter: Send + Sync {
    fn mint_caps(
        &self,
        principal: &Principal,
        run_id: &str,
        client_label: &str,
        caps: &[ResolvedCapability],
    ) -> Vec<CapabilityHandle>;
}

impl CapabilityMinter for crate::broker::IdentityBroker {
    fn mint_caps(
        &self,
        principal: &Principal,
        run_id: &str,
        client_label: &str,
        caps: &[ResolvedCapability],
    ) -> Vec<CapabilityHandle> {
        crate::broker::IdentityBroker::mint_caps(self, principal, run_id, client_label, caps)
    }
}

/// Installs the freshly signed-in OIDC tokens where the broker reads them: the
/// `id_token` for the exchange path and the `access_token` for the pass-through path.
/// The production implementor is the session-aware credential source shared with the
/// broker; neither token ever leaves the daemon.
pub trait IdTokenSink: Send + Sync {
    fn set_id_token(&self, id_token: String);
    fn set_access_token(&self, access_token: String);
}

/// Typed controller failure (Phase-4 XC2 registry codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerError {
    /// A requested capability is not in the manifest.
    CapUnknown,
    /// Consent or step-up was declined / unavailable — fail closed.
    InteractionDenied,
    /// The per-run/session budget is exhausted.
    RateLimited,
}

impl ControllerError {
    pub fn code(&self) -> &'static str {
        match self {
            ControllerError::CapUnknown => "CAP_UNKNOWN",
            ControllerError::InteractionDenied => "INTERACTION_DENIED",
            ControllerError::RateLimited => "RATE_LIMITED",
        }
    }
}

/// The result of a `run`: a full result, or a dry-run plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Run(RunResult),
    DryRun(DryRunResult),
}

pub struct SandboxController {
    policy: Arc<PolicyEngine>,
    interactor: Arc<dyn Interactor>,
    minter: Arc<dyn CapabilityMinter>,
    runtime: Arc<SandboxRuntime>,
    sessions: Arc<SessionManager>,
    creds: Arc<dyn IdTokenSink>,
    issuer: String,
    limits: Limits,
}

impl SandboxController {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: Arc<PolicyEngine>,
        interactor: Arc<dyn Interactor>,
        minter: Arc<dyn CapabilityMinter>,
        runtime: Arc<SandboxRuntime>,
        sessions: Arc<SessionManager>,
        creds: Arc<dyn IdTokenSink>,
        issuer: String,
        limits: Limits,
    ) -> SandboxController {
        SandboxController {
            policy,
            interactor,
            minter,
            runtime,
            sessions,
            creds,
            issuer,
            limits,
        }
    }

    /// Orchestrate one run. Returns a `DryRunResult` when `req.dry_run`, else a
    /// `RunResult` with redacted output and no token.
    pub async fn run(
        &self,
        req: RunRequest,
        session: SessionHandle,
    ) -> Result<RunOutcome, ControllerError> {
        // 1. Resolve every requested capability (unknown → CAP_UNKNOWN).
        let mut resolved: Vec<ResolvedCapability> =
            Vec::with_capacity(req.requested_capabilities.len());
        for cap_id in &req.requested_capabilities {
            match self.policy.resolve(cap_id) {
                Some(cap) => resolved.push(cap.clone()),
                None => return Err(ControllerError::CapUnknown),
            }
        }

        // 2. Gather consent for any not-yet-consented OIDC-backed capability (decline →
        //    fail closed). Non-OIDC (api_key/none) capabilities are pre-granted by the
        //    admin-signed policy (ADR-039), so no consent is rendered for them.
        for cap in &resolved {
            if !matches!(cap.auth_mode, AuthMode::Exchange | AuthMode::Passthrough) {
                continue;
            }
            if !self
                .sessions
                .is_consented(&session.client, &session.workspace_id, &cap.id)
            {
                let what = InteractionRequired::Consent {
                    capability_id: cap.id.clone(),
                    host: cap.host.clone(),
                    methods: cap.methods.clone(),
                    provider: cap.provider.clone(),
                    require_step_up: cap.require_step_up,
                };
                match self.interactor.require_boxed(&session.client, what).await {
                    Ok(InteractionOutcome::Allowed) => {
                        self.sessions.record_consent(
                            &session.client,
                            &session.workspace_id,
                            &cap.id,
                        );
                    }
                    _ => return Err(ControllerError::InteractionDenied),
                }
            }
        }

        // 3. Dry-run: plan only — no sign-in, no minting, no egress, no token use.
        if req.dry_run {
            let planned = resolved
                .iter()
                .map(|c| CallSummary {
                    provider: c.provider.clone(),
                    host: c.host.clone(),
                    path: String::new(),
                    method: c.methods.first().cloned().unwrap_or_default(),
                    status: None,
                })
                .collect();
            return Ok(RunOutcome::DryRun(DryRunResult {
                planned_calls: planned,
            }));
        }

        // 4. Sign-in only when the run needs OIDC (exchange/passthrough); raise step-up if
        //    any such capability needs it (pre-run step-up; mid-run retry ADR-015 is FU-024).
        //    A pure api_key/none run (server-mode, ADR-038) proceeds with no human: no
        //    sign-in and no token install.
        let needs_oidc = resolved
            .iter()
            .any(|c| matches!(c.auth_mode, AuthMode::Exchange | AuthMode::Passthrough));
        let principal = if needs_oidc {
            let (principal, id_token, access_token) = self.sign_in(&session.client).await?;
            let (principal, id_token, access_token) = if resolved.iter().any(|c| c.require_step_up)
            {
                self.step_up(&session.client).await?
            } else {
                (principal, id_token, access_token)
            };
            // Install both tokens where the broker reads them: id_token for the exchange
            // path, access_token for pass-through (never logged, never leave the daemon).
            self.creds.set_id_token(id_token);
            self.creds.set_access_token(access_token);
            principal
        } else {
            // SPEC-GAP-1: synthesise a service principal for audit attribution (see const).
            Principal {
                subject: SERVER_MODE_SUBJECT.to_string(),
                issuer: String::new(),
                acr: None,
                amr: Vec::new(),
                auth_time: None,
            }
        };

        // 5. Charge the per-run budget (C7); mint the capability bundle (C11).
        self.sessions
            .try_charge(&session.client, &session.workspace_id)
            .map_err(|_| ControllerError::RateLimited)?;
        // Server-minted run correlator — never client-asserted — bound into every cap so
        // the audit trail can group this run's calls; the client label travels as a hint.
        let run_id = mint_run_id();
        let handles =
            self.minter
                .mint_caps(&principal, &run_id, &session.client.client_label, &resolved);
        let mut mappings = HashMap::new();
        for (cap, handle) in resolved.iter().zip(handles.iter()) {
            mappings.insert(cap.id.clone(), handle.cap_id);
        }
        let bundle = CapabilityBundle { mappings };

        // 6. Execute on the runtime (C12); redact token-shaped strings from output.
        let mut result = self.runtime.run(&req.code, &bundle, &self.limits).await;
        result.stdout = redact(&result.stdout);
        result.stderr = redact(&result.stderr);
        Ok(RunOutcome::Run(result))
    }

    async fn sign_in(
        &self,
        client: &ClientIdentity,
    ) -> Result<(Principal, String, String), ControllerError> {
        let what = InteractionRequired::SignIn {
            issuer: self.issuer.clone(),
        };
        match self.interactor.require_boxed(client, what).await {
            Ok(InteractionOutcome::SignedIn {
                principal,
                id_token,
                access_token,
            }) => Ok((principal, id_token, access_token)),
            _ => Err(ControllerError::InteractionDenied),
        }
    }

    async fn step_up(
        &self,
        client: &ClientIdentity,
    ) -> Result<(Principal, String, String), ControllerError> {
        let what = InteractionRequired::StepUp {
            acr_values: Vec::new(),
            max_age_secs: 0,
        };
        match self.interactor.require_boxed(client, what).await {
            Ok(InteractionOutcome::SignedIn {
                principal,
                id_token,
                access_token,
            }) => Ok((principal, id_token, access_token)),
            _ => Err(ControllerError::InteractionDenied),
        }
    }
}

/// Mint a 128-bit server-side run correlation id (hex). Server-derived, never
/// client-asserted, so the audit trail (C3) can group one run's outbound calls and
/// attribute them trustworthily. Returns an empty id only if the CSPRNG draw fails —
/// degraded correlation is preferable to a predictable id.
fn mint_run_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return String::new();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Redact token-shaped strings (JWTs and `Bearer …`) from guest output — defence in
/// depth on top of the broker never serialising a token into a response.
fn redact(s: &str) -> String {
    let re = regex::Regex::new(
        r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+|Bearer\s+[A-Za-z0-9._\-]+",
    )
    .expect("static redaction regex");
    re.replace_all(s, "[REDACTED]").into_owned()
}

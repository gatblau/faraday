//! C4 — PolicyEngine. Loads the capability manifest (a workspace override is honoured
//! only if admin-signed, ADR-021 — else fail-closed to the shipped default), resolves
//! a `capabilityId`, and authorises a call: canonical path + host/method allowlist +
//! per-run budget + step-up requirement.

use crate::errors::WireError;
use crate::types::{AuthMode, KeyPlacement, ResolvedCapability, Session};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct RawCapability {
    /// Optional for `none` (server-mode, ADR-037); required for `exchange`/`passthrough`
    /// (enforced in `load`, since the pluggable provider set is not enumerable here).
    #[serde(default)]
    provider: String,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    host: String,
    #[serde(rename = "pathAllow")]
    path_allow: Vec<String>,
    methods: Vec<String>,
    #[serde(rename = "requireStepUpAuth", default)]
    require_step_up: bool,
    /// `exchange` (default) routes via the obo-broker; `passthrough` forwards the
    /// user's OIDC access token to a same-trust-domain provider (ADR-021: only an
    /// admin-signed manifest may set `passthrough`, since faraday then holds the token).
    #[serde(rename = "authMode", default)]
    auth_mode: AuthMode,
    /// Server-mode write gate (ADR-039): permits unsafe methods. Default `false`.
    #[serde(rename = "allowWrite", default)]
    allow_write: bool,
    /// `api_key` mode (ADR-036): resolver reference for the key (a file path under
    /// `FileSecretResolver`). Required for `api_key`; forbidden otherwise.
    #[serde(rename = "secretRef", default)]
    secret_ref: Option<String>,
    /// `api_key` mode (ADR-036): how the key is attached. Required for `api_key`.
    #[serde(rename = "keyPlacement", default)]
    key_placement: Option<KeyPlacement>,
}

/// HTTP methods that mutate state; permitted only on a capability with `allowWrite` (ADR-039).
const UNSAFE_METHODS: [&str; 4] = ["POST", "PUT", "PATCH", "DELETE"];

#[derive(Debug, Deserialize)]
struct RawManifest {
    #[serde(default)]
    capabilities: HashMap<String, RawCapability>,
}

pub struct PolicyEngine {
    caps: HashMap<String, ResolvedCapability>,
}

impl PolicyEngine {
    /// Load the shipped default; honour a workspace override **only** if
    /// `verify(json_bytes, signature)` returns true (admin-signed), otherwise fall
    /// back fail-closed to the default. The concrete signature scheme is injected
    /// (a real asymmetric verifier is a later hardening — see the plan follow-up).
    pub fn load(
        default_json: &str,
        signed_override: Option<(&str, &[u8])>,
        verify: &dyn Fn(&[u8], &[u8]) -> bool,
    ) -> Result<PolicyEngine, WireError> {
        let chosen = match signed_override {
            Some((json, sig)) if verify(json.as_bytes(), sig) => json,
            _ => default_json, // unsigned / mis-signed / absent → shipped default
        };
        let raw: RawManifest = serde_json::from_str(chosen)
            .map_err(|_| WireError::new("CFG_INVALID", "manifest parse"))?;

        let mut caps = HashMap::new();
        for (id, c) in raw.capabilities {
            let path_allow = c
                .path_allow
                .iter()
                .map(|p| regex::Regex::new(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WireError::new("CFG_INVALID", "pathAllow regex"))?;
            // Server-mode validation (fail-closed):
            // (1) exchange/passthrough require a provider (the auth plugin selector).
            if matches!(c.auth_mode, AuthMode::Exchange | AuthMode::Passthrough)
                && c.provider.is_empty()
            {
                return Err(WireError::new(
                    "CFG_INVALID",
                    "provider required for exchange/passthrough",
                ));
            }
            // (2) step-up is not applicable to a non-OIDC capability (ADR-039).
            if matches!(c.auth_mode, AuthMode::Unauthenticated | AuthMode::ApiKey)
                && c.require_step_up
            {
                return Err(WireError::new(
                    "CFG_INVALID",
                    "step-up not applicable for api_key/none",
                ));
            }
            // (4) api_key requires secretRef + keyPlacement; both are forbidden on any
            //     other mode (ADR-036).
            if matches!(c.auth_mode, AuthMode::ApiKey) {
                if c.secret_ref.is_none() || c.key_placement.is_none() {
                    return Err(WireError::new(
                        "CFG_INVALID",
                        "api_key requires secretRef + keyPlacement",
                    ));
                }
            } else if c.secret_ref.is_some() || c.key_placement.is_some() {
                return Err(WireError::new(
                    "CFG_INVALID",
                    "secretRef/keyPlacement only valid for api_key",
                ));
            }
            // (3) write gate: an unsafe method needs the explicit opt-in (ADR-039).
            if !c.allow_write
                && c.methods
                    .iter()
                    .any(|m| UNSAFE_METHODS.iter().any(|u| m.eq_ignore_ascii_case(u)))
            {
                return Err(WireError::new(
                    "CFG_INVALID",
                    "unsafe method requires allowWrite",
                ));
            }
            caps.insert(
                id.clone(),
                ResolvedCapability {
                    id,
                    provider: c.provider,
                    audience: c.audience,
                    scopes: c.scopes,
                    host: c.host,
                    path_allow,
                    methods: c.methods,
                    require_step_up: c.require_step_up,
                    auth_mode: c.auth_mode,
                    allow_write: c.allow_write,
                    secret_ref: c.secret_ref,
                    key_placement: c.key_placement,
                },
            );
        }
        Ok(PolicyEngine { caps })
    }

    pub fn resolve(&self, cap_id: &str) -> Option<&ResolvedCapability> {
        self.caps.get(cap_id)
    }

    /// True iff any capability needs an OIDC sign-in (`exchange` or `passthrough`).
    /// The bootstrap uses this to decide whether the OIDC config group is required
    /// (ADR-038): a pure `none`/`api_key` manifest needs no sign-in.
    pub fn has_oidc_capability(&self) -> bool {
        self.caps
            .values()
            .any(|c| matches!(c.auth_mode, AuthMode::Exchange | AuthMode::Passthrough))
    }

    /// The distinct `secretRef`s of `api_key` capabilities (ADR-036 / AS-6). The bootstrap
    /// resolves these once at startup, file-backed via the `SecretResolver`, into the
    /// `ApiKeyStore` injected into the broker.
    pub fn api_key_secret_refs(&self) -> Vec<String> {
        let mut refs: Vec<String> = self
            .caps
            .values()
            .filter(|c| matches!(c.auth_mode, AuthMode::ApiKey))
            .filter_map(|c| c.secret_ref.clone())
            .collect();
        refs.sort();
        refs.dedup();
        refs
    }

    /// Authorise a call against a resolved capability: canonicalise the path (reject
    /// traversal), check method + path allowlist, and the per-run budget. Returns the
    /// canonical path or a typed error.
    pub fn authorise(
        &self,
        cap: &ResolvedCapability,
        verb: &str,
        raw_path: &str,
        session: &Session,
        max_per_run: u32,
    ) -> Result<String, WireError> {
        let canon = canonicalise(raw_path)?;
        if !cap.methods.iter().any(|m| m.eq_ignore_ascii_case(verb)) {
            return Err(WireError::new("POLICY_METHOD_DENIED", "method not allowed"));
        }
        if !cap.path_allow.iter().any(|re| re.is_match(&canon)) {
            return Err(WireError::new("POLICY_PATH_DENIED", "path not allowed"));
        }
        if session.calls_used + 1 > max_per_run {
            return Err(WireError::new("RATE_LIMITED", "run budget exceeded"));
        }
        // Step-up: the daemon raises it via the consent UI / relays the obo-broker 401;
        // the acr allowlist check is server-side (obo-broker ADR-014), not here.
        Ok(canon)
    }
}

/// Percent-decode once, reject residual `%`, resolve `.`/`..`, collapse `//`;
/// a `..` that escapes the root → `POLICY_PATH_REJECTED`.
fn canonicalise(raw: &str) -> Result<String, WireError> {
    let decoded = percent_decode_once(raw).ok_or_else(|| reject("bad percent-encoding"))?;
    if decoded.contains('%') {
        return Err(reject("residual percent-encoding"));
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                if out.pop().is_none() {
                    return Err(reject("path traversal"));
                }
            }
            s => out.push(s),
        }
    }
    Ok(format!("/{}", out.join("/")))
}

fn reject(msg: &str) -> WireError {
    WireError::new("POLICY_PATH_REJECTED", msg)
}

fn percent_decode_once(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod server_mode_tests {
    use super::*;
    use crate::types::AuthMode;

    fn load(json: &str) -> Result<PolicyEngine, WireError> {
        PolicyEngine::load(json, None, &|_, _| true)
    }

    fn err_code(r: Result<PolicyEngine, WireError>) -> String {
        match r {
            Ok(_) => panic!("expected a load error"),
            Err(e) => e.code,
        }
    }

    #[test]
    fn none_capability_loads_without_provider() {
        let j = r#"{"capabilities":{"pub":{"authMode":"none","host":"h","pathAllow":["^/x$"],"methods":["GET"]}}}"#;
        let p = load(j).expect("loads");
        let c = p.resolve("pub").unwrap();
        assert!(matches!(c.auth_mode, AuthMode::Unauthenticated));
        assert!(!c.allow_write);
        assert!(!p.has_oidc_capability());
    }

    #[test]
    fn unsafe_method_without_allow_write_is_rejected() {
        let j = r#"{"capabilities":{"w":{"authMode":"none","host":"h","pathAllow":["^/x$"],"methods":["POST"]}}}"#;
        assert_eq!(err_code(load(j)), "CFG_INVALID");
    }

    #[test]
    fn unsafe_method_with_allow_write_loads() {
        let j = r#"{"capabilities":{"w":{"authMode":"none","host":"h","pathAllow":["^/x$"],"methods":["POST"],"allowWrite":true}}}"#;
        assert!(load(j).is_ok());
    }

    #[test]
    fn step_up_on_none_is_rejected() {
        let j = r#"{"capabilities":{"n":{"authMode":"none","host":"h","pathAllow":["^/x$"],"methods":["GET"],"requireStepUpAuth":true}}}"#;
        assert_eq!(err_code(load(j)), "CFG_INVALID");
    }

    #[test]
    fn exchange_without_provider_is_rejected() {
        let j = r#"{"capabilities":{"e":{"authMode":"exchange","host":"h","pathAllow":["^/x$"],"methods":["GET"]}}}"#;
        assert_eq!(err_code(load(j)), "CFG_INVALID");
    }

    #[test]
    fn passthrough_capability_marks_oidc() {
        let j = r#"{"capabilities":{"p":{"authMode":"passthrough","provider":"github","host":"h","pathAllow":["^/x$"],"methods":["GET"]}}}"#;
        assert!(load(j).unwrap().has_oidc_capability());
    }

    #[test]
    fn api_key_requires_secret_ref_and_placement() {
        let j = r#"{"capabilities":{"k":{"authMode":"api_key","host":"h","pathAllow":["^/x$"],"methods":["GET"]}}}"#;
        assert_eq!(err_code(load(j)), "CFG_INVALID");
    }

    #[test]
    fn secret_ref_forbidden_on_non_api_key() {
        let j = r#"{"capabilities":{"n":{"authMode":"none","host":"h","pathAllow":["^/x$"],"methods":["GET"],"secretRef":"ref1"}}}"#;
        assert_eq!(err_code(load(j)), "CFG_INVALID");
    }

    #[test]
    fn step_up_on_api_key_is_rejected() {
        let j = r#"{"capabilities":{"k":{"authMode":"api_key","host":"h","pathAllow":["^/x$"],"methods":["GET"],"requireStepUpAuth":true,"secretRef":"r","keyPlacement":{"header":{"name":"X-API-Key"}}}}}"#;
        assert_eq!(err_code(load(j)), "CFG_INVALID");
    }

    #[test]
    fn api_key_capability_loads_and_lists_secret_ref() {
        let j = r#"{"capabilities":{"k":{"authMode":"api_key","host":"h","pathAllow":["^/x$"],"methods":["GET"],"secretRef":"ref1","keyPlacement":{"query":{"param":"api_key"}}}}}"#;
        let p = load(j).expect("loads");
        assert_eq!(p.api_key_secret_refs(), vec!["ref1".to_string()]);
        assert!(!p.has_oidc_capability());
    }

    // Guards the get-started Step 6 example. The shipped demo manifest must expose a
    // `catfacts` capability shaped exactly as the guide's `api.catfacts.get('/fact')` call
    // relies on: unauthenticated (no sign-in), a real public host (so HTTPS, never the
    // loopback plaintext exception), GET-only, with `/fact` allowed and other paths refused.
    // If the demo manifest is edited in a way that breaks the documented call, this fails.
    #[test]
    fn demo_policy_catfacts_matches_get_started_example() {
        let demo = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/demo/pysandbox.policy.json"
        ))
        .expect("read demo policy file");
        let p = load(&demo).expect("demo policy loads");

        let c = p.resolve("catfacts").expect("catfacts capability present");
        assert!(
            matches!(c.auth_mode, AuthMode::Unauthenticated),
            "catfacts must be authMode none so the example needs no sign-in"
        );
        assert_eq!(
            c.host, "catfact.ninja",
            "real public host the example documents"
        );
        assert_eq!(c.methods, vec!["GET".to_string()], "GET only");
        assert!(!c.allow_write, "read-only capability");
        assert!(!c.require_step_up, "no step-up on a none capability");

        // The documented call is GET /fact: that path is allowed; an unrelated path is not.
        assert!(
            c.path_allow.iter().any(|re| re.is_match("/fact")),
            "GET /fact (the documented call) must be allowed"
        );
        assert!(
            !c.path_allow.iter().any(|re| re.is_match("/breeds")),
            "only the exact /fact path is allowed, not an arbitrary one"
        );
    }
}

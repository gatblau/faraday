//! C18 / ADR-040 — `faradayd credential set|rm|list` enrolment CLI (core).
//!
//! Provisions per-capability `api_key` secrets (ADR-036) into the OS secure store so an
//! `api_key` capability can resolve its `secretRef` from the keychain (ADR-040) instead of a
//! file. The secret is read from stdin (no-echo on a TTY) by the `main.rs` shell — **never**
//! taken as a command-line argument — validated here against the admin-signed manifest, and
//! written through the same [`KeychainStore`](crate::keychain::KeychainStore) the resolver
//! reads. The secret value is never echoed, logged, or placed in an error message.
//!
//! `list` probes the manifest's `api_key` `secretRef`s (the `keyring` crate exposes no
//! enumeration API) and reports which are provisioned — names only, never values.

use crate::keychain::{KeychainError, KeychainStore};
use crate::policy::PolicyEngine;

/// A parsed credential command. For `Set` the token has already been read from stdin, so the
/// secret value never appears on the command line.
pub enum CredentialCmd {
    Set { secret_ref: String, token: Vec<u8> },
    Rm { secret_ref: String },
    List,
}

/// A credential-CLI failure. `code` is the wire/registry code; `message` never contains the
/// secret value (only ref names and backend messages).
#[derive(Debug)]
pub struct CredentialError {
    pub code: &'static str,
    pub message: String,
}

impl CredentialError {
    fn usage(m: impl Into<String>) -> Self {
        Self {
            code: "CRED_USAGE",
            message: m.into(),
        }
    }
    /// A stdin-read failure while collecting the token (the `main.rs` shell maps I/O errors
    /// here). Carries no secret material.
    pub fn input(m: impl Into<String>) -> Self {
        Self {
            code: "CRED_USAGE",
            message: m.into(),
        }
    }
    fn unknown_ref(r: &str) -> Self {
        Self {
            code: "CRED_UNKNOWN_REF",
            message: format!("'{r}' is not an api_key capability in the manifest"),
        }
    }
    fn empty() -> Self {
        Self {
            code: "CRED_EMPTY",
            message: "token was empty".to_string(),
        }
    }
    fn not_found(r: &str) -> Self {
        Self {
            code: "CRED_NOT_FOUND",
            message: format!("no keychain entry for '{r}'"),
        }
    }
    fn keychain(e: KeychainError) -> Self {
        Self {
            code: "CRED_KEYCHAIN",
            message: e.to_string(),
        }
    }
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CredentialError {}

/// Parse `[verb, secret_ref?]` into a command. For `set` the token is obtained by calling
/// `read_token` (the `main.rs` shell reads it no-echo from stdin) — never from argv, so the
/// secret is not visible in the process list or shell history.
pub fn parse_cmd(
    args: &[String],
    read_token: impl FnOnce() -> Result<Vec<u8>, CredentialError>,
) -> Result<CredentialCmd, CredentialError> {
    match args.first().map(String::as_str) {
        Some("set") => {
            let secret_ref = args.get(1).cloned().ok_or_else(|| {
                CredentialError::usage("usage: faradayd credential set <secretRef>")
            })?;
            let token = read_token()?;
            Ok(CredentialCmd::Set { secret_ref, token })
        }
        Some("rm") => {
            let secret_ref = args.get(1).cloned().ok_or_else(|| {
                CredentialError::usage("usage: faradayd credential rm <secretRef>")
            })?;
            Ok(CredentialCmd::Rm { secret_ref })
        }
        Some("list") => Ok(CredentialCmd::List),
        _ => Err(CredentialError::usage(
            "usage: faradayd credential <set|rm|list> [secretRef]",
        )),
    }
}

/// Trim a single trailing `\n` (and a preceding `\r`) from the token.
fn trim_one_newline(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    if end > 0 && bytes[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && bytes[end - 1] == b'\r' {
            end -= 1;
        }
    }
    &bytes[..end]
}

/// Execute a credential command against the OS store `service`. Returns the lines to print
/// (never a secret value). A `set` is rejected unless its `secretRef` names an `api_key`
/// capability in the manifest.
pub fn run_credential(
    cmd: CredentialCmd,
    service: &str,
    policy: &PolicyEngine,
    keychain: &dyn KeychainStore,
) -> Result<Vec<String>, CredentialError> {
    match cmd {
        CredentialCmd::Set { secret_ref, token } => {
            if !policy
                .api_key_secret_refs()
                .iter()
                .any(|r| r == &secret_ref)
            {
                return Err(CredentialError::unknown_ref(&secret_ref));
            }
            let trimmed = trim_one_newline(&token);
            if trimmed.is_empty() {
                return Err(CredentialError::empty());
            }
            keychain
                .set(service, &secret_ref, trimmed)
                .map_err(CredentialError::keychain)?;
            Ok(vec![format!("stored key for '{secret_ref}'")])
        }
        CredentialCmd::Rm { secret_ref } => {
            let existed = keychain
                .delete(service, &secret_ref)
                .map_err(CredentialError::keychain)?;
            if !existed {
                return Err(CredentialError::not_found(&secret_ref));
            }
            Ok(vec![format!("removed key for '{secret_ref}'")])
        }
        CredentialCmd::List => {
            let mut lines = Vec::new();
            for r in policy.api_key_secret_refs() {
                let present = keychain
                    .get(service, &r)
                    .map_err(CredentialError::keychain)?
                    .is_some();
                lines.push(format!(
                    "{r}\t{}",
                    if present { "provisioned" } else { "absent" }
                ));
            }
            Ok(lines)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::test_support::InMemoryKeychain;

    const SVC: &str = "faradayd-test";

    fn manifest_with_api_key() -> PolicyEngine {
        // A single api_key capability `weather.key` (rest kind; secretRef + keyPlacement).
        let json = r#"{"capabilities":{"weather":{"authMode":"api_key","secretRef":"weather.key","keyPlacement":{"header":{"name":"X-API-Key"}},"host":"h","pathAllow":["^/x$"],"methods":["GET"]}}}"#;
        PolicyEngine::load(json, None, &|_, _| false).unwrap()
    }

    #[test]
    fn set_stores_the_trimmed_token_without_echoing_it() {
        let policy = manifest_with_api_key();
        let kc = InMemoryKeychain::default();
        let out = run_credential(
            CredentialCmd::Set {
                secret_ref: "weather.key".to_string(),
                token: b"tok-123\n".to_vec(),
            },
            SVC,
            &policy,
            &kc,
        )
        .unwrap();
        // Stored, newline trimmed.
        assert_eq!(
            kc.get(SVC, "weather.key").unwrap(),
            Some(b"tok-123".to_vec())
        );
        // The printed output never contains the secret value.
        assert!(!out.join(" ").contains("tok-123"));
    }

    #[test]
    fn set_rejects_an_unknown_ref_and_writes_nothing() {
        let policy = manifest_with_api_key();
        let kc = InMemoryKeychain::default();
        let err = run_credential(
            CredentialCmd::Set {
                secret_ref: "unknown.ref".to_string(),
                token: b"tok".to_vec(),
            },
            SVC,
            &policy,
            &kc,
        )
        .unwrap_err();
        assert_eq!(err.code, "CRED_UNKNOWN_REF");
        assert_eq!(kc.get(SVC, "unknown.ref").unwrap(), None);
    }

    #[test]
    fn set_rejects_an_empty_token() {
        let policy = manifest_with_api_key();
        let kc = InMemoryKeychain::default();
        let err = run_credential(
            CredentialCmd::Set {
                secret_ref: "weather.key".to_string(),
                token: b"\n".to_vec(),
            },
            SVC,
            &policy,
            &kc,
        )
        .unwrap_err();
        assert_eq!(err.code, "CRED_EMPTY");
        assert_eq!(kc.get(SVC, "weather.key").unwrap(), None);
    }

    #[test]
    fn rm_deletes_then_reports_not_found() {
        let policy = manifest_with_api_key();
        let kc = InMemoryKeychain::default();
        kc.set(SVC, "weather.key", b"tok").unwrap();
        run_credential(
            CredentialCmd::Rm {
                secret_ref: "weather.key".to_string(),
            },
            SVC,
            &policy,
            &kc,
        )
        .unwrap();
        assert_eq!(kc.get(SVC, "weather.key").unwrap(), None);
        // A second rm reports not-found.
        let err = run_credential(
            CredentialCmd::Rm {
                secret_ref: "weather.key".to_string(),
            },
            SVC,
            &policy,
            &kc,
        )
        .unwrap_err();
        assert_eq!(err.code, "CRED_NOT_FOUND");
    }

    #[test]
    fn list_reports_names_and_status_never_values() {
        let policy = manifest_with_api_key();
        let kc = InMemoryKeychain::default();
        kc.set(SVC, "weather.key", b"super-secret").unwrap();
        let lines = run_credential(CredentialCmd::List, SVC, &policy, &kc).unwrap();
        assert_eq!(lines, vec!["weather.key\tprovisioned".to_string()]);
        assert!(!lines.join(" ").contains("super-secret"));
    }

    // `CredentialCmd` deliberately does NOT derive `Debug` (it holds the token), so these
    // match rather than `unwrap_err()` on a `Result<CredentialCmd, _>`.
    #[test]
    fn parse_cmd_set_without_ref_is_usage_error() {
        match parse_cmd(&["set".to_string()], || Ok(b"tok".to_vec())) {
            Err(e) => assert_eq!(e.code, "CRED_USAGE"),
            Ok(_) => panic!("expected a usage error"),
        }
    }

    #[test]
    fn parse_cmd_unknown_verb_is_usage_error() {
        match parse_cmd(&["frobnicate".to_string()], || Ok(vec![])) {
            Err(e) => assert_eq!(e.code, "CRED_USAGE"),
            Ok(_) => panic!("expected a usage error"),
        }
    }
}

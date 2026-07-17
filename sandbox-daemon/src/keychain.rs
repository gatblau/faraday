//! C1 / ADR-040 — OS-keychain secret seam.
//!
//! A [`KeychainStore`] abstracts the OS secure store (macOS Keychain, Windows Credential
//! Manager, Linux Secret Service) keyed by `(service, account)`. [`KeychainSecretResolver`]
//! reads through it as a [`SecretResolver`](crate::config::SecretResolver) so an `api_key`
//! capability's `secretRef` can resolve from the keychain instead of a file (ADR-040). The
//! write side (`set`/`delete`) backs the `faradayd credential` CLI (C18, a later phase).
//!
//! The key never reaches the guest and is never logged. This module only adds the seam and
//! the read-side resolver; nothing selects it at startup yet — the default remains
//! [`FileSecretResolver`](crate::config::FileSecretResolver).
//!
//! `KeychainStore` intentionally has no `list`: the `keyring` crate exposes no enumeration
//! API, so C18's `credential list` will probe the manifest's `secretRef`s via `get` instead.

use crate::config::{ConfigError, SecretResolver};

/// The OS secure-store seam: read/write/remove a secret keyed by `(service, account)`.
/// One trait serves the read side ([`KeychainSecretResolver`]) and the C18 write side.
/// "Absent" is a successful `Ok(None)` / `Ok(false)`; a real backend fault is a
/// [`KeychainError`].
pub trait KeychainStore: Send + Sync {
    /// The secret bytes for `account` under `service`, or `None` if no such entry exists.
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError>;
    /// Store (creating or overwriting) the secret for `account` under `service`.
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError>;
    /// Remove the entry; `Ok(false)` if it did not exist.
    fn delete(&self, service: &str, account: &str) -> Result<bool, KeychainError>;
}

/// A keychain backend fault — distinct from "absent" (which is `Ok(None)`/`Ok(false)`).
/// The message never contains the secret value.
#[derive(Debug)]
pub struct KeychainError {
    pub message: String,
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keychain error: {}", self.message)
    }
}

impl std::error::Error for KeychainError {}

/// The real OS-store backend, via the `keyring` crate. Entries are stored as UTF-8 strings
/// (the `keyring` password API); an `api_key` token is text.
pub struct KeyringStore;

impl KeyringStore {
    fn entry(service: &str, account: &str) -> Result<keyring::Entry, KeychainError> {
        keyring::Entry::new(service, account).map_err(|e| KeychainError {
            message: e.to_string(),
        })
    }
}

impl KeychainStore for KeyringStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        match Self::entry(service, account)?.get_password() {
            Ok(s) => Ok(Some(s.into_bytes())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KeychainError {
                message: e.to_string(),
            }),
        }
    }

    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let value = std::str::from_utf8(secret).map_err(|_| KeychainError {
            message: "secret is not valid UTF-8".to_string(),
        })?;
        Self::entry(service, account)?
            .set_password(value)
            .map_err(|e| KeychainError {
                message: e.to_string(),
            })
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool, KeychainError> {
        match Self::entry(service, account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KeychainError {
                message: e.to_string(),
            }),
        }
    }
}

/// Reads an `api_key` `secretRef` from the OS store as a [`SecretResolver`] (ADR-040).
/// `resolve(reference)` looks up `(service, account = reference)`; an absent entry or a
/// backend fault both surface as `CFG_SECRET_UNRESOLVED` (fail closed — the daemon never
/// starts a keychain-mode `api_key` capability without its key).
pub struct KeychainSecretResolver {
    store: Box<dyn KeychainStore>,
    service: String,
}

impl KeychainSecretResolver {
    pub fn new(store: Box<dyn KeychainStore>, service: impl Into<String>) -> Self {
        Self {
            store,
            service: service.into(),
        }
    }
}

impl SecretResolver for KeychainSecretResolver {
    fn resolve(&self, reference: &str) -> Result<Vec<u8>, ConfigError> {
        match self.store.get(&self.service, reference) {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) | Err(_) => Err(ConfigError {
                code: "CFG_SECRET_UNRESOLVED",
                field: reference.to_string(),
            }),
        }
    }
}

/// Which secret backend the daemon resolves `*_REF` config secrets and `api_key`
/// `secretRef`s through (ADR-040), selected once at startup from `PYS_SECRET_RESOLVER`.
#[derive(Debug)]
pub enum ResolverKind {
    File,
    Keychain { service: String },
}

/// Read `PYS_SECRET_RESOLVER` (`file` default | `keychain`) and, for keychain,
/// `PYS_KEYCHAIN_SERVICE` (default `faradayd`). An unknown selector fails closed
/// (`CFG_INVALID`) so a misconfigured deployment never silently falls back to files.
pub fn resolver_kind(env: &dyn Fn(&str) -> Option<String>) -> Result<ResolverKind, ConfigError> {
    match env("PYS_SECRET_RESOLVER").as_deref() {
        None | Some("file") => Ok(ResolverKind::File),
        Some("keychain") => Ok(ResolverKind::Keychain {
            service: env("PYS_KEYCHAIN_SERVICE").unwrap_or_else(|| "faradayd".to_string()),
        }),
        Some(_) => Err(ConfigError {
            code: "CFG_INVALID",
            field: "PYS_SECRET_RESOLVER".to_string(),
        }),
    }
}

/// Construct the production `SecretResolver` for a [`ResolverKind`] — the keychain variant
/// uses the real [`KeyringStore`]. The daemon injects the result into `Config::load` and the
/// api_key freeze (`broker::freeze_api_keys`).
pub fn build_resolver(kind: ResolverKind) -> Box<dyn SecretResolver> {
    match kind {
        ResolverKind::File => Box::new(crate::config::FileSecretResolver),
        ResolverKind::Keychain { service } => {
            Box::new(KeychainSecretResolver::new(Box::new(KeyringStore), service))
        }
    }
}

/// Test-only support shared across the crate's `#[cfg(test)]` modules (keychain + credential).
#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// An in-memory [`KeychainStore`] test double, keyed by `(service, account)`. Mirrors the
    /// `StubResolver` pattern in `config.rs` — the materialised stub honouring the store
    /// contract, so the resolver is exercised without touching a real OS keychain (the
    /// real-`keyring` smoke test is deferred to FU-001).
    #[derive(Default)]
    pub struct InMemoryKeychain {
        entries: Mutex<HashMap<(String, String), Vec<u8>>>,
    }

    impl KeychainStore for InMemoryKeychain {
        fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .get(&(service.to_string(), account.to_string()))
                .cloned())
        }

        fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
            self.entries
                .lock()
                .unwrap()
                .insert((service.to_string(), account.to_string()), secret.to_vec());
            Ok(())
        }

        fn delete(&self, service: &str, account: &str) -> Result<bool, KeychainError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .remove(&(service.to_string(), account.to_string()))
                .is_some())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::InMemoryKeychain;
    use super::*;
    use std::collections::HashMap;

    const SVC: &str = "faradayd-test";

    #[test]
    fn resolves_a_present_key_to_its_bytes() {
        let store = InMemoryKeychain::default();
        store.set(SVC, "weather.key", b"tok-123").unwrap();
        let resolver = KeychainSecretResolver::new(Box::new(store), SVC);
        assert_eq!(
            resolver.resolve("weather.key").unwrap(),
            b"tok-123".to_vec()
        );
    }

    #[test]
    fn absent_key_is_cfg_secret_unresolved() {
        let resolver = KeychainSecretResolver::new(Box::new(InMemoryKeychain::default()), SVC);
        let err = resolver.resolve("missing.key").unwrap_err();
        assert_eq!(err.code, "CFG_SECRET_UNRESOLVED");
        assert_eq!(err.field, "missing.key");
    }

    #[test]
    fn set_then_get_round_trips() {
        let store = InMemoryKeychain::default();
        assert_eq!(store.get(SVC, "k").unwrap(), None);
        store.set(SVC, "k", b"v").unwrap();
        assert_eq!(store.get(SVC, "k").unwrap(), Some(b"v".to_vec()));
        assert!(store.delete(SVC, "k").unwrap());
        assert_eq!(store.get(SVC, "k").unwrap(), None);
        assert!(!store.delete(SVC, "k").unwrap());
    }

    #[test]
    fn service_scopes_the_lookup() {
        let store = InMemoryKeychain::default();
        store.set("svc-a", "k", b"a").unwrap();
        let resolver = KeychainSecretResolver::new(Box::new(store), "svc-b");
        // Same account, different service ⇒ not found.
        assert_eq!(
            resolver.resolve("k").unwrap_err().code,
            "CFG_SECRET_UNRESOLVED"
        );
    }

    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn resolver_kind_defaults_to_file() {
        assert!(matches!(
            resolver_kind(&env_from(&[])).unwrap(),
            ResolverKind::File
        ));
    }

    #[test]
    fn resolver_kind_keychain_uses_default_service() {
        match resolver_kind(&env_from(&[("PYS_SECRET_RESOLVER", "keychain")])).unwrap() {
            ResolverKind::Keychain { service } => assert_eq!(service, "faradayd"),
            ResolverKind::File => panic!("expected keychain"),
        }
    }

    #[test]
    fn resolver_kind_keychain_honours_service_override() {
        match resolver_kind(&env_from(&[
            ("PYS_SECRET_RESOLVER", "keychain"),
            ("PYS_KEYCHAIN_SERVICE", "acme"),
        ]))
        .unwrap()
        {
            ResolverKind::Keychain { service } => assert_eq!(service, "acme"),
            ResolverKind::File => panic!("expected keychain"),
        }
    }

    #[test]
    fn resolver_kind_unknown_fails_closed() {
        let err = resolver_kind(&env_from(&[("PYS_SECRET_RESOLVER", "vault")])).unwrap_err();
        assert_eq!(err.code, "CFG_INVALID");
        assert_eq!(err.field, "PYS_SECRET_RESOLVER");
    }

    #[test]
    fn freeze_api_keys_resolves_from_keychain_and_trims_newline() {
        let store = InMemoryKeychain::default();
        store.set(SVC, "weather.key", b"tok-123\n").unwrap();
        let resolver = KeychainSecretResolver::new(Box::new(store), SVC);
        let map =
            crate::broker::freeze_api_keys(vec!["weather.key".to_string()], &resolver).unwrap();
        assert_eq!(map.get("weather.key").unwrap(), "tok-123");
    }

    #[test]
    fn freeze_api_keys_fails_closed_on_missing_key() {
        let resolver = KeychainSecretResolver::new(Box::new(InMemoryKeychain::default()), SVC);
        let err =
            crate::broker::freeze_api_keys(vec!["missing.key".to_string()], &resolver).unwrap_err();
        assert_eq!(err.code, "CFG_SECRET_UNRESOLVED");
    }
}

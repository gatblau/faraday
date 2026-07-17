//! Plan 03 / FU-001 — real-OS-keychain smoke test (opt-in, per-OS).
//!
//! Exercises the **real** [`KeyringStore`] against the host's OS secure store (macOS
//! Keychain / Windows Credential Manager / Linux Secret Service) — the one ADR-040 path the
//! in-memory `KeychainStore` fake cannot cover. Opt-in behind the `real-keyring` feature so
//! it never runs under default `cargo test` or the Docker `integration` job; a per-OS run
//! (`cargo test --features real-keyring`) enables it where a backend exists.
//!
//! The `(service, account)` is unique per process so parallel runs and real entries are not
//! clobbered, and a `Drop` guard guarantees the entry is removed even if an assertion fails.
#![cfg(feature = "real-keyring")]

use faradayd::keychain::{KeychainStore, KeyringStore};

/// Best-effort cleanup: always attempt a final delete, even on a panicking assertion, so a
/// failed run leaves no `faradayd-smoke-*` entry behind in the real keychain.
struct Cleanup<'a> {
    store: &'a KeyringStore,
    service: String,
    account: &'a str,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let _ = self.store.delete(&self.service, self.account);
    }
}

#[test]
fn real_keyring_set_get_delete_roundtrip() {
    let store = KeyringStore;
    let service = format!("faradayd-smoke-{}", std::process::id());
    let account = "k";
    const VALUE: &[u8] = b"real-roundtrip";

    let _guard = Cleanup {
        store: &store,
        service: service.clone(),
        account,
    };

    // Absent to begin with.
    assert_eq!(store.get(&service, account).expect("get(before)"), None);

    // Set, then read back byte-identical.
    store.set(&service, account, VALUE).expect("set");
    assert_eq!(
        store
            .get(&service, account)
            .expect("get(after set)")
            .as_deref(),
        Some(VALUE),
        "the value read back from the real keychain matches what was written"
    );

    // Delete removes it; a second delete is idempotent-false.
    assert!(
        store.delete(&service, account).expect("delete"),
        "delete reports the entry existed"
    );
    assert_eq!(
        store.get(&service, account).expect("get(after delete)"),
        None,
        "the entry is gone after delete"
    );
    assert!(
        !store.delete(&service, account).expect("delete(second)"),
        "a second delete finds nothing"
    );
}

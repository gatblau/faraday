//! C6 — ClientAuth (security-critical, ADR-024). Authenticates a connecting peer:
//! the peer principal must equal the daemon's, the presented connection token must
//! match (constant-time), and a new client identity must pass first-connect consent.

use crate::errors::WireError;
use crate::types::ClientIdentity;
use std::collections::HashSet;
use std::sync::Mutex;

/// The server-derived peer identity now lives in the `faradayd-ipc` transport seam
/// (windows-deployment phase 2), re-exported here so call sites keep `clientauth::PeerPrincipal`.
pub use faradayd_ipc::PeerPrincipal;

pub struct ClientAuth {
    daemon: PeerPrincipal,
    token: Vec<u8>,
    seen: Mutex<HashSet<String>>,
}

impl ClientAuth {
    pub fn new(daemon: PeerPrincipal, token: Vec<u8>) -> Self {
        ClientAuth {
            daemon,
            token,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Authenticate a connection. `peer` is server-derived (e.g. via
    /// `UnixStream::peer_cred`), never client-asserted. `first_connect_consent` is the
    /// daemon-owned approval for a previously-unseen client identity (rendered by C8).
    pub fn authenticate(
        &self,
        peer: PeerPrincipal,
        presented_token: &[u8],
        client_label: &str,
        first_connect_consent: &dyn Fn(&str) -> bool,
    ) -> Result<ClientIdentity, WireError> {
        if peer != self.daemon {
            return Err(WireError::new(
                "CLIENT_UID_DENIED",
                "peer principal mismatch",
            ));
        }
        if !constant_time_eq(presented_token, &self.token) {
            return Err(WireError::new(
                "CLIENT_TOKEN_DENIED",
                "invalid connection token",
            ));
        }
        let mut seen = self.seen.lock().unwrap();
        if !seen.contains(client_label) {
            if !first_connect_consent(client_label) {
                return Err(WireError::new("CLIENT_NOT_APPROVED", "client not approved"));
            }
            seen.insert(client_label.to_string());
        }
        Ok(ClientIdentity {
            principal: peer.as_principal(),
            client_label: client_label.to_string(),
        })
    }
}

/// Length-checked constant-time byte comparison of the connection token.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

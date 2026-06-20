//! C6 — ClientAuth (security-critical, ADR-024). Authenticates a connecting peer:
//! the peer UID must equal the daemon's, the presented connection token must match
//! (constant-time), and a new client identity must pass first-connect consent.

use crate::errors::WireError;
use crate::types::ClientIdentity;
use std::collections::HashSet;
use std::sync::Mutex;

pub struct ClientAuth {
    daemon_uid: u32,
    token: Vec<u8>,
    seen: Mutex<HashSet<String>>,
}

impl ClientAuth {
    pub fn new(daemon_uid: u32, token: Vec<u8>) -> Self {
        ClientAuth {
            daemon_uid,
            token,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Authenticate a connection. `peer_uid` is server-derived (e.g. via
    /// `UnixStream::peer_cred`), never client-asserted. `first_connect_consent` is the
    /// daemon-owned approval for a previously-unseen client identity (rendered by C8).
    pub fn authenticate(
        &self,
        peer_uid: u32,
        presented_token: &[u8],
        client_label: &str,
        first_connect_consent: &dyn Fn(&str) -> bool,
    ) -> Result<ClientIdentity, WireError> {
        if peer_uid != self.daemon_uid {
            return Err(WireError::new("CLIENT_UID_DENIED", "peer uid mismatch"));
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
            peer_uid,
            client_label: client_label.to_string(),
        })
    }
}

/// Mint a 128-bit CSPRNG connection token (hex). Reads `/dev/urandom` on unix.
#[cfg(unix)]
pub fn mint_token() -> std::io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
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

//! C7 — SessionManager. In-memory `(client, workspace)` sessions: consent cache +
//! per-session call budget. Dropped on daemon stop (never persisted).

use crate::errors::WireError;
use crate::types::{ClientIdentity, Session};
use std::collections::HashMap;
use std::sync::Mutex;

type Key = (String, String, String);

pub struct SessionManager {
    max_per_session: u32,
    sessions: Mutex<HashMap<Key, Session>>,
}

impl SessionManager {
    pub fn new(max_per_session: u32) -> Self {
        SessionManager {
            max_per_session,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn key(client: &ClientIdentity, workspace: &str) -> Key {
        (
            client.principal.clone(),
            client.client_label.clone(),
            workspace.to_string(),
        )
    }

    fn ensure<'a>(
        map: &'a mut HashMap<Key, Session>,
        c: &ClientIdentity,
        ws: &str,
    ) -> &'a mut Session {
        map.entry(Self::key(c, ws)).or_insert_with(|| Session {
            client: c.clone(),
            workspace_id: ws.to_string(),
            consented: Default::default(),
            calls_used: 0,
        })
    }

    pub fn is_consented(&self, c: &ClientIdentity, ws: &str, cap_id: &str) -> bool {
        let map = self.sessions.lock().unwrap();
        map.get(&Self::key(c, ws))
            .map(|s| s.consented.contains(cap_id))
            .unwrap_or(false)
    }

    pub fn record_consent(&self, c: &ClientIdentity, ws: &str, cap_id: &str) {
        let mut map = self.sessions.lock().unwrap();
        Self::ensure(&mut map, c, ws)
            .consented
            .insert(cap_id.to_string());
    }

    /// Charge one call against the per-session budget; over budget → `RATE_LIMITED`.
    pub fn try_charge(&self, c: &ClientIdentity, ws: &str) -> Result<(), WireError> {
        let mut map = self.sessions.lock().unwrap();
        let s = Self::ensure(&mut map, c, ws);
        if s.calls_used + 1 > self.max_per_session {
            return Err(WireError::new("RATE_LIMITED", "session budget exceeded"));
        }
        s.calls_used += 1;
        Ok(())
    }
}

//! C14 — ControlEndpoint. Listens on the local control socket, authenticates each
//! connection (C6 ClientAuth: peer principal + the connection token, ADR-024), binds
//! a session, and accepts the single `run` entry over a length-prefixed JSON native
//! RPC **and** a single `python_sandbox` MCP tool, dispatching to the SandboxController
//! (C13). Health/readiness (C15) are answerable without auth. Never network-bound.
//!
//! The platform-specific local transport (Unix-domain socket + `SO_PEERCRED`, or the
//! Windows named pipe) lives behind the `faradayd-ipc` seam; this module owns only the
//! wire protocol on top of [`faradayd_ipc::Connection`].

use crate::clientauth::ClientAuth;
use crate::config::Config;
use crate::controller::{RunOutcome, SandboxController};
use crate::health::HealthCheck;
use crate::types::{ClientIdentity, RunRequest, SessionHandle};
use faradayd_ipc::{Connection, Listener, PeerPrincipal};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_CODE_BYTES: usize = 1024 * 1024;
const MAX_REQUESTED_CAPS: usize = 64;
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// In-flight-run tracker for graceful shutdown (XC10): each connection holds a guard;
/// `wait_idle` blocks (bounded) until all guards drop.
struct Drain {
    count: Mutex<usize>,
}
impl Drain {
    fn new() -> Drain {
        Drain {
            count: Mutex::new(0),
        }
    }
    fn enter(&self) {
        *self.count.lock().unwrap() += 1;
    }
    fn leave(&self) {
        let mut c = self.count.lock().unwrap();
        *c = c.saturating_sub(1);
    }
    async fn wait_idle(&self, deadline: Duration) {
        let start = Instant::now();
        loop {
            if *self.count.lock().unwrap() == 0 || start.elapsed() > deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
struct DrainGuard(Arc<Drain>);
impl DrainGuard {
    fn new(d: Arc<Drain>) -> DrainGuard {
        d.enter();
        DrainGuard(d)
    }
}
impl Drop for DrainGuard {
    fn drop(&mut self) {
        self.0.leave();
    }
}

struct Inner {
    token: String,
    daemon: PeerPrincipal,
    controller: Arc<SandboxController>,
    health: Arc<HealthCheck>,
    drain: Arc<Drain>,
}

/// A bound, assembled daemon: the control socket is listening, the connection-token
/// file is written, and the controller + health check are wired in.
pub struct Daemon {
    config: Config,
    listener: Listener,
    inner: Arc<Inner>,
}

impl Daemon {
    /// Bind the control socket, mint + write the connection token, and wire the
    /// controller + health check. Must run within a Tokio runtime. On a platform whose
    /// transport is not yet implemented the bind fails with `Unsupported`.
    pub fn bind(
        config: Config,
        controller: Arc<SandboxController>,
        health: Arc<HealthCheck>,
    ) -> std::io::Result<Daemon> {
        let listener = Listener::bind(&config.socket_path, &config.token_path)?;
        let inner = Arc::new(Inner {
            token: listener.token().to_string(),
            daemon: listener.daemon_principal().clone(),
            controller,
            health,
            drain: Arc::new(Drain::new()),
        });
        Ok(Daemon {
            config,
            listener,
            inner,
        })
    }

    pub fn socket_path(&self) -> &str {
        &self.config.socket_path
    }

    /// The minted connection token (production clients read it from the `0600` file;
    /// tests read it here).
    pub fn connection_token(&self) -> &str {
        &self.inner.token
    }

    pub fn token_path(&self) -> &str {
        &self.config.token_path
    }

    /// Accept connections forever; each is authenticated and served concurrently.
    pub async fn serve(self) -> std::io::Result<()> {
        loop {
            let (conn, peer) = self.listener.accept().await?;
            let inner = self.inner.clone();
            tokio::spawn(async move {
                let _ = handle(inner, conn, peer).await;
            });
        }
    }

    /// Accept connections until `shutdown` resolves, then stop accepting and **drain
    /// in-flight runs** (bounded by `DRAIN_DEADLINE`) before returning (XC10).
    pub async fn serve_with_shutdown(
        self,
        shutdown: impl Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (conn, peer) = accepted?;
                    let inner = self.inner.clone();
                    tokio::spawn(async move {
                        let _ = handle(inner, conn, peer).await;
                    });
                }
                _ = &mut shutdown => break,
            }
        }
        self.inner.drain.wait_idle(DRAIN_DEADLINE).await;
        Ok(())
    }
}

async fn write_json(conn: &mut Connection, v: &serde_json::Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(v).unwrap_or_else(|_| b"{\"code\":\"INTERNAL\"}".to_vec());
    conn.write_frame(&bytes).await
}

async fn write_err(conn: &mut Connection, code: &str, msg: &str) -> std::io::Result<()> {
    write_json(conn, &serde_json::json!({ "error": msg, "code": code })).await
}

async fn handle(
    inner: Arc<Inner>,
    mut conn: Connection,
    peer: PeerPrincipal,
) -> std::io::Result<()> {
    // Count this connection in the graceful-shutdown drain (XC10).
    let _drain_guard = DrainGuard::new(inner.drain.clone());
    let mut authed: Option<ClientIdentity> = None;
    let mut workspace = String::new();

    while let Some(frame) = conn.read_frame().await? {
        let v: serde_json::Value = match serde_json::from_slice(&frame) {
            Ok(v) => v,
            Err(_) => {
                write_err(&mut conn, "VAL_ERR", "malformed frame").await?;
                continue;
            }
        };
        let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match typ {
            "health" => {
                write_json(&mut conn, &serde_json::json!({ "live": true })).await?;
            }
            "ready" => {
                let (ready, failed) = inner.health.ready().await;
                write_json(
                    &mut conn,
                    &serde_json::json!({ "ready": ready, "failed": failed }),
                )
                .await?;
            }
            "connect" => {
                let label = v.get("clientLabel").and_then(|x| x.as_str()).unwrap_or("");
                let token = v.get("token").and_then(|x| x.as_str()).unwrap_or("");
                workspace = v
                    .get("workspaceId")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let auth = ClientAuth::new(inner.daemon.clone(), inner.token.as_bytes().to_vec());
                match auth.authenticate(peer.clone(), token.as_bytes(), label, &|_| true) {
                    Ok(id) => {
                        authed = Some(id);
                        write_json(&mut conn, &serde_json::json!({ "type": "connected" })).await?;
                    }
                    Err(e) => {
                        // Refuse before any run, and close the connection.
                        write_err(&mut conn, &e.code, &e.error).await?;
                        return Ok(());
                    }
                }
            }
            "run" | "mcp" => {
                let client = match &authed {
                    Some(id) => id.clone(),
                    None => {
                        write_err(&mut conn, "CLIENT_TOKEN_DENIED", "connect first").await?;
                        continue;
                    }
                };
                let field = if typ == "run" { "request" } else { "arguments" };
                let req: RunRequest = match v
                    .get(field)
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                {
                    Ok(Some(r)) => r,
                    _ => {
                        write_err(&mut conn, "VAL_ERR", "invalid RunRequest").await?;
                        continue;
                    }
                };
                // XC9 — strict input validation before any orchestration.
                if req.code.trim().is_empty()
                    || req.code.len() > MAX_CODE_BYTES
                    || req.requested_capabilities.len() > MAX_REQUESTED_CAPS
                {
                    write_err(&mut conn, "VAL_ERR", "run request failed validation").await?;
                    continue;
                }
                let ws = if req.workspace_id.is_empty() {
                    workspace.clone()
                } else {
                    req.workspace_id.clone()
                };
                let handle = SessionHandle {
                    client: client.clone(),
                    workspace_id: ws,
                };
                match inner.controller.run(req, handle).await {
                    Ok(RunOutcome::Run(r)) => {
                        write_json(
                            &mut conn,
                            &serde_json::json!({ "type": "result", "result": r }),
                        )
                        .await?;
                    }
                    Ok(RunOutcome::DryRun(d)) => {
                        write_json(
                            &mut conn,
                            &serde_json::json!({ "type": "dryRun", "result": d }),
                        )
                        .await?;
                    }
                    Err(e) => {
                        write_err(&mut conn, e.code(), "run failed").await?;
                    }
                }
            }
            _ => {
                write_err(&mut conn, "VAL_ERR", "unknown request type").await?;
            }
        }
    }
    Ok(())
}

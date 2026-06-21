//! C14 — ControlEndpoint. Listens on the local control socket, authenticates each
//! connection (C6 ClientAuth: peer-UID + the `0600` connection token, ADR-024), binds
//! a session, and accepts the single `run` entry over a length-prefixed JSON native
//! RPC **and** a single `python_sandbox` MCP tool, dispatching to the SandboxController
//! (C13). Health/readiness (C15) are answerable without auth. Never network-bound.

use crate::config::Config;

#[cfg(unix)]
mod unix_impl {
    use super::Config;
    use crate::clientauth::{ClientAuth, PeerPrincipal};
    use crate::controller::{RunOutcome, SandboxController};
    use crate::health::HealthCheck;
    use crate::types::{ClientIdentity, RunRequest, SessionHandle};
    use std::future::Future;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    const MAX_FRAME: usize = 8 * 1024 * 1024;
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
        expected_uid: u32,
        controller: Arc<SandboxController>,
        health: Arc<HealthCheck>,
        drain: Arc<Drain>,
    }

    /// A bound, assembled daemon: the control socket is listening, the connection-token
    /// file is written, and the controller + health check are wired in.
    pub struct Daemon {
        config: Config,
        listener: UnixListener,
        inner: Arc<Inner>,
    }

    impl Daemon {
        /// Bind the `0600` control socket, mint + write the `0600` connection token, and
        /// wire the controller + health check. Must run within a Tokio runtime.
        pub fn bind(
            config: Config,
            controller: Arc<SandboxController>,
            health: Arc<HealthCheck>,
        ) -> std::io::Result<Daemon> {
            let _ = std::fs::remove_file(&config.socket_path);
            let listener = UnixListener::bind(&config.socket_path)?;
            std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;

            let token = mint_token()?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&config.token_path)?;
            f.write_all(token.as_bytes())?;
            // The expected peer is the OS user that owns the token file — i.e. this daemon.
            let expected_uid = std::fs::metadata(&config.token_path)?.uid();

            let inner = Arc::new(Inner {
                token,
                expected_uid,
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
                let (stream, _addr) = self.listener.accept().await?;
                let inner = self.inner.clone();
                tokio::spawn(async move {
                    let _ = handle(inner, stream).await;
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
                        let (stream, _addr) = accepted?;
                        let inner = self.inner.clone();
                        tokio::spawn(async move {
                            let _ = handle(inner, stream).await;
                        });
                    }
                    _ = &mut shutdown => break,
                }
            }
            self.inner.drain.wait_idle(DRAIN_DEADLINE).await;
            Ok(())
        }
    }

    async fn read_frame(stream: &mut UnixStream) -> std::io::Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(Some(buf))
    }

    async fn write_json(stream: &mut UnixStream, v: &serde_json::Value) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(v).unwrap_or_else(|_| b"{\"code\":\"INTERNAL\"}".to_vec());
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&bytes).await?;
        Ok(())
    }

    async fn write_err(stream: &mut UnixStream, code: &str, msg: &str) -> std::io::Result<()> {
        write_json(stream, &serde_json::json!({ "error": msg, "code": code })).await
    }

    async fn handle(inner: Arc<Inner>, mut stream: UnixStream) -> std::io::Result<()> {
        // Count this connection in the graceful-shutdown drain (XC10).
        let _drain_guard = DrainGuard::new(inner.drain.clone());
        let peer_uid = stream.peer_cred()?.uid();
        let mut authed: Option<ClientIdentity> = None;
        let mut workspace = String::new();

        while let Some(frame) = read_frame(&mut stream).await? {
            let v: serde_json::Value = match serde_json::from_slice(&frame) {
                Ok(v) => v,
                Err(_) => {
                    write_err(&mut stream, "VAL_ERR", "malformed frame").await?;
                    continue;
                }
            };
            let typ = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match typ {
                "health" => {
                    write_json(&mut stream, &serde_json::json!({ "live": true })).await?;
                }
                "ready" => {
                    let (ready, failed) = inner.health.ready().await;
                    write_json(
                        &mut stream,
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
                    let auth = ClientAuth::new(
                        PeerPrincipal::Unix(inner.expected_uid),
                        inner.token.as_bytes().to_vec(),
                    );
                    match auth.authenticate(
                        PeerPrincipal::Unix(peer_uid),
                        token.as_bytes(),
                        label,
                        &|_| true,
                    ) {
                        Ok(id) => {
                            authed = Some(id);
                            write_json(&mut stream, &serde_json::json!({ "type": "connected" }))
                                .await?;
                        }
                        Err(e) => {
                            // Refuse before any run, and close the connection.
                            write_err(&mut stream, &e.code, &e.error).await?;
                            return Ok(());
                        }
                    }
                }
                "run" | "mcp" => {
                    let client = match &authed {
                        Some(id) => id.clone(),
                        None => {
                            write_err(&mut stream, "CLIENT_TOKEN_DENIED", "connect first").await?;
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
                            write_err(&mut stream, "VAL_ERR", "invalid RunRequest").await?;
                            continue;
                        }
                    };
                    // XC9 — strict input validation before any orchestration.
                    if req.code.trim().is_empty()
                        || req.code.len() > MAX_CODE_BYTES
                        || req.requested_capabilities.len() > MAX_REQUESTED_CAPS
                    {
                        write_err(&mut stream, "VAL_ERR", "run request failed validation").await?;
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
                                &mut stream,
                                &serde_json::json!({ "type": "result", "result": r }),
                            )
                            .await?;
                        }
                        Ok(RunOutcome::DryRun(d)) => {
                            write_json(
                                &mut stream,
                                &serde_json::json!({ "type": "dryRun", "result": d }),
                            )
                            .await?;
                        }
                        Err(e) => {
                            write_err(&mut stream, e.code(), "run failed").await?;
                        }
                    }
                }
                _ => {
                    write_err(&mut stream, "VAL_ERR", "unknown request type").await?;
                }
            }
        }
        Ok(())
    }

    /// Mint a 128-bit CSPRNG connection token (hex) from `/dev/urandom`.
    fn mint_token() -> std::io::Result<String> {
        let mut bytes = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
}

#[cfg(unix)]
pub use unix_impl::Daemon;

#[cfg(not(unix))]
mod stub {
    use super::Config;
    use crate::controller::SandboxController;
    use crate::health::HealthCheck;
    use std::sync::Arc;

    pub struct Daemon;

    impl Daemon {
        pub fn bind(
            _config: Config,
            _controller: Arc<SandboxController>,
            _health: Arc<HealthCheck>,
        ) -> std::io::Result<Daemon> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "named-pipe transport is implemented in a later phase",
            ))
        }
        pub async fn serve(self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(not(unix))]
pub use stub::Daemon;

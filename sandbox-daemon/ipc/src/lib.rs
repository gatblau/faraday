//! faradayd-ipc — the local control-plane IPC seam (windows-deployment phase 2).
//!
//! Houses everything platform-specific about the daemon's local control transport so the
//! daemon's wire protocol (C14 ControlEndpoint) and MCP front door (C16) stay
//! platform-neutral:
//!
//! * [`PeerPrincipal`] — the server-derived peer identity (ADR-024), opaque across OSes.
//! * [`Listener`] / [`Connection`] — the server transport seam: bind the local control
//!   socket with the right permissions, accept connections, and frame messages.
//! * [`connect`] — the client transport for the MCP front door.
//! * [`mint_token`] — the cross-platform CSPRNG connection-token mint.
//!
//! Unix uses a `0600` Unix-domain socket + `SO_PEERCRED`. The Windows named-pipe + SID
//! peer-auth implementation lands in phase 3 (windows-peer-auth.md §4–§5); until then the
//! Windows half is a stub that fails closed with `Unsupported`.

use std::io;

/// The server-derived identity of a connecting peer (never client-asserted). Unix uses
/// the numeric UID; a `Windows(sid)` variant lands in phase 3 (windows-peer-auth §4).
/// Rendered to the opaque, platform-neutral string stored in the daemon's
/// `ClientIdentity.principal` via [`PeerPrincipal::as_principal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPrincipal {
    Unix(u32),
}

impl PeerPrincipal {
    /// The opaque, platform-neutral string form: the decimal UID on Unix — a lossless
    /// re-encoding of the integer UID, so a `principal`-keyed session means exactly what
    /// the old `peer_uid`-keyed session meant.
    pub fn as_principal(&self) -> String {
        match self {
            PeerPrincipal::Unix(uid) => uid.to_string(),
        }
    }
}

/// The largest control frame accepted on the local transport (8 MiB), bounding the
/// per-frame allocation a peer can force before authentication. Used by the Unix
/// transport; the Windows half is a stub that frames nothing until phase 3.
#[cfg(unix)]
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Mint a 128-bit CSPRNG connection token (hex). Uses the OS CSPRNG via `getrandom`
/// (`/dev/urandom` family on Unix, `BCryptGenRandom` on Windows) — one source replacing
/// the two `/dev/urandom` copies the daemon previously carried.
pub fn mint_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(not(unix))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "named-pipe transport is implemented in a later phase",
    )
}

// ---- Unix transport: a 0600 Unix-domain socket authenticated by SO_PEERCRED ----

#[cfg(unix)]
mod unix_impl {
    use super::{PeerPrincipal, MAX_FRAME};
    use std::io::{self, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};

    /// The bound server transport: a listening `0600` Unix-domain socket, the minted
    /// connection token, and this daemon's own principal (the token-file owner).
    pub struct Listener {
        inner: UnixListener,
        token: String,
        daemon: PeerPrincipal,
    }

    impl Listener {
        /// Remove any stale socket, bind a `0600` Unix-domain socket at `socket_path`,
        /// mint + write the `0600` connection-token file at `token_path`, and capture the
        /// daemon's own principal (the token-file owner UID). Must run within a Tokio
        /// runtime.
        pub fn bind(socket_path: &str, token_path: &str) -> io::Result<Listener> {
            let _ = std::fs::remove_file(socket_path);
            let inner = UnixListener::bind(socket_path)?;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

            let token = super::mint_token()?;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(token_path)?;
            f.write_all(token.as_bytes())?;
            // The expected peer is the OS user that owns the token file — i.e. this daemon.
            let uid = std::fs::metadata(token_path)?.uid();

            Ok(Listener {
                inner,
                token,
                daemon: PeerPrincipal::Unix(uid),
            })
        }

        /// The minted connection token (production clients read it from the `0600` file;
        /// tests read it here).
        pub fn token(&self) -> &str {
            &self.token
        }

        /// This daemon's own principal — the expected peer for an authenticated client.
        pub fn daemon_principal(&self) -> &PeerPrincipal {
            &self.daemon
        }

        /// Accept the next connection, deriving its peer principal from `SO_PEERCRED`.
        pub async fn accept(&self) -> io::Result<(Connection, PeerPrincipal)> {
            let (stream, _addr) = self.inner.accept().await?;
            let uid = stream.peer_cred()?.uid();
            Ok((Connection { stream }, PeerPrincipal::Unix(uid)))
        }
    }

    /// A framed control connection: a 4-byte big-endian length prefix then the payload.
    pub struct Connection {
        stream: UnixStream,
    }

    impl Connection {
        /// Read one length-prefixed frame; `Ok(None)` at a clean EOF. A length above
        /// [`MAX_FRAME`] is rejected before the buffer is allocated.
        pub async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            let mut len_buf = [0u8; 4];
            match self.stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            let mut buf = vec![0u8; len];
            self.stream.read_exact(&mut buf).await?;
            Ok(Some(buf))
        }

        /// Write one length-prefixed frame and flush.
        pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
            self.stream
                .write_all(&(payload.len() as u32).to_be_bytes())
                .await?;
            self.stream.write_all(payload).await?;
            self.stream.flush().await
        }
    }

    /// Connect to the daemon control socket at `socket_path` as a client (MCP front door).
    pub async fn connect(socket_path: &str) -> io::Result<Connection> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Connection { stream })
    }
}

#[cfg(unix)]
pub use unix_impl::{connect, Connection, Listener};

// ---- Windows transport: stubbed until phase 3 (windows-peer-auth.md §4–§5) ----

#[cfg(not(unix))]
mod stub_impl {
    use super::{unsupported, PeerPrincipal};
    use std::io;

    /// Stub server transport. A real named-pipe `Listener` lands in phase 3; until then
    /// [`Listener::bind`] fails closed so the daemon refuses to start on Windows.
    pub struct Listener {
        _private: (),
    }

    impl Listener {
        pub fn bind(_socket_path: &str, _token_path: &str) -> io::Result<Listener> {
            Err(unsupported())
        }
        pub fn token(&self) -> &str {
            ""
        }
        pub fn daemon_principal(&self) -> &PeerPrincipal {
            unreachable!("a stub Listener is never constructed")
        }
        pub async fn accept(&self) -> io::Result<(Connection, PeerPrincipal)> {
            Err(unsupported())
        }
    }

    /// Stub connection: a real named-pipe `Connection` lands in phase 3.
    pub struct Connection {
        _private: (),
    }

    impl Connection {
        pub async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            Err(unsupported())
        }
        pub async fn write_frame(&mut self, _payload: &[u8]) -> io::Result<()> {
            Err(unsupported())
        }
    }

    pub async fn connect(_socket_path: &str) -> io::Result<Connection> {
        Err(unsupported())
    }
}

#[cfg(not(unix))]
pub use stub_impl::{connect, Connection, Listener};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_token_is_32_hex_chars() {
        let t = mint_token().expect("mint");
        assert_eq!(t.len(), 32, "128 bits as hex");
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()), "hex only");
        assert_ne!(t, mint_token().expect("mint"), "two mints differ");
    }

    #[test]
    fn unix_principal_is_decimal_uid() {
        assert_eq!(PeerPrincipal::Unix(501).as_principal(), "501");
        assert_eq!(PeerPrincipal::Unix(0).as_principal(), "0");
    }

    // The Windows half is a stub until phase 3: bind and connect must fail closed so the
    // daemon never starts an unauthenticated transport on Windows.
    // `.err().expect(...)` rather than `.unwrap_err()`: the Ok types (Listener/Connection)
    // are transport handles with no Debug impl, and unwrap_err would require one.
    #[cfg(windows)]
    #[tokio::test]
    async fn windows_bind_is_unsupported_until_phase_3() {
        let err = Listener::bind(r"\\.\pipe\faradayd-test", "token.tmp")
            .err()
            .expect("bind must fail closed until phase 3");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_connect_is_unsupported_until_phase_3() {
        let err = connect(r"\\.\pipe\faradayd-test")
            .await
            .err()
            .expect("connect must fail closed until phase 3");
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}

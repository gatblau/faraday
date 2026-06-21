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

/// The server-derived identity of a connecting peer (never client-asserted, ADR-024).
/// Unix uses the numeric UID; Windows uses the connecting client's **user SID**,
/// canonicalised to its string form by `ConvertSidToStringSid` (windows-peer-auth §4).
/// Rendered to the opaque, platform-neutral string stored in the daemon's
/// `ClientIdentity.principal` via [`PeerPrincipal::as_principal`].
///
/// Equality is the same-principal check of C6: integer comparison on Unix, and on Windows
/// a comparison of the two canonical string SIDs — the spec-sanctioned equivalent of
/// `EqualSid` (§6 pitfall 4: acceptable when both sides are produced by
/// `ConvertSidToStringSid`), chosen because the principal must be rendered to a string for
/// the session key regardless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPrincipal {
    Unix(u32),
    Windows(String),
}

impl PeerPrincipal {
    /// The opaque, platform-neutral string form: the decimal UID on Unix (a lossless
    /// re-encoding of the integer UID) or the canonical string SID on Windows.
    pub fn as_principal(&self) -> String {
        match self {
            PeerPrincipal::Unix(uid) => uid.to_string(),
            PeerPrincipal::Windows(sid) => sid.clone(),
        }
    }
}

/// The largest control frame accepted on the local transport (8 MiB), bounding the
/// per-frame allocation a peer can force before authentication. Used by both the Unix
/// (UDS) and Windows (named-pipe) transports.
#[cfg(any(unix, windows))]
const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Mint a 128-bit CSPRNG connection token (hex). Uses the OS CSPRNG via `getrandom`
/// (`/dev/urandom` family on Unix, `BCryptGenRandom` on Windows) — one source replacing
/// the two `/dev/urandom` copies the daemon previously carried.
pub fn mint_token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
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

// ---- Windows transport: a named pipe authenticated by impersonating the client ----
// Implements windows-peer-auth.md §4 (principal derivation) and §5 (secure pipe creation).

#[cfg(windows)]
mod windows_impl {
    use super::{PeerPrincipal, MAX_FRAME};
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
    };
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, LocalFree, FALSE, HANDLE, HLOCAL, TRUE};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, RevertToSelf, SecurityIdentification, TokenImpersonationLevel,
        TokenUser, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
        TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    };

    fn win_err(e: windows::core::Error) -> io::Error {
        io::Error::other(e.to_string())
    }

    fn denied(msg: &'static str) -> io::Error {
        // The transport cannot determine the peer principal; ClientAuth maps a non-matching
        // principal to CLIENT_UID_DENIED (spec §7, fail closed).
        io::Error::other(msg)
    }

    /// RAII guard binding `RevertToSelf` to scope exit — §6 pitfall 1: the handling thread
    /// must stop impersonating the client on **every** path, including every error path.
    struct RevertGuard;
    impl Drop for RevertGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = RevertToSelf();
            }
        }
    }

    /// RAII guard closing a token handle on scope exit.
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// A LocalAlloc'd security descriptor (from SDDL); freed with `LocalFree` on drop. The
    /// raw pointer is read-only after construction, so sharing it across the accept loop is
    /// sound (hence the manual `Send`/`Sync`).
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(HLOCAL(self.0 .0));
            }
        }
    }
    unsafe impl Send for SecurityDescriptor {}
    unsafe impl Sync for SecurityDescriptor {}

    /// Canonical string SID for the user behind `token` (spec §4 step 4 + canonicalisation).
    /// # Safety: `token` must be a valid, open access token handle.
    unsafe fn token_user_sid_string(token: HANDLE) -> io::Result<String> {
        let mut len = 0u32;
        // First call sizes the buffer (it returns ERROR_INSUFFICIENT_BUFFER, hence ignored).
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        if len == 0 {
            return Err(denied("TokenUser size query failed"));
        }
        let mut buf = vec![0u8; len as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .map_err(win_err)?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_to_string(tu.User.Sid)
    }

    /// Canonicalise a SID to its string form via `ConvertSidToStringSid` (spec §6 pitfall 4).
    /// # Safety: `sid` must point to a valid SID.
    unsafe fn sid_to_string(sid: PSID) -> io::Result<String> {
        let mut wide = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut wide).map_err(win_err)?;
        let out = wide
            .to_string()
            .map_err(|_| denied("SID string was not valid UTF-16"));
        let _ = LocalFree(HLOCAL(wide.0 as *mut c_void));
        out
    }

    /// The daemon's own user SID (canonical string), captured once at start-up (spec §4).
    pub(super) fn daemon_user_sid_string() -> io::Result<String> {
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(win_err)?;
            let _g = HandleGuard(token);
            token_user_sid_string(token)
        }
    }

    /// Derive the connecting client's user SID by **impersonating the pipe** (spec §4).
    /// This runs synchronously with no `.await` between impersonation and reversion, so the
    /// tokio task cannot migrate threads while impersonating.
    fn derive_peer_sid(server: &NamedPipeServer) -> io::Result<String> {
        let pipe = HANDLE(server.as_raw_handle());
        unsafe {
            // §4.1 — impersonate, then immediately arm the reversion guard.
            ImpersonateNamedPipeClient(pipe).map_err(win_err)?;
            let _revert = RevertGuard;

            // §4.2 — open the impersonation token.
            let mut token = HANDLE::default();
            OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &mut token).map_err(win_err)?;
            let _tok = HandleGuard(token);

            // §4.3 — require impersonation level ≥ Identification (an anonymous client yields
            // a token with no readable SID; reject it, §6 pitfall 3).
            let mut level = SECURITY_IMPERSONATION_LEVEL::default();
            let mut got = 0u32;
            GetTokenInformation(
                token,
                TokenImpersonationLevel,
                Some(&mut level as *mut _ as *mut c_void),
                size_of::<SECURITY_IMPERSONATION_LEVEL>() as u32,
                &mut got,
            )
            .map_err(win_err)?;
            if level.0 < SecurityIdentification.0 {
                return Err(denied("impersonation level below Identification"));
            }

            // §4.4 — read the client's user SID; §4.5 RevertToSelf runs on the guard drop.
            token_user_sid_string(token)
        }
    }

    /// Build a security descriptor whose DACL grants Generic-All to **only** the daemon SID
    /// (`D:P(A;;GA;;;<sid>)`) — §5 restrictive DACL: no `Everyone`, no `Authenticated Users`.
    fn build_security_descriptor(daemon_sid: &str) -> io::Result<SecurityDescriptor> {
        let sddl = format!("D:P(A;;GA;;;{daemon_sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut psd,
                None,
            )
            .map_err(win_err)?;
        }
        Ok(SecurityDescriptor(psd))
    }

    /// Create one server pipe instance with the §5 protections: a restrictive DACL,
    /// `reject_remote_clients` (no network reach), and — for the **first** instance —
    /// `first_pipe_instance` so creation fails if a pipe of that name already exists
    /// (defeats name-squatting).
    fn create_instance(
        name: &str,
        sd: &SecurityDescriptor,
        first: bool,
    ) -> io::Result<NamedPipeServer> {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0 .0,
            bInheritHandle: FALSE,
        };
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .pipe_mode(PipeMode::Byte)
                .create_with_security_attributes_raw(name, &mut sa as *mut _ as *mut c_void)
        }
    }

    fn write_token_file(token_path: &str, token: &str) -> io::Result<()> {
        // %LOCALAPPDATA% is per-user protected by its default ACLs; create the parent dir
        // and write the token there (clients read it back over the same per-user path).
        if let Some(parent) = std::path::Path::new(token_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(token_path, token)
    }

    /// The bound server transport: a listening named pipe, the minted connection token, and
    /// this daemon's own principal (its user SID, captured at start-up).
    pub struct Listener {
        name: String,
        sd: SecurityDescriptor,
        pending: Mutex<Option<NamedPipeServer>>,
        token: String,
        daemon: PeerPrincipal,
    }

    impl Listener {
        /// Capture the daemon SID, build the §5 DACL, create the first pipe instance (fails
        /// closed if any §5 precondition cannot be met, e.g. name-squatting), and mint +
        /// write the connection-token file. Must run within a Tokio runtime.
        pub fn bind(pipe_name: &str, token_path: &str) -> io::Result<Listener> {
            let daemon_sid = daemon_user_sid_string()?;
            let sd = build_security_descriptor(&daemon_sid)?;
            let server = create_instance(pipe_name, &sd, true)?;

            let token = super::mint_token()?;
            write_token_file(token_path, &token)?;

            Ok(Listener {
                name: pipe_name.to_string(),
                sd,
                pending: Mutex::new(Some(server)),
                token,
                daemon: PeerPrincipal::Windows(daemon_sid),
            })
        }

        /// The minted connection token (production clients read it from the per-user file;
        /// tests read it here).
        pub fn token(&self) -> &str {
            &self.token
        }

        /// This daemon's own principal — the expected peer for an authenticated client.
        pub fn daemon_principal(&self) -> &PeerPrincipal {
            &self.daemon
        }

        /// Accept the next connection, deriving its peer principal by impersonation (§4).
        /// A failure to determine the SID yields an empty principal that can never equal the
        /// daemon's, so ClientAuth refuses with `CLIENT_UID_DENIED` (spec §7) and the daemon
        /// still writes that refusal back over the returned connection.
        pub async fn accept(&self) -> io::Result<(Connection, PeerPrincipal)> {
            let server = {
                let mut g = self.pending.lock().unwrap();
                g.take()
                    .ok_or_else(|| io::Error::other("no pending pipe instance"))?
            };
            server.connect().await?;
            // Keep a fresh instance listening for the next client.
            let next = create_instance(&self.name, &self.sd, false)?;
            *self.pending.lock().unwrap() = Some(next);

            let principal = match derive_peer_sid(&server) {
                Ok(sid) => PeerPrincipal::Windows(sid),
                Err(_) => PeerPrincipal::Windows(String::new()),
            };
            Ok((Connection::server(server), principal))
        }
    }

    enum Pipe {
        Server(NamedPipeServer),
        Client(NamedPipeClient),
    }

    /// A framed control connection: a 4-byte big-endian length prefix then the payload.
    pub struct Connection {
        pipe: Pipe,
    }

    impl Connection {
        fn server(s: NamedPipeServer) -> Self {
            Connection {
                pipe: Pipe::Server(s),
            }
        }
        fn client(c: NamedPipeClient) -> Self {
            Connection {
                pipe: Pipe::Client(c),
            }
        }

        /// Read one length-prefixed frame; `Ok(None)` at a clean EOF. A length above
        /// [`MAX_FRAME`] is rejected before the buffer is allocated.
        pub async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            let mut len_buf = [0u8; 4];
            let r = match &mut self.pipe {
                Pipe::Server(s) => s.read_exact(&mut len_buf).await,
                Pipe::Client(c) => c.read_exact(&mut len_buf).await,
            };
            match r {
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
            match &mut self.pipe {
                Pipe::Server(s) => s.read_exact(&mut buf).await?,
                Pipe::Client(c) => c.read_exact(&mut buf).await?,
            };
            Ok(Some(buf))
        }

        /// Write one length-prefixed frame and flush.
        pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
            let len = (payload.len() as u32).to_be_bytes();
            match &mut self.pipe {
                Pipe::Server(s) => {
                    s.write_all(&len).await?;
                    s.write_all(payload).await?;
                    s.flush().await
                }
                Pipe::Client(c) => {
                    c.write_all(&len).await?;
                    c.write_all(payload).await?;
                    c.flush().await
                }
            }
        }
    }

    /// Connect to the daemon control pipe at `pipe_name` as a client (the MCP front door).
    pub async fn connect(pipe_name: &str) -> io::Result<Connection> {
        let client = ClientOptions::new().open(pipe_name)?;
        Ok(Connection::client(client))
    }
}

#[cfg(windows)]
pub use windows_impl::{connect, Connection, Listener};

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

    #[test]
    fn windows_principal_round_trips_the_string_sid() {
        let sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        assert_eq!(PeerPrincipal::Windows(sid.to_string()).as_principal(), sid);
        // A canonical SID never equals the empty "undeterminable" sentinel accept() yields
        // on a derivation failure, so such a peer can never match the daemon principal.
        assert_ne!(
            PeerPrincipal::Windows(sid.to_string()),
            PeerPrincipal::Windows(String::new())
        );
    }

    // Runs on the windows-latest lane: the daemon can read its own user SID at start-up
    // (spec §4, the daemon-principal capture), and it is a canonical "S-1-..." string.
    #[cfg(windows)]
    #[test]
    fn windows_reads_own_user_sid() {
        let sid = super::windows_impl::daemon_user_sid_string().expect("own SID");
        assert!(sid.starts_with("S-1-"), "canonical string SID, got {sid}");
    }
}

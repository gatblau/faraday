# Component spec (draft) — Windows peer authentication for ClientAuth

**Status:** Draft · **Owner component:** C6 ClientAuth (`src/clientauth.rs`) · **Transport dependency:** C8 control endpoint (`src/endpoint.rs`) · **derivedFromHld:** 0.4.1 · **(security-critical — ADR-024)**

This spec defines how `faradayd` authenticates a connecting client on **Windows**, where the
Unix mechanism (peer UID via `SO_PEERCRED`) does not exist. It extends C6 ClientAuth; it does
not replace its contract. It is self-contained: the Unix behaviour it must match is restated
here so the spec can be implemented from this document alone.

## 1. Why this is needed

The daemon's control endpoint is a local IPC channel. Its security rests on one invariant:

> **Only a process running as the same operating-system principal as the daemon itself may
> connect.** Everything else — the connection token, first-connect consent, the capability
> allowlist, budgets, audit — sits *behind* this check and assumes it holds.

On Unix the daemon enforces this by reading the connecting peer's UID from the kernel
(`UnixStream::peer_cred().uid()`) and rejecting any UID that is not the daemon's own
(`CLIENT_UID_DENIED`, `clientauth.rs`). The peer UID is **server-derived from the kernel, never
asserted by the client** — that is what makes it trustworthy.

Windows has no UID and no `SO_PEERCRED`. The named-pipe transport (the Windows replacement for
the Unix domain socket) must derive the connecting client's principal a different way, and the
replacement must preserve the same "server-derived, never client-asserted" property. Getting
this wrong silently removes the entire security boundary, so the mechanism is specified
precisely below rather than left to implementer choice.

## 2. The principal model

The same-principal check is the only platform-specific part of authentication. Capture it in
one abstraction so the rest of ClientAuth is identical on both operating systems.

```text
PeerPrincipal           // server-derived identity of the connecting peer
  ├─ Unix(uid: u32)     // from SO_PEERCRED / getpeereid
  └─ Windows(sid)       // user SID from the impersonated named-pipe client token
```

- The transport (C8) produces a `PeerPrincipal` for each accepted connection.
- ClientAuth holds the **daemon's own** `PeerPrincipal`, captured once at start-up.
- Step 1 of `authenticate` becomes: *peer principal equals the daemon principal*, where
  equality is integer comparison on Unix and `EqualSid` on Windows. Any inequality, or any
  failure to determine the peer principal, returns `CLIENT_UID_DENIED`.

This keeps C6's three-step contract (principal → token → first-connect consent) unchanged; only
the production and comparison of the principal differ by platform.

## 3. Public interface

Restated from C6, generalised from `peer_uid: u32` to `PeerPrincipal`:

- `pub fn authenticate(&self, peer: PeerPrincipal, presented_token: &[u8], client_label: &str, first_connect_consent: &dyn Fn(&str) -> bool) -> Result<ClientIdentity, WireError>`
- `pub fn mint_token() -> std::io::Result<String>` — 128-bit CSPRNG hex token. The Unix
  implementation reads `/dev/urandom`; the Windows implementation must use a CSPRNG that does
  not depend on `/dev/urandom` (the `getrandom` crate, which maps to `BCryptGenRandom` on
  Windows, is the expected source). The token's format and length are unchanged.

`ClientAuth::new` takes the daemon's own `PeerPrincipal` in place of `daemon_uid: u32`.

## 4. Deriving the Windows peer principal (the critical sequence)

The transport derives the client's user SID **by impersonating the connection**, not by looking
up a process ID. Impersonation reflects who is actually on the other end of this specific pipe
instance; a process-ID lookup (`GetNamedPipeClientProcessId` then open the process) has a
PID-reuse race and must not be used as the security check.

For each accepted pipe connection, on the thread that owns it:

1. `ImpersonateNamedPipeClient(pipe_handle)`. From here the thread carries the client's token.
   **A reversion guard is established in the same step** so that `RevertToSelf()` runs on every
   exit path, including every error path (see §6, pitfall 1).
2. `OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &token)`. Failure → reject.
3. Confirm the impersonation level is at least *Identification*:
   `GetTokenInformation(token, TokenImpersonationLevel, …)`. A client that opened the pipe with
   `SECURITY_ANONYMOUS` yields a token from which no SID can be read; treat anything below
   Identification as a rejection (this is the correct fail-closed outcome — a client hiding its
   identity is refused, §6 pitfall 3).
4. `GetTokenInformation(token, TokenUser, …)` to read the client's **user SID**.
5. `RevertToSelf()` (guaranteed by step 1's guard). The thread is the daemon again.
6. Compare the client SID to the daemon's own user SID with `EqualSid`. Equal → the peer
   principal is the daemon; unequal → `CLIENT_UID_DENIED`.

The daemon's own user SID is captured once at start-up:
`OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, …)` → `GetTokenInformation(TokenUser, …)`.

The client token is used **only** to read `TokenUser`. It is never used to open a file, a
registry key, a handle, or any other resource. The SID is never logged.

## 5. Secure pipe creation (transport precondition — C8, stated here because the check depends on it)

The same-principal check is necessary but not sufficient on its own. It is only trustworthy if a
hostile local user cannot pre-create or share the pipe. These are properties of how C8 creates
the Windows pipe; this spec records them as **binding preconditions** because ClientAuth's
guarantee is void without them:

- **First-instance protection.** Create the server pipe with `FILE_FLAG_FIRST_PIPE_INSTANCE`,
  so creation fails if a pipe of that name already exists. This defeats name-squatting, where
  another user pre-creates the pipe to intercept connections.
- **Restrictive DACL.** The pipe's security descriptor grants access only to the daemon's own
  user SID (plus the minimum the OS requires). No `Everyone`, no `Authenticated Users`.
- **Reject remote clients.** Create with `PIPE_REJECT_REMOTE_CLIENTS` so the pipe can never be
  reached over the network, only from the same machine.

If any precondition cannot be met at start-up, the daemon fails to start (consistent with the
fail-closed posture of `config.rs`). It does not fall back to a less-protected pipe.

## 6. Security pitfalls this spec forbids

1. **Skipping `RevertToSelf` on an error path.** If the thread returns while still impersonating
   the client, the daemon continues running as that client — privilege confusion in the most
   security-sensitive component. `RevertToSelf` is mandatory on every exit path and must be
   bound to a guard (RAII / `defer`-style), not placed only on the happy path.
2. **Using `GetNamedPipeClientProcessId` as the identity check.** PIDs are reused; between
   reading the PID and opening the process, the original process may have exited and the PID may
   now name a different process. The connection-bound impersonation token in §4 has no such
   window. The PID call may be used for *diagnostics only*, never for the authorisation decision.
3. **Treating "could not read a SID" as anything but a rejection.** A missing token, an
   anonymous-level impersonation, or any failed Win32 call in §4 returns `CLIENT_UID_DENIED`.
   There is no default-allow branch.
4. **Comparing SIDs as strings by chance.** Compare with `EqualSid` against the daemon's own
   captured user SID. (A canonicalised string SID compared for equality is acceptable only if
   produced by `ConvertSidToStringSid` on both sides; `EqualSid` is the expected form.)
5. **Acting with the client token.** It is read for `TokenUser` and discarded. It is never used
   to access a resource.

## 7. Error table

| Condition | Code | Result |
|---|---|---|
| Client user SID ≠ daemon user SID | `CLIENT_UID_DENIED` | connection refused |
| Impersonation / token / SID read fails, or level below Identification | `CLIENT_UID_DENIED` | connection refused (fail closed) |
| Connection token mismatch or absent | `CLIENT_TOKEN_DENIED` | connection refused |
| New client label declined at first-connect consent | `CLIENT_NOT_APPROVED` | connection refused |
| Pipe cannot be created with the §5 protections | (start-up failure) | daemon does not start |

The first three rows reuse C6's existing codes deliberately: a Windows caller sees the same wire
contract as a Unix caller. `CLIENT_UID_DENIED` covers both "wrong principal" and "principal
could not be determined", because to a caller both mean the same thing — you are not the daemon's
user.

## 8. Gherkin

```gherkin
Feature: Windows peer authentication
  Scenario: Happy path — same-user client with a valid token
    Given a named-pipe client running as the daemon's own user
    And the client presents the live connection token
    When authenticate is called with the impersonated peer principal
    Then it returns a ClientIdentity

  Scenario: Error — a different local user is rejected
    Given a named-pipe client running as a different Windows user
    When authenticate derives the client user SID and compares it to the daemon's
    Then it returns CLIENT_UID_DENIED and the connection is refused

  Scenario: Error — a client that hides its identity is rejected
    Given a client that opened the pipe at SECURITY_ANONYMOUS
    When authenticate cannot read a user SID from the impersonation token
    Then it returns CLIENT_UID_DENIED and the connection is refused

  Scenario: Safety — the daemon reverts impersonation on every path
    Given any connection, whether accepted or rejected
    When authenticate finishes
    Then the handling thread is no longer impersonating the client

  Scenario: Transport — name-squatting is defeated at start-up
    Given another process already owns a pipe of the daemon's name
    When the daemon creates its pipe with FILE_FLAG_FIRST_PIPE_INSTANCE
    Then creation fails and the daemon does not start
```

## 9. Dependencies and assumptions

- **A1 — Windows API binding.** The implementation needs Win32 bindings for
  `ImpersonateNamedPipeClient`, `RevertToSelf`, `OpenThreadToken`, `OpenProcessToken`,
  `GetTokenInformation` (`TokenUser`, `TokenImpersonationLevel`), `EqualSid`, and
  `GetCurrentThread` / `GetCurrentProcess`, plus the named-pipe creation flags. Microsoft's
  official `windows` crate is the assumed source. It is **not yet a dependency** — see Gaps.
- **A2 — Privilege.** A same-user pipe does not require `SeImpersonatePrivilege` for the server
  to impersonate its own-user client; the daemon runs as a normal per-user process. This holds
  for the per-user autostart model (Scheduled Task / `Run` key), not a `LocalSystem` service.
- **A3 — CSPRNG.** Token minting on Windows uses `getrandom` (→ `BCryptGenRandom`); the
  `/dev/urandom` path in `mint_token` stays Unix-gated.
- **A4 — Behaviour parity.** Steps 2 (constant-time token compare via `constant_time_eq`) and 3
  (first-connect consent) of C6 are reused unchanged. Only principal derivation/comparison is
  new.

## 10. Open questions

- **OQ-1 — `ClientIdentity.peer_uid` on Windows.** The shared type is
  `ClientIdentity { peer_uid: u32, client_label }` (Phase-2C), and `peer_uid` feeds the session
  key (`session.rs`). Windows has no `u32` UID. Because every accepted connection is, by the
  §1 invariant, the *same* principal as the daemon, `peer_uid` carries no distinguishing
  information for keying — `(client_label, workspace_id)` already does that.
  **Recommended resolution:** widen `ClientIdentity` to carry an opaque
  `principal: String` (decimal UID on Unix, string SID on Windows) and key sessions on it,
  retiring the raw `peer_uid`. This is a Phase-2C shared-type change that also touches the Unix
  path, so it needs sign-off rather than a silent assumption. A lower-touch alternative — keep
  `peer_uid` and populate it with a per-launch constant on Windows — works because the field is
  degenerate, but leaves a Unix-shaped field on a platform with no UID.
- **OQ-2 — Spec↔code reconciliation.** C6's interface already names a `PeerCred` type, but
  `clientauth.rs` currently passes `peer_uid: u32`. Introducing `PeerPrincipal` should be
  reconciled with that existing `PeerCred` naming so the codebase has one principal type, not
  two. Decision needed: adopt `PeerPrincipal`, or extend the existing `PeerCred`.

## 11. Gaps

- **G1 — Win32 binding not present.** No Windows API crate (`windows` / `winapi`) is in
  `sandbox-daemon/Cargo.toml` today; the dependency must be added (and gated
  `[target.'cfg(windows)'.dependencies]`) before this can be implemented. Until then the Win32
  symbols in §4 are unresolved identifiers.
- **G2 — Transport not implemented.** The Windows control transport is a stub today
  (`endpoint.rs`: `#[cfg(not(unix))]` returns `Unsupported — "named-pipe transport is
  implemented in a later phase"`). The §5 pipe-creation preconditions cannot be verified until
  that transport exists; this spec assumes it lands first or alongside.
- **G3 — Verification environment.** The behaviours in §8 (impersonation, SID comparison,
  name-squatting) cannot be exercised on macOS or Linux. They require a real Windows host or a
  `windows-latest` CI runner; the current CI is `ubuntu-latest` only. The dedicated peer-auth
  pen test that ADR-024 relies on must be re-run on Windows — it is not covered by the existing
  Unix test suite.

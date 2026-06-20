# 05 — Tech Stack

> **Revision:** 0.3.0

The profile inherits the daemon's tech stack unchanged (sandbox-daemon 05-tech-stack / ADR-026). The only additions are the deployment substrate (container) and the secret-delivery mechanism (mounted file). One row per layer; "inherited" means no change from the base daemon design.

| Layer | Choice | Rationale (one line) |
|---|---|---|
| Language | Rust (inherited) | One memory-safe TCB for a credential-holding daemon (sandbox-daemon ADR-026). |
| Framework / runtime | Wasmtime + RustPython (inherited) | The sole isolation boundary; unchanged by this profile (sandbox-daemon ADR-013 / ADR-014). |
| Datastore | None (inherited) | The daemon holds no persistent store; the key rests in a mounted secret file, not in faraday. |
| Message broker / queue | N/A — none | No queue in the daemon; outbound is synchronous HTTPS via DownstreamClient (C10). |
| Deployment substrate | **OCI container, single-tenant, one daemon per agent** (new) | Serves a headless server-deployed agent; the agent and daemon share the container and UID so ADR-024 client-auth holds (ADR-034). |
| Observability (logs / metrics / traces) | Audit log + OTLP export (inherited) | Real-credential mode requires the OTLP sink, unchanged (sandbox-daemon ADR-016 / ADR-027). |
| Signing / crypto | OS keychain / `SecretResolver` (inherited, narrowed) | Server-mode keys are resolved from **files** via `FileSecretResolver` (`config.rs`); no raw-env secrets (ADR-036). |
| Build / test toolchain | `cargo` (inherited) | Single toolchain; `cargo audit` / `cargo deny` supply-chain gate unchanged (sandbox-daemon ADR-018). |

## Notes on the deployment substrate

- The base design ships per-OS **service installers** (sandbox-daemon ADR-031) and names a **per-user OS service** model (launchd / systemd-user / Windows service, ADR-030). Linux service packaging there is **planned, not yet implemented**. A container image is a sibling distribution target to those installers; the binary itself (Wasmtime + RustPython) is portable, so the container path is build/packaging work, not a runtime redesign. This is recorded as a dependency/risk in [10 — Risks](./10-risks.md), not assumed solved.
- The container must satisfy the daemon's existing runtime expectations: a writable runtime dir for the `0600` socket and connection-token file (`XDG_RUNTIME_DIR` or `PYS_SOCKET_PATH` / `PYS_CONNECTION_TOKEN_PATH`), and randomness for the connection token. No loopback port is bound for sign-in in a pure `api_key`/`none` deployment.

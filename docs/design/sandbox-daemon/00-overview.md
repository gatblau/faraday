# 00 — Overview

## Summary

`faradayd` is a **per-user, host-resident daemon** — a single **Rust** binary — that runs agent-authored Python inside a **WebAssembly capability sandbox** (RustPython compiled to WASM, on the Wasmtime runtime) and lets that code invoke pre-approved external APIs through the in-daemon Identity Broker. It is **independent of the IDE**: any agent host (an MCP-capable IDE via config, a CLI, or a headless harness) connects over a **local socket** through a **single `run(code, capabilities)` entry** — exposed as a faraday-native RPC and as *one* MCP tool (never per-API tools — ADR-001/ADR-023) — so **no per-IDE plugin is built or installed** (ADR-023). Tokens never enter the sandbox; the Python code is handed short-lived opaque **capability handles**, and the broker performs the authenticated HTTPS calls itself. The sandbox has **no ambient authority**: the WASM guest cannot open a socket, touch the host filesystem, or spawn a process, and reaches the broker only through a single host-provided capability function — so network egress is *structurally impossible* rather than blocked after the fact. The agent-authored Python is restricted by contract to the standard-library data-manipulation surface plus the broker SDK (no third-party or native packages). Non-goals: it is not a general-purpose REPL, not a long-running workload host, and not a secret manager.

## Motivation

Agents increasingly need to run code that calls authenticated APIs (internal corporate services fronted by the organisation's identity provider (e.g. Okta), and others such as GitHub) on a developer's behalf. The naïve implementation — pass an `Authorization: Bearer` header into a Python `requests` call — leaks the token through `os.environ` dumps, tracebacks on failed requests, `print(headers)`, on-disk token caches (e.g. an IdP token-cache file), or a custom socket to an attacker host. Because the agent is untrusted (it may be steered by prompt injection) and the Python it authors is untrusted, doing nothing — or trusting the agent with raw tokens — is not acceptable. The design eliminates these vectors by never marshalling secret material into the untrusted process and by running that process in a WebAssembly sandbox that has **no network, filesystem, or process primitive to abuse** — the historical "custom socket to an attacker host" vector does not exist when the guest cannot construct a socket at all.

## Goals

- Execute **agent-authored** Python in a capability sandbox, restricted by contract to the standard-library data-manipulation surface plus the broker SDK (no third-party or native packages).
- Allow that Python to call **pre-approved external APIs** with the user's authenticated identity.
- **Never marshal raw tokens into the Python sandbox process**, and never place them on stdout/stderr, environment variables, process arguments, or the agent-visible result.
- Provide auditable logs of every outbound call.
- Operate cross-platform (Windows, macOS, Linux) through a **single WASM runtime** and a **single Rust daemon**, not per-OS isolation primitives and not per-IDE plugins.
- Be **IDE-independent**: any MCP-capable or shell-capable agent host reuses one daemon through a single `run` entry; no per-IDE plugin is built (ADR-023).

The protected-against principal is the **untrusted agent and the Python code it authors** — not the user, who has already authenticated and runs the daemon under their own UID.

## Non-goals

- General-purpose Python REPL replacement.
- Long-running background workloads.
- Replacing existing secret managers — the design *consumes* them.
- Preventing a determined **user** from extracting tokens from their own daemon process (infeasible on a developer workstation; out of scope — see [04 — Domain](./04-domain.md) §Data Lifecycle and ADR-002).

## Glossary

| Term | Definition | Example |
|---|---|---|
| Daemon (`faradayd`) | The per-user, host-resident Rust binary that hosts the Controller, Broker, Runtime, client-auth, and consent UI; agent hosts connect to it over a local socket (ADR-023/ADR-026). | One `faradayd` per OS user, started by the OS service manager. |
| Client | A thin agent host that connects to the daemon over the local socket via the single `run` entry; holds no tokens and is not required to render UI. | An MCP-capable IDE (config only), a CLI, or a headless harness. |
| Connection token | A per-daemon-launch CSPRNG secret a client must present to open the control socket; replaces the spawn-distributed per-launch secret (ADR-024). | 128-bit token in a `0600` runtime file the client reads. |
| Control endpoint | The daemon's local socket (UDS / named pipe) exposing the single `run` entry over a faraday-native RPC and a single MCP tool (ADR-023). | `$XDG_RUNTIME_DIR/faradayd.sock`, mode `0600`. |
| `run` entry | The single agent-facing operation — submit code + requested capabilities and stream results (or a dry-run plan); the only API surface (no per-API tools, ADR-001/ADR-023). | `run({code, requestedCapabilities, dryRun})`. |
| Interaction broker / consent UI | The daemon-owned surface that renders OIDC sign-in, per-session consent, and step-up when an `interaction_required` challenge fires (ADR-025). | A tray app / native dialog / local `127.0.0.1` consent page. |
| Sandbox Controller | Daemon component that receives run requests, mints a capability bundle, and launches the Python sandbox. | Handles `run({code, requestedCapabilities})`. |
| Identity Broker | Daemon component that is the single source of truth for credentials and performs all outbound HTTPS. | Holds the IdP-issued access token; Python never sees it. |
| Python Sandbox | WebAssembly capability sandbox running the agent-authored code: RustPython (compiled to WASM) on the Wasmtime runtime, hosted by a Rust process. | No ambient authority; reaches the broker via one host import. |
| Sandbox Runtime | The Rust host process that embeds Wasmtime, loads the RustPython guest, links the single broker capability function, and enforces fuel/memory/wall-clock limits. | Forwards the guest's broker calls to the out-of-process Identity Broker. |
| `pysandbox_sdk` | The injected Python module that is the only sanctioned way for sandbox code to reach the outside world; backed by a WASM host import, not a socket. | `api.tickets.get("/api/v2/tickets/42")`. |
| Capability | A named, policy-defined permission to call a specific provider/host/path/method set. | `internal.tickets`, `github.repo.read`. |
| Capability handle (`capId`) | A short-lived, opaque 128-bit token that names a capability for the lifetime of one run. Not a credential. | `capId=ab12…`, valid ≤5 min. |
| Capability manifest | The policy file declaring which capabilities exist and their host/path/method allowlists. | `pysandbox.policy.json`. |
| Token exchange (OBO / RFC 8693) | A flow that swaps the user's token for a downstream credential carrying their identity; provider-pluggable, performed by the backend `obo-broker` service. | RFC 8693 token exchange for an internal `tickets` API. |
| Egress lockdown | The WASM capability model: the guest has no socket, filesystem, or process capability, so its only outward path is the broker host import. | Wasmtime denies all ambient authority by default — the same boundary on every OS. |
| Run | A single execution of agent-authored code with an issued capability bundle. | One `run(...)` call. |
| Session | A workspace-scoped span across which consent decisions and the per-session call budget apply. | One workspace context per connected client. |
| Audit entry | An append-only log record describing one outbound broker call (sizes, not bodies). | `{runId, capId, host, path, status, …}`. |
| Dry-run preview | A mode that reports the API calls a run *would* make, without executing them. | Preview "GET tickets `/api/v2/tickets/42`" before running. |
| Capability bundle | The `{api_name → capId}` set issued for one run; delivered to the guest at startup via a host import, not a filesystem path. | `{ tickets → ab12… }`. |
| Redaction filter | A defence-in-depth scrub of token-shaped strings in sandbox stdout/stderr; not a security control. | JWT / `gh*_` / `sk-` → `[REDACTED]`. |
| Step-up authentication | An optional, policy-configurable requirement to re-confirm identity (MFA) before a sensitive (write) call. | Re-auth before a `POST` to a tickets API. |
| SIEM export | Forwarding of audit entries to a central security-monitoring system; **mandatory in real-credential mode (ADR-016)**, checked fail-closed at startup (no reachable sink ⇒ mock / non-sensitive-credentials-only). | OTLP export of the audit log as the authoritative record. |
| Response safeguard | The broker-side control that treats API-response content as untrusted to defend against prompt injection (T6). | Mark returned text as untrusted; structural handling. |
| MCP front door (`mcp-stdio` sub-mode) | A sub-mode of the same `faradayd` binary that an MCP client spawns per session; speaks the MCP protocol over stdio and relays to the daemon's control socket as an untrusted client (ADR-028). | `command: faradayd, args: [mcp-stdio]` in Claude Code's MCP config. |
| `python_sandbox` (MCP tool) | The single MCP tool the front door exposes — submit code + requested capabilities, get the sanitised result (the `run` entry in MCP clothing). | `tools/call python_sandbox {code, requestedCapabilities}`. |
| Loopback sign-in | The concrete interactive OIDC sign-in: browser authorization-code + PKCE on a transient `127.0.0.1` redirect; the `id_token` is captured in the daemon only (ADR-029). | Daemon opens the browser to Dex; catches the redirect on `127.0.0.1:<ephemeral>`. |
| Service installer | The per-platform package that drops the binary, registers the always-on per-user OS service, and merges the MCP client config (ADR-030/ADR-031). | macOS `.pkg`/`.dmg`; Windows `.msi` (WiX); unsigned by default. |

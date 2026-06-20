# 04 — Domain Model & Data Lifecycle

## Domain Model

- **Capability** — a named, policy-defined permission. Key attributes: provider, scopes (advisory), host, path-allow patterns, methods. Relationships: declared in the Capability Manifest; referenced by a Run's `requestedCapabilities`. Lifecycle: defined in policy (static); enabled per run only after policy + consent checks pass.

- **Capability handle (`capId`)** — a runtime instance of a granted Capability. Key attributes: opaque 128-bit id, provider, scopes, `expiresAt`, allowed hosts, allowed methods. Relationships: minted by the Identity Broker from a Capability for a single Run. Lifecycle: created at run start → delivered to the guest at startup via a host import (not a filesystem path) → expires (≤5 min) or is invalidated on consent revocation → discarded at run end. Non-replayable outside the issuing extension instance — a `capId` is bound to the issuing broker instance and its per-launch IPC secret (ADR-020), so a handle leaked to the agent cannot be exercised by a different local process.

- **Run** — one execution of agent-authored code. Key attributes: `runId`, code, requested capabilities, resource limits (Wasmtime fuel/memory/epoch deadline), call count. Relationships: owns a capability bundle and a single WASM instance; emits Audit entries. Lifecycle: created on `run(...)` → instantiates the RustPython/WASM guest in the Sandbox Runtime → terminates on completion, deadline, fuel exhaustion, or limit breach → the WASM instance and its linear memory are dropped.

- **Session** — a workspace-scoped span. Key attributes: consent decisions (in-memory), per-session call budget. Relationships: contains many Runs. Lifecycle: begins on first capability use in a workspace window; consent cached until the window closes; budget (`maxCallsPerSession`) accrues across runs.

- **Capability Manifest (policy)** — the declarative permission set. Key attributes: capabilities map, defaults (consent, call budgets, response cap, debug). Relationships: read by the Identity Broker; may be overridden **only** by an admin-signed workspace policy (ADR-021) — an unsigned, mis-signed, or schema-invalid override is rejected fail-closed to the shipped default, never merged. Lifecycle: shipped (signed service-installer) default → optional admin-signed workspace override → validated at load (fail-closed); see [08 — Interfaces](./08-interfaces.md) for the schema reference. **Note:** for direct-provider capabilities (e.g. `github`, not routed through `obo-broker`), the workstation broker is the sole enforcement point — there is no server-side derived-copy re-check — so manifest integrity here is load-bearing.

- **Audit entry** — an append-only record of one outbound broker call. Key attributes: timestamp, runId, capId, provider, method, host, path, statusCode, request/response byte sizes, durationMs, keyed HMAC of the user identifier, agentId (the token `azp`). Relationships: one per outbound call within a Run. Lifecycle: written at call time → rotated daily → retained 30 days by default → exported to the SIEM/OTLP sink, which is **mandatory in real-credential mode and checked fail-closed at startup (ADR-016)** — no reachable sink ⇒ mock / non-sensitive-credentials-only.

## Data Lifecycle

- **Tokens** originate from the identity providers and reside **only** in the daemon process memory and the OS keychain. They are never written to disk in plaintext by the daemon, never logged, never placed in environment variables, never passed as process arguments, and never marshalled into the sandbox. Refreshed silently (by the provider). Privileged downstream (token-exchange) tokens, where applicable, live on the **backend `obo-broker`** service, not the workstation.

- **Capability handles** are minted per Run, delivered to the guest at startup via a host import (read once, never written to a host file), and expire within ≤5 minutes. They carry no secret material and are useless outside the issuing extension instance.

- **Audit log** is stored as append-only `globalStorageUri/audit/YYYY-MM-DD.jsonl`, rotated, retained 30 days by default. Bodies and tokens are not logged (only sizes), unless workspace debug mode is enabled. The local file is user-writable, so tamper-evidence relies on the **SIEM/OTLP export — mandatory in real-credential mode, fail-closed at startup (ADR-016)** — which is the authoritative record; the local copy is explicitly non-authoritative. The user identifier is stored as a keyed HMAC, not a bare hash.

- **Guest working storage** is the WASM instance's linear memory plus, if a Run needs scratch file I/O, an in-memory virtual filesystem the Sandbox Runtime optionally preopens for the guest. The guest has **no access to the host filesystem** (no WASI fs capability is granted); all of it is discarded when the instance is dropped at Run end.

- **User-side credential access** is explicitly *not* protected: the user owns the host process and could read their own tokens by attaching a debugger. The defensible boundary is the agent/sandbox, not the user (see ADR-002). Hardware-bound, sender-constrained tokens (optional) limit only off-device replay.

- **Multi-tenancy:** single user per daemon (per OS user); OBO downstream tokens are keyed by `(user, audience, scopes, providerId)`. No cross-user data sharing.

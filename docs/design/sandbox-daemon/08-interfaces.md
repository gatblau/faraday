# 08 — External Interfaces

Names and shapes only. Exact field types, error-code strings, status codes, JSON schemas, and retry counts are deferred to `/spec` (LLD).

## Daemon control protocol — the agent↔daemon contract (new)

The daemon's single agent-facing entry, served over the **local control socket** (UDS `0600` / named pipe; never network). The same `run` operation is exposed through two interchangeable front doors (ADR-023): the **faraday-native RPC** and a **single MCP tool** (§ below). There are **no per-API operations and no per-IDE plugin** — the API surface is code (ADR-001).

- `run({ code, requestedCapabilities, timeoutMs?, dryRun? })` → `{ stdout, stderr, exitCode, apiCalls[] }` for a normal run, or a preview `{ plannedCalls[] }` when `dryRun` is set (ADR-009). Each `apiCalls` / `plannedCalls` entry names `{ provider, host, path, method, status? }`.
- **Connect/auth handshake** — a client opens the socket presenting the per-launch **connection token**; the daemon verifies peer-UID + token (ADR-024) and binds a **session** keyed by `(client, workspace)` before any `run`.
- **`interaction_required`** — the daemon may answer a `run` (or the handshake) with a typed `{ sign_in | consent | step_up }` challenge (ADR-025); satisfied by the daemon-owned UI (default), MCP elicitation, or a CLI prompt — then the `run` proceeds. Step-up carries the RFC 9470 `acr_values`/`max_age`.

## `pysandbox_sdk` — sandbox-internal SDK surface (new)

The only sanctioned egress path for sandbox code, implemented over the **single WASM host import** the Sandbox Runtime links (there is no other capability). Shape only:

- `api.<provider>.get(path, *, params?, headers?)`
- `api.<provider>.post(path, *, json?, params?, headers?)`
- `api.<provider>.patch(path, *, json?)`
- `api.<provider>.delete(path)`

Providers (e.g. `tickets`, `github`) are populated dynamically from the issued capability bundle. User-supplied `headers` are intersected with a safe allowlist (`Accept`, `If-Match`, `Prefer`); `Authorization` is dropped by design. Each call returns the typed **untrusted-content envelope** `{ untrusted: true, contentType, body }` (ADR-017), not bare text. **Guest contract:** beyond this SDK the guest may use only the RustPython standard-library data-manipulation surface enumerated in ADR-014 — `json`, `re`, `datetime`, `base64`, `collections`, `itertools`, plus string/dict/list operations and control flow; third-party packages, native/C-extensions, and the networking/`os`/`socket` modules are not available — they are outside the guest's capabilities by construction.

## Single-`run` MCP tool — the `mcp-stdio` front door (ADR-028)

The MCP front door is the **`faradayd mcp-stdio` sub-mode** of the same binary: an **MCP server speaking JSON-RPC 2.0 over stdin/stdout**, which an MCP client (Claude Code / IDE) launches per session via plain configuration (`command: faradayd, args: [mcp-stdio]`) — **no built plugin**. Shape only:

- **MCP methods:** standard `initialize`, `tools/list`, `tools/call`. `tools/list` returns exactly **one** tool — `python_sandbox` — never per-API tools (ADR-001/ADR-023).
- **`tools/call python_sandbox`** input `{ code, requestedCapabilities, dryRun? }` → MCP tool result wrapping the daemon's `{ stdout, stderr, exitCode, apiCalls[] }` (or `{ plannedCalls[] }` for a dry run). An `interaction_required` (sign-in/consent/step-up) is surfaced to the client per MCP conventions while the daemon renders it (ADR-025/ADR-029).
- **Trust position:** the sub-mode is an **untrusted client** of the daemon — it reads the user's `0600` connection-token, connects to the local control socket, and carries only `{code, requestedCapabilities}` out / sanitised JSON back (ADR-024/ADR-028). It holds **no tokens**; it is a transport, not a security boundary. Never network-exposed.

## Service management & installer interface (ADR-030/ADR-031)

How the daemon is run and distributed (names/shapes only):

- **Service registration** — a launchd `LaunchAgents` plist (macOS, `RunAtLoad`+`KeepAlive`) / a per-user Windows service, started by the OS at login and kept alive; it owns the control socket and the connection-token file.
- **Installer** — a per-platform package (`.pkg`/`.dmg` macOS; `.msi`/WiX Windows) that drops the binary, registers the service, and **merges** the MCP client config entry for detected clients (never clobbering existing entries). Signing/notarization is an optional build parameter; the default output is unsigned/ad-hoc.

## CLI (new, optional)

A `faraday run …` CLI for non-MCP / headless agents that have a shell tool — the same `run` entry over the native RPC. No IDE plugin, no MCP.

## Per-IDE plugin (optional, not required)

A thin per-IDE plugin remains *possible* for teams wanting deep in-editor UX (inline results, in-editor dry-run preview), but is **not required** by the architecture (ADR-023) — the MCP tool + the daemon-owned consent UI cover IDE-independent use without one.

## Backend obo-broker service interface (new)

The HTTPS contract between the daemon's Identity Broker and the separately-deployed backend confidential client (committed — ADR-005). Names and shapes only:

- The daemon sends `{ userIdToken, capabilityId, verb, path, params?, body?, runId? }`; the backend validates the `id_token`, performs the provider-plugin RFC 8693 token exchange, calls the downstream API, and returns sanitized JSON. The privileged downstream token is never returned. There is **no** step-up field in the request — for a `requireStepUpAuth` capability with insufficient `acr`, the backend returns a `401` RFC 9470 `insufficient_user_authentication` challenge and the **daemon performs an IdP step-up (via its consent UI) and retries once (ADR-015/ADR-025)**; the server counterpart is `../obo-broker/` ADR-014. The detailed wire contract and the service's own internal design live in the companion HLD [`../obo-broker/`](../obo-broker/README.md) (kept in sync with this interface).

## `pysandbox.policy.json` — capability manifest (new config interface)

The declarative policy file: a `capabilities` map (each with `provider`, `scopes`, `host`, `pathAllow`, `methods`; `audience` required for token-exchange providers, e.g. `provider=rfc8693`) and a `defaults` block (`requireUserConsentPerSession`, `maxCallsPerRun`, `maxCallsPerSession`, `responseMaxBytes`, `debug`), plus (new in revision 0.2.0) a per-capability `requireStepUpAuth` toggle (OQ-1) and a `siemExport` configuration block (OQ-2). The **authoritative** formal JSON Schema (draft 2020-12) validating this file is [`./schema/pysandbox.policy.schema.json`](./schema/pysandbox.policy.schema.json), specified in [11 — Policy Schema](./11-policy-schema.md); the manifest is validated fail-closed at load (a manifest that fails validation is rejected — it does not fall back to defaults). Authoring compatible manifests (including with Gen AI assistance) is covered in [12 — Authoring Guide](./12-authoring-guide.md).

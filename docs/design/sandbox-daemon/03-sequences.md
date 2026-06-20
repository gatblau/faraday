# 03 — Principal Sequences

## Sequence: Typical run (golden path)

```mermaid
sequenceDiagram
  participant Agent
  participant Controller as Sandbox Controller
  participant Broker as Identity Broker
  participant Python as Sandbox Runtime (RustPython/WASM)
  participant API as External API

  Agent->>Controller: run(code, requestedCapabilities)
  Controller->>Broker: mintCaps(requestedCapabilities)
  Broker->>Broker: policy check and consent
  Broker-->>Controller: capIds (opaque, up to 5 min)
  Controller->>Python: launch runtime, load WASM guest and caps bundle
  Python->>Broker: api.tickets.get("/api/v2/tickets/42")  [WASM host import to control IPC]
  Broker->>API: GET /api/v2/tickets/42 with Bearer (broker-held)
  API-->>Broker: response
  Broker->>Broker: sanitize and audit
  Broker-->>Python: sanitized JSON
  Python-->>Controller: stdout / exit (after redaction filter)
  Controller-->>Agent: result {stdout, stderr, exitCode, apiCalls}
```

- **Trigger:** the agent calls `run(code, requestedCapabilities)`.
- **Result:** the agent receives the program's redacted stdout/stderr, exit code, and a summary of the API calls made — never any token.
- **Error posture:** policy rejection fails before spawn; a capability not in policy is rejected; on token-refresh failure the broker returns a `401`-shaped error to Python with no token surfaced.

## Sequence: Authenticated API call (broker validation)

```mermaid
sequenceDiagram
  participant Python as Sandbox Runtime (RustPython/WASM)
  participant Broker as Identity Broker
  participant API as External API

  Python->>Broker: broker host import to {capId, verb:"GET", path:"/api/v2/tickets/42"} over control IPC
  Broker->>Broker: lookup capId to provider/scopes/host
  Broker->>Broker: canonicalize path, reject if .. remains, match allowlist
  Broker->>Broker: refresh token if needed (silent, via provider)
  Broker->>API: HTTPS GET with Bearer (redirects NOT auto-followed)
  API-->>Broker: response
  Broker->>Broker: strip headers, size-cap, content-type check, apply response safeguard (T6, ADR-008)
  Broker->>Broker: write audit entry
  Broker-->>Python: sanitized JSON body (truncated flag if capped)
```

- **Trigger:** sandbox code invokes a `pysandbox_sdk` method, which calls the single broker host import; the Sandbox Runtime forwards it to the out-of-process broker over the control IPC.
- **Result:** sanitized JSON returned to the guest; the Bearer token never leaves the broker, and the guest never holds a socket.
- **Error posture:** path-traversal or off-allowlist path → rejected; cross-origin 3xx → returned as-is, `Authorization` never re-sent to a new host; response over cap → truncated with a flag; response content is marked untrusted before it reaches the agent (T6 safeguard, ADR-008).

## Sequence: Backend token exchange (corporate APIs via obo-broker)

```mermaid
sequenceDiagram
  participant Broker as Identity Broker (daemon)
  participant Backend as Backend obo-broker (confidential client)
  participant IdP as Identity Provider
  participant API as Downstream Corporate API

  Broker->>Backend: user id_token (audience = broker)
  Backend->>IdP: provider-plugin token exchange (RFC 8693), confidential client
  IdP-->>Backend: downstream access token
  Backend->>Backend: cache by (user, audience, scopes, providerId)
  Backend->>API: HTTPS with downstream Bearer
  API-->>Backend: response
  Backend-->>Broker: sanitized JSON (no downstream token returned)
```

- **Trigger:** sandbox code calls a capability whose provider routes to the backend `obo-broker` (e.g. via the `rfc8693` plugin).
- **Result:** the daemon (and therefore Python) sees only the final JSON; the privileged downstream token never reaches the workstation.
- **Error posture:** OBO is a **committed** component (OQ-6 resolved; ADR-005). If the backend is unreachable, token-exchange capabilities return a `503`-shaped error; capabilities not routed through the backend are unaffected. The backend's detailed design lives in [`../obo-broker/`](../obo-broker/README.md).

## Sequence: Dry-run preview (ADR-009)

```mermaid
sequenceDiagram
  participant Agent
  participant Controller as Sandbox Controller
  participant Broker as Identity Broker

  Agent->>Controller: run(code, requestedCapabilities, dryRun=true)
  Controller->>Broker: resolve requestedCapabilities to planned calls
  Broker->>Broker: static inspection only, no token use, no outbound HTTPS
  Broker-->>Controller: planned API calls {provider, method, path}
  Controller-->>Agent: preview (no execution, no side effects)
```

- **Trigger:** a run requested with the dry-run flag set.
- **Result:** the agent (and the user, via the Copilot participant) sees the planned API calls the run *would* make, with no execution and no outbound traffic. **Caveat:** the preview is **static capability resolution** (ADR-009) — for arbitrary Python with data-dependent control flow it is a best-effort plan, **not** a guaranteed-complete inventory of every call the run might make; the enforced boundary is the allowlist at call time, not the preview.
- **Error posture:** dry-run never touches tokens or the network; if a requested capability is not in policy it is reported as `rejected` in the preview rather than failing a real call.

## Sequence: Step-up authentication on a sensitive capability (ADR-015)

```mermaid
sequenceDiagram
  participant Python as Sandbox Runtime (RustPython/WASM)
  participant Controller as Sandbox Controller
  participant Broker as Identity Broker
  participant Backend as Backend obo-broker
  participant User as Developer
  participant IdP as Identity Provider

  Python->>Broker: api.tickets.post("/api/v2/tickets", json=...)  [requireStepUpAuth]
  Broker->>Backend: POST /v1/exchange (user id_token)
  Backend->>Backend: acr insufficient for this capability
  Backend-->>Broker: 401 insufficient_user_authentication, acr_values required (RFC 9470)
  Broker->>Controller: step-up required (acr_values)
  Controller->>User: step-up sign-in prompt (daemon consent UI, requested acr) [ADR-015]
  User->>IdP: re-authenticate (MFA)
  IdP-->>Controller: fresh id_token (elevated acr/amr)
  Controller->>Broker: fresh id_token, retry once
  Broker->>Backend: POST /v1/exchange (retry, elevated id_token)
  Backend-->>Broker: sanitized JSON (no downstream token)
  Broker-->>Python: result
```

- **Trigger:** the guest calls a capability whose policy sets `requireStepUpAuth` and the current `id_token` lacks the required `acr`.
- **Result:** after a one-time user step-up, the call proceeds; the assurance rides only in the `id_token` `acr` claim, server-enforced by `obo-broker` (ADR-014). The agent never asserts step-up and never sees a token.
- **Error posture:** the broker challenges with RFC 9470; the daemon retries **once** after step-up (ADR-015). A declined or failed step-up returns a typed `step_up_required`/`step_up_failed` error to the guest and the run does not proceed; the step-up signal is never a caller-supplied request field.

## Sequence: MCP client → `mcp-stdio` front door → daemon (ADR-028)

```mermaid
sequenceDiagram
  participant Agent as MCP client (Claude Code / IDE)
  participant Shim as faradayd mcp-stdio (untrusted client)
  participant EP as Control endpoint (daemon)
  participant Controller as Sandbox Controller

  Agent->>Shim: spawn `faradayd mcp-stdio` (stdio)
  Agent->>Shim: initialize / tools/list
  Shim-->>Agent: one tool — python_sandbox
  Agent->>Shim: tools/call python_sandbox {code, requestedCapabilities}
  Shim->>Shim: read 0600 connection-token file (same user)
  Shim->>EP: connect(token) over UDS 0600 / named pipe
  EP->>EP: peer-UID/SID check + token (ADR-024/030)
  Shim->>EP: run({code, requestedCapabilities})
  EP->>Controller: run lifecycle (mint caps → sandbox → broker)
  Controller-->>EP: {stdout, stderr, exitCode, apiCalls[]} (sanitised, no token)
  EP-->>Shim: result
  Shim-->>Agent: MCP tool result (sanitised JSON)
```

- **Trigger:** an MCP client invokes the `python_sandbox` tool. The shim is launched per session by the client and dies with it; the daemon is the always-on service (ADR-030).
- **Result:** the same `run` outcome the native RPC produces, wrapped as an MCP tool result. The shim relays only `{code, requestedCapabilities}` out and sanitised JSON back — **no token ever reaches the shim, the client, or the guest** (ADR-002/010/028).
- **Error posture:** if the daemon is not running, the shim returns a clear "daemon unavailable" tool error; a failed peer/token check is refused before any run (ADR-024). `interaction_required` is surfaced to the client while the daemon renders sign-in/consent/step-up.

## Sequence: Interactive sign-in — browser auth-code + PKCE on loopback (ADR-029)

```mermaid
sequenceDiagram
  participant Controller as Sandbox Controller
  participant UI as Consent/Auth UI (daemon)
  participant Loop as 127.0.0.1:&lt;ephemeral&gt; listener (daemon)
  participant Browser as System browser
  participant IdP as IdP (Dex / OIDC)

  Controller->>UI: interaction_required: sign_in
  UI->>UI: generate PKCE verifier+challenge, state, nonce
  UI->>Loop: bind transient 127.0.0.1 redirect listener
  UI->>Browser: open authorize URL (challenge, state, nonce, loopback redirect_uri)
  Browser->>IdP: user authenticates (+ MFA if step-up acr)
  IdP-->>Loop: redirect 127.0.0.1/?code=…&state=…
  Loop->>Loop: verify state; close port (single-use)
  UI->>IdP: token exchange (code + PKCE verifier)
  IdP-->>UI: id_token (+ verify nonce, signature)
  UI-->>Controller: id_token captured in daemon only
```

- **Trigger:** a run needs a user identity (or step-up) and none is held; the Controller raises `interaction_required: sign_in` (ADR-025).
- **Result:** the `id_token` is held **only in the daemon** (ADR-002/010); the agent/client/guest never see it. Step-up reuses this flow with the challenged `acr`. Targets generic OIDC discovery — Dex is the local-validation IdP.
- **Error posture:** PKCE + `state` + `nonce` + `127.0.0.1`-only + an ephemeral single-use port bound the redirect-interception surface; a `state`/`nonce` mismatch or an expired code aborts sign-in fail-closed and the run does not proceed. No local browser / loopback (remote/SSH topology) is out of scope — device-code is the recorded fallback (ADR-029).

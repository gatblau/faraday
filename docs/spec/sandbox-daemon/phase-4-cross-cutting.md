# Phase 4 — Cross-Cutting Concern Specifications (`sandbox-daemon`)

## Disposition summary

| Concern | Disposition |
|---|---|
| Authentication & Authorisation | Applies — XC1 (client-auth C6 + OIDC/consent/step-up via C8; capability authz via C4). |
| Error handling | Applies — XC2 (`WireError` C2 + code registry). |
| Logging | Applies — XC3. |
| Metrics | Applies — XC4. |
| Tracing | Applies — XC5. |
| Configuration | Applies — XC6 (delegates to Config C1). |
| Health checks | **Applies** — XC7 (HealthCheck C15; the daemon is a long-running service — ADR-023). |
| Rate limiting | Applies — XC8 (PolicyEngine C4 + SessionManager C7). |
| Input validation | Applies — XC9. |
| Graceful shutdown | Applies — XC10. |
| Pagination / CORS / DB migrations | **Out of scope** — XC11 (AS-21). |

---

### XC1 — Authentication & Authorisation
**Policy spec.**
- **Client → daemon (new):** every connection authenticated by **peer-UID (Unix) / peer-SID (Windows named pipe, ADR-030) + connection token** (+ optional first-connect consent) — ClientAuth (C6), ADR-024. The client is never a trusted principal; only `{capId, verb, path}` and sanitised JSON cross the socket. **The `mcp-stdio` MCP front door (C16) is itself such a client** — it authenticates the same way and holds no tokens (ADR-028).
- **User identity:** OIDC sign-in rendered by the daemon-owned UI (C8) as the **browser auth-code + PKCE loopback flow** (ADR-029, generic OIDC discovery — `PYS_OIDC_ISSUER`/`PYS_OIDC_CLIENT_ID`); the `id_token` is held only in the daemon (C11) and never reaches a client or the guest. No default IdP.
- **Authorisation:** capability allowlist (host + canonical path + method) enforced by PolicyEngine (C4); per-session consent gates first use (C7/C8); admin-signed manifest only (ADR-021).
- **Pass-through resource audiencing (ADR-033):** for a `Passthrough` capability the daemon requests the capability's `audience` at sign-in (C13 collects, C8 requests) so the IdP-issued `access_token` is audienced for the **resource server**, which validates it before serving — the property that makes forwarding the user's token to a same-trust-domain provider safe (`broker.rs` pass-through note). Mechanism: Dex cross-client trusted-peer scope for the demo, RFC 8707 `resource` for generic IdPs. The `exchange` path audiences downstream tokens server-side instead (C9/obo-broker).
- **Step-up:** challenge-driven (ADR-015/ADR-025) — on a `401 insufficient_user_authentication` from `obo-broker` (or a `requireStepUpAuth` capability), the daemon raises `StepUp` via C8, obtains a fresh `id_token` with the elevated `acr`, and retries once. Never caller-asserted.

```gherkin
Feature: Client authentication
  Scenario: Unauthenticated client cannot run
    Given a connection without a valid connection token
    When it sends run(...)
    Then the connection is refused before any capability is minted
```
**Errors:** see C6/C4/C8/C9 tables. **Gaps:** None.

---

### XC2 — Error Handling & Code Registry (`WireError`, C2)
**File:** `src/errors.rs` | **derivedFromHld:** 0.4.1

**Purpose.** One `WireError { error, code }` envelope and a canonical code→status registry; a panic-recovery boundary so every component emits identical, leak-free errors (no internal state, no token, no stack trace on the wire).

**Code registry.**
| Code | Status | Origin |
|---|---|---|
| VAL_ERR | 400 | ControlEndpoint |
| POLICY_PATH_REJECTED | 400 | PolicyEngine |
| TOKEN_INVALID / STEP_UP_REQUIRED / SIGN_IN_FAILED / INTERACTION_UNAVAILABLE | 401 | Broker / Policy / ConsentUI |
| CAP_UNKNOWN / POLICY_PATH_DENIED / POLICY_METHOD_DENIED / CAP_INVALID / INTERACTION_DENIED | 403 | Policy / Broker / Controller |
| RATE_LIMITED | 429 | PolicyEngine / SessionManager |
| INTERNAL / RUNTIME_ARTIFACT_MISMATCH / RUNTIME_LIMIT | 500 | various / Runtime |
| EXCHANGE_FAILED / OBO_UNAVAILABLE / DOWNSTREAM_UNAVAILABLE | 502 | OboClient / DownstreamClient |
| IDP_UNAVAILABLE | 503 | Broker |
| DOWNSTREAM_TIMEOUT | 504 | DownstreamClient |
| CLIENT_UID_DENIED / CLIENT_TOKEN_DENIED / CLIENT_NOT_APPROVED | (connection refused) | ClientAuth |
| CFG_* (the audit HMAC key is a `*_REF` resolved by Config — unresolved → `CFG_SECRET_UNRESOLVED`) | (startup fail-closed, non-zero exit) | Config (C1) |
| control socket cannot bind securely | (startup io error → non-zero exit; no wire code) | ControlEndpoint (C14) |

**Internal Logic.** `write(code, msg)` looks up the status, truncates `msg` to 200 chars, never includes upstream error text containing tokens; a recovery layer maps a panic to `500 INTERNAL` (logged server-side, never in the body).

```gherkin
Feature: WireError
  Scenario: Happy path — code maps to status
    When write("CAP_UNKNOWN", "unknown capability") is called
    Then the body is {error,code} with status 403
  Scenario: Error — panic recovered
    Given a handler panics
    When the request is served through the recovery layer
    Then the client gets 500 INTERNAL with no stack trace
```
**Gaps.** None.

---

### XC3 — Logging
**Policy spec.** JSON to stdout, one object per line. Required fields `ts, level, msg, run_id, component, code (on error)`; **never** tokens, bodies, `Authorization`, the connection token, or raw user identifiers (use `user_hmac`). `PYS_LOG_LEVEL` default `info`; `debug` never default in production. A redaction layer drops fields named `token`, `authorization`, `id_token`, `secret`, `cert`. **Gaps:** None.

### XC4 — Metrics
**Policy spec.** For the per-user **dev-machine profile (ADR-027)**, operational metrics are **out of scope by default** — there is no fleet to aggregate and a separate OTel/OTLP metrics pipeline would conflict with the lean single-binary supply chain (ADR-026). What is captured is sufficient locally: each outbound call's **sizes + `durationMs` live in the audit entry (C3)**, and the audit stream is OTLP-exportable in real-credential mode (ADR-016). A full OTel metric set (`run_total{code}`, `outbound_calls_total{provider,status}`, `rate_limited_total`, `client_auth_failures_total{code}`, …, bounded cardinality — never `path`/`user`/`run_id`) is an **optional, off-by-default** capability for fleet deployments, tracked as a follow-up (FU-028), not a build requirement here. **Gaps:** None.

### XC5 — Tracing
**Policy spec.** For the dev-machine profile (ADR-027), distributed tracing is **out of scope**: correlation is provided by **`run_id` threaded through the audit entries and the structured logs (XC3)** — sufficient for a local, single-hop daemon (the one remote dependency, `obo-broker`, carries its own server-side telemetry). A full OTel trace tree (root `run.handle` → `policy.authorise`/`broker.call`/`obo.exchange`/`downstream.do`/`runtime.execute`/`interaction.require`, parent-based sampling, errors always sampled) is an **optional, off-by-default** capability for fleet deployments (FU-028), not a build requirement here. **Gaps:** None.

### XC6 — Configuration
**Policy spec.** Delegates to Config (C1): env var > built-in default; secrets by `*_REF` only; fail-closed at startup. **Gaps:** None.

---

### XC7 — Health Checks (HealthCheck, C15)
**File:** `src/health.rs` | **derivedFromHld:** 0.4.1

**Purpose.** Local-only liveness/readiness for the per-user service (ADR-023); consumed by the OS service manager. Not network-exposed.

**Public Interface.** Over the control socket: `health()` → `{ live: true }` always; `ready()` → `{ ready: bool, failed: [..] }` when OIDC discovery + (if configured) `obo-broker` are reachable.

**Internal Logic.** Liveness returns immediately. Readiness pings the OIDC discovery/JWKS endpoint and the `obo-broker` health route (short timeouts); aggregates failures; ready only if all pass.

**Error Table.**
| Condition | Effect |
|---|---|
| IdP unreachable | not_ready, `failed:["idp"]` |
| obo-broker unreachable | not_ready, `failed:["obo"]` |

```gherkin
Feature: HealthCheck
  Scenario: Happy path — ready when deps reachable
    Given IdP and obo-broker reachable
    When ready() is called
    Then it returns ready=true
  Scenario: Edge — liveness independent of deps
    Given obo-broker down
    When health() is called
    Then it returns live=true
  Scenario: Error — not ready lists the failed dep
    Given the IdP is unreachable
    When ready() is called
    Then it returns ready=false with failed=["idp"]
```
**Gaps.** None.

---

### XC8 — Rate Limiting
**Policy spec.** Fixed-window per-`(client,workspace)` session budget (`PYS_MAX_CALLS_PER_SESSION`) and a per-run cap (`PYS_MAX_CALLS_PER_RUN`); over-budget → `429 RATE_LIMITED`. Enforced by PolicyEngine (C4) + SessionManager (C7). **Gaps:** None.

### XC9 — Input Validation
**Policy spec.** `RunRequest` decoded with strict/unknown-field-rejecting serde; `code` size-capped; `requested_capabilities` match `^[a-z0-9]+(\.[a-z0-9]+)*$`; path canonicalised and `..`-rejected by C4; the step-up signal is **never** a request field (raised only by the daemon). Malformed → `400 VAL_ERR`. **Gaps:** None.

### XC10 — Graceful Shutdown
**Policy spec.** On a stop signal — `SIGTERM`/`SIGINT` on Unix; on Windows the console-control events (`Ctrl-C`, `Ctrl-Break`, console close, logoff, system shutdown) for the per-user process — stop accepting connections, drain in-flight runs (bounded deadline), terminate WASM instances and drop linear memory, flush the OTLP exporter, invalidate live `capId`s, delete the connection-token file. (A real Windows Service stop handler, for a Service-based autostart rather than the per-user Run-key process, is a follow-up.) **Gaps:** None.

### XC11 — Out of scope
Pagination (the guest handles it), CORS (no browser origin; the socket is local-only), and DB migrations (no relational schema) do not apply (AS-21). Recorded so their absence is a decision, not an omission.

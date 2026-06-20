# Phase 3 — Detailed Component Specifications (`sandbox-daemon`)

All components are Rust modules in one binary (HLD ADR-026). Each carries Public Interface, numbered Internal Logic, an Error Table (≥2 rows), ≥3 Gherkin scenarios, and Gaps.

## Table of contents
- [C1 Config](#c1-config) 
- [C3 AuditLogger](#c3-auditlogger) 
- [C4 PolicyEngine](#c4-policyengine) 
- [C5 ResponseSanitizer](#c5-responsesanitizer) 
- [C6 ClientAuth](#c6-clientauth) 
- [C7 SessionManager](#c7-sessionmanager) 
- [C8 ConsentUI](#c8-consentui) 
- [C9 OboClient](#c9-oboclient) 
- [C10 DownstreamClient](#c10-downstreamclient) 
- [C11 IdentityBroker](#c11-identitybroker) 
- [C12 SandboxRuntime](#c12-sandboxruntime) 
- [C13 SandboxController](#c13-sandboxcontroller) 
- [C14 ControlEndpoint](#c14-controlendpoint) 
- [C16 McpFrontDoor](#c16-mcpfrontdoor) 
- [pysandbox_sdk](#pysandbox_sdk)

(C2 ErrorEnvelope and C15 HealthCheck are specified in [phase-4](./phase-4-cross-cutting.md).)

---

### C1 Config
**File:** `src/config.rs` | **Phase:** 3 | **Dependencies:** none · **derivedFromHld:** 0.4.1

**Purpose.** Load, validate, and expose all runtime configuration (Phase 2D `PYS_*`) once at startup, failing closed on any missing/invalid value or unverifiable secret reference.

**Public Interface.**
- `pub fn load(env: &dyn Env, resolver: &dyn SecretResolver) -> Result<Config, ConfigError>` — parse, resolve `*_REF` secrets, validate; return an immutable `Config` or the first invalid field.
- `pub trait SecretResolver { fn resolve(&self, reference: &str) -> Result<Vec<u8>, ConfigError>; }`

**Internal Logic.**
1. Read every Phase-2D variable; apply defaults where unset.
2. Resolve each `*_REF` via `resolver`; on error → `CFG_SECRET_UNRESOLVED`.
3. Validate: `PYS_OIDC_ISSUER` is an `https` URL (loopback `http://127.0.0.1`/`http://localhost` permitted — ADR-029); `PYS_RESPONSE_MAX_BYTES` ≤ 1 MiB; budgets ≥ 1; `PYS_GUEST_ARTIFACT_DIGEST` non-empty; `PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS` is a bool (default `false`) — when `true`, C10 may use `http` for a `127.0.0.1` provider host only (ADR-032); if any capability uses a token-exchange provider then `PYS_OBO_ENDPOINT` is set; in real-credential mode `PYS_OTLP_ENDPOINT` is set (else degrade to mock per ADR-016). On failure → `CFG_INVALID` naming the field.
4. Return an immutable `Config`; log resolved non-secret fields at `info`; never log secret values.

**Error Table.**
| Condition | Code | Effect |
|---|---|---|
| Required variable unset | CFG_MISSING | log + non-zero exit (startup) |
| Value fails parse/validate | CFG_INVALID | log + non-zero exit |
| Secret reference unresolved | CFG_SECRET_UNRESOLVED | log + non-zero exit |

**Gherkin.**
```gherkin
Feature: Config
  Scenario: Happy path — valid config loads
    Given all required PYS_* are set and well-formed
    When load is called
    Then it returns a Config and no error
  Scenario: Edge — OTLP unset degrades to mock mode
    Given PYS_OTLP_ENDPOINT is unset
    When load is called
    Then Config.mode is mock-only and a warning is logged
  Scenario: Error — required missing
    Given PYS_OIDC_ISSUER is unset
    When load is called
    Then it returns CFG_MISSING naming PYS_OIDC_ISSUER and the process exits non-zero
```
**Gaps.** None.

---

### C3 AuditLogger
**File:** `src/audit.rs` | **Dependencies:** Config, OTel SDK · **derivedFromHld:** 0.4.1

**Purpose.** Emit one append-only `AuditEntry` per outbound call — sizes + keyed-HMAC user id only, never tokens/bodies — and export via OTLP; mandatory in real-credential mode (ADR-016).

**Public Interface.**
- `pub async fn record(&self, e: AuditEntry)` — non-blocking enqueue; never fails the request (failure increments a metric).
- `pub fn user_hmac(&self, subject: &str) -> String` — HMAC-SHA256 under the per-install key (`PYS_AUDIT_HMAC_KEY_REF`).

**Internal Logic.**
1. Build the record from `AuditEntry`; **omit** tokens, request/response bodies, `Authorization`.
2. Export as an OTLP log record keyed on `run_id`; mirror to the local non-authoritative `.jsonl`.
3. On exporter failure: increment `audit_export_failures_total`, log `warn`, drop (never block).
4. At startup, if real-credential mode and no reachable OTLP sink → refuse real credentials (mock-only).

**Error Table.**
| Condition | Code | Effect |
|---|---|---|
| OTLP export fails | AUDIT_EXPORT_FAIL | metric + warn; request unaffected |
| HMAC key (`PYS_AUDIT_HMAC_KEY_REF`) unresolved | CFG_SECRET_UNRESOLVED (resolved by Config C1) | fail-closed at startup |

**Gherkin.**
```gherkin
Feature: AuditLogger
  Scenario: Happy path — record emitted with HMAC id, no token
    Given a completed call
    When record is called
    Then an OTLP entry with run_id and user_hmac is emitted and no token/body field
  Scenario: Edge — exporter down does not fail the run
    Given the OTLP collector is unreachable
    When record is called
    Then the run is unaffected and audit_export_failures_total increments
  Scenario: Error — real-credential mode without a sink
    Given real credentials and no reachable OTLP sink
    When the daemon starts
    Then it runs mock-only (real credentials refused)
```
**Gaps.** None.

---

### C4 PolicyEngine
**File:** `src/policy.rs` | **Dependencies:** Config · **derivedFromHld:** 0.4.1

**Purpose.** Load the capability manifest fail-closed (admin-signed overrides only, ADR-021), resolve a `capabilityId` to a `ResolvedCapability`, and authorise a call: canonical-path/method/host allowlist + per-run/session budget + step-up requirement.

**Public Interface.**
- `pub fn load(cfg: &Config) -> Result<Manifest, PolicyError>` — load default + (if present and admin-signed) overlay; reject unsigned/invalid to the shipped default.
- `pub fn resolve(&self, cap_id: &str) -> Option<ResolvedCapability>`
- `pub fn authorise(&self, cap: &ResolvedCapability, verb: &str, raw_path: &str, session: &Session) -> Result<String, PolicyError>` — canonicalise path, check host/method/path, enforce budget; return the canonical path or a typed error.

**Internal Logic.**
1. Canonicalise `raw_path`: percent-decode once; reject residual `%`; resolve `.`/`..`; collapse `//`; residual `..` → `POLICY_PATH_REJECTED`.
2. `verb ∉ cap.methods` → `POLICY_METHOD_DENIED`.
3. No anchored regex in `cap.path_allow` matches → `POLICY_PATH_DENIED`.
4. Budget: `session.calls_used + 1 > max_calls_*` → `RATE_LIMITED`.
5. `cap.require_step_up` and the session's `id_token` `acr`/recency insufficient → `STEP_UP_REQUIRED` (carries the required `acr_values`/`max_age` for the C8 challenge). Manifest load fails closed if a capability requires step-up while no acceptable `acr` set is configured.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| capability not in manifest | CAP_UNKNOWN | 403 |
| traversal after canonicalisation | POLICY_PATH_REJECTED | 400 |
| path not allowlisted | POLICY_PATH_DENIED | 403 |
| method not allowed | POLICY_METHOD_DENIED | 403 |
| budget exceeded | RATE_LIMITED | 429 |
| step-up required | STEP_UP_REQUIRED | 401 |
| unsigned/invalid override | (load) → falls back to default | n/a |

**Gherkin.**
```gherkin
Feature: PolicyEngine
  Scenario: Happy path — allowed call returns canonical path
    Given internal.tickets allows GET on ^/api/v2/tickets($|/.*)
    When authorise(GET, /api/v2/tickets/42) under budget
    Then it returns the canonical path and no error
  Scenario: Edge — traversal canonicalised then matched
    When authorise(GET, /api/v2/tickets/../tickets/42)
    Then the path canonicalises to /api/v2/tickets/42 and is allowed
  Scenario: Error — traversal escaping the allowlist
    When authorise(GET, /api/v2/tickets/../../admin)
    Then it returns POLICY_PATH_DENIED (403)
  Scenario: Error — unsigned workspace override rejected
    Given an unsigned workspace pysandbox.policy.json override
    When load is called
    Then the override is rejected and only the shipped default is in force
```
**Gaps.** None.

---

### C5 ResponseSanitizer
**File:** `src/sanitize.rs` | **Dependencies:** Config · **derivedFromHld:** 0.4.1

**Purpose.** Reduce a raw downstream response to the typed `UntrustedResponse` envelope (ADR-017): strip headers to a safe allowlist, size-cap with a truncation flag, mark untrusted.

**Public Interface.**
- `pub fn sanitize(&self, status: u16, raw: &[u8], headers: &HeaderMap, content_type: &str) -> UntrustedResponse`

**Internal Logic.**
1. Drop all response headers except `Content-Type`, `ETag`, `Retry-After`; never copy `Set-Cookie`/`Authorization`/`WWW-Authenticate`.
2. Truncate body to `PYS_RESPONSE_MAX_BYTES`; set `truncated=true` if exceeded.
3. Set `untrusted=true` always; record `unexpected_content_type_total` if not JSON/text.
4. Return `UntrustedResponse`.

**Error Table.**
| Condition | Effect |
|---|---|
| body exceeds cap | truncated, `truncated=true` (not an error) |
| unexpected content-type | metric incremented; body returned as-is (not an error) |

**Gherkin.**
```gherkin
Feature: ResponseSanitizer
  Scenario: Happy path — JSON under cap, safe headers only
    Given a 200 JSON body under the cap
    When sanitize is called
    Then untrusted=true, truncated=false, and only Content-Type/ETag/Retry-After survive
  Scenario: Edge — oversize body truncated
    Given a body larger than the cap
    When sanitize is called
    Then truncated=true and the body is capped
  Scenario: Error path — auth header stripped
    Given the response carries Set-Cookie
    When sanitize is called
    Then Set-Cookie is absent from the UntrustedResponse
```
**Gaps.** None.

---

### C6 ClientAuth
**File:** `src/clientauth.rs` | **Dependencies:** Config · **derivedFromHld:** 0.4.1 · **(security-critical — ADR-024)**

**Purpose.** Authenticate a connecting client: peer-UID equals the daemon's, the per-launch connection token matches, and (optionally) a new client identity passes first-connect consent. Mint/rotate the connection token at startup.

**Public Interface.**
- `pub fn init_token(&self) -> Result<(), AuthError>` — generate a 128-bit CSPRNG token; write `0600` to `PYS_CONNECTION_TOKEN_PATH`.
- `pub fn authenticate(&self, peer: PeerCred, presented_token: &[u8], client_label: &str) -> Result<ClientIdentity, AuthError>`

**Internal Logic.**
1. Read `peer.uid` via `SO_PEERCRED`/`getpeereid` (UDS) or `GetNamedPipeClientProcessId`+token (Windows); `uid != daemon uid` → `CLIENT_UID_DENIED`.
2. Constant-time compare `presented_token` to the live connection token; mismatch → `CLIENT_TOKEN_DENIED`.
3. If `PYS_REQUIRE_FIRST_CONNECT_CONSENT` and `client_label` is unseen this launch → raise an `InteractionRequired::Consent`-style first-connect approval; on decline → `CLIENT_NOT_APPROVED`.
4. Return `ClientIdentity{ peer_uid, client_label }`. Never log the token.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| peer UID ≠ daemon UID | CLIENT_UID_DENIED | conn refused |
| connection token mismatch/absent | CLIENT_TOKEN_DENIED | conn refused |
| new client identity declined | CLIENT_NOT_APPROVED | conn refused |

**Gherkin.**
```gherkin
Feature: ClientAuth
  Scenario: Happy path — same-UID client with valid token
    Given a same-UID client presenting the live connection token
    When authenticate is called
    Then it returns a ClientIdentity
  Scenario: Edge — first-connect consent for a new client label
    Given PYS_REQUIRE_FIRST_CONNECT_CONSENT=true and an unseen client label
    When authenticate is called and the user approves
    Then a ClientIdentity is returned and the label is remembered this launch
  Scenario: Error — wrong token rejected
    Given a client presenting an incorrect token
    When authenticate is called
    Then it returns CLIENT_TOKEN_DENIED and the connection is refused
  Scenario: Error — different UID rejected
    Given a connection whose peer UID differs from the daemon's
    When authenticate is called
    Then it returns CLIENT_UID_DENIED
```
**Gaps.** None. *(SR-24: the same-UID-process residual is bounded by consent/allowlist/budgets/audit and accepted per ADR-024; verified by the dedicated pen test, not a spec gap.)*

---

### C7 SessionManager
**File:** `src/session.rs` | **Dependencies:** Config · **derivedFromHld:** 0.4.1

**Purpose.** Hold per-`(client, workspace)` sessions in memory: consent cache and per-session call budget.

**Public Interface.**
- `pub fn get_or_create(&self, client: &ClientIdentity, workspace_id: &str) -> SessionHandle`
- `pub fn is_consented(&self, h: &SessionHandle, cap_id: &str) -> bool` / `pub fn record_consent(&self, h, cap_id)`
- `pub fn try_charge(&self, h: &SessionHandle) -> Result<(), SessionError>` — increment the session/run budget; over-budget → `RATE_LIMITED`.

**Internal Logic.**
1. Key sessions by `(peer_uid, client_label, workspace_id)`; create on first use.
2. Consent decisions and `calls_used` live only in memory; dropped on daemon stop.
3. `try_charge` enforces `PYS_MAX_CALLS_PER_SESSION`; the per-run cap is charged by the Controller.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| session budget exceeded | RATE_LIMITED | 429 |
| unknown session handle | SESSION_UNKNOWN | 500 (internal) |

**Gherkin.**
```gherkin
Feature: SessionManager
  Scenario: Happy path — consent cached within a session
    Given a session that consented to internal.tickets
    When is_consented is checked again
    Then it returns true without re-prompting
  Scenario: Edge — distinct client+workspace are isolated
    Given two sessions differing only by workspace_id
    When one records consent
    Then the other's consent set is unaffected
  Scenario: Error — session budget exhausted
    Given a session at PYS_MAX_CALLS_PER_SESSION
    When try_charge is called
    Then it returns RATE_LIMITED
```
**Gaps.** None.

---

### C8 ConsentUI
**File:** `src/interaction.rs` | **Dependencies:** Config · **derivedFromHld:** 0.4.1

**Purpose.** Render `InteractionRequired` (sign-in/consent/step-up, ADR-025) on a daemon-owned surface; return the result to the Controller. Never trusts a client-asserted result.

**Public Interface.**
- `pub async fn require(&self, who: &ClientIdentity, what: InteractionRequired) -> Result<InteractionOutcome, InteractionError>`

**Internal Logic.**
1. Select the surface per `PYS_CONSENT_UI_MODE`: `browser` → the loopback sign-in flow (always used for OIDC `SignIn`); `dialog` → native dialog/tray; `auto` → browser for sign-in, dialog for consent.
2. For `SignIn` (the concrete flow — ADR-029): do generic OIDC discovery at `<PYS_OIDC_ISSUER>/.well-known/openid-configuration`; generate a PKCE `code_verifier`/`code_challenge`, a CSPRNG `state`, and a `nonce`; bind a **transient `127.0.0.1:<ephemeral>` HTTP listener** as the `redirect_uri`; open the system browser to the `authorize` endpoint (`PYS_OIDC_CLIENT_ID` public client, `PYS_OIDC_SCOPES`, **plus a resource-audience request per entry in `what.audiences`** — ADR-033); on redirect verify `state`, close the single-use port, exchange the code (+ `code_verifier`) at the token endpoint, verify the `id_token` signature and `nonce`; **capture the `id_token` and `access_token` in the daemon only** (never returned to any client/guest); return `SignedIn(Principal)`.
   - **Resource-audience request (ADR-033).** For each audience `A` in `what.audiences`, add a Dex cross-client trusted-peer scope `audience:server:client_id:A` to the authorize request (the demo Dex mechanism; for a generic IdP the standards-track equivalent is the RFC 8707 `resource=A` parameter — OQ-G). The issued `access_token` then carries `aud` containing each `A`, so a pass-through resource server can validate it. When `what.audiences` is empty the request is unchanged from today.
3. For `Consent`: show capability id, host, methods, provider, step-up flag (ADR-021); return `Allowed`/`Denied`.
4. For `StepUp`: drive the same loopback sign-in requesting the challenged `acr` **and the same `what.audiences`** (so the refreshed token stays audienced for the run's resources — ADR-033); return the fresh `id_token`/`access_token`.
5. **Headless fallback:** if no browser/loopback (or `PYS_CONSENT_UI_MODE` selects none) and no elicitation/CLI renderer is available → `INTERACTION_UNAVAILABLE` (the Controller fails the call closed unless pre-consented/mock). Headless is a fallback posture, not the default. Remote/SSH topology (no local browser/loopback) is out of scope — device-code is the recorded future fallback (ADR-029).

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| user declines | INTERACTION_DENIED | 401/403 per kind |
| no renderer (headless) | INTERACTION_UNAVAILABLE | 401 (fail closed) |
| OIDC flow error / `state`/`nonce` mismatch / expired code | SIGN_IN_FAILED | 401 |
| IdP refuses a requested resource audience (untrusted peer / unknown resource) | SIGN_IN_FAILED | 401 |

**Gherkin.**
```gherkin
Feature: ConsentUI
  Scenario: Happy path — consent approved
    Given an interaction_required Consent for internal.tickets
    When the user approves in the daemon-owned dialog
    Then require returns Allowed
  Scenario: Edge — step-up drives a fresh id_token
    Given a StepUp challenge with acr_values=[mfa]
    When the user re-authenticates
    Then require returns a fresh id_token carrying the elevated acr
  Scenario: Edge — sign-in requests a resource audience
    Given a SignIn with audiences=[demo-resource]
    When the loopback flow completes
    Then the issued access_token carries aud containing demo-resource
  Scenario: Error — IdP refuses the requested audience
    Given a SignIn with audiences=[unknown-resource] the IdP will not grant
    When the token exchange runs
    Then require returns SIGN_IN_FAILED
  Scenario: Error — headless with no renderer
    Given no UI surface and no elicitation
    When require is called for a sensitive write
    Then it returns INTERACTION_UNAVAILABLE and the call fails closed
```
**Gaps.** None.

---

### C9 OboClient
**File:** `src/obo.rs` | **Dependencies:** Config · **derivedFromHld:** 0.4.1

**Purpose.** Call the backend `obo-broker` `POST /v1/exchange` for token-exchange providers; surface the RFC 9470 step-up challenge.

**Public Interface.**
- `pub async fn exchange(&self, id_token: &str, cap: &ResolvedCapability, verb: &str, path: &str, params: &Params, body: &[u8]) -> Result<UntrustedResponse, OboError>`

**Internal Logic.**
1. POST `{ userIdToken, capabilityId, verb, path, params?, body?, runId? }` to `PYS_OBO_ENDPOINT/v1/exchange` over TLS.
2. `401 insufficient_user_authentication` → return `OboError::StepUpRequired{ acr_values, max_age }` (Controller raises C8 step-up, retries once).
3. `2xx` → return the sanitized JSON (the backend never returns a token).
4. `5xx`/unreachable → `OBO_UNAVAILABLE`. Never log the `id_token`.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| step-up challenge | STEP_UP_REQUIRED | 401 |
| backend unreachable/5xx | OBO_UNAVAILABLE | 502/503 |
| exchange rejected | EXCHANGE_FAILED | 502 |

**Gherkin.**
```gherkin
Feature: OboClient
  Scenario: Happy path — exchange returns sanitized JSON
    Given a valid id_token and a token-exchange capability
    When exchange is called
    Then it returns the sanitized response and no token
  Scenario: Edge — step-up challenge surfaced
    Given the backend returns 401 insufficient_user_authentication
    When exchange is called
    Then it returns STEP_UP_REQUIRED with acr_values
  Scenario: Error — backend unreachable
    Given the obo-broker is down
    When exchange is called
    Then it returns OBO_UNAVAILABLE
```
**Gaps.** None.

---

### C10 DownstreamClient
**File:** `src/downstream.rs` | **Dependencies:** Config · **derivedFromHld:** 0.4.1

**Purpose.** Issue the direct-provider HTTPS call (e.g. `github`) with the broker-held credential applied; no cross-origin redirect; size-capped read. Egress is HTTPS-only, with one bounded exception: plaintext to a **loopback** provider when explicitly enabled for the dev-machine topology (ADR-032).

**Public Interface.**
- `pub async fn do_call(&self, cap: &ResolvedCapability, verb: &str, canon_path: &str, params: &Params, body: &[u8], apply: impl Fn(&mut Request)) -> Result<RawResponse, DownstreamError>`

**Internal Logic.**
1. Choose the scheme from `cap.host`: `https` by default; `http` **only if** `PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS=true` **and** the host is the loopback IP `127.0.0.1` (exactly, or `127.0.0.1:<port>` — `localhost` and any DNS name do not qualify) — ADR-032; a remote `http` URL is never produced. Build `{scheme}://{cap.host}{canon_path}` + params; host comes from policy, never caller input.
2. `apply` attaches the credential; redirect policy returns the 3xx as-is (never re-send `Authorization` across hosts — AS-17).
3. Read up to `PYS_RESPONSE_MAX_BYTES`+1; enforce the per-call timeout.
4. Transport error/timeout → `DOWNSTREAM_UNAVAILABLE`/`DOWNSTREAM_TIMEOUT`.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| timeout | DOWNSTREAM_TIMEOUT | 504 |
| connection/TLS error | DOWNSTREAM_UNAVAILABLE | 502 |

**Gherkin.**
```gherkin
Feature: DownstreamClient
  Scenario: Happy path — direct GET returns body
    Given an allowlisted host and an applied bearer
    When do_call is invoked
    Then it returns the status and body
  Scenario: Edge — cross-origin 3xx not followed
    Given a 302 to another host
    When do_call is invoked
    Then the 302 is returned as-is and Authorization is not re-sent
  Scenario: Error — timeout
    Given the host does not respond within the timeout
    When do_call is invoked
    Then it returns DOWNSTREAM_TIMEOUT
  Scenario: Dev — loopback plaintext egress when explicitly enabled
    Given PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS is true and the host is 127.0.0.1
    When do_call is invoked
    Then the request uses the http scheme
  Scenario: Security — a remote host is never downgraded to http
    Given PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS is true and the host is api.example.com
    When do_call is invoked
    Then the request uses the https scheme
  Scenario: Security — only the loopback IP qualifies, not a name
    Given PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS is true and the host is localhost
    When do_call is invoked
    Then the request uses the https scheme
```
**Gaps.** None.

---

### C11 IdentityBroker
**File:** `src/broker.rs` | **Dependencies:** Config, AuditLogger, PolicyEngine, ResponseSanitizer, OboClient, DownstreamClient, keychain · **derivedFromHld:** 0.4.1

**Purpose.** The single source of truth for credentials: hold tokens, maintain the capability table, route a `{capId, verb, path}` call to OBO (exchange) or direct provider, sanitise, and audit. Tokens never leave this module.

**Public Interface.**
- `pub fn mint_caps(&self, principal: &Principal, run_id: &str, client_label: &str, caps: &[ResolvedCapability]) -> Vec<CapabilityHandle>`
- `pub async fn call(&self, cap_id: &[u8;16], verb: &str, path: &str, params: &Params, body: &[u8]) -> Result<UntrustedResponse, BrokerError>`

**Internal Logic.**
1. `mint_caps`: generate a 128-bit `capId` per capability, valid ≤5 min, bound to the daemon instance; store `capId → ResolvedCapability + Principal + (run_id, client_label)` in the in-memory table. `run_id` is the server-minted run correlator and `client_label` the client-asserted label, bound here so each call's `AuditEntry` (step 4) is attributed to its run without per-run mutable broker state.
2. `call`: look up `capId` (unknown/expired → `CAP_INVALID`); re-check host/path/method via PolicyEngine.
3. Route by `cap.provider`: token-exchange → `OboClient.exchange` (surfaces step-up); direct → acquire the held token (OIDC session / keychain), apply via `DownstreamClient.do_call`.
4. Sanitize the raw response (C5) → `UntrustedResponse`; write an `AuditEntry` (C3); return. Never serialise a token into the result.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| capId unknown/expired | CAP_INVALID | 403 |
| step-up required (from OBO) | STEP_UP_REQUIRED | 401 |
| exchange/downstream failure | EXCHANGE_FAILED / DOWNSTREAM_* | 502/504 |
| dependency unavailable | OBO_UNAVAILABLE / IDP_UNAVAILABLE | 503 |

**Gherkin.**
```gherkin
Feature: IdentityBroker
  Scenario: Happy path — exchange capability proxied
    Given a minted capId for a token-exchange capability
    When call is invoked
    Then obo-broker is used and a sanitized UntrustedResponse is returned with no token
  Scenario: Edge — direct provider uses the held token
    Given a minted capId for a github capability
    When call is invoked
    Then the held token is applied directly and the response is sanitized
  Scenario: Error — expired capId
    Given a capId past its 5-minute validity
    When call is invoked
    Then it returns CAP_INVALID and no outbound call is made
```
**Gaps.** None.

---

### C12 SandboxRuntime
**File:** `src/runtime.rs` | **Dependencies:** Config, IdentityBroker · **derivedFromHld:** 0.4.1 · **(security-critical — ADR-013/019)**

**Purpose.** Run agent Python as RustPython-on-Wasmtime with no ambient authority and exactly one *capability* host import (the broker call shim), plus a hardened deny-by-default WASI subset (clock/random/captured-stdio only); enforce resource limits; verify the guest artefact digest before instantiation.

**Public Interface.**
- `pub async fn run(&self, code: &str, bundle: &CapabilityBundle, limits: &Limits) -> RunResult`

**Internal Logic.**
1. Verify the bundled WASM guest digest equals `PYS_GUEST_ARTIFACT_DIGEST`; mismatch → fail closed (`RUNTIME_ARTIFACT_MISMATCH`, ADR-018).
2. Instantiate Wasmtime with the hardened config (ADR-019): a **deny-by-default WASI subset** — monotonic clock, randomness, and captured stdout/stderr (fd 1/2 → byte-capped buffers) only; **no filesystem (no preopens), no sockets, no environment, no args** — plus fuel, max memory, epoch deadline, transient-execution mitigations on, risky proposals off.
3. Link exactly one **capability** host import — the broker call shim — that maps `{api_name → capId}` and forwards `{capId, verb, path}` to `IdentityBroker.call`, returning the `UntrustedResponse` to the guest. (The WASI subset above is host-provided plumbing, not a guest-grantable capability and not an egress path.)
4. Inject `pysandbox_sdk`; run `code`; capture stdout/stderr from the WASI stdio sink (byte-capped); on fuel/epoch/memory limit → terminate with the matching limit error.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| guest digest mismatch | RUNTIME_ARTIFACT_MISMATCH | startup/run fail-closed |
| fuel/epoch/memory exhausted | RUNTIME_LIMIT | run terminated |

**Gherkin.**
```gherkin
Feature: SandboxRuntime
  Scenario: Happy path — guest calls api via the single host import
    Given a verified guest and a capability bundle
    When run executes api.tickets.get(...)
    Then the broker shim is invoked and the sanitized JSON returns to the guest
  Scenario: Edge — wall-clock deadline terminates the run
    Given code that loops past the epoch deadline
    When run executes
    Then the run is terminated with RUNTIME_LIMIT
  Scenario: Error — tampered guest artefact
    Given a guest whose digest differs from PYS_GUEST_ARTIFACT_DIGEST
    When run is attempted
    Then instantiation fails closed with RUNTIME_ARTIFACT_MISMATCH
```
**Gaps.** None.

---

### C13 SandboxController
**File:** `src/controller.rs` | **Dependencies:** IdentityBroker, SandboxRuntime, PolicyEngine, ConsentUI, SessionManager, AuditLogger · **derivedFromHld:** 0.4.1

**Purpose.** Orchestrate one `run`: resolve + consent capabilities, mint the bundle, launch the runtime, route `interaction_required`, redact output, and return — never returning a token.

**Public Interface.**
- `pub async fn run(&self, req: RunRequest, session: SessionHandle) -> Result<RunResult, ControllerError>` (or `DryRunResult` when `req.dry_run`).

**Internal Logic.**
1. Resolve each `requested_capability` via PolicyEngine; unknown → `CAP_UNKNOWN`.
2. For each not-yet-consented capability in the session, raise `InteractionRequired::Consent` (C8); on decline → fail closed.
3. If `dry_run`: return `DryRunResult{ planned_calls }` (static resolution only; no tokens, no egress).
4. Collect the **distinct `audience` values** of the run's resolved capabilities (those that set one) into `audiences` (ADR-033). Ensure a valid `id_token`: raise `SignIn { issuer, audiences }` (C8) when none is held or it is expired, and raise `StepUp { acr_values, max_age_secs, audiences }` (C8) when a resolved capability sets `require_step_up` and the current `acr`/recency is insufficient; on a `STEP_UP_REQUIRED` returned from a call, drive step-up once and retry the call once (ADR-015/ADR-025). The held `access_token` is thereby audienced for each resource the run will call.
5. Mint a server-side `run_id` (128-bit CSPRNG hex; never client-asserted) for audit correlation; `mint_caps` (C11) with `run_id` + the session's `client_label` → bundle; `SandboxRuntime.run` (C12); charge per-run budget (C7).
6. Redact token-shaped strings from stdout/stderr (defence-in-depth); assemble `RunResult`; the broker already wrote per-call audit entries.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| unknown capability | CAP_UNKNOWN | 403 |
| consent/step-up declined | INTERACTION_DENIED | 401/403 |
| run budget exceeded | RATE_LIMITED | 429 |

**Gherkin.**
```gherkin
Feature: SandboxController
  Scenario: Happy path — consented run returns redacted result
    Given a session consented to internal.tickets and a valid id_token
    When run executes code that calls the capability
    Then it returns stdout/stderr (redacted), exit code, and apiCalls, with no token
  Scenario: Edge — dry-run plans without executing
    Given dry_run=true
    When run is invoked
    Then it returns plannedCalls and performs no token use or egress
  Scenario: Error — step-up declined aborts the run
    Given a requireStepUpAuth capability and the user declines step-up
    When run is invoked
    Then it returns INTERACTION_DENIED and no downstream call is made
```
**Gaps.** None.

---

### C14 ControlEndpoint
**File:** `src/endpoint.rs` | **Dependencies:** ClientAuth, SessionManager, SandboxController · **derivedFromHld:** 0.4.1

**Purpose.** Listen on the local socket; authenticate each connection (C6); bind a session (C7); accept the single `run` entry over the faraday-native RPC; stream results; emit `interaction_required`. Never network-bound. The MCP front door is the separate `mcp-stdio` sub-mode (C16), which connects here as an ordinary authenticated client (ADR-028) — the endpoint itself serves only the native RPC.

**Public Interface.**
- Native RPC (length-prefixed JSON): `connect{ clientLabel, token, workspaceId }` → session; `run(RunRequest)` → stream of `{ chunk | interaction_required | result | error }`. (The same operation that C16 wraps as the `python_sandbox` MCP tool.)

**Internal Logic.**
1. Bind the per-platform transport (ADR-030): a `0600` **Unix domain socket** with `SO_PEERCRED`/`getpeereid` (macOS/Linux) or a **named pipe** with a per-user-SID DACL and a `GetNamedPipeClientProcessId`→token-SID check (Windows); refuse if it cannot be created securely.
2. On connect: `ClientAuth.authenticate` (C6) — peer-UID/SID equality **and** the connection token; on success `SessionManager.get_or_create` (C7).
3. Dispatch `run` to `SandboxController.run`; stream chunks; forward `interaction_required` to the client (or the daemon UI) and resume.
4. Map every error to the `WireError` envelope (phase-4 registry). Never expose internal state or tokens.

**Error Table.**
| Condition | Code | Status |
|---|---|---|
| auth failure (UID/SID or token) | CLIENT_* (from C6) | connection refused |
| malformed request | VAL_ERR | 400 |
| socket/pipe cannot bind securely | (startup io error → non-zero exit; no wire code) | startup fail-closed |

**Gherkin.**
```gherkin
Feature: ControlEndpoint
  Scenario: Happy path — authenticated client runs via native RPC
    Given a client that passed connect with a valid token
    When it sends run(RunRequest)
    Then it receives streamed chunks and a final result
  Scenario: Edge — Windows named-pipe peer is the client token SID
    Given a Windows client connecting over the named pipe
    When its process token SID does not equal the daemon's user SID
    Then the connection is refused before any run (ADR-030)
  Scenario: Error — unauthenticated connection refused
    Given a connection without a valid connection token
    When it attempts to connect
    Then the connection is refused (CLIENT_TOKEN_DENIED) before any run
```
**Gaps.** None.

---

### C16 McpFrontDoor
**File:** `src/mcp.rs` (the `faradayd mcp-stdio` sub-mode) | **Dependencies:** (client of) ControlEndpoint C14 over the control socket; the connection-token file | **derivedFromHld:** 0.4.1 · **(security-relevant — ADR-028)**

**Purpose.** The MCP front door (ADR-028): an MCP server speaking **JSON-RPC 2.0 over stdin/stdout** that an MCP client (Claude Code / IDE) launches per session via `faradayd mcp-stdio`. It exposes exactly **one** tool, `python_sandbox`, and translates `tools/call` into a `connect`+`run` on the daemon's control socket. It is on the **untrusted client side** of the ADR-024 boundary: it holds no tokens, carries only `{code, requestedCapabilities}` out / sanitised JSON back, and is the same binary as the daemon (version-locked, ADR-026).

**Public Interface.**
- Process entry: `faradayd mcp-stdio` (the sub-mode dispatched from `main`).
- MCP methods: `initialize` → server info + capabilities; `tools/list` → exactly one tool `python_sandbox`; `tools/call python_sandbox` with input `{ code: string, requestedCapabilities: string[], dryRun?: bool }` → MCP tool result wrapping `RunResult` (or `DryRunResult`).
- No other tools are ever advertised (ADR-001/ADR-023).

**Internal Logic.**
1. On startup, read `PYS_CONNECTION_TOKEN_PATH` (the `0600` token file) and `PYS_SOCKET_PATH`; if the daemon socket is absent/unreachable, answer `tools/call` with a clear "daemon unavailable" MCP tool error (do not spawn a daemon).
2. Serve MCP over stdio: answer `initialize`/`tools/list`; advertise the single `python_sandbox` tool with a JSON-Schema input.
3. On `tools/call python_sandbox`: validate the input shape; open the control socket; `connect{ clientLabel:"mcp", token, workspaceId }` (C14/C6); send `run(RunRequest{ code, requested_capabilities, dry_run })`.
4. Relay the stream: forward `interaction_required` to the MCP client per MCP conventions (the daemon renders sign-in/consent/step-up — C8); on `result`/`dryRun` wrap it as the MCP tool result; on `error` map the `WireError` to an MCP tool error (code + message, no internal state).
5. Hold no tokens and never log the connection token (XC3 redaction applies).

**Error Table.**
| Condition | Code / surface | Behaviour |
|---|---|---|
| daemon socket absent/unreachable | MCP tool error `DAEMON_UNAVAILABLE` | clear actionable message; no run attempted |
| connection-token file unreadable | MCP tool error `DAEMON_UNAVAILABLE` | same — cannot authenticate |
| daemon refuses auth (UID/SID or token) | MCP tool error carrying `CLIENT_*` | surfaced verbatim from C6; no run |
| malformed `tools/call` input | MCP tool error `VAL_ERR` | rejected before any `run` |
| daemon `run` returns `WireError` | MCP tool error (code + message) | mapped from the wire envelope; no internal state/token |

**Gherkin.**
```gherkin
Feature: McpFrontDoor (mcp-stdio)
  Scenario: Happy path — tools/call relays to the daemon
    Given a running daemon and a readable connection-token file
    When an MCP client calls python_sandbox {code, requestedCapabilities}
    Then the sub-mode connects, runs, and returns a RunResult-equivalent tool result with no token
  Scenario: Edge — exactly one tool advertised
    When the MCP client calls tools/list
    Then exactly one tool, python_sandbox, is returned (never per-API tools)
  Scenario: Error — daemon not running
    Given no daemon socket present
    When an MCP client calls python_sandbox
    Then it receives a DAEMON_UNAVAILABLE tool error and no run is attempted
```
**Gaps.** None.

---

### pysandbox_sdk
**File:** `sdk/pysandbox_sdk/__init__.py` (guest Python) | **derivedFromHld:** 0.4.1

**Purpose.** The only egress path for guest code, implemented over the single WASM host import the runtime links. Shape only (no other capability exists).

**Public Interface (guest).**
- `api.<provider>.get(path, *, params=None, headers=None)` / `.post(path, *, json=None, params=None, headers=None)` / `.patch(path, *, json=None)` / `.delete(path)` → an `UntrustedResponse`-shaped object `{ untrusted, status, content_type, body }`.

**Internal Logic.**
1. Providers populate from the capability bundle delivered via the host import (not a filesystem path).
2. User `headers` are intersected with `{Accept, If-Match, Prefer}`; `Authorization` is dropped.
3. Each call invokes the single host import with `{capId, verb, path, params?, body?}` and returns the typed untrusted envelope.

**Error Table.**
| Condition | Effect |
|---|---|
| capability not in bundle | raises `PermissionError` (no host import made) |
| broker returns error | raises a typed `SandboxError` carrying the code |

**Gherkin.**
```gherkin
Feature: pysandbox_sdk
  Scenario: Happy path — get returns the untrusted envelope
    Given a bundle granting tickets
    When api.tickets.get("/api/v2/tickets/42") is called
    Then it returns an object with untrusted=true and a body
  Scenario: Edge — Authorization header dropped
    When a call passes headers={"Authorization": "x"}
    Then the header is not forwarded
  Scenario: Error — ungranted provider
    When api.secret.get("/") is called and secret is not in the bundle
    Then PermissionError is raised and no host import occurs
```
**Gaps.** None.

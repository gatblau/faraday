# Phase 3 — Detailed Component Specifications (`faradayd-server-mode`)

> **Status:** Draft
> **derivedFromHld:** 0.3.0 (`docs/design/faradayd-server-mode/`)

A delta onto `docs/spec/sandbox-daemon/phase-3-components.md`. Each spec below states **only** the server-mode change to an existing component; the baseline behaviour is inherited verbatim and not restated. Identifiers are verified against `sandbox-daemon/src/{config,policy,broker,downstream,types}.rs`. Greenfield mode — no classification tags.

## Contents
- [SPEC: Config (C1)](#spec-config-c1)
- [SPEC: PolicyEngine (C4)](#spec-policyengine-c4)
- [SPEC: IdentityBroker (C11)](#spec-identitybroker-c11)
- [SPEC: SandboxController (C13)](#spec-sandboxcontroller-c13)
- [SPEC: Policy manifest schema (SCHEMA)](#spec-policy-manifest-schema-schema)

---

### SPEC: Config (C1)
**File:** `src/config.rs` | **Package:** `config` | **Phase:** 3 | **Dependencies:** SecretResolver

> **Mode:** greenfield
> **derivedFromHld:** 0.3.0

#### Purpose
Make the OIDC configuration group optional so a pure `api_key`/`none` deployment starts with no sign-in configuration (ADR-038), without weakening validation for deployments that do use OIDC.

#### Approach
Relax the two OIDC fields from required-at-load to optional-at-load, and move the "OIDC must be present" check to a separate, manifest-aware step that the bootstrap calls only when the loaded manifest contains an `exchange`/`passthrough` capability. This avoids coupling `Config` to manifest parsing (the manifest is owned by C4) while keeping the fail-closed posture. Rejected: parse the manifest inside `Config::load` (couples C1 to C4 and to the policy file format).

#### Shared Context
- `CredentialMode` (`config.rs:42-46`): `Real` iff `PYS_OTLP_ENDPOINT` is set, else `Mock` (ADR-016) — **unchanged**.
- `ConfigError { code: &'static str, field: String }` with codes `CFG_MISSING`, `CFG_INVALID`, `CFG_SECRET_UNRESOLVED` (`config.rs:196-207`).
- `SecretResolver` / `FileSecretResolver` (`config.rs:9-24`): resolves a reference to bytes by reading it as a file path — **unchanged**, reused by the bootstrap to resolve api_key secrets (C11 `ApiKeyStore`).

#### Public Interface
- **Changed field types** on `struct Config`: `pub oidc_issuer: Option<String>` and `pub oidc_client_id: Option<String>` (were `String`, `config.rs:54-55`). All other fields unchanged.
- **`Config::load(get: &dyn Fn(&str) -> Option<String>, resolver: &dyn SecretResolver) -> Result<Config, ConfigError>`** — signature unchanged; behaviour changed (below).
- **New: `Config::require_oidc(&self) -> Result<(), ConfigError>`** — returns `Err(CFG_MISSING)` naming `PYS_OIDC_ISSUER` (or `PYS_OIDC_CLIENT_ID`) if either is `None`; `Ok(())` otherwise. The bootstrap calls this only when `PolicyEngine::has_oidc_capability()` (C4) is true.

#### Example
- Key-only container env (no OIDC vars set): `Config::load` succeeds with `oidc_issuer == None`; bootstrap sees `has_oidc_capability() == false` and does **not** call `require_oidc`. Daemon starts.
- Mixed manifest (one `passthrough` cap) with `PYS_OIDC_ISSUER` unset: `Config::load` succeeds, but bootstrap calls `require_oidc()` → `Err(CFG_MISSING { field: "PYS_OIDC_ISSUER" })`; daemon refuses to start.

#### Internal Logic
1. `oidc_issuer = opt(get, "PYS_OIDC_ISSUER")` (was `required`). If `Some`, validate the existing format rule (`https://` or `http://127.0.0.1`/`http://localhost`, `config.rs:101-106`); on failure return `CFG_INVALID("PYS_OIDC_ISSUER")`. If `None`, skip the format check. [changed]
2. `oidc_client_id = opt(get, "PYS_OIDC_CLIENT_ID")` (was `required`). [changed]
3. All other field loads (`PYS_POLICY_PATH` required, `PYS_AUDIT_HMAC_KEY_REF` required+resolved, `PYS_OTLP_ENDPOINT` optional, budgets, WASM limits, `credential_mode`) are **unchanged** (`config.rs:112-187`).
4. `require_oidc()` (new): if `oidc_issuer.is_none()` return `CFG_MISSING("PYS_OIDC_ISSUER")`; if `oidc_client_id.is_none()` return `CFG_MISSING("PYS_OIDC_CLIENT_ID")`; else `Ok(())`.

#### Data Model
N/A — no persistent store; `Config` is an in-memory immutable struct.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| `PYS_OIDC_ISSUER` set but not `https`/loopback | n/a (startup, fail-closed) | CFG_INVALID | `CFG_INVALID: config PYS_OIDC_ISSUER` |
| Manifest has an OIDC capability but `PYS_OIDC_ISSUER`/`PYS_OIDC_CLIENT_ID` unset | n/a (startup, fail-closed) | CFG_MISSING | `CFG_MISSING: config PYS_OIDC_ISSUER` |
| `PYS_AUDIT_HMAC_KEY_REF` file unreadable (unchanged) | n/a (startup) | CFG_SECRET_UNRESOLVED | `CFG_SECRET_UNRESOLVED: config <ref>` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: Config OIDC optionality (server-mode)

  Scenario: Happy path — key-only deployment starts without OIDC
    Given PYS_OIDC_ISSUER and PYS_OIDC_CLIENT_ID are unset
    And the manifest contains only api_key and none capabilities
    When Config::load runs and the bootstrap evaluates has_oidc_capability()
    Then load succeeds and require_oidc is not called and the daemon starts

  Scenario: Edge case — OIDC vars present but unused
    Given PYS_OIDC_ISSUER is a valid https issuer
    And the manifest contains only api_key capabilities
    When Config::load runs
    Then load succeeds and oidc_issuer is Some and require_oidc is not called

  Scenario: Error path — OIDC capability without OIDC config
    Given the manifest contains a passthrough capability
    And PYS_OIDC_ISSUER is unset
    When the bootstrap calls require_oidc()
    Then it returns CFG_MISSING naming PYS_OIDC_ISSUER and the daemon does not start
```

#### Performance, Security, Observability
- **Performance:** startup-only; negligible.
- **Security:** no weakening — OIDC is enforced whenever an OIDC-backed capability exists; the format check is retained when an issuer is set. Real-credential mode still requires the OTLP sink (unchanged).
- **Observability:** the `CFG_MISSING`/`CFG_INVALID` startup error is logged at the existing startup-failure log site.

#### Gaps
None.

---

### SPEC: PolicyEngine (C4)
**File:** `src/policy.rs` | **Package:** `policy` | **Phase:** 3 | **Dependencies:** SecretResolver (resolution done by bootstrap, not C4)

> **Mode:** greenfield
> **derivedFromHld:** 0.3.0

#### Purpose
Parse and validate the two new auth modes and their fields at manifest load, enforce the read-only-by-default write gate (ADR-039), and expose the distinct api_key secret references so the bootstrap can resolve them once at startup.

#### Approach
Extend `RawCapability`/`ResolvedCapability` with the three new fields and add load-time validation as a per-capability pass inside the existing `load()` loop. Enforcing at load (not per call) keeps the runtime `authorise()` path (`policy.rs:91-112`) unchanged — the existing method/path allowlist remains the per-call check; the write gate is a load-time structural rule. Rejected: enforce the write gate per call (duplicates the method check and risks a load-time/runtime split).

#### Shared Context
- `AuthMode` extended with `ApiKey` (`#[serde(rename = "api_key")]`) and `Unauthenticated` (`#[serde(rename = "none")]`) — Phase 2C.
- `KeyPlacement` (`Header { name, scheme: Option<String> }` | `Query { param }`) — Phase 2C.
- `ResolvedCapability` gains `secret_ref: Option<String>`, `key_placement: Option<KeyPlacement>`, `allow_write: bool` — Phase 2C.
- `WireError::new(code, msg)`; load failures use `CFG_INVALID` (`policy.rs:56,65`).
- Admin-signed load path: `load(default_json, signed_override, verify)` falls back to the shipped default unless `verify(json, sig)` is true (`policy.rs:46-54`) — **unchanged**; an unsigned override therefore cannot introduce a writable capability.

#### Public Interface
- **`PolicyEngine::load(default_json: &str, signed_override: Option<(&str, &[u8])>, verify: &dyn Fn(&[u8], &[u8]) -> bool) -> Result<PolicyEngine, WireError>`** — signature unchanged; validation extended (below).
- **`PolicyEngine::resolve(&self, cap_id: &str) -> Option<&ResolvedCapability>`** — unchanged.
- **`PolicyEngine::authorise(...) -> Result<String, WireError>`** — unchanged (runtime method/path/budget check).
- **New: `PolicyEngine::api_key_secret_refs(&self) -> Vec<String>`** — the distinct `secret_ref` values of capabilities whose `auth_mode == ApiKey`. Bootstrap input for building the `ApiKeyStore`.
- **New: `PolicyEngine::has_oidc_capability(&self) -> bool`** — true iff any capability's `auth_mode` is `Exchange` or `Passthrough`. Drives `Config::require_oidc` (C1).

#### Example
Manifest fragment for a public read and a keyed write:
```json
{
  "capabilities": {
    "gov.holidays": { "authMode": "none", "host": "www.gov.uk",
      "pathAllow": ["^/bank-holidays.json$"], "methods": ["GET"] },
    "tickets.create": { "authMode": "api_key", "host": "api.example.com",
      "pathAllow": ["^/v1/tickets$"], "methods": ["POST"], "allowWrite": true,
      "secretRef": "/var/run/secrets/tickets.key",
      "keyPlacement": { "header": { "name": "Authorization", "scheme": "Token" } } }
  },
  "defaults": { "requireUserConsentPerSession": false, "maxCallsPerRun": 50,
    "maxCallsPerSession": 500, "responseMaxBytes": 1048576 }
}
```
`api_key_secret_refs()` → `["/var/run/secrets/tickets.key"]`; `has_oidc_capability()` → `false`.

#### Internal Logic
1. Deserialise each `RawCapability` (now also reading `secretRef`→`secret_ref`, `keyPlacement`→`key_placement`, `allowWrite`→`allow_write` default `false`; `provider` is optional with a `default` and is required only for OIDC modes — rule 5). [changed]
2. Build `ResolvedCapability` carrying the three new fields. [changed]
3. **Validation pass** per capability (all failures → `WireError::new("CFG_INVALID", <reason>)`): [new]
   1. `auth_mode == ApiKey` ⇒ `secret_ref.is_some()` and `key_placement.is_some()`, else `CFG_INVALID("api_key requires secretRef + keyPlacement")`.
   2. `auth_mode != ApiKey` ⇒ `secret_ref.is_none()` and `key_placement.is_none()`, else `CFG_INVALID("secretRef/keyPlacement only valid for api_key")`.
   3. `auth_mode ∈ {ApiKey, Unauthenticated}` ⇒ `require_step_up == false`, else `CFG_INVALID("step-up not applicable for api_key/none")` (AS-8).
   4. `allow_write == false` ⇒ no element of `methods` equals (case-insensitive) `POST`/`PUT`/`PATCH`/`DELETE`, else `CFG_INVALID("unsafe method requires allowWrite")` (ADR-039 / AS-5).
   5. `auth_mode ∈ {Exchange, Passthrough}` ⇒ `provider` is non-empty, else `CFG_INVALID("provider required for exchange/passthrough")` — the pluggable provider set is not enumerable in the schema, so the broker validates it at load. [reconciled from code, /sync-spec]
4. `api_key_secret_refs()` collects distinct `secret_ref` of `ApiKey` capabilities. `has_oidc_capability()` scans `auth_mode`. [new]
5. `authorise()` is **unchanged** — the per-call method/path/budget check still applies to every mode, including `none`.

#### Data Model
The capability-manifest shape it parses is specified in [SPEC: Policy manifest schema](#spec-policy-manifest-schema-schema). No persistent store.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| `api_key` capability missing `secretRef` or `keyPlacement` | n/a (load, fail-closed) | CFG_INVALID | `CFG_INVALID: config api_key requires secretRef + keyPlacement` |
| `secretRef`/`keyPlacement` on a non-`api_key` capability | n/a (load) | CFG_INVALID | `CFG_INVALID: config secretRef/keyPlacement only valid for api_key` |
| `requireStepUpAuth: true` on `api_key`/`none` | n/a (load) | CFG_INVALID | `CFG_INVALID: config step-up not applicable for api_key/none` |
| Unsafe method on a capability without `allowWrite: true` | n/a (load) | CFG_INVALID | `CFG_INVALID: config unsafe method requires allowWrite` |
| `exchange`/`passthrough` capability with empty/missing `provider` | n/a (load) | CFG_INVALID | `CFG_INVALID: config provider required for exchange/passthrough` |
| `pathAllow` regex invalid (unchanged) | n/a (load) | CFG_INVALID | `CFG_INVALID: config pathAllow regex` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: PolicyEngine server-mode validation

  Scenario: Happy path — public read + keyed write load
    Given a manifest with a none GET capability and an api_key POST capability with allowWrite true, secretRef and a header keyPlacement
    When PolicyEngine::load runs against the trusted default
    Then load succeeds and api_key_secret_refs returns the one secretRef and has_oidc_capability is false

  Scenario: Edge case — read-only api_key needs no allowWrite
    Given an api_key capability whose methods are ["GET"] with allowWrite absent
    When PolicyEngine::load runs
    Then load succeeds

  Scenario: Error path — unsafe method without opt-in
    Given a capability with methods ["POST"] and allowWrite absent or false
    When PolicyEngine::load runs
    Then it returns CFG_INVALID naming the unsafe-method/allowWrite rule

  Scenario: Error path — unsigned override cannot enable a write
    Given a signed default with no writable capability and an unsigned override adding an allowWrite POST capability
    When PolicyEngine::load runs with a verifier that rejects the override
    Then the shipped default is used and the writable capability is absent
```

#### Performance, Security, Observability
- **Performance:** load-time only; O(capabilities).
- **Security:** the write gate is load-time and fail-closed; it is honoured only through the admin-signed path, so workspace tampering cannot enable writes (ADR-021/ADR-039). `none` capabilities remain host/path/method-allowlisted.
- **Observability:** load failures surface the `CFG_INVALID` reason at the startup-failure log site; no secret value is logged (only the `secret_ref` reference string, which is a path, not a key).

#### Gaps
None.

---

### SPEC: IdentityBroker (C11)
**File:** `src/broker.rs` | **Package:** `broker` | **Phase:** 3 | **Dependencies:** Config, PolicyEngine, DownstreamClient, AuditLogger, ApiKeyStore

> **Mode:** greenfield
> **derivedFromHld:** 0.3.0

#### Purpose
Route an `api_key` capability call by applying its startup-resolved static key at the configured placement, and a `none` capability call with no credential — preserving the invariant that the key is never serialised into the returned envelope or logged.

#### Approach
Add two arms to the existing `match cap.auth_mode` in `call()` (`broker.rs:263-312`). Header placement reuses the existing `apply_credential` helper (`broker.rs:338-357`) via a `Credential::Headers`/`Credential::Bearer`; query placement appends `(param, key)` to a local copy of `params` and uses a no-op `apply` closure, leaning on `do_call`'s existing `Params`→query serialisation (`downstream.rs:124-127`). The key is fetched from an injected, startup-frozen `ApiKeyStore` (AS-6) so the broker holds no file-resolution logic and the key lives only in the broker's memory. Rejected: resolve the key from a file on each call (re-reads on the hot path; contradicts AS-6).

#### Shared Context
- `match cap.auth_mode { Exchange => …, Passthrough => … }` today (`broker.rs:263-312`); `Passthrough` builds `Credential::Bearer`, calls `downstream.do_call(&cap, verb, &canon, params, body, |req| apply_credential(req, &cred))`, then `sanitize::sanitize(...)`.
- `apply_credential(req, cred)` injects `Credential::Bearer` as `Authorization: Bearer <t>` or `Credential::Headers` as arbitrary headers (`broker.rs:338-357`) — **unchanged**.
- `ApiKeyStore::lookup(&self, secret_ref) -> Option<String>` — Phase 2C.
- `KeyPlacement` — Phase 2C. `Params = Vec<(String, String)>` (`types.rs:158`).
- `AuditEntry` — unchanged (`types.rs:171-186`); records sizes + keyed-HMAC id, never a token.

#### Public Interface
- **Constructor change:** `IdentityBroker::new(policy, audit, obo, downstream, creds, max_response_bytes, api_keys: Arc<dyn ApiKeyStore>)` — one new trailing parameter; `with_ttl`/`new_with_ttl` gain it identically. [changed]
- **New `BrokerError` variant:** `KeyUnavailable` → `code() == "API_KEY_UNAVAILABLE"` (`broker.rs:53-63`). [new]
- **`call(cap_id, verb, path, params, body) -> Result<UntrustedResponse, BrokerError>`** — signature unchanged; two new match arms (below).

#### Example
- `api_key` header capability (`Authorization: Token`): `lookup` returns `gov_xyz`; the broker builds `Credential::Headers({"Authorization": "Token gov_xyz"})`, calls `do_call` with `apply_credential`, returns the sanitised body. The returned `UntrustedResponse` contains no key; the `AuditEntry` records `provider`, `host`, `path`, status, sizes — no key.
- `api_key` query capability (`?api_key=`): the broker calls `do_call` with `params` = original + `("api_key", "gov_xyz")` and a no-op `apply`.
- `none` capability: `do_call` with original `params` and a no-op `apply`; no `Authorization`.

#### Internal Logic
(Steps 1–3 — capId lookup/expiry, throwaway-session re-authorise via `PolicyEngine::authorise` — are **unchanged**, `broker.rs:230-260`.)
4. `match cap.auth_mode`:
   - `Exchange` / `Passthrough`: **unchanged** (`broker.rs:267-311`).
   - **`ApiKey`** [new]:
     1. `key = self.api_keys.lookup(cap.secret_ref.as_deref().unwrap_or_default()).ok_or(BrokerError::KeyUnavailable)?`.
     2. Match `cap.key_placement` (guaranteed `Some` by C4 load validation):
        - `Header { name, scheme }`: `value = scheme.map(|s| format!("{s} {key}")).unwrap_or(key)`; `cred = Credential::Headers({ name: value })`; `raw = downstream.do_call(&cap, verb, &canon, params, body, |req| apply_credential(req, &cred)).await?`.
        - `Query { param }`: `let mut q = params.clone(); q.push((param.clone(), key));` `raw = downstream.do_call(&cap, verb, &canon, &q, body, |_req| {}).await?`.
     3. `status = raw.status`; `sanitised = sanitize::sanitize(raw.status, &raw.body, &raw.headers, self.max_response_bytes)`; `(sanitised, status)`. (Mirrors the `Passthrough` tail, `broker.rs:303-310`.)
   - **`Unauthenticated`** [new]: `raw = downstream.do_call(&cap, verb, &canon, params, body, |_req| {}).await?`; sanitise as above. No credential is built or applied.
5. Audit the call (**unchanged**, `broker.rs:317-331`): the key is not a field and is never recorded.

#### Data Model
N/A — in-memory capability table only (`broker.rs:104`); the `ApiKeyStore` is an in-memory frozen map. No persistence.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| `api_key` capability whose `secret_ref` was not resolved at startup | 502 | API_KEY_UNAVAILABLE | `{"error":"api key unavailable","code":"API_KEY_UNAVAILABLE"}` |
| capId unknown/expired (unchanged) | 403 | CAP_INVALID | `{"error":"...","code":"CAP_INVALID"}` |
| downstream connection/TLS error (unchanged) | 502 | DOWNSTREAM_UNAVAILABLE | `{"error":"...","code":"DOWNSTREAM_UNAVAILABLE"}` |
| downstream timeout (unchanged) | 504 | DOWNSTREAM_TIMEOUT | `{"error":"...","code":"DOWNSTREAM_TIMEOUT"}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: IdentityBroker api_key and none routing

  Scenario: Happy path — api_key header placement
    Given a resolved api_key capability with a header keyPlacement and a key in the ApiKeyStore
    When call() routes the request
    Then do_call is invoked with an apply closure that sets the configured header
    And the returned envelope contains no key and the audit entry records no key

  Scenario: Happy path — api_key query placement
    Given a resolved api_key capability with a query keyPlacement param "api_key"
    When call() routes the request
    Then the key is appended to params as ("api_key", <key>) and apply is a no-op

  Scenario: Happy path — none sends no credential
    Given a resolved none capability
    When call() routes the request
    Then do_call is invoked with a no-op apply closure and no Authorization header is set

  Scenario: Error path — api_key with unresolved key
    Given an api_key capability whose secret_ref is not in the ApiKeyStore
    When call() routes the request
    Then it returns BrokerError::KeyUnavailable with code API_KEY_UNAVAILABLE
```

#### Performance, Security, Observability
- **Performance:** one `ApiKeyStore` map lookup (O(1)) plus the existing one downstream HTTPS hop; no token-exchange round-trip (lower latency than `Exchange`).
- **Security:** the key is applied to the outbound request and never written into `UntrustedResponse`, the audit entry, or a log line (the invariant of `broker.rs:1-5`, preserved). `none` attaches no credential. Cross-origin redirects are still not followed (C10/AS-17), so a key in a header is never replayed to another host.
- **Observability:** the `AuditEntry` for an `api_key`/`none` call is identical in shape to existing modes (sizes + keyed-HMAC user id); `provider` may be empty for these modes.

#### Gaps
None.

---

### SPEC: SandboxController (C13)
**File:** `src/controller.rs` | **Package:** `controller` | **Phase:** 3 | **Dependencies:** IdentityBroker, PolicyEngine, ConsentUI, SessionManager

> **Mode:** greenfield
> **derivedFromHld:** 0.3.0

#### Purpose
Run a request whose resolved capabilities are all `api_key`/`none` with **no** interactive sign-in, consent render, or step-up, and contribute no audiences — so a headless server agent proceeds without a human (ADR-038/ADR-039), while OIDC-backed runs are unchanged.

#### Approach
At capability-resolution time, partition the run's resolved capabilities by auth mode. Raise `InteractionRequired::SignIn`/`StepUp` and collect audiences only for OIDC-backed capabilities (`Exchange`/`Passthrough`); treat `api_key`/`none` capabilities as pre-granted by the admin-signed policy (ADR-039) and skip every interactive step for them. Rejected: a global "server-mode" flag that disables all interaction (can contradict a mixed manifest that still has an OIDC capability).

#### Shared Context
- Baseline behaviour (inherited): the Controller resolves `requested_capabilities` to `ResolvedCapability` via `PolicyEngine`, raises `InteractionRequired::SignIn { issuer }` when sign-in is needed, collects `Passthrough` audiences for the sign-in challenge (ADR-033), and gates first use of a capability on consent when `requireUserConsentPerSession` is set.
- `AuthMode` with the two new variants — Phase 2C.
- `InteractionRequired` (`types.rs:73-88`) — **unchanged**.

#### Public Interface
No signature change. The behavioural change is internal to the run-setup path: the predicate that decides whether to raise sign-in/consent/step-up now excludes `api_key`/`none` capabilities.

#### Example
- Run requests `["gov.holidays" (none), "tickets.create" (api_key)]`: the Controller raises **no** `SignIn`, collects **no** audiences, renders **no** consent, and proceeds straight to `mint_caps` + execute.
- Run requests `["repo.read" (passthrough), "gov.holidays" (none)]`: the Controller raises `SignIn` carrying the `passthrough` capability's audience (unchanged); the `none` capability adds nothing to the challenge.

#### Internal Logic
1. Resolve `requested_capabilities` to `ResolvedCapability[]` (unchanged).
2. Partition by `auth_mode`: `oidc = {Exchange, Passthrough}`, `non_oidc = {ApiKey, Unauthenticated}`. [new]
3. Sign-in: raise `InteractionRequired::SignIn` only if `oidc` is non-empty (unchanged condition, now restricted to `oidc`). If the run is all `non_oidc`, raise no sign-in. [changed]
4. Audiences (ADR-033): collect from `Passthrough` capabilities only (unchanged); `non_oidc` capabilities contribute none. [unchanged]
5. Consent: for an `oidc` capability, gate first use on consent per `requireUserConsentPerSession` (unchanged). For a `non_oidc` capability, treat consent as pre-granted by the admin-signed policy (ADR-039) — render no consent challenge. [changed]
6. Step-up: never raised for `non_oidc` capabilities (and C4 rejects `requireStepUpAuth` on them at load, so the case cannot arise). [changed]
7. Principal + mint: a run that includes an `oidc` capability uses the user `Principal` returned by sign-in. An all-`non_oidc` run has no human, so the Controller synthesises a fixed **service-identity principal** (`subject = "faradayd:server-mode"`, empty issuer, no `acr`/`amr`/`auth_time`) for `mint_caps` and for audit attribution — single-tenant, one daemon per agent (ADR-034). Then `mint_caps` + execute. [reconciled from code, /sync-spec: `controller.rs` `SERVER_MODE_SUBJECT`]

#### Data Model
N/A — session/consent state is the existing in-memory `Session` (`types.rs:13-20`); no new persistence.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| OIDC capability requested but sign-in unavailable (headless, unchanged) | 401 | INTERACTION_UNAVAILABLE | `{"error":"...","code":"INTERACTION_UNAVAILABLE"}` |
| Requested capability not in manifest (unchanged) | 403 | CAP_UNKNOWN | `{"error":"...","code":"CAP_UNKNOWN"}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: SandboxController interaction gating (server-mode)

  Scenario: Happy path — all-non-OIDC run needs no human
    Given a run whose resolved capabilities are all api_key or none
    When the Controller sets up the run
    Then no SignIn is raised, no consent is rendered, and no audiences are collected

  Scenario: Edge case — mixed run still signs in for the OIDC capability
    Given a run with one passthrough capability and one none capability
    When the Controller sets up the run
    Then SignIn is raised carrying the passthrough audience and the none capability adds none

  Scenario: Error path — OIDC capability with no renderer
    Given a run with an exchange capability in a headless deployment with no renderer
    When the Controller sets up the run
    Then it fails closed with INTERACTION_UNAVAILABLE

  Scenario: Edge case — headless run attributes audit to the service subject
    Given a run whose resolved capabilities are all api_key or none
    When the Controller mints capabilities and a call is audited
    Then the audit principal subject is "faradayd:server-mode"
```

#### Performance, Security, Observability
- **Performance:** removes the sign-in round-trip for all-`non_oidc` runs.
- **Security:** `non_oidc` capabilities are authorised by the admin-signed policy (the pre-grant, ADR-039); the write gate (C4) and the runtime allowlist/budgets still bound them. Skipping consent does not widen access — the policy already fixed host/path/method and the write opt-in.
- **Observability:** unchanged; each call is audited by C11.

#### Gaps
None.

---

### SPEC: Policy manifest schema (SCHEMA)
**File:** `docs/design/sandbox-daemon/schema/pysandbox.policy.schema.json` | **Phase:** 3 | **Dependencies:** —

> **Mode:** greenfield
> **derivedFromHld:** 0.3.0

#### Purpose
Add the `authMode` property (currently absent despite being read by `RawCapability`), the two new values, and the `secretRef`/`keyPlacement`/`allowWrite` fields, with conditional requireds so `none`/`api_key` capabilities need no `provider`/`audience`/`scopes`.

#### Approach
Additive, backward-compatible edits to `$defs/capability`. Because the def has `additionalProperties: false`, every new field must be declared or conformant manifests fail validation. The runtime fail-closed gate is C4's `load()`; the schema is the authoring-time (editor/CI) check and must agree with C4. Rejected: leave `authMode` schema-undeclared and rely on C4 alone (an `authMode` manifest fails schema validation today — the existing omission, AS-10).

#### Shared Context
- Current `$defs/capability` `required`: `["provider", "scopes", "host", "pathAllow", "methods"]`; `additionalProperties: false`; existing conditional `provider == "rfc8693" ⇒ audience` (schema lines 71-80).
- `methods` items enum: `["GET", "POST", "PATCH", "PUT", "DELETE"]` (schema line 60).

#### Public Interface (schema additions)
- **`authMode`** — `{ "type": "string", "enum": ["exchange", "passthrough", "api_key", "none"], "default": "exchange" }`.
- **`secretRef`** — `{ "type": "string", "minLength": 1 }` (a `SecretResolver` reference; a file path under `FileSecretResolver`).
- **`keyPlacement`** — `oneOf`:
  - `{ "type": "object", "additionalProperties": false, "required": ["header"], "properties": { "header": { "type": "object", "additionalProperties": false, "required": ["name"], "properties": { "name": {"type":"string","minLength":1}, "scheme": {"type":"string","minLength":1} } } } }`
  - `{ "type": "object", "additionalProperties": false, "required": ["query"], "properties": { "query": { "type": "object", "additionalProperties": false, "required": ["param"], "properties": { "param": {"type":"string","minLength":1} } } } }`
- **`allowWrite`** — `{ "type": "boolean", "default": false }`.

#### Internal Logic (validation rules, expressed as schema `allOf` clauses)
1. Base `required` relaxed to `["host", "pathAllow", "methods"]`.
2. `if authMode ∈ {exchange, passthrough}` (or absent → default exchange) `then required: ["provider", "scopes"]` (and the existing `provider == rfc8693 ⇒ audience` clause stands).
3. `if authMode == "api_key" then required: ["secretRef", "keyPlacement"]`.
4. `if authMode == "api_key"` or `authMode == "none" then properties: { requireStepUpAuth: { const: false } }` (mirrors C4 rule AS-8).
5. `if not (allowWrite == true) then properties: { methods: { items: { enum: ["GET"] } } }` (mirrors C4 write gate, ADR-039/AS-5).
6. `secretRef`/`keyPlacement` permitted only when `authMode == "api_key"` (`if authMode != api_key then properties: { secretRef: false, keyPlacement: false }`).

#### Data Model
The full JSON Schema document is the artefact; the edits above are applied to `$defs/capability`. No DB.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Manifest fails schema validation at authoring/CI | n/a (authoring-time) | (validator) | validator-specific |
| Same manifest at daemon load (runtime gate) | n/a (startup, fail-closed) | CFG_INVALID | `CFG_INVALID: config <reason>` (C4) |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: Policy schema server-mode additions

  Scenario: Happy path — api_key capability validates
    Given a capability with authMode api_key, secretRef, a header keyPlacement, allowWrite true, methods ["POST"]
    When validated against the schema
    Then it passes

  Scenario: Edge case — none capability needs no provider/audience/scopes
    Given a capability with authMode none, host, pathAllow, methods ["GET"]
    When validated against the schema
    Then it passes

  Scenario: Error path — unsafe method without allowWrite fails schema
    Given a capability with methods ["DELETE"] and allowWrite absent
    When validated against the schema
    Then it fails (methods restricted to GET when allowWrite is not true)
```

#### Performance, Security, Observability
- **Performance:** N/A (authoring/CI artefact).
- **Security:** the schema mirrors C4's runtime gates so an authoring-time check catches the same write-gate and step-up violations; C4 remains the authoritative fail-closed gate at load.
- **Observability:** N/A.

#### Gaps
None.

# Phase 4 — Cross-Cutting Concern Specifications (`faradayd-server-mode`)

> **Status:** Draft
> **derivedFromHld:** 0.3.0 (`docs/design/faradayd-server-mode/`)

A delta onto `docs/spec/sandbox-daemon/phase-4-cross-cutting.md`. Only concerns with a server-mode change are specified; the rest are inherited unchanged.

## Inherited unchanged (no server-mode delta)

| Concern | Stance |
|---|---|
| Tracing | Inherited — `run_id` correlation, no distributed tracing (sandbox-daemon ADR-027). |
| Metrics | Inherited — no metrics pipeline by default. |
| Rate Limiting | Inherited — per-run/session call budgets apply to `api_key`/`none` identically. |
| Pagination | Inherited — single `run()` entry; not applicable. |
| CORS | Inherited — no browser-facing surface in this profile. |
| Database Migrations | N/A — no datastore. |
| Health Checks | Inherited — startup is fail-closed. |
| Graceful Shutdown | Inherited — unchanged. |
| Input Validation | Inherited — strict `RunRequest` parsing + per-call path/method re-check; plus the new manifest-field validation specified in Phase 3 C4. |

## Contents (delta specs)
- [SPEC: Authentication & Authorisation (downstream)](#spec-authentication--authorisation-downstream)
- [SPEC: Configuration](#spec-configuration)
- [Error Handling — delta](#error-handling--delta)
- [Logging — delta](#logging--delta)

---

### SPEC: Authentication & Authorisation (downstream)
**File:** cross-cutting (realised in `broker`, `policy`) | **Phase:** 4 | **Dependencies:** PolicyEngine (C4), IdentityBroker (C11), ApiKeyStore

> **Mode:** greenfield
> **derivedFromHld:** 0.3.0

#### Purpose
Define the server-mode downstream credential policy: two new credential modes (`api_key`, `none`) and the read-only-by-default write gate, all preserving the no-credential-to-guest invariant.

#### Approach
The credential model stays "the broker applies, the guest never holds" (ADR-002). `api_key` adds a static-key credential whose custody is identical to `passthrough`'s access-token custody; `none` adds an explicit no-credential path. Authorisation gains a load-time write gate (ADR-039) on top of the unchanged runtime host/path/method allowlist. Rejected: a runtime per-call write check (duplicates the existing method allowlist).

#### Shared Context
- Downstream auth modes: `Exchange`, `Passthrough` (inherited), `ApiKey`, `Unauthenticated` (new) — Phase 2C.
- Write gate: `allowWrite` (default false); unsafe methods (`POST`/`PUT`/`PATCH`/`DELETE`) require `allowWrite: true`, honoured only via the admin-signed load path — Phase 3 C4.
- Key custody: `ApiKeyStore` holds startup-resolved keys in the broker's memory; never serialised to the guest, the response envelope, or the audit trail — Phase 3 C11.

#### Public Interface
The policy is expressed in the manifest (`authMode`, `secretRef`, `keyPlacement`, `allowWrite`) and enforced by C4 (load) + C11 (call). No new runtime API.

#### Internal Logic
1. Each capability declares exactly one `authMode`. `api_key` requires `secretRef` + `keyPlacement`; `none` requires neither provider nor credential.
2. Authorisation is two-layer: **load-time** — the write gate and step-up/secret-field structural rules (C4); **runtime** — the unchanged host/path/method allowlist + budgets (C4 `authorise`, applied to every mode including `none`).
3. Credential application is per `authMode` in C11: `api_key` → key at `keyPlacement`; `none` → none; `exchange`/`passthrough` → unchanged.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Unsafe method without `allowWrite` (load) | n/a | CFG_INVALID | `CFG_INVALID: config unsafe method requires allowWrite` |
| `api_key` key unresolved at call | 502 | API_KEY_UNAVAILABLE | `{"error":"api key unavailable","code":"API_KEY_UNAVAILABLE"}` |
| Off-allowlist host/path/method, any mode (unchanged) | 403 | POLICY_PATH_DENIED / POLICY_METHOD_DENIED | `{"error":"...","code":"..."}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: Server-mode downstream auth policy

  Scenario: Happy path — api_key write permitted only with opt-in in a signed manifest
    Given an admin-signed manifest with an api_key POST capability and allowWrite true
    When the daemon loads and the run calls it
    Then the call is made with the key and is audited

  Scenario: Edge case — none capability is allowlist-bound
    Given a none capability allowing GET on one host/path
    When the guest calls a different path on that host
    Then the broker denies it with POLICY_PATH_DENIED

  Scenario: Error path — write without opt-in is rejected at load
    Given a capability with a POST method and no allowWrite
    When the daemon loads the manifest
    Then load fails closed with CFG_INVALID
```

#### Performance, Security, Observability
- **Performance:** `api_key`/`none` avoid the OBO round-trip.
- **Security:** key custody equals `passthrough`'s; write gate is fail-closed and signature-bound; `none` carries no credential and is still allowlisted.
- **Observability:** every call audited by C11 (sizes + keyed-HMAC id; never the key).

#### Gaps
None.

---

### SPEC: Configuration
**File:** cross-cutting (realised in `config`, `policy`, daemon bootstrap) | **Phase:** 4 | **Dependencies:** Config (C1), PolicyEngine (C4), SecretResolver, ApiKeyStore

> **Mode:** greenfield
> **derivedFromHld:** 0.3.0

#### Purpose
Define how server-mode configuration loads: OIDC becomes conditional, and api_key keys are resolved once at startup into a frozen `ApiKeyStore`.

#### Approach
Keep the existing load order (env → resolver) and fail-closed posture. Add a bootstrap step that, after `PolicyEngine::load`, (a) calls `Config::require_oidc` only if `has_oidc_capability()`, and (b) resolves `api_key_secret_refs()` via the `SecretResolver` into the `ApiKeyStore`. Rejected: resolve keys lazily per call (contradicts AS-6).

#### Shared Context
- `Config::load`, `Config::require_oidc`, `oidc_issuer: Option<String>` — Phase 3 C1.
- `PolicyEngine::api_key_secret_refs()`, `has_oidc_capability()` — Phase 3 C4.
- `ApiKeyStore::lookup` — Phase 2C.
- ADR-016: real-credential mode requires `PYS_OTLP_ENDPOINT` — unchanged.

#### Public Interface
Bootstrap sequence (daemon `main`): `cfg = Config::load(env, &FileSecretResolver)` → `policy = PolicyEngine::load(...)` → if `policy.has_oidc_capability()` then `cfg.require_oidc()?` → `keys = resolve_api_keys(policy.api_key_secret_refs(), &FileSecretResolver)?` → `IdentityBroker::new(..., keys)`.

#### Internal Logic
1. Load `Config` (OIDC optional, C1).
2. Load the manifest (`PolicyEngine`, C4) — this also runs the write-gate/secret-field validation.
3. If `has_oidc_capability()`, enforce `require_oidc()`; else skip (ADR-038).
4. For each distinct `secret_ref` in `api_key_secret_refs()`: resolve via `SecretResolver` (file read); on failure return `CFG_SECRET_UNRESOLVED` and fail startup closed; trim a single trailing newline; insert into the frozen `ApiKeyStore`.
5. Construct `IdentityBroker` with the `ApiKeyStore`.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| OIDC capability present, OIDC config absent | n/a (startup) | CFG_MISSING | `CFG_MISSING: config PYS_OIDC_ISSUER` |
| `api_key` `secretRef` file unreadable | n/a (startup) | CFG_SECRET_UNRESOLVED | `CFG_SECRET_UNRESOLVED: config <ref>` |
| Real-credential mode without OTLP sink (unchanged) | n/a (startup) | (mock-only) | runs mock-only (ADR-016) |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: Server-mode configuration bootstrap

  Scenario: Happy path — keys resolved once at startup
    Given a manifest with two api_key capabilities pointing at two mounted key files
    When the daemon boots
    Then both keys are resolved from file and frozen into the ApiKeyStore before serving

  Scenario: Edge case — no OIDC capability skips OIDC requirement
    Given a manifest with only api_key and none capabilities and no OIDC env vars
    When the daemon boots
    Then require_oidc is not called and the daemon serves

  Scenario: Error path — unreadable key file fails startup
    Given an api_key capability whose secretRef points at a missing file
    When the daemon boots
    Then startup fails closed with CFG_SECRET_UNRESOLVED
```

#### Performance, Security, Observability
- **Performance:** one file read per distinct key at startup; none on the hot path.
- **Security:** keys never logged; the `secret_ref` is a path, not a key. Rotation requires restart (AS-6).
- **Observability:** startup failures logged at the existing startup-failure site.

#### Gaps
None.

---

### Error Handling — delta

One new code joins the existing XC2 registry: **`API_KEY_UNAVAILABLE`** (502) — an `api_key` capability whose key was not resolved at startup (C11). The envelope shape is the inherited single wire-error envelope `{"error":<msg>,"code":<CODE>}`. All other codes referenced by this set (`CFG_MISSING`, `CFG_INVALID`, `CFG_SECRET_UNRESOLVED`, `CAP_UNKNOWN`, `CAP_INVALID`, `POLICY_PATH_DENIED`, `POLICY_METHOD_DENIED`, `DOWNSTREAM_UNAVAILABLE`, `DOWNSTREAM_TIMEOUT`, `INTERACTION_UNAVAILABLE`) are inherited unchanged.

### Logging — delta

The redaction policy is inherited and **extended by guarantee, not by code change**: the static `api_key` value is never logged and never appears in an `AuditEntry` (which has no token field — `types.rs:171-186`). The `secret_ref` reference string (a file path) may appear in a startup error; it is not the key. Verbose body-logging remains off by default and refused under real-credential mode (ADR-016).

# Phase 3 — Detailed Component Specifications (`obo-broker`)

## Table of contents
- [SPEC: Config (C1)](#spec-config-c1)
- [SPEC: AuditLogger (C3)](#spec-auditlogger-c3)
- [SPEC: TokenCacheAdapter (C4)](#spec-tokencacheadapter-c4)
- [SPEC: PolicyEnforcer (C5)](#spec-policyenforcer-c5)
- [SPEC: RFC8693Provider (C6)](#spec-rfc8693provider-c6)
- [SPEC: ProviderRegistry (C7)](#spec-providerregistry-c7)
- [SPEC: DownstreamClient (C8)](#spec-downstreamclient-c8)
- [SPEC: ResponseSanitizer (C9)](#spec-responsesanitizer-c9)
- [SPEC: ExchangeHandler (C10)](#spec-exchangehandler-c10)
- [SPEC: AdminInvalidateHandler (C12)](#spec-admininvalidatehandler-c12)
- [SPEC: KeyManager (C13)](#spec-keymanager-c13)

---

### SPEC: Config (C1)
**File:** `internal/config/config.go` | **Package:** `config` | **Phase:** 3 | **Dependencies:** none

#### Purpose
Load, validate, and expose all runtime configuration from environment variables (Phase 2D) once at startup, failing closed if any required value is missing or malformed.

#### Approach
A single immutable `Config` struct populated by an env loader, validated before the server starts. Chosen over a config framework (Viper) to keep the dependency surface minimal (ADR-010). Secrets are loaded by *reference* (`*_REF`) resolved via the secret store, never read from plain env.

#### Shared Context
Reads every variable in Phase 2D. Produces a `*Config` consumed by all other components.

#### Public Interface
- `func Load(ctx context.Context, getenv func(string) string, resolver SecretResolver) (*Config, error)` — parses, resolves secret references, validates; returns a fully-populated `*Config` or an error naming the first invalid field.
- `type SecretResolver interface { Resolve(ctx context.Context, ref string) ([]byte, error) }`

##### Example
Input env: `OBO_IDP_ISSUER=https://idp.acme.example`, `OBO_IDP_AUDIENCE=api://obo-broker`, … → `&Config{IDPIssuer:"https://idp.acme.example", ...}`. Missing `OBO_IDP_ISSUER` → `error: required config OBO_IDP_ISSUER is not set`.

#### Internal Logic
1. Read every variable via `getenv`; apply defaults from Phase 2D where unset.
2. For each `*_REF` value, call `resolver.Resolve`; on error return `CFG_SECRET_UNRESOLVED`.
3. Parse typed fields (durations via `time.ParseDuration`, ints via `strconv`, bools); on parse failure return `CFG_INVALID` naming the field.
4. Validate: required fields non-empty; `OBO_IDP_ISSUER` is an `https` URL; `OBO_RESPONSE_MAX_BYTES` ≤ 1 MiB; `OBO_MAX_CALLS_PER_SESSION` ≥ 1. On failure return `CFG_INVALID`.
5. Return the immutable `*Config`. Log each non-secret field at `info`; never log secret values.

#### Data Model
N/A — no persistent storage; in-memory struct only.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Required variable unset | n/a (startup) | CFG_MISSING | log + non-zero exit |
| Value fails to parse / validate | n/a (startup) | CFG_INVALID | log + non-zero exit |
| Secret reference cannot be resolved | n/a (startup) | CFG_SECRET_UNRESOLVED | log + non-zero exit |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: Config
  Scenario: Happy path
    Given all required variables are set and well-formed
    When Load is called
    Then it returns a populated Config and no error

  Scenario: Edge case — optional unset uses default
    Given OBO_MAX_CALLS_PER_SESSION is unset
    When Load is called
    Then Config.MaxCallsPerSession equals 500

  Scenario: Error path — required missing
    Given OBO_IDP_AUDIENCE is unset
    When Load is called
    Then it returns an error naming OBO_IDP_AUDIENCE and the process exits non-zero
```

#### Performance, Security, Observability
- **Performance:** one-shot at startup; no budget.
- **Security:** secrets resolved by reference, never logged; fail-closed on any invalid field.
- **Observability:** logs the resolved non-secret config at `info`; metric `obo_config_load_errors_total`.

#### Gaps
None.

---

### SPEC: AuditLogger (C3)
**File:** `internal/audit/audit.go` | **Package:** `audit` | **Phase:** 3 | **Dependencies:** Config, OTel SDK

#### Purpose
Emit one append-only `AuditEntry` per exchange + downstream call — sizes and a hashed user identifier only, never tokens or bodies — and export it via OTLP to the SIEM.

#### Approach
A thin wrapper over the structured logger and the OTLP exporter. The user identifier is stored as an HMAC keyed by a per-install secret (not a bare hash, which is dictionary-reversible). Chosen over writing a local JSONL file as the system of record because the SIEM is the tamper-evident sink (HLD 06).

#### Shared Context
`AuditEntry` (Phase 2C). HMAC key from `OBO_CACHE_ENC_KEY_REF`-sibling audit key (see Config). `RunID` propagated from the request.

#### Public Interface
- `func (a *AuditLogger) Record(ctx context.Context, e AuditEntry)` — non-blocking; enqueues the entry for export. Never returns an error to the caller (audit failure must not fail the request, but increments a metric).

##### Example
`Record(ctx, AuditEntry{RunID:"r-1", UserHMAC:"9f…", Host:"tickets.contoso.com", Path:"/api/v2/tickets/42", Method:"GET", StatusCode:200, ResponseBytes:812, DurationMs:73, CacheHit:true})`.

#### Internal Logic
1. Compute `UserHMAC = HMAC-SHA256(auditKey, principal.Subject)` (caller passes Subject; never the raw token).
2. Build the structured record with all `AuditEntry` fields; **omit** any token, request body, response body, and `Authorization` header.
3. Emit as an OTLP log record with `runId` as the correlation attribute; mirror to stdout JSON at `info`.
4. On exporter failure: increment `obo_audit_export_failures_total`, log at `warn`, drop the record (never block the request).

#### Data Model
N/A — emits to OTLP/stdout; no owned storage.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| OTLP export fails | n/a | AUDIT_EXPORT_FAIL | none (metric + warn log; request unaffected) |
| HMAC key unavailable | n/a (startup) | AUDIT_KEY_MISSING | fail-closed at startup |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: AuditLogger
  Scenario: Happy path
    Given a completed exchange
    When Record is called
    Then an OTLP log record is emitted with runId and a UserHMAC, and no token or body field

  Scenario: Edge case — exporter down
    Given the OTLP collector is unreachable
    When Record is called
    Then the request is unaffected and obo_audit_export_failures_total increments

  Scenario: Error path — startup without audit key
    Given the audit HMAC key cannot be resolved
    When the service starts
    Then it exits non-zero with AUDIT_KEY_MISSING
```

#### Performance, Security, Observability
- **Performance:** non-blocking enqueue; < 1 ms on the request path.
- **Security:** never logs tokens, bodies, or raw user identifiers; HMAC keyed per install.
- **Observability:** metric `obo_audit_records_total`, `obo_audit_export_failures_total`; this component *is* the audit sink.

#### Gaps
None.

---

### SPEC: TokenCacheAdapter (C4)
**File:** `internal/cache/cache.go` | **Package:** `cache` | **Phase:** 3 | **Dependencies:** Config, Redis, KeyManager (C13)

#### Purpose
Store and retrieve downstream `Credential`s keyed by `(user, audience, scopes, providerId)`, encrypted at rest with AES-256-GCM, with a TTL that never outlives the credential **and never exceeds a hard ceiling** (ADR-016), and support immediate operator eviction of all of one user's entries.

#### Approach
A Redis-backed adapter (ADR-003). Values are sealed with AES-256-GCM under a **per-entry data key obtained from the KeyManager** (C13; envelope encryption, ADR-011/ADR-018) before `SETEX` and opened on `GET`; the plaintext credential and the unwrapped data key never reach Redis, and the adapter never talks to a concrete KMS — only to the `KeyManager` interface. A table-driven key builder produces a stable, collision-free key. The effective TTL is bounded by a **hard ceiling** `OBO_CACHE_MAX_TTL_SECONDS` so a long-lived downstream token cannot sit cached for its full natural life — this bounds revocation lag (ADR-016 / AS-8). A **per-user index set** records every live key for a user so `InvalidateUser` can evict all of them in one operation (the operator deprovisioning path, C12). Chosen over in-memory caching (loses tokens on restart; needs sticky routing — AS-13).

#### Shared Context
`Credential`, `CacheKey`, `Principal`, `AdminInvalidateRequest`, `KeyManager` (Phase 2C). `OBO_REFRESH_WINDOW`, `OBO_CACHE_MAX_TTL_SECONDS`, `OBO_REDIS_*` (Phase 2D). The envelope master-key config (`OBO_KMS_PROVIDER`, `OBO_CACHE_ENC_KEY_REF`) is owned by the KeyManager (C13), not read here.

#### Public Interface
- `func (c *Adapter) Get(ctx context.Context, k CacheKey) (Credential, bool, error)` — returns `(cred, true, nil)` on a live entry; `(_, false, nil)` on miss/expired-within-window; error only on Redis/decrypt failure.
- `func (c *Adapter) Put(ctx context.Context, k CacheKey, cred Credential) error` — encrypts and stores with `TTL = min(cred.ExpiresAt − now − refreshWindow, OBO_CACHE_MAX_TTL_SECONDS)`; a non-positive TTL means "do not cache". Also records the key in the user's index set.
- `func (c *Adapter) Invalidate(ctx context.Context, k CacheKey) error` — evicts a single entry and removes it from the user's index set.
- `func (c *Adapter) InvalidateUser(ctx context.Context, userSub, audience, providerID string) (evicted int, err error)` — evicts all of a user's cached entries (optionally filtered by `audience` and/or `providerID`); returns the count. Backs the operator deprovisioning endpoint (C12, ADR-016).

##### Example
`Get(ctx, CacheKey{UserSub:"00u1", Audience:"api://tickets", Scopes:"Tickets.ReadWrite", ProviderID:"rfc8693"})` → `(Credential{Kind:"bearer", Token:"<opaque>", ExpiresAt:…}, true, nil)`.

#### Internal Logic
1. `keyString(k)` = `"obo:" + providerId + ":" + sha256(userSub|audience|scopes)` — sorted, lower-cased scopes; hashing avoids leaking identifiers in Redis keys. `userIdx(userSub)` = `"obo:idx:" + sha256(userSub)` — the per-user index set; its members are `audience + "\x1f" + keyString` (providerId is recoverable from the `keyString` prefix), so `InvalidateUser` can apply the optional `audience`/`providerID` filters without decrypting any value.
2. **Get:** `GET keyString`; miss → `(_, false, nil)`. On hit: split off the stored `wrappedDataKey`, recover the plaintext data key via `keyManager.Unwrap` (C13), then AES-256-GCM open; on auth-tag failure return `CACHE_DECRYPT_FAIL`. If `cred.ExpiresAt − now ≤ refreshWindow` treat as miss `(_, false, nil)` (forces re-exchange).
3. **Put:** marshal `Credential` to JSON; obtain a per-entry data key via `keyManager.GenerateDataKey` (C13) — returns `(plaintext, wrapped)`; seal the JSON with AES-256-GCM under `plaintext` (96-bit random nonce); store `wrappedDataKey || nonce || ciphertext || tag`; compute `ttl = min(cred.ExpiresAt − now − refreshWindow, OBO_CACHE_MAX_TTL_SECONDS)` (the hard ceiling bounds revocation lag — ADR-016); if `ttl ≤ 0` return nil without storing; else `SETEX keyString ttl sealed` (envelope encryption, ADR-011), then `SADD userIdx member` and `EXPIRE userIdx` to the same `ttl` (refreshed on each Put; the index self-cleans).
4. **Invalidate:** `DEL keyString`; `SREM userIdx member`.
5. **InvalidateUser:** `SMEMBERS userIdx(userSub)`; for each member split into `(audience, keyString)` and derive `providerID` from the `keyString` prefix; skip members that fail the optional `audience`/`providerID` filters; `DEL` each matching `keyString` and `SREM` it from the index; if the index is now empty `DEL userIdx`; return the count evicted. This is the only path that removes a *live, non-expired* entry — the operator deprovisioning kill-switch (ADR-016 / SR-29).
6. All Redis calls bounded by `ctx` (request deadline); on timeout/connection error return `CACHE_UNAVAILABLE`.

#### Data Model
N/A — Redis key/value, not a relational schema. Entry keys: `obo:<providerId>:<sha256>`; values: `wrappedDataKey || nonce || ciphertext || tag`. Index keys: `obo:idx:<sha256(userSub)>` → SET of `audience\x1fkeyString` members, TTL-bounded to the longest live entry. No migrations (AS-14).

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Redis unreachable / timeout | 503 | CACHE_UNAVAILABLE | `{"error":"cache unavailable","code":"CACHE_UNAVAILABLE"}` |
| AES-GCM open fails (tamper/key change) | 500 | CACHE_DECRYPT_FAIL | `{"error":"internal error","code":"CACHE_DECRYPT_FAIL"}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: TokenCacheAdapter
  Scenario: Happy path — hit
    Given a sealed live credential exists for the key
    When Get is called
    Then it returns the decrypted credential and true

  Scenario: Edge case — within refresh window treated as miss
    Given a cached credential expiring in less than the refresh window
    When Get is called
    Then it returns false so the caller re-exchanges

  Scenario: Error path — Redis down
    Given Redis is unreachable
    When Get is called
    Then it returns CACHE_UNAVAILABLE

  Scenario: Operator eviction — invalidate all of a user's entries
    Given two cached credentials exist for user "00u1" across two audiences
    When InvalidateUser(ctx, "00u1", "", "") is called
    Then both entries are deleted, the index set is removed, and evicted equals 2

  Scenario: Operator eviction — filtered by audience
    Given cached credentials for user "00u1" on audiences A and B
    When InvalidateUser(ctx, "00u1", "A", "") is called
    Then only the audience-A entry is deleted and evicted equals 1
```

#### Performance, Security, Observability
- **Performance:** p95 Get/Put < 5 ms (in-cluster Redis). `InvalidateUser` is O(entries-per-user) — bounded by the per-user cap on distinct (audience, scopes) keys.
- **Security:** AES-256-GCM at rest; key by reference; identifiers hashed in keys (entry and index); values never logged. The hard TTL ceiling and `InvalidateUser` bound how long a deprovisioned user's cached access can persist (ADR-016).
- **Observability:** `obo_cache_hits_total`, `obo_cache_misses_total`, `obo_cache_errors_total{op}`, `obo_cache_user_evictions_total`; span `cache.get`/`cache.put`/`cache.invalidate_user`.

#### Gaps
None.

---

### SPEC: PolicyEnforcer (C5)
**File:** `internal/policy/policy.go` | **Package:** `policy` | **Phase:** 3 | **Dependencies:** Config

#### Purpose
Resolve a `capabilityId` to a `ResolvedCapability` from the derived manifest and authorise a request against it: canonical-path allowlist, method allowlist, and the per-`(user,agent)` rate budget.

#### Approach
A table-driven enforcer over a fail-closed-loaded manifest (AS-15). Path matching is performed on the **canonicalised** path (decode, resolve `.`/`..`, collapse `//`) to defeat traversal — this is the security crux (HLD ADR carried from the parent C2 finding). Rate counting delegates to the cache (Redis `INCR` with TTL). Chosen over per-request manifest parsing by loading once at startup.

#### Shared Context
`ResolvedCapability`, `Principal` (Phase 2C). Manifest from `OBO_POLICY_PATH`; `OBO_MAX_CALLS_PER_SESSION`, `OBO_STEP_UP_ACR_VALUES` → `Config.StepUpACRValues`, `OBO_STEP_UP_MAX_AGE_SECONDS` → `Config.StepUpMaxAge` (Phase 2D).

#### Public Interface
- `func (e *Enforcer) Resolve(capID string) (ResolvedCapability, bool)` — manifest lookup.
- `func (e *Enforcer) Authorise(ctx context.Context, p Principal, cap ResolvedCapability, verb, rawPath string) (canonPath string, err error)` — canonicalises `rawPath`, checks host/method/path, enforces the rate budget keyed on `p.Subject` + `p.AgentID` (both from the validated token); returns the canonical path to use downstream or a typed error.

##### Example
`Authorise(ctx, p, "agentX", capTickets, "GET", "/api/v2/tickets/../tickets/42")` → canonicalises to `/api/v2/tickets/42`; if `^/api/v2/tickets($|/.*)` matches and `GET` allowed and budget not exhausted → returns `"/api/v2/tickets/42", nil`.

#### Internal Logic
1. Canonicalise `rawPath`: percent-decode once, reject if it still contains `%`; split, resolve `.`/`..`, collapse repeated `/`; if any `..` remains after resolution return `POLICY_PATH_REJECTED`.
2. If `verb` ∉ `cap.Methods` → `POLICY_METHOD_DENIED`.
3. If no regex in `cap.PathAllow` fully matches the canonical path (anchored) → `POLICY_PATH_DENIED`.
4. Rate budget: `INCR rl:<p.Subject>:<p.AgentID>` in Redis with TTL = session window; if result > `MaxCallsPerSession` → `RATE_LIMITED`. `p.AgentID` is the token's `azp` claim (server-derived in `ValidateIdentity`), so a caller cannot rotate it to evade the budget.
5. If `cap.RequireStepUpAuth`, both must hold or it is `STEP_UP_REQUIRED` (AS-16/AS-17; ADR-014/ADR-015): (a) `p.ACR ∈ Config.StepUpACRValues` (loaded from `OBO_STEP_UP_ACR_VALUES`); **and** (b) `p.AuthTime` is non-zero and `now − p.AuthTime ≤ Config.StepUpMaxAge` (loaded from `OBO_STEP_UP_MAX_AGE_SECONDS`) — step-up means *recent* authentication, so a historical MFA whose `acr` lingers on a fresh `id_token` does **not** satisfy a sensitive write (ADR-015). `acr`/`auth_time` are server-derived from the validated `id_token` (C6), never caller-supplied. Config load already fails closed if any capability sets `requireStepUpAuth` while `StepUpACRValues` is empty or `StepUpMaxAge` is unset (Config C1 / AS-16/AS-17), so this check never silently passes. The ExchangeHandler (C10) renders the 401 with the RFC 9470 challenge naming the required `acr_values` and `max_age`.
6. Return the canonical path.

#### Data Model
N/A — manifest is read-only config; rate counters live in Redis (no relational schema).

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| capabilityId not in manifest | 403 | CAP_UNKNOWN | `{"error":"unknown capability","code":"CAP_UNKNOWN"}` |
| Path fails canonicalisation / has traversal | 400 | POLICY_PATH_REJECTED | `{"error":"invalid path","code":"POLICY_PATH_REJECTED"}` |
| Path not on allowlist | 403 | POLICY_PATH_DENIED | `{"error":"path not allowed","code":"POLICY_PATH_DENIED"}` |
| Method not allowed | 403 | POLICY_METHOD_DENIED | `{"error":"method not allowed","code":"POLICY_METHOD_DENIED"}` |
| Session budget exceeded | 429 | RATE_LIMITED | `{"error":"rate limit exceeded","code":"RATE_LIMITED"}` |
| Step-up required, `acr` not in `StepUpACRValues` **or** `auth_time` older than `StepUpMaxAge` (or absent) | 401 | STEP_UP_REQUIRED | `{"error":"step-up auth required","code":"STEP_UP_REQUIRED"}` + header `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="<required>", max_age="<seconds>"` (RFC 9470, set by C10) |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: PolicyEnforcer
  Scenario: Happy path
    Given capability internal.tickets allows GET on ^/api/v2/tickets($|/.*)
    When Authorise is called with GET /api/v2/tickets/42 under budget
    Then it returns the canonical path and no error

  Scenario: Edge case — traversal canonicalised then matched
    When Authorise is called with GET /api/v2/tickets/../tickets/42
    Then the path is canonicalised to /api/v2/tickets/42 and allowed

  Scenario: Error path — traversal escaping the allowlist
    When Authorise is called with GET /api/v2/tickets/../../admin
    Then it returns POLICY_PATH_DENIED (403)

  Scenario: Error path — budget exhausted
    Given the user/agent has reached MaxCallsPerSession
    When Authorise is called
    Then it returns RATE_LIMITED (429)

  Scenario: Error path — step-up required but acr insufficient
    Given capability internal.payments has RequireStepUpAuth=true
    And Config.StepUpACRValues contains "urn:acme:loa:mfa"
    And the principal's ACR is absent or not in that set
    When Authorise is called
    Then it returns STEP_UP_REQUIRED (401)
    And no downstream call is made

  Scenario: Error path — step-up acr present but stale
    Given capability internal.payments has RequireStepUpAuth=true
    And Config.StepUpMaxAge is 300 seconds
    And the principal's ACR is acceptable but auth_time is 20 minutes ago
    When Authorise is called
    Then it returns STEP_UP_REQUIRED (401)
    And no downstream call is made
```

#### Performance, Security, Observability
- **Performance:** p95 < 2 ms (in-memory match + one Redis INCR).
- **Security:** canonicalisation before match is the traversal defence; fail-closed manifest load; scopes are advisory — host/path/method are enforced.
- **Observability:** `obo_policy_denials_total{code}`, `obo_rate_limited_total`; span `policy.authorise`.

#### Gaps
None.

---

### SPEC: RFC8693Provider (C6)
**File:** `internal/provider/rfc8693/rfc8693.go` | **Package:** `rfc8693` | **Phase:** 3 | **Dependencies:** Config, TokenCacheAdapter, `coreos/go-oidc`, `x/oauth2`

#### Purpose
Implement the `ProviderPlugin` SPI for any standards-compliant RFC 8693 identity provider (the reference baseline — ADR-017; the concrete IdP is set by config, e.g. Okta, Keycloak, or Entra's standards endpoint): validate the inbound user `id_token`, perform RFC 8693 token exchange (confidential-client cert auth) to acquire a downstream credential, apply it as a Bearer, and refresh it silently.

#### Approach
Wraps `coreos/go-oidc` for JWKS-backed `id_token` verification and a token-exchange call against the configured IdP's `/token` endpoint (discovered via OIDC discovery from `OBO_IDP_ISSUER`) with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`. The confidential-client credential is a certificate (ADR-006). The cache is consulted in `AcquireDownstreamCredential`. Built on standard OIDC/OAuth2 libraries rather than any IdP-specific SDK (ADR-010), so a single implementation serves every standards-based provider (Okta, Keycloak, Entra) selected by configuration. Providers that deviate from the standard — a non-standard token-exchange dialect (Entra OBO) or header-injection fronting (an Okta Access Gateway, ADR-013) — are served by their own peer plugins registered under distinct provider ids (ADR-009/ADR-017), not by this one.

#### Shared Context
`Principal`, `Credential`, `ResolvedCapability`, `CacheKey` (Phase 2C). `OBO_IDP_ISSUER`, `OBO_IDP_AUDIENCE`, `OBO_IDP_CLIENT_ID`, `OBO_IDP_CLIENT_CERT_REF`, `OBO_JWKS_CACHE_TTL`, `OBO_CLOCK_SKEW` (Phase 2D).

#### Public Interface
Implements `ProviderPlugin`:
- `ID() string` → `"rfc8693"`.
- `ValidateIdentity(ctx, idToken) (Principal, error)`
- `AcquireDownstreamCredential(ctx, p, cap) (Credential, error)`
- `ApplyCredential(req, cred)` — sets `Authorization: Bearer <cred.Token>` for `Kind=="bearer"`.
- `Refresh(ctx, p, cap) (Credential, error)`

##### Example
`ValidateIdentity(ctx, "<jwt>")` → `Principal{Subject:"00u1", Issuer:"https://idp.acme.example"}`. `AcquireDownstreamCredential(ctx, p, capTickets)` → `Credential{Kind:"bearer", Token:"<idp-issued>", ExpiresAt:now+1h}`.

#### Internal Logic
1. **ValidateIdentity:** verify the JWT via the cached OIDC verifier — signature against JWKS (refetch on unknown `kid`), `iss == OBO_IDP_ISSUER`, `aud == OBO_IDP_AUDIENCE`, `exp`/`nbf` within `OBO_CLOCK_SKEW`. Reject any token whose header `alg` is not in the allowed asymmetric set (never `none`/HMAC) — `TOKEN_INVALID`. On any failure return `TOKEN_INVALID`. Extract `sub`, `azp` (→ `Principal.AgentID`), optional `email`, and the `acr` (→ `Principal.ACR`), `amr` (→ `Principal.AMR`), and `auth_time` (→ `Principal.AuthTime`, parsed as a Unix timestamp) claims into `Principal` — the step-up assurance and recency signal (AS-16/AS-17). The configured-value comparison and the freshness check are **not** done here; they are the provider-agnostic PolicyEnforcer's job (C5).
2. **AcquireDownstreamCredential:** build `CacheKey` from `(p.Subject, cap.Audience, sorted(cap.Scopes), "rfc8693")`; call `cache.Get`; on hit return it. On miss call `Refresh`.
3. **Refresh:** POST to the configured IdP's `/token` endpoint with `grant_type=token-exchange`, `subject_token=<user id_token>`, `subject_token_type=...:id_token`, `audience=cap.Audience`, `scope=join(cap.Scopes)`, authenticated with the client certificate; parse the returned access token + `expires_in` into a `Credential{Kind:"bearer"}`; `cache.Put`; return. On a non-2xx that indicates the grant is no longer valid (e.g. `invalid_grant` — a revoked grant or a disabled/deprovisioned user), **evict the existing cache entry** (`cache.Invalidate(key)`) and return `EXCHANGE_FAILED` — refresh **fails closed** and never extends a revoked user's access (ADR-016 / SR-29). On any other non-2xx or transport error return `EXCHANGE_FAILED` (transient) without eviction.
4. **ApplyCredential:** set `req.Header["Authorization"] = "Bearer " + cred.Token`.
5. Never log the user `id_token`, the downstream token, or the client certificate.

#### Data Model
N/A — delegates persistence to TokenCacheAdapter.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| id_token invalid (sig/iss/aud/exp) | 401 | TOKEN_INVALID | `{"error":"invalid token","code":"TOKEN_INVALID"}` |
| Token exchange rejected by the IdP | 502 | EXCHANGE_FAILED | `{"error":"token exchange failed","code":"EXCHANGE_FAILED"}` |
| IdP/JWKS endpoint unreachable | 503 | IDP_UNAVAILABLE | `{"error":"identity provider unavailable","code":"IDP_UNAVAILABLE"}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: RFC8693Provider
  Scenario: Happy path — exchange on cache miss
    Given a valid id_token and an empty cache
    When AcquireDownstreamCredential is called
    Then an RFC 8693 token exchange occurs and the credential is cached and returned

  Scenario: Edge case — cache hit skips IdP
    Given a live cached credential for the key
    When AcquireDownstreamCredential is called
    Then no IdP call is made and the cached credential is returned

  Scenario: Error path — wrong audience
    Given an id_token whose aud is not this service
    When ValidateIdentity is called
    Then it returns TOKEN_INVALID (401)

  Scenario: Error path — the IdP rejects exchange
    Given the IdP returns 400 invalid_grant
    When Refresh is called
    Then it returns EXCHANGE_FAILED (502) and no token is surfaced
```

#### Performance, Security, Observability
- **Performance:** validate p95 < 3 ms (cached JWKS); exchange p95 bounded by IdP latency, < 400 ms typical.
- **Security:** strict `aud`/`iss`/signature/exp validation (the inbound trust boundary, AS-5); client cert custody via workload identity; no token ever logged or returned.
- **Observability:** `obo_token_exchanges_total{result}`, `obo_token_validation_failures_total`; spans `idp.validate`, `idp.exchange`.

#### Gaps
None.

---

### SPEC: ProviderRegistry (C7)
**File:** `internal/provider/registry.go` | **Package:** `provider` | **Phase:** 3 | **Dependencies:** RFC8693Provider, Config

#### Purpose
Hold the set of compiled-in `ProviderPlugin`s and return the plugin for a capability's `provider` field.

#### Approach
A `map[string]ProviderPlugin` populated at startup from in-tree implementations only (ADR-009 — never dynamically loaded). Trivial by design; the value is the isolation boundary it enforces.

#### Shared Context
`ProviderPlugin` (Phase 2C). Plugin set known at compile time: `{"rfc8693": RFC8693Provider}`.

#### Public Interface
- `func New(plugins ...ProviderPlugin) *Registry` — indexes by `ID()`; panics at startup on duplicate IDs (bootstrap-only panic, rule C5).
- `func (r *Registry) Get(providerID string) (ProviderPlugin, bool)`

##### Example
`r.Get("rfc8693")` → `(rfc8693Provider, true)`; `r.Get("unconfigured")` → `(nil, false)`.

#### Internal Logic
1. `New` builds the map; duplicate `ID()` → panic (misconfiguration, fail at boot).
2. `Get` returns the plugin or `(nil, false)`.

#### Data Model
N/A — in-memory map.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Unknown provider id requested | 500 | PROVIDER_UNKNOWN | `{"error":"provider not configured","code":"PROVIDER_UNKNOWN"}` |
| Duplicate plugin id at startup | n/a (startup) | PROVIDER_DUP | panic + non-zero exit |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: ProviderRegistry
  Scenario: Happy path
    Given the rfc8693 plugin is registered
    When Get("rfc8693") is called
    Then it returns the rfc8693 plugin and true

  Scenario: Edge case — unknown provider
    When Get("unconfigured") is called
    Then it returns nil and false

  Scenario: Error path — duplicate registration
    Given two plugins both report ID "rfc8693"
    When New is called
    Then it panics at startup
```

#### Performance, Security, Observability
- **Performance:** O(1) map lookup.
- **Security:** plugin set fixed at compile time; no dynamic loading.
- **Observability:** `obo_provider_unknown_total`.

#### Gaps
None.

---

### SPEC: DownstreamClient (C8)
**File:** `internal/downstream/client.go` | **Package:** `downstream` | **Phase:** 3 | **Dependencies:** Config

#### Purpose
Issue the authenticated HTTPS request to the allowlisted downstream host with the credential the plugin applied, enforcing no-cross-origin-redirect and a strict timeout.

#### Approach
A configured `http.Client` with `CheckRedirect` returning `ErrUseLastResponse` (never auto-follow) and a per-call timeout. The credential is applied by the plugin's `ApplyCredential` before the call. Chosen to centralise the ADR-007 redirect rule in one auditable place.

#### Shared Context
`Credential`, `ResolvedCapability` (Phase 2C). `OBO_DOWNSTREAM_TIMEOUT` (Phase 2D).

#### Public Interface
- `func (c *Client) Do(ctx context.Context, cap ResolvedCapability, verb, canonPath string, params map[string]string, body []byte, apply func(*http.Request)) (status int, respBody []byte, header http.Header, err error)`

##### Example
`Do(ctx, capTickets, "GET", "/api/v2/tickets/42", nil, nil, applyBearer)` → `(200, <json>, header, nil)`.

#### Internal Logic
1. Build URL: `https://` + `cap.Host` + `canonPath` + encoded `params`. Host is taken from the capability, never from caller input.
2. Create the request with `ctx` carrying `OBO_DOWNSTREAM_TIMEOUT`; call `apply(req)` to attach the credential.
3. Execute with a client whose `CheckRedirect` returns `http.ErrUseLastResponse` — a 3xx is returned to the caller as-is; `Authorization` is never re-sent to another host (AS-12 / ADR-007).
4. Read the body up to `OBO_RESPONSE_MAX_BYTES`+1 (the extra byte detects oversize for the sanitiser's truncation flag).
5. On transport error/timeout return `DOWNSTREAM_UNAVAILABLE`.

#### Data Model
N/A.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Downstream timeout / connection error | 504 | DOWNSTREAM_TIMEOUT | `{"error":"downstream timeout","code":"DOWNSTREAM_TIMEOUT"}` |
| Downstream unreachable (DNS/TLS) | 502 | DOWNSTREAM_UNAVAILABLE | `{"error":"downstream unavailable","code":"DOWNSTREAM_UNAVAILABLE"}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: DownstreamClient
  Scenario: Happy path
    Given an allowlisted host and an applied bearer credential
    When Do is called
    Then it returns the downstream status and body

  Scenario: Edge case — 3xx not followed
    Given the downstream returns a 302 to another host
    When Do is called
    Then the 302 is returned as-is and Authorization is not re-sent

  Scenario: Error path — timeout
    Given the downstream does not respond within the timeout
    When Do is called
    Then it returns DOWNSTREAM_TIMEOUT (504)
```

#### Performance, Security, Observability
- **Performance:** bounded by `OBO_DOWNSTREAM_TIMEOUT` (10 s); typical p95 < downstream latency.
- **Security:** host pinned from policy; no cross-origin redirect; body size-capped; TLS 1.3.
- **Observability:** `obo_downstream_requests_total{host,status}`, `obo_downstream_latency_seconds`; span `downstream.do`.

#### Gaps
None.

---

### SPEC: ResponseSanitizer (C9)
**File:** `internal/sanitize/sanitize.go` | **Package:** `sanitize` | **Phase:** 3 | **Dependencies:** Config

#### Purpose
Reduce a raw downstream response to the safe `ExchangeResponse` shape: strip headers to a safe set, enforce the size cap with a truncation flag, and check content type.

#### Approach
A pure function over the raw response. Strips all headers except an allowlist; truncates at `OBO_RESPONSE_MAX_BYTES`. Note: this is transport hygiene, not prompt-injection defence — the parent daemon owns the untrusted-content stance (HLD lineage).

#### Shared Context
`ExchangeResponse` (Phase 2C). `OBO_RESPONSE_MAX_BYTES` (Phase 2D). Safe header allowlist: `Content-Type`, `ETag`, `Retry-After`.

#### Public Interface
- `func Sanitize(status int, raw []byte, header http.Header, host, path, method string, cacheHit bool) ExchangeResponse`

##### Example
`Sanitize(200, <1.5MiB json>, hdr, "tickets.contoso.com", "/api/v2/tickets/42", "GET", true)` → `ExchangeResponse{Status:200, Body:<1MiB>, Truncated:true, CacheHit:true, ...}`.

#### Internal Logic
1. Drop all response headers except the safe allowlist; never copy `Set-Cookie`, `Authorization`, `WWW-Authenticate`, or `Www-*` auth headers into the response.
2. If `len(raw) > OBO_RESPONSE_MAX_BYTES`: truncate to the cap, set `Truncated=true`.
3. If `Content-Type` is absent or not `application/json`/`text/*`, still return the (capped) bytes but record `obo_unexpected_content_type_total` (the broker does not transform the body).
4. Assemble and return `ExchangeResponse`.

#### Data Model
N/A.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Raw body exceeds cap | 200 (flagged) | — | body truncated, `truncated:true` in `ExchangeResponse` |
| Unexpected content type | 200 (metric only) | — | body returned as-is; metric incremented |

(Sanitiser does not itself originate HTTP errors; it shapes a response. Two non-error conditions documented per the ≥2-row rule.)

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: ResponseSanitizer
  Scenario: Happy path
    Given a 200 JSON response under the cap
    When Sanitize is called
    Then it returns the body with Truncated=false and only safe headers

  Scenario: Edge case — oversize body
    Given a response larger than OBO_RESPONSE_MAX_BYTES
    When Sanitize is called
    Then the body is truncated and Truncated=true

  Scenario: Error path — auth header present on response
    Given the downstream response includes a Set-Cookie header
    When Sanitize is called
    Then that header is not present in the ExchangeResponse
```

#### Performance, Security, Observability
- **Performance:** O(n) over the capped body; < 1 ms.
- **Security:** header allowlist prevents credential/cookie leakage back to the caller; size cap bounds memory.
- **Observability:** `obo_response_truncated_total`, `obo_unexpected_content_type_total`.

#### Gaps
None.

---

### SPEC: ExchangeHandler (C10)
**File:** `internal/handler/exchange.go` | **Package:** `handler` | **Phase:** 3 | **Dependencies:** ProviderRegistry, PolicyEnforcer, TokenCacheAdapter, DownstreamClient, ResponseSanitizer, AuditLogger

#### Purpose
Orchestrate one `POST /v1/exchange`: validate identity, authorise, acquire/refresh the downstream credential, proxy the call, sanitise, audit, and return — never returning the downstream credential.

#### Approach
A linear pipeline with fail-fast error mapping to the shared envelope. Chosen over middleware-chained auth because validation is provider-specific (lives in the plugin), not generic router middleware (HLD A-1 rationale). The handler holds no state.

#### Shared Context
`ExchangeRequest`, `ExchangeResponse`, `Principal`, `ResolvedCapability`, `Credential`, `AuditEntry`, `ErrorEnvelope` (Phase 2C). `OBO_REQUEST_MAX_BYTES` (Phase 2D).

#### Public Interface
- HTTP: `POST /v1/exchange`
  - Request: `ExchangeRequest` (JSON; body ≤ `OBO_REQUEST_MAX_BYTES`).
  - Response 200: `ExchangeResponse`.
  - Errors: the `ErrorEnvelope` shapes from every dependency's error table, mapped to status.
  - Auth: `userIdToken` in the body is the credential; no separate header.

##### Example
Request:
```json
{ "userIdToken":"<jwt>", "capabilityId":"internal.tickets", "verb":"GET", "path":"/api/v2/tickets/42", "runId":"r-1" }
```
Response 200:
```json
{ "status":200, "body":{"id":42,"state":"open"}, "host":"tickets.contoso.com", "path":"/api/v2/tickets/42", "method":"GET", "cacheHit":false }
```

#### Internal Logic
1. Read body with a `MaxBytesReader` of `OBO_REQUEST_MAX_BYTES`; decode `ExchangeRequest`; on failure → `VAL_ERR` (400).
2. `cap, ok := policy.Resolve(req.CapabilityId)`; `!ok` → `CAP_UNKNOWN` (403).
3. `plugin, ok := registry.Get(cap.Provider)`; `!ok` → `PROVIDER_UNKNOWN` (500).
4. `principal, err := plugin.ValidateIdentity(ctx, req.UserIDToken)`; err → `TOKEN_INVALID` (401). The core then **independently re-checks** `principal.Issuer == OBO_IDP_ISSUER` and the expected audience (ADR-012), failing `TOKEN_INVALID` on mismatch — the plugin's result is not solely trusted.
5. `canonPath, err := policy.Authorise(ctx, principal, cap, req.Verb, req.Path)`; err → mapped policy code (400/403/429/401). The rate-budget agent dimension is `principal.AgentID` (the token `azp`), not a caller-supplied value. On `STEP_UP_REQUIRED`, set `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="<space-join(Config.StepUpACRValues)>", max_age="<Config.StepUpMaxAge seconds>"` (RFC 9470) before writing the 401 envelope, so the daemon knows which `acr` to obtain **and that it must be recent** before it retries (ADR-014/ADR-015).
6. `cred, err := plugin.AcquireDownstreamCredential(ctx, principal, cap)`; err → `EXCHANGE_FAILED`/`IDP_UNAVAILABLE` (502/503).
7. `status, raw, hdr, err := downstream.Do(ctx, cap, req.Verb, canonPath, req.Params, req.Body, func(r){ plugin.ApplyCredential(r, cred) })`; err → `DOWNSTREAM_*` (502/504).
8. `resp := sanitize.Sanitize(status, raw, hdr, cap.Host, canonPath, req.Verb, cacheHit)`.
9. `audit.Record(ctx, AuditEntry{...})` (sizes, hashed user; never tokens/bodies).
10. Write 200 + `resp` JSON. The downstream `Credential` is never serialised into the response.

#### Data Model
N/A — stateless handler.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Body unparseable / oversize | 400 | VAL_ERR | `{"error":"invalid request","code":"VAL_ERR"}` |
| Unknown capability | 403 | CAP_UNKNOWN | `{"error":"unknown capability","code":"CAP_UNKNOWN"}` |
| id_token invalid | 401 | TOKEN_INVALID | `{"error":"invalid token","code":"TOKEN_INVALID"}` |
| Policy denial (path/method/rate/step-up) | 400/403/429/401 | POLICY_*/RATE_LIMITED/STEP_UP_REQUIRED | per PolicyEnforcer table; `STEP_UP_REQUIRED` additionally carries the RFC 9470 `WWW-Authenticate` challenge |
| Token exchange failed | 502 | EXCHANGE_FAILED | `{"error":"token exchange failed","code":"EXCHANGE_FAILED"}` |
| IdP/cache/downstream unavailable | 503/502/504 | IDP_UNAVAILABLE/CACHE_UNAVAILABLE/DOWNSTREAM_* | per dependency tables |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: ExchangeHandler
  Scenario: Happy path
    Given a valid id_token and an allowed capability
    When POST /v1/exchange is called
    Then it returns 200 with the sanitised downstream body and no token field

  Scenario: Edge case — cache hit path
    Given a live cached credential
    When POST /v1/exchange is called
    Then no IdP exchange occurs and cacheHit is true

  Scenario: Error path — invalid token
    Given an expired id_token
    When POST /v1/exchange is called
    Then it returns 401 with code TOKEN_INVALID and no downstream call is made

  Scenario: Error path — path traversal
    When POST /v1/exchange is called with path /api/v2/tickets/../../admin
    Then it returns 403 with code POLICY_PATH_DENIED
```

#### Performance, Security, Observability
- **Performance:** cache-hit p95 < downstream latency + 10 ms; cache-miss adds one IdP round-trip.
- **Security:** the credential never enters the response; body size-capped; every branch maps to the shared envelope with no internal-state leakage.
- **Observability:** `obo_exchange_requests_total{code}`, `obo_exchange_latency_seconds{cacheHit}`; root span `exchange.handle` with `runId`.

#### Gaps
None.

---

### SPEC: AdminInvalidateHandler (C12)
**File:** `internal/handler/admin.go` | **Package:** `handler` | **Phase:** 3 | **Dependencies:** TokenCacheAdapter, Config, AuditLogger

#### Purpose
Expose `POST /v1/admin/invalidate` so an operator can immediately evict a deprovisioned user's cached downstream credentials, bounding revocation lag (ADR-016 / SR-29). Off by default; operator-authenticated; never reachable by the daemon or the agent.

#### Approach
A thin handler that authenticates the caller as an **operator via mutual TLS** (a client certificate signed by `OBO_ADMIN_CLIENT_CA_REF` whose subject CN is in `OBO_ADMIN_ALLOWED_CNS`), validates the body, and calls `TokenCacheAdapter.InvalidateUser` (C4). It is mounted **only** when `OBO_ADMIN_ENABLED=true`; otherwise the route is absent and any request to it returns 404. Operator authentication is deliberately a different trust path from the user `id_token` (ADR-016) — the user token can never reach this endpoint. Chosen over an `id_token`-gated route because deprovisioning is an operator action, not a user action, and must work even when the target user has no valid token.

#### Shared Context
`AdminInvalidateRequest`, `AdminInvalidateResponse`, `ErrorEnvelope` (Phase 2C). `OBO_ADMIN_ENABLED`, `OBO_ADMIN_CLIENT_CA_REF`, `OBO_ADMIN_ALLOWED_CNS`, `OBO_REQUEST_MAX_BYTES` (Phase 2D). `TokenCacheAdapter.InvalidateUser` (C4).

#### Public Interface
- HTTP: `POST /v1/admin/invalidate` (mounted only when `OBO_ADMIN_ENABLED=true`)
  - Request: `AdminInvalidateRequest` (JSON; body ≤ `OBO_REQUEST_MAX_BYTES`; `userSub` required).
  - Response 200: `AdminInvalidateResponse` `{ "evicted": <int> }`.
  - Auth: mutual TLS; client cert signed by the configured CA with CN ∈ `OBO_ADMIN_ALLOWED_CNS`. No user `id_token`.

##### Example
Request: `{ "userSub":"00u1", "audience":"api://tickets" }` → Response 200: `{ "evicted": 1 }`.

#### Internal Logic
1. If `!Config.AdminEnabled` the route is not mounted; a request 404s (handled by the router).
2. Verify the TLS client certificate: chains to `OBO_ADMIN_CLIENT_CA_REF` and `cert.Subject.CN ∈ Config.AdminAllowedCNs`; otherwise `ADMIN_UNAUTHORIZED` (403). (TLS already rejects an absent/untrusted client cert at the transport layer; this is the in-handler CN allowlist check.)
3. Read body with `MaxBytesReader`; decode with `DisallowUnknownFields`; require non-empty `userSub`; on failure `VAL_ERR` (400).
4. `evicted, err := cache.InvalidateUser(ctx, req.UserSub, req.Audience, req.ProviderID)`; on Redis error `CACHE_UNAVAILABLE` (503).
5. `audit.Record` an admin-action entry (operator CN as the actor, `userSub` as a `UserHMAC`, count evicted; never tokens).
6. Write 200 `AdminInvalidateResponse`.

#### Data Model
N/A — stateless handler; delegates eviction to TokenCacheAdapter (C4).

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Admin endpoint disabled | 404 | (router) | not found (route not mounted) |
| Client cert missing/untrusted or CN not allowlisted | 403 | ADMIN_UNAUTHORIZED | `{"error":"operator not authorised","code":"ADMIN_UNAUTHORIZED"}` |
| Body unparseable / `userSub` empty | 400 | VAL_ERR | `{"error":"invalid request","code":"VAL_ERR"}` |
| Redis unavailable | 503 | CACHE_UNAVAILABLE | `{"error":"cache unavailable","code":"CACHE_UNAVAILABLE"}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: AdminInvalidateHandler
  Scenario: Happy path — operator evicts a user
    Given OBO_ADMIN_ENABLED is true and a valid operator client cert with an allowlisted CN
    And user "00u1" has two cached credentials
    When POST /v1/admin/invalidate {"userSub":"00u1"} is called
    Then it returns 200 with evicted=2 and the entries are gone

  Scenario: Edge case — endpoint disabled
    Given OBO_ADMIN_ENABLED is false
    When POST /v1/admin/invalidate is called
    Then it returns 404 and no eviction occurs

  Scenario: Error path — non-operator caller
    Given a client cert whose CN is not in OBO_ADMIN_ALLOWED_CNS
    When POST /v1/admin/invalidate is called
    Then it returns 403 ADMIN_UNAUTHORIZED and no eviction occurs
```

#### Performance, Security, Observability
- **Performance:** one cache index scan + N deletes; not on the hot path.
- **Security:** operator-only via mTLS + CN allowlist; disabled by default; never accepts the user `id_token`; every invocation audited with the operator identity.
- **Observability:** `obo_admin_invalidations_total{result}`; span `admin.invalidate`.

#### Gaps
None.

---

### SPEC: KeyManager (C13)
**File:** `internal/kms/kms.go` (SPI) + `internal/kms/<backend>/<backend>.go` | **Package:** `kms` | **Phase:** 3 | **Dependencies:** Config, the configured KMS SDK

#### Purpose
Implement the `KeyManager` SPI (ADR-018) for the configured key-management backend: mint per-entry data keys (`GenerateDataKey`) and recover them (`Unwrap`) for the TokenCacheAdapter's envelope encryption (ADR-011). The backend is selected at startup by `OBO_KMS_PROVIDER`; the rest of the service depends only on the interface.

#### Approach
A small interface with one compiled-in implementation per backend (`awskms`, `gcpkms`, `azurekv`, `vault-transit`). Each backend wraps its provider SDK / API: `GenerateDataKey` calls the backend's generate-data-key primitive (or generates a random 256-bit DEK locally and wraps it via the backend's encrypt) under the master key `OBO_CACHE_ENC_KEY_REF`; `Unwrap` calls the backend's decrypt. Backends are first-party, in-tree, and security-reviewed — **never dynamically loaded** (ADR-018, inheriting the ADR-009/ADR-012 stance). A startup factory resolves `OBO_KMS_PROVIDER` to exactly one backend and fails closed on an unset/unknown value. Chosen over the cache holding KMS logic directly (couples the cache to one platform) and over a single generic "KMS URL" (cannot cover per-backend auth/wrap/rotation).

#### Shared Context
`KeyManager` (Phase 2C). `OBO_KMS_PROVIDER`, `OBO_CACHE_ENC_KEY_REF` (Phase 2D). Master-key rotation is handled by the backend / KMS, not here (ADR-011). Used by TokenCacheAdapter (C4).

#### Public Interface
Implements `KeyManager`:
- `ID() string` → the backend id (e.g. `"vault-transit"`).
- `GenerateDataKey(ctx) (plaintext []byte, wrapped []byte, err error)`
- `Unwrap(ctx, wrapped []byte) (plaintext []byte, err error)`

Plus a startup factory: `func New(cfg *config.Config) (KeyManager, error)` — selects the backend by `cfg.KMSProvider`; returns `KMS_PROVIDER_UNKNOWN` for an unset/unknown value (config fails closed).

##### Example
`New(cfg)` with `OBO_KMS_PROVIDER=vault-transit` → a Vault-transit `KeyManager`. `GenerateDataKey(ctx)` → `(<32-byte DEK>, <wrapped-blob>, nil)`; `Unwrap(ctx, wrapped)` → `(<32-byte DEK>, nil)`.

#### Internal Logic
1. **New (factory):** switch on `cfg.KMSProvider`; construct the matching backend with `cfg.CacheEncKeyRef` (master key) and backend auth (workload identity for cloud KMS; a Vault token/role for transit); on unknown/empty → `KMS_PROVIDER_UNKNOWN` (fail closed at startup).
2. **GenerateDataKey:** obtain a 256-bit data key and its wrapped form under the master key (one round-trip to the KMS, or a local CSPRNG DEK + a wrap call, per backend); return `(plaintext, wrapped)`. Never log either value.
3. **Unwrap:** decrypt `wrapped` under the master key; return the plaintext DEK. Never log it.
4. All calls bounded by `ctx`; on transport/permission error return `KMS_UNAVAILABLE`.

#### Data Model
N/A — stateless; holds only backend config and an SDK client.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| `OBO_KMS_PROVIDER` unset/unknown | n/a (startup) | KMS_PROVIDER_UNKNOWN | log + non-zero exit |
| KMS unreachable / permission denied | 503 | KMS_UNAVAILABLE | surfaced to C4 as a wrap/unwrap failure (`CACHE_UNAVAILABLE` on the request path) |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: KeyManager
  Scenario: Happy path — generate then unwrap round-trips
    Given a configured backend
    When GenerateDataKey is called and the wrapped key is later passed to Unwrap
    Then Unwrap returns the same plaintext data key

  Scenario: Edge case — unknown provider fails closed
    Given OBO_KMS_PROVIDER is "nope"
    When New is called
    Then it returns KMS_PROVIDER_UNKNOWN and the process does not start

  Scenario: Error path — KMS unreachable
    Given the KMS endpoint is unreachable
    When GenerateDataKey is called
    Then it returns KMS_UNAVAILABLE and no data key is produced
```

#### Performance, Security, Observability
- **Performance:** one KMS round-trip per cache miss (`GenerateDataKey`) and per cold read (`Unwrap`); cache hits within a process may reuse nothing — the data key is per entry. p95 bounded by KMS latency.
- **Security:** plaintext data keys and wrapped blobs are never logged; the master key is referenced, never materialised in config; backends are compiled-in and security-reviewed, never dynamically loaded (ADR-018).
- **Observability:** `obo_kms_calls_total{op,result}`; spans `kms.generate_data_key`, `kms.unwrap`.

#### Gaps
None.

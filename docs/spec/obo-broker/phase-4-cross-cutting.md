# Phase 4 — Cross-Cutting Concern Specifications (`obo-broker`)

## Table of contents
- [Disposition summary](#disposition-summary)
- [XC1 — Authentication & Authorisation](#xc1--authentication--authorisation)
- [XC2 — Error Handling & Code Registry (ErrorEnvelope, C2)](#xc2--error-handling--code-registry-errorenvelope-c2)
- [XC3 — Logging](#xc3--logging)
- [XC4 — Metrics](#xc4--metrics)
- [XC5 — Tracing](#xc5--tracing)
- [XC6 — Configuration](#xc6--configuration)
- [XC7 — Health Checks (HealthHandler, C11)](#xc7--health-checks-healthhandler-c11)
- [XC8 — Rate Limiting](#xc8--rate-limiting)
- [XC9 — Input Validation](#xc9--input-validation)
- [XC10 — Graceful Shutdown](#xc10--graceful-shutdown)
- [XC11 — Out of scope](#xc11--out-of-scope)

## Disposition summary

| Concern | Disposition |
|---|---|
| Authentication & Authorisation | Applies — XC1 (delegates to RFC8693Provider C6 + PolicyEnforcer C5; step-up requires recent `auth_time` per ADR-015; operator admin endpoint via mTLS per ADR-016). |
| Error Handling | Applies — XC2 (new shared spec + code registry). |
| Logging | Applies — XC3. |
| Metrics | Applies — XC4. |
| Tracing | Applies — XC5. |
| Configuration | Applies — XC6 (delegates to Config C1). |
| Health Checks | Applies — XC7 (new component C11). |
| Rate Limiting | Applies — XC8 (delegates to PolicyEnforcer C5). |
| Input Validation | Applies — XC9. |
| Graceful Shutdown | Applies — XC10. |
| Pagination | **Out of scope** (AS-14) — single-call proxy; pagination is the caller's concern. |
| CORS | **Out of scope** (AS-14) — server-to-server API, no browser origin. |
| Database Migrations | **Out of scope** (AS-14) — no relational schema; cache is self-expiring. |

---

### XC1 — Authentication & Authorisation
**Policy spec.** Token format, validation flow, and authorisation model.

- **Inbound token:** IdP-issued OIDC `id_token` (JWT), `aud` = `OBO_IDP_AUDIENCE`. Validation is performed by the active Provider Plugin (`RFC8693Provider.ValidateIdentity`, C6): signature via cached JWKS, `iss`, `aud`, `exp`/`nbf` within `OBO_CLOCK_SKEW`.
- **Service→IdP:** confidential-client **certificate** (ADR-006), loaded via workload identity.
- **Authorisation model:** capability-based allowlist enforced by PolicyEnforcer (C5) — `host` + canonical `path` + `method`; `scopes` are advisory. Per-`(user, agent)` rate budget (`agent` = the token `azp` claim, server-derived). Optional per-capability step-up (`requireStepUpAuth`) — see *Step-up authentication* below.
- **Key rotation:** JWKS refreshed on unknown `kid` and every `OBO_JWKS_CACHE_TTL`; client certificate rotated via the secret store without redeploy.
- **Error mapping:** invalid token → 401 `TOKEN_INVALID`; authz denials → 401/403/429 per the PolicyEnforcer error table; step-up not satisfied → 401 `STEP_UP_REQUIRED` with an RFC 9470 `WWW-Authenticate` challenge.

#### Step-up authentication (resolves OQ-4 / parent sandbox OQ-1; ADR-014)

- **Signal — not caller-supplied.** Step-up assurance is conveyed solely by the validated `id_token`'s `acr` claim (with `amr` corroborating). `POST /v1/exchange` carries **no** step-up field; a body flag would be forgeable by the untrusted agent and is rejected by design (XC9, `DisallowUnknownFields`).
- **Configuration.** `OBO_STEP_UP_ACR_VALUES` (csv → `Config.StepUpACRValues`) lists the `acr` values that satisfy step-up; `OBO_STEP_UP_MAX_AGE_SECONDS` (→ `Config.StepUpMaxAge`) bounds how recent the step-up must be (ADR-015). If any capability sets `requireStepUpAuth: true` while either is unset, the manifest/config load **fails closed** (Config C1 / AS-16/AS-17). The acceptable `acr` value and the recency window are org-specific — verify per deployment (example only: `urn:acme:loa:mfa`, 300 s).
- **Enforcement.** For a `RequireStepUpAuth` capability, PolicyEnforcer (C5) requires both `Principal.ACR ∈ Config.StepUpACRValues` **and** `Principal.AuthTime` within `Config.StepUpMaxAge` of now (ADR-015 — step-up means *recent* step-up); otherwise `STEP_UP_REQUIRED`. The `acr`/`amr`/`auth_time` claims are extracted by the plugin (C6 `ValidateIdentity`) but trusted only after the core's independent `iss`/`aud` re-check (ADR-012); the comparison is performed by the provider-agnostic PolicyEnforcer, not the plugin.
- **Challenge & retry (RFC 9470).** The 401 response carries `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="<space-joined required values>", max_age="<StepUpMaxAge seconds>"` (set by ExchangeHandler C10). The daemon performs an IdP step-up, obtains a fresh `id_token` with the elevated `acr` and a recent `auth_time`, and re-issues the same request; the downstream call never executes until step-up is satisfied.
- **Parent dependency.** The daemon (sandbox OQ-1) drives the step-up on the challenge and retries; the backend is stateless about *how* step-up was achieved — it checks only the resulting `acr`.

```gherkin
Feature: Step-up authentication
  Scenario: Capability requires step-up but acr is insufficient
    Given capability internal.payments has requireStepUpAuth=true
    And OBO_STEP_UP_ACR_VALUES contains "urn:acme:loa:mfa"
    And a valid id_token whose acr is absent or not in that set
    When POST /v1/exchange targets internal.payments
    Then the response is 401 STEP_UP_REQUIRED
    And WWW-Authenticate names error="insufficient_user_authentication" with the required acr_values
    And no downstream call is made
```

#### Operator administration (admin endpoint; ADR-016)

- **Separate trust path.** `POST /v1/admin/invalidate` (AdminInvalidateHandler C12) is an **operator** action, authenticated by **mutual TLS** — a client certificate chaining to `OBO_ADMIN_CLIENT_CA_REF` whose subject CN is in `OBO_ADMIN_ALLOWED_CNS`. It **never** accepts the user `id_token`; the daemon and the agent cannot reach it.
- **Off by default.** Mounted only when `OBO_ADMIN_ENABLED=true`; otherwise the route is absent (404). When enabled, `OBO_ADMIN_CLIENT_CA_REF` and `OBO_ADMIN_ALLOWED_CNS` are required or config fails closed (AS-18).
- **Purpose.** Immediate eviction of a deprovisioned user's cached downstream credentials, bounding revocation lag together with the hard cache-TTL ceiling and refresh-fails-closed-on-revocation (ADR-016 / SR-29). Every invocation is audited with the operator CN as the actor.

**Errors:** see C5, C6, and C12 error tables (≥2 rows each). **Gaps:** None.

---

### XC2 — Error Handling & Code Registry (ErrorEnvelope, C2)
**File:** `internal/httperr/httperr.go` | **Package:** `httperr` | **Phase:** 4 | **Dependencies:** none

#### Purpose
Define the single error envelope and the canonical code→status registry, and provide panic recovery, so every component emits identical, leak-free error responses.

#### Approach
One `Write(w, status, code, msg)` helper plus a recovery middleware. A central registry maps codes to statuses so handlers reference a code, not a literal status. No internal state, stack traces, or upstream error strings are ever serialised.

#### Shared Context
`ErrorEnvelope` (Phase 2C): `{ "error": <human>, "code": <UPPER_SNAKE> }`.

#### Public Interface
- `func Write(w http.ResponseWriter, status int, code, msg string)` — writes the envelope JSON with the status.
- `func Recover(next http.Handler) http.Handler` — recovers panics → 500 `INTERNAL`; logs the panic server-side (never in the body).

##### Code registry
| Code | Status | Origin |
|---|---|---|
| VAL_ERR | 400 | ExchangeHandler |
| POLICY_PATH_REJECTED | 400 | PolicyEnforcer |
| TOKEN_INVALID | 401 | RFC8693Provider |
| STEP_UP_REQUIRED | 401 | PolicyEnforcer |
| CAP_UNKNOWN / POLICY_PATH_DENIED / POLICY_METHOD_DENIED / ADMIN_UNAUTHORIZED | 403 | Policy/Handler/AdminInvalidateHandler |
| RATE_LIMITED | 429 | PolicyEnforcer |
| INTERNAL / CACHE_DECRYPT_FAIL / PROVIDER_UNKNOWN / KMS_PROVIDER_UNKNOWN | 500 | various / KeyManager (`KMS_PROVIDER_UNKNOWN` is a startup fail-closed, not a response) |
| EXCHANGE_FAILED / DOWNSTREAM_UNAVAILABLE | 502 | RFC8693Provider / DownstreamClient |
| IDP_UNAVAILABLE / CACHE_UNAVAILABLE / KMS_UNAVAILABLE | 503 | RFC8693Provider / TokenCacheAdapter / KeyManager (a KMS failure surfaces on the request path as `CACHE_UNAVAILABLE`) |
| DOWNSTREAM_TIMEOUT | 504 | DownstreamClient |

#### Internal Logic
1. `Write` sets `Content-Type: application/json`, writes `{error,code}`; truncates `msg` to 200 chars; never includes upstream error text containing tokens.
2. `Recover` wraps the handler; on panic logs `error` with the run id and returns 500 `INTERNAL`.

#### Data Model
N/A.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Unrecovered panic | 500 | INTERNAL | `{"error":"internal error","code":"INTERNAL"}` |
| Unknown code passed to Write | 500 | INTERNAL | falls back to 500 INTERNAL (registry miss logged) |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: ErrorEnvelope
  Scenario: Happy path
    When Write(w, 403, "CAP_UNKNOWN", "unknown capability") is called
    Then the body is {"error":"unknown capability","code":"CAP_UNKNOWN"} with status 403

  Scenario: Edge case — long message truncated
    When Write is called with a 500-char message
    Then the emitted error string is truncated to 200 chars

  Scenario: Error path — panic recovered
    Given a handler panics
    When the request is served through Recover
    Then the client receives 500 INTERNAL and no stack trace
```

#### Performance, Security, Observability
- **Performance:** negligible.
- **Security:** no stack traces, upstream error strings, or tokens in any body.
- **Observability:** `obo_errors_total{code}`; panic logged at `error`.

#### Gaps
None.

---

### XC3 — Logging
**Policy spec.**
- **Format:** JSON to stdout; one object per line.
- **Required fields:** `ts`, `level`, `msg`, `runId`, `component`, `code` (on errors). **Never:** tokens, request/response bodies, `Authorization`, raw user identifiers (use `UserHMAC`).
- **Levels:** `OBO_LOG_LEVEL` (default `info`); `debug` must never be the default in production.
- **Correlation:** `runId` from the request propagated through context to every log line.
- **Redaction:** a logging wrapper drops any field named `token`, `authorization`, `id_token`, `secret`, `cert`. **Errors:** logging failures are best-effort (stdout); never fail the request. **Gaps:** None.

---

### XC4 — Metrics
**Policy spec.** Prometheus/OTel metrics, exposed via OTLP (`OBO_OTLP_ENDPOINT`).
- **Names (labels):** `obo_exchange_requests_total{code}`, `obo_exchange_latency_seconds{cacheHit}` (histogram, buckets `5,10,25,50,100,250,500,1000,2500 ms`), `obo_token_exchanges_total{result}`, `obo_cache_hits_total`/`obo_cache_misses_total`/`obo_cache_errors_total{op}`, `obo_policy_denials_total{code}`, `obo_rate_limited_total`, `obo_downstream_requests_total{host,status}`, `obo_audit_export_failures_total`.
- **Cardinality:** `host` label bounded by the policy allowlist; never label by `path`, `user`, or `runId`. **Errors:** exporter failure increments an internal counter; no request impact. **Gaps:** None.

---

### XC5 — Tracing
**Policy spec.** OpenTelemetry, OTLP exporter.
- **Span naming:** `exchange.handle` (root) → `policy.authorise`, `idp.validate`, `idp.exchange`, `cache.get`/`cache.put`, `downstream.do`.
- **Propagation:** the daemon's `runId` is set as a span attribute and the trace correlation id; W3C tracecontext accepted if present.
- **Sampling:** parent-based, ratio from config (default 0.1); errors always sampled. **Errors:** exporter failure is best-effort. **Gaps:** None.

---

### XC6 — Configuration
**Policy spec.** Delegates to Config (C1).
- **Loading order:** env var > built-in default; secrets by reference only.
- **Validation:** fail-closed at startup (C1 §Internal Logic step 4).
- **Secret handling:** `*_REF` resolved via the secret store / workload identity; never logged. **Errors:** see C1 error table. **Gaps:** None.

---

### XC7 — Health Checks (HealthHandler, C11)
**File:** `internal/handler/health.go` | **Package:** `handler` | **Phase:** 4 | **Dependencies:** ProviderRegistry, TokenCacheAdapter

#### Purpose
Expose Kubernetes liveness and readiness probes.

#### Approach
`/healthz` is a static liveness 200. `/readyz` checks the two hard dependencies (IdP JWKS reachable, Redis reachable) with short timeouts and returns 503 until both pass. Unauthenticated, but bound to the pod/cluster network only.

#### Shared Context
ProviderRegistry (C7), TokenCacheAdapter (C4).

#### Public Interface
- `GET /healthz` → 200 `{"status":"ok"}` always (process alive).
- `GET /readyz` → 200 `{"status":"ready"}` when JWKS + Redis reachable; else 503 `{"status":"not_ready","failed":["redis"]}`.

##### Example
`GET /readyz` with Redis down → `503 {"status":"not_ready","failed":["redis"]}`.

#### Internal Logic
1. `/healthz`: return 200 immediately.
2. `/readyz`: ping Redis (`PING`, 500 ms timeout) and the OIDC discovery/JWKS endpoint (cached, 500 ms); aggregate failures; 200 only if both pass, else 503 listing failed checks.

#### Data Model
N/A.

#### Error Table
| Condition | Status | Code | Response Body |
|---|---|---|---|
| Redis not reachable | 503 | — | `{"status":"not_ready","failed":["redis"]}` |
| JWKS/IdP not reachable | 503 | — | `{"status":"not_ready","failed":["idp"]}` |

#### Acceptance Criteria (Gherkin)
```gherkin
Feature: HealthHandler
  Scenario: Happy path — ready
    Given Redis and JWKS are reachable
    When GET /readyz is called
    Then it returns 200 status ready

  Scenario: Edge case — liveness independent of deps
    Given Redis is down
    When GET /healthz is called
    Then it returns 200 (process alive)

  Scenario: Error path — not ready
    Given Redis is down
    When GET /readyz is called
    Then it returns 503 listing redis as failed
```

#### Performance, Security, Observability
- **Performance:** probe checks bounded at 500 ms each.
- **Security:** unauthenticated but cluster-internal; exposes no secret or identity data.
- **Observability:** `obo_readyz_failures_total{check}`.

#### Gaps
None.

---

### XC8 — Rate Limiting
**Policy spec.** Delegates to PolicyEnforcer (C5).
- **Algorithm:** fixed-window counter in Redis (`INCR` + TTL) per `(userSub, azp)` — both from the validated token; window = session lifetime.
- **Limit:** `OBO_MAX_CALLS_PER_SESSION` (default 500); a global ceiling guards against many sessions.
- **Response:** 429 `RATE_LIMITED`; `Retry-After` header set to the window remainder. **Errors:** see C5 error table. **Gaps:** None.

---

### XC9 — Input Validation
**Policy spec.**
- **Library:** standard-library JSON decode with `DisallowUnknownFields`; `http.MaxBytesReader` at `OBO_REQUEST_MAX_BYTES`.
- **Rules:** `verb` ∈ {GET,POST,PATCH,PUT,DELETE}; `capabilityId` matches `^[a-z0-9]+(\.[a-z0-9]+)*$`; `path` must begin with `/`; path canonicalised and `..`-rejected by PolicyEnforcer (C5).
- **Error shape:** 400 `VAL_ERR` envelope. **Errors:** see C10 error table. **Gaps:** None.

---

### XC10 — Graceful Shutdown
**Policy spec.**
- **Signals:** `SIGTERM`/`SIGINT` trigger shutdown.
- **Drain:** `http.Server.Shutdown` with a 25 s deadline (under the k8s 30 s grace); readiness flips to 503 immediately (fail readiness first), in-flight requests complete.
- **Cleanup order:** stop accepting → drain HTTP → flush audit/OTLP exporter → close Redis client. **Errors:** if drain exceeds the deadline, force-close and log at `warn`. **Gaps:** None.

---

### XC11 — Out of scope
Pagination, CORS, and Database Migrations do not apply (AS-14). Recorded here so their absence is a decision, not an omission.

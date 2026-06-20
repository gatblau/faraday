# Phase 5 — Generation Playbook (`obo-broker`)

Ordered build checklist. Build in dependency order (Phase 2B DAG). Each component step consumes its Phase 3 / Phase 4 spec in isolation.

## Step 0 — Scaffolding
- [ ] Go module `github.com/acme/obo-broker`; layout `cmd/obo-broker/main.go`, `internal/...`.
- [ ] Toolchain: `go build`, `go test`, `go vet`, `golangci-lint` (ADR-010). CI runs all four; coverage gate ≥ 70%.
- [ ] Base dependencies: chi, `coreos/go-oidc`, `x/oauth2`, redis client, OTel SDK + OTLP exporter, and the KMS SDK(s) for the configured KeyManager backend(s) (cloud-KMS SDK and/or a Vault client — ADR-018).
- [ ] Dockerfile (distroless static base); image scan in CI.
- [ ] k8s manifests: Deployment (N replicas), Service, readiness/liveness probes, workload-identity binding for the client cert.

## Step 1 — Foundations (no deps)
- [ ] **C1 Config** — env load, secret-ref resolution, fail-closed validation. Unit tests per error-table row.
- [ ] **C2 ErrorEnvelope (XC2)** — `Write`, `Recover`, code registry. Table-driven tests over the registry.

## Step 2 — Leaf services (depend on Config + externals)
- [ ] **C3 AuditLogger** — HMAC user id, OTLP emit, never-log-secrets. Tests: redaction, exporter-down no-fail.
- [ ] **C13 KeyManager** — `KeyManager` SPI + a startup factory keyed on `OBO_KMS_PROVIDER` (fail-closed on unset/unknown); per-backend `GenerateDataKey`/`Unwrap` (cloud KMS via SDK, Vault transit via API), never-log-key-material. Tests: generate→unwrap round-trip per backend, unknown-provider→`KMS_PROVIDER_UNKNOWN` (no start), KMS-unreachable→`KMS_UNAVAILABLE`. Cloud backends tested against the provider emulator / a recorded contract; Vault transit against a dev container. Build before C4 (C4 depends on it).
- [ ] **C4 TokenCacheAdapter** — AES-256-GCM seal/open with a per-entry data key from the **KeyManager (C13)** (`GenerateDataKey` on put, `Unwrap` on get — ADR-018), `TTL = min(exp − refreshWindow, OBO_CACHE_MAX_TTL_SECONDS)` (hard ceiling, ADR-016), Redis get/put/invalidate, per-user index + `InvalidateUser`. Tests: hit, within-window-miss, decrypt-fail, Redis-down, TTL-capped-by-ceiling, invalidate-user (all + audience-filtered) — with a fake `KeyManager` for the seal/open path. Use a Redis test container.
- [ ] **C5 PolicyEnforcer** — manifest load, path canonicalisation (+ traversal rejection), method/host allowlist, rate budget. Table-driven tests incl. the traversal-escape case.
- [ ] **C8 DownstreamClient** — no-redirect client, timeout, size-capped read. Tests: happy, 3xx-not-followed, timeout. Use an httptest server.
- [ ] **C9 ResponseSanitizer** — header allowlist, truncation flag. Tests: under cap, oversize, auth-header-stripped.

## Step 3 — Provider + registry
- [ ] **C6 RFC8693Provider** — OIDC verify (aud/iss/exp/sig, alg allowlist, extract `acr`/`amr`/`auth_time`), RFC 8693 exchange (client cert), apply bearer, refresh (evict + fail-closed on `invalid_grant` — ADR-016), cache integration. Tests: validate happy/wrong-aud/expired/auth_time-extracted, exchange happy/cache-hit/idp-reject, refresh-revoked-evicts. Mock the IdP with an httptest OIDC + token endpoint.
- [ ] **C7 ProviderRegistry** — index by ID, duplicate-panic, unknown lookup. Tests: get/unknown/duplicate.

## Step 4 — Orchestration + entry points
- [ ] **C10 ExchangeHandler** — the `POST /v1/exchange` pipeline (steps 1–10), error mapping. Tests: one per Gherkin scenario (happy, cache-hit, invalid-token, traversal) + one per error-table row.
- [ ] **C11 HealthHandler (XC7)** — `/healthz`, `/readyz` with dep checks.
- [ ] **C12 AdminInvalidateHandler** — `POST /v1/admin/invalidate`; mTLS operator auth (CA + CN allowlist), body validation, `cache.InvalidateUser`, audit. Mounted only when `OBO_ADMIN_ENABLED=true`. Tests: happy evict, disabled→404, non-operator-CN→403. Use a test mTLS pair.
- [ ] Wire `main.go`: load Config → build Redis/cache, audit, policy, rfc8693 provider, registry, downstream, sanitiser → mount chi routes (`/v1/exchange`, `/healthz`, `/readyz`, and `/v1/admin/invalidate` **only when `OBO_ADMIN_ENABLED`**, behind an mTLS-requiring listener/middleware) with Recover + logging + tracing middleware → start server with graceful shutdown (XC10).

## Step 5 — Cross-cutting wiring
- [ ] **XC3 Logging** — JSON logger with redaction wrapper; `runId` in context.
- [ ] **XC4 Metrics / XC5 Tracing** — OTel meter + tracer providers; spans per the naming in XC5; OTLP export.
- [ ] **XC8 Rate Limiting** — verified via C5 tests.
- [ ] **XC9 Input Validation** — `MaxBytesReader`, `DisallowUnknownFields`, capability-id/verb/path checks.
- [ ] **XC10 Graceful Shutdown** — signal handler, readiness-first drain, exporter flush, Redis close.

## Step 6 — Integration & verification
- [ ] **Integration test:** end-to-end with a Redis test container + a mock IdP + mock downstream — happy path, cache-hit on second call, token-invalid, traversal-denied, downstream-timeout.
- [ ] **Security:** dependency scan; verify no token/body/credential appears in logs, traces, or the response (assert on captured output); confirm no cross-origin redirect is followed.
- [ ] **Observability:** assert the documented metrics and spans are emitted; assert audit records carry `UserHMAC` not raw subject.
- [ ] **Lint + coverage:** `golangci-lint` clean; coverage ≥ 70%.
- [ ] **Load smoke:** cache-hit p95 within budget; confirm graceful shutdown drains in-flight under SIGTERM.

## Notes
- This is a greenfield playbook — no remediation/continuity split (that is code-evidence mode only).
- The daemon↔service contract (`ExchangeRequest`/`ExchangeResponse`) must match `docs/design/sandbox-daemon/08-interfaces.md`; verify both sides when either is built.

# 07 — Cross-cutting Concerns & NFRs

## Cross-cutting Concerns

| Concern | Stance |
|---|---|
| Authentication | **Applies** — inbound: the active Provider Plugin validates the user's audience-restricted `id_token` (issuer, signature via cached JWKS, expiry, `audience` = this service), per the configured IdP (selected per deployment; no default — ADR-017). Outbound: the service authenticates to the IdP as a **confidential client** using a certificate. Provider-specific validation lives in the plugin (ADR-009). **Step-up:** for a `requireStepUpAuth` capability, the validated `id_token` `acr` claim must be in `OBO_STEP_UP_ACR_VALUES` **and** its `auth_time` must be within `OBO_STEP_UP_MAX_AGE_SECONDS` of the request (ADR-015 — step-up means *recent* step-up); otherwise a `401` with an RFC 9470 `WWW-Authenticate` challenge (carrying `acr_values` and `max_age`) is returned and the daemon steps up and retries — the signal is never caller-supplied (ADR-014). |
| Authorisation | **Applies** — Policy Enforcer resolves `capabilityId` against a derived copy of the daemon's manifest; host + canonical path + method allowlist; optional per-capability step-up requirement (parent OQ-1). |
| Logging | **Applies** — structured logs + append-only audit (sizes, keyed-HMAC user identifier, never tokens/bodies). |
| Metrics | **Applies** — OpenTelemetry metrics: exchange latency, cache-hit rate, downstream status codes, rate-limit rejections. |
| Tracing | **Applies** — OpenTelemetry traces; the daemon-supplied `runId` is propagated as the correlation id. |
| Rate limiting | **Applies** — per-user/per-agent budgets (mirroring the daemon's `maxCallsPerSession`) plus a global ceiling; over-budget returns `429`. |
| Pagination | **Does not apply** — the service proxies a single downstream call per request; pagination is the caller's concern against the upstream API. |
| Input validation | **Applies** — request-shape validation; `id_token` audience/issuer checks; path canonicalisation (reject `..`); method and host allowlist. |
| Error handling / envelope | **Applies** — typed errors (`401` auth, `403` policy, `429` rate, `502` exchange, `503` dependency, `504` downstream timeout) with no token or internal-state leakage. Wire-level codes/strings deferred to `/spec`. |
| Configuration | **Applies** — environment variables + secret store; the derived capability policy and allowlist are configuration, reloaded on change. |
| Health checks | **Applies** — Kubernetes liveness and readiness probes; readiness gates on IdP JWKS reachability and cache connectivity. |
| Migrations | **Does not apply** — no relational schema; the cache is ephemeral and self-expiring. |
| Graceful shutdown | **Applies** — drain in-flight requests, close cache/IdP connections, honour the Kubernetes `preStop` hook and termination grace period. |
| CORS | **Does not apply** — server-to-server API; no browser origin. The endpoint is not exposed for cross-origin browser calls. |
| Multi-tenancy | **Does not apply at runtime** — single-tenant per enterprise deployment (ADR-002); isolation is achieved by separate instances, not in-process tenant partitioning. |

## Non-functional Requirements

- **Performance targets:** cache-hit path adds only the downstream round-trip; cache-miss adds one IdP exchange round-trip. Target p95 service overhead (excluding downstream latency) on the order of tens of milliseconds on a hit; exact budgets set in `/spec`.
- **Scale:** stateless service, horizontally scalable behind a Kubernetes Deployment; shared state confined to the distributed cache; sized per enterprise user population.
- **Availability:** depends on the Identity Provider and the distributed cache; target an SLO with graceful `503` degradation when a dependency is unavailable; no single-instance state to lose.
- **Security posture:** confidential-client credential custody via workload identity; downstream tokens encrypted at rest and never returned; audience-restricted inbound auth; host/path/method allowlist as defense in depth; TLS 1.3 throughout; no cross-origin redirect following. This service is a high-value target (it holds many users' downstream access) and warrants its own threat model and pen test before production.

# 04 — Domain Model & Data Lifecycle

## Domain Model

- **Exchange Request** — one incoming call. Key attributes: validated user principal (from `id_token`), `capabilityId`, verb, path, params, body, correlation `runId`. Relationships: resolves to a Capability; produces an Audit entry. Lifecycle: created on receipt → validated → authorised → served → discarded (not stored).

- **Capability** — a derived copy of a daemon capability. Key attributes: `provider` (e.g. `rfc8693`, `okta`, `keycloak`), audience, scopes, host, path-allow patterns, methods, optional `requireStepUpAuth`. Relationships: referenced by an Exchange Request; its `provider` selects a Provider Plugin; sourced from the daemon's `pysandbox.policy.json`. Lifecycle: loaded from configuration; reloaded on config change.

- **Provider Plugin** — a first-party, in-tree unit encapsulating one IdP's identity validation and credential acquisition (ADR-009). Key attributes: `providerId`, supported audiences/scopes, credential type (Bearer / headers / mTLS / API key). Relationships: selected by the Provider Registry from a Capability's `provider`. Lifecycle: compiled in; instantiated at startup with provider configuration; security-reviewed as an isolated unit.

- **Token Cache Entry** — a cached downstream credential. Key attributes: key `(user, audience, scopes, providerId)`, encrypted credential value, `expiresAt`, refresh window. Relationships: produced by the active Provider Plugin (via the Token Cache Adapter); consumed by the Downstream HTTP Client. Lifecycle: created on exchange → encrypted-at-rest in the distributed cache → refreshed silently near expiry → evicted on expiry, refresh failure, or explicit invalidation.

- **Confidential-client Credential** — the service's identity to the IdP. Key attributes: certificate (preferred) or secret, rotation metadata. Relationships: used by the active Provider Plugin. Lifecycle: loaded via workload identity / secret store at startup → rotated without downtime → never logged, never returned, never written to the cache.

- **Audit Entry** — append-only record of one exchange + downstream call. Key attributes: timestamp, `runId`, keyed-HMAC user identifier, audience, host, path, method, statusCode, request/response sizes, durationMs, cache-hit flag. Relationships: one per served request. Lifecycle: written at call time → exported via OTLP → retained per policy.

## Data Lifecycle

- **User `id_token`** originates from the daemon, is validated on receipt, and is **not stored** — only the derived user principal is used (as a cache key component and a keyed-HMAC audit field).
- **Confidential-client credential** lives only in the secret store / workload identity and in process memory; never on disk in plaintext, never logged, never cached.
- **Downstream access tokens** are cached encrypted at rest (AES-256) in the distributed cache, keyed by `(user, audience, scopes, providerId)`, with TTL ≤ the token's own expiry; evicted on expiry/refresh-failure/invalidation; never returned to the caller.
- **Audit entries** record sizes and a **keyed-HMAC** user identifier (a keyed HMAC, not a bare hash — consistent with the parent `../sandbox-daemon/` audit, so the identifier resists offline rainbow-table reversal) — never tokens or bodies — and are exported to the SIEM; local retention follows the configured window (default aligned to the parent's 30 days).
- **Tenancy & residency:** single-tenant per enterprise deployment (ADR-002); all data (cache, credential, audit) is isolated within the enterprise's own instance. No cross-tenant sharing exists by construction.
- **Encryption in transit:** TLS 1.3 on every hop (daemon→service, service→IdP, service→cache, service→downstream).

# 08 — External Interfaces

Names and shapes only. Exact field types, error-code strings, status codes, JSON schemas, and retry counts are deferred to `/spec` (LLD).

## Exchange-and-call endpoint (new)

The single functional endpoint the daemon's Identity Broker calls.

- `POST /v1/exchange` — request shape `{ userIdToken, capabilityId, verb, path, params?, body?, runId? }`; response is the **sanitized downstream JSON** plus call metadata `{ host, path, method, status, cacheHit }`. The privileged downstream token is **never** included in the response. There is **no** step-up field in the request — step-up assurance rides in the `id_token` `acr` claim (ADR-014). For a `requireStepUpAuth` capability with insufficient `acr`, the response is `401` with a `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="<required>"` challenge (RFC 9470) and the daemon steps up and retries. This is the server counterpart of the daemon's "Backend OBO Broker service interface" in [`../sandbox-daemon/08-interfaces.md`](../sandbox-daemon/08-interfaces.md).

## Operational endpoints (new)

- `GET /healthz` — liveness.
- `GET /readyz` — readiness (gates on IdP JWKS reachability and cache connectivity).
- `GET /metrics` — OpenTelemetry metrics scrape (or OTLP push; mechanism set in `/spec`).

## Admin endpoint (new)

- `POST /v1/admin/invalidate` — request shape `{ user, audience?, providerId? }`; evicts matching cached downstream-token entries so an operator can cut a deprovisioned user's cached access immediately, without waiting for natural expiry (ADR-016). The caller is authenticated as an **operator** (cluster-internal; mTLS or a dedicated admin credential — **not** the user `id_token`), never reachable by the daemon or the agent. The call is audited like any other privileged action. Exact auth mechanism, response shape, and authorisation model are set in `/spec`.

## Outbound interfaces consumed (not exposed)

For completeness — these are dependencies the service calls, not interfaces it offers:

- Identity Provider token endpoint (provider-specific; e.g. RFC 8693 token exchange against the configured IdP — generic authorization server, Okta, Keycloak, or Entra — with confidential-client cert auth) — reached via the active Provider Plugin.
- Distributed cache protocol (assumption: Redis) over in-cluster TLS.
- Downstream corporate APIs (allowlisted hosts), HTTPS + OBO Bearer.

## Configuration interface (new)

- A derived **capability policy** (host/path/method allowlist + audiences/scopes + `provider` + optional `requireStepUpAuth`), sourced from the daemon's `pysandbox.policy.json` and supplied to the service as configuration. The authoritative JSON Schema for the manifest lives with the daemon design — [`../sandbox-daemon/schema/pysandbox.policy.schema.json`](../sandbox-daemon/schema/pysandbox.policy.schema.json), specified in `../sandbox-daemon/11-policy-schema.md`; the service validates its derived copy fail-closed at load.

## Provider Plugin SPI (internal extension point, new)

The in-tree contract every Provider Plugin implements (ADR-009). Names and shapes only; **not** a dynamically-loaded or third-party interface — plugins are compiled in and security-reviewed:

- `validateIdentity(inboundToken) → Principal` — provider-specific inbound user-token validation (issuer, JWKS, audience). The **core independently re-checks** the returned `Principal`'s `iss`/`aud` against the expected values (ADR-012) — the plugin's result is not solely trusted.
- `acquireDownstreamCredential(principal, capability) → Credential` — obtain the downstream credential (e.g. RFC 8693 token exchange), using the confidential-client credential and the token cache.
- `applyCredential(request, credential)` — attach the credential to the outbound request (Bearer, custom headers, mTLS, or API key).
- `refresh(credential) → Credential` — silent refresh near expiry.
- Plugin metadata: `providerId`, supported audiences/scopes, credential type.

Reference baseline: the generic RFC 8693 token-exchange plugin; Okta, Keycloak, and Entra are peer first-class plugins (ADR-017). The SPI is versioned; see [10 — Risks](./10-risks.md) (OQ-8).

## KeyManager SPI (internal extension point, new)

The in-tree contract every key-management backend implements (ADR-018). Names and shapes only; **not** a dynamically-loaded or third-party interface — backends are compiled in and security-reviewed (the no-dynamic-load rule is load-bearing: a KeyManager handles the cache's data-key material):

- `generateDataKey() → (plaintextDataKey, wrappedDataKey)` — mint a fresh per-entry data key under the configured master key (`OBO_CACHE_ENC_KEY_REF`); the cache seals the credential with `plaintextDataKey` and persists `wrappedDataKey` alongside the ciphertext. The plaintext data key is never written to the cache.
- `unwrap(wrappedDataKey) → plaintextDataKey` — recover the plaintext data key from its wrapped form (a KMS decrypt) on read.
- Backend metadata: `kmsProviderId`.

No default backend: the active one is selected at startup by `OBO_KMS_PROVIDER` (deployment-wide — one per single-tenant instance, ADR-002/ADR-018); an unset or unknown value fails closed. In-tree backends cover cloud KMS (AWS/GCP/Azure) and a Vault transit engine. Master-key rotation stays with the backend (ADR-011). The SPI is versioned alongside the Provider Plugin SPI (OQ-8).

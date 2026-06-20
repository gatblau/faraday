# Phase 1 — Analysis & Ambiguity Resolution (`obo-broker`)

## Table of contents
- [1A — Assumptions Register](#1a--assumptions-register)
- [1B — Open Questions](#1b--open-questions)
- [1C — Glossary](#1c--glossary)

## 1A — Assumptions Register

| ID | Area | Assumption | Rationale | Impact if wrong |
|---|---|---|---|---|
| AS-1 | Language/runtime | Service is Go, `net/http` + chi router. | HLD ADR-010 / A-1. | Re-scaffold; interfaces unaffected. |
| AS-2 | Cache | Redis with TLS in transit and AES-256-GCM value encryption at rest; key supplied by reference. | HLD ADR-003 / A-2. | Swap cache adapter; contract unaffected. |
| AS-3 | Credential custody | Confidential-client **certificate** loaded via Kubernetes workload identity; no static secret on disk. | HLD ADR-006 / A-3. | Fallback to mounted secret; reduced custody. |
| AS-4 | IdP | The launch provider plugin is the generic `rfc8693` reference plugin (OIDC + RFC 8693 token exchange — ADR-017); the concrete IdP (Okta, Keycloak, or Entra's standards endpoint) is set by `OBO_IDP_ISSUER`. There is no default IdP. | HLD ADR-009/ADR-017 / A-4. | Provider-specific plugins (non-standard dialects/fronting) added without core change. |
| AS-5 | Inbound auth | A request is trusted only after the active plugin validates the user `id_token` (issuer, signature via cached JWKS, `exp`, `aud` = `OBO_IDP_AUDIENCE`). No client secret from the daemon. | HLD ADR-004. | Forged requests admitted — security-critical; validated by tests. |
| AS-6 | Clock skew | Token `exp`/`nbf` validation allows ±60 s leeway. | Standard OIDC practice; absent from HLD. | Spurious 401s or briefly-valid expired tokens. |
| AS-7 | JWKS cache | The IdP's JWKS cached for `OBO_JWKS_CACHE_TTL` (default 5 min), refreshed on unknown `kid`. | Avoids per-request JWKS fetch; bounded staleness. | Higher IdP load or slow key-rotation pickup. |
| AS-8 | Cache TTL | A cache entry's TTL is `min(token exp − now − refresh_window, OBO_CACHE_MAX_TTL_SECONDS)`; `refresh_window` default 60 s, hard ceiling default 900 s (ADR-016). | Never serve an expired token; pre-emptive refresh; the hard ceiling bounds revocation lag. | Stale or prematurely-evicted tokens, or unbounded revocation lag if the ceiling is too high. |
| AS-9 | Request body cap | Inbound request body capped at 64 KiB; downstream response capped at `OBO_RESPONSE_MAX_BYTES` (1 MiB). | DoS/abuse bound; mirrors daemon cap. | Large legitimate bodies rejected. |
| AS-10 | Rate budget | Per-`(user, agent)` budget where `agent` is the validated `id_token` `azp` claim (server-derived, never caller-supplied); mirrors the daemon's `maxCallsPerSession` (default 500); plus a global ceiling. | HLD 07 NFR / M-3 lineage. | Abuse not bounded, or a caller forges `agent` to evade the budget. |
| AS-11 | Error envelope | All errors use one JSON envelope `{ "error": <human>, "code": <UPPER_SNAKE> }`; no token/internal-state leakage. | Cross-cutting consistency. | Clients must special-case each differing error shape. |
| AS-12 | Redirects | Downstream HTTP client does **not** follow cross-origin redirects and never re-sends `Authorization` across hosts. | HLD ADR-007. | Token-leak vector reopens — security-critical. |
| AS-13 | Concurrency | The service is stateless; all shared state is in Redis; safe to run N replicas behind a Service. | HLD ADR-003/005. | Token duplication or sticky-routing need. |
| AS-14 | Out-of-scope concerns | Pagination, CORS, and DB migrations do **not** apply (single-call proxy, server-to-server API, no relational schema). | HLD 07 cross-cutting stances. | Unneeded code if added. |
| AS-15 | Policy source | The service loads a **derived copy** of the daemon's capability manifest from `OBO_POLICY_PATH` and validates it fail-closed at startup. | HLD 08 / A-5. | Policy drift between daemon and service. |
| AS-16 | Step-up auth | Step-up for a `requireStepUpAuth` capability is asserted by the validated `id_token` `acr` claim (with `amr` corroborating), checked against `OBO_STEP_UP_ACR_VALUES`; never a caller-supplied field. If any capability requires step-up while that list is empty, config load fails closed. The `acr` value is org-specific — verify per deployment. | HLD ADR-014; resolves parent sandbox OQ-1 / obo OQ-4. | Sensitive write capabilities ungated end-to-end, or a forged step-up signal admitted — security-critical. |
| AS-17 | Step-up freshness | Step-up additionally requires the validated `id_token` `auth_time` to be within `OBO_STEP_UP_MAX_AGE_SECONDS` (default 300 s) of the request — recency, not just assurance level. Config fails closed if a capability requires step-up while the max-age is unset. | HLD ADR-015 / SR-26. | A single historical MFA satisfies sensitive writes indefinitely — security-relevant. |
| AS-18 | Token lifecycle & operator eviction | Cached downstream tokens carry a hard TTL ceiling (AS-8); silent refresh fails closed on IdP-side revocation (evict + 502); an operator-authenticated `POST /v1/admin/invalidate` (mTLS, CN allowlist, off by default) evicts a user's cached entries immediately on deprovisioning. | HLD ADR-016 / SR-29. | Deprovisioned users retain cached downstream access (revocation lag); no operator kill-switch. |

## 1B — Open Questions

Only decisions that **block** authoring are listed. **None block.** The HLD's non-blocking open questions (OQ-1…OQ-8) are carried as design-time choices and resolved by assumptions above or deferred to deployment:

| ID | Question | Options | Impact | Blocking? |
|---|---|---|---|---|
| OQ-A | Fronting flavour for the configured provider (token exchange vs access gateway) → which provider plugin. | `rfc8693` reference (token exchange) / a header-injection variant (e.g. `okta-access-gateway`) | **Resolved (ADR-013, generalised by ADR-017):** the generic `rfc8693` token-exchange plugin is the reference baseline; the fronting model is verified per deployment for whichever provider is selected, and a header-injection variant is built where the provider fronts apps that way. | No |
| OQ-B | Concrete encryption-key custody (KMS vs sealed secret) and rotation cadence. | KMS ref / sealed secret | **Resolved (ADR-011):** KMS envelope encryption, per-entry data keys, scheduled master rotation. | No |
| OQ-C | Enterprise compliance programme (if any). | named programme / none | May add audit-retention or residency constraints. | No |
| OQ-D | How does the parent's step-up auth (sandbox OQ-1) propagate to the backend? | id_token `acr` / caller flag / separate token | **Resolved (ADR-014 / AS-16):** via the validated `id_token` `acr` claim, server-enforced, RFC 9470 challenge on insufficiency; never caller-supplied. | No |

## 1C — Glossary

| Term | Definition | Example |
|---|---|---|
| OBO / token exchange | OAuth2 flow (RFC 8693) swapping a user token for a downstream credential carrying the user's identity. | RFC 8693 exchange for an internal `tickets` API token. |
| Confidential client | Server-side OAuth2 client authenticating to the IdP with a certificate. | This service's service app registered with the configured IdP. |
| `id_token` (audience-restricted) | The user's identity assertion with `aud` = this service. | `aud = api://obo-broker`. |
| Provider Plugin | First-party, compiled-in unit implementing `validateIdentity` / `acquireDownstreamCredential` / `applyCredential` / `refresh` for one IdP. | The generic `rfc8693` reference plugin. |
| Provider Registry | Component selecting the plugin for a capability by its `provider` field. | Routes `internal.tickets` → the configured provider plugin (e.g. `rfc8693`). |
| Capability | A policy entry (provider, audience, scopes, host, path-allow, methods). | `internal.tickets`. |
| Downstream credential | The privileged token/headers the plugin acquires; never returned to the caller. | IdP-issued Bearer for `tickets.contoso.com`. |
| Cache entry | Encrypted, TTL'd downstream credential keyed by `(user, audience, scopes, providerId)`. | Redis entry, AES-256-GCM. |
| Audit entry | Append-only record of one exchange + downstream call (sizes, hashed user; never tokens/bodies). | `{runId, user(hmac), host, path, status}`. |
| `acr` (auth context class) | OIDC claim naming the assurance level under which the `id_token` was issued; the basis for step-up. | `urn:acme:loa:mfa` (example — verify per deployment). |
| `amr` (auth methods) | OIDC claim listing the authentication methods used; corroborates `acr` for step-up. | `["mfa","otp"]`. |
| `auth_time` | OIDC claim giving the time of the user's last authentication; the basis for step-up *recency* (ADR-015). | `auth_time` within the last 300 s satisfies a fresh-MFA requirement. |
| Step-up authentication | Requiring a higher *and recent* assurance level (e.g. MFA) for a sensitive capability; asserted via `acr` + `auth_time`, challenged via RFC 9470. | `requireStepUpAuth` capability returns 401 until an elevated, recent `acr` is presented. |

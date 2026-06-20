# 10 — Assumptions, Open Questions, Risks, Alternatives, Dependencies, Rollout

## Assumptions

| ID | Area | Assumption | Rationale |
|---|---|---|---|
| A-1 | Framework | The HTTP layer uses Go's `net/http` with the **chi** router. | chi keeps the standard `net/http` handler model and a minimal, auditable dependency surface — preferred for a credential-handling service (consistent with ADR-008/ADR-010). Echo was considered but its `echo.Context` abstraction and batteries (e.g. built-in JWT middleware) add surface we would not use, since token validation is provider-plugin-specific, not router middleware. Non-architectural; confirmable in `/spec`. |
| A-2 | Cache product | The distributed cache is Redis with encryption at rest. | Common, supports TTL + encryption; the interview fixed "distributed + encrypted", not the product. |
| A-3 | Credential custody | The confidential-client credential is a certificate delivered via workload identity. | Strongest custody on Kubernetes (ADR-006). |
| A-4 | Provider config | The enterprise owns an identity provider (a generic RFC 8693 authorization server, Okta, Keycloak, or Entra — ADR-017) with a service app (confidential client) and the corporate services configured for token exchange. | Token exchange cannot function without the provider's app/scopes pre-configured; an operational prerequisite, for whichever provider the deployment selects. |
| A-5 | Policy source | The service enforces a copy of the daemon's capability policy as defense in depth. | Single source of truth is the daemon manifest; the service re-checks. |
| A-6 | Retention / locale | Audit retention defaults to 30 days; narrative output is en-GB. | Aligns with the parent HLD defaults. |

## Open Questions

No blocking open questions. All items below are non-blocking and may be resolved during `/spec` or by the HLD-impact-pass.

| ID | Question | Plain-English | Decision needed by | Blocking? |
|---|---|---|---|---|
| OQ-1 | Which specific distributed-cache product and encryption-key custody? | Exactly which caching product, and where its encryption key lives. | **Resolved:** Redis + **KMS envelope encryption** (ADR-011); the KMS **backend is pluggable** behind the KeyManager SPI and selected per deployment (cloud KMS / Vault transit), with no default — ADR-018. | No |
| OQ-2 | Certificate vs secret, and the rotation mechanism. | How the service's server credential is stored and rotated. | **Resolved:** certificate via workload identity, rotated without redeploy (ADR-006). | No |
| OQ-3 | Which enterprise compliance programme applies (if any)? | Whether a named standard (e.g. data-protection regime) governs this. | before production | No |
| OQ-4 | How does the parent's step-up auth (sandbox OQ-1) propagate to the backend? | When a sensitive action needs re-confirmation, how the server learns of it. | **Resolved (ADR-014):** via the validated `id_token` `acr` claim against `OBO_STEP_UP_ACR_VALUES`, server-enforced, RFC 9470 challenge on insufficiency; never caller-supplied. | No |
| OQ-5 | Multi-region / disaster-recovery posture for a single-tenant instance. | What happens if a region or the cache goes down. | `/spec` NFR / ops | No |
| OQ-6 | Is the capability policy pushed to the service, or pulled from a shared source? | How the allowlist reaches the server and stays in sync with the daemon. | `/spec` config phase | No |
| OQ-7 | Which fronting model for the configured provider — token exchange or access gateway (header injection)? | Whether the IdP hands out tokens for the services, or sits in front injecting headers. | **Resolved (ADR-013, generalised by ADR-017):** the generic RFC 8693 token-exchange flow is the reference baseline; the fronting model is verified per deployment for whichever provider is selected (Okta, Keycloak, Entra, …), and a header-injection plugin variant (e.g. `okta-access-gateway`) is built where the provider fronts apps that way. | No |
| OQ-8 | How is the Provider Plugin SPI versioned and compatibility-managed? | How we evolve the plugin contract without breaking existing providers. | `/spec` | No |

## Risks

- **High-value target.** The service holds many users' privileged downstream access. *Mitigation:* dedicated threat model + pen test before production; least-privilege scopes; strong credential custody (ADR-006); single-tenant isolation (ADR-002).
- **Token-cache compromise.** A breach of the cache could expose downstream tokens. *Mitigation:* encryption at rest, short TTLs, in-cluster TLS, network policy restricting cache access to the service.
- **`id_token` validation flaws.** Weak audience/issuer/signature checks would let forged requests through. *Mitigation:* strict validation against cached JWKS; reject on any mismatch; security review of the validator. The validator must pin an explicit algorithm allowlist (reject `alg=none` and HS/RS confusion) and a bounded JWKS cache with kid-miss refresh — confirmed in `/spec`.
- **Inbound `id_token` replay (bearer credential, no sender constraint by default).** The `id_token` is the sole authenticator (ADR-004); mTLS is optional and DPoP is not required. An actor who captures a live token — a TLS-intercepting corporate proxy (common in the target enterprises), a misconfigured logger, or off-host malware — can exercise the user's granted capabilities until it expires. There is no `jti` replay tracking and no stated maximum accepted token age. *Mitigation:* short token lifetimes, audience restriction, TLS 1.3 throughout; **decision deferred to `/spec`** — evaluate making DPoP or mTLS sender-constraint default-on rather than optional, optionally track `jti`, and set a maximum accepted token age. Tracked as SR-28 (Partial — open design decision) in `../threat-model.md`.
- **Downstream-token lifetime & revocation lag.** Cache TTL ≤ token expiry left the cached lifetime bounded only by a token the service does not control, and silent refresh could extend a deprovisioned user's access. *Mitigation (ADR-016):* a hard cache-TTL ceiling (smaller of ceiling and natural expiry wins); refresh fails closed on IdP-side revocation (evict + `502`), never outliving revocation; an operator-authenticated `POST /v1/admin/invalidate` cuts a user's cached access immediately on deprovisioning. Tracked as SR-29.
- **IdP / cache availability.** Both are hard dependencies. *Mitigation:* readiness gating, graceful `503`, bounded retries with backoff; cache hits reduce IdP coupling.
- **Confidential-credential leakage.** A leaked credential is catastrophic. *Mitigation:* certificate + workload identity (no static secret), rotation, never logged.
- **Provider Plugin SPI drift, or a buggy plugin.** A flawed plugin could mishandle validation or credential acquisition. *Mitigation:* plugins are in-tree and security-reviewed (never third-party-loadable, ADR-009); the SPI is versioned; each plugin is tested and pen-tested as an isolated unit.
- **KeyManager backend bug or misconfiguration.** A flawed KeyManager backend could wrap/unwrap data keys incorrectly (silent decrypt failures) or weaken the envelope guarantee. *Mitigation (ADR-018):* backends are in-tree, first-party, and security-reviewed — never dynamically loaded; the SPI is versioned alongside the Provider Plugin SPI; each backend is tested as an isolated unit (cloud backends against the provider emulator / a recorded contract, Vault transit against a dev container); an unset/unknown `OBO_KMS_PROVIDER` fails closed at startup; a KMS outage fails the affected request closed (`KMS_UNAVAILABLE`, surfaced on the request path as `CACHE_UNAVAILABLE`/503), so no cached credential is ever served without a valid data key.

## Alternatives considered

- **No backend (OBO in the daemon).** Rejected upstream (parent ADR-005) — a public client cannot hold a confidential credential.
- **Managed PaaS hosting.** Viable and lower-ops, but the interview selected self-managed Kubernetes (ADR-005).
- **Multi-tenant SaaS.** Rejected for the initial design (ADR-002) on cross-tenant isolation grounds.
- **Hand the daemon a scoped downstream token to call APIs itself.** Rejected — recreates the replay/exfiltration risk the architecture removes.
- **Adopt an off-the-shelf API gateway or IdP token-exchange product** (Azure API Management, Keycloak, Curity) *as the broker*. Weighed in ADR-008 and rejected as the *primary* mechanism for a self-managed-Kubernetes, single-tenant deployment with a specific never-return-token contract; the off-the-shelf *plumbing* (ingress/Envoy, workload identity, encrypted cache, OTel/SIEM) is adopted, the contract is built. Revisit triggers recorded in ADR-008. **Note (ADR-008 rev 0.8.0):** this rejects Keycloak/Curity *as the broker* — not Keycloak/Curity *as identity providers the broker exchanges against*, which are supported peer plugins (ADR-009/ADR-017).
- **Replace the broker with an Okta-portfolio product** (API Access Management, Cross-App Access, Auth0 Token Vault, Okta Access Gateway). Rejected (ADR-008 rev 0.8.0): each either returns a downstream token to the caller (Cross-App Access, Token Vault) or does not proxy-and-sanitize behind the capability allowlist (Access Gateway fronts browser-session SSO, not a headless agent flow), so none satisfies the never-return-token contract (ADR-007). Okta/Keycloak/Entra remain the *engine* the broker performs RFC 8693 token exchange against, consumed via a provider plugin. **Revisit trigger:** a deliberate decision to relax the never-return-token guarantee (e.g. accept a scoped on-workstation token via Token Vault) would amend ADR-001/ADR-007.
- **Hard-code a single identity provider** (Okta, or the original Microsoft). Rejected (ADR-009; reinforced by ADR-017) — repeats the coupling that forced this revision; a Provider Plugin boundary keeps the core IdP-agnostic, with no default provider and the generic RFC 8693 plugin as the reference baseline, and defers each provider's fronting-flavour choice to a plugin.

## Dependencies

- An identity provider (a generic RFC 8693 authorization server, Okta, Keycloak, or Entra) and a service app (confidential client) with the corporate services configured for token exchange, per the active provider plugin (A-4, ADR-017).
- A self-managed Kubernetes cluster with workload-identity federation.
- A distributed cache (assumption: Redis) with encryption at rest.
- A key-management service for envelope encryption — selected by `OBO_KMS_PROVIDER` (cloud KMS or an in-cluster Vault transit engine), reached via the active KeyManager backend (ADR-018).
- The daemon's capability policy as the authoritative allowlist source.
- The parent design ([`../sandbox-daemon/`](../sandbox-daemon/README.md)) — this service is its committed ADR-005 component.

## Rollout and Rollback

- **Rollout:** containerised Kubernetes Deployment; staged rollout (rolling update) behind readiness probes; integrate with the daemon's M5 milestone in the parent rollout. Initial deployment to a non-production tenant for the threat model and pen test before any production enterprise instance.
- **Configuration gating:** capabilities are enabled per the derived policy; a capability can be pre-denied centrally.
- **Rollback:** stateless service — roll back the Deployment image with no data migration; cache entries self-expire; revoking the confidential-client credential (or the app registration's permissions) disables all OBO immediately.

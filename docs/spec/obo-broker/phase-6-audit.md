# Phase 6 — Self-Audit (`obo-broker`)

## Checklist

```
[x] Every entity has a complete data model with types and constraints.
        — Phase 2C defines all shared types with Go types + JSON tags; storage-less components state "N/A — <reason>".
[x] Every action has defined inputs, outputs, numbered steps, and errors.
        — Each component carries Public Interface + numbered Internal Logic + Error Table.
[x] No banned phrases remain.
        — Scanned; remaining matches are the OS "process", the `exchange.handle` span identifier, and "secret handling" followed by concrete steps. AS-11 impact reworded.
[x] Every component has ≥3 Gherkin acceptance criteria (happy, edge, error).
        — C1,C3,C4,C5,C6,C7,C8,C9,C10,C13, XC2, XC7 each have 3–4 scenarios.
[x] Every component has an error table with ≥2 rows.
        — All present; ResponseSanitizer documents two non-error conditions explicitly per the rule.
[x] Every cross-component interaction is documented on BOTH sides.
        — Internal deps listed per component; the daemon↔service contract appears in both obo-broker/08 and docs/design/sandbox-daemon/08-interfaces.md.
[x] Build order (Phase 2B) is a valid DAG — no circular dependencies.
        — Verified: C1 → {C3,C5,C8,C9,C13}; C4 → {C1,C13}; C6 → C4; C7 → C6; C10 → C5/C7/C4/C8/C9/C3; C11 → C7/C4; C12 → {C4,C1,C3}. No cycles (C13 is a leaf; C4 depends on it).
[x] Every config value / env var listed with type, default, required flag, and owner.
        — Phase 2D, 24 variables (incl. OBO_STEP_UP_MAX_AGE_SECONDS, OBO_CACHE_MAX_TTL_SECONDS, OBO_ADMIN_*, OBO_KMS_PROVIDER).
[x] Every spec is self-contained — implementable from its section alone.
        — Each carries a Shared Context duplicating referenced types/config.
[x] Assumptions register complete; open questions are truly blocking only.
        — 18 assumptions (AS-1…AS-18); 1B lists 0 blocking (3 non-blocking carried from HLD).
[x] Example I/O provided for every component with non-trivial logic.
        — Each component has an Example block.
[x] Shared types defined once in Phase 2C, duplicated into Shared Context of consumers.
        — Yes.
[x] Security addressed for every entry point.
        — ExchangeHandler (POST /v1/exchange) and HealthHandler (/healthz,/readyz) each carry a Security note; XC1 covers the auth model.
[x] Performance targets stated for every latency-sensitive component.
        — C4,C5,C6,C8,C10 carry p95 budgets.
[x] All specifications use the active locale (en-GB).
        — sanitise/authorise/-ise spellings throughout.
[x] Destructive schema changes surface rollback considerations.
        — N/A — no relational schema (AS-14); cache is self-expiring.
[x] Every Component, Cross-cutting, and Preamble spec carries a `derivedFromHld:` field.
        — All at 0.4.1 (phase headers + component banners).
[x] No spec body contains an ADR-shaped paragraph.
        — "Approach" sections give component-level rationale (chosen direction + one-line rejected alt); no Decision/Context/Consequences/Alternatives blocks. System-level ADRs remain in HLD 09-decisions.
[x] Every glossary term used in any spec is present in the HLD glossary.
        — OBO/token exchange, confidential client, Provider Plugin, Provider Registry, capability, downstream credential, cache entry, audit entry all present in docs/design/obo-broker/00-overview.md.
[x] Every spec's `derivedFromHld:` matches the HLD's current `revision:` (0.9.1).
        — Match; re-derived against HLD 0.7.0 (ADR-015/016 folded in), then re-pinned to 0.7.1 for the `auth_time` glossary promotion (D-HLD-1, metadata only); no stale phases.
[x] In folder-form HLDs: every revision bump has a corresponding 99-changelog line.
        — docs/design/obo-broker/99-changelog.md covers 0.1.0 → 0.4.1.
```

## HLD-impact-pass result

Scanned every Phase 3 / Phase 4 draft for HLD-shaped findings (new component, ADR, glossary term, tech-stack member, cross-cutting policy, regulatory obligation, external actor, principal sequence).

**Re-audited after design review (HLD → 0.5.0).** A second pass recorded three new ADRs and threaded them into the spec: **ADR-011** KMS envelope cache encryption (phase-2D `OBO_CACHE_ENC_KEY_REF`, phase-3 C4), **ADR-012** provider-plugin guardrails (core re-validates `iss`/`aud` — phase-3 C6/C10; phase-2C SPI), and **ADR-013** Okta fronting default = token exchange, verify per deployment (phase-3 C6). OQ-A/OQ-B are resolved. Earlier: The post-review reconciliation bubbled four items to the HLD and resolved one spec gap: the cache key was standardised to the 4-tuple `(user, audience, scopes, providerId)` (HLD 00/02/04/09 + ADR-003); an **Agent (`azp`)** glossary term was added (HLD 00); the **504 downstream-timeout** status was added (HLD 03/07); and `jwx`/Entra/Envoy wording was cleaned. The **`agentID` provenance gap** is closed in-spec: `agentID` is the validated token's `azp` claim (server-derived, not caller-supplied) — see phase-2C `Principal.AgentID`, phase-3 C5/C6/C10, phase-1 AS-10. Beyond these, the component set maps onto the HLD's existing architecture components (ExchangeHandler ↔ HTTP ingress; ProviderRegistry/RFC8693Provider/PolicyEnforcer/TokenCacheAdapter/DownstreamClient/ResponseSanitizer/AuditLogger ↔ the HLD's named components; Config/ErrorEnvelope/HealthHandler are implementation-level, and the health endpoints already exist in HLD 08). No new ADRs (all rationale is component-level), no new glossary terms, no new tech-stack members (chi/go-oidc/x-oauth2/redis/OTel already in HLD 05), no new cross-cutting policy, no new regulatory obligation, no new actor; the cache-hit and silent-refresh sequences elaborate the HLD's existing token-exchange sequence rather than adding a new principal one. (That post-review reconciliation re-pinned `derivedFromHld` to **0.4.2** at the time.) The pin was **0.6.1**, re-synced on 2026-06-11 by `/sync-check` to track the HLD's review-fix revisions (0.6.0→0.6.1); that re-sync was a metadata refresh, not a re-derivation.

**Re-derived after the security-review follow-up (HLD → 0.7.0).** `/sync-check` flagged D-HLD-3 (stale pin) and INTENT-DRIFT against two new HLD ADRs; this phase re-runs against HLD 0.7.0 and folds them in: **ADR-015** (step-up requires recent `auth_time` within `OBO_STEP_UP_MAX_AGE_SECONDS` — phase-2C `Principal.AuthTime`, phase-2D the new env var, phase-3 C5 enforcement + C6 claim extraction + C10 `max_age` challenge, phase-4 XC1, phase-1 AS-17); and **ADR-016** (hard cache-TTL ceiling `OBO_CACHE_MAX_TTL_SECONDS`, refresh fails closed on IdP revocation, and a new operator-authenticated admin invalidation endpoint — phase-2B/2C/2D, phase-3 C4 `InvalidateUser` + new **C12 AdminInvalidateHandler**, phase-4 XC1 operator-admin + XC2 `ADMIN_UNAUTHORIZED`, phase-5 build steps, phase-1 AS-8/AS-18). **One new component (C12)** and a new glossary term (`auth_time`) trace to existing HLD ADRs in `docs/design/obo-broker/09-decisions.md` and the endpoint in `08-interfaces.md`, so no back-edge to the HLD was required (no D-HLD-1/2/4). The `derivedFromHld` pin advances to **0.7.0** across all phases.

**Re-pinned after the provider-neutral refactor (HLD → 0.8.0; ADR-017).** The HLD removed any default IdP and made the generic RFC 8693 plugin the reference baseline, with Okta/Keycloak/Entra as peer providers selected by config. This phase folds that in as a **rename + neutralisation**, not a behavioural re-derivation: component **C6 `OktaProvider` → `RFC8693Provider`** (`internal/provider/rfc8693/`, ID `"rfc8693"`); config env vars **`OBO_OKTA_*` → `OBO_IDP_*`** (`OBO_IDP_ISSUER`/`OBO_IDP_AUDIENCE`/`OBO_IDP_CLIENT_ID`/`OBO_IDP_CLIENT_CERT_REF`); `Config.OktaIssuer` → `Config.IDPIssuer`; trace spans `okta.validate`/`okta.exchange` → `idp.validate`/`idp.exchange`; the concrete IdP is now configuration (issuer/discovery), so a single standards-based plugin serves Okta, Keycloak, and Entra's standards endpoint, while non-standard dialects/fronting (Entra OBO, header-injection gateways) are peer plugins under distinct ids (phase-1 AS-4/OQ-A, phase-2 2A/2B/2C/2D, phase-3 C6/C7, phase-4 XC1/XC4/XC5/XC7, phase-5 steps 3–6). No new component, glossary term, ADR, tech-stack member, or cross-cutting policy; the error tables, status codes, contract shapes (`ExchangeRequest`/`ExchangeResponse`/SPI), and security behaviour are unchanged — only identifiers and prose were neutralised. The `derivedFromHld` pin advances to **0.8.0** across all phases. **Recommended:** run `/sync-check` to confirm no INTENT/CONTRACT drift before any `/sync-code` regeneration, since the env-var and component renames are a contract change for downstream code.

**Re-derived after the pluggable-KeyManager addition (HLD → 0.9.0; ADR-018).** The HLD abstracted the KMS dependency (ADR-011) behind a **`KeyManager` SPI** selected at startup by `OBO_KMS_PROVIDER`, with in-tree cloud-KMS + Vault-transit backends, no default, fail-closed — mirroring the Provider Plugin model (ADR-009/ADR-012). This is a genuine re-derivation (new component + type + env var + error codes), threaded down: **new component C13 KeyManager** (`phase-2B` inventory + DAG, `phase-3` spec, `phase-5` Step 2 build order before C4); **new type `KeyManager`** (`phase-2C`); **new env var `OBO_KMS_PROVIDER`** (`phase-2D`, total 24); **new error codes `KMS_PROVIDER_UNKNOWN`/`KMS_UNAVAILABLE`** (`phase-4` XC2 registry + C13 error table); and **`TokenCacheAdapter` (C4) now depends on the `KeyManager` interface** rather than calling KMS directly (`phase-2B` deps, `phase-3` C4 Approach/Shared-Context/Internal-Logic steps 2–3). **Bubble-up to HLD already done in the same pass** — ADR-018 in `09-decisions`, the KeyManager component + `kms` node in `02-architecture`, the KeyManager SPI in `08-interfaces`, OQ-1/dependency/risk in `10-risks`, the glossary term in `00-overview`, and the `05` crypto row — so no D-HLD-1/2/4 remains. Envelope encryption, per-entry data keys, rotation, the `ExchangeRequest`/`ExchangeResponse` contract, and security behaviour are unchanged; readiness still gates on IdP+cache (a KMS outage fails the request closed as `CACHE_UNAVAILABLE`). The `derivedFromHld` pin advances to **0.9.0** across all phases.

## Result

**PASSED.** All 21 checklist items pass; no unresolved Gaps in any component (every component's Gaps section reads `None.`); no blocking Open Questions. The spec set is promoted **Draft → Approved** and is ready for `/breakdown`.

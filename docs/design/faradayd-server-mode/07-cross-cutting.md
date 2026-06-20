# 07 — Cross-cutting Concerns & NFRs

> **Revision:** 0.3.0

## Cross-cutting Concerns

| Concern | Stance |
|---|---|
| Authentication (client → daemon) | **Applies — unchanged.** Same-UID peer check + `0600` socket + connection token (sandbox-daemon ADR-024). The agent and daemon share one container/UID, so the local controls hold without a network auth scheme (ADR-034). |
| Authentication (downstream) | **Applies — extended.** Adds `api_key` (per-capability static key, file-backed, applied per configured placement — ADR-036) and `none` (no credential — ADR-037), alongside the existing `exchange` / `passthrough`. |
| Authorisation | **Applies — extended.** The policy allowlist (host / path / method), path canonicalisation, and admin-signed override rule (sandbox-daemon ADR-021 / SR-2 / SR-25) apply to `api_key` and `none` capabilities identically; `none` is allowlist-bound, not "any call". **New:** capabilities are **read-only by default in every manifest** (all profiles — the gate is enforced in `PolicyEngine`, which makes no profile distinction) — a capability may declare an unsafe method (`POST`/`PUT`/`PATCH`/`DELETE`) only with an explicit per-capability write opt-in, honoured only in an admin-signed manifest (ADR-039). |
| Logging | **Applies — unchanged.** Structured, `run_id`-correlated, redacted logging (sandbox-daemon XC3 / ADR-027). The static key is never logged. |
| Metrics | **Project default — see sandbox-daemon ADR-027.** No metrics pipeline by default; OTel is an optional fleet add-on, unchanged. |
| Tracing | **Project default — see sandbox-daemon ADR-027.** `run_id` correlation locally; no distributed tracing by default. |
| Rate limiting | **Applies — unchanged.** Per-run / per-session call budgets (sandbox-daemon SR-8) bound `api_key` / `none` calls identically. |
| Pagination | **Does not apply** — the daemon exposes a single `run()` entry, not a paged collection API. |
| Input validation | **Applies — unchanged.** Strict `RunRequest` parsing, path/method validation at the shim and re-checked at the broker (sandbox-daemon SR-6 / SR-22); plus validation of the new policy fields (`secretRef`, key placement) at config load — exact rules in `/spec`. |
| Error handling / envelope | **Applies — unchanged.** Typed errors and the untrusted-content response envelope (sandbox-daemon ADR-017); resolution/placement failures fail closed (see [03 — Sequences](./03-sequences.md)). |
| Configuration | **Applies — extended.** The OIDC config group (issuer + client id) becomes optional when no OIDC-backed capability is present (ADR-038); per-capability key references resolve via `FileSecretResolver`. The ADR-016 OTLP-for-real-credentials rule is unchanged. |
| Health checks | **Project default — inherited.** Startup is fail-closed; readiness follows the base daemon. No new health surface introduced by this profile. |
| Migrations | **Does not apply** — no datastore; the policy-schema additions are additive (new enum values + optional fields), backward-compatible (see [10 — Risks](./10-risks.md) §Rollout). |
| Graceful shutdown | **Project default — inherited.** Unchanged from the base daemon. |
| CORS | **Does not apply** — no browser-facing HTTP surface in this profile (no loopback sign-in page is bound for `api_key`/`none`). |
| Multi-tenancy | **Does not apply — by design.** Single-tenant, one daemon per agent (ADR-034). A-1 ("one daemon per OS user") is reinterpreted as "one daemon per agent service"; no cross-tenant isolation requirement arises. |

## Non-functional Requirements

- **Performance targets:** unchanged from the base daemon. `api_key`/`none` add no token-exchange round-trip, so an `api_key` call is at most one HTTPS hop plus a one-time file read of the key — lower latency than the `exchange` path, which makes a server round-trip to `obo-broker`.
- **Scale:** one daemon serves one agent (single-tenant). Horizontal scale is "more agent+daemon containers", not "more tenants per daemon". Per-run/session budgets bound a single agent's load.
- **Availability:** the daemon is a single point of failure for its one agent; the agent fails closed (never to ambient execution) if the daemon is unavailable, unchanged from the base posture.
- **Security posture:** the credential is a **static, long-lived key** held in the broker process and a mounted file — a different posture from the short-lived OIDC tokens of the desktop profile. Blast radius if the container is compromised is **bounded** to the configured keys and their allowlisted host/path/method scope and call budgets; OBO's "privileged token never on the host" property does not apply because there is no untrusted host and no human user to defend against (ADR-002 scope, ADR-035). Rotation is the deployment's responsibility (mounted-secret rotation). Headless **write** capabilities are permitted only by an explicit per-capability opt-in in an admin-signed manifest, read-only by default — the signed policy is the pre-grant that stands in for the human-present renderer of sandbox-daemon ADR-025 (resolved by ADR-039).

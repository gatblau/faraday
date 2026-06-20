# Phase 1 — Analysis & Ambiguity Resolution (`faradayd-server-mode`)

> **Status:** Draft
> **derivedFromHld:** 0.3.0 (`docs/design/faradayd-server-mode/`)
> **Branch:** A — new spec set (greenfield), authored as a **delta** onto the approved `sandbox-daemon` spec set (`docs/spec/sandbox-daemon/`).

This spec set specifies the **server-mode profile** only — the changes to existing components C1 (Config), C4 (PolicyEngine), C10 (DownstreamClient), C11 (IdentityBroker), C13 (SandboxController) and the policy-manifest schema needed for the two non-OIDC auth modes and the container deployment. Baseline behaviour of every component is **inherited unchanged** from `docs/spec/sandbox-daemon/`; this set states only the deltas. Identifiers are verified against `sandbox-daemon/src/{types,policy,broker,config}.rs` and `docs/design/sandbox-daemon/schema/pysandbox.policy.schema.json`.

## Contents
- [1A Assumptions Register](#1a-assumptions-register)
- [1B Open Questions](#1b-open-questions)
- [1C Glossary](#1c-glossary)

## 1A Assumptions Register

| ID | Area | Assumption | Rationale | Impact if wrong |
|---|---|---|---|---|
| AS-1 | Scope | This set is a **delta** onto `docs/spec/sandbox-daemon/`; only C1, C4, C10, C11, C13 and the policy schema change. Baseline contracts are inherited verbatim. | HLD scopes server-mode as a profile, not a new system (`00-overview.md` Non-goals). | Re-scope to a full spec set; component contracts unaffected. |
| AS-2 | Wire token — `AuthMode` | Extend the `AuthMode` enum (`types.rs:24-35`) with two variants: `ApiKey` carrying `#[serde(rename = "api_key")]` and `Unauthenticated` carrying `#[serde(rename = "none")]`. | The container has `#[serde(rename_all = "lowercase")]`, which would serialise `ApiKey`→`apikey`; an explicit per-variant rename produces the HLD-fixed token `api_key`. `Unauthenticated` is named to avoid shadowing `Option::None` while the wire value stays `none`. | Wire value mismatch between manifest and parser; manifests fail to load. |
| AS-3 | Key source | An `api_key` capability's key is resolved through the existing `SecretResolver` (`FileSecretResolver`, `config.rs:15-24`). The manifest `secretRef` value **is** the resolver reference — under `FileSecretResolver` a file path. No new environment variable per key. | User decision #1 (file, not env); matches the existing `*_REF` → file model (`PYS_AUDIT_HMAC_KEY_REF`, `PYS_ADMIN_SIGNING_KEY_REF`). | Keys would need an env-var indirection layer; secret-handling surface widens. |
| AS-4 | Key placement (resolves HLD OQ-SM-2) | A per-capability `keyPlacement` is a tagged union: `{ "header": { "name": <string>, "scheme": <string?> } }` or `{ "query": { "param": <string> } }`. Header placement is applied in C11 by building a `Credential::Headers` (`types.rs:100-103`) and passing it through `DownstreamClient.do_call`'s existing `apply` closure; query placement appends `(param, key)` to the outbound `Params`, which `do_call` already serialises into the query string (`downstream.rs:124-127`). **C10 needs no change.** | Both placements use seams `do_call` already exposes (`apply` closure; `Params`→query). Covers `Authorization: Token <key>`, `X-API-Key: <key>`, and `?api_key=<key>`. | C11 application path and schema shape change; C10 contract unaffected. |
| AS-5 | Write gate (ADR-039) | A per-capability boolean `allowWrite` (default `false`). At manifest load (C4 PolicyEngine), a capability whose `methods` include any of `POST`/`PUT`/`PATCH`/`DELETE` while `allowWrite` is `false` fails closed with `CFG_INVALID`. The flag is honoured only via the existing admin-signed load path (`policy.rs:46-54`); an unsigned override falls back to the shipped default, so it cannot enable writes. | ADR-039: per-capability opt-in, default read-only, signed-policy pre-grant. Enforcing at load keeps the runtime method allowlist (`policy.rs:100-102`) unchanged. | Writes either silently permitted or universally blocked. |
| AS-6 | Key reload (resolves HLD OQ-SM-3) | `api_key` keys are resolved **once at startup** (config/manifest load), like every other `*_REF` secret; rotation of a mounted key requires a daemon restart. | Matches the existing one-shot resolution of `audit_hmac_key`/`admin_signing_key` at `Config::load`; no file-watch machinery exists today. | A hot-reload requirement would add a watcher to C1/C4. |
| AS-7 | OIDC optional (ADR-038) | `PYS_OIDC_ISSUER` and `PYS_OIDC_CLIENT_ID` (today both `required`, `config.rs:98,108`) become **conditionally required**: required only when the loaded manifest contains at least one capability with `authMode` `exchange` or `passthrough`. `Config::load` is given the parsed manifest's auth modes to decide. | ADR-038; a pure `api_key`/`none` deployment has no sign-in surface. | A key-only deployment cannot start, or OIDC validation is wrongly skipped for a mixed manifest. |
| AS-8 | Step-up not applicable | At manifest load, `requireStepUpAuth: true` on an `api_key` or `none` capability fails closed with `CFG_INVALID`. | ADR-039: step-up needs a human and an `id_token`; neither exists for these modes. | A meaningless step-up requirement is accepted and never satisfiable. |
| AS-9 | Audit unchanged (ADR-016) | A real `api_key` deployment still sets `CredentialMode::Real` and therefore still requires `PYS_OTLP_ENDPOINT` (`config.rs:153,158-162`); `none`-only deployments may run mock-only. The `AuditEntry` shape (`types.rs:171-186`) is unchanged; the key is never recorded (no token field exists). | ADR-016 carried forward; user decision #6. | Loss of the authoritative audit trail for credentialled calls. |
| AS-10 | Schema must add `authMode` | The policy schema (`pysandbox.policy.schema.json`) `$defs/capability` has `additionalProperties: false` and does **not** currently list `authMode` — yet `RawCapability` (`policy.rs:27`) reads it. The server-mode schema edit adds `authMode` (enum `exchange`/`passthrough`/`api_key`/`none`), `secretRef`, `keyPlacement`, and `allowWrite`, and relaxes `required` so `provider`/`audience`/`scopes` are not required for `none`/`api_key`. | The schema predates the `authMode` code; extending it here closes that omission for the new values. | A conformant `authMode` manifest fails schema validation. |
| AS-11 | `none` applies no credential | The C11 broker arm for `Unauthenticated` calls `DownstreamClient.do_call` with a no-op closure (no `Authorization`, no injected header, no appended param). | HLD ADR-037. | A credential leaks onto a public call, or the call is wrongly rejected. |
| AS-12 | Deployment substrate | The daemon and agent share one OCI container under one UID; the existing local client-auth (ADR-024) is inherited unchanged. Container packaging is build work, not a runtime contract, and is out of this spec set's component scope (tracked in HLD `10-risks.md`). | HLD ADR-034; user decision #5. | A network client-auth boundary would be needed (out of scope here). |

## 1B Open Questions

**No blocking open questions.** The HLD's two non-blocking open questions are resolved in this phase as assumptions: **OQ-SM-2** (key placement) → AS-4; **OQ-SM-3** (key reload) → AS-6. The HLD's previously-blocking OQ-SM-1 was resolved upstream by ADR-039 (revision 0.2.0).

| ID | Question | Options | Impact | Blocking? |
|---|---|---|---|---|
| — | (none) | — | — | — |

## 1C Glossary

| Term | Definition | Example |
|---|---|---|
| Server-mode profile | A deployment of `faradayd` in a container, single-tenant, one daemon per agent, serving a headless agent with no human present. | A sidecar container running `faradayd` beside one agent runtime. |
| `api_key` mode | The `AuthMode::ApiKey` downstream auth mode: the broker applies a per-capability static key (resolved from a file) to the outbound call. | A capability calling a SaaS API with `X-API-Key`. |
| `none` mode | The `AuthMode::Unauthenticated` downstream auth mode: the broker sends no credential; the call is still allowlist/budget/audit bound. | A capability calling `https://www.gov.uk/bank-holidays.json`. |
| `secretRef` | The per-capability resolver reference naming the key source; under `FileSecretResolver` a file path. | `"/var/run/secrets/govuk.key"`. |
| `keyPlacement` | The per-capability instruction for how the key is attached: a header (name + optional scheme) or a query parameter. | `{ "header": { "name": "Authorization", "scheme": "Token" } }`. |
| `allowWrite` | The per-capability boolean opt-in permitting unsafe methods; `false` (read-only, `GET` only) by default. | `true` on a capability issuing `POST`. |

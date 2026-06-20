# 04 — Domain Model & Data Lifecycle

> **Revision:** 0.3.0

## Domain Model

This profile extends the existing **Capability** entity (the `pysandbox.policy.json` capability object, sandbox-daemon 11-policy-schema) and introduces two value concepts. Names and shapes only — exact field types and JSON schema are `/spec`'s job.

- **Capability (extended).** The `authMode` value set gains `api_key` and `none`, alongside the existing `exchange` and `passthrough`. The existing fields (`provider`, `host`, `pathAllow`, `methods`, `scopes`, `audience`, `requireStepUpAuth`) are unchanged; for `api_key`/`none` capabilities, `audience` and (for `none`) `provider` are not meaningful and are not required. Lifecycle: authored in the policy manifest, resolved at run start to the in-memory resolved-capability form, discarded at run end.
- **Credential reference (`secretRef`) — new value.** A per-capability reference naming the source from which the broker resolves that capability's static key. It follows the existing `*_REF` → file convention; the broker resolves it through `SecretResolver` (`FileSecretResolver` reads the reference as a file path). One key per capability. Required when `authMode: api_key`; absent otherwise. Lifecycle: declared in the manifest; the *value* it points at lives in a mounted file (see Data Lifecycle).
- **Key placement — new value.** A per-capability description of **how** the resolved key is attached to the outbound request: a named request header with a scheme/prefix (e.g. `Authorization: Token <key>`, `X-API-Key: <key>`) or a query parameter. Required when `authMode: api_key`. It carries no secret itself — only the placement instruction. Lifecycle: declared in the manifest, consumed by DownstreamClient (C10) per call.
- **Write opt-in flag — new value.** A per-capability boolean (conceptually `allowWrite`; exact field name in `/spec`) that permits a capability to declare an unsafe method (`POST` / `PUT` / `PATCH` / `DELETE`). Absent / false (the default) means the capability is **read-only** and may declare only `GET`. Honoured only in a trusted / administrator-signed manifest (ADR-039 / sandbox-daemon ADR-021). Lifecycle: declared in the manifest, validated at config load, enforced per call by the broker's method allowlist.

## Data Lifecycle

- **Origin.** The static key originates outside faraday — issued by the third-party API provider, provisioned into the deployment as a **mounted secret file** (e.g. a Kubernetes/Docker secret mounted into the container), referenced by the capability's `secretRef`.
- **Storage at rest.** The key rests **only** in the mounted file, with the file's own permissions/owner under the deployment's control. faraday does not copy it to any persistent store of its own.
- **In use.** The broker resolves the key (at resolve time / call time) into **broker-process memory only**, applies it to the outbound request via DownstreamClient, and never marshals it across the guest boundary. This extends the [sandbox-daemon ADR-002](../sandbox-daemon/09-decisions.md) custody guarantee and the `broker.rs` "tokens never leave this module" property to static keys.
- **Never.** The key is never written to the guest sandbox, never placed in the returned envelope, never logged (the audit trail records sizes + keyed-HMAC user id only — sandbox-daemon ADR-018 / SR-18), and never sent to any host other than the capability's allowlisted `host`.
- **Retention / rotation.** The key's lifetime is the lifetime of the mounted secret. Rotation is performed by the deployment rotating the mounted file; whether the daemon hot-reloads on file change or requires a restart is a non-blocking open question ([10 — Risks](./10-risks.md)).
- **Multi-tenancy constraint.** None — the profile is single-tenant, one daemon per agent. There is no cross-tenant key isolation requirement because there is no second tenant in a daemon instance.

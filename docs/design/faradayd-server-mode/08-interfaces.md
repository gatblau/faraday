# 08 — Interfaces (external)

> **Revision:** 0.3.0

Names and shapes only. Exact JSON schema, field types, error-code strings, and the policy JSON Schema additions belong in `/spec` (LLD).

## Policy manifest (`pysandbox.policy.json`) — extends existing

- **`authMode` value set — extended.** Adds `api_key` and `none` to the existing `exchange` / `passthrough` (sandbox-daemon 11-policy-schema). *Extends existing.*
- **`secretRef` — new field (per capability).** Names the file reference from which the broker resolves this capability's static key (the `*_REF` → file convention). Required when `authMode: api_key`; absent otherwise. *New.*
- **Key-placement descriptor — new field (per capability).** Declares how the resolved key is attached to the request (header name + scheme, or query parameter). Required when `authMode: api_key`. Carries no secret. *New.* (Exact field name and shape — header vs query, scheme/prefix encoding — are `/spec`'s to fix; see Open Questions.)
- **Write opt-in flag — new field (per capability).** A boolean (conceptually `allowWrite`, default false) permitting the capability to declare an unsafe method (`POST`/`PUT`/`PATCH`/`DELETE`); read-only (`GET` only) by default, honoured only in an admin-signed manifest (ADR-039). *New.*
- For `authMode: none`: `audience` and `provider` are not required. For `authMode: api_key`: `audience` is not required.

The JSON Schema (`sandbox-daemon/schema/pysandbox.policy.schema.json`) and the authoring guide (`sandbox-daemon/12-authoring-guide.md`) are updated by `/spec` to reflect these additions; this HLD names them but does not specify the wire schema.

## Configuration (environment) — extends existing

- **OIDC config group (`PYS_OIDC_ISSUER`, `PYS_OIDC_CLIENT_ID`) — now conditional.** Required only when the manifest contains an OIDC-backed capability; not required for a pure `api_key`/`none` deployment (ADR-038). *Extends existing (currently mandatory at `config.rs`).*
- **Per-capability key references** — resolved via the existing `SecretResolver` (`FileSecretResolver`). The reference names are referenced by the manifest's `secretRef`, not enumerated as fixed env vars. *Extends existing secret-resolution mechanism.*
- All other `PYS_*` configuration (socket path, connection-token path, policy path, budgets, OTLP endpoint, audit HMAC key) is unchanged.

## No new network interface

The profile introduces **no** new listener, port, or RPC. The agent reaches the daemon over the existing local socket / `mcp-stdio` front door (sandbox-daemon ADR-028); outbound is the existing DownstreamClient HTTPS egress.

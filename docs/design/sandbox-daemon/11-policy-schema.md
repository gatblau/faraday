# 11 — Policy Manifest Schema (authoritative)

The capability manifest `pysandbox.policy.json` is the **authorisation taxonomy** of the whole solution: each capability names a Provider Plugin plus the host/path/method allowlist the Identity Broker (and the derived copy in `obo-broker`) enforces. This page is the authoritative specification of that taxonomy. The machine-readable contract is [`./schema/pysandbox.policy.schema.json`](./schema/pysandbox.policy.schema.json) (JSON Schema, draft 2020-12); this document explains it and records the rules the schema cannot express.

This supersedes the pre-pivot schema once held in the retired `design.md` §17 (which still named `provider` values `microsoft`/`msal-obo`). The current taxonomy is **provider-pluggable** with no default IdP (obo-broker ADR-009/ADR-017): the generic `rfc8693` plugin is the reference baseline.

## Top-level structure

```jsonc
{
  "capabilities": { "<capability-id>": { /* capability */ } },  // required, ≥1 entry
  "defaults":     { /* defaults */ },                            // required
  "siemExport":   { /* audit export config */ }                 // optional
}
```

`additionalProperties` is `false` at every object level: an unknown key is a validation failure, not an ignored extra.

## Capability object

A capability id is a dotted lowercase string (`^[a-z0-9]+(\.[a-z0-9]+)*$`), e.g. `github.repo.read`, `internal.tickets`. It is the stable key referenced by `run().requestedCapabilities`.

| Field | Type | Required | Meaning and constraints |
|---|---|---|---|
| `provider` | string `^[a-z0-9][a-z0-9-]*$` | yes | `providerId` of an in-tree, security-reviewed Provider Plugin (obo-broker ADR-009), selected per capability by the Provider Registry. Plugins are compiled in, never dynamically loaded. Known values: `rfc8693` (RFC 8693 token exchange), `github` (OAuth). An unknown provider fails closed at load. |
| `scopes` | string[] (≥1, unique) | yes | **Advisory only.** The issued token may carry broader scopes, and per-call downscoping is not generally available. Never treat `scopes` as a boundary. |
| `host` | string (hostname) | yes | Exactly **one** allowlisted host. The broker pins outbound calls to it, does not auto-follow cross-origin redirects, and never re-sends `Authorization` across a host boundary. No wildcards. |
| `audience` | string (≥1) | conditional | Downstream API audience for token exchange. **Required for token-exchange providers** (`provider=rfc8693` and equivalents); omit for non-exchange providers such as `github`. The schema enforces the `rfc8693` case structurally; the broker enforces the rule for every token-exchange plugin at load. |
| `pathAllow` | string[] regex (≥1) | yes | Anchored regexes matched against the **canonicalised** path (decoded; `.`/`..` resolved; `//` collapsed), excluding the query string. A path still containing `..` after canonicalisation is rejected before matching. |
| `methods` | enum[] (≥1, unique) | yes | Subset of `GET`, `POST`, `PATCH`, `PUT`, `DELETE`. The SDK currently exposes get/post/patch/delete; `PUT` is accepted in policy for forward compatibility. |
| `requireStepUpAuth` | boolean (default `false`) | no | When `true`, the broker requires a stepped-up `id_token` `acr` (obo-broker ADR-014) and otherwise returns an RFC 9470 challenge; the daemon steps up (via its consent UI) and retries once (ADR-015). Recommended `true` for write capabilities. |

## `defaults` object

| Field | Type | Required | Meaning |
|---|---|---|---|
| `requireUserConsentPerSession` | boolean | yes | First use of each capability per workspace session prompts for consent (cached in memory, not persisted). |
| `maxCallsPerRun` | integer ≥1 | yes | Hard cap on broker calls within one run; over-budget returns a `429`-shaped error. |
| `maxCallsPerSession` | integer ≥1 | yes | Hard cap across all runs in a session. MUST be ≥ `maxCallsPerRun` (broker-enforced — see below). |
| `responseMaxBytes` | integer ≥1 | yes | Maximum response body returned to the guest; larger responses are truncated with a flag. |
| `debug` | boolean (default `false`) | no | Developer mode: request/response bodies may be logged. MUST be `false` in enterprise / real-credential policy. |

## `siemExport` object (optional)

Audit export configuration (obo-broker ADR-016). When the deployment uses **real (non-mock) credentials**, a reachable tamper-evident sink is **required** and checked fail-closed at startup; with no reachable sink the deployment runs mock / non-sensitive-credentials-only. The exported stream is the authoritative audit record; the local `.jsonl` log is non-authoritative.

| Field | Type | Required | Meaning |
|---|---|---|---|
| `enabled` | boolean | yes | Whether audit entries are exported to a SIEM/OTLP sink. |
| `otlpEndpoint` | string (uri) | conditional | OTLP endpoint URL; required (and must be reachable) when `enabled` is `true` under real credentials. |

> **Assumption (S6).** The exact `siemExport` field set is a documented assumption pending `/spec` confirmation — `enabled` + `otlpEndpoint` is the proposed minimal shape. Recorded here rather than left as an open question because real-credential operation depends on it (ADR-016).

## Rules the schema cannot express (broker-enforced, fail-closed)

The JSON Schema validates shape; the broker enforces these cross-field and semantic rules at load, **rejecting** a non-conforming manifest (it never falls back to defaults):

1. **`maxCallsPerSession` ≥ `maxCallsPerRun`.** A per-session budget below the per-run budget is incoherent.
2. **`debug` MUST be `false`** under enterprise / real-credential mode.
3. **`audience` required for every token-exchange provider**, not only `rfc8693`. The pluggable provider set cannot be fully enumerated in the schema, so the broker applies this per plugin (each token-exchange plugin declares it needs an audience).
4. **`provider` must name a known in-tree plugin.** An unknown `providerId` is rejected — capabilities are never silently disabled.
5. **`pathAllow` patterns must be anchored and are matched against the canonicalised path.** An unanchored pattern is accepted by the schema (it is still a valid regex) but is a privilege-escalation hazard — see [12 — Authoring Guide](./12-authoring-guide.md).

## Validation behaviour (errors are first-class)

| Condition | Behaviour |
|---|---|
| Manifest fails JSON-Schema validation (unknown key, missing required field, wrong type, bad capability-id pattern) | Rejected at load; the daemon fails closed (no fallback to defaults). |
| `rfc8693` capability without `audience` | Rejected by the schema (`allOf` if/then). |
| `siemExport.enabled = true` without `otlpEndpoint` | Rejected by the schema. |
| Broker-only rule violated (rules 1–5 above) | Rejected at load by the broker with a typed configuration error naming the offending capability/field. |
| Unknown `provider` | Rejected at load; the capability is not registered. |

## Worked example (validates against the schema)

```json
{
  "capabilities": {
    "github.repo.read": {
      "provider": "github",
      "scopes": ["repo"],
      "host": "api.github.com",
      "pathAllow": ["^/repos/.+", "^/user$"],
      "methods": ["GET"]
    },
    "internal.tickets": {
      "provider": "rfc8693",
      "audience": "api://tickets.example.com",
      "scopes": ["Tickets.ReadWrite"],
      "host": "tickets.example.com",
      "pathAllow": ["^/api/v2/tickets($|/.*)"],
      "methods": ["GET", "POST", "PATCH"],
      "requireStepUpAuth": true
    }
  },
  "defaults": {
    "requireUserConsentPerSession": true,
    "maxCallsPerRun": 50,
    "maxCallsPerSession": 500,
    "responseMaxBytes": 1048576,
    "debug": false
  },
  "siemExport": {
    "enabled": true,
    "otlpEndpoint": "https://otlp.example.com:4318"
  }
}
```

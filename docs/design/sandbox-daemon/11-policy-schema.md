# 11 — Policy Manifest Schema (authoritative)

The capability manifest `pysandbox.policy.json` is the **authorisation taxonomy** of the whole solution: each capability names a Provider Plugin plus an allowlist the Identity Broker (and the derived copy in `obo-broker`) enforces — a host/path/method allowlist for a `rest` capability, or a server-origin/tool-name allowlist for an `mcp` capability (ADR-034). This page is the authoritative specification of that taxonomy. The machine-readable contract is [`./schema/pysandbox.policy.schema.json`](./schema/pysandbox.policy.schema.json) (JSON Schema, draft 2020-12); this document explains it and records the rules the schema cannot express.

> **Schema-file follow-up (ADR-034).** The `mcp` capability kind described below is new in this prose taxonomy and the JSON Schema file does **not yet** encode `kind`/`serverUrl`/`toolAllow`; extending it (a discriminated union on `kind`, with the kind/allowlist constraints of rule 6 expressed as `if/then`) is a `/spec` task. Until that lands, this document is authoritative for the `mcp` kind and a `kind: "mcp"` capability will not pass the current `.schema.json`.

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

Every capability has a **`kind`** that selects its shape and therefore which allowlist fields apply:

| Field | Type | Required | Meaning and constraints |
|---|---|---|---|
| `kind` | enum `rest` \| `mcp` (default `rest`) | no | `rest` mediates a REST/HTTP API by host + path + method; `mcp` mediates a downstream MCP server over HTTP/SSE transport by server origin + tool name (ADR-034). A capability that omits `kind` is `rest`, so manifests written before ADR-034 are unchanged. |

`provider`, `scopes`, `audience`, and `requireStepUpAuth` are **shared** by both kinds. The allowlist fields differ: `rest` uses `host` + `pathAllow` + `methods`; `mcp` uses `serverUrl` + `toolAllow`.

### Shared and REST fields (`kind: "rest"`)

| Field | Type | Required | Meaning and constraints |
|---|---|---|---|
| `provider` | string `^[a-z0-9][a-z0-9-]*$` | yes | `providerId` of an in-tree, security-reviewed Provider Plugin (obo-broker ADR-009), selected per capability by the Provider Registry. Plugins are compiled in, never dynamically loaded. Known values: `rfc8693` (RFC 8693 token exchange), `github` (OAuth). An unknown provider fails closed at load. Shared by both kinds. |
| `scopes` | string[] (≥1, unique) | yes | **Advisory only.** The issued token may carry broader scopes, and per-call downscoping is not generally available. Never treat `scopes` as a boundary. Shared by both kinds. |
| `host` | string (hostname) | yes *(rest)* | Exactly **one** allowlisted host. The broker pins outbound calls to it, does not auto-follow cross-origin redirects, and never re-sends `Authorization` across a host boundary. No wildcards. **REST only** — absent on an `mcp` capability (use `serverUrl`). |
| `audience` | string (≥1) | conditional | Downstream API audience for token exchange. **Required for token-exchange providers** (`provider=rfc8693` and equivalents); omit for non-exchange providers such as `github`. The schema enforces the `rfc8693` case structurally; the broker enforces the rule for every token-exchange plugin at load. Shared by both kinds. |
| `pathAllow` | string[] regex (≥1) | yes *(rest)* | Anchored regexes matched against the **canonicalised** path (decoded; `.`/`..` resolved; `//` collapsed), excluding the query string. A path still containing `..` after canonicalisation is rejected before matching. **REST only** — absent on an `mcp` capability (use `toolAllow`). |
| `methods` | enum[] (≥1, unique) | yes *(rest)* | Subset of `GET`, `POST`, `PATCH`, `PUT`, `DELETE`. The SDK currently exposes get/post/patch/delete; `PUT` is accepted in policy for forward compatibility. **REST only** — absent on an `mcp` capability (the MCP transport is always a `tools/call` POST). |
| `requireStepUpAuth` | boolean (default `false`) | no | When `true`, the broker requires a stepped-up `id_token` `acr` (obo-broker ADR-014) and otherwise returns an RFC 9470 challenge; the daemon steps up (via its consent UI) and retries once (ADR-015). Recommended `true` for write capabilities. Shared by both kinds. |

### MCP fields (`kind: "mcp"`)

A `kind: "mcp"` capability carries the shared fields above (`provider`, `scopes`, `audience` for token-exchange providers, `requireStepUpAuth`) plus the two fields below, and MUST NOT carry `host`, `pathAllow`, or `methods`.

| Field | Type | Required | Meaning and constraints |
|---|---|---|---|
| `serverUrl` | string (https URI) | yes *(mcp)* | The single allowlisted downstream MCP server origin. The broker pins each `tools/call` to it over HTTPS, does not auto-follow cross-origin redirects, and never re-sends the credential across a host boundary — the `host` rules of a `rest` capability, applied to the MCP transport. HTTP/SSE transport only; loopback plaintext follows ADR-032. A non-HTTP transport (stdio) is not expressible (ADR-034 / threat-model RR-10). |
| `toolAllow` | string[] (≥1, unique) | yes *(mcp)* | The exact downstream tool names the agent may call via `mcp.<capability-id>.call_tool(name, ...)`. A tool the server advertises through `tools/list` but absent from `toolAllow` is unreachable, fail-closed — the server's advertised list is never the authorisation surface (ADR-034). The allowlist is over tool **names only**; per-argument constraints are deferred to `/spec` and, when added, extend this field without a schema break. |

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
6. **Allowlist fields must match `kind`.** A `rest` capability (or one omitting `kind`) MUST carry `host`/`pathAllow`/`methods` and MUST NOT carry `serverUrl`/`toolAllow`; an `mcp` capability MUST carry `serverUrl`/`toolAllow` and MUST NOT carry `host`/`pathAllow`/`methods`. A mismatched capability is rejected at load (ADR-034).
7. **`mcp` capabilities are HTTP/SSE transport only.** `serverUrl` MUST be an `https` origin (or an ADR-032 loopback `http` origin under the dev opt-in). stdio-transport downstream MCP is not expressible and is out of scope (ADR-034 / threat-model RR-10).

## Validation behaviour (errors are first-class)

| Condition | Behaviour |
|---|---|
| Manifest fails JSON-Schema validation (unknown key, missing required field, wrong type, bad capability-id pattern) | Rejected at load; the daemon fails closed (no fallback to defaults). |
| `rfc8693` capability without `audience` | Rejected by the schema (`allOf` if/then). |
| `siemExport.enabled = true` without `otlpEndpoint` | Rejected by the schema. |
| Broker-only rule violated (rules 1–7 above) | Rejected at load by the broker with a typed configuration error naming the offending capability/field. |
| `mcp` capability carrying `host`/`pathAllow`/`methods`, or `rest` capability carrying `serverUrl`/`toolAllow` | Rejected at load (kind/allowlist mismatch — rule 6). |
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
    },
    "tickets.mcp": {
      "kind": "mcp",
      "provider": "rfc8693",
      "audience": "api://tickets-mcp.example.com",
      "scopes": ["Tickets.Read"],
      "serverUrl": "https://tickets-mcp.example.com/mcp",
      "toolAllow": ["search_tickets", "get_ticket"]
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

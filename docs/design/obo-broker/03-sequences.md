# 03 — Principal Sequences

## Sequence: Exchange and call — cache miss (golden path)

```mermaid
sequenceDiagram
  participant Ext as faradayd (Identity Broker)
  participant Svc as obo-broker
  participant IdP as Identity Provider
  participant Cache as Distributed cache
  participant API as Downstream API

  Ext->>Svc: POST exchange {userIdToken, capabilityId, verb, path}
  Svc->>Svc: validate id_token (issuer, audience, signature, expiry)
  Svc->>Svc: resolve capability, canonicalise path, allowlist and rate check
  Svc->>Cache: lookup (user, audience, scopes, providerId)
  Cache-->>Svc: miss
  Svc->>IdP: provider plugin - RFC 8693 token exchange (confidential client, cert)
  IdP-->>Svc: downstream access token
  Svc->>Cache: store (encrypted, TTL up to token expiry)
  Svc->>API: verb path with downstream Bearer (no cross-origin redirect)
  API-->>Svc: response
  Svc->>Svc: sanitize and audit
  Svc-->>Ext: sanitized JSON (no downstream token)
```

- **Trigger:** the daemon's Identity Broker proxies a sandbox call to a token-exchange capability (the provider is selected by the Provider Registry per the capability's `provider` field — ADR-017).
- **Result:** the daemon receives sanitized downstream JSON; the downstream token stays server-side.
- **Error posture:** invalid/expired/wrong-audience `id_token` → `401`; capability/host/path/method not allowed → `403`; rate budget exceeded → `429`; token-exchange failure → `502` with no token surfaced; IdP/cache unreachable → `503`; downstream timeout → `504`.

## Sequence: Exchange and call — cache hit

```mermaid
sequenceDiagram
  participant Ext as faradayd
  participant Svc as obo-broker
  participant Cache as Distributed cache
  participant API as Downstream API

  Ext->>Svc: POST exchange {userIdToken, capabilityId, verb, path}
  Svc->>Svc: validate id_token, allowlist and rate check
  Svc->>Cache: lookup (user, audience, scopes, providerId)
  Cache-->>Svc: hit (decrypt, not expired)
  Svc->>API: verb path with downstream Bearer
  API-->>Svc: response
  Svc->>Svc: sanitize and audit
  Svc-->>Ext: sanitized JSON
```

- **Trigger:** as above, when a non-expired token is cached.
- **Result:** the IdP round-trip is skipped; lower latency.
- **Error posture:** a decrypt failure or near-expiry token falls through to the cache-miss exchange path.

## Sequence: Silent refresh on expiry

```mermaid
sequenceDiagram
  participant Svc as obo-broker
  participant Cache as Distributed cache
  participant IdP as Identity Provider

  Svc->>Cache: lookup, entry expired or within refresh window
  Svc->>IdP: provider plugin - refresh (silent)
  alt refresh succeeds
    IdP-->>Svc: new downstream token
    Svc->>Cache: replace (encrypted, new TTL)
  else refresh fails
    IdP-->>Svc: error
    Svc->>Svc: evict entry, return 502 (auth_refresh_failed) to caller
  end
```

- **Trigger:** a cached token is expired or inside its refresh window at use time.
- **Result:** transparent re-exchange; the caller is unaware on success.
- **Error posture:** on refresh failure the entry is evicted and the caller receives an auth-failure shape; no token is surfaced.

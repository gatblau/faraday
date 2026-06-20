# 00 — Overview

## Summary

`obo-broker` is a single-tenant, server-side confidential-client service that performs **provider-pluggable** token exchange (RFC 8693 and equivalents; the provider is selected per deployment with no default — ADR-017) for the `faradayd` daemon and proxies the resulting authenticated call to an allowlisted downstream corporate API. It exists so that privileged downstream tokens are minted and held on a server the user does not control, never on the workstation. It is deployed on Kubernetes, caches exchanged tokens in a distributed encrypted cache, and authenticates incoming requests by validating the user's audience-restricted `id_token`. Non-goals: it is not a general API gateway, not an identity provider, and not the policy authoring surface (that is the daemon's capability manifest).

## Motivation

The parent design ([`../sandbox-daemon/`](../sandbox-daemon/README.md), ADR-005) establishes that token-exchange flows (RFC 8693, Microsoft OBO, and equivalents) require a confidential client credential (secret or certificate). The concrete identity provider is pluggable (ADR-009) and selected per deployment — a generic RFC 8693 authorization server, Okta, Keycloak, or Microsoft Entra — with no default IdP (ADR-017); whichever provider an enterprise runs fronts its corporate services. The sandbox daemon is a public client distributed to user machines and cannot safely ship such a credential. Without a server-side component, on-behalf-of access to corporate APIs is impossible to offer securely — the only alternatives are to embed a confidential credential (unacceptable) or to hand the user a broadly-scoped downstream token they could replay directly (defeats the sandbox boundary). This service is the committed resolution: it holds the confidential credential, performs the exchange, and ensures the privileged downstream token never leaves the server.

## Goals

- Perform provider-pluggable OAuth2 token exchange (RFC 8693) for the daemon, using a server-held confidential-client credential; the provider is selected per deployment with no default IdP (ADR-017).
- **Never return a downstream access token to the caller** — return only the sanitized downstream API response.
- Validate every incoming request as a genuine, audience-restricted user `id_token` before acting.
- Enforce the same host / path / method allowlist the daemon declares, as defense in depth.
- Cache exchanged tokens securely (encrypted, distributed) and refresh them silently.
- Provide an auditable record of every exchange and downstream call.

## Non-goals

- Acting as a general-purpose API gateway or reverse proxy for arbitrary hosts.
- Being an identity provider or issuing its own user tokens.
- Owning the capability policy authoring experience (the daemon's `pysandbox.policy.json` is the source; the service enforces a derived copy).
- Multi-tenant SaaS operation — each enterprise runs its own instance (ADR-002).
- Long-term storage of tokens beyond their natural expiry.

## Glossary

| Term | Definition | Example |
|---|---|---|
| OBO (on-behalf-of) | An OAuth2 token-exchange flow (RFC 8693) that swaps a user token for a downstream-API token carrying the user's identity. | Exchange a user token for a `tickets.contoso.com` token. |
| Confidential client | An OAuth2 client that authenticates to the identity provider with its own secret or certificate; only safe on a server. | This service's service app/client registered with the configured IdP, holding a certificate. |
| Provider Plugin | A first-party, in-tree, compiled-in unit encapsulating one IdP's inbound-token validation and downstream-credential acquisition behind a common contract (ADR-009). | The generic `rfc8693` reference plugin, or a provider plugin such as `okta` / `keycloak`. |
| Provider Registry | The core component that selects the Provider Plugin for a capability by its `provider` field. | Routes an `internal.tickets` capability to its configured provider plugin (e.g. `keycloak`). |
| `id_token` (audience-restricted) | The user's identity assertion, whose audience is set to this service; proves who the caller is without granting downstream access. | Token with `aud = api://obo-broker`. |
| Downstream access token | The privileged token minted by the OBO exchange for a corporate API; never returned to the caller. | Bearer for `tickets.contoso.com`. |
| Capability | A named permission (provider/host/path/method allowlist) carried over from the daemon's manifest. | `internal.tickets`. |
| Token cache entry | A cached downstream credential keyed by `(user, audience, scopes, providerId)`, encrypted at rest, with a TTL. | Redis entry, AES-256-GCM-encrypted. |
| KeyManager | The pluggable key-management backend (ADR-018) that mints and unwraps the per-entry data keys for cache envelope encryption (ADR-011); selected per deployment, no default. | A Vault-transit or cloud-KMS backend, selected by `OBO_KMS_PROVIDER`. |
| Workload identity | A Kubernetes mechanism that grants a pod a federated identity to fetch the confidential-client credential without a static secret. | Pod federates to the cluster workload-identity provider to load the signing cert. |
| Agent (`azp`) | The calling client identity, taken from the user `id_token`'s `azp` (authorized-party) claim; the rate budget is per-`(user, agent)`. | A specific agent/client application. |
| Audit entry | An append-only record of one exchange + downstream call (sizes, not bodies). | `{runId, user(keyed HMAC), audience, host, path, status}`. |
| `acr` / `amr` | OIDC `id_token` claims naming the assurance level (`acr`) and methods (`amr`) of the user's authentication; the basis for step-up. | An `acr` value in the configured allowlist denoting MFA (the concrete value is provider-specific). |
| `auth_time` | OIDC `id_token` claim giving the time of the user's last authentication; the basis for step-up *recency* (ADR-015) — step-up requires a recent `auth_time`, not merely an elevated `acr`. | `auth_time` within `OBO_STEP_UP_MAX_AGE_SECONDS` of the request. |
| Step-up authentication | Requiring a higher *and recent* assurance level (e.g. MFA) for a sensitive capability, asserted via `acr` + `auth_time` and challenged via RFC 9470. | A `requireStepUpAuth` capability returns 401 until an elevated, recent `acr` is presented (ADR-014/ADR-015). |

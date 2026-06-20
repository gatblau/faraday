# 00 — Overview

> **Mode:** draft
> **Generated from:** inline context (decisions fixed by the user; evidence from `docs/design/sandbox-daemon/`, `docs/security/threat-model.md`, `sandbox-daemon/src/broker.rs`, `sandbox-daemon/src/config.rs`)
> **Revision:** 0.3.0
> **Last updated:** 2026-06-18

## Summary

A **server-side, single-tenant deployment profile** for `faradayd`: the daemon runs in a container, one daemon per agent, to serve an agent deployed on a server runtime rather than a developer's desktop. The profile adds two **non-OIDC downstream auth modes** — `api_key` (a per-capability static key held by the broker) and `none` (genuinely public endpoints) — so a headless agent with no human present can call keyed third-party APIs and public APIs without an interactive sign-in and without the `obo-broker`. The core invariant is unchanged: a credential never reaches the guest sandbox or the agent code. This design covers topology, the threat-model delta, and the architectural decisions; wire-level schema for the new policy fields belongs in `/spec`.

## Motivation

`faradayd` today is a **per-user desktop daemon** ([sandbox-daemon ADR-023](../sandbox-daemon/09-decisions.md)). The two existing downstream auth modes both presuppose a human OIDC sign-in:

- `Exchange` (default) sends the user's `id_token` to the server-side `obo-broker` for RFC 8693 token exchange (sandbox-daemon ADR-005).
- `Passthrough` forwards the user's OIDC `access_token` as a `Bearer`, audienced per [sandbox-daemon ADR-033](../sandbox-daemon/09-decisions.md).

User credentials are obtained only by an **interactive browser authorization-code + PKCE flow on a loopback redirect** (sandbox-daemon ADR-029). A server-deployed agent has no human at a browser and no loopback session, so it cannot sign in — and therefore cannot make any authenticated outbound call today. There is also no path for a call that carries **no** credential: every outbound call must resolve to a capability, and an unmatched call fails closed (`CAP_UNKNOWN`). So a server agent can reach neither a public API (e.g. `https://www.gov.uk/bank-holidays.json`) nor an API-keyed third-party service. Doing nothing leaves faraday-mediated agents undeployable on a server runtime.

## Goals

- Run `faradayd` server-side in a **container**, **single-tenant**, **one daemon per agent service**.
- Add an `api_key` downstream auth mode: the broker holds a **per-capability static key**, **file-backed** via the existing `SecretResolver` (`*_REF`) convention, and applies it to the outbound request.
- Let the policy author configure **how** the key is applied (header name + scheme, or query parameter) — not assume `Bearer`.
- Add a `none` (unauthenticated) downstream auth mode for genuinely public endpoints — no credential, no sign-in — still bounded by host / path / method allowlist, call budgets, and audit.
- A run that uses only `api_key` and/or `none` capabilities requires **no interactive sign-in**.
- Capabilities are **read-only by default** (all manifests, every profile); a capability may perform writes only via an explicit per-capability opt-in in an admin-signed manifest.
- Preserve the one invariant: the key (and any credential) is applied by the broker and **never serialised into the returned envelope, never reaches the guest sandbox** — the property `Passthrough` already upholds in `broker.rs`.
- Preserve the audit posture: real-credential operation still requires the OTLP audit sink ([sandbox-daemon ADR-016](../sandbox-daemon/09-decisions.md)).

## Non-goals

- **Multi-tenancy / a multi-user daemon.** This profile is explicitly single-tenant, one daemon per agent; the per-session token-vault isolation a multi-tenant server would need is out of scope.
- **Network client-authentication between agent and daemon.** The agent and the daemon ship in **one container under one UID**, so the existing local client-auth controls ([sandbox-daemon ADR-024](../sandbox-daemon/09-decisions.md): same-UID peer check + `0600` socket + connection token) hold unchanged. No mTLS / bearer client-auth is introduced.
- **Replacing OBO for the desktop profile.** `Exchange` and `Passthrough` are unchanged; the desktop profile is unaffected.
- **Raw environment-variable secrets.** The key is file-backed via `SecretResolver`; a raw-env credential resolver is explicitly rejected (ADR-036).
- **Wire-level schema.** Exact field types, error-code strings, JSON schema for the new policy fields belong in `/spec` (LLD), not here.

## Glossary

| Term | Definition | Example |
|---|---|---|
| Server-mode profile | A deployment of `faradayd` inside a container, single-tenant, one daemon per agent service, serving a headless agent. | A sidecar/container running `faradayd` alongside one agent process. |
| `api_key` auth mode | A downstream auth mode where the broker applies a per-capability static key, resolved from a file, to the outbound call. | A capability calling a SaaS API that authenticates with an `X-API-Key` header. |
| `none` auth mode | A downstream auth mode where the broker sends no credential; the call is still allowlist- and budget-constrained. | A capability calling `https://www.gov.uk/bank-holidays.json`. |
| `secretRef` | A per-capability reference naming the file from which the broker resolves that capability's key (the `*_REF` → file convention, `config.rs` `FileSecretResolver`). | `secretRef: "PYS_CAP_GOVUK_KEY_REF"`. |
| Key placement | The policy-configured description of **how** the key is attached to the request (header name + scheme, or query parameter). | `Authorization: Token <key>` vs `X-API-Key: <key>` vs `?api_key=<key>`. |
| Write opt-in flag | A per-capability boolean permitting unsafe methods; read-only (`GET` only) by default, honoured only in an admin-signed manifest. | `allowWrite: true` on a capability that issues `POST`. |

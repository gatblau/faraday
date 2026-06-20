# OBO Broker Service (`obo-broker`) — High-Level Design

> **Generated from:** problem statement (backend OBO service for `faradayd`) + targeted interview; companion to [`../sandbox-daemon/`](../sandbox-daemon/README.md) ADR-005

## Orientation

`obo-broker` is the server-side confidential-client service that performs **provider-pluggable** token exchange for the `faradayd` sandbox daemon. Its reason to exist: a distributed desktop daemon is a *public* client and cannot safely hold a confidential-client credential, so the token exchange — and the privileged downstream corporate-API tokens it produces — must live on a server the user does not control. The identity provider is abstracted behind a Provider Plugin (ADR-009) with **no default IdP** (ADR-017): the generic RFC 8693 token-exchange plugin is the reference baseline, and Okta, Keycloak, and Microsoft Entra are peer first-class plugins, so the core is independent of any one IdP. The daemon sends the user's audience-restricted `id_token` plus the requested capability call; the service validates the token, exchanges it, calls the downstream API, and returns only sanitized JSON. Downstream tokens never reach the workstation. This HLD is the companion to the parent daemon design ([`../sandbox-daemon/`](../sandbox-daemon/README.md)); it owns everything inside the backend service boundary. The next move is `/spec` against `docs/design/obo-broker/` — there are no blocking open questions.

## Contents

- [00 — Overview](./00-overview.md) — Summary, Motivation, Goals, Non-goals, Glossary.
- [01 — Context](./01-context.md) — System context diagram, external actors, neighbouring systems.
- [02 — Architecture](./02-architecture.md) — System architecture diagram, component responsibilities.
- [03 — Sequences](./03-sequences.md) — Principal sequence diagrams (cache miss/exchange, cache hit, refresh).
- [04 — Domain](./04-domain.md) — Domain Model, Data Lifecycle.
- [05 — Tech stack](./05-tech-stack.md) — Tech choices and rationale.
- [06 — Regulatory](./06-regulatory.md) — Compliance obligations and how the design addresses them.
- [07 — Cross-cutting](./07-cross-cutting.md) — Cross-cutting Concerns table, NFRs.
- [08 — Interfaces](./08-interfaces.md) — External interfaces (names and shapes only).
- [09 — Decisions](./09-decisions.md) — Architectural Decision Records (ADRs).
- [10 — Risks](./10-risks.md) — Risks, Alternatives, Dependencies, Rollout/Rollback.

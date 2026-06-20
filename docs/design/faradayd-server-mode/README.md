# faradayd Server-Mode — High-Level Design

> **Mode:** draft
> **Generated from:** inline context (decisions fixed by the user; evidence from `docs/design/sandbox-daemon/`, `docs/security/threat-model.md`, `sandbox-daemon/src/broker.rs`, `sandbox-daemon/src/config.rs`)
> **Revision:** 0.3.0
> **Last updated:** 2026-06-18

## Orientation

This HLD defines a **server-side, single-tenant deployment profile** for `faradayd` — the daemon running in a container, one daemon per agent, to serve a headless agent on a server runtime. It adds two non-OIDC downstream auth modes (`api_key`, `none`) so a server agent can call keyed and public APIs with no human present and no `obo-broker`, while preserving the invariant that credentials never reach the guest sandbox. It is a **companion** to the [sandbox-daemon HLD](../sandbox-daemon/README.md), continues that daemon's ADR register from **ADR-034**, and reinterprets threat-model assumption **A-1** as "one daemon per agent". All blocking open questions are resolved (OQ-SM-1 by ADR-039 — per-capability write opt-in, default read-only); the next move is `/spec` against this folder.

## Contents

- [00 — Overview](./00-overview.md) — Summary, Motivation, Goals, Non-goals, Glossary.
- [01 — Context](./01-context.md) — System context diagram, external actors, what the profile removes from the flow.
- [02 — Architecture](./02-architecture.md) — Component diagram, per-component delta (C11 / C10 / C13 / C1 changed).
- [03 — Sequences](./03-sequences.md) — `api_key` golden path, `none` call, startup without OIDC.
- [04 — Domain](./04-domain.md) — Capability extension, `secretRef`, key placement, key data lifecycle.
- [05 — Tech stack](./05-tech-stack.md) — Inherited stack plus container substrate and file-backed secrets.
- [06 — Regulatory](./06-regulatory.md) — N/A — non-regulated; audit posture carried forward.
- [07 — Cross-cutting](./07-cross-cutting.md) — Cross-cutting Concerns table, NFRs (static-key security posture).
- [08 — Interfaces](./08-interfaces.md) — Policy-manifest and configuration additions (names and shapes only).
- [09 — Decisions](./09-decisions.md) — ADR-034 … ADR-039.
- [10 — Risks](./10-risks.md) — Assumptions, Open Questions (all blocking ones resolved), Risks, Alternatives, Dependencies, Rollout/Rollback.
- [99 — Changelog](./99-changelog.md) — HLD revision history.

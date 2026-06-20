# Host-resident Sandbox Daemon (`faradayd`) — High-Level Design

> **Generated from:** the host-resident-daemon redesign of the former `sandbox` topic (forked at its revision 0.9.0, then **removed 2026-06-13**); the rationale is captured in ADR-023–026.
> **Replaces:** the former `sandbox` topic (removed); this is the single authoritative source for the sandbox design, and obo-broker references point here (`../sandbox-daemon/`).

## Orientation

`faradayd` is a **per-user, host-resident daemon** — a single **Rust** binary — that executes **agent-authored Python** in a **WebAssembly capability sandbox** (RustPython compiled to WASM, on the Wasmtime runtime — ADR-013/ADR-014) and lets that code call **pre-approved external APIs** — primarily IdP-fronted corporate services, with other providers (e.g. GitHub) available via the backend broker's pluggable providers — on the user's behalf, without ever marshalling the underlying tokens into the Python process, the agent, or the user's terminal. It is **independent of the IDE**: any agent host reaches it over a **local socket** (UDS / named pipe) through a **single `run(code, capabilities)` entry** — exposed both as a faraday-native RPC and as a *single* MCP tool (not per-API tools — ADR-001/ADR-023) — so **no per-IDE plugin is built or installed** (ADR-023). Interactive sign-in, consent, and step-up are rendered by a **daemon-owned UI** (ADR-025), so the clients stay thin. All authenticated traffic is mediated by the in-daemon **Identity Broker**; the WASM guest has **no ambient authority** and reaches the outside world only through a single broker host import, so network egress is structurally impossible — the same boundary on every OS. The whole daemon (controller, broker, runtime, client-auth, consent UI) is **Rust** for one efficient binary and a lean, auditable supply chain (ADR-026), with no Node/TypeScript runtime. The sandbox's purpose is **token custody**, not a network perimeter (ADR-002). The agent Python contract is the standard-library data-manipulation surface plus the broker SDK (no third-party or native packages). The on-behalf-of backend ([`../obo-broker/`](../obo-broker/README.md)) is a **committed** component. The next move is `/spec` against `docs/design/sandbox-daemon/`. Load-bearing controls needing sign-off before production: the **Wasmtime-escape pen test** (plus a RustPython coverage spike), and the **local client-authentication model** (ADR-024) — the one genuinely new security surface this daemon model introduces.

## Contents

- [00 — Overview](./00-overview.md) — Summary, Motivation, Goals, Non-goals, Glossary.
- [01 — Context](./01-context.md) — System context diagram, external actors, neighbouring systems.
- [02 — Architecture](./02-architecture.md) — System architecture diagram, component responsibilities.
- [03 — Sequences](./03-sequences.md) — Principal sequence diagrams (typical run, authenticated call, backend token exchange).
- [04 — Domain](./04-domain.md) — Domain Model, Data Lifecycle.
- [05 — Tech stack](./05-tech-stack.md) — Tech choices and rationale.
- [06 — Regulatory](./06-regulatory.md) — Compliance obligations and how the design addresses them.
- [07 — Cross-cutting](./07-cross-cutting.md) — Cross-cutting Concerns table, NFRs.
- [08 — Interfaces](./08-interfaces.md) — External interfaces (names and shapes only).
- [09 — Decisions](./09-decisions.md) — Architectural Decision Records (ADRs).
- [10 — Risks](./10-risks.md) — Risks, Alternatives, Dependencies, Rollout/Rollback.
- [11 — Policy Schema](./11-policy-schema.md) — authoritative capability-manifest taxonomy; specifies [`./schema/pysandbox.policy.schema.json`](./schema/pysandbox.policy.schema.json).
- [12 — Authoring Guide](./12-authoring-guide.md) — building taxonomy-compatible assets (with Gen AI) that validate and stay least-privilege.

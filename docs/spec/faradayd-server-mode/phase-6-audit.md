# Phase 6 — Self-Audit (`faradayd-server-mode`)

> **Status:** Draft → (Approved on passing this gate)
> **derivedFromHld:** 0.3.0 (`docs/design/faradayd-server-mode/`)

Verdict: **PASSED** (with two non-blocking notes, below). Every item is binary; notes do not gate promotion.

```
[x] Every entity has a complete data model with types and constraints.
    — AuthMode, KeyPlacement, ResolvedCapability delta, ApiKeyStore defined in Phase 2C with full Rust definitions.
[x] Every action has defined inputs, outputs, numbered steps, and errors.
    — C1, C4, C11, C13, SCHEMA each carry numbered Internal Logic + an Error Table.
[x] No banned phrases remain (see banned-phrases.md).
    — Verified by scan; no "handle/manage/process/etc./as appropriate/properly/correctly/straightforward/obviously".
[x] Every component has ≥3 Gherkin acceptance criteria (happy, edge, error).
    — C1:3, C4:4, C11:4, C13:3, SCHEMA:3, Auth&Authz:3, Configuration:3.
[x] Every component has an error table with ≥2 rows.
    — C1:3, C4:5, C11:4, C13:2, SCHEMA:2, Auth&Authz:3, Configuration:3.
[x] Every cross-component interaction is documented on BOTH sides.
    — C4 exposes api_key_secret_refs()/has_oidc_capability(); consumed by bootstrap (Phase 4 Configuration) + C1 require_oidc; C11 consumes ApiKeyStore built by bootstrap from C4. Documented on each side.
[x] Build order (Phase 2B) is a valid DAG — no circular dependencies.
    — C1 → C4 → C11 → C13; C10 unchanged. Acyclic.
[x] Every config value / env var listed with type, default, required flag, and owner component.
    — Phase 2D lists the three changed vars (PYS_OIDC_ISSUER, PYS_OIDC_CLIENT_ID conditional; PYS_OTLP_ENDPOINT) with all columns; states no new env var.
[x] Every spec is self-contained — implementable from its section alone.
    — Each spec duplicates the needed types/refs into Shared Context.
[x] Assumptions register is complete; open questions are truly blocking only.
    — 12 assumptions (AS-1..12); 0 open questions (HLD OQ-SM-2/3 resolved as AS-4/AS-6).
[x] Example I/O provided for every component with non-trivial logic.
    — C1, C4, C11, C13 carry Example blocks; SCHEMA carries fixtures.
[x] Shared types defined once in Phase 2C, referenced by name and duplicated into Shared Context.
    — AuthMode, KeyPlacement, ResolvedCapability, ApiKeyStore in 2C; duplicated into each consuming spec.
[x] Security addressed for every entry point.
    — Each component carries a Security note; the no-key-to-guest invariant is stated in C11 and Phase 4 Auth.
[x] Performance targets stated for every latency-sensitive component.
    — C11 states api_key/none avoid the OBO round-trip; one map lookup + one HTTPS hop.
[x] All specifications use the active locale (en-GB).
    — British spelling throughout (sanitise, authorise, behaviour).
[x] Destructive schema changes surface rollback considerations.
    — No DB. The policy-JSON-schema change is additive/backward-compatible (new enum values + optional fields); rollback = remove api_key/none capabilities (HLD 10-risks Rollout/Rollback).
[x] Every Component, Cross-cutting, and Preamble spec carries a derivedFromHld preamble field.
    — All six phase files and every component/cross-cutting spec carry derivedFromHld: 0.3.0.
[x] No spec body contains an ADR-shaped paragraph; every such trade-off is in HLD 09-decisions.
    — Specs cite ADR-034..039 (already in the HLD); no new ADR-shaped paragraph is authored in the spec.
[x] Every glossary term used in any spec is present in the HLD glossary.
    — server-mode profile, api_key mode, none mode, secretRef, keyPlacement, allowWrite all map to HLD 00-overview glossary rows (see Note 2).
[x] Every spec's derivedFromHld matches the HLD's current revision.
    — HLD current revision 0.3.0; every spec pins 0.3.0.
[x] In folder-form HLDs: every revision bump in README has a matching 99-changelog line.
    — HLD 0.1.0, 0.2.0, 0.2.1, and 0.3.0 each have a changelog line.
```

## Notes (non-blocking)

1. **HLD-architecture clarification (C10) — applied (revision 0.2.1).** The LLD established that **C10 (DownstreamClient) carries no code change** — header/query placement reuses C10's existing `apply` closure and `Params`→query serialisation; the placement is built in C11. HLD `02-architecture.md` was updated (C10 bullet and component diagram) from "*changed*" to "*unchanged*" with a matching `99-changelog.md` line.

2. **Glossary label nuance.** The spec uses the field identifier `allowWrite` as a glossary term; the HLD glossary row is labelled "Write opt-in flag" and carries `allowWrite: true` as its example. The term is present in the HLD; the label differs from the identifier. No action required; flagged for sync-check D-HLD-1 awareness.

3. **Write gate is global — applied (revision 0.3.0).** Reconciled after `make ci`: the read-only-by-default write gate (ADR-039) is enforced in `PolicyEngine` for **every manifest/profile**, not only server-mode. The HLD (ADR-039 amendment plus `00`/`07`/`10` wording) was updated to match the code, the changelog appended, and every spec re-pinned to `derivedFromHld: 0.3.0`.

## Promotion

All blocking checklist items pass; the non-blocking notes (C10 clarification at 0.2.1, glossary label, global write gate at 0.3.0) are applied — HLD and spec are aligned at **0.3.0**. The spec set is eligible for promotion **Draft → Approved**.

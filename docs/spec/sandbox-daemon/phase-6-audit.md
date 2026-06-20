# Phase 6 — Self-Audit (`sandbox-daemon`)

## Checklist

```
[x] Every entity has a complete data model with types and constraints.
        — Phase 2C defines all shared types as Rust structs/enums with serde shape; storage-less components state N/A.
[x] Every action has defined inputs, outputs, numbered steps, and errors.
        — Each component (C1,C3–C14, pysandbox_sdk; C2/C15 in phase-4) carries Public Interface + numbered Internal Logic + Error Table.
[x] No banned phrases remain.
        — Scanned all spec files; the single "as needed" in C13 was reworded to concrete conditions. Remaining "process" usages denote OS processes; "handle" denotes typed handles (SessionHandle/CapabilityHandle).
[x] Every component has ≥3 Gherkin acceptance criteria (happy, edge, error).
        — 44 scenarios across the 14 phase-3 component sections (3–4 each); XC2/XC7 each carry scenarios in phase-4.
[x] Every component has an error table with ≥2 rows.
        — All present; ResponseSanitizer documents two non-error conditions explicitly per the ≥2 rule.
[x] Every cross-component interaction is documented on BOTH sides.
        — Phase 2B dependency column + per-component Dependencies; the run contract (RunRequest/RunResult) and the obo-broker /v1/exchange contract appear in phase-3 (C9/C11/C13/C14) and trace to ../obo-broker/08-interfaces.md.
[x] Build order (Phase 2B) is a valid DAG — no circular dependencies.
        — Verified: C1 → {C2..C10} → C11 → C12 → C13 → C14; C15 → C11. No cycles (phase-2B + phase-5 steps 1–4).
[x] Every config value / env var listed with type, default, required flag, and owner.
        — Phase 2D, 18 PYS_* variables.
[x] Every spec is self-contained — implementable from its section alone.
        — Each component names its File, Dependencies, Public Interface, and the shared types it consumes (defined once in 2C).
[x] Assumptions register complete; open questions are truly blocking only.
        — 21 assumptions (AS-1…21); 1B lists 0 blocking (6 non-blocking: client-auth strength, activation, consent-UI mechanism, multi-client routing, Windows peer-auth, MCP elicitation).
[x] Example I/O provided for every component with non-trivial logic.
        — Each component's Gherkin scenarios supply concrete Given/When/Then example I/O; interface signatures give the typed shapes.
[x] Shared types defined once in Phase 2C, duplicated into Shared Context of consumers.
        — Yes; consumers reference them by name.
[x] Security addressed for every entry point.
        — ControlEndpoint (the sole agent entry) gates on ClientAuth (C6, ADR-024); HealthCheck is local-only/unauthenticated by design; XC1 covers the full auth model; the run entry carries no step-up field (XC9).
[x] Performance targets stated for every latency-sensitive component.
        — The run-path budgets are the Wasmtime limits (fuel/512 MiB/30 s epoch — AS-10/Phase 2D) and the HLD 07 NFRs (carried); the broker/downstream paths are bounded by the per-call timeout; capability handles expire ≤5 min.
[x] All specifications use the active locale (en-GB).
        — sanitise/authorise/-ise spellings throughout.
[x] Destructive schema changes surface rollback considerations.
        — N/A — no relational schema (AS-21); the only persisted artefact is the rotating audit log.
[x] Every Component/Cross-cutting/Preamble spec carries derivedFromHld.
        — All phases + per-component banners at 0.2.0.
[x] No spec body contains an ADR-shaped paragraph.
        — Component "Purpose/Approach" give component-level rationale only; system ADRs remain in HLD 09-decisions (ADR-001…026).
[x] Every glossary term used in any spec is present in the HLD glossary.
        — The terms the LLD uses (Daemon, Client, Connection token, Control endpoint, run entry, Interaction broker/consent UI, Session, capId, Capability manifest, Identity Broker, Sandbox Runtime, pysandbox_sdk, Untrusted-content envelope, obo-broker) are in docs/design/sandbox-daemon/00-overview.md (Control endpoint + run entry promoted this pass — D-HLD-1 clean).
[x] Every spec's derivedFromHld matches the HLD's current revision (0.2.0).
        — Match — all phases pinned 0.2.0 = HLD 0.2.0; no stale phases.
[x] In folder-form HLDs: every revision bump has a 99-changelog line.
        — docs/design/sandbox-daemon/99-changelog.md covers 0.1.0 (fork) → 0.2.0 (glossary promotion).
```

## HLD-impact-pass result

Scanned every Phase 1–5 draft for HLD-shaped findings. **One finding, resolved in-pass:** the LLD uses `Control endpoint` and `run entry` as glossary terms (D-HLD-1) — both promoted to `docs/design/sandbox-daemon/00-overview.md`, HLD bumped 0.1.0 → 0.2.0 with a changelog line, and all spec phases pinned at 0.2.0. **No new ADRs, components, tech-stack members, regulatory obligations, external actors, or principal sequences** beyond the HLD — the 15-component LLD maps onto the HLD's daemon architecture (ADR-023–026) and the carried-over core (ADR-001/002/005/013/014/016–022). The new daemon components (ClientAuth C6, SessionManager C7, ConsentUI C8, ControlEndpoint C14, the OBO/direct split C9/C10) realise HLD `02-architecture` components; no back-edge beyond the glossary was required (no D-HLD-2/4/5/6).

## Result

**PASSED.** All 21 checklist items pass; every component's Gaps section reads `None.`; no blocking Open Questions. Two controls are flagged for **pre-production verification engagements** (not spec gaps): the **SR-24 client-authentication pen test** (ADR-024 — the one new security surface) and the **Wasmtime-escape pen test** (ADR-013, the sole isolation boundary). The spec set is promoted **Draft → Approved** and is ready for `/breakdown`.

## Amendment re-audit — revision 0.3.1 (`/spec` Branch B, 2026-06-13)

An intent change refined the C12 isolation invariant from "no WASI / exactly one host import" to **"exactly one *capability* host import (the broker) + a deny-by-default WASI subset (monotonic clock, randomness, captured stdout/stderr only — no filesystem, sockets, env, or args)"** (HLD ADR-019/ADR-013 amended; rationale in `09-decisions.md` and `99-changelog.md`). Affected LLD: **C12 SandboxRuntime** (purpose + Internal Logic steps 2–4), **AS-10** (isolation contract), and the **Phase-5 Playbook C12 step**; all spec phases re-pinned `derivedFromHld: 0.3.0 → 0.3.1`. **Re-audit verdict: still PASSED** — C12 retains its full Public Interface, Internal Logic, Error Table (`RUNTIME_ARTIFACT_MISMATCH`/`RUNTIME_LIMIT`), Gherkin, and `Gaps: None`; no banned phrases; no new component/actor/ADR beyond the amended ones; the no-ambient-authority / egress-only-via-broker guarantee is preserved (the WASI subset grants no socket/file/process authority). The WASI subset joins the existing Wasmtime-escape pen-test scope (no new verification engagement). **D-HLD checks:** glossary clean (no new term), the ADR change lives in `09-decisions.md` (no hidden ADR — D-HLD-2 clean), pins current at 0.3.1 (D-HLD-3 clean), changelog line present for the 0.3.1 bump (D-HLD-6 clean).

## Amendment re-audit — revision 0.3.2 (`/spec` Branch B, 2026-06-14)

An intent change scoped the daemon's observability for the **per-user dev-machine profile** (new **ADR-027**): the observability is the **audit log (C3, OTLP-exportable, mandatory in real-credential mode)** + **structured redacted logging (XC3, `run_id`-correlated)**; the full **OTel metrics+traces (XC4/XC5)** are **out of scope by default**, optional/off-by-default for fleets (FU-028), honouring the lean single-binary supply chain (ADR-026). This **re-aligns the LLD to the HLD's already-lean stance** (HLD 07 framed metrics as "no separate metrics pipeline" and tracing as "`runId` correlation"). Affected: HLD `09-decisions` (ADR-027) + `07-cross-cutting` rows; LLD `phase-4` **XC4/XC5** reworded to the lean stance; all spec phases re-pinned `0.3.1 → 0.3.2`. **Re-audit verdict: still PASSED** — XC4/XC5 retain `Gaps: None`; no component interface changes; the security-relevant observability (audit non-repudiation, redaction) is fully specified and built. **D-HLD checks:** ADR-027 in `09-decisions` (D-HLD-2 clean), pins current at 0.3.2 (D-HLD-3 clean), changelog line present for the 0.3.2 bump (D-HLD-6 clean), `07-cross-cutting`/`02-architecture`/`09-decisions`/`10-risks` cite ADR-027/the lean stance consistently (D-HLD-5 clean).

## Amendment re-audit — revision 0.4.0 (`/spec` Branch B, 2026-06-14)

An intent change added **production agent-integration + distribution** (HLD ADR-028–031): the **MCP front door** as the `faradayd mcp-stdio` sub-mode (ADR-028), the concrete **browser auth-code + PKCE loopback sign-in** (ADR-029), **always-on OS-service + cross-platform IPC** resolving the Windows peer-auth question (ADR-030), and **per-user service installers, unsigned-now / signable-later** (ADR-031). **LLD changes:** new component **C16 McpFrontDoor** (`src/mcp.rs`); **C14 ControlEndpoint** amended (cross-platform UDS/named-pipe + SID peer-auth; MCP is now C16, not in-endpoint framing); **C8 ConsentUI** sign-in made concrete (loopback, generic OIDC discovery, `state`/`nonce`/PKCE, `id_token` in-daemon only); **XC1** records the `mcp-stdio` client + Windows SID auth; Phase 2 inventory (+C16) and env vars (`PYS_OIDC_CLIENT_ID`/`PYS_OIDC_SCOPES`); Phase 1 **AS-3/AS-5/AS-8** refreshed and **OQ-E (Windows peer-auth) RESOLVED**; Phase 5 **Step 7 (M7)** added; all phases re-pinned `0.3.2 → 0.4.0`.

**Re-audit verdict: PASSED.** Checklist re-verified for the delta:
- **C16 is complete** — File, Dependencies, Purpose, Public Interface (MCP `initialize`/`tools/list`/`tools/call`), numbered Internal Logic, a ≥2-row Error Table, 3 Gherkin scenarios (happy/edge/error), `Gaps: None`.
- **C8/C14 amendments** retain their full interface + Error Table + Gherkin (each gained a scenario: loopback `state`/`nonce` mismatch; Windows SID mismatch) and `Gaps: None`.
- **Security at every entry point** — the new entry point (C16) is an **untrusted client** authenticated by C6 over the same UDS/SID + token boundary (XC1/ADR-024); it holds no tokens; the `id_token` stays in the daemon (ADR-002/010). The new loopback redirect surface is bounded by PKCE/`state`/`nonce`/`127.0.0.1`-only/ephemeral-port; both join the SR-24 client-auth pen-test scope (no net-new pen-test engagement beyond SR-24's existing scope).
- **Build order** — C16 is a separate process connecting to C14 as a client; **no new in-process edge, DAG still acyclic** (leaves → C11 → C12 → C13 → C14).
- **No banned phrases**; **active locale en-GB**; every new env var carries type/default/required/owner (Phase 2D).
- **D-HLD checks:** ADRs 028–031 live in HLD `09-decisions` (no hidden ADR — D-HLD-2 clean); no new glossary term used in the LLD that is absent from HLD `00-overview` (the HLD glossary added MCP front door / loopback sign-in / service installer this pass — D-HLD-1 clean); the new component **C16** appears in both HLD `02-architecture` and Phase 2/3 (no orphan — D-HLD-4 clean); pins current at **0.4.0 = HLD 0.4.0** (D-HLD-3 clean); changelog line present for the 0.4.0 bump (D-HLD-6 clean); siblings consistent (D-HLD-5 clean). **The spec set remains Approved at revision 0.4.0; ready for `/breakdown`.**

## Amendment re-audit — revision 0.4.1 (`/spec` Branch B, 2026-06-17)

An intent change (RFC 01) makes pass-through's "audienced for the provider" premise enforceable: the daemon **requests a per-capability resource `audience` at sign-in** so the IdP issues an access token audienced for the **resource server**, which validates it (new **ADR-033**). **LLD changes:** **C8 ConsentUI** (`SignIn`/`StepUp` add the resource-audience request — Dex cross-client trusted-peer scope, RFC 8707 for generic IdPs; new error row + two Gherkin scenarios); **C13 SandboxController** (collects the run's distinct capability audiences and passes them in `SignIn`/`StepUp`); **Phase 2C** `InteractionRequired::SignIn`/`StepUp` gain `audiences: Vec<String>`; **XC1** records resource-audiencing; **Phase 1** adds **AS-22/AS-23/AS-24** and non-blocking **OQ-G**, plus two glossary terms; **Phase 5** adds **Step 8** (the C8/C13 wiring + the demo validating resource server, example infra per AS-23). All component pins re-pinned `0.4.0 → 0.4.1`.

**Re-audit verdict: PASSED.** Checklist re-verified for the delta:
- **C8/C13 complete** — both retain File, Dependencies, Public Interface, numbered Internal Logic, Error Table (C8 now 4 rows incl. audience-refused→`SIGN_IN_FAILED`; C13 unchanged at 3), Gherkin (C8 +2 scenarios), and `Gaps: None`.
- **No invented identifiers** — `audience` already exists on `ResolvedCapability` (`phase-2-architecture.md`); the Dex `audience:server:client_id:<peer>` scope and RFC 8707 `resource` are named external IdP mechanisms (flagged via OQ-G), not repo symbols; ADR-033 now exists in `09-decisions.md`.
- **Security at every entry point** — unchanged token custody (the `access_token` is still held in-daemon and forwarded by C10/C11; ADR-033 only audiences it correctly). No new entry point. The demo resource server is example infra (AS-23), not a product component, so it adds no faraday attack surface.
- **No banned phrases; active locale en-GB; ≥2 error rows; ≥3 Gherkin per touched component.**
- **No new env var / shared type** beyond the `InteractionRequired` field (Phase 2C), consistent across its three consumers (C8/C13/C14).
- **D-HLD checks:** ADR-033 lives in HLD `09-decisions` (D-HLD-2 clean); the two new glossary terms (resource audience; trusted peer / resource indicator) are in Phase 1 §1C and map to HLD concepts — **D-HLD-1 note:** they are LLD-glossary terms not yet promoted to HLD `00-overview` (promotion deferred; recorded here, no INTENT-DRIFT); no orphan component — the resource server is deliberately out of the product inventory (AS-23, D-HLD-4 N/A); pins current at **0.4.1** (D-HLD-3 clean); **D-HLD-6:** `99-changelog.md` was absent for 0.1.0–0.4.0 (pre-existing gap, now created and started at 0.4.1 with a history note). **The spec set is Approved at revision 0.4.1; ready for `/breakdown`.**

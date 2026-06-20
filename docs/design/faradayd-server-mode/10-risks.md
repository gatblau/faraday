# 10 — Risks, Assumptions, Open Questions, Alternatives, Dependencies, Rollout

> **Revision:** 0.3.0

## Assumptions

| ID | Area | Assumption | Rationale |
|---|---|---|---|
| AS-SM-1 | Topology | The agent runtime and `faradayd` run in the **same container under one UID**. | User decision #5 (single service); makes ADR-024 client-auth hold without change (ADR-034). |
| AS-SM-2 | Secrets | Each `api_key` is delivered as a **mounted secret file** referenced by `secretRef` and resolved via `FileSecretResolver`. | User decision #1; matches the repo's `*_REF` → file convention (ADR-036). |
| AS-SM-3 | Secrets | **One key per endpoint/capability**; no shared-key indirection. | User decisions #1 and #3. |
| AS-SM-4 | Audit | Real-credential `api_key` operation **still requires a reachable OTLP sink**. | sandbox-daemon ADR-016 carried forward unchanged (user decision #6). |
| AS-SM-5 | Egress | HTTPS is the default egress; the loopback-plaintext exception (sandbox-daemon ADR-032) is a dev-only concern, not part of this profile. | Inherited C10 behaviour. |
| AS-SM-6 | Scope | `Exchange` / `Passthrough` and the desktop profile are **unchanged**; this profile only adds modes and a deployment shape. | 00-overview Non-goals. |
| AS-SM-7 | Authorisation | A capability is **read-only by default** in every manifest (all profiles); without the write opt-in flag it may declare only `GET`. | ADR-039. |
| AS-SM-8 | Authorisation | The write opt-in flag is honoured **only in a trusted / administrator-signed manifest** (the signed policy is the pre-grant). | ADR-039, sandbox-daemon ADR-021. |

## Open Questions

| ID | Question | Plain-English | Options | Impact | Blocking? |
|---|---|---|---|---|---|
| OQ-SM-2 | Exact shape of the **key-placement** descriptor (header name + scheme vs query parameter; how the scheme/prefix is encoded). | How is the key attached to the request, in policy terms? | Header-name + scheme template; or a small typed union (header \| query). | Wire schema only; `/spec` resolves it. | No |
| OQ-SM-3 | **Key reload / rotation**: hot-reload on mounted-file change, or restart to pick up a rotated key? | When the operator rotates the key file, does the daemon notice without a restart? | Watch the file and reload; or require restart. | Operational behaviour; no architectural change. | No |

**Resolved** (see [09 — Decisions](./09-decisions.md)): **OQ-SM-1** (headless writes) → ADR-039: per-capability write opt-in, default read-only, honoured only in an admin-signed manifest. **OQ-SM-4** (step-up applicability) → ADR-039: step-up is not applicable in server-mode. **OQ-SM-5** (per-session consent semantics) → ADR-039: consent is a no-op in headless mode; the signed policy is the authorisation of record.

## Risks

- **Static long-lived key exposure.** The key sits in broker memory and a mounted file for the daemon's lifetime; a container compromise exposes it. *Mitigation:* bounded by the key's allowlisted host/path/method scope and call budgets; rotation via mounted-secret rotation; never logged or returned (ADR-018 / SR-18).
- **Containerised Linux runtime path is unexercised.** The base design ships per-OS service installers (ADR-031) and Linux service packaging is planned-not-implemented (ADR-030); a container image is new packaging. *Mitigation:* the binary is portable (Wasmtime + RustPython); treat the container path as build/packaging work and validate the socket/connection-token/runtime-dir plumbing in a Linux container before relying on it.
- **OIDC-optional regression risk.** Making the OIDC config group conditional must not weaken the desktop profile (where it stays mandatory). *Mitigation:* requiredness derives from the manifest's actual capabilities (ADR-038); a mixed manifest still demands OIDC.
- **Over-broad write opt-in.** An administrator could mark too many capabilities writable in the signed manifest. *Mitigation:* read-only is the default (ADR-039), so writes are never granted by omission; the opt-in is only honoured in an admin-signed manifest (ADR-021), and every write is still method/host/path-allowlisted, budgeted, and audited.

## Alternatives considered (system-level)

- **Full multi-tenant server daemon.** Rejected for this profile — per-tenant vault isolation and a network client-auth boundary are a much larger design; the single-tenant, one-daemon-per-agent shape avoids both (ADR-034).
- **Keep OBO and add workload identity for the daemon.** Rejected for single-tenant — OBO's value (privileged token off an untrusted host, away from a human user) does not apply; the broker process is the trust anchor (ADR-035). Recorded as the path to revisit for a multi-tenant or on-behalf-of-user server profile.
- **Raw env-var credentials.** Rejected — file-backed via the existing `SecretResolver` is safer and idiomatic (ADR-036).

## Dependencies

- The existing **sandbox-daemon** design and code: `SecretResolver` / `FileSecretResolver` (`config.rs`), the broker auth-mode routing (`broker.rs`), DownstreamClient (C10), the policy schema (`11-policy-schema.md`, `schema/pysandbox.policy.schema.json`), and the audit sink (ADR-016).
- A **container build / image** for the daemon (new packaging alongside ADR-031 installers).
- A **secret-mounting mechanism** in the deployment (e.g. Kubernetes/Docker secrets) to provide the key files.

## Rollout and Rollback

- **Additive and opt-in.** The two new auth modes are new `authMode` enum values plus optional capability fields (`secretRef`, key placement); existing manifests using `exchange` / `passthrough` are unaffected. The OIDC-optional change only relaxes a previously-mandatory requirement, so existing OIDC deployments are unchanged.
- **Rollout.** Ship the schema additions and broker arms; build the container image; deploy one daemon per agent with mounted key files and an OTLP sink (if real credentials).
- **Rollback.** Remove `api_key`/`none` capabilities from the manifest (calls revert to fail-closed `CAP_UNKNOWN`), and/or stop deploying the server-mode container. No data migration is involved — there is no datastore and the schema change is backward-compatible.

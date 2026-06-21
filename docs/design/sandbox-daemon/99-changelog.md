# HLD changelog (`sandbox-daemon`)

One line per HLD revision bump (folder-form requirement, D-HLD-6).

> **Note on history.** This file was absent for revisions 0.1.0–0.4.0; their bumps are
> recorded in the Phase 6 audit amendments (`../../spec/sandbox-daemon/phase-6-audit.md`)
> and in git history. It is started here at 0.4.1 and maintained going forward.

> **Erratum (2026-06-21, no revision bump).** `05-tech-stack.md`, `02-architecture.md`,
> `10-risks.md`, and ADR-020/ADR-024/ADR-030 (`09-decisions.md`) described the Windows
> named-pipe peer check as `GetNamedPipeClientProcessId`→token-SID. That PID lookup
> has a reuse race and is forbidden for the authz decision by
> `docs/spec/sandbox-daemon/windows-peer-auth.md` §6; corrected in place to
> `ImpersonateNamedPipeClient`→`TokenUser` SID→`EqualSid`, matching the spec and the
> implementation. A prose correction of a security mechanism — the intent (ADR-024 local
> peer-auth boundary) is unchanged — so **no revision bump and no spec `derivedFromHld` re-pin**.

- **0.4.1** (2026-06-17) — ADR-033: resource-audiencing for pass-through. The daemon
  requests a per-capability resource `audience` at sign-in so the IdP issues an access token
  audienced for the resource server, which validates it (RFC 01). No new component; consumes
  the existing `ResolvedCapability.audience`.

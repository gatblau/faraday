# HLD changelog (`sandbox-daemon`)

One line per HLD revision bump (folder-form requirement, D-HLD-6).

> **Note on history.** This file was absent for revisions 0.1.0–0.4.0; their bumps are
> recorded in the Phase 6 audit amendments (`../../spec/sandbox-daemon/phase-6-audit.md`)
> and in git history. It is started here at 0.4.1 and maintained going forward.

- **0.4.1** (2026-06-17) — ADR-033: resource-audiencing for pass-through. The daemon
  requests a per-capability resource `audience` at sign-in so the IdP issues an access token
  audienced for the resource server, which validates it (RFC 01). No new component; consumes
  the existing `ResolvedCapability.audience`.

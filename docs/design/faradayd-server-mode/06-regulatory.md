# 06 — Regulatory and Compliance Context

> **Revision:** 0.3.0

N/A — non-regulated. This profile introduces no new regulatory obligation over the base daemon design (sandbox-daemon 06-regulatory). The existing audit / non-repudiation posture carries forward unchanged and is the only compliance-adjacent control affected.

| Obligation | Source | How the design addresses it |
|---|---|---|
| Authoritative, tamper-evident audit of credentialled calls | sandbox-daemon ADR-016 (carried forward) | Real-credential operation — including `api_key` mode — still requires a reachable OTLP sink, checked fail-closed at startup; absent one, the daemon runs mock-only. `api_key` calls are audited identically to existing modes (sizes + keyed-HMAC user id, never the key — SR-18). |
| Credential confidentiality | sandbox-daemon ADR-002 (extended) | The static key never reaches the guest, the returned envelope, or the audit trail; it lives only in the mounted file and broker-process memory. |

No GDPR / PCI-DSS / sector-specific obligation is introduced by running the daemon server-side or by the two new auth modes. If a specific deployment places the daemon in a regulated environment, that obligation is a deployment concern recorded against that deployment, not a property of this profile.

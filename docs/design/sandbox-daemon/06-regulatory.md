# 06 — Regulatory and Compliance Context

The product is a developer tool and is **not** itself subject to a sector regulation. However, because it holds and transmits authentication tokens and writes an audit log that may contain a user identifier, a small number of data-handling obligations apply. This HLD does not state a jurisdiction or compliance programme; the rows below are the design's own data-protection stances, and the absence of an explicit programme is recorded as a non-blocking open question.

| Obligation | Source | How the design addresses it |
|---|---|---|
| Minimise and protect personal data in logs | General data-protection principle (e.g. GDPR data minimisation) | The audit log stores a **keyed HMAC** of the user identifier, not the raw UPN; bodies and tokens are never logged (sizes only). |
| Do not persist credentials in plaintext | Secret-handling baseline | Tokens live only in process memory and the OS keychain; never written to disk, logged, env-injected, or passed as arguments. |
| Auditability of privileged access | Enterprise security-operations expectation | Append-only per-call audit log with `runId` correlation; SIEM/OTLP export as the tamper-evident system of record, **mandatory in real-credential mode and checked fail-closed at startup (ADR-016)** — no reachable sink ⇒ mock / non-sensitive-credentials-only (supersedes the earlier "configurable" stance). |
| Data residency for downstream tokens | Enterprise expectation | Privileged downstream tokens are held server-side by the backend `obo-broker` service, never on the workstation (ADR-005). |

> **N/A** — No specific named programme (such as PCI-DSS, HIPAA, or IFRS17) is stated in the source. If the daemon is deployed into a regulated enterprise, the applicable programme must be confirmed; this is tracked as a non-blocking open question and is a candidate for the `/spec` HLD-impact-pass to firm up.

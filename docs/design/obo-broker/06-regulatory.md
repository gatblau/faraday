# 06 — Regulatory and Compliance Context

This service holds privileged credentials and exchanged tokens for many users and records an audit trail keyed by a user identifier, so data-protection and token-custody obligations apply more strongly here than in the daemon. The specific enterprise compliance programme is not yet stated and is recorded as a non-blocking open question.

| Obligation | Source | How the design addresses it |
|---|---|---|
| Protect credentials and tokens at rest | Secret-handling baseline | Confidential-client credential held via workload identity / secret store (never on disk plaintext); cached downstream tokens encrypted at rest (AES-256). |
| Encrypt data in transit | Transport-security baseline | TLS 1.3 on every hop (daemon→service, service→IdP, service→cache, service→downstream). |
| Minimise personal data in logs | Data-minimisation principle (e.g. GDPR) | Audit stores a keyed-HMAC user identifier and sizes only — never tokens, bodies, or raw UPNs. |
| Auditability of privileged access | Enterprise security-operations expectation | Append-only per-call audit with `runId` correlation, exported to the SIEM as the tamper-evident system of record. |
| Tenant isolation | Enterprise expectation | Single-tenant per enterprise deployment (ADR-002); no shared cache, credential, or audit across organisations. |
| Token custody / least privilege | OAuth2 / enterprise IAM baseline | Downstream tokens never leave the service; scopes limited to the requested capability's audience; tokens evicted at expiry. |

> **N/A** — No specific named programme (PCI-DSS, HIPAA, IFRS17, or a comparable named regime) is stated. The applicable enterprise programme must be confirmed before production; tracked as a non-blocking open question and a candidate for the `/spec` HLD-impact-pass.

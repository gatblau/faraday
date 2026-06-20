# 05 — Tech Stack

| Layer | Choice | Rationale (one line) |
|---|---|---|
| Language | Go | Best operational fit for a small, security-critical, stateless k8s service: tiny static binary, fast cold start, low memory, memory-safe, lean dependency surface (ADR-010, supersedes the earlier TypeScript choice). |
| Framework / runtime | Go `net/http` with a lightweight router (assumption: chi) + a versioned Provider Plugin SPI realised as Go interfaces; per-provider auth via standard OIDC/OAuth2 libraries (`coreos/go-oidc`, `x/oauth2`) | Lightweight HTTP service; the active plugin (a compiled-in interface implementation) performs the provider-specific exchange. |
| Datastore | Distributed cache (assumption: Redis), values encrypted at rest; no relational database | Token cache only; the service is otherwise stateless (interview decision). |
| Message broker / queue | N/A — synchronous request/response | The service proxies a single call per request; no async messaging. |
| Deployment substrate | Kubernetes (self-managed), container image; confidential-client credential via workload identity / external secret store | Interview decision; horizontal scaling of a stateless service. |
| Observability (logs / metrics / traces) | Structured logs + append-only audit; OpenTelemetry metrics/traces; OTLP export to SIEM | `runId` correlation from the daemon; cache-hit rate and exchange latency as key metrics. |
| Signing / crypto | TLS 1.3 in transit; AES-256-GCM cache encryption at rest via **KMS envelope** (per-entry data keys, ADR-011) behind a **pluggable KeyManager backend** (cloud KMS / Vault transit, selected by `OBO_KMS_PROVIDER`, no default — ADR-018); confidential-client **certificate** preferred over secret | Token custody and at-rest protection of cached downstream tokens; bounded blast radius + rotation; key custody is deployment-agnostic like identity. |
| Build / test toolchain | `go build` + `go test` + `go vet` + `golangci-lint`; container build + image scan | Standard Go toolchain; the broker is a separately operated deployable, not part of the daemon build (ADR-010). |

Assumptions (the chi router, Redis) are recorded in [10 — Risks](./10-risks.md) §Assumptions; alternatives are non-blocking and may be confirmed by the Practice Pack during `/spec`.

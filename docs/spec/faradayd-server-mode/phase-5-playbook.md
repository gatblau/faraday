# Phase 5 — Generation Playbook (`faradayd-server-mode`)

> **Status:** Draft
> **derivedFromHld:** 0.3.0 (`docs/design/faradayd-server-mode/`)

Ordered build checklist for the server-mode delta. Each step cites its Phase 3/4 spec. Build order follows the Phase 2B DAG: C1 → C4 → C11 → C13, with the schema and bootstrap wiring interleaved. C10 has no step (inherited unchanged).

## Step 0 — Scaffolding (shared types)
- [ ] Extend `AuthMode` (`src/types.rs`) with `ApiKey` (`#[serde(rename = "api_key")]`) and `Unauthenticated` (`#[serde(rename = "none")]`). (Phase 2C)
- [ ] Add `KeyPlacement` enum (`Header { name, scheme: Option<String> }` | `Query { param }`) to `src/types.rs`. (Phase 2C)
- [ ] Add `secret_ref: Option<String>`, `key_placement: Option<KeyPlacement>`, `allow_write: bool` to `ResolvedCapability`. (Phase 2C)
- [ ] Add the `ApiKeyStore` trait. (Phase 2C)
- [ ] Add `BrokerError::KeyUnavailable` → `code() == "API_KEY_UNAVAILABLE"`. (Phase 3 C11)

## Step 1 — Config (C1)
- [ ] Change `Config.oidc_issuer` / `oidc_client_id` to `Option<String>`; make `Config::load` read them via `opt` (not `required`), retaining the issuer format check when present. (Phase 3 C1)
- [ ] Add `Config::require_oidc(&self) -> Result<(), ConfigError>`. (Phase 3 C1)
- [ ] Unit tests: key-only load succeeds without OIDC; `require_oidc` returns `CFG_MISSING` when unset; issuer format still rejected when malformed.

## Step 2 — PolicyEngine (C4)
- [ ] Extend `RawCapability` with `secretRef`/`keyPlacement`/`allowWrite`; map into `ResolvedCapability`. (Phase 3 C4)
- [ ] Add the per-capability load validation: api_key⇒secretRef+keyPlacement; secretRef/keyPlacement only on api_key; step-up forbidden on api_key/none; unsafe method⇒allowWrite. All → `CFG_INVALID`. (Phase 3 C4)
- [ ] Add `api_key_secret_refs()` and `has_oidc_capability()`. (Phase 3 C4)
- [ ] Unit tests: one per validation rule (table-driven); unsigned override cannot enable a write (reuses the existing verify-fallback test pattern).

## Step 3 — Policy manifest schema (SCHEMA)
- [ ] Add `authMode` (enum incl. `api_key`/`none`), `secretRef`, `keyPlacement` (oneOf header/query), `allowWrite` to `$defs/capability`. (Phase 3 SCHEMA)
- [ ] Relax base `required` to `["host","pathAllow","methods"]`; add the conditional `allOf` clauses (provider/scopes for exchange/passthrough; secretRef/keyPlacement for api_key; step-up const false for api_key/none; methods GET-only unless allowWrite true; secretRef/keyPlacement forbidden off api_key). (Phase 3 SCHEMA)
- [ ] Schema-validation tests (CI): the three Gherkin fixtures pass/fail as specified.

## Step 4 — IdentityBroker (C11)
- [ ] Add the `Arc<dyn ApiKeyStore>` constructor parameter to `new`/`with_ttl`/`new_with_ttl`. (Phase 3 C11)
- [ ] Add the `AuthMode::ApiKey` arm (header placement via `Credential::Headers` + `apply_credential`; query placement via `params.clone()` + push + no-op apply) and the `AuthMode::Unauthenticated` arm (no-op apply). (Phase 3 C11)
- [ ] Unit tests: header placement sets the configured header; query placement appends the param; `none` sets no Authorization; `KeyUnavailable` when the store misses; the returned envelope and audit entry contain no key.

## Step 5 — SandboxController (C13)
- [ ] Partition resolved capabilities into OIDC / non-OIDC; raise `SignIn`/collect audiences/render consent only for OIDC capabilities; treat api_key/none as pre-granted (no interaction). (Phase 3 C13)
- [ ] Unit tests: all-non-OIDC run raises no SignIn; mixed run still signs in for the OIDC capability; OIDC capability with no renderer fails `INTERACTION_UNAVAILABLE`.

## Step 6 — Bootstrap wiring (daemon `main`)
- [ ] After `Config::load` and `PolicyEngine::load`: call `require_oidc()` iff `has_oidc_capability()`; resolve `api_key_secret_refs()` via `FileSecretResolver` (trim one trailing newline) into the `ApiKeyStore`, failing startup closed on `CFG_SECRET_UNRESOLVED`; pass the store to `IdentityBroker::new`. (Phase 4 Configuration)

## Step 7 — Integration & verification
- [ ] Integration test (`integration` feature, against the existing stub): an `api_key` header capability calls the stub and the stub observes the configured header; a `none` capability calls with no Authorization; a query-placement capability shows the param on the stub.
- [ ] Integration test: a key-only manifest boots with no OIDC env set.
- [ ] Coverage ≥70% on changed modules (`config`, `policy`, `broker`).
- [ ] `cargo build`, `cargo test`, `cargo clippy`, `cargo audit`/`cargo deny` pass (the existing gate).
- [ ] Confirm no new `PYS_*` variable was introduced (keys are referenced by manifest `secretRef`).

## Container packaging (out of this set's build scope)
The OCI image and secret-mount mechanism (HLD `10-risks.md`) are deployment/packaging work, not component code. They are not part of this Playbook's `codegen` steps; track them separately against the HLD risk.

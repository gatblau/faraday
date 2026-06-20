# Phase 5 — Generation Playbook (`sandbox-daemon`)

Ordered build checklist. Build in dependency order (Phase 2B DAG). Each component step consumes its Phase 3 / Phase 4 spec in isolation. All daemon code is **Rust** (ADR-026).

## Step 0 — Scaffolding
- [ ] Cargo workspace `faradayd` (single binary `src/main.rs` + modules per Phase 2B); `cargo`, `clippy`, `rustfmt`; CI runs `cargo build`/`test`/`clippy -D warnings`/`fmt --check`; coverage gate ≥ 70%.
- [ ] Base crates: `tokio`, `serde`/`serde_json`, `wasmtime`, RustPython (WASM guest artefact, pinned + digest), an OIDC/OAuth2 client crate, `reqwest`/`hyper` + `rustls`, an OS-keychain crate, `regex`, `hmac`/`sha2`, OTel SDK + OTLP exporter, a local-socket crate (UDS / named pipe).
- [ ] `cargo audit` + `cargo deny` in CI (ADR-018 dependency gate); pin the RustPython WASM artefact + record its content digest in a committed checksum manifest.
- [ ] Per-OS/arch **signed service-installer** packaging (systemd user unit / launchd agent / Windows service); installer signing (ADR-022/ADR-023).

## Step 1 — Foundations (no deps)
- [ ] **C1 Config** — env load, `*_REF` resolution, fail-closed validation (incl. real-credential-mode OTLP, OBO-endpoint-if-exchange, guest digest set). Unit tests per error-table row.
- [ ] **C2 WireError (XC2)** — envelope + code→status registry + panic-recovery layer. Table-driven tests over the registry.

## Step 2 — Leaf services (depend on Config + externals)
- [ ] **C3 AuditLogger** — keyed-HMAC id, OTLP export, redaction, real-credential-mode fail-closed. Tests: emit-with-hmac/no-token, exporter-down no-fail, startup-without-sink → mock.
- [ ] **C4 PolicyEngine** — manifest load (admin-signed override only), path canonicalisation + traversal rejection, method/host allowlist, step-up requirement, budget. Table-driven tests incl. traversal-escape and unsigned-override-rejected.
- [ ] **C5 ResponseSanitizer** — header allowlist, size cap + truncation flag, untrusted envelope. Tests: under-cap, oversize, auth-header-stripped.
- [ ] **C6 ClientAuth** — connection-token mint, peer-UID check, token compare (constant-time), first-connect consent. Tests: valid-token, wrong-token, wrong-UID, new-label-consent. **Security-critical — covered additionally by the SR-24 pen test.**
- [ ] **C7 SessionManager** — `(client,workspace)` sessions, consent cache, budget. Tests: consent-cached, sessions-isolated, budget-exhausted.
- [ ] **C8 ConsentUI** — `interaction_required` rendering; sign-in is the concrete **browser auth-code + PKCE loopback flow** (ADR-029): generic OIDC discovery, PKCE/`state`/`nonce`, transient `127.0.0.1:<ephemeral>` redirect listener, `id_token` captured in-daemon; native consent dialog; step-up. Tests: consent-approved, sign-in-loopback-captures-token, `state`/`nonce`-mismatch→SIGN_IN_FAILED, step-up-fresh-token, headless→INTERACTION_UNAVAILABLE.
- [ ] **C9 OboClient** — `POST /v1/exchange`, step-up surfacing, never-log-id_token. Tests: happy, step-up-401, backend-down. Mock obo-broker with an httptest server.
- [ ] **C10 DownstreamClient** — no-cross-origin-redirect client, timeout, size-capped read. Tests: happy, 3xx-not-followed, timeout. Use an httptest server.

## Step 3 — Broker + runtime
- [ ] **C11 IdentityBroker** — capability table + `mint_caps`, route to OBO/direct, sanitise, audit; tokens never leave. Tests: exchange-proxied, direct-provider, expired-capId. Wire C5/C9/C10/C3.
- [ ] **C12 SandboxRuntime** — Wasmtime hardened config (ADR-019: deny-by-default WASI subset = clock/random/captured-stdio only), guest digest verify (ADR-018), single **capability** host import → broker shim, fuel/epoch/memory limits, RustPython guest + `pysandbox_sdk`. Tests: guest-calls-api, deadline-terminates, tampered-artefact-fails-closed.

## Step 4 — Orchestration + entry
- [ ] **C13 SandboxController** — the `run` pipeline (resolve/consent/dry-run/sign-in/step-up-retry/mint/execute/redact). Tests: one per Gherkin (happy, dry-run, step-up-declined) + per error-table row.
- [ ] **C14 ControlEndpoint** — cross-platform listener (secure bind): UDS `0600`+peer-UID (Unix) / named pipe + per-user-SID + token-SID check (Windows, ADR-030); connect+auth handshake; native-RPC `run` streaming; `interaction_required` forwarding. (The MCP tool is C16, not in-endpoint.) Tests: authed-run, Windows-SID-mismatch-refused, unauth-refused.
- [ ] **C15 HealthCheck (XC7)** — liveness/readiness over the socket; dep reachability. Tests: ready, liveness-independent, not-ready-lists-dep.
- [ ] Wire `main.rs`: load Config → build audit/policy/sanitiser/obo/downstream → broker → runtime → controller → bind ControlEndpoint behind ClientAuth + SessionManager → register the OS service; init connection token; graceful shutdown (XC10).

## Step 5 — Cross-cutting wiring
- [ ] **XC3 Logging** — JSON logger + redaction layer; `run_id` in task-local context.
- [ ] **XC4 Metrics / XC5 Tracing** — OTel meter/tracer; spans per XC5; OTLP export.
- [ ] **XC8/XC9/XC10** — budgets (via C4/C7), strict input validation, signal-driven graceful shutdown.

## Step 6 — Integration & verification
- [ ] **Integration:** end-to-end over a real UDS — a test client connects (token + peer-UID), runs code that calls a capability against a mock obo-broker + mock downstream; assert: happy path, dry-run (no egress), unauthenticated-refused, traversal-denied, step-up challenge→consent-UI→retry, downstream-timeout.
- [ ] **Security:** assert no token/body/credential/connection-token appears in any response, log, or trace; no cross-origin redirect followed; tampered guest artefact fails closed; **the SR-24 client-auth pen test and the Wasmtime-escape pen test are scheduled before production sign-off.**
- [ ] **Observability:** assert the documented metrics/spans emit; audit records carry `user_hmac` not raw subject.
- [ ] **Lint + coverage:** `cargo clippy -D warnings` + `fmt --check` clean; coverage ≥ 70%; `cargo audit`/`cargo deny` clean.

## Step 7 — Production agent integration & distribution (M7, ADR-028–031)
- [ ] **C16 McpFrontDoor (`faradayd mcp-stdio`)** — MCP JSON-RPC server over stdio; `initialize`/`tools/list` (exactly one tool `python_sandbox`)/`tools/call`; reads the connection-token file; connects to C14 as a client; relays `run`; maps `WireError`→MCP tool error; surfaces `interaction_required`. Tests: tools/list-one-tool, tools/call-relays-no-token, daemon-unavailable→DAEMON_UNAVAILABLE, malformed-input→VAL_ERR.
- [ ] **Interactive sign-in (real surface)** — implement the ADR-029 loopback auth-code+PKCE surface as the production `InteractionSurface`, replacing the headless placeholder (closes FU-015). Integration test against a **Dex** container: daemon opens the (headless-driven) authorize URL, the loopback listener captures the code, the `id_token` lands in the daemon only.
- [ ] **OS-service registration** — launchd user agent (`RunAtLoad`+`KeepAlive`) / Windows per-user service / systemd user unit; the daemon owns the socket + token file; clean error from C16 when the service is down.
- [ ] **Service installers (ADR-031)** — macOS `.pkg`/`.dmg` and Windows `.msi` (WiX) that drop the binary, register the service, and **merge** the MCP client config (`faradayd mcp-stdio`) without clobbering. Signing/notarization (`codesign`+`notarytool`, `signtool`) wired as an **optional, off-by-default** build parameter — unsigned/ad-hoc by default (no certs required).
- [ ] **Local validation harness (not shipped)** — Dex (OIDC) + a dummy REST API as a local service + IntelliJ/Claude Code driving `python_sandbox` through the sandbox to the dummy API. The M7 developer-machine acceptance environment.

## Step 8 — Pass-through resource audiencing + demo validation (RFC 01, ADR-033)
- [ ] **C13 SandboxController** — collect the distinct `audience` values of a run's resolved capabilities and pass them in `InteractionRequired::SignIn`/`StepUp`. Test: run with a pass-through capability that sets `audience` ⇒ `SignIn.audiences` carries it; run with none ⇒ empty.
- [ ] **C8 ConsentUI** — include a resource-audience request in the authorize/token call per `what.audiences` (Dex cross-client trusted-peer scope `audience:server:client_id:<aud>`; RFC 8707 `resource` for generic IdPs). Tests: issued `access_token` carries `aud`==requested; IdP refuses unknown audience ⇒ `SIGN_IN_FAILED`. Extend the Step-7 Dex integration test with a trusted-peer resource client.
- [ ] **Demo validating resource server (`examples/demo/`, not shipped)** — replace/front the stub so it verifies the forwarded Bearer against Dex (OIDC discovery + JWKS; signature, `iss`, `aud`, `exp`) before serving; point the `dummy` capability's `host`/`audience` at it; add the Dex resource client + `trustedPeers: [faradayd]` and the `dummy` capability `audience`. Verification per RFC 01 acceptance criteria 1–9 (valid⇒200; missing/malformed/bad-sig/expired/wrong-iss/wrong-aud⇒401), as an `examples/demo` test or documented `curl` matrix.
- [ ] **Docs** — update `get-started.md` / `examples/demo/README.md` (RFC 01 AC 10): the downstream service validates the token; remove the "returns fixed JSON regardless" caveat.

## Notes
- Greenfield playbook — no remediation/continuity split, except Step 7 (M7) which is the production agent-integration + distribution layer added in HLD 0.4.0 (ADR-028–031). **Step 8** is the RFC-01 change-lane addition (ADR-033): faraday consumes the existing per-capability `audience` at sign-in, and the demo gains a token-validating resource server (example infra, not a product component — AS-23).
- **C16 is a separate process** (the `mcp-stdio` sub-mode of the same binary) connecting to C14 as a client — not an in-process dependency; build/test it after C14.
- The `run` contract (`RunRequest`/`RunResult`) is the agent↔daemon boundary; the `obo-broker` `/v1/exchange` contract must match `../obo-broker/08-interfaces.md` — verify both sides.
- The Runtime may be built in-process (default) or as a child process (AS-2) without changing component contracts.

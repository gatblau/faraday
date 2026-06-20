# 03 — Principal Sequences

> **Revision:** 0.3.0

## Sequence: server-mode `api_key` call (golden path)

```mermaid
sequenceDiagram
  participant Agent as Agent runtime (same UID)
  participant Front as Front door (C7/C16)
  participant Ctl as Controller (C13)
  participant Guest as WASM guest (RustPython)
  participant Broker as Identity Broker (C11)
  participant Cfg as Config (C1)
  participant Down as DownstreamClient (C10)
  participant API as API-keyed service

  Agent->>Front: run(code, requestedCapabilities)
  Front->>Ctl: dispatch run (UID + connection token checked)
  Note over Ctl: resolved caps are all api_key / none →<br/>no InteractionRequired::SignIn, no audiences
  Ctl->>Broker: mint capIds
  Ctl->>Guest: load + execute code
  Guest->>Broker: {capId, verb, path}
  Broker->>Broker: resolve capId → cap (authMode=api_key)
  Broker->>Cfg: resolve secretRef (file, FileSecretResolver)
  Cfg-->>Broker: key bytes
  Broker->>Down: outbound request + key per placement
  Down->>API: HTTPS (header/scheme or query param)
  API-->>Down: response
  Down-->>Broker: response
  Broker->>Broker: sanitise → typed untrusted envelope (key never serialised)
  Broker-->>Guest: sanitised JSON
  Guest-->>Ctl: run result
  Ctl-->>Agent: result
```

- **Trigger:** the agent submits `run(...)` whose requested capabilities resolve only to `api_key` / `none` modes.
- **Result:** the outbound call is made with the static key attached per the capability's placement; the guest receives only sanitised JSON; no human interaction occurs.
- **Error posture:** unknown capability → fail closed (`CAP_UNKNOWN`, existing); off-allowlist host/path/method → fail closed (existing); unresolvable `secretRef` → fail closed at resolve time (existing `CFG_SECRET_UNRESOLVED` shape; exact code in `/spec`); downstream unavailable → typed error to guest (existing). The key is never placed in an error, log line, or returned envelope.

## Sequence: server-mode `none` (public) call

```mermaid
sequenceDiagram
  participant Guest as WASM guest
  participant Broker as Identity Broker (C11)
  participant Down as DownstreamClient (C10)
  participant API as Public API

  Guest->>Broker: {capId, verb, path}
  Broker->>Broker: resolve capId → cap (authMode=none)
  Note over Broker: no credential resolution, no audience, no sign-in
  Broker->>Down: outbound request (no Authorization)
  Down->>API: HTTPS (no credential)
  API-->>Down: response
  Down-->>Broker: response
  Broker-->>Guest: sanitised untrusted envelope
```

- **Trigger:** the guest calls a `none` capability (e.g. a public dataset).
- **Result:** the call is made with no credential; the response is sanitised and returned. The allowlist (host/path/method), budgets, and audit still apply — `none` is *not* "any call".
- **Error posture:** identical to the golden path, minus credential resolution.

## Sequence: startup with no OIDC-backed capability

```mermaid
sequenceDiagram
  participant Svc as OS / container runtime
  participant Cfg as Config (C1)
  participant Daemon as faradayd

  Svc->>Daemon: start (server-mode)
  Daemon->>Cfg: load(env, FileSecretResolver)
  Cfg->>Cfg: parse policy manifest
  alt manifest has no OIDC-backed capability
    Cfg->>Cfg: OIDC issuer + client id NOT required (ADR-038)
    Cfg->>Cfg: resolve per-capability key refs (api_key caps)
  else manifest has an OIDC-backed capability
    Cfg->>Cfg: OIDC config group required (existing behaviour)
  end
  Cfg-->>Daemon: Config (fail closed on any missing required value)
  Daemon-->>Svc: ready (no browser, no loopback listener bound for sign-in)
```

- **Trigger:** the container starts the daemon.
- **Result:** the daemon is ready to serve `api_key`/`none` runs with no OIDC configured. If real `api_key` credentials are in use, the ADR-016 OTLP-sink requirement is still enforced fail-closed at startup.
- **Error posture:** a missing required value (policy path, an `api_key` capability's `secretRef`, or the OTLP sink in real-credential mode) fails startup closed — the daemon does not start in a degraded-but-serving state.

# Configuring faradayd

This is the configuration reference for `faradayd`, the sandbox daemon. It explains every
setting you can change, what each one is for, when you would change it, and what to write.

If you just want to see the thing run, read [the get-started guide](sandbox-daemon/get-started.md)
first — it installs a working demo in a few minutes. This document is the level below that:
the full set of knobs, for when you want to point faraday at your own systems.

Everything here is verified against the current code. Where a feature is designed but not yet
wired up, it says so plainly.

---

## The two things you configure

faraday has exactly two configuration surfaces. Keep them straight and the rest follows.

1. **Environment variables** — *how the daemon runs.* Where it listens, how big a response it
   will return, how long a snippet may run, where to find the other two files. On macOS these
   are written into the launchd file that starts the service.

2. **The policy file** (a JSON file, by default `pysandbox.policy.json`) — *what the code is
   allowed to reach.* This is the allowlist. It names each system the sandbox may call, which
   paths and methods are permitted on it, and how faraday should authenticate to it.

A short way to remember it: **environment variables shape the daemon; the policy file shapes
what the daemon will let through.** The policy file is the security boundary — the sandbox can
only reach what is listed in it.

---

## How a call actually flows

This is the whole system in one picture, so the settings later have somewhere to hang.

1. Your AI agent sends a snippet of Python plus a list of capability names it wants to use
   (`requestedCapabilities`) to the daemon, over MCP.
2. The snippet runs in a **WebAssembly sandbox** with no network and no files. The only thing
   it can do to reach the outside world is call `api.<name>.get('/path')` (or `.post`,
   `.patch`, `.delete`).
3. That call goes to the **broker** — the part of the daemon that holds credentials. The
   broker checks the call against the policy file: is `<name>` an allowed capability? Is this
   path and method permitted on it?
4. If allowed, the broker makes the real call to the system, attaching whatever credential the
   capability's `authMode` says to attach (or none).
5. The broker returns only the response data to the sandbox. The credential never enters the
   sandbox and is never logged.

So a capability in the policy file answers four questions: **which host**, **which paths and
methods**, **how to authenticate**, and **may it write**.

---

## The four ways a capability can authenticate

This is the core of the configuration, so it comes first. Every capability in the policy file
has an `authMode`. There are four, and which one you pick depends entirely on what the target
system expects.

| `authMode` | The call carries… | Needs a user sign-in? | Use it when… |
|---|---|---|---|
| `none` | nothing | No | the API is public / needs no auth |
| `api_key` | a static API key you hold | No | the system uses a fixed API key or token |
| `passthrough` | the user's own sign-in token | Yes | the system trusts your company's single sign-on |
| `exchange` | a token minted by the OBO broker | Yes | a privileged system needs a swapped-in token |

`exchange` is the default if you do not set `authMode` (it matches the original design where
every call is brokered). For most real setups you will pick one of the others deliberately.

### `none` — no authentication

**What it is.** The broker makes the call with no credential attached at all. The request is
still bound by the host/path/method allowlist, the budgets, and the audit log — `none` removes
the credential, not the controls.

**Why you'd use it.** Plenty of useful APIs need no login: reference data, public datasets,
status pages, currency rates, that sort of thing. There is no token to hold, so faraday does
not open a browser and the user is never prompted. This is the simplest possible capability.

**What it needs.** Just `host`, `pathAllow`, and `methods`. No `provider`, no secret.

**Example** — the Cat Facts API used in the get-started demo:

```json
"catfacts": {
  "authMode": "none",
  "host": "catfact.ninja",
  "pathAllow": ["^/fact$"],
  "methods": ["GET"]
}
```

The agent then runs `print(api.catfacts.get('/fact').decode())` and gets data back, with no
sign-in step.

**Gotchas.** The host is real and public, so the call goes over HTTPS and needs internet
access. (faraday always uses HTTPS for any host that is not the literal `127.0.0.1`.)

### `api_key` — a static API key

**What it is.** Many services authenticate with a long-lived API key or token that you paste
into a header or a query parameter. With `api_key`, you tell faraday where the key file is and
how to attach it; the broker reads the key once at startup, holds it, and adds it to every
outbound call for that capability. The key never reaches the sandbox and is never written to
the audit log.

**Why you'd use it.** It is the most common way to talk to a third-party SaaS API that is not
wired into your company sign-in. The agent gets to use the service without ever seeing the key.

**What it needs.** Two extra fields beyond the basics:

- `secretRef` — a **file path** to the key. The broker reads the bytes of that file (trimming
  one trailing newline) and uses them as the key. Keep the file readable only by the daemon's
  user.
- `keyPlacement` — *where in the request* faraday should put the key. A key only works if it
  lands where the service expects to read it, and different services expect different places.
  This field is how you tell faraday which one. There are two choices.

  **In a header** (most common). You give the header's name:

  ```json
  "keyPlacement": { "header": { "name": "X-API-Key" } }
  ```

  faraday then sends the header `X-API-Key: <your key>`.

  Some APIs want a word in front of the key — a "scheme", most often `Bearer`. Add `scheme` and
  faraday puts it before the key, separated by a space:

  ```json
  "keyPlacement": { "header": { "name": "Authorization", "scheme": "Bearer" } }
  ```

  faraday sends `Authorization: Bearer <your key>`. Leave `scheme` out and it would send
  `Authorization: <your key>` with no prefix.

  **In the URL query string.** Some APIs read the key from a query parameter instead. You give
  the parameter's name:

  ```json
  "keyPlacement": { "query": { "param": "appid" } }
  ```

  faraday appends `?appid=<your key>` to the call.

  How do you know which to use? Read the target API's own documentation. It will say something
  like "send your key in the `X-API-Key` header" or "add `?appid=YOUR_KEY` to the URL" — copy
  that into the matching shape above. `<your key>` above always means the contents of the
  `secretRef` file; you never write the key itself into the policy.

**Example** — a service that wants a bearer token in the `Authorization` header:

```json
"tickets": {
  "authMode": "api_key",
  "host": "api.example.com",
  "pathAllow": ["^/v2/issues(/.*)?$"],
  "methods": ["GET", "POST"],
  "allowWrite": true,
  "secretRef": "/Users/you/.config/faradayd/example-api.key",
  "keyPlacement": { "header": { "name": "Authorization", "scheme": "Bearer" } }
}
```

**Example** — a service that wants the key in the URL:

```json
"weather": {
  "authMode": "api_key",
  "host": "api.weather.example",
  "pathAllow": ["^/forecast$"],
  "methods": ["GET"],
  "secretRef": "/Users/you/.config/faradayd/weather.key",
  "keyPlacement": { "query": { "param": "appid" } }
}
```

**Gotchas.**

- `secretRef` and `keyPlacement` are **only** valid on an `api_key` capability. Put them on any
  other mode and the daemon refuses to start.
- If the key file cannot be read at startup, the daemon fails to start (it will not run with a
  half-configured key). The error is `CFG_SECRET_UNRESOLVED`.
- The key is read once, at startup. If you rotate the key file, restart the daemon.

### `passthrough` — the user's own sign-in token

**What it is.** The broker forwards the *user's own* sign-in (OIDC) access token straight to
the target system as a `Bearer` header. faraday holds the token only long enough to attach it;
it never goes into the sandbox.

**Why you'd use it.** When the target system already trusts your company's single sign-on and
will accept the same token the user signed in with. No separate key to manage — the user's
existing identity is the credential.

**What it needs.**

- A user sign-in. Because this mode uses the user's token, the daemon must be configured with
  an OIDC issuer and client (`PYS_OIDC_ISSUER`, `PYS_OIDC_CLIENT_ID` — see the env section).
  The first call triggers a browser sign-in.
- A `provider` string. This names the provider the capability belongs to; it is required for
  `passthrough` (and `exchange`).

**Example:**

```json
"wiki": {
  "authMode": "passthrough",
  "provider": "internal-sso",
  "host": "wiki.corp.example",
  "pathAllow": ["^/api/pages(/.*)?$"],
  "methods": ["GET"]
}
```

**Gotchas.** Forwarding a real user token to a system is only safe when that system is in the
same trust domain as the sign-in. The design treats `passthrough` as something an administrator
signs off on, not something to sprinkle around. Only use it for systems that are meant to
accept the IdP's token directly.

### `exchange` — a token swapped by the OBO broker

**What it is.** The default mode. Instead of sending the user's token, the daemon sends it to a
separate **OBO broker** service, which swaps it ("on behalf of" the user) for a different,
usually more privileged, downstream token and makes the call. The privileged token never
touches the laptop.

**Why you'd use it.** For sensitive systems where you do not want even the user's own token to
be the thing presented — you want a scoped, swapped token minted somewhere safer.

**What it needs.** `provider`, plus a user sign-in (as with `passthrough`), plus
`PYS_OBO_ENDPOINT` pointing at the OBO broker service. Optionally `audience` and `scopes` to
shape the swapped token.

```json
"payments": {
  "authMode": "exchange",
  "provider": "payments-api",
  "audience": "https://payments.corp.example",
  "scopes": ["payments.read"],
  "host": "payments.corp.example",
  "pathAllow": ["^/v1/transactions(/.*)?$"],
  "methods": ["GET"]
}
```

> **Not usable end-to-end yet.** The OBO broker is currently design-only — there is no running
> service in this repository to exchange tokens against (see the project README). You can
> declare an `exchange` capability and the daemon will load it, but the call will fail until an
> OBO broker is deployed and `PYS_OBO_ENDPOINT` points at it. For working setups today, use
> `none`, `api_key`, or `passthrough`.

---

## The policy file, field by field

The policy file is JSON. It has one top-level key, `capabilities`, mapping each capability name
to its definition:

```json
{
  "capabilities": {
    "<name>": { ...fields... },
    "<name>": { ...fields... }
  }
}
```

The `<name>` is what the agent uses in code (`api.<name>.get(...)`) and lists in
`requestedCapabilities`. Pick short, clear names.

Each capability supports these fields:

| Field | Required? | Default | What it does |
|---|---|---|---|
| `host` | **Yes** | — | The host to call, as `host` or `host:port`. **No scheme** — do not write `https://`. The scheme is chosen by faraday (always HTTPS, except plaintext to `127.0.0.1` when that dev toggle is on). |
| `pathAllow` | **Yes** | — | A list of **anchored regular expressions**. A call is allowed only if its path matches one of them. This is how you stop a capability from reaching every endpoint on a host. |
| `methods` | **Yes** | — | The HTTP methods allowed, e.g. `["GET"]` or `["GET", "POST"]`. |
| `authMode` | No | `exchange` | One of `none`, `api_key`, `passthrough`, `exchange` (see above). |
| `provider` | For `exchange`/`passthrough` | `""` | Names the provider this capability belongs to. Required for the two token modes; ignored for `none`/`api_key`. |
| `allowWrite` | No | `false` | Must be `true` to allow any state-changing method (`POST`, `PUT`, `PATCH`, `DELETE`). Without it, a capability is read-only even if you list `POST` in `methods` — the daemon refuses to start. |
| `secretRef` | For `api_key` | — | File path to the API key. Only valid for `api_key`. |
| `keyPlacement` | For `api_key` | — | How to attach the key: `{"header": {"name": "...", "scheme": "..."}}` or `{"query": {"param": "..."}}`. Only valid for `api_key`. |
| `audience` | No | — | For `exchange`: the audience of the swapped token. |
| `scopes` | No | `[]` | For `exchange`: the scopes to request on the swapped token. |
| `requireStepUpAuth` | No | `false` | For `exchange`/`passthrough`: demand a stronger sign-in (step-up) for this capability. Not allowed on `none`/`api_key` (there is no sign-in to step up). |

### A note on `pathAllow`

The patterns are real regular expressions, matched against the request path. Anchor them with
`^` and `$` so a pattern cannot match more than you intend.

- `["^/fact$"]` — allows exactly `/fact`, nothing else.
- `["^/v2/issues(/.*)?$"]` — allows `/v2/issues` and anything beneath it.
- `["^/json$", "^/get$"]` — allows two specific paths.

Without anchors, `"/users"` would also match `/admin/users/delete` — which is exactly the kind
of over-permission this field exists to prevent. **Anchor everything.**

### A note on `allowWrite`

Listing `POST` in `methods` is not enough on its own — you also need `allowWrite: true`. This
is a deliberate two-step: it is easy to add a method by reflex, so the daemon makes you opt in
again before it will let the sandbox change anything. If you only ever read from a system, omit
`allowWrite` and use `["GET"]`.

---

## Environment variables, grouped by why you'd touch them

These control the daemon itself. On the macOS demo, `make install` writes a handful of them
into the launchd file; everything else takes its default. To change one, edit the launchd file
(`~/Library/LaunchAgents/dev.faraday.faradayd.plist`) and restart the service, or set it
however your platform launches the daemon.

### The three you must set

The daemon will not start without these.

| Variable | What to put | Why it exists |
|---|---|---|
| `PYS_POLICY_PATH` | Path to your policy JSON file | This is the allowlist. No policy, no daemon. |
| `PYS_GUEST_ARTIFACT_DIGEST` | The SHA-256 of the sandbox guest | The daemon refuses to load a sandbox runtime whose digest does not match — so a tampered guest fails closed. The value comes from `CHECKSUMS.txt`. |
| `PYS_AUDIT_HMAC_KEY_REF` | Path to a 32-byte key file | The key that signs the tamper-evident audit log. `make install` generates one for you the first time. |

### Sign-in (OIDC) — only if you use `passthrough` or `exchange`

If every capability is `none` or `api_key`, leave all of these unset — the daemon needs no
sign-in and starts without them. The moment one capability is `passthrough` or `exchange`, the
first two below become required (the daemon checks this at startup and tells you which is
missing).

| Variable | Default | What it does |
|---|---|---|
| `PYS_OIDC_ISSUER` | unset | Your sign-in provider's URL. Must be `https://…`, except a local `http://127.0.0.1…` or `http://localhost…` for the demo. |
| `PYS_OIDC_CLIENT_ID` | unset | The public client id registered with that provider. No client secret is used — the sign-in is a browser (PKCE) flow. |
| `PYS_OIDC_SCOPES` | `openid profile email` | The scopes asked for at sign-in. |
| `PYS_OBO_ENDPOINT` | unset | The OBO broker's URL. Needed for `exchange` (which, as noted, has no running broker yet). |

### Limits and safety — sensible defaults, tighten as you like

| Variable | Default | What it does |
|---|---|---|
| `PYS_MAX_CALLS_PER_RUN` | `50` | How many brokered calls a single snippet may make. Minimum 1. Stops a runaway loop from hammering a system. |
| `PYS_MAX_CALLS_PER_SESSION` | `500` | The same cap across a whole session. Must be at least `PYS_MAX_CALLS_PER_RUN`. |
| `PYS_RESPONSE_MAX_BYTES` | `1048576` (1 MiB) | The most data one call may return to the sandbox. You can only **lower** this — 1 MiB is the hard ceiling. Keeps a huge response from blowing up the sandbox's memory. |
| `PYS_WASM_DEADLINE_SECONDS` | `30` | Wall-clock limit for one snippet. After this it is stopped. |
| `PYS_WASM_MAX_MEMORY_BYTES` | `536870912` (512 MiB) | Memory ceiling for the sandbox. |
| `PYS_WASM_FUEL` | unlimited | An optional instruction budget (a second, finer limit on top of the deadline). Leave unset unless you specifically want to cap CPU work. |
| `PYS_REQUIRE_FIRST_CONNECT_CONSENT` | `true` | When `true`, a newly-connecting client must be approved before it can run anything. Set `false` for a fully headless server where no human is present to approve. |
| `PYS_CONSENT_UI_MODE` | `auto` | How the consent prompt is shown: `browser`, `dialog`, or `auto` (let faraday choose). The native dialog is implemented on macOS only today. |

### The dev-only one — leave it off in production

| Variable | Default | What it does |
|---|---|---|
| `PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS` | `false` | When `true`, the broker may call `127.0.0.1` over plain `http` instead of HTTPS. This is **only** for local demos where a stub service speaks plain HTTP. It can never downgrade a remote host — `127.0.0.1` and nothing else. The demo turns this on; production leaves it off and stays HTTPS-only. |

### Observability and housekeeping

| Variable | Default | What it does |
|---|---|---|
| `PYS_OTLP_ENDPOINT` | unset | Where to export traces and metrics (OpenTelemetry). Setting it also marks the daemon as "real-credential mode" (the design requires an audit/telemetry sink before real credentials are used); leaving it unset keeps the daemon in mock-only mode. The broader real-credential gating is still being built, so today this mainly controls where telemetry goes. |
| `PYS_LOG_LEVEL` | `info` | Log verbosity. |
| `PYS_SOCKET_PATH` | `$XDG_RUNTIME_DIR/faradayd.sock` (or a temp dir) | The Unix socket the daemon listens on. Change it only if the default location does not suit your setup. |
| `PYS_CONNECTION_TOKEN_PATH` | `$XDG_RUNTIME_DIR/faradayd.token` | Where the per-run connection token is written. The MCP bridge reads it to authenticate to the daemon. |
| `PYS_ADMIN_SIGNING_KEY_REF` | unset | Reserved. The design allows a per-workspace policy override that is honoured only if admin-signed; that override path is not active in this build, so this value is read but currently unused. The daemon always loads the policy at `PYS_POLICY_PATH` directly. |

---

## How the agent calls a capability

You configure capabilities; the agent uses them. For reference, the sandbox exposes each
allowed capability as `api.<name>` with four methods:

```python
api.<name>.get('/path')
api.<name>.post('/path')
api.<name>.patch('/path')
api.<name>.delete('/path')
```

Each takes a path and returns the response **bytes** — call `.decode()` to get text. The agent
must also list the names it uses in `requestedCapabilities` when it calls the `python_sandbox`
tool. A name that is not in the policy file, a path that no `pathAllow` pattern matches, or a
method not in `methods`, is refused by the broker before any real call is made.

There is also a **dry-run**: the tool accepts `dryRun: true`, which plans the calls a snippet
would make without executing them. Useful for checking that a snippet's intended calls are all
within the allowlist.

---

## Common setups (recipes)

Each of these is a complete, working shape. Pick the one closest to what you need.

### 1. The local demo (what `make install` gives you)

A `passthrough` capability against a local stub, with a local sign-in (Dex), plus the `none`
capability for a public API. Plaintext egress is on so the stub can speak plain HTTP. You do
not assemble this by hand — `make install` wires it. It is the reference for "all the pieces
present at once." See the get-started guide.

### 2. A public, no-auth API

The simplest real setup. One `none` capability, no sign-in, no secrets:

```json
{ "capabilities": {
  "facts": { "authMode": "none", "host": "catfact.ninja",
             "pathAllow": ["^/fact$"], "methods": ["GET"] }
} }
```

No OIDC variables needed. The daemon starts with just the three required variables.

### 3. A SaaS API behind an API key

One `api_key` capability. Put the key in a file readable only by you, point `secretRef` at it,
and choose `keyPlacement`:

```json
{ "capabilities": {
  "github": {
    "authMode": "api_key",
    "host": "api.github.com",
    "pathAllow": ["^/repos/[^/]+/[^/]+/issues(/.*)?$"],
    "methods": ["GET", "POST"],
    "allowWrite": true,
    "secretRef": "/Users/you/.config/faradayd/github.token",
    "keyPlacement": { "header": { "name": "Authorization", "scheme": "Bearer" } }
  }
} }
```

Still no sign-in needed — `api_key` is headless. Just the three required variables plus the key
file.

### 4. A company system behind single sign-on

One `passthrough` capability, plus OIDC configured so the user can sign in:

- Policy: a `passthrough` capability with a `provider` (recipe in the `passthrough` section).
- Environment: set `PYS_OIDC_ISSUER` and `PYS_OIDC_CLIENT_ID` to your real provider. The first
  call opens a browser sign-in; the token is forwarded to the system.

### 5. Read-only vs read-write

By default a capability is read-only. To let the agent change something, list the write method
**and** set `allowWrite`:

```json
"notes": {
  "authMode": "api_key",
  "host": "api.example.com",
  "pathAllow": ["^/notes(/.*)?$"],
  "methods": ["GET", "POST", "DELETE"],
  "allowWrite": true,
  "secretRef": "/Users/you/.config/faradayd/notes.key",
  "keyPlacement": { "header": { "name": "X-API-Key" } }
}
```

If you forget `allowWrite`, the daemon refuses to start and tells you an unsafe method needs
it — a deliberate nudge, not a bug.

### 6. Hardening for production

Starting from the demo, the changes that matter:

- **Turn off plaintext egress.** Remove `PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS` (or set it
  `false`). Every capability `host` must then be a real HTTPS host.
- **Use a real sign-in.** Point `PYS_OIDC_ISSUER` / `PYS_OIDC_CLIENT_ID` at your real provider,
  not local Dex.
- **Send telemetry somewhere.** Set `PYS_OTLP_ENDPOINT`.
- **Tighten the limits** if your workloads are smaller than the defaults — lower
  `PYS_MAX_CALLS_PER_RUN`, `PYS_RESPONSE_MAX_BYTES`, `PYS_WASM_DEADLINE_SECONDS` to fit.
- **Keep `pathAllow` narrow.** This is the single most important habit: a host-wide allow is a
  host-wide permission.

---

## Applying a change

Configuration is read at startup. After editing either the environment or the policy file,
restart the daemon so it re-reads them.

On the macOS demo:

```
launchctl bootout  gui/$(id -u)/dev.faraday.faradayd
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.faraday.faradayd.plist
```

Then check it came back cleanly:

```
launchctl list | grep faraday      # middle column 0 = started cleanly
tail ~/Library/Logs/faradayd.err.log
```

---

## When startup fails: the config error codes

If the daemon will not start, it prints one of these. They name the exact thing that is wrong.

| Code | Means | Common cause |
|---|---|---|
| `CFG_MISSING` | A required variable is unset | `PYS_POLICY_PATH`, `PYS_GUEST_ARTIFACT_DIGEST`, or `PYS_AUDIT_HMAC_KEY_REF` not set; or an OIDC variable missing while a `passthrough`/`exchange` capability is present. The message names the variable. |
| `CFG_INVALID` | A value is malformed, or the policy breaks a rule | A bad issuer scheme; a response-bytes value over 1 MiB; or a policy problem — a `pathAllow` regex that does not compile, a `passthrough`/`exchange` capability with no `provider`, `secretRef`/`keyPlacement` on a non-`api_key` capability, an `api_key` capability missing them, `requireStepUpAuth` on a `none`/`api_key` capability, or a write method without `allowWrite`. |
| `CFG_SECRET_UNRESOLVED` | A file reference could not be read | The audit-key file or an `api_key` `secretRef` file is missing or unreadable by the daemon's user. |

The daemon fails **closed**: a configuration mistake stops it rather than letting it run in a
half-configured, possibly unsafe state.

---

## What is not wired up yet

So you are not surprised, and do not spend time on something that cannot work today:

- **`exchange` mode** has no running OBO broker to exchange tokens against. Declare it if you
  like, but calls will fail until a broker is deployed. Use `none`, `api_key`, or `passthrough`
  for working setups.
- **The admin-signed policy override** (`PYS_ADMIN_SIGNING_KEY_REF`) is read but its override
  path is dormant in this build; the policy at `PYS_POLICY_PATH` is loaded directly.
- **Real-credential mode** is marked by `PYS_OTLP_ENDPOINT` but the broader gating around it is
  still being built; today the daemon is effectively mock-aware rather than enforcing a full
  real-vs-mock split.
- **Consent dialogs** are implemented on macOS only. On other platforms the consent surface
  fails closed rather than prompting.
- **Installers** exist for macOS (launchd) only; Linux (systemd) and Windows are planned.

---

## See also

- [Get-started guide](sandbox-daemon/get-started.md) — install the demo and make your first
  call.
- [Project README](README.md) — what faraday is and why it is shaped this way.
- `sandbox-daemon/examples/demo/pysandbox.policy.json` — a working policy file to copy from.

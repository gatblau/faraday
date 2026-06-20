# 12 — Authoring Guide: building taxonomy-compatible assets with Gen AI

This guide is for **content developers** who author `pysandbox.policy.json` capability manifests — the *assets* of the policy *taxonomy* defined in [11 — Policy Schema](./11-policy-schema.md). It explains how to produce a valid, safe asset, and how to do so reliably with a Gen-AI assistant (an LLM) in the loop. A manifest is a security artefact: it is the authorisation boundary for agent-authored code, so "it validates" is necessary but **not** sufficient — it must also be least-privilege.

## 1. What you are building

- **The taxonomy** is the capability schema: a capability = `provider` + `host` + `pathAllow` + `methods` (+ advisory `scopes`, conditional `audience`, optional `requireStepUpAuth`).
- **A compatible asset** is a `pysandbox.policy.json` (or a fragment of its `capabilities` map) that (a) validates against [`./schema/pysandbox.policy.schema.json`](./schema/pysandbox.policy.schema.json) and (b) satisfies the broker-enforced rules in [11 §Rules the schema cannot express](./11-policy-schema.md).
- An asset is *consumed twice*: the daemon's Identity Broker enforces it on the workstation, and `obo-broker` enforces a derived copy server-side. Both validate fail-closed.

## 2. The non-negotiable rules

Author every capability to these rules. The first four are security; the rest are correctness.

1. **One host, no wildcards.** `host` is a single hostname. Never `*`, never a suffix pattern.
2. **Anchored, narrow `pathAllow`.** Every regex is anchored (`^…$` or `^…/.*`) and matches the **canonicalised** path. `".*"`, `"^/.*"`, or an unanchored fragment is a privilege-escalation hazard and must never appear. Prefer the tightest pattern that covers the real calls.
3. **Least method, and step-up on outward writes.** Grant only the methods actually used. If any write method (`POST`/`PATCH`/`PUT`/`DELETE`) is present on a sensitive host, set `requireStepUpAuth: true`. **A write capability whose sink is readable beyond the enterprise** (a public issue tracker, an externally visible ticket queue, any host that can echo data back to an outside reader) MUST set `requireStepUpAuth: true` — no judgement call. This is the control against *cross-capability exfiltration*: prompt-injected code that reads via one allowlisted capability and writes out via another. Both calls are in-policy, so the allowlist alone does not stop it; the human-in-the-loop step-up does (SR-27).
4. **`scopes` are advisory — do not lean on them.** They document intent; they do not constrain the token. The real boundary is host + path + method.
5. **`audience` for token-exchange providers.** Required for `provider: "rfc8693"` (and any other token-exchange plugin); omit for `github`.
6. **Coherent budgets.** `maxCallsPerSession ≥ maxCallsPerRun`.
7. **`debug: false`** for anything that will run with real credentials.
8. **Known providers only.** Use a `providerId` that an in-tree plugin implements (`rfc8693`, `github`, …). Do not invent providers.

## 3. The Gen-AI authoring workflow

An LLM is good at turning a natural-language request ("let the agent read GitHub issues and create tickets") into a manifest draft, and bad at being conservative about scope. Use it to draft, then gate it. The loop:

1. **Ground the model.** Put the JSON Schema (`pysandbox.policy.schema.json`), this guide's §2 rules, and the §6 anti-patterns into the model's context. Do not ask it to recall the taxonomy from memory.
2. **Constrain the request.** State the provider, the exact host, the specific operations (verb + path), and whether any are writes. Vague asks produce broad manifests.
3. **Generate** a draft asset.
4. **Validate** the draft against the schema (fail-closed — reject, do not auto-repair into defaults). This catches shape errors; it does **not** catch over-broad-but-valid patterns.
5. **Run the §5 self-check** (the rules the schema cannot express, plus least-privilege judgement).
6. **Human review and approve.** A person confirms the scope matches intent before the asset is committed. The LLM never self-approves.

The two gates that matter are step 4 (machine: shape) and step 5+6 (human/judgement: scope). Skipping step 5/6 is how an LLM-authored `".*"` reaches production.

## 4. Prompt template

Give the assistant a prompt of this shape (fill the bracketed parts):

```
You are authoring a capability for the pysandbox-agent policy manifest.
Authoritative schema (validate against this) and rules are below:
<paste pysandbox.policy.schema.json>
<paste §2 rules and §6 anti-patterns from 12-authoring-guide.md>

Request: allow [provider] calls to host [host] for these exact operations:
  - [METHOD] [path or path family], purpose: [why]
  - ...
Writes present: [yes/no]. Token-exchange provider: [yes=rfc8693 / no=github].

Produce ONLY the capabilities-map entry/entries as JSON. Requirements:
  - one host per capability, no wildcards;
  - pathAllow anchored and as narrow as the operations above (no ".*");
  - methods limited to exactly those listed;
  - if any write on a sensitive host, set requireStepUpAuth: true;
  - include audience iff the provider is a token-exchange provider;
  - do not invent providers or fields not in the schema.
After the JSON, list each pathAllow regex and the exact paths it admits,
so I can confirm it is not broader than requested.
```

The final instruction — make the model enumerate what each regex admits — turns an opaque pattern into something a reviewer can check.

## 5. Self-check before committing an asset

Run this checklist (the broker enforces the starred items at load; the rest are judgement the broker cannot make for you):

- [ ] Validates against `pysandbox.policy.schema.json`. *
- [ ] `host` is one concrete hostname, no wildcard. *
- [ ] Every `pathAllow` is anchored; none is `".*"` / `"^/.*"` / unanchored.
- [ ] Each `pathAllow` admits only the intended paths (you enumerated them).
- [ ] `methods` is exactly the set needed — no extra verbs.
- [ ] Any write on a sensitive host has `requireStepUpAuth: true`.
- [ ] Any write whose sink is readable beyond the enterprise has `requireStepUpAuth: true` (cross-capability exfiltration control, SR-27).
- [ ] `audience` present iff the provider is a token-exchange provider. * (rfc8693 case)
- [ ] `provider` is a known in-tree plugin. *
- [ ] `maxCallsPerSession ≥ maxCallsPerRun`. *
- [ ] `debug: false` for real-credential use. *
- [ ] A human has confirmed scope matches the request.

## 6. Anti-patterns (LLM-generated assets fail here most)

| Anti-pattern | Why it is dangerous | Fix |
|---|---|---|
| `"pathAllow": [".*"]` or unanchored fragment | Grants the entire host; `..`-style traversal aside, it admits every path | Anchor and narrow to the real operations |
| `"host": "*.example.com"` or `"*"` | Wildcard host defeats the single-host pin and redirect protection | One concrete hostname per capability |
| Adding `scopes` to "tighten" access | `scopes` are advisory; this gives false assurance | Tighten host + path + method instead |
| Write methods without `requireStepUpAuth` | Sensitive writes proceed without MFA assurance | Set `requireStepUpAuth: true` |
| Write to an externally-readable sink without `requireStepUpAuth` | Enables cross-capability exfiltration — read via one capability, post out via this one (both in-policy) | Set `requireStepUpAuth: true` on any outward-readable write sink (SR-27) |
| `audience` on a `github` capability | Schema/broker reject it; non-exchange providers forbid it | Omit `audience` for non-exchange providers |
| Missing `audience` on an `rfc8693` capability | Rejected by the schema | Add the downstream API audience |
| Inventing a provider (`"provider": "slack"`) with no plugin | Unknown provider fails closed at load | Use a `providerId` an in-tree plugin implements |
| Copying broad example patterns verbatim | Examples illustrate shape, not your scope | Rewrite paths for your exact operations |
| `debug: true` left in | Bodies may be logged; rejected under real credentials | Set `debug: false` |

## 7. Definition of done

An asset is ready to commit when: it passes schema validation; every item in §5 is ticked; each `pathAllow` has been shown (by enumeration) to admit only intended paths; and a human reviewer has approved the scope against the original request. Until then it is a draft — a manifest that fails any of these is rejected fail-closed by both the daemon broker and `obo-broker`, so an unreviewed asset does not silently take effect.

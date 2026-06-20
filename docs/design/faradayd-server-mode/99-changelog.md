# faradayd server-mode HLD — Changelog

Append-only. One line per edit, newest at the bottom. Format: `<date> — <origin>: <summary> → revision: <new-revision>`.

2026-06-18 — initial draft (designgen, mode=draft): bootstrapped HLD for faradayd-server-mode (server-side single-tenant profile; ADR-034 container topology, ADR-035 no-OBO, ADR-036 api_key, ADR-037 none, ADR-038 OIDC-optional) → revision: 0.1.0
2026-06-18 — direct edit: ADR-039 sensitive-write per-capability opt-in (default read-only); resolves blocking OQ-SM-1 (and OQ-SM-4, OQ-SM-5) → revision: 0.2.0
2026-06-18 — promoted from spec/faradayd-server-mode phase-3: C10 carries no code change (placement built in C11) → revision: 0.2.1
2026-06-19 — direct edit: ADR-039 amendment — write gate is global (all manifests/profiles), not server-mode-only; reconciled 00/07/10 wording → revision: 0.3.0

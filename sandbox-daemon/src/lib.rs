//! `faradayd` — host-resident sandbox daemon (one Rust binary).
//!
//! Module layout mirrors the Phase 2B component inventory in
//! `docs/spec/sandbox-daemon/phase-2-architecture.md`. Phase 0 implements only the
//! minimal boot path (`config` + `endpoint`); the remaining modules are stubs that
//! later phases of `docs/wip/plan/02-sandbox-daemon-build.md` fill in.

pub mod audit; // C3
pub mod broker; // C11
pub mod clientauth; // C6
pub mod config; // C1
pub mod controller; // C13
pub mod downstream; // C10
pub mod endpoint; // C14
pub mod errors; // C2
pub mod health; // C15
pub mod install; // ADR-031 installer helpers (MCP-config merge)
pub mod interaction; // C8
pub mod log; // XC3 structured logging + redaction
pub mod mcp; // C16 MCP front door (`mcp-stdio` sub-mode)
pub mod obo; // C9
pub mod policy; // C4
pub mod runtime; // C12
pub mod sanitize; // C5
pub mod session; // C7
pub mod types; // shared types catalogue (phase-2C)

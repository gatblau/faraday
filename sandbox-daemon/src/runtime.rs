//! C12 — SandboxRuntime (the isolation boundary, ADR-013/019). Runs the RustPython
//! guest (`wasm32-wasip1`) on a hardened Wasmtime engine with **no ambient authority**:
//! exactly **one capability host import** (the broker call shim) plus a **deny-by-default
//! WASI subset** — monotonic clock, randomness, and captured stdin/stdout/stderr only;
//! no filesystem (no preopens), no sockets, no environment, no args. The guest artefact
//! digest is verified before instantiation (ADR-018, fail-closed). Resource limits
//! (fuel, epoch deadline, max memory) terminate a run as `RUNTIME_LIMIT`.
//!
//! The agent Python `code` is delivered to the guest on **stdin**; `print(...)` is
//! captured from **stdout/stderr**. The guest reaches the broker only via `broker_call`.

use crate::broker::BrokerCall;
use crate::types::{CallSummary, RunResult, UntrustedMcpResult, UntrustedPart};
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{I32Exit, WasiCtxBuilder};

/// Exit code stamped on a `RunResult` when the run was terminated by a resource limit
/// (fuel / epoch / memory) or a guest trap. The Controller maps this to `RUNTIME_LIMIT`.
pub const RUNTIME_LIMIT_EXIT: i32 = -2;
/// Exit code when the guest could not be instantiated or lacks the `_start` entry.
pub const RUNTIME_INSTANTIATE_EXIT: i32 = -3;

/// Per-run resource limits (ADR-019).
#[derive(Debug, Clone)]
pub struct Limits {
    pub fuel: Option<u64>,
    pub epoch_deadline: Duration,
    pub max_memory_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            fuel: Some(2_000_000_000),
            epoch_deadline: Duration::from_secs(30),
            max_memory_bytes: 512 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
        }
    }
}

/// The per-run set of `{api_name → capId}` mappings the guest may invoke.
#[derive(Debug, Clone, Default)]
pub struct CapabilityBundle {
    pub mappings: HashMap<String, [u8; 16]>,
}

/// Startup failure of the runtime (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// The bundled guest digest does not match `PYS_GUEST_ARTIFACT_DIGEST`.
    ArtifactMismatch,
    /// The guest module could not be compiled.
    GuestInvalid,
}

impl RuntimeError {
    pub fn code(&self) -> &'static str {
        match self {
            RuntimeError::ArtifactMismatch => "RUNTIME_ARTIFACT_MISMATCH",
            RuntimeError::GuestInvalid => "RUNTIME_ARTIFACT_MISMATCH",
        }
    }
}

/// Mutable per-run store state: the deny-by-default WASI ctx, resource limiter, the
/// capability bundle, the collected per-call summaries, and host-side diagnostics
/// (broker-error codes) accumulated by the broker shim for surfacing on stderr.
struct StoreData {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
    bundle: HashMap<String, [u8; 16]>,
    calls: Vec<CallSummary>,
    /// Broker-error codes appended by the `broker_call` shim. Merged into the run's
    /// stderr so a failed brokered call is no longer indistinguishable from one that
    /// returned an empty body.
    host_stderr: String,
}

pub struct SandboxRuntime {
    engine: Engine,
    module: Module,
    broker: Arc<dyn BrokerCall>,
}

impl SandboxRuntime {
    /// Build the runtime: verify the guest digest (fail-closed), then compile the guest
    /// on a hardened engine. `guest` may be a wasm binary or (with the `wat` feature) WAT.
    pub fn new(
        expected_digest_hex: &str,
        guest: &[u8],
        broker: Arc<dyn BrokerCall>,
    ) -> Result<SandboxRuntime, RuntimeError> {
        if sha256_hex(guest) != expected_digest_hex.trim().to_ascii_lowercase() {
            return Err(RuntimeError::ArtifactMismatch);
        }
        let engine = Engine::new(&hardened_config()).map_err(|_| RuntimeError::GuestInvalid)?;
        let module = Module::new(&engine, guest).map_err(|_| RuntimeError::GuestInvalid)?;
        Ok(SandboxRuntime {
            engine,
            module,
            broker,
        })
    }

    /// The digest the runtime will accept for a guest (so callers can pin it).
    pub fn digest_of(guest: &[u8]) -> String {
        sha256_hex(guest)
    }

    /// Run the guest: deliver `code` on stdin, capture stdout/stderr, surface the
    /// broker capability via the single host import. Resource exhaustion or a guest
    /// trap terminates the run with `RUNTIME_LIMIT_EXIT`.
    pub async fn run(&self, code: &str, bundle: &CapabilityBundle, limits: &Limits) -> RunResult {
        let stdout = MemoryOutputPipe::new(limits.max_output_bytes.max(4096));
        let stderr = MemoryOutputPipe::new(64 * 1024);
        let wasi = WasiCtxBuilder::new()
            .stdin(MemoryInputPipe::new(code.as_bytes().to_vec()))
            .stdout(stdout.clone())
            .stderr(stderr.clone())
            .build_p1();
        // No args, no env, no preopens, no sockets — deny-by-default (ADR-019).

        let data = StoreData {
            wasi,
            limits: StoreLimitsBuilder::new()
                .memory_size(limits.max_memory_bytes)
                .build(),
            bundle: bundle.mappings.clone(),
            calls: Vec::new(),
            host_stderr: String::new(),
        };
        let mut store = Store::new(&self.engine, data);
        store.limiter(|d| &mut d.limits);
        if let Some(fuel) = limits.fuel {
            let _ = store.set_fuel(fuel);
        }
        store.set_epoch_deadline(1);

        let mut linker: Linker<StoreData> = Linker::new(&self.engine);
        // The hardened WASI subset + the single broker capability import.
        if wasmtime_wasi::p1::add_to_linker_async(&mut linker, |d: &mut StoreData| &mut d.wasi)
            .is_err()
            || self.link_broker_shim(&mut linker).is_err()
        {
            return fail(RUNTIME_INSTANTIATE_EXIT, String::new());
        }

        // Background epoch ticker: bump the engine epoch once after the deadline so a
        // runaway guest traps (→ RUNTIME_LIMIT).
        let engine = self.engine.clone();
        let deadline = limits.epoch_deadline;
        let ticker = tokio::spawn(async move {
            tokio::time::sleep(deadline).await;
            engine.increment_epoch();
        });

        let call_result = match linker.instantiate_async(&mut store, &self.module).await {
            Ok(instance) => match instance.get_typed_func::<(), ()>(&mut store, "_start") {
                Ok(start) => Some(start.call_async(&mut store, ()).await),
                Err(_) => None, // no `_start` — not a WASI command
            },
            Err(_) => None, // instantiation failed (e.g. an unsatisfied import)
        };
        ticker.abort();

        // A WASI command signals normal exit by trapping with `I32Exit`; a real trap
        // (fuel/epoch/memory) maps to RUNTIME_LIMIT.
        let exit_code = match &call_result {
            None => RUNTIME_INSTANTIATE_EXIT,
            Some(Ok(())) => 0,
            Some(Err(e)) => match e.downcast_ref::<I32Exit>() {
                Some(exit) => exit.0,
                None => RUNTIME_LIMIT_EXIT,
            },
        };

        let data = store.into_data();
        let calls = data.calls;
        let host_stderr = data.host_stderr;
        let raw = stdout.contents();
        let truncated = raw.len() > limits.max_output_bytes;
        let take = raw.len().min(limits.max_output_bytes);
        let stdout_s = String::from_utf8_lossy(&raw[..take]).into_owned();
        let stderr_s = if exit_code == RUNTIME_LIMIT_EXIT {
            // A resource-limit kill owns stderr wholesale (the Controller matches this
            // sentinel); host diagnostics are immaterial to that outcome.
            "RUNTIME_LIMIT".to_string()
        } else {
            let mut s = String::from_utf8_lossy(&stderr.contents()).into_owned();
            if !host_stderr.is_empty() {
                if !s.is_empty() && !s.ends_with('\n') {
                    s.push('\n');
                }
                s.push_str(&host_stderr);
            }
            s
        };

        RunResult {
            stdout: stdout_s,
            stderr: stderr_s,
            exit_code,
            api_calls: calls,
            truncated,
        }
    }

    /// Link exactly one **capability** host import: `env.broker_call`, carrying a **tagged**
    /// request (ADR-034). `kind=0` is a REST call (`a`=verb, `b`=path) routed to
    /// `IdentityBroker.call`; `kind=1` is an MCP `tools/call` (`a`=tool, `b`=arguments JSON)
    /// routed to `IdentityBroker.call_tool`. The tag is carried inside the single import, so
    /// this remains **one** capability host import (the ADR-013/019 isolation invariant). The
    /// shim reads the strings from guest memory, maps `api → capId` via the bundle, forwards
    /// to the broker, and writes the sanitised result back. A token is never written back.
    fn link_broker_shim(&self, linker: &mut Linker<StoreData>) -> wasmtime::Result<()> {
        let broker = self.broker.clone();
        linker.func_wrap_async(
            "env",
            "broker_call",
            move |mut caller: Caller<'_, StoreData>,
                  (kind, api_ptr, api_len, a_ptr, a_len, b_ptr, b_len, out_ptr, out_cap): (
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
                i32,
            )| {
                let broker = broker.clone();
                Box::new(async move {
                    let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                        Some(m) => m,
                        None => return -1i32,
                    };
                    let api = match read_str(&mem, &caller, api_ptr, api_len) {
                        Some(s) => s,
                        None => return -1,
                    };
                    // a = verb (rest) / tool (mcp); b = path (rest) / arguments JSON (mcp).
                    let a = match read_str(&mem, &caller, a_ptr, a_len) {
                        Some(s) => s,
                        None => return -1,
                    };
                    let b = match read_str(&mem, &caller, b_ptr, b_len) {
                        Some(s) => s,
                        None => return -1,
                    };
                    let cap_id = match caller.data().bundle.get(&api).copied() {
                        Some(id) => id,
                        None => return -1, // unknown api name → guest-visible error
                    };

                    match kind {
                        // REST call (C10/C11).
                        0 => {
                            let no_params = Vec::new();
                            match broker.call_boxed(&cap_id, &a, &b, &no_params, &[]).await {
                                Ok(resp) => {
                                    let n = resp.body.len().min(out_cap.max(0) as usize);
                                    if mem
                                        .write(&mut caller, out_ptr as usize, &resp.body[..n])
                                        .is_err()
                                    {
                                        return -1;
                                    }
                                    caller.data_mut().calls.push(CallSummary {
                                        provider: String::new(),
                                        host: String::new(),
                                        path: b,
                                        method: a,
                                        status: Some(resp.status),
                                    });
                                    n as i32
                                }
                                Err(e) => {
                                    let diag = format!("broker_call {a} {b}: {}\n", e.code());
                                    let data = caller.data_mut();
                                    data.host_stderr.push_str(&diag);
                                    data.calls.push(CallSummary {
                                        provider: String::new(),
                                        host: String::new(),
                                        path: b,
                                        method: a,
                                        status: None,
                                    });
                                    -1
                                }
                            }
                        }
                        // MCP tools/call (C17/C11, ADR-034).
                        1 => {
                            let arguments: Value = if b.trim().is_empty() {
                                json!({})
                            } else {
                                match serde_json::from_str(&b) {
                                    Ok(v) => v,
                                    Err(_) => return -1, // malformed guest arguments
                                }
                            };
                            match broker.call_tool_boxed(&cap_id, &a, &arguments).await {
                                Ok(result) => {
                                    let body = mcp_result_to_json(&result);
                                    let n = body.len().min(out_cap.max(0) as usize);
                                    if mem
                                        .write(&mut caller, out_ptr as usize, &body[..n])
                                        .is_err()
                                    {
                                        return -1;
                                    }
                                    caller.data_mut().calls.push(CallSummary {
                                        provider: String::new(),
                                        host: String::new(),
                                        path: a,
                                        method: "mcp.tools/call".to_string(),
                                        status: Some(200),
                                    });
                                    n as i32
                                }
                                Err(e) => {
                                    let diag = format!("broker_call mcp {a}: {}\n", e.code());
                                    let data = caller.data_mut();
                                    data.host_stderr.push_str(&diag);
                                    data.calls.push(CallSummary {
                                        provider: String::new(),
                                        host: String::new(),
                                        path: a,
                                        method: "mcp.tools/call".to_string(),
                                        status: None,
                                    });
                                    -1
                                }
                            }
                        }
                        _ => -1, // unknown tag
                    }
                })
            },
        )?;
        Ok(())
    }
}

/// Serialise an `UntrustedMcpResult` to the JSON the guest SDK parses (ADR-034). Binary
/// parts (image / embedded resource) are base64-encoded under `data_b64`; a text part's
/// body is decoded lossily; a `structuredContent` part is embedded as JSON; a resource
/// link carries a uri only. The `untrusted` marker is always present.
fn mcp_result_to_json(r: &UntrustedMcpResult) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let parts: Vec<Value> = r
        .parts
        .iter()
        .map(|p| match p {
            UntrustedPart::Text { content_type, body } => json!({
                "type": "text",
                "content_type": content_type,
                "text": String::from_utf8_lossy(body),
            }),
            UntrustedPart::Json { body } => json!({
                "type": "json",
                "json": serde_json::from_slice::<Value>(body).unwrap_or(Value::Null),
            }),
            UntrustedPart::Image { mime_type, body } => json!({
                "type": "image",
                "mime_type": mime_type,
                "data_b64": b64.encode(body),
            }),
            UntrustedPart::ResourceLink { uri, mime_type } => json!({
                "type": "resource_link",
                "uri": uri,
                "mime_type": mime_type,
            }),
            UntrustedPart::EmbeddedResource {
                uri,
                mime_type,
                body,
            } => json!({
                "type": "embedded_resource",
                "uri": uri,
                "mime_type": mime_type,
                "data_b64": b64.encode(body),
            }),
        })
        .collect();
    let v = json!({
        "untrusted": r.untrusted,
        "is_error": r.is_error,
        "truncated": r.truncated,
        "parts": parts,
    });
    serde_json::to_vec(&v).unwrap_or_default()
}

fn fail(code: i32, stderr: String) -> RunResult {
    RunResult {
        stdout: String::new(),
        stderr,
        exit_code: code,
        api_calls: Vec::new(),
        truncated: false,
    }
}

/// The hardened engine config (ADR-019): fuel + epoch interruption for resource limits,
/// risky proposals disabled. The WASI subset is provided via the linker, not here.
fn hardened_config() -> Config {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    // RustPython's frozen-stdlib import recurses deeply; give the guest a generous
    // wasm stack (and a larger async fiber stack, which must exceed it) so init does
    // not overflow. Still bounded — not unlimited recursion.
    config.max_wasm_stack(8 * 1024 * 1024);
    config.async_stack_size(16 * 1024 * 1024);
    // Threads are the one proposal we hard-deny (shared memory / atomics are not part
    // of the single-threaded guest contract). Other proposals are left at Wasmtime's
    // defaults because the RustPython `wasm32-wasip1` artefact is built with the
    // standard rustc feature set (reference-types, bulk-memory, multivalue, sign-ext);
    // disabling those would fail module validation. Tightening to an explicit
    // guest-matched allow-list is tracked as FU-020.
    config.wasm_threads(false);
    config
}

fn read_str(mem: &Memory, store: &Caller<'_, StoreData>, ptr: i32, len: i32) -> Option<String> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let (ptr, len) = (ptr as usize, len as usize);
    let data = mem.data(store);
    let slice = data.get(ptr..ptr.checked_add(len)?)?;
    std::str::from_utf8(slice).ok().map(|s| s.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_result_json_shape() {
        let result = UntrustedMcpResult {
            untrusted: true,
            is_error: false,
            truncated: true,
            parts: vec![
                UntrustedPart::Text {
                    content_type: "text/plain".into(),
                    body: b"hello".to_vec(),
                },
                UntrustedPart::ResourceLink {
                    uri: "file:///x".into(),
                    mime_type: None,
                },
                UntrustedPart::Image {
                    mime_type: "image/png".into(),
                    body: b"hi".to_vec(),
                },
            ],
        };
        let v: Value = serde_json::from_slice(&mcp_result_to_json(&result)).unwrap();
        assert_eq!(v["untrusted"], json!(true));
        assert_eq!(v["is_error"], json!(false));
        assert_eq!(v["truncated"], json!(true));
        let parts = v["parts"].as_array().unwrap();
        assert_eq!(parts[0]["type"], json!("text"));
        assert_eq!(parts[0]["text"], json!("hello"));
        assert_eq!(parts[1]["type"], json!("resource_link"));
        assert_eq!(parts[1]["uri"], json!("file:///x"));
        // "hi" base64-encoded is "aGk=" — the link before it is never given a body.
        assert_eq!(parts[2]["type"], json!("image"));
        assert_eq!(parts[2]["data_b64"], json!("aGk="));
    }
}

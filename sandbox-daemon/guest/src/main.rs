//! `pysandbox-guest` — the RustPython interpreter compiled to `wasm32-wasip1` (C12).
//!
//! Contract with the SandboxRuntime host (ADR-013/019):
//!   - the agent Python `code` arrives on **stdin** (a host-controlled WASI pipe);
//!   - `print(...)` output is captured by the host via **stdout/stderr** (WASI);
//!   - the **only** egress is the single capability host import `env.broker_call`,
//!     surfaced to Python as `pysandbox_sdk._call` and wrapped by the injected
//!     `api.<name>.get/post/patch/delete(path)` SDK.
//! No filesystem, sockets, env, or args are available (deny-by-default WASI subset).

use rustpython_vm::scope::Scope;
use rustpython_vm::{self as vm, PyResult, VirtualMachine};
use std::io::Read;

// The single capability host import. Pointers are offsets into this guest's linear
// memory (wasm pointers are `i32` offsets); the host reads the request strings and
// writes the sanitised response body into `out`, returning its length (or `<0`).
#[link(wasm_import_module = "env")]
extern "C" {
    fn broker_call(
        api_ptr: i32,
        api_len: i32,
        verb_ptr: i32,
        verb_len: i32,
        path_ptr: i32,
        path_len: i32,
        out_ptr: i32,
        out_cap: i32,
    ) -> i32;
}

const OUT_CAP: usize = 1 << 20; // 1 MiB response buffer

fn broker_call_raw(api: &str, verb: &str, path: &str) -> Vec<u8> {
    let mut out = vec![0u8; OUT_CAP];
    let n = unsafe {
        broker_call(
            api.as_ptr() as i32,
            api.len() as i32,
            verb.as_ptr() as i32,
            verb.len() as i32,
            path.as_ptr() as i32,
            path.len() as i32,
            out.as_mut_ptr() as i32,
            out.len() as i32,
        )
    };
    if n < 0 {
        return Vec::new();
    }
    out.truncate(n as usize);
    out
}

/// The native module the guest exposes to Python; the only sanctioned egress path.
#[vm::pymodule]
mod pysandbox_sdk {
    use rustpython_vm::{PyObjectRef, VirtualMachine};

    /// `_call(api, verb, path) -> bytes` — forwards to the broker capability import.
    #[pyfunction]
    fn _call(api: String, verb: String, path: String, vm: &VirtualMachine) -> PyObjectRef {
        let body = super::broker_call_raw(&api, &verb, &path);
        vm.ctx.new_bytes(body).into()
    }
}

/// Python SDK preamble: `api.<name>.get(path)` over `pysandbox_sdk._call`. Injected
/// before the agent code so the agent contract (ADR-014) is in scope.
const PREAMBLE: &str = r#"
import pysandbox_sdk as _sdk
class _Cap:
    def __init__(self, name):
        self._n = name
    def get(self, path):
        return _sdk._call(self._n, "GET", path)
    def post(self, path):
        return _sdk._call(self._n, "POST", path)
    def patch(self, path):
        return _sdk._call(self._n, "PATCH", path)
    def delete(self, path):
        return _sdk._call(self._n, "DELETE", path)
class _Api:
    def __getattr__(self, name):
        return _Cap(name)
api = _Api()
"#;

fn run_source(vm: &VirtualMachine, scope: Scope, src: &str, name: &str) -> PyResult<()> {
    let code_obj = vm
        .compile(src, vm::compiler::Mode::Exec, name.to_owned())
        .map_err(|err| vm.new_syntax_error(&err, Some(src)))?;
    vm.run_code_obj(code_obj, scope)?;
    Ok(())
}

fn main() {
    let mut code = String::new();
    let _ = std::io::stdin().read_to_string(&mut code);

    let builder = vm::InterpreterBuilder::new().settings(vm::Settings::default());
    let sdk_def = pysandbox_sdk::module_def(&builder.ctx);
    // Native (Rust-implemented) stdlib accelerators (_sre, _json, math, …) and the
    // frozen pure-Python stdlib bytes. Together these make the ADR-014 modules
    // importable in the no-filesystem guest. The capability SDK import is added too;
    // the deny-by-default WASI subset (no fs/sockets/env/args) is unchanged.
    let native = rustpython_stdlib::stdlib_module_defs(&builder.ctx);
    let interp = builder
        .add_native_modules(&native)
        .add_native_module(sdk_def)
        .add_frozen_modules(rustpython_pylib::FROZEN_STDLIB)
        .build();

    let exit_code = interp.enter(|vm| {
        let scope = vm.new_scope_with_builtins();
        if let Err(e) = run_source(vm, scope.clone(), PREAMBLE, "<preamble>") {
            vm.print_exception(e);
            return 70; // internal preamble failure
        }
        match run_source(vm, scope, &code, "<run>") {
            Ok(()) => 0,
            Err(e) => {
                vm.print_exception(e);
                1
            }
        }
    });

    std::process::exit(exit_code);
}

//! `faradayd` entry point — assembles the full daemon: Config → leaves → broker →
//! runtime (with the embedded, digest-verified guest) → controller → control endpoint,
//! behind ClientAuth + SessionManager; init the connection token; graceful shutdown.
//!
//! The production InteractionSurface (the daemon-owned consent/sign-in UI) is not yet
//! built (FU-015); a headless surface is wired, so real interactive runs fail closed
//! until it lands. Every downstream token derives from the OIDC provider (exchange or
//! pass-through); per-provider audiencing of the pass-through access token is FU-031.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use faradayd::audit::{AuditLogger, AuditSink};
use faradayd::broker::{ApiKeyStore, BrokerCall, CredentialSource, IdentityBroker};
use faradayd::config::{Config, FileSecretResolver, SecretResolver};
use faradayd::controller::{CapabilityMinter, IdTokenSink, Interactor, SandboxController};
use faradayd::downstream::{DownstreamClient, DEFAULT_CALL_TIMEOUT};
use faradayd::endpoint::Daemon;
use faradayd::health::HealthCheck;
use faradayd::interaction::{ConsentSummary, ConsentUI, InteractionSurface};
use faradayd::mcp_upstream::McpUpstreamClient;
use faradayd::obo::OboClient;
use faradayd::policy::PolicyEngine;
use faradayd::runtime::{Limits, SandboxRuntime};
use faradayd::session::SessionManager;
use faradayd::types::AuditEntry;

/// The bundled, digest-verified RustPython guest (ADR-018).
const GUEST: &[u8] = include_bytes!("../guest/pysandbox-guest.wasm");

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Audit sink: emit one structured, redacted JSON line per call (sizes + keyed-HMAC id,
/// never tokens) via the XC3 logging layer.
struct StderrAuditSink;
impl AuditSink for StderrAuditSink {
    fn emit(&self, e: &AuditEntry) {
        let mut fields = serde_json::Map::new();
        fields.insert("user_hmac".into(), e.user_hmac.clone().into());
        fields.insert("provider".into(), e.provider.clone().into());
        fields.insert("capability_id".into(), e.capability_id.clone().into());
        fields.insert("method".into(), e.method.clone().into());
        fields.insert("host".into(), e.host.clone().into());
        fields.insert("path".into(), e.path.clone().into());
        fields.insert("status_code".into(), e.status_code.into());
        fields.insert("response_bytes".into(), e.response_bytes.into());
        fields.insert("duration_ms".into(), e.duration_ms.into());
        println!(
            "{}",
            faradayd::log::log_line(
                now_ts(),
                "info",
                "outbound call",
                &e.run_id,
                "broker",
                None,
                &fields
            )
        );
    }
}

/// The session-aware credential source: holds the signed-in OIDC tokens for the broker
/// — the `id_token` (exchange subject token) and the `access_token` (forwarded to
/// pass-through providers). Both are derived from the OIDC provider; faraday holds no
/// static provider secrets. Neither token leaves the daemon and neither is logged.
struct SessionCreds {
    id_token: Mutex<Option<String>>,
    access_token: Mutex<Option<String>>,
}
impl CredentialSource for SessionCreds {
    fn id_token(&self) -> Option<String> {
        self.id_token.lock().unwrap().clone()
    }
    fn access_token(&self) -> Option<String> {
        self.access_token.lock().unwrap().clone()
    }
}
impl IdTokenSink for SessionCreds {
    fn set_id_token(&self, id_token: String) {
        *self.id_token.lock().unwrap() = Some(id_token);
    }
    fn set_access_token(&self, access_token: String) {
        *self.access_token.lock().unwrap() = Some(access_token);
    }
}

/// The production interaction surface (ADR-029 / ADR-025): opens the system browser for
/// the OIDC loopback sign-in, and presents a native OS dialog for capability consent.
/// The `id_token` is captured by the daemon's loopback listener (C8) — never here.
struct BrowserSurface;
impl InteractionSurface for BrowserSurface {
    fn available(&self) -> bool {
        true
    }
    fn open(&self, url: &str) {
        // Best-effort: launch the user's browser at the OIDC authorize URL. The redirect
        // is captured by the daemon's transient 127.0.0.1 listener (C8).
        let _ = open_in_browser(url);
    }
    fn confirm_consent(&self, summary: &ConsentSummary) -> bool {
        // Fail closed if no dialog surface is available.
        confirm_via_dialog(summary).unwrap_or(false)
    }
}

/// Launch the system browser at `url` (macOS `open` / Windows `start` / Linux `xdg-open`).
fn open_in_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.spawn().map(|_| ())
}

/// Present a native consent dialog; `Some(true)` ⇒ approved. macOS uses `osascript`;
/// other platforms return `None` (no dialog wired yet ⇒ caller fails closed).
fn confirm_via_dialog(summary: &ConsentSummary) -> Option<bool> {
    // The client_label is client-asserted, not verified (RR-5) — phrase it as a
    // self-claimed name so the displayed identity cannot be mistaken for proof.
    let prompt = format!(
        "Allow a client identifying itself as '{}' to use capability '{}' ({} on {}, provider {})?{}",
        summary.client_label,
        summary.capability_id,
        summary.methods.join(", "),
        summary.host,
        summary.provider,
        if summary.require_step_up {
            " [step-up required]"
        } else {
            ""
        }
    );
    #[cfg(target_os = "macos")]
    {
        // `cancel button "Deny"` ⇒ Deny exits non-zero, Allow exits 0.
        let safe = prompt.replace('\\', "").replace('"', "'");
        let script = format!(
            "display dialog \"{safe}\" buttons {{\"Deny\", \"Allow\"}} cancel button \"Deny\" default button \"Allow\" with title \"faradayd consent\""
        );
        let status = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .status()
            .ok()?;
        Some(status.success())
    }
    #[cfg(target_os = "windows")]
    {
        // The per-user daemon runs in the user's interactive session, so it can show a GUI
        // consent dialog (mirrors the macOS osascript path). Yes ⇒ approved; anything else
        // (No, or a failure to show the dialog) ⇒ the caller fails closed.
        //
        // The prompt is passed via the environment and read as `$env:...`, never interpolated
        // into the script text, so a client-asserted label cannot inject PowerShell.
        let script = "Add-Type -AssemblyName PresentationFramework; \
             if ([System.Windows.MessageBox]::Show($env:FARADAYD_CONSENT_PROMPT,'faradayd consent','YesNo','Question') -eq 'Yes') { exit 0 } else { exit 1 }";
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("FARADAYD_CONSENT_PROMPT", prompt)
            .status()
            .ok()?;
        Some(status.success())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = prompt; // Linux consent dialog (xdg surface): follow-up (FU-003).
        None
    }
}

/// Implements `faradayd install-mcp-config [config-path]`: merge our `mcp-stdio` entry
/// into the MCP client config (default `$HOME/.claude.json`), preserving other servers.
fn run_install_mcp_config() -> i32 {
    let config_path = std::env::args().nth(2).unwrap_or_else(|| {
        // %USERPROFILE% on Windows where HOME is usually unset; HOME on Unix.
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        format!("{home}/.claude.json")
    });
    let binary = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "faradayd".to_string());
    let existing = std::fs::read_to_string(&config_path).ok();
    match faradayd::install::merge_mcp_config(existing.as_deref(), "faradayd", &binary) {
        Ok(merged) => match std::fs::write(&config_path, merged) {
            Ok(()) => {
                eprintln!("merged faradayd MCP server into {config_path}");
                0
            }
            Err(e) => {
                eprintln!("write {config_path} failed: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("refusing to modify {config_path}: {e}");
            1
        }
    }
}

fn die(context: &str, e: impl std::fmt::Debug) -> ! {
    eprintln!("{context}: {e:?}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    // Sub-mode dispatch (ADR-028): `faradayd mcp-stdio` runs the MCP front door — a
    // thin client of this same daemon over the control socket. Default: run the daemon.
    if std::env::args().nth(1).as_deref() == Some("mcp-stdio") {
        if let Err(e) = faradayd::mcp::run_stdio().await {
            eprintln!("mcp-stdio error: {e}");
            std::process::exit(1);
        }
        return;
    }
    // `faradayd install-mcp-config [config-path]` — register the MCP front door in the
    // client config (default ~/.claude.json) without clobbering existing servers (ADR-031).
    if std::env::args().nth(1).as_deref() == Some("install-mcp-config") {
        std::process::exit(run_install_mcp_config());
    }

    let resolver = FileSecretResolver;
    let config = match Config::load(&|k| std::env::var(k).ok(), &resolver) {
        Ok(c) => c,
        Err(e) => die("config error", e),
    };

    let policy_json = match std::fs::read_to_string(&config.policy_path) {
        Ok(s) => s,
        Err(e) => die("policy read error", e),
    };
    let policy = match PolicyEngine::load(&policy_json, None, &|_, _| false) {
        Ok(p) => Arc::new(p),
        Err(e) => die("policy load error", e),
    };
    // ADR-038: the OIDC config group is required only when the manifest has an
    // exchange/passthrough capability; a pure api_key/none deployment needs no sign-in.
    if policy.has_oidc_capability() {
        if let Err(e) = config.require_oidc() {
            die("config error", e);
        }
    }

    let audit = Arc::new(AuditLogger::new(
        config.audit_hmac_key.clone(),
        Box::new(StderrAuditSink),
    ));
    let obo = match OboClient::new(config.obo_endpoint.clone().unwrap_or_default()) {
        Ok(c) => Arc::new(c),
        Err(e) => die("obo client error", e),
    };
    let downstream = match DownstreamClient::new(
        config.response_max_bytes,
        DEFAULT_CALL_TIMEOUT,
        config.allow_plaintext_loopback_egress,
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => die("downstream client error", e),
    };
    let creds = Arc::new(SessionCreds {
        id_token: Mutex::new(None),
        access_token: Mutex::new(None),
    });
    // ADR-036 / AS-6: resolve each api_key capability's key once at startup, file-backed
    // via the SecretResolver, trimming a single trailing newline; fail closed on an
    // unreadable reference. Frozen into the ApiKeyStore the broker holds.
    let mut api_key_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for secret_ref in policy.api_key_secret_refs() {
        let bytes = match resolver.resolve(&secret_ref) {
            Ok(b) => b,
            Err(e) => die("api key resolve error", e),
        };
        let mut key = String::from_utf8_lossy(&bytes).into_owned();
        if key.ends_with('\n') {
            key.pop();
            if key.ends_with('\r') {
                key.pop();
            }
        }
        api_key_map.insert(secret_ref, key);
    }
    let api_keys: Arc<dyn ApiKeyStore> = Arc::new(api_key_map);

    // C17 outbound MCP client (ADR-034): HTTPS-only with the ADR-032 loopback exception,
    // same size cap as the REST downstream. Wired to the broker for `call_tool`.
    let mcp_upstream = match McpUpstreamClient::new(
        config.response_max_bytes,
        DEFAULT_CALL_TIMEOUT,
        config.allow_plaintext_loopback_egress,
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => die("mcp upstream client error", e),
    };
    let broker = Arc::new(
        IdentityBroker::new(
            policy.clone(),
            audit,
            obo,
            downstream,
            creds.clone() as Arc<dyn CredentialSource>,
            config.response_max_bytes as usize,
            api_keys,
        )
        .with_mcp_upstream(mcp_upstream),
    );

    let runtime = match SandboxRuntime::new(
        &config.guest_artifact_digest,
        GUEST,
        broker.clone() as Arc<dyn BrokerCall>,
    ) {
        Ok(r) => Arc::new(r),
        Err(e) => die("guest artefact verification failed", e),
    };

    let consent = match ConsentUI::new(
        config.oidc_issuer.clone().unwrap_or_default(),
        config.oidc_client_id.clone().unwrap_or_default(),
        config.oidc_scopes.clone(),
        config.consent_ui_mode.clone(),
        Box::new(BrowserSurface),
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => die("consent UI error", e),
    };

    let sessions = Arc::new(SessionManager::new(config.max_calls_per_session));
    let limits = Limits {
        fuel: Some(config.wasm_fuel.unwrap_or(u64::MAX)),
        epoch_deadline: Duration::from_secs(config.wasm_deadline_seconds),
        max_memory_bytes: config.wasm_max_memory_bytes as usize,
        max_output_bytes: config.response_max_bytes as usize,
    };
    let controller = Arc::new(SandboxController::new(
        policy,
        consent as Arc<dyn Interactor>,
        broker as Arc<dyn CapabilityMinter>,
        runtime,
        sessions,
        creds as Arc<dyn IdTokenSink>,
        config.oidc_issuer.clone().unwrap_or_default(),
        limits,
    ));
    let health = Arc::new(HealthCheck::new(
        config.oidc_issuer.clone().unwrap_or_default(),
        config.obo_endpoint.clone(),
    ));

    let token_path = config.token_path.clone();
    let daemon = match Daemon::bind(config, controller, health) {
        Ok(d) => d,
        Err(e) => die("bind error", e),
    };

    println!(
        "{}",
        faradayd::log::log_line(
            now_ts(),
            "info",
            "faradayd listening",
            "-",
            "endpoint",
            None,
            &serde_json::Map::new(),
        )
    );

    serve_until_shutdown(daemon, &token_path).await;
}

#[cfg(unix)]
async fn serve_until_shutdown(daemon: Daemon, token_path: &str) {
    use tokio::signal::unix::{signal, SignalKind};
    let shutdown = async {
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                let _ = term.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    faradayd::endpoint::serve_and_cleanup(daemon, shutdown, token_path).await;
}

#[cfg(not(unix))]
async fn serve_until_shutdown(daemon: Daemon, token_path: &str) {
    use tokio::signal::windows;
    // Console-control events for the per-user Run-key process: Ctrl-C, Ctrl-Break, console
    // close, logoff, and system shutdown. Resolve on the first; a registration failure makes
    // that one source pend (never fire) rather than abort startup.
    let shutdown = async {
        tokio::select! {
            _ = async { match windows::ctrl_c()       { Ok(mut s) => { s.recv().await; } Err(_) => std::future::pending::<()>().await } } => {}
            _ = async { match windows::ctrl_break()    { Ok(mut s) => { s.recv().await; } Err(_) => std::future::pending::<()>().await } } => {}
            _ = async { match windows::ctrl_close()    { Ok(mut s) => { s.recv().await; } Err(_) => std::future::pending::<()>().await } } => {}
            _ = async { match windows::ctrl_logoff()   { Ok(mut s) => { s.recv().await; } Err(_) => std::future::pending::<()>().await } } => {}
            _ = async { match windows::ctrl_shutdown() { Ok(mut s) => { s.recv().await; } Err(_) => std::future::pending::<()>().await } } => {}
        }
    };
    faradayd::endpoint::serve_and_cleanup(daemon, shutdown, token_path).await;
}

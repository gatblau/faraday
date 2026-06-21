//! C1 — Config.
//!
//! Loads and validates the full `PYS_*` runtime configuration (phase-2D), resolves
//! `*_REF` secrets via a [`SecretResolver`], and fails closed on any missing or
//! malformed value. Credential mode follows ADR-016: real-credential operation
//! requires an OTLP sink; absent one, the daemon degrades to mock-only.

/// Resolves a `*_REF` configuration value to its secret bytes (phase-3 C1 SPI).
pub trait SecretResolver {
    fn resolve(&self, reference: &str) -> Result<Vec<u8>, ConfigError>;
}

/// Default resolver: treats the reference as a file path and reads its bytes.
/// (Keychain / workload-identity resolvers are added in a later phase.)
pub struct FileSecretResolver;

impl SecretResolver for FileSecretResolver {
    fn resolve(&self, reference: &str) -> Result<Vec<u8>, ConfigError> {
        std::fs::read(reference).map_err(|_| ConfigError {
            code: "CFG_SECRET_UNRESOLVED",
            field: reference.to_string(),
        })
    }
}

/// A startup configuration error. `code` is the wire/registry code (Phase 4 XC2).
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError {
    pub code: &'static str,
    pub field: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: config {}", self.code, self.field)
    }
}

impl std::error::Error for ConfigError {}

/// ADR-016 credential posture: real credentials require an authoritative audit sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMode {
    Real,
    Mock,
}

/// Immutable runtime configuration (phase-2D).
#[derive(Debug, Clone)]
pub struct Config {
    pub socket_path: String,
    pub token_path: String,
    pub require_first_connect_consent: bool,
    /// OIDC issuer; `None` for a pure `api_key`/`none` server-mode deployment (ADR-038).
    /// Required-ness is enforced by [`Config::require_oidc`] once the manifest is loaded.
    pub oidc_issuer: Option<String>,
    /// OIDC public client id; `None` when `oidc_issuer` is `None` (ADR-038).
    pub oidc_client_id: Option<String>,
    pub oidc_scopes: String,
    pub obo_endpoint: Option<String>,
    pub policy_path: String,
    pub admin_signing_key: Option<Vec<u8>>,
    pub consent_ui_mode: String,
    pub max_calls_per_run: u32,
    pub max_calls_per_session: u32,
    pub response_max_bytes: u64,
    /// ADR-032: when `true`, C10 (DownstreamClient) may issue plaintext `http` egress to
    /// a `127.0.0.1` provider host only (dev-machine demo). Default `false` — production
    /// egress stays HTTPS-only and fail-closed. Never relaxes egress to a remote host.
    pub allow_plaintext_loopback_egress: bool,
    pub wasm_fuel: Option<u64>,
    pub wasm_max_memory_bytes: u64,
    pub wasm_deadline_seconds: u64,
    pub guest_artifact_digest: String,
    pub otlp_endpoint: Option<String>,
    pub audit_hmac_key: Vec<u8>,
    pub log_level: String,
    pub credential_mode: CredentialMode,
}

const ONE_MIB: u64 = 1_048_576;

impl Config {
    /// Build a `Config` from an env getter (so tests inject env without touching the
    /// process environment) and a [`SecretResolver`]. Fails closed on the first
    /// missing required value (`CFG_MISSING`), malformed value (`CFG_INVALID`), or
    /// unresolvable secret reference (`CFG_SECRET_UNRESOLVED`).
    pub fn load(
        get: &dyn Fn(&str) -> Option<String>,
        resolver: &dyn SecretResolver,
    ) -> Result<Config, ConfigError> {
        let runtime_dir = opt(get, "XDG_RUNTIME_DIR")
            .unwrap_or_else(|| std::env::temp_dir().to_string_lossy().into_owned());
        // Unix: a Unix-domain socket + token file under the runtime dir.
        #[cfg(not(windows))]
        let socket_path =
            opt(get, "PYS_SOCKET_PATH").unwrap_or_else(|| format!("{runtime_dir}/faradayd.sock"));
        #[cfg(not(windows))]
        let token_path = opt(get, "PYS_CONNECTION_TOKEN_PATH")
            .unwrap_or_else(|| format!("{runtime_dir}/faradayd.token"));
        // Windows (windows-deployment phase 3): the control transport is a named pipe, and
        // the connection token lives under the per-user %LOCALAPPDATA% (per-user by its
        // default ACLs). Falls back to the runtime dir if %LOCALAPPDATA% is unset.
        #[cfg(windows)]
        let socket_path =
            opt(get, "PYS_SOCKET_PATH").unwrap_or_else(|| r"\\.\pipe\faradayd".to_string());
        #[cfg(windows)]
        let token_path = opt(get, "PYS_CONNECTION_TOKEN_PATH").unwrap_or_else(|| {
            let base = opt(get, "LOCALAPPDATA").unwrap_or_else(|| runtime_dir.clone());
            format!(r"{base}\faradayd\faradayd.token")
        });
        let require_first_connect_consent =
            parse_bool(get, "PYS_REQUIRE_FIRST_CONNECT_CONSENT", true)?;

        // OIDC is optional at load (ADR-038): a pure api_key/none deployment configures
        // none. When an issuer is set, the format rule still applies. Whether OIDC is
        // *required* depends on the manifest's auth modes and is enforced post-load by
        // `require_oidc` (the manifest is owned by PolicyEngine, not Config).
        let oidc_issuer = opt(get, "PYS_OIDC_ISSUER");
        if let Some(ref iss) = oidc_issuer {
            // TLS required, except a loopback IdP (local Dex for the dev-machine demo,
            // ADR-029) — `http://127.0.0.1`/`http://localhost` only; remote http rejected.
            let issuer_ok = iss.starts_with("https://")
                || iss.starts_with("http://127.0.0.1")
                || iss.starts_with("http://localhost");
            if !issuer_ok {
                return Err(invalid("PYS_OIDC_ISSUER"));
            }
        }
        // OIDC public client (PKCE) for the browser auth-code sign-in (ADR-029); no secret.
        let oidc_client_id = opt(get, "PYS_OIDC_CLIENT_ID");
        let oidc_scopes =
            opt(get, "PYS_OIDC_SCOPES").unwrap_or_else(|| "openid profile email".to_string());

        let obo_endpoint = opt(get, "PYS_OBO_ENDPOINT");
        let policy_path = required(get, "PYS_POLICY_PATH")?;

        let admin_signing_key = match opt(get, "PYS_ADMIN_SIGNING_KEY_REF") {
            Some(reference) => Some(resolver.resolve(&reference)?),
            None => None,
        };

        let consent_ui_mode = opt(get, "PYS_CONSENT_UI_MODE").unwrap_or_else(|| "auto".to_string());
        if !matches!(consent_ui_mode.as_str(), "browser" | "dialog" | "auto") {
            return Err(invalid("PYS_CONSENT_UI_MODE"));
        }

        let max_calls_per_run = parse_u64(get, "PYS_MAX_CALLS_PER_RUN", 50)? as u32;
        let max_calls_per_session = parse_u64(get, "PYS_MAX_CALLS_PER_SESSION", 500)? as u32;
        if max_calls_per_run < 1 {
            return Err(invalid("PYS_MAX_CALLS_PER_RUN"));
        }
        if max_calls_per_session < max_calls_per_run {
            return Err(invalid("PYS_MAX_CALLS_PER_SESSION"));
        }

        let response_max_bytes = parse_u64(get, "PYS_RESPONSE_MAX_BYTES", ONE_MIB)?;
        if response_max_bytes > ONE_MIB {
            return Err(invalid("PYS_RESPONSE_MAX_BYTES"));
        }

        // ADR-032: dev-only plaintext egress to a 127.0.0.1 provider. Default false; the
        // 127.0.0.1-only constraint is enforced at the call site (DownstreamClient), so a
        // remote host can never be downgraded to http regardless of this flag.
        let allow_plaintext_loopback_egress =
            parse_bool(get, "PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS", false)?;

        let wasm_fuel = match opt(get, "PYS_WASM_FUEL") {
            Some(v) => Some(v.parse().map_err(|_| invalid("PYS_WASM_FUEL"))?),
            None => None,
        };
        let wasm_max_memory_bytes = parse_u64(get, "PYS_WASM_MAX_MEMORY_BYTES", 536_870_912)?;
        let wasm_deadline_seconds = parse_u64(get, "PYS_WASM_DEADLINE_SECONDS", 30)?;

        let guest_artifact_digest = required(get, "PYS_GUEST_ARTIFACT_DIGEST")?;
        let otlp_endpoint = opt(get, "PYS_OTLP_ENDPOINT");
        let audit_hmac_key = resolver.resolve(&required(get, "PYS_AUDIT_HMAC_KEY_REF")?)?;
        let log_level = opt(get, "PYS_LOG_LEVEL").unwrap_or_else(|| "info".to_string());

        // ADR-016: real-credential operation requires an OTLP sink; absent one, mock-only.
        let credential_mode = if otlp_endpoint.is_some() {
            CredentialMode::Real
        } else {
            CredentialMode::Mock
        };

        Ok(Config {
            socket_path,
            token_path,
            require_first_connect_consent,
            oidc_issuer,
            oidc_client_id,
            oidc_scopes,
            obo_endpoint,
            policy_path,
            admin_signing_key,
            consent_ui_mode,
            max_calls_per_run,
            max_calls_per_session,
            response_max_bytes,
            allow_plaintext_loopback_egress,
            wasm_fuel,
            wasm_max_memory_bytes,
            wasm_deadline_seconds,
            guest_artifact_digest,
            otlp_endpoint,
            audit_hmac_key,
            log_level,
            credential_mode,
        })
    }

    /// Enforce the OIDC config group (ADR-038): the bootstrap calls this only when the
    /// loaded manifest has an `exchange`/`passthrough` capability. Returns `CFG_MISSING`
    /// (naming the absent variable) if `oidc_issuer` or `oidc_client_id` is unset.
    pub fn require_oidc(&self) -> Result<(), ConfigError> {
        if self.oidc_issuer.is_none() {
            return Err(ConfigError {
                code: "CFG_MISSING",
                field: "PYS_OIDC_ISSUER".to_string(),
            });
        }
        if self.oidc_client_id.is_none() {
            return Err(ConfigError {
                code: "CFG_MISSING",
                field: "PYS_OIDC_CLIENT_ID".to_string(),
            });
        }
        Ok(())
    }
}

fn opt(get: &dyn Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get(key).filter(|v| !v.is_empty())
}

fn required(get: &dyn Fn(&str) -> Option<String>, key: &str) -> Result<String, ConfigError> {
    opt(get, key).ok_or_else(|| ConfigError {
        code: "CFG_MISSING",
        field: key.to_string(),
    })
}

fn invalid(field: &str) -> ConfigError {
    ConfigError {
        code: "CFG_INVALID",
        field: field.to_string(),
    }
}

fn parse_u64(
    get: &dyn Fn(&str) -> Option<String>,
    key: &str,
    default: u64,
) -> Result<u64, ConfigError> {
    match opt(get, key) {
        Some(v) => v.parse().map_err(|_| invalid(key)),
        None => Ok(default),
    }
}

fn parse_bool(
    get: &dyn Fn(&str) -> Option<String>,
    key: &str,
    default: bool,
) -> Result<bool, ConfigError> {
    match opt(get, key) {
        Some(v) => match v.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(invalid(key)),
        },
        None => Ok(default),
    }
}

#[cfg(test)]
mod server_mode_tests {
    use super::*;
    use std::collections::HashMap;

    struct StubResolver;
    impl SecretResolver for StubResolver {
        fn resolve(&self, _r: &str) -> Result<Vec<u8>, ConfigError> {
            Ok(vec![1, 2, 3])
        }
    }

    fn base_env() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("PYS_POLICY_PATH".into(), "/tmp/policy.json".into());
        m.insert("PYS_GUEST_ARTIFACT_DIGEST".into(), "deadbeef".into());
        m.insert("PYS_AUDIT_HMAC_KEY_REF".into(), "/tmp/key".into());
        m
    }

    fn load(env: &HashMap<String, String>) -> Result<Config, ConfigError> {
        Config::load(&|k| env.get(k).cloned(), &StubResolver)
    }

    #[test]
    fn loads_without_oidc() {
        let cfg = load(&base_env()).expect("loads");
        assert!(cfg.oidc_issuer.is_none());
        assert!(cfg.oidc_client_id.is_none());
    }

    #[test]
    fn require_oidc_fails_when_absent() {
        let cfg = load(&base_env()).unwrap();
        assert_eq!(cfg.require_oidc().unwrap_err().code, "CFG_MISSING");
    }

    #[test]
    fn require_oidc_ok_when_present() {
        let mut env = base_env();
        env.insert("PYS_OIDC_ISSUER".into(), "https://idp.example".into());
        env.insert("PYS_OIDC_CLIENT_ID".into(), "faradayd".into());
        let cfg = load(&env).unwrap();
        assert!(cfg.require_oidc().is_ok());
    }

    #[test]
    fn invalid_issuer_scheme_rejected() {
        let mut env = base_env();
        env.insert("PYS_OIDC_ISSUER".into(), "ftp://bad".into());
        assert_eq!(load(&env).unwrap_err().code, "CFG_INVALID");
    }

    #[test]
    fn file_resolver_missing_file_fails_closed() {
        // The bootstrap resolves api_key secrets through this resolver; a missing key file
        // must fail closed (the source of the startup CFG_SECRET_UNRESOLVED, ADR-036).
        let e = FileSecretResolver
            .resolve("/nonexistent/faradayd/key")
            .unwrap_err();
        assert_eq!(e.code, "CFG_SECRET_UNRESOLVED");
    }
}

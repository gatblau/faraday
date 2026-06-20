//! Phase 1 integration gate (in-process; no external services): every Config
//! error-row fails closed, the WireError registry maps every code to its status,
//! and a panic routes to INTERNAL/500 with no detail on the wire.
#![cfg(feature = "integration")]

use faradayd::config::{Config, ConfigError, CredentialMode, SecretResolver};
use faradayd::errors::{recover, status_for, WireError};

struct OkResolver;
impl SecretResolver for OkResolver {
    fn resolve(&self, _r: &str) -> Result<Vec<u8>, ConfigError> {
        Ok(b"test-hmac-key".to_vec())
    }
}

/// A complete, valid env (no OTLP → mock mode). Individual tests override one key.
fn base(key: &str) -> Option<String> {
    match key {
        "PYS_OIDC_ISSUER" => Some("https://idp.example".to_string()),
        "PYS_OIDC_CLIENT_ID" => Some("faradayd".to_string()),
        "PYS_POLICY_PATH" => Some("/dev/null".to_string()),
        "PYS_GUEST_ARTIFACT_DIGEST" => Some("sha256:x".to_string()),
        "PYS_AUDIT_HMAC_KEY_REF" => Some("ref".to_string()),
        _ => None,
    }
}

#[test]
fn config_missing_required_fails_closed() {
    // PYS_OIDC_ISSUER is now optional (ADR-038); use a still-required var to assert the
    // fail-closed-on-missing-required behaviour.
    let get = |k: &str| {
        if k == "PYS_POLICY_PATH" {
            None
        } else {
            base(k)
        }
    };
    let err = Config::load(&get, &OkResolver).unwrap_err();
    assert_eq!(err.code, "CFG_MISSING");
    assert_eq!(err.field, "PYS_POLICY_PATH");
}

#[test]
fn config_non_https_issuer_is_invalid() {
    let get = |k: &str| {
        if k == "PYS_OIDC_ISSUER" {
            Some("http://idp.example".to_string())
        } else {
            base(k)
        }
    };
    assert_eq!(
        Config::load(&get, &OkResolver).unwrap_err().code,
        "CFG_INVALID"
    );
}

#[test]
fn config_response_cap_over_1mib_is_invalid() {
    let get = |k: &str| {
        if k == "PYS_RESPONSE_MAX_BYTES" {
            Some("2000000".to_string())
        } else {
            base(k)
        }
    };
    assert_eq!(
        Config::load(&get, &OkResolver).unwrap_err().code,
        "CFG_INVALID"
    );
}

#[test]
fn config_unresolvable_secret_fails_closed() {
    struct BadResolver;
    impl SecretResolver for BadResolver {
        fn resolve(&self, r: &str) -> Result<Vec<u8>, ConfigError> {
            Err(ConfigError {
                code: "CFG_SECRET_UNRESOLVED",
                field: r.to_string(),
            })
        }
    }
    assert_eq!(
        Config::load(&base, &BadResolver).unwrap_err().code,
        "CFG_SECRET_UNRESOLVED"
    );
}

#[test]
fn config_degrades_to_mock_without_otlp() {
    let cfg = Config::load(&base, &OkResolver).unwrap();
    assert_eq!(cfg.credential_mode, CredentialMode::Mock);
    assert_eq!(cfg.max_calls_per_run, 50);
    assert_eq!(cfg.max_calls_per_session, 500);
}

#[test]
fn config_real_mode_with_otlp() {
    let get = |k: &str| {
        if k == "PYS_OTLP_ENDPOINT" {
            Some("http://collector:4317".to_string())
        } else {
            base(k)
        }
    };
    let cfg = Config::load(&get, &OkResolver).unwrap();
    assert_eq!(cfg.credential_mode, CredentialMode::Real);
}

#[test]
fn wireerror_registry_maps_every_code() {
    for (code, status) in [
        ("VAL_ERR", 400),
        ("POLICY_PATH_REJECTED", 400),
        ("STEP_UP_REQUIRED", 401),
        ("TOKEN_INVALID", 401),
        ("CAP_UNKNOWN", 403),
        ("CAP_INVALID", 403),
        ("RATE_LIMITED", 429),
        ("INTERNAL", 500),
        ("RUNTIME_ARTIFACT_MISMATCH", 500),
        ("OBO_UNAVAILABLE", 502),
        ("IDP_UNAVAILABLE", 503),
        ("DOWNSTREAM_TIMEOUT", 504),
    ] {
        assert_eq!(status_for(code), status, "code {code}");
    }
    // Registry miss → INTERNAL (XC2).
    assert_eq!(status_for("NOT_A_REAL_CODE"), 500);
}

#[test]
fn wireerror_truncates_message_and_emits_clean_json() {
    let e = WireError::new("VAL_ERR", &"x".repeat(500));
    assert!(e.error.len() <= 200, "message must be truncated");
    let json = e.to_json();
    assert!(json.contains("\"code\":\"VAL_ERR\""));
}

#[test]
fn panic_recovers_to_internal_with_no_detail_on_the_wire() {
    // Silence the default server-side panic print during the test.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = recover(|| -> i32 { panic!("boom: token=supersecret") });
    std::panic::set_hook(prev);

    let err = result.unwrap_err();
    assert_eq!(err.code, "INTERNAL");
    assert_eq!(err.status(), 500);
    assert!(
        !err.to_json().contains("boom") && !err.to_json().contains("supersecret"),
        "the panic detail must never reach the wire body"
    );
}

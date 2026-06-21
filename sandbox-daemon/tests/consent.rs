//! Phase 4 integration gate: C8 ConsentUI against a real `dexidp/dex` OIDC provider.
//!
//! Covers the deterministic, security-critical core: OIDC discovery + JWKS-validated
//! real Dex `id_token` → `Principal`, a tampered token rejected, headless fail-closed
//! (`INTERACTION_UNAVAILABLE`), and consent allow/decline. The interactive
//! authorization-code + PKCE browser capture and the elevated-`acr` step-up re-issue
//! are manually verified (RISK-004) — Dex's password connector emits no `acr` and the
//! browser flow needs a human, so they are out of this headless gate.
#![cfg(feature = "integration")]

use std::time::Duration;

use faradayd::interaction::{ConsentSummary, ConsentUI, InteractionOutcome, InteractionSurface};
use faradayd::types::{ClientIdentity, InteractionRequired};
use testcontainers::{
    core::{IntoContainerPort, Mount},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

/// Dex issuer pinned to a fixed host port so the token `iss` matches the daemon's
/// discovery URL (the classic Dex-in-containers issuer/port constraint).
const DEX_ISSUER: &str = "http://127.0.0.1:5556/dex";
const CLIENT_ID: &str = "faradayd";
const CLIENT_SECRET: &str = "pysandbox-secret";

/// A programmable interaction surface — the test stands in for the human.
struct StubSurface {
    available: bool,
    consent: bool,
}
impl InteractionSurface for StubSurface {
    fn available(&self) -> bool {
        self.available
    }
    fn open(&self, _url: &str) {}
    fn confirm_consent(&self, _summary: &ConsentSummary) -> bool {
        self.consent
    }
}

fn make_ui(available: bool, consent: bool) -> ConsentUI {
    ConsentUI::new(
        DEX_ISSUER.to_string(),
        CLIENT_ID.to_string(),
        "openid profile email".to_string(),
        "auto".to_string(),
        Box::new(StubSurface { available, consent }),
    )
    .unwrap()
}

fn consent_request() -> InteractionRequired {
    InteractionRequired::Consent {
        capability_id: "internal.tickets".into(),
        host: "tickets.example.com".into(),
        methods: vec!["GET".into()],
        provider: "rfc8693".into(),
        require_step_up: false,
    }
}

/// Start Dex with a memory store, password DB, and one static client.
async fn start_dex() -> testcontainers::ContainerAsync<GenericImage> {
    // bcrypt("password"), verified to verify under Dex's golang bcrypt. A test-only
    // fixture for the ephemeral Dex container, not a secret.
    let hash = "$2y$10$N/3FzpIqyUXPz0mTY0k6NO0R7TMcPWUkRgp/Zt1UEVbKynGlqUjTW";
    let config = format!(
        r#"issuer: {DEX_ISSUER}
storage:
  type: memory
web:
  http: 0.0.0.0:5556
enablePasswordDB: true
staticPasswords:
- email: "test@example.com"
  hash: "{hash}"
  username: "test"
  userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
oauth2:
  passwordConnector: local
staticClients:
- id: {CLIENT_ID}
  secret: {CLIENT_SECRET}
  name: faradayd
  redirectURIs:
  - http://127.0.0.1/callback
"#
    );
    let dir = std::env::temp_dir().join(format!("pysd-dex-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.yaml");
    std::fs::write(&cfg_path, config).unwrap();

    GenericImage::new("dexidp/dex", "v2.39.1")
        .with_exposed_port(5556.tcp())
        .with_mapped_port(5556, 5556.tcp())
        .with_mount(Mount::bind_mount(
            cfg_path.to_string_lossy().to_string(),
            "/etc/dex/config.yaml",
        ))
        .with_cmd(["dex", "serve", "/etc/dex/config.yaml"])
        .start()
        .await
        .expect("start dex container")
}

/// Poll the discovery endpoint until Dex answers (robust to log-line wording).
async fn wait_ready(http: &reqwest::Client) {
    for attempt in 0..60u32 {
        if let Ok(r) = http
            .get(format!("{DEX_ISSUER}/.well-known/openid-configuration"))
            .send()
            .await
        {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        if attempt == 59 {
            panic!("dex discovery never became ready");
        }
    }
}

/// Obtain a real `id_token` via the OAuth2 resource-owner password grant.
async fn password_grant(http: &reqwest::Client) -> String {
    let form = [
        ("grant_type", "password"),
        ("scope", "openid email profile"),
        ("username", "test@example.com"),
        ("password", "password"),
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
    ];
    let resp = http
        .post(format!("{DEX_ISSUER}/token"))
        .form(&form)
        .send()
        .await
        .expect("token request");
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert!(
        status.is_success(),
        "dex password grant failed: {status} — {text}"
    );
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    body["id_token"]
        .as_str()
        .expect("id_token in token response")
        .to_string()
}

#[tokio::test]
async fn c8_validates_real_dex_token_headless_and_consent() {
    let _guard = start_dex().await;
    let http = reqwest::Client::new();
    wait_ready(&http).await;

    let id_token = password_grant(&http).await;
    let who = ClientIdentity {
        principal: "501".into(),
        client_label: "vscode".into(),
    };

    // 1) JWKS-validated real Dex token → Principal (discovery + RS256 + iss/aud).
    let ui = make_ui(true, true);
    let principal = ui
        .validate_for_test(&id_token)
        .await
        .expect("validate real Dex id_token");
    assert!(!principal.subject.is_empty(), "subject must be populated");
    assert_eq!(principal.issuer, DEX_ISSUER, "iss must match the issuer");

    // 2) A tampered token fails closed.
    let tampered = format!("{id_token}x");
    assert_eq!(
        ui.validate_for_test(&tampered).await.unwrap_err().code(),
        "SIGN_IN_FAILED"
    );

    // 3) Headless (no surface) → INTERACTION_UNAVAILABLE, fail closed.
    let headless = make_ui(false, true);
    let err = headless
        .require(
            &who,
            InteractionRequired::SignIn {
                issuer: DEX_ISSUER.to_string(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), "INTERACTION_UNAVAILABLE");

    // 4) Consent declined → INTERACTION_DENIED; approved → Allowed.
    let decline = make_ui(true, false);
    assert_eq!(
        decline
            .require(&who, consent_request())
            .await
            .unwrap_err()
            .code(),
        "INTERACTION_DENIED"
    );
    match ui.require(&who, consent_request()).await.unwrap() {
        InteractionOutcome::Allowed => {}
        other => panic!("expected Allowed, got {other:?}"),
    }
}

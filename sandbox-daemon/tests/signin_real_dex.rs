//! RISK-004 regression: the REAL `ConsentUI` interactive authorization-code + PKCE
//! loopback capture (ADR-029) against a real `dexidp/dex` provider — the automatable half
//! of the otherwise-manual browser check covered in `tests/consent.rs`.
//!
//! Guards the redirect-URI handling that previously broke sign-in (`Bad Request:
//! Unregistered redirect_uri`, then a hang): the daemon advertises a transient
//! `127.0.0.1:<ephemeral>` `redirect_uri`, and Dex must accept it under RFC 8252.
//!
//! Two conditions are load-bearing and both are asserted here by construction. First, the
//! Dex version is v2.42.0 or newer — earlier versions match the loopback exemption on host
//! `localhost` only, never the `127.0.0.1` IP literal the daemon uses. Second, the public
//! client registers NO `redirectURIs` — registering any switches Dex to exact-string
//! matching, which an ephemeral port can never satisfy.
//!
//! A scripted surface stands in for the human at the Dex login form; every other step —
//! discovery, listener bind, authorize URL, code capture, PKCE token exchange, JWKS
//! validation — is the production path.
#![cfg(all(feature = "integration", unix))]

use std::time::Duration;

use faradayd::interaction::{ConsentSummary, ConsentUI, InteractionSurface};
use testcontainers::{
    core::{IntoContainerPort, Mount},
    runners::AsyncRunner,
    GenericImage, ImageExt,
};

/// Dex issuer pinned to a fixed host port so the token `iss` matches the daemon's
/// discovery URL (the classic Dex-in-containers issuer/port constraint). A different
/// port from `tests/consent.rs` (5556) so both real-Dex gates can run concurrently.
const DEX_ISSUER: &str = "http://127.0.0.1:5557/dex";
const DEX_VERSION: &str = "v2.45.1";
const CLIENT_ID: &str = "faradayd";

/// A scripted browser: on `open(auth_url)` it performs the Dex password login so the
/// issued auth code redirects to the daemon's transient `127.0.0.1` listener — exactly
/// what a human browser would do. Non-blocking, mirroring the production `BrowserSurface`.
struct ScriptedDexBrowser;
impl InteractionSurface for ScriptedDexBrowser {
    fn available(&self) -> bool {
        true
    }
    fn open(&self, url: &str) {
        let url = url.to_string();
        tokio::spawn(async move {
            // Default reqwest client follows redirects (up to 10).
            let http = reqwest::Client::new();
            // 1) GET the authorize URL. Dex validates `redirect_uri` here (the regression
            //    point), then 302s to its local login form; the effective URL is that
            //    form's POST target.
            let form_url = match http.get(&url).send().await {
                Ok(r) => r.url().clone(),
                Err(e) => {
                    eprintln!("scripted-browser: authorize GET failed: {e}");
                    return;
                }
            };
            // 2) POST the test credentials. With `skipApprovalScreen`, Dex 303s straight
            //    through to the loopback callback, which reqwest follows — delivering
            //    ?code=&state= to the daemon listener that `capture_code` awaits.
            if let Err(e) = http
                .post(form_url)
                .form(&[("login", "test@example.com"), ("password", "password")])
                .send()
                .await
            {
                eprintln!("scripted-browser: login POST failed: {e}");
            }
        });
    }
    fn confirm_consent(&self, _summary: &ConsentSummary) -> bool {
        true
    }
}

/// Start Dex with a memory store, password DB, and one PUBLIC client carrying NO
/// `redirectURIs` (the configuration that enables the RFC 8252 any-port loopback
/// exemption). `skipApprovalScreen` lets the scripted login reach the callback in one POST.
async fn start_dex() -> testcontainers::ContainerAsync<GenericImage> {
    // bcrypt("password"); a test-only fixture for the ephemeral Dex container, not a secret.
    let hash = "$2y$10$N/3FzpIqyUXPz0mTY0k6NO0R7TMcPWUkRgp/Zt1UEVbKynGlqUjTW";
    let config = format!(
        r#"issuer: {DEX_ISSUER}
storage:
  type: memory
web:
  http: 0.0.0.0:5557
enablePasswordDB: true
oauth2:
  passwordConnector: local
  skipApprovalScreen: true
staticPasswords:
- email: "test@example.com"
  hash: "{hash}"
  username: "test"
  userID: "08a8684b-db88-4b73-90a9-3cd1661f5466"
staticClients:
- id: {CLIENT_ID}
  name: faradayd
  public: true
"#
    );
    let dir = std::env::temp_dir().join(format!("pysd-dex-signin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.yaml");
    std::fs::write(&cfg_path, config).unwrap();

    GenericImage::new("dexidp/dex", DEX_VERSION)
        .with_exposed_port(5557.tcp())
        .with_mapped_port(5557, 5557.tcp())
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

fn make_ui() -> ConsentUI {
    ConsentUI::new(
        DEX_ISSUER.to_string(),
        CLIENT_ID.to_string(),
        "openid profile email".to_string(),
        "auto".to_string(),
        Box::new(ScriptedDexBrowser),
    )
    .expect("construct ConsentUI")
}

/// The full loopback sign-in must complete against real Dex: the ephemeral `127.0.0.1`
/// redirect is accepted, the code is captured (state-checked) and exchanged with PKCE,
/// and the returned `id_token` is a JWKS-valid Dex token for this issuer and client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c8_loopback_signin_accepts_ephemeral_127_0_0_1_redirect() {
    let _guard = start_dex().await;
    wait_ready(&reqwest::Client::new()).await;

    let ui = make_ui();

    // Real path: discover -> bind 127.0.0.1:<ephemeral> -> authorize (Dex accepts the
    // ephemeral loopback redirect) -> capture code -> PKCE exchange -> raw id_token.
    let id_token = ui
        .sign_in_capture_for_test()
        .await
        .expect("real-Dex loopback capture + PKCE exchange must succeed");
    assert_eq!(
        id_token.split('.').count(),
        3,
        "captured id_token must be a 3-part JWT"
    );

    // The captured token validates against Dex's JWKS, with iss/aud bound to this provider
    // and client — proving it is a genuine Dex token, not merely well-shaped.
    let principal = ui
        .validate_for_test(&id_token)
        .await
        .expect("captured id_token must validate against Dex JWKS");
    assert_eq!(principal.issuer, DEX_ISSUER, "iss must match the issuer");
    assert!(
        !principal.subject.is_empty(),
        "subject must be populated from the Dex token"
    );
}

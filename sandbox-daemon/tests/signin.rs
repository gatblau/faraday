//! Plan 04 Phase 2 gate (C8 interactive sign-in, ADR-029). Drives the **full loopback
//! capture + PKCE code-exchange path** of the real `ConsentUI` deterministically: a
//! stub OIDC serves discovery + token, and a scripted-browser `InteractionSurface`
//! plays the redirect to the daemon's transient `127.0.0.1` listener. Proves the
//! mechanism end-to-end (code captured, state-checked, exchanged) and that a `state`
//! mismatch fails closed. The JWKS-validation core is covered against real Dex in
//! `tests/consent.rs`; the real-browser sign-in is the manual check (RISK-004).
#![cfg(all(feature = "integration", unix))]

use faradayd::interaction::{ConsentSummary, ConsentUI, InteractionSurface};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A scripted browser: on `open(auth_url)`, parse `redirect_uri` + `state` and hit the
/// daemon's loopback listener as the IdP redirect would (optionally with a bad state).
struct ScriptedBrowser {
    bad_state: bool,
}
impl InteractionSurface for ScriptedBrowser {
    fn available(&self) -> bool {
        true
    }
    fn open(&self, url: &str) {
        let parsed = reqwest::Url::parse(url).expect("auth url");
        let mut redirect_uri = None;
        let mut state = None;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "redirect_uri" => redirect_uri = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                _ => {}
            }
        }
        let redirect_uri = redirect_uri.expect("redirect_uri in auth url");
        let state = if self.bad_state {
            "WRONG-STATE".to_string()
        } else {
            state.expect("state in auth url")
        };
        let target = format!("{redirect_uri}?code=stub-code&state={state}");
        // Fire the redirect to the loopback listener (capture_code is awaiting accept).
        tokio::spawn(async move {
            let _ = reqwest::Client::new().get(&target).send().await;
        });
    }
    fn confirm_consent(&self, _summary: &ConsentSummary) -> bool {
        true
    }
}

/// Minimal stub OIDC: `/.well-known/openid-configuration` + `/token`. `/authorize` is
/// never hit (the scripted browser synthesises the redirect from the auth URL).
async fn spawn_stub_oidc() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let disc = format!(
        r#"{{"issuer":"{base}","authorization_endpoint":"{base}/authorize","token_endpoint":"{base}/token","jwks_uri":"{base}/jwks"}}"#
    );
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let disc = disc.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let line = req.lines().next().unwrap_or("");
                let body = if line.contains("/.well-known/openid-configuration") {
                    disc.clone()
                } else if line.contains("/token") {
                    r#"{"id_token":"stub-id-token","token_type":"Bearer"}"#.to_string()
                } else {
                    "{}".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            });
        }
    });
    base
}

fn ui(issuer: &str, bad_state: bool) -> ConsentUI {
    ConsentUI::new(
        issuer.to_string(),
        "faradayd".to_string(),
        "openid profile email".to_string(),
        "auto".to_string(),
        Box::new(ScriptedBrowser { bad_state }),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signin_loopback_captures_and_exchanges() {
    let issuer = spawn_stub_oidc().await;
    let id_token = ui(&issuer, false)
        .sign_in_capture_for_test()
        .await
        .expect("loopback capture + exchange");
    assert_eq!(
        id_token, "stub-id-token",
        "the exchanged id_token is returned"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signin_rejects_state_mismatch() {
    let issuer = spawn_stub_oidc().await;
    let err = ui(&issuer, true)
        .sign_in_capture_for_test()
        .await
        .expect_err("state mismatch must fail closed");
    assert_eq!(
        err.code(),
        "SIGN_IN_FAILED",
        "CSRF guard rejects a bad state"
    );
}

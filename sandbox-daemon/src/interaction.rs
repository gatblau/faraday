//! C8 — ConsentUI. Renders `InteractionRequired` (sign-in / consent / step-up,
//! ADR-025) on a daemon-owned surface and returns the result to the Controller.
//! A client-asserted result is never trusted — sign-in runs a real OIDC flow and the
//! `id_token` is validated against the issuer's JWKS before a `Principal` is produced.
//!
//! The interactive authorization-code + PKCE browser capture and the elevated-`acr`
//! step-up re-issue are exercised in production but not headlessly (RISK-004); the
//! security-critical token-validation core is. The `id_token` is never logged.

use crate::types::{ClientIdentity, InteractionRequired, Principal};
use base64::Engine;
use serde::Deserialize;
use std::time::Duration;

/// The human-facing surface (browser / native dialog). Abstracted so the daemon owns
/// the OIDC protocol while the renderer stays swappable and testable.
pub trait InteractionSurface: Send + Sync {
    /// Whether any interactive surface exists; `false` ⇒ headless ⇒ fail closed.
    fn available(&self) -> bool;
    /// Open `url` in the user's browser (best-effort; the redirect is captured locally).
    fn open(&self, url: &str);
    /// Present a consent prompt; `true` ⇒ the user approved.
    fn confirm_consent(&self, summary: &ConsentSummary) -> bool;
}

/// What the user is asked to approve for a `Consent` interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentSummary {
    pub client_label: String,
    pub capability_id: String,
    pub host: String,
    pub methods: Vec<String>,
    pub provider: String,
    pub require_step_up: bool,
}

/// The result of a satisfied interaction. `SignedIn` carries the fresh OIDC tokens —
/// the `id_token` (subject token for the obo exchange) and the `access_token`
/// (forwarded to pass-through providers). Both are sensitive and never logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionOutcome {
    SignedIn {
        principal: Principal,
        id_token: String,
        access_token: String,
    },
    Allowed,
}

/// Typed interaction failure (Phase-4 XC2 registry codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionError {
    /// User declined a consent prompt.
    Denied,
    /// No interactive surface available (headless) — the call fails closed.
    Unavailable,
    /// OIDC sign-in flow error (discovery, code exchange, or token validation).
    SignInFailed,
}

impl InteractionError {
    pub fn code(&self) -> &'static str {
        match self {
            InteractionError::Denied => "INTERACTION_DENIED",
            InteractionError::Unavailable => "INTERACTION_UNAVAILABLE",
            InteractionError::SignInFailed => "SIGN_IN_FAILED",
        }
    }
}

pub struct ConsentUI {
    issuer: String,
    client_id: String,
    /// OAuth scopes requested at sign-in (`PYS_OIDC_SCOPES`); space-separated.
    scopes: String,
    /// `PYS_CONSENT_UI_MODE` (`browser`/`dialog`/`auto`); retained for surface selection.
    #[allow(dead_code)]
    ui_mode: String,
    http: reqwest::Client,
    surface: Box<dyn InteractionSurface>,
}

impl ConsentUI {
    pub fn new(
        issuer: String,
        client_id: String,
        scopes: String,
        ui_mode: String,
        surface: Box<dyn InteractionSurface>,
    ) -> Result<ConsentUI, InteractionError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|_| InteractionError::SignInFailed)?;
        Ok(ConsentUI {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id,
            scopes: if scopes.trim().is_empty() {
                "openid profile email".to_string()
            } else {
                scopes
            },
            ui_mode,
            http,
            surface,
        })
    }

    /// Render the interaction and return its outcome. Fails closed when no surface
    /// is available (`INTERACTION_UNAVAILABLE`).
    pub async fn require(
        &self,
        who: &ClientIdentity,
        what: InteractionRequired,
    ) -> Result<InteractionOutcome, InteractionError> {
        if !self.surface.available() {
            return Err(InteractionError::Unavailable);
        }
        match what {
            InteractionRequired::SignIn { .. } => {
                let (principal, id_token, access_token) = self.sign_in(&[]).await?;
                Ok(InteractionOutcome::SignedIn {
                    principal,
                    id_token,
                    access_token,
                })
            }
            InteractionRequired::StepUp { acr_values, .. } => {
                let (principal, id_token, access_token) = self.sign_in(&acr_values).await?;
                Ok(InteractionOutcome::SignedIn {
                    principal,
                    id_token,
                    access_token,
                })
            }
            InteractionRequired::Consent {
                capability_id,
                host,
                methods,
                provider,
                require_step_up,
            } => {
                let summary = ConsentSummary {
                    client_label: who.client_label.clone(),
                    capability_id,
                    host,
                    methods,
                    provider,
                    require_step_up,
                };
                if self.surface.confirm_consent(&summary) {
                    Ok(InteractionOutcome::Allowed)
                } else {
                    Err(InteractionError::Denied)
                }
            }
        }
    }

    /// Run the OIDC authorization-code + PKCE flow, optionally requesting `acr_values`
    /// (step-up). Interactive — manually verified (RISK-004); not headlessly tested.
    async fn sign_in(
        &self,
        acr_values: &[String],
    ) -> Result<(Principal, String, String), InteractionError> {
        let (id_token, access_token) = self.capture_and_exchange(acr_values).await?;
        let principal = self.validate_id_token(&id_token).await?;
        Ok((principal, id_token, access_token))
    }

    /// The loopback capture + PKCE code-exchange half of sign-in: discover, bind a
    /// transient `127.0.0.1` redirect listener, open the browser, capture the code
    /// (state-checked), and exchange it for the raw `id_token`. Validation is separate.
    async fn capture_and_exchange(
        &self,
        acr_values: &[String],
    ) -> Result<(String, String), InteractionError> {
        let disc = self.discover().await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| InteractionError::SignInFailed)?;
        let port = listener
            .local_addr()
            .map_err(|_| InteractionError::SignInFailed)?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");

        let verifier = random_b64url(32)?;
        let challenge = pkce_challenge(&verifier);
        let state = random_b64url(24)?;
        let auth_url = build_auth_url(
            &disc.authorization_endpoint,
            &self.client_id,
            &redirect_uri,
            &self.scopes,
            &challenge,
            &state,
            acr_values,
        )?;

        self.surface.open(&auth_url);
        let code = capture_code(listener, &state)
            .await
            .ok_or(InteractionError::SignInFailed)?;
        self.exchange_code(&disc.token_endpoint, &code, &verifier, &redirect_uri)
            .await
    }

    /// Integration-test seam: drive the full loopback capture + PKCE exchange against a
    /// stub OIDC and return the raw (pre-validation) `id_token`. The JWKS-validation
    /// core is separately exercised against real Dex (`tests/consent.rs`).
    #[cfg(feature = "integration")]
    pub async fn sign_in_capture_for_test(&self) -> Result<String, InteractionError> {
        self.capture_and_exchange(&[]).await.map(|(id, _)| id)
    }

    /// Fetch the OIDC discovery document.
    async fn discover(&self) -> Result<OidcDiscovery, InteractionError> {
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        self.http
            .get(url)
            .send()
            .await
            .map_err(|_| InteractionError::SignInFailed)?
            .error_for_status()
            .map_err(|_| InteractionError::SignInFailed)?
            .json::<OidcDiscovery>()
            .await
            .map_err(|_| InteractionError::SignInFailed)
    }

    /// Exchange the authorization code for tokens at the token endpoint (PKCE).
    async fn exchange_code(
        &self,
        token_endpoint: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<(String, String), InteractionError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &self.client_id),
            ("code_verifier", verifier),
        ];
        let tok: TokenResponse = self
            .http
            .post(token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|_| InteractionError::SignInFailed)?
            .error_for_status()
            .map_err(|_| InteractionError::SignInFailed)?
            .json()
            .await
            .map_err(|_| InteractionError::SignInFailed)?;
        Ok((tok.id_token, tok.access_token))
    }

    /// Validate an `id_token`: fetch JWKS, verify the RS256 signature against the
    /// matching key, and re-check `iss`/`aud` (ADR-012), then extract a `Principal`.
    async fn validate_id_token(&self, id_token: &str) -> Result<Principal, InteractionError> {
        let disc = self.discover().await?;
        let jwks: Jwks = self
            .http
            .get(&disc.jwks_uri)
            .send()
            .await
            .map_err(|_| InteractionError::SignInFailed)?
            .error_for_status()
            .map_err(|_| InteractionError::SignInFailed)?
            .json()
            .await
            .map_err(|_| InteractionError::SignInFailed)?;

        let header =
            jsonwebtoken::decode_header(id_token).map_err(|_| InteractionError::SignInFailed)?;
        let kid = header.kid.ok_or(InteractionError::SignInFailed)?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == kid && k.kty == "RSA")
            .ok_or(InteractionError::SignInFailed)?;

        let key = jsonwebtoken::DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|_| InteractionError::SignInFailed)?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.client_id]);

        let data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|_| InteractionError::SignInFailed)?;
        let c = data.claims;
        Ok(Principal {
            subject: c.sub,
            issuer: c.iss,
            acr: c.acr,
            amr: c.amr,
            auth_time: c.auth_time,
        })
    }

    /// Integration-test seam: drive the JWKS-backed validation core against a real
    /// IdP-issued token (the interactive browser capture is manually verified).
    #[cfg(feature = "integration")]
    pub async fn validate_for_test(&self, id_token: &str) -> Result<Principal, InteractionError> {
        self.validate_id_token(id_token).await
    }
}

// ---- OIDC wire shapes ----

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    /// The OAuth access token issued alongside the id_token. Defaulted so sign-in for
    /// exchange-only deployments (where the IdP may omit it) does not fail; an empty
    /// value simply means no pass-through call can be authorised this session.
    #[serde(default)]
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    acr: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default)]
    auth_time: Option<i64>,
}

// ---- helpers ----

/// Build the authorization-endpoint URL with PKCE and optional `acr_values`.
fn build_auth_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &str,
    challenge: &str,
    state: &str,
    acr_values: &[String],
) -> Result<String, InteractionError> {
    let mut url =
        reqwest::Url::parse(authorization_endpoint).map_err(|_| InteractionError::SignInFailed)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", client_id);
        q.append_pair("redirect_uri", redirect_uri);
        q.append_pair("scope", scopes);
        q.append_pair("state", state);
        q.append_pair("code_challenge", challenge);
        q.append_pair("code_challenge_method", "S256");
        if !acr_values.is_empty() {
            q.append_pair("acr_values", &acr_values.join(" "));
        }
    }
    Ok(url.to_string())
}

/// `n` random bytes, base64url-no-pad encoded (PKCE verifier / state / nonce).
fn random_b64url(n: usize) -> Result<String, InteractionError> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|_| InteractionError::SignInFailed)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// PKCE S256 challenge = base64url(sha256(verifier)).
fn pkce_challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Accept the single browser redirect, verify `state`, and return the `code`.
async fn capture_code(listener: tokio::net::TcpListener, expected_state: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(300), listener.accept())
        .await
        .ok()?
        .ok()?;
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).await.ok()?;
    let request = String::from_utf8_lossy(&buf[..n]);
    let request_line = request.lines().next()?;
    let path = request_line.split_whitespace().nth(1)?;
    let query = path.split_once('?')?.1;

    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("code=") {
            code = Some(url_decode(v));
        } else if let Some(v) = pair.strip_prefix("state=") {
            state = Some(url_decode(v));
        }
    }

    let body = "<html><body>Sign-in complete. You may close this window.</body></html>";
    let _ = stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        )
        .await;

    if state.as_deref() != Some(expected_state) {
        return None; // CSRF guard: reject a mismatched/absent state.
    }
    code
}

/// Minimal percent-decoder for query values (`+` → space, `%XX` → byte).
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

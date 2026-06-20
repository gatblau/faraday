//! C10 — DownstreamClient. Issues the direct-provider HTTPS call with the
//! broker-held credential applied. No cross-origin redirect is ever followed
//! (AS-17: a 3xx is returned as-is, so `Authorization` is never re-sent to another
//! host). The body is read under a hard size cap, and a per-call timeout is enforced.
//!
//! Egress is HTTPS-only, with one bounded dev exception (ADR-032): when
//! `PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS` is set, a `127.0.0.1` provider host — and only
//! that literal loopback IP — is dialled over plaintext `http`. A remote host can never
//! be downgraded, so a forwarded credential never leaves the machine in cleartext.

use crate::errors::WireError;
use crate::types::{Params, RawResponse, ResolvedCapability};
use std::time::Duration;

/// Default per-call timeout. §2D defines no `PYS_*` variable for it; a follow-up
/// tracks adding one. Injectable via [`DownstreamClient::new`] so it is never a
/// hidden constant at the call site.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Typed failure of a downstream call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownstreamError {
    /// The per-call timeout elapsed.
    Timeout,
    /// Connection / TLS / transport error.
    Unavailable,
}

impl DownstreamError {
    /// The wire/registry code for this failure (Phase-4 XC2 registry).
    pub fn code(&self) -> &'static str {
        match self {
            DownstreamError::Timeout => "DOWNSTREAM_TIMEOUT",
            DownstreamError::Unavailable => "DOWNSTREAM_UNAVAILABLE",
        }
    }

    /// Map to the single wire-error envelope.
    pub fn to_wire(&self) -> WireError {
        let msg = match self {
            DownstreamError::Timeout => "downstream timed out",
            DownstreamError::Unavailable => "downstream unavailable",
        };
        WireError::new(self.code(), msg)
    }
}

/// How `do_call` chooses the URL scheme. Production is HTTPS-only unless ADR-032's dev
/// toggle is set, in which case a `127.0.0.1` host — and only that — uses plaintext.
#[derive(Clone, Copy)]
enum SchemePolicy {
    /// HTTPS for every host (production default).
    HttpsOnly,
    /// `http` for a `127.0.0.1` host (ADR-032); `https` for every other host.
    PlaintextLoopback,
    /// `http` for every host — integration-test stubs only.
    #[cfg(feature = "integration")]
    ForcePlaintext,
}

pub struct DownstreamClient {
    scheme_policy: SchemePolicy,
    http: reqwest::Client,
    max_bytes: u64,
}

impl DownstreamClient {
    /// Production constructor: HTTPS-only by default. When `allow_plaintext_loopback` is
    /// set (ADR-032, `PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS`), a `127.0.0.1` provider host —
    /// and only that — is dialled over plaintext `http`; every other host stays HTTPS.
    pub fn new(
        max_bytes: u64,
        timeout: Duration,
        allow_plaintext_loopback: bool,
    ) -> Result<DownstreamClient, WireError> {
        let policy = if allow_plaintext_loopback {
            SchemePolicy::PlaintextLoopback
        } else {
            SchemePolicy::HttpsOnly
        };
        Self::build(policy, max_bytes, timeout)
    }

    /// Integration-test constructor: plaintext for every host against a containerised
    /// stub. Compiled only under the `integration` feature.
    #[cfg(feature = "integration")]
    pub fn new_plaintext(max_bytes: u64, timeout: Duration) -> Result<DownstreamClient, WireError> {
        Self::build(SchemePolicy::ForcePlaintext, max_bytes, timeout)
    }

    fn build(
        scheme_policy: SchemePolicy,
        max_bytes: u64,
        timeout: Duration,
    ) -> Result<DownstreamClient, WireError> {
        let http = reqwest::Client::builder()
            // Never follow a redirect: a cross-origin 3xx must be returned as-is so the
            // credential is never replayed to another host (AS-17).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| WireError::new("INTERNAL", "downstream client build"))?;
        Ok(DownstreamClient {
            scheme_policy,
            http,
            max_bytes,
        })
    }

    /// Issue the call. The host comes from policy (`cap.host`), never caller input;
    /// `apply` attaches the broker-held credential to the request.
    pub async fn do_call(
        &self,
        cap: &ResolvedCapability,
        verb: &str,
        canon_path: &str,
        params: &Params,
        body: &[u8],
        apply: impl Fn(&mut reqwest::Request),
    ) -> Result<RawResponse, DownstreamError> {
        let scheme = scheme_for(self.scheme_policy, &cap.host);
        let mut url = reqwest::Url::parse(&format!("{scheme}://{}{}", cap.host, canon_path))
            .map_err(|_| DownstreamError::Unavailable)?;
        if !params.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }

        let method = reqwest::Method::from_bytes(verb.as_bytes())
            .map_err(|_| DownstreamError::Unavailable)?;
        let mut req = self
            .http
            .request(method, url)
            .body(body.to_vec())
            .build()
            .map_err(|_| DownstreamError::Unavailable)?;
        apply(&mut req);

        let mut resp = self.http.execute(req).await.map_err(map_send_error)?;

        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();

        // Read up to max_bytes + 1 so we can flag truncation, without ever buffering
        // an unbounded hostile response.
        let mut buf: Vec<u8> = Vec::new();
        let mut truncated = false;
        while let Some(chunk) = resp.chunk().await.map_err(map_send_error)? {
            buf.extend_from_slice(&chunk);
            if buf.len() as u64 > self.max_bytes {
                buf.truncate(self.max_bytes as usize);
                truncated = true;
                break;
            }
        }

        Ok(RawResponse {
            status,
            headers,
            body: buf,
            truncated,
        })
    }
}

/// Resolve the URL scheme for a call. Pure (no I/O) so the ADR-032 boundary is unit-
/// testable: plaintext is reachable only via `PlaintextLoopback` + a `127.0.0.1` host.
fn scheme_for(policy: SchemePolicy, host: &str) -> &'static str {
    match policy {
        SchemePolicy::HttpsOnly => "https",
        // ADR-032: plaintext only for the literal loopback IP; any other host (a DNS
        // name, a public IP) stays HTTPS even with the dev toggle on.
        SchemePolicy::PlaintextLoopback if is_loopback_host(host) => "http",
        SchemePolicy::PlaintextLoopback => "https",
        #[cfg(feature = "integration")]
        SchemePolicy::ForcePlaintext => "http",
    }
}

/// True only for the literal loopback IP `127.0.0.1` (bare, or with a `:port`). A DNS
/// name — `localhost`, or a `127.0.0.1.evil.com` prefix trick — is never loopback, so
/// ADR-032's plaintext exception can never apply to a remote host.
fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host.starts_with("127.0.0.1:")
}

fn map_send_error(e: reqwest::Error) -> DownstreamError {
    if e.is_timeout() {
        DownstreamError::Timeout
    } else {
        DownstreamError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::{scheme_for, SchemePolicy};

    #[test]
    fn https_only_never_uses_plaintext() {
        // Happy path / default posture: every host is HTTPS, loopback included.
        assert_eq!(
            scheme_for(SchemePolicy::HttpsOnly, "127.0.0.1:8080"),
            "https"
        );
        assert_eq!(
            scheme_for(SchemePolicy::HttpsOnly, "api.example.com"),
            "https"
        );
    }

    #[test]
    fn loopback_ip_uses_plaintext_when_enabled() {
        // ADR-032 dev exception: the literal loopback IP, bare or with a port.
        assert_eq!(
            scheme_for(SchemePolicy::PlaintextLoopback, "127.0.0.1"),
            "http"
        );
        assert_eq!(
            scheme_for(SchemePolicy::PlaintextLoopback, "127.0.0.1:8080"),
            "http"
        );
    }

    #[test]
    fn remote_and_name_hosts_stay_https_even_when_enabled() {
        // Security boundary: only the loopback IP qualifies. A public host, a DNS name
        // (`localhost`), and a prefix trick all stay HTTPS — a forwarded credential can
        // never leave the machine in cleartext.
        for host in [
            "api.example.com",
            "localhost",
            "127.0.0.1.evil.com",
            "127.0.0.1.evil.com:443",
            "10.0.0.1",
        ] {
            assert_eq!(
                scheme_for(SchemePolicy::PlaintextLoopback, host),
                "https",
                "host {host} must not be downgraded to http"
            );
        }
    }
}

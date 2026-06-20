//! C15 — HealthCheck (XC7). Local-only liveness/readiness for the per-user service
//! (ADR-023), consumed over the control socket by the OS service manager. Liveness is
//! immediate; readiness pings the OIDC discovery endpoint and (if configured) the
//! `obo-broker` health route with short timeouts, aggregating failures.

use std::time::Duration;

pub struct HealthCheck {
    issuer: String,
    obo_endpoint: Option<String>,
    http: reqwest::Client,
}

impl HealthCheck {
    pub fn new(issuer: String, obo_endpoint: Option<String>) -> HealthCheck {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        HealthCheck {
            issuer,
            obo_endpoint,
            http,
        }
    }

    /// Liveness: the process is up. Returns immediately, independent of dependencies.
    pub fn live(&self) -> bool {
        true
    }

    /// Readiness: ready only if OIDC discovery and (if configured) the obo-broker are
    /// reachable; otherwise `(false, failed)` lists the unreachable dependencies.
    pub async fn ready(&self) -> (bool, Vec<String>) {
        let mut failed = Vec::new();
        if !self
            .reachable(&format!(
                "{}/.well-known/openid-configuration",
                self.issuer.trim_end_matches('/')
            ))
            .await
        {
            failed.push("idp".to_string());
        }
        if let Some(obo) = &self.obo_endpoint {
            if !self
                .reachable(&format!("{}/healthz", obo.trim_end_matches('/')))
                .await
            {
                failed.push("obo".to_string());
            }
        }
        (failed.is_empty(), failed)
    }

    async fn reachable(&self, url: &str) -> bool {
        self.http
            .get(url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

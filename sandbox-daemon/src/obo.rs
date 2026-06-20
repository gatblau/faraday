//! C9 — OboClient. Calls the backend `obo-broker` `POST /v1/exchange` for
//! token-exchange providers and surfaces the RFC 9470 step-up challenge.
//!
//! The privileged downstream token is never returned by the backend, never enters
//! this process, and the user `id_token` is never logged (ADR-007). This module
//! emits no log lines at all — there is nothing here to leak.

use crate::errors::WireError;
use crate::types::{Params, ResolvedCapability, UntrustedResponse};
use serde::Serialize;

/// Typed failure of an exchange. `StepUpRequired` carries the structured RFC 9470
/// challenge so the Controller can raise C8 step-up and retry once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OboError {
    /// `401 insufficient_user_authentication` — step-up assurance required.
    StepUpRequired {
        acr_values: Vec<String>,
        max_age: Option<u64>,
    },
    /// Backend unreachable or `5xx`.
    Unavailable,
    /// Exchange rejected (a non-step-up `4xx`).
    ExchangeFailed,
}

impl OboError {
    /// The wire/registry code for this failure (Phase-4 XC2 registry).
    pub fn code(&self) -> &'static str {
        match self {
            OboError::StepUpRequired { .. } => "STEP_UP_REQUIRED",
            OboError::Unavailable => "OBO_UNAVAILABLE",
            OboError::ExchangeFailed => "EXCHANGE_FAILED",
        }
    }

    /// Map to the single wire-error envelope.
    pub fn to_wire(&self) -> WireError {
        let msg = match self {
            OboError::StepUpRequired { .. } => "step-up authentication required",
            OboError::Unavailable => "obo-broker unavailable",
            OboError::ExchangeFailed => "token exchange failed",
        };
        WireError::new(self.code(), msg)
    }
}

/// Request body for `POST /v1/exchange` (field names are the obo-broker contract,
/// `../obo-broker/08-interfaces.md`).
#[derive(Serialize)]
struct ExchangeRequest<'a> {
    #[serde(rename = "userIdToken")]
    user_id_token: &'a str,
    #[serde(rename = "capabilityId")]
    capability_id: &'a str,
    verb: &'a str,
    path: &'a str,
    #[serde(rename = "params", skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(rename = "body", skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

pub struct OboClient {
    base: String,
    http: reqwest::Client,
}

impl OboClient {
    /// Build a client targeting the `obo-broker` base URL (`PYS_OBO_ENDPOINT`).
    pub fn new(base: String) -> Result<OboClient, WireError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|_| WireError::new("INTERNAL", "obo client build"))?;
        Ok(OboClient {
            base: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// POST the exchange request; surface step-up; return the sanitized JSON envelope.
    pub async fn exchange(
        &self,
        id_token: &str,
        cap: &ResolvedCapability,
        verb: &str,
        path: &str,
        params: &Params,
        body: &[u8],
    ) -> Result<UntrustedResponse, OboError> {
        let req = ExchangeRequest {
            user_id_token: id_token,
            capability_id: &cap.id,
            verb,
            path,
            params: params_to_object(params),
            body: if body.is_empty() {
                None
            } else {
                Some(String::from_utf8_lossy(body).into_owned())
            },
        };

        let resp = self
            .http
            .post(format!("{}/v1/exchange", self.base))
            .json(&req)
            .send()
            .await
            .map_err(|_| OboError::Unavailable)?;

        let status = resp.status();

        if status.as_u16() == 401 {
            if let Some(challenge) = www_authenticate_step_up(&resp) {
                return Err(challenge);
            }
            return Err(OboError::ExchangeFailed);
        }
        if status.is_server_error() {
            return Err(OboError::Unavailable);
        }
        if !status.is_success() {
            return Err(OboError::ExchangeFailed);
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let bytes = resp.bytes().await.map_err(|_| OboError::Unavailable)?;

        Ok(UntrustedResponse {
            untrusted: true,
            status: status.as_u16(),
            content_type,
            body: bytes.to_vec(),
            truncated: false,
        })
    }
}

/// Convert ordered params to a JSON object for the request body (last value wins on
/// duplicate keys — the obo-broker contract models `params` as an object).
fn params_to_object(params: &Params) -> Option<serde_json::Map<String, serde_json::Value>> {
    if params.is_empty() {
        return None;
    }
    let mut map = serde_json::Map::new();
    for (k, v) in params {
        map.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    Some(map)
}

/// Parse a `401` response's `WWW-Authenticate` challenge. Only the RFC 9470
/// `insufficient_user_authentication` error is treated as step-up; `acr_values` is a
/// space-separated list, `max_age` is optional.
fn www_authenticate_step_up(resp: &reqwest::Response) -> Option<OboError> {
    let header = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)?
        .to_str()
        .ok()?;
    if !header.contains("insufficient_user_authentication") {
        return None;
    }
    let acr_values = auth_param(header, "acr_values")
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let max_age = auth_param(header, "max_age").and_then(|v| v.parse().ok());
    Some(OboError::StepUpRequired {
        acr_values,
        max_age,
    })
}

/// Extract `key="value"` (or bare `key=value`) from an auth-challenge header.
fn auth_param(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let start = header.find(&needle)? + needle.len();
    let rest = &header[start..];
    if let Some(rest) = rest.strip_prefix('"') {
        rest.find('"').map(|end| rest[..end].to_string())
    } else {
        let end = rest.find([',', ' ']).unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

//! Shared types catalogue (phase-2C). Defined once here; consumers reference them.
//! Only the types the current build needs are present; later phases extend this.

use std::collections::HashSet;

/// The authenticated connecting peer (server-derived, never client-asserted) — C6.
/// `principal` is the opaque, platform-neutral peer identity (decimal UID on Unix,
/// string SID on Windows); see `clientauth::PeerPrincipal`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientIdentity {
    pub principal: String,
    pub client_label: String,
}

/// A `(client, workspace)`-keyed session: consent cache + per-session budget — C7.
#[derive(Debug, Clone)]
pub struct Session {
    pub client: ClientIdentity,
    pub workspace_id: String,
    pub consented: HashSet<String>,
    pub calls_used: u32,
}

/// How the broker obtains the token it presents downstream for a capability — C4/C11.
/// Both modes derive the token from the OIDC provider; faraday holds no static secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Server-side token exchange via the obo-broker (C9): the privileged downstream
    /// token is minted by the broker backend and never enters this process. Default.
    #[default]
    Exchange,
    /// Forward the user's OIDC `access_token` straight to the service (C10), for a
    /// provider in the same trust domain that accepts the IdP-issued token. faraday
    /// holds the access token only to apply it; it is never returned to the guest.
    Passthrough,
    /// Unauthenticated: no credential is sent (server-mode, ADR-037). The call is still
    /// bound by the host/path/method allowlist, budgets, and audit. No sign-in required.
    /// Named `Unauthenticated` (not `None`) to avoid shadowing `Option::None`; the wire
    /// token is `none`.
    #[serde(rename = "none")]
    Unauthenticated,
    /// A static per-capability API key the broker applies to the outbound call (server-mode,
    /// ADR-036). The key is file-backed and held only in the broker; never reaches the guest.
    /// `rename_all = "lowercase"` would yield `apikey`, so the wire token is set explicitly.
    #[serde(rename = "api_key")]
    ApiKey,
}

/// How an `api_key` capability's resolved key is attached to the outbound request — C4/C11
/// (ADR-036). `rename_all = "lowercase"` maps the variant tags to the wire tokens
/// `header` / `query`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyPlacement {
    /// Attach as a request header `<name>: [<scheme> ]<key>` (scheme optional, e.g. `Token`).
    Header {
        name: String,
        #[serde(default)]
        scheme: Option<String>,
    },
    /// Attach as a query parameter `?<param>=<key>`.
    Query { param: String },
}

/// Selects a capability's allowlist shape — C4/C11/C17 (ADR-034).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityKind {
    /// REST/HTTP API: host + path + method allowlist. Default; also when `kind` is omitted.
    #[default]
    Rest,
    /// Downstream MCP server over HTTP/SSE: server origin + tool-name allowlist.
    Mcp,
}

/// A capability-manifest entry after lookup — C4.
#[derive(Debug, Clone)]
pub struct ResolvedCapability {
    pub id: String,
    pub provider: String,
    pub audience: Option<String>,
    pub scopes: Vec<String>,
    pub host: String,
    pub path_allow: Vec<regex::Regex>,
    pub methods: Vec<String>,
    pub require_step_up: bool,
    pub auth_mode: AuthMode,
    /// Server-mode write gate (ADR-039): a capability is read-only (`GET` only) unless
    /// this is set. Honoured only via the admin-signed load path. Default `false`.
    pub allow_write: bool,
    /// `api_key` mode (ADR-036): the `SecretResolver` reference for this capability's key
    /// (a file path under `FileSecretResolver`). `Some` iff `auth_mode == ApiKey`.
    pub secret_ref: Option<String>,
    /// `api_key` mode (ADR-036): how the resolved key is attached. `Some` iff `ApiKey`.
    pub key_placement: Option<KeyPlacement>,
    /// Capability kind (ADR-034). `Rest` uses `host`/`path_allow`/`methods`; `Mcp` uses
    /// `server_url`/`tool_allow`. Defaults to `Rest`; a manifest entry without `kind` is REST.
    pub kind: CapabilityKind,
    /// `Mcp` kind (ADR-034): the single allowlisted downstream MCP server origin (HTTPS, or a
    /// `127.0.0.1` loopback under the ADR-032 dev toggle). `Some` iff `kind == Mcp`.
    pub server_url: Option<String>,
    /// `Mcp` kind (ADR-034): the permitted downstream tool names (the `toolAllow` set).
    /// Empty for a `Rest` capability.
    pub tool_allow: Vec<String>,
}

/// The typed untrusted-content envelope returned to the guest (ADR-017) — C5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedResponse {
    pub untrusted: bool,
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// The validated user identity from the OIDC `id_token` (held only in the daemon) — C8/C11/C3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub subject: String,
    pub issuer: String,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    pub auth_time: Option<i64>,
}

/// A daemon→client interaction challenge (ADR-025); never client-asserted satisfied — C8/C13/C14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractionRequired {
    SignIn {
        issuer: String,
    },
    Consent {
        capability_id: String,
        host: String,
        methods: Vec<String>,
        provider: String,
        require_step_up: bool,
    },
    StepUp {
        acr_values: Vec<String>,
        max_age_secs: u64,
    },
}

/// An opaque per-run capability handle bound to this daemon instance — C11/C12/C13.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityHandle {
    pub cap_id: [u8; 16],
    pub capability_id: String,
    pub expires_at: i64,
}

/// What the broker holds/acquires and applies to an outbound request; never returned — C11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    Bearer(String),
    Headers(std::collections::HashMap<String, String>),
}

/// The single agent-facing entry payload (native RPC and the MCP tool share it) — C13/C14.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunRequest {
    pub code: String,
    #[serde(default)]
    pub requested_capabilities: Vec<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub dry_run: bool,
    pub workspace_id: String,
    #[serde(default)]
    pub run_id: Option<String>,
}

/// A dry-run result: planned calls only (static resolution, ADR-009) — C13/C14.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DryRunResult {
    pub planned_calls: Vec<CallSummary>,
}

/// Identifies the calling session for a run: the authenticated peer + its workspace — C13/C14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHandle {
    pub client: ClientIdentity,
    pub workspace_id: String,
}

/// One named outbound call in a run summary; carries no body and no token — C12/C13/C14.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallSummary {
    pub provider: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub status: Option<u16>,
}

/// The result of a normal run; the downstream credential is NEVER included — C12/C13/C14.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub api_calls: Vec<CallSummary>,
    pub truncated: bool,
}

/// Query/body parameters for an outbound call (ordered; duplicates allowed) — C9/C10.
pub type Params = Vec<(String, String)>;

/// A raw downstream response before sanitisation (C10 → C5). Carries the wire status,
/// the response headers, the size-capped body, and whether the body hit the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// A raw MCP `tools/call` result before sanitisation (C17 → C5), ADR-034. Carries the
/// tool-level `is_error` flag, the content parts, optional structured content (raw JSON
/// bytes), and whether the transport read hit the size cap. C5 (`sanitize_mcp`) maps this
/// to the guest-facing untrusted envelope; the broker never auto-dereferences a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolResult {
    pub is_error: bool,
    pub content: Vec<McpContentPart>,
    pub structured_content: Option<Vec<u8>>,
    pub truncated: bool,
}

/// One content part of a raw MCP tool result (C17 → C5), ADR-034. A `ResourceLink` carries
/// a uri only — the broker never fetches it; an `EmbeddedResource` carries the inlined body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpContentPart {
    Text {
        content_type: String,
        body: Vec<u8>,
    },
    Image {
        mime_type: String,
        body: Vec<u8>,
    },
    ResourceLink {
        uri: String,
        mime_type: Option<String>,
    },
    EmbeddedResource {
        uri: String,
        mime_type: Option<String>,
        body: Vec<u8>,
    },
}

/// The guest-facing untrusted envelope for an MCP `tools/call` (ADR-017/ADR-034) — C5/C11.
/// Every part is untrusted and is never auto-fed to the model; a `ResourceLink` carries a
/// uri only and is never dereferenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedMcpResult {
    pub untrusted: bool,
    pub is_error: bool,
    pub parts: Vec<UntrustedPart>,
    pub truncated: bool,
}

/// One part of the guest-facing untrusted MCP envelope (ADR-034) — C5. `Json` carries the
/// tool's `structuredContent`; `ResourceLink` carries a uri only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntrustedPart {
    Text {
        content_type: String,
        body: Vec<u8>,
    },
    Json {
        body: Vec<u8>,
    },
    Image {
        mime_type: String,
        body: Vec<u8>,
    },
    ResourceLink {
        uri: String,
        mime_type: Option<String>,
    },
    EmbeddedResource {
        uri: String,
        mime_type: Option<String>,
        body: Vec<u8>,
    },
}

/// One audit record per outbound call (sizes + keyed-HMAC id; never tokens/bodies) — C3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub run_id: String,
    pub user_hmac: String,
    pub client_label: String,
    pub provider: String,
    pub capability_id: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status_code: u16,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration_ms: u64,
}

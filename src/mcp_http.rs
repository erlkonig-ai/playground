//! Streamable-HTTP MCP transport with per-sandbox bearer-token auth.
//!
//! This is the internet-facing half of the sandbox provider (the seam left on
//! [`crate::mcp::McpTransport`]): MCP's Streamable HTTP transport (spec rev
//! 2025-06-18) on a single `/mcp` endpoint, in front of the blocking
//! [`McpServer`](crate::mcp::McpServer) core.
//!
//! ## Protocol surface (v1)
//!
//! - `POST /mcp` — one JSON-RPC message per request body. Requests (with an
//!   `id`) get a single `application/json` JSON-RPC response; notifications
//!   get `202 Accepted`. The spec explicitly permits plain-JSON responses for
//!   servers that don't stream — SSE streaming (`Accept: text/event-stream`
//!   upgrades, server-push notifications, resumability) is a deliberate v2
//!   seam, see [`get_mcp`].
//! - `GET /mcp` — `405 Method Not Allowed` (that's the SSE seam).
//! - `DELETE /mcp` — explicit MCP-session termination.
//! - `Mcp-Session-Id` — issued on `initialize`, required on every subsequent
//!   request, expired after [`HttpServerConfig::idle_timeout`] of inactivity
//!   (checked lazily on access — no reaper thread) or on `DELETE`.
//! - JSON-RPC batch arrays are rejected (removed from the spec in 2025-06-18).
//!
//! ## Auth model (the product feature)
//!
//! Every request must carry `Authorization: Bearer <token>`. Tokens live in a
//! JSON [`TokenStore`] on disk (minted with `playground token mint`) and map
//! to a **tenant** (label + allowed backend). Enforcement, all *before*
//! dispatch, at this layer:
//!
//! - no/unknown token → `401`;
//! - token minted for a different backend than this server runs → `403`;
//! - `open_session` for a tenant other than the token's → `403` (a missing
//!   `tenant` argument is filled in from the token, so clients need not know
//!   their own label);
//! - `exec`/`close_session` against a sandbox session owned by another tenant
//!   → `403` (via [`SandboxProvider::session_tenant`]);
//! - an `Mcp-Session-Id` issued to another tenant's token → `403`.
//!
//! The stdio transport (`playground mcp`) stays unauthenticated by design: it
//! is operator-local, single-tenant-by-trust. HTTP is the multi-tenant
//! boundary.
//!
//! `Origin` is validated against an allowlist (DNS-rebinding defence):
//! requests *with* an `Origin` header are rejected unless the value was
//! passed via `--allow-origin`; requests without one (normal MCP clients,
//! curl) pass. Default bind is loopback; internet exposure is expected to go
//! through a TLS-terminating reverse proxy — this server speaks plain HTTP
//! only, TLS is deliberately out of scope.
//!
//! Static tokens require handing a secret out of band, which browser-based
//! MCP connectors (claude.ai, ChatGPT web) can't do — for those, an optional
//! OAuth 2.1 layer ([`crate::oauth`]) mounts discovery/registration/authorize
//! /token endpoints when `--public-url` + `--oauth-state` are given. OAuth
//! access tokens resolve to the same [`TokenEntry`] shape in [`authenticate`],
//! so every downstream check (backend, session, tenant scope) is shared.
//! Without those flags this file's behavior is unchanged.
//!
//! ## Concurrency design
//!
//! The provider and its backends are blocking (limactl/ssh subprocesses), the
//! HTTP stack is tokio. Rather than an actor or an outer lock, one
//! [`McpServer`] is shared in an `Arc` and every dispatch runs under
//! `tokio::task::spawn_blocking`. This is sound because the server core is
//! already `&self` + interior locking: the provider's session-registry
//! `Mutex` is held only for map lookups, never across a backend call, so
//! concurrent `exec`s from different sandboxes genuinely run in parallel on
//! the blocking pool while the async side stays unblocked. The HTTP-session
//! map here follows the same shape (a `Mutex<HashMap>` held for lookups
//! only).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::mcp::McpServer;
use crate::sandbox::SessionId;

// ---------------------------------------------------------------------------
// Token store
// ---------------------------------------------------------------------------

/// What a bearer token authorizes: one tenant on one backend.
///
/// `pile_policy` is reserved (always absent today): the slot where per-tenant
/// pile restrictions (allowed host paths, quota) will live.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    /// Tenant label the token acts as (`Tenant::label`).
    pub tenant: String,
    /// Backend the token is valid for ("lima", "jail", ...). A server running
    /// a different backend rejects the token with 403.
    pub backend: String,
}

/// On-disk token store: a JSON map of token → [`TokenEntry`].
///
/// Tokens are stored in the clear (the file is the secret; it is written
/// `0600`). Hashing them would buy little here — whoever reads the store also
/// reads the piles the tokens guard.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TokenStore {
    pub tokens: HashMap<String, TokenEntry>,
}

impl TokenStore {
    /// Load a store from `path`. A missing file is an empty store, so `mint`
    /// works on a fresh path without a separate init step.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse token store {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TokenStore::default()),
            Err(e) => Err(e).with_context(|| format!("read token store {}", path.display())),
        }
    }

    /// Persist the store to `path` (pretty JSON, mode 0600).
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("write token store {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 600 token store {}", path.display()))?;
        }
        Ok(())
    }

    /// Mint a fresh random token bound to `tenant` on `backend` and add it to
    /// the store. Returns the token — the caller prints it exactly once.
    pub fn mint(&mut self, tenant: &str, backend: &str) -> String {
        let token = random_urlsafe(32);
        self.tokens.insert(
            token.clone(),
            TokenEntry {
                tenant: tenant.to_string(),
                backend: backend.to_string(),
            },
        );
        token
    }
}

/// `n` bytes of OS randomness as URL-safe base64 (no padding).
pub(crate) fn random_urlsafe(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Settings for [`serve`].
#[derive(Debug)]
pub struct HttpServerConfig {
    /// Address to bind (keep it loopback unless a TLS proxy fronts this).
    pub bind: SocketAddr,
    /// Backend this server runs; tokens minted for other backends are 403'd.
    pub backend_name: String,
    /// Exact `Origin` header values to accept. Empty (the default) rejects
    /// every request that carries an `Origin` header.
    pub allowed_origins: Vec<String>,
    /// MCP sessions idle longer than this expire (lazily, on next access).
    pub idle_timeout: Duration,
    /// OAuth 2.1 for browser-based connectors ([`crate::oauth`]); `None` (the
    /// default posture) leaves this file's static-token behavior untouched.
    pub oauth: Option<crate::oauth::OauthConfig>,
}

/// One live MCP session (Streamable-HTTP `Mcp-Session-Id`).
///
/// Note this is *transport* state only: sandbox sessions opened through it
/// belong to the tenant, not to the MCP session, and survive a reconnect —
/// which is exactly what a client that lost its connection wants.
pub(crate) struct HttpSession {
    tenant: String,
    last_seen: Instant,
}

pub(crate) struct HttpState {
    pub(crate) server: McpServer,
    pub(crate) tokens: HashMap<String, TokenEntry>,
    pub(crate) sessions: Mutex<HashMap<String, HttpSession>>,
    /// Present iff OAuth was configured; the oauth routes are mounted exactly
    /// then, so their handlers may unwrap it.
    pub(crate) oauth: Option<crate::oauth::OauthRuntime>,
    pub(crate) config: HttpServerConfig,
}

/// Serve `server` over Streamable HTTP until the process is killed.
///
/// Owns the tokio runtime, so callers (the sync `main`) need no async of
/// their own.
pub fn serve(server: McpServer, tokens: TokenStore, config: HttpServerConfig) -> Result<()> {
    let bind = config.bind;
    // OAuth is opt-in: a runtime (persistent state + in-memory auth codes)
    // exists exactly when it was configured, and its routes mount exactly then.
    let oauth = config
        .oauth
        .clone()
        .map(crate::oauth::OauthRuntime::new)
        .transpose()?;
    let state = Arc::new(HttpState {
        server,
        tokens: tokens.tokens,
        sessions: Mutex::new(HashMap::new()),
        oauth,
        config,
    });
    let runtime = tokio::runtime::Runtime::new().context("create tokio runtime")?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("bind {bind}"))?;
        eprintln!(
            "playground mcp-http: MCP at http://{}/mcp (backend {}, {} token(s); plain HTTP — front with a TLS proxy for the internet)",
            listener.local_addr()?,
            state.config.backend_name,
            state.tokens.len(),
        );
        if let Some(oauth) = &state.oauth {
            eprintln!(
                "playground mcp-http: OAuth 2.1 enabled (issuer {}, invite-gated authorize)",
                oauth.public_url,
            );
        }
        axum::serve(listener, router(state))
            .await
            .context("serve mcp-http")
    })
}

fn router(state: Arc<HttpState>) -> Router {
    let mut router = Router::new().route(
        "/mcp",
        axum::routing::post(post_mcp).get(get_mcp).delete(delete_mcp),
    );
    // Discovery/registration/authorize/token endpoints exist only when OAuth
    // was configured; without it the route table is exactly the v1 surface.
    if state.oauth.is_some() {
        router = router.merge(crate::oauth::routes());
    }
    router.with_state(state)
}

/// `POST /mcp`: one JSON-RPC message in, one JSON-RPC response (or 202) out.
async fn post_mcp(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let token = match authenticate(&state, &headers) {
        Ok(token) => token,
        Err(response) => return response,
    };

    let mut request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(e) => return http_error(StatusCode::BAD_REQUEST, &format!("invalid JSON body: {e}")),
    };
    if request.is_array() {
        return http_error(
            StatusCode::BAD_REQUEST,
            "JSON-RPC batching was removed in MCP 2025-06-18; send one message per request",
        );
    }
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // Session handling: `initialize` mints an Mcp-Session-Id; everything else
    // must present one that belongs to this token's tenant and isn't idle-out.
    let issued_session = if method == "initialize" {
        let session_id = random_urlsafe(16);
        state.sessions.lock().expect("sessions poisoned").insert(
            session_id.clone(),
            HttpSession {
                tenant: token.tenant.clone(),
                last_seen: Instant::now(),
            },
        );
        Some(session_id)
    } else {
        if let Err(response) = validate_session(&state, &headers, &token) {
            return response;
        }
        None
    };

    // Tenant authorization on the tool surface, before dispatch.
    if method == "tools/call" {
        if let Err(response) = enforce_tenant_scope(&state, &token, &mut request) {
            return response;
        }
    }

    // Dispatch on the blocking pool: the provider/backends shell out
    // (limactl/ssh), and handle_request itself is cheap but synchronous.
    let dispatch_state = state.clone();
    let response = match tokio::task::spawn_blocking(move || {
        dispatch_state.server.handle_request(&request)
    })
    .await
    {
        Ok(response) => response,
        Err(e) => {
            return http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("dispatch panicked: {e}"),
            );
        }
    };

    match response {
        // Notification (no `id`): accepted, nothing to say. Per spec, 202.
        None => StatusCode::ACCEPTED.into_response(),
        Some(value) => {
            let mut response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                value.to_string(),
            )
                .into_response();
            if let Some(session_id) = issued_session {
                response.headers_mut().insert(
                    "mcp-session-id",
                    session_id.parse().expect("base64url is a valid header value"),
                );
            }
            response
        }
    }
}

/// `GET /mcp`: the SSE seam, deliberately unimplemented in v1.
///
/// A streaming server would answer a GET carrying `Accept: text/event-stream`
/// with a server-push SSE stream (unsolicited notifications, exec progress);
/// until then the spec allows a plain 405, which also tells well-behaved
/// clients not to retry the upgrade.
async fn get_mcp() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST, DELETE")],
        "SSE streaming not implemented; POST one JSON-RPC message per request",
    )
        .into_response()
}

/// `DELETE /mcp`: explicit MCP-session termination.
///
/// Removes the transport session only — sandbox sessions stay open (they
/// belong to the tenant; close them with the `close_session` tool).
async fn delete_mcp(State(state): State<Arc<HttpState>>, headers: HeaderMap) -> Response {
    let token = match authenticate(&state, &headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let Some(session_id) = header_str(&headers, "mcp-session-id") else {
        return http_error(StatusCode::BAD_REQUEST, "missing Mcp-Session-Id header");
    };
    let mut sessions = state.sessions.lock().expect("sessions poisoned");
    match sessions.get(session_id) {
        None => http_error(StatusCode::NOT_FOUND, "unknown Mcp-Session-Id"),
        Some(session) if session.tenant != token.tenant => http_error(
            StatusCode::FORBIDDEN,
            "Mcp-Session-Id belongs to a different tenant",
        ),
        Some(_) => {
            sessions.remove(session_id);
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Checks (origin, token, session, tenant scope)
// ---------------------------------------------------------------------------

/// Origin allowlist + bearer token, in that order. Returns the token's entry.
///
/// Bearer resolution is static-store first (unchanged semantics), then — only
/// when OAuth is configured — the OAuth access-token store, which yields the
/// same [`TokenEntry`] shape so everything downstream (backend check, session
/// ownership, tenant scope) treats both token kinds identically.
fn authenticate(state: &HttpState, headers: &HeaderMap) -> Result<TokenEntry, Response> {
    // Origin check (DNS-rebinding defence): only requests that *carry* an
    // Origin header are candidates for rejection — plain MCP clients send none.
    if let Some(origin) = header_str(headers, header::ORIGIN.as_str()) {
        if !state.config.allowed_origins.iter().any(|o| o == origin) {
            return Err(http_error(
                StatusCode::FORBIDDEN,
                &format!("origin '{origin}' not allowed (pass --allow-origin to permit it)"),
            ));
        }
    }

    let bearer = header_str(headers, header::AUTHORIZATION.as_str())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = bearer else {
        return Err(unauthorized(state, "missing Authorization: Bearer <token>"));
    };
    let entry = if let Some(entry) = state.tokens.get(token) {
        entry.clone()
    } else if let Some(oauth) = &state.oauth {
        match oauth.lookup_access(token) {
            Ok(entry) => entry,
            Err(message) => return Err(unauthorized(state, message)),
        }
    } else {
        return Err(unauthorized(state, "unknown token"));
    };
    if entry.backend != state.config.backend_name {
        return Err(http_error(
            StatusCode::FORBIDDEN,
            &format!(
                "token is for backend '{}', this server runs '{}'",
                entry.backend, state.config.backend_name
            ),
        ));
    }
    Ok(entry)
}

/// Non-initialize requests must present a live session owned by this tenant.
fn validate_session(
    state: &HttpState,
    headers: &HeaderMap,
    token: &TokenEntry,
) -> Result<(), Response> {
    let Some(session_id) = header_str(headers, "mcp-session-id") else {
        return Err(http_error(
            StatusCode::BAD_REQUEST,
            "missing Mcp-Session-Id header (initialize first)",
        ));
    };
    let mut sessions = state.sessions.lock().expect("sessions poisoned");
    match sessions.get_mut(session_id) {
        None => Err(http_error(
            StatusCode::NOT_FOUND,
            "unknown Mcp-Session-Id (expired or never issued); re-initialize",
        )),
        Some(session) => {
            if session.last_seen.elapsed() > state.config.idle_timeout {
                sessions.remove(session_id);
                return Err(http_error(
                    StatusCode::NOT_FOUND,
                    "Mcp-Session-Id expired (idle timeout); re-initialize",
                ));
            }
            if session.tenant != token.tenant {
                return Err(http_error(
                    StatusCode::FORBIDDEN,
                    "Mcp-Session-Id belongs to a different tenant",
                ));
            }
            session.last_seen = Instant::now();
            Ok(())
        }
    }
}

/// Pin `tools/call` to the token's tenant, before dispatch.
///
/// - `open_session`: an explicit `tenant` argument must match the token's; a
///   missing one is filled in from it (clients need not know their label).
/// - `exec`/`close_session`: the sandbox session named in `arguments.session`
///   must belong to the token's tenant. Unknown sessions fall through — the
///   provider reports those as tool errors itself, and telling a prober
///   "forbidden" vs "unknown" for other tenants' ids would leak liveness.
///
/// Malformed calls (missing name/arguments) also fall through to dispatch,
/// which owns the error wording.
fn enforce_tenant_scope(
    state: &HttpState,
    token: &TokenEntry,
    request: &mut Value,
) -> Result<(), Response> {
    let Some(name) = request
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
    else {
        return Ok(());
    };

    match name {
        "open_session" => {
            let args = request
                .get_mut("params")
                .and_then(|p| p.get_mut("arguments"));
            match args.as_ref().and_then(|a| a.get("tenant")).and_then(Value::as_str) {
                Some(tenant) if tenant != token.tenant => Err(http_error(
                    StatusCode::FORBIDDEN,
                    &format!("token is not authorized for tenant '{tenant}'"),
                )),
                Some(_) => Ok(()),
                None => {
                    if let Some(Value::Object(map)) = args {
                        map.insert("tenant".to_string(), json!(token.tenant));
                    }
                    Ok(())
                }
            }
        }
        "exec" | "close_session" => {
            let session = request
                .get("params")
                .and_then(|p| p.get("arguments"))
                .and_then(|a| a.get("session"))
                .and_then(Value::as_str);
            let Some(session) = session else {
                return Ok(());
            };
            match state
                .server
                .provider()
                .session_tenant(&SessionId::new(session))
            {
                Some(owner) if owner != token.tenant => Err(http_error(
                    StatusCode::FORBIDDEN,
                    "session belongs to a different tenant",
                )),
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Transport-level failure: plain `{"error": ...}` JSON with an HTTP status.
/// (JSON-RPC error objects are reserved for dispatch-level failures, which
/// arrive with a request id; these rejections happen before dispatch.)
pub(crate) fn http_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        json!({ "error": message }).to_string(),
    )
        .into_response()
}

/// 401 with `WWW-Authenticate`. When OAuth is configured the challenge names
/// the RFC 9728 metadata URL — this is how browser-based MCP connectors
/// discover the whole authorization flow (MCP auth spec requirement); without
/// OAuth it stays the bare `Bearer` of v1.
fn unauthorized(state: &HttpState, message: &str) -> Response {
    let mut response = http_error(StatusCode::UNAUTHORIZED, message);
    let challenge = match &state.oauth {
        Some(oauth) => format!(
            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
            oauth.public_url
        )
        .parse()
        .expect("public url came from config and is header-safe"),
        None => "Bearer".parse().expect("static"),
    };
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
}

/// Test support shared with `crate::oauth`'s integration test: state builder,
/// server spawner and a blocking ureq client.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mcp::testing::MockBackend;
    use crate::mcp::{McpServer, SandboxProvider};

    /// Build a server state over the mock backend with two tenants (alice,
    /// bob) plus one token minted for the wrong backend.
    pub(crate) fn test_state(
        allowed_origins: Vec<String>,
        idle_timeout: Duration,
    ) -> Arc<HttpState> {
        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        let mut tokens = HashMap::new();
        for (token, tenant, backend) in [
            ("tok-alice", "alice", "mock"),
            ("tok-bob", "bob", "mock"),
            ("tok-carol-lima", "carol", "lima"),
        ] {
            tokens.insert(
                token.to_string(),
                TokenEntry {
                    tenant: tenant.to_string(),
                    backend: backend.to_string(),
                },
            );
        }
        Arc::new(HttpState {
            server,
            tokens,
            sessions: Mutex::new(HashMap::new()),
            oauth: None,
            config: HttpServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                backend_name: "mock".to_string(),
                allowed_origins,
                idle_timeout,
                oauth: None,
            },
        })
    }

    /// Build a server state like [`test_state`] but with OAuth configured
    /// (fresh persistent store at `state_path`, issuer `public_url`).
    pub(crate) fn test_state_with_oauth(
        public_url: &str,
        state_path: &Path,
        access_ttl: Duration,
    ) -> Arc<HttpState> {
        let state = test_state(vec![], Duration::from_secs(3600));
        let mut state = Arc::into_inner(state).expect("fresh state has one ref");
        let oauth_config = crate::oauth::OauthConfig {
            public_url: public_url.to_string(),
            state_path: state_path.to_path_buf(),
            access_ttl,
        };
        state.oauth =
            Some(crate::oauth::OauthRuntime::new(oauth_config.clone()).expect("oauth runtime"));
        state.config.oauth = Some(oauth_config);
        Arc::new(state)
    }

    /// Bind an ephemeral port, run axum on a dedicated runtime thread, and
    /// return the address. Tests then use blocking ureq like a real client.
    pub(crate) fn spawn_server(state: Arc<HttpState>) -> SocketAddr {
        let runtime = tokio::runtime::Runtime::new().expect("test runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            runtime
                .block_on(async move { axum::serve(listener, router(state)).await })
                .expect("test server");
        });
        addr
    }

    pub(crate) fn agent() -> ureq::Agent {
        // Non-2xx statuses are data for these tests, not errors.
        ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build(),
        )
    }

    pub(crate) struct Reply {
        pub(crate) status: u16,
        pub(crate) session: Option<String>,
        pub(crate) body: Value,
    }

    /// POST one JSON-RPC message with optional token/session/origin headers.
    pub(crate) fn post(
        agent: &ureq::Agent,
        addr: SocketAddr,
        token: Option<&str>,
        session: Option<&str>,
        origin: Option<&str>,
        message: &Value,
    ) -> Reply {
        let mut request = agent.post(format!("http://{addr}/mcp"));
        if let Some(token) = token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(session) = session {
            request = request.header("Mcp-Session-Id", session);
        }
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        let mut response = request.send_json(message).expect("send request");
        let status = response.status().as_u16();
        let session = response
            .headers()
            .get("mcp-session-id")
            .map(|v| v.to_str().unwrap().to_string());
        let text = response.body_mut().read_to_string().expect("read body");
        let body = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        Reply {
            status,
            session,
            body,
        }
    }

    pub(crate) fn rpc(id: u64, method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
    }

    /// initialize → session id → tools/list → open/exec/close, then DELETE
    /// tears the MCP session down. The whole colleague-client flow.
    #[test]
    fn http_full_handshake_over_mock_backend() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        let agent = agent();
        let tok = Some("tok-alice");

        // initialize: 200, echoes the requested protocol version, issues a session.
        let init = post(
            &agent,
            addr,
            tok,
            None,
            None,
            &rpc(1, "initialize", json!({ "protocolVersion": "2025-06-18" })),
        );
        assert_eq!(init.status, 200, "init body: {}", init.body);
        assert_eq!(init.body["result"]["protocolVersion"], "2025-06-18");
        let session = init.session.expect("initialize must issue Mcp-Session-Id");

        // notifications/initialized: a notification, so 202 with no body.
        let notified = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        );
        assert_eq!(notified.status, 202);
        assert_eq!(notified.body, Value::Null);

        // tools/list: the three sandbox tools.
        let tools = post(&agent, addr, tok, Some(&session), None, &rpc(2, "tools/list", json!({})));
        assert_eq!(tools.status, 200);
        assert_eq!(tools.body["result"]["tools"].as_array().unwrap().len(), 3);

        // open_session without a tenant argument: filled in from the token.
        let opened = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(
                3,
                "tools/call",
                json!({ "name": "open_session", "arguments": { "pile_host_path": "/tmp/alice/self.pile" } }),
            ),
        );
        assert_eq!(opened.status, 200);
        assert_eq!(opened.body["result"]["isError"], false);
        assert_eq!(opened.body["result"]["content"][0]["text"], "mock-alice");

        // exec in the opened sandbox session.
        let ran = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(
                4,
                "tools/call",
                json!({ "name": "exec", "arguments": { "session": "mock-alice", "command": "echo hi" } }),
            ),
        );
        assert_eq!(ran.status, 200);
        let text = ran.body["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("ran: echo hi"), "exec text: {text}");

        // close_session.
        let closed = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(
                5,
                "tools/call",
                json!({ "name": "close_session", "arguments": { "session": "mock-alice" } }),
            ),
        );
        assert_eq!(closed.status, 200);
        assert_eq!(closed.body["result"]["isError"], false);

        // DELETE terminates the MCP session; it is unknown afterwards.
        let mut delete = agent
            .delete(format!("http://{addr}/mcp"))
            .header("Authorization", "Bearer tok-alice")
            .header("Mcp-Session-Id", &session)
            .call()
            .expect("delete");
        assert_eq!(delete.status().as_u16(), 204);
        let _ = delete.body_mut().read_to_string();
        let gone = post(&agent, addr, tok, Some(&session), None, &rpc(6, "tools/list", json!({})));
        assert_eq!(gone.status, 404);
    }

    #[test]
    fn missing_or_bad_token_is_401() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        let agent = agent();
        let init = rpc(1, "initialize", json!({}));

        let missing = post(&agent, addr, None, None, None, &init);
        assert_eq!(missing.status, 401);

        let bad = post(&agent, addr, Some("tok-nonsense"), None, None, &init);
        assert_eq!(bad.status, 401);
    }

    #[test]
    fn wrong_backend_token_is_403() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        // carol's token was minted for the lima backend; this server is mock.
        let reply = post(
            &agent(),
            addr,
            Some("tok-carol-lima"),
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
        assert_eq!(reply.status, 403);
    }

    /// The product feature: bob's token cannot touch alice's sandboxes, open
    /// sessions as alice, or ride alice's MCP session.
    #[test]
    fn cross_tenant_session_access_is_403() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        let agent = agent();

        // alice initializes and opens her sandbox.
        let alice = post(&agent, addr, Some("tok-alice"), None, None, &rpc(1, "initialize", json!({})));
        let alice_session = alice.session.unwrap();
        let opened = post(
            &agent,
            addr,
            Some("tok-alice"),
            Some(&alice_session),
            None,
            &rpc(
                2,
                "tools/call",
                json!({ "name": "open_session", "arguments": { "pile_host_path": "/tmp/alice/self.pile" } }),
            ),
        );
        assert_eq!(opened.body["result"]["content"][0]["text"], "mock-alice");

        // bob initializes his own MCP session...
        let bob = post(&agent, addr, Some("tok-bob"), None, None, &rpc(1, "initialize", json!({})));
        let bob_session = bob.session.unwrap();

        // ...and may not exec in alice's sandbox,
        let exec = post(
            &agent,
            addr,
            Some("tok-bob"),
            Some(&bob_session),
            None,
            &rpc(
                3,
                "tools/call",
                json!({ "name": "exec", "arguments": { "session": "mock-alice", "command": "cat /pile/self.pile" } }),
            ),
        );
        assert_eq!(exec.status, 403);

        // ...may not close it,
        let close = post(
            &agent,
            addr,
            Some("tok-bob"),
            Some(&bob_session),
            None,
            &rpc(
                4,
                "tools/call",
                json!({ "name": "close_session", "arguments": { "session": "mock-alice" } }),
            ),
        );
        assert_eq!(close.status, 403);

        // ...may not open a session claiming to be alice,
        let open_as = post(
            &agent,
            addr,
            Some("tok-bob"),
            Some(&bob_session),
            None,
            &rpc(
                5,
                "tools/call",
                json!({ "name": "open_session", "arguments": { "tenant": "alice", "pile_host_path": "/tmp/alice/self.pile" } }),
            ),
        );
        assert_eq!(open_as.status, 403);

        // ...and may not present alice's Mcp-Session-Id with his token.
        let hijack = post(
            &agent,
            addr,
            Some("tok-bob"),
            Some(&alice_session),
            None,
            &rpc(6, "tools/list", json!({})),
        );
        assert_eq!(hijack.status, 403);
    }

    #[test]
    fn session_id_required_and_validated_after_initialize() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        let agent = agent();
        let tok = Some("tok-alice");

        // No Mcp-Session-Id on a non-initialize request: 400.
        let missing = post(&agent, addr, tok, None, None, &rpc(1, "tools/list", json!({})));
        assert_eq!(missing.status, 400);

        // A session id the server never issued: 404.
        let bogus = post(&agent, addr, tok, Some("never-issued"), None, &rpc(2, "tools/list", json!({})));
        assert_eq!(bogus.status, 404);
    }

    #[test]
    fn idle_sessions_expire() {
        // Zero idle timeout: the session is already stale on its second use.
        let addr = spawn_server(test_state(vec![], Duration::ZERO));
        let agent = agent();
        let init = post(&agent, addr, Some("tok-alice"), None, None, &rpc(1, "initialize", json!({})));
        let session = init.session.unwrap();
        let expired = post(&agent, addr, Some("tok-alice"), Some(&session), None, &rpc(2, "tools/list", json!({})));
        assert_eq!(expired.status, 404);
    }

    #[test]
    fn origin_rejected_unless_allowlisted() {
        let addr = spawn_server(test_state(
            vec!["http://localhost:5173".to_string()],
            Duration::from_secs(3600),
        ));
        let agent = agent();
        let init = rpc(1, "initialize", json!({}));

        // Unlisted browser origin: rejected before auth even runs.
        let evil = post(&agent, addr, Some("tok-alice"), None, Some("https://evil.example"), &init);
        assert_eq!(evil.status, 403);

        // Allowlisted origin: fine.
        let ok = post(&agent, addr, Some("tok-alice"), None, Some("http://localhost:5173"), &init);
        assert_eq!(ok.status, 200);

        // No Origin header (plain MCP client): fine.
        let plain = post(&agent, addr, Some("tok-alice"), None, None, &init);
        assert_eq!(plain.status, 200);
    }

    #[test]
    fn get_is_405_and_batches_are_400() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        let agent = agent();

        let mut get = agent
            .get(format!("http://{addr}/mcp"))
            .call()
            .expect("get");
        assert_eq!(get.status().as_u16(), 405);
        let _ = get.body_mut().read_to_string();

        let batch = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            None,
            &json!([rpc(1, "initialize", json!({}))]),
        );
        assert_eq!(batch.status, 400);
    }

    #[test]
    fn token_store_mint_and_reload() {
        let dir = std::env::temp_dir().join(format!(
            "playground_token_store_{}_{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tokens.json");

        // Fresh path loads as empty; mint + save round-trips.
        let mut store = TokenStore::load(&path).expect("load fresh");
        assert!(store.tokens.is_empty());
        let token = store.mint("alice", "lima");
        assert_eq!(token.len(), 43); // 32 bytes as unpadded base64url
        store.save(&path).expect("save");

        let reloaded = TokenStore::load(&path).expect("reload");
        let entry = reloaded.tokens.get(&token).expect("minted token present");
        assert_eq!(entry.tenant, "alice");
        assert_eq!(entry.backend, "lima");

        // Minting again yields a distinct token and keeps the first.
        let mut reloaded = reloaded;
        let second = reloaded.mint("bob", "lima");
        assert_ne!(token, second);
        assert_eq!(reloaded.tokens.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }
}

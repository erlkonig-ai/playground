//! Streamable-HTTP MCP transport with per-sandbox bearer-token auth.
//!
//! This is the internet-facing half of the sandbox provider (the seam left on
//! [`crate::mcp::McpTransport`]): MCP's Streamable HTTP transport (spec rev
//! 2025-06-18) on the origin-root endpoint, in front of the blocking
//! [`McpServer`](crate::mcp::McpServer) core.
//!
//! ## Protocol surface (v1)
//!
//! - `POST /` — one JSON-RPC message per request body. Requests (with an
//!   `id`) get a single `application/json` JSON-RPC response; notifications
//!   get `202 Accepted`. The spec explicitly permits plain-JSON responses for
//!   servers that don't stream — SSE streaming (`Accept: text/event-stream`
//!   upgrades, server-push notifications, resumability) is a deliberate v2
//!   seam, see [`get_mcp`].
//! - `GET /` — `405 Method Not Allowed` (that's the SSE seam).
//! - `DELETE /` — explicit MCP-session termination.
//! - `Mcp-Session-Id` — issued on `initialize`, required on every subsequent
//!   request, expired after [`HttpServerConfig::idle_timeout`] of inactivity
//!   (checked lazily on access — no reaper thread) or on `DELETE`.
//! - JSON-RPC batch arrays are rejected (removed from the spec in 2025-06-18).
//!
//! ## Auth model (the product feature)
//!
//! Every request must carry `Authorization: Bearer <token>`. Tokens live in a
//! JSON [`TokenStore`] on disk (minted with `playground user create`) and map
//! to a **tenant** (label + allowed backend). Enforcement, all *before*
//! dispatch, at this layer:
//!
//! - no/unknown token → `401`;
//! - token minted for a different backend than this server runs → `403`;
//! - `open_session` for a tenant other than the token's → `403` (a missing
//!   `tenant` argument is filled in from the token, so clients need not know
//!   their own label);
//! - `exec`/`close_session`/`destroy_session` against a sandbox session owned by
//!   another tenant → `403` (via [`SandboxProvider::session_tenant`]);
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

    /// Persist the store to `path` (pretty JSON, mode 0600) crash-atomically:
    /// a `0600` temp sibling is written, fsync'd, then `rename`d into place, so
    /// there is never a truncate-in-place window an interrupted write could
    /// leave torn or world-readable. See [`atomic_write_0600`].
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        atomic_write_0600(path, json.as_bytes())
            .with_context(|| format!("write token store {}", path.display()))
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

// ---------------------------------------------------------------------------
// Live token authority (repair #5 HIGH: reset must be live revocation)
// ---------------------------------------------------------------------------

/// The one live, in-memory authority the request path consults for static
/// bearer tokens — the fix for "reset is not live revocation".
///
/// Before this, the daemon snapshotted the token map at startup into a plain
/// `HashMap` and never looked at disk again, so `playground user token reset`
/// (a *separate* process that rewrites the JSON) took effect only after a full
/// server restart: the revoked token stayed valid and the fresh one was
/// rejected until then.
///
/// The daemon and the `user` CLI are distinct processes, so their shared
/// channel is the on-disk store — exactly as the OAuth layer already treats its
/// state file as the source of truth. This makes that explicit: the live
/// authority is an `RwLock<HashMap>` that the auth path reads, and it
/// **reloads from disk the moment the file's mtime changes** (a cheap `stat` on
/// each auth, a full re-read only when it actually moved). A CLI
/// `create`/`reset`/`destroy` writes the store atomically (see
/// [`atomic_write_0600`]); the daemon picks the change up on the very next
/// request — no restart. The on-disk store is the durable copy; this live set
/// is the source of truth for every auth decision.
///
/// Admin ops running *inside* the daemon (were any added) would mutate the
/// `RwLock` directly and be instantly live too; the disk-reload path is what
/// bridges the current out-of-process CLI. Tokens minted for other backends are
/// kept here as-is — the backend check downstream in [`authenticate`] 403s
/// them, unchanged.
pub(crate) struct TokenAuthority {
    /// The live token map. `RwLock` because auth is read-mostly (every request
    /// takes a read guard; a reload — rare — takes the write guard briefly).
    tokens: std::sync::RwLock<HashMap<String, TokenEntry>>,
    /// The on-disk store this authority tracks, and the last mtime we loaded.
    /// `None` = a purely in-memory authority (tests, or a future all-in-process
    /// deployment) with no disk to reload from.
    disk: Option<Mutex<DiskTracking>>,
}

/// The path + last-seen modification time of the backing store file, so a
/// reload happens exactly when the file actually changed.
struct DiskTracking {
    path: std::path::PathBuf,
    /// Last modification time we loaded, if the file existed then. `None` means
    /// "not yet loaded / file was absent", which always triggers a reload
    /// attempt so a store that appears after startup is still picked up.
    loaded_mtime: Option<std::time::SystemTime>,
}

impl TokenAuthority {
    /// Build a live authority from a store loaded off `path`, tracking that
    /// file for out-of-process mutations (the CLI's `create`/`reset`/`destroy`).
    pub(crate) fn from_disk(store: TokenStore, path: std::path::PathBuf) -> Self {
        let loaded_mtime = file_mtime(&path);
        TokenAuthority {
            tokens: std::sync::RwLock::new(store.tokens),
            disk: Some(Mutex::new(DiskTracking { path, loaded_mtime })),
        }
    }

    /// Build a purely in-memory authority (no disk tracking) — for tests and
    /// any deployment that mutates the live set directly rather than via a file.
    #[cfg(test)]
    pub(crate) fn in_memory(tokens: HashMap<String, TokenEntry>) -> Self {
        TokenAuthority {
            tokens: std::sync::RwLock::new(tokens),
            disk: None,
        }
    }

    /// Number of tokens currently live (for the startup banner only).
    pub(crate) fn len(&self) -> usize {
        self.tokens.read().expect("token authority poisoned").len()
    }

    /// Resolve `token` to its entry against the *current* live set, reloading
    /// from disk first if the backing file changed since the last load. This is
    /// the request-path hook: a revoked token is rejected and a freshly-minted
    /// one accepted immediately, with no restart.
    pub(crate) fn resolve(&self, token: &str) -> Option<TokenEntry> {
        self.refresh_if_changed();
        self.tokens
            .read()
            .expect("token authority poisoned")
            .get(token)
            .cloned()
    }

    /// If the backing file's mtime moved since our last load, re-read it and
    /// swap the live map. Cheap in the steady state (one `stat`, no lock
    /// upgrade); the full re-read + write-lock happens only when the file
    /// actually changed. A read error is logged and the current in-memory set
    /// is kept — a transient disk hiccup must not blank out every token.
    fn refresh_if_changed(&self) {
        let Some(disk) = &self.disk else {
            return; // in-memory authority: nothing to track.
        };
        let mut tracking = disk.lock().expect("token authority disk poisoned");
        let current = file_mtime(&tracking.path);
        // Reload when the mtime changed (including appearing/disappearing).
        // `None`/`None` (file still absent) is a no-op after the first check.
        if current == tracking.loaded_mtime && current.is_some() {
            return;
        }
        if current.is_none() && tracking.loaded_mtime.is_none() {
            return;
        }
        match TokenStore::load(&tracking.path) {
            Ok(fresh) => {
                *self.tokens.write().expect("token authority poisoned") = fresh.tokens;
                tracking.loaded_mtime = current;
            }
            Err(e) => {
                eprintln!(
                    "warning: failed to reload token store {} (keeping the current live set): {e:#}",
                    tracking.path.display(),
                );
            }
        }
    }
}

/// The modification time of `path`, or `None` if it is absent or unstattable.
fn file_mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// `n` bytes of OS randomness as URL-safe base64 (no padding).
pub(crate) fn random_urlsafe(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

/// Write `bytes` to `path` crash-atomically with mode `0600` from the first
/// byte — the auth-store persistence primitive (both [`TokenStore::save`] and
/// [`crate::oauth::OauthStore::save`] funnel through it).
///
/// The old path (`std::fs::write` then `set_permissions`) had two windows a
/// crash could tear open: (1) `write` truncates the destination in place, so an
/// interrupted write leaves a half-written store on disk; (2) the file is
/// briefly world-default-perms before the `chmod`, so a secret store is
/// readable in that gap. This instead:
///
/// 1. creates a temp sibling in the *same directory* (so the final `rename` is
///    a same-filesystem atomic swap) with `O_CREAT|O_EXCL|O_WRONLY` and mode
///    `0600` up front — the secret is never world-readable, not even for an
///    instant;
/// 2. writes the full contents and `fsync`s the temp file (durability);
/// 3. `rename`s the temp over `path` — atomic, so a reader sees either the old
///    complete file or the new complete file, never a torn one;
/// 4. best-effort `fsync`s the parent directory so the rename itself survives a
///    crash.
///
/// On any failure before the rename the temp file is removed, so a crashed
/// write leaves no `.tmp` litter and never touches the live store.
pub(crate) fn atomic_write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // Unpredictable temp name in the same dir: same-filesystem rename + no
    // collision with a concurrent writer's temp, and O_EXCL below refuses to
    // follow a pre-planted symlink at this name (confused-deputy defence).
    let tmp = {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".tmp.{}.{}", std::process::id(), random_urlsafe(8)));
        dir.join(name)
    };

    // Create O_EXCL with mode 0600 from the start. `.mode()` is unix-only; on
    // other targets the file is created with default perms (this crate's
    // deployment target is unix, where the auth stores live).
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let write_result = (|| -> Result<()> {
        let mut file = opts
            .open(&tmp)
            .with_context(|| format!("create temp file {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write temp file {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync temp file {}", tmp.display()))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
    {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // Best-effort directory fsync so the rename is durable across a crash. A
    // failure here doesn't invalidate the (already atomic) swap, so it's not
    // fatal — the data is safe, only the rename's crash-durability is at stake.
    #[cfg(unix)]
    if let Ok(dir_file) = std::fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
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
    /// Maximum accepted request body, in bytes. Made EXPLICIT (rather than
    /// inheriting axum's 2 MiB `DefaultBodyLimit`) so the policy is a stated
    /// bound, not a dependency default a future axum bump could silently move.
    /// A JSON-RPC MCP message (even one carrying `stdin`) is tiny, so this is a
    /// low ceiling that rejects an oversized body before it is buffered.
    pub max_body_bytes: usize,
    /// OAuth 2.1 for browser-based connectors ([`crate::oauth`]); `None` (the
    /// default posture) leaves this file's static-token behavior untouched.
    pub oauth: Option<crate::oauth::OauthConfig>,
    /// Ceiling on live transport sessions across all tenants (repair #5 HIGH:
    /// unbounded transport-session retention). Once the table is full — after
    /// an idle sweep — `initialize` is refused with 503 rather than growing
    /// memory without bound.
    pub max_sessions_global: usize,
    /// Ceiling on live transport sessions per tenant. A tenant at its cap has
    /// its own idlest session evicted to make room, so a single token can never
    /// hold more than this many `Mcp-Session-Id`s (and so can't crowd the
    /// global table on its own).
    pub max_sessions_per_tenant: usize,
}

/// Default explicit request-body ceiling (1 MiB). Comfortably fits any JSON-RPC
/// MCP message while bounding what one request can make the server buffer.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default global transport-session ceiling. Each entry is tiny (a tenant label
/// plus an `Instant`), so this bounds the table's memory at a few tens of KiB
/// while comfortably fitting real fan-out.
pub const DEFAULT_MAX_SESSIONS_GLOBAL: usize = 10_000;

/// Default per-tenant transport-session ceiling. A well-behaved client holds
/// one or a few sessions; this leaves generous headroom for reconnect churn
/// while stopping one token from minting sessions without limit.
pub const DEFAULT_MAX_SESSIONS_PER_TENANT: usize = 64;

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
    /// The live static-token authority (disk-tracking; picks up CLI
    /// create/reset/destroy without a restart). See [`TokenAuthority`].
    pub(crate) tokens: TokenAuthority,
    pub(crate) sessions: Mutex<HashMap<String, HttpSession>>,
    /// Present iff OAuth was configured; the oauth routes are mounted exactly
    /// then, so their handlers may unwrap it.
    pub(crate) oauth: Option<crate::oauth::OauthRuntime>,
    pub(crate) config: HttpServerConfig,
}

/// Serve `server` over Streamable HTTP until the process is killed.
///
/// `tokens` is the startup snapshot of the static token store and `tokens_path`
/// the file it came from — the live [`TokenAuthority`] tracks that file so a CLI
/// `user create`/`token reset`/`destroy` (a separate process) takes effect
/// without a restart.
///
/// Owns the tokio runtime, so callers (the sync `main`) need no async of
/// their own.
pub fn serve(
    server: McpServer,
    tokens: TokenStore,
    tokens_path: std::path::PathBuf,
    config: HttpServerConfig,
) -> Result<()> {
    let bind = config.bind;
    server
        .provider()
        .set_fatal_handler(Arc::new(|_reason| std::process::exit(1)));
    // OAuth is opt-in: a runtime (persistent state + in-memory auth codes)
    // exists exactly when it was configured, and its routes mount exactly then.
    let oauth = config
        .oauth
        .clone()
        .map(crate::oauth::OauthRuntime::new)
        .transpose()?;
    let state = Arc::new(HttpState {
        server,
        tokens: TokenAuthority::from_disk(tokens, tokens_path),
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
            "playground mcp-http: MCP at http://{}/ (backend {}, {} token(s); plain HTTP — front with a TLS proxy for the internet)",
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
        // `state` is cloned into the router so the original Arc survives the
        // serve to drive the post-shutdown spin-down below.
        let serve_result = axum::serve(listener, router(state.clone()))
            .with_graceful_shutdown(shutdown_signal(state.clone()))
            .await
            .context("serve mcp-http");

        // Graceful shutdown reached (SIGINT/SIGTERM), or serve errored out:
        // spin DOWN every owned sandbox that must not outlive this process
        // (Lima VMs; jail is a no-op). A HARD kill skips this path entirely —
        // `playground clean` is the backstop for that case.
        let spun = state.server.provider().shutdown();
        eprintln!("playground mcp-http: spun down {spun} owned sandbox(es) on shutdown");
        serve_result
    })
}

/// Resolves when the process is asked to stop — SIGINT (Ctrl-C) or, on unix,
/// SIGTERM — so axum drains in-flight requests before `serve` returns and we
/// spin down owned sandboxes. A hard SIGKILL cannot be caught; `playground
/// clean` recovers that case.
async fn shutdown_signal(state: Arc<HttpState>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    // Start cancellation before Axum drains in-flight requests. Otherwise a
    // synchronous exec can hold graceful shutdown open until its full command
    // timeout and invite the service supervisor to SIGKILL us first.
    state.server.provider().begin_shutdown();
    eprintln!("playground mcp-http: shutdown signal received — cancelling jobs, then draining");
}

fn router(state: Arc<HttpState>) -> Router {
    let mut router = Router::new().route(
        "/",
        axum::routing::post(post_mcp)
            .get(get_mcp)
            .delete(delete_mcp),
    );
    // Discovery/registration/authorize/token endpoints exist only when OAuth
    // was configured; without it the route table is exactly the v1 surface.
    if state.oauth.is_some() {
        router = router.merge(crate::oauth::routes());
    }
    // EXPLICIT request-body ceiling (repair #4 HIGH follow-up): state the bound
    // rather than inheriting axum's 2 MiB `DefaultBodyLimit`. An oversized body
    // is rejected with 413 before it is buffered.
    router
        .layer(axum::extract::DefaultBodyLimit::max(
            state.config.max_body_bytes,
        ))
        .with_state(state)
}

/// `POST /`: one JSON-RPC message in, one JSON-RPC response (or 202) out.
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
        match open_session(&state, &token.tenant) {
            Ok(session_id) => Some(session_id),
            Err(response) => return response,
        }
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
    let response =
        match tokio::task::spawn_blocking(move || dispatch_state.server.handle_request(&request))
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
        Some(mut value) => {
            if method == "tools/list" && state.config.backend_name == "jail" {
                specialize_host_owned_jail_tools(&mut value);
            }
            let mut response = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                value.to_string(),
            )
                .into_response();
            if let Some(session_id) = issued_session {
                response.headers_mut().insert(
                    "mcp-session-id",
                    session_id
                        .parse()
                        .expect("base64url is a valid header value"),
                );
            }
            response
        }
    }
}

/// The public jail service derives identity and pile placement from the bearer
/// credential and its host-owned storage topology. Keep those implementation
/// details off the model-visible tool schema: a client opens *its* persistent
/// sandbox, optionally choosing only process-local cwd/env settings.
fn specialize_host_owned_jail_tools(response: &mut Value) {
    let Some(tools) = response
        .get_mut("result")
        .and_then(|result| result.get_mut("tools"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    let Some(open) = tools
        .iter_mut()
        .find(|tool| tool.get("name").and_then(Value::as_str) == Some("open_session"))
    else {
        return;
    };
    open["description"] = json!(
        "Open or reattach your persistent sandbox and return its session id. Identity and piles come from your authenticated account."
    );
    open["inputSchema"] = json!({
        "type": "object",
        "properties": {
            "cwd": { "type": "string", "description": "Working directory the shell starts in." },
            "env": { "type": "object", "description": "Extra environment variables.", "additionalProperties": { "type": "string" } }
        },
        "additionalProperties": false
    });
}

/// `GET /`: the SSE seam, deliberately unimplemented in v1.
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

/// `DELETE /`: explicit MCP-session termination.
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
// Transport-session table (bounded — repair #5 HIGH)
// ---------------------------------------------------------------------------

/// Mint a transport session for `tenant`, sweeping idle ones and enforcing the
/// per-tenant and global ceilings first (repair #5 HIGH: unbounded
/// transport-session retention).
///
/// Order, all under one lock so the counts checked are the counts written:
/// 1. **Idle sweep** — drop every session idle longer than `idle_timeout`. This
///    is the "periodic expiry" the review asked for, folded onto the mint path
///    (the busy path) rather than a reaper thread, matching this file's
///    lazy-reaping style. Abandoned ids therefore self-drain as new ones arrive.
/// 2. **Per-tenant cap** — if this tenant is already at `max_sessions_per_tenant`,
///    evict *its own* idlest session (LRU). A single token thus never holds more
///    than the cap, and only ever displaces itself.
/// 3. **Global cap** — if the whole table is still at `max_sessions_global`,
///    refuse with 503 rather than grow memory unbounded. (The per-tenant cap
///    already stops one tenant filling it, so this is the multi-tenant backstop.)
// `Response` is the module-wide error type for the pre-dispatch checks (as on
// `authenticate`/`validate_session`/…); the `result_large_err` lint is an
// accepted trade there, so keep the same idiom here rather than boxing one fn.
#[allow(clippy::result_large_err)]
fn open_session(state: &HttpState, tenant: &str) -> Result<String, Response> {
    let now = Instant::now();
    let idle_timeout = state.config.idle_timeout;
    let mut sessions = state.sessions.lock().expect("sessions poisoned");

    // 1. Idle sweep.
    sessions.retain(|_, s| now.duration_since(s.last_seen) <= idle_timeout);

    // 2. Per-tenant cap: evict this tenant's idlest until it has room for one more.
    let mut mine: Vec<(String, Instant)> = sessions
        .iter()
        .filter(|(_, s)| s.tenant == tenant)
        .map(|(id, s)| (id.clone(), s.last_seen))
        .collect();
    if mine.len() >= state.config.max_sessions_per_tenant {
        // Oldest first, evict down to (cap - 1) so the new one fits at the cap.
        mine.sort_by_key(|(_, last_seen)| *last_seen);
        let evict = mine.len() + 1 - state.config.max_sessions_per_tenant;
        for (id, _) in mine.into_iter().take(evict) {
            sessions.remove(&id);
        }
    }

    // 3. Global cap: after the sweep + per-tenant trim, refuse if still full.
    if sessions.len() >= state.config.max_sessions_global {
        return Err(http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "transport-session table is full; retry later",
        ));
    }

    let session_id = random_urlsafe(16);
    sessions.insert(
        session_id.clone(),
        HttpSession {
            tenant: tenant.to_string(),
            last_seen: now,
        },
    );
    Ok(session_id)
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
    // Static-token resolution goes through the live authority, which reloads
    // the on-disk store if it changed since the last request — so a CLI
    // `token reset`/`destroy` revokes immediately and a freshly-minted token is
    // accepted immediately, no restart (repair #5 HIGH: live revocation).
    let entry = if let Some(entry) = state.tokens.resolve(token) {
        entry
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
///   missing one is filled in from it (clients need not know their label). For
///   the host-owned jail backend the ignored pile path is also synthesized, so
///   its public tool accepts `{}` and exposes no host-storage plumbing.
/// - `exec`/`job_exec`/`close_session`/`destroy_session`: the sandbox session named in `arguments.session`
///   must belong to the token's tenant. Unknown sessions fall through — the
///   provider reports those as tool errors itself, and telling a prober
///   "forbidden" vs "unknown" for other tenants' ids would leak liveness.
/// - `job_poll`/`job_cancel`: the retained job id must belong to the token's
///   tenant. Unknown/expired ids likewise fall through to the provider.
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
            let Some(params) = request.get_mut("params").and_then(Value::as_object_mut) else {
                return Ok(());
            };
            let args = params
                .entry("arguments".to_string())
                .or_insert_with(|| json!({}));
            if args.is_null() {
                *args = json!({});
            }
            let Some(map) = args.as_object_mut() else {
                return Ok(());
            };
            match map.get("tenant").and_then(Value::as_str) {
                Some(tenant) if tenant != token.tenant => Err(http_error(
                    StatusCode::FORBIDDEN,
                    &format!("token is not authorized for tenant '{tenant}'"),
                )),
                Some(_) => {
                    if state.config.backend_name == "jail" {
                        map.insert(
                            "pile_host_path".to_string(),
                            json!("/host-owned/by-jail-backend/self.pile"),
                        );
                        map.remove("pile_guest_path");
                    }
                    Ok(())
                }
                None => {
                    map.insert("tenant".to_string(), json!(token.tenant));
                    if state.config.backend_name == "jail" {
                        map.insert(
                            "pile_host_path".to_string(),
                            json!("/host-owned/by-jail-backend/self.pile"),
                        );
                        map.remove("pile_guest_path");
                    }
                    Ok(())
                }
            }
        }
        "exec" | "job_exec" | "close_session" | "destroy_session" => {
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
        "job_poll" | "job_cancel" => {
            let job_id = request
                .get("params")
                .and_then(|p| p.get("arguments"))
                .and_then(|a| a.get("job_id"))
                .and_then(Value::as_str);
            let Some(job_id) = job_id else {
                return Ok(());
            };
            match state.server.provider().job_tenant(job_id) {
                Some(owner) if owner != token.tenant => Err(http_error(
                    StatusCode::FORBIDDEN,
                    "job belongs to a different tenant",
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
        test_state_for_backend(allowed_origins, idle_timeout, "mock")
    }

    fn test_state_for_backend(
        allowed_origins: Vec<String>,
        idle_timeout: Duration,
        backend_name: &str,
    ) -> Arc<HttpState> {
        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        let mut tokens = HashMap::new();
        for (token, tenant, backend) in [
            ("tok-alice", "alice", backend_name),
            ("tok-bob", "bob", backend_name),
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
            tokens: TokenAuthority::in_memory(tokens),
            sessions: Mutex::new(HashMap::new()),
            oauth: None,
            config: HttpServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                backend_name: backend_name.to_string(),
                allowed_origins,
                idle_timeout,
                max_body_bytes: DEFAULT_MAX_BODY_BYTES,
                oauth: None,
                max_sessions_global: DEFAULT_MAX_SESSIONS_GLOBAL,
                max_sessions_per_tenant: DEFAULT_MAX_SESSIONS_PER_TENANT,
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
        let mut request = agent.post(format!("http://{addr}"));
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

        // tools/list: lifecycle, sync exec, and the cancellable job triple.
        let tools = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(2, "tools/list", json!({})),
        );
        assert_eq!(tools.status, 200);
        assert_eq!(tools.body["result"]["tools"].as_array().unwrap().len(), 7);

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

        // Long work uses the same execution kernel but returns a durable job
        // handle that survives transport reconnects.
        let started = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(
                5,
                "tools/call",
                json!({ "name": "job_exec", "arguments": { "session": "mock-alice", "command": "build" } }),
            ),
        );
        assert_eq!(started.status, 200);
        let started_text = started.body["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        let started_json: Value = serde_json::from_str(started_text).unwrap();
        let job_id = started_json["job_id"].as_str().unwrap();
        let mut cursor = 0;
        let mut job_output = String::new();
        let polled = loop {
            let reply = post(
                &agent,
                addr,
                tok,
                Some(&session),
                None,
                &rpc(
                    6,
                    "tools/call",
                    json!({ "name": "job_poll", "arguments": { "job_id": job_id, "cursor": cursor } }),
                ),
            );
            let text = reply.body["result"]["content"][0]["text"].as_str().unwrap();
            let poll: Value = serde_json::from_str(text).unwrap();
            for chunk in poll["chunks"].as_array().unwrap() {
                job_output.push_str(chunk["text"].as_str().unwrap());
            }
            cursor = poll["next_cursor"].as_u64().unwrap();
            if poll["state"] == "terminal" && poll["has_more"] == false {
                break poll;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(polled["terminal"]["kind"], "exited");
        assert_eq!(job_output, "ran: build");

        // close_session.
        let closed = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(
                7,
                "tools/call",
                json!({ "name": "close_session", "arguments": { "session": "mock-alice" } }),
            ),
        );
        assert_eq!(closed.status, 200);
        assert_eq!(closed.body["result"]["isError"], false);

        // DELETE terminates the MCP session; it is unknown afterwards.
        let mut delete = agent
            .delete(format!("http://{addr}"))
            .header("Authorization", "Bearer tok-alice")
            .header("Mcp-Session-Id", &session)
            .call()
            .expect("delete");
        assert_eq!(delete.status().as_u16(), 204);
        let _ = delete.body_mut().read_to_string();
        let gone = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(8, "tools/list", json!({})),
        );
        assert_eq!(gone.status, 404);
    }

    /// The public jail profile carries no caller-selected tenant or host path:
    /// auth supplies identity and Model B supplies the host-owned piles.
    #[test]
    fn jail_http_open_session_schema_and_call_hide_host_plumbing() {
        let state = test_state_for_backend(vec![], Duration::from_secs(3600), "jail");
        let token = state.tokens.resolve("tok-alice").expect("alice token");
        let mut hostile = rpc(
            0,
            "tools/call",
            json!({
                "name": "open_session",
                "arguments": {
                    "pile_host_path": "/attacker/chosen.pile",
                    "pile_guest_path": "/attacker/chosen-guest",
                }
            }),
        );
        enforce_tenant_scope(&state, &token, &mut hostile).expect("scope synthesis");
        assert_eq!(hostile["params"]["arguments"]["tenant"], "alice");
        assert_eq!(
            hostile["params"]["arguments"]["pile_host_path"],
            "/host-owned/by-jail-backend/self.pile"
        );
        assert!(
            hostile["params"]["arguments"]
                .get("pile_guest_path")
                .is_none(),
            "caller-controlled guest path must be removed"
        );

        let addr = spawn_server(state);
        let agent = agent();
        let tok = Some("tok-alice");
        let init = post(
            &agent,
            addr,
            tok,
            None,
            None,
            &rpc(1, "initialize", json!({ "protocolVersion": "2025-06-18" })),
        );
        let session = init.session.expect("initialize must issue a session");

        let listed = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(2, "tools/list", json!({})),
        );
        let open = listed.body["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "open_session")
            .expect("open_session schema");
        let properties = open["inputSchema"]["properties"].as_object().unwrap();
        assert!(!properties.contains_key("tenant"));
        assert!(!properties.contains_key("pile_host_path"));
        assert!(open["inputSchema"].get("required").is_none());

        let opened = post(
            &agent,
            addr,
            tok,
            Some(&session),
            None,
            &rpc(
                3,
                "tools/call",
                json!({ "name": "open_session", "arguments": {} }),
            ),
        );
        assert_eq!(opened.status, 200);
        assert_eq!(opened.body["result"]["isError"], false);
        assert_eq!(opened.body["result"]["content"][0]["text"], "mock-alice");
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
        let alice = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
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
        let bob = post(
            &agent,
            addr,
            Some("tok-bob"),
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
        let bob_session = bob.session.unwrap();

        // Alice's completed jobs remain tenant-scoped even after their
        // transport request is over: a job handle is an authority-bearing
        // object just like a sandbox session id.
        let started = post(
            &agent,
            addr,
            Some("tok-alice"),
            Some(&alice_session),
            None,
            &rpc(
                3,
                "tools/call",
                json!({ "name": "job_exec", "arguments": { "session": "mock-alice", "command": "private" } }),
            ),
        );
        let started_text = started.body["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        let started_json: Value = serde_json::from_str(started_text).unwrap();
        let alice_job = started_json["job_id"].as_str().unwrap();

        let poll_job = post(
            &agent,
            addr,
            Some("tok-bob"),
            Some(&bob_session),
            None,
            &rpc(
                4,
                "tools/call",
                json!({ "name": "job_poll", "arguments": { "job_id": alice_job, "cursor": 0 } }),
            ),
        );
        assert_eq!(poll_job.status, 403);

        let cancel_job = post(
            &agent,
            addr,
            Some("tok-bob"),
            Some(&bob_session),
            None,
            &rpc(
                5,
                "tools/call",
                json!({ "name": "job_cancel", "arguments": { "job_id": alice_job } }),
            ),
        );
        assert_eq!(cancel_job.status, 403);

        // ...and may not exec in alice's sandbox,
        let exec = post(
            &agent,
            addr,
            Some("tok-bob"),
            Some(&bob_session),
            None,
            &rpc(
                6,
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
                7,
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
                8,
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
            &rpc(9, "tools/list", json!({})),
        );
        assert_eq!(hijack.status, 403);
    }

    #[test]
    fn session_id_required_and_validated_after_initialize() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        let agent = agent();
        let tok = Some("tok-alice");

        // No Mcp-Session-Id on a non-initialize request: 400.
        let missing = post(
            &agent,
            addr,
            tok,
            None,
            None,
            &rpc(1, "tools/list", json!({})),
        );
        assert_eq!(missing.status, 400);

        // A session id the server never issued: 404.
        let bogus = post(
            &agent,
            addr,
            tok,
            Some("never-issued"),
            None,
            &rpc(2, "tools/list", json!({})),
        );
        assert_eq!(bogus.status, 404);
    }

    #[test]
    fn idle_sessions_expire() {
        // Zero idle timeout: the session is already stale on its second use.
        let addr = spawn_server(test_state(vec![], Duration::ZERO));
        let agent = agent();
        let init = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
        let session = init.session.unwrap();
        let expired = post(
            &agent,
            addr,
            Some("tok-alice"),
            Some(&session),
            None,
            &rpc(2, "tools/list", json!({})),
        );
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
        let evil = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            Some("https://evil.example"),
            &init,
        );
        assert_eq!(evil.status, 403);

        // Allowlisted origin: fine.
        let ok = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            Some("http://localhost:5173"),
            &init,
        );
        assert_eq!(ok.status, 200);

        // No Origin header (plain MCP client): fine.
        let plain = post(&agent, addr, Some("tok-alice"), None, None, &init);
        assert_eq!(plain.status, 200);
    }

    #[test]
    fn root_get_is_405_old_mcp_is_404_and_batches_are_400() {
        let addr = spawn_server(test_state(vec![], Duration::from_secs(3600)));
        let agent = agent();

        let mut get = agent.get(format!("http://{addr}")).call().expect("get");
        assert_eq!(get.status().as_u16(), 405);
        let _ = get.body_mut().read_to_string();

        let mut old_endpoint = agent
            .get(format!("http://{addr}/mcp"))
            .call()
            .expect("old endpoint");
        assert_eq!(old_endpoint.status().as_u16(), 404);
        let _ = old_endpoint.body_mut().read_to_string();

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

    /// The explicit request-body ceiling rejects an oversized body (repair #4
    /// HIGH follow-up): a body past `max_body_bytes` is refused with 413 rather
    /// than being buffered. We build a state with a tiny 1 KiB limit and POST a
    /// larger body.
    #[test]
    fn oversized_body_is_413() {
        // A dedicated state with a small explicit body cap.
        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        let mut tokens = HashMap::new();
        tokens.insert(
            "tok-alice".to_string(),
            TokenEntry {
                tenant: "alice".to_string(),
                backend: "mock".to_string(),
            },
        );
        let state = Arc::new(HttpState {
            server,
            tokens: TokenAuthority::in_memory(tokens),
            sessions: Mutex::new(HashMap::new()),
            oauth: None,
            config: HttpServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                backend_name: "mock".to_string(),
                allowed_origins: vec![],
                idle_timeout: Duration::from_secs(3600),
                max_body_bytes: 1024, // 1 KiB
                oauth: None,
                max_sessions_global: DEFAULT_MAX_SESSIONS_GLOBAL,
                max_sessions_per_tenant: DEFAULT_MAX_SESSIONS_PER_TENANT,
            },
        });
        let addr = spawn_server(state);
        let agent = agent();

        // A body well over 1 KiB: a command string padded past the cap.
        let big = "x".repeat(4096);
        let reply = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            None,
            &rpc(1, "initialize", json!({ "pad": big })),
        );
        assert_eq!(
            reply.status, 413,
            "oversized body must be 413: {}",
            reply.body
        );

        // A small body still works (sanity: the limit is not rejecting everything).
        let ok = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            None,
            &rpc(2, "initialize", json!({})),
        );
        assert_eq!(ok.status, 200);
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

    /// The token-store operations that back the `user` CLI verbs, exercised
    /// directly (the CLI handlers themselves build a jail backend + do IO, so
    /// the testable seam is the store): `user create`/`user token reset` mint
    /// by tenant, `user token show` looks up by tenant, and `user destroy` /
    /// `user token reset` remove by tenant.
    #[test]
    fn user_verb_token_semantics() {
        let mut store = TokenStore::default();

        // `user create alice` -> mint a jail token for alice.
        let alice = store.mint("alice", "jail");
        // `user create bob` -> mint one for bob.
        let bob = store.mint("bob", "jail");
        assert_eq!(store.tokens.len(), 2);

        // `user token show alice` -> exactly alice's token, looked up by tenant.
        let alices: Vec<&String> = store
            .tokens
            .iter()
            .filter(|(_, e)| e.tenant == "alice")
            .map(|(t, _)| t)
            .collect();
        assert_eq!(alices, vec![&alice]);

        // `user token reset alice` -> remove alice's, mint a fresh one; bob's
        // token is untouched.
        let before = store.tokens.len();
        store.tokens.retain(|_, e| e.tenant != "alice");
        let revoked = before - store.tokens.len();
        assert_eq!(revoked, 1);
        let alice2 = store.mint("alice", "jail");
        assert_ne!(alice, alice2);
        assert!(store.tokens.contains_key(&bob), "reset must not touch bob");
        assert_eq!(store.tokens.len(), 2);

        // `user destroy alice` -> remove every alice token (here: the fresh one).
        let before = store.tokens.len();
        store.tokens.retain(|_, e| e.tenant != "alice");
        assert_eq!(before - store.tokens.len(), 1);
        assert!(!store.tokens.values().any(|e| e.tenant == "alice"));
        assert!(store.tokens.contains_key(&bob), "destroy alice keeps bob");

        // `user token show alice` now finds nothing.
        assert!(!store.tokens.values().any(|e| e.tenant == "alice"));
    }

    // -- repair #5 HIGH: atomic auth-store persistence ----------------------

    /// [`atomic_write_0600`] never leaves a truncate-in-place window and writes
    /// mode 0600 from the first byte: the destination is created 0600 (never a
    /// world-perms gap), an overwrite is a rename (either the whole old or whole
    /// new content is visible, never a torn prefix), and no `.tmp` litter is
    /// left behind on success.
    #[test]
    #[cfg(unix)]
    fn atomic_write_is_0600_and_leaves_no_tmp() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "playground_atomic_{}_{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");

        // First write creates the file 0600.
        atomic_write_0600(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created file must be 0600 from the first byte");

        // Overwriting a file whose mode was tampered to 0644 still yields 0600
        // (the write goes through a fresh 0600 temp + rename, not an in-place
        // truncate that would keep the loose mode).
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        atomic_write_0600(&path, b"second-and-longer").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second-and-longer");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "overwrite restores 0600 (no truncate-in-place)"
        );

        // No `.tmp` sibling survives a successful write.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp files left after a clean write"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- repair #5 HIGH: live token revocation (no restart) -----------------

    /// A disk-backed [`TokenAuthority`] picks up a store rewritten out of band
    /// (the CLI's `token reset`/`destroy`, a separate process) on the very next
    /// request: a revoked token is rejected immediately and a freshly-minted one
    /// accepted immediately, with no server restart.
    #[test]
    fn live_token_authority_tracks_disk_reset() {
        let dir = std::env::temp_dir().join(format!(
            "playground_live_tokens_{}_{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tokens.json");

        // Seed a store on disk with alice's original token, then boot a server
        // whose authority tracks that file.
        let mut store = TokenStore::default();
        store.tokens.insert(
            "tok-old".to_string(),
            TokenEntry {
                tenant: "alice".to_string(),
                backend: "mock".to_string(),
            },
        );
        store.save(&path).unwrap();

        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        let loaded = TokenStore::load(&path).unwrap();
        let state = Arc::new(HttpState {
            server,
            tokens: TokenAuthority::from_disk(loaded, path.clone()),
            sessions: Mutex::new(HashMap::new()),
            oauth: None,
            config: HttpServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                backend_name: "mock".to_string(),
                allowed_origins: vec![],
                idle_timeout: Duration::from_secs(3600),
                max_body_bytes: DEFAULT_MAX_BODY_BYTES,
                oauth: None,
                max_sessions_global: DEFAULT_MAX_SESSIONS_GLOBAL,
                max_sessions_per_tenant: DEFAULT_MAX_SESSIONS_PER_TENANT,
            },
        });
        let addr = spawn_server(state);
        let agent = agent();

        // The original token works.
        let ok = post(
            &agent,
            addr,
            Some("tok-old"),
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
        assert_eq!(ok.status, 200, "original token accepted before reset");

        // Out-of-band `token reset`: rewrite the store atomically with a fresh
        // token for alice, dropping the old one — exactly what the CLI does in a
        // separate process. Ensure the mtime advances so the tracker notices
        // even on a coarse-resolution clock.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let mut reset = TokenStore::default();
        reset.tokens.insert(
            "tok-new".to_string(),
            TokenEntry {
                tenant: "alice".to_string(),
                backend: "mock".to_string(),
            },
        );
        reset.save(&path).unwrap();

        // WITHOUT a restart: the old token is now rejected...
        let revoked = post(
            &agent,
            addr,
            Some("tok-old"),
            None,
            None,
            &rpc(2, "initialize", json!({})),
        );
        assert_eq!(
            revoked.status, 401,
            "revoked token rejected immediately, no restart"
        );

        // ...and the freshly-minted one is accepted immediately.
        let fresh = post(
            &agent,
            addr,
            Some("tok-new"),
            None,
            None,
            &rpc(3, "initialize", json!({})),
        );
        assert_eq!(
            fresh.status, 200,
            "freshly-issued token accepted immediately, no restart"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- repair #5 HIGH: transport-session sweep + caps ---------------------

    /// Idle transport sessions are swept on the next `initialize` and never
    /// accrete: with a zero idle timeout each new session sweeps the previous
    /// one, so the table never grows past one entry no matter how many
    /// `initialize`s arrive.
    #[test]
    fn transport_sessions_sweep_on_idle() {
        let state = test_state(vec![], Duration::ZERO);
        let addr = spawn_server(state.clone());
        let agent = agent();
        for i in 0..5 {
            let init = post(
                &agent,
                addr,
                Some("tok-alice"),
                None,
                None,
                &rpc(i, "initialize", json!({})),
            );
            assert_eq!(init.status, 200);
        }
        let live = state.sessions.lock().unwrap().len();
        assert_eq!(
            live, 1,
            "zero-idle sweep keeps the table at a single fresh entry"
        );
    }

    /// The per-tenant cap evicts a tenant's own idlest session (never another
    /// tenant's) and the global cap refuses `initialize` with 503 when the whole
    /// table is full.
    #[test]
    fn transport_sessions_respect_caps() {
        // Build a state with a long idle timeout (so nothing is swept for age)
        // and tiny caps: per-tenant 2, global 3.
        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        let mut tokens = HashMap::new();
        for (t, tenant) in [("tok-alice", "alice"), ("tok-bob", "bob")] {
            tokens.insert(
                t.to_string(),
                TokenEntry {
                    tenant: tenant.to_string(),
                    backend: "mock".to_string(),
                },
            );
        }
        let state = Arc::new(HttpState {
            server,
            tokens: TokenAuthority::in_memory(tokens),
            sessions: Mutex::new(HashMap::new()),
            oauth: None,
            config: HttpServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                backend_name: "mock".to_string(),
                allowed_origins: vec![],
                idle_timeout: Duration::from_secs(3600),
                max_body_bytes: DEFAULT_MAX_BODY_BYTES,
                oauth: None,
                max_sessions_global: 3,
                max_sessions_per_tenant: 2,
            },
        });
        let addr = spawn_server(state.clone());
        let agent = agent();

        // alice mints 4 sessions; the per-tenant cap of 2 keeps only her 2 newest.
        let mut alice_sessions = Vec::new();
        for i in 0..4 {
            let init = post(
                &agent,
                addr,
                Some("tok-alice"),
                None,
                None,
                &rpc(i, "initialize", json!({})),
            );
            assert_eq!(init.status, 200);
            alice_sessions.push(init.session.unwrap());
        }
        {
            let sessions = state.sessions.lock().unwrap();
            let alice_live = sessions.values().filter(|s| s.tenant == "alice").count();
            assert_eq!(alice_live, 2, "per-tenant cap holds alice to 2 sessions");
            // Her two oldest were evicted; the two newest survive.
            assert!(!sessions.contains_key(&alice_sessions[0]));
            assert!(!sessions.contains_key(&alice_sessions[1]));
            assert!(sessions.contains_key(&alice_sessions[2]));
            assert!(sessions.contains_key(&alice_sessions[3]));
        }

        // bob mints one (table now: alice 2 + bob 1 = 3 = global cap).
        let bob1 = post(
            &agent,
            addr,
            Some("tok-bob"),
            None,
            None,
            &rpc(10, "initialize", json!({})),
        );
        assert_eq!(bob1.status, 200);
        assert_eq!(
            state.sessions.lock().unwrap().len(),
            3,
            "table at the global cap"
        );

        // bob's second initialize: bob is under his per-tenant cap (1 < 2), so no
        // self-eviction happens, and the global table is full → 503. alice's
        // sessions are untouched (a tenant can't crowd others out).
        let bob2 = post(
            &agent,
            addr,
            Some("tok-bob"),
            None,
            None,
            &rpc(11, "initialize", json!({})),
        );
        assert_eq!(
            bob2.status, 503,
            "global cap refuses a new session when full"
        );
        let sessions = state.sessions.lock().unwrap();
        assert_eq!(
            sessions.values().filter(|s| s.tenant == "alice").count(),
            2,
            "alice untouched"
        );

        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("nonexistent-cleanup"));
    }
}

//! MCP provider skeleton: exposes sandbox sessions over the Model Context
//! Protocol.
//!
//! Because a shell is **stateful** (cwd, env, running processes), the MCP
//! surface is a *session* model rather than a stateless tool call:
//!
//!   - `open_session` -> provision a sandbox via the backend, return a session
//!     id (one tenant = one pile mount × driver).
//!   - `exec`         -> run a command in that session's shell.
//!   - `close_session`-> tear the sandbox down.
//!
//! This module defines the [`SandboxProvider`] (session registry +
//! multi-tenancy) and, on top of it, a minimal dependency-free MCP server
//! ([`McpServer`]): JSON-RPC 2.0 over a pluggable transport. Two transports
//! exist:
//!
//!   - [`StdioTransport`] (here): newline-delimited JSON over stdin/stdout,
//!     blocking, operator-local, unauthenticated.
//!   - `crate::mcp_http` (feature `mcp-http`): Streamable HTTP with
//!     per-sandbox bearer-token auth — the internet-facing transport. It calls
//!     [`McpServer::handle_request`] directly and does tenant authorization
//!     *before* dispatch.
//!
//! ## Hand-rolled JSON-RPC (deliberate)
//!
//! The MCP surface this provider exposes is three tools and a handful of
//! lifecycle methods — small enough to hand-roll over `serde_json` (already a
//! dependency) instead of pulling the official Rust SDK
//! [`rmcp`](https://crates.io/crates/rmcp). Keeping the surface tiny and
//! explicit is worth more here than SDK conformance machinery we would not use.
//! The HTTP transport bridges to this blocking core with
//! `tokio::task::spawn_blocking` rather than rewriting the provider async.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use crate::sandbox::{
    ExecRequest, ExecResult, LifecycleLocks, PileMount, SandboxBackend, SessionId, SessionSpec,
    Tenant,
};

// ---------------------------------------------------------------------------
// Admission control
// ---------------------------------------------------------------------------

/// Default cap on `exec`s in flight ACROSS ALL tenants. This is the daemon
/// bound: a tenant `exec` pins one tokio blocking-pool worker (the provider is
/// blocking; the HTTP transport bridges via `spawn_blocking`) plus one jail
/// process for up to the timeout ceiling, so the global cap keeps a flood from
/// occupying every blocking thread and wedging the whole service.
pub const DEFAULT_GLOBAL_EXEC_LIMIT: usize = 32;

/// Default cap on `exec`s in flight FOR ONE tenant. The per-tenant bound is the
/// fairness guarantee: no single authenticated tenant can consume all the
/// global slots and starve everyone else.
pub const DEFAULT_PER_TENANT_EXEC_LIMIT: usize = 4;

/// Default bound on how many `exec`s may WAIT for a slot (globally). Past this,
/// admission is rejected immediately rather than queued — a bounded queue, so a
/// burst cannot pile up unbounded waiters (each holding a blocking-pool thread).
pub const DEFAULT_MAX_WAITERS: usize = 64;

/// How long a waiting `exec` blocks for a slot before giving up. Bounds the time
/// a queued request pins its blocking-pool thread.
const ADMISSION_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-tenant + global concurrency limiter for `exec`. Holds a permit for the
/// life of one `exec` and releases it (even on panic) via [`AdmissionGuard`].
///
/// Enforcement is a single mutex-guarded state + a condvar: an admitted `exec`
/// increments the global and per-tenant counters; a blocked one waits on the
/// condvar (bounded by [`AdmissionConfig::max_waiters`] and a wall-clock
/// timeout) until a permit frees or it is rejected. This is deliberately
/// std-only (no tokio): the provider is synchronous and this guards the blocking
/// side, which is exactly the scarce resource.
pub struct AdmissionControl {
    config: AdmissionConfig,
    state: Mutex<AdmissionState>,
    freed: Condvar,
}

/// Tunables for [`AdmissionControl`].
#[derive(Debug, Clone, Copy)]
pub struct AdmissionConfig {
    pub global_limit: usize,
    pub per_tenant_limit: usize,
    pub max_waiters: usize,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        AdmissionConfig {
            global_limit: DEFAULT_GLOBAL_EXEC_LIMIT,
            per_tenant_limit: DEFAULT_PER_TENANT_EXEC_LIMIT,
            max_waiters: DEFAULT_MAX_WAITERS,
        }
    }
}

#[derive(Default)]
struct AdmissionState {
    /// Total `exec`s currently holding a permit.
    global_in_flight: usize,
    /// Per-tenant in-flight counts (entries drop to 0 stay until swept lazily;
    /// a handful of tenants, so unbounded growth is not a concern).
    per_tenant: HashMap<String, usize>,
    /// Number of `exec`s currently blocked waiting for a permit.
    waiters: usize,
}

impl AdmissionControl {
    pub fn new(config: AdmissionConfig) -> Self {
        AdmissionControl {
            config,
            state: Mutex::new(AdmissionState::default()),
            freed: Condvar::new(),
        }
    }

    /// Acquire a permit for one `exec` by `tenant`, or return an error if the
    /// caps are full and either the wait queue is full or the wait times out.
    /// The returned guard releases the permit (and wakes a waiter) on drop.
    fn acquire(&self, tenant: &str) -> Result<AdmissionGuard<'_>> {
        let mut state = self.state.lock().expect("admission poisoned");
        loop {
            let tenant_in_flight = state.per_tenant.get(tenant).copied().unwrap_or(0);
            let has_slot = state.global_in_flight < self.config.global_limit
                && tenant_in_flight < self.config.per_tenant_limit;
            if has_slot {
                state.global_in_flight += 1;
                *state.per_tenant.entry(tenant.to_string()).or_insert(0) += 1;
                return Ok(AdmissionGuard {
                    control: self,
                    tenant: tenant.to_string(),
                });
            }
            // No slot. Refuse to queue past the waiter bound (a bounded queue).
            if state.waiters >= self.config.max_waiters {
                return Err(anyhow!(
                    "sandbox busy: {} exec(s) already queued (global {}/{}, tenant '{}' {}/{}); \
                     retry shortly",
                    state.waiters,
                    state.global_in_flight,
                    self.config.global_limit,
                    tenant,
                    tenant_in_flight,
                    self.config.per_tenant_limit
                ));
            }
            state.waiters += 1;
            let (next, wait) = self
                .freed
                .wait_timeout(state, ADMISSION_WAIT_TIMEOUT)
                .expect("admission poisoned");
            state = next;
            state.waiters -= 1;
            if wait.timed_out() {
                // Retry once more (a permit may have freed as we timed out); if
                // still full, give up so the caller's blocking-pool thread is not
                // pinned indefinitely.
                let tenant_in_flight = state.per_tenant.get(tenant).copied().unwrap_or(0);
                if state.global_in_flight >= self.config.global_limit
                    || tenant_in_flight >= self.config.per_tenant_limit
                {
                    return Err(anyhow!(
                        "sandbox busy: timed out after {:?} waiting for an exec slot \
                         (global {}/{}, tenant '{}' {}/{})",
                        ADMISSION_WAIT_TIMEOUT,
                        state.global_in_flight,
                        self.config.global_limit,
                        tenant,
                        tenant_in_flight,
                        self.config.per_tenant_limit
                    ));
                }
            }
            // Woken (or a slot may exist): loop and re-check.
        }
    }

    fn release(&self, tenant: &str) {
        let mut state = self.state.lock().expect("admission poisoned");
        state.global_in_flight = state.global_in_flight.saturating_sub(1);
        if let Some(n) = state.per_tenant.get_mut(tenant) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                state.per_tenant.remove(tenant);
            }
        }
        drop(state);
        // Wake ALL waiters, not one: a freed slot might be unusable to the first
        // waiter it wakes (that waiter's tenant could still be at its per-tenant
        // cap) while a DIFFERENT tenant's waiter could take it. `notify_all` lets
        // every waiter re-check `has_slot` so the freed permit is never stranded
        // behind a capped-tenant waiter. Waiter counts are small (bounded by
        // `max_waiters`), so the re-check herd is cheap.
        self.freed.notify_all();
    }
}

/// RAII permit: releases its admission slot (and wakes waiters) on drop, so a
/// permit is freed even if the guarded `exec` panics.
struct AdmissionGuard<'a> {
    control: &'a AdmissionControl,
    tenant: String,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        self.control.release(&self.tenant);
    }
}

/// Parameters for the `open_session` MCP method.
#[derive(Debug, Clone)]
pub struct OpenSessionParams {
    pub tenant: Tenant,
    pub cwd: Option<std::path::PathBuf>,
    pub env: Vec<(String, String)>,
}

/// Parameters for the `exec` MCP method.
#[derive(Debug, Clone)]
pub struct ExecParams {
    pub session: SessionId,
    pub command: String,
    pub cwd: Option<std::path::PathBuf>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

/// One registry entry: which tenant a session belongs to, plus a reference
/// count of how many live MCP endpoints/connections currently hold it open.
///
/// The refcount is the multi-endpoint sharing invariant: two honest
/// connections from the SAME tenant map to the SAME backend session id (the
/// jail is per-tenant, not per-connection), so they must SHARE one jail
/// concurrently and teardown must happen only when the LAST handle detaches —
/// otherwise the first connection's `close_session` would evict the second's
/// still-live box.
struct SessionEntry {
    tenant: Tenant,
    refs: usize,
}

/// The sandbox MCP provider: owns a backend and the set of live sessions.
///
/// Multi-tenancy: each session records its [`Tenant`] so a single provider can
/// host several piles/drivers at once. The provider enforces that `exec` and
/// `close_session` only touch sessions it opened.
///
/// Reference counting: multiple endpoints from one tenant share a single
/// backend session (see [`SessionEntry`]). `open_session` bumps the count and
/// `close_session` decrements it, only DETACHING the backend at the last
/// handle; `destroy_session` is the explicit hard teardown that ignores the
/// count.
pub struct SandboxProvider {
    backend: Box<dyn SandboxBackend>,
    sessions: Mutex<HashMap<SessionId, SessionEntry>>,
    /// Per-canonical-tenant lifecycle lock. Serializes `open_session` /
    /// `close_session` / `destroy_session` for one tenant so the refcount
    /// close/open race (repair #1 follow-up) cannot orphan a concurrently-opened
    /// session: `close_session` holds this lock across the whole
    /// decrement + backend-close + registry-remove, so a same-tenant
    /// `open_session` either runs entirely before (and is not evicted) or
    /// entirely after (and re-opens cleanly). Keyed by
    /// [`SandboxBackend::canonical_key`], the same key the jail backend locks on.
    lifecycle: LifecycleLocks,
    /// Per-tenant + global admission gate for `exec` (repair #4). A tenant
    /// command pins one blocking-pool worker + one jail process for up to the
    /// timeout ceiling; this caps how many run at once so no single tenant can
    /// occupy every worker (per-tenant limit) and no flood can wedge the daemon
    /// (global limit), with a bounded wait queue in between.
    admission: AdmissionControl,
}

impl SandboxProvider {
    pub fn new(backend: Box<dyn SandboxBackend>) -> Self {
        Self::with_admission(backend, AdmissionConfig::default())
    }

    /// [`SandboxProvider::new`] with an explicit admission-control config (the
    /// server passes operator-tuned limits; tests pass tight ones to exercise
    /// the caps).
    pub fn with_admission(backend: Box<dyn SandboxBackend>, admission: AdmissionConfig) -> Self {
        SandboxProvider {
            backend,
            sessions: Mutex::new(HashMap::new()),
            lifecycle: LifecycleLocks::new(),
            admission: AdmissionControl::new(admission),
        }
    }

    /// MCP `open_session`: provision a sandbox and register it (or attach to an
    /// already-open one from the same tenant, sharing the backend session).
    ///
    /// The backend maps a tenant to a stable session id, so a second endpoint
    /// from the same tenant lands on the same id: we bump that entry's refcount
    /// instead of re-opening. A different tenant resolving to the same id is
    /// rejected here (provider-layer defence complementing the jail backend's
    /// ZFS-property provenance check).
    pub fn open_session(&self, params: OpenSessionParams) -> Result<SessionId> {
        // Serialize against a concurrent same-tenant close: hold the per-tenant
        // lifecycle lock across the backend open AND the refcount bump, so this
        // open cannot land in the window where close has decremented to 0 but not
        // yet removed the entry (which would orphan us).
        let key = self.backend.canonical_key(&params.tenant);
        self.lifecycle.with_lock(&key, || {
            let spec = SessionSpec {
                tenant: params.tenant.clone(),
                cwd: params.cwd.clone(),
                env: params.env.clone(),
            };
            let id = self.backend.open_session(&spec)?;
            let mut guard = self.sessions.lock().expect("sessions poisoned");
            let entry = guard.entry(id.clone()).or_insert(SessionEntry {
                tenant: params.tenant.clone(),
                refs: 0,
            });
            if entry.tenant.label != params.tenant.label {
                return Err(anyhow!(
                    "session id {} already bound to tenant '{}', refusing to attach tenant '{}'",
                    id.as_str(),
                    entry.tenant.label,
                    params.tenant.label
                ));
            }
            entry.refs += 1;
            Ok(id)
        })
    }

    /// MCP `exec`: run a command in an open session.
    ///
    /// Streaming/long-running commands: the current [`SandboxBackend::exec`] is
    /// blocking and returns a whole [`ExecResult`]. Streaming will be layered in
    /// as an MCP notification channel (chunked stdout/stderr) once the transport
    /// is chosen — the backend trait will grow an `exec_streaming` variant then,
    /// not before.
    pub fn exec(&self, params: ExecParams) -> Result<ExecResult> {
        // Resolve the owning tenant (also enforces that this provider knows the
        // session) so admission can key the per-tenant limit on it.
        let tenant = {
            let guard = self.sessions.lock().expect("sessions poisoned");
            match guard.get(&params.session) {
                Some(entry) => entry.tenant.label.clone(),
                None => return Err(anyhow!("unknown session {}", params.session.as_str())),
            }
        };
        // ADMISSION: hold a per-tenant + global permit for the whole exec. When
        // the caps are full this blocks (bounded) or is rejected; the guard
        // releases the permit on drop, including if the backend exec panics.
        let _permit = self.admission.acquire(&tenant)?;
        let request = ExecRequest {
            command: params.command,
            cwd: params.cwd,
            stdin: params.stdin,
            timeout: params.timeout,
        };
        self.backend.exec(&params.session, &request)
    }

    /// MCP `close_session`: drop one endpoint's handle on a sandbox. Both
    /// shipped backends (jail, lima) are persistent, so this only DETACHES — and
    /// with refcounting it detaches only when the LAST endpoint sharing the box
    /// leaves. A `close_session` from one of several handles just decrements the
    /// count and leaves the box (and every other handle's `exec`) untouched; the
    /// box lives on and the same tenant can reconnect. Use `destroy_session` to
    /// remove it for good.
    pub fn close_session(&self, session: &SessionId) -> Result<()> {
        // Resolve the tenant so we can lock on the SAME per-tenant key
        // `open_session` uses. If the session is unknown, there is nothing to
        // close (and nothing to serialize).
        let tenant = {
            let guard = self.sessions.lock().expect("sessions poisoned");
            match guard.get(session) {
                Some(entry) => entry.tenant.clone(),
                None => return Err(anyhow!("unknown session {}", session.as_str())),
            }
        };
        let key = self.backend.canonical_key(&tenant);
        // Hold the per-tenant lifecycle lock across the ENTIRE close: the
        // decrement, the last-handle backend detach, AND the registry removal.
        // A concurrent same-tenant `open_session` blocks on this lock, so it
        // cannot slip into the old window (refs decremented to 0, lock released,
        // then we remove the entry it just bumped) and be orphaned. It runs
        // wholly before or wholly after this close.
        self.lifecycle.with_lock(&key, || {
            {
                let mut guard = self.sessions.lock().expect("sessions poisoned");
                let entry = guard
                    .get_mut(session)
                    .ok_or_else(|| anyhow!("unknown session {}", session.as_str()))?;
                entry.refs = entry.refs.saturating_sub(1);
                if entry.refs > 0 {
                    // Other endpoints still hold this box — do NOT touch the backend.
                    return Ok(());
                }
            }
            // Last handle: detach the backend, then drop the entry. The
            // per-tenant lifecycle lock (held for this whole closure) serializes
            // this against a concurrent open; the short sessions-map lock is
            // still released around the backend call (it can block on
            // ssh/limactl). We remove the entry only after the close succeeds so
            // a failed close leaves the session known (and retryable).
            self.backend.close_session(session)?;
            self.sessions
                .lock()
                .expect("sessions poisoned")
                .remove(session);
            Ok(())
        })
    }

    /// MCP `destroy_session`: permanently tear a sandbox down and deregister it,
    /// REGARDLESS of refcount — this is the explicit hard teardown (jail:
    /// `jail -r` + `zfs destroy`; lima: `limactl stop` + `limactl delete`), as
    /// opposed to `close_session`'s last-handle detach. Any other endpoints still
    /// holding the box are cut off. Destroy now takes the per-tenant lifecycle
    /// lock, so it serializes against concurrent open/close of the same box
    /// (repair #3); draining in-flight EXECs during a destroy (a fully
    /// transactional exec lifecycle) is still future work.
    pub fn destroy_session(&self, session: &SessionId) -> Result<()> {
        // Resolve the tenant to lock on the same per-tenant key as open/close, so
        // a hard teardown serializes against concurrent lifecycle ops on this
        // box rather than racing them.
        let tenant = {
            let guard = self.sessions.lock().expect("sessions poisoned");
            match guard.get(session) {
                Some(entry) => entry.tenant.clone(),
                None => return Err(anyhow!("unknown session {}", session.as_str())),
            }
        };
        let key = self.backend.canonical_key(&tenant);
        self.lifecycle.with_lock(&key, || {
            self.backend.destroy_session(session)?;
            self.sessions
                .lock()
                .expect("sessions poisoned")
                .remove(session);
            Ok(())
        })
    }

    /// Tear down every session this provider still has open, best-effort.
    ///
    /// This is the leak backstop: when a connection ends (stdio EOF/disconnect)
    /// or the process is asked to stop, every sandbox the connection opened must
    /// be released so a crashed or disconnected client can never orphan a VM or
    /// jail. Failures to close an individual session are logged to stderr and do
    /// not abort the sweep — a backend hiccup on one session must not strand the
    /// rest. The session registry is left empty regardless. This is independent
    /// of refcounts: each unique backend session is closed exactly ONCE (the map
    /// keys on session id, so N endpoints sharing one box already collapse to one
    /// entry), so process teardown never double-closes a shared box.
    ///
    /// Returns the number of sessions that failed to close cleanly (0 on a full
    /// teardown).
    pub fn close_all_sessions(&self) -> usize {
        // Drain the registry under the lock, then close each entry without
        // holding it (backend close can block on limactl/ssh).
        let sessions: Vec<SessionId> = {
            let mut guard = self.sessions.lock().expect("sessions poisoned");
            guard.drain().map(|(id, _)| id).collect()
        };
        let mut failed = 0usize;
        for id in &sessions {
            if let Err(e) = self.backend.close_session(id) {
                failed += 1;
                eprintln!(
                    "playground mcp: failed to close session {} on teardown: {e:#}",
                    id.as_str()
                );
            }
        }
        failed
    }

    /// Process-shutdown hook: detach every open session, then spin DOWN every
    /// owned sandbox that must not outlive the process (Lima VMs; jail is a
    /// no-op by design — its kernel records are free and persist). The inverse
    /// of the startup `reattach_all` sweep. Returns how many sandboxes were spun
    /// down. Best-effort: session-close failures are logged by
    /// `close_all_sessions` and do not block the spin-down.
    #[cfg(feature = "mcp-http")]
    pub fn shutdown(&self) -> usize {
        self.close_all_sessions();
        match self.backend.shutdown() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("playground mcp: sandbox spin-down on shutdown failed: {e:#}");
                0
            }
        }
    }

    /// The tenant label a live session belongs to, or `None` if this provider
    /// never opened it (or already closed it).
    ///
    /// This is the hook the HTTP transport uses to authorize `exec` /
    /// `close_session` tool calls against the caller's token *before*
    /// dispatch: a token may only touch sessions of its own tenant.
    #[cfg(feature = "mcp-http")]
    pub fn session_tenant(&self, session: &SessionId) -> Option<String> {
        self.sessions
            .lock()
            .expect("sessions poisoned")
            .get(session)
            .map(|entry| entry.tenant.label.clone())
    }
}

// ---------------------------------------------------------------------------
// MCP server surface
// ---------------------------------------------------------------------------
//
// A minimal, dependency-free MCP server: newline-delimited JSON-RPC 2.0 over a
// pluggable transport. v1 ships a blocking stdio transport (`StdioTransport`).
//
// Protocol coverage (client-visible):
//   - `initialize`                -> capabilities + serverInfo
//   - `notifications/initialized` -> acknowledged (no response, per JSON-RPC
//                                    notification semantics)
//   - `tools/list`                -> the sandbox tools
//   - `tools/call`                -> dispatch to SandboxProvider
//
// The tools mirror the provider verbs: `open_session`, `exec`,
// `close_session`, `destroy_session`.

/// The newest MCP protocol version this server speaks (and the one it
/// advertises when the client requests something it doesn't know).
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// All protocol versions this server can serve. `initialize` echoes the
/// client's requested version when it is one of these (per-spec negotiation);
/// otherwise it answers with [`MCP_PROTOCOL_VERSION`]. The tool surface is
/// identical across all three, so no per-version branching exists elsewhere.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// A message transport for the MCP server: read one request, write one
/// response, both as a single JSON value (framing is the transport's business).
///
/// [`StdioTransport`] (newline-delimited JSON over stdin/stdout, blocking)
/// implements this. The Streamable-HTTP transport (`crate::mcp_http`,
/// per-sandbox bearer tokens, feature `mcp-http`) deliberately does *not*: its
/// request/response pairing is carried by HTTP itself, so it bypasses the
/// pull-loop framing and calls [`McpServer::handle_request`] per POST.
pub trait McpTransport {
    /// Read the next request frame. `Ok(None)` means the peer closed the
    /// connection (clean EOF); the server loop exits.
    fn read_message(&mut self) -> Result<Option<Value>>;
    /// Write one response frame.
    fn write_message(&mut self, msg: &Value) -> Result<()>;
}

/// Blocking stdio transport: newline-delimited JSON-RPC 2.0.
///
/// Each line on stdin is one JSON-RPC request object; each response is written
/// as one line to stdout. Blocking reads are fine for v1 (one client, one
/// stdio pipe); the async story arrives with the HTTP transport.
pub struct StdioTransport<R: BufRead, W: Write> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> StdioTransport<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        StdioTransport { reader, writer }
    }
}

impl StdioTransport<std::io::BufReader<std::io::Stdin>, std::io::Stdout> {
    /// The default: read from process stdin, write to process stdout.
    pub fn stdio() -> Self {
        StdioTransport::new(std::io::BufReader::new(std::io::stdin()), std::io::stdout())
    }
}

impl<R: BufRead, W: Write> McpTransport for StdioTransport<R, W> {
    fn read_message(&mut self) -> Result<Option<Value>> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line)?;
            if n == 0 {
                return Ok(None); // EOF
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue; // tolerate blank keep-alive lines
            }
            let value: Value = serde_json::from_str(trimmed)
                .map_err(|e| anyhow!("invalid JSON-RPC frame: {e}"))?;
            return Ok(Some(value));
        }
    }

    fn write_message(&mut self, msg: &Value) -> Result<()> {
        let line = serde_json::to_string(msg)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

/// The MCP server: owns a [`SandboxProvider`] and dispatches JSON-RPC requests
/// over a [`McpTransport`].
pub struct McpServer {
    provider: SandboxProvider,
}

impl McpServer {
    pub fn new(provider: SandboxProvider) -> Self {
        McpServer { provider }
    }

    /// The provider behind this server. The HTTP transport uses this for
    /// pre-dispatch tenant authorization ([`SandboxProvider::session_tenant`]).
    #[cfg(feature = "mcp-http")]
    pub fn provider(&self) -> &SandboxProvider {
        &self.provider
    }

    /// Run the request/response loop until the transport reports EOF or errors.
    ///
    /// On *any* exit — clean EOF, a read/write error, or the loop unwinding —
    /// every session this server opened is torn down (best-effort). This is the
    /// leak backstop: a client that disconnects mid-session (or crashes) must
    /// not orphan a VM/jail. See [`SandboxProvider::close_all_sessions`].
    pub fn serve_loop(&self, transport: &mut dyn McpTransport) -> Result<()> {
        let outcome = self.serve_inner(transport);
        // Teardown runs on both the happy path and the error path.
        self.provider.close_all_sessions();
        outcome
    }

    fn serve_inner(&self, transport: &mut dyn McpTransport) -> Result<()> {
        while let Some(request) = transport.read_message()? {
            if let Some(response) = self.handle_request(&request) {
                transport.write_message(&response)?;
            }
        }
        Ok(())
    }

    /// Serve the stdio transport with signal-safe teardown.
    ///
    /// Beyond [`serve_loop`](Self::serve_loop)'s EOF/error teardown, this
    /// installs a SIGINT/SIGTERM handler that tears down all open sessions and
    /// exits the process — so `Ctrl+C` or a `kill` on the server never leaks a
    /// sandbox either. The signal handler needs `'static` access to the
    /// provider, hence the `Arc<Self>`.
    pub fn serve_stdio(
        self,
        transport: &mut StdioTransport<
            std::io::BufReader<std::io::Stdin>,
            std::io::Stdout,
        >,
    ) -> Result<()> {
        let server = std::sync::Arc::new(self);
        let on_signal = server.clone();
        // On SIGINT/SIGTERM: close every open session, then exit. Best-effort;
        // the handler runs on ctrlc's own thread, so touching the provider's
        // Mutex is safe. Exit code mirrors "terminated cleanly".
        let _ = ctrlc::set_handler(move || {
            eprintln!("playground mcp: signal received — closing sessions before exit");
            on_signal.provider.close_all_sessions();
            std::process::exit(0);
        });
        server.serve_loop(transport)
    }

    /// Handle a single JSON-RPC message and produce the response, if any.
    ///
    /// Returns `None` for notifications (no `id`), which per JSON-RPC get no
    /// reply. This is the transport-independent core: the stdio loop calls it
    /// per line, the HTTP transport per POST body.
    pub fn handle_request(&self, request: &Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        match self.dispatch(method, params) {
            DispatchOutcome::Notification => None,
            DispatchOutcome::Result(result) => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                })
            }),
            DispatchOutcome::Error { code, message } => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": code, "message": message },
                })
            }),
        }
    }

    fn dispatch(&self, method: &str, params: Value) -> DispatchOutcome {
        match method {
            "initialize" => {
                // Version negotiation per spec: echo the client's requested
                // version when we support it, otherwise offer our newest.
                let requested = params.get("protocolVersion").and_then(Value::as_str);
                let version = requested
                    .filter(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(v))
                    .unwrap_or(MCP_PROTOCOL_VERSION);
                DispatchOutcome::Result(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "playground-sandbox", "version": env!("CARGO_PKG_VERSION") },
                }))
            }
            "notifications/initialized" => DispatchOutcome::Notification,
            "ping" => DispatchOutcome::Result(json!({})),
            "tools/list" => DispatchOutcome::Result(json!({ "tools": tool_schemas() })),
            "tools/call" => self.dispatch_tool_call(params),
            other => DispatchOutcome::Error {
                code: -32601,
                message: format!("method not found: {other}"),
            },
        }
    }

    fn dispatch_tool_call(&self, params: Value) -> DispatchOutcome {
        let name = match params.get("name").and_then(Value::as_str) {
            Some(n) => n,
            None => {
                return DispatchOutcome::Error {
                    code: -32602,
                    message: "tools/call missing 'name'".to_string(),
                };
            }
        };
        let args = params.get("arguments").cloned().unwrap_or(Value::Null);

        let outcome = match name {
            "open_session" => self.tool_open_session(args),
            "exec" => self.tool_exec(args),
            "close_session" => self.tool_close_session(args),
            "destroy_session" => self.tool_destroy_session(args),
            other => Err(anyhow!("unknown tool: {other}")),
        };

        match outcome {
            Ok(text) => DispatchOutcome::Result(tool_ok(&text)),
            // Tool-level failures are reported as an `isError` result (per MCP),
            // not a JSON-RPC protocol error — the model needs to see the text.
            Err(e) => DispatchOutcome::Result(tool_err(&format!("{e:#}"))),
        }
    }

    fn tool_open_session(&self, args: Value) -> Result<String> {
        let tenant = parse_tenant(&args)?;
        let cwd = args
            .get("cwd")
            .and_then(Value::as_str)
            .map(PathBuf::from);
        let env = parse_env(&args);
        let id = self.provider.open_session(OpenSessionParams { tenant, cwd, env })?;
        Ok(id.as_str().to_string())
    }

    fn tool_exec(&self, args: Value) -> Result<String> {
        let session = SessionId::new(
            args.get("session")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("exec missing 'session'"))?,
        );
        let command = args
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("exec missing 'command'"))?
            .to_string();
        let cwd = args.get("cwd").and_then(Value::as_str).map(PathBuf::from);
        let stdin = args
            .get("stdin")
            .and_then(Value::as_str)
            .map(|s| s.as_bytes().to_vec());
        let timeout = args
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .map(Duration::from_millis);
        let result = self.provider.exec(ExecParams {
            session,
            command,
            cwd,
            stdin,
            timeout,
        })?;
        Ok(render_exec_result(&result))
    }

    fn tool_close_session(&self, args: Value) -> Result<String> {
        let session = SessionId::new(
            args.get("session")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("close_session missing 'session'"))?,
        );
        self.provider.close_session(&session)?;
        Ok(format!("closed {}", session.as_str()))
    }

    fn tool_destroy_session(&self, args: Value) -> Result<String> {
        let session = SessionId::new(
            args.get("session")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("destroy_session missing 'session'"))?,
        );
        self.provider.destroy_session(&session)?;
        Ok(format!("destroyed {}", session.as_str()))
    }
}

/// Internal dispatch result: a JSON-RPC result, error, or a notification that
/// gets no reply.
enum DispatchOutcome {
    Notification,
    Result(Value),
    Error { code: i64, message: String },
}

/// The MCP `tools/list` schema for the sandbox tools.
fn tool_schemas() -> Value {
    json!([
        {
            "name": "open_session",
            "description": "Provision an isolated sandbox shell bound to a pile (append-only) and driver, and return its session id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "tenant": { "type": "string", "description": "Tenant label (persona / instance)." },
                    "pile_host_path": { "type": "string", "description": "Absolute host path to the pile file." },
                    "pile_guest_path": { "type": "string", "description": "Path the pile appears at inside the sandbox (default /pile/<name>)." },
                    "cwd": { "type": "string", "description": "Working directory (guest path) the shell starts in." },
                    "env": { "type": "object", "description": "Extra environment variables.", "additionalProperties": { "type": "string" } }
                },
                "required": ["tenant", "pile_host_path"]
            }
        },
        {
            "name": "exec",
            "description": "Run a shell command inside an open sandbox session (stateful cwd/env persist across calls).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id from open_session." },
                    "command": { "type": "string", "description": "Shell command line (run via sh -lc)." },
                    "cwd": { "type": "string", "description": "Per-call working directory override (guest path)." },
                    "stdin": { "type": "string", "description": "Optional stdin, as text." },
                    "timeout_ms": { "type": "integer", "description": "Wall-clock timeout in milliseconds." }
                },
                "required": ["session", "command"]
            }
        },
        {
            "name": "close_session",
            "description": "Release a sandbox session. Sandboxes are persistent (both the jail and lima backends): close_session only detaches, so the box stays alive and the same tenant can reconnect. Use destroy_session to remove it for good.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id from open_session." }
                },
                "required": ["session"]
            }
        },
        {
            "name": "destroy_session",
            "description": "Permanently tear down a sandbox session and free its storage. Both backends' sandboxes are persistent (close_session only detaches); this removes the box for good.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id from open_session." }
                },
                "required": ["session"]
            }
        }
    ])
}

/// A successful MCP tool result (single text content block).
fn tool_ok(text: &str) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ], "isError": false })
}

/// A failed MCP tool result (single text content block, `isError` set).
fn tool_err(text: &str) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ], "isError": true })
}

fn parse_tenant(args: &Value) -> Result<Tenant> {
    let label = args
        .get("tenant")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("open_session missing 'tenant'"))?
        .to_string();
    let host_path = PathBuf::from(
        args.get("pile_host_path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("open_session missing 'pile_host_path'"))?,
    );
    let guest_path = match args.get("pile_guest_path").and_then(Value::as_str) {
        Some(p) => PathBuf::from(p),
        None => {
            let name = host_path
                .file_name()
                .ok_or_else(|| anyhow!("pile_host_path has no filename"))?;
            PathBuf::from("/pile").join(name)
        }
    };
    Ok(Tenant {
        label,
        pile: PileMount {
            host_path,
            guest_path,
            append_only: true,
        },
    })
}

fn parse_env(args: &Value) -> Vec<(String, String)> {
    args.get("env")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Render an [`ExecResult`] as the text a model client sees.
fn render_exec_result(result: &ExecResult) -> String {
    let mut out = String::new();
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    if !stdout.is_empty() {
        out.push_str(&stdout);
    }
    if !stderr.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("[stderr]\n");
        out.push_str(&stderr);
    }
    if let Some(err) = &result.error {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("[error] {err}"));
    }
    out.push_str(&format!("\n[exit {}]", result.exit_code.unwrap_or(-1)));
    out
}

/// Test support shared with `crate::mcp_http`: a backend that needs no Lima.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A backend that records calls and needs no Lima. Session id =
    /// `mock-<tenant label>`.
    #[derive(Default)]
    pub(crate) struct MockBackend {
        pub(crate) execs: Arc<AtomicUsize>,
        pub(crate) closes: Arc<AtomicUsize>,
        pub(crate) destroys: Arc<AtomicUsize>,
    }

    impl SandboxBackend for MockBackend {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn open_session(&self, spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new(format!("mock-{}", spec.tenant.label)))
        }
        fn exec(&self, _session: &SessionId, request: &ExecRequest) -> Result<ExecResult> {
            self.execs.fetch_add(1, Ordering::SeqCst);
            Ok(ExecResult {
                stdout: format!("ran: {}", request.command).into_bytes(),
                stderr: Vec::new(),
                exit_code: Some(0),
                error: None,
            })
        }
        fn close_session(&self, _session: &SessionId) -> Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn destroy_session(&self, _session: &SessionId) -> Result<()> {
            self.destroys.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::MockBackend;
    use super::*;

    /// Drive the whole handshake over an in-memory stdio transport and assert
    /// the JSON-RPC responses. Proves the server surface without Lima.
    #[test]
    fn end_to_end_stdio_session() {
        let requests = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"open_session","arguments":{"tenant":"alice","pile_host_path":"/tmp/alice/self.pile"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec","arguments":{"session":"mock-alice","command":"echo hi"}}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"close_session","arguments":{"session":"mock-alice"}}}"#,
        ]
        .join("\n");

        let input = std::io::Cursor::new(requests.into_bytes());
        let mut output: Vec<u8> = Vec::new();

        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        {
            let mut transport = StdioTransport::new(input, &mut output);
            server.serve_loop(&mut transport).expect("serve");
        }

        // One response line per request that carried an `id` (5 of 6; the
        // notification produced none).
        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 5);

        // initialize
        assert_eq!(lines[0]["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        // tools/list has the four sandbox tools
        assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 4);
        // open_session returned the mock session id
        assert_eq!(lines[2]["result"]["content"][0]["text"], "mock-alice");
        assert_eq!(lines[2]["result"]["isError"], false);
        // exec ran the command
        let exec_text = lines[3]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(exec_text.contains("ran: echo hi"));
        assert!(exec_text.contains("[exit 0]"));
        // close_session ok
        assert_eq!(lines[4]["result"]["isError"], false);
    }

    /// Exec against a session the provider never opened is refused (ownership
    /// enforcement) and surfaces as an `isError` tool result, not a crash.
    #[test]
    fn exec_on_unknown_session_is_error() {
        let requests =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"session":"nope","command":"echo hi"}}}"#;
        let input = std::io::Cursor::new(requests.as_bytes().to_vec());
        let mut output: Vec<u8> = Vec::new();
        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        {
            let mut transport = StdioTransport::new(input, &mut output);
            server.serve_loop(&mut transport).expect("serve");
        }
        let line: Value =
            serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(line["result"]["isError"], true);
        assert!(line["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown session"));
    }

    /// The `destroy_session` tool routes to the backend's `destroy_session`
    /// (permanent teardown), distinct from `close_session`'s detach, and
    /// deregisters the session so a follow-up is refused.
    #[test]
    fn destroy_session_tool_calls_backend_destroy() {
        let requests = [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_session","arguments":{"tenant":"alice","pile_host_path":"/tmp/alice/self.pile"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"destroy_session","arguments":{"session":"mock-alice"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"exec","arguments":{"session":"mock-alice","command":"echo hi"}}}"#,
        ]
        .join("\n");

        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let destroys = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = MockBackend {
            closes: closes.clone(),
            destroys: destroys.clone(),
            ..Default::default()
        };
        let provider = SandboxProvider::new(Box::new(backend));
        let server = McpServer::new(provider);

        let input = std::io::Cursor::new(requests.into_bytes());
        let mut output: Vec<u8> = Vec::new();
        {
            let mut transport = StdioTransport::new(input, &mut output);
            server.serve_loop(&mut transport).expect("serve");
        }

        // destroy_session went to the backend's destroy path, not close.
        assert_eq!(destroys.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 0);

        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // destroy_session succeeded...
        assert_eq!(lines[1]["result"]["isError"], false);
        assert!(lines[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("destroyed mock-alice"));
        // ...and deregistered the session: the later exec is now unknown.
        assert_eq!(lines[2]["result"]["isError"], true);
        assert!(lines[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown session"));
    }

    /// MEDIUM-1 leak fix: when the transport reaches EOF with sessions still
    /// open (the client opened a session and disconnected without closing it),
    /// `serve_loop` tears every open session down — the connection can never
    /// orphan a sandbox.
    #[test]
    fn serve_loop_closes_open_sessions_on_eof() {
        // Two open_sessions, no close_session, then EOF (end of input).
        let requests = [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_session","arguments":{"tenant":"alice","pile_host_path":"/tmp/alice/self.pile"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_session","arguments":{"tenant":"bob","pile_host_path":"/tmp/bob/self.pile"}}}"#,
        ]
        .join("\n");

        let closes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let backend = MockBackend {
            closes: closes.clone(),
            ..Default::default()
        };
        let provider = SandboxProvider::new(Box::new(backend));
        let server = McpServer::new(provider);

        let input = std::io::Cursor::new(requests.into_bytes());
        let mut output: Vec<u8> = Vec::new();
        {
            let mut transport = StdioTransport::new(input, &mut output);
            server.serve_loop(&mut transport).expect("serve");
        }

        // Both sessions were torn down on EOF, and the registry is now empty
        // (a second sweep closes nothing).
        assert_eq!(closes.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(server.provider.close_all_sessions(), 0);
    }

    // -- Security repair #1(3): reference-counted sessions --------------------

    use crate::sandbox::{PileMount, Tenant};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Build `OpenSessionParams` for a tenant label (the pile fields are inert
    /// for the mock backend, which keys the session id on the label only).
    fn params(label: &str) -> OpenSessionParams {
        OpenSessionParams {
            tenant: Tenant {
                label: label.to_string(),
                pile: PileMount {
                    host_path: std::path::PathBuf::from(format!("/tmp/{label}/self.pile")),
                    guest_path: std::path::PathBuf::from("/pile/self.pile"),
                    append_only: true,
                },
            },
            cwd: None,
            env: Vec::new(),
        }
    }

    fn exec_params(session: &SessionId) -> ExecParams {
        ExecParams {
            session: session.clone(),
            command: "true".to_string(),
            cwd: None,
            stdin: None,
            timeout: None,
        }
    }

    /// Two `open_session`s from the SAME tenant map to ONE backend sandbox
    /// (shared jail): the second open bumps a refcount rather than re-opening,
    /// the first `close_session` only decrements (box still known + execable),
    /// and the SECOND `close_session` triggers exactly ONE backend close (the
    /// last handle detaches). This is the explicit multi-endpoint sharing
    /// requirement — one honest connection closing must not evict another.
    #[test]
    fn provider_refcounts_shared_tenant_sessions() {
        let closes = Arc::new(AtomicUsize::new(0));
        let backend = MockBackend {
            closes: closes.clone(),
            ..Default::default()
        };
        let provider = SandboxProvider::new(Box::new(backend));

        // Two endpoints from the same tenant -> the same backend session id.
        let id1 = provider.open_session(params("alice")).expect("open 1");
        let id2 = provider.open_session(params("alice")).expect("open 2");
        assert_eq!(id1, id2, "same tenant shares one backend sandbox");

        // First close: refcount 2 -> 1. No backend close yet; still execable.
        provider.close_session(&id1).expect("close 1");
        assert_eq!(closes.load(Ordering::SeqCst), 0, "first close must not detach");
        provider.exec(exec_params(&id1)).expect("still execable after first close");

        // Second close: refcount 1 -> 0. Exactly one backend close, now unknown.
        provider.close_session(&id1).expect("close 2");
        assert_eq!(closes.load(Ordering::SeqCst), 1, "last close detaches exactly once");
        assert!(
            provider.exec(exec_params(&id1)).is_err(),
            "session must be unknown after the last handle leaves"
        );
    }

    /// A second, DIFFERENT tenant whose principal would resolve to the same
    /// backend session id is REFUSED at the provider (tenant mismatch) — the
    /// provider-layer defence complementing the jail backend's ZFS-property
    /// provenance check. Modelled with a backend that pins every session to a
    /// fixed id regardless of tenant, so two tenants collide.
    #[test]
    fn provider_refuses_colliding_second_tenant() {
        /// Every `open_session` returns the SAME id, forcing a collision between
        /// distinct tenants.
        #[derive(Default)]
        struct CollidingBackend {
            closes: Arc<AtomicUsize>,
        }
        impl SandboxBackend for CollidingBackend {
            fn name(&self) -> &'static str {
                "colliding"
            }
            fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
                Ok(SessionId::new("shared-id"))
            }
            fn exec(&self, _s: &SessionId, _r: &ExecRequest) -> Result<ExecResult> {
                Ok(ExecResult::default())
            }
            fn close_session(&self, _s: &SessionId) -> Result<()> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn destroy_session(&self, _s: &SessionId) -> Result<()> {
                Ok(())
            }
        }

        let provider = SandboxProvider::new(Box::new(CollidingBackend::default()));
        let id = provider.open_session(params("alice")).expect("open alice");

        // Bob resolves to the same backend id: the provider must refuse to
        // attach him to alice's entry.
        let err = provider
            .open_session(params("bob"))
            .expect_err("colliding second tenant must be refused");
        assert!(
            err.to_string().contains("already bound to tenant"),
            "err: {err}"
        );

        // Alice's session is intact and still owned by her.
        provider.exec(exec_params(&id)).expect("alice still execable");
    }

    /// `destroy_session` is the hard teardown: it tears the box down and
    /// deregisters it REGARDLESS of a nonzero refcount (a second endpoint still
    /// held it). Concurrent-exec safety during destroy is repair #3's job.
    #[test]
    fn provider_destroy_ignores_refcount() {
        let destroys = Arc::new(AtomicUsize::new(0));
        let closes = Arc::new(AtomicUsize::new(0));
        let backend = MockBackend {
            destroys: destroys.clone(),
            closes: closes.clone(),
            ..Default::default()
        };
        let provider = SandboxProvider::new(Box::new(backend));

        // Two handles on one shared box (refcount 2).
        let id = provider.open_session(params("alice")).expect("open 1");
        provider.open_session(params("alice")).expect("open 2");

        // Hard teardown removes the entry despite refs == 2, backend destroy once.
        provider.destroy_session(&id).expect("destroy");
        assert_eq!(destroys.load(Ordering::SeqCst), 1);
        assert_eq!(closes.load(Ordering::SeqCst), 0, "destroy is not a close");
        assert!(
            provider.exec(exec_params(&id)).is_err(),
            "destroyed session is gone regardless of prior refcount"
        );
    }

    /// (c) The per-tenant lifecycle lock closes the close/open refcount race
    /// (repair #1 review follow-up): a single handle's `close_session`
    /// decrements refs to 0 and detaches the backend, but a CONCURRENT
    /// same-tenant `open_session` that lands in that window must NOT be orphaned
    /// — the box must stay registered and execable for it.
    ///
    /// We force the race by making the backend's `close_session` block on a
    /// barrier: the closing thread is parked mid-teardown (after the decrement,
    /// before the registry remove) while the opening thread runs. Without the
    /// lock, the opener would bump the entry and the parked closer would then
    /// `remove` it, orphaning the box (a later `exec` would fail "unknown
    /// session"). With the lock, the open blocks until the close fully finishes,
    /// then re-opens cleanly — so the final session is always known and execable.
    #[test]
    fn lifecycle_lock_prevents_close_open_orphan() {
        use std::sync::mpsc;
        use std::sync::Arc;

        /// Backend whose `close_session` blocks on a channel so the test can hold
        /// a close mid-flight and drive a concurrent open into the race window.
        struct BlockingCloseBackend {
            in_close: mpsc::Sender<()>,
            release: Mutex<Option<mpsc::Receiver<()>>>,
        }
        impl SandboxBackend for BlockingCloseBackend {
            fn name(&self) -> &'static str {
                "blocking-close"
            }
            fn open_session(&self, spec: &SessionSpec) -> Result<SessionId> {
                Ok(SessionId::new(format!("box-{}", spec.tenant.label)))
            }
            fn exec(&self, _s: &SessionId, _r: &ExecRequest) -> Result<ExecResult> {
                Ok(ExecResult { exit_code: Some(0), ..Default::default() })
            }
            fn close_session(&self, _s: &SessionId) -> Result<()> {
                // Signal we are mid-close, then block until released — this is the
                // window where the old code had dropped the lock.
                let _ = self.in_close.send(());
                if let Some(rx) = self.release.lock().unwrap().take() {
                    let _ = rx.recv();
                }
                Ok(())
            }
            fn destroy_session(&self, _s: &SessionId) -> Result<()> {
                Ok(())
            }
        }

        let (in_close_tx, in_close_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let provider = Arc::new(SandboxProvider::new(Box::new(BlockingCloseBackend {
            in_close: in_close_tx,
            release: Mutex::new(Some(release_rx)),
        })));

        // One handle open (refs = 1).
        let id = provider.open_session(params("alice")).expect("open 1");

        // Thread A closes: it decrements to 0 and blocks inside backend close,
        // holding the per-tenant lifecycle lock the whole time.
        let pa = provider.clone();
        let close_thread = std::thread::spawn(move || {
            pa.close_session(&id).expect("close");
        });
        in_close_rx.recv().expect("close reached the backend");

        // Thread B opens the SAME tenant while the close is parked. With the
        // lock, it BLOCKS until the close finishes; give it time to try, then
        // release the close.
        let pb = provider.clone();
        let open_thread = std::thread::spawn(move || pb.open_session(params("alice")).expect("open 2"));
        std::thread::sleep(std::time::Duration::from_millis(200));
        release_tx.send(()).expect("release close");

        close_thread.join().unwrap();
        let id2 = open_thread.join().unwrap();

        // The concurrently-opened session is NOT orphaned: it is registered and
        // execable. (Without the lock, thread A's post-window `remove` would have
        // evicted thread B's freshly-bumped entry.)
        provider
            .exec(exec_params(&id2))
            .expect("concurrently-opened session must remain known and execable");
    }

    // -- Security repair #4: admission control (per-tenant + global caps) ------

    /// The [`AdmissionControl`] unit: the per-tenant cap, the global cap, and
    /// the bounded wait queue, exercised directly (fast, no backend).
    #[test]
    fn admission_caps_are_enforced() {
        // Global 3, per-tenant 2, no waiters allowed (reject immediately on full).
        let ctl = AdmissionControl::new(AdmissionConfig {
            global_limit: 3,
            per_tenant_limit: 2,
            max_waiters: 0,
        });

        // alice takes her 2 (the per-tenant limit)...
        let a1 = ctl.acquire("alice").expect("a1");
        let a2 = ctl.acquire("alice").expect("a2");
        // ...a 3rd for alice is refused (per-tenant cap), even though a GLOBAL
        // slot is still free — the per-tenant limit is the fairness guarantee.
        assert!(
            ctl.acquire("alice").is_err(),
            "a tenant must not exceed its per-tenant cap"
        );

        // bob can still take a slot (his own per-tenant budget), filling global.
        let b1 = ctl.acquire("bob").expect("b1");
        // Now global is full (3/3): even a fresh tenant is refused.
        assert!(
            ctl.acquire("carol").is_err(),
            "the global cap must hold across tenants"
        );

        // Releasing one frees exactly one slot.
        drop(a1);
        let c1 = ctl.acquire("carol").expect("a freed global slot admits carol");

        drop(a2);
        drop(b1);
        drop(c1);
    }

    /// A blocked acquire WAITS (up to the queue bound) and is then admitted when
    /// a permit frees — proving the queue is a bounded wait, not just a reject.
    #[test]
    fn admission_waits_then_admits_on_release() {
        use std::sync::Arc;
        let ctl = Arc::new(AdmissionControl::new(AdmissionConfig {
            global_limit: 1,
            per_tenant_limit: 1,
            max_waiters: 4,
        }));

        // Hold the only slot.
        let held = ctl.acquire("alice").expect("first");

        // A second acquire on a DIFFERENT tenant must block (global is full),
        // then succeed once we release.
        let ctl2 = ctl.clone();
        let waiter = std::thread::spawn(move || {
            // This blocks until the held permit is dropped.
            let _g = ctl2.acquire("bob").expect("admitted after release");
        });
        // Give the waiter time to park on the condvar, then release.
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(held);
        waiter.join().expect("waiter admitted");
    }

    /// Provider-level: a single tenant cannot run more than its per-tenant exec
    /// limit concurrently. We hold execs open with a blocking backend and prove
    /// the (limit+1)-th same-tenant exec is refused with `max_waiters = 0`.
    #[test]
    fn provider_admission_bounds_one_tenant() {
        use std::sync::Arc;
        use std::sync::mpsc;

        /// Backend whose `exec` blocks until released, so a test can hold N execs
        /// in flight and probe the admission cap.
        struct BlockingExecBackend {
            entered: mpsc::Sender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl SandboxBackend for BlockingExecBackend {
            fn name(&self) -> &'static str {
                "blocking-exec"
            }
            fn open_session(&self, spec: &SessionSpec) -> Result<SessionId> {
                Ok(SessionId::new(format!("box-{}", spec.tenant.label)))
            }
            fn exec(&self, _s: &SessionId, _r: &ExecRequest) -> Result<ExecResult> {
                let _ = self.entered.send(());
                // Block until the test releases one unit.
                let _ = self.release.lock().expect("poisoned").recv();
                Ok(ExecResult { exit_code: Some(0), ..Default::default() })
            }
            fn close_session(&self, _s: &SessionId) -> Result<()> {
                Ok(())
            }
            fn destroy_session(&self, _s: &SessionId) -> Result<()> {
                Ok(())
            }
        }

        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let provider = Arc::new(SandboxProvider::with_admission(
            Box::new(BlockingExecBackend {
                entered: entered_tx,
                release: Mutex::new(release_rx),
            }),
            AdmissionConfig {
                global_limit: 10,   // plenty of global room...
                per_tenant_limit: 2, // ...but only 2 per tenant.
                max_waiters: 0,      // full => reject immediately (no queue).
            },
        ));

        let id = provider.open_session(params("alice")).expect("open");

        // Launch 2 execs that will block inside the backend, holding both of
        // alice's per-tenant permits.
        let mut runners = Vec::new();
        for _ in 0..2 {
            let p = provider.clone();
            let id = id.clone();
            runners.push(std::thread::spawn(move || {
                let _ = p.exec(exec_params(&id));
            }));
        }
        // Wait until BOTH are actually inside the backend (permits held).
        entered_rx.recv().expect("exec 1 entered");
        entered_rx.recv().expect("exec 2 entered");

        // A 3rd concurrent exec for alice must be refused: per-tenant cap is full
        // and no waiter slot exists. (Global still has 8 free — this proves the
        // per-tenant bound, not the global one.)
        let err = provider
            .exec(exec_params(&id))
            .expect_err("3rd same-tenant exec must be refused");
        assert!(err.to_string().contains("sandbox busy"), "err: {err}");

        // Release both in-flight execs and join.
        release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();
        for r in runners {
            r.join().unwrap();
        }

        // With the permits freed, a fresh exec is admitted again.
        release_tx.send(()).unwrap(); // pre-load one release for the final exec
        provider.exec(exec_params(&id)).expect("exec admitted after release");
    }
}

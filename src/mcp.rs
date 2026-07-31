//! MCP provider skeleton: exposes sandbox sessions over the Model Context
//! Protocol.
//!
//! Because a shell is **stateful** (cwd, env, running processes), the MCP
//! surface is a *session* model rather than a stateless tool call:
//!
//!   - `open_session` -> provision a sandbox via the backend, return a session
//!     id (one tenant = one pile mount × driver).
//!   - `exec`         -> run a short command and wait for its result.
//!   - `read`/`write` -> exchange bounded, lossless file payloads with an open
//!     session through that same synchronous execution path.
//!   - `job_*`        -> start, poll, and cancel long-running commands.
//!   - `close_session`-> release a handle to the persistent sandbox.
//!   - `destroy_session` -> permanently tear the sandbox down.
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
//! The MCP surface this provider exposes is nine small tools and a handful of
//! lifecycle methods — small enough to hand-roll over `serde_json` (already a
//! dependency) instead of pulling the official Rust SDK
//! [`rmcp`](https://crates.io/crates/rmcp). Keeping the surface tiny and
//! explicit is worth more here than SDK conformance machinery we would not use.
//! The HTTP transport bridges to this blocking core with
//! `tokio::task::spawn_blocking` rather than rewriting the provider async.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use base64::Engine as _;
use serde_json::{Value, json};

use crate::jobs::{JobManager, JobSnapshot, JobState};
#[cfg(test)]
use crate::sandbox::ExecControl;
use crate::sandbox::{
    ExecRequest, ExecResult, ExecShellMode, ExecStream, LifecycleLocks, PileMount, SandboxBackend,
    SessionId, SessionSpec, Tenant,
};

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
    shell_mode: ExecShellMode,
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
    backend: Arc<dyn SandboxBackend>,
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
    /// The one execution state machine used by both synchronous `exec` and the
    /// retained `job_*` surface. It owns the fixed concurrency and retention
    /// bounds; there is no second waiter/admission scheduler.
    jobs: Arc<JobManager>,
}

impl SandboxProvider {
    pub fn new(backend: Box<dyn SandboxBackend>) -> Self {
        let backend: Arc<dyn SandboxBackend> = Arc::from(backend);
        let jobs = JobManager::new(backend.clone());
        SandboxProvider {
            backend,
            sessions: Mutex::new(HashMap::new()),
            lifecycle: LifecycleLocks::new(),
            jobs,
        }
    }

    /// MCP `open_session`: provision a sandbox and register it (or attach to an
    /// already-open one from the same tenant, sharing the backend session).
    ///
    /// The backend maps a tenant to a stable session id, so every call first
    /// performs its idempotent open/re-attach check. A second endpoint from the
    /// same tenant then lands on the same registry entry and bumps its refcount.
    /// A different tenant resolving to the same id is rejected here
    /// (provider-layer defence complementing the jail backend's ZFS-property
    /// provenance check).
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

    fn request_for(params: &ExecParams) -> ExecRequest {
        ExecRequest {
            command: params.command.clone(),
            shell_mode: params.shell_mode,
            cwd: params.cwd.clone(),
            stdin: params.stdin.clone(),
            timeout: params.timeout,
        }
    }

    /// Register one execution while holding the same per-tenant lifecycle lock
    /// as open/close/destroy. The session is rechecked inside the lock, so a job
    /// can never slip in after `destroy_session` has scanned and reaped jobs.
    fn start_job(&self, params: &ExecParams) -> Result<String> {
        let tenant = {
            let guard = self.sessions.lock().expect("sessions poisoned");
            guard
                .get(&params.session)
                .map(|entry| entry.tenant.clone())
                .ok_or_else(|| anyhow!("unknown session {}", params.session.as_str()))?
        };
        let key = self.backend.canonical_key(&tenant);
        self.lifecycle.with_lock(&key, || {
            let guard = self.sessions.lock().expect("sessions poisoned");
            let current = guard
                .get(&params.session)
                .ok_or_else(|| anyhow!("unknown session {}", params.session.as_str()))?;
            if current.tenant.label != tenant.label {
                return Err(anyhow!("session ownership changed while starting job"));
            }
            self.jobs.start(
                tenant.label.clone(),
                params.session.clone(),
                Self::request_for(params),
            )
        })
    }

    /// MCP `exec`: run through the same job kernel as `job_exec`, wait for its
    /// terminal state, then discard the hidden handle.
    pub fn exec(&self, params: ExecParams) -> Result<ExecResult> {
        let id = self.start_job(&params)?;
        self.jobs.wait_result_and_forget(&id)
    }

    pub fn job_exec(&self, params: ExecParams) -> Result<String> {
        if !self.backend.supports_background_jobs() {
            return Err(anyhow!(
                "backend '{}' does not provide proven background-job cancellation; use synchronous exec",
                self.backend.name()
            ));
        }
        self.start_job(&params)
    }

    pub fn job_poll(&self, id: &str, cursor: u64) -> Result<JobSnapshot> {
        self.jobs.poll(id, cursor)
    }

    pub fn job_cancel(&self, id: &str) -> Result<JobState> {
        self.jobs.cancel(id)
    }

    #[cfg(feature = "mcp-http")]
    pub fn job_tenant(&self, id: &str) -> Option<String> {
        self.jobs.tenant(id)
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
    /// (repair #3). In-flight commands are cancelled and reaped under that same
    /// lock before the backend is destroyed.
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
            if self.backend.supports_background_jobs() {
                self.jobs.cancel_session_and_wait(session);
            } else {
                self.jobs.wait_session(session);
            }
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
        // Jobs outlive individual HTTP transport sessions, but not the provider
        // process. Reap them before detaching/stopping their sandboxes.
        if self.backend.supports_background_jobs() {
            self.jobs.cancel_all_and_wait();
        } else {
            self.jobs.wait_all();
        }
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
    pub fn begin_shutdown(&self) {
        if self.backend.supports_background_jobs() {
            self.jobs.begin_shutdown();
        } else {
            self.jobs.stop_accepting();
        }
    }

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

    /// Register the owning transport's process-level fail-stop action. A
    /// backend marks only loss of command-tree control as fatal; ordinary
    /// command and transport errors remain per-job results.
    pub fn set_fatal_handler(&self, handler: Arc<dyn Fn(String) + Send + Sync>) {
        self.jobs.set_fatal_handler(handler);
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
// The tools mirror the provider verbs: session lifecycle, synchronous `exec`,
// and the cancellable `job_exec` / `job_poll` / `job_cancel` surface.

/// The newest MCP protocol version this server speaks (and the one it
/// advertises when the client requests something it doesn't know).
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// All protocol versions this server can serve. `initialize` echoes the
/// client's requested version when it is one of these (per-spec negotiation);
/// otherwise it answers with [`MCP_PROTOCOL_VERSION`]. The tool surface is
/// identical across all three, so no per-version branching exists elsewhere.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Maximum byte payload accepted by `write` or returned by `read`.
///
/// Reads ask the sandbox for at most one byte beyond this ceiling, which lets
/// us report an explicit oversize error without ever overflowing the shared
/// synchronous job log's 4 MiB retention bound. Writes are checked before the
/// payload enters that execution path.
const MAX_FILE_BYTES: usize = 3 * 1024 * 1024;

// Base-system locations shared by the Ubuntu Jammy Lima image and FreeBSD.
// Absolute paths keep tenant PATH changes and shell functions out of the file
// payload boundary.
const SANDBOX_HEAD: &str = "/usr/bin/head";
const SANDBOX_CAT: &str = "/bin/cat";

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
        transport: &mut StdioTransport<std::io::BufReader<std::io::Stdin>, std::io::Stdout>,
    ) -> Result<()> {
        let server = std::sync::Arc::new(self);
        server
            .provider
            .set_fatal_handler(Arc::new(|_reason| std::process::exit(1)));
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

        let outcome: Result<Value> = match name {
            "open_session" => self.tool_open_session(args).map(|text| tool_ok(&text)),
            "exec" => self.tool_exec(args).map(|text| tool_ok(&text)),
            "read" => self.tool_read(args),
            "write" => self.tool_write(args),
            "job_exec" => self.tool_job_exec(args).map(|text| tool_ok(&text)),
            "job_poll" => self.tool_job_poll(args).map(|text| tool_ok(&text)),
            "job_cancel" => self.tool_job_cancel(args).map(|text| tool_ok(&text)),
            "close_session" => self.tool_close_session(args).map(|text| tool_ok(&text)),
            "destroy_session" => self.tool_destroy_session(args).map(|text| tool_ok(&text)),
            other => Err(anyhow!("unknown tool: {other}")),
        };

        match outcome {
            Ok(result) => DispatchOutcome::Result(result),
            // Tool-level failures are reported as an `isError` result (per MCP),
            // not a JSON-RPC protocol error — the model needs to see the text.
            Err(e) => DispatchOutcome::Result(tool_err(&format!("{e:#}"))),
        }
    }

    fn tool_open_session(&self, args: Value) -> Result<String> {
        let tenant = parse_tenant(&args)?;
        let cwd = args.get("cwd").and_then(Value::as_str).map(PathBuf::from);
        let env = parse_env(&args);
        let id = self
            .provider
            .open_session(OpenSessionParams { tenant, cwd, env })?;
        Ok(id.as_str().to_string())
    }

    fn tool_exec(&self, args: Value) -> Result<String> {
        let result = self.provider.exec(parse_exec_params(&args, "exec")?)?;
        Ok(render_exec_result(&result))
    }

    fn tool_read(&self, args: Value) -> Result<Value> {
        let target = parse_file_target(&args, "read")?;
        let quoted_path = shell_quote(&target.path)?;
        // `head` bounds the producer itself. A concurrently growing file can
        // therefore never evict the beginning of the shared 4 MiB job log.
        let command = format!(
            "file={quoted_path}; {SANDBOX_HEAD} -c {} < \"$file\"",
            MAX_FILE_BYTES + 1
        );
        let result = self.provider.exec(ExecParams {
            session: target.session,
            command,
            shell_mode: ExecShellMode::Clean,
            cwd: target.cwd,
            stdin: None,
            timeout: None,
        })?;
        ensure_file_command_succeeded("read", &result)?;
        if result.stdout.len() > MAX_FILE_BYTES {
            return Err(anyhow!(
                "read refused: '{}' exceeds the {} byte file limit",
                target.path,
                MAX_FILE_BYTES
            ));
        }
        Ok(read_tool_result(&target.path, &result.stdout))
    }

    fn tool_write(&self, args: Value) -> Result<Value> {
        let target = parse_file_target(&args, "write")?;
        let bytes = parse_write_payload(&args)?;
        let size = bytes.len();
        let mime_type = infer_mime(&target.path, &bytes);
        let quoted_path = shell_quote(&target.path)?;
        let result = self.provider.exec(ExecParams {
            session: target.session,
            command: format!("file={quoted_path}; {SANDBOX_CAT} > \"$file\""),
            shell_mode: ExecShellMode::Clean,
            cwd: target.cwd,
            stdin: Some(bytes),
            timeout: None,
        })?;
        ensure_file_command_succeeded("write", &result)?;

        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("wrote {size} bytes to {} ({mime_type})", target.path),
            }],
            "isError": false,
            "_meta": file_meta(&target.path, &mime_type, size),
        }))
    }

    fn tool_job_exec(&self, args: Value) -> Result<String> {
        let id = self
            .provider
            .job_exec(parse_exec_params(&args, "job_exec")?)?;
        Ok(json!({
            "job_id": id,
            "state": "running",
            "cursor": 0,
        })
        .to_string())
    }

    fn tool_job_poll(&self, args: Value) -> Result<String> {
        let id = args
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("job_poll missing 'job_id'"))?;
        let cursor = args.get("cursor").and_then(Value::as_u64).unwrap_or(0);
        Ok(render_job_snapshot(&self.provider.job_poll(id, cursor)?).to_string())
    }

    fn tool_job_cancel(&self, args: Value) -> Result<String> {
        let id = args
            .get("job_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("job_cancel missing 'job_id'"))?;
        let state = self.provider.job_cancel(id)?;
        Ok(json!({ "job_id": id, "state": state.as_str() }).to_string())
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

fn parse_exec_params(args: &Value, tool: &str) -> Result<ExecParams> {
    let session = SessionId::new(
        args.get("session")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{tool} missing 'session'"))?,
    );
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{tool} missing 'command'"))?
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
    Ok(ExecParams {
        session,
        command,
        shell_mode: ExecShellMode::Login,
        cwd,
        stdin,
        timeout,
    })
}

struct FileTarget {
    session: SessionId,
    path: String,
    cwd: Option<PathBuf>,
}

fn parse_file_target(args: &Value, tool: &str) -> Result<FileTarget> {
    let session = SessionId::new(
        args.get("session")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{tool} missing 'session'"))?,
    );
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{tool} missing 'path'"))?
        .to_string();
    if path.contains('\0') {
        return Err(anyhow!("{tool} path contains a NUL byte"));
    }
    let cwd = match args.get("cwd") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let cwd = value
                .as_str()
                .ok_or_else(|| anyhow!("{tool} 'cwd' must be a string"))?;
            if cwd.contains('\0') {
                return Err(anyhow!("{tool} cwd contains a NUL byte"));
            }
            Some(PathBuf::from(cwd))
        }
    };
    Ok(FileTarget { session, path, cwd })
}

fn parse_write_payload(args: &Value) -> Result<Vec<u8>> {
    let bytes = match (args.get("text"), args.get("base64")) {
        (Some(_), Some(_)) | (None, None) => {
            return Err(anyhow!(
                "write requires exactly one payload: either 'text' or 'base64'"
            ));
        }
        (Some(value), None) => value
            .as_str()
            .ok_or_else(|| anyhow!("write 'text' payload must be a string"))?
            .as_bytes()
            .to_vec(),
        (None, Some(value)) => {
            let encoded = value
                .as_str()
                .ok_or_else(|| anyhow!("write 'base64' payload must be a string"))?;
            // Reject a payload that cannot possibly fit before asking the
            // decoder to allocate for it. The exact decoded-size check below
            // remains authoritative for padding and short final quanta.
            let max_encoded = MAX_FILE_BYTES.div_ceil(3) * 4;
            if encoded.len() > max_encoded {
                return Err(anyhow!(
                    "write payload exceeds the {} byte file limit",
                    MAX_FILE_BYTES
                ));
            }
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| anyhow!("write 'base64' payload is invalid: {error}"))?
        }
    };
    if bytes.len() > MAX_FILE_BYTES {
        return Err(anyhow!(
            "write payload is {} bytes; limit is {} bytes",
            bytes.len(),
            MAX_FILE_BYTES
        ));
    }
    Ok(bytes)
}

/// Quote one arbitrary (non-NUL) path as a single POSIX-shell word.
fn shell_quote(path: &str) -> Result<String> {
    if path.contains('\0') {
        return Err(anyhow!("file path contains a NUL byte"));
    }
    Ok(format!("'{}'", path.replace('\'', "'\"'\"'")))
}

fn ensure_file_command_succeeded(tool: &str, result: &ExecResult) -> Result<()> {
    if result.exit_code == Some(0) && result.error.is_none() && !result.cancelled {
        return Ok(());
    }

    let mut details = Vec::new();
    details.push(format!("exit {}", result.exit_code.unwrap_or(-1)));
    if result.cancelled {
        details.push("cancelled".to_string());
    }
    if let Some(error) = &result.error {
        details.push(error.clone());
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        details.push(format!("stderr: {stderr}"));
    }
    Err(anyhow!(
        "{tool} sandbox command failed ({})",
        details.join("; ")
    ))
}

fn infer_mime(path: &str, bytes: &[u8]) -> String {
    infer::get(bytes)
        .map(|kind| kind.mime_type().to_string())
        .or_else(|| mime_guess::from_path(path).first_raw().map(str::to_string))
        .unwrap_or_else(|| {
            if std::str::from_utf8(bytes).is_ok() {
                "text/plain; charset=utf-8".to_string()
            } else {
                "application/octet-stream".to_string()
            }
        })
}

fn is_textual_mime(mime_type: &str) -> bool {
    let essence = mime_type.split(';').next().unwrap_or(mime_type);
    essence.starts_with("text/")
        || essence.ends_with("+json")
        || essence.ends_with("+xml")
        || matches!(
            essence,
            "application/json"
                | "application/javascript"
                | "application/x-javascript"
                | "application/xml"
                | "application/yaml"
                | "application/x-yaml"
                | "application/toml"
                | "application/sql"
        )
}

fn sandbox_uri(path: &str) -> String {
    let (kind, path) = if let Some(path) = path.strip_prefix('/') {
        ("absolute", path.trim_start_matches('/'))
    } else {
        ("relative", path)
    };
    let mut uri = format!("sandbox:///{kind}/");
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in path.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' | b'/' => {
                uri.push(*byte as char)
            }
            _ => {
                uri.push('%');
                uri.push(HEX[(byte >> 4) as usize] as char);
                uri.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    uri
}

fn file_meta(path: &str, mime_type: &str, size: usize) -> Value {
    json!({
        "path": path,
        "mimeType": mime_type,
        "size": size,
        "uri": sandbox_uri(path),
    })
}

fn read_tool_result(path: &str, bytes: &[u8]) -> Value {
    let detected_by_magic = infer::get(bytes).is_some();
    let mime_type = infer_mime(path, bytes);
    let encoded = || base64::engine::general_purpose::STANDARD.encode(bytes);
    let content = if mime_type.starts_with("image/") {
        json!({ "type": "image", "data": encoded(), "mimeType": mime_type })
    } else if mime_type.starts_with("audio/") {
        // Native audio content was added after some protocol revisions this
        // server still negotiates. An embedded blob keeps the MIME and exact
        // bytes while remaining valid for every advertised revision.
        json!({
            "type": "resource",
            "resource": {
                "uri": sandbox_uri(path),
                "mimeType": mime_type,
                "blob": encoded(),
            }
        })
    } else if is_textual_mime(&mime_type)
        || (!detected_by_magic && std::str::from_utf8(bytes).is_ok())
    {
        match std::str::from_utf8(bytes) {
            Ok(text) => json!({ "type": "text", "text": text }),
            // A textual filename does not make malformed bytes safe to decode.
            // Fall back to a blob so the read remains lossless.
            Err(_) => json!({
                "type": "resource",
                "resource": {
                    "uri": sandbox_uri(path),
                    "mimeType": mime_type,
                    "blob": encoded(),
                }
            }),
        }
    } else {
        json!({
            "type": "resource",
            "resource": {
                "uri": sandbox_uri(path),
                "mimeType": mime_type,
                "blob": encoded(),
            }
        })
    };

    json!({
        "content": [content],
        "isError": false,
        "_meta": file_meta(path, &mime_type, bytes.len()),
    })
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
            "description": "Run a short shell command inside an open sandbox session and wait for its terminal result. Use job_exec for long-running work.",
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
            "name": "read",
            "description": "Read one file from an open sandbox session without byte loss (maximum 3 MiB). Returns text or image content directly and other MIME-labelled binary (including audio) as an embedded resource.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id from open_session." },
                    "path": { "type": "string", "description": "File path inside the sandbox." },
                    "cwd": { "type": "string", "description": "Working directory for a relative path." }
                },
                "required": ["session", "path"],
                "additionalProperties": false
            }
        },
        {
            "name": "write",
            "description": "Write one complete text or base64 file payload inside an open sandbox session (maximum 3 MiB, additionally subject to transport request limits). Exactly one payload field is required.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id from open_session." },
                    "path": { "type": "string", "description": "File path inside the sandbox." },
                    "cwd": { "type": "string", "description": "Working directory for a relative path." },
                    "text": { "type": "string", "description": "UTF-8 text payload." },
                    "base64": { "type": "string", "description": "Standard base64 payload for arbitrary bytes." }
                },
                "required": ["session", "path"],
                "oneOf": [
                    { "required": ["text"], "not": { "required": ["base64"] } },
                    { "required": ["base64"], "not": { "required": ["text"] } }
                ],
                "additionalProperties": false
            }
        },
        {
            "name": "job_exec",
            "description": "Start a cancellable shell command and return a job id immediately. Poll incremental output with job_poll.",
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
            "name": "job_poll",
            "description": "Read one retry-safe page of incremental stdout/stderr and job state. Advance next_cursor and continue until state is terminal and has_more is false.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": { "type": "string", "description": "Opaque id returned by job_exec." },
                    "cursor": { "type": "integer", "minimum": 0, "description": "Chunk cursor from the previous poll; defaults to 0." }
                },
                "required": ["job_id"]
            }
        },
        {
            "name": "job_cancel",
            "description": "Idempotently request cancellation of one job. Poll until its state becomes terminal.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": { "type": "string", "description": "Opaque id returned by job_exec." }
                },
                "required": ["job_id"]
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

fn render_job_snapshot(snapshot: &JobSnapshot) -> Value {
    let chunks: Vec<Value> = snapshot
        .chunks
        .iter()
        .map(|chunk| {
            json!({
                "sequence": chunk.sequence,
                "stream": match chunk.stream {
                    ExecStream::Stdout => "stdout",
                    ExecStream::Stderr => "stderr",
                },
                "text": chunk.text,
            })
        })
        .collect();
    let terminal = snapshot.terminal.as_ref().map(|terminal| {
        json!({
            "kind": terminal.kind(),
            "exit_code": terminal.exit_code(),
            "error": terminal.error(),
        })
    });
    json!({
        "job_id": snapshot.id,
        "state": snapshot.state.as_str(),
        "chunks": chunks,
        "next_cursor": snapshot.next_cursor,
        "has_more": snapshot.has_more,
        "gap": snapshot.gap,
        "dropped_bytes": snapshot.dropped_bytes,
        "terminal": terminal,
    })
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
        fn supports_background_jobs(&self) -> bool {
            true
        }
        fn open_session(&self, spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new(format!("mock-{}", spec.tenant.label)))
        }
        fn exec(
            &self,
            _session: &SessionId,
            request: &ExecRequest,
            control: &ExecControl,
        ) -> Result<ExecResult> {
            self.execs.fetch_add(1, Ordering::SeqCst);
            let stdout = format!("ran: {}", request.command).into_bytes();
            control.emit(ExecStream::Stdout, &stdout);
            Ok(ExecResult {
                stdout,
                exit_code: Some(0),
                ..Default::default()
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

    use std::sync::Mutex as StdMutex;

    struct FileBackend {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_code: Option<i32>,
        error: Option<String>,
        requests: Arc<StdMutex<Vec<ExecRequest>>>,
    }

    impl FileBackend {
        fn reading(bytes: Vec<u8>) -> (Self, Arc<StdMutex<Vec<ExecRequest>>>) {
            let requests = Arc::new(StdMutex::new(Vec::new()));
            (
                Self {
                    stdout: bytes,
                    stderr: Vec::new(),
                    exit_code: Some(0),
                    error: None,
                    requests: requests.clone(),
                },
                requests,
            )
        }
    }

    impl SandboxBackend for FileBackend {
        fn name(&self) -> &'static str {
            "file-test"
        }

        fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new("file-alice"))
        }

        fn exec(
            &self,
            _session: &SessionId,
            request: &ExecRequest,
            control: &ExecControl,
        ) -> Result<ExecResult> {
            self.requests.lock().unwrap().push(request.clone());
            control.emit(ExecStream::Stdout, &self.stdout);
            control.emit(ExecStream::Stderr, &self.stderr);
            Ok(ExecResult {
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
                exit_code: self.exit_code,
                cancelled: false,
                error: self.error.clone(),
            })
        }

        fn close_session(&self, _session: &SessionId) -> Result<()> {
            Ok(())
        }
    }

    /// Models the exact hostile profile behavior file tools must bypass: a
    /// login shell consumes write stdin and prefixes read stdout. Clean mode
    /// instead behaves like the absolute cat/head commands in the backends.
    #[derive(Default)]
    struct ProfilePoisonBackend {
        file: Arc<StdMutex<Vec<u8>>>,
        requests: Arc<StdMutex<Vec<ExecRequest>>>,
    }

    impl SandboxBackend for ProfilePoisonBackend {
        fn name(&self) -> &'static str {
            "profile-poison-test"
        }

        fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new("file-alice"))
        }

        fn exec(
            &self,
            _session: &SessionId,
            request: &ExecRequest,
            control: &ExecControl,
        ) -> Result<ExecResult> {
            self.requests.lock().unwrap().push(request.clone());
            match request.shell_mode {
                ExecShellMode::Login => {
                    // Simulate profile stdout plus `read` consuming all stdin.
                    control.emit(ExecStream::Stdout, b"PROFILE_NOISE\n");
                }
                ExecShellMode::Clean => match &request.stdin {
                    Some(bytes) => *self.file.lock().unwrap() = bytes.clone(),
                    None => {
                        let bytes = self.file.lock().unwrap().clone();
                        control.emit(ExecStream::Stdout, &bytes);
                    }
                },
            }
            Ok(ExecResult {
                exit_code: Some(0),
                ..Default::default()
            })
        }

        fn close_session(&self, _session: &SessionId) -> Result<()> {
            Ok(())
        }
    }

    fn file_server(backend: impl SandboxBackend + 'static) -> McpServer {
        let provider = SandboxProvider::new(Box::new(backend));
        provider
            .open_session(OpenSessionParams {
                tenant: Tenant {
                    label: "alice".to_string(),
                    pile: PileMount {
                        host_path: PathBuf::from("/tmp/alice/self.pile"),
                        guest_path: PathBuf::from("/pile/self.pile"),
                        append_only: true,
                    },
                },
                cwd: None,
                env: Vec::new(),
            })
            .unwrap();
        McpServer::new(provider)
    }

    fn call_tool(server: &McpServer, name: &str, arguments: Value) -> Value {
        server
            .handle_request(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": name, "arguments": arguments },
            }))
            .unwrap()["result"]
            .clone()
    }

    #[test]
    fn read_preserves_exact_binary_and_quotes_unusual_path() {
        let bytes = vec![0xff, 0x00, b'\n', 0x80, b'Z'];
        let (backend, requests) = FileBackend::reading(bytes.clone());
        let server = file_server(backend);
        let path = "odd ' name\n$(not-executed);.unknown";
        let result = call_tool(
            &server,
            "read",
            json!({ "session": "file-alice", "path": path, "cwd": "/work dir" }),
        );

        assert_eq!(result["isError"], false);
        assert_eq!(result["content"][0]["type"], "resource");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(result["content"][0]["resource"]["blob"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, bytes);
        assert_eq!(result["_meta"]["path"], path);
        assert_eq!(result["_meta"]["size"], 5);
        assert_eq!(result["content"][0]["resource"]["uri"], sandbox_uri(path));

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].shell_mode, ExecShellMode::Clean);
        assert_eq!(requests[0].cwd, Some(PathBuf::from("/work dir")));
        assert_eq!(requests[0].stdin, None);
        assert_eq!(
            requests[0].command,
            format!(
                "file={}; /usr/bin/head -c {} < \"$file\"",
                shell_quote(path).unwrap(),
                MAX_FILE_BYTES + 1
            )
        );
    }

    #[test]
    fn write_passes_exact_base64_bytes_as_stdin() {
        let (backend, requests) = FileBackend::reading(Vec::new());
        let server = file_server(backend);
        let bytes = vec![0, 1, 2, 0xfe, 0xff];
        let path = "-leading ' quote.bin";
        let result = call_tool(
            &server,
            "write",
            json!({
                "session": "file-alice",
                "path": path,
                "base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            }),
        );

        assert_eq!(result["isError"], false);
        assert_eq!(result["_meta"]["path"], path);
        assert_eq!(result["_meta"]["size"], bytes.len());
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].shell_mode, ExecShellMode::Clean);
        assert_eq!(requests[0].stdin.as_deref(), Some(bytes.as_slice()));
        assert_eq!(
            requests[0].command,
            format!("file={}; /bin/cat > \"$file\"", shell_quote(path).unwrap())
        );
    }

    #[test]
    fn file_tools_bypass_profile_stdout_and_stdin_interception() {
        let backend = ProfilePoisonBackend::default();
        let file = backend.file.clone();
        let requests = backend.requests.clone();
        let server = file_server(backend);
        let payload = "exact payload despite hostile profile";

        let written = call_tool(
            &server,
            "write",
            json!({
                "session": "file-alice",
                "path": "relative.txt",
                "text": payload,
            }),
        );
        assert_eq!(written["isError"], false);
        assert_eq!(&*file.lock().unwrap(), payload.as_bytes());

        let read = call_tool(
            &server,
            "read",
            json!({ "session": "file-alice", "path": "relative.txt" }),
        );
        assert_eq!(read["isError"], false);
        assert_eq!(read["content"][0]["type"], "text");
        assert_eq!(read["content"][0]["text"], payload);

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.shell_mode == ExecShellMode::Clean)
        );
        assert!(requests.iter().all(|request| request.cwd.is_none()));
        assert!(requests[0].command.contains("/bin/cat"));
        assert!(requests[1].command.contains("/usr/bin/head"));
    }

    #[test]
    fn ordinary_exec_requests_remain_login_shells() {
        let params = parse_exec_params(
            &json!({ "session": "file-alice", "command": "compass list" }),
            "exec",
        )
        .unwrap();
        assert_eq!(params.shell_mode, ExecShellMode::Login);
    }

    #[test]
    fn read_dispatches_text_image_audio_and_opaque_binary_losslessly() {
        let text = read_tool_result("notes.md", "hello, Liora\n".as_bytes());
        assert_eq!(text["content"][0]["type"], "text");
        assert_eq!(text["content"][0]["text"], "hello, Liora\n");
        assert_eq!(text["_meta"]["mimeType"], "text/markdown");

        let utf8_with_binary_name = read_tool_result("actually-text.bin", b"plain utf-8");
        assert_eq!(utf8_with_binary_name["content"][0]["type"], "text");
        assert_eq!(utf8_with_binary_name["content"][0]["text"], "plain utf-8");
        assert_eq!(
            utf8_with_binary_name["_meta"]["mimeType"],
            "application/octet-stream"
        );

        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let image = read_tool_result("misleading.bin", png);
        assert_eq!(image["content"][0]["type"], "image");
        assert_eq!(image["content"][0]["mimeType"], "image/png");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(image["content"][0]["data"].as_str().unwrap())
                .unwrap(),
            png
        );

        let wav = b"RIFF\x04\x00\x00\x00WAVEfmt ";
        let audio = read_tool_result("sound.wav", wav);
        assert_eq!(audio["content"][0]["type"], "resource");
        assert_eq!(audio["content"][0]["resource"]["mimeType"], "audio/x-wav");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(audio["content"][0]["resource"]["blob"].as_str().unwrap())
                .unwrap(),
            wav
        );

        let opaque_bytes = [0xff, 0x00, 0x81];
        let opaque = read_tool_result("payload", &opaque_bytes);
        assert_eq!(opaque["content"][0]["type"], "resource");
        assert_eq!(opaque["_meta"]["mimeType"], "application/octet-stream");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(opaque["content"][0]["resource"]["blob"].as_str().unwrap())
                .unwrap(),
            opaque_bytes
        );
    }

    #[test]
    fn write_requires_one_valid_bounded_payload() {
        for arguments in [
            json!({}),
            json!({ "text": "a", "base64": "Yg==" }),
            json!({ "text": 7 }),
            json!({ "base64": "%%%" }),
        ] {
            assert!(parse_write_payload(&arguments).is_err(), "{arguments}");
        }
        assert_eq!(
            parse_write_payload(&json!({ "text": "hé" })).unwrap(),
            "hé".as_bytes()
        );
        assert_eq!(
            parse_write_payload(&json!({ "base64": "AAEC" })).unwrap(),
            [0, 1, 2]
        );

        let too_large = "x".repeat(MAX_FILE_BYTES + 1);
        let error = parse_write_payload(&json!({ "text": too_large })).unwrap_err();
        assert!(error.to_string().contains("limit"));
    }

    #[test]
    fn read_limit_plus_one_is_an_error_not_truncated_success() {
        let (backend, _) = FileBackend::reading(vec![b'x'; MAX_FILE_BYTES + 1]);
        let server = file_server(backend);
        let result = call_tool(
            &server,
            "read",
            json!({ "session": "file-alice", "path": "large.bin" }),
        );
        assert_eq!(result["isError"], true);
        assert_eq!(result["content"].as_array().unwrap().len(), 1);
        let error = result["content"][0]["text"].as_str().unwrap();
        assert!(error.contains("exceeds"), "{error}");
        assert!(error.contains(&MAX_FILE_BYTES.to_string()), "{error}");
    }

    #[test]
    fn nonzero_file_command_is_a_tool_error() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let server = file_server(FileBackend {
            stdout: Vec::new(),
            stderr: b"permission denied".to_vec(),
            exit_code: Some(13),
            error: None,
            requests,
        });
        let result = call_tool(
            &server,
            "read",
            json!({ "session": "file-alice", "path": "/secret" }),
        );
        assert_eq!(result["isError"], true);
        let error = result["content"][0]["text"].as_str().unwrap();
        assert!(error.contains("exit 13"), "{error}");
        assert!(error.contains("permission denied"), "{error}");
    }

    #[test]
    fn shell_quote_round_trips_metacharacters() {
        let path = "-odd ' path\n$(touch nope); * [x] café";
        let command = format!("file={}; printf '%s' \"$file\"", shell_quote(path).unwrap());
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, path.as_bytes());
    }

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
        // tools/list has lifecycle, file I/O, sync exec, and the cancellable
        // job triple.
        assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 9);
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
        let requests = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"session":"nope","command":"echo hi"}}}"#;
        let input = std::io::Cursor::new(requests.as_bytes().to_vec());
        let mut output: Vec<u8> = Vec::new();
        let provider = SandboxProvider::new(Box::new(MockBackend::default()));
        let server = McpServer::new(provider);
        {
            let mut transport = StdioTransport::new(input, &mut output);
            server.serve_loop(&mut transport).expect("serve");
        }
        let line: Value = serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(line["result"]["isError"], true);
        assert!(
            line["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("unknown session")
        );
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
        assert!(
            lines[1]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("destroyed mock-alice")
        );
        // ...and deregistered the session: the later exec is now unknown.
        assert_eq!(lines[2]["result"]["isError"], true);
        assert!(
            lines[2]["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("unknown session")
        );
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
            shell_mode: ExecShellMode::Login,
            cwd: None,
            stdin: None,
            timeout: None,
        }
    }

    /// Two `open_session`s from the SAME tenant map to ONE backend sandbox
    /// (shared jail): after the backend's idempotent open/re-attach check, the
    /// second provider handle bumps the shared registry refcount. The first
    /// `close_session` only decrements (box still known + execable), and the
    /// SECOND `close_session` triggers exactly ONE backend close (the last
    /// handle detaches). This is the explicit multi-endpoint sharing requirement
    /// — one honest connection closing must not evict another.
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
        assert_eq!(
            closes.load(Ordering::SeqCst),
            0,
            "first close must not detach"
        );
        provider
            .exec(exec_params(&id1))
            .expect("still execable after first close");

        // Second close: refcount 1 -> 0. Exactly one backend close, now unknown.
        provider.close_session(&id1).expect("close 2");
        assert_eq!(
            closes.load(Ordering::SeqCst),
            1,
            "last close detaches exactly once"
        );
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
            fn exec(
                &self,
                _s: &SessionId,
                _r: &ExecRequest,
                _control: &ExecControl,
            ) -> Result<ExecResult> {
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
        provider
            .exec(exec_params(&id))
            .expect("alice still execable");
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
        use std::sync::Arc;
        use std::sync::mpsc;

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
            fn exec(
                &self,
                _s: &SessionId,
                _r: &ExecRequest,
                _control: &ExecControl,
            ) -> Result<ExecResult> {
                Ok(ExecResult {
                    exit_code: Some(0),
                    ..Default::default()
                })
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
        let open_thread =
            std::thread::spawn(move || pb.open_session(params("alice")).expect("open 2"));
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

    // -- One bounded execution state machine ---------------------------------

    /// A tenant has one foreground mutation lane. Long work returns a handle
    /// immediately; a second command is refused rather than parking another
    /// blocking worker in a hidden admission queue.
    #[test]
    fn provider_rejects_second_active_command_for_tenant() {
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
            fn supports_background_jobs(&self) -> bool {
                true
            }
            fn open_session(&self, spec: &SessionSpec) -> Result<SessionId> {
                Ok(SessionId::new(format!("box-{}", spec.tenant.label)))
            }
            fn exec(
                &self,
                _s: &SessionId,
                _r: &ExecRequest,
                _control: &ExecControl,
            ) -> Result<ExecResult> {
                let _ = self.entered.send(());
                // Block until the test releases one unit.
                let _ = self.release.lock().expect("poisoned").recv();
                Ok(ExecResult {
                    exit_code: Some(0),
                    ..Default::default()
                })
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
        let provider = SandboxProvider::new(Box::new(BlockingExecBackend {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }));

        let id = provider.open_session(params("alice")).expect("open");
        let first = provider.job_exec(exec_params(&id)).expect("job starts");
        entered_rx.recv().expect("job entered backend");
        let err = provider
            .job_exec(exec_params(&id))
            .expect_err("second same-tenant job must be refused");
        assert!(err.to_string().contains("sandbox busy"), "err: {err}");

        // Once terminal, the tenant lane is immediately reusable.
        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if provider.job_poll(&first, 0).unwrap().state == JobState::Terminal {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let second = provider.job_exec(exec_params(&id)).expect("lane reused");
        entered_rx.recv().expect("second entered backend");
        release_tx.send(()).unwrap();
        for _ in 0..100 {
            if provider.job_poll(&second, 0).unwrap().state == JobState::Terminal {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("second job did not become terminal");
    }
}

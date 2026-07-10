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
//! ([`McpServer`]): newline-delimited JSON-RPC 2.0 over a pluggable
//! [`McpTransport`]. v1 ships a blocking stdio transport ([`StdioTransport`]);
//! the internet-facing HTTP/SSE + per-sandbox-token transport is the next phase
//! and is left as a documented seam (see [`McpTransport`]).
//!
//! ## No MCP crate dependency (deliberate, for v1)
//!
//! The official Rust SDK [`rmcp`](https://crates.io/crates/rmcp) is
//! tokio/async, and this crate is entirely synchronous today. Rather than pull
//! a large async stack in for a blocking stdio server, v1 hand-rolls the small
//! JSON-RPC surface over `serde_json` (already a dependency). When the
//! HTTP/SSE transport lands it will need async anyway (triblespace now has both
//! sync and async APIs); that is the point at which adopting `rmcp` or
//! hyper+`spawn_blocking` should be reconsidered.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde_json::{Value, json};

use crate::sandbox::{
    ExecRequest, ExecResult, PileMount, SandboxBackend, SessionId, SessionSpec, Tenant,
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
    pub cwd: Option<std::path::PathBuf>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
}

/// The sandbox MCP provider: owns a backend and the set of live sessions.
///
/// Multi-tenancy: each session records its [`Tenant`] so a single provider can
/// host several piles/drivers at once. The provider enforces that `exec` and
/// `close_session` only touch sessions it opened.
pub struct SandboxProvider {
    backend: Box<dyn SandboxBackend>,
    sessions: Mutex<HashMap<SessionId, Tenant>>,
}

impl SandboxProvider {
    pub fn new(backend: Box<dyn SandboxBackend>) -> Self {
        SandboxProvider {
            backend,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// MCP `open_session`: provision a sandbox and register it.
    pub fn open_session(&self, params: OpenSessionParams) -> Result<SessionId> {
        let spec = SessionSpec {
            tenant: params.tenant.clone(),
            cwd: params.cwd,
            env: params.env,
        };
        let id = self.backend.open_session(&spec)?;
        self.sessions
            .lock()
            .expect("sessions poisoned")
            .insert(id.clone(), params.tenant);
        Ok(id)
    }

    /// MCP `exec`: run a command in an open session.
    ///
    /// Streaming/long-running commands: the current [`SandboxBackend::exec`] is
    /// blocking and returns a whole [`ExecResult`]. Streaming will be layered in
    /// as an MCP notification channel (chunked stdout/stderr) once the transport
    /// is chosen — the backend trait will grow an `exec_streaming` variant then,
    /// not before.
    pub fn exec(&self, params: ExecParams) -> Result<ExecResult> {
        self.ensure_known(&params.session)?;
        let request = ExecRequest {
            command: params.command,
            cwd: params.cwd,
            stdin: params.stdin,
            timeout: params.timeout,
        };
        self.backend.exec(&params.session, &request)
    }

    /// MCP `close_session`: tear down a sandbox and deregister it.
    pub fn close_session(&self, session: &SessionId) -> Result<()> {
        self.ensure_known(session)?;
        self.backend.close_session(session)?;
        self.sessions
            .lock()
            .expect("sessions poisoned")
            .remove(session);
        Ok(())
    }

    fn ensure_known(&self, session: &SessionId) -> Result<()> {
        if self
            .sessions
            .lock()
            .expect("sessions poisoned")
            .contains_key(session)
        {
            Ok(())
        } else {
            Err(anyhow!("unknown session {}", session.as_str()))
        }
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
//   - `tools/list`                -> the three sandbox tools
//   - `tools/call`                -> dispatch to SandboxProvider
//
// The three tools mirror the provider verbs: `open_session`, `exec`,
// `close_session`.

/// MCP protocol version this server advertises.
const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// A message transport for the MCP server: read one request, write one
/// response, both as a single JSON value (framing is the transport's business).
///
/// v1 implements [`StdioTransport`] (newline-delimited JSON over stdin/stdout,
/// blocking). This trait is the seam where the internet-facing transport slots
/// in later.
///
/// TODO(sandbox-provider, next phase): add an `HttpSseTransport` that speaks MCP
/// over HTTP+SSE with a **per-sandbox access token** (operator-distributed) in
/// an `Authorization: Bearer <token>` header, checked before dispatch. That
/// transport must be async (tokio/hyper); the plan is to run the blocking
/// `SandboxProvider` calls under `spawn_blocking` behind it. Do NOT build it in
/// this increment.
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

    /// Run the request/response loop until the transport reports EOF.
    pub fn serve(&self, transport: &mut dyn McpTransport) -> Result<()> {
        while let Some(request) = transport.read_message()? {
            // JSON-RPC notifications (no `id`) get no response.
            let id = request.get("id").cloned();
            let method = request.get("method").and_then(Value::as_str).unwrap_or("");
            let params = request.get("params").cloned().unwrap_or(Value::Null);

            match self.dispatch(method, params) {
                DispatchOutcome::Notification => { /* no reply */ }
                DispatchOutcome::Result(result) => {
                    if let Some(id) = id {
                        transport.write_message(&json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": result,
                        }))?;
                    }
                }
                DispatchOutcome::Error { code, message } => {
                    if let Some(id) = id {
                        transport.write_message(&json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": code, "message": message },
                        }))?;
                    }
                }
            }
        }
        Ok(())
    }

    fn dispatch(&self, method: &str, params: Value) -> DispatchOutcome {
        match method {
            "initialize" => DispatchOutcome::Result(json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "playground-sandbox", "version": env!("CARGO_PKG_VERSION") },
            })),
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
}

/// Internal dispatch result: a JSON-RPC result, error, or a notification that
/// gets no reply.
enum DispatchOutcome {
    Notification,
    Result(Value),
    Error { code: i64, message: String },
}

/// The MCP `tools/list` schema for the three sandbox tools.
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
            "description": "Tear down a sandbox session and release its resources.",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A backend that records calls and needs no Lima. Session id = tenant label.
    #[derive(Default)]
    struct MockBackend {
        execs: Arc<AtomicUsize>,
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
            Ok(())
        }
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
            server.serve(&mut transport).expect("serve");
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
        // tools/list has three tools
        assert_eq!(lines[1]["result"]["tools"].as_array().unwrap().len(), 3);
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
            server.serve(&mut transport).expect("serve");
        }
        let line: Value =
            serde_json::from_str(String::from_utf8(output).unwrap().trim()).unwrap();
        assert_eq!(line["result"]["isError"], true);
        assert!(line["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown session"));
    }
}

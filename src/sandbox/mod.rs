//! Sandbox provider layer (architecture layer 3 of 4: Substrate / Verbs /
//! **Sandbox** / Drive).
//!
//! `playground` is becoming a *sandbox provider*: it spins up isolated shells
//! and exposes them over MCP. This module holds the backend-agnostic core of
//! that provider. It is deliberately additive and does not yet replace the
//! existing pile-mediated exec loop (`crate::exec_worker`) or the Lima
//! provisioning in `main.rs`; those remain the live path until the provider is
//! wired end-to-end.
//!
//! ## Concepts
//!
//! - A [`SandboxBackend`] provisions and tears down an isolated shell
//!   environment (a **session**). Backends: Lima ([`lima::LimaBackend`], local
//!   VM) and FreeBSD jails ([`jail::JailBackend`], remote host over SSH);
//!   `sandbox-exec`/seatbelt slots in behind the same trait later.
//! - A [`Session`] is one live sandbox with stateful shell context (cwd, env,
//!   running processes). Commands ([`SandboxBackend::exec`]) run *inside* a
//!   session, so state persists across calls the way a real terminal does.
//! - The pile is mounted into every session as an **append-only** file
//!   ([`PileMount`]): a process inside the sandbox can read and append the pile
//!   but cannot truncate it. This is the structural fix for the 2026-07 pile
//!   truncation incident.

pub mod faculties;
pub mod jail;
pub mod lima;
pub mod proc;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;

/// A logical sandbox session: one isolated, stateful shell.
///
/// The identifier is opaque to callers; backends map it to whatever they need
/// (a Lima instance name, a seatbelt process group, a jail id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new(raw: impl Into<String>) -> Self {
        SessionId(raw.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How the pile is exposed inside a session.
///
/// `append_only` is the load-bearing invariant: the guest gets a handle it can
/// read and `>>`-append but not `O_TRUNC`. Backends realise it differently
/// (macOS `chflags uappend` / `uappnd`, a read-only virtiofs mount plus an
/// append-only overlay in the guest, a jail with `sappnd`, ...).
///
/// ## TRUST BOUNDARY (which backends may realise this at all)
///
/// A pile may only be exposed to a session whose substrate is a
/// **operator-controlled surface**. Local backends (Lima on the Mac) qualify.
/// Remote backends on shared machines do NOT: [`jail::JailBackend`] runs on
/// `ai.bultmann.eu`, which other people can access, so it deliberately ignores
/// this mount — its sessions are pile-less and exec results come back to the
/// caller over MCP. Pile access from
/// server jails is deferred until either an encrypted / capability-gated
/// replica design or a `shared.pile`-only policy is decided (see the trust
/// boundary section in [`jail`]'s module docs).
#[derive(Debug, Clone)]
pub struct PileMount {
    /// Absolute path to the pile on the host.
    pub host_path: PathBuf,
    /// Path at which the pile appears inside the sandbox.
    pub guest_path: PathBuf,
    /// When true, the guest may read+append but not truncate/replace the file.
    pub append_only: bool,
}

/// A tenant = (pile mount × driver). The same infra will later serve both our
/// own drive and colleagues' Claude/ChatGPT sandboxes, each pinned to its own
/// pile and its own driver identity.
#[derive(Debug, Clone)]
pub struct Tenant {
    /// Stable label for the tenant (e.g. persona / instance name).
    pub label: String,
    /// The pile this tenant's sessions may touch.
    pub pile: PileMount,
}

/// Everything a backend needs to provision one session.
#[derive(Debug, Clone)]
pub struct SessionSpec {
    pub tenant: Tenant,
    /// Working directory the shell starts in (guest path), if any.
    pub cwd: Option<PathBuf>,
    /// Extra environment variables to seed into the session shell.
    pub env: Vec<(String, String)>,
}

/// A single command invocation within an already-open session.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Shell command line (run via `sh -lc`, matching the current exec worker).
    pub command: String,
    /// Optional per-call cwd override (guest path).
    pub cwd: Option<PathBuf>,
    /// Optional stdin bytes.
    pub stdin: Option<Vec<u8>>,
    /// Wall-clock timeout; `None` means the backend default.
    pub timeout: Option<Duration>,
}

/// The terminal result of an [`ExecRequest`].
///
/// Mirrors the fields the exec worker already records into the pile
/// (`crate::exec_worker::ExecOutput`) so the two can converge later.
#[derive(Debug, Default)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    /// Present iff the command was killed by the timeout / an error occurred.
    pub error: Option<String>,
}

/// A backend that can provision isolated shells and run commands in them.
///
/// Implementors: `lima::LimaBackend` (now), a future `seatbelt::SeatbeltBackend`
/// (macOS `sandbox-exec`), and a future `jail::JailBackend` (FreeBSD).
///
/// The trait is intentionally synchronous and blocking to match the rest of the
/// crate (no tokio anywhere today). The MCP server layer is where an async
/// runtime, if adopted, will bridge to these calls (see `crate::mcp`).
pub trait SandboxBackend: Send + Sync {
    /// Human-readable backend name for diagnostics ("lima", "seatbelt", ...).
    fn name(&self) -> &'static str;

    /// Open a session on an ALREADY-provisioned sandbox and return its session
    /// id. On the shipped persistent backends (jail, lima) this is pure
    /// reuse-or-reattach — it NEVER creates: a running box is reused, a
    /// down/stopped box is brought back up, and an unprovisioned tenant is an
    /// error (run `playground user create`). Explicit creation is
    /// `provision_sandbox`.
    fn open_session(&self, spec: &SessionSpec) -> Result<SessionId>;

    /// Explicitly create a tenant's PERSISTENT sandbox (idempotent: an existing
    /// box is just brought up, not recreated). Both shipped backends — jail and
    /// lima — are persistent/provision-based and implement this; the default
    /// no-op exists only for a hypothetical ephemeral (create-on-open) backend.
    fn provision_sandbox(&self, _spec: &SessionSpec) -> Result<()> {
        Ok(())
    }

    /// Bring up every already-provisioned sandbox this backend owns (e.g. after a
    /// host reboot wiped the in-kernel jail records / stopped the Lima VMs, while
    /// the on-disk datasets / instances remain). Returns how many were
    /// (re)attached. Both jail and lima implement this; default: none.
    fn reattach_all(&self) -> Result<usize> {
        Ok(0)
    }

    /// Run one command inside an open session. Blocks until the command exits,
    /// times out, or is killed.
    fn exec(&self, session: &SessionId, request: &ExecRequest) -> Result<ExecResult>;

    /// Release a session. On the shipped persistent backends (jail, lima) this
    /// only DETACHES — the box stays alive so the same tenant can reconnect. Use
    /// `destroy_session` to remove it for good. (A hypothetical ephemeral backend
    /// would tear the sandbox down here.)
    fn close_session(&self, session: &SessionId) -> Result<()>;

    /// Permanently tear a sandbox down and free its storage, even for backends
    /// whose `close_session` only detaches (the persistent sandboxes). Both
    /// shipped backends (jail, lima) override this with real teardown; the
    /// default delegates to `close_session`, correct only for a hypothetical
    /// ephemeral backend where closing already destroys.
    fn destroy_session(&self, session: &SessionId) -> Result<()> {
        self.close_session(session)
    }

    /// Spin DOWN every owned sandbox that must not outlive the playground
    /// process — the inverse of `reattach_all`'s startup spin-up, but WITHOUT
    /// destroying anything (the on-disk dataset / instance stays, so the next
    /// `reattach_all` brings it back). Returns how many were spun down.
    ///
    /// The two shipped backends differ by how costly an idle-but-live sandbox
    /// is:
    /// - **jail** (default no-op): a jail is an in-kernel `prison` record with
    ///   zero processes — essentially free — so jails PERSIST across playground
    ///   restarts and there is nothing to spin down.
    /// - **lima** (override): a VM holds real host RAM/CPU even when idle, so a
    ///   Lima instance is tied to the playground process lifetime — `limactl
    ///   stop` each owned running instance here.
    ///
    /// Called on graceful shutdown and, crucially, by `playground clean` — the
    /// reliable sweep after a hard kill, since a killed process cannot run its
    /// own cleanup.
    fn shutdown(&self) -> Result<usize> {
        Ok(0)
    }
}

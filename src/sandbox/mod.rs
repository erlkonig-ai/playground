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
//! - A session is one live sandbox with stateful shell context (cwd, env,
//!   running processes). Commands ([`SandboxBackend::exec`]) run *inside* a
//!   session, so state persists across calls the way a real terminal does.
//! - A durable faculty pile is chosen once, while provisioning. Opening an
//!   existing sandbox names only its tenant; no reconnecting client can swap
//!   the storage underneath it.

pub mod faculties;
pub mod jail;
pub mod lima;
pub mod policy;
pub mod proc;
pub mod runner;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Per-canonical-key lifecycle lock manager.
///
/// Serializes the create/open/close/destroy lifecycle of a single tenant so two
/// concurrent operations on the SAME box cannot race (the blocker-#3 concurrent-
/// create data-loss class, and the mcp.rs refcount close/open orphan window).
/// The key is the tenant's CANONICAL physical identity — for the jail backend
/// that is the injective `jail_name` (repair #1), so two labels that map to one
/// box also map to one lock.
///
/// It is a map of key -> `Arc<Mutex<()>>`. [`Self::with_lock`] runs a closure
/// while holding the per-key mutex, so a lifecycle entry point wraps its whole
/// body in one call. The map only ever grows (a handful of tenants); an unused
/// entry is a bare `Arc<Mutex<()>>` that costs nothing.
///
/// This is an IN-PROCESS lock: it serializes everything inside one playground
/// process (the daemon's concurrent open/close, and any in-process concurrent
/// provision/destroy). It does NOT span the separate `playground user` CLI
/// process and the daemon — that residual cross-process window is covered
/// instead by the backend's tri-state probe + operation-owned cleanup (a
/// concurrent create is non-destructive even unlocked), with a host flock a
/// noted follow-up.
#[derive(Default)]
pub struct LifecycleLocks {
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl LifecycleLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up (creating on first use) the per-key mutex and return its `Arc`.
    fn mutex_for(&self, key: &str) -> Arc<Mutex<()>> {
        self.locks
            .lock()
            .expect("lifecycle locks poisoned")
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Run `body` while holding the lifecycle lock for `key`, blocking until the
    /// lock is free. The entire lifecycle operation happens under the lock, so a
    /// same-key operation elsewhere waits its turn.
    pub fn with_lock<T>(&self, key: &str, body: impl FnOnce() -> T) -> T {
        let mutex = self.mutex_for(key);
        let _guard: MutexGuard<'_, ()> = mutex.lock().expect("tenant lifecycle lock poisoned");
        body()
    }
}

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

/// Fixed guest path of the durable faculty pile.
pub const GUEST_FACULTY_PILE: &str = "/pile/self.pile";

/// Fixed guest path of the signing key belonging to the lexical pile identity.
pub const GUEST_FACULTY_KEY: &str = "/identity/self.key";

/// The two host files that make a writable faculty installation useful.
///
/// Callers provide the *lexical* `self.pile` path once. [`Self::resolve`] finds
/// the real pile file while deliberately finding `self.key` beside the lexical
/// path first. This distinction matters when a convenient workspace
/// `self.pile` is a symlink into a custody directory but its durable signing key
/// remains in the workspace. Both stored paths are canonical regular files, so
/// a backend never has to reinterpret a symlink chain.
///
/// Guest destinations are not caller-controlled: every backend exposes these
/// files at [`GUEST_FACULTY_PILE`] and [`GUEST_FACULTY_KEY`]. That keeps
/// `PILE`/`TRIBLESPACE_KEY` stable while allowing Lima to hardlink only these
/// two inodes into private per-tenant view directories. Neither the source
/// parents nor their potentially huge common ancestor cross the guest boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacultyFiles {
    pile: PathBuf,
    signing_key: PathBuf,
}

impl HostFacultyFiles {
    /// Resolve one lexical `.../self.pile` and its lexical sibling `self.key`.
    pub fn resolve(lexical_pile: &std::path::Path) -> Result<Self> {
        if !lexical_pile.is_absolute() {
            bail!(
                "faculty pile must be an absolute host path (got {})",
                lexical_pile.display()
            );
        }
        if lexical_pile.file_name() != Some(std::ffi::OsStr::new("self.pile")) {
            bail!(
                "faculty pile must name self.pile (got {})",
                lexical_pile.display()
            );
        }

        let lexical_parent = lexical_pile.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "faculty pile path has no lexical parent: {}",
                lexical_pile.display()
            )
        })?;
        let lexical_key = lexical_parent.join("self.key");

        Ok(Self {
            pile: canonical_regular_file("faculty pile", lexical_pile)?,
            signing_key: canonical_regular_file("faculty signing key", &lexical_key)?,
        })
    }

    pub fn pile(&self) -> &std::path::Path {
        &self.pile
    }

    pub fn signing_key(&self) -> &std::path::Path {
        &self.signing_key
    }

    /// Recheck the provisioning-time invariant after resolution. This catches
    /// a file removed or replaced between CLI parsing and backend mutation.
    pub fn validate(&self) -> Result<()> {
        validate_regular_file("faculty pile", &self.pile)?;
        validate_regular_file("faculty signing key", &self.signing_key)
    }
}

fn canonical_regular_file(kind: &str, path: &std::path::Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("resolve {kind} {}", path.display()))?;
    validate_regular_file(kind, &canonical)?;
    Ok(canonical)
}

fn validate_regular_file(kind: &str, path: &std::path::Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect {kind} {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{kind} is not a regular file: {}", path.display());
    }
    Ok(())
}

/// A stable sandbox identity. Storage is deliberately absent: it is fixed by
/// [`ProvisionSpec`] and cannot be supplied while opening a session.
#[derive(Debug, Clone)]
pub struct Tenant {
    /// Stable label for the tenant (e.g. persona / instance name).
    pub label: String,
}

/// The two supported ownership topologies for a sandbox's durable faculty pile.
///
/// Append-only intent is the load-bearing invariant: the guest gets a handle it
/// can read and `>>`-append but not `O_TRUNC`. A host pile may only be exposed
/// to an operator-controlled substrate such as local Lima. The jail backend
/// runs on a shared host and therefore accepts only [`Self::BackendOwned`]: it
/// allocates per-tenant piles under its own `pile_root` rather than accepting a
/// caller-selected host path.
#[derive(Debug, Clone)]
pub enum FacultyPile {
    /// Operator-controlled host pile + signing key mounted into a local sandbox
    /// (Lima).
    Host(HostFacultyFiles),
    /// Storage allocated and retained by the backend itself (FreeBSD jail).
    BackendOwned,
}

/// Everything a backend needs to create one persistent sandbox.
#[derive(Debug, Clone)]
pub struct ProvisionSpec {
    pub tenant: Tenant,
    /// Working directory the shell starts in (guest path), if any.
    pub cwd: Option<PathBuf>,
    /// Extra environment variables to seed into the session shell.
    pub env: Vec<(String, String)>,
    /// Durable pile used by faculties inside the provisioned sandbox.
    pub faculty_pile: FacultyPile,
}

/// Everything a backend needs to open an already-provisioned sandbox.
///
/// This type intentionally carries only a tenant. In particular, it has no
/// host path, cwd, or environment: those are provisioning facts, not reconnect
/// choices.
#[derive(Debug, Clone)]
pub struct OpenSpec {
    pub tenant: Tenant,
}

/// How an [`ExecRequest`] enters the sandbox shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExecShellMode {
    /// Stateful user command: source the sandbox's session profile (`sh -lc`).
    #[default]
    Login,
    /// Internal protocol command: bypass tenant profile code (`sh -c`).
    Clean,
}

/// A single command invocation within an already-open session.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Shell command line interpreted according to [`ExecShellMode`].
    pub command: String,
    /// Login shells preserve the stateful user-command contract; clean shells
    /// are reserved for internal operations whose stdout/stdin are protocol
    /// payloads and therefore must not pass through tenant profile code.
    pub shell_mode: ExecShellMode,
    /// Optional per-call cwd override (guest path).
    pub cwd: Option<PathBuf>,
    /// Optional stdin bytes.
    pub stdin: Option<Vec<u8>>,
    /// Wall-clock timeout; `None` means the backend default.
    pub timeout: Option<Duration>,
}

/// Which output pipe produced a streamed execution chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStream {
    Stdout,
    Stderr,
}

/// Receives output while a command is still running.
///
/// Implementations must do only bounded, in-memory work here: the callback is
/// invoked directly by the stdout/stderr drain threads. When a sink is present
/// it owns output retention and the terminal [`ExecResult`] does not duplicate
/// stdout/stderr; callers that need a captured result omit the sink.
pub trait ExecOutputSink: Send + Sync {
    fn on_output(&self, stream: ExecStream, chunk: &[u8]);
}

/// Cloneable control plane for one execution.
///
/// Every clone shares the same cancellation flag and optional output sink. A
/// job table can therefore retain one clone to cancel/poll while a blocking
/// backend owns another for the duration of [`SandboxBackend::exec`].
#[derive(Clone)]
pub struct ExecControl {
    cancelled: Arc<AtomicBool>,
    output_sink: Option<Arc<dyn ExecOutputSink>>,
    capture_output: bool,
    output_open: Arc<Mutex<bool>>,
}

impl Default for ExecControl {
    fn default() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            output_sink: None,
            capture_output: true,
            output_open: Arc::new(Mutex::new(true)),
        }
    }
}

impl std::fmt::Debug for ExecControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecControl")
            .field("cancelled", &self.is_cancelled())
            .field("has_output_sink", &self.output_sink.is_some())
            .field("capture_output", &self.capture_output)
            .finish()
    }
}

impl ExecControl {
    pub fn with_output_sink(output_sink: Arc<dyn ExecOutputSink>) -> Self {
        Self {
            output_sink: Some(output_sink),
            // The sink owns bounded retention. Keeping a second full copy in
            // each drain thread would both double memory and couple process
            // lifetime to the retained-log ceiling.
            capture_output: false,
            ..Self::default()
        }
    }

    /// Request cooperative cancellation. The process driver observes this at
    /// its short polling cadence and then kills and reaps the transported child.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn emit(&self, stream: ExecStream, chunk: &[u8]) {
        let open = self
            .output_open
            .lock()
            .expect("execution output gate poisoned");
        if !*open {
            return;
        }
        if let Some(sink) = &self.output_sink {
            sink.on_output(stream, chunk);
        }
    }

    /// Close the streaming side before a job publishes its terminal state.
    /// Taking the same gate as [`Self::emit`] waits for any in-flight callback,
    /// so detached drain threads can never append after terminal publication.
    pub(crate) fn seal_output(&self) {
        *self
            .output_open
            .lock()
            .expect("execution output gate poisoned") = false;
    }

    pub(crate) fn captures_output(&self) -> bool {
        self.capture_output
    }
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
    /// True iff an [`ExecControl`] cancellation request killed this execution.
    pub cancelled: bool,
    /// Present iff the command was killed by cancellation/timeout or an error
    /// occurred.
    pub error: Option<String>,
}

/// The backend has lost the ability to prove that a cancellable command and
/// all of its descendants are gone. This is not an ordinary command/backend
/// failure: a server that receives it must stop global admission and exit so an
/// operator can recover the host explicitly.
#[derive(Debug)]
pub(crate) struct SandboxControlLost {
    reason: String,
}

impl std::fmt::Display for SandboxControlLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sandbox execution control lost: {}", self.reason)
    }
}

impl std::error::Error for SandboxControlLost {}

pub(crate) fn sandbox_control_lost(reason: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(SandboxControlLost {
        reason: reason.into(),
    })
}

pub(crate) fn is_sandbox_control_lost(error: &anyhow::Error) -> bool {
    error.downcast_ref::<SandboxControlLost>().is_some()
}

/// A backend that can provision isolated shells and run commands in them.
///
/// Implementors: `lima::LimaBackend` (now), a future `seatbelt::SeatbeltBackend`
/// (macOS `sandbox-exec`), and a future `jail::JailBackend` (FreeBSD).
///
/// The trait is deliberately synchronous and blocking: backends drive
/// `ssh`/`limactl`/`jexec` as blocking subprocesses, and a sync provider core
/// stays simple. The async boundary lives in the `mcp-http` transport (feature
/// `mcp-http` = tokio + axum), which bridges to these blocking calls via
/// `tokio::task::spawn_blocking` (see `crate::mcp_http`).
pub trait SandboxBackend: Send + Sync {
    /// Human-readable backend name for diagnostics ("lima", "seatbelt", ...).
    fn name(&self) -> &'static str;

    /// Whether this backend can prove prompt cancellation and reaping for a
    /// retained background job. The public `job_*` surface is intentionally
    /// narrower than synchronous execution: unsupported backends keep `exec`
    /// but do not pretend that killing a local transport killed remote work.
    fn supports_background_jobs(&self) -> bool {
        false
    }

    /// The CANONICAL physical key for a tenant: the stable identity that maps
    /// two aliasing labels to ONE sandbox. The provider uses it to pick a
    /// per-tenant lifecycle lock BEFORE it knows the eventual `SessionId`, so
    /// open and close serialize on the same lock (closing the refcount
    /// close/open orphan race). For the jail backend this is the injective
    /// `jail_name` (repair #1); the default is the raw label, correct for
    /// backends whose session id is a 1:1 function of the label.
    fn canonical_key(&self, tenant: &Tenant) -> String {
        tenant.label.clone()
    }

    /// Open a session on an ALREADY-provisioned sandbox and return its session
    /// id. On the shipped persistent backends (jail, lima) this is pure
    /// reuse-or-reattach — it NEVER creates: a running box is reused, a
    /// down/stopped box is brought back up, and an unprovisioned tenant is an
    /// error (run `playground user create`). Explicit creation is
    /// `provision_sandbox`.
    fn open_session(&self, spec: &OpenSpec) -> Result<SessionId>;

    /// Explicitly create a tenant's PERSISTENT sandbox (idempotent: an existing
    /// box is just brought up, not recreated). Both shipped backends — jail and
    /// lima — are persistent/provision-based and implement this; the default
    /// no-op exists only for a hypothetical ephemeral (create-on-open) backend.
    fn provision_sandbox(&self, _spec: &ProvisionSpec) -> Result<()> {
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
    fn exec(
        &self,
        session: &SessionId,
        request: &ExecRequest,
        control: &ExecControl,
    ) -> Result<ExecResult>;

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

#[cfg(test)]
mod host_faculty_files_tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "playground-host-faculty-files-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create fixture root");
        root
    }

    #[test]
    fn resolve_rejects_missing_and_non_regular_files() {
        let missing_pile = fixture("missing-pile");
        std::fs::write(missing_pile.join("self.key"), b"key").expect("create key");
        let error = HostFacultyFiles::resolve(&missing_pile.join("self.pile"))
            .expect_err("missing pile must fail");
        assert!(format!("{error:#}").contains("faculty pile"));

        let missing_key = fixture("missing-key");
        std::fs::write(missing_key.join("self.pile"), b"pile").expect("create pile");
        let error = HostFacultyFiles::resolve(&missing_key.join("self.pile"))
            .expect_err("missing key must fail");
        assert!(format!("{error:#}").contains("faculty signing key"));

        let pile_directory = fixture("pile-directory");
        std::fs::create_dir(pile_directory.join("self.pile")).expect("create pile directory");
        std::fs::write(pile_directory.join("self.key"), b"key").expect("create key");
        let error = HostFacultyFiles::resolve(&pile_directory.join("self.pile"))
            .expect_err("directory pile must fail");
        assert!(error.to_string().contains("not a regular file"));

        let key_directory = fixture("key-directory");
        std::fs::write(key_directory.join("self.pile"), b"pile").expect("create pile");
        std::fs::create_dir(key_directory.join("self.key")).expect("create key directory");
        let error = HostFacultyFiles::resolve(&key_directory.join("self.pile"))
            .expect_err("directory key must fail");
        assert!(error.to_string().contains("not a regular file"));
    }
}

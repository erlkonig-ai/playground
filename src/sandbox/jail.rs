//! FreeBSD jail backend for the sandbox provider.
//!
//! Drives a remote FreeBSD host (default `ai.bultmann.eu`) over SSH and maps
//! the [`SandboxBackend`] verbs onto base `jail(8)` + ZFS:
//!
//!   - `provision_sandbox` = explicit CREATE of a PERSISTENT per-tenant box: a
//!     brand-new tenant is `zfs clone`d from the template snapshot
//!     (`aitemp/playground/template@base`) into a per-tenant dataset
//!     (`aitemp/playground/<session>`), given a manual `devfs` mount, its two
//!     host-owned piles (per-coworker `self.pile` + the shared `shared.pile`)
//!     nullfs-mounted rw at guest `/pile` and `/shared`, seeded `/etc/profile`
//!     (PATH=/opt/faculties + PILE=/pile/self.pile), then `jail -c
//!     name=playground-<session> path=<mountpoint> persist ...`. Idempotent: a
//!     tenant whose dataset already exists is treated as already-provisioned
//!     (skip the clone, just ensure the jail is up). This is what `playground
//!     user create <name>` calls.
//!   - `open_session`  = pure reuse-or-reattach of an ALREADY-provisioned box —
//!     it NEVER clones. A running jail context is reused as-is; a persisted
//!     dataset whose jail is gone (host reboot / playground restart) is
//!     re-attached (devfs re-mount + `jail -c`, no clone/re-seed); a tenant with
//!     no dataset at all is an error ("not provisioned — run `playground user
//!     create <name>`").
//!   - `reattach_all` = the startup sweep: enumerate every provisioned dataset
//!     under `dataset_parent` and `jail -c` each one whose jail context is gone
//!     (host reboot wiped the in-kernel jail records but the datasets remain).
//!   - `exec`          = `jexec <jail> /bin/sh -lc <command>`, wrapped in
//!     FreeBSD `timeout(1)` server-side so a runaway command is killed *on the
//!     server* (exit 124), with a local wall-clock backstop mirroring
//!     [`super::lima::LimaBackend`]'s timeout/exit-124 semantics.
//!   - `close_session` = DETACH only: the box persists across disconnects and
//!     reconnects so the same tenant returns to the same box (one box per
//!     tenant). No teardown.
//!   - `destroy_session` = the explicit teardown: `jail -r` + unmount (both
//!     nullfs pile mounts AND devfs) + `zfs destroy` of the dataset. The
//!     host-owned piles (self + shared) are NEVER deleted — Model B keeps them
//!     decoupled from the jail lifecycle. ZFS clones are cheap copy-on-write
//!     children of the template snapshot, so a tenant box costs ~nothing until
//!     destroyed.
//!
//! Everything the backend creates on the server is namespaced: jail names are
//! `<prefix>-<label>` (default prefix `playground`) and datasets live under
//! the configured parent (default `aitemp/playground`). The backend never
//! touches jails or datasets outside that namespace.
//!
//! ## Host access model
//!
//! All server commands go through a small [`HostRunner`] trait. Two production
//! impls exist:
//!
//!   - [`SshRunner`] (`ssh -o BatchMode=yes <host> <command>`, root via
//!     `sudo -n`): the backend *drives the server from wherever it runs*, so
//!     `playground mcp --backend jail` works directly on the Mac with no
//!     playground binary on the FreeBSD side.
//!   - [`LocalRunner`]: server-side hosting — the same argv spawned directly
//!     on the jail host itself, no ssh wrapper. Selected with `--jail-local`;
//!     this is what the `playground_mcp` rc.d service uses (see
//!     `deploy/freebsd/`).
//!
//! Tests use a mock runner, mirroring how `crate::mcp` tests use a mock
//! backend.
//!
//! ## Networking
//!
//! v1 jails are created with `ip4=disable ip6=disable`: no network at all.
//! This is deliberate default-deny; host-only or NAT networking is a later,
//! explicit decision.
//!
//! ## Pile provisioning (Model B: host-owned, server-born piles)
//!
//! This backend does NOT use the caller-supplied `tenant.pile.host_path` (that
//! field is only logged); every tenant jail is given its OWN piles, created on
//! the server under `pile_root`. Two host-owned pile FILES are mounted in via
//! single-FILE `nullfs` (FreeBSD nullfs mounts a plain file onto a plain file,
//! verified on 15.1 — NOT only directories). Each pile file is mounted directly
//! onto a pre-created empty target file that lives INSIDE the jail's own ZFS
//! clone, so **no host directory is ever nullfs-mounted rw into a jail**:
//!
//!   - **`self.pile`** — per-tenant, host <pile_root>/<jail>/self.pile,
//!     nullfs-mounted **rw** onto guest `/pile/self.pile` (so
//!     `PILE=/pile/self.pile`). Seeded by copying `bootstrap_pile` at provision
//!     if absent. **Model B: DECOUPLED from the jail lifecycle** — destroying
//!     the jail unmounts but never deletes it, and a re-provision reattaches the
//!     same accumulated pile.
//!   - **`shared.pile`** — a SINGLE host file shared by ALL tenant jails,
//!     host <pile_root>/shared/shared.pile, nullfs-mounted **rw** onto guest
//!     `/shared/shared.pile` (same append-only semantics as self.pile; multiple
//!     concurrent writers appending the one pile file is supported and was
//!     verified on 15.1 — two jail views appended 50 lines each, all 100
//!     landed). Seeded once, race-safely; never deleted by a single-tenant
//!     teardown.
//!
//! ### Why single-FILE mounts (symlink confused-deputy fix, 2026-07-24)
//!
//! An earlier layout nullfs-mounted the host per-jail dir and the host shared
//! DIRECTORY rw into each jail (guest `/pile`, `/shared`). That handed a tenant
//! (root in its jail) a WRITABLE HOST DIRECTORY: it could create arbitrary
//! sibling entries — e.g. pre-place `shared.pile.<jail>.tmp` as an absolute
//! symlink — and the next privileged host-side provision `cp` would FOLLOW that
//! symlink and overwrite the chosen host file with bootstrap bytes (a symlink
//! confused deputy; needed no `chflags`, since the tenant was appending/creating
//! a sibling, not clearing a flag). Mounting only the individual FILES removes
//! the writable host directory entirely: the jail's `/shared` (and `/pile`) is
//! now the jail's OWN clone directory, so a sibling a tenant creates there stays
//! in the throwaway clone and never reaches the host pile dir. Combined with
//! host-private `0700` staging for the bootstrap `cp` (below), the deputy is
//! gone structurally, not just defended.
//!
//! Both mounts are re-established on every attach (they do not survive a jail
//! restart, exactly like the devfs mount) and torn down before `zfs destroy`
//! (a dataset with mounts under its tree cannot be destroyed).
//!
//! ## FACULTY PROVISIONING (faculties on PATH)
//!
//! The full faculty CLI bin set is **baked into the ZFS template** at
//! `/opt/faculties` server-side (a template-baking step, not this backend's
//! job — every `zfs clone` inherits it copy-on-write). This backend's part is
//! two `/etc/profile` lines seeded at provision alongside the session env
//! block: `export PATH=/opt/faculties:$PATH` and `export PILE=/pile/self.pile`,
//! so a faculty run in the jail resolves and operates on the coworker's own
//! mounted pile (the jail analogue of the Lima template's faculties staging in
//! `render_config`).

use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use super::proc::{DEFAULT_MAX_OUTPUT_BYTES, drive_child, drive_child_capped};
use super::{ExecRequest, ExecResult, LifecycleLocks, SandboxBackend, SessionId, SessionSpec};

/// Output of one host command, however it was transported. Local-backstop
/// timeouts set `timed_out`; server-side `timeout(1)` expiry shows up as
/// `exit_code == Some(124)` instead.
pub use super::proc::ChildOutput as HostOutput;

/// Default per-command timeout when an [`ExecRequest`] does not specify one.
/// Matches `super::lima::DEFAULT_EXEC_TIMEOUT`.
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);
/// Server-side CEILING on a per-command timeout. A caller may request LESS via
/// `ExecRequest::timeout`, never MORE: the effective timeout is
/// `min(requested, MAX_EXEC_TIMEOUT)`. This bounds how long one tenant can pin a
/// blocking worker + a jail process regardless of what `timeout_ms` it sends
/// (the review's caller-selected-`u64`-timeout class). 30 minutes is generous
/// for an honest long build while still finite.
const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Timeout for administrative host commands (zfs/jail/mount lifecycle).
const ADMIN_TIMEOUT: Duration = Duration::from_secs(120);
/// Extra local wall-clock grace on top of the server-side `timeout(1)`: the
/// server kill is authoritative; the local kill only fires if SSH itself
/// wedges.
const LOCAL_TIMEOUT_GRACE: Duration = Duration::from_secs(20);
/// Per-stream output ceiling for a tenant `exec` (see
/// [`super::proc::DEFAULT_MAX_OUTPUT_BYTES`]). Each of stdout/stderr is capped
/// independently and the jail process is killed the instant either exceeds it,
/// so a runaway producer cannot make the daemon accumulate unbounded memory.
const MAX_EXEC_OUTPUT_BYTES: usize = DEFAULT_MAX_OUTPUT_BYTES;
/// Default ZFS `refquota` for a per-tenant clone (a ZFS size string). Bounds how
/// much a tenant can write into its own dataset so it cannot fill the host pool.
const DEFAULT_CLONE_REFQUOTA: &str = "10G";
/// Default ZFS `quota` for the pile-root dataset (a ZFS size string). Global cap
/// across all tenants' piles (self + shared) so pile writes cannot fill the pool.
const DEFAULT_PILE_ROOT_QUOTA: &str = "50G";
/// Default per-jail `rctl(8)` rules (the `<resource>:<action>=<amount>` tails).
/// Applied ONLY when host RACCT is enabled (probed at runtime); a no-op on the
/// current RACCT-off deploy box. These clamp the fork/thread/FD/RAM/CPU pressure
/// the review flagged as reaching host-global resources: cap processes and
/// threads (fork-bomb), resident + swap memory (RAM exhaustion), open files (FD
/// exhaustion), and CPU-seconds (runaway spin). Deny actions fail the offending
/// syscall; the CPU rule signals the process.
const DEFAULT_RCTL_RULES: &[&str] = &[
    "maxproc:deny=512",
    "openfiles:deny=8192",
    "memoryuse:deny=2G",
    "swapuse:deny=1G",
    "pcpu:deny=90",
    "nthr:deny=2048",
];

/// Tri-state, ERROR-PRESERVING result of a "does this ZFS dataset exist?" probe.
///
/// A plain `bool` collapses transport failure, permission failure, timeout, and
/// true absence all into "no", and a lifecycle op that then runs destructive
/// cleanup (`zfs destroy`) on a merely-transient probe failure can DESTROY a
/// valid persistent workspace (the 2026-07-24 blocker-#3 data-loss class). This
/// enum keeps the three cases apart so a caller can fail CLOSED on doubt:
///
///   - [`DatasetState::Exists`] — `zfs list` returned success. The dataset is
///     definitely present.
///   - [`DatasetState::Absent`] — `zfs list` failed with the CANONICAL
///     "dataset does not exist" signal (exit non-zero AND the stderr ZFS emits
///     for a genuinely missing name). Only in this state is it safe to treat a
///     tenant as un-provisioned / free to clone into.
///   - [`DatasetState::Unknown`] — anything else: a transport error (ssh 255),
///     a local timeout, a permission failure, a faulted pool, or any non-zero
///     exit whose stderr is NOT the not-found signal. The probe simply does not
///     know, so NO destructive action may run on this state — the caller bails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DatasetState {
    Exists,
    Absent,
    Unknown,
}

/// Runs one argv on the jail host. The seam that makes [`JailBackend`]
/// testable without a FreeBSD server (mirror of the mock-backend pattern in
/// `crate::mcp` tests).
pub trait HostRunner: Send + Sync {
    /// Run `argv` on the host, optionally feeding `stdin`, killing after
    /// `timeout` wall-clock. Implementations must capture stdout/stderr
    /// completely (drain concurrently — a full pipe must not deadlock the
    /// child). Used for administrative host commands whose output is bounded by
    /// construction (zfs/jail/mount).
    fn run(&self, argv: &[String], stdin: Option<&[u8]>, timeout: Duration) -> Result<HostOutput>;

    /// Like [`run`](Self::run) but caps each of stdout/stderr at
    /// `max_output_bytes` and KILLS the transported child the instant either
    /// exceeds it (`ChildOutput::output_truncated` is then set). This is the
    /// path for a TENANT `exec`, whose output is attacker-controlled: it must
    /// not accumulate unbounded memory in the daemon. The default is unbounded
    /// (delegates to `run`), correct only for a runner that never carries a
    /// tenant command; the production runners override it.
    fn run_capped(
        &self,
        argv: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
        _max_output_bytes: usize,
    ) -> Result<HostOutput> {
        self.run(argv, stdin, timeout)
    }

    /// Exit code that means "the transport itself failed", as opposed to the
    /// host command's own status. `ssh` reserves 255 for this; a local spawn
    /// has no separate transport, so the default is `None`.
    fn transport_error_exit(&self) -> Option<i32> {
        None
    }
}

/// Production runner: `ssh -o BatchMode=yes -o ConnectTimeout=<n> <host> <cmd>`.
///
/// SSH hands the remote side a single string that the login shell re-parses,
/// so every argv element is single-quote-escaped ([`shell_quote`]) before
/// joining. Local stdin pipes through to the remote command; the remote
/// command's exit code propagates as ssh's exit code (255 = transport error).
#[derive(Debug, Clone)]
pub struct SshRunner {
    pub host: String,
    pub connect_timeout: Duration,
}

impl SshRunner {
    pub fn new(host: impl Into<String>) -> Self {
        SshRunner {
            host: host.into(),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl HostRunner for SshRunner {
    fn run(&self, argv: &[String], stdin: Option<&[u8]>, timeout: Duration) -> Result<HostOutput> {
        let remote = argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ");
        let mut cmd = Command::new("ssh");
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(format!("ConnectTimeout={}", self.connect_timeout.as_secs()))
            .arg(&self.host)
            .arg(remote);

        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn().context("spawn ssh")?;

        // Concurrent stdin-feed + stdout/stderr drain (super::proc, extracted
        // from the original inline implementation here): a remote command
        // producing more than a pipe buffer of output cannot deadlock against
        // the timeout loop.
        drive_child(child, stdin.map(|b| b.to_vec()), timeout)
    }

    fn run_capped(
        &self,
        argv: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<HostOutput> {
        let remote = argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ");
        let mut cmd = Command::new("ssh");
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(format!("ConnectTimeout={}", self.connect_timeout.as_secs()))
            .arg(&self.host)
            .arg(remote);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let child = cmd.spawn().context("spawn ssh")?;
        // Killing the LOCAL ssh on a cap breach also tears down the pipe to the
        // remote; the authoritative remote-side kill of the jail process tree is
        // the backend's `timeout(1)` wrapper (server-side, exit 124). The cap is
        // the daemon-memory bound; the timeout is the process-tree bound.
        drive_child_capped(child, stdin.map(|b| b.to_vec()), timeout, max_output_bytes)
    }

    fn transport_error_exit(&self) -> Option<i32> {
        Some(255) // ssh reserves 255 for its own failures
    }
}

/// Server-side hosting runner: spawn the argv directly on this machine (which
/// *is* the jail host), no ssh wrapper and no re-quoting — the argv reaches
/// `execve` verbatim. Everything else (root via `sudo -n`, the command
/// vocabulary, the namespace guard) is identical to [`SshRunner`], so the two
/// are interchangeable behind [`JailBackend`].
#[derive(Debug, Clone, Default)]
pub struct LocalRunner;

impl HostRunner for LocalRunner {
    fn run(&self, argv: &[String], stdin: Option<&[u8]>, timeout: Duration) -> Result<HostOutput> {
        let Some((program, args)) = argv.split_first() else {
            bail!("empty argv");
        };
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn().with_context(|| format!("spawn {program}"))?;
        drive_child(child, stdin.map(|b| b.to_vec()), timeout)
    }

    fn run_capped(
        &self,
        argv: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<HostOutput> {
        let Some((program, args)) = argv.split_first() else {
            bail!("empty argv");
        };
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let child = cmd.spawn().with_context(|| format!("spawn {program}"))?;
        drive_child_capped(child, stdin.map(|b| b.to_vec()), timeout, max_output_bytes)
    }
}

/// POSIX single-quote escaping: `it's` -> `'it'\''s'`. Safe for any byte
/// sequence except NUL under every sh-compatible remote login shell (the jail
/// host's is zsh; quoting rules for single quotes are identical).
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// FreeBSD-jail-backed sandbox. One [`SessionId`] maps to one jail name, which
/// equals the session's ZFS dataset leaf under `dataset_parent`.
///
/// Stateless beyond configuration (mirrors [`super::lima::LimaBackend`]): jail
/// and dataset identity live on the server, so a restarted provider can still
/// `close_session` a jail it finds by name.
pub struct JailBackend {
    runner: Box<dyn HostRunner>,
    /// Jail-name / dataset-leaf prefix; the concrete name is `<prefix>-<label>`.
    pub jail_prefix: String,
    /// Template snapshot cloned per session, e.g. `aitemp/playground/template@base`.
    pub template_snapshot: String,
    /// Parent dataset for per-session clones, e.g. `aitemp/playground`.
    pub dataset_parent: String,
    /// Host directory root that holds the per-coworker pile dirs and the shared
    /// pile dir (Model B: host-owned, DECOUPLED from the jail lifecycle). The
    /// per-coworker `self.pile` lives at `<pile_root>/<jail-name>/self.pile` and
    /// is nullfs-mounted rw at guest `/pile`; the single shared pile lives at
    /// `<pile_root>/shared/shared.pile` and is nullfs-mounted rw at guest
    /// `/shared`. Destroying a jail never deletes anything under this root.
    pub pile_root: String,
    /// Host path to the `bootstrap.pile` seed copied into a brand-new
    /// coworker's `self.pile` (and used to seed the shared pile the first time).
    /// This is the server-side bootstrap seed, not any caller-supplied pile.
    pub bootstrap_pile: String,
    /// ZFS `refquota` (bytes) set on each per-tenant clone at provision so a
    /// tenant cannot fill the host pool via its own dataset's writes (repair #4
    /// storage bound). `refquota` (vs `quota`) bounds the dataset's OWN data
    /// only, not descendants/snapshots — exactly the tenant-controlled surface.
    /// `None` disables it (e.g. a pool with its own delegated quota). A ZFS-value
    /// string like "10G" is accepted via the CLI; stored as the raw bytes here.
    pub clone_refquota: Option<String>,
    /// ZFS `quota` (a size string) set on the pile-root DATASET at provision so
    /// tenants cannot fill the host pool through pile writes (the host-owned
    /// `self.pile`s + the shared `shared.pile` all live under `pile_root`).
    /// `quota` (vs `refquota`) here bounds the dataset AND all its descendants,
    /// i.e. every per-tenant pile dir at once — a single global pile-storage cap.
    /// Best-effort + idempotent: applied only when `pile_root` resolves to a real
    /// ZFS dataset (a plain-directory `pile_root` is skipped with a note).
    /// Per-tenant pile isolation would need per-tenant pile datasets — a noted
    /// follow-up; this global cap already stops the fill-the-pool attack. `None`
    /// disables it.
    pub pile_root_quota: Option<String>,
    /// Per-jail `rctl(8)` resource rules applied at provision, but ONLY when the
    /// host has RACCT enabled (`kern.racct.enable=1`, probed at runtime). Each
    /// entry is the `<resource>:<action>=<amount>` tail of a
    /// `jail:<name>:<resource>:<action>=<amount>` rule (e.g. `maxproc:deny=512`).
    /// Host RACCT is currently OFF on the deploy box, so these are a NO-OP there
    /// with a clear operator note (deploy/freebsd/README.md) on enabling it;
    /// once enabled they clamp per-jail process/RAM/CPU/FD pressure without any
    /// code change. Empty disables the programmatic path.
    pub rctl_rules: Vec<String>,
    /// Per-canonical-tenant (jail-name-keyed) lifecycle lock. Serializes
    /// provision / open / destroy for one tenant WITHIN this process, so two
    /// concurrent lifecycle ops on the same box cannot race (blocker #3). The
    /// mcp `SandboxProvider` holds its own [`LifecycleLocks`] over open/close to
    /// serialize the refcount race; this one covers the backend-driven paths
    /// (notably the `playground user create`/`destroy` CLI).
    lifecycle: LifecycleLocks,
}

impl JailBackend {
    /// Backend talking to `host` over SSH with the default namespace layout.
    pub fn ssh(host: impl Into<String>) -> Self {
        JailBackend::with_runner(Box::new(SshRunner::new(host)))
    }

    /// Backend running directly on the FreeBSD jail host itself (server-side
    /// hosting): same commands, no ssh hop. Requires non-interactive root via
    /// `sudo -n` for the invoking user (or running as root, where `sudo -n`
    /// is a pass-through).
    pub fn local() -> Self {
        JailBackend::with_runner(Box::new(LocalRunner))
    }

    /// Backend over an explicit runner (tests inject a mock here).
    pub fn with_runner(runner: Box<dyn HostRunner>) -> Self {
        JailBackend {
            runner,
            jail_prefix: "playground".to_string(),
            template_snapshot: "aitemp/playground/template@base".to_string(),
            dataset_parent: "aitemp/playground".to_string(),
            pile_root: "/aitemp/playground/piles".to_string(),
            bootstrap_pile: "/aitemp/playground/bootstrap.pile".to_string(),
            // Sane default: 10 GiB per tenant clone. Generous for a working
            // sandbox, finite enough that no tenant can fill the pool. Operators
            // tune it with `--jail-clone-refquota` (`0`/empty disables).
            clone_refquota: Some(DEFAULT_CLONE_REFQUOTA.to_string()),
            // Sane default: 50 GiB across ALL tenants' piles (self + shared).
            // Tune with `--jail-pile-quota` (`0`/empty disables).
            pile_root_quota: Some(DEFAULT_PILE_ROOT_QUOTA.to_string()),
            // Default per-jail rctl rules — applied ONLY when host RACCT is on
            // (probed at runtime; a no-op on the current RACCT-off deploy box).
            // Bounds process count, RAM, swap, open files, and CPU per jail.
            rctl_rules: DEFAULT_RCTL_RULES.iter().map(|s| s.to_string()).collect(),
            lifecycle: LifecycleLocks::new(),
        }
    }

    /// Deterministic, INJECTIVE jail name for a tenant label:
    /// `<prefix>-<safe>-<digest>`.
    ///
    /// The `<safe>` part is the human-readable sanitisation (label mapped onto
    /// `[A-Za-z0-9-]`, `-` for anything else) TRUNCATED to
    /// [`Self::SAFE_NAME_LEN`] bytes for operator legibility only — it is NOT
    /// what distinguishes tenants. The `<digest>` part is the first
    /// [`Self::DIGEST_HEX_LEN`] hex chars of SHA-256 over the ORIGINAL full
    /// label, and THAT is what guarantees injectivity: two labels that collapse
    /// to the same `<safe>` (e.g. `a/b`, `a?b`, `a-b`) still differ in the
    /// digest, so they get distinct jail names / ZFS datasets / private piles —
    /// no cross-tenant hijack. Same label → same name (deterministic, so
    /// reattach/destroy find the exact box).
    ///
    /// Public so the `user` CLI derives the same name the backend uses via this
    /// one function — the two must never drift on session ids (destroy,
    /// reattach). Callers that accept a raw principal label must
    /// [`validate_label`](Self::validate_label) it first; `jail_name` itself is
    /// total (it maps any string), but the lifecycle entry points reject
    /// pathological labels before they reach here.
    pub fn jail_name(&self, label: &str) -> String {
        let mut safe: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        safe.truncate(Self::SAFE_NAME_LEN);
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest
            .iter()
            .take(Self::DIGEST_HEX_LEN / 2)
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{}-{}-{}", self.jail_prefix, safe, hex)
    }

    /// Truncation bound for the human-readable `<safe>` part of a jail name
    /// (operator legibility only; injectivity comes from the digest).
    const SAFE_NAME_LEN: usize = 32;
    /// Number of hex chars of the SHA-256 label digest carried in a jail name.
    /// 20 hex chars = 80 bits: collision-resistant well past any realistic
    /// tenant count, and the ZFS `playground:tenant` property is the
    /// authoritative backstop even if it ever collided.
    const DIGEST_HEX_LEN: usize = 20;

    /// ZFS user property that records the ORIGINAL tenant label on a session's
    /// dataset. Set right after `zfs clone` and verified on every reuse /
    /// reattach: a stored-vs-requested mismatch means a digest collision or
    /// tampering, and the backend refuses rather than hand one tenant another's
    /// box. This is the authoritative injectivity check (the jail-name digest is
    /// the first line of defence; this is defence-in-depth).
    const TENANT_PROPERTY: &'static str = "playground:tenant";

    /// Reject pathological tenant labels before they are used to derive a jail
    /// name / dataset. A well-behaved principal (email, uuid, OAuth subject)
    /// always passes; this only stops empties, overlong strings, and labels
    /// carrying control characters (newline / NUL / other C0), which have no
    /// business in an identity and would be hazardous in property values,
    /// argv, or operator output. Called at the entry of `open_session`,
    /// `provision_sandbox`, and `destroy_session`.
    pub fn validate_label(label: &str) -> Result<()> {
        if label.is_empty() {
            bail!("invalid tenant label: empty");
        }
        if label.len() > Self::MAX_LABEL_LEN {
            bail!(
                "invalid tenant label: {} bytes exceeds the {}-byte limit",
                label.len(),
                Self::MAX_LABEL_LEN
            );
        }
        if let Some(c) = label.chars().find(|c| c.is_control()) {
            bail!(
                "invalid tenant label: contains control character U+{:04X}",
                c as u32
            );
        }
        Ok(())
    }

    /// Upper bound on a tenant label's length (bytes). A real principal is well
    /// under this; the cap stops a pathological label from ballooning argv /
    /// property values.
    const MAX_LABEL_LEN: usize = 200;

    fn dataset(&self, jail: &str) -> String {
        format!("{}/{}", self.dataset_parent, jail)
    }

    /// Host directory that holds this coworker's `self.pile` (Model B: owned by
    /// the host, decoupled from the jail dataset — surviving jail teardown). It
    /// is NOT mounted into the jail; only the `self.pile` FILE inside it is.
    fn self_pile_dir(&self, jail: &str) -> String {
        format!("{}/{}", self.pile_root, jail)
    }

    /// Host path of this coworker's `self.pile` FILE — the single-file nullfs
    /// mount SOURCE (mounted onto guest `/pile/self.pile`).
    fn self_pile_file(&self, jail: &str) -> String {
        format!("{}/self.pile", self.self_pile_dir(jail))
    }

    /// Host directory that holds the single `shared.pile` all coworker jails
    /// append to concurrently. It is NOT mounted into any jail; only the
    /// `shared.pile` FILE inside it is (single-file nullfs).
    fn shared_pile_dir(&self) -> String {
        format!("{}/shared", self.pile_root)
    }

    /// Host path of the single shared `shared.pile` FILE — the single-file
    /// nullfs mount SOURCE (mounted onto every jail's guest `/shared/shared.pile`).
    fn shared_pile_file(&self) -> String {
        format!("{}/shared.pile", self.shared_pile_dir())
    }

    /// Host-PRIVATE staging directory (mode 0700, root-owned) where the bootstrap
    /// `cp` writes the pile temp before it is published into place. DERIVED as a
    /// sibling of `pile_root` (`<pile_root>/../staging`) so it stays on the SAME
    /// ZFS filesystem — the publish is a hardlink, which requires same-FS — and
    /// automatically tracks a `--jail-pile-root` override instead of diverging
    /// from it. It is NEVER nullfs-mounted into any jail, so no tenant can
    /// pre-place a symlink at the temp path and trick the privileged `cp` into
    /// following it (the 2026-07-24 symlink confused-deputy class).
    fn staging_root(&self) -> String {
        // Sibling of pile_root: strip the last path component and append
        // `/staging`. `pile_root` is always an absolute path with at least one
        // component (default `/aitemp/playground/piles`), so `rfind('/')`
        // succeeds; a degenerate root falls back to a `.staging` suffix.
        match self.pile_root.rfind('/') {
            Some(i) if i > 0 => format!("{}/staging", &self.pile_root[..i]),
            _ => format!("{}.staging", self.pile_root),
        }
    }

    /// Per-provision staging path inside the host-PRIVATE staging dir. Namespaced
    /// by jail name so two concurrent provisions never collide. This dir is
    /// created 0700 and is NEVER nullfs-mounted into a jail, so no tenant can
    /// pre-place anything at this path.
    fn staging_pile_tmp(&self, jail: &str) -> String {
        format!("{}/{}.pile.tmp", self.staging_root(), jail)
    }

    /// Ensure the host-private staging dir exists and is mode 0700 (root-owned).
    /// Called before any bootstrap `cp`. Mode 0700 is belt-and-suspenders: the
    /// real guarantee is that this dir is never mounted into a jail, so no tenant
    /// process can reach it at all.
    fn ensure_staging_root(&self) -> Result<()> {
        let staging_root = self.staging_root();
        let mkdir = self.run(
            &["sudo", "-n", "mkdir", "-p", &staging_root],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !mkdir.success() {
            bail!("mkdir staging root {staging_root} failed: {}", mkdir.stderr_lossy());
        }
        let chmod = self.run(
            &["sudo", "-n", "chmod", "700", &staging_root],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !chmod.success() {
            bail!("chmod 700 staging root {staging_root} failed: {}", chmod.stderr_lossy());
        }
        Ok(())
    }

    /// Seed a host pile file from `bootstrap_pile`, create-if-absent, with a
    /// tenant-unreachable staging copy and a no-follow / create-only atomic
    /// publish. This is the symlink confused-deputy fix (2026-07-24):
    ///
    ///   1. `cp bootstrap` -> `<staging_root>/<jail>.pile.tmp` (a host-PRIVATE
    ///      0700 dir that is never mounted into any jail, so no tenant can
    ///      pre-place a symlink there and redirect the privileged copy).
    ///   2. Publish with `ln <staging_tmp> <dest>` — a hardlink, which is ATOMIC,
    ///      CREATE-ONLY (fails `EEXIST` if `<dest>` already exists), and NEVER
    ///      follows a symlink at `<dest>` (verified on FreeBSD 15.1: `ln` onto a
    ///      symlink pointing at a victim file fails EEXIST and leaves the victim
    ///      untouched). So the privileged copy can never be tricked into
    ///      overwriting a chosen host file. `staging_root` and the pile dirs share
    ///      one ZFS filesystem, so the hardlink is valid.
    ///   3. `rm -f` the staging temp (on success it is just the second name of
    ///      the now-published inode; on the create-if-absent no-op it is our
    ///      leftover copy).
    ///
    /// On an `ln` failure we distinguish "destination already a regular file"
    /// (the benign create-if-absent no-op: a reprovision kept the accumulated
    /// pile, or a concurrent provision won the publish) from a genuine error
    /// (e.g. destination is a symlink or special file — refuse loudly rather than
    /// mount something a tenant may have planted).
    fn stage_and_publish_pile(&self, jail: &str, dest: &str) -> Result<()> {
        self.ensure_staging_root()?;
        let staging_tmp = self.staging_pile_tmp(jail);
        // Fresh staging copy every time (clobber any stale leftover in the
        // private dir): `cp` into the host-private path, never near the dest.
        let cp = self.run(
            &["sudo", "-n", "cp", &self.bootstrap_pile, &staging_tmp],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !cp.success() {
            bail!(
                "stage bootstrap -> {staging_tmp} failed: {}",
                cp.stderr_lossy()
            );
        }
        // Atomic create-only, no-follow publish via hardlink.
        let link = self.run(
            &["sudo", "-n", "ln", &staging_tmp, dest],
            None,
            ADMIN_TIMEOUT,
        )?;
        // Clean up the staging temp regardless: on success it is a redundant
        // second name for the published inode; on a no-op it is our leftover.
        let _ = self.run(&["sudo", "-n", "rm", "-f", &staging_tmp], None, ADMIN_TIMEOUT);
        if !link.success() {
            // `ln` failed. The ONLY acceptable reason is "destination already
            // exists as a regular, non-symlink file" — the create-if-absent
            // no-op. Verify that with a no-follow test; anything else (symlink,
            // special file, or a real link error) is refused loudly.
            self.assert_regular_nonsymlink(dest).with_context(|| {
                format!(
                    "publish pile -> {dest} failed and destination is not a safe \
                     regular file: {}",
                    link.stderr_lossy()
                )
            })?;
        }
        Ok(())
    }

    /// Verify `path` exists as a REGULAR, NON-SYMLINK file, `bail!`-ing otherwise.
    /// Uses `test -f` (regular file) AND `test ! -L` (not a symlink); `test -f`
    /// follows symlinks, so the explicit `! -L` closes the "symlink -> regular
    /// file" case. This gates the create-if-absent no-op: we only tolerate a
    /// failed publish when the destination is a genuine regular file, never a
    /// tenant-planted symlink or special file.
    fn assert_regular_nonsymlink(&self, path: &str) -> Result<()> {
        let out = self.run(
            &[
                "sudo", "-n", "sh", "-c",
                "test -f \"$1\" && test ! -L \"$1\"", "sh", path,
            ],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!("{path} is not a regular non-symlink file (refusing)");
        }
        Ok(())
    }

    /// Guest mount TARGET (absolute path under the jail root) for the per-coworker
    /// self.pile FILE. The host `self.pile` file is single-file-nullfs-mounted
    /// directly onto this path, so `PILE=/pile/self.pile` resolves to the mounted
    /// file. `/pile` itself is the jail's OWN clone directory (not a host mount),
    /// so a tenant creating siblings there only dirties the throwaway clone.
    const GUEST_SELF_PILE: &'static str = "/pile/self.pile";
    /// Guest mount TARGET for the shared.pile FILE. The single host `shared.pile`
    /// is single-file-nullfs-mounted directly onto this path. `/shared` is the
    /// jail's OWN clone directory — never a writable host directory.
    const GUEST_SHARED_PILE: &'static str = "/shared/shared.pile";

    /// The nullfs filesystem type — the one `(fstype)` a pile mount is ever
    /// allowed to be. Used to validate the exact `(source, target, fstype)`
    /// tuple before trusting a reused mount (never a devfs/procfs/zfs shadowing
    /// the pile target).
    const PILE_FSTYPE: &'static str = "nullfs";

    /// True iff a `mount(8)` listing already shows EXACTLY the intended mount:
    /// `<host_file> on <target> (nullfs, …)`. Parses each line in the FreeBSD
    /// shape `"<src> on <TARGET> (<fstype>, <opts>)"` and requires all three of
    /// source, whole-token target, and fstype to match — so a DIFFERENT source
    /// mounted at `target` (a tenant-planted redirection), or a non-nullfs
    /// filesystem, is NOT accepted as our mount. This is the exact-mount
    /// validation the reattach path needs before it trusts a reused jail's pile
    /// mount instead of blindly starting the jail.
    fn mount_listing_has_exact(listing: &str, host_file: &str, target: &str) -> bool {
        listing.lines().any(|line| {
            // Split on the literal " on " that FreeBSD `mount` prints between
            // source and target. rsplit-once would misparse a source containing
            // " on ", but our sources are pile paths, so split_once is safe and
            // simplest; guard the source match to the exact prefix anyway.
            let Some((src, rest)) = line.split_once(" on ") else {
                return false;
            };
            if src.trim() != host_file {
                return false;
            }
            // `rest` is "<TARGET> (<fstype>, <opts>)". The target is everything
            // up to the " (" that opens the fstype group; take it as a whole so
            // `/pile/self.pile` never matches a substring of another path.
            let Some((tgt, tail)) = rest.split_once(" (") else {
                return false;
            };
            tgt.trim() == target
                && tail
                    .split([',', ')'])
                    .next()
                    .map(|fs| fs.trim() == Self::PILE_FSTYPE)
                    .unwrap_or(false)
        })
    }

    /// Read the current `mount(8)` listing, failing CLOSED if the command itself
    /// failed (we must never proceed on an unreadable mount table — a silently
    /// empty listing would let a missing mount pass as "already correct").
    fn mount_listing(&self) -> Result<String> {
        let out = self.run(&["sudo", "-n", "mount"], None, ADMIN_TIMEOUT)?;
        if !out.success() {
            bail!("`mount` failed: {}", out.stderr_lossy());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// THE ONE shared, FAIL-CLOSED single-file pile mount primitive, used by BOTH
    /// fresh provision AND reattach (so reattach is no longer the weak path).
    ///
    /// Single-file-nullfs-mounts `host_file` rw onto `<root><guest_file>` and
    /// GUARANTEES, on success, that the exact intended mount
    /// `(source=host_file, target, fstype=nullfs)` is live. It handles the two
    /// legitimate entry states uniformly and refuses every dangerous one:
    ///
    ///   1. **Already correctly mounted** (the reattach EBUSY no-op case): a
    ///      re-mount of the same source at the same live target FAILS with EBUSY
    ///      on FreeBSD 15.1 and does NOT stack. Rather than ignore the mount
    ///      status (the old weak reattach path), we VALIDATE the pre-existing
    ///      mount is EXACTLY ours first; if so, this is a verified no-op.
    ///   2. **Not yet mounted** (fresh provision, or the mount went away across a
    ///      restart): ensure the target file exists, mount, then re-read the
    ///      table and CONFIRM the exact `(source, target, nullfs)` tuple is now
    ///      present.
    ///
    /// Fail closed on: an unreadable mount table; a target already occupied by a
    /// DIFFERENT source or a non-nullfs filesystem (a tenant-controlled
    /// mountpoint redirection — do NOT start/keep a jail whose pile target is
    /// something we did not put there); a mount that reports success but does not
    /// appear in the table; a failed mkdir/touch of the target. In every failure
    /// the caller `bail!`s rather than booting a jail with a missing or
    /// redirected `PILE`. `mkdir`/`touch` of the guest target traverse the jail's
    /// OWN clone dir (never a host dir); the exact-tuple check is what makes the
    /// mount itself trustworthy.
    fn ensure_pile_mount(&self, host_file: &str, root: &str, guest_file: &str) -> Result<()> {
        let target = format!("{root}{guest_file}");

        // If the target is ALREADY mounted, it must be EXACTLY our mount — same
        // source, same target, nullfs. A different source or fstype at this path
        // is a redirection we refuse to trust (blocker #3: a tenant-controlled
        // underlying mountpoint must never become a silently-accepted PILE).
        let listing = self.mount_listing()?;
        if listing
            .lines()
            .any(|line| Self::line_target_is(line, &target))
        {
            if Self::mount_listing_has_exact(&listing, host_file, &target) {
                // Reattach no-op: the pre-existing mount is precisely ours.
                return Ok(());
            }
            bail!(
                "refusing to reuse jail: pile target {target} is already mounted by \
                 something other than {host_file} (nullfs) — possible mount redirection"
            );
        }

        // Not mounted yet: ensure the guest target FILE exists (inside the jail's
        // own clone), then mount.
        let parent = match target.rfind('/') {
            Some(i) => &target[..i],
            None => target.as_str(),
        };
        let mkdir = self.run(&["sudo", "-n", "mkdir", "-p", parent], None, ADMIN_TIMEOUT)?;
        if !mkdir.success() {
            bail!("mkdir guest mount parent {parent} failed: {}", mkdir.stderr_lossy());
        }
        let touch = self.run(&["sudo", "-n", "touch", &target], None, ADMIN_TIMEOUT)?;
        if !touch.success() {
            bail!("touch guest mount target {target} failed: {}", touch.stderr_lossy());
        }
        let mount = self.run(
            &["sudo", "-n", "mount", "-t", "nullfs", host_file, &target],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !mount.success() {
            bail!("nullfs mount {host_file} -> {target} failed: {}", mount.stderr_lossy());
        }
        // Post-condition: re-read the table and confirm the EXACT tuple is live.
        // A silently-failed mount (exit 0, nothing mounted) would leave the guest
        // pile on the EMPTY clone file, silently redirecting PILE to throwaway
        // scratch that `destroy_session` later `zfs destroy`s (data loss).
        let after = self.mount_listing()?;
        if !Self::mount_listing_has_exact(&after, host_file, &target) {
            bail!(
                "nullfs mount {host_file} -> {target} did not take exactly \
                 (not present as ({host_file}, {target}, nullfs) in `mount` output)"
            );
        }
        Ok(())
    }

    /// Whether a `mount` line's TARGET token equals `target` (whole-token, so
    /// `/pile/self.pile` never matches a longer path). Shared by the
    /// already-mounted probe and the exact-tuple check.
    fn line_target_is(line: &str, target: &str) -> bool {
        line.split_once(" on ")
            .and_then(|(_, rest)| rest.split_once(" ("))
            .map(|(tgt, _)| tgt.trim() == target)
            .unwrap_or(false)
    }

    /// Re-establish BOTH single-file pile mounts (self + shared) over a jail
    /// root, FAIL-CLOSED, via the one shared [`JailBackend::ensure_pile_mount`]
    /// primitive. Used by BOTH fresh provision and reattach: a failure `bail!`s
    /// so no jail is ever started or kept with a missing/redirected pile mount.
    fn mount_piles(&self, jail: &str, root: &str) -> Result<()> {
        self.ensure_pile_mount(&self.self_pile_file(jail), root, Self::GUEST_SELF_PILE)?;
        self.ensure_pile_mount(&self.shared_pile_file(), root, Self::GUEST_SHARED_PILE)?;
        Ok(())
    }

    /// Public liveness probe for the `user list` CLI: true iff the tenant's jail
    /// context is currently running. Sanitises the label the same way
    /// [`JailBackend::jail_name`] does, so the CLI and backend agree.
    pub fn jail_running_for_label(&self, label: &str) -> bool {
        self.jail_running(&self.jail_name(label))
    }

    fn run(&self, argv: &[&str], stdin: Option<&[u8]>, timeout: Duration) -> Result<HostOutput> {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        self.runner.run(&argv, stdin, timeout)
    }

    /// `run` for a TENANT command: caps each output stream at `max_output_bytes`
    /// and kills the transported child on breach (see
    /// [`HostRunner::run_capped`]). Used only by `exec`, never by the admin
    /// commands (whose output is bounded by construction).
    fn run_capped(
        &self,
        argv: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<HostOutput> {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        self.runner.run_capped(&argv, stdin, timeout, max_output_bytes)
    }

    /// Record the ORIGINAL tenant label on a freshly-cloned dataset as a ZFS
    /// user property (`zfs set playground:tenant=<label> <dataset>`, argv form —
    /// no shell). This is the provenance the reuse/reattach arms verify against.
    fn set_tenant_property(&self, dataset: &str, label: &str) -> Result<()> {
        let assignment = format!("{}={}", Self::TENANT_PROPERTY, label);
        let out = self.run(
            &["sudo", "-n", "zfs", "set", &assignment, dataset],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!(
                "zfs set {} on {dataset} failed: {}",
                Self::TENANT_PROPERTY,
                out.stderr_lossy()
            );
        }
        Ok(())
    }

    /// Set the ZFS `refquota` on a freshly-cloned per-tenant dataset (repair #4
    /// storage bound), if one is configured. `refquota` bounds the dataset's OWN
    /// referenced data (not snapshots/descendants), so a tenant cannot fill the
    /// host pool through its clone's writes — the empty pile target files, any
    /// scratch under `/workspace`, /tmp, logs, etc. A `None` or empty/`"0"`
    /// setting disables it (leaving pool-level quota to the operator). Idempotent
    /// (re-setting the same value is a no-op), so it is safe on a converge path.
    fn set_clone_refquota(&self, dataset: &str) -> Result<()> {
        let Some(refquota) = self.clone_refquota.as_deref() else {
            return Ok(());
        };
        if refquota.is_empty() || refquota == "0" || refquota == "none" {
            return Ok(());
        }
        let assignment = format!("refquota={refquota}");
        let out = self.run(
            &["sudo", "-n", "zfs", "set", &assignment, dataset],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!(
                "zfs set refquota={refquota} on {dataset} failed: {}",
                out.stderr_lossy()
            );
        }
        Ok(())
    }

    /// Ensure a global ZFS `quota` is set on the pile-root DATASET so all
    /// tenants' pile writes together cannot fill the host pool (repair #4). The
    /// pile files live under `pile_root` (a host path); we resolve which ZFS
    /// dataset that path belongs to and, if it IS a dataset mountpoint, set the
    /// quota. Best-effort + idempotent (safe to run on every provision): if
    /// `pile_root` is a plain directory inside some larger dataset we do NOT
    /// touch that dataset (setting a quota on an unrelated shared dataset would
    /// be wrong), we just log — the operator sets a pile-root dataset up for the
    /// bound to bite. A `None`/empty/`"0"` config disables it entirely.
    fn ensure_pile_root_quota(&self) {
        let Some(quota) = self.pile_root_quota.as_deref() else {
            return;
        };
        if quota.is_empty() || quota == "0" || quota == "none" {
            return;
        }
        // `zfs list -H -o name <path>` prints the dataset a path lives in; if the
        // path is exactly a dataset mountpoint we get that dataset. We only set
        // the quota when the path's dataset mountpoint IS the pile root, so we
        // never clamp an unrelated ancestor dataset.
        let name = self.run(
            &["sudo", "-n", "zfs", "list", "-H", "-o", "name", &self.pile_root],
            None,
            ADMIN_TIMEOUT,
        );
        let dataset = match name {
            Ok(out) if out.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            _ => {
                eprintln!(
                    "[{}] pile-root '{}' is not a ZFS dataset mountpoint; skipping the global \
                     pile quota (set up a dataset at the pile root to enforce it)",
                    self.name(),
                    self.pile_root
                );
                return;
            }
        };
        let assignment = format!("quota={quota}");
        match self.run(
            &["sudo", "-n", "zfs", "set", &assignment, &dataset],
            None,
            ADMIN_TIMEOUT,
        ) {
            Ok(out) if out.success() => {}
            Ok(out) => eprintln!(
                "[{}] zfs set quota={quota} on pile-root dataset {dataset} failed: {} \
                 (continuing; the per-clone refquota still bounds each tenant)",
                self.name(),
                out.stderr_lossy()
            ),
            Err(e) => eprintln!(
                "[{}] zfs set quota on pile-root dataset {dataset} errored: {e:#} (continuing)",
                self.name()
            ),
        }
    }

    /// Is host RACCT/RCTL enabled? Probes `sysctl -n kern.racct.enable`; a value
    /// of `1` means `rctl(8)` rules can be set. Any failure (sysctl missing,
    /// transport error) is read conservatively as DISABLED, so we never try to
    /// set a rule that would error. Cheap and side-effect-free.
    fn racct_enabled(&self) -> bool {
        match self.run(&["sysctl", "-n", "kern.racct.enable"], None, ADMIN_TIMEOUT) {
            Ok(out) if out.success() => {
                String::from_utf8_lossy(&out.stdout).trim() == "1"
            }
            _ => false,
        }
    }

    /// Apply the configured per-jail `rctl(8)` rules IF host RACCT is enabled.
    /// This is the guarded programmatic path the review asks for: on the current
    /// RACCT-off deploy box `racct_enabled()` returns false and this is a no-op
    /// (with a one-line operator hint); once the operator sets
    /// `kern.racct.enable=1` the same rules clamp per-jail resource pressure with
    /// no code change. Best-effort per rule: a rule that fails to apply is logged
    /// and the rest proceed (partial limits beat none). Called AFTER `jail -c`,
    /// since a `jail:<name>:...` rule needs the jail to exist.
    fn apply_rctl_rules(&self, jail: &str) {
        if self.rctl_rules.is_empty() {
            return;
        }
        if !self.racct_enabled() {
            eprintln!(
                "[{}] host RACCT is disabled (kern.racct.enable=0); skipping per-jail rctl \
                 limits for '{jail}'. Enable RACCT + reprovision to clamp CPU/RAM/maxproc/FDs \
                 (see deploy/freebsd/README.md).",
                self.name()
            );
            return;
        }
        for tail in &self.rctl_rules {
            let rule = format!("jail:{jail}:{tail}");
            match self.run(&["sudo", "-n", "rctl", "-a", &rule], None, ADMIN_TIMEOUT) {
                Ok(out) if out.success() => {}
                Ok(out) => eprintln!(
                    "[{}] rctl -a {rule} failed: {} (continuing with remaining rules)",
                    self.name(),
                    out.stderr_lossy()
                ),
                Err(e) => eprintln!(
                    "[{}] rctl -a {rule} errored: {e:#} (continuing)",
                    self.name()
                ),
            }
        }
    }

    /// Read back the recorded tenant label and VERIFY it equals `expected`. A
    /// mismatch means a digest collision or tampering — the caller must refuse
    /// to hand this box to the requester. This makes tenant identity
    /// authoritative even if the jail-name digest ever collided.
    fn verify_tenant_property(&self, dataset: &str, expected: &str) -> Result<()> {
        let out = self.run(
            &["sudo", "-n", "zfs", "get", "-H", "-o", "value", Self::TENANT_PROPERTY, dataset],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!(
                "zfs get {} on {dataset} failed: {}",
                Self::TENANT_PROPERTY,
                out.stderr_lossy()
            );
        }
        let stored = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if stored != expected {
            bail!(
                "tenant mismatch on {dataset}: stored '{stored}' != requested '{expected}' \
                 (hash collision or tampering — refusing)"
            );
        }
        Ok(())
    }

    /// `zfs get -H -o value mountpoint <dataset>` — the jail root path.
    fn mountpoint(&self, dataset: &str) -> Result<String> {
        let out = self.run(
            &["zfs", "get", "-H", "-o", "value", "mountpoint", dataset],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!("zfs get mountpoint {dataset} failed: {}", out.stderr_lossy());
        }
        let mp = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !mp.starts_with('/') {
            bail!("dataset {dataset} has no usable mountpoint (got '{mp}')");
        }
        Ok(mp)
    }

    /// Best-effort teardown of any leftovers from a previous session with the
    /// same name (mirrors Lima's stale-instance delete before start). Errors
    /// are ignored: on a clean host every step is a no-op failure.
    fn cleanup_leftovers(&self, jail: &str) {
        let dataset = self.dataset(jail);
        let _ = self.run(&["sudo", "-n", "jail", "-r", jail], None, ADMIN_TIMEOUT);
        if let Ok(mp) = self.mountpoint(&dataset) {
            // Unmount everything mounted under the (possibly half-made) clone —
            // the two single-file pile mounts plus devfs — so the zfs destroy
            // below is not blocked. Host pile files themselves are never removed.
            for guest in [Self::GUEST_SELF_PILE, Self::GUEST_SHARED_PILE, "/dev"] {
                let _ = self.run(
                    &["sudo", "-n", "umount", "-f", &format!("{mp}{guest}")],
                    None,
                    ADMIN_TIMEOUT,
                );
            }
        }
        let _ = self.run(&["sudo", "-n", "zfs", "destroy", &dataset], None, ADMIN_TIMEOUT);
    }

    /// True iff a jail with this name currently exists (a running jail context).
    /// `jls -j <name>` exits 0 when the jail is present, non-zero otherwise.
    /// Prefixed with `sudo -n` to match the file's privileged-command pattern
    /// and stay robust to hosts that restrict `jls` to root.
    fn jail_running(&self, jail: &str) -> bool {
        self.run(&["sudo", "-n", "jls", "-j", jail], None, ADMIN_TIMEOUT)
            .map(|o| o.success())
            .unwrap_or(false)
    }

    /// TRI-STATE, error-preserving probe for a ZFS dataset (see
    /// [`DatasetState`]). `zfs list <dataset>` exits 0 when the dataset is
    /// present; on absence it exits non-zero with a stderr that includes the
    /// canonical `dataset does not exist` phrase. We classify:
    ///
    ///   - runner `Err`, a local timeout, or the runner's transport-error exit
    ///     (ssh 255) -> [`DatasetState::Unknown`] (we never reached / trusted
    ///     the answer);
    ///   - exit 0 -> [`DatasetState::Exists`];
    ///   - a non-zero exit whose stderr contains the not-found phrase ->
    ///     [`DatasetState::Absent`];
    ///   - ANY OTHER non-zero exit (permission denied, faulted pool, an
    ///     unexpected message) -> [`DatasetState::Unknown`].
    ///
    /// Callers must NEVER run destructive cleanup on `Unknown`: on doubt, fail
    /// closed and destroy nothing. This is the primary fix for the blocker-#3
    /// data-loss class where a transient SSH failure looked identical to a real
    /// absence and triggered a `zfs destroy` of a valid workspace.
    fn dataset_state(&self, dataset: &str) -> DatasetState {
        let out = match self.run(&["sudo", "-n", "zfs", "list", dataset], None, ADMIN_TIMEOUT) {
            Ok(out) => out,
            // The command never produced a trustworthy status (spawn failed,
            // pipe error, ...). We do not know — fail closed.
            Err(_) => return DatasetState::Unknown,
        };
        if out.success() {
            return DatasetState::Exists;
        }
        // A local wall-clock kill or the transport's own error exit (ssh 255)
        // means we never got ZFS's real answer — Unknown, not Absent.
        if out.timed_out || (out.exit_code.is_some() && out.exit_code == self.runner.transport_error_exit())
        {
            return DatasetState::Unknown;
        }
        // Non-zero from ZFS itself: only the canonical not-found stderr proves a
        // genuine absence. Anything else (permission, faulted pool, an
        // unexpected error) is Unknown — we refuse to treat it as "free to
        // clone into / safe to destroy".
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("does not exist") {
            DatasetState::Absent
        } else {
            DatasetState::Unknown
        }
    }

    /// Re-establish a jail context over an EXISTING persistent dataset: the
    /// ephemeral devfs mount (does not survive a reboot) plus the two pile mounts
    /// plus `jail -c`. The dataset and its `/etc/profile` are left exactly as
    /// they are — this clones nothing and re-seeds nothing. Shared by
    /// `open_session`'s reattach arm, `provision_sandbox`'s already-provisioned
    /// arm, and `reattach_all`.
    ///
    /// FAIL-CLOSED (blocker #3): reattach used to ignore devfs / nullfs mount
    /// failures and start the jail anyway, silently redirecting `PILE` to
    /// clone-local scratch and, worse, letting a tenant-controlled underlying
    /// mountpoint become a later host-root mount redirection. Now BOTH pile
    /// mounts go through the one shared [`JailBackend::ensure_pile_mount`]
    /// primitive (exact `(source, target, nullfs)` validation, so a redirected
    /// or missing pile target aborts the reattach) AND we VERIFY devfs took —
    /// establishing every mount BEFORE `jail -c`, so a jail is never started with
    /// a missing or redirected mount. Fresh provision and reattach share this one
    /// primitive; reattach is no longer the weak path.
    fn reattach(&self, jail: &str, dataset: &str) -> Result<()> {
        let root = self.mountpoint(dataset)?;
        // devfs: re-mount and VERIFY it is live. A re-mount over a still-live
        // devfs fails "already mounted", so we do not gate on the mount's own
        // exit; instead we confirm `{root}/dev` is a devfs mount in the table
        // afterward (covers both the fresh mount and the already-mounted no-op),
        // and fail closed if it is absent — a jail with a broken /dev must not
        // start.
        let dev_target = format!("{root}/dev");
        let _ = self.run(
            &[
                "sudo", "-n", "mount", "-t", "devfs", "-o", "ruleset=4", "devfs",
                &dev_target,
            ],
            None,
            ADMIN_TIMEOUT,
        );
        let listing = self.mount_listing()?;
        let devfs_live = listing.lines().any(|line| {
            Self::line_target_is(line, &dev_target)
                && line
                    .split_once(" (")
                    .and_then(|(_, tail)| tail.split([',', ')']).next())
                    .map(|fs| fs.trim() == "devfs")
                    .unwrap_or(false)
        });
        if !devfs_live {
            bail!("reattach {jail}: devfs not mounted at {dev_target} (refusing to start jail)");
        }
        // Pile mounts do not survive a jail restart either — re-establish both,
        // FAIL-CLOSED (exact-tuple validated). A failure aborts before `jail -c`.
        self.mount_piles(jail, &root)?;
        let created = self.run(
            &[
                "sudo",
                "-n",
                "jail",
                "-c",
                &format!("name={jail}"),
                &format!("path={root}"),
                &format!("host.hostname={jail}"),
                "persist",
                "ip4=disable",
                "ip6=disable",
            ],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !created.success() {
            bail!("jail -c {jail} failed: {}", created.stderr_lossy());
        }
        Ok(())
    }
}

impl SandboxBackend for JailBackend {
    fn name(&self) -> &'static str {
        "jail"
    }

    /// The canonical key IS the injective jail name (repair #1): the provider's
    /// per-tenant lock and this backend's own lifecycle lock therefore agree on
    /// one key per physical box, including for two labels that alias to one jail.
    fn canonical_key(&self, tenant: &crate::sandbox::Tenant) -> String {
        self.jail_name(&tenant.label)
    }

    fn open_session(&self, spec: &SessionSpec) -> Result<SessionId> {
        Self::validate_label(&spec.tenant.label)?;
        let jail = self.jail_name(&spec.tenant.label);
        let dataset = self.dataset(&jail);
        eprintln!(
            "[{}] opening session for tenant '{}' -> jail '{}' (dataset {})",
            self.name(),
            spec.tenant.label,
            jail,
            dataset
        );
        // This backend does not use the caller-supplied `spec.tenant.pile`
        // path: the session operates on its own server-born pile, provisioned
        // under `pile_root` and mounted at /pile/self.pile by provision_sandbox.
        eprintln!(
            "[{}] session operates on its server-born pile under pile_root \
             (caller pile_host_path '{}' is not used by this backend)",
            self.name(),
            spec.tenant.pile.host_path.display()
        );

        // Serialize the whole reuse/reattach decision under the per-canonical-
        // tenant lifecycle lock (blocker #3): a concurrent provision/destroy of
        // the SAME box cannot interleave with this open.
        self.lifecycle.with_lock(&jail, || {
            // Pure reuse-or-reattach: the box must already be provisioned (via
            // `provision_sandbox` / `playground user create`). open NEVER clones.

            // 1. Already up? The tenant's jail context is running over its
            //    dataset; just hand back the same id — no `jail -c`, no re-seed.
            //    First VERIFY the dataset's recorded tenant matches the requester
            //    (authoritative injectivity check): a mismatch means a digest
            //    collision or tampering, and we refuse rather than hand over
            //    another tenant's box.
            if self.jail_running(&jail) {
                self.verify_tenant_property(&dataset, &spec.tenant.label)
                    .with_context(|| format!("verify tenant provenance for jail '{jail}'"))?;
                eprintln!("[{}] reusing persistent sandbox '{}'", self.name(), jail);
                return Ok(SessionId::new(jail.clone()));
            }

            // 2. Not running: probe the persistent dataset with a TRI-STATE,
            //    error-preserving check so a transient failure never masquerades
            //    as absence. `open_session` never destroys anything, but it must
            //    still distinguish a genuine "not provisioned" (Absent) from "the
            //    probe could not tell" (Unknown) so it fails CLOSED on doubt
            //    rather than emitting a misleading "run `playground user create`".
            match self.dataset_state(&dataset) {
                // The persistent dataset exists (host reboot / playground restart
                // wiped the jail context). Re-attach it: devfs + pile re-mount +
                // `jail -c`, keeping the dataset and its /etc/profile as they are.
                // Never destroy the dataset — it is the tenant's PERSISTENT
                // storage. VERIFY the recorded tenant first, same as the reuse arm.
                DatasetState::Exists => {
                    self.verify_tenant_property(&dataset, &spec.tenant.label)
                        .with_context(|| format!("verify tenant provenance for jail '{jail}'"))?;
                    eprintln!("[{}] reattaching persistent sandbox '{}'", self.name(), jail);
                    self.reattach(&jail, &dataset)
                        .with_context(|| format!("reattach jail '{jail}'"))?;
                    Ok(SessionId::new(jail.clone()))
                }
                // 3. No dataset at all: the tenant was never provisioned.
                DatasetState::Absent => bail!(
                    "sandbox for tenant '{}' is not provisioned — run `playground user create {}`",
                    spec.tenant.label,
                    spec.tenant.label
                ),
                // The probe failed for a reason that is NOT a clean absence
                // (transport error, timeout, permission, faulted pool). Fail
                // closed: do not reattach a box we cannot confirm and do not claim
                // it is unprovisioned.
                DatasetState::Unknown => bail!(
                    "cannot determine sandbox state for tenant '{}' (dataset {} probe was \
                     inconclusive — transport/permission/timeout); refusing to act",
                    spec.tenant.label,
                    dataset
                ),
            }
        })
    }

    fn provision_sandbox(&self, spec: &SessionSpec) -> Result<()> {
        Self::validate_label(&spec.tenant.label)?;
        let jail = self.jail_name(&spec.tenant.label);
        let dataset = self.dataset(&jail);

        // Serialize the entire create/converge under the per-canonical-tenant
        // lifecycle lock (blocker #3): a concurrent provision/open/destroy of the
        // SAME box cannot interleave with this one. Combined with the tri-state
        // probe + operation-owned cleanup below, a concurrent create can neither
        // clone-over nor destroy a valid dataset.
        self.lifecycle.with_lock(&jail, || {
        // Idempotent: a tenant whose dataset already exists is already
        // provisioned. Don't clone or re-seed; just ensure the jail is up so
        // `provision` doubles as "converge to running" (reattach if the jail
        // context is gone). VERIFY the recorded tenant first (authoritative
        // injectivity check), same as `open_session`'s reuse arms.
        //
        // TRI-STATE probe: we only proceed to CLONE on a definite `Absent`. An
        // `Unknown` (transport/permission/timeout) must NOT fall through to the
        // clone path — a clone into a name whose real state is unknown, followed
        // by a failure, is exactly the situation that used to `zfs destroy` a
        // valid dataset. Fail closed instead.
        match self.dataset_state(&dataset) {
            DatasetState::Exists => {
                self.verify_tenant_property(&dataset, &spec.tenant.label)
                    .with_context(|| format!("verify tenant provenance for jail '{jail}'"))?;
                eprintln!(
                    "[{}] sandbox '{}' already provisioned; ensuring it is up",
                    self.name(),
                    jail
                );
                if !self.jail_running(&jail) {
                    self.reattach(&jail, &dataset)
                        .with_context(|| format!("reattach existing jail '{jail}'"))?;
                }
                return Ok(());
            }
            DatasetState::Unknown => bail!(
                "cannot determine sandbox state for tenant '{}' (dataset {} probe was \
                 inconclusive — transport/permission/timeout); refusing to provision \
                 (would risk cloning over or destroying an existing workspace)",
                spec.tenant.label,
                dataset
            ),
            // Definitely absent: safe to clone a fresh box below.
            DatasetState::Absent => {}
        }

        eprintln!(
            "[{}] provisioning new persistent sandbox '{}' (dataset {})",
            self.name(),
            jail,
            dataset
        );

        // OPERATION-OWNED CLEANUP: a failed provision may only tear down what
        // THIS operation created. `created_clone` flips true the instant our own
        // `zfs clone` succeeds; on failure we only `zfs destroy` when it is set,
        // so a provision that fails BEFORE (or AT) the clone never destroys a
        // dataset it did not make. This closes the concurrent-create data-loss
        // race: even if two provisions somehow both proceed past the tri-state
        // probe, the loser's `zfs clone` fails EEXIST (it did not create the
        // dataset), `created_clone` stays false, and the winner's valid dataset
        // is left untouched.
        let mut created_clone = false;

        // Brand-new tenant: clone the template, then set up /dev, cwd, and
        // /etc/profile from scratch, then `jail -c`.
        let provision = (|created_clone: &mut bool| -> Result<()> {
            let clone = self.run(
                &["sudo", "-n", "zfs", "clone", &self.template_snapshot, &dataset],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !clone.success() {
                bail!(
                    "zfs clone {} -> {dataset} failed: {}",
                    self.template_snapshot,
                    clone.stderr_lossy()
                );
            }
            // Our clone succeeded: from here on, teardown of THIS dataset is
            // ours to do on failure (and only ours).
            *created_clone = true;

            // Record the ORIGINAL tenant label on the dataset immediately after
            // the clone: this is the authoritative provenance the reuse/reattach
            // arms verify against (defence-in-depth over the jail-name digest).
            self.set_tenant_property(&dataset, &spec.tenant.label)?;

            // STORAGE BOUND (repair #4): cap the tenant clone's referenced data
            // with a ZFS refquota so it cannot fill the host pool. Set right
            // after the clone, before the jail is even started, so the bound is
            // live for every byte the tenant ever writes into its dataset.
            self.set_clone_refquota(&dataset)
                .with_context(|| format!("set refquota on clone {dataset}"))?;

            let root = self.mountpoint(&dataset)?;

            // devfs, mounted manually (not via jail(8) params) so lifecycle
            // stays explicit and destroy_session can unmount symmetrically.
            // Ruleset 4 = devfsrules_jail: the standard, minimal jail /dev.
            let devfs = self.run(
                &[
                    "sudo", "-n", "mount", "-t", "devfs", "-o", "ruleset=4", "devfs",
                    &format!("{root}/dev"),
                ],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !devfs.success() {
                bail!("mount devfs failed: {}", devfs.stderr_lossy());
            }

            // The session workdir (guest path), default /workspace.
            let cwd = spec
                .cwd
                .as_deref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "/workspace".to_string());
            let mkdir = self.run(
                &["sudo", "-n", "mkdir", "-p", &format!("{root}{cwd}")],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !mkdir.success() {
                bail!("mkdir session cwd failed: {}", mkdir.stderr_lossy());
            }

            // Model-B pile provisioning: two HOST-OWNED pile FILES single-file-
            // mounted into the jail, decoupled from the dataset lifecycle.
            //
            //   host <pile_root>/<jail>/self.pile  -> nullfs rw -> guest /pile/self.pile
            //   host <pile_root>/shared/shared.pile -> nullfs rw -> guest /shared/shared.pile
            //
            // These live OUTSIDE the ZFS clone tree, so destroy_session (which
            // destroys the dataset) never touches them. The `self.pile` is the
            // tenant's server-born pile under `pile_root`, distinct from the
            // caller-supplied `spec.tenant.pile` path (not used by this backend).
            //
            // SYMLINK CONFUSED-DEPUTY FIX (2026-07-24): the bootstrap `cp` NEVER
            // writes to a tenant-reachable path. Every seed is `cp`'d into a
            // host-PRIVATE 0700 staging dir (`staging_root`, never mounted into a
            // jail) and then PUBLISHED into place with a no-follow / create-only
            // rename that refuses to overwrite through an existing entry or a
            // symlink (`stage_and_publish_pile`). Even if the destination dir were
            // somehow tenant-writable, a pre-placed symlink at the destination
            // cannot redirect the privileged copy onto a chosen host file.
            let self_dir = self.self_pile_dir(&jail);
            let self_pile = self.self_pile_file(&jail);
            let shared_dir = self.shared_pile_dir();
            let shared_pile = self.shared_pile_file();

            // Per-coworker pile dir + seed self.pile from bootstrap if absent.
            let mkdir_self = self.run(
                &["sudo", "-n", "mkdir", "-p", &self_dir],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !mkdir_self.success() {
                bail!("mkdir self pile dir failed: {}", mkdir_self.stderr_lossy());
            }
            // Seed self.pile create-if-absent via host-private staging + a
            // no-follow / create-only publish (see `stage_and_publish_pile`): a
            // reprovision keeps the coworker's accumulated pile, and the
            // privileged copy never follows a symlink at the destination.
            self.stage_and_publish_pile(&jail, &self_pile)
                .context("seed self.pile from bootstrap")?;
            // Make the host self.pile APPEND-ONLY (`chflags sappnd`): a process
            // inside the jail can O_APPEND but not O_TRUNC/unlink/rename it, so a
            // buggy or stale tool cannot truncate the pile (the 2026-07-03
            // truncation incident class). Idempotent — sappnd on an already-flagged
            // file is a no-op — and only set on first provision (reattach skips
            // the seed). NOTE: at the current `securelevel=-1` this blocks
            // ACCIDENTAL truncation; deliberate truncation by a jail-root would
            // still need `securelevel>=1` (then the same flag becomes malicious-
            // proof with no code change). A rare crash-torn tail is repaired
            // host-side: `chflags nosappnd` -> amputate -> re-flag.
            let protect_self = self.run(
                &["sudo", "-n", "chflags", "sappnd", &self_pile],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !protect_self.success() {
                bail!("chflags sappnd self.pile failed: {}", protect_self.stderr_lossy());
            }

            // Shared pile dir + shared.pile: a SINGLE file shared by ALL jails.
            // Create-if-absent and race-safe against concurrent provisions — and
            // the seed must be ATOMIC (a coworker must never mount a partial
            // shared.pile). `stage_and_publish_pile` copies bootstrap into the
            // host-private staging dir, then publishes with a no-follow /
            // create-only rename: the winner installs a complete file in one
            // atomic rename; a loser no-ops on the existing target. No reader ever
            // observes a partial file, and no tenant-reachable path is ever
            // written through. (`mkdir -p` stays idempotent; same append-only
            // semantics as self.pile — many concurrent appenders on one pile file
            // is fine, verified on FreeBSD 15.1.)
            let mkdir_shared = self.run(
                &["sudo", "-n", "mkdir", "-p", &shared_dir],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !mkdir_shared.success() {
                bail!("mkdir shared pile dir failed: {}", mkdir_shared.stderr_lossy());
            }
            // STORAGE BOUND (repair #4): ensure the global pile-storage quota is
            // set on the pile-root dataset so no tenant can fill the pool via
            // pile appends. Best-effort + idempotent (see the helper).
            self.ensure_pile_root_quota();
            self.stage_and_publish_pile(&jail, &shared_pile)
                .context("seed shared.pile from bootstrap")?;
            // Same append-only protection on the SHARED pile — the higher-stakes
            // one, since a truncation here would corrupt org-wide data for every
            // coworker, not just the one who did it.
            let protect_shared = self.run(
                &["sudo", "-n", "chflags", "sappnd", &shared_pile],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !protect_shared.success() {
                bail!("chflags sappnd shared.pile failed: {}", protect_shared.stderr_lossy());
            }

            // single-file-nullfs-mount BOTH pile files rw via the one shared
            // FAIL-CLOSED primitive (same one reattach uses). The mounts do not
            // survive a jail restart (re-established by `reattach`), but they must
            // be live and EXACTLY correct for this first `jail -c`: a silently-
            // failed mount would leave guest /pile on the EMPTY file baked into
            // the clone, so PILE=/pile/self.pile writes into the clone, which
            // destroy_session then `zfs destroy`s — silent data loss. A bail! here
            // triggers the operation-owned cleanup (we created the clone, so it is
            // ours to tear down).
            self.mount_piles(&jail, &root)?;

            // Seed session env + default cwd via /etc/profile, which `sh -l`
            // sources on every exec (same mechanism as the Lima template's
            // __SESSION_ENV__). Only on first create — the persisted dataset
            // already carries its profile. PATH picks up the baked
            // /opt/faculties bins; PILE points at the mounted self.pile so a
            // faculty run in the jail operates on the coworker's own pile.
            let mut profile = String::new();
            profile.push_str("\n# playground session seed\n");
            profile.push_str(&format!("cd {} 2>/dev/null || true\n", shell_quote(&cwd)));
            profile.push_str("export PATH=/opt/faculties:$PATH\n");
            profile.push_str(&format!(
                "export PILE={}\n",
                shell_quote(Self::GUEST_SELF_PILE)
            ));
            for (k, v) in &spec.env {
                profile.push_str(&format!("export {}={}\n", k, shell_quote(v)));
            }
            let seed = self.run(
                &["sudo", "-n", "tee", "-a", &format!("{root}/etc/profile")],
                Some(profile.as_bytes()),
                ADMIN_TIMEOUT,
            )?;
            if !seed.success() {
                bail!("seed /etc/profile failed: {}", seed.stderr_lossy());
            }

            // Create the jail context: persistent (no processes yet), no
            // network at all (default-deny v1), minimal params.
            let created = self.run(
                &[
                    "sudo",
                    "-n",
                    "jail",
                    "-c",
                    &format!("name={jail}"),
                    &format!("path={root}"),
                    &format!("host.hostname={jail}"),
                    "persist",
                    "ip4=disable",
                    "ip6=disable",
                ],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !created.success() {
                bail!("jail -c {jail} failed: {}", created.stderr_lossy());
            }

            // RESOURCE BOUND (repair #4): apply per-jail rctl rules now that the
            // jail exists — but only if host RACCT is enabled (a no-op otherwise,
            // with an operator hint). This clamps fork/thread/FD/RAM/CPU pressure
            // per jail once the operator turns RACCT on; see deploy README.
            self.apply_rctl_rules(&jail);
            Ok(())
        })(&mut created_clone);

        if let Err(e) = provision {
            if created_clone {
                // THIS operation created the clone and then failed part-way: it
                // is ours to tear down, and only this dataset. `cleanup_leftovers`
                // stops the jail, unmounts, and `zfs destroy`s the dataset we
                // just made — never a pre-existing one, because we only reach
                // here with `created_clone == true`.
                self.cleanup_leftovers(&jail);
            } else {
                // We failed AT or BEFORE the clone (e.g. the clone lost an
                // EEXIST race to a concurrent provision, or the tri-state probe
                // path let us in but the clone still refused). We did NOT create
                // this dataset, so we destroy NOTHING — the existing/winning
                // dataset stays intact. This is the operation-owned-cleanup
                // invariant that makes concurrent creates non-destructive.
                eprintln!(
                    "[{}] provision '{}' failed before creating the dataset; \
                     destroying nothing (operation-owned cleanup)",
                    self.name(),
                    jail
                );
            }
            return Err(e.context(format!("provision jail '{jail}'")));
        }
        Ok(())
        })
    }

    fn reattach_all(&self) -> Result<usize> {
        // Enumerate the direct children of the parent dataset (`-d 1`), so a
        // session's own child datasets (if any) don't masquerade as sessions.
        let out = self.run(
            &[
                "sudo", "-n", "zfs", "list", "-H", "-o", "name", "-d", "1", "-r",
                &self.dataset_parent,
            ],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!(
                "zfs list -r {} failed: {}",
                self.dataset_parent,
                out.stderr_lossy()
            );
        }

        let prefix = format!("{}-", self.jail_prefix);
        let mut reattached = 0usize;
        for dataset in String::from_utf8_lossy(&out.stdout).lines() {
            let dataset = dataset.trim();
            // Skip the parent dataset itself and any leaf whose name isn't a
            // `<prefix>-…` session (e.g. the `template` dataset).
            if dataset.is_empty() || dataset == self.dataset_parent {
                continue;
            }
            let Some(leaf) = dataset.strip_prefix(&format!("{}/", self.dataset_parent)) else {
                continue;
            };
            // A session dataset's leaf IS its jail name (`<prefix>-<label>`).
            if !leaf.starts_with(&prefix) {
                continue;
            }
            let jail = leaf;
            if self.jail_running(jail) {
                continue; // already up — nothing to do
            }
            match self.reattach(jail, dataset) {
                Ok(()) => {
                    eprintln!("[{}] reattached persistent sandbox '{}'", self.name(), jail);
                    reattached += 1;
                }
                Err(e) => {
                    // Log and keep sweeping — one bad box must not strand the rest.
                    eprintln!("[{}] reattach '{}' failed: {e:#}", self.name(), jail);
                }
            }
        }
        Ok(reattached)
    }

    fn exec(&self, session: &SessionId, request: &ExecRequest) -> Result<ExecResult> {
        let jail = session.as_str();

        // Per-call cwd override; the session default cwd comes from the
        // /etc/profile seed written at open_session.
        let script = match &request.cwd {
            Some(cwd) => format!(
                "cd {} || exit 1\n{}",
                shell_quote(&cwd.to_string_lossy()),
                request.command
            ),
            None => request.command.clone(),
        };

        // TIMEOUT CEILING: a caller may request LESS than the default, never
        // MORE than the server-side maximum. `min(requested, MAX)` bounds how
        // long one tenant pins a blocking worker + a jail process regardless of
        // the `timeout_ms` it sends (the caller-selected-`u64` class).
        let requested = request.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);
        let timeout = requested.min(MAX_EXEC_TIMEOUT);
        // Server-side kill is authoritative: FreeBSD timeout(1) exits 124 and
        // actually terminates the process tree on the server (a local ssh kill
        // alone would leave the remote command running).
        let secs = timeout.as_secs().max(1).to_string();
        let argv = [
            "sudo", "-n", "timeout", "-k", "5", &secs, "jexec", jail, "/bin/sh", "-lc", &script,
        ];

        // Tenant output is attacker-controlled: cap each stream and kill the
        // transported child on breach (bounds daemon memory; see MAX_EXEC_OUTPUT_BYTES).
        let out = self.run_capped(
            &argv,
            request.stdin.as_deref(),
            timeout + LOCAL_TIMEOUT_GRACE,
            MAX_EXEC_OUTPUT_BYTES,
        )?;

        // REAP the jail's process tree on ANY early kill (local timeout backstop
        // or output-cap breach). The server-side `timeout(1)` reaps the tree it
        // launched on a clean server-side expiry (exit 124), but if the LOCAL
        // side gave up first — an ssh/transport wedge, or a cap kill that tore
        // down only the local ssh — the `jexec`'d command (and any background
        // processes it spawned inside the jail) can still be alive on the host.
        // A jailed process can only be signalled from OUTSIDE the jail, so we
        // ask the host to kill every process in this jail. Best-effort: on a
        // clean exit there is nothing to kill and this is skipped.
        if out.timed_out || out.output_truncated {
            // `jexec <jail> kill -TERM -1` signals every process inside the jail
            // (PID -1 = all processes the caller may signal; as jail-root that is
            // the whole jail), then a short grace and SIGKILL for stragglers.
            let _ = self.run(
                &["sudo", "-n", "jexec", jail, "/bin/kill", "-TERM", "-1"],
                None,
                ADMIN_TIMEOUT,
            );
            let _ = self.run(
                &["sudo", "-n", "jexec", jail, "/bin/kill", "-KILL", "-1"],
                None,
                ADMIN_TIMEOUT,
            );
        }

        let mut result = ExecResult {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
            error: None,
        };
        if out.timed_out || out.exit_code == Some(124) {
            // Mirror LimaBackend: timeouts surface as exit 124 + error text.
            result.exit_code = Some(124);
            let ceiling = if requested > MAX_EXEC_TIMEOUT {
                format!(
                    " (requested {requested:?} was clamped to the {MAX_EXEC_TIMEOUT:?} server maximum)"
                )
            } else {
                String::new()
            };
            result.error = Some(format!(
                "command timed out after {timeout:?}{ceiling}; jail process tree killed"
            ));
        } else if out.output_truncated {
            // Output ceiling breached: the process was KILLED at the cap, its
            // tree reaped, and the captured bytes stop at the ceiling.
            result.error = Some(format!(
                "output truncated at {MAX_EXEC_OUTPUT_BYTES} bytes per stream; \
                 process killed and jail tree reaped"
            ));
        } else if out.exit_code.is_some() && out.exit_code == self.runner.transport_error_exit() {
            // Transport failure (e.g. ssh's reserved exit 255), not the host
            // command's own exit code. Never fires for LocalRunner.
            result.error = Some(format!("transport error: {}",
                String::from_utf8_lossy(&result.stderr).trim()));
        }
        Ok(result)
    }

    fn close_session(&self, session: &SessionId) -> Result<()> {
        // Persistent backend: closing a session only DETACHES — the jail and its
        // dataset stay alive so the same tenant can reconnect to the same box.
        // Use `destroy_session` to remove it for good.
        eprintln!(
            "[{}] detach: sandbox '{}' persists (use destroy_session to remove)",
            self.name(),
            session.as_str()
        );
        Ok(())
    }

    fn destroy_session(&self, session: &SessionId) -> Result<()> {
        // `destroy_session` receives an already-derived jail-name session id (not
        // a raw label), so the pathological-label gate is the caller's job at
        // open/provision time; here we validate the session-id string itself is
        // non-empty / control-char-free before it reaches argv, and enforce the
        // namespace guard below.
        Self::validate_label(session.as_str())
            .context("invalid destroy_session session id")?;
        let jail = session.as_str();
        if !jail.starts_with(&format!("{}-", self.jail_prefix)) {
            bail!(
                "refusing to destroy '{jail}': outside the '{}-' namespace",
                self.jail_prefix
            );
        }
        let dataset = self.dataset(jail);

        // Serialize teardown under the per-canonical-tenant lifecycle lock
        // (blocker #3): a concurrent provision/open of the SAME box cannot
        // interleave with this destroy.
        self.lifecycle.with_lock(jail, || {
            // Remove the jail (kills its processes). Failure is tolerated — the
            // jail may already be gone — but is surfaced on stderr.
            let removed = self.run(&["sudo", "-n", "jail", "-r", jail], None, ADMIN_TIMEOUT)?;
            if !removed.success() {
                eprintln!(
                    "[{}] jail -r {jail}: {} (continuing to dataset teardown)",
                    self.name(),
                    removed.stderr_lossy()
                );
            }

            // Remove any per-jail rctl rules (keyed by jail NAME, so they would
            // otherwise linger and re-bind if the name were ever reused). Only
            // meaningful when RACCT is on; a no-op / tolerated failure otherwise.
            if !self.rctl_rules.is_empty() && self.racct_enabled() {
                let _ = self.run(
                    &["sudo", "-n", "rctl", "-r", &format!("jail:{jail}")],
                    None,
                    ADMIN_TIMEOUT,
                );
            }

            // Unmount devfs AND the two single-file pile mounts (must precede zfs
            // destroy: a dataset with mounts anywhere under its tree cannot be
            // destroyed — enforce_statfs). Model B: we unmount the piles but NEVER
            // delete the host self.pile or shared.pile — they are host-owned and
            // outlive the jail (a re-provision reattaches the same self.pile).
            if let Ok(root) = self.mountpoint(&dataset) {
                for guest in [Self::GUEST_SELF_PILE, Self::GUEST_SHARED_PILE, "/dev"] {
                    let _ = self.run(
                        &["sudo", "-n", "umount", "-f", &format!("{root}{guest}")],
                        None,
                        ADMIN_TIMEOUT,
                    );
                }
            }

            // Destroy the dataset. This MUST succeed or we leak the session
            // dataset; one retry covers transient "dataset is busy" races after
            // jail -r.
            let mut destroy =
                self.run(&["sudo", "-n", "zfs", "destroy", &dataset], None, ADMIN_TIMEOUT)?;
            if !destroy.success() {
                std::thread::sleep(Duration::from_secs(2));
                destroy =
                    self.run(&["sudo", "-n", "zfs", "destroy", &dataset], None, ADMIN_TIMEOUT)?;
            }
            if !destroy.success() {
                bail!("zfs destroy {dataset} failed: {}", destroy.stderr_lossy());
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{PileMount, Tenant};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// Records every host invocation; replies from a script keyed on the argv
    /// prefix, defaulting to success with empty output. Tests hold an `Arc`
    /// to it and hand a clone to the backend (mirrors the mock-backend
    /// pattern in `crate::mcp` tests).
    ///
    /// The `mount(8)` family is modelled STATEFULLY (`mounts` below): a
    /// `mount -t <fstype> <src> <target>` records a mount, `umount -f <target>`
    /// removes it, and bare `mount` renders the live table in FreeBSD's
    /// `"<src> on <TARGET> (<fstype>, local)"` shape. This makes the mock behave
    /// like a real host for the fail-closed mount primitive: the pre-mount check
    /// sees an empty target, the post-mount verify sees the exact tuple, a
    /// re-mount over a live mount is the EBUSY no-op (recorded once, so the
    /// exact-tuple check still passes), and a redirection (a different source at
    /// a target) is faithfully refused. Tests that need the mount table itself to
    /// fail script it explicitly (a scripted `mount`/`umount` prefix wins over the
    /// stateful model).
    #[derive(Default)]
    struct MockRunner {
        calls: Mutex<Vec<(Vec<String>, Option<Vec<u8>>)>>,
        /// (argv-prefix-to-match, canned output). Checked FIRST, so a test can
        /// force any command (including a `mount`/`umount`) to a canned result.
        script: Vec<(Vec<&'static str>, HostOutput)>,
        /// Stateful mount table: `(source, target, fstype)`, newest last.
        mounts: Mutex<Vec<(String, String, String)>>,
    }

    impl MockRunner {
        fn reply(mut self, prefix: &[&'static str], out: HostOutput) -> Self {
            self.script.push((prefix.to_vec(), out));
            self
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().iter().map(|(a, _)| a.clone()).collect()
        }
        /// Seed a mount into the stateful table (e.g. to model a jail whose pile
        /// mounts are already live for a reattach test).
        fn with_mount(self, source: &str, target: &str, fstype: &str) -> Self {
            self.mounts.lock().unwrap().push((
                source.to_string(),
                target.to_string(),
                fstype.to_string(),
            ));
            self
        }
        /// Render the stateful mount table in FreeBSD `mount(8)` output shape.
        fn render_mounts(&self) -> HostOutput {
            let listing = self
                .mounts
                .lock()
                .unwrap()
                .iter()
                .map(|(src, tgt, fs)| format!("{src} on {tgt} ({fs}, local)"))
                .collect::<Vec<_>>()
                .join("\n");
            ok_with_stdout(&format!("{listing}\n"))
        }
        /// Backend + handle pair: the backend owns one Arc clone, the test the other.
        fn into_backend(self) -> (JailBackend, Arc<MockRunner>) {
            let mock = Arc::new(self);
            (JailBackend::with_runner(Box::new(mock.clone())), mock)
        }
    }

    impl HostRunner for Arc<MockRunner> {
        fn run(&self, argv: &[String], stdin: Option<&[u8]>, _timeout: Duration) -> Result<HostOutput> {
            self.calls
                .lock()
                .unwrap()
                .push((argv.to_vec(), stdin.map(|b| b.to_vec())));
            // Explicit scripts win, so a test can force any command to fail.
            for (prefix, out) in &self.script {
                if argv.len() >= prefix.len()
                    && argv.iter().zip(prefix.iter()).all(|(a, p)| a == p)
                {
                    return Ok(out.clone());
                }
            }
            // Stateful mount table for the unscripted mount family.
            let a: Vec<&str> = argv.iter().map(String::as_str).collect();
            match a.as_slice() {
                // bare `mount` (possibly with sudo -n): render the live table.
                ["sudo", "-n", "mount"] | ["mount"] => return Ok(self.render_mounts()),
                // `mount -t <fstype> <src> <target>`: record it (once per exact
                // (src,target) — a duplicate re-mount is the EBUSY no-op and must
                // not stack).
                ["sudo", "-n", "mount", "-t", fstype, .., src, target] => {
                    let mut mounts = self.mounts.lock().unwrap();
                    let already = mounts.iter().any(|(s, t, _)| s == src && t == target);
                    if already {
                        // EBUSY no-op: exactly one mount survives (already there).
                        return Ok(fail());
                    }
                    // A DIFFERENT source already at this target is a redirection —
                    // model it as still-present (the real kernel would stack /
                    // shadow; either way our validator must catch the mismatch),
                    // so record the new one and let the exact-tuple check decide.
                    mounts.push((src.to_string(), target.to_string(), fstype.to_string()));
                    return Ok(HostOutput { exit_code: Some(0), ..Default::default() });
                }
                // `umount -f <target>`: drop every mount at that target.
                ["sudo", "-n", "umount", "-f", target] | ["umount", "-f", target] => {
                    self.mounts.lock().unwrap().retain(|(_, t, _)| t != target);
                    return Ok(HostOutput { exit_code: Some(0), ..Default::default() });
                }
                _ => {}
            }
            Ok(HostOutput {
                exit_code: Some(0),
                ..Default::default()
            })
        }
    }

    fn ok_with_stdout(s: &str) -> HostOutput {
        HostOutput {
            stdout: s.as_bytes().to_vec(),
            exit_code: Some(0),
            ..Default::default()
        }
    }

    /// A non-zero exit with no stderr: used to script "jail not running".
    fn fail() -> HostOutput {
        HostOutput {
            exit_code: Some(1),
            ..Default::default()
        }
    }

    /// A `zfs list` reply that means "dataset genuinely does NOT exist": the
    /// tri-state probe ([`JailBackend::dataset_state`]) classifies this as
    /// [`DatasetState::Absent`] only because the stderr carries ZFS's canonical
    /// not-found phrase. A bare non-zero `fail()` is instead classified as
    /// [`DatasetState::Unknown`] (an error we cannot interpret as clean
    /// absence), which is the whole point — a transient failure must NOT look
    /// like an absence and trigger a clone/cleanup.
    fn dataset_absent() -> HostOutput {
        HostOutput {
            exit_code: Some(1),
            stderr: b"cannot open 'aitemp/playground/x': dataset does not exist\n".to_vec(),
            ..Default::default()
        }
    }

    /// A `zfs list` reply that means "the probe FAILED for a reason that is NOT
    /// clean absence" (permission denied here; a transport 255 or timeout would
    /// be equivalent). Classified [`DatasetState::Unknown`], so a lifecycle op
    /// must fail closed and destroy nothing.
    fn dataset_probe_error() -> HostOutput {
        HostOutput {
            exit_code: Some(1),
            stderr: b"cannot open 'aitemp/playground/x': permission denied\n".to_vec(),
            ..Default::default()
        }
    }

    fn spec(label: &str) -> SessionSpec {
        SessionSpec {
            tenant: Tenant {
                label: label.to_string(),
                pile: PileMount {
                    host_path: PathBuf::from("/caller/supplied/arbitrary.pile"),
                    guest_path: PathBuf::from("/pile/self.pile"),
                    append_only: true,
                },
            },
            cwd: None,
            env: vec![("FOO".to_string(), "bar's".to_string())],
        }
    }

    /// The canonical jail name for a label under the default prefix, computed
    /// via the SAME `jail_name` the backend uses so tests never hardcode the
    /// injective `<prefix>-<safe>-<digest>` string (which would drift if the
    /// scheme changed). Alice's name is e.g. `playground-alice-<20 hex>`.
    fn alice_jail() -> String {
        JailBackend::local().jail_name("alice")
    }

    /// Alice's dataset + jail root under the default namespace, both derived
    /// from her injective jail name.
    fn alice_dataset() -> String {
        format!("aitemp/playground/{}", alice_jail())
    }
    fn alice_root() -> String {
        format!("/aitemp/playground/{}", alice_jail())
    }

    /// The mountpoint query needs a scripted reply everywhere. Keyed on the
    /// `zfs get … mountpoint` prefix (dataset name excluded), so it matches
    /// whatever injective dataset name alice resolves to and returns her root.
    /// Also scripts the `playground:tenant` provenance read-back so the
    /// reuse/reattach arms (which now VERIFY it) see alice's recorded label.
    fn mock_with_mountpoint() -> MockRunner {
        MockRunner::default()
            .reply(
                &["zfs", "get", "-H", "-o", "value", "mountpoint"],
                ok_with_stdout(&format!("{}\n", alice_root())),
            )
            .reply(
                &["sudo", "-n", "zfs", "get", "-H", "-o", "value", "playground:tenant"],
                ok_with_stdout("alice\n"),
            )
    }

    /// Mock ready for the fresh-provision path. The mount table is now STATEFUL
    /// (the mock records `mount -t …` and renders bare `mount`), so no static
    /// `mount` listing is scripted: the fail-closed mount primitive sees an empty
    /// target on the pre-check, issues the real `mount`, and the post-verify sees
    /// the exact tuple the mock just recorded — a faithful fresh provision.
    fn mock_provision_ready() -> MockRunner {
        mock_with_mountpoint()
    }

    /// A mock modelling an ALREADY-attached jail whose devfs + both pile mounts
    /// are live at alice's root (the reattach entry state): re-mounts over these
    /// are the EBUSY no-op, and the exact-tuple validation must accept them.
    fn mock_reattached_alice() -> MockRunner {
        let jail = alice_jail();
        let root = alice_root();
        mock_with_mountpoint()
            .with_mount("devfs", &format!("{root}/dev"), "devfs")
            .with_mount(
                &format!("/aitemp/playground/piles/{jail}/self.pile"),
                &format!("{root}/pile/self.pile"),
                "nullfs",
            )
            .with_mount(
                "/aitemp/playground/piles/shared/shared.pile",
                &format!("{root}/shared/shared.pile"),
                "nullfs",
            )
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    /// LocalRunner really spawns the argv on this machine: argv reaches the
    /// process verbatim (no shell re-parse), stdin is fed, both output
    /// streams and the exit code come back. (Pipe-buffer-sized payloads and
    /// timeout kills are covered by `super::super::proc`'s own tests.)
    #[test]
    fn local_runner_spawns_argv_directly() {
        let runner = LocalRunner;
        let argv: Vec<String> = ["/bin/sh", "-c", "cat; printf err >&2; exit 3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = runner
            .run(&argv, Some(b"space out"), Duration::from_secs(10))
            .expect("run");
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(3));
        // "space out" arrives as one argv element / one stdin write — a shell
        // re-parse (the ssh path) would have needed quoting.
        assert_eq!(out.stdout, b"space out");
        assert_eq!(out.stderr_lossy(), "err");
        // A local spawn has no transport that can fail separately.
        assert_eq!(runner.transport_error_exit(), None);
    }

    /// Exit 255 is a *transport* error only where a transport exists (ssh).
    /// For a runner without one (LocalRunner, and this mock via the trait
    /// default) it is an ordinary exit code and must not grow an error.
    #[test]
    fn exec_maps_exit_255_per_runner_transport() {
        assert_eq!(LocalRunner.transport_error_exit(), None);
        assert_eq!(SshRunner::new("h").transport_error_exit(), Some(255));

        let (backend, _mock) = MockRunner::default()
            .reply(
                &["sudo", "-n", "timeout"],
                HostOutput {
                    exit_code: Some(255),
                    ..Default::default()
                },
            )
            .into_backend();
        let req = ExecRequest {
            command: "exit 255".to_string(),
            cwd: None,
            stdin: None,
            timeout: None,
        };
        let result = backend
            .exec(&SessionId::new("playground-alice"), &req)
            .expect("exec");
        assert_eq!(result.exit_code, Some(255));
        assert!(result.error.is_none(), "no transport, no transport error");
    }

    #[test]
    fn provision_sandbox_clones_and_creates() {
        // First-create path: no existing dataset (zfs list fails), so provision
        // must clone the template and create a fresh jail. (jls also fails so
        // the already-provisioned "ensure up" arm is never reached — but
        // provision keys off dataset existence, not the jail.)
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");

        let calls = mock.calls();
        let jail = alice_jail();

        // Must clone the template into the namespaced (injective) dataset...
        assert!(calls.iter().any(|c| c.starts_with(&[
            "sudo".into(), "-n".into(), "zfs".into(), "clone".into(),
            "aitemp/playground/template@base".into(),
            alice_dataset(),
        ] as &[String])));
        // ...record the tenant provenance right after the clone...
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "zfs".into(), "set".into(),
                "playground:tenant=alice".into(), alice_dataset(),
            ]),
            "must `zfs set playground:tenant=alice` on the fresh dataset: {calls:?}"
        );
        // ...and create a jail with no network, correct name/path.
        let jail_call = calls
            .iter()
            .find(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            })
            .expect("jail -c issued");
        assert!(jail_call.contains(&format!("name={jail}")));
        assert!(jail_call.contains(&format!("path={}", alice_root())));
        assert!(jail_call.contains(&"ip4=disable".to_string()));
        assert!(jail_call.contains(&"ip6=disable".to_string()));
        assert!(jail_call.contains(&"persist".to_string()));
    }

    // ---- repair #4: resource bounds ----------------------------------------

    /// Provision sets the ZFS `refquota` on the fresh per-tenant clone (storage
    /// bound) — a tenant cannot fill the host pool via its own dataset. The
    /// default backend carries `clone_refquota = Some("10G")`.
    #[test]
    fn provision_sets_clone_refquota() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");

        let calls = mock.calls();
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "zfs".into(), "set".into(),
                "refquota=10G".into(), alice_dataset(),
            ]),
            "must `zfs set refquota=10G` on the fresh clone: {calls:?}"
        );
    }

    /// A `None`/disabled `clone_refquota` skips the refquota set entirely (so an
    /// operator whose pool has its own delegated quota is not forced into ours).
    #[test]
    fn provision_skips_refquota_when_disabled() {
        let (mut backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        backend.clone_refquota = None;
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.iter().any(|a| a.starts_with("refquota="))),
            "no refquota set must be issued when disabled: {calls:?}"
        );
    }

    /// With host RACCT OFF (the mock's `sysctl kern.racct.enable` yields empty →
    /// not "1"), provision must NOT attempt any `rctl -a` rule — it fails closed
    /// on the probe and only emits the operator hint.
    #[test]
    fn provision_skips_rctl_when_racct_off() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            // sysctl returns empty stdout by the mock default → racct_enabled() == false.
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("rctl")),
            "no rctl rule may be applied while RACCT is off: {calls:?}"
        );
    }

    /// With host RACCT ON (sysctl → "1"), provision applies the configured
    /// per-jail `rctl -a jail:<name>:<rule>` rules.
    #[test]
    fn provision_applies_rctl_when_racct_on() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .reply(&["sysctl", "-n", "kern.racct.enable"], ok_with_stdout("1\n"))
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");

        let calls = mock.calls();
        let jail = alice_jail();
        // At least the maxproc rule must be applied, keyed on alice's jail name.
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "rctl".into(), "-a".into(),
                format!("jail:{jail}:maxproc:deny=512"),
            ]),
            "must apply the maxproc rctl rule when RACCT is on: {calls:?}"
        );
    }

    /// The caller-supplied exec timeout is CLAMPED to the server maximum: a huge
    /// `timeout_ms` becomes `timeout(1) <MAX>`, never larger. (A caller may still
    /// ask for LESS.)
    #[test]
    fn exec_clamps_timeout_to_the_ceiling() {
        let (backend, mock) = MockRunner::default().into_backend();
        // Ask for 10 hours — far past the 30-minute ceiling.
        let req = ExecRequest {
            command: "true".to_string(),
            cwd: None,
            stdin: None,
            timeout: Some(Duration::from_secs(10 * 3600)),
        };
        backend
            .exec(&SessionId::new("playground-alice"), &req)
            .expect("exec");
        let calls = mock.calls();
        // Find the `timeout(1)` argv and read the seconds arg (index after -k 5).
        let tcall = calls
            .iter()
            .find(|c| c.get(2).map(String::as_str) == Some("timeout"))
            .expect("timeout(1) issued");
        // argv: sudo -n timeout -k 5 <secs> jexec ...
        let secs: u64 = tcall[5].parse().expect("secs is numeric");
        assert_eq!(
            secs,
            MAX_EXEC_TIMEOUT.as_secs(),
            "a huge requested timeout must be clamped to the ceiling: {calls:?}"
        );
    }

    /// A caller requesting LESS than the ceiling gets exactly what it asked for.
    #[test]
    fn exec_honours_a_smaller_requested_timeout() {
        let (backend, mock) = MockRunner::default().into_backend();
        let req = ExecRequest {
            command: "true".to_string(),
            cwd: None,
            stdin: None,
            timeout: Some(Duration::from_secs(5)),
        };
        backend
            .exec(&SessionId::new("playground-alice"), &req)
            .expect("exec");
        let calls = mock.calls();
        let tcall = calls
            .iter()
            .find(|c| c.get(2).map(String::as_str) == Some("timeout"))
            .expect("timeout(1) issued");
        assert_eq!(tcall[5], "5", "a sub-ceiling timeout passes through: {calls:?}");
    }

    /// On an output-cap breach the jail process tree is reaped (best-effort
    /// `jexec <jail> kill -TERM/-KILL -1`) and the result carries the truncation
    /// error, so a runaway producer's background procs cannot outlive the exec.
    #[test]
    fn exec_reaps_tree_on_output_truncation() {
        let (backend, mock) = MockRunner::default()
            .reply(
                &["sudo", "-n", "timeout"],
                HostOutput {
                    stdout: vec![b'x'; 4096],
                    output_truncated: true,
                    exit_code: Some(0),
                    ..Default::default()
                },
            )
            .into_backend();
        let req = ExecRequest {
            command: "yes".to_string(),
            cwd: None,
            stdin: None,
            timeout: None,
        };
        let result = backend
            .exec(&SessionId::new("playground-alice"), &req)
            .expect("exec");
        assert!(
            result.error.as_deref().unwrap_or("").contains("output truncated"),
            "truncation must be signalled: {:?}",
            result.error
        );
        let calls = mock.calls();
        // The kill -TERM -1 and kill -KILL -1 reap calls were issued.
        assert!(
            calls.iter().any(|c| c
                == &["sudo".to_string(), "-n".into(), "jexec".into(),
                     "playground-alice".into(), "/bin/kill".into(), "-TERM".into(), "-1".into()]),
            "must SIGTERM the jail tree on truncation: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c
                == &["sudo".to_string(), "-n".into(), "jexec".into(),
                     "playground-alice".into(), "/bin/kill".into(), "-KILL".into(), "-1".into()]),
            "must SIGKILL stragglers on truncation: {calls:?}"
        );
    }

    // ---- blocker #3: lifecycle uncertainty must never destroy valid data ----

    /// The tri-state probe classifies each `zfs list` outcome correctly: exit 0
    /// is `Exists`, the canonical not-found stderr is `Absent`, and EVERYTHING
    /// else (a bare non-zero, a permission error, a transport 255, a local
    /// timeout) is `Unknown` — never mistaken for a clean absence.
    #[test]
    fn dataset_state_distinguishes_absent_from_error() {
        let cases: &[(HostOutput, DatasetState)] = &[
            (ok_with_stdout("aitemp/playground/x\n"), DatasetState::Exists),
            (dataset_absent(), DatasetState::Absent),
            (dataset_probe_error(), DatasetState::Unknown),
            (fail(), DatasetState::Unknown), // bare non-zero, no stderr
            (
                HostOutput { exit_code: Some(255), ..Default::default() },
                DatasetState::Unknown,
            ),
            (
                HostOutput { timed_out: true, exit_code: None, ..Default::default() },
                DatasetState::Unknown,
            ),
        ];
        for (out, want) in cases {
            let (backend, _mock) = MockRunner::default()
                .reply(&["sudo", "-n", "zfs", "list"], out.clone())
                .into_backend();
            // The mock runner's transport-error-exit is None, so a bare exit 255
            // is not treated as a transport error here — but it still classifies
            // as Unknown because its stderr lacks the canonical not-found phrase.
            // (The dedicated ssh-transport path is covered by
            // `exec_maps_exit_255_per_runner_transport`.) A local timeout
            // (`timed_out`) is Unknown unconditionally.
            assert_eq!(
                backend.dataset_state("aitemp/playground/x"),
                *want,
                "probe {out:?} should classify as {want:?}"
            );
        }
    }

    /// (a) A provision whose dataset probe is INCONCLUSIVE (`Unknown` — here a
    /// permission error, equivalent to a transport failure or timeout) must fail
    /// closed: NO `zfs clone`, and above all NO `zfs destroy`. The old bool probe
    /// collapsed this into "absent", cloned, then on the inevitable failure ran
    /// destructive cleanup — the data-loss class this repair closes.
    #[test]
    fn provision_bails_on_unknown_probe_without_destroying_anything() {
        let (backend, mock) = MockRunner::default()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_probe_error())
            .into_backend();
        let err = backend
            .provision_sandbox(&spec("alice"))
            .expect_err("must refuse on an inconclusive probe");
        assert!(
            format!("{err:#}").contains("inconclusive"),
            "should explain the fail-closed reason: {err:#}"
        );
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("clone")),
            "an Unknown probe must NOT clone: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("destroy")),
            "an Unknown probe must NEVER destroy: {calls:?}"
        );
    }

    /// (a') `open_session` likewise fails closed on an `Unknown` probe: it does
    /// not reattach an unconfirmable box and does not misreport it as
    /// "unprovisioned".
    #[test]
    fn open_session_bails_on_unknown_probe() {
        let (backend, mock) = mock_with_mountpoint()
            .reply(&["sudo", "-n", "jls", "-j"], fail()) // not running
            .reply(&["sudo", "-n", "zfs", "list"], dataset_probe_error())
            .into_backend();
        let err = backend
            .open_session(&spec("alice"))
            .expect_err("must refuse on an inconclusive probe");
        assert!(format!("{err:#}").contains("inconclusive"), "{err:#}");
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            }),
            "must NOT reattach (jail -c) on an Unknown probe: {calls:?}"
        );
    }

    /// (b) OPERATION-OWNED CLEANUP: a provision that fails AT the `zfs clone`
    /// (modelling the loser of a concurrent create — its clone loses the EEXIST
    /// race) must NOT run `zfs destroy`. It never created the dataset, so the
    /// winner's valid dataset stays intact. This is the invariant that makes
    /// concurrent creates non-destructive even without a lock.
    #[test]
    fn failed_clone_destroys_nothing_operation_owned_cleanup() {
        let (backend, mock) = MockRunner::default()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent()) // looked absent
            .reply(&["sudo", "-n", "zfs", "clone"], fail()) // but the clone loses the race
            .into_backend();
        let err = backend
            .provision_sandbox(&spec("alice"))
            .expect_err("clone failure must surface");
        assert!(format!("{err:#}").contains("zfs clone"), "{err:#}");
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("destroy")),
            "a provision that did not create the dataset must destroy NOTHING: {calls:?}"
        );
    }

    /// (b') Conversely, when the clone SUCCEEDS and a later step fails, the op
    /// DID create the dataset, so operation-owned cleanup DOES tear down that
    /// one dataset (and only it). Here the post-clone `jail -c` fails.
    #[test]
    fn failed_provision_after_clone_destroys_only_its_own_dataset() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .reply(&["sudo", "-n", "jail", "-c"], fail()) // fail AFTER the clone
            .into_backend();
        backend
            .provision_sandbox(&spec("alice"))
            .expect_err("jail -c failure must surface");
        let calls = mock.calls();
        let destroys: Vec<_> = calls
            .iter()
            .filter(|c| {
                c.get(2).map(String::as_str) == Some("zfs")
                    && c.get(3).map(String::as_str) == Some("destroy")
            })
            .collect();
        assert!(
            !destroys.is_empty(),
            "a provision that created the clone must clean it up on failure: {calls:?}"
        );
        assert!(
            destroys
                .iter()
                .all(|c| c.last().map(String::as_str) == Some(alice_dataset().as_str())),
            "cleanup must destroy ONLY the dataset this op created: {destroys:?}"
        );
    }

    /// (d) FAIL-CLOSED MOUNT: a pile mount that reports success but does not
    /// actually appear in the mount table (a silently-failed mount) must abort
    /// the provision — never boot a jail whose PILE points at empty clone-local
    /// scratch. We model this by scripting the nullfs `mount` to succeed while
    /// the stateful table is bypassed (an explicit `mount -t nullfs` script
    /// returns success but records nothing), so the post-mount exact-tuple verify
    /// finds the target absent.
    #[test]
    fn silently_failed_pile_mount_fails_closed() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            // nullfs mount "succeeds" but is scripted, so the stateful table
            // never records it -> the exact-tuple post-verify must catch it.
            .reply(
                &["sudo", "-n", "mount", "-t", "nullfs"],
                HostOutput { exit_code: Some(0), ..Default::default() },
            )
            .into_backend();
        let err = backend
            .provision_sandbox(&spec("alice"))
            .expect_err("a mount that did not take must fail the provision");
        assert!(
            format!("{err:#}").contains("did not take exactly"),
            "should fail closed on the missing mount: {err:#}"
        );
        // And because the clone WAS created, operation-owned cleanup destroys it.
        let calls = mock.calls();
        assert!(
            calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("destroy")),
            "the created-but-unusable clone must be torn down: {calls:?}"
        );
    }

    /// (d') MOUNT REDIRECTION REFUSED: reattaching a jail whose pile target is
    /// already mounted by a DIFFERENT source (a tenant-controlled mountpoint
    /// redirection) must refuse rather than trust the reused mount and start the
    /// jail. We seed the mount table with a rogue source at alice's self.pile
    /// target.
    #[test]
    fn reattach_refuses_redirected_pile_mount() {
        let root = alice_root();
        let (backend, mock) = mock_with_mountpoint()
            .reply(&["sudo", "-n", "jls", "-j"], fail()) // not running -> reattach
            // devfs is fine; the SELF pile target is hijacked by a rogue source.
            .with_mount("devfs", &format!("{root}/dev"), "devfs")
            .with_mount(
                "/evil/rogue.pile",
                &format!("{root}/pile/self.pile"),
                "nullfs",
            )
            .into_backend();
        let err = backend
            .open_session(&spec("alice"))
            .expect_err("a redirected pile mount must abort the reattach");
        assert!(
            format!("{err:#}").contains("mount redirection")
                || format!("{err:#}").contains("already mounted by something other"),
            "should refuse the redirection: {err:#}"
        );
        // The jail must NOT have been started with the redirected pile.
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            }),
            "must not `jail -c` with a redirected pile mount: {calls:?}"
        );
    }

    /// (c) PER-TENANT LIFECYCLE LOCK serializes two concurrent same-tenant
    /// backend ops: while one provision holds the lock, a second same-tenant
    /// provision cannot begin its work until the first releases. We prove
    /// mutual exclusion by having the first op block inside the lock (on a
    /// barrier) and asserting the second has made NO host calls until the first
    /// finishes.
    #[test]
    fn lifecycle_lock_serializes_same_tenant_ops() {
        use std::sync::mpsc;
        use std::sync::Arc;

        // A runner whose FIRST `zfs list` (dataset probe) blocks on a channel, so
        // the op that grabs the tenant lock first stalls inside the critical
        // section; a same-tenant op must then wait for the lock.
        struct GateRunner {
            calls: Mutex<Vec<Vec<String>>>,
            gate_rx: Mutex<Option<mpsc::Receiver<()>>>,
            entered: mpsc::Sender<()>,
        }
        impl HostRunner for Arc<GateRunner> {
            fn run(
                &self,
                argv: &[String],
                _stdin: Option<&[u8]>,
                _t: Duration,
            ) -> Result<HostOutput> {
                self.calls.lock().unwrap().push(argv.to_vec());
                if argv.get(2).map(String::as_str) == Some("zfs")
                    && argv.get(3).map(String::as_str) == Some("list")
                {
                    // Only the first caller finds a receiver; it blocks until the
                    // test releases the gate. The second caller (which only
                    // reaches here AFTER acquiring the lock) sees None.
                    if let Some(rx) = self.gate_rx.lock().unwrap().take() {
                        let _ = self.entered.send(());
                        let _ = rx.recv(); // block inside the lock
                    }
                    return Ok(dataset_absent());
                }
                if argv.get(2).map(String::as_str) == Some("zfs")
                    && argv.get(3).map(String::as_str) == Some("clone")
                {
                    // Fail the clone so neither op does real work past the probe.
                    return Ok(fail());
                }
                Ok(HostOutput { exit_code: Some(0), ..Default::default() })
            }
        }

        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let runner = Arc::new(GateRunner {
            calls: Mutex::new(Vec::new()),
            gate_rx: Mutex::new(Some(gate_rx)),
            entered: entered_tx,
        });
        let backend = Arc::new(JailBackend::with_runner(Box::new(runner.clone())));

        // Op 1: grabs the lock, blocks inside the probe.
        let b1 = backend.clone();
        let t1 = std::thread::spawn(move || {
            let _ = b1.provision_sandbox(&spec("alice"));
        });
        // Wait until op 1 is confirmed inside the critical section.
        entered_rx.recv().expect("op1 entered the probe");

        // Op 2: same tenant. It should BLOCK on the lifecycle lock and make no
        // host calls yet. Give it a moment to try.
        let b2 = backend.clone();
        let t2 = std::thread::spawn(move || {
            let _ = b2.provision_sandbox(&spec("alice"));
        });
        std::thread::sleep(Duration::from_millis(200));

        // Op 1 is still inside the lock; op 2 must not have issued its own probe.
        let probes_before = runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("list"))
            .count();
        assert_eq!(
            probes_before, 1,
            "only op1's probe may have run while it holds the tenant lock"
        );

        // Release op 1; op 2 may now proceed and run its own probe.
        gate_tx.send(()).expect("release gate");
        t1.join().unwrap();
        t2.join().unwrap();
        let probes_after = runner
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("list"))
            .count();
        assert_eq!(probes_after, 2, "op2 runs its probe only after op1 releases");
    }

    /// Model-B pile provisioning: a brand-new tenant gets BOTH host-owned pile
    /// FILES single-file-nullfs-mounted rw (self at guest /pile/self.pile, shared
    /// at guest /shared/shared.pile), each seeded from bootstrap.pile via a
    /// host-PRIVATE staging copy published with a no-follow / create-only
    /// hardlink, the guest target files touched, and /etc/profile seeded with the
    /// faculties PATH + PILE=/pile/self.pile. The piles derive from
    /// `pile_root`+jail name, NOT from the caller-supplied `spec.tenant.pile`.
    #[test]
    fn provision_mounts_both_piles_seeds_path_and_pile() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();
        let jail = alice_jail();
        let root = alice_root();
        let root = root.as_str();

        // Default pile-root derived paths (keyed on the injective jail name).
        let self_dir = format!("/aitemp/playground/piles/{jail}");
        let self_dir = self_dir.as_str();
        let self_pile = format!("{self_dir}/self.pile");
        let shared_dir = "/aitemp/playground/piles/shared";
        let shared_pile = format!("{shared_dir}/shared.pile");
        let staging_root = "/aitemp/playground/staging";
        let staging_tmp = format!("{staging_root}/{jail}.pile.tmp");

        // Host per-coworker pile dir is created.
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "mkdir".into(), "-p".into(), self_dir.into()
            ] as &[String])),
            "must mkdir the per-coworker pile dir: {calls:?}"
        );
        // The host-private staging dir is created AND locked down to 0700.
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "mkdir".into(), "-p".into(), staging_root.into()
            ] as &[String])),
            "must mkdir the host-private staging dir: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "chmod".into(), "700".into(), staging_root.into()
            ] as &[String])),
            "must chmod 700 the host-private staging dir: {calls:?}"
        );
        // Both piles are made append-only (`chflags sappnd`) after seeding: an
        // in-jail process can append but not truncate them.
        for pile in [&self_pile, &shared_pile] {
            assert!(
                calls.iter().any(|c| c.ends_with(&[
                    "chflags".into(),
                    "sappnd".into(),
                    pile.clone(),
                ] as &[String])),
                "must chflags sappnd {pile}: {calls:?}"
            );
        }
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "mkdir".into(), "-p".into(), shared_dir.into()
            ] as &[String])),
            "must mkdir the shared pile dir: {calls:?}"
        );

        // BOTH piles are seeded the SAME tenant-safe way: cp bootstrap into the
        // host-PRIVATE staging temp (never a tenant-reachable path), then publish
        // with a no-follow / create-only HARDLINK into place.
        for dest in [&self_pile, &shared_pile] {
            // Stage: cp bootstrap -> host-private staging temp.
            assert!(
                calls.iter().any(|c| c.ends_with(&[
                    "cp".into(),
                    "/aitemp/playground/bootstrap.pile".into(),
                    staging_tmp.clone(),
                ] as &[String])),
                "must cp bootstrap.pile into the host-private staging temp: {calls:?}"
            );
            // Publish: ln staging_tmp -> dest (atomic, create-only, no-follow).
            assert!(
                calls.iter().any(|c| c == &[
                    "sudo".to_string(), "-n".into(), "ln".into(),
                    staging_tmp.clone(), dest.clone(),
                ]),
                "must publish {dest} via no-follow/create-only `ln` from staging: {calls:?}"
            );
        }
        // The bootstrap `cp` must NEVER write to a tenant-reachable pile path
        // (the symlink confused-deputy fix): its destination is always the
        // host-private staging temp.
        assert!(
            !calls.iter().any(|c| {
                let is_cp = c.iter().any(|a| a == "cp");
                let dest = c.last().map(String::as_str);
                is_cp && (dest == Some(self_pile.as_str()) || dest == Some(shared_pile.as_str()))
            }),
            "must NOT cp bootstrap directly into a pile path (must stage privately): {calls:?}"
        );

        // BOTH single-file nullfs mounts: host pile FILE -> guest pile FILE.
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(), self_pile.clone(), format!("{root}/pile/self.pile"),
            ]),
            "must single-file-nullfs-mount self.pile at /pile/self.pile: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(), shared_pile.clone(), format!("{root}/shared/shared.pile"),
            ]),
            "must single-file-nullfs-mount shared.pile at /shared/shared.pile: {calls:?}"
        );
        // The guest target FILES are touched (created empty) before the mount.
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "touch".into(), format!("{root}/pile/self.pile"),
            ] as &[String])),
            "must touch the guest self.pile target before mounting: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "touch".into(), format!("{root}/shared/shared.pile"),
            ] as &[String])),
            "must touch the guest shared.pile target before mounting: {calls:?}"
        );

        // /etc/profile seed carries the faculties PATH + PILE at the mounted
        // self.pile guest path.
        let (_, seed_stdin) = mock
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|(argv, _)| argv.iter().any(|a| a == "tee"))
            .cloned()
            .expect("profile seed issued");
        let seed = String::from_utf8(seed_stdin.expect("seed body")).unwrap();
        assert!(
            seed.contains("export PATH=/opt/faculties:$PATH"),
            "profile must put /opt/faculties on PATH: {seed}"
        );
        assert!(
            seed.contains("export PILE='/pile/self.pile'"),
            "profile must export PILE at the mounted self.pile: {seed}"
        );

        // The caller-supplied pile path is NEVER referenced by any host
        // command (only logged): the mounted pile is the coworker's server-born
        // artifact under pile_root.
        assert!(
            calls.iter().flatten().all(|a| !a.contains("/caller/supplied/arbitrary.pile")),
            "must never reference the caller-supplied pile path: {calls:?}"
        );
    }

    /// A tenant with no dataset yet cannot be opened — open never clones. The
    /// error names `playground user create` and NO clone is issued.
    #[test]
    fn open_session_errors_when_unprovisioned() {
        let (backend, mock) = mock_with_mountpoint()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        let err = backend.open_session(&spec("alice")).expect_err("must bail");
        assert!(
            err.to_string().contains("not provisioned"),
            "err: {err}"
        );
        assert!(err.to_string().contains("playground user create alice"));
        // Crucially: no clone was attempted.
        assert!(
            !mock.calls().iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("clone")),
            "open must not zfs clone"
        );
    }

    /// A tenant whose jail context is gone but whose dataset persists is
    /// reattached on open (devfs re-mount + `jail -c`), WITHOUT cloning.
    #[test]
    fn open_session_reattaches_existing_dataset() {
        let (backend, mock) = mock_with_mountpoint()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            // dataset present: zfs list succeeds (default success from the mock).
            .into_backend();
        let id = backend.open_session(&spec("alice")).expect("open");
        assert_eq!(id.as_str(), alice_jail());

        let calls = mock.calls();
        // jail -c must be issued (reattach)...
        assert!(
            calls.iter().any(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            }),
            "reattach must jail -c"
        );
        // ...but nothing was cloned or re-seeded.
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("clone")),
            "reattach must not zfs clone"
        );
        assert!(
            !calls.iter().any(|c| c.get(3).map(String::as_str) == Some("tee")
                || c.get(2).map(String::as_str) == Some("tee")),
            "reattach must not re-seed /etc/profile"
        );
    }

    /// Reattach re-establishes BOTH single-file pile mounts (self + shared) —
    /// they do not survive a jail restart, exactly like the devfs re-mount —
    /// without re-seeding self.pile or the profile (the persisted host piles
    /// carry their accumulated content).
    #[test]
    fn reattach_remounts_both_piles() {
        let (backend, mock) = mock_with_mountpoint()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            // dataset present (default success) -> reattach on open.
            .into_backend();
        backend.open_session(&spec("alice")).expect("open");
        let calls = mock.calls();
        let jail = alice_jail();
        let root = alice_root();
        let root = root.as_str();

        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                format!("/aitemp/playground/piles/{jail}/self.pile"),
                format!("{root}/pile/self.pile"),
            ]),
            "reattach must re-mount the self.pile at /pile/self.pile: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                "/aitemp/playground/piles/shared/shared.pile".into(),
                format!("{root}/shared/shared.pile"),
            ]),
            "reattach must re-mount the shared.pile at /shared/shared.pile: {calls:?}"
        );
        // Reattach seeds nothing: no bootstrap copy.
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("cp")),
            "reattach must not re-seed a pile: {calls:?}"
        );
    }

    /// Reattach over a jail whose devfs + both pile mounts are ALREADY live and
    /// EXACTLY correct (the FreeBSD EBUSY-no-op entry state) succeeds as a
    /// verified no-op: the shared fail-closed primitive accepts a pre-existing
    /// mount that matches the intended `(source, target, nullfs)` tuple, and the
    /// jail is (re)started. This is the reattach happy path the primitive must
    /// NOT break while it fails closed on redirections/missing mounts.
    #[test]
    fn reattach_accepts_exact_existing_mounts_as_noop() {
        let (backend, mock) = mock_reattached_alice()
            .reply(&["sudo", "-n", "jls", "-j"], fail()) // not running -> reattach
            .into_backend();
        let id = backend.open_session(&spec("alice")).expect("reattach no-op");
        assert_eq!(id.as_str(), alice_jail());
        // The jail is (re)started even though the mounts were already live.
        let calls = mock.calls();
        assert!(
            calls.iter().any(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            }),
            "reattach must still jail -c over already-live exact mounts: {calls:?}"
        );
    }

    /// destroy_session unmounts BOTH single-file pile mounts (self AND shared)
    /// plus devfs BEFORE `zfs destroy` (a dataset with mounts under its tree
    /// cannot be destroyed), and — Model B — issues NO delete of the host pile
    /// dirs or pile files: they are host-owned and outlive the jail.
    #[test]
    fn destroy_unmounts_both_piles_and_never_deletes_host_piles() {
        let (backend, mock) = mock_with_mountpoint().into_backend();
        backend
            .destroy_session(&SessionId::new(alice_jail()))
            .expect("destroy");
        let calls = mock.calls();
        let root = alice_root();
        let root = root.as_str();

        let idx_of = |suffix: &str| -> usize {
            calls
                .iter()
                .position(|c| c.last().map(String::as_str) == Some(suffix))
                .unwrap_or_else(|| panic!("missing umount of {suffix} in {calls:?}"))
        };
        let self_umount = idx_of(&format!("{root}/pile/self.pile"));
        let shared_umount = idx_of(&format!("{root}/shared/shared.pile"));
        let dev_umount = idx_of(&format!("{root}/dev"));

        // All three unmounts happen...
        for i in [self_umount, shared_umount, dev_umount] {
            assert_eq!(
                calls[i].get(2).map(String::as_str),
                Some("umount"),
                "expected an umount: {:?}",
                calls[i]
            );
        }
        // ...and all precede the zfs destroy.
        let destroy_idx = calls
            .iter()
            .position(|c| {
                c.get(2).map(String::as_str) == Some("zfs")
                    && c.get(3).map(String::as_str) == Some("destroy")
            })
            .expect("zfs destroy issued");
        assert!(
            self_umount < destroy_idx
                && shared_umount < destroy_idx
                && dev_umount < destroy_idx,
            "all pile/devfs unmounts must precede zfs destroy: {calls:?}"
        );

        // Model-B guarantee: the host pile dirs and files are NEVER removed.
        assert!(
            !calls.iter().any(|c| {
                let rm = c.iter().any(|a| a == "rm");
                let touches_piles = c.iter().any(|a| {
                    a.contains("/piles/") || a.ends_with("self.pile") || a.ends_with("shared.pile")
                });
                rm && touches_piles
            }),
            "destroy must never delete the host self/shared pile: {calls:?}"
        );
        // And it must not zfs-destroy the pile-root either (piles live outside
        // the dataset tree). The only zfs destroy is the session dataset.
        let destroys: Vec<_> = calls
            .iter()
            .filter(|c| {
                c.get(2).map(String::as_str) == Some("zfs")
                    && c.get(3).map(String::as_str) == Some("destroy")
            })
            .collect();
        assert!(
            destroys.iter().all(|c| c.last().map(String::as_str)
                == Some(alice_dataset().as_str())),
            "only the session dataset may be destroyed: {destroys:?}"
        );
    }

    /// The shared-pile seed is create-if-absent, race-safe, ATOMIC, AND
    /// tenant-unreachable: bootstrap is staged to a per-provision temp in the
    /// host-PRIVATE staging dir (never a tenant-writable path), then published
    /// into shared.pile with a no-follow / create-only HARDLINK (`ln`). It never
    /// `cp`s directly into shared.pile (non-atomic AND, historically, the symlink
    /// confused-deputy sink). The staging temp is per-jail-name so two concurrent
    /// provisions never collide, and the leftover is cleaned up. `mkdir -p` stays
    /// idempotent. Two back-to-back provisions of different tenants both publish
    /// the SAME shared.pile via create-only `ln`, so a concurrent race is a
    /// harmless no-op on the loser (the existing regular file is accepted).
    #[test]
    fn shared_pile_seed_is_atomic_and_create_if_absent() {
        for label in ["alice", "bob"] {
            let jail = JailBackend::local().jail_name(label);
            let (backend, mock) = mock_provision_ready()
                .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
                .into_backend();
            backend.provision_sandbox(&spec(label)).expect("provision");
            let calls = mock.calls();
            let shared_pile = "/aitemp/playground/piles/shared/shared.pile";
            let staging_tmp = format!("/aitemp/playground/staging/{jail}.pile.tmp");
            // Shared dir mkdir is idempotent (`-p`).
            assert!(
                calls.iter().any(|c| c
                    == &[
                        "sudo".to_string(), "-n".into(), "mkdir".into(), "-p".into(),
                        "/aitemp/playground/piles/shared".into(),
                    ]),
                "shared dir mkdir must be idempotent (-p): {calls:?}"
            );
            // Stage to the host-PRIVATE staging temp (NOT a tenant-reachable path).
            assert!(
                calls.iter().any(|c| c.ends_with(&[
                    "cp".into(),
                    "/aitemp/playground/bootstrap.pile".into(),
                    staging_tmp.clone(),
                ] as &[String])),
                "shared seed must stage to the host-private staging temp: {calls:?}"
            );
            // Publish via a create-only, no-follow HARDLINK temp -> shared.pile.
            let shared_lns: Vec<_> = calls
                .iter()
                .filter(|c| {
                    c.last().map(String::as_str) == Some(shared_pile)
                        && c.get(2).map(String::as_str) == Some("ln")
                })
                .collect();
            assert_eq!(shared_lns.len(), 1, "one create-only shared-pile publish: {calls:?}");
            assert!(
                shared_lns[0].iter().any(|a| a == staging_tmp.as_str()),
                "publish must hardlink the host-private staging temp: {:?}",
                shared_lns[0]
            );
            // The `ln` must be a plain hardlink (no `-s`): a symlink publish would
            // reintroduce a follow-through, and only a hardlink gives EEXIST
            // create-only semantics.
            assert!(
                !shared_lns[0].iter().any(|a| a == "-s"),
                "publish must be a HARDLINK (no -s), for create-only no-follow: {:?}",
                shared_lns[0]
            );
            // NEVER a `cp` straight into shared.pile — non-atomic AND the
            // historical symlink confused-deputy sink this fix removes.
            assert!(
                !calls.iter().any(|c| {
                    c.last().map(String::as_str) == Some(shared_pile)
                        && c.iter().any(|a| a == "cp")
                }),
                "must not cp directly into shared.pile (non-atomic + unsafe): {calls:?}"
            );
        }
    }

    /// Security repair #2: the bootstrap seed `cp` NEVER writes to a
    /// tenant-reachable path. Its ONLY destination is the host-private staging
    /// dir (`staging_root`, mode 0700, never mounted into a jail). This is the
    /// structural half of the symlink confused-deputy fix: a tenant cannot
    /// pre-place a symlink where the privileged `cp` writes, because the `cp`
    /// destination is unreachable to every jail.
    #[test]
    fn bootstrap_cp_only_targets_host_private_staging() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();

        // Every bootstrap `cp` must land under the staging root and nowhere else.
        let cps: Vec<_> = calls
            .iter()
            .filter(|c| c.iter().any(|a| a == "cp"))
            .collect();
        assert!(!cps.is_empty(), "at least one bootstrap cp expected: {calls:?}");
        for c in &cps {
            let dest = c.last().map(String::as_str).unwrap_or("");
            assert!(
                dest.starts_with("/aitemp/playground/staging/"),
                "every bootstrap cp must target the host-private staging dir, got {dest:?}: {c:?}"
            );
            // And it must be seeded FROM bootstrap.pile (not some other source).
            assert!(
                c.iter().any(|a| a == "/aitemp/playground/bootstrap.pile"),
                "cp source must be bootstrap.pile: {c:?}"
            );
        }
        // The staging dir is locked to 0700 before any cp reaches it.
        let chmod_idx = calls
            .iter()
            .position(|c| c.ends_with(&[
                "chmod".into(), "700".into(), "/aitemp/playground/staging".into(),
            ] as &[String]))
            .expect("staging chmod 700 issued");
        let first_cp_idx = calls
            .iter()
            .position(|c| c.iter().any(|a| a == "cp"))
            .expect("a cp issued");
        assert!(
            chmod_idx < first_cp_idx,
            "staging must be chmod 700 BEFORE the first bootstrap cp: {calls:?}"
        );
    }

    /// Security repair #2: the publish step is NO-FOLLOW and CREATE-ONLY. When
    /// the create-only hardlink (`ln`) fails AND the destination is a regular,
    /// non-symlink file, that is the benign create-if-absent no-op (a reprovision
    /// kept an accumulated pile, or a concurrent provision won the publish) — we
    /// accept it. The publish never overwrites through the existing entry.
    #[test]
    fn publish_accepts_existing_regular_file_as_noop() {
        // `ln` fails (destination exists) and the no-follow validator
        // (`sh -c "test -f && test ! -L"`) SUCCEEDS -> destination is a genuine
        // regular file, so the seed is a create-if-absent no-op, not an error.
        let (backend, _mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .reply(&["sudo", "-n", "ln"], fail())
            // default success for the `sh -c "test ..."` validator (regular file)
            .into_backend();
        // Provision must SUCCEED: the existing regular pile file is accepted.
        backend
            .provision_sandbox(&spec("alice"))
            .expect("provision succeeds when destination is an existing regular file");
    }

    /// Security repair #2: the publish REFUSES to proceed when the create-only
    /// hardlink fails AND the destination is NOT a safe regular file (a
    /// tenant-planted symlink or special file). It never mounts something a
    /// tenant may have swapped in — it fails loudly instead. This is the
    /// no-follow guard on the create-if-absent no-op path.
    #[test]
    fn publish_refuses_symlink_or_special_destination() {
        // `ln` fails (destination exists) AND the no-follow validator FAILS
        // (destination is a symlink / special file) -> provision must bail, not
        // silently proceed to mount a tenant-planted target.
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .reply(&["sudo", "-n", "ln"], fail())
            .reply(&["sudo", "-n", "sh", "-c"], fail())
            .into_backend();
        let err = backend
            .provision_sandbox(&spec("alice"))
            .expect_err("provision must refuse a non-regular destination");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("not a regular non-symlink file")
                || msg.contains("not a safe regular file"),
            "error must name the no-follow refusal: {msg}"
        );
        // The no-follow validator uses `test -f` AND `test ! -L` (the latter
        // closes the "symlink -> regular file" case that `test -f` alone would
        // follow through).
        let calls = mock.calls();
        let validator = calls
            .iter()
            .find(|c| c.get(2).map(String::as_str) == Some("sh")
                && c.get(3).map(String::as_str) == Some("-c"))
            .expect("no-follow validator issued");
        let script = validator.get(4).map(String::as_str).unwrap_or("");
        assert!(
            script.contains("test -f") && script.contains("test ! -L"),
            "validator must be no-follow (test -f && test ! -L): {script:?}"
        );
    }

    /// Security repair #2: no HOST DIRECTORY is ever nullfs-mounted into a jail —
    /// only the individual pile FILES. This is the structural half of the fix:
    /// with only file mounts, the jail's `/pile` and `/shared` are the jail's OWN
    /// clone directories (not writable host dirs), so a tenant creating siblings
    /// there only dirties the throwaway clone and can never plant an entry a
    /// privileged host operation would traverse.
    #[test]
    fn no_host_directory_is_mounted_into_a_jail() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();

        // Every nullfs mount's SOURCE (5th argv token) must be a pile FILE, never
        // a bare pile DIRECTORY.
        let nullfs_mounts: Vec<_> = calls
            .iter()
            .filter(|c| {
                c.get(2).map(String::as_str) == Some("mount")
                    && c.iter().any(|a| a == "nullfs")
            })
            .collect();
        assert!(!nullfs_mounts.is_empty(), "expected nullfs mounts: {calls:?}");
        for m in &nullfs_mounts {
            // argv shape: sudo -n mount -t nullfs <source> <target>
            let source = m.get(5).map(String::as_str).unwrap_or("");
            let target = m.get(6).map(String::as_str).unwrap_or("");
            assert!(
                source.ends_with("/self.pile") || source.ends_with("/shared.pile"),
                "nullfs SOURCE must be a pile FILE, not a host dir: {source:?} ({m:?})"
            );
            assert!(
                target.ends_with("/self.pile") || target.ends_with("/shared.pile"),
                "nullfs TARGET must be a pile FILE inside the jail clone: {target:?} ({m:?})"
            );
        }
    }

    /// Security repair #2: the host-private staging dir is DERIVED as a sibling
    /// of `pile_root`, so a `--jail-pile-root` override moves staging with it
    /// (same ZFS filesystem — the hardlink publish requires same-FS) instead of
    /// diverging to a stale hardcoded path. The default lands at
    /// `/aitemp/playground/staging`, a sibling of the default pile root and NOT
    /// under it (so it is never mounted into a jail).
    #[test]
    fn staging_root_tracks_pile_root_as_a_sibling() {
        let mut b = JailBackend::local();
        assert_eq!(b.staging_root(), "/aitemp/playground/staging");
        // The staging dir must be a SIBLING of pile_root, never under it (under
        // it would risk being reachable if pile_root's parent were mounted).
        assert!(
            !b.staging_root().starts_with(&format!("{}/", b.pile_root)),
            "staging must not live under pile_root: {}",
            b.staging_root()
        );
        // Override pile_root: staging follows to the same parent.
        b.pile_root = "/tank/pg/piles".to_string();
        assert_eq!(b.staging_root(), "/tank/pg/staging");
        assert_eq!(b.staging_pile_tmp("playground-x"), "/tank/pg/staging/playground-x.pile.tmp");
    }

    /// Security repair #2 — LIVE on the real FreeBSD host. Proves the two
    /// FreeBSD-specific properties this repair depends on, against the actual
    /// kernel (unit tests above pin the argv shape; this pins the SEMANTICS):
    ///
    ///   1. No-follow / create-only publish: a `ln` onto a pre-placed absolute
    ///      symlink at the destination FAILS and leaves the symlink's victim
    ///      target byte-for-byte untouched (the confused-deputy exploit is dead).
    ///   2. Single-file nullfs concurrent append: mounting ONE host `shared.pile`
    ///      file onto target files in two separate "jail" dirs, then appending
    ///      from both views, lands every line in the one source with no loss —
    ///      the shared-append feature the repair must preserve.
    ///
    /// Gated (talks to and mutates a scratch dir on the deploy host): run with
    /// `SANDBOX_JAIL_LIVE_TESTS=1 cargo test --bins jail_live_symlink_and_append`.
    /// Everything happens under a `mktemp -d` scratch dir and is torn down.
    #[test]
    fn jail_live_symlink_and_append() {
        if std::env::var("SANDBOX_JAIL_LIVE_TESTS").as_deref() != Ok("1") {
            eprintln!(
                "skipping: set SANDBOX_JAIL_LIVE_TESTS=1 to run (mutates a scratch \
                 dir on the FreeBSD deploy host)"
            );
            return;
        }
        let host = std::env::var("SANDBOX_JAIL_LIVE_HOST")
            .unwrap_or_else(|_| "ai.bultmann.eu".to_string());

        // One self-contained shell script: create a scratch dir, run BOTH proofs,
        // print PASS/FAIL markers, tear down. Any non-zero `set -e` step or a
        // FAIL marker fails the test.
        let script = r#"
set -eu
WORK=$(mktemp -d /tmp/jail-live-test.XXXXXX)
cleanup() {
  for f in "$WORK"/jailA/shared/shared.pile "$WORK"/jailB/shared/shared.pile; do
    sudo -n umount "$f" 2>/dev/null || true
  done
  sudo -n chflags nosappnd "$WORK/shared.pile" 2>/dev/null || true
  sudo -n rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

# ---- Proof 1: no-follow / create-only publish (ln onto a symlink) ----
echo "SECRET-VICTIM" | sudo -n tee "$WORK/victim" >/dev/null
echo "BOOTSTRAP-BYTES" | sudo -n tee "$WORK/staging.tmp" >/dev/null
# A tenant-planted absolute symlink at the publish destination.
sudo -n ln -s "$WORK/victim" "$WORK/dest"
# The publish primitive: a plain hardlink. Must FAIL (EEXIST), no follow.
if sudo -n ln "$WORK/staging.tmp" "$WORK/dest" 2>/dev/null; then
  echo "FAIL: ln onto a symlink destination SUCCEEDED (followed through)"; exit 1
fi
if [ "$(cat "$WORK/victim")" != "SECRET-VICTIM" ]; then
  echo "FAIL: victim file was overwritten through the symlink"; exit 1
fi
echo "PASS: ln refused symlink destination, victim untouched"

# ---- Proof 2: single-file nullfs concurrent shared-append ----
echo "SEED" | sudo -n tee "$WORK/shared.pile" >/dev/null
sudo -n chflags sappnd "$WORK/shared.pile"
for j in jailA jailB; do
  sudo -n mkdir -p "$WORK/$j/shared"
  sudo -n touch "$WORK/$j/shared/shared.pile"
  sudo -n mount -t nullfs "$WORK/shared.pile" "$WORK/$j/shared/shared.pile"
done
( for i in $(seq 1 50); do echo "A-$i" | sudo -n tee -a "$WORK/jailA/shared/shared.pile" >/dev/null; done ) &
( for i in $(seq 1 50); do echo "B-$i" | sudo -n tee -a "$WORK/jailB/shared/shared.pile" >/dev/null; done ) &
wait
LINES=$(wc -l < "$WORK/shared.pile" | tr -d ' ')
AC=$(grep -c '^A-' "$WORK/shared.pile" || true)
BC=$(grep -c '^B-' "$WORK/shared.pile" || true)
if [ "$LINES" != "101" ] || [ "$AC" != "50" ] || [ "$BC" != "50" ]; then
  echo "FAIL: concurrent append lost lines (total=$LINES A=$AC B=$BC, want 101/50/50)"; exit 1
fi
echo "PASS: single-file nullfs concurrent append kept all 100 lines"
"#;

        let out = Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg(&host)
            .arg(script)
            .output()
            .expect("spawn ssh to the live host");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("live-host stdout:\n{stdout}\nlive-host stderr:\n{stderr}");
        assert!(out.status.success(), "live host script failed: {stderr}");
        assert!(
            stdout.contains("PASS: ln refused symlink destination, victim untouched"),
            "missing no-follow/create-only proof: {stdout}"
        );
        assert!(
            stdout.contains("PASS: single-file nullfs concurrent append kept all 100 lines"),
            "missing concurrent-append proof: {stdout}"
        );
    }

    /// Security repair #3 — LIVE on the real FreeBSD host. Pins the two
    /// FreeBSD/ZFS SEMANTICS the fail-closed lifecycle depends on (the unit tests
    /// above pin the argv + classification against a mock; this pins the actual
    /// kernel/zfs behaviour):
    ///
    ///   1. Tri-state probe grounding: `zfs list` of a NONEXISTENT dataset exits
    ///      non-zero AND its stderr contains the canonical `dataset does not
    ///      exist` phrase — the exact signal [`JailBackend::dataset_state`] keys
    ///      `Absent` on. (An error we can't interpret would be `Unknown`.)
    ///   2. Exact-mount no-op grounding: a nullfs re-mount of the SAME source at
    ///      the SAME live target fails (EBUSY) and does NOT stack — exactly one
    ///      mount survives and a single umount clears it. This is the property the
    ///      shared mount primitive relies on to treat an already-correct reattach
    ///      mount as a verified no-op.
    ///
    /// Gated + fully torn down (mutates a scratch ZFS dataset under the deploy
    /// pool): `SANDBOX_JAIL_LIVE_TESTS=1 cargo test --bins jail_live_probe_and_mount_semantics`.
    /// `SANDBOX_JAIL_LIVE_POOL` overrides the scratch parent (default `aitemp`).
    #[test]
    fn jail_live_probe_and_mount_semantics() {
        if std::env::var("SANDBOX_JAIL_LIVE_TESTS").as_deref() != Ok("1") {
            eprintln!(
                "skipping: set SANDBOX_JAIL_LIVE_TESTS=1 to run (mutates a scratch \
                 ZFS dataset on the FreeBSD deploy host)"
            );
            return;
        }
        let host = std::env::var("SANDBOX_JAIL_LIVE_HOST")
            .unwrap_or_else(|_| "ai.bultmann.eu".to_string());
        let pool = std::env::var("SANDBOX_JAIL_LIVE_POOL").unwrap_or_else(|_| "aitemp".to_string());

        // Self-contained: prove the not-found stderr, then prove the EBUSY
        // no-op on a real nullfs single-file mount, then tear everything down.
        let script = format!(
            r#"
set -eu
POOL="{pool}"
SCRATCH="$POOL/pg-live-repair3-$$"
WORK=$(mktemp -d /tmp/jail-live-repair3.XXXXXX)
cleanup() {{
  sudo -n umount "$WORK/target" 2>/dev/null || true
  sudo -n zfs destroy -r "$SCRATCH" 2>/dev/null || true
  sudo -n rm -rf "$WORK" 2>/dev/null || true
}}
trap cleanup EXIT

# ---- Proof 1: `zfs list` of a nonexistent dataset -> canonical not-found ----
ERR=$(sudo -n zfs list "$SCRATCH" 2>&1 >/dev/null || true)
case "$ERR" in
  *"does not exist"*) echo "PASS: zfs list of an absent dataset says 'does not exist'";;
  *) echo "FAIL: absent-dataset stderr was '$ERR' (no 'does not exist' phrase)"; exit 1;;
esac

# ---- Proof 2: nullfs re-mount over a live mount is EBUSY + does not stack ----
echo "SRC" | sudo -n tee "$WORK/source" >/dev/null
sudo -n touch "$WORK/target"
sudo -n mount -t nullfs "$WORK/source" "$WORK/target"
BEFORE=$(mount | grep -c " on $WORK/target " || true)
# Re-mount the SAME source at the SAME target: must FAIL (EBUSY).
if sudo -n mount -t nullfs "$WORK/source" "$WORK/target" 2>/dev/null; then
  echo "FAIL: duplicate nullfs re-mount SUCCEEDED (should be EBUSY)"; exit 1
fi
AFTER=$(mount | grep -c " on $WORK/target " || true)
if [ "$BEFORE" != "1" ] || [ "$AFTER" != "1" ]; then
  echo "FAIL: mount stacked (before=$BEFORE after=$AFTER, want 1/1)"; exit 1
fi
sudo -n umount "$WORK/target"
STILL=$(mount | grep -c " on $WORK/target " || true)
if [ "$STILL" != "0" ]; then
  echo "FAIL: a single umount did not clear the mount (still=$STILL)"; exit 1
fi
echo "PASS: nullfs re-mount is EBUSY no-op, one umount clears it"
"#,
        );

        let out = Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg(&host)
            .arg(&script)
            .output()
            .expect("spawn ssh to the live host");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("live-host stdout:\n{stdout}\nlive-host stderr:\n{stderr}");
        assert!(out.status.success(), "live host script failed: {stderr}");
        assert!(
            stdout.contains("PASS: zfs list of an absent dataset says 'does not exist'"),
            "missing tri-state not-found grounding: {stdout}"
        );
        assert!(
            stdout.contains("PASS: nullfs re-mount is EBUSY no-op, one umount clears it"),
            "missing exact-mount no-op grounding: {stdout}"
        );
    }

    /// LIVE, env-gated (repair #4 storage bound + RACCT probe). On a scratch
    /// dataset: prove a ZFS `refquota` actually STOPS a write past the cap
    /// (`ENOSPC`), and report the host's `kern.racct.enable` so the operator
    /// knows whether the programmatic rctl path is live. Requires sudo on the
    /// FreeBSD deploy host (JP grant, scratch datasets only, torn down):
    /// `SANDBOX_JAIL_LIVE_TESTS=1 cargo test --bins jail_live_refquota_enforced`.
    /// `SANDBOX_JAIL_LIVE_POOL` overrides the scratch parent (default `aitemp`).
    #[test]
    fn jail_live_refquota_enforced() {
        if std::env::var("SANDBOX_JAIL_LIVE_TESTS").as_deref() != Ok("1") {
            eprintln!(
                "skipping: set SANDBOX_JAIL_LIVE_TESTS=1 to run (mutates a scratch \
                 ZFS dataset on the FreeBSD deploy host)"
            );
            return;
        }
        let host = std::env::var("SANDBOX_JAIL_LIVE_HOST")
            .unwrap_or_else(|_| "ai.bultmann.eu".to_string());
        let pool = std::env::var("SANDBOX_JAIL_LIVE_POOL").unwrap_or_else(|_| "aitemp".to_string());

        // Create a scratch dataset, set a tiny refquota, then prove a write that
        // exceeds it fails with ENOSPC (the pool is NOT filled — refquota bounds
        // the dataset's own referenced data). Also surface kern.racct.enable so
        // the operator note in deploy/freebsd/README.md is grounded in fact.
        let script = format!(
            r#"
set -eu
POOL="{pool}"
SCRATCH="$POOL/pg-live-repair4-$$"
cleanup() {{
  sudo -n zfs destroy -r "$SCRATCH" 2>/dev/null || true
}}
trap cleanup EXIT

# ---- Proof: refquota bounds the dataset's own writes (ENOSPC past the cap) ----
sudo -n zfs create "$SCRATCH"
sudo -n zfs set refquota=16M "$SCRATCH"
MP=$(sudo -n zfs get -H -o value mountpoint "$SCRATCH")
# Write past the 16M refquota; it MUST fail (ENOSPC) rather than fill the pool.
if sudo -n dd if=/dev/zero of="$MP/fill" bs=1M count=64 2>/dev/null; then
  echo "FAIL: a 64M write past a 16M refquota SUCCEEDED (quota not enforced)"; exit 1
fi
USED=$(sudo -n zfs get -H -o value used "$SCRATCH")
echo "PASS: refquota enforced — 64M write refused, used capped at $USED"

# ---- Report: is host RACCT enabled? (the guarded rctl path only runs if so) --
RACCT=$(sysctl -n kern.racct.enable 2>/dev/null || echo "?")
echo "INFO: kern.racct.enable=$RACCT"
"#,
        );

        let out = Command::new("ssh")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg(&host)
            .arg(&script)
            .output()
            .expect("spawn ssh to the live host");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("live-host stdout:\n{stdout}\nlive-host stderr:\n{stderr}");
        assert!(out.status.success(), "live host script failed: {stderr}");
        assert!(
            stdout.contains("PASS: refquota enforced"),
            "refquota did not bound the write: {stdout}"
        );
    }

    #[test]
    fn provision_sandbox_sanitises_label() {
        // No dataset yet: provision the fresh box; its id is the injective name
        // `<prefix>-<safe>-<digest>` — `<safe>` is the human-readable
        // sanitisation (`li ora/x` -> `li-ora-x`), and the digest disambiguates.
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], dataset_absent())
            .into_backend();
        backend.provision_sandbox(&spec("li ora/x")).expect("provision");
        let calls = mock.calls();
        let jail = backend.jail_name("li ora/x");
        // The jail -c call carries the injective name...
        assert!(calls.iter().any(|c| c.contains(&format!("name={jail}"))));
        // ...whose human-readable prefix is the sanitisation, followed by a
        // 20-hex-char digest.
        assert!(
            jail.starts_with("playground-li-ora-x-"),
            "name must keep the readable sanitisation: {jail}"
        );
        let digest = jail.strip_prefix("playground-li-ora-x-").unwrap();
        assert_eq!(digest.len(), 20, "digest is 20 hex chars: {jail}");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Security repair #1(a): `jail_name` is INJECTIVE. The three labels
    /// `a/b`, `a?b`, `a-b` all collapse to the same human-readable `<safe>`
    /// part (`a-b`) — the pre-repair bug mapped them to ONE jail name / dataset
    /// / private pile (cross-tenant hijack). The digest over the ORIGINAL label
    /// now makes all three DISTINCT, while the same label stays DETERMINISTIC
    /// (so reattach/destroy still find the exact box).
    #[test]
    fn jail_name_is_injective_across_colliding_labels() {
        let b = JailBackend::local();
        let ab_slash = b.jail_name("a/b");
        let ab_question = b.jail_name("a?b");
        let ab_dash = b.jail_name("a-b");

        // All three share the readable prefix but differ overall.
        for n in [&ab_slash, &ab_question, &ab_dash] {
            assert!(n.starts_with("playground-a-b-"), "shared readable part: {n}");
        }
        assert_ne!(ab_slash, ab_question, "a/b and a?b must differ");
        assert_ne!(ab_slash, ab_dash, "a/b and a-b must differ");
        assert_ne!(ab_question, ab_dash, "a?b and a-b must differ");

        // THREE distinct names from three distinct labels.
        let distinct: std::collections::HashSet<_> =
            [&ab_slash, &ab_question, &ab_dash].into_iter().collect();
        assert_eq!(distinct.len(), 3, "three labels -> three jail names");

        // Determinism: the same label always yields the same name (reattach).
        assert_eq!(b.jail_name("a/b"), ab_slash);
        assert_eq!(b.jail_name("alice"), b.jail_name("alice"));
    }

    /// Security repair #1(a): pathological tenant labels are rejected up front
    /// (a well-behaved principal — email / uuid / OAuth subject — always
    /// passes). Empty, control-char-bearing, and overlong labels bail; the
    /// error is clear.
    #[test]
    fn validate_label_rejects_pathological_labels() {
        // Empty.
        assert!(JailBackend::validate_label("").is_err());
        // Control chars: newline, NUL, and a C0 control.
        assert!(JailBackend::validate_label("a\nb").is_err());
        assert!(JailBackend::validate_label("a\0b").is_err());
        assert!(JailBackend::validate_label("a\x07b").is_err());
        // Overlong (past the 200-byte cap).
        assert!(JailBackend::validate_label(&"x".repeat(201)).is_err());

        // Well-behaved principals pass.
        for good in [
            "alice",
            "jp@bultmann.eu",
            "8e09ce34824a51534bee9f635cb6a81d",
            "auth0|abc123",
            &"x".repeat(200),
        ] {
            assert!(
                JailBackend::validate_label(good).is_ok(),
                "well-behaved label rejected: {good:?}"
            );
        }
    }

    /// Security repair #1(2): the reuse arm REFUSES a box whose recorded
    /// `playground:tenant` provenance does not match the requester — a digest
    /// collision or tampering must never hand one tenant another's sandbox.
    #[test]
    fn open_session_refuses_on_tenant_property_mismatch() {
        // jail is up (default success) but the dataset's recorded tenant is
        // someone else — the reuse arm must bail rather than reattach.
        let (backend, _mock) = MockRunner::default()
            .reply(
                &["zfs", "get", "-H", "-o", "value", "mountpoint"],
                ok_with_stdout(&format!("{}\n", alice_root())),
            )
            .reply(
                &["sudo", "-n", "zfs", "get", "-H", "-o", "value", "playground:tenant"],
                ok_with_stdout("someone-else\n"),
            )
            .into_backend();
        let err = backend.open_session(&spec("alice")).expect_err("must refuse");
        assert!(
            err.to_string().contains("tenant mismatch")
                || format!("{err:#}").contains("tenant mismatch"),
            "err: {err:#}"
        );
    }

    #[test]
    fn exec_wraps_in_server_side_timeout_and_jexec() {
        let (backend, mock) = MockRunner::default().into_backend();
        let req = ExecRequest {
            command: "echo hello".to_string(),
            cwd: None,
            stdin: Some(b"in-bytes".to_vec()),
            timeout: Some(Duration::from_secs(7)),
        };
        backend
            .exec(&SessionId::new("playground-alice"), &req)
            .expect("exec");
        let (argv, stdin) = mock.calls.lock().unwrap()[0].clone();
        assert_eq!(
            argv,
            vec![
                "sudo", "-n", "timeout", "-k", "5", "7", "jexec", "playground-alice",
                "/bin/sh", "-lc", "echo hello"
            ]
        );
        assert_eq!(stdin.as_deref(), Some(b"in-bytes" as &[u8]));
    }

    #[test]
    fn exec_maps_exit_124_to_timeout_error() {
        let (backend, _mock) = MockRunner::default()
            .reply(
                &["sudo", "-n", "timeout"],
                HostOutput {
                    exit_code: Some(124),
                    ..Default::default()
                },
            )
            .into_backend();
        let req = ExecRequest {
            command: "sleep 999".to_string(),
            cwd: None,
            stdin: None,
            timeout: Some(Duration::from_secs(1)),
        };
        let result = backend
            .exec(&SessionId::new("playground-alice"), &req)
            .expect("exec");
        assert_eq!(result.exit_code, Some(124));
        assert!(result.error.as_deref().unwrap_or("").contains("timed out"));
    }

    #[test]
    fn exec_applies_cwd_override() {
        let (backend, mock) = MockRunner::default().into_backend();
        let req = ExecRequest {
            command: "pwd".to_string(),
            cwd: Some(PathBuf::from("/tmp/it's here")),
            stdin: None,
            timeout: None,
        };
        backend
            .exec(&SessionId::new("playground-alice"), &req)
            .expect("exec");
        let (argv, _) = mock.calls.lock().unwrap()[0].clone();
        let script = argv.last().unwrap();
        assert!(script.starts_with("cd '/tmp/it'\\''s here' || exit 1\n"));
        assert!(script.ends_with("pwd"));
    }

    /// A tenant whose jail context is already up: open must hand back the same
    /// id WITHOUT re-cloning or re-creating the jail (persistent reuse).
    #[test]
    fn open_session_reuses_running_jail() {
        // jail is up (jls succeeds by default) and the recorded tenant matches;
        // mock_with_mountpoint scripts the `playground:tenant` read-back.
        let (backend, mock) = mock_with_mountpoint().into_backend();
        let id = backend.open_session(&spec("alice")).expect("open");
        assert_eq!(id.as_str(), alice_jail());

        let calls = mock.calls();
        // The reuse arm VERIFIES the recorded tenant provenance before handing
        // back the box.
        assert!(
            calls.iter().any(|c| c.starts_with(&[
                "sudo".to_string(), "-n".into(), "zfs".into(), "get".into(),
                "-H".into(), "-o".into(), "value".into(), "playground:tenant".into(),
            ] as &[String])),
            "reuse must verify playground:tenant provenance: {calls:?}"
        );
        // Reuse must not provision anything: no clone, no jail -c.
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("clone")),
            "reuse must not zfs clone"
        );
        assert!(
            !calls.iter().any(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            }),
            "reuse must not jail -c"
        );
    }

    /// The startup sweep: two provisioned datasets under the parent, one whose
    /// jail is already up and one whose jail is gone. Exactly one `jail -c` is
    /// issued (for the down one), the count is 1, and the `template` dataset +
    /// the parent itself are skipped. The sweep also re-establishes BOTH nullfs
    /// pile mounts (self + shared) for the down jail — mount coverage is pinned
    /// on all three attach arms (open-reattach, provision-reattach, sweep).
    #[test]
    fn reattach_all_reattaches_only_down_jails() {
        let listing = "aitemp/playground\n\
                       aitemp/playground/template\n\
                       aitemp/playground/playground-alice\n\
                       aitemp/playground/playground-bob\n";
        let (backend, mock) = MockRunner::default()
            // The enumeration query (more specific than a bare `zfs list`).
            .reply(&["sudo", "-n", "zfs", "list", "-H"], ok_with_stdout(listing))
            // alice's jail is up; bob's (and everything else) defaults to down.
            .reply(
                &["sudo", "-n", "jls", "-j", "playground-alice"],
                ok_with_stdout("1\n"),
            )
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            // Mountpoint for bob (the one being reattached).
            .reply(
                &["zfs", "get", "-H", "-o", "value", "mountpoint"],
                ok_with_stdout("/aitemp/playground/playground-bob\n"),
            )
            .into_backend();

        let n = backend.reattach_all().expect("sweep");
        assert_eq!(n, 1, "only the down jail is reattached");

        let calls = mock.calls();
        let jail_creates: Vec<_> = calls
            .iter()
            .filter(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            })
            .collect();
        assert_eq!(jail_creates.len(), 1, "exactly one jail -c");
        assert!(jail_creates[0].contains(&"name=playground-bob".to_string()));
        // The template dataset and the parent are never touched (no jail -c for
        // them, and no zfs clone anywhere — reattach never clones).
        assert!(!jail_creates[0].contains(&"name=aitemp/playground/template".to_string()));
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("clone")),
            "sweep must not clone"
        );

        // The sweep re-establishes BOTH single-file pile mounts for the down
        // jail (bob), mirroring the open-reattach mount assertions — mount
        // coverage is now pinned on the sweep arm too.
        let bob_root = "/aitemp/playground/playground-bob";
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                "/aitemp/playground/piles/playground-bob/self.pile".into(),
                format!("{bob_root}/pile/self.pile"),
            ]),
            "sweep must single-file-nullfs-mount the self.pile at /pile/self.pile for the down jail: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                "/aitemp/playground/piles/shared/shared.pile".into(),
                format!("{bob_root}/shared/shared.pile"),
            ]),
            "sweep must single-file-nullfs-mount the shared.pile at /shared/shared.pile for the down jail: {calls:?}"
        );
    }

    #[test]
    fn destroy_session_removes_jail_and_destroys_clone() {
        let (backend, mock) = mock_with_mountpoint().into_backend();
        backend
            .destroy_session(&SessionId::new("playground-alice"))
            .expect("destroy");
        let calls = mock.calls();
        assert!(calls.iter().any(|c| c.ends_with(&[
            "jail".into(), "-r".into(), "playground-alice".into()
        ] as &[String])));
        assert!(calls.iter().any(|c| c.ends_with(&[
            "zfs".into(), "destroy".into(), "aitemp/playground/playground-alice".into()
        ] as &[String])));
    }

    /// close_session on the persistent jail backend DETACHES: the box lives on,
    /// so no `jail -r` and no `zfs destroy` are issued.
    #[test]
    fn close_session_detaches_without_teardown() {
        let (backend, mock) = mock_with_mountpoint().into_backend();
        backend
            .close_session(&SessionId::new("playground-alice"))
            .expect("close");
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.ends_with(&[
                "jail".into(), "-r".into(), "playground-alice".into()
            ] as &[String])),
            "detach must not jail -r"
        );
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("zfs")
                && c.get(3).map(String::as_str) == Some("destroy")),
            "detach must not zfs destroy"
        );
    }

    #[test]
    fn destroy_session_refuses_foreign_jail_names() {
        let (backend, mock) = MockRunner::default().into_backend();
        let err = backend
            .destroy_session(&SessionId::new("trible.bultmann.eu"))
            .expect_err("must refuse");
        assert!(err.to_string().contains("outside the 'playground-' namespace"));
        // And crucially: no host command was issued at all.
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn destroy_session_fails_loud_when_destroy_fails() {
        let (backend, _mock) = mock_with_mountpoint()
            .reply(
                &["sudo", "-n", "zfs", "destroy"],
                HostOutput {
                    exit_code: Some(1),
                    stderr: b"dataset is busy".to_vec(),
                    ..Default::default()
                },
            )
            .into_backend();
        let err = backend
            .destroy_session(&SessionId::new("playground-alice"))
            .expect_err("destroy failure must surface");
        assert!(err.to_string().contains("zfs destroy"));
    }
}

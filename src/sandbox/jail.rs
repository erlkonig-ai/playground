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

use super::proc::drive_child;
use super::{ExecRequest, ExecResult, SandboxBackend, SessionId, SessionSpec};

/// Output of one host command, however it was transported. Local-backstop
/// timeouts set `timed_out`; server-side `timeout(1)` expiry shows up as
/// `exit_code == Some(124)` instead.
pub use super::proc::ChildOutput as HostOutput;

/// Default per-command timeout when an [`ExecRequest`] does not specify one.
/// Matches `super::lima::DEFAULT_EXEC_TIMEOUT`.
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);
/// Timeout for administrative host commands (zfs/jail/mount lifecycle).
const ADMIN_TIMEOUT: Duration = Duration::from_secs(120);
/// Extra local wall-clock grace on top of the server-side `timeout(1)`: the
/// server kill is authoritative; the local kill only fires if SSH itself
/// wedges.
const LOCAL_TIMEOUT_GRACE: Duration = Duration::from_secs(20);

/// Runs one argv on the jail host. The seam that makes [`JailBackend`]
/// testable without a FreeBSD server (mirror of the mock-backend pattern in
/// `crate::mcp` tests).
pub trait HostRunner: Send + Sync {
    /// Run `argv` on the host, optionally feeding `stdin`, killing after
    /// `timeout` wall-clock. Implementations must capture stdout/stderr
    /// completely (drain concurrently — a full pipe must not deadlock the
    /// child).
    fn run(&self, argv: &[String], stdin: Option<&[u8]>, timeout: Duration) -> Result<HostOutput>;

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

    /// Ensure the guest single-file mount TARGET exists: `mkdir -p` its parent
    /// dir (which is the jail's OWN clone directory — `/pile` or `/shared`) then
    /// `touch` the empty target file the pile is mounted onto. Both live inside
    /// the throwaway clone, so a tenant tampering with them (or with siblings
    /// next to them) only dirties its own box, never a host directory.
    fn ensure_mount_target(&self, target: &str) {
        // `dirname` without an extra host round-trip: the guest file paths are
        // fixed constants (`/pile/self.pile`, `/shared/shared.pile`), so the
        // parent is the substring before the final '/'.
        let parent = match target.rfind('/') {
            Some(i) => &target[..i],
            None => target,
        };
        let _ = self.run(&["sudo", "-n", "mkdir", "-p", parent], None, ADMIN_TIMEOUT);
        let _ = self.run(&["sudo", "-n", "touch", target], None, ADMIN_TIMEOUT);
    }

    /// Single-file-nullfs-mount `host_file` read-write onto `<root><guest_file>`,
    /// first ensuring the guest target file exists. Mounting the FILE (not its
    /// parent directory) is the symlink-confused-deputy fix: the jail's `/pile`
    /// and `/shared` are the jail's OWN clone dirs, never writable host dirs.
    ///
    /// The mount's own status is deliberately IGNORED — this is the REATTACH
    /// path. A re-mount of the same source file at the same live target FAILS
    /// (FreeBSD 15.1: EBUSY, "Device busy") but crucially does NOT stack: exactly
    /// one mount remains and a single `umount` clears it (verified 2026-07-24).
    /// So a re-mount over a mount that never went away is a safe no-op. The
    /// fresh-provision path uses [`JailBackend::nullfs_mount_verified`], which
    /// does NOT ignore the status (a first-mount failure there is fatal).
    fn nullfs_mount(&self, host_file: &str, root: &str, guest_file: &str) {
        let target = format!("{root}{guest_file}");
        // Ensure the target file exists on EVERY attach — reattach doesn't run
        // the fresh-provision arm that first made it.
        self.ensure_mount_target(&target);
        let _ = self.run(
            &["sudo", "-n", "mount", "-t", "nullfs", host_file, &target],
            None,
            ADMIN_TIMEOUT,
        );
    }

    /// Single-file-nullfs-mount `host_file` rw onto `<root><guest_file>` and
    /// VERIFY the mount actually took, `bail!`-ing on a real failure. Used ONLY
    /// on the fresh-provision path, where ignoring the status is dangerous: a
    /// silently failed mount leaves guest `/pile/self.pile` on the EMPTY file
    /// baked into the ZFS clone, so a faculty writes into the clone — which
    /// `destroy_session` then `zfs destroy`s (silent data loss). We confirm the
    /// mountpoint appears in `mount` output before trusting it. (On reattach the
    /// EBUSY no-op from [`JailBackend::nullfs_mount`] applies instead, so
    /// verification there would false-positive on the harmless duplicate.)
    fn nullfs_mount_verified(&self, host_file: &str, root: &str, guest_file: &str) -> Result<()> {
        let target = format!("{root}{guest_file}");
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
        // Post-condition: the target must actually be a mountpoint now. A
        // silently-failed mount (exit 0 but nothing mounted) would leave
        // /pile/self.pile on the empty clone file; catch it here, before
        // /etc/profile points PILE at it.
        let check = self.run(&["sudo", "-n", "mount"], None, ADMIN_TIMEOUT)?;
        if !check.success() {
            bail!("verify mount {target}: `mount` failed: {}", check.stderr_lossy());
        }
        let listing = String::from_utf8_lossy(&check.stdout);
        // `mount` prints one line per filesystem as "src on TARGET (type, …)";
        // require the exact target as a whitespace-delimited token so
        // /pile/self.pile does not match a substring.
        let mounted = listing
            .lines()
            .any(|line| line.split_whitespace().any(|tok| tok == target));
        if !mounted {
            bail!("nullfs mount {host_file} -> {target} did not take (not in `mount` output)");
        }
        Ok(())
    }

    /// Re-establish BOTH single-file pile mounts (self + shared) over a jail root
    /// on the REATTACH path — the mounts do NOT survive a jail restart, exactly
    /// like the devfs mount. Status is ignored: a re-mount over a still-live
    /// mount is a safe no-op (see `nullfs_mount`). Each mount first ensures its
    /// guest target file exists, so reattach works even though it never ran the
    /// fresh-provision arm that originally made them.
    fn mount_piles(&self, jail: &str, root: &str) {
        self.nullfs_mount(&self.self_pile_file(jail), root, Self::GUEST_SELF_PILE);
        self.nullfs_mount(&self.shared_pile_file(), root, Self::GUEST_SHARED_PILE);
    }

    /// Fresh-provision variant of [`JailBackend::mount_piles`]: mount BOTH piles
    /// and VERIFY each took (see `nullfs_mount_verified`). A failure `bail!`s,
    /// which on the provision path cleanly triggers `cleanup_leftovers` —
    /// preferable to a silently-empty /pile that later gets `zfs destroy`ed.
    fn mount_piles_verified(&self, jail: &str, root: &str) -> Result<()> {
        self.nullfs_mount_verified(&self.self_pile_file(jail), root, Self::GUEST_SELF_PILE)?;
        self.nullfs_mount_verified(&self.shared_pile_file(), root, Self::GUEST_SHARED_PILE)?;
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

    /// True iff the ZFS dataset exists. `zfs list <dataset>` exits 0 when the
    /// dataset is present, non-zero otherwise.
    fn dataset_exists(&self, dataset: &str) -> bool {
        self.run(&["sudo", "-n", "zfs", "list", dataset], None, ADMIN_TIMEOUT)
            .map(|o| o.success())
            .unwrap_or(false)
    }

    /// Re-establish a jail context over an EXISTING persistent dataset: the
    /// ephemeral devfs mount (does not survive a reboot) plus `jail -c`. The
    /// dataset and its `/etc/profile` are left exactly as they are — this
    /// clones nothing and re-seeds nothing. Shared by `open_session`'s reattach
    /// arm, `provision_sandbox`'s already-provisioned arm, and `reattach_all`.
    ///
    /// The devfs re-mount's own status is deliberately ignored: if /dev is
    /// already mounted from a still-live mount, the mount fails with "already
    /// mounted" and that is fine; any other failure leaves /dev broken, which
    /// the first `jexec` surfaces loudly (a broken /dev shows up at exec time,
    /// not attach time — cleaner than brittle stderr matching here).
    ///
    /// The two single-file pile mounts (self + shared) are re-established the
    /// same ignore-status way, but for a DIFFERENT mechanism than devfs's
    /// "already mounted": a duplicate single-file nullfs mount of the same source
    /// at the same live target FAILS with EBUSY ("Device busy") and does NOT
    /// stack (verified on FreeBSD 15.1, 2026-07-24 — exactly one mount survives a
    /// re-mount over a live one, and a single umount clears it). So a re-mount
    /// over a still-live pile mount is a safe no-op here. Note this is the
    /// reattach path; the first-ever provision uses the VERIFIED mount
    /// (`mount_piles_verified`), where a silent mount failure is fatal.
    fn reattach(&self, jail: &str, dataset: &str) -> Result<()> {
        let root = self.mountpoint(dataset)?;
        let _ = self.run(
            &[
                "sudo", "-n", "mount", "-t", "devfs", "-o", "ruleset=4", "devfs",
                &format!("{root}/dev"),
            ],
            None,
            ADMIN_TIMEOUT,
        );
        // Pile mounts do not survive a jail restart either — re-establish both.
        self.mount_piles(jail, &root);
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

        // Pure reuse-or-reattach: the box must already be provisioned (via
        // `provision_sandbox` / `playground user create`). open NEVER clones.

        // 1. Already up? The tenant's jail context is running over its dataset;
        //    just hand back the same id — no `jail -c`, no re-seed. First VERIFY
        //    the dataset's recorded tenant matches the requester (authoritative
        //    injectivity check): a mismatch means a digest collision or
        //    tampering, and we refuse rather than hand over another tenant's box.
        if self.jail_running(&jail) {
            self.verify_tenant_property(&dataset, &spec.tenant.label)
                .with_context(|| format!("verify tenant provenance for jail '{jail}'"))?;
            eprintln!("[{}] reusing persistent sandbox '{}'", self.name(), jail);
            return Ok(SessionId::new(jail));
        }

        // 2. Not running, but the persistent dataset exists (host reboot /
        //    playground restart wiped the jail context). Re-attach it: devfs
        //    re-mount + `jail -c`, keeping the dataset and its /etc/profile as
        //    they are. Never destroy the dataset on a transient failure — it is
        //    the tenant's PERSISTENT storage. VERIFY the recorded tenant first,
        //    same as the reuse arm.
        if self.dataset_exists(&dataset) {
            self.verify_tenant_property(&dataset, &spec.tenant.label)
                .with_context(|| format!("verify tenant provenance for jail '{jail}'"))?;
            eprintln!("[{}] reattaching persistent sandbox '{}'", self.name(), jail);
            self.reattach(&jail, &dataset)
                .with_context(|| format!("reattach jail '{jail}'"))?;
            return Ok(SessionId::new(jail));
        }

        // 3. No dataset at all: the tenant was never provisioned.
        bail!(
            "sandbox for tenant '{}' is not provisioned — run `playground user create {}`",
            spec.tenant.label,
            spec.tenant.label
        )
    }

    fn provision_sandbox(&self, spec: &SessionSpec) -> Result<()> {
        Self::validate_label(&spec.tenant.label)?;
        let jail = self.jail_name(&spec.tenant.label);
        let dataset = self.dataset(&jail);

        // Idempotent: a tenant whose dataset already exists is already
        // provisioned. Don't clone or re-seed; just ensure the jail is up so
        // `provision` doubles as "converge to running" (reattach if the jail
        // context is gone). VERIFY the recorded tenant first (authoritative
        // injectivity check), same as `open_session`'s reuse arms.
        if self.dataset_exists(&dataset) {
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

        eprintln!(
            "[{}] provisioning new persistent sandbox '{}' (dataset {})",
            self.name(),
            jail,
            dataset
        );

        // Brand-new tenant: clone the template, then set up /dev, cwd, and
        // /etc/profile from scratch, then `jail -c`.
        let provision = (|| -> Result<()> {
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

            // Record the ORIGINAL tenant label on the dataset immediately after
            // the clone: this is the authoritative provenance the reuse/reattach
            // arms verify against (defence-in-depth over the jail-name digest).
            self.set_tenant_property(&dataset, &spec.tenant.label)?;

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

            // single-file-nullfs-mount BOTH pile files rw (each touches its own
            // guest target file first). The mounts themselves do not survive a jail
            // restart (re-established by `reattach`), but they must be live for
            // this first `jail -c`. On the fresh-provision path we VERIFY each
            // mount took: a silently-failed mount would leave guest /pile on the
            // EMPTY dir baked into the clone, so PILE=/pile/self.pile writes into
            // the clone, which destroy_session then `zfs destroy`s — silent data
            // loss. A bail! here cleanly triggers cleanup_leftovers.
            self.mount_piles_verified(&jail, &root)?;

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
            Ok(())
        })();

        if let Err(e) = provision {
            // A brand-new box that failed to provision must not leak a
            // half-made dataset.
            self.cleanup_leftovers(&jail);
            return Err(e.context(format!("provision jail '{jail}'")));
        }
        Ok(())
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

        let timeout = request.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);
        // Server-side kill is authoritative: FreeBSD timeout(1) exits 124 and
        // actually terminates the process tree on the server (a local ssh kill
        // alone would leave the remote command running).
        let secs = timeout.as_secs().max(1).to_string();
        let argv = [
            "sudo", "-n", "timeout", "-k", "5", &secs, "jexec", jail, "/bin/sh", "-lc", &script,
        ];

        let out = self.run(&argv, request.stdin.as_deref(), timeout + LOCAL_TIMEOUT_GRACE)?;

        let mut result = ExecResult {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
            error: None,
        };
        if out.timed_out || out.exit_code == Some(124) {
            // Mirror LimaBackend: timeouts surface as exit 124 + error text.
            result.exit_code = Some(124);
            result.error = Some(format!("command timed out after {timeout:?}"));
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

        // Destroy the dataset. This MUST succeed or we leak the session dataset;
        // one retry covers transient "dataset is busy" races after jail -r.
        let mut destroy = self.run(&["sudo", "-n", "zfs", "destroy", &dataset], None, ADMIN_TIMEOUT)?;
        if !destroy.success() {
            std::thread::sleep(Duration::from_secs(2));
            destroy = self.run(&["sudo", "-n", "zfs", "destroy", &dataset], None, ADMIN_TIMEOUT)?;
        }
        if !destroy.success() {
            bail!("zfs destroy {dataset} failed: {}", destroy.stderr_lossy());
        }
        Ok(())
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
    #[derive(Default)]
    struct MockRunner {
        calls: Mutex<Vec<(Vec<String>, Option<Vec<u8>>)>>,
        /// (argv-prefix-to-match, canned output)
        script: Vec<(Vec<&'static str>, HostOutput)>,
    }

    impl MockRunner {
        fn reply(mut self, prefix: &[&'static str], out: HostOutput) -> Self {
            self.script.push((prefix.to_vec(), out));
            self
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().iter().map(|(a, _)| a.clone()).collect()
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
            for (prefix, out) in &self.script {
                if argv.len() >= prefix.len()
                    && argv.iter().zip(prefix.iter()).all(|(a, p)| a == p)
                {
                    return Ok(out.clone());
                }
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

    /// A non-zero exit: used to script "jail not running" / "dataset absent".
    fn fail() -> HostOutput {
        HostOutput {
            exit_code: Some(1),
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

    /// A `mount` listing that shows BOTH single-file pile mounts live under
    /// alice's jail root, in the `src on TARGET (type, …)` shape FreeBSD `mount`
    /// prints. The fresh-provision path calls bare `mount` to VERIFY each nullfs
    /// mount took (matching the exact guest FILE target token); scripting this
    /// satisfies that post-condition. Keyed on the bare `["sudo","-n","mount"]`
    /// prefix, which also matches the `mount -t nullfs` / `mount -t devfs` calls
    /// — harmless, they only need exit 0.
    fn mount_listing_for_alice() -> HostOutput {
        let jail = alice_jail();
        let root = alice_root();
        ok_with_stdout(&format!(
            "{}/{jail} on {root} (zfs, local, nfsv4acls)\n\
             /aitemp/playground/piles/{jail}/self.pile on {root}/pile/self.pile (nullfs, local)\n\
             /aitemp/playground/piles/shared/shared.pile on {root}/shared/shared.pile (nullfs, local)\n\
             devfs on {root}/dev (devfs)\n",
            "aitemp/playground"
        ))
    }

    /// Mock ready for the fresh-provision path: mountpoint query + the `mount`
    /// verify listing showing both pile mounts live.
    fn mock_provision_ready() -> MockRunner {
        mock_with_mountpoint().reply(&["sudo", "-n", "mount"], mount_listing_for_alice())
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
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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
                .reply(&["sudo", "-n", "zfs", "list"], fail())
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
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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

    #[test]
    fn provision_sandbox_sanitises_label() {
        // No dataset yet: provision the fresh box; its id is the injective name
        // `<prefix>-<safe>-<digest>` — `<safe>` is the human-readable
        // sanitisation (`li ora/x` -> `li-ora-x`), and the digest disambiguates.
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], fail())
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

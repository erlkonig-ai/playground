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
//! the server under `pile_root`. Two host-owned piles are mounted in via
//! `nullfs` (which mounts DIRECTORIES, not single files, so the layout is a
//! dir-per-tenant + one shared dir):
//!
//!   - **`self.pile`** — per-tenant, host <pile_root>/<jail>/self.pile,
//!     nullfs-mounted **rw** at guest `/pile` (so `PILE=/pile/self.pile`).
//!     Seeded by copying `bootstrap_pile` at provision if absent. **Model B:
//!     DECOUPLED from the jail lifecycle** — destroying the jail unmounts but
//!     never deletes it, and a re-provision reattaches the same accumulated
//!     pile.
//!   - **`shared.pile`** — a SINGLE host file shared by ALL tenant jails,
//!     host <pile_root>/shared/shared.pile, nullfs-mounted **rw** at guest
//!     `/shared` (same append-only semantics as self.pile; multiple concurrent
//!     writers appending one pile is supported). Seeded once, race-safely;
//!     never deleted by a single-tenant teardown.
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

    /// Deterministic jail name for a tenant label. Jail names and ZFS dataset
    /// components share the safe alphabet `[A-Za-z0-9-]` here; anything else
    /// in the label is mapped to `-` (mirrors Lima's instance sanitisation).
    ///
    /// Public so the `user` CLI derives the same `<prefix>-<sanitised>` name the
    /// backend uses — the two must agree on session ids (destroy, reattach).
    pub fn jail_name(&self, label: &str) -> String {
        let safe: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("{}-{}", self.jail_prefix, safe)
    }

    fn dataset(&self, jail: &str) -> String {
        format!("{}/{}", self.dataset_parent, jail)
    }

    /// Host directory that holds this coworker's `self.pile` (Model B: owned by
    /// the host, decoupled from the jail dataset — surviving jail teardown). It
    /// is nullfs-mounted rw at the jail's `/pile`.
    fn self_pile_dir(&self, jail: &str) -> String {
        format!("{}/{}", self.pile_root, jail)
    }

    /// Host directory that holds the single `shared.pile` all coworker jails
    /// append to concurrently. Nullfs-mounted rw at every jail's `/shared`.
    fn shared_pile_dir(&self) -> String {
        format!("{}/shared", self.pile_root)
    }

    /// Guest mountpoint (absolute path under the jail root) for the per-coworker
    /// pile dir. `self.pile` therefore lands at guest `/pile/self.pile`.
    const GUEST_PILE_DIR: &'static str = "/pile";
    /// Guest mountpoint for the shared pile dir. `shared.pile` lands at guest
    /// `/shared/shared.pile`.
    const GUEST_SHARED_DIR: &'static str = "/shared";

    /// Nullfs-mount `host_dir` read-write onto `<root><guest_dir>`, first
    /// `mkdir -p`-ing the guest mountpoint so an attach never fails for a
    /// missing target (harmless no-op when it already exists, e.g. the
    /// fresh-provision path already made it).
    ///
    /// The mount's own status is deliberately IGNORED, and this is safe for a
    /// specific FreeBSD nullfs reason (NOT the devfs "already mounted" one):
    /// FreeBSD nullfs REFUSES a duplicate mount of the same source at the same
    /// mountpoint with EDEADLK ("Resource deadlock avoided") — the mount does
    /// NOT stack. Empirically (FreeBSD 15.1) exactly one mount remains after a
    /// re-mount over a still-live mount, and a single `umount` clears it. So a
    /// re-mount on reattach over a mount that never went away is a genuine
    /// no-op, and ignoring the status is correct. This is the reattach path;
    /// the fresh-provision path uses [`JailBackend::nullfs_mount_verified`],
    /// which does NOT ignore the status (a first-mount failure there is fatal —
    /// see that method).
    ///
    /// nullfs mounts DIRECTORIES (not single files), which is why the layout is
    /// dir-per-coworker + a shared dir, with the pile files living inside.
    fn nullfs_mount(&self, host_dir: &str, root: &str, guest_dir: &str) {
        let target = format!("{root}{guest_dir}");
        // mkdir the mountpoint on EVERY attach — reattach doesn't run the
        // fresh-provision arm that first made it, and `mkdir -p` is a no-op
        // when it already exists.
        let _ = self.run(&["sudo", "-n", "mkdir", "-p", &target], None, ADMIN_TIMEOUT);
        let _ = self.run(
            &["sudo", "-n", "mount", "-t", "nullfs", host_dir, &target],
            None,
            ADMIN_TIMEOUT,
        );
    }

    /// Nullfs-mount `host_dir` rw onto `<root><guest_dir>` and VERIFY the mount
    /// actually took, `bail!`-ing on a real failure. Used ONLY on the
    /// fresh-provision path, where ignoring the status is dangerous: a silently
    /// failed mount leaves guest `/pile` pointing at the EMPTY dir baked into
    /// the ZFS clone, so a faculty writes into the clone — which
    /// `destroy_session` then `zfs destroy`s (silent data loss). We confirm the
    /// mountpoint appears in `mount` output before trusting it. (On reattach the
    /// nullfs EDEADLK no-op from [`JailBackend::nullfs_mount`] applies instead,
    /// so verification there would false-positive on the harmless duplicate.)
    fn nullfs_mount_verified(&self, host_dir: &str, root: &str, guest_dir: &str) -> Result<()> {
        let target = format!("{root}{guest_dir}");
        let mkdir = self.run(&["sudo", "-n", "mkdir", "-p", &target], None, ADMIN_TIMEOUT)?;
        if !mkdir.success() {
            bail!("mkdir guest mountpoint {target} failed: {}", mkdir.stderr_lossy());
        }
        let mount = self.run(
            &["sudo", "-n", "mount", "-t", "nullfs", host_dir, &target],
            None,
            ADMIN_TIMEOUT,
        )?;
        if !mount.success() {
            bail!("nullfs mount {host_dir} -> {target} failed: {}", mount.stderr_lossy());
        }
        // Post-condition: the target must actually be a mountpoint now. A
        // silently-failed mount (exit 0 but nothing mounted) would leave /pile
        // on the empty clone dir; catch it here, before /etc/profile points
        // PILE at it.
        let check = self.run(&["sudo", "-n", "mount"], None, ADMIN_TIMEOUT)?;
        if !check.success() {
            bail!("verify mount {target}: `mount` failed: {}", check.stderr_lossy());
        }
        let listing = String::from_utf8_lossy(&check.stdout);
        // `mount` prints one line per filesystem as "src on TARGET (type, …)";
        // require the exact target as a whitespace-delimited token so /pile
        // does not match /pile2 or a substring.
        let mounted = listing
            .lines()
            .any(|line| line.split_whitespace().any(|tok| tok == target));
        if !mounted {
            bail!("nullfs mount {host_dir} -> {target} did not take (not in `mount` output)");
        }
        Ok(())
    }

    /// Re-establish BOTH nullfs pile mounts (self + shared) over a jail root on
    /// the REATTACH path — the mounts do NOT survive a jail restart, exactly
    /// like the devfs mount. Status is ignored: a re-mount over a still-live
    /// mount is FreeBSD nullfs's EDEADLK no-op (see `nullfs_mount`). Each mount
    /// first `mkdir -p`s its guest mountpoint, so reattach works even though it
    /// never ran the fresh-provision arm that originally made them.
    fn mount_piles(&self, jail: &str, root: &str) {
        self.nullfs_mount(&self.self_pile_dir(jail), root, Self::GUEST_PILE_DIR);
        self.nullfs_mount(&self.shared_pile_dir(), root, Self::GUEST_SHARED_DIR);
    }

    /// Fresh-provision variant of [`JailBackend::mount_piles`]: mount BOTH piles
    /// and VERIFY each took (see `nullfs_mount_verified`). A failure `bail!`s,
    /// which on the provision path cleanly triggers `cleanup_leftovers` —
    /// preferable to a silently-empty /pile that later gets `zfs destroy`ed.
    fn mount_piles_verified(&self, jail: &str, root: &str) -> Result<()> {
        self.nullfs_mount_verified(&self.self_pile_dir(jail), root, Self::GUEST_PILE_DIR)?;
        self.nullfs_mount_verified(&self.shared_pile_dir(), root, Self::GUEST_SHARED_DIR)?;
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
            // the two nullfs pile mounts plus devfs — so the zfs destroy below
            // is not blocked. Host pile dirs themselves are never removed.
            for guest in [Self::GUEST_PILE_DIR, Self::GUEST_SHARED_DIR, "/dev"] {
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
    /// The two nullfs pile mounts (self + shared) are re-established the same
    /// ignore-status way, but for a DIFFERENT mechanism than devfs's "already
    /// mounted": FreeBSD nullfs refuses a duplicate mount of the same source at
    /// the same mountpoint with EDEADLK ("Resource deadlock avoided") and does
    /// NOT stack (verified on FreeBSD 15.1 — exactly one mount survives a
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
        //    just hand back the same id — no `jail -c`, no re-seed.
        if self.jail_running(&jail) {
            eprintln!("[{}] reusing persistent sandbox '{}'", self.name(), jail);
            return Ok(SessionId::new(jail));
        }

        // 2. Not running, but the persistent dataset exists (host reboot /
        //    playground restart wiped the jail context). Re-attach it: devfs
        //    re-mount + `jail -c`, keeping the dataset and its /etc/profile as
        //    they are. Never destroy the dataset on a transient failure — it is
        //    the tenant's PERSISTENT storage.
        if self.dataset_exists(&dataset) {
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
        let jail = self.jail_name(&spec.tenant.label);
        let dataset = self.dataset(&jail);

        // Idempotent: a tenant whose dataset already exists is already
        // provisioned. Don't clone or re-seed; just ensure the jail is up so
        // `provision` doubles as "converge to running" (reattach if the jail
        // context is gone).
        if self.dataset_exists(&dataset) {
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

            // Model-B pile provisioning: two HOST-OWNED piles mounted into the
            // jail, decoupled from the dataset lifecycle.
            //
            //   host <pile_root>/<jail>/self.pile  -> nullfs rw -> guest /pile
            //   host <pile_root>/shared/shared.pile -> nullfs rw -> guest /shared
            //
            // These live OUTSIDE the ZFS clone tree, so destroy_session (which
            // destroys the dataset) never touches them. The `self.pile` is the
            // tenant's server-born pile under `pile_root`, distinct from the
            // caller-supplied `spec.tenant.pile` path (not used by this backend).
            let self_dir = self.self_pile_dir(&jail);
            let self_pile = format!("{self_dir}/self.pile");
            let shared_dir = self.shared_pile_dir();
            let shared_pile = format!("{shared_dir}/shared.pile");

            // Per-coworker pile dir + seed self.pile from bootstrap if absent.
            let mkdir_self = self.run(
                &["sudo", "-n", "mkdir", "-p", &self_dir],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !mkdir_self.success() {
                bail!("mkdir self pile dir failed: {}", mkdir_self.stderr_lossy());
            }
            // Copy-if-absent: `cp -n` never clobbers an existing self.pile, so a
            // reprovision keeps the coworker's accumulated pile.
            let seed_self = self.run(
                &["sudo", "-n", "cp", "-n", &self.bootstrap_pile, &self_pile],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !seed_self.success() {
                bail!("seed self.pile from bootstrap failed: {}", seed_self.stderr_lossy());
            }
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
            // Create-if-absent and race-safe against concurrent provisions —
            // but the seed must be ATOMIC. `cp -n bootstrap shared.pile` is
            // create-if-absent yet NOT atomic: a second provision's `cp -n` can
            // see the target already exists mid-copy and no-op, then a coworker
            // mounts and appends to a still-PARTIAL shared.pile (torn tail ->
            // CorruptPile). So publish atomically: `cp` bootstrap to a
            // per-provision temp in the same dir, then `mv -n` (atomic same-FS
            // rename) into place. The loser's `mv -n` no-ops on an existing
            // target and no reader ever sees a partial file; we clean up the
            // temp when the mv no-ops. (`mkdir -p` stays idempotent; same
            // append-only semantics as self.pile — many concurrent appenders on
            // one pile is fine.)
            let mkdir_shared = self.run(
                &["sudo", "-n", "mkdir", "-p", &shared_dir],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !mkdir_shared.success() {
                bail!("mkdir shared pile dir failed: {}", mkdir_shared.stderr_lossy());
            }
            // Per-provision temp in the SAME dir (so `mv` is a same-FS rename,
            // hence atomic). Namespaced by jail name so two concurrent
            // provisions never share a temp path.
            let shared_tmp = format!("{shared_dir}/shared.pile.{jail}.tmp");
            let cp_tmp = self.run(
                &["sudo", "-n", "cp", &self.bootstrap_pile, &shared_tmp],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !cp_tmp.success() {
                bail!("stage shared.pile temp from bootstrap failed: {}", cp_tmp.stderr_lossy());
            }
            // Atomic publish: `mv -n` renames into shared.pile only if it does
            // not already exist. The winner installs a complete file in one
            // rename; a loser no-ops (target exists) and leaves its temp behind,
            // which we then remove. Either way no reader observes a partial
            // shared.pile.
            let mv_shared = self.run(
                &["sudo", "-n", "mv", "-n", &shared_tmp, &shared_pile],
                None,
                ADMIN_TIMEOUT,
            )?;
            if !mv_shared.success() {
                bail!("atomic publish shared.pile failed: {}", mv_shared.stderr_lossy());
            }
            // Clean up the temp if the `mv -n` no-op'd (a concurrent provision
            // won the publish, so our temp still sits in the shared dir).
            // Best-effort: a leftover temp is harmless clutter, not a hazard.
            let _ = self.run(&["sudo", "-n", "rm", "-f", &shared_tmp], None, ADMIN_TIMEOUT);
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

            // nullfs-mount BOTH pile dirs rw (each mkdir's its own guest
            // mountpoint first). The mounts themselves do not survive a jail
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
                shell_quote(&format!("{}/self.pile", Self::GUEST_PILE_DIR))
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

        // Unmount devfs AND the two nullfs pile mounts (must precede zfs
        // destroy: a dataset with mounts anywhere under its tree cannot be
        // destroyed — enforce_statfs). Model B: we unmount the piles but NEVER
        // delete the host self.pile or shared.pile — they are host-owned and
        // outlive the jail (a re-provision reattaches the same self.pile).
        if let Ok(root) = self.mountpoint(&dataset) {
            for guest in [Self::GUEST_PILE_DIR, Self::GUEST_SHARED_DIR, "/dev"] {
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

    /// The mountpoint query needs a scripted reply everywhere.
    fn mock_with_mountpoint() -> MockRunner {
        MockRunner::default().reply(
            &["zfs", "get", "-H", "-o", "value", "mountpoint"],
            ok_with_stdout("/aitemp/playground/playground-alice\n"),
        )
    }

    /// A `mount` listing that shows BOTH pile mounts live under alice's jail
    /// root, in the `src on TARGET (type, …)` shape FreeBSD `mount` prints. The
    /// fresh-provision path calls bare `mount` to VERIFY each nullfs mount took;
    /// scripting this satisfies that post-condition. Keyed on the bare
    /// `["sudo","-n","mount"]` prefix, which also matches the `mount -t nullfs`
    /// / `mount -t devfs` calls — harmless, they only need exit 0.
    fn mount_listing_for_alice() -> HostOutput {
        let root = "/aitemp/playground/playground-alice";
        ok_with_stdout(&format!(
            "aitemp/playground/playground-alice on {root} (zfs, local, nfsv4acls)\n\
             /aitemp/playground/piles/playground-alice on {root}/pile (nullfs, local)\n\
             /aitemp/playground/piles/shared on {root}/shared (nullfs, local)\n\
             devfs on {root}/dev (devfs)\n"
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

        // Must clone the template into the namespaced dataset...
        assert!(calls.iter().any(|c| c.starts_with(&[
            "sudo".into(), "-n".into(), "zfs".into(), "clone".into(),
            "aitemp/playground/template@base".into(),
            "aitemp/playground/playground-alice".into(),
        ] as &[String])));
        // ...and create a jail with no network, correct name/path.
        let jail_call = calls
            .iter()
            .find(|c| {
                c.get(2).map(String::as_str) == Some("jail")
                    && c.get(3).map(String::as_str) == Some("-c")
            })
            .expect("jail -c issued");
        assert!(jail_call.contains(&"name=playground-alice".to_string()));
        assert!(jail_call.contains(&"path=/aitemp/playground/playground-alice".to_string()));
        assert!(jail_call.contains(&"ip4=disable".to_string()));
        assert!(jail_call.contains(&"ip6=disable".to_string()));
        assert!(jail_call.contains(&"persist".to_string()));
    }

    /// Model-B pile provisioning: a brand-new tenant gets BOTH host-owned piles
    /// nullfs-mounted rw (self at guest /pile, shared at guest /shared), the
    /// bootstrap.pile copied into an absent self.pile (and the shared pile), the
    /// guest mountpoints made, and /etc/profile seeded with the faculties PATH +
    /// PILE=/pile/self.pile. The piles derive from `pile_root`+jail name, NOT
    /// from the caller-supplied `spec.tenant.pile` path.
    #[test]
    fn provision_mounts_both_piles_seeds_path_and_pile() {
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], fail())
            .into_backend();
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();
        let root = "/aitemp/playground/playground-alice";

        // Default pile-root derived paths.
        let self_dir = "/aitemp/playground/piles/playground-alice";
        let self_pile = format!("{self_dir}/self.pile");
        let shared_dir = "/aitemp/playground/piles/shared";
        let shared_pile = format!("{shared_dir}/shared.pile");

        // Host per-coworker pile dir is created.
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "mkdir".into(), "-p".into(), self_dir.into()
            ] as &[String])),
            "must mkdir the per-coworker pile dir: {calls:?}"
        );
        // self.pile seeded from bootstrap.pile, copy-if-absent (`cp -n`), from
        // the configured bootstrap path — NOT the caller-supplied pile path.
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "cp".into(), "-n".into(),
                "/aitemp/playground/bootstrap.pile".into(),
                self_pile.clone(),
            ] as &[String])),
            "must cp -n bootstrap.pile into self.pile: {calls:?}"
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
        // Shared dir + shared.pile seeded create-if-absent (idempotent),
        // published ATOMICALLY: bootstrap is `cp`'d to a per-provision temp in
        // the shared dir, then `mv -n`'d into shared.pile (atomic same-FS
        // rename) so no reader ever sees a partial file.
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "mkdir".into(), "-p".into(), shared_dir.into()
            ] as &[String])),
            "must mkdir the shared pile dir: {calls:?}"
        );
        let shared_tmp = format!("{shared_dir}/shared.pile.playground-alice.tmp");
        // Stage: cp bootstrap -> per-provision temp (NOT directly to shared.pile).
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "cp".into(),
                "/aitemp/playground/bootstrap.pile".into(),
                shared_tmp.clone(),
            ] as &[String])),
            "must cp bootstrap.pile into a per-provision temp: {calls:?}"
        );
        // Publish: mv -n temp -> shared.pile (atomic, create-if-absent).
        assert!(
            calls.iter().any(|c| c.ends_with(&[
                "mv".into(), "-n".into(),
                shared_tmp.clone(),
                shared_pile.clone(),
            ] as &[String])),
            "must atomic-publish via mv -n temp -> shared.pile: {calls:?}"
        );
        // No non-atomic direct cp into shared.pile.
        assert!(
            !calls.iter().any(|c| c.last().map(String::as_str) == Some(shared_pile.as_str())
                && c.iter().any(|a| a == "cp")),
            "must NOT cp directly into shared.pile (non-atomic): {calls:?}"
        );

        // BOTH nullfs mounts, rw, host-dir -> guest-mountpoint.
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(), self_dir.to_string(), format!("{root}/pile"),
            ]),
            "must nullfs-mount self pile dir at /pile: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(), shared_dir.to_string(), format!("{root}/shared"),
            ]),
            "must nullfs-mount shared pile dir at /shared: {calls:?}"
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
        assert_eq!(id.as_str(), "playground-alice");

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

    /// Reattach re-establishes BOTH nullfs pile mounts (self + shared) — they do
    /// not survive a jail restart, exactly like the devfs re-mount — without
    /// re-seeding self.pile or the profile (the persisted host piles carry
    /// their accumulated content).
    #[test]
    fn reattach_remounts_both_piles() {
        let (backend, mock) = mock_with_mountpoint()
            .reply(&["sudo", "-n", "jls", "-j"], fail())
            // dataset present (default success) -> reattach on open.
            .into_backend();
        backend.open_session(&spec("alice")).expect("open");
        let calls = mock.calls();
        let root = "/aitemp/playground/playground-alice";

        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                "/aitemp/playground/piles/playground-alice".into(),
                format!("{root}/pile"),
            ]),
            "reattach must re-mount the self pile at /pile: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                "/aitemp/playground/piles/shared".into(),
                format!("{root}/shared"),
            ]),
            "reattach must re-mount the shared pile at /shared: {calls:?}"
        );
        // Reattach seeds nothing: no bootstrap copy.
        assert!(
            !calls.iter().any(|c| c.get(2).map(String::as_str) == Some("cp")),
            "reattach must not re-seed a pile: {calls:?}"
        );
    }

    /// destroy_session unmounts BOTH nullfs pile mounts (self AND shared) plus
    /// devfs BEFORE `zfs destroy` (a dataset with mounts under its tree cannot
    /// be destroyed), and — Model B — issues NO delete of the host pile dirs or
    /// pile files: they are host-owned and outlive the jail.
    #[test]
    fn destroy_unmounts_both_piles_and_never_deletes_host_piles() {
        let (backend, mock) = mock_with_mountpoint().into_backend();
        backend
            .destroy_session(&SessionId::new("playground-alice"))
            .expect("destroy");
        let calls = mock.calls();
        let root = "/aitemp/playground/playground-alice";

        let idx_of = |suffix: &str| -> usize {
            calls
                .iter()
                .position(|c| c.last().map(String::as_str) == Some(suffix))
                .unwrap_or_else(|| panic!("missing umount of {suffix} in {calls:?}"))
        };
        let self_umount = idx_of(&format!("{root}/pile"));
        let shared_umount = idx_of(&format!("{root}/shared"));
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
                == Some("aitemp/playground/playground-alice")),
            "only the session dataset may be destroyed: {destroys:?}"
        );
    }

    /// The shared-pile seed is create-if-absent and race-safe, and — the fix —
    /// ATOMIC: bootstrap is staged to a per-provision temp in the shared dir,
    /// then `mv -n`'d into shared.pile (atomic same-FS rename). It never `cp`s
    /// directly into shared.pile (that create-if-absent is not atomic — a loser
    /// `cp -n` could no-op mid-copy of the winner, exposing a torn tail). The
    /// temp is per-jail-name so two concurrent provisions never collide, and the
    /// no-op'd loser's temp is cleaned up. `mkdir -p` stays idempotent. Two
    /// back-to-back provisions of different tenants both publish the SAME
    /// shared.pile via `mv -n`, so a concurrent race is a harmless no-op on the
    /// loser.
    #[test]
    fn shared_pile_seed_is_atomic_and_create_if_absent() {
        for label in ["alice", "bob"] {
            let jail = format!("playground-{label}");
            let (backend, mock) = mock_provision_ready()
                .reply(&["sudo", "-n", "zfs", "list"], fail())
                .into_backend();
            backend.provision_sandbox(&spec(label)).expect("provision");
            let calls = mock.calls();
            let shared_pile = "/aitemp/playground/piles/shared/shared.pile";
            let shared_tmp = format!("/aitemp/playground/piles/shared/shared.pile.{jail}.tmp");
            // Shared dir mkdir is idempotent (`-p`).
            assert!(
                calls.iter().any(|c| c
                    == &[
                        "sudo".to_string(), "-n".into(), "mkdir".into(), "-p".into(),
                        "/aitemp/playground/piles/shared".into(),
                    ]),
                "shared dir mkdir must be idempotent (-p): {calls:?}"
            );
            // Stage to a per-provision temp (NOT directly to shared.pile).
            assert!(
                calls.iter().any(|c| c.ends_with(&[
                    "cp".into(),
                    "/aitemp/playground/bootstrap.pile".into(),
                    shared_tmp.clone(),
                ] as &[String])),
                "shared seed must stage to a per-provision temp: {calls:?}"
            );
            // Publish atomically via `mv -n` temp -> shared.pile.
            let shared_mvs: Vec<_> = calls
                .iter()
                .filter(|c| {
                    c.last().map(String::as_str) == Some(shared_pile)
                        && c.iter().any(|a| a == "mv")
                })
                .collect();
            assert_eq!(shared_mvs.len(), 1, "one atomic shared-pile publish: {calls:?}");
            assert!(
                shared_mvs[0].iter().any(|a| a == "-n"),
                "publish must be create-if-absent (mv -n), never clobber: {:?}",
                shared_mvs[0]
            );
            assert!(
                shared_mvs[0].iter().any(|a| a == shared_tmp.as_str()),
                "publish must rename the per-provision temp: {:?}",
                shared_mvs[0]
            );
            // NEVER a `cp` straight into shared.pile — that is the non-atomic
            // path this fix removes.
            assert!(
                !calls.iter().any(|c| {
                    c.last().map(String::as_str) == Some(shared_pile)
                        && c.iter().any(|a| a == "cp")
                }),
                "must not cp directly into shared.pile (non-atomic): {calls:?}"
            );
        }
    }

    #[test]
    fn provision_sandbox_sanitises_label() {
        // No dataset yet: provision the fresh box; its id is the sanitised name.
        let (backend, mock) = mock_provision_ready()
            .reply(&["sudo", "-n", "zfs", "list"], fail())
            .into_backend();
        backend.provision_sandbox(&spec("li ora/x")).expect("provision");
        let calls = mock.calls();
        // The jail -c call carries the sanitised name.
        assert!(calls.iter().any(|c| c.contains(&"name=playground-li-ora-x".to_string())));
        assert_eq!(backend.jail_name("li ora/x"), "playground-li-ora-x");
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
        let (backend, mock) = MockRunner::default()
            .reply(&["sudo", "-n", "jls", "-j", "playground-alice"], ok_with_stdout("1\n"))
            .into_backend();
        let id = backend.open_session(&spec("alice")).expect("open");
        assert_eq!(id.as_str(), "playground-alice");

        let calls = mock.calls();
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

        // The sweep re-establishes BOTH nullfs pile mounts for the down jail
        // (bob), mirroring the open-reattach mount assertions — mount coverage
        // is now pinned on the sweep arm too.
        let bob_root = "/aitemp/playground/playground-bob";
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                "/aitemp/playground/piles/playground-bob".into(),
                format!("{bob_root}/pile"),
            ]),
            "sweep must nullfs-mount the self pile at /pile for the down jail: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c == &[
                "sudo".to_string(), "-n".into(), "mount".into(), "-t".into(),
                "nullfs".into(),
                "/aitemp/playground/piles/shared".into(),
                format!("{bob_root}/shared"),
            ]),
            "sweep must nullfs-mount the shared pile at /shared for the down jail: {calls:?}"
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

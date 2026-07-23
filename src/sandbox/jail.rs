//! FreeBSD jail backend for the sandbox provider.
//!
//! Drives a remote FreeBSD host (default `ai.bultmann.eu`) over SSH and maps
//! the [`SandboxBackend`] verbs onto base `jail(8)` + ZFS:
//!
//!   - `open_session`  = `zfs clone` of a pre-provisioned template snapshot
//!     (`aitemp/playground/template@base`) into a per-session dataset
//!     (`aitemp/playground/<session>`), a manual `devfs` mount, then
//!     `jail -c name=playground-<session> path=<clone mountpoint> persist ...`.
//!   - `exec`          = `jexec <jail> /bin/sh -lc <command>`, wrapped in
//!     FreeBSD `timeout(1)` server-side so a runaway command is killed *on the
//!     server* (exit 124), with a local wall-clock backstop mirroring
//!     [`super::lima::LimaBackend`]'s timeout/exit-124 semantics.
//!   - `close_session` = `jail -r` + devfs unmount + `zfs destroy` of the
//!     clone. ZFS clones are cheap copy-on-write children of the template
//!     snapshot, so sessions cost ~nothing to open and destroy cleanly.
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
//! ## TRUST BOUNDARY: no pile on the server (v1 is PILE-LESS by design)
//!
//! `ai.bultmann.eu` is a **shared machine** (JP's coworker has access), so it
//! is not a trusted destination for private pile content — `self.pile` never
//! lands on non-operator-controlled surfaces. Therefore this backend deliberately
//! does **not** realise [`super::PileMount`]: the [`SessionSpec`]'s pile is
//! ignored (logged, not mounted), sessions get a plain `/workspace` workdir,
//! exec results return over MCP. That is the v1 architecture, not a gap: the shell runs remotely.
//!
//! TODO(sandbox-provider, deferred): pile access from server jails waits until
//! either (a) an encrypted / capability-gated replica design (triblespace-net
//! sync to a cyphertext-at-rest replica the coworker cannot read), or (b) a
//! `shared.pile`-only policy is decided. When that lands, the mount seam is
//! here: clone-time provisioning would place the replica inside the session
//! dataset and enforce append-only with `chflags sappnd` (the FreeBSD
//! system-append flag, un-clearable inside a jail at securelevel >= 1), the
//! jail analogue of the Lima template's `guest_pile_setup`. Do NOT wire a pile
//! path to the server before that decision.
//!
//! ## FACULTY PROVISIONING (follow-on, not yet implemented here)
//!
//! The Lima backend stages faculty CLIs into each session (a prebuilt
//! Linux-aarch64 bundle mounted at `/opt/faculties` + on PATH, with `PILE` set;
//! see [`super::faculties`] and `render_config` in [`super::lima`]). The jail
//! backend does NOT do this yet — and until the pile lands on the server it is
//! only half-useful (a faculty with no pile can print `--help` but not operate).
//! The clean equivalent, to implement alongside (a)/(b) above:
//!
//!   1. Build the faculties for **FreeBSD/aarch64** (or amd64 to match the jail
//!      host) once — `cargo build --release --no-default-features` for the same
//!      allow-list ([`super::faculties::SESSION_FACULTIES`]) — and **bake the
//!      resulting binaries into the ZFS template** (`template@base`), e.g. under
//!      `/opt/faculties`, so every `zfs clone` inherits them for free (no
//!      per-session copy; copy-on-write shares the blocks). Re-snapshot the
//!      template when the faculties change.
//!   2. Seed PATH + `PILE` in the session's `/etc/profile` exactly as the Lima
//!      template does (the `open_session` `/etc/profile` seed already writes the
//!      env block — add `export PATH=/opt/faculties:$PATH` and, once the pile is
//!      mounted, `export PILE=<guest pile path>` there).
//!
//! This is a template-baking change plus two profile lines, not new backend
//! surface — deliberately deferred to keep it paired with the pile-mount
//! decision, since a pile-less faculty is not yet worth staging.

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
        }
    }

    /// Deterministic jail name for a tenant label. Jail names and ZFS dataset
    /// components share the safe alphabet `[A-Za-z0-9-]` here; anything else
    /// in the label is mapped to `-` (mirrors Lima's instance sanitisation).
    fn jail_name(&self, label: &str) -> String {
        let safe: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("{}-{}", self.jail_prefix, safe)
    }

    fn dataset(&self, jail: &str) -> String {
        format!("{}/{}", self.dataset_parent, jail)
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
            let _ = self.run(
                &["sudo", "-n", "umount", "-f", &format!("{mp}/dev")],
                None,
                ADMIN_TIMEOUT,
            );
        }
        let _ = self.run(&["sudo", "-n", "zfs", "destroy", &dataset], None, ADMIN_TIMEOUT);
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
        // TRUST BOUNDARY (see module docs): the pile is NOT mounted on the
        // shared server. v1 sessions are pile-less; the pile stays on the local host.
        eprintln!(
            "[{}] note: pile '{}' stays on the local host; session is pile-less by design",
            self.name(),
            spec.tenant.pile.host_path.display()
        );

        self.cleanup_leftovers(&jail);

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

        // Everything after the clone must tear the clone down on failure, or
        // we leak a dataset per failed open.
        let provision = (|| -> Result<String> {
            let root = self.mountpoint(&dataset)?;

            // devfs, mounted manually (not via jail(8) params) so lifecycle
            // stays explicit and close_session can unmount symmetrically.
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

            // Seed session env + default cwd via /etc/profile, which
            // `sh -l` sources on every exec (same mechanism as the Lima
            // template's __SESSION_ENV__).
            let mut profile = String::new();
            profile.push_str("\n# playground session seed\n");
            profile.push_str(&format!("cd {} 2>/dev/null || true\n", shell_quote(&cwd)));
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

            // Create the jail: persistent (no processes yet), no network at
            // all (default-deny v1), minimal params.
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
            Ok(root)
        })();

        if let Err(e) = provision {
            self.cleanup_leftovers(&jail);
            return Err(e.context(format!("provision jail '{jail}'")));
        }
        Ok(SessionId::new(jail))
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
        let jail = session.as_str();
        if !jail.starts_with(&format!("{}-", self.jail_prefix)) {
            bail!(
                "refusing to close '{jail}': outside the '{}-' namespace",
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

        // Unmount devfs (must precede zfs destroy or the dataset is busy).
        if let Ok(root) = self.mountpoint(&dataset) {
            let _ = self.run(
                &["sudo", "-n", "umount", "-f", &format!("{root}/dev")],
                None,
                ADMIN_TIMEOUT,
            );
        }

        // Destroy the clone. This MUST succeed or we leak the session dataset;
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

    fn spec(label: &str) -> SessionSpec {
        SessionSpec {
            tenant: Tenant {
                label: label.to_string(),
                pile: PileMount {
                    host_path: PathBuf::from("/Users/x/self.pile"),
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
    fn open_session_clones_and_creates_namespaced_jail() {
        let (backend, mock) = mock_with_mountpoint().into_backend();
        let id = backend.open_session(&spec("alice")).expect("open");
        assert_eq!(id.as_str(), "playground-alice");

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
        // No call anywhere references the pile (pile-less by design).
        assert!(calls.iter().flatten().all(|a| !a.contains("self.pile")));
    }

    #[test]
    fn open_session_sanitises_label() {
        let (backend, _mock) = mock_with_mountpoint().into_backend();
        let s = spec("li ora/x");
        let id = backend.open_session(&s).expect("open");
        assert_eq!(id.as_str(), "playground-li-ora-x");
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

    #[test]
    fn close_session_removes_jail_and_destroys_clone() {
        let (backend, mock) = mock_with_mountpoint().into_backend();
        backend
            .close_session(&SessionId::new("playground-alice"))
            .expect("close");
        let calls = mock.calls();
        assert!(calls.iter().any(|c| c.ends_with(&[
            "jail".into(), "-r".into(), "playground-alice".into()
        ] as &[String])));
        assert!(calls.iter().any(|c| c.ends_with(&[
            "zfs".into(), "destroy".into(), "aitemp/playground/playground-alice".into()
        ] as &[String])));
    }

    #[test]
    fn close_session_refuses_foreign_jail_names() {
        let (backend, mock) = MockRunner::default().into_backend();
        let err = backend
            .close_session(&SessionId::new("trible.bultmann.eu"))
            .expect_err("must refuse");
        assert!(err.to_string().contains("outside the 'playground-' namespace"));
        // And crucially: no host command was issued at all.
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn close_session_fails_loud_when_destroy_fails() {
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
            .close_session(&SessionId::new("playground-alice"))
            .expect_err("destroy failure must surface");
        assert!(err.to_string().contains("zfs destroy"));
    }
}

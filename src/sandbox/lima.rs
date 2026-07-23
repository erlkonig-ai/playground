//! Lima backend for the sandbox provider.
//!
//! This wires the [`SandboxBackend`] trait to the `limactl` lifecycle. It is a
//! *session-oriented* reworking of the provisioning that currently lives inline
//! in `crate::main` (`prepare_lima_service`, `ensure_lima_instance`,
//! `stop_lima_instance`, `render_lima_template`). It is **persistent** and
//! provision-based, mirroring [`super::jail::JailBackend`] exactly — one Lima
//! instance per tenant, created explicitly and reused across connects:
//!
//!   - `provision_sandbox` = explicit CREATE of a PERSISTENT per-tenant VM:
//!     render the session config (pile mount + faculty staging preserved — Lima
//!     is an operator-controlled surface, so it KEEPS mounting the pile), then
//!     `limactl start --name <instance> <config>`. Idempotent: a tenant whose
//!     instance already exists is treated as already-provisioned — no
//!     re-render, no recreate; it is just brought up (`limactl start
//!     <instance>` if stopped). This is what `playground user create <name>
//!     --backend lima` calls.
//!   - `open_session`  = pure reuse-or-start of an ALREADY-provisioned VM — it
//!     NEVER creates. A running instance is reused as-is; a stopped instance is
//!     brought up (`limactl start <instance>`, no re-render); a tenant with no
//!     instance at all is an error ("not provisioned — run `playground user
//!     create <name> --backend lima`").
//!   - `reattach_all`  = the startup sweep: enumerate every provisioned instance
//!     under the `<prefix>-` namespace and `limactl start` each one that is
//!     stopped.
//!   - `exec`          = `limactl shell <instance> -- sh -lc <command>` with a
//!     wall-clock timeout (a *session* shell, not the pile-polling systemd
//!     service the `run` command provisions).
//!   - `close_session` = DETACH only: the VM persists across disconnects so the
//!     same tenant returns to the same box. No stop, no delete.
//!   - `destroy_session` = the explicit teardown: `limactl stop <instance>` +
//!     `limactl delete --force <instance>`, namespace-guarded to the
//!     `<prefix>-` instance namespace.
//!
//! Everything the backend touches is namespaced: instance names are
//! `<prefix>-<label>` (default prefix `playground-sbx`), and the backend never
//! stops or deletes an instance outside that namespace.
//!
//! ## Relationship to `main.rs`
//!
//! The live `playground run` path (`prepare_lima_service`) provisions a VM that
//! runs `playground exec` as a systemd service polling the pile queue. That path
//! is unchanged. This backend is the *provider* path: one Lima instance per
//! session, commands pushed in synchronously over `limactl shell`. The two share
//! the same `limactl` verbs and the same virtiofs mount layout; they differ in
//! *who drives exec* (systemd-in-guest vs. `limactl shell`-from-host).
//!
//! ## Append-only pile (intended, but a no-op on virtiofs today)
//!
//! The pile is mounted writable over virtiofs so the driver can append commits.
//! The provision script *tries* to set the Linux append-only inode attribute
//! (`chattr +a`) guest-side — but virtiofs does not support inode flags, so this
//! currently fails with `Operation not supported` and provides no protection
//! (measured 2026-07-11). See [`guest_pile_setup`] for the full measurement and
//! the follow-on options for a durable guarantee. The mount is writable and a
//! session can truncate its own pile; Lima sessions are trusted on this axis
//! until a real enforcement mechanism lands.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use super::proc::drive_child;
use super::{ExecRequest, ExecResult, SandboxBackend, SessionId, SessionSpec};

/// Default per-command timeout when an [`ExecRequest`] does not specify one.
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);
/// Timeout for administrative `limactl` commands (start/stop/delete/list).
/// Generous because a cold `limactl start` boots a VM.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(600);

/// Runs one `limactl` lifecycle argv (start/stop/delete/list) and captures its
/// output. The seam that makes [`LimaBackend`]'s reuse/start/exists/running
/// logic testable without a real Lima install (mirror of the mock-runner
/// pattern in [`super::jail`]'s tests). The streaming `exec` path drives its own
/// `limactl shell` child directly via [`drive_child`] and is not part of this
/// seam — it needs a live VM and is covered by the gated real-VM test.
pub trait LimaRunner: Send + Sync {
    /// Run `limactl <argv>`, killing after `timeout` wall-clock. Implementations
    /// must capture stdout/stderr completely.
    fn run(&self, argv: &[String], timeout: Duration) -> Result<super::proc::ChildOutput>;
}

/// Production runner: spawn `limactl <argv>` and collect its output.
#[derive(Debug, Clone, Default)]
pub struct LimactlRunner;

impl LimaRunner for LimactlRunner {
    fn run(&self, argv: &[String], timeout: Duration) -> Result<super::proc::ChildOutput> {
        let mut cmd = Command::new("limactl");
        cmd.args(argv);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let child = cmd.spawn().context("spawn limactl")?;
        drive_child(child, None, timeout)
    }
}

/// Lima-instance-backed sandbox. One [`SessionId`] maps to one Lima instance
/// name.
///
/// Persistent and provision-based (mirrors [`super::jail::JailBackend`]):
/// instance identity lives entirely in `limactl`, so a restarted provider can
/// still reattach/destroy an instance it finds by name. The live set of MCP
/// sessions is tracked one layer up in [`crate::mcp::SandboxProvider`].
pub struct LimaBackend {
    /// The `limactl` command seam (tests inject a mock here).
    runner: Box<dyn LimaRunner>,
    /// Instance-name prefix; the concrete instance is `<prefix>-<label>`.
    pub instance_prefix: String,
    /// Path to the Lima YAML template (with `__TOKEN__` placeholders). If unset,
    /// the backend falls back to `scripts/lima-session.yaml.tmpl` next to the
    /// crate, then `scripts/lima.yaml.tmpl`.
    pub template: Option<PathBuf>,
    /// Directory under which rendered per-session Lima configs are written.
    pub state_root: PathBuf,
    /// Host directory of prebuilt Linux-aarch64 faculty binaries to stage into
    /// every session (mounted read-only at `/opt/faculties`, put on PATH, with
    /// `PILE` set to the mounted pile). When `None`, sessions come up without
    /// faculties (the previous behaviour). Populate this via
    /// [`super::faculties::ensure_faculties_bundle`].
    pub faculties_bundle: Option<PathBuf>,
}

impl Default for LimaBackend {
    fn default() -> Self {
        LimaBackend {
            runner: Box::new(LimactlRunner),
            instance_prefix: "playground-sbx".to_string(),
            template: None,
            state_root: std::env::temp_dir().join("playground-sandbox"),
            faculties_bundle: None,
        }
    }
}

impl LimaBackend {
    pub fn new(instance_prefix: impl Into<String>) -> Self {
        LimaBackend {
            instance_prefix: instance_prefix.into(),
            ..Default::default()
        }
    }

    /// Backend over an explicit `limactl` runner (tests inject a mock here).
    #[cfg(test)]
    pub fn with_runner(runner: Box<dyn LimaRunner>) -> Self {
        LimaBackend {
            runner,
            ..Default::default()
        }
    }

    /// Deterministic instance name for a tenant label. Lima instance names must
    /// match `[A-Za-z0-9-]`, so the label is sanitised.
    ///
    /// Public so the `user` CLI derives the same `<prefix>-<sanitised>` name the
    /// backend uses — the two must agree on session ids (destroy, reattach).
    pub fn instance_name(&self, label: &str) -> String {
        let safe: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("{}-{}", self.instance_prefix, safe)
    }

    /// Run one `limactl` lifecycle argv through the seam.
    fn limactl(&self, argv: &[&str], timeout: Duration) -> Result<super::proc::ChildOutput> {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        self.runner.run(&argv, timeout)
    }

    /// `(name, status)` for every Lima instance, parsed from
    /// `limactl list --format '{{.Name}} {{.Status}}'` (one instance per line,
    /// space-separated — Lima names and statuses never contain spaces).
    fn list_instances(&self) -> Result<Vec<(String, String)>> {
        let out = self.limactl(
            &["list", "--format", "{{.Name}} {{.Status}}"],
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!("limactl list failed: {}", out.stderr_lossy());
        }
        let mut rows = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let Some(name) = parts.next() {
                let status = parts.next().unwrap_or("").to_string();
                rows.push((name.to_string(), status));
            }
        }
        Ok(rows)
    }

    /// True iff a Lima instance with this name exists and is `Running`.
    fn instance_running(&self, instance: &str) -> bool {
        self.list_instances()
            .map(|rows| {
                rows.iter()
                    .any(|(name, status)| name == instance && status == "Running")
            })
            .unwrap_or(false)
    }

    /// Public liveness probe for the `user list` CLI: true iff the tenant's Lima
    /// instance is currently running. Sanitises the label the same way
    /// [`LimaBackend::instance_name`] does, so the CLI and backend agree.
    pub fn instance_running_for_label(&self, label: &str) -> bool {
        self.instance_running(&self.instance_name(label))
    }

    /// Bring up an EXISTING instance: `limactl start <instance>` (no `--name`,
    /// no config file — this never creates or re-renders). Shared by
    /// `provision_sandbox`'s already-provisioned arm, `open_session`'s
    /// start-if-stopped arm, and `reattach_all` (analogous to jail's
    /// `reattach`).
    fn bring_up(&self, instance: &str) -> Result<()> {
        let out = self.limactl(&["start", "--tty=false", instance], ADMIN_TIMEOUT)?;
        if !out.success() {
            bail!("limactl start {instance} failed: {}", out.stderr_lossy());
        }
        Ok(())
    }

    fn template_path(&self) -> Result<PathBuf> {
        if let Some(t) = &self.template {
            return Ok(t.clone());
        }
        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let session = crate_root.join("scripts/lima-session.yaml.tmpl");
        if session.exists() {
            return Ok(session);
        }
        let default = crate_root.join("scripts/lima.yaml.tmpl");
        if default.exists() {
            return Ok(default);
        }
        bail!(
            "no Lima template found (looked for {} and {})",
            session.display(),
            default.display()
        )
    }

    /// Render this session's Lima config from the template. Mirrors
    /// `crate::main::render_lima_template` (same `__TOKEN__` scheme) but is
    /// self-contained so the backend does not depend on `main.rs`.
    fn render_config(&self, spec: &SessionSpec, out_path: &Path) -> Result<()> {
        let template = self.template_path()?;
        let mut text = std::fs::read_to_string(&template)
            .with_context(|| format!("read Lima template {}", template.display()))?;

        let pile = &spec.tenant.pile;
        let pile_root = pile
            .host_path
            .parent()
            .ok_or_else(|| anyhow!("pile host path missing parent directory"))?;
        // Guest path of the pile file is caller-chosen (defaults to
        // /pile/<pile-name> upstream in the MCP layer). We honour it verbatim so
        // a tenant can pin an explicit mount path.
        let guest_pile = pile.guest_path.clone();

        let replacements: [(&str, &Path); 3] = [
            ("__PILE_ROOT__", pile_root),
            ("__PILE_PATH__", guest_pile.as_path()),
            ("__VM_ROOT__", spec.cwd.as_deref().unwrap_or(Path::new("/workspace"))),
        ];
        for (token, path) in replacements {
            text = text.replace(token, &path.to_string_lossy());
        }

        // Seed session env as guest profile exports so it is present in every
        // `limactl shell -- sh -lc` (which sources /etc/profile via `sh -l`).
        let env_exports: String = spec
            .env
            .iter()
            .map(|(k, v)| format!("export {}='{}'\n", k, v.replace('\'', "'\\''")))
            .collect();
        text = text.replace("__SESSION_ENV__", &env_exports);

        // Faculties: mount the host bundle read-only at /opt/faculties and put
        // it on PATH so `compass list` / `wiki search X` resolve in a session.
        // PILE (the mounted pile guest path) is exported unconditionally by the
        // template via __PILE_PATH__, so a faculty run in any session operates
        // on the session's mounted pile. When no bundle is configured, both
        // markers render empty (sessions come up without faculties).
        let (faculties_mount, faculties_path_export) = match &self.faculties_bundle {
            Some(bundle) => (
                format!(
                    "  - location: \"{}\"\n    mountPoint: \"/opt/faculties\"\n    writable: false",
                    bundle.display()
                ),
                "export PATH=\"/opt/faculties:$PATH\"".to_string(),
            ),
            None => (String::new(), String::new()),
        };
        text = text.replace("__FACULTIES_MOUNT__", &faculties_mount);
        text = text.replace("__FACULTIES_PATH_EXPORT__", &faculties_path_export);

        // Append-only enforcement fragment, injected guest-side (see
        // guest_pile_setup). The session template carries a __GUEST_PILE_SETUP__
        // marker; if the fallback (live) template is used, this is a no-op.
        let setup = if pile.append_only {
            guest_pile_setup(&guest_pile).join("\n      ")
        } else {
            "true".to_string()
        };
        text = text.replace("__GUEST_PILE_SETUP__", &setup);

        let vm_user = std::env::var("PLAYGROUND_LIMA_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "lima".to_string());
        text = text.replace("__VM_USER__", &vm_user);

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).context("create Lima config directory")?;
        }
        std::fs::write(out_path, text)
            .with_context(|| format!("write Lima config {}", out_path.display()))?;
        Ok(())
    }
}

impl SandboxBackend for LimaBackend {
    fn name(&self) -> &'static str {
        "lima"
    }

    fn open_session(&self, spec: &SessionSpec) -> Result<SessionId> {
        let instance = self.instance_name(&spec.tenant.label);
        eprintln!(
            "[{}] opening session for tenant '{}' -> instance '{}'",
            self.name(),
            spec.tenant.label,
            instance
        );

        // Pure reuse-or-start: the box must already be provisioned (via
        // `provision_sandbox` / `playground user create --backend lima`). open
        // NEVER creates or re-renders.
        let rows = self.list_instances()?;
        let found = rows.iter().find(|(name, _)| name == &instance);

        match found {
            // 1. Already running: hand back the same id — no start, no re-render.
            Some((_, status)) if status == "Running" => {
                eprintln!("[{}] reusing persistent sandbox '{}'", self.name(), instance);
                Ok(SessionId::new(instance))
            }
            // 2. Exists but stopped (host reboot / playground restart): bring it
            //    up (`limactl start <instance>`), keeping its config/disk as they
            //    are. No `--name`, no config file — this never re-renders.
            Some(_) => {
                eprintln!("[{}] starting stopped sandbox '{}'", self.name(), instance);
                self.bring_up(&instance)
                    .with_context(|| format!("start stopped instance '{instance}'"))?;
                Ok(SessionId::new(instance))
            }
            // 3. No instance at all: the tenant was never provisioned.
            None => bail!(
                "sandbox for tenant '{}' is not provisioned — run \
                 `playground user create {} --backend lima`",
                spec.tenant.label,
                spec.tenant.label
            ),
        }
    }

    fn provision_sandbox(&self, spec: &SessionSpec) -> Result<()> {
        let instance = self.instance_name(&spec.tenant.label);

        // Idempotent: a tenant whose instance already exists is already
        // provisioned. Don't re-render or recreate; just ensure it is up so
        // `provision` doubles as "converge to running".
        let rows = self.list_instances()?;
        if let Some((_, status)) = rows.iter().find(|(name, _)| name == &instance) {
            eprintln!(
                "[{}] sandbox '{}' already provisioned; ensuring it is up",
                self.name(),
                instance
            );
            if status != "Running" {
                self.bring_up(&instance)
                    .with_context(|| format!("start existing instance '{instance}'"))?;
            }
            return Ok(());
        }

        eprintln!(
            "[{}] provisioning new persistent sandbox '{}'",
            self.name(),
            instance
        );

        // Brand-new tenant: render this session's config (pile mount + faculty
        // staging preserved — Lima is an operator-controlled surface) and create the
        // VM with `limactl start --name <instance> <config>`.
        let config_path = self.state_root.join(&instance).join("lima.yaml");
        self.render_config(spec, &config_path)?;

        let out = self.limactl(
            &[
                "start",
                "--tty=false",
                "--name",
                &instance,
                &config_path.to_string_lossy(),
            ],
            ADMIN_TIMEOUT,
        )?;
        if !out.success() {
            bail!(
                "limactl start --name {instance} failed: {}",
                out.stderr_lossy()
            );
        }
        Ok(())
    }

    fn reattach_all(&self) -> Result<usize> {
        // Enumerate the instances this backend owns (namespaced by the
        // `<prefix>-` instance-name prefix) and `limactl start` each one that is
        // stopped.
        let prefix = format!("{}-", self.instance_prefix);
        let rows = self.list_instances()?;
        let mut reattached = 0usize;
        for (name, status) in rows {
            if !name.starts_with(&prefix) {
                continue; // not ours
            }
            if status == "Running" {
                continue; // already up — nothing to do
            }
            match self.bring_up(&name) {
                Ok(()) => {
                    eprintln!(
                        "[{}] reattached persistent sandbox '{}'",
                        self.name(),
                        name
                    );
                    reattached += 1;
                }
                Err(e) => {
                    // Log and keep sweeping — one bad box must not strand the rest.
                    eprintln!("[{}] reattach '{}' failed: {e:#}", self.name(), name);
                }
            }
        }
        Ok(reattached)
    }

    fn shutdown(&self) -> Result<usize> {
        // Spin DOWN (graceful `limactl stop`, never delete) every owned RUNNING
        // instance so no VM outlives the playground process. The disk + config
        // stay, so the next `reattach_all` brings each box back. Unlike a jail
        // (a free kernel record that persists), a Lima VM holds real host RAM.
        let prefix = format!("{}-", self.instance_prefix);
        let rows = self.list_instances()?;
        let mut stopped = 0usize;
        for (name, status) in rows {
            if !name.starts_with(&prefix) {
                continue; // not ours
            }
            if status != "Running" {
                continue; // already down
            }
            let out = self.limactl(&["stop", &name], ADMIN_TIMEOUT)?;
            if out.success() {
                eprintln!("[{}] spun down persistent sandbox '{}'", self.name(), name);
                stopped += 1;
            } else {
                // Log and keep sweeping — one stuck box must not strand the rest.
                eprintln!(
                    "[{}] stop '{}' failed: {} (continuing)",
                    self.name(),
                    name,
                    out.stderr_lossy()
                );
            }
        }
        Ok(stopped)
    }

    fn exec(&self, session: &SessionId, request: &ExecRequest) -> Result<ExecResult> {
        let instance = session.as_str();

        // limactl shell <instance> -- sh -lc <command>. A per-call cwd is applied
        // via `--workdir`; otherwise we anchor at `/`. Without an explicit
        // workdir `limactl shell` tries to cd into the *host* cwd mirrored in the
        // guest — a path a session VM does not mount (it mounts only /pile and
        // /opt/faculties) — and the login shell aborts before the command runs.
        // `/` always exists, so the session's own `cd`/PILE-relative work is
        // unaffected.
        let mut cmd = Command::new("limactl");
        cmd.arg("shell");
        match &request.cwd {
            Some(cwd) => {
                cmd.arg("--workdir").arg(cwd);
            }
            None => {
                cmd.arg("--workdir").arg("/");
            }
        }
        cmd.arg(instance).arg("--").arg("sh").arg("-lc").arg(&request.command);

        if request.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let child = cmd.spawn().context("spawn limactl shell")?;

        // Concurrent stdin-feed + stdout/stderr drain (super::proc): a command
        // pushing more than a pipe buffer of output — or consuming more than a
        // pipe buffer of stdin — must not deadlock against the timeout loop.
        let timeout = request.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);
        let out = drive_child(child, request.stdin.clone(), timeout)?;

        let mut result = ExecResult {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
            error: None,
        };
        if out.timed_out {
            result.exit_code = Some(124);
            result.error = Some(format!("command timed out after {timeout:?}"));
        }
        Ok(result)
    }

    fn close_session(&self, session: &SessionId) -> Result<()> {
        // Persistent backend: closing a session only DETACHES — the instance
        // stays alive so the same tenant can reconnect to the same box. Use
        // `destroy_session` to remove it for good.
        eprintln!(
            "[{}] detach: sandbox '{}' persists (use destroy_session to remove)",
            self.name(),
            session.as_str()
        );
        Ok(())
    }

    fn destroy_session(&self, session: &SessionId) -> Result<()> {
        let instance = session.as_str();
        if !instance.starts_with(&format!("{}-", self.instance_prefix)) {
            bail!(
                "refusing to destroy '{instance}': outside the '{}-' namespace",
                self.instance_prefix
            );
        }

        // Stop the VM (kills its processes). Failure is tolerated — the instance
        // may already be stopped — but is surfaced on stderr.
        let stopped = self.limactl(&["stop", "--force", instance], ADMIN_TIMEOUT)?;
        if !stopped.success() {
            eprintln!(
                "[{}] limactl stop {instance}: {} (continuing to delete)",
                self.name(),
                stopped.stderr_lossy()
            );
        }

        // Delete the instance and its disk. This MUST succeed or we leak the box.
        let deleted = self.limactl(&["delete", "--force", instance], ADMIN_TIMEOUT)?;
        if !deleted.success() {
            bail!(
                "limactl delete {instance} failed: {}",
                deleted.stderr_lossy()
            );
        }
        Ok(())
    }
}

/// Guest-side commands that *attempt* to make the pile mount append-only.
///
/// The pile arrives via a *writable* virtiofs mount at `/pile` (writability is
/// required so the driver can append commits). The intent is to set the
/// ext4/Linux append-only inode attribute with `chattr +a` so `open(...,
/// O_TRUNC)`, `unlink`, and rename fail with `EPERM` while append keeps working.
///
/// KNOWN LIMITATION (measured 2026-07-11, `--backend lima` on an M4 Max): the
/// `/pile` mount is **virtiofs**, which does **not** support Linux inode flags.
/// `chattr +a` fails with `Operation not supported` (and `lsattr` likewise), so
/// this fragment is a **no-op on the current mount** — a session can still
/// truncate the pile (verified: `: > /pile/<pile>` succeeded and the host file
/// went to 0 bytes). The command is written defensively (`... || true`) so the
/// failure does not abort provisioning, but it provides **no** protection today.
///
/// This is a pre-existing property (the fragment predates faculty provisioning)
/// and is left in place because it is harmless and becomes effective if the
/// mount FS ever gains inode-flag support. The durable append-only guarantee
/// must come from elsewhere — candidates for the follow-on: host-side
/// `chflags uappnd/sappnd` on the pile file (the macOS analogue, applied before
/// the mount), a FUSE/virtiofsd policy that rejects `O_TRUNC`, or keeping the
/// pile off the guest entirely (the jail backend's pile-less model). Until one
/// lands, a Lima session is trusted not to truncate its own pile, not prevented.
///
/// Returned as shell fragments so the caller controls when they run and the code
/// stays inert until rendered into the provision script.
pub fn guest_pile_setup(guest_pile: &Path) -> Vec<String> {
    vec![
        // Only the pile file itself is made append-only, not the mount directory
        // (the directory must stay writable for sidecar files / lockfiles).
        format!(
            "sudo chattr +a '{}' 2>/dev/null || chattr +a '{}' 2>/dev/null || true",
            guest_pile.display(),
            guest_pile.display()
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{PileMount, Tenant};
    use std::sync::{Arc, Mutex};

    /// Records every `limactl` lifecycle invocation and replies from a script
    /// keyed on the argv prefix, defaulting to success with empty output. Tests
    /// hold an `Arc` and hand a clone to the backend (mirror of `jail`'s
    /// `MockRunner`). The `list` reply is what drives the reuse/start/exists
    /// three-case selection.
    #[derive(Default)]
    struct MockRunner {
        calls: Mutex<Vec<Vec<String>>>,
        /// (argv-prefix-to-match, canned output)
        script: Vec<(Vec<&'static str>, super::super::proc::ChildOutput)>,
    }

    impl MockRunner {
        fn reply(mut self, prefix: &[&'static str], out: super::super::proc::ChildOutput) -> Self {
            self.script.push((prefix.to_vec(), out));
            self
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
        /// Backend + handle pair: the backend owns one Arc clone, the test the other.
        fn into_backend(self, instance_prefix: &str) -> (LimaBackend, Arc<MockRunner>) {
            let mock = Arc::new(self);
            let mut backend = LimaBackend::with_runner(Box::new(mock.clone()));
            backend.instance_prefix = instance_prefix.to_string();
            // Point at the real session template so provision's render succeeds.
            backend.template = Some(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/lima-session.yaml.tmpl"),
            );
            (backend, mock)
        }
    }

    impl LimaRunner for Arc<MockRunner> {
        fn run(
            &self,
            argv: &[String],
            _timeout: Duration,
        ) -> Result<super::super::proc::ChildOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            for (prefix, out) in &self.script {
                if argv.len() >= prefix.len() && argv.iter().zip(prefix.iter()).all(|(a, p)| a == p)
                {
                    return Ok(out.clone());
                }
            }
            Ok(super::super::proc::ChildOutput {
                exit_code: Some(0),
                ..Default::default()
            })
        }
    }

    fn ok_with_stdout(s: &str) -> super::super::proc::ChildOutput {
        super::super::proc::ChildOutput {
            stdout: s.as_bytes().to_vec(),
            exit_code: Some(0),
            ..Default::default()
        }
    }

    /// A `limactl list` reply naming the given `(name, status)` instances.
    fn list_reply(rows: &[(&str, &str)]) -> super::super::proc::ChildOutput {
        let body: String = rows
            .iter()
            .map(|(n, s)| format!("{n} {s}\n"))
            .collect();
        ok_with_stdout(&body)
    }

    fn render(spec: &SessionSpec, faculties_bundle: Option<PathBuf>) -> String {
        let mut backend = LimaBackend::new("t");
        // Point at the real session template so the markers actually exist.
        backend.template =
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/lima-session.yaml.tmpl"));
        backend.faculties_bundle = faculties_bundle;
        let out = std::env::temp_dir().join(format!(
            "playground-render-test-{}-{}.yaml",
            std::process::id(),
            spec.tenant.label,
        ));
        backend.render_config(spec, &out).expect("render");
        let text = std::fs::read_to_string(&out).expect("read rendered");
        let _ = std::fs::remove_file(&out);
        text
    }

    fn spec(label: &str) -> SessionSpec {
        SessionSpec {
            tenant: Tenant {
                label: label.to_string(),
                pile: PileMount {
                    host_path: PathBuf::from("/tmp/scratch/self.pile"),
                    guest_path: PathBuf::from("/pile/self.pile"),
                    append_only: true,
                },
            },
            cwd: None,
            env: vec![],
        }
    }

    /// With a faculties bundle configured, the rendered session config mounts it
    /// read-only at /opt/faculties, puts it on PATH, and always exports PILE at
    /// the mounted pile guest path — so a faculty run in a session resolves and
    /// operates on that pile. Without a bundle, the mount/PATH markers render
    /// empty but PILE is still exported.
    #[test]
    fn render_wires_faculties_and_pile() {
        let with = render(&spec("with"), Some(PathBuf::from("/host/faculties-bundle")));
        assert!(
            with.contains("location: \"/host/faculties-bundle\"")
                && with.contains("mountPoint: \"/opt/faculties\"")
                && with.contains("writable: false"),
            "expected faculties mount in rendered config:\n{with}"
        );
        // Regression: the placeholder tokens must NOT appear in the template's
        // prose, or the global string-replace injects YAML into the comment
        // header and corrupts the document. The mount `mountPoint` line must
        // appear exactly once (in the real `mounts:` block, not duplicated into
        // a comment), and no rendered comment line may carry injected YAML.
        assert_eq!(
            with.matches("mountPoint: \"/opt/faculties\"").count(),
            1,
            "faculties mount rendered more than once (token leaked into prose?):\n{with}"
        );
        for line in with.lines() {
            let t = line.trim_start();
            if t.starts_with('#') {
                assert!(
                    !t.contains("mountPoint:") && !t.contains("location: \"/host"),
                    "YAML injected into a comment line: {line:?}"
                );
            }
        }
        assert!(
            with.contains("export PATH=\"/opt/faculties:$PATH\""),
            "expected faculties PATH export:\n{with}"
        );
        assert!(
            with.contains("export PILE='/pile/self.pile'"),
            "expected PILE export at the guest pile path:\n{with}"
        );
        // No unreplaced markers must survive into the guest config.
        assert!(!with.contains("__FACULTIES_MOUNT__"));
        assert!(!with.contains("__FACULTIES_PATH_EXPORT__"));

        let without = render(&spec("without"), None);
        // No actual mount / PATH export (the header comment mentions
        // /opt/faculties in prose, so assert on the load-bearing lines only).
        assert!(
            !without.contains("mountPoint: \"/opt/faculties\""),
            "no faculties mount when unconfigured:\n{without}"
        );
        assert!(
            !without.contains("export PATH=\"/opt/faculties:$PATH\""),
            "no faculties PATH export when unconfigured:\n{without}"
        );
        // PILE is still exported (faculties-independent).
        assert!(without.contains("export PILE='/pile/self.pile'"));
        assert!(!without.contains("__FACULTIES_MOUNT__"));
        assert!(!without.contains("__FACULTIES_PATH_EXPORT__"));
    }

    /// End-to-end regression for the pipe deadlock through a *real* Lima VM:
    /// with the old poll-then-collect exec, any command producing more than a
    /// pipe buffer (~64 KiB) of output blocked forever and surfaced as a
    /// spurious exit-124 timeout. The pure drain logic is covered everywhere
    /// by `crate::sandbox::proc::tests`; this test additionally proves the
    /// `limactl shell` wiring. It boots (and tears down) a throwaway VM, so it
    /// is gated: run with `SANDBOX_LIMA_TESTS=1 cargo test lima_exec`.
    #[test]
    fn lima_exec_survives_output_larger_than_a_pipe_buffer() {
        if std::env::var("SANDBOX_LIMA_TESTS").as_deref() != Ok("1") {
            eprintln!("skipping: set SANDBOX_LIMA_TESTS=1 to run (boots a real Lima VM)");
            return;
        }

        // Scratch pile in a scratch dir — the Lima template mounts the pile's
        // parent directory into the guest.
        let scratch = std::env::temp_dir().join(format!(
            "playground-lima-pipe-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&scratch).expect("create scratch dir");
        let pile_path = scratch.join("test.pile");
        std::fs::write(&pile_path, b"").expect("create scratch pile");

        let backend = LimaBackend::new("playground-sbxtest");
        let spec = SessionSpec {
            tenant: Tenant {
                label: "pipes".to_string(),
                pile: PileMount {
                    host_path: pile_path,
                    guest_path: PathBuf::from("/pile/test.pile"),
                    append_only: true,
                },
            },
            cwd: None,
            env: vec![],
        };

        // Persistent lifecycle: provision (create) first, then open (reuse).
        backend.provision_sandbox(&spec).expect("provision lima sandbox");
        let id = backend.open_session(&spec).expect("open lima session");
        // 256 KiB of 'a' — several pipe buffers deep.
        let req = ExecRequest {
            command: "dd if=/dev/zero bs=1024 count=256 2>/dev/null | tr '\\0' 'a'".to_string(),
            cwd: None,
            stdin: None,
            timeout: Some(Duration::from_secs(120)),
        };
        let result = backend.exec(&id, &req);
        // Tear the VM down before asserting so a failure doesn't leak it.
        // (close only detaches now — destroy is the teardown.)
        let _ = backend.destroy_session(&id);
        let _ = std::fs::remove_dir_all(&scratch);

        let result = result.expect("exec");
        assert_eq!(
            result.exit_code,
            Some(0),
            "error: {:?}, stderr: {}",
            result.error,
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout.len(), 256 * 1024);
        assert!(result.stdout.iter().all(|&b| b == b'a'));
    }

    // --- Persistence-model unit tests (mock `limactl` runner) ----------------
    //
    // These mirror the jail persistence tests. They cover the lifecycle
    // control-flow (reuse-if-running / start-if-stopped / error-if-unprovisioned,
    // provision-creates-or-brings-up, detach-on-close, stop+delete-on-destroy,
    // and the reattach sweep) without a real `limactl`. The `open`/`provision`
    // creation paths that shell out to `limactl start --name <cfg>` also render
    // a config file; the render succeeds against the real session template, and
    // the mock intercepts the `start` itself.

    /// A running instance is reused on open: the same id comes back and NO
    /// `limactl start` is issued (persistent reuse, no re-render).
    #[test]
    fn open_session_reuses_running_instance() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-alice", "Running")]))
            .into_backend("t");
        let id = backend.open_session(&spec("alice")).expect("open");
        assert_eq!(id.as_str(), "t-alice");
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.first().map(String::as_str) == Some("start")),
            "reuse must not limactl start: {calls:?}"
        );
    }

    /// A stopped instance is brought up on open with `limactl start <instance>`
    /// (no `--name`, no config file — never re-renders).
    #[test]
    fn open_session_starts_stopped_instance() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-alice", "Stopped")]))
            .into_backend("t");
        let id = backend.open_session(&spec("alice")).expect("open");
        assert_eq!(id.as_str(), "t-alice");
        let calls = mock.calls();
        // Exactly a bring-up start (no --name, no config path).
        let starts: Vec<_> = calls
            .iter()
            .filter(|c| c.first().map(String::as_str) == Some("start"))
            .collect();
        assert_eq!(starts.len(), 1, "one bring-up start: {calls:?}");
        assert!(
            starts[0].iter().all(|a| a != "--name"),
            "bring-up must not pass --name (that creates/re-renders): {:?}",
            starts[0]
        );
        assert!(
            starts[0].last().map(String::as_str) == Some("t-alice"),
            "bring-up targets the instance by name: {:?}",
            starts[0]
        );
    }

    /// A tenant with no instance cannot be opened — open never creates. The
    /// error names `playground user create ... --backend lima` and no `start` is
    /// issued.
    #[test]
    fn open_session_errors_when_unprovisioned() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-other", "Running")]))
            .into_backend("t");
        let err = backend.open_session(&spec("alice")).expect_err("must bail");
        let msg = err.to_string();
        assert!(msg.contains("not provisioned"), "err: {msg}");
        assert!(
            msg.contains("playground user create alice --backend lima"),
            "err: {msg}"
        );
        assert!(
            !mock.calls().iter().any(|c| c.first().map(String::as_str) == Some("start")),
            "open must not limactl start when unprovisioned"
        );
    }

    /// Provision on a brand-new tenant renders a config and creates the VM with
    /// `limactl start --name <instance> <config>`.
    #[test]
    fn provision_creates_when_absent() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[])) // nothing exists yet
            .into_backend("t");
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();
        let create = calls
            .iter()
            .find(|c| {
                c.first().map(String::as_str) == Some("start") && c.iter().any(|a| a == "--name")
            })
            .expect("create start issued");
        assert!(create.contains(&"t-alice".to_string()));
        // The last arg is the rendered config path.
        assert!(
            create.last().map(|p| p.ends_with("lima.yaml")).unwrap_or(false),
            "create start must reference the rendered config: {create:?}"
        );
    }

    /// Provision is idempotent: an already-running instance is left alone (no
    /// start, no re-render).
    #[test]
    fn provision_idempotent_when_running() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-alice", "Running")]))
            .into_backend("t");
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();
        assert!(
            !calls.iter().any(|c| c.first().map(String::as_str) == Some("start")),
            "idempotent provision of a running box must not start: {calls:?}"
        );
    }

    /// Provision brings up an already-provisioned-but-stopped instance (no
    /// re-render), via `limactl start <instance>`.
    #[test]
    fn provision_brings_up_stopped() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-alice", "Stopped")]))
            .into_backend("t");
        backend.provision_sandbox(&spec("alice")).expect("provision");
        let calls = mock.calls();
        let starts: Vec<_> = calls
            .iter()
            .filter(|c| c.first().map(String::as_str) == Some("start"))
            .collect();
        assert_eq!(starts.len(), 1, "one bring-up start: {calls:?}");
        assert!(
            starts[0].iter().all(|a| a != "--name"),
            "bring-up of an existing box must not pass --name: {:?}",
            starts[0]
        );
    }

    /// The instance name is sanitised to Lima's `[A-Za-z0-9-]` alphabet, and the
    /// CLI-facing derivation agrees.
    #[test]
    fn instance_name_sanitises_label() {
        let backend = LimaBackend::new("t");
        assert_eq!(backend.instance_name("li ora/x"), "t-li-ora-x");
    }

    /// close_session on the persistent Lima backend DETACHES: no `limactl stop`
    /// and no `limactl delete` are issued.
    #[test]
    fn close_session_detaches_without_teardown() {
        let (backend, mock) = MockRunner::default().into_backend("t");
        backend
            .close_session(&SessionId::new("t-alice"))
            .expect("close");
        let calls = mock.calls();
        assert!(calls.is_empty(), "detach must issue no limactl commands: {calls:?}");
    }

    /// destroy_session stops then deletes the instance.
    #[test]
    fn destroy_session_stops_and_deletes() {
        let (backend, mock) = MockRunner::default().into_backend("t");
        backend
            .destroy_session(&SessionId::new("t-alice"))
            .expect("destroy");
        let calls = mock.calls();
        assert!(
            calls.iter().any(|c| c.first().map(String::as_str) == Some("stop")
                && c.contains(&"t-alice".to_string())),
            "destroy must limactl stop: {calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.first().map(String::as_str) == Some("delete")
                && c.contains(&"t-alice".to_string())),
            "destroy must limactl delete: {calls:?}"
        );
    }

    /// destroy_session refuses a name outside its instance namespace, issuing no
    /// commands at all.
    #[test]
    fn destroy_session_refuses_foreign_names() {
        let (backend, mock) = MockRunner::default().into_backend("t");
        let err = backend
            .destroy_session(&SessionId::new("otherbox"))
            .expect_err("must refuse");
        assert!(err.to_string().contains("outside the 't-' namespace"), "err: {err}");
        assert!(mock.calls().is_empty(), "refusal issues no limactl commands");
    }

    /// destroy_session fails loud when `limactl delete` fails (a failed delete
    /// leaks the box).
    #[test]
    fn destroy_session_fails_loud_when_delete_fails() {
        let (backend, _mock) = MockRunner::default()
            .reply(
                &["delete"],
                super::super::proc::ChildOutput {
                    exit_code: Some(1),
                    stderr: b"instance is protected".to_vec(),
                    ..Default::default()
                },
            )
            .into_backend("t");
        let err = backend
            .destroy_session(&SessionId::new("t-alice"))
            .expect_err("delete failure must surface");
        assert!(err.to_string().contains("limactl delete"), "err: {err}");
    }

    /// The startup sweep: three instances — one of ours running, one of ours
    /// stopped, one foreign — brings up ONLY the stopped one of ours, and skips
    /// instances outside the `<prefix>-` namespace.
    #[test]
    fn reattach_all_starts_only_down_owned_instances() {
        let (backend, mock) = MockRunner::default()
            .reply(
                &["list"],
                list_reply(&[
                    ("t-alice", "Running"),
                    ("t-bob", "Stopped"),
                    ("otherbox", "Stopped"), // foreign (no `t-` prefix)
                ]),
            )
            .into_backend("t");
        let n = backend.reattach_all().expect("sweep");
        assert_eq!(n, 1, "only the down owned instance is reattached");
        let calls = mock.calls();
        let starts: Vec<_> = calls
            .iter()
            .filter(|c| c.first().map(String::as_str) == Some("start"))
            .collect();
        assert_eq!(starts.len(), 1, "exactly one bring-up: {calls:?}");
        assert!(
            starts[0].last().map(String::as_str) == Some("t-bob"),
            "the stopped owned instance is brought up: {:?}",
            starts[0]
        );
        // The foreign stopped instance is never touched.
        assert!(
            !starts.iter().any(|c| c.contains(&"otherbox".to_string())),
            "foreign instance must not be started"
        );
    }

    #[test]
    fn shutdown_stops_only_owned_running_instances() {
        // The mirror of reattach: spin DOWN owned RUNNING instances (stop, never
        // delete), leaving stopped ones and foreign namespaces alone.
        let (backend, mock) = MockRunner::default()
            .reply(
                &["list"],
                list_reply(&[
                    ("t-alice", "Running"), // ours, up   -> stop
                    ("t-bob", "Stopped"),   // ours, down -> skip
                    ("otherbox", "Running"),   // foreign    -> skip
                ]),
            )
            .into_backend("t");
        let n = backend.shutdown().expect("spin-down");
        assert_eq!(n, 1, "only the running owned instance is spun down");
        let calls = mock.calls();
        let stops: Vec<_> = calls
            .iter()
            .filter(|c| c.first().map(String::as_str) == Some("stop"))
            .collect();
        assert_eq!(stops.len(), 1, "exactly one spin-down: {calls:?}");
        assert!(
            stops[0].last().map(String::as_str) == Some("t-alice"),
            "the running owned instance is stopped: {:?}",
            stops[0]
        );
        // Spin-down never deletes — the box must survive for the next reattach.
        assert!(
            !calls
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("delete")),
            "shutdown must never delete an instance"
        );
        // The foreign running instance is left alone.
        assert!(
            !stops.iter().any(|c| c.contains(&"otherbox".to_string())),
            "foreign instance must not be stopped"
        );
    }
}

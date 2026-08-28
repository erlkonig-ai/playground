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
//!   - `exec`          = `limactl shell <instance> -- sh -lc <command>` for
//!     stateful user commands, or `/bin/sh -c` for clean internal requests,
//!     with a wall-clock timeout (a *session* shell, not the pile-polling
//!     systemd service the `run` command provisions).
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

use anyhow::{Context, Result, bail};

use super::proc::{DEFAULT_MAX_OUTPUT_BYTES, drive_child, drive_child_capped_controlled};
use super::{
    ExecControl, ExecRequest, ExecResult, ExecShellMode, FacultyPile, GUEST_FACULTY_KEY,
    GUEST_FACULTY_PILE, OpenSpec, ProvisionSpec, SandboxBackend, SessionId,
};

/// Default per-command timeout when an [`ExecRequest`] does not specify one.
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);
/// Server-side CEILING on a per-command timeout (mirrors the jail backend): a
/// caller may request less, never more.
const MAX_EXEC_TIMEOUT: Duration = Duration::from_secs(30 * 60);
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

    fn validate_owned_instance_name(&self, instance: &str) -> Result<()> {
        let prefix = format!("{}-", self.instance_prefix);
        if !instance.starts_with(&prefix)
            || instance.len() == prefix.len()
            || !instance
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!(
                "refusing to destroy '{instance}': outside the '{prefix}' Lima instance namespace"
            );
        }
        Ok(())
    }

    /// Run one `limactl` lifecycle argv through the seam.
    fn limactl(&self, argv: &[&str], timeout: Duration) -> Result<super::proc::ChildOutput> {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        self.runner.run(&argv, timeout)
    }

    /// Construct the exact guest execution argv. Keeping this pure makes the
    /// profile boundary reviewable: user commands retain `sh -lc`, while
    /// protocol-internal byte transfers use `/bin/sh -c` and an explicit root
    /// workdir when the caller supplied no cwd.
    fn exec_command(instance: &str, request: &ExecRequest) -> Command {
        let mut cmd = Command::new("limactl");
        cmd.arg("shell")
            .arg("--workdir")
            .arg(request.cwd.as_deref().unwrap_or(Path::new("/")))
            .arg(instance)
            .arg("--");
        match request.shell_mode {
            ExecShellMode::Login => {
                cmd.arg("sh").arg("-lc");
            }
            ExecShellMode::Clean => {
                cmd.arg("/bin/sh").arg("-c");
            }
        }
        cmd.arg(&request.command);
        cmd
    }

    /// Killing the local `limactl shell` transport does not prove that its
    /// guest process died. Force-stop the VM, then restart the same persistent
    /// disk/config so cancellation has a sandbox-wide death boundary.
    fn reset_after_cancel(&self, instance: &str) -> std::result::Result<(), String> {
        let stopped = self
            .limactl(&["stop", "--force", instance], ADMIN_TIMEOUT)
            .map_err(|error| {
                format!(
                    "could not guarantee sandbox-wide termination: \
                 limactl stop --force failed: {error:#}"
                )
            })?;
        if !stopped.success() {
            return Err(format!(
                "could not guarantee sandbox-wide termination: \
                 limactl stop --force exited {:?}: {}",
                stopped.exit_code,
                stopped.stderr_lossy()
            ));
        }
        let started = self
            .limactl(&["start", instance], ADMIN_TIMEOUT)
            .map_err(|error| {
                format!("VM was stopped, but restarting the persistent sandbox failed: {error:#}")
            })?;
        if !started.success() {
            return Err(format!(
                "VM was stopped, but restarting the persistent sandbox exited {:?}: {}",
                started.exit_code,
                started.stderr_lossy()
            ));
        }
        Ok(())
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

    /// Remove the host-side state owned by one deleted Lima instance.
    ///
    /// The faculty views are deliberately sealed against unlink/recreate while
    /// the guest is alive. Teardown must unseal those directories before it can
    /// remove their hardlink names. This only ever removes the two names inside
    /// the instance's private state directory; the source pile and key retain
    /// their original links and are never traversed here.
    fn remove_instance_state(&self, instance: &str) -> Result<()> {
        let instance_dir = self.state_root.join(instance);
        match std::fs::symlink_metadata(&instance_dir) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => bail!(
                "Lima instance state is not a plain directory: {}",
                instance_dir.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect Lima instance state {}", instance_dir.display())
                });
            }
        }

        cleanup_faculty_file_views(&instance_dir)?;
        remove_regular_file_if_present(&instance_dir.join("lima.yaml"))?;
        std::fs::remove_dir(&instance_dir).with_context(|| {
            format!(
                "remove empty Lima instance state {} (unexpected files are preserved)",
                instance_dir.display()
            )
        })
    }

    fn rollback_uncreated_state(&self, instance: &str, cause: anyhow::Error) -> Result<()> {
        match self.remove_instance_state(instance) {
            Ok(()) => Err(cause),
            Err(cleanup) => Err(cause.context(format!(
                "also failed to remove uncreated Lima instance state: {cleanup:#}"
            ))),
        }
    }

    /// A failed `limactl start` may or may not have created an instance. Only
    /// remove its host views after Lima proves the instance is absent; otherwise
    /// retain them so a partially created VM never loses its mounted files.
    fn fail_start_and_rollback_if_absent(
        &self,
        instance: &str,
        cause: anyhow::Error,
    ) -> Result<()> {
        match self.list_instances() {
            Ok(rows) if rows.iter().all(|(name, _)| name != instance) => {
                self.rollback_uncreated_state(instance, cause)
            }
            Ok(_) => Err(cause.context(
                "Lima reports that the instance exists after failed start; host views were retained",
            )),
            Err(probe) => Err(cause.context(format!(
                "could not prove the instance absent after failed start; host views were retained: {probe:#}"
            ))),
        }
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
    fn render_config(&self, spec: &ProvisionSpec, out_path: &Path) -> Result<()> {
        let template = self.template_path()?;
        let mut text = std::fs::read_to_string(&template)
            .with_context(|| format!("read Lima template {}", template.display()))?;

        let files = match &spec.faculty_pile {
            FacultyPile::Host(files) => files,
            FacultyPile::BackendOwned => {
                bail!("Lima provisioning requires an explicit host faculty pile")
            }
        };
        files.validate()?;
        reject_reserved_env(spec)?;

        let views = prepare_faculty_file_views(files, out_path)?;
        let file_mounts = format!(
            "{}\n{}",
            lima_mount(&views.pile_dir, "/pile", true),
            lima_mount(&views.key_dir, "/identity", false),
        );
        text = text.replace("__FACULTY_FILE_MOUNTS__", &file_mounts);

        text = text.replace(
            "__VM_ROOT__",
            &spec
                .cwd
                .as_deref()
                .unwrap_or(Path::new("/workspace"))
                .to_string_lossy(),
        );

        // Seed session env as guest profile exports so it is present in every
        // `limactl shell -- sh -lc` (which sources /etc/profile via `sh -l`).
        let env_exports: String = spec
            .env
            .iter()
            .map(|(k, v)| format!("export {}='{}'\n", k, v.replace('\'', "'\\''")))
            .collect();
        text = text.replace("__SESSION_ENV__", &env_exports);
        text = text.replace(
            "__FACULTY_ENV_EXPORTS__",
            &format!(
                "export PILE={}\n      export TRIBLESPACE_KEY={}",
                shell_quote(GUEST_FACULTY_PILE),
                shell_quote(GUEST_FACULTY_KEY),
            ),
        );
        text = text.replace(
            "__PERSONA_EXPORT__",
            &format!("export PERSONA={}", shell_quote(&spec.tenant.label)),
        );

        // Faculties: mount the host bundle read-only at /opt/faculties and put
        // it on PATH so `compass list` / `wiki search X` resolve in a session.
        // PILE and TRIBLESPACE_KEY are exported unconditionally by the template,
        // so a faculty run in any session operates on the resolved durable files.
        // When no bundle is configured, both faculty markers render empty
        // (sessions come up without faculty binaries).
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
        // guest_pile_setup). This is always requested for a faculty pile.
        let setup = guest_pile_setup(Path::new(GUEST_FACULTY_PILE)).join("\n      ");
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

struct FacultyFileViews {
    pile_dir: PathBuf,
    key_dir: PathBuf,
}

/// Build two minimal host directories containing only hardlinks to the exact
/// provisioned files. Lima only mounts directories; mounting either source
/// parent would expose unrelated custody material or an entire workspace.
/// Hardlinks preserve the live inode without copying a multi-gigabyte pile.
fn prepare_faculty_file_views(
    files: &super::HostFacultyFiles,
    config_path: &Path,
) -> Result<FacultyFileViews> {
    let instance_dir = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Lima config path has no parent"))?;
    std::fs::create_dir_all(instance_dir)
        .with_context(|| format!("create Lima instance state {}", instance_dir.display()))?;
    ensure_plain_directory(instance_dir)?;

    let root = instance_dir.join("faculty-files");
    ensure_plain_directory(&root)?;
    set_directory_mode(&root, 0o700)?;

    let pile_dir = root.join("pile");
    let key_dir = root.join("key");
    prepare_file_view(&pile_dir, "self.pile", files.pile())?;
    prepare_file_view(&key_dir, "self.key", files.signing_key())?;

    Ok(FacultyFileViews { pile_dir, key_dir })
}

fn prepare_file_view(view_dir: &Path, file_name: &str, source: &Path) -> Result<()> {
    ensure_plain_directory(view_dir)?;
    unseal_view_directory(view_dir)?;

    let result = (|| {
        let destination = view_dir.join(file_name);
        for entry in std::fs::read_dir(view_dir)
            .with_context(|| format!("inspect faculty file view {}", view_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("read faculty file view entry in {}", view_dir.display())
            })?;
            if entry.file_name() != std::ffi::OsStr::new(file_name) {
                bail!(
                    "faculty file view {} contains unexpected entry {}; refusing to expose it",
                    view_dir.display(),
                    entry.path().display()
                );
            }
        }

        match std::fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    bail!(
                        "faculty file view destination is not a regular file: {}",
                        destination.display()
                    );
                }
                if !same_file(source, &destination)? {
                    bail!(
                        "faculty file view {} already names a different inode; destroy its stale state before reprovisioning",
                        destination.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::hard_link(source, &destination).with_context(|| {
                    format!(
                        "hardlink {} into minimal Lima faculty view {} (the source and --state-root must be on the same filesystem)",
                        source.display(),
                        destination.display()
                    )
                })?;
                if !same_file(source, &destination)? {
                    bail!(
                        "new faculty file view {} does not reference source inode {}",
                        destination.display(),
                        source.display()
                    );
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect faculty file view {}", destination.display())
                });
            }
        }
        Ok(())
    })();

    let seal = seal_view_directory(view_dir);
    match (result, seal) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(seal_error)) => Err(error.context(format!(
            "also failed to reseal faculty file view {}: {seal_error:#}",
            view_dir.display()
        ))),
    }
}

/// Remove the two exact-file views after their Lima instance has been deleted.
/// Unknown entries are never recursively removed: they make cleanup fail loud
/// so a corrupt or redirected state directory cannot widen deletion scope.
fn cleanup_faculty_file_views(instance_dir: &Path) -> Result<()> {
    let root = instance_dir.join("faculty-files");
    match std::fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => bail!(
            "Lima faculty view root is not a plain directory: {}",
            root.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect Lima faculty view root {}", root.display()));
        }
    }

    remove_file_view(&root.join("pile"), "self.pile")?;
    remove_file_view(&root.join("key"), "self.key")?;
    std::fs::remove_dir(&root).with_context(|| {
        format!(
            "remove empty Lima faculty view root {} (unexpected entries are preserved)",
            root.display()
        )
    })
}

fn remove_file_view(view_dir: &Path, file_name: &str) -> Result<()> {
    match std::fs::symlink_metadata(view_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => bail!(
            "Lima faculty view is not a plain directory: {}",
            view_dir.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect Lima faculty view {}", view_dir.display()));
        }
    }

    unseal_view_directory(view_dir)?;
    let result = (|| {
        let expected = view_dir.join(file_name);
        for entry in std::fs::read_dir(view_dir)
            .with_context(|| format!("inspect faculty file view {}", view_dir.display()))?
        {
            let entry = entry.with_context(|| {
                format!("read faculty file view entry in {}", view_dir.display())
            })?;
            if entry.file_name() != std::ffi::OsStr::new(file_name) {
                bail!(
                    "faculty file view {} contains unexpected entry {}; refusing to remove it",
                    view_dir.display(),
                    entry.path().display()
                );
            }
        }

        remove_regular_file_if_present(&expected)?;
        std::fs::remove_dir(view_dir)
            .with_context(|| format!("remove empty faculty file view {}", view_dir.display()))
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) if view_dir.exists() => match seal_view_directory(view_dir) {
            Ok(()) => Err(error),
            Err(seal_error) => Err(error.context(format!(
                "also failed to reseal faculty file view {}: {seal_error:#}",
                view_dir.display()
            ))),
        },
        Err(error) => Err(error),
    }
}

fn remove_regular_file_if_present(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => std::fs::remove_file(path)
            .with_context(|| format!("remove Lima-owned file {}", path.display())),
        Ok(_) => bail!("refusing to remove non-regular file {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("inspect Lima-owned file {}", path.display()))
        }
    }
}

fn ensure_plain_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => bail!(
            "Lima faculty view path is not a plain directory: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(path)
            .with_context(|| format!("create Lima faculty view {}", path.display())),
        Err(error) => {
            Err(error).with_context(|| format!("inspect Lima faculty view {}", path.display()))
        }
    }
}

#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let left = std::fs::symlink_metadata(left)
        .with_context(|| format!("inspect source inode {}", left.display()))?;
    let right = std::fs::symlink_metadata(right)
        .with_context(|| format!("inspect view inode {}", right.display()))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_file(_left: &Path, _right: &Path) -> Result<bool> {
    bail!("Lima exact-file views require Unix hardlink identity")
}

#[cfg(unix)]
fn set_directory_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("set mode {mode:o} on {}", path.display()))
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path, _mode: u32) -> Result<()> {
    bail!("Lima exact-file views require Unix directory permissions")
}

fn unseal_view_directory(path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    run_chflags("nouchg", path)?;
    set_directory_mode(path, 0o700)
}

fn seal_view_directory(path: &Path) -> Result<()> {
    set_directory_mode(path, 0o555)?;
    #[cfg(target_os = "macos")]
    run_chflags("uchg", path)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_chflags(flag: &str, path: &Path) -> Result<()> {
    let status = Command::new("chflags")
        .arg(flag)
        .arg(path)
        .status()
        .with_context(|| format!("run chflags {flag} on {}", path.display()))?;
    if !status.success() {
        bail!(
            "chflags {flag} failed for {} with status {status}",
            path.display()
        );
    }
    Ok(())
}

fn reject_reserved_env(spec: &ProvisionSpec) -> Result<()> {
    const RESERVED: [&str; 3] = ["PILE", "TRIBLESPACE_KEY", "PERSONA"];
    if let Some((name, _)) = spec
        .env
        .iter()
        .find(|(name, _)| RESERVED.contains(&name.as_str()))
    {
        bail!(
            "{name} is reserved by Playground and derives from the provisioned faculty files or tenant '{}'",
            spec.tenant.label
        );
    }
    Ok(())
}

fn lima_mount(host_root: &Path, guest_root: &str, writable: bool) -> String {
    let location = serde_json::to_string(&host_root.to_string_lossy())
        .expect("serializing a path string cannot fail");
    let mount_point = serde_json::to_string(guest_root)
        .expect("serializing a static Lima mount point cannot fail");
    format!("  - location: {location}\n    mountPoint: {mount_point}\n    writable: {writable}")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

impl SandboxBackend for LimaBackend {
    fn name(&self) -> &'static str {
        "lima"
    }

    fn open_session(&self, spec: &OpenSpec) -> Result<SessionId> {
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
                eprintln!(
                    "[{}] reusing persistent sandbox '{}'",
                    self.name(),
                    instance
                );
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

    fn provision_sandbox(&self, spec: &ProvisionSpec) -> Result<()> {
        let files = match &spec.faculty_pile {
            FacultyPile::Host(files) => files,
            FacultyPile::BackendOwned => {
                bail!("Lima provisioning requires an explicit host faculty pile")
            }
        };
        files.validate()?;
        reject_reserved_env(spec)?;
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
        if let Err(error) = self.render_config(spec, &config_path) {
            return self.rollback_uncreated_state(&instance, error);
        }

        let start = self.limactl(
            &[
                "start",
                "--tty=false",
                "--name",
                &instance,
                &config_path.to_string_lossy(),
            ],
            ADMIN_TIMEOUT,
        );
        match start {
            Ok(out) if out.success() => Ok(()),
            Ok(out) => self.fail_start_and_rollback_if_absent(
                &instance,
                anyhow::anyhow!(
                    "limactl start --name {instance} failed: {}",
                    out.stderr_lossy()
                ),
            ),
            Err(error) => self.fail_start_and_rollback_if_absent(
                &instance,
                error.context(format!("run limactl start --name {instance}")),
            ),
        }
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
                    eprintln!("[{}] reattached persistent sandbox '{}'", self.name(), name);
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

    fn exec(
        &self,
        session: &SessionId,
        request: &ExecRequest,
        control: &ExecControl,
    ) -> Result<ExecResult> {
        let instance = session.as_str();

        // A per-call cwd is applied via `--workdir`; otherwise the transport is
        // anchored at `/`. Without it, `limactl shell` tries to mirror the host
        // cwd, which this minimal VM does not mount. Login mode may then apply
        // the session profile's own cwd; clean mode cannot source that profile
        // and therefore deterministically remains at `/`.
        let mut cmd = Self::exec_command(instance, request);

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
        // TIMEOUT CEILING + OUTPUT CAP mirror the jail backend: clamp the
        // caller-supplied timeout to the server maximum, and kill the child if
        // either output stream exceeds the per-stream ceiling.
        let timeout = request
            .timeout
            .unwrap_or(DEFAULT_EXEC_TIMEOUT)
            .min(MAX_EXEC_TIMEOUT);
        let out = drive_child_capped_controlled(
            child,
            request.stdin.clone(),
            timeout,
            DEFAULT_MAX_OUTPUT_BYTES,
            control,
        )?;

        let mut result = ExecResult {
            stdout: out.stdout,
            stderr: out.stderr,
            exit_code: out.exit_code,
            cancelled: out.cancelled,
            error: None,
        };
        if out.cancelled {
            result.error = Some(match self.reset_after_cancel(instance) {
                Ok(()) => "command cancelled; Lima VM stopped and restarted to reap the guest process tree".to_string(),
                Err(error) => format!("command cancelled; {error}"),
            });
        } else if out.timed_out {
            result.exit_code = Some(124);
            result.error = Some(format!("command timed out after {timeout:?}"));
        } else if out.output_truncated {
            result.error = Some(format!(
                "output truncated at {DEFAULT_MAX_OUTPUT_BYTES} bytes per stream; process killed"
            ));
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
        self.validate_owned_instance_name(instance)?;

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
        self.remove_instance_state(instance)
            .with_context(|| format!("remove host state for deleted Lima instance '{instance}'"))
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
/// the mount) — which is exactly what the jail backend does (`chflags sappnd` on
/// its host-owned piles) — or a FUSE/virtiofsd policy that rejects `O_TRUNC`.
/// Until one lands, a Lima session is trusted not to truncate its own pile, not
/// prevented.
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
    use crate::sandbox::{HostFacultyFiles, Tenant};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    fn host_faculty_files(label: &str) -> HostFacultyFiles {
        let root = std::env::temp_dir().join(format!(
            "playground-lima-files-{}-{label}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).expect("create faculty fixture directory");
        std::fs::write(root.join("self.pile"), b"pile").expect("create faculty pile");
        std::fs::write(root.join("self.key"), b"key").expect("create faculty key");
        HostFacultyFiles::resolve(&root.join("self.pile")).expect("resolve faculty fixture")
    }

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
            backend.state_root = std::env::temp_dir().join(format!(
                "playground-lima-mock-state-{}-{}",
                std::process::id(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed),
            ));
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

    fn command_argv(command: &Command) -> Vec<String> {
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn exec_shell_mode_selects_login_or_clean_argv() {
        let mut request = ExecRequest {
            command: "profile-sensitive".to_string(),
            shell_mode: ExecShellMode::Login,
            cwd: None,
            stdin: Some(b"payload".to_vec()),
            timeout: None,
        };
        assert_eq!(
            command_argv(&LimaBackend::exec_command("playground-alice", &request)),
            [
                "limactl",
                "shell",
                "--workdir",
                "/",
                "playground-alice",
                "--",
                "sh",
                "-lc",
                "profile-sensitive",
            ]
        );

        request.shell_mode = ExecShellMode::Clean;
        request.command = "/bin/cat > /tmp/file".to_string();
        assert_eq!(
            command_argv(&LimaBackend::exec_command("playground-alice", &request)),
            [
                "limactl",
                "shell",
                "--workdir",
                "/",
                "playground-alice",
                "--",
                "/bin/sh",
                "-c",
                "/bin/cat > /tmp/file",
            ]
        );

        request.cwd = Some(PathBuf::from("/work tree"));
        let argv = command_argv(&LimaBackend::exec_command("playground-alice", &request));
        assert_eq!(argv[3], "/work tree");
    }

    /// A `limactl list` reply naming the given `(name, status)` instances.
    fn list_reply(rows: &[(&str, &str)]) -> super::super::proc::ChildOutput {
        let body: String = rows.iter().map(|(n, s)| format!("{n} {s}\n")).collect();
        ok_with_stdout(&body)
    }

    fn render_to(spec: &ProvisionSpec, faculties_bundle: Option<PathBuf>, out: &Path) -> String {
        let mut backend = LimaBackend::new("t");
        // Point at the real session template so the markers actually exist.
        backend.template =
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/lima-session.yaml.tmpl"));
        backend.faculties_bundle = faculties_bundle;
        backend.render_config(spec, out).expect("render");
        std::fs::read_to_string(out).expect("read rendered")
    }

    fn render(spec: &ProvisionSpec, faculties_bundle: Option<PathBuf>) -> String {
        let root = std::env::temp_dir().join(format!(
            "playground-render-test-{}-{}-{}",
            std::process::id(),
            spec.tenant.label,
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed),
        ));
        render_to(spec, faculties_bundle, &root.join("lima.yaml"))
    }

    fn provision_spec(label: &str) -> ProvisionSpec {
        ProvisionSpec {
            tenant: Tenant {
                label: label.to_string(),
            },
            cwd: None,
            env: vec![],
            faculty_pile: FacultyPile::Host(host_faculty_files(label)),
        }
    }

    fn open_spec(label: &str) -> OpenSpec {
        OpenSpec {
            tenant: Tenant {
                label: label.to_string(),
            },
        }
    }

    /// With a faculties bundle configured, the rendered session config mounts it
    /// read-only at /opt/faculties, puts it on PATH, and always exports PILE at
    /// the mounted pile guest path — so a faculty run in a session resolves and
    /// operates on that pile. Without a bundle, the mount/PATH markers render
    /// empty but PILE is still exported.
    #[test]
    fn render_wires_faculties_and_pile() {
        let with_spec = provision_spec("with");
        let with = render(&with_spec, Some(PathBuf::from("/host/faculties-bundle")));
        assert!(
            with.contains("/faculty-files/pile\"")
                && with.contains("mountPoint: \"/pile\"")
                && with.contains("writable: true"),
            "the private pile view must be mounted writable:\n{with}"
        );
        assert!(
            with.contains("/faculty-files/key\"")
                && with.contains("mountPoint: \"/identity\"")
                && with.contains("writable: false"),
            "the private key view must be mounted read-only:\n{with}"
        );
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
        assert!(
            with.contains("export TRIBLESPACE_KEY='/identity/self.key'"),
            "expected signing-key export at the fixed guest path:\n{with}"
        );
        assert!(
            with.contains("export PERSONA='with'"),
            "expected tenant-derived PERSONA export:\n{with}"
        );
        // No unreplaced markers must survive into the guest config.
        assert!(!with.contains("__FACULTY_FILE_MOUNTS__"));
        assert!(!with.contains("__FACULTIES_MOUNT__"));
        assert!(!with.contains("__FACULTIES_PATH_EXPORT__"));
        assert!(!with.contains("__PERSONA_EXPORT__"));

        let without = render(&provision_spec("without"), None);
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

    #[cfg(unix)]
    #[test]
    fn render_exposes_only_live_hardlinks_to_real_pile_and_lexical_key() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "playground-lima-symlink-topology-{}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed),
        ));
        let lexical = root.join("workspace");
        let custody = root.join("custody");
        std::fs::create_dir_all(&lexical).expect("create lexical directory");
        std::fs::create_dir_all(&custody).expect("create custody directory");
        let real_pile = custody.join("self.pile");
        let lexical_pile = lexical.join("self.pile");
        let lexical_key = lexical.join("self.key");
        std::fs::write(&real_pile, b"pile").expect("create real pile");
        std::fs::write(&lexical_key, b"key").expect("create lexical key");
        std::os::unix::fs::symlink(&real_pile, &lexical_pile).expect("create lexical pile symlink");

        let files = HostFacultyFiles::resolve(&lexical_pile).expect("resolve split files");
        assert_eq!(files.pile(), real_pile.canonicalize().unwrap());
        assert_eq!(files.signing_key(), lexical_key.canonicalize().unwrap());
        let spec = ProvisionSpec {
            tenant: Tenant {
                label: "tenant-agent".to_string(),
            },
            cwd: None,
            env: vec![],
            faculty_pile: FacultyPile::Host(files),
        };
        let state = root.join("state");
        let rendered = render_to(&spec, None, &state.join("lima.yaml"));
        let pile_view_dir = state.join("faculty-files/pile");
        let key_view_dir = state.join("faculty-files/key");
        let pile_view = pile_view_dir.join("self.pile");
        let key_view = key_view_dir.join("self.key");

        assert!(
            rendered.contains(&format!(
                "location: \"{}\"\n    mountPoint: \"/pile\"\n    writable: true",
                pile_view_dir.display()
            )),
            "minimal pile view must be the writable mount:\n{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "location: \"{}\"\n    mountPoint: \"/identity\"\n    writable: false",
                key_view_dir.display()
            )),
            "minimal key view must be the read-only mount:\n{rendered}"
        );
        assert!(
            !rendered.contains(&custody.canonicalize().unwrap().to_string_lossy().as_ref())
                && !rendered.contains(&lexical.canonicalize().unwrap().to_string_lossy().as_ref()),
            "neither source parent may cross the Lima boundary:\n{rendered}"
        );
        assert!(same_file(&real_pile, &pile_view).unwrap());
        assert!(same_file(&lexical_key, &key_view).unwrap());
        let pile_names: Vec<_> = std::fs::read_dir(&pile_view_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let key_names: Vec<_> = std::fs::read_dir(&key_view_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(pile_names, [std::ffi::OsString::from("self.pile")]);
        assert_eq!(key_names, [std::ffi::OsString::from("self.key")]);
        assert!(rendered.contains("export PILE='/pile/self.pile'"));
        assert!(rendered.contains("export TRIBLESPACE_KEY='/identity/self.key'"));
        assert_eq!(
            std::fs::metadata(&pile_view_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(
            std::fs::metadata(&key_view_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );

        std::fs::OpenOptions::new()
            .append(true)
            .open(&pile_view)
            .expect("sealed directory must still allow append to the existing pile inode")
            .write_all(b"-append")
            .expect("append through hardlink view");
        assert_eq!(std::fs::read(&real_pile).unwrap(), b"pile-append");
        assert!(
            std::fs::remove_file(&pile_view).is_err(),
            "sealed view directory must prevent unlink-and-recreate forks"
        );
        assert!(rendered.contains("export PERSONA='tenant-agent'"));
    }

    #[test]
    fn render_rejects_reserved_session_environment() {
        for reserved in ["PILE", "TRIBLESPACE_KEY", "PERSONA"] {
            let mut spec = provision_spec(reserved);
            spec.env
                .push((reserved.to_string(), "override".to_string()));
            let mut backend = LimaBackend::new("t");
            backend.template = Some(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/lima-session.yaml.tmpl"),
            );
            let out = std::env::temp_dir().join(format!(
                "playground-reserved-env-{}-{reserved}.yaml",
                std::process::id()
            ));
            let error = backend
                .render_config(&spec, &out)
                .expect_err("reserved environment must have one source");
            assert!(error.to_string().contains(reserved), "error: {error:#}");
        }
    }

    #[test]
    fn provision_requires_an_explicit_host_faculty_pile() {
        let (backend, mock) = MockRunner::default().into_backend("t");
        let mut missing = provision_spec("alice");
        missing.faculty_pile = FacultyPile::BackendOwned;

        let error = backend
            .provision_sandbox(&missing)
            .expect_err("Lima cannot invent durable faculty storage");
        assert!(error.to_string().contains("explicit host faculty pile"));
        assert!(
            mock.calls().is_empty(),
            "missing storage must fail before querying or mutating Lima"
        );
    }

    #[test]
    fn reopening_a_lima_tenant_cannot_rewrite_its_provisioned_storage() {
        let state_root = std::env::temp_dir().join(format!(
            "playground-lima-reopen-storage-{}",
            std::process::id()
        ));
        let config_path = state_root.join("t-alice").join("lima.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).expect("create state dir");
        std::fs::write(&config_path, b"durable-storage-sentinel\n").expect("write sentinel");

        let (mut backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-alice", "Running")]))
            .into_backend("t");
        backend.state_root = state_root.clone();
        backend
            .open_session(&open_spec("alice"))
            .expect("reopen existing tenant");

        assert_eq!(
            std::fs::read(&config_path).expect("read config after reopen"),
            b"durable-storage-sentinel\n"
        );
        assert_eq!(
            mock.calls(),
            vec![vec![
                "list".to_string(),
                "--format".to_string(),
                "{{.Name}} {{.Status}}".to_string(),
            ]],
            "reopen may inspect instance state but cannot render or recreate storage"
        );
        let _ = std::fs::remove_dir_all(state_root);
    }

    #[test]
    fn cancellation_reset_force_stops_then_restarts_the_vm() {
        let (backend, mock) = MockRunner::default().into_backend("t");
        backend.reset_after_cancel("t-alice").expect("reset");
        assert_eq!(
            mock.calls(),
            vec![
                vec![
                    "stop".to_string(),
                    "--force".to_string(),
                    "t-alice".to_string()
                ],
                vec!["start".to_string(), "t-alice".to_string()],
            ]
        );
    }

    #[test]
    fn cancellation_reset_reports_when_sandbox_death_is_not_guaranteed() {
        let (backend, _mock) = MockRunner::default()
            .reply(
                &["stop", "--force"],
                super::super::proc::ChildOutput {
                    exit_code: Some(1),
                    stderr: b"stop refused".to_vec(),
                    ..Default::default()
                },
            )
            .into_backend("t");
        let error = backend
            .reset_after_cancel("t-alice")
            .expect_err("stop failure must be explicit");
        assert!(error.contains("could not guarantee sandbox-wide termination"));
        assert!(error.contains("stop refused"));
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

        // Scratch pile + key become the only two files exposed through the
        // per-tenant hardlink views.
        let scratch =
            std::env::temp_dir().join(format!("playground-lima-pipe-test-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("create scratch dir");
        let pile_path = scratch.join("self.pile");
        std::fs::write(&pile_path, b"").expect("create scratch pile");
        std::fs::write(scratch.join("self.key"), b"test-key").expect("create scratch key");

        let backend = LimaBackend::new("playground-sbxtest");
        let provision = ProvisionSpec {
            tenant: Tenant {
                label: "pipes".to_string(),
            },
            cwd: None,
            env: vec![],
            faculty_pile: FacultyPile::Host(
                HostFacultyFiles::resolve(&pile_path).expect("resolve scratch faculty files"),
            ),
        };

        // Persistent lifecycle: provision (create) first, then open (reuse).
        backend
            .provision_sandbox(&provision)
            .expect("provision lima sandbox");
        let id = backend
            .open_session(&open_spec("pipes"))
            .expect("open lima session");
        // 256 KiB of 'a' — several pipe buffers deep.
        let req = ExecRequest {
            command: "dd if=/dev/zero bs=1024 count=256 2>/dev/null | tr '\\0' 'a'".to_string(),
            shell_mode: ExecShellMode::Login,
            cwd: None,
            stdin: None,
            timeout: Some(Duration::from_secs(120)),
        };
        let result = backend.exec(&id, &req, &ExecControl::default());
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
        let id = backend.open_session(&open_spec("alice")).expect("open");
        assert_eq!(id.as_str(), "t-alice");
        let calls = mock.calls();
        assert!(
            !calls
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("start")),
            "reuse must not limactl start: {calls:?}"
        );
    }

    /// Live topology gate: a faculty-style append through `$PILE` reaches the
    /// durable pile chosen at provisioning, while guest unlink/recreate and key
    /// writes fail and an unrelated host ledger remains unchanged. Run alongside
    /// the other live Lima gate with `SANDBOX_LIMA_TESTS=1`.
    #[test]
    fn lima_faculty_write_targets_durable_pile_not_cognition_ledger() {
        if std::env::var("SANDBOX_LIMA_TESTS").as_deref() != Ok("1") {
            eprintln!("skipping: set SANDBOX_LIMA_TESTS=1 to run (boots a real Lima VM)");
            return;
        }

        let root = std::env::temp_dir().join(format!(
            "playground-lima-pile-topology-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create live topology dir");
        let durable = root.join("self.pile");
        let ledger = root.join("cognition.pile");
        std::fs::write(&durable, b"durable-before\n").expect("create durable pile");
        std::fs::write(root.join("self.key"), b"test-key").expect("create durable key");
        std::fs::write(&ledger, b"ledger-before\n").expect("create cognition ledger");

        let backend = LimaBackend::new("playground-piletopologytest");
        let provision = ProvisionSpec {
            tenant: Tenant {
                label: "faculty-write".to_string(),
            },
            cwd: None,
            env: vec![],
            faculty_pile: FacultyPile::Host(
                HostFacultyFiles::resolve(&durable).expect("resolve durable faculty files"),
            ),
        };
        backend
            .provision_sandbox(&provision)
            .expect("provision live topology sandbox");
        let id = backend
            .open_session(&open_spec("faculty-write"))
            .expect("open live topology sandbox");
        let result = backend.exec(
            &id,
            &ExecRequest {
                command: r#"set -eu
printf 'faculty-write\n' >> "$PILE"
if rm "$PILE" 2>/dev/null; then exit 70; fi
if mv "$PILE" /pile/replaced 2>/dev/null; then exit 71; fi
if touch /pile/replaced 2>/dev/null; then exit 72; fi
if chmod u+w /pile 2>/dev/null; then exit 73; fi
test "$(cat "$TRIBLESPACE_KEY")" = test-key
if printf x >> "$TRIBLESPACE_KEY" 2>/dev/null; then exit 74; fi"#
                    .to_string(),
                shell_mode: ExecShellMode::Login,
                cwd: None,
                stdin: None,
                timeout: Some(Duration::from_secs(120)),
            },
            &ExecControl::default(),
        );
        let _ = backend.destroy_session(&id);

        let result = result.expect("write through provisioned PILE");
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(
            std::fs::read(&durable).expect("read durable pile"),
            b"durable-before\nfaculty-write\n"
        );
        assert_eq!(
            std::fs::read(&ledger).expect("read cognition ledger"),
            b"ledger-before\n"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A stopped instance is brought up on open with `limactl start <instance>`
    /// (no `--name`, no config file — never re-renders).
    #[test]
    fn open_session_starts_stopped_instance() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-alice", "Stopped")]))
            .into_backend("t");
        let id = backend.open_session(&open_spec("alice")).expect("open");
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
        let err = backend
            .open_session(&open_spec("alice"))
            .expect_err("must bail");
        let msg = err.to_string();
        assert!(msg.contains("not provisioned"), "err: {msg}");
        assert!(
            msg.contains("playground user create alice --backend lima"),
            "err: {msg}"
        );
        assert!(
            !mock
                .calls()
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("start")),
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
        backend
            .provision_sandbox(&provision_spec("alice"))
            .expect("provision");
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
            create
                .last()
                .map(|p| p.ends_with("lima.yaml"))
                .unwrap_or(false),
            "create start must reference the rendered config: {create:?}"
        );
    }

    #[test]
    fn failed_cold_start_removes_sealed_views_and_allows_retry() {
        let state_root = std::env::temp_dir().join(format!(
            "playground-lima-failed-start-{}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed),
        ));
        let spec = provision_spec("retry");
        let files = match &spec.faculty_pile {
            FacultyPile::Host(files) => files.clone(),
            FacultyPile::BackendOwned => unreachable!(),
        };
        let (mut failing, _mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[]))
            .reply(
                &["start"],
                super::super::proc::ChildOutput {
                    exit_code: Some(1),
                    stderr: b"cold boot failed".to_vec(),
                    ..Default::default()
                },
            )
            .into_backend("t");
        failing.state_root = state_root.clone();
        let error = failing
            .provision_sandbox(&spec)
            .expect_err("failed cold start must surface");
        assert!(error.to_string().contains("cold boot failed"));
        assert!(
            !state_root.join("t-retry").exists(),
            "an absent VM must not strand sealed hardlink views"
        );
        assert_eq!(std::fs::read(files.pile()).unwrap(), b"pile");
        assert_eq!(std::fs::read(files.signing_key()).unwrap(), b"key");

        let (mut retry, _mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[]))
            .into_backend("t");
        retry.state_root = state_root;
        retry
            .provision_sandbox(&spec)
            .expect("retry after rolled-back cold start");
        assert!(
            retry
                .state_root
                .join("t-retry/faculty-files/pile/self.pile")
                .is_file()
        );
        retry
            .destroy_session(&SessionId::new("t-retry"))
            .expect("clean retry fixture");
    }

    /// Provision is idempotent: an already-running instance is left alone (no
    /// start, no re-render).
    #[test]
    fn provision_idempotent_when_running() {
        let (backend, mock) = MockRunner::default()
            .reply(&["list"], list_reply(&[("t-alice", "Running")]))
            .into_backend("t");
        backend
            .provision_sandbox(&provision_spec("alice"))
            .expect("provision");
        let calls = mock.calls();
        assert!(
            !calls
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("start")),
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
        backend
            .provision_sandbox(&provision_spec("alice"))
            .expect("provision");
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
        assert!(
            calls.is_empty(),
            "detach must issue no limactl commands: {calls:?}"
        );
    }

    /// destroy_session stops and deletes the instance, then unseals and removes
    /// only its private exact-file views. The original pile and key survive.
    #[test]
    fn destroy_session_stops_and_deletes() {
        let root = std::env::temp_dir().join(format!(
            "playground-lima-destroy-state-{}-{}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed),
        ));
        let (mut backend, mock) = MockRunner::default().into_backend("t");
        backend.state_root = root.clone();
        let spec = provision_spec("alice");
        let files = match &spec.faculty_pile {
            FacultyPile::Host(files) => files.clone(),
            FacultyPile::BackendOwned => unreachable!(),
        };
        let instance_dir = root.join("t-alice");
        backend
            .render_config(&spec, &instance_dir.join("lima.yaml"))
            .expect("prepare sealed faculty views");
        assert!(instance_dir.join("faculty-files/pile/self.pile").is_file());
        assert!(instance_dir.join("faculty-files/key/self.key").is_file());

        backend
            .destroy_session(&SessionId::new("t-alice"))
            .expect("destroy");
        assert!(
            !instance_dir.exists(),
            "destroy must remove config and unseal/remove faculty views"
        );
        assert_eq!(std::fs::read(files.pile()).unwrap(), b"pile");
        assert_eq!(std::fs::read(files.signing_key()).unwrap(), b"key");
        let calls = mock.calls();
        assert!(
            calls
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("stop")
                    && c.contains(&"t-alice".to_string())),
            "destroy must limactl stop: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.first().map(String::as_str) == Some("delete")
                    && c.contains(&"t-alice".to_string())),
            "destroy must limactl delete: {calls:?}"
        );
    }

    /// destroy_session refuses a name outside its instance namespace, issuing no
    /// commands at all.
    #[test]
    fn destroy_session_refuses_foreign_names() {
        let (backend, mock) = MockRunner::default().into_backend("t");
        for name in ["otherbox", "t-x/../../victim", "t-..", "t-"] {
            let err = backend
                .destroy_session(&SessionId::new(name))
                .expect_err("must refuse foreign or path-like name");
            assert!(err.to_string().contains("outside the 't-'"), "err: {err}");
        }
        assert!(
            mock.calls().is_empty(),
            "refusal issues no limactl commands"
        );
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
                    ("t-alice", "Running"),  // ours, up   -> stop
                    ("t-bob", "Stopped"),    // ours, down -> skip
                    ("otherbox", "Running"), // foreign    -> skip
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

//! Lima backend for the sandbox provider.
//!
//! This wires the [`SandboxBackend`] trait to the `limactl` lifecycle. It is a
//! *session-oriented* reworking of the provisioning that currently lives inline
//! in `crate::main` (`prepare_lima_service`, `ensure_lima_instance`,
//! `stop_lima_instance`, `render_lima_template`):
//!
//!   - `open_session`  = render a Lima config for this session's tenant +
//!     `limactl start --name <instance>`.
//!   - `exec`          = `limactl shell <instance> -- sh -lc <command>` with a
//!     wall-clock timeout (a *session* shell, not the pile-polling systemd
//!     service the `run` command provisions).
//!   - `close_session` = `limactl stop <instance>` (+ best-effort delete).
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
//! ## Append-only pile (the truncation fix)
//!
//! The pile is mounted writable over virtiofs (a truncate on the host would
//! break Time Machine, and macOS `chflags uappend` is host-side and does the
//! same damage — see the task brief). Append-only is therefore enforced
//! **guest-side**: on first boot the provision script sets the Linux
//! append-only inode attribute (`chattr +a`) on the pile file inside the guest.
//! See [`guest_pile_setup`] and the rendered template.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

use super::{ExecRequest, ExecResult, SandboxBackend, SessionId, SessionSpec};

/// Default per-command timeout when an [`ExecRequest`] does not specify one.
const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(300);
/// Poll cadence while waiting for a `limactl shell` child to finish.
const EXEC_POLL: Duration = Duration::from_millis(50);

/// Lima-instance-backed sandbox. One [`SessionId`] maps to one Lima instance
/// name.
///
/// A `LimaBackend` is stateless beyond its naming/template configuration; the
/// live set of sessions is tracked one layer up in
/// [`crate::mcp::SandboxProvider`]. Instance identity lives entirely in
/// `limactl`, so a restarted provider can still `close_session` an instance it
/// finds by name.
#[derive(Debug, Clone)]
pub struct LimaBackend {
    /// Instance-name prefix; the concrete instance is `<prefix>-<label>`.
    pub instance_prefix: String,
    /// Path to the Lima YAML template (with `__TOKEN__` placeholders). If unset,
    /// the backend falls back to `scripts/lima-session.yaml.tmpl` next to the
    /// crate, then `scripts/lima.yaml.tmpl`.
    pub template: Option<PathBuf>,
    /// Directory under which rendered per-session Lima configs are written.
    pub state_root: PathBuf,
}

impl Default for LimaBackend {
    fn default() -> Self {
        LimaBackend {
            instance_prefix: "playground-sbx".to_string(),
            template: None,
            state_root: std::env::temp_dir().join("playground-sandbox"),
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

    /// Deterministic instance name for a tenant label. Lima instance names must
    /// match `[A-Za-z0-9-]`, so the label is sanitised.
    fn instance_name(&self, label: &str) -> String {
        let safe: String = label
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("{}-{}", self.instance_prefix, safe)
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
        let config_path = self.state_root.join(&instance).join("lima.yaml");
        self.render_config(spec, &config_path)?;

        // Best-effort cleanup of a stale instance with the same name, mirroring
        // `crate::main::ensure_lima_instance`.
        let _ = Command::new("limactl")
            .args(["delete", "--force", &instance])
            .status();

        let status = Command::new("limactl")
            .args([
                "start",
                "--tty=false",
                "--name",
                &instance,
                &config_path.to_string_lossy(),
            ])
            .status()
            .context("run limactl start")?;
        if !status.success() {
            bail!("limactl start failed for instance '{instance}'");
        }
        Ok(SessionId::new(instance))
    }

    fn exec(&self, session: &SessionId, request: &ExecRequest) -> Result<ExecResult> {
        let instance = session.as_str();

        // limactl shell <instance> -- sh -lc <command>. A per-call cwd is applied
        // via `--workdir`; otherwise the guest default is used.
        let mut cmd = Command::new("limactl");
        cmd.arg("shell");
        if let Some(cwd) = &request.cwd {
            cmd.arg("--workdir").arg(cwd);
        }
        cmd.arg(instance).arg("--").arg("sh").arg("-lc").arg(&request.command);

        if request.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().context("spawn limactl shell")?;

        if let Some(bytes) = &request.stdin {
            use std::io::Write;
            if let Some(mut handle) = child.stdin.take() {
                let _ = handle.write_all(bytes);
            }
        }

        let timeout = request.timeout.unwrap_or(DEFAULT_EXEC_TIMEOUT);
        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        loop {
            match child.try_wait().context("wait on limactl shell")? {
                Some(_) => break,
                None => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    std::thread::sleep(EXEC_POLL);
                }
            }
        }

        let output = child.wait_with_output().context("collect limactl shell output")?;
        let mut result = ExecResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.status.code(),
            error: None,
        };
        if timed_out {
            result.exit_code = Some(124);
            result.error = Some(format!("command timed out after {timeout:?}"));
        }
        Ok(result)
    }

    fn close_session(&self, session: &SessionId) -> Result<()> {
        let instance = session.as_str();
        let status = Command::new("limactl")
            .args(["stop", instance])
            .status()
            .context("run limactl stop")?;
        if !status.success() {
            bail!("limactl stop failed for instance '{instance}'");
        }
        // Best-effort delete so a subsequent open_session with the same label
        // starts clean.
        let _ = Command::new("limactl")
            .args(["delete", "--force", instance])
            .status();
        Ok(())
    }
}

/// Guest-side commands that make the pile mount append-only.
///
/// The pile arrives via a *writable* virtiofs mount at `/pile` (writability is
/// required so the driver can append commits). To prevent truncation/replacement
/// from inside the guest, the boot provision sets the ext4/Linux append-only
/// inode attribute with `chattr +a`. With `+a` set, a file may be opened for
/// append (`O_APPEND`) and read, but `open(..., O_TRUNC)`, `unlink`, and rename
/// fail with `EPERM` — even for root inside the guest. Because triblespace piles
/// are append-only log files, this is exactly the right constraint: normal
/// commits keep working, truncation cannot happen.
///
/// Caveat worth flagging for review: `chattr +a` semantics depend on the guest
/// filesystem honouring inode attributes. On the *virtiofs-backed* mount the
/// attribute is applied to the guest-visible inode; a determined guest process
/// cannot clear it without `CAP_LINUX_IMMUTABLE` (which the session user lacks),
/// but a guest with root *could* `chattr -a`. For a hostile-tenant threat model
/// the durable guarantee still comes from the host never exposing a truncating
/// handle plus append-only being re-asserted each boot; this fragment is the
/// first, cheap line of defence and the structural fix for the accidental
/// (non-adversarial) truncation class from 2026-07.
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

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
        let _ = backend.close_session(&id);
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
}

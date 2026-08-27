//! Host-command transports shared by every host-driven sandbox backend.
//!
//! A backend that provisions a sandbox by driving privileged commands on a host
//! — FreeBSD jails ([`super::jail`]), Linux rootless containers
//! ([`super::podman`]) — needs exactly one seam: "run this argv over there, feed
//! it this stdin, kill it after this long, and tell me what it printed". That
//! seam is [`HostRunner`], and the two production transports behind it are
//! [`SshRunner`] (drive a remote host over `ssh -o BatchMode=yes`) and
//! [`LocalRunner`] (the same argv spawned directly, because this machine IS the
//! host).
//!
//! This module was lifted verbatim out of `jail.rs` when the Linux backend
//! landed: it is transport, not FreeBSD policy, and a second backend that copied
//! it would have copied the output caps, the cancellation contract, and the
//! `sudo -n` elision along with it — each of them a place where the two copies
//! could later disagree. Tests inject a mock runner here, mirroring how
//! `crate::mcp` tests inject a mock backend.

use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use super::ExecControl;
use super::proc::{
    drive_child, drive_child_capped_controlled, drive_child_capped_controlled_process_group,
};

/// Output of one host command, however it was transported. Local-backstop
/// timeouts set `timed_out`; a server-side `timeout(1)` expiry shows up as
/// `exit_code == Some(124)` instead.
pub use super::proc::ChildOutput as HostOutput;

/// Runs one argv on the sandbox host. The seam that makes a host-driven backend
/// testable without the real host (mirror of the mock-backend pattern in
/// `crate::mcp` tests).
pub trait HostRunner: Send + Sync {
    /// Run `argv` on the host, optionally feeding `stdin`, killing after
    /// `timeout` wall-clock. Implementations must capture stdout/stderr
    /// completely (drain concurrently — a full pipe must not deadlock the
    /// child). Used for administrative host commands whose output is bounded by
    /// construction (zfs/jail/mount).
    fn run(&self, argv: &[String], stdin: Option<&[u8]>, timeout: Duration) -> Result<HostOutput>;

    /// True only when this runner can prove cancellation of the command tree,
    /// not merely termination of a local transport wrapper.
    fn supports_background_jobs(&self) -> bool {
        false
    }

    /// Like [`run`](Self::run), but with an output policy suitable for a tenant
    /// command. When `control` has no streaming sink, implementations retain at
    /// most `max_output_bytes` from each captured stream
    /// (`ChildOutput::output_truncated` records a breach). Child-only transports
    /// stop on breach; the local descendant-reaper transport keeps draining so
    /// memory stays bounded without losing cleanup proof. With a sink, output
    /// drains into the separately bounded job ring and is not duplicated in the
    /// returned buffers. The default is unbounded (delegates to `run`), correct
    /// only for a runner that never carries a tenant command; production runners
    /// override it.
    fn run_capped(
        &self,
        argv: &[String],
        stdin: Option<&[u8]>,
        timeout: Duration,
        _max_output_bytes: usize,
        control: &ExecControl,
    ) -> Result<HostOutput> {
        if control.is_cancelled() {
            return Ok(HostOutput {
                cancelled: true,
                ..Default::default()
            });
        }
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
        let remote = argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let mut cmd = Command::new("ssh");
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(format!("ConnectTimeout={}", self.connect_timeout.as_secs()))
            .arg(&self.host)
            .arg(remote);

        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
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
        control: &ExecControl,
    ) -> Result<HostOutput> {
        let remote = argv
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let mut cmd = Command::new("ssh");
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(format!("ConnectTimeout={}", self.connect_timeout.as_secs()))
            .arg(&self.host)
            .arg(remote);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let child = cmd.spawn().context("spawn ssh")?;
        // Killing the LOCAL ssh on a cap breach also tears down the pipe to the
        // remote; the authoritative remote-side kill of the jail process tree is
        // the backend's `timeout(1)` wrapper (server-side, exit 124). The cap is
        // the daemon-memory bound; the timeout is the process-tree bound.
        drive_child_capped_controlled(
            child,
            stdin.map(|b| b.to_vec()),
            timeout,
            max_output_bytes,
            control,
        )
    }

    fn transport_error_exit(&self) -> Option<i32> {
        Some(255) // ssh reserves 255 for its own failures
    }
}

/// Server-side hosting runner: spawn the argv directly on this machine (which
/// *is* the sandbox host), no ssh wrapper and no re-quoting — the argv reaches
/// `execve` verbatim. Everything else (root via `sudo -n`, the command
/// vocabulary, the namespace guard) is identical to [`SshRunner`], so the two
/// are interchangeable behind a backend.
#[derive(Debug, Clone, Default)]
pub struct LocalRunner;

impl HostRunner for LocalRunner {
    fn supports_background_jobs(&self) -> bool {
        // The proof boundary is FreeBSD timeout(1) itself. When the daemon is
        // root we exec it directly; a preceding sudo wrapper would make the
        // observed group leader ambiguous, so fail closed in that mode. Other
        // Unix timeout implementations do not promise FreeBSD's PROC_REAP
        // descendant semantics, even when this process happens to be root.
        cfg!(target_os = "freebsd") && running_as_root()
    }

    fn run(&self, argv: &[String], stdin: Option<&[u8]>, timeout: Duration) -> Result<HostOutput> {
        let argv = local_argv(argv, running_as_root());
        let Some((program, args)) = argv.split_first() else {
            bail!("empty argv");
        };
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
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
        control: &ExecControl,
    ) -> Result<HostOutput> {
        let argv = local_argv(argv, running_as_root());
        let Some((program, args)) = argv.split_first() else {
            bail!("empty argv");
        };
        let mut cmd = Command::new(program);
        cmd.args(args);
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        // Make the FreeBSD timeout(1) descendant reaper the leader of a fresh
        // host process group, so cancellation targets exactly this exec tree.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let child = cmd.spawn().with_context(|| format!("spawn {program}"))?;
        drive_child_capped_controlled_process_group(
            child,
            stdin.map(|b| b.to_vec()),
            timeout,
            max_output_bytes,
            control,
        )
    }
}

/// When the daemon itself is root, `sudo -n` is redundant and would obscure
/// the timeout process-group/reaper boundary. Retain it for non-root hosts.
fn local_argv(argv: &[String], is_root: bool) -> &[String] {
    if is_root
        && argv.first().map(String::as_str) == Some("sudo")
        && argv.get(1).map(String::as_str) == Some("-n")
    {
        &argv[2..]
    } else {
        argv
    }
}

#[cfg(unix)]
fn running_as_root() -> bool {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() == 0 }
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    /// LocalRunner really spawns the argv on this machine: argv reaches the
    /// process verbatim (no shell re-parse), stdin is fed, both output
    /// streams and the exit code come back. (Pipe-buffer-sized payloads and
    /// timeout kills are covered by `super::proc`'s own tests.)
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

    #[test]
    fn root_local_runner_elides_redundant_sudo_prefix() {
        let argv = vec!["sudo".to_string(), "-n".to_string(), "timeout".to_string()];
        assert_eq!(local_argv(&argv, true), &argv[2..]);
        assert_eq!(local_argv(&argv, false), argv.as_slice());
    }

    #[cfg(not(target_os = "freebsd"))]
    #[test]
    fn non_freebsd_local_runner_never_advertises_background_jobs() {
        assert!(!LocalRunner.supports_background_jobs());
    }

    /// Exit 255 is a *transport* error only where a transport exists (ssh).
    /// For a runner without one (LocalRunner) it is an ordinary exit code.
    #[test]
    fn transport_error_exit_is_ssh_only() {
        assert_eq!(LocalRunner.transport_error_exit(), None);
        assert_eq!(SshRunner::new("h").transport_error_exit(), Some(255));
    }
}

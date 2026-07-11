//! Deadlock-free child-process driving for sandbox backends.
//!
//! The naive pattern — spawn with piped stdio, `write_all` the stdin, then
//! poll `try_wait` against a deadline and only *afterwards* collect output —
//! deadlocks in two ways once payloads exceed the OS pipe buffer (~64 KiB):
//!
//!   1. **stdout/stderr fill**: the child blocks writing to a full pipe nobody
//!      is reading, so it never exits; the poll loop spins until the timeout
//!      and reports a spurious `timed_out` for a command that had finished its
//!      work.
//!   2. **stdin fill**: `write_all` on the caller's thread blocks on a full
//!      stdin pipe while the child blocks on its full stdout pipe — mutual
//!      deadlock *before* the timeout loop even starts, so nothing ever kills
//!      anything.
//!
//! [`drive_child`] is the one shared fix (first shipped inside
//! [`super::jail`]'s `SshRunner`, extracted here for
//! [`super::lima::LimaBackend`] and any future backend): stdin is fed from its
//! own thread, stdout/stderr are drained to completion on their own threads,
//! and the caller's thread does nothing but poll for exit and enforce the
//! wall-clock timeout.

use std::io::Read;
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Poll cadence while waiting for a driven child to finish.
pub const EXEC_POLL: Duration = Duration::from_millis(50);

/// Captured output of one driven child, however it was transported
/// (`limactl shell`, `ssh`, a bare local process, ...).
#[derive(Debug, Default, Clone)]
pub struct ChildOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    /// True iff the *local* wall-clock backstop killed the child. Remote-side
    /// kills (e.g. FreeBSD `timeout(1)` on a jail host) surface as
    /// `exit_code == Some(124)` instead.
    pub timed_out: bool,
}

impl ChildOutput {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Drive a freshly spawned `child` to completion without pipe deadlocks.
///
/// The caller configures the `Command` (argv, which stdio handles are piped)
/// and spawns it; this function owns everything after `spawn()`:
///
///   - `stdin` bytes (if any) are written from a dedicated thread; dropping
///     the handle afterwards closes the pipe so the child sees EOF. Requires
///     `Stdio::piped()` on stdin iff `stdin` is `Some`.
///   - Piped stdout/stderr are drained to completion on dedicated threads, so
///     a child producing more than a pipe buffer of output can always make
///     progress. Handles that were not piped are simply absent (`take()`
///     yields `None`) and skipped.
///   - The calling thread polls `try_wait` every [`EXEC_POLL`] and kills the
///     child once `timeout` elapses; whatever output was drained before the
///     kill is still returned alongside `timed_out = true`.
pub fn drive_child(mut child: Child, stdin: Option<Vec<u8>>, timeout: Duration) -> Result<ChildOutput> {
    let stdin_thread = match (stdin, child.stdin.take()) {
        (Some(bytes), Some(mut handle)) => Some(std::thread::spawn(move || {
            use std::io::Write;
            let _ = handle.write_all(&bytes);
            // drop closes the pipe so the child sees EOF
        })),
        _ => None,
    };

    let out_thread = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let err_thread = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().context("wait on sandbox child")? {
            Some(status) => break status,
            None => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().context("reap killed sandbox child")?;
                }
                std::thread::sleep(EXEC_POLL);
            }
        }
    };

    // Killing (or exiting) closes the child's pipe ends, so these joins
    // terminate: the writer hits EPIPE, the readers hit EOF.
    if let Some(t) = stdin_thread {
        let _ = t.join();
    }
    let stdout = out_thread.map(|t| t.join().unwrap_or_default()).unwrap_or_default();
    let stderr = err_thread.map(|t| t.join().unwrap_or_default()).unwrap_or_default();
    Ok(ChildOutput {
        stdout,
        stderr,
        exit_code: status.code(),
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// Comfortably past any OS pipe buffer (64 KiB is the classic size;
    /// macOS can grow to 128 KiB under pressure).
    const BIG: usize = 1024 * 1024;

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd
    }

    #[test]
    fn drains_large_stdout_without_deadlock() {
        // The naive poll loop spins until the timeout here, because the child
        // blocks writing into an undrained pipe and can never exit.
        let child = sh("dd if=/dev/zero bs=1024 count=1024 2>/dev/null")
            .spawn()
            .expect("spawn");
        let out = drive_child(child, None, Duration::from_secs(30)).expect("drive");
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout.len(), BIG);
    }

    #[test]
    fn drains_large_stdout_and_stderr_concurrently() {
        // Second dd: `1>&2` first (dup the stderr *pipe* into fd 1), then
        // `2>/dev/null` for dd's own diagnostics — the reverse order would
        // send the payload to /dev/null.
        let child = sh(
            "dd if=/dev/zero bs=1024 count=1024 2>/dev/null; \
             dd if=/dev/zero bs=1024 count=1024 1>&2 2>/dev/null",
        )
        .spawn()
        .expect("spawn");
        let out = drive_child(child, None, Duration::from_secs(30)).expect("drive");
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout.len(), BIG);
        assert_eq!(out.stderr.len(), BIG);
    }

    #[test]
    fn feeds_large_stdin_while_draining_stdout() {
        // /bin/cat with >pipe-buffer stdin exercises the *mutual* deadlock:
        // write_all on the caller's thread blocks on a full stdin pipe while
        // cat blocks on its full stdout pipe. Only concurrent feed+drain
        // survives this.
        let mut cmd = Command::new("/bin/cat");
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let child = cmd.spawn().expect("spawn");
        let bytes = vec![b'x'; BIG];
        let out = drive_child(child, Some(bytes.clone()), Duration::from_secs(30)).expect("drive");
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, bytes);
    }

    #[test]
    fn kills_on_timeout() {
        let child = sh("sleep 30").spawn().expect("spawn");
        let start = Instant::now();
        let out = drive_child(child, None, Duration::from_millis(200)).expect("drive");
        assert!(out.timed_out);
        assert!(!out.success());
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout kill must not wait for the child's own exit"
        );
    }

    #[test]
    fn timeout_preserves_output_drained_before_the_kill() {
        let child = sh("printf hello; sleep 30").spawn().expect("spawn");
        let out = drive_child(child, None, Duration::from_millis(300)).expect("drive");
        assert!(out.timed_out);
        assert_eq!(out.stdout, b"hello");
    }

    #[test]
    fn reports_exit_code_and_stderr() {
        let child = sh("echo oops >&2; exit 3").spawn().expect("spawn");
        let out = drive_child(child, None, Duration::from_secs(10)).expect("drive");
        assert!(!out.timed_out);
        assert!(!out.success());
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.stderr_lossy(), "oops");
    }
}

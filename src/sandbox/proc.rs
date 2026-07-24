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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Poll cadence while waiting for a driven child to finish.
pub const EXEC_POLL: Duration = Duration::from_millis(50);

/// Per-stream output ceiling used by the sandbox backends: each of stdout and
/// stderr is capped independently at this many bytes, and the child is KILLED
/// the moment either exceeds it (see [`drive_child`]). A tenant that runs
/// `cat /dev/zero` therefore cannot make the daemon accumulate unbounded memory
/// upstream of any reverse-proxy response cap — the process is terminated at the
/// cap, not merely truncated while it keeps producing. 16 MiB comfortably fits
/// any honest command's output while bounding a single exec's memory.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

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
    /// True iff the child was KILLED because it exceeded the per-stream output
    /// ceiling. The captured `stdout`/`stderr` hold exactly the bytes read up to
    /// (and a little past) the cap; the process was terminated, not left running.
    pub output_truncated: bool,
}

impl ChildOutput {
    pub fn success(&self) -> bool {
        !self.timed_out && !self.output_truncated && self.exit_code == Some(0)
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Read from `pipe` into `buf`, stopping once `buf` reaches `cap` bytes. When
/// the cap is hit, flip `tripped` (so the poll loop can KILL the child) and
/// return: nothing further is read, so the pipe fills, and once the killed
/// child's write end is closed the drain terminates. Reads in bounded chunks so
/// a single `read` can never blow far past `cap`.
fn read_capped(mut pipe: impl Read, cap: usize, tripped: &AtomicBool) -> Vec<u8> {
    // Cap of 0 means "unbounded" (used where no ceiling is wanted).
    if cap == 0 {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        return buf;
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= cap {
                    // Trip the kill switch and stop draining. The poll loop sees
                    // `tripped` and kills the child; the closed write end then
                    // lets the (now-unread) pipe EOF so the caller's join returns.
                    tripped.store(true, Ordering::SeqCst);
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    buf
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
///
/// Convenience wrapper with no output ceiling (`max_output_bytes = 0`), for
/// call sites that do not run untrusted commands. The sandbox backends use
/// [`drive_child_capped`] with [`DEFAULT_MAX_OUTPUT_BYTES`].
pub fn drive_child(child: Child, stdin: Option<Vec<u8>>, timeout: Duration) -> Result<ChildOutput> {
    drive_child_capped(child, stdin, timeout, 0)
}

/// Like [`drive_child`], but caps each of stdout/stderr at `max_output_bytes`
/// and KILLS the child the instant either stream exceeds the cap (a `0` cap
/// means unbounded). This is the resource bound for tenant-controlled output:
/// the process is terminated at the ceiling, not merely truncated while it keeps
/// producing, so `cat /dev/zero` cannot make the daemon accumulate unbounded
/// memory. On a cap kill the result carries `output_truncated = true` and the
/// bytes read up to the cap.
pub fn drive_child_capped(
    mut child: Child,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<ChildOutput> {
    let stdin_thread = match (stdin, child.stdin.take()) {
        (Some(bytes), Some(mut handle)) => Some(std::thread::spawn(move || {
            use std::io::Write;
            let _ = handle.write_all(&bytes);
            // drop closes the pipe so the child sees EOF
        })),
        _ => None,
    };

    // Shared trip flag: either drain thread sets it when its stream exceeds the
    // cap, and the poll loop reacts by killing the child (see below).
    let tripped = Arc::new(AtomicBool::new(false));

    let out_thread = child.stdout.take().map(|pipe| {
        let tripped = tripped.clone();
        std::thread::spawn(move || read_capped(pipe, max_output_bytes, &tripped))
    });
    let err_thread = child.stderr.take().map(|pipe| {
        let tripped = tripped.clone();
        std::thread::spawn(move || read_capped(pipe, max_output_bytes, &tripped))
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut output_truncated = false;
    let status = loop {
        match child.try_wait().context("wait on sandbox child")? {
            Some(status) => break status,
            None => {
                // Output ceiling breached: kill the child NOW so it stops
                // producing (rather than truncating the buffer while it runs on).
                if tripped.load(Ordering::SeqCst) {
                    output_truncated = true;
                    let _ = child.kill();
                    break child.wait().context("reap output-capped sandbox child")?;
                }
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
    // A cap trip may only be observed by a drain thread AFTER the poll loop
    // already saw the child exit on its own (a fast finisher). Fold that in so
    // the flag reflects "the cap was exceeded" regardless of which raced first.
    output_truncated |= tripped.load(Ordering::SeqCst);
    Ok(ChildOutput {
        stdout,
        stderr,
        exit_code: status.code(),
        timed_out,
        output_truncated,
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

    #[test]
    fn output_cap_kills_a_runaway_producer_and_signals() {
        // `yes` streams forever. Without the cap+kill this would run until the
        // 30s timeout (or forever if unbounded); with it, the child is killed
        // the moment stdout crosses the ceiling — quickly and with a clear
        // signal, NOT merely truncated while it keeps producing.
        let cap = 256 * 1024;
        let child = sh("yes AAAAAAAA").spawn().expect("spawn");
        let start = Instant::now();
        let out = drive_child_capped(child, None, Duration::from_secs(30), cap).expect("drive");
        assert!(out.output_truncated, "cap breach must be signalled");
        assert!(!out.success(), "an output-capped run is not a success");
        assert!(!out.timed_out, "the cap kill, not the timeout, fired");
        // Captured up to the cap plus at most one 64 KiB chunk of slack.
        assert!(out.stdout.len() >= cap, "captured at least the cap");
        assert!(out.stdout.len() < cap + 128 * 1024, "did not run far past the cap");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the process must be KILLED at the cap, not left to run to the timeout"
        );
    }

    #[test]
    fn output_cap_on_stderr_also_kills() {
        let cap = 256 * 1024;
        let child = sh("yes BBBBBBBB 1>&2").spawn().expect("spawn");
        let out = drive_child_capped(child, None, Duration::from_secs(30), cap).expect("drive");
        assert!(out.output_truncated);
        assert!(out.stderr.len() >= cap);
    }

    #[test]
    fn output_under_the_cap_is_a_clean_success() {
        // A command whose output is comfortably under the ceiling completes
        // normally, with no truncation flag.
        let child = sh("printf 'small output\\n'").spawn().expect("spawn");
        let out = drive_child_capped(child, None, Duration::from_secs(10), 1024 * 1024)
            .expect("drive");
        assert!(!out.output_truncated);
        assert!(out.success());
        assert_eq!(out.stdout, b"small output\n");
    }
}

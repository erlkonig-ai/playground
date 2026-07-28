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

use anyhow::{Context, Result, anyhow};

use super::{ExecControl, ExecStream, sandbox_control_lost};

/// Poll cadence while waiting for a driven child to finish.
pub const EXEC_POLL: Duration = Duration::from_millis(50);

/// Grace between TERM and KILL when cancelling a dedicated process group.
/// FreeBSD `timeout(1)` gets five seconds to reap its descendant tree, so the
/// local backstop must be strictly longer instead of racing the same deadline.
const CANCEL_TERM_GRACE: Duration = Duration::from_secs(7);

/// Per-stream capture ceiling for direct executions. Job-managed executions
/// stream into their own bounded ring instead, so they keep draining after old
/// output is evicted without duplicating it here.
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
    /// True iff a captured (non-streamed) child exceeded the per-stream output
    /// ceiling. Child-only transports are killed; a local descendant-reaper
    /// transport keeps draining while retaining only the bounded prefix, so it
    /// never sacrifices cleanup proof merely to enforce the memory bound.
    pub output_truncated: bool,
    /// True iff an [`ExecControl`] cancellation request killed this child.
    pub cancelled: bool,
    /// Evidence that cancellation targeted a fresh process group rather than
    /// only the transported child and that its descendant reaper exited
    /// naturally. A capable backend treats cancellation without this proof as
    /// process-fatal rather than attempting another sandbox state transition.
    pub cancelled_process_group: bool,
}

impl ChildOutput {
    pub fn success(&self) -> bool {
        !self.timed_out && !self.output_truncated && !self.cancelled && self.exit_code == Some(0)
    }
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Drain one output pipe. A plain execution captures into `buf` and trips its
/// produced-output ceiling. A streamed execution sends every chunk to its
/// bounded sink without retaining a duplicate here; filling the sink's ring is
/// therefore never a reason to stop draining or kill the command.
fn read_capped(
    mut pipe: impl Read,
    cap: usize,
    tripped: &AtomicBool,
    control: &ExecControl,
    stream: ExecStream,
    stop_on_cap: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let capture_output = control.captures_output();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                control.emit(stream, &chunk[..n]);
                let exceeded_cap = capture_output && cap != 0 && n > cap.saturating_sub(buf.len());
                if capture_output {
                    let remaining = cap.saturating_sub(buf.len());
                    let retained = if cap == 0 { n } else { n.min(remaining) };
                    buf.extend_from_slice(&chunk[..retained]);
                }
                // Cap of 0 means "unbounded". Streamed executions retain their
                // own bounded ring and deliberately keep draining after
                // eviction instead of turning model polling speed into command
                // semantics.
                if exceeded_cap {
                    tripped.store(true, Ordering::SeqCst);
                    if stop_on_cap {
                        // Child-only transports must stop the producer. The
                        // poll loop kills it and the closed write end lets this
                        // deliberately abandoned pipe reach EOF.
                        break;
                    }
                    // A local descendant reaper is the stronger cleanup
                    // boundary. Keep draining, but retain no more bytes: the
                    // server-side timeout remains authoritative and the daemon
                    // never kills its own proof witness just to bound memory.
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
/// [`drive_child_capped_controlled`] with [`DEFAULT_MAX_OUTPUT_BYTES`].
pub fn drive_child(child: Child, stdin: Option<Vec<u8>>, timeout: Duration) -> Result<ChildOutput> {
    drive_child_controlled(child, stdin, timeout, &ExecControl::default())
}

/// Like [`drive_child`], with cooperative cancellation and streaming output.
pub fn drive_child_controlled(
    child: Child,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    control: &ExecControl,
) -> Result<ChildOutput> {
    drive_child_capped_inner(
        child,
        stdin,
        timeout,
        0,
        control,
        CancelTarget::Child,
        CANCEL_TERM_GRACE,
    )
}

/// Like [`drive_child`], but with a per-stream capture cap, cooperative
/// cancellation, and streamed stdout/stderr chunks. Cancellation kills and
/// reaps the transported child.
pub fn drive_child_capped_controlled(
    child: Child,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    max_output_bytes: usize,
    control: &ExecControl,
) -> Result<ChildOutput> {
    drive_child_capped_inner(
        child,
        stdin,
        timeout,
        max_output_bytes,
        control,
        CancelTarget::Child,
        CANCEL_TERM_GRACE,
    )
}

/// Controlled child driver for a command configured as the leader of a fresh
/// host process group. Cancellation sends TERM to that group, waits seven
/// seconds for a descendant reaper such as FreeBSD `timeout(1)`, then sends
/// KILL to the group if the leader has not exited. Once the reaper must be
/// force-killed, descendant cleanup is no longer provable: return a typed fatal
/// error immediately instead of waiting on a possibly stuck leader or pipe.
pub fn drive_child_capped_controlled_process_group(
    child: Child,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    max_output_bytes: usize,
    control: &ExecControl,
) -> Result<ChildOutput> {
    drive_child_capped_inner(
        child,
        stdin,
        timeout,
        max_output_bytes,
        control,
        CancelTarget::ProcessGroup,
        CANCEL_TERM_GRACE,
    )
    .map_err(|error| sandbox_control_lost(format!("{error:#}")))
}

#[derive(Debug, Clone, Copy)]
enum CancelTarget {
    Child,
    ProcessGroup,
}

#[cfg(unix)]
fn signal_process_group(process_group: u32, signal: i32) -> std::io::Result<()> {
    let process_group =
        i32::try_from(process_group).map_err(|_| std::io::Error::other("child pid exceeds i32"))?;
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    // A negative pid addresses the process group whose id is `-pid`.
    if unsafe { kill(-process_group, signal) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn signal_process_group(_process_group: u32, _signal: i32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "process-group cancellation requires Unix",
    ))
}

fn drive_child_capped_inner(
    mut child: Child,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    max_output_bytes: usize,
    control: &ExecControl,
    cancel_target: CancelTarget,
    cancel_term_grace: Duration,
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
    // cap. Child-only transports stop the producer; a process-group transport
    // keeps draining past the retained prefix so its descendant reaper remains
    // the authoritative cleanup boundary.
    let tripped = Arc::new(AtomicBool::new(false));
    let stop_on_cap = matches!(cancel_target, CancelTarget::Child);

    let out_thread = child.stdout.take().map(|pipe| {
        let tripped = tripped.clone();
        let control = control.clone();
        std::thread::spawn(move || {
            read_capped(
                pipe,
                max_output_bytes,
                &tripped,
                &control,
                ExecStream::Stdout,
                stop_on_cap,
            )
        })
    });
    let err_thread = child.stderr.take().map(|pipe| {
        let tripped = tripped.clone();
        let control = control.clone();
        std::thread::spawn(move || {
            read_capped(
                pipe,
                max_output_bytes,
                &tripped,
                &control,
                ExecStream::Stderr,
                stop_on_cap,
            )
        })
    });

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut output_truncated = false;
    let mut cancelled = false;
    let mut cancelled_process_group = false;
    let status = 'wait: loop {
        match child.try_wait().context("wait on sandbox child")? {
            Some(status) => break status,
            None => {
                if control.is_cancelled() {
                    if matches!(cancel_target, CancelTarget::ProcessGroup) {
                        if signal_process_group(child.id(), 15).is_ok() {
                            cancelled = true;
                            let kill_deadline = Instant::now() + cancel_term_grace;
                            loop {
                                if let Some(status) = child
                                    .try_wait()
                                    .context("wait on cancelled process-group leader")?
                                {
                                    // The FreeBSD timeout(1) leader exits only
                                    // after its PROC_REAP subtree is empty. A
                                    // natural leader exit is therefore proof;
                                    // merely delivering TERM is not.
                                    cancelled_process_group = true;
                                    break 'wait status;
                                }
                                if Instant::now() >= kill_deadline {
                                    // Killing the reaper destroys the proof that
                                    // escaped descendants are gone. Best-effort
                                    // KILL, then fail immediately; process exit
                                    // will reap the leader and an operator owns
                                    // recovery of the still-live jail.
                                    let _ = signal_process_group(child.id(), 9);
                                    let _ = child.kill();
                                    return Err(anyhow!(
                                        "descendant reaper did not finish cancellation within {cancel_term_grace:?}"
                                    ));
                                }
                                std::thread::sleep(EXEC_POLL);
                            }
                        }

                        // TERM may lose a race with natural completion. Give
                        // that completion priority; otherwise kill the leader
                        // best-effort and revoke the daemon's execution authority.
                        if let Some(status) = child
                            .try_wait()
                            .context("recheck process-group leader after TERM failure")?
                        {
                            break 'wait status;
                        }
                        let _ = child.kill();
                        return Err(anyhow!(
                            "could not signal the command process group; descendant cleanup is unproven"
                        ));
                    }

                    // A child-only transport has no descendant-tree proof. If
                    // it already completed, natural completion wins; otherwise
                    // a successful kill is the cancellation linearization.
                    if let Some(status) = child
                        .try_wait()
                        .context("recheck sandbox child before cancellation")?
                    {
                        break status;
                    }
                    child.kill().context("kill cancelled sandbox child")?;
                    cancelled = true;
                    break child.wait().context("reap cancelled sandbox child")?;
                }
                // A child-only transport is killed on the first cap breach. A
                // local process-group transport keeps draining but retaining no
                // more bytes; its server-side reaper remains alive and bounded.
                if tripped.load(Ordering::SeqCst) && !output_truncated {
                    output_truncated = true;
                    if matches!(cancel_target, CancelTarget::ProcessGroup) {
                        continue;
                    }
                    let _ = child.kill();
                    break child.wait().context("reap output-capped sandbox child")?;
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    if matches!(cancel_target, CancelTarget::ProcessGroup) {
                        // A failed/hung descendant reaper cannot be the thing
                        // whose exit or pipe EOF we synchronously await.
                        let _ = signal_process_group(child.id(), 9);
                        let _ = child.kill();
                        return Err(anyhow!(
                            "local execution watchdog expired before the descendant reaper exited"
                        ));
                    }
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
    let stdout = out_thread
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = err_thread
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
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
        cancelled,
        cancelled_process_group,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;

    /// Comfortably past any OS pipe buffer (64 KiB is the classic size;
    /// macOS can grow to 128 KiB under pressure).
    const BIG: usize = 1024 * 1024;

    #[cfg(unix)]
    const ESCAPED_HOLDER_PID_FILE: &str = "PLAYGROUND_ESCAPED_HOLDER_PID_FILE";
    #[cfg(unix)]
    const ESCAPED_HOLDER_MODE: &str = "PLAYGROUND_ESCAPED_HOLDER_MODE";

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd
    }

    /// Subprocess helper for
    /// [`process_group_hard_kills_fail_without_joining_escaped_pipe_holders`].
    ///
    /// The parent test starts this test binary underneath a driven shell. This
    /// helper then creates a new session, escaping the shell's process group,
    /// while deliberately retaining the inherited stdout/stderr pipes. In a
    /// normal test-harness run the marker variable is absent and this is a no-op.
    #[cfg(unix)]
    #[test]
    fn escaped_pipe_holder_process() {
        let Some(pid_file) = std::env::var_os(ESCAPED_HOLDER_PID_FILE) else {
            return;
        };

        unsafe extern "C" {
            fn setsid() -> i32;
        }
        let session = unsafe { setsid() };
        assert_ne!(
            session,
            -1,
            "escaped pipe-holder helper must create a fresh session: {}",
            std::io::Error::last_os_error()
        );
        std::fs::write(&pid_file, std::process::id().to_string())
            .expect("publish escaped pipe-holder pid");

        if std::env::var(ESCAPED_HOLDER_MODE).as_deref() == Ok("spam") {
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            let chunk = [b'x'; 16 * 1024];
            while stdout.write_all(&chunk).is_ok() {}
        }

        // Long enough that the old synchronous drain joins make the regression
        // visibly fail, yet bounded so a failing test cannot leak indefinitely.
        std::thread::sleep(Duration::from_secs(5));
    }

    #[cfg(unix)]
    fn shell_quote_for_test(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    /// PID guard for an escaped grandchild. Once its driven shell is killed it
    /// is adopted by the OS reaper, so cleanup sends KILL and waits until pid 0
    /// probing reports that the reaper has collected it.
    #[cfg(unix)]
    struct EscapedHolder {
        pid: i32,
        pid_file: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl EscapedHolder {
        fn signal(&self, signal: i32) -> std::io::Result<()> {
            unsafe extern "C" {
                fn kill(pid: i32, signal: i32) -> i32;
            }
            if unsafe { kill(self.pid, signal) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        fn terminate_and_wait_for_reap(&mut self) {
            let _ = self.signal(9);
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if self.signal(0).is_err() {
                    self.pid = 0;
                    let _ = std::fs::remove_file(&self.pid_file);
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("escaped pipe-holder pid {} was not reaped", self.pid);
        }
    }

    #[cfg(unix)]
    impl Drop for EscapedHolder {
        fn drop(&mut self) {
            if self.pid > 0 {
                let _ = self.signal(9);
            }
            let _ = std::fs::remove_file(&self.pid_file);
        }
    }

    #[cfg(unix)]
    fn spawn_escaped_pipe_holder(mode: &str) -> (Child, EscapedHolder) {
        use std::os::unix::process::CommandExt;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let pid_file = std::env::temp_dir().join(format!(
            "playground-escaped-holder-{}-{nonce}.pid",
            std::process::id()
        ));
        let executable = std::env::current_exe().expect("current test executable");
        let script = format!(
            "{} escaped_pipe_holder_process --nocapture & helper=$!; wait \"$helper\"",
            shell_quote_for_test(&executable.to_string_lossy())
        );
        let mut command = sh(&script);
        command.env(ESCAPED_HOLDER_PID_FILE, &pid_file);
        command.env(ESCAPED_HOLDER_MODE, mode);
        command.process_group(0);
        let mut child = command.spawn().expect("spawn escaped pipe-holder shell");

        let deadline = Instant::now() + Duration::from_secs(5);
        let pid = loop {
            if let Ok(contents) = std::fs::read_to_string(&pid_file)
                && let Ok(pid) = contents.trim().parse::<i32>()
            {
                break pid;
            }
            if let Some(status) = child.try_wait().expect("poll helper shell") {
                panic!("escaped pipe-holder helper exited before publishing pid: {status}");
            }
            if Instant::now() >= deadline {
                let _ = signal_process_group(child.id(), 9);
                let _ = child.kill();
                let _ = child.wait();
                panic!("escaped pipe-holder helper did not publish its pid");
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        (child, EscapedHolder { pid, pid_file })
    }

    fn drive_capped(
        child: Child,
        stdin: Option<Vec<u8>>,
        timeout: Duration,
        max_output_bytes: usize,
    ) -> Result<ChildOutput> {
        drive_child_capped_controlled(
            child,
            stdin,
            timeout,
            max_output_bytes,
            &ExecControl::default(),
        )
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
        let child = sh("dd if=/dev/zero bs=1024 count=1024 2>/dev/null; \
             dd if=/dev/zero bs=1024 count=1024 1>&2 2>/dev/null")
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
        let out = drive_capped(child, None, Duration::from_secs(30), cap).expect("drive");
        assert!(out.output_truncated, "cap breach must be signalled");
        assert!(!out.success(), "an output-capped run is not a success");
        assert!(!out.timed_out, "the cap kill, not the timeout, fired");
        assert_eq!(
            out.stdout.len(),
            cap,
            "capture itself stays strictly bounded"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the process must be KILLED at the cap, not left to run to the timeout"
        );
    }

    #[test]
    fn output_cap_on_stderr_also_kills() {
        let cap = 256 * 1024;
        let child = sh("yes BBBBBBBB 1>&2").spawn().expect("spawn");
        let out = drive_capped(child, None, Duration::from_secs(30), cap).expect("drive");
        assert!(out.output_truncated);
        assert!(out.stderr.len() >= cap);
    }

    #[test]
    fn output_under_the_cap_is_a_clean_success() {
        // A command whose output is comfortably under the ceiling completes
        // normally, with no truncation flag.
        let child = sh("printf 'small output\\n'").spawn().expect("spawn");
        let out = drive_capped(child, None, Duration::from_secs(10), 1024 * 1024).expect("drive");
        assert!(!out.output_truncated);
        assert!(out.success());
        assert_eq!(out.stdout, b"small output\n");
    }

    #[test]
    fn output_exactly_at_the_cap_is_not_truncated() {
        let cap = 32 * 1024;
        let child = sh("dd if=/dev/zero bs=32768 count=1 2>/dev/null")
            .spawn()
            .expect("spawn");
        let out = drive_capped(child, None, Duration::from_secs(10), cap).expect("drive");
        assert!(!out.output_truncated);
        assert!(out.success());
        assert_eq!(out.stdout.len(), cap);
    }

    #[derive(Default)]
    struct CollectSink {
        stdout: Mutex<Vec<u8>>,
        stderr: Mutex<Vec<u8>>,
    }

    impl super::super::ExecOutputSink for CollectSink {
        fn on_output(&self, stream: ExecStream, chunk: &[u8]) {
            let target = match stream {
                ExecStream::Stdout => &self.stdout,
                ExecStream::Stderr => &self.stderr,
            };
            target.lock().unwrap().extend_from_slice(chunk);
        }
    }

    #[test]
    fn emits_stdout_and_stderr_while_draining() {
        let sink = Arc::new(CollectSink::default());
        let control = ExecControl::with_output_sink(sink.clone());
        let child = sh("printf hello; printf warning >&2")
            .spawn()
            .expect("spawn");
        let out =
            drive_child_controlled(child, None, Duration::from_secs(10), &control).expect("drive");
        assert!(out.success());
        assert_eq!(*sink.stdout.lock().unwrap(), b"hello");
        assert_eq!(*sink.stderr.lock().unwrap(), b"warning");
        assert!(out.stdout.is_empty(), "streamed output is not duplicated");
        assert!(out.stderr.is_empty(), "streamed output is not duplicated");
    }

    #[test]
    fn streamed_output_keeps_draining_past_the_capture_cap() {
        let sink = Arc::new(CollectSink::default());
        let control = ExecControl::with_output_sink(sink.clone());
        let child = sh("dd if=/dev/zero bs=1024 count=256 2>/dev/null")
            .spawn()
            .expect("spawn");
        let out = drive_child_capped_controlled(
            child,
            None,
            Duration::from_secs(10),
            64 * 1024,
            &control,
        )
        .expect("drive");
        assert!(out.success());
        assert!(!out.output_truncated);
        assert_eq!(sink.stdout.lock().unwrap().len(), 256 * 1024);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn cancellation_promptly_kills_and_reaps_the_child() {
        let control = ExecControl::default();
        let canceller = control.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            canceller.cancel();
        });
        let child = sh("printf ready; exec sleep 30").spawn().expect("spawn");
        let start = Instant::now();
        let out =
            drive_child_controlled(child, None, Duration::from_secs(30), &control).expect("drive");
        assert!(out.cancelled);
        assert!(!out.cancelled_process_group);
        assert!(!out.success());
        assert_eq!(out.stdout, b"ready");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "cancel must not wait for the command timeout"
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_group_cancellation_reports_job_scoped_evidence() {
        use std::os::unix::process::CommandExt;

        let control = ExecControl::default();
        let canceller = control.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            canceller.cancel();
        });
        let mut command = sh("trap 'exit 0' TERM; while :; do sleep 1; done");
        command.process_group(0);
        let child = command.spawn().expect("spawn");
        let out = drive_child_capped_controlled_process_group(
            child,
            None,
            Duration::from_secs(30),
            1024 * 1024,
            &control,
        )
        .expect("drive");
        assert!(out.cancelled);
        assert!(out.cancelled_process_group);
        assert!(!out.success());
    }

    #[cfg(unix)]
    #[test]
    fn process_group_output_cap_keeps_the_cleanup_boundary_alive() {
        use std::os::unix::process::CommandExt;

        let cap = 32 * 1024;
        let mut command = sh("dd if=/dev/zero bs=1024 count=512 2>/dev/null");
        command.process_group(0);
        let child = command.spawn().expect("spawn");
        let out = drive_child_capped_controlled_process_group(
            child,
            None,
            Duration::from_secs(10),
            cap,
            &ExecControl::default(),
        )
        .expect("an ordinary output cap must not revoke execution authority");
        assert!(out.output_truncated);
        assert_eq!(out.stdout.len(), cap);
        assert_eq!(out.exit_code, Some(0));
        assert!(!out.timed_out);
    }

    #[cfg(unix)]
    #[test]
    fn forced_group_kill_fails_without_waiting_on_the_reaper() {
        use std::os::unix::process::CommandExt;

        let control = ExecControl::default();
        let canceller = control.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            canceller.cancel();
        });
        let mut command = sh("trap '' TERM; while :; do sleep 1; done");
        command.process_group(0);
        let child = command.spawn().expect("spawn");
        let start = Instant::now();
        let error = drive_child_capped_inner(
            child,
            None,
            Duration::from_secs(30),
            1024 * 1024,
            &control,
            CancelTarget::ProcessGroup,
            Duration::from_millis(100),
        )
        .expect_err("forced reaper kill must revoke execution authority");
        assert!(error.to_string().contains("descendant reaper"), "{error:#}");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn process_group_hard_kills_fail_without_joining_escaped_pipe_holders() {
        // Timeout path: the helper has called setsid(), so killing the driven
        // shell's process group cannot close the stdout/stderr descriptors it
        // inherited. The driver must return a fatal error rather than joining
        // those drains first.
        let (child, mut holder) = spawn_escaped_pipe_holder("sleep");
        let start = Instant::now();
        let error = drive_child_capped_controlled_process_group(
            child,
            None,
            Duration::from_millis(100),
            1024 * 1024,
            &ExecControl::default(),
        )
        .expect_err("timed-out process group must lose execution authority");
        assert!(crate::sandbox::is_sandbox_control_lost(&error));
        assert!(error.to_string().contains("watchdog"), "{error:#}");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timeout path joined a pipe held by an escaped descendant"
        );
        holder.terminate_and_wait_for_reap();
    }
}

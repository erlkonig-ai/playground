use std::collections::HashSet;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, sleep};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use triblespace::core::blob::Bytes;
use triblespace::core::blob::schemas::UnknownBlob;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Workspace;
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

use crate::config::Config;
use crate::repo_util::{
    close_repo, current_branch_head, ensure_worker_name, init_repo, load_text, pull_workspace,
    push_workspace, refresh_cached_checkout,
};
use crate::schema::playground_exec;
use crate::time_util::{epoch_interval, interval_key, now_epoch};

const DEFAULT_EXEC_TIMEOUT_MS: u64 = 300_000;
const EXEC_CONTROL_POLL_MS: u64 = 100;

#[derive(Debug, Clone)]
struct CommandRequest {
    id: Id,
    command: Value<Handle<Blake3, LongString>>,
    cwd: Option<Value<Handle<Blake3, LongString>>>,
    stdin: Option<Value<Handle<Blake3, UnknownBlob>>>,
    stdin_text: Option<Value<Handle<Blake3, LongString>>>,
    timeout_ms: Option<Value<U256BE>>,
}

#[derive(Debug)]
pub(crate) struct ExecOutput {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout_text: Option<String>,
    pub(crate) stderr_text: Option<String>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExecCommandEnv {
    pub(crate) pile: String,
    pub(crate) worker_id: String,
    pub(crate) turn_id: String,
    /// Additional env vars (e.g. FORK_LENS_ID, FORK_EVENT_TIME).
    pub(crate) extra: Vec<(String, String)>,
}

pub(crate) fn run_exec_loop(
    config: Config,
    worker_id: Id,
    poll_ms: u64,
    stop: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let default_cwd = config
        .exec
        .default_cwd
        .as_ref()
        .map(|path| path.to_string_lossy().to_string());

    let (mut repo, branch_id) = init_repo(&config).context("open triblespace repo")?;
    let result = (|| -> Result<()> {
        let label = format!("exec-{}", id_prefix(worker_id));
        ensure_worker_name(&mut repo, branch_id, worker_id, &label)?;
        let mut cached_head = None;
        let mut cached_catalog = TribleSet::new();

        loop {
            if stop_requested(&stop) {
                break;
            }

            let branch_head = current_branch_head(&mut repo, branch_id)?;
            if branch_head == cached_head {
                sleep(Duration::from_millis(poll_ms));
                continue;
            }

            let mut ws = pull_workspace(&mut repo, branch_id, "pull workspace")?;
            refresh_cached_checkout(&mut ws, &mut cached_head, &mut cached_catalog)?;
            let Some(request) = next_pending_request(&cached_catalog, worker_id) else {
                sleep(Duration::from_millis(poll_ms));
                continue;
            };

            if stop_requested(&stop) {
                break;
            }

            let command = load_text(&mut ws, request.command).context("load command")?;
            let cwd = match request.cwd {
                Some(handle) => Some(load_text(&mut ws, handle).context("load cwd")?),
                None => default_cwd.clone(),
            };
            let stdin = load_stdin(&mut ws, &request).context("load stdin")?;
            let attempt: u64 = 1;
            let env = ExecCommandEnv {
                pile: config.pile_path.to_string_lossy().to_string(),
                worker_id: format!("{worker_id:x}"),
                turn_id: format!("{request_id:x}", request_id = request.id),
                extra: Vec::new(),
            };

            let started_e = now_epoch();
            let started_at = epoch_interval(started_e);
            let in_progress_id = ufoid();
            let mut change = TribleSet::new();
            change += entity! { &in_progress_id @
                metadata::tag: playground_exec::kind_in_progress,
                playground_exec::about_request: request.id,
                playground_exec::worker: worker_id,
                metadata::started_at: started_at,
                playground_exec::attempt: attempt,
            };
            ws.commit(change, "playground_exec in_progress");
            push_workspace(&mut repo, &mut ws).context("push in_progress")?;

            let initial_timeout_ms = request
                .timeout_ms
                .and_then(|v| v.try_from_value::<u64>().ok())
                .unwrap_or(DEFAULT_EXEC_TIMEOUT_MS);
            let initial_timeout = Duration::from_millis(initial_timeout_ms);
            let started = Instant::now();
            let output = execute_command(
                &command,
                cwd.as_deref(),
                stdin,
                &env,
                initial_timeout,
                &stop,
                || {
                    if stop_requested(&stop) {
                        return Ok(None);
                    }

                    let branch_head = current_branch_head(&mut repo, branch_id)?;
                    if branch_head == cached_head {
                        return Ok(None);
                    }

                    let mut ws =
                        pull_workspace(&mut repo, branch_id, "pull workspace for control")?;
                    let delta =
                        refresh_cached_checkout(&mut ws, &mut cached_head, &mut cached_catalog)?;
                    Ok(collect_timeout_extension_ms(
                        &cached_catalog,
                        &delta,
                        request.id,
                        worker_id,
                    ))
                },
            );
            let ExecOutput {
                stdout,
                stderr,
                exit_code,
                stdout_text,
                stderr_text,
                error,
            } = output;
            let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            let finished_e = now_epoch();
            let finished_at = epoch_interval(finished_e);

            let result_id = ufoid();
            let mut change = TribleSet::new();
            change += entity! { &result_id @
                metadata::tag: playground_exec::kind_command_result,
                playground_exec::about_request: request.id,
                metadata::finished_at: finished_at,
                playground_exec::attempt: attempt,
                playground_exec::duration_ms: duration_ms,
            };
            let stdout_handle = ws.put::<UnknownBlob, _>(Bytes::from_source(stdout));
            let stderr_handle = ws.put::<UnknownBlob, _>(Bytes::from_source(stderr));
            change += entity! { &result_id @
                playground_exec::stdout: stdout_handle,
                playground_exec::stderr: stderr_handle,
            };

            if let Some(exit_code) = exit_code.and_then(|code| u64::try_from(code).ok()) {
                change += entity! { &result_id @ playground_exec::exit_code: exit_code };
            }

            if let Some(stdout_text) = stdout_text {
                let handle = ws.put(stdout_text);
                change += entity! { &result_id @ playground_exec::stdout_text: handle };
            }

            if let Some(stderr_text) = stderr_text {
                let handle = ws.put(stderr_text);
                change += entity! { &result_id @ playground_exec::stderr_text: handle };
            }

            if let Some(error) = error {
                let handle = ws.put(error);
                change += entity! { &result_id @ playground_exec::error: handle };
            }

            ws.commit(change, "playground_exec result");
            push_workspace(&mut repo, &mut ws).context("push result")?;
        }

        Ok(())
    })();

    if let Err(err) = close_repo(repo) {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

fn stop_requested(stop: &Option<Arc<AtomicBool>>) -> bool {
    stop.as_ref()
        .map(|flag| flag.load(Ordering::Relaxed))
        .unwrap_or(false)
}

pub(crate) fn execute_command(
    command: &str,
    cwd: Option<&str>,
    stdin: Option<Bytes>,
    env: &ExecCommandEnv,
    initial_timeout: Duration,
    stop: &Option<Arc<AtomicBool>>,
    mut poll_timeout_extension: impl FnMut() -> Result<Option<u64>>,
) -> ExecOutput {
    let mut cmd = Command::new("sh");
    cmd.arg("-lc").arg(command);
    // Make faculties available as plain commands (e.g. `orient`, `memory`) without requiring
    // hard-coded absolute paths.
    let base_path = std::env::var("PATH").unwrap_or_default();
    let extra_path = "/workspace/faculties:/opt/playground/faculties";
    let merged_path = if base_path.trim().is_empty() {
        extra_path.to_string()
    } else {
        format!("{extra_path}:{base_path}")
    };
    cmd.env("PATH", merged_path);
    cmd.env("PILE", &env.pile);
    cmd.env("WORKER_ID", &env.worker_id);
    cmd.env("TURN_ID", &env.turn_id);
    for (key, value) in &env.extra {
        cmd.env(key, value);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(unix)]
    // Spawn each command in its own process group so timeout cancellation can terminate
    // the whole subtree, not only the top-level shell process.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            return ExecOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: None,
                stdout_text: None,
                stderr_text: None,
                error: Some(format!("spawn failed: {err}")),
            };
        }
    };

    let mut stdout_reader = child.stdout.take().map(spawn_output_reader);
    let mut stderr_reader = child.stderr.take().map(spawn_output_reader);

    if let Some(stdin) = stdin {
        if let Some(mut handle) = child.stdin.take() {
            let _ = handle.write_all(stdin.as_ref());
        }
    }

    let mut deadline = Instant::now() + initial_timeout;
    let wait_started = Instant::now();
    let mut timed_out = false;
    let mut timed_out_after: Option<Duration> = None;
    let mut killed_for_stop = false;
    let mut wait_error: Option<String> = None;
    let mut status_code: Option<i32> = None;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                status_code = status.code();
                break;
            }
            Ok(None) => {}
            Err(err) => {
                wait_error = Some(format!("wait failed: {err}"));
                let _ = terminate_process_tree(&mut child);
                break;
            }
        }

        match poll_timeout_extension() {
            Ok(Some(extension_ms)) => {
                let extension = Duration::from_millis(extension_ms);
                deadline = deadline.max(Instant::now() + extension);
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("warning: timeout extension poll failed: {err:#}");
            }
        }

        if stop_requested(stop) {
            killed_for_stop = true;
            let _ = terminate_process_tree(&mut child);
            let _ = child.wait();
            status_code = Some(130);
            break;
        }

        if Instant::now() >= deadline {
            timed_out = true;
            timed_out_after = Some(wait_started.elapsed());
            let _ = terminate_process_tree(&mut child);
            let _ = child.wait();
            status_code = Some(124);
            break;
        }

        sleep(Duration::from_millis(EXEC_CONTROL_POLL_MS));
    }

    let stdout = stdout_reader
        .take()
        .map(join_output_reader)
        .unwrap_or_default();
    let mut stderr = stderr_reader
        .take()
        .map(join_output_reader)
        .unwrap_or_default();

    if timed_out {
        let timeout_hint =
            format_timeout_hint(timed_out_after.unwrap_or_else(|| wait_started.elapsed()));
        let mut msg = format!("{timeout_hint}\n").into_bytes();
        msg.extend_from_slice(&stderr);
        stderr = msg;
    } else if killed_for_stop {
        let mut msg = b"command interrupted: worker stop requested\n".to_vec();
        msg.extend_from_slice(&stderr);
        stderr = msg;
    }

    let stdout_text = std::str::from_utf8(&stdout).ok().map(str::to_string);
    let stderr_text = std::str::from_utf8(&stderr).ok().map(str::to_string);

    let error = if timed_out {
        Some(format_timeout_hint(
            timed_out_after.unwrap_or_else(|| wait_started.elapsed()),
        ))
    } else if killed_for_stop {
        Some("command interrupted: worker stop requested".to_string())
    } else {
        wait_error
    };

    ExecOutput {
        stdout,
        stderr,
        exit_code: status_code,
        stdout_text,
        stderr_text,
        error,
    }
}

fn spawn_output_reader<R>(mut reader: R) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = reader.read_to_end(&mut bytes);
        bytes
    })
}

fn join_output_reader(handle: thread::JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

fn terminate_process_tree(child: &mut std::process::Child) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // Negative pid targets the entire process group created in pre_exec.
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
        sleep(Duration::from_millis(50));
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        Ok(())
    }

    #[cfg(not(unix))]
    {
        child.kill()
    }
}

fn format_timeout_hint(duration: Duration) -> String {
    format!(
        "command timed out after {:.1}s; for long-running work, retry with `patience <duration> -- <command>`",
        duration.as_secs_f64()
    )
}

fn next_pending_request(catalog: &TribleSet, worker_id: Id) -> Option<CommandRequest> {
    let done: HashSet<Id> = find!(
        (request_id: Id),
        pattern!(catalog, [{
            _?event @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: ?request_id,
        }])
    )
    .map(|(id,)| id)
    .collect();

    let in_progress: HashSet<Id> = find!(
        (request_id: Id),
        pattern!(catalog, [{
            _?event @
            metadata::tag: playground_exec::kind_in_progress,
            playground_exec::about_request: ?request_id,
            playground_exec::worker: &worker_id,
        }])
    )
    .map(|(id,)| id)
    .collect();

    let mut candidates: Vec<_> = find!(
        (request_id: Id, command: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{
            ?request_id @
            metadata::tag: playground_exec::kind_command_request,
            playground_exec::command_text: ?command,
        }])
    )
    .filter(|(id, _)| !done.contains(id) && !in_progress.contains(id))
    .collect();

    candidates.sort_by_key(|(id, _)| {
        find!(
            (ts: Value<NsTAIInterval>),
            pattern!(catalog, [{ *id @ metadata::created_at: ?ts }])
        )
        .next()
        .map(|(ts,)| interval_key(ts))
        .unwrap_or(i128::MIN)
    });

    let (id, command) = candidates.into_iter().next()?;

    let cwd = find!(
        (v: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{ id @ playground_exec::cwd: ?v }])
    )
    .next()
    .map(|(v,)| v);

    let stdin = find!(
        (v: Value<Handle<Blake3, UnknownBlob>>),
        pattern!(catalog, [{ id @ playground_exec::stdin: ?v }])
    )
    .next()
    .map(|(v,)| v);

    let stdin_text = find!(
        (v: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{ id @ playground_exec::stdin_text: ?v }])
    )
    .next()
    .map(|(v,)| v);

    let timeout_ms = find!(
        (v: Value<U256BE>),
        pattern!(catalog, [{ id @ playground_exec::timeout_ms: ?v }])
    )
    .next()
    .map(|(v,)| v);

    Some(CommandRequest {
        id,
        command,
        cwd,
        stdin,
        stdin_text,
        timeout_ms,
    })
}

fn collect_timeout_extension_ms(
    updated: &TribleSet,
    delta: &TribleSet,
    request_id: Id,
    worker_id: Id,
) -> Option<u64> {
    let mut extension_ms: Option<u64> = None;
    for (_event_id, timeout_ms) in find!(
        (_event_id: Id, timeout_ms: Value<U256BE>),
        pattern_changes!(updated, delta, [{
            ?_event_id @
            metadata::tag: playground_exec::kind_timeout_extension,
            playground_exec::about_request: request_id,
            playground_exec::worker: worker_id,
            playground_exec::timeout_ms: ?timeout_ms,
        }])
    ) {
        let Some(timeout_ms) = timeout_ms.try_from_value::<u64>().ok() else {
            continue;
        };
        if timeout_ms == 0 {
            continue;
        }
        extension_ms = Some(extension_ms.map_or(timeout_ms, |current| current.max(timeout_ms)));
    }
    extension_ms
}


fn load_stdin(ws: &mut Workspace<Pile>, request: &CommandRequest) -> Result<Option<Bytes>> {
    if let Some(stdin) = request.stdin {
        let bytes: Bytes = ws.get(stdin).context("read stdin bytes")?;
        return Ok(Some(bytes));
    }

    if let Some(stdin_text) = request.stdin_text {
        let text = load_text(ws, stdin_text)?;
        return Ok(Some(Bytes::from_source(text.into_bytes())));
    }

    Ok(None)
}

fn id_prefix(id: Id) -> String {
    let raw: [u8; 16] = id.into();
    let mut out = String::with_capacity(8);
    for byte in raw.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

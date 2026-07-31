//! Bounded background execution for the MCP sandbox tools.
//!
//! There is deliberately one execution state machine. `job_exec` retains its
//! handle for polling; synchronous `exec` starts the same kind of job, waits
//! for its terminal state, then forgets it. The manager is in-memory because a
//! daemon restart already loses the process handles required for cancellation;
//! persistence and audit receipts are separate concerns.

use std::collections::{HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use rand::RngCore;

#[cfg(test)]
use crate::sandbox::ExecShellMode;
use crate::sandbox::{
    ExecControl, ExecOutputSink, ExecRequest, ExecResult, ExecStream, SandboxBackend, SessionId,
    is_sandbox_control_lost, sandbox_control_lost,
};

/// One foreground command per tenant keeps mutation ordering legible and stops
/// one public user from occupying every daemon worker. FreeBSD `timeout(1)` is
/// the command's kernel descendant reaper, so the lane remains occupied until
/// its entire command tree has exited.
pub const MAX_ACTIVE_JOBS_PER_TENANT: usize = 1;
/// The daemon-wide process/memory bound. This is policy, not a user-facing
/// scheduler knob.
pub const MAX_ACTIVE_JOBS_GLOBAL: usize = 32;
/// Completed handles remain replayable, but never grow the daemon forever.
/// Together with the 4 MiB per-job ring this caps retained output at 256 MiB.
pub const MAX_RETAINED_JOBS_GLOBAL: usize = 64;
pub const MAX_RETAINED_JOBS_PER_TENANT: usize = 8;
pub const TERMINAL_JOB_TTL: Duration = Duration::from_secs(60 * 60);
/// Retained incremental output per job (stdout and stderr combined).
pub const MAX_RETAINED_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
/// Payload bytes alone are not a memory bound when a producer drip-feeds tiny
/// writes: cap allocation/metadata count as well. Adjacent same-stream writes
/// are normalized into poll-sized chunks first; stream changes, polls, and
/// full chunks still create real metadata boundaries governed by this cap.
pub const MAX_RETAINED_CHUNKS_PER_JOB: usize = 1024;
/// One poll stays comfortably below HTTP and model-context ceilings.
pub const MAX_POLL_OUTPUT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Running,
    Cancelling,
    Terminal,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Running => "running",
            JobState::Cancelling => "cancelling",
            JobState::Terminal => "terminal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobTerminal {
    Exited {
        exit_code: Option<i32>,
        error: Option<String>,
    },
    Cancelled {
        error: Option<String>,
    },
    Failed {
        error: String,
    },
}

impl JobTerminal {
    pub fn kind(&self) -> &'static str {
        match self {
            JobTerminal::Exited { .. } => "exited",
            JobTerminal::Cancelled { .. } => "cancelled",
            JobTerminal::Failed { .. } => "failed",
        }
    }

    pub fn exit_code(&self) -> Option<i32> {
        match self {
            JobTerminal::Exited { exit_code, .. } => *exit_code,
            JobTerminal::Cancelled { .. } | JobTerminal::Failed { .. } => None,
        }
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            JobTerminal::Exited { error, .. } | JobTerminal::Cancelled { error } => {
                error.as_deref()
            }
            JobTerminal::Failed { error } => Some(error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolledChunk {
    pub sequence: u64,
    pub stream: ExecStream,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct JobSnapshot {
    pub id: String,
    pub state: JobState,
    pub chunks: Vec<PolledChunk>,
    pub next_cursor: u64,
    pub has_more: bool,
    pub gap: bool,
    pub dropped_bytes: u64,
    pub terminal: Option<JobTerminal>,
}

#[derive(Debug)]
struct StoredChunk {
    sequence: u64,
    stream: ExecStream,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct OutputLog {
    chunks: VecDeque<StoredChunk>,
    next_sequence: u64,
    retained_bytes: usize,
    dropped_bytes: u64,
    /// Once a poll has exposed the current tail's sequence, that chunk is
    /// immutable: appending to it would hide new bytes from a client that
    /// already advanced past the sequence.
    tail_sealed: bool,
}

impl OutputLog {
    fn enforce_bounds(&mut self) {
        while self.retained_bytes > MAX_RETAINED_OUTPUT_BYTES
            || self.chunks.len() > MAX_RETAINED_CHUNKS_PER_JOB
        {
            let Some(oldest) = self.chunks.pop_front() else {
                break;
            };
            self.retained_bytes = self.retained_bytes.saturating_sub(oldest.bytes.len());
            self.dropped_bytes = self.dropped_bytes.saturating_add(oldest.bytes.len() as u64);
        }
    }

    fn push(&mut self, stream: ExecStream, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let append_to_tail = !self.tail_sealed
                && self.chunks.back().is_some_and(|tail| {
                    tail.stream == stream && tail.bytes.len() < MAX_POLL_OUTPUT_BYTES
                });

            if append_to_tail {
                let tail = self.chunks.back_mut().expect("tail checked above");
                let take = bytes
                    .len()
                    .min(MAX_POLL_OUTPUT_BYTES.saturating_sub(tail.bytes.len()));
                tail.bytes.extend_from_slice(&bytes[..take]);
                self.retained_bytes = self.retained_bytes.saturating_add(take);
                bytes = &bytes[take..];
            } else {
                let take = bytes.len().min(MAX_POLL_OUTPUT_BYTES);
                self.chunks.push_back(StoredChunk {
                    sequence: self.next_sequence,
                    stream,
                    bytes: bytes[..take].to_vec(),
                });
                self.next_sequence = self.next_sequence.saturating_add(1);
                self.retained_bytes = self.retained_bytes.saturating_add(take);
                self.tail_sealed = false;
                bytes = &bytes[take..];
            }

            self.enforce_bounds();
        }
    }

    fn first_sequence(&self) -> u64 {
        self.chunks
            .front()
            .map(|chunk| chunk.sequence)
            .unwrap_or(self.next_sequence)
    }

    fn poll(&mut self, cursor: u64) -> (Vec<PolledChunk>, u64, bool, bool) {
        // Cursor acknowledgement is sequence-based. Freeze the only chunk that
        // could otherwise grow before exposing any sequence to this poll; the
        // next producer push will allocate a fresh sequence.
        self.tail_sealed = true;
        let first = self.first_sequence();
        let gap = cursor < first;
        // A malformed/future cursor must not suppress output that has not even
        // been produced yet. Clamp it to the current tail and return that tail
        // as the retry point.
        let effective = cursor.max(first).min(self.next_sequence);
        let mut page_bytes = 0usize;
        let mut next_cursor = effective;
        let mut chunks = Vec::new();

        for chunk in self
            .chunks
            .iter()
            .filter(|chunk| chunk.sequence >= effective)
        {
            if !chunks.is_empty()
                && page_bytes.saturating_add(chunk.bytes.len()) > MAX_POLL_OUTPUT_BYTES
            {
                break;
            }
            page_bytes = page_bytes.saturating_add(chunk.bytes.len());
            next_cursor = chunk.sequence.saturating_add(1);
            chunks.push(PolledChunk {
                sequence: chunk.sequence,
                stream: chunk.stream,
                text: String::from_utf8_lossy(&chunk.bytes).into_owned(),
            });
            if page_bytes >= MAX_POLL_OUTPUT_BYTES {
                break;
            }
        }
        let has_more = next_cursor < self.next_sequence;
        (chunks, next_cursor, gap, has_more)
    }

    fn render_all(&self) -> (Vec<u8>, Vec<u8>, bool) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for chunk in &self.chunks {
            match chunk.stream {
                ExecStream::Stdout => stdout.extend_from_slice(&chunk.bytes),
                ExecStream::Stderr => stderr.extend_from_slice(&chunk.bytes),
            }
        }
        (stdout, stderr, self.dropped_bytes > 0)
    }
}

struct JobOutputSink {
    output: Arc<Mutex<OutputLog>>,
}

impl ExecOutputSink for JobOutputSink {
    fn on_output(&self, stream: ExecStream, chunk: &[u8]) {
        self.output
            .lock()
            .expect("job output poisoned")
            .push(stream, chunk);
    }
}

#[derive(Debug)]
enum InnerState {
    Running,
    Cancelling,
    Terminal { result: JobTerminal, at: Instant },
}

struct Job {
    id: String,
    tenant: String,
    control: ExecControl,
    output: Arc<Mutex<OutputLog>>,
    state: Mutex<InnerState>,
    changed: Condvar,
}

impl Job {
    fn state(&self) -> JobState {
        match &*self.state.lock().expect("job state poisoned") {
            InnerState::Running => JobState::Running,
            InnerState::Cancelling => JobState::Cancelling,
            InnerState::Terminal { .. } => JobState::Terminal,
        }
    }

    fn terminal_at(&self) -> Option<Instant> {
        match &*self.state.lock().expect("job state poisoned") {
            InnerState::Terminal { at, .. } => Some(*at),
            InnerState::Running | InnerState::Cancelling => None,
        }
    }

    fn request_cancel(&self) -> JobState {
        let mut state = self.state.lock().expect("job state poisoned");
        match &*state {
            InnerState::Running => {
                *state = InnerState::Cancelling;
                self.control.cancel();
                self.changed.notify_all();
                JobState::Cancelling
            }
            InnerState::Cancelling => JobState::Cancelling,
            InnerState::Terminal { .. } => JobState::Terminal,
        }
    }

    fn publish_terminal(&self, backend_result: Result<ExecResult>) {
        let mut state = self.state.lock().expect("job state poisoned");
        let result = match backend_result {
            Ok(result) if result.cancelled => JobTerminal::Cancelled {
                error: result.error,
            },
            Ok(result) => JobTerminal::Exited {
                exit_code: result.exit_code,
                error: result.error,
            },
            Err(error) => JobTerminal::Failed {
                error: format!("{error:#}"),
            },
        };
        *state = InnerState::Terminal {
            result,
            at: Instant::now(),
        };
        self.changed.notify_all();
    }

    fn snapshot(&self, cursor: u64) -> JobSnapshot {
        let (state, terminal) = match &*self.state.lock().expect("job state poisoned") {
            InnerState::Running => (JobState::Running, None),
            InnerState::Cancelling => (JobState::Cancelling, None),
            InnerState::Terminal { result, .. } => (JobState::Terminal, Some(result.clone())),
        };
        let mut output = self.output.lock().expect("job output poisoned");
        let (chunks, next_cursor, gap, has_more) = output.poll(cursor);
        JobSnapshot {
            id: self.id.clone(),
            state,
            chunks,
            next_cursor,
            has_more,
            gap,
            dropped_bytes: output.dropped_bytes,
            terminal,
        }
    }

    fn wait_terminal(&self) -> JobTerminal {
        let mut state = self.state.lock().expect("job state poisoned");
        loop {
            if let InnerState::Terminal { result, .. } = &*state {
                return result.clone();
            }
            state = self.changed.wait(state).expect("job state poisoned");
        }
    }

    fn as_exec_result(&self, terminal: JobTerminal) -> ExecResult {
        let (stdout, stderr, output_gap) = self
            .output
            .lock()
            .expect("job output poisoned")
            .render_all();
        let mut result = match terminal {
            JobTerminal::Exited { exit_code, error } => ExecResult {
                stdout,
                stderr,
                exit_code,
                cancelled: false,
                error,
            },
            JobTerminal::Cancelled { error } => ExecResult {
                stdout,
                stderr,
                exit_code: None,
                cancelled: true,
                error: error.or_else(|| Some("command cancelled".to_string())),
            },
            JobTerminal::Failed { error } => ExecResult {
                stdout,
                stderr,
                exit_code: None,
                cancelled: false,
                error: Some(error),
            },
        };
        if output_gap {
            let suffix = "earliest output was evicted from the bounded job log";
            result.error = Some(match result.error {
                Some(error) => format!("{error}; {suffix}"),
                None => suffix.to_string(),
            });
        }
        result
    }
}

struct ManagerState {
    jobs: HashMap<String, Arc<Job>>,
    active_global: usize,
    active_per_tenant: HashMap<String, usize>,
    accepting: bool,
    /// First fatal loss of execution authority. Unlike ordinary backend
    /// errors, this closes admission globally and asks the owning transport to
    /// terminate; there is no recoverable per-tenant state transition.
    fatal_reason: Option<String>,
}

impl Default for ManagerState {
    fn default() -> Self {
        Self {
            jobs: HashMap::new(),
            active_global: 0,
            active_per_tenant: HashMap::new(),
            accepting: true,
            fatal_reason: None,
        }
    }
}

type FatalHandler = Arc<dyn Fn(String) + Send + Sync>;

pub struct JobManager {
    backend: Arc<dyn SandboxBackend>,
    state: Mutex<ManagerState>,
    fatal_handler: Mutex<Option<FatalHandler>>,
}

impl JobManager {
    pub fn new(backend: Arc<dyn SandboxBackend>) -> Arc<Self> {
        Arc::new(Self {
            backend,
            state: Mutex::new(ManagerState::default()),
            fatal_handler: Mutex::new(None),
        })
    }

    /// Install the transport boundary's fail-stop hook. The core stays
    /// synchronous/std-only; HTTP adapts this callback into an async shutdown
    /// notification, while stdio may exit directly. Installing after a fatal
    /// event immediately replays the retained first reason.
    pub fn set_fatal_handler(&self, handler: Arc<dyn Fn(String) + Send + Sync>) {
        *self.fatal_handler.lock().expect("fatal handler poisoned") = Some(handler.clone());
        if let Some(reason) = self.fatal_reason() {
            handler(reason);
        }
    }

    pub fn fatal_reason(&self) -> Option<String> {
        self.state
            .lock()
            .expect("job manager poisoned")
            .fatal_reason
            .clone()
    }

    fn random_id() -> String {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn sweep_locked(state: &mut ManagerState, now: Instant) {
        state.jobs.retain(|_, job| {
            job.terminal_at()
                .map(|at| now.saturating_duration_since(at) < TERMINAL_JOB_TTL)
                .unwrap_or(true)
        });
    }

    fn evict_oldest_terminal(state: &mut ManagerState, tenant: Option<&str>) -> bool {
        let oldest = state
            .jobs
            .iter()
            .filter(|(_, job)| tenant.map(|want| want == job.tenant).unwrap_or(true))
            .filter_map(|(id, job)| job.terminal_at().map(|at| (id.clone(), at)))
            .min_by_key(|(_, at)| *at)
            .map(|(id, _)| id);
        oldest.and_then(|id| state.jobs.remove(&id)).is_some()
    }

    fn make_retention_room(state: &mut ManagerState, tenant: &str) -> Result<()> {
        Self::sweep_locked(state, Instant::now());
        while state
            .jobs
            .values()
            .filter(|job| job.tenant == tenant)
            .count()
            >= MAX_RETAINED_JOBS_PER_TENANT
        {
            if !Self::evict_oldest_terminal(state, Some(tenant)) {
                return Err(anyhow!(
                    "tenant '{tenant}' already has {MAX_RETAINED_JOBS_PER_TENANT} live/retained jobs"
                ));
            }
        }
        while state.jobs.len() >= MAX_RETAINED_JOBS_GLOBAL {
            if !Self::evict_oldest_terminal(state, None) {
                return Err(anyhow!(
                    "job table is full ({MAX_RETAINED_JOBS_GLOBAL} live jobs)"
                ));
            }
        }
        Ok(())
    }

    pub fn start(
        self: &Arc<Self>,
        tenant: String,
        session: SessionId,
        request: ExecRequest,
    ) -> Result<String> {
        let output = Arc::new(Mutex::new(OutputLog::default()));
        let sink: Arc<dyn ExecOutputSink> = Arc::new(JobOutputSink {
            output: output.clone(),
        });
        let control = ExecControl::with_output_sink(sink);

        let (id, job) = {
            let mut state = self.state.lock().expect("job manager poisoned");
            if !state.accepting {
                return Err(match &state.fatal_reason {
                    Some(reason) => {
                        anyhow!("sandbox provider stopped after losing execution control: {reason}")
                    }
                    None => anyhow!("sandbox provider is shutting down"),
                });
            }
            Self::make_retention_room(&mut state, &tenant)?;
            let tenant_active = state.active_per_tenant.get(&tenant).copied().unwrap_or(0);
            if tenant_active >= MAX_ACTIVE_JOBS_PER_TENANT {
                return Err(anyhow!(
                    "sandbox busy: tenant '{tenant}' already has an active command"
                ));
            }
            if state.active_global >= MAX_ACTIVE_JOBS_GLOBAL {
                return Err(anyhow!(
                    "sandbox busy: {}/{} commands active globally",
                    state.active_global,
                    MAX_ACTIVE_JOBS_GLOBAL
                ));
            }
            let id = loop {
                let candidate = Self::random_id();
                if !state.jobs.contains_key(&candidate) {
                    break candidate;
                }
            };
            let job = Arc::new(Job {
                id: id.clone(),
                tenant: tenant.clone(),
                control,
                output,
                state: Mutex::new(InnerState::Running),
                changed: Condvar::new(),
            });
            state.active_global += 1;
            *state.active_per_tenant.entry(tenant.clone()).or_insert(0) += 1;
            state.jobs.insert(id.clone(), job.clone());
            (id, job)
        };

        let manager = self.clone();
        let worker_job = job.clone();
        let worker_tenant = tenant.clone();
        let spawn = std::thread::Builder::new()
            .name(format!("playground-job-{}", &id[..8]))
            .spawn(move || {
                let fail_stop_capable = manager.backend.supports_background_jobs();
                let result = catch_unwind(AssertUnwindSafe(|| {
                    manager
                        .backend
                        .exec(&session, &request, &worker_job.control)
                }))
                .unwrap_or_else(|_| {
                    Err(sandbox_control_lost(
                        "sandbox backend panicked while executing a live command",
                    ))
                });
                let fatal_reason = result
                    .as_ref()
                    .err()
                    .filter(|error| fail_stop_capable && is_sandbox_control_lost(error))
                    .map(|error| format!("{error:#}"));

                // Terminal state is also an output fence: after this returns no
                // drain thread can append another chunk, even when an abnormal
                // backend cleanup deliberately detached a pipe reader.
                worker_job.control.seal_output();

                let newly_fatal = {
                    let mut state = manager.state.lock().expect("job manager poisoned");
                    let newly_fatal = if let Some(reason) = &fatal_reason {
                        state.accepting = false;
                        if state.fatal_reason.is_none() {
                            state.fatal_reason = Some(reason.clone());
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    state.active_global = state.active_global.saturating_sub(1);
                    if let Some(active) = state.active_per_tenant.get_mut(&worker_tenant) {
                        *active = active.saturating_sub(1);
                        if *active == 0 {
                            state.active_per_tenant.remove(&worker_tenant);
                        }
                    }
                    newly_fatal
                };
                worker_job.publish_terminal(result);
                if newly_fatal {
                    let handler = manager
                        .fatal_handler
                        .lock()
                        .expect("fatal handler poisoned")
                        .clone();
                    if let (Some(handler), Some(reason)) = (handler, fatal_reason) {
                        handler(reason);
                    }
                }
            });

        if let Err(error) = spawn {
            let mut state = self.state.lock().expect("job manager poisoned");
            state.jobs.remove(&id);
            state.active_global = state.active_global.saturating_sub(1);
            if let Some(active) = state.active_per_tenant.get_mut(&tenant) {
                *active = active.saturating_sub(1);
                if *active == 0 {
                    state.active_per_tenant.remove(&tenant);
                }
            }
            return Err(anyhow!("spawn background job: {error}"));
        }

        Ok(id)
    }

    pub fn wait_result_and_forget(&self, id: &str) -> Result<ExecResult> {
        let job = self.get(id)?;
        let terminal = job.wait_terminal();
        let result = job.as_exec_result(terminal);
        self.state
            .lock()
            .expect("job manager poisoned")
            .jobs
            .remove(id);
        Ok(result)
    }

    fn get(&self, id: &str) -> Result<Arc<Job>> {
        let mut state = self.state.lock().expect("job manager poisoned");
        Self::sweep_locked(&mut state, Instant::now());
        state
            .jobs
            .get(id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown or expired job {id}"))
    }

    pub fn poll(&self, id: &str, cursor: u64) -> Result<JobSnapshot> {
        Ok(self.get(id)?.snapshot(cursor))
    }

    pub fn cancel(&self, id: &str) -> Result<JobState> {
        Ok(self.get(id)?.request_cancel())
    }

    #[cfg(feature = "mcp-http")]
    pub fn tenant(&self, id: &str) -> Option<String> {
        self.get(id).ok().map(|job| job.tenant.clone())
    }

    fn stop_accepting_and_collect(&self) -> Vec<Arc<Job>> {
        let mut state = self.state.lock().expect("job manager poisoned");
        state.accepting = false;
        state
            .jobs
            .values()
            .filter(|job| job.state() != JobState::Terminal)
            .cloned()
            .collect()
    }

    pub fn cancel_all_and_wait(&self) {
        let jobs = self.stop_accepting_and_collect();
        for job in &jobs {
            job.request_cancel();
        }
        for job in jobs {
            job.wait_terminal();
        }
    }

    #[cfg(feature = "mcp-http")]
    pub fn begin_shutdown(&self) {
        let jobs = self.stop_accepting_and_collect();
        for job in jobs {
            job.request_cancel();
        }
    }

    #[cfg(feature = "mcp-http")]
    pub fn stop_accepting(&self) {
        self.state.lock().expect("job manager poisoned").accepting = false;
    }

    pub fn wait_all(&self) {
        let jobs = self.stop_accepting_and_collect();
        for job in jobs {
            job.wait_terminal();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    use crate::sandbox::SessionSpec;

    struct GateBackend {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    struct LateOutputBackend;

    struct ErrorOnCancelBackend {
        entered: mpsc::Sender<()>,
    }

    struct UnsupportedControlLossBackend;

    struct FailOnceGateBackend {
        calls: AtomicUsize,
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl SandboxBackend for FailOnceGateBackend {
        fn name(&self) -> &'static str {
            "fail-once-gate"
        }

        fn supports_background_jobs(&self) -> bool {
            true
        }

        fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new("fail-once-alice"))
        }

        fn exec(
            &self,
            _session: &SessionId,
            _request: &ExecRequest,
            _control: &ExecControl,
        ) -> Result<ExecResult> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let _ = self.entered.send(());
                let _ = self.release.lock().expect("release poisoned").recv();
                return Err(anyhow!("backend transport integrity lost"));
            }
            Ok(ExecResult {
                exit_code: Some(0),
                ..Default::default()
            })
        }

        fn close_session(&self, _session: &SessionId) -> Result<()> {
            Ok(())
        }
    }

    impl SandboxBackend for ErrorOnCancelBackend {
        fn name(&self) -> &'static str {
            "error-on-cancel"
        }

        fn supports_background_jobs(&self) -> bool {
            true
        }

        fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new("error-alice"))
        }

        fn exec(
            &self,
            _session: &SessionId,
            _request: &ExecRequest,
            control: &ExecControl,
        ) -> Result<ExecResult> {
            let _ = self.entered.send(());
            while !control.is_cancelled() {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(sandbox_control_lost("cleanup could not be proven"))
        }

        fn close_session(&self, _session: &SessionId) -> Result<()> {
            Ok(())
        }
    }

    impl SandboxBackend for UnsupportedControlLossBackend {
        fn name(&self) -> &'static str {
            "unsupported-control-loss"
        }

        fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new("unsupported-alice"))
        }

        fn exec(
            &self,
            _session: &SessionId,
            _request: &ExecRequest,
            _control: &ExecControl,
        ) -> Result<ExecResult> {
            Err(sandbox_control_lost("unsupported backend marker"))
        }

        fn close_session(&self, _session: &SessionId) -> Result<()> {
            Ok(())
        }
    }

    impl SandboxBackend for LateOutputBackend {
        fn name(&self) -> &'static str {
            "late-output"
        }

        fn supports_background_jobs(&self) -> bool {
            true
        }

        fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new("late-alice"))
        }

        fn exec(
            &self,
            _session: &SessionId,
            _request: &ExecRequest,
            control: &ExecControl,
        ) -> Result<ExecResult> {
            control.emit(ExecStream::Stdout, b"before-terminal");
            let late = control.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(30));
                late.emit(ExecStream::Stdout, b"after-terminal");
            });
            Ok(ExecResult {
                exit_code: Some(0),
                ..Default::default()
            })
        }

        fn close_session(&self, _session: &SessionId) -> Result<()> {
            Ok(())
        }
    }

    impl SandboxBackend for GateBackend {
        fn name(&self) -> &'static str {
            "gate"
        }

        fn supports_background_jobs(&self) -> bool {
            true
        }

        fn open_session(&self, _spec: &SessionSpec) -> Result<SessionId> {
            Ok(SessionId::new("gate-alice"))
        }

        fn exec(
            &self,
            _session: &SessionId,
            _request: &ExecRequest,
            control: &ExecControl,
        ) -> Result<ExecResult> {
            control.emit(ExecStream::Stdout, b"first\n");
            let _ = self.entered.send(());
            loop {
                if control.is_cancelled() {
                    return Ok(ExecResult {
                        cancelled: true,
                        error: Some("cancelled by test backend".to_string()),
                        ..Default::default()
                    });
                }
                match self
                    .release
                    .lock()
                    .expect("release poisoned")
                    .recv_timeout(Duration::from_millis(10))
                {
                    Ok(()) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            control.emit(ExecStream::Stderr, b"last\n");
            Ok(ExecResult {
                exit_code: Some(0),
                ..Default::default()
            })
        }

        fn close_session(&self, _session: &SessionId) -> Result<()> {
            Ok(())
        }
    }

    fn manager() -> (Arc<JobManager>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let backend: Arc<dyn SandboxBackend> = Arc::new(GateBackend {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        (JobManager::new(backend), entered_rx, release_tx)
    }

    fn request() -> ExecRequest {
        ExecRequest {
            command: "work".to_string(),
            shell_mode: ExecShellMode::Login,
            cwd: None,
            stdin: None,
            timeout: None,
        }
    }

    fn wait_terminal(manager: &JobManager, id: &str) -> JobSnapshot {
        for _ in 0..200 {
            let snapshot = manager.poll(id, 0).expect("poll");
            if snapshot.state == JobState::Terminal {
                return snapshot;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("job did not become terminal");
    }

    #[test]
    fn partial_output_is_retryable_by_cursor() {
        let (manager, entered, release) = manager();
        let id = manager
            .start("alice".to_string(), SessionId::new("gate-alice"), request())
            .expect("start");
        entered.recv().expect("entered");

        let first = manager.poll(&id, 0).expect("first poll");
        assert_eq!(first.state, JobState::Running);
        assert_eq!(first.chunks.len(), 1);
        assert_eq!(first.chunks[0].text, "first\n");
        let retry = manager.poll(&id, 0).expect("retry same cursor");
        assert_eq!(retry.chunks[0].sequence, first.chunks[0].sequence);
        assert_eq!(retry.chunks[0].text, first.chunks[0].text);

        release.send(()).expect("release");
        let terminal = wait_terminal(&manager, &id);
        assert_eq!(terminal.terminal.as_ref().unwrap().kind(), "exited");
        let delta = manager
            .poll(&id, first.next_cursor)
            .expect("poll from acknowledged cursor");
        assert_eq!(delta.chunks.len(), 1);
        assert_eq!(delta.chunks[0].text, "last\n");
    }

    #[test]
    fn cancellation_is_idempotent_and_terminal_only_after_backend_observes_it() {
        let (manager, entered, _release) = manager();
        let id = manager
            .start("alice".to_string(), SessionId::new("gate-alice"), request())
            .expect("start");
        entered.recv().expect("entered");
        assert_eq!(manager.cancel(&id).unwrap(), JobState::Cancelling);
        assert!(matches!(
            manager.cancel(&id).unwrap(),
            JobState::Cancelling | JobState::Terminal
        ));
        let terminal = wait_terminal(&manager, &id);
        assert_eq!(terminal.terminal.as_ref().unwrap().kind(), "cancelled");
        assert_eq!(manager.cancel(&id).unwrap(), JobState::Terminal);
        assert!(manager.fatal_reason().is_none());
    }

    #[test]
    fn bounded_output_reports_a_cursor_gap() {
        let mut output = OutputLog::default();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..=(MAX_RETAINED_OUTPUT_BYTES / chunk.len()) {
            output.push(ExecStream::Stdout, &chunk);
        }
        assert!(output.retained_bytes <= MAX_RETAINED_OUTPUT_BYTES);
        assert!(output.dropped_bytes > 0);
        let (_chunks, next, gap, _has_more) = output.poll(0);
        assert!(gap);
        assert!(next > 0);
    }

    #[test]
    fn future_cursor_is_clamped_without_skipping_later_output() {
        let mut output = OutputLog::default();
        output.push(ExecStream::Stdout, b"first");

        // Even an empty/future poll seals the current tail. A later same-stream
        // push must receive a new sequence rather than becoming invisible
        // behind the cursor returned here.
        let (chunks, cursor, gap, has_more) = output.poll(u64::MAX);
        assert!(chunks.is_empty());
        assert!(!gap);
        assert!(!has_more);
        assert_eq!(cursor, 1);

        output.push(ExecStream::Stdout, b"second");
        let (chunks, next, gap, has_more) = output.poll(cursor);
        assert!(!gap);
        assert!(!has_more);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "second");
        assert_eq!(next, 2);
    }

    #[test]
    fn poll_reports_when_retained_output_has_another_page() {
        let mut output = OutputLog::default();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..5 {
            output.push(ExecStream::Stdout, &chunk);
        }

        let (first, cursor, gap, has_more) = output.poll(0);
        assert!(!gap);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].text.len(), MAX_POLL_OUTPUT_BYTES);
        assert!(has_more);

        let (second, next, gap, has_more) = output.poll(cursor);
        assert!(!gap);
        assert_eq!(second.len(), 1);
        assert!(!has_more);
        assert_eq!(next, 2);
    }

    #[test]
    fn fragmented_same_stream_output_coalesces_without_a_gap() {
        let mut output = OutputLog::default();
        let count = MAX_RETAINED_CHUNKS_PER_JOB + 257;
        for _ in 0..count {
            output.push(ExecStream::Stdout, b"x");
        }
        let (stdout, stderr, gap) = output.render_all();
        assert_eq!(stdout, vec![b'x'; count]);
        assert!(stderr.is_empty());
        assert!(!gap);
        assert_eq!(output.dropped_bytes, 0);
        assert_eq!(output.chunks.len(), 1);
    }

    #[test]
    fn one_large_emit_is_split_at_the_poll_chunk_boundary() {
        let mut output = OutputLog::default();
        let bytes = vec![b'x'; MAX_POLL_OUTPUT_BYTES + 1];
        output.push(ExecStream::Stdout, &bytes);
        assert_eq!(output.chunks.len(), 2);
        assert_eq!(output.chunks[0].bytes.len(), MAX_POLL_OUTPUT_BYTES);
        assert_eq!(output.chunks[1].bytes.len(), 1);
        let (stdout, stderr, gap) = output.render_all();
        assert_eq!(stdout, bytes);
        assert!(stderr.is_empty());
        assert!(!gap);
    }

    #[test]
    fn alternating_tiny_chunks_still_enforce_the_metadata_bound() {
        let mut output = OutputLog::default();
        for index in 0..=MAX_RETAINED_CHUNKS_PER_JOB {
            let stream = if index % 2 == 0 {
                ExecStream::Stdout
            } else {
                ExecStream::Stderr
            };
            output.push(stream, b"x");
        }
        assert_eq!(output.chunks.len(), MAX_RETAINED_CHUNKS_PER_JOB);
        assert_eq!(output.dropped_bytes, 1);
        let (_chunks, _cursor, gap, _has_more) = output.poll(0);
        assert!(gap);
    }

    #[test]
    fn terminal_state_seals_output_against_late_drain_threads() {
        let backend: Arc<dyn SandboxBackend> = Arc::new(LateOutputBackend);
        let manager = JobManager::new(backend);
        let id = manager
            .start("alice".to_string(), SessionId::new("late-alice"), request())
            .expect("start");
        let terminal = wait_terminal(&manager, &id);
        assert_eq!(terminal.chunks.len(), 1);
        assert_eq!(terminal.chunks[0].text, "before-terminal");

        std::thread::sleep(Duration::from_millis(60));
        let replay = manager.poll(&id, 0).expect("replay");
        assert_eq!(replay.state, JobState::Terminal);
        assert_eq!(replay.chunks.len(), 1);
        assert_eq!(replay.chunks[0].text, "before-terminal");
    }

    #[test]
    fn cancellation_control_loss_closes_global_admission_and_notifies_transport() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (fatal_tx, fatal_rx) = mpsc::channel();
        let backend: Arc<dyn SandboxBackend> = Arc::new(ErrorOnCancelBackend {
            entered: entered_tx,
        });
        let manager = JobManager::new(backend);
        manager.set_fatal_handler(Arc::new(move |reason| {
            let _ = fatal_tx.send(reason);
        }));
        let id = manager
            .start(
                "alice".to_string(),
                SessionId::new("error-alice"),
                request(),
            )
            .expect("start");
        entered_rx.recv().expect("entered");
        assert_eq!(manager.cancel(&id).unwrap(), JobState::Cancelling);
        let terminal = wait_terminal(&manager, &id);
        let terminal = terminal.terminal.expect("terminal detail");
        assert_eq!(terminal.kind(), "failed");
        assert!(
            terminal
                .error()
                .unwrap()
                .contains("cleanup could not be proven")
        );
        let fatal = fatal_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("fatal handler notified");
        assert!(fatal.contains("cleanup could not be proven"), "{fatal}");
        let error = manager
            .start("bob".to_string(), SessionId::new("error-bob"), request())
            .expect_err("control loss must close global admission");
        assert!(error.to_string().contains("losing execution control"));
    }

    #[test]
    fn ordinary_backend_error_releases_lane_without_sticky_state() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let backend: Arc<dyn SandboxBackend> = Arc::new(FailOnceGateBackend {
            calls: AtomicUsize::new(0),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let manager = JobManager::new(backend);
        let session = SessionId::new("fail-once-alice");
        let first = manager
            .start("alice".to_string(), session.clone(), request())
            .expect("first job starts");
        entered_rx.recv().expect("job entered backend");
        release_tx.send(()).expect("release failing backend");

        // Wait until the failing command releases its ordinary admission lane.
        for _ in 0..200 {
            let state = manager.state.lock().expect("job manager poisoned");
            if state.active_global == 0 {
                break;
            }
            drop(state);
            std::thread::sleep(Duration::from_millis(5));
        }
        let state = manager.state.lock().expect("job manager poisoned");
        assert_eq!(
            state.active_global, 0,
            "failing job did not release its lane"
        );
        drop(state);

        let terminal = wait_terminal(&manager, &first);
        assert_eq!(terminal.terminal.unwrap().kind(), "failed");
        let recovered = manager
            .start("alice".to_string(), session.clone(), request())
            .expect("an ordinary backend error must not permanently poison the tenant");
        assert_eq!(
            wait_terminal(&manager, &recovered).terminal.unwrap().kind(),
            "exited"
        );
    }

    #[test]
    fn unsupported_backend_marker_is_not_a_process_fatal_event() {
        let backend: Arc<dyn SandboxBackend> = Arc::new(UnsupportedControlLossBackend);
        let manager = JobManager::new(backend);
        let first = manager
            .start(
                "alice".to_string(),
                SessionId::new("unsupported-alice"),
                request(),
            )
            .expect("first job starts");
        assert_eq!(
            wait_terminal(&manager, &first).terminal.unwrap().kind(),
            "failed"
        );
        assert!(manager.fatal_reason().is_none());
        let second = manager
            .start(
                "bob".to_string(),
                SessionId::new("unsupported-bob"),
                request(),
            )
            .expect("unsupported backend errors must not close global admission");
        assert_eq!(
            wait_terminal(&manager, &second).terminal.unwrap().kind(),
            "failed"
        );
    }

    #[cfg(feature = "mcp-http")]
    #[test]
    fn shutdown_atomically_stops_admission_and_cancels_live_jobs() {
        let (manager, entered, _release) = manager();
        let id = manager
            .start("alice".to_string(), SessionId::new("gate-alice"), request())
            .expect("start alice");
        entered.recv().expect("entered");

        manager.begin_shutdown();
        let error = manager
            .start("bob".to_string(), SessionId::new("gate-bob"), request())
            .expect_err("shutdown must close admission before returning");
        assert!(error.to_string().contains("shutting down"));

        let terminal = wait_terminal(&manager, &id);
        assert_eq!(terminal.terminal.unwrap().kind(), "cancelled");
    }
}

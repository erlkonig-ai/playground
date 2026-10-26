//! Linux-only, ephemeral fixture profile of the existing Playground backend.
//!
//! No persistent tenant provisioning, faculty mounts, network, or fallback.
//! A delegated cgroup parent is an operator prerequisite. Only newly created
//! groups below it are configured; the parent and host policy are never changed.
//! Background admission deliberately remains OFF until the Linux descendant
//! and confinement tests below have been run against the deployed binaries.

use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::Args;

use super::SandboxBackend;

const MIB: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_FIXTURE: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_COMMAND: usize = 8192;
#[cfg(target_os = "linux")]
const OUTPUT_CAP: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const TIMEOUT_SECS: u64 = 10;
const SCRATCH_BYTES: u64 = 16 * MIB;

/// The bootstrap profile is intentionally stdio-only and single-tenant.
#[derive(Args, Clone, Debug, Default)]
pub struct Options {
    /// One explicitly selected synthetic text fixture, at most 4096 bytes.
    #[arg(long)]
    pub bubblewrap_fixture: Option<PathBuf>,
    /// Existing writable cgroup-v2 delegation with cpu, memory and pids enabled.
    #[arg(long)]
    pub bubblewrap_cgroup_parent: Option<PathBuf>,
    /// The only tenant accepted by this ephemeral provider.
    #[arg(long)]
    pub bubblewrap_tenant: Option<String>,
    /// Aggregate memory ceiling across this provider's executions (MiB).
    #[arg(long, default_value_t = 512)]
    pub bubblewrap_memory_mib: u64,
    /// Aggregate process/thread ceiling, including namespace supervisors.
    #[arg(long, default_value_t = 64)]
    pub bubblewrap_tasks: u64,
    /// Aggregate CPU quota as a percentage of one CPU.
    #[arg(long, default_value_t = 100)]
    pub bubblewrap_cpu_percent: u64,
}

impl Options {
    pub fn build(self) -> Result<Box<dyn SandboxBackend>> {
        #[cfg(target_os = "linux")]
        {
            Ok(Box::new(linux::Bubblewrap::open(self)?))
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("bubblewrap requires Linux; no unsandboxed fallback")
        }
    }
}

fn validate_limits(memory_mib: u64, tasks: u64, cpu_percent: u64) -> Result<()> {
    ensure!(
        (64..=4096).contains(&memory_mib),
        "fixture memory limit must be 64..4096 MiB"
    );
    ensure!(
        (8..=256).contains(&tasks),
        "fixture task limit must be 8..256"
    );
    ensure!(
        (1..=200).contains(&cpu_percent),
        "fixture CPU quota must be 1..200 percent"
    );
    Ok(())
}

/// Fixed guest layout; no caller-provided mount destination or extra bwrap args.
fn arguments(fixture_fd: i32, lib64: bool, command: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--setenv",
        "HOME",
        "/work",
        "--setenv",
        "LANG",
        "C",
        "--setenv",
        "LC_ALL",
        "C",
        "--ro-bind",
        "/usr/bin",
        "/usr/bin",
        "--ro-bind",
        "/usr/lib",
        "/usr/lib",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if lib64 {
        args.extend(
            [
                "--ro-bind",
                "/usr/lib64",
                "/usr/lib64",
                "--symlink",
                "usr/lib64",
                "/lib64",
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }
    args.extend([
        "--perms".into(),
        "0444".into(),
        "--ro-bind-data".into(),
        fixture_fd.to_string(),
        "/fixture/record.txt".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--size".into(),
        SCRATCH_BYTES.to_string(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--size".into(),
        SCRATCH_BYTES.to_string(),
        "--tmpfs".into(),
        "/work".into(),
        "--remount-ro".into(),
        "/".into(),
        "--chdir".into(),
        "/work".into(),
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        command.into(),
    ]);
    args
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail, ensure};

    use super::*;
    use crate::sandbox::proc::{ChildScope, drive_child_capped_controlled_scope};
    use crate::sandbox::{
        ExecControl, ExecRequest, ExecResult, OpenSpec, SandboxBackend, SessionId,
        sandbox_control_lost,
    };

    const CGROUP2_MAGIC: libc::c_long = 0x6367_7270;
    static NEXT_GROUP: AtomicU64 = AtomicU64::new(0);

    pub(super) struct Bubblewrap {
        tenant: String,
        fixture: Vec<u8>,
        group: Group,
        memory: u64,
        tasks: u64,
        cpu: u64,
        lib64: bool,
        // One active command per provider. JobManager still owns all handles,
        // result retention and cancellation. Aggregate cgroup also bounds
        // construction/probes and enforces a shared ceiling across children.
        execution: Mutex<()>,
    }

    impl Bubblewrap {
        pub(super) fn open(options: Options) -> Result<Self> {
            validate_limits(
                options.bubblewrap_memory_mib,
                options.bubblewrap_tasks,
                options.bubblewrap_cpu_percent,
            )?;
            let tenant = options
                .bubblewrap_tenant
                .context("--bubblewrap-tenant is required")?;
            ensure!(
                !tenant.is_empty() && tenant.len() <= 64 && tenant.trim() == tenant,
                "explicit fixture tenant must contain 1..64 bytes without edge whitespace"
            );
            let path = options
                .bubblewrap_fixture
                .context("--bubblewrap-fixture is required")?;
            ensure!(path.is_absolute(), "fixture path must be absolute");
            let mut fixture = Vec::new();
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
                .context("open regular synthetic fixture without following a symlink")?;
            ensure!(file.metadata()?.is_file(), "fixture must be a regular file");
            file.take((MAX_FIXTURE + 1) as u64)
                .read_to_end(&mut fixture)?;
            ensure!(
                !fixture.is_empty() && fixture.len() <= MAX_FIXTURE,
                "fixture must contain 1..4096 bytes"
            );
            std::str::from_utf8(&fixture).context("fixture must be UTF-8 text")?;
            // Fixed distro paths only, resolved before the child exists. No
            // /usr/local, host /etc, home, run, tmp, source tree or model mounts.
            for path in ["/usr/bin", "/usr/lib"] {
                ensure!(
                    fs::canonicalize(path)? == Path::new(path),
                    "distro userspace path must not redirect: {path}"
                );
                ensure!(
                    fs::metadata(path)?.is_dir(),
                    "missing distro directory {path}"
                );
            }
            let bwrap =
                fs::metadata("/usr/bin/bwrap").context("installed /usr/bin/bwrap required")?;
            ensure!(
                bwrap.is_file() && bwrap.uid() == 0 && bwrap.mode() & 0o6022 == 0,
                "bwrap must be root-owned, non-setid and not group/world writable"
            );
            let lib64 = Path::new("/usr/lib64").exists();
            if lib64 {
                ensure!(
                    fs::canonicalize("/usr/lib64")? == Path::new("/usr/lib64"),
                    "/usr/lib64 must not redirect outside the fixed userspace mapping"
                );
            }
            let parent = options
                .bubblewrap_cgroup_parent
                .context("--bubblewrap-cgroup-parent is required; no delegation is created")?;
            ensure!(parent.is_absolute(), "cgroup parent must be absolute");
            let parent = fs::canonicalize(parent)?;
            ensure!(
                parent.starts_with("/sys/fs/cgroup") && parent != Path::new("/sys/fs/cgroup"),
                "explicit delegated cgroup subtree required, not the host root"
            );
            let directory = File::open(&parent)?;
            let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
            if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            ensure!(
                unsafe { stat.assume_init() }.f_type == CGROUP2_MAGIC,
                "delegation must be an actual cgroup-v2 filesystem"
            );
            // Only inherited, already enabled controllers are used. Never
            // write to the operator's parent to obtain missing delegation.
            let enabled = fs::read_to_string(parent.join("cgroup.subtree_control"))?;
            for controller in ["cpu", "memory", "pids"] {
                ensure!(
                    enabled.split_whitespace().any(|s| s == controller),
                    "delegated parent must already enable {controller}"
                );
            }
            let memory = options.bubblewrap_memory_mib * MIB;
            let tasks = options.bubblewrap_tasks;
            let cpu = options.bubblewrap_cpu_percent;
            let group = Group::create(&parent, memory, tasks, cpu)?;
            fs::write(
                group.path.join("cgroup.subtree_control"),
                "+cpu +memory +pids",
            )
            .context("enable inherited controllers inside owned aggregate only")?;
            let backend = Self {
                tenant,
                fixture,
                group,
                memory,
                tasks,
                cpu,
                lib64,
                execution: Mutex::new(()),
            };
            // Same fully confined path as commands, BEFORE any session opens.
            // Missing namespace policy/kernel support is an error, not a retry
            // with --*-try, reduced isolation, or a host shell.
            let probe = backend.execute(&ExecRequest {
                command: "test -r /fixture/record.txt && test -d /work && test ! -e /home && test ! -e /sys && test ! -e /etc && test ! -e /pile && test -z \"${TRIBLESPACE_KEY-}${PILE-}${SSH_AUTH_SOCK-}\"".into(),
                shell_mode: super::super::ExecShellMode::Clean,
                cwd: None, stdin: None, timeout: Some(Duration::from_secs(3)),
            }, &ExecControl::default())?;
            ensure!(
                probe.exit_code == Some(0) && probe.error.is_none(),
                "unprivileged confined probe failed: {:?}: {}",
                probe.error,
                String::from_utf8_lossy(&probe.stderr)
            );
            Ok(backend)
        }

        fn execute(&self, request: &ExecRequest, control: &ExecControl) -> Result<ExecResult> {
            let _slot = self
                .execution
                .try_lock()
                .map_err(|_| anyhow::anyhow!("fixture execution slot busy"))?;
            ensure!(
                request.command.len() <= MAX_COMMAND,
                "command exceeds 8192 bytes"
            );
            ensure!(
                request
                    .stdin
                    .as_ref()
                    .is_none_or(|s| s.len() <= MAX_FIXTURE),
                "stdin exceeds 4096 bytes"
            );
            ensure!(
                request
                    .cwd
                    .as_deref()
                    .is_none_or(|p| p == Path::new("/work")),
                "fixture profile cwd is /work"
            );
            let timeout = request
                .timeout
                .unwrap_or(Duration::from_secs(TIMEOUT_SECS))
                .min(Duration::from_secs(TIMEOUT_SECS));
            ensure!(!timeout.is_zero(), "zero timeout");
            let job = Group::create(&self.group.path, self.memory / 2, self.tasks / 2, self.cpu)?;
            let procs = OpenOptions::new()
                .write(true)
                .open(job.path.join("cgroup.procs"))?;
            let fixture = sealed_fixture(&self.fixture)?;
            let fixture_fd = fixture.as_raw_fd();
            let procs_fd = procs.as_raw_fd();
            let mut command = Command::new("/usr/bin/bwrap");
            command
                .args(arguments(fixture_fd, self.lib64, &request.command))
                .env_clear()
                .current_dir("/")
                .stdin(if request.stdin.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            // async-signal-safe operations only. Membership precedes exec or
            // any child fork. CLOEXEC closes every ambient fd at exec, except
            // the one sealed fixture fd consumed/closed by --ro-bind-data.
            unsafe {
                command.pre_exec(move || {
                    if libc::write(procs_fd, b"0".as_ptr().cast(), 1) != 1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::syscall(
                        libc::SYS_close_range,
                        3u32,
                        u32::MAX,
                        libc::CLOSE_RANGE_CLOEXEC,
                    ) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(fixture_fd, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command
                .spawn()
                .context("spawn confined bubblewrap (no fallback)")?;
            let output = drive_child_capped_controlled_scope(
                child,
                request.stdin.clone(),
                timeout,
                OUTPUT_CAP,
                control,
                &job,
            )?;
            let error = if output.cancelled {
                Some("cancelled; owned cgroup empty".into())
            } else if output.timed_out {
                Some("10-second maximum wall-time exceeded; owned cgroup empty".into())
            } else if output.output_truncated {
                Some("output cap exceeded; owned cgroup empty".into())
            } else {
                None
            };
            job.remove()?;
            Ok(ExecResult {
                stdout: output.stdout,
                stderr: output.stderr,
                exit_code: output.exit_code,
                cancelled: output.cancelled,
                error,
            })
        }
    }

    impl SandboxBackend for Bubblewrap {
        fn name(&self) -> &'static str {
            "bubblewrap"
        }
        fn supports_background_jobs(&self) -> bool {
            // Source implementation is not runtime acceptance. No CLI override.
            false
        }
        fn open_session(&self, spec: &OpenSpec) -> Result<SessionId> {
            ensure!(spec.tenant.label == self.tenant, "unknown fixture tenant");
            Ok(SessionId::new(self.tenant.clone()))
        }
        fn exec(
            &self,
            session: &SessionId,
            request: &ExecRequest,
            control: &ExecControl,
        ) -> Result<ExecResult> {
            ensure!(session.as_str() == self.tenant, "unknown fixture session");
            self.execute(request, control)
        }
        fn close_session(&self, session: &SessionId) -> Result<()> {
            ensure!(session.as_str() == self.tenant, "unknown fixture session");
            Ok(())
        }
        fn provision_sandbox(&self, _: &super::super::ProvisionSpec) -> Result<()> {
            bail!("fixture backend is configured at provider start; no persistent provisioning")
        }
        fn shutdown(&self) -> Result<usize> {
            self.group
                .kill_and_wait()
                .map_err(|e| sandbox_control_lost(format!("{e:#}")))?;
            Ok(0)
        }
    }

    fn sealed_fixture(bytes: &[u8]) -> Result<File> {
        let fd = unsafe {
            libc::memfd_create(
                c"playground-fixture".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        ensure!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        let seals =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        ensure!(
            unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } == 0,
            "seal fixture: {}",
            std::io::Error::last_os_error()
        );
        // bwrap reads the supplied fd from its current offset.
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    struct Group {
        path: PathBuf,
        removed: AtomicBool,
    }

    impl Group {
        fn create(parent: &Path, memory: u64, tasks: u64, cpu: u64) -> Result<Self> {
            let serial = NEXT_GROUP.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("playground-{}-{serial}", std::process::id()));
            fs::create_dir(&path).context("create NEW owned cgroup; never reuse another owner")?;
            let group = Self {
                path,
                removed: AtomicBool::new(false),
            };
            for (name, value) in [
                ("memory.max", memory.to_string()),
                ("memory.swap.max", "0".into()),
                ("memory.oom.group", "1".into()),
                ("pids.max", tasks.to_string()),
                ("cpu.max", format!("{} 100000", cpu * 1000)),
            ] {
                fs::write(group.path.join(name), &value)
                    .with_context(|| format!("enforce {name}"))?;
                ensure!(
                    fs::read_to_string(group.path.join(name))?.trim() == value,
                    "kernel did not retain requested {name} bound"
                );
            }
            // cgroup.kill (Linux >=5.14) is compulsory before any spawn.
            OpenOptions::new()
                .write(true)
                .open(group.path.join("cgroup.kill"))?;
            Ok(group)
        }
        fn remove(self) -> Result<()> {
            self.kill_and_wait()?;
            fs::remove_dir(&self.path).context("remove empty owned execution cgroup")?;
            self.removed.store(true, Ordering::Release);
            Ok(())
        }
    }

    impl ChildScope for Group {
        fn kill_and_wait(&self) -> Result<()> {
            if self.removed.load(Ordering::Acquire) {
                return Ok(());
            }
            fs::write(self.path.join("cgroup.kill"), "1").map_err(|e| {
                sandbox_control_lost(format!("kill owned cgroup {}: {e}", self.path.display()))
            })?;
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let events = fs::read_to_string(self.path.join("cgroup.events"))?;
                if events.lines().any(|line| line == "populated 0") {
                    return Ok(());
                }
                ensure!(
                    Instant::now() < deadline,
                    "owned cgroup {} remains populated after kill",
                    self.path.display()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for Group {
        fn drop(&mut self) {
            if !self.removed.load(Ordering::Acquire) {
                if let Err(error) = self
                    .kill_and_wait()
                    .and_then(|()| fs::remove_dir(&self.path).context("remove owned cgroup"))
                {
                    // Never recursively delete an unrecognized subtree or
                    // call a failed cleanup successful. Normal exec surfaces
                    // failures through SandboxControlLost before this path.
                    eprintln!("playground bubblewrap cleanup failed: {error:#}");
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::sandbox::ExecShellMode;

        fn request(command: &str, millis: u64) -> ExecRequest {
            ExecRequest {
                command: command.into(),
                shell_mode: ExecShellMode::Clean,
                cwd: None,
                stdin: None,
                timeout: Some(Duration::from_millis(millis)),
            }
        }

        #[test]
        fn fixture_is_sealed_and_rewound() {
            let mut file = sealed_fixture(b"synthetic marker\n").unwrap();
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            assert_eq!(text, "synthetic marker\n");
            assert!(file.write_all(b"replacement").is_err());
        }

        /// Requires an explicitly allocated, already-delegated synthetic-test
        /// parent. This test never creates a service or changes its parent.
        /// It must be run under an independent finite outer unit; no model.
        #[test]
        #[ignore = "Linux operational gate: explicit PLAYGROUND_BWRAP_TEST_CGROUP; bounded outer unit required"]
        fn linux_confinement_and_detached_descendants() -> Result<()> {
            let parent = std::env::var_os("PLAYGROUND_BWRAP_TEST_CGROUP")
                .context("test requires explicit delegated cgroup parent")?;
            let path = std::env::temp_dir().join(format!(
                "playground-synthetic-{}-{}.txt",
                std::process::id(),
                rand::random::<u64>()
            ));
            let mut fixture = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            fixture.write_all(b"synthetic-marker-7a91\n")?;
            struct Remove(PathBuf);
            impl Drop for Remove {
                fn drop(&mut self) {
                    let _ = fs::remove_file(&self.0);
                }
            }
            let _remove = Remove(path.clone());
            let backend = Bubblewrap::open(Options {
                bubblewrap_fixture: Some(path.clone()),
                bubblewrap_cgroup_parent: Some(parent.into()),
                bubblewrap_tenant: Some("synthetic-test".into()),
                bubblewrap_memory_mib: 512,
                bubblewrap_tasks: 64,
                bubblewrap_cpu_percent: 100,
            })?;
            assert!(
                !backend.supports_background_jobs(),
                "operational gate must not enable itself"
            );
            for command in [
                "cat /fixture/record.txt",
                "head -c 4096 /fixture/record.txt",
            ] {
                let out = backend.execute(&request(command, 1000), &ExecControl::default())?;
                assert_eq!(out.exit_code, Some(0));
                assert_eq!(out.stdout, b"synthetic-marker-7a91\n");
            }
            let host_net = fs::read_link("/proc/self/ns/net")?;
            let host_pid = fs::read_link("/proc/self/ns/pid")?;
            let check = format!(
                "test ! -e '{}' && test ! -e /sys/fs/cgroup && test ! -e /home && test ! -e /etc && test ! -w /usr/bin && test \"$(readlink /proc/self/ns/net)\" != '{}' && test \"$(readlink /proc/self/ns/pid)\" != '{}' && env",
                path.display(),
                host_net.display(),
                host_pid.display()
            );
            let out = backend.execute(&request(&check, 1000), &ExecControl::default())?;
            assert_eq!(
                out.exit_code,
                Some(0),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let env = String::from_utf8(out.stdout)?;
            for line in env.lines() {
                assert!(
                    ["PATH=", "HOME=", "LANG=", "LC_ALL=", "PWD=", "SHLVL=", "_="]
                        .iter()
                        .any(|prefix| line.starts_with(prefix)),
                    "unexpected inherited env: {line}"
                );
            }
            for command in [
                "printf overwrite > /fixture/record.txt",
                "dd if=/dev/zero of=/work/large bs=1048576 count=32",
            ] {
                let out = backend.execute(&request(command, 2000), &ExecControl::default())?;
                assert_ne!(out.exit_code, Some(0), "write/size restriction failed");
            }
            assert_eq!(fs::read(&path)?, b"synthetic-marker-7a91\n");
            let out = backend.execute(
                &request("yes synthetic-output", 2000),
                &ExecControl::default(),
            )?;
            assert!(
                out.error
                    .as_deref()
                    .is_some_and(|e| e.contains("output cap"))
            );
            assert!(out.stdout.len() <= OUTPUT_CAP);

            // Capture host PID/start-time identities from ONLY our new job
            // group. setsid and a nested background child cannot escape cgroup
            // ancestry. Check disappearance, not merely killpg or populated=0.
            let control = ExecControl::default();
            let identities = std::thread::scope(|scope| -> Result<Vec<(u32, String)>> {
                let thread = scope.spawn(|| {
                    backend.execute(
                        &request(
                            "setsid /bin/sh -c 'sleep 60 & wait' & sleep 60 & wait",
                            5000,
                        ),
                        &control,
                    )
                });
                let deadline = Instant::now() + Duration::from_secs(2);
                let identities = loop {
                    let mut ids = Vec::new();
                    for entry in fs::read_dir(&backend.group.path)? {
                        let entry = entry?;
                        if entry.file_type()?.is_dir() {
                            for pid in fs::read_to_string(entry.path().join("cgroup.procs"))?
                                .split_whitespace()
                            {
                                let pid: u32 = pid.parse()?;
                                if let Some(start) = process_start(pid) {
                                    ids.push((pid, start));
                                }
                            }
                        }
                    }
                    if ids.len() >= 5 {
                        break ids;
                    }
                    if Instant::now() >= deadline {
                        control.cancel();
                        let _ = thread.join();
                        bail!("did not observe the synthetic descendant tree before deadline");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                control.cancel();
                let out = thread.join().expect("execution worker panicked")?;
                assert!(out.cancelled);
                Ok(identities)
            })?;
            let deadline = Instant::now() + Duration::from_secs(3);
            while identities
                .iter()
                .any(|(pid, start)| process_start(*pid).as_ref() == Some(start))
            {
                ensure!(
                    Instant::now() < deadline,
                    "synthetic descendant still exists (including zombies) after cancellation"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let out = backend.execute(
                &request("setsid /bin/sh -c 'sleep 60 & wait' & wait", 200),
                &ExecControl::default(),
            )?;
            assert!(
                out.error
                    .as_deref()
                    .is_some_and(|e| e.contains("wall-time"))
            );
            assert!(
                fs::read_dir(&backend.group.path)?.all(|e| !e
                    .unwrap()
                    .file_type()
                    .unwrap()
                    .is_dir()),
                "job cgroups were not removed"
            );
            backend.shutdown()?;
            Ok(())
        }

        fn process_start(pid: u32) -> Option<String> {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // Fields after the final ')' start at state (field3); starttime is22.
            Some(
                stat.rsplit_once(')')?
                    .1
                    .split_whitespace()
                    .nth(19)?
                    .to_owned(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_profile_has_no_host_root_or_ambient_environment() {
        let args = arguments(9, false, "cat /fixture/record.txt");
        for required in [
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--disable-userns",
            "--clearenv",
            "--remount-ro",
        ] {
            assert!(args.iter().any(|arg| arg == required));
        }
        let binds: Vec<_> = args
            .windows(3)
            .filter(|a| a[0] == "--ro-bind")
            .map(|a| (a[1].as_str(), a[2].as_str()))
            .collect();
        assert_eq!(binds, [("/usr/bin", "/usr/bin"), ("/usr/lib", "/usr/lib")]);
        for forbidden in [
            "--bind",
            "--share-net",
            "--unshare-user-try",
            "--unshare-cgroup-try",
            "/home",
            "/run",
            "/sys",
            "TRIBLESPACE_KEY",
            "SSH_AUTH_SOCK",
        ] {
            assert!(!args.iter().any(|arg| arg == forbidden), "{forbidden}");
        }
        assert_eq!(
            &args[args.len() - 4..],
            ["--", "/bin/sh", "-c", "cat /fixture/record.txt"]
        );
    }

    #[test]
    fn shell_text_cannot_become_a_bwrap_option() {
        let args = arguments(9, false, "--bind / /; cat /fixture/record.txt");
        assert_eq!(args.last().unwrap(), "--bind / /; cat /fixture/record.txt");
        assert!(!args.iter().any(|a| a == "--bind"));
    }

    #[test]
    fn aggregate_limits_are_explicit_and_bounded() {
        assert!(validate_limits(512, 64, 100).is_ok());
        for invalid in [
            (0, 64, 100),
            (4097, 64, 100),
            (512, 0, 100),
            (512, 257, 100),
            (512, 64, 0),
            (512, 64, 201),
        ] {
            assert!(validate_limits(invalid.0, invalid.1, invalid.2).is_err());
        }
    }
}

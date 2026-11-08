//! ffmpeg/ffprobe child orchestration (the product spec's process and
//! resource-limit faces).
//!
//! Contract embodied by [`MediaCommand`]/[`MediaChild`]:
//!
//! - **argv array, zero shell**: arguments travel as an `OsString`
//!   vector — there is no string-assembly API, so no shell
//!   metacharacter surface exists by construction;
//! - **absolute paths only**: a non-absolute program path is refused
//!   ([`MediaError::NotAbsolute`] — no PATH
//!   lookup at spawn time, discovery owns resolution);
//! - **explicit `-f`**: the [`MediaCommand::output`] face refuses an
//!   output path unless an explicit `-f <fmt>` was recorded first —
//!   container format is never guessed; output paths are
//!   absolute and a leading `-` in the filename is rejected
//!   (option-injection guard);
//! - **piped trio**: stdin/stdout/stderr are all piped; the stdin write
//!   end is dropped at spawn (EOF upstream; the argv carries `-nostdin`
//!   as the belt to that suspenders);
//! - **`kill_on_drop` + cancel token + watchdog**: the child dies with
//!   its handle (no orphans), the caller's [`CancellationToken`]
//!   aborts it through the TERM→(5s)→KILL escalation
//!   ([`MediaError::Cancelled`]), and the progress watchdog
//!   (frame/total_size stall window) escalates
//!   identically to [`MediaError::Stalled`];
//! - **resource limits** (unix): RLIMIT_AS 512 MiB (ffprobe
//!   256 MiB) + RLIMIT_CPU 3600 s + niceness 19, in force before any
//!   ffmpeg code runs.
//!
//! ## Limit mechanism deviation on the record (unsafe_code = forbid)
//!
//! The product spec names `pre_exec` for the limits. std's
//! `CommandExt::pre_exec` is `unsafe` (async-signal-safety contract),
//! and this workspace forbids `unsafe` outright (CONTRIBUTING: platform
//! APIs go through safe wrappers; no safe wrapper exists in the
//! dependency graph). The limits are therefore applied by a **self-exec
//! shim** ([`crate::exec_shim`]): the child spawned here is this very
//! executable in shim mode, which applies the limits through safe
//! rustix calls and then spawns the real ffmpeg/ffprobe in the same
//! process group. The spec's property — limits in force before any ffmpeg
//! code runs, limits inherited by the media child — holds unchanged;
//! the cost is one intermediate process per spawn. Kill semantics stay
//! exact because the escalation signals the whole process group.
//!
//! **Windows**: RLIMIT_*/nice do not exist; resource-limit enforcement
//! there is
//! `-max_alloc` (caller argv) + the watchdog/cancel escalation only.
//! The shim is never spawned on Windows (direct spawn), documented in
//! the design notes.
//!
//! **macOS note**: `setrlimit(RLIMIT_AS, x)` is EINVAL for any x (the
//! kernel neither sets nor enforces it — verified 2026-10-27); the
//! shim tolerates exactly that refusal with a stderr note, so the
//! posture degrades to RLIMIT_CPU + `-max_alloc` there. Linux sets and
//! enforces both, and stays fail-closed.
//!
//! Completion polling: [`MediaChild::wait`] polls `try_wait` on a
//! sleep tick instead of selecting over the `wait()` future — the
//! escalation arms need the child handle, and a select arm holding the
//! borrowed wait future would pin it (the standard ownership knot).
//! The 25 ms tick bounds exit/escalation latency and keeps every arm
//! borrow-free.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::error::MediaError;
use crate::progress::{ProgressParser, ProgressSnapshot, snapshot_advances};

/// SIGTERM grace before SIGKILL in the escalation ladder
/// (SIGTERM(5s) → SIGKILL).
const TERM_GRACE: Duration = Duration::from_secs(5);

/// Completion/watchdog poll tick.
const POLL_TICK: Duration = Duration::from_millis(25);

/// Default stall window (frame/total_size static for 300s
/// -> `ffmpeg_stalled`).
pub const DEFAULT_STALL_TIMEOUT: Duration = Duration::from_secs(300);

/// The product spec's `-max_alloc` value as a byte count. NOTE: the
/// spec text spells
/// the flag value `512M`; ffmpeg 9's `-max_alloc` takes a plain byte
/// count and rejects `512M` (verified against 9.0.2) — argv producers
/// must use this constant's decimal form. Recorded as a spec-text
/// deviation for the unified wiring step.
pub const MAX_ALLOC_BYTES: u64 = 512 * 1024 * 1024;

/// Stderr capture cap (bytes — bounded capture, excerpted
/// into errors; the redaction face is wired when the logging faces
/// consume this).
const STDERR_CAP: usize = 1024 * 1024;

/// Captured-stdout cap (bytes; `-demuxers` listings are tens of KiB —
/// 4 MiB bounds any pathological listing).
const STDOUT_CAP: usize = 4 * 1024 * 1024;

/// Read-chunk size for the pipe readers.
const READ_CHUNK: usize = 8 * 1024;

/// Resource-limit profile per binary kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// RLIMIT_AS bytes (None = leave inherited).
    pub address_space: Option<u64>,
    /// RLIMIT_CPU seconds.
    pub cpu_seconds: u64,
}

/// ffmpeg profile: RLIMIT_AS 512 MiB / RLIMIT_CPU 3600 s.
pub const FFMPEG_LIMITS: ResourceLimits = ResourceLimits {
    address_space: Some(512 * 1024 * 1024),
    cpu_seconds: 3600,
};

/// ffprobe profile: RLIMIT_AS 256 MiB / RLIMIT_CPU 3600 s (the
/// "same profile as ffprobe" ruling with the 256 MiB address space).
pub const FFPROBE_LIMITS: ResourceLimits = ResourceLimits {
    address_space: Some(256 * 1024 * 1024),
    cpu_seconds: 3600,
};

/// Which binary a command addresses (limits profile + error text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaBin {
    /// ffmpeg.
    Ffmpeg,
    /// ffprobe.
    Ffprobe,
}

impl MediaBin {
    /// Fixed binary name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ffmpeg => "ffmpeg",
            Self::Ffprobe => "ffprobe",
        }
    }

    /// Resource limits profile.
    pub fn limits(self) -> ResourceLimits {
        match self {
            Self::Ffmpeg => FFMPEG_LIMITS,
            Self::Ffprobe => FFPROBE_LIMITS,
        }
    }
}

/// How the piped stdout is consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdoutMode {
    /// Raw bytes (query commands: `-version`, `-demuxers`, ffprobe
    /// JSON).
    Capture,
    /// `-progress pipe:1` line protocol (long-running ffmpeg jobs).
    Progress,
}

/// Completed child output (the process ran to an exit; check
/// [`MediaOutput::success`] or convert with [`MediaOutput::into_ok`]).
#[derive(Debug, Clone)]
pub struct MediaOutput {
    /// Exit code (None = terminated by signal).
    pub code: Option<i32>,
    /// code == 0.
    pub success: bool,
    /// Captured stdout (Capture mode; empty in Progress mode).
    pub stdout: Vec<u8>,
    /// All progress snapshots in emission order (Progress mode; empty
    /// in Capture mode).
    pub snapshots: Vec<ProgressSnapshot>,
    /// Final snapshot (Progress mode).
    pub last_snapshot: Option<ProgressSnapshot>,
    /// Captured stderr (byte-capped).
    pub stderr: Vec<u8>,
}

impl MediaOutput {
    /// Convert a completed run into `Err(Exit)` unless it succeeded
    /// (nonzero exits carry a trailing-stderr excerpt).
    pub fn into_ok(self) -> Result<Self, MediaError> {
        if self.success {
            return Ok(self);
        }
        let excerpt = stderr_excerpt(&self.stderr, 2048);
        Err(MediaError::Exit(format!(
            "exit code {:?}: {excerpt}",
            self.code
        )))
    }
}

/// Lossy trailing excerpt of a stderr buffer.
fn stderr_excerpt(stderr: &[u8], max: usize) -> String {
    let start = stderr.len().saturating_sub(max);
    String::from_utf8_lossy(&stderr[start..]).into_owned()
}

/// Escalation ladder for one live child: TERM the process group (unix)
/// / TerminateProcess (windows), wait out the grace via `try_wait`,
/// then KILL. Signals target the group so the media grandchild dies
/// with the shim (module docs).
async fn terminate_escalation(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // The shim is a process-group leader (process_group(0) at
        // spawn); the media grandchild shares the group. If the
        // setpgid has not landed yet (fork/exec race), the KILL arm
        // below is the fallback.
        if let Some(raw) = rustix::process::Pid::from_raw(pid as i32) {
            let _ = rustix::process::kill_process_group(raw, rustix::process::Signal::TERM);
        }
    }
    #[cfg(windows)]
    let _ = child.start_kill();
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => tokio::time::sleep(POLL_TICK).await,
            Err(_) => break,
        }
    }
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        if let Some(raw) = rustix::process::Pid::from_raw(pid as i32) {
            let _ = rustix::process::kill_process_group(raw, rustix::process::Signal::KILL);
        }
    }
    // Belt to the group kill: tokio's direct-child KILL (also the only
    // arm on windows).
    let _ = child.start_kill();
}

/// A spawned media child: piped trio wired, readers armed, escalation
/// on drop guaranteed.
#[derive(Debug)]
pub struct MediaChild {
    child: Option<Child>,
    stdout_task: Option<tokio::task::JoinHandle<()>>,
    stderr_task: Option<tokio::task::JoinHandle<()>>,
    stdout_mode: StdoutMode,
    token: CancellationToken,
    stall_timeout: Option<Duration>,
    stdout_capture: Arc<Mutex<Vec<u8>>>,
    snapshots: Arc<Mutex<Vec<ProgressSnapshot>>>,
    stderr_capture: Arc<Mutex<Vec<u8>>>,
    progress_tx: Option<watch::Sender<ProgressSnapshot>>,
    last_advance: Arc<Mutex<Instant>>,
}

impl Drop for MediaChild {
    fn drop(&mut self) {
        // Sync last-ditch (no await in Drop): KILL the group first —
        // covers the media grandchild — then the direct child; tokio's
        // kill_on_drop also fires on the field drop right after.
        if let Some(child) = self.child.as_mut() {
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                if let Some(raw) = rustix::process::Pid::from_raw(pid as i32) {
                    let _ = rustix::process::kill_process_group(raw, rustix::process::Signal::KILL);
                }
            }
            let _ = child.start_kill();
        }
    }
}

impl MediaChild {
    /// Live subscription to the newest progress snapshot (Progress
    /// mode; `None` in Capture mode). Updated at each `progress=`
    /// flush.
    pub fn progress_subscription(&self) -> Option<watch::Receiver<ProgressSnapshot>> {
        self.progress_tx.as_ref().map(|tx| tx.subscribe())
    }

    /// Await completion. Returns [`MediaOutput`] for any *completed*
    /// run (success flag inside; use [`MediaOutput::into_ok`] for the
    /// error-converting form); `Err` for cancellation
    /// ([`MediaError::Cancelled`]) and watchdog expiry
    /// ([`MediaError::Stalled`]) after the escalation ladder ran.
    pub async fn wait(mut self) -> Result<MediaOutput, MediaError> {
        let started = Instant::now();
        // Stall accounting starts at spawn: silence from the first
        // block counts toward the window (the spec reads the window
        // over progress advance; a never-advancing child is the
        // extreme stall).
        *self.last_advance.lock().unwrap_or_else(|e| e.into_inner()) = started;
        let stall_timeout = self.stall_timeout;

        let child = match self.child.as_mut() {
            Some(c) => c,
            None => return Err(MediaError::Spawn("child already consumed".to_string())),
        };
        let status = loop {
            match child.try_wait() {
                // try_wait errors are ECHILD-shaped (already reaped) —
                // surfaced as an explicit spawn error, never a hang.
                Err(e) => {
                    self.finish_readers().await;
                    return Err(MediaError::Spawn(format!("try_wait: {e}")));
                }
                Ok(Some(status)) => break status,
                Ok(None) => {}
            }
            if self.token.is_cancelled() {
                terminate_escalation(child).await;
                self.finish_readers().await;
                return Err(MediaError::Cancelled);
            }
            if self.stdout_mode == StdoutMode::Progress {
                if let Some(timeout) = stall_timeout {
                    let last = *self.last_advance.lock().unwrap_or_else(|e| e.into_inner());
                    if started.elapsed() >= timeout && last.elapsed() >= timeout {
                        terminate_escalation(child).await;
                        self.finish_readers().await;
                        return Err(MediaError::Stalled(format!(
                            "no frame/total_size advance within {timeout:?}"
                        )));
                    }
                }
            }
            tokio::time::sleep(POLL_TICK).await;
        };
        let code = status.code();
        let success = status.success();
        // Pipes drain to EOF after exit; the readers finish on their
        // own and get joined here.
        self.finish_readers().await;
        let stdout = match self.stdout_mode {
            StdoutMode::Capture => std::mem::take(
                &mut *self
                    .stdout_capture
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()),
            ),
            StdoutMode::Progress => Vec::new(),
        };
        let snapshots =
            std::mem::take(&mut *self.snapshots.lock().unwrap_or_else(|e| e.into_inner()));
        let last_snapshot = snapshots.last().cloned();
        let stderr = std::mem::take(
            &mut *self
                .stderr_capture
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        Ok(MediaOutput {
            code,
            success,
            stdout,
            snapshots,
            last_snapshot,
            stderr,
        })
    }

    /// Join the pipe readers (drains the tasks; buffers stay in the
    /// shared Arcs).
    async fn finish_readers(&mut self) {
        if let Some(task) = self.stdout_task.take() {
            let _ = task.await;
        }
        if let Some(task) = self.stderr_task.take() {
            let _ = task.await;
        }
    }
}

/// Append bytes under a cap (drop beyond the cap — bounded capture).
fn capped_extend(buf: &mut Vec<u8>, chunk: &[u8], cap: usize) {
    let room = cap.saturating_sub(buf.len());
    if room > 0 {
        buf.extend_from_slice(&chunk[..room.min(chunk.len())]);
    }
}

/// Stdout reader task body: capture mode (raw bytes) or progress mode
/// (line protocol → snapshots, watch feed, stall-advance ticks).
async fn read_stdout(
    mut reader: tokio::process::ChildStdout,
    mode: StdoutMode,
    capture: Arc<Mutex<Vec<u8>>>,
    snapshots: Arc<Mutex<Vec<ProgressSnapshot>>>,
    progress_tx: Option<watch::Sender<ProgressSnapshot>>,
    last_advance: Arc<Mutex<Instant>>,
) {
    let mut parser = ProgressParser::new();
    let mut prev = ProgressSnapshot::default();
    let mut buf = [0u8; READ_CHUNK];
    let mut record = |snaps: Vec<ProgressSnapshot>| {
        for snap in snaps {
            if snapshot_advances(&prev, &snap) {
                *last_advance.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            }
            if let Some(tx) = progress_tx.as_ref() {
                let _ = tx.send(snap.clone());
            }
            snapshots
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(snap.clone());
            prev = snap;
        }
    };
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => match mode {
                StdoutMode::Capture => capped_extend(
                    &mut capture.lock().unwrap_or_else(|e| e.into_inner()),
                    &buf[..n],
                    STDOUT_CAP,
                ),
                StdoutMode::Progress => record(parser.feed(&buf[..n])),
            },
        }
    }
    if mode == StdoutMode::Progress {
        record(parser.finish());
    }
}

/// Stderr reader task body (capped capture).
async fn read_stderr(mut reader: tokio::process::ChildStderr, capture: Arc<Mutex<Vec<u8>>>) {
    let mut buf = [0u8; READ_CHUNK];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => capped_extend(
                &mut capture.lock().unwrap_or_else(|e| e.into_inner()),
                &buf[..n],
                STDERR_CAP,
            ),
        }
    }
}

/// Builder for one media child invocation (argv-array face; see the
/// module docs for the full contract).
#[derive(Debug, Clone)]
pub struct MediaCommand {
    bin: MediaBin,
    program: PathBuf,
    args: Vec<OsString>,
    format_seen: bool,
    stdout_mode: StdoutMode,
    stall_timeout: Option<Duration>,
    token: Option<CancellationToken>,
    /// Shim-program override (None = `current_exe()`, the production
    /// default — the host `main` routes the marker argv to
    /// [`crate::exec_shim`]). Test drivers whose `current_exe` is a
    /// libtest harness point this at the `taiji-media-shim` helper
    /// binary; embedders with the same constraint do the same.
    shim_program: Option<PathBuf>,
}

impl MediaCommand {
    /// New command for a resolved absolute binary path (discovery
    /// output; a non-absolute path is refused).
    pub fn new(bin: MediaBin, program: impl AsRef<Path>) -> Result<Self, MediaError> {
        let program = program.as_ref();
        if !program.is_absolute() {
            return Err(MediaError::NotAbsolute(program.display().to_string()));
        }
        Ok(Self {
            bin,
            program: program.to_path_buf(),
            args: Vec::new(),
            format_seen: false,
            stdout_mode: StdoutMode::Capture,
            stall_timeout: None,
            token: None,
            shim_program: None,
        })
    }

    /// Override the exec-shim host program (see the field doc / module
    /// docs). Production callers leave the default.
    pub fn shim_program(mut self, path: Option<PathBuf>) -> Self {
        self.shim_program = path;
        self
    }

    /// Append one raw argument (no shell; OsString verbatim).
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_os_string());
        self
    }

    /// Append several raw arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    /// Record the explicit output format (`-f <fmt>`); enables
    /// [`Self::output`].
    pub fn format(mut self, fmt: impl AsRef<str>) -> Self {
        self.args.push(OsString::from("-f"));
        self.args.push(OsString::from(fmt.as_ref()));
        self.format_seen = true;
        self
    }

    /// Append an output path. Requires a prior [`Self::format`] (the
    /// explicit `-f` contract), an absolute path, and refuses a leading
    /// `-` in the filename (option-injection guard, per the
    /// product spec).
    pub fn output(mut self, path: impl AsRef<Path>) -> Result<Self, MediaError> {
        let path = path.as_ref();
        if !self.format_seen {
            return Err(MediaError::MissingFormat(path.display().to_string()));
        }
        if !path.is_absolute() {
            return Err(MediaError::NotAbsolute(path.display().to_string()));
        }
        let name_ok = path
            .file_name()
            .is_some_and(|n| !n.to_string_lossy().starts_with('-'));
        if !name_ok {
            return Err(MediaError::NotAbsolute(format!(
                "output filename rejects a leading '-': {}",
                path.display()
            )));
        }
        self.args.push(path.as_os_str().to_os_string());
        Ok(self)
    }

    /// Consume stdout as `-progress pipe:1` line protocol (snapshots +
    /// watchdog feed). `stall_timeout` arms the watchdog; `None` keeps
    /// it off (short jobs).
    pub fn stdout_progress(mut self, stall_timeout: Option<Duration>) -> Self {
        self.stdout_mode = StdoutMode::Progress;
        self.stall_timeout = stall_timeout;
        self
    }

    /// Caller-owned cancellation token (cancelled = escalation ladder +
    /// `Err(Cancelled)`).
    pub fn cancellation(mut self, token: CancellationToken) -> Self {
        self.token = Some(token);
        self
    }

    /// The argv this command will run (introspection/test face; the
    /// shim prefix is not part of it).
    pub fn argv(&self) -> Vec<OsString> {
        let mut v = vec![self.program.as_os_str().to_os_string()];
        v.extend(self.args.iter().cloned());
        v
    }

    /// Spawn. Piped trio, `kill_on_drop`, resource limits per [`MediaBin`]
    /// (unix: via the self-exec shim, module docs; windows: direct
    /// spawn, limits N/A by platform — the Windows note).
    pub fn spawn(self) -> Result<MediaChild, MediaError> {
        let token = self.token.unwrap_or_default();
        let limits = self.bin.limits();
        let mut command = build_command(
            &self.program,
            &self.args,
            limits,
            self.shim_program.as_deref(),
        )?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command
            .spawn()
            .map_err(|e| MediaError::Spawn(format!("{} {e}", self.bin.name())))?;
        // Pipe trio: stdin's write end drops here (EOF upstream; argv
        // carries -nostdin as the belt).
        drop(child.stdin.take());
        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();

        let stdout_capture = Arc::new(Mutex::new(Vec::new()));
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let stderr_capture = Arc::new(Mutex::new(Vec::new()));
        let last_advance = Arc::new(Mutex::new(Instant::now()));
        let progress_tx = (self.stdout_mode == StdoutMode::Progress).then(|| {
            let (tx, _rx) = watch::channel(ProgressSnapshot::default());
            tx
        });

        let stdout_task = stdout_handle.map(|reader| {
            let mode = self.stdout_mode;
            let capture = Arc::clone(&stdout_capture);
            let snaps = Arc::clone(&snapshots);
            let advance = Arc::clone(&last_advance);
            let tx = progress_tx.clone();
            tokio::spawn(async move {
                read_stdout(reader, mode, capture, snaps, tx, advance).await;
            })
        });
        let stderr_task = stderr_handle.map(|reader| {
            let sink = Arc::clone(&stderr_capture);
            tokio::spawn(async move {
                read_stderr(reader, sink).await;
            })
        });

        Ok(MediaChild {
            child: Some(child),
            stdout_task,
            stderr_task,
            stdout_mode: self.stdout_mode,
            token,
            stall_timeout: self.stall_timeout,
            stdout_capture,
            snapshots,
            stderr_capture,
            progress_tx,
            last_advance,
        })
    }
}

/// Build the tokio command for one invocation: unix = self-exec shim
/// argv + limits env; windows = direct argv (limits N/A, card's
/// Windows note).
fn build_command(
    program: &Path,
    args: &[OsString],
    limits: ResourceLimits,
    shim_override: Option<&Path>,
) -> Result<Command, MediaError> {
    #[cfg(unix)]
    {
        let exe = match shim_override {
            Some(path) => path.to_path_buf(),
            None => std::env::current_exe()
                .map_err(|e| MediaError::Spawn(format!("current_exe for the exec shim: {e}")))?,
        };
        let mut command = Command::new(exe);
        command.arg(crate::exec_shim::SHIM_ARG);
        command.arg(program);
        command.args(args);
        command.env(crate::exec_shim::ENV_GUARD, "1");
        if let Some(as_bytes) = limits.address_space {
            command.env(crate::exec_shim::ENV_RLIMIT_AS, as_bytes.to_string());
        }
        command.env(
            crate::exec_shim::ENV_RLIMIT_CPU,
            limits.cpu_seconds.to_string(),
        );
        // tokio::process::Command carries its own unix `process_group`
        // (leader = shim; the media grandchild joins the group so the
        // escalation ladder's group signals reach both).
        command.process_group(0);
        Ok(command)
    }
    #[cfg(windows)]
    {
        let mut command = Command::new(program);
        command.args(args);
        Ok(command)
    }
}

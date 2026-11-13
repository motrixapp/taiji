//! The `.part` on-disk surface: positional writes + preallocation + a
//! handle-closing guard before rename.
//!
//! Production disk writes belong to the core-injected `SegmentSink`
//! (the store disk layer); this module owns the HTTP-side task-file
//! lifecycle — the part decoupled from disk writes and coupled with the
//! rename orchestration: the open policy ([`PartOpenPolicy`]:
//! degraded/length mismatch -> truncate from zero, length match ->
//! resume), `--file-allocation` prealloc via a trunc-semantics
//! `set_len` ([`FileAllocation`]), `write_all_at` positional writes
//! (blocking calls always in `spawn_blocking`), and [`PartFile::close`]
//! which releases the OS handle and yields the [`HandlesClosed`]
//! credential that finalize requires (type as proof: no rename with
//! handles still open — Windows/SMB handle-sharing and oplock
//! constraints).
//!
//! Concurrency: positional writes use no shared cursor (`&self`
//! semantics), so concurrent multi-worker writes to one task file are
//! legal (same-block double writes are backstopped by the single-point
//! accounting); `close` must run after all in-flight writes complete
//! (the worker set is joined first) and writes after close fail
//! immediately (defensive); same-path concurrent opens are arbitrated
//! by the in-process claim table ([`PartFile::open`] claims; the second
//! open gets `taiji.http.path_conflict`).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use bytes::Bytes;
use futures::future::BoxFuture;

use crate::error::HttpError;
/// The `O_NOFOLLOW` platform constants (same values as taiji-store
/// `disk.rs` — the raw fcntl.h value per platform; std does not export
/// them and taiji-http has no rustix dependency).
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100; // Darwin sys/fcntl.h
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
const O_NOFOLLOW: i32 = 0o400000; // Linux/Android asm-generic/fcntl.h
#[cfg(not(unix))]
const O_NOFOLLOW: i32 = 0;

/// unix `custom_flags(O_NOFOLLOW)` wiring (a no-op off unix).
#[cfg(unix)]
fn apply_nofollow(opts: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.custom_flags(O_NOFOLLOW);
}

#[cfg(not(unix))]
fn apply_nofollow(_opts: &mut OpenOptions) {}

use crate::traits::SegId;
use crate::traits::SegmentSink;

/// The `.part` in-process claim table: arbitrates same-path task races
/// within a session — `PartFile::open` claims atomically
/// (Mutex-serialized; the TOCTOU between a plan_output existence check
/// and the actual open no longer admits co-writers), released on close
/// or last-handle drop. Cross-process mutual exclusion is out of scope
/// (the session model is one process, one writer; aria2's file lock is
/// the cross-process face).
fn part_claims() -> &'static Mutex<HashSet<PathBuf>> {
    static CLAIMS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    CLAIMS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Claim (atomic): already held by an in-flight task ->
/// `taiji.http.path_conflict`.
fn claim_part(path: &Path) -> Result<(), HttpError> {
    let mut claims = crate::lock(part_claims());
    if !claims.insert(path.to_path_buf()) {
        return Err(HttpError::PathConflict);
    }
    Ok(())
}

/// Release the claim (first of close vs last-handle drop wins;
/// idempotent).
fn release_part(path: &Path) {
    let mut claims = crate::lock(part_claims());
    claims.remove(path);
}

/// Query whether the `.part` claim is held (the test assertion face:
/// the claim must not release while writes are in flight — probes the
/// registry directly instead of asserting through open side effects).
pub fn part_claim_held(path: &Path) -> bool {
    crate::lock(part_claims()).contains(path)
}

/// The blocking-face gate (a test seam; compiled only under
/// `cfg(test)`): per-path entered/finished/hold state — a test holds
/// the gate to suspend a blocking body before it executes, pinning the
/// in-flight write window deterministically (no reliance on large
/// buffers or real delays). With no registered key (never held),
/// enter/note are no-ops: existing tests' spawn_blocking paths behave
/// identically.
#[cfg(test)]
pub(crate) mod io_gate {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Condvar, Mutex, OnceLock};

    #[derive(Default)]
    struct State {
        entered: u32,
        finished: u32,
        hold: bool,
    }

    fn gates() -> &'static (Mutex<HashMap<PathBuf, State>>, Condvar) {
        static G: OnceLock<(Mutex<HashMap<PathBuf, State>>, Condvar)> = OnceLock::new();
        G.get_or_init(|| (Mutex::new(HashMap::new()), Condvar::new()))
    }

    /// Register and suspend the next (and subsequent) blocking body for
    /// the key.
    pub(crate) fn hold(key: &Path) {
        let (m, _) = gates();
        m.lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_path_buf())
            .or_default()
            .hold = true;
    }

    /// Blocking-body entry: record the entry; wait for release while
    /// held (blocking inside the blocking thread is legitimate).
    pub(crate) fn enter(key: &Path) {
        let (m, c) = gates();
        let mut g = m.lock().unwrap_or_else(|e| e.into_inner());
        let mut registered = false;
        loop {
            let s = g.entry(key.to_path_buf()).or_default();
            if !registered {
                s.entered += 1;
                registered = true;
                c.notify_all();
            }
            if !s.hold {
                return;
            }
            g = c.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Blocking-body exit: record completion.
    pub(crate) fn note(key: &Path) {
        let (m, c) = gates();
        m.lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_path_buf())
            .or_default()
            .finished += 1;
        c.notify_all();
    }

    /// Release a held key.
    pub(crate) fn release(key: &Path) {
        let (m, c) = gates();
        m.lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_path_buf())
            .or_default()
            .hold = false;
        c.notify_all();
    }

    /// Wait until entered reaches n (bounded 5s; async polling — under
    /// a current_thread test runtime a synchronous condvar wait would
    /// starve the task under observation, so poll + sleep yields the
    /// runtime thread). The event is guaranteed to arrive (the blocking
    /// body must run); polling affects only observation latency, not
    /// assertion semantics.
    pub(crate) async fn wait_entered(key: &Path, n: u32) {
        wait_pred(key, |s| s.entered >= n, "entered").await;
    }

    /// Wait until finished reaches n (bounded 5s; async polling as
    /// above).
    pub(crate) async fn wait_finished(key: &Path, n: u32) {
        wait_pred(key, |s| s.finished >= n, "finished").await;
    }

    async fn wait_pred(key: &Path, pred: impl Fn(&State) -> bool, what: &str) {
        let (m, _) = gates();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            {
                let g = m.lock().unwrap_or_else(|e| e.into_inner());
                if pred(g.get(key).unwrap_or(&State::default())) {
                    return;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "io_gate wait {what} timeout for {}",
                key.display()
            );
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    /// Remove a key's state (test cleanup hygiene, guards against
    /// cross-key reuse).
    pub(crate) fn remove(key: &Path) {
        let (m, _) = gates();
        m.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    }

    /// Guard that releases the gate even when an assertion fails
    /// (unwind): a suspended blocking body never released would hang
    /// the runtime drop waiting for the blocking pool to wind down —
    /// the test process must be able to exit after a failing-test panic
    /// (the failure evidence is the panic text).
    pub(crate) struct Releaser(std::path::PathBuf);

    impl Releaser {
        pub(crate) fn new(key: &Path) -> Self {
            Releaser(key.to_path_buf())
        }
    }

    impl Drop for Releaser {
        fn drop(&mut self) {
            release(&self.0);
        }
    }
}

/// Release the `.part` claim (idempotent): called by the finalize
/// close-out ([`crate::finalize`]) and the polling close-out once the
/// rename settles — the part-half release point of the claim domain;
/// core-side teardown backstops (task-removal races) reuse the same
/// face.
pub fn release_part_claim(path: &Path) {
    release_part(path);
}

/// The final-path in-process claim table (the [`part_claims`]
/// counterpart): `final path -> holder key (task gid)`. The claim spans
/// the task lifetime — taken when [`crate::naming::plan_output`] decides
/// the output name, released when the rename settles (the
/// [`crate::finalize`] close-out) or the task is removed; held across
/// the close->rename window and renamePending polling. Holder-key
/// semantics:
/// - same-key re-claim is idempotent: task reactivation (pause->resume
///   reruns plan_output) and cross-round poll re-claims do not
///   self-reject;
/// - a different holder gets `taiji.http.path_conflict` — the final
///   path is a task's exclusive output domain, and per-task incomplete
///   suffixes do not isolate (tasks A `.a` and B `.b` with the same
///   dir/out would both pass, and finalize's posix rename would
///   atomically overwrite, the later finisher silently swallowing the
///   earlier final file).
///
/// Hostile cross-process writers remain the registered existing
/// boundary (the session model is one process, one writer).
fn final_claims() -> &'static Mutex<std::collections::HashMap<PathBuf, String>> {
    static CLAIMS: OnceLock<Mutex<std::collections::HashMap<PathBuf, String>>> = OnceLock::new();
    CLAIMS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Claim the final path (atomic): held by another task ->
/// `taiji.http.path_conflict`; self-held or free -> success (idempotent
/// same-key re-entry).
pub fn claim_final_path(path: &Path, holder: &str) -> Result<(), HttpError> {
    let mut claims = crate::lock(final_claims());
    match claims.get(path) {
        Some(h) if h != holder => Err(HttpError::PathConflict),
        _ => {
            claims.insert(path.to_path_buf(), holder.to_string());
            Ok(())
        }
    }
}

/// Release the final path (removes only on a key match — never deletes
/// another holder's claim; idempotent).
pub fn release_final_path(path: &Path, holder: &str) {
    let mut claims = crate::lock(final_claims());
    if claims.get(path).is_some_and(|h| h == holder) {
        claims.remove(path);
    }
}

/// Release **all** final-path claims of a holder (clears the task's own
/// stale claims before a re-run; idempotent): a gid drives at most once
/// at a time (actor-serial activation), so key-scoped release touches
/// only this task's own claims — including claims moved to auto-rename
/// history candidates whose paths no longer appear in the row facts.
pub fn release_all_final_claims(holder: &str) {
    crate::lock(final_claims()).retain(|_, h| h != holder);
}

/// Whether another task holds the final path (the predicate for the
/// plan_output conflict face and the renamePending polling close-out
/// guard).
pub fn final_path_held_by_other(path: &Path, holder: &str) -> bool {
    crate::lock(final_claims())
        .get(path)
        .is_some_and(|h| h != holder)
}

/// The `--file-allocation` surface (default prealloc).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileAllocation {
    /// No preallocation (`--file-allocation=none`).
    None,
    /// Preallocate (`--file-allocation=prealloc`, default): `set_len`
    /// at open (trunc semantics — aria2 prealloc's platform fallback
    /// path; the fallocate fast path is carried by the core-injected
    /// store disk-layer sink).
    #[default]
    Prealloc,
}

/// The `.part` open policy (the execution face of the reuse decision;
/// the decision lives in [`crate::naming::decide_part_reuse`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartOpenPolicy {
    /// Truncate from zero: degraded (no bitmap — recovery always
    /// restarts) or length mismatch (the caller clears the bitmap).
    Restart,
    /// Keep existing bytes and resume (length matches; positional
    /// writes advance).
    Resume,
}

/// The closed-handle credential: the sole product of
/// [`PartFile::close`] — finalize takes it as its argument, a
/// type-level guarantee of "close handles before rename". The
/// credential also carries ownership of the `.part` claim: close
/// **transfers** the claim rather than releasing it, moving the release
/// point to rename settlement (the finalize close-out) — during the
/// close->rename window (journal round-trip + probe + backoff retries)
/// no new task may enter the same `.part` via [`PartFile::open`]. A
/// credential dropped without reaching close-out (teardown/cancel paths
/// discarding `part.close()`) releases the claim immediately (the Drop
/// backstop; no permanent in-process conflict); the renamePending shape
/// keeps it via [`Self::hold_for_pending`].
#[derive(Debug)]
pub struct HandlesClosed {
    /// The `.part` claim path transferred in by close (`None` = a test
    /// credential / already disposed by close-out).
    part_claim: Option<PathBuf>,
    /// Write barrier: the in-flight-writes-drained wait before the
    /// credential's Drop releases the claim (a defensive backstop for a
    /// discipline-violating close; `None` = a test credential).
    writes: Option<Arc<PartInner>>,
}

impl HandlesClosed {
    /// Test-only credential (bypasses the real handle lifecycle;
    /// visible only under `cfg(test)` — the sole production channel is
    /// [`PartFile::close`]).
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        HandlesClosed {
            part_claim: None,
            writes: None,
        }
    }

    /// Transfer to pending bookkeeping (renamePending): the `.part`
    /// claim stays held by the renamePending polling bookkeeping
    /// (released through the finalize close-out on success); Drop no
    /// longer releases it. The registry entry stays in place (release
    /// is an explicit action, not a Drop side effect).
    pub fn hold_for_pending(self) {
        // Consume the credential: `part_claim` is discarded in place
        // (the registry is untouched) — the claim stays in the
        // `part_claims` table, released by the polling close-out
        // (`retry_pending`'s complete face) or the task-removal path.
        let _ = self.part_claim;
    }
}

impl Drop for HandlesClosed {
    fn drop(&mut self) {
        // Dropped without reaching close-out (teardown, cancel, or
        // journal write failure): release the claim — aligned with the
        // old close-releases-now semantics, failures leave no conflict
        // behind.
        if let Some(p) = self.part_claim.take() {
            // Defensive: the close discipline is call-after-write-join;
            // on a violating close, releasing with pwrites still in
            // flight would reopen the "stale write landing after
            // truncate" window — wait bounded for the drain, warn and
            // give up on timeout (liveness first).
            if let Some(inner) = self.writes.as_ref()
                && !inner.wait_writes_drained()
            {
                tracing::warn!(
                    target: "taiji::http::partfile",
                    path = %p.display(),
                    "part claim released with in-flight writes (close-before-drain)"
                );
            }
            release_part(&p);
        }
    }
}

/// Upper bound for the in-flight write drain wait (the close-violation
/// defense): pwrites are bounded small writes (block-level buffers,
/// page-cache milliseconds); spin+yield with a bounded wait; on timeout
/// warn and give up — liveness of claim release wins (a permanent
/// path_conflict hurts more than a narrow race).
const WRITE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Debug)]
struct PartInner {
    file: Mutex<Option<Arc<File>>>,
    /// Claim-table ownership ([`part_claims`]): `Some(path)` = this
    /// handle family holds the claim; whoever of close vs last-handle
    /// drop gets there first takes and releases it.
    claim: Mutex<Option<PathBuf>>,
    /// In-flight positional-write count: incremented synchronously
    /// before `spawn_blocking`, decremented by the [`WriteTicket`]
    /// guard's Drop inside the blocking body (panics included). The
    /// guard also holds `Arc<PartInner>` — the handle family cannot be
    /// destroyed while writes are in flight, so claim release
    /// ([`PartInner::drop`]) is structurally ordered after all in-flight
    /// writes by the Arc lifetime (no synchronous wait inside drop).
    /// Known boundary: a runtime shutdown discarding unstarted blocking
    /// tasks leaves the count nonzero (PartInner lives until process
    /// exit) — shutdown carries no claim semantics, so this is not a
    /// leak.
    inflight_writes: AtomicUsize,
}

impl PartInner {
    /// Bounded synchronous wait for the in-flight writes to drain (a
    /// close-violation backstop — discipline says close runs after the
    /// write join; this face is purely defensive). Returns false on
    /// timeout.
    fn wait_writes_drained(&self) -> bool {
        let deadline = Instant::now() + WRITE_DRAIN_TIMEOUT;
        while self.inflight_writes.load(Ordering::Acquire) > 0 {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }
}

/// In-flight write guard: holds `Arc<PartInner>` for the blocking
/// body's lifetime (keepalive — neither the handle family nor the claim
/// is destroyed before writes drain) and decrements the count (a single
/// Drop point).
struct WriteTicket {
    inner: Arc<PartInner>,
}

impl Drop for WriteTicket {
    fn drop(&mut self) {
        self.inner.inflight_writes.fetch_sub(1, Ordering::Release);
    }
}

/// The open-window claim guard: assembled after `claim_part` succeeds,
/// released on Drop — if the open future is abandoned during its await
/// (the real open/truncate runs in spawn_blocking; e.g. a forceRemove
/// abort), the release path inside the future is unreachable and the
/// guard prevents the claim from being held forever; on the success
/// path [`Self::disarm`] transfers it to [`PartInner`].
struct PartClaimGuard {
    path: Option<PathBuf>,
}

impl PartClaimGuard {
    fn new(path: PathBuf) -> Self {
        PartClaimGuard { path: Some(path) }
    }

    /// Transfer (success path): the claim moves to `PartInner`; the
    /// guard's Drop no longer releases.
    fn disarm(mut self) -> Option<PathBuf> {
        self.path.take()
    }
}

impl Drop for PartClaimGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            release_part(&p);
        }
    }
}

impl Drop for PartInner {
    fn drop(&mut self) {
        // The release face for an aborted task (no close): no permanent
        // in-process conflict. Invariant: reaching this drop means
        // every [`WriteTicket`] is gone (guards hold the Arc), so the
        // count is 0 — release is ordered after all in-flight writes.
        if let Some(p) = crate::lock(&self.claim).take() {
            release_part(&p);
        }
    }
}

/// Handle to a task's in-progress file (`<out><suffix>`; cheap to clone
/// — holds an `Arc`).
#[derive(Clone, Debug)]
pub struct PartFile {
    path: PathBuf,
    inner: Arc<PartInner>,
    /// The metrics registry (the feed seam for prealloc `set_len` /
    /// file fsync; defaults to the process instance, tests inject a
    /// separate one via [`Self::open_with_registry`] — no bare global
    /// counting).
    metrics: Arc<taiji_io::metrics::MetricsRegistry>,
}

impl PartFile {
    /// Open (or create) the in-progress file and place it per the
    /// policy. Parent directories are created as needed (aria2
    /// `createFile` mkdirs semantics, `AbstractDiskWriter.cc`).
    ///
    /// - claim: the in-process per-path table claims atomically — a
    ///   second open of the same path while the first task is in flight
    ///   gets `taiji.http.path_conflict` (the co-write/truncate race on
    ///   one `.part` closes at the open face); released when the rename
    ///   settles (close transfers -> finalize close-out) or on last-handle
    ///   drop / credential discard;
    /// - `Restart`: truncate to 0, then place per [`FileAllocation`];
    /// - `Resume`: keep existing bytes; grow to `total_len` when short
    ///   (grow-only, never shrink — shrinking belongs to the `Restart`
    ///   decision; the resume path never truncates existing progress).
    ///
    /// Blocking: internal `spawn_blocking`; errors are
    /// `taiji.http.disk` (claim conflicts excepted).
    pub async fn open(
        path: PathBuf,
        total_len: Option<u64>,
        policy: PartOpenPolicy,
        allocation: FileAllocation,
    ) -> Result<Self, HttpError> {
        Self::open_with_registry(
            path,
            total_len,
            policy,
            allocation,
            taiji_io::metrics::registry_default(),
        )
        .await
    }

    /// Open with an injected metrics registry (the test seam;
    /// production assembly goes through [`Self::open`]'s process
    /// default — the same injection pattern as
    /// [`crate::client::HttpClient`]).
    pub async fn open_with_registry(
        path: PathBuf,
        total_len: Option<u64>,
        policy: PartOpenPolicy,
        allocation: FileAllocation,
        metrics: Arc<taiji_io::metrics::MetricsRegistry>,
    ) -> Result<Self, HttpError> {
        claim_part(&path)?;
        // The claim guard backs the open window: if the future is
        // abandoned mid-await, the in-future release path is unreachable
        // and the guard's Drop releases; the success path disarms into
        // PartInner. Error paths (including a join panic) are covered by
        // the same guard.
        let claim = PartClaimGuard::new(path.clone());
        let p = path.clone();
        let opened = {
            let metrics = Arc::clone(&metrics);
            tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                io_gate::enter(&p);
                let r = Self::open_sync(&p, total_len, policy, allocation, &metrics);
                #[cfg(test)]
                io_gate::note(&p);
                r
            })
            .await
        };
        let file = match opened {
            Ok(Ok(file)) => file,
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(HttpError::Disk(format!(
                    "join open {}: {e}",
                    path.display()
                )));
            }
        };
        let claim = claim.disarm();
        Ok(PartFile {
            path: path.clone(),
            inner: Arc::new(PartInner {
                file: Mutex::new(Some(Arc::new(file))),
                claim: Mutex::new(claim),
                inflight_writes: AtomicUsize::new(0),
            }),
            metrics,
        })
    }

    fn open_sync(
        path: &Path,
        total_len: Option<u64>,
        policy: PartOpenPolicy,
        allocation: FileAllocation,
        metrics: &taiji_io::metrics::MetricsRegistry,
    ) -> Result<File, HttpError> {
        // The verbatim conversion right before the OS call (identity on
        // non-Windows; the `\\?\` long-path prefix on Windows). Error
        // messages always use the original path (no prefix on the
        // user-visible face).
        let fs_path = taiji_io::winpath::to_fs_path(path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(taiji_io::winpath::to_fs_path(parent))
                .map_err(|e| HttpError::Disk(format!("mkdirs {}: {e}", parent.display())))?;
        }
        // `O_NOFOLLOW` like the store create face — a symlink preset at
        // the `.part` path must not be followed (following + set_len =
        // truncating an arbitrary local file); ELOOP propagates, no
        // fallback.
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        apply_nofollow(&mut opts);
        let file = opts
            .open(&fs_path)
            .map_err(|e| HttpError::Disk(format!("open {}: {e}", path.display())))?;
        let current = file
            .metadata()
            .map_err(|e| HttpError::Disk(format!("stat {}: {e}", path.display())))?
            .len();
        let target = match (policy, total_len) {
            (PartOpenPolicy::Restart, _) => 0,
            // Grow-only: the resume path never truncates existing
            // progress.
            (PartOpenPolicy::Resume, Some(total)) if current < total => total,
            (PartOpenPolicy::Resume, _) => current,
        };
        if target != current {
            // Feed point (read-only timing, zero behavior change): the
            // trunc/prealloc `set_len` also counts into
            // `taiji_disk_prealloc_seconds` (one of the two open-time
            // prealloc sites: the resume growth).
            let t0 = std::time::Instant::now();
            let r = file
                .set_len(target)
                .map_err(|e| HttpError::Disk(format!("truncate {}: {e}", path.display())));
            metrics.disk().observe_prealloc(t0.elapsed());
            r?;
        }
        // Prealloc placement (the Restart form restoring total length
        // after truncation; Resume already covered by the growth face;
        // None untouched).
        if allocation == FileAllocation::Prealloc
            && let Some(total) = total_len
        {
            let len = file
                .metadata()
                .map_err(|e| HttpError::Disk(format!("stat {}: {e}", path.display())))?
                .len();
            if len < total {
                // Feed point (read-only timing): the explicit prealloc
                // `set_len` (the main `--file-allocation=prealloc`
                // site).
                let t0 = std::time::Instant::now();
                let r = file
                    .set_len(total)
                    .map_err(|e| HttpError::Disk(format!("prealloc {}: {e}", path.display())));
                metrics.disk().observe_prealloc(t0.elapsed());
                r?;
            }
        }
        Ok(file)
    }

    /// The in-progress file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Positional write (`off` = absolute byte offset in the file;
    /// loops over short writes/EINTR until fully written). Blocking
    /// work runs in `spawn_blocking`; closed -> `taiji.http.disk`.
    pub async fn write_all_at(&self, off: u64, bytes: Bytes) -> Result<(), HttpError> {
        let file = self.handle()?;
        // The in-flight registration precedes spawn_blocking
        // (synchronously, no await gap): if the write future is
        // abandoned at the join await (forceRemove abort/cancel), the
        // count is already up and the guard holds PartInner inside the
        // closure — claim release is ordered after the pwrite completes
        // (closing the truncate-after-release revival window).
        let inner = Arc::clone(&self.inner);
        inner.inflight_writes.fetch_add(1, Ordering::Release);
        #[cfg(test)]
        let gate_key = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let _ticket = WriteTicket { inner };
            #[cfg(test)]
            io_gate::enter(&gate_key);
            let r = pwrite_all(&file, &bytes, off);
            #[cfg(test)]
            io_gate::note(&gate_key);
            r
        })
        .await
        .map_err(|e| HttpError::Disk(format!("join write: {e}")))?
    }

    /// File fsync (data lands before the completion intent — the
    /// finalize precondition and the landing point of "the task file
    /// must fsync before the bitmap snapshot"). File fsync never enjoys
    /// the directory-fsync network-drive degradation contract.
    pub async fn sync_all(&self) -> Result<(), HttpError> {
        let file = self.handle()?;
        let path = self.path.clone();
        let metrics = Arc::clone(&self.metrics);
        tokio::task::spawn_blocking(move || {
            // Feed point (read-only timing):
            // `taiji_disk_finalize_seconds {op=file_fsync}` — the
            // per-file fsync of the EOF/degraded chains (see taiji-io
            // `FinalizeOp::FileFsync`).
            let t0 = std::time::Instant::now();
            let r = file
                .sync_all()
                .map_err(|e| HttpError::Disk(format!("fsync {path:?}: {e}")));
            metrics
                .disk()
                .observe_finalize(taiji_io::metrics::FinalizeOp::FileFsync, t0.elapsed());
            r
        })
        .await
        .map_err(|e| HttpError::Disk(format!("join fsync: {e}")))?
    }

    /// Close the OS handle and produce the finalize credential
    /// (idempotent: a repeat call returns a fresh credential and no
    /// longer holds a handle). Must run after all in-flight writes
    /// complete (the module docs' concurrency discipline);
    /// [`Self::write_all_at`] fails immediately after close. The
    /// `.part` claim is **transferred** into the credential, not
    /// released (the release point moves to rename settlement — the
    /// finalize close-out or credential discard; both dispositions in
    /// [`HandlesClosed`]).
    pub fn close(&self) -> HandlesClosed {
        // Take and drop: an unclosed write handle blocks rename on
        // Windows/SMB (where the close-handle constraint lands).
        let _ = crate::lock(&self.inner.file).take();
        // Take and transfer the claim (no release): PartInner's drop
        // face will not double-dispose (first one wins); the credential
        // Drop and the close-out disposition are the only release
        // faces.
        let part_claim = crate::lock(&self.inner.claim).take();
        // The write barrier rides the credential — the drained wait
        // before Drop releases the claim (close-violation defense; on
        // an idempotent repeat close the claim is already transferred
        // and the barrier idles).
        HandlesClosed {
            part_claim,
            writes: Some(Arc::clone(&self.inner)),
        }
    }

    fn handle(&self) -> Result<Arc<File>, HttpError> {
        crate::lock(&self.inner.file)
            .clone()
            .ok_or_else(|| HttpError::Disk(format!("part file closed: {}", self.path.display())))
    }
}

/// Positional write-to-completion (unix `write_all_at` has the built-in
/// short-write loop; Windows `seek_write` loops manually, retrying
/// `Interrupted` — same semantics as the store disk layer).
fn pwrite_all(file: &File, data: &[u8], off: u64) -> Result<(), HttpError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        file.write_all_at(data, off)
            .map_err(|e| HttpError::Disk(format!("write_all_at: {e}")))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt as _;
        let mut data = data;
        let mut off = off;
        while !data.is_empty() {
            match file.seek_write(data, off) {
                Ok(0) => {
                    return Err(HttpError::Disk(
                        "write_all_at: short write of 0 bytes".into(),
                    ));
                }
                Ok(n) => {
                    data = &data[n..];
                    off += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(HttpError::Disk(format!("seek_write: {e}"))),
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, data, off);
        Err(HttpError::Disk("write_all_at: unsupported platform".into()))
    }
}

/// The positional-write sink (this crate's reference implementation for
/// the degraded path and fixtures; production grid tasks get a
/// core-injected sink that owns bitmap persistence).
///
/// [`SegmentSink::complete_block`] is degenerate accounting here (no
/// bitmap, always `Ok`) — the block grid exists only for Range-domain
/// tasks; a single-connection degraded run builds none.
pub struct FileSink {
    part: PartFile,
}

impl FileSink {
    /// Wrap a task's in-progress file.
    pub fn new(part: PartFile) -> Self {
        FileSink { part }
    }

    /// The underlying task file (the fsync/close-handle/finalize
    /// orchestration face).
    pub fn part_file(&self) -> &PartFile {
        &self.part
    }
}

impl SegmentSink for FileSink {
    fn write_at(
        &self,
        _seg: SegId,
        off: u64,
        bytes: Bytes,
    ) -> BoxFuture<'_, crate::error::Result<()>> {
        Box::pin(self.part.write_all_at(off, bytes))
    }

    fn complete_block(&self, _block: u64) -> BoxFuture<'_, crate::error::Result<()>> {
        // The degraded form has no bitmap (a single connection builds
        // no grid); grid tasks get a core-injected accounting sink (the
        // sole bitmap-persistence entry is the coordinator decision
        // face).
        Box::pin(std::future::ready(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::naming::IncompleteSuffix;
    use crate::naming::part_path_for;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("taiji-http-pf-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
        path
    }

    fn wipe(p: &Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    /// Positional-write semantics: out-of-order interval writes converge
    /// to the correct file content; Prealloc places the total length;
    /// bytes are visible after fsync.
    #[tokio::test]
    async fn positioned_writes_assemble_file_and_prealloc() {
        let dir = tempdir("pos");
        let suffix = IncompleteSuffix::default();
        let final_path = dir.join("body.bin");
        let part_path = part_path_for(&final_path, &suffix);
        let part = PartFile::open(
            part_path.clone(),
            Some(16),
            PartOpenPolicy::Restart,
            FileAllocation::Prealloc,
        )
        .await
        .unwrap_or_else(|e| panic!("open: {e}"));

        // Prealloc: the file carries the total length right after open
        // (trunc semantics).
        let meta = std::fs::metadata(&part_path).unwrap_or_else(|e| panic!("meta: {e}"));
        assert_eq!(meta.len(), 16, "prealloc set_len lands the total length");

        let sink = FileSink::new(part.clone());
        let seg = SegId {
            source: 0,
            extent: 0,
        };
        // Out of order: the second half first, then the first half.
        sink.write_at(seg, 8, Bytes::from_static(b"HALF++++"))
            .await
            .unwrap_or_else(|e| panic!("write hi: {e}"));
        sink.write_at(seg, 0, Bytes::from_static(b"LOWFIRST"))
            .await
            .unwrap_or_else(|e| panic!("write lo: {e}"));
        sink.complete_block(0)
            .await
            .unwrap_or_else(|e| panic!("block: {e}"));

        part.sync_all()
            .await
            .unwrap_or_else(|e| panic!("fsync: {e}"));
        let bytes = std::fs::read(&part_path).unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(&bytes[..8], b"LOWFIRST");
        assert_eq!(&bytes[8..], b"HALF++++");

        // Closed-handle credential: writes fail immediately after close
        // (defensive). Teardown-shaped close: the credential is dropped
        // on the spot (the claim releases immediately — under the
        // close->finalize transfer semantics a credential bound to the
        // end of a statement would hold the claim until the end of
        // scope).
        drop(part.close());
        let res = sink.write_at(seg, 0, Bytes::from_static(b"zz")).await;
        // matches! matches by reference (HttpError is not Copy; avoids
        // a partial move in the assertion).
        assert!(
            matches!(&res, Err(e) if e.code() == "taiji.http.disk"),
            "writes after close must fail: {res:?}"
        );

        wipe(&dir);
    }

    /// Disk metric feed points: an injected standalone registry — the
    /// Prealloc open counts into `prealloc_seconds` (Restart's two
    /// sites: trunc + explicit prealloc), `sync_all` counts into
    /// `finalize_seconds{op=file_fsync}` (the per-file fsync feed of
    /// the EOF/degraded chains; the standalone instance stays
    /// unpolluted).
    #[tokio::test]
    async fn disk_metrics_feed_on_prealloc_and_sync_all() {
        use taiji_io::metrics::MetricsRegistry;

        let dir = tempdir("disk-metrics");
        let suffix = IncompleteSuffix::default();
        let final_path = dir.join("metrics.bin");
        let part_path = part_path_for(&final_path, &suffix);
        let registry = Arc::new(MetricsRegistry::new());
        let zero = registry.disk().snapshot();
        assert_eq!(
            zero.prealloc_seconds.count, 0,
            "honest zero-value starting point"
        );
        assert_eq!(zero.finalize_file_fsync.count, 0);

        // 8 existing bytes + target 16: Restart takes both sites —
        // trunc (target=0) + explicit prealloc (0 < 16) — so 2 prealloc
        // samples.
        std::fs::write(&part_path, b"01234567").unwrap_or_else(|e| panic!("seed: {e}"));
        let part = PartFile::open_with_registry(
            part_path.clone(),
            Some(16),
            PartOpenPolicy::Restart,
            FileAllocation::Prealloc,
            Arc::clone(&registry),
        )
        .await
        .unwrap_or_else(|e| panic!("open: {e}"));
        let mid = registry.disk().snapshot();
        assert_eq!(
            mid.prealloc_seconds.count, 2,
            "trunc and explicit prealloc each count once at their two sites"
        );
        assert_eq!(
            mid.finalize_file_fsync.count, 0,
            "no fsync sample on the open face"
        );

        part.sync_all()
            .await
            .unwrap_or_else(|e| panic!("fsync: {e}"));
        let s = registry.disk().snapshot();
        assert_eq!(
            s.finalize_file_fsync.count, 1,
            "sync_all lands in the file_fsync slot"
        );
        assert!(
            s.finalize_file_fsync.sum_us > 0 || s.finalize_file_fsync.count > 0,
            "the file_fsync sample has been booked"
        );
        assert_eq!(
            s.finalize_rename.count, 0,
            "the rename slot is produced only by the finalize orchestration face"
        );

        // No instance sharing: the process default registry must stay
        // unpolluted by this test (spot-checks that the prealloc count
        // is independent).
        let other = Arc::new(MetricsRegistry::new());
        assert_eq!(other.disk().snapshot().prealloc_seconds.count, 0);

        // Teardown-shaped close: the credential is dropped on the spot
        // (the claim releases immediately — under the close->finalize
        // transfer semantics a credential bound to the end of a
        // statement would hold the claim until the end of scope).
        drop(part.close());
        wipe(&dir);
    }

    /// Open policy: Restart truncates from zero (the degraded/length-
    /// mismatch face); Resume grows only, never shrinks, and keeps the
    /// existing prefix (the resume face).
    #[tokio::test]
    async fn open_policy_restart_vs_resume() {
        let dir = tempdir("policy");
        let suffix = IncompleteSuffix::parse(".p7").unwrap_or_else(|e| panic!("suffix: {e}"));
        let final_path = dir.join("f.bin");
        let part_path = part_path_for(&final_path, &suffix);

        // Seed an existing `.part` (32 stale bytes).
        std::fs::write(&part_path, vec![0xAA; 32]).unwrap_or_else(|e| panic!("seed: {e}"));

        // Restart: truncate to 0, then prealloc to the total.
        let part = PartFile::open(
            part_path.clone(),
            Some(64),
            PartOpenPolicy::Restart,
            FileAllocation::Prealloc,
        )
        .await
        .unwrap_or_else(|e| panic!("open restart: {e}"));
        let meta = std::fs::metadata(&part_path).unwrap_or_else(|e| panic!("meta: {e}"));
        assert_eq!(meta.len(), 64);
        let bytes = std::fs::read(&part_path).unwrap_or_else(|e| panic!("read: {e}"));
        assert!(
            bytes.iter().all(|b| *b == 0),
            "no stale bytes after Restart"
        );
        // Close the first handle (the handle-lifecycle discipline: close
        // out stepwise). Teardown-shaped close: the credential is
        // dropped on the spot (the claim releases immediately — under
        // the close->finalize transfer semantics a credential bound to
        // the end of a statement would hold the claim until the end of
        // scope).
        drop(part.close());

        // Resume: the stale 32-byte prefix is kept, grown to 64.
        std::fs::write(&part_path, vec![0x5A; 32]).unwrap_or_else(|e| panic!("seed2: {e}"));
        let part = PartFile::open(
            part_path.clone(),
            Some(64),
            PartOpenPolicy::Resume,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open resume: {e}"));
        let bytes = std::fs::read(&part_path).unwrap_or_else(|e| panic!("read2: {e}"));
        assert_eq!(bytes.len(), 64);
        assert!(
            bytes[..32].iter().all(|b| *b == 0x5A),
            "Resume keeps the prefix"
        );
        assert!(bytes[32..].iter().all(|b| *b == 0));
        // Teardown-shaped close: the credential is dropped on the spot
        // (the claim releases immediately — under the close->finalize
        // transfer semantics a credential bound to the end of a
        // statement would hold the claim until the end of scope).
        drop(part.close());
        // Resume never shrinks: total < current keeps the original
        // length.
        let part = PartFile::open(
            part_path.clone(),
            Some(8),
            PartOpenPolicy::Resume,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open resume2: {e}"));
        drop(part.close());
        assert_eq!(
            std::fs::metadata(&part_path)
                .map(|m| m.len())
                .unwrap_or_default(),
            64,
            "Resume grows only, never shrinks"
        );

        // Parent directories created as needed (aria2 mkdirs
        // semantics).
        let nested = dir.join("mk/sub/g.bin");
        let nested_part = part_path_for(&nested, &suffix);
        let part = PartFile::open(
            nested_part.clone(),
            None,
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open nested: {e}"));
        assert!(nested_part.is_file());
        // Teardown-shaped close: the credential is dropped on the spot
        // (the claim releases immediately — under the close->finalize
        // transfer semantics a credential bound to the end of a
        // statement would hold the claim until the end of scope).
        drop(part.close());

        wipe(&dir);
    }

    /// The `.part` claim table: a second open of the same path while
    /// the first task is in flight is rejected
    /// (`taiji.http.path_conflict`) — the co-write race on one `.part`
    /// (truncate of an in-flight file) closes at the open face; after
    /// close (or last-handle drop) reopening is legal.
    #[tokio::test]
    async fn concurrent_open_same_part_conflicts_then_reopens() {
        let dir = tempdir("claim");
        let part_path = dir.join("x.bin.part");

        let first = PartFile::open(
            part_path.clone(),
            Some(8),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("first open: {e}"));

        let second = PartFile::open(
            part_path.clone(),
            Some(8),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await;
        match second {
            Err(e) => assert_eq!(e.code(), "taiji.http.path_conflict", "{e}"),
            Ok(_) => panic!("in-flight .part must not be openable by a second task"),
        }

        // Close releases the claim -> reopening is legal (teardown
        // shape: the credential is discarded).
        drop(first.close());
        let third = PartFile::open(
            part_path.clone(),
            Some(8),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("reopen after close: {e}"));
        let _ = third.close();

        wipe(&dir);
    }

    /// The close->rename window keeps claims held: `close()`
    /// **transfers** the `.part` claim into the finalize credential
    /// instead of releasing it — between close and rename settlement
    /// (journal round-trip + probe + failure backoff retries) a new
    /// task must not enter the same `.part` (a Resume would hold a
    /// write handle on the same inode; after the old rename executes,
    /// the new task's writes would all land in the completed final
    /// file) nor the same final path (different suffixes are not
    /// isolation either). Once finalize settles (Completed) both the
    /// part and final claims release and a new task may reuse the name
    /// (a regression anchor against over-blocking).
    #[tokio::test]
    async fn close_to_rename_window_keeps_part_and_final_claims() {
        use crate::finalize::FinalizeOutcome;
        use crate::finalize::Finalizer;
        use crate::finalize::FsOps;
        use crate::finalize::MemoryJournal;
        use crate::finalize::PathOps;
        use crate::finalize::RenameIntent;
        use crate::finalize::RenameJournal;
        use crate::naming::CreationPolicy;
        use crate::naming::plan_output;

        let dir = tempdir("sec22-win");
        let suffix = IncompleteSuffix::default();
        let final_path = dir.join("w.bin");
        let holder = "80000000000000b1";

        // The task's first half: plan (final claim) -> open (part
        // claim) -> write -> fsync.
        let plan = plan_output(
            final_path.clone(),
            &suffix,
            CreationPolicy::default(),
            holder,
        )
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let part = PartFile::open(
            plan.part_path.clone(),
            Some(8),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open: {e}"));
        part.write_all_at(0, Bytes::from_static(b"SEC22!!!"))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        part.sync_all()
            .await
            .unwrap_or_else(|e| panic!("fsync: {e}"));

        // The window seam: after close, before finalize settles — the
        // credential is in flight (not dropped, not yet in finalize).
        let closed = part.close();

        // (1) A new task's open of the same `.part` is rejected (before
        // the fix, close released the claim immediately).
        let second = PartFile::open(
            plan.part_path.clone(),
            Some(8),
            PartOpenPolicy::Resume,
            FileAllocation::None,
        )
        .await;
        match second {
            Err(e) => assert_eq!(e.code(), "taiji.http.path_conflict", "{e}"),
            Ok(_) => panic!(
                "must not admit a second open of the same .part \
                 within the close->rename window"
            ),
        }

        // (2) A new task's plan on the same final path is rejected
        // (different suffixes are not isolation).
        let sfx_other = IncompleteSuffix::parse(".alt").unwrap_or_else(|e| panic!("sfx: {e}"));
        match plan_output(
            final_path.clone(),
            &sfx_other,
            CreationPolicy::default(),
            "80000000000000b2",
        ) {
            Err(e) => assert_eq!(e.code(), "taiji.http.path_conflict", "{e}"),
            Ok(_) => panic!(
                "must not admit a new task on the same final path \
                 within the close->rename window"
            ),
        }

        // Finalize settles (Completed) -> both claims release (inside
        // the journal close-out).
        let journal = Arc::new(MemoryJournal::default());
        let fin = Finalizer::with_injection(
            Arc::clone(&journal) as Arc<dyn RenameJournal>,
            Arc::new(FsOps) as Arc<dyn PathOps>,
            Arc::new(crate::finalize::ExponentialBackoff {
                base: std::time::Duration::ZERO,
            }),
        );
        let intent = RenameIntent {
            gid: holder.to_string(),
            part_path: plan.part_path.clone(),
            final_path: final_path.clone(),
            expected_len: 8,
            reservation_token: String::new(),
            auto_rename: false,
        };
        let outcome = fin
            .finalize(&intent, closed)
            .await
            .unwrap_or_else(|e| panic!("finalize: {e}"));
        assert!(
            matches!(outcome, FinalizeOutcome::Completed { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            std::fs::read(&final_path).unwrap_or_else(|e| panic!("read: {e}")),
            b"SEC22!!!"
        );

        // Regression anchor: after settlement releases, a new task can
        // reuse the name (the final file is removed to simulate a clean
        // directory; both open and plan pass).
        std::fs::remove_file(&final_path).unwrap_or_else(|e| panic!("rm final: {e}"));
        let reopened = PartFile::open(
            plan.part_path.clone(),
            None,
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("reopen after settle: {e}"));
        let _ = reopened.close();
        let replan = plan_output(
            final_path.clone(),
            &suffix,
            CreationPolicy::default(),
            "80000000000000b3",
        )
        .unwrap_or_else(|e| panic!("replan after settle: {e}"));
        assert_eq!(replan.final_path, final_path);

        wipe(&dir);
    }

    /// The claim table's drop face: when a task aborts without close,
    /// the last-handle drop releases the claim — no permanent
    /// in-process conflict.
    #[tokio::test]
    async fn claim_released_on_drop_without_close() {
        let dir = tempdir("claim-drop");
        let part_path = dir.join("y.bin.part");

        let part = PartFile::open(
            part_path.clone(),
            Some(4),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open: {e}"));
        drop(part); // The abort shape: drop without close.

        let reopened = PartFile::open(
            part_path,
            Some(4),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("reopen after drop: {e}"));
        let _ = reopened.close();

        wipe(&dir);
    }

    /// The `.part` claim must not release before in-flight positional
    /// writes drain: after the write future is abandoned (forceRemove
    /// abort / cancel) and every handle dropped, the uncancellable
    /// pwrite still runs — if the claim were already released, a new
    /// task could open the same path with Restart and truncate, and the
    /// old write landing afterward would revive a stale region.
    /// Deterministic seam: io_gate suspends the blocking body before
    /// the pwrite; the test asserts the claim is held while suspended,
    /// and that releasing lets the write drain, the claim release, and
    /// the path be reusable (regression anchor). Before the fix the
    /// handle drop released the claim immediately (no ordering between
    /// claim and in-flight writes).
    #[tokio::test]
    async fn claim_held_while_write_in_flight_released_after_drain() {
        let dir = tempdir("sec34-write");
        let part_path = dir.join("w34.bin.part");

        let part = PartFile::open(
            part_path.clone(),
            Some(16),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open: {e}"));

        // The in-flight write: open's enter/note already counted (hold
        // unset, pass-through); the accounting is removed, the gate is
        // held, and only then is the write future spawned (the handle
        // cloned inside the future is discarded with the abort —
        // simulating a torn-down worker future). The Releaser
        // guarantees the gate opens even when an assertion fails — the
        // runtime can only exit after the blocking body finishes.
        io_gate::remove(&part_path);
        io_gate::hold(&part_path);
        let _gate = io_gate::Releaser::new(&part_path);
        let writer = part.clone();
        let wh = tokio::spawn(async move {
            writer
                .write_all_at(0, Bytes::from_static(b"SEC34-INTERRUPTED!"))
                .await
        });
        io_gate::wait_entered(&part_path, 1).await; // Suspended before the pwrite (deterministic).

        // The teardown shape: the write future abandoned + this handle
        // dropped = every PartFile clone gone; the blocking body (the
        // uncancellable pwrite) still runs.
        wh.abort();
        let _ = wh.await; // JoinError(cancelled): the future was dropped (handle released).
        drop(part);

        // Core assertion: the claim is held while writes are in flight
        // (a new task's open would be rejected — the
        // truncate-after-release race is closed). Before the fix:
        // released immediately.
        assert!(
            part_claim_held(&part_path),
            "the .part claim must not release while in-flight positional \
             writes are unfinished (the stale-write revival window)"
        );

        // Release -> the pwrite completes -> writes drain -> the claim
        // releases (deterministic: the guard's Drop finishes
        // synchronously after the finished registration; bounded
        // polling guards against a tiny window hang).
        io_gate::release(&part_path);
        io_gate::wait_finished(&part_path, 1).await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while part_claim_held(&part_path) {
            assert!(
                std::time::Instant::now() < deadline,
                "the claim must release once in-flight writes drain \
                 (no permanent conflict left behind)"
            );
            tokio::task::yield_now().await;
        }

        // Regression anchor: the path is reusable after the claim
        // releases (normal open-close semantics unchanged).
        let reopened = PartFile::open(
            part_path.clone(),
            Some(16),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("reopen after drain: {e}"));
        drop(reopened.close());
        io_gate::remove(&part_path);
        wipe(&dir);
    }

    /// The open-window claim guard: if the `open` future is abandoned
    /// while its spawn_blocking (the real open/truncate) runs (a
    /// forceRemove abort), claim_part has already claimed while the
    /// in-future release path is unreachable -> the claim hangs forever
    /// (every new task on the path gets path_conflict). Deterministic
    /// seam: io_gate suspends open's blocking body, the future is
    /// abandoned, and the test asserts the claim has been released (the
    /// guard's Drop backstop). Before the fix the claim hung.
    #[tokio::test]
    async fn claim_released_when_open_future_aborted_midway() {
        let dir = tempdir("sec34-open");
        let part_path = dir.join("o34.bin.part");

        io_gate::hold(&part_path);
        let _gate = io_gate::Releaser::new(&part_path);
        let p = part_path.clone();
        let oh = tokio::spawn(async move {
            PartFile::open(p, Some(8), PartOpenPolicy::Restart, FileAllocation::None).await
        });
        io_gate::wait_entered(&part_path, 1).await; // open_sync suspended (deterministic).

        oh.abort();
        let _ = oh.await; // The future was dropped (open result discarded).

        // After release and the blocking body finishing, the claim must
        // be gone (the guard's Drop backstop; before the fix the
        // claim_part claim hung).
        io_gate::release(&part_path);
        io_gate::wait_finished(&part_path, 1).await;
        assert!(
            !part_claim_held(&part_path),
            "the claim must release once the open future is abandoned \
             (no permanent path_conflict left behind)"
        );

        // Regression anchor: the path opens normally again.
        let reopened = PartFile::open(
            part_path.clone(),
            Some(8),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("reopen after abort: {e}"));
        drop(reopened.close());
        io_gate::remove(&part_path);
        wipe(&dir);
    }
}

#[cfg(all(test, unix))]
mod sec_38_tests {
    use super::*;

    /// A symlink preset at the `.part` path -> open must reject (ELOOP
    /// propagates; it must not follow through and truncate the target
    /// with set_len).
    #[tokio::test]
    async fn partfile_rejects_preset_symlink() {
        let dir = std::env::temp_dir().join(format!("taiji-sec38-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let victim = dir.join("victim.bin");
        std::fs::write(&victim, vec![0u8; 4096]).unwrap_or_else(|e| panic!("victim: {e}"));
        let part = dir.join("data.bin.part");
        std::os::unix::fs::symlink(&victim, &part).unwrap_or_else(|e| panic!("symlink: {e}"));
        let opened = PartFile::open(
            part.clone(),
            None,
            PartOpenPolicy::Resume,
            FileAllocation::None,
        )
        .await;
        assert!(
            opened.is_err(),
            "a .part with a preset symlink must be rejected on open"
        );
        // The victim file is untouched (never truncated by set_len).
        let len = std::fs::metadata(&victim)
            .unwrap_or_else(|e| panic!("stat victim: {e}"))
            .len();
        assert_eq!(
            len, 4096,
            "the penetration face must not touch the target file"
        );
        let _ = std::fs::remove_file(&part);
        let _ = std::fs::remove_file(&victim);
        let _ = std::fs::remove_dir(&dir);
    }
}

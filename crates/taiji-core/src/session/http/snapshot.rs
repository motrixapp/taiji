//! The bitmap snapshot pipeline: block completion → bitmap dirty → a
//! 2s-debounced snapshot persisted; every snapshot commit is preceded
//! by one fsync of the task file (at most one per task per 2s, bounded
//! cost).
//!
//! Timing invariant ("a power-loss bitmap is never ahead of the
//! data"): every completed block in a snapshot has its byte range
//! already persisted when the fsync returns — an fsync failure
//! withholds the snapshot (the bitmap stays dirty; the caller handles
//! the task-level fault). Under-crediting progress is acceptable;
//! over-crediting never happens.
//!
//! `NotFound` from fsync refuses the commit whenever the pipeline
//! holds completed blocks (a file declared complete but missing = an
//! inflated bitmap; never disguised as success) — snapshots only run
//! while dirty, and dirty implies ≥1 completed block, so a NotFound
//! at the commit point always accompanies a non-empty completed set.
//!
//! Exit guard: terminal-row consumption
//! ([`HttpSnapshotPipeline::into_row`]) must follow
//! [`HttpSnapshotPipeline::flush_now`] — the completion path enforces
//! "fsync + bitmap persist → terminal persist" order, and a row
//! carrying an unpersisted bitmap is refused.
//!
//! The BT-side barrier (the same timing invariant: data fsync first,
//! progress row persist second), the parent-directory trade-off, and
//! the clock contract: docs/design/core.md.
//!
//! Upstream anchor mapping: docs/design/core.md

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use taiji_store::error::StoreError;
use taiji_store::persist::{HttpTaskRow, PersistOutcome};
use tokio::task::spawn_blocking;
use tracing::warn;

use super::{bit_set, bit_test, bitmap_done_blocks, bitmap_len, row_geometry_ok};

/// The snapshot debounce window (a 2s-debounced bitmap persist, at
/// most once per task per 2s — bounded cost).
pub const SNAPSHOT_INTERVAL_MS: u64 = 2000;

/// The task-file fsync seam (injection face: production = open the
/// `.part` directly and fsync; tests = power-loss models / fault
/// stubs). Blocking semantics — the caller must put it in
/// `spawn_blocking`. Error semantics: **failures propagate verbatim**
/// (including `NotFound` — whether a missing file is tolerable is
/// decided by the pipeline on completed-block state, never disguised
/// as success here).
pub trait TaskFileSync: Send + Sync + 'static {
    /// fsync the task file. Any error (including NotFound) propagates
    /// verbatim.
    fn sync(&self) -> Result<(), StoreError>;
}

/// The production implementation: open the `.part` file directly and
/// fsync (opened read+write — Windows `FlushFileBuffers` needs a write
/// handle). `NotFound` propagates verbatim: with completed blocks in
/// the pipeline, a missing file = declared-complete bytes missing, so
/// the snapshot must refuse (see [`TaskFileSync`]). Goes through the
/// store disk layer for uniform error classification and path context.
/// Parent-directory fsync is not in this seam (see the module doc for
/// the directory-entry trade-off — recovery from zero, the safe
/// direction).
#[derive(Debug, Clone)]
pub struct PartFileSync {
    path: PathBuf,
    /// The io metrics registry (the feeding seam for
    /// `taiji_disk_finalize_seconds{op=file_fsync}` — the grid path's
    /// 2s debounce beat shares this seam with the finalize forced
    /// beat; bound by default to the process default instance; tests
    /// inject a separate instance via [`Self::with_metrics`]).
    metrics: Arc<taiji_io::metrics::MetricsRegistry>,
}

impl PartFileSync {
    pub fn new(path: PathBuf) -> Self {
        Self::with_metrics(path, taiji_io::metrics::registry_default())
    }

    /// Metrics registry injection (the test seam; production assembly
    /// goes through [`Self::new`]).
    pub fn with_metrics(path: PathBuf, metrics: Arc<taiji_io::metrics::MetricsRegistry>) -> Self {
        PartFileSync { path, metrics }
    }
}

impl TaskFileSync for PartFileSync {
    fn sync(&self) -> Result<(), StoreError> {
        use taiji_store::disk::DiskWriter as _;
        let mut w = taiji_store::disk::FileDiskWriter::new();
        w.open_existing(&self.path, false)?;
        // Feeding point (read-only timing): the task-file fsync
        // syscall face (open_existing not counted — the flush phase
        // is the observed SMB long tail).
        let t0 = std::time::Instant::now();
        let r = w.flush_os_buffers();
        self.metrics
            .disk()
            .observe_finalize(taiji_io::metrics::FinalizeOp::FileFsync, t0.elapsed());
        r
    }
}

/// The snapshot pipeline fault face (task-scoped — never infects the
/// session; the caller handles per-task errors).
#[derive(Debug, thiserror::Error)]
pub enum HttpSnapshotError {
    /// fsync before the snapshot failed (a disk write-path error —
    /// the bitmap is never committed).
    #[error("http: task file fsync before bitmap snapshot failed: {0}")]
    Fsync(StoreError),
    /// The bitmap snapshot persist failed (the PersistWriter face).
    #[error("http: bitmap snapshot persist failed: {0}")]
    Persist(StoreError),
    /// The fsync blocking task join failed (a runtime stall — the
    /// task-side projection of a session-level fault).
    #[error("http: fsync blocking task join failed: {0}")]
    Join(String),
    /// A completed block fell outside the block grid (a
    /// scheduler-side decision defect — a programming-error face).
    #[error("http: block {block} out of range (blocks_total {blocks_total})")]
    BlockOutOfRange { block: u64, blocks_total: u64 },
    /// The pipeline row geometry is corrupt (bitmap/count unpaired or
    /// granularity out of domain).
    #[error("http: snapshot pipeline row geometry invalid")]
    RowCorrupt,
    /// A terminal row carrying an unpersisted bitmap was consumed —
    /// the completion path must [`HttpSnapshotPipeline::flush_now`]
    /// (fsync + bitmap persist) before handing over the row.
    #[error("http: row consumed with unflushed bitmap blocks; flush_now before terminal persist")]
    UnflushedRow,
}

/// The per-task bitmap snapshot pipeline: holds the task's
/// authoritative row copy (the in-memory truth), marks dirty on block
/// completion, and fsyncs + persists when the debounce window expires.
/// Not Clone — the row truth is single-held (HttpTask actor exclusive;
/// snapshots commit via [`Self::flush_due`]).
pub struct HttpSnapshotPipeline {
    row: HttpTaskRow,
    /// The last successfully committed row snapshot (the fsynced
    /// upper bound; None = no successful beat yet). The cancel
    /// wrap-up's (pause row write) mirror sync uses this as its
    /// progress bound — completed blocks not yet fsynced in the
    /// in-memory truth must not enter a paused row (the row-write
    /// extension of "a power-loss bitmap is never ahead of the data";
    /// re-downloading unconfirmed blocks is the safe direction).
    flushed: Option<HttpTaskRow>,
    /// The probed authoritative total length (the last block's
    /// partial length accounted; None = the no-total form counts
    /// whole blocks).
    total_len: Option<u64>,
    block_size: u64,
    block_count: u64,
    dirty: bool,
    last_snapshot_ms: Option<u64>,
    sync: Arc<dyn TaskFileSync>,
}

impl HttpSnapshotPipeline {
    /// Assembly: `row` must carry a paired bitmap/count with
    /// granularity in domain (the same row-geometry verdict as the
    /// recovery read path — both sides share the caliber; never
    /// bookkeeping while diseased). A planned pre-first-snapshot
    /// shape without a persisted bitmap (`bitmap=None, count=Some` —
    /// after probe grid creation before the first snapshot, or the
    /// legal row shape after recovery-from-zero cleared the bitmap)
    /// assembles normally: the bitmap is built lazily on the first
    /// completed block.
    pub fn new(
        row: HttpTaskRow,
        total_len: Option<u64>,
        sync: Arc<dyn TaskFileSync>,
    ) -> Result<Self, HttpSnapshotError> {
        if !row_geometry_ok(&row) {
            return Err(HttpSnapshotError::RowCorrupt);
        }
        let block_count = row.block_count.unwrap_or(0).max(0) as u64;
        Ok(HttpSnapshotPipeline {
            block_size: row.block_size.max(0) as u64,
            block_count,
            total_len,
            row,
            flushed: None,
            dirty: false,
            last_snapshot_ms: None,
            sync,
        })
    }

    /// Block-completion bookkeeping (the sole entry after the
    /// scheduler side's single-point decision): set the bit +
    /// accumulate progress + mark dirty. When the row has no bitmap
    /// yet (the pre-first-snapshot planned state) a zero bitmap is
    /// built lazily — the geometry verdict accepts that shape and
    /// bookkeeping must not reject on a missing bitmap (otherwise the
    /// pipeline could never start from the legal prior state: the
    /// first completed block would be a permanent task-level fault).
    /// A duplicate completion = an idempotent no-op (a late duplicate
    /// write of the same block; first writer wins). Returns whether
    /// it was a new completion (duplicates = false; progress counts
    /// once).
    pub fn complete_block(&mut self, block: u64) -> Result<bool, HttpSnapshotError> {
        if block >= self.block_count {
            return Err(HttpSnapshotError::BlockOutOfRange {
                block,
                blocks_total: self.block_count,
            });
        }
        let len = bitmap_len(self.block_count);
        self.row.block_bitmap.get_or_insert_with(|| vec![0u8; len]);
        let Some(bitmap) = self.row.block_bitmap.as_mut() else {
            return Err(HttpSnapshotError::RowCorrupt);
        };
        if bit_test(bitmap, block) {
            return Ok(false);
        }
        bit_set(bitmap, block);
        let bytes = super::block_bytes(block, self.block_size, self.total_len);
        self.row.total_done = self
            .row
            .total_done
            .saturating_add(bytes.min(i64::MAX as u64) as i64);
        self.dirty = true;
        Ok(true)
    }

    /// The next snapshot due instant (None = no bitmap awaiting
    /// persist; the task actor loop's timer hint face). The first
    /// beat is due now (the first completed block can persist
    /// immediately — progress on screen as soon as possible;
    /// afterwards the 2s debounce cadence). **Failure backoff**: an
    /// fsync/persist failure also advances the cadence anchor — the
    /// next attempt = failure time + window, so a sustained disk
    /// fault never hot-spins the task actor's due polling into the
    /// disk.
    pub fn next_due_ms(&self, now_ms: u64) -> Option<u64> {
        if !self.dirty {
            return None;
        }
        Some(match self.last_snapshot_ms {
            None => now_ms,
            Some(last) => last.saturating_add(SNAPSHOT_INTERVAL_MS),
        })
    }

    /// Awaiting-persist verdict (the task actor's saveSession/pause
    /// wrap-up decision face).
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Completed block count (the in-memory truth view).
    pub fn blocks_done(&self) -> u64 {
        self.row
            .block_bitmap
            .as_deref()
            .map_or(0, |bm| bitmap_done_blocks(bm, self.block_count))
    }

    /// Total blocks in the block grid.
    pub fn blocks_total(&self) -> u64 {
        self.block_count
    }

    /// The authoritative row view (read-only — bitmap/count/progress
    /// change only via [`Self::complete_block`]; state-machine fields
    /// go through the setters below).
    pub fn row(&self) -> &HttpTaskRow {
        &self.row
    }

    /// The last successfully committed row view (the fsynced upper
    /// bound; None = no successful beat yet). Consumed by the cancel
    /// wrap-up's mirror sync (a pause row write never exceeds the
    /// fsynced face) — uncommitted completed blocks in the
    /// authoritative row [`Self::row`] do not enter this view.
    pub fn flushed_row(&self) -> Option<&HttpTaskRow> {
        self.flushed.as_ref()
    }

    /// State-machine field maintenance (task actor only): only the
    /// state text is exposed; bitmap/count/progress have no write
    /// entrance — their write face must go through the snapshot fsync
    /// order (a bare `row_mut` could carry a full dirty bitmap
    /// straight to upsert, bypassing the fsync gate).
    pub fn set_state(&mut self, state: impl Into<String>) {
        self.row.state = state.into();
    }

    /// Terminal/error payload maintenance (error_code/error_msg;
    /// recovery to a non-error state passes `(None, None)`).
    pub fn set_error(&mut self, error_code: Option<String>, error_msg: Option<String>) {
        self.row.error_code = error_code;
        self.row.error_msg = error_msg;
    }

    /// Consume the row (task wrap-up: the row goes back to the caller
    /// for terminal persistence). **A dirty bitmap = refused**
    /// ([`HttpSnapshotError::UnflushedRow`]) — the completion path
    /// must run [`Self::flush_now`] first (fsync before terminal
    /// persist, the exit guard of the ordering invariant; a done row
    /// is not in the recovery read face, so the second line of
    /// defense never covers "full bitmap + unpersisted bytes").
    pub fn into_row(self) -> Result<HttpTaskRow, HttpSnapshotError> {
        if self.dirty {
            return Err(HttpSnapshotError::UnflushedRow);
        }
        Ok(self.row)
    }

    /// Debounced snapshot: acts only when the window expires (or the
    /// first beat). `Ok(None)` = not due / not dirty.
    pub async fn flush_due<F, Fut>(
        &mut self,
        now_ms: u64,
        sink: F,
    ) -> Result<Option<PersistOutcome>, HttpSnapshotError>
    where
        F: FnOnce(HttpTaskRow) -> Fut,
        Fut: Future<Output = Result<PersistOutcome, StoreError>>,
    {
        if !self.dirty {
            return Ok(None);
        }
        if let Some(last) = self.last_snapshot_ms {
            if now_ms.saturating_sub(last) < SNAPSHOT_INTERVAL_MS {
                return Ok(None);
            }
        }
        self.submit(sink, now_ms).await
    }

    /// Forced snapshot (the pause/stop/saveSession wrap-up face:
    /// ignores the debounce window).
    pub async fn flush_now<F, Fut>(
        &mut self,
        now_ms: u64,
        sink: F,
    ) -> Result<Option<PersistOutcome>, HttpSnapshotError>
    where
        F: FnOnce(HttpTaskRow) -> Fut,
        Fut: Future<Output = Result<PersistOutcome, StoreError>>,
    {
        if !self.dirty {
            return Ok(None);
        }
        self.submit(sink, now_ms).await
    }

    /// The commit body: **fsync the task file first, commit the
    /// snapshot second** — the order is the invariant. An fsync
    /// failure (including NotFound — with completed blocks in the
    /// pipeline, a missing file is an inflated bitmap, never
    /// committed) does not commit (the bitmap stays dirty); a persist
    /// failure also stays dirty (a lost row write converges via the
    /// next snapshot/saveSession rewrite, matching the torrent
    /// row-write caliber). Failures also advance the cadence anchor
    /// (backoff: the next attempt after a full window — sustained
    /// faults never hot-spin the disk).
    async fn submit<F, Fut>(
        &mut self,
        sink: F,
        now_ms: u64,
    ) -> Result<Option<PersistOutcome>, HttpSnapshotError>
    where
        F: FnOnce(HttpTaskRow) -> Fut,
        Fut: Future<Output = Result<PersistOutcome, StoreError>>,
    {
        // Snapshot clock contract: monotonic milliseconds (module
        // doc); an inversion is a caller clock defect.
        debug_assert!(
            self.last_snapshot_ms.is_none_or(|last| now_ms >= last),
            "snapshot clock must be monotonic: now {now_ms} < last {:?}",
            self.last_snapshot_ms
        );
        let sync = Arc::clone(&self.sync);
        let gid = self.row.gid.clone();
        match spawn_blocking(move || sync.sync()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                self.last_snapshot_ms = Some(now_ms);
                warn!(target: "taiji::core::http", gid = %gid, error = %e,
                    "task file fsync failed; bitmap snapshot withheld");
                return Err(HttpSnapshotError::Fsync(e));
            }
            Err(e) => {
                self.last_snapshot_ms = Some(now_ms);
                return Err(HttpSnapshotError::Join(e.to_string()));
            }
        }
        match sink(self.row.clone()).await {
            Ok(outcome) => {
                self.dirty = false;
                self.last_snapshot_ms = Some(now_ms);
                // The fsynced upper bound advances (the cancel
                // wrap-up's row-write upper-bound view).
                self.flushed = Some(self.row.clone());
                Ok(Some(outcome))
            }
            Err(e) => {
                self.last_snapshot_ms = Some(now_ms);
                warn!(target: "taiji::core::http", gid = %gid, error = %e,
                    "bitmap snapshot persist failed; row stays dirty");
                Err(HttpSnapshotError::Persist(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::http::{bitmap_len, recover as http_recover};
    use std::sync::Mutex;
    use taiji_store::persist::PersistWriter;

    use http_recover::{PartFileFacts, Resumability, ZeroReason, recover_http_task};

    /// A deterministic RNG (xorshift64; power-loss injection
    /// sequences are reproducible).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }

    /// Power-loss model: volatile = the write face (the page cache
    /// advances arbitrarily, including sub-block granularity),
    /// durable = the fsync-persisted face; power loss = volatile
    /// falls back to durable.
    #[derive(Debug, Default)]
    struct PowerModel {
        volatile_len: u64,
        durable_len: u64,
        fsyncs: u64,
    }

    /// SimSync: fsync = durable catches up to volatile (the
    /// persistence point of a true power-loss simulation).
    struct SimSync(Arc<Mutex<PowerModel>>);

    impl TaskFileSync for SimSync {
        fn sync(&self) -> Result<(), StoreError> {
            let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
            m.durable_len = m.volatile_len;
            m.fsyncs += 1;
            Ok(())
        }
    }

    struct FailingSync;

    impl TaskFileSync for FailingSync {
        fn sync(&self) -> Result<(), StoreError> {
            Err(StoreError::FileIo {
                path: "/dl/f.bin.part".into(),
                source: std::io::Error::other("injected fsync failure"),
            })
        }
    }

    /// Missing-file injection (the NotFound semantic face: with
    /// completed blocks in the pipeline = the snapshot is refused).
    struct MissingFileSync;

    impl TaskFileSync for MissingFileSync {
        fn sync(&self) -> Result<(), StoreError> {
            Err(StoreError::FileIo {
                path: "/dl/f.bin.part".into(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            })
        }
    }

    /// Persist-failure injection seam: the first `failures` calls
    /// return a Persist error, then succeed.
    struct FlakySink(Mutex<u32>);

    impl FlakySink {
        fn new(failures: u32) -> Self {
            FlakySink(Mutex::new(failures))
        }

        /// Whether this call injects a failure (decrements the
        /// remaining failure budget).
        fn take_fail(&self) -> bool {
            let mut left = self.0.lock().unwrap_or_else(|p| p.into_inner());
            if *left > 0 {
                *left -= 1;
                true
            } else {
                false
            }
        }
    }

    /// The persist seam recorder: records the bitmap at the persist
    /// instant and the durable face at that time. The call instant =
    /// after fsync (the pipeline commit order) — the recorded value
    /// is the observation point of the order invariant.
    #[derive(Debug, Clone)]
    struct SnapshotRecord {
        bitmap: Vec<u8>,
        durable_len: u64,
    }

    fn recording_sink(
        model: Arc<Mutex<PowerModel>>,
        snaps: Arc<Mutex<Vec<SnapshotRecord>>>,
    ) -> impl FnOnce(HttpTaskRow) -> std::future::Ready<Result<PersistOutcome, StoreError>> {
        move |row| {
            let durable_len = model.lock().unwrap_or_else(|p| p.into_inner()).durable_len;
            snaps
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(SnapshotRecord {
                    bitmap: row.block_bitmap.clone().unwrap_or_default(),
                    durable_len,
                });
            std::future::ready(Ok(PersistOutcome::Written))
        }
    }

    /// A side-effect-free sink (for error-path tests: expected to be
    /// intercepted before reaching the sink).
    fn no_sink()
    -> impl FnOnce(HttpTaskRow) -> std::future::Ready<Result<PersistOutcome, StoreError>> {
        move |_row| std::future::ready(Ok(PersistOutcome::Written))
    }

    /// The maximum accumulated end (bytes) of completed blocks in the
    /// bitmap.
    fn bitmap_end(bitmap: &[u8], block_count: u64, block_size: u64) -> u64 {
        (0..block_count)
            .filter(|b| bit_test(bitmap, *b))
            .map(|b| (b + 1) * block_size)
            .max()
            .unwrap_or(0)
    }

    fn done_blocks(bitmap: &[u8], block_count: u64) -> u64 {
        (0..block_count).filter(|b| bit_test(bitmap, *b)).count() as u64
    }

    /// A test row (pipeline geometry: block_count × block_size).
    fn pipeline_row(gid: &str, block_count: u64, block_size: i64) -> HttpTaskRow {
        HttpTaskRow {
            gid: gid.into(),
            url: "http://origin/f.bin".into(),
            final_url: "http://cdn/f.bin".into(),
            mirrors_json: None,
            state: "downloading".into(),
            queue_pos: 0,
            dir: "/dl".into(),
            out: "f.bin".into(),
            config_json: "{}".into(),
            probe_json: None,
            validator_digest: None,
            block_size,
            block_bitmap: Some(vec![0u8; bitmap_len(block_count)]),
            block_count: Some(block_count as i64),
            total_done: 0,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    /// Test async Result unwrap (lint bans unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// 2s debounce coalescing: multiple block completions inside a
    /// window merge into one beat; the first beat is immediate;
    /// crossing the window unlocks; never acts when clean; fsync
    /// count == actual persist beats (bounded cost).
    #[tokio::test]
    async fn debounce_coalesces_block_completions() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let snaps = Arc::new(Mutex::new(Vec::new()));
        let bs = 4 * 1024 * 1024i64;
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000400", 8, bs),
                Some(8 * bs as u64),
                Arc::clone(&sync),
            ),
            "pipeline",
        );

        // Not dirty → never acts.
        let none = ok(
            pipe.flush_due(0, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                .await,
            "clean flush",
        );
        assert_eq!(none, None, "no dirt means no persist");
        assert_eq!(model.lock().unwrap_or_else(|p| p.into_inner()).fsyncs, 0);

        // First beat: the first completed block can persist
        // immediately.
        ok(pipe.complete_block(0), "complete 0");
        assert_eq!(pipe.next_due_ms(100), Some(100));
        let first = ok(
            pipe.flush_due(100, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                .await,
            "first flush",
        );
        assert!(first.is_some(), "the first snapshot fires immediately");
        assert!(!pipe.is_dirty());

        // Inside the window (<2s): completed blocks merge, no
        // persist, no fsync.
        ok(pipe.complete_block(1), "complete 1");
        ok(pipe.complete_block(2), "complete 2");
        for t in [500u64, 1999] {
            assert_eq!(pipe.next_due_ms(t), Some(100 + SNAPSHOT_INTERVAL_MS));
            let none = ok(
                pipe.flush_due(t, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                    .await,
                "windowed flush",
            );
            assert_eq!(none, None, "must not persist within the t={t} window");
        }
        assert!(pipe.is_dirty(), "stays dirty within the window");
        // Cross-window: one beat carries the merged blocks 1 and 2.
        let merged = ok(
            pipe.flush_due(
                100 + SNAPSHOT_INTERVAL_MS,
                recording_sink(Arc::clone(&model), Arc::clone(&snaps)),
            )
            .await,
            "merged flush",
        );
        assert!(merged.is_some());
        let records = snaps.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            records.len(),
            2,
            "three persist attempts -> two snapshots (first + merged)"
        );
        let last = records.last().unwrap_or_else(|| panic!("recorded"));
        assert_eq!(
            done_blocks(&last.bitmap, 8),
            3,
            "the merged snapshot carries every block completed within the window"
        );
        drop(records);
        assert_eq!(
            model.lock().unwrap_or_else(|p| p.into_inner()).fsyncs,
            2,
            "exactly one fsync per snapshot (bounded cost)"
        );
    }

    /// Forced snapshot: persists even inside the window (the
    /// pause/stop/saveSession wrap-up).
    #[tokio::test]
    async fn flush_now_forces_within_window() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let snaps = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = ok(
            HttpSnapshotPipeline::new(pipeline_row("8000000000000401", 4, 256 * 1024), None, sync),
            "pipeline",
        );
        ok(pipe.complete_block(3), "complete 3");
        let some = ok(
            pipe.flush_now(0, recording_sink(model, snaps)).await,
            "force flush",
        );
        assert!(
            some.is_some(),
            "a forced snapshot inside the window takes effect"
        );
        assert!(!pipe.is_dirty());
    }

    /// The fsynced upper-bound view (the cancel wrap-up face): None
    /// before the first beat; after a successful beat = the row at
    /// commit time; uncommitted completed blocks do not enter the
    /// view — a pause row write's progress face must not exceed the
    /// fsynced face (the row-write extension of "a power-loss bitmap
    /// is never ahead of the data").
    #[tokio::test]
    async fn flushed_row_tracks_last_successful_submit() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let snaps = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = ok(
            HttpSnapshotPipeline::new(pipeline_row("8000000000000408", 4, 256 * 1024), None, sync),
            "pipeline",
        );
        assert!(
            pipe.flushed_row().is_none(),
            "no fsynced high-water mark before the first snapshot"
        );
        ok(pipe.complete_block(0), "complete 0");
        assert!(
            pipe.flushed_row().is_none(),
            "blocks completed but not snapshotted stay out of the high-water view"
        );
        let flushed = ok(
            pipe.flush_now(0, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                .await,
            "first flush",
        );
        assert!(flushed.is_some());
        let view = pipe.flushed_row();
        let view = view.unwrap_or_else(|| panic!("flushed"));
        assert!(bit_test(view.block_bitmap.as_deref().unwrap_or(&[]), 0));
        // The new uncommitted block does not enter the bound; it
        // advances after the beat.
        ok(pipe.complete_block(1), "complete 1");
        let view = pipe.flushed_row();
        let view = view.unwrap_or_else(|| panic!("flushed"));
        assert!(
            !bit_test(view.block_bitmap.as_deref().unwrap_or(&[]), 1),
            "unsnapshotted blocks must not enter the fsynced high-water mark"
        );
        let flushed = ok(
            pipe.flush_now(SNAPSHOT_INTERVAL_MS, recording_sink(model, snaps))
                .await,
            "second flush",
        );
        assert!(flushed.is_some());
        let view = pipe.flushed_row();
        let view = view.unwrap_or_else(|| panic!("flushed"));
        assert!(
            bit_test(view.block_bitmap.as_deref().unwrap_or(&[]), 1),
            "advances after the snapshot"
        );
    }

    /// fsync failure: the snapshot is never committed (the bitmap
    /// stays dirty) and a retry after the backoff window can succeed
    /// — "under-count progress, never over-count"; a failure advances
    /// the cadence anchor (sustained faults never hot-spin the disk).
    #[tokio::test]
    async fn fsync_failure_withholds_snapshot_backs_off_then_recovers() {
        let sync: Arc<dyn TaskFileSync> = Arc::new(FailingSync);
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000402", 4, 4 * 1024 * 1024),
                None,
                sync,
            ),
            "pipeline",
        );
        ok(pipe.complete_block(0), "complete 0");
        let persist_calls = Arc::new(Mutex::new(0u32));
        let persist_calls_sink = Arc::clone(&persist_calls);
        let err = pipe
            .flush_due(0, move |_row| {
                let persist_calls_sink = Arc::clone(&persist_calls_sink);
                async move {
                    *persist_calls_sink.lock().unwrap_or_else(|p| p.into_inner()) += 1;
                    Ok(PersistOutcome::Written)
                }
            })
            .await;
        match err {
            Err(HttpSnapshotError::Fsync(_)) => {}
            other => panic!("expected fsync error, got {other:?}"),
        }
        assert!(pipe.is_dirty(), "stays dirty after the failure");
        assert_eq!(
            *persist_calls.lock().unwrap_or_else(|p| p.into_inner()),
            0,
            "an fsync failure never persists"
        );
        // A failure advances the cadence anchor: the next beat =
        // failure time + window (backoff); flush_due does not act
        // inside the window.
        assert_eq!(
            pipe.next_due_ms(1000),
            Some(SNAPSHOT_INTERVAL_MS),
            "no retry within the window (backoff)"
        );
        assert_eq!(
            pipe.next_due_ms(5_000),
            Some(SNAPSHOT_INTERVAL_MS),
            "after backoff the due point is pinned to the failure instant + window"
        );
        let none = ok(pipe.flush_due(1999, no_sink()).await, "windowed retry");
        assert_eq!(
            none, None,
            "must not hit the disk again inside the backoff window"
        );

        // Swap in a succeeding fsync seam: a retry after the window
        // converges to a persist and clears the dirty bit.
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let snaps = Arc::new(Mutex::new(Vec::new()));
        pipe.sync = Arc::new(SimSync(Arc::clone(&model)));
        let recovered = ok(
            pipe.flush_due(2000, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                .await,
            "retry",
        );
        assert!(
            recovered.is_some(),
            "the retry succeeds after the backoff window"
        );
        assert!(!pipe.is_dirty());
    }

    /// Persist-failure injection: fsync succeeds but the PersistWriter
    /// face fails → a `Persist` error, the bitmap stays dirty, and a
    /// retry after the backoff window converges by rewrite (a lost
    /// row write is rewritten by the next snapshot; progress is never
    /// over-counted).
    #[tokio::test]
    async fn persist_failure_keeps_dirty_and_converges_on_retry() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000403", 4, 4 * 1024 * 1024),
                None,
                sync,
            ),
            "pipeline",
        );
        ok(pipe.complete_block(0), "complete 0");
        let sink = Arc::new(FlakySink::new(1));
        let attempt = |sink: Arc<FlakySink>| {
            let sink = Arc::clone(&sink);
            move |_row: HttpTaskRow| {
                let sink = Arc::clone(&sink);
                async move {
                    if sink.take_fail() {
                        Err(StoreError::Internal("injected persist failure".into()))
                    } else {
                        Ok(PersistOutcome::Written)
                    }
                }
            }
        };
        let err = pipe.flush_now(0, attempt(Arc::clone(&sink))).await;
        assert!(
            matches!(err, Err(HttpSnapshotError::Persist(_))),
            "a persist failure must surface as Persist"
        );
        assert!(pipe.is_dirty(), "stays dirty after the persist failure");
        assert_eq!(
            pipe.next_due_ms(1000),
            Some(SNAPSHOT_INTERVAL_MS),
            "a persist failure backs off the same way"
        );
        let outcome = ok(
            pipe.flush_now(2000, attempt(sink)).await,
            "retry after backoff",
        );
        assert_eq!(
            outcome,
            Some(PersistOutcome::Written),
            "the retry converges"
        );
        assert!(!pipe.is_dirty());
    }

    /// NotFound semantics: with completed blocks in the pipeline
    /// (flush is dirty-driven, so reaching the commit point implies a
    /// non-empty completed set), a missing file = declared-complete
    /// bytes missing → the snapshot is refused; the production seam
    /// reports NotFound on a missing file verbatim (never a disguised
    /// Ok).
    #[tokio::test]
    async fn missing_task_file_rejects_snapshot_when_blocks_done() {
        let sync: Arc<dyn TaskFileSync> = Arc::new(MissingFileSync);
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000404", 4, 4 * 1024 * 1024),
                None,
                Arc::clone(&sync),
            ),
            "pipeline",
        );
        ok(pipe.complete_block(1), "complete 1");
        let err = pipe.flush_due(0, no_sink()).await;
        match err {
            Err(HttpSnapshotError::Fsync(StoreError::FileIo { source, .. })) => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected fsync NotFound, got {other:?}"),
        }
        assert!(
            pipe.is_dirty(),
            "stays dirty and retryable after the rejection"
        );
        // Production seam: a missing file's sync() propagates NotFound
        // verbatim (the pipeline decides; never swallowed here).
        let sync_err = sync.sync();
        assert!(sync_err.is_err(), "a missing file must surface NotFound");
    }

    /// Out-of-range blocks / duplicate-completion idempotence /
    /// last-block partial-length accounting / corrupt-geometry row
    /// refusal.
    #[tokio::test]
    async fn complete_block_bounds_idempotence_and_geometry() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let bs = 256 * 1024i64; // the config domain's lowest tier
        // Authoritative total 3.5 blocks: blocks 0..2 whole, block 3
        // half.
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000403", 4, bs),
                Some(3 * bs as u64 + 512),
                sync,
            ),
            "pipeline",
        );
        assert!(ok(pipe.complete_block(2), "complete 2"));
        assert!(
            !ok(pipe.complete_block(2), "complete 2 again"),
            "a duplicate completion = idempotent"
        );
        assert_eq!(pipe.row().total_done, bs, "progress is counted once");
        assert_eq!(pipe.blocks_done(), 1);
        assert_eq!(pipe.blocks_total(), 4);
        assert!(
            matches!(
                pipe.complete_block(9),
                Err(HttpSnapshotError::BlockOutOfRange {
                    block: 9,
                    blocks_total: 4
                })
            ),
            "out-of-bounds block_count is rejected"
        );
        ok(pipe.complete_block(3), "complete last partial");
        assert_eq!(
            pipe.row().total_done,
            bs + 512,
            "the last block is accounted truncated to the authoritative total length"
        );

        // A corrupt-geometry row refuses assembly (bitmap/count
        // unpaired).
        let mut bad = pipeline_row("8000000000000405", 4, bs);
        bad.block_count = None;
        assert!(matches!(
            HttpSnapshotPipeline::new(bad, None, Arc::new(FailingSync)),
            Err(HttpSnapshotError::RowCorrupt)
        ));
    }

    /// Starting from a legal prior state: the `bitmap=None,
    /// count=Some` pre-first-snapshot planned state (after probe grid
    /// creation / after recovery-from-zero cleared the bitmap) — an
    /// old implementation faulted the task permanently on the first
    /// completed block; the current implementation builds the bitmap
    /// lazily: the first block's bookkeeping, snapshot persist, and a
    /// bitmap length aligned to the block grid.
    #[tokio::test]
    async fn pipeline_starts_from_planned_state_without_bitmap() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let snaps = Arc::new(Mutex::new(Vec::new()));
        let bs = 256 * 1024i64;
        // Recovery-chain shape: the recover-from-zero product = a None
        // bitmap, the count kept.
        let mut planned = pipeline_row("8000000000000406", 8, bs);
        planned.block_bitmap = None;
        let mut pipe = ok(
            HttpSnapshotPipeline::new(planned, Some(8 * bs as u64), Arc::clone(&sync)),
            "pipeline from planned state",
        );
        assert_eq!(pipe.blocks_done(), 0, "no bitmap = zero completed");
        ok(pipe.complete_block(0), "first block on empty pipeline");
        ok(pipe.complete_block(3), "second block");
        assert_eq!(pipe.blocks_done(), 2);
        let outcome = ok(
            pipe.flush_now(0, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                .await,
            "flush planned-state pipeline",
        );
        assert!(outcome.is_some());
        let records = snaps.lock().unwrap_or_else(|p| p.into_inner());
        let last = records.last().unwrap_or_else(|| panic!("recorded"));
        assert_eq!(
            last.bitmap.len(),
            1,
            "the lazily built bitmap length aligns with the 8-block grid (ceil(8/8)=1 byte)"
        );
        assert!(bit_test(&last.bitmap, 0) && bit_test(&last.bitmap, 3));
        assert_eq!(pipe.row().block_bitmap.as_deref().map(<[u8]>::len), Some(1));
    }

    /// The terminal exit guard: with a dirty bitmap `into_row`
    /// refuses (an old implementation could carry a full dirty bitmap
    /// straight to terminal persist, bypassing the fsync gate); the
    /// row may be handed over only after flush_now; the state setters
    /// expose only state/error fields and never touch the progress
    /// face.
    #[tokio::test]
    async fn into_row_requires_flush_and_setters_cannot_touch_progress() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let snaps = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000407", 4, 256 * 1024),
                None,
                Arc::clone(&sync),
            ),
            "pipeline",
        );
        ok(pipe.complete_block(0), "complete 0");
        pipe.set_state("done");
        pipe.set_error(None, None);
        // Dirty bits not persisted → terminal row consumption refused
        // (the exit face of the order invariant).
        let guard = pipe.into_row();
        assert!(
            matches!(guard, Err(HttpSnapshotError::UnflushedRow)),
            "a dirty bitmap must flush_now before the row is handed over"
        );
        // into_row takes the capability by value: after refusal the
        // row drops with the Err path — rebuild the pipeline to
        // re-verify the clean exit (the pipeline capability's
        // single-held semantics).
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000407", 4, 256 * 1024),
                None,
                Arc::clone(&sync),
            ),
            "pipeline rebuilt",
        );
        ok(pipe.complete_block(0), "complete 0");
        pipe.set_state("done");
        let flushed = ok(
            pipe.flush_now(0, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                .await,
            "flush before terminal",
        );
        assert!(flushed.is_some());
        let row = ok(pipe.into_row(), "clean into_row");
        assert_eq!(
            row.state, "done",
            "the state written by the setter rides the row"
        );
        assert_eq!(row.block_bitmap.as_deref().map(<[u8]>::len), Some(1));
    }

    /// Power-order injection: multi-seed randomization × delete the
    /// block file + true power-loss simulation, both shapes, zero
    /// errors every round.
    ///
    /// Each round: random block completions (the write face includes
    /// sub-block advances) + synthetic clock advances +
    /// debounced/forced snapshots (the persist seam = the recorder,
    /// the fsync seam = the power-loss model), then a true power loss
    /// (volatile falls back to durable) + three-shape recovery
    /// validation, asserting zero errors every round:
    ///
    /// - **Order invariant** (primary defense evidence, asserted per
    /// beat): every persisted snapshot's completed-block end ≤ the
    /// durable face at persist time — a structural proof of the
    /// pipeline's "fsync first, persist second" order (with the
    /// order inverted, durable would lag the bitmap end and the
    /// assertion would fire);
    /// - **Shape A (prealloc true power loss)**: the file survives at
    /// full length (the size check always passes — the shape where
    /// the second line of defense is powerless) — the persisted
    /// bitmap must still lie entirely within durable, and recovery
    /// trusts it verbatim (an inflated bitmap = zero tolerance);
    /// - **Shape B (truncation injection)**: the file is cut to any
    /// random offset — recovery precisely survives the block set
    /// with "end ≤ file length", all out-of-bounds blocks revert,
    /// and total_done agrees with the surviving bitmap
    /// recomputation; total loss → explicit from zero;
    /// - **Shape C (delete the block file, even rounds)**: `.part`
    /// missing entirely → explicit from zero, bitmap cleared;
    /// - Cost bound: fsync count == actual persist beats.
    #[tokio::test]
    async fn power_order_injection_multi_seed_zero_errors() {
        // Multi-seed randomization: a fixed single seed covers one
        // script only — four independent seeds × 5 rounds, with block
        // geometry / completion order / sub-block advance / cut point
        // / forced-beat timing all drifting; the zero-error criterion
        // holds every round.
        const SEEDS: [u64; 4] = [
            0x7461_6a69_7030_3404,
            0x0b0b_5eed_1337_4200,
            0xdead_beef_cafe_0001,
            0x1234_5678_9abc_def0,
        ];
        const ROUNDS_PER_SEED: u64 = 5;
        const BS: i64 = 4 * 1024 * 1024;
        let mut global_round = 0u64;
        for &seed in &SEEDS {
            let mut rng = Rng(seed);
            for _ in 0..ROUNDS_PER_SEED {
                let round = global_round;
                global_round += 1;
                let block_count = 16 + rng.below(48);
                let total_len = block_count * BS as u64;
                let model = Arc::new(Mutex::new(PowerModel::default()));
                let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
                let snaps = Arc::new(Mutex::new(Vec::new()));
                let mut pipe = ok(
                    HttpSnapshotPipeline::new(
                        pipeline_row(&format!("80000000000005{round:02x}"), block_count, BS),
                        Some(total_len),
                        Arc::clone(&sync),
                    ),
                    "pipeline",
                );

                let mut now: u64 = 0;
                let steps = 5 + rng.below(6);
                for _ in 0..steps {
                    // Randomly complete 1..=4 blocks; advance the
                    // write face to that block's end (the page-cache
                    // face) plus a random sub-block advance (the
                    // in-flight half-block write-face shape).
                    for _ in 0..(1 + rng.below(4)) {
                        let block = rng.below(block_count);
                        if ok(pipe.complete_block(block), "complete") {
                            let end = (block + 1) * BS as u64;
                            let mut m = model.lock().unwrap_or_else(|p| p.into_inner());
                            m.volatile_len = m.volatile_len.max(end);
                        }
                    }
                    {
                        let mut m = model.lock().unwrap_or_else(|p| p.into_inner());
                        m.volatile_len = (m.volatile_len + rng.below(BS as u64 / 2)).min(total_len);
                    }
                    now += rng.below(1600);
                    // A debounced beat; an occasional forced beat (the
                    // saveSession/pause shape).
                    let force = rng.below(4) == 0;
                    let outcome = if force {
                        ok(
                            pipe.flush_now(
                                now,
                                recording_sink(Arc::clone(&model), Arc::clone(&snaps)),
                            )
                            .await,
                            "snapshot",
                        )
                    } else {
                        ok(
                            pipe.flush_due(
                                now,
                                recording_sink(Arc::clone(&model), Arc::clone(&snaps)),
                            )
                            .await,
                            "snapshot",
                        )
                    };
                    if outcome.is_some() {
                        let records = snaps.lock().unwrap_or_else(|p| p.into_inner());
                        let last = records.last().unwrap_or_else(|| panic!("recorded"));
                        let end = bitmap_end(&last.bitmap, block_count, BS as u64);
                        assert!(
                            end <= last.durable_len,
                            "round {round}: bitmap end {end} > fsync-persisted {} — a power-loss bitmap ahead of the data",
                            last.durable_len
                        );
                    }
                }

                // ---- True power loss: volatile lost, durable
                // ---- survives; the "DB row" = the last snapshot.
                {
                    let mut m = model.lock().unwrap_or_else(|p| p.into_inner());
                    m.volatile_len = m.durable_len;
                }
                let (db_bitmap, last_durable, fsyncs) = {
                    let m = model.lock().unwrap_or_else(|p| p.into_inner());
                    let records = snaps.lock().unwrap_or_else(|p| p.into_inner());
                    (
                        records.last().map(|r| r.bitmap.clone()).unwrap_or_default(),
                        m.durable_len,
                        m.fsyncs,
                    )
                };
                assert_eq!(
                    fsyncs,
                    snaps.lock().unwrap_or_else(|p| p.into_inner()).len() as u64,
                    "round {round}: fsync count == snapshot count (the cost bound)"
                );
                let mut db_row = pipeline_row("ignored", block_count, BS);
                db_row.block_bitmap = Some(db_bitmap.clone());
                db_row.total_done = done_blocks(&db_bitmap, block_count) as i64 * BS;
                let persisted_end = bitmap_end(&db_bitmap, block_count, BS as u64);

                // Shape A (prealloc true power loss): the file
                // survives at full length, the size check always
                // passes; bitmap trust comes entirely from the order
                // invariant.
                let rec_a = recover_http_task(
                    &db_row,
                    PartFileFacts {
                        exists: true,
                        len: total_len,
                    },
                    Some(total_len),
                );
                assert!(
                    persisted_end <= last_durable,
                    "round {round}: persisted bitmap end {persisted_end} > durable {last_durable} — a phantom mark"
                );
                assert_eq!(
                    rec_a.resumability,
                    Resumability::FromBitmap {
                        blocks_done: done_blocks(&db_bitmap, block_count)
                    },
                    "round {round}: the prealloc power-loss shape — the snapshotted bitmap is trusted as-is"
                );
                assert_eq!(rec_a.reverted_blocks, 0);
                assert_eq!(
                    rec_a.row.total_done, db_row.total_done,
                    "round {round}: total_done agrees with the bitmap"
                );

                // Shape B (truncation injection): the probed total is
                // unavailable (None — otherwise the length mismatch
                // would re-download everything); per-block cumulative
                // sizes decide exact survival; total_done is
                // recomputed from the surviving bitmap in whole blocks
                // (the no-authoritative-total accounting caliber).
                let cut = rng.below(total_len + 1);
                let rec_b = recover_http_task(
                    &db_row,
                    PartFileFacts {
                        exists: true,
                        len: cut,
                    },
                    None,
                );
                let expected_trusted = (0..block_count)
                    .filter(|b| bit_test(&db_bitmap, *b))
                    .filter(|b| (b + 1) * BS as u64 <= cut)
                    .count() as u64;
                let persisted_done = done_blocks(&db_bitmap, block_count);
                match rec_b.resumability {
                    Resumability::FromBitmap { blocks_done } => {
                        assert_eq!(
                            blocks_done, expected_trusted,
                            "round {round}: exact surviving blocks in the truncation shape"
                        );
                    }
                    Resumability::FromZero { reason } => {
                        assert_eq!(
                            expected_trusted, 0,
                            "round {round}: from-zero means no survivors"
                        );
                        // Total loss: a row with completed blocks =
                        // NoTrustedBlocks; a never-persisted
                        // empty-bitmap row = NoBitmap.
                        assert_eq!(
                            reason,
                            if persisted_done == 0 {
                                ZeroReason::NoBitmap
                            } else {
                                ZeroReason::NoTrustedBlocks
                            },
                            "round {round}: the wipe reason agrees with the persisted state"
                        );
                    }
                }
                assert_eq!(
                    rec_b.reverted_blocks,
                    persisted_done.saturating_sub(expected_trusted),
                    "round {round}: exact rolled-back block count"
                );
                assert_eq!(
                    rec_b.row.total_done,
                    (expected_trusted * BS as u64) as i64,
                    "round {round}: total_done agrees with the recomputed surviving bitmap"
                );

                // Shape C (delete the block file, even-round
                // injection): recovery from zero, zero errors.
                if round % 2 == 0 {
                    let rec_c = recover_http_task(
                        &db_row,
                        PartFileFacts {
                            exists: false,
                            len: 0,
                        },
                        None,
                    );
                    assert_eq!(
                        rec_c.resumability,
                        Resumability::FromZero {
                            reason: ZeroReason::PartFileMissing
                        },
                        "round {round}: deleted-block-file shape -> explicit from-zero"
                    );
                    assert_eq!(rec_c.row.total_done, 0);
                    assert!(
                        rec_c.row.block_bitmap.is_none(),
                        "round {round}: bitmap cleared"
                    );
                }

                // In-memory truth self-consistency (a lost row write
                // does not lose the pipeline's in-memory bitmap; it
                // converges by rewrite).
                assert_eq!(
                    pipe.blocks_done(),
                    pipe.row()
                        .block_bitmap
                        .as_deref()
                        .map_or(0, |bm| done_blocks(bm, block_count)),
                    "round {round}: the in-pipeline memory bitmap is self-consistent"
                );
            }
        }
        assert_eq!(
            global_round,
            SEEDS.len() as u64 * ROUNDS_PER_SEED,
            "scenario round counts are conserved across seeds"
        );
    }

    /// The 16MiB block tier (the config domain's top tier) + the
    /// last-block partial length: the full chain pipeline accounting
    /// → snapshot → recovery validation is bit-exact at 16MiB
    /// granularity.
    #[tokio::test]
    async fn sixteen_mib_block_tier_end_to_end() {
        let model = Arc::new(Mutex::new(PowerModel::default()));
        let sync: Arc<dyn TaskFileSync> = Arc::new(SimSync(Arc::clone(&model)));
        let snaps = Arc::new(Mutex::new(Vec::new()));
        let bs = 16 * 1024 * 1024i64;
        // Total 3.25 blocks @16MiB: blocks 0..2 whole, block 3 a
        // quarter.
        let total = 3 * bs as u64 + bs as u64 / 4;
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                pipeline_row("8000000000000500", 4, bs),
                Some(total),
                Arc::clone(&sync),
            ),
            "pipeline 16MiB",
        );
        assert!(ok(pipe.complete_block(0), "complete 0"));
        assert!(ok(pipe.complete_block(3), "complete last quarter"));
        assert_eq!(
            pipe.row().total_done,
            bs + bs / 4,
            "block 0 whole + block 3 truncated to the authoritative total"
        );
        let outcome = ok(
            pipe.flush_now(0, recording_sink(Arc::clone(&model), Arc::clone(&snaps)))
                .await,
            "flush 16MiB",
        );
        assert!(outcome.is_some());
        // Recovery validation: a full-length prealloc file → the
        // bitmap trusted verbatim.
        let records = snaps.lock().unwrap_or_else(|p| p.into_inner());
        let last = records.last().unwrap_or_else(|| panic!("recorded"));
        let mut db_row = pipeline_row("8000000000000500", 4, bs);
        db_row.block_bitmap = Some(last.bitmap.clone());
        db_row.total_done = pipe.row().total_done;
        let rec = recover_http_task(
            &db_row,
            PartFileFacts {
                exists: true,
                len: total,
            },
            Some(total),
        );
        assert_eq!(
            rec.resumability,
            Resumability::FromBitmap { blocks_done: 2 },
            "the 16MiB-tier bitmap is trusted"
        );
        assert_eq!(rec.reverted_blocks, 0);
        assert_eq!(rec.row.total_done, bs + bs / 4);
    }

    /// The production fsync seam: a real file fsyncs, a missing file
    /// reports NotFound verbatim (the pipeline decides, never a
    /// disguised Ok), a directory path errors (the error carries path
    /// context).
    #[tokio::test]
    async fn part_file_sync_production_faces() {
        let dir = std::env::temp_dir().join(format!(
            "taiji-http-sync-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ok(std::fs::create_dir_all(&dir), "mkdir");

        // Missing file → NotFound propagates verbatim (the pipeline
        // decides on completed-block state).
        let missing = PartFileSync::new(dir.join("absent.bin.part"));
        let err = missing.sync();
        match err {
            Err(StoreError::FileIo { source, .. }) => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected NotFound FileIo, got {other:?}"),
        }

        // Real file: write + fsync succeeds (the pipeline's
        // production path).
        let part = dir.join("f.bin.part");
        ok(std::fs::write(&part, b"0123456789"), "write part");
        ok(PartFileSync::new(part.clone()).sync(), "real fsync");
        assert_eq!(
            ok(std::fs::metadata(&part), "stat").len(),
            10,
            "fsync does not change the file length"
        );

        // A directory path → an explicit error (never a disguised
        // success).
        assert!(PartFileSync::new(dir.clone()).sync().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The disk metrics feeding seam: inject an independent registry
    /// → `PartFileSync::sync` records a
    /// `finalize_seconds{op=file_fsync}` sample (the grid path's 2s
    /// snapshot beat shares the seam with the finalize forced beat);
    /// the failure path (missing file) produces no sample (fsync
    /// never ran).
    #[test]
    fn part_file_sync_feeds_finalize_file_fsync_metric() {
        let dir = std::env::temp_dir().join(format!(
            "taiji-http-fsync-metrics-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        ok(std::fs::create_dir_all(&dir), "mkdir");
        let registry = Arc::new(taiji_io::metrics::MetricsRegistry::new());
        assert_eq!(
            registry.disk().snapshot().finalize_file_fsync.count,
            0,
            "an honest zero-value start"
        );

        let part = dir.join("m.bin.part");
        ok(std::fs::write(&part, b"abcdefgh"), "write part");
        ok(
            PartFileSync::with_metrics(part.clone(), Arc::clone(&registry)).sync(),
            "fsync with metrics",
        );
        let s = registry.disk().snapshot();
        assert_eq!(
            s.finalize_file_fsync.count, 1,
            "sync lands in the file_fsync slot"
        );
        assert_eq!(
            s.finalize_rename.count, 0,
            "the rename/fsync_dir slots are produced only by the finalize orchestration"
        );

        // Failure path: missing file → the error propagates and no
        // new sample (the fsync syscall never happened).
        assert!(
            PartFileSync::with_metrics(dir.join("absent.bin.part"), Arc::clone(&registry))
                .sync()
                .is_err()
        );
        assert_eq!(
            registry.disk().snapshot().finalize_file_fsync.count,
            1,
            "the failure path records no sample (no fsync happened)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The full chain (real sqlite + real file fsync): pipeline
    /// snapshot → PersistWriter persist →
    /// `load_http_tasks_at_startup` read-back → recovery validation
    /// trusts — end-to-end evidence for the http_task recovery read
    /// path (a library-restart equivalent = close all connections
    /// then reopen).
    #[tokio::test]
    async fn snapshot_persist_and_recovery_read_path_end_to_end() {
        let dir = std::env::temp_dir().join(format!(
            "taiji-http-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        ok(std::fs::create_dir_all(&dir), "mkdir");
        let db_path = dir.join("taiji.sqlite3");
        let part = dir.join("f.bin.part");
        let bs = 256 * 1024i64;
        let block_count = 8u64;

        // The `.part` pre-seeded with 2.5 blocks of real data (the
        // physical basis of recovery validation; the truncated shape
        // = the second line of defense's main scenario, probed total
        // unavailable → per-block size checks).
        ok(
            std::fs::write(&part, vec![0u8; 2 * bs as usize + 512]),
            "seed part",
        );

        let (handle, writer) = ok(PersistWriter::spawn(db_path.clone()).await, "spawn writer");
        let model_row = pipeline_row("8000000000000600", block_count, bs);
        let mut pipe = ok(
            HttpSnapshotPipeline::new(
                model_row,
                Some(block_count * bs as u64),
                Arc::new(PartFileSync::new(part.clone())),
            ),
            "pipeline",
        );
        for b in [0u64, 1, 3] {
            ok(pipe.complete_block(b), "complete");
        }
        let outcome = ok(
            pipe.flush_now(0, |row| {
                let handle = handle.clone();
                async move { handle.upsert_http_task(row).await }
            })
            .await,
            "snapshot to real writer",
        );
        assert_eq!(
            outcome,
            Some(PersistOutcome::Written),
            "the first persist = Written"
        );
        drop(handle);
        drop(pipe);
        ok(writer.await, "writer exit");

        // "Restart": reopen the store → the recovery read face →
        // per-task validation.
        let (handle, writer) = ok(
            PersistWriter::spawn(db_path.clone()).await,
            "respawn writer",
        );
        let rows = ok(handle.load_http_tasks_at_startup().await, "recovery read");
        assert_eq!(rows.len(), 1, "the active row reads back");
        assert_eq!(rows[0].row.gid, "8000000000000600");
        assert_eq!(
            done_blocks(
                rows[0].row.block_bitmap.as_deref().unwrap_or(&[]),
                block_count
            ),
            3,
            "bitmap bytes read back bit for bit"
        );
        let part_len = ok(std::fs::metadata(&part), "stat part").len();
        let rec = recover_http_task(
            &rows[0].row,
            PartFileFacts {
                exists: true,
                len: part_len,
            },
            None,
        );
        // Block 3's end (4 blocks) > the file (2.5 blocks) → revert;
        // blocks 0 and 1 survive (the second line of defense).
        assert_eq!(
            rec.resumability,
            Resumability::FromBitmap { blocks_done: 2 },
            "recovery verification rolls back block 3, which has no data behind it"
        );
        assert_eq!(rec.reverted_blocks, 1);
        assert_eq!(
            rec.row.total_done,
            2 * bs,
            "total_done is recomputed from the verified bitmap"
        );
        drop(handle);
        ok(writer.await, "writer exit 2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

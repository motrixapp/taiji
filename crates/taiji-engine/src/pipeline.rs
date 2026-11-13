//! Store pipeline glue (per face): `StoreJob` / `store_pipeline` -
//! build + allocate, then per batch {buffer -> verify -> cross-check ->
//! write completed pieces}.
//!
//! Pooled split: the buffer face (range/dup checks, block-level check
//! work, digest accumulation, cache merge/evict) stays inside the
//! pipeline task, batched and serialized via `spawn_blocking` (light:
//! memcpy + small hashes + bitmaps); the completion face (whole-piece
//! assembly -> primary verify -> cross-check -> disk write) is packaged
//! as [`taiji_store::verified::PieceJob`] and handed to
//! [`crate::verify_pool::VerifyPool`] (N workers in parallel; the
//! libtorrent performance precedent lives in that module's docs).
//! Progress returns to the main loop over a bounded channel.
//!
//! Upstream anchor mapping: docs/design/engine.md
//!
//! Owns: the full path of block data to disk.
//! Does not own: block dispatch, progress-row persistence.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use taiji_store::disk::DiskWriter;
use taiji_store::disk_policy::DiskPolicy;
use taiji_store::error::StoreError;
use taiji_store::hashpool::{ExpectedPieceHash, HashPool};
use taiji_store::layout::Layout;
use taiji_store::merkle;
use taiji_store::precomputed_block_hashes::PrecomputedBlockHashes;
use taiji_store::torrent_writer::TorrentWriter;
use taiji_store::verified::{BlockCheck, CrossRule, PieceJob, PooledOutcome, VerifiedWriter};

use crate::metrics::{BlockStage, SessionMetrics, WrcacheEvent};
use crate::run::peer_connections_max;

use super::dispatch::multi_piece_checkout_cap;
use super::verify_pool::{PoolVerdict, VerifyPool, VerifyPoolConfig};
use crate::config::WriterFactory;
use crate::progress::Progress;
/// Block message (flat piece index + intra-piece offset + data) into
/// the per-face store pipeline. Data is `Bytes`: a zero-copy chain from
/// wire frame decoding (`Bytes::slice`) through peer/transit channels
/// by refcount to here; the single real copy happens when the buffer
/// face returns a cell to the arena.
pub(super) type BlockMsg = (u32, u32, Bytes);

/// Store pipeline inbound block channel capacity (per face; a full
/// channel = backpressure on the peer read loop). Denominator terms for
/// the hash-pool queue-depth gauge (occupancy = capacity - available
/// permits).
pub(super) const BLOCK_CHANNEL_CAPACITY: usize = 256;

/// Upper bound on blocks buffered per `spawn_blocking` batch -
/// amortizes the per-block blocking hop overhead; <= 32 blocks per
/// batch (~512KiB) keeps latency bounded without breaking backpressure
/// semantics. Also the upper bound on completed-piece jobs per batch
/// (<= 32 blocks implies <= 32 pieces) - the basis of the verify_pool
/// verdict-channel capacity exemption from deadlock.
pub(super) const BUFFER_BATCH_BLOCKS: usize = 32;

/// Upper bound on pieces grouped per write: the pipeline flushes a
/// pending group once it reaches this many pieces (no unbounded
/// aggregation). source = a group aggregates only completed pieces of
/// a single batch (<= [`BUFFER_BATCH_BLOCKS`] steps => structural bound
/// of 32 pieces); 4 = 2x headroom over the sequential-supply shape (a
/// 32-block batch is exactly 2 adjacent completed pieces at 256KiB
/// pieces x 16KiB blocks). This constant is also the pieces-per-slot
/// multiplier in the verify_pool verdict-channel capacity formula (see
/// [`crate::verify_pool`]'s deadlock-exemption argument - after
/// grouping, one channel slot can carry several jobs, so capacity must
/// be re-budgeted in pieces, not single-job slots).
pub(super) const PIECE_GROUP_MAX: usize = 4;

/// Block sender attribution bookkeeping ((wire piece, begin) -> cuid;
/// feeds hash-failure attribution). Shared within a face: the attach
/// forward task writes, the main loop reads and clears.
pub(super) type BlockSenders = Arc<Mutex<HashMap<(u32, u32), u64>>>;

/// Live payload of the gated promotion seam (hash recovery): after a
/// missing file's whole layer is admitted, the engine sends the face a
/// full backfill snapshot of expected roots / block-check roots; the
/// pipeline rebuilds [`VerifiedWriter`] live from it (new pool + new
/// block-check table, same disk handle and hash-tree domain), promoting
/// the missing-layer pieces from placeholder zero roots (structurally
/// unverifiable, the gate basis) to real roots, after which the existing
/// download/verify/write paths take over. The payload rides a
/// `tokio::sync::watch` (single value, latest-wins); each send after a
/// file admission carries the fully accumulated array, so replays are
/// idempotent.
#[derive(Debug, Clone)]
pub(super) struct ExpectedRoots {
    /// Flat piece index -> per-piece expected hash (v2 = the real piece root).
    pub(super) expected: Vec<ExpectedPieceHash>,
    /// Flat piece index -> (owning file's pieces root, the piece's first
    /// leaf's in-file leaf index) (the block-check table; a
    /// missing-layer piece's file root is a placeholder zero root before
    /// promotion).
    pub(super) piece_leaves: Arc<Vec<([u8; 32], u64)>>,
}

/// Terminal data-flush barrier state (`tokio::sync::watch` payload).
/// The store pipeline sets the value at its terminal drain point (the
/// drain + fsync segment all exit paths converge on); the engine's
/// `final_flush` (run/tail.rs) waits for `Flushed` before it may
/// persist the terminal progress row.
///
/// Ordering invariant (same terms as the HTTP snapshot pipeline - the
/// `session/http/snapshot.rs` module doc "the outage bitmap never runs
/// ahead of data"; `session/actor/http_task.rs` `part.sync_all` is the
/// same shape on the completion path): **data fsync first, progress-row
/// upsert second**. `Flushed` promises: every dispatched write for this
/// face has returned and the data-file fsync succeeded, and the face
/// will issue no further data writes - every completed-piece byte in a
/// bitmap persisted after this moment is on disk. `Failed` promises:
/// the progress row must be refused (under-record rather than ever
/// over-record; the escalation mirrors the periodic-flush arm's Fatal -
/// a torrent-level failure voids the progress claim, the only
/// difference being that the terminal consumer has already exited, so
/// promotion = refuse the row + a warning log).
#[derive(Debug, Clone)]
pub(super) enum DataFlushState {
    /// The pipeline has not finished its terminal flush (running / before exit).
    Pending,
    /// In-flight writes drained + data-file fsync succeeded - the bitmap row is safe to persist.
    Flushed,
    /// fsync failed / teardown blocking task failed - the terminal progress row is refused.
    Failed(String),
}

/// The fsync face of the regular snapshot write barrier: the pipeline
/// stores this face's write handle (a
/// [`taiji_store::verified::SharedDiskWriter`] clone) in the cell at
/// build time; the engine's autosave arm (run/tick.rs
/// `autosave_snapshot`) fsyncs the data file via
/// `with_exclusive(flush_os_buffers)` - the same exclusive domain as
/// the write hot path, the periodic flush beat, and the terminal
/// barrier (fsync semantics unchanged).
///
/// The engine - not a pipeline select arm - consumes this face: the
/// pipeline can be silently backpressured by the engine main loop (full
/// progress channel -> the pipeline parks in send await), so a barrier
/// request through a pipeline arm would deadlock with "the engine is
/// waiting for the barrier". A `SharedDiskWriter` is an `Arc`+`RwLock`
/// value that shares across tasks anyway, so delivering it through the
/// cell removes the dependency. A promotion rebuild does not swap this
/// handle: completion-face writes always go through the initial shared
/// handle held by the VerifyPool; a rebuilt writer only carries the
/// buffer face - the cell's handle remains the active write domain for
/// this face's data file. Pipeline build failure = the cell stays empty
/// = the engine treats the barrier as failed (fail-closed; see
/// `autosave_snapshot`).
pub(super) type SnapshotSyncCell =
    Arc<std::sync::OnceLock<taiji_store::verified::SharedDiskWriter>>;

/// Parameter bundle for the store pipeline task (one per face).
pub(super) struct StoreJob {
    pub(super) initial_selection: Option<Vec<u32>>,
    pub(super) face: usize,
    pub(super) expected: Vec<ExpectedPieceHash>,
    pub(super) piece_len: u32,
    pub(super) plan_file_lengths: Vec<u64>,
    /// Flat piece index -> disk offset (v2 compact layouts must go through the table).
    pub(super) goffs: Arc<Vec<u64>>,
    /// Cross-check table (hybrid).
    pub(super) cross: Arc<Vec<Option<CrossRule>>>,
    /// v2 per-block check context (None = v1 / whole-piece path).
    pub(super) block_check: Option<BlockCheck>,
    pub(super) dest: PathBuf,
    pub(super) writer_factory: Option<Arc<dyn WriterFactory>>,
    pub(super) layout: Layout,
    /// Recovery face: false = resume from a bitmap (the store already
    /// holds confirmed pieces) -> **skip allocation** (aria2 restarts
    /// with a control file via openExistingFile; O_TRUNC allocation
    /// belongs to brand-new tasks only - an unconditional trunc would
    /// erase downloaded data first, turning the bitmap into a false
    /// claim over lost bytes). true = new task -> create + trunc
    /// allocation.
    pub(super) allocate: bool,
    pub(super) block_rx: mpsc::Receiver<BlockMsg>,
    pub(super) progress_tx: mpsc::Sender<(usize, Progress)>,
    pub(super) token: CancellationToken,
    /// Feed point for verify / WrCache events (piece verified, cache
    /// evicted - visible only inside the pipeline, the main loop never
    /// sees them; None = no feed).
    pub(super) metrics: Option<Arc<SessionMetrics>>,
    /// Live endgame flag (redundancy-economics observation face;
    /// read-only - single writer at the dispatch edge): the criterion
    /// for splitting duplicate/buffer block counts during the window.
    pub(super) endgame_live: Arc<std::sync::atomic::AtomicBool>,
    /// Verify/write worker pool parameters (default [`VerifyPoolConfig::auto`]).
    pub(super) pool: VerifyPoolConfig,
    /// Disk protection policy (three tiers; default throughput =
    /// behaviour unchanged): allocation mode, write coalescing window,
    /// flush beat, IO ops/s quota. Per-torrent overrides resolve through
    /// config_json `disk_tier` ([`DiskPolicy::resolve`]).
    pub(super) disk_policy: DiskPolicy,
    /// disk_tier live face: receiver of policy pushes (the engine command
    /// arm sends on the watch -> this pipeline shifts live) + the applied
    /// readout cell (written after a shift, so QueryDiskPolicy reports
    /// the real effective value).
    pub(super) policy_rx: tokio::sync::watch::Receiver<DiskPolicy>,
    pub(super) live: Arc<taiji_store::disk_policy::LivePolicyCell>,
    /// Gated promotion seam: receiver of the expected-root backfill after
    /// a missing file layer is admitted (None = no v2 base - v1 faces
    /// always have complete expectations, seam unused).
    pub(super) recovery_expected_rx: Option<tokio::sync::watch::Receiver<Arc<ExpectedRoots>>>,
    /// Face-level block buffer pool (None = `BH_BLOCK_ARENA=0` fallback
    /// to direct allocation). Cell construction leases from the pool; a
    /// Drop guard returns the lease; the cap counts against the face's
    /// unverified-byte budget.
    pub(super) block_arena: Option<Arc<taiji_io::block_arena::BlockArena>>,
    /// Pre-registered in-flight block counter (observation face): the
    /// direct sink increments when handing a block over, this pipeline
    /// decrements on settled confirmation (same source as
    /// `FaceState::block_inflight`).
    pub(super) block_inflight: Arc<std::sync::atomic::AtomicU64>,
    /// Batched-ack switch (`BH_BLOCK_BATCH_ACK`, defaults with the main
    /// switch): true = one `Progress::BlocksSettled` at batch end
    /// (engine iterates 1/batch); false = per-block
    /// `Progress::BlockSettled` (the fallback seam, unchanged).
    pub(super) batch_ack: bool,
    /// Terminal data-flush trigger receiver: engine teardown
    /// (run/tail.rs `final_flush`) requests the pipeline's terminal
    /// drain through it (drain in-flight jobs -> data-file fsync -> set
    /// the barrier). The payload is empty (the result rides the barrier
    /// watch; one consumer = this pipeline, one sender = engine
    /// teardown, capacity 1 suffices).
    pub(super) final_flush_rx: mpsc::Receiver<()>,
    /// Terminal data-flush barrier: set on drain completion
    /// ([`DataFlushState`]); the engine's `final_flush` waits for every
    /// face's `Flushed` before persisting terminal progress rows (data
    /// fsync first, progress-row upsert second - invariant in the
    /// [`DataFlushState`] docs).
    pub(super) data_flush_gate: tokio::sync::watch::Sender<DataFlushState>,
    /// Snapshot write-barrier fsync face ([`SnapshotSyncCell`]): the
    /// pipeline fills the write handle after build; the engine's regular
    /// autosave arm consumes it.
    pub(super) snapshot_sync: SnapshotSyncCell,
}

/// One block's result in a buffered batch (order-preserving: the
/// pipeline processes in submission order; evictions precede this
/// block's own result - the serial face's "push -> drain evictions ->
/// process results" order).
struct BatchStep {
    index: u32,
    begin: u32,
    dlen: u32,
    /// Piece indexes evicted by this block's push (registered face, passed through).
    evicted: Vec<u64>,
    /// This block's buffer-face duration (microseconds; instrumentation
    /// - the first cut of the block-push hot path: range/dup checks + v2
    ///   block hash + digest accumulation + cache merge/evict). u32 micros
    ///   caps at ~71 minutes; a per-block duration cannot overflow.
    buffer_us: u32,
    res: Result<PooledOutcome, StoreError>,
}

/// Write-cache sizing seam: lower bound = max of
/// [`taiji_store::cache::DEFAULT_CACHE_LIMIT`] (aria2 `PREF_DISK_CACHE`
/// 16MiB frozen default) and `2 x connection hard cap x piece_len`
/// (sized to the shape; the hard cap is
/// [`crate::run::peer_connections_max`] at runtime - default 120, so
/// 256KiB-piece shapes size to 32 -> 60MiB; `BH_PEER_MAX=64` shrinks
/// back to 32MiB in step). `BH_WR_CACHE_BYTES` can still override
/// explicitly (benchmark/tuning seam; must stay >= the existing 16MiB
/// lower bound).
///
/// Sizing rationale: under verify-before-write the write cache is an
/// assembly buffer for unverified data (not the same shape as aria2's
/// disk write cache - the cache.rs module doc's "intentional
/// divergence"); it drains only when a piece verifies. Aggregate
/// in-flight demand ~= connection cap x per-peer checkout residency
/// (<= 1 piece), so a 2x-cap margin keeps steady-state residency from
/// touching the limit. The cache is a cap, not a preallocation (cells
/// exist only as data arrives): steady-state RSS is unchanged, only the
/// ceiling grows with the cap.
///
/// Pool sizing (same terms as [`wr_cache_limit`]): the face-level block
/// pool cap (bytes). The face's unverified-byte budget = write-cache
/// cap + pool cap (both demand-grown caps, not preallocations;
/// watermarks exposed via the `taiji_block_arena_*` metrics).
/// `BH_BLOCK_ARENA_BYTES` overrides explicitly (tuning seam; 16MiB
/// floor like the write cache); `BH_BLOCK_ARENA=0` = the whole chain
/// falls back to direct allocation (wire decode buffer + cache cell
/// faces, existing behaviour unchanged bit-for-bit). The main bucket's
/// block-count cap = cap / 16KiB (16MiB -> 1024 blocks, ample for the
/// per-connection in-flight window).
pub(super) fn block_arena_for_face(
    piece_len: u32,
) -> Option<Arc<taiji_io::block_arena::BlockArena>> {
    // Knob parsing and read-timing registration live in `taiji_io::knobs`
    // (read at construction; the cache is not modified).
    if !taiji_io::knobs::block_arena_enabled() {
        None
    } else {
        let scaled = peer_piece_product(peer_connections_max(), piece_len);
        let dcl = taiji_store::cache::DEFAULT_CACHE_LIMIT as u64;
        let cap = taiji_io::knobs::block_arena_bytes(dcl, dcl).max(scaled as u64);
        Some(taiji_io::block_arena::BlockArena::new(cap))
    }
}

fn wr_cache_limit(piece_len: u32) -> usize {
    let scaled = peer_piece_product(peer_connections_max(), piece_len);
    let dcl = taiji_store::cache::DEFAULT_CACHE_LIMIT;
    taiji_io::knobs::wr_cache_bytes(dcl, dcl).max(scaled)
}

/// Pure core of the memory-side sizing product `2 x connection hard cap
/// x piece_len` (shared by [`block_arena_for_face`] and
/// [`wr_cache_limit`]; no checkout term - the memory-side formulas
/// intentionally have no checkout term, the [`spill_floor`] doc's note).
/// The whole multiply chain is saturating - no overflow path at usize
/// width (the `BH_PEER_MAX` / `--bt-max-peers` seam may carry extreme
/// values; the sibling spill chain at [`spill_floor`] is saturating for
/// the same reason). The peer cap is given by the caller - the
/// direct-drive seam for the overflow table tests (the real read is a
/// process-level OnceLock that parallel tests cannot set
/// deterministically, the [`crate::run::peer_connections_max`]
/// convention).
fn peer_piece_product(peer_max: usize, piece_len: u32) -> usize {
    (2usize)
        .saturating_mul(peer_max)
        .saturating_mul(piece_len as usize)
}

/// Unverified-spill switch: `BH_SPILL_UNVERIFIED` ("0"/"off"/"false" =
/// off). Default on; the explicit env-off is the fallback seam. Same
/// style as `BH_V2_HASH_PRECOMPUTE`/`BH_ENDGAME_STRICT` (benchmark /
/// fallback seam, not an EngineConfig parameter). Parsing and read
/// timing are registered in `taiji_io::knobs` (read at construction).
fn spill_unverified_enabled() -> bool {
    taiji_io::knobs::spill_unverified_enabled()
}

/// Spill disk budget: default = [`spill_default_limit`]; an explicit
/// `BH_SPILL_BYTES` override wins (a positive value takes effect; parse
/// failure or zero falls back to the default - tuning-seam semantics
/// unchanged).
fn spill_limit(piece_len: u32) -> usize {
    taiji_io::knobs::spill_bytes(spill_default_limit(piece_len))
}

/// Spill budget floor: `max(write-cache sizing, 2 x connection hard cap
/// x checkout cap x piece_len)`.
///
/// Rationale: multi-piece supply pushes each peer's checkout depth to
/// [`multi_piece_checkout_cap`] (single source - the env override and
/// the default move together), so aggregate unverified in-flight demand
/// scales with the checkout depth; without the checkout term,
/// over-limit eviction ("destroy and refetch") becomes the steady state
/// at depth. The 2x margin covers the instantaneous unverified peak
/// while pipe depth doubles (eviction/readback windows misalign). The
/// budget is a cap, not a preallocation (spill sidecar piece files
/// exist only as data arrives, `taiji_store::spill`): the steady disk
/// footprint is unchanged, the ceiling grows by the budget delta - a
/// disk-side, not RSS, term (the memory-side wr_cache/arena sizing
/// formulas intentionally have no checkout term).
///
/// # Fallback
///
/// `BH_SPILL_FIXED=1` = the pre-formula policy bit-for-bit (spill cap =
/// write-cache size; this formula is bypassed entirely). An explicit
/// `BH_SPILL_BYTES` override still wins in the fallback state.
fn spill_default_limit(piece_len: u32) -> usize {
    spill_floor(piece_len, multi_piece_checkout_cap())
}

/// Pure core of the floor formula (checkout cap given by the caller -
/// the direct-drive seam for table tests; the env seams
/// `BH_MULTI_PIECE_SUPPLY_MAX` and the `BH_SPILL_FIXED` fallback live
/// in [`spill_default_limit`]).
fn spill_floor(piece_len: u32, checkout_cap: u64) -> usize {
    let base = wr_cache_limit(piece_len);
    if taiji_io::knobs::spill_fixed_enabled() {
        base
    } else {
        // 2 x cap x checkout x piece_len; the whole multiply chain is
        // saturating - no overflow path at usize width.
        base.max(
            (2usize)
                .saturating_mul(peer_connections_max())
                .saturating_mul(checkout_cap as usize)
                .saturating_mul(piece_len as usize),
        )
    }
}

/// Future for the flush-beat arm (`flush_tick = None` -> pending; the
/// select guard already excludes that shape - this keeps the select
/// arm's type uniform).
async fn flush_beat(tick: &mut Option<tokio::time::Interval>) {
    match tick.as_mut() {
        Some(i) => {
            i.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Precomputed-table gate: only faces with v2 pieces present mount the
/// table (v1 tasks skip - v1 faces have no excess hashing; a hybrid's
/// v1-stream face expects all-V1 and skips too, since block-hash
/// precompute belongs to the v2 content face). Switch
/// `BH_V2_HASH_PRECOMPUTE` ("0"/"off"/"false" = off; default on - a
/// miss falls back to the existing path, behaviourally equivalent).
/// Seam style as `BH_VERIFY_WORKERS`/`BH_ENDGAME_STRICT` (benchmark /
/// fallback seam, not an EngineConfig parameter). Parsing and read
/// timing registered in `taiji_io::knobs` (read at construction).
fn v2_hash_precompute_enabled(expected: &[ExpectedPieceHash]) -> bool {
    if !expected
        .iter()
        .any(|e| matches!(e, ExpectedPieceHash::V2(_)))
    {
        return false;
    }
    taiji_io::knobs::v2_hash_precompute_enabled()
}

/// Store pipeline task (reworked + pooled): build + allocate -> per
/// batch {buffer} (blocking face on `spawn_blocking`) -> completed
/// pieces handed to the worker pool {verify -> cross-check -> write}.
/// A full block channel or pool = backpressure on the peer read loop.
///
/// Disk-policy enforcement face (default = throughput: every parameter
/// keeps existing behaviour, zero change): (1) new tasks allocate per
/// [`DiskPolicy::allocation`] (trunc as before / falloc reserve with
/// fallback / prealloc zero fill; per-file effect logging on the store
/// side); (2) write coalescing rides [`VerifiedWriter::with_disk_policy`]
/// into each [`PieceJob`]; (3) the flush beat (periodic fsync, sharing
/// the `taiji_store::disk_policy::IoGate` ops quota with the read
/// service - beat staggering + fair quota).
pub(super) async fn store_pipeline(job: StoreJob) {
    let StoreJob {
        initial_selection,
        face,
        expected,
        piece_len,
        plan_file_lengths,
        goffs,
        cross,
        block_check,
        dest,
        writer_factory,
        layout,
        allocate,
        mut block_rx,
        progress_tx,
        token,
        metrics,
        endgame_live,
        pool: pool_cfg,
        disk_policy,
        mut policy_rx,
        live,
        mut recovery_expected_rx,
        block_arena,
        block_inflight,
        batch_ack,
        mut final_flush_rx,
        data_flush_gate,
        snapshot_sync,
    } = job;
    let piece_count = expected.len();
    // v2 block-hash precompute table gate (constant for the face's
    // lifetime, read before build - `expected` moves into the build
    // closure, so decide first).
    let v2_precompute = v2_hash_precompute_enabled(&expected);
    // Unverified-spill switch (constant for the face's lifetime; the
    // same source for initial build and promotion rebuild).
    let spill_on = spill_unverified_enabled();
    // Build materials for the gated promotion rebuild (cloned before the
    // first build closure moves them; rebuild and initial build share
    // the same sources - factory/TorrentWriter do not allocate on open,
    // see the promotion arm). swap_trees reuses the same
    // Arc<Mutex<HashTreeCache>>: the anchor domain written at admission
    // is visible to old and new writers alike (same trust level).
    let swap_trees = block_check.as_ref().map(|c| c.trees.clone());
    let swap_factory = writer_factory.clone();
    let swap_layout = layout.clone();
    let swap_dest = dest.clone();
    let swap_cross = Arc::clone(&cross);
    let swap_plan_lens = plan_file_lengths.clone();
    // Pooled face shared with the rebuild (the rebuilt writer uses the
    // same pool - free lists shared; cell reuse is not broken by
    // promotion).
    let swap_arena = block_arena.clone();
    let built = tokio::task::spawn_blocking(move || -> Result<VerifiedWriter, String> {
        // Spill directory source (dest is moved by TorrentWriter in the
        // None arm, before the spill open - clone first).
        let spill_dest = dest.clone();
        let disk: Box<dyn DiskWriter> = match writer_factory {
            Some(f) => {
                let mut w = f.build(&layout, &dest).map_err(|e| e.to_string())?;
                // trait create() delegates TorrentWriter::allocate
                // (allocation is a blocking face); resume runs skip it
                // (StoreJob::allocate docs). The factory hook (loopback
                // benchmark injection) keeps its semantics - allocation
                // follows the hook's own implementation; only the
                // standard path (None) uses tier allocation.
                if allocate {
                    w.create(&dest).map_err(|e| e.to_string())?;
                }
                w
            }
            None => {
                let mut w = TorrentWriter::new(layout, dest, 100);
                if allocate {
                    // Allocation follows the tier (trunc = existing
                    // behaviour; falloc / prealloc semantics and
                    // platform capability notes in the store
                    // disk_policy).
                    if let Err(e) = w.allocate_selected_with(
                        disk_policy.allocation,
                        initial_selection.as_deref(),
                    ) {
                        return Err(e.to_string());
                    }
                }
                Box::new(w)
            }
        };
        let pool = HashPool::new_plan(expected, piece_len, &plan_file_lengths)
            .map_err(|e| e.to_string())?;
        let vw =
            VerifiedWriter::with_cross(disk, pool, wr_cache_limit(piece_len), (*cross).clone())
                // Write coalescing window from the policy (0 = per-cell existing behaviour).
                .with_disk_policy(disk_policy)
                // Cells lease from the face-level block pool (None = direct-alloc fallback).
                .with_block_arena(block_arena.clone());
        // Unverified spill area (switch `BH_SPILL_UNVERIFIED` default
        // on; see the taiji_io::knobs registry). The face directory is
        // built lazily, residue cleanup best-effort (open must not
        // fail); IO failures inside the spill face degrade to
        // destroy-and-refetch inside the store, never fatal.
        // Same-dest exclusivity - face lock held (a live task on the
        // same dest / a stale process) -> None = no spill this run (the
        // destroy-and-refetch status quo), the task is unaffected.
        let vw = if spill_on {
            match taiji_store::spill::SpillStore::open_for_dest(
                &spill_dest,
                face,
                spill_limit(piece_len),
            ) {
                Some(s) => vw.with_spill(s),
                None => vw,
            }
        } else {
            vw
        };
        // v2 faces mount the block-hash precompute table (computed once
        // on the write path; completion-piece verification looks up with
        // zero re-reads; cross-checked against libtorrent
        // precomputed_block_hashes - provenance note in that module's
        // docs). Table capacity is fixed by the piece's 16KiB block
        // count.
        let vw = if v2_precompute {
            vw.with_precomputed_block_hashes(PrecomputedBlockHashes::new(merkle::blocks_per_piece(
                piece_len,
            ) as usize))
        } else {
            vw
        };
        Ok(match block_check {
            Some(check) => vw.with_block_check(check),
            None => vw,
        })
    })
    .await;
    let mut vw_opt: Option<VerifiedWriter> = match built {
        Ok(Ok(v)) => Some(v),
        Ok(Err(e)) => {
            let _ = progress_tx
                .send((face, Progress::Fatal(format!("allocate: {e}"))))
                .await;
            // Build failure: this face wrote no data, but the barrier
            // must still be set - the engine's terminal-row wait point
            // must not hang; Failed = the terminal progress row is
            // refused (recheck catches it during recovery; the safe
            // direction).
            data_flush_gate.send_replace(DataFlushState::Failed(format!("allocate: {e}")));
            return;
        }
        Err(e) => {
            let _ = progress_tx
                .send((face, Progress::Fatal(format!("store task join: {e}"))))
                .await;
            data_flush_gate.send_replace(DataFlushState::Failed(format!("store task join: {e}")));
            return;
        }
    };

    // Completed-piece job pool (the parallel verify/write face). The
    // write handle is taken once at build time and shares the same
    // underlying file handle as the VerifiedWriter inline path.
    let mut pool = {
        let v = vw_opt
            .as_ref()
            .unwrap_or_else(|| unreachable!("built above"));
        VerifyPool::new(v.writer_handle(), pool_cfg)
    };
    // disk_tier live face: baseline = the watch's CURRENT value (not the
    // build-time policy captured at destructure - the engine command arm
    // may have shifted gears during the spawn_blocking build; the
    // watch's current value is the latest effective fact; borrowing also
    // marks seen, so later changed() fires only on real shifts). The
    // readout cell syncs with the baseline (queries see the real value
    // from the start).
    let baseline = *policy_rx.borrow_and_update();
    live.store(&baseline);
    // Flush beat + read/write shared IO quota bucket (throughput default
    // = no beat + unlimited, existing behaviour unchanged). The write
    // handle is cloned for the beat arm's fsync (same underlying handle
    // as pool workers / inline writes; the mutex guards only the
    // syscall).
    let flush_handle = vw_opt
        .as_ref()
        .unwrap_or_else(|| unreachable!("built above"))
        .writer_handle();
    // Hand the write handle to the engine snapshot barrier face (OnceLock
    // single fill - the cell is new per face, reset unreachable; staying
    // empty = the build-failure path returned above).
    let _ = snapshot_sync.set(flush_handle.clone());
    let io_gate = Arc::new(taiji_store::disk_policy::IoGate::new(
        baseline.io_ops_per_sec,
    ));
    let mut flush_tick = baseline.flush_interval.map(|d| {
        // interval_at: first tick after d (interval()'s immediate first
        // tick would miss the first beat-window semantics).
        tokio::time::interval_at(tokio::time::Instant::now() + d, d)
    });
    // Local anchors of the currently effective beat / merge window
    // (compared on watch shifts; the reset values after batch return).
    let mut cur_flush = baseline.flush_interval;
    let mut cur_merge = baseline.write_merge_max_bytes;
    // Write coalescing switch (`BH_WRITE_COALESCE`, default on; read
    // once from the process env - same source as the [`VerifiedWriter`]
    // write face; off = no intra-batch grouping, completed pieces
    // dispatch immediately = the status quo bit-for-bit).
    let write_coalesce = taiji_store::verified::write_coalesce_enabled();

    // The write pipeline's own verified bitmap: the late-block drop
    // decision. From now on the set point = hash-pass (the write may
    // still be in flight - data is verified and the cell left with the
    // job, so a late re-buffer is pure redundancy; the main-loop bitmap
    // converges via progress events while this one is authoritative - a
    // second response for the same piece hits PieceAlreadyComplete after
    // write serialization and is dropped benignly all the same).
    let mut writer_verified = vec![false; piece_count];
    // Received-block bitmap (first duplicate filter; the caller is the
    // push_block upstream, aligned with aria2's receive-path filter
    // architecture `BtPieceMessage.cc` `piece->hasBlock(...)` -> "Already
    // have this block."): flat piece index -> set of buffered begins.
    // Converges with piece results: cleared on piece complete/fail/abort
    // (piece reset and refetch); a rejected block is removed so it can
    // be redispatched; the store coverage backstop (`DuplicateDropped`)
    // runs after. Duplicate sources = cross-peer redispatch (the same
    // coordinate requested from a second peer inside the 2s redispatch
    // window, each RequestBook holding its own slot and answering).
    let mut received: HashMap<u64, std::collections::HashSet<u32>> = HashMap::new();
    let mut dup_drops: u64 = 0;
    // Instrumentation: evicted-unverified-piece counter (registered in
    // VerifiedWriter step 4, drained here). Evictions used to be purely
    // silent events (debug-level log + no progress event) - this counter
    // is the observation face for that loop.
    let mut evictions: u64 = 0;
    // Unified terminal exit: every exit path (token / channel close /
    // Fatal / engine terminal flush trigger) converges through the
    // `'run` break on the drain + fsync barrier segment after the loop -
    // the data-half ordering invariant lives there and in the
    // [`DataFlushState`] docs.
    'run: loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => break 'run,
            // Terminal flush trigger arm: the engine teardown request
            // (channel close = the engine side is gone - the same
            // "None = teardown" convention as the block receive arm; it
            // also falls into this break and the barrier segment).
            _ = final_flush_rx.recv() => break 'run,
            // disk_tier live apply arm (taiji.setDiskTier -> engine
            // SetDiskPolicy -> watch single-value channel -> this
            // pipeline shifts all three parameters immediately):
            // (1) the IoGate ops quota (Arc-shared - the read service
            // and the write flush shift the same bucket at once);
            // (2) the flush beat (None<->Some rebuilds the interval,
            // first tick after the new beat - interval_at semantics as
            // at build);
            // (3) the write merge window (the batch arm holds the writer
            // inside blocking tasks, so this arm cannot reach it -
            // cur_merge is re-applied when the batch returns; no lost
            // update). The allocation mode does not shift live (applies
            // to new allocations only - command doc semantics).
            updated = policy_rx.changed() => match updated {
                Ok(()) => {
                    let p = *policy_rx.borrow_and_update();
                    io_gate.set_rate(p.io_ops_per_sec);
                    if cur_flush != p.flush_interval {
                        flush_tick = p.flush_interval.map(|d| {
                            tokio::time::interval_at(
                                tokio::time::Instant::now() + d,
                                d,
                            )
                        });
                        cur_flush = p.flush_interval;
                    }
                    cur_merge = p.write_merge_max_bytes;
                    if let Some(v) = vw_opt.as_mut() {
                        v.set_write_merge_max(cur_merge);
                    }
                    live.store(&p);
                    debug!(target: "taiji::core::engine::store", face,
                        ops = p.io_ops_per_sec,
                        flush_secs = p.flush_interval.map(|d| d.as_secs()).unwrap_or(0),
                        merge = p.write_merge_max_bytes,
                        "disk policy applied live (disk tier)");
                }
                // All senders dropped (engine teardown race): this arm
                // parks forever; the pipeline converges on the existing
                // exit faces (token / channel close).
                Err(_) => std::future::pending::<()>().await,
            },
            // Gated promotion seam (biased order, ahead of the data
            // arms - a queued expected-root backfill applies before the
            // next batch of blocks, closing any window where new blocks
            // would verify against placeholder zero roots): after a
            // missing file's whole layer is admitted, the engine
            // backfills real roots -> this arm rebuilds VerifiedWriter
            // live (new HashPool + new block-check table, same disk
            // handle and hash-tree domain). The write cache is destroyed
            // with the old writer (destruction discipline: unverified
            // data never reaches disk; the rebuild is a full eviction -
            // the face-level form of the same semantics) - `received`
            // clears in step, and the engine clears the dispatch
            // in-flight / buffered / refetch books when sending the
            // backfill (recovery activation chain); unsettled bytes are
            // re-fetched by the existing dispatch paths. Cross-check:
            // libtorrent persists recovery trees with the resume data
            // (torrent.cpp) as the restart path; here the promotion is
            // live within the session (no restart).
            maybe_roots = async {
                match recovery_expected_rx.as_mut() {
                    Some(rx) => {
                        // All senders dropped (engine teardown race) ->
                        // park forever (teardown is driven by the token
                        // arm; prevents an Err busy loop).
                        if rx.changed().await.is_err() {
                            std::future::pending::<()>().await;
                        }
                        Some(rx.borrow_and_update().clone())
                    }
                    None => std::future::pending().await,
                }
            } => {
                let Some(roots) = maybe_roots else {
                    continue;
                };
                // Select arms do not run concurrently across the batch
                // await; vw_opt is always present here (the in-batch take
                // and return complete in the same arm; the Fatal path
                // already returned).
                if vw_opt.is_some() {
                    // Destroy the old writer first (releases its spill
                    // face lock) - the rebuilt spill open must re-acquire
                    // the same face lock and would fail while the old
                    // writer lives (the face lock is exclusive). This
                    // makes the promotion destruction discipline ("the
                    // write cache dies with the old writer") explicit in
                    // time: destroy before rebuild; select arms do not
                    // run concurrently during the await, so there is no
                    // third observer.
                    drop(vw_opt.take());
                    let factory = swap_factory.clone();
                    let layout = swap_layout.clone();
                    let dest = swap_dest.clone();
                    let trees = swap_trees.clone();
                    let leaves = Arc::clone(&roots.piece_leaves);
                    let cross_tbl = (*swap_cross).clone();
                    let plan_lens = swap_plan_lens.clone();
                    let arena = swap_arena.clone();
                    // Blocking-face rebuild sharing the initial build's
                    // sources (disk open + pool plan). Write-handle
                    // independence: completion-face writes go through the
                    // shared handle held by the VerifyPool (a clone of the
                    // initial build's writer_handle); this rebuilt writer
                    // Box belongs to the inline path (the pooled pipeline
                    // never writes with it) - positional writes to the
                    // same dest, so the handle generation swap has no
                    // literal effect.
                    let rebuilt = tokio::task::spawn_blocking(
                        move || -> Result<VerifiedWriter, String> {
                            // Spill directory source (dest is moved by
                            // TorrentWriter in the None arm, before the
                            // spill open - clone first).
                            let spill_dest = dest.clone();
                            let disk: Box<dyn DiskWriter> = match factory {
                                Some(f) => {
                                    let w = f
                                        .build(&layout, &dest)
                                        .map_err(|e| e.to_string())?;
                                    // Rebuild does not allocate: the file
                                    // was allocated at the initial build;
                                    // trunc would erase downloaded data
                                    // (same semantics as StoreJob::
                                    // allocate = false).
                                    w
                                }
                                None => Box::new(TorrentWriter::new(layout, dest, 100)),
                            };
                            let pool = taiji_store::hashpool::HashPool::new_plan(
                                roots.expected.clone(),
                                piece_len,
                                &plan_lens,
                            )
                            .map_err(|e| e.to_string())?;
                            let vw = VerifiedWriter::with_cross(
                                disk,
                                pool,
                                wr_cache_limit(piece_len),
                                cross_tbl,
                            );
                            // Rebuild mounts the table the same way as
                            // the initial build (new writer = new table;
                            // the write cache died with the old writer and
                            // in-flight pieces re-enter after refetch - no
                            // stale slots).
                            let vw = if v2_hash_precompute_enabled(&roots.expected) {
                                vw.with_precomputed_block_hashes(PrecomputedBlockHashes::new(
                                    merkle::blocks_per_piece(piece_len) as usize,
                                ))
                            } else {
                                vw
                            };
                            // Rebuild leases from the face-level block pool, same source.
                            let vw = vw.with_block_arena(arena);
                            // Rebuild mounts the spill area from the same
                            // source (the old writer's drop already
                            // cleaned its face directory; the new store
                            // rebuilds lazily - the "write cache dies with
                            // the old writer" discipline covers the spill
                            // face naturally).
                            // Face lock held / lock open failure -> no
                            // spill face (the initial build's degraded
                            // semantics).
                            let vw = if spill_on {
                                match taiji_store::spill::SpillStore::open_for_dest(
                                    &spill_dest,
                                    face,
                                    spill_limit(piece_len),
                                ) {
                                    Some(s) => vw.with_spill(s),
                                    None => vw,
                                }
                            } else {
                                vw
                            };
                            Ok(match trees {
                                Some(trees) => vw.with_block_check(BlockCheck {
                                    piece_leaves: leaves,
                                    trees,
                                }),
                                None => vw,
                            })
                        },
                    )
                    .await;
                    match rebuilt {
                        Ok(Ok(mut fresh)) => {
                            fresh.set_write_merge_max(cur_merge);
                            vw_opt = Some(fresh);
                            received.clear();
                            info!(target: "taiji::core::engine::store", face,
                                "recovered expected roots applied live: write cache \
                                 discarded, pieces re-armed for dispatch (C-3)");
                        }
                        Ok(Err(e)) => {
                            let _ = progress_tx
                                .send((face, Progress::Fatal(format!(
                                    "recovery expected roots rebuild: {e}"))))
                                .await;
                            break 'run;
                        }
                        Err(e) => {
                            let _ = progress_tx
                                .send((face, Progress::Fatal(format!(
                                    "recovery rebuild blocking task: {e}"))))
                                .await;
                            break 'run;
                        }
                    }
                }
            }
            // Flush beat: periodic fsync (with flush_interval = None this
            // arm is never ready; existing behaviour unchanged). The fsync
            // runs in its own blocking task and shares the ops quota with
            // the read service (ticket first - fair quota); completion and
            // failure return over the progress channel (errors are
            // torrent-level Fatal, same as the write path: disk write
            // errors carry context).
            _ = flush_beat(&mut flush_tick), if flush_tick.is_some() => {
                let handle = flush_handle.clone();
                let gate = Arc::clone(&io_gate);
                let tx = progress_tx.clone();
                tokio::spawn(async move {
                    gate.acquire(1).await;
                    let res = tokio::task::spawn_blocking(move || {
                        // Write-external ops take the exclusive domain
                        // (fsync semantics and timing unchanged - the
                        // spec red line; mutually exclusive with the write
                        // hot path).
                        handle.with_exclusive(|g| g.flush_os_buffers())
                    })
                    .await;
                    match res {
                        Ok(Ok(())) => {
                            debug!(target: "taiji::core::engine::store",
                                face, "periodic fsync done (disk policy flush beat)");
                        }
                        Ok(Err(e)) => {
                            let _ = tx.send((face, Progress::Fatal(format!("fsync: {e}")))).await;
                        }
                        Err(e) => {
                            let _ = tx.send((face, Progress::Fatal(format!("fsync join: {e}")))).await;
                        }
                    }
                });
            }
            // Completion-face verdicts (ahead of inbound blocks: drain
            // workers first; a finished write returns progress to the
            // main loop immediately). Two phases: Verified (hash-pass)
            // first - the main loop broadcasts HAVE right away (libtorrent
            // passed->have); Written (on disk) completes - upload gating /
            // persistence / completion decisions.
            res = pool.recv() => match res {
                None => break 'run, // pool stopped (pipeline teardown)
                Some(result) => {
                    match result.verdict {
                        PoolVerdict::Verified => {
                            let index = result.piece;
                            // Late-block drop gate moved up to hash-pass:
                            // the data is verified and the cell left with
                            // the job to the worker, so a late re-buffer is
                            // pure redundancy (a piece re-completion is
                            // also dropped benignly by PieceAlreadyComplete
                            // - moving the gate only moves the drop point,
                            // no new paths).
                            if (index as usize) < piece_count {
                                writer_verified[index as usize] = true;
                            }
                            received.remove(&index);
                            debug!(target: "taiji::core::engine::store", face,
                                index = result.piece, "piece hash verified (advertise early, write in flight)");
                            // Verified block count (16KiB granularity,
                            // tail piece prorated by bytes) - counted at
                            // hash-pass (verified terms).
                            if let Some(m) = metrics.as_ref() {
                                m.add_blocks_verified(
                                    result.bytes.div_ceil(u64::from(merkle::BLOCK_SIZE)),
                                );
                            }
                            // Instrumentation: verify-segment duration
                            // histogram (rides the Verified phase; the
                            // write segment rides Written).
                            if let Some(m) = metrics.as_ref() {
                                m.observe_block_stage(
                                    BlockStage::Verify,
                                    Duration::from_micros(result.verify_us),
                                );
                            }
                            if progress_tx
                                .send((face, Progress::PieceVerified {
                                    index: u32::try_from(result.piece).unwrap_or(u32::MAX),
                                }))
                                .await
                                .is_err()
                            {
                                break 'run;
                            }
                        }
                        PoolVerdict::Written => {
                            debug!(target: "taiji::core::engine::store", face,
                                index = result.piece, "piece written");
                            // WrCache flush (piece on disk) counter rides
                            // the Written phase (the real on-disk moment,
                            // flushed terms).
                            if let Some(m) = metrics.as_ref() {
                                m.note_wrcache(WrcacheEvent::Flush);
                                // Write-segment observation rides the first
                                // Written of each group (granularity = the
                                // write call - a group writes the whole
                                // group once; the fallback face's
                                // single-job write carries per piece, the
                                // existing terms). The write-call count
                                // feeds the per-block counter (the
                                // cross-check face of "write syscalls per
                                // block").
                                if let Some((us, calls)) = result.write {
                                    m.observe_block_stage(
                                        BlockStage::Write,
                                        Duration::from_micros(us),
                                    );
                                    m.note_store_write_calls(calls);
                                }
                            }
                            if progress_tx
                                .send((face, Progress::PieceWritten {
                                    index: u32::try_from(result.piece).unwrap_or(u32::MAX),
                                }))
                                .await
                                .is_err()
                            {
                                break 'run;
                            }
                        }
                        PoolVerdict::HashMismatch => {
                            debug!(target: "taiji::core::engine::store", face,
                                index = result.piece,
                                "piece hash mismatch: dropped for re-fetch");
                            // Instrumentation: a failed piece's verify
                            // duration also enters the histogram (disk
                            // never touched -> the write segment stays
                            // honestly zero, not fed).
                            if let Some(m) = metrics.as_ref() {
                                m.observe_block_stage(
                                    BlockStage::Verify,
                                    Duration::from_micros(result.verify_us),
                                );
                            }
                            // Pool reset: the verdict was produced on a
                            // worker; the serial path's finish_piece
                            // failure reset rides the verdict back to the
                            // pipeline - without clearing, refetched blocks
                            // keep hitting the benign PieceAlreadyComplete
                            // drop and the piece can never complete again
                            // (a stalled-progress loop).
                            if let Some(v) = vw_opt.as_mut() {
                                v.reset_failed_piece(result.piece);
                            }
                            received.remove(&result.piece);
                            if progress_tx
                                .send((face, Progress::PieceDropped {
                                    index: u32::try_from(result.piece).unwrap_or(u32::MAX),
                                    reason: "hash mismatch".into(),
                                    // smart_ban evidence chain: per-block
                                    // SHA-1 snapshots of the failed piece
                                    // ride the event up (worker-produced;
                                    // None = v2 / other paths - v2's
                                    // per-block check attributes naturally,
                                    // smart_ban is bypassed).
                                    digests: result.failed_digests,
                                }))
                                .await
                                .is_err()
                            {
                                break 'run;
                            }
                        }
                        PoolVerdict::CrossInconsistent(e) => {
                            // BEP52 dual-hash inconsistency: a metadata
                            // contradiction, torrent-level failure (BEP52
                            // "If any inconsistency is detected they may
                            // either abort or fall back" - this side
                            // chooses abort).
                            let _ = progress_tx
                                .send((face, Progress::Fatal(format!(
                                    "hybrid cross-check failed at piece {}: \
                                     v1/v2 hashes inconsistent (BEP52)", e.piece))))
                                .await;
                            break 'run;
                        }
                        PoolVerdict::WriteFailed(e) => {
                            let _ = progress_tx
                                .send((face, Progress::Fatal(format!("push_block: {e}"))))
                                .await;
                            break 'run;
                        }
                        PoolVerdict::JoinFailed(e) => {
                            let _ = progress_tx
                                .send((face, Progress::Fatal(format!(
                                    "store blocking task: {e}"))))
                                .await;
                            break 'run;
                        }
                    }
                }
            },
            item = block_rx.recv() => match item {
                None => break 'run, // main loop teardown (block_tx dropped)
                Some((index, begin, data)) => {
                    if writer_verified[index as usize] {
                        debug!(target: "taiji::core::engine::store", face, index, begin,
                            "late block for verified piece: dropped");
                        continue;
                    }
                    // Benign duplicate drop (first gate): a same-
                    // coordinate delivery already in the cache is dropped
                    // unconditionally and counted (an uncounted drop = a
                    // swallowed error).
                    if received.entry(u64::from(index)).or_default().contains(&begin) {
                        dup_drops += 1;
                        if let Some(m) = metrics.as_ref() {
                            m.note_duplicate_blocks(1);
                            // Redundancy-economics observation: the
                            // endgame-window subset (the live flag has a
                            // single writer at the dispatch edge;
                            // observation only).
                            if endgame_live.load(std::sync::atomic::Ordering::Relaxed) {
                                m.note_duplicate_blocks_endgame(1);
                            }
                        }
                        if dup_drops <= 10 || dup_drops % 100 == 0 {
                            debug!(target: "taiji::core::engine::store", face, index,
                                begin, drops = dup_drops,
                                "duplicate block (received bitmap): dropped benignly");
                        }
                        continue;
                    }
                    let goff = goffs
                        .get(index as usize)
                        .copied()
                        .unwrap_or_else(|| unreachable!("goff table indexed by flat piece"));
                    // Batch buffering: the first block + best-effort drain
                    // of ready channel blocks (<= BUFFER_BATCH_BLOCKS) in
                    // one spawn_blocking - amortizes the per-block blocking
                    // hop overhead.
                    let dlen = data.len() as u32;
                    let mut batch: Vec<(u32, u32, u32, u64, Bytes)> =
                        Vec::with_capacity(BUFFER_BATCH_BLOCKS);
                    batch.push((index, begin, dlen, goff + u64::from(begin), data));
                    // Buffered-block accounting during the endgame window
                    // (redundancy-economics denominator family - paired
                    // with the duplicate-block subset to form "duplicate
                    // received / total received". The flag is read at batch
                    // assembly; the criterion boundary is one batch depth).
                    if endgame_live.load(std::sync::atomic::Ordering::Relaxed)
                        && let Some(m) = metrics.as_ref()
                    {
                        m.note_buffered_blocks_endgame(1);
                    }
                    while batch.len() < BUFFER_BATCH_BLOCKS {
                        match block_rx.try_recv() {
                            Ok((i2, b2, d2)) => {
                                if writer_verified[i2 as usize] {
                                    debug!(target: "taiji::core::engine::store", face,
                                        index = i2, begin = b2,
                                        "late block for verified piece: dropped");
                                    // Count: late blocks for verified
                                    // pieces (previously uncounted wire
                                    // amplification; the criterion face of
                                    // the cancel-on-verified fix).
                                    if let Some(m) = metrics.as_ref() {
                                        m.note_late_blocks_verified(1);
                                    }
                                    continue;
                                }
                                if received.entry(u64::from(i2)).or_default().contains(&b2) {
                                    dup_drops += 1;
                                    if let Some(m) = metrics.as_ref() {
                                        m.note_duplicate_blocks(1);
                                    // endgame-window subset.
                                        if endgame_live
                                            .load(std::sync::atomic::Ordering::Relaxed)
                                        {
                                            m.note_duplicate_blocks_endgame(1);
                                        }
                                    }
                                    continue;
                                }
                                let g2 = goffs
                                    .get(i2 as usize)
                                    .copied()
                                    .unwrap_or_else(|| {
                                        unreachable!("goff table indexed by flat piece")
                                    });
                                batch.push((i2, b2, d2.len() as u32, g2 + u64::from(b2), d2));
                                // endgame-window buffered-block accounting
                                // (denominator family, as above).
                                if endgame_live.load(std::sync::atomic::Ordering::Relaxed)
                                    && let Some(m) = metrics.as_ref()
                                {
                                    m.note_buffered_blocks_endgame(1);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let vwo = vw_opt.take();
                    // Instrumentation: read the evicted-byte accumulators
                    // before and after the batch (the delta is exact -
                    // VerifiedWriter is only touched inside this
                    // single-writer spawn_blocking batch), fed to /metrics
                    // with the batch result.
                    let evict_bytes_base = vwo
                        .as_ref()
                        .map(VerifiedWriter::evicted_unverified_bytes)
                        .unwrap_or(0);
                    // Observation baselines (same delta method): spill
                    // write bytes / read bytes / readback pieces, plus the
                    // over-budget fallback-destroy bytes, snapshotted
                    // before the batch.
                    let spill_base = vwo
                        .as_ref()
                        .map(|v| {
                            (
                                v.spill_write_bytes(),
                                v.spill_read_bytes(),
                                v.spill_readback_pieces(),
                                v.spill_fallback_destroy_bytes(),
                            )
                        })
                        .unwrap_or((0, 0, 0, 0));
                    let res = tokio::task::spawn_blocking(move || {
                        let mut v =
                            vwo.unwrap_or_else(|| unreachable!("writer round-trip"));
                        // goff convention = piece base + intra-piece
                        // offset (the push_block_at contract: cells and
                        // cross-checks fold by whole-block global offset).
                        // Completed pieces are packaged into jobs right in
                        // the buffer step (verify/write handed to the pool).
                        let mut steps = Vec::with_capacity(batch.len());
                        for (index, begin, dlen, goff, data) in batch {
                            // Buffer-face duration (2x Instant::now per
                            // block ~= hundreds of ns - a negligible
                            // hot-path cost; per-block tracing spans and
                            // formatted allocations are forbidden).
                            let t = Instant::now();
                            let res = v.push_block_pooled_at(
                                u64::from(index),
                                goff,
                                begin,
                                &data,
                            );
                            let buffer_us =
                                u32::try_from(t.elapsed().as_micros()).unwrap_or(u32::MAX);
                            let evicted = v.take_evicted();
                            steps.push(BatchStep { index, begin, dlen, evicted, buffer_us, res });
                        }
                        let evicted_delta = v
                            .evicted_unverified_bytes()
                            .saturating_sub(evict_bytes_base);
                        let spill_delta = (
                            v.spill_write_bytes().saturating_sub(spill_base.0),
                            v.spill_read_bytes().saturating_sub(spill_base.1),
                            v.spill_readback_pieces().saturating_sub(spill_base.2),
                            v.spill_fallback_destroy_bytes()
                                .saturating_sub(spill_base.3),
                        );
                        (v, steps, evicted_delta, spill_delta)
                    })
                    .await;
                    let (v, steps, evicted_delta, spill_delta) = match res {
                        Ok(quadruple) => quadruple,
                        Err(e) => {
                            let _ = progress_tx
                                .send((face, Progress::Fatal(format!("store blocking task: {e}"))))
                                .await;
                            break 'run;
                        }
                    };
                    vw_opt = Some(v);
                    // Instrumentation feed: evicted bytes + per-block
                    // buffer-face durations (histogram feeds are atomic
                    // direct adds, lock-free, allocation-free).
                    if let Some(m) = metrics.as_ref() {
                        m.note_wrcache_evict_bytes(evicted_delta);
                        // Spill three-face delta feed.
                        m.note_spill(spill_delta.0, spill_delta.1, spill_delta.2);
                        // Over-budget fallback-destroy byte delta feed.
                        m.note_spill_fallback_destroy(spill_delta.3);
                        for step in &steps {
                            m.observe_block_stage(
                                BlockStage::Buffer,
                                Duration::from_micros(u64::from(step.buffer_us)),
                            );
                        }
                    }
                    // Live merge-window reset: a shift arriving during
                    // batch processing is applied when this batch's writer
                    // returns (the watch arm could not reach it then).
                    if let Some(v) = vw_opt.as_mut() {
                        v.set_write_merge_max(cur_merge);
                    }
                    // Batched ack: settled Buffered coordinates collected
                    // in the batch and raised once at batch end as
                    // `BlocksSettled` (engine iterates 1/batch).
                    // Order-preserving = steps order = pipeline submission
                    // order. Batch depth is the latency bound: sibling
                    // cancel / redispatch bookkeeping lags by at most one
                    // batch depth; the endgame decision face is untouched
                    // (only the confirmation return path changes - not the
                    // x2 gate, not generation). `PieceEvicted` /
                    // `BlockRejected` / `Fatal` are never batched (raised
                    // immediately; the three-book sync and single-block
                    // refetch semantics unchanged). An early batch exit
                    // (Fatal / ack-channel death return) loses the pending
                    // batch = the engine is failing anyway, no observer -
                    // the same semantics as the per-block send aborting
                    // mid-batch today.
                    let mut settled: Vec<(u32, u32)> = Vec::with_capacity(steps.len());
                    // Pending group (write coalescing): adjacent-goff
                    // completed pieces are grouped; one dispatch at the
                    // [`PIECE_GROUP_MAX`] cap / a non-adjacent break / the
                    // batch end (one write_batch lock domain per group +
                    // adjacent cells coalesced into segments). A group
                    // lives only within this batch (cap 4 pieces < the
                    // 32-step structural batch bound - also the
                    // pieces-per-slot multiplier of the verify_pool verdict
                    // channel capacity, see its deadlock-exemption
                    // argument); an early batch exit (Fatal / ack-channel
                    // death return) drops the pending group = the engine is
                    // failing anyway, no observer - the same precedent as
                    // the pending batch above.
                    let mut pending_group: Vec<PieceJob> = Vec::new();
                    for step in steps {
                        // Root-cause fix (paired with [`VerifiedWriter::
                        // update_min_loss`]): three-book sync on eviction -
                        // (1) the pool + cache were already reset at
                        // verified.rs step 4 (data and digests destroyed
                        // together);
                        // (2) the pipeline's `received` bitmap is
                        // invalidated with the eviction: a stale bitmap
                        // would silently swallow engine-redispatched blocks
                        // as duplicates;
                        // (3) engine dispatch bookkeeping (blocks_sent
                        // InFlight/Buffered) is cleared via the
                        // `PieceEvicted` event - a stale Buffered entry
                        // would leave the piece never requested again
                        // ("completion bookkeeping disconnected from the
                        // dispatch bitmap").
                        let mut send_failed = false;
                        for evicted_index in step.evicted {
                            evictions += 1;
                            received.remove(&evicted_index);
                            if evictions <= 10 || evictions % 100 == 0 {
                                debug!(target: "taiji::core::engine::store", face,
                                    index = evicted_index, evictions,
                                    "piece evicted unverified: bookkeeping synced, re-fetch armed");
                            }
                            if progress_tx
                                .send((face, Progress::PieceEvicted {
                                    index: u32::try_from(evicted_index).unwrap_or(u32::MAX),
                                }))
                                .await
                                .is_err()
                            {
                                send_failed = true;
                                break;
                            }
                        }
                        if send_failed {
                            break 'run;
                        }
                        match step.res {
                            Ok(PooledOutcome::PieceCompleted(job)) => {
                                debug!(target: "taiji::core::engine::store", face,
                                    index = job.piece(),
                                    "piece complete: verify+write dispatched to pool");
                                // Pool full awaits here = backpressure (the
                                // block channel backs up -> the peer read
                                // loop stalls). The job's cell has left the
                                // cache; verdicts drive the rest of the
                                // bookkeeping (PieceVerified/PieceFailed).
                                // Write coalescing: adjacent-goff completed
                                // pieces within a batch are grouped
                                // (`BH_WRITE_COALESCE` default on) - the
                                // group dispatches at a non-adjacent break /
                                // batch end, one write_batch lock domain per
                                // group + adjacent cells coalesced (the main
                                // lever for fewer write syscalls per block).
                                // Dispatch order follows step order (break
                                // flush + batch-end flush both FIFO); the
                                // off fallback = single-job immediate
                                // dispatch (the status quo bit-for-bit).
                                if write_coalesce {
                                    let adjacent = pending_group
                                        .last()
                                        .and_then(|prev| prev.last_cell_end())
                                        .zip(job.first_cell_goff())
                                        .is_some_and(|(prev_end, next_start)| {
                                            prev_end == next_start
                                        });
                                    if adjacent {
                                        pending_group.push(job);
                                        // Cap reached -> flush
                                        // ([`PIECE_GROUP_MAX`] is the
                                        // structural bound on group pieces -
                                        // the verify_pool verdict channel is
                                        // budgeted by this multiplier;
                                        // groups must not aggregate without
                                        // bound).
                                        if pending_group.len() >= PIECE_GROUP_MAX {
                                            pool
                                                .dispatch_group(std::mem::take(
                                                    &mut pending_group,
                                                ))
                                                .await;
                                        }
                                    } else {
                                        pool
                                            .dispatch_group(std::mem::take(
                                                &mut pending_group,
                                            ))
                                            .await;
                                        pending_group.push(job);
                                    }
                                } else {
                                    pool.dispatch(job).await;
                                }
                            }
                            Ok(PooledOutcome::Buffered { .. }) => {
                                // Block settled (into the write cache): the
                                // dispatch face's in-flight bookkeeping
                                // releases; the received bitmap registers it
                                // (later same-coordinate deliveries drop as
                                // duplicates).
                                received
                                    .entry(u64::from(step.index))
                                    .or_default()
                                    .insert(step.begin);
                                // Pre-registered counter decrements on
                                // confirmation (observation face; the same
                                // point serves batched and per-block forms).
                                block_inflight
                                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                if batch_ack {
                                    settled.push((step.index, step.begin));
                                } else if progress_tx
                                    .send((face, Progress::BlockSettled {
                                        index: step.index,
                                        begin: step.begin,
                                    }))
                                    .await
                                    .is_err()
                                {
                                    break 'run;
                                }
                            }
                            Ok(PooledOutcome::PieceAbortedUnverified) => {
                                debug!(target: "taiji::core::engine::store", face,
                                    index = step.index,
                                    "piece evicted unverified: dropped for re-fetch");
                                received.remove(&u64::from(step.index));
                                // WrCache evict (cache over limit, unverified piece evicted).
                                if let Some(m) = metrics.as_ref() {
                                    m.note_wrcache(WrcacheEvent::Evict);
                                }
                            }
                            Ok(PooledOutcome::BlockRejected { leaf_index }) => {
                                // v2 true per-block check: only this 16KiB
                                // is rejected; the rest of the piece keeps
                                // buffering / verifying; the main loop
                                // queues a single-block refetch by
                                // coordinate.
                                debug!(target: "taiji::core::engine::store", face,
                                    index = step.index, begin = step.begin, leaf = leaf_index,
                                    "v2 per-block check rejected 16KiB: only this block re-fetches");
                                // Not in cache: remove from the received bitmap, allow redispatch.
                                if let Some(set) = received.get_mut(&u64::from(step.index)) {
                                    set.remove(&step.begin);
                                }
                                if progress_tx
                                    .send((face, Progress::BlockRejected {
                                        index: step.index,
                                        begin: step.begin,
                                        length: step.dlen,
                                    }))
                                    .await
                                    .is_err()
                                {
                                    break 'run;
                                }
                            }
                            Ok(PooledOutcome::DuplicateDropped) => {
                                // Store coverage backstop hit (second
                                // gate): the bitmap missed but the cache
                                // already holds this goff's data - backfill
                                // the bitmap to converge, count observably
                                // (the same counter as the first gate).
                                received
                                    .entry(u64::from(step.index))
                                    .or_default()
                                    .insert(step.begin);
                                dup_drops += 1;
                                if let Some(m) = metrics.as_ref() {
                                    m.note_duplicate_blocks(1);
                                    // endgame-window subset. The criterion
                                    // reads at result-reclaim time - a flag
                                    // flip between it and the batch-assembly
                                    // criterion lands in the later window;
                                    // boundary noise <= one batch depth
                                    // (honest terms).
                                    if endgame_live
                                        .load(std::sync::atomic::Ordering::Relaxed)
                                    {
                                        m.note_duplicate_blocks_endgame(1);
                                    }
                                }
                                debug!(target: "taiji::core::engine::store", face,
                                    index = step.index, begin = step.begin, drops = dup_drops,
                                    "duplicate block (store coverage backstop): dropped benignly");
                            }
                            Ok(_) => {
                                // Forward-compat (PooledOutcome is
                                // #[non_exhaustive]): an unknown outcome is
                                // treated as not-settled - the coordinate
                                // leaves the received bitmap so the block
                                // re-fetches (the conservative
                                // PieceAbortedUnverified treatment; never
                                // counted as settled).
                                received.remove(&u64::from(step.index));
                                warn!(target: "taiji::core::engine::store", face,
                                    index = step.index, begin = step.begin,
                                    "unknown pooled outcome: block treated as not settled (re-fetch)");
                            }
                            Err(StoreError::PieceAlreadyComplete { .. }) => {
                                debug!(target: "taiji::core::engine::store", face,
                                    index = step.index, begin = step.begin,
                                    "duplicate block for completed piece: dropped");
                            }
                            // BEP52 dual-hash inconsistency is unreachable
                            // in the buffer step (the cross-check moved to
                            // the worker with the completion face); the arm
                            // stays for a complete error surface, semantics
                            // as the completion face: torrent-level failure.
                            Err(StoreError::CrossCheckFailed { piece }) => {
                                let _ = progress_tx
                                    .send((face, Progress::Fatal(format!(
                                        "hybrid cross-check failed at piece {piece}: \
                                         v1/v2 hashes inconsistent (BEP52)"
                                    ))))
                                    .await;
                                break 'run;
                            }
                            Err(e) => {
                                // Depth backstop (Fatal semantics kept):
                                // block-coordinate errors (alignment / piece
                                // bounds / duplicate slot - the RangeError
                                // family surfacing as StoreError::Internal)
                                // are unreachable for legal wire input - the
                                // bt side's unsolicited-accept arm already
                                // applies the same checks
                                // (PeerError::BadBlockCoords disconnects),
                                // and dispatch guarantees the slot-matched
                                // coordinates; a HashPool-side Err leaves
                                // zero state change (counters unpolluted).
                                // Fatal here = explicit termination on a
                                // broken internal invariant, not a peer-
                                // triggerable face. Mapping the RangeError
                                // family to a peer disconnect would need a
                                // new store error-taxonomy variant plus
                                // attribution via block_senders - a larger
                                // change than the payoff on an unreachable
                                // path.
                                let _ = progress_tx
                                    .send((face, Progress::Fatal(format!("push_block: {e}"))))
                                    .await;
                                break 'run;
                            }
                        }
                    }
                    // Batch-end flush: the pending group (the batch's last
                    // contiguous run) dispatched in one call - groups live
                    // only within the batch; dispatch order stays FIFO by
                    // step order.
                    pool.dispatch_group(std::mem::take(&mut pending_group)).await;
                    // Raised once at batch end (batched ack): engine
                    // iterations 1/batch. Queued on the existing channel -
                    // event relative order (vs the per-item evicted /
                    // rejected events) = submission order, same as the
                    // per-block send today.
                    if batch_ack && !settled.is_empty()
                        && progress_tx
                            .send((face, Progress::BlocksSettled { settled }))
                            .await
                            .is_err()
                    {
                        break 'run;
                    }
                }
            }
        }
    }

    // -- Terminal data-flush barrier (the data half) --
    //
    // Ordering invariant (same terms as the HTTP snapshot pipeline - the
    // `session/http/snapshot.rs` module doc "the outage bitmap never runs
    // ahead of data"; `session/actor/http_task.rs` `part.sync_all` same
    // shape): **data fsync first, progress-row upsert second**. Every
    // exit path (token / channel close / Fatal / engine terminal flush
    // trigger) converges here:
    //
    // 1. close the dispatch face: the dispatcher drains and exits ->
    // worker queues close -> workers drain in-flight jobs and exit
    // (in-flight writes complete naturally - the shutdown order lives
    // in the verify_pool module docs);
    // 2. draining verdicts to None = all workers exited = all dispatched
    // writes have returned; this face issues no further data writes
    // (the pipeline exits, the block channel is no longer serviced -
    // unbuffered bytes stay in the write cache and die with the
    // writer; recovery refetches them as incomplete, the safe
    // direction);
    // 3. fsync the data file: write-external ops in the exclusive domain
    // ([`SharedDiskWriter::with_exclusive`], mutually exclusive with
    // the write hot path - the mechanism behind the spec red line
    // "fsync semantics unchanged") + spawn_blocking, same shape as
    // the periodic flush arm;
    // 4. set the barrier: `Flushed` = persisting this face's bitmap from
    // here on satisfies the invariant; `Failed` = the engine refuses
    // the terminal progress row (under-record rather than ever
    // over-record).
    //
    // The engine-side consuming point = run/tail.rs `final_flush`
    // (trigger each face, wait for `Flushed`, then upsert the terminal
    // progress row). The session-side transition row (persist_transition)
    // is written after the engine JoinHandle returns - naturally after
    // the barrier.
    //
    // Trade-off: the 60s regular autosave (run/tick.rs) does not go
    // through THIS terminal barrier - draining all in-flight writes is
    // too heavy for a per-minute beat; its bitmap rows go through the
    // snapshot write barrier (dirty-face data fsync before the row
    // upsert, fail-closed row skip on failure - see run/tick.rs
    // `autosave_snapshot` and [`SnapshotSyncCell`]), so a bitmap can
    // only lag data, never run ahead; terminal rows through this barrier
    // never over-record.
    let VerifyPool {
        dispatch_tx,
        mut result_rx,
    } = pool;
    drop(dispatch_tx);
    while result_rx.recv().await.is_some() {}
    let flushed =
        tokio::task::spawn_blocking(move || flush_handle.with_exclusive(|g| g.flush_os_buffers()))
            .await;
    let gate_state = match flushed {
        Ok(Ok(())) => {
            debug!(target: "taiji::core::engine::store", face,
                "final data flush done (terminal barrier: writes drained, fsync ok)");
            DataFlushState::Flushed
        }
        Ok(Err(e)) => DataFlushState::Failed(format!("final fsync: {e}")),
        Err(e) => DataFlushState::Failed(format!("final fsync join: {e}")),
    };
    if let DataFlushState::Failed(reason) = &gate_state {
        warn!(target: "taiji::core::engine::store", face, reason,
            "final data flush failed: terminal progress row must be refused");
    }
    data_flush_gate.send_replace(gate_state);
}

#[cfg(test)]
mod tests {
    /// Sizing table ([`super::wr_cache_limit`]): lower bound =
    /// max(16MiB frozen default, 2 x cap x piece_len); the env can still
    /// exceed the cap (seam semantics unchanged). The hard cap reads its
    /// default when the env is unset (parallel tests cannot
    /// deterministically set BH_PEER_MAX); the numbers follow the sizing
    /// formula.
    #[test]
    fn wr_cache_limit_scales_with_piece_len_and_honors_env() {
        use super::{peer_connections_max, wr_cache_limit};
        let kib = 1024usize;
        // 256KiB pieces: 2x120x256KiB = 60MiB exceeds the 16MiB default.
        assert_eq!(
            wr_cache_limit(256 * 1024),
            60 * 1024 * kib,
            "aggregated in-flight demand (120 conn x 256KiB) exceeds the 16MiB default -> 2x sizing"
        );
        // Small pieces (16KiB): 2x the cap product < 16MiB -> the default is the lower bound.
        assert_eq!(
            wr_cache_limit(16 * 1024),
            16 * 1024 * kib,
            "small-piece shape freezes the default as the lower bound (aria2 same-parameter anchor kept)"
        );
        // Large pieces (1MiB): 2x120x1MiB = 240MiB.
        assert_eq!(wr_cache_limit(1024 * 1024), 240 * 1024 * kib);
        // Constant guard: the sizing anchor = the connection hard cap
        // (same source as admission; 120).
        assert_eq!(peer_connections_max(), 120);
    }

    /// Sizing table ([`super::spill_floor`]): floor =
    /// max(write-cache sizing, 2 x cap x checkout cap x piece_len).
    /// Pure function, direct-driven (the checkout cap is given by the
    /// test; env knobs cannot be manipulated deterministically under
    /// parallel tests); the `spill_limit` `BH_SPILL_BYTES` override and
    /// `BH_SPILL_FIXED` fallback faces depend on process env and are
    /// covered by integration tests, not here.
    #[test]
    fn spill_default_limit_extends_with_multi_piece_depth() {
        use super::spill_floor;
        let kib = 1024usize;
        // 256KiB pieces: 2x120x4x256KiB = 240MiB exceeds the write-cache
        // sizing of 60MiB (the 2x checkout term lifts the floor above the
        // cache sizing).
        assert_eq!(
            spill_floor(256 * 1024, 4),
            240 * 1024 * kib,
            "multi-whole-piece aggregated in-flight (2x120 conn x 4-piece checkout x 256KiB) lifts the floor"
        );
        // Small pieces (16KiB): 2x120x4x16KiB = 15MiB < the write-cache
        // default -> the write cache is the lower bound (this shape's
        // wr_cache_limit is the 16MiB frozen default).
        assert_eq!(spill_floor(16 * 1024, 4), 16 * 1024 * kib);
        // Large pieces (1MiB): 2x120x4x1MiB = 960MiB > 240MiB (the 2x-cap terms).
        assert_eq!(spill_floor(1024 * 1024, 4), 960 * 1024 * kib);
        // Checkout cap 1 (single-piece era): 2x120x1x256KiB = 60MiB,
        // exactly the write-cache sizing (the spill term does not exceed
        // it - degenerate semantics match the single-piece shape).
        assert_eq!(
            spill_floor(256 * 1024, 1),
            60 * 1024 * kib,
            "single-piece checkout = the write-cache sizing surface; the spill term stays under it"
        );
        // Checkout cap 8 (the `BH_MULTI_PIECE_SUPPLY_MAX=8` explicit
        // fallback arm): the floor scales up in step =
        // 2x120x8x256KiB ~= 480MiB (the spec number).
        assert_eq!(
            spill_floor(256 * 1024, 8),
            480 * 1024 * kib,
            "cap 8 → 2×120×8×256KiB = 480MiB"
        );
        // Checkout cap 16 (the current default): the floor scales in step
        // = 2x120x16x256KiB ~= 960MiB (the formula reads the cap from
        // multi_piece_checkout_cap - single source, no hardcoded 8, so it
        // follows the knob automatically).
        assert_eq!(
            spill_floor(256 * 1024, 16),
            960 * 1024 * kib,
            "cap 16 → 2×120×16×256KiB = 960MiB"
        );
        // Default checkout cap anchor = 16 (history: 4 -> 8 -> 16 via the
        // explicit env fallback arms).
        assert_eq!(super::multi_piece_checkout_cap(), 16);
    }

    /// Extreme-value face ([`super::block_arena_for_face`]'s sizing
    /// term): an extreme `BH_PEER_MAX` / `--bt-max-peers` value must
    /// saturate the 2 x cap x piece_len product, not overflow (debug
    /// overflow-checks would panic; release would wrap to a bogus cap).
    /// The real read is a once-per-process seam parallel tests cannot set
    /// deterministically, so the peer cap is direct-driven (the
    /// spill_floor table-test shape); the default-env anchors pin the
    /// composed site's unchanged sane-value behavior.
    #[test]
    fn block_arena_sizing_product_saturates_at_extreme_peer_max() {
        use super::{block_arena_for_face, peer_connections_max, peer_piece_product};
        let kib = 1024usize;
        // Saturation on the first link: 2 x usize::MAX.
        assert_eq!(peer_piece_product(usize::MAX, 256 * 1024), usize::MAX);
        // Saturation on the second link: 2 x (usize::MAX/2) x 3.
        assert_eq!(peer_piece_product(usize::MAX / 2, 3), usize::MAX);
        // The in-force anchor (120) multiplies exactly: 2x120x256KiB =
        // 60MiB (the sizing table's number).
        assert_eq!(peer_connections_max(), 120);
        assert_eq!(
            peer_piece_product(peer_connections_max(), 256 * 1024),
            60 * 1024 * kib
        );
        // The composed site keeps its .max() lower bounds: the
        // default-env 256KiB shape sizes the arena cap to the 60MiB
        // demand term (a cap, not a preallocation).
        let arena =
            block_arena_for_face(256 * 1024).unwrap_or_else(|| panic!("block arena default-on"));
        assert_eq!(arena.readout().cap_bytes, 60 * 1024 * 1024);
    }

    /// Extreme-value face ([`super::wr_cache_limit`]'s sizing term): the
    /// same saturation contract as the block-arena product - the sibling
    /// [`super::spill_floor`] chain is saturating for the same reason.
    /// An extreme `BH_PEER_MAX` raises the ceiling to usize::MAX (a cap,
    /// not a preallocation - cells exist only as data arrives) instead of
    /// overflowing; the default-env anchor values still hold through the
    /// real site function.
    #[test]
    fn wr_cache_sizing_product_saturates_at_extreme_peer_max() {
        use super::{peer_connections_max, peer_piece_product, wr_cache_limit};
        let kib = 1024usize;
        // Saturation on the first link: 2 x usize::MAX.
        assert_eq!(peer_piece_product(usize::MAX, 256 * 1024), usize::MAX);
        // Saturation on the second link: 2 x (usize::MAX/2) x 3.
        assert_eq!(peer_piece_product(usize::MAX / 2, 3), usize::MAX);
        // The in-force anchor (120) multiplies exactly, and the real
        // site keeps its .max() lower-bound shape (256KiB pieces = the
        // 60MiB demand cap over the 16MiB frozen default).
        assert_eq!(
            peer_piece_product(peer_connections_max(), 256 * 1024),
            60 * 1024 * kib
        );
        assert_eq!(wr_cache_limit(256 * 1024), 60 * 1024 * kib);
        assert_eq!(peer_connections_max(), 120);
    }

    /// Gate (v1 skip arm): an expected face with no v2 pieces (pure v1 /
    /// empty plan) never mounts the precompute table - the decision is
    /// read before the env switch (v1 faces have no excess hashing). The
    /// v2 arm's default-on / env override depends on process env (not
    /// deterministically settable under parallel tests) and is covered by
    /// integration tests (a v2 task pipeline mounts the table by
    /// default), not here.
    #[test]
    fn v2_hash_precompute_gate_skips_v1_faces() {
        use taiji_store::hashpool::ExpectedPieceHash;
        let v1_only = [
            ExpectedPieceHash::V1([0; 20]),
            ExpectedPieceHash::V1([1; 20]),
        ];
        assert!(!super::v2_hash_precompute_enabled(&v1_only));
        assert!(!super::v2_hash_precompute_enabled(&[]));
    }

    // -------------------------------------------------------------------
    // Terminal data-flush barrier ordering regression: the data half -
    // "drain in-flight writes, then fsync, then set Flushed"; the
    // consumer is run/tail.rs final_flush (wait for Flushed, then persist
    // the terminal progress row).
    // -------------------------------------------------------------------

    use super::*;
    use std::path::Path;

    /// The injected writer's event-order log (write_at / flush_os_buffers order).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RecOp {
        Write(u64),
        Flush,
    }

    /// Recording writer (delegates real writes to
    /// [`taiji_store::disk::FileDiskWriter`], appends events to the shared
    /// order log).
    struct RecordingWriter {
        inner: taiji_store::disk::FileDiskWriter,
        ops: Arc<Mutex<Vec<RecOp>>>,
    }

    impl DiskWriter for RecordingWriter {
        fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            self.inner.open(path, read_only)
        }
        fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            self.inner.open_existing(path, read_only)
        }
        fn create(&mut self, path: &Path) -> Result<(), StoreError> {
            self.inner.create(path)
        }
        fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
            self.inner.truncate(len)
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            self.ops
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(RecOp::Write(offset));
            self.inner.write_at(offset, data)
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            self.inner.read_at(offset, buf)
        }
        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            self.ops
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(RecOp::Flush);
            self.inner.flush_os_buffers()
        }
        fn size(&self) -> Result<u64, StoreError> {
            self.inner.size()
        }
        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            self.inner.set_bypass_page_cache()
        }
    }

    /// Recording build hook ([`WriterFactory`] injection seam; allocation
    /// is performed by the pipeline calling `create()` on the returned
    /// writer - the contract face; allocation is not part of the event
    /// order).
    struct RecordingFactory {
        ops: Arc<Mutex<Vec<RecOp>>>,
    }

    impl WriterFactory for RecordingFactory {
        fn build(
            &self,
            _layout: &Layout,
            _dest: &std::path::Path,
        ) -> Result<Box<dyn DiskWriter>, StoreError> {
            Ok(Box::new(RecordingWriter {
                inner: taiji_store::disk::FileDiskWriter::new(),
                ops: Arc::clone(&self.ops),
            }))
        }
    }

    /// Ordering regression (data half): after the terminal trigger the
    /// pipeline must (1) drain all dispatched writes (workers finish
    /// in-flight writes - the verify_pool shutdown order), (2) fsync the
    /// data file (write-external exclusive domain), (3) set the barrier
    /// to Flushed. Criteria = exactly one fsync, strictly after every
    /// write event, barrier = Flushed, on-disk content intact.
    /// PieceWritten is drained first as the deterministic precondition
    /// (writes have returned).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_flush_barrier_fsyncs_after_all_writes() {
        use sha1::{Digest as _, Sha1};
        use taiji_store::layout::PlanEntry;

        const PIECE: u32 = 16384;
        const PIECES: usize = 2;
        let total = PIECES * PIECE as usize;

        struct TempDir(PathBuf);
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let tmp = TempDir(std::env::temp_dir().join(format!(
            "taiji-final-flush-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        )));
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let dest = tmp.0.join("blob.bin");

        // Distinguishable content + expected hashes (per-piece SHA-1, concatenated).
        let content: Vec<u8> = (0..total)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let mut expected = Vec::new();
        for piece in content.chunks(PIECE as usize) {
            expected.extend_from_slice(&Sha1::digest(piece));
        }

        let ops: Arc<Mutex<Vec<RecOp>>> = Arc::new(Mutex::new(Vec::new()));
        let layout = Layout::plan_v1_padded(
            &[PlanEntry {
                path: PathBuf::from("blob.bin"),
                length: total as u64,
                padding: false,
            }],
            PIECE,
        )
        .unwrap_or_else(|e| panic!("layout: {e}"));
        let (block_tx, block_rx) = mpsc::channel::<BlockMsg>(BLOCK_CHANNEL_CAPACITY);
        let (progress_tx, mut progress_rx) = mpsc::channel::<(usize, Progress)>(64);
        let (final_flush_tx, final_flush_rx) = mpsc::channel::<()>(1);
        let (gate_tx, mut gate_rx) = tokio::sync::watch::channel(DataFlushState::Pending);
        // Keep the sender alive until the test ends (the policy arm's
        // existing semantics on sender drop = park forever after one Err -
        // in production that end lives as long as the engine; the test
        // keeps the same shape).
        let (_policy_tx, policy_rx) = tokio::sync::watch::channel(DiskPolicy::default());

        tokio::spawn(store_pipeline(StoreJob {
            initial_selection: None,
            face: 0,
            expected: (0..PIECES)
                .map(|p| {
                    taiji_store::hashpool::ExpectedPieceHash::V1(
                        Sha1::digest(&content[p * PIECE as usize..(p + 1) * PIECE as usize]).into(),
                    )
                })
                .collect(),
            piece_len: PIECE,
            plan_file_lengths: vec![total as u64],
            goffs: Arc::new((0..PIECES as u64).map(|p| p * u64::from(PIECE)).collect()),
            cross: Arc::new(vec![None; PIECES]),
            block_check: None,
            dest: dest.clone(),
            writer_factory: Some(Arc::new(RecordingFactory {
                ops: Arc::clone(&ops),
            })),
            layout,
            allocate: true,
            block_rx,
            progress_tx,
            token: CancellationToken::new(),
            metrics: None,
            endgame_live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            pool: VerifyPoolConfig {
                workers: 1,
                queue_per_worker: 1,
            },
            disk_policy: DiskPolicy::default(),
            policy_rx,
            live: Arc::new(taiji_store::disk_policy::LivePolicyCell::new(
                DiskPolicy::default(),
            )),
            recovery_expected_rx: None,
            block_arena: None,
            block_inflight: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            batch_ack: false,
            final_flush_rx,
            data_flush_gate: gate_tx,
            snapshot_sync: Arc::new(std::sync::OnceLock::new()),
        }));

        // Deliver every piece block by block (one full-piece block each).
        for (p, piece) in content.chunks(PIECE as usize).enumerate() {
            block_tx
                .send((p as u32, 0, Bytes::copy_from_slice(piece)))
                .await
                .unwrap_or_else(|e| panic!("block send: {e}"));
        }
        // Deterministic precondition: drain to both pieces' PieceWritten
        // (writes returned) before triggering the terminal flush.
        let mut written = 0usize;
        while written < PIECES {
            let next = tokio::time::timeout(Duration::from_secs(10), progress_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("progress wait timeout"));
            let Some((_, ev)) = next else {
                panic!("progress channel closed before writes completed")
            };
            if matches!(ev, Progress::PieceWritten { .. }) {
                written += 1;
            }
        }

        // Terminal trigger -> wait for the barrier value.
        final_flush_tx
            .send(())
            .await
            .unwrap_or_else(|e| panic!("final flush trigger: {e}"));
        let verdict = tokio::time::timeout(
            Duration::from_secs(10),
            gate_rx.wait_for(|s| !matches!(s, DataFlushState::Pending)),
        )
        .await
        .unwrap_or_else(|_| panic!("barrier timeout"))
        .unwrap_or_else(|_| panic!("barrier sender gone"));
        assert!(
            matches!(&*verdict, DataFlushState::Flushed),
            "barrier must settle at Flushed, got {verdict:?}"
        );

        // Ordering criteria: exactly one fsync, strictly after every write event.
        let ops = ops.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let flush_pos = ops
            .iter()
            .position(|op| *op == RecOp::Flush)
            .unwrap_or_else(|| panic!("the terminal barrier must produce one fsync"));
        assert_eq!(
            ops.iter().filter(|op| **op == RecOp::Flush).count(),
            1,
            "default throughput tier has no periodic flush cadence; fsync exactly once (terminal barrier)"
        );
        assert!(
            ops.iter()
                .filter(|op| matches!(op, RecOp::Write(_)))
                .count()
                >= 1,
            "two pieces require at least one data write"
        );
        assert!(
            ops.iter()
                .enumerate()
                .all(|(i, op)| !matches!(op, RecOp::Write(_)) || i < flush_pos),
            "every write event must precede the terminal fsync (data-half \
             ordering: fsync data first, progress row settles after), \
             actual order {ops:?}"
        );
        // On-disk content intact (real write semantics unaffected by the barrier).
        let got = std::fs::read(&dest).unwrap_or_else(|e| panic!("readback: {e}"));
        assert_eq!(
            got, content,
            "on-disk content after the barrier must be intact and identical"
        );
    }
}

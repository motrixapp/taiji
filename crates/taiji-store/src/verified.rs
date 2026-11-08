//! Verified write pipeline: block -> HashPool digest -> WrDiskCache
//! buffer -> whole-piece verification -> DiskWriter write (SPEC §4.5.2).
//!
//! Hard invariant: no byte reaches disk before verification passes.
//! - A piece whose bytes are complete is verified at once: pass -> cells
//!   written in goff order; fail -> cells dropped, piece reset for
//!   refetch (`PieceFailed`).
//! - Cache overflow evicting an unverified piece = destroy-and-refetch
//!   (`PieceAbortedUnverified`), never a disk write.
//! - The unverified spill area ([`crate::spill`], present only when the
//!   switch attaches it) is the single sanctioned bypass: a cache-full
//!   victim is staged in the sidecar (the main data files still hold
//!   zero unverified bytes) and read back at assembly; outside the
//!   budget it falls back to destroy-and-refetch (same semantics).
//!
//! Upstream anchor mapping: docs/design/store.md

use crate::cache::{CacheEntry, DataCell, WrDiskCache};
use crate::disk::DiskWriter;
use crate::disk_policy::DiskPolicy;
use crate::error::StoreError;
use crate::hashpool::{HashPool, RangeError, V2VerifyInputs};
use crate::hashtree::{HashTreeCache, TreeError};
use crate::precomputed_block_hashes::PrecomputedBlockHashes;
use crate::spill::SpillStore;
use crate::{lock, read_lock, write_lock};
use sha1::{Digest as _, Sha1};
use std::sync::{Arc, Mutex, RwLock};

/// Platform gate for concurrent positioned writes: unix `pwrite` uses no
/// shared file cursor and is safe for concurrent calls at different
/// offsets on one fd (POSIX pread/pwrite atomicity); Windows `seek_write`
/// has cursor side effects and is not thread-safe (std docs), so writes
/// always take the exclusive lock there.
#[cfg(unix)]
const PLATFORM_CONCURRENT_PWRITE: bool = true;
#[cfg(not(unix))]
const PLATFORM_CONCURRENT_PWRITE: bool = false;

/// Reads the `BH_PARALLEL_WRITES` default (concurrent-write switch);
/// parsing/reading points are registered in `taiji_io::knobs` (read at
/// construction, does not change the cache).
///
/// Default off is a measured decision: concurrent same-file pwrite
/// pushes the wait into the kernel, and per-file kernel contention
/// loses badly to the user-space whole-piece mutex. The concurrent face
/// is retained for explicit opt-in measurement (Linux / multi-file
/// faces unmeasured — measure before modify).
fn parallel_writes_env() -> bool {
    taiji_io::knobs::parallel_writes_enabled()
}

/// Reads the `BH_WRITE_COALESCE` default (write-path batching switch);
/// parsing/reading points are registered in `taiji_io::knobs` (read at
/// construction, does not change the cache).
///
/// When on: (1) a completed piece writes its adjacent contiguous cell
/// runs as one vectored write (unix `pwritev`, zero-copy iovecs;
/// cross-validation: libtorrent `visit_block_iovecs` merges contiguous
/// blocks into a single pwritev); (2) adjacent-goff completed pieces
/// within one pipeline batch are stitched into a single `write_batch`.
fn write_coalesce_env() -> bool {
    taiji_io::knobs::write_coalesce_enabled()
}

/// Public decision for `BH_WRITE_COALESCE` (the pipeline grouping face
/// and the [`VerifiedWriter`] write face must share one source: grouping
/// and vectorization are driven by the same switch; when off, no
/// grouping happens). The in-process environment is constant, so a
/// caller can read it once.
pub fn write_coalesce_enabled() -> bool {
    write_coalesce_env()
}

/// Shared disk write handle (pooled face): the verification/write worker
/// pool and the inline completion path of [`VerifiedWriter`] share one
/// underlying writer.
///
/// # Write de-serialization (lock domain split)
///
/// The old shape `Arc<Mutex<Box<dyn DiskWriter>>>` put every face's disk
/// writes behind a single global lock, serializing away the gains of
/// worker-parallel verification on the write half. The current shape
/// splits the lock by domain:
///
/// - **Positioned-write hot path** ([`Self::write_batch`]): the
///   concurrent face (unix, switch on) executes under the **read lock**
///   — `pwrite` at different offsets on one fd is safe (POSIX; see
///   `PLATFORM_CONCURRENT_PWRITE`). Cross-validation: libtorrent's mmap
///   backend writes are plain memcpy with no write-back queue, and its
///   pread backend merges contiguous blocks into single pwritev calls —
///   the same zero-global-write-serialization philosophy in equivalent
///   form under verify-before-disk. Piece goff spans never overlap
///   (pipeline invariant) and a piece's cells are written by one worker
///   in goff order — per-piece write order is unchanged; interleaving
///   happens only at piece boundaries.
/// - **Non-write operations** ([`Self::with_exclusive`]):
///   open/create/truncate/allocate/fsync/fence points keep the
///   exclusive lock (red line: zero crash-recovery regression, fsync
///   semantics unchanged).
/// - **Platform domain**: the Windows write hot path always takes the
///   write lock (`seek_write` is not thread-safe; same order as the old
///   shape).
/// - **Switch defaults off** (measured decision, see the
///   [`parallel_writes_env`] note): `BH_PARALLEL_WRITES=1` opts into
///   the concurrent face; default/explicit off -> writes take the
///   write lock = the old global-mutex shape (bit-identical behavior;
///   the explicit assembly point [`Self::with_parallel_writes`] serves
///   tests/gating).
///
/// All locks are synchronous std locks, never held across `await` (the
/// workers are blocking threads).
#[derive(Clone)]
pub struct SharedDiskWriter {
    inner: Arc<RwLock<Box<dyn DiskWriter>>>,
    /// unix concurrent-pwrite face (platform gate && BH_PARALLEL_WRITES;
    /// observed via [`Self::parallel_writes`]).
    parallel_writes: bool,
}

impl std::fmt::Debug for SharedDiskWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted (the `PieceJob` Debug rule): the inner writer is a
        // `dyn DiskWriter` trait object (no Debug bound), and a Debug
        // face must not take the RwLock (a shared reference that blocks
        // on the write hot path would be a footgun).
        f.debug_struct("SharedDiskWriter")
            .field("parallel_writes", &self.parallel_writes)
            .finish_non_exhaustive()
    }
}

impl SharedDiskWriter {
    /// Handle sharing (the constructor takes a `Box` — existing call
    /// sites unchanged); the concurrent face is decided by the platform
    /// gate && the `BH_PARALLEL_WRITES` default.
    pub fn new(writer: Box<dyn DiskWriter>) -> SharedDiskWriter {
        SharedDiskWriter::with_parallel_writes(writer, parallel_writes_env())
    }

    /// Explicit concurrent-face assembly point (test seam / gating
    /// injection; the default path is [`Self::new`]).
    pub fn with_parallel_writes(writer: Box<dyn DiskWriter>, parallel: bool) -> SharedDiskWriter {
        SharedDiskWriter {
            inner: Arc::new(RwLock::new(writer)),
            parallel_writes: PLATFORM_CONCURRENT_PWRITE && parallel,
        }
    }

    /// Concurrent-write face observation (true only when unix &&
    /// `BH_PARALLEL_WRITES=1`; default/Windows false = the old
    /// global-mutex shape).
    pub fn parallel_writes(&self) -> bool {
        self.parallel_writes
    }

    /// Positioned write segment (hot path): concurrent face = read lock
    /// (unix opt-in), fallback = write lock (old global-mutex
    /// semantics). One lock acquisition covers the whole write sequence
    /// (a job's merged cell runs land contiguously — on the fallback
    /// face intra-piece write atomicity equals the old shape; on the
    /// concurrent face intra-piece order is guaranteed by the single
    /// worker's program order).
    pub fn write_batch<R>(&self, f: impl FnOnce(&dyn DiskWriter) -> R) -> R {
        if self.parallel_writes {
            let g = read_lock(&self.inner);
            f(&**g)
        } else {
            let g = write_lock(&self.inner);
            f(&**g)
        }
    }

    /// Exclusive domain for non-write operations: truncate/allocate/
    /// fsync/fence points (open/create/truncate/allocate/size/page-cache
    /// flags) run under the write lock — mutually exclusive with the
    /// write hot path and with each other (the mechanism behind the
    /// "fsync semantics unchanged" red line).
    pub fn with_exclusive<R>(&self, f: impl FnOnce(&mut dyn DiskWriter) -> R) -> R {
        let mut g = write_lock(&self.inner);
        f(g.as_mut())
    }
}

/// Result of pushing one block.
///
/// Test seam (the existing unit-test call surface): after the pooled
/// face landed, production callers (engine/pipeline.rs,
/// engine/verify_pool.rs, engine/run/recovery_admit.rs) all go through
/// [`PooledOutcome`] / `push_block_pooled_at`; this enum and the
/// `push_block` / `push_block_at` / `finish_piece` inline serial path
/// are unreachable in production and kept alive by in-file tests only
/// (semantics verbatim from before the split; retained as a behavioral
/// cross-validation of the pooled path).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// Buffered, piece not yet complete. `pending` = bytes still
    /// missing for the piece.
    Buffered { pending: u64 },
    /// Piece verified and written to disk (`bytes_written` = the
    /// piece's byte count).
    PieceVerified { bytes_written: u64 },
    /// Piece verification failed: cells dropped, piece reset, nothing
    /// touched disk.
    PieceFailed,
    /// Cache overflow evicted some piece's (possibly the current one's)
    /// cells: nothing touched disk, the piece resets for refetch.
    /// aria2 has no such outcome (its eviction writes to disk) — an
    /// intentional divergence.
    PieceAbortedUnverified,
    /// v2 true block-level verification failure: only that 16KiB block
    /// is rejected — not digested, not buffered, the rest of the piece
    /// unaffected; the caller refetches that block by
    /// (piece, begin, len) (versus v1's whole-piece
    /// discard-and-refetch, SPEC §4.3's core v2 benefit). `leaf_index`
    /// = file-global leaf index (the file's first leaf = 0).
    BlockRejected { leaf_index: u64 },
    /// Benign drop of a duplicate delivery: data for the same goff is
    /// already cached (full span covered, or a same-goff cell hit in
    /// `cache_data` as the backstop). No refetch needed — the bytes
    /// are in the piece. aria2 filters duplicates upstream in its
    /// receive path (`BtPieceMessage.cc` `piece->hasBlock`; `Piece.cc`'s
    /// `assert(rv)` is only an invariant backstop); here it converges
    /// into one benign outcome, observable via
    /// [`VerifiedWriter::duplicate_drops`].
    DuplicateDropped,
}

/// v2 per-block verification context (sibling/leaf hashes are supplied
/// by the shared [`HashTreeCache`]).
pub struct BlockCheck {
    /// Synthetic flat piece index -> (owning file's pieces root, global
    /// leaf index of the piece's first leaf). Expanded by the engine
    /// from the per-file base-offset table (the v2 face is all-v2
    /// pieces).
    pub piece_leaves: Arc<Vec<([u8; 32], u64)>>,
    /// One hash tree per file (leaf layer fetched lazily and cached
    /// for direct block-level comparison; shared with other
    /// lazy-request sides — short critical sections, never held across
    /// await).
    pub trees: Arc<Mutex<HashTreeCache>>,
}

/// Result of [`Self::buffer_block`] (steps 1-4 + the completion check;
/// verification/writing are not part of it — the caller picks the
/// inline (test seam) or pooled path).
enum BufferOutcome {
    Buffered {
        pending: u64,
    },
    DuplicateDropped,
    BlockRejected {
        leaf_index: u64,
    },
    /// Piece aborted for refetch: today's source = cache-overflow
    /// eviction destroying it (possibly including this piece); added
    /// source = spill read-back failure (consumed via
    /// `take_complete_entry`, piece already reset).
    PieceAbortedUnverified,
    /// Piece bytes complete (cache cells still in the cache; removal
    /// and the rest of the path belong to the caller).
    Completed,
}

/// Verification inputs for a [`PieceJob`] (pooled face): material
/// cloned from the pool/metadata when the piece completes, handed to
/// the worker together with cache-cell ownership — verification can
/// therefore run independently of the [`VerifiedWriter`] state machine
/// (data + expected values complete, no shared mutable state). The
/// folded implementation ([`piece_matches`]) is shared with the
/// test-seam `finish_piece`: one verification source.
#[derive(Debug, Clone)]
enum PieceVerifyPlan {
    /// v1: whole-piece SHA-1 (authoritative verification = recompute at
    /// assembly; see the `push_block_at` step 5 note).
    V1 { want: [u8; 20] },
    /// v2: piece-root comparison (block hashes are positioned by
    /// in-piece block order, out-of-order safe).
    V2 {
        want: [u8; 32],
        block_hashes: Vec<[u8; 32]>,
        blocks_per_piece: usize,
        single_piece_file: bool,
    },
}

/// Result of [`VerifiedWriter::push_block_pooled_at`]: isomorphic to
/// `PushOutcome` (the test-seam enum), except the "piece completed"
/// variant carries an offloadable verify+write job (cell ownership
/// transfers to the worker with the job).
#[derive(Debug)]
#[non_exhaustive]
pub enum PooledOutcome {
    /// Buffered, piece not yet complete. `pending` = bytes still
    /// missing for the piece.
    Buffered { pending: u64 },
    /// Benign duplicate-delivery drop (same semantics as
    /// `PushOutcome::DuplicateDropped`).
    DuplicateDropped,
    /// v2 true block-level verification failure (same semantics as
    /// `PushOutcome::BlockRejected`).
    BlockRejected { leaf_index: u64 },
    /// Cache overflow evicted an unverified piece (same semantics as
    /// `PushOutcome::PieceAbortedUnverified`; the eviction semantics
    /// face is untouched by pooling).
    PieceAbortedUnverified,
    /// Piece complete: verify+write are packaged as a job; the caller
    /// should hand it to the worker pool ([`PieceJob::verify`] ->
    /// [`PieceJob::write_to`]; a single sequential worker degrades to
    /// the existing serial behavior).
    PieceCompleted(PieceJob),
}

/// Verify+write job for a completed piece (the pooled face).
///
/// Lifecycle: `push_block_pooled_at` removes the cells from
/// [`WrDiskCache`] when the piece completes (cache accounting settles
/// with `remove` — a finished piece no longer participates in
/// eviction, the same moment as the existing serial path), clones the
/// verification inputs from the pool/pairing table, and packages this
/// job. The worker runs [`Self::verify`] first (pure CPU: assemble +
/// hash + cross-check), then [`Self::write_to`] (positioned writes in
/// cell goff order).
///
/// Verify-before-disk holds inside the job: the only legal predecessor
/// of `write_to` is `verify() == Ok(true)`; failure/inconsistency
/// paths expose no cell write entry point.
pub struct PieceJob {
    piece: u64,
    piece_base: u64,
    bytes: u64,
    cells: CacheEntry,
    plan: PieceVerifyPlan,
    cross: Option<CrossRule>,
    /// Write merge cap (from the pipeline disk policy; 0 = per-cell
    /// writes = existing behavior).
    write_merge_max: usize,
    /// Write batching face (`BH_WRITE_COALESCE`, default on): on =
    /// writes go through adjacent contiguous cell runs vectored
    /// (`write_vectored_at`) and may be stitched with the pipeline
    /// batch's adjacent completed pieces into one `write_batch`; off =
    /// per-cell writes (existing behavior; no grouping happens — the
    /// pipeline does not stitch). Shipped to the worker with the job;
    /// a group is homogeneous (verified when the pipeline groups).
    coalesce: bool,
}

impl std::fmt::Debug for PieceJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Cell data bodies are excluded from Debug (they can reach
        // MiB scale).
        f.debug_struct("PieceJob")
            .field("piece", &self.piece)
            .field("piece_base", &self.piece_base)
            .field("bytes", &self.bytes)
            .field("cells", &self.cells.cells().len())
            .field("plan", &self.plan)
            .field("cross", &self.cross.is_some())
            .finish()
    }
}

impl PieceJob {
    /// Piece index (synthetic flat order).
    pub fn piece(&self) -> u64 {
        self.piece
    }

    /// Piece byte count (= bytes to write).
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Front edge of the write span (first cell goff; used by the
    /// pipeline's adjacency test). Structural invariants: cells are
    /// goff-ascending ([`CacheEntry`]) and a completed piece has >= 1
    /// cell (completion implies bytes) — `None` is only a hostile
    /// invariant break; the grouping face treats it as "not adjacent".
    pub fn first_cell_goff(&self) -> Option<u64> {
        self.cells.cells().first().map(DataCell::goff)
    }

    /// Back edge of the write span (last cell goff+len, exclusive end;
    /// paired with [`Self::first_cell_goff`] for the adjacency test:
    /// `prev.last_cell_end() == next.first_cell_goff()`).
    pub fn last_cell_end(&self) -> Option<u64> {
        self.cells.cells().last().map(|c| c.goff() + c.len() as u64)
    }

    /// Verification face (pure CPU, no IO): assemble -> main-format
    /// verification -> (on pass) cross-check. `Ok(true)` = pass;
    /// `Ok(false)` = main verification failed (the caller resets for
    /// refetch under PieceFailed semantics — nothing touched disk);
    /// `Err` = cross-check inconsistency (BEP52 metadata contradiction,
    /// torrent-level failure — nothing touched disk). The main-format
    /// folding is shared with the test seam `finish_piece` via
    /// [`piece_matches`] (one implementation).
    pub fn verify(&self) -> Result<bool, CrossCheckFailed> {
        if !piece_matches(&self.plan, &self.cells, self.piece_base) {
            return Ok(false);
        }
        if let Some(rule) = self.cross {
            // Cross-check inconsistency is the only failure semantics
            // (including the content-length-mismatch invariant-break
            // form — equally a metadata contradiction, torrent-level
            // failure; BEP52 "inconsistency detected").
            cross_check(rule, &self.cells, self.piece, self.piece_base)
                .map_err(|_| CrossCheckFailed { piece: self.piece })?;
        }
        Ok(true)
    }

    /// Write face: cells written positioned in goff-ascending order
    /// (per-piece write order unchanged; piece goff spans never
    /// overlap, so cross-job interleaving is harmless). Call only after
    /// `verify()` passes.
    ///
    /// `writer` shape = the [`SharedDiskWriter`] write hot-path domain
    /// (workers obtain `&dyn DiskWriter` via `write_batch` — unix
    /// concurrent read lock / fallback exclusive write lock; see its
    /// docs).
    ///
    /// Write merging: when `write_merge_max > 0`, adjacent (goff
    /// contiguous) cells merge into single `write_at` calls (capped at
    /// [`Self::write_merge_max`] bytes) — bytes, coordinates, and order
    /// are exactly the per-cell writes; only the syscall granularity
    /// changes (wider write-segment sizes: less write amplification on
    /// SSD / sequentialized on HDD). 0 = per-cell writes (existing
    /// behavior).
    ///
    /// With `coalesce` on, adjacent contiguous cell runs go out as one
    /// **vectored** write (`write_vectored_at`, unix pwritev zero-copy
    /// iovecs — the copy-and-stitch face retires); off = existing
    /// semantics bit-for-bit. Returns the write calls issued (the
    /// `write_at` + `write_vectored_at` faces).
    pub fn write_to(&self, writer: &dyn DiskWriter) -> Result<usize, StoreError> {
        Self::write_group(&[self], writer)
            .map(|calls| calls[0])
            .map_err(|(e, _)| e)
    }

    /// Group write face: the group's jobs (pipeline stitching order =
    /// goff-ascending, adjacent continuation) have their cells
    /// concatenated into **cross-piece contiguous runs**, each written
    /// with one vectored call. Bytes/coordinates/order are exactly the
    /// per-job writes (only call granularity changes); call only after
    /// the whole group passes `verify()` (verify-before-disk: what is
    /// merged is the write calls of verified pieces, not unverified
    /// data).
    ///
    /// Returns the per-job write call count (indices align with the
    /// input); on write failure returns `(error, index of the first job
    /// not fully written)` — the caller maps verdicts as `[..idx)` =
    /// Written (bytes on disk), `[idx..)` = WriteFailed (refetch and
    /// rewrite are idempotent: same coordinates, same bytes,
    /// overwrite).
    ///
    /// Mixed `coalesce` within a group (defensive fallback branch) =
    /// per-job existing semantics [`write_cells_merged`].
    pub fn write_group(
        jobs: &[&PieceJob],
        writer: &dyn DiskWriter,
    ) -> Result<Vec<usize>, (StoreError, usize)> {
        let Some(first) = jobs.first() else {
            return Ok(Vec::new());
        };
        if !first.coalesce {
            // Fallback face (BH_WRITE_COALESCE=0 / single-job backstop):
            // per-job existing writes ([`write_cells_merged`]
            // bit-for-bit — grouping does not happen; groups are only
            // built by the pipeline when coalesce is on, so this branch
            // is defensive).
            let mut calls = Vec::with_capacity(jobs.len());
            for (i, job) in jobs.iter().enumerate() {
                let n = write_cells_merged(job.cells.cells(), writer, job.write_merge_max, false)
                    .map_err(|e| (e, i))?;
                calls.push(n);
            }
            return Ok(calls);
        }
        // Batching face: cross-job adjacent cell-run construction
        // (single implementation [`build_cell_runs`]). Byte cap =
        // [`Self::write_merge_max`] (the disk-policy write-amplification
        // window; 0 = no byte cap — the structural run bound is the
        // pipeline batch depth of <= 32 blocks x 16KiB ≈ 512KiB, and
        // stitched groups only extend it).
        let byte_cap = first.write_merge_max;
        let runs = build_cell_runs(
            jobs.iter()
                .enumerate()
                .flat_map(|(ji, job)| job.cells.cells().iter().map(move |c| (ji, c))),
            byte_cap,
        );
        let mut calls = vec![0usize; jobs.len()];
        for run in &runs {
            let res = if run.bufs.len() == 1 {
                writer.write_at(run.goff, run.bufs[0])
            } else {
                writer.write_vectored_at(run.goff, &run.bufs)
            };
            match res {
                Ok(()) => {
                    for c in &mut calls[run.first_job..=run.last_job] {
                        *c += 1;
                    }
                }
                Err(e) => return Err((e, run.first_job)),
            }
        }
        Ok(calls)
    }

    /// Per-block SHA-1 snapshot of a failed piece (smart_ban evidence
    /// input; v1 only — v2 block-level verification attributes failures
    /// naturally; cross-validation: libtorrent `smart_ban.cpp` returns
    /// nullptr from the plugin when `has_v2()`).
    ///
    /// Consumption timing: after `verify() == Ok(false)` and before the
    /// job is dropped (on the verification worker): a failed piece's
    /// data exists only in this job's cells (verify-before-disk —
    /// failed pieces are never written), so libtorrent's "read back
    /// from disk and recompute" (`on_piece_failed`, `smart_ban.cpp`)
    /// becomes structurally "recompute inside the assembly buffer"
    /// (intentional divergence: the reference's data is already on
    /// disk; here it is in memory cells — equivalent evidence, one
    /// less disk IO).
    ///
    /// Implementation: cells feed a SHA-1 at 16KiB block boundaries
    /// goff-ascending (structural invariant, [`CacheEntry`]) — no
    /// whole-piece assembly (saves one full-piece memcpy); returns
    /// per-block digests (index = in-piece block order). v2 jobs
    /// return None.
    pub fn failed_block_digests(&self) -> Option<Vec<[u8; 20]>> {
        if !matches!(self.plan, PieceVerifyPlan::V1 { .. }) {
            return None;
        }
        const BLOCK: u64 = crate::merkle::BLOCK_SIZE as u64;
        let mut out: Vec<[u8; 20]> = Vec::with_capacity(self.bytes.div_ceil(BLOCK) as usize);
        let mut hasher = Sha1::new();
        let mut filled: u64 = 0;
        for cell in self.cells.cells() {
            let data = cell.data();
            let mut off = 0usize;
            while off < data.len() {
                let take = (BLOCK - filled).min((data.len() - off) as u64) as usize;
                hasher.update(&data[off..off + take]);
                filled += take as u64;
                off += take;
                if filled == BLOCK {
                    out.push(hasher.finalize().into());
                    hasher = Sha1::new();
                    filled = 0;
                }
            }
        }
        if filled > 0 {
            out.push(hasher.finalize().into());
        }
        Some(out)
    }
}

/// Hybrid cross-check rule (BEP52 upgrade-path clause: "they must also
/// verify that pieces match both piece hash formats" — while both
/// swarms run in parallel, a piece obtained from either face gets the
/// other format's hash verification appended before it lands; a
/// mismatch = metadata contradiction).
#[derive(Debug, Clone, Copy)]
pub enum CrossRule {
    /// This face is the v1 stream face: when the piece completes
    /// (stream bytes, including pad zero spans), the **content
    /// prefix** `content_bytes` is re-hashed per block into a v2 piece
    /// root and compared with `root`. The tree rule dispatches on the
    /// owning file's piece count (`single_piece_file`, see hashpool).
    V2Root {
        content_bytes: u64,
        root: [u8; 32],
        blocks_per_piece: usize,
        single_piece_file: bool,
    },
    /// This face is the v2 content face: when the piece completes
    /// (content bytes), append `pad_zeros` zero bytes to complete the
    /// piece and compare SHA-1 against `hash` (the v1 hash covers the
    /// whole piece including pad zeros, BEP47 L85 "content of padding
    /// file is all zeros").
    V1Hash { hash: [u8; 20], pad_zeros: u64 },
}

/// Cross-check failure (BEP52 "inconsistency detected" -> torrent-level
/// failure).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("hybrid cross-check failed at piece {piece}: hashes inconsistent between formats")]
pub struct CrossCheckFailed {
    pub piece: u64,
}

/// Verified write pipeline (multi-file layout plugs in via a flattened
/// HashPool::new_plan; `piece_index` = synthetic flat piece index).
pub struct VerifiedWriter {
    /// Shared write handle (pooled workers and the inline completion
    /// path share one underlying writer; the constructor still takes a
    /// `Box`, wrapped for sharing internally — existing call sites
    /// unchanged).
    writer: SharedDiskWriter,
    pool: HashPool,
    cache: WrDiskCache<u64>,
    /// Per-piece cross-check rules (hybrid; empty default = no
    /// appended verification).
    cross: Vec<Option<CrossRule>>,
    /// v2 per-block verification context (None = v1/whole-piece
    /// verification path, behavior unchanged).
    block_check: Option<BlockCheck>,
    /// Cumulative benign duplicate-delivery drops (observability).
    duplicate_drops: u64,
    /// Write merge cap (bytes; 0 = per-cell writes = existing
    /// behavior). Injected via [`Self::with_disk_policy`], shipped to
    /// workers with [`PieceJob`].
    write_merge_max: usize,
    /// Evicted unverified piece indices (instrumentation): every
    /// step-4 eviction registers here; the caller drains via
    /// [`Self::take_evicted`]. Eviction = data + digests reset
    /// together (unflushable under verify-before-disk) and used to be
    /// a purely silent event; silent discard of nearly all in-flight
    /// bytes participates in progress-stall loops, so observability
    /// came first.
    pending_evicted: Vec<u64>,
    /// Cumulative evictions (instrumentation; a total independent of
    /// `pending_evicted` draining).
    evicted_unverified: u64,
    /// Cumulative evicted bytes (instrumentation): each eviction adds
    /// the actual byte count of the destroyed cache entry
    /// ([`crate::cache::Evicted::bytes`] = the data destroyed with
    /// the eviction). The count-only `evicted_unverified` cannot
    /// distinguish "4096-byte fragments x N" from "near-whole pieces
    /// x M" (two churn shapes); with bytes accounted, a churn
    /// amplification ratio against total payload becomes computable.
    evicted_unverified_bytes: u64,
    /// v2 block-hash write-path precompute table (None = the table is
    /// off — v1 faces / switch off; every path is then the status
    /// quo, bit-identical). Rule source and lifecycle discipline:
    /// [`crate::precomputed_block_hashes`] module docs.
    precomputed: Option<PrecomputedBlockHashes>,
    /// Cumulative precompute hit slots (observability): slots served
    /// from the table (no read-back) when merging completed-piece
    /// verification inputs (the dual of the spec's "read-back count
    /// goes to zero"; with the table on, the hit rate should be
    /// ~100%).
    precomputed_hits: u64,
    /// Cumulative precompute miss slots (observability): slots not
    /// yet computed in the table, falling back to pool-located hashes
    /// (the status-quo path). ~0 in the table-on steady state;
    /// nonzero only when the table was attached mid-face or entries
    /// were cleared abnormally — a nonzero value is an observable
    /// regression signal.
    precomputed_misses: u64,
    /// Face-level block buffer pool (None = direct heap allocation,
    /// the existing shape; the `BH_BLOCK_ARENA=0` fallback switch /
    /// unit-test shape). Cell construction goes through
    /// [`crate::cache::DataCell::with_data_in`]; a Drop guard returns
    /// blocks.
    block_arena: Option<std::sync::Arc<taiji_io::block_arena::BlockArena>>,
    /// Unverified spill area (None = switch off — the default;
    /// eviction destroys and refetches, the status-quo semantics,
    /// behavior bit-identical). Cache-full victims spill to a sidecar
    /// (within the disk budget) and are read back at assembly; source
    /// and fallback face: [`crate::spill`] module docs.
    spill: Option<SpillStore>,
    /// Budget-overflow fallback destroyed bytes (observability): on
    /// the spill-enabled face, cumulative unverified bytes destroyed
    /// for budget enforcement — FIFO displacement victims plus the
    /// not-absorbed fallback arm (single-entry over-cap / store
    /// failure; read-back-failure destruction is not a budget face
    /// and is not counted). Always 0 with spill off (eviction-destroy
    /// is the status quo, accounted in `evicted_unverified_bytes`).
    /// Fed by the pipeline's batch-buffer delta method (same as the
    /// `spill_*` faces).
    spill_fallback_destroy_bytes: u64,
    /// Write batching face (`BH_WRITE_COALESCE` default read; off =
    /// per-cell existing semantics bit-for-bit). Shipped with
    /// [`PieceJob`] and shared with the inline completion seam
    /// (`finish_piece`).
    write_coalesce: bool,
}

impl std::fmt::Debug for VerifiedWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted face (the `PieceJob` Debug rule): the cache cells and
        // the pool are the bulk data — the observable identity is the
        // writer handle plus the counters and switches.
        f.debug_struct("VerifiedWriter")
            .field("writer", &self.writer)
            .field("write_merge_max", &self.write_merge_max)
            .field("write_coalesce", &self.write_coalesce)
            .field("duplicate_drops", &self.duplicate_drops)
            .field("pending_evicted", &self.pending_evicted.len())
            .field("evicted_unverified", &self.evicted_unverified)
            .field("evicted_unverified_bytes", &self.evicted_unverified_bytes)
            .field("block_check", &self.block_check.is_some())
            .field("precomputed", &self.precomputed.is_some())
            .field("precomputed_hits", &self.precomputed_hits)
            .field("precomputed_misses", &self.precomputed_misses)
            .field("block_arena", &self.block_arena.is_some())
            .field("spill", &self.spill.is_some())
            .field(
                "spill_fallback_destroy_bytes",
                &self.spill_fallback_destroy_bytes,
            )
            .finish_non_exhaustive()
    }
}

impl VerifiedWriter {
    pub fn new(writer: Box<dyn DiskWriter>, pool: HashPool, cache_limit: usize) -> VerifiedWriter {
        VerifiedWriter {
            writer: SharedDiskWriter::new(writer),
            pool,
            cache: WrDiskCache::new(cache_limit),
            cross: Vec::new(),
            block_check: None,
            duplicate_drops: 0,
            // Default 0 = per-cell writes (existing behavior, zero
            // change).
            write_merge_max: 0,
            pending_evicted: Vec::new(),
            evicted_unverified: 0,
            evicted_unverified_bytes: 0,
            // Table off by default (the status-quo path); v2 faces
            // attach it via the pipeline's
            // [`Self::with_precomputed_block_hashes`].
            precomputed: None,
            precomputed_hits: 0,
            precomputed_misses: 0,
            block_arena: None,
            // Spill off by default (fallback switch; spec: "default
            // off — on only after the trigger condition holds"). The
            // pipeline attaches via [`Self::with_spill`].
            spill: None,
            // Budget-overflow fallback destroyed bytes (always 0 with
            // spill off).
            spill_fallback_destroy_bytes: 0,
            // Write batching default = the `BH_WRITE_COALESCE`
            // environment decision (default on); the live seam
            // [`Self::set_write_coalesce`] follows the same pattern as
            // `set_write_merge_max`.
            write_coalesce: write_coalesce_env(),
        }
    }

    /// Constructor with a hybrid cross-check table (the table length
    /// must equal the piece count; entries may be None). Converged to
    /// `new` + cross assignment (field set and defaults identical,
    /// zero behavior change).
    pub fn with_cross(
        writer: Box<dyn DiskWriter>,
        pool: HashPool,
        cache_limit: usize,
        cross: Vec<Option<CrossRule>>,
    ) -> VerifiedWriter {
        let mut vw = Self::new(writer, pool, cache_limit);
        vw.cross = cross;
        vw
    }

    /// Attach the v2 per-block verification context ([`BlockCheck`]).
    pub fn with_block_check(mut self, check: BlockCheck) -> VerifiedWriter {
        self.block_check = Some(check);
        self
    }

    /// Attach the v2 block-hash write-path precompute table
    /// (cross-validation: libtorrent RC_2_1
    /// `precomputed_block_hashes.cpp` write-path precompute +
    /// `pread_disk_io.cpp` hash2 job table consumption). The caller
    /// (engine pipeline) gates by face type + switch: faces with v2
    /// pieces attach by default (`BH_V2_HASH_PRECOMPUTE=0` disables),
    /// v1 faces skip (no surplus hashing on the v1 face). Unattached
    /// = table off; every path is the status quo.
    pub fn with_precomputed_block_hashes(
        mut self,
        table: PrecomputedBlockHashes,
    ) -> VerifiedWriter {
        self.precomputed = Some(table);
        self
    }

    /// Precompute hit-slot cumulative readout (observability; always
    /// 0 with the table off).
    pub fn precomputed_hits(&self) -> u64 {
        self.precomputed_hits
    }

    /// Precompute miss (pool-fallback) slot cumulative readout
    /// (observability; ~0 in the table-on steady state — the counter
    /// for the "read-back count goes to zero" acceptance goal;
    /// always 0 with the table off).
    pub fn precomputed_misses(&self) -> u64 {
        self.precomputed_misses
    }

    /// Attach the disk policy: currently takes the write merge
    /// window; write-face behavior follows the tier (0 = per-cell,
    /// the existing behavior). The remaining parameters (allocation /
    /// flush cadence / IO quota / read merge) are consumed directly
    /// by the pipeline at build and cadence points.
    pub fn with_disk_policy(mut self, policy: DiskPolicy) -> VerifiedWriter {
        self.write_merge_max = policy.write_merge_max_bytes;
        self
    }

    /// Attach the face-level block buffer pool: cells lease from the
    /// pool (removing per-block malloc/mmap churn); None = direct
    /// heap allocation, the existing shape (fallback switch).
    pub fn with_block_arena(
        mut self,
        arena: Option<std::sync::Arc<taiji_io::block_arena::BlockArena>>,
    ) -> VerifiedWriter {
        self.block_arena = arena;
        self
    }

    /// Attach the unverified spill area: cache-full victims spill to
    /// a sidecar (not destroyed, not reset, no notification) and are
    /// read back and merged at assembly; None = off (the default,
    /// the status-quo evict-and-destroy semantics, behavior
    /// bit-identical). Lifecycle/budget/fallback:
    /// [`crate::spill`] module docs.
    pub fn with_spill(mut self, spill: SpillStore) -> VerifiedWriter {
        self.spill = Some(spill);
        self
    }

    /// Cumulative spill write-bytes readout (observability; fed to
    /// SessionMetrics as batch deltas, same method as
    /// `evicted_unverified_bytes`).
    pub fn spill_write_bytes(&self) -> u64 {
        self.spill
            .as_ref()
            .map(crate::spill::SpillStore::write_bytes_total)
            .unwrap_or(0)
    }

    /// Cumulative spill read-back bytes readout (observability).
    pub fn spill_read_bytes(&self) -> u64 {
        self.spill
            .as_ref()
            .map(crate::spill::SpillStore::read_bytes_total)
            .unwrap_or(0)
    }

    /// Read-back piece count readout (observability; the read-back
    /// hit-rate numerator).
    pub fn spill_readback_pieces(&self) -> u64 {
        self.spill
            .as_ref()
            .map(crate::spill::SpillStore::readback_pieces_total)
            .unwrap_or(0)
    }

    /// Budget-overflow fallback destroyed bytes (observability; the
    /// budget attribution split of "residual evictions" with spill
    /// on — the difference from `evicted_unverified_bytes` =
    /// non-budget faces such as read-back-failure destruction, plus
    /// status-quo evictions with spill off).
    pub fn spill_fallback_destroy_bytes(&self) -> u64 {
        self.spill_fallback_destroy_bytes
    }

    /// Live write merge window: change the merge cap mid-run — it
    /// takes effect for the next batch's completed-piece jobs /
    /// inline writes (in-flight jobs finish with their
    /// construction-time window, no interruption). Only the window
    /// bytes change; tier semantics are untouched.
    pub fn set_write_merge_max(&mut self, max: usize) {
        self.write_merge_max = max;
    }

    /// Live write-batching seam (pipeline promotion rebuild /
    /// re-apply on tier switch, same pattern as
    /// [`Self::set_write_merge_max`]): on = completed-piece writes
    /// use adjacent contiguous vectored runs and the pipeline may
    /// stitch adjacent pieces; off = per-cell existing semantics
    /// bit-for-bit.
    pub fn set_write_coalesce(&mut self, on: bool) {
        self.write_coalesce = on;
    }

    /// Write-batching face observation (test assertions / logs;
    /// default = the `BH_WRITE_COALESCE` environment decision = on).
    pub fn write_coalesce_on(&self) -> bool {
        self.write_coalesce
    }

    /// Shared write handle (pooled face): taken once at pipeline
    /// construction and handed to the worker pool — every worker and
    /// this struct write the same underlying file handle (lock
    /// domain semantics in the [`SharedDiskWriter`] docs).
    pub fn writer_handle(&self) -> SharedDiskWriter {
        self.writer.clone()
    }

    /// Cumulative benign duplicate-drop readout (observability).
    pub fn duplicate_drops(&self) -> u64 {
        self.duplicate_drops
    }

    /// Cumulative evicted-unverified-piece readout
    /// (instrumentation).
    pub fn evicted_unverified(&self) -> u64 {
        self.evicted_unverified
    }

    /// Cumulative evicted-unverified byte readout
    /// (instrumentation; accumulated at the same point as the count
    /// face [`Self::evicted_unverified`]; bytes = the actual data of
    /// the destroyed cache entry).
    pub fn evicted_unverified_bytes(&self) -> u64 {
        self.evicted_unverified_bytes
    }

    /// Drain the step-4 registered evicted piece indices
    /// (instrumentation / recovery face): the caller (store
    /// pipeline) drains after every push and syncs the upstream
    /// bookkeeping / reports back to the engine.
    pub fn take_evicted(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.pending_evicted)
    }

    /// Pool reset for a verification-failed piece (pooled face; the
    /// serial path — the `finish_piece` test seam — resets inline; on
    /// the pooled path the verification verdict is produced on the
    /// worker, so the reset duty travels back to the caller with the
    /// verdict): without clearing, the piece's pool state stays
    /// `complete` forever and refetched blocks all hit the benign
    /// `PieceAlreadyComplete` drop — the piece could never complete
    /// again (progress stall). A pure in-memory bitmap operation,
    /// safe to call synchronously.
    /// Note: the precompute-table entry is moved out whole when the
    /// completed piece is packaged (`take_piece`) — the failed
    /// piece's refetched bytes re-enter the table, so no table
    /// clearing is needed here.
    pub fn reset_failed_piece(&mut self, piece: u64) {
        self.pool.reset_piece(piece);
    }

    /// Eviction accounting + sampled warning (drop observability with
    /// sampled high-frequency logging: the first 10 events warn
    /// individually (including fill rate — a near-complete piece being
    /// evicted is direct evidence of progress destruction), then every
    /// 100th warns, the rest debug). Also adds the byte face to the
    /// WARN fields (`bytes` = destroyed this time, `evicted_bytes` =
    /// cumulative).
    fn note_evicted_unverified(&mut self, piece: u64, received: u64, expected: u64, bytes: u64) {
        self.evicted_unverified += 1;
        self.evicted_unverified_bytes = self.evicted_unverified_bytes.saturating_add(bytes);
        self.pending_evicted.push(piece);
        let total = self.evicted_unverified;
        let evicted_bytes = self.evicted_unverified_bytes;
        if total <= 10 || total.is_multiple_of(100) {
            tracing::warn!(
                target: "taiji::store::verified",
                piece, received, expected,
                fill = if expected > 0 { received as f64 / expected as f64 } else { 0.0 },
                evictions = total,
                bytes, evicted_bytes,
                "piece evicted unverified (data discarded per verify-before-disk forensics)"
            );
        } else {
            tracing::debug!(
                target: "taiji::store::verified",
                piece, received, expected, evictions = total,
                bytes, evicted_bytes,
                "piece evicted unverified (sampled)"
            );
        }
    }

    /// Unverified piece destruction (the single source of the
    /// status-quo eviction semantics): **cache entry removal** +
    /// fill-rate sampled warning + eviction registration (upstream
    /// bookkeeping sync) + pool digest reset + precompute entry
    /// clearing (cross-validation `precomputed_block_hashes.cpp`
    /// `drop()` — the digest is destroyed, so lingering slots are
    /// cleared with it; refetched blocks re-enter the table) + spill
    /// entry invalidation (when a piece is destroyed/reset on the
    /// cache side, its spilled bytes are discarded with it —
    /// otherwise redelivered blocks get swallowed as benign
    /// duplicates by the spill coverage check while the pool count
    /// is reset, and the piece could never complete).
    ///
    /// Two-sided semantics of the cache removal: the status-quo
    /// eviction via [`WrDiskCache::ensure_limit_min_loss`] already
    /// **hands the victim's cells over in full** (`Evicted.cells`),
    /// so the entry is an empty shell here and `remove` subtracts 0 —
    /// the status-quo path is unchanged; on the displacement path the
    /// victim may still hold live cache cells (the "partial spill +
    /// new block back in cache" coexistence) — without clearing,
    /// redelivered blocks get swallowed as duplicates by the cache
    /// coverage check while the pool count is reset, and the piece
    /// could never complete (permanent stall; the mirror of the
    /// spill-side invalidation that the cache side previously
    /// missed). Destroyed-byte accounting = input bytes + residual
    /// cache bytes (`Evicted.bytes` and `SpillStoreOutcome.displaced.1`
    /// each exclude the other half; adding them gives the whole).
    /// Returns the destroyed total (same source as
    /// `note_evicted_unverified`'s bytes) — consumed by the
    /// fallback-destroy counter.
    fn destroy_unverified_piece(&mut self, piece: u64, bytes: u64) -> u64 {
        let received = self.pool.piece_received(piece).unwrap_or(0);
        let expected = self.pool.piece_bytes(piece).unwrap_or(0);
        let cached_residual = self
            .cache
            .remove(&piece)
            .map_or(0, |entry| entry.size() as u64);
        let destroyed = bytes.saturating_add(cached_residual);
        self.note_evicted_unverified(piece, received, expected, destroyed);
        self.pool.reset_piece(piece);
        if let Some(table) = self.precomputed.as_mut() {
            table.drop_piece(piece);
        }
        if let Some(spill) = self.spill.as_mut() {
            spill.drop_piece(piece);
        }
        destroyed
    }

    /// Completed-piece cell collection: write-cache entry + spill
    /// read-back merged — piece bytes are held exclusively by the
    /// cache/spill domains at block granularity; the read-back cells
    /// (goff-ascending) and the cache cells (goff-ascending) are
    /// disjoint sets, merged by goff into a rebuilt entry.
    /// `Ok(None)` = spill read-back failure, the piece was destroyed
    /// and reset; the caller handles it as
    /// `PieceAbortedUnverified`.
    ///
    /// A read-back IO failure = the spilled bytes are lost (semantics
    /// = never received, see the [`crate::spill`] module docs): the
    /// piece is destroyed and reset (cache cells discarded with it) —
    /// under verify-before-disk an incomplete entry must not enter
    /// verification/writing.
    fn take_complete_entry(&mut self, piece_index: u64) -> Result<Option<CacheEntry>, StoreError> {
        let Some(mut entry) = self.cache.remove(&piece_index) else {
            return Err(StoreError::Internal(
                "piece cells missing at completion".into(),
            ));
        };
        let Some(spill) = self.spill.as_mut() else {
            return Ok(Some(entry));
        };
        if !spill.holds(piece_index) {
            return Ok(Some(entry));
        }
        let read_back = match spill.read_back(piece_index) {
            Ok(cells) => cells,
            Err(e) => {
                tracing::warn!(target: "taiji::store::verified", piece = piece_index, error = %e,
                    "spill read-back failed: piece data lost, reset for re-fetch");
                let cached_bytes = entry.size() as u64;
                self.destroy_unverified_piece(piece_index, cached_bytes);
                return Ok(None);
            }
        };
        let mut merged: Vec<DataCell> = entry.take_cells().into_iter().chain(read_back).collect();
        merged.sort_by_key(DataCell::goff);
        let mut rebuilt = CacheEntry::default();
        for cell in merged {
            if !rebuilt.cache_data(cell) {
                return Err(StoreError::Internal(format!(
                    "spill merge goff collision at piece {piece_index}"
                )));
            }
        }
        Ok(Some(rebuilt))
    }

    /// Duplicate-drop accounting + sampled warning (the first 10 warn
    /// individually, then every 100th, the rest debug).
    fn note_duplicate_drop(&mut self, piece: u64, goff: u64, len: usize) {
        self.duplicate_drops += 1;
        let drops = self.duplicate_drops;
        if drops <= 10 || drops.is_multiple_of(100) {
            tracing::warn!(
                target: "taiji::store::verified",
                piece, goff, len, drops,
                "duplicate block delivery dropped benignly (data already cached at goff)"
            );
        } else {
            tracing::debug!(
                target: "taiji::store::verified",
                piece, goff, len, drops,
                "duplicate block dropped (sampled)"
            );
        }
    }

    /// Push one block (goff = piece_index * piece_len + offset_in_piece).
    ///
    /// Test seam (the existing unit-test call surface; production goes
    /// through the pooled path, see the [`PushOutcome`] seam note):
    /// buffering/verification/discipline are fully shared with
    /// [`Self::push_block_pooled_at`] (the same `buffer_block`).
    #[cfg(test)]
    pub fn push_block(
        &mut self,
        piece_index: u64,
        offset_in_piece: u32,
        block: &[u8],
    ) -> Result<PushOutcome, StoreError> {
        let goff = piece_index * u64::from(self.pool.piece_len()) + u64::from(offset_in_piece);
        self.push_block_at(
            piece_index,
            goff,
            offset_in_piece,
            &bytes::Bytes::copy_from_slice(block),
        )
    }

    /// Push one block with a caller-given disk offset (the v2 data
    /// face: in a v2-only compact layout, file-boundary gaps exist
    /// between pieces, so `goff != flat_idx * piece_len`; the caller
    /// precomputes each piece's goff via `Layout::v2_piece_offset`).
    /// Verification and discipline as in [`Self::push_block`].
    ///
    /// The completion path is **inline serial** (assembly ->
    /// verification -> write inside this call). Pooled callers use
    /// [`Self::push_block_pooled_at`] (buffering/verification/
    /// discipline fully shared; only the completed piece is offloaded
    /// as a [`PieceJob`]).
    ///
    /// Test seam (the existing unit-test call surface; unreachable in
    /// production, see the [`PushOutcome`] seam note).
    #[cfg(test)]
    pub fn push_block_at(
        &mut self,
        piece_index: u64,
        goff: u64,
        offset_in_piece: u32,
        block: &bytes::Bytes,
    ) -> Result<PushOutcome, StoreError> {
        match self.buffer_block(piece_index, goff, offset_in_piece, block)? {
            BufferOutcome::Buffered { pending } => Ok(PushOutcome::Buffered { pending }),
            BufferOutcome::DuplicateDropped => Ok(PushOutcome::DuplicateDropped),
            BufferOutcome::BlockRejected { leaf_index } => {
                Ok(PushOutcome::BlockRejected { leaf_index })
            }
            BufferOutcome::PieceAbortedUnverified => Ok(PushOutcome::PieceAbortedUnverified),
            BufferOutcome::Completed => {
                // Cell removal timing identical to before the split
                // (completed pieces leave the cache immediately — no
                // further eviction/coverage participation; accounting
                // settles with remove). Removal includes the spill
                // read-back merge (None = read-back failure, piece
                // already reset, handled as abort-and-refetch).
                let Some(entry) = self.take_complete_entry(piece_index)? else {
                    return Ok(PushOutcome::PieceAbortedUnverified);
                };
                // Piece base derived from this block's delivery
                // coordinates (same convention as [`cross_check`];
                // tolerates the non-flat goff contract; on the flat
                // face both coincide).
                let piece_base = goff - u64::from(offset_in_piece);
                self.finish_piece(piece_index, piece_base, entry)
            }
        }
    }

    /// Push one block (pooled form): buffering/digest/eviction fully
    /// shared with `push_block_at` (steps 1-4, the same code path);
    /// the only difference is that a completed piece does not
    /// verify/write here — the cache cells are removed + verification
    /// inputs cloned and packaged into a [`PieceJob`] — which the
    /// caller hands to the worker pool (verification CPU and disk
    /// writes therefore parallelize; cross-piece out-of-order is
    /// naturally supported, intra-piece write order is guaranteed by
    /// the job's goff-ascending cells). The eviction semantics face
    /// (min-loss victim order + eviction registration) is unchanged.
    ///
    /// `block` is the wire decode slice (borrowed `Bytes` — the end of
    /// the zero-copy chain): the caller holds the frame body; this face
    /// adopts it into a shared cell on the new-cell path (zero
    /// placement copies) and copies only the rare append-remainder form
    /// into cache cells — block data takes zero or one placement copy
    /// on its way to its final place.
    pub fn push_block_pooled_at(
        &mut self,
        piece_index: u64,
        goff: u64,
        offset_in_piece: u32,
        block: &bytes::Bytes,
    ) -> Result<PooledOutcome, StoreError> {
        match self.buffer_block(piece_index, goff, offset_in_piece, block)? {
            BufferOutcome::Buffered { pending } => Ok(PooledOutcome::Buffered { pending }),
            BufferOutcome::DuplicateDropped => Ok(PooledOutcome::DuplicateDropped),
            BufferOutcome::BlockRejected { leaf_index } => {
                Ok(PooledOutcome::BlockRejected { leaf_index })
            }
            BufferOutcome::PieceAbortedUnverified => Ok(PooledOutcome::PieceAbortedUnverified),
            BufferOutcome::Completed => {
                // Cell removal timing identical to the existing serial
                // path (completed pieces leave the cache immediately —
                // no further eviction/coverage participation;
                // accounting settles with remove). Removal includes
                // the spill read-back merge (None = read-back
                // failure, piece already reset, handled as
                // abort-and-refetch).
                let Some(entry) = self.take_complete_entry(piece_index)? else {
                    return Ok(PooledOutcome::PieceAbortedUnverified);
                };
                let bytes = entry.size() as u64;
                let cross = self.cross.get(piece_index as usize).copied().flatten();
                let plan = if let Some(want) = self.pool.expected_v1_digest(piece_index)? {
                    // v1: authoritative verification = recompute the
                    // whole-piece SHA-1 at assembly (see the
                    // `finish_piece` step 5 note).
                    PieceVerifyPlan::V1 { want }
                } else {
                    // v2 piece: block hashes are positioned by
                    // in-piece order (out-of-order safe); clone the
                    // verification inputs (want root + hashes +
                    // tree-rule dispatch parameters) for the worker's
                    // independent folding. The pool keeps its complete
                    // state (late blocks still fail explicitly with
                    // PieceAlreadyComplete, as before); the failure
                    // reset stays with the caller after the verdict.
                    match self.pool.v2_verify_inputs(piece_index)? {
                        Some(V2VerifyInputs {
                            want,
                            mut block_hashes,
                            blocks_per_piece,
                            single_piece_file,
                        }) => {
                            // Piece verification inputs consult the
                            // precompute table first (cross-validation:
                            // the libtorrent hash2 job's take/fill —
                            // `precomputed_block_hashes.cpp` `take()`
                            // moves the entry out whole +
                            // `pread_disk_io.cpp` `fill_precomputed_v2`
                            // fills the job inputs). Entry ownership
                            // transfers with this job ("released with
                            // the PieceJob once the completed piece is
                            // promoted"); nothing lingers in the
                            // table. Miss slots keep the pool-located
                            // hash = the status-quo path (the values
                            // are identical — the same function of the
                            // same bytes at the same time; the
                            // decision semantics do not change).
                            if let Some(table) = self.precomputed.as_mut()
                                && let Some(slots) = table.take_piece(piece_index)
                            {
                                for (dst, src) in block_hashes.iter_mut().zip(slots.iter()) {
                                    match src {
                                        Some(h) => {
                                            *dst = *h;
                                            self.precomputed_hits += 1;
                                        }
                                        None => self.precomputed_misses += 1,
                                    }
                                }
                            }
                            PieceVerifyPlan::V2 {
                                want,
                                block_hashes,
                                blocks_per_piece,
                                single_piece_file,
                            }
                        }
                        None => {
                            return Err(StoreError::Internal(
                                "piece complete but neither v1 digest nor v2 inputs available"
                                    .into(),
                            ));
                        }
                    }
                };
                Ok(PooledOutcome::PieceCompleted(PieceJob {
                    piece: piece_index,
                    piece_base: goff - u64::from(offset_in_piece),
                    bytes,
                    cells: entry,
                    plan,
                    cross,
                    write_merge_max: self.write_merge_max,
                    coalesce: self.write_coalesce,
                }))
            }
        }
    }

    /// Steps 1-4: range check -> duplicate coverage check -> v2
    /// block-level verification -> digest accumulation -> buffer/evict
    /// -> completion check. Returns [`BufferOutcome::Completed`] =
    /// piece bytes complete (verify+write follow the caller's chosen
    /// path: inline `finish_piece` (test seam) or pooled [`PieceJob`]).
    ///
    /// `block` is the wire decode slice (`Bytes`, borrowed): the
    /// buffer step reads it (hash/coverage/append) and, on the
    /// new-cell path (no contiguous append absorbed anything), adopts
    /// it into a [`DataCell::with_shared`] cell — zero placement
    /// copies. Only the rare remainder form (a partial append leaves a
    /// tail) still copies into a pooled lease.
    fn buffer_block(
        &mut self,
        piece_index: u64,
        goff: u64,
        offset_in_piece: u32,
        block_bytes: &bytes::Bytes,
    ) -> Result<BufferOutcome, StoreError> {
        let block: &[u8] = block_bytes;
        if block.is_empty() || block.len() > crate::merkle::BLOCK_SIZE as usize {
            return Err(StoreError::Internal(format!(
                "block length {} outside (0, 16KiB]",
                block.len()
            )));
        }
        // 1) In-piece range check (out of bounds = protocol violation;
        // the caller disconnects. Explicit error here).
        self.pool
            .check_range(piece_index, offset_in_piece, block.len() as u32)?;
        // 1.25) Benign drop of duplicate deliveries (coverage check,
        // before any digest/byte accounting — duplicate bytes must not
        // pollute HashPool counts): "data already present at the same
        // goff" (cache span fully covered, including sub-block
        // redelivery) -> benign drop + count. cross-validation aria2:
        // the receive path filters upstream (`BtPieceMessage.cc`
        // `piece->hasBlock(...)` -> "Already have this block.", a
        // per-piece block bitfield); this layer is the last line of
        // defense at the position of `Piece.cc`'s `assert(rv)` —
        // intentional divergence: duplicate blocks are the norm on
        // real swarms (request timeout resends / endgame / fast-ext
        // double sends / late blocks); fatalizing would turn
        // data-correct tasks into explicit failures. Robustness wins;
        // drops are observable (count + sampled log).
        // Red line: only full coverage drops; a partial overlap
        // carries new bytes and does not qualify (it falls into the
        // existing append/residual-cell semantics — data is not
        // silently swallowed).
        // Coverage domain = write cache ∪ spill union — bytes are
        // either in the cache or in the sidecar (block-granularity
        // exclusive placement); on a cache miss the spill is
        // consulted. Reachable input = single-block delivery
        // (block-aligned, whole block as the unit), so coverage cannot
        // straddle the two domains; the cursor walk holds on each face
        // independently (`SpillStore::covers` and `CacheEntry::covers`
        // are isomorphic), so the OR is exact.
        let cache_covers = self
            .cache
            .entry(&piece_index)
            .is_some_and(|e| e.covers(goff, block.len()));
        let spill_covers = !cache_covers
            && self
                .spill
                .as_ref()
                .is_some_and(|s| s.covers(piece_index, goff, block.len()));
        if cache_covers || spill_covers {
            self.note_duplicate_drop(piece_index, goff, block.len());
            return Ok(BufferOutcome::DuplicateDropped);
        }
        // 1.4) v2 write-path precompute: the block hash is computed
        // once and reused by three faces — (1) block-level
        // verification (step 1.5) compares directly, no second hash;
        // (2) pool accumulation (step 2) pays directly, no second
        // hash; (3) piece verification inputs (table lookup at
        // completion, see push_block_pooled_at). cross-validation
        // libtorrent: write-path hashes are computed once into a
        // per-storage table (`precomputed_block_hashes.cpp` `store`,
        // entering the table when the v2 hash queue completes,
        // `pread_disk_io.cpp`), the hash2 job consults the table first
        // and reads back only uncomputed slots; intentional
        // divergence: no dedicated hasher thread here — the precompute
        // runs inline in the pipeline's existing spawn_blocking batch
        // buffer (spec: no new thread hops), the same hash is paid to
        // both faces from the local value, and the table only serves
        // as the completion-time input source. Status-quo baseline
        // (table off): the same 16KiB is hashed twice when the leaf
        // layer is present (once here in step 1.5 + once in the pool)
        // — with precompute it is always once (the v2 protocol's
        // necessary minimum). Duplicate blocks never get here
        // (dropped in step 1.25; duplicate bytes stay out of the hash
        // face); `None` = table off / v1 face, later steps take the
        // status quo path.
        let precomputed = self
            .precomputed
            .as_ref()
            .map(|_| crate::merkle::block_hash(block));
        // 1.5) v2 true block-level verification (SPEC §4.3 core v2
        // benefit): H(block) compared directly against the lazily
        // fetched leaf layer. Failure -> only that 16KiB is rejected
        // (BlockRejected; not digested/buffered, the rest of the
        // piece is unaffected); leaf layer not ready (lazy fetch
        // incomplete or degraded) -> falls back to whole-piece
        // buffering (the dispatch side logs the fallback explicitly,
        // not silently). v1 pieces (no piece_leaves entry) skip this
        // path.
        if let Some(check) = &self.block_check
            && let Some(&(root, leaf_base)) = check.piece_leaves.get(piece_index as usize)
        {
            let leaf =
                leaf_base + u64::from(offset_in_piece) / u64::from(crate::merkle::BLOCK_SIZE);
            let verdict = match precomputed {
                // Precomputed hash compared directly (the same hash's
                // second consumer; no second SHA-256; lookup/error
                // faces identical to verify_block).
                Some(h) => lock(&check.trees).verify_block_hash(&root, leaf, &h),
                None => lock(&check.trees).verify_block(&root, leaf, block),
            };
            match verdict {
                Ok(true) => {}
                Ok(false) => {
                    // A rejected block does not enter the precompute
                    // table (step 3.5 stores only after pool
                    // acceptance) — zero bad-byte residue; refetched
                    // blocks re-enter the table.
                    return Ok(BufferOutcome::BlockRejected { leaf_index: leaf });
                }
                // Whole-piece buffering fallback: the existing v2 path
                // when the lazy layer is unavailable (not fetched /
                // degraded / file tree not registered — nothing to
                // compare against). The dispatch side logs the
                // fallback explicitly.
                Err(TreeError::LeafLayerNotCached(_)) | Err(TreeError::UnknownRoot(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        // 2) Digest accumulation (a block delivered to an already
        // complete piece -> dedicated variant: the caller drops late
        // blocks benignly). The precomputed hash is paid directly (the
        // pool skips the duplicate SHA-256); None = computed in the
        // pool (the status quo, bit-identical).
        self.pool
            .push_block_with_precomputed(piece_index, offset_in_piece, block, precomputed)
            .map_err(|e: RangeError| match e {
                RangeError::PieceAlreadyComplete { index } => StoreError::PieceAlreadyComplete {
                    index: index as u64,
                },
                other => StoreError::Range(other),
            })?;
        // 3.5) Precompute store (cross-validation `pread_disk_io.cpp`
        // store_precomputed_v2: the write-path hash enters the table
        // as soon as it completes): pool acceptance = all
        // alignment/range gates passed (block index = in-piece offset
        // / 16KiB, bounded by the pool check first) — bad blocks
        // (rejected in 1.5) and late blocks (step 2 errors) leave no
        // residual slots.
        if let (Some(table), Some(h)) = (&mut self.precomputed, precomputed) {
            table.store(
                piece_index,
                offset_in_piece as usize / crate::merkle::BLOCK_SIZE as usize,
                h,
            );
        }

        // 3) Buffer: try contiguous append first (`append`, the
        // `WrDiskCache.cc` path); the unabsorbed part builds a new
        // cell with block-length capacity (`BtPieceMessage.cc`).
        // Eviction walks the min-loss victim order
        // ([`WrDiskCache::update_min_loss`], an intentional divergence
        // — largest-first systematically destroys near-complete
        // pieces under eviction-is-destroy semantics).
        if self.cache.entry(&piece_index).is_none() {
            self.cache.add(piece_index);
        }
        let appended = self
            .cache
            .entry_mut(&piece_index)
            .unwrap_or_else(|| unreachable!("entry added above"))
            .append(goff, block);
        let evictions = if appended < block.len() {
            // Cell allocation source, one of three: adoption (the wire
            // slice itself becomes the cell — zero placement copies,
            // only reachable when nothing was appended), pooled lease
            // (face-level arena present, returned by a Drop guard; the
            // rare remainder form — a partial append left a tail) or
            // direct heap allocation (fallback switch / unit-test
            // shape); the adoption and remainder forms copy zero and
            // `block.len() - appended` bytes respectively, the fallback
            // copies the same amount as the lease (cross-validation:
            // libtorrent disk_buffer_pool malloc/free reuse +
            // packet_pool size-bucketed free lists; file:symbol detail
            // in the cache.rs CellBuf docs).
            let cell = if appended == 0 {
                DataCell::with_shared(goff, block_bytes.clone())
            } else {
                match &self.block_arena {
                    Some(arena) => DataCell::with_data_in(
                        goff + appended as u64,
                        &block[appended..],
                        block.len(),
                        arena,
                    ),
                    None => DataCell::with_data(
                        goff + appended as u64,
                        block[appended..].to_vec(),
                        block.len(),
                    ),
                }
            };
            let cached = self
                .cache
                .entry_mut(&piece_index)
                .unwrap_or_else(|| unreachable!("entry added above"))
                .cache_data(cell);
            if !cached {
                // A same-goff cell already existing = the backstop
                // form of duplicate delivery (reached when the caller
                // bitmap and this layer's coverage check both missed;
                // cross-validation aria2 `Piece.cc`'s `assert(rv)`
                // backstop — divergence rationale in the step 1.25
                // note). Benign drop + count; never a fatal error.
                // Note: the HashPool bytes have accumulated here, so
                // the piece usually cannot complete any more — it
                // self-heals via cache eviction reset + refetch
                // (harmless, observable).
                self.note_duplicate_drop(
                    piece_index,
                    goff + appended as u64,
                    block.len() - appended,
                );
                return Ok(BufferOutcome::DuplicateDropped);
            }
            self.cache
                .update_min_loss(&piece_index, (block.len() - appended) as isize)
        } else {
            self.cache.update_min_loss(&piece_index, appended as isize)
        };

        // 4) Eviction re-decision: with spill present and within
        // budget, the victim spills to the sidecar — not destroyed,
        // not reset, no notification (pool/precompute/pipeline bitmap
        // untouched; read back and merged at assembly); outside
        // budget (single entry over cap / store failure / displaced
        // to make room) = the status-quo destroy semantics
        // (`destroy_unverified_piece`). The spill criterion is the
        // disk budget; fallback discipline: "over budget falls back
        // to destroy-and-refetch" — the destroy face is bit-identical
        // to the status quo.
        // Eviction = unverified-data discard (the module-doc
        // divergence point) as the base semantics, unchanged: a
        // destroyed piece's digests reset with it (the cells are no
        // longer in the cache; writing after later verification would
        // miss bytes).
        // Instrumentation: the destroy face keeps the sampled warning
        // + index registration (with spill on, this count is the
        // spec's "residual eviction count").
        let mut current_aborted = false;
        for ev in evictions {
            let mut spill_refused = false;
            if let Some(spill) = self.spill.as_mut() {
                let outcome = spill.store(ev.key, ev.cells);
                for (displaced, displaced_bytes) in outcome.displaced {
                    // Displaced (spill FIFO): destroy semantics same
                    // as a status-quo eviction —
                    // [`Self::destroy_unverified_piece`] includes the
                    // cache entry removal (the victim may be in the
                    // "partial spill + new block back in cache"
                    // coexistence; residual cache cells left behind
                    // would stall the piece forever). bytes =
                    // spilled bytes destroyed with the eviction
                    // (SpillStore is the accounting authority; the
                    // residual cache half is added inside destroy).
                    // The destroy total is charged to the
                    // budget-overflow fallback face (displacement
                    // arm).
                    let destroyed =
                        self.destroy_unverified_piece(displaced, displaced_bytes as u64);
                    self.spill_fallback_destroy_bytes =
                        self.spill_fallback_destroy_bytes.saturating_add(destroyed);
                    if displaced == piece_index {
                        current_aborted = true;
                    }
                }
                if outcome.stored {
                    // Absorbed: the piece keeps assembling; read-back
                    // happens on the completion path.
                    continue;
                }
                // Not absorbed (single entry over budget / store
                // failure): fall back to destroy-and-refetch.
                // Note: the displacement candidates were kept in
                // place inside spill (files not deleted, index
                // untouched) — zero unnecessary loss.
                spill_refused = true;
            }
            // ev.bytes = the actual byte count of the evicted cache
            // entry (the data destroyed with the eviction; cache.rs
            // Evicted is the accounting authority).
            let destroyed = self.destroy_unverified_piece(ev.key, ev.bytes as u64);
            if spill_refused {
                // Not-absorbed arm: the budget-overflow fallback
                // destroy uses the same counter (destroy total =
                // ev.bytes + the residual cache half — a status-quo
                // eviction hands the cells over in full, so the
                // residual is usually 0).
                self.spill_fallback_destroy_bytes =
                    self.spill_fallback_destroy_bytes.saturating_add(destroyed);
            }
            if ev.key == piece_index {
                current_aborted = true;
            }
        }
        if current_aborted {
            return Ok(BufferOutcome::PieceAbortedUnverified);
        }

        // 5 precondition) Completion check (completion is decoupled
        // from digests: `piece_complete` (byte counting) answers "are
        // bytes still missing", and verification moves to the
        // completion path, per format. A v1 digest accumulated in
        // arrival order (`HashPool::push_block` per-block `update`)
        // would necessarily misalign for out-of-order arrival (the
        // real-swarm norm: multiple peers / window slides / late
        // resends), and the original implementation misjudged correct
        // pieces as PieceFailed forever. Upstream cross-validation
        // `Piece.cc`: `updateHash` order gating (only
        // `begin == nextBegin_` feeds the digest) + completion
        // recompute via read-back (`updateHashWithRead`) — this repo
        // forbids unverified bytes on disk, so the equivalent is
        // reading back the cache cells (goff-ascending,
        // non-overlapping), assembling the piece, and taking one
        // SHA-1 (v1, see `finish_piece`). v2 per-block hashes are
        // positioned by in-piece order, naturally out-of-order safe,
        // and fold via [`HashPool::v2_verify_inputs`]-cloned inputs.
        if !self.pool.piece_complete(piece_index)? {
            // Saturation defense: the byte count can only exceed the
            // expectation for wire-impossible delivery shapes (a
            // same-goff variable-length redelivery, see the step 1.25
            // note) — return as soon as it cannot go negative.
            let pending = self
                .pool
                .piece_bytes(piece_index)?
                .saturating_sub(self.pool.piece_received(piece_index)?);
            return Ok(BufferOutcome::Buffered { pending });
        }
        Ok(BufferOutcome::Completed)
    }

    /// Step 5 (the inline completion path — the only form before the
    /// pooled split): assemble the completed piece -> verify -> (on
    /// pass) cross-check -> (on pass) write / (on failure) discard.
    /// The cells were already removed from the cache by the caller.
    /// Semantics preserved verbatim from before the split
    /// (verify-before-disk discipline).
    ///
    /// Test seam (unreachable in production, see the [`PushOutcome`]
    /// seam note). The main-format verification folding shares
    /// [`piece_matches`] with [`PieceJob::verify`] (one
    /// implementation; the drift surface of two near-copies is gone):
    /// v1 pieces recompute at assembly (authoritative); v2 pieces
    /// fold the same block-hash inputs as the pooled face via
    /// [`HashPool::v2_verify_inputs`] — same data, same dispatch
    /// rule, consistent verdicts under the completion invariant; the
    /// input-unavailable invariant-break form folds into verification
    /// failure and refetch, not fatal. Note: this seam bypasses the
    /// precompute table (pool values directly) — i.e. the "miss
    /// slots fall back to pool values" status-quo path, forming
    /// two-way cross-validation with the pooled face (table-first
    /// merge).
    #[cfg(test)]
    fn finish_piece(
        &mut self,
        piece_index: u64,
        piece_base: u64,
        entry: CacheEntry,
    ) -> Result<PushOutcome, StoreError> {
        let piece_ok = match self.pool.expected_v1_digest(piece_index)? {
            Some(want) => piece_matches(&PieceVerifyPlan::V1 { want }, &entry, piece_base),
            // v2 piece: block hashes positioned by in-piece order
            // (out-of-order safe), the same input cloning + the same
            // folding implementation ([`piece_matches`]) as the pooled
            // face. Under the completion invariant the inputs are
            // always available and folding can only yield true/false
            // (other variants are invariant breaks, handled as
            // verification failure into refetch, not fatal —
            // consistent with the pre-split pool-verification failure
            // folding).
            None => match self.pool.v2_verify_inputs(piece_index) {
                Ok(Some(V2VerifyInputs {
                    want,
                    block_hashes,
                    blocks_per_piece,
                    single_piece_file,
                })) => piece_matches(
                    &PieceVerifyPlan::V2 {
                        want,
                        block_hashes,
                        blocks_per_piece,
                        single_piece_file,
                    },
                    &entry,
                    piece_base,
                ),
                Ok(None) | Err(_) => false,
            },
        };
        if !piece_ok {
            self.pool.reset_piece(piece_index);
            return Ok(PushOutcome::PieceFailed);
        }
        // Hybrid cross-check (the BEP52 dual-format consistency duty):
        // a mismatch is a metadata contradiction -> torrent-level
        // failure (the cells are already taken out; nothing more is
        // written).
        if let Some(rule) = self.cross.get(piece_index as usize).copied().flatten() {
            cross_check(rule, &entry, piece_index, piece_base)?;
        }
        {
            // Shared write handle: the write hot-path domain (unix
            // concurrent read lock / fallback exclusive write lock),
            // synchronous face, no await held. coalesce decides
            // vectored-run vs per-cell (the same single write
            // implementation [`write_cells_merged`] as production
            // [`PieceJob::write_to`]).
            let coalesce = self.write_coalesce;
            let merge_max = self.write_merge_max;
            self.writer
                .write_batch(|w| write_cells_merged(entry.cells(), w, merge_max, coalesce))?;
        }
        Ok(PushOutcome::PieceVerified {
            bytes_written: entry.size() as u64,
        })
    }
}

/// Contiguous write run (the group-write construction unit): a
/// goff-contiguous concatenation view of cells — `bufs` borrows the
/// cell data (zero-copy, paid straight to the iovecs); `first_job` /
/// `last_job` = the job range the run covers (for the write-failure
/// verdict mapping).
struct CellRun<'a> {
    goff: u64,
    /// Run back edge (exclusive end = goff + bytes).
    end: u64,
    bytes: usize,
    bufs: Vec<&'a [u8]>,
    first_job: usize,
    last_job: usize,
}

/// Run construction (single implementation; shared by
/// [`write_cells_merged`]'s vectored face and
/// [`PieceJob::write_group`]'s cross-piece group write): the input is
/// an `(job index, cell)` sequence (the caller guarantees job order
/// goff-ascending and cell goffs ascending); a cell joins the current
/// run when adjacent (goff contiguous) and the byte cap allows.
/// `byte_cap = 0` = no byte cap (the structural run bound is the
/// input itself: a piece is 256KiB / a group is the pipeline batch
/// depth of <= 32 blocks).
fn build_cell_runs<'a>(
    cells: impl Iterator<Item = (usize, &'a DataCell)>,
    byte_cap: usize,
) -> Vec<CellRun<'a>> {
    let mut runs: Vec<CellRun> = Vec::new();
    for (ji, cell) in cells {
        match runs.last_mut() {
            Some(run)
                if run.end == cell.goff()
                    && (byte_cap == 0 || run.bytes + cell.len() <= byte_cap) =>
            {
                run.end = cell.goff() + cell.len() as u64;
                run.bytes += cell.len();
                run.bufs.push(cell.data());
                run.last_job = ji;
            }
            _ => runs.push(CellRun {
                goff: cell.goff(),
                end: cell.goff() + cell.len() as u64,
                bytes: cell.len(),
                bufs: vec![cell.data()],
                first_job: ji,
                last_job: ji,
            }),
        }
    }
    runs
}

/// Run execution (shared by group write / single-piece vectored): a
/// single-buffer run goes straight to `write_at` (no iovec assembly,
/// same shape as the existing single-cell write); a multi-buffer run
/// is one [`DiskWriter::write_vectored_at`]. Returns the write calls
/// issued.
fn write_cell_runs(runs: &[CellRun], writer: &dyn DiskWriter) -> Result<usize, StoreError> {
    let mut calls = 0usize;
    for run in runs {
        if run.bufs.len() == 1 {
            writer.write_at(run.goff, run.bufs[0])?;
        } else {
            writer.write_vectored_at(run.goff, &run.bufs)?;
        }
        calls += 1;
    }
    Ok(calls)
}

/// Cell write face (the write-merging face): `merge_max = 0` and
/// `vectored = false` -> per-cell writes (existing behavior, the
/// default tier unchanged); `merge_max > 0` and `vectored = false` ->
/// adjacent (`prev.goff + prev.len == next.goff`) cells merge into
/// single `write_at` calls, one merge capped at `merge_max` bytes (the
/// existing SSD/HDD tier semantics); `vectored = true`
/// (`BH_WRITE_COALESCE`) -> adjacent contiguous cell runs go out as
/// one **vectored** write (`write_vectored_at`, unix pwritev
/// zero-copy iovecs — the copy-and-stitch face retires; the byte cap
/// still follows `merge_max`).
///
/// Byte content, write coordinates, and order are exactly the
/// per-cell writes (only syscall granularity changes) —
/// verify-before-disk is unaffected. A merged run crossing file/pad
/// boundaries is handled by
/// [`crate::torrent_writer::TorrentWriter::write_at`]'s existing
/// split logic (the v1 stream goff includes pad zero spans: pad
/// ranges are skipped by it, BEP47 L87). The fallback face's merge
/// buffer is bounded by `merge_max` (bounded, no unbounded memory
/// face).
///
/// Returns the write calls issued (see the [`PieceJob::write_to`]
/// note).
fn write_cells_merged(
    cells: &[DataCell],
    writer: &dyn DiskWriter,
    merge_max: usize,
    vectored: bool,
) -> Result<usize, StoreError> {
    if !vectored {
        let mut calls = 0usize;
        if merge_max == 0 {
            for cell in cells {
                writer.write_at(cell.goff(), cell.data())?;
                calls += 1;
            }
            return Ok(calls);
        }
        let mut i = 0;
        while i < cells.len() {
            let mut run_end = cells[i].goff() + cells[i].len() as u64;
            let mut run_bytes = cells[i].len();
            let mut j = i + 1;
            while j < cells.len()
                && cells[j].goff() == run_end
                && run_bytes + cells[j].len() <= merge_max
            {
                run_end += cells[j].len() as u64;
                run_bytes += cells[j].len();
                j += 1;
            }
            if j == i + 1 {
                writer.write_at(cells[i].goff(), cells[i].data())?;
            } else {
                let mut buf = Vec::with_capacity(run_bytes);
                for cell in &cells[i..j] {
                    buf.extend_from_slice(cell.data());
                }
                writer.write_at(cells[i].goff(), &buf)?;
            }
            calls += 1;
            i = j;
        }
        return Ok(calls);
    }
    write_cell_runs(
        &build_cell_runs(cells.iter().map(|c| (0, c)), merge_max),
        writer,
    )
}

/// Piece byte assembly: cells (goff-ascending) stitched by in-piece
/// offset, holes zero-filled (the assembly face of v1 completion
/// verification; cross-validation aria2 `getDigestWithWrCache`
/// (`Piece.cc`) — feeds cached cells to the digest in order and reads
/// back to fill holes). The normal pipeline has no holes or overlaps
/// (byte counting and the cache are in sync, cells ascend without
/// overlapping); zero-fill and truncation are safety alignment only
/// under hostile construction, and misalignment is caught by the hash
/// comparison; on overlap the later cell overwrites the earlier bytes
/// (truncate then append).
///
/// Since stage 5 this is the **fallback path**: when the cell
/// sequence tiles the piece span seamlessly, `piece_matches` streams
/// SHA-1 per cell (no whole-piece allocation + copy); only
/// holes/misalignment (the hostile-construction backstop) reach this
/// function.
fn assemble_piece(entry: &CacheEntry, piece_base: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(entry.size());
    for cell in entry.cells() {
        let start = cell.goff().saturating_sub(piece_base) as usize;
        if buf.len() > start {
            buf.truncate(start);
        } else if buf.len() < start {
            buf.resize(start, 0);
        }
        buf.extend_from_slice(cell.data());
    }
    buf
}

/// Whether the cell sequence tiles seamlessly from `piece_base` (the
/// eligibility test for the streaming fast path): the first cell
/// starts exactly at the piece base and adjacent cell goffs are
/// contiguous. Structural invariant: cells are goff-ascending and
/// non-overlapping (locked by the cache.rs proptest), so "front edge
/// aligned + adjacent contiguous" means no holes and no overlaps
/// across the piece — the streamed input is byte-identical to the
/// `assemble_piece` buffer. Always true in the normal pipeline (cells
/// arrive per block, the base = the piece's first block goff);
/// leading holes (the piece's first block was evicted and
/// redelivered) / misalignment take the fallback assembly path.
fn cells_tile_from(cells: &[DataCell], piece_base: u64) -> bool {
    let mut cursor = piece_base;
    for cell in cells {
        if cell.goff() != cursor {
            return false;
        }
        cursor += cell.len() as u64;
    }
    true
}

/// Piece main-format verification folding (single implementation):
/// v1 = whole-piece SHA-1 recomputed at assembly (the authoritative
/// verification); v2 = block hashes folded in in-piece block order
/// into a piece root and compared. Shared by [`PieceJob::verify`]
/// (the production pooled face) and the test seam `finish_piece` (the
/// inline serial cross-validation face) — the drift surface of two
/// near-identical implementations is gone.
///
/// Verification rules dispatch on the owning file's piece count (the
/// current BEP52 text + the official creator's dispatch rule;
/// source: the hashpool `single_piece_file` field docs).
///
/// v1 hot path: when the cells tile the piece span seamlessly (always
/// true in the normal pipeline, see [`cells_tile_from`]), SHA-1 is
/// fed per cell — the hash input is byte-identical to the assembled
/// buffer, avoiding `assemble_piece`'s whole-piece Vec allocation +
/// full copy; holes/misalignment (the hostile-construction backstop)
/// fall back to the assembly path, byte semantics identical on both
/// faces.
///
/// SHA-1 backend: RustCrypto sha1 detects SHA-NI (x86_64) / ARMv8
/// crypto extensions (aarch64) at runtime — no compile-time features
/// or configuration involved.
fn piece_matches(plan: &PieceVerifyPlan, cells: &CacheEntry, piece_base: u64) -> bool {
    match plan {
        PieceVerifyPlan::V1 { want } => {
            if cells_tile_from(cells.cells(), piece_base) {
                let mut h = Sha1::new();
                for cell in cells.cells() {
                    h.update(cell.data());
                }
                h.finalize().as_slice() == want.as_slice()
            } else {
                Sha1::digest(assemble_piece(cells, piece_base)).as_slice() == want.as_slice()
            }
        }
        PieceVerifyPlan::V2 {
            want,
            block_hashes,
            blocks_per_piece,
            single_piece_file,
        } => {
            let root = if *single_piece_file {
                crate::merkle::root_from_block_hashes(block_hashes)
            } else {
                crate::merkle::piece_root_from_block_hashes(block_hashes, *blocks_per_piece)
            };
            root == *want
        }
    }
}

/// Cross-check execution: assemble the piece bytes from the cache
/// cells (goff-ascending) and compare the other format's hash per the
/// rule. `piece_base` = the piece's starting global offset (cell
/// goffs are global coordinates and must be converted to in-piece
/// offsets; on the v2 face the piece base is not idx*piece_len).
fn cross_check(
    rule: CrossRule,
    entry: &crate::cache::CacheEntry,
    piece: u64,
    piece_base: u64,
) -> Result<(), StoreError> {
    // With take = Some(limit), only the piece content prefix of limit
    // bytes is taken (the V2Root rule).
    let assemble = |take: Option<u64>| -> Vec<u8> {
        let mut out = Vec::with_capacity(entry.size());
        for cell in entry.cells() {
            let start = (cell.goff() - piece_base) as usize;
            let data = cell.data();
            if let Some(limit) = take {
                if start >= limit as usize {
                    break;
                }
                let end = ((start + data.len()) as u64).min(limit) as usize;
                out.extend_from_slice(&data[..end - start]);
            } else {
                out.extend_from_slice(data);
            }
        }
        out
    };
    match rule {
        CrossRule::V2Root {
            content_bytes,
            root,
            blocks_per_piece,
            single_piece_file,
        } => {
            let content = assemble(Some(content_bytes));
            if content.len() as u64 != content_bytes {
                return Err(StoreError::Internal(format!(
                    "cross-check: piece {piece} content bytes {} != expected {content_bytes}",
                    content.len()
                )));
            }
            let blocks: Vec<[u8; 32]> = content
                .chunks(crate::merkle::BLOCK_SIZE as usize)
                .map(crate::merkle::block_hash)
                .collect();
            let got = if single_piece_file {
                crate::merkle::root_from_block_hashes(&blocks)
            } else {
                crate::merkle::piece_root_from_block_hashes(&blocks, blocks_per_piece)
            };
            if got != root {
                return Err(StoreError::CrossCheckFailed { piece });
            }
            Ok(())
        }
        CrossRule::V1Hash { hash, pad_zeros } => {
            let mut content = assemble(None);
            content.resize(content.len() + pad_zeros as usize, 0);
            let got: [u8; 20] = Sha1::digest(&content).into();
            if got != hash {
                return Err(StoreError::CrossCheckFailed { piece });
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk::DiskWriter;
    use crate::hashpool::{ExpectedPieceHash, HashPool};
    use sha1::Sha1;
    use std::path::{Path, PathBuf};

    fn pattern(len: usize) -> Vec<u8> {
        const P: &[u8] = b"blackhole-merkle-reference-";
        P.iter().cycle().take(len).copied().collect()
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "taiji-verified-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const PIECE_LEN: u32 = 16384;

    /// v1 pool + an already-created single-file writer.
    fn setup_v1(content: &[u8], cache_limit: usize) -> (VerifiedWriter, PathBuf, TempDir) {
        let tmp = TempDir::new("v1");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, PIECE_LEN, content.len() as u64);
        (VerifiedWriter::new(w, pool, cache_limit), path, tmp)
    }

    /// v2 pool (piece root = each piece's root, bpp = 1).
    fn setup_v2(content: &[u8], cache_limit: usize) -> (VerifiedWriter, PathBuf, TempDir) {
        let tmp = TempDir::new("v2");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let roots: Vec<[u8; 32]> = content
            .chunks(PIECE_LEN as usize)
            .map(crate::merkle::block_hash)
            .collect();
        let pool = HashPool::new_v2(roots, PIECE_LEN, content.len() as u64);
        (VerifiedWriter::new(w, pool, cache_limit), path, tmp)
    }

    fn read_all(path: &std::path::Path, len: usize) -> Vec<u8> {
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.open_existing(path, true)
            .unwrap_or_else(|e| panic!("open: {e}"));
        let mut buf = vec![0u8; len];
        let n = w
            .read_at(0, &mut buf)
            .unwrap_or_else(|e| panic!("read: {e}"));
        buf.truncate(n);
        buf
    }

    /// Streaming fast-path eligibility + assembly-fallback
    /// equivalence: a tiled cell sequence takes the streamed SHA-1
    /// path, a sequence with a leading hole falls back to assembly —
    /// both paths agree on the same piece data (the byte-identity of
    /// the streamed input and the assembly buffer is locked here by
    /// cross-validation).
    #[test]
    fn piece_matches_streams_when_cells_tile() {
        let content = pattern(3 * PIECE_LEN as usize);
        let want: [u8; 20] = Sha1::digest(&content).into();
        let plan = PieceVerifyPlan::V1 { want };
        let piece_base = 1000u64; // arbitrary nonzero base (cell goffs are global coordinates).

        // Fast path: tiles seamlessly from piece_base (12 cells x 4KiB
        // covering the whole piece content).
        let mut tiled = CacheEntry::default();
        for (k, chunk) in content.chunks(4096).enumerate() {
            tiled.cache_data(DataCell::with_data(
                piece_base + (k * 4096) as u64,
                chunk.to_vec(),
                4096,
            ));
        }
        assert!(cells_tile_from(tiled.cells(), piece_base));
        assert!(
            piece_matches(&plan, &tiled, piece_base),
            "the tiled sequence must take the streaming path"
        );

        // Fallback path: a leading hole (first cell past piece_base) —
        // the verdict matches the assembly path (after hole zero-fill
        // the digest cannot match the real piece digest -> false).
        let mut holed = CacheEntry::default();
        for (k, chunk) in content.chunks(4096).enumerate() {
            holed.cache_data(DataCell::with_data(
                piece_base + 8192 + (k * 4096) as u64,
                chunk.to_vec(),
                4096,
            ));
        }
        assert!(!cells_tile_from(holed.cells(), piece_base));
        assert!(
            !piece_matches(&plan, &holed, piece_base),
            "the holed sequence takes the assembly fallback (zero-filled digest != real digest)"
        );
        // The same holed sequence with the expected digest computed per
        // assembly semantics (zero-filled) -> the fallback path passes.
        let mut buf = Vec::with_capacity(holed.size() + 8192);
        buf.resize(8192, 0);
        for cell in holed.cells() {
            buf.extend_from_slice(cell.data());
        }
        let plan_holed = PieceVerifyPlan::V1 {
            want: Sha1::digest(&buf).into(),
        };
        assert!(
            piece_matches(&plan_holed, &holed, piece_base),
            "the fallback path's zero-filled digest verdict holds"
        );
    }

    // -------------------------------------------------------------------
    // BEP52 folding vectors (migrated from the hashpool `verify` path —
    // that path was removed; the `piece_matches` V2 arm is the single
    // folding implementation and the vectors are locked here).
    // -------------------------------------------------------------------

    fn unhex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex: {e}"));
        }
        out
    }

    /// Creator vector: 40000B / 16KiB = 3 pieces, bpp = 1 (piece root
    /// = the single block's leaf hash; a single-block piece padded to
    /// a power of two is still 1 leaf) — all three pieces fold pass
    /// (the v2 fold consumes no cell bytes; an empty entry suffices).
    #[test]
    fn piece_matches_v2_creator_vector_single_block_pieces() {
        let content = pattern(40000);
        for chunk in content.chunks(16384) {
            let want = crate::merkle::block_hash(chunk);
            let plan = PieceVerifyPlan::V2 {
                want,
                block_hashes: vec![want],
                blocks_per_piece: 1,
                single_piece_file: true,
            };
            assert!(
                piece_matches(&plan, &CacheEntry::default(), 0),
                "bpp=1 piece root must equal the leaf hash"
            );
        }
    }

    /// Multi-block piece + last-piece zero-leaf padding vector:
    /// 100000B / 64KiB = 2 pieces, bpp = 4, expected roots are known
    /// vectors (the same reference as the merkle V6 test) — both the
    /// full 4-block piece and the 3-block short last piece (folding
    /// pads 1 zero leaf) pass under the blocks_per_piece rule.
    #[test]
    fn piece_matches_v2_multi_block_zero_padding_vector() {
        let content = pattern(100000);
        let leaves: Vec<[u8; 32]> = content
            .chunks(16384)
            .map(crate::merkle::block_hash)
            .collect();
        let want = [
            unhex32("a344810a6420bf2892406b1609f3fcf17144c39ac932efba23bf5977fbb434c6"),
            unhex32("867a052681829d0766054f05b913621bf83c2cf3323500156464121fa609788f"),
        ];
        for (piece, range) in [(0usize, 0..4), (1, 4..7)] {
            let plan = PieceVerifyPlan::V2 {
                want: want[piece],
                block_hashes: leaves[range].to_vec(),
                blocks_per_piece: 4,
                single_piece_file: false,
            };
            assert!(
                piece_matches(&plan, &CacheEntry::default(), 0),
                "piece {piece} zero-leaf padding fold must pass"
            );
        }
    }

    /// Rule-dispatch vector: a 1-piece file (2 blocks) roots via "pad
    /// to the next power of two of the block count", a multi-piece
    /// file roots via "pad to blocks_per_piece" — the two rules give
    /// different roots; mixing them must fail (a discrimination guard
    /// with positive and negative folds).
    #[test]
    fn piece_matches_v2_single_piece_file_rule_dispatch() {
        let content: Vec<u8> = (0..132_768).map(|i| (i % 253) as u8).collect();
        let f0_blocks: Vec<[u8; 32]> = content[0..32768]
            .chunks(16384)
            .map(crate::merkle::block_hash)
            .collect();
        let root_pow2 = crate::merkle::root_from_block_hashes(&f0_blocks);
        let root_bpp = crate::merkle::piece_root_from_block_hashes(&f0_blocks, 4);
        // Mixing the rules must give different roots (otherwise this
        // test has no discriminating power).
        assert_ne!(
            root_pow2, root_bpp,
            "the two rules must be distinguishable for a 1-piece file (bpp=4, 2 blocks)"
        );
        let plan = |want: [u8; 32], single_piece_file: bool| PieceVerifyPlan::V2 {
            want,
            block_hashes: f0_blocks.clone(),
            blocks_per_piece: 4,
            single_piece_file,
        };
        assert!(
            piece_matches(&plan(root_pow2, true), &CacheEntry::default(), 0),
            "a 1-piece file must pass via the block-count power-of-two rule"
        );
        assert!(
            !piece_matches(&plan(root_bpp, true), &CacheEntry::default(), 0),
            "rule mixing (multi-piece rule root + 1-piece-file dispatch) must not pass"
        );
        assert!(
            !piece_matches(&plan(root_pow2, false), &CacheEntry::default(), 0),
            "dispatch flip (1-piece file folded by the multi-piece rule) must not pass"
        );
    }

    /// v1 full pipeline: three pieces pushed in order -> all verified
    /// and written -> read back identical.
    #[test]
    fn v1_pipeline_writes_verified_file() {
        let content = pattern(40000);
        let (mut vw, path, _tmp) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        let mut outcomes = Vec::new();
        for (i, chunk) in content.chunks(PIECE_LEN as usize).enumerate() {
            for (off, block) in chunk.chunks(4096).enumerate() {
                let out = vw
                    .push_block(i as u64, (off * 4096) as u32, block)
                    .unwrap_or_else(|e| panic!("{e}"));
                outcomes.push((i, out));
            }
        }
        assert!(
            outcomes
                .iter()
                .any(|(i, o)| *i == 0 && matches!(o, PushOutcome::PieceVerified { .. })),
            "piece 0 verified: {outcomes:?}"
        );
        assert_eq!(
            read_all(&path, 40000),
            content,
            "disk content must match the verified content"
        );
    }

    /// v2 full pipeline: same, expected hashes are piece roots. (v2
    /// block hashes are positioned by in-piece block order; the push
    /// granularity is 16KiB-aligned blocks, matching the wire request
    /// granularity.)
    #[test]
    fn v2_pipeline_writes_verified_file() {
        let content = pattern(40000);
        let (mut vw, path, _tmp) = setup_v2(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        for (i, chunk) in content.chunks(PIECE_LEN as usize).enumerate() {
            for (off, block) in chunk.chunks(16384).enumerate() {
                vw.push_block(i as u64, (off * 16384) as u32, block)
                    .unwrap_or_else(|e| panic!("{e}"));
            }
        }
        assert_eq!(read_all(&path, 40000), content);
    }

    /// Verification failure -> PieceFailed, and **nothing touched
    /// disk** (the discipline). After reset and re-push of correct
    /// data the file is complete.
    #[test]
    fn corrupt_piece_fails_without_disk_write() {
        let content = pattern(40000);
        let (mut vw, path, _tmp) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        // piece 0: block 0 correct, block 1 corrupted -> fails
        // verification at completion.
        let out = vw
            .push_block(0, 0, &content[0..4096])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::Buffered { .. }));
        let mut bad = content[4096..8192].to_vec();
        bad[7] ^= 0xff;
        vw.push_block(0, 4096, &bad)
            .unwrap_or_else(|e| panic!("{e}"));
        // 4096*4 = 16384 complete -> verification fails.
        let _ = vw
            .push_block(0, 8192, &content[8192..12288])
            .unwrap_or_else(|e| panic!("{e}"));
        let out = vw
            .push_block(0, 12288, &content[12288..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            out,
            PushOutcome::PieceFailed,
            "a corrupted piece must fail verification"
        );
        // No disk writes at all (EOF short read = 0).
        assert_eq!(
            read_all(&path, 16).len(),
            0,
            "unverified data must not hit disk"
        );
        // Refetch path: correct data re-pushed -> passes.
        for (off, block) in content[0..16384].chunks(4096).enumerate() {
            vw.push_block(0, (off * 4096) as u32, block)
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(read_all(&path, 16384), content[0..16384]);
    }

    /// Pooled face with adoption: the caller hands over the wire decode
    /// slice — in production an arena-owner `Bytes` (the FrameCodec
    /// lease), here built the same way (lease -> fill -> freeze). The
    /// adopted cell holds that very lease (zero placement copies), so
    /// the arena conservation now runs over the *wire* leases: one
    /// outstanding block per buffered block, released when the job (or
    /// an evicted cell) drops. A plain heap `Bytes` is adopted the same
    /// way with no arena involvement (outstanding untouched). Disk
    /// content is byte-identical either way (locked by cross-validation).
    #[test]
    fn pooled_arena_cells_roundtrip_and_return_on_all_paths() {
        let arena = taiji_io::block_arena::BlockArena::new(64 * 1024);
        let content = pattern(40000);
        let (vw, path, _tmp) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        let mut vw = vw.with_block_arena(Some(arena.clone()));
        // Wire-shaped block: one arena lease, filled and frozen (the
        // FrameCodec's exact production shape).
        let wire = |arena: &Arc<taiji_io::block_arena::BlockArena>,
                    from: usize,
                    to: usize|
         -> bytes::Bytes {
            let mut lease = arena.lease(to - from);
            lease.push_bytes(&content[from..to]);
            lease.freeze(to - from)
        };
        // piece 0 buffered block by block (pooled path): one adopted
        // wire lease per block — the conservation the old per-cell
        // lease test pinned, now over the caller's leases.
        for off in 0..3u32 {
            let begin = off * 4096;
            let b = wire(&arena, begin as usize, begin as usize + 4096);
            vw.push_block_pooled_at(0, u64::from(begin), begin, &b)
                .unwrap_or_else(|e| panic!("{e}"));
            drop(b); // caller's handle gone; the cell is the sole owner
            assert_eq!(
                arena.readout().outstanding_blocks,
                u64::from(off) + 1,
                "wire lease under lease conservation (cell adoption)"
            );
        }
        // Complete -> PieceJob (lease ownership transfers with the job).
        let b = wire(&arena, 12288, 16384);
        let out = vw
            .push_block_pooled_at(0, 12288, 12288, &b)
            .unwrap_or_else(|e| panic!("{e}"));
        drop(b);
        let PooledOutcome::PieceCompleted(job) = out else {
            panic!("expected PieceCompleted, got {out:?}")
        };
        assert_eq!(
            arena.readout().outstanding_blocks,
            4,
            "the job holds the cells"
        );
        assert!(
            job.verify().unwrap_or_else(|e| panic!("{e:?}")),
            "adopted cells keep the same verification semantics"
        );
        let wh = vw.writer_handle();
        wh.write_batch(|g| job.write_to(g))
            .unwrap_or_else(|e| panic!("{e}"));
        drop(job);
        assert_eq!(
            arena.readout().outstanding_blocks,
            0,
            "releasing the job returns the leases"
        );
        // Reuse: the next wire lease hits the free list (no new
        // allocation, no fallback).
        let b = wire(&arena, 16384, 20480);
        vw.push_block_pooled_at(1, 0, 0, &b)
            .unwrap_or_else(|e| panic!("{e}"));
        drop(b);
        let r = arena.readout();
        assert_eq!(r.lease_hits_total, 1);
        assert_eq!(r.alloc_fallback_total, 0);
        assert_eq!(
            r.alloc_fresh_total, 4,
            "first round: 4 wire-lease blocks freshly allocated then pooled"
        );
        // Heap-Bytes adoption: no arena lease anywhere (outstanding
        // unchanged), same disk bytes.
        let before = arena.readout().outstanding_blocks;
        vw.push_block(1, 4096, &content[20480..24576])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            arena.readout().outstanding_blocks,
            before,
            "heap Bytes adoption involves no pool"
        );
        // Eviction path: filling to the limit triggers eviction -> the
        // evicted cell's adopted lease returns on Drop.
        let (vw2, _p2, _t2) = setup_v1(&content, PIECE_LEN as usize);
        let arena2 = taiji_io::block_arena::BlockArena::new(64 * 1024);
        let mut vw2 = vw2.with_block_arena(Some(arena2.clone()));
        let b0 = wire(&arena2, 0, 4096);
        vw2.push_block_at(0, 0, 0, &b0)
            .unwrap_or_else(|e| panic!("{e}"));
        drop(b0);
        assert_eq!(arena2.readout().outstanding_blocks, 1);
        let b1 = wire(&arena2, 16384, 32768);
        vw2.push_block_at(1, 16384, 0, &b1)
            .unwrap_or_else(|e| panic!("{e}"));
        drop(b1);
        assert_eq!(vw2.evicted_unverified, 1, "piece 0 was evicted");
        assert_eq!(
            arena2.readout().outstanding_blocks,
            0,
            "both the evicted cell (piece 0) and the completed-piece cell (piece 1) return via the Drop guard"
        );
        assert_eq!(
            read_all(&path, 16384),
            content[0..16384],
            "disk content is byte-identical to the heap-shaped form"
        );
    }

    /// Cache overflow evicting an unverified piece =
    /// destroy-and-refetch (a divergence point from aria2). Victim
    /// order = minimum-progress first + current-piece protection
    /// ([`crate::cache::WrDiskCache::update_min_loss`], an intentional
    /// divergence — largest-first's flush-efficiency goal does not
    /// exist under eviction-is-destroy semantics, and it
    /// systematically destroys near-complete pieces): with the limit
    /// at exactly one piece, piece 1 (the current piece, whole) pushes
    /// out piece 0 (1/4 progress, the minimum) and completes normally;
    /// piece 0's data was destroyed with the eviction and is refetched
    /// whole.
    #[test]
    fn cache_limit_evicts_unverified_piece_for_retry() {
        let content = pattern(40000);
        let (mut vw, path, _tmp) = setup_v1(&content, PIECE_LEN as usize);
        // piece 0: push 1/4 only (cache holds 4096 < limit).
        let out = vw
            .push_block(0, 0, &content[0..4096])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(out, PushOutcome::Buffered { pending: 12288 }),
            "got {out:?}"
        );
        // piece 1 whole piece enters the cache: total 20480 > limit ->
        // victim = minimum-progress piece 0 (the current piece is
        // protected, no self-eviction). piece 1 verifies and lands;
        // piece 0's 4096 bytes are destroyed and must be refetched
        // whole.
        let out = vw
            .push_block(1, 0, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            out,
            PushOutcome::PieceVerified {
                bytes_written: 16384
            },
            "got {out:?}"
        );
        assert_eq!(
            vw.evicted_unverified, 1,
            "eviction must be observable via the counter"
        );
        assert_eq!(
            vw.take_evicted(),
            vec![0u64],
            "evicted piece indexes must be registered for upstream bookkeeping sync"
        );
        // piece 0 refetched whole (the original 4096 bytes were lost
        // with the eviction): verifies and lands.
        for (off, block) in content[0..16384].chunks(4096).enumerate() {
            let out = vw
                .push_block(0, (off * 4096) as u32, block)
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(
                matches!(
                    out,
                    PushOutcome::Buffered { .. } | PushOutcome::PieceVerified { .. }
                ),
                "got {out:?}"
            );
        }
        // piece 2 finish.
        for (off, block) in content[32768..40000].chunks(4096).enumerate() {
            vw.push_block(2, (off * 4096) as u32, block)
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(
            read_all(&path, 40000),
            content,
            "all pieces eventually land with correct content"
        );
    }

    /// Eviction byte face (instrumentation): each eviction adds the
    /// actual byte count of the destroyed cache entry
    /// ([`crate::cache::Evicted::bytes`] is the accounting authority),
    /// observable at the same point as the count face
    /// ([`VerifiedWriter::evicted_unverified`]); no eviction = an
    /// honest zero.
    #[test]
    fn evicted_bytes_counter_counts_destroyed_data() {
        let content = pattern(40000);
        let (mut vw, _path, _tmp) = setup_v1(&content, PIECE_LEN as usize);
        // piece 0: push 1/4 only (cache holds 4096 < limit).
        let out = vw
            .push_block(0, 0, &content[0..4096])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::Buffered { .. }));
        assert_eq!(
            vw.evicted_unverified_bytes(),
            0,
            "no eviction = an honest zero"
        );
        // piece 1 whole piece enters the cache: total 20480 > limit ->
        // victim = minimum-progress piece 0 (4096 bytes destroyed with
        // the eviction).
        vw.push_block(1, 0, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vw.evicted_unverified(), 1);
        assert_eq!(
            vw.evicted_unverified_bytes(),
            4096,
            "evicted bytes = the actual data size of the evicted cache entry"
        );
    }

    /// Block-length validation: empty / >16KiB explicitly rejected.
    #[test]
    fn block_length_validation() {
        let content = pattern(16384);
        let (mut vw, _path, _tmp) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        assert!(vw.push_block(0, 0, &[]).is_err());
        assert!(vw.push_block(0, 0, &[0u8; 16385]).is_err());
        // Expected-hash kind check: both ExpectedPieceHash variants
        // construct (compile time).
        let _ = ExpectedPieceHash::V1([0u8; 20]);
        let _ = ExpectedPieceHash::V2([0u8; 32]);
    }

    /// Hybrid cross-check: after a v1 stream piece completes, a v2
    /// root check runs over the content prefix. Layout =
    /// a(70000) + pad(11920) + b(30000), 16KiB pieces (bpp = 1).
    fn hybrid_fixture() -> (Vec<u8>, Vec<[u8; 20]>, Vec<Option<CrossRule>>) {
        use crate::merkle;
        let content_a = pattern(70000);
        let content_b: Vec<u8> = (0..30000).map(|i| (i * 7 % 256) as u8).collect();
        let mut stream = Vec::with_capacity(111_920);
        stream.extend_from_slice(&content_a);
        stream.extend_from_slice(&[0u8; 11920]);
        stream.extend_from_slice(&content_b);
        let v1: Vec<[u8; 20]> = stream
            .chunks(16384)
            .map(|c| Sha1::digest(c).into())
            .collect();
        let a_roots: Vec<[u8; 32]> = content_a.chunks(16384).map(merkle::block_hash).collect();
        let b_roots: Vec<[u8; 32]> = content_b.chunks(16384).map(merkle::block_hash).collect();
        // Per stream piece: (content bytes, owning file's piece root):
        // k0-4 -> a's pieces 0-4, k5-6 -> b's pieces 0-1.
        let mut cross: Vec<Option<CrossRule>> = Vec::new();
        for k in 0..7usize {
            let start = k as u64 * 16384;
            let (content_bytes, root, single) = if start < 70000 {
                (
                    (70000 - start).min(16384),
                    a_roots[(start / 16384) as usize],
                    false,
                )
            } else {
                let p = (start - 81920) / 16384;
                ((111_920 - start).min(16384), b_roots[p as usize], false)
            };
            cross.push(Some(CrossRule::V2Root {
                content_bytes,
                root,
                blocks_per_piece: 1,
                single_piece_file: single,
            }));
        }
        (stream, v1, cross)
    }

    /// Positive case: pieces consistent in both formats all pass and
    /// land (including pad zero spans).
    #[test]
    fn hybrid_cross_check_v2_root_passes() {
        let (stream, v1, cross) = hybrid_fixture();
        let tmp = TempDir::new("hybrid-ok");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("hybrid.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let pool = HashPool::new_v1(&v1.concat(), 16384, stream.len() as u64);
        let mut vw = VerifiedWriter::with_cross(w, pool, crate::cache::DEFAULT_CACHE_LIMIT, cross);
        for (k, chunk) in stream.chunks(16384).enumerate() {
            vw.push_block(k as u64, 0, chunk)
                .unwrap_or_else(|e| panic!("piece {k}: {e}"));
        }
        assert_eq!(
            read_all(&path, stream.len()),
            stream,
            "all pieces land identical"
        );
    }

    /// Negative case: the v1 check passes but the v2 root mismatches
    /// -> CrossCheckFailed and nothing lands (BEP52 "inconsistency
    /// detected").
    #[test]
    fn hybrid_cross_check_mismatch_fails_without_disk_write() {
        let (stream, v1, cross) = hybrid_fixture();
        let tmp = TempDir::new("hybrid-bad");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("hybrid.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        // Push only piece 5 (b's piece 0): the v1 expectation is
        // correct, the v2 root replaced with a wrong value.
        let mut wrong = cross.clone();
        wrong[5] = Some(CrossRule::V2Root {
            content_bytes: 16384,
            root: [0x5a; 32],
            blocks_per_piece: 1,
            single_piece_file: false,
        });
        let piece5 = stream[5 * 16384..6 * 16384].to_vec();
        let pool = HashPool::new_v1(&v1.concat(), 16384, stream.len() as u64);
        let mut vw = VerifiedWriter::with_cross(w, pool, crate::cache::DEFAULT_CACHE_LIMIT, wrong);
        let err = match vw.push_block(5, 0, &piece5) {
            Err(e) => e,
            Ok(out) => panic!("cross-rule mismatch must error, got {out:?}"),
        };
        assert!(
            matches!(err, StoreError::CrossCheckFailed { piece: 5 }),
            "got {err:?}"
        );
        assert_eq!(
            read_all(&path, 16).len(),
            0,
            "the mismatched piece must not land"
        );
    }

    /// The v2-face direction: after a content piece completes, pad
    /// zeros are appended and the v1 SHA-1 is checked
    /// (CrossRule::V1Hash).
    #[test]
    fn hybrid_cross_check_v1_hash_on_content_face() {
        use crate::merkle;
        let content_b: Vec<u8> = (0..30000).map(|i| (i * 7 % 256) as u8).collect();
        // b's v1 stream piece (k6 = b's piece 1: 13616B content +
        // 2768B pad zeros -> 16384B).
        let mut stream_piece = content_b[16384..].to_vec();
        stream_piece.resize(16384, 0);
        let want_v1: [u8; 20] = Sha1::digest(&stream_piece).into();
        let root: [u8; 32] = merkle::block_hash(&content_b[16384..]);

        let tmp = TempDir::new("hybrid-v2face");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("b.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        // v2 pool: single-piece plan (b's piece 1 = this face's flat
        // 1/2 coordinates; only this piece is pushed).
        let pool = HashPool::new_plan(vec![ExpectedPieceHash::V2(root)], 16384, &[13616])
            .unwrap_or_else(|e| panic!("{e}"));
        let mut vw = VerifiedWriter::with_cross(
            w,
            pool,
            crate::cache::DEFAULT_CACHE_LIMIT,
            vec![Some(CrossRule::V1Hash {
                hash: want_v1,
                pad_zeros: 16384 - 13616,
            })],
        );
        // Push only the 13616B tail block (16KiB-aligned push
        // granularity, the v2 positioned semantics).
        vw.push_block_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&content_b[16384..]))
            .unwrap_or_else(|e| panic!("{e}"));
        // The disk holds only content bytes (pads never land — this
        // test's single-file writer writes only the content span).
        assert_eq!(read_all(&path, 13616), content_b[16384..]);
    }

    // ---------------------------------------------------------------------
    // v2 true block-level verification path (BlockCheck + direct
    // HashTreeCache sibling-hash comparison).
    // ---------------------------------------------------------------------

    /// v2 fixture: single file, 2 pieces x 32KiB (2 blocks per piece),
    /// HashTreeCache with the whole file's leaf layer lazily fetched.
    /// Returns (writer, root, content, temp dir).
    fn setup_v2_block_check(content: &[u8]) -> (VerifiedWriter, [u8; 32], TempDir) {
        const PIECE: u32 = 32768;
        let tmp = TempDir::new("v2-blocks");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let leaves: Vec<[u8; 32]> = content
            .chunks(16384)
            .map(crate::merkle::block_hash)
            .collect();
        let pieces: Vec<[u8; 32]> = leaves
            .chunks(2)
            .map(|p| crate::merkle::node_hash(&p[0], &p[1]))
            .collect();
        let root = crate::merkle::file_root_from_piece_roots(&pieces, 2);
        let pool = HashPool::new_v2(pieces.clone(), PIECE, content.len() as u64);
        let mut trees = HashTreeCache::new(PIECE);
        trees.add_file(root, pieces);
        trees
            .verify_and_put_layer(&root, 0, 0, leaves)
            .unwrap_or_else(|e| panic!("lazy layer: {e}"));
        let vw = VerifiedWriter::new(w, pool, crate::cache::DEFAULT_CACHE_LIMIT).with_block_check(
            BlockCheck {
                piece_leaves: Arc::new(vec![(root, 0), (root, 2)]),
                trees: Arc::new(std::sync::Mutex::new(trees)),
            },
        );
        (vw, root, tmp)
    }

    /// A 1-bit flip -> only that 16KiB is rejected (BlockRejected),
    /// neighbors in the piece unaffected; after the block is refetched
    /// the piece verifies and lands; the rejected block's bytes never
    /// touched disk.
    #[test]
    fn block_check_rejects_single_corrupted_block() {
        let content = pattern(2 * 32768);
        let (mut vw, _root, tmp) = setup_v2_block_check(&content);
        let path = tmp.0.join("blob.bin");
        // piece 0: both blocks good -> PieceVerified.
        let out = vw
            .push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::Buffered { pending: 16384 }));
        let out = vw
            .push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::PieceVerified { .. }));

        // piece 1: block 0 (leaf 2) flipped 1 bit -> BlockRejected,
        // isolating only that block.
        let mut bad = content[32768..49152].to_vec();
        bad[7] ^= 0x01;
        let out = vw.push_block(1, 0, &bad).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            out,
            PushOutcome::BlockRejected { leaf_index: 2 },
            "the corrupted block must isolate only itself"
        );
        // Neighbor block (leaf 3) buffers normally.
        let out = vw
            .push_block(1, 16384, &content[49152..65536])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(out, PushOutcome::Buffered { pending: 16384 }),
            "the neighbor block is unaffected, got {out:?}"
        );
        // Rejected block never touched disk: the disk holds only
        // piece 0.
        assert_eq!(read_all(&path, 65536).len(), 2 * 32768 - 2 * 16384);

        // Refetch block 0 (correct data) -> piece 1 verifies and lands.
        let out = vw
            .push_block(1, 0, &content[32768..49152])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::PieceVerified { .. }));
        assert_eq!(
            read_all(&path, 65536),
            content,
            "the file is complete after refetch"
        );
    }

    /// Leaf layer not ready (lazy fetch degraded) -> whole-piece
    /// buffering fallback: corrupted data goes through the HashPool
    /// whole-piece verification -> PieceFailed (existing v2 semantics,
    /// not silent — the caller logs the fallback).
    #[test]
    fn block_check_falls_back_to_piece_path_when_layer_missing() {
        const PIECE: u32 = 32768;
        let content = pattern(2 * 32768);
        let tmp = TempDir::new("v2-fallback");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let leaves: Vec<[u8; 32]> = content
            .chunks(16384)
            .map(crate::merkle::block_hash)
            .collect();
        let pieces: Vec<[u8; 32]> = leaves
            .chunks(2)
            .map(|p| crate::merkle::node_hash(&p[0], &p[1]))
            .collect();
        let root = crate::merkle::file_root_from_piece_roots(&pieces, 2);
        // Leaf layer not lazily fetched (no leaf layer in the cache)
        // -> verify_block returns LeafLayerNotCached.
        let mut trees = HashTreeCache::new(PIECE);
        trees.add_file(root, pieces.clone());
        let pool = HashPool::new_v2(pieces, PIECE, content.len() as u64);
        let mut vw = VerifiedWriter::new(w, pool, crate::cache::DEFAULT_CACHE_LIMIT)
            .with_block_check(BlockCheck {
                piece_leaves: Arc::new(vec![(root, 0), (root, 2)]),
                trees: Arc::new(std::sync::Mutex::new(trees)),
            });
        // piece 1 block 0 corrupted + block 1 correct -> no
        // block-level rejection; the whole-piece verification fails at
        // completion.
        let mut bad = content[32768..49152].to_vec();
        bad[7] ^= 0x01;
        vw.push_block(1, 0, &bad).unwrap_or_else(|e| panic!("{e}"));
        let out = vw
            .push_block(1, 16384, &content[49152..65536])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            out,
            PushOutcome::PieceFailed,
            "the fallback path must still intercept the corrupted piece"
        );
        assert_eq!(
            read_all(&path, 16).len(),
            0,
            "unverified data must not hit disk"
        );
    }

    // ---------------------------------------------------------------------
    // Three duplicate-delivery shapes — exact duplicate / partial-
    // overlap append / late piece (redelivery after abort) — are all
    // handled benignly, cache invariants hold, and drops are
    // observable. Wire granularity = 16KiB-aligned fixed-length blocks
    // (short tail blocks); tests split at 4096 only to manufacture
    // multi-block pieces; the cache cell invariant is the same as the
    // cache.rs proptest (goff-ascending, non-overlapping).
    // ---------------------------------------------------------------------

    /// Cell structural invariant (goff-ascending, non-overlapping; a
    /// piece with no cache entry = already settled/evicted, trivially
    /// satisfied).
    fn assert_cells_invariant(vw: &VerifiedWriter, piece: u64) {
        if let Some(e) = vw.cache.entry(&piece) {
            let cells = e.cells();
            assert!(
                cells
                    .windows(2)
                    .all(|w| w[0].goff() + w[0].len() as u64 <= w[1].goff()),
                "piece {piece} cells must be ascending and non-overlapping: {cells:?}"
            );
        }
    }

    /// Shape one (exact duplicate block): the same (piece, begin, len)
    /// received twice — the coverage check (step 1.25) hits ->
    /// DuplicateDropped + count; duplicate bytes are stopped before
    /// any digest/byte accounting (the completion check stays clean),
    /// and the piece still completes, verifies, and lands.
    #[test]
    fn exact_duplicate_block_dropped_benignly() {
        let content = pattern(2 * PIECE_LEN as usize);
        let (mut vw, path, _tmp) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        const BLK: usize = 4096;
        // piece 0: first 3 blocks buffered (a 16KiB piece = 4 blocks).
        for off in 0..3 {
            let out = vw
                .push_block(0, (off * BLK) as u32, &content[off * BLK..(off + 1) * BLK])
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(matches!(out, PushOutcome::Buffered { .. }), "got {out:?}");
        }
        // Exact duplicate (piece in flight): block 1 received again ->
        // benign drop + count.
        let out = vw
            .push_block(0, BLK as u32, &content[BLK..2 * BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out, PushOutcome::DuplicateDropped);
        assert_eq!(vw.duplicate_drops(), 1);
        assert_cells_invariant(&vw, 0);
        // Another duplicate (block 2) when only the last block is
        // missing -> dropped too, without polluting the byte count —
        // after the last block arrives the piece must complete exactly
        // and pass verification.
        let out = vw
            .push_block(0, (2 * BLK) as u32, &content[2 * BLK..3 * BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out, PushOutcome::DuplicateDropped);
        assert_eq!(vw.duplicate_drops(), 2);
        let out = vw
            .push_block(0, (3 * BLK) as u32, &content[3 * BLK..4 * BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(
                out,
                PushOutcome::PieceVerified {
                    bytes_written: 16384
                }
            ),
            "got {out:?}"
        );
        assert_eq!(read_all(&path, PIECE_LEN as usize), content[..16384]);
    }

    /// Shape two (partial-overlap append): a merged delivery whose
    /// span is **fully** covered by existing cells -> benign drop
    /// (within the "data already present at the same goff" red line);
    /// a variable-length partial overlap **carrying new bytes** (same
    /// goff, variable length — impossible under the wire's fixed
    /// granularity, but the store contract face must still not
    /// fatalize) is not pre-dropped by the coverage check: it falls
    /// into the existing append/residual-cell face, is refused by
    /// cache_data's same-goff rejection (`WrDiskCacheEntry.cc`), and
    /// ends in the backstop drop + count; its un-cached residual bytes
    /// mean the completion hash gate intercepts (nothing lands, no bad
    /// data produced) and refetch converges (no silent data-error
    /// swallowing).
    #[test]
    fn partial_overlap_append_benign_and_hash_gated() {
        let content = pattern(PIECE_LEN as usize);
        let (mut vw, path, _tmp) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        const BLK: usize = 4096;
        // Buffer only block 0.
        let out = vw
            .push_block(0, 0, &content[0..BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::Buffered { pending: 12288 }));
        // Variable-length partial-overlap delivery [0,8192) (new bytes
        // [4096,8192)): the coverage check misses -> steps 2/3 run as
        // usual -> cache_data refuses the same goff -> backstop drop.
        // The cache must not grow (new bytes not cached, size still
        // 4096).
        let out = vw
            .push_block(0, 0, &content[0..2 * BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            out,
            PushOutcome::DuplicateDropped,
            "backstop drop, must not fatalize"
        );
        assert_eq!(vw.duplicate_drops(), 1);
        assert_eq!(
            vw.cache.entry(&0).map(crate::cache::CacheEntry::size),
            Some(BLK)
        );
        assert_cells_invariant(&vw, 0);
        // Fill delivery -> byte count completes -> assembly has a hole
        // (new bytes never cached) -> the hash gate intercepts with
        // PieceFailed, nothing lands (data errors must not be silently
        // produced).
        let out = vw
            .push_block(0, BLK as u32, &content[BLK..2 * BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            out,
            PushOutcome::PieceFailed,
            "the hash gate must intercept hole-containing assembly"
        );
        assert_eq!(
            read_all(&path, 16).len(),
            0,
            "unverified data must not hit disk"
        );
        // Refetch convergence: after reset, correct data re-pushed;
        // once blocks 0/1 are settled, one merged delivery [0,8192)
        // (full coverage) -> benign drop (only now is it a "same goff
        // already has data" duplicate), and it must not pollute the
        // byte count — the piece still completes exactly and passes.
        for off in 0..2 {
            let out = vw
                .push_block(0, (off * BLK) as u32, &content[off * BLK..(off + 1) * BLK])
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(matches!(out, PushOutcome::Buffered { .. }), "got {out:?}");
        }
        let out = vw
            .push_block(0, 0, &content[0..2 * BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out, PushOutcome::DuplicateDropped);
        assert_eq!(vw.duplicate_drops(), 2);
        assert_cells_invariant(&vw, 0);
        for off in 2..4 {
            let out = vw
                .push_block(0, (off * BLK) as u32, &content[off * BLK..(off + 1) * BLK])
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(
                matches!(
                    out,
                    PushOutcome::Buffered { .. } | PushOutcome::PieceVerified { .. }
                ),
                "got {out:?}"
            );
        }
        assert_eq!(read_all(&path, PIECE_LEN as usize), content);
    }

    /// Shape three (late piece: redelivery after eviction): after a
    /// cache overflow evicts an unverified piece (data + digests fully
    /// reset; under the min-loss victim order the victim is the
    /// minimum-progress piece) — a same-coordinate second delivery to
    /// a completed piece errors explicitly (the pipeline drops it
    /// benignly); a true duplicate for an incomplete piece drops
    /// benignly + count; late/redelivered blocks of an evicted piece
    /// must be **re-accepted** (the data was lost with the eviction;
    /// dropping them would deadlock the refetch); every piece
    /// eventually converges, verifies, lands, and the content matches.
    #[test]
    fn late_redelivery_after_abort_accepted_and_duplicates_dropped() {
        let content = pattern(3 * PIECE_LEN as usize);
        let (mut vw, path, _tmp) = setup_v1(&content, PIECE_LEN as usize);
        const BLK: usize = 4096;
        const P2: usize = 2 * PIECE_LEN as usize;
        // piece 0 block 0 into the cache (4096 <= limit).
        let out = vw
            .push_block(0, 0, &content[0..BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::Buffered { pending: 12288 }));
        // piece 1 whole piece into the cache -> over limit -> victim =
        // minimum-progress piece 0 (the min-loss order + current-piece
        // protection): piece 0's data + digests fully reset, piece 1
        // verifies and lands as usual.
        let out = vw
            .push_block(1, 0, &content[PIECE_LEN as usize..2 * PIECE_LEN as usize])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            out,
            PushOutcome::PieceVerified {
                bytes_written: 16384
            },
            "got {out:?}"
        );
        assert_eq!(vw.evicted_unverified(), 1);
        assert_eq!(vw.take_evicted(), vec![0u64]);
        // A true duplicate in between: piece 1 same-coordinate second
        // delivery (pool already complete) -> explicit error (the
        // pipeline drops the late block of a completed piece benignly,
        // not fatal).
        let out = vw.push_block(1, 0, &content[PIECE_LEN as usize..2 * PIECE_LEN as usize]);
        assert!(
            matches!(out, Err(StoreError::PieceAlreadyComplete { .. })),
            "got {out:?}"
        );
        // Exact duplicate for an incomplete piece: piece 2 block 0
        // received again -> benign drop + count (caching piece 2 would
        // over-limit, but the cache holds only piece 2 < limit, no
        // eviction).
        let out = vw
            .push_block(2, 0, &content[P2..P2 + BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PushOutcome::Buffered { pending: 12288 }));
        let out = vw
            .push_block(2, 0, &content[P2..P2 + BLK])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out, PushOutcome::DuplicateDropped);
        assert_eq!(vw.duplicate_drops(), 1);
        assert_cells_invariant(&vw, 2);
        // Evicted piece 0's redelivery: the data was destroyed with
        // the eviction -> **must be re-accepted** (dropping would
        // deadlock the refetch) — the whole piece arrives again, not a
        // duplicate, no count. Note: piece 0's last block pushes the
        // total over the limit again; the victim is then the
        // minimum-progress piece 2 (its blk0 is destroyed) — under the
        // min-loss order, near-complete pieces are always protected.
        for off in 0..4 {
            let out = vw
                .push_block(0, (off * BLK) as u32, &content[off * BLK..(off + 1) * BLK])
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(matches!(
                out,
                PushOutcome::Buffered { .. } | PushOutcome::PieceVerified { .. }
            ));
        }
        assert_eq!(read_all(&path, PIECE_LEN as usize), content[..16384]);
        // piece 2 redelivery (blk0 was destroyed with the eviction in
        // the previous step -> whole piece arrives again): completes,
        // verifies, lands, content matches the source.
        for off in 0..4 {
            let out = vw
                .push_block(
                    2,
                    (off * BLK) as u32,
                    &content[P2 + off * BLK..P2 + (off + 1) * BLK],
                )
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(matches!(
                out,
                PushOutcome::Buffered { .. } | PushOutcome::PieceVerified { .. }
            ));
        }
        assert_eq!(
            vw.duplicate_drops(),
            1,
            "redelivery is not a duplicate, the counter must not grow"
        );
        assert_eq!(read_all(&path, 3 * PIECE_LEN as usize), content);
    }

    // ---------------------------------------------------------------------
    // Pooled completion path (push_block_pooled_at -> PieceJob ->
    // verify/write). The buffering/eviction/duplicate faces share the
    // serial path's source (the same buffer_block); covered here are
    // the job's v1 whole-piece / v2 piece-root verification paths and
    // the "nothing touched disk" discipline.
    // ---------------------------------------------------------------------

    /// v1 pooled full pipeline: complete -> PieceCompleted -> the
    /// job's verify passes -> written -> read back identical; a
    /// corrupted piece -> Ok(false) and nothing touched disk.
    #[test]
    fn pooled_piece_job_v1_verify_and_write() {
        let content = pattern(2 * PIECE_LEN as usize);
        let (mut vw, path, _tmp) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        let mut jobs = Vec::new();
        for (i, chunk) in content.chunks(PIECE_LEN as usize).enumerate() {
            for (off, block) in chunk.chunks(4096).enumerate() {
                let begin = (off * 4096) as u32;
                match vw
                    .push_block_pooled_at(
                        i as u64,
                        (i * PIECE_LEN as usize + off * 4096) as u64,
                        begin,
                        &bytes::Bytes::copy_from_slice(block),
                    )
                    .unwrap_or_else(|e| panic!("{e}"))
                {
                    PooledOutcome::Buffered { .. } => {}
                    PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    other => panic!("piece {i}: unexpected {other:?}"),
                }
            }
        }
        assert_eq!(jobs.len(), 2, "each of the two pieces yields one job");
        // Jobs write to disk (via the shared handle, simulating the
        // pool worker path — the write hot-path domain).
        for job in &jobs {
            assert_eq!(
                job.verify(),
                Ok(true),
                "piece {} must pass verification",
                job.piece()
            );
            let w = vw.writer_handle();
            w.write_batch(|g| job.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(
            read_all(&path, content.len()),
            content,
            "job-written disk content matches"
        );

        // Corruption face: a new pool receives a corrupted block -> the
        // job's verify = Ok(false), nothing touched disk.
        let (mut vw2, path2, _tmp2) = setup_v1(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        let mut bad = content[0..PIECE_LEN as usize].to_vec();
        bad[11] ^= 0xff;
        let job = match vw2
            .push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&bad))
            .unwrap_or_else(|e| panic!("{e}"))
        {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(
            job.verify(),
            Ok(false),
            "a corrupted piece must fail verification"
        );
        assert_eq!(
            read_all(&path2, 16).len(),
            0,
            "a failed-verification job must not write to disk"
        );
        assert_eq!(
            vw2.evicted_unverified(),
            0,
            "no eviction without cache pressure"
        );
    }

    /// v2 pooled path: piece-root input cloning -> the job folds and
    /// verifies -> written (an assertion that the v2 verification face
    /// is covered by the pool; block granularity 16KiB-aligned, same
    /// as the wire granularity).
    #[test]
    fn pooled_piece_job_v2_piece_root_path() {
        let content = pattern(2 * PIECE_LEN as usize);
        let (mut vw, path, _tmp) = setup_v2(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        let mut jobs = Vec::new();
        for (i, chunk) in content.chunks(PIECE_LEN as usize).enumerate() {
            let goff = (i * PIECE_LEN as usize) as u64;
            for (off, block) in chunk.chunks(16384).enumerate() {
                match vw
                    .push_block_pooled_at(
                        i as u64,
                        goff,
                        (off * 16384) as u32,
                        &bytes::Bytes::copy_from_slice(block),
                    )
                    .unwrap_or_else(|e| panic!("{e}"))
                {
                    PooledOutcome::Buffered { .. } => {}
                    PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    other => panic!("piece {i}: unexpected {other:?}"),
                }
            }
        }
        assert_eq!(jobs.len(), 2);
        for job in &jobs {
            assert_eq!(job.verify(), Ok(true), "v2 piece {} must pass", job.piece());
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(read_all(&path, content.len()), content);

        // v2 corruption face: one block flipped -> the job's
        // verification fails, nothing touched disk.
        let (mut vw2, path2, _tmp2) = setup_v2(&content, crate::cache::DEFAULT_CACHE_LIMIT);
        let mut bad = content[0..16384].to_vec();
        bad[3] ^= 0x80;
        let job = match vw2
            .push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&bad))
            .unwrap_or_else(|e| panic!("{e}"))
        {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(job.verify(), Ok(false));
        assert_eq!(
            read_all(&path2, 16).len(),
            0,
            "a failed-verification job must not write to disk"
        );
    }

    /// The pooled face's buffering semantics match the serial path:
    /// benign duplicate drops, eviction registration (the semantics
    /// unchanged), cell invariants — spot checks of the behavior face
    /// of the same buffer_block code path.
    #[test]
    fn pooled_push_buffer_semantics_match_serial_path() {
        let content = pattern(2 * PIECE_LEN as usize);
        let (mut vw, _path, _tmp) = setup_v1(&content, PIECE_LEN as usize);
        const BLK: usize = 4096;
        // Block 0 buffered -> duplicate delivery -> benign drop (same
        // verdict as serial).
        let out = vw
            .push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&content[0..BLK]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PooledOutcome::Buffered { pending: 12288 }));
        let out = vw
            .push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&content[0..BLK]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(out, PooledOutcome::DuplicateDropped));
        // piece 1 whole piece over-limits the cache -> piece 0 evicted
        // (the min-loss order); the registration face unchanged
        // (`evicted_unverified` + `take_evicted`).
        let out = vw
            .push_block_pooled_at(
                1,
                PIECE_LEN as u64,
                0,
                &bytes::Bytes::copy_from_slice(
                    &content[PIECE_LEN as usize..2 * PIECE_LEN as usize],
                ),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let job = match out {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(job.piece(), 1);
        assert_eq!(
            vw.evicted_unverified, 1,
            "eviction must be observable via the counter"
        );
        assert_eq!(
            vw.take_evicted(),
            vec![0u64],
            "the eviction registration face unchanged"
        );
        assert_eq!(job.verify(), Ok(true));
    }

    // -------------------------------------------------------------------
    // Write merging (write-segment size distribution assertions; with
    // the default = 0, per-cell writes are unchanged).
    // -------------------------------------------------------------------

    /// Recording writer: logs every write_at's (goff, byte count) — the
    /// write-segment size distribution assertion face; reads/writes go
    /// straight to the file (the shared log is visible across
    /// instances). Vectored calls are logged separately (`vectored` —
    /// the (goff, total bytes) of each write_vectored_at, a call-
    /// granularity assertion face); the data lands through
    /// [`FileDiskWriter::write_vectored_at`]'s real vectored path.
    struct RecordingWriter {
        path: std::path::PathBuf,
        segments: SharedSegments,
        vectored: SharedSegments,
    }

    type SharedSegments = std::sync::Arc<std::sync::Mutex<Vec<(u64, usize)>>>;

    fn segments_of(s: &SharedSegments) -> Vec<(u64, usize)> {
        s.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    impl RecordingWriter {
        fn new(path: std::path::PathBuf, segments: SharedSegments) -> RecordingWriter {
            RecordingWriter {
                path,
                segments,
                vectored: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn new_with_vectored(
            path: std::path::PathBuf,
            segments: SharedSegments,
            vectored: SharedSegments,
        ) -> RecordingWriter {
            RecordingWriter {
                path,
                segments,
                vectored,
            }
        }
    }

    impl DiskWriter for RecordingWriter {
        fn open(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open(path, read_only)?;
            self.path = path.to_path_buf();
            Ok(())
        }

        fn open_existing(&mut self, path: &Path, read_only: bool) -> Result<(), StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(path, read_only)?;
            self.path = path.to_path_buf();
            Ok(())
        }

        fn create(&mut self, path: &Path) -> Result<(), StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.create(path)?;
            self.path = path.to_path_buf();
            Ok(())
        }

        fn truncate(&mut self, len: u64) -> Result<(), StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, false)?;
            f.truncate(len)
        }

        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            self.segments
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((offset, data.len()));
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, false)?;
            f.write_at(offset, data)
        }

        /// Logs the vectored call (call granularity) + the data goes
        /// through the real pwritev face. Does not reuse the default
        /// per-segment base — that would double-log write_at segments.
        fn write_vectored_at(&self, offset: u64, bufs: &[&[u8]]) -> Result<(), StoreError> {
            let total: usize = bufs.iter().map(|b| b.len()).sum();
            self.vectored
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((offset, total));
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, false)?;
            f.write_vectored_at(offset, bufs)
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, true)?;
            f.read_at(offset, buf)
        }

        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            Ok(())
        }

        fn size(&self) -> Result<u64, StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, true)?;
            f.size()
        }

        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    /// v1 pipeline with the recording writer: blocks pushed out of
    /// order (0,2,3,1) give cell distribution =
    /// [(0,4096),(4096,4096),(8192,8192)] (append only joins the last
    /// contiguous cell; block 1 arriving late forms its own cell —
    /// manufacturing mergeable adjacent runs).
    fn setup_v1_merged(
        content: &[u8],
        cache_limit: usize,
        policy: crate::disk_policy::DiskPolicy,
    ) -> (VerifiedWriter, SharedSegments, TempDir) {
        let tmp = TempDir::new("merged");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let segments: SharedSegments = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut w: Box<dyn DiskWriter> =
            Box::new(RecordingWriter::new(path.clone(), segments.clone()));
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, PIECE_LEN, content.len() as u64);
        let mut vw = VerifiedWriter::new(w, pool, cache_limit).with_disk_policy(policy);
        // coalesce pinned off for this harness: this group serves the
        // existing write-merge face's (the disk-policy final
        // semantics) deterministic assertions — the batching face has
        // its own tests (the `coalesce_*` family), so the environment
        // default (on) does not leak into these assertions.
        vw.set_write_coalesce(false);
        (vw, segments, tmp)
    }

    /// Push a piece full out of order (0,2,3,1 -> 4096 block
    /// granularity).
    fn push_piece_shuffled(vw: &mut VerifiedWriter, content: &[u8]) {
        for i in [0usize, 2, 3, 1] {
            vw.push_block(0, (i * 4096) as u32, &content[i * 4096..(i + 1) * 4096])
                .unwrap_or_else(|e| panic!("block {i}: {e}"));
        }
    }

    /// Default-zero-change test (write face): merge_max = 0 (the
    /// throughput default tier) -> per-cell writes; the write-segment
    /// sequence is verbatim the existing behavior (coordinates + sizes +
    /// order), and the content lands correctly. Note: cell capacity
    /// = block length (cache.rs cross-validates
    /// `BtPieceMessage.cc`), so a wire-granularity block is always one
    /// cell — 4096 blocks x 4 -> four segments.
    #[test]
    fn default_policy_writes_per_cell_exactly_as_before() {
        let content = pattern(PIECE_LEN as usize);
        let (mut vw, segments, _tmp) = setup_v1_merged(
            &content,
            crate::cache::DEFAULT_CACHE_LIMIT,
            Default::default(),
        );
        push_piece_shuffled(&mut vw, &content);
        assert_eq!(
            segments_of(&segments),
            vec![(0, 4096), (4096, 4096), (8192, 4096), (12288, 4096)],
            "the default tier must keep per-cell writes (zero behavior change)"
        );
    }

    /// Write merging active (write-segment size distribution
    /// assertions): merge_max > 0 merges adjacent cells into single
    /// write_at calls; everything merges within the cap; splits at the
    /// cap. Byte content and disk results are identical at every tier.
    #[test]
    fn write_merge_coalesces_adjacent_cells_with_cap() {
        let content = pattern(PIECE_LEN as usize);

        // ssd/hdd tier shape (cap >= whole piece): all four cells merge
        // -> one 16KiB write.
        let (mut vw, segments, tmp) = setup_v1_merged(
            &content,
            crate::cache::DEFAULT_CACHE_LIMIT,
            crate::disk_policy::DiskTier::SsdProtect.policy(),
        );
        push_piece_shuffled(&mut vw, &content);
        assert_eq!(
            segments_of(&segments),
            vec![(0, 16384)],
            "adjacent cells within the cap merge into one sequential large write"
        );

        // Cap split: merge_max = 8KiB -> [0,8KiB) merged +
        // [8KiB,16KiB) separate.
        let (mut vw2, segments2, tmp2) = setup_v1_merged(
            &content,
            crate::cache::DEFAULT_CACHE_LIMIT,
            crate::disk_policy::DiskPolicy {
                write_merge_max_bytes: 8192,
                ..crate::disk_policy::DiskTier::Throughput.policy()
            },
        );
        push_piece_shuffled(&mut vw2, &content);
        assert_eq!(
            segments_of(&segments2),
            vec![(0, 8192), (8192, 8192)],
            "must split at the merge cap"
        );

        // All three shapes land byte-identical content (merging only
        // changes syscall granularity).
        let read_back = |p: &std::path::Path| -> Vec<u8> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(p, true).unwrap_or_else(|e| panic!("{e}"));
            let mut buf = vec![0u8; PIECE_LEN as usize];
            let n = f.read_at(0, &mut buf).unwrap_or_else(|e| panic!("{e}"));
            buf.truncate(n);
            buf
        };
        let base = read_back(tmp.0.join("blob.bin").as_path());
        assert_eq!(base, content[..PIECE_LEN as usize]);
        assert_eq!(read_back(tmp2.0.join("blob.bin").as_path()), base);
    }

    /// Policy delivery on the pooled path: `with_disk_policy` travels
    /// with the [`PieceJob`] to the worker write face (verify_pool is
    /// unaware — `write_to` merges internally).
    #[test]
    fn pooled_job_write_to_honors_merge_policy() {
        let content = pattern(PIECE_LEN as usize);
        let (mut vw, segments, tmp) = setup_v1_merged(
            &content,
            crate::cache::DEFAULT_CACHE_LIMIT,
            crate::disk_policy::DiskTier::SsdProtect.policy(),
        );
        let job = match vw
            .push_block_pooled_at(
                0,
                0,
                0,
                &bytes::Bytes::copy_from_slice(&content[..PIECE_LEN as usize]),
            )
            .unwrap_or_else(|e| panic!("{e}"))
        {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(job.verify(), Ok(true));
        {
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(
            segments_of(&segments),
            vec![(0, 16384)],
            "the pooled worker write face must merge per policy (a single-cell whole piece is a single write)"
        );
        // Content correct.
        let mut f = crate::disk::FileDiskWriter::new();
        f.open_existing(&tmp.0.join("blob.bin"), true)
            .unwrap_or_else(|e| panic!("{e}"));
        let mut buf = vec![0u8; PIECE_LEN as usize];
        let n = f.read_at(0, &mut buf).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(n, PIECE_LEN as usize);
        assert_eq!(&buf[..n], &content[..PIECE_LEN as usize]);
    }

    // -------------------------------------------------------------------
    // Write-path batching (BH_WRITE_COALESCE): adjacent contiguous
    // cell runs vectored + cross-piece group writes. Red/green = the
    // vectored call log ((goff, total bytes) per write_vectored_at) —
    // the old code had no such call shape, so the assertion must be
    // red; byte content is the backstop. Cross-validation anchor:
    // libtorrent `visit_block_iovecs` merges contiguous blocks into a
    // single pwritev.
    // -------------------------------------------------------------------

    /// Single-piece vectored face (merge_max = 0 default tier +
    /// coalesce on): 4 adjacent cells stitch into **one**
    /// write_vectored_at (16KiB in one call) and per-cell write_at
    /// never happens; the read-back matches. The fallback control =
    /// [`default_policy_writes_per_cell_exactly_as_before`]
    /// (coalesce off, per cell).
    #[test]
    fn coalesce_on_single_piece_writes_one_vectored_call() {
        let content = pattern(PIECE_LEN as usize);
        let tmp = TempDir::new("coalesce-1p");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let segments: SharedSegments = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let vectored: SharedSegments = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut w: Box<dyn DiskWriter> = Box::new(RecordingWriter::new_with_vectored(
            path.clone(),
            segments.clone(),
            vectored.clone(),
        ));
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, PIECE_LEN, content.len() as u64);
        let mut vw = VerifiedWriter::new(w, pool, crate::cache::DEFAULT_CACHE_LIMIT);
        assert!(vw.write_coalesce_on(), "default = BH_WRITE_COALESCE on");
        push_piece_shuffled(&mut vw, &content);
        assert!(
            segments_of(&segments).is_empty(),
            "per-cell write_at must never happen on the vectored face"
        );
        assert_eq!(
            segments_of(&vectored),
            vec![(0, PIECE_LEN as usize)],
            "4 adjacent cells must stitch into one vectored call (red/green assertion)"
        );
        assert_eq!(read_all(&path, PIECE_LEN as usize), content);
    }

    /// Cross-piece group write (the spec acceptance "adjacent pieces
    /// stitched, whole-file hash" red/green): two adjacent completed
    /// pieces go through one [`PieceJob::write_group`] — adjacent
    /// cells stitch into a **cross-piece single** vectored call
    /// (2x16KiB = 32KiB in one call); the whole file reads back
    /// byte-identical + per-job call counts [1, 1]. The group-write
    /// precondition = the whole group passed verify()
    /// (verify-before-disk: what is merged is the write calls of
    /// verified pieces).
    #[test]
    fn coalesce_group_adjacent_pieces_whole_file_hash() {
        let content = pattern(2 * PIECE_LEN as usize);
        let tmp = TempDir::new("coalesce-grp");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let segments: SharedSegments = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let vectored: SharedSegments = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut w: Box<dyn DiskWriter> = Box::new(RecordingWriter::new_with_vectored(
            path.clone(),
            segments.clone(),
            vectored.clone(),
        ));
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, PIECE_LEN, content.len() as u64);
        let mut vw = VerifiedWriter::new(w, pool, crate::cache::DEFAULT_CACHE_LIMIT);
        // pieces 0 and 1 each pushed full out of order -> two jobs
        // (goff-adjacent: [0,16KiB) + [16KiB,32KiB)).
        let mut jobs = Vec::new();
        for p in 0..2usize {
            for i in [0usize, 2, 3, 1] {
                let goff = (p * PIECE_LEN as usize + i * 4096) as u64;
                match vw
                    .push_block_pooled_at(
                        p as u64,
                        goff,
                        (i * 4096) as u32,
                        &bytes::Bytes::copy_from_slice(
                            &content[p * PIECE_LEN as usize + i * 4096
                                ..p * PIECE_LEN as usize + (i + 1) * 4096],
                        ),
                    )
                    .unwrap_or_else(|e| panic!("piece {p} block {i}: {e}"))
                {
                    crate::verified::PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    crate::verified::PooledOutcome::Buffered { .. } => {}
                    other => panic!("piece {p} block {i}: unexpected {other:?}"),
                }
            }
        }
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].verify(), Ok(true));
        assert_eq!(jobs[1].verify(), Ok(true));
        // Adjacency test (the same formula as the pipeline's grouping
        // criterion): prev.last_cell_end == next.first_cell_goff.
        assert_eq!(
            jobs[0].last_cell_end(),
            jobs[1].first_cell_goff(),
            "the two pieces' goffs are adjacent (the group-write precondition)"
        );
        {
            let handle = vw.writer_handle();
            let calls = handle
                .write_batch(|g| PieceJob::write_group(&[&jobs[0], &jobs[1]], g))
                .unwrap_or_else(|e| panic!("group write: {e:?}"));
            assert_eq!(
                calls,
                vec![1, 1],
                "exactly one call per job (shared across pieces)"
            );
        }
        assert!(
            segments_of(&segments).is_empty(),
            "per-cell write_at must never happen on the group-write face"
        );
        assert_eq!(
            segments_of(&vectored),
            vec![(0, 2 * PIECE_LEN as usize)],
            "adjacent pieces must stitch into a single cross-piece vectored call (red/green assertion)"
        );
        assert_eq!(
            read_all(&path, content.len()),
            content,
            "whole-file read-back matches"
        );
    }

    /// Group-write failure mapping (the verdict-face red line): two
    /// **non-adjacent** pieces (two runs) + an injected failure in the
    /// second run -> `write_group` returns `Err((e, 1))` — `[..1)`'s
    /// bytes are on disk (the Written domain), `[1..)` failed (the
    /// WriteFailed domain; refetch+rewrite idempotent); the failed
    /// run's data must leave no residue and the file must not grow
    /// past its bounds.
    struct FailSecondRunWriter {
        path: std::path::PathBuf,
        runs: std::sync::atomic::AtomicUsize,
    }

    impl FailSecondRunWriter {
        fn fail_on(&self) -> Result<(), StoreError> {
            let n = self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 1 {
                return Err(StoreError::Internal("injected write failure".into()));
            }
            Ok(())
        }
    }

    impl DiskWriter for FailSecondRunWriter {
        fn open(&mut self, _path: &Path, _read_only: bool) -> Result<(), StoreError> {
            Ok(())
        }
        fn open_existing(&mut self, _path: &Path, _read_only: bool) -> Result<(), StoreError> {
            Ok(())
        }
        fn create(&mut self, path: &Path) -> Result<(), StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.create(path)?;
            self.path = path.to_path_buf();
            Ok(())
        }
        fn truncate(&mut self, _len: u64) -> Result<(), StoreError> {
            Ok(())
        }
        fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            self.fail_on()?;
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, false)?;
            f.write_at(offset, data)
        }
        /// Run execution (the group write) goes through here — the run
        /// count injection point (single/multi-buffer runs each count
        /// one).
        fn write_vectored_at(&self, offset: u64, bufs: &[&[u8]]) -> Result<(), StoreError> {
            self.fail_on()?;
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, false)?;
            f.write_vectored_at(offset, bufs)
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, true)?;
            f.read_at(offset, buf)
        }
        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            Ok(())
        }
        fn size(&self) -> Result<u64, StoreError> {
            let mut f = crate::disk::FileDiskWriter::new();
            f.open_existing(&self.path, true)?;
            f.size()
        }
        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn write_group_failure_maps_verdict_boundary() {
        let content = pattern(3 * PIECE_LEN as usize);
        let tmp = TempDir::new("coalesce-fail");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(FailSecondRunWriter {
            path: path.clone(),
            runs: std::sync::atomic::AtomicUsize::new(0),
        });
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, PIECE_LEN, content.len() as u64);
        let mut vw = VerifiedWriter::new(w, pool, crate::cache::DEFAULT_CACHE_LIMIT);
        // pieces 0 and 2 complete (piece 1 not pushed = the two jobs
        // are **non-adjacent** -> two independent runs).
        let mut jobs = Vec::new();
        for p in [0usize, 2usize] {
            for i in 0..4usize {
                let goff = (p * PIECE_LEN as usize + i * 4096) as u64;
                match vw
                    .push_block_pooled_at(
                        p as u64,
                        goff,
                        (i * 4096) as u32,
                        &bytes::Bytes::copy_from_slice(
                            &content[p * PIECE_LEN as usize + i * 4096
                                ..p * PIECE_LEN as usize + (i + 1) * 4096],
                        ),
                    )
                    .unwrap_or_else(|e| panic!("piece {p} block {i}: {e}"))
                {
                    crate::verified::PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    crate::verified::PooledOutcome::Buffered { .. } => {}
                    other => panic!("piece {p} block {i}: unexpected {other:?}"),
                }
            }
        }
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].verify(), Ok(true));
        assert_eq!(jobs[1].verify(), Ok(true));
        assert_ne!(
            jobs[0].last_cell_end(),
            jobs[1].first_cell_goff(),
            "pieces 0/2 are non-adjacent (the two-run precondition)"
        );
        {
            let handle = vw.writer_handle();
            let err = match handle.write_batch(|g| PieceJob::write_group(&[&jobs[0], &jobs[1]], g))
            {
                Err(e) => e,
                Ok(calls) => panic!(
                    "the injected failure must hit (the group write must not fully succeed): {calls:?}"
                ),
            };
            // The first run (piece 0's whole run, run 0) succeeds; the
            // second run (piece 2) hits the injected failure ->
            // first_failed = 1 (the WriteFailed domain start).
            assert_eq!(err.1, 1, "the first job not fully on disk = group index 1");
        }
        // piece 0's span is on disk (the Written domain, content
        // matches); piece 2's span has zero residue (the WriteFailed
        // domain — the file must not grow into the failed run).
        assert_eq!(
            read_all(&path, PIECE_LEN as usize),
            content[..PIECE_LEN as usize]
        );
        assert_eq!(
            read_all(&path, content.len()).len(),
            PIECE_LEN as usize,
            "the failed run must not extend the file (zero residual bytes)"
        );
    }

    /// Fallback face (BH_WRITE_COALESCE=0, the same shape as
    /// `set_write_coalesce(false)`): the default tier writes per cell
    /// and no grouping happens — a single-job group write goes through
    /// the existing [`write_cells_merged`] bit-for-bit (zero change),
    /// and the whole file reads back identical.
    #[test]
    fn coalesce_off_falls_back_per_cell() {
        let content = pattern(2 * PIECE_LEN as usize);
        let tmp = TempDir::new("coalesce-off");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let segments: SharedSegments = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let vectored: SharedSegments = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut w: Box<dyn DiskWriter> = Box::new(RecordingWriter::new_with_vectored(
            path.clone(),
            segments.clone(),
            vectored.clone(),
        ));
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, PIECE_LEN, content.len() as u64);
        let mut vw = VerifiedWriter::new(w, pool, crate::cache::DEFAULT_CACHE_LIMIT);
        vw.set_write_coalesce(false);
        assert!(!vw.write_coalesce_on());
        let mut jobs = Vec::new();
        for p in 0..2usize {
            for i in 0..4usize {
                let goff = (p * PIECE_LEN as usize + i * 4096) as u64;
                match vw
                    .push_block_pooled_at(
                        p as u64,
                        goff,
                        (i * 4096) as u32,
                        &bytes::Bytes::copy_from_slice(
                            &content[p * PIECE_LEN as usize + i * 4096
                                ..p * PIECE_LEN as usize + (i + 1) * 4096],
                        ),
                    )
                    .unwrap_or_else(|e| panic!("piece {p} block {i}: {e}"))
                {
                    crate::verified::PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    crate::verified::PooledOutcome::Buffered { .. } => {}
                    other => panic!("piece {p} block {i}: unexpected {other:?}"),
                }
            }
        }
        assert_eq!(jobs[0].verify(), Ok(true));
        assert_eq!(jobs[1].verify(), Ok(true));
        {
            let handle = vw.writer_handle();
            let calls = handle
                .write_batch(|g| PieceJob::write_group(&[&jobs[0], &jobs[1]], g))
                .unwrap_or_else(|e| panic!("fallback write: {e:?}"));
            // Fallback face: per cell per job (4 cells/piece) as
            // independent write_at calls; vectored calls never happen
            // (the status quo bit-for-bit).
            assert_eq!(
                calls,
                vec![4, 4],
                "fallback face = per-cell write call counts"
            );
        }
        assert_eq!(
            segments_of(&segments),
            vec![
                (0, 4096),
                (4096, 4096),
                (8192, 4096),
                (12288, 4096),
                (16384, 4096),
                (20480, 4096),
                (24576, 4096),
                (28672, 4096),
            ],
            "fallback-face per-cell write-segment sequence (final state bit-for-bit)"
        );
        assert!(
            segments_of(&vectored).is_empty(),
            "no vectored calls on the fallback face"
        );
        assert_eq!(read_all(&path, content.len()), content);
    }

    // ---------------------------------------------------------------------
    // v2 block-hash write-path precompute — table attachment / lookup
    // merge / miss fallback / eviction sync / block-verification
    // direct payment. Cross-validation anchors and the divergence note
    // live in the crate::precomputed_block_hashes module docs
    // (libtorrent precomputed_block_hashes.cpp + pread_disk_io.cpp, by
    // file:symbol).
    // ---------------------------------------------------------------------

    /// Piece length for the precompute tests (bpp = 4; a multi-block
    /// piece shape — a single-block piece cannot exercise slot
    /// merging).
    const PRECOMP_PIECE: u32 = 65536;

    /// v2 pool (each piece's root = the 4-block converged root) + the
    /// precompute-table attachment switch (table capacity = piece
    /// length / 16KiB, same parameters as the pipeline build point).
    fn setup_v2_precomputed(
        content: &[u8],
        cache_limit: usize,
        with_table: bool,
    ) -> (VerifiedWriter, PathBuf, TempDir) {
        let tmp = TempDir::new("v2-precomp");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let bpp = (PRECOMP_PIECE / crate::merkle::BLOCK_SIZE) as usize;
        let roots: Vec<[u8; 32]> = content
            .chunks(PRECOMP_PIECE as usize)
            .map(|p| {
                let blocks: Vec<[u8; 32]> = p
                    .chunks(crate::merkle::BLOCK_SIZE as usize)
                    .map(crate::merkle::block_hash)
                    .collect();
                crate::merkle::piece_root_from_block_hashes(&blocks, bpp)
            })
            .collect();
        let pool = HashPool::new_v2(roots, PRECOMP_PIECE, content.len() as u64);
        let mut vw = VerifiedWriter::new(w, pool, cache_limit);
        if with_table {
            vw.precomputed = Some(PrecomputedBlockHashes::new(bpp));
        }
        (vw, path, tmp)
    }

    /// Precompute table accessor (test face): the table must be
    /// attached (None = a test construction error).
    fn table_of(vw: &mut VerifiedWriter) -> &mut PrecomputedBlockHashes {
        vw.precomputed
            .as_mut()
            .unwrap_or_else(|| panic!("the precompute table must be attached"))
    }

    /// Table-attached full pipeline: v2 pieces pushed block by block
    /// (16KiB, pooled face); completed-piece verification inputs
    /// consult the table first — all hits (hits = total blocks,
    /// misses = 0, the "read-back goes to zero" steady state),
    /// verdicts and disk content bit-identical to the status quo path;
    /// the completed piece's entry moves out with the job (zero table
    /// residue — "released with the PieceJob").
    #[test]
    fn v2_precomputed_table_verifies_and_counts_hits() {
        let content = pattern(2 * PRECOMP_PIECE as usize);
        let (mut vw, path, _tmp) =
            setup_v2_precomputed(&content, crate::cache::DEFAULT_CACHE_LIMIT, true);
        let mut jobs = Vec::new();
        for (i, chunk) in content.chunks(PRECOMP_PIECE as usize).enumerate() {
            let base = (i * PRECOMP_PIECE as usize) as u64;
            for (off, block) in chunk.chunks(16384).enumerate() {
                // goff contract = piece base + in-piece offset
                // (push_block_pooled_at).
                match vw
                    .push_block_pooled_at(
                        i as u64,
                        base + (off * 16384) as u64,
                        (off * 16384) as u32,
                        &bytes::Bytes::copy_from_slice(block),
                    )
                    .unwrap_or_else(|e| panic!("{e}"))
                {
                    PooledOutcome::Buffered { .. } => {}
                    PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    other => panic!("piece {i}: unexpected {other:?}"),
                }
            }
        }
        assert_eq!(jobs.len(), 2);
        for job in &jobs {
            assert_eq!(job.verify(), Ok(true), "piece {}", job.piece());
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(vw.precomputed_hits(), 8, "all 8 blocks hit");
        assert_eq!(
            vw.precomputed_misses(),
            0,
            "steady-state zero read-backs (the misses-go-to-zero semantics)"
        );
        assert_eq!(read_all(&path, content.len()), content);
        let table = table_of(&mut vw);
        let slots0 = table.take_piece(0);
        let slots1 = table.take_piece(1);
        assert!(
            slots0.is_none() && slots1.is_none(),
            "the completed piece's entry moves out with the job, zero table residue"
        );
    }

    /// Corrupt-block injection (equivalence lock): with the table on,
    /// a corrupted block still enters the table (the write-path hash
    /// faithfully reflects the bad bytes); the completed piece's
    /// folded root mismatches -> Ok(false) — the lookup only changes
    /// the input source, not "when it is trusted"; the
    /// nothing-touched-disk discipline is unchanged.
    #[test]
    fn v2_precomputed_corrupt_block_still_fails_verify() {
        let content = pattern(2 * PRECOMP_PIECE as usize);
        let (mut vw, path, _tmp) =
            setup_v2_precomputed(&content, crate::cache::DEFAULT_CACHE_LIMIT, true);
        let mut bad = content[0..16384].to_vec();
        bad[9] ^= 0x40;
        vw.push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&bad))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut job = None;
        for off in 1..4usize {
            // goff contract = piece base (0) + in-piece offset.
            let res = vw
                .push_block_pooled_at(
                    0,
                    (off * 16384) as u64,
                    (off * 16384) as u32,
                    &bytes::Bytes::copy_from_slice(&content[off * 16384..(off + 1) * 16384]),
                )
                .unwrap_or_else(|e| panic!("{e}"));
            match (off, res) {
                (3, PooledOutcome::PieceCompleted(j)) => job = Some(j),
                (3, other) => panic!("unexpected {other:?}"),
                (_, PooledOutcome::Buffered { .. }) => {}
                (_, other) => panic!("unexpected {other:?}"),
            }
        }
        let job = job.unwrap_or_else(|| panic!("a full piece must yield a job on the spot"));
        assert_eq!(
            job.verify(),
            Ok(false),
            "the table path must intercept the corrupted piece accurately"
        );
        assert_eq!(
            vw.precomputed_hits(),
            4,
            "all 4 blocks enter the table (including the bad one)"
        );
        assert_eq!(vw.precomputed_misses(), 0);
        assert_eq!(
            read_all(&path, 16).len(),
            0,
            "the nothing-touched-disk discipline unchanged"
        );
    }

    /// Miss-slot fallback (equivalence lock): the first two blocks'
    /// table entries are cleared (the defense face for a mid-face
    /// attachment / lost entries), the last two enter as usual — at
    /// completion, miss slots keep the pool-located hashes (the
    /// status-quo path), decision semantics unchanged (verdicts match
    /// the all-hit control group), and the counters split correctly
    /// (2 miss + 2 hit).
    #[test]
    fn v2_precomputed_miss_slots_fall_back_to_pool_values() {
        let content = pattern(PRECOMP_PIECE as usize);
        // Control group: all table hits.
        let (mut vw, _path, _tmp) =
            setup_v2_precomputed(&content, crate::cache::DEFAULT_CACHE_LIMIT, true);
        // Experiment group: same content; the piece's table entry is
        // cleared after the first two blocks (a constructed miss).
        let (mut vw2, _path2, _tmp2) =
            setup_v2_precomputed(&content, crate::cache::DEFAULT_CACHE_LIMIT, true);
        for off in 0..2usize {
            // goff contract = piece base (0) + in-piece offset.
            let res = vw2
                .push_block_pooled_at(
                    0,
                    (off * 16384) as u64,
                    (off * 16384) as u32,
                    &bytes::Bytes::copy_from_slice(&content[off * 16384..(off + 1) * 16384]),
                )
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(matches!(res, PooledOutcome::Buffered { .. }));
        }
        table_of(&mut vw2).drop_piece(0);
        let mut job_ctl = None;
        let mut job_exp = None;
        for off in 0..4usize {
            let goff = (off * 16384) as u64;
            let block = &content[off * 16384..(off + 1) * 16384];
            let res = vw
                .push_block_pooled_at(
                    0,
                    goff,
                    (off * 16384) as u32,
                    &bytes::Bytes::copy_from_slice(block),
                )
                .unwrap_or_else(|e| panic!("{e}"));
            if let PooledOutcome::PieceCompleted(job) = res {
                job_ctl = Some(job);
            }
            let res = vw2
                .push_block_pooled_at(
                    0,
                    goff,
                    (off * 16384) as u32,
                    &bytes::Bytes::copy_from_slice(block),
                )
                .unwrap_or_else(|e| panic!("{e}"));
            if let PooledOutcome::PieceCompleted(job) = res {
                job_exp = Some(job);
            }
        }
        // Control group: the first two blocks were pushed before the
        // experiment group's clear — all four blocks hit (vw only
        // pushes in this loop, 4 hits).
        let ctl = job_ctl.unwrap_or_else(|| panic!("control job missing"));
        let exp = job_exp.unwrap_or_else(|| panic!("experiment job missing"));
        assert_eq!(ctl.verify(), Ok(true));
        assert_eq!(
            exp.verify(),
            Ok(true),
            "miss slots fall back to pool values, verdict unchanged"
        );
        assert_eq!(vw.precomputed_hits(), 4);
        assert_eq!(vw.precomputed_misses(), 0);
        assert_eq!(
            vw2.precomputed_hits(),
            2,
            "the last two blocks enter the table and hit as usual"
        );
        assert_eq!(
            vw2.precomputed_misses(),
            2,
            "the first two blocks counted as misses accurately"
        );
    }

    /// Eviction and table sync (cross-validation
    /// precomputed_block_hashes drop): piece 0 partially in the table
    /// gets evicted (cache overflow, min-loss victim order); its table
    /// entry is cleared together with the pool reset; the whole-piece
    /// refetch re-enters the table and verifies — no stale slot is
    /// consumed.
    #[test]
    fn v2_precomputed_eviction_drops_table_entry_in_sync() {
        let content = pattern(2 * PRECOMP_PIECE as usize);
        // limit = one piece: piece 1 completing must evict piece 0
        // (16KiB started vs 64KiB whole).
        let (mut vw, path, _tmp) = setup_v2_precomputed(&content, PRECOMP_PIECE as usize, true);
        let res = vw
            .push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&content[0..16384]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(res, PooledOutcome::Buffered { .. }));
        // piece 1 whole -> victim = minimum-progress piece 0 (data +
        // digests + table entry).
        let mut job1 = None;
        for off in 0..4usize {
            let base = PRECOMP_PIECE as usize;
            let res = vw
                .push_block_pooled_at(
                    1,
                    base as u64 + (off * 16384) as u64,
                    (off * 16384) as u32,
                    &bytes::Bytes::copy_from_slice(
                        &content[base + off * 16384..base + (off + 1) * 16384],
                    ),
                )
                .unwrap_or_else(|e| panic!("{e}"));
            if let PooledOutcome::PieceCompleted(j) = res {
                job1 = Some(j);
            }
        }
        let job1 = job1.unwrap_or_else(|| panic!("piece 1 must complete"));
        assert_eq!(job1.verify(), Ok(true));
        // The job writes to disk (pool worker semantics).
        {
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job1.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(vw.evicted_unverified(), 1);
        assert!(
            table_of(&mut vw).take_piece(0).is_none(),
            "the evicted piece's table entry must be cleared in sync with the pool reset (the drop-sync discipline)"
        );
        // piece 0 refetched whole: re-enters the table, verifies, and
        // lands (no stale slots).
        let mut job0 = None;
        for off in 0..4usize {
            let res = vw
                .push_block_pooled_at(
                    0,
                    (off * 16384) as u64,
                    (off * 16384) as u32,
                    &bytes::Bytes::copy_from_slice(&content[off * 16384..(off + 1) * 16384]),
                )
                .unwrap_or_else(|e| panic!("{e}"));
            if let PooledOutcome::PieceCompleted(j) = res {
                job0 = Some(j);
            }
        }
        let job0 = job0.unwrap_or_else(|| panic!("the refetched piece must complete"));
        assert_eq!(job0.verify(), Ok(true));
        {
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job0.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(
            vw.precomputed_misses(),
            0,
            "refetched slots all re-enter the table"
        );
        assert_eq!(
            read_all(&path, content.len()),
            content,
            "all pieces eventually land identical"
        );
    }

    /// Block-verification direct-payment arm: with the table on, step
    /// 1.5 uses `verify_block_hash` (the precomputed hash compared
    /// directly, no second SHA-256) — a bad block is still
    /// BlockRejected, isolating only itself, and **does not enter the
    /// table** (the store happens after pool acceptance); the
    /// refetched good bytes re-enter the table and the piece completes
    /// as usual. The normal v2 shape with the leaf layer present.
    #[test]
    fn v2_block_check_consumes_precomputed_hash() {
        let content = pattern(2 * 32768);
        let (vw, _root, tmp) = setup_v2_block_check(&content);
        let mut vw = vw.with_precomputed_block_hashes(PrecomputedBlockHashes::new(2));
        let path = tmp.0.join("blob.bin");
        // piece 0: both blocks good (the 1.5 direct-comparison arm
        // hits) -> complete -> written.
        let res = vw
            .push_block_pooled_at(0, 0, 0, &bytes::Bytes::copy_from_slice(&content[0..16384]))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(res, PooledOutcome::Buffered { .. }));
        let job0 = match vw
            .push_block_pooled_at(
                0,
                16384,
                16384,
                &bytes::Bytes::copy_from_slice(&content[16384..32768]),
            )
            .unwrap_or_else(|e| panic!("{e}"))
        {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(job0.verify(), Ok(true));
        {
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job0.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        // piece 1 block 0 corrupted -> the direct-comparison arm
        // BlockRejects, and the bad hash leaves zero residue.
        let mut bad = content[32768..49152].to_vec();
        bad[7] ^= 0x01;
        let res = vw
            .push_block_pooled_at(1, 32768, 0, &bytes::Bytes::copy_from_slice(&bad))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(res, PooledOutcome::BlockRejected { leaf_index: 2 }),
            "got {res:?}"
        );
        assert!(
            table_of(&mut vw).take_piece(1).is_none(),
            "rejected blocks do not enter the table (storage happens after pool acceptance)"
        );
        // The neighbor block buffers as usual; the refetched block
        // (good bytes) -> piece 1 completes and verifies -> written.
        let res = vw
            .push_block_pooled_at(
                1,
                49152,
                16384,
                &bytes::Bytes::copy_from_slice(&content[49152..65536]),
            )
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(res, PooledOutcome::Buffered { .. }));
        let job1 = match vw
            .push_block_pooled_at(
                1,
                32768,
                0,
                &bytes::Bytes::copy_from_slice(&content[32768..49152]),
            )
            .unwrap_or_else(|e| panic!("{e}"))
        {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(job1.verify(), Ok(true));
        {
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job1.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(
            vw.precomputed_hits(),
            4,
            "piece 0 x2 + piece 1 x2 (refetch enters the table)"
        );
        assert_eq!(vw.precomputed_misses(), 0);
        assert_eq!(
            read_all(&path, 65536),
            content,
            "all pieces eventually land identical"
        );
    }

    // ---- Unverified spill area (spill sidecar) in-domain tests ----

    const SPILL_PIECE_LEN: u32 = 4 * 16384; // 64KiB = 4 blocks/piece

    /// Read a file range, zero-padding short reads (an untouched sparse
    /// region reads back 0 bytes — the zero-scan assertion needs a
    /// fixed-length view).
    fn read_all_padded(path: &std::path::Path, len: usize) -> Vec<u8> {
        let mut buf = read_all(path, len);
        buf.resize(len, 0);
        buf
    }

    /// Multi-block-piece v1 pool + spill area (`spill_limit` given per
    /// test; the sidecar directory lives under the test TempDir and is
    /// cleaned up with its Drop).
    fn setup_v1_spill(
        content: &[u8],
        piece_len: u32,
        cache_limit: usize,
        spill_limit: usize,
    ) -> (VerifiedWriter, PathBuf, TempDir) {
        let tmp = TempDir::new("spill");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(piece_len as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let pool = HashPool::new_v1(&expected, piece_len, content.len() as u64);
        // open_for_dest derives the sidecar next to the dest — which
        // is exactly the test TempDir (cleaned with TempDir::drop; the
        // Drop path has its own test). The face lock on an exclusive
        // test directory must be obtainable — None = a
        // test-environment anomaly.
        let vw = match crate::spill::SpillStore::open_for_dest(&path, 0, spill_limit) {
            Some(s) => VerifiedWriter::new(w, pool, cache_limit).with_spill(s),
            None => panic!("spill face lock unavailable in test: {}", path.display()),
        };
        (vw, path, tmp)
    }

    /// Spill absorption + read-back at completion: the victim piece is
    /// not destroyed (evicted_unverified = 0); a piece partly in the
    /// spill completes by reading back, assembling, verifying, and
    /// landing byte-identical (the in-domain loop of the acceptance
    /// goal "residual eviction count -> 0").
    #[test]
    fn spill_absorbs_eviction_and_reads_back_at_completion() {
        let content = pattern(2 * SPILL_PIECE_LEN as usize);
        // Cache 3 blocks (48KiB); spill budget 4 blocks (64KiB).
        let (mut vw, path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 3 * 16384, 4 * 16384);
        let push = |vw: &mut VerifiedWriter, p: u64, off: u32, blk: &[u8]| {
            vw.push_block(p, off, blk)
                .unwrap_or_else(|e| panic!("push {p}/{off}: {e}"))
        };
        // p0: three blocks into the cache (48KiB, exactly full).
        assert!(matches!(
            push(&mut vw, 0, 0, &content[0..16384]),
            PushOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 0, 16384, &content[16384..32768]),
            PushOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 0, 32768, &content[32768..49152]),
            PushOutcome::Buffered { .. }
        ));
        // p1's first block -> over limit, the min-loss victim = p0
        // (the only unprotected entry, 48KiB) -> the whole entry is
        // absorbed by spill (not destroyed, not reset, no
        // notification).
        assert!(matches!(
            push(&mut vw, 1, 0, &content[65536..81920]),
            PushOutcome::Buffered { .. }
        ));
        assert_eq!(
            vw.evicted_unverified(),
            0,
            "spill absorption: zero destruction"
        );
        assert_eq!(vw.spill_write_bytes(), 49152, "p0's whole entry spilled");
        assert!(
            vw.take_evicted().is_empty(),
            "no upstream notification (no refetch)"
        );
        // p0's last block enters the cache -> piece complete: read
        // back the three spilled blocks + the cached one ->
        // verification passes -> lands (the read-back-at-completion
        // path).
        assert!(matches!(
            push(&mut vw, 0, 49152, &content[49152..65536]),
            PushOutcome::PieceVerified { .. }
        ));
        assert_eq!(vw.spill_readback_pieces(), 1, "p0 read back once");
        assert_eq!(vw.spill_read_bytes(), 49152);
        // p1's remaining three blocks assemble fully in cache (the
        // transient over-limit mid-advance converges via the
        // termination guard — no second victim) -> verifies and lands.
        assert!(matches!(
            push(&mut vw, 1, 16384, &content[81920..98304]),
            PushOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 1, 32768, &content[98304..114688]),
            PushOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 1, 49152, &content[114688..131072]),
            PushOutcome::PieceVerified { .. }
        ));
        assert_eq!(
            vw.evicted_unverified(),
            0,
            "zero residual evictions throughout"
        );
        assert_eq!(
            read_all(&path, content.len()),
            content,
            "the main file is byte-identical"
        );
        drop(vw);
        let spill_root = path
            .parent()
            .unwrap_or_else(|| panic!("dest has no parent"))
            .join(".taiji-spill");
        // The face directory is deleted at task teardown; the task
        // directory keeps only the face lock file (permanent by
        // discipline — the release+unlink inode-swap race, see
        // spill.rs `FaceLock` docs) -> zero spill data residue.
        let task = spill_root.join(crate::spill::spill_task_name(&path));
        assert!(
            !task.join("face0").exists(),
            "the sidecar face directory is deleted at task teardown"
        );
        let residue: Vec<String> = std::fs::read_dir(&task)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            residue.iter().all(|n| n == "face0.lock"),
            "the task directory keeps only the face lock file: {residue:?}"
        );
    }

    /// Invariant ("the main file holds no unverified bytes at any
    /// moment"): a failed piece's bytes are partly in the spill
    /// (sidecar), partly in the cache; assembly verification fails ->
    /// everything is dropped and the main file is untouched (a
    /// file-level all-zero scan); after refetching correct bytes the
    /// piece verifies and lands. Spilled bytes can only ever be in the
    /// sidecar — the main data file holds zero unverified bytes at any
    /// moment.
    #[test]
    fn spilled_bytes_never_reach_main_file_on_verify_failure() {
        // 4-piece rig: p0 is the piece under test; p1-p3 provide cache
        // pressure only (never complete).
        let content = pattern(4 * SPILL_PIECE_LEN as usize);
        let (mut vw, path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 3 * 16384, 4 * 16384);
        // One block from each of four pieces overfills the cache
        // (64KiB > 48KiB) -> victim = the oldest same-size entry p0 ->
        // p0 blk1 spills.
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(1, 0, &content[65536..81920])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(2, 0, &content[131072..147456])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(3, 0, &content[196608..212992])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vw.evicted_unverified(), 0, "p0 was absorbed by spill");
        assert_eq!(vw.spill_write_bytes(), 16384);
        // p0 gets three more blocks, blk2 corrupted (v1 face: no
        // block-level verification, interception only at whole-piece
        // recompute on completion) -> three cache-side evictions pull
        // p1-p3 into the spill too -> p0 completes, verification must
        // fail -> the piece resets for refetch.
        let mut corrupt = content[16384..32768].to_vec();
        corrupt[3] ^= 0xff;
        vw.push_block(0, 16384, &corrupt)
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(0, 32768, &content[32768..49152])
            .unwrap_or_else(|e| panic!("{e}"));
        let verdict = vw
            .push_block(0, 49152, &content[49152..65536])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(verdict, PushOutcome::PieceFailed),
            "got {verdict:?}"
        );
        assert_eq!(
            vw.evicted_unverified(),
            0,
            "absorbed throughout (including the corrupted block — v1 verification happens at completion)"
        );
        vw.reset_failed_piece(0);
        // File-level scan: p0's whole span untouched (no written bytes
        // — the sparse file reads back zeros).
        let file = read_all_padded(&path, 65536);
        assert!(
            file.iter().all(|&b| b == 0),
            "unverified bytes appeared in the main file (invariant broken)"
        );
        // Refetch the whole piece's correct bytes -> verification
        // passes -> lands (the spilled remnant was consumed by the
        // failed read-back, so the coverage check no longer swallows
        // redeliveries — piece completability restored).
        for (off, range) in [
            (0u32, 0..16384),
            (16384, 16384..32768),
            (32768, 32768..49152),
            (49152, 49152..65536),
        ] {
            let res = vw
                .push_block(0, off, &content[range])
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(
                !matches!(res, PushOutcome::DuplicateDropped),
                "refetched blocks must not be swallowed"
            );
        }
        assert_eq!(
            read_all(&path, 65536),
            content[0..65536],
            "p0's span lands correctly after refetch"
        );
    }

    /// Out-of-budget fallback ("over budget falls back to
    /// destroy-and-refetch"): a single entry over the spill budget ->
    /// the status-quo destroy semantics bit-for-bit (count +
    /// registration + reset).
    #[test]
    fn spill_budget_overflow_falls_back_to_destroy() {
        let content = pattern(2 * SPILL_PIECE_LEN as usize);
        // Spill budget = 1 block (a 32KiB whole entry must exceed it).
        let (mut vw, path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 2 * 16384, 16384);
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        let res = vw
            .push_block(1, 0, &content[65536..81920])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(res, PushOutcome::Buffered { .. }));
        assert_eq!(vw.evicted_unverified(), 1, "over-budget fallback destroys");
        assert_eq!(
            vw.take_evicted(),
            vec![0],
            "the upstream invalidation notification as usual"
        );
        assert_eq!(vw.spill_write_bytes(), 0, "not absorbed: zero spill writes");
        assert!(
            read_all_padded(&path, content.len())
                .iter()
                .all(|&b| b == 0),
            "the destroy face touches zero disk"
        );
    }

    /// Budget-overflow fallback destroyed bytes: the not-absorbed arm
    /// (single entry over cap) and the displacement arm (FIFO victim)
    /// each book one destroyed total; status-quo evictions with spill
    /// off do **not** count (they belong to
    /// `evicted_unverified_bytes`; the difference is the budget
    /// attribution face).
    #[test]
    fn spill_fallback_destroy_bytes_counts_budget_fallback_only() {
        // Not-absorbed arm: budget 1 block; the 32KiB whole entry must
        // be refused -> p0 (two blocks) destroyed.
        let content = pattern(2 * SPILL_PIECE_LEN as usize);
        let (mut vw, _path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 2 * 16384, 16384);
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(1, 0, &content[65536..81920])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vw.evicted_unverified(), 1);
        assert_eq!(
            vw.spill_fallback_destroy_bytes(),
            32768,
            "the not-absorbed arm = the full over-budget fallback destroy total"
        );
        drop(vw);
        // Displacement arm: budget 3 blocks; after p0 spills it is
        // displaced FIFO = 32KiB destroyed.
        let content = pattern(3 * SPILL_PIECE_LEN as usize);
        let (mut vw, _path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 2 * 16384, 3 * 16384);
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(1, 0, &content[65536..81920])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vw.evicted_unverified(), 0, "p0 was absorbed by spill");
        assert_eq!(
            vw.spill_fallback_destroy_bytes(),
            0,
            "the absorbed face destroys zero"
        );
        vw.push_block(1, 16384, &content[81920..98304])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(2, 0, &content[131072..147456])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vw.evicted_unverified(), 1, "displacement victim p0");
        assert_eq!(
            vw.spill_fallback_destroy_bytes(),
            32768,
            "the displacement arm = the FIFO victim destroy total"
        );
        drop(vw);
        // Spill off: the same not-absorbed shape counts 0 (the
        // status-quo destroy is not a budget face).
        let content = pattern(2 * SPILL_PIECE_LEN as usize);
        let tmp = TempDir::new("fallback-off");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(SPILL_PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let mut vw = VerifiedWriter::new(
            w,
            HashPool::new_v1(&expected, SPILL_PIECE_LEN, content.len() as u64),
            2 * 16384,
        );
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(1, 0, &content[65536..81920])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vw.evicted_unverified(), 1, "status-quo destroy semantics");
        assert_eq!(
            vw.spill_fallback_destroy_bytes(),
            0,
            "spill off does not count (steady-state evictions belong to evicted_unverified_bytes)"
        );
    }

    /// Default off (the fallback discipline "default off"): the same
    /// operation sequence without a spill area follows the status-quo
    /// destroy semantics — a regression guard against the switch
    /// accidentally defaulting on.
    #[test]
    fn spill_off_by_default_keeps_baseline_destroy_semantics() {
        let content = pattern(2 * SPILL_PIECE_LEN as usize);
        let tmp = TempDir::new("spill-off");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("blob.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let mut expected = Vec::new();
        for c in content.chunks(SPILL_PIECE_LEN as usize) {
            expected.extend_from_slice(&Sha1::digest(c));
        }
        let mut vw = VerifiedWriter::new(
            w,
            HashPool::new_v1(&expected, SPILL_PIECE_LEN, content.len() as u64),
            2 * 16384,
        );
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(1, 0, &content[65536..81920])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            vw.evicted_unverified(),
            1,
            "status-quo destroy semantics (no spill area present)"
        );
        assert_eq!(vw.spill_write_bytes(), 0);
        assert_eq!(vw.spill_readback_pieces(), 0);
    }

    /// Spill coverage check: a redelivery of an already-spilled block
    /// is dropped benignly (no re-caching, no refetch); the piece then
    /// completes as usual via read-back.
    #[test]
    fn spilled_block_redelivery_is_dropped_as_duplicate() {
        let content = pattern(SPILL_PIECE_LEN as usize);
        let (mut vw, path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 2 * 16384, 4 * 16384);
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        let _ = vw.push_block(0, 16384, &content[16384..32768]);
        let _ = vw.push_block(1, 0, &content[0..16384]); // force over-limit -> spill
        assert_eq!(vw.evicted_unverified(), 0);
        let drops_before = vw.duplicate_drops();
        // Redeliver the spilled blk1 (same coordinates) -> the spill
        // coverage hits -> benign drop.
        let res = vw
            .push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(res, PushOutcome::DuplicateDropped), "got {res:?}");
        assert_eq!(vw.duplicate_drops(), drops_before + 1);
        // The piece completes as usual (spill read-back + cached
        // blk3, blk4) -> verifies and lands.
        vw.push_block(0, 32768, &content[32768..49152])
            .unwrap_or_else(|e| panic!("{e}"));
        let verdict = vw
            .push_block(0, 49152, &content[49152..65536])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(verdict, PushOutcome::PieceVerified { .. }));
        assert_eq!(read_all(&path, content.len()), content);
    }

    /// Spill displacement (FIFO, oldest first): when the budget is
    /// short, the displaced entry = destroy-and-refetch (a residual
    /// eviction); the new entry still spills and reads back; the
    /// displaced piece can complete after refetch.
    #[test]
    fn spill_zone_displaces_oldest_entry_as_residual_eviction() {
        let content = pattern(3 * SPILL_PIECE_LEN as usize);
        // Spill budget = 3 blocks (48KiB: with one 32KiB entry present,
        // another 32KiB must displace).
        let (mut vw, path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 2 * 16384, 3 * 16384);
        // p0: two blocks into the cache.
        vw.push_block(0, 0, &content[0..16384])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(0, 16384, &content[16384..32768])
            .unwrap_or_else(|e| panic!("{e}"));
        // p1's first block -> p0 (32KiB) evicted -> p0 spills (32KiB
        // <= budget).
        vw.push_block(1, 0, &content[65536..81920])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(vw.evicted_unverified(), 0);
        assert_eq!(vw.spill_write_bytes(), 32768);
        // p1's second block into cache -> p2's first block -> victim
        // p1 (32KiB) -> spill p1: budget 32+32 > 48 -> displace p0
        // (FIFO oldest) = a residual eviction.
        vw.push_block(1, 16384, &content[81920..98304])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(2, 0, &content[131072..147456])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            vw.evicted_unverified(),
            1,
            "the displacement victim = the spill area's FIFO oldest"
        );
        assert_eq!(vw.take_evicted(), vec![0]);
        assert_eq!(vw.spill_write_bytes(), 65536, "p1 spills as usual");
        // p1's last two blocks complete: read back the two spilled
        // blocks + the two cached ones -> verifies and lands.
        vw.push_block(1, 32768, &content[98304..114688])
            .unwrap_or_else(|e| panic!("{e}"));
        let p1 = vw
            .push_block(1, 49152, &content[114688..131072])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(p1, PushOutcome::PieceVerified { .. }));
        // p0 refetched whole (its spill entry was destroyed by the
        // displacement — redelivered blocks must not be swallowed).
        for (off, range) in [
            (0u32, 0..16384),
            (16384, 16384..32768),
            (32768, 32768..49152),
        ] {
            let res = vw
                .push_block(0, off, &content[range])
                .unwrap_or_else(|e| panic!("{e}"));
            assert!(
                !matches!(res, PushOutcome::DuplicateDropped),
                "the evicted piece's refetch must not be swallowed"
            );
        }
        let p0 = vw
            .push_block(0, 49152, &content[49152..65536])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(p0, PushOutcome::PieceVerified { .. }));
        // p2 completes (b1 already spilled, b2-b4 cached).
        vw.push_block(2, 16384, &content[147456..163840])
            .unwrap_or_else(|e| panic!("{e}"));
        vw.push_block(2, 32768, &content[163840..180224])
            .unwrap_or_else(|e| panic!("{e}"));
        let p2 = vw
            .push_block(2, 49152, &content[180224..196608])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(p2, PushOutcome::PieceVerified { .. }));
        assert_eq!(
            vw.evicted_unverified(),
            1,
            "the only residual eviction throughout = the displacement victim"
        );
        assert_eq!(read_all(&path, content.len()), content);
    }

    /// Regression for the displaced-victim coexistence defect
    /// (production pooled path): when a displacement victim is in the
    /// "partially spilled + new block back in cache" state, destruction
    /// must also clear the **cache half** — otherwise the redelivered
    /// block is swallowed by the cache coverage check as
    /// DuplicateDropped while the pool count is reset, and the piece
    /// stalls forever (all blocks delivered yet one byte count always
    /// missing, with no completion or failure event).
    ///
    /// Orchestration: p0 spills two blocks (32KiB) -> p0's third block
    /// returns to the cache (coexistence) -> p2's first block triggers
    /// p2's spill, the budget is short, displacement evicts p0 -> p0
    /// redelivered in full -> it must be able to complete. Before the
    /// fix: the third block's redelivery was swallowed by the residual
    /// cache cell, so after b4 arrived the pool still missed 16KiB and
    /// the piece never completed (the observed shape); after the fix:
    /// destruction includes the cache entry removal, all redeliveries
    /// count, and the piece completes normally.
    #[test]
    fn displaced_victim_with_live_cache_cells_completes_after_refetch() {
        let content = pattern(3 * SPILL_PIECE_LEN as usize);
        // Cache 3 blocks (48KiB); spill budget 40KiB (with a 32KiB
        // entry present, another 16KiB must displace).
        let (mut vw, path, _tmp) = setup_v1_spill(&content, SPILL_PIECE_LEN, 3 * 16384, 40 * 1024);
        let push = |vw: &mut VerifiedWriter, p: u64, off: u32, blk: &[u8]| {
            vw.push_block_pooled_at(
                p,
                p * u64::from(SPILL_PIECE_LEN) + u64::from(off),
                off,
                &bytes::Bytes::copy_from_slice(blk),
            )
            .unwrap_or_else(|e| panic!("push {p}/{off}: {e}"))
        };
        // p0: two blocks into cache -> p1's two blocks push p0 into
        // the spill (32KiB <= budget).
        assert!(matches!(
            push(&mut vw, 0, 0, &content[0..16384]),
            PooledOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 0, 16384, &content[16384..32768]),
            PooledOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 1, 0, &content[65536..81920]),
            PooledOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 1, 16384, &content[81920..98304]),
            PooledOutcome::Buffered { .. }
        ));
        assert_eq!(vw.evicted_unverified(), 0, "p0 was absorbed by spill");
        // p2's first block into cache (48KiB, exactly full).
        assert!(matches!(
            push(&mut vw, 2, 0, &content[131072..147456]),
            PooledOutcome::Buffered { .. }
        ));
        // p0's third block: enters the cache first (coexistence), then
        // the in-push over-limit evicts -> victim p2 (the smallest
        // entry) -> p2's spill is over budget -> displace p0 (spill
        // FIFO) -> p0 is destroyed while holding a live cache cell
        // (the third block) -> this piece returns under the
        // abort-and-refetch semantics (including being a displacement
        // victim itself).
        assert!(matches!(
            push(&mut vw, 0, 32768, &content[32768..49152]),
            PooledOutcome::PieceAbortedUnverified
        ));
        assert_eq!(vw.evicted_unverified(), 1, "the displacement victim = p0");
        assert_eq!(
            vw.take_evicted(),
            vec![0],
            "the upstream bookkeeping invalidation notification"
        );
        assert_eq!(
            vw.evicted_unverified_bytes(),
            49152,
            "destroy accounting = spill 32KiB + residual cache 16KiB (both halves sum)"
        );
        // p0 redelivered in full: the third block must not be swallowed
        // by the residual cache (the core fix assertion); with all
        // four blocks present the piece must complete (before the fix:
        // the third block DuplicateDropped, and after b4 the pool
        // still missed 16KiB — piece_complete never held).
        assert!(matches!(
            push(&mut vw, 0, 0, &content[0..16384]),
            PooledOutcome::Buffered { .. }
        ));
        assert!(matches!(
            push(&mut vw, 0, 16384, &content[16384..32768]),
            PooledOutcome::Buffered { .. }
        ));
        let third = push(&mut vw, 0, 32768, &content[32768..49152]);
        assert!(
            !matches!(third, PooledOutcome::DuplicateDropped),
            "the redelivered block was swallowed by the residual cache as a duplicate (the stall shape recurs): {third:?}"
        );
        let job = match push(&mut vw, 0, 49152, &content[49152..65536]) {
            PooledOutcome::PieceCompleted(job) => job,
            other => panic!("the piece must complete (a stall = regression): {other:?}"),
        };
        assert_eq!(job.verify(), Ok(true));
        {
            let handle = vw.writer_handle();
            handle
                .write_batch(|g| job.write_to(g))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(
            read_all(&path, 65536),
            content[0..65536],
            "p0's span lands correctly after refetch"
        );
    }

    // -------------------------------------------------------------------
    // Write de-serialization: concurrent-write correctness (the red
    // line "out-of-order writes are safe").
    // -------------------------------------------------------------------

    /// Concurrency harness: `THREADS` threads write non-overlapping
    /// piece spans through one [`SharedDiskWriter`] (each thread
    /// claims alternating pieces and emits them in **reverse** order =
    /// out-of-order arrival); after joining, the whole file reads back
    /// byte-identical + per-piece SHA-1. The criterion is a direct
    /// translation of the red line "concurrent pwrite at different
    /// piece offsets, then a whole-file hash verification test".
    fn drive_concurrent_piece_writes(shared: &SharedDiskWriter, path: &Path, pieces: usize) {
        const THREADS: usize = 4;
        let content = Arc::new(pattern(pieces * PIECE_LEN as usize));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let shared = shared.clone();
                let content = Arc::clone(&content);
                std::thread::spawn(move || {
                    for p in (0..pieces).filter(|p| p % THREADS == t).rev() {
                        let off = (p * PIECE_LEN as usize) as u64;
                        let seg = &content[p * PIECE_LEN as usize..(p + 1) * PIECE_LEN as usize];
                        shared
                            .write_batch(|w| w.write_at(off, seg))
                            .unwrap_or_else(|e| panic!("t{t} piece {p}: {e}"));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join()
                .unwrap_or_else(|e| panic!("writer thread panicked: {e:?}"));
        }
        // Whole-file read-back byte-identical + per-piece SHA-1 (write
        // out-of-order safety).
        let got = read_all(path, content.len());
        assert_eq!(
            got, *content,
            "after concurrent writes the whole-file read-back must be byte-identical"
        );
        for (p, c) in got.chunks(PIECE_LEN as usize).enumerate() {
            let want = Sha1::digest(&content[p * PIECE_LEN as usize..(p + 1) * PIECE_LEN as usize]);
            assert_eq!(
                Sha1::digest(c).as_slice(),
                want.as_slice(),
                "piece {p} hash"
            );
        }
    }

    /// Concurrent face (the same shape as an explicit
    /// `BH_PARALLEL_WRITES=1`): multiple threads pwrite different
    /// piece offsets concurrently; the whole-file hash check passes;
    /// the concurrent-face observation bit is true (unix).
    #[test]
    fn shared_writer_concurrent_positioned_writes_hash_verified() {
        let tmp = TempDir::new("conc-w");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("conc.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let shared = SharedDiskWriter::with_parallel_writes(w, true);
        #[cfg(unix)]
        assert!(
            shared.parallel_writes(),
            "unix explicit on must land on the concurrent face (read lock) — the precondition for concurrency discriminating power"
        );
        drive_concurrent_piece_writes(&shared, &path, 32);
    }

    /// Serial fallback face (the default shape;
    /// [`SharedDiskWriter::with_parallel_writes`](.., false) assembled
    /// explicitly, env-independent, no race): writes take the
    /// exclusive write lock = the old global-mutex shape; the same
    /// concurrent driver yields identical content (zero default
    /// regression).
    #[test]
    fn shared_writer_fallback_exclusive_writes_content_verified() {
        let tmp = TempDir::new("fallback-w");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("fallback.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let shared = SharedDiskWriter::with_parallel_writes(w, false);
        assert!(
            !shared.parallel_writes(),
            "explicit off = the exclusive write lock (the old global-mutex shape)"
        );
        drive_concurrent_piece_writes(&shared, &path, 32);
    }

    /// Default-face lock: `SharedDiskWriter::new` = platform gate &&
    /// switch (default off = the serial fallback, see the
    /// [`parallel_writes_env`] note; the differential ON round with
    /// BH_PARALLEL_WRITES=1 holds in reverse).
    #[test]
    fn shared_writer_default_follows_switch() {
        let tmp = TempDir::new("default-w");
        std::fs::create_dir_all(&tmp.0).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let path = tmp.0.join("d.bin");
        let mut w: Box<dyn DiskWriter> = Box::new(crate::disk::FileDiskWriter::new());
        w.create(&path).unwrap_or_else(|e| panic!("create: {e}"));
        let shared = SharedDiskWriter::new(w);
        assert_eq!(
            shared.parallel_writes(),
            cfg!(unix) && parallel_writes_env(),
            "the default face = platform gate && BH_PARALLEL_WRITES (the measured decision locked)"
        );
    }
}

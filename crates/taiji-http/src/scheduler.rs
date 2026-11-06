//! Scheduling modes and allocation plans (`--http-scheduler=dynamic|static`;
//! default `dynamic`; `static` is kept as a comparison/fallback baseline).
//!
//! Scope (two-layer model): the extent layer serves only the Range domain —
//! post-probe merged 206 sources with a known authoritative total length
//! ([`crate::traits::ResumeValidator::total_len`] = `Some`). The no-range
//! shape (all 200 sources) degrades to a single connection, builds no grid,
//! and has no offset resume (recovery restarts from zero) — it never reaches
//! this scheduler.
//!
//! `static`: fixed segmentation mirroring upstream aria2 `--split`/
//! `--min-split-size` semantics — `n = min(split, max(1, total/min-split-size))`
//! segments, lengths aligned down to the block granule (sub-block extents
//! forbidden), remainder folded into the last segment; collapses to one
//! segment when `total <= block_size` or the aligned length is 0.
//!
//! `dynamic`: guided self-scheduling (the self-split form of
//! Kruskal & Weiss 1985: each allocation takes `remaining/(2*W)`, W = the
//! active-worker snapshot at allocation time) composed with a rate cap (a
//! single worker's 3s lease `rate_ewma*3s/W`; while the EWMA is
//! unestablished the lease is capped at the block granule — see
//! [`compose_len`]). Shrinking allocation granularity removes the static
//! scheme's fixed-segment tail; a thin-zone whole-block floor stops the
//! shrink from fragmenting tail leases (see [`compose_len`]).
//!
//! Hard invariants: persistence/bookkeeping stay block-aligned while line
//! leases are byte-granular with a sub-block floor (`SUBBLOCK_PER_BLOCK` =
//! block/4, engine-internal, no CLI knob); adjacent leases claim disjoint
//! byte domains; block completion is the sole persistence unit (whole-block
//! watermark test; the single-point decision/fsync discipline in
//! [`crate::coordinator`] is untouched). Block 0 is claimed first at
//! 1-block granularity (file header preview) in both modes. Endgame: when
//! remaining blocks < the worker count ([`in_endgame`]) allocation degrades
//! to single sub-blocks ([`GuidedPlan::pop_single_granule`]) and stealing is
//! rejected by default (the single rejection face lives in
//! [`crate::coordinator`]).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::{BTreeMap, VecDeque};

use crate::error::HttpError;
use crate::grid::{self};
use crate::traits::Extent;

/// Scheduling mode (`--http-scheduler=dynamic|static`).
///
/// `dynamic` (default) = guided self-scheduling + rate composition
/// ([`GuidedPlan`]); `static` = the fixed seg_len plan, kept for
/// comparison and fallback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SchedulerMode {
    /// Dynamic split scheduling (default): guided self-scheduling + rate
    /// composition (allocation face = [`GuidedPlan`]; parameters in
    /// [`GuidedConfig`]).
    #[default]
    Dynamic,
    /// Fixed seg_len static plan (comparison and fallback baseline).
    Static,
}

impl SchedulerMode {
    /// Option text parsing: both `static` and `dynamic` are accepted; an
    /// unknown value is rejected with `taiji.option.invalid` (no truncation,
    /// no fallback — options fail honestly).
    pub fn parse(value: &str) -> Result<Self, HttpError> {
        match value {
            "static" => Ok(SchedulerMode::Static),
            "dynamic" => Ok(SchedulerMode::Dynamic),
            other => Err(HttpError::OptionInvalid {
                option: "--http-scheduler",
                value: format!("{other} (expected static|dynamic)"),
            }),
        }
    }
}

/// Upper bound of the `--split` value range (1..=[`MAX_SPLIT`]). Under
/// `static` scheduling the first wave spawns `--split` workers per source
/// unconditionally ([`crate::pool::WorkerPool::fixed`], emitted directly by
/// `pool.apply(&[], &[])`), so `split` is a task-amplification factor:
/// without an upper bound a million-scale split means a million tasks and
/// `u32::MAX` means 4 billion (OOM / process death). The `dynamic` face is
/// clamped by AIMD at 16 (`AimdConfig::with_start`'s
/// `min(·, max_connections)`) and is unaffected by this bound (`split` only
/// sets the slow-start starting point / initial extent hint). 4096 far
/// exceeds real per-machine connection concurrency (fd/memory limits are
/// far lower) while leaving room for large-split static comparison runs.
///
/// Three consumers share this single constant source (taiji-core references
/// this site): creation/change parsing (taiji-core `parse_split_value`,
/// out-of-range rejected without truncation), the runtime backstop in
/// [`SchedulerConfig::validate`] (replayed poisoned task rows and
/// programmatically built configs bypass the creation-side parse), and
/// replay clamping of persisted concurrency intent (taiji-core
/// `HttpConcurrencyPersist::apply_to` — a poisoned `split=u32::MAX` row
/// persisted before this bound existed would otherwise be replayed as-is on
/// every restart, reproducing the OOM across reboots).
pub const MAX_SPLIT: u32 = 4096;

/// Scheduling config (validated once at task creation, immutable for the
/// task's lifetime — the `block_size` freeze seam lives in
/// [`grid::BlockGrid`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// Scheduling mode (default `dynamic`; `static` kept as fallback. The
    /// dynamic allocation face: [`SchedulerMode::Dynamic`] and [`GuidedPlan`]).
    pub mode: SchedulerMode,
    /// Block granule (`--http-block-size`, default 4MiB; domain validation
    /// in [`grid::validate_block_size`]).
    pub block_size: u64,
    /// Static split target segment count (`--split`, default 5; domain >= 1).
    pub split: u32,
    /// Static split minimum segment length (`--min-split-size`, default 20MiB).
    pub min_split_size: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            mode: SchedulerMode::default(),
            block_size: grid::DEFAULT_BLOCK_SIZE,
            split: 5,
            min_split_size: 20 * 1024 * 1024,
        }
    }
}

impl SchedulerConfig {
    /// Config-domain validation: block granule {power of two, 256KiB..16MiB};
    /// `split` in 1..=[`MAX_SPLIT`] (the upper bound is a runtime backstop —
    /// static's first wave spawns `split` workers per source unconditionally,
    /// so a missing bound is an OOM face; creation-side parsing is the first
    /// gate, replayed poisoned rows / programmatic construction hit this
    /// backstop); `min_split_size` >= the block granule (0 would divide by
    /// zero in `total/min_split_size`; with block-aligned extents a sub-block
    /// minimum segment is unreachable anyway, so the floor is the block
    /// granule). Out-of-range values are rejected, never truncated, with
    /// error code `taiji.option.invalid`.
    pub fn validate(&self) -> Result<(), HttpError> {
        grid::validate_block_size(self.block_size)?;
        if self.split == 0 || self.split > MAX_SPLIT {
            return Err(HttpError::OptionInvalid {
                option: "--split",
                value: format!("{} (expected 1..={MAX_SPLIT})", self.split),
            });
        }
        if self.min_split_size < self.block_size {
            return Err(HttpError::OptionInvalid {
                option: "--min-split-size",
                value: format!(
                    "{} (must be >= block size {})",
                    self.min_split_size, self.block_size
                ),
            });
        }
        Ok(())
    }
}

/// Static allocation queue: block-0 head slot + fixed-segment FIFO; an
/// abandoned extent is recycled to the queue front (failure recycling;
/// stall-steal cancellation semantics belong to dynamic scheduling).
#[derive(Debug, Default)]
pub struct StaticPlan {
    /// Block 0 head slot, claimed first at 1-block granularity; `None` for an empty file.
    head: Option<(u64, Extent)>,
    /// Fixed-segment FIFO (including requeue of recycled extents at the front).
    segments: VecDeque<(u64, Extent)>,
    /// Extent sequence allocator (0-based; runtime identity, never persisted).
    next_seq: u64,
}

impl StaticPlan {
    /// Build the static split plan. `config` must pass
    /// [`SchedulerConfig::validate`] (out-of-range rejected); `total_len` is
    /// the probed authoritative total length (0 = empty file, nothing to
    /// allocate).
    pub fn build(total_len: u64, config: &SchedulerConfig) -> Result<Self, HttpError> {
        config.validate()?;
        let bs = config.block_size;
        let mut plan = StaticPlan::default();

        // Empty or single-block file: the head slot is the whole content.
        if total_len == 0 {
            return Ok(plan);
        }
        if total_len <= bs {
            plan.head = Some((
                plan.take_seq(),
                Extent {
                    start: 0,
                    len: total_len,
                },
            ));
            return Ok(plan);
        }

        // Segment count n = min(split, max(1, total/min-split-size)); segment
        // lengths align down to the block granule (sub-block extents are
        // forbidden). Aligned length 0 or n collapsing to 1 -> single-segment
        // shape (one segment eats the range left after the head slot).
        let n_target = u64::from(config.split).min((total_len / config.min_split_size).max(1));
        let aligned = (total_len / n_target) / bs * bs;
        if n_target <= 1 || aligned == 0 {
            plan.head = Some((plan.take_seq(), Extent { start: 0, len: bs }));
            let seq = plan.take_seq();
            plan.segments.push_back((
                seq,
                Extent {
                    start: bs,
                    len: total_len - bs,
                },
            ));
            return Ok(plan);
        }

        // Head slot first. All segment boundaries are multiples of `aligned`
        // (block-aligned): segment 0 = head remainder [bs, aligned) (empty
        // and skipped when aligned == bs); segment i = [i*aligned,
        // (i+1)*aligned) for i in 1..n-1; the last segment absorbs the
        // remainder: [(n-1)*aligned, total) (alignment excess + partial
        // last block).
        plan.head = Some((plan.take_seq(), Extent { start: 0, len: bs }));
        if bs < aligned {
            let seq = plan.take_seq();
            plan.segments.push_back((
                seq,
                Extent {
                    start: bs,
                    len: aligned - bs,
                },
            ));
        }
        for i in 1..(n_target - 1) {
            let start = i * aligned;
            let seq = plan.take_seq();
            plan.segments.push_back((
                seq,
                Extent {
                    start,
                    len: aligned,
                },
            ));
        }
        let last_start = (n_target - 1) * aligned;
        let seq = plan.take_seq();
        plan.segments.push_back((
            seq,
            Extent {
                start: last_start,
                len: total_len - last_start,
            },
        ));
        Ok(plan)
    }

    fn take_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    /// Next allocatable extent: block 0 first, then fixed segments FIFO.
    /// Returns `None` when exhausted (worker shutdown face).
    pub fn pop_next(&mut self) -> Option<(u64, Extent)> {
        if let Some(head) = self.head.take() {
            return Some(head);
        }
        self.segments.pop_front()
    }

    /// Failure recycling: requeue an unfinished extent at the front (keeping
    /// the original extent sequence number — steal/recycle never renumbers,
    /// keeping `SegId.extent` accounting stable).
    pub fn push_front(&mut self, seq: u64, extent: Extent) {
        self.segments.push_front((seq, extent));
    }

    /// Pending extent count (the block-0 head slot counts as 1).
    pub fn remaining(&self) -> usize {
        usize::from(self.head.is_some()) + self.segments.len()
    }
}

/// Sub-block divisor for line-level leases: the lease floor and alignment
/// clamp are block/4. Engine-internal constant, no CLI knob. The block
/// granule domain floor of 256KiB implies a sub-block floor >= 64KiB.
/// Persistence/accounting granularity is unaffected (still whole blocks).
pub const SUBBLOCK_PER_BLOCK: u64 = 4;

/// Sub-block granule (engine-internal constant = block/4, see
/// [`SUBBLOCK_PER_BLOCK`]). `block` is a power of two (config-domain
/// validation guarantees it), so the division is exact; defensive clamp >= 1.
pub fn sub_block_granule(block: u64) -> u64 {
    (block / SUBBLOCK_PER_BLOCK).max(1)
}

/// Dynamic (guided) scheduling config (line/ledger decoupling).
///
/// Separate from [`SchedulerConfig`]: static's `split`/`min_split_size` are
/// meaningless for guided, and guided's block granule / extent size domain
/// does not enter the static split — exactly one is validated at task
/// creation according to the selected mode, preventing cross-mode parameter
/// misuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuidedConfig {
    /// Block granule (`--http-block-size`, default 4MiB; domain validation
    /// in [`grid::validate_block_size`]; immutable for the task's lifetime).
    /// Persistence/accounting granule — the line-level lease floor is
    /// [`sub_block_granule`] (this granule / 4).
    pub block_size: u64,
    /// Maximum extent size (`--http-max-chunk`, default 32MiB; must be >= the block granule).
    pub max_chunk: u64,
}

impl Default for GuidedConfig {
    fn default() -> Self {
        GuidedConfig {
            block_size: grid::DEFAULT_BLOCK_SIZE,
            max_chunk: 32 * 1024 * 1024,
        }
    }
}

impl GuidedConfig {
    /// Config-domain validation (out-of-range rejected, never truncated,
    /// error code `taiji.option.invalid`): block granule {power of two,
    /// 256KiB..16MiB}; `max_chunk` >= the block granule (an inverted clamp
    /// domain would panic in the allocation face, so it must be rejected at
    /// the config face — lease floor [`sub_block_granule`] <= block granule
    /// <= max-chunk keeps the clamp domain ordered).
    pub fn validate(&self) -> Result<(), HttpError> {
        grid::validate_block_size(self.block_size)?;
        if self.max_chunk < self.block_size {
            return Err(HttpError::OptionInvalid {
                option: "--http-max-chunk",
                value: format!(
                    "{} (must be >= block size {})",
                    self.max_chunk, self.block_size
                ),
            });
        }
        Ok(())
    }
}

/// Rate composition formula (the single formula; line/ledger decoupled):
///
/// ```text
/// guided = remaining/(2*W); clamp guided up to block (thin-zone
/// whole-block floor)
/// raw = min( guided, rate_ewma*3s/W ) // EWMA unestablished -> the rate
/// term is the block granule
/// len = align_down(clamp(raw, sub-block floor, max-chunk), sub-block floor)
/// // sub-block floor = block/4
/// len = min(len, remaining) // final truncation to the remainder
/// (file-tail shape)
/// ```
///
/// - `remaining` = unallocated, unfinished bytes in the pool (guided
/// semantics: each allocation takes 1/(2W) of the remaining work, W =
/// active-worker snapshot at allocation time, including the requester, >=
/// 1 so no division by zero);
/// - the rate term is a **3-second lease for one worker**
/// (`rate_ewma*3s/W`): the concrete form of "never hand out more than
/// ~3s of work". `rate_ewma` is the per-source **aggregate** rate shared
/// by all W workers; sizing one lease at aggregate-rate*3s would
/// over-provision by W and inflate the lease to `W*3s` (48s+ at 16
/// connections) — the pool moves into flight early and idle workers have
/// nothing to claim;
/// - EWMA unestablished (first 10s) or non-positive: the rate term is the
/// **block granule** (the user's explicit download granularity — the
/// engine-side equivalent of fork `min-split-size`). In the cold-start
/// burst all workers' acquires arrive within milliseconds and the W
/// snapshot ramps per request (the first lease sees W=1); pure guided
/// would carve max-chunk-scale giant leases. A block-granule lease lasts
/// seconds; the rate term takes over once the EWMA is established;
/// - **thin-zone whole-block floor**: when the guided share drops below the
/// block granule (iff `remaining < 2W*block` — the predicate is the
/// formula itself: no new constant, invariant to block scale), the guided
/// term is clamped back up to a whole block so tail leases stay
/// whole-block instead of shrinking into fragments (fragmented leases
/// amortize more request rounds per byte and bite back on tail
/// throughput). The floor applies to the guided term **before** the min
/// with the rate term: the rate term's 3s lease-cap semantics survive
/// (slow sources stay capped) and the `max` composition keeps `len`
/// monotone in `remaining` — a floor applied after the clamp would let
/// the lower bound jump with `remaining` at the boundary and break the
/// monotonicity argument. Endgame (remaining blocks < W) does not pass
/// through this formula — the single sub-block arm
/// ([`GuidedPlan::pop_single_granule`]) and the steal decision face never
/// touch it;
/// - **alignment clamp = sub-block floor** (line/ledger decoupling: the
/// engine-internal block/4, no CLI knob). The old "always >= 1 block
/// after alignment" structural floor is gone: once W ramps up, guided
/// shares below the block granule are no longer clamped to whole blocks
/// and leases refine down to sub-blocks (retiring wave quantization —
/// the 16-connection tail wave idling half its workers). Refinement
/// holds only in the thick-pool zone; the thin zone clamps back to whole
/// blocks. The aligned length is always >= 1 sub-block (the clamp floor
/// is the alignment granularity; blocks are whole multiples of
/// sub-blocks, so a whole-block floor stays whole after alignment). The
/// only exception is the `min(len, remaining)` file-tail truncation (the
/// last block may be partial).
fn compose_len(
    remaining: u64,
    active_workers: usize,
    rate_bps: Option<f64>,
    granule: u64,
    max_chunk: u64,
    block: u64,
) -> u64 {
    let w = active_workers.max(1) as u64;
    // Overflow-safe division: floor(floor(r/2)/w) == floor(r/(2w)) (nested
    // integer-division identity) — the literal 2*w wraps at the top of the
    // w domain (usize::MAX); the nested form is identical and has no
    // overflow face.
    let guided = remaining / 2 / w;
    // Thin-zone whole-block floor: when the guided share drops below the
    // block granule (iff remaining < 2W*block), clamp back up to a whole
    // block so tail leases stay whole instead of fragmenting (fragmented
    // leases amortize more request rounds per byte). The floor applies to
    // the guided term before the min with the rate term: the 3s lease-cap
    // semantics for slow sources are preserved and the max composition
    // keeps len monotone in remaining (a floor after the clamp would let
    // the lower bound jump at the boundary). Endgame (remaining blocks < W)
    // never reaches this formula — the single sub-block arm and the steal
    // decision face bypass it.
    let guided = guided.max(block);
    let rate_term = match rate_bps {
        Some(r) if r > 0.0 => ((r * 3.0) as u64 / w).max(1),
        // EWMA unestablished/non-positive -> block-granule lease (see above).
        _ => block,
    };
    let raw = guided.min(rate_term);
    // Clamp domain ordering is guaranteed by GuidedConfig::validate
    // (max_chunk >= block >= granule).
    let clamped = raw.clamp(granule, max_chunk);
    let aligned = (clamped / granule) * granule;
    // The clamp floor is the alignment granularity, so alignment never cuts
    // below 1 sub-block (defensive clamp, same semantics; blocks are whole
    // multiples of sub-blocks, so a whole-block floor stays whole).
    let aligned = aligned.max(granule);
    aligned.min(remaining)
}

/// Endgame predicate (the single criterion): endgame begins when the
/// remaining block count in the pool drops below the task's worker count —
/// once each worker can barely expect one more block, "nothing left to
/// claim" is near, and allocation degrades to single sub-blocks (endgame
/// fragmentation lands in the sub-block domain,
/// [`GuidedPlan::pop_single_granule`]). The coordinator's allocation arms
/// and the endgame metric simulation share this predicate (same criterion,
/// preventing drift); `workers` is clamped >= 1 (a single-worker task has
/// no endgame face — the pool empties outright).
pub(crate) fn in_endgame(pool_remaining_blocks: u64, workers: usize) -> bool {
    pool_remaining_blocks < workers.max(1) as u64
}

/// Dynamic (guided) allocation plan: a byte-granular free pool carved by the
/// composition formula (line/ledger decoupled — pool and leases live in the
/// byte domain; persisted accounting stays block-aligned).
///
/// # Pool model
///
/// The pool is the set of unfinished, unallocated byte intervals
/// (`BTreeMap<start byte, byte len>`, address-ordered — allocation starts
/// at the lowest address so the download front advances in order; adjacent
/// intervals merge). During resume, blocks completed in the bitmap
/// naturally form holes; [`GuidedPlan::build`] removes them via the
/// `is_done` predicate (holes are removed whole-block — no half-block data
/// exists on disk), and extents never span a hole. `remaining` (the
/// formula's remainder) is the exact byte sum of the pool, O(1).
///
/// Interval boundary domain: splits align to [`sub_block_granule`] (the
/// composition formula's alignment clamp), except for a partial file-tail
/// block; failure recycling restarts at the real written-byte watermark
/// (the coordinator ledger), keeping domains disjoint.
///
/// # Difference from the static plan
///
/// Static failure recycling requeues the original extent at the front (same
/// sequence number); guided recycling returns the **unwritten byte domain**
/// to the pool ([`GuidedPlan::restore_extent`], dropping whole blocks the
/// grid marks done) and re-splits with a new sequence number — extent
/// sequence numbers promise only runtime uniqueness, not stability across
/// recycling (byte coordinates are authoritative for sink write tracking).
///
/// # Endgame allocation face
///
/// Regular allocation goes through [`GuidedPlan::pop_next`] (composition
/// formula). When the remaining block count drops below the worker count,
/// the caller (the coordinator's endgame arm) switches to
/// [`GuidedPlan::pop_single_granule`] — single sub-block granularity,
/// bypassing the formula (endgame fragmentation lands in the sub-block
/// domain: every worker can always claim work; tail waves never idle). Both
/// faces share the same pool model, block-0 priority, and recycling
/// semantics.
#[derive(Debug)]
pub struct GuidedPlan {
    block: u64,
    /// Line-level lease floor = sub-block granule (engine-internal block/4,
    /// fixed once at build time).
    granule: u64,
    max_chunk: u64,
    total_len: u64,
    /// Block 0 head slot at 1-block granularity, claimed first; `None` if block 0 is done (resume).
    head: Option<(u64, Extent)>,
    /// Free byte intervals (start byte -> byte length; never adjacent — adjacent intervals merge).
    free: BTreeMap<u64, u64>,
    /// Exact byte sum remaining in the pool (the formula's `remaining`; a
    /// partial last block counts at its real size).
    remaining_bytes: u64,
    next_seq: u64,
}

impl GuidedPlan {
    /// Build the guided plan. `config` must pass [`GuidedConfig::validate`];
    /// `is_done` is the resume-bitmap predicate (`true` = block complete,
    /// not pooled — removed whole-block, the pool side of crash recovery's
    /// "a half-written block is re-downloaded whole"); `total_len` is the
    /// probed authoritative total length (0 = empty file, nothing to
    /// allocate). The build makes one linear pass over the block count
    /// (resume-bitmap holes); runtime allocate/recycle are O(log n).
    pub fn build(
        total_len: u64,
        config: &GuidedConfig,
        is_done: &(dyn Fn(u64) -> bool + Send + Sync),
    ) -> Result<Self, HttpError> {
        config.validate()?;
        let block = config.block_size;
        let block_count = total_len.div_ceil(block);
        let mut next_seq = 0u64;
        let head = if block_count > 0 && !is_done(0) {
            let seq = next_seq;
            next_seq += 1;
            Some((
                seq,
                Extent {
                    start: 0,
                    len: block.min(total_len),
                },
            ))
        } else {
            None
        };

        let mut free = BTreeMap::new();
        // Remaining bytes include the unclaimed head slot (all unfinished, unallocated work).
        let mut remaining_bytes = head.as_ref().map_or(0, |(_, e)| e.len);
        // Merge adjacent unfinished blocks into byte intervals (whole-block
        // holes removed); skip block 0 while the head slot carries it.
        let mut run_start: Option<u64> = None;
        for b in 0..block_count {
            let in_pool = !is_done(b) && !(b == 0 && head.is_some());
            if in_pool {
                if run_start.is_none() {
                    run_start = Some(b * block);
                }
                let start = b * block;
                remaining_bytes += block.min(total_len - start);
            } else if let Some(s) = run_start.take() {
                let end = (b * block).min(total_len);
                free.insert(s, end - s);
            }
        }
        if let Some(s) = run_start {
            free.insert(s, total_len - s);
        }

        Ok(GuidedPlan {
            block,
            granule: sub_block_granule(block),
            max_chunk: config.max_chunk,
            total_len,
            head,
            free,
            remaining_bytes,
            next_seq,
        })
    }

    /// Bytes remaining in the pool (the formula's `remaining`; all
    /// unfinished, unallocated work, including the unclaimed head slot).
    pub fn remaining_bytes(&self) -> u64 {
        self.remaining_bytes
    }

    /// Remaining block count in the pool (input to the endgame predicate,
    /// [`in_endgame`]): remaining bytes rounded up to blocks — exact for
    /// whole-block pools; fragmented pools count by byte share (a partial
    /// block always counts 1).
    pub fn remaining_blocks(&self) -> u64 {
        self.remaining_bytes.div_ceil(self.block)
    }

    /// Next extent (`active_workers` = active-worker snapshot at allocation
    /// time, including the requester; `rate_bps` = the requesting source's
    /// rate EWMA, `None` = unestablished -> pure guided). Block 0 first;
    /// `None` when the pool is empty (worker shutdown face).
    pub fn pop_next(
        &mut self,
        active_workers: usize,
        rate_bps: Option<f64>,
    ) -> Option<(u64, Extent)> {
        self.pop_len(self.next_len(active_workers, rate_bps))
    }

    /// The composition formula's output length for the **current pool
    /// state** (query only, does not consume the pool). Weighted-share
    /// arbitration computes the formula value first, clamps by share, and
    /// carves once via [`Self::pop_len`] — arbitration never rewrites
    /// formula semantics.
    pub fn next_len(&self, active_workers: usize, rate_bps: Option<f64>) -> u64 {
        compose_len(
            self.remaining_bytes,
            active_workers,
            rate_bps,
            self.granule,
            self.max_chunk,
            self.block,
        )
    }

    /// Allocate the next extent of the given byte length (block 0 first;
    /// length truncated to interval/pool remainder by [`carve_front`]). The
    /// caller (the coordinator's weighted arm) passes a share-arbitrated,
    /// clamped length; [`Self::pop_next`] is `pop_len(next_len(..))`.
    pub fn pop_len(&mut self, want: u64) -> Option<(u64, Extent)> {
        if let Some(head) = self.head.take() {
            self.remaining_bytes = self.remaining_bytes.saturating_sub(head.1.len);
            return Some((head.0, head.1));
        }
        self.carve_front(want)
    }

    /// Granularity floor for a single allocation (the line-level lease
    /// sub-block floor = block/4): the lower clamp for
    /// weighted-share-arbitrated lengths.
    pub fn min_granule(&self) -> u64 {
        self.granule
    }

    /// Endgame allocation: **single sub-block granularity**, bypassing the
    /// composition formula — near the end the pool holds less work than
    /// there are workers, and "few but fragmented" (each sub-block
    /// independently claimable, done when claimed) beats "few but large"
    /// (whole-block granularity would reintroduce wave quantization into
    /// the tail). Block-0 priority and pool model match
    /// [`GuidedPlan::pop_next`]; `None` when the pool is empty.
    pub fn pop_single_granule(&mut self) -> Option<(u64, Extent)> {
        if let Some(head) = self.head.take() {
            self.remaining_bytes = self.remaining_bytes.saturating_sub(head.1.len);
            return Some((head.0, head.1));
        }
        self.carve_front(self.granule)
    }

    /// Carve at most `want` bytes from the lowest-addressed free interval
    /// (sub-block aligned; a partial file-tail block is allowed). `want` is
    /// already aligned/clamped by the caller; this layer only truncates to
    /// the interval and pool remainder and maintains the pool structure.
    fn carve_front(&mut self, want: u64) -> Option<(u64, Extent)> {
        if self.remaining_bytes == 0 {
            return None; // invariant: free and remaining bytes empty together (defensive re-entry after drain)
        }
        let (&start, &len) = self.free.iter().next()?;
        let range_end = (start + len).min(self.total_len);

        // want is sub-block aligned; truncate to interval/pool remainder (partial tail allowed).
        let carve = want.min(range_end - start).min(self.remaining_bytes);
        debug_assert!(carve > 0, "an non-empty pool must carve a non-empty extent");

        self.free.remove(&start);
        if carve < len {
            self.free.insert(start + carve, len - carve);
        }
        self.remaining_bytes -= carve;

        let seq = self.next_seq;
        self.next_seq += 1;
        Some((seq, Extent { start, len: carve }))
    }

    /// Failure recycling: return the extent's **unwritten** byte domain to
    /// the pool (adjacent intervals merge; whole blocks the grid marks done
    /// are excluded as the single source of truth — progress is recorded
    /// once). Recycling starts at the real written-byte watermark from the
    /// coordinator ledger (a contiguous written prefix after the extent
    /// start is not recycled); re-splitting assigns a new sequence number
    /// (see the type doc). Done-block exclusion is trimmed on whole-block
    /// boundaries (no half-accounted block exists inside the recycled
    /// domain — the block is the sole persistence unit).
    pub fn restore_extent(
        &mut self,
        extent: &Extent,
        is_done: &(dyn Fn(u64) -> bool + Send + Sync),
    ) {
        if extent.is_empty() || self.total_len == 0 {
            return;
        }
        // Defensive clamping: the public API does not assume an in-bounds
        // extent (a saturated end must not spin a giant loop).
        let lo = extent.start.min(self.total_len);
        let hi = extent.end().min(self.total_len);
        if lo >= hi {
            return;
        }
        let first = lo / self.block;
        let last = (hi - 1) / self.block;
        // Scan block by block, pooling unaccounted blocks' byte domains
        // (trimmed to [lo, hi)) as segments.
        let mut seg_start: Option<u64> = None;
        for b in first..=last {
            let b_start = b * self.block;
            let b_end = (b_start + self.block).min(self.total_len);
            if is_done(b) {
                if let Some(s) = seg_start.take() {
                    self.insert_free_range(s, b_start.min(hi));
                }
                continue;
            }
            let seg_lo = b_start.max(lo);
            let seg_hi = b_end.min(hi);
            if seg_lo >= seg_hi {
                continue;
            }
            if seg_start.is_none() {
                seg_start = Some(seg_lo);
            }
        }
        if let Some(s) = seg_start {
            self.insert_free_range(s, hi);
        }
    }

    /// Return a byte interval to the pool + merge adjacent intervals
    /// (predecessor tail / successor head). Only this segment's bytes are
    /// added to the remaining count (merged neighbors are already accounted;
    /// adding them again would double-count).
    fn insert_free_range(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        self.remaining_bytes += end - start;
        let mut lo = start;
        let mut hi = end;
        if let Some((&pred_start, &pred_len)) = self.free.range(..start).next_back()
            && pred_start + pred_len >= start
        {
            lo = lo.min(pred_start);
            hi = hi.max(pred_start + pred_len);
            self.free.remove(&pred_start);
        }
        // Successor merge: absorb every interval touching/overlapping
        // [lo, hi) (keys ordered; absorb consecutive runs from lo).
        while let Some((&succ_start, &succ_len)) = self.free.range(lo..).next()
            && succ_start <= hi
        {
            hi = hi.max(succ_start + succ_len);
            self.free.remove(&succ_start);
        }
        self.free.insert(lo, hi - lo);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grid::MIN_BLOCK_SIZE;

    /// Config-domain out-of-range rejection across mode/block_size/split.
    #[test]
    fn scheduler_config_domain_rejects() {
        // Valid defaults pass.
        let ok = SchedulerConfig::default();
        ok.validate()
            .unwrap_or_else(|e| panic!("default config: {e}"));

        // Block granule out of domain (delegates to grid validation, same error code).
        let bad = SchedulerConfig {
            block_size: 3 * 1024 * 1024,
            ..SchedulerConfig::default()
        };
        assert!(matches!(
            bad.validate(),
            Err(HttpError::OptionInvalid {
                option: "--http-block-size",
                ..
            })
        ));

        // split = 0 rejected (not truncated to 1).
        let bad = SchedulerConfig {
            split: 0,
            ..SchedulerConfig::default()
        };
        assert!(matches!(
            bad.validate(),
            Err(HttpError::OptionInvalid {
                option: "--split",
                ..
            })
        ));

        // Mode parsing: static/dynamic accepted; unknown values rejected.
        assert_eq!(SchedulerMode::parse("static"), Ok(SchedulerMode::Static));
        assert_eq!(SchedulerMode::parse("dynamic"), Ok(SchedulerMode::Dynamic));
        assert!(SchedulerMode::parse("guided").is_err());
        assert!(SchedulerMode::parse("").is_err());
        assert!(
            SchedulerMode::parse("STATIC").is_err(),
            "rejected except for the lowercase surface"
        );
    }

    /// `--split` runtime backstop upper bound (1..=4096; out of range
    /// rejected with `taiji.option.invalid`, no truncation). Static's first
    /// wave spawns `split` workers per source unconditionally
    /// ([`crate::pool::WorkerPool::fixed`]) — split is a task-amplification
    /// factor, and u32::MAX-scale values mean billions of tasks (OOM).
    /// Creation-side parsing (taiji-core `parse_split_value`) is the first
    /// gate; this validation is the runtime backstop for replayed poisoned
    /// rows and programmatically built `SchedulerConfig`s that bypass it —
    /// the value domain must still hold (4096 is pinned to
    /// [`super::MAX_SPLIT`]; revisit this assertion when the constant
    /// changes).
    #[test]
    fn split_domain_caps_at_upper_bound_runtime_backstop() {
        // Exactly at the bound: accepted.
        let cap = SchedulerConfig {
            split: 4096,
            ..SchedulerConfig::default()
        };
        cap.validate()
            .unwrap_or_else(|e| panic!("split=4096 at the bound must be accepted: {e}"));

        // One past the bound: rejected (no truncation).
        let over = SchedulerConfig {
            split: 4097,
            ..SchedulerConfig::default()
        };
        match over.validate() {
            Err(HttpError::OptionInvalid { option, value }) => {
                assert_eq!(option, "--split");
                assert!(
                    value.contains("4097"),
                    "payload carries the rejected original value: {value}"
                );
            }
            other => {
                panic!("split=4097 past the bound must be rejected (no truncation), got {other:?}")
            }
        }

        // Poisoned-row shape (a u32::MAX persisted before the bound existed)
        // rejected by the same gate.
        let poison = SchedulerConfig {
            split: u32::MAX,
            ..SchedulerConfig::default()
        };
        assert!(
            matches!(poison.validate(), Err(HttpError::OptionInvalid { .. })),
            "the poisoned split=u32::MAX row must be rejected by the runtime backstop"
        );
    }

    /// `--min-split-size` domain floor: `min_split_size = 0` would divide by
    /// zero in `total / min_split_size` — validate rejects it out of domain.
    /// The floor is the block granule: with block-aligned extents a
    /// sub-block minimum segment is unreachable anyway, closing the semantic
    /// and divide-by-zero faces together.
    #[test]
    fn min_split_size_domain_floor() {
        // Direct hit on the defect shape: with min_split_size = 0, build
        // must return Err, not panic on division by zero.
        let zero = SchedulerConfig {
            min_split_size: 0,
            ..SchedulerConfig::default()
        };
        match zero.validate() {
            Err(HttpError::OptionInvalid { option, value }) => {
                assert_eq!(option, "--min-split-size");
                assert!(
                    value.contains('0'),
                    "payload carries the rejected original value: {value}"
                );
            }
            other => panic!("min-split 0 must be rejected, got {other:?}"),
        }
        assert!(StaticPlan::build(100 * 1024 * 1024, &zero).is_err());

        // Floor neighbors: exactly the block granule is legal; below it is rejected.
        let bs = MIN_BLOCK_SIZE;
        let exact = SchedulerConfig {
            block_size: bs,
            min_split_size: bs,
            ..SchedulerConfig::default()
        };
        assert!(exact.validate().is_ok());
        let below = SchedulerConfig {
            block_size: bs,
            min_split_size: bs / 2,
            ..SchedulerConfig::default()
        };
        assert!(below.validate().is_err());
        assert!(StaticPlan::build(10 * bs, &below).is_err());
    }

    /// Static split algebra: segments cover completely without overlap and
    /// are block-aligned (the last segment may hold a partial block); block
    /// 0 is a separate head slot claimed first at 1-block granularity.
    #[test]
    fn static_plan_covers_grid_exactly() {
        let bs = MIN_BLOCK_SIZE;
        // 10 blocks total, split=4 -> 4 aligned segments + head slot.
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 4,
            min_split_size: bs,
            ..SchedulerConfig::default()
        };
        let total = 10 * bs;
        let mut plan = StaticPlan::build(total, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        assert_eq!(plan.remaining(), 1 + 4, "head slot + 4 segments");

        let head = plan.pop_next().unwrap_or_else(|| panic!("head"));
        assert_eq!(
            head.1,
            Extent { start: 0, len: bs },
            "the head block claims 1-block granularity first"
        );

        let mut covered: Vec<(u64, u64)> = Vec::new();
        while let Some((_, ext)) = plan.pop_next() {
            assert_eq!(ext.start % bs, 0, "segment starts are block-aligned");
            assert!(ext.end() <= total);
            covered.push((ext.start, ext.end()));
        }
        // No overlap + full coverage of [bs, total).
        covered.sort_unstable();
        let mut cursor = bs;
        for (s, e) in covered {
            assert_eq!(
                s, cursor,
                "segments join seamlessly with no gaps or overlap"
            );
            cursor = e;
        }
        assert_eq!(cursor, total, "coverage reaches the total length");

        // pop = None once exhausted.
        let mut plan = StaticPlan::build(total, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        for _ in 0..5 {
            assert!(plan.pop_next().is_some());
        }
        assert!(plan.pop_next().is_none(), "None once drained");
    }

    /// Boundary shapes: empty / single-block / aligned collapse to one
    /// segment / huge split clamped.
    #[test]
    fn static_plan_boundary_shapes() {
        let bs = MIN_BLOCK_SIZE;

        // Empty file: nothing allocatable.
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 8,
            ..SchedulerConfig::default()
        };
        let mut plan = StaticPlan::build(0, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        assert_eq!(plan.remaining(), 0);
        assert!(
            plan.pop_next().is_none(),
            "an empty file has nothing to allocate"
        );

        // Single-block file (total <= block): the head slot is the whole content.
        let mut plan = StaticPlan::build(bs - 7, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        assert_eq!(plan.remaining(), 1);
        let (_, only) = plan.pop_next().unwrap_or_else(|| panic!("head"));
        assert_eq!(
            only,
            Extent {
                start: 0,
                len: bs - 7
            },
            "single-block file's priority face = the whole content"
        );

        // total < n * block: aligned length 0 -> collapse to one segment
        // (head + one remainder segment).
        let tiny = SchedulerConfig {
            block_size: bs,
            split: 16,
            min_split_size: bs,
            ..SchedulerConfig::default()
        };
        let mut plan = StaticPlan::build(2 * bs + 5, &tiny).unwrap_or_else(|e| panic!("plan: {e}"));
        assert!(
            plan.remaining() <= 2,
            "the aligned shrink collapses to the single-segment shape"
        );
        let mut seen = Vec::new();
        while let Some((_, ext)) = plan.pop_next() {
            seen.push(ext);
        }
        assert_eq!(seen.first().copied(), Some(Extent { start: 0, len: bs }));
        let rest: u64 = seen.iter().skip(1).map(|e| e.len).sum();
        let rest_start = seen.first().map(|e| e.len).unwrap_or(0);
        assert_eq!(
            rest,
            2 * bs + 5 - rest_start,
            "one segment consumes the whole remaining interval"
        );

        // Huge split but min-split-size raises the effective segment floor:
        // the count is clamped by total/min-split-size (aria2 static split
        // semantics).
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 1024,
            min_split_size: 4 * bs,
            ..SchedulerConfig::default()
        };
        let mut plan = StaticPlan::build(10 * bs, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        // Head + segments (n = min(1024, 10/4=2) = 2).
        let mut count = 0;
        while plan.pop_next().is_some() {
            count += 1;
        }
        assert_eq!(
            count,
            1 + 2,
            "the segment count is clamped by min-split-size"
        );

        // Failure recycling: the abandoned extent is requeued at the front
        // with its original sequence number.
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 4,
            min_split_size: bs,
            ..SchedulerConfig::default()
        };
        let mut plan = StaticPlan::build(10 * bs, &cfg).unwrap_or_else(|e| panic!("plan: {e}"));
        let first = plan.pop_next().unwrap_or_else(|| panic!("head"));
        let second = plan.pop_next().unwrap_or_else(|| panic!("seg0"));
        plan.push_front(second.0, second.1);
        let again = plan.pop_next().unwrap_or_else(|| panic!("requeue"));
        assert_eq!(
            again.0, second.0,
            "recycling keeps the original extent sequence number"
        );
        assert_eq!(again.1, second.1);
        let _ = first;
    }

    // ---------------- dynamic (guided + rate composition) ----------------

    /// Decision table for the composition formula at small numbers:
    /// compose_len is unit-independent, so block=4, granule=1 (= block/4,
    /// the sub-block floor) and max=32 give transparent arithmetic, pinned
    /// cell by cell. Rate term = a single worker's 3s lease rate*3s/W; EWMA
    /// unestablished = block-granule lease; alignment clamp = the sub-block
    /// floor; a guided share below the block granule hits the thin-zone
    /// whole-block floor — refinement holds only in the thick-pool zone
    /// (see [`composition_thin_zone_floor_decision_table`]).
    #[test]
    fn composition_formula_decision_table() {
        use super::compose_len;
        let (b, g, mx) = (4u64, 1u64, 32u64);

        // No EWMA -> block-granule lease (4 < max; >= the sub-block floor 1 -> exactly 4).
        let none: Option<f64> = None;
        assert_eq!(
            compose_len(1000, 1, none, g, mx, b),
            4,
            "A: large pool W=1 -> block-granule lease (the cold-start lease bound)"
        );
        assert_eq!(
            compose_len(1000, 4, none, g, mx, b),
            4,
            "B: W=4 is the same lease bound"
        );
        // EWMA present -> the rate term dominates (rate*3/W = 3 is inside
        // the domain — the floor is 1 — so it carves directly).
        assert_eq!(
            compose_len(1000, 4, Some(4.0), g, mx, b),
            3,
            "C: rate×3/W=3 carves inside the domain (single-worker 3s lease conversion)"
        );
        // W=1: rate*3/1 = 12 inside the domain (a single worker is the whole aggregate).
        assert_eq!(
            compose_len(1000, 1, Some(4.0), g, mx, b),
            12,
            "C1: W=1 → min(guided, rate×3)"
        );
        // Rate term below the sub-block floor -> the clamp lifts it (even an
        // extremely slow source claims at least one sub-block).
        assert_eq!(
            compose_len(1000, 1, Some(0.2), g, mx, b),
            1,
            "D: rate×3=0.6 -> lifted to the sub-block floor 1"
        );
        // Rate term above the cap -> the clamp caps it.
        assert_eq!(
            compose_len(1000, 1, Some(100.0), g, mx, b),
            32,
            "E: rate×3=300 > max → 32"
        );
        // Intersection of the guided and rate terms: equal values take the intersection.
        assert_eq!(
            compose_len(24, 1, Some(4.0), g, mx, b),
            12,
            "F: intersection"
        );
        // rate = 0 / negative -> same as EWMA unestablished (block-granule
        // lease; zero/sign defense).
        assert_eq!(
            compose_len(1000, 1, Some(0.0), g, mx, b),
            4,
            "G1: rate=0 -> block-granule lease"
        );
        assert_eq!(
            compose_len(1000, 1, Some(-3.0), g, mx, b),
            4,
            "G2: rate<0 -> block-granule lease"
        );

        // remaining/W boundary (no EWMA, rate term = block 4; thin-zone
        // floor: guided below the block granule -> whole-block lease, no
        // sub-block refinement — the tail does not fragment; the file tail
        // is truncated once by min(·, remaining)).
        assert_eq!(
            compose_len(8, 1, none, g, mx, b),
            4,
            "H1: remaining=2W×b -> exactly 1 block (outside the boundary, the normal domain)"
        );
        assert_eq!(
            compose_len(7, 1, none, g, mx, b),
            4,
            "H2: guided=3 < block -> thin-zone whole-block floor 4 \
             (no shrinking into a 3-sub-block carve)"
        );
        assert_eq!(
            compose_len(1000, 16, none, g, mx, b),
            4,
            "H2a: deep pool with large W -> the block-granule lease bound is visible"
        );
        assert_eq!(
            compose_len(4, 1, none, g, mx, b),
            4,
            "H3: remaining=1 block -> the whole-block floor exactly exhausts \
             the pool (no half-pool sub-block carve)"
        );
        assert_eq!(
            compose_len(3, 1, none, g, mx, b),
            3,
            "H4: the thin-zone floor is tail-truncated by min(·,remaining) \
             -> one carve of the whole remainder"
        );
        assert_eq!(
            compose_len(3, 5, none, g, mx, b),
            3,
            "H5: large W, guided=0 -> whole-block floor then tail-truncated to 3 \
             (the progress-keeping fallback)"
        );
        // W defense: 0 (no division by zero) is equivalent to 1.
        assert_eq!(
            compose_len(1000, 0, none, g, mx, b),
            4,
            "I: W=0 clamps to 1 -> the lease bound"
        );
        // Alignment (sub-block granularity): only visible when raw lands
        // inside (granule, max) — the rate term in-domain shape (W=1,
        // rate=4 -> 12; guided 13 -> min takes 12, exactly aligned).
        assert_eq!(
            compose_len(26, 1, Some(4.0), g, mx, b),
            12,
            "J1: sub-block alignment does not give back"
        );
        assert_eq!(
            compose_len(26, 4, Some(4.0), g, mx, b),
            3,
            "J2: rate×3/4=3 in-domain + sub-block alignment"
        );
        assert_eq!(
            compose_len(1000, 4, Some(1.5), g, mx, b),
            1,
            "J3: rate×3/4=1.125 -> align_down to 1 sub-block"
        );
        // remaining = 0 -> 0 (callers drain empty pools first; the formula defends itself).
        assert_eq!(compose_len(0, 1, none, g, mx, b), 0, "L: empty pool");
    }

    /// Decision table at true block scale (MIN_BLOCK_SIZE tier): the rate
    /// term and guided term composed over the real config domain (sub-block
    /// floor = block/4, max-chunk = 8 blocks).
    #[test]
    fn composition_formula_decision_table_grid_scale() {
        use super::compose_len;
        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs);
        let none: Option<f64> = None;
        let mx = 8 * bs;

        // Large pool, EWMA unestablished -> block-granule lease (user
        // download granularity, the cold-start lease bound).
        let big = 64 * bs;
        assert_eq!(
            compose_len(big, 1, none, g, mx, bs),
            bs,
            "the lease bound = block granularity"
        );
        assert_eq!(
            compose_len(big, 4, none, g, mx, bs),
            bs,
            "W=4 is the same lease bound"
        );

        // EWMA established: the rate term = rate*3s/W (a single worker's 3s
        // lease). 1MiB/s * 3s = 3MiB = 12 blocks -> capped at max (8
        // blocks) for W=1.
        let rate = Some(1024.0 * 1024.0);
        assert_eq!(
            compose_len(64 * bs, 1, rate, g, mx, bs),
            8 * bs,
            "max caps after the rate term dominates"
        );
        // 512KiB/s * 3s = 1.5MiB = 6 blocks < max (W=1 equals the aggregate).
        assert_eq!(
            compose_len(64 * bs, 1, Some(512.0 * 1024.0), g, mx, bs),
            6 * bs,
            "rate×3 dominates inside the domain"
        );
        assert_eq!(
            compose_len(64 * bs, 1, Some(300_000.0), g, mx, bs),
            13 * bs / 4,
            "900_000B floors down to the sub-block granule (3.25 blocks, r7.0)"
        );
        // W scaling: 4 workers share the aggregate rate -> one worker's
        // lease = rate*3/4. 2MiB/s * 3s / 4 = 1.5MiB = 6 blocks.
        assert_eq!(
            compose_len(64 * bs, 4, Some(2.0 * 1024.0 * 1024.0), g, mx, bs),
            6 * bs,
            "rate×3/W: single-worker lease conversion"
        );
        // Rate so fast the lease cap is meaningless -> guided dominates
        // (W=2: guided = 4bs/4 = bs).
        assert_eq!(
            compose_len(4 * bs, 2, Some(1024.0 * 1024.0 * 1024.0), g, mx, bs),
            bs,
            "guided=bs < rate×3/W -> take guided"
        );
        // Thin-zone floor cell: at W=64, guided = 64bs/128 = half a block <
        // block -> whole-block floor (no half-block sub-block carving —
        // tail leases stay whole).
        assert_eq!(
            compose_len(64 * bs, 64, Some(1024.0 * 1024.0 * 1024.0), g, mx, bs),
            bs,
            "W=64 -> thin-zone whole-block floor \
             (guided half-block falls below block, clamped back to whole)"
        );
        assert_eq!(
            compose_len(bs / 2, 64, Some(1024.0 * 1024.0 * 1024.0), g, mx, bs),
            bs / 2,
            "deep tail remaining=half block -> the whole-block floor is \
             tail-truncated to half a block (one truncation)"
        );
    }

    /// Formula monotonicity: for fixed W and rate, len is non-decreasing in
    /// remaining (guided term / rate term / clamp / alignment / tail
    /// truncation are all monotone composites). Exhaustive per-byte at
    /// small numbers + coarse grid-scale sampling.
    #[test]
    fn composition_len_monotone_in_remaining() {
        use super::compose_len;
        // Exhaustive per-byte at small numbers (transparent b=4/g=1/mx=32 arithmetic).
        for w in 1..=6usize {
            for rate in [None, Some(1.0), Some(16.0)] {
                let mut prev = 0u64;
                for remaining in 0..=1000u64 {
                    let len = compose_len(remaining, w, rate, 1, 32, 4);
                    assert!(
                        len >= prev,
                        "len must be non-decreasing in remaining: w={w} rate={rate:?} r={remaining}"
                    );
                    prev = len;
                }
            }
        }
        // Coarse sampling at grid scale (MIN_BLOCK_SIZE tier, sub-block step).
        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs);
        for w in [1usize, 3, 8, 64] {
            for rate in [None, Some(256.0 * 1024.0), Some(4.0 * 1024.0 * 1024.0)] {
                let mut prev = 0u64;
                for remaining in (0..=(48 * bs)).step_by(g as usize) {
                    let len = compose_len(remaining, w, rate, g, 8 * bs, bs);
                    assert!(
                        len >= prev,
                        "len must be non-decreasing in remaining: w={w} rate={rate:?} r={remaining}"
                    );
                    prev = len;
                }
            }
        }
    }

    /// Thin-zone lease floor decision table (tail optimization): when the
    /// guided share drops below the block granule (iff remaining < 2W*block),
    /// compose yields a whole-block lease — tail leases never fragment.
    /// Pinned: exactly-at-boundary 2W*block on both sides, the shrink
    /// path's single file-tail truncation, the rate term's 3s lease cap
    /// preserved (the floor does not override it), and division overflow
    /// defense (W at its domain cap / maximal pool depth neither panic nor
    /// wrap).
    #[test]
    fn composition_thin_zone_floor_decision_table() {
        use super::compose_len;
        let (b, g, mx) = (4u64, 1u64, 32u64);
        let none: Option<f64> = None;

        // Exactly at the boundary (remaining = 2W*block iff guided = block):
        // outside is the normal domain (W=3 -> boundary 24; W=2 -> 16).
        assert_eq!(
            compose_len(24, 3, none, g, mx, b),
            4,
            "T1: W=3 exactly at 2W×b, outside the boundary -> guided=block, the normal 1 block"
        );
        assert_eq!(
            compose_len(16, 2, none, g, mx, b),
            4,
            "T2: W=2 exactly at the boundary, outside -> the normal 1 block"
        );
        // One step inside the boundary: guided = block-1 -> the floor
        // applies, still whole-block (continuous with the outside;
        // previously this cell carved 3 sub-blocks, the start of the tail
        // shrink path).
        assert_eq!(
            compose_len(23, 3, none, g, mx, b),
            4,
            "T3: W=3 inside the boundary, guided=block-1 -> the whole-block floor (continuous)"
        );
        assert_eq!(
            compose_len(15, 2, none, g, mx, b),
            4,
            "T4: W=2 inside the boundary -> the whole-block floor"
        );
        // The rate term's 3s lease cap is preserved: when rate_term < block
        // the floor acts on the guided term and the min defers to the rate
        // term — slow sources stay within the 3s bound, continuous on both
        // sides.
        let slow = Some(2.0); // rate*3/W = 6/2 = 3 < block
        assert_eq!(
            compose_len(16, 2, slow, g, mx, b),
            3,
            "T5: outside the boundary the rate term dominates at 3 (the normal domain)"
        );
        assert_eq!(
            compose_len(15, 2, slow, g, mx, b),
            3,
            "T6: inside the boundary the rate term still dominates \
             — the floor never crosses the 3s lease bound"
        );
        // Shrink-path truncation (no EWMA): after the floor the tail pool no
        // longer shrinks stepwise; the only contraction is the single
        // file-tail truncation by min(·, remaining).
        assert_eq!(
            compose_len(2, 1, none, g, mx, b),
            2,
            "T7: tail 2 sub-blocks -> one truncation of the whole remainder \
             (no further sub-block shrinking)"
        );
        assert_eq!(
            compose_len(1, 1, none, g, mx, b),
            1,
            "T8: tail 1 sub-block -> truncated to the remainder (the floor backstop)"
        );
        // Division overflow defense: W=usize::MAX (a literal 2*w would wrap)
        // and a u64::MAX pool neither panic nor wrap into giant leases; an
        // f64::MAX rate term saturates in conversion and converges via
        // min/floor.
        assert_eq!(
            compose_len(u64::MAX, usize::MAX, none, g, mx, b),
            4,
            "T9: W=usize::MAX -> the nested integer-division identity \
             guards against wrap -> the whole-block floor"
        );
        assert_eq!(
            compose_len(u64::MAX, usize::MAX, Some(f64::MAX), g, mx, b),
            1,
            "T10: the rate term f64::MAX saturates at the u64::MAX ÷ W domain cap \
             -> 1 sub-block (no panic in the division chain)"
        );
    }

    /// Thin-zone floor handover to endgame, and static unaffected: the
    /// regular arm issues whole-block leases throughout the thin zone until
    /// the endgame predicate takes over (remaining blocks < W -> the single
    /// sub-block arm); both faces share the pool seamlessly and drain to
    /// None. Static mode is untouched — fixed split and the dynamic floor
    /// share no code path; the same file's split shape is pinned segment by
    /// segment.
    #[test]
    fn thin_zone_floor_hands_over_to_endgame_and_static_unaffected() {
        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs);
        let workers = 2usize;

        // dynamic: 8-block pool, 2 workers, pure guided. The regular arm's
        // leases stay whole-block (including the thin zone: with 3/2 blocks
        // left, guided is below the block granule and the floor clamps back
        // to a whole block) until 1 block remains (< W) and the endgame
        // predicate takes over.
        let total = 8 * bs;
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 8 * bs,
        };
        let mut plan =
            GuidedPlan::build(total, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));
        let (_, head) = plan.pop_next(1, None).unwrap_or_else(|| panic!("head"));
        assert_eq!(head.len, bs, "the head special case goes first");
        let mut regular = Vec::new();
        while !super::in_endgame(plan.remaining_blocks(), workers) {
            let (_, ext) = plan
                .pop_next(workers, None)
                .unwrap_or_else(|| panic!("the regular arm must drain before endgame"));
            assert_eq!(
                ext.start % g,
                0,
                "lease starts are sub-block aligned \
                 (the floor does not change alignment semantics): {:?}",
                ext
            );
            assert_eq!(
                ext.len, bs,
                "regular-arm leases in the thin zone stay whole blocks: {:?}",
                ext
            );
            regular.push(ext.len);
        }
        assert_eq!(
            regular.len(),
            6,
            "6 regular-arm carves after head (blocks 7..=2 remain)"
        );
        assert_eq!(
            plan.remaining_blocks(),
            1,
            "the handover happens exactly at the endgame boundary (< 2 blocks)"
        );
        // Endgame arm: single sub-blocks claimed one by one until the pool empties.
        let mut singles = 0;
        while let Some((_, ext)) = plan.pop_single_granule() {
            assert!(
                ext.len <= g,
                "endgame allocations are single sub-blocks: {ext:?}"
            );
            singles += 1;
        }
        assert_eq!(
            singles, 4,
            "the last block's 4 sub-blocks are claimed one by one"
        );
        assert!(
            plan.pop_next(1, None).is_none(),
            "both faces share one pool; drained to None"
        );

        // static: the same file's fixed split is untouched by the dynamic
        // floor (independent code path; split algebra pinned — split=4,
        // min-split=2 blocks -> 4 segments).
        let scfg = SchedulerConfig {
            block_size: bs,
            split: 4,
            min_split_size: 2 * bs,
            ..SchedulerConfig::default()
        };
        let mut splan = StaticPlan::build(total, &scfg).unwrap_or_else(|e| panic!("static: {e}"));
        assert_eq!(
            splan.remaining(),
            1 + 4,
            "head slot alone + 4 segments (the segment count is independent of the dynamic floor)"
        );
        let (_, sh) = splan.pop_next().unwrap_or_else(|| panic!("static head"));
        assert_eq!(sh.len, bs, "the head block is 1 block");
        let seg_lens: Vec<u64> = (0..4)
            .map(|_| splan.pop_next().unwrap_or_else(|| panic!("seg")).1.len)
            .collect();
        let aligned = (total / 4) / bs * bs; // 2 blocks per segment (block-aligned split)
        assert_eq!(
            seg_lens,
            vec![aligned - bs, aligned, aligned, total - 3 * aligned],
            "static segment lengths = the fixed split algebra (no thin-zone floor shape)"
        );
        assert_eq!(
            SchedulerMode::parse("static"),
            Ok(SchedulerMode::Static),
            "the static-mode parse surface is undisturbed"
        );
    }

    /// Guided plan algebraic properties: random pools x random W/rate
    /// sequences x random abandon-and-recycle — allocations completely cover
    /// and only cover unfinished bytes, never overlap, start sub-block
    /// aligned, are non-empty, and terminate (None shutdown); recycling
    /// never yields duplicate allocations. Line/ledger decoupling: leases
    /// are byte domains (sub-block granularity); overlap/coverage
    /// assertions are bookkept as byte intervals.
    #[test]
    fn guided_plan_partition_no_starvation_property() {
        /// Deterministic RNG (xorshift64; random combinations are reproducible).
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

        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs);
        let mut rng = Rng(0x6755_6465_6431_3637);
        for round in 0..64 {
            let blocks = 1 + rng.below(48);
            let partial = rng.below(2) == 0;
            let total = if partial {
                blocks * bs - rng.below(bs).max(1)
            } else {
                blocks * bs
            };
            // Random resume bitmap (including block 0 done -> no head slot).
            let mut done = std::collections::BTreeSet::new();
            for b in 0..blocks {
                if rng.below(10) < 3 {
                    done.insert(b);
                }
            }
            let is_done = |b: u64| done.contains(&b);
            let max_chunk = bs << rng.below(4);
            let cfg = GuidedConfig {
                block_size: bs,
                max_chunk,
            };
            let mut plan = GuidedPlan::build(total, &cfg, &is_done)
                .unwrap_or_else(|e| panic!("round {round}: {e}"));

            // Reference pool: total bytes of unfinished blocks.
            let want_remaining: u64 = (0..blocks)
                .filter(|b| !done.contains(b))
                .map(|b| {
                    let start = b * bs;
                    bs.min(total - start)
                })
                .sum();
            assert_eq!(
                plan.remaining_bytes(),
                want_remaining,
                "round {round}: pool bytes are exact"
            );

            // In-flight byte interval ledger (ordered; allocation checks
            // overlap, recycling removes).
            let mut claimed: Vec<(u64, u64)> = Vec::new();
            let mut outstanding: Vec<(u64, Extent)> = Vec::new();
            let mut restores = 0u64;
            for step in 0..4000u64 {
                // Random W (including the 0 defense) and rates (mostly pure guided).
                let w = rng.below(6) as usize;
                let rate = if rng.below(4) == 0 {
                    Some((bs * (1 + rng.below(8))) as f64)
                } else {
                    None
                };
                match plan.pop_next(w, rate) {
                    Some((seq, ext)) => {
                        assert!(
                            !ext.is_empty(),
                            "round {round} step {step}: non-empty allocation"
                        );
                        assert_eq!(
                            ext.start % g,
                            0,
                            "round {round} step {step}: start sub-block aligned"
                        );
                        assert!(ext.end() <= total, "round {round} step {step}: in bounds");
                        // Only unfinished byte domains are claimed (checked block by block).
                        let mut cursor = ext.start;
                        while cursor < ext.end() {
                            let b = cursor / bs;
                            assert!(
                                !done.contains(&b),
                                "round {round}: must not claim completed block {b}"
                            );
                            cursor = ((b + 1) * bs).min(ext.end());
                        }
                        // No overlap at byte level (in-flight intervals pairwise disjoint).
                        let idx = claimed.partition_point(|(_, e)| *e <= ext.start);
                        assert!(
                            idx == claimed.len() || claimed[idx].0 >= ext.end(),
                            "round {round} step {step}: byte-interval overlap {ext:?} vs {:?}",
                            claimed.get(idx)
                        );
                        claimed.insert(idx, (ext.start, ext.end()));
                        outstanding.push((seq, ext));
                        // Randomly abandon the latest lease (re-claiming
                        // after recycling must not duplicate; the budget cap
                        // keeps the convergence phase pure allocation — a
                        // strictly decreasing remainder must terminate).
                        if rng.below(5) == 0 && restores < 8 {
                            restores += 1;
                            if let Some((_, ext)) = outstanding.pop() {
                                let idx = claimed
                                    .iter()
                                    .position(|(s, e)| *s == ext.start && *e == ext.end())
                                    .unwrap_or_else(|| {
                                        panic!(
                                            "round {round}: the recycled interval \
                                             is not on the ledger"
                                        )
                                    });
                                claimed.remove(idx);
                                plan.restore_extent(&ext, &is_done);
                            }
                        }
                    }
                    None => break,
                }
            }
            // Termination: pool drained (no starvation, no zero-length loops);
            // outstanding bytes are exactly the unfinished domain.
            assert!(
                plan.pop_next(1, None).is_none(),
                "round {round}: None after drain"
            );
            let got_bytes: u64 = outstanding.iter().map(|(_, e)| e.len).sum();
            assert_eq!(got_bytes, want_remaining, "round {round}: bytes conserved");
            let mut covered: Vec<(u64, u64)> = outstanding
                .iter()
                .map(|(_, e)| (e.start, e.end()))
                .collect();
            covered.sort_unstable();
            for w2 in covered.windows(2) {
                assert!(
                    w2[0].1 <= w2[1].0,
                    "round {round}: final-state byte overlap"
                );
            }
            // Coverage is exactly the byte union of unfinished blocks
            // (checked per block, including the partial last block).
            for b in 0..blocks {
                let s = b * bs;
                let e = s + bs.min(total - s);
                let cov: u64 = covered
                    .iter()
                    .filter(|(cs, ce)| *cs < e && *ce > s)
                    .map(|(cs, ce)| (*ce).min(e) - (*cs).max(s))
                    .sum();
                let want = u64::from(!done.contains(&b)) * (e - s);
                assert_eq!(cov, want, "round {round}: block {b} coverage domain");
            }
            let got_bytes: u64 = outstanding.iter().map(|(_, e)| e.len).sum();
            assert_eq!(got_bytes, want_remaining, "round {round}: bytes conserved");
        }
    }

    /// Guided monotone shrink sequence: fixed W=1, pure guided, no
    /// recycling — successive allocation lengths after the head slot are
    /// non-increasing (guidance shrinks with the remainder — a structural
    /// anti-long-tail property; the 1-block head is a priority special case,
    /// excluded from the sequence comparison).
    #[test]
    fn guided_pop_sequence_is_nonincreasing() {
        let bs = MIN_BLOCK_SIZE;
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 8 * bs,
        };
        let blocks = 64u64;
        let mut plan = GuidedPlan::build(blocks * bs, &cfg, &|_| false)
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let (_, head) = plan.pop_next(1, None).unwrap_or_else(|| panic!("head"));
        assert_eq!(head.len, bs, "the head special case is consumed first");
        let mut prev = u64::MAX;
        let mut count = 0;
        while let Some((_, ext)) = plan.pop_next(1, None) {
            let l = ext.len;
            assert!(
                l <= prev,
                "allocation lengths must be non-increasing: {l} > {prev}"
            );
            prev = l;
            count += 1;
        }
        assert!(
            count >= 8,
            "a 64-block pool should carve enough slices at W=1: {count}"
        );
    }

    /// Head priority and resume holes: block 0 unfinished -> the first
    /// allocation is exactly 1 block; bitmap-completed blocks (including
    /// block 0) never enter the pool; extents never span holes.
    #[test]
    fn guided_head_priority_and_resume_holes() {
        let bs = MIN_BLOCK_SIZE;
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 4 * bs,
        };

        // Cold start: the head is claimed first at 1 block, then from block 1.
        let mut plan =
            GuidedPlan::build(16 * bs, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));
        let (seq0, head) = plan.pop_next(1, None).unwrap_or_else(|| panic!("head"));
        assert_eq!(
            (head.start, head.len),
            (0, bs),
            "the head block claims 1-block granularity first"
        );
        let (_, second) = plan.pop_next(1, None).unwrap_or_else(|| panic!("second"));
        assert_eq!(
            second.start, bs,
            "allocation starts from block 1 after the head"
        );
        let _ = seq0;

        // Resume: block 0 done -> no head; mid-file holes (blocks 5..8) stay out of the pool.
        let done: std::collections::BTreeSet<u64> = [0, 5, 6, 7].into_iter().collect();
        let mut plan = GuidedPlan::build(16 * bs, &cfg, &|b| done.contains(&b))
            .unwrap_or_else(|e| panic!("plan: {e}"));
        let want = 16 * bs - bs /*b0*/ - 3 * bs /*b5..7*/;
        assert_eq!(
            plan.remaining_bytes(),
            want,
            "the pool excludes completed blocks"
        );
        while let Some((_, ext)) = plan.pop_next(4, None) {
            let first = ext.start / bs;
            let last = (ext.end() - 1) / bs;
            for b in first..=last {
                assert!(
                    !done.contains(&b),
                    "hole blocks must not appear in any extent: {b}"
                );
            }
            assert!(
                last < 5 || first >= 8,
                "extents must not span the resume hole [5..7]: {ext:?}"
            );
        }

        // All complete (full resume bitmap): nothing to allocate.
        let mut plan =
            GuidedPlan::build(16 * bs, &cfg, &|_| true).unwrap_or_else(|e| panic!("plan: {e}"));
        assert_eq!(plan.remaining_bytes(), 0);
        assert!(
            plan.pop_next(1, None).is_none(),
            "a fully-complete pool drains to None"
        );
    }

    /// Rate term taking effect at the plan level (decision table through to
    /// allocation): same pool — an EWMA-established slow source splits
    /// finer than pure guided (the rate cap dominates); an EWMA-less source
    /// stays pure guided. Recycling restores only unfinished blocks.
    #[test]
    fn guided_rate_term_and_restore_undone_only() {
        let bs = MIN_BLOCK_SIZE;
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 32 * bs,
        };
        let blocks = 64u64;
        let total = blocks * bs;

        // EWMA unestablished (block-granule lease): the first slice after
        // the head = 1 block (cold-start lease bound, user download
        // granularity — the engine-side equivalent of fork min-split-size).
        let mut pure =
            GuidedPlan::build(total, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));
        let (_, head) = pure.pop_next(1, None).unwrap_or_else(|| panic!("head"));
        assert_eq!(head.len, bs);
        let (_, big) = pure.pop_next(1, None).unwrap_or_else(|| panic!("guided"));
        assert_eq!(big.len, bs, "EWMA unestablished -> block-granule lease");

        // Slow source (256KiB/s * 3s = 3 blocks, W=1): 3 blocks at the same
        // position (the rate lease dominates).
        let mut slow =
            GuidedPlan::build(total, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));
        let _ = slow.pop_next(1, None);
        let (_, capped) = slow
            .pop_next(1, Some(bs as f64))
            .unwrap_or_else(|| panic!("rate"));
        assert_eq!(capped.len, 3 * bs, "rate×3/W dominates (3 blocks)");

        // W effect (EWMA established): at W=2 the rate lease scales to
        // rate*3/2 = 3 blocks, min'd against guided (~15bs) — the
        // single-worker lease dominates; the second slice shrinks with the
        // remainder (non-increasing at fixed W).
        let mut many =
            GuidedPlan::build(total, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));
        let _ = many.pop_next(1, None);
        let (a, ea) = many
            .pop_next(2, Some((2 * bs) as f64))
            .unwrap_or_else(|| panic!("w2"));
        let (b, eb) = many
            .pop_next(2, Some((2 * bs) as f64))
            .unwrap_or_else(|| panic!("w2b"));
        assert!(a < b, "extent sequence numbers increase with allocations");
        assert_eq!(
            ea.len,
            3 * bs,
            "W=2 first slice = min(guided 15bs, rate×3/2 = 3bs)"
        );
        assert!(
            eb.len <= ea.len,
            "the sequence is non-increasing at fixed W"
        );

        // Recycling: claim a 1-block slice -> mark done -> abandon ->
        // re-claim restores only unfinished blocks (progress recorded once;
        // recycling trusts the grid's truth).
        let done = std::sync::Mutex::new(std::collections::BTreeSet::new());
        let mut plan = GuidedPlan::build(8 * bs, &cfg, &|b| {
            done.lock().map(|d| d.contains(&b)).unwrap_or(false)
        })
        .unwrap_or_else(|e| panic!("plan: {e}"));
        let _ = plan.pop_next(1, None); // head (block 0)
        let (_, ext) = plan.pop_next(1, None).unwrap_or_else(|| panic!("w"));
        assert_eq!(ext.start, bs, "carving starts after the head");
        let first = ext.start / bs;
        let done_blocks = 1u64;
        {
            let mut d = done.lock().unwrap_or_else(|e| panic!("done set: {e}"));
            for b in first..first + done_blocks {
                d.insert(b);
            }
        }
        plan.restore_extent(&ext, &|b| {
            done.lock().map(|d| d.contains(&b)).unwrap_or(false)
        });
        let mut recarved: Vec<Extent> = Vec::new();
        while let Some((_, e)) = plan.pop_next(1, None) {
            recarved.push(e);
        }
        let covered: std::collections::BTreeSet<u64> = recarved
            .iter()
            .flat_map(|e| {
                let f = e.start / bs;
                let l = (e.end() - 1) / bs;
                f..=l
            })
            .collect();
        assert!(
            !covered.contains(&first),
            "decided blocks are not recycled for re-carving"
        );
        assert_eq!(
            covered.len(),
            8 - 1 - done_blocks as usize,
            "all remaining blocks are recycled"
        );
    }

    /// Guided config domain validation: the block granule delegates to grid
    /// validation; max-chunk below the block granule is rejected — an
    /// inverted clamp domain ([sub-block floor, max-chunk]) must be
    /// rejected at the config face.
    #[test]
    fn guided_config_domain_rejects() {
        let ok = GuidedConfig::default();
        ok.validate().unwrap_or_else(|e| panic!("default: {e}"));

        // Block granule out of domain (delegates to grid validation).
        let bad = GuidedConfig {
            block_size: 3 * 1024 * 1024,
            ..GuidedConfig::default()
        };
        assert!(matches!(
            bad.validate(),
            Err(HttpError::OptionInvalid {
                option: "--http-block-size",
                ..
            })
        ));

        // max-chunk < block granule (inverted clamp domain — the ordering
        // lease floor = block/4 <= block granule <= max-chunk is guaranteed
        // at the config face).
        let inverted = GuidedConfig {
            block_size: 4 * 1024 * 1024,
            max_chunk: 4 * 1024 * 1024 - 1,
        };
        match inverted.validate() {
            Err(HttpError::OptionInvalid { option, value }) => {
                assert_eq!(option, "--http-max-chunk");
                assert!(value.contains("must be >= block size"), "{value}");
            }
            other => panic!("inverted clamp domain must be rejected, got {other:?}"),
        }
        // Exactly the block granule is legal (the min-chunk knob has
        // collapsed into the engine-internal sub-block constant; only
        // max-chunk >= block remains at the config face).
        let exact = GuidedConfig {
            block_size: 4 * 1024 * 1024,
            max_chunk: 4 * 1024 * 1024,
        };
        exact
            .validate()
            .unwrap_or_else(|e| panic!("exact floor must be accepted: {e}"));
    }

    // ---------------- endgame degradation ----------------

    /// Endgame predicate boundary: remaining blocks < workers triggers
    /// endgame (equality does not); workers clamped >= 1 (0 defends as one
    /// worker — endgame only when the pool is empty; no division or
    /// negative-overflow face).
    #[test]
    fn endgame_predicate_boundary() {
        use super::in_endgame;
        assert!(!in_endgame(4, 4), "equality does not trigger endgame");
        assert!(in_endgame(3, 4), "below the worker count triggers endgame");
        assert!(!in_endgame(5, 4));
        assert!(
            in_endgame(0, 1),
            "single worker + empty pool triggers endgame (the theoretical close-out face)"
        );
        assert!(!in_endgame(1, 1));
        assert!(
            in_endgame(0, 0),
            "workers=0 clamps to 1: endgame on an empty pool"
        );
        assert!(
            !in_endgame(1, 0),
            "workers=0 clamps to 1: a non-empty pool does not trigger endgame"
        );
        assert!(
            in_endgame(u64::MAX - 1, usize::MAX),
            "no wrap in the large domain"
        );
    }

    /// Pool remaining-block bookkeeping: head counts 1, a partial last
    /// block counts 1, allocation decrements, recycling increments.
    #[test]
    fn remaining_blocks_tracks_pool() {
        let bs = MIN_BLOCK_SIZE;
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 8 * bs,
        };
        // 10 whole blocks + unclaimed head -> 10.
        let mut plan =
            GuidedPlan::build(10 * bs, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));
        assert_eq!(plan.remaining_blocks(), 10);

        // head claimed -> 9; a 1-block lease claimed -> 8.
        let _ = plan.pop_next(1, None);
        assert_eq!(
            plan.remaining_blocks(),
            9,
            "decrements after the head is consumed"
        );
        let (_, ext) = plan.pop_next(1, None).unwrap_or_else(|| panic!("ext"));
        assert_eq!(
            ext.len, bs,
            "EWMA unestablished -> block-granule lease (1 block)"
        );
        assert_eq!(plan.remaining_blocks(), 8);

        // Recycling: the unfinished slice returns -> 9 (with interval merging).
        plan.restore_extent(&ext, &|_| false);
        assert_eq!(
            plan.remaining_blocks(),
            9,
            "unfinished blocks count back into the pool"
        );

        // Resume holes: bitmap-completed blocks excluded.
        let done: std::collections::BTreeSet<u64> = [0, 3, 9].into_iter().collect();
        let plan = GuidedPlan::build(10 * bs, &cfg, &|b| done.contains(&b))
            .unwrap_or_else(|e| panic!("plan: {e}"));
        assert_eq!(plan.remaining_blocks(), 7, "3 completed blocks excluded");
    }

    /// Endgame allocation face: single sub-block granularity bypasses the
    /// composition formula (the essential difference from regular
    /// allocation — endgame fragmentation lands in the sub-block domain); a
    /// partial file-tail block is served at its real size; exhaustion
    /// returns None; the two faces never overlap (both carve the same pool,
    /// covering exactly once).
    #[test]
    fn pop_single_granule_serves_endgame_without_quantization() {
        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs);
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 8 * bs,
        };
        // 9 blocks - 100B: partial last block.
        let total = 9 * bs - 100;
        let mut plan =
            GuidedPlan::build(total, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));

        // Regular face (control): after head, remaining 8bs, W=1 -> guided
        // 4bs -> rate term (EWMA unestablished) = block lease bs -> bs.
        let (_, head) = plan.pop_next(1, None).unwrap_or_else(|| panic!("head"));
        assert_eq!(head.len, bs, "the head special case goes first (1 block)");
        let (_, regular) = plan.pop_next(1, None).unwrap_or_else(|| panic!("reg"));
        assert_eq!(
            regular.len, bs,
            "the regular face's cold-start lease bound = block granularity"
        );

        // Endgame face: single sub-blocks claimed one by one, the last
        // block with partial bytes, exhaustion returns None (endgame
        // fragmentation lands in the sub-block domain — 9 blocks of work x
        // 16 workers can finish in one wave; no more 2-wave block-granularity
        // floor).
        let mut singles = Vec::new();
        while let Some((_, ext)) = plan.pop_single_granule() {
            assert_eq!(ext.start % g, 0, "sub-block aligned");
            assert!(
                ext.len <= g,
                "endgame allocations must not exceed 1 sub-block"
            );
            singles.push(ext);
        }
        assert_eq!(
            singles.len(),
            28,
            "the remaining 7 blocks = 28 sub-blocks claimed one by one"
        );
        for ext in &singles[..27] {
            assert_eq!(
                ext.len, g,
                "whole sub-blocks are always 1 sub-block granule"
            );
        }
        // Last block = [8bs, 9bs-100): after 27 whole sub-blocks the real
        // tail is (bs-100) mod g bytes (g divides bs, so the final piece is
        // that modulus).
        let tail = (bs - 100) % g;
        assert_eq!(
            singles.last().map(|e| e.len),
            Some(if tail == 0 { g } else { tail }),
            "the last piece follows the real size (a partial last block's tail piece)"
        );
        assert_eq!(
            singles.last().map(|e| e.end()),
            Some(total),
            "the last piece is truncated to the total length"
        );
        assert!(
            plan.pop_next(1, None).is_none(),
            "both faces share one pool; drained to None"
        );
    }

    /// Endgame full-load sampling metric: with 10 equally spaced samples in
    /// the last 10% of progress, active workers = min(workers, remaining)
    /// holds for >= 9 samples; no sampling at remaining=0; remaining counts
    /// **sub-blocks** — endgame allocates single sub-blocks, so a
    /// block-granularity reading would misjudge sub-block full load as
    /// overload. The mock slow tail serves the last 10% of blocks at 10x
    /// cost (bandwidth /10).
    ///
    /// A deterministic event simulation drives the **real** [`GuidedPlan`]
    /// with the coordinator's own endgame predicate ([`in_endgame`]): a
    /// worker-pull model — a sub-block completes and settles, and an
    /// exhausted extent re-acquires immediately (acquisition latency is
    /// negligible next to transfer; the metric measures scheduling load,
    /// not message latency). Samples fire when completed progress crosses
    /// a remaining threshold (90%..99% equally spaced). Same assertions:
    /// every endgame-window allocation is a single sub-block and the grid
    /// has no double coverage.
    #[test]
    fn endgame_full_load_sampling_metric() {
        use super::in_endgame;

        const WORKERS: usize = 4;
        const BLOCKS: u64 = 500;
        /// Slow-tail start (the last 10% of blocks).
        const TAIL_FROM: u64 = 450;
        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs); // = bs/4
        const SUBS_PER_BLOCK: u64 = 4;
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 8 * bs,
        };
        let total = BLOCKS * bs;
        let mut plan =
            GuidedPlan::build(total, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));
        // Mock slow tail: the last 10% of blocks at 1/10 bandwidth (10x
        // cost; a sub-block inherits its block's cost).
        let cost = |gr: u64| {
            if gr / SUBS_PER_BLOCK >= TAIL_FROM {
                10
            } else {
                1
            }
        };

        struct Worker {
            /// In-flight extent (cursor_sub..=last_sub, sub-block coordinates).
            holding: Option<(u64, u64)>,
            /// Completion time of the next sub-block.
            free_at: u64,
            done: bool,
        }
        // Start: all workers acquire concurrently (acquisitions settle in
        // index order — deterministically isomorphic to single-point FIFO
        // message processing).
        let mut workers: Vec<Worker> = (0..WORKERS)
            .map(|_| Worker {
                holding: None,
                free_at: 0,
                done: false,
            })
            .collect();
        let total_subs = BLOCKS * SUBS_PER_BLOCK;
        let mut completed = 0u64;
        let mut claimed = std::collections::BTreeMap::<u64, u64>::new(); // sub-block -> seq
        let mut endgame_allocs = 0u64;

        // Sampling thresholds: remaining in {200,190,...,110} (90%..99%
        // equally spaced; no sampling at 0; sub-block scale).
        let targets: Vec<u64> = (0..10u64).map(|i| 200 - 10 * i).collect();
        let mut next_target = 0usize;
        let mut samples: Vec<(u64, usize)> = Vec::new(); // (remaining, active)

        // Acquisition settle (shared by the start phase and extent
        // exhaustion; returns whether work was claimed).
        let acquire = |i: usize,
                       ws: &[Worker],
                       plan: &mut GuidedPlan,
                       claimed: &mut std::collections::BTreeMap<u64, u64>,
                       endgame_allocs: &mut u64|
         -> Option<(u64, u64)> {
            let holders = ws
                .iter()
                .enumerate()
                .filter(|(j, w)| *j != i && w.holding.is_some())
                .count();
            let w_snap = holders + 1;
            let endgame = in_endgame(plan.remaining_blocks(), WORKERS);
            let alloc = if endgame {
                plan.pop_single_granule()
            } else {
                plan.pop_next(w_snap, None)
            };
            let (seq, ext) = alloc?;
            if endgame {
                *endgame_allocs += 1;
                assert!(
                    ext.len <= g,
                    "endgame allocations must be single sub-blocks: {ext:?}"
                );
            }
            let first = ext.start / g;
            let last = (ext.end() / g).saturating_sub(1);
            for gr in first..=last {
                assert!(
                    claimed.insert(gr, seq).is_none(),
                    "sub-block {gr} allocated twice"
                );
            }
            Some((first, last))
        };

        // Event loop: advance to the earliest event (none = all done);
        // same-instant events settle in index order (a deterministic FIFO
        // isomorph).
        while let Some(t) = workers.iter().filter(|w| !w.done).map(|w| w.free_at).min() {
            for i in 0..WORKERS {
                if workers[i].done || workers[i].free_at != t {
                    continue;
                }
                match workers[i].holding {
                    Some((cursor, last)) => {
                        // Sub-block completes (settle).
                        completed += 1;
                        if cursor < last {
                            // Continue with the next sub-block inside the extent.
                            workers[i].holding = Some((cursor + 1, last));
                            workers[i].free_at = t + cost(cursor + 1);
                        } else {
                            // Extent exhausted -> re-acquire immediately
                            // (pull model: acquisition latency is
                            // negligible, settles the same instant).
                            if let Some((first, last)) =
                                acquire(i, &workers, &mut plan, &mut claimed, &mut endgame_allocs)
                            {
                                workers[i].holding = Some((first, last));
                                workers[i].free_at = t + cost(first);
                            } else {
                                workers[i].holding = None;
                                workers[i].done = true;
                            }
                        }
                    }
                    None => {
                        // Start-phase acquisition.
                        if let Some((first, last)) =
                            acquire(i, &workers, &mut plan, &mut claimed, &mut endgame_allocs)
                        {
                            workers[i].holding = Some((first, last));
                            workers[i].free_at = t + cost(first);
                        } else {
                            workers[i].done = true;
                        }
                    }
                }
                // Sample when progress crosses a threshold (exactly once each).
                let remaining = total_subs - completed;
                if next_target < targets.len() && remaining <= targets[next_target] {
                    let active = workers.iter().filter(|w| w.holding.is_some()).count();
                    samples.push((remaining, active));
                    next_target += 1;
                }
            }
        }

        // The whole grid is covered exactly once and the endgame face actually fires.
        assert_eq!(
            claimed.len() as u64,
            total_subs,
            "the allocation face must cover the whole grid exactly once"
        );
        assert!(
            endgame_allocs > 0,
            "the endgame window must actually trigger sub-block allocations"
        );

        // Metric: >= 9 of 10 samples at full load (active = min(workers, remaining)).
        assert_eq!(samples.len(), 10, "exactly 10 samples pinned: {samples:?}");
        let loaded = samples
            .iter()
            .filter(|(rem, active)| *active == WORKERS.min(*rem as usize))
            .count();
        assert!(
            loaded >= 9,
            "endgame full load <9/10: {samples:?} (loaded={loaded})"
        );
    }

    /// Single-wave completion: 24MiB x 16 connections finishes in one wave.
    /// Whole-block-aligned leases quantized waves: 24 blocks / 16
    /// connections = 16 first-wave leases + a tail wave of 8 — half the
    /// workers idle in the tail wave (8 blocks of work < 16 workers; the
    /// endgame whole-block arm would only replay the quantization), a
    /// structural floor of ~2x ideal makespan. With the sub-block floor
    /// (block/4), the tail refines by sub-blocks — **while the pool is
    /// non-empty every acquire gets a non-empty lease** (no idling), all
    /// workers finish in one wave, makespan <= 1.05x ideal.
    ///
    /// A deterministic event simulation drives the **real** [`GuidedPlan`]
    /// with the coordinator's own endgame predicate/arms ([`in_endgame`] +
    /// the regular formula + endgame single sub-blocks). Rates: 256KiB/s
    /// per connection; the time unit is one 4KiB transfer (ideal makespan
    /// = 24MiB / (16x256KiB/s) = 384 units).
    #[test]
    fn single_wave_completion_24mib_16_connections() {
        use super::in_endgame;

        const BLOCKS: u64 = 24; // 24 x 1MiB = 24MiB
        const WORKERS: usize = 16;
        /// Per-connection rate (4KiB per time unit = 256KiB/s).
        const RATE: u64 = 4;

        let bs = 1024 * 1024u64;
        let g = super::sub_block_granule(bs);
        let total = BLOCKS * bs;
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 32 * 1024 * 1024,
        };
        let mut plan =
            GuidedPlan::build(total, &cfg, &|_| false).unwrap_or_else(|e| panic!("plan: {e}"));

        struct Worker {
            /// Remaining lease bytes in flight.
            holding: u64,
            /// Completion time of this lease.
            free_at: u64,
            done: bool,
        }
        let mut workers: Vec<Worker> = (0..WORKERS)
            .map(|_| Worker {
                holding: 0,
                free_at: 0,
                done: false,
            })
            .collect();

        // Acquisition arm (same as the coordinator): endgame -> single
        // sub-block; regular -> the composition formula.
        let acquire = |i: usize, workers: &[Worker], plan: &mut GuidedPlan| -> Option<u64> {
            let active = workers.iter().filter(|w| w.holding > 0).count();
            let w_snap = active + 1;
            let endgame = in_endgame(plan.remaining_blocks(), WORKERS);
            let alloc = if endgame {
                plan.pop_single_granule()
            } else {
                plan.pop_next(w_snap, None)
            };
            let (_, ext) = alloc?;
            // Core assertion: a non-empty pool implies a non-empty lease (no wave idling).
            assert!(ext.len > 0, "worker {i}: a non-empty pool must yield work");
            Some(ext.len)
        };

        // Start: all 16 workers acquire at the same instant (the W snapshot ramps 1..=16).
        let mut t = 0u64;
        let mut leased_total = 0u64;
        for i in 0..WORKERS {
            let len = acquire(i, &workers, &mut plan).unwrap_or_else(|| {
                panic!(
                    "worker {i}: the starting pool {}/{} is non-empty and must yield work",
                    plan.remaining_bytes(),
                    total
                )
            });
            leased_total += len;
            workers[i].holding = len;
            workers[i].free_at = t + len / RATE;
        }

        // Event loop: a completed lease settles and re-acquires immediately (pull model).
        let mut makespan = 0u64;
        while let Some(now) = workers.iter().filter(|w| !w.done).map(|w| w.free_at).min() {
            t = now;
            for i in 0..WORKERS {
                if workers[i].done || workers[i].free_at != t {
                    continue;
                }
                workers[i].holding = 0;
                match acquire(i, &workers, &mut plan) {
                    Some(len) => {
                        leased_total += len;
                        workers[i].holding = len;
                        workers[i].free_at = t + len / RATE;
                    }
                    None => {
                        // A worker may finish only when the pool is empty.
                        assert_eq!(
                            plan.remaining_bytes(),
                            0,
                            "worker {i}: pool remainder {} is non-empty; \
                             no work available is wave idling",
                            plan.remaining_bytes()
                        );
                        workers[i].done = true;
                    }
                }
            }
            makespan = t;
        }

        // Three one-wave assertions: byte conservation, full participation, makespan near ideal.
        assert_eq!(leased_total, total, "lease bytes conserved");
        assert!(
            workers.iter().all(|w| w.holding == 0),
            "all 16 workers closed out"
        );
        let ideal = total / RATE / WORKERS as u64; // = 384
        assert!(
            makespan <= ideal + ideal / 20,
            "makespan {makespan} must be <= 1.05x the ideal {ideal} (wave-quantization residue)"
        );
        let _ = (g, makespan);
    }

    /// Crash recovery: a sub-block lease interrupted in flight (process
    /// crash — no abandon, no watermark recorded) rebuilds the recovery
    /// pool from the bitmap. **No half-block data exists**: unaccounted
    /// blocks return to the pool whole, and re-download restarts from the
    /// block start (the written sub-block prefix is not resumed — matching
    /// the established crash-recovery semantics).
    #[test]
    fn crash_recovery_sub_block_inflight_redownloads_whole_block() {
        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs);
        let total = 4 * bs;

        // First pass (real allocation algebra): block 0 accounted (head
        // done), W=1 pure guided carves a **sub-block-crossing lease**
        // [bs, bs+1.5bs) (all of block 1 + the front half of block 2 — a
        // line-level lease shape only expressible with byte-granular
        // leases).
        let done0: std::collections::BTreeSet<u64> = [0].into_iter().collect();
        let cfg = GuidedConfig {
            block_size: bs,
            max_chunk: 8 * bs,
        };
        let mut plan = GuidedPlan::build(total, &cfg, &|b| done0.contains(&b))
            .unwrap_or_else(|e| panic!("plan: {e}"));
        // Rate lease term >= guided (0.5bs/s * 3s = 1.5bs) -> the lease length follows guided.
        let (_, lease) = plan
            .pop_next(1, Some(bs as f64 * 0.5))
            .unwrap_or_else(|| panic!("lease"));
        assert_eq!(
            lease,
            crate::traits::Extent {
                start: bs,
                len: 3 * bs / 2
            },
            "a sub-block-crossing lease (all of block 1 + the front half of block 2)"
        );

        // Crash: the process vanishes — no abandon, no heartbeat, zero
        // bitmap progress (block 1 has only 1 sub-block on disk; the
        // half-block state must not be accounted). Recovery rebuilds the
        // pool from the bitmap.
        let bitmap_done = |b: u64| b == 0; // only block 0 (half-blocks not accounted)
        let mut recovered = GuidedPlan::build(total, &cfg, &bitmap_done)
            .unwrap_or_else(|e| panic!("recovered: {e}"));
        assert_eq!(
            recovered.remaining_bytes(),
            3 * bs,
            "the recovery pool = all unaccounted bytes (half blocks count as whole)"
        );

        // Re-download: the new lease starts whole at block 1's **start**
        // (the written sub-block prefix is not resumed — crash-recovery
        // semantics unchanged).
        let (_, retry) = recovered
            .pop_next(1, None)
            .unwrap_or_else(|| panic!("retry"));
        assert_eq!(
            retry.start, bs,
            "whole-block re-download starts at block 1's start"
        );
        assert!(
            retry.len >= bs,
            "the re-download lease covers whole blocks (>= 1 block)"
        );
        assert!(
            retry.start / bs == (retry.end() - 1) / bs || retry.len >= 2 * bs,
            "the first block re-downloads completely"
        );
        let _ = g;
    }

    /// Long-tail elimination: with a slow-tail server fixture (the last
    /// 70% of content at 1/10 bandwidth), the "last 10% of content" time
    /// share — dynamic guided < **15%**; the static control (`split=16`,
    /// `min-split-size=20M`, same fixture, same worker count) > **40%**.
    ///
    /// A deterministic event simulation drives the **real** [`GuidedPlan`]
    /// and [`StaticPlan`] (the same [`in_endgame`] endgame predicate;
    /// endgame single-sub-block degradation applies to the dynamic pool —
    /// dynamic work units are sub-blocks, each inheriting its block's
    /// cost). The worker-pull model matches
    /// [`endgame_full_load_sampling_metric`]; the metric is the share of
    /// T between the moment content reaches 90% completion (t90) and the
    /// final completion time T.
    #[test]
    fn long_tail_metric_dynamic_vs_static() {
        use super::in_endgame;

        const BLOCKS: u64 = 1280; // 1280*256KiB = 320MiB => min(16, 320M/20M) = 16 segments exactly
        const SLOW_FROM: u64 = (BLOCKS * 3) / 10; // last 70% of content (blocks 384..) at 1/10 bandwidth
        const SLOW_COST: u64 = 10;
        const WORKERS: usize = 16;
        const SUBS_PER_BLOCK: u64 = 4; // sub-block floor = block/4 (g = bs/4)

        let bs = MIN_BLOCK_SIZE;
        let g = super::sub_block_granule(bs);
        let total = BLOCKS * bs;
        let block_cost = |b: u64| if b >= SLOW_FROM { SLOW_COST } else { 1 };
        // A sub-block inherits its block's cost.
        let cost = |gr: u64| block_cost(gr / SUBS_PER_BLOCK);

        // dynamic: guided self-scheduling (real GuidedPlan; endgame single-sub-block degradation).
        let mut plan = GuidedPlan::build(
            total,
            &GuidedConfig {
                block_size: bs,
                max_chunk: 8 * bs,
            },
            &|_| false,
        )
        .unwrap_or_else(|e| panic!("guided plan: {e}"));
        struct DWorker {
            holding: Option<(u64, u64)>,
            free_at: u64,
            done: bool,
        }
        let mut workers: Vec<DWorker> = (0..WORKERS)
            .map(|_| DWorker {
                holding: None,
                free_at: 0,
                done: false,
            })
            .collect();
        let total_subs = BLOCKS * SUBS_PER_BLOCK;
        let mut done_at = vec![0u64; total_subs as usize];
        while let Some(t) = workers.iter().filter(|w| !w.done).map(|w| w.free_at).min() {
            for i in 0..WORKERS {
                if workers[i].done || workers[i].free_at != t {
                    continue;
                }
                let alloc = |workers: &[DWorker], plan: &mut GuidedPlan| {
                    let holders = workers
                        .iter()
                        .enumerate()
                        .filter(|(j, w)| *j != i && w.holding.is_some())
                        .count();
                    let endgame = in_endgame(plan.remaining_blocks(), WORKERS);
                    let a = if endgame {
                        plan.pop_single_granule()
                    } else {
                        plan.pop_next(holders + 1, None)
                    };
                    a.map(|(_, ext)| (ext.start / g, ext.end() / g - 1))
                };
                match workers[i].holding {
                    Some((cursor, last)) => {
                        done_at[cursor as usize] = t;
                        if cursor < last {
                            workers[i].holding = Some((cursor + 1, last));
                            workers[i].free_at = t + cost(cursor + 1);
                        } else if let Some((first, last)) = alloc(&workers, &mut plan) {
                            workers[i].holding = Some((first, last));
                            workers[i].free_at = t + cost(first);
                        } else {
                            workers[i].holding = None;
                            workers[i].done = true;
                        }
                    }
                    None => match alloc(&workers, &mut plan) {
                        Some((first, last)) => {
                            workers[i].holding = Some((first, last));
                            workers[i].free_at = t + cost(first);
                        }
                        None => workers[i].done = true,
                    },
                }
            }
        }
        assert!(
            plan.pop_next(1, None).is_none() && plan.remaining_blocks() == 0,
            "the dynamic simulation must drain the whole pool"
        );
        let dynamic_share = tail_time_share(&done_at);

        // static control: fixed split (real StaticPlan; split=16,
        // min-split-size=20M pinned; work units stay whole blocks).
        let cfg = SchedulerConfig {
            block_size: bs,
            split: 16,
            min_split_size: 20 * 1024 * 1024,
            ..SchedulerConfig::default()
        };
        let mut splan = StaticPlan::build(total, &cfg).unwrap_or_else(|e| panic!("static: {e}"));
        struct SWorker {
            cur: Option<(u64, u64)>,
            free_at: u64,
            done: bool,
        }
        let mut sw: Vec<SWorker> = (0..WORKERS)
            .map(|_| SWorker {
                cur: None,
                free_at: 0,
                done: false,
            })
            .collect();
        let mut s_done_at = vec![0u64; BLOCKS as usize];
        while let Some(t) = sw.iter().filter(|w| !w.done).map(|w| w.free_at).min() {
            for w in sw.iter_mut() {
                if w.done || w.free_at != t {
                    continue;
                }
                match w.cur {
                    Some((cursor, last)) => {
                        s_done_at[cursor as usize] = t;
                        if cursor < last {
                            w.cur = Some((cursor + 1, last));
                            w.free_at = t + block_cost(cursor + 1);
                        } else {
                            w.cur = None;
                        }
                    }
                    None => match splan
                        .pop_next()
                        .map(|(_, ext)| (ext.start / bs, (ext.end() - 1) / bs))
                    {
                        Some((first, last)) => {
                            w.cur = Some((first, last));
                            w.free_at = t + block_cost(first);
                        }
                        None => w.done = true,
                    },
                }
            }
        }
        let static_share = tail_time_share(&s_done_at);

        /// Time share of the last 10% of content: wall clock from the
        /// 90%-completion moment (the completion time of the 90th content
        /// unit in order) to final completion, divided by the total.
        fn tail_time_share(done_at: &[u64]) -> f64 {
            let total_t = done_at
                .iter()
                .copied()
                .max()
                .unwrap_or_else(|| panic!("non-empty completion table"));
            let idx90 = (done_at.len() as u64 * 9 / 10 - 1) as usize;
            let t90 = done_at[idx90];
            (total_t - t90) as f64 / total_t as f64
        }

        assert!(
            dynamic_share < 0.15,
            "long-tail gate: dynamic's time share of the last 10% of content \
             {dynamic_share:.3} >= 15%"
        );
        assert!(
            static_share > 0.40,
            "static control: time share of the last 10% of content {static_share:.3} <= 40%"
        );
    }
}

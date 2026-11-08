//! Block grid: the fixed-granularity progress unit of the persistence
//! layer (the persistence side of the two-layer scheduling model).
//!
//! Position in the two-layer model: the persistence layer (this
//! module) keeps `block` = a fixed-granularity grid cell carrying the
//! bitmap/resume/progress/RPC/recovery validation; the runtime layer
//! (dynamic extents, scheduler/coordinator) keeps `extent` =
//! block-aligned byte ranges that vanish on completion and never
//! touch the database (scheduling/retry/stealing/multi-source
//! allocation).
//!
//! # Frozen seam: block-grid bitmap semantics
//!
//! The bitmap encoding is byte-compatible with the persistence layer
//! (`http_task.block_bitmap` column); any change is a breaking
//! change:
//!
//! - bit `i` = block `i` complete; **LSB-first** within a byte
//!   (bitfield convention);
//! - tail bits beyond `block_count` are invalid (ignored when
//!   encoding/validating);
//! - the last block is truncated by the authoritative total length
//!   (a `total_len % block_size` partial block counts only its real
//!   bytes — the progress-accounting domain);
//! - **block completion is first-report-wins, late reports dropped**
//!   (serial single-point decision; [`BlockGrid::record`] carries the
//!   semantics with its idempotent `false` return; the decision point
//!   lives in [`crate::coordinator::ExtentCoordinator`]);
//! - **`block_size` is task-level immutable**: frozen after
//!   construction-time validation; this type offers no mutation face
//!   (runtime option changes are rejected outright with
//!   `taiji.option.invalid`).
//!
//! Block completion does not mean the bytes are contiguously
//! trustworthy: same-block double writes under steal races are legal
//! (worst case wasted bandwidth, never interleaved corruption);
//! accounting follows this structure's first-report-wins.
//!
//! Upstream anchor mapping: docs/design/http.md

use crate::error::HttpError;
use crate::traits::Extent;

/// Default block granularity: 4 MiB.
pub const DEFAULT_BLOCK_SIZE: u64 = 4 * 1024 * 1024;

/// Config-domain lower bound for block granularity: 256 KiB
/// (`--http-block-size`).
pub const MIN_BLOCK_SIZE: u64 = 256 * 1024;

/// Config-domain upper bound for block granularity: 16 MiB
/// (`--http-block-size`).
pub const MAX_BLOCK_SIZE: u64 = 16 * 1024 * 1024;

/// Authoritative total-length ceiling: 16 TiB (2^44).
///
/// aria2 imposes no hard cap on download total length; this engine
/// takes 16 TiB with process safety as the boundary — far beyond any
/// realistic single-file download while pinning the worst-case bitmap
/// allocation at `16TiB ÷ 256KiB (min block) ÷ 8 = 8MiB`. A
/// malicious/faulty source reporting a 2^63-scale `Content-Range`
/// total or `Content-Length` is rejected task-level by
/// `BlockGrid::new` (`taiji.http.total_length_exceeded`), so a giant
/// bitmap allocation (`handle_alloc_error` aborting the whole
/// process) is unreachable at the construction face. The probe face
/// (`crate::probe`) rejects at the same ceiling first; this is the
/// defensive validation — the grid is a pub API and cannot assume the
/// layer above it has already decided.
pub const MAX_TOTAL_LEN: u64 = 16 * 1024 * 1024 * 1024 * 1024;

/// Config-domain validation: `block_size` ∈ {powers of two,
/// 256KiB..16MiB}.
///
/// Out-of-domain is always rejected (no truncation, no silent
/// clamping), error code `taiji.option.invalid`.
pub fn validate_block_size(block_size: u64) -> Result<(), HttpError> {
    if block_size.is_power_of_two() && (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) {
        return Ok(());
    }
    Err(HttpError::OptionInvalid {
        option: "--http-block-size",
        value: format!(
            "{block_size} (must be a power of two within {}..={})",
            MIN_BLOCK_SIZE, MAX_BLOCK_SIZE
        ),
    })
}

/// Block grid: fixed granularity + bitmap accounting.
///
/// Construction freezes: `block_size` is immutable after config-domain
/// validation; `total_len` is the probe's authoritative total (the
/// merged 206-source face). The no-total form (no-range
/// single-connection degradation) builds no grid — no bitmap, no
/// offset resume, recovery restarts from zero.
#[derive(Debug, Clone)]
pub struct BlockGrid {
    /// Block granularity (bytes; task-level immutable — see the
    /// frozen seam in the module docs).
    block_size: u64,
    /// Authoritative total length (bytes).
    total_len: u64,
    /// Total blocks = ceil(total_len / block_size); total_len = 0 →
    /// 0 blocks.
    block_count: u64,
    /// Bitmap (LSB-first; tail bits beyond `block_count` always 0).
    bitmap: Vec<u8>,
}

/// Minimum bitmap bytes: `ceil(count / 8)`.
fn bitmap_len(block_count: u64) -> usize {
    block_count.div_ceil(8) as usize
}

/// Bit read (LSB-first). Out of range returns `false` — tail bits
/// beyond `block_count` are invalid.
fn bit_test(bitmap: &[u8], block: u64) -> bool {
    bitmap
        .get((block / 8) as usize)
        .is_some_and(|b| b & (1 << (block % 8)) != 0)
}

/// Bit set. The caller guarantees `block < block_count` (byte in
/// bounds).
fn bit_set(bitmap: &mut [u8], block: u64) {
    let idx = (block / 8) as usize;
    bitmap[idx] |= 1 << (block % 8);
}

impl BlockGrid {
    /// Assembles the grid. `block_size` out of the config domain →
    /// `taiji.option.invalid`; `total_len = 0` is legal (empty file: 0
    /// blocks, empty bitmap, immediately all-done); `total_len` beyond
    /// [`MAX_TOTAL_LEN`] → `taiji.http.total_length_exceeded`
    /// (defensive validation: the grid is a pub API, the giant bitmap
    /// allocation is rejected at the construction face — never assume
    /// the probe layer above has already decided).
    pub fn new(block_size: u64, total_len: u64) -> Result<Self, HttpError> {
        validate_block_size(block_size)?;
        if total_len > MAX_TOTAL_LEN {
            return Err(HttpError::TotalLengthExceeded {
                total: total_len,
                max: MAX_TOTAL_LEN,
            });
        }
        let block_count = total_len.div_ceil(block_size);
        Ok(BlockGrid {
            block_size,
            total_len,
            block_count,
            bitmap: vec![0u8; bitmap_len(block_count)],
        })
    }

    /// Block granularity (bytes).
    pub fn block_size(&self) -> u64 {
        self.block_size
    }

    /// Authoritative total length (bytes).
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Total block count.
    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    /// Bitmap view (persistence encoding; frozen seam — see the
    /// module docs).
    pub fn bitmap(&self) -> &[u8] {
        &self.bitmap
    }

    /// Byte range covered by block `block` (block-aligned; last block
    /// truncated by the total length). Beyond the grid → `None`.
    pub fn block_extent(&self, block: u64) -> Option<Extent> {
        if block >= self.block_count {
            return None;
        }
        let start = block * self.block_size;
        let len = self.block_size.min(self.total_len - start);
        Some(Extent { start, len })
    }

    /// Block range **spanned** by an extent (both ends inclusive):
    /// block alignment is not required — a line-level lease start can
    /// land on any sub-block boundary, and first/last are taken by
    /// floor/ceil division (the last-block-truncated-by-total
    /// semantics unchanged). Empty extent or out of bounds
    /// (`end > total_len` / `start >= total_len`) → `None`. The
    /// in-flight accounting face (coordinator register/unregister);
    /// [`Self::blocks_covered`]'s strict alignment validation stays
    /// reserved for the static face (block-aligned extents).
    pub fn blocks_spanned(&self, extent: &Extent) -> Option<(u64, u64)> {
        if extent.is_empty() || extent.end() > self.total_len || extent.start >= self.total_len {
            return None;
        }
        let first = extent.start / self.block_size;
        let last = (extent.end() - 1) / self.block_size;
        Some((first, last))
    }

    /// Block range covered by an extent (both ends inclusive). The
    /// extent must be block-aligned and inside the grid (the static
    /// face's extent invariant; dynamic line-level leases are
    /// sub-block-granular and go through [`Self::blocks_spanned`]);
    /// empty extent, unaligned start, or out of bounds → `None`
    /// (defensive rejection — silently absorbing an unaligned start by
    /// division would fold a misaligned extent into a false block
    /// number and amplify it into cross-block misaccounting through
    /// the accounting face).
    pub fn blocks_covered(&self, extent: &Extent) -> Option<(u64, u64)> {
        if extent.is_empty()
            || extent.end() > self.total_len
            || extent.start >= self.total_len
            || !extent.start.is_multiple_of(self.block_size)
        {
            return None;
        }
        let first = extent.start / self.block_size;
        let last = (extent.end() - 1) / self.block_size;
        Some((first, last))
    }

    /// Block-completion accounting (the bookkeeping face of the single
    /// decision point): first report wins (`Ok(true)`), late reports
    /// dropped (`Ok(false)` — late reports of same-block double
    /// writes; progress counts once). Beyond the grid = a
    /// scheduler-side defect → [`HttpError::BadRange`].
    pub fn record(&mut self, block: u64) -> Result<bool, HttpError> {
        if block >= self.block_count {
            return Err(HttpError::BadRange);
        }
        if bit_test(&self.bitmap, block) {
            return Ok(false);
        }
        bit_set(&mut self.bitmap, block);
        Ok(true)
    }

    /// Whether block `block` is recorded.
    pub fn is_recorded(&self, block: u64) -> bool {
        block < self.block_count && bit_test(&self.bitmap, block)
    }

    /// Number of recorded blocks.
    pub fn done_blocks(&self) -> u64 {
        (0..self.block_count)
            .filter(|b| bit_test(&self.bitmap, *b))
            .count() as u64
    }

    /// Accumulated recorded bytes (last block counted truncated by the
    /// authoritative total — the progress-display domain).
    pub fn done_bytes(&self) -> u64 {
        (0..self.block_count)
            .filter(|b| bit_test(&self.bitmap, *b))
            .map(|b| {
                let start = b * self.block_size;
                self.block_size.min(self.total_len - start)
            })
            .sum()
    }

    /// All-blocks-complete verdict (a `total_len = 0` empty grid is
    /// always true — nothing to do).
    pub fn is_all_done(&self) -> bool {
        self.done_blocks() == self.block_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::HttpError;

    /// Deterministic RNG (xorshift64; random combinations
    /// reproducible).
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

    /// Geometry edges (the explicitly listed shapes): total=0 /
    /// single segment (total < block) / divisible boundary / partial
    /// last block.
    #[test]
    fn grid_geometry_edges() {
        // total = 0: 0 blocks, empty bitmap, always complete, any
        // record beyond range rejected.
        let mut g = BlockGrid::new(DEFAULT_BLOCK_SIZE, 0).unwrap_or_else(|e| panic!("grid: {e}"));
        assert_eq!(g.block_count(), 0);
        assert!(g.bitmap().is_empty());
        assert!(g.is_all_done(), "an empty file has nothing to do");
        assert_eq!(g.done_bytes(), 0);
        assert!(matches!(g.record(0), Err(HttpError::BadRange)));
        assert!(g.block_extent(0).is_none());

        // Single segment: total < block → 1 partial block; after
        // recording, done_bytes == total.
        let mut g =
            BlockGrid::new(DEFAULT_BLOCK_SIZE, 4096).unwrap_or_else(|e| panic!("grid: {e}"));
        assert_eq!(g.block_count(), 1);
        assert_eq!(g.bitmap().len(), 1);
        let ext = g.block_extent(0).unwrap_or_else(|| panic!("block 0"));
        assert_eq!(
            (ext.start, ext.len),
            (0, 4096),
            "the last block is truncated by the total length"
        );
        assert!(!g.is_all_done());
        assert!(g.record(0).unwrap_or_else(|e| panic!("record: {e}")));
        assert_eq!(g.done_bytes(), 4096);
        assert!(g.is_all_done());

        // Divisible boundary: total = 3 × block → exactly 3 blocks, no
        // partial last block.
        let g = BlockGrid::new(DEFAULT_BLOCK_SIZE, 3 * DEFAULT_BLOCK_SIZE)
            .unwrap_or_else(|e| panic!("grid: {e}"));
        assert_eq!(g.block_count(), 3);
        assert_eq!(g.bitmap().len(), 1);
        let ext = g.block_extent(2).unwrap_or_else(|| panic!("block 2"));
        assert_eq!(
            ext.len, DEFAULT_BLOCK_SIZE,
            "no partial block at the divisible boundary"
        );
        assert_eq!(g.done_blocks(), 0);

        // Non-divisible: ceil up + bitmap bytes ceil/8; invalid tail
        // bits read as false.
        let mut g = BlockGrid::new(MIN_BLOCK_SIZE, 9 * MIN_BLOCK_SIZE + 1)
            .unwrap_or_else(|e| panic!("grid: {e}"));
        assert_eq!(g.block_count(), 10);
        assert_eq!(g.bitmap().len(), 2, "ceil(10/8) = 2 bytes");
        assert!(!g.is_recorded(9));
        // Out-of-range block reads are always false, records rejected.
        assert!(!g.is_recorded(10));
        assert!(matches!(g.record(10), Err(HttpError::BadRange)));
        assert!(g.block_extent(10).is_none());
    }

    /// Block algebra: extent → covered block range (cross-block
    /// extents, partial last block, empty and out-of-bounds).
    #[test]
    fn blocks_covered_algebra() {
        let bs = MIN_BLOCK_SIZE;
        let g = BlockGrid::new(bs, 5 * bs + 100).unwrap_or_else(|e| panic!("grid: {e}"));
        let ext = |start: u64, len: u64| Extent { start, len };

        // Within one block, across 2 blocks, covering a partial last
        // block.
        assert_eq!(g.blocks_covered(&ext(0, 1)), Some((0, 0)));
        assert_eq!(g.blocks_covered(&ext(0, bs)), Some((0, 0)));
        assert_eq!(g.blocks_covered(&ext(0, bs + 1)), Some((0, 1)));
        assert_eq!(g.blocks_covered(&ext(bs, 2 * bs)), Some((1, 2)));
        // Partial last block: an extent with end == total covers the
        // last block.
        assert_eq!(g.blocks_covered(&ext(5 * bs, 100)), Some((5, 5)));
        // The whole grid in one row.
        assert_eq!(g.blocks_covered(&ext(0, 5 * bs + 100)), Some((0, 5)));

        // Empty extent / out of bounds / start past total → None.
        assert_eq!(g.blocks_covered(&ext(0, 0)), None);
        assert_eq!(g.blocks_covered(&ext(0, 5 * bs + 101)), None);
        assert_eq!(g.blocks_covered(&ext(5 * bs + 100, bs)), None);

        // Unaligned start (a scheduler-side defect shape — the
        // scheduler only produces block-aligned extents, sub-block
        // extents forbidden) → None defensive rejection, not silently
        // absorbed by division (that would fold the misaligned extent
        // into a false block number and amplify it through the
        // accounting face).
        assert_eq!(g.blocks_covered(&ext(1, bs)), None);
        assert_eq!(g.blocks_covered(&ext(bs / 2, bs)), None);
        assert_eq!(g.blocks_covered(&ext(3 * bs + 7, bs)), None);
    }

    /// Arbitrary extent combinations → bitmap consistency (the
    /// randomized face): random grid × random extent partition
    /// (including overlapping duplicate reports), model = independent
    /// bit set; bitmap bytes, block count, and byte total all agree;
    /// first-report-wins is idempotent.
    #[test]
    fn arbitrary_extent_combinations_bitmap_consistent() {
        const ROUNDS: u64 = 64;
        let mut rng = Rng(0x7461_6a69_7030_3505);
        for round in 0..ROUNDS {
            // Random in-domain block granularity + random total
            // (covering 0 / single segment / divisible / non-divisible).
            let bs_log = 18 + rng.below(7); // 2^18=256KiB .. 2^24=16MiB
            let bs = 1u64 << bs_log;
            let total = match rng.below(4) {
                0 => 0,
                1 => rng.below(bs),           // single-segment partial block
                2 => bs * (1 + rng.below(9)), // divisible
                _ => bs * rng.below(10) + rng.below(bs), // non-divisible
            };
            let mut grid =
                BlockGrid::new(bs, total).unwrap_or_else(|e| panic!("round {round}: {e}"));

            // Reference model: block-number bit set + byte total.
            let mut expect: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
            let count = grid.block_count();
            if count == 0 {
                assert!(grid.is_all_done());
                continue;
            }

            // Randomly cut the grid into 1..=16 segments
            // (block-aligned), shuffle, record segment by segment;
            // each segment additionally reports once more (the
            // late-report shape of same-block double writes).
            let cuts = 1 + rng.below(16);
            let mut bounds = vec![0u64];
            for _ in 0..cuts {
                bounds.push(rng.below(count + 1));
            }
            bounds.push(count);
            bounds.sort_unstable();
            bounds.dedup();
            let mut segments: Vec<(u64, u64)> = bounds
                .windows(2)
                .filter_map(|w| {
                    if w[0] < w[1] {
                        // Bounds are exclusive cut points: segment =
                        // blocks [w0, w1).
                        Some((w[0], w[1] - 1))
                    } else {
                        None
                    }
                })
                .collect();
            // Shuffle (deterministic Fisher-Yates).
            for i in (1..segments.len()).rev() {
                let j = rng.below((i + 1) as u64) as usize;
                segments.swap(i, j);
            }

            let mut expect_bytes = 0u64;
            for (first, last) in &segments {
                let ext_start = first * bs;
                let ext_end = ((*last + 1) * bs).min(total);
                let ext = Extent {
                    start: ext_start,
                    len: ext_end - ext_start,
                };
                // Scheduler invariant: the extent is block-aligned and
                // accepted by the grid coverage algebra.
                assert_eq!(
                    grid.blocks_covered(&ext),
                    Some((*first, *last)),
                    "round {round}: blocks_covered"
                );
                for b in *first..=*last {
                    let first_win = grid
                        .record(b)
                        .unwrap_or_else(|e| panic!("round {round}: {e}"));
                    assert!(
                        first_win,
                        "round {round}: block {b} first record must be a new completion"
                    );
                    expect.insert(b);
                    // Late reports dropped: a duplicate record returns
                    // false and is not double-counted.
                    assert!(
                        !grid
                            .record(b)
                            .unwrap_or_else(|e| panic!("round {round}: {e}")),
                        "round {round}: block {b} duplicate record must be dropped"
                    );
                }
                // Reference byte total (last-block truncation domain).
                for b in *first..=*last {
                    let start = b * bs;
                    expect_bytes += bs.min(total - start);
                }
            }

            // Byte-by-byte bitmap comparison (independent re-encode).
            let mut want = vec![0u8; grid.bitmap().len()];
            for b in &expect {
                want[(*b / 8) as usize] |= 1 << (*b % 8);
            }
            assert_eq!(grid.bitmap(), &want[..], "round {round}: bitmap mismatch");
            assert_eq!(grid.done_blocks(), expect.len() as u64, "round {round}");
            assert_eq!(
                grid.done_bytes(),
                expect_bytes,
                "round {round}: byte accumulation"
            );
            assert_eq!(
                grid.is_all_done(),
                expect.len() == count as usize,
                "round {round}"
            );
        }
    }

    /// Total-length ceiling defensive validation (pub-API defense —
    /// never assume the layer above has decided): exactly at the cap
    /// assembles legally; one past the cap is rejected (a 2^63-scale
    /// injected shape is rejected first at the classification layer —
    /// see
    /// probe::tests::authoritative_total_beyond_cap_is_task_rejection;
    /// constructing with 2^63 directly here would have triggered the
    /// giant-allocation abort before the fix, hence the adjacent
    /// value).
    #[test]
    fn total_len_beyond_cap_rejected() {
        assert!(
            BlockGrid::new(MIN_BLOCK_SIZE, MAX_TOTAL_LEN).is_ok(),
            "exactly at the cap assembles legally"
        );
        match BlockGrid::new(MIN_BLOCK_SIZE, MAX_TOTAL_LEN + 1) {
            Err(HttpError::TotalLengthExceeded { .. }) => {}
            other => panic!("over-cap grid must be rejected, got {other:?}"),
        }
    }

    /// Config-domain rejection: accepted only as a power of two within
    /// 256KiB..16MiB; boundary values (lower/upper) accepted;
    /// 0 / non-power / below / above / power-but-outside rejected with
    /// error code `taiji.option.invalid`.
    #[test]
    fn block_size_domain_rejects_out_of_range() {
        for ok in [
            MIN_BLOCK_SIZE,
            512 * 1024,
            1024 * 1024,
            DEFAULT_BLOCK_SIZE,
            8 * 1024 * 1024,
            MAX_BLOCK_SIZE,
        ] {
            assert!(
                validate_block_size(ok).is_ok(),
                "{ok} must be inside the domain"
            );
            assert!(BlockGrid::new(ok, 1024).is_ok(), "{ok} must assemble");
        }
        let rejected: [(u64, &str); 6] = [
            (0, "zero"),
            (MIN_BLOCK_SIZE / 2, "below domain"),
            (3 * 1024 * 1024, "not a power of two"),
            (DEFAULT_BLOCK_SIZE + 1, "not a power of two"),
            (2 * MAX_BLOCK_SIZE, "above domain"),
            (u64::MAX, "absurd"),
        ];
        for (bad, why) in rejected {
            match validate_block_size(bad) {
                Err(HttpError::OptionInvalid { option, .. }) => {
                    assert_eq!(option, "--http-block-size", "{why}");
                    assert_eq!(
                        HttpError::OptionInvalid {
                            option,
                            value: String::new()
                        }
                        .code(),
                        "taiji.option.invalid"
                    );
                }
                other => panic!("{bad} ({why}) must be rejected, got {other:?}"),
            }
            assert!(
                BlockGrid::new(bad, 1024).is_err(),
                "{bad} must not assemble"
            );
        }
    }
}

//! HTTP task persistence face (the versioned `http_task` table): the sole
//! core-side home of the write and read paths.
//!
//! Write path (bitmap snapshot pipeline), startup recovery read path,
//! resume verdicts, and the shared block-bitmap encoding:
//! docs/design/core.md

use taiji_store::persist::HttpTaskRow;

pub mod recover;
pub mod resume;
pub mod snapshot;

pub use recover::{PartFileFacts, RecoveredHttpTask, Resumability, ZeroReason, recover_http_task};
pub use resume::{
    RestartReason, ResumeBasis, ResumeDecision, ValidatorFacts, decide_resume, strong_etag,
    url_path, validator_digest,
};
pub use snapshot::{HttpSnapshotError, HttpSnapshotPipeline, PartFileSync, SNAPSHOT_INTERVAL_MS};

/// Minimum byte count of a block bitmap (`ceil(count/8)`).
pub(crate) fn bitmap_len(block_count: u64) -> usize {
    block_count.div_ceil(8) as usize
}

/// Bit read (LSB-first; out-of-range returns false — tail bits beyond
/// `block_count` are invalid).
pub(crate) fn bit_test(bitmap: &[u8], block: u64) -> bool {
    bitmap
        .get((block / 8) as usize)
        .is_some_and(|b| b & (1 << (block % 8)) != 0)
}

/// Bit set (the caller guarantees `block < block_count`, i.e. the byte
/// is in bounds).
pub(crate) fn bit_set(bitmap: &mut [u8], block: u64) {
    let idx = (block / 8) as usize;
    bitmap[idx] |= 1 << (block % 8);
}

/// Byte length covered by block `block` (the last block truncates to
/// the authoritative total; without a total, count the whole block).
pub(crate) fn block_bytes(block: u64, block_size: u64, total_len: Option<u64>) -> u64 {
    match total_len {
        Some(total) => block_size.min(total.saturating_sub(block * block_size)),
        None => block_size,
    }
}

/// Validated bitmap -> completed byte total (the progress display face;
/// recovery trust defers to the bitmap).
pub(crate) fn bitmap_done_bytes(
    bitmap: &[u8],
    block_count: u64,
    block_size: u64,
    total_len: Option<u64>,
) -> u64 {
    (0..block_count)
        .filter(|b| bit_test(bitmap, *b))
        .map(|b| block_bytes(b, block_size, total_len))
        .sum()
}

/// Completed block count within `block_count` bounds.
pub(crate) fn bitmap_done_blocks(bitmap: &[u8], block_count: u64) -> u64 {
    (0..block_count).filter(|b| bit_test(bitmap, *b)).count() as u64
}

/// Block geometry domain validation (config domain): powers of two in
/// 256KiB..16MiB.
pub(crate) fn valid_block_size(block_size: u64) -> bool {
    const MIN: u64 = 256 * 1024;
    const MAX: u64 = 16 * 1024 * 1024;
    (MIN..=MAX).contains(&block_size) && block_size.is_power_of_two()
}

/// `.part` full path assembly (`<out><suffix>`; the suffix comes from
/// the task config's in-progress suffix, persisted at creation —
/// default-value changes do not break in-flight tasks).
pub fn part_path(dir: &str, out: &str, suffix: &str) -> std::path::PathBuf {
    std::path::Path::new(dir).join(format!("{out}{suffix}"))
}

/// Row payload sanity (the geometry consistency criterion shared by the
/// recovery read path and the snapshot pipeline): the block size is in
/// the config domain and the bitmap byte length aligns with
/// `block_count` (when a bitmap exists). `bitmap=None` (the
/// pre-first-shot plan state / a recovery from-zero product) is a
/// legitimate shape — the snapshot pipeline lazily creates a zero
/// bitmap at the first completed block ([`snapshot`]) and the recovery
/// side reports `NoBitmap`.
pub(crate) fn row_geometry_ok(row: &HttpTaskRow) -> bool {
    if !valid_block_size(row.block_size.max(0) as u64) {
        return false;
    }
    match (row.block_bitmap.as_deref(), row.block_count) {
        (Some(bm), Some(bc)) if bc >= 0 => bm.len() == bitmap_len(bc as u64),
        // Bitmap not yet written (before the first shot) / pre-first-
        // shot plan state: the count is a probe-plan fact, independent
        // of bitmap presence.
        (None, _) => true,
        // Bitmap without a count (cannot delimit) or a negative count =
        // row corrupt.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_helpers_are_lsb_first_and_bounded() {
        let mut bm = vec![0u8; bitmap_len(10)];
        bit_set(&mut bm, 0);
        bit_set(&mut bm, 7);
        bit_set(&mut bm, 8);
        assert!(bit_test(&bm, 0));
        assert!(bit_test(&bm, 7));
        assert!(bit_test(&bm, 8));
        assert!(!bit_test(&bm, 9));
        // Out-of-range bit reads are safe (tail bits beyond block_count
        // are invalid).
        assert!(!bit_test(&bm, 64));
        assert_eq!(bitmap_done_blocks(&bm, 10), 3);
        assert_eq!(bitmap_len(0), 0);
        assert_eq!(bitmap_len(8), 1);
        assert_eq!(bitmap_len(9), 2);
    }

    #[test]
    fn block_bytes_clamps_last_partial_block() {
        let bs = 1024;
        assert_eq!(block_bytes(0, bs, Some(3 * 1024 + 5)), 1024);
        // The last block (index 3) has only 5 bytes left.
        assert_eq!(block_bytes(3, bs, Some(3 * 1024 + 5)), 5);
        // Blocks beyond the total count 0 (a defensive face before
        // recovery validation).
        assert_eq!(block_bytes(9, bs, Some(3 * 1024 + 5)), 0);
        // No authoritative total: count the whole block.
        assert_eq!(block_bytes(2, bs, None), 1024);
    }

    #[test]
    fn block_size_domain_is_power_of_two_256k_16m() {
        for ok in [256 * 1024u64, 4 * 1024 * 1024, 16 * 1024 * 1024] {
            assert!(valid_block_size(ok), "{ok}");
        }
        for bad in [
            0,
            1024,             // power of two below the floor
            32 * 1024 * 1024, // above the cap
            3 * 1024 * 1024,  // in range but not a power of two
        ] {
            assert!(!valid_block_size(bad), "{bad}");
        }
    }

    #[test]
    fn part_path_appends_suffix_to_out() {
        let p = part_path("/dl", "f.bin", ".part");
        assert!(p.ends_with("f.bin.part"), "{p:?}");
    }
}

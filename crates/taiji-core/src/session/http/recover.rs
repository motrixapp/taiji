//! http_task startup recovery read path ("recovery trust
//! precondition" / SPEC §6 recovery semantics): PersistWriter active
//! rows -> per-task validation -> trusted task state.
//!
//! **Second line of defense** (pure-function verdicts + caller-supplied
//! file facts; this module does no IO): the cumulative end of every
//! completed block must land within the task file's actual length —
//! blocks that fail fall back to incomplete. Under prealloc the file
//! length always equals the authoritative total, so the size check
//! always passes; the first line of defense is the fsync ordering
//! before the bitmap snapshot ([`super::snapshot`], SPEC §4.3/§14.1
//! "a power-loss bitmap must never be ahead of the data"). This check
//! catches abnormal shapes outside the snapshot ordering: `.part`
//! deleted/truncated (manual cleanup, incomplete cross-volume restore),
//! etc.
//!
//! Validation passing = the bitmap is valid (resume); otherwise restart
//! from zero per the reason (bitmap cleared, same rule as SPEC §4.5
//! "length != probed length -> re-download everything with the bitmap
//! cleared"). `total_done` is recomputed from the validated bitmap —
//! the bitmap is the only persisted progress truth.

use taiji_store::persist::HttpTaskRow;

use super::{
    bit_set, bit_test, bitmap_done_blocks, bitmap_done_bytes, bitmap_len, row_geometry_ok,
};

/// `.part` file facts (the caller stats within `spawn_blocking`; the
/// only IO face during recovery, extracted as a value so the verdicts
/// stay pure-function testable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartFileFacts {
    /// The file exists (absent = the block file deleted shape's
    /// power-loss injection face).
    pub exists: bool,
    /// File length (fstat st_size; 0 when absent).
    pub len: u64,
}

/// Restart-from-zero reason (observation face: recovery report / log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroReason {
    /// The row has no bitmap/block count (never entered bitmap form:
    /// no-range / REST-degraded tasks — "bitmap-less degraded tasks
    /// always restart from zero").
    NoBitmap,
    /// Row geometry corrupt: block size out of domain, bitmap and
    /// count unpaired / length mismatch (the store row was tampered
    /// with or the write side is defective — never recover a sick
    /// row).
    RowCorrupt,
    /// `.part` absent (the data is missing wholesale; the bitmap is
    /// void entirely).
    PartFileMissing,
    /// `.part` exists but its length != the probed authoritative total
    /// (the `.part` reuse verdict: re-download everything).
    PartFileLengthMismatch,
    /// After block reversion nothing survived (the cumulative size
    /// check wiped all completed blocks).
    NoTrustedBlocks,
}

/// Recovery verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resumability {
    /// The (validated) bitmap is trusted; resume by bitmap.
    FromBitmap {
        /// Completed block count after validation.
        blocks_done: u64,
    },
    /// Restart from zero (bitmap cleared).
    FromZero { reason: ZeroReason },
}

/// Per-task recovery product: the corrected row copy (bitmap/total_done
/// per the validation) + the recovery verdict. The original row is
/// never mutated in place (replay-safe on recovery failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredHttpTask {
    /// The corrected row (bitmap reverted/cleared, total_done
    /// recomputed; all other fields as-is).
    pub row: HttpTaskRow,
    /// Block-grid total (`block_count`; 0 in unrecoverable states).
    pub blocks_total: u64,
    /// Completed block count after validation.
    pub blocks_done: u64,
    /// Completed blocks reverted by the size check (the second line of
    /// defense's outcome; 0 = no reversion).
    pub reverted_blocks: u64,
    pub resumability: Resumability,
}

/// Recover one task: `part` = `.part` file facts; `expected_len` = the
/// probed authoritative total (from the probe payload, parsed by the
/// caller; None = skip the file-length-vs-total comparison and only run
/// the per-block cumulative size check). Two legitimate None sources:
/// the probe length is unavailable (the bitmap should not have been
/// enabled in the first place; the row's bitmap is the empty-set
/// shape), and imported/absorbed rows (the `.part` was absorbed from
/// fork data, its length = the fork's write frontier — without prealloc
/// it routinely differs from the probed total, so the length-equality
/// gate does not apply; the per-block cumulative size check still
/// decides, with the last block judged conservatively at the whole-block
/// boundary).
///
/// Verdict order: row geometry -> file existence -> file length vs
/// total -> per-block cumulative size.
pub fn recover_http_task(
    row: &HttpTaskRow,
    part: PartFileFacts,
    expected_len: Option<u64>,
) -> RecoveredHttpTask {
    let block_size = row.block_size.max(0) as u64;
    let mut corrected = row.clone();

    // Row geometry (domain validation + bitmap/count pairing): a
    // corrupt row is never recovered as-is.
    if !row_geometry_ok(row) {
        return from_zero(corrected, 0, ZeroReason::RowCorrupt);
    }
    let Some(block_count) = row.block_count else {
        return from_zero(corrected, 0, ZeroReason::NoBitmap);
    };
    if block_count < 0 {
        // A negative count is not a probe-plan fact (0 = the legitimate
        // empty-file shape) — the store row was tampered with or the
        // write side is defective; never recover a sick row (boundary:
        // no bitmap + negative count gets the same verdict and must not
        // pass as the "empty trusted state").
        return from_zero(corrected, 0, ZeroReason::RowCorrupt);
    }
    let block_count = block_count as u64;
    if block_count == 0 {
        // Empty-file task (0 blocks): no progress to validate and no
        // bitmap to clear.
        corrected.total_done = 0;
        return RecoveredHttpTask {
            row: corrected,
            blocks_total: 0,
            blocks_done: 0,
            reverted_blocks: 0,
            resumability: Resumability::FromBitmap { blocks_done: 0 },
        };
    }
    let Some(bitmap) = row.block_bitmap.clone() else {
        return from_zero(corrected, block_count, ZeroReason::NoBitmap);
    };

    // File existence: `.part` missing = the data is missing wholesale
    // (the block-file-deleted shape).
    if !part.exists {
        return from_zero(corrected, block_count, ZeroReason::PartFileMissing);
    }
    // File length vs probed authoritative total (the `.part` reuse
    // verdict; skipped when the probe length is unavailable — the
    // bitmap should not have been enabled then, and the row's bitmap is
    // the empty-set shape).
    if let Some(total) = expected_len {
        if part.len != total {
            return from_zero(corrected, block_count, ZeroReason::PartFileLengthMismatch);
        }
    }

    // Per-block cumulative size check: a completed block's end must be
    // <= the file's actual length (beyond it the data never hit disk —
    // revert to incomplete; the bitmap is a set, not a prefix, so each
    // block is judged independently). The last block's effective end is
    // truncated to the authoritative total (when a partial last block
    // is complete its end = the total, not the whole-block boundary);
    // with no authoritative total, judge conservatively at the
    // whole-block boundary (may revert one extra partial last block —
    // the safe direction, re-download cost <= 1 block).
    let mut trusted = vec![0u8; bitmap_len(block_count)];
    let mut blocks_done = 0u64;
    for block in 0..block_count {
        if bit_test(&bitmap, block) {
            let end = (block + 1)
                .saturating_mul(block_size)
                .min(expected_len.unwrap_or(u64::MAX));
            if end <= part.len {
                bit_set(&mut trusted, block);
                blocks_done += 1;
            }
        }
    }
    let completed_before = bitmap_done_blocks(&bitmap, block_count);
    let reverted = completed_before - blocks_done.min(completed_before);
    if blocks_done == 0 && completed_before > 0 {
        // All lost: clear the bitmap but report the reverted count
        // accurately (the second line of defense's outcome face).
        let mut out = from_zero(corrected, block_count, ZeroReason::NoTrustedBlocks);
        out.reverted_blocks = completed_before;
        return out;
    }
    corrected.block_bitmap = Some(trusted.clone());
    corrected.total_done = bitmap_done_bytes(&trusted, block_count, block_size, expected_len)
        .min(i64::MAX as u64) as i64;
    RecoveredHttpTask {
        row: corrected,
        blocks_total: block_count,
        blocks_done,
        reverted_blocks: reverted,
        resumability: Resumability::FromBitmap { blocks_done },
    }
}

/// From-zero exit: clear the bitmap (None = the no-bitmap shape) and
/// zero total_done; keep the block count (the grid plan fact comes from
/// the probe and has nothing to do with progress trust).
fn from_zero(mut row: HttpTaskRow, blocks_total: u64, reason: ZeroReason) -> RecoveredHttpTask {
    row.block_bitmap = None;
    row.total_done = 0;
    RecoveredHttpTask {
        row,
        blocks_total,
        blocks_done: 0,
        reverted_blocks: 0,
        resumability: Resumability::FromZero { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test block size 256KiB (the config domain floor — legal in
    /// domain, so the geometry validation passes).
    const BS: u64 = 256 * 1024;

    /// Test row: 8 blocks x BS, bitmap built from the done set.
    fn row(done: &[u64], total_done: i64) -> HttpTaskRow {
        let bc = 8u64;
        let mut bm = vec![0u8; bitmap_len(bc)];
        for b in done {
            bit_set(&mut bm, *b);
        }
        HttpTaskRow {
            gid: "8000000000000300".into(),
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
            block_size: BS as i64,
            block_bitmap: Some(bm),
            block_count: Some(bc as i64),
            total_done,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn complete_bitmap_with_full_file_is_trusted() {
        // Complete file (prealloc full length) + all done blocks in
        // range -> all trusted, zero reversion.
        let r = row(&[0, 1, 3], 3 * BS as i64);
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: 8 * BS,
            },
            None,
        );
        assert_eq!(
            rec.resumability,
            Resumability::FromBitmap { blocks_done: 3 }
        );
        assert_eq!(rec.blocks_total, 8);
        assert_eq!(rec.blocks_done, 3);
        assert_eq!(rec.reverted_blocks, 0);
        assert_eq!(rec.row.total_done, 3 * BS as i64);
    }

    #[test]
    fn torn_tail_reverts_unbacked_blocks_only() {
        // Done {0,1,3}; the file holds only 3.5 blocks (block 3's end
        // at 4 blocks > 3.5) -> block 3 reverts, 0/1 survive (the
        // bitmap is a set; blocks are judged independently).
        let r = row(&[0, 1, 3], 3 * BS as i64);
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: 3 * BS + 512,
            },
            None,
        );
        assert_eq!(rec.blocks_total, 8);
        assert_eq!(rec.blocks_done, 2, "block 3 rolled back");
        assert_eq!(rec.reverted_blocks, 1);
        assert_eq!(
            rec.resumability,
            Resumability::FromBitmap { blocks_done: 2 }
        );
        let Some(bm) = rec.row.block_bitmap.as_deref() else {
            panic!("bitmap kept");
        };
        assert!(bit_test(bm, 0) && bit_test(bm, 1));
        assert!(!bit_test(bm, 3), "the rolled-back block is cleared");
        // total_done recomputed from the validated bitmap.
        assert_eq!(rec.row.total_done, 2 * BS as i64);
    }

    /// The block-file-deleted shape: `.part` missing -> the bitmap is
    /// void wholesale, restart from zero (zero-wrong: the verdict is
    /// explicit, the row copy is cleared, and the original row is not
    /// modified).
    #[test]
    fn missing_part_file_restarts_from_zero() {
        let r = row(&[0, 1, 2, 3], 4 * BS as i64);
        let before = r.clone();
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: false,
                len: 0,
            },
            None,
        );
        assert_eq!(
            rec.resumability,
            Resumability::FromZero {
                reason: ZeroReason::PartFileMissing
            }
        );
        assert_eq!(rec.blocks_done, 0);
        assert!(rec.row.block_bitmap.is_none(), "bitmap cleared to zero");
        assert_eq!(rec.row.total_done, 0);
        assert_eq!(r, before, "the original row is not modified in place");
    }

    /// File length != probed authoritative total -> re-download
    /// everything (the `.part` reuse verdict); when the probe length is
    /// unavailable (None) the comparison is skipped.
    #[test]
    fn part_length_mismatch_vs_probe_restarts() {
        let r = row(&[0, 1], 2 * BS as i64);
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: 8 * BS,
            },
            Some(9 * BS), // prealloc length differs from the probed total = wrong file
        );
        assert_eq!(
            rec.resumability,
            Resumability::FromZero {
                reason: ZeroReason::PartFileLengthMismatch
            }
        );
        // None = probe length unavailable -> skip the comparison; the
        // block-level check still runs.
        let rec2 = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: 8 * BS,
            },
            None,
        );
        assert_eq!(
            rec2.resumability,
            Resumability::FromBitmap { blocks_done: 2 }
        );
    }

    /// The prealloc shape: the file length always equals the
    /// authoritative total, so the size check always passes (the size
    /// check cannot cover the power-loss bitmap-data window — that is
    /// the pre-snapshot fsync's job; see the snapshot module's
    /// power-loss ordering injection tests). The row uses another
    /// in-domain granularity (4MiB) to exercise the domain face.
    #[test]
    fn prealloc_length_passes_size_check() {
        let mut r = row(&[0, 2], 0);
        r.block_size = 4 * 1024 * 1024;
        let bs = 4 * 1024 * 1024u64;
        let total = 8 * bs;
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: total,
            },
            Some(total),
        );
        assert_eq!(
            rec.resumability,
            Resumability::FromBitmap { blocks_done: 2 }
        );
        assert_eq!(rec.reverted_blocks, 0);
        assert_eq!(
            rec.row.total_done,
            2 * bs as i64,
            "block 2 is not the last block, accounted whole"
        );
    }

    /// Partial last block: total_done truncates to the authoritative
    /// total (the progress display never over-reports).
    #[test]
    fn last_partial_block_counts_actual_bytes() {
        // Total 7.5 blocks -> block_count 8; done {7} (a 0.5-block last
        // block). The prealloc full-length file = 7.5 blocks total; the
        // partial last block's effective end = the total.
        let r = row(&[7], BS as i64);
        let total = 7 * BS + 512;
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: total,
            },
            Some(total),
        );
        assert_eq!(rec.blocks_done, 1);
        assert_eq!(
            rec.row.total_done, 512,
            "the last block truncated to the authoritative total"
        );
        // No authoritative total (None): the partial last block is
        // judged conservatively at the whole-block boundary -> reverted
        // (the safe direction, re-download cost <= 1 block).
        let rec2 = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: total,
            },
            None,
        );
        assert_eq!(
            rec2.blocks_done, 0,
            "with no total length a partial last block conservatively rolls back"
        );
        assert_eq!(
            rec2.resumability,
            Resumability::FromZero {
                reason: ZeroReason::NoTrustedBlocks
            }
        );
        assert_eq!(rec2.reverted_blocks, 1);
    }

    /// Corrupt row shapes: granularity out of domain / bitmap and count
    /// unpaired / bitmap length mismatch -> RowCorrupt (never recover a
    /// sick row); a row without a bitmap -> NoBitmap.
    #[test]
    fn corrupt_rows_restart_with_reason() {
        // Block size out of domain (a power of two below the 256KiB
        // floor; in-domain non-powers get the same verdict).
        for bad in [1024i64, 3 * 1024 * 1024] {
            let mut r = row(&[], 0);
            r.block_size = bad;
            assert_eq!(
                recover_http_task(
                    &r,
                    PartFileFacts {
                        exists: true,
                        len: 0
                    },
                    None
                )
                .resumability,
                Resumability::FromZero {
                    reason: ZeroReason::RowCorrupt
                },
                "granularity {bad} must be judged corrupt"
            );
        }
        // Bitmap and count unpaired (one side missing).
        let mut r = row(&[0], 0);
        r.block_bitmap = None;
        assert_eq!(
            recover_http_task(
                &r,
                PartFileFacts {
                    exists: true,
                    len: 8 * BS
                },
                None
            )
            .resumability,
            Resumability::FromZero {
                reason: ZeroReason::NoBitmap
            }
        );
        let mut r = row(&[0], 0);
        r.block_count = None;
        assert_eq!(
            recover_http_task(
                &r,
                PartFileFacts {
                    exists: true,
                    len: 8 * BS
                },
                None
            )
            .resumability,
            Resumability::FromZero {
                reason: ZeroReason::RowCorrupt
            }
        );
        // Bitmap byte length inconsistent with block_count.
        let mut r = row(&[0], 0);
        r.block_bitmap = Some(vec![0u8; 7]);
        assert_eq!(
            recover_http_task(
                &r,
                PartFileFacts {
                    exists: true,
                    len: 8 * BS
                },
                None
            )
            .resumability,
            Resumability::FromZero {
                reason: ZeroReason::RowCorrupt
            }
        );
    }

    /// The all-lost shape: every completed block is out of range (the
    /// file was truncated before the first block) -> NoTrustedBlocks,
    /// with the reverted count reported accurately.
    #[test]
    fn fully_invalidated_bitmap_restarts() {
        let r = row(&[2, 5], 2 * BS as i64);
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: 512,
            },
            None,
        );
        assert_eq!(
            rec.resumability,
            Resumability::FromZero {
                reason: ZeroReason::NoTrustedBlocks
            }
        );
        assert_eq!(
            rec.reverted_blocks, 2,
            "total wipe = everything rolls back (the observation face states it accurately)"
        );
        assert!(rec.row.block_bitmap.is_none());
        assert_eq!(rec.row.total_done, 0);
    }

    /// Zero-block task (empty file): no progress face; recovery is the
    /// empty trusted state.
    #[test]
    fn zero_block_task_is_empty_trusted_state() {
        let mut r = row(&[], 0);
        r.block_bitmap = Some(Vec::new());
        r.block_count = Some(0);
        let rec = recover_http_task(
            &r,
            PartFileFacts {
                exists: true,
                len: 0,
            },
            None,
        );
        assert_eq!(
            rec.resumability,
            Resumability::FromBitmap { blocks_done: 0 }
        );
        assert_eq!(rec.blocks_total, 0);
    }

    /// Negative block_count boundary: a negative count is not a plan
    /// fact — with or without a bitmap (the pre-first-shot plan-state
    /// shape) both get RowCorrupt; a tampered row must not pass as the
    /// "empty trusted state".
    #[test]
    fn negative_block_count_is_row_corrupt_with_and_without_bitmap() {
        // With bitmap + negative count: the geometry check (count must
        // be >= 0) rejects first.
        let mut r = row(&[0], 0);
        r.block_count = Some(-3);
        assert_eq!(
            recover_http_task(
                &r,
                PartFileFacts {
                    exists: true,
                    len: 8 * BS
                },
                None
            )
            .resumability,
            Resumability::FromZero {
                reason: ZeroReason::RowCorrupt
            }
        );
        // No bitmap + negative count: the geometry check passes (the
        // bitmap never became legal), so the recovery side rejects
        // explicitly — it must not fall into the "0 blocks = empty
        // trusted state" branch.
        let mut r = row(&[], 0);
        r.block_bitmap = None;
        r.block_count = Some(-3);
        assert_eq!(
            recover_http_task(
                &r,
                PartFileFacts {
                    exists: true,
                    len: 0
                },
                None
            )
            .resumability,
            Resumability::FromZero {
                reason: ZeroReason::RowCorrupt
            }
        );
    }
}

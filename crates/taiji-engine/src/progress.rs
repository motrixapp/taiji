//! Progress and terminal event face: `Progress` (pipeline -> main
//! loop), `EngineEnd` (engine terminal states), torrent_progress
//! counter row assembly/persistence, and v2 bitmap encode/restore
//! (`encode_v2_file_bits`/`restore_progress_bits`).
//!
//! Upstream anchor mapping: docs/design/engine.md
//!
//! Owns: encoding, restoring, and persisting progress readings.
//! Does not own: advancing the bitmap in the in-memory model (the
//! caller's taiji_domain::progress::ProgressModel).

use tracing::{debug, warn};

use taiji_store::persist::{PersistOutcome, TorrentProgressRow};

use taiji_domain::progress::ProgressModel;

use std::sync::Arc;

use crate::config::FaceKind;
use crate::faces::FaceState;
use crate::tracker::TrackerPersistShared;
/// Engine terminal state.
#[derive(Debug)]
pub enum EngineEnd {
    /// Every face, every piece verified and written (returned when
    /// `seed_after_complete = false`).
    Completed,
    /// Download completed, seeded, then stopped by the shutdown signal
    /// (CLI Ctrl-C path).
    SeedStopped,
    /// A task running bt-detach-seed-only=true that finished downloading
    /// and moved to seed-only (SPEC §7.2: seed-only does not occupy a
    /// `--max-concurrent-downloads` concurrency slot). Distinguished
    /// from [`EngineEnd::SeedStopped`] by SessionActor bookkeeping: this
    /// group released its concurrency slot at completion (aria2
    /// `RequestGroup.cc` `enableSeedOnly` -> `decreaseNumActive()` +
    /// `requestQueueCheck()`; decided by
    /// [`taiji_domain::seed::seed_only_detached`]). The seeding-stop path
    /// (criteria met / shutdown signal) matches SeedStopped; only the
    /// returned variant differs.
    Detached,
    Failed(String),
    Cancelled,
}
/// Progress events from the store pipeline to the main loop (the
/// channel carries the face index; bounded at 16 x face count,
/// backpressure propagates to the block channel).
#[derive(Debug)]
pub enum Progress {
    /// Piece verified (**write still in flight**; set at hash-pass):
    /// drives HAVE broadcast + verified progress (libtorrent
    /// passed->have - advertise without waiting for the write, the
    /// pipeline-stall fix). Upload serving and persistence do not follow
    /// this event (see [`Progress::PieceWritten`] for the on-disk face).
    PieceVerified { index: u32 },
    /// Piece written to disk (the write half of the verify->write double
    /// confirmation): drives the written bitmap (upload gating release),
    /// persisted bitmap advance + face completion (libtorrent
    /// have->flushed's flushed half - the seeding full source reads disk
    /// ungated, so only full flushing may enter the seeding state).
    PieceWritten { index: u32 },
    /// Piece hash failure / cache eviction: drop and refetch. `digests`
    /// = per-block SHA-1 snapshots of the failed piece (smart_ban
    /// evidence; non-None only on the v1 whole-piece hash-failure path -
    /// the verify worker produces them before the job's cells are
    /// destroyed; eviction and other paths are None).
    PieceDropped {
        index: u32,
        reason: String,
        digests: Option<Arc<Vec<[u8; 20]>>>,
    },
    /// An unverified piece evicted from the write cache: data + digests
    /// were reset with the eviction; the piece still needs downloading.
    /// A separate variant from [`Progress::PieceDropped`] (hash failure,
    /// with attribution/ban paths) on purpose: eviction carries no "bad
    /// peer" semantics, only bookkeeping recovery (clear dispatch
    /// in-flight / buffered books, allow redispatch) - evictions used to
    /// be fully silent to the main loop.
    PieceEvicted { index: u32 },
    /// v2 per-block check failure: only this 16KiB refetches; the rest
    /// of the piece is unaffected.
    BlockRejected { index: u32, begin: u32, length: u32 },
    /// Block confirmed settled by the store pipeline (Buffered - bytes
    /// in the write cache; the basis of the dispatch face's redispatch
    /// window).
    BlockSettled { index: u32, begin: u32 },
    /// Batch block ack: settled coordinates aggregated by the pipeline
    /// and raised in one event - engine iterations drop from 1/block to
    /// 1/batch (<= 1/32 at the `BUFFER_BATCH_BLOCKS` batch depth).
    /// `settled` is order-preserving = pipeline submission order
    /// (intra-batch steps order); applying in order flips
    /// InFlight->Buffered in that order. Fallback seam:
    /// `BH_BLOCK_BATCH_ACK=0` returns to per-block
    /// [`Progress::BlockSettled`] granularity (variant kept).
    BlocksSettled { settled: Vec<(u32, u32)> },
    /// Fatal store error (allocation / disk IO / cross-check failure): torrent-level failure.
    Fatal(String),
}
/// torrent_progress counter row assembly (SPEC §5.3):
/// - `upload_at_startup` = this session's baseline (the restored value;
/// the schema comment "cumulative upload before this session", the
/// `.aria2` control file uploadLength semantics);
/// - `uploaded_total`/`downloaded_total` = baseline + session deltas
/// (cross-session totals);
/// - `active_time_s`/`seed_time_s` = baseline + session totals (1s tick);
/// - `v1_bitfield` = face 0's synthesized bitmap (v1/hybrid real bitmap,
/// v2 synthetic pseudo-bitmap, SPEC §4.4);
/// - `v2_file_bits` = the v2 face's per-file bitmap (encoding in
/// [`encode_v2_file_bits`]; the write side of the restore face).
///
/// **In-flight block bitmaps are not persisted (intentional
/// deviation)**: aria2's control file persists and restores in-flight
/// pieces (`DefaultBtProgressInfoFile.cc` writes in-flight segments and
/// calls `addInFlightPiece` on load); this engine's bitmaps record only
/// written (verify + write double-confirmed) pieces, so recovery loses
/// at most unconfirmed blocks - correctness is guaranteed by SPEC §5.2
/// verify-before-write.
#[expect(
    clippy::too_many_arguments,
    reason = "the row inputs are the persisted counter set; mirrors autosave_snapshot's shape"
)]
pub(super) fn progress_row(
    faces: &[FaceState],
    persist: Option<&TrackerPersistShared>,
    piece_len: u32,
    startup_uploaded: u64,
    startup_downloaded: u64,
    startup_active_s: u64,
    startup_seed_s: u64,
    session_up: u64,
    session_down: u64,
    active_secs: u64,
    seed_secs: u64,
) -> Option<TorrentProgressRow> {
    let p = persist?;
    // The persisted bitmap = written terms: v1_bitfield / v2_file_bits
    // read the written model - both halves of the "bitmap never ahead of
    // data" invariant: the content face records only verify+write
    // confirmed pieces (verified-but-unwritten pieces stay out; after a
    // crash they are treated as incomplete, no rollback face), and the
    // persistence face is backed by the write barrier (data fsync before
    // the row upsert - regular rows in run/tick.rs autosave_snapshot,
    // terminal rows in run/tail.rs final_flush; an outage bitmap can
    // only lag data, never run ahead). Advert/progress readings use each
    // face's verified model (faces.progress), kept apart from
    // persistence.
    let v1_bitfield = faces
        .first()
        .map(|f| f.written_bitfield_bytes())
        .filter(|b| !b.is_empty());
    let v2_file_bits = faces
        .iter()
        .find(|f| f.kind == FaceKind::V2)
        .and_then(|f| encode_v2_file_bits(&f.written_progress));
    Some(TorrentProgressRow {
        gid: p.gid.clone(),
        piece_length: i64::from(piece_len),
        v1_bitfield,
        v2_file_bits,
        upload_at_startup: startup_uploaded.min(i64::MAX as u64) as i64,
        downloaded_total: startup_downloaded
            .saturating_add(session_down)
            .min(i64::MAX as u64) as i64,
        uploaded_total: startup_uploaded
            .saturating_add(session_up)
            .min(i64::MAX as u64) as i64,
        active_time_s: startup_active_s
            .saturating_add(active_secs)
            .min(i64::MAX as u64) as i64,
        seed_time_s: startup_seed_s
            .saturating_add(seed_secs)
            .min(i64::MAX as u64) as i64,
    })
}

/// v2_file_bits encoding (the `torrent_progress.v2_file_bits` BLOB
/// format; [`restore_progress_bits`] is its dual): per file
/// `[u32 BE file_index][u32 BE piece_count][ceil(count/8) B bitmap]`
/// concatenated, bit order matching [`ProgressModel`] (MSB first).
/// Files with 0 pieces encode as empty bitmap entries (file_index
/// alignment kept). All files at 0 pieces (empty torrent, unreachable
/// state) -> None.
pub(super) fn encode_v2_file_bits(progress: &ProgressModel) -> Option<Vec<u8>> {
    if progress.files.iter().all(|f| f.piece_count == 0) {
        return None;
    }
    let mut out = Vec::new();
    for (fi, f) in progress.files.iter().enumerate() {
        out.extend_from_slice(&(fi as u32).to_be_bytes());
        out.extend_from_slice(&(f.piece_count as u32).to_be_bytes());
        out.extend_from_slice(&f.pieces);
    }
    Some(out)
}

/// Bitmap restore (SPEC §5.4 "skip recheck when the progress bitmap is
/// trustworthy" fast-start path). `v2_file_bits` (authoritative
/// per-file) first; missing, fall back to the `v1_bitfield` synthesized
/// global bitmap - under BEP52 alignment a global coordinate is
/// cross-face synonymous (hybrid faces have equal piece counts, k <-> k;
/// proven by [`crate::faces::on_piece_verified`] cross-face
/// propagation). **In-flight block bitmaps are not restored
/// (intentional deviation - the evidence and rationale live in the
/// `progress_row` docs)**. Returns the restored verified piece count
/// (the face `verified_count` initial value, the completion-decision
/// basis).
pub(super) fn restore_progress_bits(
    progress: &mut ProgressModel,
    v1_bitfield: Option<&[u8]>,
    v2_file_bits: Option<&[u8]>,
) -> usize {
    let mut restored: u64 = 0;
    match v2_file_bits {
        Some(bits) => {
            let mut cur = bits;
            while cur.len() >= 8 {
                let file_index = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]) as usize;
                let count = u32::from_be_bytes([cur[4], cur[5], cur[6], cur[7]]) as u64;
                let bytes = count.div_ceil(8) as usize;
                if cur.len() < 8 + bytes {
                    break; // truncated tail segment: dropped defensively as a corrupt payload (the writer never produces this)
                }
                let bf = &cur[8..8 + bytes];
                // Out-of-range file_index (corrupt/alien payload): drop the
                // whole segment - the model has no such file, sets are
                // no-ops, the count cannot inflate.
                if file_index < progress.files.len() {
                    for i in 0..count {
                        if bf[(i / 8) as usize] & (0x80 >> (i % 8)) != 0
                            && !progress.piece_done(file_index, i)
                        {
                            progress.set_piece_done(file_index, i);
                            restored += 1;
                        }
                    }
                }
                cur = &cur[8 + bytes..];
            }
        }
        None => {
            if let Some(bits) = v1_bitfield {
                for k in 0..(bits.len() as u64 * 8) {
                    if bits[(k / 8) as usize] & (0x80 >> (k % 8)) != 0
                        && !progress.piece_done_global(k)
                    {
                        progress.set_piece_done_global(k);
                        restored += 1;
                    }
                }
            }
        }
    }
    restored as usize
}

/// Counter row persistence (digest dedup skip-write kept; failures only
/// warn - the counter face is not correctness data, matching aria2's
/// tolerance of control-file save failures).
/// Returns true = the row is persisted (Written or SkippedUnchanged -
/// both mean "the stored bitmap = this row's bitmap"); false = not
/// persisted (no persist face / no row / write failed - the dirty-flag
/// clear only accepts true; a write failure keeps the face dirty for the
/// next barrier round).
pub(super) async fn flush_progress_row(
    persist: Option<&TrackerPersistShared>,
    row: Option<TorrentProgressRow>,
) -> bool {
    let (Some(p), Some(row)) = (persist, row) else {
        return false;
    };
    match p.handle.upsert_torrent_progress(row).await {
        Ok(PersistOutcome::Written) => {
            debug!(target: "taiji::core::engine", gid = %p.gid,
                "torrent progress row written")
        }
        Ok(PersistOutcome::SkippedUnchanged) => {}
        Err(e) => {
            warn!(target: "taiji::core::engine", gid = %p.gid, %e,
                "torrent progress persist failed");
            return false;
        }
    }
    true
}

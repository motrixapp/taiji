//! Startup recheck: the on-disk verification entry for rows restored
//! with `torrent.state = 'checking'` (checking-state re-entry).
//!
//! Semantics: rebuild the layout and expected hashes from the restored
//! row's metadata, verify piece by piece from disk (v1 whole-piece
//! SHA-1 / v2 block-level Merkle to the piece root), and rebuild the
//! bitmap from **measured** results — verified pieces are kept (not
//! re-downloaded), failed/missing pieces are cleared (re-downloaded),
//! count history untouched. The session actor advances the row state
//! and requeues at the RecheckDone consume (finish_recheck; the
//! bootstrap 'checking' rows ride the same
//! budget-gated path — parked into check_pending, promoted within
//! max-concurrent-checks, the same RecheckDone write-back + routing).
//!
//! Relation to aria2: the reference recheck goes through
//! CheckIntegrityEntry (verify when the file exists and the bitmap is
//! untrusted, then requeue); this entry is triggered by row state
//! (importer degradation / user-set checking), and the default
//! fast-start path (trusted bitmap skips recheck) is unchanged. Pure
//! functions except for disk reads; the caller must `spawn_blocking`
//! (per-piece pread + hashing is a blocking face).
//!
//! Suspend / re-entry boundary (missing piece layers):
//! docs/design/core.md.
//!
//! Upstream anchor mapping: docs/design/core.md

use std::path::Path;

use bytes::Bytes;
use sha1::{Digest as _, Sha1};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::merkle;
use taiji_store::torrent_writer::TorrentReader;

use crate::engine::{FaceConfig, FaceKind};
use crate::metainfo::Metainfo;

/// Single-file recovery-layer re-entry payload: layer bytes read back
/// from the derived tables (the caller may pre-validate via the
/// `session::persist::recovery` assembly; the re-entry path here
/// re-validates for convergence — defense in depth, a bad row only
/// affects its own file and falls back to suspended).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFileLayer {
    /// TorrentMeta.files index (= torrent_file.file_index).
    pub file_index: u32,
    /// Raw recovered piece-layer hash bytes (32 B x piece count).
    pub layer: Vec<u8>,
}

/// Recheck result: the measured bitmap (written back to
/// `torrent_progress`) and statistics (log face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecheckOutcome {
    /// v1/hybrid global piece bitmap (face 0 measured; v2-only = None).
    pub v1_bitfield: Option<Vec<u8>>,
    /// v2-only per-file bitmap (same format as
    /// `engine::encode_v2_file_bits`: `[u32 file_index][u32
    /// piece_count][bits]` concatenated; hybrid = None — the restore
    /// face back-fills both faces from the v1 bitmap, BEP52 k<->k).
    /// Entries of suspended files are all-zero bits — **not** a
    /// measured failure; the caller preserves the previous session's
    /// values via [`preserve_suspended_v2_bits`].
    pub v2_file_bits: Option<Vec<u8>>,
    /// Verified piece count (suspended pieces not counted — neither
    /// passed nor failed).
    pub verified: usize,
    /// Total piece count (face-0 basis).
    pub total: usize,
    /// Suspend boundary: the set of v2 files missing a piece layer with
    /// no valid recovery layer this pass (file_index ascending). Their
    /// pieces are not failed and not cleared; a later recheck re-entry
    /// fills them in once the layer arrives. Always empty for
    /// v1/hybrid (the v1 face's expectations are complete — no
    /// suspension concept).
    pub suspended_files: Vec<u32>,
}

/// Measured-bitmap completeness over a recheck outcome (the RecheckDone
/// routing predicate): the task's on-disk content
/// measured **fully verified** — the checking→seeding transfer edge's
/// condition (full → the seed side direct: seed slot or seed_wait,
/// never the reserved download-slot detour; not full → requeue
/// reserved). Piece geometry comes from the metainfo (the outcome
/// carries no piece-length field; the recheck ran under this geometry
/// by construction).
///
/// Predicate structure mirrors the persisted-row routing dual
/// (`lifecycle::progress_row_complete`, the routing dual):
/// - v2-only (`v2_file_bits` present): every non-padding file's piece
/// range fully set in its stored segment (a missing segment or a
/// stored count below the expected piece count = incomplete);
/// - else v1/hybrid (`v1_bitfield` present): every global piece index
/// set (a short/absent bitfield = incomplete — the same conservative
/// read as `bit_set`'s out-of-bounds face);
/// - neither present = incomplete;
/// - any suspended file = incomplete (its bits are all-zero
/// placeholders — unmeasured content must not route to the seed
/// side).
///
/// The `verified`/`total` counters are log faces, not the predicate:
/// the bitmap is authoritative (the counters exclude suspended pieces,
/// so a complete outcome and `verified == total` agree only when
/// nothing is suspended — the bitmap branch above is the single
/// source).
pub fn recheck_outcome_complete(meta: &crate::metainfo::TorrentMeta, o: &RecheckOutcome) -> bool {
    if !o.suspended_files.is_empty() {
        return false;
    }
    let piece_len = u64::from(meta.piece_length);
    if piece_len == 0 {
        return false;
    }
    let bit_set = |bytes: &[u8], i: u64| {
        bytes
            .get((i / 8) as usize)
            .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
    };
    if let Some(bits) = o.v2_file_bits.as_deref() {
        for (fi, f) in meta.files.iter().enumerate() {
            if f.padding {
                continue;
            }
            let expected = f.length.div_ceil(piece_len);
            if expected == 0 {
                continue;
            }
            let mut cur = bits;
            let mut file_ok = false;
            while cur.len() >= 8 {
                let file_index = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]) as usize;
                let count = u32::from_be_bytes([cur[4], cur[5], cur[6], cur[7]]) as u64;
                let bytes = count.div_ceil(8) as usize;
                if cur.len() < 8 + bytes {
                    break;
                }
                if file_index == fi {
                    file_ok =
                        count >= expected && (0..expected).all(|i| bit_set(&cur[8..8 + bytes], i));
                    break;
                }
                cur = &cur[8 + bytes..];
            }
            if !file_ok {
                return false;
            }
        }
        return true;
    }
    if let Some(bits) = o.v1_bitfield.as_deref() {
        let total_len: u64 = meta.files.iter().map(|f| f.length).sum();
        let total_pieces = total_len.div_ceil(piece_len);
        if total_pieces == 0 {
            return false;
        }
        return (0..total_pieces).all(|i| bit_set(bits, i));
    }
    false
}

/// On-disk recheck (blocking: per-piece pread + hashing; the caller
/// spawns it on a blocking thread).
///
/// Construction failure (invalid layout / hash face) = Err -> the
/// caller clears the bitmap and re-downloads from scratch; a
/// single-piece read failure = that piece counts as not passed (a
/// missing file = the empty-store shape, not a fatal error).
///
/// Standard entry (the run chain always goes through
/// [`recheck_on_disk_recovering`]; this 2-arg signature is the contract
/// face pinned by existing vector tests — the suspend boundary is
/// reported identically when there is no recovery-layer data; semantics
/// only added, never changed).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "contract face pinned by the vector tests; no production caller"
    )
)]
pub fn recheck_on_disk(meta: &Metainfo, dir: &Path) -> Result<RecheckOutcome, String> {
    recheck_on_disk_recovering(meta, dir, &[])
}

/// On-disk recheck with a recovery-layer read-back set (the startup
/// recovery entry + run-time re-entry): layers from `recovered` that
/// **pass convergence re-validation** are merged into the metadata
/// (same admission semantics — the same trust level as metadata-borne
/// layers) and verified at full configuration; rows failing
/// re-validation (hand-tampered / stale rows in the store) fall back to
/// suspended — never full-configured while in doubt; the file stays
/// layer-gated and the swarm re-pulls (after convergence the new layer
/// overwrites the store through the admission face).
pub fn recheck_on_disk_recovering(
    meta: &Metainfo,
    dir: &Path,
    recovered: &[RecoveredFileLayer],
) -> Result<RecheckOutcome, String> {
    recheck_on_disk_recovering_with_progress(meta, dir, recovered, None)
}

/// Progress-observing variant of [`Self::recheck_on_disk_recovering`]:
/// when `progress` is present, each completed piece verdict does
/// `fetch_add(1)` (piece-count basis — the caller projects bytes via
/// piece_length for the tellStatus completedLength; aria2's
/// verification-period completedLength = bytes checked so far, same
/// direction). Semantics identical to the base function word for word;
/// observation only.
pub fn recheck_on_disk_recovering_with_progress(
    meta: &Metainfo,
    dir: &Path,
    recovered: &[RecoveredFileLayer],
    progress: Option<&std::sync::atomic::AtomicU64>,
) -> Result<RecheckOutcome, String> {
    // Recovery-layer merge (per file, independent: a bad row does not
    // block the other files). Only applies to files "missing a layer
    // and carrying a pieces root" — metadata-borne layers are never
    // replaced (their own trust level).
    let piece_len = meta.meta.piece_length;
    let mut patched = meta.clone();
    let mut admitted = 0usize;
    let mut invalid = 0usize;
    for rec in recovered {
        let Some(f) = patched.meta.files.get_mut(rec.file_index as usize) else {
            invalid += 1;
            continue;
        };
        if !f.layer_missing(piece_len) {
            // Full / single-block / root-less files: no re-entry
            // semantics (layer in place or the root is the leaf); the
            // row is discarded.
            invalid += 1;
            continue;
        }
        let Some(root) = f.pieces_root else {
            invalid += 1;
            continue;
        };
        // Admission criterion, same source: entry count + root
        // convergence (the same function bt::filetree uses to load
        // metadata layers). Failure = the row is not merged (the file
        // stays suspended, swarm re-pull).
        if merkle::validate_piece_layer(&root, &rec.layer, f.length, piece_len).is_err() {
            invalid += 1;
            continue;
        }
        f.piece_layer = Some(Bytes::from(rec.layer.clone()));
        admitted += 1;
    }
    if admitted > 0 || invalid > 0 {
        // Observation face: re-validation results are never silent.
        tracing::debug!(target: "taiji::core::session",
            admitted, invalid, total = recovered.len(),
            "recheck recovering: persisted layers re-validated (semantics)");
    }

    // Layout / expected-hash face assembly (pure CPU): reuses
    // engine_config's face construction (piece_goffs/piece_bytes/
    // expected share the source with the download face — no second set
    // of bookkeeping).
    let mut cfg = crate::engine::engine_config(
        &patched,
        dir.to_path_buf(),
        0,
        [0u8; 20],
        crate::engine::CompletionMode::ReturnOnComplete,
    )
    .map_err(|e| format!("recheck: face build failed: {e}"))?;
    let piece_len = cfg.piece_len;
    let reader = TorrentReader::new(cfg.layout.clone(), dir.to_path_buf());
    let face = cfg
        .faces
        .first_mut()
        .ok_or_else(|| "recheck: no swarm face".to_string())?;
    // Suspend set = files still missing a layer after the merge (v2
    // face only — a missing layer's expected root can only be a
    // placeholder; the v1 face's expectations are complete). Bit order
    // = meta.files order (the v2-only face plan expands from the same
    // source).
    let suspended_files: Vec<u32> = if face.kind == FaceKind::V2 {
        patched
            .meta
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| f.layer_missing(piece_len))
            .map(|(i, _)| i as u32)
            .collect()
    } else {
        Vec::new()
    };
    let bits = verify_face(&reader, face, piece_len, progress)?;
    let total = bits.len();
    let verified = bits.iter().filter(|b| **b).count();
    let (v1_bitfield, v2_file_bits) = match face.kind {
        // v1/hybrid: face 0 = the v1 face (hybrid faces have equal
        // piece counts k<->k; the restore face back-fills both faces
        // from the v1 bitmap — the engine::restore_progress_bits
        // fallback path).
        FaceKind::V1 => (Some(pack_bits(&bits)), None),
        // v2-only: the restore face's authority = v2_file_bits (fold
        // the flat measured bits per file).
        FaceKind::V2 => (None, Some(encode_v2_file_bits(&bits, face, piece_len))),
    };
    Ok(RecheckOutcome {
        v1_bitfield,
        v2_file_bits,
        verified,
        total,
        suspended_files,
    })
}

/// Suspended-preserving merge: entries of suspended files in the
/// measured bitmap (all zeros) are replaced with the **previous
/// session's values** (never clear on suspend — on-disk facts are not
/// erased before review; until the layer arrives, re-entry completion
/// or gating the file out of service is the backstop); non-suspended
/// entries follow this pass's measurement. No matching prev entry
/// (first verification / foreign payload) -> keep the measurement (all
/// zeros).
pub fn preserve_suspended_v2_bits(
    new_bits: &mut Option<Vec<u8>>,
    prev_bits: Option<&[u8]>,
    suspended: &[u32],
) {
    let (Some(new), Some(prev)) = (new_bits.as_mut(), prev_bits) else {
        return;
    };
    for &file_index in suspended {
        // Locate the prev entry ([u32 fi][u32 count][bits]
        // concatenation).
        let Some((count, prev_seg)) = find_entry(prev, file_index) else {
            continue;
        };
        // Rewrite the new entry (entry length is determined by the
        // piece count, same meta = same length — mismatched foreign
        // payloads are defensively skipped; truncated payloads are
        // skipped too, never written out of bounds).
        if let Some((new_count, at)) = find_entry_pos(new, file_index) {
            let nbytes = count.div_ceil(8) as usize;
            if new_count != count || at + 8 + nbytes > new.len() {
                continue;
            }
            new[at + 8..at + 8 + nbytes].copy_from_slice(prev_seg);
        }
    }
}

/// Concatenated-encoding entry lookup: (count, bits slice).
fn find_entry(enc: &[u8], file_index: u32) -> Option<(u32, &[u8])> {
    let (count, at) = find_entry_pos(enc, file_index)?;
    let nbytes = count.div_ceil(8) as usize;
    Some((count, enc.get(at + 8..at + 8 + nbytes)?))
}

/// Concatenated-encoding entry location: (count, entry start offset).
fn find_entry_pos(enc: &[u8], file_index: u32) -> Option<(u32, usize)> {
    let mut cur = 0usize;
    while cur + 8 <= enc.len() {
        let fi = u32::from_be_bytes([enc[cur], enc[cur + 1], enc[cur + 2], enc[cur + 3]]);
        let count = u32::from_be_bytes([enc[cur + 4], enc[cur + 5], enc[cur + 6], enc[cur + 7]]);
        let nbytes = count.div_ceil(8) as usize;
        if fi == file_index {
            return Some((count, cur));
        }
        cur += 8 + nbytes;
    }
    None
}

/// Per-piece on-disk verification. Returns measured bits in face flat
/// order.
///
/// The v2 tree rule dispatches on **the piece count of the file owning
/// the piece** (aligned with the verified.rs `piece_matches` dispatch
/// and the hashpool.rs `single_piece_file` field docs; current BEP52
/// text + the official creator): a file of exactly 1 piece -> pad
/// leaves to the **actual block count**'s power of two
/// ([`merkle::root_from_block_hashes`]); a file of more than 1 piece
/// (including a short tail piece) -> pad to blocks_per_piece
/// ([`merkle::piece_root_from_block_hashes`]). The two rules give
/// different roots; unifying on either would misjudge (short tail
/// pieces of multi-piece files / non-power-of-two block counts of
/// single-piece files).
///
/// Ownership is derived by expanding the `face.plan_file_lengths`
/// cursor (the same walk as file-order DFS and
/// [`encode_v2_file_bits`]; empty files with 0 pieces skip naturally);
/// the expanded total must equal `face.expected.len()`, otherwise Err
/// (layout self-consistency gate).
///
/// `progress` present = count +1 as soon as each piece verdict
/// completes (failed pieces included — the count means "checked", not
/// "passed"; the caller's byte projection takes a min clamp).
fn verify_face(
    reader: &TorrentReader,
    face: &FaceConfig,
    piece_len: u32,
    progress: Option<&std::sync::atomic::AtomicU64>,
) -> Result<Vec<bool>, String> {
    if face.piece_goffs.len() != face.piece_bytes.len()
        || face.piece_goffs.len() != face.expected.len()
    {
        return Err("recheck: face plan length mismatch".to_string());
    }
    let mut single_piece = Vec::with_capacity(face.expected.len());
    for &len in &face.plan_file_lengths {
        let pieces = len.div_ceil(u64::from(piece_len)) as usize;
        single_piece.extend(std::iter::repeat_n(pieces == 1, pieces));
    }
    if single_piece.len() != face.expected.len() {
        return Err(format!(
            "recheck: file plan expands to {} pieces, face expects {}",
            single_piece.len(),
            face.expected.len()
        ));
    }
    let bpp = (piece_len / merkle::BLOCK_SIZE) as usize;
    let mut bits = Vec::with_capacity(face.expected.len());
    for (k, expected) in face.expected.iter().enumerate() {
        let goff = face.piece_goffs[k];
        let len = face.piece_bytes[k] as usize;
        let mut buf = vec![0u8; len];
        // Short read / missing file = not passed (TorrentReader
        // zero-fills sparse EOF, and an all-zero piece naturally
        // mismatches a non-zero hash; an explicit short read here also
        // counts as not passed — no gray zone).
        let ok = match reader.read_at(goff, &mut buf) {
            Ok(n) if n == len => match expected {
                ExpectedPieceHash::V1(h) => Sha1::digest(&buf).as_slice() == h.as_slice(),
                ExpectedPieceHash::V2(root) => {
                    // Block hashes cut the buf at its actual length
                    // (short tail piece n < bpp); zero padding is
                    // handled inside the two root functions (the BEP52
                    // zero-leaf rule) — hand-written padding is
                    // forbidden here.
                    let blocks: Vec<[u8; 32]> = buf
                        .chunks(merkle::BLOCK_SIZE as usize)
                        .map(merkle::block_hash)
                        .collect();
                    let got = if single_piece[k] {
                        merkle::root_from_block_hashes(&blocks)
                    } else {
                        merkle::piece_root_from_block_hashes(&blocks, bpp)
                    };
                    got == *root
                }
            },
            _ => false,
        };
        if let Some(p) = progress {
            p.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        bits.push(ok);
    }
    Ok(bits)
}

/// Compact bytes (big-endian bit order MSB first, trailing bits 0 —
/// the BEP3 wire convention, same shape as the engine's stored
/// bitmap).
fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            out[i / 8] |= 0x80 >> (i % 8);
        }
    }
    out
}

/// v2 flat measured bits -> per-file concatenation.
/// `face.plan_file_lengths` order = meta.files DFS order (the v2 face
/// build shares the source); each file's piece count =
/// ceil(len/piece_len), matching the flat plan's expansion order — just
/// slice in sequence.
fn encode_v2_file_bits(bits: &[bool], face: &FaceConfig, piece_len: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    for (fi, len) in face.plan_file_lengths.iter().enumerate() {
        let pieces = (*len).div_ceil(u64::from(piece_len)) as usize;
        let end = (cursor + pieces).min(bits.len());
        let file_bits = bits.get(cursor..end).unwrap_or(&[]);
        out.extend_from_slice(&(fi as u32).to_be_bytes());
        out.extend_from_slice(&(file_bits.len() as u32).to_be_bytes());
        out.extend_from_slice(&pack_bits(file_bits));
        cursor = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pack_bits: MSB first + trailing bits 0.
    #[test]
    fn pack_bits_msb_first() {
        assert_eq!(pack_bits(&[]), Vec::<u8>::new());
        assert_eq!(pack_bits(&[true, false, false]), vec![0b1000_0000]);
        assert_eq!(pack_bits(&[true; 8]), vec![0xff]);
        assert_eq!(pack_bits(&[true; 9]), vec![0xff, 0b1000_0000]);
    }

    /// encode_v2_file_bits: per-file `[index][count][bits]`
    /// concatenation + an empty bitmap entry for empty files
    /// (compatible with the engine::encode_v2_file_bits restore dual).
    #[test]
    fn v2_encoding_splits_flat_bits_per_file() {
        use crate::engine::FaceKind;
        let face = FaceConfig {
            kind: FaceKind::V2,
            info_hash: [0u8; 20],
            reserved: taiji_bt::peer_wire::Reserved::aria2_default(),
            addressing: taiji_bt::piece_id::Addressing::Flat,
            piece_goffs: Vec::new(),
            piece_bytes: Vec::new(),
            expected: Vec::new(),
            plan_file_lengths: vec![2 * 16384, 16384, 0],
            progress_file_lens: Vec::new(),
            cross: Vec::new(),
            hash_files: None,
        };
        let bits = vec![true, true, false, true, false, false];
        let enc = encode_v2_file_bits(&bits, &face, 16384);
        // file0: 2 pieces [1,1]; file1: 1 piece [0]; file2: 0 pieces,
        // empty (leftover bits beyond the plan are not encoded —
        // unreachable when the face plan is self-consistent).
        assert_eq!(
            enc,
            [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                2,
                0b1100_0000, // file0
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                1,
                0b0000_0000, // file1
                0,
                0,
                0,
                2,
                0,
                0,
                0,
                0, // file2 empty bitmap
            ]
        );
    }

    // ==== v2 tree-rule dispatch (verify_face), four vectors ====
    //
    // Fixture construction follows the build_v2_only_torrent precedent
    // of tests/dual_swarm.rs (local BEP52 metainfo; the piece-layers
    // load validation must pass). Expected roots are built with
    // merkle::file_root / piece_root_from_block_hashes (the
    // authoritative BEP52 tree shapes), so any deviation in the
    // recheck-side tree rule misjudges as failure.

    use std::path::PathBuf;
    use taiji_bt::bencode::{self, Value};

    /// piece length 128 KiB -> blocks_per_piece = 8 (power of two >=
    /// 16 KiB, BEP52).
    const PIECE: u32 = 128 * 1024;
    const B: usize = merkle::BLOCK_SIZE as usize;
    /// Blocks per piece paired with [`PIECE`] (explicit test constant,
    /// used in vector descriptions).
    const BPP: usize = (128 * 1024) / (16 * 1024);

    fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e:?}"),
        }
    }

    fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
        pairs.sort_by(|a, b| a.0.cmp(b.0));
        Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
    }

    /// dict with dynamic keys (32 B root): bencode dict keys must be in
    /// byte order (strict decode).
    fn dict_dyn(mut pairs: Vec<(Vec<u8>, Value)>) -> Value {
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Dict(pairs)
    }

    /// Deterministic non-zero content (an all-zero piece would blur
    /// into the "missing file sparse zeros" path and weaken the
    /// vectors).
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 + 1).collect()
    }

    /// Three-file vector face (DFS order = dict key byte order: empty
    /// < multi < single):
    /// - `data/empty.bin`: 0 pieces (the plan_file_lengths cursor
    /// skips naturally);
    /// - `data/multi.bin`: 2 pieces — piece 0 = a full 8-block piece
    /// (n == bpp); piece 1 = a 2-block short tail (n = 2 < bpp/2,
    /// the two tree shapes must differ);
    /// - `data/single.bin`: 1 piece of 3 blocks (a non-power-of-two
    /// block count; a file of <= 1 piece is independent of the piece
    /// boundary — BEP52 "padded to the next power of two instead of
    /// the next piece boundary").
    fn fixture_files() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty.bin", Vec::new()),
            ("multi.bin", pattern(PIECE as usize + 2 * B)),
            ("single.bin", pattern(3 * B)),
        ]
    }

    /// v2-only multi-file metainfo (single-level directory "data").
    fn build_v2_only_torrent(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut tree = Vec::new();
        let mut layers = Vec::new();
        for (name, content) in files {
            let mut props: Vec<(&[u8], Value)> =
                vec![(b"length", Value::Int(content.len() as i64))];
            if !content.is_empty() {
                let leaves: Vec<[u8; 32]> = content.chunks(B).map(merkle::block_hash).collect();
                let root = ok(merkle::file_root(&leaves, PIECE), "file_root");
                props.push((b"pieces root", Value::Bytes(root.to_vec())));
                // The piece layers entry is only needed for files of
                // more than 1 piece (BEP52: files <= piece size have no
                // entry; empty files have no pieces root for the same
                // reason).
                if content.len() > PIECE as usize {
                    let layer: Vec<u8> = leaves
                        .chunks(BPP)
                        .flat_map(|c| merkle::piece_root_from_block_hashes(c, BPP))
                        .collect();
                    layers.push((root.to_vec(), Value::Bytes(layer)));
                }
            }
            tree.push((name.as_bytes().to_vec(), dict(vec![(b"", dict(props))])));
        }
        let info = dict(vec![
            (
                b"file tree",
                dict_dyn(vec![(b"data".to_vec(), dict_dyn(tree))]),
            ),
            (b"meta version", Value::Int(2)),
            (b"piece length", Value::Int(i64::from(PIECE))),
        ]);
        let top = dict(vec![
            (
                b"announce",
                Value::Bytes(b"http://127.0.0.1:9/announce".to_vec()),
            ),
            (b"info", info),
            (b"piece layers", dict_dyn(layers)),
        ]);
        ok(bencode::encode(&top), "encode")
    }

    /// On-disk payload write (<dir>/data/<name>; the v2-only compact
    /// layout = DFS concatenation).
    fn write_payload(dir: &Path, files: &[(&str, Vec<u8>)]) {
        for (name, data) in files {
            let p = dir.join("data").join(name);
            if let Some(parent) = p.parent() {
                ok(std::fs::create_dir_all(parent), "mkdir");
            }
            ok(std::fs::write(&p, data), "write payload");
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bh-p99-{tag}-{}", std::process::id()))
    }

    /// Standard vector payload: fixture written to disk (data intact)
    /// -> recheck.
    fn recheck_fixture(dir: &Path) -> RecheckOutcome {
        let files = fixture_files();
        let raw = build_v2_only_torrent(&files);
        let meta = ok(Metainfo::parse(&raw), "parse");
        write_payload(dir, &files);
        ok(recheck_on_disk(&meta, dir), "recheck_on_disk")
    }

    /// v2_file_bits decode (same format as engine::encode_v2_file_bits:
    /// `[u32 file_index][u32 piece_count][bits]` concatenation).
    fn decode_v2_file_bits(enc: &[u8]) -> Vec<(u32, Vec<bool>)> {
        fn be32(enc: &[u8], at: usize) -> u32 {
            enc.get(at..at + 4)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .map(u32::from_be_bytes)
                .unwrap_or(0)
        }
        let mut out = Vec::new();
        let mut cur = 0usize;
        while cur + 8 <= enc.len() {
            let fi = be32(enc, cur);
            let count = be32(enc, cur + 4) as usize;
            cur += 8;
            let nbytes = count.div_ceil(8);
            let bytes = enc.get(cur..cur + nbytes).unwrap_or(&[]);
            let bits: Vec<bool> = (0..count)
                .map(|i| bytes[i / 8] & (0x80 >> (i % 8)) != 0)
                .collect();
            out.push((fi, bits));
            cur += nbytes;
        }
        out
    }

    /// Expected full picture for an intact vector payload: empty 0
    /// pieces, multi [T,T], single [T].
    fn expect_all_pass(outcome: &RecheckOutcome) {
        assert_eq!(outcome.total, 3);
        assert_eq!(outcome.verified, 3);
        assert!(
            outcome.v1_bitfield.is_none(),
            "v2-only carries no v1 bitfield"
        );
        let enc = outcome.v2_file_bits.clone().unwrap_or_default();
        assert_eq!(
            decode_v2_file_bits(&enc),
            vec![(0, vec![]), (1, vec![true, true]), (2, vec![true])]
        );
    }

    /// Vector a (the main fix target): a multi-piece file's short tail
    /// piece (2 blocks < bpp/2 = 4) went from misjudged to passing.
    /// Before the fix, verify_face unified on `root_from_block_hashes`
    /// (padded to next_pow2(2) = 2 leaves), which necessarily differs
    /// from the metadata tree shape (padded to bpp = 8 leaves, the
    /// hashpool authoritative dispatch) -> that piece was always
    /// misjudged as failed -> a clear-and-redownload loop that never
    /// ends.
    #[test]
    fn v2_multipiece_short_tail_piece_passes() {
        let dir = temp_dir("short-tail");
        let outcome = recheck_fixture(&dir);
        expect_all_pass(&outcome);
        // Vector sensitivity self-check (guards against the fixture
        // degrading into a non-discriminating vector): a 2-block tail
        // piece must have different roots under the two tree rules —
        // this is the precondition for the bug to bite, and this
        // vector's discriminating power.
        let tail: Vec<[u8; 32]> = fixture_files()[1]
            .1
            .chunks(B)
            .skip(PIECE as usize / B)
            .map(merkle::block_hash)
            .collect();
        assert_eq!(tail.len(), 2);
        assert_ne!(
            merkle::root_from_block_hashes(&tail),
            merkle::piece_root_from_block_hashes(&tail, BPP)
        );
    }

    /// Vector b: a single-piece file (non-power-of-two block count, 3
    /// blocks) still passes. BEP52: a file of <= 1 piece pads the tree
    /// to the **block count**'s power of two (independent of piece
    /// size) — a dispatch that wrongly applies the piece_root rule
    /// (padded to bpp = 8) fails this vector (discriminating power:
    /// next_pow2(3) = 4 != bpp = 8; the two rules give different
    /// roots).
    #[test]
    fn v2_single_piece_file_nonpow2_blocks_passes() {
        let dir = temp_dir("single-nonpow2");
        let outcome = recheck_fixture(&dir);
        expect_all_pass(&outcome);
        let single: Vec<[u8; 32]> = fixture_files()[2]
            .1
            .chunks(B)
            .map(merkle::block_hash)
            .collect();
        assert_eq!(single.len(), 3);
        assert_ne!(
            merkle::root_from_block_hashes(&single),
            merkle::piece_root_from_block_hashes(&single, BPP)
        );
    }

    /// Vector c: a multi-piece file's full piece (n == bpp, 8 blocks)
    /// still passes (the two rules always share the root on a full
    /// piece — a regression guard).
    #[test]
    fn v2_multipiece_full_piece_passes() {
        let dir = temp_dir("full-piece");
        let outcome = recheck_fixture(&dir);
        expect_all_pass(&outcome);
    }

    /// Vector d: a corrupted piece still fails (guards against a fix
    /// that turns checks always-true). The corruption is injected
    /// inside the short tail piece (exactly the fix target) — after the
    /// fix that piece must still fail, the other pieces unaffected.
    #[test]
    fn v2_corrupted_short_tail_piece_still_fails() {
        let dir = temp_dir("corrupt-tail");
        let files = fixture_files();
        let raw = build_v2_only_torrent(&files);
        let meta = ok(Metainfo::parse(&raw), "parse");
        write_payload(&dir, &files);
        let mut tail = files[1].1.clone();
        let at = PIECE as usize + B; // multi.bin piece 1 (short tail), within block 2
        tail[at] ^= 0xff;
        ok(
            std::fs::write(dir.join("data").join("multi.bin"), &tail),
            "corrupt",
        );
        let outcome = ok(recheck_on_disk(&meta, &dir), "recheck_on_disk");
        assert_eq!(outcome.total, 3);
        assert_eq!(outcome.verified, 2);
        let enc = outcome.v2_file_bits.clone().unwrap_or_default();
        assert_eq!(
            decode_v2_file_bits(&enc),
            vec![(0, vec![]), (1, vec![true, false]), (2, vec![true])]
        );
    }

    // ==== Missing-layer suspend / recovery-layer re-entry boundary
    // (table-driven) ====
    //
    // Boundary case table (file layer state x disk x recovery row ->
    // piece action):
    // | # | layer state | disk | recovery row | action |
    // |---|-------------------|---------|--------------|--------|
    // | 1 | metadata layer | intact | — | measured pass kept |
    // | 2 | missing, no row | intact | — | suspended (not failed, not cleared) |
    // | 3 | missing, good row | intact | passes | re-entry verify passes (= full config) |
    // | 4 | missing, bad row | intact | fails | falls back to suspended |
    // | 5 | missing, good row | corrupt | passes | re-entry fails, cleared as usual |
    // | 6 | suspended bitmap | — | — | keeps previous session's values |

    use crate::session::recheck::{RecoveredFileLayer, preserve_suspended_v2_bits};

    /// Two multi-piece file vectors: f0 `a-miss.bin` (2 pieces, layer
    /// entry omitted — the missing-layer recovery scenario), f1
    /// `b-full.bin` (2 pieces, layer in place — control). The name
    /// prefixes guarantee dict byte order = DFS order = meta.files
    /// index (a- < b-).
    fn boundary_files() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("a-miss.bin", pattern(PIECE as usize + 2 * B)),
            ("b-full.bin", pattern(PIECE as usize + 3 * B)),
        ]
    }

    /// Missing-layer variant constructor (fixture construction as in
    /// build_v2_only_torrent; files whose index is in `omit` drop the
    /// `piece layers` entry — a missing-layer shape the BEP52 transfer
    /// face allows; the parser degrades to layer_missing and keeps
    /// loading).
    fn build_v2_only_torrent_omitting_layers(files: &[(&str, Vec<u8>)], omit: &[usize]) -> Vec<u8> {
        let mut tree = Vec::new();
        let mut layers = Vec::new();
        for (fi, (name, content)) in files.iter().enumerate() {
            let mut props: Vec<(&[u8], Value)> =
                vec![(b"length", Value::Int(content.len() as i64))];
            if !content.is_empty() {
                let leaves: Vec<[u8; 32]> = content.chunks(B).map(merkle::block_hash).collect();
                let root = ok(merkle::file_root(&leaves, PIECE), "file_root");
                props.push((b"pieces root", Value::Bytes(root.to_vec())));
                if content.len() > PIECE as usize && !omit.contains(&fi) {
                    let layer: Vec<u8> = leaves
                        .chunks(BPP)
                        .flat_map(|c| merkle::piece_root_from_block_hashes(c, BPP))
                        .collect();
                    layers.push((root.to_vec(), Value::Bytes(layer)));
                }
            }
            tree.push((name.as_bytes().to_vec(), dict(vec![(b"", dict(props))])));
        }
        let info = dict(vec![
            (
                b"file tree",
                dict_dyn(vec![(b"data".to_vec(), dict_dyn(tree))]),
            ),
            (b"meta version", Value::Int(2)),
            (b"piece length", Value::Int(i64::from(PIECE))),
        ]);
        let top = dict(vec![
            (
                b"announce",
                Value::Bytes(b"http://127.0.0.1:9/announce".to_vec()),
            ),
            (b"info", info),
            (b"piece layers", dict_dyn(layers)),
        ]);
        ok(bencode::encode(&top), "encode")
    }

    /// The file's real piece-layer bytes (32 B x piece count; the
    /// construction source for recovery-layer rows).
    fn file_layer(content: &[u8]) -> Vec<u8> {
        let leaves: Vec<[u8; 32]> = content.chunks(B).map(merkle::block_hash).collect();
        leaves
            .chunks(BPP)
            .flat_map(|c| merkle::piece_root_from_block_hashes(c, BPP))
            .collect()
    }

    /// Suspend re-entry boundary, table-driven: boundary cases #1-#5
    /// asserted row by row.
    #[test]
    fn suspend_and_reentry_boundary_table() {
        let files = boundary_files();
        let dir = temp_dir("boundary");
        // Missing-layer metadata (f0 layer omitted) + intact disk.
        let raw = build_v2_only_torrent_omitting_layers(&files, &[0]);
        let meta = ok(Metainfo::parse(&raw), "parse");
        write_payload(&dir, &files);
        assert!(
            meta.meta.files[0].layer_missing(PIECE),
            "f0 must start in the missing-layer state (fixture precondition)"
        );
        assert!(
            !meta.meta.files[1].layer_missing(PIECE),
            "the f1 layer is in place (control)"
        );

        // #2 missing, no row: suspended — not failed (verified excludes
        // f0), not cleared (f0 bits all 0 awaiting the preserving
        // merge), the control file measured as usual.
        let out_suspended = ok(recheck_on_disk(&meta, &dir), "recheck suspended");
        assert_eq!(
            out_suspended.suspended_files,
            vec![0],
            "the suspension set = file 0"
        );
        assert_eq!(out_suspended.total, 4);
        assert_eq!(
            out_suspended.verified, 2,
            "suspended pieces are not counted in verified"
        );
        assert_eq!(
            decode_v2_file_bits(&out_suspended.v2_file_bits.clone().unwrap_or_default()),
            vec![(0, vec![false, false]), (1, vec![true, true])],
            "f0 bits all 0 (pending the preserved merge, not a measured failure)"
        );
        // The default entry (the 2-arg recheck_on_disk) matches the
        // suspend accounting (the boundary is always reported).
        assert_eq!(ok(recheck_on_disk(&meta, &dir), "2-arg"), out_suspended);

        // #3 missing, good row (re-entry): convergence re-validation
        // merged -> full-config re-verification passes.
        let good_layer = file_layer(&files[0].1);
        let out_reentered = ok(
            recheck_on_disk_recovering(
                &meta,
                &dir,
                &[RecoveredFileLayer {
                    file_index: 0,
                    layer: good_layer.clone(),
                }],
            ),
            "recheck re-entry",
        );
        assert_eq!(
            out_reentered.suspended_files,
            Vec::<u32>::new(),
            "no suspension after re-entry"
        );
        assert_eq!(
            out_reentered.verified, 4,
            "the re-entry re-verification passes"
        );
        assert_eq!(
            decode_v2_file_bits(&out_reentered.v2_file_bits.clone().unwrap_or_default()),
            vec![(0, vec![true, true]), (1, vec![true, true])]
        );

        // #4 missing, bad row (store row hand-tampered): re-validation
        // fails -> falls back to suspended, never full-configured while
        // in doubt (negative case).
        let mut tampered = good_layer.clone();
        tampered[3] ^= 0x01;
        let out_tampered = ok(
            recheck_on_disk_recovering(
                &meta,
                &dir,
                &[RecoveredFileLayer {
                    file_index: 0,
                    layer: tampered,
                }],
            ),
            "recheck tampered row",
        );
        assert_eq!(
            out_tampered.suspended_files,
            vec![0],
            "a bad row falls back to suspension"
        );
        assert_eq!(out_tampered.verified, 2);
        // Rows with an out-of-range file_index are discarded too
        // (defense face).
        let out_oob = ok(
            recheck_on_disk_recovering(
                &meta,
                &dir,
                &[RecoveredFileLayer {
                    file_index: 9,
                    layer: good_layer.clone(),
                }],
            ),
            "recheck oob row",
        );
        assert_eq!(
            out_oob.suspended_files,
            vec![0],
            "an out-of-bounds row is voided -> suspension"
        );

        // #5 missing, good row, corrupt disk (re-entry fails, cleared
        // as usual): flip the last block of f0.
        let mut bad_disk = files[0].1.clone();
        bad_disk[PIECE as usize + B] ^= 0xff;
        ok(
            std::fs::write(dir.join("data").join("a-miss.bin"), &bad_disk),
            "corrupt f0",
        );
        let out_bad_disk = ok(
            recheck_on_disk_recovering(
                &meta,
                &dir,
                &[RecoveredFileLayer {
                    file_index: 0,
                    layer: good_layer,
                }],
            ),
            "recheck re-entry with corrupt disk",
        );
        assert_eq!(
            out_bad_disk.suspended_files,
            Vec::<u32>::new(),
            "layers in place, no suspension"
        );
        assert_eq!(
            out_bad_disk.verified, 3,
            "f0 piece 1 fails, the rest proceed as usual"
        );
        assert_eq!(
            decode_v2_file_bits(&out_bad_disk.v2_file_bits.clone().unwrap_or_default()),
            vec![(0, vec![true, false]), (1, vec![true, true])],
            "the re-entry failure verdict clears as usual"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #6 suspended bitmap preserving merge (never clear on suspend):
    /// suspended file entries keep the previous session's values,
    /// non-suspended entries follow this measurement; defensive
    /// branches for a missing prev entry / mismatched entry length.
    #[test]
    fn suspended_bits_preserve_previous_session_values() {
        // Suspended-state measured bitmap (f0 all 0, f1 measured
        // [T,F]).
        let encoded = {
            let mut e = Vec::new();
            e.extend_from_slice(&0u32.to_be_bytes());
            e.extend_from_slice(&2u32.to_be_bytes());
            e.push(0b0000_0000); // f0 suspended (placeholder all 0)
            e.extend_from_slice(&1u32.to_be_bytes());
            e.extend_from_slice(&2u32.to_be_bytes());
            e.push(0b1000_0000); // f1 measured [T,F]
            e
        };
        let mut new_bits = Some(encoded.clone());
        // Previous session's bitmap: f0 [T,T] (verified while the layer
        // was present last session), f1 [F,T] — f1 is not suspended, so
        // this measurement [T,F] overrides (measurement is
        // authoritative).
        let prev_bits: Vec<u8> = {
            let mut e = Vec::new();
            e.extend_from_slice(&0u32.to_be_bytes());
            e.extend_from_slice(&2u32.to_be_bytes());
            e.push(0b1100_0000);
            e.extend_from_slice(&1u32.to_be_bytes());
            e.extend_from_slice(&2u32.to_be_bytes());
            e.push(0b0100_0000);
            e
        };
        preserve_suspended_v2_bits(&mut new_bits, Some(&prev_bits), &[0]);
        assert_eq!(
            decode_v2_file_bits(new_bits.as_deref().unwrap_or_default()),
            vec![(0, vec![true, true]), (1, vec![true, false])],
            "suspended entries keep the previous session value; non-suspended entries go by the measured result"
        );
        // No prev entry for the suspended file -> keep the measurement
        // (all 0), never fabricated.
        let mut fresh = Some(encoded);
        preserve_suspended_v2_bits(&mut fresh, None, &[0]);
        assert_eq!(
            decode_v2_file_bits(fresh.as_deref().unwrap_or_default()),
            vec![(0, vec![false, false]), (1, vec![true, false])]
        );
        // Prev entry piece count mismatches the measurement (foreign
        // payload) -> defensive skip, no out-of-bounds write.
        let mut mismatch_prev = Vec::new();
        mismatch_prev.extend_from_slice(&0u32.to_be_bytes());
        mismatch_prev.extend_from_slice(&5u32.to_be_bytes());
        mismatch_prev.push(0xff);
        mismatch_prev.push(0xe0);
        let mut guarded = new_bits.clone();
        preserve_suspended_v2_bits(&mut guarded, Some(&mismatch_prev), &[0]);
        assert_eq!(guarded, new_bits, "the length-mismatch guard skips");
    }
}

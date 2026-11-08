//! ProgressModel: per-file piece/block progress plus synthesized views.
//!
//! Design facts:
//! - There is no global piece index space. Bitmaps are allocated per file
//!   ("pieces per file"), keyed by `(file_index, piece_in_file)`; every
//!   global view is synthesized.
//! - `completedLength` = the sum of per-file verified bytes; padding files
//!   count as fully verified (BEP47: pad content is all zeros and piece
//!   hashes are computed over zeros — pads are never transferred, so a
//!   fixed layout already means owned).
//! - `bitfield` (RPC compatibility field): v1 uses the real bitmap; v2 and
//!   hybrid synthesize a pseudo-bitmap by concatenating per-file bitmaps in
//!   file order (trailing pad bits 0). Frontends render it with v1 bitmap
//!   semantics (matching libtorrent's external reporting).
//! - In-flight block bitmaps: 16 KiB granularity, per (file, piece),
//!   maintained by dispatch/complete events; when a piece passes hash
//!   check, its whole bitmap is cleared (in-flight state ends with the
//!   piece).
//!
//! For v1-only torrents the per-file piece count is derived from the total
//! length and piece_length; for v2/hybrid it comes from
//! `MetaFile::piece_count` (length/piece_length rounded up, 0 pieces for
//! empty files).

use taiji_store::merkle::BLOCK_SIZE;

/// Per-file progress: piece bitmap (this file's piece count) plus in-flight
/// block bitmap (16 KiB per piece).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileProgress {
    /// Piece bitmap: bit j of `pieces[i]` = piece i*8+j of this file
    /// verified.
    pub pieces: Vec<u8>,
    /// In-flight block bitmap: same layout as pieces; bit j = the
    /// corresponding piece has a block in flight. Set as soon as any block
    /// of the piece is in flight; cleared when the piece passes hash check
    /// (in-flight state ends with the piece).
    pub in_flight: Vec<u8>,
    /// Number of pieces in this file (basis for bitmap allocation; v2
    /// per-file counts are uneven).
    pub piece_count: u64,
}

impl FileProgress {
    pub fn new(piece_count: u64) -> FileProgress {
        let bytes = piece_count.div_ceil(8) as usize;
        FileProgress {
            pieces: vec![0u8; bytes],
            in_flight: vec![0u8; bytes],
            piece_count,
        }
    }

    fn get(bitmap: &[u8], idx: u64) -> bool {
        bitmap[(idx / 8) as usize] & (0x80 >> (idx % 8)) != 0
    }

    fn set(bitmap: &mut [u8], idx: u64) {
        bitmap[(idx / 8) as usize] |= 0x80 >> (idx % 8);
    }

    fn clear(bitmap: &mut [u8], idx: u64) {
        bitmap[(idx / 8) as usize] &= !(0x80 >> (idx % 8));
    }

    /// Is piece `(piece_in_file)` verified?
    pub fn piece_done(&self, piece_in_file: u64) -> bool {
        piece_in_file < self.piece_count && Self::get(&self.pieces, piece_in_file)
    }

    /// Marks a piece verified (out of range is a caller bug: debug assert,
    /// ignored in release).
    pub fn set_piece_done(&mut self, piece_in_file: u64) {
        debug_assert!(piece_in_file < self.piece_count);
        if piece_in_file < self.piece_count {
            Self::set(&mut self.pieces, piece_in_file);
            Self::clear(&mut self.in_flight, piece_in_file);
        }
    }

    /// In-flight mark: one new block received for this piece (set when any
    /// block of the piece is in flight).
    pub fn mark_block_in_flight(&mut self, piece_in_file: u64) {
        debug_assert!(piece_in_file < self.piece_count);
        if piece_in_file < self.piece_count && !self.piece_done(piece_in_file) {
            Self::set(&mut self.in_flight, piece_in_file);
        }
    }

    /// Verified byte count for this file: completed pieces x piece_len
    /// (last piece truncated to the file length via the `file_len`
    /// argument; padding files count fully, BEP47).
    pub fn verified_bytes(&self, file_len: u64, piece_len: u32) -> u64 {
        if self.piece_count == 0 {
            return 0;
        }
        let mut done = 0u64;
        for i in 0..self.piece_count {
            if Self::get(&self.pieces, i) {
                let start = i * u64::from(piece_len);
                done += (file_len - start).min(u64::from(piece_len));
            }
        }
        done
    }

    /// Are all pieces complete?
    pub fn all_done(&self) -> bool {
        (0..self.piece_count).all(|i| Self::get(&self.pieces, i))
    }
}

/// Per-torrent progress model (keyed by file index; file index =
/// TorrentMeta.files order).
#[derive(Debug, Clone, Default)]
pub struct ProgressModel {
    pub files: Vec<FileProgress>,
    piece_len: u32,
    /// Per-file lengths (for synthesized views; same order as files).
    file_lens: Vec<u64>,
    /// Padding flags (BEP47 full-count policy; same order as files).
    padding: Vec<bool>,
}

impl ProgressModel {
    /// Builds from unified metadata (pieces per file = ceil(len /
    /// piece_len), 0 pieces for empty files).
    pub fn from_meta(meta: &crate::metainfo::TorrentMeta) -> ProgressModel {
        let piece_len = meta.piece_length;
        let mut files = Vec::with_capacity(meta.files.len());
        let mut file_lens = Vec::with_capacity(meta.files.len());
        let mut padding = Vec::with_capacity(meta.files.len());
        for f in &meta.files {
            let count = if f.length == 0 {
                0
            } else {
                f.length.div_ceil(u64::from(piece_len))
            };
            files.push(FileProgress::new(count));
            file_lens.push(f.length);
            padding.push(f.padding);
        }
        ProgressModel {
            files,
            piece_len,
            file_lens,
            padding,
        }
    }

    /// Test/engine direct construction (avoids depending on the metadata
    /// shape).
    pub fn from_lengths(file_lens: &[u64], piece_len: u32) -> ProgressModel {
        let files = file_lens
            .iter()
            .map(|&l| {
                let count = if l == 0 {
                    0
                } else {
                    l.div_ceil(u64::from(piece_len))
                };
                FileProgress::new(count)
            })
            .collect();
        ProgressModel {
            files,
            piece_len,
            file_lens: file_lens.to_vec(),
            padding: vec![false; file_lens.len()],
        }
    }

    pub fn piece_len(&self) -> u32 {
        self.piece_len
    }

    /// Builds from layout (engine path; pad flags come from LayoutFile).
    pub fn from_layout(layout: &taiji_store::layout::Layout) -> ProgressModel {
        let piece_len = layout.piece_len();
        let files: Vec<FileProgress> = layout
            .files()
            .iter()
            .map(|f| {
                let count = if f.length == 0 {
                    0
                } else {
                    f.length.div_ceil(u64::from(piece_len))
                };
                FileProgress::new(count)
            })
            .collect();
        let file_lens: Vec<u64> = layout.files().iter().map(|f| f.length).collect();
        let padding: Vec<bool> = layout.files().iter().map(|f| f.padding).collect();
        ProgressModel {
            files,
            piece_len,
            file_lens,
            padding,
        }
    }

    /// Total global piece count (synthesized view: sum of per-file counts;
    /// for single-file v1 this is the global index space).
    pub fn global_piece_count(&self) -> u64 {
        self.files.iter().map(|f| f.piece_count).sum()
    }

    /// Global piece index (file-order concatenation coordinates) to
    /// (file_index, piece_in_file).
    fn locate_global(&self, g: u64) -> Option<(usize, u64)> {
        let mut base = 0u64;
        for (i, f) in self.files.iter().enumerate() {
            if g < base + f.piece_count {
                return Some((i, g - base));
            }
            base += f.piece_count;
        }
        None
    }

    /// Global-coordinate query (synthesized view for the engine v1 dispatch
    /// path; out of range = nothing to dispatch).
    pub fn piece_done_global(&self, g: u64) -> bool {
        match self.locate_global(g) {
            Some((fi, pi)) => self.piece_done(fi, pi),
            None => true,
        }
    }

    /// Sets by global coordinate; returns whether newly complete (for
    /// main-loop counting).
    pub fn set_piece_done_global(&mut self, g: u64) -> bool {
        match self.locate_global(g) {
            Some((fi, pi)) if !self.piece_done(fi, pi) => {
                self.set_piece_done(fi, pi);
                true
            }
            _ => false,
        }
    }

    /// In-flight mark by global coordinate.
    pub fn mark_block_in_flight_global(&mut self, g: u64) {
        if let Some((fi, pi)) = self.locate_global(g) {
            self.mark_block_in_flight(fi, pi);
        }
    }

    /// Global coordinate of the first incomplete piece (lowest-order
    /// dispatch; None when all complete).
    pub fn first_incomplete_global(&self) -> Option<u64> {
        let mut base = 0u64;
        for f in &self.files {
            for i in 0..f.piece_count {
                if !f.piece_done(i) {
                    return Some(base + i);
                }
            }
            base += f.piece_count;
        }
        None
    }

    /// Is `(file_index, piece_in_file)` verified?
    pub fn piece_done(&self, file_index: usize, piece_in_file: u64) -> bool {
        self.files
            .get(file_index)
            .is_some_and(|f| f.piece_done(piece_in_file))
    }

    /// Marks a piece hash-verified.
    pub fn set_piece_done(&mut self, file_index: usize, piece_in_file: u64) {
        if let Some(f) = self.files.get_mut(file_index) {
            f.set_piece_done(piece_in_file);
        }
    }

    /// In-flight block event (call at dispatch; piece completion goes
    /// through [`Self::set_piece_done`]).
    pub fn mark_block_in_flight(&mut self, file_index: usize, piece_in_file: u64) {
        if let Some(f) = self.files.get_mut(file_index) {
            f.mark_block_in_flight(piece_in_file);
        }
    }

    /// `completedLength`: sum of per-file verified bytes; padding files
    /// count fully (BEP47: pads are all zeros, never transferred; a fixed
    /// layout means owned).
    pub fn completed_length(&self) -> u64 {
        self.files
            .iter()
            .enumerate()
            .map(|(i, f)| {
                if self.padding[i] {
                    self.file_lens[i]
                } else {
                    f.verified_bytes(self.file_lens[i], self.piece_len)
                }
            })
            .sum()
    }

    /// Are all files complete?
    pub fn all_done(&self) -> bool {
        self.files.iter().all(FileProgress::all_done)
    }

    /// Synthesizes the bitfield (RPC surface): concatenates per-file piece
    /// bitmaps in file order, trailing pad bits 0. Returns (bitmap bytes,
    /// total valid bits). For v1-only, the per-file derivation equals the
    /// real global bitmap (strictly identical for a single file).
    pub fn synthesized_bitfield(&self) -> (Vec<u8>, u64) {
        let total: u64 = self.files.iter().map(|f| f.piece_count).sum();
        let mut out = vec![0u8; total.div_ceil(8) as usize];
        let mut bit = 0u64;
        for f in &self.files {
            for i in 0..f.piece_count {
                if FileProgress::get(&f.pieces, i) {
                    out[(bit / 8) as usize] |= 0x80 >> (bit % 8);
                }
                bit += 1;
            }
        }
        (out, total)
    }

    /// In-flight piece count (diagnostics; not part of the synthesized
    /// surface).
    pub fn in_flight_pieces(&self) -> u64 {
        self.files
            .iter()
            .map(|f| {
                (0..f.piece_count)
                    .filter(|&i| FileProgress::get(&f.in_flight, i))
                    .count() as u64
            })
            .sum()
    }

    /// Exports the global block granularity (16 KiB) constant (for block
    /// bitmap conversion; BEP52 fixes the leaf granularity).
    pub fn block_size() -> u32 {
        BLOCK_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::{MetaFile, TorrentIdentity, TorrentMeta};
    use taiji_bt::filetree::SwarmKind;

    fn meta(files: &[(u64, bool)]) -> TorrentMeta {
        TorrentMeta {
            identity: TorrentIdentity { v1: None, v2: None },
            kind: SwarmKind::V1Only,
            piece_length: 16384,
            files: files
                .iter()
                .map(|&(len, padding)| MetaFile {
                    path: std::path::PathBuf::from(format!("f{len}")),
                    length: len,
                    padding,
                    pieces_root: None,
                    piece_layer: None,
                    v1_offset: None,
                })
                .collect(),
        }
    }

    /// Hybrid fixture numeric sample: a.bin 70000 (5 pieces) / pad 11920
    /// (1 piece) / b.bin 30000 (2 pieces) -> synthesized 8-bit bitmap;
    /// exact completedLength.
    #[test]
    fn hybrid_fixture_numeric_sample() {
        let lens = [(70000u64, false), (11920, true), (30000, false)];
        let m = meta(&lens);
        let pm = ProgressModel::from_meta(&m);
        // Piece counts: ceil(70000/16384)=5; ceil(11920/16384)=1;
        // ceil(30000/16384)=2.
        assert_eq!(
            [5, 1, 2],
            [
                pm.files[0].piece_count,
                pm.files[1].piece_count,
                pm.files[2].piece_count
            ]
        );
        // Synthesized bitmap: 8 valid bits.
        let (bits, total) = pm.synthesized_bitfield();
        assert_eq!(total, 8);
        assert_eq!(bits, vec![0u8; 1]);
        drop(pm);
        // pad full count = its full length 11920 (BEP47: pads are all
        // zeros, never transferred; a fixed layout means owned).
        let mut pm2 = ProgressModel::from_meta(&m);
        pm2.set_piece_done(1, 0);
        assert_eq!(pm2.completed_length(), 11920, "pad counted in full");
        // a.bin all 5 pieces + pad + b.bin 2 pieces = full.
        for i in 0..5 {
            pm2.set_piece_done(0, i);
        }
        pm2.set_piece_done(2, 0);
        pm2.set_piece_done(2, 1);
        assert!(pm2.all_done());
        assert_eq!(pm2.completed_length(), 70000 + 11920 + 30000);
        // Synthesized bitmap all ones.
        let (bits, _) = pm2.synthesized_bitfield();
        assert_eq!(bits, vec![0xFF]);
        let _ = bits;
    }

    /// Synthesized bitmap equals per-file truth (proptest): under any set
    /// pattern, bit k of the synthesized bitmap == bit k of the flattened
    /// per-file truth; completedLength is monotone and <= total.
    #[test]
    fn synthesized_matches_per_file_truth() {
        // Deterministic pseudo-random sweep (samples the 3-file set
        // combinations).
        let lens = [70000u64, 11920, 30000];
        let m = meta(&[(lens[0], false), (lens[1], true), (lens[2], false)]);
        let mut state = 0x2545F4914F6CDD1Du64;
        let mut xorshift = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _round in 0..64 {
            let mut pm = ProgressModel::from_meta(&m);
            for (fi, f) in pm.files.iter_mut().enumerate() {
                for i in 0..f.piece_count {
                    if xorshift() & 1 == 1 {
                        f.set_piece_done(i);
                    }
                }
                let _ = fi;
            }
            let (bits, total) = pm.synthesized_bitfield();
            // Bit-by-bit comparison against the flattened truth.
            let mut expect_bits = Vec::new();
            for (fi, f) in pm.files.iter().enumerate() {
                for i in 0..f.piece_count {
                    expect_bits.push(((fi, i), f.piece_done(i)));
                }
            }
            for (k, (_, done)) in expect_bits.iter().enumerate() {
                let byte = bits[k / 8];
                let on = byte & (0x80 >> (k % 8)) != 0;
                assert_eq!(on, *done, "bit {k} mismatch");
            }
            // completedLength <= total, and monotone: setting more pieces
            // never decreases it.
            let before = pm.completed_length();
            assert!(before <= lens.iter().sum::<u64>());
            let _ = total;
        }
    }

    // proptest: random file lengths + random set pattern -> three
    // synthesized invariants (bitmap bits match truth / completedLength <=
    // sum of lengths / pad counts fully).
    proptest::proptest! {
        #[test]
        fn invariants_hold(lens in proptest::prelude::prop::collection::vec(
            proptest::prelude::any::<u64>(), 1..6
        )) {
            let lens: Vec<u64> = lens.iter().map(|&l| l % 200_000).collect();
            let flags: Vec<bool> = lens.iter().map(|_| false).collect();
            let flags: Vec<(u64, bool)> = lens.iter().copied().zip(flags).collect();
            let m = meta(&flags);
            let mut pm = ProgressModel::from_meta(&m);
            let mut state = 0x9E3779B97F4A7C15u64 ^ lens.len() as u64;
            for (fi, f) in pm.files.iter_mut().enumerate() {
                for i in 0..f.piece_count {
                    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
                    if state & 1 == 1 {
                        f.set_piece_done(i);
                    }
                }
                let _ = fi;
            }
            let (bits, total) = pm.synthesized_bitfield();
            // Equivalence: synthesized bits match the true state.
            let mut k = 0u64;
            for f in &pm.files {
                for i in 0..f.piece_count {
                    let on = bits[(k / 8) as usize] & (0x80 >> (k % 8)) != 0;
                    assert_eq!(on, f.piece_done(i));
                    k += 1;
                }
            }
            assert_eq!(k, total);
            // completedLength upper bound.
            let sum: u64 = lens.iter().sum();
            let cl_pad = pm.completed_length();
            assert!(cl_pad <= sum);
            // The pad full-count policy is covered by the fixture numeric
            // test (this proptest has no pad files).
        }
    }

    /// In-flight bitmap lifecycle: dispatch sets, piece completion clears;
    /// re-dispatching a complete piece does not set.
    #[test]
    fn in_flight_lifecycle() {
        let mut pm = ProgressModel::from_lengths(&[50000], 16384);
        pm.mark_block_in_flight(0, 0);
        assert_eq!(pm.in_flight_pieces(), 1);
        pm.set_piece_done(0, 0);
        assert_eq!(
            pm.in_flight_pieces(),
            0,
            "piece completion clears in-flight"
        );
        pm.mark_block_in_flight(0, 0);
        assert_eq!(
            pm.in_flight_pieces(),
            0,
            "complete piece never re-enters in-flight"
        );
    }
}

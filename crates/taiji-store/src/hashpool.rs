//! HashPool: piece verification state machine (SPEC §4.3/§4.5.2).
//!
//! Upstream anchor mapping: docs/design/store.md
//!
//! - v1: whole-piece SHA-1. This pool does no arrival-order digest
//!   accumulation (upstream anchor: aria2 `Piece.cc` `updateHash` gates
//!   on `begin == nextBegin_` — out-of-order blocks are not fed to the
//!   digest, and completion rereads via `getDigestWithWrCache`).
//!   Unordered accumulation would misalign, so it was removed from the
//!   `verify` path; authoritative v1 verification recomputes at
//!   completion from the cached cells in verified.rs `piece_matches`
//!   (see that module's docs).
//! - v2: collect per-block SHA-256 hashes and recompute the piece root
//!   at piece completion against the metadata (piece-tree rules in
//!   [`crate::merkle`]; the creator's "sole piece padded to a power of
//!   two / other pieces padded to blocks_per_piece" branches are split
//!   between [`merkle::piece_root_from_block_hashes`] and the file-level
//!   [`merkle::file_root`]).
//! - M0 scope (honesty note): block-level **incremental** verification
//!   needs base-layer (16KiB granularity) sibling hashes, which the
//!   metadata does not carry; lazy base-layer hash requests are later
//!   work (SPEC §4.3/§6.3). So M0's v2 verification granularity is "at
//!   piece completion", the same moment as v1; v2's payoff (a failure
//!   refetches only one block) lands once the base layer is available.
//!
//! No byte reaches disk before verification passes — this type only
//! computes hashes; the write decision lives in [`crate::verified`].

use crate::merkle;

/// v2 block granularity (BEP52 fixed 16KiB, same as
/// [`merkle::BLOCK_SIZE`]).
pub const BLOCK_SIZE: u32 = merkle::BLOCK_SIZE;

/// Expected hash per piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedPieceHash {
    /// v1: whole-piece SHA-1 (BEP3 `pieces`).
    V1([u8; 20]),
    /// v2: piece root (BEP52 `pieces root` / `piece layers`).
    V2([u8; 32]),
}

/// Cloned verification inputs for a completed v2 piece (the pooled
/// surface, [`HashPool::v2_verify_inputs`]): workers fold the piece root
/// independently, with no access to mutable pool state.
#[derive(Debug, Clone)]
pub struct V2VerifyInputs {
    /// Metadata-expected root (this piece's piece root).
    pub want: [u8; 32],
    /// Positioned per-block leaf hashes (hole-free under the completion
    /// invariant).
    pub block_hashes: Vec<[u8; 32]>,
    /// Blocks per piece (tree-rule folding parameter).
    pub blocks_per_piece: usize,
    /// Whether the owning file is exactly one piece (tree-rule dispatch,
    /// see the [`HashPool`] field docs).
    pub single_piece_file: bool,
}

/// In-flight receive state of one piece (no v1 digest surface —
/// arrival-order accumulation was removed with the `verify` path; v1
/// verification recomputes in verified.rs at assembly, see the module
/// docs).
#[derive(Debug)]
struct PieceDigest {
    /// v2 received block hashes, positioned by in-piece block index
    /// (`blocks[offset/16KiB]`). v2 leaf hashes are independent per
    /// block (`SHA256(16KiB block)`, BEP52 `pieces root` section),
    /// independent of arrival order — the v2 per-block verification
    /// chain refetches single blocks out of order, and positional writes
    /// keep the completion fold in correct in-piece order.
    blocks: Option<Vec<Option<[u8; 32]>>>,
    /// Received byte count.
    bytes: u64,
    /// Whether all block hashes are in.
    complete: bool,
}

/// Verification pool shared by v1/v2: piece index → receive state.
///
/// `expected` is built from the metadata (v1 = the `pieces` string, v2 =
/// each file's piece layer); with v2 multi-file, piece indices are a
/// **synthetic flat order** (files expanded × pieces per file, allowed
/// by SPEC §4.4; the flat idx ↔ (file, piece_in_file) mapping lives in
/// the caller's bt-side base table — store does not depend back on bt).
/// Per-piece expected byte counts are fixed at construction
/// ([`HashPool::new_plan`]); the single-file constructors are special
/// cases of it.
#[derive(Debug)]
pub struct HashPool {
    piece_len: u32,
    /// Expected bytes per piece (the last piece is shorter than
    /// piece_len; multi-file computed per owning file's last piece).
    piece_expected: Vec<u64>,
    /// Whether this piece's file is exactly one piece (the multi-file v2
    /// fix): for a BEP52 file of ≤1 piece the tree pads to the next
    /// power of two in **block count** ("padded to the next power of two
    /// instead of the next piece boundary"), independent of piece size;
    /// a >1-piece file's last piece pads to blocks_per_piece. The two
    /// rules root differently and must dispatch.
    single_piece_file: Vec<bool>,
    expected: Vec<ExpectedPieceHash>,
    pieces: Vec<Option<PieceDigest>>,
}

/// Multi-file plan construction error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    #[error("piece plan count {got} mismatches file-derived count {expected}")]
    PieceCountMismatch { got: usize, expected: usize },
}

impl HashPool {
    /// Multi-file plan: `expected` holds the per-piece expected hashes in
    /// the synthetic flat order (v1 = whole-piece SHA-1; v2 = the owning
    /// file's pieces root); `file_lengths` is the layout file-length
    /// table (including pads — pads produce no pieces, pass the real
    /// file lengths; pad ranges count into v1's global piece coverage,
    /// and the caller's flat plan guarantees consistency with
    /// `expected`).
    pub fn new_plan(
        expected: Vec<ExpectedPieceHash>,
        piece_len: u32,
        file_lengths: &[u64],
    ) -> Result<HashPool, PlanError> {
        let mut piece_expected = Vec::new();
        let mut single_piece_file = Vec::new();
        for &len in file_lengths {
            let n = len.div_ceil(u64::from(piece_len));
            for k in 0..n {
                piece_expected.push((len - k * u64::from(piece_len)).min(u64::from(piece_len)));
                single_piece_file.push(n == 1);
            }
        }
        if expected.len() != piece_expected.len() {
            return Err(PlanError::PieceCountMismatch {
                got: expected.len(),
                expected: piece_expected.len(),
            });
        }
        let n = expected.len();
        Ok(HashPool {
            piece_len,
            piece_expected,
            single_piece_file,
            expected,
            pieces: (0..n).map(|_| None).collect(),
        })
    }

    /// v1 pool: `pieces_sha1` = the metadata `pieces` string (20B × piece
    /// count). Single-file special case of [`HashPool::new_plan`]
    /// (file_lengths = [file_len]).
    pub fn new_v1(pieces_sha1: &[u8], piece_len: u32, file_len: u64) -> HashPool {
        let expected: Vec<ExpectedPieceHash> = pieces_sha1
            .as_chunks::<20>()
            .0
            .iter()
            .map(|h| {
                let mut e = [0u8; 20];
                e.copy_from_slice(h);
                ExpectedPieceHash::V1(e)
            })
            .collect();
        HashPool::new_plan(expected, piece_len, &[file_len])
            .unwrap_or_else(|e| unreachable!("single-file plan consistent: {e}"))
    }

    /// v2 pool: `piece_roots` = roots of all the file's pieces (cut from
    /// bt::filetree's piece layer; a single-file root is the only entry).
    pub fn new_v2(piece_roots: Vec<[u8; 32]>, piece_len: u32, file_len: u64) -> HashPool {
        let expected: Vec<ExpectedPieceHash> =
            piece_roots.into_iter().map(ExpectedPieceHash::V2).collect();
        HashPool::new_plan(expected, piece_len, &[file_len])
            .unwrap_or_else(|e| unreachable!("single-file plan consistent: {e}"))
    }

    pub fn piece_count(&self) -> usize {
        self.expected.len()
    }

    pub fn piece_len(&self) -> u32 {
        self.piece_len
    }

    /// Layout total bytes (Σ per-piece expected bytes; multi-file =
    /// Σ file_lengths).
    pub fn total_len(&self) -> u64 {
        self.piece_expected.iter().sum()
    }

    /// Total bytes of piece `idx` (the last piece may be shorter than
    /// piece_len; multi-file per owning file).
    pub fn piece_bytes(&self, idx: u64) -> Result<u64, RangeError> {
        Ok(self.piece_bytes_at(self.resolve(idx)?))
    }

    /// Direct lookup on a resolved index (internal; the caller
    /// guarantees in bounds).
    fn piece_bytes_at(&self, i: usize) -> u64 {
        self.piece_expected[i]
    }

    /// In-piece offset bounds check (callers disconnect on protocol
    /// violations, SPEC §6.2).
    pub fn check_range(&self, idx: u64, offset_in_piece: u32, len: u32) -> Result<(), RangeError> {
        let i = self.resolve(idx)?;
        let bytes = self.piece_bytes_at(i);
        if u64::from(offset_in_piece) + u64::from(len) > bytes {
            return Err(RangeError::OutOfBounds {
                index: i,
                offset: offset_in_piece,
                len,
                piece_bytes: bytes as u32,
            });
        }
        Ok(())
    }

    /// Receive one block: accumulate receive state; returns whether the
    /// piece is now full (the verification inputs are then taken via
    /// [`Self::v2_verify_inputs`] / [`Self::expected_v1_digest`];
    /// folding happens in the single implementation verified.rs
    /// `piece_matches`).
    pub fn push_block(
        &mut self,
        idx: u64,
        offset_in_piece: u32,
        block: &[u8],
    ) -> Result<bool, RangeError> {
        self.push_block_with_precomputed(idx, offset_in_piece, block, None)
    }

    /// Push one block (the write-path precomputed-hash form):
    /// `precomputed` = the first block's hash already computed on the
    /// write path — production callers always push a single ≤16KiB block
    /// (the verified.rs `buffer_block` step-0 length gate), so the pool
    /// skips the duplicate SHA-256 for that block (the same hash rides
    /// along: block-level direct compare / pool accumulation hand-off /
    /// completion lookup; upstream anchor: libtorrent computes once on
    /// the write path into the table, `precomputed_block_hashes.cpp`,
    /// and hash2 jobs consume it, `pread_disk_io.cpp`). `None` = compute
    /// in the pool (the existing path; bit-identical behavior — this
    /// method is a pass-through implementation of the existing
    /// [`Self::push_block`]). The alignment/duplicate/bounds gates are
    /// exactly `push_block`'s (precomputation changes no error surface);
    /// multi-block pushes (test-only shapes) consume `precomputed` for
    /// the first block only, the rest compute normally (the debug_assert
    /// pins the caller contract).
    ///
    /// Zero-change invariant: all validation precedes any state change —
    /// on Err the piece's receive state is bit-identical to before the
    /// call (see the validation-section comments in the method body).
    pub fn push_block_with_precomputed(
        &mut self,
        idx: u64,
        offset_in_piece: u32,
        block: &[u8],
        precomputed: Option<[u8; 32]>,
    ) -> Result<bool, RangeError> {
        debug_assert!(
            precomputed.is_none() || block.len() <= BLOCK_SIZE as usize,
            "precomputed hash is defined for single-block pushes only"
        );
        let i = self.resolve(idx)?;
        self.check_range(idx, offset_in_piece, block.len() as u32)?;
        let expected_bytes = self.piece_bytes_at(i);
        let is_v1 = matches!(self.expected[i], ExpectedPieceHash::V1(_));
        let expected_blocks = expected_bytes.div_ceil(u64::from(BLOCK_SIZE)) as usize;
        // ── Validation section (all of it precedes any state change) ──
        //
        // Zero-change invariant: on Err, `pieces[i]` is bit-identical to
        // before the call — bytes accounting, block-hash writes,
        // complete flagging, and starting a not-yet-started piece's
        // digest state all happen only after every check passes. If a
        // rejected block polluted bytes first (the old order: alignment/
        // duplicate-slot errors reported after accounting), the piece's
        // completion judgment would be permanently misaligned (legal
        // blocks could never add up exactly) and the upstream would
        // eventually fail the whole task as Fatal.
        if self.pieces[i].as_ref().is_some_and(|s| s.complete) {
            // Duplicate delivery to a complete piece = caller bookkeeping
            // error; error explicitly instead of silently recomputing.
            return Err(RangeError::PieceAlreadyComplete { index: i });
        }
        if !is_v1 {
            // v2: block hashes are independent per block (leaf =
            // SHA256(block)), written positionally by in-piece block
            // index; a duplicate block (same slot twice) = bookkeeping
            // error, explicit error. The positional semantics require
            // 16KiB-aligned, block-granular pushes (aligned start + len
            // a BLOCK multiple, or exactly filling the short tail block)
            // — wire request granularity always satisfies this (SPEC
            // §6.2 request semantics). The completion check uses the
            // post-push byte count (received + len), without mutating
            // state itself.
            let received = self.pieces[i].as_ref().map_or(0, |s| s.bytes);
            if !(offset_in_piece as usize).is_multiple_of(BLOCK_SIZE as usize)
                || (!block.len().is_multiple_of(BLOCK_SIZE as usize)
                    && received + block.len() as u64 != expected_bytes)
            {
                return Err(RangeError::UnalignedBlock {
                    index: i,
                    offset: offset_in_piece,
                });
            }
            if let Some(blocks) = self.pieces[i].as_ref().and_then(|s| s.blocks.as_ref()) {
                // Target-slot occupancy precheck (check_range already
                // guarantees start + n ≤ expected_blocks = blocks.len(),
                // so the slice is in bounds).
                let start = offset_in_piece as usize / BLOCK_SIZE as usize;
                let n = block.len().div_ceil(BLOCK_SIZE as usize);
                if blocks[start..start + n].iter().any(Option::is_some) {
                    return Err(RangeError::PieceAlreadyComplete { index: i });
                }
            }
        }
        // ── Mutation section (all checks passed; the single
        // state-advance point) ──
        let state = self.pieces[i].get_or_insert_with(|| PieceDigest {
            blocks: (!is_v1).then(|| vec![None; expected_blocks]),
            bytes: 0,
            complete: false,
        });
        state.bytes += block.len() as u64;
        if let Some(blocks) = &mut state.blocks {
            let start = offset_in_piece as usize / BLOCK_SIZE as usize;
            for (pos, chunk) in (start..).zip(block.chunks(BLOCK_SIZE as usize)) {
                // Write-path precomputed hash handed straight in (first
                // block only — production callers always push single
                // blocks, see the method docs); miss = compute here (the
                // existing path).
                let hash = match precomputed {
                    Some(h) if pos == start => h,
                    _ => merkle::block_hash(chunk),
                };
                blocks[pos] = Some(hash);
            }
        }
        // v1 pieces: no in-pool digest state (`blocks` = None) — bytes/
        // completion accounting advanced uniformly above; the verdict
        // comes from the verified.rs recompute at assembly.
        state.complete = state.bytes == expected_bytes;
        Ok(state.complete)
    }

    /// Whether the piece's bytes are all received (bytes == expected;
    /// completion is decoupled from digests — v1 arrival-order digests
    /// cannot back a verification verdict, see the verified.rs assembly
    /// path; this only answers "are bytes still missing").
    pub fn piece_complete(&self, idx: u64) -> Result<bool, RangeError> {
        let i = self.resolve(idx)?;
        Ok(self.pieces[i].as_ref().is_some_and(|s| s.complete))
    }

    /// Bytes received for the piece (0 before start; the companion read
    /// for the completion check).
    pub fn piece_received(&self, idx: u64) -> Result<u64, RangeError> {
        let i = self.resolve(idx)?;
        Ok(self.pieces[i].as_ref().map_or(0, |s| s.bytes))
    }

    /// The piece's expected v1 digest (for the verified completion-time
    /// assembly verification; None = v2 piece — v2 per-block hashes are
    /// written positionally in piece order, order-safe by construction,
    /// and its verification inputs come via [`Self::v2_verify_inputs`]).
    pub fn expected_v1_digest(&self, idx: u64) -> Result<Option<[u8; 20]>, RangeError> {
        let i = self.resolve(idx)?;
        Ok(match &self.expected[i] {
            ExpectedPieceHash::V1(want) => Some(*want),
            ExpectedPieceHash::V2(_) => None,
        })
    }

    /// Cloned verification inputs for a completed v2 piece: want root +
    /// positioned per-block hashes + tree-rule dispatch parameters.
    /// Caller contract: take only after `piece_complete` is true (the
    /// completion invariant guarantees hole-free block hashes); v1
    /// pieces return `None` (v1 inputs via [`Self::expected_v1_digest`]).
    /// The pool's completion state is untouched (clone, not take — late
    /// blocks still error explicitly with `PieceAlreadyComplete`).
    pub fn v2_verify_inputs(&self, idx: u64) -> Result<Option<V2VerifyInputs>, RangeError> {
        let i = self.resolve(idx)?;
        let ExpectedPieceHash::V2(want) = &self.expected[i] else {
            return Ok(None);
        };
        let Some(state) = &self.pieces[i] else {
            return Ok(None);
        };
        let Some(blocks) = &state.blocks else {
            return Ok(None);
        };
        Ok(Some(V2VerifyInputs {
            want: *want,
            block_hashes: blocks
                .iter()
                .map(|b| b.unwrap_or_else(|| unreachable!("complete piece has all blocks")))
                .collect(),
            blocks_per_piece: (self.piece_len / BLOCK_SIZE) as usize,
            single_piece_file: self.single_piece_file[i],
        }))
    }

    /// Reset a piece's state (the refetch path after cache eviction /
    /// verification failure).
    pub fn reset_piece(&mut self, idx: u64) {
        // Domain validation (`usize::try_from`): an index outside the
        // usize domain is outside the piece domain — the same no-op as
        // the bounds guard below (the old `idx as usize` would silently
        // truncate on 32-bit targets, potentially clobbering a valid
        // piece).
        let Ok(i) = usize::try_from(idx) else {
            return;
        };
        if i < self.pieces.len() {
            self.pieces[i] = None;
        }
    }

    /// Resolve a piece index in bounds (u64 domain → Vec index).
    fn resolve(&self, idx: u64) -> Result<usize, RangeError> {
        let i = usize::try_from(idx)
            .ok()
            .filter(|&i| i < self.expected.len())
            .ok_or(RangeError::UnknownPiece {
                index: i64::try_from(idx).unwrap_or(i64::MAX) as usize,
            })?;
        Ok(i)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RangeError {
    #[error("piece index {index} outside hash pool")]
    UnknownPiece { index: usize },
    #[error("block {offset}+{len} beyond piece {index} (piece bytes {piece_bytes})")]
    OutOfBounds {
        index: usize,
        offset: u32,
        len: u32,
        piece_bytes: u32,
    },
    #[error("piece {index} already complete: duplicate block")]
    PieceAlreadyComplete { index: usize },
    #[error(
        "v2 push at piece {index} offset {offset} must be 16KiB-aligned and block-granular (wire request granularity)"
    )]
    UnalignedBlock { index: usize, offset: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(len: usize) -> Vec<u8> {
        const P: &[u8] = b"blackhole-merkle-reference-";
        P.iter().cycle().take(len).copied().collect()
    }

    /// Multi-file plan: per-piece expected bytes are truncated by each
    /// owning file's last piece; a plan/file-derived count mismatch →
    /// explicit error.
    #[test]
    fn plan_multi_file_expected_bytes() {
        // File A: 5 pieces (70000/16KiB, last 4464B) + B: 2 pieces
        // (30000, last 13616B).
        let expected = vec![ExpectedPieceHash::V1([0; 20]); 7];
        let pool =
            HashPool::new_plan(expected, 16384, &[70000, 30000]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(pool.piece_count(), 7);
        assert_eq!(pool.total_len(), 100_000);
        assert_eq!(pool.piece_bytes(4).unwrap_or_else(|e| panic!("{e}")), 4464);
        assert_eq!(pool.piece_bytes(5).unwrap_or_else(|e| panic!("{e}")), 16384);
        assert_eq!(pool.piece_bytes(6).unwrap_or_else(|e| panic!("{e}")), 13616);
        assert!(matches!(
            pool.piece_bytes(7),
            Err(RangeError::UnknownPiece { index: 7 })
        ));
        // Count mismatch: 2 files derive 7 pieces, the plan gives 6.
        assert!(matches!(
            HashPool::new_plan(
                vec![ExpectedPieceHash::V1([0; 20]); 6],
                16384,
                &[70000, 30000]
            ),
            Err(PlanError::PieceCountMismatch {
                got: 6,
                expected: 7
            })
        ));
        // Zero-length files produce no pieces (consistent with
        // Addressing::per_file).
        let zero = HashPool::new_plan(vec![ExpectedPieceHash::V1([0; 20])], 16384, &[0, 16384])
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(zero.piece_count(), 1);
    }

    /// The multi-file v2 plan's `single_piece_file` dispatch flags and
    /// per-block input extraction (the pool side of the dispatch fix;
    /// the BEP52 folding rules themselves are locked by the verified.rs
    /// `piece_matches` tests — single implementation, so this only locks
    /// the pool's outputs): at piece_len 64KiB (bpp=4) a 1-piece file
    /// flags true and multi-piece files flag false per piece; a
    /// completed piece's per-block hashes extract in full in-piece order
    /// (including the short tail block).
    #[test]
    fn v2_multi_file_plan_flags_and_verify_inputs() {
        let content: Vec<u8> = (0..132_768).map(|i| (i % 253) as u8).collect();
        // File 0: 32768B (1 piece = 2 blocks); file 1: 100000B (2 pieces:
        // 65536 + 34464 = 3 blocks).
        let bh = |b: &[u8]| merkle::block_hash(b);
        let f0_blocks: Vec<[u8; 32]> = content[0..32768].chunks(16384).map(bh).collect();
        let f1_p0: Vec<[u8; 32]> = content[32768..98304].chunks(16384).map(bh).collect();
        let f1_p1: Vec<[u8; 32]> = content[98304..132768].chunks(16384).map(bh).collect();
        // Expected roots derived independently per the BEP52 rules (the
        // values are not judged here, only the new_plan input contract
        // satisfied; root correctness is locked by the piece_matches-side
        // vectors).
        let roots = [
            merkle::root_from_block_hashes(&f0_blocks),
            merkle::root_from_block_hashes(&f1_p0),
            merkle::piece_root_from_block_hashes(&f1_p1, 4),
        ];

        let mut pool = HashPool::new_plan(
            roots.iter().map(|r| ExpectedPieceHash::V2(*r)).collect(),
            65536,
            &[32768, 100000],
        )
        .unwrap_or_else(|e| panic!("{e}"));
        // Piece 0 (the sole piece of a 1-piece file): the whole piece
        // pushed at once.
        assert!(
            pool.push_block(0, 0, &content[0..32768])
                .unwrap_or_else(|e| panic!("{e}"))
        );
        // Pieces 1/2 (multi-piece file, file-local coordinates): pushed
        // per 16KiB (piece 2's last block is a 1712B short block filling
        // the tail).
        for (idx, range) in [(1u64, 32768..98304), (2u64, 98304..132768)] {
            let mut off = 0u32;
            for chunk in content[range].chunks(16384) {
                let done = pool
                    .push_block(idx, off, chunk)
                    .unwrap_or_else(|e| panic!("{e}"));
                off += chunk.len() as u32;
                if done {
                    assert_eq!(
                        off as u64,
                        pool.piece_bytes(idx).unwrap_or_else(|e| panic!("{e}"))
                    );
                }
            }
        }
        // Dispatch flags: a 1-piece file → true; multi-piece file pieces
        // → false. Per-block inputs: extracted fully in piece order
        // (bit-identical to the construction leaves).
        let inputs = |idx: u64| {
            pool.v2_verify_inputs(idx)
                .unwrap_or_else(|e| panic!("{e}"))
                .unwrap_or_else(|| panic!("piece {idx} completed-state inputs must exist"))
        };
        let in0 = inputs(0);
        assert!(in0.single_piece_file, "the 1-piece-file flag must be true");
        assert_eq!(in0.block_hashes, f0_blocks);
        assert_eq!(in0.blocks_per_piece, 4);
        for (idx, want) in [(1u64, &f1_p0), (2u64, &f1_p1)] {
            let inp = inputs(idx);
            assert!(
                !inp.single_piece_file,
                "multi-piece file piece {idx} flag must be false"
            );
            assert_eq!(inp.block_hashes, *want);
        }
    }

    /// v2 out-of-order arrival (the refetch-path shape): block hashes are
    /// positioned by in-piece block index — a late block does not
    /// disturb earlier positions, and a completed piece's leaf hashes
    /// are always in correct in-piece order (folding is locked on the
    /// verified.rs `piece_matches` side). Contrast: arrival-order
    /// accumulation would append refetched blocks at the end and
    /// misalign the root.
    #[test]
    fn v2_out_of_order_block_arrival_positional() {
        let content = pattern(32768); // 1 piece, 2 blocks (32KiB piece)
        let h0 = merkle::block_hash(&content[0..16384]);
        let h1 = merkle::block_hash(&content[16384..32768]);
        let root = merkle::root_from_block_hashes(&[h0, h1]);
        let mut pool = HashPool::new_v2(vec![root], 32768, 32768);
        // Receive block 1 first (out of order).
        assert!(
            !pool
                .push_block(0, 16384, &content[16384..32768])
                .unwrap_or_else(|e| panic!("{e}"))
        );
        // Then block 0 → full; positional semantics put the leaf hashes
        // in piece order.
        assert!(
            pool.push_block(0, 0, &content[0..16384])
                .unwrap_or_else(|e| panic!("{e}"))
        );
        let inputs = pool
            .v2_verify_inputs(0)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("completed-piece inputs must exist"));
        assert_eq!(
            inputs.block_hashes,
            vec![h0, h1],
            "positioned by in-piece order"
        );
        // Same-slot re-receipt (duplicate block) = explicit error.
        assert!(matches!(
            pool.push_block(0, 16384, &content[16384..32768]),
            Err(RangeError::PieceAlreadyComplete { .. })
        ));
    }

    /// Precomputed-hash hand-off: the caller's hash enters the slot
    /// verbatim (not recomputed); `None` slots compute normally (the
    /// existing path); a bogus hash folds into a root mismatch (table/
    /// pool only move values; "when to trust" is unchanged — the same
    /// semantics as libtorrent `store` writing the caller's hash,
    /// `precomputed_block_hashes.cpp`).
    #[test]
    fn precomputed_hash_is_consumed_verbatim() {
        let content = pattern(32768);
        let root = merkle::root_from_block_hashes(
            &content
                .chunks(16384)
                .map(merkle::block_hash)
                .collect::<Vec<_>>(),
        );
        let mut pool = HashPool::new_v2(vec![root], 32768, 32768);
        let bogus = [0xAA; 32];
        let done = pool
            .push_block_with_precomputed(0, 0, &content[0..16384], Some(bogus))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!done, "a single block does not complete");
        assert!(
            pool.push_block(0, 16384, &content[16384..32768])
                .unwrap_or_else(|e| panic!("{e}")),
            "the second block completes (2-block piece)"
        );
        let inputs = pool
            .v2_verify_inputs(0)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("completed-piece inputs must exist"));
        assert_eq!(
            inputs.block_hashes[0], bogus,
            "the precomputed hash enters the slot verbatim (no second SHA-256)"
        );
        assert_eq!(
            inputs.block_hashes[1],
            merkle::block_hash(&content[16384..32768]),
            "a None slot = computed in the pool (the status-quo path)"
        );
        // The root-mismatch verdict for a bogus hash is locked on the
        // verified.rs `piece_matches` side (the pool only moves values;
        // "when to trust" is unchanged).
    }

    /// Negative test: a block inside check_range bounds but unaligned
    /// must Err with **zero state change** — if bytes were accounted
    /// before the error, the rejected block's 16383B would permanently
    /// poison the piece's completion judgment (legal blocks could never
    /// add up exactly) and the upstream would eventually fail the whole
    /// task.
    #[test]
    fn unaligned_rejected_push_leaves_state_untouched() {
        let mut pool = HashPool::new_v2(vec![[0u8; 32]], 16384, 16384);
        // begin=1 + 16383B: 1+16384-1 = 16384 exactly in bounds (passes
        // check_range), but begin is not 16KiB aligned → UnalignedBlock.
        assert!(matches!(
            pool.push_block_with_precomputed(0, 1, &[0xAA; 16383], None),
            Err(RangeError::UnalignedBlock {
                index: 0,
                offset: 1
            })
        ));
        // Zero-change invariant: on Err the piece state matches pre-call.
        assert_eq!(
            pool.piece_received(0).unwrap_or_else(|e| panic!("{e}")),
            0,
            "a rejected block must not poison the bytes count"
        );
        // A later legal push is unaffected by residual state: one
        // whole-piece push completes it.
        assert!(
            pool.push_block(0, 0, &[0xBB; 16384])
                .unwrap_or_else(|e| panic!("{e}")),
            "a legal block after the rejection must still complete the piece exactly"
        );
    }

    /// Negative test (the same-slot duplicate path): a duplicate-slot Err
    /// is likewise zero-change — if bytes were accounted first, double
    /// counting would push an incomplete piece to complete=true while
    /// block hashes still have holes (completion invariant broken;
    /// v2_verify_inputs' hole-free premise void).
    #[test]
    fn duplicate_slot_rejected_without_poisoning_completion() {
        let content = pattern(32768); // 1 piece, 2 blocks
        let h0 = merkle::block_hash(&content[0..16384]);
        let h1 = merkle::block_hash(&content[16384..32768]);
        let root = merkle::root_from_block_hashes(&[h0, h1]);
        let mut pool = HashPool::new_v2(vec![root], 32768, 32768);
        assert!(
            !pool
                .push_block(0, 0, &content[0..16384])
                .unwrap_or_else(|e| panic!("{e}"))
        );
        // Same-slot duplicate (piece incomplete) → PieceAlreadyComplete
        // with zero change.
        assert!(matches!(
            pool.push_block(0, 0, &content[0..16384]),
            Err(RangeError::PieceAlreadyComplete { index: 0 })
        ));
        assert_eq!(
            pool.piece_received(0).unwrap_or_else(|e| panic!("{e}")),
            16384,
            "a rejected duplicate must not double-count bytes"
        );
        assert!(
            !pool.piece_complete(0).unwrap_or_else(|e| panic!("{e}")),
            "double counting must not push an incomplete piece to complete"
        );
        // Fill block 1 → complete with hole-free block hashes.
        assert!(
            pool.push_block(0, 16384, &content[16384..32768])
                .unwrap_or_else(|e| panic!("{e}"))
        );
        let inputs = pool
            .v2_verify_inputs(0)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|| panic!("completed-piece inputs must exist"));
        assert_eq!(inputs.block_hashes, vec![h0, h1]);
    }

    /// Range/state errors: out-of-bounds piece, in-piece overflow, no
    /// inputs before start, duplicate completion.
    #[test]
    fn range_and_state_errors() {
        let mut pool = HashPool::new_v1(&[0u8; 20], 16384, 16384);
        assert!(matches!(
            pool.push_block(1, 0, &[0u8; 16]),
            Err(RangeError::UnknownPiece { .. })
        ));
        assert!(matches!(
            pool.push_block(0, 16000, &[0u8; 512]),
            Err(RangeError::OutOfBounds { .. })
        ));
        // Not-started piece: completion false, v1 expected digest
        // available (Some answers the format kind, not startedness).
        assert!(!pool.piece_complete(0).unwrap_or_else(|e| panic!("{e}")));
        assert_eq!(
            pool.expected_v1_digest(0).unwrap_or_else(|e| panic!("{e}")),
            Some([0u8; 20])
        );
        let _ = pool.push_block(0, 0, &[0u8; 16384]);
        assert!(matches!(
            pool.push_block(0, 0, &[0u8; 16]),
            Err(RangeError::PieceAlreadyComplete { .. })
        ));
        // After reset, receiving again works (the refetch path).
        pool.reset_piece(0);
        assert!(!pool.piece_complete(0).unwrap_or_else(|e| panic!("{e}")));
        assert!(
            pool.push_block(0, 0, &[0u8; 16384])
                .unwrap_or_else(|e| panic!("{e}"))
        );
    }
}

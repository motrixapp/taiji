//! HashTreeCache (SPEC §4.3 / BEP-52 hash-exchange requester side).
//!
//! # Model (SPEC §4.3)
//!
//! - Metadata-supplied (trusted): the per-file **piece layer**
//!   (piece_length granularity), already recompute-verified at load time by
//!   `bt::filetree`;
//! - Lazily fetched cache: the **base layer** (16 KiB block granularity)
//!   and others, keyed by `(root, layer_depth)`, fetched from peers via
//!   hash request (21);
//! - Admission discipline: a lazily fetched layer must recompute bottom-up
//!   to the known piece roots before it is stored (BEP-52 / SPEC §4.3) —
//!   the current shape accepts piece-aligned whole segments only (partial
//!   segment verification needs proof chains and expands with interop
//!   testing);
//! - Core v2 benefit: block-granularity verification — `H(block)` is
//!   compared directly against the cached leaf layer; a failure re-fetches
//!   only that 16 KiB (v1 re-fetches the whole piece).
//!
//! # Relation to the write pipeline
//!
//! This type is the verification-math foundation; the write pipeline's
//! (verified.rs) v2 per-block write-through and the engine's lazy-fetch
//! triggering land with the v2 data-plane wiring.
//!
//! Upstream anchor mapping: docs/design/store.md

use std::collections::HashMap;

use crate::merkle;

/// Cache operation errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TreeError {
    #[error("file root {0:?} not registered (no metadata piece layer)")]
    UnknownRoot([u8; 32]),
    #[error("leaf layer for {0:?} not cached yet (fetch via hash request first)")]
    LeafLayerNotCached([u8; 32]),
    #[error("leaf index {index} beyond file leaf count {count}")]
    LeafIndexOutOfRange { index: u64, count: u64 },
    #[error(
        "leaf segment [start={start}, len={len}) must be piece-aligned ({bpp} leaves/piece) for M1 verification"
    )]
    SegmentNotPieceAligned { start: u64, len: u64, bpp: u64 },
    #[error("leaf segment verification failed at piece {piece}: recomputed root mismatch")]
    SegmentVerificationFailed { piece: u64 },
    #[error("block length {0} exceeds 16KiB")]
    OversizeBlock(usize),
}

/// Per-file hash tree: the trusted metadata piece layer plus a lazily
/// fetched block-layer cache.
#[derive(Debug, Default)]
pub struct HashTreeCache {
    piece_layers: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Keyed by `(file root, layer_depth)`; depth 0 = the leaf layer (16 KiB
    /// granularity).
    block_layers: HashMap<([u8; 32], u32), Vec<[u8; 32]>>,
    piece_len: u32,
}

impl HashTreeCache {
    pub fn new(piece_len: u32) -> HashTreeCache {
        HashTreeCache {
            piece_layers: HashMap::new(),
            block_layers: HashMap::new(),
            piece_len,
        }
    }

    pub fn piece_len(&self) -> u32 {
        self.piece_len
    }

    /// Register a file's metadata piece layer (trusted; already verified by
    /// bt::filetree at load).
    pub fn add_file(&mut self, root: [u8; 32], piece_layer: Vec<[u8; 32]>) {
        self.piece_layers.insert(root, piece_layer);
    }

    /// Whether a file anchor is registered (true for metadata-supplied
    /// layers and admitted recovery layers). Used for the duplicate
    /// admission check in `recovery::admit_piece_layer`.
    pub fn has_file(&self, root: &[u8; 32]) -> bool {
        self.piece_layers.contains_key(root)
    }

    /// Backfill a lazily fetched layer (piece-aligned whole segment); it is
    /// stored only if every piece recomputes to its piece root. depth 0 =
    /// the leaf layer. Any single mismatching piece rejects the whole
    /// segment (a bad hash entering the cache would keep polluting later
    /// block verification).
    pub fn verify_and_put_layer(
        &mut self,
        root: &[u8; 32],
        depth: u32,
        start_leaf: u64,
        hashes: Vec<[u8; 32]>,
    ) -> Result<(), TreeError> {
        let Some(pieces) = self.piece_layers.get(root) else {
            return Err(TreeError::UnknownRoot(*root));
        };
        let bpp = u64::from(merkle::blocks_per_piece(self.piece_len));
        if depth != 0 {
            // Only the leaf layer is needed (block verification compares it
            // directly); caching higher layers is deferred until needed.
            return Err(TreeError::SegmentNotPieceAligned {
                start: start_leaf,
                len: hashes.len() as u64,
                bpp,
            });
        }
        let start = start_leaf;
        let len = hashes.len() as u64;
        if !start.is_multiple_of(bpp) || !len.is_multiple_of(bpp) || len == 0 {
            return Err(TreeError::SegmentNotPieceAligned { start, len, bpp });
        }
        for (i, piece_rel) in (0..len / bpp).enumerate() {
            let piece_idx = start / bpp + piece_rel;
            let Some(&anchor) = pieces.get(piece_idx as usize) else {
                return Err(TreeError::LeafIndexOutOfRange {
                    index: piece_idx,
                    count: pieces.len() as u64,
                });
            };
            let seg = &hashes[i * bpp as usize..(i + 1) * bpp as usize];
            let recomputed = merkle::piece_root_from_block_hashes(seg, bpp as usize);
            if recomputed != anchor {
                return Err(TreeError::SegmentVerificationFailed { piece: piece_idx });
            }
        }
        // Storage: merging with existing cached ranges = plain whole-range
        // replacement (the requester fetches per piece range; overlapping
        // segments are necessarily identical — both passed the same anchor
        // check).
        let key = (*root, depth);
        let entry = self.block_layers.entry(key).or_default();
        if entry.len() < (start + len) as usize {
            entry.resize((start + len) as usize, [0u8; 32]);
        }
        entry[start as usize..(start + len) as usize].copy_from_slice(&hashes);
        Ok(())
    }

    /// Block-granularity verification (the core v2 benefit): `H(block)` is
    /// compared directly against the cached leaf layer. Failure means only
    /// that 16 KiB needs re-fetching (v1 re-fetches the whole piece; SPEC
    /// §4.3). A miss (layer not fetched) -> Err; the caller fetches the
    /// layer via hash request first.
    pub fn verify_block(
        &self,
        root: &[u8; 32],
        leaf_index: u64,
        block: &[u8],
    ) -> Result<bool, TreeError> {
        if block.len() > merkle::BLOCK_SIZE as usize {
            return Err(TreeError::OversizeBlock(block.len()));
        }
        let want = self.leaf_want(root, leaf_index)?;
        // The last block may be shorter than 16 KiB: hash the actual length
        // (BEP-52).
        Ok(merkle::block_hash(block) == want)
    }

    /// Block-granularity verification (precomputed-hash form): `hash` is
    /// the `H(block)` already computed by the write path (verified.rs buffer
    /// step 1.4, the second consumer of the same hash), compared directly
    /// against the cached leaf layer — avoiding a second SHA-256 over the
    /// same 16 KiB. Lookup and error behavior are bit-identical to
    /// [`Self::verify_block`] (the byte-length gate belongs to the caller —
    /// this form has no block bytes to check; the verified.rs `buffer_block`
    /// step 0 already rejects lengths outside (0, 16 KiB]). Cross-validated
    /// against libtorrent: the hash2 job consults the precomputed table
    /// first, and a hit skips the disk read and the recompute
    /// (`pread_disk_io.cpp` `fill_precomputed_v2`) — this method is the
    /// consuming half of that hit path.
    pub fn verify_block_hash(
        &self,
        root: &[u8; 32],
        leaf_index: u64,
        hash: &[u8; 32],
    ) -> Result<bool, TreeError> {
        Ok(self.leaf_want(root, leaf_index)? == *hash)
    }

    /// Expected-hash lookup in the leaf layer (shared by `verify_block` /
    /// `verify_block_hash`): error set and order identical to the lookup
    /// half of the pre-split `verify_block` (UnknownRoot -> leaf index out
    /// of range -> layer not cached -> index out of range within the
    /// layer).
    fn leaf_want(&self, root: &[u8; 32], leaf_index: u64) -> Result<[u8; 32], TreeError> {
        let Some(pieces) = self.piece_layers.get(root) else {
            return Err(TreeError::UnknownRoot(*root));
        };
        let leaves_total =
            pieces.len() as u64 * u64::from(merkle::blocks_per_piece(self.piece_len));
        if leaf_index >= leaves_total {
            return Err(TreeError::LeafIndexOutOfRange {
                index: leaf_index,
                count: leaves_total,
            });
        }
        let Some(layer) = self.block_layers.get(&(*root, 0)) else {
            return Err(TreeError::LeafLayerNotCached(*root));
        };
        let Some(&want) = layer.get(leaf_index as usize) else {
            return Err(TreeError::LeafIndexOutOfRange {
                index: leaf_index,
                count: layer.len() as u64,
            });
        };
        Ok(want)
    }

    /// Length of the cached leaf layer (for diagnostics/tests).
    pub fn leaf_layer_len(&self, root: &[u8; 32]) -> Option<usize> {
        self.block_layers.get(&(*root, 0)).map(|l| l.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;

    /// 4 pieces x 32 KiB (2 leaves/piece) = 8-leaf file fixture.
    fn fixture() -> (HashTreeCache, [u8; 32], Vec<u8>, Vec<[u8; 32]>) {
        const PIECE: u32 = 32768;
        let content: Vec<u8> = (0..4 * PIECE as usize).map(|i| (i % 251) as u8).collect();
        let leaves: Vec<[u8; 32]> = content.chunks(16384).map(merkle::block_hash).collect();
        let pieces: Vec<[u8; 32]> = leaves
            .chunks(2)
            .map(|p| merkle::node_hash(&p[0], &p[1]))
            .collect();
        let mut layer = pieces.clone();
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .map(|p| match p {
                    [l, r] => merkle::node_hash(l, r),
                    [l] => merkle::node_hash(l, l),
                    _ => unreachable!(),
                })
                .collect();
        }
        let root = layer[0];
        let mut cache = HashTreeCache::new(PIECE);
        cache.add_file(root, pieces);
        (cache, root, content, leaves)
    }

    /// Layer admission: a piece-aligned segment is stored only if it
    /// recomputes to every piece root; a bad segment is rejected.
    #[test]
    fn layer_admission_requires_piece_root_match() {
        let (mut cache, root, content, leaves) = fixture();
        // Correct segment for the first 2 pieces (4 leaves) -> stored.
        cache
            .verify_and_put_layer(&root, 0, 0, leaves[..4].to_vec())
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cache.leaf_layer_len(&root), Some(4));
        // One tampered leaf -> that piece root mismatches -> the whole
        // segment is rejected.
        let mut bad = leaves[4..8].to_vec();
        bad[0] = [0xFF; 32];
        assert!(matches!(
            cache.verify_and_put_layer(&root, 0, 4, bad),
            Err(TreeError::SegmentVerificationFailed { piece: 2 })
        ));
        assert_eq!(
            cache.leaf_layer_len(&root),
            Some(4),
            "a bad segment must not be stored"
        );
        let _ = content;
    }

    /// Block-granularity verification: correct blocks pass; flipping 1 bit
    /// in a 16 KiB block fails only that block (the core v2 benefit).
    #[test]
    fn per_block_verification_isolates_corruption() {
        let (mut cache, root, content, leaves) = fixture();
        cache
            .verify_and_put_layer(&root, 0, 0, leaves.clone())
            .unwrap_or_else(|e| panic!("{e}"));

        // All 8 blocks verify one by one.
        for (i, block) in content.chunks(16384).enumerate() {
            assert!(
                cache
                    .verify_block(&root, i as u64, block)
                    .unwrap_or_else(|e| panic!("{e}")),
                "block {i} should verify"
            );
        }
        // Corruption: flip 1 bit in block 5 -> only block 5 fails; the
        // neighbors are unaffected.
        let mut corrupted = content[5 * 16384..6 * 16384].to_vec();
        corrupted[0] ^= 0x01;
        assert!(
            !cache
                .verify_block(&root, 5, &corrupted)
                .unwrap_or_else(|e| panic!("{e}")),
            "the corrupted block must fail verification"
        );
        assert!(
            cache
                .verify_block(&root, 4, &content[4 * 16384..5 * 16384])
                .unwrap_or_else(|e| panic!("{e}")),
            "neighbor blocks are unaffected by the corruption"
        );
        assert!(
            cache
                .verify_block(&root, 6, &content[6 * 16384..7 * 16384])
                .unwrap_or_else(|e| panic!("{e}")),
            "neighbor blocks are unaffected by the corruption"
        );
    }

    /// Not fetched -> Err (the caller fetches the layer via hash request
    /// first); unregistered root -> Err.
    #[test]
    fn uncached_layer_and_unknown_root_error() {
        let (cache, root, _content, _leaves) = fixture();
        assert!(matches!(
            cache.verify_block(&root, 0, &[0u8; 100]),
            Err(TreeError::LeafLayerNotCached(_))
        ));
        assert!(matches!(
            cache.verify_block(&[9u8; 32], 0, &[0u8; 100]),
            Err(TreeError::UnknownRoot(_))
        ));
        // Leaf index out of range.
        let (mut cache, root, _c, leaves) = fixture();
        cache
            .verify_and_put_layer(&root, 0, 0, leaves)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cache.verify_block(&root, 8, &[0u8; 100]),
            Err(TreeError::LeafIndexOutOfRange { index: 8, count: 8 })
        ));
        // A non-piece-aligned segment is rejected.
        let (_, root2, _c2, leaves2) = fixture();
        assert!(matches!(
            cache.verify_and_put_layer(&root2, 0, 1, leaves2[..4].to_vec()),
            Err(TreeError::SegmentNotPieceAligned { .. })
        ));
    }

    /// Precomputed-hash compare (`verify_block_hash`) agrees with byte
    /// compare (`verify_block`) block by block, good and bad hashes alike;
    /// the error set (unknown root / layer not cached / leaf index out of
    /// range) and order match (shared `leaf_want` lookup).
    #[test]
    fn verify_block_hash_matches_verify_block() {
        let (mut cache, root, content, leaves) = fixture();
        cache
            .verify_and_put_layer(&root, 0, 0, leaves)
            .unwrap_or_else(|e| panic!("{e}"));
        // All 8 blocks: hash compare and byte compare agree (a good hash
        // passes, a bad hash fails).
        for (i, block) in content.chunks(16384).enumerate() {
            let h = merkle::block_hash(block);
            assert!(
                cache
                    .verify_block_hash(&root, i as u64, &h)
                    .unwrap_or_else(|e| panic!("{e}")),
                "block {i} precomputed-hash direct compare should pass"
            );
            assert!(
                cache
                    .verify_block(&root, i as u64, block)
                    .unwrap_or_else(|e| panic!("{e}")),
                "block {i} byte direct compare should pass"
            );
            let mut bad = h;
            bad[0] ^= 0xff;
            assert!(
                !cache
                    .verify_block_hash(&root, i as u64, &bad)
                    .unwrap_or_else(|e| panic!("{e}")),
                "block {i} bad hash must fail"
            );
        }
        // Error-set parity (same error order as verify_block: UnknownRoot
        // first).
        assert!(matches!(
            cache.verify_block_hash(&[0; 32], 0, &[0; 32]),
            Err(TreeError::UnknownRoot(_))
        ));
        assert!(matches!(
            cache.verify_block_hash(&root, 8, &[0; 32]),
            Err(TreeError::LeafIndexOutOfRange { index: 8, count: 8 })
        ));
        // Not fetched: registered root but no leaf layer ->
        // LeafLayerNotCached.
        let mut fresh = HashTreeCache::new(32768);
        fresh.add_file(root, vec![[0; 32]; 2]);
        assert!(matches!(
            fresh.verify_block_hash(&root, 0, &[0; 32]),
            Err(TreeError::LeafLayerNotCached(_))
        ));
    }
}

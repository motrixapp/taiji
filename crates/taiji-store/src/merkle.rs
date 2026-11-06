//! BEP-52 v2 Merkle tree math (SPEC §4.2/§4.3).
//!
//! Pure hash arithmetic, no IO. Leaf hash = `SHA256(16 KiB block)`,
//! interior node = `SHA256(left || right)`, no prefix bytes; missing leaf
//! slots are zero-padded to a power of two (per-piece trees pad to
//! `blocks_per_piece`). Shared by `taiji-bt::filetree` and the HashPool
//! (SPEC §4.3).
//!
//! Upstream anchor mapping: docs/design/store.md

use sha2::{Digest, Sha256};
use thiserror::Error;

/// v2 leaf granularity: 16 KiB (fixed by BEP-52; SPEC §4.2 `block_size` is
/// always 16 KiB).
pub const BLOCK_SIZE: u32 = 16 * 1024;

/// Zero leaf for tree balancing: 32 zero bytes themselves (not a hash;
/// provenance in the module docs).
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Piece length constraint (BEP-52: "It must be a power of two and at least
/// 16KiB").
pub fn validate_piece_len(piece_len: u32) -> Result<(), MerkleError> {
    if piece_len < BLOCK_SIZE || !piece_len.is_power_of_two() {
        return Err(MerkleError::InvalidPieceLength { piece_len });
    }
    Ok(())
}

/// Blocks per piece (>= 1 once `piece_len` passes [`validate_piece_len`]).
pub fn blocks_per_piece(piece_len: u32) -> u32 {
    piece_len / BLOCK_SIZE
}

/// Block hash: `SHA256(16 KiB block)`, no prefix bytes.
pub fn block_hash(block: &[u8]) -> [u8; 32] {
    Sha256::digest(block).into()
}

/// Interior node: `SHA256(left || right)`, no prefix bytes (see module
/// docs).
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of a block-hash sequence: zero-pad the leaf count to the next power
/// of two, then fold.
///
/// Two uses: the file root when the file fits in one piece (padded to a
/// power of two of the block count), and the root of a full piece (leaf
/// count = `blocks_per_piece`, already a power of two, so no padding is
/// added).
pub fn root_from_block_hashes(block_hashes: &[[u8; 32]]) -> [u8; 32] {
    debug_assert!(!block_hashes.is_empty());
    let mut layer = block_hashes.to_vec();
    layer.resize(next_pow2(layer.len()), ZERO_HASH);
    fold_pow2(layer)
}

/// File root computed from the piece-root layer ("one hash covers piece
/// length bytes"; the creator's layer->root step).
///
/// # Panics
///
/// Panics on an empty `piece_roots` slice (the `debug_assert!`; a file
/// with a piece root always has at least one piece — callers guarantee
/// non-empty). In release builds the assertion is compiled out; the
/// fold then degenerates to the empty-piece padding root rather than
/// panicking, which is why the caller-side guarantee matters.
pub fn file_root_from_piece_roots(piece_roots: &[[u8; 32]], blocks_per_piece: usize) -> [u8; 32] {
    debug_assert!(!piece_roots.is_empty());
    if piece_roots.len() == 1 {
        return piece_roots[0];
    }
    let mut layer = piece_roots.to_vec();
    layer.resize(next_pow2(layer.len()), empty_piece_root(blocks_per_piece));
    fold_pow2(layer)
}

/// File root from a block-hash sequence per the BEP-52 FileHasher rules:
/// group into piece roots, then fold the piece-root layer.
pub fn file_root(block_hashes: &[[u8; 32]], piece_len: u32) -> Result<[u8; 32], MerkleError> {
    validate_piece_len(piece_len)?;
    if block_hashes.is_empty() {
        // An empty file has no pieces root (BEP-52 "For non-empty files this
        // is …") and never reaches here; fail explicitly rather than return
        // zero silently.
        return Err(MerkleError::NoBlocks);
    }
    let bpp = blocks_per_piece(piece_len) as usize;
    if block_hashes.len() <= bpp {
        // File fits in one piece: tree = block count zero-padded to a power
        // of two (independent of piece size).
        return Ok(root_from_block_hashes(block_hashes));
    }
    let piece_roots: Vec<[u8; 32]> = block_hashes
        .chunks(bpp)
        .map(|chunk| {
            if chunk.len() == bpp {
                root_from_block_hashes(chunk)
            } else {
                // Short final group: pad to blocks_per_piece (a power of
                // two), not to the next power of two of the block count.
                let mut leaves = chunk.to_vec();
                leaves.resize(bpp, ZERO_HASH);
                fold_pow2(leaves)
            }
        })
        .collect();
    Ok(file_root_from_piece_roots(&piece_roots, bpp))
}

/// Load-time validation (SPEC §4.2): the layer must recompute the pieces
/// root, otherwise the torrent is rejected.
///
/// Tests: entry count == `ceil(file_len / piece_len)` (rejects a wrong
/// layer) and the root recomputed from the piece-root layer matches `root`
/// (rejects corruption).
pub fn validate_piece_layer(
    root: &[u8; 32],
    layer: &[u8],
    file_len: u64,
    piece_len: u32,
) -> Result<(), MerkleError> {
    validate_piece_len(piece_len)?;
    if file_len == 0 {
        return Err(MerkleError::InvalidFileLength(file_len));
    }
    if !layer.len().is_multiple_of(32) {
        return Err(MerkleError::LayerNotMultipleOf32 { len: layer.len() });
    }
    let expected = file_len.div_ceil(u64::from(piece_len));
    let count = (layer.len() / 32) as u64;
    if count != expected {
        return Err(MerkleError::LayerCountMismatch {
            expected,
            got: count,
        });
    }
    let piece_roots: Vec<[u8; 32]> = layer
        .as_chunks::<32>()
        .0
        .iter()
        .map(|c| {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            h
        })
        .collect();
    let computed = file_root_from_piece_roots(&piece_roots, blocks_per_piece(piece_len) as usize);
    if computed != *root {
        return Err(MerkleError::RootMismatch {
            expected: hex(root),
            computed: hex(&computed),
        });
    }
    Ok(())
}

/// Root of a single piece: leaves zero-padded to `blocks_per_piece` (piece
/// trees pad to the piece boundary — the creator's else branch); only when
/// this piece is the file's only piece does [`file_root`] pad to the block
/// count instead (tree shape independent of piece size). Used by the
/// HashPool's v2 whole-piece verification.
pub fn piece_root_from_block_hashes(
    block_hashes: &[[u8; 32]],
    blocks_per_piece: usize,
) -> [u8; 32] {
    debug_assert!(!block_hashes.is_empty());
    debug_assert!(blocks_per_piece.is_power_of_two() && blocks_per_piece >= 1);
    if block_hashes.len() == blocks_per_piece {
        return root_from_block_hashes(block_hashes);
    }
    debug_assert!(block_hashes.len() < blocks_per_piece);
    let mut leaves = block_hashes.to_vec();
    leaves.resize(blocks_per_piece, ZERO_HASH);
    fold_pow2(leaves)
}

/// Root of the all-zero-leaf tree (`blocks_per_piece` leaves): the padding
/// value used to fill up the piece-root layer.
///
/// Public because the hash-request server (`taiji-core::hash_source`) builds
/// upper layers from piece roots padded with the same BEP-52 tree shape —
/// the same rule as [`file_root_from_piece_roots`] (creator "balance the
/// tree by padding with zero hashes").
pub fn empty_piece_root(blocks_per_piece: usize) -> [u8; 32] {
    debug_assert!(blocks_per_piece.is_power_of_two() && blocks_per_piece >= 1);
    // The leaf count is a power of two, so no padding is needed — just fold.
    fold_pow2(vec![ZERO_HASH; blocks_per_piece])
}

/// Pairwise fold down to the root; the caller guarantees len >= 1 and a
/// power of two (BEP-52 tree shape).
fn fold_pow2(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
    debug_assert!(layer.len().is_power_of_two() && !layer.is_empty());
    while layer.len() > 1 {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| node_hash(&pair[0], &pair[1]))
            .collect();
    }
    layer[0]
}

/// Next power of two (matches the creator's `1 << (len - 1).bit_length()`;
/// unchanged when already a power of two).
fn next_pow2(n: usize) -> usize {
    debug_assert!(n >= 1);
    n.next_power_of_two()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MerkleError {
    #[error("piece length {piece_len} must be a power of two and at least 16KiB (BEP52)")]
    InvalidPieceLength { piece_len: u32 },
    #[error("empty block list: a file with a piece root must have at least one block")]
    NoBlocks,
    #[error("invalid file length {0}: must be non-zero when a piece layer is present")]
    InvalidFileLength(u64),
    #[error("piece layer length {len} is not a multiple of 32")]
    LayerNotMultipleOf32 { len: usize },
    #[error("piece layer has {got} hashes, expected {expected} (= ceil(file_len/piece_len))")]
    LayerCountMismatch { expected: u64, got: u64 },
    #[error("piece layer recompute mismatch: expected root {expected}, computed {computed}")]
    RootMismatch { expected: String, computed: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-vector reference: results of running the BEP-52 official
    /// reference implementation `bep_0052_torrent_creator.py`
    /// (bittorrent.org/beps/) on `b"blackhole-merkle-reference-"` cycled to
    /// the given length. The content must be rebuilt exactly as this
    /// function does.
    fn test_content(len: usize) -> Vec<u8> {
        const PATTERN: &[u8] = b"blackhole-merkle-reference-";
        PATTERN.iter().cycle().take(len).copied().collect()
    }

    fn unhex(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "vector must be 32-byte hex, got {s}");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .unwrap_or_else(|e| panic!("bad hex vector: {e}"));
        }
        out
    }

    fn unhex_layer(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(64), "layer hex must be whole hashes");
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(
                    std::str::from_utf8(pair).unwrap_or_else(|e| panic!("{e}")),
                    16,
                )
                .unwrap_or_else(|e| panic!("bad hex vector: {e}"))
            })
            .collect()
    }

    /// Block-hash sequence (16 KiB chunks).
    fn blocks(content: &[u8]) -> Vec<[u8; 32]> {
        content
            .chunks(BLOCK_SIZE as usize)
            .map(block_hash)
            .collect()
    }

    /// Piece-root layer bytes (creator storage format: piece roots
    /// concatenated in order).
    fn layer_bytes(content: &[u8], piece_len: u32) -> Vec<u8> {
        let bpp = blocks_per_piece(piece_len) as usize;
        let mut out = Vec::new();
        for chunk in blocks(content).chunks(bpp) {
            let root = if chunk.len() == bpp {
                root_from_block_hashes(chunk)
            } else {
                let mut leaves = chunk.to_vec();
                leaves.resize(bpp, ZERO_HASH);
                fold_pow2(leaves)
            };
            out.extend_from_slice(&root);
        }
        out
    }

    /// V1: 90 B < 16 KiB, single block (root == block hash == the only piece
    /// root).
    #[test]
    fn v1_single_block_90b() {
        let content = test_content(90);
        let root = file_root(&blocks(&content), 16 * 1024).ok();
        let want = unhex("459c122a0c223b8465bb25ab1a88233eebfa33452f7151437f2986de5e4afaeb");
        assert_eq!(root, Some(want));
        assert_eq!(block_hash(&content), want);
    }

    /// V2: 20000 B = 2 blocks (16384 + 3616); 2 is already a power of two,
    /// root = node(h0, h1).
    #[test]
    fn v2_two_blocks_20000b() {
        let content = test_content(20000);
        let root = file_root(&blocks(&content), 16 * 1024).ok();
        let want = unhex("70d5e293b168effe081a92df2b8bc6d0447c4bcbe620ecb0cd4f788c27c38d67");
        assert_eq!(root, Some(want));
    }

    /// V3: 40000 B = 3 blocks -> not a power of two; padded with one zero
    /// leaf before folding (non-power-of-two padding rule). The piece-root
    /// layer has 3 entries and the layer->root recompute matches (creator
    /// padding path).
    #[test]
    fn v3_three_blocks_nonpow2_40000b() {
        let content = test_content(40000);
        let want_root = unhex("3243e71b370b568e8f3b74d494545e15165cbd897b594811c698641760f93bf7");
        assert_eq!(
            file_root(&blocks(&content), 16 * 1024).ok(),
            Some(want_root)
        );

        let layer = layer_bytes(&content, 16 * 1024);
        assert_eq!(layer.len() / 32, 3);
        assert!(validate_piece_layer(&want_root, &layer, 40000, 16 * 1024).is_ok());
    }

    /// V4: 70000 B = 5 blocks, 5 pieces (same shape as a.bin in the hybrid
    /// fixture): the 5-entry piece-root layer is padded with 3 zero pad
    /// values, then folded.
    #[test]
    fn v4_five_blocks_70000b() {
        let content = test_content(70000);
        let want_root = unhex("8f854d946585d2a0c1d60705bf092f069988caad10b539473d2640402536771b");
        assert_eq!(
            file_root(&blocks(&content), 16 * 1024).ok(),
            Some(want_root)
        );
        let layer = layer_bytes(&content, 16 * 1024);
        assert_eq!(layer.len() / 32, 5);
        assert!(validate_piece_layer(&want_root, &layer, 70000, 16 * 1024).is_ok());
    }

    /// V5: 65536 B is exactly one piece (piece 64 KiB): root == piece root ==
    /// root of the 4-full-block tree. The layer exists only when the file
    /// exceeds the piece size; here the single entry is the root itself.
    #[test]
    fn v5_single_piece_64k() {
        let content = test_content(65536);
        let want_root = unhex("a344810a6420bf2892406b1609f3fcf17144c39ac932efba23bf5977fbb434c6");
        assert_eq!(
            file_root(&blocks(&content), 64 * 1024).ok(),
            Some(want_root)
        );
        let layer = layer_bytes(&content, 64 * 1024);
        assert_eq!(layer.len(), 32);
        assert!(validate_piece_layer(&want_root, &layer, 65536, 64 * 1024).is_ok());
    }

    /// V6: 100000 B / 64 KiB = 2 pieces; the last piece has 3 blocks padded
    /// to bpp = 4 (block-level zero-padding path). Piece 0's root equals V5's
    /// root (same content prefix; piece-size independence).
    #[test]
    fn v6_two_pieces_100k_64k() {
        let content = test_content(100000);
        let want_root = unhex("7a3eaa86f2ce940774650439851d3c1c9b1ef5aea5fe034807ccb1127c140c4e");
        assert_eq!(
            file_root(&blocks(&content), 64 * 1024).ok(),
            Some(want_root)
        );
        let layer = layer_bytes(&content, 64 * 1024);
        assert_eq!(layer.len() / 32, 2);
        assert_eq!(
            &layer[..32],
            &unhex("a344810a6420bf2892406b1609f3fcf17144c39ac932efba23bf5977fbb434c6")
        );
        assert!(validate_piece_layer(&want_root, &layer, 100000, 64 * 1024).is_ok());
    }

    /// V7: the file root is independent of piece size (BEP-52 "identical
    /// files …"): the same 70000 B content has one root under 16 KiB / 64 KiB
    /// / 256 KiB pieces.
    #[test]
    fn v7_root_independent_of_piece_size() {
        let content = test_content(70000);
        let r16 = file_root(&blocks(&content), 16 * 1024).ok();
        let r64 = file_root(&blocks(&content), 64 * 1024).ok();
        let r256 = file_root(&blocks(&content), 256 * 1024).ok();
        assert_eq!(r16, r64);
        assert_eq!(r64, r256);
    }

    /// Corrupted layer (last hash flipped) -> RootMismatch; wrong entry
    /// count -> LayerCountMismatch.
    #[test]
    fn layer_validation_negatives() {
        let content = test_content(40000);
        let root = file_root(&blocks(&content), 16 * 1024).ok();
        let want_root = unhex("3243e71b370b568e8f3b74d494545e15165cbd897b594811c698641760f93bf7");
        assert_eq!(root, Some(want_root));
        let mut layer = layer_bytes(&content, 16 * 1024);

        let last = layer.len() - 1;
        layer[last] ^= 0xff;
        let err = validate_piece_layer(&want_root, &layer, 40000, 16 * 1024)
            .err()
            .unwrap_or_else(|| panic!("corrupted layer must be rejected"));
        assert!(matches!(err, MerkleError::RootMismatch { .. }), "got {err}");

        let truncated = &layer[..64]; // 2 entries, expected 3
        let err = validate_piece_layer(&want_root, truncated, 40000, 16 * 1024)
            .err()
            .unwrap_or_else(|| panic!("wrong layer count must be rejected"));
        assert!(
            matches!(
                err,
                MerkleError::LayerCountMismatch {
                    expected: 3,
                    got: 2
                }
            ),
            "got {err}"
        );
    }

    /// Layer length not a multiple of 32, zero file length, invalid piece
    /// lengths (< 16 KiB / not a power of two).
    #[test]
    fn parameter_validation_negatives() {
        let content = test_content(40000);
        let root = file_root(&blocks(&content), 16 * 1024).ok();
        let want_root = unhex("3243e71b370b568e8f3b74d494545e15165cbd897b594811c698641760f93bf7");
        assert_eq!(root, Some(want_root));
        let layer = layer_bytes(&content, 16 * 1024);

        let err = validate_piece_layer(&want_root, &layer[..40], 40000, 16 * 1024)
            .err()
            .unwrap_or_else(|| panic!("must reject non-multiple-of-32"));
        assert!(
            matches!(err, MerkleError::LayerNotMultipleOf32 { .. }),
            "got {err}"
        );

        let err = validate_piece_layer(&want_root, &layer, 0, 16 * 1024)
            .err()
            .unwrap_or_else(|| panic!("must reject zero length"));
        assert!(
            matches!(err, MerkleError::InvalidFileLength(0)),
            "got {err}"
        );

        for bad in [8 * 1024u32, 24 * 1024, 0] {
            let err = validate_piece_len(bad)
                .err()
                .unwrap_or_else(|| panic!("piece length {bad} must be rejected"));
            assert!(
                matches!(err, MerkleError::InvalidPieceLength { .. }),
                "got {err}"
            );
            assert!(file_root(&blocks(&content), bad).is_err());
        }
    }

    /// An empty block sequence has no root (BEP-52: an empty file has no
    /// pieces root).
    #[test]
    fn empty_blocks_rejected() {
        assert!(matches!(
            file_root(&[], 16 * 1024),
            Err(MerkleError::NoBlocks)
        ));
    }

    /// With a single piece root, the root is that value (a redundant layer
    /// for a small file still validates).
    #[test]
    fn redundant_layer_for_small_file() {
        let content = test_content(90);
        let root = file_root(&blocks(&content), 16 * 1024).ok();
        let want = unhex("459c122a0c223b8465bb25ab1a88233eebfa33452f7151437f2986de5e4afaeb");
        assert_eq!(root, Some(want));
        let layer = unhex_layer("459c122a0c223b8465bb25ab1a88233eebfa33452f7151437f2986de5e4afaeb");
        assert!(validate_piece_layer(&want, &layer, 90, 16 * 1024).is_ok());
    }
}

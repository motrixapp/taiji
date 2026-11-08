//! Whole-file admission of recovered piece layers (SPEC §4.2
//! "missing-layer degradation and recovery" / §4.3 "recovery-layer
//! admission").
//!
//! # Trust model (root convergence is trust; single-source verification,
//! no voting)
//!
//! The only authority for a missing piece layer is the per-file pieces
//! root inside the info dictionary (the root is protected by the
//! infohash — BEP-52 info dictionary section: "implementations must also
//! check that the piece layers hashes outside the info dictionary match
//! the pieces root fields"). A delivered layer therefore has exactly one
//! trust criterion: **per-file recomputation converging on that pieces
//! root** ([`merkle::validate_piece_layer`]: the count criterion rules
//! out a wrong-layer delivery; the root recompute rules out corrupted
//! content). Once convergence passes, a recovered layer carries the
//! **same trust level as a metadata-carried layer** — every downstream
//! consumer ([`HashTreeCache`] anchors, the lazy-fetch domain, recheck
//! expectations) works the fully-provisioned path with no distinction
//! by layer origin.
//!
//! # Admission granularity (transfer per block, quarantine per block,
//! admission per whole file)
//!
//! A file is verified and admitted **once**, after all of its blocks
//! have arrived; if any block fails its part of the check the whole file
//! is refused (the caller counts the drop and re-fetches), and no
//! content may enter the anchor/lazy-fetch domain before whole-file
//! convergence (SPEC §4.3 addendum). The difference from the lazy-fetch
//! "verify-and-admit per segment" ([`HashTreeCache::verify_and_put_layer`])
//! is structural: lazy-fetch segments have the metadata layer as a
//! per-piece anchor; in the recovery scenario no anchor exists yet, so
//! only whole-file convergence works.
//!
//! This module is pure hash judgment + cache writes — no IO, no network;
//! the caller (the engine consumer side) owns the delivery channel, drop
//! counting, and re-fetch bookkeeping.
//!
//! Upstream anchor mapping: docs/design/store.md

use crate::hashtree::HashTreeCache;
use crate::merkle::{self, MerkleError};

/// Whole-file layer admission result errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdmissionError {
    /// This file's pieces root already has a registered anchor (a
    /// metadata-carried layer or a previously admitted recovery layer).
    /// A recovered layer has the same trust level as an existing anchor,
    /// so re-admission adds nothing — the caller drops the delivery
    /// benignly (not counted as a bad layer).
    #[error("pieces root already anchored (metadata layer or prior recovery)")]
    AlreadyAnchored,
    /// Convergence check failed (count or root-recompute mismatch): the
    /// whole file is refused.
    #[error("recovered piece layer failed whole-file convergence: {0}")]
    ConvergenceFailed(#[source] MerkleError),
    /// The delivered payload has 0 hashes (nothing to converge; a
    /// caller-side delivery anomaly).
    #[error("recovered piece layer is empty")]
    EmptyLayer,
}

/// Number of piece-layer hashes for a file
/// (`ceil(file_len / piece_len)`; BEP-52 `piece layers` section: "Layer
/// hashes which exclusively cover data beyond the end of file … are
/// omitted").
fn expected_piece_count(file_len: u64, piece_len: u32) -> u64 {
    file_len.div_ceil(u64::from(piece_len))
}

/// Whole-file piece-layer admission (the only admission path; the
/// consumer of the `RecoveredPieceLayer` delivery payload).
///
/// Flow: truncate the delivered layer to `ceil(file_len/piece_len)`
/// hashes (zero-padded tail slots and extra hashes from the peer are
/// trimmed here — the equivalent of the lazy-fetch trim in
/// [`crate::hash_fetch`] `admit_hashes`) -> one-shot convergence check
/// via [`merkle::validate_piece_layer`] -> on success
/// [`HashTreeCache::add_file`] registers the anchors (the same trust
/// level as a metadata-carried layer).
///
/// `Ok(())` = trust established; `Err` = the whole file is refused
/// (zero writes to the anchor domain) and the caller counts the drop and
/// re-fetches from another peer (with whole-file admission granularity a
/// bad block cannot be located, so the re-fetch unit is the whole file
/// too).
pub fn admit_piece_layer(
    trees: &mut HashTreeCache,
    root: &[u8; 32],
    layer: &[[u8; 32]],
    file_len: u64,
    piece_len: u32,
) -> Result<(), AdmissionError> {
    if trees.has_file(root) {
        return Err(AdmissionError::AlreadyAnchored);
    }
    if layer.is_empty() {
        return Err(AdmissionError::EmptyLayer);
    }
    let pieces = expected_piece_count(file_len, piece_len);
    let take = (layer.len() as u64).min(pieces) as usize;
    let bytes: Vec<u8> = layer[..take]
        .iter()
        .flat_map(|h| h.iter())
        .copied()
        .collect();
    // One-shot convergence criterion: count == ceil(len/piece_len)
    // (rules out a wrong layer) and the piece-root layer recompute
    // converges on the info pieces root (rules out corrupt content —
    // one bad block fails the whole file as RootMismatch). A short
    // delivery after trimming also fails here explicitly.
    merkle::validate_piece_layer(root, &bytes, file_len, piece_len)
        .map_err(AdmissionError::ConvergenceFailed)?;
    let piece_roots: Vec<[u8; 32]> = bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|c| {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            h
        })
        .collect();
    trees.add_file(*root, piece_roots);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::BLOCK_SIZE;

    /// File geometry of 3 pieces x 16KiB (bpp = 1): content / true
    /// piece-root layer / file root.
    fn fixture() -> (Vec<u8>, Vec<[u8; 32]>, [u8; 32]) {
        let content: Vec<u8> = (0..3 * BLOCK_SIZE as usize)
            .map(|i| (i % 249) as u8)
            .collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let root = merkle::file_root(&leaves, BLOCK_SIZE).unwrap_or_else(|e| panic!("{e}"));
        (content, leaves, root)
    }

    /// Admission convergence table:
    /// - good layer (true piece-root layer) -> converges and is admitted
    ///   with the same trust level as a metadata-carried layer
    ///   (downstream `verify_and_put_layer`/`verify_block` behave
    ///   bit-for-bit identically);
    /// - bad layer (any hash flipped 1 bit) -> the whole file is
    ///   refused;
    /// - wrong layer (a half-block layer string — count mismatch) ->
    ///   refused;
    /// - wrong root (converges on a different root) -> refused;
    /// - short delivery (too few hashes) -> refused;
    /// - extra hashes (untrimmed out-of-bounds slots) -> admitted after
    ///   trimming;
    /// - empty payload -> refused.
    #[test]
    fn admission_convergence_table() {
        let (content, piece_roots, root) = fixture();

        // Good 1: the true layer is admitted -> the anchor domain goes
        // live (lazy-fetch admission / block checks work — direct
        // evidence of downstream equivalence with a metadata layer).
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        admit_piece_layer(
            &mut trees,
            &root,
            &piece_roots,
            content.len() as u64,
            BLOCK_SIZE,
        )
        .unwrap_or_else(|e| panic!("good layer must admit: {e}"));
        assert!(
            trees.has_file(&root),
            "convergence succeeded = registered in the anchor domain"
        );
        // Downstream equivalence: lazy leaf-layer backfill + block
        // checks run on the same path as for a metadata layer.
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        trees
            .verify_and_put_layer(&root, 0, 0, leaves.clone())
            .unwrap_or_else(|e| panic!("lazy admission must work after recovery: {e}"));
        for (i, block) in content.chunks(BLOCK_SIZE as usize).enumerate() {
            assert!(
                trees
                    .verify_block(&root, i as u64, block)
                    .unwrap_or_else(|e| panic!("{e}")),
                "block {i} verifies against recovered anchors"
            );
        }

        // Good 2: extra hashes (zero-padded tail-slot shape) -> admitted
        // after truncating to the piece count.
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        let mut padded = piece_roots.clone();
        padded.push([0u8; 32]);
        admit_piece_layer(&mut trees, &root, &padded, content.len() as u64, BLOCK_SIZE)
            .unwrap_or_else(|e| panic!("over-long delivery must truncate-admit: {e}"));
        assert!(trees.has_file(&root));

        // Good 3: re-admission (root already anchored) ->
        // AlreadyAnchored (the benign-drop face).
        assert!(matches!(
            admit_piece_layer(
                &mut trees,
                &root,
                &piece_roots,
                content.len() as u64,
                BLOCK_SIZE
            ),
            Err(AdmissionError::AlreadyAnchored)
        ));

        // Bad 1: any block flipped 1 bit -> the whole file is refused
        // (quarantine per block, admission per whole file); zero writes
        // to the anchor domain.
        let mut bad = piece_roots.clone();
        bad[1][0] ^= 0x01;
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        assert!(
            matches!(
                admit_piece_layer(&mut trees, &root, &bad, content.len() as u64, BLOCK_SIZE),
                Err(AdmissionError::ConvergenceFailed(
                    MerkleError::RootMismatch { .. }
                ))
            ),
            "bit-flipped block must reject whole file"
        );
        assert!(!trees.has_file(&root), "a bad layer must not be stored");

        // Bad 2: wrong layer (a half-block layer of 6 hashes instead of
        // 3 piece roots) -> trimmed to the piece count first, leaving 3
        // half-block hashes rather than piece roots -> root recompute
        // mismatch, still refused whole. The genuinely short-layer shape
        // excluded by the count criterion is Bad 3.
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        let wrong_layer: Vec<[u8; 32]> = content
            .chunks(BLOCK_SIZE as usize / 2)
            .map(merkle::block_hash)
            .collect();
        assert!(
            matches!(
                admit_piece_layer(
                    &mut trees,
                    &root,
                    &wrong_layer,
                    content.len() as u64,
                    BLOCK_SIZE
                ),
                Err(AdmissionError::ConvergenceFailed(
                    MerkleError::RootMismatch { .. }
                ))
            ),
            "wrong-layer delivery must reject on root recompute"
        );
        assert!(!trees.has_file(&root));

        // Bad 3: short delivery (too few hashes) -> count mismatch after
        // trimming -> refused.
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        assert!(matches!(
            admit_piece_layer(
                &mut trees,
                &root,
                &piece_roots[..2],
                content.len() as u64,
                BLOCK_SIZE
            ),
            Err(AdmissionError::ConvergenceFailed(
                MerkleError::LayerCountMismatch {
                    expected: 3,
                    got: 2
                }
            ))
        ));
        assert!(!trees.has_file(&root));

        // Bad 4: a delivered layer converging on another root
        // (wrong-root delivery) -> excluded by the root criterion.
        let (_, other_roots, other_root) = {
            let content: Vec<u8> = (0..3 * BLOCK_SIZE as usize)
                .map(|i| (i % 241) as u8)
                .collect();
            let leaves: Vec<[u8; 32]> = content
                .chunks(BLOCK_SIZE as usize)
                .map(merkle::block_hash)
                .collect();
            let root = merkle::file_root(&leaves, BLOCK_SIZE).unwrap_or_else(|e| panic!("{e}"));
            (content, leaves, root)
        };
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        // Deliver another file's layer against this file's root: the
        // count matches, the root does not.
        assert!(
            matches!(
                admit_piece_layer(
                    &mut trees,
                    &root,
                    &other_roots,
                    content.len() as u64,
                    BLOCK_SIZE
                ),
                Err(AdmissionError::ConvergenceFailed(
                    MerkleError::RootMismatch { .. }
                ))
            ),
            "cross-root delivery must reject"
        );
        assert!(!trees.has_file(&root));
        // The converse check: that layer is good against its own root.
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        admit_piece_layer(
            &mut trees,
            &other_root,
            &other_roots,
            content.len() as u64,
            BLOCK_SIZE,
        )
        .unwrap_or_else(|e| panic!("own root must admit: {e}"));

        // Bad 5: empty payload -> refused.
        let mut trees = HashTreeCache::new(BLOCK_SIZE);
        assert!(matches!(
            admit_piece_layer(&mut trees, &root, &[], content.len() as u64, BLOCK_SIZE),
            Err(AdmissionError::EmptyLayer)
        ));
        assert!(!trees.has_file(&root));
        // Parameter face: a zero-length file (no layer semantics) is
        // refused by the criterion.
        assert!(matches!(
            admit_piece_layer(&mut trees, &root, &piece_roots, 0, BLOCK_SIZE),
            Err(AdmissionError::ConvergenceFailed(
                MerkleError::InvalidFileLength(0)
            ))
        ));
    }

    /// Admission equivalence (the hash-face proof that both trust paths
    /// are level-identical): for the same file geometry, registering the
    /// metadata layer via `add_file` directly and admitting the same
    /// layer through `admit_piece_layer` yield bit-identical anchors
    /// (under add_file's overwrite semantics both paths converge to the
    /// same cache state).
    #[test]
    fn admitted_recovery_equals_metadata_layer_bit_for_bit() {
        let (content, piece_roots, root) = fixture();
        let mut via_metadata = HashTreeCache::new(BLOCK_SIZE);
        via_metadata.add_file(root, piece_roots.clone());
        let mut via_recovery = HashTreeCache::new(BLOCK_SIZE);
        admit_piece_layer(
            &mut via_recovery,
            &root,
            &piece_roots,
            content.len() as u64,
            BLOCK_SIZE,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        // Downstream observable face: lazy-fetch admission and block
        // checks behave identically on both trust paths.
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        for trees in [&mut via_metadata, &mut via_recovery] {
            trees
                .verify_and_put_layer(&root, 0, 0, leaves.clone())
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let mut corrupted = content.clone();
        corrupted[0] ^= 0x01;
        for trees in [&via_metadata, &via_recovery] {
            assert!(
                !trees
                    .verify_block(&root, 0, &corrupted[..BLOCK_SIZE as usize])
                    .unwrap_or_else(|e| panic!("{e}")),
                "the bad-block verdict must be bit-identical on both trust paths"
            );
            assert!(
                trees
                    .verify_block(
                        &root,
                        1,
                        &content[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize]
                    )
                    .unwrap_or_else(|e| panic!("{e}")),
                "the good-block verdict must be bit-identical on both trust paths"
            );
        }
    }
}

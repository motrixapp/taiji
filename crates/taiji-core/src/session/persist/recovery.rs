//! Recovery-layer derived row assembly and startup restore injection
//! (pure functions, no IO — call sites are the engine admission arm and
//! the session activation chain; table-driven tests in the same file).
//!
//! - Write side: the recovery layer admitted wholesale at runtime ->
//! the [`RecoveredLayerRow`] store payload (through the PersistWriter
//! seam, SPEC §2.3 single-writer);
//! - Read side: at task activation/upgrade, derived table rows ->
//! per-file admission-semantics revalidation
//! ([`merkle::validate_piece_layer`] piece count + root convergence)
//! -> on pass, merge into the metadata (the same trust level as
//! metadata-carried layers); on failure (a hand-tampered or stale
//! store row) do not merge — the file stays in the layer_missing
//! gated state for the swarm to re-fetch — never fully-configure with
//! a sick layer.

use taiji_store::merkle;
use taiji_store::persist::RecoveredLayerRow;

use crate::metainfo::TorrentMeta;

// The write-side row assembly implementation lives in the engine
// subtree (`engine::recovery` — the runtime admission arm is the only
// producer); re-exported here so this module's read side (restore
// injection) and the tests share one path, with zero drift on the
// existing public path.
pub use crate::engine::recovery::recovered_layer_row;

/// Startup restore report (an observation face, never silent).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreReport {
    /// Files (file_index) whose revalidation passed and were merged
    /// into the metadata.
    pub applied: Vec<u32>,
    /// Rows that failed revalidation / do not apply: (file_index,
    /// reason). The file keeps the layer-missing gated state.
    pub rejected: Vec<(u32, String)>,
}

/// Derived table rows -> metadata injection (the task activation/
/// upgrade read-back face). Per-file independent: a bad row affects
/// only its own file (falls back to layer-missing re-fetch) and never
/// blocks the remaining files from being fully configured.
///
/// Criteria (same source as the admission semantics): the row's
/// piece_length matches the metadata + the file is layer-missing (a
/// metadata-carried layer is never replaced) + the root matches the
/// pieces root inside the info dict + the layer converges when
/// recomputed to the root. Any failure = the row is not merged.
pub fn apply_recovered_layers(meta: &mut TorrentMeta, rows: &[RecoveredLayerRow]) -> RestoreReport {
    let piece_len = meta.piece_length;
    let mut report = RestoreReport::default();
    for row in rows {
        let file_index = row.file_index.max(0) as u32;
        let mut reject = |reason: String| {
            report.rejected.push((file_index, reason));
        };
        let Some(f) = meta.files.get_mut(row.file_index.max(0) as usize) else {
            reject(format!("file index {file_index} out of range"));
            continue;
        };
        if row.piece_length != i64::from(piece_len) {
            reject(format!(
                "piece_length mismatch: row {} vs meta {piece_len}",
                row.piece_length
            ));
            continue;
        }
        if !f.layer_missing(piece_len) {
            // Fully-configured / single-piece files have no re-entry
            // semantics (layer in place or the root is the leaf) — the
            // row is void.
            reject("file not layer-missing (metadata layer present or single piece)".into());
            continue;
        }
        let Some(root) = f.pieces_root else {
            reject("file has no pieces root".into());
            continue;
        };
        if row.pieces_root.len() != 32 || row.pieces_root != root.to_vec() {
            reject("pieces root mismatch with metadata".into());
            continue;
        }
        let pieces = f.length.div_ceil(u64::from(piece_len)) as usize;
        if row.file_length < 0
            || row.file_length as u64 != f.length
            || row.layer.len() != pieces * 32
        {
            reject(format!(
                "file_length/layer size mismatch: row {}/{}B vs meta {}/{}B",
                row.file_length,
                row.layer.len(),
                f.length,
                pieces * 32
            ));
            continue;
        }
        if let Err(e) = merkle::validate_piece_layer(&root, &row.layer, f.length, piece_len) {
            reject(format!("layer convergence failed: {e}"));
            continue;
        }
        f.piece_layer = Some(bytes::Bytes::from(row.layer.clone()));
        report.applied.push(file_index);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_fetch::RecoveredPieceLayer;
    use crate::metainfo::TorrentIdentity;
    use std::path::PathBuf;

    // ==== recovery-layer store assembly + startup restore injection
    // (table-driven) ====

    /// Two-file v2 metadata: f0 layer-missing (multi-piece, root
    /// present, layer None), f1 fully configured (layer in place — the
    /// control; a metadata-carried layer is never replaced).
    fn v2_meta_with_missing_file() -> (TorrentMeta, [u8; 32], Vec<u8>, [u8; 32], Vec<u8>) {
        use taiji_store::merkle::{self, BLOCK_SIZE};
        let content: Vec<u8> = (0..2 * BLOCK_SIZE as usize)
            .map(|i| (i % 249) as u8)
            .collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        // piece = BLOCK shape (bpp = 1, so the piece-count criterion is
        // direct).
        let layer: Vec<u8> = leaves.iter().flat_map(|h| h.iter()).copied().collect();
        let missing_root = merkle::file_root(&leaves, BLOCK_SIZE).unwrap_or_else(|e| panic!("{e}"));
        // f1 control: different content, different root, different
        // layer.
        let content2: Vec<u8> = (0..BLOCK_SIZE as usize).map(|i| (i % 241) as u8).collect();
        let leaves2: Vec<[u8; 32]> = content2
            .chunks(BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let full_root = merkle::file_root(&leaves2, BLOCK_SIZE).unwrap_or_else(|e| panic!("{e}"));
        let full_layer: Vec<u8> = leaves2.iter().flat_map(|h| h.iter()).copied().collect();
        let meta = TorrentMeta {
            identity: TorrentIdentity {
                v1: None,
                v2: Some([7u8; 32]),
            },
            kind: taiji_bt::filetree::SwarmKind::V2Only,
            piece_length: BLOCK_SIZE,
            files: vec![
                crate::metainfo::MetaFile {
                    path: PathBuf::from("missing.bin"),
                    length: 2 * BLOCK_SIZE as u64,
                    padding: false,
                    pieces_root: Some(missing_root),
                    piece_layer: None,
                    v1_offset: None,
                },
                crate::metainfo::MetaFile {
                    path: PathBuf::from("full.bin"),
                    length: BLOCK_SIZE as u64,
                    padding: false,
                    pieces_root: Some(full_root),
                    piece_layer: Some(bytes::Bytes::from(full_layer.clone())),
                    v1_offset: None,
                },
            ],
        };
        (meta, missing_root, layer, full_root, full_layer)
    }

    /// Derived row builder (criteria payload filled directly;
    /// piece_length always = meta.piece_length).
    fn mk_row(
        meta: &TorrentMeta,
        file_index: i64,
        root: [u8; 32],
        bytes: Vec<u8>,
        file_length: i64,
    ) -> taiji_store::persist::RecoveredLayerRow {
        taiji_store::persist::RecoveredLayerRow {
            gid: "80000000000000aa".into(),
            file_index,
            piece_length: meta.piece_length as i64,
            file_length,
            pieces_root: root.to_vec(),
            layer: bytes,
        }
    }

    /// Store assembly: RecoveredPieceLayer -> row payload field by
    /// field (criteria payload + layer byte concatenation); key = gid +
    /// file_index.
    #[test]
    fn recovered_layer_row_assembly_matches_delivery() {
        let (_, root, layer, _, _) = v2_meta_with_missing_file();
        let rec = RecoveredPieceLayer {
            root,
            file_len: 2 * 16384,
            piece_len: 16384,
            layer: layer
                .chunks_exact(32)
                .map(|c| {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(c);
                    h
                })
                .collect(),
        };
        let row = recovered_layer_row("80000000000000aa", 0, &rec);
        assert_eq!(row.gid, "80000000000000aa");
        assert_eq!(row.file_index, 0);
        assert_eq!(row.pieces_root, root.to_vec());
        assert_eq!(
            row.layer, layer,
            "the layer byte cascade matches bit for bit"
        );
        assert_eq!(row.file_length, rec.file_len as i64);
        assert_eq!(row.piece_length, 16384);
    }

    /// Restore-injection verdict table: good rows merge (a
    /// layer-missing file becomes fully configured); tampered layer /
    /// bad root / wrong length / out-of-range / fully-configured-file
    /// rows are rejected one by one (the file keeps the layer-missing
    /// gated state — never fully-configure with a sick layer); mixed
    /// multi-row batches stay per-file independent.
    #[test]
    fn apply_recovered_layers_admits_good_and_rejects_bad_rows() {
        let (mut meta, missing_root, layer, full_root, full_layer) = v2_meta_with_missing_file();
        let len0 = meta.files[0].length as i64;
        // Good 1: f0's true layer -> merges; the file becomes fully
        // configured (piece_layer in place).
        let rows = vec![mk_row(&meta, 0, missing_root, layer.clone(), len0)];
        let report = apply_recovered_layers(&mut meta, &rows);
        assert_eq!(report.applied, vec![0], "applied: {report:?}");
        assert!(report.rejected.is_empty());
        assert_eq!(
            meta.files[0].piece_layer.as_deref(),
            Some(layer.as_slice()),
            "merged = the same shape as the metadata layer"
        );
        // Reset (the following negative cases start from the
        // layer-missing state).
        meta.files[0].piece_layer = None;

        // Bad 1: a flipped layer byte (a hand-tampered store row) ->
        // convergence-failure rejection.
        let mut tampered = layer.clone();
        tampered[5] ^= 0x01;
        let rows = vec![mk_row(&meta, 0, missing_root, tampered, len0)];
        let report = apply_recovered_layers(&mut meta, &rows);
        assert!(report.applied.is_empty(), "a bad row must not merge");
        assert_eq!(report.rejected.len(), 1);
        assert!(report.rejected[0].1.contains("convergence failed"));
        assert!(
            meta.files[0].piece_layer.is_none(),
            "the file stays in the missing-layer gated state"
        );

        // Bad 2: root mismatches the metadata (a row from another
        // torrent) -> reject.
        let rows = vec![mk_row(&meta, 0, [0xEE; 32], layer.clone(), len0)];
        let report = apply_recovered_layers(&mut meta, &rows);
        assert!(report.applied.is_empty());
        assert!(report.rejected[0].1.contains("root mismatch"));

        // Bad 3: file_length mismatch -> reject.
        let rows = vec![mk_row(&meta, 0, missing_root, layer.clone(), len0 - 1)];
        let report = apply_recovered_layers(&mut meta, &rows);
        assert!(report.applied.is_empty());
        assert!(report.rejected[0].1.contains("size mismatch"));

        // Bad 4: out-of-range file_index -> reject.
        let rows = vec![mk_row(&meta, 9, missing_root, layer.clone(), len0)];
        let report = apply_recovered_layers(&mut meta, &rows);
        assert!(report.applied.is_empty());
        assert!(report.rejected[0].1.contains("out of range"));

        // Bad 5: a row for a fully-configured file (f1, metadata-carried
        // layer) -> reject (its own trust level is never replaced); the
        // carried layer is untouched.
        let rows = vec![mk_row(
            &meta,
            1,
            full_root,
            full_layer.clone(),
            meta.files[1].length as i64,
        )];
        let report = apply_recovered_layers(&mut meta, &rows);
        assert!(report.applied.is_empty());
        assert!(report.rejected[0].1.contains("not layer-missing"));
        assert_eq!(
            meta.files[1].piece_layer.as_deref(),
            Some(full_layer.as_slice()),
            "the metadata's own layer is untouched"
        );

        // Good 2 + bad mixed: per-file independent (the good row
        // merges, the bad one does not interfere).
        meta.files[0].piece_layer = None;
        let rows = vec![
            mk_row(&meta, 1, full_root, full_layer, meta.files[1].length as i64), // bad (fully configured)
            mk_row(&meta, 0, missing_root, layer.clone(), len0),                  // good
        ];
        let report = apply_recovered_layers(&mut meta, &rows);
        assert_eq!(report.applied, vec![0], "a good row merges independently");
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.rejected[0].0, 1);
        assert_eq!(meta.files[0].piece_layer.as_deref(), Some(layer.as_slice()));
    }
}

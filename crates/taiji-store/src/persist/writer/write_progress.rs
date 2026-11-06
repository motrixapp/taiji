//! torrent_progress row write face: digest-dedup skip-write
//! (digest = SHA-256(deterministic payload serialization),
//! following the upstream fork's `lastDigest_` trick, source read-only) +
//! upsert and read-back.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::TorrentProgressRow;

/// digest = SHA-256(deterministic payload serialization).
///
/// `serde_json::to_vec` output is deterministic for structs with a fixed
/// field order (no maps involved), enough to express "did the payload
/// change"; the JSON bytes themselves are never stored — only their hash.
fn digest_of(row: &TorrentProgressRow) -> Result<[u8; 32], StoreError> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(row).map_err(|e| StoreError::Internal(e.to_string()))?;
    Ok(Sha256::digest(&bytes).into())
}

/// Upsert torrent_progress: digest matches the db -> skip; otherwise a
/// transactional whole write.
pub(super) fn upsert_torrent_progress(
    conn: &mut Connection,
    row: &TorrentProgressRow,
) -> Result<PersistOutcome, StoreError> {
    let digest = digest_of(row)?;
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT digest FROM torrent_progress WHERE gid = ?1",
            params![row.gid],
            |r| r.get(0),
        )
        .optional()?;
    if existing.as_deref() == Some(digest.as_slice()) {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let updated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO torrent_progress (
            gid, piece_length, v1_bitfield, v2_file_bits,
            upload_at_startup, downloaded_total, uploaded_total,
            active_time_s, seed_time_s, digest, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(gid) DO UPDATE SET
            piece_length = excluded.piece_length,
            v1_bitfield = excluded.v1_bitfield,
            v2_file_bits = excluded.v2_file_bits,
            upload_at_startup = excluded.upload_at_startup,
            downloaded_total = excluded.downloaded_total,
            uploaded_total = excluded.uploaded_total,
            active_time_s = excluded.active_time_s,
            seed_time_s = excluded.seed_time_s,
            digest = excluded.digest,
            updated_at = excluded.updated_at",
        params![
            row.gid,
            row.piece_length,
            row.v1_bitfield,
            row.v2_file_bits,
            row.upload_at_startup,
            row.downloaded_total,
            row.uploaded_total,
            row.active_time_s,
            row.seed_time_s,
            digest,
            updated_at,
        ],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Read back the torrent_progress row: no row -> None. digest/updated_at
/// stay out of the read face (digest is write-side dedup metadata,
/// updated_at is the persist moment — neither is business payload).
pub(super) fn load_torrent_progress(
    conn: &Connection,
    gid: &str,
) -> Result<Option<TorrentProgressRow>, StoreError> {
    conn.query_row(
        "SELECT gid, piece_length, v1_bitfield, v2_file_bits,
                upload_at_startup, downloaded_total, uploaded_total,
                active_time_s, seed_time_s
         FROM torrent_progress WHERE gid = ?1",
        params![gid],
        |r| {
            Ok(TorrentProgressRow {
                gid: r.get(0)?,
                piece_length: r.get(1)?,
                v1_bitfield: r.get(2)?,
                v2_file_bits: r.get(3)?,
                upload_at_startup: r.get(4)?,
                downloaded_total: r.get(5)?,
                uploaded_total: r.get(6)?,
                active_time_s: r.get(7)?,
                seed_time_s: r.get(8)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

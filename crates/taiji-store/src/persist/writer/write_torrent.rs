//! torrent/torrent_file business-row write face (SPEC §5.3/§5.4):
//! authoritative parent-row + file-set replacement, row-comparison
//! skip-write (observability columns created_at/updated_at excluded), the
//! remove face (FK cascade), the recovery read face (the active set), and
//! persisted DownloadResults (terminal-row write/purge/remove/read).

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::{TORRENT_ACTIVE_STATES, TorrentFileRow, TorrentRow, TorrentSnapshot};

/// Now (epoch seconds) — the write-side time source for observability
/// columns.
fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Torrent parent-row dedup comparison tuple (created_at/updated_at are
/// observability columns and excluded — a skip keeps the in-db values;
/// updated_at expresses "when the content last changed").
#[allow(clippy::type_complexity)]
type TorrentRowCmp = (
    String,
    String,
    i64,
    String,
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    Option<String>,
);

const TORRENT_CMP_COLS: &str = "name, state, queue_pos, dir, config_json, kind,
        v1_infohash, v2_infohash, is_private, metadata, error_code, error_msg";

fn torrent_cmp_from(row: &TorrentRow) -> TorrentRowCmp {
    (
        row.name.clone(),
        row.state.clone(),
        row.queue_pos,
        row.dir.clone(),
        row.config_json.clone(),
        row.kind.clone(),
        row.v1_infohash.clone(),
        row.v2_infohash.clone(),
        i64::from(row.is_private),
        row.metadata.clone(),
        row.error_code,
        row.error_msg.clone(),
    )
}

fn read_torrent_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TorrentRow> {
    Ok(TorrentRow {
        gid: r.get(0)?,
        name: r.get(1)?,
        state: r.get(2)?,
        queue_pos: r.get(3)?,
        dir: r.get(4)?,
        config_json: r.get(5)?,
        kind: r.get(6)?,
        v1_infohash: r.get(7)?,
        v2_infohash: r.get(8)?,
        is_private: r.get::<_, i64>(9)? != 0,
        metadata: r.get(10)?,
        error_code: r.get(11)?,
        error_msg: r.get(12)?,
        created_at: r.get(13)?,
        updated_at: r.get(14)?,
    })
}

const TORRENT_READ_COLS: &str = "gid, name, state, queue_pos, dir, config_json, kind,
        v1_infohash, v2_infohash, is_private, metadata, error_code, error_msg,
        created_at, updated_at";

/// Upsert the torrent parent row: with `files` = None the file set is not
/// touched (the semantics of the result-row write face
/// [`super::PersistJob::InsertDownloadResult`] — file facts are maintained
/// by [`super::PersistJob::UpsertTorrent`]); Some = authoritative
/// replacement, participating in the comparison. Parent row + (compared)
/// file set all equal to the db (observability columns aside) -> skip;
/// otherwise a single transaction writes (parent-row upsert -> file rows
/// delete-all + insert-all, FK parents before children).
pub(super) fn upsert_torrent(
    conn: &mut Connection,
    row: &TorrentRow,
    files: Option<&[TorrentFileRow]>,
) -> Result<PersistOutcome, StoreError> {
    let existing: Option<TorrentRowCmp> = conn
        .query_row(
            &format!("SELECT {TORRENT_CMP_COLS} FROM torrent WHERE gid = ?1"),
            params![row.gid],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get::<_, i64>(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                ))
            },
        )
        .optional()?;
    let files_existing = if files.is_some() {
        Some(load_torrent_files(conn, &row.gid)?)
    } else {
        None
    };
    let same = existing.as_ref() == Some(&torrent_cmp_from(row))
        && match (&files_existing, files) {
            (Some(cur), Some(next)) => {
                cur.len() == next.len() && cur.iter().zip(next.iter()).all(|(a, b)| a == b)
            }
            _ => true,
        };
    if same {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let updated_at = now_epoch_secs();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO torrent (
            gid, name, state, queue_pos, dir, config_json, kind,
            v1_infohash, v2_infohash, is_private, metadata, error_code, error_msg,
            created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                  COALESCE((SELECT created_at FROM torrent WHERE gid = ?1), ?14), ?15)
        ON CONFLICT(gid) DO UPDATE SET
            name = excluded.name,
            state = excluded.state,
            queue_pos = excluded.queue_pos,
            dir = excluded.dir,
            config_json = excluded.config_json,
            kind = excluded.kind,
            v1_infohash = excluded.v1_infohash,
            v2_infohash = excluded.v2_infohash,
            is_private = excluded.is_private,
            metadata = excluded.metadata,
            error_code = excluded.error_code,
            error_msg = excluded.error_msg,
            updated_at = excluded.updated_at",
        params![
            row.gid,
            row.name,
            row.state,
            row.queue_pos,
            row.dir,
            row.config_json,
            row.kind,
            row.v1_infohash,
            row.v2_infohash,
            i64::from(row.is_private),
            row.metadata,
            row.error_code,
            row.error_msg,
            row.created_at,
            updated_at,
        ],
    )?;
    // Authoritative file-set replacement (few rows; identical content was
    // already intercepted by the skip path).
    if let Some(files) = files {
        tx.execute("DELETE FROM torrent_file WHERE gid = ?1", params![row.gid])?;
        for f in files {
            tx.execute(
                "INSERT INTO torrent_file (
                    gid, file_index, path, length, attr, pieces_root, piece_layer,
                    v1_offset, selected, priority
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    f.gid,
                    f.file_index,
                    f.path,
                    f.length,
                    f.attr,
                    f.pieces_root,
                    f.piece_layer,
                    f.v1_offset,
                    i64::from(f.selected),
                    f.priority,
                ],
            )?;
        }
    }
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Delete the torrent parent row (remove face): FK ON DELETE CASCADE clears
/// torrent_file/torrent_progress/tracker. Written = deleted.
pub(super) fn delete_torrent(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let n = conn.execute("DELETE FROM torrent WHERE gid = ?1", params![gid])?;
    Ok(if n > 0 {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

/// Read back the torrent file-row set (file_index order; the read face
/// shared by comparison and recovery).
fn load_torrent_files(conn: &Connection, gid: &str) -> Result<Vec<TorrentFileRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT gid, file_index, path, length, attr, pieces_root, piece_layer,
                v1_offset, selected, priority
         FROM torrent_file WHERE gid = ?1 ORDER BY file_index",
    )?;
    let rows = stmt.query_map(params![gid], |r| {
        Ok(TorrentFileRow {
            gid: r.get(0)?,
            file_index: r.get(1)?,
            path: r.get(2)?,
            length: r.get(3)?,
            attr: r.get(4)?,
            pieces_root: r.get(5)?,
            piece_layer: r.get(6)?,
            v1_offset: r.get(7)?,
            selected: r.get::<_, i64>(8)? != 0,
            priority: r.get(9)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

/// Recovery read face (SPEC §5.4): all rows of the active set (queue_pos,
/// created_at order) + their file sets.
pub(super) fn load_torrents_at_startup(
    conn: &Connection,
) -> Result<Vec<TorrentSnapshot>, StoreError> {
    let placeholders = TORRENT_ACTIVE_STATES
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT {TORRENT_READ_COLS} FROM torrent
         WHERE state IN ({placeholders})
         ORDER BY queue_pos, created_at, gid"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(TORRENT_ACTIVE_STATES.iter()),
        read_torrent_row,
    )?;
    let mut out = Vec::new();
    for row in rows {
        let row = row.map_err(StoreError::from)?;
        let files = load_torrent_files(conn, &row.gid)?;
        out.push(TorrentSnapshot { row, files });
    }
    Ok(out)
}

/// Startup seeding read: the global upper bound of in-db `queue_pos` — the
/// two-table MAX over torrent full-state (done/error terminal rows share
/// the table and count too) + http_task full-state, all empty = 0.
/// Cross-table read (the row_seq seeding source, consumed by core-side
/// bootstrap): a new task's enqueue key must be strictly greater than every
/// existing key in the db, terminal-row keys included — the recovery-order
/// stable key stays monotonic across restarts.
pub(super) fn load_max_queue_pos(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row(
        "SELECT COALESCE(MAX(q), 0) FROM (
             SELECT MAX(queue_pos) AS q FROM torrent
             UNION ALL
             SELECT MAX(queue_pos) AS q FROM http_task
         )",
        [],
        |r| r.get(0),
    )
    .map_err(StoreError::from)
}

/// Terminal-state domain (shared by three sites; the 2 values outside
/// TORRENT_ACTIVE_STATES).
const TERMINAL_STATES: &[&str] = &["done", "error"];

/// Persisted DownloadResult write face: only terminal rows (done/error)
/// accepted — letting non-state semantics slip in would pollute the
/// recovery active set; the write side rejects explicitly (defense).
pub(super) fn insert_download_result(
    conn: &mut Connection,
    row: &TorrentRow,
) -> Result<PersistOutcome, StoreError> {
    if !TERMINAL_STATES.contains(&row.state.as_str()) {
        return Err(StoreError::Internal(format!(
            "download result row must have terminal state (done|error), got '{}'",
            row.state
        )));
    }
    upsert_torrent(conn, row, None)
}

/// Purge persisted DownloadResults: all terminal rows deleted (FK cascade
/// removes dependents).
pub(super) fn purge_download_results(conn: &mut Connection) -> Result<PersistOutcome, StoreError> {
    let placeholders = TERMINAL_STATES
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let n = conn.execute(
        &format!("DELETE FROM torrent WHERE state IN ({placeholders})"),
        rusqlite::params_from_iter(TERMINAL_STATES.iter()),
    )?;
    Ok(if n > 0 {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

/// Remove one persisted DownloadResult: only terminal rows can be removed
/// (active-set rows cannot be deleted through the result face — aria2
/// removeDownloadResult only acts on the result table).
pub(super) fn remove_download_result(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let placeholders = TERMINAL_STATES
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql_params: Vec<&str> = std::iter::once(gid)
        .chain(TERMINAL_STATES.iter().copied())
        .collect();
    let n = conn.execute(
        &format!("DELETE FROM torrent WHERE gid = ?1 AND state IN ({placeholders})"),
        rusqlite::params_from_iter(sql_params),
    )?;
    Ok(if n > 0 {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

/// Read back one persisted DownloadResult; no terminal row for the gid ->
/// None.
pub(super) fn load_download_result(
    conn: &Connection,
    gid: &str,
) -> Result<Option<TorrentRow>, StoreError> {
    conn.query_row(
        &format!(
            "SELECT {TORRENT_READ_COLS} FROM torrent
             WHERE gid = ?1 AND state IN ('done', 'error')"
        ),
        params![gid],
        read_torrent_row,
    )
    .optional()
    .map_err(StoreError::from)
}

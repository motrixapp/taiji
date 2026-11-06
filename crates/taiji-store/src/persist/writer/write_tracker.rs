//! Tracker row write face (SPEC §5.3) and the globally imported tracker
//! set write face (the `global_tracker` table, the persistence face of the
//! second tier of the three-tier architecture): the tables have no digest
//! column -> row-comparison / set-comparison skip-write (externally
//! identical to digest dedup); on change a single transaction replaces the
//! table.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::TrackerRow;

/// Tracker row dedup comparison tuple (SELECT column order: enabled + 8
/// nullable business fields).
#[allow(clippy::type_complexity)]
pub(super) type TrackerRowCmp = (
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

/// Upsert a tracker row: full-field equality with the existing row -> skip
/// (zero disk writes for identical data, matching digest-dedup behavior —
/// implementation differences in the `TrackerRow` docs); otherwise a
/// transactional whole write (new row INSERT / existing row UPDATE, primary
/// key `(gid, tier, url)`).
pub(super) fn upsert_tracker(
    conn: &mut Connection,
    row: &TrackerRow,
) -> Result<PersistOutcome, StoreError> {
    let enabled = i64::from(row.enabled);
    let existing: Option<TrackerRowCmp> = conn
        .query_row(
            "SELECT enabled, last_interval, last_min_interval, next_announce_at,
                    last_error, last_ok_at, seeds, leechers
             FROM tracker WHERE gid = ?1 AND tier = ?2 AND url = ?3",
            params![row.gid, row.tier, row.url],
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
                ))
            },
        )
        .optional()?;
    if existing.as_ref().is_some_and(|e| {
        *e == (
            enabled,
            row.last_interval,
            row.last_min_interval,
            row.next_announce_at,
            row.last_error.clone(),
            row.last_ok_at,
            row.seeds,
            row.leechers,
        )
    }) {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO tracker (
            gid, tier, url, enabled, last_interval, last_min_interval,
            next_announce_at, last_error, last_ok_at, seeds, leechers
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(gid, tier, url) DO UPDATE SET
            enabled = excluded.enabled,
            last_interval = excluded.last_interval,
            last_min_interval = excluded.last_min_interval,
            next_announce_at = excluded.next_announce_at,
            last_error = excluded.last_error,
            last_ok_at = excluded.last_ok_at,
            seeds = excluded.seeds,
            leechers = excluded.leechers",
        params![
            row.gid,
            row.tier,
            row.url,
            enabled,
            row.last_interval,
            row.last_min_interval,
            row.next_announce_at,
            row.last_error,
            row.last_ok_at,
            row.seeds,
            row.leechers,
        ],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Whole-table replacement of the globally imported tracker set: unchanged
/// set (rowid order) -> skip; on change a single-transaction DELETE + batch
/// INSERT (added_at = write-side now, observability column). A 1000+ entry
/// ngosang list lands in one transaction, replacing the N-fold write
/// amplification of per-row upserts.
pub(super) fn replace_global_trackers(
    conn: &mut Connection,
    urls: &[String],
) -> Result<PersistOutcome, StoreError> {
    let existing = load_global_trackers(conn)?;
    if existing.as_slice() == urls {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM global_tracker", [])?;
    for url in urls {
        tx.execute(
            "INSERT INTO global_tracker (url, added_at) VALUES (?1, ?2)
             ON CONFLICT(url) DO NOTHING",
            params![url, now],
        )?;
    }
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Read face of the globally imported tracker set: rowid order = import
/// order.
pub(super) fn load_global_trackers(conn: &Connection) -> Result<Vec<String>, StoreError> {
    let mut stmt = conn.prepare("SELECT url FROM global_tracker ORDER BY rowid")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

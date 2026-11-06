//! session_kv write/read face (the base of the importer's `imported_from`
//! dedup marker) and the saveSession durability barrier
//! (`PRAGMA wal_checkpoint(TRUNCATE)`).

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;

/// session_kv write face: unchanged value -> skip.
pub(super) fn put_kv(
    conn: &mut Connection,
    key: &str,
    value: &str,
) -> Result<PersistOutcome, StoreError> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM session_kv WHERE key = ?1",
            params![key],
            |r| r.get(0),
        )
        .optional()?;
    if existing.as_deref() == Some(value) {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO session_kv (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// session_kv read face; missing key -> None.
pub(super) fn get_kv(conn: &Connection, key: &str) -> Result<Option<String>, StoreError> {
    conn.query_row(
        "SELECT value FROM session_kv WHERE key = ?1",
        params![key],
        |r| r.get(0),
    )
    .optional()
    .map_err(StoreError::from)
}

/// saveSession durability barrier: the execution point itself is the
/// ordering guarantee that "all previous jobs are on disk" (the single
/// writer connection consumes the channel serially); the WAL checkpoint
/// shrinks the log file. A TRUNCATE failure (e.g. other readers lagging) is
/// not an error — checkpointing is file management, not a durability
/// condition (see [`super::PersistJob::Checkpoint`]).
pub(super) fn run_checkpoint(conn: &mut Connection) -> Result<(), StoreError> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(())
}

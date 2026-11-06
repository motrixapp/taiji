//! dht_state row write face (SPEC §5.3): family-primary-key upsert with
//! content comparison (node_id + routing_table own BLOBs) skip-write +
//! read-back; no FK, session-scoped.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::DhtStateRow;

/// dht_state row comparison tuple (node_id, routing_table; saved_at
/// excluded — see the `DhtStateRow::saved_at` field note).
type DhtStateRowCmp = (Vec<u8>, Vec<u8>);

/// Upsert a dht_state row: primary key family; unchanged content -> skip
/// (the routing-table BLOB uses bt::dht's own encoding, unchanged = no new
/// node information; frequent autosave triggers cost zero disk writes).
pub(super) fn upsert_dht_state(
    conn: &mut Connection,
    row: &DhtStateRow,
) -> Result<PersistOutcome, StoreError> {
    let existing: Option<DhtStateRowCmp> = conn
        .query_row(
            "SELECT node_id, routing_table FROM dht_state WHERE family = ?1",
            params![row.family],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if existing
        .as_ref()
        .is_some_and(|e| *e == (row.node_id.clone(), row.routing_table.clone()))
    {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO dht_state (family, node_id, routing_table, saved_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(family) DO UPDATE SET
            node_id = excluded.node_id,
            routing_table = excluded.routing_table,
            saved_at = excluded.saved_at",
        params![row.family, row.node_id, row.routing_table, row.saved_at],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Read back a single dht_state row (startup recovery); no row -> None.
pub(super) fn load_dht_state(
    conn: &Connection,
    family: &str,
) -> Result<Option<DhtStateRow>, StoreError> {
    conn.query_row(
        "SELECT family, node_id, routing_table, saved_at FROM dht_state WHERE family = ?1",
        params![family],
        |r| {
            Ok(DhtStateRow {
                family: r.get(0)?,
                node_id: r.get(1)?,
                routing_table: r.get(2)?,
                saved_at: r.get(3)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

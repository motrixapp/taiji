//! recovered_layer derived-table write/read face: recovery layers admitted
//! at runtime are persisted (key = torrent gid + file index, value = layer
//! bytes); at startup they are read back, re-validated with the admission
//! semantics and re-stored — nothing lost, nothing re-fetched across
//! restarts.
//!
//! Dedup: row-level comparison (following the `super::write_tracker`
//! precedent — the v2 DDL has no digest column and the table schema is
//! frozen); the `updated_at` observability column is excluded from the
//! comparison, and a skip keeps the older in-db value.
//!
//! Upstream anchor mapping: docs/design/store.md

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::RecoveredLayerRow;

/// recovered_layer write face: primary key `(gid, file_index)` upsert;
/// unchanged row content -> skip the write. A dangling FK (torrent row
/// missing) = explicit error (with foreign_keys=ON the INSERT fails and is
/// propagated; the caller must not swallow it — a recovery layer without
/// its task row is dirty data).
pub(super) fn upsert_recovered_layer(
    conn: &mut Connection,
    row: &RecoveredLayerRow,
) -> Result<PersistOutcome, StoreError> {
    let existing = load_one(conn, &row.gid, row.file_index)?;
    // Row-level comparison (observability column updated_at excepted):
    // full equality = no new information, skip the write.
    if existing.as_ref() == Some(row) {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO recovered_layer
           (gid, file_index, piece_length, file_length, pieces_root, layer, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(gid, file_index) DO UPDATE SET
           piece_length = excluded.piece_length,
           file_length = excluded.file_length,
           pieces_root = excluded.pieces_root,
           layer = excluded.layer,
           updated_at = excluded.updated_at",
        params![
            row.gid,
            row.file_index,
            row.piece_length,
            row.file_length,
            row.pieces_root,
            row.layer,
            now_epoch(),
        ],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// recovered_layer read face (startup recovery): all rows of one task,
/// file_index order; no rows -> empty set.
pub(super) fn load_recovered_layers(
    conn: &Connection,
    gid: &str,
) -> Result<Vec<RecoveredLayerRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT gid, file_index, piece_length, file_length, pieces_root, layer
         FROM recovered_layer WHERE gid = ?1 ORDER BY file_index",
    )?;
    let rows = stmt.query_map(params![gid], |r| {
        Ok(RecoveredLayerRow {
            gid: r.get(0)?,
            file_index: r.get(1)?,
            piece_length: r.get(2)?,
            file_length: r.get(3)?,
            pieces_root: r.get(4)?,
            layer: r.get(5)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Single-row read (the existing-value side of the skip-write comparison).
fn load_one(
    conn: &Connection,
    gid: &str,
    file_index: i64,
) -> Result<Option<RecoveredLayerRow>, StoreError> {
    conn.query_row(
        "SELECT gid, file_index, piece_length, file_length, pieces_root, layer
         FROM recovered_layer WHERE gid = ?1 AND file_index = ?2",
        params![gid, file_index],
        |r| {
            Ok(RecoveredLayerRow {
                gid: r.get(0)?,
                file_index: r.get(1)?,
                piece_length: r.get(2)?,
                file_length: r.get(3)?,
                pieces_root: r.get(4)?,
                layer: r.get(5)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// Now (epoch seconds; the base value for the updated_at observability
/// column).
fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::schema::{MIGRATIONS, SCHEMA_V2_TABLES};

    /// Unique tmp db path (same scheme as the persist/mod.rs tests: pid +
    /// nanosecond tag).
    fn tmp_db(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "taiji-recovery-{}-{}-{}.sqlite3",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Result unwrap for tests (lint forbids unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    fn row(gid: &str, file_index: i64, layer_byte: u8) -> RecoveredLayerRow {
        RecoveredLayerRow {
            gid: gid.to_string(),
            file_index,
            piece_length: 16384,
            file_length: 3 * 16384,
            pieces_root: vec![0xAA; 32],
            layer: vec![layer_byte; 3 * 32],
        }
    }

    /// Build a v1 db: manually run the ledger v1 DDL and pin user_version
    /// to 1 (the "old-version db" side of the upgrade path), with one
    /// legacy torrent + file row.
    fn legacy_v1_db(path: &std::path::Path, gid: &str) {
        let conn = ok(Connection::open(path), "open raw");
        for sql in MIGRATIONS[0].sqls {
            ok(conn.execute_batch(sql), "v1 ddl");
        }
        ok(
            conn.pragma_update(None, "user_version", 1),
            "pin user_version=1",
        );
        ok(
            conn.execute(
                "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                     is_private, created_at, updated_at)
                 VALUES (?1, 'legacy.bin', 'queued', 0, '/dl', '{}', 'v2', 0, 1, 1)",
                params![gid],
            ),
            "legacy torrent row",
        );
        ok(
            conn.execute(
                "INSERT INTO torrent_file (gid, file_index, path, length, selected, priority)
                 VALUES (?1, 0, 'legacy.bin', 49152, 1, 0)",
                params![gid],
            ),
            "legacy file row",
        );
    }

    /// Migration-ledger discipline: a v1 old db upgrades row-preserving
    /// through v2+v3 — legacy data intact column by column (read/write
    /// locked), appended tables created, user_version advanced, reopen
    /// idempotent. Since ledger v4 (the one-shot state-CHECK rebuild)
    /// the full open face wipes the rows by design, so the losslessness
    /// pin rides the parameterized ceiling `open_and_migrate_up_to(_,
    /// 3)` (the isomorphic old-binary face); the v4 wipe semantics are
    /// pinned in persist/mod.rs (`old_v3_db_opens_to_v4_rebuilt_with_check`).
    #[test]
    fn v1_to_v3_migration_preserves_legacy_rows_and_adds_tables() {
        let path = tmp_db("v1-to-v2");
        let gid = "8000000000000042";
        legacy_v1_db(&path, gid);
        // Upgrade: the ceiling-3 open advances v1 -> v3, rows preserved.
        {
            let conn = ok(
                crate::persist::open_and_migrate_up_to(&path, 3),
                "migrate v1->v3",
            );
            let version: i64 = ok(
                conn.query_row("PRAGMA user_version", [], |r| r.get(0)),
                "user_version",
            );
            assert_eq!(
                version, 3,
                "the ledger advanced to the v3 ceiling (v4 rebuilds; see the test doc)"
            );
            // Legacy data undamaged: parent row + file row read back column
            // by column (cross-check).
            let (name, state): (String, String) = ok(
                conn.query_row(
                    "SELECT name, state FROM torrent WHERE gid = ?1",
                    params![gid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                ),
                "legacy torrent readable",
            );
            assert_eq!((name.as_str(), state.as_str()), ("legacy.bin", "queued"));
            let len: i64 = ok(
                conn.query_row(
                    "SELECT length FROM torrent_file WHERE gid = ?1 AND file_index = 0",
                    params![gid],
                    |r| r.get(0),
                ),
                "legacy file readable",
            );
            assert_eq!(len, 49152);
            // Legacy rows are writable (read/write test lock: FK/constraints
            // did not degrade through migration).
            ok(
                conn.execute(
                    "UPDATE torrent_file SET selected = 0 WHERE gid = ?1 AND file_index = 0",
                    params![gid],
                ),
                "legacy row writable",
            );
            // The derived table is in place and empty (migration only
            // creates tables, no data).
            let count: i64 = ok(
                conn.query_row("SELECT COUNT(*) FROM recovered_layer", [], |r| r.get(0)),
                "recovered_layer count",
            );
            assert_eq!(count, 0);
        }
        // Reopen idempotent at the same ceiling: migrations skipped.
        {
            let conn = ok(crate::persist::open_and_migrate_up_to(&path, 3), "reopen");
            let version: i64 = ok(
                conn.query_row("PRAGMA user_version", [], |r| r.get(0)),
                "user_version",
            );
            assert_eq!(version, 3);
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A fresh db reaches the latest ledger in one step + v2 derived-table
    /// name check (the ledger append face).
    #[test]
    fn fresh_db_reaches_latest_with_derived_table() {
        let path = tmp_db("fresh-v2");
        let conn = ok(crate::persist::open_and_migrate(&path), "migrate fresh");
        for table in SCHEMA_V2_TABLES {
            let n: i64 = ok(
                conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1",
                    params![table],
                    |r| r.get(0),
                ),
                "table exists",
            );
            assert_eq!(n, 1, "v2 derived table {table} must be in place");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Roundtrip + row-level dedup: upsert -> Written, identical rewrite ->
    /// SkippedUnchanged (zero disk write), changed content -> overwrite,
    /// read back in file_index order.
    #[test]
    fn recovered_layer_roundtrip_dedupe_and_overwrite() {
        let path = tmp_db("roundtrip");
        let mut conn = ok(crate::persist::open_and_migrate(&path), "open");
        // FK parent row (the parent of the torrent_file coordinates).
        ok(
            conn.execute(
                "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                     is_private, created_at, updated_at)
                 VALUES ('80000000000000aa', 't', 'queued', 0, '/dl', '{}', 'v2', 0, 1, 1)",
                [],
            ),
            "parent torrent",
        );
        let gid = "80000000000000aa";
        assert_eq!(
            ok(
                upsert_recovered_layer(&mut conn, &row(gid, 1, 0x11)),
                "upsert 1"
            ),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(
                upsert_recovered_layer(&mut conn, &row(gid, 0, 0x22)),
                "upsert 0"
            ),
            PersistOutcome::Written
        );
        // Identical rewrite -> skip the write.
        assert_eq!(
            ok(
                upsert_recovered_layer(&mut conn, &row(gid, 1, 0x11)),
                "rewrite"
            ),
            PersistOutcome::SkippedUnchanged
        );
        // Changed content (layer byte flipped) -> overwrite (the new layer
        // after a re-fetch converges).
        assert_eq!(
            ok(
                upsert_recovered_layer(&mut conn, &row(gid, 1, 0x33)),
                "overwrite"
            ),
            PersistOutcome::Written
        );
        // Read back: file_index order + bit-identical bytes.
        let loaded = ok(load_recovered_layers(&conn, gid), "load");
        assert_eq!(
            loaded,
            vec![row(gid, 0, 0x22), row(gid, 1, 0x33)],
            "the roundtrip is bit-identical (criterion payload included)"
        );
        // A task with no rows -> empty set.
        assert!(
            ok(
                load_recovered_layers(&conn, "80000000000000ff"),
                "load empty"
            )
            .is_empty()
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Survives restart: write db -> close all connections (equivalent to
    /// process exit) -> reopen and read back, bit-identical (WAL replay
    /// semantics — committed means durable).
    #[test]
    fn recovered_layer_survives_restart() {
        let path = tmp_db("restart");
        let gid = "80000000000000bb";
        {
            let mut conn = ok(crate::persist::open_and_migrate(&path), "open 1");
            ok(
                conn.execute(
                    "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                         is_private, created_at, updated_at)
                     VALUES (?1, 't', 'seeding', 0, '/dl', '{}', 'v2', 0, 1, 1)",
                    params![gid],
                ),
                "parent torrent",
            );
            ok(
                upsert_recovered_layer(&mut conn, &row(gid, 0, 0x44)),
                "upsert",
            );
        }
        // Process boundary: drop all handles, then reopen (new Connection,
        // same db file).
        {
            let conn = ok(crate::persist::open_and_migrate(&path), "open 2");
            let loaded = ok(load_recovered_layers(&conn, gid), "load after restart");
            assert_eq!(
                loaded,
                vec![row(gid, 0, 0x44)],
                "nothing lost across restart"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// FK cascade hygiene: task deletion (the same SQL face as
    /// DeleteTorrent) removes the recovery layers with the row — the
    /// derived table keeps no orphan rows.
    #[test]
    fn recovered_layer_cascades_with_torrent_delete() {
        let path = tmp_db("cascade");
        let mut conn = ok(crate::persist::open_and_migrate(&path), "open");
        ok(
            conn.execute(
                "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                     is_private, created_at, updated_at)
                 VALUES ('80000000000000cc', 't', 'queued', 0, '/dl', '{}', 'v2', 0, 1, 1)",
                [],
            ),
            "parent torrent",
        );
        ok(
            upsert_recovered_layer(&mut conn, &row("80000000000000cc", 0, 0x55)),
            "upsert",
        );
        ok(
            conn.execute("DELETE FROM torrent WHERE gid = '80000000000000cc'", []),
            "delete torrent",
        );
        assert!(
            ok(
                load_recovered_layers(&conn, "80000000000000cc"),
                "load after delete"
            )
            .is_empty(),
            "task deletion must cascade-clean the recovery layers"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Dangling FK rejection: torrent parent row missing -> the write fails
    /// explicitly (a recovery layer must not exist without its task row;
    /// dirty-data defense).
    #[test]
    fn recovered_layer_requires_parent_torrent_row() {
        let path = tmp_db("fk");
        let mut conn = ok(crate::persist::open_and_migrate(&path), "open");
        assert!(
            upsert_recovered_layer(&mut conn, &row("80000000000000ee", 0, 0x66)).is_err(),
            "a dangling FK must be an explicit error"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// PersistHandle seam (single-writer job-channel path): the async API
    /// behaves identically to the direct face (upsert/dedup/read) — the
    /// integration face of the writer-thread dispatch arm.
    #[tokio::test]
    async fn handle_seam_roundtrip_matches_direct_face() {
        let path = tmp_db("handle");
        let (handle, join) = ok(
            super::super::PersistWriter::spawn(path.clone()).await,
            "spawn",
        );
        // First persist the torrent parent row (seam face).
        let parent = super::super::TorrentRow {
            gid: "8000000000000099".to_string(),
            name: "t".into(),
            state: "queued".into(),
            queue_pos: 0,
            dir: "/dl".into(),
            config_json: "{}".into(),
            kind: "v2".into(),
            v1_infohash: None,
            v2_infohash: None,
            is_private: false,
            metadata: None,
            error_code: None,
            error_msg: None,
            created_at: 1,
            updated_at: 1,
        };
        let gid = parent.gid.clone();
        let files = Vec::new();
        assert!(handle.upsert_torrent(parent, files).await.is_ok());
        let r = row(&gid, 0, 0x77);
        assert_eq!(
            ok(
                handle.upsert_recovered_layer(r.clone()).await,
                "handle upsert"
            ),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(
                handle.upsert_recovered_layer(r.clone()).await,
                "handle rewrite"
            ),
            PersistOutcome::SkippedUnchanged
        );
        assert_eq!(
            ok(handle.load_recovered_layers(&gid).await, "handle load"),
            vec![r]
        );
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(2), join).await,
            "writer exit",
        );
        let _ = std::fs::remove_file(&path);
    }
}

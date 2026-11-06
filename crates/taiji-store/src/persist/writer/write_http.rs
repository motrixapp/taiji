//! http_task business-row write/read faces (the media data-model
//! increment): upsert + row-level-comparison skip-write
//! (observational created_at/updated_at excluded) + the startup recovery
//! read face (active set + task cookie set). The cookie faces moved to
//! [`super::write_cookie`] when the table unified across families;
//! this module keeps the http row faces and the
//! cookie **reads** that ride them, plus the paired delete.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::{
    HTTP_TASK_ACTIVE_STATES, HTTP_TASK_TERMINAL_STATES, HttpTaskRow, HttpTaskSnapshot,
};
use super::write_cookie::load_task_cookies;

/// Now, in epoch seconds — the writer-side time source for observational
/// columns.
fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn read_http_task_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<HttpTaskRow> {
    Ok(HttpTaskRow {
        gid: r.get(0)?,
        url: r.get(1)?,
        final_url: r.get(2)?,
        mirrors_json: r.get(3)?,
        state: r.get(4)?,
        queue_pos: r.get(5)?,
        dir: r.get(6)?,
        out: r.get(7)?,
        config_json: r.get(8)?,
        probe_json: r.get(9)?,
        validator_digest: r.get(10)?,
        block_size: r.get(11)?,
        block_bitmap: r.get(12)?,
        block_count: r.get(13)?,
        total_done: r.get(14)?,
        error_code: r.get(15)?,
        error_msg: r.get(16)?,
        created_at: r.get(17)?,
        updated_at: r.get(18)?,
    })
}

const HTTP_TASK_READ_COLS: &str = "gid, url, final_url, mirrors_json, state, queue_pos, dir, out,
        config_json, probe_json, validator_digest, block_size, block_bitmap, block_count,
        total_done, error_code, error_msg, created_at, updated_at";

/// Upsert one http_task row: all columns equal to the stored row
/// (observational columns excepted) -> skip (zero disk writes,
/// externally identical to digest dedup); otherwise a single transaction
/// (created_at keeps its initial value, updated_at = writer-side now).
/// The comparison reads the whole row back and normalizes it by taking
/// the stored values of the observational columns (tuple comparison is
/// capped at 12 elements; whole-struct comparison is equivalent and
/// readable).
///
/// **Terminal rows refuse downgrade writes** (a writer-side guard under
/// row serialization): if the stored row is terminal (done/error) and
/// the payload row is not -> skip. Read-judge + write complete
/// atomically inside the single write connection, which structurally
/// excludes the last-writer-wins race between mirror-face rewrites
/// (saveSession and kin) and the finalize terminal write (a stale mirror
/// row landing after the terminal write must not drag a done row back to
/// downloading); the only exit from a terminal state is the explicit
/// [`reopen_http_task`] (escaping a terminal state does not pass this
/// guard).
pub(super) fn upsert_http_task(
    conn: &mut Connection,
    row: &HttpTaskRow,
) -> Result<PersistOutcome, StoreError> {
    let existing: Option<HttpTaskRow> = conn
        .query_row(
            &format!("SELECT {HTTP_TASK_READ_COLS} FROM http_task WHERE gid = ?1"),
            params![row.gid],
            read_http_task_row,
        )
        .optional()?;
    if let Some(cur) = existing.as_ref()
        && HTTP_TASK_TERMINAL_STATES.contains(&cur.state.as_str())
        && !HTTP_TASK_TERMINAL_STATES.contains(&row.state.as_str())
    {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let same = match existing.as_ref() {
        Some(cur) => {
            let mut next = row.clone();
            next.created_at = cur.created_at;
            next.updated_at = cur.updated_at;
            cur == &next
        }
        None => false,
    };
    if same {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let updated_at = now_epoch_secs();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO http_task (
            gid, url, final_url, mirrors_json, state, queue_pos, dir, out,
            config_json, probe_json, validator_digest, block_size, block_bitmap,
            block_count, total_done, error_code, error_msg, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                  ?17, COALESCE((SELECT created_at FROM http_task WHERE gid = ?1), ?18), ?19)
        ON CONFLICT(gid) DO UPDATE SET
            url = excluded.url,
            final_url = excluded.final_url,
            mirrors_json = excluded.mirrors_json,
            state = excluded.state,
            queue_pos = excluded.queue_pos,
            dir = excluded.dir,
            out = excluded.out,
            config_json = excluded.config_json,
            probe_json = excluded.probe_json,
            validator_digest = excluded.validator_digest,
            block_size = excluded.block_size,
            block_bitmap = excluded.block_bitmap,
            block_count = excluded.block_count,
            total_done = excluded.total_done,
            error_code = excluded.error_code,
            error_msg = excluded.error_msg,
            updated_at = excluded.updated_at",
        params![
            row.gid,
            row.url,
            row.final_url,
            row.mirrors_json,
            row.state,
            row.queue_pos,
            row.dir,
            row.out,
            row.config_json,
            row.probe_json,
            row.validator_digest,
            row.block_size,
            row.block_bitmap,
            row.block_count,
            row.total_done,
            row.error_code,
            row.error_msg,
            row.created_at,
            updated_at,
        ],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Startup recovery read face: all rows in the active set (queue_pos,
/// created_at order) + each row's task cookie set (the unified
/// task_cookie table: replayed deterministically in
/// name/domain/path order). Terminal rows (done/error) are not on this
/// face — persisted result rows remain as task facts that can be
/// purged/removed (matching the torrent recovery policy); their
/// cookies were already cleared at the terminal
/// ([`super::write_cookie::clear_task_cookies`]).
pub(super) fn load_http_tasks_at_startup(
    conn: &Connection,
) -> Result<Vec<HttpTaskSnapshot>, StoreError> {
    let placeholders = HTTP_TASK_ACTIVE_STATES
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT {HTTP_TASK_READ_COLS} FROM http_task
         WHERE state IN ({placeholders})
         ORDER BY queue_pos, created_at, gid"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(HTTP_TASK_ACTIVE_STATES.iter()),
        read_http_task_row,
    )?;
    let rows: Vec<HttpTaskRow> = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    // Cookie sets fetched in one query and grouped by gid (IN arity =
    // active row count, bounded at startup); the sort key matches the
    // primary-key order (name, domain, path) — replay determinism.
    let gids: Vec<&str> = rows.iter().map(|r| r.gid.as_str()).collect();
    let in_clause = gids.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let cookie_sql = format!(
        "SELECT {cols} FROM task_cookie WHERE gid IN ({in_clause})
         ORDER BY gid, name, domain, path",
        cols = super::write_cookie::task_cookie_cols()
    );
    let mut stmt = conn.prepare(&cookie_sql)?;
    let mut by_gid: std::collections::HashMap<String, Vec<super::rows::TaskCookieRow>> =
        std::collections::HashMap::new();
    let mapped = stmt.query_map(rusqlite::params_from_iter(gids.iter()), |r| {
        Ok((
            r.get::<_, String>(0)?,
            super::write_cookie::read_cookie_row_of(r)?,
        ))
    })?;
    for row in mapped {
        let (gid, cookie) = row.map_err(StoreError::from)?;
        by_gid.entry(gid).or_default().push(cookie);
    }
    Ok(rows
        .into_iter()
        .map(|row| {
            let gid = row.gid.clone();
            let mut cookies = by_gid.remove(&gid).unwrap_or_default();
            cookies
                .sort_by(|a, b| (&a.name, &a.domain, &a.path).cmp(&(&b.name, &b.domain, &b.path)));
            HttpTaskSnapshot { row, cookies }
        })
        .collect())
}

/// Delete one http_task row (remove face): the **paired delete**
/// clears the gid's task_cookie rows inside the same transaction
/// (the unified table carries no FK, so the delete
/// paths pair their own cookie clear; the discipline is pinned by the
/// delete-face integration tests). The delete closure also clears
/// `imported_from` re-import marks pointing back at this gid (a mark
/// left behind after its row is deleted would block re-import forever —
/// session_kv has no gid-lookup index, so the hit face cannot tell a
/// live mark from a dead one; the HTTP and BT gid namespaces are
/// disjoint (the BT high-bit isolation), so BT-side marks are never
/// cleared by mistake). Row existed = `Written` (deleted); no row =
/// `SkippedUnchanged` (zero disk writes, idempotent).
pub(super) fn delete_http_task(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let tx = conn.transaction()?;
    let deleted = tx.execute("DELETE FROM http_task WHERE gid = ?1", params![gid])?;
    if deleted > 0 {
        tx.execute("DELETE FROM task_cookie WHERE gid = ?1", params![gid])?;
        tx.execute(
            "DELETE FROM session_kv WHERE key LIKE 'imported_from:%' AND value = ?1",
            params![gid],
        )?;
    }
    tx.commit()?;
    if deleted == 0 {
        Ok(PersistOutcome::SkippedUnchanged)
    } else {
        Ok(PersistOutcome::Written)
    }
}

/// Explicit reopen of a terminal row (the only terminal exit, for the
/// Error->unpause re-probe migration arm): state back to queued, error
/// fields cleared; bitmap/progress/resume digest preserved as-is (the
/// re-probe settles via the existing resume criteria — nothing
/// fabricated, nothing lost). Hit = `Written`; missing or non-terminal
/// row = `SkippedUnchanged` (idempotent).
pub(super) fn reopen_http_task(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let tx = conn.transaction()?;
    let reopened = tx.execute(
        "UPDATE http_task SET state = 'queued', error_code = NULL, error_msg = NULL,
         updated_at = ?2
         WHERE gid = ?1 AND state IN ('done', 'error')",
        params![gid, now_epoch_secs()],
    )?;
    tx.commit()?;
    if reopened > 0 {
        Ok(PersistOutcome::Written)
    } else {
        Ok(PersistOutcome::SkippedUnchanged)
    }
}

/// Read back terminal done rows (the "DB as journal" read face of the
/// renamePending startup closure): all rows with state='done'
/// (queue_pos, created_at, gid order). The rename_pending flag lives in
/// config_json — the store does not interpret payloads; filtering
/// belongs to the caller (mirrored by [`HttpPersistConfig`] parsing on
/// the core side).
pub(super) fn load_http_done_rows(conn: &Connection) -> Result<Vec<HttpTaskRow>, StoreError> {
    let sql = format!(
        "SELECT {HTTP_TASK_READ_COLS} FROM http_task WHERE state = 'done'
         ORDER BY queue_pos, created_at, gid"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], read_http_task_row)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

/// Single-row read (any state; the row-fact source for the
/// Error->unpause re-probe migration arm): row + task cookie set (the
/// same shape as the recovery replay). Missing row = `Ok(None)`.
pub(super) fn load_http_task(
    conn: &Connection,
    gid: &str,
) -> Result<Option<HttpTaskSnapshot>, StoreError> {
    let existing: Option<HttpTaskRow> = conn
        .query_row(
            &format!("SELECT {HTTP_TASK_READ_COLS} FROM http_task WHERE gid = ?1"),
            params![gid],
            read_http_task_row,
        )
        .optional()?;
    let Some(row) = existing else {
        return Ok(None);
    };
    let cookies = load_task_cookies(conn, gid)?;
    Ok(Some(HttpTaskSnapshot { row, cookies }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::open_and_migrate;
    use crate::persist::writer::rows::{TASK_KIND_HTTP, TASK_KIND_MEDIA, TaskCookieRow};
    use crate::persist::writer::write_cookie::{clear_task_cookies, upsert_task_cookies};

    /// Unique tmp database path (the same scheme as the persist tests:
    /// pid + nanosecond tag).
    fn tmp_db(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "taiji-http-{}-{}-{}.sqlite3",
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

    /// Test-side Result unwrap (lints bar unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    fn row(gid: &str, state: &str, total_done: i64) -> HttpTaskRow {
        HttpTaskRow {
            gid: gid.into(),
            url: "http://origin/f.bin".into(),
            final_url: "http://cdn/f.bin".into(),
            mirrors_json: Some(r#"[{"url":"http://m1/f.bin"}]"#.into()),
            state: state.into(),
            queue_pos: 0,
            dir: "/dl".into(),
            out: "f.bin".into(),
            config_json: r#"{"split":16}"#.into(),
            probe_json: Some(r#"{"length":1048576,"range":true}"#.into()),
            validator_digest: Some(vec![0x77; 32]),
            block_size: 4 * 1024 * 1024,
            block_bitmap: Some(vec![0b1010_1010, 0x00]),
            block_count: Some(16),
            total_done,
            error_code: None,
            error_msg: None,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        }
    }

    /// Direct write-face roundtrip + row-level-comparison dedup: upsert
    /// -> Written, identical rewrite -> SkippedUnchanged (zero disk
    /// writes), changed payload -> overwrite (created_at keeps its
    /// initial value, updated_at = the writer-side clock).
    #[test]
    fn http_task_roundtrip_dedupe_and_overwrite() {
        let path = tmp_db("roundtrip");
        let mut conn = ok(open_and_migrate(&path), "open");
        let gid = "8000000000000200";
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &row(gid, "downloading", 0)),
                "upsert 1"
            ),
            PersistOutcome::Written
        );
        // Identical rewrite -> skip (different observational values do
        // not trigger a write either).
        let mut again = row(gid, "downloading", 0);
        again.updated_at = 1_700_000_999;
        assert_eq!(
            ok(upsert_http_task(&mut conn, &again), "rewrite"),
            PersistOutcome::SkippedUnchanged
        );
        // Payload change (bitmap advance + counter) -> overwrite.
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &row(gid, "downloading", 262_144)),
                "overwrite"
            ),
            PersistOutcome::Written
        );
        // Read back: business fields equal field for field (updated_at is
        // a writer-side observational column, compared after
        // normalization); created_at kept, updated_at not the payload's
        // observational value.
        let mut stmt = ok(
            conn.prepare(&format!(
                "SELECT {HTTP_TASK_READ_COLS} FROM http_task WHERE gid = ?1"
            )),
            "prepare read",
        );
        let loaded = ok(stmt.query_row(params![gid], read_http_task_row), "readback");
        let mut expected = row(gid, "downloading", 262_144);
        expected.updated_at = loaded.updated_at;
        assert_eq!(loaded, expected);
        assert_eq!(
            loaded.created_at, 1_700_000_000,
            "created_at keeps its initial value"
        );
        assert_ne!(
            loaded.updated_at, 1_700_000_999,
            "updated_at = the writer-side now"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Startup recovery read face: the active set
    /// (queued/probing/downloading/paused) read back in queue_pos order
    /// (ties broken by created_at then gid); terminal done/error rows
    /// are not rebuilt.
    #[test]
    fn http_task_startup_read_returns_active_set_ordered() {
        let path = tmp_db("startup");
        let mut conn = ok(open_and_migrate(&path), "open");
        let cases = [
            ("8000000000000210", "downloading", 1i64, 100i64),
            ("8000000000000211", "paused", 0, 100),
            ("8000000000000212", "done", 2, 100),
            ("8000000000000213", "error", 3, 100),
            ("8000000000000214", "queued", 4, 100),
            ("8000000000000215", "probing", 5, 100),
            // Identical queue_pos + created_at -> gid lexicographic
            // tie-break (the last determinism level; the replay never
            // drifts with insertion order).
            ("8000000000000217", "downloading", 9, 100),
            ("8000000000000216", "downloading", 9, 100),
        ];
        for (gid, state, pos, created) in cases {
            let mut r = row(gid, state, 0);
            r.queue_pos = pos;
            r.created_at = created;
            assert_eq!(
                ok(upsert_http_task(&mut conn, &r), "upsert"),
                PersistOutcome::Written
            );
        }
        let loaded = ok(load_http_tasks_at_startup(&conn), "load startup");
        let gids: Vec<&str> = loaded.iter().map(|s| s.row.gid.as_str()).collect();
        assert_eq!(
            gids,
            vec![
                "8000000000000211",
                "8000000000000210",
                "8000000000000214",
                "8000000000000215",
                "8000000000000216",
                "8000000000000217",
            ],
            "the active set ordered by queue_pos, created_at, gid; done/error rows are not rebuilt"
        );
        // Terminal rows stay in the DB (the persisted result face); they
        // merely stay off the recovery read face.
        let total: i64 = ok(
            conn.query_row("SELECT COUNT(*) FROM http_task", [], |r| r.get(0)),
            "count all",
        );
        assert_eq!(total, 8);
        let _ = std::fs::remove_file(&path);
    }

    /// Nothing lost across restart: write -> close all connections
    /// (equivalent to process exit) -> reopen and read back; bitmap and
    /// validator payload are bit-for-bit identical (a WAL commit is
    /// durable).
    #[test]
    fn http_task_survives_restart() {
        let path = tmp_db("restart");
        let gid = "8000000000000220";
        {
            let mut conn = ok(open_and_migrate(&path), "open 1");
            assert_eq!(
                ok(
                    upsert_http_task(&mut conn, &row(gid, "paused", 1024)),
                    "upsert"
                ),
                PersistOutcome::Written
            );
        }
        {
            let conn = ok(open_and_migrate(&path), "open 2");
            let loaded = ok(load_http_tasks_at_startup(&conn), "load after restart");
            // updated_at is a writer-side observational column, compared
            // after normalization; the business payload must be
            // bit-for-bit identical.
            let mut expected = row(gid, "paused", 1024);
            expected.updated_at = loaded[0].row.updated_at;
            assert_eq!(
                loaded,
                vec![HttpTaskSnapshot {
                    row: expected,
                    cookies: Vec::new(),
                }],
                "nothing lost across restart"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Zero-disk-write measurement for skip-writes (SkippedUnchanged
    /// must have objective zero-write evidence): a second connection's
    /// `PRAGMA data_version` is the observer — that pragma advances only
    /// on commits from **other** connections (a connection's own writes
    /// do not advance its own view), so the observer connection is the
    /// only valid meter. The control arm (Written advances the observer)
    /// proves the meter itself works.
    #[test]
    fn http_task_skip_is_zero_disk_write_by_data_version() {
        let path = tmp_db("data-version");
        let mut conn = ok(open_and_migrate(&path), "open");
        let observer = ok(open_and_migrate(&path), "observer conn");
        let data_version = |conn: &Connection| -> i64 {
            ok(
                conn.query_row("PRAGMA data_version", [], |r| r.get(0)),
                "data_version",
            )
        };
        let dv0 = data_version(&observer);
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &row("8000000000000221", "paused", 0)),
                "first write"
            ),
            PersistOutcome::Written
        );
        let dv1 = data_version(&observer);
        assert_ne!(
            dv1, dv0,
            "control: Written advances the observer's data_version"
        );
        // Identical rewrite = SkippedUnchanged -> the observer does not
        // advance (zero disk writes).
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &row("8000000000000221", "paused", 0)),
                "skip rewrite"
            ),
            PersistOutcome::SkippedUnchanged
        );
        let dv2 = data_version(&observer);
        assert_eq!(
            dv2, dv1,
            "a skip-write must produce zero disk writes (data_version unmoved)"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Cookie row fixture (DDL field-for-field).
    fn cookie(gid: &str, name: &str, domain: &str, path: &str, value: &str) -> TaskCookieRow {
        TaskCookieRow {
            gid: gid.into(),
            task_kind: TASK_KIND_HTTP.into(),
            name: name.into(),
            domain: domain.into(),
            path: path.into(),
            value: value.into(),
            expires_utc: Some(1_800_000_000),
            secure: true,
            host_only: false,
            creation_utc: 1_700_000_000,
        }
    }

    /// Unified cookie write face: whole-set replacement
    /// (payload order irrelevant) + unchanged-set skip + empty-set
    /// clear-all + an idempotent Clear + an http payload with no
    /// http_task row = explicit error + a media payload without a row
    /// allowed (creation-time landing).
    #[test]
    fn task_cookie_set_replace_dedupe_and_clear() {
        let path = tmp_db("cookie-set");
        let mut conn = ok(open_and_migrate(&path), "open");
        let gid = "8000000000000230";
        ok(
            conn.execute(
                "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                     config_json, block_size, total_done, created_at, updated_at)
                 VALUES (?1, 'https://o/f', 'https://c/f', 'downloading', 0, '/dl', 'f',
                     '{}', 1048576, 0, 1, 1)",
                params![gid],
            ),
            "task fixture",
        );
        // First write (unordered payload) -> Written; the same set (a
        // different order) -> skip.
        let set1 = vec![
            cookie(gid, "sid", "cdn.example", "/", "v1"),
            cookie(gid, "auth", "origin.example", "/dl", "tok"),
            cookie(gid, "pref", "cdn.example", "/", "dark"),
        ];
        assert_eq!(
            ok(
                upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &set1),
                "cookie write 1"
            ),
            PersistOutcome::Written
        );
        let mut reordered = vec![set1[2].clone(), set1[0].clone(), set1[1].clone()];
        assert_eq!(
            ok(
                upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &reordered),
                "cookie rewrite (same set, other order)"
            ),
            PersistOutcome::SkippedUnchanged,
            "an unchanged set (order-insensitive) = zero disk writes"
        );
        // Change one value -> whole-set replace (single-transaction
        // DELETE + INSERT); the session cookie (expires_utc = NULL) and
        // the secure/host_only booleans read back exactly.
        reordered[0].value = "light".to_string();
        reordered[0].secure = false;
        reordered[0].host_only = true;
        reordered[0].expires_utc = None;
        assert_eq!(
            ok(
                upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &reordered),
                "cookie replace"
            ),
            PersistOutcome::Written
        );
        {
            let mut stmt = ok(
                conn.prepare(
                    "SELECT value, expires_utc, secure, host_only FROM task_cookie
                     WHERE gid = ?1 AND name = 'pref' AND domain = 'cdn.example'",
                ),
                "prepare cookie read",
            );
            let (value, expires, secure, host_only): (String, Option<i64>, i64, i64) = ok(
                stmt.query_row(params![gid], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                }),
                "cookie readback",
            );
            assert_eq!(value, "light");
            assert_eq!(expires, None, "a session cookie = NULL expiry");
            assert_eq!((secure, host_only), (0, 1));
        }
        // Empty set = clear all; clearing again = SkippedUnchanged
        // (idempotent).
        assert_eq!(
            ok(
                upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &[]),
                "empty set"
            ),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(clear_task_cookies(&mut conn, gid), "clear empty"),
            PersistOutcome::SkippedUnchanged,
            "clearing with no rows = idempotent"
        );
        // Dangling http task: no http_task row -> explicit error
        // (http cookies never outlive their task row).
        let orphan = vec![cookie("8000000000000231", "sid", "x.example", "/", "v")];
        assert!(
            upsert_task_cookies(&mut conn, "8000000000000231", TASK_KIND_HTTP, &orphan).is_err(),
            "a dangling http task must error"
        );
        // The media arm of the same face: no media_task row is legal at
        // creation time (addMedia lands cookies before Resolving writes
        // the row; the startup GC owns the orphan backstop).
        assert!(
            upsert_task_cookies(
                &mut conn,
                "8000000000000233",
                TASK_KIND_MEDIA,
                &[TaskCookieRow {
                    gid: "8000000000000233".into(),
                    task_kind: TASK_KIND_MEDIA.into(),
                    ..orphan[0].clone()
                }]
            )
            .is_ok(),
            "media creation-time landing (row not yet present) is legal"
        );
        // A payload mixing in another task's gid = a writer-side defense
        // error.
        let mut mixed = set1.clone();
        mixed.push(cookie("8000000000000232", "x", "y.example", "/", "z"));
        assert!(upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &mixed).is_err());
        let _ = std::fs::remove_file(&path);
    }

    /// Clearing points + paired delete + restart replay:
    /// (1) the delete face pairs the cookie clear into the same
    /// transaction (raw DELETE FROM http_task alone leaves the rows —
    /// the unified table has no FK);
    /// (2) after Clear (clear on completion) a restart read face carries
    /// no cookies;
    /// (3) write cookies -> close all connections -> reopen and
    /// `load_http_tasks_at_startup` replays the task cookie store
    /// (bit-for-bit, in name/domain/path order).
    #[test]
    fn task_cookie_clear_paired_delete_and_restart_replay() {
        let path = tmp_db("cookie-lifecycle");
        let gid = "8000000000000240";
        {
            let mut conn = ok(open_and_migrate(&path), "open 1");
            ok(
                conn.execute(
                    "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                         config_json, block_size, total_done, created_at, updated_at)
                     VALUES (?1, 'https://o/f', 'https://c/f', 'downloading', 0, '/dl', 'f',
                         '{}', 1048576, 0, 1, 1)",
                    params![gid],
                ),
                "task fixture",
            );
            let set1 = vec![
                cookie(gid, "auth", "origin.example", "/dl", "tok"),
                cookie(gid, "sid", "cdn.example", "/", "v1"),
            ];
            assert_eq!(
                ok(
                    upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &set1),
                    "seed cookies"
                ),
                PersistOutcome::Written
            );
            // Replay before all connections close: the read face carries
            // the cookie set in deterministic primary-key order.
            let loaded = ok(load_http_tasks_at_startup(&conn), "load with cookies");
            assert_eq!(loaded.len(), 1);
            assert_eq!(
                loaded[0].cookies,
                vec![
                    cookie(gid, "auth", "origin.example", "/dl", "tok"),
                    cookie(gid, "sid", "cdn.example", "/", "v1"),
                ],
                "cookies replay in name/domain/path order"
            );
            // No FK on the unified table: a raw task-row delete alone
            // leaves the cookie rows behind (the orphan the startup GC
            // clears); the delete FACE pairs the clear.
            ok(
                conn.execute("DELETE FROM http_task WHERE gid = ?1", params![gid]),
                "raw delete task (no face)",
            );
            let n: i64 = ok(
                conn.query_row(
                    "SELECT COUNT(*) FROM task_cookie WHERE gid = ?1",
                    params![gid],
                    |r| r.get(0),
                ),
                "count after cascade",
            );
            assert_eq!(
                n, 2,
                "the unified table has no FK: a raw delete leaves cookies (GC owns orphans)"
            );
        }
        // Clearing point (the explicit clear-on-completion face): task
        // row + cookies -> Clear -> the read face has no cookies and the
        // task row is untouched; nothing resurrects across restart.
        {
            let mut conn = ok(open_and_migrate(&path), "open 2");
            ok(
                conn.execute(
                    "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                         config_json, block_size, total_done, created_at, updated_at)
                     VALUES (?1, 'https://o/f', 'https://c/f', 'downloading', 0, '/dl', 'f',
                         '{}', 1048576, 0, 1, 1)",
                    params![gid],
                ),
                "task fixture 2",
            );
            let set1 = vec![cookie(gid, "sid", "cdn.example", "/", "v1")];
            assert_eq!(
                ok(
                    upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &set1),
                    "seed 2"
                ),
                PersistOutcome::Written
            );
            assert_eq!(
                ok(clear_task_cookies(&mut conn, gid), "clear on complete"),
                PersistOutcome::Written,
                "clear-on-completion = Written"
            );
            assert_eq!(
                ok(clear_task_cookies(&mut conn, gid), "clear again"),
                PersistOutcome::SkippedUnchanged,
                "clearing again = idempotent"
            );
        }
        {
            let conn = ok(open_and_migrate(&path), "open 3 (restart)");
            let loaded = ok(load_http_tasks_at_startup(&conn), "load after clear");
            assert_eq!(loaded.len(), 1, "the task row is still there");
            assert!(
                loaded[0].cookies.is_empty(),
                "cleared cookies must not resurrect across restart"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// DeleteHttpTask row deletion (the remove closure): row present =
    /// Written with cookies cleared by the FK cascade; no row =
    /// SkippedUnchanged (idempotent).
    #[test]
    fn http_task_delete_cascades_cookies_and_is_idempotent() {
        let path = tmp_db("delete-http");
        let mut conn = ok(open_and_migrate(&path), "open");
        let gid = "8000000000000250";
        ok(
            upsert_http_task(&mut conn, &row(gid, "downloading", 0)),
            "upsert",
        );
        let set1 = vec![cookie(gid, "sid", "cdn.example", "/", "v1")];
        assert_eq!(
            ok(
                upsert_task_cookies(&mut conn, gid, TASK_KIND_HTTP, &set1),
                "seed cookies"
            ),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(delete_http_task(&mut conn, gid), "delete"),
            PersistOutcome::Written
        );
        let n: i64 = ok(
            conn.query_row("SELECT COUNT(*) FROM http_task", [], |r| r.get(0)),
            "count tasks",
        );
        let c: i64 = ok(
            conn.query_row("SELECT COUNT(*) FROM task_cookie", [], |r| r.get(0)),
            "count cookies",
        );
        assert_eq!((n, c), (0, 0), "row deleted + cookies cascade-cleared");
        assert_eq!(
            ok(delete_http_task(&mut conn, gid), "delete again"),
            PersistOutcome::SkippedUnchanged,
            "deleting with no row = idempotent"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The delete closure clears imported_from re-import marks pointing
    /// back at this gid (a leftover mark used to block re-import
    /// forever). Unrelated keys and other gids' marks are preserved.
    #[test]
    fn http_task_delete_cleans_imported_from_marks() {
        let path = tmp_db("delete-kv");
        let mut conn = ok(open_and_migrate(&path), "open");
        let gid = "8000000000000260";
        ok(
            upsert_http_task(&mut conn, &row(gid, "downloading", 0)),
            "upsert",
        );
        ok(
            conn.execute_batch(
                &format!(
                    "INSERT INTO session_kv VALUES ('imported_from:db:/f.sqlite3#42', '{gid}');
                     INSERT INTO session_kv VALUES ('imported_from:db:/f.sqlite3#other', '8000000000000off');
                     INSERT INTO session_kv VALUES ('unrelated', 'value');"
                ),
            ),
            "seed kv marks",
        );
        assert_eq!(
            ok(delete_http_task(&mut conn, gid), "delete"),
            PersistOutcome::Written
        );
        let remaining: Vec<(String, String)> = {
            let mut stmt = ok(
                conn.prepare("SELECT key, value FROM session_kv ORDER BY key"),
                "prepare kv read",
            );
            let rows = ok(
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))),
                "query kv",
            );
            ok(rows.collect::<Result<Vec<_>, _>>(), "collect kv")
        };
        assert_eq!(
            remaining,
            vec![
                (
                    "imported_from:db:/f.sqlite3#other".to_string(),
                    "8000000000000off".to_string()
                ),
                ("unrelated".to_string(), "value".to_string()),
            ],
            "marks pointing back at this gid are cleared; unrelated keys and other gids kept"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Terminal rows refuse downgrade writes (writer-side guard): a
    /// non-terminal payload onto a stored terminal (done/error) row is
    /// skipped — the last-writer-wins race between stale saveSession
    /// mirror rows and the finalize terminal write is excluded by
    /// read-judge + write atomicity inside the single writer;
    /// terminal->terminal writes (e.g. a renamePending settle rewrite)
    /// and non-terminal-to-non-terminal writes are unaffected.
    #[test]
    fn http_task_terminal_row_rejects_downgrade_write() {
        let path = tmp_db("terminal-guard");
        let mut conn = ok(open_and_migrate(&path), "open");
        let gid = "8000000000000270";
        let stale = row(gid, "downloading", 0);
        assert_eq!(
            ok(upsert_http_task(&mut conn, &stale), "seed active"),
            PersistOutcome::Written
        );
        // Finalize the terminal write: full bitmap + progress + done.
        let mut done = row(gid, "done", 262_144);
        done.validator_digest = Some(vec![0x55; 32]);
        assert_eq!(
            ok(upsert_http_task(&mut conn, &done), "finalize"),
            PersistOutcome::Written
        );
        // A stale mirror row (downloading, zero progress, no digest)
        // landing after the terminal write -> skip; the stored done row
        // is untouched (no fallback to downloading, progress kept).
        assert_eq!(
            ok(upsert_http_task(&mut conn, &stale), "stale mirror write"),
            PersistOutcome::SkippedUnchanged,
            "a non-terminal overwrite of a terminal row must be refused"
        );
        // A stale paused row likewise.
        let paused = row(gid, "paused", 0);
        assert_eq!(
            ok(upsert_http_task(&mut conn, &paused), "stale paused write"),
            PersistOutcome::SkippedUnchanged
        );
        let loaded = ok(load_http_task(&conn, gid), "read back");
        let loaded = match loaded {
            Some(s) => s.row,
            None => panic!("row must exist"),
        };
        assert_eq!(loaded.state, "done", "a done row does not regress");
        assert_eq!(loaded.total_done, 262_144, "progress not lost");
        assert_eq!(loaded.validator_digest, Some(vec![0x55; 32]));
        // The error terminal state is under the same guard.
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &row(gid, "error", 1)),
                "error write"
            ),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(upsert_http_task(&mut conn, &stale), "stale over error"),
            PersistOutcome::SkippedUnchanged
        );
        // Terminal->terminal writes still land (a renamePending settle =
        // rewriting a done row).
        let mut done2 = done.clone();
        done2.config_json = r#"{"rename_pending":false}"#.into();
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &done2),
                "terminal over terminal"
            ),
            PersistOutcome::Written
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Explicit reopen of a terminal row (the only exit, for the
    /// Error->unpause re-probe migration arm): state back to queued,
    /// error fields cleared, bitmap/progress/digest retained;
    /// non-terminal and missing rows = idempotent skip; after the reopen
    /// the guard no longer blocks non-terminal-to-non-terminal writes.
    #[test]
    fn http_task_reopen_terminal_row_clears_errors_keeps_progress() {
        let path = tmp_db("reopen");
        let mut conn = ok(open_and_migrate(&path), "open");
        let gid = "8000000000000271";
        // Non-terminal row -> idempotent skip.
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &row(gid, "downloading", 0)),
                "seed"
            ),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(reopen_http_task(&mut conn, gid), "reopen active"),
            PersistOutcome::SkippedUnchanged
        );
        // error row -> reopen: queued + error fields cleared + progress
        // retained.
        let mut err = row(gid, "error", 524_288);
        err.error_code = Some("taiji.http.transport".into());
        err.error_msg = Some("boom".into());
        err.validator_digest = Some(vec![0x66; 32]);
        assert_eq!(
            ok(upsert_http_task(&mut conn, &err), "seed error"),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(reopen_http_task(&mut conn, gid), "reopen"),
            PersistOutcome::Written
        );
        let loaded = ok(load_http_task(&conn, gid), "read back");
        let loaded = match loaded {
            Some(s) => s.row,
            None => panic!("row must exist"),
        };
        assert_eq!(loaded.state, "queued");
        assert_eq!(loaded.error_code, None, "error code cleared");
        assert_eq!(loaded.error_msg, None, "error message cleared");
        assert_eq!(loaded.total_done, 524_288, "progress retained");
        assert_eq!(
            loaded.validator_digest,
            Some(vec![0x66; 32]),
            "digest retained"
        );
        // After the reopen the row allows non-terminal writes again (the
        // guard only looks at terminal states).
        assert_eq!(
            ok(
                upsert_http_task(&mut conn, &row(gid, "probing", 524_288)),
                "post-reopen"
            ),
            PersistOutcome::Written
        );
        // Missing row = idempotent.
        assert_eq!(
            ok(
                reopen_http_task(&mut conn, "8000000000000999"),
                "reopen missing"
            ),
            PersistOutcome::SkippedUnchanged
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Terminal done-row read face (the "DB as journal" read face of the
    /// renamePending startup closure): only state='done' rows; the
    /// single-row read face (any state) returns the row + the cookie
    /// set, missing row = None.
    #[test]
    fn http_task_done_rows_and_single_row_read_faces() {
        let path = tmp_db("done-read");
        let mut conn = ok(open_and_migrate(&path), "open");
        let done_gid = "8000000000000260";
        let active_gid = "8000000000000261";
        ok(
            upsert_http_task(&mut conn, &row(done_gid, "done", 4096)),
            "done row",
        );
        ok(
            upsert_http_task(&mut conn, &row(active_gid, "downloading", 0)),
            "active row",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                active_gid,
                TASK_KIND_HTTP,
                &[cookie(active_gid, "sid", "x.example", "/", "v")],
            ),
            "active cookies",
        );
        let done = ok(load_http_done_rows(&conn), "done rows");
        assert_eq!(
            done.iter().map(|r| r.gid.as_str()).collect::<Vec<_>>(),
            vec![done_gid],
            "only done rows returned"
        );
        // Single-row read face: the cookie set rides along
        // (primary-key order); missing row = None.
        let snap = ok(load_http_task(&conn, active_gid), "single row");
        let snap = match snap {
            Some(s) => s,
            None => panic!("active row must be found"),
        };
        assert_eq!(snap.row.gid, active_gid);
        assert_eq!(snap.cookies.len(), 1);
        assert_eq!(snap.cookies[0].name, "sid");
        assert!(ok(load_http_task(&conn, "8000000000000999"), "missing").is_none());
        let _ = std::fs::remove_file(&path);
    }
}

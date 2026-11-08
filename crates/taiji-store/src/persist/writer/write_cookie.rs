//! Unified `task_cookie` write/read faces: one cookie
//! table across the http|media families. The table carries **no FK**
//! (an explicit trade-off — a unified table cannot FK to either
//! parent family), so this module owns the three disciplines that
//! replace the old cascade:
//!
//! 1. **Paired delete**: the task-row delete faces
//!    ([`super::write_http::delete_http_task`] /
//!    [`super::write_media::delete_media_task`]) clear the gid's cookie
//!    rows inside the same transaction — the delete paths never leave
//!    cookie residue.
//! 2. **Terminal clear on the full terminal set** (the v0.3 widening): done
//!    **and** error both clear, driven by the caller (the actor's
//!    terminal close-out); [`clear_task_cookies`] is the idempotent
//!    store face.
//! 3. **Startup GC** ([`sweep_task_cookies`]): clears crash-window
//!    residue — (a) rows with no task row at all (a crash between the
//!    task-row delete and the paired cookie delete), (b) rows whose
//!    task row already sits at a terminal state (a crash before the
//!    terminal clear fired). Error-form residue is reported per gid so
//!    the bootstrap re-emits the clear-on-error alert; done-form and
//!    orphan residue are reported for the GC log. The sweep is
//!    idempotent and never touches active (non-terminal) rows.
//!
//! Write semantics (unchanged from the original face): whole-set
//! replacement — an unchanged set skips (zero disk writes), otherwise a
//! single-transaction DELETE of the task's rows + batch INSERT; an
//! empty set = clear all.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::{TASK_KIND_HTTP, TASK_KIND_MEDIA, TaskCookieRow};

pub(super) const TASK_COOKIE_COLS: &str =
    "gid, task_kind, name, domain, path, value, expires_utc, secure, host_only, creation_utc";

/// The unified table's column list (shared by the sibling read faces
/// that ride the http row reads).
pub(super) fn task_cookie_cols() -> &'static str {
    TASK_COOKIE_COLS
}

/// One swept terminal-residue group (the bootstrap alert face: one
/// event per (gid, kind); `count` = cookie rows cleared — never the
/// values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCookieSweepEntry {
    pub gid: String,
    /// `http`|`media` (the row's own task_kind).
    pub task_kind: String,
    /// Cookie rows cleared under this entry (a count only — cookie
    /// values never enter the report/alert face).
    pub count: i64,
}

/// Startup GC report (log + alert faces; no cookie values anywhere).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaskCookieSweepReport {
    /// Orphan rows cleared (no http_task/media_task row at all).
    pub orphaned: usize,
    /// Terminal-residue rows cleared on done-form tasks (log face).
    pub done_cleared: usize,
    /// Terminal-residue rows cleared on error-form tasks — each group
    /// re-fires the `taiji.task.cookiesClearedOnError` alert at
    /// bootstrap (the crash already ate the runtime emission).
    pub error_cleared: Vec<TaskCookieSweepEntry>,
}

/// Does the gid have a live parent row in either family? (The
/// paired-delete/GC liveness probe; `http`/`media` are the only
/// parents the unified table serves.)
fn task_row_exists(conn: &Connection, gid: &str) -> Result<bool, StoreError> {
    let http: Option<String> = conn
        .query_row(
            "SELECT gid FROM http_task WHERE gid = ?1",
            params![gid],
            |r| r.get(0),
        )
        .optional()?;
    if http.is_some() {
        return Ok(true);
    }
    let media: Option<String> = conn
        .query_row(
            "SELECT gid FROM media_task WHERE gid = ?1",
            params![gid],
            |r| r.get(0),
        )
        .optional()?;
    Ok(media.is_some())
}

/// Whole-set replacement of a task's cookies (the whole set in
/// one transaction): a set equal to the stored one -> skip (zero disk
/// writes, externally identical to digest dedup); otherwise a
/// single-transaction DELETE of all the task's cookies + batch INSERT.
/// An empty set = clear all (equivalent to [`clear_task_cookies`]).
///
/// Writer-side defenses: all payload rows must share `gid` **and** the
/// payload `task_kind`. Dangling-task policy (the FK-free table's
/// replacement discipline): a `http` payload requires an existing
/// http_task row (the family's invariant — cookies never outlive their
/// http task row); a `media` payload is accepted without a media_task
/// row because addMedia lands cookies at creation while the media_task
/// row first lands inside Resolving (the pipeline's row lifecycle)
/// — the single-writer serialization keeps the ordering
/// durable, and a media cookie row whose task never materialized is an
/// orphan the startup GC clears (the task is unrecoverable without its
/// row). Payload order is irrelevant (both sides are normalized to
/// primary-key order before comparison).
pub(super) fn upsert_task_cookies(
    conn: &mut Connection,
    gid: &str,
    task_kind: &str,
    cookies: &[TaskCookieRow],
) -> Result<PersistOutcome, StoreError> {
    if task_kind != TASK_KIND_HTTP && task_kind != TASK_KIND_MEDIA {
        return Err(StoreError::Internal(format!(
            "task_cookie payload kind {task_kind:?} outside the http|media domain"
        )));
    }
    if cookies
        .iter()
        .any(|c| c.gid != gid || c.task_kind != task_kind)
    {
        return Err(StoreError::Internal(
            "task_cookie set spans multiple gids/kinds; one task per call".into(),
        ));
    }
    if task_kind == TASK_KIND_HTTP && !task_row_exists(conn, gid)? {
        return Err(StoreError::Internal(format!(
            "http task_cookie set for {gid} has no http_task parent row"
        )));
    }
    let mut proposed: Vec<TaskCookieRow> = cookies.to_vec();
    proposed.sort_by(|a, b| (&a.name, &a.domain, &a.path).cmp(&(&b.name, &b.domain, &b.path)));
    let existing = load_task_cookies(conn, gid)?;
    if existing == proposed {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM task_cookie WHERE gid = ?1", params![gid])?;
    for c in &proposed {
        tx.execute(
            &format!(
                "INSERT INTO task_cookie ({TASK_COOKIE_COLS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
            ),
            params![
                c.gid,
                c.task_kind,
                c.name,
                c.domain,
                c.path,
                c.value,
                c.expires_utc,
                c.secure,
                c.host_only,
                c.creation_utc,
            ],
        )?;
    }
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Clear a task's cookies (the terminal close-out entry: the
/// full terminal set done|error clears on both families; the row
/// deletes pair their own clear): no rows = `SkippedUnchanged`
/// (idempotent).
pub(super) fn clear_task_cookies(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let tx = conn.transaction()?;
    let deleted = tx.execute("DELETE FROM task_cookie WHERE gid = ?1", params![gid])?;
    tx.commit()?;
    if deleted == 0 {
        Ok(PersistOutcome::SkippedUnchanged)
    } else {
        Ok(PersistOutcome::Written)
    }
}

/// The task's stored cookie set (primary-key order = name/domain/path);
/// the count face for the clear-on-error alert (load first, then
/// clear) and the media activation seed read-back.
pub(super) fn load_task_cookies(
    conn: &Connection,
    gid: &str,
) -> Result<Vec<TaskCookieRow>, StoreError> {
    let sql = format!(
        "SELECT {TASK_COOKIE_COLS} FROM task_cookie
         WHERE gid = ?1 ORDER BY name, domain, path"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![gid], read_cookie_row_of)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

/// The row reader (shared by the sibling faces that read cookie sets
/// alongside http rows).
pub(super) fn read_cookie_row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskCookieRow> {
    Ok(TaskCookieRow {
        gid: r.get(0)?,
        task_kind: r.get(1)?,
        name: r.get(2)?,
        domain: r.get(3)?,
        path: r.get(4)?,
        value: r.get(5)?,
        expires_utc: r.get(6)?,
        secure: r.get::<_, i64>(7)? != 0,
        host_only: r.get::<_, i64>(8)? != 0,
        creation_utc: r.get(9)?,
    })
}

/// Startup GC ("the startup GC cleans crash orphans"). One transaction, three
/// residue classes:
/// - orphans: rows whose gid has no http_task and no media_task row
///   (crash between the task-row delete and the paired cookie delete);
/// - terminal residue: rows whose task row sits at done/error (crash
///   before the terminal clear fired) — error-form groups are reported
///   per (gid, kind) so the bootstrap re-emits the clear-on-error
///   alert (the crash already ate the runtime emission); done-form
///   rows feed the log count only;
/// - everything else (an active/paused task's rows) is untouched.
///
/// Idempotent by construction (the second run finds no residue); never
/// touches active rows.
pub(super) fn sweep_task_cookies(
    conn: &mut Connection,
) -> Result<TaskCookieSweepReport, StoreError> {
    let tx = conn.transaction()?;
    // (a) Orphans: no parent row in either family.
    let orphaned = tx.execute(
        "DELETE FROM task_cookie WHERE gid NOT IN (SELECT gid FROM http_task)
         AND gid NOT IN (SELECT gid FROM media_task)",
        [],
    )?;
    // (b) Terminal residue, collected per (gid, task_kind) before
    // deleting so the report carries the cleared row counts (counts
    // only — cookie values never enter the report face). The parent
    // row's own state decides the done/error classification; the
    // cookie row's task_kind is reported verbatim (the rare re-labeled
    // row — a DirectLink-converted task's pre-conversion rows — still
    // clears with its gid).
    let mut error_cleared: Vec<TaskCookieSweepEntry> = Vec::new();
    let mut done_cleared: usize = 0;
    for (state, is_error) in [("error", true), ("done", false)] {
        for parent in ["http_task", "media_task"] {
            let sql = format!(
                "SELECT c.gid, c.task_kind, COUNT(*) FROM task_cookie c
                 JOIN {parent} t ON t.gid = c.gid AND t.state = '{state}'
                 GROUP BY c.gid, c.task_kind"
            );
            let mut stmt = tx.prepare(&sql)?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (gid, task_kind, count) = row.map_err(StoreError::from)?;
                if is_error {
                    error_cleared.push(TaskCookieSweepEntry {
                        gid,
                        task_kind,
                        count,
                    });
                } else {
                    done_cleared += count as usize;
                }
            }
        }
    }
    let terminal = tx.execute(
        "DELETE FROM task_cookie WHERE gid IN (
             SELECT gid FROM http_task WHERE state IN ('done','error'))
         OR gid IN (
             SELECT gid FROM media_task WHERE state IN ('done','error'))",
        [],
    )?;
    tx.commit()?;
    debug_assert_eq!(
        terminal as i64,
        error_cleared.iter().map(|e| e.count).sum::<i64>() + done_cleared as i64,
        "the sweep report counts must equal the deleted terminal-residue rows"
    );
    Ok(TaskCookieSweepReport {
        orphaned,
        done_cleared,
        error_cleared,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::open_and_migrate;
    use crate::persist::writer::rows::{HttpTaskRow, MediaTaskRow};
    use crate::persist::writer::write_http::{delete_http_task, upsert_http_task};
    use crate::persist::writer::write_media::{delete_media_task, upsert_media_task};

    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    fn tmp_db(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "taiji-cookie-{}-{}-{}.sqlite3",
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

    fn cookie(gid: &str, kind: &str, name: &str) -> TaskCookieRow {
        TaskCookieRow {
            gid: gid.into(),
            task_kind: kind.into(),
            name: name.into(),
            domain: "x.example".into(),
            path: "/".into(),
            value: format!("v-{name}"),
            expires_utc: None,
            secure: false,
            host_only: true,
            creation_utc: 1,
        }
    }

    fn http_row(gid: &str, state: &str) -> HttpTaskRow {
        HttpTaskRow {
            gid: gid.into(),
            url: "http://o/f".into(),
            final_url: "http://c/f".into(),
            mirrors_json: None,
            state: state.into(),
            queue_pos: 0,
            dir: "/dl".into(),
            out: "f".into(),
            config_json: "{}".into(),
            probe_json: None,
            validator_digest: None,
            block_size: 4096,
            block_bitmap: None,
            block_count: None,
            total_done: 0,
            error_code: None,
            error_msg: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn media_row(gid: &str, state: &str) -> MediaTaskRow {
        MediaTaskRow {
            gid: gid.into(),
            kind: "hls".into(),
            manifest_url: "http://x/m.m3u8".into(),
            state: state.into(),
            phase_detail_json: None,
            variant_json: None,
            selector_json: None,
            output_name: None,
            bridge_json: None,
            staging_dir: "/tmp/s".into(),
            output_path: "/tmp/o".into(),
            manifest_norm_digest: vec![1],
            total_done: 0,
            config_json: "{}".into(),
            error_code: None,
            error_msg: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        ok(conn.query_row(sql, [], |r| r.get(0)), "count")
    }

    /// The paired-delete double integration: the http
    /// and media delete faces each clear the gid's task_cookie rows in
    /// the same transaction — zero residue after remove/forceRemove.
    #[test]
    fn delete_faces_pair_the_cookie_clear_http_and_media() {
        let path = tmp_db("paired");
        let mut conn = ok(open_and_migrate(&path), "open");
        let h = "8000000000000281";
        let m = "8000000000000282";
        ok(
            upsert_http_task(&mut conn, &http_row(h, "downloading")),
            "http row",
        );
        ok(
            upsert_media_task(&mut conn, &media_row(m, "downloading")),
            "media row",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                h,
                TASK_KIND_HTTP,
                &[
                    cookie(h, TASK_KIND_HTTP, "sid"),
                    cookie(h, TASK_KIND_HTTP, "auth"),
                ],
            ),
            "http cookies",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                m,
                TASK_KIND_MEDIA,
                &[cookie(m, TASK_KIND_MEDIA, "sid")],
            ),
            "media cookies",
        );
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM task_cookie"), 3);
        // Both delete faces pair their clear.
        assert_eq!(
            ok(delete_http_task(&mut conn, h), "http delete"),
            PersistOutcome::Written
        );
        assert_eq!(
            ok(delete_media_task(&mut conn, m), "media delete"),
            PersistOutcome::Written
        );
        assert_eq!(
            count(&conn, "SELECT COUNT(*) FROM task_cookie"),
            0,
            "the delete face must pair the cookie clear (zero residue in both families)"
        );
        // Idempotent re-deletes stay clean.
        assert_eq!(
            ok(delete_http_task(&mut conn, h), "http redelete"),
            PersistOutcome::SkippedUnchanged
        );
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM task_cookie"), 0);
        let _ = std::fs::remove_file(&path);
    }

    /// The startup GC (acceptance item 3): orphan rows and terminal residue are
    /// cleared, active rows survive, the sweep is idempotent, and the
    /// error-form groups ride the report for the bootstrap alert
    /// (counts only, no values).
    #[test]
    fn sweep_clears_orphans_and_terminal_residue_keeps_active() {
        let path = tmp_db("sweep");
        let mut conn = ok(open_and_migrate(&path), "open");
        // Active http + media rows: their cookies must survive.
        let ha = "8000000000000283";
        let ma = "8000000000000284";
        ok(
            upsert_http_task(&mut conn, &http_row(ha, "paused")),
            "http active",
        );
        ok(
            upsert_media_task(&mut conn, &media_row(ma, "downloading")),
            "media active",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                ha,
                TASK_KIND_HTTP,
                &[cookie(ha, TASK_KIND_HTTP, "sid")],
            ),
            "http active cookies",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                ma,
                TASK_KIND_MEDIA,
                &[cookie(ma, TASK_KIND_MEDIA, "sid")],
            ),
            "media active cookies",
        );
        // Terminal residue: http error + media error + http done rows
        // whose terminal clear never fired (crash window).
        let he = "8000000000000285";
        let me = "8000000000000286";
        let hd = "8000000000000287";
        ok(
            upsert_http_task(&mut conn, &http_row(he, "error")),
            "http err row",
        );
        ok(
            upsert_media_task(&mut conn, &media_row(me, "error")),
            "media err row",
        );
        ok(
            upsert_http_task(&mut conn, &http_row(hd, "done")),
            "http done row",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                he,
                TASK_KIND_HTTP,
                &[
                    cookie(he, TASK_KIND_HTTP, "sid"),
                    cookie(he, TASK_KIND_HTTP, "tok"),
                ],
            ),
            "http err cookies",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                me,
                TASK_KIND_MEDIA,
                &[cookie(me, TASK_KIND_MEDIA, "sid")],
            ),
            "media err cookies",
        );
        ok(
            upsert_task_cookies(
                &mut conn,
                hd,
                TASK_KIND_HTTP,
                &[cookie(hd, TASK_KIND_HTTP, "sid")],
            ),
            "http done cookies",
        );
        // Orphans: no task row at all (crash between the task-row
        // delete and the paired clear) — seeded raw (the write face
        // would refuse/allow by kind; the GC face takes rows as they
        // are).
        ok(
            conn.execute(
                "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                     expires_utc, secure, host_only, creation_utc)
                 VALUES ('8000000000000288', 'http', 'o1', 'x.example', '/', 'v', NULL, 0, 1, 1)",
                [],
            ),
            "seed http orphan",
        );
        ok(
            conn.execute(
                "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                     expires_utc, secure, host_only, creation_utc)
                 VALUES ('8000000000000289', 'media', 'o2', 'x.example', '/', 'v', NULL, 0, 1, 1)",
                [],
            ),
            "seed media orphan",
        );
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM task_cookie"), 8);

        let report = ok(sweep_task_cookies(&mut conn), "sweep 1");
        assert_eq!(report.orphaned, 2, "each of the two orphans clears one row");
        assert_eq!(
            report.done_cleared, 1,
            "1 done-residue row goes into the log face"
        );
        let mut want_err = vec![
            TaskCookieSweepEntry {
                gid: he.to_string(),
                task_kind: TASK_KIND_HTTP.to_string(),
                count: 2,
            },
            TaskCookieSweepEntry {
                gid: me.to_string(),
                task_kind: TASK_KIND_MEDIA.to_string(),
                count: 1,
            },
        ];
        want_err.sort_by(|a, b| a.gid.cmp(&b.gid));
        assert_eq!(
            report.error_cleared, want_err,
            "error residue is reported grouped by (gid, kind)"
        );
        // Active rows survive; everything else is gone.
        let left = count(
            &conn,
            "SELECT COUNT(*) FROM task_cookie WHERE gid IN ('8000000000000283','8000000000000284')",
        );
        assert_eq!(left, 2, "active rows are not mistakenly cleared");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM task_cookie"), 2);
        // Idempotent: the second sweep finds nothing.
        let again = ok(sweep_task_cookies(&mut conn), "sweep 2");
        assert_eq!(
            (
                again.orphaned,
                again.done_cleared,
                again.error_cleared.len()
            ),
            (0, 0, 0),
            "the GC is idempotent"
        );
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM task_cookie"), 2);
        let _ = std::fs::remove_file(&path);
    }

    /// The unified table's own guards: the task_kind CHECK domain
    /// rejects out-of-family values; an out-of-domain payload kind is
    /// refused by the write face before touching SQL.
    #[test]
    fn task_kind_domain_is_checked() {
        let path = tmp_db("kind-check");
        let mut conn = ok(open_and_migrate(&path), "open");
        assert!(
            conn.execute(
                "INSERT INTO task_cookie (gid, task_kind, name, domain, path, value,
                     expires_utc, secure, host_only, creation_utc)
                 VALUES ('8000000000000290', 'bt', 'n', 'x.example', '/', 'v', NULL, 0, 1, 1)",
                [],
            )
            .is_err(),
            "the task_kind CHECK must reject values outside the http|media domain"
        );
        assert!(
            upsert_task_cookies(&mut conn, "8000000000000291", "bt", &[]).is_err(),
            "the write face must refuse out-of-domain kind payloads"
        );
        let _ = std::fs::remove_file(&path);
    }
}

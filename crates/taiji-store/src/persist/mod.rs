//! `taiji.sqlite3` persistence.
//!
//! Layout: [`schema`] holds the migration ledger and DDL; [`writer`]
//! holds the single PersistWriter task (digest dedup skips redundant
//! writes).
//!
//! Discipline: single writer — the `rusqlite::Connection` lives only
//! inside PersistWriter's dedicated blocking task (`Connection` is not
//! `Sync`, so ownership expresses the single writer). Open/migrate/query
//! are all disk IO and always run on `spawn_blocking` or a dedicated
//! blocking thread, never on a runtime worker.

pub mod fork_import;
pub mod schema;
pub mod writer;

pub use fork_import::{
    Aria2ControlFile, Aria2CtrlError, Aria2HttpControl, FORK_SCHEMA_VERSION, ForkHttpTaskRow,
    ForkProgress, ForkTaskRow, collect_aria2_files, completed_length_from_bitfield,
    count_fork_tasks, expected_bitfield_len, load_fork_bt_tasks, load_fork_http_tasks,
    open_fork_readonly, parse_aria2_control, parse_aria2_control_http, probe_fork_readonly,
};
pub use schema::{MIGRATIONS, Migration, SCHEMA_V2_TABLES, SCHEMA_V3_TABLES};
pub use writer::{
    DhtStateRow, HTTP_TASK_ACTIVE_STATES, HttpTaskRow, HttpTaskSnapshot, IpfilterRow,
    MediaArchiveRow, MediaFormatRow, MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow,
    PeerBanRow, PersistHandle, PersistJob, PersistObserve, PersistOutcome, PersistWriter,
    RecoveredLayerRow, SharedPersistObserve, TASK_KIND_HTTP, TASK_KIND_MEDIA,
    TORRENT_ACTIVE_STATES, TaskCookieRow, TaskCookieSweepEntry, TaskCookieSweepReport,
    TorrentFileRow, TorrentProgressRow, TorrentRow, TorrentSnapshot, TrackerRow,
};

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, params_from_iter};

use crate::error::StoreError;

/// Open a connection and advance migrations (WAL + synchronous=NORMAL +
/// foreign_keys=ON + busy_timeout=5000 + user_version ledger).
///
/// Migration semantics: the version read and all pending
/// migrations commit atomically inside a single `BEGIN IMMEDIATE` write
/// transaction; any failure rolls everything back and `user_version`
/// does not advance — after a mid-way kill, reopening replays safely;
/// concurrent opens serialize at the transaction boundary (see
/// [`open_and_migrate_up_to`]).
pub(crate) fn open_and_migrate(path: &Path) -> Result<Connection, StoreError> {
    open_and_migrate_up_to(path, schema::LATEST_VERSION)
}

/// Parameterized open path: migrations up to `supported` replay,
/// anything above is refused.
///
/// Built for rollback-semantics verification: an old binary's open
/// behavior is isomorphic to this function with `supported` set to the
/// old [`schema::LATEST_VERSION`] (the same `current > supported` ->
/// [`StoreError::MigrationVersionMismatch`] decision and the same
/// migration replay loop), so tests verify "old binaries refuse new
/// databases" without shipping an old binary.
///
/// # Concurrent open/migrate race (semantics authority)
///
/// If the version read happened outside the transaction and each
/// migration ran in its own transaction, two processes (or two
/// PersistWriter instances) opening an unmigrated database could
/// interleave as "loser reads the old version -> winner commits the
/// migration -> loser's DDL hits `table already exists`", failing the
/// open — a real trigger surface that violates the
/// single-writer semantics. This implementation wraps the
/// `PRAGMA user_version` read and all migrations in a single
/// `BEGIN IMMEDIATE` transaction: the loser is blocked at the
/// transaction start by the write lock (waiting within busy_timeout),
/// and after the winner commits the loser reads the advanced version
/// and its migration loop is naturally empty — the race window is
/// structurally eliminated by the transaction semantics.
pub(crate) fn open_and_migrate_up_to(
    path: &Path,
    supported: i64,
) -> Result<Connection, StoreError> {
    // The sqlite session-database open point converts too — the C
    // library consumes the same string semantics (on Windows, sqlite3
    // opens hit the same MAX_PATH limit; on non-Windows this is a
    // zero-cost identity borrow). Error classification keeps the
    // original path.
    let mut conn = Connection::open(taiji_io::winpath::to_fs_path(path))
        .map_err(|e| classify_open_error(path, e))?;
    // At-rest hardening: the database file (plus the -wal/-shm sidecars
    // sqlite creates later) gets 0600. The database stores cookies in
    // plaintext plus tracker passkeys and config_json credentials
    // verbatim; on a multi-user host the default 0644&~umask would be
    // readable by any local user. Failures are best-effort (opening is
    // not blocked — a permission error on an existing database should
    // not keep the session from starting; for a new database this call
    // sets the permission).
    secure_at_rest(path);
    apply_pragmas(&conn, path)?;
    // IMMEDIATE (not DEFERRED): the version read must happen after the
    // write lock is held — under DEFERRED the version read sees the old
    // snapshot and the upgrade write hits the lock later, leaving the
    // race intact.
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| classify_open_error(path, e))?;
    let current: i64 = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| classify_open_error(path, e))?;
    if current > supported {
        // Old binary refuses a newer database: `tx` rolls back in place
        // (drop) with zero writes in this transaction. Open-phase PRAGMAs
        // are connection-level configuration (journal_mode writes nothing
        // when already WAL); the main file's bytes are untouched by this
        // path — tests back this with a before/after sha256 of the main
        // file plus no -wal/-shm leftovers.
        return Err(StoreError::MigrationVersionMismatch {
            db: current,
            supported,
        });
    }
    for migration in schema::MIGRATIONS
        .iter()
        .filter(|m| m.version > current && m.version <= supported)
    {
        // Ledger discipline: all SQL + the `user_version` advance share
        // the transaction with the version decision — all or nothing.
        for sql in migration.sqls {
            tx.execute_batch(sql)?;
        }
        tx.pragma_update(None, "user_version", migration.version)?;
    }
    tx.commit()?;
    Ok(conn)
}

/// At-rest 0600 for the session database (main file + WAL/SHM sidecars —
/// sqlite creates sidecars lazily, so this is re-applied idempotently on
/// each open; NotFound ignored). unix-only.
#[cfg(unix)]
fn secure_at_rest(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["", "-wal", "-shm"] {
        let mode = std::fs::Permissions::from_mode(0o600);
        let p = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            path.with_file_name(format!(
                "{}{suffix}",
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ))
        };
        if std::fs::set_permissions(&p, mode).is_err() {
            // best-effort: sidecar not created yet (NotFound) or an
            // existing database with restricted permissions.
        }
    }
}

#[cfg(not(unix))]
fn secure_at_rest(_path: &Path) {}

/// Open-phase PRAGMAs (these actually touch the database, so corrupt
/// files surface here). `busy_timeout` goes first: every later statement
/// (including the journal_mode switch and BEGIN IMMEDIATE) should wait
/// under concurrent opens instead of failing immediately.
///
/// `secure_delete=ON` (the at-rest posture): deleted rows'
/// pages are zeroed before reuse, so cleared cookies (the full-terminal
/// clear + the startup GC) leave no plaintext residue in freelist
/// pages. The at-rest posture itself: cookie (and
/// key) values are stored **plaintext** under the local-machine threat
/// model — the database file is 0600 (see [`secure_at_rest`]) and
/// secure_delete bounds the deleted-copy surface; OS keyring / static
/// encryption is explicitly deferred to a later milestone. The setting rides
/// [`apply_pragmas`], the one open face every connection that can
/// **write** goes through (`open_and_migrate` — the PersistWriter's
/// single writer connection, the only face that ever deletes a cookie
/// row); the read-only import/probe connections never delete anything,
/// so the setting is moot there. The value is a per-connection setting
/// (never persisted in the database file); external tools opening the
/// same file do not inherit it.
fn apply_pragmas(conn: &Connection, path: &Path) -> Result<(), StoreError> {
    conn.busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(|e| classify_open_error(path, e))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| classify_open_error(path, e))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| classify_open_error(path, e))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| classify_open_error(path, e))?;
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|e| classify_open_error(path, e))?;
    Ok(())
}

/// Open-phase error classification: NOTADB(26)/CORRUPT(11) and other
/// content-level corruption map to [`StoreError::CorruptDatabase`];
/// everything else (permissions, busy, path) stays
/// [`StoreError::Sqlite`] — callers decide rebuild/alert from the error
/// code and must not mislabel corruption.
fn classify_open_error(path: &Path, e: rusqlite::Error) -> StoreError {
    const SQLITE_CORRUPT: i32 = 11;
    const SQLITE_NOTADB: i32 = 26;
    if let rusqlite::Error::SqliteFailure(ffi, _) = &e
        && (ffi.extended_code & 0xFF == SQLITE_CORRUPT || ffi.extended_code & 0xFF == SQLITE_NOTADB)
    {
        return StoreError::CorruptDatabase {
            path: path.display().to_string(),
            source: e,
        };
    }
    StoreError::Sqlite(e)
}

/// Outcome of the automatic pre-import backup ([`backup_target_db`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportBackup {
    /// Created `.v1.bak` (first-import path — the restore anchor of the
    /// rollback runbook).
    Created(std::path::PathBuf),
    /// `.v1.bak` already exists; kept, never overwritten: the earliest
    /// pre-import snapshot is the fork-era data truth. A second import
    /// rewriting it would displace it with a "post-rollback re-import"
    /// snapshot, breaking the runbook's "restore to the fork era"
    /// semantics.
    KeptExisting(std::path::PathBuf),
    /// Target database does not exist (fresh endpoint) — no state to
    /// preserve, no backup needed.
    NotNeeded,
}

impl ImportBackup {
    /// Backup file path (`NotNeeded` = None).
    pub fn path(&self) -> Option<&Path> {
        match self {
            ImportBackup::Created(p) | ImportBackup::KeptExisting(p) => Some(p),
            ImportBackup::NotNeeded => None,
        }
    }

    /// Stable report descriptor (the conclusion half of the import
    /// report's "pre-import backup: ..." line).
    pub fn description(&self) -> &'static str {
        match self {
            ImportBackup::Created(_) => "created",
            ImportBackup::KeptExisting(_) => "kept existing (never overwritten)",
            ImportBackup::NotNeeded => "not needed",
        }
    }
}

/// Automatic pre-import backup of `taiji.sqlite3` ->
/// `taiji.sqlite3.v1.bak` (the rollback runbook's restore anchor).
///
/// Semantics:
/// - Must be called before any open/migration of the target database —
///   `.v1.bak` preserves the bytes from before the migration ledger
///   advances (a form a 0.1.x binary can open, readable by the
///   rollback);
/// - "Target offline" enforcement (precheck item 3) = WAL sidecar
///   detection: `-wal`/`-shm` on disk means a live local taiji session
///   or an unclean previous exit (sqlite checkpoints and deletes both
///   when the last connection closes cleanly; they stay on disk while a
///   session lives) -> [`StoreError::TargetInUse`]. Checkpoint busy is
///   not the primary probe: its semantics for idle connections are
///   unreliable across platforms, and an active session would yield no
///   snapshot — never silently produce a torn backup;
/// - Sidecars absent = cleanly offline; a best-effort
///   `wal_checkpoint(TRUNCATE)` folds any residual WAL in (busy also
///   refuses), then a single-file copy is a consistent snapshot;
/// - Copy atomicity: temp (unique name in the same directory) + fsync +
///   atomic rename — an interrupted copy leaves garbage only under the
///   temp name; a torn copy can never reach the anchor name (a
///   readability check runs once more before landing the anchor);
/// - Existing `.v1.bak` -> after a usability check (sqlite header /
///   openable) [`ImportBackup::KeptExisting`] (never overwritten; see
///   the variant docs); a failed check = a torn/corrupt backup is
///   explicitly rejected ([`StoreError::CorruptDatabase`]; anchor bytes
///   untouched); no target database -> [`ImportBackup::NotNeeded`].
///
/// # Errors
///
/// [`StoreError::TargetInUse`] when the target is not offline (WAL
/// sidecars present / checkpoint busy); [`StoreError::CorruptDatabase`]
/// when an existing backup fails the usability check;
/// [`StoreError::Sqlite`]/[`StoreError::FileIo`] from the checkpoint
/// open, the copy and its fsync.
///
/// Blocking: disk IO + sqlite connections; callers put this in
/// `spawn_blocking`.
pub fn backup_target_db(db_path: &Path) -> Result<ImportBackup, StoreError> {
    let backup_path = backup_path_for(db_path);
    if !db_path.exists() {
        return Ok(ImportBackup::NotNeeded);
    }
    if wal_sidecars_present(db_path) {
        return Err(StoreError::TargetInUse {
            path: db_path.display().to_string(),
        });
    }
    if backup_path.exists() {
        // An existing backup must be usable to deserve "restore anchor":
        // a torn/corrupt backup is explicitly rejected rather than kept
        // under the KeptExisting name (discovering it is unusable when
        // the rollback actually needs it is the worst failure timing).
        ensure_backup_readable(&backup_path)?;
        return Ok(ImportBackup::KeptExisting(backup_path));
    }
    {
        // The sqlite open point converts too (backup validation face;
        // identity on non-Windows).
        let conn = Connection::open(taiji_io::winpath::to_fs_path(db_path))
            .map_err(|e| classify_open_error(db_path, e))?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))
            .map_err(StoreError::from)?;
        let (busy, _log_frames, _ckpt_frames): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map_err(StoreError::from)?;
        if busy != 0 {
            return Err(StoreError::TargetInUse {
                path: db_path.display().to_string(),
            });
        }
    }
    // temp + fsync + atomic rename: an interrupted copy leaves garbage
    // only under the temp name; the anchor name never appears in torn
    // form (a direct `fs::copy` to the final name once let a kill window
    // produce half a `.v1.bak` — worse than no backup, because it looks
    // like a restore anchor). fsync before rename fixes the disk order;
    // a directory fsync after rename fixes the dirent (unix; Windows
    // skips best-effort — the crash window leaves only "backup missing",
    // the main database unharmed).
    let temp_path = temp_backup_path(&backup_path);
    let fail_io = |path: &Path, e: std::io::Error| StoreError::FileIo {
        path: path.display().to_string(),
        source: e,
    };
    let copied = match std::fs::copy(db_path, &temp_path) {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&temp_path);
            return Err(fail_io(&temp_path, e));
        }
    };
    let source_len = match std::fs::metadata(db_path) {
        Ok(m) => m.len(),
        Err(e) => {
            let _ = std::fs::remove_file(&temp_path);
            return Err(fail_io(db_path, e));
        }
    };
    if copied != source_len {
        let _ = std::fs::remove_file(&temp_path);
        return Err(fail_io(
            &temp_path,
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short copy (backup would be torn)",
            ),
        ));
    }
    if let Err(e) = std::fs::File::open(&temp_path).and_then(|f| f.sync_all()) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(fail_io(&temp_path, e));
    }
    // Validate before landing the anchor: a torn copy can never reach
    // the `.v1.bak` name.
    if let Err(e) = ensure_backup_readable(&temp_path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    std::fs::rename(&temp_path, &backup_path).map_err(|e| fail_io(&backup_path, e))?;
    #[cfg(unix)]
    if let Some(dir) = backup_path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(ImportBackup::Created(backup_path))
}

/// `.v1.bak` usability check (sqlite header / openable): read-only open +
/// schema read probe — sqlite reads the database header on the first
/// statement, so NOTADB(26)/truncation/CORRUPT(11) all flow through
/// [`classify_open_error`] into an explicit
/// [`StoreError::CorruptDatabase`] rejection;
/// `SQLITE_OPEN_READ_ONLY` guarantees the check itself writes nothing
/// (anchor bytes untouched).
fn ensure_backup_readable(path: &Path) -> Result<(), StoreError> {
    let conn = open_import_target_readonly(path)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|e| classify_open_error(path, e))?;
    Ok(())
}

/// Backup temp naming: same directory as the anchor (the rename stays
/// atomic within one filesystem) + a unique suffix (concurrent runs and
/// leftovers do not collide); the caller cleans up failure paths.
fn temp_backup_path(backup_path: &Path) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mut s = backup_path.as_os_str().to_os_string();
    s.push(format!(".tmp-{}-{}", std::process::id(), nanos));
    std::path::PathBuf::from(s)
}

/// `.v1.bak` naming: suffix appended to the full file name
/// (`taiji.sqlite3` -> `taiji.sqlite3.v1.bak`).
fn backup_path_for(db_path: &Path) -> std::path::PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(".v1.bak");
    std::path::PathBuf::from(s)
}

/// WAL sidecar presence (`<db>-wal` / `<db>-shm`): sqlite deletes both
/// when the last connection closes cleanly; either on disk = a live
/// session or an unclean previous exit (the primary "target offline"
/// probe of [`backup_target_db`]).
fn wal_sidecars_present(db_path: &Path) -> bool {
    ["-wal", "-shm"].iter().any(|suffix| {
        let mut s = db_path.as_os_str().to_os_string();
        s.push(suffix);
        std::path::Path::new(&s).exists()
    })
}

/// Read-only probe result for the import target (shape guard + ledger
/// position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportTargetProbe {
    /// `PRAGMA user_version` (migration ledger position).
    pub user_version: i64,
    /// Highest ledger version this build supports (a real import advances
    /// to it).
    pub latest_supported: i64,
    /// Target has the fork schema shape (`task`/`task_progress` tables
    /// present) — the guard against pointing the fork database at the
    /// import target (the mirror of the fork side's table-set probe: the
    /// fork side blocks "taiji database as source", this probe blocks
    /// "fork database as target"; otherwise the pre-import backup's
    /// checkpoint and the open/migration would write fork storage).
    pub fork_shaped: bool,
}

/// Read-only snapshot of the import target (the dry-run dedup/occupancy
/// query face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportTargetSnapshot {
    /// `PRAGMA user_version` (migration ledger position).
    pub user_version: i64,
    /// Highest ledger version this build supports (a real import advances
    /// to it).
    pub latest_supported: i64,
    /// Target has the fork schema shape (same as
    /// [`ImportTargetProbe::fork_shaped`]).
    pub fork_shaped: bool,
    /// Dedup key read face: request key -> imported gid. The single hit
    /// criterion is the task row (http_task row config_json's
    /// `origin_fork_key`: row present + key equal = hit; row absent =
    /// re-import allowed, no dead-marker form);
    /// `session_kv.imported_from` is the reverse-index fallback (old
    /// databases missing row keys + the BT import face); a fallback hit
    /// is still liveness-checked — a missing back-reference row counts
    /// as not-imported and lands in [`Self::stale_imported`].
    pub imported: std::collections::HashMap<String, Option<String>>,
    /// Dedup hit keys whose back-reference went stale (kv entry present
    /// but the referenced row deleted — treated as not-imported so
    /// re-import is not permanently blocked by a dead reference; the key
    /// set is reported. The row-key criterion has no dead form — it lives
    /// and dies with the row; this set only collects stale keys from the
    /// kv fallback).
    pub stale_imported: Vec<String>,
    /// Occupied active http_task (dir, out) set (the path-conflict
    /// decision face).
    pub occupied_http: Vec<(String, String)>,
}

/// Read-only probe of the import target (`SQLITE_OPEN_READ_ONLY`, zero
/// writes in all cases). A dry run never opens the existing target
/// through [`PersistWriter`] — opening advances the migration ledger,
/// and the standard "dry-run first, import later" flow once poisoned
/// the `.v1.bak` rollback anchor into an "already migrated" snapshot.
/// Disk IO: callers put this in `spawn_blocking`.
pub fn probe_import_target_readonly(path: &Path) -> Result<ImportTargetProbe, StoreError> {
    let conn = open_import_target_readonly(path)?;
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| classify_open_error(path, e))?;
    Ok(ImportTargetProbe {
        user_version,
        latest_supported: schema::LATEST_VERSION,
        fork_shaped: has_table(&conn, "task")? && has_table(&conn, "task_progress")?,
    })
}

/// Read-only snapshot of the import target (dry-run dedup keys + HTTP
/// occupancy set in one open; the write face stays PersistWriter's
/// single point, this function only serves queries). Disk IO: callers
/// put this in `spawn_blocking`.
///
/// Version gating (exact facts, not degradation):
/// - `user_version == 0` (uninitialized database): no session_kv /
///   http_task — dedup all empty, occupancy all empty (an uninitialized
///   database cannot have imported anything);
/// - `0 < user_version < 3` (0.1.x shape): session_kv is present and
///   queried for dedup (kv reverse-index fallback); http_task is a
///   ledger v3 table — a pre-v3 (BT-only) database cannot contain HTTP
///   tasks, so
///   an empty occupancy set is an exact fact.
///
/// Hit criterion (single source): row present + key equal — scan
/// http_task rows' `origin_fork_key` first (the criterion proper, alive
/// with the row); on a miss consult the session_kv reverse index and
/// liveness-check it (fallback).
pub fn read_import_target_snapshot(
    path: &Path,
    keys: &[String],
) -> Result<ImportTargetSnapshot, StoreError> {
    let conn = open_import_target_readonly(path)?;
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| classify_open_error(path, e))?;
    let fork_shaped = has_table(&conn, "task")? && has_table(&conn, "task_progress")?;
    // Row-key criterion proper: origin_fork_key lands with the task row
    // (the criterion face exists only when the table does).
    let mut by_origin: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if has_table(&conn, "http_task")? {
        for (key, gid) in origin_fork_key_rows(&conn)? {
            by_origin.entry(key).or_insert(gid);
        }
    }
    let mut imported = std::collections::HashMap::with_capacity(keys.len());
    let mut stale_imported = Vec::new();
    for key in keys {
        // Criterion proper: row present + key equal = hit (alive with the
        // row, no dead-marker form).
        if let Some(gid) = by_origin.get(key) {
            imported.insert(key.clone(), Some(gid.clone()));
            continue;
        }
        // Fallback: kv reverse index (old databases missing row keys +
        // the BT import face).
        let value = if user_version > 0 {
            conn.query_row("SELECT value FROM session_kv WHERE key = ?1", [key], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .map_err(StoreError::from)?
        } else {
            None
        };
        // Hit liveness check: a kv hit's value is the referenced task gid
        // and must be backed by a live row. Death needs evidence: the
        // referenced gid is absent from every *present* task table
        // (http_task / torrent — the BT import face shares the gid key
        // space) while at least one task table is present -> the row was
        // deleted (dead reference), treated as not-imported so re-import
        // is not permanently blocked, and the stale key is recorded for
        // the report; with no task table present (degenerate shape) there
        // is no evidence, so the hit is conservatively kept (dedup is the
        // conservative face of overwrite protection — never silently
        // treat a failed dedup read as not-imported). BT/HTTP gid
        // namespaces are disjoint (the BT high-bit isolation), so
        // cross-face misjudgment cannot happen.
        let value = match value {
            Some(gid) => {
                let mut tables_present = 0usize;
                let mut absent_everywhere = true;
                for table in ["http_task", "torrent"] {
                    if has_table(&conn, table)? {
                        tables_present += 1;
                        absent_everywhere &= !gid_row_exists(&conn, table, &gid)?;
                    }
                }
                if tables_present > 0 && absent_everywhere {
                    stale_imported.push(key.clone());
                    None
                } else {
                    Some(gid)
                }
            }
            None => None,
        };
        imported.insert(key.clone(), value);
    }
    let occupied_http = if user_version >= schema::LATEST_VERSION {
        occupied_http_rows(&conn)?
    } else {
        Vec::new()
    };
    Ok(ImportTargetSnapshot {
        user_version,
        latest_supported: schema::LATEST_VERSION,
        fork_shaped,
        imported,
        stale_imported,
        occupied_http,
    })
}

/// Scan for http_task rows' `origin_fork_key` (the read face of the
/// row-key criterion). A constant LIKE prefilter (static pattern, no
/// path-wildcard escaping); config_json parsing and key comparison are
/// settled precisely on the Rust side; a row present = criterion alive
/// (no dead form). Same-key multi-row semantics (theoretically old
/// database leftovers): `ORDER BY gid` + first wins, deterministically
/// taking the smallest gid; rows with invalid config_json / no key are
/// skipped (conservative — that row yields no hit; the kv fallback stays
/// usable).
fn origin_fork_key_rows(conn: &Connection) -> Result<Vec<(String, String)>, StoreError> {
    const MARKER_LIKE: &str = "%\"origin_fork_key\"%";
    let mut stmt = conn.prepare(
        "SELECT gid, config_json FROM http_task
         WHERE config_json LIKE ?1 ORDER BY gid",
    )?;
    let rows = stmt.query_map([MARKER_LIKE], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (gid, config_json) = row.map_err(StoreError::from)?;
        let key = serde_json::from_str::<serde_json::Value>(&config_json)
            .ok()
            .and_then(|v| {
                v.get("origin_fork_key")
                    .and_then(|k| k.as_str())
                    .map(String::from)
            });
        if let Some(key) = key {
            out.push((key, gid));
        }
    }
    Ok(out)
}

/// gid row liveness probe (half of the dedup liveness check; table names
/// are internal constant literals, no injection surface).
fn gid_row_exists(conn: &Connection, table: &str, gid: &str) -> Result<bool, StoreError> {
    let sql = format!("SELECT 1 FROM {table} WHERE gid = ?1");
    conn.query_row(&sql, [gid], |_| Ok(()))
        .optional()
        .map(|x| x.is_some())
        .map_err(StoreError::from)
}

/// Read-only connection to the import target (shared by the dry-run
/// snapshot/probe and backup validation): `SQLITE_OPEN_READ_ONLY` makes
/// sqlite itself reject every write (not just "we don't write"). With
/// sidecars absent (cleanly closed — the offline precondition of the
/// import precheck itself), an `immutable=1` URI is used: a plain
/// read-only open would still *create* `-shm`/`-wal`, a read-only
/// connection never cleans them up, and leftovers after a dry run would
/// wedge the next real import's offline probe; immutable takes no
/// locks, leaves no filesystem traces, and reads the main file only
/// (WAL not on disk = all data in the main file, an exact read face).
/// With sidecars present (live/unclean exit), a plain read-only open
/// reads a consistent WAL view via shm (creating no sidecars).
fn open_import_target_readonly(path: &Path) -> Result<Connection, StoreError> {
    // The sqlite open point converts too (once at the entry; the sidecar
    // probe and the URI form share the conversion — the verbatim prefix
    // is percent-encoded into the URI; identity on non-Windows).
    let fs_path = taiji_io::winpath::to_fs_path(path);
    let conn = if wal_sidecars_present(&fs_path) {
        Connection::open_with_flags(&fs_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    } else {
        Connection::open_with_flags(
            Path::new(&immutable_uri(&fs_path)),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
    }
    .map_err(|e| classify_open_error(path, e))?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(StoreError::from)?;
    Ok(conn)
}

/// sqlite URI filename (`immutable=1`): the path is percent-encoded byte
/// by byte — everything outside unreserved (RFC 3986) plus `/` is
/// escaped, so `?`/`#` etc. cannot break URI semantics; non-UTF-8 paths
/// go through a lossy view (an extreme import-face corner, a deliberate
/// degradation).
fn immutable_uri(path: &Path) -> String {
    let s = path.to_string_lossy();
    let mut out = String::with_capacity(s.len() * 3 + 16);
    out.push_str("file:");
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push_str("?immutable=1");
    out
}

/// Table presence probe (sqlite_master; the target-side reuse of the
/// same criterion as the fork side's [`open_fork_readonly`]).
fn has_table(conn: &Connection, name: &str) -> Result<bool, StoreError> {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |_| Ok(()),
    )
    .optional()
    .map(|x| x.is_some())
    .map_err(StoreError::from)
}

/// Occupied active http_task (dir, out) set (the same state filter as
/// the startup recovery read face `HTTP_TASK_ACTIVE_STATES`; terminal
/// done/error rows are not in the path-conflict decision face).
fn occupied_http_rows(conn: &Connection) -> Result<Vec<(String, String)>, StoreError> {
    let placeholders = writer::HTTP_TASK_ACTIVE_STATES
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT dir, out FROM http_task WHERE state IN ({placeholders})");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params_from_iter(writer::HTTP_TASK_ACTIVE_STATES.iter()),
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::persist::schema::{
        LATEST_VERSION, SCHEMA_V1_TABLES, SCHEMA_V2_TABLES, SCHEMA_V3_TABLES,
    };
    use rusqlite::params;

    /// Total table count across all ledger versions (v1 baseline + per-migration additions).
    fn all_migrated_table_count() -> usize {
        SCHEMA_V1_TABLES.len() + SCHEMA_V2_TABLES.len() + SCHEMA_V3_TABLES.len()
    }

    /// Unique tmp database path (pid + nanosecond tag; no tempfile dependency).
    fn tmp_db(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "taiji-persist-{}-{}-{}.sqlite3",
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

    /// Test Result unwrap: panics with context on failure (lints forbid unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    fn tables_of(conn: &Connection) -> Vec<String> {
        let mut stmt = ok(
            conn.prepare("SELECT name FROM sqlite_master WHERE type='table'"),
            "prepare",
        );
        let rows = ok(
            stmt.query_map([], |r| r.get::<_, String>(0)),
            "query tables",
        );
        rows.filter_map(|r| r.ok()).collect()
    }

    fn user_version_of(conn: &Connection) -> i64 {
        ok(
            conn.query_row("PRAGMA user_version", [], |r| r.get(0)),
            "user_version",
        )
    }

    /// Main-file byte digest (the measurement face of the zero-write rejection assertions).
    fn sha256_of(path: &std::path::Path) -> String {
        use sha2::{Digest, Sha256};
        let bytes = ok(std::fs::read(path), "read db file");
        let mut h = Sha256::new();
        h.update(&bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// WAL sidecar (-wal/-shm) leftover check (clean shutdown/rejection paths must leave none).
    fn sidecars_present(path: &std::path::Path) -> [bool; 2] {
        [
            std::path::Path::new(&format!("{}-wal", path.display())).exists(),
            std::path::Path::new(&format!("{}-shm", path.display())).exists(),
        ]
    }

    #[test]
    fn fresh_db_migrates_to_latest_then_reopen_is_idempotent() {
        let path = tmp_db("fresh");
        // v0 -> latest ledger in one step (the test name follows the
        // "ledger is already v3" reality — the old v0_to_v1_... name no
        // longer matched the coverage).
        {
            let conn = ok(open_and_migrate(&path), "migrate fresh");
            assert_eq!(user_version_of(&conn), LATEST_VERSION);
            let tables = tables_of(&conn);
            for t in SCHEMA_V1_TABLES {
                assert!(tables.iter().any(|x| x == t), "missing table {t}");
            }
        }
        // Reopen: migrations skip; table creation is idempotent
        // (table set = v1 baseline + derived tables).
        {
            let conn = ok(open_and_migrate(&path), "reopen");
            assert_eq!(user_version_of(&conn), LATEST_VERSION);
            assert_eq!(tables_of(&conn).len(), all_migrated_table_count());
        }
        // WAL persists in the file header (still wal after reopen).
        {
            let conn = ok(Connection::open(&path), "raw open");
            let mode: String = ok(
                conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)),
                "journal_mode",
            );
            assert_eq!(mode, "wal");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Concurrent open/migrate race regression: two connections open an
    /// unmigrated database; the winner holds the `BEGIN IMMEDIATE` write
    /// transaction and runs migrations, the loser concurrently runs
    /// `open_and_migrate` — with the old implementation (version read
    /// outside the transaction) the loser read v0 and its DDL hit
    /// "table already exists"/busy, failing the open; with the current
    /// implementation the version read shares the transaction, the loser
    /// is blocked by the write lock until the winner commits, reads v3,
    /// and its migration loop is empty — both succeed (the open face of
    /// the single-writer semantics).
    #[test]
    fn concurrent_open_of_unmigrated_db_serializes_and_both_succeed() {
        let path = tmp_db("concurrent-open");
        // Winner: IMMEDIATE write transaction held; migration DDL + ledger advance *uncommitted*.
        let mut winner = ok(Connection::open(&path), "winner open");
        ok(
            winner.busy_timeout(std::time::Duration::from_millis(5000)),
            "winner busy timeout",
        );
        ok(
            winner.pragma_update(None, "journal_mode", "WAL"),
            "winner wal",
        );
        let wtx = ok(
            winner.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
            "winner tx",
        );
        for migration in schema::MIGRATIONS {
            for sql in migration.sqls {
                ok(wtx.execute_batch(sql), "winner ddl");
            }
            ok(
                wtx.pragma_update(None, "user_version", migration.version),
                "winner ledger",
            );
        }
        // Loser concurrent open: the real interleaving = the loser passes
        // the PRAGMA face while the winner is uncommitted, then sticks on
        // the IMMEDIATE write lock.
        let loser_path = path.clone();
        let loser = std::thread::spawn(move || open_and_migrate(&loser_path));
        std::thread::sleep(std::time::Duration::from_millis(200));
        ok(wtx.commit(), "winner commit");
        let joined = loser.join();
        let loser_conn = ok(
            ok(
                joined.map_err(|e| format!("loser thread panicked: {e:?}")),
                "loser join",
            ),
            "loser open_and_migrate",
        );
        assert_eq!(
            user_version_of(&loser_conn),
            LATEST_VERSION,
            "the loser must read the winner's committed version inside its transaction"
        );
        assert_eq!(
            tables_of(&loser_conn).len(),
            all_migrated_table_count(),
            "the loser must not re-execute DDL (table collision)"
        );
        // Winner connection reread: database state consistent.
        drop(winner);
        {
            let conn = ok(open_and_migrate(&path), "reopen after race");
            assert_eq!(user_version_of(&conn), LATEST_VERSION);
            assert_eq!(tables_of(&conn).len(), all_migrated_table_count());
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn interrupted_migration_rolls_back_then_replays() {
        let path = tmp_db("interrupted");
        // In-process simulation of a mid-way kill: open a transaction on
        // a v0 database, run partial DDL, drop the connection without
        // committing — the uncommitted transaction rolls back on close
        // (equivalent to a kill followed by WAL rollback).
        {
            let mut conn = ok(Connection::open(&path), "open raw");
            let tx = ok(conn.transaction(), "begin tx");
            for sql in &schema::MIGRATIONS[0].sqls[..2] {
                ok(tx.execute_batch(sql), "partial ddl");
            }
            drop(tx);
            drop(conn); // simulate kill: no commit.
        }
        {
            let conn = ok(Connection::open(&path), "reopen raw");
            assert_eq!(user_version_of(&conn), 0, "user_version must not advance");
            let tables = tables_of(&conn);
            for t in SCHEMA_V1_TABLES {
                assert!(
                    !tables.iter().any(|x| x == t),
                    "table {t} must be rolled back"
                );
            }
        }
        // After reopen, migrations replay fully: all version tables
        // created (v1 baseline + derived tables).
        {
            let conn = ok(open_and_migrate(&path), "replay migration");
            assert_eq!(user_version_of(&conn), LATEST_VERSION);
            assert_eq!(tables_of(&conn).len(), all_migrated_table_count());
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_database_file_reports_error_not_panic() {
        let path = tmp_db("corrupt");
        ok(
            std::fs::write(
                &path,
                b"this is definitely not a sqlite database file at all!!",
            ),
            "seed garbage",
        );
        match open_and_migrate(&path) {
            Err(StoreError::CorruptDatabase { path: p, .. }) => {
                assert!(p.contains("corrupt"), "error must carry path: {p}");
            }
            other => panic!("expected CorruptDatabase, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn newer_user_version_is_rejected() {
        let path = tmp_db("newer");
        {
            let conn = ok(open_and_migrate(&path), "migrate");
            ok(
                conn.pragma_update(None, "user_version", LATEST_VERSION + 1),
                "bump version",
            );
        }
        match open_and_migrate(&path) {
            Err(StoreError::MigrationVersionMismatch { db, supported }) => {
                assert_eq!(db, LATEST_VERSION + 1);
                assert_eq!(supported, LATEST_VERSION);
            }
            other => panic!("expected MigrationVersionMismatch, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Pre-Phase-B old database (0.1.x shape, user_version=2) builder:
    /// replay the ledger's first two migrations, pin the version, insert
    /// legacy rows as lossless-upgrade samples — all columns non-default
    /// (including the nullable metadata/attr/v1_offset/error_* columns;
    /// earlier seeds left most columns default, which upgrade checks
    /// missed).
    fn legacy_v2_db(path: &std::path::Path) {
        let conn = ok(Connection::open(path), "open raw");
        for migration in &schema::MIGRATIONS[..2] {
            for sql in migration.sqls {
                ok(conn.execute_batch(sql), "legacy ddl");
            }
        }
        ok(
            conn.pragma_update(None, "user_version", 2),
            "pin user_version=2",
        );
        ok(
            conn.execute(
                "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                     v1_infohash, v2_infohash, is_private, metadata, error_code, error_msg,
                     created_at, updated_at)
                 VALUES ('8000000000000007', 'legacy.bin', 'seeding', 7, '/dl/legacy', '{\"k\":1}', 'v2',
                     ?1, ?2, 1, ?3, 42, 'legacy error', 111, 222)",
                params![
                    vec![0xABu8; 20], // v1_infohash (20-byte SHA-1 shape)
                    vec![0xCDu8; 32], // v2_infohash
                    vec![0x5Au8; 48], // metadata (raw .torrent bytes)
                ],
            ),
            "legacy torrent",
        );
        ok(
            conn.execute(
                "INSERT INTO torrent_file (gid, file_index, path, length, attr, pieces_root,
                     piece_layer, v1_offset, selected, priority)
                 VALUES ('8000000000000007', 0, 'legacy/inner.bin', 49152, 'p', ?1, ?2, 16384, 0, 5)",
                params![vec![0x11u8; 32], vec![0x22u8; 96]],
            ),
            "legacy file",
        );
        ok(
            conn.execute(
                "INSERT INTO torrent_progress (gid, piece_length, v1_bitfield, v2_file_bits,
                     upload_at_startup, downloaded_total, uploaded_total, active_time_s,
                     seed_time_s, digest, updated_at)
                 VALUES ('8000000000000007', 16384, ?1, ?2, 3, 49152, 7, 95, 60, ?3, 333)",
                params![vec![0xFEu8; 2], vec![0x77u8; 40], vec![0x33u8; 32]],
            ),
            "legacy progress",
        );
        ok(
            conn.execute(
                "INSERT INTO recovered_layer (gid, file_index, piece_length, file_length,
                     pieces_root, layer, updated_at)
                 VALUES ('8000000000000007', 0, 16384, 49152, ?1, ?2, 444)",
                params![vec![0x11u8; 32], vec![0x44u8; 96]],
            ),
            "legacy recovered layer",
        );
    }

    /// *Full-column* read-back of the legacy sample rows (whole-row
    /// comparison across the upgrade; earlier checks sampled only 3-4
    /// columns over mostly-default seeds, missing the nullable
    /// metadata/attr/v1_offset/error_* faces). Expected values = the
    /// [`legacy_v2_db`] seeds column by column. The torrent row has 14
    /// columns, past Rust's tuple trait impl limit (12) -> a test-local
    /// struct carries them.
    #[derive(Debug, PartialEq)]
    struct LegacyTorrentFullRow {
        name: String,
        state: String,
        dir: String,
        queue_pos: i64,
        config_json: String,
        kind: String,
        v1_infohash: Vec<u8>,
        v2_infohash: Vec<u8>,
        is_private: i64,
        metadata: Vec<u8>,
        error_code: i64,
        error_msg: Option<String>,
        created_at: i64,
        updated_at: i64,
    }

    fn legacy_torrent_full_row(conn: &Connection) -> LegacyTorrentFullRow {
        ok(
            conn.query_row(
                "SELECT name, state, dir, queue_pos, config_json, kind, v1_infohash,
                        v2_infohash, is_private, metadata, error_code, error_msg,
                        created_at, updated_at
                 FROM torrent WHERE gid = '8000000000000007'",
                [],
                |r| {
                    Ok(LegacyTorrentFullRow {
                        name: r.get(0)?,
                        state: r.get(1)?,
                        dir: r.get(2)?,
                        queue_pos: r.get(3)?,
                        config_json: r.get(4)?,
                        kind: r.get(5)?,
                        v1_infohash: r.get(6)?,
                        v2_infohash: r.get(7)?,
                        is_private: r.get(8)?,
                        metadata: r.get(9)?,
                        error_code: r.get(10)?,
                        error_msg: r.get(11)?,
                        created_at: r.get(12)?,
                        updated_at: r.get(13)?,
                    })
                },
            ),
            "legacy torrent full row",
        )
    }

    #[derive(Debug, PartialEq)]
    struct LegacyFileFullRow {
        length: i64,
        path: String,
        attr: Option<String>,
        pieces_root: Vec<u8>,
        piece_layer: Vec<u8>,
        v1_offset: Option<i64>,
        selected: i64,
        priority: i64,
    }

    fn legacy_file_full_row(conn: &Connection) -> LegacyFileFullRow {
        ok(
            conn.query_row(
                "SELECT length, path, attr, pieces_root, piece_layer, v1_offset, selected,
                        priority
                 FROM torrent_file
                 WHERE gid = '8000000000000007' AND file_index = 0",
                [],
                |r| {
                    Ok(LegacyFileFullRow {
                        length: r.get(0)?,
                        path: r.get(1)?,
                        attr: r.get(2)?,
                        pieces_root: r.get(3)?,
                        piece_layer: r.get(4)?,
                        v1_offset: r.get(5)?,
                        selected: r.get(6)?,
                        priority: r.get(7)?,
                    })
                },
            ),
            "legacy file full row",
        )
    }

    #[derive(Debug, PartialEq)]
    struct LegacyProgressFullRow {
        piece_length: i64,
        v1_bitfield: Vec<u8>,
        v2_file_bits: Vec<u8>,
        upload_at_startup: i64,
        downloaded_total: i64,
        uploaded_total: i64,
        active_time_s: i64,
        seed_time_s: i64,
        digest: Vec<u8>,
        updated_at: i64,
    }

    fn legacy_progress_full_row(conn: &Connection) -> LegacyProgressFullRow {
        ok(
            conn.query_row(
                "SELECT piece_length, v1_bitfield, v2_file_bits, upload_at_startup,
                        downloaded_total, uploaded_total, active_time_s, seed_time_s,
                        digest, updated_at
                 FROM torrent_progress WHERE gid = '8000000000000007'",
                [],
                |r| {
                    Ok(LegacyProgressFullRow {
                        piece_length: r.get(0)?,
                        v1_bitfield: r.get(1)?,
                        v2_file_bits: r.get(2)?,
                        upload_at_startup: r.get(3)?,
                        downloaded_total: r.get(4)?,
                        uploaded_total: r.get(5)?,
                        active_time_s: r.get(6)?,
                        seed_time_s: r.get(7)?,
                        digest: r.get(8)?,
                        updated_at: r.get(9)?,
                    })
                },
            ),
            "legacy progress full row",
        )
    }

    fn legacy_layer_full_row(conn: &Connection) -> (i64, i64, Vec<u8>, Vec<u8>, i64) {
        ok(
            conn.query_row(
                "SELECT piece_length, file_length, pieces_root, layer, updated_at
                 FROM recovered_layer
                 WHERE gid = '8000000000000007' AND file_index = 0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            ),
            "legacy layer full row",
        )
    }

    /// Lossless-upgrade check: all four legacy tables' full columns equal
    /// the seeds (the upgrade is pure DDL, zero data-face changes).
    fn assert_legacy_rows_intact(conn: &Connection) {
        assert_eq!(
            legacy_torrent_full_row(conn),
            LegacyTorrentFullRow {
                name: "legacy.bin".into(),
                state: "seeding".into(),
                dir: "/dl/legacy".into(),
                queue_pos: 7,
                config_json: "{\"k\":1}".into(),
                kind: "v2".into(),
                v1_infohash: vec![0xABu8; 20],
                v2_infohash: vec![0xCDu8; 32],
                is_private: 1,
                metadata: vec![0x5Au8; 48],
                error_code: 42,
                error_msg: Some("legacy error".into()),
                created_at: 111,
                updated_at: 222,
            },
            "torrent: all columns lossless"
        );
        assert_eq!(
            legacy_file_full_row(conn),
            LegacyFileFullRow {
                length: 49152,
                path: "legacy/inner.bin".into(),
                attr: Some("p".into()),
                pieces_root: vec![0x11u8; 32],
                piece_layer: vec![0x22u8; 96],
                v1_offset: Some(16384),
                selected: 0,
                priority: 5,
            },
            "torrent_file: all columns lossless"
        );
        assert_eq!(
            legacy_progress_full_row(conn),
            LegacyProgressFullRow {
                piece_length: 16384,
                v1_bitfield: vec![0xFEu8; 2],
                v2_file_bits: vec![0x77u8; 40],
                upload_at_startup: 3,
                downloaded_total: 49152,
                uploaded_total: 7,
                active_time_s: 95,
                seed_time_s: 60,
                digest: vec![0x33u8; 32],
                updated_at: 333,
            },
            "torrent_progress: all columns lossless"
        );
        assert_eq!(
            legacy_layer_full_row(conn),
            (16384, 49152, vec![0x11u8; 32], vec![0x44u8; 96], 444),
            "recovered_layer: all columns lossless"
        );
    }

    /// A pre-media-model old database (v2) upgrades to v3 — legacy data
    /// intact in all columns (readable and writable), the new media
    /// tables
    /// created and empty (migrations only create tables), user_version
    /// advanced, reopen idempotent.
    #[test]
    fn pre_phase_b_db_upgrades_to_v3_preserving_legacy_rows() {
        let path = tmp_db("v2-to-v3");
        legacy_v2_db(&path);
        {
            let conn = ok(open_and_migrate(&path), "migrate v2->v3");
            assert_eq!(
                user_version_of(&conn),
                LATEST_VERSION,
                "ledger advanced to v3"
            );
            assert_eq!(
                LATEST_VERSION, 3,
                "the media DDL settles the ledger at v3 (v2 is taken by the existing release)"
            );
            // Legacy data undamaged: whole-row, full-column comparison across the four tables.
            assert_legacy_rows_intact(&conn);
            // Legacy rows writable (read-write lock: constraints did
            // not degrade with the migration).
            ok(
                conn.execute(
                    "UPDATE torrent_file SET selected = 0 WHERE gid = '8000000000000007'",
                    [],
                ),
                "legacy row writable",
            );
            // Media-model tables present and empty.
            for table in SCHEMA_V3_TABLES {
                let n: i64 = ok(
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)),
                    "new-table count",
                );
                assert_eq!(n, 0, "{table} must be empty (migrations create no data)");
            }
        }
        // Reopen idempotent: all migrations skip, the table set does not double.
        {
            let conn = ok(open_and_migrate(&path), "reopen");
            assert_eq!(user_version_of(&conn), LATEST_VERSION);
            assert_eq!(tables_of(&conn).len(), all_migrated_table_count());
        }
        let _ = std::fs::remove_file(&path);
    }

    /// sqlite_master output compared verbatim: a fresh database vs an
    /// upgraded one (v2->v3) produce *exactly the same* table set and DDL
    /// text — the upgrade path must not drift from the fresh-create
    /// schema.
    #[test]
    fn fresh_and_upgraded_dbs_produce_identical_sqlite_master() {
        let fresh = tmp_db("ddl-fresh");
        let upgraded = tmp_db("ddl-upgraded");
        legacy_v2_db(&upgraded);
        let fresh_conn = ok(open_and_migrate(&fresh), "fresh open");
        let upgraded_conn = ok(open_and_migrate(&upgraded), "upgraded open");
        assert_eq!(
            user_version_of(&fresh_conn),
            user_version_of(&upgraded_conn)
        );
        let master_of = |conn: &Connection| -> Vec<(String, String)> {
            let mut stmt = ok(
                conn.prepare(
                    "SELECT name, sql FROM sqlite_master WHERE type = 'table'
                     ORDER BY name",
                ),
                "prepare master",
            );
            let rows = ok(
                stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))),
                "query master",
            );
            rows.filter_map(|r| r.ok()).collect()
        };
        assert_eq!(
            master_of(&fresh_conn),
            master_of(&upgraded_conn),
            "sqlite_master output must be verbatim identical between fresh-create and upgrade"
        );
        let _ = std::fs::remove_file(&fresh);
        let _ = std::fs::remove_file(&upgraded);
    }

    /// `PRAGMA secure_delete=ON` read-back on the store's open face
    /// (the at-rest posture): every connection opened through
    /// `open_and_migrate` (the single-writer PersistWriter connection —
    /// the only face that ever deletes a cookie row) carries the
    /// setting; it survives a reopen (a per-connection setting applied
    /// at every open, not a file property).
    #[test]
    fn open_face_applies_secure_delete() {
        let path = tmp_db("secure-delete");
        {
            let conn = ok(open_and_migrate(&path), "open");
            let sd: i64 = ok(
                conn.query_row("PRAGMA secure_delete", [], |r| r.get(0)),
                "read secure_delete",
            );
            assert_eq!(sd, 1, "secure_delete must be ON (at-rest posture)");
            // The three pre-existing PRAGMAs keep their values (zero change).
            let jm: String = ok(
                conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)),
                "journal_mode",
            );
            let sync: i64 = ok(
                conn.query_row("PRAGMA synchronous", [], |r| r.get(0)),
                "synchronous",
            );
            let fk: i64 = ok(
                conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)),
                "foreign_keys",
            );
            assert_eq!((jm.as_str(), sync, fk), ("wal", 1, 1));
        }
        // Reopen: the setting re-applies (per-connection).
        {
            let conn = ok(open_and_migrate(&path), "reopen");
            let sd: i64 = ok(
                conn.query_row("PRAGMA secure_delete", [], |r| r.get(0)),
                "reread secure_delete",
            );
            assert_eq!(sd, 1, "secure_delete stays ON after reopen");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// v1->v3 direct path: an old database that skipped the v2 migration
    /// (pre-0.1.0) upgrades straight to v3 — the migration loop replays
    /// the ledger interval, missing versions do not mean missing tables,
    /// legacy data intact.
    #[test]
    fn v1_db_upgrades_directly_to_v3() {
        let path = tmp_db("v1-to-v3");
        {
            let conn = ok(Connection::open(&path), "open raw");
            for sql in schema::MIGRATIONS[0].sqls {
                ok(conn.execute_batch(sql), "v1 ddl");
            }
            ok(conn.pragma_update(None, "user_version", 1), "pin v1");
            ok(
                conn.execute(
                    "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                         created_at, updated_at)
                     VALUES ('8000000000000008', 'old.bin', 'paused', 1, '/dl', '{}', 'v1', 5, 6)",
                    [],
                ),
                "v1 row",
            );
        }
        {
            let conn = ok(open_and_migrate(&path), "migrate v1->v3");
            assert_eq!(user_version_of(&conn), LATEST_VERSION);
            assert_eq!(tables_of(&conn).len(), all_migrated_table_count());
            let name: String = ok(
                conn.query_row(
                    "SELECT name FROM torrent WHERE gid = '8000000000000008'",
                    [],
                    |r| r.get(0),
                ),
                "v1 row readable",
            );
            assert_eq!(name, "old.bin");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Rollback semantics: an old binary (0.1.x, supported ceiling =
    /// ledger v2) refuses a v3 (media-model) database, and the refusal happens
    /// before any migration DDL / ledger write (the database is neither
    /// downgraded nor polluted). Open-phase PRAGMAs are connection-level
    /// configuration (journal_mode writes nothing on an already-migrated
    /// database, busy_timeout is set first); `BEGIN IMMEDIATE` only takes
    /// the write lock and writes no bytes — verified by a before/after
    /// sha256 of the main file plus no -wal/-shm leftovers. The old
    /// binary's open path is isomorphic to
    /// `open_and_migrate_up_to(_, 2)` (see the function doc).
    #[test]
    fn phase_a_binary_rejects_phase_b_db_unchanged() {
        let path = tmp_db("rollback-reject");
        {
            let conn = ok(open_and_migrate(&path), "build v3 db");
            assert_eq!(user_version_of(&conn), 3);
        }
        // After clean shutdown there are no sidecars; the main-file baseline is in place.
        assert_eq!(
            sidecars_present(&path),
            [false, false],
            "no -wal/-shm after shutdown"
        );
        let before = sha256_of(&path);
        // Old-binary view: supported = 2 -> the v3 database is refused.
        match open_and_migrate_up_to(&path, 2) {
            Err(StoreError::MigrationVersionMismatch { db, supported }) => {
                assert_eq!(
                    (db, supported),
                    (3, 2),
                    "0.1.x supported ceiling = v2, new db = v3"
                );
            }
            Ok(_) => panic!("old binary must not open a v3 database"),
            Err(other) => panic!("expected MigrationVersionMismatch, got {other:?}"),
        }
        // Rejection path: zero written bytes, zero leftovers.
        assert_eq!(
            sidecars_present(&path),
            [false, false],
            "no -wal/-shm leftovers after refusal"
        );
        let after = sha256_of(&path);
        assert_eq!(
            before, after,
            "the refusal path must not touch any byte of the main file"
        );
        // After refusal the database stays v3 as-is (not advanced, not
        // reverted; reopen still works).
        {
            let conn = ok(open_and_migrate(&path), "reopen after reject");
            assert_eq!(user_version_of(&conn), 3);
            assert_eq!(tables_of(&conn).len(), all_migrated_table_count());
        }
        // Reverse sanity: the old binary opens a v2 database fine (the
        // rollback target state can open).
        let legacy = tmp_db("rollback-legacy");
        legacy_v2_db(&legacy);
        {
            let conn = ok(open_and_migrate_up_to(&legacy, 2), "old binary opens v2 db");
            assert_eq!(user_version_of(&conn), 2);
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&legacy);
    }

    /// Fresh-create side: a v0 database builds all version tables in one
    /// step and the v3 DDL contract holds on the spot (media CHECK
    /// value domain + FK cascade).
    #[test]
    fn fresh_db_enforces_phase_b_ddl_contract() {
        let path = tmp_db("v3-ddl");
        let conn = ok(open_and_migrate(&path), "migrate fresh");
        assert_eq!(user_version_of(&conn), LATEST_VERSION);
        assert_eq!(tables_of(&conn).len(), all_migrated_table_count());
        // media_task: the kind CHECK rejects out-of-domain values.
        ok(
            conn.execute(
                "INSERT INTO media_task (gid, kind, manifest_url, state, staging_dir,
                     output_path, manifest_norm_digest, config_json, created_at, updated_at)
                 VALUES ('8000000000000100', 'hls', 'https://x/master.m3u8', 'queued',
                     '/dl/.taiji-b/x', '/dl/out.mp4', ?1, '{}', 1, 1)",
                params![vec![0x55u8; 32]],
            ),
            "media_task hls",
        );
        assert!(
            conn.execute(
                "INSERT INTO media_task (gid, kind, manifest_url, state, staging_dir,
                     output_path, manifest_norm_digest, config_json, created_at, updated_at)
                 VALUES ('8000000000000101', 'smooth', 'https://x/', 'queued', '/d', '/o',
                     ?1, '{}', 1, 1)",
                params![vec![0x55u8; 32]],
            )
            .is_err(),
            "the kind CHECK must reject out-of-domain values"
        );
        // Child-table FK cascade: track/segment/key rows cleared with media_task.
        ok(
            conn.execute(
                "INSERT INTO media_track (gid, track_idx, kind, playlist_uri, local_name)
                 VALUES ('8000000000000100', 0, 'video', 'https://x/v.m3u8', 'archive-v.ts')",
                [],
            ),
            "media_track",
        );
        ok(
            conn.execute(
                "INSERT INTO media_segment (gid, track_idx, seg_idx, media_sequence, uri,
                     seg_len, duration_ms)
                 VALUES ('8000000000000100', 0, 0, 1, 'https://x/seg0.ts', 65536, 4000)",
                [],
            ),
            "media_segment",
        );
        ok(
            conn.execute(
                "INSERT INTO media_key (gid, key_id, uri, iv, key)
                 VALUES ('8000000000000100', 'k0', 'https://x/key', ?1, ?2)",
                params![vec![0x00u8; 16], vec![0xEEu8; 16]],
            ),
            "media_key",
        );
        ok(
            conn.execute("DELETE FROM media_task WHERE gid = '8000000000000100'", []),
            "delete media_task",
        );
        for table in ["media_track", "media_segment", "media_key"] {
            let n: i64 = ok(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)),
                "cascade count",
            );
            assert_eq!(n, 0, "{table} must be cascade-cleared with media_task");
        }
        // http_task: writable on a fresh database (frozen column-set DDL smoke).
        ok(
            conn.execute(
                "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                     config_json, block_size, total_done, created_at, updated_at)
                 VALUES ('8000000000000102', 'https://x/f.bin', 'https://cdn/x/f.bin',
                     'queued', 0, '/dl', 'f.bin', '{}', 4194304, 0, 1, 1)",
                [],
            ),
            "http_task smoke insert",
        );
        let _ = std::fs::remove_file(&path);
    }

    /// media_key UNIQUE(gid, key_id) conflict path: a second insert with
    /// the same key_id for the same task must be rejected; a different
    /// key_id / different gid passes.
    #[test]
    fn media_key_unique_conflict_is_rejected() {
        let path = tmp_db("media-key-unique");
        let conn = ok(open_and_migrate(&path), "migrate fresh");
        ok(
            conn.execute(
                "INSERT INTO media_task (gid, kind, manifest_url, state, staging_dir,
                     output_path, manifest_norm_digest, config_json, created_at, updated_at)
                 VALUES ('8000000000000103', 'hls', 'https://x/master.m3u8', 'queued',
                     '/dl/.taiji-b/x', '/dl/out.mp4', ?1, '{}', 1, 1)",
                params![vec![0x55u8; 32]],
            ),
            "media_task",
        );
        let insert_key = |conn: &Connection, gid: &str, key_id: &str| {
            conn.execute(
                "INSERT INTO media_key (gid, key_id, uri, iv, key) VALUES (?1, ?2, 'https://x/k', NULL, ?3)",
                params![gid, key_id, vec![0xEEu8; 16]],
            )
        };
        ok(insert_key(&conn, "8000000000000103", "k0"), "first key");
        assert!(
            insert_key(&conn, "8000000000000103", "k0").is_err(),
            "UNIQUE(gid, key_id) must reject a duplicate key_id"
        );
        ok(insert_key(&conn, "8000000000000103", "k1"), "second key id");
        // Cascade confirms the unique constraint is gid-scoped: the
        // same key_id on another task is legal.
        ok(
            conn.execute(
                "INSERT INTO media_task (gid, kind, manifest_url, state, staging_dir,
                     output_path, manifest_norm_digest, config_json, created_at, updated_at)
                 VALUES ('8000000000000104', 'hls', 'https://y/master.m3u8', 'queued',
                     '/dl/.taiji-b/y', '/dl/y.mp4', ?1, '{}', 1, 1)",
                params![vec![0x66u8; 32]],
            ),
            "media_task 2",
        );
        ok(
            insert_key(&conn, "8000000000000104", "k0"),
            "other gid same key id",
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Pre-import backup negative case (the "target offline" enforcement
    /// point): the target database is in WAL mode with a live local
    /// session (connection open -> `-wal`/`-shm` sidecars on disk) ->
    /// [`StoreError::TargetInUse`] refusal, and no torn `.v1.bak` may be
    /// produced; after a clean shutdown (last connection closed -> sqlite
    /// checkpoints and deletes the sidecars) the retry succeeds with a
    /// byte-identical snapshot; an existing backup is kept, never
    /// overwritten.
    #[test]
    fn backup_refuses_live_session_then_succeeds_after_clean_shutdown() {
        let path = tmp_db("bak-inuse");
        let bak_path = backup_path_for(&path);
        // WAL session state: the connection stays open (sidecars on
        // disk = the local taiji session has not stopped).
        let conn = ok(Connection::open(&path), "open target");
        ok(
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE t(x INTEGER);
                 INSERT INTO t VALUES (1);",
            ),
            "seed wal db",
        );
        assert!(
            wal_sidecars_present(&path),
            "-wal/-shm must be on disk while the session is alive (probe precondition)"
        );
        match backup_target_db(&path) {
            Err(StoreError::TargetInUse { .. }) => {}
            other => panic!("expected TargetInUse, got {other:?}"),
        }
        assert!(
            !bak_path.exists(),
            "the refusal path must not leave a partial backup (torn snapshot)"
        );
        // Clean shutdown: last connection closed -> sqlite checkpoints and deletes the sidecars.
        drop(conn);
        assert!(
            !wal_sidecars_present(&path),
            "sidecars must disappear after clean shutdown (sqlite close semantics)"
        );
        match backup_target_db(&path) {
            Ok(ImportBackup::Created(p)) => {
                assert_eq!(p, bak_path);
                assert_eq!(
                    ok(std::fs::read(&path), "read main"),
                    ok(std::fs::read(&bak_path), "read bak"),
                    "the snapshot is byte-identical after clean shutdown"
                );
            }
            other => panic!("expected Created after shutdown, got {other:?}"),
        }
        // Second import -> KeptExisting (overwriting would destroy the
        // rollback anchor, negative assertion): mutate the main database,
        // then import — the existing backup must byte-for-byte keep the
        // first-import snapshot, never displaced by the new one (a
        // byte-level non-overwrite assertion, stronger than sentinel
        // bytes).
        let first_snapshot = ok(std::fs::read(&bak_path), "read first snapshot");
        {
            let conn = ok(Connection::open(&path), "reopen target");
            ok(
                conn.execute("CREATE TABLE IF NOT EXISTS evolved(x)", []),
                "evolve db",
            );
        }
        match backup_target_db(&path) {
            Ok(ImportBackup::KeptExisting(p)) => {
                assert_eq!(&p, &bak_path);
                assert_eq!(
                    ok(std::fs::read(&bak_path), "read kept bak"),
                    first_snapshot,
                    "the existing backup must be preserved byte-for-byte (never overwritten)"
                );
            }
            other => panic!("expected KeptExisting, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&bak_path);
        let _ = std::fs::remove_file(std::path::PathBuf::from(format!("{}-wal", path.display())));
        let _ = std::fs::remove_file(std::path::PathBuf::from(format!("{}-shm", path.display())));
    }

    /// Torn-backup rejection: an existing `.v1.bak` that is corrupt
    /// (non-sqlite bytes / valid header + truncated body) -> explicit
    /// rejection (rather than keeping an unusable rollback anchor under
    /// the KeptExisting name), and the rejection path does not rewrite
    /// the existing backup's bytes.
    #[test]
    fn backup_rejects_torn_existing_backup() {
        let path = tmp_db("bak-torn");
        {
            let conn = ok(Connection::open(&path), "open target");
            ok(
                conn.execute_batch(
                    "PRAGMA journal_mode=WAL;
                     CREATE TABLE t(x INTEGER);
                     INSERT INTO t VALUES (1);",
                ),
                "seed target",
            );
        }
        let bak_path = backup_path_for(&path);
        // Torn shape 1: non-sqlite bytes (sentinel garbage).
        ok(
            std::fs::write(&bak_path, b"torn-not-a-sqlite-database-at-all"),
            "seed torn bak",
        );
        match backup_target_db(&path) {
            Err(StoreError::CorruptDatabase { path: p, .. }) => {
                assert!(
                    p.contains(".v1.bak"),
                    "the error must point at the backup file: {p}"
                );
            }
            other => panic!("expected CorruptDatabase for garbage bak, got {other:?}"),
        }
        assert_eq!(
            ok(std::fs::read(&bak_path), "read bak"),
            b"torn-not-a-sqlite-database-at-all",
            "the rejection path must not rewrite the existing backup's bytes"
        );
        // Torn shape 2: the typical interrupted-copy shape — valid sqlite header + truncated body.
        let full = ok(std::fs::read(&path), "read full db");
        ok(
            std::fs::write(&bak_path, &full[..full.len() / 2]),
            "truncate bak",
        );
        match backup_target_db(&path) {
            Err(StoreError::CorruptDatabase { path: p, .. }) => {
                assert!(p.contains(".v1.bak"), "{p}");
            }
            other => panic!("expected CorruptDatabase for truncated bak, got {other:?}"),
        }
        assert_eq!(
            ok(std::fs::read(&bak_path), "read truncated bak"),
            &full[..full.len() / 2],
            "the rejection path must not rewrite the existing backup's bytes"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&bak_path);
    }

    /// Backup creation atomicity: temp + fsync + atomic rename — no
    /// `.tmp` leftovers after success, and the backup under the anchor
    /// name passed the openability check (a torn copy can never reach
    /// the `.v1.bak` name).
    #[test]
    fn backup_creation_is_atomic_without_temp_litter() {
        let path = tmp_db("bak-atomic");
        {
            let conn = ok(Connection::open(&path), "open target");
            ok(
                conn.execute_batch(
                    "PRAGMA journal_mode=WAL;
                     CREATE TABLE t(x INTEGER);
                     INSERT INTO t VALUES (42);",
                ),
                "seed target",
            );
        }
        let bak_path = backup_path_for(&path);
        match backup_target_db(&path) {
            Ok(ImportBackup::Created(p)) => {
                assert_eq!(p, bak_path);
                // The backup under the anchor name is openable (the
                // check runs on the creation path).
                ok(
                    ensure_backup_readable(&p),
                    "created backup must be readable",
                );
                // No temp leftovers (temp naming = <anchor>.tmp-<pid>-<nanos>).
                let prefix = format!("{}.tmp", bak_path.display());
                let litter: Vec<String> = ok(
                    std::fs::read_dir(bak_path.parent().unwrap_or(std::path::Path::new("."))),
                    "read_dir",
                )
                .filter_map(|e| e.ok())
                .map(|e| e.path().display().to_string())
                .filter(|n| n.starts_with(&prefix))
                .collect();
                assert!(litter.is_empty(), "temp leftovers: {litter:?}");
                assert_eq!(
                    ok(std::fs::read(&path), "read main"),
                    ok(std::fs::read(&bak_path), "read bak"),
                    "the anchor-named backup is byte-identical to the source"
                );
            }
            other => panic!("expected Created, got {other:?}"),
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&bak_path);
    }

    /// Read-only snapshot of the import target (dry-run zero-write
    /// discipline + shape guard): (1) a cleanly closed WAL database
    /// (0.1.x shape) -> the snapshot is queryable with zero written
    /// bytes and no sidecars; (2) the fork shape (task/task_progress
    /// table set) is detectable; (3) a v3 target's occupancy set holds
    /// only active http_task rows.
    #[test]
    fn import_target_snapshot_is_readonly_and_shape_aware() {
        use crate::persist::schema::{LATEST_VERSION, SCHEMA_V3_TABLES};
        // (1) 0.1.x shape: WAL + session_kv + torrent + user_version=2,
        // cleanly closed. Two dedup marker states: referenced torrent row
        // present (alive) vs row missing (dead reference).
        let v2 = tmp_db("snap-v2");
        {
            let conn = ok(Connection::open(&v2), "open v2");
            ok(
                conn.execute_batch(
                    "PRAGMA journal_mode=WAL;
                     CREATE TABLE session_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                     CREATE TABLE torrent (
                       gid TEXT PRIMARY KEY, name TEXT NOT NULL, state TEXT NOT NULL,
                       queue_pos INTEGER NOT NULL, dir TEXT NOT NULL,
                       config_json TEXT NOT NULL, kind TEXT NOT NULL,
                       is_private INTEGER NOT NULL DEFAULT 0,
                       created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                     INSERT INTO session_kv VALUES ('imported_from:db:/f.sqlite3#42', '80000000000000aa');
                     INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                                          created_at, updated_at)
                       VALUES ('80000000000000aa', 't', 'paused', 0, '/dl', '{}', 'v2', 0, 0);
                     INSERT INTO session_kv VALUES ('imported_from:db:/f.sqlite3#dead', '80000000000000de');",
                ),
                "seed v2",
            );
            ok(conn.pragma_update(None, "user_version", 2), "pin v2");
        }
        assert_eq!(
            sidecars_present(&v2),
            [false, false],
            "clean shutdown leaves no sidecars"
        );
        let before = sha256_of(&v2);
        let keys = vec![
            "imported_from:db:/f.sqlite3#42".to_string(),
            "imported_from:db:/f.sqlite3#dead".to_string(),
            "absent-key".to_string(),
        ];
        let snap = ok(read_import_target_snapshot(&v2, &keys), "snapshot v2");
        assert_eq!(snap.user_version, 2);
        assert_eq!(snap.latest_supported, LATEST_VERSION);
        assert!(!snap.fork_shaped, "a 0.1.x database has no fork table set");
        assert_eq!(
            snap.imported.get("imported_from:db:/f.sqlite3#42"),
            Some(&Some("80000000000000aa".to_string())),
            "dedup keys read via the read-only connection (the referenced torrent row is alive)"
        );
        assert_eq!(
            snap.imported.get("imported_from:db:/f.sqlite3#dead"),
            Some(&None),
            "a dead back-reference = liveness check failed, treated as not-imported"
        );
        assert_eq!(
            snap.stale_imported,
            vec!["imported_from:db:/f.sqlite3#dead".to_string()],
            "dead keys go into stale_imported (noted on the report face)"
        );
        assert_eq!(snap.imported.get("absent-key"), Some(&None));
        assert!(
            snap.occupied_http.is_empty(),
            "no http_task rows possible on a v2 target (pre-v3 is BT-only) — empty set is exact"
        );
        assert_eq!(
            sidecars_present(&v2),
            [false, false],
            "the read-only snapshot leaves no sidecars"
        );
        assert_eq!(
            before,
            sha256_of(&v2),
            "the read-only snapshot writes zero bytes"
        );
        // (2) fork-shape probe (the guard against pointing a fork database at the import target).
        let fork = tmp_db("snap-fork");
        {
            let conn = ok(Connection::open(&fork), "open fork");
            ok(
                conn.execute_batch(
                    "CREATE TABLE task (gid TEXT);
                     CREATE TABLE task_progress (gid TEXT);",
                ),
                "seed fork tables",
            );
            ok(conn.pragma_update(None, "user_version", 1), "pin fork v1");
        }
        let snap = ok(read_import_target_snapshot(&fork, &[]), "snapshot fork");
        assert!(
            snap.fork_shaped,
            "task/task_progress present = the fork shape"
        );
        // (3) v3 target: the occupancy set holds only active rows
        // (terminal done is not in the decision face).
        let v3 = tmp_db("snap-v3");
        {
            let conn = ok(open_and_migrate(&v3), "migrate v3");
            ok(
                conn.execute(
                    "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                         config_json, block_size, total_done, created_at, updated_at)
                     VALUES ('80000000000000b1', 'http://a/x', '', 'downloading', 0, '/dl', 'x.bin',
                             '{}', 4096, 0, 1, 1)",
                    [],
                ),
                "seed active http row",
            );
            ok(
                conn.execute(
                    "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                         config_json, block_size, total_done, created_at, updated_at)
                     VALUES ('80000000000000b2', 'http://a/y', '', 'done', 1, '/dl', 'y.bin',
                             '{}', 4096, 0, 1, 1)",
                    [],
                ),
                "seed done http row",
            );
        }
        assert_eq!(sidecars_present(&v3), [false, false]);
        let snap = ok(read_import_target_snapshot(&v3, &[]), "snapshot v3");
        assert_eq!(snap.user_version, LATEST_VERSION);
        assert!(!snap.fork_shaped);
        assert_eq!(
            snap.occupied_http,
            vec![("/dl".to_string(), "x.bin".to_string())],
            "occupancy set = active rows' (dir, out); done rows are not in the path-conflict face"
        );
        for t in SCHEMA_V3_TABLES {
            // The fork-shape probe matches the exact names `task` /
            // `task_progress` (has_table), so the no-intersection
            // premise is over exact equality — the unified `task_cookie`
            // table may share the `task` prefix without
            // touching the probe.
            assert!(
                *t != "task" && *t != "task_progress",
                "the v3 table set cannot intersect the fork-shape probe (exact names): {t}"
            );
        }
        // (4) sidecars on disk (live-session branch): a plain read-only
        // open reads a consistent WAL view via shm (uncommitted writes
        // included), creating no sidecars.
        {
            let live = ok(Connection::open(&v2), "hold live session");
            ok(
                live.execute_batch(
                    "PRAGMA journal_mode=WAL; INSERT INTO session_kv VALUES ('live', '1');
                     INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind,
                                          created_at, updated_at)
                       VALUES ('1', 'live', 'paused', 0, '/dl', '{}', 'v2', 0, 0);",
                ),
                "write via live conn",
            );
            assert!(
                wal_sidecars_present(&v2),
                "the live session's sidecars are on disk"
            );
            let snap = ok(
                read_import_target_snapshot(&v2, &["live".to_string()]),
                "snapshot live",
            );
            assert_eq!(
                snap.imported.get("live"),
                Some(&Some("1".to_string())),
                "un-checkpointed WAL writes are visible (consistent view)"
            );
        }
        let _ = std::fs::remove_file(&v2);
        let _ = std::fs::remove_file(&fork);
        let _ = std::fs::remove_file(&v3);
    }

    /// Row-key criterion (the single source of the dedup rule): a hit =
    /// row present + key equal — http_task row config_json's
    /// `origin_fork_key` is the criterion proper, session_kv demoted to a
    /// reverse index. (1) Row hit (no kv marker) -> Some(gid); (2) row
    /// present but key differs / row absent -> not imported (positive
    /// and negative cases); (3) criterion row deleted -> the criterion
    /// disappears with the row (auto-expiry, no dead-marker form —
    /// stale_imported gets no row-key entries); (4) the kv reverse-index
    /// fallback does not resurrect: kv present but the referenced row
    /// dead -> treated as not-imported + stale_imported.
    #[test]
    fn snapshot_dedup_criterion_is_the_row_key() {
        let v3 = tmp_db("snap-rowkey");
        let key_a = "imported_from:db:/f.sqlite3#a1".to_string();
        let key_b = "imported_from:db:/f.sqlite3#b2".to_string();
        let key_c = "imported_from:db:/f.sqlite3#c3".to_string();
        {
            let conn = ok(open_and_migrate(&v3), "migrate v3");
            // Row A: origin_fork_key lands with the row (no kv
            // marker — the criterion proper is in the row).
            ok(
                conn.execute(
                    "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                         config_json, block_size, total_done, created_at, updated_at)
                     VALUES ('80000000000000c1', 'http://a/x', '', 'done', 0, '/dl', 'x.bin',
                             ?1, 4096, 0, 1, 1)",
                    rusqlite::params![format!(r#"{{"origin_fork_key":"{key_a}"}}"#)],
                ),
                "seed row a",
            );
            // Row B: an ordinary row without origin_fork_key (engine-created shape).
            ok(
                conn.execute(
                    "INSERT INTO http_task (gid, url, final_url, state, queue_pos, dir, out,
                         config_json, block_size, total_done, created_at, updated_at)
                     VALUES ('80000000000000c2', 'http://a/y', '', 'downloading', 1, '/dl',
                             'y.bin', '{}', 4096, 0, 1, 1)",
                    [],
                ),
                "seed row b",
            );
        }
        let keys = vec![key_a.clone(), key_b.clone(), key_c.clone()];
        let snap = ok(read_import_target_snapshot(&v3, &keys), "snapshot rowkey");
        assert_eq!(
            snap.imported.get(&key_a),
            Some(&Some("80000000000000c1".to_string())),
            "row present + key equal = hit (the criterion lives in the row, no kv marker needed)"
        );
        assert_eq!(
            snap.imported.get(&key_b),
            Some(&None),
            "row present but key differs = miss (negative case)"
        );
        assert_eq!(
            snap.imported.get(&key_c),
            Some(&None),
            "row absent = not imported (re-import allowed)"
        );
        assert!(
            snap.stale_imported.is_empty(),
            "the row criterion has no dead-marker form: a row-key hit produces no stale entries"
        );
        // (3) Criterion row deleted -> the criterion disappears with
        // the row (auto-expiry; no leftover marker to detect death).
        {
            let conn = ok(Connection::open(&v3), "reopen after delete");
            ok(
                conn.execute("DELETE FROM http_task WHERE gid = '80000000000000c1'", []),
                "delete criterion row",
            );
        }
        let snap = ok(read_import_target_snapshot(&v3, &keys), "snapshot deleted");
        assert_eq!(
            snap.imported.get(&key_a),
            Some(&None),
            "row absent = re-import allowed (criterion retires with the row; .bak restore alike)"
        );
        assert!(
            snap.stale_imported.is_empty(),
            "no dead-marker form: a row deletion leaves no dead keys"
        );
        // (4) The kv reverse-index fallback does not resurrect: kv
        // present but the referenced row dead -> treated as not-imported
        // + stale_imported (the tolerance half for the BT face and old
        // databases missing row keys).
        {
            let conn = ok(Connection::open(&v3), "reopen kv fallback");
            ok(
                conn.execute(
                    "INSERT INTO session_kv VALUES (?1, '80000000000000de')",
                    rusqlite::params![key_c],
                ),
                "seed reverse-index mark",
            );
        }
        let snap = ok(read_import_target_snapshot(&v3, &keys), "snapshot fallback");
        assert_eq!(
            snap.imported.get(&key_c),
            Some(&None),
            "a dead back-reference = treated as not-imported"
        );
        assert_eq!(
            snap.stale_imported,
            vec![key_c.clone()],
            "the stale_imported semantics do not regress"
        );
        let _ = std::fs::remove_file(&v3);
    }
}

#[cfg(all(test, unix))]
mod sec_36_tests {
    use super::*;

    /// The session database is 0600 on disk (with idempotent -wal/-shm sidecar re-application).
    #[test]
    fn db_file_created_with_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("taiji-sec36-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let db = dir.join("s.sqlite3");
        let conn = open_and_migrate_up_to(&db, schema::LATEST_VERSION)
            .unwrap_or_else(|e| panic!("open: {e}"));
        let mode = std::fs::metadata(&db)
            .unwrap_or_else(|e| panic!("stat: {e}"))
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the db file must be 0600, got {:o}",
            mode
        );
        drop(conn);
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_dir(&dir);
    }
}

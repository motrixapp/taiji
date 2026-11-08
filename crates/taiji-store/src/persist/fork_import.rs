//! Migration-import storage face: read-only access to the legacy fork's
//! sqlite database (a task + task_progress join) and binary parsing of
//! the legacy `.aria2` control files.
//!
//! # Read-only discipline (fork storage is never written)
//!
//! The fork DB is opened with `OpenFlags::SQLITE_OPEN_READ_ONLY`, so
//! sqlite itself rejects every write statement (not "we don't write" but
//! "writes cannot land"); this module also has no write path.
//!
//! The `.aria2` control file byte layout, the version policy, and the
//! HTTP/FTP variant tolerances are documented in docs/design/store.md.
//!
//! Upstream anchor mapping: docs/design/store.md

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::error::StoreError;

/// Current fork sqlite schema version (`Sqlite3Migrations.h`
/// `kCurrentSchemaVersion = 1`).
pub const FORK_SCHEMA_VERSION: i64 = 1;

/// Fork `task` row + `task_progress` join payload (the migration row
/// model); fields map one-to-one to the `Sqlite3Migrations.cc` columns.
/// The BitTorrent filter is `is_torrent = 1` with non-empty `info_hash`,
/// so `info_hash` is always non-empty here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkTaskRow {
    /// Fork GID (16 hex, top bit = 0 — kept out of the taiji GID namespace).
    pub gid: String,
    /// Fork task.state ("paused" | "waiting"; `Sqlite3SessionStore.cc`).
    pub state: String,
    /// input-file compatible text (`Sqlite3SessionStore.cc` write side;
    /// `SessionSerializer.cc` line format).
    pub serialized: String,
    pub following: Option<String>,
    pub followed_by: Option<String>,
    /// magnet / http(s) `.torrent` metadata URI (data source for readd
    /// priority 3, `RpcMethodImpl.cc`).
    pub metadata_uri: Option<String>,
    /// Local `.torrent` path (readd priority 2, `RpcMethodImpl.cc`).
    pub bt_local_path: Option<String>,
    pub queue_position: i64,
    /// SHA-1(info) (20 bytes; task_progress.info_hash).
    pub info_hash: Vec<u8>,
    /// task_progress row (LEFT JOIN; `None` = no progress row — a
    /// just-added BT task that has not saved progress yet).
    pub progress: Option<ForkProgress>,
}

/// `task_progress` business columns (`Sqlite3Migrations.cc`; digest /
/// updated_at are fork write-side metadata and stay unread;
/// `in_flight_blob` is discarded after reading).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkProgress {
    pub piece_length: i64,
    pub total_length: i64,
    pub upload_length: i64,
    /// v1 global piece bitmap (MSB-first; length must equal [`expected_bitfield_len`]).
    pub bitfield: Vec<u8>,
}

/// Open the fork sqlite database read-only and probe its schema.
///
/// - `SQLITE_OPEN_READ_ONLY`: sqlite rejects every write;
/// - `user_version != 1` or missing task/task_progress tables ->
///   [`StoreError::ForkSchema`] (unknown schemas are rejected
///   explicitly; this also catches this engine's own taiji.sqlite3
///   passed in by mistake — both are user_version 1 with different
///   table sets).
///
/// Disk IO: callers must run this inside `spawn_blocking`.
pub fn open_fork_readonly(path: &Path) -> Result<Connection, StoreError> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| classify_fork_open_error(path, e))?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(StoreError::from)?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| classify_fork_open_error(path, e))?;
    // Table-set probe: fork v1 always has meta/task/task_progress
    // (Sqlite3Migrations.cc). A missing table = not a fork v1 database
    // (including a taiji.sqlite3 passed by mistake).
    let has_table = |name: &str| -> Result<bool, StoreError> {
        conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![name],
            |_| Ok(()),
        )
        .optional()
        .map(|x| x.is_some())
        .map_err(StoreError::from)
    };
    let schema_ok =
        version == FORK_SCHEMA_VERSION && has_table("task")? && has_table("task_progress")?;
    if !schema_ok {
        return Err(StoreError::ForkSchema {
            path: path.display().to_string(),
            version,
        });
    }
    Ok(conn)
}

/// Fork-side task row count (report use: total rows vs BT candidates).
pub fn count_fork_tasks(conn: &Connection) -> Result<i64, StoreError> {
    conn.query_row("SELECT COUNT(*) FROM task", [], |r| r.get(0))
        .map_err(StoreError::from)
}

/// SQLITE_BUSY test (half of the fork lock probe classification: still
/// busy after the busy_timeout wait = the lock holder is long-lived).
fn is_busy_error(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(ffi, _)
            if ffi.code == rusqlite::ErrorCode::DatabaseBusy
    )
}

/// Pre-read probe of the fork database (storage half of import precheck
/// item 1): read-only open + a task-count read probe. SQLITE_BUSY at
/// either step (a legacy aria2-fork / Motrix process still holds the
/// write lock) -> [`StoreError::ForkLocked`] (refuse and ask the user to
/// exit the old app; no forcing through the lock). A schema mismatch
/// still yields [`StoreError::ForkSchema`]. Returns the total task row
/// count (the "all rows" base of the import report).
pub fn probe_fork_readonly(path: &Path) -> Result<i64, StoreError> {
    let conn = open_fork_readonly(path)?;
    let total = count_fork_tasks(&conn).map_err(|e| match &e {
        StoreError::Sqlite(re) if is_busy_error(re) => StoreError::ForkLocked {
            path: path.display().to_string(),
        },
        _ => e,
    })?;
    Ok(total)
}

// ---- fork liveness fd scan (precheck layers 2/3) ----
//
// Layer 1 (the SQLITE_BUSY lock probe, [`probe_fork_readonly`]) only
// catches the "currently writing" window; a fork running in WAL mode
// holds no lock most of the time. The strongest cooperation-free
// liveness evidence for a live fork is the process table: a process
// still holding open handles to the fork DB / `-wal` / `-shm` means the
// old app has not exited (a sqlite connection always holds these fds,
// regardless of writing).
//
// Three-state semantics (input to layer 3):
// - [`ForkLiveness::Clean`]: the scan face is usable and no holder was
// found — provable "fork is closed";
// - [`ForkLiveness::Alive`]: holder processes found (reported by pid) —
// import is refused and the override flag does not exempt this
// (letting a live process keep handles means writing into a live
// database, the same risk layer 1 refuses);
// - [`ForkLiveness::Uncertain`]: platform unsupported / tool missing
// (macOS without lsof) — "cannot prove" is handled as default-refuse;
// `--i-know-fork-is-closed` explicitly accepts responsibility (flag
// semantics belong to the core/CLI face). Never silently treated as
// clean.

/// One fd-scan hit: one process's open handle to the fork DB / `-wal` / `-shm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkFdHolder {
    /// Holding process pid (reported to the user when import is refused).
    pub pid: u32,
    /// Handle target path (raw scan-face fact, for report display).
    pub path: String,
}

/// Three-state result of the fork liveness fd scan (see the module comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkLiveness {
    /// Scan face usable and no holder found.
    Clean,
    /// Holder processes found for fork DB files (one entry per handle).
    Alive(Vec<ForkFdHolder>),
    /// Cannot prove (platform unsupported / lsof missing / procfs unreadable) — default refuse.
    Uncertain(String),
}

/// Full set of fork DB probe paths: the given spelling plus its
/// canonical spelling, each with `-wal`/`-shm` sidecars. The canonical
/// face is required on macOS — lsof reports `/tmp/...` under its
/// vnode's real name `/private/tmp/...`; Linux procfs readlink also
/// yields canonical paths.
fn fork_db_watch_paths(db: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut push_with_sidecars = |base: &Path| {
        for suffix in ["", "-wal", "-shm"] {
            let mut s = base.as_os_str().to_os_string();
            s.push(suffix);
            out.push(PathBuf::from(s));
        }
    };
    push_with_sidecars(db);
    if let Ok(canon) = std::fs::canonicalize(db)
        && canon != db
    {
        push_with_sidecars(&canon);
    }
    out
}

/// Handle-target vs candidate match (tolerates delete/truncation
/// markers): exact equality, or candidate prefix followed by a
/// space-led annotation (the Linux lsof/readlink ` (deleted)` form).
/// A prefix followed by anything but a space does not match —
/// `fork.sqlite3-journal` must not masquerade as `fork.sqlite3`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn fd_target_matches(name: &str, candidates: &[PathBuf]) -> bool {
    candidates.iter().any(|c| {
        let c = c.to_string_lossy();
        name == c.as_ref()
            || name
                .strip_prefix(c.as_ref())
                .is_some_and(|rest| rest.starts_with(' '))
    })
}

/// Parse `lsof -Fn` output (pure function): a process set starts at
/// `p<pid>`; `n<name>` is that process's open file name; other field
/// lines (`f`/`c`/...) are ignored.
#[cfg(target_os = "macos")]
fn parse_lsof_fn_output(output: &str, candidates: &[PathBuf]) -> Vec<ForkFdHolder> {
    let mut holders = Vec::new();
    let mut pid: Option<u32> = None;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            pid = rest.parse().ok();
        } else if let Some(name) = line.strip_prefix('n')
            && let Some(cur) = pid
            && fd_target_matches(name, candidates)
        {
            holders.push(ForkFdHolder {
                pid: cur,
                path: name.to_string(),
            });
        }
    }
    holders
}

/// macOS scan face: run `lsof -Fn -- <paths>` and judge from the child
/// output. Exit 0 and exit 1 are both decided from stdout (a missing
/// sidecar's "status error" also produces exit 1; hits are decided by
/// stdout); > 1 is a hard error -> Uncertain.
#[cfg(target_os = "macos")]
fn scan_fork_fds_platform(candidates: &[PathBuf]) -> ForkLiveness {
    // lsof stats paths to locate vnodes — missing files only add stderr noise; filter first.
    let existing: Vec<PathBuf> = candidates.iter().filter(|p| p.exists()).cloned().collect();
    if existing.is_empty() {
        return ForkLiveness::Uncertain(
            "no fork database file to scan on disk (unexpected after the lock \
             probe passed)"
                .to_string(),
        );
    }
    match std::process::Command::new("lsof")
        .args(["-Fn", "--"])
        .args(&existing)
        .output()
    {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ForkLiveness::Uncertain(
            "lsof is not available (not on PATH): cannot enumerate processes \
             holding fork database handles"
                .to_string(),
        ),
        Err(e) => ForkLiveness::Uncertain(format!("lsof spawn failed: {e}")),
        Ok(out) if out.status.success() || out.status.code() == Some(1) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut holders = parse_lsof_fn_output(&text, candidates);
            // Self-holder exclusion: this importer's own read-only probe
            // connection is not "fork alive" evidence.
            holders.retain(|h| h.pid != std::process::id());
            if holders.is_empty() {
                ForkLiveness::Clean
            } else {
                ForkLiveness::Alive(holders)
            }
        }
        Ok(out) => ForkLiveness::Uncertain(format!(
            "lsof exited with status {}: cannot enumerate fork fd holders",
            out.status.code().unwrap_or(-1)
        )),
    }
}

/// Linux scan face: full `/proc/<pid>/fd/*` readlink sweep (the procfs
/// equivalent of lsof, no external tool). An unreadable per-process fd
/// directory (another user's process) is skipped — the same visibility
/// as lsof (same-uid enumeration); only a fully unreadable procfs is
/// Uncertain.
#[cfg(target_os = "linux")]
fn scan_fork_fds_platform(candidates: &[PathBuf]) -> ForkLiveness {
    let mut holders = Vec::new();
    let entries = match std::fs::read_dir("/proc") {
        Ok(e) => e,
        Err(e) => {
            return ForkLiveness::Uncertain(format!(
                "procfs unavailable: {e}: cannot enumerate fork fd holders"
            ));
        }
    };
    let self_pid = std::process::id();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(text) = target.to_str() else {
                continue;
            };
            if fd_target_matches(text, candidates) {
                holders.push(ForkFdHolder {
                    pid,
                    path: text.to_string(),
                });
            }
        }
    }
    if holders.is_empty() {
        ForkLiveness::Clean
    } else {
        ForkLiveness::Alive(holders)
    }
}

/// Other-platform face (Windows and the remaining unix ports): no fd
/// enumeration mechanism is wired (only the lsof/procfs faces above
/// exist), so liveness cannot be proven — always
/// [`ForkLiveness::Uncertain`] (default refuse, never silently clean;
/// the caller decides on the layer-3 override flag). The
/// scan_reports_external_process_holding_the_fork_db test pins this
/// contract.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn scan_fork_fds_platform(_candidates: &[PathBuf]) -> ForkLiveness {
    ForkLiveness::Uncertain(
        "no fork fd enumeration mechanism on this platform: cannot enumerate \
         processes holding fork database handles"
            .to_string(),
    )
}

/// Fork liveness fd scan entry point (precheck layer 2): enumerate
/// processes holding open handles to the fork DB / `-wal` / `-shm`.
/// macOS runs the lsof child process, Linux walks procfs; other
/// platforms are always [`ForkLiveness::Uncertain`] (cannot prove =
/// default refuse, never silently clean). The caller (core/CLI face)
/// decides on the layer-3 override flag.
pub fn scan_fork_liveness(db_path: &Path) -> ForkLiveness {
    let candidates = fork_db_watch_paths(db_path);
    scan_fork_fds_platform(&candidates)
}

/// BT task join read face (filter `is_torrent = 1` with non-empty
/// `info_hash`; ordered by `queue_position` — the fork queue order
/// becomes the import order).
///
/// Non-BT rows (is_torrent = 0) and rows without info_hash are not in
/// this read face (the fork writes task rows for HTTP/FTP tasks too,
/// `Sqlite3SessionStore.cc`); BT tasks without a task_progress row (no
/// progress saved yet) are likewise absent from the join — nothing to
/// migrate, noted in the import report (the `count_fork_tasks`
/// difference is exactly the filtered row count).
pub fn load_fork_bt_tasks(conn: &Connection) -> Result<Vec<ForkTaskRow>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT t.gid, t.state, t.serialized, t.following, t.followed_by,
                    t.metadata_uri, t.bt_local_path, t.queue_position,
                    p.info_hash, p.piece_length, p.total_length, p.upload_length,
                    p.bitfield
             FROM task t
             JOIN task_progress p ON p.gid = t.gid
             WHERE p.is_torrent = 1 AND p.info_hash IS NOT NULL
             ORDER BY t.queue_position, t.gid",
        )
        .map_err(StoreError::from)?;
    let rows = stmt
        .query_map([], |r| {
            let info_hash: Vec<u8> = r.get(8)?;
            let piece_length: i64 = r.get(9)?;
            let total_length: i64 = r.get(10)?;
            let upload_length: i64 = r.get(11)?;
            let bitfield: Vec<u8> = r.get(12)?;
            Ok(ForkTaskRow {
                gid: r.get(0)?,
                state: r.get(1)?,
                serialized: r.get(2)?,
                following: r.get(3)?,
                followed_by: r.get(4)?,
                metadata_uri: r.get(5)?,
                bt_local_path: r.get(6)?,
                queue_position: r.get(7)?,
                info_hash,
                progress: Some(ForkProgress {
                    piece_length,
                    total_length,
                    upload_length,
                    bitfield,
                }),
            })
        })
        .map_err(StoreError::from)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

/// HTTP/FTP task row (the import read face: rows with
/// `is_torrent = 0` — URIs/options all live in `serialized`; the
/// progress payload feeds the piece-to-block bitmap mapping, see the
/// core-side import_bitmap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkHttpTaskRow {
    /// Fork GID (16 hex, top bit = 0; anchor of the dedup key and new-GID mapping tables).
    pub gid: String,
    /// Fork task.state ("paused" | "waiting"; `Sqlite3SessionStore.cc`).
    pub state: String,
    /// input-file compatible text (first line URI + ` key=value` option
    /// lines — reference `SessionSerializer.cc` write /
    /// `UriListParser.cc` read).
    pub serialized: String,
    pub queue_position: i64,
    /// task_progress classification: `None` = no progress row (progress
    /// never saved); `Some(false)` = HTTP/FTP row (the main import
    /// candidate body); `Some(true)` = torrent row without info_hash
    /// (a metadata-incomplete BT task — unrecoverable by either import
    /// face, noted in the report, never passed off as an HTTP task).
    pub is_torrent: Option<bool>,
    /// Progress row payload (piece bitmap + granularity/total length),
    /// carried only by `is_torrent = Some(false)` rows (the fork writes
    /// task_progress for HTTP tasks too — `Sqlite3BtProgressInfoFile.cc`
    /// save writes is_torrent=0 / info_hash=NULL for non-BT rows; the
    /// bitmap is an MSB-first piece bitmap of fixed length
    /// [`expected_bitfield_len`]). All other shapes are `None` (a BT
    /// row's progress belongs to the BT migration face; no progress row
    /// = nothing to map).
    pub progress: Option<ForkProgress>,
}

/// HTTP/FTP task join read face (complement of [`load_fork_bt_tasks`]:
/// the BT face takes `is_torrent = 1` with non-empty info_hash, this
/// face takes everything else — no progress row, `is_torrent = 0`, and
/// torrent rows without info_hash; `queue_position` order keeps the
/// fork queue order as the import order). The union of both faces
/// equals the `count_fork_tasks` total. Progress payloads are assembled
/// only for `is_torrent = 0` rows (nothing outside the BT face consumes
/// them).
pub fn load_fork_http_tasks(conn: &Connection) -> Result<Vec<ForkHttpTaskRow>, StoreError> {
    let mut stmt = conn
        .prepare(
            "SELECT t.gid, t.state, t.serialized, t.queue_position, p.is_torrent,
                    p.piece_length, p.total_length, p.bitfield
             FROM task t
             LEFT JOIN task_progress p ON p.gid = t.gid
             WHERE p.gid IS NULL OR p.is_torrent = 0 OR p.info_hash IS NULL
             ORDER BY t.queue_position, t.gid",
        )
        .map_err(StoreError::from)?;
    let rows = stmt
        .query_map([], |r| {
            let is_torrent: Option<i64> = r.get(4)?;
            let is_torrent = is_torrent.map(|v| v != 0);
            // LEFT JOIN: with no progress row the three columns are NULL
            // (read as Options); the progress payload belongs only to
            // HTTP rows (is_torrent = Some(false)).
            let progress = if is_torrent == Some(false) {
                let piece_length: Option<i64> = r.get(5)?;
                let total_length: Option<i64> = r.get(6)?;
                let bitfield: Option<Vec<u8>> = r.get(7)?;
                match (piece_length, total_length, bitfield) {
                    (Some(pl), Some(tl), Some(bf)) => Some(ForkProgress {
                        piece_length: pl,
                        total_length: tl,
                        upload_length: 0,
                        bitfield: bf,
                    }),
                    _ => None,
                }
            } else {
                None
            };
            Ok(ForkHttpTaskRow {
                gid: r.get(0)?,
                state: r.get(1)?,
                serialized: r.get(2)?,
                queue_position: r.get(3)?,
                is_torrent,
                progress,
            })
        })
        .map_err(StoreError::from)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

/// Open-phase error classification: content-level corruption maps to
/// [`StoreError::CorruptDatabase`], SQLITE_BUSY (a legacy fork process
/// holds the lock) maps to [`StoreError::ForkLocked`], everything else
/// stays [`StoreError::Sqlite`] (same policy as opening this engine's
/// own database; see the `persist::mod` comment).
fn classify_fork_open_error(path: &Path, e: rusqlite::Error) -> StoreError {
    const SQLITE_CORRUPT: i32 = 11;
    const SQLITE_NOTADB: i32 = 26;
    if let rusqlite::Error::SqliteFailure(ffi, _) = &e {
        if ffi.code == rusqlite::ErrorCode::DatabaseBusy {
            return StoreError::ForkLocked {
                path: path.display().to_string(),
            };
        }
        if ffi.extended_code & 0xFF == SQLITE_CORRUPT || ffi.extended_code & 0xFF == SQLITE_NOTADB {
            return StoreError::CorruptDatabase {
                path: path.display().to_string(),
                source: e,
            };
        }
    }
    StoreError::Sqlite(e)
}

/// `.aria2` control file parse errors (corrupt files produce explicit
/// errors and never enter storage; each variant names its reference).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum Aria2CtrlError {
    /// Version != 0x0001 (the reference load raises "Unsupported ctrl
    /// file version" for anything but 0000/0001; the 0000 host-order
    /// legacy form is not accepted here — see the module comment).
    #[error("unsupported .aria2 control file version: {0:#06x}")]
    UnsupportedVersion(u16),
    /// Not a BT control file (extension low byte bit0 = 0 — an HTTP/FTP
    /// task's `.aria2` is not part of the BT migration face; skipped,
    /// not an error).
    #[error("not a BitTorrent control file (extension bit0 clear)")]
    NotBitTorrent,
    /// A BT control file reached the HTTP parse face (extension bit0 =
    /// 1) — it belongs to the BT migration face; the caller routes it,
    ///    never mixed reads.
    #[error("BitTorrent control file (extension bit0 set): belongs to the BitTorrent import face")]
    IsBitTorrent,
    /// infoHashLength != 20 (BT requires the full length; reference
    /// "Invalid info hash length").
    #[error("invalid info hash length: {0} (expected 20)")]
    InvalidInfoHashLength(u32),
    /// pieceLength = 0 (reference "piece length must not be 0").
    #[error("piece length must not be 0")]
    ZeroPieceLength,
    /// Bitfield length != ((total+piece-1)/piece+7)/8 (reference
    /// "bitfield length mismatch").
    #[error("bitfield length mismatch: expected {expected}, actual {actual}")]
    BitfieldLengthMismatch { expected: u64, actual: u64 },
    /// In-flight piece segment index >= numPieces (reference "piece
    /// index out of range" — bounds must be validated before a segment
    /// can be safely skipped).
    #[error("in-flight piece index out of range: {index} (num pieces {num_pieces})")]
    InFlightIndexOutOfRange { index: u32, num_pieces: u32 },
    /// In-flight piece length > pieceLength (reference).
    #[error("in-flight piece length out of range: {length} > {piece_length}")]
    InFlightLengthOutOfRange { length: u32, piece_length: u32 },
    /// In-flight piece bitfield length != (length+7)/8 (reference).
    #[error("in-flight piece bitfield length mismatch: expected {expected}, actual {actual}")]
    InFlightBitfieldLengthMismatch { expected: u64, actual: u64 },
    /// File truncated (reference READ_CHECK -> EX_SEGMENT_FILE_READ).
    #[error("truncated .aria2 control file: need {need} bytes at offset {offset}, have {have}")]
    Truncated {
        offset: usize,
        need: usize,
        have: usize,
    },
}

/// Parsed `.aria2` control file payload (in-flight segments validated
/// then discarded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aria2ControlFile {
    /// SHA-1(info) (20 bytes).
    pub info_hash: [u8; 20],
    pub piece_length: u32,
    pub total_length: u64,
    /// Cumulative upload (uploadLengthAtStartup + session sum,
    /// `DefaultBtProgressInfoFile.cc`).
    pub upload_length: u64,
    /// v1 global piece bitmap (MSB-first; `expected_bitfield_len` bytes).
    pub bitfield: Vec<u8>,
}

/// Expected bitmap byte count (direct translation of the reference
/// `DefaultBtProgressInfoFile.cc` formula
/// `((totalLength + pieceLength - 1) / pieceLength + 7) / 8`).
pub fn expected_bitfield_len(total_length: u64, piece_length: u64) -> u64 {
    let num_pieces = total_length.div_ceil(piece_length);
    num_pieces.div_ceil(8)
}

/// Fixed block length of an in-flight piece bitmap (`Piece::BLOCK_LENGTH
/// = 16 KiB`, Piece.h; used only for in-flight segment validation — the
/// main bitmap's length derives from piece_length and is unrelated).
const PIECE_BLOCK_LENGTH: u64 = 16 * 1024;

/// Completed byte count implied by a bitmap (full piece lengths plus
/// the last piece's real length; the import face derives its
/// `downloaded_total` base from this — the fork never persists total
/// downloaded bytes, the bitmap is the fact).
pub fn completed_length_from_bitfield(
    bitfield: &[u8],
    num_pieces: u64,
    piece_length: u64,
    total_length: u64,
) -> u64 {
    let mut completed: u64 = 0;
    for k in 0..num_pieces {
        let set = bitfield[(k / 8) as usize] & (0x80 >> (k % 8)) != 0;
        if !set {
            continue;
        }
        let start = k * piece_length;
        let end = start + piece_length;
        completed += end.min(total_length) - start;
    }
    completed
}

/// Parse a `.aria2` control file (byte layout in docs/design/store.md;
/// fields checked one by one against `DefaultBtProgressInfoFile.cc`
/// save/load).
pub fn parse_aria2_control(data: &[u8]) -> Result<Aria2ControlFile, Aria2CtrlError> {
    let mut cur = Cursor::new(data);
    // version: 16 bits (the reference writes {0x00,0x01}).
    let version = cur.take_u16()?;
    if version != 0x0001 {
        return Err(Aria2CtrlError::UnsupportedVersion(version));
    }
    // extension: 32 bits; BT = low byte bit0.
    let extension = cur.take_u32()?;
    if extension & 1 == 0 {
        return Err(Aria2CtrlError::NotBitTorrent);
    }
    // infoHashLength: 32 bits + infoHash; BT must equal
    // INFO_HASH_LENGTH (20).
    let info_hash_length = cur.take_u32()?;
    if info_hash_length != 20 {
        return Err(Aria2CtrlError::InvalidInfoHashLength(info_hash_length));
    }
    let mut info_hash = [0u8; 20];
    cur.take_into(&mut info_hash)?;
    // pieceLength: 32 bits.
    let piece_length = cur.take_u32()?;
    if piece_length == 0 {
        return Err(Aria2CtrlError::ZeroPieceLength);
    }
    // totalLength / uploadLength: 64 bits.
    let total_length = cur.take_u64()?;
    let upload_length = cur.take_u64()?;
    // bitfieldLength + bitfield; the length check uses the reference
    // formula.
    let bitfield_length = cur.take_u32()?;
    let expected_len = expected_bitfield_len(total_length, u64::from(piece_length));
    if u64::from(bitfield_length) != expected_len {
        return Err(Aria2CtrlError::BitfieldLengthMismatch {
            expected: expected_len,
            actual: u64::from(bitfield_length),
        });
    }
    // need first: the truncation check precedes allocation. expected_len
    // is derived from the *declared* totalLength (a ~34-byte file
    // declaring a 32 GiB total with 1-byte pieces lifts it to ~4 GiB);
    // allocating with `vec!` before validating would commit the full
    // zeroed allocation before reporting Truncated (a corrupt file
    // forcing a huge allocation). The need check rejects before any
    // allocation happens.
    cur.need(bitfield_length as usize)?;
    let mut bitfield = vec![0u8; bitfield_length as usize];
    cur.take_into(&mut bitfield)?;
    // numInFlightPiece + one entry per in-flight piece: read, validate
    // bounds, then discard (the reference load reads the same fields;
    // this engine does not restore in-flight blocks).
    skip_in_flight_pieces(&mut cur, piece_length, total_length)?;
    // Trailing bytes ignored (the reference load does not check EOF; same behavior).
    Ok(Aria2ControlFile {
        info_hash,
        piece_length,
        total_length,
        upload_length,
        bitfield,
    })
}

/// Shared reader for the in-flight piece section (both BT/HTTP parse
/// faces): numInFlightPiece + per-segment bounds validation, then
/// discard (reference load; per-piece bitmap length =
/// `ceil(ceil(length/16KiB)/8)` — `Piece.cc` + `Piece.h`
/// BLOCK_LENGTH=16KiB + `BitfieldMan.cc`).
fn skip_in_flight_pieces(
    cur: &mut Cursor<'_>,
    piece_length: u32,
    total_length: u64,
) -> Result<(), Aria2CtrlError> {
    let num_in_flight = cur.take_u32()?;
    let num_pieces = total_length
        .div_ceil(u64::from(piece_length))
        .min(u32::MAX as u64) as u32;
    for _ in 0..num_in_flight {
        let index = cur.take_u32()?;
        if index >= num_pieces {
            return Err(Aria2CtrlError::InFlightIndexOutOfRange { index, num_pieces });
        }
        let length = cur.take_u32()?;
        if length > piece_length {
            return Err(Aria2CtrlError::InFlightLengthOutOfRange {
                length,
                piece_length,
            });
        }
        let piece_bf_len = cur.take_u32()?;
        let expected_piece_bf = u64::from(length).div_ceil(PIECE_BLOCK_LENGTH).div_ceil(8);
        if u64::from(piece_bf_len) != expected_piece_bf {
            return Err(Aria2CtrlError::InFlightBitfieldLengthMismatch {
                expected: expected_piece_bf,
                actual: u64::from(piece_bf_len),
            });
        }
        let mut piece_bitfield = vec![0u8; piece_bf_len as usize];
        cur.take_into(&mut piece_bitfield)?;
        // discard(piece_bitfield) — in-flight blocks are not imported.
    }
    Ok(())
}

/// Parsed HTTP/FTP `.aria2` control file payload (in-flight pieces validated then discarded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aria2HttpControl {
    pub piece_length: u32,
    pub total_length: u64,
    /// Non-BT save always writes 0 (reference branch); read out for completeness only.
    pub upload_length: u64,
    /// Piece bitmap (MSB-first; `expected_bitfield_len(total, piece)` bytes).
    pub bitfield: Vec<u8>,
}

/// Parse an HTTP/FTP `.aria2` control file (non-BT variant; layout and
/// tolerances in docs/design/store.md). extension bit0 set =
/// [`Aria2CtrlError::IsBitTorrent`] (a BT-migration-face file; the
/// caller routes it).
pub fn parse_aria2_control_http(data: &[u8]) -> Result<Aria2HttpControl, Aria2CtrlError> {
    let mut cur = Cursor::new(data);
    // version: 16 bits (same as the BT face).
    let version = cur.take_u16()?;
    if version != 0x0001 {
        return Err(Aria2CtrlError::UnsupportedVersion(version));
    }
    // extension: 32 bits — HTTP/FTP always 0 (non-BT save branch).
    let extension = cur.take_u32()?;
    if extension & 1 == 1 {
        return Err(Aria2CtrlError::IsBitTorrent);
    }
    // infoHashLength: the reference save writes 0 for non-BT; the load
    // side tolerates <= 20 and skips that many bytes (HTTP load does not
    // enable infohash checking:
    // `infoHashCheckEnabled = extension[3] & 1 && isTorrentDownload()`).
    let info_hash_length = cur.take_u32()?;
    if info_hash_length > 20 {
        return Err(Aria2CtrlError::InvalidInfoHashLength(info_hash_length));
    }
    let mut skipped = vec![0u8; info_hash_length as usize];
    cur.take_into(&mut skipped)?;
    // pieceLength / totalLength / uploadLength; uploadLength is always 0
    // for non-BT, read for completeness only.
    let piece_length = cur.take_u32()?;
    if piece_length == 0 {
        return Err(Aria2CtrlError::ZeroPieceLength);
    }
    let total_length = cur.take_u64()?;
    let upload_length = cur.take_u64()?;
    // bitfieldLength + bitfield; the fixed-length formula is the
    // reference's.
    let bitfield_length = cur.take_u32()?;
    let expected_len = expected_bitfield_len(total_length, u64::from(piece_length));
    if u64::from(bitfield_length) != expected_len {
        return Err(Aria2CtrlError::BitfieldLengthMismatch {
            expected: expected_len,
            actual: u64::from(bitfield_length),
        });
    }
    // need first: same as the BT face — the declared-length vector that
    // lifts the expected fixed length is rejected by the truncation
    // check before allocation.
    cur.need(bitfield_length as usize)?;
    let mut bitfield = vec![0u8; bitfield_length as usize];
    cur.take_into(&mut bitfield)?;
    // In-flight pieces: bounds-validated then discarded (same rule as the BT face).
    skip_in_flight_pieces(&mut cur, piece_length, total_length)?;
    // Trailing bytes ignored (the reference load does not check EOF; same behavior).
    Ok(Aria2HttpControl {
        piece_length,
        total_length,
        upload_length,
        bitfield,
    })
}

/// Parse cursor: truncation detection with offsets (errors carry a diagnosable offset/need/have).
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn need(&self, n: usize) -> Result<(), Aria2CtrlError> {
        if self.data.len() - self.pos < n {
            Err(Aria2CtrlError::Truncated {
                offset: self.pos,
                need: n,
                have: self.data.len() - self.pos,
            })
        } else {
            Ok(())
        }
    }

    fn take_u16(&mut self) -> Result<u16, Aria2CtrlError> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn take_u32(&mut self) -> Result<u32, Aria2CtrlError> {
        self.need(4)?;
        let b: [u8; 4] = self.data[self.pos..self.pos + 4].try_into().map_err(|_| {
            Aria2CtrlError::Truncated {
                offset: self.pos,
                need: 4,
                have: self.data.len() - self.pos,
            }
        })?;
        self.pos += 4;
        Ok(u32::from_be_bytes(b))
    }

    fn take_u64(&mut self) -> Result<u64, Aria2CtrlError> {
        self.need(8)?;
        let b: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().map_err(|_| {
            Aria2CtrlError::Truncated {
                offset: self.pos,
                need: 8,
                have: self.data.len() - self.pos,
            }
        })?;
        self.pos += 8;
        Ok(u64::from_be_bytes(b))
    }

    fn take_into(&mut self, out: &mut [u8]) -> Result<(), Aria2CtrlError> {
        self.need(out.len())?;
        out.copy_from_slice(&self.data[self.pos..self.pos + out.len()]);
        self.pos += out.len();
        Ok(())
    }
}

/// Recursively collect `.aria2` control files under a directory
/// (`<dir>/**/<file>.aria2`; results sorted lexicographically — report
/// and import order are reproducible). Does not follow symlinked
/// directories.
pub fn collect_aria2_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk_aria2(dir, 0, &mut out)?;
    out.sort();
    Ok(out)
}

/// Recursion depth cap: guards abnormally deep trees (a normal
/// download directory is < 10 levels).
const WALK_MAX_DEPTH: usize = 32;

fn walk_aria2(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if depth > WALK_MAX_DEPTH {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            walk_aria2(&path, depth + 1, out)?;
        } else if path.extension().is_some_and(|e| e == "aria2") {
            out.push(path);
        }
    }
    Ok(())
}

// Bounded-allocation fact: with the workspace's `-F unsafe-code` a
// custom allocation counter is not feasible; "peak allocation is
// bounded" is closed by the parser's code-order invariant —
// `need(fixed_len)` runs before `vec![0u8; fixed_len]`, so the
// allocation is clamped to bytes actually on disk (the declared-length
// attack = "declared but absent", rejected before allocation). The
// attack-vector tests below pin the rejection contract (immediate
// Truncated + exact offset/need/have) and the fixed-length formula
// anchor.
#[cfg(test)]
mod tests {
    use super::*;

    /// Test Result unwrap (lints forbid unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// Unique tmp database path (same convention as the persist/mod tests: no tempfile dependency).
    fn tmp_path(tag: &str, ext: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "taiji-forkimport-{tag}-{}-{}.{ext}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ))
    }

    /// Synthetic fork-schema fixture (DDL matches `Sqlite3Migrations.cc`
    /// clause by clause; user_version = 1). Returns the database path.
    fn seed_fork_db(tag: &str) -> PathBuf {
        let path = tmp_path(tag, "sqlite3");
        let conn = ok(Connection::open(&path), "open fixture");
        ok(
            conn.execute_batch(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE task (
                   gid             TEXT    PRIMARY KEY,
                   state           TEXT    NOT NULL,
                   serialized      TEXT    NOT NULL,
                   belongs_to      TEXT,
                   following       TEXT,
                   followed_by     TEXT,
                   metadata_uri    TEXT,
                   bt_local_path   TEXT,
                   queue_position  INTEGER NOT NULL,
                   digest          BLOB    NOT NULL,
                   created_at      INTEGER NOT NULL,
                   updated_at      INTEGER NOT NULL
                 );
                 CREATE INDEX idx_task_state          ON task(state);
                 CREATE INDEX idx_task_queue_position ON task(queue_position);
                 CREATE TABLE task_progress (
                   gid              TEXT    PRIMARY KEY,
                   ctrl_version     INTEGER NOT NULL DEFAULT 1,
                   is_torrent       INTEGER NOT NULL DEFAULT 0,
                   info_hash        BLOB,
                   piece_length     INTEGER NOT NULL,
                   total_length     INTEGER NOT NULL,
                   upload_length    INTEGER NOT NULL DEFAULT 0,
                   bitfield         BLOB    NOT NULL,
                   in_flight_blob   BLOB    NOT NULL DEFAULT X'',
                   digest           BLOB    NOT NULL,
                   updated_at       INTEGER NOT NULL,
                   FOREIGN KEY (gid) REFERENCES task(gid) ON DELETE CASCADE
                 );
                 PRAGMA user_version = 1;",
            ),
            "seed fork schema",
        );
        path
    }

    /// Seeding parameter bundle (compresses clippy::too_many_arguments;
    /// the fixture passes column values directly).
    struct SeedTask<'a> {
        gid: &'a str,
        queue: i64,
        is_torrent: i64,
        info_hash: Option<&'a [u8]>,
        piece_length: i64,
        total_length: i64,
        upload_length: i64,
        bitfield: &'a [u8],
        bt_local_path: Option<&'a str>,
    }

    fn insert_task(conn: &Connection, s: SeedTask<'_>) {
        ok(
            conn.execute(
                "INSERT INTO task (gid, state, serialized, queue_position, digest,
                                   created_at, updated_at, bt_local_path)
                 VALUES (?1, 'waiting', ' dir=/dl\n', ?2, x'00', 0, 0, ?3)",
                params![s.gid, s.queue, s.bt_local_path],
            ),
            "insert task",
        );
        ok(
            conn.execute(
                "INSERT INTO task_progress (gid, is_torrent, info_hash, piece_length,
                                            total_length, upload_length, bitfield,
                                            digest, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, x'00', 0)",
                params![
                    s.gid,
                    s.is_torrent,
                    s.info_hash,
                    s.piece_length,
                    s.total_length,
                    s.upload_length,
                    s.bitfield
                ],
            ),
            "insert progress",
        );
    }

    #[test]
    fn readonly_open_rejects_wrong_user_version_and_missing_tables() {
        // user_version != 1 must be rejected explicitly.
        let wrong_version = tmp_path("wrongver", "sqlite3");
        {
            let conn = ok(Connection::open(&wrong_version), "open");
            ok(
                conn.execute_batch(
                    "CREATE TABLE task (gid TEXT PRIMARY KEY);
                     CREATE TABLE task_progress (gid TEXT PRIMARY KEY);
                     PRAGMA user_version = 2;",
                ),
                "seed v2",
            );
        }
        match open_fork_readonly(&wrong_version) {
            Err(StoreError::ForkSchema { version, .. }) => assert_eq!(version, 2),
            other => panic!("expected ForkSchema, got {other:?}"),
        }
        // Missing tables (e.g. a taiji.sqlite3 passed by mistake —
        // also user_version 1) are rejected too.
        let not_fork = tmp_path("notfork", "sqlite3");
        {
            let conn = ok(Connection::open(&not_fork), "open");
            ok(
                conn.execute_batch(
                    "CREATE TABLE torrent (gid TEXT PRIMARY KEY);
                     PRAGMA user_version = 1;",
                ),
                "seed bt-like",
            );
        }
        match open_fork_readonly(&read_only_prep(&not_fork)) {
            Err(StoreError::ForkSchema { version, .. }) => assert_eq!(version, 1),
            other => panic!("expected ForkSchema for missing tables, got {other:?}"),
        }
        let _ = std::fs::remove_file(&wrong_version);
        let _ = std::fs::remove_file(&not_fork);
    }

    /// A read-only open of a WAL database needs a writable -shm in some
    /// environments; fixtures always use the DELETE journal (default) to
    /// avoid environment coupling — the object under test is the flags
    /// and the probe, not the journal mode.
    fn read_only_prep(path: &Path) -> PathBuf {
        path.to_path_buf()
    }

    #[test]
    fn readonly_open_enforces_no_write_at_sqlite_level() {
        let path = seed_fork_db("ro");
        let conn = ok(open_fork_readonly(&path), "open ro");
        // Hard proof of the read-only discipline: sqlite rejects the write statement.
        let refused = conn.execute("INSERT INTO meta (key, value) VALUES ('k', 'v')", []);
        assert!(refused.is_err(), "write on readonly connection must fail");
        let _ = std::fs::remove_file(&path);
    }

    /// Fork fixture import roundtrip, first half of the read face: the
    /// join is checked column by column against seeded values; the BT
    /// filter is is_torrent = 1 with non-empty info_hash.
    #[test]
    fn load_fork_bt_tasks_joins_and_filters_like_spec10() {
        let path = seed_fork_db("join");
        let conn = ok(Connection::open(&path), "open fixture");
        let ih = [7u8; 20];
        // BT task (import candidate).
        insert_task(
            &conn,
            SeedTask {
                gid: "0000000000000001",
                queue: 2,
                is_torrent: 1,
                info_hash: Some(&ih),
                piece_length: 16384,
                total_length: 32768,
                upload_length: 4096,
                bitfield: &[0b1100_0000],
                bt_local_path: None,
            },
        );
        // Non-BT task (HTTP) -> filtered out.
        insert_task(
            &conn,
            SeedTask {
                gid: "0000000000000002",
                queue: 1,
                is_torrent: 0,
                info_hash: None,
                piece_length: 16384,
                total_length: 1024,
                upload_length: 0,
                bitfield: &[0u8],
                bt_local_path: None,
            },
        );
        // is_torrent=1 but info_hash NULL -> filtered out.
        insert_task(
            &conn,
            SeedTask {
                gid: "0000000000000003",
                queue: 3,
                is_torrent: 1,
                info_hash: None,
                piece_length: 16384,
                total_length: 1024,
                upload_length: 0,
                bitfield: &[0u8],
                bt_local_path: None,
            },
        );
        // BT task with bt_local_path + serialized (mapping-face input).
        insert_task(
            &conn,
            SeedTask {
                gid: "0000000000000004",
                queue: 0,
                is_torrent: 1,
                info_hash: Some(&ih),
                piece_length: 16384,
                total_length: 49152,
                upload_length: 1,
                bitfield: &[0b1111_1111],
                bt_local_path: Some("/tmp/src/a.torrent"),
            },
        );
        drop(conn);

        let conn = ok(open_fork_readonly(&path), "open ro");
        assert_eq!(ok(count_fork_tasks(&conn), "count"), 4);
        let tasks = ok(load_fork_bt_tasks(&conn), "load");
        // Only 2 rows pass the filter (gid 1 and 4), queue_position order.
        assert_eq!(tasks.len(), 2, "filtered rows: {tasks:?}");
        let t4 = &tasks[0];
        assert_eq!(t4.gid, "0000000000000004");
        assert_eq!(t4.queue_position, 0);
        assert_eq!(t4.bt_local_path.as_deref(), Some("/tmp/src/a.torrent"));
        assert_eq!(t4.serialized, " dir=/dl\n");
        assert_eq!(t4.info_hash, ih);
        let p = t4
            .progress
            .as_ref()
            .unwrap_or_else(|| panic!("progress missing"));
        assert_eq!(
            (p.piece_length, p.total_length, p.upload_length),
            (16384, 49152, 1)
        );
        assert_eq!(p.bitfield, vec![0b1111_1111]);
        let t1 = &tasks[1];
        assert_eq!(t1.gid, "0000000000000001");
        assert_eq!(t1.queue_position, 2);
        let _ = std::fs::remove_file(&path);
    }

    // ---- `.aria2` control file vectors: byte-for-byte against the
    // DefaultBtProgressInfoFile.cc layout; the source is named per
    // vector ----

    /// Builder: assemble a control file following the reference save()
    /// layout (shared by test vectors and future regressions; field
    /// order = the module layout table).
    struct CtrlBuilder {
        buf: Vec<u8>,
    }

    impl CtrlBuilder {
        fn new() -> Self {
            CtrlBuilder {
                buf: vec![0x00, 0x01],
            } // version 0001
        }
        fn ext_bt(mut self) -> Self {
            // extension: 32 bits; BT = low byte 0x01.
            self.buf.extend_from_slice(&[0, 0, 0, 1]);
            self
        }
        fn ext_plain(mut self) -> Self {
            self.buf.extend_from_slice(&[0, 0, 0, 0]);
            self
        }
        fn info_hash(mut self, ih: &[u8; 20]) -> Self {
            self.buf.extend_from_slice(&20u32.to_be_bytes()); // infoHashLength = 20
            self.buf.extend_from_slice(ih); // infoHash
            self
        }
        fn piece_length(mut self, v: u32) -> Self {
            self.buf.extend_from_slice(&v.to_be_bytes()); // pieceLength
            self
        }
        fn total_length(mut self, v: u64) -> Self {
            self.buf.extend_from_slice(&v.to_be_bytes()); // totalLength
            self
        }
        fn upload_length(mut self, v: u64) -> Self {
            self.buf.extend_from_slice(&v.to_be_bytes()); // uploadLength
            self
        }
        fn bitfield(mut self, bf: &[u8]) -> Self {
            self.buf.extend_from_slice(&(bf.len() as u32).to_be_bytes()); // bitfieldLength
            self.buf.extend_from_slice(bf); // bitfield
            self
        }
        fn in_flight(mut self, index: u32, length: u32, bf: &[u8]) -> Self {
            // numInFlightPiece is written once, outside (see
            // finish_in_flight_count); each piece = index/length/
            // bitfieldLength/bitfield.
            self.buf.extend_from_slice(&index.to_be_bytes());
            self.buf.extend_from_slice(&length.to_be_bytes());
            self.buf.extend_from_slice(&(bf.len() as u32).to_be_bytes());
            self.buf.extend_from_slice(bf);
            self
        }
        fn finish_in_flight_count(mut self, n: u32) -> Self {
            // numInFlightPiece (32 bits) sits after the bitmap, before the first piece.
            let tail = self.buf.split_off(54 + self.bf_len_pos());
            // Split at the end of the bitfield: 54 + bf_len. Before the split: header + bitmap.
            self.buf.extend_from_slice(&n.to_be_bytes());
            self.buf.extend_from_slice(&tail);
            self
        }
        fn bf_len_pos(&self) -> usize {
            // The bitmap-length field is at offset 50; the bitmap length is that field's value.
            let b: [u8; 4] = self.buf[50..54].try_into().unwrap_or([0; 4]);
            u32::from_be_bytes(b) as usize
        }
        fn bytes(self) -> Vec<u8> {
            self.buf
        }
    }

    fn sample_ih() -> [u8; 20] {
        let mut ih = [0u8; 20];
        for (i, b) in ih.iter_mut().enumerate() {
            *b = i as u8;
        }
        ih
    }

    /// Vector 1 (positive): minimal valid BT control file — a 1-piece
    /// torrent, all-zero bitmap, no in-flight entries (layout = the save
    /// header, field by field).
    #[test]
    fn vector_minimal_valid_bt_control_parses() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(16 * 1024)
            .total_length(16 * 1024)
            .upload_length(1234)
            .bitfield(&[0b0000_0000])
            .finish_in_flight_count(0)
            .bytes();
        let parsed = ok(parse_aria2_control(&raw), "parse minimal");
        assert_eq!(parsed.info_hash, sample_ih());
        assert_eq!(parsed.piece_length, 16 * 1024);
        assert_eq!(parsed.total_length, 16 * 1024);
        assert_eq!(parsed.upload_length, 1234);
        assert_eq!(parsed.bitfield, vec![0b0000_0000]);
    }

    /// Vector 2 (positive): a file with 2 in-flight pieces — parses
    /// successfully, in-flight segments are discarded (absent from the
    /// payload), bitmap untouched. In-flight bitmap length =
    /// ceil(ceil(length/16KiB)/8) (Piece.cc + BitfieldMan.cc): length 8
    /// -> 1 byte, length 16KiB -> 1 byte.
    #[test]
    fn vector_in_flight_pieces_are_validated_then_discarded() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(16 * 1024)
            .total_length(4 * 16 * 1024)
            .upload_length(0)
            .bitfield(&[0b1000_0000])
            .finish_in_flight_count(2)
            .in_flight(1, 8, &[0b1000_0000])
            .in_flight(2, 16 * 1024, &[0b0100_0000])
            .bytes();
        let parsed = ok(parse_aria2_control(&raw), "parse with in-flight");
        assert_eq!(
            parsed.bitfield,
            vec![0b1000_0000],
            "the bitmap is 1:1; in-flight segments do not mix in"
        );
    }

    /// Vector 3 (negative): version 0x0002 -> UnsupportedVersion (the
    /// reference raises "Unsupported ctrl file version" for unknown
    /// versions).
    #[test]
    fn vector_future_version_is_rejected() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        let mut patched = raw;
        patched[1] = 0x02;
        assert_eq!(
            parse_aria2_control(&patched),
            Err(Aria2CtrlError::UnsupportedVersion(0x0002))
        );
    }

    /// Vector 4 (negative): version 0x0000 (the upstream-supported
    /// host-order legacy form) is rejected explicitly — host-order files
    /// are not portable across machines; refusing beats misreading.
    #[test]
    fn vector_legacy_host_order_version_is_rejected() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        let mut patched = raw;
        patched[1] = 0x00;
        assert_eq!(
            parse_aria2_control(&patched),
            Err(Aria2CtrlError::UnsupportedVersion(0x0000))
        );
    }

    /// Vector 5 (negative): bitfield truncated mid-way -> Truncated (reference READ_CHECK).
    #[test]
    fn vector_truncated_bitfield_reports_explicit_error() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(16 * 1024)
            .total_length(16 * 1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        assert!(matches!(
            parse_aria2_control(&raw[..raw.len() - 1]),
            Err(Aria2CtrlError::Truncated { .. })
        ));
    }

    /// Vector 6 (negative): infoHashLength = 24 != 20 ->
    /// InvalidInfoHashLength (reference "Invalid info hash length").
    #[test]
    fn vector_oversized_info_hash_length_is_rejected() {
        let mut raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        // Set the infoHashLength field to 24 (no trailing bytes -> the length check fires first).
        raw[6..10].copy_from_slice(&24u32.to_be_bytes());
        assert_eq!(
            parse_aria2_control(&raw),
            Err(Aria2CtrlError::InvalidInfoHashLength(24))
        );
    }

    /// Vector 7 (negative): pieceLength = 0 -> ZeroPieceLength (reference
    /// "piece length must not be 0").
    #[test]
    fn vector_zero_piece_length_is_rejected() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(0)
            .total_length(0)
            .upload_length(0)
            .bitfield(&[])
            .finish_in_flight_count(0)
            .bytes();
        assert_eq!(
            parse_aria2_control(&raw),
            Err(Aria2CtrlError::ZeroPieceLength)
        );
    }

    /// Vector 8 (negative): bitfield length != formula value ->
    /// BitfieldLengthMismatch.
    #[test]
    fn vector_bitfield_length_mismatch_is_rejected() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(16 * 1024)
            .total_length(16 * 1024) // 1 piece -> expected 1 byte
            .upload_length(0)
            .bitfield(&[0, 0, 0]) // actual 3 bytes
            .finish_in_flight_count(0)
            .bytes();
        assert_eq!(
            parse_aria2_control(&raw),
            Err(Aria2CtrlError::BitfieldLengthMismatch {
                expected: 1,
                actual: 3
            })
        );
    }

    /// Vector 9 (skip face): non-BT control file (extension bit0 = 0) ->
    /// NotBitTorrent — a directory scan also hits HTTP tasks' `.aria2`
    /// files; skipping is not an error (the reference writes 0 extension
    /// for non-BT).
    #[test]
    fn vector_non_bittorrent_extension_is_skippable() {
        let raw = CtrlBuilder::new()
            .ext_plain()
            .info_hash(&sample_ih())
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        assert_eq!(
            parse_aria2_control(&raw),
            Err(Aria2CtrlError::NotBitTorrent)
        );
    }

    /// Vector 10 (negative, skip bounds): in-flight index >= numPieces ->
    /// explicit error (bounds must be validated to skip segments safely).
    #[test]
    fn vector_in_flight_index_out_of_range_is_rejected() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(16 * 1024)
            .total_length(2 * 16 * 1024) // 2 pieces
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(1)
            .in_flight(2, 16 * 1024, &[0])
            .bytes();
        assert_eq!(
            parse_aria2_control(&raw),
            Err(Aria2CtrlError::InFlightIndexOutOfRange {
                index: 2,
                num_pieces: 2
            })
        );
    }

    /// Vector 11 (positive): trailing garbage bytes after the bitmap are
    /// ignored (the reference load does not check EOF; same behavior).
    #[test]
    fn vector_trailing_garbage_is_ignored() {
        let mut raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(16 * 1024)
            .total_length(16 * 1024)
            .upload_length(9)
            .bitfield(&[0b0000_0001])
            .finish_in_flight_count(0)
            .bytes();
        raw.extend_from_slice(b"garbage");
        let parsed = ok(parse_aria2_control(&raw), "parse trailing");
        assert_eq!(parsed.upload_length, 9);
    }

    /// Vector 12 (negative, skip bounds): in-flight piece bitfield length
    /// mismatch -> explicit error (expected = ceil(ceil(length/16KiB)/8)).
    #[test]
    fn vector_in_flight_bitfield_length_mismatch_is_rejected() {
        let raw = CtrlBuilder::new()
            .ext_bt()
            .info_hash(&sample_ih())
            .piece_length(16 * 1024)
            .total_length(2 * 16 * 1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(1)
            .in_flight(0, 16 * 1024, &[0, 0]) // expected 1 (1 block), given 2
            .bytes();
        assert_eq!(
            parse_aria2_control(&raw),
            Err(Aria2CtrlError::InFlightBitfieldLengthMismatch {
                expected: 1,
                actual: 2
            })
        );
    }

    // ---- fork liveness fd scan vectors (precheck layers 2/3) ----

    /// `lsof -Fn` parse vectors (real output shape: `p<pid>` process
    /// sets plus `f<fd>`/`n<name>` field lines): candidate hits,
    /// canonical spelling, the `-journal` neighbor not masquerading,
    /// `(deleted)` marker tolerance, unrelated processes not collected.
    #[cfg(target_os = "macos")]
    #[test]
    fn lsof_fn_output_parse_matches_candidates_only() {
        // Candidate face = the shape [`fork_db_watch_paths`] produces:
        // given spelling + canonical spelling (macOS lsof reports /tmp
        // under its real name /private/tmp), each with sidecars.
        let candidates = [
            "/dl/fork.sqlite3",
            "/dl/fork.sqlite3-wal",
            "/dl/fork.sqlite3-shm",
            "/private/dl/fork.sqlite3",
            "/private/dl/fork.sqlite3-wal",
            "/private/dl/fork.sqlite3-shm",
        ]
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
        let out = "p64340\n\
                   f0\n\
                   n/private/dl/fork.sqlite3\n\
                   p999\n\
                   f3\n\
                   n/private/dl/fork.sqlite3-wal\n\
                   p7\n\
                   f4\n\
                   n/private/dl/fork.sqlite3-journal\n\
                   n/private/dl/other.sqlite3\n\
                   p555\n\
                   f5\n\
                   n/private/dl/fork.sqlite3 (deleted)\n";
        let holders = parse_lsof_fn_output(out, &candidates);
        assert_eq!(
            holders,
            vec![
                ForkFdHolder {
                    pid: 64340,
                    path: "/private/dl/fork.sqlite3".into()
                },
                ForkFdHolder {
                    pid: 999,
                    path: "/private/dl/fork.sqlite3-wal".into()
                },
                ForkFdHolder {
                    pid: 555,
                    path: "/private/dl/fork.sqlite3 (deleted)".into()
                },
            ],
            "main db/-wal/(deleted) hit; -journal neighbors and unrelated paths are not collected"
        );
    }

    /// Matcher edges: delete-marker tolerance; a non-space after the
    /// prefix is rejected (`-wal`/`-journal` do not masquerade as the
    /// main DB); empty candidates never match.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn fd_target_match_tolerates_markers_and_rejects_adjacent_names() {
        let candidates = vec![PathBuf::from("/dl/fork.sqlite3")];
        assert!(fd_target_matches("/dl/fork.sqlite3", &candidates));
        assert!(fd_target_matches("/dl/fork.sqlite3 (deleted)", &candidates));
        assert!(!fd_target_matches("/dl/fork.sqlite3-wal", &candidates));
        assert!(!fd_target_matches("/dl/fork.sqlite3-journal", &candidates));
        assert!(!fd_target_matches("/dl2/fork.sqlite3", &candidates));
        assert!(!fd_target_matches("/dl/fork.sqlite3", &[]));
    }

    /// Live-holder face: a child process holds the DB file fd (sleep
    /// holding stdin suffices) -> the scan reports that pid.
    #[test]
    fn scan_reports_external_process_holding_the_fork_db() {
        if !cfg!(any(target_os = "macos", target_os = "linux")) {
            // Other platforms: scan face absent = Uncertain (default
            // refuse face).
            let liveness = scan_fork_liveness(Path::new("/nonexistent/f.sqlite3"));
            assert!(
                matches!(liveness, ForkLiveness::Uncertain(_)),
                "{liveness:?}"
            );
            return;
        }
        let path = seed_fork_db("fdscan");
        // Clean face proven first: with no holder the scan is usable and Clean.
        match scan_fork_liveness(&path) {
            ForkLiveness::Clean => {}
            ForkLiveness::Uncertain(reason) => panic!("clean scan uncertain: {reason}"),
            ForkLiveness::Alive(h) => panic!("no holder expected: {h:?}"),
        }
        // Live case: a child process holds the DB file via stdin (the fd
        // is in place at exec, kernel-visible once spawn returns).
        let holder = ok(std::fs::File::open(&path), "open holder fd");
        let mut child = ok(
            std::process::Command::new("sleep")
                .arg("20")
                .stdin(std::process::Stdio::from(holder))
                .spawn(),
            "spawn fd holder",
        );
        let child_pid = child.id();
        // spawn->exec race tolerance: bounded rescans; the hit must report the child pid.
        let mut seen = None;
        for _ in 0..40 {
            if let ForkLiveness::Alive(holders) = scan_fork_liveness(&path) {
                if holders.iter().any(|h| h.pid == child_pid) {
                    seen = Some(holders);
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let holders = seen.unwrap_or_else(|| panic!("holder pid {child_pid} not reported"));
        assert!(
            holders
                .iter()
                .all(|h| h.pid == child_pid || h.path.contains("forkimport-fdscan")),
            "self-held handles (this test process) must not enter the report: {holders:?}"
        );
        ok(child.kill(), "kill holder");
        let _ = child.wait();
        let _ = std::fs::remove_file(&path);
    }

    /// Empty file / truncated header -> Truncated (corrupt files
    /// produce explicit errors, never enter storage).
    #[test]
    fn empty_and_header_truncated_files_error() {
        assert!(matches!(
            parse_aria2_control(&[]),
            Err(Aria2CtrlError::Truncated { .. })
        ));
        assert!(matches!(
            parse_aria2_control(&[0x00, 0x01, 0x00]),
            Err(Aria2CtrlError::Truncated { .. })
        ));
    }

    /// Bitmap formula and completed-length derivation (last piece's real length).
    #[test]
    fn bitfield_length_formula_and_completed_length() {
        // 10 pieces -> 2 bytes.
        assert_eq!(expected_bitfield_len(10 * 1000, 1000), 2);
        // Exact division: 8 pieces -> 1 byte.
        assert_eq!(expected_bitfield_len(8 * 512, 512), 1);
        // Completed length: 3 pieces (piece length 1000, total 2500),
        // bitmap 0b101_0000_0 -> piece0 (1000) + piece2 (500, the last
        // piece's real length).
        let bf = [0b1010_0000u8];
        assert_eq!(completed_length_from_bitfield(&bf, 3, 1000, 2500), 1500);
        // All-zero bitmap -> 0.
        assert_eq!(completed_length_from_bitfield(&[0, 0], 16, 1000, 16000), 0);
    }

    /// Directory scan: recursive + lexicographically stable (`<dir>/**/<file>.aria2`).
    #[test]
    fn collect_aria2_files_walks_recursively_and_sorts() {
        let root = tmp_path("scan", "d");
        ok(std::fs::create_dir_all(root.join("sub/deep")), "mkdir");
        ok(std::fs::write(root.join("b.aria2"), b""), "write b");
        ok(std::fs::write(root.join("sub/a.aria2"), b""), "write a");
        ok(
            std::fs::write(root.join("sub/deep/c.aria2"), b""),
            "write c",
        );
        ok(
            std::fs::write(root.join("keep.torrent"), b""),
            "write torrent",
        );
        ok(std::fs::write(root.join("note.txt"), b""), "write txt");
        let found = ok(collect_aria2_files(&root), "scan");
        let names: Vec<String> = found
            .iter()
            .map(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(names, vec!["b.aria2", "a.aria2", "c.aria2"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- HTTP/FTP `.aria2` control file vectors (non-BT variant;
    // layout against the DefaultBtProgressInfoFile.cc non-BT save branch
    // and the load tolerance face) ----

    /// Non-BT control file builder (field by field along the reference save branch).
    struct HttpCtrlBuilder {
        buf: Vec<u8>,
        /// infoHashLength byte count (offset correction for later fields).
        ihl: usize,
    }

    impl HttpCtrlBuilder {
        fn new() -> Self {
            HttpCtrlBuilder {
                buf: vec![0x00, 0x01], // version 0001
                ihl: 0,
            }
        }
        fn ext_http(mut self) -> Self {
            // extension = 0 (non-BT branch).
            self.buf.extend_from_slice(&[0, 0, 0, 0]);
            self
        }
        fn ext_bt(mut self) -> Self {
            self.buf.extend_from_slice(&[0, 0, 0, 1]);
            self
        }
        fn info_hash_length(mut self, n: u32) -> Self {
            // save writes 0 for non-BT; load tolerates <= 20.
            self.buf.extend_from_slice(&n.to_be_bytes());
            self.ihl = n as usize;
            self
        }
        fn info_hash_bytes(mut self, n: usize) -> Self {
            self.buf.extend_from_slice(&vec![0xAA; n]);
            self
        }
        fn piece_length(mut self, v: u32) -> Self {
            self.buf.extend_from_slice(&v.to_be_bytes()); // pieceLength
            self
        }
        fn total_length(mut self, v: u64) -> Self {
            self.buf.extend_from_slice(&v.to_be_bytes()); // totalLength
            self
        }
        fn upload_length(mut self, v: u64) -> Self {
            self.buf.extend_from_slice(&v.to_be_bytes()); // uploadLength
            self
        }
        fn bitfield(mut self, bf: &[u8]) -> Self {
            self.buf.extend_from_slice(&(bf.len() as u32).to_be_bytes()); // bitfieldLength
            self.buf.extend_from_slice(bf); // bitfield
            self
        }
        fn in_flight(mut self, index: u32, length: u32, bf: &[u8]) -> Self {
            self.buf.extend_from_slice(&index.to_be_bytes());
            self.buf.extend_from_slice(&length.to_be_bytes());
            self.buf.extend_from_slice(&(bf.len() as u32).to_be_bytes());
            self.buf.extend_from_slice(bf);
            self
        }
        fn finish_in_flight_count(mut self, n: u32) -> Self {
            // numInFlightPiece sits after the bitmap; the bitmap-length
            // field is at offset 30 + infoHashLength, the bitmap starts
            // at 34 + infoHashLength.
            let b = 30 + self.ihl;
            let bf_len =
                u32::from_be_bytes(self.buf[b..b + 4].try_into().unwrap_or([0; 4])) as usize;
            let tail = self.buf.split_off(b + 4 + bf_len);
            self.buf.extend_from_slice(&n.to_be_bytes());
            self.buf.extend_from_slice(&tail);
            self
        }
        fn bytes(self) -> Vec<u8> {
            self.buf
        }
    }

    /// Vector H1 (positive): minimal valid HTTP control file —
    /// infoHashLength=0, uploadLength=0 (the non-BT save branch).
    #[test]
    fn vector_http_control_minimal_parses() {
        let raw = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(0)
            .piece_length(1024 * 1024)
            .total_length(10 * 1024 * 1024)
            .upload_length(0)
            .bitfield(&[0b1110_0000, 0x00])
            .finish_in_flight_count(0)
            .bytes();
        let parsed = ok(parse_aria2_control_http(&raw), "parse http minimal");
        assert_eq!(parsed.piece_length, 1024 * 1024);
        assert_eq!(parsed.total_length, 10 * 1024 * 1024);
        assert_eq!(parsed.upload_length, 0);
        assert_eq!(parsed.bitfield, vec![0b1110_0000, 0x00]);
    }

    /// Vector H2 (positive): an HTTP file with 1 in-flight piece —
    /// parses successfully, the in-flight segment is discarded
    /// (validated before discard on load).
    #[test]
    fn vector_http_control_in_flight_validated_then_discarded() {
        let raw = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(0)
            .piece_length(256 * 1024)
            .total_length(2 * 256 * 1024)
            .upload_length(0)
            .bitfield(&[0b1000_0000])
            .finish_in_flight_count(1)
            .in_flight(1, 8, &[0b1000_0000])
            .bytes();
        let parsed = ok(parse_aria2_control_http(&raw), "parse http in-flight");
        assert_eq!(
            parsed.bitfield,
            vec![0b1000_0000],
            "in-flight segments do not mix into the bitmap"
        );
    }

    /// Vector H3 (routing face): extension bit0 set = a
    /// BT-migration-face file -> IsBitTorrent (the HTTP face never
    /// mixes reads).
    #[test]
    fn vector_http_control_rejects_bittorrent_extension() {
        let raw = HttpCtrlBuilder::new()
            .ext_bt()
            .info_hash_length(0)
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        assert_eq!(
            parse_aria2_control_http(&raw),
            Err(Aria2CtrlError::IsBitTorrent)
        );
    }

    /// Vector H4 (negative): version 0x0002 -> UnsupportedVersion.
    #[test]
    fn vector_http_control_future_version_rejected() {
        let raw = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(0)
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        let mut patched = raw;
        patched[1] = 0x02;
        assert_eq!(
            parse_aria2_control_http(&patched),
            Err(Aria2CtrlError::UnsupportedVersion(0x0002))
        );
    }

    /// Vector H5 (negative, load tolerance bound): infoHashLength > 20
    /// -> InvalidInfoHashLength (the reference's upper bound).
    #[test]
    fn vector_http_control_oversized_info_hash_length_rejected() {
        // The over-limit shape is rejected at the parser's infoHashLength
        // check (the builder does not backfill the in-flight count — the
        // layout is already out of bounds).
        let raw = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(21)
            .info_hash_bytes(21)
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .bytes();
        assert_eq!(
            parse_aria2_control_http(&raw),
            Err(Aria2CtrlError::InvalidInfoHashLength(21))
        );
        // Within tolerance (<= 20): a file carrying infoHash bytes parses
        // normally (the reference load reads and skips infoHashLength
        // bytes).
        let tolerated = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(20)
            .info_hash_bytes(20)
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        assert!(parse_aria2_control_http(&tolerated).is_ok());
    }

    /// Vector H6 (negative): pieceLength = 0 / bitfield length mismatch -> explicit errors.
    #[test]
    fn vector_http_control_geometry_violations_rejected() {
        let zero_piece = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(0)
            .piece_length(0)
            .total_length(0)
            .upload_length(0)
            .bitfield(&[])
            .finish_in_flight_count(0)
            .bytes();
        assert_eq!(
            parse_aria2_control_http(&zero_piece),
            Err(Aria2CtrlError::ZeroPieceLength)
        );
        let bad_bf = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(0)
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0, 0, 0])
            .finish_in_flight_count(0)
            .bytes();
        assert_eq!(
            parse_aria2_control_http(&bad_bf),
            Err(Aria2CtrlError::BitfieldLengthMismatch {
                expected: 1,
                actual: 3
            })
        );
    }

    /// Vector H7 (negative): bitfield truncated -> Truncated; trailing garbage ignored.
    #[test]
    fn vector_http_control_truncation_and_trailing_garbage() {
        let raw = HttpCtrlBuilder::new()
            .ext_http()
            .info_hash_length(0)
            .piece_length(1024)
            .total_length(1024)
            .upload_length(0)
            .bitfield(&[0])
            .finish_in_flight_count(0)
            .bytes();
        assert!(matches!(
            parse_aria2_control_http(&raw[..raw.len() - 1]),
            Err(Aria2CtrlError::Truncated { .. })
        ));
        let mut garbage = raw;
        garbage.extend_from_slice(b"tail");
        let parsed = ok(parse_aria2_control_http(&garbage), "parse trailing");
        assert_eq!(parsed.bitfield, vec![0]);
    }

    /// Fork HTTP row read face progress payloads: is_torrent=0 rows
    /// carry the piece bitmap/granularity/total length; rows without
    /// progress and torrent rows get progress = None (contract face).
    #[test]
    fn load_fork_http_tasks_carries_progress_only_for_http_rows() {
        let path = seed_fork_db("httpprog");
        {
            let conn = ok(Connection::open(&path), "open fixture");
            // HTTP row with progress (the fork writes task_progress for HTTP tasks too).
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, queue_position,
                                        digest, created_at, updated_at)
                     VALUES ('0000000000000042', 'waiting', 'http://a/f\n out=f\n dir=/dl\n',
                             0, x'00', 0, 0)",
                    [],
                ),
                "insert http task",
            );
            ok(
                conn.execute(
                    "INSERT INTO task_progress (gid, is_torrent, piece_length,
                                                total_length, bitfield, digest, updated_at)
                     VALUES ('0000000000000042', 0, 1048576, 10485760, x'11111111111111111111', x'00', 0)",
                    [],
                ),
                "insert http progress",
            );
            // HTTP row without a progress row (just added, no progress yet).
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, queue_position,
                                        digest, created_at, updated_at)
                     VALUES ('0000000000000043', 'paused', 'http://a/g\n out=g\n dir=/dl\n',
                             1, x'00', 0, 0)",
                    [],
                ),
                "insert http task 2",
            );
        }
        let conn = ok(open_fork_readonly(&path), "open ro");
        let rows = ok(load_fork_http_tasks(&conn), "load http rows");
        assert_eq!(rows.len(), 2, "rows: {rows:?}");
        assert_eq!(rows[0].gid, "0000000000000042");
        assert_eq!(rows[0].is_torrent, Some(false));
        let p = rows[0]
            .progress
            .as_ref()
            .unwrap_or_else(|| panic!("http row must carry progress"));
        assert_eq!((p.piece_length, p.total_length), (1048576, 10485760));
        assert_eq!(p.bitfield, vec![0x11; 10], "10 pieces -> a 10-byte bitmap");
        assert_eq!(rows[1].gid, "0000000000000043");
        assert_eq!(rows[1].progress, None, "no progress row -> None");
        let _ = std::fs::remove_file(&path);
    }

    // ---- Declared-length attack vectors: immediate Truncated with the
    // peak allocation bounded ----

    /// Maximum declarable value of the bitmap fixed-length formula:
    /// piece = 1, totalLength = 8 x u32::MAX -> expected bitmap =
    /// u32::MAX bytes (~4 GiB) — the full allocation reachable within
    /// the u32 declaration domain (the attack's declaration ceiling).
    #[test]
    fn bitfield_formula_declares_max_u32_len_for_tiny_piece() {
        assert_eq!(
            expected_bitfield_len(8 * u32::MAX as u64, 1),
            u32::MAX as u64
        );
    }

    /// HTTP face: a ~34-byte corrupt control file declares a 32 GiB
    /// total with 1-byte pieces -> an expected bitmap of ~4 GiB. Parsing
    /// rejects *immediately* with Truncated (rejection point = the
    /// bitmap bound: offset 34 / need = declared length / have = 0) —
    /// allocation is clamped to on-disk bytes by the parser's need-first
    /// ordering.
    #[test]
    fn vector_http_declared_length_attack_truncates_immediately() {
        let mut raw = Vec::with_capacity(34);
        raw.extend_from_slice(&[0x00, 0x01]); // version 0001
        raw.extend_from_slice(&0u32.to_be_bytes()); // extension bit0 = 0 (HTTP face)
        raw.extend_from_slice(&0u32.to_be_bytes()); // infoHashLength = 0 (non-BT save)
        raw.extend_from_slice(&1u32.to_be_bytes()); // pieceLength = 1 (smallest non-zero)
        raw.extend_from_slice(&(8 * u32::MAX as u64).to_be_bytes()); // declared total 32 GiB
        raw.extend_from_slice(&0u64.to_be_bytes()); // uploadLength
        raw.extend_from_slice(&u32::MAX.to_be_bytes()); // bitfieldLength = expected fixed length
        // EOF: every declared bitmap byte absent = the full declared
        // allocation attack (an earlier implementation committed a ~4 GiB
        // zeroed allocation before reporting truncation; with need first,
        // rejection happens before allocation).
        assert_eq!(
            parse_aria2_control_http(&raw),
            Err(Aria2CtrlError::Truncated {
                offset: 34,
                need: u32::MAX as usize,
                have: 0,
            })
        );
        // Partial supply (10 bitmap bytes present) rejected at the same
        // point — allocation still never passes the on-disk bytes.
        let mut partial = raw.clone();
        partial.extend_from_slice(&[0u8; 10]);
        assert_eq!(
            parse_aria2_control_http(&partial),
            Err(Aria2CtrlError::Truncated {
                offset: 34,
                need: u32::MAX as usize,
                have: 10,
            })
        );
    }

    /// BT face: the same attack vector — a ~54-byte file with extension
    /// bit0 set and a 20-byte infoHash declaring a ~4 GiB fixed length ->
    /// immediate Truncated (offset 54 / need = declared length /
    /// have = 0).
    #[test]
    fn vector_bt_declared_length_attack_truncates_immediately() {
        let mut raw = Vec::with_capacity(54);
        raw.extend_from_slice(&[0x00, 0x01]); // version 0001
        raw.extend_from_slice(&1u32.to_be_bytes()); // extension bit0 = 1 (BT face)
        raw.extend_from_slice(&20u32.to_be_bytes()); // infoHashLength = 20
        raw.extend_from_slice(&sample_ih()); // infoHash
        raw.extend_from_slice(&1u32.to_be_bytes()); // pieceLength = 1
        raw.extend_from_slice(&(8 * u32::MAX as u64).to_be_bytes()); // declared total 32 GiB
        raw.extend_from_slice(&0u64.to_be_bytes()); // uploadLength
        raw.extend_from_slice(&u32::MAX.to_be_bytes()); // bitfieldLength = expected fixed length
        assert_eq!(
            parse_aria2_control(&raw),
            Err(Aria2CtrlError::Truncated {
                offset: 54,
                need: u32::MAX as usize,
                have: 0,
            })
        );
    }
}

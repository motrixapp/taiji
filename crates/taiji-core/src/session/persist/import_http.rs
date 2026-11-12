//! HTTP-side core of the fork migration importer (`taiji import`):
//! fork sqlite `task` rows with `is_torrent=0` (HTTP/FTP tasks) become
//! `http_task` rows in the target `taiji.sqlite3`, written only through
//! the existing PersistWriter seam ([`super::import::apply_import`] /
//! [`apply_http_import`] never bypass the persistence face).
//!
//! Covers `task.serialized` parsing (fork write side `SessionSerializer.cc`,
//! read side `UriListParser.cc`), the serialized->http_task mapping,
//! piece->block bitmap mapping, `.aria2` orphan reconciliation, the
//! preflight checklist, dedup, and the single-command orchestration.
//! Upstream anchor mapping: docs/design/core.md.
//!
//! Hard invariants:
//! - the dedup criterion lives on the task row: row present + key equal =
//! skip and point back at the old GID; row absent = re-import allowed
//! (no dead-marker form exists);
//! - piece->block mapping follows the complete-coverage rule: partially
//! covered blocks are dropped and re-downloaded, progress is never
//! over-reported; a failed bitmap validation drops progress explicitly
//! to a weak resume;
//! - dry-run is read-only against the target database (never opened
//! through PersistWriter, so no migration-ledger advance); the
//! pre-import `.v1.bak` backup is kept, never overwritten;
//! - orphan `.aria2` control files are reported and left untouched on
//! disk; they never become silent broken rows.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tracing::warn;

use taiji_http::naming::{AUTO_RENAME_MAX_TRIES, renamed_candidate};
// The fd-scan face uses the `fork_import` module path directly; the
// persist re-export surface stays untouched.
use taiji_store::persist::fork_import::ForkLiveness;
use taiji_store::persist::{
    Aria2CtrlError, Aria2HttpControl, ForkHttpTaskRow, ForkTaskState, HttpTaskRow, ImportBackup,
    ImportTargetProbe, ImportTargetSnapshot, PersistHandle, TaskPhase, backup_target_db,
    collect_aria2_files, load_fork_http_tasks, open_fork_readonly, parse_aria2_control_http,
    probe_fork_readonly, probe_import_target_readonly,
    read_import_target_snapshot as read_target_snapshot_impl,
};

use super::import::{AppliedTask, ImportSource};
use super::import_bitmap::map_pieces_to_blocks;
use super::now_epoch;
use crate::session::actor::http_task::{HttpPersistConfig, mirrors_json_of};
use crate::session::actor::sanitize_out_option;
use crate::session::http::{ValidatorFacts, url_path, validator_digest};

/// Import preflight checklist (contract copy consumed by the CLI report
/// and docs; item-for-item it matches the checklist in
/// docs/design/core.md).
pub const PREFLIGHT_CHECKLIST: &[&str] = &[
    "fork process must be exited: the preflight is three-layered     §10.2 r6.8) — (1) a held sqlite write lock refuses (SQLITE_BUSY); (2) \
     a live-fork fd scan refuses and reports the pid when any process \
     still holds the fork db/-wal/-shm open (macOS lsof / Linux procfs; \
     WAL-idle forks hold no lock, the fd scan is the catch); (3) when the \
     scan cannot prove the fork is closed (unsupported platform / lsof \
     absent) import refuses by default — pass --i-know-fork-is-closed to \
     accept responsibility; the flag never overrides layers (1)/(2)",
    "Motrix .motrix/p/<id> data must be moved into place BEFORE `taiji \
     import`: tasks are restored verbatim at their recorded paths; importing \
     before the data move breaks task paths (per-task explicit failure, never \
     a silently broken link)",
    "target database must be offline: a live or uncleanly-exited taiji \
     session leaves -wal/-shm sidecar files and the pre-import backup \
     refuses (stop the local taiji session first; a clean shutdown removes \
     the sidecars)",
    "pre-import backup is automatic: taiji.sqlite3 -> taiji.sqlite3.v1.bak \
     (rollback anchor; an existing backup is kept, never overwritten)",
    "imported HTTP tasks carry a piece->block mapped bitmap when fork \
     progress survives the complete-coverage rule (partial blocks are \
     dropped, never faked; unmappable progress is explicitly dropped to a \
     weak resume); trust is still decided by the resume validator and the \
     existence+size second line of defense at activation — any mismatch \
     restarts from zero",
    "fork partial data is adopted as the resume input at import: for \
     tasks carrying imported bitmap progress the data file <out> is \
     renamed to <out>.part (if free) so activation can resume from it; \
     when a .part already exists both files are kept as-is and activation \
     reports a path conflict instead of renaming (auto-file-renaming is \
     disabled for imported-progress tasks)",
    "imported request-identity options are folded back in at activation: \
     header/user-agent/proxy/credentials from the migrated inventory \
     drive the restored task's requests (same parse and rejection rules \
     as addUri; socks proxies are rejected explicitly — the task fails \
     instead of silently bypassing its proxy)",
    "fork cookies are NOT migrated: the serialized task format carries \
     no cookies, so imported tasks restart with an empty per-task cookie \
     jar and re-learn cookies from Set-Cookie at activation — \
     cookie-gated sources may need the session re-established by the \
     source (declared breakage, never silently faked)",
];

/// Parsed `serialized` payload (first-line URIs plus option lines; plain
/// data).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedSerialized {
    /// First-line URIs (TAB/space separated, order-preserving, deduped —
    /// the writer-side `Unique` predicate follows the same rule).
    pub uris: Vec<String>,
    /// Option key/value pairs (order- and duplicate-preserving; cumulative
    /// options keep one entry per line). `gid=` lines are excluded (fork
    /// GIDs are not migrated; see the mapping table in
    /// docs/design/core.md).
    pub options: Vec<(String, String)>,
}

/// Parse `serialized` text (mirrors the fork `UriListParser.cc` behavior:
/// empty/`#` lines skipped, a leading space/TAB marks an option line,
/// anything else is a URI line; empty input tolerated). Missing data
/// beats wrong data: option lines without `=` are ignored, never fatal.
pub fn parse_serialized(text: &str) -> ParsedSerialized {
    let mut out = ParsedSerialized::default();
    let mut uri_line_seen = false;
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            let body = line.trim_start_matches([' ', '\t']);
            let Some((key, value)) = body.split_once('=') else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() || key == "gid" {
                continue;
            }
            out.options.push((key.to_string(), value.to_string()));
            continue;
        }
        // URI line: only the first counts (one segment per task in the
        // fork format); later URI lines are ignored, not passed off as
        // options.
        if uri_line_seen {
            continue;
        }
        uri_line_seen = true;
        for uri in line.split(['\t', ' ']).filter(|u| !u.is_empty()) {
            if !out.uris.iter().any(|u| u == uri) {
                out.uris.push(uri.to_string());
            }
        }
    }
    out
}

/// URI schemes the HTTP face accepts (same domain as addUri:
/// http(s)/ftp(s) — `ftps://` is not an accepted scheme, express it as
/// `ftp://` plus `--ftp-ssl`; see the actor/tasks.rs acceptance face).
fn supported_scheme(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("ftp://")
}

/// Fork progress facts (input to the piece->block bitmap mapping; both
/// sources share the shape: `task_progress` rows and non-BT `.aria2`
/// control files).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProgressFacts {
    pub piece_length: u64,
    pub total_length: u64,
    /// MSB-first piece bitmap (fork/aria2 `BitfieldMan` encoding; fixed
    /// length = `expected_bitfield_len(total, piece)`).
    pub bitfield: Vec<u8>,
}

impl HttpProgressFacts {
    /// From a fork `task_progress` payload (a negative column means the
    /// row was tampered with -> None, no mapping input).
    fn from_fork(p: &taiji_store::persist::ForkProgress) -> Option<Self> {
        if p.piece_length <= 0 || p.total_length < 0 {
            return None;
        }
        Some(HttpProgressFacts {
            piece_length: p.piece_length as u64,
            total_length: p.total_length as u64,
            bitfield: p.bitfield.clone(),
        })
    }

    /// From a non-BT `.aria2` control file (the parser guarantees the
    /// bitmap length).
    fn from_ctrl(c: &Aria2HttpControl) -> Self {
        HttpProgressFacts {
            piece_length: u64::from(c.piece_length),
            total_length: c.total_length,
            bitfield: c.bitfield.clone(),
        }
    }
}

/// One collected HTTP source task (the dedup key is fixed inside the
/// blocking collect context — canonicalize is IO).
#[derive(Debug, Clone, PartialEq)]
pub struct HttpSourceTask {
    pub source: ImportSource,
    /// Deterministic dedup key (stored on the task row as the
    /// `origin_fork_key` criterion; same key space as the
    /// `session_kv.imported_from` reverse index).
    pub source_key: String,
    pub fork_gid: Option<String>,
    /// Queue order (fork `queue_position` — fork queue order becomes the
    /// import order).
    pub queue_pos: i64,
    /// Source URIs with an accepted scheme (order-preserving, deduped;
    /// the first item -> the row's `url` column).
    pub uris: Vec<String>,
    /// URIs with an unsupported scheme (surfaced in the report, never
    /// silently dropped).
    pub unsupported_uris: Vec<String>,
    /// Download directory (`serialized dir=` first, CLI `--dir` fallback;
    /// verified on disk during collection — the per-task enforcement point
    /// of preflight item 2).
    pub dir: String,
    /// `serialized out=` (last value wins for a repeated key — aria2
    /// Option::put overwrite semantics; empty = unset, derived from the
    /// URI/Content-Disposition at activation, same as addUri).
    pub out: Option<String>,
    /// Pause face (fork state="paused" OR `serialized pause=true`).
    pub paused: bool,
    /// Migrated inventory options (key/value pairs verbatim, except
    /// dir/out/pause/gid).
    pub options: Vec<(String, String)>,
    /// Fork progress facts (bitmap-mapping input; None = no progress row,
    /// weak resume). `.aria2` orphan reconciliation
    /// ([`crate::session::persist::import_http::reconcile_aria2_orphans`])
    /// may fill progress for a row without one.
    pub progress: Option<HttpProgressFacts>,
}

/// One directory-scan/row-collection result (broken and failed rows are
/// surfaced explicitly — never stored silently).
#[derive(Debug, Clone, PartialEq)]
pub enum HttpCollectEntry {
    /// Box: suppresses large_enum_variant (the Ready payload dwarfs the
    /// skip/fail faces).
    Ready(Box<HttpSourceTask>),
    /// A normal skip (BT-face task, no accepted source, ...) — shown in
    /// the report.
    Skipped {
        source: ImportSource,
        reason: String,
    },
    /// An explicit failure (data-move ordering precondition unmet /
    /// directory unreachable — broken links are never stored).
    Failed {
        source: ImportSource,
        reason: String,
    },
}

/// Fork DB HTTP-face collection (read-only; the lock probe runs first as
/// in [`collect_fork_all_tasks`]; this face is a projection of it — the
/// single command uses the merged face, this entry remains for targeted
/// dry runs/tests). Returns (total fork task rows, HTTP candidate
/// entries).
pub async fn collect_fork_http_tasks(
    db_path: PathBuf,
    fallback_dir: PathBuf,
) -> Result<(i64, Vec<HttpCollectEntry>), String> {
    let fc = collect_fork_all_tasks(db_path, fallback_dir).await?;
    Ok((fc.total_tasks, fc.http))
}

/// Single-command, both-face collection (the `taiji import` merge point,
/// shared with the BT import): one read-only open of the fork DB with the
/// lock probe (preflight item 1) forced first; the BT face
/// (`load_fork_bt_tasks`) and the HTTP face ([`load_fork_http_tasks`])
/// partition the rows — the union of both read faces equals the
/// `count_fork_tasks` total; `bt.len() + http.len()` falling short of the
/// total = filtered rows (BT tasks without progress).
pub async fn collect_fork_all_tasks(
    db_path: PathBuf,
    fallback_dir: PathBuf,
) -> Result<ForkCollect, String> {
    use taiji_store::persist::load_fork_bt_tasks;
    tokio::task::spawn_blocking(move || {
        let total = probe_fork_readonly(&db_path)
            .map_err(|e| format!("probe fork db {}: {e}", db_path.display()))?;
        let conn = open_fork_readonly(&db_path)
            .map_err(|e| format!("open fork db {}: {e}", db_path.display()))?;
        let bt = load_fork_bt_tasks(&conn).map_err(|e| format!("read fork db bt tasks: {e}"))?;
        let http_rows =
            load_fork_http_tasks(&conn).map_err(|e| format!("read fork db tasks: {e}"))?;
        let bt_tasks = bt
            .iter()
            .filter_map(|t| super::import::source_task_from_fork(t, &db_path, &fallback_dir))
            .collect();
        let http = http_rows
            .iter()
            .map(|row| http_collect_entry(row, &db_path, &fallback_dir))
            .collect();
        Ok(ForkCollect {
            total_tasks: total,
            bt: bt_tasks,
            http,
        })
    })
    .await
    .map_err(|e| format!("fork db collect join: {e}"))?
}

/// Both-face collection output (BT assembly candidates + classified HTTP
/// entries; a plain-data handoff — persistence goes through
/// [`super::import::apply_import`] / [`apply_http_import`] respectively).
#[derive(Debug, Clone, PartialEq)]
pub struct ForkCollect {
    /// Total fork `task` rows (the basis of the report's "all rows"
    /// figure).
    pub total_tasks: i64,
    /// BT-face candidates.
    pub bt: Vec<super::import::SourceTask>,
    /// HTTP-face entries (Ready/Skipped/Failed classification, never
    /// silent).
    pub http: Vec<HttpCollectEntry>,
}

/// Fork HTTP row -> collect entry (classification + path check; disk IO —
/// the caller must run in a `spawn_blocking` context).
fn http_collect_entry(
    row: &ForkHttpTaskRow,
    db_path: &std::path::Path,
    fallback_dir: &std::path::Path,
) -> HttpCollectEntry {
    let source = ImportSource::ForkDb {
        db_path: db_path.to_path_buf(),
        fork_gid: row.gid.clone(),
    };
    // A torrent row without info_hash = a BT task whose metadata fetch
    // never completed (unrecoverable by either import face) — skip it
    // accurately instead of passing it off as an HTTP task.
    if row.is_torrent == Some(true) {
        return HttpCollectEntry::Skipped {
            source,
            reason: "BitTorrent task whose metadata fetch never completed (no \
                     task_progress info_hash): nothing recoverable by either \
                     import face"
                .to_string(),
        };
    }
    let parsed = parse_serialized(&row.serialized);
    // Scheme accounting: accepted sources vs explicitly dropped sources
    // (metalink/local metadata/magnet/etc.).
    let mut uris = Vec::new();
    let mut unsupported = Vec::new();
    for uri in &parsed.uris {
        if supported_scheme(uri) {
            uris.push(uri.clone());
        } else {
            unsupported.push(uri.clone());
        }
    }
    if uris.is_empty() {
        let reason = if parsed
            .uris
            .first()
            .is_some_and(|u| u.to_ascii_lowercase().starts_with("magnet:"))
        {
            "no supported URI (http/https/ftp) in serialized first line: magnet \
             task belongs to the BitTorrent face and has no importable progress \
             without task_progress info_hash"
                .to_string()
        } else {
            "no supported URI (http/https/ftp) in serialized first line: \
             metalink/local-metadata sources are not recoverable from \
             serializedweak-resume declaration)"
                .to_string()
        };
        return HttpCollectEntry::Skipped { source, reason };
    }
    // Option accounting: dir/out/pause get dedicated slots (columns/state);
    // everything else goes verbatim into the inventory. The parked seed
    // reads `row.state` through the fork archive vocabulary's parse face
    // ([`ForkTaskState::parse`]) — an unknown fork state (hand-edited /
    // unknown-schema database) is explicit, never silent: warn (fork gid
    // + the raw value) and land the task **paused** — the conservative
    // state (an import whose archived intent cannot be read must not
    // silently auto-start; the user sees the parked row and unpauses it).
    let mut dir_opt = None;
    let mut out_opt = None;
    let mut paused = match ForkTaskState::parse(&row.state) {
        Ok(ForkTaskState::Paused) => true,
        Ok(ForkTaskState::Waiting) => false,
        Err(e) => {
            warn!(target: "taiji::core::persist", fork_gid = %row.gid, %e,
                "fork http task state outside the paused|waiting archive domain; \
                 imported paused (conservative state)");
            true
        }
    };
    let mut options = Vec::new();
    for (key, value) in &parsed.options {
        match key.as_str() {
            "dir" => dir_opt = Some(value.clone()),
            "out" => out_opt = Some(value.clone()),
            "pause" => paused = paused || value == "true",
            _ => options.push((key.clone(), value.clone())),
        }
    }
    let dir = dir_opt.unwrap_or_else(|| fallback_dir.display().to_string());
    // Enforcement point of preflight item 2 (the .motrix/p/<id> data-move
    // ordering): a directory missing on disk = the data is not in place —
    // this task fails explicitly (broken-link copy), never stored
    // silently.
    match std::fs::metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return HttpCollectEntry::Failed {
                source,
                reason: format!(
                    "download dir {dir} does not exist: recorded paths are \
                     restored verbatim — move the Motrix .motrix/p/<id> data \
                     into place before import (task would otherwise be a \
                     broken link)"
                ),
            };
        }
        Err(e) => {
            return HttpCollectEntry::Failed {
                source,
                reason: format!("stat download dir {dir}: {e}"),
            };
        }
        Ok(meta) if !meta.is_dir() => {
            return HttpCollectEntry::Failed {
                source,
                reason: format!("download dir {dir} is not a directory"),
            };
        }
        Ok(_) => {}
    }
    HttpCollectEntry::Ready(Box::new(HttpSourceTask {
        source_key: source.source_key(),
        fork_gid: Some(row.gid.clone()),
        queue_pos: row.queue_position,
        paused,
        uris,
        unsupported_uris: unsupported,
        dir,
        out: out_opt,
        options,
        progress: row.progress.as_ref().and_then(HttpProgressFacts::from_fork),
        source,
    }))
}

/// One `.aria2` orphan-reconciliation result (disposition semantics in
/// docs/design/core.md, "`.aria2` orphan reconciliation").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aria2Reconciliation {
    /// A sqlite row matched — merged (`fork_gid` = the matched row;
    /// `progress_filled` = the row had no progress and the control file
    /// filled it). Produces no second import entry.
    Reconciled {
        ctrl_path: PathBuf,
        /// The target output path with the `.aria2` suffix stripped.
        output_path: PathBuf,
        fork_gid: String,
        total_length: u64,
        progress_filled: bool,
        /// The paired data file exists on disk (whether orphan progress
        /// has data to carry it).
        data_present: bool,
    },
    /// No matching row — an orphan. Reported separately in dry-run; a real
    /// import produces no row (the control-file format carries no URI, so
    /// a URI-less row would be a silent broken task); the file and its
    /// data stay untouched (read-only discipline).
    Orphan {
        ctrl_path: PathBuf,
        output_path: PathBuf,
        total_length: u64,
        data_present: bool,
    },
    /// A BT-migration-face file (extension bit 0 set) — belongs to the BT
    /// ctrl-import face.
    BitTorrentFace { ctrl_path: PathBuf },
    /// Corrupt/unreadable — an explicit failure entry (never silent).
    Failed { ctrl_path: PathBuf, reason: String },
}

/// Reconciliation report (the report face presents entries by type).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Aria2ReconciliationReport {
    pub entries: Vec<Aria2Reconciliation>,
}

impl Aria2ReconciliationReport {
    pub fn reconciled_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e, Aria2Reconciliation::Reconciled { .. }))
            .count()
    }

    pub fn orphan_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e, Aria2Reconciliation::Orphan { .. }))
            .count()
    }
}

/// Directory-spelling normalization (a canonicalize failure falls back to
/// the original spelling — the same rule as the import dedup key).
fn canonical_or_raw_dir(dir: &Path) -> String {
    match std::fs::canonicalize(dir) {
        Ok(c) => c.display().to_string(),
        Err(_) => dir.display().to_string(),
    }
}

/// Reconcile one control file (disk IO — the caller must run in a
/// `spawn_blocking` context; Ready entries' progress may be filled by the
/// merge).
fn reconcile_one_ctrl(ctrl_path: &Path, entries: &mut [HttpCollectEntry]) -> Aria2Reconciliation {
    let bytes = match std::fs::read(ctrl_path) {
        Ok(b) => b,
        Err(e) => {
            return Aria2Reconciliation::Failed {
                ctrl_path: ctrl_path.to_path_buf(),
                reason: format!("read: {e}"),
            };
        }
    };
    let ctrl = match parse_aria2_control_http(&bytes) {
        Ok(c) => c,
        Err(Aria2CtrlError::IsBitTorrent) => {
            return Aria2Reconciliation::BitTorrentFace {
                ctrl_path: ctrl_path.to_path_buf(),
            };
        }
        Err(e) => {
            return Aria2Reconciliation::Failed {
                ctrl_path: ctrl_path.to_path_buf(),
                reason: format!("parse: {e}"),
            };
        }
    };
    // Output path = the `.aria2` suffix stripped (naming semantics from
    // message.h; the BT ctrl face applies the same `set_extension("")`).
    let mut target = ctrl_path.to_path_buf();
    target.set_extension("");
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let Some(file_name) = target.file_name().and_then(|n| n.to_str()) else {
        return Aria2Reconciliation::Failed {
            ctrl_path: ctrl_path.to_path_buf(),
            reason: "control file target name is not valid UTF-8".to_string(),
        };
    };
    let dir_key = canonical_or_raw_dir(dir);
    let data_present = target.exists();
    // Length-corroboration input for merging progress-less rows: the
    // on-disk data file length is the only length fact comparable against
    // the control file's totalLength.
    let data_len = std::fs::metadata(&target).ok().map(|m| m.len());
    // Reconciliation key = totalLength + output path. When the row has no
    // progress, a path hit + length corroboration merges (the
    // task_progress write-failure window — with corroboration the control
    // file's total becomes authoritative for that row; data on disk with
    // a different length = a different download generation on the same
    // path, not merged).
    for entry in entries.iter_mut() {
        let HttpCollectEntry::Ready(task) = entry else {
            continue;
        };
        let Some(out) = task.out.as_deref().filter(|o| !o.is_empty()) else {
            continue; // out unset: the name is only fixed at activation, no path to reconcile
        };
        if canonical_or_raw_dir(Path::new(&task.dir)) != dir_key || out != file_name {
            continue;
        }
        let progress_filled = task.progress.is_none();
        if let Some(p) = &task.progress {
            if p.total_length != ctrl.total_length {
                continue; // total length mismatch = a foreign source (another generation on this path), not merged
            }
        } else {
            // Key corroboration: merging a progress-less row additionally
            // requires "on-disk data length == ctrl totalLength" — the row
            // side has no total to compare, so the on-disk length is the
            // only totalLength half-fact; mismatch = another generation on
            // the same path, not merged (missing beats wrong: a foreign
            // bitmap is never folded into the row payload). Data absent =
            // no length fact to compare, so the path hit keeps the merge
            // (the rescue face for the task_progress write-failure window —
            // a row that just started and laid down no data is not lost
            // for lack of corroboration).
            if data_len.is_some_and(|len| len != ctrl.total_length) {
                continue;
            }
            task.progress = Some(HttpProgressFacts::from_ctrl(&ctrl));
        }
        return Aria2Reconciliation::Reconciled {
            ctrl_path: ctrl_path.to_path_buf(),
            output_path: target.clone(),
            fork_gid: task.fork_gid.clone().unwrap_or_default(),
            total_length: ctrl.total_length,
            progress_filled,
            data_present,
        };
    }
    Aria2Reconciliation::Orphan {
        ctrl_path: ctrl_path.to_path_buf(),
        output_path: target,
        total_length: ctrl.total_length,
        data_present,
    }
}

/// `.aria2` orphan reconciliation: scan every control file under
/// `scan_dir` (recursive, lexicographically stable) and classify it
/// against the HTTP import candidates by the key (totalLength + output
/// path) — a hit merges (and may fill the bitmap payload of a
/// progress-less row), no match is reported as an orphan. Disposition
/// semantics in docs/design/core.md. Entries move by value
/// (`spawn_blocking` ownership); returns (reconciled entries, report).
pub async fn reconcile_aria2_orphans(
    scan_dir: PathBuf,
    entries: Vec<HttpCollectEntry>,
) -> Result<(Vec<HttpCollectEntry>, Aria2ReconciliationReport), String> {
    tokio::task::spawn_blocking(move || {
        let files = collect_aria2_files(&scan_dir)
            .map_err(|e| format!("scan {}: {e}", scan_dir.display()))?;
        let mut entries = entries;
        let mut report = Aria2ReconciliationReport::default();
        for path in files {
            report.entries.push(reconcile_one_ctrl(&path, &mut entries));
        }
        Ok((entries, report))
    })
    .await
    .map_err(|e| format!("aria2 reconcile join: {e}"))?
}

/// Second-import path-conflict action (a same dir+out conflict is decided
/// in the dry-run report; the default Skip = report only, never a silent
/// overwrite).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathConflictAction {
    /// Skip the conflicting task (shown in the report; the user resolves
    /// it manually afterwards).
    #[default]
    Skip,
    /// Rename via the aria2 candidate-name algorithm (`out.1` shape,
    /// `RequestGroup.cc`, via taiji-http `renamed_candidate`); exhausted
    /// candidates = an explicit failure.
    Rename,
}

/// One fully planned import (rows assembled, waiting for
/// [`apply_http_import`]).
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedHttpImport {
    pub source: ImportSource,
    pub source_key: String,
    pub fork_gid: Option<String>,
    /// The new taiji GID (hex16, top bit set; fork GIDs are not
    /// inherited).
    pub gid: String,
    /// Stored state: queued | paused.
    pub state: String,
    pub dir: String,
    pub out: String,
    /// Number of accepted source URIs (report face).
    pub uri_count: usize,
    /// Explicit warnings (unsupported-URI drops / weak-resume declaration
    /// — report only, not failures).
    pub warnings: Vec<String>,
    /// The http_task row (the only persisted payload).
    pub row: HttpTaskRow,
}

/// One planning result (dedup/conflict/sanitizing failures each land in
/// their own class; a failure does not block the batch).
#[derive(Debug, Clone, PartialEq)]
pub enum HttpPlanEntry {
    Planned(Box<PlannedHttpImport>),
    Skipped {
        source: ImportSource,
        reason: String,
    },
    Failed {
        source: ImportSource,
        reason: String,
    },
}

/// Per-batch planner: holds the `(dir,out)` occupancy set (in-flight
/// target rows + earlier tasks of this batch); first-wins semantics, from
/// the same lineage as the metalink (dir,out) dedup precedent.
pub struct HttpImportPlanner {
    occupied: BTreeSet<(String, String)>,
}

impl HttpImportPlanner {
    /// Seed with the `(dir,out)` set of existing in-flight http_task rows
    /// (the caller obtains it via `load_http_tasks_at_startup`; terminal
    /// rows are not in-flight and do not occupy).
    pub fn new(existing: impl IntoIterator<Item = (String, String)>) -> Self {
        HttpImportPlanner {
            occupied: existing.into_iter().collect(),
        }
    }

    /// Plan one task (the pure half: no disk IO — disk-level conflicts
    /// belong to activation-time `plan_output`; this decision only
    /// reconciles the task-face occupancy).
    ///
    /// Decision order:
    /// 1. dedup (kv hit) -> Skipped (points back at the old GID);
    /// 2. `out` sanitizing (the same rules as addUri) -> violation = Failed;
    /// 3. `(dir,out)` occupancy conflict -> Skip/Rename per the action;
    /// 4. assemble the row (weak resume: bitmap/progress/probe payloads
    ///    empty, the warning made explicit).
    pub fn plan(&mut self, input: HttpPlanInput<'_>) -> HttpPlanEntry {
        let HttpPlanInput {
            task,
            gid_hex,
            imported_gid,
            conflict_action,
        } = input;
        // Dedup (hit = row present + key equal) -> Skipped, pointing back
        // at the old GID. The criterion lives on the row: `origin_fork_key`
        // in the row's config_json (stamped by this planner on every
        // planned row, see below); row absent = the criterion disappears
        // with it, re-import allowed — no dead-marker form exists.
        // `imported_gid` must come from a liveness-checked read face (dead
        // back-references from the kv reverse-index fallback are treated
        // as not-imported by the store read face after a liveness check:
        // cleared at the delete close-out; the dry-run snapshot checks
        // liveness + notes stale keys in `stale_imported`), so a hit
        // reaching this planner is always a live back-reference.
        if let Some(prev_gid) = imported_gid {
            return HttpPlanEntry::Skipped {
                source: task.source.clone(),
                reason: format!(
                    "already imported (origin_fork_key row hit) -> {prev_gid} \
                     (criterion is the task row: row present + key equal = skip; \
                     row absent = re-import allowed — session_kv.imported_from \
                     is only a reverse index)"
                ),
            };
        }
        if task.uris.is_empty() {
            // Already filtered at collection; a direct-call defense (a row
            // with no accepted source never yields an empty url).
            return HttpPlanEntry::Failed {
                source: task.source.clone(),
                reason: "no supported URI (http/https/ftp) to import".to_string(),
            };
        }
        let out = match &task.out {
            Some(raw) if !raw.is_empty() => match sanitize_out_option(raw) {
                Ok(name) => name,
                Err(e) => {
                    return HttpPlanEntry::Failed {
                        source: task.source.clone(),
                        reason: format!("serialized out= violates the output-name domain: {e}"),
                    };
                }
            },
            _ => String::new(),
        };
        let mut warnings = Vec::new();
        if !task.unsupported_uris.is_empty() {
            warnings.push(format!(
                "unsupported URI(s) dropped: {}",
                task.unsupported_uris.join(", ")
            ));
        }
        // piece->block bitmap mapping (the complete-coverage rule; see the
        // bitmap section in docs/design/core.md): trusted progress -> the
        // row's bitmap payload + an imported-progress note; mapping
        // failure -> progress dropped explicitly (missing beats wrong),
        // degraded to a weak resume; no progress -> the weak-resume
        // declaration.
        let mapped = match &task.progress {
            Some(p) => match map_pieces_to_blocks(&p.bitfield, p.piece_length, p.total_length) {
                Ok(m) => {
                    warnings.push(format!(
                        "imported progress: {}/{} blocks @ {}-byte grid \
                         (piece->block complete-coverage mapping)",
                        m.bitmap.iter().map(|b| b.count_ones()).sum::<u32>(),
                        m.block_count,
                        m.block_size
                    ));
                    Some(m)
                }
                Err(e) => {
                    warnings.push(format!(
                        "fork progress dropped (bitmap validation failed: \
                         {e}): weak resume"
                    ));
                    None
                }
            },
            None => {
                warnings.push(
                    "weak resume: no piece->block bitmap carried (re-probe \
                     and download from zero)"
                        .to_string(),
                );
                None
            }
        };
        // Path-conflict reconciliation (when out is unset the name is only
        // fixed at activation and cannot be pre-reconciled — that face is
        // explicitly skipped; disk/naming conflicts are closed by the
        // engine's creation-time checks).
        let mut out = out;
        if !out.is_empty() && self.occupied.contains(&(task.dir.clone(), out.clone())) {
            match conflict_action {
                PathConflictAction::Skip => {
                    return HttpPlanEntry::Skipped {
                        source: task.source.clone(),
                        reason: format!(
                            "path conflict: {}/{} is occupied by another task \
                             (second-import adjudication = skip)",
                            task.dir, out
                        ),
                    };
                }
                PathConflictAction::Rename => {
                    let Some(renamed) = rename_candidate(&task.dir, &out, &self.occupied) else {
                        return HttpPlanEntry::Failed {
                            source: task.source.clone(),
                            reason: format!(
                                "path conflict: {}/{} occupied and candidate \
                                 names exhausted ({} tries)",
                                task.dir, out, AUTO_RENAME_MAX_TRIES
                            ),
                        };
                    };
                    warnings.push(format!("renamed {out} -> {renamed} (path conflict)"));
                    out = renamed;
                }
            }
        }
        let cfg = HttpPersistConfig {
            imported_options: Some(task.options.clone()),
            // Bitmap rows set the flag — the criterion bit that disables
            // auto-rename at activation (adopted data meeting an existing
            // final file is an explicit conflict, never a silent rename
            // into a broken link) and degrades the digest gate (closed by
            // the "existence+size" second line of defense); weak-resume
            // rows write false as no key (zero drift on existing
            // payloads).
            imported_progress: mapped.is_some(),
            // The dedup key is stored with the row ("the dedup key is
            // stored with the task row") — row present + key equal = skip;
            // row absent = re-import allowed. Stamped in both the bitmap
            // and weak-resume states (dedup and the progress payload are
            // orthogonal).
            origin_fork_key: Some(task.source_key.clone()),
            ..HttpPersistConfig::default()
        };
        // Admission phase through the unified vocabulary's enum (the row
        // word serializes only at the row/report payloads below).
        let phase = if task.paused {
            TaskPhase::Paused
        } else {
            TaskPhase::Queued
        };
        // Bitmap payload (the successful-mapping face): block granularity
        // = the largest power-of-two factor of the piece clamped into
        // 256KiB..16MiB (the task-level immutable row contract);
        // counts/bitmap/done-bytes match the grid.rs semantics. The
        // validator digest is seeded with the facts known at import (the
        // first URI path + total length, no strong-validator facts) —
        // first activation uses the degraded gate (the fork leaves no
        // strong validator while real servers always send
        // etag/last_modified, so the seeded digest would certainly drift;
        // bitmap trust is decided by the "existence+size" second line of
        // defense); after the first-activation probe the measured facts
        // backfill and later resumes return to the strong gate. The
        // mapping creates no shortcut around resume trust.
        let validator = mapped.as_ref().map(|_| {
            validator_digest(&ValidatorFacts {
                final_url_path: url_path(&task.uris[0]).to_string(),
                total_len: Some(task.progress.as_ref().map_or(0, |p| p.total_length)),
                etag: None,
                last_modified: None,
                encoding_ok: true,
            })
            .ok()
        });
        let row = HttpTaskRow {
            gid: gid_hex.clone(),
            url: task.uris[0].clone(),
            // Probe payload empty: resume = re-probe (final_url/probe are
            // backfilled by the activation face).
            final_url: String::new(),
            mirrors_json: mirrors_json_of(&task.uris),
            state: phase.as_v1_str().to_string(),
            queue_pos: task.queue_pos,
            dir: task.dir.clone(),
            out,
            config_json: cfg.to_json(),
            probe_json: None,
            validator_digest: validator.unwrap_or(None),
            // A zero block-size row value = the resume face falls back to
            // the default granularity (the weak-resume row contract).
            block_size: mapped
                .as_ref()
                .map_or(0, |m| m.block_size.min(i64::MAX as u64) as i64),
            block_bitmap: mapped.as_ref().map(|m| m.bitmap.clone()),
            block_count: mapped
                .as_ref()
                .map(|m| m.block_count.min(i64::MAX as u64) as i64),
            total_done: mapped
                .as_ref()
                .map_or(0, |m| m.done_bytes.min(i64::MAX as u64) as i64),
            error_code: None,
            error_msg: None,
            created_at: now_epoch(),
            updated_at: now_epoch(),
        };
        // Register occupancy after the row is built (a Rename candidate is
        // already folded into row.out; tasks with out unset get their name
        // at activation and do not occupy the pre-reconciliation face).
        if !row.out.is_empty() {
            self.occupied.insert((row.dir.clone(), row.out.clone()));
        }
        HttpPlanEntry::Planned(Box::new(PlannedHttpImport {
            source: task.source.clone(),
            source_key: task.source_key.clone(),
            fork_gid: task.fork_gid.clone(),
            gid: gid_hex,
            state: phase.as_v1_str().to_string(),
            dir: task.dir.clone(),
            out: row.out.clone(),
            uri_count: task.uris.len(),
            warnings,
            row,
        }))
    }
}

/// Planning input bundle (the GID is allocated by the caller via
/// GidAllocator — this module generates no randomness, staying testable;
/// the same rule as the BT-side assemble).
#[derive(Debug, Clone)]
pub struct HttpPlanInput<'a> {
    pub task: &'a HttpSourceTask,
    pub gid_hex: String,
    /// Dedup hit (criterion = row present + key equal; the caller queries
    /// the target read face): Some = already imported. The criterion lives
    /// on the row (the row's config_json `origin_fork_key`, stamped by the
    /// planner); the kv reverse index is the fallback face (old-database
    /// rows missing the key + the BT face). Liveness contract for the
    /// back-reference: Some must point at a **live** row — a dead
    /// reference (the pointed-to row deleted) is treated as not-imported
    /// by the store read face after a liveness check (dry-run snapshot
    /// liveness + a `stale_imported` note; the real-import delete
    /// close-out clears the reverse index in step) and must not be passed
    /// as Some.
    pub imported_gid: Option<String>,
    pub conflict_action: PathConflictAction,
}

/// The aria2 candidate name (the first free slot in the occupancy set; a
/// pure function — the existence predicate is occupancy-set membership,
/// candidates stay bare file names within dir). Returns the candidate
/// `out`.
fn rename_candidate(dir: &str, out: &str, occupied: &BTreeSet<(String, String)>) -> Option<String> {
    let final_path = std::path::Path::new(dir).join(out);
    (1..AUTO_RENAME_MAX_TRIES)
        .map(|i| renamed_candidate(&final_path, i))
        .find(
            |c| match c.file_name().map(|n| n.to_string_lossy().into_owned()) {
                Some(name) => !occupied.contains(&(dir.to_string(), name)),
                None => false,
            },
        )
        .and_then(|c| c.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Batch persistence (the existing PersistWriter face: UpsertHttpTask —
/// the row's config_json carries the `origin_fork_key` criterion — then
/// the PutKv reverse index; the per-task result reuses the BT face
/// [`super::import::AppliedTask`]). Any step failing marks that task
/// failed and continues — one task's failure never blocks the batch (the
/// single-task-failure rule). kv written last = a failed task has no
/// reverse index while the row-key criterion still works (the criterion
/// lives on the row, so a missing kv never lets a duplicate through;
/// upsert idempotence absorbs leftover rows). Before persisting, fork
/// data adoption runs ([`adopt_fork_data_file`]): rename first, persist
/// second — inside a mid-crash window the `.part` exists while the row
/// does not, so a re-import can simply retry; the reverse order would
/// deadlock ("row stored but data not adopted", with dedup blocking the
/// retry).
pub async fn apply_http_import(
    persist: &PersistHandle,
    planned: &[PlannedHttpImport],
) -> Vec<AppliedTask> {
    let mut out = Vec::with_capacity(planned.len());
    for p in planned {
        adopt_fork_data_file(p).await;
        let mut err: Option<String> = None;
        if let Err(e) = persist.upsert_http_task(p.row.clone()).await {
            err = Some(format!("http_task row: {e}"));
        }
        if err.is_none() {
            if let Err(e) = persist.put_kv(&p.source_key, &p.gid).await {
                err = Some(format!("imported_from kv: {e}"));
            }
        }
        out.push(AppliedTask {
            gid: p.gid.clone(),
            source_key: p.source_key.clone(),
            error: err,
        });
    }
    out
}

/// Adoption: archive-rename the fork data file of a bitmap row,
/// `<out>` -> `<out><suffix>`. The fork writes partial HTTP data straight
/// to the final path, while the taiji resume face only accepts
/// `<out>.part` — without adoption, activation resumes with
/// PartFileMissing -> FromZero, the bitmap is cleared, and the fork
/// partial data and the imported bitmap are lost together. Guards (skip
/// adoption rather than destroy data):
/// - bitmap rows only (`block_bitmap` present): renaming a row without a
///   bitmap would let an activation-time Restart truncate it = data
///   destruction; the final file is left to the auto-rename semantics
///   (the data survives the rename);
/// - the part slot is free (`<out><suffix>` absent): if taken, the two
///   data sets cannot be merged and both stay as-is — auto-rename is
///   disabled for bitmap rows, so activation reports the conflict
///   explicitly;
/// - `<out>` is a regular file: directories and other shapes are not
///   adopted (an explicit conflict at activation);
/// - `out` is set: unset = the name is only fixed at activation, nothing
///   to adopt at import time;
/// - a failed rename is not fatal: the row is stored as usual and the
///   activation defenses take over (equivalent to the pre-fix behavior,
///   never silently destroying data).
async fn adopt_fork_data_file(p: &PlannedHttpImport) {
    if p.row.block_bitmap.is_none() || p.row.out.is_empty() {
        return;
    }
    let final_path = PathBuf::from(&p.row.dir).join(&p.row.out);
    let suffix = HttpPersistConfig::from_json(&p.row.config_json).incomplete_suffix;
    let mut part_os = final_path.as_os_str().to_os_string();
    part_os.push(&suffix);
    let part_path = PathBuf::from(part_os);
    let part_in_closure = part_path.clone();
    let renamed = tokio::task::spawn_blocking(move || -> Result<bool, String> {
        match std::fs::metadata(&final_path) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Ok(false),  // a directory shape: not adopted
            Err(_) => return Ok(false), // the final file is not on disk: nothing to adopt
        }
        if part_in_closure.symlink_metadata().is_ok() {
            return Ok(false); // part slot taken: the two data sets cannot be merged, keep both
        }
        std::fs::rename(&final_path, &part_in_closure)
            .map(|_| true)
            .map_err(|e| {
                format!(
                    "rename {} -> {}: {e}",
                    final_path.display(),
                    part_in_closure.display()
                )
            })
    })
    .await;
    match renamed {
        Ok(Ok(true)) => tracing::info!(
            target: "taiji::core::import",
            gid = %p.gid,
            part = %part_path.display(),
            "fork partial data adopted as resume input (<out> -> <out><suffix>)"
        ),
        Ok(Ok(false)) => {}
        Ok(Err(e)) => tracing::warn!(target: "taiji::core::import", gid = %p.gid, "{e}; \
            the row is imported as-is and activation will adjudicate from disk facts"),
        Err(e) => {
            tracing::warn!(target: "taiji::core::import", gid = %p.gid, "fork data adoption join: {e}")
        }
    }
}

/// Async wrapper for preflight item 1 (fork process exited / lock
/// released): a read-only probe (internal `spawn_blocking`); the display
/// text of `StoreError::ForkLocked` is the "exit the old version"
/// guidance (checklist item 1 in docs/design/core.md). Returns the total
/// task row count.
pub async fn preflight_fork_read(db_path: PathBuf) -> Result<i64, String> {
    tokio::task::spawn_blocking(move || probe_fork_readonly(&db_path))
        .await
        .map_err(|e| format!("fork preflight join: {e}"))?
        .map_err(|e| e.to_string())
}

// ---- The three preflight layers ----
//
// (1) a sqlite lock is held -> refuse with "exit the old version"
// guidance ([`probe_fork_readonly`]);
// (2) a live-fork fd scan ([`taiji_store::persist::fork_import::
// scan_fork_liveness`]): enumerate the processes holding the fork
// db/-wal/-shm open; a hit refuses and reports the pid — a WAL-idle fork
// holds no lock most of the time, so layer (1) cannot catch "alive but
// idle"; the fd scan is the catch;
// (3) when it cannot be proven (unsupported platform / lsof absent),
// refuse by default; `--i-know-fork-is-closed` explicitly accepts
// responsibility. The flag releases only layer (3) — a held lock and a
// live fd hit are direct facts that the fork is still alive; letting them
// through would write a target database against a live fork, so no
// exemption exists.

/// The three-layer pass proof: `Proven` = the fd-scan face is available
/// and found no holder (the provable face of "the fork is closed");
/// `AcknowledgedUncertain` = cannot be proven + the user accepted
/// responsibility (the CLI surfaces a warning, never silently).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkClosedProof {
    Proven,
    AcknowledgedUncertain(String),
}

/// Layers (2)/(3) adjudication (a pure function; [`ForkLiveness`] is
/// injected for testability, platform/tooling belongs to the store scan).
/// Refusal text reports the pid/reason and gives the user a way out.
pub fn adjudicate_fork_fd_scan(
    scan: ForkLiveness,
    i_know_fork_is_closed: bool,
) -> Result<ForkClosedProof, String> {
    match scan {
        ForkLiveness::Clean => Ok(ForkClosedProof::Proven),
        ForkLiveness::Alive(holders) => {
            // Dedup pids ascending, one sample path per process (keeps the
            // report diagnosable).
            let mut per_pid = std::collections::BTreeMap::new();
            for h in holders {
                per_pid.entry(h.pid).or_insert(h.path);
            }
            let detail = per_pid
                .iter()
                .map(|(pid, path)| format!("pid {pid} ({path})"))
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!(
                "fork database is held open by live process(es): {detail} — \
                 the old Motrix (legacy fork) is still running; exit it and \
                 retry (importing against a live fork is refused and cannot \
                 be overridden)"
            ))
        }
        ForkLiveness::Uncertain(reason) if i_know_fork_is_closed => {
            Ok(ForkClosedProof::AcknowledgedUncertain(reason))
        }
        ForkLiveness::Uncertain(reason) => Err(format!(
            "cannot prove the fork is closed: {reason} — import refuses by \
             default; if the old Motrix (legacy fork) is \
             really exited, pass --i-know-fork-is-closed to take \
             responsibility and proceed"
        )),
    }
}

/// The three-layer preflight entry (async; disk IO/subprocess inside
/// `spawn_blocking`): (1) lock probe (ForkLocked = refuse with "exit the
/// old version" guidance) -> (2) live-fd scan (a hit reports the pid) ->
/// (3) cannot-prove refuses by default (the flag accepts responsibility).
/// Returns (total task rows, pass proof) — probing the total once more
/// here duplicates the collect face, an acceptable cost for a one-shot
/// operation in exchange for closing all three layers before any
/// collection/IO.
pub async fn preflight_fork_liveness(
    db_path: PathBuf,
    i_know_fork_is_closed: bool,
) -> Result<(i64, ForkClosedProof), String> {
    tokio::task::spawn_blocking(move || {
        let total = probe_fork_readonly(&db_path).map_err(|e| e.to_string())?;
        let scan = taiji_store::persist::fork_import::scan_fork_liveness(&db_path);
        let proof = adjudicate_fork_fd_scan(scan, i_know_fork_is_closed)?;
        Ok((total, proof))
    })
    .await
    .map_err(|e| format!("fork preflight join: {e}"))?
}

/// Async wrapper for preflight item 4 (the automatic pre-import backup):
/// `taiji.sqlite3` -> `taiji.sqlite3.v1.bak` (disk IO — internal
/// `spawn_blocking`; semantics in the store-side [`backup_target_db`]:
/// must run before any open/migration of the target; refuses while a
/// session is live (sidecars on disk); an existing backup is kept, never
/// overwritten).
pub async fn backup_target_for_import(db_path: PathBuf) -> Result<ImportBackup, String> {
    tokio::task::spawn_blocking(move || backup_target_db(&db_path))
        .await
        .map_err(|e| format!("import backup join: {e}"))?
        .map_err(|e| e.to_string())
}

/// Async wrapper for the target read-only probe (the shape/ledger guard)
/// (disk IO — internal `spawn_blocking`): the table-set criterion that
/// catches `--sqlite3-db-path` pointing at a fork database + the ledger
/// position. Must run BEFORE the pre-import backup — when a fork database
/// is mistaken for the target, both the backup's checkpoint and the later
/// open/migration would write the fork storage (a read-only discipline
/// red line).
pub async fn probe_import_target(db_path: PathBuf) -> Result<ImportTargetProbe, String> {
    tokio::task::spawn_blocking(move || probe_import_target_readonly(&db_path))
        .await
        .map_err(|e| format!("import target probe join: {e}"))?
        .map_err(|e| e.to_string())
}

/// Async wrapper for the import-target read-only snapshot (the dry-run
/// dedup/occupancy query face): zero-write discipline against the
/// existing target — never opened through PersistWriter (opening advances
/// the migration ledger; the standard dry-run-then-real flow once poisoned
/// the `.v1.bak` rollback anchor into an "already migrated" snapshot).
pub async fn read_target_snapshot_for_dry_run(
    db_path: PathBuf,
    keys: Vec<String>,
) -> Result<ImportTargetSnapshot, String> {
    tokio::task::spawn_blocking(move || read_target_snapshot_impl(&db_path, &keys))
        .await
        .map_err(|e| format!("import target snapshot join: {e}"))?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Result unwrapping (the lint forbids unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    // ---- serialized parse vectors (cross-checked against
    // UriListParser.cc / SessionSerializer.cc) ----

    /// Vector 1 (positive): the real writer shape — a TAB-separated URI
    /// line (a TAB after each URI, SessionSerializer.cc writeUri), option
    /// lines with a leading space (writeOptionLine); a cumulative option
    /// (header) keeps multiple order-preserving lines.
    #[test]
    fn vector_tab_separated_uri_line_and_option_lines() {
        let text = "http://a/f.bin\thttp://b/f.bin\thttp://c/f.bin\t\n \
                    header=X-A: 1\n \
                    header=X-B: 2\n \
                    out=f.bin\n \
                    dir=/dl\n \
                    user-agent=taiji/1\n \
                    gid=0000000000000042\n";
        let p = parse_serialized(text);
        assert_eq!(
            p.uris,
            vec!["http://a/f.bin", "http://b/f.bin", "http://c/f.bin"],
            "TAB splitting + trailing-TAB tolerance + order preservation"
        );
        assert_eq!(
            p.options,
            vec![
                ("header".to_string(), "X-A: 1".to_string()),
                ("header".to_string(), "X-B: 2".to_string()),
                ("out".to_string(), "f.bin".to_string()),
                ("dir".to_string(), "/dl".to_string()),
                ("user-agent".to_string(), "taiji/1".to_string()),
            ],
            "options keep order and duplicates; gid rows do not migrate"
        );
    }

    /// Vector 2: the documented space-separated shape is also accepted;
    /// `#` comment lines are skipped; option lines with a leading TAB are
    /// tolerated (the read side accepts ' ' or '\t').
    #[test]
    fn vector_space_separated_comments_and_tab_option_prefix() {
        let text = "# saved session\nhttp://a/f http://b/f\n\tpause=true\n dir=/dl\n";
        let p = parse_serialized(text);
        assert_eq!(p.uris, vec!["http://a/f", "http://b/f"]);
        assert_eq!(
            p.options,
            vec![
                ("pause".to_string(), "true".to_string()),
                ("dir".to_string(), "/dl".to_string()),
            ]
        );
    }

    /// Vector 3 (negative/tolerance): empty text = all defaults; option
    /// lines without `=` are ignored; duplicate URIs are deduped (the
    /// writer-side Unique rule); a second URI line is not passed off as
    /// an option.
    #[test]
    fn vector_empty_input_and_tolerant_faces() {
        assert_eq!(parse_serialized(""), ParsedSerialized::default());
        assert_eq!(
            parse_serialized("\n#only comment\n"),
            ParsedSerialized::default()
        );
        let p = parse_serialized("http://a/f http://a/f\n nokey\nhttp://b/f\n");
        assert_eq!(
            p.uris,
            vec!["http://a/f"],
            "deduped + the second URI row ignored"
        );
        assert!(p.options.is_empty(), "none = the options row is ignored");
    }

    /// Scheme accounting: http/https/ftp accepted; magnet/ftps/local
    /// paths explicitly dropped.
    #[test]
    fn scheme_classification_matches_add_uri_domain() {
        assert!(supported_scheme("http://a/f"));
        assert!(supported_scheme("HTTPS://a/f"));
        assert!(supported_scheme("ftp://a/f"));
        assert!(!supported_scheme("magnet:?xt=urn:btih:aa"));
        assert!(!supported_scheme("ftps://a/f"));
        assert!(!supported_scheme("/tmp/m.meta4"));
    }

    // ---- collect/plan/persist (synthetic fixtures) ----

    use std::path::{Path, PathBuf};

    /// Synthetic fork-schema fixture (the DDL cross-checked against
    /// Sqlite3Migrations.cc, user_version = 1; isomorphic to the
    /// store-side tests).
    fn seed_fork_db(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "taiji-httpimport-{tag}-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let conn = ok(rusqlite::Connection::open(&path), "open fixture");
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
                 CREATE INDEX idx_task_state ON task(state);
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

    fn insert_http_task(
        conn: &rusqlite::Connection,
        gid: &str,
        serialized: &str,
        queue: i64,
        state: &str,
    ) {
        ok(
            conn.execute(
                "INSERT INTO task (gid, state, serialized, queue_position, digest,
                                   created_at, updated_at)
                 VALUES (?1, ?4, ?2, ?3, x'00', 0, 0)",
                rusqlite::params![gid, serialized, queue, state],
            ),
            "insert http task",
        );
        // An HTTP task with an is_torrent=0 progress row (the fork writes
        // progress for HTTP tasks too — the non-BT branch of the
        // Sqlite3BtProgressInfoFile.cc save): 1MiB pieces, 10MiB total, a
        // 10-piece bitmap (2B, MSB-first) with pieces 0-2 done.
        ok(
            conn.execute(
                "INSERT INTO task_progress (gid, is_torrent, piece_length,
                                            total_length, bitfield, digest, updated_at)
                 VALUES (?1, 0, 1048576, 10485760, x'E000', x'00', 0)",
                rusqlite::params![gid],
            ),
            "insert http progress",
        );
    }

    /// Download directory fixture (an on-disk directory — the positive
    /// precondition of preflight item 2).
    fn seed_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "taiji-httpimport-dir-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        ok(std::fs::create_dir_all(&d), "mkdir fixture");
        d
    }

    /// First half of the synthetic dry run (the collection face): every
    /// class present — HTTP Ready (multi-URI -> mirrors, pause face, queue
    /// order), torrent-without-infohash Skipped, missing-directory Failed
    /// (the `.motrix/p/<id>` ordering copy).
    #[tokio::test]
    async fn collect_classifies_http_entries_with_preflight() {
        let db = seed_fork_db("collect");
        let dir = seed_dir("collect");
        let missing_dir = dir.parent().unwrap_or(Path::new(".")).join("no-such-dl");
        {
            let conn = ok(rusqlite::Connection::open(&db), "reopen");
            insert_http_task(
                &conn,
                "000000000000000a",
                &format!(
                    "http://a/f.iso\thttp://b/f.iso\t\n header=X-A: 1\n out=f.iso\n dir={}\n pause=true\n",
                    dir.display()
                ),
                1,
                "waiting",
            );
            insert_http_task(
                &conn,
                "000000000000000b",
                "magnet:?xt=urn:btih:aa\n dir=/dl\n",
                2,
                "waiting",
            );
            insert_http_task(
                &conn,
                "000000000000000c",
                &format!("http://c/f.bin\n dir={}\n", missing_dir.display()),
                3,
                "waiting",
            );
        }
        let (total, entries) = ok(
            collect_fork_http_tasks(db.clone(), dir.clone()).await,
            "collect",
        );
        assert_eq!(total, 3, "the full-row baseline");
        assert_eq!(
            entries.len(),
            3,
            "the union of both read faces = the full set (the BT face fetches 0 rows)"
        );
        let mut ready = 0;
        let mut skipped = 0;
        let mut failed = 0;
        for e in &entries {
            match e {
                HttpCollectEntry::Ready(t) => {
                    ready += 1;
                    assert_eq!(t.fork_gid.as_deref(), Some("000000000000000a"));
                    assert_eq!(t.uris, vec!["http://a/f.iso", "http://b/f.iso"]);
                    assert!(t.paused, "serialized pause=true");
                    assert_eq!(t.dir, dir.display().to_string());
                    assert_eq!(t.out.as_deref(), Some("f.iso"));
                    assert_eq!(
                        t.options,
                        vec![("header".to_string(), "X-A: 1".to_string())],
                        "dir/out/pause have dedicated slots, everything else goes to the migration list"
                    );
                    assert_eq!(t.queue_pos, 1);
                }
                HttpCollectEntry::Skipped { reason, .. } => {
                    skipped += 1;
                    assert!(reason.contains("magnet"), "magnet skip wording: {reason}");
                }
                HttpCollectEntry::Failed { reason, .. } => {
                    failed += 1;
                    assert!(
                        reason.contains(".motrix/p/<id>"),
                        "dangling-chain wording: {reason}"
                    );
                }
            }
        }
        assert_eq!((ready, skipped, failed), (1, 1, 1), "entries: {entries:?}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
    }

    /// Single-command both-face collection (the `taiji import` merge):
    /// one read-only open; the BT face (torrent rows with progress) and
    /// the HTTP-face entries partition complementary, the union against
    /// the total; the lock probe still runs first.
    #[tokio::test]
    async fn merged_collect_accounts_bt_and_http_faces() {
        let db = seed_fork_db("merged");
        let dir = seed_dir("merged");
        {
            let conn = ok(rusqlite::Connection::open(&db), "reopen");
            // BT face: is_torrent=1 + a non-empty info_hash ->
            // load_fork_bt_tasks.
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, bt_local_path,
                                       queue_position, digest, created_at, updated_at)
                     VALUES ('00000000000000b7', 'waiting', ' dir=/dl\n', '/tmp/src/b.torrent',
                             0, x'00', 0, 0)",
                    [],
                ),
                "insert bt task",
            );
            ok(
                conn.execute(
                    "INSERT INTO task_progress (gid, is_torrent, info_hash, piece_length,
                                                total_length, bitfield, digest, updated_at)
                     VALUES ('00000000000000b7', 1, ?1, 16384, 32768, x'c0', x'00', 0)",
                    rusqlite::params![vec![7u8; 20]],
                ),
                "insert bt progress",
            );
            // HTTP face: is_torrent=0 -> load_fork_http_tasks.
            insert_http_task(
                &conn,
                "0000000000000040",
                &format!("http://a/f.bin\n out=f.bin\n dir={}\n", dir.display()),
                1,
                "waiting",
            );
        }
        let fc = ok(
            collect_fork_all_tasks(db.clone(), dir.clone()).await,
            "merged",
        );
        assert_eq!(fc.total_tasks, 2, "the full-row baseline");
        assert_eq!(fc.bt.len(), 1, "one row on the BT face");
        assert_eq!(fc.bt[0].fork_gid.as_deref(), Some("00000000000000b7"));
        let http_ready = fc
            .http
            .iter()
            .filter(|e| matches!(e, HttpCollectEntry::Ready(_)))
            .count();
        assert_eq!(http_ready, 1, "one row on the HTTP face");
        // Complementary partition: BT candidates + HTTP entries = the
        // total.
        assert_eq!(
            fc.bt.len() + fc.http.len(),
            fc.total_tasks as usize,
            "the union of both read faces = the full row set"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
    }

    /// Second half of the synthetic dry run (planning + a persistence
    /// roundtrip + dedup + the conflict decision + the weak-resume
    /// declaration): row fields read back column by column; a second
    /// import is intercepted via kv; a same (dir,out) gets Skip then
    /// Rename.
    #[tokio::test]
    async fn plan_apply_roundtrip_dedup_and_conflict() {
        use taiji_store::persist::PersistWriter;
        let db = seed_fork_db("apply");
        let dir = seed_dir("apply");
        {
            let conn = ok(rusqlite::Connection::open(&db), "reopen");
            insert_http_task(
                &conn,
                "0000000000000021",
                &format!(
                    "http://a/f.iso\thttp://b/f.iso\t\n out=f.iso\n dir={}\n user-agent=taiji/1\n header=X-A: 1\n",
                    dir.display()
                ),
                0,
                "waiting",
            );
            insert_http_task(
                &conn,
                "0000000000000022",
                &format!("http://c/other.bin\n out=f.iso\n dir={}\n", dir.display()),
                1,
                "waiting",
            );
        }
        let (total, entries) = ok(
            collect_fork_http_tasks(db.clone(), dir.clone()).await,
            "collect",
        );
        assert_eq!(total, 2);
        let tasks: Vec<HttpSourceTask> = entries
            .into_iter()
            .map(|e| match e {
                HttpCollectEntry::Ready(t) => *t,
                other => panic!("expected ready, got {other:?}"),
            })
            .collect();

        let target = std::env::temp_dir().join(format!(
            "taiji-httpimport-target-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));

        // Plan: task 1 straight in; task 2 has the same (dir,out) -> the
        // Skip decision (the default face).
        let mut planner = HttpImportPlanner::new(Vec::new());
        let mut planned = Vec::new();
        let gids = ["80000000000000f1", "80000000000000f2"];
        for (i, task) in tasks.iter().enumerate() {
            match planner.plan(HttpPlanInput {
                task,
                gid_hex: gids[i].to_string(),
                imported_gid: None,
                conflict_action: PathConflictAction::Skip,
            }) {
                HttpPlanEntry::Planned(p) => planned.push(*p),
                HttpPlanEntry::Skipped { reason, .. } => {
                    assert_eq!(i, 1, "the conflict lands only on the second task: {reason}");
                    assert!(reason.contains("path conflict"), "{reason}");
                }
                other => panic!("unexpected entry: {other:?}"),
            }
        }
        assert_eq!(planned.len(), 1);
        let p = &planned[0];
        assert_eq!(p.gid, "80000000000000f1", "new GID = the shared namespace");
        assert_eq!(p.state, "queued");
        assert!(
            p.warnings
                .iter()
                .any(|w| w.contains("imported progress: 3/10 blocks")),
            "bitmap-mapped progress note: {:?}",
            p.warnings
        );
        assert_eq!(p.row.url, "http://a/f.iso");
        assert_eq!(
            p.row.mirrors_json.as_deref(),
            Some(r#"[{"url":"http://a/f.iso"},{"url":"http://b/f.iso"}]"#),
            "multi-source mirrors_json matches the recovery-side shape"
        );
        assert!(p.row.config_json.contains(r#""imported_options":["#));
        assert!(p.row.config_json.contains(r#"["user-agent","taiji/1"]"#));

        // Persist (the PersistWriter seam) -> restart and read back.
        let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn writer");
        let applied = apply_http_import(&handle, &planned).await;
        assert!(applied[0].error.is_none(), "apply: {:?}", applied[0].error);
        // The dedup kv hit (the second-import interception face).
        let kv = ok(handle.get_kv(&p.source_key).await, "get kv");
        assert_eq!(kv.as_deref(), Some("80000000000000f1"));
        let snaps = ok(handle.load_http_tasks_at_startup().await, "load startup");
        assert_eq!(snaps.len(), 1);
        let row = &snaps[0].row;
        assert_eq!(row.gid, "80000000000000f1");
        assert_eq!(row.state, "queued");
        assert_eq!(row.dir, dir.display().to_string());
        assert_eq!(row.out, "f.iso");
        // Bitmap payload (fork progress pieces 0-2/10 @ 1MiB piece ->
        // blocks 0-2).
        assert_eq!(
            row.block_size, 1048576,
            "block granularity = the largest power-of-two factor of the piece"
        );
        assert_eq!(
            row.block_bitmap.as_deref(),
            Some(&[0b0000_0111u8, 0x00][..]),
            "LSB-first block bitmap (blocks 0/1/2)"
        );
        assert_eq!(row.block_count, Some(10));
        assert_eq!(
            row.total_done,
            3 * 1048576,
            "completed bytes = exactly 3 blocks"
        );
        assert!(
            row.validator_digest.is_some(),
            "the validator digest is seeded with the imported known facts"
        );
        let cfg = HttpPersistConfig::from_json(&row.config_json);
        assert_eq!(
            cfg.imported_options,
            Some(vec![
                ("user-agent".to_string(), "taiji/1".to_string()),
                ("header".to_string(), "X-A: 1".to_string()),
            ]),
            "the migration list is carried verbatim, order preserved"
        );
        assert_eq!(
            cfg.incomplete_suffix, ".part",
            "the remaining persistence keys keep their defaults"
        );
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );

        // Second import: dedup Skipped + Rename for the conflict task
        // (candidate = f.1.iso).
        let (handle2, join2) = ok(PersistWriter::spawn(target.clone()).await, "respawn");
        let existing: Vec<(String, String)> =
            ok(handle2.load_http_tasks_at_startup().await, "load")
                .into_iter()
                .map(|s| (s.row.dir, s.row.out))
                .collect();
        let mut planner = HttpImportPlanner::new(existing);
        // Task 1: the kv hit.
        match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "80000000000000f3".to_string(),
            imported_gid: Some("80000000000000f1".to_string()),
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Skipped { reason, .. } => {
                assert!(reason.contains("already imported"), "{reason}");
            }
            other => panic!("dedup must skip: {other:?}"),
        }
        // Task 2: the Rename decision -> f.1.iso.
        match planner.plan(HttpPlanInput {
            task: &tasks[1],
            gid_hex: "80000000000000f4".to_string(),
            imported_gid: None,
            conflict_action: PathConflictAction::Rename,
        }) {
            HttpPlanEntry::Planned(p) => {
                assert_eq!(
                    p.row.out, "f.1.iso",
                    "the aria2 candidate-name algorithm (f.iso -> f.1.iso)"
                );
                assert!(
                    p.warnings
                        .iter()
                        .any(|w| w.contains("renamed f.iso -> f.1.iso")),
                    "the rename is made explicit: {:?}",
                    p.warnings
                );
            }
            other => panic!("rename adjudication must plan: {other:?}"),
        }
        drop(handle2);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join2).await,
            "writer 2 exit",
        );

        // out= sanitizing (the same rules as addUri): a path-traversing
        // out -> Failed.
        let bad = HttpSourceTask {
            source: tasks[0].source.clone(),
            source_key: "imported_from:db:x#bad".into(),
            fork_gid: Some("0000000000000099".into()),
            queue_pos: 0,
            uris: vec!["http://a/x.bin".into()],
            unsupported_uris: Vec::new(),
            dir: dir.display().to_string(),
            out: Some("../escape.bin".into()),
            paused: false,
            options: Vec::new(),
            progress: None,
        };
        let mut planner = HttpImportPlanner::new(Vec::new());
        match planner.plan(HttpPlanInput {
            task: &bad,
            gid_hex: "80000000000000f5".to_string(),
            imported_gid: None,
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Failed { reason, .. } => {
                assert!(reason.contains("output-name domain"), "{reason}");
            }
            other => panic!("path traversal out must fail: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(&target);
    }

    /// The mirrors_json shape is inverse to the resume face: a single
    /// source writes no redundant payload (None); mirrors_json_of is one
    /// function serving both the addUri and import producers (this test
    /// pins the shape contract by mirroring the resume-side parse
    /// logic).
    #[test]
    fn mirrors_json_shape_contract() {
        let one = vec!["http://a/f".to_string()];
        assert_eq!(
            mirrors_json_of(&one),
            None,
            "the single-source url column is the truth"
        );
        let many = vec!["http://a/f".to_string(), "ftp://b/f".to_string()];
        let raw = mirrors_json_of(&many)
            .unwrap_or_else(|| panic!("multi-source always carries a payload"));
        let vals: Vec<serde_json::Value> = ok(serde_json::from_str(&raw), "parse mirrors");
        assert_eq!(
            vals,
            vec![
                serde_json::json!({"url": "http://a/f"}),
                serde_json::json!({"url": "ftp://b/f"}),
            ]
        );
    }

    /// Backup negative cases (the store-side semantics exercised through
    /// the core wrapper): (1) no target db = NotNeeded; (2) the real
    /// import path creates .v1.bak whose bytes include the written data
    /// (checkpoint folded in); (3) an existing backup is kept, never
    /// overwritten; (4) the backup content is readable by sqlite (the
    /// rollback-runbook recovery face).
    #[tokio::test]
    async fn backup_target_db_lifecycle_and_kept_existing() {
        use taiji_store::persist::PersistWriter;
        let target = std::env::temp_dir().join(format!(
            "taiji-httpimport-bak-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        // (1) target db absent -> NotNeeded.
        assert_eq!(
            ok(
                backup_target_for_import(target.clone()).await,
                "backup absent"
            ),
            ImportBackup::NotNeeded
        );
        // First import: create the db, write one row (simulating an
        // existing BT task), then back up.
        {
            let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn");
            let row = HttpTaskRow {
                gid: "80000000000000b1".into(),
                url: "http://a/pre.bin".into(),
                final_url: String::new(),
                mirrors_json: None,
                state: "queued".into(),
                queue_pos: 0,
                dir: "/dl".into(),
                out: "pre.bin".into(),
                config_json: "{}".into(),
                probe_json: None,
                validator_digest: None,
                block_size: 0,
                block_bitmap: None,
                block_count: None,
                total_done: 0,
                error_code: None,
                error_msg: None,
                created_at: 0,
                updated_at: 0,
            };
            assert!(handle.upsert_http_task(row).await.is_ok());
            drop(handle);
            let _ = ok(
                tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
                "writer exit",
            );
        }
        let bak_path = {
            let mut s = target.as_os_str().to_os_string();
            s.push(".v1.bak");
            PathBuf::from(s)
        };
        // (2) the pre-import backup -> Created; the bytes include the
        // first import's data (the checkpoint folded into the main file).
        match ok(
            backup_target_for_import(target.clone()).await,
            "backup create",
        ) {
            ImportBackup::Created(ref p) => {
                assert_eq!(p, &bak_path, "naming = <db>.v1.bak");
                let src = ok(std::fs::read(&target), "read src");
                let bak = ok(std::fs::read(&bak_path), "read bak");
                assert_eq!(
                    src, bak,
                    "after the checkpoint the main-file snapshot matches byte for byte"
                );
            }
            other => panic!("expected Created, got {other:?}"),
        }
        // (3) a second import -> KeptExisting (overwriting would destroy
        // the rollback anchor, hence the negative assertion): evolve the
        // main db, then back up again — the existing backup must keep the
        // first snapshot byte for byte.
        let first_snapshot = ok(std::fs::read(&bak_path), "read first snapshot");
        {
            let conn = ok(rusqlite::Connection::open(&target), "evolve target");
            ok(
                conn.execute_batch("CREATE TABLE evolved(x INTEGER)"),
                "evolve db",
            );
        }
        match ok(
            backup_target_for_import(target.clone()).await,
            "backup again",
        ) {
            ImportBackup::KeptExisting(ref p) => {
                assert_eq!(p, &bak_path);
                assert_eq!(
                    ok(std::fs::read(&bak_path), "read kept bak"),
                    first_snapshot,
                    "a pre-existing backup must be preserved byte for byte (never overwritten)"
                );
            }
            other => panic!("expected KeptExisting, got {other:?}"),
        }
        // (4) sqlite readability is backed by (2)'s byte equality (the
        // same file bytes); recovery = copy back under the original name
        // and it opens (runbook semantics); explicit rejection of torn or
        // corrupt backups is covered on the store side.
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&bak_path);
    }

    /// Target read-only probe (the shape guard): a fork schema (the
    /// task/task_progress tables present) sets `fork_shaped` — the guard
    /// criterion for `--sqlite3-db-path` pointing at a fork database; a
    /// taiji v3 database is not misjudged.
    #[tokio::test]
    async fn probe_import_target_detects_fork_shape() {
        use taiji_store::persist::PersistWriter;
        let root = std::env::temp_dir().join(format!(
            "taiji-httpimport-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        ok(std::fs::create_dir_all(&root), "mkdir");
        // taiji v3 target: not fork-shaped, the ledger position reported
        // accurately.
        let target = root.join("taiji.sqlite3");
        let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn");
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );
        let probe = ok(probe_import_target(target.clone()).await, "probe taiji");
        assert!(!probe.fork_shaped);
        assert_eq!(probe.user_version, probe.latest_supported);
        // Fork-shaped file: the table-set criterion hits.
        let fork = root.join("fork.sqlite3");
        {
            let conn = ok(rusqlite::Connection::open(&fork), "open fork");
            ok(
                conn.execute_batch(
                    "CREATE TABLE task (gid TEXT);
                     CREATE TABLE task_progress (gid TEXT);",
                ),
                "seed fork tables",
            );
        }
        let probe = ok(probe_import_target(fork.clone()).await, "probe fork");
        assert!(
            probe.fork_shaped,
            "task/task_progress present = the fork shape"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Preflight item 1 negative: the fork database held under an
    /// exclusive lock (simulating a running old process) -> the read-only
    /// probe returns ForkLocked (refuse with the "exit the old version"
    /// guidance) and the collect face fails explicitly.
    #[tokio::test]
    async fn preflight_rejects_fork_locked_db() {
        let db = seed_fork_db("locked");
        {
            let conn = ok(rusqlite::Connection::open(&db), "open locker");
            ok(conn.execute_batch("BEGIN EXCLUSIVE;"), "lock");
            // Probe face: ForkLocked (not a bare sqlite error).
            match probe_fork_readonly(&db) {
                Err(taiji_store::error::StoreError::ForkLocked { .. }) => {}
                other => panic!("expected ForkLocked, got {other:?}"),
            }
            // Collect face: an explicit Err (the copy carries the locked
            // guidance).
            let err = collect_fork_http_tasks(db.clone(), PathBuf::from("."))
                .await
                .err();
            let err = err.unwrap_or_else(|| panic!("collect must fail on locked db"));
            assert!(err.contains("locked"), "{err}");
            ok(conn.execute_batch("COMMIT;"), "unlock");
        }
        let _ = std::fs::remove_file(&db);
    }

    // ---- the three-layer preflight decision (layers 2/3) ----

    /// Layer 2: a live hit refuses and reports the pid — the
    /// responsibility flag does NOT exempt (a live process holding a
    /// handle is a direct fact that the fork is alive, same rank as the
    /// lock; no bypass exists).
    #[test]
    fn three_layer_alive_hit_refuses_with_pid_and_flag_does_not_release() {
        let scan = ForkLiveness::Alive(vec![
            taiji_store::persist::fork_import::ForkFdHolder {
                pid: 4242,
                path: "/dl/fork.sqlite3".to_string(),
            },
            taiji_store::persist::fork_import::ForkFdHolder {
                pid: 4242,
                path: "/dl/fork.sqlite3-wal".to_string(),
            },
            taiji_store::persist::fork_import::ForkFdHolder {
                pid: 7,
                path: "/dl/fork.sqlite3-shm".to_string(),
            },
        ]);
        for flag in [false, true] {
            let err = adjudicate_fork_fd_scan(scan.clone(), flag)
                .err()
                .unwrap_or_else(|| panic!("alive hit must refuse (flag={flag})"));
            assert!(err.contains("pid 4242"), "{err}");
            assert!(
                err.contains("pid 7"),
                "multi-process pids are reported one by one: {err}"
            );
            assert!(
                err.contains("(/dl/fork.sqlite3)"),
                "the sample path is diagnosable (one per pid): {err}"
            );
            assert!(
                err.contains("cannot be overridden"),
                "accurately states there is no exemption hatch: {err}"
            );
        }
    }

    /// Layer 3: cannot-prove = refuse by default; only
    /// `--i-know-fork-is-closed` passes (the proof carries the reason for
    /// the CLI warning — never silent).
    #[test]
    fn three_layer_uncertain_defaults_to_refuse_flag_takes_responsibility() {
        let scan = ForkLiveness::Uncertain("lsof is not available".to_string());
        let err = adjudicate_fork_fd_scan(scan.clone(), false)
            .err()
            .unwrap_or_else(|| panic!("uncertain must refuse by default"));
        assert!(err.contains("cannot prove the fork is closed"), "{err}");
        assert!(
            err.contains("--i-know-fork-is-closed"),
            "the flag appears in the wording: {err}"
        );
        assert!(
            err.contains("lsof is not available"),
            "the cause is diagnosable: {err}"
        );
        match adjudicate_fork_fd_scan(scan, true) {
            Ok(ForkClosedProof::AcknowledgedUncertain(reason)) => {
                assert!(reason.contains("lsof is not available"), "{reason}");
            }
            other => panic!("flag releases uncertain with proof, got {other:?}"),
        }
    }

    /// The clean face: the scan face is available with no holders = Proven
    /// (flag-independent).
    #[test]
    fn three_layer_clean_passes_as_proven() {
        for flag in [false, true] {
            assert_eq!(
                adjudicate_fork_fd_scan(ForkLiveness::Clean, flag),
                Ok(ForkClosedProof::Proven)
            );
        }
    }

    /// The three-layer entry end to end: layer 1 with the lock held
    /// refuses (the flag does not exempt) -> after release a clean db
    /// passes (platforms with a scan face = Proven; platforms without =
    /// the flag accepts responsibility).
    #[tokio::test]
    async fn preflight_three_layer_end_to_end_lock_then_clean() {
        let db = seed_fork_db("threelayer");
        // Layer 1: the exclusive lock is in place -> refuse; the flag does
        // not exempt.
        let locker = ok(rusqlite::Connection::open(&db), "open locker");
        ok(locker.execute_batch("BEGIN EXCLUSIVE;"), "lock");
        for flag in [false, true] {
            let err = preflight_fork_liveness(db.clone(), flag)
                .await
                .err()
                .unwrap_or_else(|| panic!("locked db must refuse (flag={flag})"));
            assert!(err.contains("locked"), "{err}");
        }
        drop(locker);
        // Clean db: layer 1 passes; layers 2/3 split by scan-face
        // availability.
        let (total, proof) = match preflight_fork_liveness(db.clone(), false).await {
            Ok(r) => r,
            Err(err) if err.contains("cannot prove the fork is closed") => {
                // Scan face absent: refuse-by-default = the layer 3
                // semantics; the flag accepts responsibility.
                let (total, proof) = ok(
                    preflight_fork_liveness(db.clone(), true).await,
                    "ack preflight",
                );
                assert!(
                    matches!(proof, ForkClosedProof::AcknowledgedUncertain(_)),
                    "{proof:?}"
                );
                (total, proof)
            }
            other => panic!("unexpected preflight result: {other:?}"),
        };
        assert_eq!(total, 0, "an empty fixture = 0 rows");
        if !matches!(proof, ForkClosedProof::AcknowledgedUncertain(_)) {
            assert_eq!(proof, ForkClosedProof::Proven);
        }
        let _ = std::fs::remove_file(&db);
    }

    // ---- piece->block bitmap mapping x `.aria2` orphan reconciliation x
    // real fork DB fixture regression samples (one dry run + one real
    // run; the serialized text in the real fork write-side
    // SessionSerializer.cc shape) ----

    /// HTTP/FTP `.aria2` control-file bytes (the non-BT save branch of
    /// DefaultBtProgressInfoFile.cc: version 0001 / extension 0 / ihl 0 /
    /// piece length / total / upload=0 / bitfield / 0 in flight).
    fn build_http_ctrl(piece_length: u32, total_length: u64, bitfield: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x00, 0x01]);
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&piece_length.to_be_bytes());
        b.extend_from_slice(&total_length.to_be_bytes());
        b.extend_from_slice(&0u64.to_be_bytes());
        b.extend_from_slice(&(bitfield.len() as u32).to_be_bytes());
        b.extend_from_slice(bitfield);
        b.extend_from_slice(&0u32.to_be_bytes());
        b
    }

    /// Real fork DB regression fixture (the BT-face fixture extended with
    /// HTTP rows; the DDL cross-checked against Sqlite3Migrations.cc) + a
    /// download directory + the `.aria2` face. Rows: 1 BT regression
    /// anchor + 4 HTTP (in-flight with progress / paused without a
    /// progress row / magnet skip / missing-directory failure).
    fn seed_fork_fixture(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "taiji-fixture-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let dl = root.join("download");
        ok(std::fs::create_dir_all(&dl), "mkdir dl");
        let db = root.join("bt.sqlite3");
        let missing_dir = root.join("no-such-relocated-dir");
        {
            let conn = ok(rusqlite::Connection::open(&db), "open fixture db");
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
                     CREATE INDEX idx_task_state ON task(state);
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
            // BT regression anchor (the BT-face fixture: the BT import is
            // unaffected by the added HTTP rows).
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, bt_local_path,
                                       queue_position, digest, created_at, updated_at)
                     VALUES ('00000000000000b7', 'paused', ?1, '/tmp/src/b.torrent',
                             0, x'00', 0, 0)",
                    rusqlite::params![format!(" dir={}\n pause=true\n", dl.display())],
                ),
                "seed bt task",
            );
            ok(
                conn.execute(
                    "INSERT INTO task_progress (gid, is_torrent, info_hash, piece_length,
                                                total_length, upload_length, bitfield,
                                                digest, updated_at)
                     VALUES ('00000000000000b7', 1, ?1, 16384, 32768, 4096, x'C0', x'00', 0)",
                    rusqlite::params![vec![7u8; 20]],
                ),
                "seed bt progress",
            );
            // HTTP A: an in-flight task with progress (the real
            // writer-side serialized shape — a TAB-separated multi-URI
            // first line plus option lines, including a cumulative
            // header).
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, queue_position,
                                       digest, created_at, updated_at)
                     VALUES ('0000000000000042', 'waiting', ?1, 1, x'00', 0, 0)",
                    rusqlite::params![format!(
                        "http://mirror-a.example/f.iso\thttp://mirror-b.example/f.iso\t\n \
                         header=X-From: aria2 fork\n out=f.iso\n dir={}\n \
                         user-agent=aria2/1.37.0\n",
                        dl.display()
                    )],
                ),
                "seed http a",
            );
            ok(
                conn.execute(
                    "INSERT INTO task_progress (gid, is_torrent, piece_length,
                                                total_length, bitfield, digest, updated_at)
                     VALUES ('0000000000000042', 0, 1048576, 10485760, x'E000', x'00', 0)",
                    [],
                ),
                "seed http a progress",
            );
            // HTTP B: paused, no progress row (the task_progress
            // write-failure window shape).
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, queue_position,
                                       digest, created_at, updated_at)
                     VALUES ('0000000000000043', 'paused', ?1, 2, x'00', 0, 0)",
                    rusqlite::params![format!(
                        "http://mirror-a.example/g.zip\t\n out=g.zip\n dir={}\n",
                        dl.display()
                    )],
                ),
                "seed http b",
            );
            // HTTP C: a magnet (the BT face, no migratable progress) ->
            // Skipped.
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, queue_position,
                                       digest, created_at, updated_at)
                     VALUES ('0000000000000044', 'waiting', ?1, 3, x'00', 0, 0)",
                    rusqlite::params!["magnet:?xt=urn:btih:aa\n dir=/dl\n"],
                ),
                "seed http c",
            );
            // HTTP D: the directory is not in place (the .motrix/p/<id>
            // data-move ordering precondition unmet) -> Failed.
            ok(
                conn.execute(
                    "INSERT INTO task (gid, state, serialized, queue_position,
                                       digest, created_at, updated_at)
                     VALUES ('0000000000000045', 'waiting', ?1, 4, x'00', 0, 0)",
                    rusqlite::params![format!(
                        "http://mirror-a.example/h.bin\n out=h.bin\n dir={}\n",
                        missing_dir.display()
                    )],
                ),
                "seed http d",
            );
        }
        // `.aria2` face: merged x2 (A matched on total length; B matched
        // on path with progress filled), orphan x1, BT face x1.
        ok(
            std::fs::write(
                dl.join("f.iso.aria2"),
                build_http_ctrl(1024 * 1024, 10 * 1024 * 1024, &[0xE0, 0x00]),
            ),
            "write f.iso.aria2",
        );
        ok(
            std::fs::write(
                dl.join("g.zip.aria2"),
                build_http_ctrl(256 * 1024, 2 * 1024 * 1024, &[0xC0]),
            ),
            "write g.zip.aria2",
        );
        ok(
            std::fs::write(
                dl.join("orphan.bin.aria2"),
                build_http_ctrl(1024 * 1024, 5 * 1024 * 1024, &[0b1000_0000]),
            ),
            "write orphan ctrl",
        );
        ok(
            std::fs::write(dl.join("orphan.bin"), b"partial"),
            "write orphan data",
        );
        // A BT-face file (extension bit 0 set) -> the HTTP-face accounting
        // keeps it separate.
        let mut bt_ctrl = vec![0x00, 0x01];
        bt_ctrl.extend_from_slice(&[0, 0, 0, 1]);
        bt_ctrl.extend_from_slice(&20u32.to_be_bytes());
        bt_ctrl.extend_from_slice(&[0u8; 20]);
        bt_ctrl.extend_from_slice(&16384u32.to_be_bytes());
        bt_ctrl.extend_from_slice(&32768u64.to_be_bytes());
        bt_ctrl.extend_from_slice(&0u64.to_be_bytes());
        bt_ctrl.extend_from_slice(&1u32.to_be_bytes());
        bt_ctrl.extend_from_slice(&[0xC0]);
        bt_ctrl.extend_from_slice(&0u32.to_be_bytes());
        ok(
            std::fs::write(dl.join("migrated.bin.aria2"), bt_ctrl),
            "write bt ctrl",
        );
        (root, db, dl)
    }

    /// Orphan-reconciliation classification: merged x2 (one fills a
    /// progress-less row), orphan x1, BT face x1; after the fill the task
    /// carries the control-file progress.
    #[tokio::test]
    async fn reconcile_aria2_orphans_classifies_and_fills_progress() {
        let (root, db, dl) = seed_fork_fixture("reconcile");
        let fc = ok(
            collect_fork_all_tasks(db.clone(), dl.clone()).await,
            "collect",
        );
        let (_entries, report) = ok(
            reconcile_aria2_orphans(dl.clone(), fc.http).await,
            "reconcile",
        );
        assert_eq!(report.entries.len(), 4, "entries: {:?}", report.entries);
        assert_eq!(
            report.reconciled_count(),
            2,
            "entries: {:?}",
            report.entries
        );
        assert_eq!(report.orphan_count(), 1, "entries: {:?}", report.entries);
        // Lexicographic: f.iso < g.zip < migrated(BT) < orphan.
        // A: a total-length match (10MiB == the row progress total); the
        // row has its own progress -> not filled.
        match &report.entries[0] {
            Aria2Reconciliation::Reconciled {
                fork_gid,
                total_length,
                progress_filled,
                data_present,
                ..
            } => {
                assert_eq!(fork_gid, "0000000000000042");
                assert_eq!(*total_length, 10 * 1024 * 1024);
                assert!(
                    !progress_filled,
                    "the row has progress, the control file is redundant"
                );
                assert!(
                    !data_present,
                    "the f.iso data file is not laid down (the fixture only carries the progress face)"
                );
            }
            other => panic!("entry 0 must be Reconciled(A), got {other:?}"),
        }
        // B: a path match (the row has no progress) -> control-file
        // progress filled.
        match &report.entries[1] {
            Aria2Reconciliation::Reconciled {
                fork_gid,
                progress_filled,
                ..
            } => {
                assert_eq!(fork_gid, "0000000000000043");
                assert!(
                    progress_filled,
                    "the missing progress row is backfilled from the control file"
                );
            }
            other => panic!("entry 1 must be Reconciled(B), got {other:?}"),
        }
        // BT face: kept separate.
        assert!(
            matches!(
                &report.entries[2],
                Aria2Reconciliation::BitTorrentFace { .. }
            ),
            "entry 2: {:?}",
            report.entries[2]
        );
        // Orphan: no matching row.
        match &report.entries[3] {
            Aria2Reconciliation::Orphan {
                total_length,
                data_present,
                ..
            } => {
                assert_eq!(*total_length, 5 * 1024 * 1024);
                assert!(data_present, "orphan.bin data is on disk");
            }
            other => panic!("entry 3 must be Orphan, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Reconciliation-key negatives — a control file with the same
    /// (dir,out) but a different totalLength is NOT merged (Orphan).
    /// Three cases:
    /// a) a row with progress (10MiB) x a ctrl total of 5MiB -> Orphan
    /// (the totalLength half-guard; removing the guard turns this test
    /// red);
    /// b) a row without progress x on-disk data 4MiB x a ctrl total of
    /// 2MiB -> Orphan (the on-disk length corroboration for progress-less
    /// merges — a second guard, likewise red on removal);
    /// c) a row without progress x on-disk data 3MiB = a ctrl total of
    /// 3MiB -> merged with fill (the positive control proving the guards
    /// do not reject same-source pairs).
    #[tokio::test]
    async fn reconcile_rejects_total_length_mismatched_ctrl() {
        let root = std::env::temp_dir().join(format!(
            "taiji-reconcile-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        ok(std::fs::create_dir_all(&root), "mkdir");
        let dir = root.display().to_string();
        let task = |out: &str, progress: Option<HttpProgressFacts>, fork_gid: &str| {
            HttpCollectEntry::Ready(Box::new(HttpSourceTask {
                source: ImportSource::ForkDb {
                    db_path: root.join("fork.sqlite3"),
                    fork_gid: fork_gid.to_string(),
                },
                source_key: format!("imported_from:db:{fork_gid}"),
                fork_gid: Some(fork_gid.to_string()),
                queue_pos: 0,
                uris: vec![format!("http://a/{out}")],
                unsupported_uris: Vec::new(),
                dir: dir.clone(),
                out: Some(out.to_string()),
                paused: false,
                options: Vec::new(),
                progress,
            }))
        };
        // ctrl face (lexicographic = processing order): a-w < b-n < c-m.
        // The bitmap byte length follows each declared geometry (the
        // fixed-length formula ceil(pieces/8)).
        ok(
            std::fs::write(
                root.join("a-w.bin.aria2"),
                build_http_ctrl(1024 * 1024, 5 * 1024 * 1024, &[0xE0]),
            ),
            "write a-w ctrl",
        );
        ok(
            std::fs::write(
                root.join("b-n.bin.aria2"),
                build_http_ctrl(256 * 1024, 2 * 1024 * 1024, &[0xC0]),
            ),
            "write b-n ctrl",
        );
        ok(
            std::fs::write(
                root.join("c-m.bin.aria2"),
                build_http_ctrl(256 * 1024, 3 * 1024 * 1024, &[0x80, 0x00]),
            ),
            "write c-m ctrl",
        );
        // Data face (sparse, length only): b-n 4MiB != ctrl 2MiB (a
        // foreign source); c-m 3MiB = ctrl 3MiB (corroboration holds).
        let seed_len = |name: &str, len: u64| {
            let f = ok(std::fs::File::create(root.join(name)), "create {name}");
            ok(f.set_len(len), "set {name} len");
        };
        seed_len("b-n.bin", 4 * 1024 * 1024);
        seed_len("c-m.bin", 3 * 1024 * 1024);
        let progress10 = HttpProgressFacts {
            piece_length: 1024 * 1024,
            total_length: 10 * 1024 * 1024,
            bitfield: vec![0xE0, 0x00],
        };
        let entries = vec![
            task("a-w.bin", Some(progress10), "00000000000000w1"),
            task("b-n.bin", None, "00000000000000n2"),
            task("c-m.bin", None, "00000000000000m3"),
        ];
        let (entries, report) = ok(
            reconcile_aria2_orphans(root.clone(), entries).await,
            "reconcile",
        );
        assert_eq!(report.entries.len(), 3, "{:?}", report.entries);
        // a) a row with progress x a different total -> Orphan (the
        // totalLength-half negative).
        assert!(
            matches!(
                &report.entries[0],
                Aria2Reconciliation::Orphan { total_length, .. }
                    if *total_length == 5 * 1024 * 1024
            ),
            "entry 0: {:?}",
            report.entries[0]
        );
        // b) a row without progress x an on-disk length != the ctrl total
        // -> Orphan (the length-corroboration negative).
        assert!(
            matches!(
                &report.entries[1],
                Aria2Reconciliation::Orphan { total_length, .. }
                    if *total_length == 2 * 1024 * 1024
            ),
            "entry 1: {:?}",
            report.entries[1]
        );
        // c) corroboration holds -> merged with fill (the positive
        // control).
        match &report.entries[2] {
            Aria2Reconciliation::Reconciled {
                fork_gid,
                progress_filled,
                data_present,
                ..
            } => {
                assert_eq!(fork_gid, "00000000000000m3");
                assert!(
                    progress_filled,
                    "corroboration holds = the missing progress row is backfilled"
                );
                assert!(*data_present, "c-m.bin is on disk");
            }
            other => panic!("entry 2 must be Reconciled, got {other:?}"),
        }
        // Row-side payload check: a's original progress is not overwritten
        // by the foreign ctrl; b stays unfilled (weak resume preserved);
        // c is filled with the ctrl progress.
        assert_eq!(entries.len(), 3);
        let progress_of = |e: &HttpCollectEntry| match e {
            HttpCollectEntry::Ready(t) => t.progress.clone(),
            other => panic!("expected ready entry, got {other:?}"),
        };
        assert_eq!(
            progress_of(&entries[0]),
            Some(HttpProgressFacts {
                piece_length: 1024 * 1024,
                total_length: 10 * 1024 * 1024,
                bitfield: vec![0xE0, 0x00],
            }),
            "a row carrying progress = the fork is authoritative, a foreign ctrl must not overwrite"
        );
        assert_eq!(
            progress_of(&entries[1]),
            None,
            "foreign corroboration fails = no backfill (the weak-resume row is preserved)"
        );
        assert_eq!(
            progress_of(&entries[2]),
            Some(HttpProgressFacts {
                piece_length: 256 * 1024,
                total_length: 3 * 1024 * 1024,
                bitfield: vec![0x80, 0x00],
            }),
            "corroboration holds = the ctrl progress backfills"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A dead dedup back-reference can be re-imported. Both states of the
    /// chain:
    /// (1) import -> delete the task row (the close-out clears the kv
    /// mark) -> the dry-run snapshot no longer hits -> a re-import plans
    /// normally;
    /// (2) a leftover dead reference (old-version delete leftovers: the kv
    /// present, the referenced row absent) -> the snapshot liveness check
    /// fails = treated as not-imported + noted in `stale_imported` -> a
    /// re-import plans normally.
    #[tokio::test]
    async fn dedup_backref_liveness_allows_reimport_after_delete() {
        use taiji_store::persist::PersistWriter;
        let db = seed_fork_db("reimport");
        let dir = seed_dir("reimport");
        {
            let conn = ok(rusqlite::Connection::open(&db), "reopen");
            insert_http_task(
                &conn,
                "0000000000000031",
                &format!("http://a/r.bin\n out=r.bin\n dir={}\n", dir.display()),
                0,
                "waiting",
            );
        }
        let (total, entries) = ok(
            collect_fork_http_tasks(db.clone(), dir.clone()).await,
            "collect",
        );
        assert_eq!(total, 1);
        let tasks: Vec<HttpSourceTask> = entries
            .into_iter()
            .map(|e| match e {
                HttpCollectEntry::Ready(t) => *t,
                other => panic!("expected ready, got {other:?}"),
            })
            .collect();
        let target = std::env::temp_dir().join(format!(
            "taiji-reimport-target-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let key = tasks[0].source_key.clone();
        // First import: persist the row + the kv mark; the snapshot hits
        // (the reference points at a live row).
        let mut planner = HttpImportPlanner::new(Vec::new());
        let planned = match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000091".to_string(),
            imported_gid: None,
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => vec![*p],
            other => panic!("first import must plan: {other:?}"),
        };
        let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn");
        let applied = apply_http_import(&handle, &planned).await;
        assert!(
            applied.iter().all(|a| a.error.is_none()),
            "apply: {applied:?}"
        );
        let snap = ok(
            read_target_snapshot_for_dry_run(target.clone(), vec![key.clone()]).await,
            "snap 1",
        );
        assert_eq!(
            snap.imported.get(&key).cloned().flatten().as_deref(),
            Some("8000000000000091"),
            "a pointer to a live row = a hit"
        );
        assert!(snap.stale_imported.is_empty());
        // (1) delete the task row -> the mark is cleared with it -> the
        // snapshot no longer hits -> a re-import plans normally.
        ok(handle.delete_http_task("8000000000000091").await, "delete");
        let snap = ok(
            read_target_snapshot_for_dry_run(target.clone(), vec![key.clone()]).await,
            "snap 2",
        );
        assert_eq!(
            snap.imported.get(&key),
            Some(&None),
            "the marker was cleaned up along with the deletion"
        );
        assert!(
            snap.stale_imported.is_empty(),
            "the deletion closes cleanly = no dead pointers remain"
        );
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );
        let mut planner = HttpImportPlanner::new(Vec::new());
        match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000092".to_string(),
            imported_gid: None,
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => assert_eq!(p.gid, "8000000000000092"),
            other => panic!("re-import after delete must plan: {other:?}"),
        }
        // (2) a leftover dead reference (kv present, referenced row
        // absent) -> liveness fails = treated as not-imported + a
        // stale_imported note -> a re-import plans normally.
        {
            let conn = ok(rusqlite::Connection::open(&target), "reopen target");
            ok(
                conn.execute(
                    "INSERT INTO session_kv (key, value) VALUES (?1, '8000000000000099')",
                    rusqlite::params![key],
                ),
                "seed stale mark",
            );
        }
        let snap = ok(
            read_target_snapshot_for_dry_run(target.clone(), vec![key.clone()]).await,
            "snap 3",
        );
        assert_eq!(
            snap.imported.get(&key),
            Some(&None),
            "a dead pointer is treated as not-imported"
        );
        assert_eq!(
            snap.stale_imported,
            vec![key.clone()],
            "the stale key is recorded"
        );
        let mut planner = HttpImportPlanner::new(Vec::new());
        match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000093".to_string(),
            imported_gid: snap.imported.get(&key).cloned().flatten(),
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => assert_eq!(p.gid, "8000000000000093"),
            other => panic!("re-import with stale backref must plan: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(&target);
    }

    /// The real fork DB regression full chain (one dry run + one real
    /// run): dry = collect + reconcile + plan (zero write side effects);
    /// real = persist + rows read back column by column (bitmap payload/
    /// digest/dedup kv) + second-import interception.
    #[tokio::test]
    async fn fixture_dry_run_then_real_run_rounds() {
        use taiji_store::persist::PersistWriter;
        let (root, db, dl) = seed_fork_fixture("rounds");
        let target = root.join("taiji.sqlite3");

        // ---- dry run (one round): zero write side effects ----
        let fc = ok(
            collect_fork_all_tasks(db.clone(), dl.clone()).await,
            "collect",
        );
        assert_eq!(fc.total_tasks, 5, "the full-row baseline (BT 1 + HTTP 4)");
        assert_eq!(
            fc.bt.len(),
            1,
            "the BT-face regression anchor is unaffected by the added HTTP rows"
        );
        let (mut entries, report) = ok(
            reconcile_aria2_orphans(dl.clone(), fc.http).await,
            "reconcile",
        );
        assert_eq!((report.reconciled_count(), report.orphan_count()), (2, 1));
        // Plan (the Ready face; the Skipped/Failed classes asserted; B's
        // progress already filled by reconciliation).
        let mut tasks = Vec::new();
        for e in entries.drain(..) {
            match e {
                HttpCollectEntry::Ready(t) => tasks.push(*t),
                HttpCollectEntry::Skipped { source, reason } => {
                    assert!(
                        matches!(
                            &source,
                            ImportSource::ForkDb { fork_gid, .. }
                                if fork_gid == "0000000000000044"
                        ),
                        "magnet row: {source:?}"
                    );
                    assert!(reason.contains("magnet"), "{reason}");
                }
                HttpCollectEntry::Failed { source, reason } => {
                    assert!(
                        matches!(
                            &source,
                            ImportSource::ForkDb { fork_gid, .. }
                                if fork_gid == "0000000000000045"
                        ),
                        "dangling row: {source:?}"
                    );
                    assert!(reason.contains(".motrix/p/<id>"), "{reason}");
                }
            }
        }
        assert_eq!(tasks.len(), 2, "A + B are Ready (C skipped / D failed)");
        let mut planner = HttpImportPlanner::new(Vec::new());
        let mut planned = Vec::new();
        let gids = ["80000000000000f1", "80000000000000f2"];
        for (i, task) in tasks.iter().enumerate() {
            match planner.plan(HttpPlanInput {
                task,
                gid_hex: gids[i].to_string(),
                imported_gid: None,
                conflict_action: PathConflictAction::Skip,
            }) {
                HttpPlanEntry::Planned(p) => planned.push(*p),
                other => panic!("task {i} must plan, got {other:?}"),
            }
        }
        assert!(
            !target.exists(),
            "a dry run must not create the target database"
        );

        // ---- real run (one round): persist + rows read back column by
        // column ----
        let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn writer");
        let applied = apply_http_import(&handle, &planned).await;
        assert!(
            applied.iter().all(|a| a.error.is_none()),
            "apply errors: {applied:?}"
        );
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );
        let (handle2, join2) = ok(PersistWriter::spawn(target.clone()).await, "respawn");
        let snaps = ok(handle2.load_http_tasks_at_startup().await, "load startup");
        assert_eq!(
            snaps.len(),
            2,
            "rows: {:?}",
            snaps.iter().map(|s| &s.row).collect::<Vec<_>>()
        );
        let by_gid = |gid: &str| {
            snaps
                .iter()
                .find(|s| s.row.gid == gid)
                .unwrap_or_else(|| panic!("row {gid} missing"))
        };
        // A: fork DB progress -> blocks 0-2/10 @ 1MiB (the
        // complete-coverage mapping).
        let a = &by_gid("80000000000000f1").row;
        assert_eq!(a.out, "f.iso");
        assert_eq!(
            a.mirrors_json.as_deref(),
            Some(
                r#"[{"url":"http://mirror-a.example/f.iso"},{"url":"http://mirror-b.example/f.iso"}]"#
            ),
            "the real multi-source mirrors_json shape"
        );
        assert_eq!(a.block_size, 1024 * 1024);
        assert_eq!(a.block_bitmap.as_deref(), Some(&[0b0000_0111u8, 0x00][..]));
        assert_eq!(a.block_count, Some(10));
        assert_eq!(a.total_done, 3 * 1024 * 1024);
        // The digest = the deterministic digest of the facts known at
        // import (the first URI path + the total length).
        assert_eq!(
            a.validator_digest.as_deref(),
            validator_digest(&ValidatorFacts {
                final_url_path: url_path("http://mirror-a.example/f.iso").to_string(),
                total_len: Some(10 * 1024 * 1024),
                etag: None,
                last_modified: None,
                encoding_ok: true,
            })
            .ok()
            .as_deref(),
        );
        // B: control-file progress filled (merged) -> blocks 0-1/8 @
        // 256KiB, paused.
        let b = &by_gid("80000000000000f2").row;
        assert_eq!(b.state, "paused");
        assert_eq!(b.out, "g.zip");
        assert_eq!(b.block_size, 256 * 1024);
        assert_eq!(b.block_bitmap.as_deref(), Some(&[0b0000_0011u8][..]));
        assert_eq!(b.block_count, Some(8));
        assert_eq!(b.total_done, 2 * 256 * 1024);
        // Dedup kv x2.
        let mut kv_count = 0;
        for p in &planned {
            if ok(handle2.get_kv(&p.source_key).await, "get kv").is_some() {
                kv_count += 1;
            }
        }
        assert_eq!(kv_count, 2, "dedup markers land as a pair");
        drop(handle2);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join2).await,
            "writer 2 exit",
        );

        // ---- second import: dedup interception (all Skipped at planning)
        // ----
        let mut planner = HttpImportPlanner::new(Vec::new());
        for (i, task) in tasks.iter().enumerate() {
            let gid_hex = format!("800000000000{:04x}", 0x0080 + i as u16);
            match planner.plan(HttpPlanInput {
                task,
                gid_hex,
                imported_gid: Some(gids[i].to_string()),
                conflict_action: PathConflictAction::Skip,
            }) {
                HttpPlanEntry::Skipped { reason, .. } => {
                    assert!(reason.contains("already imported"), "{reason}");
                }
                other => panic!("re-import must skip task {i}, got {other:?}"),
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ===== imported in-flight progress activation rescue (flag + data
    // adoption) =====

    /// Bitmap-row test constructor (a paused row baseline; `out`/bitmap
    /// overridden per case).
    fn p50_row(gid: &str, dir: &Path, out: &str, bitmap: Option<Vec<u8>>) -> HttpTaskRow {
        HttpTaskRow {
            gid: gid.into(),
            url: "http://a/f.bin".into(),
            final_url: String::new(),
            mirrors_json: None,
            state: "paused".into(),
            queue_pos: 0,
            dir: dir.display().to_string(),
            out: out.into(),
            config_json: HttpPersistConfig::default().to_json(),
            probe_json: None,
            validator_digest: None,
            block_size: 256 * 1024,
            block_bitmap: bitmap,
            block_count: Some(8),
            total_done: 0,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    /// Planning face: bitmap rows get the imported_progress flag (the
    /// criterion bit that disables auto-rename at activation and degrades
    /// the digest gate); weak-resume rows (no progress) carry no flag —
    /// the key is not written, config_json stays zero-drift.
    #[test]
    fn planner_marks_imported_progress_flag_only_for_bitmap_rows() {
        let dir = seed_dir("p50-flag");
        let task = |progress: Option<HttpProgressFacts>| HttpSourceTask {
            source_key: "fork-db:0000000000000051".into(),
            fork_gid: Some("0000000000000051".into()),
            queue_pos: 0,
            uris: vec!["http://a/f.bin".into()],
            unsupported_uris: vec![],
            dir: dir.display().to_string(),
            out: Some("f.bin".into()),
            paused: false,
            options: vec![],
            progress,
            source: ImportSource::ForkDb {
                db_path: dir.join("fork.sqlite3"),
                fork_gid: "0000000000000051".into(),
            },
        };
        // Bitmap row (pieces 0-2/10 @ 1MiB, complete coverage) -> the flag
        // set.
        let mut planner = HttpImportPlanner::new(Vec::new());
        let with_progress = match planner.plan(HttpPlanInput {
            task: &task(Some(HttpProgressFacts {
                piece_length: 1024 * 1024,
                total_length: 10 * 1024 * 1024,
                bitfield: vec![0b1110_0000, 0x00],
            })),
            gid_hex: "8000000000000501".into(),
            imported_gid: None,
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => *p,
            other => panic!("bitmap row must plan: {other:?}"),
        };
        let cfg = HttpPersistConfig::from_json(&with_progress.row.config_json);
        assert!(
            cfg.imported_progress,
            "a bitmap row must carry the imported_progress flag"
        );
        // Weak-resume row (no progress) -> no flag; the key is not written
        // (zero drift).
        let mut planner = HttpImportPlanner::new(Vec::new());
        let weak = match planner.plan(HttpPlanInput {
            task: &task(None),
            gid_hex: "8000000000000502".into(),
            imported_gid: None,
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => *p,
            other => panic!("weak row must plan: {other:?}"),
        };
        let cfg = HttpPersistConfig::from_json(&weak.row.config_json);
        assert!(
            !cfg.imported_progress,
            "a weak-resume row must not carry the imported_progress flag"
        );
        assert!(
            !weak.row.config_json.contains("imported_progress"),
            "flag false writes no bytes (zero drift of the existing payload): {}",
            weak.row.config_json
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Adoption on real import: the fork data file of a bitmap row is
    /// archive-renamed `<out>` -> `<out>.part` (the fork writes the final
    /// path while the taiji resume face only accepts `.part`; without
    /// adoption, activation hits PartFileMissing -> FromZero, the bitmap
    /// clears, and the partial data is lost). Guard matrix: part slot
    /// taken / no bitmap row (the Restart-truncation data-destruction
    /// defense) / final file absent / out absent — none adopt, everything
    /// stays as-is (skip adoption rather than destroy data).
    #[tokio::test]
    async fn apply_adopts_fork_data_file_into_part_slot_with_guards() {
        use taiji_store::persist::PersistWriter;
        let dir = seed_dir("p50-adopt");
        let db = dir.parent().unwrap_or(Path::new(".")).join(format!(
            "taiji-p50-adopt-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let bm = Some(vec![0b0000_1111u8]);
        let planned = vec![
            // a: a bitmap row + the final file on disk -> adopted
            // (`adopt.bin` -> `adopt.bin.part`).
            PlannedHttpImport {
                source_key: "k-a".into(),
                gid: "8000000000000a01".into(),
                dir: dir.display().to_string(),
                out: "adopt.bin".into(),
                warnings: vec![],
                row: p50_row("8000000000000a01", &dir, "adopt.bin", bm.clone()),
                source: ImportSource::ForkDb {
                    db_path: db.clone(),
                    fork_gid: "a".into(),
                },
                fork_gid: Some("a".into()),
                state: "paused".into(),
                uri_count: 1,
            },
            // b: the part slot is taken (the two data sets cannot be
            // merged) -> both stay as-is.
            PlannedHttpImport {
                source_key: "k-b".into(),
                gid: "8000000000000a02".into(),
                dir: dir.display().to_string(),
                out: "both.bin".into(),
                warnings: vec![],
                row: p50_row("8000000000000a02", &dir, "both.bin", bm.clone()),
                source: ImportSource::ForkDb {
                    db_path: db.clone(),
                    fork_gid: "b".into(),
                },
                fork_gid: Some("b".into()),
                state: "paused".into(),
                uri_count: 1,
            },
            // c: no bitmap row, not adopted (renaming it would let an
            // activation Restart truncate = data destruction).
            PlannedHttpImport {
                source_key: "k-c".into(),
                gid: "8000000000000a03".into(),
                dir: dir.display().to_string(),
                out: "weak.bin".into(),
                warnings: vec![],
                row: p50_row("8000000000000a03", &dir, "weak.bin", None),
                source: ImportSource::ForkDb {
                    db_path: db.clone(),
                    fork_gid: "c".into(),
                },
                fork_gid: Some("c".into()),
                state: "paused".into(),
                uri_count: 1,
            },
            // d: the final file is absent (the data-move window) -> no
            // adoption, no error.
            PlannedHttpImport {
                source_key: "k-d".into(),
                gid: "8000000000000a04".into(),
                dir: dir.display().to_string(),
                out: "absent.bin".into(),
                warnings: vec![],
                row: p50_row("8000000000000a04", &dir, "absent.bin", bm.clone()),
                source: ImportSource::ForkDb {
                    db_path: db.clone(),
                    fork_gid: "d".into(),
                },
                fork_gid: Some("d".into()),
                state: "paused".into(),
                uri_count: 1,
            },
            // e: out absent (named at activation) -> no path to adopt.
            PlannedHttpImport {
                source_key: "k-e".into(),
                gid: "8000000000000a05".into(),
                dir: dir.display().to_string(),
                out: String::new(),
                warnings: vec![],
                row: p50_row("8000000000000a05", &dir, "", bm.clone()),
                source: ImportSource::ForkDb {
                    db_path: db.clone(),
                    fork_gid: "e".into(),
                },
                fork_gid: Some("e".into()),
                state: "paused".into(),
                uri_count: 1,
            },
        ];
        // Disk fixture: the a/b/c fork data files + b's existing part.
        let seed = |name: &str, body: &[u8]| {
            ok(
                std::fs::write(dir.join(name), body),
                &format!("seed {name}"),
            );
        };
        seed("adopt.bin", b"fork-frontier-data");
        seed("both.bin", b"fork-leftover");
        seed("both.bin.part", b"taiji-part");
        seed("weak.bin", b"weak-data");

        let (handle, join) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
        let applied = apply_http_import(&handle, &planned).await;
        assert!(
            applied.iter().all(|a| a.error.is_none()),
            "apply errors: {applied:?}"
        );
        // a: adopted — the final file is archived as `.part`, bytes
        // intact.
        assert!(
            !dir.join("adopt.bin").exists(),
            "the final file must already be renamed into the archive"
        );
        assert_eq!(
            ok(std::fs::read(dir.join("adopt.bin.part")), "read adopted"),
            b"fork-frontier-data",
            "adopting the `.part` bytes = the fork-side frontier data"
        );
        // b: the part slot taken -> both as-is.
        assert_eq!(
            ok(std::fs::read(dir.join("both.bin")), "read both final"),
            b"fork-leftover"
        );
        assert_eq!(
            ok(std::fs::read(dir.join("both.bin.part")), "read both part"),
            b"taiji-part"
        );
        // c: no bitmap row, not adopted.
        assert_eq!(
            ok(std::fs::read(dir.join("weak.bin")), "read weak"),
            b"weak-data"
        );
        assert!(!dir.join("weak.bin.part").exists());
        // d: the final file absent -> no `.part` conjured.
        assert!(!dir.join("absent.bin").exists());
        assert!(!dir.join("absent.bin.part").exists());
        // All five rows stored.
        let snaps = ok(handle.load_http_tasks_at_startup().await, "load startup");
        assert_eq!(snaps.len(), 5, "adoption does not disturb the persist face");
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
    }

    // ===== the dedup key stored with the row (the origin_fork_key single
    // criterion + dual-mode anchors) =====

    /// Test task constructor (with/without fork progress; source_key =
    /// the same deterministic key as the collect face).
    fn p56_task(
        dir: &Path,
        source_key: &str,
        progress: Option<HttpProgressFacts>,
    ) -> HttpSourceTask {
        HttpSourceTask {
            source: ImportSource::ForkDb {
                db_path: dir.join("fork.sqlite3"),
                fork_gid: "0000000000000056".into(),
            },
            source_key: source_key.into(),
            fork_gid: Some("0000000000000056".into()),
            queue_pos: 0,
            uris: vec!["http://a/f.bin".into()],
            unsupported_uris: Vec::new(),
            dir: dir.display().to_string(),
            out: Some("f.bin".into()),
            paused: false,
            options: vec![],
            progress,
        }
    }

    /// Every planned row (bitmap and weak-resume states) carries
    /// origin_fork_key in its config_json (the criterion itself stored on
    /// the row). The flag semantics do not regress: a weak-resume row has
    /// no imported_progress but does have origin_fork_key (orthogonal
    /// criterion domains).
    #[test]
    fn planner_stamps_origin_fork_key_on_every_planned_row() {
        let dir = seed_dir("p56-stamp");
        let key = "imported_from:db:/f.sqlite3#0000000000000056";
        let progress = HttpProgressFacts {
            piece_length: 1024 * 1024,
            total_length: 10 * 1024 * 1024,
            bitfield: vec![0b1110_0000, 0x00],
        };
        for (tag, task) in [
            ("bitmap", p56_task(&dir, key, Some(progress.clone()))),
            ("weak", p56_task(&dir, key, None)),
        ] {
            let mut planner = HttpImportPlanner::new(Vec::new());
            let planned = match planner.plan(HttpPlanInput {
                task: &task,
                gid_hex: format!("800000000000056{}", if tag == "bitmap" { "1" } else { "2" }),
                imported_gid: None,
                conflict_action: PathConflictAction::Skip,
            }) {
                HttpPlanEntry::Planned(p) => *p,
                other => panic!("row must plan: {other:?}"),
            };
            let cfg = HttpPersistConfig::from_json(&planned.row.config_json);
            assert_eq!(
                cfg.origin_fork_key.as_deref(),
                Some(key),
                "{tag}: the evidence key must persist with the row"
            );
            assert!(
                planned.row.config_json.contains("origin_fork_key"),
                "{tag}: the evidence key bytes are inside the row payload: {}",
                planned.row.config_json
            );
            if tag == "weak" {
                assert!(
                    !planned.row.config_json.contains("imported_progress"),
                    "the weak-resume row still writes no imported_progress"
                );
            }
        }
        // Engine-built tasks' default payload stays zero-drift:
        // origin_fork_key None writes no bytes.
        let bare = HttpPersistConfig::default().to_json();
        assert!(
            !bare.contains("origin_fork_key"),
            "zero drift of the default payload: {bare}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Hit criterion = row present + key equal, both directions end to
    /// end. Positive: the row present (the kv reverse index explicitly
    /// wiped and it still hits — the criterion lives on the row, a missing
    /// kv never lets a duplicate through). Negative: a row with another
    /// key / no row -> not imported; deleting the criterion row -> a
    /// re-import allowed with no dead-marker form (stale_imported stays
    /// empty).
    #[tokio::test]
    async fn dedup_row_key_hit_skips_and_row_absent_reimports() {
        use taiji_store::persist::PersistWriter;
        let db = seed_fork_db("p56-criterion");
        let dir = seed_dir("p56-criterion");
        {
            let conn = ok(rusqlite::Connection::open(&db), "reopen");
            insert_http_task(
                &conn,
                "0000000000000056",
                &format!("http://a/k.bin\n out=k.bin\n dir={}\n", dir.display()),
                0,
                "waiting",
            );
        }
        let (_total, entries) = ok(
            collect_fork_http_tasks(db.clone(), dir.clone()).await,
            "collect",
        );
        let tasks: Vec<HttpSourceTask> = entries
            .into_iter()
            .map(|e| match e {
                HttpCollectEntry::Ready(t) => *t,
                other => panic!("expected ready, got {other:?}"),
            })
            .collect();
        let target = std::env::temp_dir().join(format!(
            "taiji-p56-criterion-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let key = tasks[0].source_key.clone();
        // First import: the row + the kv reverse index stored as a pair.
        let mut planner = HttpImportPlanner::new(Vec::new());
        let planned = match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000560".to_string(),
            imported_gid: None,
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => vec![*p],
            other => panic!("first import must plan: {other:?}"),
        };
        let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn");
        let applied = apply_http_import(&handle, &planned).await;
        assert!(
            applied.iter().all(|a| a.error.is_none()),
            "apply: {:?}",
            applied[0].error
        );
        // Positive (the criterion lives on the row): wipe the kv reverse
        // index and it still hits — a missing kv never leaks a duplicate.
        {
            let conn = ok(rusqlite::Connection::open(&target), "reopen target");
            ok(
                conn.execute(
                    "DELETE FROM session_kv WHERE key = ?1",
                    rusqlite::params![key],
                ),
                "drop reverse-index mark",
            );
        }
        let snap = ok(
            read_target_snapshot_for_dry_run(target.clone(), vec![key.clone(), "no-such".into()])
                .await,
            "snap row-criterion",
        );
        assert_eq!(
            snap.imported.get(&key).cloned().flatten().as_deref(),
            Some("8000000000000560"),
            "row present + key equal = a hit (the missing kv reverse index does not let a block slip through)"
        );
        assert_eq!(
            snap.imported.get("no-such"),
            Some(&None),
            "negative case: no row, no key = not imported"
        );
        assert!(
            snap.stale_imported.is_empty(),
            "the row-evidence shape has no dead-marker form: a hit produces no stale entry"
        );
        // A hit -> the planner skips (the reference points at a live row).
        let mut planner = HttpImportPlanner::new(Vec::new());
        match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000561".to_string(),
            imported_gid: snap.imported.get(&key).cloned().flatten(),
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Skipped { reason, .. } => {
                assert!(reason.contains("already imported"), "{reason}");
                assert!(
                    reason.contains("origin_fork_key"),
                    "the skip wording is anchored on the row-key evidence: {reason}"
                );
            }
            other => panic!("row-key hit must skip: {other:?}"),
        }
        // Row absent = a re-import allowed: deleting the criterion row
        // (the close-out clears the reverse index) -> not imported, no
        // dead-marker form; a re-import plans normally.
        ok(handle.delete_http_task("8000000000000560").await, "delete");
        let snap = ok(
            read_target_snapshot_for_dry_run(target.clone(), vec![key.clone()]).await,
            "snap after delete",
        );
        assert_eq!(
            snap.imported.get(&key),
            Some(&None),
            "row absent = a re-import is allowed"
        );
        assert!(
            snap.stale_imported.is_empty(),
            "the row deletion closes cleanly = no dead markers remain"
        );
        let mut planner = HttpImportPlanner::new(Vec::new());
        match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000562".to_string(),
            imported_gid: snap.imported.get(&key).cloned().flatten(),
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => assert_eq!(p.gid, "8000000000000562"),
            other => panic!("row absent must re-import: {other:?}"),
        }
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(&target);
    }

    /// Dual-mode second-import semantics:
    /// **`.bak` restore mode** — the dedup marks roll back with the
    /// database (row + key restored together), so upgrading again = a
    /// full re-import (the report notes the weak resume/bitmap
    /// reconciliation backstop — downloaded bytes are not re-downloaded);
    /// **target-keep mode** — the row is in the database, an
    /// `origin_fork_key` hit skips.
    #[tokio::test]
    async fn dual_mode_second_import_bak_restore_reimports_and_target_keep_skips() {
        use taiji_store::persist::PersistWriter;
        let db = seed_fork_db("p56-dual");
        let dir = seed_dir("p56-dual");
        {
            let conn = ok(rusqlite::Connection::open(&db), "reopen");
            insert_http_task(
                &conn,
                "0000000000000056",
                &format!("http://a/d.bin\n out=d.bin\n dir={}\n", dir.display()),
                0,
                "waiting",
            );
        }
        let (_total, entries) = ok(
            collect_fork_http_tasks(db.clone(), dir.clone()).await,
            "collect",
        );
        let tasks: Vec<HttpSourceTask> = entries
            .into_iter()
            .map(|e| match e {
                HttpCollectEntry::Ready(t) => *t,
                other => panic!("expected ready, got {other:?}"),
            })
            .collect();
        let target = std::env::temp_dir().join(format!(
            "taiji-p56-dual-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        // The target db exists before the first import (nothing to adopt)
        // -> the pre-import backup produces `.v1.bak` (the rollback
        // runbook's recovery anchor).
        {
            let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn seed");
            ok(handle.put_kv("pre-import", "state").await, "seed kv");
            drop(handle);
            let _ = ok(
                tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
                "seed writer exit",
            );
        }
        match ok(
            backup_target_for_import(target.clone()).await,
            "pre-import backup",
        ) {
            ImportBackup::Created(_) => {}
            other => panic!("expected Created backup, got {other:?}"),
        }
        let bak_path = {
            let mut s = target.as_os_str().to_os_string();
            s.push(".v1.bak");
            PathBuf::from(s)
        };
        // First import: the row (origin_fork_key on it) + the kv reverse
        // index.
        let key = tasks[0].source_key.clone();
        let mut planner = HttpImportPlanner::new(Vec::new());
        let planned = match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000560".to_string(),
            imported_gid: None,
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => vec![*p],
            other => panic!("first import must plan: {other:?}"),
        };
        let (handle, join) = ok(PersistWriter::spawn(target.clone()).await, "spawn");
        let applied = apply_http_import(&handle, &planned).await;
        assert!(
            applied.iter().all(|a| a.error.is_none()),
            "apply: {:?}",
            applied[0].error
        );
        // ---- target-keep mode: the row is in the db -> an
        // origin_fork_key hit skips ----
        let snap = ok(
            read_target_snapshot_for_dry_run(target.clone(), vec![key.clone()]).await,
            "snap keep",
        );
        assert_eq!(
            snap.imported.get(&key).cloned().flatten().as_deref(),
            Some("8000000000000560"),
            "the preserve shape: row present + key equal = a hit"
        );
        let mut planner = HttpImportPlanner::new(Vec::new());
        match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000561".to_string(),
            imported_gid: snap.imported.get(&key).cloned().flatten(),
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Skipped { reason, .. } => {
                assert!(reason.contains("already imported"), "{reason}");
                assert!(reason.contains("origin_fork_key"), "{reason}");
            }
            other => panic!("target-keep mode must skip: {other:?}"),
        }
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );
        // ---- `.bak` restore mode: the row + key roll back with the db ->
        // upgrading again = a full re-import ----
        ok(
            std::fs::copy(&bak_path, &target),
            "restore .bak over target",
        );
        let snap = ok(
            read_target_snapshot_for_dry_run(target.clone(), vec![key.clone()]).await,
            "snap bak",
        );
        assert_eq!(
            snap.imported.get(&key),
            Some(&None),
            "the .bak-restore shape: the evidence rolls back with the database = not imported (full re-import)"
        );
        assert!(
            snap.stale_imported.is_empty(),
            "a database rollback leaves no residual markers (same-database rollback = no dead shape)"
        );
        let mut planner = HttpImportPlanner::new(Vec::new());
        match planner.plan(HttpPlanInput {
            task: &tasks[0],
            gid_hex: "8000000000000562".to_string(),
            imported_gid: snap.imported.get(&key).cloned().flatten(),
            conflict_action: PathConflictAction::Skip,
        }) {
            HttpPlanEntry::Planned(p) => {
                assert_eq!(
                    p.gid, "8000000000000562",
                    "the .bak-restore shape = full re-import"
                );
                assert!(
                    p.warnings.iter().any(|w| w.contains("imported progress")),
                    "the report states the weak-resume/bitmap reconciliation backstop (downloaded bytes are not re-fetched): {:?}",
                    p.warnings
                );
            }
            other => panic!("bak-restore mode must fully re-import: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&bak_path);
    }
}

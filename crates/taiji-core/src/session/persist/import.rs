//! Migration importer assembly face (read-only discipline): pure
//! mapping + source collection (source collection does disk IO; callers
//! put it in `spawn_blocking` or use this module's async wrappers); row
//! writes go through the existing PersistWriter face ([`apply_import`],
//! a single-task failure never blocks the batch).
//!
//! The fork-column -> bt-column mapping table and the failure
//! semantics (degrade-to-`checking` rules) live in
//! docs/design/core.md.
//!
//! Upstream anchor mapping: docs/design/core.md

use std::path::{Path, PathBuf};

use taiji_store::persist::{
    Aria2ControlFile, Aria2CtrlError, ForkTaskRow, PersistHandle, PersistWriter, TorrentFileRow,
    TorrentProgressRow, TorrentRow, TrackerRow, collect_aria2_files,
    completed_length_from_bitfield, count_fork_tasks, expected_bitfield_len, load_fork_bt_tasks,
    open_fork_readonly, parse_aria2_control,
};

use super::{PersistedTaskConfig, file_rows, fill_torrent_identity, torrent_row};

use crate::session::options::{MAX_SEED_TIME_MIN, checked_seed_ratio};

/// Import source (anchor for the dedup key and the removal list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSource {
    /// Fork sqlite task row (source of the removal list;
    /// `--from-aria2-db`).
    ForkDb { db_path: PathBuf, fork_gid: String },
    /// `.aria2` control file (`--from-aria2-dir` scan; no GID concept).
    Aria2Ctrl { ctrl_path: PathBuf },
}

impl ImportSource {
    /// session_kv dedup key (deterministic: re-importing the same
    /// source always yields the same key). Paths are canonicalized
    /// (failure falls back to the raw path — same spelling = same key).
    pub fn source_key(&self) -> String {
        match self {
            ImportSource::ForkDb { db_path, fork_gid } => {
                format!("imported_from:db:{}#{fork_gid}", canonical_or_raw(db_path))
            }
            ImportSource::Aria2Ctrl { ctrl_path } => {
                format!("imported_from:ctrl:{}", canonical_or_raw(ctrl_path))
            }
        }
    }

    /// Display form for reports/logs.
    pub fn display(&self) -> String {
        match self {
            ImportSource::ForkDb { db_path, fork_gid } => {
                format!("db:{}#{fork_gid}", db_path.display())
            }
            ImportSource::Aria2Ctrl { ctrl_path } => {
                format!("ctrl:{}", ctrl_path.display())
            }
        }
    }
}

/// A canonicalize failure (broken link / permissions) falls back to the
/// raw path — the dedup key only requires determinism.
fn canonical_or_raw(p: &Path) -> String {
    match std::fs::canonicalize(p) {
        Ok(c) => c.display().to_string(),
        Err(_) => p.display().to_string(),
    }
}

/// Normalized control progress (shared by the fork `task_progress` and
/// `.aria2` control files).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlProgress {
    /// SHA-1(info) (20 B).
    pub info_hash: [u8; 20],
    pub piece_length: u64,
    pub total_length: u64,
    /// Cumulative upload (= `uploadLengthAtStartup + session`, per
    /// `DefaultBtProgressInfoFile.cc`).
    pub upload_length: u64,
    /// v1 global piece bitfield (MSB-first).
    pub bitfield: Vec<u8>,
}

impl ControlProgress {
    /// Progress from a fork task row; no `task_progress` row or an
    /// info_hash that is not exactly 20 B (corrupt row) -> `None` (the
    /// caller degrades to failure/skip).
    pub fn from_fork(task: &ForkTaskRow) -> Option<Self> {
        let p = task.progress.as_ref()?;
        let info_hash: [u8; 20] = task.info_hash.as_slice().try_into().ok()?;
        Some(ControlProgress {
            info_hash,
            piece_length: p.piece_length.max(0) as u64,
            total_length: p.total_length.max(0) as u64,
            upload_length: p.upload_length.max(0) as u64,
            bitfield: p.bitfield.clone(),
        })
    }

    /// Progress from a `.aria2` control file (the parser already
    /// guarantees the bitfield length is correct).
    pub fn from_ctrl(ctrl: &Aria2ControlFile) -> Self {
        ControlProgress {
            info_hash: ctrl.info_hash,
            piece_length: u64::from(ctrl.piece_length),
            total_length: ctrl.total_length,
            upload_length: ctrl.upload_length,
            bitfield: ctrl.bitfield.clone(),
        }
    }
}

/// A single collected source task, ready (metadata candidates pending
/// parsing; `source_key` is fixed inside the blocking collection
/// context — canonicalize is IO).
#[derive(Debug, Clone, PartialEq)]
pub struct SourceTask {
    pub source: ImportSource,
    /// Deterministic dedup key (session_kv).
    pub source_key: String,
    /// Fork source = the fork GID (removal list); ctrl source = None.
    pub fork_gid: Option<String>,
    /// Queue order (fork `queue_position` or scan order).
    pub queue_pos: i64,
    /// Download directory (serialized ` dir=` or the ctrl target's
    /// parent / CLI `--dir`).
    pub dir: String,
    /// Paused face (fork state="paused" or serialized ` pause=true`).
    pub paused: bool,
    /// Serialized option subset (config_json payload; ctrl source =
    /// defaults).
    pub options: InputFileOptions,
    pub progress: ControlProgress,
    /// Metadata candidates (priority order; `resolve_metadata` probes
    /// in order).
    pub candidates: Vec<PathBuf>,
    /// Ctrl source: the target path paired with the control file
    /// (existence verified).
    pub target_path: Option<PathBuf>,
}

/// One directory-scan result (explicit presentation of control-file
/// parse/pairing failures — corrupt files fail loudly and are never
/// imported; non-BT files are skipped; failures are never silent).
#[derive(Debug, Clone, PartialEq)]
pub enum CtrlEntry {
    /// Box: suppresses large_enum_variant (the Ready payload dwarfs the
    /// skip/fail faces).
    Ready(Box<SourceTask>),
    /// Non-BT control file (extension bit0 = 0) — a normal skip.
    Skipped { path: PathBuf, reason: String },
    /// Corrupt / pairing failed — explicit failure (shown in the
    /// report, not imported).
    Failed { path: PathBuf, reason: String },
}

/// Fork DB source collection: read-only open + task/task_progress join +
/// metadata candidate preparation (disk IO + sqlite reads —
/// `spawn_blocking` inside the async wrapper). Returns (total fork task
/// rows, the BT candidate task set).
pub async fn collect_fork_tasks(
    db_path: PathBuf,
    fallback_dir: PathBuf,
) -> Result<(i64, Vec<SourceTask>), String> {
    tokio::task::spawn_blocking(move || {
        let conn = open_fork_readonly(&db_path)
            .map_err(|e| format!("open fork db {}: {e}", db_path.display()))?;
        let total = count_fork_tasks(&conn).map_err(|e| format!("count fork tasks: {e}"))?;
        let rows = load_fork_bt_tasks(&conn).map_err(|e| format!("read fork db tasks: {e}"))?;
        let tasks = rows
            .iter()
            .filter_map(|t| source_task_from_fork(t, &db_path, &fallback_dir))
            .collect();
        Ok((total, tasks))
    })
    .await
    .map_err(|e| format!("fork db collect join: {e}"))?
}

/// Fork task row -> source task (metadata candidate order = the fork
/// readd priorities 1/2, `RpcMethodImpl.cc`:
/// `<dir>/<hex(info_hash)>.torrent` -> `bt_local_path`; the
/// non-network priorities 3-5 are deliberately not implemented — noted
/// in the report).
pub fn source_task_from_fork(
    task: &ForkTaskRow,
    db_path: &Path,
    fallback_dir: &Path,
) -> Option<SourceTask> {
    let progress = ControlProgress::from_fork(task)?;
    let options = parse_input_file(&task.serialized);
    let dir = options
        .dir
        .clone()
        .unwrap_or_else(|| fallback_dir.display().to_string());
    let mut candidates = Vec::new();
    // Priority 1: <dir>/<hex>.torrent (where bt-save-metadata writes).
    let dir_path = PathBuf::from(&dir);
    candidates.push(dir_path.join(format!("{}.torrent", hex_lower(&task.info_hash))));
    // Priority 2: bt_local_path (.torrent suffix only, same rule as the
    // fork).
    if let Some(lp) = task
        .bt_local_path
        .as_ref()
        .filter(|p| p.ends_with(".torrent"))
    {
        candidates.push(PathBuf::from(lp));
    }
    candidates.dedup();
    let source = ImportSource::ForkDb {
        db_path: db_path.to_path_buf(),
        fork_gid: task.gid.clone(),
    };
    Some(SourceTask {
        source_key: source.source_key(),
        fork_gid: Some(task.gid.clone()),
        queue_pos: task.queue_position,
        paused: task.state == "paused" || options.paused,
        options,
        target_path: None,
        source,
        dir,
        progress,
        candidates,
    })
}

/// `.aria2` directory scan collection (recursive; per-file parse +
/// pairing — disk IO, `spawn_blocking` inside the async wrapper). A
/// single-file failure only affects that entry (CtrlEntry::Failed) and
/// does not block the batch.
pub async fn collect_ctrl_tasks(dir: PathBuf) -> Result<Vec<CtrlEntry>, String> {
    tokio::task::spawn_blocking(move || {
        let files =
            collect_aria2_files(&dir).map_err(|e| format!("scan {}: {e}", dir.display()))?;
        let mut out = Vec::new();
        for ctrl_path in files {
            out.push(ctrl_entry(&ctrl_path));
        }
        Ok(out)
    })
    .await
    .map_err(|e| format!("ctrl scan join: {e}"))?
}

/// One `.aria2` file -> entry (parse + target existence check +
/// same-directory candidates).
fn ctrl_entry(ctrl_path: &Path) -> CtrlEntry {
    let bytes = match std::fs::read(ctrl_path) {
        Ok(b) => b,
        Err(e) => {
            return CtrlEntry::Failed {
                path: ctrl_path.to_path_buf(),
                reason: format!("read: {e}"),
            };
        }
    };
    let ctrl = match parse_aria2_control(&bytes) {
        Ok(c) => c,
        Err(Aria2CtrlError::NotBitTorrent) => {
            return CtrlEntry::Skipped {
                path: ctrl_path.to_path_buf(),
                reason: "not a BitTorrent control file".to_string(),
            };
        }
        Err(e) => {
            return CtrlEntry::Failed {
                path: ctrl_path.to_path_buf(),
                reason: format!("parse: {e}"),
            };
        }
    };
    // Paired target = the path with the .aria2 suffix stripped (naming
    // semantics per message.h "control file(*.aria2)"); a missing
    // target = orphan control file, explicit failure.
    let mut target = ctrl_path.to_path_buf();
    target.set_extension("");
    if !target.exists() {
        return CtrlEntry::Failed {
            path: ctrl_path.to_path_buf(),
            reason: format!("target {} missing (orphan control file)", target.display()),
        };
    }
    // Metadata candidates = same-directory *.torrent (lexicographic;
    // the "same-directory .torrent metadata" rule).
    let parent = ctrl_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let source = ImportSource::Aria2Ctrl {
        ctrl_path: ctrl_path.to_path_buf(),
    };
    CtrlEntry::Ready(Box::new(SourceTask {
        source_key: source.source_key(),
        fork_gid: None,
        // Ctrl sources have no queue-order concept — the CLI assigns
        // scan order by list index.
        queue_pos: 0,
        dir: parent.display().to_string(),
        paused: false,
        options: InputFileOptions::default(),
        progress: ControlProgress::from_ctrl(&ctrl),
        candidates: torrent_siblings(&parent),
        target_path: Some(target),
        source,
    }))
}

/// Same-directory .torrent candidates (lexicographic, stable; none =
/// empty).
fn torrent_siblings(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "torrent"))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort();
    out
}

/// Metadata resolution result (`matched` = the candidate's v1 infohash
/// equals the control data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaResolution {
    pub bytes: Vec<u8>,
    pub path: PathBuf,
    pub matched: bool,
}

/// Parse the .torrent candidates in order and cross-check the infohash
/// (disk IO + metadata parsing — the caller puts this in
/// `spawn_blocking`). Returns: a candidate whose infohash matches ->
/// `matched: true`; only non-matching parseable candidates -> the first
/// one (degradation face); all unreadable/unparseable -> `Err` (a
/// failure for both source kinds).
pub fn resolve_metadata(candidates: &[PathBuf], want: &[u8; 20]) -> Result<MetaResolution, String> {
    let mut first_parseable: Option<MetaResolution> = None;
    let mut last_err = "no .torrent candidate located".to_string();
    for c in candidates {
        let bytes = match std::fs::read(c) {
            Ok(b) => b,
            Err(e) => {
                last_err = format!("read {}: {e}", c.display());
                continue;
            }
        };
        match crate::metainfo::Metainfo::parse(&bytes) {
            Err(e) => {
                last_err = format!("parse {}: {e}", c.display());
                continue;
            }
            Ok(meta) => {
                let matched = meta.meta.identity.v1.as_ref() == Some(want);
                let r = MetaResolution {
                    bytes,
                    path: c.clone(),
                    matched,
                };
                if matched {
                    return Ok(r);
                }
                if first_parseable.is_none() {
                    first_parseable = Some(r);
                }
            }
        }
    }
    first_parseable.ok_or(last_err)
}

/// A completed single-task import plan (row set assembled, awaiting
/// [`apply_import`]).
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedImport {
    pub source: ImportSource,
    pub source_key: String,
    /// Fork GID (None for ctrl sources).
    pub fork_gid: Option<String>,
    /// The new taiji GID (hex16, top bit = 1 — namespace isolation;
    /// imported tasks do not inherit fork GIDs, the removal list
    /// carries the old->new mapping).
    pub gid: String,
    /// Store state: queued | paused | checking (degraded).
    pub state: String,
    pub degraded: bool,
    pub degrade_reason: Option<String>,
    pub metadata_path: PathBuf,
    pub row: TorrentRow,
    pub files: Vec<TorrentFileRow>,
    pub progress: Option<TorrentProgressRow>,
    pub trackers: Vec<TrackerRow>,
}

/// Assembly input (`meta` is the resolved candidate; `gid_hex` is
/// allocated by the caller via the GID allocator — this module
/// generates no randomness, staying testable).
#[derive(Debug, Clone)]
pub struct AssembleInput {
    pub source: ImportSource,
    pub source_key: String,
    pub gid_hex: String,
    pub meta: MetaResolution,
    pub progress: ControlProgress,
    /// Download directory (resolved from serialized / the target's
    /// parent directory).
    pub dir: String,
    /// Paused face (fork state, serialized pause; ctrl is always
    /// false).
    pub paused: bool,
    /// Serialized option subset (config_json payload).
    pub options: InputFileOptions,
    pub queue_pos: i64,
}

/// Single-task assembly (the mapping table applied column by column;
/// failure = that task is not imported).
///
/// Failure order:
/// 1. unparseable metadata -> failure;
/// 2. candidate infohash mismatch: fork source (task_progress.info_hash
/// is authoritative) -> failure; ctrl source (the paired metadata is
/// the identity anchor) -> **degrade to checking**
/// (EX_INFOHASH_MISMATCH_IN_SEGFILE, message.h), bitmap and upload
/// count dropped together (history belonging to a different
/// torrent);
/// 3. bitmap validation failure (piece_length / total_length /
/// bitfield length inconsistent with the metadata) -> degrade to
/// checking, bitmap dropped, upload count kept (trusted history of
/// the same torrent — "tasks that fail bitmap validation degrade to
/// re-Checking").
pub fn assemble(input: AssembleInput) -> Result<PlannedImport, String> {
    let meta = crate::metainfo::Metainfo::parse(&input.meta.bytes)
        .map_err(|e| format!("metadata unparseable at {}: {e}", input.meta.path.display()))?;

    // ---- infohash cross-check (import identity) ----
    let v1 = meta.meta.identity.v1;
    let matched = v1.as_ref() == Some(&input.progress.info_hash);
    let mut degraded = false;
    let mut degrade_reason: Option<String> = None;
    let bits: Option<Vec<u8>>;
    let upload: u64;
    if !matched {
        match &input.source {
            ImportSource::ForkDb { .. } => {
                // The fork's progress.info_hash is the task's
                // authoritative identity: a candidate that does not
                // match = the wrong metadata was found; the progress
                // must not be misattributed.
                return Err(format!(
                    "metadata infohash mismatch: control data belongs to {}, \
                     candidate {} is a different torrent",
                    hex_lower(&input.progress.info_hash),
                    input.meta.path.display()
                ));
            }
            ImportSource::Aria2Ctrl { .. } => {
                degraded = true;
                degrade_reason = Some(
                    "infohash mismatch with paired .torrent (control file \
                     belongs to a different torrent): progress and upload \
                     dropped, re-check required (EX_INFOHASH_MISMATCH_IN_SEGFILE, \
                     message.h)"
                        .to_string(),
                );
                bits = None;
                upload = 0;
            }
        }
    } else {
        // ---- bitmap validation (trustworthy only for the same
        // torrent) ----
        let meta_total = meta.meta.total_len();
        let meta_piece = u64::from(meta.meta.piece_length);
        let expected_len = expected_bitfield_len(meta_total, meta_piece);
        if input.progress.piece_length != meta_piece
            || input.progress.total_length != meta_total
            || input.progress.bitfield.len() as u64 != expected_len
        {
            degraded = true;
            degrade_reason = Some(format!(
                "bitmap validation failed (piece_length {}/total {}/bitfield {}B \
                 vs metadata {meta_piece}/{meta_total}/{expected_len}B): \
                 progress dropped, re-check required (SPEC §10)",
                input.progress.piece_length,
                input.progress.total_length,
                input.progress.bitfield.len()
            ));
            bits = None;
            upload = input.progress.upload_length;
        } else {
            // v1 bitmap 1:1 (aria2 can never have in-flight v2 tasks,
            // so nothing v2 is lost).
            bits = Some(input.progress.bitfield.clone());
            upload = input.progress.upload_length;
        }
    }

    let state = if degraded {
        "checking".to_string()
    } else if input.paused {
        "paused".to_string()
    } else {
        "queued".to_string()
    };

    // ---- torrent parent row + file rows (the persist/mod.rs assembly
    // face reused; the serialized seed/limit subset merges into
    // config_json — "serialized -> config_json") ----
    let cfg = PersistedTaskConfig {
        dir: input.dir.clone(),
        seed_ratio: input.options.seed_ratio.unwrap_or(0.0),
        seed_time_min: input.options.seed_time_min.unwrap_or(0.0),
        max_download_limit: input.options.max_download_limit.unwrap_or(0),
        max_upload_limit: input.options.max_upload_limit.unwrap_or(0),
        ..Default::default()
    };
    let mut row = torrent_row(&input.gid_hex, &state, input.queue_pos, "", &cfg);
    fill_torrent_identity(&mut row, &meta, input.meta.bytes.clone());
    let files = file_rows(&input.gid_hex, &meta.meta.files);

    // ---- progress row ----
    let piece = u64::from(meta.meta.piece_length);
    let total = meta.meta.total_len();
    let downloaded_total = bits
        .as_deref()
        .map(|bf| {
            let num_pieces = total.div_ceil(piece);
            completed_length_from_bitfield(bf, num_pieces, piece, total)
        })
        .unwrap_or(0);
    let progress = TorrentProgressRow {
        gid: input.gid_hex.clone(),
        piece_length: piece.min(i64::MAX as u64) as i64,
        v1_bitfield: bits,
        // No v2 in flight on the aria2 side, so v2 never carries state.
        v2_file_bits: None,
        // upload_length -> upload_at_startup; uploaded_total gets the
        // same seed baseline (engine recovery reads uploaded_total as
        // the next session's baseline — the ratio baseline chain never
        // breaks).
        upload_at_startup: upload.min(i64::MAX as u64) as i64,
        downloaded_total: downloaded_total.min(i64::MAX as u64) as i64,
        uploaded_total: upload.min(i64::MAX as u64) as i64,
        // The fork does not persist active/seed time — unknown (0) at
        // import, never fabricated.
        active_time_s: 0,
        seed_time_s: 0,
    };

    // ---- trackers rebuilt from metadata (announce first URL, tier
    // 0) ----
    let trackers = if meta.announce.is_empty() {
        Vec::new()
    } else {
        vec![TrackerRow {
            gid: input.gid_hex.clone(),
            tier: 0,
            url: meta.announce.clone(),
            enabled: true,
            last_interval: None,
            last_min_interval: None,
            next_announce_at: None,
            last_error: None,
            last_ok_at: None,
            seeds: None,
            leechers: None,
        }]
    };

    let fork_gid = match &input.source {
        ImportSource::ForkDb { fork_gid, .. } => Some(fork_gid.clone()),
        ImportSource::Aria2Ctrl { .. } => None,
    };
    Ok(PlannedImport {
        source_key: input.source_key.clone(),
        source: input.source,
        fork_gid,
        gid: input.gid_hex.clone(),
        state,
        degraded,
        degrade_reason,
        metadata_path: input.meta.path.clone(),
        row,
        files,
        progress: Some(progress),
        trackers,
    })
}

/// Single-task apply result (`error` = the failure reason; a failure
/// does not block the batch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedTask {
    pub gid: String,
    pub source_key: String,
    pub error: Option<String>,
}

/// One parameterized implementation for the two writer constructors:
/// [`open_target_writer`] / [`open_session_writer`] differ only in
/// whether the join handle is kept and the error label — signatures and
/// error texts ("open target db" / "open session db") are preserved
/// verbatim, zero behavior change.
async fn open_writer(
    path: PathBuf,
    label: &str,
) -> Result<(PersistHandle, tokio::task::JoinHandle<()>), String> {
    PersistWriter::spawn(path)
        .await
        .map_err(|e| format!("open {label} db: {e}"))
}

/// Opens the PersistWriter for the target taiji.sqlite3 (single writer;
/// disk IO -> spawn_blocking is already handled inside
/// PersistWriter::spawn). The CLI goes through core (cli does not
/// depend on store directly). The writer thread handle is dropped
/// immediately — the writer exits on its own once all handles drop
/// (fine for process-shaped CLIs).
pub async fn open_target_writer(path: PathBuf) -> Result<PersistHandle, String> {
    let (handle, _join) = open_writer(path, "target").await?;
    Ok(handle)
}

/// Import-subcommand form of the target store open: same face as
/// [`open_target_writer`] (same "open target db" error text), but keeps
/// the writer join handle — the import CLI must explicitly wait for the
/// writer to drain its finalization queue before exiting: process exit
/// kills an undrained writer thread outright, the sqlite connection
/// gets no clean close, and leftover `-wal`/`-shm` sidecars make the
/// next import's pre-import backup fail with `TargetInUse` (a second
/// import deadlocked by its own previous import).
pub async fn open_import_writer(
    path: PathBuf,
) -> Result<(PersistHandle, tokio::task::JoinHandle<()>), String> {
    open_writer(path, "target").await
}

/// Resident-service form of the session store open: same face as
/// [`open_target_writer`], but keeps the writer thread handle —
/// idle-mode graceful shutdown explicitly waits for the writer to drain
/// its finalization queue (the process exits only after the final
/// flush's bitmap/count/tracker rows are on disk).
pub async fn open_session_writer(
    path: PathBuf,
) -> Result<(PersistHandle, tokio::task::JoinHandle<()>), String> {
    open_writer(path, "session").await
}

/// Observed form of [`open_session_writer`]: the PersistWriter write
/// thread gets a [`PersistMetricsBridge`] (the store `PersistObserve`
/// callback seam -> the process-default io registry persistence family
/// — the production assembly point; tests use the unobserved
/// [`open_session_writer`], zero writes to the process-default
/// registry). Same "open session db" error face.
pub async fn open_session_writer_with_metrics(
    path: PathBuf,
) -> Result<(PersistHandle, tokio::task::JoinHandle<()>), String> {
    let observer = crate::session::metrics::persist_observer_default();
    taiji_store::persist::PersistWriter::spawn_with_observer(path, Some(observer))
        .await
        .map_err(|e| format!("open session db: {e}"))
}

/// Batch apply (the existing PersistWriter face: UpsertTorrent /
/// UpsertTorrentProgress / UpsertTracker / PutKv). Order: parent row +
/// files -> progress row -> tracker rows -> dedup kv; any step failing
/// marks that task failed and continues with the next (a single-task
/// failure does not block the batch). The kv is written last = a failed
/// task has no dedup marker and can be safely re-imported (upsert
/// idempotence absorbs leftover rows).
pub async fn apply_import(persist: &PersistHandle, planned: &[PlannedImport]) -> Vec<AppliedTask> {
    let mut out = Vec::with_capacity(planned.len());
    for p in planned {
        let mut err: Option<String> = None;
        if let Err(e) = persist.upsert_torrent(p.row.clone(), p.files.clone()).await {
            err = Some(format!("torrent row: {e}"));
        }
        if err.is_none() {
            if let Some(pr) = &p.progress {
                if let Err(e) = persist.upsert_torrent_progress(pr.clone()).await {
                    err = Some(format!("progress row: {e}"));
                }
            }
        }
        if err.is_none() {
            for tr in &p.trackers {
                if let Err(e) = persist.upsert_tracker(tr.clone()).await {
                    err = Some(format!("tracker row: {e}"));
                    break;
                }
            }
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

/// Input-file text option subset (the parser for the
/// `task.serialized` -> `config_json` face; line format =
/// `SessionSerializer.cc`: first URI line + ` key=value` option lines).
/// Only the local subset of keys is recognized; unknown keys are
/// ignored.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct InputFileOptions {
    pub dir: Option<String>,
    pub paused: bool,
    pub seed_ratio: Option<f64>,
    /// aria2 `--seed-time` unit = minutes.
    pub seed_time_min: Option<f64>,
    pub max_download_limit: Option<u64>,
    pub max_upload_limit: Option<u64>,
}

/// Parse serialized text (tolerates empty text / unknown keys / bad
/// values — the migration face prefers missing over wrong).
pub fn parse_input_file(text: &str) -> InputFileOptions {
    let mut o = InputFileOptions::default();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(' ') else {
            continue; // URI and other non-option lines
        };
        let Some((key, value)) = rest.split_once('=') else {
            continue;
        };
        match key {
            "dir" => o.dir = Some(value.to_string()),
            "pause" => o.paused = value == "true",
            // seed-ratio domain = [0, inf) (finite, >= 0;
            // `checked_seed_ratio` is the single point; same rule as
            // the RPC option face): out-of-domain values are rejected
            // at this parse single point (missing over wrong — a bad
            // value is skipped, never blocking the whole migration;
            // same shape as the seed-time arm). A non-finite value that
            // got stored would project to null via serde_json and
            // recovery's from_json would fail the whole payload -> the
            // whole config silently dropped; a finite inf = a
            // seed-forever condition.
            "seed-ratio" => {
                o.seed_ratio = value.parse::<f64>().ok().and_then(checked_seed_ratio);
            }
            // seed-time domain = [0, MAX_SEED_TIME_MIN] (finite, >= 0):
            // imported values reach the store via config_json -> the
            // restart bootstrap replays the minutes->seconds conversion,
            // so out-of-domain values are rejected at this parse single
            // point (missing over wrong — a bad value is skipped, never
            // blocking the whole migration).
            "seed-time" => {
                o.seed_time_min = value
                    .parse::<f64>()
                    .ok()
                    .filter(|m| m.is_finite() && *m >= 0.0 && *m <= MAX_SEED_TIME_MIN);
            }
            "max-download-limit" => o.max_download_limit = parse_size_literal(value),
            "max-upload-limit" => o.max_upload_limit = parse_size_literal(value),
            _ => {}
        }
    }
    o
}

/// aria2 size literal (bare bytes / k/M/G in 1024 base; bad value ->
/// None).
fn parse_size_literal(s: &str) -> Option<u64> {
    let (digits, mult) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1024u64),
        'm' | 'M' => (&s[..s.len() - 1], 1024 * 1024),
        'g' | 'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

/// Lowercase hex (shared by fork GID/infohash display, candidate
/// file-name construction, CLI reports, and the magnet face templates /
/// logs — the single implementation after unification; magnet.rs now
/// references this function).
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Per-task report (shared by import and dry-run: a dry run differs
/// only in whether rows are written).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskReport {
    pub source: String,
    pub fork_gid: Option<String>,
    pub info_hash_hex: Option<String>,
    pub metadata_path: Option<PathBuf>,
    pub new_gid: Option<String>,
    pub state: Option<String>,
    pub degraded: bool,
    pub degrade_reason: Option<String>,
    /// Reason for skipped (dedup / non-BT) and failed.
    pub note: Option<String>,
    /// planned (including degraded) | skipped | failed.
    pub kind: TaskReportKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskReportKind {
    Planned,
    Skipped,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_bt::bencode::{self, Value};

    /// Test-only Result unwrap (unwrap/expect are lint-forbidden).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    fn dict(pairs: Vec<(&[u8], Value)>) -> Value {
        let mut v: Vec<(Vec<u8>, Value)> =
            pairs.into_iter().map(|(k, x)| (k.to_vec(), x)).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Dict(v)
    }

    /// Single-file v1 torrent (2 pieces x 16 KiB): encoded bytes +
    /// parsed identity.
    fn v1_torrent() -> (Vec<u8>, [u8; 20], String) {
        let info = dict(vec![
            (b"length", Value::Int(32768)),
            (b"name", Value::Bytes(b"migrated.bin".to_vec())),
            (b"piece length", Value::Int(16384)),
            (b"pieces", Value::Bytes(vec![0xab; 40])),
        ]);
        let top = dict(vec![
            (
                b"announce",
                Value::Bytes(b"http://t.invalid/announce".to_vec()),
            ),
            (b"info", info),
        ]);
        let raw = ok(bencode::encode(&top), "encode torrent");
        let meta = ok(crate::metainfo::Metainfo::parse(&raw), "parse torrent");
        let v1 = meta
            .meta
            .identity
            .v1
            .unwrap_or_else(|| panic!("the v1 identity is always present"));
        let announce = meta.announce.clone();
        (raw, v1, announce)
    }

    fn ctrl_progress(ih: [u8; 20], bitfield: Vec<u8>) -> ControlProgress {
        ControlProgress {
            info_hash: ih,
            piece_length: 16384,
            total_length: 32768,
            upload_length: 4096,
            bitfield,
        }
    }

    fn fork_source() -> ImportSource {
        ImportSource::ForkDb {
            db_path: PathBuf::from("/tmp/aria2.sqlite3"),
            fork_gid: "0000000000000042".into(),
        }
    }

    fn ctrl_source() -> ImportSource {
        ImportSource::Aria2Ctrl {
            ctrl_path: PathBuf::from("/dl/migrated.bin.aria2"),
        }
    }

    fn input(
        source: ImportSource,
        source_key: String,
        meta: MetaResolution,
        progress: ControlProgress,
    ) -> AssembleInput {
        AssembleInput {
            source,
            source_key,
            gid_hex: "80000000000000ff".into(),
            meta,
            progress,
            dir: "/dl".into(),
            paused: false,
            options: InputFileOptions::default(),
            queue_pos: 3,
        }
    }

    /// Fork-fixture import roundtrip through the assembly face: the
    /// mapping table asserted column by column.
    #[test]
    fn assemble_maps_fork_columns_one_to_one() {
        let (raw, ih, announce) = v1_torrent();
        let meta = MetaResolution {
            bytes: raw,
            path: PathBuf::from("/dl/8000..ff.torrent"),
            matched: true,
        };
        let bf = vec![0b1100_0000u8]; // both pieces complete
        let planned = ok(
            assemble(input(
                fork_source(),
                "imported_from:db:/tmp/aria2.sqlite3#0000000000000042".into(),
                meta,
                ctrl_progress(ih, bf),
            )),
            "assemble full",
        );
        // Row mapping: new GID high-bit namespace, state=queued,
        // kind=v1, raw metadata bytes, name derived from the file path.
        assert_eq!(planned.gid, "80000000000000ff");
        assert_eq!(planned.row.state, "queued");
        assert_eq!(planned.row.queue_pos, 3);
        assert_eq!(planned.row.kind, "v1");
        assert_eq!(planned.row.name, "migrated.bin");
        assert_eq!(planned.row.v1_infohash.as_deref(), Some(ih.as_slice()));
        assert!(planned.row.metadata.is_some());
        assert!(planned.row.config_json.contains("\"dir\":\"/dl\""));
        // Bitmap 1:1; upload_length -> upload_at_startup and
        // uploaded_total share the baseline (ratio chain);
        // downloaded_total = completed length from the bitmap (1 piece
        // = 16 KiB).
        let pr = planned
            .progress
            .as_ref()
            .unwrap_or_else(|| panic!("progress"));
        assert_eq!(pr.v1_bitfield.as_deref(), Some(&[0b1100_0000u8][..]));
        assert_eq!(pr.piece_length, 16384);
        assert_eq!(pr.upload_at_startup, 4096);
        assert_eq!(pr.uploaded_total, 4096);
        assert_eq!(
            pr.downloaded_total, 32768,
            "both pieces fully set = the full amount"
        );
        assert_eq!(pr.v2_file_bits, None);
        // Trackers rebuilt from metadata (tier 0 = announce).
        assert_eq!(planned.trackers.len(), 1);
        assert_eq!(planned.trackers[0].url, announce);
        assert_eq!(planned.trackers[0].tier, 0);
        // 1 file row + removal-list anchor = fork GID.
        assert_eq!(planned.files.len(), 1);
        assert_eq!(planned.fork_gid.as_deref(), Some("0000000000000042"));
        assert!(!planned.degraded);
    }

    /// Degradation face: ctrl-source infohash mismatch -> degrade to
    /// checking (EX_INFOHASH_MISMATCH_IN_SEGFILE); fork source ->
    /// explicit failure.
    #[test]
    fn infohash_mismatch_degrades_ctrl_and_fails_fork() {
        let (raw, _ih, _announce) = v1_torrent();
        let wrong_ih = [0u8; 20];
        let meta = MetaResolution {
            bytes: raw,
            path: PathBuf::from("/dl/other.torrent"),
            matched: false,
        };
        // Ctrl source: degrade.
        let planned = ok(
            assemble(input(
                ctrl_source(),
                "imported_from:ctrl:/dl/migrated.bin.aria2".into(),
                meta.clone(),
                ctrl_progress(wrong_ih, vec![0b1100_0000]),
            )),
            "assemble ctrl mismatch",
        );
        assert!(planned.degraded);
        assert_eq!(planned.state, "checking");
        let pr = planned
            .progress
            .as_ref()
            .unwrap_or_else(|| panic!("progress"));
        assert_eq!(pr.v1_bitfield, None, "the bitfield is dropped");
        assert_eq!(
            pr.uploaded_total, 0,
            "a different torrent's upload history is not inherited"
        );
        // Fork source: failure (task_progress.info_hash authoritative).
        let failed = assemble(input(
            fork_source(),
            "imported_from:db:x#1".into(),
            meta,
            ctrl_progress(wrong_ih, vec![0b1100_0000]),
        ));
        assert!(
            failed.is_err(),
            "an infohash mismatch against the fork source must fail explicitly"
        );
    }

    /// Bitmap validation failure (same torrent, bitfield length
    /// mismatch) -> degrade to checking, bitmap dropped, upload count
    /// kept.
    #[test]
    fn bitmap_validation_failure_degrades_keeping_upload() {
        let (raw, ih, _announce) = v1_torrent();
        let meta = MetaResolution {
            bytes: raw,
            path: PathBuf::from("/dl/x.torrent"),
            matched: true,
        };
        let mut progress = ctrl_progress(ih, vec![0b1100_0000, 0xff]); // expected 1B, given 2B
        progress.piece_length = 16384;
        let planned = ok(
            assemble(input(
                fork_source(),
                "imported_from:db:x#1".into(),
                meta,
                progress,
            )),
            "assemble bitmap mismatch",
        );
        assert!(planned.degraded);
        assert_eq!(planned.state, "checking");
        let pr = planned
            .progress
            .as_ref()
            .unwrap_or_else(|| panic!("progress"));
        assert_eq!(pr.v1_bitfield, None);
        assert_eq!(
            pr.uploaded_total, 4096,
            "the upload counter is trusted history for the same torrent"
        );
    }

    /// serialized -> config_json: the pause/seed/limit subset and the
    /// directory fallback.
    #[test]
    fn parse_input_file_options_subset() {
        let text = "magnet:?xt=urn:btih:aa\n gid=0000000000000001\n pause=true\n \
                    dir=/dl/old\n seed-ratio=1.5\n seed-time=30\n \
                    max-upload-limit=512K\n unknown-key=x\n";
        let o = parse_input_file(text);
        assert_eq!(o.dir.as_deref(), Some("/dl/old"));
        assert!(o.paused);
        assert_eq!(o.seed_ratio, Some(1.5));
        assert_eq!(o.seed_time_min, Some(30.0));
        assert_eq!(o.max_upload_limit, Some(512 * 1024));
        assert_eq!(o.max_download_limit, None);
        // Empty text = all defaults.
        assert_eq!(parse_input_file(""), InputFileOptions::default());
    }

    /// Import-face seed-time domain tightening (finite, >= 0, <= the
    /// upper bound). Imported values reach the store via config_json ->
    /// the restart bootstrap replays the conversion
    /// (`Duration::from_secs_f64` panics on out-of-domain values — a
    /// session crash loop), so they are rejected at this parse single
    /// point and never stored.
    #[test]
    fn parse_input_file_seed_time_domain() {
        for bad in ["1e30", "inf", "-inf", "nan", "-1"] {
            let o = parse_input_file(&format!(" seed-time={bad}\n"));
            assert_eq!(
                o.seed_time_min, None,
                "seed-time {bad:?} must not be imported"
            );
        }
        // In-domain values (including the 2^40-minute upper bound) pass
        // through unchanged.
        for good in ["0", "60", "5.5", "1099511627776"] {
            let o = parse_input_file(&format!(" seed-time={good}\n"));
            let want: f64 = good.parse().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                o.seed_time_min,
                Some(want),
                "seed-time {good:?} must be imported"
            );
        }
    }

    /// Import-face seed-ratio domain tightening (finite, >= 0 — same
    /// rule as the RPC option face's seed-ratio arm). What is guarded
    /// against: `parse().ok()` with no domain filter would admit
    /// nan/inf/-inf/-1 into config_json — non-finite values serialize
    /// to null and get stored, recovery's from_json then fails the
    /// whole payload -> unwrap_or_default silently drops the whole
    /// config (dir/magnet_uri/tiers/limits gone); a finite inf builds a
    /// never-satisfiable ShareRatio condition via SeedCheck::build =
    /// seeding forever.
    #[test]
    fn parse_input_file_seed_ratio_domain() {
        for bad in ["inf", "-inf", "nan", "-1"] {
            let o = parse_input_file(&format!(" seed-ratio={bad}\n"));
            assert_eq!(
                o.seed_ratio, None,
                "seed-ratio {bad:?} must not be imported"
            );
        }
        // In-domain values pass through (0 = a legal explicit value
        // that mounts no ratio condition).
        for good in ["0", "1.5"] {
            let o = parse_input_file(&format!(" seed-ratio={good}\n"));
            let want: f64 = good.parse().unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                o.seed_ratio,
                Some(want),
                "seed-ratio {good:?} must be imported"
            );
        }
    }

    /// Fork task -> source task: candidate order = the fork readd
    /// priorities 1/2; paused face from both sources.
    #[test]
    fn fork_source_task_candidates_follow_readd_priority() {
        let task = ForkTaskRow {
            gid: "0000000000000007".into(),
            state: "waiting".into(),
            serialized: " dir=/dl\n pause=true\n".into(),
            following: None,
            followed_by: None,
            metadata_uri: None,
            bt_local_path: Some("/tmp/src/real.torrent".into()),
            queue_position: 5,
            info_hash: vec![9u8; 20],
            progress: Some(taiji_store::persist::ForkProgress {
                piece_length: 16384,
                total_length: 32768,
                upload_length: 4096,
                bitfield: vec![0b1100_0000],
            }),
        };
        let st = source_task_from_fork(
            &task,
            Path::new("/tmp/aria2.sqlite3"),
            Path::new("/fallback"),
        )
        .unwrap_or_else(|| panic!("BT task must map"));
        // Candidate 1 = <serialized dir>/<hex>.torrent; candidate 2 =
        // bt_local_path.
        assert_eq!(
            st.candidates[0],
            PathBuf::from(format!("/dl/{}.torrent", hex_lower(&[9u8; 20])))
        );
        assert_eq!(st.candidates[1], PathBuf::from("/tmp/src/real.torrent"));
        // Paused face = serialized pause=true; dedup key determinism.
        assert!(st.paused);
        assert_eq!(st.queue_pos, 5);
        assert_eq!(
            st.source_key,
            st.source.source_key(),
            "the collection-face precompute = the source method"
        );
        // Non-BT row (no progress) -> None (never enters the read
        // face).
        let mut http_task = task.clone();
        http_task.progress = None;
        assert!(source_task_from_fork(&http_task, Path::new("/x"), Path::new("/y")).is_none());
    }

    /// Directory scan collection: positive Ready, non-BT Skipped,
    /// orphan/corrupt Failed.
    #[tokio::test]
    async fn collect_ctrl_tasks_classifies_entries() {
        let root = std::env::temp_dir().join(format!(
            "bh-import-ctrl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let sub = root.join("dl");
        ok(std::fs::create_dir_all(&sub), "mkdir");
        // Positive sample: target + same-directory .torrent + a valid
        // control file.
        let (raw, ih, _a) = v1_torrent();
        ok(std::fs::write(sub.join("m.torrent"), &raw), "write torrent");
        ok(
            std::fs::write(sub.join("m.bin"), b"payload"),
            "write target",
        );
        let good_ctrl = {
            // Bitfield length = ceil(ceil(32768/16384)/8) = 1 B.
            let bf = vec![0b1100_0000u8];
            let mut b = vec![0x00u8, 0x01];
            b.extend_from_slice(&[0, 0, 0, 1]);
            b.extend_from_slice(&20u32.to_be_bytes());
            b.extend_from_slice(&ih);
            b.extend_from_slice(&16384u32.to_be_bytes());
            b.extend_from_slice(&32768u64.to_be_bytes());
            b.extend_from_slice(&7777u64.to_be_bytes());
            b.extend_from_slice(&(bf.len() as u32).to_be_bytes());
            b.extend_from_slice(&bf);
            b.extend_from_slice(&0u32.to_be_bytes());
            b
        };
        ok(
            std::fs::write(sub.join("m.bin.aria2"), &good_ctrl),
            "write ctrl",
        );
        // Non-BT control file -> Skipped.
        let non_bt = {
            let mut b = vec![0x00u8, 0x01, 0, 0, 0, 0];
            b.extend_from_slice(&0u32.to_be_bytes()); // infoHashLength = 0
            b
        };
        ok(
            std::fs::write(sub.join("http.dl.aria2"), &non_bt),
            "write non-bt",
        );
        // Orphan (target missing) -> Failed; corrupt -> Failed.
        ok(
            std::fs::write(sub.join("orphan.aria2"), &good_ctrl),
            "write orphan",
        );
        ok(
            std::fs::write(sub.join("bad.aria2"), b"\x00\x09garbage"),
            "write bad",
        );
        let entries = ok(collect_ctrl_tasks(root.clone()).await, "collect");
        let mut ready = 0;
        let mut skipped = 0;
        let mut failed = 0;
        for e in &entries {
            match e {
                CtrlEntry::Ready(t) => {
                    ready += 1;
                    assert_eq!(t.progress.upload_length, 7777);
                    assert_eq!(
                        t.candidates.len(),
                        1,
                        "a same-directory .torrent candidate (m.torrent)"
                    );
                }
                CtrlEntry::Skipped { .. } => skipped += 1,
                CtrlEntry::Failed { path, .. } => {
                    failed += 1;
                    assert!(
                        path.ends_with("orphan.aria2") || path.ends_with("bad.aria2"),
                        "unexpected failed: {path:?}"
                    );
                }
            }
        }
        assert_eq!((ready, skipped, failed), (1, 1, 2), "entries: {entries:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Single-task apply + dedup kv: apply_import writes rows through
    /// the existing face + PutKv; row fields asserted column by column
    /// on read-back.
    #[tokio::test]
    async fn apply_import_writes_rows_kv_and_survives_restart() {
        use taiji_store::persist::PersistWriter;
        let db = std::env::temp_dir().join(format!(
            "bh-import-apply-{}-{}.sqlite3",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let (raw, ih, _a) = v1_torrent();
        let meta = MetaResolution {
            bytes: raw,
            path: PathBuf::from("/dl/x.torrent"),
            matched: true,
        };
        let planned = ok(
            assemble(input(
                fork_source(),
                "imported_from:db:/tmp/aria2.sqlite3#0000000000000042".into(),
                meta,
                ctrl_progress(ih, vec![0b1100_0000]),
            )),
            "assemble",
        );
        let (handle, join) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
        let applied = apply_import(&handle, std::slice::from_ref(&planned)).await;
        assert!(applied[0].error.is_none(), "apply: {:?}", applied[0].error);
        drop(handle);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join).await,
            "writer exit",
        );

        // Restart read face (the same path as bootstrap): row fields
        // asserted column by column.
        let (handle2, join2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
        let snaps = ok(handle2.load_torrents_at_startup().await, "load startup");
        assert_eq!(
            snaps.len(),
            1,
            "the imported task is in the active set (queued)"
        );
        let snap = &snaps[0];
        assert_eq!(snap.row.gid, "80000000000000ff");
        assert_eq!(snap.row.state, "queued");
        assert_eq!(snap.row.v1_infohash.as_deref(), Some(ih.as_slice()));
        assert_eq!(snap.files.len(), 1);
        let pr = ok(
            handle2.load_torrent_progress("80000000000000ff").await,
            "load progress",
        )
        .unwrap_or_else(|| panic!("progress row"));
        assert_eq!(pr.uploaded_total, 4096);
        assert_eq!(pr.v1_bitfield.as_deref(), Some(&[0b1100_0000u8][..]));
        // Dedup kv hit -> a repeated import is intercepted.
        let kv = ok(handle2.get_kv(&planned.source_key).await, "get kv");
        assert_eq!(kv.as_deref(), Some("80000000000000ff"));
        drop(handle2);
        let _ = ok(
            tokio::time::timeout(std::time::Duration::from_secs(1), join2).await,
            "writer 2 exit",
        );
        let _ = std::fs::remove_file(&db);
    }

    /// Dedup key determinism: same source = same key; different sources
    /// = different keys; a canonicalize failure falls back to the raw
    /// path and stays deterministic.
    #[test]
    fn source_keys_are_deterministic_per_source() {
        let a = ctrl_source();
        assert_eq!(a.source_key(), a.source_key());
        assert_eq!(
            a.source_key(),
            "imported_from:ctrl:/dl/migrated.bin.aria2",
            "the dangling path falls back as-is"
        );
        let b = fork_source();
        assert_ne!(a.source_key(), b.source_key());
        assert!(b.source_key().ends_with("#0000000000000042"));
    }
}

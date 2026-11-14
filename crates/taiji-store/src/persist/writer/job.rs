//! [`PersistJob`]: the single-writer command set (submitted from the
//! async side over a bounded mpsc with oneshot result replies)
//! plus the [`PersistOutcome`] write result — execution lives in the
//! `write_*` row faces (digest skip-write / row-level comparison
//! semantics preserved as-is).

use tokio::sync::oneshot;

use crate::error::StoreError;

use super::rows::{
    DhtStateRow, HttpTaskRow, HttpTaskSnapshot, IpfilterRow, MediaArchiveRow, MediaFormatRow,
    MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow, PeerBanRow, RecoveredLayerRow,
    TaskCookieRow, TorrentFileRow, TorrentProgressRow, TorrentRow, TorrentSnapshot, TrackerRow,
};

/// One task's whole track set as the recovery read reply (track row +
/// its segment rows, per track).
pub type MediaTrackSet = Vec<(MediaTrackRow, Vec<MediaSegmentRow>)>;

/// One persistence command.
pub enum PersistJob {
    /// Derived verified metadata, independent of a task's lifetime.
    CacheMetadata {
        identity: super::MetadataCacheIdentity,
        metadata: Vec<u8>,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Load cached content or an existing task's metadata; callers reverify it.
    LoadMetadata {
        identity: super::MetadataCacheIdentity,
        reply: oneshot::Sender<Result<Option<Vec<u8>>, StoreError>>,
    },
    /// Evict corrupt content, or clear all cached metadata when identity is None.
    EvictMetadata {
        identity: Option<super::MetadataCacheIdentity>,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Upsert one torrent progress row; skip if the digest is unchanged.
    UpsertTorrentProgress {
        row: TorrentProgressRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Upsert one tracker row; skip if the row content is unchanged.
    UpsertTracker {
        row: TrackerRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read back one torrent progress row: at task registration,
    /// `uploaded_total`/`downloaded_total`/`active_time_s`/`seed_time_s`
    /// become the cross-session base (the `upload_at_startup` semantics
    /// of ratio computation). A read-only job, still serialized through
    /// the single write connection — no second connection.
    LoadTorrentProgress {
        gid: String,
        reply: oneshot::Sender<Result<Option<TorrentProgressRow>, StoreError>>,
    },
    /// Upsert one peer_ban row; skip if the row content is unchanged.
    UpsertPeerBan {
        row: PeerBanRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Delete one peer_ban row (`taiji.unbanAddr`): the unban face for
    /// manual bans. Missing row -> `SkippedUnchanged` (idempotent).
    DeletePeerBan {
        ip: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Whole-table replace of the ipfilter rows of the given kind: a
    /// blocklist import is a full replacement — transactional DELETE of
    /// the old rows + batch INSERT; re-importing identical content skips
    /// (row-set comparison). Rows of other kinds (e.g. cidr) are
    /// untouched.
    ReplaceIpfilter {
        kind: String,
        rows: Vec<IpfilterRow>,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read back active peer_ban rows (startup recovery: only rows with
    /// `until > now` are in force).
    LoadActivePeerBans {
        now: i64,
        reply: oneshot::Sender<Result<Vec<PeerBanRow>, StoreError>>,
    },
    /// Read back all ipfilter rows (startup recovery: rebuild the
    /// IpGuard static rule set).
    LoadIpfilter {
        reply: oneshot::Sender<Result<Vec<IpfilterRow>, StoreError>>,
    },
    /// Upsert one dht_state row: primary key family; skip if the
    /// routing-table BLOB is unchanged (a node_id stable across
    /// restarts + an unchanged BLOB = no new information).
    UpsertDhtState {
        row: DhtStateRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read back one dht_state row (startup recovery: the payload source
    /// for `DhtRestoreState::from_state_row`). Missing row (first
    /// session / never saved) -> `Ok(None)`.
    LoadDhtState {
        family: String,
        reply: oneshot::Sender<Result<Option<DhtStateRow>, StoreError>>,
    },
    // ---- business rows ----
    /// Upsert the torrent parent row + **authoritative file-set
    /// replacement**. Dedup: parent row + file set compared row by row
    /// across all fields (observational columns excepted); full equality
    /// -> skip; otherwise a single transaction (parent upsert -> file-row
    /// DELETE + INSERT, FK order parent before children).
    UpsertTorrent {
        row: TorrentRow,
        files: Vec<TorrentFileRow>,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Delete the torrent parent row (remove face): FK ON DELETE CASCADE
    /// clears torrent_file/torrent_progress/tracker (foreign_keys=ON).
    /// Row existed = `Written` (deleted); no row = `SkippedUnchanged`
    /// (zero disk writes).
    DeleteTorrent {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Recovery read face (startup bootstrap): all rows in the
    /// active set (the torrent-family active derivation,
    /// [`super::TaskPhase::active_words`]) + their file sets,
    /// in `queue_pos, created_at` order. Terminal rows (done/error) are
    /// not on this read face (persisted DownloadResults go through
    /// [`PersistJob::LoadDownloadResult`]).
    LoadTorrentsAtStartup {
        reply: oneshot::Sender<Result<Vec<TorrentSnapshot>, StoreError>>,
    },
    /// Startup seeding read face: the global upper bound of stored
    /// `queue_pos` (MAX across all torrent rows + all http_task rows,
    /// across the two tables; 0 when both are empty) — seeds the
    /// monotonic row_seq key across restarts, so keys enqueued after
    /// recovery continue above the bound (a new key is always strictly
    /// greater than every stored key, terminal rows included). A
    /// read-only job, serialized through the single write connection.
    LoadTaskGids {
        reply: oneshot::Sender<Result<Vec<String>, StoreError>>,
    },
    LoadMaxQueuePos {
        reply: oneshot::Sender<Result<i64, StoreError>>,
    },
    /// Persist a DownloadResult: land a terminal torrent row
    /// (state in {done,error}) — the file set is not on this write face
    /// (a closing result row; file facts are maintained by
    /// UpsertTorrent). A non-terminal state is an explicit error
    /// (writer-side defense keeping result rows out of the active-set
    /// semantics).
    InsertDownloadResult {
        row: TorrentRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Clear persisted DownloadResults (mirrors aria2
    /// purgeDownloadResult): delete all rows with state in {done,error}
    /// (the FK cascade follows); no rows = skip.
    PurgeDownloadResults {
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Delete one persisted DownloadResult (mirrors aria2
    /// removeDownloadResult): only terminal rows can be deleted; a
    /// missing or still-active row = `SkippedUnchanged` (the caller maps
    /// this to the aria2 failure face).
    RemoveDownloadResult {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read back one persisted DownloadResult: located by gid with state
    /// in the terminal set, else `Ok(None)`.
    LoadDownloadResult {
        gid: String,
        reply: oneshot::Sender<Result<Option<TorrentRow>, StoreError>>,
    },
    /// session_kv write face (the base for the importer `imported_from`
    /// re-import marks): primary key key; unchanged value -> skip.
    PutKv {
        key: String,
        value: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// session_kv read face; missing key -> `Ok(None)`.
    GetKv {
        key: String,
        reply: oneshot::Sender<Result<Option<String>, StoreError>>,
    },
    /// Whole-table replace of the globally imported tracker set (the
    /// persistence face of the second architecture layer): an import is
    /// a union accumulation — the caller computes the full new set; an
    /// unchanged set -> skip; a changed set = single-transaction DELETE +
    /// batch INSERT. Import order = table rowid order (the read face
    /// matches).
    ReplaceGlobalTrackers {
        urls: Vec<String>,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read face of the globally imported tracker set (startup bootstrap
    /// recovery): rowid order (import order).
    LoadGlobalTrackers {
        reply: oneshot::Sender<Result<Vec<String>, StoreError>>,
    },
    /// saveSession persistence barrier: single-writer-connection
    /// serialization guarantees every earlier job is already durable
    /// (the channel is the order); this job then runs
    /// `PRAGMA wal_checkpoint(TRUNCATE)`. Durability argument per the
    /// official SQLite documentation (safety-review item): in WAL mode a
    /// commit lands in the WAL file (`synchronous=NORMAL` does not fsync
    /// the WAL); on process kill the page cache survives and committed
    /// transactions are necessarily in the WAL (replayed at recovery;
    /// the WAL must never be deleted across restarts). A **power loss**
    /// may roll back the most recent NORMAL commits — no corruption, and
    /// only under-recording, never phantom progress (the progress bitmap
    /// re-baselines from the snapshot in the safe direction). The
    /// checkpoint only shrinks the WAL file and lets a stalled writer
    /// advance; it is not a durability condition.
    Checkpoint {
        reply: oneshot::Sender<Result<(), StoreError>>,
    },
    // ---- hash recovery derived table ----
    /// Upsert one recovered_layer row: key = `(gid, file_index)`;
    /// unchanged row content (criterion payload + layer bytes) -> skip.
    /// A dangling FK (no torrent row) = explicit error (a recovery layer
    /// must not exist without its task row).
    UpsertRecoveredLayer {
        row: RecoveredLayerRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read back all recovery-layer rows of one task (startup recovery:
    /// the payload source for re-verifying into the store when a task
    /// activates/upgrades); file_index order; no rows -> empty set.
    LoadRecoveredLayers {
        gid: String,
        reply: oneshot::Sender<Result<Vec<RecoveredLayerRow>, StoreError>>,
    },
    // ---- HTTP business rows ----
    /// Upsert one http_task row (the media data-model increment): all
    /// columns equal to the stored row (observational columns excepted)
    /// -> skip; changed state/bitmap/validator payload -> a
    /// single-transaction overwrite (created_at keeps its initial
    /// value).
    UpsertHttpTask {
        row: HttpTaskRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read back all active http_task rows (startup recovery) + each
    /// row's task cookie set (the unified `task_cookie` table:
    /// the task cookie store replays with recovery,
    /// deterministic in primary-key order); queue_pos order; terminal
    /// rows (done/error) are not on this read face.
    LoadHttpTasksAtStartup {
        reply: oneshot::Sender<Result<Vec<HttpTaskSnapshot>, StoreError>>,
    },
    /// Whole-set replacement of a task's cookie store (the
    /// unified table, http|media): a single-transaction DELETE of all
    /// the task's cookies + batch INSERT; an unchanged set -> skip; an
    /// empty set = clear all. All payload rows must share `(gid,
    /// task_kind)` (writer-side defense); an http payload with no
    /// http_task row = explicit error (a media payload may precede its
    /// media_task row — addMedia lands cookies at creation, the row
    /// lands in Resolving; see `write_cookie`).
    UpsertTaskCookies {
        gid: String,
        task_kind: String,
        cookies: Vec<TaskCookieRow>,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Clear a task's cookies (cleared on the full terminal
    /// set done|error at both families — the terminal close-out entry;
    /// the task-row delete paths pair their own clear). No rows =
    /// `SkippedUnchanged` (idempotent).
    ClearTaskCookies {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// The task's stored cookie set (any family, primary-key order) —
    /// the count face for the clear-on-error alert and the media
    /// activation seed read-back.
    LoadTaskCookies {
        gid: String,
        reply: oneshot::Sender<Result<Vec<TaskCookieRow>, StoreError>>,
    },
    /// Startup GC ("the startup GC cleans crash orphans"): clears orphan rows
    /// (no task row) and terminal residue (task row already done/error)
    /// in one transaction; never touches active rows; idempotent. The
    /// report carries per-gid error-form groups (the bootstrap alert
    /// re-emission) + the orphan/done counts (the GC log).
    SweepTaskCookies {
        reply: oneshot::Sender<Result<super::write_cookie::TaskCookieSweepReport, StoreError>>,
    },
    /// Delete one http_task row (remove face): the paired delete clears
    /// the gid's `task_cookie` rows in the same transaction (the
    /// unified table carries no FK). Row existed = `Written`; no row =
    /// `SkippedUnchanged`.
    DeleteHttpTask {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Explicit reopen of a terminal row (the only terminal exit, for
    /// the Error->unpause re-probe migration arm): state back to queued +
    /// error fields cleared; progress retained. Hit = `Written`;
    /// missing row/non-terminal = `SkippedUnchanged` (idempotent). The
    /// upsert write face's terminal-downgrade guard refuses non-terminal
    /// overwrites — leaving a terminal state must go through this job.
    ReopenHttpTask {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Read back terminal done rows (the read face of the renamePending
    /// startup closure): all rows with state='done'. The rename_pending
    /// flag inside config_json is interpreted by the caller (the store
    /// does not interpret payloads).
    LoadHttpDoneRows {
        reply: oneshot::Sender<Result<Vec<HttpTaskRow>, StoreError>>,
    },
    /// Single-row read (any state; the row-fact source for the
    /// Error->unpause re-probe migration arm): row + task cookie set.
    /// Missing row = `Ok(None)`.
    LoadHttpTask {
        gid: String,
        reply: oneshot::Sender<Result<Option<HttpTaskSnapshot>, StoreError>>,
    },
    // ---- media business rows (media write enablement) ----
    /// Upsert one media_task row (the minimal parent face anchoring the
    /// track/segment FKs; the orchestration state machine stays on the
    /// media mount). Row-comparison skip-write semantics as [`PersistJob::
    /// UpsertHttpTask`].
    UpsertMediaTask {
        row: MediaTaskRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Replace one track row + its whole segment set (single
    /// transaction: track upsert -> segment DELETE + batch INSERT; an
    /// unchanged set skips). A dangling FK (no media_task row) is an
    /// explicit error. All segment rows must share the payload
    /// `(gid, track_idx)` (writer-side defense).
    ReplaceMediaTrack {
        track: MediaTrackRow,
        segments: Vec<MediaSegmentRow>,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Recovery read face: all tracks of one task + their segment sets
    /// (track_idx then seg_idx order); no rows -> empty set.
    LoadMediaTracks {
        gid: String,
        reply: oneshot::Sender<Result<MediaTrackSet, StoreError>>,
    },
    /// Upsert the task's key rows (media_key write enablement):
    /// per-row insert-or-update keyed by `(gid, key_id)` with
    /// row-comparison skip; **no delete** — row ids stay stable because
    /// `media_segment.key_id` references them. A dangling FK (no
    /// media_task row) is an explicit error.
    UpsertMediaKeys {
        gid: String,
        keys: Vec<MediaKeyRow>,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Key-row read face (ids included — the media-side restart face:
    /// keys already in the DB are never re-fetched).
    LoadMediaKeys {
        gid: String,
        reply: oneshot::Sender<Result<Vec<MediaKeyRow>, StoreError>>,
    },
    /// Delete one media_task row (remove face): FK ON DELETE CASCADE
    /// clears media_track/media_segment/media_key/media_format + the
    /// paired delete clears the gid's `task_cookie` rows. Row
    /// existed = `Written`; no row = `SkippedUnchanged`.
    DeleteMediaTask {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    // ---- media_format + the orchestration read/reopen set ----
    /// Upsert one media_format row (the resolved format-tree snapshot
    /// — the probe token's server cache made durable). Row-comparison
    /// skip; dangling FK (no media_task row) = explicit error.
    UpsertMediaFormat {
        row: MediaFormatRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// media_format read face (the getMediaFormats source); no row =
    /// `Ok(None)`.
    LoadMediaFormat {
        gid: String,
        reply: oneshot::Sender<Result<Option<MediaFormatRow>, StoreError>>,
    },
    /// Startup recovery read face: all media_task rows in the active
    /// set (every state except done/error), created_at order.
    LoadMediaTasksAtStartup {
        reply: oneshot::Sender<Result<Vec<MediaTaskRow>, StoreError>>,
    },
    /// Single-row read (any state; the Error→unpause re-resolve
    /// arm's row-fact source); no row = `Ok(None)`.
    LoadMediaTask {
        gid: String,
        reply: oneshot::Sender<Result<Option<MediaTaskRow>, StoreError>>,
    },
    /// Staging-GC liveness read face: `(gid, staging_dir)`
    /// of **every** media_task row, any state — the startup GC's
    /// liveness set + scan roots (a true orphan = a gid directory with
    /// no row at all; terminal rows keep their staged trees).
    LoadMediaTaskGcRefs {
        reply: oneshot::Sender<Result<Vec<(String, String)>, StoreError>>,
    },
    /// The paused→queued unpause transition (the reserved unpause
    /// face's single exit from `paused`; routed explicitly because the
    /// upsert's guarded-state guard refuses live-phase
    /// overwrites). Clears the phase memory; progress retained.
    UnpauseMediaTask {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// Explicit reopen of a terminal media row (the Error→unpause
    /// re-resolve arm): state back to `resolving`, error fields +
    /// phase memory cleared, progress retained. Missing row /
    /// non-terminal state = `SkippedUnchanged` (idempotent).
    ReopenMediaTask {
        gid: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// The error-terminal partial-column update (state +
    /// error fields + updated_at; the row's facts stay as written).
    /// No row for the gid = `SkippedUnchanged` (the caller's
    /// fresh-row fallback owns that shape).
    FailMediaTask {
        gid: String,
        error_code: String,
        error_msg: String,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    // ---- media_archive write/read/clear faces ----
    /// Upsert one media_archive row (the Done close-out of a
    /// `--media-archive` task): keyed by url_digest; an unchanged row
    /// (the observational columns excepted) skips; updated_at bumps.
    UpsertMediaArchive {
        row: MediaArchiveRow,
        reply: oneshot::Sender<Result<PersistOutcome, StoreError>>,
    },
    /// First checkpoint lookup (admission/activation — zero outbound):
    /// the row whose url_digest matches, else `Ok(None)`.
    LoadMediaArchiveByUrl {
        url_digest: String,
        reply: oneshot::Sender<Result<Option<MediaArchiveRow>, StoreError>>,
    },
    /// Second checkpoint lookup (Resolving, after the manifest fetch):
    /// the first row whose manifest_digest matches (the CDN/mirror
    /// switch same-content hit face), else `Ok(None)`.
    LoadMediaArchiveByManifest {
        manifest_digest: String,
        reply: oneshot::Sender<Result<Option<MediaArchiveRow>, StoreError>>,
    },
    /// The destructive whole-table clear (`taiji.clearMediaArchive` /
    /// `--media-archive-clear`): deletes every row, replies with the
    /// removed count. Empty table = 0 (idempotent).
    ClearMediaArchive {
        reply: oneshot::Sender<Result<u64, StoreError>>,
    },
}

/// Write result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistOutcome {
    /// Payload changed and actually written.
    Written,
    /// Matches the stored digest; skipped (zero disk writes this time).
    SkippedUnchanged,
}

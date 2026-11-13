//! [`PersistHandle`]: a cheap-to-clone handle to the PersistWriter — the
//! async API face, one pair per job (bounded mpsc submit + oneshot reply);
//! a full job channel backpressures the caller (unbounded is forbidden).

use tokio::sync::{mpsc, oneshot};

use crate::error::StoreError;

use super::job::{PersistJob, PersistOutcome};
use super::rows::{
    DhtStateRow, HttpTaskRow, HttpTaskSnapshot, IpfilterRow, MediaArchiveRow, MediaFormatRow,
    MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow, PeerBanRow, RecoveredLayerRow,
    TaskCookieRow, TorrentFileRow, TorrentProgressRow, TorrentRow, TorrentSnapshot, TrackerRow,
};

/// PersistWriter handle (cheap to clone: internally just a cloned mpsc
/// Sender).
#[derive(Clone)]
pub struct PersistHandle {
    pub(super) job_tx: mpsc::Sender<PersistJob>,
}

impl PersistHandle {
    /// Upsert the progress row and wait for the durable-write verdict
    /// (backpressure: awaits queue up when the job channel is full).
    pub async fn upsert_torrent_progress(
        &self,
        row: TorrentProgressRow,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertTorrentProgress { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert a single tracker row and wait for the durable-write verdict.
    pub async fn upsert_tracker(&self, row: TrackerRow) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertTracker { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back a torrent's progress row: the cross-session baseline read
    /// at task registration. A missing row (first task / no progress) ->
    /// `Ok(None)`.
    pub async fn load_torrent_progress(
        &self,
        gid: &str,
    ) -> Result<Option<TorrentProgressRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadTorrentProgress {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert a single peer_ban row: written as soon as a ban takes effect
    /// (with `until`, the "with until" persistence semantics); a
    /// rewrite with identical content skips the write.
    pub async fn upsert_peer_ban(&self, row: PeerBanRow) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertPeerBan { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Delete a single peer_ban row (`taiji.unbanAddr`): the manual unban
    /// face. A missing row -> `SkippedUnchanged` (idempotent; this
    /// distinguishes unbanning something that is not banned).
    pub async fn delete_peer_ban(&self, ip: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::DeletePeerBan {
                ip: ip.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Whole-table replacement of the ipfilter rows of one kind:
    /// full-replacement semantics for blocklist imports; re-importing
    /// identical content skips the write.
    pub async fn replace_ipfilter(
        &self,
        kind: &str,
        rows: Vec<IpfilterRow>,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::ReplaceIpfilter {
                kind: kind.to_string(),
                rows,
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back the currently effective peer_ban rows (startup recovery):
    /// the set with `until > now`.
    pub async fn load_active_peer_bans(&self, now: i64) -> Result<Vec<PeerBanRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadActivePeerBans { now, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back all ipfilter rows (startup recovery: rebuild IpGuard's
    /// static rule set).
    pub async fn load_ipfilter(&self) -> Result<Vec<IpfilterRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadIpfilter { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert a single dht_state row: DhtEvent::Persist -> persist
    /// (autosave/halt); identical content (node_id + routing_table) skips
    /// the write.
    pub async fn upsert_dht_state(&self, row: DhtStateRow) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertDhtState { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back a single dht_state row (startup recovery): located by the
    /// family primary key.
    pub async fn load_dht_state(&self, family: &str) -> Result<Option<DhtStateRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadDhtState {
                family: family.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert the torrent parent row + file set: the business-row write
    /// face for task registration / state transitions / completion.
    /// Unchanged row content (observability columns aside) -> skip the
    /// write.
    pub async fn upsert_torrent(
        &self,
        row: TorrentRow,
        files: Vec<TorrentFileRow>,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertTorrent {
                row,
                files,
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Delete the torrent parent row (remove face): FK cascade clears the
    /// subtables.
    pub async fn delete_torrent(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::DeleteTorrent {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Recovery read face (startup bootstrap): all rows of the active set +
    /// their file sets.
    pub async fn load_torrents_at_startup(&self) -> Result<Vec<TorrentSnapshot>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadTorrentsAtStartup { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Startup seeding read: the global upper bound of in-db `queue_pos`
    /// (cross-table MAX over torrent full-state + http_task full-state; all
    /// empty = 0). Consumer: core bootstrap's row_seq seeding (enqueue keys
    /// continue increasing from the bound, monotonic across restarts).
    pub async fn load_task_gids(&self) -> Result<Vec<String>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadTaskGids { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    pub async fn load_max_queue_pos(&self) -> Result<i64, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMaxQueuePos { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Persist a DownloadResult: the terminal torrent row is stored
    /// (non-terminal = explicit error).
    pub async fn insert_download_result(
        &self,
        row: TorrentRow,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::InsertDownloadResult { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Clear persisted DownloadResults: all terminal rows deleted.
    pub async fn purge_download_results(&self) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::PurgeDownloadResults { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Remove one persisted DownloadResult: only terminal rows can be
    /// removed.
    pub async fn remove_download_result(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::RemoveDownloadResult {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back one persisted DownloadResult; no terminal row ->
    /// `Ok(None)`.
    pub async fn load_download_result(&self, gid: &str) -> Result<Option<TorrentRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadDownloadResult {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// session_kv write face; unchanged value -> skip the write.
    pub async fn put_kv(&self, key: &str, value: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::PutKv {
                key: key.to_string(),
                value: value.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// session_kv read face; missing key -> `Ok(None)`.
    pub async fn get_kv(&self, key: &str) -> Result<Option<String>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::GetKv {
                key: key.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Whole-set replacement of the globally imported tracker set:
    /// unchanged set -> skip the write.
    pub async fn replace_global_trackers(
        &self,
        urls: Vec<String>,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::ReplaceGlobalTrackers { urls, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read face for the globally imported tracker set (startup bootstrap):
    /// rowid order (import order).
    pub async fn load_global_trackers(&self) -> Result<Vec<String>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadGlobalTrackers { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// saveSession durability barrier: wait for all previously submitted
    /// write jobs to hit disk + `wal_checkpoint(TRUNCATE)`. Failure is only
    /// reported in the reply (the caller decides the error response).
    pub async fn checkpoint(&self) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::Checkpoint { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert a single recovered_layer row: persisted after a recovery
    /// layer is admitted; unchanged content -> skip the write.
    pub async fn upsert_recovered_layer(
        &self,
        row: RecoveredLayerRow,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertRecoveredLayer { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back all recovery-layer rows of one task (startup recovery);
    /// ordered by file_index, no rows -> empty set.
    pub async fn load_recovered_layers(
        &self,
        gid: &str,
    ) -> Result<Vec<RecoveredLayerRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadRecoveredLayers {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert a single http_task row (the media data-model increment):
    /// unchanged row content (observability columns aside) -> skip the
    /// write.
    pub async fn upsert_http_task(&self, row: HttpTaskRow) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertHttpTask { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back all active http_task rows (startup recovery) + each row's
    /// task cookie set (the unified table): queue_pos order; terminal states
    /// (done/error) are not in this read face.
    pub async fn load_http_tasks_at_startup(&self) -> Result<Vec<HttpTaskSnapshot>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadHttpTasksAtStartup { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Whole-set replacement of a task's cookie store (the
    /// unified table): unchanged set -> skip the write; an http
    /// payload with no http_task row = explicit error; an empty set =
    /// clear all; payload rows must all belong to `(gid, task_kind)`.
    pub async fn upsert_task_cookies(
        &self,
        gid: &str,
        task_kind: &str,
        cookies: Vec<TaskCookieRow>,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertTaskCookies {
                gid: gid.to_string(),
                task_kind: task_kind.to_string(),
                cookies,
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Clear a task's cookies (the terminal close-out entry:
    /// cleared on done|error at both families; delete paths pair their
    /// own clear); no rows = idempotent skip.
    pub async fn clear_task_cookies(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::ClearTaskCookies {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// The task's stored cookie set (any family, primary-key order) —
    /// the count face for the clear-on-error alert and the media
    /// activation seed read-back.
    pub async fn load_task_cookies(&self, gid: &str) -> Result<Vec<TaskCookieRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadTaskCookies {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Startup GC: clear orphan rows (no task row) and
    /// terminal residue (task row done/error) in one transaction;
    /// never touches active rows; idempotent. Error-form groups ride
    /// the report for the bootstrap alert re-emission.
    pub async fn sweep_task_cookies(
        &self,
    ) -> Result<super::write_cookie::TaskCookieSweepReport, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::SweepTaskCookies { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Delete a single http_task row (remove face): the paired delete
    /// clears the gid's task_cookie rows in the same transaction; no
    /// rows = idempotent skip.
    pub async fn delete_http_task(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::DeleteHttpTask {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Explicitly reopen a terminal row (the only terminal exit of the
    /// Error->unpause re-probe migration arm): state back to queued + error
    /// fields cleared, progress fields retained; hit = `Written`, no row /
    /// non-terminal = idempotent skip.
    pub async fn reopen_http_task(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::ReopenHttpTask {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read back terminal done rows (the read face of the renamePending
    /// startup sweep): all rows with state='done', queue_pos order.
    pub async fn load_http_done_rows(&self) -> Result<Vec<HttpTaskRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadHttpDoneRows { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert one media_task row (the minimal parent face
    /// anchoring the track/segment FKs; row-comparison skip).
    pub async fn upsert_media_task(&self, row: MediaTaskRow) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertMediaTask { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Replace one track row + its whole segment set (single
    /// transaction; unchanged set skips; dangling FK = explicit
    /// error).
    pub async fn replace_media_track(
        &self,
        track: MediaTrackRow,
        segments: Vec<MediaSegmentRow>,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::ReplaceMediaTrack {
                track,
                segments,
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Recovery read face: all tracks of one task + segment sets.
    pub async fn load_media_tracks(
        &self,
        gid: &str,
    ) -> Result<super::job::MediaTrackSet, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaTracks {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert the task's key rows (media_key face): per-row
    /// upsert keyed by (gid, key_id); row ids stay stable (no delete —
    /// media_segment.key_id references them).
    pub async fn upsert_media_keys(
        &self,
        gid: &str,
        keys: Vec<MediaKeyRow>,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertMediaKeys {
                gid: gid.to_string(),
                keys,
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Key-row read face (ids included — the media-side restart face:
    /// keys already in the DB are never re-fetched).
    pub async fn load_media_keys(&self, gid: &str) -> Result<Vec<MediaKeyRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaKeys {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Delete one media_task row (children cascade).
    pub async fn delete_media_task(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::DeleteMediaTask {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Upsert one media_format row (the resolved format-tree
    /// snapshot — the probe token's server cache made durable).
    pub async fn upsert_media_format(
        &self,
        row: MediaFormatRow,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertMediaFormat { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// media_format read face (the getMediaFormats source).
    pub async fn load_media_format(&self, gid: &str) -> Result<Option<MediaFormatRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaFormat {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Startup recovery read face: all active-set media_task rows
    /// (every state except done/error), created_at order.
    pub async fn load_media_tasks_at_startup(&self) -> Result<Vec<MediaTaskRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaTasksAtStartup { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Single-row read (any state; the Error→unpause re-resolve arm).
    pub async fn load_media_task(&self, gid: &str) -> Result<Option<MediaTaskRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaTask {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Staging-GC liveness read face: `(gid, staging_dir)`
    /// of every media_task row, any state — the startup GC's liveness
    /// set + scan roots (a true orphan = a gid directory with no row;
    /// terminal rows keep their staged trees).
    pub async fn load_media_task_gc_refs(&self) -> Result<Vec<(String, String)>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaTaskGcRefs { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// The paused→queued unpause transition (the explicit exit from
    /// `paused` — the upsert's guarded-state guard refuses the
    /// plain overwrite).
    pub async fn unpause_media_task(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UnpauseMediaTask {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// The error-terminal partial-column update — state
    /// `error` + the error fields + updated_at; kind, output_name,
    /// the variant/selector snapshots and the manifest digest stay
    /// as the run wrote them (the whole-row upsert would clobber
    /// them with the fail template's placeholders). Hit = `Written`;
    /// no row = `SkippedUnchanged` (the caller falls back to the
    /// fresh-row insert).
    pub async fn fail_media_task(
        &self,
        gid: &str,
        error_code: &str,
        error_msg: &str,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::FailMediaTask {
                gid: gid.to_string(),
                error_code: error_code.to_string(),
                error_msg: error_msg.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Explicit reopen of a terminal media row (Error→unpause
    /// re-resolve: state back to `resolving`, error fields cleared).
    pub async fn reopen_media_task(&self, gid: &str) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::ReopenMediaTask {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    // ---- media_archive faces ----

    /// Upsert one media_archive row (a `--media-archive` task's Done
    /// close-out); row-comparison skip as the sibling faces.
    pub async fn upsert_media_archive(
        &self,
        row: MediaArchiveRow,
    ) -> Result<PersistOutcome, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::UpsertMediaArchive { row, reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// First checkpoint lookup (admission/activation, zero outbound):
    /// the row whose normalized-URL digest matches.
    pub async fn load_media_archive_by_url(
        &self,
        url_digest: &str,
    ) -> Result<Option<MediaArchiveRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaArchiveByUrl {
                url_digest: url_digest.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Second checkpoint lookup (Resolving, post-manifest): the first row
    /// whose manifest digest matches (the same-content hit face).
    pub async fn load_media_archive_by_manifest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<MediaArchiveRow>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMediaArchiveByManifest {
                manifest_digest: manifest_digest.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// The destructive whole-table clear (`taiji.clearMediaArchive` /
    /// `--media-archive-clear`); replies with the removed row count.
    pub async fn clear_media_archive(&self) -> Result<u64, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::ClearMediaArchive { reply: tx })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Single-row read (any state; the row source of truth for the
    /// Error->unpause migration arm): row + task cookie set; no row =
    /// `Ok(None)`.
    pub async fn load_http_task(&self, gid: &str) -> Result<Option<HttpTaskSnapshot>, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadHttpTask {
                gid: gid.to_string(),
                reply: tx,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }
}

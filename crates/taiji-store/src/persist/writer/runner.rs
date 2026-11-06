//! PersistWriter entry and the dedicated blocking thread's main loop:
//! `spawn` opens (including migration) and `spawn_blocking`s the writer
//! thread; the main loop dispatches each job to its `write_*` row face.
//! Single-writer proof = `Connection` ownership exclusive to this thread;
//! after all handles are dropped the queue drains and the thread exits.

use std::path::PathBuf;
use std::time::Instant;

use rusqlite::Connection;
use tokio::sync::mpsc;
use tracing::debug;

use crate::error::StoreError;
use crate::persist::{open_and_migrate, schema};

use super::handle::PersistHandle;
use super::job::{PersistJob, PersistOutcome};
use super::observer::SharedPersistObserve;
use super::write_cookie::{
    clear_task_cookies, load_task_cookies, sweep_task_cookies, upsert_task_cookies,
};
use super::write_dht::{load_dht_state, upsert_dht_state};
use super::write_http::{
    delete_http_task, load_http_done_rows, load_http_task, load_http_tasks_at_startup,
    reopen_http_task, upsert_http_task,
};
use super::write_ipguard::{
    delete_peer_ban, load_active_peer_bans, load_ipfilter, replace_ipfilter, upsert_peer_ban,
};
use super::write_kv::{get_kv, put_kv, run_checkpoint};
use super::write_media::{
    clear_media_archive, delete_media_task, fail_media_task, load_media_archive_by_manifest,
    load_media_archive_by_url, load_media_format, load_media_keys, load_media_task,
    load_media_task_gc_refs, load_media_tasks_at_startup, load_media_tracks, reopen_media_task,
    replace_media_track, unpause_media_task, upsert_media_archive, upsert_media_format,
    upsert_media_keys, upsert_media_task,
};
use super::write_progress::{load_torrent_progress, upsert_torrent_progress};
use super::write_recovery::{load_recovered_layers, upsert_recovered_layer};
use super::write_torrent::{
    delete_torrent, insert_download_result, load_download_result, load_max_queue_pos,
    load_torrents_at_startup, purge_download_results, remove_download_result, upsert_torrent,
};
use super::write_tracker::{load_global_trackers, replace_global_trackers, upsert_tracker};

/// Job channel capacity: persistence writes are low-frequency (digest dedup
/// skips most), and a full channel backpressures the caller (unbounded
/// forbidden).
const JOB_CHANNEL_CAPACITY: usize = 32;

/// PersistWriter: the single-writer task entry.
pub struct PersistWriter;

impl PersistWriter {
    /// Open (including migration) and start the dedicated blocking writer
    /// thread.
    ///
    /// Opening and migrating are disk IO, done inside `spawn_blocking`;
    /// failures return [`StoreError`] as-is (including
    /// [`StoreError::CorruptDatabase`] for a corrupt db).
    pub async fn spawn(
        path: PathBuf,
    ) -> Result<(PersistHandle, tokio::task::JoinHandle<()>), StoreError> {
        Self::spawn_with_observer(path, None).await
    }

    /// The observation-injection face of [`Self::spawn`]: when `observer`
    /// is present the writer thread, per job, reports the commit duration
    /// and the channel's retained depth (the convention documented in
    /// [`super::observer::PersistObserve`]). None = zero-overhead
    /// pass-through (existing behavior unchanged).
    pub async fn spawn_with_observer(
        path: PathBuf,
        observer: SharedPersistObserve,
    ) -> Result<(PersistHandle, tokio::task::JoinHandle<()>), StoreError> {
        let path_for_open = path.clone();
        let conn = tokio::task::spawn_blocking(move || open_and_migrate(&path_for_open))
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))??;
        let (job_tx, job_rx) = mpsc::channel::<PersistJob>(JOB_CHANNEL_CAPACITY);
        let join = tokio::task::spawn_blocking(move || writer_loop(conn, job_rx, observer));
        Ok((PersistHandle { job_tx }, join))
    }
}

/// Dedicated blocking thread's main loop: exits after processing every job
/// in the channel (all handles dropped).
///
/// Observation feed points (per job, when an observer is present): start a
/// timer before dispatch -> report the commit duration when the row write
/// completes; sample the job channel's retained depth after completion. The
/// callback runs on the dedicated blocking writer thread; implementers must
/// be non-blocking (the discipline is in the trait docs).
fn writer_loop(
    mut conn: Connection,
    mut job_rx: mpsc::Receiver<PersistJob>,
    observer: SharedPersistObserve,
) {
    debug!(target: "taiji::store::persist", version = schema::LATEST_VERSION, "persist writer up (single writer, digest-dedup)");
    while let Some(job) = job_rx.blocking_recv() {
        let started = Instant::now();
        match job {
            PersistJob::UpsertTorrentProgress { row, reply } => {
                let outcome = upsert_torrent_progress(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %row.gid, "progress row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::UpsertTracker { row, reply } => {
                let outcome = upsert_tracker(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %row.gid, tier = row.tier,
                        url = %row.url, "tracker row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadTorrentProgress { gid, reply } => {
                let _ = reply.send(load_torrent_progress(&conn, &gid));
            }
            PersistJob::UpsertPeerBan { row, reply } => {
                let outcome = upsert_peer_ban(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", ip = %row.ip,
                        until = row.until, "peer ban row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::DeletePeerBan { ip, reply } => {
                let outcome = delete_peer_ban(&mut conn, &ip);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", ip = %ip,
                        "peer ban row deleted");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::ReplaceIpfilter { kind, rows, reply } => {
                let outcome = replace_ipfilter(&mut conn, &kind, &rows);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", kind = %kind,
                        count = rows.len(), "ipfilter rows replaced");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadActivePeerBans { now, reply } => {
                let _ = reply.send(load_active_peer_bans(&conn, now));
            }
            PersistJob::LoadIpfilter { reply } => {
                let _ = reply.send(load_ipfilter(&conn));
            }
            PersistJob::UpsertDhtState { row, reply } => {
                let outcome = upsert_dht_state(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", family = %row.family,
                        "dht_state row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadDhtState { family, reply } => {
                let _ = reply.send(load_dht_state(&conn, &family));
            }
            PersistJob::UpsertTorrent { row, files, reply } => {
                let outcome = upsert_torrent(&mut conn, &row, Some(&files));
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %row.gid,
                        state = %row.state, files = files.len(), "torrent row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::DeleteTorrent { gid, reply } => {
                let outcome = delete_torrent(&mut conn, &gid);
                let _ = reply.send(outcome);
            }
            PersistJob::LoadTorrentsAtStartup { reply } => {
                let _ = reply.send(load_torrents_at_startup(&conn));
            }
            PersistJob::LoadMaxQueuePos { reply } => {
                let _ = reply.send(load_max_queue_pos(&conn));
            }
            PersistJob::InsertDownloadResult { row, reply } => {
                let outcome = insert_download_result(&mut conn, &row);
                let _ = reply.send(outcome);
            }
            PersistJob::PurgeDownloadResults { reply } => {
                let outcome = purge_download_results(&mut conn);
                let _ = reply.send(outcome);
            }
            PersistJob::RemoveDownloadResult { gid, reply } => {
                let outcome = remove_download_result(&mut conn, &gid);
                let _ = reply.send(outcome);
            }
            PersistJob::LoadDownloadResult { gid, reply } => {
                let _ = reply.send(load_download_result(&conn, &gid));
            }
            PersistJob::PutKv { key, value, reply } => {
                let outcome = put_kv(&mut conn, &key, &value);
                let _ = reply.send(outcome);
            }
            PersistJob::GetKv { key, reply } => {
                let _ = reply.send(get_kv(&conn, &key));
            }
            PersistJob::ReplaceGlobalTrackers { urls, reply } => {
                let outcome = replace_global_trackers(&mut conn, &urls);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist",
                        count = urls.len(), "global tracker set written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadGlobalTrackers { reply } => {
                let _ = reply.send(load_global_trackers(&conn));
            }
            PersistJob::Checkpoint { reply } => {
                let _ = reply.send(run_checkpoint(&mut conn));
            }
            PersistJob::UpsertRecoveredLayer { row, reply } => {
                let outcome = upsert_recovered_layer(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %row.gid,
                        file_index = row.file_index, bytes = row.layer.len(),
                        "recovered layer row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadRecoveredLayers { gid, reply } => {
                let _ = reply.send(load_recovered_layers(&conn, &gid));
            }
            PersistJob::UpsertHttpTask { row, reply } => {
                let outcome = upsert_http_task(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %row.gid,
                        state = %row.state, "http task row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadHttpTasksAtStartup { reply } => {
                let _ = reply.send(load_http_tasks_at_startup(&conn));
            }
            PersistJob::UpsertTaskCookies {
                gid,
                task_kind,
                cookies,
                reply,
            } => {
                let outcome = upsert_task_cookies(&mut conn, &gid, &task_kind, &cookies);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        task_kind = %task_kind, cookies = cookies.len(),
                        "task cookies written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::ClearTaskCookies { gid, reply } => {
                let outcome = clear_task_cookies(&mut conn, &gid);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        "task cookies cleared");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadTaskCookies { gid, reply } => {
                let _ = reply.send(load_task_cookies(&conn, &gid));
            }
            PersistJob::SweepTaskCookies { reply } => {
                let report = sweep_task_cookies(&mut conn);
                if let Ok(r) = &report
                    && (r.orphaned > 0 || r.done_cleared > 0 || !r.error_cleared.is_empty())
                {
                    debug!(target: "taiji::store::persist",
                        orphaned = r.orphaned, done_cleared = r.done_cleared,
                        error_groups = r.error_cleared.len(),
                        "task cookie startup GC swept residue");
                }
                let _ = reply.send(report);
            }
            PersistJob::DeleteHttpTask { gid, reply } => {
                let outcome = delete_http_task(&mut conn, &gid);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        "http task row deleted");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::ReopenHttpTask { gid, reply } => {
                let outcome = reopen_http_task(&mut conn, &gid);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        "http task terminal row reopened (queued)");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadHttpDoneRows { reply } => {
                let _ = reply.send(load_http_done_rows(&conn));
            }
            PersistJob::LoadHttpTask { gid, reply } => {
                let _ = reply.send(load_http_task(&conn, &gid));
            }
            PersistJob::UpsertMediaTask { row, reply } => {
                let outcome = upsert_media_task(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %row.gid,
                        state = %row.state, "media task row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::ReplaceMediaTrack {
                track,
                segments,
                reply,
            } => {
                let outcome = replace_media_track(&mut conn, &track, &segments);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %track.gid,
                        track_idx = track.track_idx, segments = segments.len(),
                        "media track row written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadMediaTracks { gid, reply } => {
                let _ = reply.send(load_media_tracks(&conn, &gid));
            }
            PersistJob::UpsertMediaKeys { gid, keys, reply } => {
                let outcome = upsert_media_keys(&mut conn, &gid, &keys);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        keys = keys.len(), "media key rows written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadMediaKeys { gid, reply } => {
                let _ = reply.send(load_media_keys(&conn, &gid));
            }
            PersistJob::DeleteMediaTask { gid, reply } => {
                let outcome = delete_media_task(&mut conn, &gid);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        "media task row deleted (children cascaded)");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::UpsertMediaFormat { row, reply } => {
                let outcome = upsert_media_format(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %row.gid,
                        "media format snapshot written");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadMediaFormat { gid, reply } => {
                let _ = reply.send(load_media_format(&conn, &gid));
            }
            PersistJob::LoadMediaTasksAtStartup { reply } => {
                let _ = reply.send(load_media_tasks_at_startup(&conn));
            }
            PersistJob::LoadMediaTask { gid, reply } => {
                let _ = reply.send(load_media_task(&conn, &gid));
            }
            PersistJob::LoadMediaTaskGcRefs { reply } => {
                let _ = reply.send(load_media_task_gc_refs(&conn));
            }
            PersistJob::UnpauseMediaTask { gid, reply } => {
                let outcome = unpause_media_task(&mut conn, &gid);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        "media task row unpaused (queued)");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::ReopenMediaTask { gid, reply } => {
                let outcome = reopen_media_task(&mut conn, &gid);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        "media task terminal row reopened (resolving)");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::FailMediaTask {
                gid,
                error_code,
                error_msg,
                reply,
            } => {
                let outcome = fail_media_task(&mut conn, &gid, &error_code, &error_msg);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist", gid = %gid,
                        "media task row failed (error; facts preserved)");
                }
                let _ = reply.send(outcome);
            }
            PersistJob::UpsertMediaArchive { row, reply } => {
                let outcome = upsert_media_archive(&mut conn, &row);
                if matches!(&outcome, Ok(PersistOutcome::Written)) {
                    debug!(target: "taiji::store::persist",
                        "media archive row written ({} bytes of provenance)", row.output_name.len());
                }
                let _ = reply.send(outcome);
            }
            PersistJob::LoadMediaArchiveByUrl { url_digest, reply } => {
                let _ = reply.send(load_media_archive_by_url(&conn, &url_digest));
            }
            PersistJob::LoadMediaArchiveByManifest {
                manifest_digest,
                reply,
            } => {
                let _ = reply.send(load_media_archive_by_manifest(&conn, &manifest_digest));
            }
            PersistJob::ClearMediaArchive { reply } => {
                let cleared = clear_media_archive(&mut conn);
                if let Ok(n) = &cleared {
                    debug!(target: "taiji::store::persist",
                        "media archive cleared ({n} rows — the browsing-history face)");
                }
                let _ = reply.send(cleared);
            }
        }
        if let Some(obs) = &observer {
            obs.observe_commit(started.elapsed());
            obs.set_queue_depth(job_rx.len() as u64);
        }
    }
    debug!(target: "taiji::store::persist", "persist writer exited (all handles dropped)");
}

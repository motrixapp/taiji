//! One HTTP publication owner. Downloaded bytes stay durable while the host
//! runs optional hooks or a filesystem temporarily refuses the final name.
//! The download driver waits here without occupying a payload admission slot.
use super::TaskNotice;
use super::http_task::{HttpLive, HttpPersistConfig, HttpTaskRun, PersistJournal};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use taiji_http::error::HttpError;
use taiji_http::finalize::{FinalizeOutcome, Finalizer, RenameIntent, RenameJournal};
use taiji_http::partfile::HandlesClosed;
use taiji_store::persist::{HttpTaskRow, TaskPhase};
use tokio::sync::Notify;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PublicationPhase {
    Ready,
    Publishing,
    Published,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PublicationRecord {
    pub intent: RenameIntent,
    pub phase: PublicationPhase,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Default)]
pub(super) struct OutputControl {
    record: Mutex<Option<PublicationRecord>>,
    pub changed: Notify,
    pub io_gate: Arc<tokio::sync::Mutex<()>>,
}
impl OutputControl {
    pub fn record(&self) -> Option<PublicationRecord> {
        crate::lock(&self.record).clone()
    }
    pub fn set(&self, record: PublicationRecord) {
        *crate::lock(&self.record) = Some(record);
    }
    pub fn request(&self, target: PathBuf, external: bool) -> Result<PublicationRecord, String> {
        let mut record = self.record().ok_or("HTTP data is not ready")?;
        if record.phase == PublicationPhase::Ready {
            record.intent.final_path = target;
            record.phase = PublicationPhase::Publishing;
            record.external = external;
            record.error = None;
        }
        Ok(record)
    }
}

pub(super) async fn store(
    run: &HttpTaskRun,
    mirror: &Arc<Mutex<HttpTaskRow>>,
    record: &PublicationRecord,
) -> Result<(), HttpError> {
    let row = {
        let mut row = crate::lock(mirror).clone();
        let mut cfg = HttpPersistConfig::from_json(&row.config_json);
        cfg.publication = Some(record.clone());
        cfg.rename_pending = record.phase != PublicationPhase::Published;
        row.config_json = cfg.to_json();
        row.total_done = record.intent.expected_len as i64;
        row.state = if record.phase == PublicationPhase::Published {
            TaskPhase::Done
        } else {
            TaskPhase::Finalizing
        }
        .as_v1_str()
        .into();
        row.updated_at = super::now_epoch();
        if record.phase == PublicationPhase::Published {
            if let Some(parent) = record.intent.final_path.parent() {
                row.dir = parent.display().to_string();
            }
            row.out = record
                .intent
                .final_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
        }
        row.clone()
    };
    if let Some(persist) = &run.persist {
        persist
            .upsert_http_task(row.clone())
            .await
            .map_err(|error| HttpError::Disk(error.to_string()))?;
    }
    *crate::lock(mirror) = row;
    Ok(())
}

pub(super) async fn finish(
    run: &HttpTaskRun,
    live: &Arc<HttpLive>,
    mirror: &Arc<Mutex<HttpTaskRow>>,
    proposed: RenameIntent,
    mut closed: Option<HandlesClosed>,
) -> Result<Option<PathBuf>, HttpError> {
    let cfg = HttpPersistConfig::from_json(&crate::lock(mirror).config_json);
    let journal = Arc::new(PersistJournal::new(run.persist.clone(), mirror.clone()));
    let finalizer = Finalizer::new(journal.clone());
    let mut record = match live.output.record().or(cfg.publication) {
        Some(record) => record,
        None => {
            let mut intent = finalizer.prepare_intent(&proposed);
            intent.auto_rename = !cfg.imported_progress || cfg.host_finalize;
            PublicationRecord {
                intent,
                phase: if cfg.host_finalize {
                    PublicationPhase::Ready
                } else {
                    PublicationPhase::Publishing
                },
                external: false,
                error: None,
            }
        }
    };
    live.host_controlled
        .store(cfg.host_finalize, Ordering::Relaxed);
    live.total_len
        .store(record.intent.expected_len, Ordering::Relaxed);
    live.done_bytes
        .store(record.intent.expected_len, Ordering::Relaxed);
    live.rate.store(0, Ordering::Relaxed);
    live.connections.store(0, Ordering::Relaxed);
    live.extents_active.store(0, Ordering::Relaxed);
    live.rename_pending.store(
        record.phase != PublicationPhase::Published,
        Ordering::Relaxed,
    );
    *crate::lock(&live.out_path) = record.intent.part_path.display().to_string();
    store(run, mirror, &record).await?;
    live.output.set(record.clone());
    if let Some(notices) = &run.notices {
        let _ = notices
            .send(TaskNotice::HttpFinalizing {
                gid: run.gid,
                host_ready: record.phase == PublicationPhase::Ready,
            })
            .await;
    }
    loop {
        if run.token.is_cancelled() {
            return Ok(None);
        }
        if let Some(request) = live.output.record() {
            record = request;
        }
        if record.phase == PublicationPhase::Published {
            return Ok(Some(record.intent.final_path));
        }
        if record.phase == PublicationPhase::Publishing {
            let _io = live.output.io_gate.lock().await;
            if run.token.is_cancelled() {
                return Ok(None);
            }
            // A request is journaled before publication. Retrying an accepted
            // request after restart must never restart the HTTP transfer.
            store(run, mirror, &record).await?;
            let result = if record.external {
                // Only the authenticated embedding host uses this acknowledgement
                // after its optional replacement/move transaction has committed.
                let path = record.intent.final_path.clone();
                tokio::task::spawn_blocking(move || {
                    std::fs::metadata(taiji_io::winpath::to_fs_path(&path))
                })
                .await
                .map_err(|error| HttpError::Disk(error.to_string()))?
                .map(|_| FinalizeOutcome::Completed {
                    final_path: record.intent.final_path.clone(),
                })
                .map_err(|error| HttpError::Disk(error.to_string()))
            } else if let Some(handles) = closed.take() {
                finalizer.finalize(&record.intent, handles).await
            } else {
                finalizer.resume(&record.intent).await
            };
            match result {
                Ok(FinalizeOutcome::Completed { final_path }) => {
                    record.intent.final_path = final_path.clone();
                    record.phase = PublicationPhase::Published;
                    record.error = None;
                    store(run, mirror, &record).await?;
                    live.output.set(record.clone());
                    *crate::lock(&live.out_path) = final_path.display().to_string();
                    live.rename_pending.store(false, Ordering::Relaxed);
                    taiji_http::partfile::release_part_claim(&record.intent.part_path);
                    taiji_http::partfile::release_all_final_claims(&record.intent.gid);
                    return Ok(Some(final_path));
                }
                Ok(FinalizeOutcome::RenamePending {
                    final_path,
                    last_error,
                }) => {
                    record.intent.final_path = final_path;
                    record.error = Some(last_error);
                }
                Err(error) => {
                    record.error = Some(error.to_string());
                }
            }
            // The finalizer may have selected another name; its persisted
            // receipt contains the actual target and reservation nonce.
            if let Some(intent) = journal.load_pending().await?.into_iter().next() {
                record.intent = intent;
            }
            store(run, mirror, &record).await?;
            live.output.set(record.clone());
        }
        tokio::select! {
            _ = run.token.cancelled() => return Ok(None),
            _ = live.output.changed.notified() => {},
            _ = tokio::time::sleep(Duration::from_secs(3)), if record.phase == PublicationPhase::Publishing => {},
        }
    }
}

pub(super) struct CompletedData {
    pub source: PathBuf,
    pub target: PathBuf,
    pub len: u64,
    pub closed: HandlesClosed,
    pub last_modified: Option<String>,
}

pub(super) async fn complete_download(
    run: &HttpTaskRun,
    live: &Arc<HttpLive>,
    mirror: &Arc<Mutex<HttpTaskRow>>,
    pause: &Arc<std::sync::atomic::AtomicBool>,
    data: CompletedData,
) -> super::http_task::DriveStop {
    let intent = RenameIntent::new(run.gid.to_string(), data.source, data.target, data.len);
    let result = finish(run, live, mirror, intent, Some(data.closed)).await;
    terminal_result(
        run,
        live,
        mirror,
        pause,
        result,
        data.len,
        data.last_modified,
    )
    .await
}

pub(super) async fn resume_download(
    run: &HttpTaskRun,
    live: &Arc<HttpLive>,
    mirror: &Arc<Mutex<HttpTaskRow>>,
    pause: &Arc<std::sync::atomic::AtomicBool>,
    record: PublicationRecord,
) -> super::http_task::DriveStop {
    let len = record.intent.expected_len;
    let result = finish(run, live, mirror, record.intent, None).await;
    terminal_result(run, live, mirror, pause, result, len, None).await
}

async fn terminal_result(
    run: &HttpTaskRun,
    live: &Arc<HttpLive>,
    mirror: &Arc<Mutex<HttpTaskRow>>,
    pause: &Arc<std::sync::atomic::AtomicBool>,
    result: Result<Option<PathBuf>, HttpError>,
    len: u64,
    last_modified: Option<String>,
) -> super::http_task::DriveStop {
    match result {
        Ok(Some(path)) => {
            let cfg = HttpPersistConfig::from_json(&crate::lock(mirror).config_json);
            if cfg.remote_time && !live.output.record().is_some_and(|r| r.external) {
                if let Some(value) = last_modified {
                    if let Err(error) =
                        taiji_http::remotetime::apply_remote_mtime(&path, &value).await
                    {
                        tracing::warn!(%error,"published file remote timestamp could not be set");
                    }
                }
            }
            super::http_task::DriveStop::Done {
                total_len: len,
                completed_len: len,
            }
        }
        // Cancel and failure both leave the publication unresolved: the
        // claims of the record go first (one arm, so the two exits
        // cannot drift apart).
        unresolved @ (Ok(None) | Err(_)) => {
            release_unresolved_claims(live.output.record());
            match unresolved {
                Ok(_) => super::http_task::cancelled_row(run, mirror, pause).await,
                Err(error) => {
                    super::http_task::fail(
                        run.persist.as_ref(),
                        mirror,
                        crate::session::view::EngineFailure::of_http_error(&error),
                        error.to_string(),
                    )
                    .await
                }
            }
        }
    }
}

/// The exits that leave a publication unresolved (cancel, failure) own
/// the release: after the renamePending handover
/// ([`HandlesClosed::hold_for_pending`]) no Drop is left to release the
/// `.part` claim, and a finished driver owns no output path. Idempotent —
/// an exit before the handover runs, the credential's own Drop releases
/// the `.part` claim too.
fn release_unresolved_claims(record: Option<PublicationRecord>) {
    let Some(record) = record else {
        return;
    };
    taiji_http::partfile::release_part_claim(&record.intent.part_path);
    taiji_http::partfile::release_all_final_claims(&record.intent.gid);
}

#[cfg(test)]
mod tests {
    use super::super::http_task::{ChainTrace, DriveStop, HttpTaskOpts};
    use super::*;
    use crate::session::metrics::SessionMetrics;
    use std::sync::atomic::AtomicBool;
    use taiji_domain::gid::Gid;
    use taiji_http::partfile::{
        FileAllocation, PartFile, PartOpenPolicy, claim_final_path, final_path_held_by_other,
        part_claim_held,
    };
    use tokio_util::sync::CancellationToken;

    /// The renamePending claim shape under a fresh temp dir: the
    /// credential handed the `.part` claim over, the final path is
    /// claimed under the record's gid. Returns the dir and the record
    /// (the paths to assert on ride with the record's intent).
    async fn handover_claims(tag: &str) -> (PathBuf, PublicationRecord) {
        let dir = std::env::temp_dir().join(format!("taiji-http-pub-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("tempdir: {e}"));
        let part_path = dir.join("claims.bin.part");
        let final_path = dir.join("claims.bin");
        let gid = format!("pub-{tag}-{}", std::process::id());
        let part = PartFile::open(
            part_path.clone(),
            Some(8),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("open: {e}"));
        part.close().hold_for_pending();
        claim_final_path(&final_path, &gid).unwrap_or_else(|e| panic!("claim final: {e}"));
        assert!(
            part_claim_held(&part_path),
            "the handover keeps the .part claim"
        );
        assert!(
            final_path_held_by_other(&final_path, "another-task"),
            "the final path is claimed under the record's gid"
        );
        let record = PublicationRecord {
            intent: RenameIntent::new(gid, part_path, final_path, 8),
            phase: PublicationPhase::Publishing,
            external: false,
            error: None,
        };
        (dir, record)
    }

    /// Both claims of the record are gone (neither path is conflicted
    /// for a later task).
    fn claims_released(record: &PublicationRecord) -> bool {
        !part_claim_held(&record.intent.part_path)
            && !final_path_held_by_other(&record.intent.final_path, "another-task")
    }

    /// The smallest driver context the unresolved exits of
    /// [`terminal_result`] read: no persistence, no notices.
    fn toy_run() -> (
        HttpTaskRun,
        Arc<HttpLive>,
        Arc<Mutex<HttpTaskRow>>,
        Arc<AtomicBool>,
    ) {
        let run = HttpTaskRun {
            notices: None,
            gid: Gid::from_u64(0x8000_0000_0000_0001),
            uris: Vec::new(),
            dir: PathBuf::new(),
            out: None,
            restore: None,
            row_mirror: None,
            cookies: Vec::new(),
            task_cookies: taiji_http::cookies::CookieStore::new(),
            opts: HttpTaskOpts::default(),
            per_host: taiji_http::perhost::HostCap::default(),
            queue_pos: 0,
            persist: None,
            limiter: None,
            token: CancellationToken::new(),
            metrics: Arc::new(SessionMetrics::default()),
            trace: ChainTrace::with_origin(std::time::Instant::now()),
        };
        let live = Arc::new(HttpLive::new(&[]));
        let mirror = Arc::new(Mutex::new(HttpTaskRow {
            gid: run.gid.to_string(),
            url: String::new(),
            final_url: String::new(),
            mirrors_json: None,
            state: TaskPhase::Finalizing.as_v1_str().to_string(),
            queue_pos: 0,
            dir: String::new(),
            out: "claims.bin".into(),
            config_json: "{}".into(),
            probe_json: None,
            validator_digest: None,
            block_size: 0,
            block_bitmap: None,
            block_count: None,
            total_done: 8,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        }));
        let pause = Arc::new(AtomicBool::new(false));
        (run, live, mirror, pause)
    }

    /// The exits themselves (not only the release helper): the driver's
    /// landing on a failure and on a cancel both release the handover
    /// claims of the record. Before the fix the failure exit skipped it,
    /// and once the handover keeps the `.part` claim (instead of the
    /// credential's Drop dropping it) that left both paths conflicted
    /// for every later task.
    #[tokio::test]
    async fn failure_and_cancel_exits_release_the_handover_claims() {
        let (run, live, mirror, pause) = toy_run();

        // Failure: the rename stayed refused past its retries.
        let (dir, record) = handover_claims("landing-fail").await;
        live.output.set(record.clone());
        let stop = terminal_result(
            &run,
            &live,
            &mirror,
            &pause,
            Err(HttpError::Disk("rename refused".into())),
            8,
            None,
        )
        .await;
        assert!(
            matches!(stop, DriveStop::Failed { .. }),
            "the failure exit lands the Failed stop"
        );
        assert_eq!(
            crate::lock(&mirror).state,
            TaskPhase::Error.as_v1_str(),
            "the failure exit lands the error row state"
        );
        assert!(
            claims_released(&record),
            "the failure exit must release the .part and final-path claims"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Cancel: the token fired while the publication waited.
        let (dir, record) = handover_claims("landing-cancel").await;
        live.output.set(record.clone());
        let stop = terminal_result(&run, &live, &mirror, &pause, Ok(None), 8, None).await;
        assert!(matches!(stop, DriveStop::Cancelled));
        assert!(
            claims_released(&record),
            "the cancel exit must release the .part and final-path claims"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The release helper on its own: a record releases both claims, and
    /// is idempotent with the credential's own Drop (an exit before the
    /// handover runs releases the `.part` claim there; no record means
    /// nothing to release).
    #[tokio::test]
    async fn release_helper_follows_the_record() {
        let (dir, record) = handover_claims("helper").await;

        // No record (the exit preceded the first journal write): nothing
        // to release — the credential's own Drop owns the claim then.
        release_unresolved_claims(None);
        assert!(!claims_released(&record), "no record = nothing to release");

        release_unresolved_claims(Some(record.clone()));
        assert!(claims_released(&record), "the record's claims go");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

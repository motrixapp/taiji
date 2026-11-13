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
        let mut row = crate::lock(mirror);
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
            .upsert_http_task(row)
            .await
            .map_err(|error| HttpError::Disk(error.to_string()))?;
    }
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
    live.output.set(record.clone());
    store(run, mirror, &record).await?;
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
        Ok(None) => {
            if let Some(record) = live.output.record() {
                taiji_http::partfile::release_part_claim(&record.intent.part_path);
                taiji_http::partfile::release_all_final_claims(&record.intent.gid);
            }
            super::http_task::cancelled_row(run, mirror, pause).await
        }
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

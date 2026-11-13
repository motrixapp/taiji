//! Fixed host publication API. Commands mutate durable intent; the HTTP driver
//! owns filesystem work, so a slow volume never blocks the session actor.
use super::http_publication::PublicationPhase;
use super::http_task::HttpPersistConfig;
use super::*;
use taiji_store::persist::HttpTaskRow;

impl SessionActor {
    async fn http_output_row(&self, gid: Gid) -> Result<HttpTaskRow, SessionError> {
        if let Some(Job::Http(job)) = self.jobs.get(&gid) {
            if let Some(mirror) = &job.mirror {
                return Ok(crate::lock(mirror).clone());
            }
            if let Some(row) = &job.restore {
                return Ok(row.clone());
            }
        }
        if let Some(persist) = &self.persist {
            if let Some(snapshot) = persist
                .load_http_task(&gid.to_string())
                .await
                .map_err(|e| SessionError::failed(e.to_string()))?
            {
                return Ok(snapshot.row);
            }
        }
        Err(SessionError::failed(format!(
            "GID {gid} is not found (HTTP output)"
        )))
    }

    pub(super) async fn get_http_output(
        &self,
        raw_gid: &str,
    ) -> Result<CommandReply, SessionError> {
        let gid = if raw_gid.len() == 16 {
            Gid::from_u64(
                u64::from_str_radix(raw_gid, 16)
                    .map_err(|_| SessionError::failed("Invalid GID"))?,
            )
        } else {
            self.resolve_gid(raw_gid)?
        };
        let row = self.http_output_row(gid).await?;
        let cfg = HttpPersistConfig::from_json(&row.config_json);
        use crate::session::view::{HttpOutputPhase, HttpOutputView};
        let mut output = HttpOutputView {
            phase: HttpOutputPhase::Downloading,
            host_controlled: cfg.host_finalize,
            paused: row.state == TaskPhase::Paused.as_v1_str(),
            source_path: None,
            final_path: None,
            length: None,
            error: None,
        };
        if let Some(record) = cfg.publication {
            output.phase = match record.phase {
                PublicationPhase::Ready => HttpOutputPhase::Ready,
                PublicationPhase::Publishing => HttpOutputPhase::Publishing,
                PublicationPhase::Published => HttpOutputPhase::Published,
            };
            output.source_path = Some(record.intent.part_path.display().to_string());
            output.final_path = Some(record.intent.final_path.display().to_string());
            output.length = Some(record.intent.expected_len);
            output.error = record.error;
        }
        Ok(CommandReply::HttpOutput(Box::new(output)))
    }

    pub(super) async fn finalize_http(
        &mut self,
        raw_gid: &str,
        action: &str,
        path: Option<String>,
    ) -> Result<CommandReply, SessionError> {
        let gid = if raw_gid.len() == 16 {
            Gid::from_u64(
                u64::from_str_radix(raw_gid, 16)
                    .map_err(|_| SessionError::failed("Invalid GID"))?,
            )
        } else {
            self.resolve_gid(raw_gid)?
        };
        if action == "hold" {
            if let Some(live) = self
                .running
                .get(&gid)
                .and_then(|task| task.backend.http_live())
                .cloned()
            {
                if live.output.record().is_none() {
                    return Err(SessionError::failed("HTTP data is not ready"));
                }
                self.pause(gid).await?;
                let _drained = live.output.io_gate.lock().await;
            }
            return Ok(CommandReply::Accepted);
        }
        let mut row = self.http_output_row(gid).await?;
        let mut cfg = HttpPersistConfig::from_json(&row.config_json);
        let target = path
            .map(PathBuf::from)
            .or_else(|| {
                cfg.publication
                    .as_ref()
                    .map(|r| r.intent.final_path.clone())
            })
            .unwrap_or_else(|| PathBuf::from(&row.dir).join(&row.out));
        if !target.is_absolute() || target.file_name().is_none() {
            return Err(SessionError::failed(
                "HTTP output path must be an absolute file path",
            ));
        }
        if action != "publish" && action != "external" {
            return Err(SessionError::failed(
                "HTTP finalize action must be publish, external or hold",
            ));
        }
        if cfg
            .publication
            .as_ref()
            .is_some_and(|r| r.phase == PublicationPhase::Published)
        {
            return Ok(CommandReply::Accepted);
        }
        let live = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.http_live())
            .ok_or_else(|| SessionError::failed("HTTP output is paused or not ready"))?;
        let record = live
            .output
            .request(target, action == "external")
            .map_err(SessionError::failed)?;
        // Persist acceptance before waking the driver or answering the host.
        // A lost RPC reply is replayed without running hooks or changing targets.
        if record.phase != PublicationPhase::Ready
            && cfg
                .publication
                .as_ref()
                .is_some_and(|r| r.phase != PublicationPhase::Ready)
        {
            return Ok(CommandReply::Accepted);
        }
        cfg.publication = Some(record.clone());
        row.config_json = cfg.to_json();
        if let Some(persist) = &self.persist {
            persist
                .upsert_http_task(row.clone())
                .await
                .map_err(|e| SessionError::failed(e.to_string()))?;
        }
        if let Some(mirror) = self.running.get(&gid).and_then(|t| t.backend.http_row()) {
            *crate::lock(mirror) = row;
        }
        live.output.set(record);
        live.output.changed.notify_one();
        Ok(CommandReply::Accepted)
    }
}

//! A magnet stays in one task while the host obtains metadata and confirms
//! its output layout. The selection barrier survives restarts and bulk resume.
use super::*;

impl SessionActor {
    pub(super) fn awaiting_torrent_selection(&self, gid: Gid) -> bool {
        matches!(self.jobs.get(&gid), Some(Job::Torrent(_)))
            && self.rows.get(&gid.to_string()).is_some_and(|(row, _)| {
                PersistedTaskConfig::from_json(&row.config_json).selection_pending
            })
    }

    pub(super) fn get_torrent_metadata(&self, raw_gid: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw_gid)?;
        let data = self
            .rows
            .get(&gid.to_string())
            .and_then(|(row, _)| row.metadata.clone())
            .ok_or_else(|| SessionError::failed("torrent metadata is not ready"))?;
        Ok(CommandReply::TorrentMetadata {
            data,
            awaiting_selection: self.awaiting_torrent_selection(gid),
        })
    }

    pub(super) async fn confirm_torrent_selection(
        &mut self,
        raw_gid: &str,
        options: BTreeMap<String, String>,
    ) -> Result<CommandReply, SessionError> {
        if options
            .keys()
            .any(|key| !matches!(key.as_str(), "dir" | "select-file" | "motrix-output-paths"))
        {
            return Err(SessionError::failed("unsupported torrent selection option"));
        }
        let gid = if raw_gid.len() == 16 {
            Gid::from_u64(
                u64::from_str_radix(raw_gid, 16)
                    .map_err(|_| SessionError::failed("invalid task identity"))?,
            )
        } else {
            self.resolve_gid(raw_gid)?
        };
        let mut row = if let Some((row, _)) = self.rows.get(&gid.to_string()) {
            row.clone()
        } else if let Some(persist) = &self.persist {
            persist
                .load_download_result(&gid.to_string())
                .await
                .map_err(|e| SessionError::failed(e.to_string()))?
                .ok_or_else(|| SessionError::failed("torrent metadata is not ready"))?
        } else {
            return Err(SessionError::failed("torrent metadata is not ready"));
        };
        let patch = parse_task_options(&options);
        let dir = patch
            .dir
            .clone()
            .filter(|path| path.is_absolute())
            .ok_or_else(|| SessionError::failed("absolute torrent output directory is required"))?;
        if patch.select_file.is_none() {
            return Err(SessionError::failed(
                "explicit torrent file selection is required",
            ));
        }
        let mut cfg = PersistedTaskConfig::from_json(&row.config_json);
        let directory = dir.display().to_string();
        let requested = Some(
            parse_select_file(patch.select_file.as_deref().unwrap_or_default())
                .map_err(SessionError::failed)?,
        );
        if !cfg.selection_pending {
            let paths = options
                .get("motrix-output-paths")
                .map(|value| serde_json::from_str(value))
                .transpose()
                .map_err(|_| SessionError::failed("invalid torrent output paths"))?
                .unwrap_or_default();
            if cfg.dir == directory && cfg.output_paths == paths && cfg.selected_files == requested
            {
                return Ok(CommandReply::Gid(gid));
            }
            return Err(SessionError::failed(
                "torrent selection was already confirmed",
            ));
        }
        // The pending job already owns verified, unmapped metadata. A replay
        // after confirmation returns above, so the mapping is applied once.
        let mut meta = match self.jobs.get(&gid) {
            Some(Job::Torrent(job)) => (*job.metainfo).clone(),
            _ => return Err(SessionError::failed("torrent metadata is not ready")),
        };
        let paths = super::output_paths::parse(&options, meta.meta.files.len())?;
        super::output_paths::apply(&mut meta, &paths)?;
        let selected = resolve_select_file_for_meta(&patch, &meta.meta)?;
        if selected.as_ref().is_none_or(Vec::is_empty) {
            return Err(SessionError::failed("select at least one torrent file"));
        }
        if !matches!(self.queue.find(gid), Some(Location::ReservedPaused)) {
            return Err(SessionError::failed("torrent selection must be parked"));
        }
        let name = derive_name(&meta.meta);
        if self.torrent_dest_is_occupied(&dir, &name, gid) {
            return Err(Self::dest_conflict_error(&dir, &name));
        }
        cfg.dir = directory;
        cfg.output_paths = paths;
        cfg.selected_files = selected.clone();
        cfg.selection_pending = false;
        row.config_json = cfg.to_json();
        row.state = TaskPhase::Queued.as_v1_str().into();
        let files = file_rows(&row.gid, &meta.meta.files);
        // This acknowledgement is a commit boundary. Never start payload IO
        // or expose new paths if the durable write fails.
        if let Some(persist) = &self.persist {
            persist
                .upsert_torrent(row.clone(), files.clone())
                .await
                .map_err(|e| SessionError::failed(e.to_string()))?;
        }
        self.rows.insert(row.gid.clone(), (row, files));
        if let Some(Job::Torrent(job)) = self.jobs.get_mut(&gid) {
            job.metainfo = Arc::new(meta);
            job.dir = dir;
            job.selected_files = selected;
        }
        self.queue.startup_held.remove(&gid);
        if let Some(entry) = self.queue.reserved_entry_mut(gid) {
            entry.paused = false;
        }
        Ok(CommandReply::Gid(gid))
    }
}

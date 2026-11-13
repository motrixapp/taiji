//! PersistWriter glue: per-task config_json assembly
//! (patch_config/job_config), row writes/transitions/removals
//! (persist_row/transition/refresh/remove), and end-of-life
//! persistence (persist_after_end).
//!
//! Owns: actor-side persistence payload assembly and the serial write
//! entry points (single-writer discipline).
//! Does not own: recovery rebuild (lifecycle::bootstrap), store-layer
//! implementation (taiji-store).

use super::*;

impl SessionActor {
    /// Final persistence after a task ends (called after retire; flags
    /// = pre-retire snapshot):
    /// - remove flag -> DeleteTorrent (decision in [`Self::remove`]);
    /// - pause/restart flag -> paused/queued row (task not terminal);
    /// - natural terminal states: Complete -> done terminal row,
    ///   Error -> error terminal row (error_msg rides with the row) —
    ///   persists the DownloadResult (SPEC §5.3 state set);
    /// - everything else (shutdown-interrupted, classified Removed) ->
    ///   queued row = unfinished task (aria2 saveInProgress semantics:
    ///   resumed after restart, not lost).
    /// - flags = None (forceRemove immediate teardown / late event) ->
    ///   the row was already handled by remove; nothing more to do.
    ///   `upgraded` (magnet upgrade product) refreshes the row content
    ///   first.
    pub(super) async fn persist_after_end(
        &mut self,
        gid: Gid,
        status: StatusKind,
        note: Option<String>,
        flags: Option<(bool, bool, bool)>,
        upgraded: Option<(Arc<Metainfo>, Vec<u8>)>,
    ) {
        let gid_hex = gid.to_string();
        if let Some((meta, torrent)) = upgraded {
            let cfg = self.job_config(&gid);
            let mut row = super::super::persist::torrent_row(
                &gid_hex,
                TaskPhase::Queued,
                self.row_seq(),
                &derive_name(&meta.meta),
                &cfg,
            );
            super::super::persist::fill_torrent_identity(&mut row, &meta, torrent);
            let files = file_rows(&gid_hex, &meta.meta.files);
            // Keep the mirror's existing row state (a pre-upgrade
            // paused/queued state does not drift because of the upgrade).
            if let Some((prev, _)) = self.rows.get(&gid_hex) {
                row.state = prev.state.clone();
            }
            self.persist_row(row, files).await;
        }
        let Some((pause, remove, restart)) = flags else {
            return;
        };
        if remove {
            self.persist_remove_row(gid).await;
            return;
        }
        let state = if pause {
            TaskPhase::Paused
        } else if restart {
            TaskPhase::Queued
        } else {
            match status {
                StatusKind::Complete => TaskPhase::Done,
                StatusKind::Error => TaskPhase::Error,
                // Shutdown interruption (flagless Cancelled->Removed
                // classification): unfinished task.
                StatusKind::Removed | StatusKind::Active => TaskPhase::Queued,
                // Defensive: waiting states never appear in the
                // result-table classification.
                StatusKind::Waiting | StatusKind::Paused => TaskPhase::Queued,
                // Seeding-residence terminal dispatch:
                // the seed-pool teardown routes here with the natural
                // classification (Complete/Error/Removed); the Seeding
                // value itself only rides the waiting projection —
                // defensively persisted as the seeding row state.
                StatusKind::Seeding => TaskPhase::Seeding,
                // War 2: the Checking value rides the waiting
                // projection only (in-flight rechecks project active);
                // defensively persisted as the checking row state.
                StatusKind::Checking => TaskPhase::Checking,
            }
        };
        let Some((row, files)) = self.rows.get_mut(&gid_hex) else {
            return;
        };
        row.state = state.as_v1_str().to_string();
        if state == TaskPhase::Error {
            row.error_msg = note;
        }
        let (row, files) = (row.clone(), files.clone());
        if state.is_terminal() {
            // Persist the DownloadResult = the torrent row's terminal
            // form (the file set is not part of the result write face).
            // Drop the mirror (task is terminal; restart does not
            // rebuild it).
            self.rows.remove(&gid_hex);
            if let Some(p) = &self.persist {
                if let Err(e) = p.insert_download_result(row).await {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                        "download result persist failed");
                }
            }
        } else {
            self.persist_row(row, files).await;
        }
    }

    // ---- persistence assembly / bootstrap / saveSession ----

    /// Monotonic row_seq increments (stable key for torrent-row
    /// queue_pos).
    pub(super) fn row_seq(&mut self) -> i64 {
        self.row_seq += 1;
        self.row_seq
    }

    /// Per-task option patch -> config_json payload (add path; the
    /// activated payload round-trips through [`Self::job_config`]).
    pub(super) fn patch_config(&self, patch: &TaskOptionPatch) -> PersistedTaskConfig {
        PersistedTaskConfig {
            selection_pending: false,
            magnet_flags: None,
            output_paths: Default::default(),
            dir: patch
                .dir
                .clone()
                .unwrap_or_else(|| self.global.dir.clone())
                .display()
                .to_string(),
            seed_ratio: patch.seed_ratio.unwrap_or(self.global.seed_ratio),
            seed_time_min: patch.seed_time_min.unwrap_or(self.global.seed_time_min),
            max_download_limit: patch.max_download_limit.unwrap_or(0),
            max_upload_limit: patch.max_upload_limit.unwrap_or(0),
            // bt-stop-timeout: the patch value wins, falling back to the
            // session global (seed_policy_from uses the same order —
            // one semantic across the add face and the policy
            // projection).
            bt_stop_timeout_secs: patch
                .bt_stop_timeout_secs
                .unwrap_or(self.global.bt_stop_timeout_secs),
            tiers: Vec::new(),
            magnet_uri: None,
            torrent_url: None,
            // Add-face defaults (super-seeding has no RPC option; the
            // selection face is overwritten by each add branch —
            // magnet = the merged so=/select-file winner,
            // addTorrent/.torrent URL = the select-file parsed value).
            super_seeding: false,
            selected_files: None,
            // Add face carries no file priorities; they are established
            // via taiji.setFilePriority or the recovery chain.
            file_priorities: None,
            // Enabled on the add face by default (no RPC option;
            // internal config_json face).
            holepunch: true,
            // Default add-face policy (None = rarest_first, writes no
            // bytes); bt-sequential-download=true projects to
            // sequential (the authoritative face is
            // taiji.setSchedulerPolicy; this key is a compatibility
            // projection).
            scheduler_policy: patch
                .bt_sequential_download
                .and_then(|seq| seq.then_some(crate::engine::SchedulerPolicy::sequential())),
            // No RPC option on the add face (internal config_json face)
            // — default None = throughput tier.
            disk_tier: None,
            // Add-face flag defaults to None = follow the session
            // enable-dht; explicit overrides go through the per-task
            // `bt-disable-dht` option face.
            bt_disable_dht: patch.bt_disable_dht,
            // Add-face switch defaults to None = webseeding on (BEP19;
            // explicit off goes through the per-task
            // `enable-http-seeding` option face).
            enable_http_seeding: patch.enable_http_seeding,
        }
    }

    /// Task payload -> config_json payload (for transition rewrites;
    /// seed_time is stored in minutes, matching the option unit).
    pub(super) fn job_config(&self, gid: &Gid) -> PersistedTaskConfig {
        match self.jobs.get(gid) {
            Some(Job::Torrent(tj)) => PersistedTaskConfig {
                selection_pending: self.rows.get(&gid.to_string()).is_some_and(|(row, _)| {
                    PersistedTaskConfig::from_json(&row.config_json).selection_pending
                }),
                magnet_flags: None,
                output_paths: self
                    .rows
                    .get(&gid.to_string())
                    .map(|(row, _)| PersistedTaskConfig::from_json(&row.config_json).output_paths)
                    .unwrap_or_default(),
                dir: tj.dir.display().to_string(),
                seed_ratio: tj.seed.seed_ratio,
                seed_time_min: tj.seed.seed_time.as_secs_f64() / 60.0,
                max_download_limit: tj.max_download_limit,
                max_upload_limit: tj.max_upload_limit,
                tiers: tj.tiers.clone(),
                magnet_uri: None,
                torrent_url: None,
                // BEP16 switch and BEP53 selection face persist with
                // the task mirror.
                super_seeding: tj.seed.super_seeding,
                selected_files: tj.selected_files.clone(),
                file_priorities: tj.file_priorities.clone(),
                // The switch persists with the task mirror.
                holepunch: tj.holepunch,
                // The policy persists with the task mirror (the default
                // writes no bytes, so existing payloads do not drift).
                scheduler_policy: (tj.scheduler_policy
                    != crate::engine::SchedulerPolicy::default())
                .then_some(tj.scheduler_policy.clone()),
                // The disk tier persists with the task mirror (internal
                // face).
                disk_tier: tj.disk_tier.clone(),
                // The per-task DHT flag persists with the task mirror
                // (None = follow session; the explicit-override/follow
                // distinction survives restart).
                bt_disable_dht: tj.bt_disable_dht,
                // The webseeding switch persists with the task mirror
                // (BEP19; None = on by default).
                enable_http_seeding: tj.enable_http_seeding,
                // bt-stop-timeout persists with the task mirror
                // (SeedPolicy seconds mapped directly — 0 writes no
                // bytes, so existing payloads do not drift).
                bt_stop_timeout_secs: tj.seed.stop_timeout.as_secs(),
            },
            Some(Job::Magnet(mj)) => PersistedTaskConfig {
                selection_pending: self.rows.get(&gid.to_string()).is_some_and(|(row, _)| {
                    PersistedTaskConfig::from_json(&row.config_json).selection_pending
                }),
                magnet_flags: Some(crate::session::persist::PersistedMagnetFlags::from(
                    &mj.options,
                )),
                output_paths: self
                    .rows
                    .get(&gid.to_string())
                    .map(|(row, _)| PersistedTaskConfig::from_json(&row.config_json).output_paths)
                    .unwrap_or_default(),
                dir: mj.dest.display().to_string(),
                seed_ratio: mj.seed.seed_ratio,
                seed_time_min: mj.seed.seed_time.as_secs_f64() / 60.0,
                max_download_limit: mj.max_download_limit,
                max_upload_limit: mj.max_upload_limit,
                tiers: Vec::new(),
                magnet_uri: Some(mj.magnet_uri.clone()),
                torrent_url: None,
                // BEP16 switch mirrors the task; the selection merge has
                // a single point = effective_magnet_selection
                // (select-file option value first, falling back to
                // re-parsing the magnet URI so= — consistent with the
                // upgrade chain's reuse).
                super_seeding: mj.seed.super_seeding,
                selected_files: effective_magnet_selection(mj),
                // No file face during the magnet metadata phase (the
                // torrent task carries it after upgrade).
                file_priorities: None,
                // Preserve the metadata rendezvous policy across restart.
                holepunch: mj.options.holepunch,
                // The scheduling policy mirrors the magnet (carried
                // during the metadata phase, passed through the upgrade
                // chain — projection of the bt-sequential-download
                // option value).
                scheduler_policy: (mj.scheduler_policy
                    != crate::engine::SchedulerPolicy::default())
                .then_some(mj.scheduler_policy.clone()),
                // The tier face belongs to the torrent task (always
                // default in the metadata phase).
                disk_tier: None,
                // The per-task DHT flag mirrors the task and is
                // consumed during the metadata phase — the phase DHT
                // lease gates on the flag, and the engine gets the same
                // value after upgrade.
                bt_disable_dht: mj.bt_disable_dht,
                // The webseeding switch mirrors the task (BEP19; after
                // upgrade the engine applies it at the same point via
                // MagnetTaskConfig.webseeding_enabled).
                enable_http_seeding: mj.enable_http_seeding,
                // bt-stop-timeout persists with the task mirror (same
                // as the torrent branch).
                bt_stop_timeout_secs: mj.seed.stop_timeout.as_secs(),
            },
            Some(Job::TorrentUrl {
                url,
                dir,
                select_file,
                bt_disable_dht,
                enable_http_seeding,
                ..
            }) => PersistedTaskConfig {
                selection_pending: self.rows.get(&gid.to_string()).is_some_and(|(row, _)| {
                    PersistedTaskConfig::from_json(&row.config_json).selection_pending
                }),
                magnet_flags: None,
                output_paths: self
                    .rows
                    .get(&gid.to_string())
                    .map(|(row, _)| PersistedTaskConfig::from_json(&row.config_json).output_paths)
                    .unwrap_or_default(),
                dir: dir.display().to_string(),
                seed_ratio: 0.0,
                seed_time_min: 0.0,
                max_download_limit: 0,
                max_upload_limit: 0,
                tiers: Vec::new(),
                magnet_uri: None,
                torrent_url: Some(url.clone()),
                super_seeding: false,
                // The .torrent URL task's select-file option face (same
                // source as the upgraded TorrentJob.selected_files).
                selected_files: select_file.clone(),
                file_priorities: None,
                // Enabled by default for URL tasks.
                holepunch: true,
                // URL metadata tasks carry no policy face (the torrent
                // task after upgrade does).
                scheduler_policy: None,
                // The tier face belongs to the torrent task.
                disk_tier: None,
                // The flag passes through with the task (same source as
                // the upgraded TorrentJob).
                bt_disable_dht: *bt_disable_dht,
                // The switch passes through with the task (BEP19; same
                // source as the upgraded TorrentJob).
                enable_http_seeding: *enable_http_seeding,
                // .torrent URL tasks have no stop-timeout option face
                // (carried by the upgraded TorrentJob — mirrored by
                // job_config after activation).
                bt_stop_timeout_secs: 0,
            },
            // HTTP task rows live in the http_task table (config_json
            // carried separately) and have no torrent-row payload; this
            // arm exists only for match exhaustiveness (returns the
            // default payload).
            Some(Job::Http(_) | Job::Media(_)) => PersistedTaskConfig {
                selection_pending: self.rows.get(&gid.to_string()).is_some_and(|(row, _)| {
                    PersistedTaskConfig::from_json(&row.config_json).selection_pending
                }),
                magnet_flags: None,
                output_paths: self
                    .rows
                    .get(&gid.to_string())
                    .map(|(row, _)| PersistedTaskConfig::from_json(&row.config_json).output_paths)
                    .unwrap_or_default(),
                dir: self.global.dir.display().to_string(),
                ..PersistedTaskConfig::default()
            },
            None => PersistedTaskConfig {
                selection_pending: self.rows.get(&gid.to_string()).is_some_and(|(row, _)| {
                    PersistedTaskConfig::from_json(&row.config_json).selection_pending
                }),
                magnet_flags: None,
                output_paths: self
                    .rows
                    .get(&gid.to_string())
                    .map(|(row, _)| PersistedTaskConfig::from_json(&row.config_json).output_paths)
                    .unwrap_or_default(),
                dir: self.global.dir.display().to_string(),
                ..PersistedTaskConfig::default()
            },
        }
    }

    /// Persist an http_task row (single PersistWriter; failure only
    /// warns — a lost row write converges on the driver's next
    /// transition/snapshot rewrite).
    pub(super) async fn persist_http_row(&self, row: &taiji_store::persist::HttpTaskRow) {
        if let Some(p) = &self.persist {
            if let Err(e) = p.upsert_http_task(row.clone()).await {
                warn!(target: "taiji::core::session", gid = %row.gid, %e,
                    "http task row persist failed");
            }
        }
    }

    /// Waiting-state row phase (dispatched by task shape: magnet
    /// metadata task = metadata). Returns the unified vocabulary's
    /// enum; the row word serializes only at the write face.
    pub(super) fn reserved_state(&self, gid: Gid) -> TaskPhase {
        match self.jobs.get(&gid) {
            Some(Job::Magnet(_)) => TaskPhase::Metadata,
            // HTTP task row state belongs to the driver/http_task
            // table; no torrent-row mirror -> the transition face is a
            // no-op. The phase only serves UnpauseAll dispatch.
            _ => TaskPhase::Queued,
        }
    }

    /// Persist a row + register the mirror (single PersistWriter;
    /// failure only warns — a lost write converges on the next
    /// transition/saveSession rewrite and does not block the command
    /// face).
    pub(super) async fn persist_row(&mut self, row: TorrentRow, files: Vec<TorrentFileRow>) {
        if let Some(p) = &self.persist {
            if let Err(e) = p.upsert_torrent(row.clone(), files.clone()).await {
                warn!(target: "taiji::core::session", gid = %row.gid, %e,
                    "torrent row persist failed");
            }
        }
        self.rows.insert(row.gid.clone(), (row, files));
    }

    /// State-transition rewrite (update state on the mirror row; no
    /// mirror = never persisted, skip). The phase arrives as the unified
    /// vocabulary's enum and serializes through its canonical table —
    /// the torrent-row write face never sees a raw row word.
    pub(super) async fn persist_transition(&mut self, gid: Gid, phase: TaskPhase) {
        let key = gid.to_string();
        let Some((row, files)) = self.rows.get_mut(&key) else {
            return;
        };
        row.state = phase.as_v1_str().to_string();
        let (row, files) = (row.clone(), files.clone());
        if let Some(p) = &self.persist {
            if let Err(e) = p.upsert_torrent(row, files).await {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "torrent state persist failed");
            }
        }
    }

    /// config_json rewrite (payload sync for changeOption/changeUri;
    /// state unchanged).
    pub(super) async fn persist_refresh_config(&mut self, gid: Gid) {
        if !self.jobs.contains_key(&gid) {
            return;
        }
        let config_json = self.job_config(&gid).to_json();
        let key = gid.to_string();
        let Some((row, files)) = self.rows.get_mut(&key) else {
            return;
        };
        row.config_json = config_json;
        let (row, files) = (row.clone(), files.clone());
        if let Some(p) = &self.persist {
            if let Err(e) = p.upsert_torrent(row, files).await {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "torrent config persist failed");
            }
        }
    }

    /// Row deletion (remove face; the mirror is dropped in step).
    pub(super) async fn persist_remove_row(&mut self, gid: Gid) {
        let gid_hex = gid.to_string();
        self.rows.remove(&gid_hex);
        if let Some(p) = &self.persist {
            if let Err(e) = p.delete_torrent(&gid_hex).await {
                warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                    "torrent row delete failed");
            }
        }
    }

    /// Renumber and persist `queue_pos` across the whole waiting queue.
    /// Two triggers: changePosition reordering (commands.rs
    /// `change_position`) and re-queueing at the front on retirement
    /// (the tasks.rs `retire_and_fire` pause/restart branch, same as
    /// the shutdown drain — queue.rs `retire_active` push_front has
    /// already rewritten the reserved FIFO order; without this rewrite
    /// the recovery order after restart would differ from the running
    /// order at shutdown). Rewrites reserved rows one by one in the
    /// post-reorder FIFO order, with row_seq as the monotonically
    /// increasing key (torrent/magnet/torrent-url mirror rows go to the
    /// torrent table; HTTP waiting-task rows go to the http_task
    /// table) — recovery reads `ORDER BY queue_pos` on keys from one
    /// family-wide source (the bootstrap merge face in lifecycle.rs).
    /// New keys are always strictly greater than every existing key
    /// (the row_seq monotonic-source invariant — bootstrap seeds it
    /// from the global `queue_pos` upper bound in the store, MAX over
    /// the torrent/http tables with terminal rows counted, the
    /// lifecycle::bootstrap seeding segment), so there is zero conflict
    /// with the old keys of active/done rows and the enqueue tail
    /// position for adds after restart is unaffected. Failure only
    /// warns (a lost write converges on the next transition/saveSession
    /// rewrite — same policy as persist_row).
    pub(super) async fn persist_queue_renumber(&mut self) {
        for entry in self.queue.reserved_snapshot() {
            let pos = self.row_seq();
            let gid_hex = entry.gid.to_string();
            // Torrent-family rows (including magnet metadata/torrent-url
            // rows — queue_pos shares the same column and source; the
            // row-level compare always becomes a real write because
            // queue_pos changed; write_torrent TORRENT_CMP_COLS includes
            // queue_pos).
            if let Some((row, files)) = self.rows.get_mut(&gid_hex) {
                row.queue_pos = pos;
                let (row, files) = (row.clone(), files.clone());
                if let Some(p) = &self.persist {
                    if let Err(e) = p.upsert_torrent(row, files).await {
                        warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                            "queue renumber torrent persist failed");
                    }
                }
                continue;
            }
            // HTTP-family rows. Truth-source dispatch: activated =
            // mirror (the driver shares the row mirror, which holds the
            // latest bitmap/final URL/row state — a paused/queued row
            // returning to the front has always been activated and
            // always takes this arm; restore is a bootstrap/add-time
            // snapshot, stale after activation, and writing it would
            // roll the whole progress face back); never activated =
            // restore (the driver has not taken over yet; the row is
            // the add/bootstrap persisted value). The rewrite goes
            // through the mirror so any later snapshot write inherits
            // the new key — the renumber is not lost.
            if let Some(Job::Http(hj)) = self.jobs.get_mut(&entry.gid) {
                // The lock only wraps the rewrite (MutexGuard is !Send —
                // dropped at block exit before the await, so the future
                // stays Send).
                let mirrored = match &hj.mirror {
                    Some(m) => {
                        let mut guard = crate::lock(m);
                        guard.queue_pos = pos;
                        Some(guard.clone())
                    }
                    None => None,
                };
                if let Some(row) = mirrored {
                    self.persist_http_row(&row).await;
                } else if let Some(row) = hj.restore.as_mut() {
                    row.queue_pos = pos;
                    let row = row.clone();
                    self.persist_http_row(&row).await;
                }
            }
        }
    }
}

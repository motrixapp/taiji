//! Session lifecycle: startup bootstrap (rebuilding from active rows in
//! the store + GID reserve; 'checking' rows batch-admit into
//! check_pending), saveSession / exportEntries, graceful shutdown
//! (shutdown_routine: token-hierarchy propagation + drain budget), and
//! the stop-family hook events.
//!
//! Owns: session-level startup/shutdown/export orchestration.
//! Does not own: per-task activation/retirement (tasks), row-write
//! details (persist).
//!
//! Upstream anchor mapping: docs/design/core.md

use super::*;
use crate::session::queue::RetireOutcome;

fn requeued_paused(outcome: RetireOutcome) -> Option<bool> {
    match outcome {
        RetireOutcome::Requeued { paused } => Some(paused),
        RetireOutcome::RequeuedUnpauseSuperseded => Some(false),
        RetireOutcome::Result => None,
    }
}

impl SessionActor {
    /// Startup bootstrap: PersistWriter ready -> LoadTorrentsAtStartup
    /// -> rebuild row by row from the active rows. GID reserve dedups
    /// across restarts; rows + file rows enter the mirror (reused by
    /// the transfer face); a parseable metadata BLOB -> torrent payload
    /// (queued/paused follow the row state); missing/unparseable -> if
    /// magnet_uri is known, rebuild to the metadata state and re-run
    /// ut_metadata, otherwise degrade to an error result row (never
    /// disguised as recoverable). Bitmap/count restoration lives
    /// engine-side (after the persist injection, spawn reads back the
    /// totals and bitmaps); the `--bt-hash-check-seed` forced-recheck
    /// entry point (checking re-entry) hangs off this path.
    pub(super) async fn bootstrap(&mut self) {
        let Some(persist) = self.persist.clone() else {
            return;
        };
        // Unified-table cookie startup GC: sweep the
        // crash-window residue — orphan rows (no task row; the paired
        // delete's missing half) and terminal residue (task row already
        // done/error when the crash ate the runtime terminal clear).
        // Error-form groups re-emit the bypass alert here (the
        // runtime emission died with the crash); done-form + orphans
        // feed the log. The sweep is idempotent and never touches
        // active rows (both pinned by the store-side tests).
        match persist.sweep_task_cookies().await {
            Ok(report) => {
                if report.orphaned > 0 || report.done_cleared > 0 {
                    info!(target: "taiji::core::session",
                        orphaned = report.orphaned,
                        done_cleared = report.done_cleared,
                        "task cookie startup GC: crash-window residue cleared");
                }
                for entry in &report.error_cleared {
                    if let Ok(raw) = u64::from_str_radix(&entry.gid, 16) {
                        let _ = self
                            .cookie_bus
                            .send(crate::session::events::TaskCookieEvent {
                                gid: Gid::from_u64(raw),
                                // The unified table's kind domain is
                                // 'http'|'media'; the payload's
                                // &'static str face takes the literal.
                                task_kind: match entry.task_kind.as_str() {
                                    taiji_store::persist::TASK_KIND_MEDIA => {
                                        taiji_store::persist::TASK_KIND_MEDIA
                                    }
                                    _ => taiji_store::persist::TASK_KIND_HTTP,
                                },
                                count: entry.count.max(0) as u64,
                            });
                        warn!(target: "taiji::core::session", gid = %entry.gid,
                            task_kind = %entry.task_kind, count = entry.count,
                            "startup GC cleared error-terminal cookie residue; \
                             alert re-emitted");
                    }
                }
            }
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "task cookie startup GC failed (residue stays; next \
                     startup retries — idempotent)");
            }
        }
        // row_seq seeding (one monotonic key across restarts): continue
        // from the global upper bound of in-store `queue_pos` (MAX over
        // the torrent table in all states + the http_task table;
        // final-state row keys are counted). Without this seed, row_seq
        // restarts at 1 each process: changePosition renumbering ->
        // restart -> a newly added task's key is always smaller than
        // every renumbered recovery key, so on the second restart the
        // new task deterministically sorts to the queue head (recovery
        // order != last run's queue order, which breaks the stable-key
        // premise of the key-ordered reserved sequencing below). On
        // read failure, skip the seed (same as the old per-process
        // recount — an honest degradation, not a fake monotonicity).
        match persist.load_max_queue_pos().await {
            Ok(seed) => self.row_seq = self.row_seq.max(seed),
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "startup queue_pos seed read failed (row_seq continues unseeded)");
            }
        }
        let snaps = match persist.load_torrents_at_startup().await {
            Ok(s) => s,
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "startup torrent load failed (treated as fresh session)");
                return;
            }
        };
        // Enqueue bookkeeping merged across task families (recovery
        // queue order stays ordered across families): the torrent/http
        // read faces each order by queue_pos, cross-family keys come
        // from the same row_seq, and one merged enqueue means the queue
        // order no longer drifts with the "torrents first, then http"
        // rebuild order.
        let mut reserved: Vec<(i64, Gid, bool)> = Vec::new();
        // 'seeding'-state rows routed to the seed side by the measured
        // bitmap (the observation counter for the restart-routing log).
        let mut seeded_restarts = 0usize;
        // 'checking'-state rows batch-admitted into the check pool's
        // waiting FIFO (the check pool; the observation counter for the
        // bootstrap log — the admission count meter).
        let mut checked_restarts = 0usize;
        let total = snaps.len();
        for snap in snaps {
            let mut row = snap.row;
            let gid_hex = row.gid.clone();
            let Ok(raw_gid) = u64::from_str_radix(&gid_hex, 16) else {
                warn!(target: "taiji::core::session", gid = %gid_hex,
                    "startup row has malformed gid; skipped");
                continue;
            };
            let gid = Gid::from_u64(raw_gid);
            // GID reserve (cross-restart dedup): a fresh allocation
            // never collides with a restored GID.
            self.gid.reserve(raw_gid);
            let cfg = PersistedTaskConfig::from_json(&row.config_json);
            let paused = row.state == "paused";
            match self.rebuild_from_row(&gid, &row, &cfg).await {
                Rebuilt::Torrent(boxed) => {
                    let (metainfo, tiers) = *boxed;
                    let meta = Arc::new(metainfo);
                    let total_len = meta.meta.total_len();
                    let dir = PathBuf::from(&cfg.dir);
                    // checking-state re-entry (the check-pool routing): row
                    // state 'checking' = the bitmap is not trusted
                    // (importer degradation / user marker / a recheck
                    // interrupted by restart), so recovery re-verifies
                    // on disk. **Batch admission into check_pending —
                    // no per-row serial await** (the former inline
                    // startup_recheck blocked bootstrap for the sum of
                    // the verify times and delayed RPC service).
                    // Promotion = the check budget (pump_check drives;
                    // the run loop's first pump_all after bootstrap
                    // promotes up to max-concurrent-checks immediately).
                    // The row keeps 'checking' (the state covers
                    // pending and in-flight alike — the pre-war
                    // precedent); finish_recheck writes the measured
                    // bitmap back and advances the row (queued/paused)
                    // + routes per the bitmap (seed side when full).
                    if row.state == "checking" {
                        self.queue.insert_check_pending(gid, false);
                        checked_restarts += 1;
                    }
                    // Top-level attributes restored from the in-store
                    // metadata BLOB (the bittorrent dict source
                    // survives restarts).
                    let attrs_top = row
                        .metadata
                        .as_deref()
                        .map(torrent_top_attrs)
                        .unwrap_or((None, None, None));
                    self.jobs.insert(
                        gid,
                        Job::Torrent(Box::new(TorrentJob {
                            metainfo: Arc::clone(&meta),
                            tiers,
                            dir,
                            seed: SeedPolicy {
                                // Out-of-domain seed_ratio drops the
                                // condition (warn + 0, matching the
                                // seed_time shape below): config_json
                                // values are not protected by the
                                // option-parsing face — a non-finite /
                                // negative value passing through would
                                // seed forever or silently swallow the
                                // condition; the write faces filter,
                                // this is the fallback for poisoned
                                // rows / legacy databases.
                                seed_ratio: checked_seed_ratio(cfg.seed_ratio).unwrap_or_else(
                                    || {
                                        warn!(target: "taiji::core::session", gid = %gid_hex,
                                            seed_ratio = cfg.seed_ratio,
                                            "startup seed_ratio out of range; \
                                             seed ratio condition dropped");
                                        0.0
                                    },
                                ),
                                // config_json values are not protected
                                // by the option-parsing face (poisoned
                                // rows / legacy databases): an
                                // out-of-domain seed time drops the
                                // condition (warn + ZERO) and the row
                                // is still restored — no panic
                                // (otherwise every restart replays the
                                // panic = crash loop, all RPC sessions
                                // closed).
                                seed_time: seed_duration_from_minutes(cfg.seed_time_min)
                                    .unwrap_or_else(|| {
                                        warn!(target: "taiji::core::session", gid = %gid_hex,
                                            seed_time_min = cfg.seed_time_min,
                                            "startup seed_time_min out of range; \
                                             seed time condition dropped");
                                        std::time::Duration::ZERO
                                    }),
                                // bt-stop-timeout: config_json
                                // task-face mirror back-fill (0 = never
                                // stop — same as the aria2 default; the
                                // u64 seconds domain has no poisoning
                                // face).
                                stop_timeout: std::time::Duration::from_secs(
                                    cfg.bt_stop_timeout_secs,
                                ),
                                detach_seed_only: self.global.bt_detach_seed_only,
                                // config_json internal face restored
                                // (BEP16 switch, default off — the
                                // recovery chain passes it through
                                // unchanged).
                                super_seeding: cfg.super_seeding,
                            },
                            total_len,
                            attrs_top,
                            max_download_limit: cfg.max_download_limit,
                            max_upload_limit: cfg.max_upload_limit,
                            hooks: Arc::new(self.global.hooks.clone()),
                            // BEP53 selection face restored from
                            // config_json.
                            selected_files: cfg.selected_files.clone(),
                            // Per-file priority face restored from
                            // config_json (None = default face).
                            file_priorities: cfg.file_priorities.clone(),
                            // config_json internal face restored
                            // (enabled by default; the recovery chain
                            // passes it through unchanged).
                            holepunch: cfg.holepunch,
                            // config_json internal face restored
                            // (default rarest_first; the recovery chain
                            // passes it through unchanged).
                            scheduler_policy: cfg.scheduler_policy.unwrap_or_default(),
                            // Disk tier override restored (internal
                            // face, passed through unchanged; None =
                            // the default throughput tier).
                            disk_tier: cfg.disk_tier.clone(),
                            // Per-task DHT flag restored (None =
                            // follow the session — the recovery chain
                            // passes it through unchanged).
                            bt_disable_dht: cfg.bt_disable_dht,
                            // Web-seeding switch restored (BEP19; None
                            // = default on — the recovery chain
                            // passes it through unchanged).
                            enable_http_seeding: cfg.enable_http_seeding,
                        })),
                    );
                    // 'seeding'-state restart routing (the seed pool,
                    // §4.1.4): the row-state extension that keeps
                    // seeding residence across restarts (covering
                    // seed_wait members too — the 'checking' covers
                    // pending+in-flight precedent). The measured bitmap
                    // decides the branch:
                    // - full → the seed side: park into seed_wait; the
                    // first pump_all promotes as many as the seed
                    // budget admits (full + slot → seeding registry,
                    // seed-slot engine spawn; full + budget full →
                    // stays parked — no download slot touched either
                    // way);
                    // - not full → the download side: the waiting queue
                    // with a 'queued' row (the same rewrite the
                    // checking arm does — the seeding state no
                    // longer applies).
                    // The engine-assembly window of a promoted member
                    // occupies a seed slot only (activate_seed); the
                    // known boundary (a download slot held before
                    // SeedingStarted) exists only on the download
                    // side, which full bitmaps never take.
                    let seed_side = if row.state == "seeding" {
                        let progress = match &self.persist {
                            Some(p) => p.load_torrent_progress(&gid_hex).await.ok().flatten(),
                            None => None,
                        };
                        let complete = progress
                            .as_ref()
                            .is_some_and(|pr| progress_row_complete(&meta.meta, pr));
                        if complete {
                            seeded_restarts += 1;
                            true
                        } else {
                            // Not full (or no measured bitmap): the
                            // download side takes the row with the
                            // seeding state rewritten away.
                            row.state = "queued".to_string();
                            if let Some(persist) = &self.persist {
                                if let Err(e) = persist
                                    .upsert_torrent(row.clone(), snap.files.clone())
                                    .await
                                {
                                    warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                                        "seeding→queued row state persist failed");
                                }
                            }
                            false
                        }
                    } else {
                        false
                    };
                    if seed_side {
                        // Row stays 'seeding' (the mirror registration
                        // after the match carries it into saveSession
                        // unchanged).
                        self.queue.push_seed_wait(gid);
                    } else if row.state == "checking" {
                        // War 2: parked above — the row mirror keeps
                        // 'checking'; not a reserved member (the
                        // post-recheck requeue comes from finish_recheck).
                    } else {
                        reserved.push((row.queue_pos, gid, paused));
                    }
                }
                Rebuilt::Magnet(magnet_uri) => {
                    // announceList source = magnet `tr` rebuild (same
                    // shape as add_uri's tr_tiers; a parse failure
                    // degrades to an empty table).
                    let tr_tiers: Vec<(usize, String)> = taiji_bt::magnet::parse(&magnet_uri)
                        .map(|m| {
                            m.tr.iter()
                                .enumerate()
                                .map(|(i, t)| (i, String::from_utf8_lossy(t).into_owned()))
                                .collect()
                        })
                        .unwrap_or_default();
                    self.jobs.insert(
                        gid,
                        Job::Magnet(Box::new(MagnetJob {
                            magnet_uri,
                            dest: PathBuf::from(&cfg.dir),
                            options: MagnetOptions::default(),
                            seed: SeedPolicy {
                                // Out-of-domain seed_ratio drops the
                                // condition (same as the Torrent arm
                                // above; fallback for poisoned rows /
                                // legacy databases).
                                seed_ratio: checked_seed_ratio(cfg.seed_ratio).unwrap_or_else(
                                    || {
                                        warn!(target: "taiji::core::session", gid = %gid_hex,
                                            seed_ratio = cfg.seed_ratio,
                                            "startup seed_ratio out of range; \
                                             seed ratio condition dropped");
                                        0.0
                                    },
                                ),
                                // Out-of-domain seed time drops the
                                // condition (same as the Torrent arm
                                // above; bootstrap replay does not
                                // panic).
                                seed_time: seed_duration_from_minutes(cfg.seed_time_min)
                                    .unwrap_or_else(|| {
                                        warn!(target: "taiji::core::session", gid = %gid_hex,
                                            seed_time_min = cfg.seed_time_min,
                                            "startup seed_time_min out of range; \
                                             seed time condition dropped");
                                        std::time::Duration::ZERO
                                    }),
                                // bt-stop-timeout: config_json
                                // task-face mirror back-fill (same as
                                // the torrent arm).
                                stop_timeout: std::time::Duration::from_secs(
                                    cfg.bt_stop_timeout_secs,
                                ),
                                detach_seed_only: self.global.bt_detach_seed_only,
                                // config_json internal face restored
                                // (BEP16 switch).
                                super_seeding: cfg.super_seeding,
                            },
                            btih: row.v1_infohash.clone().and_then(|b| b.try_into().ok()),
                            btmh: row.v2_infohash.clone().and_then(|b| b.try_into().ok()),
                            tiers: tr_tiers,
                            // BEP53 selection face restored from
                            // config_json (the select-file option value
                            // or the so= projection — back-filled at
                            // the job_config merge single point; the
                            // upgrade chain passes it through
                            // MagnetTaskConfig).
                            selected_files: cfg.selected_files.clone(),
                            // Scheduler policy restored (passed through
                            // the upgrade chain).
                            scheduler_policy: cfg.scheduler_policy.clone().unwrap_or_default(),
                            max_download_limit: cfg.max_download_limit,
                            max_upload_limit: cfg.max_upload_limit,
                            hooks: Arc::new(self.global.hooks.clone()),
                            upgraded: false,
                            // Per-task DHT flag restored (None =
                            // follow the session — the recovery chain
                            // passes it through unchanged).
                            bt_disable_dht: cfg.bt_disable_dht,
                            // Web-seeding switch restored (BEP19; None
                            // = default on — the recovery chain passes
                            // it through unchanged).
                            enable_http_seeding: cfg.enable_http_seeding,
                        })),
                    );
                    reserved.push((row.queue_pos, gid, paused));
                }
                Rebuilt::Unrecoverable(reason) => {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %reason,
                        "startup row unrecoverable; recorded as error result");
                    let mut err_row = row;
                    err_row.state = "error".to_string();
                    err_row.error_msg = Some(reason);
                    if let Err(e) = persist.insert_download_result(err_row).await {
                        warn!(target: "taiji::core::session", gid = %gid_hex, %e,
                            "error result persist failed");
                    }
                    continue;
                }
            }
            // Mirror registration (reused by the transfer face; file
            // rows ride with the snapshot).
            self.rows.insert(gid_hex, (row, snap.files));
        }
        if total > 0 {
            info!(target: "taiji::core::session", restored = total,
                "session bootstrap: active torrents restored (GID reserved)");
        }
        if seeded_restarts > 0 {
            info!(target: "taiji::core::session", seeded = seeded_restarts,
                "session bootstrap: seeding-resident rows routed to the seed side \
                 (measured-bitmap full; activation within max-concurrent-seeds)");
        }
        if checked_restarts > 0 {
            info!(target: "taiji::core::session", checking = checked_restarts,
                "session bootstrap: checking rows batch-admitted into check_pending \
                 (verification within max-concurrent-checks; no per-row serial await)");
        }
        // HTTP task row rebuild (http_task table; the bitmap recovery
        // face lives in the driver activation chain: probe -> recover
        // second line of defense -> bitmap resume) + renamePending
        // on-disk close-out (unclosed rows enter the in-process polling
        // registry).
        let http_reserved = self.bootstrap_http().await;
        reserved.extend(http_reserved);
        // Media task rows (§8 recovery): phase re-entry + the
        // staging startup GC linkage (the orphan-gid sweep runs on
        // the observed roots before activation).
        let media_reserved = self.bootstrap_media().await;
        reserved.extend(media_reserved);
        reserved.sort_by_key(|(pos, _, _)| *pos);
        for (_, gid, paused) in reserved {
            self.queue
                .insert_reserved(ReservedEntry { gid, paused }, None);
        }
    }

    /// HTTP task bootstrap: active rows read back -> Job::Http rebuild +
    /// GID reserve + enqueue (paused rows stay paused; the rest wait
    /// for activation). The restore-trust decision is not made here
    /// (bitmap / size validation settles during driver activation on
    /// then-current probe facts); the row mirror rides with the Job
    /// (the remove/pause faces share the same source). Returns the
    /// merged enqueue bookkeeping `(queue_pos, gid, paused)` (order
    /// preserved across task families; see [`Self::bootstrap`]).
    pub(super) async fn bootstrap_http(&mut self) -> Vec<(i64, Gid, bool)> {
        let Some(persist) = self.persist.clone() else {
            return Vec::new();
        };
        // renamePending startup close-out: done+pending rows read back
        // -> idempotent on-disk close-out (`.part` rename / final file
        // already in place clears the account); rows still unclosed
        // enter the in-process polling registry (periodic retry until
        // closed or the task is removed).
        match persist.load_http_done_rows().await {
            Ok(rows) => {
                let mut pending = 0usize;
                let mut closed = 0usize;
                for row in rows {
                    let cfg = crate::session::actor::http_task::HttpPersistConfig::from_json(
                        &row.config_json,
                    );
                    if !cfg.rename_pending {
                        continue;
                    }
                    if http_task::close_out_pending_row(&self.persist, &row).await {
                        closed += 1;
                    } else {
                        pending += 1;
                        if let Ok(raw) = u64::from_str_radix(&row.gid, 16) {
                            self.http_rename_pending
                                .insert(Gid::from_u64(raw), row.clone());
                        }
                    }
                }
                if closed > 0 || pending > 0 {
                    info!(target: "taiji::core::session", closed, pending,
                        "startup renamePending close-out sweep");
                }
            }
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "startup http done-row load failed (renamePending close-out skipped)");
            }
        }
        let snaps = match persist.load_http_tasks_at_startup().await {
            Ok(s) => s,
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "startup http task load failed (treated as fresh set)");
                return Vec::new();
            }
        };
        let mut reserved: Vec<(i64, Gid, bool)> = Vec::new();
        for snap in snaps {
            let row = snap.row;
            let gid_hex = row.gid.clone();
            let Ok(raw_gid) = u64::from_str_radix(&gid_hex, 16) else {
                warn!(target: "taiji::core::session", gid = %gid_hex,
                    "startup http row has malformed gid; skipped");
                continue;
            };
            let gid = Gid::from_u64(raw_gid);
            // GID reserve (cross-restart dedup, same pool as torrent).
            self.gid.reserve(raw_gid);
            let paused = row.state == "paused";
            let queue_pos = row.queue_pos;
            // Concurrency-intent face replay: the split/cap effective
            // values frozen into the row at creation override the
            // session defaults — a restored activation assembles the
            // same starting concurrency (`AimdConfig::with_start` /
            // `WorkerPool::with_start` + 5ms source-rotation waves), so
            // a kill-9 resume no longer degrades to a single connection
            // at the default cap of 1. Old/imported rows without the
            // face = None -> the new session defaults (intent that was
            // not recorded is not fabricated — honest degradation).
            let mut opts = http_task::HttpTaskOpts::default();
            if let Some(face) =
                http_task::HttpPersistConfig::from_json(&row.config_json).concurrency
            {
                face.apply_to(&mut opts);
            }
            self.jobs.insert(
                gid,
                Job::Http(Box::new(HttpJob {
                    // Multi-source restore expansion: mirrors_json (the
                    // multi-URI list persisted with the row at add
                    // time) restores the same-origin set; a missing or
                    // corrupt payload -> single-source fallback (the
                    // row url column is always first).
                    uris: http_task::uris_from_mirrors(row.mirrors_json.as_deref(), &row.url),
                    dir: PathBuf::from(&row.dir),
                    out: (!row.out.is_empty()).then(|| row.out.clone()),
                    max_download_limit: 0,
                    max_upload_limit: 0,
                    hooks: Arc::new(self.global.hooks.clone()),
                    // Runtime option faces are not stored — identity
                    // faces (timeouts / credentials / proxy) rebuild
                    // from new-session defaults; the concurrency-intent
                    // face is the narrow exception, replayed from the
                    // row above.
                    opts,
                    restore: Some(row),
                    mirror: None,
                    // Restore replay: the task's cookie set rides with
                    // the snapshot into the Job.
                    cookies: snap.cookies,
                    // bootstrap rebuild = empty seed: the cookie file
                    // source is not re-read across restarts; restore
                    // replays from the persisted cookie rows.
                    cookie_seed: Vec::new(),
                    submitted: std::time::Instant::now(),
                })),
            );
            reserved.push((queue_pos, gid, paused));
        }
        if !reserved.is_empty() {
            info!(target: "taiji::core::session", restored = reserved.len(),
                "session bootstrap: active http tasks restored (GID reserved)");
        }
        reserved
    }

    /// In-process periodic polling for renamePending: retries the
    /// on-disk close-out for registered tasks that are not active (the
    /// journal list inside the driver is consumed by finalize
    /// immediately; this face covers the "closable only after finalize"
    /// window — the conflicting file was moved away, a network drive
    /// came back, etc.). A successful close-out removes the entry.
    pub(super) async fn poll_rename_pending(&mut self) {
        if self.http_rename_pending.is_empty() {
            return;
        }
        let gids: Vec<Gid> = self.http_rename_pending.keys().copied().collect();
        for gid in gids {
            // Active/queued tasks are not raced (the driver or the next
            // activation face owns them).
            if self.running.contains_key(&gid) || self.jobs.contains_key(&gid) {
                continue;
            }
            let Some(row) = self.http_rename_pending.get(&gid) else {
                continue;
            };
            if http_task::close_out_pending_row(&self.persist, row).await {
                self.http_rename_pending.remove(&gid);
            }
        }
    }

    /// Single-row rebuild dispatch: a parseable metadata BLOB -> torrent
    /// payload; otherwise a known magnet URI -> metadata-state re-run;
    /// neither -> unrecoverable.
    pub(super) async fn rebuild_from_row(
        &self,
        gid: &Gid,
        row: &TorrentRow,
        cfg: &PersistedTaskConfig,
    ) -> Rebuilt {
        if let Some(bytes) = &row.metadata {
            let parsed = {
                let bytes = bytes.clone();
                tokio::task::spawn_blocking(move || Metainfo::parse(&bytes)).await
            };
            match parsed {
                Ok(Ok(meta)) => {
                    let tiers = if cfg.tiers.is_empty() {
                        single_tier_from_announce(&meta.announce)
                    } else {
                        cfg.tiers.clone()
                    };
                    return Rebuilt::Torrent(Box::new((meta, tiers)));
                }
                Ok(Err(e)) => {
                    warn!(target: "taiji::core::session", gid = %gid, %e,
                        "startup metadata unparseable; falling back to metadata state");
                }
                Err(e) => {
                    warn!(target: "taiji::core::session", gid = %gid, %e,
                        "startup metadata parse join failed");
                }
            }
        }
        match &cfg.magnet_uri {
            Some(uri) => Rebuilt::Magnet(uri.clone()),
            None => Rebuilt::Unrecoverable(format!(
                "no metadata and no magnet uri (state '{}', SPEC §5.4 metadata fallback unavailable)",
                row.state
            )),
        }
    }

    /// saveSession (per the SessionSerializer.cc save semantics):
    /// 1) full task-row flush (the mirror is rewritten from the current
    ///    state; row-level comparison absorbs no-op writes); HTTP task-row
    ///    mirrors flush in sync (the compatibility method promises a full
    ///    persist — progress deltas inside the driver's 2s debounce window
    ///    are closed out here; state columns follow the mirror's current
    ///    value, while Completed/failed terminal rows are written by the
    ///    finalize path and not duplicated);
    /// 2) `--save-session` text export (input-file compatible, atomic
    ///    write via `__temp` + rename; metainfo tasks have no URI to write
    ///    -> skipped, same rule as SessionSerializer.cc);
    /// 3) disk barrier + `wal_checkpoint(TRUNCATE)` — the single write
    ///    connection's serialization guarantees all earlier write jobs
    ///    have committed; WAL semantics: a commit is durable (replay
    ///    recovery after kill), checkpoint is file shrinking, not a
    ///    durability condition (synchronous=NORMAL).
    ///
    /// Declared deviation: no aria2 session-file format is produced
    /// (sqlite is the single source of truth; the `--save-session` text
    /// export is an optional extra face).
    pub(super) async fn save_session(&mut self) -> Result<(), SessionError> {
        let Some(persist) = self.persist.clone() else {
            return Err(SessionError::failed(
                "saveSession: session storage is not enabled",
            ));
        };
        // 1) Full task-row flush.
        let rows: Vec<(TorrentRow, Vec<TorrentFileRow>)> = self.rows.values().cloned().collect();
        for (row, files) in rows {
            persist
                .upsert_torrent(row, files)
                .await
                .map_err(|e| SessionError::failed(format!("saveSession persist failed: {e}")))?;
        }
        // 1b) HTTP task-row mirror flush (active/waiting task mirrors =
        // the current row truth; the driver may still advance after the
        // snapshot — its debounced write then overwrites, losslessly).
        for job in self.jobs.values() {
            if let Job::Http(hj) = job {
                let row = match &hj.mirror {
                    Some(m) => crate::lock(m).clone(),
                    // Not-yet-activated task = the row registered at
                    // add time (held by restore).
                    None => match &hj.restore {
                        Some(r) => r.clone(),
                        None => continue,
                    },
                };
                persist.upsert_http_task(row).await.map_err(|e| {
                    SessionError::failed(format!("saveSession persist failed: {e}"))
                })?;
            }
        }
        // 2) Text export (--save-session).
        if let Some(path) = self.global.save_session.clone() {
            let text = serialize_export(&self.export_entries());
            let write = tokio::task::spawn_blocking(move || {
                // SessionSerializer.cc: write the whole file to
                // filename + "__temp", then atomically replace via
                // renameTo.
                let temp = {
                    let mut p = path.clone().into_os_string();
                    p.push("__temp");
                    std::path::PathBuf::from(p)
                };
                std::fs::write(&temp, text.as_bytes())?;
                // The export text carries cookie/credential lines —
                // restrict the temp file to 0600 before rename (rename
                // keeps the inode permissions; unix-only, other
                // platforms keep the fs::write default).
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600));
                }
                std::fs::rename(&temp, &path)?;
                Ok::<(), std::io::Error>(())
            })
            .await;
            match write {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    return Err(SessionError::failed(format!(
                        "saveSession text export failed: {e}"
                    )));
                }
                Err(e) => {
                    return Err(SessionError::failed(format!(
                        "saveSession export join failed: {e}"
                    )));
                }
            }
        }
        // 3) Disk barrier + WAL checkpoint.
        persist
            .checkpoint()
            .await
            .map_err(|e| SessionError::failed(format!("saveSession checkpoint failed: {e}")))?;
        Ok(())
    }

    /// Text-export entry collection (magnet metadata URIs / .torrent
    /// URL tasks; metainfo tasks have no URI -> skipped, same "no URIs"
    /// rule as SessionSerializer.cc — such tasks are carried by the
    /// sqlite rows).
    pub(super) fn export_entries(&self) -> Vec<SessionExportEntry> {
        let mut out = Vec::new();
        for (gid, job) in &self.jobs {
            let (uri, metadata_style) = match job {
                Job::Magnet(mj) => (mj.magnet_uri.clone(), true),
                Job::TorrentUrl { url, .. } => (url.clone(), false),
                // HTTP task = first source URI (input-file compatible
                // shape; multi-source expansion belongs to the
                // http_task row restore face).
                Job::Http(hj) => (hj.uris.first().cloned().unwrap_or_default(), false),
                // Media task = the entry URL (the session-export text
                // face; the media_task row carries the full payload).
                Job::Media(mj) => (mj.cfg.url.clone(), false),
                Job::Torrent(_) => continue,
            };
            let dir = match job {
                Job::Http(hj) => hj.dir.display().to_string(),
                Job::Media(mj) => mj.cfg.output_dir.display().to_string(),
                _ => self
                    .rows
                    .get(&gid.to_string())
                    .map(|(r, _)| r.dir.clone())
                    .unwrap_or_default(),
            };
            let paused = self
                .queue
                .reserved_entry(*gid)
                .map(|e| e.paused)
                .unwrap_or(false);
            out.push(SessionExportEntry {
                uri,
                metadata_style,
                gid_hex: gid.to_string(),
                dir,
                paused,
            });
        }
        out
    }

    /// The shutdown drain's terminal-cookie close-out hook: on the
    /// done/error terminals, clear the task's cookie rows through the
    /// same [`Self::terminal_cookie_closeout`] face
    /// the running path uses — the retired graceful-shutdown sweep
    /// (which waited for the 24h register) no longer exists; a task
    /// that finished inside the drain window settles its cookies now,
    /// the startup GC only backstops the crash window.
    async fn shutdown_cookie_closeout(&mut self, gid: Gid, status: StatusKind) {
        if !matches!(status, StatusKind::Complete | StatusKind::Error) {
            return;
        }
        let kind = match self.jobs.get(&gid) {
            Some(Job::Http(_)) => Some(taiji_store::persist::TASK_KIND_HTTP),
            Some(Job::Media(_)) => Some(taiji_store::persist::TASK_KIND_MEDIA),
            _ => None,
        };
        if let Some(kind) = kind {
            self.terminal_cookie_closeout(gid, kind, status == StatusKind::Error)
                .await;
        }
    }

    /// Shutdown: cancel the root token (hierarchical propagation) ->
    /// wait for running tasks to exit (within the drain budget).
    ///
    /// Observation face: each phase logs its latency at its completion
    /// point (drain / disk save / NAT teardown) — the info-level phase
    /// logs are the observation input for the shutdown budget;
    /// consumers are shutdown phase profiles and slow-shutdown
    /// diagnostics.
    pub(super) async fn shutdown_routine(&mut self) {
        let shutdown_started = std::time::Instant::now();
        info!(target: "taiji::core::session",
            running = self.running.len(),
            waiting = self.queue.reserved_snapshot().len(),
            "session shutdown: propagating to running tasks");
        self.token.cancel();
        let deadline = tokio::time::Instant::now() + TORRENT_DRAIN_TIMEOUT;
        while !self.running.is_empty() {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            match tokio::time::timeout_at(deadline, self.event_rx.recv()).await {
                Ok(Some(TaskNotice::Ended { gid, outcome })) => {
                    // Seed-pool bookkeeping first: a
                    // seeding resident / budget-parked stop landing inside
                    // the shutdown window keeps its 'seeding' row (the
                    // restart face routes it back); consumed here — no
                    // retire processing, no fillup (shutting down).
                    if self.shutdown_seed_dispatch(gid).await {
                        continue;
                    }
                    // Synthesis-pool bookkeeping next: a
                    // gate-hung / synthesizing media task ending inside
                    // the shutdown window keeps its row at the driver's
                    // last phase write ('downloading' for the gate hang —
                    // the Processing row write only happens after the
                    // permit); no proc_wait-specific row state exists and
                    // no proc_wait position persists (§4.3) — the restart
                    // re-walks Resolving → Downloading (idempotent) →
                    // gate and re-parks. Consumed here — no retire
                    // processing, no fillup (shutting down).
                    if self.shutdown_synthesis_dispatch(gid) {
                        continue;
                    }
                    // Bookkeeping only (no fillup — shutting down).
                    // Finalization rows are persisted with the task (a
                    // flagless Cancelled -> incomplete queued row,
                    // resumed after restart).
                    let total = self
                        .running
                        .get(&gid)
                        .map(|t| t.total_len)
                        .unwrap_or_default();
                    let (status, completed, _) = ended_classification(&outcome, total);
                    let flags = self.queue.active_flags(gid);
                    // Terminal cookie close-out: a
                    // task finishing done/error inside the shutdown
                    // window clears its cookies here too — the retired
                    // shutdown sweep no longer exists, and the startup
                    // GC is only the crash backstop.
                    self.shutdown_cookie_closeout(gid, status).await;
                    let requeued = self.retire_and_fire(gid, status, total, completed, None, None);
                    self.persist_after_end(gid, status, None, flags, None).await;
                    // Finalizations with a pause/restart suspended
                    // inside the shutdown window also re-enter at the
                    // queue head — the key rewrite shares the same
                    // closure as the running path (handle_ended;
                    // saveSession's checkpoint comes after, so the
                    // order holds).
                    // A delayed forceRecheck registration in the active
                    // domain ties in on the same face: row state
                    // 'checking' persisted -> the restart bootstrap re-admits
                    // into check_pending (the verification itself does
                    // not cross sessions; the intent does).
                    self.begin_deferred_recheck(gid, requeued_paused(requeued))
                        .await;
                    if !matches!(requeued, RetireOutcome::Result) {
                        self.persist_queue_renumber().await;
                    }
                }
                _ => break,
            }
        }
        // Drain timeout fallback (halt-style finalization). Tasks whose
        // Ended was not received within budget (engine finalization
        // includes a final flush; the tail can be slower than
        // TORRENT_DRAIN_TIMEOUT) are finalized in place as Cancelled —
        // otherwise their torrent rows would stay stuck at downloading
        // and the restart face could not return them to the recoverable
        // queued semantics. Late watcher events die with the closed
        // event_rx (the actor main loop has exited).
        let remaining: Vec<Gid> = self.running.keys().copied().collect();
        for gid in remaining {
            // The same seed-pool face as the drain branch above (a
            // seeding resident whose Ended never landed inside the
            // budget — the row must still keep 'seeding').
            if self.shutdown_seed_dispatch(gid).await {
                continue;
            }
            // The same synthesis-pool face as the drain branch above
            // (a gate-hung / synthesizing media task whose Ended never
            // landed inside the budget — the row keeps its last
            // driver-written phase; the restart re-walks to the gate).
            if self.shutdown_synthesis_dispatch(gid) {
                continue;
            }
            let total = self
                .running
                .get(&gid)
                .map(|t| t.total_len)
                .unwrap_or_default();
            let outcome = TaskOutcome::Engine(EngineEnd::Cancelled);
            let (status, completed, _) = ended_classification(&outcome, total);
            let flags = self.queue.active_flags(gid);
            let requeued = self.retire_and_fire(gid, status, total, completed, None, None);
            self.persist_after_end(gid, status, None, flags, None).await;
            // The shutdown fallback arm ties in on the same face; see
            // the Ended branch above.
            self.begin_deferred_recheck(gid, requeued_paused(requeued))
                .await;
            if !matches!(requeued, RetireOutcome::Result) {
                self.persist_queue_renumber().await;
            }
        }
        info!(target: "taiji::core::session",
            phase = "drain",
            drained = self.running.is_empty(),
            elapsed_ms = shutdown_started.elapsed().as_millis() as u64,
            "shutdown phase complete: task drain");
        // Full persist at shutdown (aria2's save-session-on-exit
        // semantics + queued-row snapshots of unfinished tasks; WAL
        // checkpoint barrier to close).
        if self.persist.is_some() {
            if let Err(e) = self.save_session().await {
                warn!(target: "taiji::core::session", e = %e,
                    "session save on shutdown failed");
            }
            info!(target: "taiji::core::session",
                phase = "save",
                elapsed_ms = shutdown_started.elapsed().as_millis() as u64,
                "shutdown phase complete: session save");
        }
        // NAT singleton teardown (best-effort unmap of mappings + stop
        // the event pump; the NatActor cleans up after itself when the
        // handle drops). Delete requests are advisory (RFC 6886 §3.1) —
        // gateway-side automatic reclaim at lifetime expiry (3600s) is
        // the backstop; we await with a bounded budget
        // (NAT_SHUTDOWN_BUDGET, see mod.rs) so a slow gateway does not
        // eat the 1s shutdown budget. No power / no active mappings = a
        // fast no-op.
        if let Some(sup) = self.nat.take() {
            let _ = tokio::time::timeout(NAT_SHUTDOWN_BUDGET, sup.shutdown()).await;
            info!(target: "taiji::core::session",
                phase = "nat",
                elapsed_ms = shutdown_started.elapsed().as_millis() as u64,
                "shutdown phase complete: nat teardown");
        }
        let drained = self.running.is_empty();
        info!(target: "taiji::core::session", drained,
            num_stopped_total = self.queue.num_stopped_total(),
            total_ms = shutdown_started.elapsed().as_millis() as u64,
            "session actor exited");
    }

    /// Seed-pool shutdown bookkeeping (§4.1.4 — the
    /// drain/fallback consume): a seeding resident ending inside the
    /// shutdown window keeps its **'seeding'** row (the pool's one
    /// user-visible row-state change — seeding residence is no longer
    /// finalized as Complete at shutdown; restart routes it back by the
    /// measured bitmap). A forceRecheck-stop-in-flight voids into a
    /// 'checking' row (the next session's check-pending re-admission re-verifies).
    /// A budget-park stop landing here parks into seed_wait (row
    /// 'seeding', no result). Returns true = consumed (the caller skips
    /// the retire processing).
    async fn shutdown_seed_dispatch(&mut self, gid: Gid) -> bool {
        if self.queue.contains_seeding(gid) {
            if self.checking_deferred.remove(&gid) {
                // forceRecheck stop in flight at shutdown: persist the
                // checking intent; the next session's bootstrap
                // check-pending re-admission executes it (no spawn here —
                // shutting down).
                self.queue.remove_seeding(gid);
                self.running.remove(&gid);
                self.seed_parked.remove(&gid);
                self.persist_transition(gid, "checking").await;
                return true;
            }
            self.queue.remove_seeding(gid);
            self.running.remove(&gid);
            // No persist_after_end: the mirror row keeps 'seeding'
            // (written at the transfer / park admission); saveSession's
            // flush below carries it out.
            return true;
        }
        if self.seed_wait_deferred.remove(&gid) {
            // Budget-park stop landing inside the window: park without
            // results; a user pause/remove flag already ran its face
            // through the normal drain paths.
            self.queue.drop_active(gid);
            self.queue.push_seed_wait(gid);
            self.running.remove(&gid);
            self.persist_transition(gid, "seeding").await;
            return true;
        }
        false
    }

    /// Synthesis-pool shutdown bookkeeping (§4.3 — the
    /// drain/fallback consume): a gate-hung (proc_wait) or synthesizing
    /// (processing) media task ending inside the shutdown window leaves
    /// the registries **and the permit map** here — no result, no
    /// requeue, no fillup (shutting down). The row keeps its last
    /// driver-written phase: the gate hang never wrote 'processing'
    /// (that write happens only after the permit), so a parked task's
    /// row stays 'downloading' — a normal unfinished-task row; a
    /// synthesizing task's row keeps 'processing'/'verifying' (the
    /// idempotent re-run face). No proc_wait-specific row state exists
    /// and no proc_wait position persists: the restart re-walks
    /// Resolving → Downloading (idempotent, bitmap full) → gate and
    /// re-parks (proc_wait does not cross a restart). A user
    /// pause/remove landing inside the window already ran its teardown
    /// (Paused row / Ended consume) before the registries drained —
    /// the flags' consume orders precede this face either way.
    /// Returns true = consumed (the caller skips the retire
    /// processing).
    fn shutdown_synthesis_dispatch(&mut self, gid: Gid) -> bool {
        if self.queue.contains_synthesis(gid) {
            self.queue.remove_synthesis(gid);
            self.media_gate_tx.remove(&gid);
            self.running.remove(&gid);
            // No persist_after_end: the media row keeps its last
            // driver-written phase; saveSession's flush below carries
            // it out.
            return true;
        }
        false
    }
}

/// stop-family hook: the three branches of the aria2 RequestGroupMan.cc
/// `executeStopHook` translation — FINISHED -> complete, error (non
/// IN_PROGRESS/REMOVED) -> error, otherwise -> stop. A hook failure
/// does not affect the task state (util.cc semantics); the hook fires
/// before the event notification (same upstream order; the notification
/// half is [`stop_family_kind`]).
pub(super) fn fire_stop_family(hook: Option<&Arc<HookRunner>>, status: StatusKind) {
    let Some(hook) = hook else {
        return;
    };
    // Terminal states are only Complete/Error/Removed (the
    // ended_classification face; Active/Waiting/Paused are
    // non-terminal — the defensive branches never fire).
    match status {
        StatusKind::Complete => {
            hook.fire(HookEvent::Complete);
        }
        StatusKind::Error => {
            hook.fire(HookEvent::Error);
        }
        StatusKind::Removed => {
            hook.fire(HookEvent::Stop);
        }
        StatusKind::Active
        | StatusKind::Waiting
        | StatusKind::Paused
        | StatusKind::Seeding
        | StatusKind::Checking => {}
    }
}

/// EventKind mapping for the stop-family notification (the notification
/// half of `executeStopHook`, same source and mapping as
/// [`fire_stop_family`]'s hook branches) — FINISHED -> `Complete`,
/// error -> `Error`, REMOVED/IN_PROGRESS -> `Stop`; the non-terminal
/// defensive branches = None (no notification).
pub(super) fn stop_family_kind(status: StatusKind) -> Option<EventKind> {
    match status {
        StatusKind::Complete => Some(EventKind::Complete),
        StatusKind::Error => Some(EventKind::Error),
        StatusKind::Removed => Some(EventKind::Stop),
        StatusKind::Active
        | StatusKind::Waiting
        | StatusKind::Paused
        | StatusKind::Seeding
        | StatusKind::Checking => None,
    }
}

/// Measured-bitmap completeness (the §4.1.4 routing predicate —
/// session-side, read from the persisted `torrent_progress` row the
/// engine/recheck wrote; the dual of the engine's
/// `restore_progress_bits` + `check_resume_complete` faces):
/// - `v2_file_bits` present (v2-only): every non-padding file's piece
///   range must be fully set in its stored segment (a missing segment
///   for a file with pieces, or a stored count below the expected
///   piece count, = stale geometry = incomplete);
/// - else `v1_bitfield` (v1/hybrid): every global piece index set;
/// - neither present, or a piece-length mismatch (a stale row written
///   under another metainfo geometry) = **not** complete — the
///   conservative branch (the download side re-measures).
pub(super) fn progress_row_complete(
    meta: &crate::metainfo::TorrentMeta,
    row: &taiji_store::persist::TorrentProgressRow,
) -> bool {
    let piece_len = u64::from(meta.piece_length);
    if piece_len == 0 || row.piece_length != i64::from(meta.piece_length) {
        return false;
    }
    let bit_set = |bytes: &[u8], i: u64| {
        bytes
            .get((i / 8) as usize)
            .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
    };
    if let Some(bits) = row.v2_file_bits.as_deref() {
        for (fi, f) in meta.files.iter().enumerate() {
            if f.padding {
                continue;
            }
            let expected = f.length.div_ceil(piece_len);
            if expected == 0 {
                continue;
            }
            let mut cur = bits;
            let mut file_ok = false;
            while cur.len() >= 8 {
                let file_index = u32::from_be_bytes([cur[0], cur[1], cur[2], cur[3]]) as usize;
                let count = u32::from_be_bytes([cur[4], cur[5], cur[6], cur[7]]) as u64;
                let bytes = count.div_ceil(8) as usize;
                if cur.len() < 8 + bytes {
                    break;
                }
                if file_index == fi {
                    file_ok =
                        count >= expected && (0..expected).all(|i| bit_set(&cur[8..8 + bytes], i));
                    break;
                }
                cur = &cur[8 + bytes..];
            }
            if !file_ok {
                return false;
            }
        }
        return true;
    }
    if let Some(bits) = row.v1_bitfield.as_deref() {
        let total_len: u64 = meta.files.iter().map(|f| f.length).sum();
        let total_pieces = total_len.div_ceil(piece_len);
        if total_pieces == 0 {
            return false;
        }
        return (0..total_pieces).all(|i| bit_set(bits, i));
    }
    false
}

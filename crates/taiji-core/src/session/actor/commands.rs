//! SessionCommand dispatch face: the handle_command command table, the
//! global/task-level queries (tellStatus/getFiles/getPeers/getServers/
//! getUris/getGlobalStat), GID resolution, the changeOption/changeUri
//! subset, and global tracker import (bootstrap_global_trackers /
//! import_global_trackers).
//!
//! Owns: RPC command intake and reply assembly. Does not own: task
//! activation/retirement (tasks), row-write details (persist), view
//! field synthesis (views).
//!
//! Upstream anchor mapping: docs/design/core.md

use super::*;

impl SessionActor {
    async fn remove_durable_result(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        let in_memory = matches!(self.queue.find(gid), Some(Location::Result));
        if self.queue.find(gid).is_some() && !in_memory {
            return Err(SessionError::failed(format!(
                "Could not remove download result of GID#{gid}"
            )));
        }
        let written = if let Some(persist) = &self.persist {
            matches!(
                persist
                    .remove_download_result(&gid.to_string())
                    .await
                    .map_err(|e| SessionError::failed(e.to_string()))?,
                taiji_store::persist::PersistOutcome::Written
            )
        } else {
            false
        };
        self.queue.remove_result(gid);
        self.queue.startup_held.remove(&gid);
        self.rows.remove(&gid.to_string());
        if in_memory || written {
            Ok(CommandReply::Accepted)
        } else {
            Err(SessionError::failed(format!("GID {gid} is not found")))
        }
    }

    /// Startup bootstrap: ready the globally imported tracker set. Order
    /// = in-store restore (`global_tracker` table rowid order) -> CLI
    /// seed increment (`--bt-tracker` comma list + `--bt-tracker-file`
    /// ngosang parse, read via `spawn_blocking`) -> persist the full
    /// set when the seed adds anything (idempotent: an unchanged set on
    /// restart with the same CLI arguments skips the write). A
    /// missing/oversized/badly encoded file degrades to a warning (same
    /// rule as the bootstrap read failure "treated as fresh session";
    /// never disguised, never blocks the session).
    pub(super) async fn bootstrap_global_trackers(&mut self) {
        // CLI/caller-injected initial import seed (from the
        // spawn_with_persist options).
        let mut seed = std::mem::take(&mut self.global.bt_tracker);
        if let Some(path) = self.global.bt_tracker_file.clone() {
            let parsed =
                tokio::task::spawn_blocking(move || trackerslist::read_trackerslist(&path)).await;
            match parsed {
                Ok(Ok(urls)) => seed.extend(urls),
                Ok(Err(e)) => {
                    warn!(target: "taiji::core::session", %e,
                        "bt-tracker-file import failed at startup; ignored");
                }
                Err(e) => {
                    warn!(target: "taiji::core::session", %e,
                        "bt-tracker-file parse join failed; ignored");
                }
            }
        }
        // In-store restore (no persistence = start from an empty set).
        let mut restored: Vec<String> = Vec::new();
        if let Some(p) = &self.persist {
            match p.load_global_trackers().await {
                Ok(v) => restored = v,
                Err(e) => {
                    warn!(target: "taiji::core::session", %e,
                        "global tracker load failed (treated as fresh set)");
                }
            }
        }
        // Union: in-store order first, seed increments appended (same
        // order as import_global_trackers).
        let mut seen: std::collections::BTreeSet<String> = restored.iter().cloned().collect();
        let mut merged = restored.clone();
        for u in seed {
            if seen.insert(u.clone()) {
                merged.push(u);
            }
        }
        let added = merged.len() - restored.len();
        if added > 0 {
            if let Some(p) = &self.persist {
                if let Err(e) = p.replace_global_trackers(merged.clone()).await {
                    warn!(target: "taiji::core::session", %e,
                        "global tracker startup persist failed");
                }
            }
        }
        let total = merged.len();
        self.global.bt_tracker = merged;
        if total > 0 {
            info!(target: "taiji::core::session", total, imported = added,
                "global tracker set ready (three-tier tracker config)");
        }
    }

    /// Global import seam (the execution face of changeGlobalOption
    /// bt-tracker/bt-tracker-file): union-accumulate into the global
    /// set -> persist the full set (the only PersistWriter write seam)
    /// -> hot-push in-flight torrent tasks (`set_trackers` applies
    /// immediately; tasks activated later merge naturally). Returns the
    /// number of newly imported URLs.
    ///
    /// The hot-push merge semantics share a source with activate
    /// ([`merge_global_trackers`], incremental URLs only): the existing
    /// contents of the in-flight table (including manual edits from the
    /// taiji.addTracker/removeTracker face) are preserved up front, and
    /// newly imported URLs are appended each as an independent tier
    /// (isomorphic to aria2 addAnnounceUri). Job mirror sync and
    /// config_json refresh follow the tracker-edit discipline (tellStatus
    /// announceList matches the across-restart shape).
    pub(super) async fn import_global_trackers(&mut self, urls: Vec<String>) -> usize {
        let mut added_urls: Vec<String> = Vec::new();
        {
            let set = &mut self.global.bt_tracker;
            let mut seen: std::collections::BTreeSet<String> = set.iter().cloned().collect();
            for u in urls {
                if u.is_empty() || !seen.insert(u.clone()) {
                    continue;
                }
                // Global set cap: union accumulation has no natural
                // cross-call bound (drop at cap + warn; the hot-push
                // surface stays bounded).
                if set.len() >= crate::session::options::MAX_GLOBAL_TRACKERS {
                    warn!(target: "taiji::core::session",
                        cap = crate::session::options::MAX_GLOBAL_TRACKERS,
                        "global tracker set full; surplus import dropped");
                    break;
                }
                set.push(u.clone());
                added_urls.push(u);
            }
        }
        if added_urls.is_empty() {
            return 0;
        }
        if let Some(p) = &self.persist {
            if let Err(e) = p
                .replace_global_trackers(self.global.bt_tracker.clone())
                .await
            {
                warn!(target: "taiji::core::session", %e,
                    "global tracker persist failed (in-memory set still live)");
            }
        }
        // Metadata discovery needs the same updates before an engine exists.
        for task in self.running.values_mut() {
            if let TaskBackend::Metadata {
                tracker_updates: Some(updates),
            } = &task.backend
            {
                let tiers = merge_global_trackers(&task.tiers, &added_urls);
                task.tiers = tiers.clone();
                updates.send_replace(tiers);
            }
        }
        // In-flight hot push: snapshot (gid, engine, current tiers)
        // then merge-push one by one (avoids holding a mutable borrow
        // across await; no engine = metadata-phase task, merges at
        // activation after upgrade).
        let targets: Vec<HotPushTarget> = self
            .running
            .iter()
            .filter_map(|(gid, t)| {
                t.backend
                    .engine()
                    .map(|e| (*gid, e.clone(), t.tiers.clone()))
            })
            .collect();
        for (gid, engine, tiers) in targets {
            let merged = merge_global_trackers(&tiers, &added_urls);
            if merged == tiers {
                continue;
            }
            if engine.set_trackers(merged.clone()).await.is_ok() {
                if let Some(t) = self.running.get_mut(&gid) {
                    t.tiers = merged.clone();
                }
                // Job mirror sync + config_json refresh (the
                // bt-tracker import effect face and persistence share
                // one source, same discipline as the tracker edit face
                // taiji.addTracker/removeTracker).
                if let Some(Job::Torrent(tj)) = self.jobs.get_mut(&gid) {
                    tj.tiers = merged;
                    self.persist_refresh_config(gid).await;
                }
            }
        }
        info!(target: "taiji::core::session", imported = added_urls.len(),
            total = self.global.bt_tracker.len(),
            "global trackers imported (union dedup, persisted, hot-applied)");
        added_urls.len()
    }

    /// Handles one command; returns `true` to exit the main loop
    /// (shutdown family).
    pub(super) async fn handle_command(
        &mut self,
        cmd: SessionCommand,
        reply: oneshot::Sender<Result<CommandReply, SessionError>>,
    ) -> bool {
        use SessionCommand as C;
        match cmd {
            C::GetVersion => {
                let _ = reply.send(Ok(CommandReply::Version {
                    version: crate::version_string(),
                }));
            }
            C::Shutdown | C::ForceShutdown => {
                // (The old graceful-shutdown cookie sweep is retired —
                // cookies clear at the error
                // terminal itself now, the drain path close-out covers
                // tasks finishing inside the shutdown window, and the
                // startup GC backstops the crash window.)
                let _ = reply.send(Ok(CommandReply::Accepted));
                return true;
            }
            C::AddUri {
                uris,
                options,
                position,
            } => {
                // Phase timings for add_uri (accept + row persist) and
                // pump (activation) — per-command cost attribution for
                // the serial command loop. The reply goes out before
                // pump (the client reply never waits for activation);
                // instrumentation changes no behavior.
                let cmd_t0 = std::time::Instant::now();
                let result = self.add_uri(uris, options, position).await;
                let add_us = cmd_t0.elapsed().as_micros() as u64;
                let _ = reply.send(result);
                self.pump_all().await;
                debug!(target: "taiji::core::session",
                    add_us, pump_us = cmd_t0.elapsed().as_micros() as u64,
                    active = self.queue.active_len(),
                    "adduri command phases (add_uri | +pump)");
            }
            C::AddTorrent {
                torrent,
                options,
                position,
            } => {
                let result = self.add_torrent(torrent, options, position).await;
                let _ = reply.send(result);
                self.pump_all().await;
            }
            // addUriWithCookies: the structured cookie payload rides
            // the same assembly face as addUri (pump timing matches
            // AddUri — reply on acceptance, activation follows).
            C::AddUriWithCookies {
                uris,
                cookies,
                options,
                position,
            } => {
                let result = self
                    .add_uri_with_cookies(uris, cookies, options, position)
                    .await;
                let _ = reply.send(result);
                self.pump_all().await;
            }
            // setTaskCookies: direct translation of
            // SetTaskCookiesRpcMethod — GID prefix resolution up front
            // (str2Gid family); the state gate and whole-set
            // replacement live in the session arm.
            C::SetTaskCookies { gid, cookies } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(g) => self.set_task_cookies(g, cookies).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
            }
            C::TellStatus { gid, keys: _ } => {
                // keys filtering happens at the RPC layer (see
                // CommandReply); core always returns the full-field
                // semantic view.
                let _ = reply.send(self.tell_status(&gid).await);
            }
            C::GetFiles { gid } => {
                let _ = reply.send(self.get_files(&gid).await);
            }
            C::GetPeers { gid } => {
                let _ = reply.send(self.get_peers(&gid).await);
            }
            C::GetServers { gid } => {
                let _ = reply.send(self.get_servers(&gid).await);
            }
            C::GetTorrentMetadata { gid } => {
                let result = self.get_torrent_metadata(&gid);
                let _ = reply.send(result);
            }
            C::ConfirmTorrentSelection { gid, options } => {
                let result = self.confirm_torrent_selection(&gid, options).await;
                let _ = reply.send(result);
                self.pump_all().await;
            }
            C::GetUris { gid } => {
                let _ = reply.send(self.get_uris(&gid));
            }
            C::GetGlobalStat => {
                let _ = reply.send(self.get_global_stat().await);
            }
            C::Pause { gid } | C::ForcePause { gid } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(g) => self.pause(g).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
            }
            C::Unpause { gid } => {
                let resolved = self.resolve_gid(&gid).or_else(|error| {
                    if gid.len() == 16 && gid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        if let Ok(raw) = u64::from_str_radix(&gid, 16) {
                            if raw != 0 {
                                return Ok(Gid::from_u64(raw));
                            }
                        }
                    }
                    Err(error)
                });
                let r = match resolved {
                    Ok(g) => self.unpause(g).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
                self.pump_all().await;
            }
            C::ForceRecheck { gid } => {
                // gid prefix resolution happens inside force_recheck
                // (str2Gid family, same as the pause family).
                let r = self.force_recheck(gid).await;
                let _ = reply.send(r);
                self.pump_all().await;
            }
            // pauseAll/forcePauseAll share one arm: reference
            // pauseAllDownloads sets pauseRequested per group over
            // active + reserved (RpcMethodImpl.cc); the force branch
            // adds setForceHaltRequested(true, NONE), skipping tracker
            // notification and other graceful wrap-up
            // (pauseRequestGroup) — the local force difference follows
            // the single-task pause/forcePause equivalence (actor
            // `pause` note) and shares the traversal skeleton. Groups
            // that cannot pause do not short-circuit (pauseRequestGroups
            // swallows false per group); the reserved face is marked
            // paused by both methods.
            C::PauseAll | C::ForcePauseAll => {
                for gid in self.queue.active_gids() {
                    if self.queue.request_pause(gid) {
                        if let Some(t) = self.running.get(&gid) {
                            // HTTP task: pause raises the
                            // source-cancel flag (the drive finishes
                            // into a paused row; torrent tasks have no
                            // such face).
                            if let Some(p) = t.backend.http_pause() {
                                p.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            // Media task: the same cancel-source flag
                            // shape (the driver teardown writes the
                            // paused row — the single-task pause arm's
                            // face; without it the teardown classifies
                            // Cancelled and the row keeps its live
                            // phase, losing the pause intent across a
                            // restart).
                            if let Some(p) = t.backend.media_pause() {
                                p.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            t.token.cancel();
                        }
                    }
                }
                // In-recheck tasks: record the pause intent (staying
                // paused when they return to the queue) — the pause-all
                // face covers checking tasks too. The sweep reaches
                // **both check faces**: previously every
                // scheduled recheck sat in the checking registry, so the
                // in-flight loop covered all of them; since the check
                // pool landed, a
                // recheck parks in check_pending until the budget gate
                // admits it (bootstrap parks all N 'checking' rows
                // before the first pump admits two; forceRecheck beyond
                // the budget parks the rest) — a member missed here
                // promotes after pause-all and its recheck requeues
                // unpaused (the paused task re-activates). The row stays
                // 'checking' on either face (no persist — the same face
                // as the in-flight sweep).
                for gid in self.queue.checking_gids() {
                    self.queue.set_checking_paused(gid, true);
                }
                for gid in self.queue.check_pending_gids() {
                    self.queue.set_check_pending_paused(gid, true);
                }
                // Synthesis pool: the same both-faces
                // sweep, the check pool's shape one pool over. Since the
                // synthesis pool landed, a
                // media task leaves the active face at its Downloading →
                // Processing gate (the download slot releases there), so
                // a synthesizing member (processing registry) or a
                // gate-hung driver (proc_wait) is invisible to the
                // active sweep above — missed here, the pump's synthesis
                // segment would still fire the parked member's permit
                // and every synthesis would run to Done against the
                // global pause intent (tasks even landing Complete in
                // results). Flag on whichever synthesis face holds the
                // gid + the media pause flag + token cancel: the
                // teardown lands Paused{memory: Processing} (the §3.2
                // phase memory) and the Ended consume requeues to the
                // paused queue front — the same landing the single-task
                // pause arm produces.
                for gid in self
                    .queue
                    .processing_gids()
                    .into_iter()
                    .chain(self.queue.proc_wait_gids())
                {
                    if self.queue.request_synthesis_pause(gid) {
                        info!(target: "taiji::core::session", gid = %gid,
                            "pause-all: synthesis-side member flagged (token cancel racing the gate await / synthesis)");
                        if let Some(t) = self.running.get(&gid) {
                            if let Some(p) = t.backend.media_pause() {
                                p.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                            t.token.cancel();
                        }
                    }
                }
                for entry in self.queue.reserved_snapshot() {
                    if self.awaiting_torrent_selection(entry.gid) {
                        continue;
                    }
                    if let Some(e) = self.queue.reserved_entry_mut(entry.gid) {
                        e.paused = true;
                    }
                    // Persist the paused state of waiting tasks
                    // (paused row; HTTP tasks via the http_task
                    // table; media tasks via the media_task row).
                    self.http_reserved_transition(entry.gid, TaskPhase::Paused)
                        .await;
                    self.media_reserved_transition(entry.gid, TaskPhase::Paused)
                        .await;
                    self.persist_transition(entry.gid, TaskPhase::Paused).await;
                }
                let _ = reply.send(Ok(CommandReply::Accepted));
            }
            C::UnpauseAll => {
                self.queue.startup_held.clear();
                // Revoke every in-flight pause intent first: the epoch
                // bump marks all still-undelivered pause requests
                // (active/seeding teardowns in flight, recorded against
                // an older epoch) as superseded — their late landing
                // requeues UNPAUSED instead of resurrecting the revoked
                // intent (queue::RetireOutcome::RequeuedUnpauseSuperseded;
                // the landing side also rewrites the row to queued via
                // the restart face). The old "transient window
                // self-heals" assumption was wrong: on slow hosts the
                // teardown lands after this arm finished and the member
                // stayed paused forever (the CI-caught intermittence —
                // see the unpause_all e2e regression test).
                self.queue.bump_pause_epoch();
                // In-recheck tasks: clear the pause intent (activation
                // resumes as soon as they return to the queue) — on both
                // check faces (the parked-face mirror of
                // pause-all's sweep: a stale intent surviving on a parked
                // member would requeue it paused after unpause-all). The
                // synthesis faces are deliberately **not** swept here
                // (the pool rule): a pause-flagged synthesis member always has a
                // driver teardown already in flight (the pause face
                // cancels the token in the same step), so its landing —
                // requeue to the paused queue front — is fixed at the
                // Ended consume regardless of a flag clear, the same
                // posture as the active face's mid-teardown members
                // (whose rescue is the epoch bump above). Clearing the
                // flag instead would desynchronize the registry from the
                // driver's own pause decision (the teardown reads the
                // media pause flag, not the registry) and finalize the
                // task into results on a mere unpause-all.
                for gid in self.queue.checking_gids() {
                    self.queue.set_checking_paused(gid, false);
                }
                for gid in self.queue.check_pending_gids() {
                    self.queue.set_check_pending_paused(gid, false);
                }
                for entry in self.queue.reserved_snapshot() {
                    if self.awaiting_torrent_selection(entry.gid) {
                        continue;
                    }
                    if let Some(e) = self.queue.reserved_entry_mut(entry.gid) {
                        e.paused = false;
                    }
                    // Back to the waiting-state row (queued/metadata
                    // per task shape; HTTP/media task rows return to
                    // queued).
                    self.media_reserved_transition(entry.gid, TaskPhase::Queued)
                        .await;
                    self.http_reserved_transition(entry.gid, TaskPhase::Queued)
                        .await;
                    let state = self.reserved_state(entry.gid);
                    self.persist_transition(entry.gid, state).await;
                }
                let _ = reply.send(Ok(CommandReply::Accepted));
                self.pump_all().await;
            }
            C::Remove { gid } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(g) => self.remove(g).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
                self.pump_all().await;
            }
            C::ForceRemove { gid } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(g) => self.force_remove(g).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
                self.pump_all().await;
            }
            C::PurgeDownloadResult => {
                if let Some(persist) = &self.persist {
                    if let Err(error) = persist.purge_download_results().await {
                        let _ = reply.send(Err(SessionError::failed(error.to_string())));
                        return false;
                    }
                }
                self.queue.purge_results();
                let keep: std::collections::HashSet<_> =
                    self.queue.known_gids().into_iter().collect();
                self.queue.startup_held.retain(|gid, _| keep.contains(gid));
                let _ = reply.send(Ok(CommandReply::Accepted));
            }
            C::RemoveDownloadResult { gid: raw } => {
                let resolved = self.resolve_gid(&raw).or_else(|error| {
                    if raw.len() == 16 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        if let Ok(value) = u64::from_str_radix(&raw, 16) {
                            if value != 0 {
                                return Ok(Gid::from_u64(value));
                            }
                        }
                    }
                    Err(error)
                });
                let result = match resolved {
                    Ok(gid) => self.remove_durable_result(gid).await,
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            C::ChangeUri {
                gid,
                file_index,
                del_uris,
                add_uris,
                pos,
            } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(gid) => {
                        self.change_uri(gid, file_index, del_uris, add_uris, pos)
                            .await
                    }
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
            }
            // taiji.addTracker/removeTracker: GID prefix resolution up
            // front (str2Gid family); the shape gate and table
            // transforms live in the session arm.
            C::AddTracker {
                gid,
                urls,
                position,
            } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(gid) => self.add_tracker(gid, urls, position).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
            }
            C::RemoveTracker { gid, urls } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(gid) => self.remove_tracker(gid, urls).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
            }
            C::ChangeOption { gid, options } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(g) => self.change_option(g, options).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
                self.pump_all().await;
            }
            C::GetHttpOutput { gid } => {
                let _ = reply.send(self.get_http_output(&gid).await);
            }
            C::FinalizeHttp { gid, action, path } => {
                let result = self.finalize_http(&gid, &action, path).await;
                let _ = reply.send(result);
                self.pump_all().await;
            }
            C::GetOption { gid } => {
                let _ = reply.send(self.get_option(&gid).await);
            }
            C::ChangePosition { gid, pos, how } => {
                let _ = reply.send(self.change_position(&gid, pos, how).await);
            }
            C::ChangeGlobalOption { options } => {
                if let Some(raw) = options.get("motrix-peer-mappings") {
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Mapping {
                        id: String,
                        port: u16,
                        tcp: Option<u16>,
                        udp: Option<u16>,
                    }
                    let parsed = serde_json::from_str::<Vec<Mapping>>(raw)
                        .ok()
                        .filter(|items| {
                            items.len() <= 256
                                && items.iter().all(|item| {
                                    item.id.len() == 33
                                        && item.port > 0
                                        && item.tcp != Some(0)
                                        && item.udp != Some(0)
                                })
                        });
                    let Some(items) = parsed else {
                        let _ = reply.send(Err(SessionError::failed("invalid peer mappings")));
                        return false;
                    };
                    if self.nat.is_none() {
                        for item in items {
                            if self.magnet_services.network().update(
                                &item.id,
                                item.port,
                                crate::nat::ExternalPorts {
                                    tcp: item.tcp,
                                    udp: item.udp,
                                },
                            ) {
                                continue;
                            }
                            for task in self.running.values() {
                                if let Some(binding) = &task.network {
                                    if binding.update(
                                        &item.id,
                                        item.port,
                                        crate::nat::ExternalPorts {
                                            tcp: item.tcp,
                                            udp: item.udp,
                                        },
                                    ) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(raw) = options.get("motrix-release-startup") {
                    let parsed = serde_json::from_str::<Vec<String>>(raw)
                        .ok()
                        .and_then(|values| {
                            values
                                .into_iter()
                                .map(|value| {
                                    if value.len() != 16 {
                                        return None;
                                    }
                                    u64::from_str_radix(&value, 16).ok().map(Gid::from_u64)
                                })
                                .collect::<Option<Vec<_>>>()
                        });
                    let Some(gids) = parsed else {
                        let _ =
                            reply.send(Err(SessionError::failed("invalid startup release list")));
                        return false;
                    };
                    for gid in gids {
                        self.queue.startup_held.remove(&gid);
                    }
                }
                // bt-tracker / bt-tracker-file global hot-import face.
                // bt-tracker has a setChangeGlobalOption bit in the
                // reference (OptionHandlerFactory.cc); bt-tracker-file
                // is a local extension. Import = union accumulation
                // (explicit deviation declared on the field): persist
                // immediately + hot-push running engines + merge at
                // later activations. File reads go through
                // spawn_blocking; a bad file/value = warn and ignore
                // (same rule as the reference "unacceptable options
                // ignored"), never a wrong reply, never interrupting
                // the other hot-changeable keys.
                if let Some(v) = options.get("bt-tracker") {
                    let urls = split_bt_tracker(v);
                    if !urls.is_empty() {
                        self.import_global_trackers(urls).await;
                    }
                }
                if let Some(v) = options.get("bt-tracker-file") {
                    if !v.trim().is_empty() {
                        let path = PathBuf::from(v.trim());
                        let parsed = tokio::task::spawn_blocking(move || {
                            trackerslist::read_trackerslist(&path)
                        })
                        .await;
                        match parsed {
                            Ok(Ok(urls)) => {
                                self.global.bt_tracker_file = Some(PathBuf::from(v.trim()));
                                self.import_global_trackers(urls).await;
                            }
                            Ok(Err(e)) => {
                                warn!(target: "taiji::core::session", %e,
                                    "bt-tracker-file import failed; ignored");
                            }
                            Err(e) => {
                                warn!(target: "taiji::core::session", %e,
                                    "bt-tracker-file parse join failed; ignored");
                            }
                        }
                    }
                }
                // enable-dht hot-change detection (session-level hot
                // switch): value intake happens in apply_global_patch
                // (existing arm); the runtime linkage lives here — a
                // change pushes the effective value to every running BT
                // engine (DHT spawn/teardown; a trackerless stalled task
                // revives when switched on). aria2 has no
                // setChangeGlobalOption bit for this key (not
                // hot-changeable) — the local extension via libtorrent
                // apply_settings is declared (rpc-api-diff §3);
                // enable-dht6 is accepted under the same key but there
                // is no separate v6 DHT gate (the v6 family follows the
                // enable-dht master gate plus the connectivity gate; the
                // value echoes as set).
                for (key, value) in &options {
                    if matches!(
                        key.as_str(),
                        "split"
                            | "max-connection-per-server"
                            | "min-split-size"
                            | "user-agent"
                            | "connect-timeout"
                            | "timeout"
                            | "max-tries"
                            | "retry-wait"
                            | "lowest-speed-limit"
                            | "remote-time"
                            | "all-proxy"
                            | "all-proxy-user"
                            | "all-proxy-passwd"
                            | "no-proxy"
                            | "http-proxy"
                            | "https-proxy"
                            | "ftp-proxy"
                    ) {
                        self.global
                            .motrix_http_defaults
                            .insert(key.clone(), value.clone());
                    }
                }
                let dht_before = self.global.enable_dht;
                apply_global_patch(&mut self.global, &options);
                let dht_flipped = dht_before != self.global.enable_dht;
                // Global rate-limit hot change (direct translation of
                // setMaxOverallDownload/UploadSpeedLimit,
                // RpcMethodImpl.cc) — snapshot store + shared-bucket
                // rate changed atomically, live for every running
                // engine.
                self.limits.set_overall(
                    self.global.max_overall_download_limit,
                    self.global.max_overall_upload_limit,
                );
                // client-ban-prefixes hot change ( key) —
                // kv persist + re-push to running engines (whole-table
                // replace semantics in apply_global_patch).
                if options.contains_key("client-ban-prefixes") {
                    self.apply_client_ban_change().await;
                }
                // enable-dht flip -> hot-update running BT engines
                // (idempotent: same-state engines answer Ok no-op;
                // per-task explicit flags are applied at the synthesis
                // point).
                if dht_flipped {
                    self.push_dht_session_change().await;
                }
                info!(target: "taiji::core::session",
                    max_concurrent = self.global.max_concurrent_downloads,
                    enable_dht = self.global.enable_dht,
                    "global options changed via changeGlobalOption");
                if options.contains_key("enable-dht") || options.contains_key("enable-dht6") {
                    self.magnet_services
                        .set_dht_enabled(
                            self.global.enable_dht,
                            self.global.enable_dht && self.global.enable_dht6,
                        )
                        .await;
                }
                let _ = reply.send(Ok(CommandReply::Accepted));
                self.pump_all().await;
            }
            C::GetGlobalOption => {
                let mut echo = global_option_echo(&self.global);
                let mut listeners = Vec::new();
                for (gid, task) in &self.running {
                    if let Some(binding) = &task.network {
                        let (id, port) = binding.snapshot();
                        if port != 0 {
                            listeners.push(serde_json::json!({ "id": id, "gid": gid.to_string(), "port": port, "hostManaged": self.nat.is_none() }));
                        }
                    }
                }
                let (id, port) = self.magnet_services.network().snapshot();
                if port != 0 {
                    listeners.push(serde_json::json!({"id":id,"gid":"0000000000000000","port":port,"hostManaged":self.nat.is_none()}));
                }
                echo.insert(
                    "motrix-peer-listeners".into(),
                    serde_json::to_string(&listeners).unwrap_or_default(),
                );
                let held: Vec<(String, bool)> = self
                    .queue
                    .startup_held
                    .iter()
                    .map(|(gid, resume)| (gid.to_string(), *resume))
                    .collect();
                echo.insert(
                    "motrix-startup-tasks".into(),
                    serde_json::to_string(&held).unwrap_or_default(),
                );
                // http-max-per-host echoes the effective cap: a runtime
                // addUri change (last-set-wins) only moves HostCap, not
                // the option field — override the echo via cap() so
                // echo face = effect face (at spawn both faces start
                // equal: HostCap init shares the option field's
                // source).
                echo.insert(
                    "http-max-per-host".to_string(),
                    self.http_per_host.cap().to_string(),
                );
                let _ = reply.send(Ok(CommandReply::Options(echo)));
            }
            C::GetSessionInfo => {
                let _ = reply.send(Ok(CommandReply::SessionInfo {
                    session_id: self.session_id.clone(),
                }));
            }
            C::TellActive { keys: _ } => {
                // The tellActive set caliber (the finalized caliber):
                // exactly the four in-flight registries — the download
                // pool's active set, in-flight rechecks, seeding
                // residents, synthesis residents. The three waiting
                // FIFOs (seed_wait / check_pending / proc_wait) never
                // appear here — their members live in tellWaiting's
                // segments (pinned by the observation-face tests).
                // - In-recheck tasks project into the active set —
                // aria2 keeps groups active during validation
                // (checking progress rides completedLength; there is
                // no separate status value).
                // - Seeding residents project the 'seeding' value (the
                // flip: residence and seed_wait share the row
                // state; the engine is live, isomorphic to aria2's
                // post-detach group staying in the active list —
                // [`Self::seeding_live_view`], the shared
                // tellActive/tellStatus face).
                // - Synthesis residents project 'active' (the driver is
                // live; the media sub-dictionary carries the phases).
                // The numActive *meter* (getGlobalStat) stays
                // download-slots-only — the caliber's formal migration
                // landed here (declared in the rpc-api-diff
                // entry).
                let mut views = Vec::new();
                for gid in self.queue.active_gids() {
                    views.push(self.live_status_view(gid).await);
                }
                for gid in self.queue.checking_gids() {
                    views.push(self.checking_status_view(gid));
                }
                for gid in self.queue.seeding_gids() {
                    views.push(self.seeding_live_view(gid).await);
                }
                for gid in self.queue.processing_gids() {
                    views.push(self.live_status_view(gid).await);
                }
                let _ = reply.send(Ok(CommandReply::StatusList(views)));
            }
            C::TellWaiting {
                offset: _,
                num: _,
                keys: _,
            } => {
                // The unified waiting projection (the
                // segment-order consolidation): one source — the queue's
                // waiting snapshot, the fixed segment order
                // `reserved ++ check_pending ++ seed_wait ++ proc_wait`
                // with the per-segment status matrix, each segment
                // internally FIFO. The interim append order is
                // closed. Client visibility contract: the
                // active/waiting/stopped three-list union covers every
                // gid exactly once — no parked task goes invisible (the
                // no-invisible-task discipline, now the finalized face; pinned by
                // the coverage tests).
                let views = self
                    .queue
                    .waiting_snapshot()
                    .into_iter()
                    .map(|m| self.base_status_view(m.gid, m.status))
                    .collect::<Vec<_>>();
                let _ = reply.send(Ok(CommandReply::StatusList(views)));
            }
            C::TellStopped {
                offset: _,
                num: _,
                keys: _,
            } => {
                // Table order = completion order (DownloadResult append
                // order; same shape as RequestGroupMan
                // getDownloadResults).
                let views = self
                    .queue
                    .results()
                    .map(|r| self.result_status_view(r))
                    .collect();
                let _ = reply.send(Ok(CommandReply::StatusList(views)));
            }
            C::SaveSession => {
                // Full task rows + progress flush (barrier + WAL
                // checkpoint) + the optional input-file text export
                // (--save-session).
                let result = self.save_session().await;
                let _ = reply.send(result.map(|_| CommandReply::Accepted));
            }
            C::SystemListMethods => not_yet(reply, "system.listMethods"),
            C::SystemMulticall => not_yet(reply, "system.multicall"),
            C::SystemListNotifications => not_yet(reply, "system.listNotifications"),
            C::MoveStorage { gid, dir: _ } => {
                // Deferred extension: GID resolution first (aria2
                // parameter face), capability always not_supported
                // (SPEC §8.2).
                let r: Result<CommandReply, SessionError> =
                    self.resolve_gid(&gid).and(Err(SessionError::NotSupported {
                        method: "taiji.moveStorage",
                    }));
                let _ = reply.send(r);
            }
            C::RenameFile { gid, .. } => {
                let r: Result<CommandReply, SessionError> =
                    self.resolve_gid(&gid).and(Err(SessionError::NotSupported {
                        method: "taiji.renameFile",
                    }));
                let _ = reply.send(r);
            }
            C::BanAddr { target, minutes } => {
                let _ = reply.send(self.ban_addr(target, minutes).await);
            }
            C::UnbanAddr { target } => {
                let _ = reply.send(self.unban_addr(target).await);
            }
            C::ListBans => {
                let _ = reply.send(self.list_bans().await);
            }
            C::SetSchedulerPolicy { gid, policy } => {
                let _ = reply.send(self.set_scheduler_policy(gid, policy).await);
            }
            C::GetSchedulerPolicy { gid } => {
                let _ = reply.send(self.get_scheduler_policy(&gid));
            }
            C::SetFilePriority { gid, pairs } => {
                let _ = reply.send(self.set_file_priority(gid, pairs).await);
            }
            C::SetStreamingPlayhead {
                gid,
                file,
                position,
                bytes_per_sec,
            } => {
                let _ = reply.send(
                    self.set_streaming_playhead(gid, file, position, bytes_per_sec)
                        .await,
                );
            }
            C::GetDiskTier { gid } => {
                let _ = reply.send(self.get_disk_tier(&gid));
            }
            C::SetDiskTier { gid, tier } => {
                let _ = reply.send(self.set_disk_tier(gid, tier).await);
            }
            C::GetCapabilities => {
                // Declarative collection from the policy/feature
                // registry (single source of truth) + taiji.* extension
                // method names (filtered from the session promise table
                // — capability face and method face stay reconciled).
                let mut view = crate::engine::CapabilitiesView::collect(
                    crate::engine::FeatureToggles {
                        dht: self.global.enable_dht,
                        dht6: self.global.enable_dht6,
                        lsd: self.global.bt_lsd,
                    },
                    crate::version_string(),
                );
                view.rpc_extensions = RPC_METHODS
                    .iter()
                    .filter(|m| m.starts_with("taiji."))
                    .copied()
                    .collect();
                // taiji.* extension notification event names (single
                // name source = RecoveryEventKind::notification_method;
                // extension events always keep the taiji.* face and are
                // never re-faced by --rpc-aria2-compat — the six events
                // are declared via listNotifications, the extension
                // events via capabilities).
                view.notifications = RecoveryEventKind::ALL
                    .iter()
                    .map(|k| k.notification_method())
                    // The media extension event (the bypass — the
                    // same declaration face as the recovery events;
                    // listNotifications stays six-events-only).
                    .chain(std::iter::once(
                        crate::session::events::MEDIA_PHASE_EVENT_METHOD,
                    ))
                    // The task-cookie alert (the same
                    // bypass declaration face; the six-event table and
                    // listNotifications stay untouched).
                    .chain(std::iter::once(
                        crate::session::events::TASK_COOKIE_EVENT_METHOD,
                    ))
                    .collect();
                let _ = reply.send(Ok(CommandReply::Capabilities(Box::new(view))));
            }
            // Media line: the four methods'
            // actor arms.
            C::AddMedia {
                url,
                options,
                cookies,
                position,
            } => {
                let result = self.add_media(url, options, cookies, position).await;
                let _ = reply.send(result);
                self.pump_all().await;
            }
            C::ProbeMedia { url } => {
                // The probe action face runs on a spawned task (the
                // fetch must not block the command loop; the shared
                // ProbeFace enforces the in-flight cap 2 + the
                // per-origin rate limit across concurrent probes).
                self.spawn_probe(url, reply);
            }
            C::GetMediaFormats { gid } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(g) => self.get_media_formats(g).await,
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
            }
            C::StopRecording { gid } => {
                let r = match self.resolve_gid(&gid) {
                    Ok(g) => self.stop_recording(g),
                    Err(e) => Err(e),
                };
                let _ = reply.send(r);
            }
            C::ClearMediaArchive => {
                let _ = reply.send(self.clear_media_archive().await);
            }
        }
        false
    }

    // ---- Media faces ----

    /// taiji.probeMedia's spawned execution: rate admission → the
    /// in-flight slot → the §10 #7 first-order SSRF line → fetch +
    /// classify + the format tree → the server-side snapshot under a
    /// fresh opaque token. The reply carries the token + the TTL +
    /// the tree (§4).
    fn spawn_probe(&self, url: String, reply: oneshot::Sender<Result<CommandReply, SessionError>>) {
        use crate::session::media::PROBE_TTL;
        let face = Arc::clone(&self.probe_face);
        let url_clone = url.clone();
        // §10 #7: the probe URL (first-order) crosses the
        // media SSRF line before any fetch — same judgment face
        // (scheme whitelist / literal + resolved layers), same allow
        // flag (`--media-allow-private-key-url`, the session-global
        // face — a probe owns no task-level option). Redirect
        // endpoints ride the base client's redirect IP hygiene (the
        // same coverage the key/segment SSRF line documents: a
        // restricted hop target of a public initial is refused
        // there). Declared difference: the Resolving-side no-token
        // manifest fetch (a committed task's first-order URL) stays
        // at the aria2 task-URL trust level — the
        // probe face is spec'd stricter as a pre-commit action face.
        let allow_private = self.global.media_allow_private_key_url;
        tokio::spawn(async move {
            let now = std::time::Instant::now();
            if let Err(wait) = face.admit_rate(&url_clone, now) {
                // A plain rejection message, deliberately NOT a
                // `taiji.media.*` code: the RPC error table has no row for
                // the rate-limit face, and new codes are outside this
                // batch's freeze seam (the canonical-code need is
                // raised to the coordination face; the message rides
                // the generic execution-error shape like the reference
                // cap rejections, e.g. "Too many task cookies.").
                let _ = reply.send(Err(SessionError::failed(format!(
                    "probe rate limit: this origin's next probe slot is \
                     {}ms away (per-source rate limit; retry later)",
                    wait.as_millis()
                ))));
                return;
            }
            let Some(_guard) = face.acquire_inflight() else {
                // Same posture: a plain busy rejection, no new code.
                let _ = reply.send(Err(SessionError::failed(
                    "probe busy: 2 probes already in flight (global cap; retry later)",
                )));
                return;
            };
            let policy = taiji_media::ssrf::SsrfPolicy { allow_private };
            let resolver = taiji_media::ssrf::default_resolver();
            let mut cache = taiji_media::ssrf::HostVerdictCache::new();
            if let Err(e) =
                taiji_media::ssrf::check_uri(&url_clone, &policy, resolver.as_ref(), &mut cache)
                    .await
            {
                let _ = reply.send(Err(SessionError::failed(e.to_string())));
                return;
            }
            let ctx = taiji_segment::traits::RequestCtx::default();
            let client = match taiji_http::client::HttpClient::new(
                taiji_http::client::ClientConfig::default(),
            ) {
                Ok(c) => c,
                Err(e) => {
                    let _ = reply.send(Err(SessionError::failed(format!(
                        "taiji.media.staging: probe client build: {e}"
                    ))));
                    return;
                }
            };
            let bytes = match taiji_media::mediadl::http_get_bytes(&client, &url_clone, &ctx).await
            {
                Ok(b) => b,
                Err(e) => {
                    let _ = reply.send(Err(SessionError::failed(e.to_string())));
                    return;
                }
            };
            let path = url_clone.split(['?', '#']).next().unwrap_or(&url_clone);
            let file = path.rsplit('/').next().unwrap_or_default().to_string();
            let kind = taiji_media::classify_entry(Some(&bytes), Some(&file), None);
            let (tree, direct) = match &kind {
                // The DASH arm (flipping the earlier refusal —
                // the MPD parser owns the bytes): parse + the DASH
                // format tree into the snapshot. The judgment-table
                // codes route verbatim — dynamic → live_unsupported
                // and ContentProtection → drm_unsupported surface
                // here as the parser's own errors; the nested-sidx
                // row is a materialization-time refusal reaching its
                // code through the download a token later drives (the
                // probe face routes codes, never swallowing or
                // re-coding them).
                taiji_media::EntryKind::Manifest(taiji_media::ManifestFlavor::Dash) => {
                    match taiji_media::parse_mpd(&bytes)
                        .map_err(|e| e.to_string())
                        .and_then(|mpd| {
                            taiji_media::build_format_tree_dash(&url_clone, &mpd)
                                .map_err(|e| e.to_string())
                        }) {
                        Ok(tree) => (tree, false),
                        Err(text) => {
                            let _ = reply.send(Err(SessionError::failed(text)));
                            return;
                        }
                    }
                }
                taiji_media::EntryKind::Manifest(_) => {
                    match taiji_media::parse_manifest(&bytes)
                        .map_err(|e| e.to_string())
                        .and_then(|p| {
                            taiji_media::build_format_tree(&url_clone, &p)
                                .map_err(|e| e.to_string())
                        }) {
                        Ok(tree) => (tree, false),
                        Err(text) => {
                            let _ = reply.send(Err(SessionError::failed(text)));
                            return;
                        }
                    }
                }
                taiji_media::EntryKind::DirectFile => {
                    // A direct media file: the single-node tree (the
                    // uri = the entry itself); addMedia converts to the
                    // HTTP family.
                    let ext = file.rsplit('.').next().unwrap_or_default().to_string();
                    (
                        taiji_media::FormatTree {
                            url: url_clone.clone(),
                            kind: "direct".into(),
                            formats: vec![taiji_media::FormatNode {
                                format_id: "v0".into(),
                                protocol: "direct".into(),
                                ext,
                                ..taiji_media::FormatNode::default()
                            }],
                        },
                        true,
                    )
                }
                taiji_media::EntryKind::NotMedia => {
                    let _ = reply.send(Err(SessionError::failed(
                        "taiji.media.not_media: no media signature in content, extension or \
                         Content-Type",
                    )));
                    return;
                }
            };
            let token = face.store(&url_clone, tree.clone(), direct);
            let _ = reply.send(Ok(CommandReply::MediaProbe {
                token,
                ttl_secs: PROBE_TTL.as_secs(),
                formats: Box::new(tree),
            }));
        });
    }

    /// taiji.getMediaFormats: the task's resolved format tree — the
    /// live snapshot (an active task's format set) or the media_format
    /// row (the probe snapshot's durable counterpart).
    async fn get_media_formats(&mut self, gid: Gid) -> Result<CommandReply, SessionError> {
        // Family + snapshot = row-driven (the jobs table empties at the
        // terminal teardown — the results domain must still answer).
        let Some(p) = self.persist.as_ref() else {
            return Err(SessionError::failed(format!(
                "GID#{gid} is not a media task"
            )));
        };
        match p.load_media_format(&gid.to_string()).await {
            Ok(Some(row)) => {
                if let Ok(tree) = serde_json::from_str::<taiji_media::FormatTree>(&row.formats_json)
                {
                    return Ok(CommandReply::MediaFormats(Box::new(tree)));
                }
                Err(SessionError::failed(format!(
                    "GID#{gid} has an unreadable format snapshot"
                )))
            }
            Ok(None) => Err(SessionError::failed(format!(
                "GID#{gid} has no resolved format tree yet (still resolving, or not a \
                     media task)"
            ))),
            Err(e) => Err(SessionError::failed(format!(
                "GID#{gid} format snapshot read failed: {e}"
            ))),
        }
    }

    /// taiji.stopRecording (registration + dispatch only — the LIVE
    /// execution body lands in 0.4): a 0.3 task can never be
    /// in the `recording` phase, so every call answers the explicit
    /// non-recording error (never a silent no-op).
    fn stop_recording(&self, gid: Gid) -> Result<CommandReply, SessionError> {
        let recording = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.media_live())
            .map(|live| {
                live.lock()
                    .map(|st| st.phase == taiji_media::MediaPhase::Recording)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if recording {
            // Unreachable in 0.3 (no LIVE executor); the honest arm
            // for the 0.4 wiring: the stop source wins the §6
            // arbitration at the driver. Plain message (no
            // `taiji.media.*` code — §14 has no stop-recording row;
            // the code need, if any, belongs to the 0.4 card).
            return Err(SessionError::failed(
                "recording stop arbitration lands with the LIVE executor in 0.4",
            ));
        }
        Err(SessionError::failed(format!(
            "GID#{gid} is not a recording task (LIVE lands in 0.4 — VOD tasks \
             never record)"
        )))
    }

    /// taiji.clearMediaArchive: the whole-table
    /// destructive clear through the single writer. No session
    /// persistence = the explicit error (there is no archive to
    /// clear, and a silent OK would fake the destructive promise);
    /// the reply carries the removed row count (0 = already empty —
    /// idempotent, the honest count face).
    async fn clear_media_archive(&mut self) -> Result<CommandReply, SessionError> {
        let Some(p) = self.persist.as_ref() else {
            return Err(SessionError::failed(
                "taiji.session.closed: no session storage — the media archive lives in the \
                 session database",
            ));
        };
        let removed = p
            .clear_media_archive()
            .await
            .map_err(|e| SessionError::failed(format!("clearMediaArchive: {e}")))?;
        info!(target: "taiji::core::session", removed,
            "media archive cleared (the browsing-history face)");
        Ok(CommandReply::ArchiveCleared { removed })
    }

    // ---- Ban face (manual ban bookkeeping + client identity rules) ----

    /// Snapshot of the ban-face payload (identity rules + unexpired
    /// manual bans) — the activation path reads it through this
    /// function before taking the jobs borrow, then pushes after spawn
    /// (never holding self across await).
    pub(super) fn ban_config_payload(&self) -> (Vec<String>, Vec<ManualBanRule>) {
        let now = now_epoch();
        let manual = self
            .manual_bans
            .iter()
            .filter(|b| b.until > now)
            .map(|b| ManualBanRule {
                start: b.start,
                end: b.end,
                until: b.until,
            })
            .collect();
        (self.global.client_ban_prefixes.clone(), manual)
    }

    /// Push the full ban face to one engine: identity rules + unexpired
    /// manual bans. Failure = the engine is already going away (session
    /// shutdown race); debug only.
    pub(super) async fn push_ban_config(&self, engine: &EngineHandle) {
        let (clients, manual) = self.ban_config_payload();
        if let Err(e) = engine.set_ban_config(clients, manual).await {
            debug!(target: "taiji::core::session", %e,
                "ban config push skipped (engine already down)");
        }
    }

    /// Session-side half of the ban hot change: re-store the
    /// session-level IpGuard snapshot for metadata-phase tasks
    /// (`push_all_ban_configs` only reaches tasks holding an engine
    /// handle; metadata tasks have none and would otherwise be a
    /// bypass). Snapshot input = the session management face (unexpired
    /// manual bans + the client identity list; static rules/ledger stay
    /// empty — the auto-ban ledger and ipfilter read-back are
    /// engine-local and not covered here). Live magnet tasks read the
    /// latest arc-swap snapshot on every dial, so re-storing is the
    /// whole hot change (no per-task notification; with no persistence
    /// the snapshot stays empty = no address is banned).
    pub(super) fn refresh_meta_guard(&self) {
        let now = now_epoch();
        let manual: Vec<ManualBanRule> = self
            .manual_bans
            .iter()
            .filter(|b| b.until > now)
            .map(|b| ManualBanRule {
                start: b.start,
                end: b.end,
                until: b.until,
            })
            .collect();
        // Ledger placeholder (always empty) — assembly goes through
        // the refresh_guard_full single path, shape-identical to the
        // engine-side snapshot (no ad-hoc snapshots).
        let ledger = crate::peer_guard::BanLedger::new(Box::new(
            crate::peer_guard::variable_bad_peer_timeout,
        ));
        crate::peer_guard::refresh_guard_full(
            &self.meta_guard,
            &[],
            &ledger,
            &manual,
            &self.global.client_ban_prefixes,
            now,
        );
    }

    /// Re-push the ban face to every running engine (after
    /// ban/unban/list hot change).
    pub(super) async fn push_all_ban_configs(&mut self) {
        // Metadata-phase session snapshot is hot-updated too
        // (extension face) — live magnet tasks see it immediately via
        // arc-swap.
        self.refresh_meta_guard();
        let targets: Vec<EngineHandle> = self
            .running
            .values()
            .filter_map(|t| t.backend.engine().cloned())
            .collect();
        for engine in targets {
            self.push_ban_config(&engine).await;
        }
    }

    /// Startup bootstrap: restore `client_ban_prefixes` from kv (a kv
    /// key is the across-restart truth and overrides the option initial
    /// value) + read back manual peer_ban rows (reason=manual ->
    /// in-memory bookkeeping; a bad row is warned and skipped —
    /// filtering is a hardening face and one corrupt row must not
    /// cripple it, same rule as `ipfilter_row_to_rule`). No persistence
    /// = pure in-memory shape (tests / bare runs).
    pub(super) async fn bootstrap_ban_face(&mut self) {
        let Some(p) = &self.persist else {
            return;
        };
        match p.get_kv(CLIENT_BAN_PREFIXES_KV).await {
            Ok(Some(json)) => match serde_json::from_str::<Vec<String>>(&json) {
                Ok(v) => {
                    let n = v.len();
                    self.global.client_ban_prefixes = v;
                    info!(target: "taiji::core::session", prefixes = n,
                        "client ban prefixes restored (empty list bans no client)");
                }
                Err(e) => {
                    warn!(target: "taiji::core::session", %e,
                        "client ban prefixes kv corrupt; keeping initial value");
                }
            },
            Ok(None) => {}
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "client ban prefixes kv load failed; keeping initial value");
            }
        }
        let now = now_epoch();
        match p.load_active_peer_bans(now).await {
            Ok(rows) => {
                for r in rows {
                    if r.reason != crate::peer_guard::REASON_MANUAL {
                        continue; // auto/client rows are restored engine-side at startup.
                    }
                    // Range comes from the normalized parse (legacy
                    // rows tolerated); target keeps the stored original
                    // text — unban deletes by exact stored text.
                    match parse_manual_target(&r.ip) {
                        Some((_, start, end)) => self.manual_bans.push(ManualBan {
                            target: r.ip.clone(),
                            start,
                            end,
                            until: r.until,
                        }),
                        None => {
                            warn!(target: "taiji::core::session", ip = %r.ip,
                                "stored manual ban target unparsable, skipped");
                        }
                    }
                }
                let n = self.manual_bans.len();
                if n > 0 {
                    info!(target: "taiji::core::session", bans = n,
                        "manual bans restored from peer_ban ");
                }
            }
            Err(e) => {
                warn!(target: "taiji::core::session", %e,
                    "manual ban restore failed (fresh book)");
            }
        }
        // Seed the metadata-phase snapshot with the restored manual
        // bans / list (before this the snapshot is the empty
        // constructor-time face).
        self.refresh_meta_guard();
    }

    /// taiji.banAddr: parse and normalize the target -> bookkeeping
    /// upsert (same target = overwrite with the latest until) ->
    /// persist to peer_ban (reason=manual, timed or permanent) ->
    /// re-push running engines (snapshot hot change + live-connection
    /// drops for hit ranges).
    pub(super) async fn ban_addr(
        &mut self,
        target: String,
        minutes: Option<i64>,
    ) -> Result<CommandReply, SessionError> {
        let (canonical, start, end) = parse_manual_target(&target)
            .ok_or_else(|| SessionError::failed(format!("invalid ban target: {target}")))?;
        let until = match minutes {
            None => i64::MAX,
            Some(m) if m >= 1 => now_epoch().saturating_add(m.saturating_mul(60)),
            Some(m) => {
                return Err(SessionError::failed(format!(
                    "minutes must be a positive integer: {m}"
                )));
            }
        };
        let ban = ManualBan {
            target: canonical.clone(),
            start,
            end,
            until,
        };
        if let Some(pos) = self.manual_bans.iter().position(|b| b.target == canonical) {
            self.manual_bans[pos] = ban;
        } else {
            if self.manual_bans.len() >= MAX_MANUAL_BANS {
                return Err(SessionError::failed(format!(
                    "too many manual bans (cap {MAX_MANUAL_BANS})"
                )));
            }
            self.manual_bans.push(ban);
        }
        if let Some(p) = &self.persist {
            let row = PeerBanRow {
                ip: canonical.clone(),
                reason: crate::peer_guard::REASON_MANUAL.to_string(),
                until,
            };
            if let Err(e) = p.upsert_peer_ban(row).await {
                warn!(target: "taiji::core::session", target = %canonical, %e,
                    "manual ban persist failed (in-memory still live)");
            }
        }
        self.push_all_ban_configs().await;
        info!(target: "taiji::core::session", target = %canonical, until,
            "manual ban enacted (reason=manual, empty list bans no client)");
        Ok(CommandReply::Accepted)
    }

    /// taiji.unbanAddr: exact-match the normalized target in
    /// bookkeeping -> remove -> delete the peer_ban row -> re-push
    /// running engines. Only manual bans are affected (auto/client bans
    /// lift at expiry; there is no RPC removal face for them).
    pub(super) async fn unban_addr(
        &mut self,
        target: String,
    ) -> Result<CommandReply, SessionError> {
        let (canonical, _, _) = parse_manual_target(&target)
            .ok_or_else(|| SessionError::failed(format!("invalid ban target: {target}")))?;
        let pos = self
            .manual_bans
            .iter()
            .position(|b| b.target == canonical)
            .ok_or_else(|| SessionError::failed(format!("no such ban: {canonical}")))?;
        self.manual_bans.remove(pos);
        if let Some(p) = &self.persist {
            if let Err(e) = p.delete_peer_ban(&canonical).await {
                warn!(target: "taiji::core::session", target = %canonical, %e,
                    "manual ban delete persist failed (in-memory already removed)");
            }
        }
        self.push_all_ban_configs().await;
        info!(target: "taiji::core::session", target = %canonical,
            "manual ban lifted ");
        Ok(CommandReply::Accepted)
    }

    /// taiji.listBans: snapshot of active bans = this session's manual
    /// bookkeeping (unexpired) union peer_ban active rows (auto + client
    /// identity; manual rows deduped with the bookkeeping as authority).
    /// No persistence = bookkeeping only (auto bans live in engine
    /// memory or the store; no store = no history). Sorted by (source,
    /// target).
    pub(super) async fn list_bans(&self) -> Result<CommandReply, SessionError> {
        let now = now_epoch();
        let mut out: Vec<BanEntryView> = Vec::new();
        for b in self.manual_bans.iter().filter(|b| b.until > now) {
            out.push(BanEntryView {
                target: b.target.clone(),
                reason: crate::peer_guard::REASON_MANUAL.to_string(),
                until: b.until,
                source: BanSource::Manual,
            });
        }
        if let Some(p) = &self.persist {
            match p.load_active_peer_bans(now).await {
                Ok(rows) => {
                    for r in rows {
                        let source = ban_source(&r.reason);
                        if source == BanSource::Manual && out.iter().any(|b| b.target == r.ip) {
                            continue; // manual rows defer to the bookkeeping (same-key dedup).
                        }
                        out.push(BanEntryView {
                            target: r.ip,
                            reason: r.reason,
                            until: r.until,
                            source,
                        });
                    }
                }
                Err(e) => {
                    warn!(target: "taiji::core::session", %e,
                        "active peer ban load failed (manual book only)");
                }
            }
        }
        out.sort_by(|a, b| (&a.source, &a.target).cmp(&(&b.source, &b.target)));
        Ok(CommandReply::Bans(out))
    }

    /// List hot-change wrap-up (changeGlobalOption
    /// client-ban-prefixes arm): kv persist (the across-restart truth) +
    /// re-push running engines.
    pub(super) async fn apply_client_ban_change(&mut self) {
        if let Some(p) = &self.persist {
            // A serialization failure skips the kv write (the in-memory
            // face stays live; the previously persisted list is kept): a
            // fallback "[]" payload would silently clear the across-restart
            // bans — the same skip-and-warn face as every other persist
            // failure in this file.
            match serde_json::to_string(&self.global.client_ban_prefixes) {
                Ok(json) => {
                    if let Err(e) = p.put_kv(CLIENT_BAN_PREFIXES_KV, &json).await {
                        warn!(target: "taiji::core::session", %e,
                            "client ban prefixes persist failed (in-memory still live)");
                    }
                }
                Err(e) => {
                    warn!(target: "taiji::core::session", %e,
                        "client ban prefixes serialize failed; kv write skipped (in-memory live)");
                }
            }
        }
        self.push_all_ban_configs().await;
        info!(target: "taiji::core::session",
            prefixes = self.global.client_ban_prefixes.len(),
            "client ban prefixes changed (empty list bans no client)");
    }

    // ---- Scheduler policy switch face (taiji.set/getSchedulerPolicy) ----

    /// taiji.setSchedulerPolicy: support validation (rarest_first/
    /// streaming are configurable; sequential is unimplemented and
    /// fails explicitly, sharing the engine-side text) -> torrent job
    /// mirror update -> atomic `SetSchedulerPolicy` policy-object swap
    /// on the running engine (waits for the engine receipt) ->
    /// config_json rewrite (survives restart). Metadata tasks
    /// (magnet/URL fetch) are refused explicitly — same rule as
    /// changeUri (only the post-upgrade torrent face is editable).
    pub(super) async fn set_scheduler_policy(
        &mut self,
        raw_gid: String,
        policy: crate::engine::SchedulerPolicy,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(&raw_gid)?;
        if !policy.is_supported() {
            return Err(SessionError::failed(format!(
                "scheduler policy '{}' is not implemented yet",
                policy.name()
            )));
        }
        if !matches!(self.jobs.get(&gid), Some(Job::Torrent(_))) {
            return Err(SessionError::failed(format!(
                "taiji.setSchedulerPolicy: requires a torrent task (GID#{gid})"
            )));
        }
        if let Some(engine) = self.running.get(&gid).and_then(|t| t.backend.engine()) {
            engine.set_scheduler_policy(policy.clone()).await?;
        }
        if let Some(Job::Torrent(tj)) = self.jobs.get_mut(&gid) {
            tj.scheduler_policy = policy.clone();
        }
        self.persist_refresh_config(gid).await;
        info!(target: "taiji::core::session", gid = %gid, policy = policy.name(),
            "scheduler policy updated ");
        Ok(CommandReply::Accepted)
    }

    /// taiji.getSchedulerPolicy: torrent jobs answer from the job
    /// mirror; magnet/URL metadata tasks and finished tasks answer the
    /// default (the policy face persists with the torrent job, not a
    /// fabricated configurable face).
    pub(super) fn get_scheduler_policy(&self, raw_gid: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw_gid)?;
        let policy = match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => tj.scheduler_policy.clone(),
            _ => crate::engine::SchedulerPolicy::default(),
        };
        Ok(CommandReply::SchedulerPolicy { policy })
    }

    /// taiji.setFilePriority: partial update of per-file priority
    /// levels as decided pairs (unlisted files untouched). Validation
    /// order — everything before any mirror change, so a rejected call
    /// has zero side effects: gid resolution -> torrent gate
    /// (magnet/URL metadata and HTTP = explicit Err, the file face
    /// belongs to torrent jobs) -> pairs parse (1-based -> 0-based,
    /// level domain -1..=7, duplicate and out-of-range indexes explicit
    /// Err; file count = metadata non-padding entries) -> sparse-table
    /// merge simulation + selection-face recomputation (-1 removes,
    /// 0..=7 includes; the priority table is the single truth and
    /// selected_files its projection) -> an empty selection is an
    /// explicit Err (the engine rejects an empty mask with the same
    /// meaning). After validation: live push to the active engine
    /// (SetFileSelection + SetFilePriority as a pair — skip face and
    /// selection order change together) -> mirror rewrite ->
    /// config_json rewrite (survives restart). Waiting/paused tasks
    /// have no engine = mirror + persistence only (pushed at
    /// activation, same shape as the select-file Reserved face).
    pub(super) async fn set_file_priority(
        &mut self,
        raw_gid: String,
        pairs: Vec<(u32, i8)>,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(&raw_gid)?;
        if !matches!(self.jobs.get(&gid), Some(Job::Torrent(_))) {
            return Err(SessionError::failed(format!(
                "taiji.setFilePriority: requires a torrent task (GID#{raw_gid})"
            )));
        }
        if pairs.is_empty() {
            return Err(SessionError::failed(
                "taiji.setFilePriority: empty priority table",
            ));
        }
        let real_count = {
            let Some(Job::Torrent(tj)) = self.jobs.get(&gid) else {
                // The gate above passed; a refetch miss means the
                // invariant broke — fail explicitly, never panic.
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: task GID#{raw_gid} is not a torrent job"
                )));
            };
            tj.metainfo.meta.files.iter().filter(|f| !f.padding).count() as u32
        };
        // 1-based -> 0-based + domain validation + duplicate rejection
        // (the same three tightenings as the select-file parse:
        // illegal input is rejected explicitly, never silently
        // absorbed).
        let mut patch: Vec<(u32, i8)> = Vec::with_capacity(pairs.len());
        // Duplicate check via HashSet (removes the O(p^2) patch
        // scan).
        let mut patch_seen: std::collections::HashSet<u32> =
            std::collections::HashSet::with_capacity(pairs.len());
        for (index, level) in pairs {
            if index == 0 || index > real_count {
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: file index {index} out of range ({real_count} files)"
                )));
            }
            if !(-1..=7).contains(&level) {
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: priority {level} out of range (-1..=7)"
                )));
            }
            let zero_based = index - 1;
            if !patch_seen.insert(zero_based) {
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: duplicate file index {index}"
                )));
            }
            patch.push((zero_based, level));
        }
        // Merge simulation + selection recompute (validate before
        // mutate — a rejected call leaves no side effects). Both the
        // merge and the selection recompute are HashMap-based (removes
        // the O(p*t + n*t) linear scans on the RPC hot path of
        // large-file tasks).
        let (merged, selection) = {
            let Some(Job::Torrent(tj)) = self.jobs.get(&gid) else {
                // Same defensive face as the real_count refetch: the
                // gate above passed, so a miss here fails explicitly.
                return Err(SessionError::failed(format!(
                    "taiji.setFilePriority: task GID#{raw_gid} is not a torrent job"
                )));
            };
            let mut table: Vec<(u32, i8)> = tj.file_priorities.clone().unwrap_or_default();
            let mut table_map: std::collections::HashMap<u32, i8> = table.iter().copied().collect();
            for (i, q) in &patch {
                table_map.insert(*i, *q);
            }
            table = table_map.iter().map(|(&i, &q)| (i, q)).collect();
            table.sort_by_key(|(i, _)| *i);
            let selected: Vec<u32> = (0..real_count)
                .filter(|i| table_map.get(i).is_none_or(|&q| q != -1))
                .collect();
            if selected.is_empty() {
                return Err(SessionError::failed(
                    "taiji.setFilePriority: all files skipped (empty selection)",
                ));
            }
            (table, selected)
        };
        // Live push to the active engine (selection + priority as a
        // pair; the engine re-validates defensively). Engine offline
        // (waiting/paused) = pushed at activation.
        if let Some(engine) = self.running.get(&gid).and_then(|t| t.backend.engine()) {
            engine
                .set_file_selection(Arc::from(selection.as_slice()))
                .await?;
            let sparse: Vec<(u32, i8)> = merged.iter().filter(|&(_, q)| q != &0).copied().collect();
            let push = if sparse.is_empty() {
                // All levels fall back to 0 = the default face (the
                // engine rejects an empty table, so a single (0,0)
                // placeholder expresses "clear priorities"; the
                // engine's all-zero default reads the same).
                vec![(0u32, 0i8)]
            } else {
                sparse
            };
            engine.set_file_priority(Arc::from(push.as_slice())).await?;
        }
        if let Some(Job::Torrent(tj)) = self.jobs.get_mut(&gid) {
            // Single truth = the priority table; selected_files is its
            // projection (-1 = removed).
            let sparse: Vec<(u32, i8)> = merged.iter().filter(|&(_, q)| q != &0).copied().collect();
            tj.file_priorities = (!sparse.is_empty()).then_some(sparse);
            tj.selected_files = Some(selection);
        }
        // Row projection sync (torrent_file.selected/priority columns
        // rewrite with the mirror; config_json is the single truth and
        // the row columns are the externally visible projection).
        let key = gid.to_string();
        if let Some(Job::Torrent(tj)) = self.jobs.get(&gid) {
            if let Some((_, files)) = self.rows.get_mut(&key) {
                *files = super::super::persist::file_rows_with_face(
                    &key,
                    &tj.metainfo.meta.files,
                    tj.selected_files.as_deref(),
                    tj.file_priorities.as_deref(),
                );
            }
        }
        self.persist_refresh_config(gid).await;
        info!(target: "taiji::core::session", gid = %gid, entries = patch.len(),
            "file priority updated");
        Ok(CommandReply::Accepted)
    }

    /// taiji.setStreamingPlayhead: push the streaming playhead at
    /// runtime. Torrent tasks only (GID validation as in
    /// setSchedulerPolicy) and only with a **running engine**
    /// (paused/waiting/metadata phase = explicit Err — no fabricated
    /// replayable playhead state; after a restart the caller replays by
    /// progress). Forwards `EngineCommand::SetStreamingPlayhead`
    /// (out-of-range file/position = an explicit engine-side Err) and
    /// waits for the receipt; **no mirror write, no persistence** — the
    /// playhead is a high-frequency transient cursor whose truth lives
    /// in the engine. It only affects selection under the streaming
    /// policy (switching = taiji.setSchedulerPolicy(streaming) plus
    /// this command, in either order).
    pub(super) async fn set_streaming_playhead(
        &mut self,
        raw_gid: String,
        file: u32,
        position: u64,
        bytes_per_sec: Option<u64>,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(&raw_gid)?;
        if !matches!(self.jobs.get(&gid), Some(Job::Torrent(_))) {
            return Err(SessionError::failed(format!(
                "taiji.setStreamingPlayhead: requires a torrent task (GID#{gid})"
            )));
        }
        let Some(engine) = self.running.get(&gid).and_then(|t| t.backend.engine()) else {
            return Err(SessionError::failed(format!(
                "taiji.setStreamingPlayhead: task GID#{gid} has no active engine \
                 (start the task and retry)"
            )));
        };
        engine
            .set_streaming_playhead(file, position, bytes_per_sec)
            .await?;
        info!(target: "taiji::core::session", gid = %gid, file, position,
            bps = ?bytes_per_sec,
            "streaming playhead updated ");
        Ok(CommandReply::Accepted)
    }

    // ---- disk_tier RPC face ----

    /// taiji.getDiskTier: read back the task's current disk tier.
    /// Truth = the torrent job mirror (config_json `disk_tier`, same
    /// source); magnet/URL metadata tasks and finished tasks answer the
    /// default (throughput — the tier face persists with the torrent
    /// job, same rule as getSchedulerPolicy). Unknown mirror names
    /// degrade through
    /// [`taiji_store::disk_policy::DiskPolicy::resolve`] (warn
    /// visible); the core layer always answers a known name.
    pub(super) fn get_disk_tier(&self, raw_gid: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw_gid)?;
        let tier = match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => {
                taiji_store::disk_policy::DiskPolicy::resolve(tj.disk_tier.as_deref()).tier
            }
            _ => taiji_store::disk_policy::DiskTier::Throughput,
        };
        Ok(CommandReply::DiskTier { tier })
    }

    /// taiji.setDiskTier: per-torrent disk tier switch, torrent tasks
    /// only (metadata tasks are refused as in setSchedulerPolicy; only
    /// the post-upgrade torrent face is editable). Order: live
    /// `EngineCommand::SetDiskPolicy` on the running engine (IoGate
    /// quota / flush cadence / write-merge window shift immediately;
    /// waits for the engine command receipt) -> job mirror update ->
    /// config_json rewrite (restored across restarts via
    /// `DiskPolicy::resolve` in the activation chain). **prealloc/falloc
    /// applies to new allocations only** (existing files were allocated
    /// when the pipeline was built; a running task never
    /// re-allocates).
    pub(super) async fn set_disk_tier(
        &mut self,
        raw_gid: String,
        tier: taiji_store::disk_policy::DiskTier,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(&raw_gid)?;
        if !matches!(self.jobs.get(&gid), Some(Job::Torrent(_))) {
            return Err(SessionError::failed(format!(
                "taiji.setDiskTier: requires a torrent task (GID#{gid})"
            )));
        }
        if let Some(engine) = self.running.get(&gid).and_then(|t| t.backend.engine()) {
            engine.set_disk_policy(tier.policy()).await?;
        }
        if let Some(Job::Torrent(tj)) = self.jobs.get_mut(&gid) {
            tj.disk_tier = Some(tier.name().to_string());
        }
        self.persist_refresh_config(gid).await;
        info!(target: "taiji::core::session", gid = %gid, tier = tier.name(),
            "disk tier updated (live io-gate/flush/merge for running engine, \
             prealloc applies to new allocations only)");
        Ok(CommandReply::Accepted)
    }

    // ---- GID resolution (expandUnique, up front for every
    // gid-taking method) ----

    /// str2Gid semantics (RpcMethodImpl.cc + GroupId.cc): the prefix is
    /// uniquely expanded over active ∪ waiting ∪ results; error texts
    /// are direct translations quoting the original input string.
    pub(super) fn resolve_gid(&self, raw: &str) -> Result<Gid, SessionError> {
        let known = self.queue.known_gids();
        match expand_unique(raw, &known) {
            Ok(gid) => Ok(gid),
            Err(GidResolveError::Invalid) => {
                Err(SessionError::failed(format!("Invalid GID {raw}")))
            }
            Err(GidResolveError::NotFound) => {
                Err(SessionError::failed(format!("GID {raw} is not found")))
            }
            Err(GidResolveError::NotUnique) => {
                Err(SessionError::failed(format!("GID {raw} is not unique")))
            }
        }
    }

    /// tellStatus two-source aggregation (RpcMethodImpl.cc): active/
    /// waiting first, then DownloadResult; neither -> "No such download
    /// for GID#%s". `&mut self`: the active live view reads through the
    /// engine status snapshot cache (backfilled when stale or
    /// missing).
    pub(super) async fn tell_status(&mut self, raw: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw)?;
        let view = match self.queue.find(gid) {
            Some(Location::Active) => self.live_status_view(gid).await,
            // In-recheck: active-semantics projection + check progress
            // (checked pieces x piece_length, clamped to total).
            Some(Location::Checking | Location::CheckingPaused) => self.checking_status_view(gid),
            // Seeding residence: the engine is live — the live view
            // face with the 'seeding' status (the projection
            // finalization: residence and seed_wait share
            // the row state, the projection follows; the interim
            // of projecting residents as 'active' is closed).
            // The tellActive seeding segment shares this exact face
            // ([`Self::seeding_live_view`]).
            Some(Location::Seeding) => self.seeding_live_view(gid).await,
            // Parked in the seed FIFO: the base view with the
            // 'seeding' extended status.
            Some(Location::SeedWaiting) => self.base_status_view(gid, StatusKind::Seeding),
            // Synthesis pool: the driver is live —
            // the same live view as Active (the media sub-dictionary
            // carries the Processing/Verifying phases; the status
            // stays 'active', the numActive *meter* is
            // download-slots-only).
            Some(Location::Synthesizing) => self.live_status_view(gid).await,
            // Parked at the synthesis gate: the base view with the
            // 'waiting' status — the existing value, zero extension
            // (the gate hang is an in-task phase, §4.3/§5).
            Some(Location::SynthesisWaiting) => self.base_status_view(gid, StatusKind::Waiting),
            Some(Location::Reserved | Location::ReservedPaused) => {
                let status = match self.queue.reserved_entry(gid) {
                    Some(e) if e.paused => StatusKind::Paused,
                    _ => StatusKind::Waiting,
                };
                self.base_status_view(gid, status)
            }
            Some(Location::Result) => {
                let entry = self
                    .queue
                    .results()
                    .find(|r| r.gid == gid)
                    .cloned()
                    .unwrap_or_else(|| self.build_result_entry(gid, StatusKind::Error, 0, 0, None));
                self.result_status_view(&entry)
            }
            None => {
                return Err(SessionError::failed(format!(
                    "No such download for GID#{gid}"
                )));
            }
        };
        Ok(CommandReply::TorrentStatus(Box::new(view)))
    }

    /// getFiles (RpcMethodImpl.cc: group or result table; neither ->
    /// "No file data is available for GID#%s"). `&mut self`: the active
    /// live view reads through the engine status snapshot cache
    /// (backfilled when stale or missing).
    pub(super) async fn get_files(&mut self, raw: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw)?;
        let files = match self.queue.find(gid) {
            Some(Location::Active) => self.live_status_view(gid).await.files,
            // In-recheck: files project from metadata (progress unknown
            // -> completed all 0, same shape as the waiting face; check
            // progress rides tellStatus.completedLength).
            Some(Location::Checking | Location::CheckingPaused) => {
                self.checking_status_view(gid).files
            }
            // Seeding residence: live engine, live file view (the same
            // face as Active); a parked seed_wait member projects from
            // metadata (the base view's file face).
            Some(Location::Seeding) => self.live_status_view(gid).await.files,
            Some(Location::SeedWaiting) => self.base_status_view(gid, StatusKind::Seeding).files,
            // Synthesis pool: the live file view for an
            // in-flight synthesis; a gate-hung member projects from
            // metadata (the base view's file face).
            Some(Location::Synthesizing) => self.live_status_view(gid).await.files,
            Some(Location::SynthesisWaiting) => {
                self.base_status_view(gid, StatusKind::Waiting).files
            }
            Some(Location::Reserved | Location::ReservedPaused) => {
                self.base_status_view(gid, StatusKind::Waiting).files
            }
            Some(Location::Result) => self
                .queue
                .results()
                .find(|r| r.gid == gid)
                .map(|r| r.files.clone())
                .unwrap_or_default(),
            None => {
                return Err(SessionError::failed(format!(
                    "No file data is available for GID#{gid}"
                )));
            }
        };
        Ok(CommandReply::Files(files))
    }

    /// getPeers (RpcMethodImpl.cc: findGroup hits only; no peer face =
    /// an empty table, not an error; unknown group -> "No peer data is
    /// available for GID#%s").
    pub(super) async fn get_peers(&self, raw: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw)?;
        match self.queue.find(gid) {
            Some(Location::Active) => {
                let peers = match self
                    .running
                    .get(&gid)
                    .and_then(|t| t.backend.engine().cloned())
                {
                    // aria2 getPeers always carries a bitfield (the
                    // local switch only silences internal counting).
                    Some(engine) => engine.query_peers().await.unwrap_or_default(),
                    None => Vec::new(),
                };
                let views = peers
                    .into_iter()
                    .map(|p| PeerEntryView {
                        peer_id: Some(p.peer_id),
                        ip: p.ip,
                        port: p.port,
                        bitfield: p.bitfield,
                        am_choking: p.am_choking,
                        peer_choking: p.peer_choking,
                        download_speed: p.download_speed,
                        upload_speed: p.upload_speed,
                        seeder: p.seeder,
                        // Live wire: the real transport from the
                        // connection-point snapshot (dial-plan winner /
                        // accepted listener).
                        transport: match p.transport {
                            taiji_bt::utp::Transport::Tcp => PeerTransportKind::Tcp,
                            taiji_bt::utp::Transport::Utp => PeerTransportKind::Utp,
                        },
                        crypto: match p.crypto {
                            taiji_bt::mse::CryptoLevel::Plain => PeerCryptoKind::Plain,
                            taiji_bt::mse::CryptoLevel::Arc4 => PeerCryptoKind::Arc4,
                        },
                    })
                    .collect();
                Ok(CommandReply::Peers(views))
            }
            Some(Location::Reserved | Location::ReservedPaused) => {
                Ok(CommandReply::Peers(Vec::new()))
            }
            // In-recheck tasks have no engine (no peer face) — an
            // empty table, like reserved.
            Some(Location::Checking | Location::CheckingPaused) => {
                Ok(CommandReply::Peers(Vec::new()))
            }
            // Seeding residence: the engine is live —
            // the same live peer face as Active. A parked seed_wait
            // member has no engine (the empty-table shape).
            Some(Location::Seeding) => {
                let peers = match self
                    .running
                    .get(&gid)
                    .and_then(|t| t.backend.engine().cloned())
                {
                    Some(engine) => engine.query_peers().await.unwrap_or_default(),
                    None => Vec::new(),
                };
                let views = peers
                    .into_iter()
                    .map(|p| PeerEntryView {
                        peer_id: Some(p.peer_id),
                        ip: p.ip,
                        port: p.port,
                        bitfield: p.bitfield,
                        am_choking: p.am_choking,
                        peer_choking: p.peer_choking,
                        download_speed: p.download_speed,
                        upload_speed: p.upload_speed,
                        seeder: p.seeder,
                        transport: match p.transport {
                            taiji_bt::utp::Transport::Tcp => PeerTransportKind::Tcp,
                            taiji_bt::utp::Transport::Utp => PeerTransportKind::Utp,
                        },
                        crypto: match p.crypto {
                            taiji_bt::mse::CryptoLevel::Plain => PeerCryptoKind::Plain,
                            taiji_bt::mse::CryptoLevel::Arc4 => PeerCryptoKind::Arc4,
                        },
                    })
                    .collect();
                Ok(CommandReply::Peers(views))
            }
            Some(Location::SeedWaiting) => Ok(CommandReply::Peers(Vec::new())),
            // Synthesis pool: media tasks have no peer
            // face — an empty table for both the in-flight and parked
            // forms (the checking/SeedWaiting shapes).
            Some(Location::Synthesizing) | Some(Location::SynthesisWaiting) => {
                Ok(CommandReply::Peers(Vec::new()))
            }
            _ => Err(SessionError::failed(format!(
                "No peer data is available for GID#{gid}"
            ))),
        }
    }

    /// getServers (RpcMethodImpl.cc: ACTIVE groups only; anything else
    /// -> "No active download for GID#%s"; SPEC §8.2 tracker-perspective
    /// snapshot).
    pub(super) async fn get_servers(&self, raw: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw)?;
        // Seeding residence joins the active face: the
        // engine is live and the tracker table persists (aria2's detached
        // group stays in the active list, getServers answers the same).
        if !self.queue.contains_active(gid) && !self.queue.contains_seeding(gid) {
            return Err(SessionError::failed(format!(
                "No active download for GID#{gid}"
            )));
        }
        // HTTP task: the source list is the server face (aria2 HTTP
        // semantics — one server entry per URI; the tracker snapshot
        // face is BT-only).
        //
        // Declared method diff: aria2 getServers emits one entry per
        // in-flight request (`fe->getInFlightRequests()`,
        // RpcMethodImpl.cc — several connections to one server produce
        // several rows); here one aggregated row per source (state/rate
        // follow the source). The status projection shares the source
        // ledger with the `http.sources` sub-dictionary
        // ([`http_source_server_status`]): the terminal states
        // demoted/removed/failed never collapse back to waiting.
        // downloadSpeed is the per-source measured rate (aria2 reports
        // a request-level rate); the extra tier/status keys (absent
        // from the aria2 server dict) follow the SPEC §8.2 tracker view
        // and are part of the declared diff.
        if let Some(Job::Http(_)) = self.jobs.get(&gid) {
            let views = self
                .running
                .get(&gid)
                .and_then(|t| t.backend.http_live())
                .map(|live| {
                    live.http_view()
                        .sources
                        .iter()
                        .map(|s| ServerEntryView {
                            url: s.url.clone(),
                            tier: 1,
                            status: http_source_server_status(s.state),
                            seeds: None,
                            leechers: None,
                            download_speed: s.rate,
                        })
                        .collect()
                })
                .unwrap_or_default();
            return Ok(CommandReply::Servers(views));
        }
        let rows = match self
            .running
            .get(&gid)
            .and_then(|t| t.backend.engine().cloned())
        {
            Some(engine) => engine.query_trackers().await.unwrap_or_default(),
            None => Vec::new(),
        };
        let views = rows
            .into_iter()
            .map(|row| {
                let status = if !row.enabled {
                    ServerStatus::Disabled
                } else if row.last_error.is_some() {
                    ServerStatus::Error
                } else if row.last_ok_at.is_some() {
                    ServerStatus::Working
                } else {
                    ServerStatus::Waiting
                };
                ServerEntryView {
                    url: row.url,
                    tier: row.tier,
                    status,
                    seeds: row.seeds,
                    leechers: row.leechers,
                    // BT tracker snapshots carry no live rate (aria2
                    // tracker entries behave the same — rates are only
                    // measured on the HTTP server face).
                    download_speed: 0,
                }
            })
            .collect();
        Ok(CommandReply::Servers(views))
    }

    /// getUris (SPEC §8.2: the magnet/metadata URI; aria2
    /// createUriEntry uses used/waiting; unknown group -> "No URI data
    /// is available for GID#%s").
    ///
    /// Declared method diff: status cross-validates `getSpentUris` /
    /// `getRemainingUris` (RpcMethodImpl.cc) — "used" = spent (has been
    /// requested). An activated HTTP task has probed every source, so
    /// all URIs are "used"; a task that never ran (queued/paused) is
    /// all "waiting" (aria2 without a start has no spent URIs either).
    /// Scheduling state (a worker in flight) does not change the spend
    /// fact and is not a signal. aria2 errors on the stopped face
    /// (findGroup excludes the result table); same rule here (jobs are
    /// removed at teardown).
    pub(super) fn get_uris(&self, raw: &str) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw)?;
        match self.jobs.get(&gid) {
            Some(Job::Magnet(mj)) => Ok(CommandReply::Uris(vec![UriEntryView {
                uri: mj.magnet_uri.clone(),
                status: UriStatus::Used,
            }])),
            Some(Job::TorrentUrl { url, .. }) => Ok(CommandReply::Uris(vec![UriEntryView {
                uri: url.clone(),
                status: UriStatus::Used,
            }])),
            // HTTP task: the source list is the URI face (one item per
            // source, user order). status follows spent/remaining:
            // activation probes every source, so every URI has been
            // requested ("used"); a task that never ran (queued/paused)
            // is all "waiting". Scheduling state (a worker in flight)
            // does not change the spend fact.
            Some(Job::Http(hj)) => {
                let activated = hj.mirror.is_some()
                    || self.running.get(&gid).is_some_and(|t| t.backend.is_http());
                Ok(CommandReply::Uris(
                    hj.uris
                        .iter()
                        .map(|u| UriEntryView {
                            uri: u.clone(),
                            status: if activated {
                                UriStatus::Used
                            } else {
                                UriStatus::Waiting
                            },
                        })
                        .collect(),
                ))
            }
            // .torrent direct-add tasks have no webseed URI face (BEP19
            // P2) -> empty.
            Some(Job::Torrent(_)) => Ok(CommandReply::Uris(Vec::new())),
            // Media task: the entry URL is the URI face (one item;
            // "used" once activated).
            Some(Job::Media(mj)) => {
                let activated = self.running.contains_key(&gid);
                Ok(CommandReply::Uris(vec![UriEntryView {
                    uri: mj.cfg.url.clone(),
                    status: if activated {
                        UriStatus::Used
                    } else {
                        UriStatus::Waiting
                    },
                }]))
            }
            None => Err(SessionError::failed(format!(
                "No URI data is available for GID#{gid}"
            ))),
        }
    }

    /// getGlobalStat (RpcMethodImpl.cc + the four-pool extension
    /// keys): speeds = the sum of active engines' 10s sliding-window
    /// readings plus the HTTP live drive-tick rate (HTTP tasks were
    /// previously missing from downloadSpeed); counters come from queue
    /// bookkeeping. BT engine speeds read through the per-engine status
    /// snapshot cache (zero round trips within [`STATUS_CACHE_TTL`] —
    /// the single-threaded actor no longer performs O(active tasks)
    /// engine round trips; invalidation rides the TaskNotice event
    /// arm); HTTP rates stay an atomic synchronous read.
    ///
    /// Counter caliber (the formalized caliber):
    /// numActive = download-slot occupancy only (seeding / checking /
    /// synthesis hold no download slot — the queue-side meter already
    /// narrowed with the four-pool transfers; the caliber test pins
    /// it); numWaiting = the four waiting segments merged (the
    /// tellWaiting caliber — one source, the queue's waiting snapshot);
    /// numSeeding/numChecking/numSynthesizing = the three pools
    /// **in flight only** (their waiting FIFOs are not included — a
    /// waiting-pool breakdown rides the client-side tellWaiting status
    /// histogram, no third-layer keys).
    pub(super) async fn get_global_stat(&mut self) -> Result<CommandReply, SessionError> {
        let mut download_speed = 0u64;
        let mut upload_speed = 0u64;
        // Snapshot (gid, http_live) pairs first, then aggregate (avoids
        // a traversal borrow across await); per-gid reads go through
        // the cache (an engine failure skips that task).
        type MediaLiveArc = Arc<std::sync::Mutex<crate::session::media::MediaLiveState>>;
        let entries: Vec<(Gid, Option<Arc<http_task::HttpLive>>, Option<MediaLiveArc>)> = self
            .running
            .iter()
            .map(|(gid, t)| {
                (
                    *gid,
                    t.backend.http_live().cloned(),
                    t.backend.media_live().cloned(),
                )
            })
            .collect();
        for (gid, http_live, media_live) in entries {
            if let Some(live) = http_live {
                download_speed += live.rate.load(std::sync::atomic::Ordering::Relaxed);
            }
            // Media tasks: the whole-task rate rollup — the speed face
            // is live-task-wide (a synthesis in progress rolls in
            // here), while the numActive *meter* is caliber-bound to
            // the download slots (a processing-phase media task
            // sits in the synthesis pool, not in numActive; its speed
            // still belongs to the session's speed aggregate).
            if let Some(live) = media_live {
                let st = crate::lock(&live);
                download_speed += st.rate;
            }
            if let Some(snap) = self.engine_status_cached(gid).await {
                download_speed += snap.download_speed;
                upload_speed += snap.upload_speed;
            }
        }
        Ok(CommandReply::GlobalStat(GlobalStatView {
            download_speed,
            upload_speed,
            num_active: self.queue.active_len() as u64,
            num_waiting: self.queue.waiting_snapshot().len() as u64,
            num_stopped: self.queue.results().count() as u64,
            num_stopped_total: self.queue.num_stopped_total(),
            num_seeding: self.queue.seeding_len() as u64,
            num_checking: self.queue.checking_len() as u64,
            num_synthesizing: self.queue.processing_len() as u64,
        }))
    }

    // ---- Waiting-queue reorder ----

    /// changePosition (RpcMethodImpl.cc + RequestGroupMan.cc direct
    /// translation, extended to the four-pool waiting domain): gid
    /// prefix resolution (str2Gid ->
    /// expandUnique) -> waiting-domain dispatch ([`QueueMan::
    /// move_waiting`]) ->
    ///
    /// - **reserved segment** (the aria2 face, semantics unchanged):
    ///   the [`QueueMan::move_reserved`] three-mode reorder
    ///   (IndexedList.h direct translation); an in-place reorder
    ///   (dest == current, e.g. POS_CUR clamped to 0 or a single
    ///   element) leaves the order unchanged and skips the queue_pos
    ///   rewrite; an actual move renumbers the whole segment and
    ///   persists it ([`Self::persist_queue_renumber`]).
    /// - **three phase FIFO segments** (check_pending / seed_wait /
    ///   proc_wait — the §5 revision): POS_SET / POS_CUR / POS_END are
    ///   interpreted **inside the owning segment** (a phase segment is
    ///   a resource domain — the move never crosses the segment
    ///   boundary, the raw destination clamps into the segment's own
    ///   head/tail); the reply position is in the same segment-local
    ///   space (request space = reply space). Paused/flag payloads
    ///   ride untouched (the reserved segment's move-paused precedent).
    ///   **Zero persistence** — segment positions are runtime ordering
    ///   (proc_wait is never persisted §4.3; check_pending / seed_wait
    ///   rebuild from the batch-restore/restart order), zero schema.
    ///
    /// Anything outside the four waiting segments (active, seeding
    /// residence, in-flight recheck, synthesis in flight, results,
    /// unknown) fails with the reference
    /// `changeReservedGroupPosition` -1 text
    /// `"GID#%s not found in the waiting queue."` (aria2 moves the
    /// waiting domain only). No pump: a non-empty waiting queue
    /// implies full concurrency slots (fillup semantics), so a reorder
    /// never creates an activation opportunity.
    pub(super) async fn change_position(
        &mut self,
        raw_gid: &str,
        pos: i64,
        how: OffsetMode,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(raw_gid)?;
        let Some(moved) = self.queue.move_waiting(gid, pos, how) else {
            return Err(SessionError::failed(format!(
                "GID#{gid} not found in the waiting queue."
            )));
        };
        // Only the reserved segment owns the persisted face: an actual
        // (non-in-place) move renumbers the queue_pos keys; a phase-FIFO
        // move is runtime-only ordering.
        if moved.segment == WaitingSegment::Reserved && moved.from != moved.to {
            self.persist_queue_renumber().await;
        }
        info!(target: "taiji::core::session", gid = %gid, from = moved.from, dest = moved.to,
            segment = ?moved.segment,
            "waiting queue position changed");
        Ok(CommandReply::Position {
            position: moved.to as u64,
        })
    }

    // ---- Options ----

    /// Per-task DHT effective value (single synthesis point): session
    /// `enable-dht` combined with a task `bt-disable-dht` override
    /// (None = follow the session; private torrents are suppressed
    /// engine-side by the BEP-27 gate, invisible here).
    fn effective_task_dht(&self, gid: &Gid) -> bool {
        let disable = match self.jobs.get(gid) {
            Some(Job::Torrent(tj)) => tj.bt_disable_dht,
            Some(Job::Magnet(mj)) => mj.bt_disable_dht,
            _ => None,
        };
        self.global.enable_dht && !disable.unwrap_or(false)
    }

    /// Session-level enable-dht flip -> hot-push every running BT
    /// engine. Idempotent: same-state engines answer Ok no-op
    /// (engine-side gate); per-task explicit overrides are applied in
    /// [`Self::effective_task_dht`] (overridden tasks never follow the
    /// session flip). Magnet metadata-phase tasks hold no engine handle
    /// (the lease belongs to the phase; the upgrade chain consumes
    /// it).
    pub(super) async fn push_dht_session_change(&mut self) {
        for (gid, t) in self.running.iter() {
            let Some(engine) = t.backend.engine() else {
                continue;
            };
            let effective = self.effective_task_dht(gid);
            let pushed = if effective {
                engine.enable_dht().await
            } else {
                engine.disable_dht().await
            };
            match pushed {
                Ok(()) => {
                    info!(target: "taiji::core::session", gid = %gid,
                        dht_enabled = effective,
                        "session dht flip pushed to running engine");
                }
                Err(e) => {
                    // Engine already gone / private rejection (BEP-27)
                    // — warn, no disguise.
                    warn!(target: "taiji::core::session", gid = %gid, %e,
                        "session dht flip push skipped");
                }
            }
        }
    }

    /// Per-task `bt-disable-dht` hot change -> push to that task's
    /// active engine (counterpart of libtorrent
    /// `torrent_handle::set_flags(disable_dht)` runtime flips). Waiting
    /// tasks have no engine (the activation chain composes from the
    /// flag); magnet metadata phase likewise (upgrade-chain
    /// consumed).
    pub(super) async fn push_dht_task_change(&mut self, gid: Gid) {
        let Some(t) = self.running.get(&gid) else {
            return;
        };
        let Some(engine) = t.backend.engine() else {
            return;
        };
        let effective = self.effective_task_dht(&gid);
        let pushed = if effective {
            engine.enable_dht().await
        } else {
            engine.disable_dht().await
        };
        match pushed {
            Ok(()) => {
                info!(target: "taiji::core::session", gid = %gid,
                    dht_enabled = effective,
                    "task dht flag pushed to running engine");
            }
            Err(e) => {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "task dht flag push skipped");
            }
        }
    }

    /// changeOption subset. Waiting task: merge the payload (effective
    /// at activation). Active task: no live application face in the
    /// subset -> restart semantics (direct translation of aria2
    /// ChangeOption's pauseRequestGroup + setRestartRequested path,
    /// RpcMethodImpl.cc — teardown returns to the queue head and
    /// reactivates with the merged payload). The merged per-task
    /// payload syncs config_json (row comparison absorbs no-op
    /// writes). `select-file`: reserved merges the selection payload
    /// (recompute selection -> config_json persist -> SetFileSelection
    /// replay on reactivation, isomorphic to the reference
    /// reserved-change bit); active = explicit rejection (declared
    /// diff, below).
    pub(super) async fn change_option(
        &mut self,
        gid: Gid,
        options: BTreeMap<String, String>,
    ) -> Result<CommandReply, SessionError> {
        if !matches!(
            self.queue.find(gid),
            Some(Location::Active)
                | Some(Location::Reserved)
                | Some(Location::ReservedPaused)
                // Seeding residence (§4.1.3): the engine is
                // live — the same active-family semantics as the Active arm
                // (live limiter hot-reload below; the restart block further
                // down stays keyed on the active face — a resident never
                // restarts on changeOption, the mirror + live limiter
                // suffice). SeedWaiting stays rejected here (the
                // waiting-face finalization owns that seam).
                | Some(Location::Seeding)
                // Synthesis pool (§4.3): a synthesizing
                // media task keeps the live-driver face (the Seeding-arm
                // shape). SynthesisWaiting stays rejected — the same
                // waiting-face seam as SeedWaiting (the decision of record:
                // the parked media option face finalizes with the segment
                // semantics).
                | Some(Location::Synthesizing)
        ) {
            return Err(SessionError::failed(format!(
                "Cannot change option for GID#{gid}"
            )));
        }
        let patch = parse_task_options(&options);
        let metadata_tracker_only = options.len() == 1
            && options.contains_key("bt-tracker")
            && matches!(self.jobs.get(&gid), Some(Job::Magnet(_)));
        // load-cookies changeOption face: loading is fail-closed up
        // front (a rejected call mutates nothing — the
        // validate-all-first discipline); acceptance = whole-set seed
        // replacement (effective on the next activation, running tasks
        // reactivate through the existing restart semantics; empty
        // string = clear) + manual Cookie header stripping (combined
        // semantics declared at cookie_intake_active; the discriminator
        // is this payload's load-cookies key). Runtime keys are not
        // persisted (restart restore uses session defaults, same as the
        // HTTP runtime face).
        let mut cookie_seed_replace: Option<Vec<taiji_http::cookies::NetscapeCookie>> = None;
        let mut options = options;
        if cookie_intake_active(None, &options, 0) {
            cookie_seed_replace = match options.get("load-cookies").filter(|v| !v.trim().is_empty())
            {
                Some(path) => Some(load_cookie_seed(path.trim()).await?),
                None => Some(Vec::new()),
            };
            strip_manual_cookie_headers(&mut options);
        }
        // Option error semantics: an out-of-domain value for a known
        // HTTP per-task option rejects the whole call (no truncation,
        // no silent fallback to defaults) with `taiji.option.invalid`
        // (the numeric face 28 comes from the mapping table). Legal
        // values apply with this call: the runtime family lands in
        // hj.opts (consumed by restart/reactivation), the persist
        // family rewrites row config_json (same source across
        // restarts). Declared diff: aria2 wholly ignores non-changeable
        // keys (illegal values included); taiji validates known keys
        // tightly.
        //
        // Validate everything before mutating (a rejected call mutates
        // nothing): the persist/runtime/scheduler parses plus the
        // max-chunk cross-key domain check all complete before any
        // payload merge — previously the scheduler parse and cross-key
        // rejection ran after hj.opts/row payloads had already merged,
        // leaving a half-applied mutation behind. Baseline-merged
        // parsing (keys absent from the payload keep the task's current
        // values) removes the silent reset of absent keys by a full
        // re-parse (the --checksum final-arbitration wipe through
        // changeOption is fixed by the same change).
        let http_apply = if matches!(self.jobs.get(&gid), Some(Job::Http(_))) {
            let sched = http_sched_patch(&options)?;
            if let Some(mc) = sched.max_chunk {
                let block_size = match self.jobs.get(&gid) {
                    Some(Job::Http(hj)) => hj.opts.block_size,
                    _ => http_task::HttpTaskOpts::default().block_size,
                };
                if mc < block_size {
                    return Err(SessionError::failed(format!(
                        "taiji.option.invalid: --http-max-chunk {mc:?} below block size {block_size}"
                    )));
                }
            }
            let base_cfg = match self.jobs.get(&gid) {
                Some(Job::Http(hj)) => match hj.mirror.as_ref() {
                    Some(m) => http_task::HttpPersistConfig::from_json(&crate::lock(m).config_json),
                    None => match hj.restore.as_ref() {
                        Some(r) => http_task::HttpPersistConfig::from_json(&r.config_json),
                        None => http_task::HttpPersistConfig::default(),
                    },
                },
                _ => http_task::HttpPersistConfig::default(),
            };
            let base_opts = match self.jobs.get(&gid) {
                Some(Job::Http(hj)) => hj.opts.clone(),
                _ => http_task::HttpTaskOpts::default(),
            };
            Some((
                http_task_options(&options, &base_cfg)?,
                http_task_runtime_options(&options, &base_opts)?,
                sched,
            ))
        } else {
            None
        };
        // select-file (aria2 INITIAL + reserved-change bits;
        // OptionHandlerFactory.cc has no setChangeOption):
        // - Active tasks = explicit rejection (aria2 ignores
        // non-changeable keys, RpcMethod.cc; taiji tightens to an
        // error, declared diff). Live reselection (libtorrent
        // prioritize_files semantics) is a taiji.* extension
        // candidate, not on this face.
        // - Reserved/ReservedPaused accepted (cross-validates the
        // reference reserved changeOption path): recompute selection
        // -> persist config_json (persist_refresh_config below) ->
        // SetFileSelection replay on reactivation (existing
        // activation-chain consumer).
        // - Validate before mutating: magnet metadata unknown -> syntax
        // validation only, range validation defers to the upgrade
        // chain (same as so=); a URI carrying so= = two selection
        // sources -> explicit conflict rejection (same as the add
        // face).
        // - Non-BT tasks (HTTP/.torrent URL) = explicit rejection
        // (accepting without effect would be a disguise).
        // bt-sequential-download: active tasks are rejected explicitly
        // (live switching goes through the taiji.setSchedulerPolicy
        // authoritative face; the option key shares the select-file
        // gate — aria2 silently ignores non-changeable keys, taiji
        // errors); HTTP/.torrent URL tasks are rejected as non-BT.
        if patch.bt_sequential_download.is_some() {
            // Live-engine faces (active download / seeding residence alike)
            // reject the mirror-only keys — the same reason as Active.
            if self.queue.contains_active(gid) || self.queue.contains_seeding(gid) {
                return Err(SessionError::failed(
                    "taiji.option.invalid: --bt-sequential-download is not changeable \
                     for an active or seeding task (pause it first, or use \
                     taiji.setSchedulerPolicy for live switching)",
                ));
            }
            if !matches!(
                self.jobs.get(&gid),
                Some(Job::Torrent(_)) | Some(Job::Magnet(_))
            ) {
                return Err(SessionError::failed(
                    "taiji.option.invalid: --bt-sequential-download applies to \
                     BitTorrent tasks only (torrent/magnet)",
                ));
            }
        }
        let select_file_sel = if patch.select_file.is_some() {
            // Live-engine faces (active / seeding residence) reject — the
            // same reason as Active.
            if self.queue.contains_active(gid) || self.queue.contains_seeding(gid) {
                return Err(SessionError::failed(
                    "taiji.option.invalid: --select-file is not changeable for an \
                     active or seeding task (pause it first; aria2 silently ignores \
                     non-changeable keys, taiji rejects explicitly)",
                ));
            }
            let raw = patch.select_file.as_deref().unwrap_or_default();
            match self.jobs.get(&gid) {
                Some(Job::Torrent(tj)) => resolve_select_file_for_meta(&patch, &tj.metainfo.meta)?,
                Some(Job::Magnet(mj)) => {
                    if magnet_selected_files(&mj.magnet_uri).is_some() {
                        return Err(SessionError::failed(
                            "taiji.option.invalid: both magnet URI 'so=' and option \
                             'select-file' are present (single selection source; remove one)",
                        ));
                    }
                    Some(parse_select_file(raw).map_err(SessionError::failed)?)
                }
                _ => {
                    return Err(SessionError::failed(
                        "taiji.option.invalid: --select-file applies to BitTorrent \
                         tasks only (torrent/magnet)",
                    ));
                }
            }
        } else {
            None
        };
        // Active-task per-task rate limit applies live (direct
        // translation of setMaxDownload/UploadSpeedLimit,
        // RpcMethodImpl.cc) — set_rate changes the shared bucket
        // atomically and Throttled streams see it immediately (ahead of
        // the restart convergence).
        let live_limiter = self.running.get(&gid).and_then(|t| t.limiter.clone());
        if let Some(limiter) = live_limiter {
            if let Some(m) = patch.max_download_limit {
                limiter.per_torrent.down.set_rate(m);
            }
            if let Some(m) = patch.max_upload_limit {
                limiter.per_torrent.up.set_rate(m);
            }
        }
        let mut http_row_snapshot: Option<taiji_store::persist::HttpTaskRow> = None;
        // bt-disable-dht change flag (set inside the match, pushed
        // outside it — the borrow phase split).
        let mut dht_flag_changed = false;
        match self.jobs.get_mut(&gid) {
            Some(Job::Torrent(tj)) => {
                // dir applies only to never-activated tasks (aria2
                // reserved face; a seeding residence is activated too).
                if let Some(dir) = &patch.dir {
                    if !(self.queue.contains_active(gid) || self.queue.contains_seeding(gid)) {
                        tj.dir = dir.clone();
                    }
                }
                if let Some(r) = patch.seed_ratio {
                    tj.seed.seed_ratio = r;
                }
                // Out-of-domain value = invalid: skip this seed change
                // (keep the current value) and warn, no panic (the
                // parse face catches extremes; this is the conversion
                // backstop).
                if let Some(m) = patch.seed_time_min {
                    match seed_duration_from_minutes(m) {
                        Some(d) => tj.seed.seed_time = d,
                        None => warn!(target: "taiji::core::session", gid = %gid,
                            seed_time_min = m,
                            "changeOption seed-time out of range; ignored"),
                    }
                }
                // Per-task rate limits into the payload
                // (restart/reactivation path).
                if let Some(m) = patch.max_download_limit {
                    tj.max_download_limit = m;
                }
                if let Some(m) = patch.max_upload_limit {
                    tj.max_upload_limit = m;
                }
                // bt-max-peers / max-connection: numbers land in the
                // payload; live connection management hangs off the
                // engine constant seam (MIN_PEERS) with the query
                // seam.
                //
                // select-file (validated up front): recompute selection
                // into the job mirror -> config_json via
                // persist_refresh_config below -> SetFileSelection
                // replay on reactivation (the activate consumer).
                if let Some(sel) = select_file_sel {
                    tj.selected_files = Some(sel);
                }
                // bt-disable-dht: the flag enters the job mirror
                // (persist_refresh_config below lands config_json —
                // same source as restart restore). Hot push happens
                // outside the match (borrow phase split;
                // push_dht_task_change needs &mut self): libtorrent
                // set_flags runtime-flip semantics; an explicit false
                // forces it back on (recomposed with the session
                // face).
                if let Some(v) = patch.bt_disable_dht {
                    tj.bt_disable_dht = Some(v);
                    dht_flag_changed = true;
                }
                // enable-http-seeding (BEP19): the switch enters the
                // job mirror (config_json via persist_refresh_config
                // below — same source as restart restore). Effect =
                // restart semantics (active tasks pause + reactivate
                // below; build_engine_config clears the webseed set);
                // no live engine push exists for webseeding.
                if let Some(v) = patch.enable_http_seeding {
                    tj.enable_http_seeding = Some(v);
                }
                // bt-sequential-download: project onto the policy in
                // the mirror (live switching on active tasks goes
                // through taiji.setSchedulerPolicy; this key shares the
                // select-file gate: explicit rejection on active tasks,
                // above).
                if let Some(seq) = patch.bt_sequential_download {
                    tj.scheduler_policy = if seq {
                        crate::engine::SchedulerPolicy::sequential()
                    } else {
                        crate::engine::SchedulerPolicy::default()
                    };
                }
            }
            Some(Job::Magnet(mj)) => {
                if let Some(trackers) = &patch.bt_tracker {
                    mj.tiers = trackers.iter().cloned().enumerate().collect();
                    let tiers = merge_global_trackers(&mj.tiers, &self.global.bt_tracker);
                    if let Some(task) = self.running.get_mut(&gid) {
                        if let TaskBackend::Metadata {
                            tracker_updates: Some(updates),
                        } = &task.backend
                        {
                            if task.tiers != tiers {
                                task.tiers = tiers.clone();
                                updates.send_replace(tiers);
                            }
                        }
                    }
                }
                if let Some(r) = patch.seed_ratio {
                    mj.seed.seed_ratio = r;
                }
                // Out-of-domain values skip the seed change (same as
                // the Torrent arm).
                if let Some(m) = patch.seed_time_min {
                    match seed_duration_from_minutes(m) {
                        Some(d) => mj.seed.seed_time = d,
                        None => warn!(target: "taiji::core::session", gid = %gid,
                            seed_time_min = m,
                            "changeOption seed-time out of range; ignored"),
                    }
                }
                // Per-task rate limits into the payload.
                if let Some(m) = patch.max_download_limit {
                    mj.max_download_limit = m;
                }
                if let Some(m) = patch.max_upload_limit {
                    mj.max_upload_limit = m;
                }
                // select-file (validated up front; metadata unknown so
                // range validation defers to the upgrade chain): the
                // value enters the job mirror -> config_json (the
                // effective_magnet_selection merge point) -> replayed
                // by the upgrade chain via MagnetTaskConfig.
                if let Some(sel) = select_file_sel {
                    mj.selected_files = Some(sel);
                }
                // bt-disable-dht: the flag enters the mirror (gates the
                // next activation of the metadata phase; after upgrade
                // the engine gets the hot push — the phase holds no
                // engine handle, the upgrade chain consumes it). Hot
                // push outside the match (borrow phase split).
                if let Some(v) = patch.bt_disable_dht {
                    mj.bt_disable_dht = Some(v);
                    dht_flag_changed = true;
                }
                // enable-http-seeding (BEP19): the switch enters the
                // mirror (consumed by the upgrade chain via
                // MagnetTaskConfig.webseeding_enabled; the metadata
                // phase has no webseed face and no hot-push arm —
                // restart semantics backstops, as in the torrent
                // arm).
                if let Some(v) = patch.enable_http_seeding {
                    mj.enable_http_seeding = Some(v);
                }
                // bt-sequential-download: policy projection into the
                // mirror (carried by job_config through the upgrade
                // chain; the metadata phase holds no engine handle).
                if let Some(seq) = patch.bt_sequential_download {
                    mj.scheduler_policy = if seq {
                        crate::engine::SchedulerPolicy::sequential()
                    } else {
                        crate::engine::SchedulerPolicy::default()
                    };
                }
                apply_magnet_patch(&mut mj.options, &patch);
            }
            Some(Job::Http(hj)) => {
                // Whole-set seed replacement (load-cookies changeOption
                // face, validated up front): the next activation seeds
                // the task store (running tasks pick it up on
                // reactivation via restart semantics).
                if let Some(seed) = cookie_seed_replace.take() {
                    hj.cookie_seed = seed;
                }
                // Per-task rate limits into the payload (consumed by
                // restart/reactivation); live application matches the
                // torrent arm (shared LimiterSet).
                if let Some(m) = patch.max_download_limit {
                    hj.max_download_limit = m;
                }
                if let Some(m) = patch.max_upload_limit {
                    hj.max_upload_limit = m;
                }
                // dir applies only to never-activated tasks (aria2
                // reserved face, same as the torrent branch).
                if let Some(dir) = &patch.dir
                    && !self.queue.contains_active(gid)
                {
                    hj.dir = dir.clone();
                }
                // Apply legal values for known HTTP options (validated
                // up front): the runtime family (read by
                // restart/reactivation) + the persist family (row
                // config_json rewrite — absent keys were baseline-merged
                // in the parse face, so a whole payload overwrite is
                // safe). Row persistence is deferred outside the match
                // (borrow phase split).
                if let Some((cfg, opts, sched)) = &http_apply {
                    hj.opts = opts.clone();
                    for row in hj.restore.iter_mut() {
                        http_overlay_persist_config(row, cfg);
                    }
                    if let Some(m) = &hj.mirror {
                        let mut guard = crate::lock(m);
                        http_overlay_persist_config(&mut guard, cfg);
                        http_row_snapshot = Some(guard.clone());
                    }
                    // Scheduler parameter family: applies via the
                    // existing restart semantics (merge, requeue at the
                    // head, reactivate — bitmap progress survives; the
                    // AIMD ring rebuilds the connection ring with the
                    // new caps).
                    if let Some(v) = sched.split {
                        hj.opts.split = v;
                    }
                    if let Some(v) = sched.min_split_size {
                        hj.opts.min_split_size = v;
                    }
                    if let Some(v) = sched.max_conn_per_server {
                        hj.opts.max_conn_per_server = v;
                    }
                    if let Some(v) = sched.stall_window {
                        hj.opts.stall_window = v;
                    }
                    if let Some(v) = sched.scheduler {
                        hj.opts.scheduler = v;
                    }
                    if let Some(v) = sched.max_chunk {
                        // Cross-key domain check already ran
                        // (http_apply construction); plain assignment
                        // here.
                        hj.opts.max_chunk = v;
                    }
                    // Concurrency intent sync: split/cap changes
                    // persist with the row so recovery after a restart
                    // starts from the latest effective values (same
                    // source as hj.opts; replayed by bootstrap_http).
                    if sched.split.is_some() || sched.max_conn_per_server.is_some() {
                        for row in hj.restore.iter_mut() {
                            http_overlay_concurrency(row, &hj.opts);
                        }
                        if let Some(m) = &hj.mirror {
                            let mut guard = crate::lock(m);
                            http_overlay_concurrency(&mut guard, &hj.opts);
                            http_row_snapshot = Some(guard.clone());
                        }
                    }
                }
            }
            Some(Job::Media(mj)) => {
                // Media waiting/paused/error-resident tasks: the
                // selector + template keys re-arm the next
                // Resolving pass (§3.2: Error -> unpause/change selector
                // -> Resolving re-resolution). Active tasks take effect
                // via the shared restart semantics below (cancel +
                // requeue -> re-resolve). dir applies to never-activated
                // tasks (the aria2 reserved face).
                if let Some(dir) = &patch.dir
                    && !self.queue.contains_active(gid)
                {
                    mj.cfg.output_dir = dir.clone();
                }
                for key in ["media-selector", "media-template", "out"] {
                    if let Some(v) = options.get(key) {
                        match key {
                            "media-selector" => mj.cfg.selector = Some(v.clone()),
                            "media-template" => mj.cfg.template = Some(v.clone()),
                            _ => mj.cfg.out = Some(v.clone()),
                        }
                    }
                }
            }
            Some(Job::TorrentUrl { .. }) | None => {}
        }
        if let Some(row) = http_row_snapshot {
            self.persist_http_row(&row).await;
        }
        // bt-disable-dht change -> immediate hot push on active tasks
        // (ahead of the restart backstop — engine SetDhtEnabled goes
        // live without tearing down connections).
        if dht_flag_changed {
            self.push_dht_task_change(gid).await;
        }
        if !metadata_tracker_only
            && self.queue.contains_active(gid)
            && self.queue.request_pause(gid)
        {
            if let Some(rec) = self.queue.active_record_mut(gid) {
                rec.restart_requested = true;
            }
            if let Some(t) = self.running.get(&gid) {
                t.token.cancel();
            }
        }
        self.persist_refresh_config(gid).await;
        Ok(CommandReply::Accepted)
    }

    /// setTaskCookies actor arm (direct translation of the fork
    /// SetTaskCookiesRpcMethod, RpcMethodImpl.cc):
    /// - State gate (one fork text): only **waiting/paused** tasks
    ///   accept cookies — active tasks and misses both answer verbatim
    ///   "Task cookies can only be set on waiting or paused cookie
    ///   tasks.". Declared authorization diff: the fork also requires
    ///   the `require-task-cookies` task preference bit (set by
    ///   AddUriWithCookies, which mounts the store selectively); taiji
    ///   HTTP tasks always mount a store (spawn_http_task), so the
    ///   equivalent gate relaxes to the cookie-bearing task shapes.
    ///   The cookie design widens the accepted domain to the **media**
    ///   family too (`Job::Http | Job::Media` — addMedia's structured
    ///   pass made media a cookie task; a declared taiji extension),
    ///   while torrent/magnet/metadata tasks stay refused.
    /// - Whole-set replacement: seed conversion drops expired entries
    ///   ([`cookies_from_specs`]) -> persist first (fork "Persist
    ///   first... report the RPC failure" — here via the unified
    ///   task_cookie row upsert (http|media kind), a failure
    ///   fails whole and the in-memory face never mutates) ->
    ///   overwrite the in-memory seed (the next activation seeds from
    ///   the unified table read-back — same semantics for both
    ///   families; waiting tasks hold no live store).
    pub(super) async fn set_task_cookies(
        &mut self,
        gid: Gid,
        cookies: Vec<TaskCookieSpec>,
    ) -> Result<CommandReply, SessionError> {
        let n_specs = cookies.len();
        let waiting = matches!(
            self.queue.find(gid),
            Some(Location::Reserved) | Some(Location::ReservedPaused)
        );
        let kind = match self.jobs.get(&gid) {
            Some(Job::Http(_)) => Some(taiji_store::persist::TASK_KIND_HTTP),
            Some(Job::Media(_)) => Some(taiji_store::persist::TASK_KIND_MEDIA),
            _ => None,
        };
        let Some(kind) = kind.filter(|_| waiting) else {
            return Err(SessionError::failed(
                "Task cookies can only be set on waiting or paused cookie tasks.",
            ));
        };
        let entries = cookies_from_specs(&cookies);
        // Persist first (fork rule): whole-set replacement — the old
        // set is fully cleared and the new set is stamped with the
        // current time as the creation baseline.
        if let Some(p) = self.persist.as_ref() {
            let now = now_epoch();
            let rows: Vec<taiji_store::persist::TaskCookieRow> = entries
                .iter()
                .map(|c| taiji_store::persist::TaskCookieRow {
                    gid: gid.to_string(),
                    task_kind: kind.to_string(),
                    name: c.name.clone(),
                    domain: c.domain.clone(),
                    path: c.path.clone(),
                    value: c.value.clone(),
                    expires_utc: c.expires,
                    secure: c.secure,
                    host_only: c.host_only,
                    creation_utc: now,
                })
                .collect();
            p.upsert_task_cookies(&gid.to_string(), kind, rows)
                .await
                .map_err(|e| SessionError::failed(format!("setTaskCookies persist failed: {e}")))?;
        }
        // In-memory face (after persist succeeds): overwrite the seed
        // for the next activation — the http seed pairs and the media
        // cfg pairs + specs (the media activation reads the unified
        // table too; this keeps a not-yet-activated waiting task's
        // in-memory face consistent).
        match self.jobs.get_mut(&gid) {
            Some(Job::Http(hj)) => {
                hj.cookie_seed = entries;
            }
            Some(Job::Media(mj)) => {
                mj.cfg.cookies = entries
                    .iter()
                    .map(|c| (c.name.clone(), c.value.clone()))
                    .collect();
                mj.cookie_specs = cookies;
            }
            _ => {}
        }
        info!(target: "taiji::core::session", gid = %gid, task_kind = kind, n = n_specs,
            "task cookies replaced via setTaskCookies");
        Ok(CommandReply::Accepted)
    }

    /// getOption (GetOptionRpcMethod direct translation,
    /// RpcMethodImpl.cc): gid prefix resolution (resolve_gid up front,
    /// as in tellStatus — the str2Gid family text face) -> three-domain
    /// lookup (active ∪ reserved = `findGroup`, result =
    /// `findDownloadResult`, the same domain coverage as tellStatus) ->
    /// the accepted-subset option dictionary (string value table,
    /// pushRequestOption shape).
    ///
    /// The echo face is the projection of the declared diffs (checked
    /// against the rpc-api-diff.md §3 option stance table): the
    /// reference answers the whole table because its option face
    /// accepts everything (`option->defined(pref)` per pref); here the
    /// answer is the accepted key set intersected with keys holding a
    /// per-task truth source — unaccepted keys are never fabricated.
    /// `bt-max-peers` parses but has no per-task payload (its execution
    /// hangs off an engine constant seam), so it is honestly omitted.
    ///
    /// - active/reserved: assembled from the task payload
    ///   (changeOption's merge rewrites the row, so a read sees the
    ///   merged values); active rate limits are echoed with the live
    ///   bucket values (the set_rate effect read back, same family as
    ///   getGlobalOption's `http-max-per-host` cap overwrite — echo
    ///   face = effect face; restart-restored/waiting tasks have no
    ///   bucket and fall back to the payload fields).
    /// - result: read back from the result row's config_json (torrent
    ///   rows in `download_result`; HTTP rows in `http_task` — the
    ///   torrent/http two-table split). No persistence or a missing row = an
    ///   empty table, honestly: the reference keeps `dr->option` in
    ///   memory while the local result table carries no option
    ///   snapshot — the store row is the only persistent truth ("no
    ///   store = no history", as in list_bans).
    pub(super) async fn get_option(&self, raw_gid: &str) -> Result<CommandReply, SessionError> {
        if raw_gid.len() == 16 && raw_gid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            if let Some(persist) = &self.persist {
                if let Some(snapshot) = persist
                    .load_http_task(raw_gid)
                    .await
                    .map_err(|e| SessionError::failed(e.to_string()))?
                {
                    let row = snapshot.row;
                    let cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
                    if row.state == "error" && cfg.retain_request_context {
                        let available = row.total_done == 0 || cfg.http_resume_context.is_some();
                        return Ok(CommandReply::Options(BTreeMap::from([
                            ("motrix-retry-available".into(), available.to_string()),
                            (
                                "motrix-retry-uri-hash".into(),
                                cfg.http_resume_context
                                    .as_ref()
                                    .map(|context| context.source_hash.clone())
                                    .unwrap_or_else(|| {
                                        crate::session::persist::import_http::request_uri_hash(
                                            &row.url,
                                        )
                                    }),
                            ),
                            ("dir".into(), row.dir),
                            ("out".into(), row.out),
                        ])));
                    }
                }
            }
        }
        let gid = self.resolve_gid(raw_gid)?;
        let echo = match self.queue.find(gid) {
            Some(Location::Active) => {
                let mut echo = task_option_echo(self.jobs.get(&gid));
                if let Some(l) = self.running.get(&gid).and_then(|t| t.limiter.clone()) {
                    echo.insert(
                        "max-download-limit".into(),
                        l.per_torrent.down.rate().to_string(),
                    );
                    echo.insert(
                        "max-upload-limit".into(),
                        l.per_torrent.up.rate().to_string(),
                    );
                }
                echo
            }
            Some(Location::Reserved | Location::ReservedPaused) => {
                task_option_echo(self.jobs.get(&gid))
            }
            // In-recheck: the payload face is the job mirror (same as
            // reserved).
            Some(Location::Checking | Location::CheckingPaused) => {
                task_option_echo(self.jobs.get(&gid))
            }
            // Seed pool: the payload face is the job
            // mirror (residence and parked alike — the job payload
            // survives both); a resident's live rate limits echo the
            // same limiter face as Active.
            Some(Location::Seeding) => {
                let mut echo = task_option_echo(self.jobs.get(&gid));
                if let Some(l) = self.running.get(&gid).and_then(|t| t.limiter.clone()) {
                    echo.insert(
                        "max-download-limit".into(),
                        l.per_torrent.down.rate().to_string(),
                    );
                    echo.insert(
                        "max-upload-limit".into(),
                        l.per_torrent.up.rate().to_string(),
                    );
                }
                echo
            }
            Some(Location::SeedWaiting) => task_option_echo(self.jobs.get(&gid)),
            // Synthesis pool: the payload face is the
            // job mirror (in flight and parked alike — the job payload
            // survives both faces; no limiter face on media tasks).
            Some(Location::Synthesizing) | Some(Location::SynthesisWaiting) => {
                task_option_echo(self.jobs.get(&gid))
            }
            Some(Location::Result) => {
                // Torrent rows read back from download_result; HTTP
                // tasks (result entries carry an http snapshot) read
                // the http_task row — a missing row = empty (removed
                // task or no persistence).
                let is_http = self
                    .queue
                    .results()
                    .any(|r| r.gid == gid && r.http.is_some());
                let mut echo = BTreeMap::new();
                if let Some(p) = &self.persist {
                    if is_http {
                        if let Ok(Some(snap)) = p.load_http_task(&gid.to_string()).await {
                            echo = http_persist_option_echo(
                                &http_task::HttpPersistConfig::from_json(&snap.row.config_json),
                            );
                        }
                    } else if let Ok(Some(row)) = p.load_download_result(&gid.to_string()).await {
                        echo = torrent_result_option_echo(&PersistedTaskConfig::from_json(
                            &row.config_json,
                        ));
                    }
                }
                echo
            }
            // Defensive arm: the resolve_gid universe (active ∪
            // reserved ∪ results) matches the find domain, normally
            // unreachable — the reference text stays verbatim ("Cannot
            // get option for GID#%s", RpcMethodImpl.cc).
            None => {
                return Err(SessionError::failed(format!(
                    "Cannot get option for GID#{gid}"
                )));
            }
        };
        Ok(CommandReply::Options(echo))
    }

    /// changeUri (upstream semantics restored; the tracker-hijack use
    /// is gone). Arm order direct-translates aria2 ChangeUriRpcMethod
    /// (RpcMethodImpl.cc): gid locate (resolve_gid up front, str2Gid
    /// family) -> fileIndex domain check -> file-entry URI operations
    /// -> a `[deleted, added]` count reply.
    ///
    /// fileIndex is checked against the job shape's file-entry count
    /// (the client-visible file face, same source as the tellStatus
    /// files projection): Torrent = metainfo entry count (upstream
    /// `files.size()`, filled by download_helper.cc
    /// `bittorrent::loadFromMemory`); magnet = 1 (metadata-phase
    /// placeholder — download_helper.cc
    /// `DownloadContext(METADATA_PIECE_SIZE, 0)` pushes a single
    /// entry, DownloadContext.cc); TorrentUrl = 1 (metadata fetch is a
    /// single-entry createRequestGroup group); Http = 1 (one file
    /// entry carrying every source URI, download_helper.cc
    /// `setUris`).
    ///
    /// Out of range = verbatim "fileIndex is out of range"; a gid
    /// outside the job universe — including terminal jobs, since the
    /// upstream `findGroup` covers only active ∪ reserved — = verbatim
    /// "Cannot remove URIs from GID#%s".
    ///
    /// The file-entry URI operation is a declared no-op: there is no
    /// file-entry URI ledger (BT file views carry empty `uris`; BEP19
    /// webseed does not consume them — declared on the addTorrent
    /// face), so every shape returns the upstream no-op count
    /// `[0, 0]`. The declared gaps (rpc-api-diff.md §1): BT/magnet —
    /// upstream addUri enqueues and counts any parseable URI
    /// (FileEntry.cc `uri_split`, consumed by the webseed face) while
    /// local enqueued URIs have no consumer, so always 0; HTTP —
    /// upstream edits the true source ledger (removeUri deletes on hit
    /// and withdraws in-flight requests, FileEntry.cc) while the local
    /// live source ledger is the drive's sources and `EngineCommand`
    /// has no source-change seam, so this pass stays [0,0].
    pub(super) async fn change_uri(
        &mut self,
        gid: Gid,
        file_index: u64,
        del_uris: Vec<String>,
        add_uris: Vec<String>,
        pos: Option<usize>,
    ) -> Result<CommandReply, SessionError> {
        // URI/position parameters are not consumed in this pass (the
        // gap is declared above; the direct translation keeps the
        // shape).
        let _ = (del_uris, add_uris, pos);
        let file_count = match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => tj.metainfo.meta.files.len() as u64,
            // Media tasks are single-product (the file-entry face has
            // one entry — the file_index domain check).
            Some(Job::Magnet(_) | Job::TorrentUrl { .. } | Job::Http(_) | Job::Media(_)) => 1,
            None => {
                return Err(SessionError::failed(format!(
                    "Cannot remove URIs from GID#{gid}"
                )));
            }
        };
        if file_count < file_index {
            return Err(SessionError::failed("fileIndex is out of range"));
        }
        Ok(CommandReply::UriChange {
            deleted: 0,
            added: 0,
        })
    }

    // ---- Tracker dynamic edit face (taiji.addTracker/removeTracker) ----

    /// taiji.addTracker: append/insert into the tracker table (each
    /// URL its own tier; `position` defaults to the end — the table
    /// transform is [`super::options::add_trackers`]). Active tasks:
    /// `EngineCommand::SetTrackers` applies immediately (announce face
    /// — the engine receipt comes first and a failure mutates nothing) +
    /// job mirror sync + config_json refresh (tellStatus
    /// announceList and the across-restart shape share one source, same
    /// as the global-import hot push). Waiting tasks: payload change +
    /// config_json persist (reactivation carries it to the engine
    /// through the tasks.rs activation chain). The shape gate is
    /// [`tracker_edit_reject_message`] — a rejected call mutates
    /// nothing.
    pub(super) async fn add_tracker(
        &mut self,
        gid: Gid,
        urls: Vec<String>,
        position: Option<usize>,
    ) -> Result<CommandReply, SessionError> {
        if let Some(message) =
            tracker_edit_reject_message("taiji.addTracker", gid, self.jobs.get(&gid))
        {
            return Err(SessionError::failed(message));
        }
        if let Some(t) = self.running.get_mut(&gid) {
            let (tiers, added) = add_trackers(&t.tiers, &urls, position);
            if let Some(engine) = t.backend.engine() {
                engine.set_trackers(tiers.clone()).await?;
            }
            t.tiers = tiers.clone();
            if let Some(Job::Torrent(tj)) = self.jobs.get_mut(&gid) {
                tj.tiers = tiers;
                self.persist_refresh_config(gid).await;
            }
            return Ok(CommandReply::TrackerChange { removed: 0, added });
        }
        match self.jobs.get_mut(&gid) {
            Some(Job::Torrent(tj)) => {
                let (tiers, added) = add_trackers(&tj.tiers, &urls, position);
                tj.tiers = tiers;
                self.persist_refresh_config(gid).await;
                Ok(CommandReply::TrackerChange { removed: 0, added })
            }
            // The gate only passes torrent payloads; this arm is
            // normally unreachable (activation/teardown and command
            // handling never overlap in the single-threaded actor) —
            // defensive, fails explicitly.
            _ => Err(SessionError::failed(format!(
                "taiji.addTracker: task GID#{gid} is not editable"
            ))),
        }
    }

    /// taiji.removeTracker: delete by exact URL match (tier cleanup
    /// and renumbering included — the table transform is
    /// [`super::options::remove_trackers`]); an emptied tier table is
    /// the pure DHT face, legal and accepted. Effect/persistence and
    /// the rejection face mirror [`Self::add_tracker`].
    pub(super) async fn remove_tracker(
        &mut self,
        gid: Gid,
        urls: Vec<String>,
    ) -> Result<CommandReply, SessionError> {
        if let Some(message) =
            tracker_edit_reject_message("taiji.removeTracker", gid, self.jobs.get(&gid))
        {
            return Err(SessionError::failed(message));
        }
        if let Some(t) = self.running.get_mut(&gid) {
            let (tiers, removed) = remove_trackers(&t.tiers, &urls);
            if let Some(engine) = t.backend.engine() {
                engine.set_trackers(tiers.clone()).await?;
            }
            t.tiers = tiers.clone();
            if let Some(Job::Torrent(tj)) = self.jobs.get_mut(&gid) {
                tj.tiers = tiers;
                self.persist_refresh_config(gid).await;
            }
            return Ok(CommandReply::TrackerChange { removed, added: 0 });
        }
        match self.jobs.get_mut(&gid) {
            Some(Job::Torrent(tj)) => {
                let (tiers, removed) = remove_trackers(&tj.tiers, &urls);
                tj.tiers = tiers;
                self.persist_refresh_config(gid).await;
                Ok(CommandReply::TrackerChange { removed, added: 0 })
            }
            // Defensive arm (as in add_tracker — normally unreachable
            // past the gate).
            _ => Err(SessionError::failed(format!(
                "taiji.removeTracker: task GID#{gid} is not editable"
            ))),
        }
    }
}

// ---- Free functions ----

/// Shape gate for the tracker edit face (taiji.addTracker /
/// removeTracker): routed by job shape (`None` = torrent passes; a
/// rejected call mutates nothing). Messages:
/// - magnet/.torrent URL = metadata-phase task — no tracker face
///   exists before upgrade; keeps the pre-existing wording ("metadata
///   tasks are not editable before upgrade") under the new method
///   names;
/// - HTTP = no tracker face ("requires a torrent task", the
///   taiji.setSchedulerPolicy/setDiskTier style);
/// - terminal (result domain) = the payload was dropped at teardown
///   and the result row is never rebuilt (not restored on restart),
///   so an edit could never take effect — accepting would be a
///   disguise (the same direction as aria2 changeUri's findGroup
///   excluding the result domain, RpcMethodImpl.cc).
fn tracker_edit_reject_message(method: &str, gid: Gid, job: Option<&Job>) -> Option<String> {
    match job {
        Some(Job::Torrent(_)) => None,
        Some(Job::Magnet(_) | Job::TorrentUrl { .. }) => Some(format!(
            "{method}: tracker edit requires a torrent task \
             (metadata tasks are not editable before upgrade)"
        )),
        Some(Job::Http(_) | Job::Media(_)) => {
            Some(format!("{method}: requires a torrent task (GID#{gid})"))
        }
        None => Some(format!(
            "{method}: task GID#{gid} is already finished \
             (download results are not editable)"
        )),
    }
}

/// HTTP source state (`http.sources` state domain) -> getServers
/// status fold (the L2 projection: enum -> enum; the aria2 server
/// words working|waiting|error|disabled are rendered by the rpc
/// adapter's word table). This shares the source ledger with the
/// `http.sources` sub-dictionary: ledger terminal states never
/// collapse back to waiting (waiting means merely unscheduled with no
/// failure semantics; rendering demoted/removed/failed as waiting
/// would tell the client the source is fresh). Mapping: `Active` ->
/// working (worker in flight); `Waiting` -> waiting (unscheduled);
/// `Demoted` -> error (repeated extent failures demoted the source —
/// it still participates at a halved share; the nearest aria2
/// semantics is a tracker's last failed interaction); `Failed` ->
/// error (dropped at probe or merge); `Removed` -> disabled (a ledger
/// terminal, no longer scheduled).
pub(super) fn http_source_server_status(state: HttpSourceState) -> ServerStatus {
    match state {
        HttpSourceState::Active => ServerStatus::Working,
        HttpSourceState::Demoted | HttpSourceState::Failed => ServerStatus::Error,
        HttpSourceState::Removed => ServerStatus::Disabled,
        HttpSourceState::Waiting => ServerStatus::Waiting,
    }
}

/// HTTP persist-option overlay (changeOption application): the merge
/// of keys absent from the payload already happened baseline-side in
/// [`http_task_options`]; this writes the merged payload into the row
/// config_json, preserving unexposed keys such as renamePending.
pub(super) fn http_overlay_persist_config(
    row: &mut taiji_store::persist::HttpTaskRow,
    cfg: &http_task::HttpPersistConfig,
) {
    let mut current = http_task::HttpPersistConfig::from_json(&row.config_json);
    current.host_finalize = cfg.host_finalize;
    current.incomplete_suffix = cfg.incomplete_suffix.clone();
    current.checksum = cfg.checksum.clone();
    current.remote_time = cfg.remote_time;
    row.config_json = current.to_json();
    row.updated_at = now_epoch();
}

/// HTTP concurrency intent sync (changeOption application): after a
/// split/cap change, overwrite the effective values into the row
/// config_json so a restart's recovery starts with the latest intent
/// (replayed by bootstrap_http; other keys untouched).
fn http_overlay_concurrency(
    row: &mut taiji_store::persist::HttpTaskRow,
    opts: &http_task::HttpTaskOpts,
) {
    let mut current = http_task::HttpPersistConfig::from_json(&row.config_json);
    current.concurrency = Some(http_task::HttpConcurrencyPersist::of(opts));
    row.config_json = current.to_json();
    row.updated_at = now_epoch();
}

// ---- getOption echo assembly helpers (per job shape) ----

/// getOption active/reserved echo assembly (per job shape; truth =
/// the task payload — changeOption's merge rewrites the row, so a
/// read sees merged values). Key names check against the three
/// declared option tables (the echo key universe is pinned by the
/// `get_option_echo_keys_are_fully_declared` test); `bt-max-peers`
/// has no per-task payload and is honestly omitted.
pub(super) fn task_option_echo(job: Option<&Job>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let Some(job) = job else {
        return m;
    };
    match job {
        Job::Torrent(tj) => {
            insert_common_task_options(
                &mut m,
                &tj.dir,
                Some(tj.hooks.as_ref()),
                tj.max_download_limit,
                tj.max_upload_limit,
            );
            insert_seed_options(&mut m, &tj.seed);
            insert_select_file_option(&mut m, tj.selected_files.as_deref());
            // bt-disable-dht: echoed only on explicit override (None =
            // follow the session; no fabricated key — the taiji-only
            // key stance is declared with the diff).
            if let Some(v) = tj.bt_disable_dht {
                m.insert("bt-disable-dht".into(), v.to_string());
            }
            // enable-http-seeding (BEP19): echoed only on explicit
            // override (None = default on; no fabricated key).
            if let Some(v) = tj.enable_http_seeding {
                m.insert("enable-http-seeding".into(), v.to_string());
            }
            // bt-sequential-download: projected from the task policy
            // (the authoritative face is taiji.setSchedulerPolicy; this
            // key is the aria2-compatible projection and stays
            // consistent with the policy echo).
            m.insert(
                "bt-sequential-download".into(),
                (tj.scheduler_policy == crate::engine::SchedulerPolicy::sequential()).to_string(),
            );
        }
        Job::Magnet(mj) => {
            insert_common_task_options(
                &mut m,
                &mj.dest,
                Some(mj.hooks.as_ref()),
                mj.max_download_limit,
                mj.max_upload_limit,
            );
            insert_seed_options(&mut m, &mj.seed);
            // Selection = the effective_magnet_selection merge point
            // (the select-file option wins; None re-parses the URI
            // so=).
            insert_select_file_option(&mut m, effective_magnet_selection(mj).as_deref());
            // magnet family (MagnetOptions effective values; aria2 bool
            // literals).
            m.insert(
                "bt-save-metadata".into(),
                mj.options.bt_save_metadata.to_string(),
            );
            m.insert(
                "bt-metadata-only".into(),
                mj.options.bt_metadata_only.to_string(),
            );
            m.insert(
                "follow-torrent".into(),
                mj.options.follow_torrent.to_string(),
            );
            m.insert(
                "pause-metadata".into(),
                mj.options.pause_metadata.to_string(),
            );
            m.insert(
                "bt-load-saved-metadata".into(),
                mj.options.bt_load_saved_metadata.to_string(),
            );
            // bt-sequential-download: policy projection echo (same as
            // the torrent arm).
            m.insert(
                "bt-sequential-download".into(),
                (mj.scheduler_policy == crate::engine::SchedulerPolicy::sequential()).to_string(),
            );
            // bt-disable-dht: echoed only on explicit override (as in
            // the torrent arm).
            if let Some(v) = mj.bt_disable_dht {
                m.insert("bt-disable-dht".into(), v.to_string());
            }
            // enable-http-seeding (BEP19): echoed only on explicit
            // override (as in the torrent arm).
            if let Some(v) = mj.enable_http_seeding {
                m.insert("enable-http-seeding".into(), v.to_string());
            }
        }
        Job::TorrentUrl {
            dir,
            seed,
            max_download_limit,
            max_upload_limit,
            hooks,
            select_file,
            bt_disable_dht,
            enable_http_seeding,
            ..
        } => {
            insert_common_task_options(
                &mut m,
                dir,
                Some(hooks.as_ref()),
                *max_download_limit,
                *max_upload_limit,
            );
            insert_seed_options(&mut m, seed);
            insert_select_file_option(&mut m, select_file.as_deref());
            // bt-disable-dht: echoed only on explicit override (same
            // source as the upgraded TorrentJob).
            if let Some(v) = bt_disable_dht {
                m.insert("bt-disable-dht".into(), v.to_string());
            }
            // enable-http-seeding (BEP19): echoed only on explicit
            // override (same source as the upgraded TorrentJob).
            if let Some(v) = enable_http_seeding {
                m.insert("enable-http-seeding".into(), v.to_string());
            }
        }
        Job::Http(hj) => {
            insert_common_task_options(
                &mut m,
                &hj.dir,
                Some(hj.hooks.as_ref()),
                hj.max_download_limit,
                hj.max_upload_limit,
            );
            // Persist family baseline order matches changeOption
            // (mirror -> restore -> default).
            let cfg = match hj.mirror.as_ref() {
                Some(mm) => http_task::HttpPersistConfig::from_json(&crate::lock(mm).config_json),
                None => match hj.restore.as_ref() {
                    Some(r) => http_task::HttpPersistConfig::from_json(&r.config_json),
                    None => http_task::HttpPersistConfig::default(),
                },
            };
            m.extend(http_persist_option_echo(&cfg));
            m.extend(http_runtime_option_echo(&hj.opts));
            if let Some(out) = &hj.out {
                m.insert("out".into(), out.clone());
            }
        }
        Job::Media(mj) => {
            insert_common_task_options(&mut m, &mj.cfg.output_dir, None, 0, 0);
            // The media family's per-task echo (the accepted addMedia
            // option subset; absent keys omitted — the reference's
            // undefined-key rule).
            if let Some(sel) = &mj.cfg.selector {
                m.insert("media-selector".into(), sel.clone());
            }
            if let Some(lang) = &mj.cfg.audio_lang {
                m.insert("media-audio-lang".into(), lang.clone());
            }
            m.insert(
                "media-subtitles".into(),
                if mj.cfg.subtitles == taiji_media::SubtitleMode::Sidecar {
                    "sidecar"
                } else {
                    "none"
                }
                .into(),
            );
            if let Some(t) = &mj.cfg.template {
                m.insert("media-template".into(), t.clone());
            }
            if let Some(out) = &mj.cfg.out {
                m.insert("out".into(), out.clone());
            }
        }
    }
    m
}

/// Torrent result-row projection (read back from the download_result
/// row's config_json): dir / seeding / rate limits / select-file.
/// Hooks are not part of the config_json payload (fixed at add, never
/// persisted) and the magnet/torrent-url payload keys are not option
/// keys — all honestly omitted.
pub(super) fn torrent_result_option_echo(cfg: &PersistedTaskConfig) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("dir".into(), cfg.dir.clone());
    m.insert("seed-ratio".into(), format_seed_ratio(cfg.seed_ratio));
    m.insert("seed-time".into(), format_minutes(cfg.seed_time_min));
    m.insert(
        "max-download-limit".into(),
        cfg.max_download_limit.to_string(),
    );
    m.insert("max-upload-limit".into(), cfg.max_upload_limit.to_string());
    // bt-stop-timeout (task-face echo: direct map of the config_json
    // mirror value; 0 = unset — the aria2 getOption decimal-seconds
    // shape).
    m.insert(
        "bt-stop-timeout".into(),
        cfg.bt_stop_timeout_secs.to_string(),
    );
    insert_select_file_option(&mut m, cfg.selected_files.as_deref());
    m
}

/// getOption HTTP persist-family projection (row config_json ->
/// option keys: the `http_task_options` key set plus the
/// `http-max-per-host` addUri cap intent, as declared). No checksum
/// = key omitted (same as the reference).
pub(super) fn http_persist_option_echo(
    cfg: &http_task::HttpPersistConfig,
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(
        "http-incomplete-suffix".into(),
        cfg.incomplete_suffix.clone(),
    );
    if let Some(c) = &cfg.checksum {
        m.insert("checksum".into(), c.clone());
    }
    m.insert("remote-time".into(), cfg.remote_time.to_string());
    if let Some(cap) = cfg.host_cap {
        m.insert("http-max-per-host".into(), cap.to_string());
    }
    m
}

/// getOption HTTP runtime-family projection (HttpTaskOpts -> option
/// keys, the `http_task_runtime_options` key set — the runtime face
/// is not persisted, so this face exists only for active/reserved).
/// A None/absent slot omits the key (the reference does not echo
/// undefined keys); numbers and sizes answer as byte literals (the
/// getGlobalOption rate-limit echo discipline); `--max-tries`
/// infinity (u32::MAX) projects back to the accepted literal "0".
/// Per-task http/ftp credentials are echoed as in the reference
/// pushRequestOption (no secret-stripping branch — the SPEC §13
/// tightening covers only the session secrets rpc-secret/rpc-passwd).
pub(super) fn http_runtime_option_echo(o: &http_task::HttpTaskOpts) -> BTreeMap<String, String> {
    use taiji_segment::traits::AuthScheme;
    let mut m = BTreeMap::new();
    m.insert("timeout".into(), o.read_timeout.as_secs().to_string());
    m.insert(
        "connect-timeout".into(),
        o.connect_timeout.as_secs().to_string(),
    );
    m.insert(
        "max-tries".into(),
        if o.retry.max_tries == u32::MAX {
            "0".into()
        } else {
            o.retry.max_tries.to_string()
        },
    );
    m.insert("retry-wait".into(), o.retry.base_wait.as_secs().to_string());
    if let Some(ua) = &o.user_agent {
        m.insert("user-agent".into(), ua.clone());
    }
    if !o.headers.is_empty() {
        let lines: Vec<String> = o.headers.iter().map(|(n, v)| format!("{n}: {v}")).collect();
        m.insert("header".into(), lines.join("\n"));
    }
    if let Some(AuthScheme::Basic { user, passwd } | AuthScheme::Digest { user, passwd }) = &o.auth
    {
        m.insert("http-user".into(), user.clone());
        m.insert("http-passwd".into(), passwd.clone());
    }
    if let Some(proxy) = &o.proxy {
        m.insert("all-proxy".into(), proxy.clone());
    }
    m.insert(
        "check-certificate".into(),
        (!o.accept_invalid_certs).to_string(),
    );
    if let Some(p) = &o.ca_cert_path {
        // Task-level CA face: an accepted key with a per-task truth
        // source, so it echoes (None = key omitted, as in the
        // reference).
        m.insert("ca-certificate".into(), p.display().to_string());
    }
    m.insert("split".into(), o.split.to_string());
    m.insert("min-split-size".into(), o.min_split_size.to_string());
    m.insert(
        "max-connection-per-server".into(),
        o.max_conn_per_server.to_string(),
    );
    m.insert(
        "http-stall-window".into(),
        o.stall_window.as_secs().to_string(),
    );
    m.insert(
        "http-scheduler".into(),
        match o.scheduler {
            taiji_http::scheduler::SchedulerMode::Dynamic => "dynamic".to_string(),
            taiji_http::scheduler::SchedulerMode::Static => "static".to_string(),
        },
    );
    m.insert("http-block-size".into(), o.block_size.to_string());
    m.insert("http-max-chunk".into(), o.max_chunk.to_string());
    m.insert(
        "http-protocol".into(),
        match o.http_protocol {
            taiji_http::client::HttpProtocol::Auto => "auto".to_string(),
            taiji_http::client::HttpProtocol::Http1 => "h1".to_string(),
            taiji_http::client::HttpProtocol::Http2 => "h2".to_string(),
        },
    );
    m.insert(
        "http2-adaptive-window".into(),
        o.http2_adaptive_window.to_string(),
    );
    if let Some(w) = o.http2_stream_window {
        m.insert("http2-stream-window".into(), w.to_string());
    }
    if let Some(w) = o.http2_connection_window {
        m.insert("http2-connection-window".into(), w.to_string());
    }
    m.insert(
        "http2-max-connections".into(),
        o.http2_max_connections.to_string(),
    );
    m.insert(
        "http2-keep-alive-interval".into(),
        o.http2_keep_alive_interval
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string(),
    );
    m.insert("http-batch-budget".into(), o.batch_budget.to_string());
    if let Some(AuthScheme::Basic { user, passwd } | AuthScheme::Digest { user, passwd }) =
        &o.ftp_auth
    {
        m.insert("ftp-user".into(), user.clone());
        m.insert("ftp-passwd".into(), passwd.clone());
    }
    m.insert(
        "ftp-ssl".into(),
        match o.ftp_tls {
            taiji_http::ftp::FtpTlsMode::None => "none".to_string(),
            taiji_http::ftp::FtpTlsMode::Explicit => "auth".to_string(),
            taiji_http::ftp::FtpTlsMode::Implicit => "implicit".to_string(),
        },
    );
    // ftp-pasv: active mode is not accepted (false is rejected) — the
    // value is always true.
    m.insert("ftp-pasv".into(), "true".into());
    m.insert(
        "ftp-reuse-connection".into(),
        o.ftp_reuse_connection.to_string(),
    );
    m
}

/// getOption common keys: dir / hooks (effective-set projection) /
/// per-task rate limits as byte literals (the active live-bucket
/// overwrite happens in the get_option arm).
fn insert_common_task_options(
    m: &mut BTreeMap<String, String>,
    dir: &Path,
    hooks: Option<&HookSet>,
    max_download_limit: u64,
    max_upload_limit: u64,
) {
    m.insert("dir".into(), dir.display().to_string());
    if let Some(hooks) = hooks {
        insert_hook_options(m, hooks);
    }
    m.insert("max-download-limit".into(), max_download_limit.to_string());
    m.insert("max-upload-limit".into(), max_upload_limit.to_string());
}

/// Hook option echo (effective-set projection): set slots echo by
/// name (the payload is the merged global baseline + per-task
/// override, source not distinguished — declared diff); unset slots
/// omit the key (the reference does not echo undefined keys); the
/// hash-check gate always echoes as a bool literal.
fn insert_hook_options(m: &mut BTreeMap<String, String>, hooks: &HookSet) {
    for ev in crate::hook::HookEvent::ALL {
        if let Some(cmd) = hooks.command(ev) {
            m.insert(ev.option_name().into(), cmd.to_string());
        }
    }
    m.insert(
        "bt-enable-hook-after-hash-check".into(),
        hooks.bt_enable_hook_after_hash_check.to_string(),
    );
}

/// seed-ratio/seed-time echo (`SeedPolicy.seed_time` Duration ->
/// minutes in one place; formats follow `format_seed_ratio` /
/// `format_minutes`).
fn insert_seed_options(m: &mut BTreeMap<String, String>, seed: &SeedPolicy) {
    m.insert("seed-ratio".into(), format_seed_ratio(seed.seed_ratio));
    m.insert(
        "seed-time".into(),
        format_minutes(seed.seed_time.as_secs_f64() / 60.0),
    );
}

/// select-file echo: 0-based stored indexes project to a normalized
/// 1-based comma string (storage holds the expanded index sequence;
/// the reference echoes the pre-parse stored value). None = unset
/// (select-all default) -> key omitted.
fn insert_select_file_option(m: &mut BTreeMap<String, String>, sel: Option<&[u32]>) {
    if let Some(sel) = sel {
        let one_based: Vec<String> = sel.iter().map(|i| (i + 1).to_string()).collect();
        m.insert("select-file".into(), one_based.join(","));
    }
}

pub(super) fn not_yet(
    reply: oneshot::Sender<Result<CommandReply, SessionError>>,
    method: &'static str,
) {
    let _ = reply.send(Err(SessionError::NotSupported { method }));
}

#[cfg(test)]
mod tests {
    use super::http_source_server_status;
    use crate::session::view::{HttpSourceState, ServerStatus};

    /// The getServers source-state projection covers the full domain:
    /// demoted/removed/failed never collapse back to waiting (matching
    /// the `http.sources` terminal projection) and the value stays
    /// within the four server states (the wire words are rendered by
    /// the rpc adapter's word table).
    #[test]
    fn http_source_server_status_projects_ledger_terminal_states() {
        assert_eq!(
            http_source_server_status(HttpSourceState::Active),
            ServerStatus::Working
        );
        assert_eq!(
            http_source_server_status(HttpSourceState::Waiting),
            ServerStatus::Waiting
        );
        assert_eq!(
            http_source_server_status(HttpSourceState::Demoted),
            ServerStatus::Error,
            "demoted != waiting"
        );
        assert_eq!(
            http_source_server_status(HttpSourceState::Failed),
            ServerStatus::Error,
            "probe-eliminated != waiting"
        );
        assert_eq!(
            http_source_server_status(HttpSourceState::Removed),
            ServerStatus::Disabled,
            "ledger removal = out of the source set (terminal)"
        );
    }
}

//! `taiji.moveStorage` orchestration (the SPEC §8.2 deferred
//! extension made real): move a task's on-disk payload to a new
//! download dir — same-volume atomic rename or cross-volume copy
//! (taiji-io fsmove) — with crash safety by journal + idempotent redo.
//!
//! Families: Torrent (the payload root = the multi-file `name` subtree
//! or the single file), HTTP (the `.part` file; the final name comes
//! from the row's `out` + `incomplete_suffix`), Magnet / .torrent-URL
//! and never-activated HTTP (a dir-only swap — nothing on disk, no
//! journal). Media keeps the `NotSupported` capability face (the
//! staging/output two-root layout is out of scope).
//!
//! State adjudication: waiting (Reserved/ReservedPaused) moves
//! immediately; Active quiesces through the changeOption restart path
//! (request_pause + restart_requested + token cancel — the Ended
//! teardown requeues at the front and the move fires before
//! reactivation); Seeding quiesces through the seed-pause face (the
//! requeue lands paused + seed_parked; the commit re-enters the seed
//! side via unpause). Checking / synthesis / results reject with the
//! changeOption-style wording.
//!
//! Crash safety: the [`MovePending`] journal lands in the row's
//! config_json **in the same upsert, strictly before any on-disk
//! action**; the payload source is never destroyed before the commit,
//! so the bootstrap close-out simply redoes the move and then commits
//! the row (`dir = to_dir`, journal cleared). A failed runtime move
//! keeps the journal (the next restart retries) and releases the hold
//! — the task continues at the old dir with data intact.
//!
//! Reply face: `Accepted` ("OK") on acceptance; completion is
//! observable through tellStatus's `dir` (the async-acceptance
//! semantics of the taiji.* extension — cross-volume copies of
//! gigabyte payloads must not stall the single-threaded actor).
use std::path::{Path, PathBuf};

use super::*;
use crate::session::persist::MovePending;

/// In-flight move bookkeeping (the actor-side runtime face; the
/// durable truth is the row's `move_pending` journal).
pub(super) struct MoveState {
    pending: MovePending,
    /// Payload roots (from → to); the mover's spawn_blocking inputs.
    from_payload: PathBuf,
    to_payload: PathBuf,
    /// An active-family task must tear down before the payload moves;
    /// the promotion step fires only once `running` no longer holds
    /// the gid.
    quiescing: bool,
    /// Seeding provenance: the seed-pause requeue lands paused, so the
    /// commit re-enters the seed side (unpause) instead of the
    /// download fillup.
    seed_resume: bool,
    /// The user paused the task while the move was in flight: the
    /// commit then honors the pause intent (no auto seed re-entry /
    /// no restart reactivation beyond what the queue state says).
    /// `pub(super)` — the pause command marks it (tasks.rs).
    pub(super) user_paused: bool,
    /// The mover task has been spawned (re-entry guard for the pump
    /// promotion step).
    fired: bool,
}

/// The task's on-disk payload root relative to the download dir
/// (multi-file = the `name` subtree, single-file = the file itself;
/// None = no derivable payload → dir-only swap).
fn torrent_payload_root(meta: &Metainfo) -> Option<String> {
    if meta.multi_file {
        return meta.name.clone().filter(|n| !n.is_empty());
    }
    let path = meta.meta.files.first()?.path.clone();
    let name = path.file_name()?.to_string_lossy().into_owned();
    (!name.is_empty()).then_some(name)
}

impl SessionActor {
    /// The `taiji.moveStorage(gid, dir)` command face. Accepts the
    /// move (journal + quiesce initiation) and answers `Accepted`;
    /// see the module docs for the completion semantics.
    pub(super) async fn move_storage(
        &mut self,
        raw_gid: String,
        dir: String,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(&raw_gid)?;
        if self.moving.contains_key(&gid) {
            return Err(SessionError::failed(format!(
                "storage move already in flight for GID#{gid}"
            )));
        }
        // A deferred recheck's teardown (or its post-Ended check-pool
        // entry) reads the payload at the current dir — refuse until it
        // settles (forceRecheck while moving is refused symmetrically
        // on its own face).
        if self.checking_deferred.contains(&gid) {
            return Err(SessionError::failed(format!(
                "Cannot move storage for GID#{gid}: recheck in flight"
            )));
        }
        // Selection-pending tasks rewrite cfg.dir at confirmation — a
        // concurrent move's journal would silently win over the
        // confirmed dir. Confirm first, then move.
        if self.queue.startup_held.contains_key(&gid) {
            return Err(SessionError::failed(format!(
                "Cannot move storage for GID#{gid}: file selection awaiting confirmation"
            )));
        }
        let to_dir = PathBuf::from(&dir);
        // Payload roots. Dir-only families (magnet / .torrent URL /
        // never-activated HTTP) commit inline — nothing is on disk, so
        // no journal and no moving entry exist.
        let payload = match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => {
                if to_dir == tj.dir {
                    return Err(same_dir_error(gid));
                }
                if to_dir.starts_with(&tj.dir) {
                    return Err(nested_move_error(gid));
                }
                torrent_payload_root(&tj.metainfo).map(|name| {
                    let from = tj.dir.join(&name);
                    let to = to_dir.join(&name);
                    (from, to)
                })
            }
            Some(Job::Http(job)) => {
                let row = job
                    .mirror
                    .as_ref()
                    .map(|m| crate::lock(m).clone())
                    .or_else(|| job.restore.clone());
                match row {
                    Some(row) if !row.out.is_empty() => {
                        let cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
                        // A pending publication carries absolute
                        // old-dir part/final paths that reactivation
                        // replays verbatim — relocating the .part under
                        // it wedges the finalize retry loop. Refuse
                        // until the publication settles (Published rows
                        // are results and refuse on location anyway).
                        if cfg.publication.as_ref().is_some_and(|r| {
                            r.phase != super::http_publication::PublicationPhase::Published
                        }) {
                            return Err(SessionError::failed(format!(
                                "Cannot move storage for GID#{gid}: publication in flight"
                            )));
                        }
                        let old_dir = PathBuf::from(&row.dir);
                        if to_dir == old_dir {
                            return Err(same_dir_error(gid));
                        }
                        if to_dir.starts_with(&old_dir) {
                            return Err(nested_move_error(gid));
                        }
                        let part = format!("{}{}", row.out, cfg.incomplete_suffix);
                        Some((old_dir.join(&part), to_dir.join(&part)))
                    }
                    _ => None,
                }
            }
            Some(Job::Magnet(_) | Job::TorrentUrl { .. }) => None,
            // Media keeps the explicit not_supported capability face
            // (the two-root staging layout is out of scope; declared).
            Some(Job::Media(_)) => {
                return Err(SessionError::NotSupported {
                    method: "taiji.moveStorage",
                });
            }
            None => {
                return Err(SessionError::failed(format!(
                    "Cannot move storage for GID#{gid}"
                )));
            }
        };

        // Location adjudication runs for BOTH faces: the dir-only fast
        // path must not run under a live engine/driver either — an
        // upgraded magnet's engine writes the spawn-time dest snapshot
        // and a probing HTTP driver stamps run.dir at plan time, so an
        // inline swap under Active/Seeding splits job-dir from
        // payload-dir (the row says NEW, the live task writes OLD).
        let location = self.queue.find(gid);
        // Dir-only swap: mutate the Job + row and answer — no disk
        // action, no journal, nothing to recover. Waiting face only
        // (see above).
        let Some((from_payload, to_payload)) = payload else {
            match location {
                Some(Location::Reserved | Location::ReservedPaused) => {}
                _ => {
                    return Err(SessionError::failed(format!(
                        "Cannot move storage for GID#{gid}: task is active — pause first"
                    )));
                }
            }
            self.swap_job_dir(gid, &to_dir).await;
            return Ok(CommandReply::Accepted);
        };

        let (quiescing, seed_resume) = match location {
            Some(Location::Reserved | Location::ReservedPaused) => (false, false),
            Some(Location::Active) => {
                if self.queue.finalizing.contains(&gid) {
                    return Err(SessionError::failed(format!(
                        "Cannot move storage for GID#{gid}: publication in flight"
                    )));
                }
                (true, false)
            }
            Some(Location::Seeding) => (true, true),
            _ => {
                return Err(SessionError::failed(format!(
                    "Cannot move storage for GID#{gid}"
                )));
            }
        };
        // Foreign destination guard: the mover's redo windows are the
        // only legitimate way a destination slot pre-exists at mover
        // time; at accept time it means another file owns the slot
        // (e.g. a same-length preallocated foreign .part — the
        // equal-length adoption heuristic must never see it).
        if to_payload.exists() {
            return Err(SessionError::failed(format!(
                "Cannot move storage for GID#{gid}: destination file already exists"
            )));
        }

        // Journal first (the same row upsert, strictly before any
        // on-disk action or quiesce).
        let pending = MovePending {
            from_dir: from_payload
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            to_dir: dir.clone(),
        };
        self.write_move_journal(gid, &pending).await?;
        // The durability seam: the journal must survive power loss that
        // the (fsynced) payload move outlives — one WAL checkpoint
        // right after the intent lands (best-effort; the periodic
        // save-session checkpoint backstops it).
        if let Some(p) = &self.persist {
            if let Err(e) = p.checkpoint().await {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "post-journal checkpoint failed (periodic save-session backstop applies)");
            }
        }

        self.moving.insert(
            gid,
            MoveState {
                pending,
                from_payload,
                to_payload,
                quiescing,
                seed_resume,
                user_paused: false,
                fired: false,
            },
        );

        // Quiesce initiation (the teardown completes asynchronously;
        // the pump promotion step fires the move once `running` is
        // gone — the changeOption restart path's bookkeeping). A failed
        // initiation (a pause/recheck teardown already in flight) rolls
        // the journal back and rejects: proceeding would race the
        // other teardown's own post-Ended spawn (recheck at the old dir
        // versus the mover).
        if quiescing {
            let initiated = if seed_resume {
                self.queue.request_seed_pause(gid)
            } else {
                self.queue.request_pause(gid)
            };
            if !initiated {
                self.clear_move_journal(gid).await;
                self.moving.remove(&gid);
                return Err(SessionError::failed(format!(
                    "Cannot move storage for GID#{gid}: teardown already in flight"
                )));
            }
            if !seed_resume {
                if let Some(rec) = self.queue.active_record_mut(gid) {
                    rec.restart_requested = true;
                }
            }
            if let Some(t) = self.running.get(&gid) {
                t.token.cancel();
            }
            if seed_resume {
                self.persist_transition(gid, TaskPhase::Paused).await;
            }
        }
        self.pump_all().await;
        Ok(CommandReply::Accepted)
    }

    /// Rollback face: strip the journal from the task row (mirror +
    /// upsert) with the dir left untouched — used when a move is
    /// refused after its journal landed (quiesce-initiation failure).
    async fn clear_move_journal(&mut self, gid: Gid) {
        let key = gid.to_string();
        if let Some((row, files)) = self.rows.get_mut(&key) {
            let mut cfg = PersistedTaskConfig::from_json(&row.config_json);
            if cfg.move_pending.take().is_none() {
                return;
            }
            row.config_json = cfg.to_json();
            let (row, files) = (row.clone(), files.clone());
            if let Some(p) = &self.persist {
                if let Err(e) = p.upsert_torrent(row, files).await {
                    warn!(target: "taiji::core::session", gid = %gid, %e,
                        "move journal rollback persist failed");
                }
            }
            return;
        }
        if let Some(Job::Http(job)) = self.jobs.get_mut(&gid) {
            let mut row = job
                .mirror
                .as_ref()
                .map(|m| crate::lock(m).clone())
                .or_else(|| job.restore.clone());
            if let Some(row) = row.as_mut() {
                let mut cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
                if cfg.move_pending.take().is_none() {
                    return;
                }
                row.config_json = cfg.to_json();
                let row = row.clone();
                if let Some(mirror) = job.mirror.as_ref() {
                    *crate::lock(mirror) = row.clone();
                }
                if job.restore.is_some() {
                    job.restore = Some(row.clone());
                }
                if let Some(p) = &self.persist {
                    if let Err(e) = p.upsert_http_task(row).await {
                        warn!(target: "taiji::core::session", gid = %gid, %e,
                            "move journal rollback persist failed (http)");
                    }
                }
            }
        }
    }

    /// Inline dir swap (dir-only families): mutate the Job, rewrite the
    /// row through the derived-config path (no journal involved).
    async fn swap_job_dir(&mut self, gid: Gid, to_dir: &Path) {
        match self.jobs.get_mut(&gid) {
            Some(Job::Torrent(tj)) => tj.dir = to_dir.to_path_buf(),
            Some(Job::Magnet(mj)) => mj.dest = to_dir.to_path_buf(),
            Some(Job::TorrentUrl { dir, .. }) => *dir = to_dir.to_path_buf(),
            Some(Job::Http(job)) => {
                job.dir = to_dir.to_path_buf();
                // A never-activated HTTP task may still carry a restore
                // row (no `out` yet): keep the row's dir in step so a
                // restart restores at the new dir.
                if let Some(row) = job.restore.as_mut() {
                    row.dir = to_dir.display().to_string();
                    let row = row.clone();
                    self.persist_http_row(&row).await;
                }
                return;
            }
            _ => return,
        }
        self.persist_refresh_config(gid).await;
    }

    /// Journal write (torrent face: the rows mirror + upsert; HTTP
    /// face: the mirror/restore row + upsert). An intent journal is not
    /// warn-grade: a failed upsert rejects the whole move (the mover
    /// must never relocate payload without the durable intent).
    async fn write_move_journal(
        &mut self,
        gid: Gid,
        pending: &MovePending,
    ) -> Result<(), SessionError> {
        match self.jobs.get(&gid) {
            Some(Job::Http(job)) => {
                let mut row = job
                    .mirror
                    .as_ref()
                    .map(|m| crate::lock(m).clone())
                    .or_else(|| job.restore.clone());
                let Some(row) = row.as_mut() else {
                    return Err(SessionError::failed(format!(
                        "Cannot move storage for GID#{gid}: no task row"
                    )));
                };
                let mut cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
                cfg.move_pending = Some(pending.clone());
                row.config_json = cfg.to_json();
                let row = row.clone();
                // Live copies in step (mirror + restore), then the row
                // upsert — the durable journal.
                if let Some(Job::Http(job)) = self.jobs.get_mut(&gid) {
                    if let Some(mirror) = job.mirror.as_ref() {
                        *crate::lock(mirror) = row.clone();
                    }
                    if job.restore.is_some() {
                        job.restore = Some(row.clone());
                    }
                }
                if let Some(persist) = &self.persist {
                    if let Err(e) = persist.upsert_http_task(row).await {
                        return Err(SessionError::failed(format!(
                            "move journal persist failed: {e}"
                        )));
                    }
                }
            }
            _ => {
                let key = gid.to_string();
                let Some((row, files)) = self.rows.get_mut(&key) else {
                    return Err(SessionError::failed(format!(
                        "Cannot move storage for GID#{gid}: no task row"
                    )));
                };
                let mut cfg = PersistedTaskConfig::from_json(&row.config_json);
                cfg.move_pending = Some(pending.clone());
                row.config_json = cfg.to_json();
                let (row, files) = (row.clone(), files.clone());
                if let Some(p) = &self.persist {
                    if let Err(e) = p.upsert_torrent(row, files).await {
                        return Err(SessionError::failed(format!(
                            "move journal persist failed: {e}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Pump promotion step (called at the top of [`SessionActor::pump_all`]):
    /// feed the queue's hold set, then spawn the mover for every entry
    /// whose quiesce has completed (`running` no longer holds the gid;
    /// waiting-origin entries were never quiescing).
    pub(super) fn promote_matured_moves(&mut self) {
        self.queue.set_moving(self.moving.keys().copied());
        let matured: Vec<Gid> = self
            .moving
            .iter()
            .filter(|(gid, m)| !m.fired && (!m.quiescing || !self.running.contains_key(gid)))
            .map(|(gid, _)| *gid)
            .collect();
        for gid in matured {
            let Some(state) = self.moving.get_mut(&gid) else {
                continue;
            };
            state.fired = true;
            let from = state.from_payload.clone();
            let to = state.to_payload.clone();
            let tag = gid.to_string();
            let events = self.events.clone();
            info!(target: "taiji::core::session", gid = %gid,
                from = %from.display(), to = %to.display(),
                "storage move payload migration started");
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    taiji_io::fsmove::move_path(&from, &to, &tag, taiji_io::fsmove::MoveMode::Auto)
                })
                .await
                .map_err(|e| format!("move task join failed: {e}"))
                .and_then(|r| r.map_err(|e| format!("move failed: {e}")));
                if let Err(error) = events
                    .send(TaskNotice::MoveDone {
                        gid,
                        result: Box::new(result),
                    })
                    .await
                {
                    warn!(target: "taiji::core::session", gid = %gid, %error,
                        "move completion notice dropped (session shutting down)");
                }
            });
        }
    }

    /// `TaskNotice::MoveDone` consume: commit the new dir (Job + row +
    /// journal cleared) and release the hold, or log the failure and
    /// release (the journal stays — the next bootstrap retries; the
    /// task continues at the old dir with data intact).
    pub(super) async fn finish_move(
        &mut self,
        gid: Gid,
        result: Result<taiji_io::fsmove::MoveOutcome, String>,
    ) {
        let Some(state) = self.moving.remove(&gid) else {
            return;
        };
        match result {
            Err(error) => {
                warn!(target: "taiji::core::session", gid = %gid, %error,
                    "storage move failed; task continues at the old dir \
                     (journal retained, next restart retries)");
                self.pump_all().await;
            }
            Ok(outcome) => {
                info!(target: "taiji::core::session", gid = %gid,
                    from = %state.pending.from_dir, to = %state.pending.to_dir,
                    outcome = ?outcome,
                    "storage move committed");
                let seed_resume = state.seed_resume && !state.user_paused;
                self.commit_move(gid, &state.pending).await;
                if seed_resume {
                    // Seeding provenance: the seed-pause requeue landed
                    // paused; re-enter the seed side (the unpause face
                    // routes seed_parked members back to seeding).
                    if let Err(error) = self.unpause(gid).await {
                        warn!(target: "taiji::core::session", gid = %gid, %error,
                            "post-move seed re-entry failed (task stays paused; \
                             unpause manually)");
                    }
                }
                self.pump_all().await;
            }
        }
    }

    /// Commit: swap the Job's dir, rewrite the row (`dir = to_dir`,
    /// journal cleared) and upsert. The task reactivates at the new
    /// dir on the following pump (restart semantics unchanged).
    async fn commit_move(&mut self, gid: Gid, pending: &MovePending) {
        let to_dir = PathBuf::from(&pending.to_dir);
        match self.jobs.get_mut(&gid) {
            Some(Job::Torrent(tj)) => {
                tj.dir = to_dir.clone();
                let key = gid.to_string();
                if let Some((row, files)) = self.rows.get_mut(&key) {
                    let mut cfg = PersistedTaskConfig::from_json(&row.config_json);
                    cfg.dir = pending.to_dir.clone();
                    cfg.move_pending = None;
                    row.dir = pending.to_dir.clone();
                    row.config_json = cfg.to_json();
                    let (row, files) = (row.clone(), files.clone());
                    if let Some(p) = &self.persist {
                        if let Err(e) = p.upsert_torrent(row, files).await {
                            warn!(target: "taiji::core::session", gid = %gid, %e,
                                "move commit row persist failed");
                        }
                    }
                }
            }
            Some(Job::Http(job)) => {
                job.dir = to_dir.clone();
                let mut row = job
                    .mirror
                    .as_ref()
                    .map(|m| crate::lock(m).clone())
                    .or_else(|| job.restore.clone());
                if let Some(row) = row.as_mut() {
                    let mut cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
                    cfg.move_pending = None;
                    row.dir = pending.to_dir.clone();
                    row.config_json = cfg.to_json();
                    let row = row.clone();
                    if let Some(Job::Http(job)) = self.jobs.get_mut(&gid) {
                        if let Some(mirror) = job.mirror.as_ref() {
                            *crate::lock(mirror) = row.clone();
                        }
                        if job.restore.is_some() {
                            job.restore = Some(row.clone());
                        }
                    }
                    self.persist_http_row(&row).await;
                }
            }
            // Dir-only families (magnet / .torrent URL) never
            // journal — the inline swap commits in one step; media
            // answers NotSupported. Unreachable with a journal.
            Some(_) => {}
            // Terminal mid-move (completed/removed while the mover
            // ran): the Job is gone, but a journal left on the row
            // must not outlive the move decision — strip it wherever
            // the row still lives so a later restart cannot replay a
            // stale intent (done/error rows are outside the startup
            // close-out's active set today; not stripping it here
            // would leave it dormant but misleading). The payload
            // landed wherever the mover put it; the row's dir stays
            // truthful for whatever face still reads it.
            None => {
                let key = gid.to_string();
                if !self.rows.contains_key(&key) {
                    if let Some(persist) = &self.persist {
                        if let Ok(Some(snapshot)) = persist.load_http_task(&key).await {
                            let mut row = snapshot.row;
                            let mut cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
                            if cfg.move_pending.take().is_some() {
                                row.config_json = cfg.to_json();
                                if let Err(e) = persist.upsert_http_task(row).await {
                                    warn!(target: "taiji::core::session", gid = %gid, %e,
                                        "terminal-row move journal strip failed");
                                }
                            }
                        }
                    }
                } else {
                    self.clear_move_journal(gid).await;
                }
            }
        }
    }

    /// Bootstrap close-out for a torrent row carrying a journal (the
    /// crash-recovery face): redo the move idempotently (fsmove), then
    /// commit the row — all before the Job/queue rebuild continues
    /// with the corrected dir. A redo failure keeps the journal and
    /// the old dir (the next restart retries; the declared posture).
    pub(super) async fn close_out_torrent_move(
        &self,
        gid_hex: &str,
        row: &mut TorrentRow,
        files: &[TorrentFileRow],
        cfg: &mut PersistedTaskConfig,
        meta: &Metainfo,
    ) {
        let Some(pending) = cfg.move_pending.clone() else {
            return;
        };
        let mut committed = false;
        if let Some(name) = torrent_payload_root(meta) {
            let from = Path::new(&pending.from_dir).join(&name);
            let to = Path::new(&pending.to_dir).join(&name);
            let tag = gid_hex.to_string();
            let moved = tokio::task::spawn_blocking(move || {
                taiji_io::fsmove::move_path(&from, &to, &tag, taiji_io::fsmove::MoveMode::Auto)
            })
            .await;
            match moved {
                Ok(Ok(outcome)) => {
                    info!(target: "taiji::core::session", gid = %gid_hex,
                        from = %pending.from_dir, to = %pending.to_dir,
                        outcome = ?outcome,
                        "startup storage-move close-out committed");
                    committed = true;
                }
                Ok(Err(error)) => {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                        "startup storage-move close-out failed; old dir retained \
                         (journal kept, next restart retries)");
                }
                Err(error) => {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                        "startup storage-move close-out join failed; old dir retained");
                }
            }
        } else {
            // No derivable payload (degenerate metadata): a dir-only
            // journal commits trivially.
            committed = true;
        }
        if committed {
            cfg.dir = pending.to_dir.clone();
            cfg.move_pending = None;
            row.dir = pending.to_dir.clone();
            row.config_json = cfg.to_json();
            if let Some(persist) = &self.persist {
                if let Err(error) = persist.upsert_torrent(row.clone(), files.to_vec()).await {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                        "startup move close-out row persist failed (row repairs on \
                         the next transition write)");
                }
            }
        }
    }

    /// Bootstrap close-out for an http row carrying a journal (the
    /// torrent face's twin; see [`Self::close_out_torrent_move`]).
    pub(super) async fn close_out_http_move(
        &self,
        gid_hex: &str,
        row: &mut taiji_store::persist::HttpTaskRow,
    ) {
        let mut cfg = http_task::HttpPersistConfig::from_json(&row.config_json);
        let Some(pending) = cfg.move_pending.clone() else {
            return;
        };
        let mut committed = false;
        if !row.out.is_empty() {
            let part = format!("{}{}", row.out, cfg.incomplete_suffix);
            let from = Path::new(&pending.from_dir).join(&part);
            let to = Path::new(&pending.to_dir).join(&part);
            let tag = gid_hex.to_string();
            let moved = tokio::task::spawn_blocking(move || {
                taiji_io::fsmove::move_path(&from, &to, &tag, taiji_io::fsmove::MoveMode::Auto)
            })
            .await;
            match moved {
                Ok(Ok(outcome)) => {
                    info!(target: "taiji::core::session", gid = %gid_hex,
                        from = %pending.from_dir, to = %pending.to_dir,
                        outcome = ?outcome,
                        "startup storage-move close-out committed (http)");
                    committed = true;
                }
                Ok(Err(error)) => {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                        "startup storage-move close-out failed (http); old dir \
                         retained (journal kept, next restart retries)");
                }
                Err(error) => {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                        "startup storage-move close-out join failed (http)");
                }
            }
        } else {
            committed = true;
        }
        if committed {
            cfg.move_pending = None;
            row.dir = pending.to_dir.clone();
            row.config_json = cfg.to_json();
            if let Some(persist) = &self.persist {
                if let Err(error) = persist.upsert_http_task(row.clone()).await {
                    warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                        "startup move close-out http row persist failed");
                }
            }
        }
    }
}

/// The nesting rejection (a move whose target dir lives inside the
/// current payload dir — fsmove's guard expressed at the dir face).
fn nested_move_error(gid: Gid) -> SessionError {
    SessionError::failed(format!(
        "Cannot move storage for GID#{gid}: target dir nested inside the current dir"
    ))
}

/// The no-op rejection (target equals the current dir — refused with
/// its own wording rather than the nesting text an equal-path
/// `starts_with` would produce).
fn same_dir_error(gid: Gid) -> SessionError {
    SessionError::failed(format!(
        "Cannot move storage for GID#{gid}: target equals the current dir"
    ))
}

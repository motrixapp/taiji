//! `taiji.renameFile` orchestration: rename one file of a torrent
//! task while it runs, with the libtorrent `rename_file` semantics on
//! this engine's execution model.
//!
//! Semantics (aligned with libtorrent / qBittorrent's RenameFileJob):
//! - **Identity preserving** — like libtorrent's in-memory
//!   `file_storage` path rewrite, only the host-side layout view
//!   changes. The raw metadata BLOB and both infohashes never move;
//!   peers, trackers, and piece maps are untouched.
//! - **Progress preserving** — the piece bitfield never enters the
//!   picture (file bytes do not move, only the path), so no recheck
//!   is triggered and no progress is lost.
//! - **Fenced** — libtorrent fences the rename behind the disk-io
//!   queue (no writer may hold the file); taiji fences at teardown
//!   granularity instead: an active/seeding task quiesces through the
//!   moveStorage restart path (request_pause + restart_requested +
//!   token cancel — the Ended teardown requeues at the front and the
//!   rename fires before reactivation, a coarser but equivalent
//!   no-writer guarantee).
//! - **Relative rename face** — qBittorrent renames a leaf name;
//!   this face takes full relative paths (a superset: moving a file
//!   across subdirectories inside the payload root is legal, escaping
//!   the root is not).
//!
//! Families: Torrent only (magnet / .torrent URL / HTTP / media reject
//! with the family face). States: waiting (Reserved/ReservedPaused)
//! renames after journaling without a quiesce; Active quiesces through
//! the changeOption restart path; Seeding quiesces through the
//! seed-pause face (the commit re-enters the seed side via unpause).
//! Checking / synthesis / results reject with the changeOption-style
//! wording.
//!
//! Crash safety (the [`crate::session::persist::RenamePending`]
//! journal): the intent lands in the row's `config_json` **in the same
//! upsert, strictly before any on-disk action**; the on-disk rename is
//! idempotent (`from` absent + `to` present = settled), so a kill at
//! any point recovers by redoing the rename and then committing the
//! row (`file_renames` gains the entry, journal cleared). A failed
//! runtime rename keeps the journal (the next restart retries) and
//! releases the hold — the task continues at the old path with data
//! intact.
//!
//! Reply face: `Accepted` ("OK") on acceptance; completion is
//! observable through `getFiles`/`tellStatus` `files[].path` (the
//! async-acceptance semantics of the taiji.* extension — the rename
//! must not stall the single-threaded actor).
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::*;
use crate::session::persist::RenamePending;

/// In-flight rename bookkeeping (the actor-side runtime face; the
/// durable truth is the row's `rename_pending` journal — the
/// [`move_storage::MoveState`] shape for a single file's path).
pub(super) struct RenameState {
    pending: RenamePending,
    /// An active-family task must tear down before the payload file
    /// moves; the promotion step fires only once `running` no longer
    /// holds the gid.
    quiescing: bool,
    /// Seeding provenance: the seed-pause requeue lands paused, so
    /// the commit re-enters the seed side (unpause) instead of the
    /// download fillup.
    seed_resume: bool,
    /// The user paused the task while the rename was in flight: the
    /// commit then honors the pause intent (no auto seed re-entry /
    /// no restart reactivation beyond what the queue state says).
    /// `pub(super)` — the pause command marks it (tasks.rs).
    pub(super) user_paused: bool,
    /// The renamer task has been spawned (re-entry guard for the pump
    /// promotion step).
    fired: bool,
}

/// Rebuild-time replay of the durable rename map onto a freshly
/// parsed [`Metainfo`] (the `output_paths::apply` sibling — pure path
/// overrides in the wire coordinate system; identity untouched).
pub(super) fn apply_renames(
    meta: &mut Metainfo,
    renames: &BTreeMap<usize, PathBuf>,
) -> Result<(), SessionError> {
    for (index, path) in renames {
        let Some(file) = meta.meta.files.get_mut(*index) else {
            return Err(SessionError::failed(
                "rename replay: file index out of range",
            ));
        };
        if !crate::session::actor::output_paths::is_safe_rel(path) {
            return Err(SessionError::failed("unsafe torrent rename mapping"));
        }
        file.path = path.clone();
    }
    Ok(())
}

/// Component-wise path equality (ignores `./` noise and trailing
/// separators; both sides are wire-relative).
fn same_path(a: &Path, b: &Path) -> bool {
    a.components().eq(b.components())
}

/// Normalize a client-supplied path face into the task's wire-relative
/// coordinate system: absolute paths must live under the task dir
/// (what `getFiles` hands back), relative paths are taken as-is.
/// Escapes (`..`, `/`, absolute paths outside the dir) reject.
fn wire_path(dir: &Path, raw: &str) -> Result<PathBuf, SessionError> {
    let candidate = Path::new(raw);
    let rel = if candidate.is_absolute() {
        candidate
            .strip_prefix(dir)
            .map_err(|_| SessionError::failed(format!("path '{raw}' lies outside the task dir")))?
    } else {
        candidate
    };
    if !crate::session::actor::output_paths::is_safe_rel(rel) {
        return Err(SessionError::failed(format!("unsafe path '{raw}'")));
    }
    Ok(rel.to_path_buf())
}

impl SessionActor {
    /// The `taiji.renameFile(gid, oldPath, newPath)` command face.
    /// Validates, journals, and (for active tasks) initiates the
    /// quiesce, then answers `Accepted`; see the module docs for the
    /// completion semantics.
    pub(super) async fn rename_file(
        &mut self,
        raw_gid: String,
        old_path: String,
        new_path: String,
    ) -> Result<CommandReply, SessionError> {
        let gid = self.resolve_gid(&raw_gid)?;
        if self.renaming.contains_key(&gid) {
            return Err(SessionError::failed(format!(
                "file rename already in flight for GID#{gid}"
            )));
        }
        // Cross-family fences: a storage move relocates the whole
        // payload, a deferred recheck hashes it — a rename must not
        // interleave with either (both refuse symmetrically on their
        // own faces).
        if self.moving.contains_key(&gid) {
            return Err(SessionError::failed(format!(
                "Cannot rename file for GID#{gid}: storage move in flight"
            )));
        }
        if self.checking_deferred.contains(&gid) {
            return Err(SessionError::failed(format!(
                "Cannot rename file for GID#{gid}: recheck in flight"
            )));
        }
        // Selection-pending tasks rewrite cfg.dir at confirmation —
        // a concurrent rename's journal would silently lose the race
        // against the selection commit. Confirm first, then rename.
        if self.queue.startup_held.contains_key(&gid) {
            return Err(SessionError::failed(format!(
                "Cannot rename file for GID#{gid}: file selection awaiting confirmation"
            )));
        }

        // Resolve the file + both path faces against the current wire
        // view (validate-before-mutate; nothing below touches state
        // until every check passed).
        let (index, rel_new, from_disk, to_disk) = {
            let Some(Job::Torrent(tj)) = self.jobs.get(&gid) else {
                return Err(SessionError::failed(format!(
                    "Cannot rename file for GID#{gid}"
                )));
            };
            let rel_old = wire_path(&tj.dir, &old_path)?;
            let rel_new = wire_path(&tj.dir, &new_path)?;
            // The disk face: the wire path under the multi-file root
            // prefix (the `Metainfo::disk_layout` rule — flattened
            // tasks carry the root inside the wire path already).
            let disk_rel = |wire: &Path| -> PathBuf {
                match (&tj.metainfo.name, tj.metainfo.multi_file) {
                    (Some(root), true) => Path::new(root).join(wire),
                    _ => wire.to_path_buf(),
                }
            };
            let index = tj
                .metainfo
                .meta
                .files
                .iter()
                .position(|f| !f.padding && same_path(&f.path, &rel_old));
            let Some(index) = index else {
                return Err(SessionError::failed(format!(
                    "Cannot rename file for GID#{gid}: no file matches path '{old_path}'"
                )));
            };
            // Pad entries are BEP47 transfer placeholders, not files.
            if tj.metainfo.meta.files[index].padding {
                return Err(SessionError::failed(format!(
                    "Cannot rename file for GID#{gid}: pad file cannot be renamed"
                )));
            }
            // Idempotent face: renaming to the current path is a
            // settled rename (qB/libtorrent answer success).
            if same_path(&tj.metainfo.meta.files[index].path, &rel_new) {
                return Ok(CommandReply::Accepted);
            }
            // Collision face: the target must not collide with (or
            // nest around) any other file's path — the combined
            // post-rename layout must stay a sane file tree.
            for (other, file) in tj.metainfo.meta.files.iter().enumerate() {
                if other == index || file.padding {
                    continue;
                }
                if same_path(&file.path, &rel_new) {
                    return Err(SessionError::failed(format!(
                        "Cannot rename file for GID#{gid}: target path already in use"
                    )));
                }
                let target_longer = rel_new.starts_with(&file.path);
                let file_longer = file.path.starts_with(&rel_new);
                if target_longer || file_longer {
                    return Err(SessionError::failed(format!(
                        "Cannot rename file for GID#{gid}: target path overlaps another file path"
                    )));
                }
            }
            (
                index,
                rel_new.clone(),
                tj.dir.join(disk_rel(&rel_old)),
                tj.dir.join(disk_rel(&rel_new)),
            )
        };

        let location = self.queue.find(gid);
        let (quiescing, seed_resume) = match location {
            Some(Location::Reserved | Location::ReservedPaused) => (false, false),
            Some(Location::Active) => {
                if self.queue.finalizing.contains(&gid) {
                    return Err(SessionError::failed(format!(
                        "Cannot rename file for GID#{gid}: publication in flight"
                    )));
                }
                (true, false)
            }
            Some(Location::Seeding) => (true, true),
            _ => {
                return Err(SessionError::failed(format!(
                    "Cannot rename file for GID#{gid}"
                )));
            }
        };
        // Foreign destination guard (the moveStorage accept-time face):
        // at accept time an existing destination means another file
        // owns the slot — the payload rename must never overwrite it.
        if to_disk.exists() {
            return Err(SessionError::failed(format!(
                "Cannot rename file for GID#{gid}: destination file already exists"
            )));
        }

        // Journal first (the same row upsert, strictly before any
        // on-disk action or quiesce).
        let pending = RenamePending {
            index,
            new_path: rel_new,
            from_disk: from_disk.display().to_string(),
            to_disk: to_disk.display().to_string(),
        };
        self.write_rename_journal(gid, &pending).await?;
        // The durability seam: the journal must survive power loss
        // that the (fsynced) payload rename outlives — one WAL
        // checkpoint right after the intent lands (best-effort; the
        // periodic save-session checkpoint backstops it).
        if let Some(p) = &self.persist {
            if let Err(e) = p.checkpoint().await {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "post-journal checkpoint failed (periodic save-session backstop applies)");
            }
        }

        self.renaming.insert(
            gid,
            RenameState {
                pending,
                quiescing,
                seed_resume,
                user_paused: false,
                fired: false,
            },
        );

        // Quiesce initiation (the teardown completes asynchronously;
        // the pump promotion step fires the rename once `running` is
        // gone — the moveStorage bookkeeping). A failed initiation (a
        // pause/recheck teardown already in flight) rolls the journal
        // back and rejects.
        if quiescing {
            let initiated = if seed_resume {
                self.queue.request_seed_pause(gid)
            } else {
                self.queue.request_pause(gid)
            };
            if !initiated {
                self.clear_rename_journal(gid).await;
                self.renaming.remove(&gid);
                return Err(SessionError::failed(format!(
                    "Cannot rename file for GID#{gid}: teardown already in flight"
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

    /// Journal write (the rows mirror + upsert). An intent journal is
    /// not warn-grade: a failed upsert rejects the whole rename (the
    /// renamer must never relocate payload without the durable
    /// intent).
    async fn write_rename_journal(
        &mut self,
        gid: Gid,
        pending: &RenamePending,
    ) -> Result<(), SessionError> {
        let key = gid.to_string();
        let Some((row, files)) = self.rows.get_mut(&key) else {
            return Err(SessionError::failed(format!(
                "Cannot rename file for GID#{gid}: no task row"
            )));
        };
        let mut cfg = PersistedTaskConfig::from_json(&row.config_json);
        cfg.rename_pending = Some(pending.clone());
        row.config_json = cfg.to_json();
        let (row, files) = (row.clone(), files.clone());
        if let Some(p) = &self.persist {
            if let Err(e) = p.upsert_torrent(row, files).await {
                return Err(SessionError::failed(format!(
                    "rename journal persist failed: {e}"
                )));
            }
        }
        Ok(())
    }

    /// Rollback face: strip the journal from the task row (mirror +
    /// upsert) with the paths left untouched — used when a rename is
    /// refused after its journal landed (quiesce-initiation failure).
    async fn clear_rename_journal(&mut self, gid: Gid) {
        let key = gid.to_string();
        let Some((row, files)) = self.rows.get_mut(&key) else {
            return;
        };
        let mut cfg = PersistedTaskConfig::from_json(&row.config_json);
        if cfg.rename_pending.take().is_none() {
            return;
        }
        row.config_json = cfg.to_json();
        let (row, files) = (row.clone(), files.clone());
        if let Some(p) = &self.persist {
            if let Err(e) = p.upsert_torrent(row, files).await {
                warn!(target: "taiji::core::session", gid = %gid, %e,
                    "rename journal rollback persist failed");
            }
        }
    }

    /// Pump promotion step (called from [`SessionActor::pump_all`]
    /// after `promote_matured_moves`): spawn the renamer for every
    /// entry whose quiesce has completed (`running` no longer holds
    /// the gid; waiting-origin entries were never quiescing).
    pub(super) fn promote_matured_renames(&mut self) {
        let matured: Vec<Gid> = self
            .renaming
            .iter()
            .filter(|(gid, r)| !r.fired && (!r.quiescing || !self.running.contains_key(gid)))
            .map(|(gid, _)| *gid)
            .collect();
        for gid in matured {
            let Some(state) = self.renaming.get_mut(&gid) else {
                continue;
            };
            state.fired = true;
            let from = PathBuf::from(&state.pending.from_disk);
            let to = PathBuf::from(&state.pending.to_disk);
            let events = self.events.clone();
            info!(target: "taiji::core::session", gid = %gid,
                from = %from.display(), to = %to.display(),
                "file rename payload migration started");
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || rename_payload_file(&from, &to))
                    .await
                    .map_err(|e| format!("rename task join failed: {e}"))
                    .and_then(|r| r);
                if let Err(error) = events
                    .send(TaskNotice::RenameDone {
                        gid,
                        result: Box::new(result),
                    })
                    .await
                {
                    warn!(target: "taiji::core::session", gid = %gid, %error,
                        "rename completion notice dropped (session shutting down)");
                }
            });
        }
    }

    /// `TaskNotice::RenameDone` consume: commit the renamed view
    /// (metainfo swap + row rewrite + journal cleared) and release
    /// the hold, or log the failure and release (the journal stays —
    /// the next bootstrap retries; the task continues at the old path
    /// with data intact).
    pub(super) async fn finish_rename(&mut self, gid: Gid, result: Result<(), String>) {
        let Some(state) = self.renaming.remove(&gid) else {
            return;
        };
        match result {
            Err(error) => {
                warn!(target: "taiji::core::session", gid = %gid, %error,
                    "file rename failed; task continues at the old path \
                     (journal retained, next restart retries)");
                self.pump_all().await;
            }
            Ok(()) => {
                info!(target: "taiji::core::session", gid = %gid,
                    from = %state.pending.from_disk, to = %state.pending.to_disk,
                    "file rename committed");
                let seed_resume = state.seed_resume && !state.user_paused;
                self.commit_rename(gid, &state.pending).await;
                if seed_resume {
                    // Seeding provenance: the seed-pause requeue landed
                    // paused; re-enter the seed side (the unpause face
                    // routes seed_parked members back to seeding).
                    if let Err(error) = self.unpause(gid).await {
                        warn!(target: "taiji::core::session", gid = %gid, %error,
                            "post-rename seed re-entry failed (task stays paused; \
                             unpause manually)");
                    }
                }
                self.pump_all().await;
            }
        }
    }

    /// Commit: swap the Job's metainfo view (identity untouched —
    /// the raw BLOB and infohashes never move), record the rename in
    /// the durable map, rewrite the row (`torrent_file` paths follow
    /// the new view, journal cleared) and upsert. The task reactivates
    /// on the following pump with a layout rebuilt from the new view
    /// (restart semantics unchanged).
    async fn commit_rename(&mut self, gid: Gid, pending: &RenamePending) {
        // (1) The Job face: a fresh metainfo view + the mirror map.
        let files_faces = match self.jobs.get_mut(&gid) {
            Some(Job::Torrent(tj)) => {
                let mut meta = (*tj.metainfo).clone();
                let Some(file) = meta.meta.files.get_mut(pending.index) else {
                    warn!(target: "taiji::core::session", gid = %gid,
                        "rename commit skipped: file index out of range");
                    return;
                };
                file.path = pending.new_path.clone();
                tj.metainfo = Arc::new(meta);
                tj.file_renames
                    .insert(pending.index, pending.new_path.clone());
                (tj.selected_files.clone(), tj.file_priorities.clone())
            }
            // Non-torrent jobs cannot carry a rename (the accept face
            // rejects them; unreachable in practice — same defensive
            // face as the terminal arm below).
            Some(_) => return,
            // Terminal mid-rename (removed while the renamer ran): the
            // Job is gone. The journal must not outlive the rename
            // decision — the strip below records the mapping wherever
            // the row still lives so a later restart cannot replay a
            // settled intent against a vanished path.
            None => {
                let key = gid.to_string();
                if let Some((row, files)) = self.rows.get_mut(&key) {
                    let mut cfg = PersistedTaskConfig::from_json(&row.config_json);
                    cfg.rename_pending = None;
                    cfg.file_renames
                        .insert(pending.index, pending.new_path.clone());
                    if let Some(file) = files
                        .iter_mut()
                        .find(|f| f.file_index == pending.index as i64)
                    {
                        file.path = pending.new_path.display().to_string();
                    }
                    row.config_json = cfg.to_json();
                    let (row, files) = (row.clone(), files.clone());
                    if let Some(p) = &self.persist {
                        if let Err(e) = p.upsert_torrent(row, files).await {
                            warn!(target: "taiji::core::session", gid = %gid, %e,
                                "rename commit row persist failed (terminal face)");
                        }
                    }
                }
                return;
            }
        };
        // (2) 先构造候选行落盘，仅在持久化成功后才清除内存中的 rename_pending journal，
        // 避免 DB 写入失败时内存假装已关闭 journal。
        let key = gid.to_string();
        let new_files = match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => crate::session::persist::file_rows_with_face(
                &key,
                &tj.metainfo.meta.files,
                files_faces.0.as_deref(),
                files_faces.1.as_deref(),
            ),
            _ => return,
        };
        let mut next_cfg = self.job_config(&gid);
        next_cfg.rename_pending = None;
        let config_json = next_cfg.to_json();
        if let Some((prev_row, _)) = self.rows.get(&key) {
            let mut cand_row = prev_row.clone();
            cand_row.config_json = config_json;
            let persisted_ok = if let Some(p) = &self.persist {
                match p.upsert_torrent(cand_row.clone(), new_files.clone()).await {
                    Ok(_) => true,
                    Err(e) => {
                        warn!(target: "taiji::core::session", gid = %gid, %e,
                            "rename commit row persist failed; journal kept in mirror for retry");
                        false
                    }
                }
            } else {
                true
            };
            if persisted_ok {
                self.rows.insert(key, (cand_row, new_files));
            }
        }
    }

    /// Bootstrap close-out for a torrent row carrying a rename
    /// journal (the crash-recovery face): redo the on-disk rename
    /// idempotently, then commit the row and the rebuilt metainfo
    /// view — all before the Job/queue rebuild continues on the
    /// corrected view. A redo failure keeps the journal and the old
    /// path (the next restart retries; the declared posture).
    pub(super) async fn close_out_torrent_rename(
        &self,
        gid_hex: &str,
        row: &mut TorrentRow,
        files: &[TorrentFileRow],
        cfg: &mut PersistedTaskConfig,
        meta: &mut Metainfo,
    ) {
        let Some(pending) = cfg.rename_pending.clone() else {
            return;
        };
        let from = PathBuf::from(&pending.from_disk);
        let to = PathBuf::from(&pending.to_disk);
        let moved = tokio::task::spawn_blocking(move || rename_payload_file(&from, &to)).await;
        match moved {
            Ok(Ok(())) => {
                info!(target: "taiji::core::session", gid = %gid_hex,
                    from = %pending.from_disk, to = %pending.to_disk,
                    "startup file-rename close-out committed");
            }
            Ok(Err(error)) => {
                warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                    "startup file-rename close-out failed; old path retained \
                     (journal kept, next restart retries)");
                return;
            }
            Err(error) => {
                warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                    "startup file-rename close-out join failed; old path retained");
                return;
            }
        }
        // Committed: record the mapping, follow the metainfo view and
        // the file row, clear the journal, upsert. (The Job rebuild
        // consumes `cfg.file_renames` and this already-corrected
        // metainfo.)
        cfg.rename_pending = None;
        cfg.file_renames
            .insert(pending.index, pending.new_path.clone());
        if let Some(file) = meta.meta.files.get_mut(pending.index) {
            file.path = pending.new_path.clone();
        }
        let mut files = files.to_vec();
        if let Some(file) = files
            .iter_mut()
            .find(|f| f.file_index == pending.index as i64)
        {
            file.path = pending.new_path.display().to_string();
        }
        row.config_json = cfg.to_json();
        if let Some(persist) = &self.persist {
            if let Err(error) = persist.upsert_torrent(row.clone(), files).await {
                warn!(target: "taiji::core::session", gid = %gid_hex, %error,
                    "startup rename close-out row persist failed (row repairs on \
                     the next transition write)");
            }
        }
    }
}

/// The fenced on-disk payload rename (the promotion step's
/// spawn_blocking body). Idempotent redo face:
/// - `from` absent + `to` present = a prior rename already settled
///   (a kill between the rename and the commit);
/// - `from` absent + `to` absent = the file was never written (a
///   metadata-only rename — nothing on disk to move);
/// - `to` present + `from` present = a foreign file owns the
///   destination — refuse, never overwrite.
fn rename_payload_file(from: &Path, to: &Path) -> Result<(), String> {
    if !from.exists() {
        // Both settled-prior and never-written faces: no disk action.
        return Ok(());
    }
    if to.exists() {
        return Err(format!("destination exists: {}", to.display()));
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir failed: {e}"))?;
    }
    std::fs::rename(from, to).map_err(|e| format!("rename failed: {e}"))
}

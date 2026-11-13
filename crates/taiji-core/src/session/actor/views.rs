//! Query view composition: the tellStatus base/live/result three-state
//! views, the getFiles file view, bittorrent dict assembly, and pure
//! functions such as bitmap / piece counts (the fetch-and-shape side of
//! the query seam).
//!
//! Owns: field composition of the outward status projection (mostly
//! pure functions).
//! Does not own: read sources (the engine query seam), command
//! dispatch (commands).
//!
//! Upstream anchor mapping: docs/design/core.md

use super::*;

/// Result-entry file_views budget cap: bounds the aggregate
/// amplification of the results table (1000 resident entries x each
/// entry's file views); truncated entries carry a
/// `[+N more truncated]` note, while length/count fields stay fully
/// accurate.
pub(crate) const MAX_RESULT_FILES: usize = 256;

impl SessionActor {
    // ---- query-face view assembly ----

    /// Base view for the waiting/metadata stages (no live readings;
    /// full fields once metadata is available).
    pub(super) fn base_status_view(&self, gid: Gid, status: StatusKind) -> TorrentStatusView {
        let status = if self.queue.startup_held.contains_key(&gid) {
            StatusKind::Paused
        } else {
            status
        };
        let mut view = TorrentStatusView::minimal(gid, status, 0, 0);
        // aria2 isSeeder: always false with no piece storage (the
        // "false" key is always present).
        view.seeder = Some(false);
        match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => {
                let meta = &tj.metainfo;
                view.total_length = tj.total_len;
                view.dir = tj.dir.display().to_string();
                view.piece_length = meta.meta.piece_length;
                let lens: Vec<u64> = meta.meta.files.iter().map(|f| f.length).collect();
                let bases = file_piece_bases(&lens, meta.meta.piece_length);
                view.num_pieces = bases.last().copied().unwrap_or(0)
                    + lens
                        .last()
                        .map(|&l| piece_count(l, meta.meta.piece_length))
                        .unwrap_or(0);
                view.files = file_views(
                    &meta.meta,
                    None,
                    tj.selected_files.as_deref(),
                    tj.file_priorities.as_deref(),
                );
                view.bittorrent = Some(torrent_bittorrent_view(tj));
                view.info_hash = info_hash_20(&meta.meta.identity);
            }
            Some(Job::Magnet(mj)) => {
                view.dir = mj.dest.display().to_string();
                view.bittorrent = Some(magnet_bittorrent_view(mj));
                let identity = TorrentIdentity {
                    v1: mj.btih,
                    v2: mj.btmh,
                };
                view.info_hash = info_hash_20(&identity);
                // followedBy/following fields are provided as specified:
                // in-place upgrade = the same-GID degradation chain (the
                // [`crate::magnet::MetadataChain`]
                // followed_by/following semantics, the aria2
                // RequestGroup.cc projection point); not given during
                // the metadata stage (pre-upgrade), matching aria2's
                // metadata group with no followedBy before upgrade.
                if mj.upgraded {
                    view.followed_by = vec![gid];
                    view.following = Some(gid);
                    // After upgrade, total comes from the back-fill face
                    // (during the metadata stage aria2's
                    // totalLengthIsUnknown also reads 0; after the
                    // upgrade, query_status no longer answers inside the
                    // engine finalization window, so the live view falls
                    // back to this base view — without this back-fill
                    // the finalization window and the result entry would
                    // both collapse to 0/0).
                    view.total_length = self.running.get(&gid).map(|t| t.total_len).unwrap_or(0);
                }
            }
            Some(Job::TorrentUrl { dir, .. }) => {
                view.dir = dir.display().to_string();
            }
            Some(Job::Media(mj)) => {
                view.dir = mj.cfg.output_dir.display().to_string();
                // Cold-row projection: the restore row's phase (a
                // paused task reads its persisted phase; the phase
                // memory rides phase_detail).
                if let Some(row) = &mj.cfg.restore {
                    view.media = Some(super::super::view::MediaView {
                        kind: row.kind.clone(),
                        phase: row.state.clone(),
                        phase_detail: row.phase_detail_json.clone(),
                        tracks: Vec::new(),
                        staging_dir: row.staging_dir.clone(),
                        output_name: row.output_name.clone(),
                        selector: row.selector_json.clone(),
                        variant: None,
                        manifest_url: row.manifest_url.clone(),
                    });
                } else {
                    view.media = Some(self.job_media_view(gid, mj));
                }
            }
            Some(Job::Http(hj)) => {
                view.dir = hj.dir.display().to_string();
                // Cold-row projection (no live readings): real in-row
                // progress — the fork returns real values for paused
                // tasks (same rule as the fork); a constant 0/0 would be
                // an out-of-whitelist compat difference and would appear
                // in bulk in migration scenarios.
                let (total, done) = http_cold_lengths(hj);
                view.total_length = total;
                view.completed_length = done;
                // HTTP task view: take the live readings when present
                // (the waiting/paused face = cold-row projection + the
                // source list — the aria2 reserved face's keys, same
                // shape).
                view.http = Some(self.job_http_view(gid, hj));
            }
            None => {}
        }
        resolve_file_paths(&view.dir, &mut view.files);
        view
    }

    /// HTTP task http sub-dictionary view assembly: live readings win
    /// (atomic synchronous reads), otherwise the task's static face
    /// (source list waiting, zero connections, zero progress).
    pub(super) fn job_http_view(&self, gid: Gid, hj: &HttpJob) -> super::super::view::HttpView {
        if let Some(live) = self.running.get(&gid).and_then(|t| t.backend.http_live()) {
            return live.http_view();
        }
        super::super::view::HttpView {
            final_url: hj.uris.first().cloned().unwrap_or_default(),
            connections: 0,
            extents_active: 0,
            blocks_done: 0,
            blocks_total: 0,
            encoding: None,
            rename_pending: false,
            sources: hj
                .uris
                .iter()
                .map(|u| super::super::view::HttpSourceView {
                    url: u.clone(),
                    rate: 0,
                    state: "waiting".into(),
                })
                .collect(),
        }
    }

    /// Media task `media` sub-dictionary view assembly: live readings
    /// win (the mutex rollup — phase/tracks/staging), otherwise the
    /// job's static face (phase queued, the staging layout derived).
    pub(super) fn job_media_view(
        &self,
        gid: Gid,
        mj: &media_task::MediaJob,
    ) -> super::super::view::MediaView {
        let st = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.media_live())
            .map(|live| crate::lock(live));
        match st {
            Some(st) => super::super::view::MediaView {
                kind: if st.kind.is_empty() { "hls" } else { st.kind }.to_string(),
                phase: st.phase.as_str().to_string(),
                phase_detail: st.phase_detail.clone(),
                tracks: st
                    .tracks
                    .iter()
                    .map(|t| super::super::view::MediaTrackView {
                        label: t.label.clone(),
                        kind: t.kind.to_string(),
                        state: t.state.to_string(),
                        segments_done: t.segments_done,
                        segments_total: t.segments_total,
                    })
                    .collect(),
                staging_dir: st.staging_dir.clone(),
                output_name: st.output_name.clone(),
                selector: st.selector.clone(),
                variant: st.variant.clone(),
                manifest_url: st.manifest_url.clone(),
            },
            None => super::super::view::MediaView {
                kind: "hls".to_string(),
                phase: taiji_media::MediaPhase::Queued.as_str().to_string(),
                phase_detail: None,
                tracks: Vec::new(),
                staging_dir: mj.cfg.staging_gid_dir().display().to_string(),
                output_name: None,
                selector: mj.cfg.selector.clone(),
                variant: None,
                manifest_url: mj.cfg.url.clone(),
            },
        }
    }

    /// Single-file view of an HTTP task (the createFileEntry shape:
    /// index/path/length/completedLength + uris = the source list).
    /// `live` present = running readings; a terminal snapshot uses the
    /// retire-time arguments.
    pub(super) fn http_file_view(
        &self,
        hj: &HttpJob,
        total: u64,
        completed: u64,
        live: Option<&Arc<http_task::HttpLive>>,
    ) -> FileEntryView {
        // Cold projection (no live): the planned final name from the row
        // mirror (the actual on-disk name after sanitization /
        // auto-rename, written into `row.out` during the drive phase)
        // takes priority over the admission-face raw `out` (URL-derived
        // tasks have hj.out = None; auto-renamed tasks have hj.out = the
        // original name — using it directly would project the requested
        // name, not the actual one). A missing mirror (not yet
        // activated) = the existing placeholder projection unchanged.
        let out_path = live
            .map(|l| l.out_path_str())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| {
                let planned = hj
                    .mirror
                    .as_ref()
                    .map(|m| crate::lock(m).out.clone())
                    .filter(|o| !o.is_empty());
                planned
                    .or_else(|| hj.out.clone())
                    .filter(|name| !name.is_empty())
                    .map(|name| hj.dir.join(name).display().to_string())
                    .unwrap_or_default()
            });
        let uris = live
            .map(|l| l.source_uris())
            .unwrap_or_else(|| hj.uris.clone());
        FileEntryView {
            index: 1,
            path: out_path,
            // HTTP single-file tasks have no selection face (aria2
            // select-file belongs to the multi-file torrent/metalink
            // domain; a single file is always a requested entry) —
            // routed through the single-source projection function's
            // None face (select all), the same projection source as the
            // BT view.
            selected: file_selected(None, Some(0)),
            priority: 0,
            length: total,
            completed_length: completed,
            uris: uris
                .iter()
                .map(|u| UriEntryView {
                    uri: u.clone(),
                    status: "used",
                })
                .collect(),
            pieces_root: None,
            piece_size: 0,
            padding: false,
            recovery: None,
        }
    }

    /// Recheck-in-flight view (the checking projection domain): active
    /// semantics (an aria2 verification-period group is active — no
    /// separate status value) + a verification-progress projection —
    /// completed = `checked pieces x piece_length` (`session::recheck`
    /// feeds one point per piece, min-clamped to total; the "checked"
    /// accounting includes failed pieces), zero speed/connections (no
    /// transfer during verification). The bitfield key is absent (the
    /// measured bitmap is only trustworthy after verification completes
    /// and is written back to the progress row).
    pub(super) fn checking_status_view(&self, gid: Gid) -> TorrentStatusView {
        let mut view = self.base_status_view(gid, StatusKind::Active);
        let total = view.total_length;
        let piece_len = u64::from(view.piece_length);
        if let (Some(sink), false) = (
            self.checking_progress.get(&gid),
            piece_len == 0 || total == 0,
        ) {
            let checked = sink.load(std::sync::atomic::Ordering::Relaxed);
            view.completed_length = (checked.saturating_mul(piece_len)).min(total);
        }
        resolve_file_paths(&view.dir, &mut view.files);
        view
    }

    /// Active-task live view: base view + engine snapshot (speeds /
    /// connections / synthetic bitmap / per-file completed amounts /
    /// seeder / numSeeders). magnet/url metadata tasks have no
    /// EngineHandle (the MagnetEngine internal upgrade architecture) ->
    /// metadata-stage readings (speed 0, honest values). Engine status
    /// readings go through the per-engine snapshot cache read seam (zero
    /// round trips within [`STATUS_CACHE_TTL`] — the polling face lags
    /// by at most TTL in exchange for an unblocked control face;
    /// invalidation = a TaskNotice for that gid, see the run() event
    /// arm).
    pub(super) async fn live_status_view(&mut self, gid: Gid) -> TorrentStatusView {
        let mut view = self.base_status_view(gid, StatusKind::Active);
        // HTTP task live readings (no engine; atomic synchronous reads,
        // no command-channel occupancy).
        if let Some(Job::Http(hj)) = self.jobs.get(&gid) {
            let live = self
                .running
                .get(&gid)
                .and_then(|t| t.backend.http_live().cloned());
            if let Some(live) = &live {
                view.total_length = live.total_len.load(std::sync::atomic::Ordering::Relaxed);
                // Byte-level real-time projection: completedLength reads
                // the real written-bytes counter (block bookkeeping as
                // the base layer + sink write points accumulating
                // monotonically, clamped to the known total length) —
                // aria2's byte-level same granularity, so 1 Hz sampling
                // compares directly across engines; block bookkeeping
                // remains the persistence authority (projection !=
                // bookkeeping; the http sub-dictionary blocks face and
                // the cold-row projection keep the block accounting).
                view.completed_length = live.completed_bytes();
                view.download_speed = live.rate.load(std::sync::atomic::Ordering::Relaxed);
                view.connections = live.connections.load(std::sync::atomic::Ordering::Relaxed);
                view.http = Some(live.http_view());
            }
            let (total, completed) = (view.total_length, view.completed_length);
            view.files = vec![self.http_file_view(hj, total, completed, live.as_ref())];
            return view;
        }
        // Media task live readings (no engine; the mutex rollup).
        if let Some(Job::Media(mj)) = self.jobs.get(&gid) {
            if let Some(live) = self
                .running
                .get(&gid)
                .and_then(|t| t.backend.media_live().cloned())
            {
                if let Ok(st) = live.lock() {
                    view.completed_length = st.bytes_done;
                    view.download_speed = st.rate;
                    if let Some(name) = &st.output_name {
                        view.files = vec![super::super::view::FileEntryView {
                            index: 1,
                            path: mj.cfg.output_dir.join(name).display().to_string(),
                            selected: file_selected(None, Some(0)),
                            priority: 0,
                            length: 0,
                            completed_length: st.bytes_done,
                            uris: vec![super::super::view::UriEntryView {
                                uri: mj.cfg.url.clone(),
                                status: "used",
                            }],
                            pieces_root: None,
                            piece_size: 0,
                            padding: false,
                            recovery: None,
                        }];
                    }
                }
            }
            view.media = Some(self.job_media_view(gid, mj));
            return view;
        }
        let Some(engine) = self
            .running
            .get(&gid)
            .and_then(|t| t.backend.engine().cloned())
        else {
            return view;
        };
        // Engine status readings go through the cached read seam (within
        // TTL the cache is used directly; expired / event-invalidated ->
        // the existing bounded command channel + oneshot
        // `query_status`, with a back-fill). An engine-exit race ->
        // SessionClosed -> None -> keep the base view, honest zeros
        // (same shape as the existing failure face).
        let Some(snap) = self.engine_status_cached(gid).await else {
            return view;
        };
        view.total_length = if snap.total_length > 0 {
            snap.total_length
        } else {
            view.total_length
        };
        view.completed_length = snap.completed_length;
        view.upload_length = snap.upload_length;
        view.download_speed = snap.download_speed;
        view.upload_speed = snap.upload_speed;
        view.connections = snap.connections;
        view.bitfield = snap.bitfield.clone();
        view.piece_length = snap.piece_length;
        view.num_pieces = snap.num_pieces;
        view.seeder = Some(snap.seeder);
        if let Some(Job::Torrent(tj)) = self.jobs.get(&gid) {
            let meta = &tj.metainfo.meta;
            let lens: Vec<u64> = meta.files.iter().map(|f| f.length).collect();
            let bases = file_piece_bases(&lens, snap.piece_length);
            // Per-file completed amounts = bitmap-range conversion (the
            // createFileEntry accounting).
            let per_file = snap
                .bitfield
                .as_ref()
                .map(|bf| per_file_completed(bf, snap.piece_length, &bases, &lens));
            view.files = file_views(
                meta,
                per_file.as_deref(),
                tj.selected_files.as_deref(),
                tj.file_priorities.as_deref(),
            );
            // Missing-layer projection: the engine snapshot's recovery
            // file states are patched into the entries (the 0-based
            // meta.files position = the files vector position;
            // getFiles/tellStatus.files share this view, so a management
            // UI can show "waiting for hash recovery").
            for (idx, st) in &snap.recovery_files {
                if let Some(f) = view.files.get_mut(*idx as usize) {
                    f.recovery = Some(*st);
                }
            }
            view.dir = tj.dir.display().to_string();
        }
        // numSeeders = the seeder peer count (aria2 countSeeder,
        // RpcMethodImpl.cc). The detail query face (the same seam as
        // getPeers) does not go through the status snapshot cache —
        // direct query as today. The count face does not package the
        // bitmap (zero transient materialization).
        if let Ok(peers) = engine.query_peers_summary().await {
            view.num_seeders = peers.iter().filter(|p| p.seeder).count() as u64;
        }
        resolve_file_paths(&view.dir, &mut view.files);
        view
    }

    /// Seeding-resident live view: the [`Self::live_status_view`] face
    /// with the status flipped to `seeding` (the projection
    /// finalization: residence and seed_wait share the
    /// `'seeding'` row state, the projection follows it; the interim of
    /// projecting residents as `active` is closed).
    /// tellActive's seeding segment and tellStatus's Seeding arm share
    /// this one face, so the two projections cannot drift.
    pub(super) async fn seeding_live_view(&mut self, gid: Gid) -> TorrentStatusView {
        let mut view = self.live_status_view(gid).await;
        view.status = StatusKind::Seeding;
        resolve_file_paths(&view.dir, &mut view.files);
        view
    }

    /// Result-entry view (the gatherStoppedDownload field face).
    pub(super) fn result_status_view(&self, r: &DownloadResultEntry) -> TorrentStatusView {
        let mut v = TorrentStatusView::minimal(r.gid, r.status, r.total_length, r.completed_length);
        v.upload_length = r.upload_length;
        v.download_length = r.download_length;
        v.bitfield = r.bitfield.clone();
        v.piece_length = r.piece_length;
        v.num_pieces = r.num_pieces;
        v.files = r.files.clone();
        v.num_files_full = r.num_files_full;
        v.bittorrent = r.bittorrent.clone();
        v.info_hash = r.info_hash;
        // The aria2 ds->result numeric face: FINISHED=0 / REMOVED=31 /
        // everything else merged into UNKNOWN_ERROR=1 (error_code.h;
        // the error message is preserved with the entry).
        v.error_code = Some(match r.status {
            StatusKind::Complete => 0,
            StatusKind::Removed => 31,
            _ => 1,
        });
        // Per-code refinement chain: engine-side structured failures are
        // passed through with the entry, and numeric-face refinement
        // happens in the taiji-rpc rendering layer (the mapping's single
        // source; per-code and per-detail end to end — status-code
        // families / read-idle timeouts do not collapse).
        v.error_engine = r.error_engine.clone();
        v.error_message = Some(r.error_message.clone().unwrap_or_default());
        v.dir = r.dir.clone();
        // The http sub-dictionary terminal snapshot is passed through
        // with the entry (None = the key is absent for non-HTTP tasks).
        v.http = r.http.clone();
        // The media sub-dictionary terminal snapshot is passed through
        // with the entry (None = the key is absent for non-media
        // tasks).
        v.media = r.media.clone();
        // The seeder key is not in the stopped face
        // (gatherStoppedDownload has no KEY_SEEDER).
        v.seeder = None;
        v
    }

    /// Terminal-state display snapshot into the DownloadResult table
    /// (the isomorphic face of the aria2 DownloadResult keeping
    /// fileEntries/bitfield/attrs; the task payload is still present at
    /// finalization time).
    pub(super) fn build_result_entry(
        &self,
        gid: Gid,
        status: StatusKind,
        total: u64,
        completed: u64,
        note: Option<String>,
    ) -> DownloadResultEntry {
        let mut e = DownloadResultEntry {
            gid,
            status,
            total_length: total,
            completed_length: completed,
            upload_length: 0,
            download_length: 0,
            dir: String::new(),
            error_message: note,
            error_engine: None,
            bitfield: None,
            piece_length: 0,
            num_pieces: 0,
            info_hash: None,
            files: Vec::new(),
            num_files_full: None,
            bittorrent: None,
            http: None,
            media: None,
        };
        let complete = status == StatusKind::Complete;
        match self.jobs.get(&gid) {
            Some(Job::Torrent(tj)) => {
                let meta = &tj.metainfo.meta;
                e.dir = tj.dir.display().to_string();
                e.piece_length = meta.piece_length;
                let lens: Vec<u64> = meta.files.iter().map(|f| f.length).collect();
                let bases = file_piece_bases(&lens, meta.piece_length);
                e.num_pieces = total_piece_count(&bases, &lens, meta.piece_length);
                let per: Vec<u64> = if complete {
                    lens.clone()
                } else {
                    vec![0; lens.len()]
                };
                // Result-entry file_views budget: bounds the aggregate
                // amplification of the results table (1000 resident
                // entries x full file views each — a 100k-file task is
                // tens of MB per entry). Beyond the cap, truncate to the
                // first MAX_RESULT_FILES entries (an aria2-face semantic
                // difference: the tellStopped file list is truncated and
                // entry N+1's name carries the truncation note;
                // length/count fields stay fully accurate).
                let full = file_views(
                    meta,
                    Some(&per),
                    tj.selected_files.as_deref(),
                    tj.file_priorities.as_deref(),
                );
                if full.len() > MAX_RESULT_FILES {
                    warn!(target: "taiji::core::session",
                        gid = %gid, total = full.len(),
                        cap = MAX_RESULT_FILES,
                        "result entry files truncated (memory budget)");
                    let total_files = full.len() as u64;
                    let mut cut = full;
                    cut.truncate(MAX_RESULT_FILES);
                    let kept = cut.len() as u64;
                    if let Some(last) = cut.last_mut() {
                        last.path =
                            format!("{} [+{} more truncated]", last.path, total_files - kept);
                    }
                    e.num_files_full = Some(total_files);
                    e.files = cut;
                } else {
                    e.files = full;
                }
                // Complete-state bitmap = an all-ones synthetic bitmap
                // (trailing bits 0); a partial bitmap of a partially
                // complete terminal state is not kept -> None (key
                // absent, the same default as aria2's empty bitmap).
                e.bitfield = complete.then(|| all_ones_bitfield(e.num_pieces));
                e.info_hash = info_hash_20(&meta.identity);
                e.bittorrent = Some(torrent_bittorrent_view(tj));
            }
            Some(Job::Magnet(mj)) => {
                e.dir = mj.dest.display().to_string();
                e.info_hash = info_hash_20(&TorrentIdentity {
                    v1: mj.btih,
                    v2: mj.btmh,
                });
                e.bittorrent = Some(magnet_bittorrent_view(mj));
            }
            Some(Job::TorrentUrl { dir, .. }) => {
                e.dir = dir.display().to_string();
            }
            Some(Job::Media(mj)) => {
                e.dir = mj.cfg.output_dir.display().to_string();
                e.media = Some(self.job_media_view(gid, mj));
                let completed = if complete { total } else { 0 };
                let name = self.job_media_view(gid, mj).output_name.unwrap_or_default();
                e.files = vec![super::super::view::FileEntryView {
                    index: 1,
                    path: mj
                        .cfg
                        .output_dir
                        .join(if name.is_empty() { "media.mp4" } else { &name })
                        .display()
                        .to_string(),
                    selected: file_selected(None, Some(0)),
                    priority: 0,
                    length: total,
                    completed_length: completed,
                    uris: vec![super::super::view::UriEntryView {
                        uri: mj.cfg.url.clone(),
                        status: "used",
                    }],
                    pieces_root: None,
                    piece_size: 0,
                    padding: false,
                    recovery: None,
                }];
            }
            Some(Job::Http(hj)) => {
                e.dir = hj.dir.display().to_string();
                // http sub-dictionary terminal snapshot (the live
                // readings at retire time — the renamePending flag is
                // preserved with the terminal entry).
                let live = self
                    .running
                    .get(&gid)
                    .and_then(|t| t.backend.http_live().cloned());
                if let Some(live) = &live {
                    e.http = Some(live.http_view());
                }
                let completed = if complete { total } else { e.completed_length };
                e.files = vec![self.http_file_view(hj, total, completed, live.as_ref())];
            }
            None => {}
        }
        resolve_file_paths(&e.dir, &mut e.files);
        e
    }
}

// ---- query-face view assembly free functions (field semantics in the
// session::view payload docs) ----

/// HTTP cold-row readings (no live projection face):
/// `(total_length, completed_length)`.
///
/// The row source = the active row mirror first (the freshest progress
/// truth written back by [`http_task::sync_mirror_progress`] during
/// activation), falling back to the bootstrap-registered row (the
/// import mapping face / the add-registered row). `completedLength` =
/// the row's `total_done`; `totalLength` takes the probe-authoritative
/// total (`probe_json`), else the grid-derived total
/// (`block_count x block_size` — the in-row total truth of imported
/// bitmap rows; a non-aligned total overestimates by at most one block,
/// a declared deviation), else 0 (the same shape as the fork's unknown
/// total).
pub(super) fn http_cold_lengths(hj: &HttpJob) -> (u64, u64) {
    let row = hj
        .mirror
        .as_ref()
        .map(|m| crate::lock(m).clone())
        .or_else(|| hj.restore.clone());
    let Some(row) = row else {
        return (0, 0);
    };
    let done = row.total_done.max(0) as u64;
    let probe_total = row
        .probe_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<crate::session::http::ValidatorFacts>(raw).ok())
        .and_then(|f| f.total_len);
    let grid_total = match (row.block_count, row.block_size) {
        (Some(count), size) if count > 0 && size > 0 => count as u64 * size as u64,
        _ => 0,
    };
    (probe_total.unwrap_or(grid_total), done)
}

/// Piece count of a single file (ceil(len/piece_len); a 0-length file
/// has 0 pieces — the same formula).
pub(super) fn piece_count(len: u64, piece_len: u32) -> u64 {
    if len == 0 {
        0
    } else {
        len.div_ceil(u64::from(piece_len))
    }
}

/// Total piece count of the synthetic piece space (the sum of per-file
/// piece counts; the final value of [`file_piece_bases`]).
pub(super) fn total_piece_count(bases: &[u64], lens: &[u64], piece_len: u32) -> u64 {
    match bases.last() {
        Some(&last) => last + lens.last().map(|&l| piece_count(l, piece_len)).unwrap_or(0),
        None => 0,
    }
}

/// Complete-state synthetic bitmap (all ones, trailing bits 0 — the
/// session-side equivalent of the synthesized_bitfield full bitmap,
/// avoiding keeping an engine handle for a terminal snapshot).
pub(super) fn all_ones_bitfield(num_pieces: u64) -> Vec<u8> {
    let bytes = num_pieces.div_ceil(8) as usize;
    let mut out = vec![0xFFu8; bytes];
    let rem = (num_pieces % 8) as usize;
    if rem > 0 {
        if let Some(last) = out.last_mut() {
            *last = 0xFFu8 << (8 - rem);
        }
    }
    out
}

/// The 20-byte outward infohash: the v1 sha1 verbatim; v2-only = a
/// truncated sha256 (the field accounting is noted).
pub(super) fn info_hash_20(identity: &TorrentIdentity) -> Option<[u8; 20]> {
    match (identity.v1, identity.v2) {
        (Some(v1), _) => Some(v1),
        (None, Some(v2)) => {
            let mut t = [0u8; 20];
            t.copy_from_slice(&v2[..20]);
            Some(t)
        }
        _ => None,
    }
}

/// File view list (the createFileEntry field face + the piecesRoot /
/// pieceSize / padding additions; `completed` = per-file completed
/// amounts, defaulting to all 0 — the waiting face).
///
/// `selection` = the task selection face (`cfg.selected_files`; the
/// BEP53 client file list = 0-based over non-pad entries): the
/// `selected` truth is projected through the [`file_selected`] single
/// source (the aria2 isRequested accounting; None = select all). Pad
/// entries take no part in index counting (anchored the same as the
/// engine `selection_mask`).
pub(super) fn file_views(
    meta: &TorrentMeta,
    completed: Option<&[u64]>,
    selection: Option<&[u32]>,
    priorities: Option<&[(u32, i8)]>,
) -> Vec<FileEntryView> {
    // Sparse priority table lookup (entries not listed = 0, normal):
    // tables over 8 entries become a HashMap (removes the files x
    // priorities linear product — the status-view CPU face for large
    // tables + large tasks); small tables keep a zero-allocation linear
    // scan.
    let prio_map: Option<std::collections::HashMap<u32, i8>> =
        priorities.and_then(|p| (p.len() > 8).then(|| p.iter().copied().collect()));
    let level_of = |idx: u32| {
        if let Some(m) = &prio_map {
            return m.get(&idx).copied().unwrap_or(0);
        }
        priorities
            .and_then(|p| p.iter().find(|(i, _)| *i == idx).map(|(_, q)| *q))
            .unwrap_or(0)
    };
    // BEP53 client file-list cursor: increments only over non-pad
    // entries (pad = BEP47 transfer placeholders, not files, never in
    // the selection set — false on the Some face, true with select-all
    // on the None face).
    let mut client_idx = 0u32;
    meta.files
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let selected = if f.padding {
                file_selected(selection, None)
            } else {
                let idx = client_idx;
                client_idx += 1;
                file_selected(selection, Some(idx))
            };
            FileEntryView {
                index: i as u64 + 1,
                path: f.path.display().to_string(),
                selected,
                priority: if f.padding {
                    0
                } else {
                    let idx = client_idx - 1;
                    level_of(idx)
                },
                length: f.length,
                completed_length: completed.and_then(|c| c.get(i)).copied().unwrap_or(0),
                // A BT task's FileEntry URIs have no HTTP semantics ->
                // always empty.
                uris: Vec::new(),
                pieces_root: f.pieces_root,
                piece_size: meta.piece_length,
                padding: f.padding,
                // Missing-layer projection: patched from the engine
                // snapshot (live view) — None at construction.
                recovery: None,
            }
        })
        .collect()
}

/// Tracker table -> announceList (ascending tier grouping, URL order
/// preserved; the gatherBitTorrentMetadata KEY_ANNOUNCE_LIST face).
pub(super) fn group_tiers(tiers: &[(usize, String)]) -> Vec<Vec<String>> {
    let mut map: std::collections::BTreeMap<usize, Vec<String>> = std::collections::BTreeMap::new();
    for (t, u) in tiers {
        map.entry(*t).or_default().push(u.clone());
    }
    map.into_values().collect()
}

/// The bittorrent sub-dictionary payload of a torrent task (the full
/// aria2 set + additions).
pub(super) fn torrent_bittorrent_view(tj: &TorrentJob) -> BittorrentView {
    let meta = &tj.metainfo;
    let (comment, creation_date, name) = tj.attrs_top.clone();
    BittorrentView {
        comment,
        creation_date,
        // single = info has a length (single file); multi-file /
        // pad-bearing = multi (the bittorrent_helper getModeString
        // value domain).
        mode: Some(if meta.meta.files.len() == 1 {
            "single"
        } else {
            "multi"
        }),
        announce_list: group_tiers(&tj.tiers),
        name,
        // Synthetic meta-version accounting: v1-only = 1;
        // v2-only/hybrid = 2 (a hybrid info dict carries
        // "meta version": 2, the metadata truth; v1-only has no such
        // key -> synthesized 1).
        meta_version: Some(match meta.meta.kind {
            taiji_bt::filetree::SwarmKind::V1Only => 1,
            _ => 2,
        }),
        v2_info_hash: meta.meta.identity.v2,
        private: Some(meta.private),
    }
}

/// The random session id for getSessionInfo (16 random bytes -> 32 hex
/// chars; isomorphic to RpcMethodImpl.cc
/// `util::toHex(e->getSessionId())`).
pub(super) fn random_session_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn resolve_file_paths(dir: &str, files: &mut [super::super::view::FileEntryView]) {
    let root = std::path::Path::new(dir);
    if !root.is_absolute() {
        return;
    }
    for file in files {
        if !file.path.is_empty() && !std::path::Path::new(&file.path).is_absolute() {
            file.path = root.join(&file.path).display().to_string();
        }
    }
}

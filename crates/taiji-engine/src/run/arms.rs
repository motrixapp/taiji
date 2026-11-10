//! Main select! event arm bodies (extracted): the command surface, store
//! progress events, availability events, register/leave, and lazy-fetch
//! events. The arm bodies are moved verbatim from the original run()
//! select! arms; `continue`/`break <EngineEnd>` are translated into
//! [`ControlFlow`] return values (the caller restores the equivalent jump —
//! continue = `Break(())`, break = `Break(end)`).
//!
//! Covers: data-plane event decisions of the engine main loop.
//! Not covered: dial-source arms (dial), ticker arms (tick), and the
//! teardown sequence (tail).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use sha1::{Digest as _, Sha1};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use taiji_bt::peer::AvailEvent;
use taiji_bt::peer::PeerHandle as _;
use taiji_bt::peer_policy::Violation;
use taiji_bt::tracker::actor::TrackerCommand;
use taiji_store::torrent_writer::TorrentReader;

use crate::metrics::SessionMetrics;
use taiji_domain::seed::SeedPolicy;

use super::state::EngineLoop;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use taiji_bt::dht::{DhtEvent, DhtFamily};
use taiji_bt::mse::CryptoLevel;
use taiji_bt::utp::Transport;

use taiji_store::layout::Layout;
use taiji_store::merkle;

use crate::ban::{
    FailedBlockEntry, SMART_BAN_REASON_PREFIX, SMART_BAN_TRUST_BAN_THRESHOLD, take_block_sender,
    take_block_sender_map, take_piece_dispatch_targets,
};
use crate::choke::{budget_derived_slots, leecher_choke_round, preemptive_unchoke};
use crate::command::EngineCommand;
use crate::dht::{DhtFamilyWiring, DhtRuntimeSeam, spawn_dht_announces, spawn_dht_family};
use crate::dispatch::{
    HashFetchEvent, LayerFetchState, LedgerArrival, PieceSentLedger,
    dispatch_face_selected_with_stream, handle_recovery_reply_and_drive, note_peer_bitfield,
    note_peer_have, note_peer_have_all, note_peer_have_none, note_recovery_evidence,
    on_block_arrived, priority_mask, remove_peer_avail, selection_mask,
};
use crate::faces::{
    FaceState, PeerRegistration, attach_seeding_sources, on_piece_verified, on_piece_written,
    pex_note_left, pex_note_registered, recheck_face_completion, release_download_state,
};
use crate::progress::{EngineEnd, Progress};
use crate::query::{peer_snapshots, status_snapshot, tracker_snapshots};
use crate::run::recovery_admit;
use crate::run::state::DialCtx;
use crate::run::tail::dht_halt_save;
use crate::run::tick::note_supply_down;
use crate::strategy::{DEFAULT_PLAYBACK_BYTES_PER_SEC, Playhead};
use crate::superseed::enter_seeding_state;
use crate::tracker::{apply_set_trackers, epoch_secs};
use crate::transit::AttachDht;
use taiji_domain::hash_fetch::HASH_FETCH_MAX_ATTEMPTS;
use taiji_domain::seed::{DetachSeedOnly, DownloadPhase, seed_only_detached};
/// First-round "resumed as complete" branch of the main loop (runs once,
/// only while completion is not yet accounted): attach the seeding sources
/// and enter the seeding state; without continue-seeding, return completed
/// directly (the original in-arm `break EngineEnd::Completed` ->
/// `Break`).
pub(super) fn check_resume_complete(
    state: &mut EngineLoop,
    seed: &SeedPolicy,
    layout: &Layout,
    dest: &Path,
    piece_len: u32,
    seed_after_complete: bool,
) -> ControlFlow<EngineEnd, ()> {
    if !state.completed && state.faces.iter().all(|f| f.completed) {
        info!(target: "taiji::core::engine",
            "download already complete at start (bitfield restored)");
        attach_seeding_sources(
            &mut state.faces,
            &mut state.seeding_sources,
            &mut state.seeding_hash_sources,
            layout,
            dest,
            piece_len,
        );
        // Enter the seeding state (BEP21 upload_only broadcast + BEP16
        // super-seeding).
        enter_seeding_state(
            &mut state.faces,
            &mut state.upload_only,
            &mut state.super_seed,
            seed.super_seeding,
            &mut state.superseed_rng,
        );
        // Download-state memory release (the resume path's share of the
        // completion release — nothing was arena-grown in this shape, the
        // call is a cheap idempotent no-op that keeps both completion
        // paths on one discipline).
        release_download_state(&state.faces);
        if !seed_after_complete {
            return ControlFlow::Break(EngineEnd::Completed);
        }
        state.completed = true;
        state.detached = seed_only_detached(
            if seed.detach_seed_only {
                DetachSeedOnly::On
            } else {
                DetachSeedOnly::Off
            },
            DownloadPhase::Finished,
        );
    }
    ControlFlow::Continue(())
}

/// Control-plane command arm body: the branch runs before the data-plane
/// tick, so control commands never lag behind a busy swarm (the biased
/// select arm order is unchanged).
#[expect(
    clippy::too_many_arguments,
    reason = "arm body: parameters mirror the run() locals the original select arm captured"
)]
pub(super) async fn handle_engine_command(
    cmd: Option<EngineCommand>,
    state: &mut EngineLoop,
    actor_cmds: &[Option<mpsc::Sender<TrackerCommand>>],
    session_up: &AtomicU64,
    layout: &Layout,
    piece_len: u32,
    startup_uploaded: u64,
    dht: &mut DhtRuntime<'_>,
) {
    match cmd {
        None => {}
        Some(EngineCommand::SetTrackers { tiers, reply }) => {
            apply_set_trackers(
                &mut state.faces,
                actor_cmds,
                tiers,
                state.persist_shared.as_ref(),
            )
            .await;
            let _ = reply.send(());
        }
        // DHT runtime enable/disable (a hot switch; idempotence and the
        // private gate live in the arm body).
        Some(EngineCommand::SetDhtEnabled { enabled, reply }) => {
            let r = handle_set_dht_enabled(
                enabled,
                state,
                dht.wiring,
                dht.seam,
                dht.ev_rx,
                dht.dial,
                dht.actual_port,
            )
            .await;
            let _ = reply.send(r);
        }
        // Query surface: tellStatus live snapshot / getPeers / getServers.
        Some(EngineCommand::QueryStatus { reply }) => {
            let snap = status_snapshot(
                &state.faces,
                piece_len,
                layout.total(),
                startup_uploaded + session_up.load(Ordering::Relaxed),
                state.speed_up.calculate(Instant::now()),
                state.speed_down.calculate(Instant::now()),
                // getFiles missing-layer projection reading (non-empty table only
                // for tasks with missing layers).
                recovery_admit::recovery_file_states(state),
            );
            let _ = reply.send(snap);
        }
        Some(EngineCommand::QueryPeers {
            want_bitfield,
            reply,
        }) => {
            let _ = reply.send(peer_snapshots(&mut state.faces, want_bitfield));
        }
        Some(EngineCommand::QueryTrackers { reply }) => {
            let _ = reply.send(tracker_snapshots(&state.faces));
        }
        // BEP53 select-file: file indexes are validated (out of range or
        // empty = an explicit Err, never silently ignored); the engine
        // projects the mask onto its own layout.
        Some(EngineCommand::SetFileSelection { files, reply }) => {
            match selection_mask(layout, piece_len, &files) {
                Ok(mask) => {
                    state.required = state
                        .faces
                        .iter()
                        .map(|_| mask.iter().filter(|&&b| b).count())
                        .collect();
                    // Faces reaching the new post-mask required count are
                    // re-judged under the mask (resume-as-complete plus
                    // file-selection tasks: the command can arrive after the
                    // resume round). The predicate is
                    // [`recheck_face_completion`] (written-based):
                    // hash-pass counts do not qualify — a face whose
                    // selected pieces are verified-but-unwritten (flush
                    // still in flight) must not be marked complete
                    // (completed pieces get the ungated full seeding source
                    // and completion is reported).
                    recheck_face_completion(&mut state.faces, &state.required);
                    state.selected_mask = Some(Arc::from(mask.as_slice()));
                    info!(target: "taiji::core::engine",
                        files = files.len(),
                        pieces = state.required.first().copied().unwrap_or(0),
                        "file selection applied (BEP53)");
                    let _ = reply.send(Ok(()));
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
        }
        // File priorities: projection validated + the piece-level table
        // replaced wholesale. Unlike SetFileSelection — does not touch
        // required/completion accounting (priority only affects selection
        // order; skipped files are expressed by the selection mask); takes
        // effect in later dispatch rounds.
        Some(EngineCommand::SetFilePriority { priority, reply }) => {
            match priority_mask(layout, piece_len, &priority) {
                Ok(table) => {
                    state.piece_priority = Some(Arc::from(table.as_slice()));
                    info!(target: "taiji::core::engine",
                        entries = priority.len(),
                        "file priority applied");
                    let _ = reply.send(Ok(()));
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
        }
        // ut_holepunch runtime switch: flips the shared atomic (read at
        // attach time via DialCtx::holepunch_attach). Affects new
        // connections only (see the command docs).
        Some(EngineCommand::SetHolepunch { enabled, reply }) => {
            state
                .hp_enabled
                .store(enabled, std::sync::atomic::Ordering::Relaxed);
            info!(target: "taiji::core::engine", enabled,
                "ut_holepunch toggled (affects new connections)");
            let _ = reply.send(());
        }
        // Ban config pushed wholesale: identity rules + manual ban range
        // replacement + snapshot hot refresh + disconnecting online
        // connections that hit a range (BanBook::set_ban_config).
        Some(EngineCommand::SetBanConfig {
            client_deny,
            manual,
            reply,
        }) => {
            info!(target: "taiji::core::engine",
                clients = client_deny.len(), manual = manual.len(),
                "ban config applied ");
            state
                .ban_book
                .set_ban_config(client_deny, manual, &mut state.faces);
            let _ = reply.send(());
        }
        // Scheduler policy swap: whole-object atomic replacement inside the
        // single-writer loop (lock-free). rarest_first/streaming are
        // configurable; sequential remains unimplemented and is explicitly
        // refused — the session side already validates, this is the same
        // defensive rule (an explicit Err reply, never a silent fallback to
        // the default). A swap affects only future selection decisions;
        // in-flight requests, refetch queues, and claim bookkeeping are
        // strategy-agnostic and survive the swap.
        Some(EngineCommand::SetSchedulerPolicy { policy, reply }) => {
            if !policy.is_supported() {
                warn!(target: "taiji::core::engine", policy = policy.name(),
                    "scheduler policy rejected: not implemented yet");
                let _ = reply.send(Err(format!(
                    "scheduler policy '{}' is not implemented yet",
                    policy.name()
                )));
            } else {
                let strategy = policy.into_strategy();
                info!(target: "taiji::core::engine", policy = strategy.name(),
                    "scheduler policy swapped (piece selection strategy)");
                state.strategy = strategy;
                let _ = reply.send(Ok(()));
            }
        }
        // Streaming playhead delivery: after static-geometry validation
        // (out of range = an explicit Err, never a silent clamp — the same
        // out-of-range semantics as selection_mask's BEP53 handling), the
        // runtime state is replaced. The current strategy is not validated —
        // the playhead is only consumed under the streaming strategy (either
        // ordering of the combined swap works); advancing = calling again
        // (an idempotent replacement). No immediate dispatch is triggered:
        // the playhead is a priority input to later selection and takes
        // effect at the next dispatch trigger (tick/event).
        Some(EngineCommand::SetStreamingPlayhead {
            file,
            position,
            bytes_per_sec,
            reply,
        }) => match state.stream_geo.validate(file, position) {
            Ok(()) => {
                state.playhead = Some(Playhead {
                    file,
                    position,
                    bytes_per_sec,
                });
                info!(target: "taiji::core::engine", file, position,
                    bps = bytes_per_sec.unwrap_or(DEFAULT_PLAYBACK_BYTES_PER_SEC),
                    "streaming playhead updated ");
                let _ = reply.send(Ok(()));
            }
            Err(e) => {
                warn!(target: "taiji::core::engine", file, position, %e,
                    "streaming playhead rejected");
                let _ = reply.send(Err(e));
            }
        },
        // Live disk-tier surface: forwards on the watch single-value
        // channel (all store pipelines re-gear live); the allocation mode
        // applies only to new allocations (the command-doc convention). The
        // pipelines' applied value is observed via state.disk_live
        // (QueryDiskPolicy).
        Some(EngineCommand::SetDiskPolicy { policy, reply }) => {
            info!(target: "taiji::core::engine",
                ops = policy.io_ops_per_sec,
                flush_secs = policy.flush_interval.map(|d| d.as_secs()).unwrap_or(0),
                merge = policy.write_merge_max_bytes,
                allocation = ?policy.allocation,
                "disk policy applied live (setDiskTier)");
            let _ = state.disk_policy_tx.send(policy);
            let _ = reply.send(());
        }
        // Live reading: the pipelines' real effective value after
        // application (an atomic read, not a config mirror).
        Some(EngineCommand::QueryDiskPolicy { reply }) => {
            let _ = reply.send(state.disk_live.get());
        }
    }
}

/// smart_ban pass-arm read-back: reads the just-verified, flushed piece
/// from disk and hashes each 16 KiB block with SHA-1 (the good-data digest
/// baseline). Reads go through [`TorrentReader`] (handle pooling — no more
/// reopening the file per segment); `Err` = read-back failure (the caller
/// conservatively drops the evidence and bans nobody — banning a good peer
/// is a net loss).
fn read_back_block_digests(reader: TorrentReader, goff: u64, nbytes: u64) -> Option<Vec<[u8; 20]>> {
    let mut buf = vec![0u8; usize::try_from(nbytes).ok()?];
    let n = reader.read_at(goff, &mut buf).ok()?;
    buf.truncate(n);
    const BLOCK: usize = merkle::BLOCK_SIZE as usize;
    Some(buf.chunks(BLOCK).map(|c| Sha1::digest(c).into()).collect())
}

/// Store-pipeline progress event arm body: pipeline exit/fatal = engine
/// failure; piece settles/rejections and block rejections drive attribution
/// plus event-driven re-dispatch; a fully written piece drives seeding-state
/// entry and stop evaluation. The parameter list mirrors the run locals the
/// original arm body captured (the expect matches wire_dht_and_utp;
/// not a behavior surface).
#[expect(
    clippy::too_many_arguments,
    reason = "arm body: parameters mirror the run() locals the original select arm captured"
)]
pub(super) async fn handle_store_progress(
    prog: Option<(usize, Progress)>,
    state: &mut EngineLoop,
    hook: &Option<Arc<taiji_domain::hook::HookRunner>>,
    seed: &SeedPolicy,
    seed_after_complete: bool,
    layout: &Layout,
    dest: &Path,
    piece_len: u32,
) -> ControlFlow<EngineEnd, ()> {
    match prog {
        None => ControlFlow::Break(EngineEnd::Failed("store pipeline exited".into())),
        Some((_, Progress::Fatal(msg))) => ControlFlow::Break(EngineEnd::Failed(msg)),
        Some((
            fi,
            Progress::PieceDropped {
                index,
                reason,
                digests,
            },
        )) => {
            debug!(target: "taiji::core::engine", face = fi, index, %reason,
                "piece dropped, will re-fetch");
            // Piece-level settle: the whole piece's in-flight bookkeeping
            // clears (all blocks re-dispatchable) + the dispatch-target
            // ownership is taken out (fused ordering: with ownership folded
            // into the blocks_sent row's owner,
            // `take_piece_dispatch_targets` removes the row and collects
            // owners in one call, replacing the old two-step "remove row +
            // take the separate block_dispatch table"). This runs BEFORE the
            // re-dispatch round, so rows the re-dispatch writes afterward
            // (new ownership for re-dispatched coordinates) are not taken by
            // this call — matching the old take-then-clear ordering. Edge
            // note: under the old order the re-dispatch round would
            // overwrite same-coordinate ownership before the take (losing
            // the pre-failure owner of in-event re-dispatched coordinates,
            // narrowing attribution); the new order preserves pre-failure
            // ownership, attribution is strictly more complete, and the
            // smart_ban evidence gate (deliverer == dispatch target)
            // accepts a superset.
            let dispatch_targets = state
                .faces
                .get_mut(fi)
                .map(|f| take_piece_dispatch_targets(f, u64::from(index)))
                .unwrap_or_default();
            // Event-driven re-dispatch does not wait for the next tick.
            let plan = state.stream_plan();
            if let Some(face) = state.faces.get_mut(fi) {
                dispatch_face_selected_with_stream(
                    face,
                    fi,
                    state.selected_mask.as_deref(),
                    state.strategy.as_ref(),
                    plan.as_ref(),
                    state.piece_priority.as_deref(),
                );
            }
            // Hash-failure attribution (the v1 whole-piece path) — each
            // sender of the piece's blocks counts once (usually one peer
            // under single-requester dispatch; the SPEC §13 sliding window
            // of >=3 per 10min auto-bans; the aria2 single-point
            // counterpart is BtPieceMessage.cc bad piece hash ->
            // addBadPeer). Forensics (observation only; ban semantics
            // unchanged): the failed piece index, the block source peer
            // (cuid+ip), and whether we had requested from it
            // (dispatch-target bookkeeping lookup) — separating dirty peer
            // data from local assembly/dispatch mistakes. The take-out is
            // now per-block (begin -> cuid): smart_ban evidence pairs
            // digests with deliverers per block; the piece-level culprit
            // view is the distinct values of this table (same set
            // semantics).
            let sender_map = take_block_sender_map(&mut state.faces, fi, u64::from(index));
            let mut culprits: Vec<u64> = Vec::new();
            for cuid in sender_map.values() {
                if !culprits.contains(cuid) {
                    culprits.push(*cuid);
                }
            }
            // smart_ban (v1 faces only — v2 per-block verification
            // attributes natively; the `trees.is_some()` bypass mirrors
            // smart_ban.cpp returning nullptr for the plugin when
            // `has_v2()`). Gate = the `BH_SMART_BAN` fallback knob
            // (default on).
            let smart_ban_on = state.ban_book.smart_ban.enabled()
                && state.faces.get(fi).is_some_and(|f| f.trees.is_none());
            if smart_ban_on {
                // (1) parole suspect registration (an independent
                // BH_SMART_BAN_PAROLE knob): every deliverer of the failed
                // piece becomes a suspect (consumed by the dispatch gate —
                // only unclaimed whole pieces, endgame forbidden;
                // faces::parole_peers).
                if state.ban_book.smart_ban.parole_enabled()
                    && let Some(face) = state.faces.get_mut(fi)
                {
                    for cuid in sender_map.values() {
                        face.parole_peers.insert(*cuid);
                    }
                }
                // (2) evidence registration + the same-peer same-block
                // contradiction decision (two failures with different
                // digests imply at least one bad — ban directly;
                // smart_ban.cpp 220-255). Attribution-confidence gate: only
                // blocks whose deliverer == dispatch target are registered —
                // under re-dispatch transfer or duplicate delivery the two
                // ledgers can diverge (last arrival vs the holder of the
                // first send), making attribution doubtful; such blocks are
                // conservatively not registered and produce no evidence
                // (banning a good peer is a net loss).
                if let Some(digests) = digests.as_ref() {
                    let entries: Vec<FailedBlockEntry> = sender_map
                        .iter()
                        .filter(|(begin, cuid)| dispatch_targets.get(*begin) == Some(cuid))
                        .filter_map(|(begin, cuid)| {
                            let blk = (begin / merkle::BLOCK_SIZE) as usize;
                            digests.get(blk).map(|d| (*begin, *cuid, *d))
                        })
                        .collect();
                    let contradicted = state
                        .ban_book
                        .smart_ban
                        .note_piece_failed(u64::from(index), &entries);
                    for cuid in contradicted {
                        let ip = state
                            .faces
                            .get(fi)
                            .and_then(|f| f.peer_state.get(&cuid).and_then(|ps| ps.ip));
                        if let Some(ip) = ip {
                            warn!(target: "taiji::core::engine", face = fi,
                                index, culprit_cuid = cuid, %ip,
                                blocks = entries.len(),
                                "smart-ban: digest contradiction (same peer, \
                                 two digests for one block) -> banning");
                            state
                                .ban_book
                                .violation(
                                    Violation {
                                        ip,
                                        reason: format!(
                                            "{SMART_BAN_REASON_PREFIX}digest \
                                         contradiction (piece {index})"
                                        ),
                                    },
                                    &mut state.faces,
                                    state.persist_shared.as_ref(),
                                )
                                .await;
                            state.redial_pool.remove_ip(ip);
                        }
                    }
                }
                // (3) trust penalty (once per delivering peer's IP;
                // crossing the -7 threshold bans — it coexists with the
                // sliding window; the division of labor is in
                // SmartBanLedger).
                let mut trust_ips: Vec<IpAddr> = Vec::new();
                for cuid in &culprits {
                    if let Some(ip) = state
                        .faces
                        .get(fi)
                        .and_then(|f| f.peer_state.get(cuid).and_then(|ps| ps.ip))
                        && !trust_ips.contains(&ip)
                    {
                        trust_ips.push(ip);
                    }
                }
                for ip in trust_ips {
                    if state.ban_book.smart_ban.trust_penalize(ip) {
                        warn!(target: "taiji::core::engine", face = fi, index,
                            %ip, "smart-ban: trust points exhausted -> banning");
                        state
                            .ban_book
                            .violation(
                                Violation {
                                    ip,
                                    reason: format!(
                                        "{SMART_BAN_REASON_PREFIX}trust points \
                                     exhausted (<= -{SMART_BAN_TRUST_BAN_THRESHOLD})"
                                    ),
                                },
                                &mut state.faces,
                                state.persist_shared.as_ref(),
                            )
                            .await;
                        state.redial_pool.remove_ip(ip);
                    }
                }
            }
            for cuid in culprits {
                let ip = state
                    .faces
                    .get(fi)
                    .and_then(|f| f.peer_state.get(&cuid).and_then(|ps| ps.ip));
                if let Some(ip) = ip {
                    let blocks_requested =
                        dispatch_targets.values().filter(|&&c| c == cuid).count();
                    warn!(target: "taiji::core::engine", face = fi,
                        index, culprit_cuid = cuid, %ip,
                        requested_from_peer = blocks_requested > 0,
                        blocks_requested,
                        "piece hash failure attribution (pre-ban forensics)");
                    state
                        .ban_book
                        .hash_failure(ip, &mut state.faces, state.persist_shared.as_ref())
                        .await;
                    // A peer banned by crossing the threshold leaves the
                    // redial pool (below the threshold only counts; the
                    // entry stays — the peer is not condemned).
                    if state.ban_book.ledger.is_banned(ip, epoch_secs()).is_some() {
                        state.redial_pool.remove_ip(ip);
                    }
                }
            }
            ControlFlow::Continue(())
        }
        Some((fi, Progress::PieceEvicted { index })) => {
            // An unverified piece was evicted from the write cache: the
            // data + digests are already reset on the storage side; this
            // side only restores bookkeeping — clear the piece's in-flight
            // and buffered dispatch accounts (including the fused row
            // take-out that removes the row and collects owners; the return
            // value is discarded because eviction carries no attribution) +
            // event-driven re-dispatch (no 1s-tick wait). NO attribution or
            // ban path — a deliberate split from PieceDropped: eviction has
            // no "bad peer" meaning; the data was destroyed by our own cache
            // discipline, not supplied dirty by a peer.
            let plan = state.stream_plan();
            if let Some(face) = state.faces.get_mut(fi) {
                let _ = take_piece_dispatch_targets(face, u64::from(index));
                debug!(target: "taiji::core::engine", face = fi, index,
                    "piece evicted unverified: dispatch bookkeeping cleared, re-fetching");
                dispatch_face_selected_with_stream(
                    face,
                    fi,
                    state.selected_mask.as_deref(),
                    state.strategy.as_ref(),
                    plan.as_ref(),
                    state.piece_priority.as_deref(),
                );
            }
            ControlFlow::Continue(())
        }
        Some((
            fi,
            Progress::BlockRejected {
                index,
                begin,
                length,
            },
        )) => {
            // v2 true per-block verification: only this 16 KiB block is
            // refetched — log fields (file_index, piece_in_file, block) plus
            // the within-file leaf order.
            let (file_index, piece_in_file) = state
                .faces
                .get(fi)
                .and_then(|f| f.flat_coords.get(index as usize).copied())
                .unwrap_or((u32::MAX, u32::MAX));
            let leaf = u64::from(piece_in_file) * u64::from(piece_len / merkle::BLOCK_SIZE)
                + u64::from(begin) / u64::from(merkle::BLOCK_SIZE);
            info!(target: "taiji::core::engine",
                face = fi, index, file_index, piece_in_file,
                block = begin / merkle::BLOCK_SIZE, leaf, begin, length,
                "block rejected by v2 per-block verification: \
                 re-fetching ONLY this 16KiB block");
            // Block-level failure attribution — pinned to the sender of
            // this 16 KiB block. Forensic dimensions as in PieceDropped (the
            // failed block coordinate + the source peer + whether we had
            // requested from it; ban semantics unchanged).
            if let Some(cuid) = take_block_sender(&mut state.faces, fi, index, begin) {
                let ip = state
                    .faces
                    .get(fi)
                    .and_then(|f| f.peer_state.get(&cuid).and_then(|ps| ps.ip));
                if let Some(ip) = ip {
                    // The dispatch-target lookup now goes through the row's inline
                    // owner -> cuid.
                    let requested_from_peer = state
                        .faces
                        .get(fi)
                        .and_then(|f| {
                            f.blocks_sent
                                .get(&u64::from(index))
                                .and_then(|l| l.owner_of(begin))
                                .and_then(|owner| f.peer_cuids.get(owner as usize))
                        })
                        .is_some_and(|&c| c == cuid);
                    warn!(target: "taiji::core::engine", face = fi,
                        index, begin, culprit_cuid = cuid, %ip,
                        requested_from_peer,
                        "block hash failure attribution (pre-ban forensics)");
                    state
                        .ban_book
                        .hash_failure(ip, &mut state.faces, state.persist_shared.as_ref())
                        .await;
                    // A peer banned by crossing the threshold leaves the
                    // redial pool (below the threshold only counts; the
                    // entry stays — the peer is not condemned).
                    if state.ban_book.ledger.is_banned(ip, epoch_secs()).is_some() {
                        state.redial_pool.remove_ip(ip);
                    }
                }
            }
            // The rejected block settles (= rejection): removed from the
            // in-flight set (clear_slot removes state and inline ownership
            // together), allowing refetch dispatch; the single-block refetch
            // is queued (deduplicated). Event-driven re-dispatch: no
            // next-tick wait — the refetch queue is served this round.
            let plan = state.stream_plan();
            if let Some(face) = state.faces.get_mut(fi) {
                if let Some(ledger) = face.blocks_sent.get_mut(&u64::from(index)) {
                    ledger.clear_slot(begin);
                }
                let dup = face
                    .refetch
                    .iter()
                    .any(|(p, b, _)| *p == index && *b == begin);
                if !dup {
                    face.refetch.push((index, begin, length));
                }
                dispatch_face_selected_with_stream(
                    face,
                    fi,
                    state.selected_mask.as_deref(),
                    state.strategy.as_ref(),
                    plan.as_ref(),
                    state.piece_priority.as_deref(),
                );
            }
            ControlFlow::Continue(())
        }
        Some((fi, Progress::BlockSettled { index, begin })) => {
            // The block was confirmed by the store pipeline (Buffered): it
            // moves to the keep-skip state — the bytes are in the write
            // cache and re-dispatch would be pointless (cleared on piece
            // settle/rejection). Window-filling dispatch (the port of
            // aria2's per-round addRequests) is replaced by dispatch debt
            // (tick-driven): this block's bookkeeping lands immediately, and
            // full dispatch rounds settle on the three conditions (quiet /
            // settle batch / debt-age fallback; see the
            // dispatch::DISPATCH_DEBT_MAX_AGE docs) — previously each block
            // triggered one full O(peers x pieces) sweep, and that round
            // multiplier dominated real-network CPU per block. Sibling
            // in-flight cancellation for x2 duplicate coordinates: see
            // [`on_block_settled`].
            if let Some(face) = state.faces.get_mut(fi) {
                on_block_settled(face, index, begin);
            }
            state.note_dispatch_settle(fi);
            ControlFlow::Continue(())
        }
        Some((fi, Progress::BlocksSettled { settled })) => {
            // Batch confirmation (return-flow batching): reuses the
            // single-block semantics of [`on_block_settled`] per coordinate —
            // the InFlight->Buffered flip order = the settled order = the
            // pipeline delivery order (in-batch order is preserved; the
            // pipeline batch-tail note); `was_dup` sibling cancellation
            // happens exactly once per coordinate (verbatim same semantics
            // as the single-block arm). Dispatch debt is noted once per
            // EVENT (a batch is one return flow; the only difference from
            // per-block granularity is that debt registration moves later by
            // at most one batch depth — bounded, see the pipeline batch
            // tail; the three-condition settle decision order is unchanged).
            // The arm set is unchanged — batch events ride the existing
            // progress arm, select topology untouched.
            if let Some(face) = state.faces.get_mut(fi) {
                for (index, begin) in settled {
                    on_block_settled(face, index, begin);
                }
            }
            state.note_dispatch_settle(fi);
            ControlFlow::Continue(())
        }
        Some((fi, Progress::PieceVerified { index })) => {
            // Phase split: attribution bookkeeping (block_senders) is
            // retained until the Written phase — the smart_ban pass arm
            // (reward / parole clearing / read-back compare) takes it out
            // and clears it after consuming (read-back needs on-disk data;
            // at hash-pass the flush is still in flight). This phase only
            // clears the dispatch side (the blocks_sent clear lives in
            // on_piece_verified). Cancel-on-verified: after verification,
            // every in-flight delivery of this piece is pure redundancy (the
            // pipeline drops it as a "late block for verified piece") — take
            // out the dispatch targets (the same take-out order as
            // forensics) and send CancelPiece per holder (the deliberate
            // non-cancellation moments are in the
            // dispatch::cancel_piece_requests_on_verify docs). This cleanup
            // moved earlier to hash-pass, narrowing the redundancy window in
            // step.
            let dispatch_targets = state
                .faces
                .get_mut(fi)
                .map(|face| take_piece_dispatch_targets(face, u64::from(index)))
                .unwrap_or_default();
            super::super::dispatch::cancel_piece_requests_on_verify(
                &mut state.faces,
                fi,
                u64::from(index),
                &dispatch_targets,
            );
            // Advertisement/progress: HAVE broadcast + verified-bit
            // advance (announce at hash-pass, libtorrent RC_2_1
            // 7f691246a passed->have). Completion is NOT decided here — the
            // seeding full source reads disk ungated, so entry requires
            // everything flushed (the PieceWritten arm).
            on_piece_verified(&mut state.faces, fi, u64::from(index));
            // Piece-level settle (a settle-type event, same accounting):
            // in-flight bookkeeping cleared with verification, the next
            // piece is dispatched event-driven — like the BlockSettled arm
            // this goes through dispatch debt (tick-driven; conditions in
            // the dispatch::DISPATCH_DEBT_MAX_AGE docs; the inter-piece
            // top-up delay is bounded by the 20ms debt-age fallback, noise
            // against piece download time).
            state.note_dispatch_settle(fi);
            ControlFlow::Continue(())
        }
        Some((fi, Progress::PieceWritten { index })) => {
            // Piece flushed (a new arm): the written bitmap advances (the
            // upload-serving gate lifts) along with the persistence bitmap +
            // the face completion decision (written-based — the flushed
            // half of libtorrent RC_2_1 7f691246a have->flushed).
            let pass_senders = take_block_sender_map(&mut state.faces, fi, u64::from(index));
            let all_done =
                on_piece_written(&mut state.faces, fi, u64::from(index), &state.required);
            // smart_ban pass arm (v1 faces only, the same gate as the
            // failure arm):
            // (1) reward (this round's deliverers get trust +1, capped at 0)
            // + parole clearance (their delivered blocks are proven good by
            // the piece passing verification = the suspicion dissolves);
            // (2) read-back compare of registered failure evidence — peers
            // whose registered digests differ from this round's per-block
            // SHA-1 of the good data are the bad-block sources -> ban +
            // disconnect (smart_ban.cpp on_piece_pass semantics; read-back
            // goes through the TorrentReader handle pool, one piece per
            // torrent at a time — the read-back budget gate). Evidence is
            // cleared after consumption (cleared on read-back failure too —
            // conservatively produce no evidence, so stale evidence cannot
            // drift across piece cycles into a wrong ban).
            let smart_ban_on = state.ban_book.smart_ban.enabled()
                && state.faces.get(fi).is_some_and(|f| f.trees.is_none());
            if smart_ban_on {
                let piece = u64::from(index);
                let mut pass_ips: Vec<IpAddr> = Vec::new();
                for cuid in pass_senders.values() {
                    if let Some(ip) = state
                        .faces
                        .get(fi)
                        .and_then(|f| f.peer_state.get(cuid).and_then(|ps| ps.ip))
                        && !pass_ips.contains(&ip)
                    {
                        pass_ips.push(ip);
                    }
                }
                for ip in pass_ips {
                    state.ban_book.smart_ban.trust_reward(ip);
                }
                if state.ban_book.smart_ban.parole_enabled()
                    && let Some(face) = state.faces.get_mut(fi)
                {
                    for cuid in pass_senders.values() {
                        face.parole_peers.remove(cuid);
                    }
                }
                if state.ban_book.smart_ban.has_failed_records(piece) {
                    let goff = state
                        .faces
                        .get(fi)
                        .and_then(|f| f.piece_goffs.get(index as usize).copied());
                    let nbytes = state
                        .faces
                        .get(fi)
                        .and_then(|f| f.piece_bytes.get(index as usize).copied());
                    if let (Some(goff), Some(nbytes)) = (goff, nbytes) {
                        let gate = Arc::clone(&state.ban_book.smart_ban_read_gate);
                        let reader = TorrentReader::new(layout.clone(), dest.to_path_buf());
                        // One piece per torrent at a time (the read-back
                        // budget; waits at most one piece read — evidence
                        // comparison is not a hot path).
                        let _permit = gate.acquire().await;
                        let good = tokio::task::spawn_blocking(move || {
                            read_back_block_digests(reader, goff, nbytes)
                        })
                        .await
                        .unwrap_or_else(|e| {
                            warn!(target: "taiji::core::engine", face = fi, index, %e,
                                "smart-ban read-back join failed (evidence discarded)");
                            None
                        });
                        if let Some(good) = good.as_ref() {
                            let culprits = state.ban_book.smart_ban.pass_compare(piece, good);
                            for (cuid, begin) in culprits {
                                let ip = state
                                    .faces
                                    .get(fi)
                                    .and_then(|f| f.peer_state.get(&cuid).and_then(|ps| ps.ip));
                                if let Some(ip) = ip {
                                    warn!(target: "taiji::core::engine", face = fi,
                                        index, block = begin / merkle::BLOCK_SIZE,
                                        culprit_cuid = cuid, %ip,
                                        "smart-ban: failed-attempt digest differs \
                                         from verified piece -> banning");
                                    state
                                        .ban_book
                                        .violation(
                                            Violation {
                                                ip,
                                                reason: format!(
                                                    "{SMART_BAN_REASON_PREFIX}digest \
                                                 mismatch vs verified piece {index}"
                                                ),
                                            },
                                            &mut state.faces,
                                            state.persist_shared.as_ref(),
                                        )
                                        .await;
                                    state.redial_pool.remove_ip(ip);
                                }
                            }
                        }
                    }
                    // Evidence consumed (cleared on success and failure alike —
                    // the conservative stance, see above).
                    state.ban_book.smart_ban.clear_piece(piece);
                }
            }
            if all_done {
                info!(target: "taiji::core::engine", seed_after_complete,
                    "download complete (all faces)");
                // The on-bt-download-complete trigger (ported from
                // DefaultPieceStorage.cc — the hook fires at BT download
                // completion, before enableSeedOnly, with no option gate.
                // BT tasks and `complete` fire twice by design:
                // on-download-complete happens at the teardown
                // executeStopHook (FINISHED); this trigger precedes it — the
                // RequestGroupMan.cc event order).
                if let Some(hook) = hook {
                    hook.fire(taiji_domain::hook::HookEvent::BtComplete);
                }
                // Seeding sources are built per face: FaceSource's goff
                // table is the face's wire index -> disk offset map; v2
                // faces additionally mount a hash-serving source.
                attach_seeding_sources(
                    &mut state.faces,
                    &mut state.seeding_sources,
                    &mut state.seeding_hash_sources,
                    layout,
                    dest,
                    piece_len,
                );
                // Enter the seeding state (BEP21 upload_only broadcast +
                // BEP16 super-seeding bookkeeping mounted).
                enter_seeding_state(
                    &mut state.faces,
                    &mut state.upload_only,
                    &mut state.super_seed,
                    seed.super_seeding,
                    &mut state.superseed_rng,
                );
                // Download-state memory release (quick win 1): the
                // block working set (wire-decode + write-cache cells +
                // the free-list watermark they leave behind) is dead
                // weight in seeding — idle arena pages go back to the
                // OS here. All cells are back on the free list at this
                // point (all_done = every piece's Written verdict was
                // processed; a completed piece's cells leave with its
                // job).
                release_download_state(&state.faces);
                if !seed_after_complete {
                    return ControlFlow::Break(EngineEnd::Completed);
                }
                state.completed = true;
                // The bt-detach-seed-only decision (the port of
                // RequestGroup.cc enableSeedOnly): option on AND download
                // complete -> seed-only. On EngineEnd::Detached the session
                // books the concurrency slot as released (the equivalent of
                // decreaseNumActive + requestQueueCheck).
                state.detached = seed_only_detached(
                    if seed.detach_seed_only {
                        DetachSeedOnly::On
                    } else {
                        DetachSeedOnly::Off
                    },
                    DownloadPhase::Finished,
                );
                if state.detached {
                    info!(target: "taiji::core::engine",
                        "task detached as seed-only (bt-detach-seed-only); \
                         concurrency slot released at M3 session wiring");
                }
            }
            ControlFlow::Continue(())
        }
    }
}

/// Whether a face still has unsettled in-flight requests (the supply-
/// active signal): `blocks_sent` InFlight/InFlightDuplicate entries are
/// requests already sent and not yet confirmed by the store pipeline
/// (BlockSettled -> Buffered / cleared at piece settle). Over real-network
/// RTT this set is almost always non-empty (requests stay in flight about
/// one RTT), while on loopback it drains in milliseconds — it is the
/// "supply quiet" test of [`flush_dispatch_debt`] (quiet = settle
/// immediately; the tick only constrains coalescing while supply is
/// flowing).
///
/// Network-phase accounting: the test naturally matches only the InFlight
/// family — `Settling` entries (block bytes already local) carry no
/// in-flight debt, and an all-Settling face is supply-quiet (nothing left
/// to dispatch; immediate settle is the correct timing). Differential
/// whitelist: with the arrival knob on, the arrival instant already exits
/// debt waiting, so quiet arrives earlier than before (previously a block
/// had to wait for `BlockSettled` to go quiet); with the knob off,
/// `Settling` is unreachable and the test is bit-identical.
fn face_has_outstanding_requests(face: &FaceState) -> bool {
    face.blocks_sent
        .values()
        .any(PieceSentLedger::has_live_inflight)
}

/// Block-arrival arm (new; the main loop select! arrival body):
/// bookkeeping-only — the arrival transition ([`on_block_arrived`],
/// network phase -> storage phase), with NO dispatch round and NO debt
/// registration (dispatch rounds remain driven by the existing
/// settle/advertisement/tick triggers; the arrival event only changes the
/// phase, it never triggers supply). A face out of range (already torn
/// down) is dropped after a debug trace — arrival events are a pure
/// optimization and safe to lose (entries keep the network phase's
/// existing convergence path).
pub(super) fn handle_dispatch_arrival(arrival: LedgerArrival, state: &mut EngineLoop) {
    match state.faces.get_mut(arrival.face) {
        Some(face) => on_block_arrived(face, arrival.index, arrival.begin, Instant::now()),
        None => debug!(target: "taiji::core::engine", face = arrival.face,
            index = arrival.index, begin = arrival.begin, cuid = arrival.cuid,
            "block arrival for unknown face: dropped (engine tearing down)"),
    }
}

/// Settles dispatch debt (the tick-driven dispatch surface; constants and
/// rationale in the `dispatch::DISPATCH_DEBT_INTERVAL` docs). Mixed gate:
/// - debt age >= the tick (2ms) -> settle (the real-network shape:
///   in-flight requests persist for about one RTT, so the age gate
///   compresses rounds from one-per-event to <= 500 rounds/s — the round
///   multiplier of the full O(peers x pieces) sweep);
/// - supply quiet (no unsettled in-flight request on any indebted face) ->
///   settle immediately (the loopback shape: requests drain in
///   milliseconds, and waiting for the tick would clamp low-RTT supply — a
///   pure age gate measurably throttles loopback throughput. Quiet-
///   settling restores the event-driven cadence; between such rounds there
///   is no overlapping supply left to coalesce anyway).
///
/// In-round decision order is identical to per-event dispatch (the same
/// function, the same input snapshot); only rounds are coalesced. Debt is
/// deduped by face number (BTreeSet) and settles exactly once per round;
/// it is cleared afterward (including the age anchor). Triggers = the top
/// of the main loop (so a biased select cannot starve the tick arm under a
/// continuous event stream) + the debt-ticker arm (waking a loop parked
/// with no events); completed faces are guarded by the `completed` early
/// return at the top of `dispatch_face_selected_with_stream`.
pub(super) fn flush_dispatch_debt(state: &mut EngineLoop) {
    if state.dispatch_debt.is_empty() {
        return;
    }
    use super::super::dispatch::{
        DISPATCH_DEBT_MAX_AGE, DISPATCH_DEBT_SETTLE_BATCH_MAX, DISPATCH_DEBT_SETTLE_BATCH_MIN,
    };
    let age_ok = state
        .dispatch_debt_since
        .is_some_and(|t| t.elapsed() >= DISPATCH_DEBT_MAX_AGE);
    // Supply-quiet shortcut: no indebted face has any unsettled in-flight
    // request -> coalescing gains nothing, settle immediately (the loopback
    // wave-tail shape). Settle batch: while supply is flowing, coalesce by
    // batch; the threshold adapts to the peer count (a round's cost is
    // proportional to the peer count — the more peers, the more coalescing
    // is worth; see the DISPATCH_DEBT_SETTLE_BATCH_* docs).
    let quiet = state.dispatch_debt.iter().all(|&fi| {
        state
            .faces
            .get(fi)
            .is_none_or(|f| !face_has_outstanding_requests(f))
    });
    let batched = state.dispatch_debt.iter().any(|&fi| {
        let k = state
            .faces
            .get(fi)
            .map(|f| f.peers.len() as u32)
            .unwrap_or(0)
            .clamp(
                DISPATCH_DEBT_SETTLE_BATCH_MIN,
                DISPATCH_DEBT_SETTLE_BATCH_MAX,
            );
        state
            .dispatch_debt_settles
            .get(&fi)
            .is_some_and(|&n| n >= k)
    });
    if !age_ok && !quiet && !batched {
        return;
    }
    state.dispatch_debt_since = None;
    state.dispatch_debt_settles.clear();
    let debt = std::mem::take(&mut state.dispatch_debt);
    for fi in debt {
        let plan = state.stream_plan();
        if let Some(face) = state.faces.get_mut(fi) {
            dispatch_face_selected_with_stream(
                face,
                fi,
                state.selected_mask.as_deref(),
                state.strategy.as_ref(),
                plan.as_ref(),
                state.piece_priority.as_deref(),
            );
        }
    }
}

/// Peer availability event arm body: immediate advertisement bookkeeping +
/// dispatch-debt registration — advertisements are the candidate-supply
/// source for dispatch, and top-ups settle on the debt's three conditions
/// (HAVE storms stay out of the settle counts and fall to the debt-age
/// fallback); while seeding, this feeds the super-seed book.
pub(super) fn handle_peer_avail(
    ev: (usize, AvailEvent),
    state: &mut EngineLoop,
) -> ControlFlow<(), ()> {
    let (fi, ev) = ev;
    let Some(face) = state.faces.get_mut(fi) else {
        return ControlFlow::Break(());
    };
    match ev {
        AvailEvent::Have { peer, index } => {
            note_peer_have(face, peer, u64::from(index));
            // Re-advertisement = the peer is reachable again and claims
            // data -> clear its recovery peer-cooldown (fresh evidence
            // resets; the storm bound is in note_recovery_evidence).
            if let Some(book) = state.recovery.get_mut(fi) {
                note_recovery_evidence(book, peer);
            }
            // BEP16: super-seeding while in the seed state — the peer
            // completed its assigned piece (HAVE arrived) -> send only new
            // pieces not yet propagated out (rotation on completion,
            // cross-checked with peer_connection.cpp).
            if state.completed {
                if let Some(book) = &state.super_seed {
                    book.note_have(peer, u64::from(index));
                    if let Some(next) = book.on_completed(peer, u64::from(index)) {
                        if let Some(pos) = face.peer_cuids.iter().position(|&c| c == peer) {
                            let _ =
                                face.peers[pos].command(taiji_bt::peer::PeerCommand::SendHave {
                                    index: u32::try_from(next).unwrap_or(u32::MAX),
                                });
                        }
                    }
                }
            }
        }
        AvailEvent::HaveAll { peer } => {
            // BEP6: have_all = a full-possession advertisement ("replace
            // the Have Bitfield") — the primary interoperability form of
            // fast-negotiated seeders. Previously only a debug log, so the
            // peer was treated as having no pieces and was never dispatched
            // (a lost primary data source). A synthetic all-ones candidate
            // set (piece count = the face flat space) takes the exact
            // Bitfield bookkeeping/dispatch-unlock path. The super-seed book
            // is NOT fed (a frozen constraint: seeding advertisement
            // behavior must not change on have_all —
            // get_piece_to_super_seed's availability input stays identical;
            // the have_all peer's assignment rotation proceeds under the
            // existing HAVE event semantics).
            note_peer_have_all(face, peer);
            // have_all is a full-possession advertisement: the same
            // fresh-evidence reset as Have/Bitfield.
            if let Some(book) = state.recovery.get_mut(fi) {
                note_recovery_evidence(book, peer);
            }
        }
        AvailEvent::HaveNone { peer } => {
            // BEP6: explicit zero possession (replacement semantics, a late
            // evidence retraction) — equivalent to the missing-row "no
            // evidence" observation; neither unlocks dispatch (zero requests
            // until a real advertisement).
            note_peer_have_none(face, peer);
        }
        AvailEvent::Bitfield { peer, bits } => {
            note_peer_bitfield(face, peer, &bits);
            // A bitfield advertisement is also possession evidence (the same
            // fresh-evidence reset as the Have arm).
            if let Some(book) = state.recovery.get_mut(fi) {
                note_recovery_evidence(book, peer);
            }
            // BEP16: the peer's bitfield feeds the super-seed book (the
            // swarm propagation view — get_piece_to_super_seed's
            // availability input). The closure feeds wire bits directly
            // (note_bitfield's closure form) — avoiding materializing an
            // N-byte Vec<bool> expansion per bitfield.
            if state.completed {
                if let Some(book) = &state.super_seed {
                    let n = face.piece_count as u64;
                    book.note_bitfield(peer, n, |i: u64| {
                        bits.get((i / 8) as usize)
                            .is_some_and(|b| b & (0x80 >> (i % 8)) != 0)
                    });
                }
            }
        }
        AvailEvent::Unchoked { peer } => {
            // Unchoke edge = a top-up trigger (the dispatch request surface
            // sends nothing to choked peers — the dispatch.rs main-loop
            // gate; this edge returns a peer newly unchoked by the optimistic
            // or rate round to the supply surface immediately instead of
            // waiting for the next natural event). Bookkeeping: no
            // candidate-set change (zero advertisement bookkeeping); falling
            // through to the shared dispatch-debt registration at the end of
            // this match closes the loop.
            debug!(target: "taiji::core::engine", face = fi, cuid = peer,
                "peer unchoked us -> dispatch debt noted");
        }
        AvailEvent::Interested { peer } => {
            // Preemptive unchoke (libtorrent peer_connection.cpp +
            // session_impl.cpp): on an INTERESTED rising edge while choked
            // with a free slot, unchoke immediately (saves one round RTT).
            // The slot test, mode gate, and placement live in the engine
            // choke module's `preemptive_unchoke`. No dispatch-debt feed
            // here — the peer's interest in us does not change our request
            // surface (the tail note_dispatch_debt is idempotent and
            // harmless; the arm stays uniform).
            preemptive_unchoke(face, peer);
        }
    }
    // Immediate advertisement bookkeeping + dispatch debt (tick-driven):
    // advertisements are the candidate-supply source for dispatch and
    // top-ups settle on the debt's three conditions (waiting for the 1s tick
    // would stretch a single-peer swarm's bitfield-arrival -> first-request
    // latency to seconds — the 20ms debt-age fallback keeps first-request
    // latency low while coalescing real-network per-HAVE full dispatch
    // sweeps). New-connection registration still dispatches immediately
    // (low frequency).
    // While seeding, advertisements feed the super-seed book (inside the
    // match arms above).
    state.note_dispatch_debt(fi);
    ControlFlow::Continue(())
}

/// Connection-registration event arm body: bitfield possession after the
/// handshake (BEP3) + the seeding-state registration branches (BEP21
/// catch-up / super-seed bootstrap) + all bookkeeping registration +
/// dispatch-on-registration.
pub(super) fn handle_peer_registered(
    reg: PeerRegistration,
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    pex_enabled: bool,
) -> ControlFlow<(), ()> {
    debug!(target: "taiji::core::engine", face = reg.face, cuid = reg.cuid,
        ip = %reg.meta.ip, "peer registered");
    let Some(face) = state.faces.get_mut(reg.face) else {
        return ControlFlow::Break(());
    };
    // BEP3: after the handshake, a bitfield announces current possession
    // (partial while downloading, all ones while seeding; trailing bits 0).
    // An all-zero bitfield must NOT be sent (a real-swarm interop fix):
    // aria2 only queues a Bitfield when `completedLength > 0`; under fast
    // negotiation empty possession sends HaveNone, on non-fast it sends
    // nothing (`DefaultBtInteractive.cc`) — most real clients FIN an
    // all-zero bitfield immediately. This side takes the non-fast branch
    // (empty possession sends nothing — BEP3 "need only be sent if a client
    // has pieces"); the HaveNone optimization awaits fast-extension wiring.
    // Seeding-state registration branches: the upload_only catch-up (the
    // connection was assembled before the seeding state was entered) —
    // BEP21 semantics; under super-seeding do not send a full bitfield
    // (libtorrent bt_peer_connection.cpp: "pretend to not have any piece
    // and don't send a bitfield"), instead bootstrap-assign at most two
    // pieces (HAVE).
    if state.upload_only {
        let _ = reg
            .handle
            .command(taiji_bt::peer::PeerCommand::SetUploadOnly(true));
    }
    if let Some(book) = state.super_seed.as_ref().filter(|_| state.upload_only) {
        let _ = reg
            .handle
            .command(taiji_bt::peer::PeerCommand::SetSuperSeed(book.clone()));
        for piece in book.bootstrap(reg.cuid) {
            let _ = reg.handle.command(taiji_bt::peer::PeerCommand::SendHave {
                index: u32::try_from(piece).unwrap_or(u32::MAX),
            });
        }
    } else {
        let packed = face.bitfield_bytes();
        if packed.iter().any(|&b| b != 0) {
            let _ = reg
                .handle
                .command(taiji_bt::peer::PeerCommand::SendBitfield { packed });
        }
    }
    let cuid = reg.cuid;
    face.peer_cuids.push(cuid);
    face.peers.push(reg.handle);
    // Per-peer table consolidation: the register arm closes in one row —
    // IP ownership (attribution / ban-disconnect targeting) + the PEX
    // address + connection metadata + rate sampling + the 30s download
    // window + the registration time (the former
    // EngineLoop.peer_registered_at observation anchor) all land at once;
    // lazy fields (unchoke surface / µTP governance / checkout) start at
    // zero.
    let reg_addr = SocketAddr::new(reg.meta.ip, reg.meta.port);
    let reg_inbound = reg.meta.inbound;
    let reg_crypto = reg.meta.crypto;
    face.peer_state.insert(
        cuid,
        crate::faces::PeerState::registered(cuid, reg_addr.ip(), reg.meta, Instant::now()),
    );
    // PEX fresh-candidate registration (outbound connections only;
    // inbound is excluded by the bookkeeping function).
    if pex_enabled {
        pex_note_registered(
            &mut face.pex_candidates,
            cuid,
            reg_addr,
            reg_inbound,
            Instant::now(),
        );
    }
    // Connection established -> remove the redial entry (regardless of
    // whether the connection came from a redial, announce, or inbound; a
    // stale entry would make the scan arm dial repeatedly). The failure
    // count clears with the entry — the same effect as libtorrent zeroing
    // failcount on a successful connection.
    state.redial_pool.note_connected(&reg_addr);
    // MSE negotiation result counting (registration is the point where the
    // handshake/negotiation succeeded; arc4 = encryption established,
    // plain = cleartext/unencrypted. Connections dropped on handshake
    // failure have no registration event and are not counted — an honest
    // denominator). (The reg.meta fields are snapshotted before the row
    // moves into peer_state.)
    if let Some(m) = metrics {
        m.note_mse_result(matches!(reg_crypto, CryptoLevel::Arc4));
    }
    // Dispatch on registration: no next-tick wait (which would mean up to
    // 2s dispatch latency); lazy-fetch gating and in-flight bookkeeping are
    // decided uniformly inside dispatch_face.
    let plan = state.stream_plan();
    dispatch_face_selected_with_stream(
        &mut state.faces[reg.face],
        reg.face,
        state.selected_mask.as_deref(),
        state.strategy.as_ref(),
        plan.as_ref(),
        state.piece_priority.as_deref(),
    );
    ControlFlow::Continue(())
}

/// Peer-leave event arm body: rarity subtraction + bookkeeping removal
/// (choking/super-seed/PEX) + session counter reconciliation (loss guard) +
/// redial pool admission + an immediate choke-round rerun (SPEC §6.9).
/// Leave-reason counters feed from here ([`crate::LeaveKind`] five kinds
/// -> `taiji_peer_leaves_total{reason}`; the connection-retention
/// diagnostic quantifies "peer closed / we closed / transport error" —
/// observation only, zero behavior).
#[expect(
    clippy::too_many_arguments,
    reason = "arm body: parameters mirror the run() locals the original select arm captured"
)]
pub(super) fn handle_peer_left(
    fi: usize,
    cuid: u64,
    kind: crate::LeaveKind,
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    session_up: &AtomicU64,
    session_down: &AtomicU64,
    pex_enabled: bool,
) -> ControlFlow<(), ()> {
    // Leave-reason counters (the single feed point = the leave event;
    // engine-teardown cancellations count too — an excluded denominator
    // class for diagnosis, honestly total).
    if let Some(m) = metrics {
        m.note_peer_leave(kind);
    }
    // Peer left: subtract its bitfield's contribution to the rarity counts
    // (the wiring item; PieceStatMan.cc semantics — `remove_peer` =
    // subtract_bitfield).
    let Some(face) = state.faces.get_mut(fi) else {
        return ControlFlow::Break(());
    };
    if let Some(pos) = face.peer_cuids.iter().position(|c| *c == cuid) {
        face.peer_cuids.remove(pos);
        face.peers.remove(pos);
        // Inline ownership index fix: a blocks_sent row's owner is a
        // peer_cuids index; after `Vec::remove` shifts elements, every row
        // is re-marked (owner == pos -> unowned — under the old cuid form
        // this was the subsequent position-lookup miss fallback;
        // owner > pos -> shift left by one). O(in-flight slots), bounded.
        for ledger in face.blocks_sent.values_mut() {
            ledger.reindex_owners(pos);
        }
        // Per-peer table consolidation: the old per-table removals
        // (peer_ips, last_unchoke, am_unchoked, down_windows, utp_mute_since,
        // peer_piece, peer_extra_pieces, peer_registered_at) are folded
        // into the single row remove below (no per-item calls here — the
        // row existing means the fields die with it). Candidate-set row
        // subtraction (the extracted remove_peer_avail; bitfield/HAVE/
        // HAVE_ALL/HAVE_NONE all live in peer_avail, so the removal path is
        // inherited).
        remove_peer_avail(face, cuid);
        face.regular_unchoked.remove(&cuid);
        // Parole suspect removal (cuids are per-connection unique, so like
        // the above there is no unbounded growth; the suspicion dies with
        // the connection — IP-level memory lives in the trust/ban ledgers).
        face.parole_peers.remove(&cuid);
        // BEP16: super-seed assignment slot/bitfield removal (the slot is
        // returned to the pool).
        if let Some(book) = &state.super_seed {
            book.leave(cuid);
        }
        debug!(target: "taiji::core::engine", face = fi, cuid,
            "peer left: rarity counts subtracted");
    }
    // Outbound peer left -> dropped-candidate registration (the
    // getDroppedPeers projection; the fresh record is retracted with it).
    if pex_enabled {
        pex_note_left(&mut face.pex_candidates, cuid, Instant::now());
    }
    // On leave, immediately fold the connection's un-bridged counter deltas
    // into the session totals (the baseline = the last tick sync point;
    // guards against lost counts from a delayed leave). The bridging
    // baselines simultaneously subtract the connection's already-synced
    // share so later tick deltas are not polluted by the departed
    // connection's old counts.
    // (The old peer_meta/peer_rates two-table removes are merged into the
    // one row removal — absent meta (partially assembled test fixtures) =
    // the old missing-peer_meta entry skip; an absent rates baseline falls
    // back to zero like the old None arm.)
    // Leave-path fallback removal (unconditional, outside the guard — the
    // in-guard removal above stays as the fast path; here it is an
    // idempotent no-op for already-removed rows. If the invariant "an avail
    // row exists only alongside a peer_state row" is ever broken by future
    // refactoring, this fallback guarantees rows cannot leak).
    remove_peer_avail(face, cuid);
    face.regular_unchoked.remove(&cuid);
    face.parole_peers.remove(&cuid);
    if let Some(mut ps) = face.peer_state.remove(&cuid) {
        if let Some(meta) = ps.meta.take() {
            let (last_up, last_down) = match ps.rates.take() {
                Some(r) => (r.last_up, r.last_down),
                None => (0, 0),
            };
            let up_now = meta.up.load(Ordering::Relaxed);
            let down_now = meta.down.load(Ordering::Relaxed);
            let du = up_now.saturating_sub(last_up);
            let dd = down_now.saturating_sub(last_down);
            if du > 0 {
                session_up.fetch_add(du, Ordering::Relaxed);
            }
            if dd > 0 {
                session_down.fetch_add(dd, Ordering::Relaxed);
            }
            // Supply bytes are reconciled per transport family: the final
            // deltas go into the same-family totals and the same-family
            // bridging baselines are subtracted (paired with
            // drain_peer_counters' family-baseline semantics, so later tick
            // deltas are not polluted by the departed connection's old
            // counts).
            note_supply_down(
                state,
                metrics,
                match meta.transport {
                    Transport::Tcp => dd,
                    Transport::Utp => 0,
                },
                match meta.transport {
                    Transport::Tcp => 0,
                    Transport::Utp => dd,
                },
            );
            match meta.transport {
                Transport::Tcp => {
                    state.last_down_tcp_total = state.last_down_tcp_total.saturating_sub(last_down)
                }
                Transport::Utp => {
                    state.last_down_utp_total = state.last_down_utp_total.saturating_sub(last_down)
                }
            }
            state.last_up_total = state.last_up_total.saturating_sub(last_up);
            state.last_down_total = state.last_down_total.saturating_sub(last_down);
            // Redial pool admission: leave events presuppose "handshake
            // completed and registered" (a connection that failed its
            // handshake has no registration/leave events) — stale bare
            // DHT/PEX addresses have no path into the pool (see the redial
            // module docs). Outbound connections only (an inbound peer's
            // remote port is an ephemeral source port, not redialable);
            // banned peers do not enter the pool (checked against the live
            // IpGuard snapshot — the ban-activation path removes
            // separately, so the two together cover event reordering).
            if !meta.inbound
                && state
                    .ban_book
                    .guard
                    .load()
                    .blocks(meta.ip, epoch_secs())
                    .is_none()
            {
                let now = Instant::now();
                let addr = SocketAddr::new(meta.ip, meta.port);
                let had_data = up_now > 0 || down_now > 0;
                // Slow-eviction mark consumption: a hit is removed
                // immediately (one-shot, regardless of TTL); a hit within
                // TTL forces had_data false, i.e. the 60s base interval
                // (fast redial serves peers that delivered data and then
                // went silent — the churn/restart shape; a slow-evicted peer
                // is online but slow, not lost, so it is pushed back to 60s
                // = libtorrent's min_reconnect_time default
                // (settings_pack.cpp) plus the reconnect gate (f+1) x 60
                // (peer_list.cpp), preventing the 5s-interval eviction from
                // spinning on dial slots; the full divergence note is in
                // `run::ecology::slow_evict_marked`, the TTL decision table
                // in the run::ecology tests — this arm is the one join point
                // that cannot drive itself, noted for the record).
                // The addr construction matches the mark insertion point
                // (slow_churn_faces): both build from the peer meta's
                // ip/port via a single SocketAddr::new.
                let slow_evicted =
                    super::ecology::slow_evict_marked(state.slow_evict_marks.remove(&addr), now);
                let had_data = had_data && !slow_evicted;
                let delivered = if had_data {
                    taiji_domain::redial::DataDelivered::Yes
                } else {
                    taiji_domain::redial::DataDelivered::No
                };
                state.redial_pool.note_departure(fi, addr, delivered, now);
                debug!(target: "taiji::core::engine", face = fi, %meta.ip,
                port = meta.port, had_data, slow_evicted,
                pool = state.redial_pool.len(),
                "peer admitted to redial pool");
            }
        }
    }
    // The SPEC §6.9 event-trigger port: when an unchoked+interested peer
    // leaves, rerun the choke round immediately (download-period leecher
    // side; the seeding period keeps its 10s cadence, untouched). The
    // budget-derived slots use the same parameters as the ticker round (the
    // same assembly as `handle_choke_round` — both read points agree at the
    // same instant).
    let budget_slots = budget_derived_slots(
        taiji_io::knobs::unchoke_budget_slots_enabled(),
        state.limiter.as_deref(),
    );
    if let Some(face) = state.faces.get_mut(fi) {
        if !face.completed {
            leecher_choke_round(face, &mut state.choke_rng, budget_slots);
        }
    }
    ControlFlow::Continue(())
}

/// Lazy-fetch progress event arm body: admitted -> the next planned block
/// or Done; failure -> retry, exhausted -> the whole-piece buffering
/// fallback (an explicit warn, not a silent default). Recovery replies
/// reuse this channel ([`HashFetchEvent::Recovery`]) and delegate to
/// dispatch bookkeeping ([`handle_recovery_reply_and_drive`] — the reply
/// decision + drive round).
pub(super) fn handle_hash_fetch(
    ev: (usize, usize, HashFetchEvent),
    state: &mut EngineLoop,
) -> ControlFlow<(), ()> {
    let (fi, file_idx, evt) = ev;
    if let HashFetchEvent::Recovery { block, reply } = evt {
        let Some(face) = state.faces.get_mut(fi) else {
            return ControlFlow::Break(());
        };
        let Some(book) = state.recovery.get_mut(fi) else {
            return ControlFlow::Break(());
        };
        let deliver = state.recovery_deliver.clone();
        handle_recovery_reply_and_drive(fi, face, book, &deliver, file_idx, block, reply);
        return ControlFlow::Continue(());
    }
    let Some(face) = state.faces.get_mut(fi) else {
        return ControlFlow::Break(());
    };
    let Some(layer) = face.layers.get_mut(file_idx) else {
        return ControlFlow::Break(());
    };
    match evt {
        HashFetchEvent::Admitted { next } => {
            layer.attempts = 0;
            if next + 1 < layer.plans.len() {
                layer.state = LayerFetchState::Queued { next: next + 1 };
            } else {
                layer.state = LayerFetchState::Done;
                info!(target: "taiji::core::engine", face = fi,
                    file_index = file_idx, leaves = layer.leaf_total,
                    "base layer fetched + verified to piece root: cached");
            }
        }
        HashFetchEvent::Failed { next } => {
            layer.attempts += 1;
            if layer.attempts >= HASH_FETCH_MAX_ATTEMPTS {
                warn!(target: "taiji::core::engine", face = fi,
                    file_index = file_idx, attempts = layer.attempts,
                    "hash layer unavailable after retries: falling back to \
                     whole-piece buffering (non-silent fallback, BEP52 hash \
                     exchange optional on remote peers)");
                layer.state = LayerFetchState::Failed;
            } else {
                debug!(target: "taiji::core::engine", face = fi,
                    file_index = file_idx, plan = next,
                    attempt = layer.attempts, "hash fetch failed, will retry");
                layer.state = LayerFetchState::Queued { next };
            }
        }
        // Unreachable: Recovery replies returned early above (the if-let);
        // this defensive arm satisfies exhaustiveness (never touches
        // lazy-fetch bookkeeping).
        HashFetchEvent::Recovery { .. } => {}
    }
    ControlFlow::Continue(())
}

// ---------------------------------------------------------------------------
// DHT runtime hot switch (the SetDhtEnabled arm body)
// ---------------------------------------------------------------------------

/// Runtime DHT borrow bundle for the SetDhtEnabled arm (lends the main
/// loop's local wiring — select! arm bodies run sequentially with exclusive
/// access; the borrow never outlives the arm).
pub(super) struct DhtRuntime<'a> {
    /// Current hot DHT wiring (non-empty while enabled).
    pub(super) wiring: &'a mut Vec<DhtFamilyWiring>,
    /// Cold wiring + channel spares + config (shared by the enable and
    /// disable arms).
    pub(super) seam: &'a mut DhtRuntimeSeam,
    /// DHT event aggregation receiver (the disable arm uses it to harvest
    /// Persist rows during halt-save).
    pub(super) ev_rx: &'a mut mpsc::Receiver<(DhtFamily, DhtEvent)>,
    /// Attach slot for new dials (swapped on enable/disable).
    pub(super) dial: &'a DialCtx,
    /// Unified announce/UDP port (the announce registration value).
    pub(super) actual_port: u16,
}

/// Single write-point for the DHT-on projection: the handshake reserved
/// bit + the dial attach slot are the two faces that must move together
/// with the wiring swap in [`handle_set_dht_enabled`]. One call site per
/// state transition (plus the idempotent self-heal below) — no arm can
/// update one face and skip the other, the triple-write tearing this
/// stopgap closes.
///
/// The wiring-direction assert pins the mid-state defense (the same
/// debug-build discipline as `faces.rs` row-key asserts): a non-empty
/// wiring must never meet an unprojected dial/handshake face — a tear
/// (only reachable via an interrupted toggle) surfaces immediately in
/// test builds; release builds carry on into the check-and-self-heal.
fn project_dht_on(
    wiring: &[DhtFamilyWiring],
    faces: &mut [FaceState],
    dial: &DialCtx,
    port: u16,
    port_tx: mpsc::Sender<(u64, u16)>,
) {
    debug_assert!(
        !wiring.is_empty(),
        "dht-on projection requires non-empty wiring (torn mid-state)"
    );
    // Handshake DHT bit (declared on new outbound/inbound handshakes;
    // existing connections keep their negotiated state for their
    // lifetime — the same rule as libtorrent apply_settings).
    for f in faces {
        f.reserved = f.reserved.with_dht();
    }
    // Attach slot (new dials read it at dial assembly).
    dial.attach_dht.set(Some(AttachDht {
        local_port: port,
        port_tx,
    }));
}

/// Dual of [`project_dht_on`]: the single write-point for the DHT-off
/// projection (the handshake bit cleared — new outbound handshakes stop
/// declaring DHT — and the attach slot emptied).
fn project_dht_off(wiring: &[DhtFamilyWiring], faces: &mut [FaceState], dial: &DialCtx) {
    debug_assert!(
        wiring.is_empty(),
        "dht-off projection requires empty wiring (torn mid-state)"
    );
    for f in faces {
        f.reserved = f.reserved.without_dht();
    }
    dial.attach_dht.set(None);
}

/// Cold-wiring gate slots cleared explicitly (pumps stop; the next enable
/// rebuilds the channels) — shared by the disable main path and the
/// idempotent self-heal (`set_engine(None)` rides a watch send, itself
/// idempotent, so repeated calls are harmless).
async fn clear_gates(seam: &DhtRuntimeSeam) {
    for cold in &seam.cold {
        cold.gate.set_engine(None).await;
    }
}

/// Torn-projection predicate (pure, unit-tested in the file-local tests
/// mod): `wiring_nonempty` fixes the direction, and the two projection
/// faces must agree with it — enabled demands `attach_some` plus the
/// handshake bit on *every* face (enable callers pass the all-faces
/// reading), disabled demands no attach plus the bit on *no* face
/// (disable callers pass the any-face reading; hence the directional
/// `any_reserved_dht` name). Any disagreement = a torn mid-state the
/// idempotent branches self-heal.
fn dht_projection_torn(wiring_nonempty: bool, attach_some: bool, any_reserved_dht: bool) -> bool {
    if wiring_nonempty {
        !attach_some || !any_reserved_dht
    } else {
        attach_some || any_reserved_dht
    }
}

/// `EngineCommand::SetDhtEnabled` arm body (a hot switch; the counterpart
/// of libtorrent `apply_settings(enable_dht)` runtime toggling plus the
/// per-torrent `torrent_flags::disable_dht` flag flip, src/torrent.cpp).
///
/// - Enable: the BEP27 gate first (a private engine is always refused —
///   `torrent.cpp` `priv()` is a hard gate no flag can override);
///   idempotent (already enabled = Ok, but check-and-self-heal: a torn
///   projection from an interrupted historical toggle is re-projected,
///   so no mid-state can freeze forever behind the Ok); per-family cold
///   wiring warms up (state restored from dht_state) + the projection
///   write-point (handshake DHT bit + attach slot, atomically one call)
///   + an immediate announce registration (the stalled-task revival
///     path = a new discovery source starts; the existing 2s tick
///     continues per announce_interval).
/// - Disable: idempotent (already disabled = Ok, same check-and-heal of
///   a leftover projection); halt-save (the routing table persisted, the
///   same as shutdown semantics), then unwire; the projection
///   write-point clears both faces and the gate slots are zeroed;
///   announces end with the engine Shutdown (the registry dies with the
///   actor).
async fn handle_set_dht_enabled(
    enabled: bool,
    state: &mut EngineLoop,
    wiring: &mut Vec<DhtFamilyWiring>,
    seam: &mut DhtRuntimeSeam,
    ev_rx: &mut mpsc::Receiver<(DhtFamily, DhtEvent)>,
    dial: &DialCtx,
    actual_port: u16,
) -> Result<(), String> {
    if enabled {
        // BEP27 hard gate: a private engine cannot enable DHT (torrent.cpp
        // priv() cannot be overridden — neither flags nor session switches;
        // pinned by regression tests).
        if state.private {
            return Err("private torrent: DHT disabled (BEP27)".to_string());
        }
        if !wiring.is_empty() {
            // Idempotent — but check-and-self-heal, not a blind Ok: a torn
            // mid-state left by an interrupted historical toggle (wiring
            // non-empty while the attach slot or the handshake bit lags)
            // would otherwise freeze forever behind this branch. The check
            // still reads the wiring slot alone (the idempotent gate's own
            // source of truth — no second truth added; the attach read is
            // a plain lock read, `dht.rs` AttachDhtSlot::get).
            let attach_some = dial.attach_dht.get().is_some();
            let all_reserved = state.faces.iter().all(|f| f.reserved.supports_dht());
            if dht_projection_torn(true, attach_some, all_reserved) {
                warn!(target: "taiji::core::engine", families = wiring.len(),
                    "dht-on projection torn (attach/handshake lag the wiring) — \
                     re-projecting");
                let port = wiring.first().map(|w| w.dht_port).unwrap_or(actual_port);
                project_dht_on(wiring, &mut state.faces, dial, port, seam.port_tx.clone());
            }
            return Ok(()); // idempotent: already enabled.
        }
        let mut fresh: Vec<DhtFamilyWiring> = Vec::with_capacity(seam.cold.len());
        for cold in &seam.cold {
            fresh.push(
                spawn_dht_family(
                    cold.family,
                    &cold.gate,
                    cold.demux.clone(),
                    cold.dht_port,
                    &seam.cfg,
                    state.persist_shared.as_ref(),
                    &seam.ev_tx,
                )
                .await,
            );
        }
        let port = fresh.first().map(|w| w.dht_port).unwrap_or(actual_port);
        *wiring = fresh;
        // Single projection write-point: the handshake DHT bit + the attach
        // slot move together with the wiring swap (one call, both faces —
        // no torn window between them).
        project_dht_on(wiring, &mut state.faces, dial, port, seam.port_tx.clone());
        // Immediate announce registration (the revival path) + cadence base
        // reset.
        spawn_dht_announces(wiring, &state.faces, actual_port, actual_port);
        state.last_dht_announce = Instant::now();
        info!(target: "taiji::core::engine",
            families = wiring.len(), port,
            "dht wired at runtime (hot enable; announces registered)");
        Ok(())
    } else {
        if wiring.is_empty() {
            // Idempotent — but check-and-self-heal, not a blind Ok: clear any
            // projection residue (attach slot / handshake bit / gate pumps)
            // a historical interrupted toggle left behind. Harmless for an
            // engine that never enabled DHT (all reads are empty; the gate
            // send is idempotent).
            let attach_some = dial.attach_dht.get().is_some();
            let any_reserved = state.faces.iter().any(|f| f.reserved.supports_dht());
            if dht_projection_torn(false, attach_some, any_reserved) {
                warn!(target: "taiji::core::engine",
                    "dht-off projection residue (attach/handshake outlive the \
                     wiring) — re-projecting");
                project_dht_off(wiring, &mut state.faces, dial);
                clear_gates(seam).await;
            }
            return Ok(()); // idempotent: already disabled.
        }
        // Halt-save (DHTSetup.cc shutdown semantics): Shutdown -> persist
        // the routing table within the budget.
        dht_halt_save(state, wiring, ev_rx).await;
        wiring.clear(); // the engine Shutdown makes it exit on its own (the join
        // teardown path takes over).
        // Single projection write-point (handshake bit + attach slot) + the
        // cold-wiring gate slots zeroed (pumps stop; the next enable
        // rebuilds the channels).
        project_dht_off(wiring, &mut state.faces, dial);
        clear_gates(seam).await;
        info!(target: "taiji::core::engine",
            "dht unwired at runtime (hot disable; state saved)");
        Ok(())
    }
}

/// Block-settled bookkeeping (the extracted BlockSettled arm body; an early
/// return means no bookkeeping existed — a harmless no-op): the coordinate
/// moves to `Buffered` (bytes already in the write cache; re-dispatch
/// would be pointless) plus the redundancy-economy step — once an x2
/// duplicate coordinate (`InFlightDuplicate`) lands, the sibling in-flight
/// request is cancelled in place (the hedge has paid off; the second copy
/// no longer earns its keep, so stop paying its wire bytes and receive-
/// path cost).
///
/// Upstream anchors:
/// - libtorrent `torrent.cpp`: a block written to disk with
///   `picker().num_peers(block) > 1` runs `torrent::cancel_block`, which
///   calls `cancel_request` on every connection — the first landing copy
///   withdraws all sibling in-flight requests;
/// - aria2 1.37.0 `BtPieceMessage.cc`: a received already-owned block is
///   dropped via `piece->hasBlock(...) -> "Already have this block."` — a
///   receive-side stopgap (redundant bytes still count in updateDownload;
///   no sibling-withdrawal half).
///
/// Semantic bounds:
/// - The x2 gate and the endgame fanout decision are untouched — the hedge
///   itself stays (both hops in flight until one lands); only the leftover
///   in-flight of an already-landed coordinate is converged;
/// - The cancel target is the inline owner (the old block_dispatch ledger
///   folded into the row; owner = a peer_cuids index — under x2 order that
///   is the second-hop requester = the sibling). If the second hop lands
///   first, the cancel frame reaches a peer that already delivered — a
///   harmless no-op (its slot was consumed by delivery; `RequestBook`
///   without a slot does nothing), and the first hop's request surface
///   converges via the existing 2s re-dispatch window — an asymmetry of
///   single-slot coordinate accounting, practically equivalent to
///   libtorrent's "cancel on all connections; the delivering side's slot
///   is already consumed";
/// - A cancelled slot's late delivery is accepted by the peer-side grace
///   (`RequestBook::cancel_with_grace`, so slow peers are not punished);
/// - First-copy supply (non-duplicate coordinates) never reaches this
///   cancel branch — zero behavior change there.
///
/// A total function over the settle transitions: every phase converges to
/// `Buffered` — `SettlingDup` keeps the sibling withdrawal (the dup
/// predicate survives across the phase boundary, semantics lifted
/// verbatim); `Settling` cancels nothing; `InFlight` goes straight to
/// `Buffered` (tolerating a missed arrival event — a full arrival channel
/// or a lost-event window; identical to the previous behavior);
/// `InFlightDuplicate` cancels (as before).
pub(crate) fn on_block_settled(face: &mut FaceState, index: u32, begin: u32) {
    let piece = u64::from(index);
    let Some(ledger) = face.blocks_sent.get_mut(&piece) else {
        return;
    };
    let Some(was_dup) = ledger.settle_buffered(begin) else {
        return;
    };
    if !was_dup {
        return;
    }
    // Sibling withdrawal: the inline owner (a peer_cuids index, still
    // readable after settling — ownership lives with the slot state across
    // phases).
    let Some(owner) = ledger.owner_of(begin) else {
        return;
    };
    let Some(peer) = face.peers.get(owner as usize) else {
        return;
    };
    let Some(id) = face.addressing.from_wire(index) else {
        return;
    };
    let nbytes = face
        .piece_bytes
        .get(piece as usize)
        .copied()
        .unwrap_or(u64::from(merkle::BLOCK_SIZE));
    let length =
        (nbytes.saturating_sub(u64::from(begin))).min(u64::from(merkle::BLOCK_SIZE)) as u32;
    let cuid = face
        .peer_cuids
        .get(owner as usize)
        .copied()
        .unwrap_or(u64::from(owner));
    debug!(target: "taiji::core::engine", piece, begin, cuid,
        "duplicate coordinate settled: cancel sibling in-flight request ");
    let _ = peer.command(taiji_bt::peer::PeerCommand::CancelPiece { id, begin, length });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Enabled-direction tear: wiring non-empty while the attach slot or
    /// the handshake-bit projection lags (the interrupted-toggle residue).
    #[test]
    fn torn_enable_projection_is_detected() {
        assert!(dht_projection_torn(true, false, true), "attach missing");
        assert!(
            dht_projection_torn(true, true, false),
            "handshake bit lagging"
        );
        assert!(dht_projection_torn(true, false, false), "both lagging");
    }

    /// Disabled-direction tear: wiring empty while the attach slot or the
    /// handshake-bit projection residue survives.
    #[test]
    fn torn_disable_projection_is_detected() {
        assert!(dht_projection_torn(false, true, false), "attach residue");
        assert!(
            dht_projection_torn(false, false, true),
            "handshake bit residue"
        );
        assert!(dht_projection_torn(false, true, true), "both residue");
    }

    /// Consistent states in both directions pass (no tear): fully-on and
    /// fully-off.
    #[test]
    fn consistent_projections_pass() {
        assert!(!dht_projection_torn(true, true, true), "fully on");
        assert!(!dht_projection_torn(false, false, false), "fully off");
    }
}

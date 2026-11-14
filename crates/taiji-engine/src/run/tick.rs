//! Bodies of the periodic `select!` arms (extracted): the 2s slow tick
//! (ban sweep, counter bridging, DHT announce re-issue, NAT port
//! coupling, dispatch, PEX snapshot push, SwarmView refresh), the 1s
//! seeding-ops tick (gauge feeds, ratio, time accumulation,
//! stop-timeout, SeedCheck, autosave), and the choke round. Arm bodies
//! were carried verbatim out of the original `run()` `select!` arms;
//! `break <EngineEnd>` is translated into a [`ControlFlow`] return.
//!
//! Scope: periodic operations decisions. Event-driven paths (arms/dial)
//! and shutdown sequencing (tail) live elsewhere.

use std::ops::ControlFlow;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use tracing::{info, warn};

use taiji_bt::peer::PeerHandle as _;
use taiji_bt::tracker::actor::TrackerCommand;

use crate::metrics::{DhtQueryKind, EngineGauges, SessionMetrics};
use taiji_domain::nat::NatEngine;
use taiji_domain::seed::SeedPolicy;

use super::state::EngineLoop;
use taiji_bt::dht::DhtFamily;
use taiji_bt::utp::Transport;

use crate::choke::{budget_derived_slots, choke_round, leecher_choke_round};
use crate::dht::{DhtFamilyWiring, spawn_dht_announces};
use crate::dispatch::{
    LEDGER_ARRIVALS, LEDGER_DEGRADES, STORE_PENDING_GUARD, STORE_PENDING_GUARD_HITS,
    dispatch_face_selected_with_stream, drive_recovery, store_pending_guard_scan,
};
use crate::faces::{FaceState, face_transport_supply, pex_snapshot};
use crate::lean_telemetry_enabled;
use crate::pipeline::BLOCK_CHANNEL_CAPACITY;
use crate::progress::{EngineEnd, flush_progress_row, progress_row};
use crate::query::{count_peer_gauges, drain_peer_counters};
use crate::tracker::epoch_secs;
/// Autosave period for the torrent_progress counter row; matches the
/// aria2 `--auto-save-interval` default of 60s (`OptionHandlerFactory.cc`).
const AUTO_SAVE_INTERVAL_SECS: u64 = 60;

/// fsync wait budget for the snapshot barrier; same scale as the final
/// barrier's `run::tail::DATA_FLUSH_BUDGET`. fsync is local IO whose upper
/// bound is dirty-page size over disk speed (the default throughput
/// profile does no periodic fsync, so the dirty set can reach GBs — tens
/// of seconds on an HDD is realistic). The budget only bounds a hung IO;
/// on timeout the barrier counts as failed (bitmap row skipped, dirty
/// flag kept, retried next round — fail-closed, see [`autosave_snapshot`]).
const SNAPSHOT_SYNC_BUDGET: Duration = Duration::from_secs(120);

/// 2s slow-tick arm body: expired-ban sweep, counter bridging, DHT
/// announce re-issue, NAT external-port coupling, per-face dispatch, PEX
/// snapshot push, SwarmView snapshot refresh (announce readings lag by at
/// most one 2s tick). Parameters mirror the run() locals the original arm
/// captured (the `expect` is shared with wire_dht_and_utp; not a
/// behavioral surface).
#[expect(
    clippy::too_many_arguments,
    reason = "arm body: parameters mirror the run() locals the original select arm captured"
)]
pub(super) fn handle_slow_tick(
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    session_up: &AtomicU64,
    session_down: &AtomicU64,
    nat: &Option<NatEngine>,
    dht_wiring: &[DhtFamilyWiring],
    actual_port: u16,
    announce_interval: Duration,
    pex_enabled: bool,
    actor_cmds: &[Option<mpsc::Sender<TrackerCommand>>],
) {
    // Sweep the whole expired-ban table (the 1h cadence gate lives in the
    // ledger; aria2 `DefaultPeerStorage.cc` — the sweep cadence is
    // independent of per-entry expiry checks).
    state.ban_book.sweep(epoch_secs());
    // Bridge per-peer counter deltas into session totals (before the
    // SwarmSnapshot reads; announce uploaded lags by at most one tick).
    let drained = drain_peer_counters(
        &mut state.faces,
        &mut state.last_up_total,
        &mut state.last_down_total,
        &mut state.last_down_tcp_total,
        &mut state.last_down_utp_total,
        session_up,
        session_down,
        &mut state.speed_up,
        &mut state.speed_down,
    );
    note_supply_down(state, metrics, drained.down_tcp, drained.down_utp);
    // Re-issue DHT announce commands. The registry drops an entry after
    // 30min without a re-issue (PURGE); the cadence is
    // dht_cfg.announce_interval, default 15min, matching aria2
    // `DHTConstants.h` DHT_PEER_ANNOUNCE_INTERVAL. Ports are taken per
    // family (both families use actual_port when there is no NAT
    // snapshot). Two fast paths re-register at 1/3 cadence (default
    // 5min): when every face has zero connected peers (the vacuum window
    // before tracker/DHT discovery), and — gated by `BH_CONN_FILL_DHT`
    // (=0 restores the plain cadence) — when the connection count is
    // below [`super::ecology::dht_ramp_min_peers`] (threshold from
    // libtorrent `torrent.cpp`); this accelerates DHT candidate supply
    // while the connection table bleeds in a hostile dialing
    // environment (nonzero speed, stall valve not tripped).
    // Registration is idempotent (engine-side entry overwrite +
    // immediate get_peers), so the fast paths only add traffic during
    // the vacuum window. The upstream `prioritize_dht` immediate-requeue
    // form (`session_impl.cpp`) has no equivalent in this 2s-tick shape;
    // the cadence decision is centralized in
    // [`super::ecology::dht_announce_cadence`].
    let peers_idle = state.faces.iter().all(|f| f.peers.is_empty());
    let dht_cadence = super::ecology::dht_announce_cadence(
        state.registered_peers(),
        state.completed,
        peers_idle,
        super::ecology::conn_fill_dht_enabled(),
        super::ecology::dht_ramp_min_peers(),
        super::ecology::dht_ramp_interval(),
        announce_interval,
    );
    //
    // Passive-seed DHT posture (opt-in `BH_SEED_PASSIVE_DHT=1`, default
    // off): once
    // every face is complete, the re-issue is suppressed — the node
    // keeps answering inbound queries and maintaining its table (the bt
    // DHT engine's own refresh/autosave are untouched) but no longer
    // actively crawls for download peers; announce registry entries
    // lapse on their own 30min purge cadence.
    let passive_dht = super::ecology::seed_passive_dht_suppressed(
        state.completed,
        super::ecology::seed_passive_dht_enabled(),
    );
    let ports = nat.as_ref().map(|n| n.external_ports()).unwrap_or_default();
    let udp_port = ports.udp.unwrap_or(actual_port);
    if !passive_dht
        && (state.last_nat_announced_port != udp_port
            || (!dht_wiring.is_empty() && state.last_dht_announce.elapsed() >= dht_cadence))
    {
        spawn_dht_announces(dht_wiring, &state.faces, udp_port, actual_port);
        state.last_dht_announce = Instant::now();
        state.last_nat_announced_port = udp_port;
    }
    for actor in actor_cmds.iter().flatten() {
        let _ = actor.try_send(TrackerCommand::SetListenPort {
            port: ports.effective(actual_port),
        });
    }
    for face in &state.faces {
        for (handle, cuid) in face.peers.iter().zip(&face.peer_cuids) {
            if let Some(peer) = face.peer_state.get(cuid).and_then(|p| p.meta.as_ref()) {
                let port = taiji_domain::nat::peer_announce_port(
                    nat.as_ref(),
                    actual_port,
                    peer.ip,
                    peer.transport,
                );
                let _ = handle.command(taiji_bt::peer::PeerCommand::SetListenPort(port));
            }
        }
    }
    // Dispatch (independent per face; each face's TrackerActor drives its
    // own announce cadence — the engine no longer announces directly).
    // The stream-plan payload is taken up front: faces are mutably
    // borrowed inside the loop, so the borrow cannot overlap with state
    // reads.
    let plan = state.stream_plan();
    for (fi, face) in state.faces.iter_mut().enumerate() {
        dispatch_face_selected_with_stream(
            face,
            fi,
            state.selected_mask.as_deref(),
            state.strategy.as_ref(),
            plan.as_ref(),
            state.piece_priority.as_deref(),
        );
    }
    // Recovery drive round (no-op while the bookkeeping is empty; this is
    // the periodic-retry entry for newly discovered peers). Field borrows
    // are disjoint: faces / recovery / recovery_deliver.
    for fi in 0..state.faces.len() {
        let Some(book) = state.recovery.get_mut(fi) else {
            continue;
        };
        if book.files.is_empty() {
            continue;
        }
        let Some(face) = state.faces.get_mut(fi) else {
            continue;
        };
        drive_recovery(
            face,
            fi,
            book,
            &state.recovery_deliver,
            state.selected_mask.as_deref(),
        );
    }
    // Push PEX candidate snapshots for dirty faces: project after the
    // 60s window prune and overwrite per peer (the peer-side
    // PexSwarmSender applies negotiation/throttling/admission; the engine
    // only supplies session-level candidates).
    if pex_enabled {
        for face in state.faces.iter_mut() {
            if !face.pex_candidates.dirty {
                continue;
            }
            let (fresh, dropped) = pex_snapshot(&mut face.pex_candidates, Instant::now());
            // Any peer command channel full (Full) keeps the face dirty
            // for a re-push next round; Closed means the peer is about to
            // be removed by the leave arm — no re-push needed.
            let any_full = face.peers.iter().any(|p| {
                matches!(
                    p.command(taiji_bt::peer::PeerCommand::SetPexCandidates {
                        fresh: fresh.clone(),
                        dropped: dropped.clone(),
                    }),
                    Err(taiji_bt::peer::PeerCommandRejected::Full)
                )
            });
            if !any_full {
                face.pex_candidates.dirty = false;
            }
        }
    }
    // Refresh SwarmView snapshots (read by each TrackerActor's next
    // announce; lag is bounded by the 2s tick, the same command-round
    // granularity as aria2). The completed flag flips at the same instant
    // (mirror attribution shares the actor's reading). uploaded/
    // downloaded are torrent-level session counters.
    let up_now = session_up.load(Ordering::Relaxed);
    let down_now = session_down.load(Ordering::Relaxed);
    for face in state.faces.iter_mut() {
        let completed = face.progress.completed_length();
        let mut snap = crate::lock(&face.swarm.0);
        snap.completed = completed;
        snap.all_finished = face.completed;
        snap.peers = face.peers.len();
        snap.uploaded = up_now;
        snap.downloaded = down_now;
        drop(snap);
        if face.completed {
            face.mirror.completed = true;
        }
    }
}

/// 1s seeding-ops tick arm body (cadence per aria2
/// `BtStopDownloadCommand.cc`): counter bridging -> gauge feeds -> ratio
/// refresh -> time accumulation -> bt-stop-timeout -> SeedCheck ->
/// autosave. stop-timeout expiry / SeedCheck satisfaction returns `Break`
/// (the original `break EngineEnd::...`). Parameters mirror the run()
/// locals the original arm captured.
#[expect(
    clippy::too_many_arguments,
    reason = "arm body: parameters mirror the run() locals the original select arm captured"
)]
pub(super) async fn handle_seed_tick(
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    gauge_slot: Option<&EngineGauges>,
    dht_wiring: &[DhtFamilyWiring],
    session_up: &AtomicU64,
    session_down: &AtomicU64,
    seed: &SeedPolicy,
    startup_uploaded: u64,
    startup_downloaded: u64,
    startup_active_s: u64,
    startup_seed_s: u64,
    piece_len: u32,
    actor_cmds: &[Option<mpsc::Sender<TrackerCommand>>],
) -> ControlFlow<EngineEnd, ()> {
    // Counter bridging first, so the stop-timeout speed sample and the
    // SwarmView readings stay consistent.
    let drained = drain_peer_counters(
        &mut state.faces,
        &mut state.last_up_total,
        &mut state.last_down_total,
        &mut state.last_down_tcp_total,
        &mut state.last_down_utp_total,
        session_up,
        session_down,
        &mut state.speed_up,
        &mut state.speed_down,
    );
    note_supply_down(state, metrics, drained.down_tcp, drained.down_utp);
    // Observation surface: a 30s-cadence INFO with the connection mix by
    // transport plus per-transport supply bytes (cumulative and
    // 30s-window rate). Byte readings come from the engine-level
    // accumulators maintained by note_supply_down, so they are truthful
    // even without SessionMetrics. Observe-only: dispatch, choke and
    // dialing semantics are untouched.
    if state.active_secs > 0 && state.active_secs % 30 == 0 {
        let (tcp_in, tcp_out, utp_in, utp_out, _choked) = count_peer_gauges(&state.faces);
        let (prev_at, prev_tcp, prev_utp, prev_dials) = match state.mix_log_prev {
            Some((at, tcp, utp, dials)) => (Some(at), tcp, utp, dials),
            None => (None, 0, 0, 0),
        };
        let win = prev_at
            .map(|at| at.elapsed().as_secs().max(1))
            .unwrap_or(30);
        let tcp_rate = state.supply_tcp_down.saturating_sub(prev_tcp) / win;
        let utp_rate = state.supply_utp_down.saturating_sub(prev_utp) / win;
        // Peer-pool curve fields (same 30s window; observe-only):
        // known = DHT dial-dedup table size, registered = connected peers
        // across faces, redial = redial pool size.
        let pool_known = state.dht_dial_dedup.len();
        let pool_registered = state.registered_peers();
        let pool_redial = state.redial_pool.len();
        // Rate-distribution fields (observe-only; recomputed from the
        // same readings as the slow_churn decision, no behavioral
        // coupling): p10/p50/p90 of the 30s-window down rate over
        // connected peers of non-completed faces (integer KiB/s),
        // slow_n = count below the current eviction line
        // (median x frac%; 0 when the median is 0), cand = candidate
        // table size, un = peers we have unchoked across faces (same
        // expression as in the choke module).
        let mut rates: Vec<f64> = Vec::new();
        for face in &state.faces {
            if face.completed {
                continue;
            }
            for cuid in &face.peer_cuids {
                rates.push(
                    face.peer_state
                        .get(cuid)
                        .and_then(|ps| ps.down_window.as_ref())
                        .map(|w| w.rate())
                        .unwrap_or(0.0),
                );
            }
        }
        let mut sorted = rates.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let pct_kib = |p: usize| -> u64 {
            if sorted.is_empty() {
                0
            } else {
                (sorted[(sorted.len() * p) / 100].max(0.0) / 1024.0) as u64
            }
        };
        let rate_p10 = pct_kib(10);
        let rate_p50 = pct_kib(50);
        let rate_p90 = pct_kib(90);
        let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0.0);
        let threshold = median * super::ecology::slow_churn_frac_pct() as f64 / 100.0;
        let slow_n = if threshold > 0.0 {
            rates.iter().filter(|&&r| r < threshold).count() as u64
        } else {
            0
        };
        let cand = state.dial_candidates.len();
        let un: usize = state
            .faces
            .iter()
            .map(|f| f.peer_state.values().filter(|ps| ps.am_unchoked).count())
            .sum();
        // Dial-queue governance fields (observe-only): dial_ifl =
        // in-flight dial count (incremented by the spawn wrapper,
        // decremented at peer_connect completion, atomic on EngineLoop);
        // dial_rate = dials completed within the 30s window (differential
        // of the completion total, same window and base point as
        // mix_log_prev).
        let dial_ifl = state.dial_ifl.load(Ordering::Relaxed).max(0) as u64;
        let dial_done_total = state.dial_done.load(Ordering::Relaxed);
        let dial_rate = dial_done_total.saturating_sub(prev_dials) / win;
        info!(target: "taiji::core::engine", at = state.active_secs,
            tcp_in, tcp_out, utp_in, utp_out,
            tcp_bytes = state.supply_tcp_down, utp_bytes = state.supply_utp_down,
            tcp_bps = tcp_rate, utp_bps = utp_rate,
            pool_known, pool_registered, pool_redial,
            rate_p10, rate_p50, rate_p90, slow_n, cand, un,
            dial_ifl, dial_rate,
            "conn mix by transport (supply bytes) + peer pool curve");
        state.mix_log_prev = Some((
            Instant::now(),
            state.supply_tcp_down,
            state.supply_utp_down,
            dial_done_total,
        ));
    }
    // Endgame elapsed checkpoint: the in-flight endgame segment
    // (registered at dispatch edges as `endgame_edge`) is accumulated in
    // tick slices, so the final segment is not lost when the engine
    // finishes or shuts down while in the endgame state.
    checkpoint_endgame(metrics, state.faces.iter_mut());
    // Two-phase bookkeeping observation (1s cadence; observe-only):
    // (1) store_pending guard scan — warn + count when a Settling entry
    // ages past STORE_PENDING_GUARD (bounded by the in-flight entry
    // count; warn-only, never re-issues on the wire; see the constant
    // docs for the watermark hook); (2) bridge the arrival/degrade/guard
    // counter deltas into SessionMetrics (process-level atomics are the
    // sole write point; the tick only reads — same pattern as the
    // utp/DHT query sampling).
    let obs_now = Instant::now();
    let mut guard_hits = 0u64;
    let mut guard_worst = Duration::ZERO;
    for face in &state.faces {
        let (n, worst) = store_pending_guard_scan(face, obs_now);
        guard_hits += n;
        guard_worst = guard_worst.max(worst);
    }
    if guard_hits > 0 {
        STORE_PENDING_GUARD_HITS.fetch_add(guard_hits, Ordering::Relaxed);
        warn!(target: "taiji::core::engine", entries = guard_hits,
            worst_secs = guard_worst.as_secs(), guard_secs = STORE_PENDING_GUARD.as_secs(),
            "store_pending guard: settling blocks awaiting pipeline confirmation \
             (warn+count only; no wire re-issue;  watermark hook pending)");
    }
    {
        let arrivals = LEDGER_ARRIVALS.load(Ordering::Relaxed);
        let degrades = LEDGER_DEGRADES.load(Ordering::Relaxed);
        let guard_total = STORE_PENDING_GUARD_HITS.load(Ordering::Relaxed);
        let (prev_a, prev_d, prev_g) = state.two_phase_obs_prev;
        if let Some(m) = metrics {
            m.note_two_phase_ledger(
                arrivals.saturating_sub(prev_a),
                degrades.saturating_sub(prev_d),
                guard_total.saturating_sub(prev_g),
            );
        }
        state.two_phase_obs_prev = (arrivals, degrades, guard_total);
    }
    // Holepunch observation family (1s cadence; observe-only): bridge the
    // seven counter deltas into SessionMetrics (process-level atomics are
    // the sole write point; each feed site is single-source — see the
    // run::holepunch module docs; same pattern as the two-phase bridge).
    {
        let now = super::holepunch::HolepunchObs::current();
        let delta = now.delta_since(&state.hp_obs_prev);
        if let Some(m) = metrics {
            m.note_holepunch(
                delta.rendezvous_sent,
                delta.relayed_connects,
                delta.punch_dials,
                delta.punch_established,
                delta.introducer_hits,
                delta.no_introducer,
                delta.punch_failed_nat,
            );
        }
        state.hp_obs_prev = now;
    }
    // Per-peer in-flight telemetry, sampled per connection on the 1s
    // tick. `PeerTaskHandle::in_flight` is a lock-free mirror of the
    // pending-request count in the bt RequestBook (counted at a single
    // point in the bookkeeping, so no double counting here): one
    // observation per connection per tick feeds the histogram (mean =
    // sum/count, p99 via the bucket table); depth > 0 counts into the
    // engine's active-peer gauge (a live "is it actually supplying"
    // signal during download). Observe-only: no dispatch/choke/
    // re-request semantics change.
    let mut inflight_active = 0u64;
    for face in &state.faces {
        for p in &face.peers {
            let depth = p.in_flight();
            if depth > 0 {
                inflight_active += 1;
            }
            if let Some(m) = metrics {
                m.observe_peer_inflight(depth);
            }
        }
    }
    if let Some(slot) = gauge_slot {
        slot.set_peer_inflight_active(inflight_active);
    }
    // Lean-swarm telemetry (gated by `BH_LEAN_TELEMETRY`; default off =
    // zero logs, zero behavior): one per-face line per 1s tick with a
    // per-peer snapshot reading three facets in one event (same cadence
    // and lock-free mirror family as the in-flight histogram above).
    // Supply depth: `w` = BDP target window
    // ([`PeerTaskHandle::target_request_window`]), `i` = in-flight
    // (`in_flight`), `r` = 30s-window rate (`down_windows`, same source
    // as the leecher sort key) — tells whether a slow peer's window is
    // pinned small (the low-rate form of the BDP formula).
    // Reciprocity: `ck` = peer choking us, `it` = peer interested,
    // `sn` = this connection snubbed (slot timeout).
    // Upload generosity: `u` = our upload rate to the peer in B/s
    // (`peer_rates.up` 10s sliding window — quantifies reciprocity
    // against `ck`: how much we still feed while choked); `au` = our
    // unchoke state (`am_unchoked`, read back at the choke round's
    // landing point).
    // Transport mix: `t` = per-peer transport plus face-level TCP/uTP
    // cumulative supply bytes and connection counts
    // ([`face_transport_supply`], a wider sample than the 30s conn-mix
    // cadence).
    // Encoding: the `supply` field is `cuid,tp,w,i,r,ck,it,sn,u,au`
    // joined by semicolons with no spaces (tracing field-rendering
    // fidelity). Observe-only: no dispatch/choke/re-dispatch semantics
    // change.
    if lean_telemetry_enabled() {
        // iter_mut: `SessionSpeedCalc::calculate` needs a &mut window
        // read (same precedent as utp_mute_face's peer_rates.get_mut in
        // run/ecology.rs).
        for (fi, face) in state.faces.iter_mut().enumerate() {
            let mut row = String::new();
            for (i, p) in face.peers.iter().enumerate() {
                let cuid = face.peer_cuids.get(i).copied().unwrap_or(u64::MAX);
                // One row fetch covers meta, download window, upload
                // sample and unchoke state; a missing row or field falls
                // back the same as a missing entry.
                let ps_row = face.peer_state.get_mut(&cuid);
                let tp = match ps_row.as_ref().and_then(|ps| ps.meta.as_ref()) {
                    Some(m) => match m.transport {
                        Transport::Tcp => "t",
                        Transport::Utp => "u",
                    },
                    None => "?",
                };
                let rate = ps_row
                    .as_ref()
                    .and_then(|ps| ps.down_window.as_ref())
                    .map(|w| w.rate())
                    .unwrap_or(0.0);
                // u = our upload rate (peer_rates.up sampled at the same
                // instant, &mut window read per the utp_mute precedent);
                // au = our unchoke state (default false = BEP 3
                // default-choked on connect).
                let up_rate = ps_row
                    .and_then(|ps| ps.rates.as_mut())
                    .map(|r| r.up.calculate(obs_now))
                    .unwrap_or(0);
                let am_unchoke =
                    u8::from(face.peer_state.get(&cuid).is_some_and(|ps| ps.am_unchoked));
                if !row.is_empty() {
                    row.push(';');
                }
                let _ = std::fmt::Write::write_fmt(
                    &mut row,
                    format_args!(
                        "{cuid:x},{tp},{w},{i},{rate:.0},{ck},{it},{sn},{up_rate},{am_unchoke}",
                        w = p.target_request_window(),
                        i = p.in_flight(),
                        ck = u8::from(p.is_choking_us()),
                        it = u8::from(p.is_interested()),
                        sn = u8::from(p.is_snubbed()),
                    ),
                );
            }
            let (tcp_down, utp_down, tcp_conns, utp_conns) = face_transport_supply(face);
            info!(target: "taiji::core::engine", face = fi,
                at = state.active_secs, peers = face.peers.len(),
                tcp_conns, utp_conns, tcp_down, utp_down,
                supply = %row,
                "lean telemetry (per-peer window/inflight/rate/choke/transport)");
        }
    }
    // Gauge feeds (connection family + internal pool family; SET
    // semantics into this engine's slot, rendered as a sum across
    // engines; the transport split tracks the live uTP data plane).
    if let Some(slot) = gauge_slot {
        let (inb, outb, utp_in, utp_out, choked) = count_peer_gauges(&state.faces);
        slot.set_conn_tcp(inb, outb);
        slot.set_conn_utp(utp_in, utp_out);
        slot.set_conn_choked(choked);
        // Redial pool size (bounded by REDIAL_POOL_CAP).
        slot.set_redial_pool_size(state.redial_pool.len() as u64);
        let depth: u64 = state
            .faces
            .iter()
            .map(|f| BLOCK_CHANNEL_CAPACITY.saturating_sub(f.block_tx.capacity()) as u64)
            .sum();
        slot.set_hash_queue_depth(depth);
        // Block-arena watermark/hits/fallbacks (summed across faces;
        // cumulative counters as SET snapshots plus a watermark gauge.
        // A None face means the pool is off; zeros join the sum —
        // honest zeros).
        let mut hits = 0u64;
        let mut fallbacks = 0u64;
        let mut outstanding = 0u64;
        let mut cap = 0u64;
        for f in &state.faces {
            if let Some(a) = &f.block_arena {
                let r = a.readout();
                hits += r.lease_hits_total;
                fallbacks += r.alloc_fallback_total;
                outstanding += r.outstanding_blocks;
                cap += r.cap_bytes;
            }
        }
        slot.set_block_arena(hits, fallbacks, outstanding, cap);
        // Block pre-registration count (observe-only): sum of
        // `block_inflight` across faces (incremented when the sink
        // submits a block, decremented on pipeline batch confirmation —
        // the "submitted but unconfirmed" watermark; SET semantics on
        // the 1s tick). Complements the gauge above: queue_depth is the
        // per-face channel occupancy regardless of sender
        // (`block_tx.capacity()` read), inflight is the pipeline-side
        // unconfirmed total including in-batch work.
        let block_inflight: u64 = state
            .faces
            .iter()
            .map(|f| f.block_inflight.load(std::sync::atomic::Ordering::Relaxed))
            .sum();
        slot.set_block_inflight(block_inflight);
        // DHT routing table size (existing Snapshot command interface;
        // engine exit reports 0).
        let mut v4 = 0u64;
        let mut v6 = 0u64;
        for w in dht_wiring {
            let nodes = w
                .handle
                .snapshot()
                .await
                .map(|s| s.num_nodes as u64)
                .unwrap_or(0);
            match w.family {
                DhtFamily::V4 => v4 += nodes,
                DhtFamily::V6 => v6 += nodes,
            }
        }
        slot.set_dht_nodes(v4, v6);
        // uTP packet counts (existing demux stats, fed as sampling
        // deltas).
        for w in dht_wiring {
            let st = w._demux_keepalive.stats();
            let prev_recv = w.last_utp_recv.swap(st.forwarded_utp, Ordering::Relaxed);
            let prev_drop = w.last_utp_drop.swap(st.dropped_utp_full, Ordering::Relaxed);
            if let Some(m) = metrics {
                m.add_utp_packets(
                    st.forwarded_utp.saturating_sub(prev_recv),
                    st.dropped_utp_full.saturating_sub(prev_drop),
                );
            }
        }
        // Per-kind DHT outbound query counts: fed as sampling deltas from
        // the `DhtSnapshot::queries_*` fields (per-engine deltas
        // accumulate into the sum). Feed point is the successful outbound
        // enqueue in bt::dht `send_query`; after engine exit sampling
        // stops and the cumulative value is kept.
        for w in dht_wiring {
            let Ok(s) = w.handle.snapshot().await else {
                continue;
            };
            let prev_ping = w
                .last_queries_ping
                .swap(s.queries_ping_total, Ordering::Relaxed);
            let prev_find = w
                .last_queries_find_node
                .swap(s.queries_find_node_total, Ordering::Relaxed);
            let prev_gp = w
                .last_queries_get_peers
                .swap(s.queries_get_peers_total, Ordering::Relaxed);
            let prev_ann = w
                .last_queries_announce_peer
                .swap(s.queries_announce_peer_total, Ordering::Relaxed);
            // DHT inbound observation family: the inbound
            // counting face consumed as sampling deltas, same pattern as
            // the outbound queries above. Counters only — the engine's
            // dial/DHT decisions never read these.
            let prev_in_pkts = w
                .last_inbound_packets
                .swap(s.inbound_packets_total, Ordering::Relaxed);
            let prev_in_q = w
                .last_inbound_queries
                .swap(s.inbound_queries_total, Ordering::Relaxed);
            let prev_in_drop = w
                .last_inbound_unmatched_drops
                .swap(s.inbound_unmatched_drops_total, Ordering::Relaxed);
            if let Some(m) = metrics {
                m.add_dht_queries(
                    DhtQueryKind::Ping,
                    s.queries_ping_total.saturating_sub(prev_ping),
                );
                m.add_dht_queries(
                    DhtQueryKind::FindNode,
                    s.queries_find_node_total.saturating_sub(prev_find),
                );
                m.add_dht_queries(
                    DhtQueryKind::GetPeers,
                    s.queries_get_peers_total.saturating_sub(prev_gp),
                );
                m.add_dht_queries(
                    DhtQueryKind::AnnouncePeer,
                    s.queries_announce_peer_total.saturating_sub(prev_ann),
                );
                m.add_dht_inbound(
                    s.inbound_packets_total.saturating_sub(prev_in_pkts),
                    s.inbound_queries_total.saturating_sub(prev_in_q),
                    s.inbound_unmatched_drops_total.saturating_sub(prev_in_drop),
                );
            }
        }
    }
    // Ratio reading refresh: completed length of face 0 (hybrid = v1
    // layout view including pad, matching aria2's v1 accounting).
    let done0 = state
        .faces
        .first()
        .map(|f| f.progress.completed_length())
        .unwrap_or(0);
    state.stats_completed.store(done0, Ordering::Relaxed);
    // Time accumulation: engine-online time counts as active; after
    // download completes it also counts as seed time (the seed-time
    // accounting aria2 lacks).
    state.active_secs = state.active_secs.saturating_add(1);
    if state.completed {
        state.seed_secs = state.seed_secs.saturating_add(1);
    }
    // bt-stop-timeout (download phase only; the aria2 command exits after
    // downloadFinished per `BtStopDownloadCommand.cc`): speed > 0 resets
    // the checkpoint (SpeedCalc 10s sliding window), expiry forces a
    // stop.
    if !state.completed {
        let down_now = session_down.load(Ordering::Relaxed);
        // Stall sampling point: zero-delta check on the raw 1s difference,
        // taken before last_down_sample advances (the stall valve uses
        // the raw delta, not the 10s sliding window; see
        // run::stall::STALL_DETECT_SECS).
        let zero_delta = down_now == state.last_down_sample;
        state
            .speed_calc
            .add(down_now.saturating_sub(state.last_down_sample));
        state.last_down_sample = down_now;
        if let Some(watch) = state.stop_watch.as_mut() {
            let speed = state.speed_calc.calculate(Instant::now());
            if watch.tick(speed) {
                // Message verbatim from aria2 `BtStopDownloadCommand.cc`.
                warn!(target: "taiji::core::engine",
                    timeout = ?seed.stop_timeout,
                    "stop downloading torrent due to --bt-stop-timeout option");
                return ControlFlow::Break(EngineEnd::Failed(format!(
                    "stop downloading torrent due to --bt-stop-timeout option \
                     (no download activity for {:?})",
                    seed.stop_timeout
                )));
            }
        }
        // Stall detection valve: stall-state decision plus urgent actions
        // (reannounce, dispatch reset, capped disconnection of starved
        // seeders; upstream anchors and trade-offs in the run::stall
        // module docs).
        super::stall::stall_valve_tick(state, zero_delta, actor_cmds).await;
    }
    // Peer turnover: past the hard cap, optimistically disconnect the
    // worst max(n*4%, 1) peers every 90s (libtorrent `session_impl.cpp`
    // snapshot + `torrent.cpp` worst-first; anchors and trade-offs in
    // the run::ecology module docs). Division of labor: turnover treats
    // rigidity near the cap (periodic, count driven); the stall valve's
    // seeder rotation treats zero-rate seeds (stall driven,
    // supply-recovery oriented) — predicates and caps are independent.
    // Placed after the stall valve so both rotations can stack during a
    // stall (each capped, total pressure bounded); also runs while
    // seeding (the stop-timeout branch is download-phase only).
    super::ecology::turnover_tick(state, Instant::now());
    // uTP zero-throughput connection governance (`BH_UTP_MUTE=0` restores
    // the plain behavior): a uTP connection whose LEDBAT yields can sit
    // at bps ~ 0 while staying alive and occupying a slot (upstream
    // prefer_tcp limits the TCP class to rate 0; the local rate-limit
    // half is naturally equivalent, the occupancy half is covered by
    // disconnecting at zero throughput; anchors in the run::ecology
    // module docs). Placed after turnover: same active-disconnect family,
    // independent predicate (transport gate + two-way zero throughput +
    // observation window vs cap proximity + worst-first), neither
    // substitutes for the other.
    super::ecology::utp_mute_tick(state, Instant::now());
    // Slow-peer eviction (`BH_SLOW_PEER_CHURN=0` restores the plain
    // behavior): online-but-slow TCP peers are rotated out by rate
    // distribution (30s cadence: eviction line = pool median x frac%,
    // K = max(1, n*k%) worst per round, no disconnect when there is no
    // replacement candidate; anchors in the run::ecology module docs).
    // Placed after utp_mute as the third active-disconnect predicate:
    // turnover treats cap-proximity rigidity (count driven), utp_mute
    // treats zero-throughput uTP, slow_churn treats slow live TCP
    // (rate-distribution driven) — predicates are independent.
    super::ecology::slow_peer_churn_tick(state, Instant::now());
    // SeedCheck (aria2 `SeedCheckCommand.cc`): the latch is set and reset
    // at downloadFinished (the timer starts at completion); satisfaction
    // halts (seeding ends, MSG_SEEDING_END).
    if let Some(check) = state.seed_check.as_mut() {
        if state.completed && check.tick(taiji_domain::seed::DownloadPhase::Finished) {
            info!(target: "taiji::core::engine",
                seed_ratio = seed.seed_ratio,
                seed_time = ?seed.seed_time,
                uploaded_total = startup_uploaded + session_up.load(Ordering::Relaxed),
                completed = done0,
                "seeding end: seed criteria met (halt)");
            return ControlFlow::Break(if state.detached {
                EngineEnd::Detached
            } else {
                EngineEnd::SeedStopped
            });
        }
    }
    // Autosave of the torrent_progress counter row (60s cadence, the
    // --auto-save-interval default per `OptionHandlerFactory.cc`; digest
    // dedup keeps skipping unchanged rows — zero disk writes).
    //
    // Write barrier: before this arm writes the bitmap row, dirty faces
    // (written since the last successful snapshot) get an fsync of their
    // data files. If the sqlite row landed (WAL + checkpoint fsync)
    // before the data files were durable, a post-power-loss
    // restore_progress_bits would read page-cache-lost pieces as sparse
    // zeros (scattered bad blocks while seeding). Barrier order,
    // fail-closed failure semantics and the dirty-flag lifecycle are
    // documented on [`autosave_snapshot`]; zero dirty faces = zero
    // fsyncs. The final row also passes the terminal barrier
    // (run/tail.rs final_flush: drain in-flight writes + fsync, no
    // phantom records at shutdown).
    if state.persist_shared.is_some() && state.active_secs % AUTO_SAVE_INTERVAL_SECS == 0 {
        autosave_snapshot(
            &mut state.faces,
            state.persist_shared.as_ref(),
            piece_len,
            startup_uploaded,
            startup_downloaded,
            startup_active_s,
            startup_seed_s,
            session_up.load(Ordering::Relaxed),
            session_down.load(Ordering::Relaxed),
            state.active_secs,
            state.seed_secs,
        )
        .await;
    }
    ControlFlow::Continue(())
}

/// Routine autosave snapshot (torrent_progress counter row assembly +
/// persist; extraction seam of the 60s arm — driving this function
/// directly drives one autosave).
///
/// Write-barrier order (the same timing invariant as the HTTP side's
/// `session/http/snapshot.rs` "fsync before bitmap persist" and the
/// terminal barrier run/tail.rs `final_flush`):
///
/// 1. fsync half first: fsync the data files of dirty faces (written
///    since the last successful snapshot,
///    [`FaceState::dirty_since_snapshot`], set by `on_piece_written`).
///    Clean faces cost zero fsyncs (unchanged bitmap -> digest dedup
///    skips the write). The bitmap only records PieceWritten pieces
///    (verified AND written), and that event arrives before this
///    function (single-task serial main loop), so every piece's pwrite
///    has returned by the time we fsync — the structurally guaranteed
///    "bitmap never runs ahead of data".
/// 2. fsync failure = the whole bitmap row is skipped this round
///    (fail-closed): prefer progress rollback, never phantom records.
///    Handled at row level, not per-face None: the row is one atomic
///    upsert (v1_bitfield + v2_file_bits together); setting a failed
///    face to None would erase the last good barrier-passed bitmap in
///    the store (re-introducing the full-recheck fallback on restore),
///    while skipping the row keeps the last consistent row in place
///    (the bitmap <= verified-bytes-on-disk invariant holds; the cost is
///    at most one 60s progress delay, converged next round).
/// 3. Dirty flags clear only after a successful persist
///    (Written/SkippedUnchanged): from that point every piece's bytes in
///    the bitmap are fsynced. On persist failure the flags stay (fsync
///    succeeded but the row did not land: bytes are already on disk, so
///    next round rewrites the row without a fresh fsync — keeping the
///    flag one extra round only costs one extra fsync, the safe
///    direction).
#[expect(
    clippy::too_many_arguments,
    reason = "the snapshot inputs are the persisted counter set; a one-use bundle adds no clarity"
)]
pub(super) async fn autosave_snapshot(
    faces: &mut [FaceState],
    persist: Option<&crate::tracker::TrackerPersistShared>,
    piece_len: u32,
    startup_uploaded: u64,
    startup_downloaded: u64,
    startup_active_s: u64,
    startup_seed_s: u64,
    session_up: u64,
    session_down: u64,
    active_secs: u64,
    seed_secs: u64,
) {
    let Some(p) = persist else {
        return;
    };
    // Barrier half: fsync dirty faces (the write handle shares the
    // exclusive domain with the store pipeline's hot write path, see
    // pipeline::SnapshotSyncCell; blocking IO -> spawn_blocking).
    let dirty: Vec<usize> = faces
        .iter()
        .enumerate()
        .filter_map(|(i, f)| f.dirty_since_snapshot.then_some(i))
        .collect();
    for &fi in &dirty {
        let cell = faces[fi].snapshot_sync.clone();
        // The budget only bounds a hung IO (same scale as the terminal
        // barrier's DATA_FLUSH_BUDGET); timeout = barrier failed (skip
        // this round, keep the dirty flag, retry next round). After a
        // timeout the spawn_blocking task detaches and runs to
        // completion — a late fsync is just one more flush (safe
        // direction), coupled to no state.
        let res = tokio::time::timeout(
            SNAPSHOT_SYNC_BUDGET,
            tokio::task::spawn_blocking(move || {
                cell.get().map_or_else(
                    || {
                        Err(taiji_store::error::StoreError::Internal(
                            "snapshot sync: store writer not built".into(),
                        ))
                    },
                    |w| w.with_exclusive(|g| g.flush_os_buffers()),
                )
            }),
        )
        .await;
        match res {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => {
                warn!(target: "taiji::core::engine", face = fi, %e,
                    "autosave snapshot fsync failed: bitmap row refused this round \
                     (fail-closed; retry next beat)");
                return;
            }
            Ok(Err(e)) => {
                warn!(target: "taiji::core::engine", face = fi,
                    "autosave snapshot fsync join failed: {e}: bitmap row refused");
                return;
            }
            Err(_) => {
                warn!(target: "taiji::core::engine", face = fi,
                    budget = ?SNAPSHOT_SYNC_BUDGET,
                    "autosave snapshot fsync budget exceeded: bitmap row refused");
                return;
            }
        }
    }
    let row = progress_row(
        faces,
        Some(p),
        piece_len,
        startup_uploaded,
        startup_downloaded,
        startup_active_s,
        startup_seed_s,
        session_up,
        session_down,
        active_secs,
        seed_secs,
    );
    if flush_progress_row(Some(p), row).await {
        for &fi in &dirty {
            faces[fi].dirty_since_snapshot = false;
        }
    }
}

/// Choke-round arm body (ordering verbatim from aria2): completed faces
/// take the seeder path; downloading faces take the leecher path
/// (LeacherChoke decision + unchoke/choke landing points + tit-for-tat
/// upload service).
///
/// Part 1: budget-derived slots are assembled here; the limiter (an
/// EngineLoop field) is the budget source for [`budget_derived_slots`]
/// (the choke decision surface takes it as a parameter; the knob and
/// bucket rates are read once per 15s round — not a hot path).
pub(super) fn handle_choke_round(state: &mut EngineLoop) {
    let budget_slots = budget_derived_slots(
        taiji_io::knobs::unchoke_budget_slots_enabled(),
        state.limiter.as_deref(),
    );
    for face in &mut state.faces {
        if face.completed {
            choke_round(face);
        } else {
            leecher_choke_round(face, &mut state.choke_rng, budget_slots);
        }
    }
}

/// Supply-byte accounting (observation infrastructure): engine-level
/// accumulators (`supply_*_down`, data source for the 30s conn-mix log
/// and the endgame edge log — truthful even in CLI mode without
/// SessionMetrics) plus the session-counter feed (the only feed site for
/// the per-transport /metrics counters; used when coexisting with rpc).
/// Feed sites: the three counter bridges (2s slow tick / 1s seed tick /
/// final flush) plus the leave arm's final delta.
pub(super) fn note_supply_down(
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    tcp_delta: u64,
    utp_delta: u64,
) {
    state.supply_tcp_down = state.supply_tcp_down.saturating_add(tcp_delta);
    state.supply_utp_down = state.supply_utp_down.saturating_add(utp_delta);
    if let Some(m) = metrics {
        m.add_transport_down_bytes(tcp_delta, utp_delta);
    }
}

/// Endgame in-flight segment slice accumulation (observation surface;
/// shared by the 1s seed tick and the final flush): slices `endgame_edge`
/// (registered at dispatch edges) into `endgame_cum`, so the final
/// segment is not lost if the engine completes or shuts down
/// mid-endgame; a nonzero accumulation feeds the session counter
/// (`note_endgame_elapsed`, the shutdown-summary and /metrics endgame
/// duration). Observe-only: dispatch semantics untouched.
/// Also the bridge site where the last-mile finals (`last_mile_final`
/// / `last8_final`, recorded once at completion) enter the session
/// counters (same 1s tick + final flush dual feed).
pub(super) fn checkpoint_endgame<'a>(
    metrics: Option<&SessionMetrics>,
    faces: impl Iterator<Item = &'a mut FaceState>,
) {
    for face in faces {
        if let Some(since) = face.endgame_edge.take() {
            face.endgame_cum += since.elapsed();
            face.endgame_edge = Some(Instant::now());
        }
        if !face.endgame_cum.is_zero() {
            if let Some(m) = metrics {
                m.note_endgame_elapsed(face.endgame_cum);
            }
            face.endgame_cum = Duration::ZERO;
        }
        // Last-mile final bridge (Option::take = one-shot accounting —
        // cleared at the first checkpoint after completion; the shutdown
        // summary reads the session counters).
        if let Some(m) = metrics {
            if let Some(d) = face.last_mile_final.take() {
                m.note_last_mile_elapsed(d);
            }
            if let Some(d) = face.last8_final.take() {
                m.note_last8_pieces_elapsed(d);
            }
        }
        // Write-locality bridge (face-level take-and-reset, same shape as
        // `endgame_cum`; observe-only — feeds the shutdown summary's
        // `write_adj`/`write_iso` line).
        let (write_adj, write_iso) = (face.write_adjacent, face.write_isolated);
        if write_adj > 0 || write_iso > 0 {
            if let Some(m) = metrics {
                m.note_write_locality(write_adj, write_iso);
            }
            face.write_adjacent = 0;
            face.write_isolated = 0;
        }
    }
}

// -------------------------------------------------------------------
// Deterministic tests for the bitmap-persistence write barrier (the
// power-loss phantom-record fix): real power loss is untestable, so
// injection seams (a stub writer in
// [`crate::pipeline::SnapshotSyncCell`] + readback through the real
// sqlite PersistWriter) lock three invariants: (1) fsync precedes the
// bitmap upsert, (2) only dirty faces are fsynced, (3) fsync failure is
// fail-closed (bitmap not updated, dirty flag kept, retried next
// round). No sleeps, no races: the order probe uses Notify + a std
// channel latch (the blocking point sits inside the barrier's
// spawn_blocking thread; the observer joins deterministically via
// notified()).
// -------------------------------------------------------------------

#[cfg(test)]
mod sec21_tests {
    use super::autosave_snapshot;
    use crate::faces::FaceState;
    use crate::progress::encode_v2_file_bits;
    use crate::tracker::TrackerPersistShared;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use taiji_store::disk::DiskWriter;
    use taiji_store::error::StoreError;
    use taiji_store::persist::PersistWriter;
    use taiji_store::verified::SharedDiskWriter;

    /// fsync script stub (only flush_os_buffers is scripted; every other
    /// trait method returns Ok — barrier-order tests never touch disk):
    /// - `Ok`: count +1, then succeed;
    /// - `Fail`: count +1, then return the injected error (the failure
    ///   seam for the fail-closed test);
    /// - `Gate`: count +1, wake the observer via Notify, then block on
    ///   the Condvar latch until the test releases (the order probe: the
    ///   barrier must reach fsync before the bitmap upsert — the
    ///   progress row must not be visible before release).
    enum FlushScript {
        Ok,
        Fail,
        Gate {
            entered: Arc<tokio::sync::Notify>,
            release: Arc<GateLatch>,
        },
    }

    /// std latch (needed for the `Sync` bound — `mpsc::Receiver` is not
    /// `Sync`, and the stub writer must satisfy
    /// `DiskWriter: Send + Sync`). Every wait blocks until open (the
    /// blocking context is the barrier's spawn_blocking thread).
    struct GateLatch(std::sync::Mutex<bool>, std::sync::Condvar);

    impl GateLatch {
        fn new() -> Arc<GateLatch> {
            Arc::new(GateLatch(
                std::sync::Mutex::new(false),
                std::sync::Condvar::new(),
            ))
        }
        fn wait(&self) {
            let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
            while !*g {
                g = self.1.wait(g).unwrap_or_else(|e| e.into_inner());
            }
        }
        fn open(&self) {
            let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
            *g = true;
            self.1.notify_all();
        }
    }

    struct BarrierWriter {
        flushes: Arc<AtomicUsize>,
        script: FlushScript,
    }

    impl DiskWriter for BarrierWriter {
        fn open(&mut self, _: &Path, _: bool) -> Result<(), StoreError> {
            Ok(())
        }
        fn open_existing(&mut self, _: &Path, _: bool) -> Result<(), StoreError> {
            Ok(())
        }
        fn create(&mut self, _: &Path) -> Result<(), StoreError> {
            Ok(())
        }
        fn truncate(&mut self, _: u64) -> Result<(), StoreError> {
            Ok(())
        }
        fn write_at(&self, _: u64, _: &[u8]) -> Result<(), StoreError> {
            Ok(())
        }
        fn read_at(&self, _: u64, buf: &mut [u8]) -> Result<usize, StoreError> {
            Ok(buf.len())
        }
        fn flush_os_buffers(&self) -> Result<(), StoreError> {
            self.flushes.fetch_add(1, Ordering::Relaxed);
            match &self.script {
                FlushScript::Ok => Ok(()),
                FlushScript::Fail => {
                    Err(StoreError::Internal("injected fsync failure ( PoC)".into()))
                }
                FlushScript::Gate { entered, release } => {
                    entered.notify_one();
                    // Blocking context (the barrier calls in via
                    // spawn_blocking): the latch waits for the test to
                    // release — the barrier does not return and the
                    // bitmap row cannot land meanwhile.
                    release.wait();
                    Ok(())
                }
            }
        }
        fn size(&self) -> Result<u64, StoreError> {
            Ok(0)
        }
        fn set_bypass_page_cache(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    /// Install the stub writer into the face's snapshot-barrier cell
    /// (test injection seam — production fills in the real writer when
    /// the store pipeline is built). Returns the fsync counter handle
    /// held by the test (the same `Arc` the writer counts on, readable
    /// after the snapshot).
    fn inject(face: &mut FaceState, script: FlushScript) -> Arc<AtomicUsize> {
        let flushes = Arc::new(AtomicUsize::new(0));
        let cell: crate::pipeline::SnapshotSyncCell = Arc::new(std::sync::OnceLock::new());
        let _ = cell.set(SharedDiskWriter::new(Box::new(BarrierWriter {
            flushes: Arc::clone(&flushes),
            script,
        })));
        face.snapshot_sync = cell;
        flushes
    }

    /// Real sqlite persistence (temp database): bitmap row writes and
    /// readbacks go through the production path. Registers the torrent
    /// parent row first (the FK anchor for torrent_progress.gid —
    /// production writes it via task registration; the test mirrors that
    /// order).
    async fn persist_fixture(dir: &Path) -> TrackerPersistShared {
        let (handle, _join) = PersistWriter::spawn(dir.join("taiji.sqlite3"))
            .await
            .unwrap_or_else(|e| panic!("persist spawn: {e}"));
        let shared = TrackerPersistShared {
            gid: "sec21".into(),
            handle,
            dirty: Arc::new(Mutex::new(Vec::new())),
            notify: Arc::new(tokio::sync::Notify::new()),
        };
        let row = taiji_store::persist::TorrentRow {
            gid: "sec21".into(),
            name: "sec21-fixture".into(),
            state: "downloading".into(),
            queue_pos: 0,
            dir: dir.display().to_string(),
            config_json: "{}".into(),
            kind: "v2".into(),
            v1_infohash: None,
            v2_infohash: Some(vec![0u8; 32]),
            is_private: false,
            metadata: None,
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        };
        shared
            .handle
            .upsert_torrent(row, Vec::new())
            .await
            .unwrap_or_else(|e| panic!("torrent parent row: {e}"));
        shared
    }

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp_dir(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "taiji-sec21-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        TempDir(dir)
    }

    /// Face fixture (v2, 4 pieces x 16KiB; same shape as the
    /// recovery_tests face).
    fn sec21_face() -> FaceState {
        crate::recovery_tests::recovery_face(4, 16384)
    }

    /// Counting test: a dirty face is fsynced exactly once, a clean face
    /// zero times, the dirty flag clears on a successful snapshot, and
    /// the row content matches face 0's written model.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn autosave_snapshot_fsyncs_dirty_face_only() {
        let tmp = temp_dir("dirty-only");
        let persist = persist_fixture(&tmp.0).await;
        let mut faces = vec![sec21_face(), sec21_face()];
        let (f0, f1) = faces.split_at_mut(1);
        // Face 0: dirty — piece 0 lands, advancing the written bitmap and
        // the dirty flag (production sets it at the same
        // on_piece_written point). Face 1: clean — piece 1 predates the
        // last snapshot (dirty flag false means its bytes already passed
        // the barrier with the last successful snapshot).
        let c0 = inject(&mut f0[0], FlushScript::Ok);
        let c1 = inject(&mut f1[0], FlushScript::Ok);
        assert!(f0[0].written_progress.set_piece_done_global(0));
        f0[0].dirty_since_snapshot = true;
        assert!(f1[0].written_progress.set_piece_done_global(1));

        autosave_snapshot(&mut faces, Some(&persist), 16384, 0, 0, 0, 0, 0, 0, 60, 0).await;

        assert_eq!(
            c0.load(Ordering::Relaxed),
            1,
            "a dirty face must fsync exactly once (write barrier)"
        );
        assert_eq!(
            c1.load(Ordering::Relaxed),
            0,
            "a clean face must not fsync (no writes = no barrier cost)"
        );
        assert!(
            !faces[0].dirty_since_snapshot,
            "the dirty flag must clear after a successful snapshot"
        );
        let row = persist
            .handle
            .load_torrent_progress("sec21")
            .await
            .unwrap_or_else(|e| panic!("readback: {e}"))
            .unwrap_or_else(|| panic!("the progress row must be settled"));
        assert_eq!(
            row.v2_file_bits,
            encode_v2_file_bits(&faces[0].written_progress),
            "the bitmap row must reflect face 0's written model (piece 0 set)"
        );
    }

    /// Order test: while the barrier's fsync is suspended on the std
    /// latch, the progress row must not be in the store (the bitmap
    /// upsert strictly follows the fsync return); after release the row
    /// lands and the dirty flag clears.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn autosave_snapshot_upsert_waits_for_fsync() {
        let tmp = temp_dir("gate");
        let persist = persist_fixture(&tmp.0).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let latch = GateLatch::new();
        let mut face = sec21_face();
        let c = inject(
            &mut face,
            FlushScript::Gate {
                entered: Arc::clone(&entered),
                release: Arc::clone(&latch),
            },
        );
        assert!(face.written_progress.set_piece_done_global(0));
        face.dirty_since_snapshot = true;
        let mut faces = vec![face];

        let p_task = persist.clone();
        let task = tokio::spawn(async move {
            autosave_snapshot(&mut faces, Some(&p_task), 16384, 0, 0, 0, 0, 0, 0, 60, 0).await;
            faces
        });

        // fsync must be invoked (barrier exists): deterministic
        // rendezvous on the latch's entered notify.
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .unwrap_or_else(|_| panic!("red test (pre-fix): autosave bypasses the fsync barrier"));

        // While fsync is suspended the bitmap row must not land (the
        // upsert strictly follows the fsync return).
        let row = persist
            .handle
            .load_torrent_progress("sec21")
            .await
            .unwrap_or_else(|e| panic!("readback: {e}"));
        assert!(
            row.is_none(),
            "before fsync returns the bitmap row must not settle (current row \
             {row:?} = the phantom-accounting face of the bitmap running ahead of data)"
        );

        // Release -> snapshot completes: row lands, exactly one fsync,
        // dirty flag cleared.
        latch.open();
        let faces = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap_or_else(|_| {
                panic!("red test (pre-fix)/parked: the snapshot must complete once fsync admits it")
            })
            .unwrap_or_else(|e| panic!("autosave task join: {e:?}"));
        assert_eq!(c.load(Ordering::Relaxed), 1);
        assert!(!faces[0].dirty_since_snapshot);
        let row = persist
            .handle
            .load_torrent_progress("sec21")
            .await
            .unwrap_or_else(|e| panic!("readback: {e}"))
            .unwrap_or_else(|| panic!("the progress row must settle once fsync admits it"));
        assert_eq!(
            row.v2_file_bits,
            encode_v2_file_bits(&faces[0].written_progress)
        );
    }

    /// Fail-closed test: a dirty face's fsync failure leaves the bitmap
    /// unupdated this round (the store keeps the last barrier-passed
    /// row) and the dirty flag set (retry next round); switching the
    /// injection to Ok makes the next round persist normally and clear
    /// the flag. The baseline row comes from a first clean-face snapshot
    /// (a clean face's standing bitmap is the previous snapshot's
    /// barrier-passed content and needs no fsync).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn autosave_snapshot_fsync_failure_keeps_last_row() {
        let tmp = temp_dir("fail-closed");
        let persist = persist_fixture(&tmp.0).await;
        let mut faces = vec![sec21_face()];
        // Baseline: piece 0 is standing content (clean face); the first
        // snapshot writes the baseline row.
        let _c = inject(&mut faces[0], FlushScript::Ok);
        assert!(faces[0].written_progress.set_piece_done_global(0));
        autosave_snapshot(&mut faces, Some(&persist), 16384, 0, 0, 0, 0, 0, 0, 60, 0).await;
        let baseline = persist
            .handle
            .load_torrent_progress("sec21")
            .await
            .unwrap_or_else(|e| panic!("baseline readback: {e}"))
            .unwrap_or_else(|| panic!("the baseline row must be settled"));

        // New piece lands (piece 1) + injected fsync failure -> the
        // bitmap must not update this round.
        let c_fail = inject(&mut faces[0], FlushScript::Fail);
        assert!(faces[0].written_progress.set_piece_done_global(1));
        faces[0].dirty_since_snapshot = true;
        autosave_snapshot(&mut faces, Some(&persist), 16384, 0, 0, 0, 0, 0, 0, 120, 0).await;
        let after = persist
            .handle
            .load_torrent_progress("sec21")
            .await
            .unwrap_or_else(|e| panic!("after-failure readback: {e}"))
            .unwrap_or_else(|| panic!("the baseline row must still be present"));
        assert_eq!(
            (after.v1_bitfield, &after.v2_file_bits),
            (baseline.v1_bitfield, &baseline.v2_file_bits),
            "on fsync failure the bitmap must not update (fail-closed: prefer \
             progress regression, never phantom accounting)"
        );
        assert_eq!(
            c_fail.load(Ordering::Relaxed),
            1,
            "the failure seam must be hit"
        );
        assert!(
            faces[0].dirty_since_snapshot,
            "after failure the dirty flag must persist (the next round re-walks the barrier)"
        );

        // Injection switched to Ok -> next round persists normally and
        // clears the dirty flag (recovery path converges).
        let c_ok = inject(&mut faces[0], FlushScript::Ok);
        autosave_snapshot(&mut faces, Some(&persist), 16384, 0, 0, 0, 0, 0, 0, 180, 0).await;
        let recovered = persist
            .handle
            .load_torrent_progress("sec21")
            .await
            .unwrap_or_else(|e| panic!("recovery readback: {e}"))
            .unwrap_or_else(|| panic!("the row must be present"));
        assert_eq!(
            recovered.v2_file_bits,
            encode_v2_file_bits(&faces[0].written_progress),
            "after fsync succeeds the bitmap must converge to the written model (pieces 0+1)"
        );
        assert_eq!(c_ok.load(Ordering::Relaxed), 1);
        assert!(!faces[0].dirty_since_snapshot);
    }
}

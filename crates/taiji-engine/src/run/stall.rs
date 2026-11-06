//! Stall detection valve: detection/action state machine coordinated
//! with admission (which lives in run::state::admission_verdict).
//!
//! Mechanism: a stall window is seeder slot starvation — the unchoke
//! slots stick to active downloaders (seeder-side outstanding-upload
//! first key, `BtSeederStateChoke.cc`), so the optimistic rotation (1
//! random slot per round) never lands on us; during DL=0 connections
//! keep growing, burning CPU without delivering bytes. Three urgent
//! actions per action window: urgent re-announce, dispatch reset, and
//! capped seeder rotation. Upstream anchor mapping:
//! docs/design/engine.md.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use taiji_bt::peer::PeerHandle as _;
use taiji_bt::tracker::actor::TrackerCommand;
use tracing::{info, warn};

use super::state::EngineLoop;

/// Stall verdict: consecutive 1s samples with zero DL increment (fed by
/// the 1s seed tick; raw differencing rather than a 10s sliding-window
/// mean — window decay would postpone the stall onset by about one
/// window). 10s sits well below the shortest real stall and above the
/// transient intra-window gaps of slot switching (sub-second to a few
/// seconds).
pub(crate) const STALL_DETECT_SECS: u32 = 10;

/// Valve armed minimum session age (seconds): skips the startup segment
/// (zero traffic while announce/handshake are unfinished is not stall
/// evidence; ttfb 2-5s plus first-announce noise).
pub(crate) const STALL_ARM_MIN_AGE_SECS: u64 = 30;

/// Urgent action period while stalled (once on the entry edge + repeat
/// every 30s; magnitude between aria2's 30s choke round cadence and the
/// 10s replenish window of `ActivePeerConnectionCommand` — re-announce
/// is hard-gated by tracker min_interval, so denser actions buy
/// nothing).
pub(crate) const STALL_ACTION_PERIOD: Duration = Duration::from_secs(30);

/// Seeder rotation eligibility: minimum duration of the zero-supply +
/// choking-us posture (30-bucket down-window rate==0, fed at 2s ticks =
/// ~60s observation span). Shorter seeder silences are mostly the normal
/// shape of slot competition.
pub(crate) const SEEDER_ROTATE_IDLE_SECS: u64 = 60;

/// Rotation disconnect cap per action window (the cap = conservative
/// rotation pressure; disconnecting every seeder connection at once
/// would cut our own supply).
pub(crate) const SEEDER_ROTATE_BATCH: usize = 2;

/// Rotation pure row (the scan face projected onto the decision;
/// unit tests drive it directly, not through FaceState).
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerStallRow {
    pub(crate) cuid: u64,
    /// seeder ∧ choking us ∧ zero supply in the window (three-condition
    /// AND).
    pub(crate) starved: bool,
}

/// Stall valve state (mounted as a single EngineLoop field; Default at
/// assemble).
#[derive(Default)]
pub(crate) struct StallValve {
    /// Consecutive zero-DL-increment sample count (1s seed tick fed).
    pub(crate) zero_secs: u32,
    /// Stall hysteresis state (set at >= [`STALL_DETECT_SECS`]; cleared
    /// on the supply-recovery edge).
    pub(crate) active: bool,
    /// Last urgent action instant ([`STALL_ACTION_PERIOD`] throttle
    /// anchor).
    pub(crate) last_action: Option<Instant>,
    /// Seeder rotation observation bookkeeping: (face, cuid) -> first
    /// instant all three conditions held (the continuity criterion; the
    /// whole table clears on the supply-recovery edge; entries of
    /// departed peers linger lazily and vanish with the scan face —
    /// capacity bound = stalled seeder connection count, recovered on
    /// the clearing edge).
    pub(crate) starved_since: HashMap<(usize, u64), Instant>,
    /// Urgent action trigger count (observability counter).
    pub(crate) actions: u32,
    /// Seeder rotation disconnect total (observability counter).
    pub(crate) rotations: u32,
    /// Urgent reannounce action-window total (observability counter;
    /// actual sends per window are in the log).
    pub(crate) reannounces: u32,
}

/// Seeder rotation decision (pure function; table-driven test face over
/// [`PeerStallRow`]):
/// - first sight of an eligible row -> record the observation start, no
/// disconnect (the continuity criterion begins);
/// - eligible row sustained >= [`SEEDER_ROTATE_IDLE_SECS`] and this
/// window's batch not full -> disconnect (observation bookkeeping
/// cleared; reconnection is handled by the redial pool's 60s backoff —
/// sequential single connection);
/// - ineligible row -> clear observation bookkeeping (supply recovery /
/// unchoke revokes the rotation intent).
///
/// Returns the cuids disconnected this window (<= batch).
pub(crate) fn rotation_pick(
    rows: &[PeerStallRow],
    starved_since: &mut HashMap<(usize, u64), Instant>,
    fi: usize,
    now: Instant,
    batch: usize,
) -> Vec<u64> {
    let mut picked = Vec::new();
    for row in rows {
        if !row.starved {
            starved_since.remove(&(fi, row.cuid));
            continue;
        }
        let since = *starved_since.entry((fi, row.cuid)).or_insert(now);
        if now.duration_since(since) >= Duration::from_secs(SEEDER_ROTATE_IDLE_SECS)
            && picked.len() < batch
        {
            starved_since.remove(&(fi, row.cuid));
            picked.push(row.cuid);
        }
    }
    picked
}

/// Stall detection state machine (pure function; table-driven test
/// face): advances the valve on 1s samples, returns whether this sample
/// opens an action window (entry edge ∨ action-period edge).
///
/// - `armed` = session age >= [`STALL_ARM_MIN_AGE_SECS`] ∧ leecher phase
/// (guaranteed by the caller); while not armed, zero-increment counts
/// do not accumulate (startup noise).
/// - `zero_delta` = false (supply-recovery edge): clear the count / stall
/// state / rotation bookkeeping.
/// - Zero increment >= [`STALL_DETECT_SECS`]: set the stall state; the
/// entry edge returns true; afterwards true once per
/// [`STALL_ACTION_PERIOD`].
pub(crate) fn stall_valve_advance(
    valve: &mut StallValve,
    zero_delta: bool,
    armed: bool,
    now: Instant,
) -> bool {
    if !armed {
        valve.zero_secs = 0;
        return false;
    }
    if !zero_delta {
        valve.zero_secs = 0;
        valve.active = false;
        valve.starved_since.clear();
        valve.last_action = None;
        return false;
    }
    valve.zero_secs = valve.zero_secs.saturating_add(1);
    if valve.zero_secs < STALL_DETECT_SECS {
        return false;
    }
    if !valve.active {
        // Entry edge: set the stall state and act immediately.
        valve.active = true;
        valve.last_action = Some(now);
        return true;
    }
    match valve.last_action {
        Some(t) if now.duration_since(t) < STALL_ACTION_PERIOD => false,
        _ => {
            valve.last_action = Some(now);
            true
        }
    }
}

/// Stall detection valve tick (1s seed tick fed; leecher phase only).
/// `zero_delta` = this 1s sample saw zero session download increment
/// (the same sampling point as stop-timeout).
pub(super) async fn stall_valve_tick(
    state: &mut EngineLoop,
    zero_delta: bool,
    actor_cmds: &[Option<mpsc::Sender<TrackerCommand>>],
) {
    if state.completed {
        state.stall_valve.zero_secs = 0;
        state.stall_valve.active = false;
        return;
    }
    let was_active = state.stall_valve.active;
    // Valve armed gate: the startup segment is not stall evidence (see
    // the constant docs).
    let armed = state.active_secs >= STALL_ARM_MIN_AGE_SECS;
    let now = Instant::now();
    if !zero_delta && was_active {
        info!(target: "taiji::core::engine",
            stalled_for = state.stall_valve.zero_secs,
            actions = state.stall_valve.actions,
            rotations = state.stall_valve.rotations,
            "stall valve: supply recovered, valve reset");
    }
    let due = stall_valve_advance(&mut state.stall_valve, zero_delta, armed, now);
    if state.stall_valve.active && !was_active {
        info!(target: "taiji::core::engine",
            zero_secs = state.stall_valve.zero_secs,
            conns = state.registered_peers(),
            "stall valve: download stalled (DL=0), urgent actions armed");
    }
    if !due {
        return;
    }
    state.stall_valve.last_action = Some(now);
    state.stall_valve.actions = state.stall_valve.actions.wrapping_add(1);
    // Action 1: urgent reannounce (the actor min_interval compliance
    // gate untouched — a full channel / missing actor skips, retried at
    // the next action window; never blocks the 1s tick).
    let mut reannounced = 0usize;
    for (fi, cmd) in actor_cmds.iter().enumerate() {
        let Some(face) = state.faces.get(fi) else {
            continue;
        };
        if face.completed {
            continue;
        }
        if let Some(cmd) = cmd {
            let (tx, _rx) = tokio::sync::oneshot::channel();
            if cmd
                .try_send(TrackerCommand::Reannounce { reply: tx })
                .is_ok()
            {
                reannounced += 1;
            }
        }
    }
    state.stall_valve.reannounces = state.stall_valve.reannounces.wrapping_add(1);
    // Action 2: dispatch reset (register dispatch debt for every
    // incomplete face — settled by the loop-top / debt-cadence arm under
    // the existing three-condition gate; in-round decision order
    // unchanged).
    let debt_faces = state
        .faces
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.completed)
        .map(|(fi, _)| fi)
        .collect::<Vec<_>>();
    for fi in debt_faces {
        state.note_dispatch_debt(fi);
    }
    // Action 3: seeder rotation (eligibility scan + capped disconnects;
    // a disconnect enters the redial pool naturally via the leave arm —
    // outbound, backoff from 60s, sequential single connection).
    // Webseed pseudo-peers are exempt (rotation value = stuck-connection
    // self-healing + a fresh optimistic ticket via redial — webseeds have
    // no BT redial face, a disconnect would lose the source permanently;
    // `EngineLoop::is_webseed`; the turnover/slow-churn sweeps follow the
    // same rule).
    let mut rotated = Vec::new();
    for (fi, face) in state.faces.iter_mut().enumerate() {
        if face.completed {
            continue;
        }
        let rows = face
            .peer_cuids
            .iter()
            .enumerate()
            .filter(|(_, cuid)| !state.webseed_cuids.contains(*cuid))
            // (Direct field access instead of the
            // [`EngineLoop::is_webseed`] method: capturing the method
            // receiver would borrow the whole struct, conflicting with
            // this loop's mutable faces borrow; separate field paths
            // borrow disjointly — semantically the same lookup.)
            .map(|(i, cuid)| {
                // Seeder test = bitmap row all ones (`is_full`, the
                // bitset form of count==N; same verdict as the old
                // per-bit all).
                let is_seeder = face.peer_avail.get(cuid).is_some_and(|bits| bits.is_full());
                let choking = face.peers[i].is_choking_us();
                let zero_supply = face
                    .peer_state
                    .get(cuid)
                    .and_then(|ps| ps.down_window.as_ref())
                    .map(|w| w.rate() == 0.0)
                    .unwrap_or(true);
                PeerStallRow {
                    cuid: *cuid,
                    starved: is_seeder && choking && zero_supply,
                }
            })
            .collect::<Vec<_>>();
        let picked = rotation_pick(
            &rows,
            &mut state.stall_valve.starved_since,
            fi,
            now,
            SEEDER_ROTATE_BATCH,
        );
        for cuid in picked {
            if let Some(pos) = face.peer_cuids.iter().position(|c| *c == cuid) {
                let ip = face.peer_state.get(&cuid).and_then(|ps| ps.ip);
                // Disconnect = graceful Shutdown + token cancel (same
                // form as the ban path); the leave event goes through
                // handle_peer_left -> redial pool admission (outbound,
                // not banned); the reconnect cadence is managed by the
                // redial pool's 60s backoff.
                face.peers[pos].shutdown();
                rotated.push((fi, cuid, ip));
            }
        }
    }
    state.stall_valve.rotations = state
        .stall_valve
        .rotations
        .wrapping_add(rotated.len() as u32);
    if !rotated.is_empty() {
        warn!(target: "taiji::core::engine",
            count = rotated.len(),
            total_rotations = state.stall_valve.rotations,
            reannounced,
            conns = state.registered_peers(),
            redial_pool = state.redial_pool.len(),
            "stall valve: rotated starved seeder connections (redial will re-connect with backoff)");
    } else {
        info!(target: "taiji::core::engine",
            reannounced,
            conns = state.registered_peers(),
            "stall valve: urgent actions (reannounce + dispatch reset), no starved seeder qualified");
    }
}

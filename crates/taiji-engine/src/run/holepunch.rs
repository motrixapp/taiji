//! ut_holepunch engine orchestration: event consumption (relay
//! decisions + punch dials), dial-outcome report consumption (the
//! trigger surface), swarm connection-table/introducer bookkeeping
//! lookups.
//!
//! Scope: PeerTask events -> decisions and command dispatch with the
//! swarm's global view; dial outcomes -> trigger bookkeeping
//! ([`taiji_bt::holepunch::HolepunchBook`]) -> rendezvous asks. Wire
//! codec/rate limiting (bt::peer), the dial tasks themselves (transit),
//! and event-channel assembly (assemble) live elsewhere.
//!
//! Upstream anchor mapping: docs/design/engine.md.
//!
//! Hard invariant: introducer/connection lookups are face-scoped —
//! [`find_connection_by_ep`] only matches the requester's own face;
//! cross-face hits are treated as not connected (no existence probe, no
//! induced dialing, no cross-face address leakage).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tracing::{debug, info};

use taiji_bt::holepunch::{HpError, RelayAction, UtHolepunch, relay_decision};
use taiji_bt::peer::PeerHandle as _;
use taiji_bt::peer::{HolepunchEvent, PeerCommand, PeerTaskHandle};
use taiji_bt::peer_policy::IpGuardHandle;

use std::ops::ControlFlow;

use super::state::{DialCtx, EngineLoop, spawn_peer_dial};
use tokio_util::sync::CancellationToken;

use crate::dht::DialDedup;
use crate::faces::FaceState;
use crate::tracker::epoch_secs;
// ---- Holepunch observation family (process-level atomics = the sole
// write points; each feed site is single-source) ----
//
// Each counter has exactly one fetch_add site; the 1s seed tick bridges
// deltas into [`crate::metrics::SessionMetrics`] (same pattern as the
// tick.rs two-phase observation family), rendered by /metrics as seven
// `taiji_holepunch_*_total` series. Observe-only, zero behavior.
/// Rendezvous sent to an introducer by the trigger surface (feed = the
/// send point in [`handle_hp_dial_report`]; counted at send, no receipt
/// accounting — libtorrent has no receipt surface either).
pub(crate) static HP_RENDEZVOUS_SENT: AtomicU64 = AtomicU64::new(0);
/// Relay Introduce action (feed = the introduce arm of
/// [`relay_introduce`]; one introduction sends at most two connect
/// payloads (bt_peer_connection.cpp) but counts the action itself).
pub(crate) static HP_RELAYED_CONNECTS: AtomicU64 = AtomicU64::new(0);
/// Punch dial spawns (feed = after all admission gates in
/// [`punch_dial`]; blocked attempts do not count — the unit is a real
/// outbound attempt).
pub(crate) static HP_PUNCH_DIALS: AtomicU64 = AtomicU64::new(0);
/// Punch-dial handshake successes (feed = connected AND punch in
/// [`handle_hp_dial_report`]; same source under both modes — with
/// BH_HOLEPUNCH_MODE=0 punch dials take the regular plan and still
/// count, keeping the observation surface purely additive).
pub(crate) static HP_PUNCH_ESTABLISHED: AtomicU64 = AtomicU64::new(0);
/// Introducer hits (feed = [`handle_hp_dial_report`]; `HolepunchBook::
/// rendezvous_target` = Some — the failed address has a live PEX
/// introducer and the backoff has elapsed).
pub(crate) static HP_INTRODUCER_HITS: AtomicU64 = AtomicU64::new(0);
/// No introducer (feed = [`handle_hp_dial_report`]; rendezvous_target =
/// None — the failed address has no PEX delivery record / backoff not
/// elapsed / TTL expired. Denominator = hits + no, quantifying the
/// punchability rate).
pub(crate) static HP_NO_INTRODUCER: AtomicU64 = AtomicU64::new(0);
/// Punch window exhausted with total silence (feed = the give-up point
/// of the transit punch path; zero peer replies across the whole attempt
/// budget = the port-prediction surface never opened, a symmetric-NAT
/// shape — classified by [`punch_gave_up_nat`]).
pub(crate) static HP_PUNCH_FAILED_NAT: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the observation family ([`HolepunchObs::current`] reads
/// the process-level atomics; the prev carrier for the tick delta bridge
/// — [`EngineLoop.hp_obs_prev`]; zero at session start).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HolepunchObs {
    pub(crate) rendezvous_sent: u64,
    pub(crate) relayed_connects: u64,
    pub(crate) punch_dials: u64,
    pub(crate) punch_established: u64,
    pub(crate) introducer_hits: u64,
    pub(crate) no_introducer: u64,
    pub(crate) punch_failed_nat: u64,
}

impl HolepunchObs {
    /// Current process-level readings (one pass over 7 atomics;
    /// negligible at the 1s cadence).
    pub(crate) fn current() -> HolepunchObs {
        HolepunchObs {
            rendezvous_sent: HP_RENDEZVOUS_SENT.load(Ordering::Relaxed),
            relayed_connects: HP_RELAYED_CONNECTS.load(Ordering::Relaxed),
            punch_dials: HP_PUNCH_DIALS.load(Ordering::Relaxed),
            punch_established: HP_PUNCH_ESTABLISHED.load(Ordering::Relaxed),
            introducer_hits: HP_INTRODUCER_HITS.load(Ordering::Relaxed),
            no_introducer: HP_NO_INTRODUCER.load(Ordering::Relaxed),
            punch_failed_nat: HP_PUNCH_FAILED_NAT.load(Ordering::Relaxed),
        }
    }

    /// Delta against the previous reading (the tick bridge feed;
    /// saturating subtraction — the atomic reads are not one atomic
    /// snapshot, so theoretical rollback counts as 0, same as the
    /// two-phase bridge).
    pub(crate) fn delta_since(&self, prev: &HolepunchObs) -> HolepunchObs {
        HolepunchObs {
            rendezvous_sent: self.rendezvous_sent.saturating_sub(prev.rendezvous_sent),
            relayed_connects: self.relayed_connects.saturating_sub(prev.relayed_connects),
            punch_dials: self.punch_dials.saturating_sub(prev.punch_dials),
            punch_established: self
                .punch_established
                .saturating_sub(prev.punch_established),
            introducer_hits: self.introducer_hits.saturating_sub(prev.introducer_hits),
            no_introducer: self.no_introducer.saturating_sub(prev.no_introducer),
            punch_failed_nat: self.punch_failed_nat.saturating_sub(prev.punch_failed_nat),
        }
    }
}

/// holepunch mode switch (fallback knob): `BH_HOLEPUNCH_MODE=0` ->
/// punch dials take the regular same-discipline path (regular dial plan,
/// single pass); default/anything else = mode on (uTP sticky + in-window
/// fast retry). Read at DialJob assembly ([`super::state::
/// spawn_peer_dial`], same discipline as BH_BLOCK_BYPASS — no env reads
/// inside dial tasks). Parsing and read timing live in `taiji_io::knobs`
/// (read per event, no cache mutation).
pub(crate) fn holepunch_mode_enabled() -> bool {
    taiji_io::knobs::holepunch_mode_enabled()
}

/// Outbound dial-outcome report (peer_connect -> main loop; carried by
/// every regular/punch outbound dial). `connected` = a transport
/// handshake succeeded (failure memory cleared); false = the dial plan
/// ran out (a real direct-connect failure, arming the trigger gate —
/// libtorrent's trigger point is the connection-failed callback,
/// `peer_connection.cpp`). `silent` = the silent-give-up classification
/// at plan exhaustion ([`crate::transit::plan_is_silent`]; always false
/// when connected) — the main loop feeds it into the silent ledger
/// (escalating backoff/cool-down). `punch` = this dial originated from a
/// ut_holepunch connect command ([`super::state::DialSource::Punch`];
/// the feed criterion for punch_established, independent of the mode
/// switch: with the fallback mode on, punch-dial successes still count).
/// `face` = the owning face (a field for failed-candidate re-queueing;
/// snapshotted at dial assembly, with a face-presence check at
/// drain-round dial time). `discovery` = a discovery-source dial
/// (produced by tracker/DHT/PEX candidate drain rounds; the source
/// criterion for failed-candidate re-queueing — the Redial pool and the
/// Punch surface manage their own cadence and never enter the candidate
/// table).
#[derive(Debug)]
pub(crate) struct HpDialReport {
    pub(crate) addr: SocketAddr,
    pub(crate) connected: bool,
    pub(crate) silent: bool,
    pub(crate) punch: bool,
    pub(crate) face: usize,
    pub(crate) discovery: bool,
}

/// Inbound ut_holepunch event arm: rendezvous -> relay decision;
/// connect -> punch dial; failed -> debug (informational, same as
/// libtorrent).
pub(super) fn handle_holepunch_event(
    ev: HolepunchEvent,
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
    actual_port: u16,
) -> ControlFlow<(), ()> {
    // Face attribution: cuid -> face (same method as the pex arm).
    let Some(fi) = state
        .faces
        .iter()
        .position(|f| f.peer_cuids.contains(&ev.from))
    else {
        debug!(target: "taiji::core::engine", cuid = ev.from,
            "ut_holepunch from unknown peer: dropped");
        return ControlFlow::Break(());
    };
    match ev.msg {
        UtHolepunch::Rendezvous { ep } => relay_introduce(&state.faces, fi, ev.from, ep),
        UtHolepunch::Connect { ep } => punch_dial(state, dial, token, fi, ep, actual_port),
        UtHolepunch::Failed { ep, error } => {
            debug!(target: "taiji::core::engine", %ep, ?error,
                "ut_holepunch failed received (informational)");
        }
    }
    ControlFlow::Continue(())
}

/// Relay decision: requester `from` (a connection on face `fi`) asks to
/// be introduced to target `ep`.
fn relay_introduce(faces: &[FaceState], fi: usize, from: u64, ep: SocketAddr) {
    // The requester's mapped address (the relay's observation) — the
    // connect payload sent to the target.
    let requester_addr = faces[fi]
        .peer_state
        .get(&from)
        .and_then(|ps| ps.meta.as_ref())
        .map(|m| SocketAddr::new(m.ip, m.port));
    let Some(requester_addr) = requester_addr else {
        debug!(target: "taiji::core::engine", cuid = from,
            "rendezvous requester has no meta: dropped");
        return;
    };
    // find_peer (libtorrent `torrent.cpp`): exact (ip, port) match in the
    // connection table; the target's negotiation eligibility = the
    // handle's negotiation mirror. The lookup is scoped to the
    // requester's face (libtorrent find_peer is torrent-scoped —
    // `associated_torrent()->find_peer(ep)`, `bt_peer_connection.cpp`);
    // a cross-face search would leak cross-torrent connection existence
    // and enable cross-face induced dialing, so any cross-face hit is
    // treated as not connected.
    let target = find_connection_by_ep(faces, fi, ep);
    let target_supports = target
        .and_then(|(tfi, tcuid)| handle_for_cuid(&faces[tfi], tcuid))
        .map(|h| h.supports_holepunch());
    let action = relay_decision(
        from,
        target.map(|(_, tcuid)| (tcuid, target_supports.unwrap_or(false))),
    );
    let requester_handle = handle_for_cuid(&faces[fi], from).cloned();
    match action {
        RelayAction::ReplyNotConnected => {
            debug!(target: "taiji::core::engine", %ep, cuid = from,
                "rendezvous: not connected to target");
            reply_failed(requester_handle.as_ref(), ep, HpError::NotConnected);
        }
        RelayAction::ReplyNoSupport => {
            debug!(target: "taiji::core::engine", %ep, cuid = from,
                "rendezvous: target without holepunch negotiation");
            reply_failed(requester_handle.as_ref(), ep, HpError::NoSupport);
        }
        RelayAction::ReplyNoSelf => {
            debug!(target: "taiji::core::engine", %ep, cuid = from,
                "rendezvous: target is requester itself");
            reply_failed(requester_handle.as_ref(), ep, HpError::NoSelf);
        }
        RelayAction::Introduce => {
            info!(target: "taiji::core::engine", requester = %requester_addr,
                target = %ep, "rendezvous: introducing (both dial)");
            // Observation family: count the relay introduce action (at
            // most two connect payloads per introduction; the action
            // counts once — single-source feed).
            HP_RELAYED_CONNECTS.fetch_add(1, Ordering::Relaxed);
            // connect(target ep) -> requester; connect(requester's mapped
            // address) -> target. Both addresses belong to live handshake
            // connections (structurally no amplification); each side's
            // outbound dial and admission are handled by its own connect
            // arm.
            if let Some(h) = requester_handle.as_ref() {
                let _ = h.command(PeerCommand::SendHolepunch(UtHolepunch::Connect { ep }));
            }
            if let Some((tfi, tcuid)) = target {
                // Same-face check: the target must belong to the
                // requester's face (structurally guaranteed by the
                // face-scoped lookup; the explicit check is call-site
                // regression defense — on violation the introduction is
                // refused, never sending connect to a cross-face
                // connection or leaking the requester's address).
                if tfi != fi {
                    debug!(target: "taiji::core::engine", face = fi,
                        target_face = tfi, %ep,
                        "rendezvous: cross-face target rejected (F-92-1)");
                    return;
                }
                if let Some(h) = handle_for_cuid(&faces[tfi], tcuid).cloned() {
                    let _ = h.command(PeerCommand::SendHolepunch(UtHolepunch::Connect {
                        ep: requester_addr,
                    }));
                }
            }
        }
    }
}

/// connect outbound-dial admission gates: self-connect guard (the same
/// guard as the tracker/DHT/PEX arms: loopback + this client's announce
/// port) -> IpGuard filter point (same as libtorrent's
/// banned-no-connect) -> already connected on this face by IP
/// (libtorrent's already-connected gate) -> the [`DialDedup`] dedup
/// window. false = skip the dial (each gate keeps its own debug log —
/// bans are never silent).
fn punch_dial_admit(
    guard: &IpGuardHandle,
    face: &FaceState,
    dedup: &mut DialDedup,
    ep: SocketAddr,
    actual_port: u16,
    now: Instant,
) -> bool {
    // Self-connect guard (single point in addr_hygiene: loopback /
    // unspecified / v4-mapped loopback / local interface address set AND
    // the announce port; same discipline as the tracker/DHT/PEX arms).
    if crate::addr_hygiene::is_self_endpoint(
        ep,
        actual_port,
        crate::addr_hygiene::LocalIpSet::shared(),
    ) {
        debug!(target: "taiji::core::engine", %ep, "punch dial skipped: self");
        return false;
    }
    // IpGuard filter point (same as libtorrent's banned-no-connect; the
    // dial task filters again — here we pre-filter to avoid a useless
    // spawn).
    if let Some(block) = guard.load().blocks(ep.ip(), epoch_secs()) {
        debug!(target: "taiji::core::engine", %ep, block = %block,
            "punch dial skipped by IpGuard");
        return false;
    }
    // Already connected by IP (libtorrent's already-connected gate; same
    // guard as the dht/pex arms).
    if face.peer_state.values().any(|ps| ps.ip == Some(ep.ip())) {
        debug!(target: "taiji::core::engine", %ep,
            "punch dial skipped: already connected by ip");
        return false;
    }
    // The discovery surface's dedup window — DHT/PEX source dials already
    // go through [`DialDedup::admit`] (dial.rs); the connect command was
    // the only dial source bypassing dedup (each peer's 4/60s rate limit
    // x colluding peers = a directed dialing gun). On the shared table,
    // one address dials out at most once per window (window 10min >=
    // RENDEZVOUS_ASK_BACKOFF 60s, the same scale as the trigger surface's
    // backoff).
    if !dedup.admit(ep, now) {
        debug!(target: "taiji::core::engine", %ep,
            "punch dial skipped: dial dedup window");
        return false;
    }
    true
}

/// Punch dial: the connect(ep) command -> the regular outbound dial path
/// (handshake -> attach -> swarm registration, converging naturally with
/// ad-aware dispatch).
fn punch_dial(
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
    fi: usize,
    ep: SocketAddr,
    actual_port: u16,
) {
    if !punch_dial_admit(
        &state.ban_book.guard,
        &state.faces[fi],
        &mut state.dht_dial_dedup,
        ep,
        actual_port,
        Instant::now(),
    ) {
        return;
    }
    debug!(target: "taiji::core::engine", face = fi, %ep,
        "punch dial (ut_holepunch connect)");
    // Observation family: all gates passed = a real outbound attempt
    // (blocked attempts do not count).
    HP_PUNCH_DIALS.fetch_add(1, Ordering::Relaxed);
    spawn_peer_dial(
        state,
        dial,
        token,
        fi,
        ep,
        // The punch source bypasses the silent-ledger gate (the
        // introducer asserts reachability = fresh external evidence, see
        // state::DialSource docs); the outcome is still recorded.
        super::state::DialSource::Punch,
        state.seeding_sources[fi].clone(),
        state.seeding_hash_sources[fi].clone(),
    );
}

/// Trigger surface: dial plan exhausted (a real direct-connect failure)
/// -> failure bookkeeping -> introducer + backoff decision -> send
/// rendezvous to the introducer. The same report streams into the silent
/// ledger: success = fresh evidence resetting the count (peer revived);
/// silent failure = escalating consecutive count (backoff/cool-down);
/// non-silent failure (definitively unreachable) neither touches the
/// ledger nor resets it (continuity preserved).
pub(super) fn handle_hp_dial_report(report: HpDialReport, state: &mut EngineLoop) {
    // Dial-outcome observation window feed (every receipt enters the
    // window, classified by connected — the decision input for
    // connect_speed environment adaptation, see `run::ecology::
    // DialOutcomeWindow` for the window/denominator discipline). Read at
    // the drain round (250ms cadence); write-only here — the main loop is
    // the sole writer.
    state.dial_outcomes.note(report.connected, Instant::now());
    // Dead-address window feed: a failed dial extends the
    // address's dedup window (30min) so re-supplies of the same dead
    // endpoint are skipped instead of re-dialed; a success clears the
    // mark. Orthogonal to the silent ledger (which covers the silent
    // classification with its own backoff): this covers *all* failure
    // classes — connect-refused/timeout (definitely unreachable) had no
    // outcome memory at all before.
    if report.connected {
        state.dht_dial_dedup.note_connected(&report.addr);
        // Observation family: punch-source dial handshake success
        // (single-source feed; the punch criterion is the dial-source
        // mark, independent of BH_HOLEPUNCH_MODE — with the fallback mode
        // on, punch dials take the regular plan and still count).
        if report.punch {
            HP_PUNCH_ESTABLISHED.fetch_add(1, Ordering::Relaxed);
        }
        state.hp_book.note_dial_connected(&report.addr);
        state.silent_book.note_connected(&report.addr);
        return;
    }
    state.dht_dial_dedup.note_failed(&report.addr);
    let now = Instant::now();
    if report.silent {
        state.silent_book.note_silent(report.addr, now);
        // Failed-candidate re-queue: a discovery-source silent failure
        // re-enters the candidate table, with the retry cadence carried
        // by the silent backoff curve (120/240s in-table waiting room —
        // the drain round's `admit` skips Backoff and releases on expiry;
        // the 3rd failure enters cool-down and does not re-queue, 1800s
        // cool-down semantics unchanged). Decision shape and the
        // three-arm exclusion:
        // [`super::ecology::repush_on_silent_failure`]. The re-queued
        // rank uses the Dht facet: the sort key last_connected (the dedup
        // admit time, non-None) already ranks re-queued entries after
        // every never-dialed candidate, so the rank only tiebreaks
        // between two re-queued entries — no behavioral surface. Fallback
        // knob BH_CONN_FILL_RETRY=0 -> the decision is always false
        // (current behavior: re-entry is driven only by discovery-source
        // resupply).
        let verdict = state.silent_book.admit(&report.addr, now);
        if super::ecology::repush_on_silent_failure(
            report.discovery,
            super::ecology::conn_fill_retry_enabled(),
            verdict,
        ) {
            super::ecology::push_candidate(
                state,
                report.addr,
                report.face,
                super::ecology::DialSourceRank::Dht,
                now,
            );
        }
    }
    state.hp_book.note_dial_failed(report.addr, now);
    let Some(relay_cuid) = state.hp_book.rendezvous_target(&report.addr, now) else {
        // Observation family: no introducer (the failed address has no
        // PEX delivery record / backoff not elapsed / TTL expired — the
        // denominator paired with hits for the punchability rate).
        HP_NO_INTRODUCER.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // Observation family: introducer hit (a live PEX introducer exists
    // and the backoff has elapsed).
    HP_INTRODUCER_HITS.fetch_add(1, Ordering::Relaxed);
    // The introducer must be a live connection that negotiated
    // ut_holepunch (find_introducer, `torrent.cpp`; the
    // supports_holepunch gate).
    let Some((handle, supports)) = state.faces.iter().find_map(|f| {
        let h = handle_for_cuid(f, relay_cuid)?;
        Some((h.clone(), h.supports_holepunch()))
    }) else {
        debug!(target: "taiji::core::engine", cuid = relay_cuid,
            "introducer gone: rendezvous skipped");
        return;
    };
    if !supports {
        debug!(target: "taiji::core::engine", cuid = relay_cuid,
            "introducer without holepunch negotiation: rendezvous skipped");
        return;
    }
    debug!(target: "taiji::core::engine", target = %report.addr,
        introducer = relay_cuid, "sending rendezvous to introducer");
    // Observation family: rendezvous sent (feed = the send point; no
    // receipt accounting).
    HP_RENDEZVOUS_SENT.fetch_add(1, Ordering::Relaxed);
    let _ = handle.command(PeerCommand::SendHolepunch(UtHolepunch::Rendezvous {
        ep: report.addr,
    }));
}

/// (ip, port) -> (face, cuid) connection-table lookup (find_peer
/// isomorphism). Hits are scoped to the requester's face `fi` —
/// libtorrent find_peer is torrent-scoped
/// (`associated_torrent()->find_peer(ep)`, `bt_peer_connection.cpp`);
/// cross-face hits are never returned (for the requester's face that
/// means not connected, handled as failed(not_connected): never confirm
/// a connection's existence on another face, never induce a dial there).
fn find_connection_by_ep(faces: &[FaceState], fi: usize, ep: SocketAddr) -> Option<(usize, u64)> {
    let face = faces.get(fi)?;
    face.peer_state
        .iter()
        .find(|(_, ps)| {
            ps.meta
                .as_ref()
                .is_some_and(|m| m.ip == ep.ip() && m.port == ep.port())
        })
        .map(|(cuid, _)| (fi, *cuid))
}

/// cuid -> connection handle (parallel-order lookup over the face's
/// peers/peer_cuids).
fn handle_for_cuid(face: &FaceState, cuid: u64) -> Option<&PeerTaskHandle> {
    face.peer_cuids
        .iter()
        .position(|&c| c == cuid)
        .and_then(|i| face.peers.get(i))
}

/// Relay rejection reply (a failed frame; a dead requester connection =
/// silent).
fn reply_failed(handle: Option<&PeerTaskHandle>, ep: SocketAddr, error: HpError) {
    if let Some(h) = handle {
        let _ = h.command(PeerCommand::SendHolepunch(UtHolepunch::Failed {
            ep,
            error,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Explicit mode construction (test determinism: no drift with the
    // environment fallback knob).
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::time::Duration;

    use taiji_bt::choke::{LeecherChoke, SeederChoke};
    use taiji_bt::mse::CryptoLevel;
    use taiji_bt::peer_policy::FilterRule;
    use taiji_bt::peer_wire::Reserved;
    use taiji_bt::piece_id::Addressing;
    use taiji_bt::piece_stat::PieceStatMan;
    use taiji_bt::utp::Transport;

    use taiji_store::merkle;

    use tokio::sync::mpsc;

    use crate::bitmap::PieceBitmap;
    use crate::config::FaceKind;
    use crate::dht::DHT_DIAL_DEDUP_WINDOW;
    use crate::faces::{FaceView, PeerMeta, PexCandidates, SwarmSnapshot};
    use crate::pipeline::DataFlushState;
    use crate::tracker::TrackerMirror;
    use crate::transit::UtpDial;
    use taiji_bt::choke::{ChokeMode, SeedingPolicy};
    use taiji_domain::progress::ProgressModel;

    /// DialCtx test assembly (toggle adjustable; channels are
    /// disconnected — this test group only inspects the attach
    /// resolution, no delivery).
    fn dial_ctx(hp_enabled: bool) -> DialCtx {
        let (reg_tx, _r1) = mpsc::channel(1);
        let (leave_tx, _r2) = mpsc::channel(1);
        let (violation_tx, _r3) = mpsc::channel(1);
        let (redial_tx, _r4) = mpsc::channel(1);
        let (hp_tx, _r5) = mpsc::channel(1);
        let (hp_report_tx, _r6) = mpsc::channel(1);
        let (ledger_tx, _r7) = mpsc::channel(1);
        DialCtx {
            peer_id: [0u8; 20],
            crypto: taiji_bt::mse::CryptoPolicy::optional(),
            conn_type: taiji_bt::utp::PeerConnectionType::default(),
            ext: taiji_bt::peer::ExtConfig::default(),
            limiter: None,
            attach_dht: crate::dht::AttachDhtSlot::default(),
            utp_dial: UtpDial::default(),
            reg_tx,
            leave_tx,
            violation_tx,
            redial_tx,
            holepunch: Some(taiji_bt::peer::HolepunchExt { tx: hp_tx }),
            hp_enabled: Arc::new(std::sync::atomic::AtomicBool::new(hp_enabled)),
            hp_report_tx,
            avail_tx_face: Vec::new(),
            ledger_tx,
            client_deny: None,
        }
    }

    /// Toggle table test: attach resolution = channel present AND the
    /// runtime switch on. The engine default is true (the assemble
    /// literal); SetHolepunch flips this bit.
    #[test]
    fn holepunch_attach_gate_table() {
        // Default (true) -> wiring present.
        assert!(dial_ctx(true).holepunch_attach().is_some());
        // Off -> None (new connections neither advertise nor consume).
        assert!(dial_ctx(false).holepunch_attach().is_none());
        // Runtime flip symmetry: the same ctx flips and the resolution
        // follows (the EngineCommand atom is this Arc).
        let ctx = dial_ctx(true);
        ctx.hp_enabled
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(ctx.holepunch_attach().is_none());
        ctx.hp_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(ctx.holepunch_attach().is_some());
    }

    // ===== Regression tests =====

    /// Minimal FaceState (v1, zero pieces, no connections; only the
    /// bookkeeping consumed by the relay/dial gates is assembled).
    fn hp_face() -> FaceState {
        let (block_tx, _rx) = mpsc::channel(1);
        let (fetch_tx, _frx) = mpsc::channel(1);
        // Terminal barrier seam: the fixture has no pipeline peer — no
        // consumer on the trigger side, the barrier stays Pending (the
        // terminal-row wait surface is not on the fixture's consumption
        // path).
        let (final_flush_tx, _final_flush_rx) = mpsc::channel::<()>(1);
        let (_data_flush_gate, data_flush_gate) =
            tokio::sync::watch::channel(DataFlushState::Pending);
        FaceState {
            kind: FaceKind::V1,
            info_hash: [0u8; 20],
            reserved: Reserved::aria2_default(),
            addressing: Addressing::Flat,
            piece_bytes: Vec::new().into(),
            piece_goffs: Arc::new(Vec::new()),
            progress: ProgressModel::from_lengths(&[0], merkle::BLOCK_SIZE),
            piece_count: 0,
            verified_count: 0,
            stat_man: PieceStatMan::new(0, &mut |_| 0),
            peer_avail: std::collections::HashMap::new(),
            peer_seeds: std::collections::HashSet::new(),
            peers: Vec::new(),
            peer_cuids: Vec::new(),
            // Per-peer tables merged into one.
            peer_state: std::collections::HashMap::new(),
            block_senders: Arc::new(Mutex::new(std::collections::HashMap::new())),
            choke: SeederChoke::with(ChokeMode::Libtorrent, SeedingPolicy::FastestUpload),
            leecher_choke: LeecherChoke::with_mode(ChokeMode::Libtorrent),
            regular_unchoked: std::collections::HashSet::new(),
            download_source: None,
            written_bits: Arc::new(PieceBitmap::new(0)),
            // Isomorphic to progress (production clones it after restore;
            // the two bitmaps diverge from here).
            written_progress: ProgressModel::from_lengths(&[0], merkle::BLOCK_SIZE),
            written_count: 0,
            selected_written_count: 0,
            completed: false,
            hash_files: None,
            swarm: FaceView(Arc::new(Mutex::new(SwarmSnapshot {
                total: 0,
                completed: 0,
                all_finished: false,
                peers: 0,
                uploaded: 0,
                downloaded: 0,
            }))),
            mirror: TrackerMirror::new(&[], ""),
            block_cursor: 0,
            block_tx,
            trees: None,
            flat_coords: Arc::new(Vec::new()),
            layers: Vec::new(),
            fetch_tx,
            refetch: Vec::new(),
            dispatch_replies: Vec::new(),
            // Dispatch-round scratch pool starts resident.
            dispatch_scratch: Default::default(),
            endgame_live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            endgame_edge: None,
            endgame_cum: Duration::ZERO,
            last_mile_edge: None,
            last_mile_final: None,
            last8_edge: None,
            last8_final: None,
            endgame_deadline: std::collections::HashMap::new(),
            write_adjacent: 0,
            write_isolated: 0,
            blocks_sent: std::collections::HashMap::new(),
            parole_peers: std::collections::HashSet::new(),
            block_arena: None,
            block_inflight: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pex_candidates: PexCandidates::default(),
            read_pool: None,
            final_flush_tx,
            data_flush_gate,
            // Snapshot barrier surface: dirty flag starts false; the cell
            // stays empty (the consumer is not on the fixture's path).
            dirty_since_snapshot: false,
            snapshot_sync: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// Connection metadata (relay_introduce's requester mapped address /
    /// the face-scoped find input).
    fn hp_meta(addr: SocketAddr) -> PeerMeta {
        PeerMeta {
            ip: addr.ip(),
            port: addr.port(),
            inbound: false,
            peer_id: [0u8; 20],
            crypto: CryptoLevel::Plain,
            transport: Transport::Tcp,
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            upload_only: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A real PeerTask (duplex carrier): the handle registers into the
    /// face bookkeeping; `remote` is the test-side observation/injection
    /// point (read frames the task emits / inject a peer handshake).
    async fn hp_peer(root: &CancellationToken) -> (PeerTaskHandle, tokio::io::DuplexStream) {
        let (local, remote) = tokio::io::duplex(64 * 1024);
        let (handle, _join, _data) =
            taiji_bt::peer::PeerTask::spawn(root, local, taiji_bt::peer::PeerConfig::flat());
        (handle, remote)
    }

    /// Inject a peer ext handshake (the m.ut_holepunch advertisement):
    /// sets the negotiation mirror + registers the outbound id — the
    /// relay eligibility check and the SendHolepunch consumption surface
    /// (BEP 10). Polls the mirror until set (PeerTask processes frames
    /// asynchronously).
    async fn inject_holepunch_handshake(
        remote: &mut tokio::io::DuplexStream,
        handle: &PeerTaskHandle,
    ) {
        use tokio::io::AsyncWriteExt as _;
        let hs = taiji_bt::peer_wire::ExtHandshake {
            m_ut_holepunch: Some(taiji_bt::holepunch::OUTBOUND_UT_HOLEPUNCH_ID),
            ..taiji_bt::peer_wire::ExtHandshake::default()
        };
        let payload = hs.encode().unwrap_or_else(|e| panic!("{e}"));
        let frame = taiji_bt::peer_wire::Message::Extended { ext_id: 0, payload }.encode();
        remote
            .write_all(&frame)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !handle.supports_holepunch() {
            assert!(
                Instant::now() < deadline,
                "peer task did not process ext handshake"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Read one ut_holepunch message (ext frame -> payload decode;
    /// silence within the window = None).
    async fn read_holepunch(
        remote: &mut tokio::io::DuplexStream,
        wait: Duration,
    ) -> Option<UtHolepunch> {
        use tokio::io::AsyncReadExt as _;
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(wait, remote.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => return None,
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len < 2 {
            return None;
        }
        let mut body = vec![0u8; len];
        tokio::time::timeout(wait, remote.read_exact(&mut body))
            .await
            .ok()?
            .ok()?;
        // [msg id = Extended(20)][ext id][ut_holepunch payload].
        if body[0] != 20 {
            return None;
        }
        UtHolepunch::decode(&body[2..]).ok()
    }

    fn test_addr(s: &str) -> SocketAddr {
        s.parse()
            .unwrap_or_else(|e| panic!("bad test addr {s}: {e}"))
    }

    /// Regression (cross-face probe): a cross-face rendezvous must not
    /// become an existence probe. An attacker connects on torrent X
    /// (face 0) and probes an (ip,port) that is exactly our connection on
    /// torrent Y (face 1); with the face-scoped lookup the reply is
    /// always failed(not_connected) — indistinguishable from "target does
    /// not exist", closing the probe — and never no_support/introduce
    /// (both would confirm the connection exists).
    #[tokio::test]
    async fn rendezvous_cross_face_probe_answers_not_connected() {
        let root = CancellationToken::new();
        let mut faces = vec![hp_face(), hp_face()];
        let (attacker, mut a_remote) = hp_peer(&root).await;
        let (victim, mut v_remote) = hp_peer(&root).await;
        inject_holepunch_handshake(&mut a_remote, &attacker).await;
        inject_holepunch_handshake(&mut v_remote, &victim).await;
        let victim_ep = test_addr("203.0.113.9:6881");
        // Attacker registers on face 0; the victim connection sits on
        // face 1 (exact match on the same ep — the cross-face probe).
        faces[0].peer_cuids.push(1);
        faces[0].peers.push(attacker);
        faces[0].peer_state_row(1).meta = Some(hp_meta(test_addr("203.0.113.1:40000")));
        faces[1].peer_cuids.push(2);
        faces[1].peers.push(victim);
        faces[1].peer_state_row(2).meta = Some(hp_meta(victim_ep));
        relay_introduce(&faces, 0, 1, victim_ep);
        let reply = read_holepunch(&mut a_remote, Duration::from_millis(500))
            .await
            .unwrap_or_else(|| panic!("requester must get a failed reply"));
        assert_eq!(
            reply,
            UtHolepunch::Failed {
                ep: victim_ep,
                error: HpError::NotConnected
            },
            "cross-face probe = same shape as nonexistent (no_support/introduce both confirm existence)"
        );
        // A cross-face probe must not disturb the face 1 connection (no
        // commands sent at all).
        assert!(
            read_holepunch(&mut v_remote, Duration::from_millis(200))
                .await
                .is_none(),
            "cross-face probe must not touch the other face"
        );
        root.cancel();
    }

    /// Regression (cross-face induction): the target of a cross-face
    /// rendezvous must never receive connect(requester's mapped address)
    /// — that command would make the victim connection dial the attacker
    /// under its own face's infohash (torrent Y), leaking identity at
    /// handshake.
    #[tokio::test]
    async fn rendezvous_cross_face_target_never_induced() {
        let root = CancellationToken::new();
        let mut faces = vec![hp_face(), hp_face()];
        let (attacker, mut a_remote) = hp_peer(&root).await;
        let (victim, mut v_remote) = hp_peer(&root).await;
        inject_holepunch_handshake(&mut a_remote, &attacker).await;
        inject_holepunch_handshake(&mut v_remote, &victim).await;
        let victim_ep = test_addr("203.0.113.9:6881");
        faces[0].peer_cuids.push(1);
        faces[0].peers.push(attacker);
        faces[0].peer_state_row(1).meta = Some(hp_meta(test_addr("203.0.113.1:40000")));
        faces[1].peer_cuids.push(2);
        faces[1].peers.push(victim);
        faces[1].peer_state_row(2).meta = Some(hp_meta(victim_ep));
        relay_introduce(&faces, 0, 1, victim_ep);
        // The induction chain is severed: the victim connection receives
        // zero commands (no infohash/identity leak).
        assert!(
            read_holepunch(&mut v_remote, Duration::from_millis(300))
                .await
                .is_none(),
            "cross-face induce must not reach the victim connection"
        );
        root.cancel();
    }

    /// Same-face introduction positive control (the fix must not break
    /// legitimate holepunching): both parties on one face negotiated
    /// ut_holepunch -> the two connect payloads asserted one by one.
    #[tokio::test]
    async fn rendezvous_same_face_still_introduces_both() {
        let root = CancellationToken::new();
        let mut faces = vec![hp_face()];
        let (attacker, mut a_remote) = hp_peer(&root).await;
        let (victim, mut v_remote) = hp_peer(&root).await;
        inject_holepunch_handshake(&mut a_remote, &attacker).await;
        inject_holepunch_handshake(&mut v_remote, &victim).await;
        let requester_addr = test_addr("203.0.113.1:40000");
        let victim_ep = test_addr("203.0.113.9:6881");
        faces[0].peer_cuids.push(1);
        faces[0].peers.push(attacker);
        faces[0].peer_state_row(1).meta = Some(hp_meta(requester_addr));
        faces[0].peer_cuids.push(2);
        faces[0].peers.push(victim);
        faces[0].peer_state_row(2).meta = Some(hp_meta(victim_ep));
        relay_introduce(&faces, 0, 1, victim_ep);
        // The requester receives connect(target ep).
        let to_requester = read_holepunch(&mut a_remote, Duration::from_millis(500))
            .await
            .unwrap_or_else(|| panic!("requester must get connect(target)"));
        assert_eq!(to_requester, UtHolepunch::Connect { ep: victim_ep });
        // The target receives connect(requester's mapped address).
        let to_target = read_holepunch(&mut v_remote, Duration::from_millis(500))
            .await
            .unwrap_or_else(|| panic!("target must get connect(requester)"));
        assert_eq!(to_target, UtHolepunch::Connect { ep: requester_addr });
        // Observation family: the Introduce action counts exactly once
        // (single-source feed — two connect payloads count as one
        // introduction).
        assert_eq!(
            HP_RELAYED_CONNECTS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "introduce arm must feed relayed_connects exactly once"
        );
        root.cancel();
    }

    /// Observation delta pure function: `delta_since` saturating
    /// subtraction — read-order rollback counts as zero (the tick bridge
    /// surface, same as the two-phase bridge); normal monotonic
    /// increments checked field by field.
    #[test]
    fn holepunch_obs_delta_saturates() {
        let prev = HolepunchObs {
            rendezvous_sent: 3,
            relayed_connects: 2,
            punch_dials: 5,
            punch_established: 1,
            introducer_hits: 4,
            no_introducer: 10,
            punch_failed_nat: 2,
        };
        // Monotonic increments: per-field deltas.
        let now = HolepunchObs {
            rendezvous_sent: 4,
            relayed_connects: 2,
            punch_dials: 8,
            punch_established: 3,
            introducer_hits: 4,
            no_introducer: 12,
            punch_failed_nat: 2,
        };
        let d = now.delta_since(&prev);
        assert_eq!(d.rendezvous_sent, 1);
        assert_eq!(d.relayed_connects, 0);
        assert_eq!(d.punch_dials, 3);
        assert_eq!(d.punch_established, 2);
        assert_eq!(d.introducer_hits, 0);
        assert_eq!(d.no_introducer, 2);
        assert_eq!(d.punch_failed_nat, 0);
        // Rollback (multi-engine process read order is not an atomic
        // snapshot): saturates to 0, never wraps.
        let rolled = HolepunchObs::default();
        let d = rolled.delta_since(&prev);
        assert_eq!(
            (d.rendezvous_sent, d.punch_dials, d.no_introducer),
            (0, 0, 0),
            "counter rollback must saturate to zero"
        );
    }

    /// connect outbound-dial admission gates, table-driven — per-gate
    /// assertions for self-connect / IpGuard / already-connected-by-IP on
    /// this face / the dedup window; the dedup window shares one table
    /// with the DHT/PEX sources (one side registers, the other is also
    /// refused within the same window = rate sharing).
    #[test]
    fn punch_dial_admit_gates_table() {
        let t0 = Instant::now();
        let actual_port = 6881;
        let normal = test_addr("203.0.113.10:6881");
        // IpGuard deny range (static rule; other addresses pass).
        use taiji_bt::peer_policy::{IpGuard, RuleAction};
        let guard = IpGuardHandle::new(IpGuard::new(
            [FilterRule {
                action: RuleAction::Deny,
                start: IpAddr::from([203, 0, 113, 200]),
                end: IpAddr::from([203, 0, 113, 255]),
            }],
            [],
        ));
        let mut face = hp_face();
        let mut dedup = DialDedup::new();

        // Gate 1: self-connect (loopback + our announce port) -> refuse;
        // the dedup table does not record.
        assert!(!punch_dial_admit(
            &guard,
            &face,
            &mut dedup,
            test_addr("127.0.0.1:6881"),
            actual_port,
            t0,
        ));
        assert!(!dedup.0.contains_key(&test_addr("127.0.0.1:6881")));

        // Gate 2: IpGuard hit -> refuse.
        assert!(!punch_dial_admit(
            &guard,
            &face,
            &mut dedup,
            test_addr("203.0.113.201:6881"),
            actual_port,
            t0,
        ));

        // Gate 3: already connected to the same IP on this face ->
        // refuse.
        face.peer_state_row(7).ip = Some(normal.ip());
        assert!(!punch_dial_admit(
            &guard,
            &face,
            &mut dedup,
            normal,
            actual_port,
            t0,
        ));
        face.peer_state.clear();

        // Gate 4: a fresh address -> admit and record in the dedup window
        // (connection in face, guard shared — the same pre-spawn
        // accounting as the DHT/PEX arms).
        assert!(punch_dial_admit(
            &guard,
            &face,
            &mut dedup,
            normal,
            actual_port,
            t0,
        ));
        assert!(dedup.0.contains_key(&normal));

        // Gate 5: a repeated connect for the same address within the
        // window -> refuse (N colluding peers each sending one command
        // per 4/60s no longer buy a full outbound dial each).
        assert!(!punch_dial_admit(
            &guard,
            &face,
            &mut dedup,
            normal,
            actual_port,
            t0 + Duration::from_secs(60),
        ));

        // Gate 6 (rate sharing): an address registered by punch also
        // constrains the discovery surface — the DHT arm's identical
        // admit returns false for it within the window.
        assert!(!dedup.admit(normal, t0 + Duration::from_secs(120)));
        // Mirror direction: DHT/PEX registers first, the punch gate
        // refuses within the same window.
        let other = test_addr("203.0.113.11:6881");
        assert!(dedup.admit(other, t0));
        assert!(!punch_dial_admit(
            &guard,
            &face,
            &mut dedup,
            other,
            actual_port,
            t0 + Duration::from_secs(30),
        ));

        // Gate 7: after the window expires (DHT_DIAL_DEDUP_WINDOW =
        // 10min) the same address is admitted again.
        assert!(punch_dial_admit(
            &guard,
            &face,
            &mut dedup,
            normal,
            actual_port,
            t0 + DHT_DIAL_DEDUP_WINDOW,
        ));
    }
}

//! Download-engine main loop: the `run()` skeleton (assembly call ->
//! main `tokio::select!` loop -> teardown) and the `DownloadEngine`
//! spawn face. Assembly / main-loop arm bodies / teardown are extracted
//! into sibling submodules (assemble/state/arms/dial/tick/tail); the
//! select! expressions (arm order, arm set, per-arm future
//! expressions) are kept verbatim — zero behaviour change.
//!
//! Scope: orchestration and lifecycle of the module wiring. Out of
//! scope: decision logic that can stand alone (see the sibling
//! modules).

pub(super) mod arms;
mod assemble;
pub(super) mod dial;
// Connection ecology governance: dial throttling / candidate table /
// turnover — wired at the drain arm and the seed tick feed points.
mod ecology;
pub(super) mod holepunch;
/// pub(super): the gate-promotion activation chain
/// (`activate_recovered_file` and friends) is served through the engine
/// namespace as the test assembly face (the recovery_tests three-gate
/// table reuses it).
pub(super) mod recovery_admit;
// Stall detection valve (the detection/action face; the rotation pure
// functions are pub(crate) for the engine tests' table-driven suites).
mod stall;
mod state;
mod tail;
mod tick;

// Connection admission gate pure-decision face: served through the
// engine namespace as the test assembly face (the tests' admission
// table; the runtime face goes through EngineLoop::admission_open).
// PEER_CONNECTIONS_MAX is re-exported unconditionally: the pipeline
// write-cache sizing `2 x hard cap x piece_len` aggregate in-flight
// demand anchor needs the module path visible through this namespace.
// Sizing and turnover consume the runtime override seam
// `peer_connections_max` (BH_PEER_MAX; env unset = the default constant
// 120); `admission_verdict_limits` lets tests pin the fallback values
// (51/64) directly.
pub(crate) use state::peer_connections_max;
// The tracker numwant gate consumes the same outbound-target reading
// (faces.rs `tracker_min_peers` — the gate default = the target;
// pipeline.rs consumes the max the same way).
pub(crate) use state::peer_connections_target;
#[cfg(test)]
pub(crate) use state::{
    PEER_CONNECTIONS_MAX, PEER_CONNECTIONS_TARGET, admission_verdict, admission_verdict_limits,
};

// Stall-valve pure functions: served through the engine namespace as
// the test assembly face (the tests' state-machine/rotation tables; the
// runtime face goes through the seed tick feed point stall_valve_tick).
#[cfg(test)]
pub(crate) use stall::{
    PeerStallRow, SEEDER_ROTATE_BATCH, SEEDER_ROTATE_IDLE_SECS, STALL_ACTION_PERIOD,
    STALL_DETECT_SECS, StallValve, rotation_pick, stall_valve_advance,
};

// µTP zero-throughput governance pure functions/constants: served
// through the engine namespace as the test assembly face (the stall.rs
// shape; the runtime face goes through the seed tick feed point
// utp_mute_tick).
#[cfg(test)]
pub(crate) use ecology::{UTP_MUTE_AFTER, utp_mute_face};

// Slow-peer eviction direct-drive face: served through the engine
// namespace as the test assembly face (the utp_mute shape; the runtime
// face goes through the seed tick feed point slow_peer_churn_tick, the
// decision core's tables embedded in ecology::tests).
#[cfg(test)]
pub(crate) use ecology::{SlowChurnParams, slow_churn_faces};

// Connection ecology governance: the pure-function decision tables live
// in ecology::tests (same-file `use super::*` direct drive); the
// runtime face is wired through the 250ms drain arm (run()) and the
// seed tick feed point turnover_tick (tick.rs); no cross-module test
// consumers.

use std::ops::ControlFlow;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use taiji_bt::peer::PeerHandle as _;
use taiji_bt::utp::PeerConnectionType;

use tokio::sync::mpsc;

use tokio_util::sync::CancellationToken;

use tracing::{debug, info, warn};

use crate::command::{EngineCommand, EngineHandle, engine_command_recv};
use crate::config::{EngineConfig, TrackerWireConfig};
use crate::faces::recheck_face_completion;
use crate::pipeline::BLOCK_CHANNEL_CAPACITY;
use crate::progress::EngineEnd;
use arms::{
    DhtRuntime, check_resume_complete, flush_dispatch_debt, handle_dispatch_arrival,
    handle_engine_command, handle_hash_fetch, handle_peer_avail, handle_peer_left,
    handle_peer_registered, handle_store_progress,
};
use assemble::{AssembledEngine, assemble_engine};
use dial::{
    handle_dht_event, handle_dht_port, handle_inbound_tcp, handle_inbound_utp, handle_pex_event,
    handle_redial_report, handle_redial_sweep, handle_tracker_event, handle_violation,
};
use holepunch::{handle_holepunch_event, handle_hp_dial_report};
use tail::{dht_halt_save, drive_stopped_sequence, final_flush};
use tick::{handle_choke_round, handle_seed_tick, handle_slow_tick};

/// µTP accept merge channel capacity (aligned with the frozen accept
/// queue value 64 — after the v4/v6 dual-listener merge the same policy
/// applies: a full queue drops the SYN and peer retransmission
/// recovers).
pub(super) const UTP_ACCEPT_MERGE_CAPACITY: usize = 64;
/// TCP accept merge channel capacity: aligned with the µTP merge
/// channel in size and semantics ([`UTP_ACCEPT_MERGE_CAPACITY`], same
/// value — the merged v4/v6 dual TcpListeners feed one main-loop arm).
/// When full, the merge task awaits (backpressure) and stops accepting
/// (µTP: the dropped SYN is recovered by peer retransmission; TCP is
/// lossless and bursts are absorbed by the kernel listen backlog — each
/// semantics holds on its own).
pub(super) const TCP_ACCEPT_MERGE_CAPACITY: usize = UTP_ACCEPT_MERGE_CAPACITY;
/// Retry backoff after a single TCP accept error (not a protocol
/// constant — a per-connection accept error such as fd exhaustion
/// (EMFILE) returns ready immediately; without a backoff the merge task
/// would hot-spin, unlike the main loop's existing "accept Err retries
/// via select" behaviour, hence the sleep pacing).
const TCP_ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// µTP outbound dial request channel capacity (dialing is
/// low-frequency, announce/DHT-period driven; full = the dial task
/// awaits under backpressure). The awaited send is additionally bounded
/// by the [`UtpDial::connect`](crate::transit::UtpDial::connect)
/// overall budget (BH_UTP_DIAL_TIMEOUT_SECS, default 10s) — a stalled
/// consumer leaves the pending dial bounded instead of hanging forever.
pub(super) const UTP_DIAL_QUEUE_CAPACITY: usize = 64;
/// Block-arrival event channel capacity: 4 x [`BLOCK_CHANNEL_CAPACITY`]
/// (256, pipeline.rs) — arrival events accompany block data from the
/// same source (at most one per successful `block_tx.send`); depth 4
/// keeps the normal supply flow at zero degradation; full = try_send
/// drops and the entry stays InFlight (bounded discipline: the forward
/// task is never blocked; the main loop re-dispatches per the current
/// behaviour and converges — self-healing).
pub(super) const LEDGER_CHANNEL_CAPACITY: usize = 4 * BLOCK_CHANNEL_CAPACITY;
/// BT listen-port bind fallback window width = the 119 ports of the
/// aria2 default range 6881-6999 (`BtSetup.cc` `PREF_LISTEN_PORT`
/// default parsing).
pub(super) const LISTEN_PORT_FALLBACK_WIDTH: u16 = 118;

/// TCP dual-stack listener set: v4 = the main stack (always present;
/// bind failure walks the port-window fallback); v6 = best effort
/// (after the [`bind_tcp_v6_only`] V6ONLY prerequisite it coexists with
/// v4 on the same port; None = the v6 bind failed and the stack
/// degrades to v4-only — no v6 kernel/address or a taken port, all
/// common environments).
pub(super) struct DualStackListener {
    v4: tokio::net::TcpListener,
    v6: Option<tokio::net::TcpListener>,
}

/// IPv6 listen socket creation (a safe socket2 wrapper — std has no
/// sockopt face and the workspace forbids unsafe; precedents: the
/// bt/src/lsd.rs multicast socket, the io/src/udp_demux.rs v6 UDP
/// creation). `IPV6_V6ONLY` **must be set before bind** (socket2
/// `set_only_v6` docs; setting it after bind does not change the
/// port-occupancy semantics at bind time): Linux ipv6(7) `bindv6only`
/// defaults to 0, so a bare `[::]` yields a dual-stack socket that
/// excludes `0.0.0.0` on the same port (the second bind EADDRINUSEs,
/// and std has no sockopt face to work around it); with V6ONLY=1 both
/// families bind into independent buckets and coexist on one port.
/// macOS/Windows default to 1; setting it explicitly here does not rely
/// on OS defaults (the two families' defaults differ — no luck-based
/// dual-stack). Upstream anchor: aria2 `SocketCore.cc` (an AF_INET6
/// socket gets `IPV6_V6ONLY=1` before `::bind`, the same-origin
/// scope).
///
/// Returns a std socket (`IPV6_V6ONLY` can be asserted directly via
/// `socket2::SockRef`, the same test scope as io::udp_demux; the caller
/// converts to tokio with `from_std`).
/// socket/setsockopt/bind/listen are all non-blocking syscalls (no data
/// waits, no "blocking operation" boundary, the same scope as
/// io::udp_demux::bind_v6_std).
fn bind_tcp_v6_only(port: u16) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    s.set_only_v6(true)?;
    // Aligned with std::net::TcpListener::bind (tokio's bind is a thin
    // wrapper over std): std sets SO_REUSEADDR before bind on
    // non-Windows and omits it on Windows (the port-hijack exposure) —
    // the v6 side matches, so TIME_WAIT leftovers cannot make the two
    // families' rebind success asymmetric (v4 rebinds while v6 hits
    // EADDRINUSE -> a silent single-stack degradation).
    #[cfg(not(windows))]
    s.set_reuse_address(true)?;
    s.bind(&SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port).into())?;
    // backlog 128 = the std::net::TcpListener::bind value (aligned).
    s.listen(128)?;
    // tokio `from_std` precondition: non-blocking mode (otherwise IO
    // blocks a runtime thread).
    s.set_nonblocking(true)?;
    Ok(s.into())
}

/// TCP listen bind (dual stack): same-port v4 (`0.0.0.0`, main stack) +
/// v6 (`[::]`, V6ONLY first, see [`bind_tcp_v6_only`]). `port = 0` is a
/// single attempt (an OS ephemeral port); non-zero retries each port
/// ascending up to +[`LISTEN_PORT_FALLBACK_WIDTH`] (the aria2
/// `BtSetup.cc` + `PeerListenCommand.cc` range walk). Same-port rule:
/// a v4 failure defers both stacks to the next candidate port (no
/// v6-only port is kept); a v6 failure (no v6 kernel/address, port
/// taken — common) degrades to a v4-only stack without walking back.
/// All failing = None (outbound-only degradation). The returned port is
/// the single announce/LSD/DHT-PORT reference (actual_port; this
/// function does not change its semantics — the v4 main stack's
/// local_addr).
pub(super) async fn bind_listen_with_fallback(
    port: u16,
    token: &CancellationToken,
) -> Option<(DualStackListener, u16)> {
    let last = port.saturating_add(if port == 0 {
        0
    } else {
        LISTEN_PORT_FALLBACK_WIDTH
    });
    for candidate in port..=last {
        if candidate != port {
            debug!(target: "taiji::core::engine", port = candidate,
                "listen port taken, trying next (aria2 listen-port range semantics)");
        }
        // Shutdown race: once the token is cancelled no new port is
        // bound (zero side effects on the teardown path).
        if token.is_cancelled() {
            return None;
        }
        // v4 main-stack anchor: a bind failure walks the window (the
        // next candidate defers both stacks — no v6-only port is left
        // on a port where v4 is not ready).
        let v4 = match tokio::net::TcpListener::bind(("0.0.0.0", candidate)).await {
            Ok(l) => l,
            Err(e) if candidate == last => {
                warn!(target: "taiji::core::engine", %e, port = candidate,
                    "listen failed across port window (outbound only)");
                return None;
            }
            Err(_) => continue,
        };
        // actual_port source: the v4 main stack's local_addr (the OS
        // port when port=0 — v6 must then bind the same port; the
        // same-port rule includes the port=0 path).
        let bound = v4.local_addr().map(|a| a.port()).unwrap_or(candidate);
        // v6 best effort: with V6ONLY set first it coexists with v4 on
        // the port; failure = degrade to a v4-only stack (no v6
        // kernel/address is a common environment; info-observable, not
        // an error path). std -> tokio conversion (from_std's
        // non-blocking prerequisite is set at the creation point).
        let v6 = match bind_tcp_v6_only(bound).and_then(tokio::net::TcpListener::from_std) {
            Ok(l) => {
                debug!(target: "taiji::core::engine", port = bound,
                    "tcp dual-stack listening (v4+v6 same port, V6ONLY=1)");
                Some(l)
            }
            Err(e) => {
                info!(target: "taiji::core::engine", %e, port = bound,
                    "ipv6 listen unavailable; inbound TCP degraded to IPv4-only");
                None
            }
        };
        return Some((DualStackListener { v4, v6 }, bound));
    }
    None
}

/// v4/v6 TCP accept merge: both listeners feed one bounded channel for
/// single-arm main-loop consumption (the µTP merge channel's twin,
/// capacity [`TCP_ACCEPT_MERGE_CAPACITY`]).
///
/// Lifecycle (the µTP shape): the task lives with the listeners under
/// the token; channel closure (the main loop gone) exits it. Error
/// face: a v4 main-stack accept error does not end the task — back off
/// [`TCP_ACCEPT_ERROR_BACKOFF`] and retry (otherwise an Err is ready
/// immediately -> a hot spin); the best-effort v6 face drops its arm at
/// the first accept error (the socket stays held by the task until
/// engine teardown, the port occupancy unchanged) and the v4-only stack
/// keeps serving.
pub(super) fn spawn_tcp_accept_merge(
    dual: DualStackListener,
    token: CancellationToken,
) -> mpsc::Receiver<(tokio::net::TcpStream, SocketAddr)> {
    let DualStackListener { v4, v6 } = dual;
    let mut v6_active = v6.is_some();
    let (tx, rx) = mpsc::channel(TCP_ACCEPT_MERGE_CAPACITY);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                accepted = v4.accept() => match accepted {
                    Ok(pair) => {
                        if tx.send(pair).await.is_err() {
                            // Merge channel closed = the engine main loop has exited (teardown).
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(target: "taiji::core::engine", %e,
                            "tcp v4 accept error; backing off");
                        tokio::time::sleep(TCP_ACCEPT_ERROR_BACKOFF).await;
                    }
                },
                accepted = async {
                    match v6.as_ref() {
                        Some(l) => l.accept().await,
                        None => std::future::pending().await,
                    }
                }, if v6_active => match accepted {
                    Ok(pair) => {
                        if tx.send(pair).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        info!(target: "taiji::core::engine", %e,
                            "tcp v6 accept failed; v6 inbound disabled");
                        v6_active = false;
                    }
                },
            }
        }
    });
    rx
}
pub(super) async fn run(
    cfg: EngineConfig,
    tracker: TrackerWireConfig,
    token: CancellationToken,
    cmd_rx: Option<mpsc::Receiver<EngineCommand>>,
    conn_type: PeerConnectionType,
) -> EngineEnd {
    let parts = match assemble_engine(cfg, tracker, &token, cmd_rx, conn_type).await {
        Ok(parts) => parts,
        Err(end) => return end,
    };
    let AssembledEngine {
        mut tcp_inbound,
        actual_port,
        mut cmd_rx,
        mut progress_rx,
        // Block-arrival event receiver (the arrival arm; the channel is built in assemble).
        mut ledger_rx,
        mut fetch_rx,
        mut avail_rx,
        mut tracker_ev_rx,
        mut violation_rx,
        mut dht_ev_rx,
        mut pex_rx,
        pex_enabled,
        mut hp_rx,
        mut hp_report_rx,
        mut utp_inbound,
        mut dht_port_rx,
        mut reg_rx,
        mut leave_rx,
        mut redial_rx,
        mut redial_ticker,
        mut ecology_ticker,
        mut ticker,
        mut seed_ticker,
        mut choke_ticker,
        mut debt_ticker,
        session_up,
        session_down,
        session_metrics,
        gauge_slot,
        hook,
        nat,
        seed,
        seed_after_complete,
        layout,
        dest,
        piece_len,
        dht_announce_interval,
        mut dht_wiring,
        mut dht_seam,
        actor_cmds,
        startup_uploaded,
        startup_downloaded,
        startup_active_s,
        startup_seed_s,
        dial,
        mut state,
        // Recovery delivery-seam receiver (the main-loop event channel
        // convention — locally bound so select! arms borrow separately).
        mut recovery_deliver_rx,
        // The BEP19 webseed set (engine-face assembly input).
        webseeds,
    } = parts;

    // Webseed pseudo-peer assembly (engine face): with the BH_WEBSEED
    // switch on and a non-empty set, one duplex wire + attach_peer per
    // URL (v1 faces only; wired once before the main loop starts;
    // register events flow through the leave/avail/reg arms on the
    // first round — see the webseed module docs).
    dial::attach_webseeds(&webseeds, &mut state, &dial, &token);

    // Resume-as-complete: tasks whose restored bitmap is already
    // complete (finished in a previous session; this session resumes
    // into seeding/teardown) get their face completion flag set before
    // the main loop (the completion side and cleanup are driven by the
    // first round's resume branch — the same teardown path as an online
    // completion, not bypassing the stopped sequence / final flush).
    // The on-bt-download-complete hook does not fire on the resume
    // path: the completion event belongs to the online completion
    // moment (aria2 does not re-emit after a restart). Criterion =
    // [`recheck_face_completion`] (the written count is the single
    // source of truth; the restored bitmap comes from the previous
    // session's verify+write double-confirmed pieces, so both counters
    // are equal by construction — the written criterion is used
    // explicitly to prevent a verified-leads-written imbalance from
    // recurring).
    recheck_face_completion(&mut state.faces, &state.required);

    // Recovery activation emission point (the activation chain): when
    // the set of files whose post-assembly bookkeeping is still
    // incomplete is non-empty -> initialize event tracking + relay
    // taiji.recoveryStarted (the engine emits on every activation; the
    // session side dedups to exactly once by gid).
    recovery_admit::emit_recovery_activation(&mut state, &hook);

    let end = loop {
        // Dispatch-debt settlement: the age check at the top of the
        // loop — settle when the debt age >= the cadence (2ms). Must
        // run before the select: under the biased order the
        // debt-cadence arm is last and a continuous event stream (every
        // BlockSettled / every HAVE) would starve it. This check costs
        // one Instant::elapsed per iteration (tens of ns) and
        // short-circuits on empty debt.
        flush_dispatch_debt(&mut state);
        // Lazy re-arm of the debt ticker: with no debt the
        // 5ms ticker arm is disabled — an unpolled `tick()` registers no
        // timer-wheel waker, so a parked idle loop (night shape:
        // seeding with no block flow) stops paying the ~200 wakes/s the
        // always-armed cadence cost, while the fire itself only ever
        // ran a no-op `flush_dispatch_debt` (empty-debt short circuit).
        // Wake-density-only change: with debt outstanding the arm is
        // enabled on the very next loop iteration after the registering
        // event arm, and the age backstop grid is unchanged (same
        // period, same MissedTickBehavior::Skip — an arm enabled after
        // a disabled stretch first drains the expired tick as a no-op
        // flush, then re-syncs to the grid; the settle gate keeps
        // anchoring on `dispatch_debt_since`, so no settle happens
        // earlier or later than before).
        let debt_live = !state.dispatch_debt.is_empty();
        // Resume-as-complete first-round branch (runs once, only when
        // the completion state is unrecorded).
        if let ControlFlow::Break(end) = check_resume_complete(
            &mut state,
            &seed,
            &layout,
            &dest,
            piece_len,
            seed_after_complete,
        ) {
            break end;
        }
        tokio::select! {
            biased;
            _ = token.cancelled() => break state.end_on_cancel(),
            // Control plane (changeUri tracker linkage); the branch
            // precedes the data-plane ticks so control commands do not
            // lag behind a busy swarm.
            cmd = engine_command_recv(&mut cmd_rx) => {
                // Runtime DHT borrow bundle (arm-body exclusive —
                // select arms run sequentially, borrows do not outlive
                // the arm).
                let mut dht = DhtRuntime {
                    wiring: &mut dht_wiring,
                    seam: &mut dht_seam,
                    ev_rx: &mut dht_ev_rx,
                    dial: &dial,
                    actual_port,
                };
                handle_engine_command(
                    cmd,
                    &mut state,
                    &actor_cmds,
                    &session_up,
                    &layout,
                    piece_len,
                    startup_uploaded,
                    &mut dht,
                )
                .await;
            }
            prog = progress_rx.recv() => {
                if let ControlFlow::Break(end) = handle_store_progress(
                    prog,
                    &mut state,
                    &hook,
                    &seed,
                    seed_after_complete,
                    &layout,
                    &dest,
                    piece_len,
                )
                .await
                {
                    break end;
                }
            }
            // Block-arrival arm: after StoreProgress in the biased
            // order — consuming confirmations first keeps the
            // arrival/confirmation reorder window minimal; this arm is
            // bookkeeping-only (no dispatch round, no debt
            // registration, see handle_dispatch_arrival). A full
            // channel degrades (the transit emitter try_sends and
            // drops on full = stays InFlight).
            Some(arrival) = ledger_rx.recv() => {
                handle_dispatch_arrival(arrival, &mut state);
            }
            Some((fi, ev)) = avail_rx.recv() => {
                if handle_peer_avail((fi, ev), &mut state).is_break() {
                    continue;
                }
            }
            Some(reg) = reg_rx.recv() => {
                if handle_peer_registered(reg, &mut state, session_metrics.as_deref(), pex_enabled)
                    .is_break()
                {
                    continue;
                }
            }
            Some((fi, cuid, kind)) = leave_rx.recv() => {
                if handle_peer_left(
                    fi,
                    cuid,
                    kind,
                    &mut state,
                    session_metrics.as_deref(),
                    &session_up,
                    &session_down,
                    pex_enabled,
                )
                .is_break()
                {
                    continue;
                }
            }
            Some((fi, file_idx, evt)) = fetch_rx.recv() => {
                if handle_hash_fetch((fi, file_idx, evt), &mut state).is_break() {
                    continue;
                }
            }
            // Recovery delivery-seam consumer arm (whole-file
            // admission): convergence criteria + anchor-domain
            // insertion + bookkeeping convergence live in
            // recovery_admit (single writer — the main-loop arm body).
            // The channel idles at zero cost (the arm suspends when
            // nothing is delivered).
            // Anchors of a recovered layer are persisted immediately
            // (a derived table, survives restarts).
            // Returns = all promotion coordinates (the main + same-root
            // siblings promoted together), each persisted as its own
            // derived row (the read-back side re-verifies per the
            // admission semantics, idempotent).
            Some(rec) = recovery_deliver_rx.recv() => {
                let lifted = recovery_admit::consume_recovered_layer(&mut state, rec);
                for (_fi, file_idx, snapshot) in &lifted {
                    recovery_admit::persist_recovered_layer(
                        state.persist_shared.as_ref(),
                        *file_idx,
                        snapshot,
                    )
                    .await;
                }
                // Promotion registration (the promotion-propagation
                // convergence point) — when the activation's
                // outstanding set is fully unblocked, relay
                // taiji.recoveryCompleted (exactly once).
                recovery_admit::note_promotions(&mut state, &lifted, &hook);
            }
            Some((fi, ev)) = tracker_ev_rx.recv() => {
                if handle_tracker_event(
                    (fi, ev),
                    &mut state,
                    session_metrics.as_deref(),
                    actual_port,
                )
                .is_break()
                {
                    continue;
                }
            }
            // v4/v6 dual-stack accept merge channel (the µTP merge
            // channel's twin; None = outbound-only degradation, the arm
            // pends forever, matching the old absent-listener
            // behaviour).
            Some((stream, peer_addr)) = async {
                match tcp_inbound.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if handle_inbound_tcp(stream, peer_addr, &mut state, &dial, &token).is_break() {
                    continue;
                }
            }
            Some((peer_addr, utp_stream)) = async {
                match utp_inbound.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if handle_inbound_utp(utp_stream, peer_addr, &mut state, &dial, &token).is_break()
                {
                    continue;
                }
            }
            Some(v) = violation_rx.recv() => {
                handle_violation(v, &mut state).await;
            }
            Some((_family, ev)) = dht_ev_rx.recv() => {
                if handle_dht_event(
                    ev,
                    &mut state,
                    session_metrics.as_deref(),
                    actual_port,
                )
                .await
                .is_break()
                {
                    continue;
                }
            }
            Some(ev) = pex_rx.recv() => {
                // dial/token pass-through (immediate dialing — spawns
                // when the pool is not full; the arm-body docs).
                if handle_pex_event(
                    ev,
                    &mut state,
                    &dial,
                    &token,
                    session_metrics.as_deref(),
                    actual_port,
                )
                .is_break()
                {
                    continue;
                }
            }
            // ut_holepunch event arm: rendezvous relay / connect
            // outbound punch / failed bookkeeping (the engine::holepunch
            // module docs; a closed channel = the engine gate closed,
            // this arm pends on None).
            Some(ev) = hp_rx.recv() => {
                if handle_holepunch_event(
                    ev,
                    &mut state,
                    &dial,
                    &token,
                    actual_port,
                )
                .is_break()
                {
                    continue;
                }
            }
            // Dial-outcome report arm: a direct-dial failure -> the
            // trigger face (introducer rendezvous).
            Some(report) = hp_report_rx.recv() => {
                handle_hp_dial_report(report, &mut state);
            }
            _ = redial_ticker.tick() => {
                handle_redial_sweep(&mut state, &dial, &token, session_metrics.as_deref());
            }
            Some(report) = redial_rx.recv() => {
                handle_redial_report(report, &mut state, session_metrics.as_deref());
            }
            // Discovery-candidate drain arm: 250ms cadence, the budget
            // accrued continuously (the rate adapts to the environment
            // 30<->100/s via the entry shift decision + the cap
            // formula) — synthesized sort keys over an O(300) sample,
            // top-N dialed off the table (the biased order places it
            // after the redial arm: ready at the same instant,
            // previously successful peers get budget first; the
            // state::DialSource tiering points the same way). See the
            // run::ecology module docs.
            _ = ecology_ticker.tick() => {
                ecology::drain_dial_candidates(
                    &mut state,
                    &dial,
                    &token,
                    actual_port,
                );
            }
            Some((cuid, port)) = dht_port_rx.recv() => {
                if handle_dht_port((cuid, port), &mut state, &dht_wiring)
                    .await
                    .is_break()
                {
                    continue;
                }
            }
            _ = ticker.tick() => {
                handle_slow_tick(
                    &mut state,
                    session_metrics.as_deref(),
                    &session_up,
                    &session_down,
                    &nat,
                    &dht_wiring,
                    actual_port,
                    dht_announce_interval,
                    pex_enabled,
                );
            }
            _ = seed_ticker.tick() => {
                if let ControlFlow::Break(end) = handle_seed_tick(
                    &mut state,
                    session_metrics.as_deref(),
                    gauge_slot.as_deref(),
                    &dht_wiring,
                    &session_up,
                    &session_down,
                    &seed,
                    startup_uploaded,
                    startup_downloaded,
                    startup_active_s,
                    startup_seed_s,
                    piece_len,
                    // Stall-valve action face: the urgent reannounce
                    // goes through the per-face actor command channel
                    // (the min_interval compliance gate lives in the
                    // actor).
                    &actor_cmds,
                )
                .await
                {
                    break end;
                }
            }
            _ = choke_ticker.tick() => {
                handle_choke_round(&mut state);
            }
            // Dispatch-debt settlement arm (the cadenced dispatch face):
            // high-frequency event arms (every BlockSettled / every
            // HAVE / a piece-landed re-dispatch) only register the face
            // (EngineLoop::note_dispatch_debt); this arm wakes on debt
            // age as the bottom-line cadence (the three-condition gate
            // lives in flush_dispatch_debt; the loop-top check above
            // keeps this arm from starving under continuous event
            // streams) — the in-round decision order matches per-event
            // dispatch exactly, only merged by round (rationale and
            // values in the dispatch::DISPATCH_DEBT_MAX_AGE docs). The
            // `if debt_live` guard is the lazy re-arm (see
            // the loop-top comment): disabled while no debt is
            // outstanding (a parked loop then holds no timer-waker for
            // this arm at all), re-enabled the iteration after a
            // registering event arm.
            _ = debt_ticker.tick(), if debt_live => {
                flush_dispatch_debt(&mut state);
            }
        }
    };
    // Shutdown stopped sequence (user-stop paths only — before
    // shutdown, aria2 drives the stopped announce until noMoreAnnounce,
    // TrackerWatcherCommand semantics): Stop -> the actor drives the
    // stopped event sequence -> Halted; peers/store are torn down only
    // after every face completes or the budget is exhausted.
    // Completed/Failed do not drive the stopped sequence (TorrentTask
    // takes over the RPC pause/remove shutdown semantics; the actor
    // ends when the command channel drops at engine exit). Detached and
    // SeedStopped are both "seeding ended" paths.
    if matches!(
        end,
        EngineEnd::Cancelled | EngineEnd::SeedStopped | EngineEnd::Detached
    ) {
        drive_stopped_sequence(
            &mut state,
            &actor_cmds,
            &mut tracker_ev_rx,
            session_metrics.as_deref(),
        )
        .await;
    }
    // DHT halt-save (`DHTSetup.cc` + `DHTAutoSaveCommand.cc` shutdown
    // save semantics): Shutdown per family (the receipt after the
    // actor's internal emit_persist) -> harvest Persist events within
    // the budget into the store (exactly one save per family).
    dht_halt_save(&mut state, &dht_wiring, &mut dht_ev_rx).await;
    // Final flush: dirty rows attributed within the shutdown window are
    // written serially, then the flusher task is aborted (the handle
    // drops afterwards -> PersistWriter drains the queue and exits;
    // the single-writer discipline).
    final_flush(
        &mut state,
        session_metrics.as_deref(),
        &session_up,
        &session_down,
        piece_len,
        startup_uploaded,
        startup_downloaded,
        startup_active_s,
        startup_seed_s,
    )
    .await;
    if let Some(flusher) = state.tracker_flusher.take() {
        flusher.abort();
    }
    token.cancel();
    for f in &state.faces {
        for p in &f.peers {
            p.shutdown();
        }
    }
    state.tasks.abort_all();
    end
}

/// The download engine.
pub struct DownloadEngine;
impl DownloadEngine {
    /// Controlled engine: additionally returns a command handle (the
    /// SessionActor linkage face; behaviour identical to
    /// [`Self::spawn_with`], just one extra bounded control channel).
    /// `conn_type` = the outbound transport plan (the
    /// `--bt-peer-connection-type` session option is injected through
    /// this parameter).
    pub fn spawn_controlled(
        cfg: EngineConfig,
        tracker: TrackerWireConfig,
        parent: &CancellationToken,
        conn_type: PeerConnectionType,
    ) -> (EngineHandle, tokio::task::JoinHandle<EngineEnd>) {
        let (cmd_tx, cmd_rx) = mpsc::channel::<EngineCommand>(16);
        let token = parent.child_token();
        let join =
            tokio::spawn(async move { run(cfg, tracker, token, Some(cmd_rx), conn_type).await });
        (EngineHandle { cmd_tx }, join)
    }
}

impl DownloadEngine {
    /// Download engine (the frozen face: tracker wiring takes the
    /// default = a single tier 0 `announce`, not persisted; the only
    /// behavioural difference is that announce orchestration is owned
    /// by the TrackerActor). For tier overrides / tracker-table
    /// persistence use [`Self::spawn_with`]. Outbound transport plan =
    /// the default prefer-tcp (session-face injection via
    /// [`Self::spawn_controlled`]).
    pub fn spawn(
        cfg: EngineConfig,
        parent: &CancellationToken,
    ) -> tokio::task::JoinHandle<EngineEnd> {
        Self::spawn_with(cfg, TrackerWireConfig::default(), parent)
    }

    /// Download engine (tracker tiers override + tracker-table
    /// persistence injection). Outbound transport plan = the default
    /// prefer-tcp (session-face injection via
    /// [`Self::spawn_controlled`]).
    pub fn spawn_with(
        cfg: EngineConfig,
        tracker: TrackerWireConfig,
        parent: &CancellationToken,
    ) -> tokio::task::JoinHandle<EngineEnd> {
        let token = parent.child_token();
        tokio::spawn(
            async move { run(cfg, tracker, token, None, PeerConnectionType::default()).await },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCP accept merge channel consumption wait cap (a test guard: a
    /// normal loopback connection is milliseconds; a timeout means an
    /// environment problem, and the panic reports which family's
    /// accept was lost).
    const ACCEPT_WAIT: Duration = Duration::from_secs(5);

    /// IPv6 environment probe (the same scope as the io::udp_demux
    /// tests: a container/CI where `::1` cannot bind has no IPv6; skip
    /// at runtime with the reason printed — an environmental skip, not
    /// a semantic exemption).
    fn ipv6_available() -> bool {
        std::net::TcpListener::bind("[::1]:0").is_ok()
    }

    /// Criterion: a same-port dual-stack bind + merged accept (one
    /// connection each from 127.0.0.1 and ::1; both arrive on the
    /// single channel and the two peer addresses show one family
    /// each).
    #[tokio::test]
    async fn dual_stack_binds_same_port_and_accepts_both_families() {
        if !ipv6_available() {
            eprintln!(
                "skip dual_stack_binds_same_port_and_accepts_both_families: ::1 unavailable (no IPv6 environment)"
            );
            return;
        }
        let token = CancellationToken::new();
        let Some((dual, bound)) = bind_listen_with_fallback(0, &token).await else {
            panic!("port=0 dual-stack bind should succeed (OS ephemeral port)");
        };
        // Same port: the v4/v6 local_addr ports agree with the returned
        // port (the actual_port source).
        let v4_port = dual
            .v4
            .local_addr()
            .unwrap_or_else(|e| panic!("v4 local_addr: {e}"))
            .port();
        let v6_port = dual
            .v6
            .as_ref()
            .unwrap_or_else(|| panic!("port=0 should bind v6 (::1 available environment)"))
            .local_addr()
            .unwrap_or_else(|e| panic!("v6 local_addr: {e}"))
            .port();
        assert_eq!(v4_port, bound, "v4 port = returned port");
        assert_eq!(
            v6_port, bound,
            "v6 port = same port (two stacks one port principle)"
        );

        let mut rx = spawn_tcp_accept_merge(dual, token.clone());
        let c4 = tokio::net::TcpStream::connect(("127.0.0.1", bound))
            .await
            .unwrap_or_else(|e| panic!("127.0.0.1:{bound} connect failed: {e}"));
        let c6 = tokio::net::TcpStream::connect(("::1", bound))
            .await
            .unwrap_or_else(|e| panic!("[::1]:{bound} connect failed: {e}"));

        let first = tokio::time::timeout(ACCEPT_WAIT, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("merged accept timeout (connection 1)"));
        let second = tokio::time::timeout(ACCEPT_WAIT, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("merged accept timeout (connection 2)"));
        // Merge payload = (TcpStream, SocketAddr) (the handle_inbound_tcp
        // order).
        let (_s_a, addr_a) = first.unwrap_or_else(|| panic!("merge channel closed (connection 1)"));
        let (_s_b, addr_b) =
            second.unwrap_or_else(|| panic!("merge channel closed (connection 2)"));
        // Accept order is nondeterministic (the merge task's select
        // race); one family each suffices.
        assert!(
            (addr_a.is_ipv4() && addr_b.is_ipv6()) || (addr_a.is_ipv6() && addr_b.is_ipv4()),
            "one connection per stack: got {addr_a} / {addr_b}"
        );
        drop((c4, c6));
        token.cancel();
    }

    /// Criterion: V6ONLY effective — (1) the creation point reads
    /// `IPV6_V6ONLY=1` (macOS/Windows already default to 1; the read
    /// pins "explicitly set, not relying on the OS default"; Linux
    /// ipv6(7) `bindv6only` defaults to 0, so this set is the fix
    /// itself, behaviourally proven by (2)); (2) while the v6 listener
    /// is held, `0.0.0.0` binds successfully on the same port
    /// (independent bind buckets per family; on Linux a bare `[::]`
    /// dual-stack socket would EADDRINUSE — no Linux runner in CI, so
    /// the defect scenario is excluded by the explicit set at the
    /// creation point and this comment is its record).
    #[test]
    fn v6_creation_point_sets_only_v6_and_v4_coexists_on_same_port() {
        if !ipv6_available() {
            eprintln!(
                "skip v6_creation_point_sets_only_v6_and_v4_coexists_on_same_port: ::1 unavailable (no IPv6 environment)"
            );
            return;
        }
        let l = bind_tcp_v6_only(0)
            .unwrap_or_else(|e| panic!("v6 creation point bind [::]:0 failed: {e}"));
        let only_v6 = socket2::SockRef::from(&l)
            .only_v6()
            .unwrap_or_else(|e| panic!("getsockopt IPV6_V6ONLY: {e}"));
        assert!(
            only_v6,
            "the v6 creation point must explicitly set IPV6_V6ONLY=1 (a bind precondition)"
        );
        let port = l
            .local_addr()
            .unwrap_or_else(|e| panic!("v6 local_addr: {e}"))
            .port();
        let v4co = std::net::TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
            panic!(
                "0.0.0.0:{port} bind failed while the v6 listener is held (V6ONLY ineffective): {e}"
            )
        });
        assert_eq!(
            v4co.local_addr()
                .unwrap_or_else(|e| panic!("v4 local_addr: {e}"))
                .port(),
            port,
            "v4 same-port coexistence bind"
        );
    }

    /// Lazy re-arm guard, pinned on the wall clock (the
    /// workspace does not enable tokio's `test-util` clock, so the
    /// assertion windows carry real-time jitter margins — the frozen
    /// properties are strong enough to survive it). The main loop's
    /// debt arm shape (`_ = debt_ticker.tick(), if debt_live`) has two
    /// properties this test freezes:
    ///
    /// 1. **Parked idle = zero ticker fires**: while the guard is false
    /// an unpolled `tick()` holds no timer-waker, so an idle stretch
    /// of 10 tick periods (50ms) must not run the arm body once.
    /// (With the guard removed — an always-armed tick — the same
    /// stretch fires ~10 times, which is exactly the regression
    /// shape this pins against.)
    /// 2. **Age backstop survives**: once debt is registered the arm
    /// re-enables on the next loop iteration; the first post-gap
    /// tick drains the expired grid point as a no-op (age gate
    /// anchored on the registration instant, < 5ms) and the settle
    /// still lands within one grid period — the wake-density-only
    /// freeze seam (dispatch semantics, gate order and the
    /// `dispatch_debt_since` anchor are untouched).
    #[tokio::test]
    async fn debt_ticker_lazy_rearm_guard_parks_idle_loop_and_keeps_age_backstop() {
        use std::collections::BTreeSet;
        const PERIOD: Duration = Duration::from_millis(5);
        let mut ticker = tokio::time::interval(PERIOD);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The same guard evaluation point as the main loop: after the
        // loop-top flush, before the select.
        let mut debt: BTreeSet<usize> = BTreeSet::new();

        // Phase 1: idle park across 10 tick periods — zero arm fires.
        let park_until = tokio::time::Instant::now() + Duration::from_millis(50);
        let mut fires = 0u32;
        loop {
            let debt_live = !debt.is_empty();
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(park_until) => break,
                _ = ticker.tick(), if debt_live => { fires += 1; }
            }
        }
        assert_eq!(
            fires, 0,
            "the debt arm must not fire within the idle park window (10 periods)"
        );

        // Phase 2: debt registered — the arm re-enables and the age
        // backstop settles. (Fires before the age gate passes are
        // expected no-ops — expired grid points draining after the
        // disabled stretch; the settle itself can only ever happen at
        // `since.elapsed() >= PERIOD`, the same anchor the real
        // `flush_dispatch_debt` age gate uses.)
        debt.insert(0);
        let since = tokio::time::Instant::now();
        let drain_until = since + 6 * PERIOD;
        let mut settled = false;
        loop {
            if settled || tokio::time::Instant::now() >= drain_until {
                break;
            }
            let debt_live = !debt.is_empty();
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(drain_until) => break,
                _ = ticker.tick(), if debt_live => {
                    if since.elapsed() >= PERIOD {
                        debt.clear();
                        settled = true;
                    }
                }
            }
        }
        assert!(
            settled,
            "the age fallback must settle within the 6-period window once debt is registered (flush_dispatch_debt's age gate)"
        );
    }

    /// Fixed port for the degradation test: deliberately a
    /// non-privileged port outside the OS ephemeral ranges (macOS
    /// 49152-65535, Linux 32768-60999 by default) — when this test
    /// group runs in parallel, the other cases' port=0 binds land in
    /// the ephemeral zone and cannot invade the fixed window, avoiding
    /// cross-case port collisions (the determinism premise of the
    /// window-fallback assertions).
    const DEGRADE_TEST_PORT: u16 = 18681;
    /// Fixed base port for the window-fallback test (offset from
    /// [`DEGRADE_TEST_PORT`], mutually non-invasive).
    const WINDOW_TEST_PORT: u16 = 18683;

    /// Criterion: the v6 port is taken (simulating a v6 bind failure —
    /// the same shape as no v6 kernel/address) -> degrade to a v4-only
    /// stack; v4 succeeds on the original port without window
    /// fallback.
    #[tokio::test]
    async fn v6_bind_failure_degrades_to_v4_single_stack() {
        if !ipv6_available() {
            eprintln!(
                "skip v6_bind_failure_degrades_to_v4_single_stack: ::1 unavailable (no IPv6 environment)"
            );
            return;
        }
        // Occupy the v6 side: after the same creation point (V6ONLY=1 +
        // REUSEADDR) binds [::]:p, a second v6 socket still gets
        // EADDRINUSE (SO_REUSEADDR exempts only TIME_WAIT, not an
        // active listener — this is not SO_REUSEPORT).
        let occupier = bind_tcp_v6_only(DEGRADE_TEST_PORT)
            .unwrap_or_else(|e| panic!("v6 occupier bind [::]:{DEGRADE_TEST_PORT} failed: {e}"));
        let p = occupier
            .local_addr()
            .unwrap_or_else(|e| panic!("v6 local_addr: {e}"))
            .port();
        assert_eq!(p, DEGRADE_TEST_PORT);
        let token = CancellationToken::new();
        let Some((dual, bound)) = bind_listen_with_fallback(p, &token).await else {
            panic!("must not fail the whole window when the v4 side is free");
        };
        assert_eq!(bound, p, "v4 binds on p: no window fallback");
        assert!(
            dual.v6.is_none(),
            "v6 taken -> degraded to a single v4 stack"
        );
        assert_eq!(
            dual.v4
                .local_addr()
                .unwrap_or_else(|e| panic!("v4 local_addr: {e}"))
                .port(),
            p,
            "single-stack port = requested port"
        );
    }

    /// Criterion: with the same port taken on both v4+v6 -> after the
    /// window fallback (ascending) both stacks are still on one port
    /// (the same-port rule: the fallback defers both stacks, no
    /// single-stack misalignment).
    #[tokio::test]
    async fn port_window_fallback_keeps_both_stacks_on_same_port() {
        if !ipv6_available() {
            eprintln!(
                "skip port_window_fallback_keeps_both_stacks_on_same_port: ::1 unavailable (no IPv6 environment)"
            );
            return;
        }
        let p = WINDOW_TEST_PORT;
        let occ4 = std::net::TcpListener::bind(("0.0.0.0", p))
            .unwrap_or_else(|e| panic!("v4 occupier bind 0.0.0.0:{p} failed: {e}"));
        let occ6 =
            bind_tcp_v6_only(p).unwrap_or_else(|e| panic!("v6 occupier bind [::]:{p} failed: {e}"));
        let token = CancellationToken::new();
        let Some((dual, bound)) = bind_listen_with_fallback(p, &token).await else {
            panic!("a bindable port must exist within the window (p taken, deferred fallback)");
        };
        // Under the deterministic ascending semantics this is p+1;
        // against environment noise only in-window advancement is
        // asserted.
        assert!(
            bound > p && bound <= p + LISTEN_PORT_FALLBACK_WIDTH,
            "port window fallback happened: bound={bound} should fall in (p, p+{LISTEN_PORT_FALLBACK_WIDTH}]"
        );
        let v4_port = dual
            .v4
            .local_addr()
            .unwrap_or_else(|e| panic!("v4 local_addr: {e}"))
            .port();
        let v6_port = dual
            .v6
            .as_ref()
            .unwrap_or_else(|| {
                panic!("after window fallback v6 should rebind on the same port as v4")
            })
            .local_addr()
            .unwrap_or_else(|e| panic!("v6 local_addr: {e}"))
            .port();
        assert_eq!(
            bound, v4_port,
            "after fallback the returned port = the v4 bound port"
        );
        assert_eq!(
            v4_port, v6_port,
            "after fallback both stacks still share one port"
        );
        drop((occ4, occ6));
    }

    /// BEP21 upload_only inbound consumption, engine profile face: an
    /// ext handshake with `upload_only = 1` sets the peer profile seed
    /// flag true (BEP21: "Setting the value of this key to 1 indicates
    /// that this peer is not interested in downloading anything." —
    /// seeder/partial-seeder identity); a re-sent handshake **without
    /// the key** follows back to false (a missing key = false;
    /// libtorrent reads the dict per frame in on_extended_handshake,
    /// bt_peer_connection.cpp). Assembly mirrors the transit attach:
    /// the mirror Arc goes into both PeerConfig (the PeerTask write
    /// face, stored via handle_extended) and PeerMeta (the profile read
    /// face, the same pipeline as the up/down counters). Determinism
    /// proof: a frame-order sentinel (an out-of-set Piece -> Violation
    /// ends the task; join returning proves the handshakes were
    /// processed).
    #[tokio::test]
    async fn peer_upload_only_lands_in_peer_profile() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        async fn drive(handshakes: Vec<taiji_bt::peer_wire::ExtHandshake>) -> bool {
            use tokio::io::AsyncWriteExt as _;
            let root = CancellationToken::new();
            let mirror = std::sync::Arc::new(AtomicBool::new(false));
            let config = taiji_bt::peer::PeerConfig {
                peer_upload_only: Some(std::sync::Arc::clone(&mirror)),
                ..taiji_bt::peer::PeerConfig::flat()
            };
            let (local, mut remote) = tokio::io::duplex(64 * 1024);
            let (_handle, join, _data) = taiji_bt::peer::PeerTask::spawn(&root, local, config);
            for hs in &handshakes {
                let frame = taiji_bt::peer_wire::Message::Extended {
                    ext_id: 0,
                    payload: hs.encode().unwrap_or_else(|e| panic!("{e}")),
                }
                .encode();
                remote
                    .write_all(&frame)
                    .await
                    .unwrap_or_else(|e| panic!("{e}"));
            }
            // Sentinel: an out-of-set Piece -> Violation (the
            // processing order guarantees the handshakes were consumed
            // first).
            let sentinel = taiji_bt::peer_wire::Message::Piece {
                index: 9,
                begin: 0,
                block: bytes::Bytes::from_static(b"sentinel"),
            }
            .encode();
            remote
                .write_all(&sentinel)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            let end = tokio::time::timeout(ACCEPT_WAIT, join)
                .await
                .unwrap_or_else(|e| panic!("timeout: {e:?}"))
                .unwrap_or_else(|e| panic!("join: {e}"));
            assert!(
                matches!(
                    end,
                    taiji_bt::peer::PeerEnd::Violation(
                        taiji_bt::peer::PeerError::UnsolicitedPiece { index: 9, .. }
                    )
                ),
                "the sentinel must disconnect on an out-of-set push (proof that \
                 frames were processed in order), got {end:?}"
            );
            // Profile read face (the transit.rs attach-shaped
            // assembly): PeerMeta holds the same-source mirror.
            let meta = crate::faces::PeerMeta {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port: 6881,
                inbound: false,
                peer_id: [0u8; 20],
                crypto: taiji_bt::mse::CryptoLevel::Plain,
                transport: taiji_bt::utp::Transport::Tcp,
                up: std::sync::Arc::new(AtomicU64::new(0)),
                down: std::sync::Arc::new(AtomicU64::new(0)),
                upload_only: mirror,
            };
            meta.upload_only.load(Ordering::Relaxed)
        }

        // Row 1: upload_only=1 -> the profile seed flag true.
        assert!(
            drive(vec![taiji_bt::peer_wire::ExtHandshake {
                upload_only: true,
                ..taiji_bt::peer_wire::ExtHandshake::default()
            }])
            .await,
            "a peer upload_only=1 must land in the engine peer profile (the seed flag)"
        );
        // Row 2: follow-up — first 1 then a keyless handshake (a BEP21
        // missing key = false).
        assert!(
            !drive(vec![
                taiji_bt::peer_wire::ExtHandshake {
                    upload_only: true,
                    ..taiji_bt::peer_wire::ExtHandshake::default()
                },
                taiji_bt::peer_wire::ExtHandshake::default(),
            ])
            .await,
            "a re-sent keyless handshake must follow back to false (the inbound-state follow updates)"
        );
    }
}

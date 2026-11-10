//! Main `select!` dial/inbound arm bodies (extracted): tracker Peers,
//! TCP/µTP inbound accept, violation, DHT events, ut_pex, redial
//! sweep/report, inbound PORT. Arm bodies are verbatim ports of the former
//! `run()` `select!` arms; `continue` is translated to
//! [`ControlFlow::Break`] (the caller restores the main-loop continue
//! semantics); the four DialJob literals collapsed into the single assembly
//! point [`super::state::spawn_peer_dial`] (field order / cuid issuance
//! order / discovery counting points preserved).
//!
//! Discovery dialing is two-phase: the tracker/DHT/PEX arms only run the
//! batch-level admission gate plus address hygiene / self-connect / dedup /
//! same-IP prechecks; surviving addresses enter the candidate table
//! ([`super::ecology::push_candidate`], the source rank encoded in the
//! entry). Actual dialing is composed by the 250 ms drain wheel by sort key
//! (failcount → local → last_connected → source_rank → BEP-40) + O(300)
//! sampling top-N + a session-level budget (`run::ecology` module docs).
//! Redial and punch sources bypass the candidate table and keep direct
//! [`spawn_peer_dial`] dialing (each manages its own cadence).
//!
//! PEX immediate dialing: after a PEX arm passes a candidate through the
//! batch admission gate into the table, if the pool is not full
//! (`registered < outbound target`) and the switch is on
//! (`BH_PEX_IMMEDIATE`, default on), the dial spawns immediately (Discovery
//! source — the silent-ledger gate / token-bucket spend / silent-failure
//! re-push apply automatically inside the spawn). An exhausted spawn (tokens
//! / silent backoff) leaves the candidate in the table for the drain wheel,
//! removing 250 ms batching-latency accumulation during ramp-up.
//!
//! In scope: discovery → candidate admission for new connections and
//! inbound connection acceptance. Out of scope: swarm data-plane events
//! (arms), cadence ticks.
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use taiji_bt::dht::{DhtEvent, DhtFamily, DhtSwarmKind};
use taiji_bt::mse;
use taiji_bt::peer::PexEvent;
use taiji_bt::peer::handshake_exchange;
use taiji_bt::peer_policy::Violation;
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_bt::tracker::actor::TrackerActorEvent;
use taiji_bt::utp::Transport;
use taiji_io::rate_limit::Throttled;
use taiji_io::utp::UtpStream;

use crate::metrics::SessionMetrics;

use super::state::{DialCtx, EngineLoop, spawn_peer_dial};
use std::net::IpAddr;
use std::sync::Arc;

use crate::ban::client_violation;
use crate::config::FaceKind;
use crate::dht::{DhtFamilyWiring, persist_dht_state};
use crate::pipeline::{BlockMsg, BlockSenders};
use crate::redial::{DialOutcome, RedialReport};
use crate::tracker::{epoch_secs, handle_tracker_bookkeeping};
use crate::transit::{MSE_HANDSHAKE_TIMEOUT, attach_peer};
use crate::webseed;
/// Outbound dial failure classes (io layer): connect-refused /
/// connect-timeout / connect-error (all other io error kinds).
pub(crate) fn classify_connect_io(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::ConnectionRefused => "connect-refused",
        std::io::ErrorKind::TimedOut => "connect-timeout",
        _ => "connect-error",
    }
}

/// Dial-outcome log sampler (sampling discipline).
///
/// Shape (one INFO line per dial target: addr / result / failure class;
/// high-frequency cases are sampled as a periodic summary + full failure
/// logging):
/// - Failures: logged in full — `peer_connect` already aggregates a target's
///   per-transport attempts into one line (addr + the attempts' class
///   sequence), so this sampler only counts;
/// - Successes: a high-frequency flood risk → counted into the periodic
///   summary (one `dial summary` line per [`DIAL_LOG_SUMMARY_WINDOW`], only
///   in windows with dial activity; per-target success lines stay at the
///   existing DEBUG text "outbound connected").
///
/// Process-level singleton ([`Self::global`]): one session-semantic logging
/// state per process; tests use [`Self::with_window`] (private) to inject a
/// zero window for deterministic driving. The std Mutex never spans an await
/// (`note_result` returns synchronously).
pub(crate) struct DialLogSampler {
    window: Duration,
    inner: Mutex<DialLogState>,
}

/// Summary window (a local policy value chosen so a normal swarm does not
/// flood the log).
pub(crate) const DIAL_LOG_SUMMARY_WINDOW: Duration = Duration::from_secs(30);

#[derive(Default)]
struct DialLogState {
    window_start: Option<Instant>,
    ok: u64,
    fail_by_class: HashMap<&'static str, u64>,
}

impl DialLogSampler {
    /// Process-level singleton.
    pub(crate) fn global() -> &'static Self {
        static S: OnceLock<DialLogSampler> = OnceLock::new();
        S.get_or_init(|| DialLogSampler {
            window: DIAL_LOG_SUMMARY_WINDOW,
            inner: Mutex::new(DialLogState::default()),
        })
    }

    /// Test assembly: inject a window (a zero window = every note flushes
    /// the previous window's summary, deterministic).
    #[cfg(test)]
    fn with_window(window: Duration) -> Self {
        DialLogSampler {
            window,
            inner: Mutex::new(DialLogState::default()),
        }
    }

    /// Record one dial outcome (exactly once per dial target; with ok=false,
    /// class = the failure class of the target's last transport attempt). A
    /// window rollover flushes the previous window's summary.
    pub(crate) fn note_result(&self, ok: bool, class: &'static str) {
        let mut st = crate::lock(&self.inner);
        let now = Instant::now();
        match st.window_start {
            Some(start) if now.duration_since(start) < self.window => {}
            Some(_) => {
                let fail_total: u64 = st.fail_by_class.values().sum();
                if st.ok + fail_total > 0 {
                    info!(target: "taiji::core::engine",
                        window_secs = self.window.as_secs(), ok = st.ok, fail = fail_total,
                        fail_by_class = ?st.fail_by_class, "dial summary");
                }
                st.ok = 0;
                st.fail_by_class.clear();
                st.window_start = Some(now);
            }
            None => st.window_start = Some(now),
        }
        if ok {
            st.ok += 1;
        } else {
            *st.fail_by_class.entry(class).or_insert(0) += 1;
        }
    }
}

/// Discovery-source dial admission gate (lever 1; shared batch-level by the
/// tracker/DHT/PEX arms).
///
/// - Batch-level: the gate is decided once per batch (no state can change
///   between batches inside the single-writer loop, so per-address
///   re-checking within a batch is pure redundancy) — gate closed = the
///   whole batch is skipped;
/// - Before dedup consumption: addresses stopped by the gate never enter
///   the dedup table, so the next announce/PEX re-offer retries them — the
///   backfill chain is preserved (consuming first and blocking later would
///   leave a static tracker list unable to backfill for one 10 min dedup
///   window after a peer leaves);
/// - Form: leecher target gate + slow-download relief (aria2 minPeers
///   semantics + the `--bt-request-peer-speed-limit` valve; see
///   [`super::state::EngineLoop::admission_open`] and the constant docs) —
///   the gate only tightens while the download is healthy.
///
/// Returns false = skip the whole batch (the caller short-circuits).
pub(super) fn discovery_admission_open(state: &mut EngineLoop) -> bool {
    if state.admission_open(false, Instant::now()) {
        return true;
    }
    debug!(target: "taiji::core::engine",
        registered = state.registered_peers(),
        target = super::state::peer_connections_target(),
        "discovery dial batch skipped by connection admission ");
    false
}

/// Tracker announce event arm: Peers → the candidate table (the dial
/// decision is handed to the drain wheel — `run::ecology` module docs);
/// everything else → row-attribution persistence (pointer mirror in the
/// tracker module docs).
pub(super) fn handle_tracker_event(
    ev: (usize, TrackerActorEvent),
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    actual_port: u16,
) -> ControlFlow<(), ()> {
    let (fi, ev) = ev;
    match ev {
        TrackerActorEvent::Peers { peers, peers6, .. } => {
            if state.faces.get_mut(fi).is_none() {
                return ControlFlow::Break(());
            }
            // Connection admission gate (batch-level): consumed before dedup
            // (the backfill chain is preserved — see
            // [`discovery_admission_open`]).
            if !discovery_admission_open(state) {
                return ControlFlow::Continue(());
            }
            let addrs: Vec<std::net::SocketAddr> = peers
                .iter()
                .map(|p| std::net::SocketAddr::from((p.ip, p.port)))
                .chain(
                    peers6
                        .iter()
                        .map(|p| std::net::SocketAddr::from((p.ip, p.port))),
                )
                .collect();
            for addr in addrs {
                // Address hygiene (a single-point decision, addr_hygiene
                // module docs): v4-mapped normalization onto the v4 face +
                // bogon rejection — rejected addresses enter no derived
                // surface (no discovery count, no dedup). The tracker's
                // peers6/UDP 18 B carrier is a known v6 injection face;
                // parsing is untouched, hygiene is unified on the consumer
                // side.
                let Some(addr) = crate::addr_hygiene::sanitize_discovered_addr(addr) else {
                    debug!(target: "taiji::core::engine", raw = %addr,
                        "tracker peer rejected by address hygiene ");
                    continue;
                };
                // Never connect to self (an extended decision, single-point
                // reuse of addr_hygiene: loopback / unspecified / v4-mapped
                // loopback / the local interface address set ∧ the announce
                // port). Fix note: this used to compare config listen_port —
                // the session-form engine spawns with listen_port = 0 (an
                // ephemeral port), so the guard never hit and the engine
                // self-connected whenever an announce echo contained its own
                // address (requests sent to itself, spinning). The guard must
                // use the announce-port semantics (`actual_port`).
                if crate::addr_hygiene::is_self_endpoint(
                    addr,
                    actual_port,
                    crate::addr_hygiene::LocalIpSet::shared(),
                ) {
                    continue;
                }
                // Discovery count (tracker source; see
                // SessionMetrics::note_peer_discovered).
                if let Some(m) = metrics {
                    m.note_peer_discovered(false);
                }
                // Duplicate addresses within the window do not re-dial
                // (stale-pool pruning: the tracker arm aligns with the
                // DHT/PEX arms on the same source-agnostic dedup table + the
                // same-IP-connected check — previously the tracker source had
                // no dedup window, so every announce re-offer re-dialed the
                // same stale endpoint once per announce period). The admission
                // gate already ran batch-level in this arm (before dedup
                // consumption, backfill chain preserved).
                if !state.dht_dial_dedup.admit(addr, Instant::now()) {
                    continue;
                }
                if state.faces[fi]
                    .peer_state
                    .values()
                    .any(|ps| ps.ip == Some(addr.ip()))
                {
                    debug!(target: "taiji::core::engine", %addr,
                        "tracker peer already connected by ip: skipped");
                    continue;
                }
                // Candidate entry: tracker source rank = 1<<5 (libtorrent
                // request_blocks.cpp); the drain wheel composes dialing from
                // the table by sort key (`run::ecology` module docs).
                super::ecology::push_candidate(
                    state,
                    addr,
                    fi,
                    super::ecology::DialSourceRank::Tracker,
                    Instant::now(),
                );
            }
        }
        ev => {
            if let Some(face) = state.faces.get_mut(fi) {
                handle_tracker_bookkeeping(face, ev, state.persist_shared.as_ref(), metrics);
            }
        }
    }
    ControlFlow::Continue(())
}

/// TCP inbound accept arm: filter point 1 (check IpGuard at accept — reject
/// before the handshake, exchanging no bytes with banned peers; bans are
/// never silent: the log carries ip + verdict) and the inbound sniffing/demux
/// task spawn (the multi-candidate BT handshake completes on the transparent
/// stream after MSE negotiation; the PeerTransport seam shape is unchanged).
/// Identity-rule verdicts happen at handshake completion (on a hit: drop the
/// connection + a Violation event, see `client_violation`).
///
/// Returns `Break` = the connection was filtered (main-loop continue
/// semantics).
pub(super) fn handle_inbound_tcp(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
) -> ControlFlow<(), ()> {
    if let Some(block) = state
        .ban_book
        .guard
        .load()
        .blocks(peer_addr.ip(), epoch_secs())
    {
        warn!(target: "taiji::core::engine", %peer_addr, block = %block,
            "inbound peer rejected by IpGuard (before handshake)");
        drop(stream);
        return ControlFlow::Break(());
    }
    // Inbound connection admission gate: hard cap full and download healthy →
    // reject (the same verdict as aria2 `PeerReceiveHandshakeCommand.cc`
    // `(!finished && downloadSpeed < threshold) || lessThanMaxPeers()`;
    // divergence noted: upstream decides after the handshake, here the gate
    // sits at accept — an equivalent, cheaper point that saves the MSE/BT
    // handshake CPU; from the peer's view both are "connect then close", and
    // reconnection is governed by the peer's own cadence). Slow-download
    // relief: see [`super::state::EngineLoop::admission_open`].
    if !state.admission_open(true, Instant::now()) {
        debug!(target: "taiji::core::engine", %peer_addr,
            registered = state.registered_peers(),
            max = super::state::peer_connections_max(),
            "inbound peer dropped by connection admission (before handshake)");
        drop(stream);
        return ControlFlow::Break(());
    }
    let candidates: Vec<([u8; 20], Reserved)> = state
        .faces
        .iter()
        .map(|f| (f.info_hash, f.reserved))
        .collect();
    let mut addrings: Vec<Addressing> = state.faces.iter().map(|f| f.addressing.clone()).collect();
    // Unsolicited block-coordinate upper-bound table (face-shared; consumed
    // by the matched index, same order as addrings).
    let mut pbytes: Vec<std::sync::Arc<[u64]>> =
        state.faces.iter().map(|f| f.piece_bytes.clone()).collect();
    let mut blocks: Vec<mpsc::Sender<BlockMsg>> =
        state.faces.iter().map(|f| f.block_tx.clone()).collect();
    // Face-level block arena passed through with the face index (None =
    // fallback to direct allocation).
    let mut arenas: Vec<Option<Arc<taiji_io::block_arena::BlockArena>>> =
        state.faces.iter().map(|f| f.block_arena.clone()).collect();
    let mut senders: Vec<BlockSenders> = state
        .faces
        .iter()
        .map(|f| f.block_senders.clone())
        .collect();
    let pid = dial.peer_id;
    let reg = dial.reg_tx.clone();
    let leave = dial.leave_tx.clone();
    let parent = token.clone();
    let mut avail = dial.avail_tx_face.clone();
    let srcs = state.seeding_sources.clone();
    let hash_srcs = state.seeding_hash_sources.clone();
    // Face-level read pools: resolved per face at attach (the same shape as
    // srcs — matched is only known after sniffing, so per-face slots are
    // pre-cloned).
    let mut read_pools: Vec<Option<Arc<taiji_bt::peer::ReadPool>>> =
        state.faces.iter().map(|f| f.read_pool.clone()).collect();
    let ext = dial.ext.clone();
    // -6: the `v` field identity re-check callback (inbound connections
    // get the same verdict as outbound).
    let client_deny = dial.client_deny.clone();
    // holepunch wiring resolved at attach (gate open ∧ channel present).
    let holepunch = dial.holepunch_attach();
    let vio = dial.violation_tx.clone();
    // Arrival-event sender (an engine-level single channel, injected at attach).
    let ledger = dial.ledger_tx.clone();
    let guard = state.ban_book.guard.clone();
    let addr = peer_addr;
    let cuid = state.next_cuid;
    state.next_cuid += 1;
    // Direct-connect seam: switch on → mint a sink per face (cuid attribution
    // rides along; consumed by the matched index, same order as
    // blocks/senders); off → all None = the old path. Read at accept-assembly
    // time, never on the block hot path.
    let mut sinks: Vec<Option<std::sync::Arc<dyn taiji_bt::peer::BlockSink>>> =
        state.faces.iter().map(|f| f.block_sink_for(cuid)).collect();
    let policy = dial.crypto;
    let dht_attach = dial.attach_dht.get();
    let limiter = dial.limiter.clone();
    state.tasks.spawn(async move {
        // Inbound sniff/demux (aria2 `ReceiverMSEHandshakeCommand.cc`
        // anchor): the first byte decides legacy vs MSE; require-crypto
        // rejects legacy; the multi-candidate BT handshake completes on the
        // transparent stream negotiated by MSE. PeerTransport seam shape
        // unchanged (PeerStream is transparent to PeerTask).
        match mse::accept_any(stream, &pid, &candidates, policy, MSE_HANDSHAKE_TIMEOUT).await {
            Ok(accepted) => {
                let mse::Accepted {
                    stream,
                    matched,
                    handshake,
                    crypto: level,
                } = accepted;
                // Identity rule (at handshake completion — peer_id is only
                // available now): on a hit, drop the connection + a Violation
                // event (persisted as reason=client-ban:* + same-IP online
                // connections severed); it never enters the swarm.
                if let Some(v) = client_violation(&guard, &handshake.peer_id, addr.ip()) {
                    debug!(target: "taiji::core::engine", %addr, reason = %v.reason,
                        "inbound peer rejected by identity rule ");
                    let _ = vio.send(v).await;
                    return;
                }
                debug!(target: "taiji::core::engine", %addr, ?level,
                    "inbound accepted");
                // Inbound throttles like outbound (the post-handshake
                // transport stream; read-path await permits = TCP/µTP window
                // backpressure).
                attach_peer(
                    Throttled::maybe(stream, limiter),
                    matched,
                    cuid,
                    addr,
                    // Inbound connection (getPeers port=0 semantics, aria2
                    // RpcMethodImpl.cc).
                    true,
                    handshake.peer_id,
                    level,
                    Transport::Tcp,
                    addrings.swap_remove(matched),
                    pbytes.swap_remove(matched),
                    blocks.swap_remove(matched),
                    senders.swap_remove(matched),
                    sinks.swap_remove(matched),
                    ledger,
                    avail.swap_remove(matched),
                    reg,
                    leave,
                    srcs.into_iter().nth(matched).flatten(),
                    hash_srcs.into_iter().nth(matched).flatten(),
                    vio,
                    ext,
                    // -6: the `v` field identity re-check callback.
                    client_deny,
                    // holepunch wiring (resolved at attach).
                    holepunch,
                    // Face-level read pool for serve (face-shared).
                    read_pools.swap_remove(matched),
                    // Face-level block arena (None = fallback to direct allocation).
                    arenas.swap_remove(matched),
                    parent,
                    dht_attach,
                    // Peer DHT capability (BEP-5 reserved[7]&0x01): true ∧
                    // locally enabled → PORT sent after the handshake.
                    handshake.reserved.supports_dht(),
                    // BEP-10 negotiation gate (see the attach_peer note).
                    handshake.reserved.supports_extended(),
                    // BEP-6 fast negotiation mirror (the outbound Reject
                    // gate; attach_peer note).
                    handshake.reserved.supports_fast(),
                )
                .await;
            }
            Err(e) => {
                debug!(target: "taiji::core::engine", %peer_addr, %e,
                    "inbound handshake failed");
            }
        }
    });
    ControlFlow::Continue(())
}

/// µTP inbound accept arm: filter point 1 (µTP inbound follows the same
/// discipline as TCP) and the sniff/demux task spawn. "Accept both inbound
/// transports": µTP inbound merges into the same bt::peer accept path as TCP
/// (the connection-type option constrains outbound planning only). The
/// identity-rule verdict at handshake completion matches the TCP arm
/// (`client_violation`).
///
/// Returns `Break` = the connection was filtered (main-loop continue
/// semantics).
pub(super) fn handle_inbound_utp(
    utp_stream: UtpStream,
    peer_addr: SocketAddr,
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
) -> ControlFlow<(), ()> {
    if let Some(block) = state
        .ban_book
        .guard
        .load()
        .blocks(peer_addr.ip(), epoch_secs())
    {
        warn!(target: "taiji::core::engine", %peer_addr, block = %block,
            "inbound utp peer rejected by IpGuard (before handshake)");
        drop(utp_stream);
        return ControlFlow::Break(());
    }
    // Inbound connection admission gate (the same discipline as the TCP arm).
    if !state.admission_open(true, Instant::now()) {
        debug!(target: "taiji::core::engine", %peer_addr,
            registered = state.registered_peers(),
            max = super::state::peer_connections_max(),
            "inbound utp peer dropped by connection admission (before handshake)");
        drop(utp_stream);
        return ControlFlow::Break(());
    }
    // Face-vector snapshots isomorphic to the TCP arm (order = faces order, consumed by matched).
    let candidates: Vec<([u8; 20], Reserved)> = state
        .faces
        .iter()
        .map(|f| (f.info_hash, f.reserved))
        .collect();
    let mut addrings: Vec<Addressing> = state.faces.iter().map(|f| f.addressing.clone()).collect();
    // Unsolicited block-coordinate upper-bound table (face-shared; consumed
    // by the matched index, same order as addrings).
    let mut pbytes: Vec<std::sync::Arc<[u64]>> =
        state.faces.iter().map(|f| f.piece_bytes.clone()).collect();
    let mut blocks: Vec<mpsc::Sender<BlockMsg>> =
        state.faces.iter().map(|f| f.block_tx.clone()).collect();
    // Face-level block arena passed through with the face index (None =
    // fallback to direct allocation).
    let mut arenas: Vec<Option<Arc<taiji_io::block_arena::BlockArena>>> =
        state.faces.iter().map(|f| f.block_arena.clone()).collect();
    let mut senders: Vec<BlockSenders> = state
        .faces
        .iter()
        .map(|f| f.block_senders.clone())
        .collect();
    let pid = dial.peer_id;
    let reg = dial.reg_tx.clone();
    let leave = dial.leave_tx.clone();
    let parent = token.clone();
    let mut avail = dial.avail_tx_face.clone();
    let srcs = state.seeding_sources.clone();
    let hash_srcs = state.seeding_hash_sources.clone();
    // Face-level read pools: resolved per face at attach (the same shape as
    // srcs — matched is only known after sniffing, so per-face slots are
    // pre-cloned).
    let mut read_pools: Vec<Option<Arc<taiji_bt::peer::ReadPool>>> =
        state.faces.iter().map(|f| f.read_pool.clone()).collect();
    let ext = dial.ext.clone();
    // -6: the `v` field identity re-check callback (inbound connections
    // get the same verdict as outbound).
    let client_deny = dial.client_deny.clone();
    // holepunch wiring resolved at attach (gate open ∧ channel present).
    let holepunch = dial.holepunch_attach();
    let vio = dial.violation_tx.clone();
    // Arrival-event sender (an engine-level single channel, injected at attach; the TCP-arm shape).
    let ledger = dial.ledger_tx.clone();
    let guard = state.ban_book.guard.clone();
    let addr = peer_addr;
    let cuid = state.next_cuid;
    state.next_cuid += 1;
    // Direct-connect seam: mint a sink per face (the same discipline as the TCP arm).
    let mut sinks: Vec<Option<std::sync::Arc<dyn taiji_bt::peer::BlockSink>>> =
        state.faces.iter().map(|f| f.block_sink_for(cuid)).collect();
    let policy = dial.crypto;
    let dht_attach = dial.attach_dht.get();
    let limiter = dial.limiter.clone();
    state.tasks.spawn(async move {
        // The inbound sniff/demux works identically on the µTP byte stream
        // (the first byte decides legacy vs MSE; require-crypto rejects
        // legacy). The listener has already completed the SYN handshake
        // (SynRecv answers ST_STATE); this module only does the BT-layer
        // handshake.
        match mse::accept_any(utp_stream, &pid, &candidates, policy, MSE_HANDSHAKE_TIMEOUT).await {
            Ok(accepted) => {
                let mse::Accepted {
                    stream,
                    matched,
                    handshake,
                    crypto: level,
                } = accepted;
                // Identity rule (at handshake completion; the same discipline as TCP inbound).
                if let Some(v) = client_violation(&guard, &handshake.peer_id, addr.ip()) {
                    debug!(target: "taiji::core::engine", %addr, reason = %v.reason,
                        "inbound utp peer rejected by identity rule ");
                    let _ = vio.send(v).await;
                    return;
                }
                debug!(target: "taiji::core::engine", %addr, ?level,
                    "inbound utp accepted");
                // Inbound throttles like outbound (the post-handshake
                // transport stream; read-path await permits = TCP/µTP window
                // backpressure).
                attach_peer(
                    Throttled::maybe(stream, limiter),
                    matched,
                    cuid,
                    addr,
                    // Inbound connection (getPeers port=0 semantics, aria2
                    // RpcMethodImpl.cc).
                    true,
                    handshake.peer_id,
                    level,
                    Transport::Utp,
                    addrings.swap_remove(matched),
                    pbytes.swap_remove(matched),
                    blocks.swap_remove(matched),
                    senders.swap_remove(matched),
                    sinks.swap_remove(matched),
                    ledger,
                    avail.swap_remove(matched),
                    reg,
                    leave,
                    srcs.into_iter().nth(matched).flatten(),
                    hash_srcs.into_iter().nth(matched).flatten(),
                    vio,
                    ext,
                    // -6: the `v` field identity re-check callback.
                    client_deny,
                    // holepunch wiring (resolved at attach).
                    holepunch,
                    // Face-level read pool for serve (face-shared).
                    read_pools.swap_remove(matched),
                    // Face-level block arena (None = fallback to direct allocation).
                    arenas.swap_remove(matched),
                    parent,
                    dht_attach,
                    // Peer DHT capability (BEP-5 reserved[7]&0x01): true ∧
                    // locally enabled → PORT sent after the handshake.
                    handshake.reserved.supports_dht(),
                    // BEP-10 negotiation gate (see the attach_peer note).
                    handshake.reserved.supports_extended(),
                    // BEP-6 fast negotiation mirror (the outbound Reject
                    // gate; attach_peer note).
                    handshake.reserved.supports_fast(),
                )
                .await;
            }
            Err(e) => {
                debug!(target: "taiji::core::engine", %peer_addr, %e,
                    "inbound utp handshake failed");
            }
        }
    });
    ControlFlow::Continue(())
}

/// BEP-19 webseed pseudo-peer assembly (called once before the `run()` main
/// loop starts): `BH_WEBSEED` on ∧ `urls` non-empty → per URL (dedup,
/// order-preserving + `BH_WEBSEED_MAX` truncation) spawn a
/// `tokio::io::duplex` pseudo-peer — the remote half is the wire responder
/// ([`webseed::WebseedResponder`]: Request → HTTP Range fetch → Piece), the
/// local half runs the outbound handshake + the full [`attach_peer`] chain
/// (register/interest/dispatch/delivery/leave come for free).
///
/// Face choice: v1 faces only (the webseed module note — a hybrid hangs it
/// on the v1 face; v2-only is skipped). cuid issuance = the inbound arm's
/// order (`next_cuid` increment; assembly precedes the main loop and all
/// dialing); issued cuids are pre-registered in
/// [`EngineLoop::webseed_cuids`] (a predicate-exemption face — the
/// turnover/slow-churn/stall rotations skip them: a CDN has unlimited
/// patience, slowness is transient, and no-alternative semantics do not
/// apply).
///
/// Synthetic PeerMeta choices: `inbound=true` (the leave arm's redial
/// admission naturally skips it — webseeds cannot be BT-redialed, preventing
/// redial-pool pollution; PEX fresh-candidate bookkeeping is likewise
/// waived); ip = `127.0.0.(2+i)` increasing in the loopback segment (≤ 8, no
/// collision with the common real-peer 127.0.0.1/::1 forms; the registration
/// path bypasses dial hygiene — `addr_hygiene`/IpGuard are consumed only on
/// the dial/accept and Violation surfaces, and this assembly goes straight
/// to attach_peer → reg_tx, never triggering the self-connect/bogon filters;
/// the ban face books by cuid, the synthetic ip only feeds getPeers display
/// and hash-fail attribution); port = the URL port (default 80/443,
/// `webseed::url_endpoint_port`).
pub(super) fn attach_webseeds(
    urls: &[String],
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
) {
    if !webseed::webseed_enabled() || urls.is_empty() {
        return;
    }
    let Some(fi) = state
        .faces
        .iter()
        .position(|f| matches!(f.kind, FaceKind::V1))
    else {
        debug!(target: "taiji::core::engine::webseed", count = urls.len(),
            "webseeds skipped: no v1 face (v2-only torrent, BEP19 face out of scope)");
        return;
    };
    // Dedup order-preserving + cap truncation.
    let mut seen = std::collections::HashSet::new();
    let urls: Vec<&String> = urls
        .iter()
        .filter(|u| seen.insert(u.as_str()))
        .take(webseed::webseed_max_urls())
        .collect();
    for (i, url) in urls.iter().enumerate() {
        let cuid = state.next_cuid;
        state.next_cuid += 1;
        state.webseed_cuids.insert(cuid);
        // Face geometry/wiring snapshot (the face borrow ends inside the
        // block, never overlapping state mutation).
        let (
            info_hash,
            reserved,
            addressing,
            goffs,
            lens,
            pbytes,
            block_tx,
            block_senders,
            sink,
            block_arena,
            avail_tx,
        ) = {
            let face = &state.faces[fi];
            (
                face.info_hash,
                face.reserved,
                face.addressing.clone(),
                Arc::clone(&face.piece_goffs),
                face.piece_bytes.to_vec(),
                // Unsolicited block-coordinate upper-bound table (face-shared).
                face.piece_bytes.clone(),
                face.block_tx.clone(),
                face.block_senders.clone(),
                face.block_sink_for(cuid),
                face.block_arena.clone(),
                dial.avail_tx_face[fi].clone(),
            )
        };
        // Debug-build assembly invariant (the FaceConfig equal-length
        // guarantee, config.rs): both tables come from one piece count — a
        // divergence would route every missing-span piece down the failure
        // path (webseed.rs spawn_fetch's span-miss arm). Catch a broken
        // assembly at the source instead.
        debug_assert_eq!(
            goffs.len(),
            lens.len(),
            "webseed face tables diverged (piece_goffs vs piece_bytes)"
        );
        let peer_id = webseed::webseed_peer_id(url);
        let addr = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2 + i as u8)),
            webseed::url_endpoint_port(url),
        );
        // The production fetch implementation failed to build (TLS backend
        // etc.) → abandon this URL (warn).
        let fetch = match webseed::HttpRangeFetch::build() {
            Ok(f) => std::sync::Arc::new(f),
            Err(e) => {
                warn!(target: "taiji::core::engine::webseed",
                    url = %taiji_bt::tracker::redact_url_for_log(url), %e,
                    "webseed http client build failed (url skipped)");
                continue;
            }
        };
        let (local, remote) = tokio::io::duplex(webseed::WEBSEED_DUPLEX_BUF);
        // Responder (the remote half speaks wire; a child of the engine token).
        let wire =
            webseed::WebseedResponder::new(fetch, (*url).clone(), info_hash, peer_id, goffs, lens);
        let wire_token = token.child_token();
        tokio::spawn(wire.run(remote, wire_token));
        // Local half: outbound handshake (info_hash check) → the full
        // attach_peer chain. Throttled uses the same LimiterSet as the BT
        // face (approximation note: the HTTP fetch side has no real gate;
        // duplex backpressure propagation keeps the overshoot within the
        // 4-concurrent-piece cap + 32 MiB cache).
        let my_pid = dial.peer_id;
        let reg_tx = dial.reg_tx.clone();
        let leave_tx = dial.leave_tx.clone();
        let violation_tx = dial.violation_tx.clone();
        let ledger_tx = dial.ledger_tx.clone();
        let ext = dial.ext.clone();
        let limiter = dial.limiter.clone();
        let parent = token.clone();
        info!(target: "taiji::core::engine::webseed",
            url = %taiji_bt::tracker::redact_url_for_log(url), face = fi, cuid,
            peer_addr = %addr, "webseed pseudo-peer attached (duplex wire responder)");
        state.tasks.spawn(async move {
            match handshake_exchange(local, &info_hash, &my_pid, reserved, MSE_HANDSHAKE_TIMEOUT)
                .await
            {
                Ok((stream, theirs)) => {
                    attach_peer(
                        Throttled::maybe(stream, limiter),
                        fi,
                        cuid,
                        addr,
                        // inbound=true: redial/PEX surfaces skip it
                        // naturally (see the function doc).
                        true,
                        peer_id,
                        mse::CryptoLevel::Plain,
                        Transport::Tcp,
                        addressing,
                        pbytes,
                        block_tx,
                        block_senders,
                        sink,
                        ledger_tx,
                        avail_tx,
                        reg_tx,
                        leave_tx,
                        // Pure leecher view: the webseed never requests from
                        // us (no upload service/read pool); the hash service
                        // face is likewise absent (v1 has no hash request).
                        None,
                        None,
                        violation_tx,
                        ext,
                        // Identity re-check callback default (no ext
                        // handshake, so the `v` re-check is unreachable).
                        None,
                        // ut_holepunch neither advertised nor consumed (no ext bit in reserved).
                        None,
                        None,
                        block_arena,
                        parent,
                        // DHT wiring default: the pseudo-peer's reserved has
                        // no DHT bit → no PORT sent; the inbound PORT
                        // forward face is likewise not consumed.
                        None,
                        false,
                        // BEP-10 negotiation gate closed (transit.rs
                        // attach_peer's peer_ext param — no ext bit in the
                        // pseudo-peer reserved).
                        false,
                        // BEP-6 fast negotiation mirror = the handshake's
                        // actual value (the responder's reserved has only the
                        // fast bit, webseed.rs webseed_reserved — its HaveAll
                        // output requires fast to be advertised).
                        theirs.reserved.supports_fast(),
                    )
                    .await;
                }
                Err(e) => {
                    debug!(target: "taiji::core::engine::webseed", %e,
                        "webseed pseudo-peer handshake failed (responder gone?)");
                }
            }
        });
    }
}

/// Protocol-violation event arm: violation/flood → immediate ban + a hot
/// snapshot update + same-IP online disconnect (a message-level filter
/// point, event-driven); banned peers leave the redial pool.
pub(super) async fn handle_violation(v: Violation, state: &mut EngineLoop) {
    let violation_ip = v.ip;
    state
        .ban_book
        .violation(v, &mut state.faces, state.persist_shared.as_ref())
        .await;
    // Banned peers leave the redial pool (never redialed; covers the
    // leave-before-violation ordering — the admission arm's IpGuard check
    // covers the reverse direction).
    state.redial_pool.remove_ip(violation_ip);
}

/// DHT event arm: PeersFound → candidates into the table after dedup (the
/// same as the tracker arm); Persist → dht_state persistence (the autosave
/// cadence driven by the engine table). With DHT disabled the channel has no
/// sender (recv is always None → the arm is permanently disabled, never busy
/// under select).
pub(super) async fn handle_dht_event(
    ev: DhtEvent,
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    actual_port: u16,
) -> ControlFlow<(), ()> {
    match ev {
        DhtEvent::PeersFound {
            info_hash,
            face: kind,
            peers,
        } => {
            // Event-to-face routing: transport id + face kind double match
            // (v1 sha1 / v2 truncated sha256; no hit = a late event from an
            // expired announce, dropped).
            let fi = state.faces.iter().position(|f| {
                f.info_hash == info_hash
                    && matches!(
                        (f.kind, kind),
                        (FaceKind::V1, DhtSwarmKind::V1) | (FaceKind::V2, DhtSwarmKind::V2)
                    )
            });
            let Some(fi) = fi else {
                return ControlFlow::Break(());
            };
            // Connection admission gate (batch-level, the tracker-arm note: consumed before dedup).
            if !discovery_admission_open(state) {
                return ControlFlow::Continue(());
            }
            let now = Instant::now();
            for addr in peers {
                // Address hygiene (nodes/values can inject loopback /
                // link-local / multicast probing — the reject class includes
                // these; the tracker arm reuses the same single-point
                // decision).
                let Some(addr) = crate::addr_hygiene::sanitize_discovered_addr(addr) else {
                    debug!(target: "taiji::core::engine", raw = %addr,
                        "dht peer rejected by address hygiene ");
                    continue;
                };
                // Never connect to self (an extended decision, single-point
                // reuse of addr_hygiene, tracker-arm parity); duplicate peers
                // within the window do not re-dial (get_peers multi-source
                // replies + announce-period resends; minimal-intervention
                // connection management).
                if crate::addr_hygiene::is_self_endpoint(
                    addr,
                    actual_port,
                    crate::addr_hygiene::LocalIpSet::shared(),
                ) {
                    continue;
                }
                // Discovery count (DHT source; see
                // SessionMetrics::note_peer_discovered).
                if let Some(m) = metrics {
                    m.note_peer_discovered(false);
                }
                if !state.dht_dial_dedup.admit(addr, now) {
                    continue;
                }
                if state.faces[fi]
                    .peer_state
                    .values()
                    .any(|ps| ps.ip == Some(addr.ip()))
                {
                    debug!(target: "taiji::core::engine", %addr,
                        "dht peer already connected by ip: skipped");
                    continue;
                }
                // Candidate entry: DHT source rank = 1<<3 (libtorrent
                // request_blocks.cpp).
                super::ecology::push_candidate(
                    state,
                    addr,
                    fi,
                    super::ecology::DialSourceRank::Dht,
                    now,
                );
            }
        }
        DhtEvent::Persist {
            family,
            node_id,
            routing_table,
        } => {
            persist_dht_state(
                state.persist_shared.as_ref(),
                family,
                node_id,
                routing_table,
            )
            .await;
        }
    }
    ControlFlow::Continue(())
}

/// PEX immediate-dial switch (a fallback knob, the same pattern as ecology.rs
/// `utp_mute_enabled`): `BH_PEX_IMMEDIATE=0` restores the previous behavior
/// exactly (PEX candidates still enter the table and wait for the 250 ms
/// drain wheel); any other value (including unset) → immediate dialing. Read
/// at the PEX event arm (a per-event read — PEX frames arrive at most once
/// per 60 s per peer, not a hot path). Parse/read-timing registry:
/// `taiji_io::knobs` (read per event, uncached).
pub(crate) fn pex_immediate_enabled() -> bool {
    taiji_io::knobs::pex_immediate_enabled()
}

/// PEX immediate-dial gate (a pure function, driven directly by the
/// decision-table test — env stays out of this function; the
/// `pex_immediate_enabled` read is taken in the event arm and passed in):
/// switch on ∧ connected peers < the outbound target
/// ([`super::state::peer_connections_target`], the `BH_PEER_TARGET`
/// override, default 100) → dial immediately.
///
/// Pool full (`registered ≥ target`) → table only, no dial — left to the
/// drain wheel's normal cadence. The demand gate sits on the immediate face,
/// not inside the spawn (avoiding changes to the [`spawn_peer_dial`]
/// semantics shared by the drain wheel/redial/punch): the immediate face is
/// an express lane that removes queueing latency, meaningless when the pool
/// is already full. The arm-entry batch admission gate
/// ([`discovery_admission_open`], the leecher target gate + slow-download
/// relief) runs first; this gate is a stricter independent check on the
/// express lane (within the relief band registered may exceed target — there
/// the express lane closes and relief backfill still goes through the drain
/// wheel; the express lane never overrides the cadence surface).
pub(crate) fn pex_immediate_gate(enabled: bool, registered: usize, target: usize) -> bool {
    enabled && registered < target
}

/// Inbound ut_pex event arm: discovered peers → the candidate table (the
/// same consumption path as DhtEvent::PeersFound; the upstream anchor is
/// aria2 `UTPexExtensionMessage::doReceivedAction` in UTPexExtensionMessage.cc
/// — both fresh/dropped enter PeerStorage, so both lists feed the dial
/// decision) + immediate dialing (pool not full ∧ switch on → spawn right
/// after the table insert). A closed channel (no sender when the pex gate is
/// off) → the arm is permanently disabled (never busy under select).
pub(super) fn handle_pex_event(
    ev: PexEvent,
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
    metrics: Option<&SessionMetrics>,
    actual_port: u16,
) -> ControlFlow<(), ()> {
    let Some(fi) = state
        .faces
        .iter()
        .position(|f| f.peer_cuids.contains(&ev.from))
    else {
        debug!(target: "taiji::core::engine", cuid = ev.from,
            "ut_pex from unknown peer: dropped");
        return ControlFlow::Break(());
    };
    // Connection admission gate (batch-level, the tracker/DHT-arm note: consumed before dedup).
    if !discovery_admission_open(state) {
        return ControlFlow::Continue(());
    }
    let now = Instant::now();
    // Address hygiene: fresh addresses pass the single-point check before
    // entering introducer bookkeeping — bogon/mapped forms must not enter
    // hp_book (a derived key of the rendezvous query face); dropped addresses
    // are filtered the same way.
    let fresh: Vec<SocketAddr> = ev
        .fresh
        .iter()
        .filter_map(|a| crate::addr_hygiene::sanitize_discovered_addr(*a))
        .collect();
    let dropped: Vec<SocketAddr> = ev
        .dropped
        .iter()
        .filter_map(|a| crate::addr_hygiene::sanitize_discovered_addr(*a))
        .collect();
    // Introducer bookkeeping (first-wins): a fresh address records the
    // delivering connection's cuid — if a direct connection to it fails
    // later, the rendezvous query targets that connection (find_introducer
    // bookkeeping, libtorrent torrent.cpp). dropped addresses are not booked
    // (not dial candidates).
    for addr in &fresh {
        state.hp_book.note_introduced(*addr, ev.from, now);
    }
    // Immediate-dial gate (a batch-level verdict: registered/switch/target
    // cannot change between addresses inside the single-writer synchronous
    // loop, so per-address re-checking is pure redundancy — the same note as
    // discovery_admission_open).
    let immediate = pex_immediate_gate(
        pex_immediate_enabled(),
        state.registered_peers(),
        super::state::peer_connections_target(),
    );
    for addr in fresh.into_iter().chain(dropped) {
        // Never connect to self (an extended decision, single-point reuse of
        // addr_hygiene; the same guard as tracker/DHT).
        if crate::addr_hygiene::is_self_endpoint(
            addr,
            actual_port,
            crate::addr_hygiene::LocalIpSet::shared(),
        ) {
            continue;
        }
        // Discovery count (an engine-level contribution observation point):
        // after the self-connect guard, before dedup — discovery ≠ connect
        // success.
        if let Some(m) = metrics {
            m.note_peer_discovered(true);
        }
        // Duplicate addresses within the window do not re-dial (multiple
        // peers re-announcing the same peer); shares the DHT source's dedup
        // table (source-agnostic).
        if !state.dht_dial_dedup.admit(addr, now) {
            continue;
        }
        // The same-IP check is a linear scan over the face: O(connections)
        // per address. Per-frame address counts are already capped twice
        // (decode caps fresh/dropped at ≤50 each + a per-connection frame
        // rate of 4/60s), so the scan's total bound = 100 addresses ×
        // connections; converting peer_ips to a HashSet (an ip → cuid
        // reverse index) is a performance refactor deliberately not done
        // here.
        if state.faces[fi]
            .peer_state
            .values()
            .any(|ps| ps.ip == Some(addr.ip()))
        {
            debug!(target: "taiji::core::engine", %addr,
                "pex peer already connected by ip: skipped");
            continue;
        }
        // Candidate entry: PEX source rank = 1<<2 (libtorrent
        // request_blocks.cpp).
        super::ecology::push_candidate(state, addr, fi, super::ecology::DialSourceRank::Pex, now);
        // PEX immediate dial: removes the 250 ms drain-wheel batching delay
        // (anchor: rqbit dials PEX/table-discovered new peers immediately,
        // peer state queued→dialing with no periodic batching delay; the
        // event-driven direct-dial precedent = punch_dial in run::holepunch,
        // spawned directly in the event arm, not queued). Table insert
        // precedes the spawn: if the spawn is exhausted the candidate is
        // already in the table and the drain wheel backstops (mirroring
        // rqbit's "boost first, stop dialing regular candidates when quota
        // is out"); the table removal happens only on spawn success — an
        // in-flight dial is not yet registered, so the same-IP check cannot
        // see it, and leaving it in the table would re-dial the same address
        // 250 ms later (a wasted duplicate connection). Source = Discovery
        // (shared with the drain wheel): the silent-ledger gate, the
        // token-bucket spend and the silent-failure re-push inside
        // `spawn_peer_dial` all apply automatically — zero duplication in
        // this arm. Immediate-dial safety bound: one PEX frame per peer per
        // ≥60 s (DEFAULT_INTERVAL, taiji-bt pex/message.rs, tightened by a
        // per-connection 4/60s rate limit) and ≤50 fresh/dropped each (decode
        // rejects over-limit frames wholesale) → at most 100 addresses per
        // frame, naturally capped by the 30/s token bucket — exhaustion just
        // falls back to the drain-wheel cadence, no new burst surface.
        if immediate {
            let spawned = spawn_peer_dial(
                state,
                dial,
                token,
                fi,
                addr,
                super::state::DialSource::Discovery,
                state.seeding_sources[fi].clone(),
                state.seeding_hash_sources[fi].clone(),
            );
            if spawned {
                // Now dialing: out of the table (remove is idempotent — a
                // no-op if the table refused the insert).
                state.dial_candidates.remove(&addr);
                debug!(target: "taiji::core::engine", face = fi, %addr,
                    registered = state.registered_peers(),
                    "pex immediate dial (new peer, no drain-wheel latency)");
            } else {
                debug!(target: "taiji::core::engine", face = fi, %addr,
                    "pex immediate dial skipped (silent book / budget); \
                     candidate stays for drain wheel");
            }
        }
    }
    ControlFlow::Continue(())
}

/// Redial sweep arm (a 2 s cadence; the pool dequeues at most
/// REDIAL_SWEEP_BATCH per sweep, non-busy rounds): re-dial known-reachable
/// peers when due — backfill for the discovery surface during the
/// announce-interval (1800 s) gap. Announce semantics unchanged (out of
/// scope); dialing follows the same IpGuard/handshake discipline as the
/// regular path.
pub(super) fn handle_redial_sweep(
    state: &mut EngineLoop,
    dial: &DialCtx,
    token: &CancellationToken,
    metrics: Option<&SessionMetrics>,
) {
    for (fi, addr) in state.redial_pool.due(Instant::now()) {
        if let Some(block) = state.ban_book.guard.load().blocks(addr.ip(), epoch_secs()) {
            debug!(target: "taiji::core::engine", %addr, block = %block,
                "redial skipped by IpGuard: pool entry dropped");
            state.redial_pool.remove_ip(addr.ip());
            continue;
        }
        let Some(face) = state.faces.get(fi) else {
            // Face gone (defensive; faces can shrink at runtime) → drop the entry.
            state.redial_pool.note_connected(&addr);
            continue;
        };
        if face.peer_state.values().any(|ps| ps.ip == Some(addr.ip())) {
            // Same IP already connected (including the peer having
            // reconnected via another path) → drop the entry; it re-registers
            // via the admission arm on the next leave.
            state.redial_pool.note_connected(&addr);
            continue;
        }
        debug!(target: "taiji::core::engine", face = fi, %addr,
            pool = state.redial_pool.len(), "redial due");
        if let Some(m) = metrics {
            m.note_redial_attempt();
        }
        spawn_peer_dial(
            state,
            dial,
            token,
            fi,
            addr,
            // Redial source: carries the report sender; exempt from the
            // silent-ledger gate (as-is, see state::DialSource docs).
            super::state::DialSource::Redial(dial.redial_tx.clone()),
            state.seeding_sources[fi].clone(),
            state.seeding_hash_sources[fi].clone(),
        );
    }
}

/// Redial report arm (redial module docs): success → remove; a ban
/// interception → remove; failure → backoff/eviction (a failing peer never
/// holds a slot permanently).
pub(super) fn handle_redial_report(
    report: RedialReport,
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
) {
    debug!(target: "taiji::core::engine", addr = %report.addr,
        outcome = ?report.outcome, "redial outcome");
    match report.outcome {
        DialOutcome::Connected => {
            if let Some(m) = metrics {
                m.note_redial_connected();
            }
            state.redial_pool.note_connected(&report.addr);
        }
        DialOutcome::Blocked => state.redial_pool.remove_ip(report.addr.ip()),
        DialOutcome::Failed => {
            state.redial_pool.note_result(
                &report.addr,
                taiji_domain::redial::RedialOutcome::Failed,
                Instant::now(),
            );
        }
    }
}

/// Inbound PORT event arm (BEP-5; the `BtPortMessage.cc` semantics with
/// port=0 filtering already done at the peer layer): a cuid is globally
/// unique → locate the peer IP across faces and feed AddPortNode to the
/// matching family engine (node ping / single-bucket node_lookup driven by
/// the engine).
pub(super) async fn handle_dht_port(
    ev: (u64, u16),
    state: &mut EngineLoop,
    dht_wiring: &[DhtFamilyWiring],
) -> ControlFlow<(), ()> {
    let (cuid, port) = ev;
    let located = state
        .faces
        .iter()
        .find_map(|f| f.peer_state.get(&cuid).and_then(|ps| ps.ip));
    let Some(ip) = located else {
        debug!(target: "taiji::core::engine", cuid,
            "PORT from unknown peer: dropped");
        return ControlFlow::Break(());
    };
    let target_family = if ip.is_ipv4() {
        DhtFamily::V4
    } else {
        DhtFamily::V6
    };
    for w in dht_wiring {
        if w.family == target_family {
            if let Err(e) = w.handle.add_port_node(ip, port).await {
                debug!(target: "taiji::core::engine", %e,
                    "AddPortNode failed (dht actor down)");
            }
        }
    }
    ControlFlow::Continue(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Log-capture writer (the sink subscribed via the thread-local set_default).
    #[derive(Clone, Default)]
    struct CaptureBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureBuf {
        type Writer = CaptureBuf;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// Periodic summary: zero-window driving → each note flushes one window
    /// summary (the ok count + failure-class histogram); an empty window logs
    /// nothing.
    #[test]
    fn dial_summary_window_aggregates() {
        let buf = CaptureBuf::default();
        use tracing_subscriber::util::SubscriberInitExt as _;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish()
            .set_default();
        let sampler = DialLogSampler::with_window(Duration::ZERO);
        sampler.note_result(true, "ok");
        sampler.note_result(true, "ok");
        sampler.note_result(false, "connect-refused");
        // The next note flushes the previous window's summary (ok=2, fail=1, connect-refused).
        sampler.note_result(true, "ok");
        let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(text.contains("dial summary"), "got: {text}");
        assert!(text.contains("connect-refused"), "got: {text}");
        assert!(text.contains("fail=1"), "got: {text}");
    }

    /// No summary line before the window ends (many counts inside a large window, zero output).
    #[test]
    fn dial_summary_silent_before_window_end() {
        let buf = CaptureBuf::default();
        use tracing_subscriber::util::SubscriberInitExt as _;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish()
            .set_default();
        let sampler = DialLogSampler::with_window(Duration::from_secs(3600));
        sampler.note_result(true, "ok");
        sampler.note_result(false, "connect-refused");
        let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !text.contains("dial summary"),
            "window not yet due: no summary should be emitted: {text}"
        );
    }

    /// Dial io failure-class table.
    #[test]
    fn connect_io_class_table() {
        use std::io::ErrorKind;
        assert_eq!(
            classify_connect_io(ErrorKind::ConnectionRefused),
            "connect-refused"
        );
        assert_eq!(classify_connect_io(ErrorKind::TimedOut), "connect-timeout");
        assert_eq!(
            classify_connect_io(ErrorKind::NetworkUnreachable),
            "connect-error"
        );
    }

    /// Immediate-dial gate decision table: on ∧ connected < target → dial;
    /// pool full (`registered ≥ target`, including the relief-band overshoot)
    /// → table only. Behavioral tests (table removal, task creation, cuid
    /// issuance after spawn) would need a fully wired EngineLoop + DialCtx
    /// (~60 fields, no lightweight constructor outside the assemble stage) —
    /// not worth the assembly cost: the pure-function decision table pins the
    /// gate semantics, the wiring order is covered by `handle_pex_event`
    /// (the spawn/table-removal order), and the full-chain behavior is
    /// covered by the existing PEX→dial tests in tests/pex_engine.rs.
    #[test]
    fn pex_immediate_gate_decision_table() {
        // On ∧ empty pool → dial (the ramp-up shape: peer-starved first minutes).
        assert!(pex_immediate_gate(true, 0, 100));
        // On ∧ just under target → dial (strictly less; the pool may top
        // out mid-dial, next frame the gate closes).
        assert!(pex_immediate_gate(true, 99, 100));
        // On ∧ pool full (= target) → no dial (left to the drain wheel's cadence).
        assert!(!pex_immediate_gate(true, 100, 100));
        // On ∧ relief-band overshoot (registered > target) → no dial.
        assert!(!pex_immediate_gate(true, 150, 100));
        // The same verdict under the BH_PEER_TARGET override.
        assert!(pex_immediate_gate(true, 50, 51));
        assert!(!pex_immediate_gate(true, 51, 51));
    }

    /// `BH_PEX_IMMEDIATE=0` equivalence (parameterized as enabled=false in
    /// the pure function, not process env — the `pex_immediate_enabled` read
    /// seam is independent): every (registered, target) combination yields
    /// zero immediate spawns — candidates still enter the table and wait for
    /// the 250 ms drain wheel (the previous behavior pinned exactly).
    #[test]
    fn pex_immediate_gate_disabled_is_zero_spawn() {
        for registered in [0usize, 1, 50, 99, 100, 150, 300] {
            for target in [1usize, 51, 100, 120] {
                assert!(
                    !pex_immediate_gate(false, registered, target),
                    "enabled=false must zero immediate spawns: registered={registered} target={target}"
                );
            }
        }
    }
}

//! Outbound dial/handshake/connection-attach transport face: `Transit`
//! (plain | MSE-flattened carrier), `DialJob`/`UtpDial`/`dial_tcp`/
//! `peer_connect`/`handshake_over`, and `attach_peer` (PeerTask spawn ->
//! registration -> block aggregation forwarding).
//!
//! Covers: transport negotiation and peer-task assembly after the
//! connect point (shared by outbound and inbound). Does not cover: dial
//! sourcing (tracker/DHT/PEX/redial feed the run main loop), inbound
//! accept (run main loop), redial outcome accounting (redial).
//!
//! Upstream anchor mapping: docs/design/engine.md.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use bytes::Bytes;

use taiji_bt::mse::{self, CryptoLevel, CryptoPolicy, Encrypted};
use taiji_bt::peer::AvailEvent;
use taiji_bt::peer::{
    BlockSink, HashSource, PeerConfig, PeerEnd, PeerHandle as _, PeerTask, PieceSource,
    handshake_exchange,
};
use taiji_bt::peer_policy::{IpGuardHandle, Violation};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::{Addressing, PieceId};
use taiji_bt::utp::{PeerConnectionType, Transport, dial_plan};
use taiji_io::rate_limit::{LimiterSet, Throttled};
use taiji_io::utp::UtpStream;

use crate::ban::{client_violation, violation_of};
use crate::dispatch::{LEDGER_ARRIVALS, LEDGER_DEGRADES, LedgerArrival, two_phase_ledger};
use crate::faces::{PeerMeta, PeerRegistration};
use crate::pipeline::{BlockMsg, BlockSenders};
use crate::redial::{DialOutcome, RedialReport, redial_report};
use crate::tracker::epoch_secs;
/// MSE/handshake budget (10s, the same tier as the outbound connect /
/// handshake budget — a local policy value matching the existing
/// [`peer_connect`] connect-timeout baseline). On MSE failure with
/// legacy fallback, a fresh TCP connection is dialed
/// (`InitiatorMSEHandshakeCommand.cc`): the bytes of a connection whose
/// negotiation failed cannot be reused.
pub(super) const MSE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// DHT wiring for the attach phase (None = DHT not enabled).
#[derive(Clone)]
pub(super) struct AttachDht {
    /// Our DHT UDP port (sent after the handshake when the peer's
    /// reserved bytes declare DHT, `DefaultBtInteractive.cc`).
    pub(super) local_port: u16,
    /// Inbound PORT forwarding ((cuid, port) -> engine -> AddPortNode;
    /// cuid is globally unique, so the engine main loop locates the
    /// peer's IP across faces by it).
    pub(super) port_tx: mpsc::Sender<(u64, u16)>,
}

/// Post-handshake outbound stream (the transport-generalized carrier):
/// a successful MSE negotiation = an `Encrypted` wrapper; a plain legacy
/// connection = the transport stream as-is. The two arms have different
/// types — the enum flattening avoids boxing the hot read loop. Carrier
/// `S` = TCP (`TcpStream`) or uTP ([`UtpStream`], BEP29) — the
/// `PeerTransport` seam shape stays frozen (callers/PeerTask are
/// transport-agnostic; `attach_peer` is generic over it).
pub(super) enum Transit<S> {
    Plain(S),
    /// Box-flattened size gap (`Encrypted` carries 2x256B ARC4 state
    /// plus a read scratch; the same shape as bt::mse::PeerStream).
    Mse(Box<Encrypted<S>>),
}

impl<S: AsyncRead + Unpin> AsyncRead for Transit<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transit::Plain(s) => std::pin::pin!(s).poll_read(cx, out),
            Transit::Mse(s) => std::pin::pin!(s.as_mut()).poll_read(cx, out),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Transit<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Transit::Plain(s) => std::pin::pin!(s).poll_write(cx, buf),
            Transit::Mse(s) => std::pin::pin!(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transit::Plain(s) => std::pin::pin!(s).poll_flush(cx),
            Transit::Mse(s) => std::pin::pin!(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Transit::Plain(s) => std::pin::pin!(s).poll_shutdown(cx),
            Transit::Mse(s) => std::pin::pin!(s.as_mut()).poll_shutdown(cx),
        }
    }
}
/// Per-connection block direct-delivery sink (data-plane bypass,
/// core-side): minted per connection by the
/// [`crate::faces::FaceState::block_sink_for`] factory — captures the
/// face addressing, this connection's cuid, the attribution
/// bookkeeping, a clone of the face block channel, and the
/// pre-registration counter. `deliver` = `to_flat` flat-index
/// conversion + out-of-range skip with warn (the old forward path's
/// behavior) + a `block_senders` attribution insert (overwrite on
/// same-coordinate re-receipt = last arrival wins; lock discipline
/// unchanged) + the pre-registration counter increment + `block_tx`
/// enqueue.
///
/// Deliberate difference from the old forward path: the attribution
/// insert and the counter increment happen only AFTER a successful
/// enqueue — on a full channel the payload is returned to the caller
/// for the backpressure slow path with no partial registration (the
/// old path inserts then sends; a failed send means the engine is about
/// to fail-exit with no observer, while here full-then-retry is the
/// normal path and partial registration would corrupt the
/// last-arrival-wins record). The engine read points
/// (take_block_senders/take_block_sender) and the key/value semantics
/// are unchanged.
///
/// Reference: libtorrent `peer_connection::incoming_piece`
/// (src/peer_connection.cpp) hands a received block straight to
/// `m_disk_thread.async_write` on the receive thread — this type is
/// the tokio isomorph of that receive-point hand-off; the bounded face
/// channel (capacity 256, the prior figure) crossing the task boundary
/// is an intentional divergence (single network thread -> two tokio
/// tasks), see the [`BlockSink`] seam docs. More upstream anchors:
/// docs/design/engine.md.
pub(super) struct FaceBlockSink {
    pub(super) addressing: Addressing,
    pub(super) cuid: u64,
    pub(super) block_senders: BlockSenders,
    pub(super) block_tx: mpsc::Sender<BlockMsg>,
    pub(super) inflight: Arc<AtomicU64>,
}

impl FaceBlockSink {
    /// Flat piece-index conversion + out-of-range defense (the old
    /// forward path's behavior: skip the block with a warn without
    /// dropping the connection — a peer protocol violation already
    /// disconnects at the bt-side `from_wire`; this only guards the
    /// addressing-conversion failure face).
    fn to_flat(&self, id: PieceId) -> Option<u32> {
        self.addressing
            .to_flat(id)
            .and_then(|i| u32::try_from(i).ok())
    }

    /// Attribution insert (the old forward path's lock discipline and
    /// overwrite semantics) + pre-registration counter increment.
    fn pre_register(&self, index: u32, begin: u32) {
        {
            let mut senders = crate::lock(&self.block_senders);
            senders.insert((index, begin), self.cuid);
        }
        self.inflight
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Counter rollback when the enqueue fails (pipeline dead = the
    /// engine is about to fail-exit) — attribution entries are not
    /// rolled back (the old path's failed-send semantics; the engine
    /// has no observer).
    fn rollback_inflight(&self) {
        self.inflight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl BlockSink for FaceBlockSink {
    fn try_deliver(&self, id: PieceId, begin: u32, block: Bytes) -> Result<(), Bytes> {
        let Some(index) = self.to_flat(id) else {
            warn!(target: "taiji::core::engine", piece = ?id,
                "piece id outside addressing: block skipped");
            // Defensive skip = consumed (the old path's continue), not backpressure.
            return Ok(());
        };
        match self.block_tx.try_send((index, begin, block)) {
            Ok(()) => {
                self.pre_register(index, begin);
                Ok(())
            }
            // Channel full: counter not registered, payload returned
            // as-is -> the caller takes the backpressure slow path.
            Err(mpsc::error::TrySendError::Full((_, _, block))) => Err(block),
            Err(mpsc::error::TrySendError::Closed((_, _, _))) => {
                // Store pipeline dead (engine about to fail-exit):
                // drop silently (the old path's failed-send break
                // semantics — no join wait, to avoid hanging).
                Ok(())
            }
        }
    }

    fn deliver_backpressure(
        &self,
        id: PieceId,
        begin: u32,
        block: Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let Some(index) = self.to_flat(id) else {
                warn!(target: "taiji::core::engine", piece = ?id,
                    "piece id outside addressing: block skipped");
                return;
            };
            self.pre_register(index, begin);
            if self.block_tx.send((index, begin, block)).await.is_err() {
                self.rollback_inflight();
            }
        })
    }
}

/// Connection leave reason (the connection-retention observation
/// face): the engine-side five-way projection of
/// [`taiji_bt::peer::PeerEnd`] — the leave event carries it and
/// `handle_peer_left` feeds the `taiji_peer_leaves_total{reason}`
/// counter family. Closed set:
/// - `Local`: we disconnected (PeerEnd::Clean — turnover rotation /
///   stall-valve seeder rotation / same-IP ban disconnect / engine
///   shutdown, all command points);
/// - `PeerClosed`: the peer closed normally (EOF) — the peer-side
///   main class of connection-table loss;
/// - `Io`: transport-layer errors (RST / the uTP timeout give-up
///   family — the timeout carrier; io error strings are not
///   subdivided, timeout-vs-reset attribution belongs to the log
///   face);
/// - `Protocol`: protocol-face disconnects (violation / flooding —
///   we disconnected for protocol reasons; the ban face keeps its
///   own counters, this class is the connection-table attribution);
/// - `Cancelled`: engine shutdown cancellation (not churn; excluded
///   from diagnostics denominators).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaveKind {
    Local,
    PeerClosed,
    Io,
    Protocol,
    Cancelled,
}

/// The `PeerConnectionType` option-value strings (SPEC §6.1/§11
/// domain: tcp|utp|prefer-utp|prefer-tcp). The single source lives
/// engine-side (the transit dial-observation label and the
/// session-options echo share one literal table — the session options
/// side consumes it via re-export; a second match is forbidden to
/// prevent domain drift).
pub fn peer_connection_type_str(t: PeerConnectionType) -> &'static str {
    match t {
        PeerConnectionType::Tcp => "tcp",
        PeerConnectionType::Utp => "utp",
        PeerConnectionType::PreferUtp => "prefer-utp",
        PeerConnectionType::PreferTcp => "prefer-tcp",
    }
}

impl LeaveKind {
    /// Terminal-state projection ([`taiji_bt::peer::PeerEnd`] -> five
    /// classes; the mapping table is locked by a unit test). The
    /// /metrics label set = the closed five classes
    /// (`taiji_peer_leaves_total{reason}`, rendered by the taiji-rpc
    /// metrics.rs literal table — across the crate boundary the label
    /// contract's single source is the
    /// [`crate::metrics::MetricsSnapshot`] field docs).
    pub(crate) fn of(end: &taiji_bt::peer::PeerEnd) -> LeaveKind {
        use taiji_bt::peer::PeerEnd;
        match end {
            PeerEnd::Clean => LeaveKind::Local,
            PeerEnd::Cancelled => LeaveKind::Cancelled,
            PeerEnd::Closed => LeaveKind::PeerClosed,
            PeerEnd::Io { .. } => LeaveKind::Io,
            PeerEnd::Violation(_) | PeerEnd::Flooded => LeaveKind::Protocol,
        }
    }
}

/// Post-handshake connection attach: PeerTask spawn -> interested
/// [-> PORT] -> register back to the engine -> block-data aggregation
/// forwarding (shared by outbound/inbound; PieceId is converted to the
/// flat piece index through the face addressing).
///
/// PeerEnd observation (violation/flooded -> a Violation event for the
/// core to book and ban immediately) + block-sender attribution
/// bookkeeping (on hash failure, aggregated to the IP through this).
/// `peer_dht` (the peer's reserved bytes declare) AND `dht` (locally
/// enabled) -> send PORT after the handshake
/// (`DefaultBtInteractive.cc`); an inbound PORT is forwarded via
/// `port_tx` to the engine -> AddPortNode.
///
/// With `block_sink` present the data arm is NOT wired (the direct
/// delivery seam hands blocks to the face channel within the same
/// task, removing the intermediate forward task); the forward loop
/// keeps only the cancel/join arms to observe the connection's
/// terminal state. `None` = the old path as-is (both paths coexist
/// for one milestone for A/B and rollback).
#[expect(
    clippy::too_many_arguments,
    reason = "the attach takes the full negotiated identity; both delivery paths coexist (see doc)"
)]
pub(super) async fn attach_peer<S>(
    stream: S,
    face: usize,
    cuid: u64,
    addr: SocketAddr,
    inbound: bool,
    peer_id: [u8; 20],
    crypto: CryptoLevel,
    transport: Transport,
    addressing: Addressing,
    // Upper bound for unsolicited block coordinates at the accept
    // arm (face-shared table).
    piece_bytes: std::sync::Arc<[u64]>,
    block_tx: mpsc::Sender<BlockMsg>,
    block_senders: BlockSenders,
    block_sink: Option<Arc<dyn BlockSink>>,
    // Block-arrival event sender (the main-loop arrival arm; not
    // emitted while the switch is off).
    ledger_tx: mpsc::Sender<LedgerArrival>,
    avail_tx: mpsc::Sender<AvailEvent>,
    reg_tx: mpsc::Sender<PeerRegistration>,
    leave_tx: mpsc::Sender<(usize, u64, LeaveKind)>,
    source: Option<Arc<dyn PieceSource>>,
    hash_source: Option<Arc<dyn HashSource>>,
    violation_tx: mpsc::Sender<Violation>,
    ext: taiji_bt::peer::ExtConfig,
    // Ext handshake `v` field identity re-check callback (None = no
    // re-check).
    client_deny: Option<taiji_bt::peer::ClientDenyCheck>,
    // ut_holepunch wiring (None/switch off = neither advertised nor
    // consumed). Shared by outbound/inbound attach (relay and hole
    // punching can occur on connections in either direction).
    holepunch: Option<taiji_bt::peer::HolepunchExt>,
    // Face-level read pool: moves serve disk reads out of the peer
    // event loop (None = the inline form — unit tests / the metadata
    // face).
    read_pool: Option<Arc<taiji_bt::peer::ReadPool>>,
    // Face-level block arena (None = fall back to direct
    // allocation) — passed through to PeerConfig.
    block_arena: Option<Arc<taiji_io::block_arena::BlockArena>>,
    parent: CancellationToken,
    dht: Option<AttachDht>,
    peer_dht: bool,
    peer_ext: bool,
    // BEP6 fast negotiation mirror (the peer's handshake
    // reserved[7]&0x04): the negotiation gate for outbound Reject
    // (`PeerConfig::peer_fast`; rationale at the bt-side
    // `OutboundWriter::send_reject`) — the same pipeline as
    // peer_dht/peer_ext, passed through from the peer's handshake
    // bits.
    peer_fast: bool,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Per-peer counters (the getPeers speed data source): the
    // PeerConfig counter face = per-connection atomics; torrent-level
    // session totals are bridged from the deltas by the main loop's
    // 1s tick (see [`drain_peer_counters`] — the announce/
    // stop-timeout/persistence readings are unchanged, only a <=1s
    // granularity is introduced).
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    // The peer's BEP21 upload_only inbound mirror (the peer-profile
    // seed flag): one Arc shared by the PeerConfig write face (stored
    // on PeerTask handle_extended) and the PeerMeta read face — the
    // same pipeline as the up/down counters.
    let upload_only = Arc::new(AtomicBool::new(false));
    // BEP10 negotiation gate (real-swarm interop fix): when the
    // peer's handshake reserved[5]&0x10 does not declare the
    // extension face, our ext handshake must not be sent — aria2 only
    // queues it when `peer_->isExtendedMessagingEnabled()` (the
    // peer's handshake bit, `DefaultBtInteractive.cc`
    // `doPostHandshakeProcessing`). Sending unconditionally is a
    // protocol violation: real Canonical seedboxes (the only answering
    // peer on torrent.ubuntu.com) FIN immediately on an unnegotiated
    // ext handshake, killing the download face on real swarms.
    let mut ext = ext;
    ext.enabled = ext.enabled && peer_ext;
    // Direct-delivery bypass form: with the sink present the data arm
    // is not wired (the recv arm is disabled by a boolean gate — the
    // select topology is unchanged, only the arm value is guarded),
    // and the forward loop degenerates to cancel/join terminal-state
    // observation.
    let direct = block_sink.is_some();
    let config = PeerConfig {
        addressing: addressing.clone(),
        piece_bytes,
        direct_block_sink: block_sink,
        source,
        hash_source,
        cuid,
        avail_tx: Some(avail_tx),
        port_tx: dht.as_ref().map(|d| d.port_tx.clone()),
        uploaded: Some(Arc::clone(&up)),
        downloaded: Some(Arc::clone(&down)),
        peer_upload_only: Some(Arc::clone(&upload_only)),
        // PEX outbound-candidate filter: exclude the peer's own
        // address (the aria2 `peer_->getIPAddress()` comparison).
        remote_ip: Some(addr.ip()),
        ext,
        // Identity re-check of the `v` field (the callback when the
        // peer's ext handshake arrives).
        client_deny,
        // ut_holepunch advertise/consume wiring (None = gate off).
        holepunch,
        // Face-level read pool: inbound-request disk reads go through
        // pooled spawn_blocking — zero blocking syscalls in the peer
        // event loop.
        read_pool,
        // Face-level block arena (None = fall back to direct
        // allocation).
        block_arena,
        // BEP6 fast negotiation mirror (the outbound Reject gate).
        peer_fast,
        ..PeerConfig::flat()
    };
    let (handle, mut join, mut data_rx) = PeerTask::spawn(&parent, stream, config);
    // interested (BEP3: the precondition for requests); the handle is
    // then handed to the engine via registration.
    let _ = handle.command(taiji_bt::peer::PeerCommand::SendInterest);
    // PORT (BEP5): sent when our DHT is enabled and the peer's
    // handshake reserved[7]&0x01 declares support (the aria2
    // `peer_->isDHTEnabled() && dhtEnabled_` test).
    if let (Some(d), true) = (&dht, peer_dht) {
        let _ = handle.command(taiji_bt::peer::PeerCommand::SendPort {
            dht_port: d.local_port,
        });
    }
    let reg = PeerRegistration {
        face,
        cuid,
        meta: PeerMeta {
            ip: addr.ip(),
            port: addr.port(),
            inbound,
            peer_id,
            crypto,
            transport,
            up,
            down,
            upload_only,
        },
        handle,
    };
    if reg_tx.send(reg).await.is_err() {
        return;
    }
    // In the select, join precedes data: a violation terminal state
    // surfaces immediately instead of waiting for the data channel to
    // drain.
    let mut end: Option<PeerEnd> = None;
    let mut send_failed = false;
    loop {
        tokio::select! {
            _ = parent.cancelled() => break,
            e = &mut join => { end = e.ok(); break; }
            // Under the direct-delivery bypass this arm is disabled:
            // PeerTask no longer delivers blocks via data_tx (the
            // sink delivers straight to the face channel) and recv is
            // always Pending — the arm-value guard avoids empty
            // polling.
            item = data_rx.recv(), if !direct => match item {
                None => break,
                Some(data) => {
                    // Face addressing -> flat piece index (v1
                    // identity; v2 = base + in-file order). Out of
                    // range = a peer protocol violation (peer.rs
                    // validates the addressing and disconnects);
                    // this is defensive: skip the block without
                    // breaking the forward loop.
                    let index = addressing
                        .to_flat(data.id)
                        .and_then(|i| u32::try_from(i).ok());
                    let Some(index) = index else {
                        warn!(target: "taiji::core::engine", piece = ?data.id,
                            "piece id outside addressing: block skipped");
                        continue;
                    };
                    // Attribution bookkeeping: the block's sender
                    // (aggregated to the IP on hash failure;
                    // same-coordinate re-receipt overwrites = last
                    // arrival wins).
                    {
                        let mut senders = crate::lock(&block_senders);
                        senders.insert((index, data.begin), cuid);
                    }
                    // Block payload moved straight through (the
                    // zero-copy chain tail): passed by Bytes reference
                    // count, no `.to_vec()` 16KiB copy — block data
                    // stays zero-copy from frame decode (Bytes::slice)
                    // until the single placement copy in the store
                    // buffer.
                    let msg = (index, data.begin, data.block);
                    if block_tx.send(msg).await.is_err() {
                        // Store pipeline dead (engine about to
                        // fail-exit): no join wait — the peer task may
                        // live until engine shutdown; avoid hanging
                        // this module.
                        send_failed = true;
                        break;
                    }
                    // Arrival emission: `block_tx.send` succeeded =
                    // the block bytes are local (the peer's wire slot
                    // retired at frame receive) = the network segment
                    // is done. Switch gate (off = the whole face falls
                    // back, no emission) + try_send drops when full —
                    // the degraded face keeps InFlight (the main loop
                    // re-dispatches per current behavior and
                    // converges; the degraded counter is observation
                    // only). Rationale in the
                    // [`dispatch::on_block_arrived`] docs.
                    if two_phase_ledger() {
                        match ledger_tx.try_send(LedgerArrival {
                            face,
                            index,
                            begin: data.begin,
                            cuid,
                        }) {
                            Ok(()) => {
                                LEDGER_ARRIVALS
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(_) => {
                                LEDGER_DEGRADES
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            },
        }
    }
    if send_failed {
        // Store pipeline dead = the engine is about to fail-exit
        // (shutdown-cancel semantics, not connection-table churn).
        let _ = leave_tx.send((face, cuid, LeaveKind::Cancelled)).await;
        return;
    }
    let end = match end {
        Some(e) => e,
        // Data-channel closed / cancelled path: PeerTask has exited
        // (or is about to, via cancellation) — take the terminal
        // state.
        None => join.await.unwrap_or(PeerEnd::Cancelled),
    };
    // Leave-reason projection before the terminal state is consumed
    // (violation_of takes PeerEnd by value).
    let kind = LeaveKind::of(&end);
    // Protocol violation / flooding -> a Violation event (the core
    // main loop bans immediately and drops same-IP connections).
    if let Some(v) = violation_of(end, addr.ip()) {
        // Violations are low-frequency and a dropped event = a missed
        // ban (silent drops forbidden): await backpressure.
        if violation_tx.send(v).await.is_err() {
            debug!(target: "taiji::core::engine", "violation channel closed (engine down)");
        }
    }
    // Peer left: report to the engine to decrement rarity counts
    // (PieceStatMan.remove_peer, the aria2 semantics: the peer's
    // bitfield is withdrawn from the statistics). The leave reason
    // rides along (the five-way PeerEnd projection, the
    // connection-retention observation face).
    let _ = leave_tx.send((face, cuid, kind)).await;
    // The handle has been handed to the engine (shutdown is executed
    // by the engine).
}
/// Outbound dial wiring bundle.
pub(super) struct DialJob {
    pub(super) addr: std::net::SocketAddr,
    /// Face (progress/availability/registration events are returned
    /// through it).
    pub(super) face: usize,
    pub(super) info_hash: [u8; 20],
    pub(super) peer_id: [u8; 20],
    pub(super) reserved: Reserved,
    pub(super) cuid: u64,
    pub(super) addressing: Addressing,
    /// Expected bytes-per-piece table (the upper bound for
    /// unsolicited block coordinates; a face-shared `Arc` clone,
    /// semantics at [`taiji_bt::peer::PeerConfig::piece_bytes`]).
    pub(super) piece_bytes: std::sync::Arc<[u64]>,
    pub(super) avail_tx: mpsc::Sender<AvailEvent>,
    pub(super) initial_source: Option<Arc<dyn PieceSource>>,
    pub(super) initial_hash_source: Option<Arc<dyn HashSource>>,
    /// BEP10 extension face (the ut_metadata serving face; the
    /// request face is used only during the magnet metadata phase —
    /// the engine face is always the serving face).
    pub(super) ext: taiji_bt::peer::ExtConfig,
    pub(super) reg_tx: mpsc::Sender<PeerRegistration>,
    pub(super) leave_tx: mpsc::Sender<(usize, u64, LeaveKind)>,
    pub(super) block_tx: mpsc::Sender<BlockMsg>,
    pub(super) block_senders: BlockSenders,
    /// Block direct-delivery seam (`None` = the old forward path —
    /// both paths coexist for one milestone for A/B and rollback; the
    /// switch is read at the `FaceState::block_sink_for` factory).
    pub(super) block_sink: Option<Arc<dyn BlockSink>>,
    /// Block-arrival event sender (emitted by the forward loop;
    /// consumed by the main-loop arrival arm).
    pub(super) ledger_tx: mpsc::Sender<LedgerArrival>,
    /// Filter point: the IpGuard is consulted before dialing (the
    /// arc-swap latest snapshot).
    pub(super) guard: IpGuardHandle,
    pub(super) violation_tx: mpsc::Sender<Violation>,
    pub(super) parent: CancellationToken,
    /// MSE crypto policy (the three-branch outbound shape mapping is
    /// at [`outbound_crypto_shape`]: require -> MSE only; min=arc4 ->
    /// MSE-first + a legacy fallback on a fresh connection; default
    /// plain -> direct legacy).
    pub(super) crypto: CryptoPolicy,
    /// Outbound transport plan (the `--bt-peer-connection-type` four
    /// states, expanded by bt::utp::dial_plan — pure types do not
    /// degrade; prefer-* retries once on the other transport).
    pub(super) conn_type: PeerConnectionType,
    /// uTP outbound dial face (a None channel family = no uTP
    /// listener for that family; a Utp attempt fails directly and
    /// moves to the plan's next transport).
    pub(super) utp: UtpDial,
    /// DHT wiring (None = not enabled — no PORT sent, inbound PORT
    /// not forwarded).
    pub(super) dht: Option<AttachDht>,
    /// Rate-limit topology (None = unlimited). The post-handshake
    /// transport stream is wrapped in `Throttled`.
    pub(super) limits: Option<Arc<LimiterSet>>,
    /// Redial report end (None = not a redial — the tracker/DHT/PEX/
    /// regular path).
    pub(super) redial: Option<mpsc::Sender<RedialReport>>,
    /// ut_holepunch wiring (None = the engine gate off).
    pub(super) holepunch: Option<taiji_bt::peer::HolepunchExt>,
    /// Dial-outcome report end (None = no trigger bookkeeping). All
    /// outbound dials carry it — success clears the failure memory,
    /// failure opens the trigger gate (engine/holepunch module docs).
    pub(super) hp_report: Option<mpsc::Sender<super::run::holepunch::HpDialReport>>,
    /// Ext handshake `v` field identity re-check callback (None = no
    /// re-check).
    pub(super) client_deny: Option<taiji_bt::peer::ClientDenyCheck>,
    /// Face-level read pool: the serve read service for outbound
    /// connections (face-shared).
    pub(super) read_pool: Option<Arc<taiji_bt::peer::ReadPool>>,
    /// Punch-source marker (source = Punch, independent of the mode
    /// switch): rides down [`HpDialReport::punch`] — the feed-point
    /// predicate of the punch_established observation face (in
    /// fallback mode punch dials take the regular plan and still
    /// count on success).
    pub(super) punch: bool,
    /// Mode gate (punch AND BH_HOLEPUNCH_MODE, read at assembly):
    /// true = [`peer_connect`] takes the punch-dedicated path (uTP
    /// sticky + in-window fast retry, [`PUNCH_ATTEMPT_MAX`]); false =
    /// the regular dial-plan path unchanged (the
    /// [`super::run::holepunch::holepunch_mode_enabled`] fallback
    /// face).
    pub(super) punch_mode: bool,
    /// Silent-failure ledger reading (snapshotted from
    /// `silent_book.fails(&addr)` at assembly; >= 1 = evidence the
    /// address went silent at least once): the input to the uTP-arm
    /// trim decision in the regular plan loop
    /// ([`skip_dead_utp_arm`]). Not consumed by the punch-dedicated
    /// path (uTP stickiness is a protocol prerequisite of punching,
    /// so the arm is not trimmed).
    pub(super) fails: u32,
    /// Face-level block arena (None = fall back to direct
    /// allocation) — passed through to PeerConfig for the
    /// connection read-side FrameCodec.
    pub(super) block_arena: Option<Arc<taiji_io::block_arena::BlockArena>>,
}

/// uTP outbound dial request: destination address + reply end (None
/// = no uTP face for that family).
pub(super) type UtpDialReq = (SocketAddr, oneshot::Sender<Option<UtpStream>>);

// ---- Punch-dedicated path (holepunch mode) ----

/// Fast-retry cap inside the punch window. Source: libtorrent
/// `max_failcount` = 3 (RC_2_1 `settings_pack.cpp`) — the failure cap
/// before giving up on a peer; holepunch mode's retry-faster spends
/// that cap at a fast pace (`peer_connection.cpp` failure arm
/// `fast_reconnect(true)` re-arms the reconnect gate so the
/// `(f+1)x60s` door reopens immediately). Materialized here as
/// in-window retries of one task (3 attempts x 3s budget = a ~9s
/// window), deep enough to cover >= 2 SYN rounds on both sides (uTP
/// initial RTO 1000ms + doubling, BEP29 timeouts; the io
/// `Rtt::default` note) — a needle hole needs crossed SYNs, and the
/// window depth is sized jointly by this constant and
/// [`PUNCH_ATTEMPT_BUDGET`]. Like the reference's immediate redial,
/// attempts have zero inter-attempt gap (refusal-class failures
/// exhaust the cap immediately; silent ones naturally consume a full
/// budget window each).
pub(super) const PUNCH_ATTEMPT_MAX: usize = 3;

/// Budget per punch attempt (the outer timeout over uTP connect + BT
/// handshake). Source: libtorrent `utp_connect_timeout` = 3000ms
/// (RC_2_1 `settings_pack.cpp`) + the same 3000ms for the
/// no-RTT-estimate (SYN) packet timeout (`utp_stream.cpp`
/// packet_timeout's none-state arm) + an unconfirmed socket dying on
/// its first timeout (the `!m_confirmed` arm) — the reference's
/// give-up window for one unanswered uTP attempt is exactly this 3s
/// order. The inner handshake budget (10s) is unchanged; the outer 3s
/// cancels first = attempt-level fast retry. A None within budget =
/// an explicit peer refusal (not silent); budget exhaustion = the
/// peer stayed silent throughout (a NAT-face candidate, see
/// [`punch_gave_up_nat`]).
pub(super) const PUNCH_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);

/// Punch-window-exhaustion attribution (a pure, table-driven face):
/// all attempts budget-exhausted (`punch-timeout`) = zero replies
/// from the peer during the whole window — the port-prediction face
/// never opened (the symmetric-NAT shape, the structural presentation
/// of both sides' port prediction failing) -> counted as
/// `punch_failed_nat`; any attempt failing explicitly within budget
/// (the peer responded) -> non-NAT attribution (the peer is reachable
/// but refused / would not negotiate — stop-loss without touching the
/// NAT count). Same semantics family as [`plan_is_silent`] (silent =
/// evidence of an unreachable peer).
pub(super) fn punch_gave_up_nat(attempts: &[&str]) -> bool {
    !attempts.is_empty() && attempts.iter().all(|a| *a == "punch-timeout")
}

/// Failure class of one attempt on the punch-dedicated path.
pub(super) const PUNCH_CLASS_TIMEOUT: &str = "punch-timeout";

/// uTP outbound dial face: each family's UtpListenerHandle is held by
/// an exclusive service task (the only consumer of the demuxed uTP
/// channel; the listener routing table is the connection registry —
/// outbound connect and accept must consume the same instance), and
/// dials go through a request channel. The request channel is
/// bounded(64): dialing is low-frequency (announce/DHT-period
/// driven), and a full channel awaits backpressure on the dial task —
/// the whole backpressure/reply wait is bounded by the
/// [`UtpDial::connect`] budget (default 10s), so a stalled consumer
/// no longer hangs the dial task indefinitely.
#[derive(Clone, Default)]
pub(super) struct UtpDial {
    pub(super) v4: Option<mpsc::Sender<UtpDialReq>>,
    pub(super) v6: Option<mpsc::Sender<UtpDialReq>>,
}

impl UtpDial {
    /// Open a uTP connection: `UtpListenerHandle::connect` returns
    /// the stream handle (SYN retransmission/give-up is bounded by
    /// the driver's timeout rounds; the handshake budget =
    /// [`MSE_HANDSHAKE_TIMEOUT`], see [`handshake_over`]). No uTP face
    /// for the address family (demux bind failure / missing family)
    /// -> None = this transport attempt failed; move to the next
    /// transport per the plan.
    ///
    /// Total budget: this await used to be the only timeout-free point
    /// in the peer_connect chain (both the bounded(64) queue's
    /// `tx.send().await` and the oneshot `rx.await` were unbounded) —
    /// while the delegated-dial consumer was stalled (accept-merge
    /// backpressure / the consumer exited), a dead address's uTP
    /// fallback requests queued without bound. The whole window
    /// (queueing + delegation + reply) now sits under
    /// [`utp_dial_budget`]: timeout / closed queue / dead reply end ->
    /// None, taking the existing utp-connect failure class (the
    /// plan-exhausted semantics already exist; the same criterion as
    /// [`plan_is_silent`] — not counted silent). The budget order =
    /// [`MSE_HANDSHAKE_TIMEOUT`] 10s (aligned with the existing
    /// connect/handshake budgets — an upper bound over queueing + the
    /// SYN retransmit window); `BH_UTP_DIAL_TIMEOUT_SECS=0` falls back
    /// to the old unbounded behavior (the emergency seam). All four
    /// call sites (the regular Utp arm / the MSE fallback redial /
    /// both punch sites) benefit automatically; the consumer-side
    /// dead-reply tolerance already exists (the assemble `let _ =`
    /// reply face).
    pub(super) async fn connect(&self, addr: SocketAddr) -> Option<UtpStream> {
        self.connect_bounded(addr, utp_dial_budget()).await
    }

    /// Budget-parameterized face (the direct-drive seam of
    /// [`Self::connect`] — tests inject short budgets instead of
    /// really waiting for the 10s default; production always reads
    /// through [`utp_dial_budget`]).
    pub(super) async fn connect_bounded(
        &self,
        addr: SocketAddr,
        budget: Option<Duration>,
    ) -> Option<UtpStream> {
        let tx = if addr.is_ipv4() {
            self.v4.as_ref()?
        } else {
            self.v6.as_ref()?
        };
        let (back, rx) = oneshot::channel();
        let dial = async {
            tx.send((addr, back)).await.ok()?;
            rx.await.ok().flatten()
        };
        match budget {
            Some(b) => tokio::time::timeout(b, dial).await.unwrap_or_default(),
            // None = the old unbounded behavior (the emergency
            // fallback seam, BH_UTP_DIAL_TIMEOUT_SECS=0).
            None => dial.await,
        }
    }
}

/// uTP dial total budget: `BH_UTP_DIAL_TIMEOUT_SECS` seconds ->
/// `Option<Duration>` (0 -> None = the old unbounded fallback). Read
/// timing is registered in `taiji_io::knobs` (event-level — read per
/// uTP dial arm; low-frequency, not hot path).
pub(super) fn utp_dial_budget() -> Option<Duration> {
    utp_dial_budget_of_secs(taiji_io::knobs::utp_dial_timeout_secs())
}

/// The pure budget-mapping face (table-driven tests): 0 = None (the
/// unbounded fallback seam); otherwise a seconds budget.
fn utp_dial_budget_of_secs(secs: u64) -> Option<Duration> {
    match secs {
        0 => None,
        s => Some(Duration::from_secs(s)),
    }
}

/// Dead-address uTP-arm trim predicate (a pure function,
/// four-quadrant table-tested): `fails >= 1` (the silent-failure
/// ledger remembers the endpoint going silent at least once) AND
/// `transport == Utp` AND the switch on -> true (the plan loop skips
/// that arm).
///
/// Rationale: a second uTP try against a dead address (TCP failure +
/// historical silence) has zero benefit and two harms — it feeds the
/// bounded(64) delegation queue (hung supply) and a dead connect
/// leaves 120s of driver debris on the io stack (approaching the 512
/// routing-table cap). The first attempt (fails = 0) keeps the full
/// [Tcp, Utp] plan — good peers (TCP fails but uTP is reachable) keep
/// their uTP path. Switch `BH_DIAL_DEAD_TCP_ONLY` (default on; =0
/// restores the full plan). Intentional divergence: libtorrent has no
/// per-failcount transport-plan trim (peer_list.cpp's
/// connect-candidate eligibility is decided per endpoint, not per
/// transport arm; this side keeps the endpoint's TCP arm in the plan
/// — only uTP's queue/driver-debris costs trigger the trim).
pub(super) fn skip_dead_utp_arm(fails: u32, transport: Transport, enabled: bool) -> bool {
    enabled && fails >= 1 && transport == Transport::Utp
}

/// The uTP-preferred dial-plan flip (a pure function, two-arm
/// decision table). Switch on AND `PreferTcp` -> the plan flips to
/// [Utp, Tcp] (the uTP fallback arm becomes primary — outbound
/// connections run BEP29 LEDBAT congestion control and yield
/// automatically while the user is browsing = a guardrail on ADSL).
/// Other types untouched: pure `tcp`/`utp` are the user's explicit
/// only-type choices (never second-guessed); `PreferUtp` is already
/// [Utp, Tcp]. Inbound is unaffected (whatever the peer picks is
/// accepted — the accept face takes both transports, see the
/// `bt::utp` module docs).
///
/// Orthogonal to `BH_DIAL_DEAD_TCP_ONLY`: the trim acts on arm
/// filtering ([`skip_dead_utp_arm`]), this flip on arm order — the
/// combination is order-then-filter, each unaware of the other
/// (locked by a combined-arm test). Switch = `BH_DIAL_PREFER_UTP`
/// (opt-in, default off, zero behavior change; the event-level read
/// point = plan construction in [`peer_connect`]).
pub(super) fn outbound_dial_plan(
    t: PeerConnectionType,
    prefer_utp: bool,
) -> taiji_bt::utp::heapless_vec::DialPlan {
    dial_plan(if prefer_utp && t == PeerConnectionType::PreferTcp {
        PeerConnectionType::PreferUtp
    } else {
        t
    })
}

/// Outbound TCP connect (a 10s budget; returns the failure class —
/// the INFO result line is aggregated per target by `peer_connect`,
/// this keeps DEBUG-level granularity).
pub(super) async fn dial_tcp(addr: SocketAddr) -> Result<TcpStream, &'static str> {
    let connect = tokio::net::TcpStream::connect(addr);
    match tokio::time::timeout(Duration::from_secs(10), connect).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            let class = super::run::dial::classify_connect_io(e.kind());
            debug!(target: "taiji::core::engine", %addr, class, %e, "connect failed");
            Err(class)
        }
        Err(_) => {
            debug!(target: "taiji::core::engine", %addr, class = "connect-timeout",
                "connect failed (10s budget)");
            Err("connect-timeout")
        }
    }
}
/// Outbound connection task: IpGuard filter -> connect per the dial
/// plan -> crypto face (per policy) -> BT handshake (identity /
/// reserved per face) -> attach_peer.
///
/// Outbound transport plan (SPEC §6.1 `--bt-peer-connection-type`):
/// transports are tried in the order expanded by `bt::utp::dial_plan`;
/// any successful handshake attaches; total failure is log-only
/// (reconnection is re-triggered by the announce/DHT discovery
/// periods — the minimal-intervention connection stance). prefer-* =
/// retry once on the other transport after the preferred one fails or
/// times out; pure `tcp`/`utp` do not degrade.
///
/// Outbound crypto order (generalized over the transport): with
/// `bt-require-crypto` the outbound side MUST start with MSE (the
/// `bt::mse::connect` initiator, provide excludes plain; a failed
/// negotiation drops the connection — no silent plaintext fallback,
/// `InitiatorMSEHandshakeCommand.cc`). With `bt-min-crypto-level=arc4`
/// and !require: MSE-first — start with MSE and, on failure
/// (a legacy-only peer / no answer / a negotiation rejection incl.
/// timeout), fall back to legacy plaintext on a fresh connection. The
/// fallback is a dial-order shape change, not a protocol violation (a
/// non-encrypting inbound face accepts legacy outbound as usual;
/// upstream anchors in docs/design/engine.md). Default plain dials
/// legacy directly (the promise face of the SPEC §6.1 prefer-tcp
/// default; the divergence from aria2's default MSE-first narrows to
/// the default shape only — the mapping at
/// [`outbound_crypto_shape`]). All three shapes' inbound side demuxes
/// through [`mse::accept_any`] sniffing (inbound accepts both, SPEC
/// §6.1).
pub(super) async fn peer_connect(job: DialJob) {
    // Punch-dedicated path (the mode gate is read at DialJob
    // assembly): uTP sticky + in-window fast retry
    // ([`PUNCH_ATTEMPT_MAX`]). With the mode off / a regular source,
    // the regular dial-plan path below runs unchanged (the
    // wire-behavior compatibility line — the regular arm is
    // untouched).
    if job.punch_mode {
        punch_connect_window(job).await;
        return;
    }
    let DialJob {
        addr,
        face,
        info_hash,
        peer_id,
        reserved,
        cuid,
        addressing,
        piece_bytes,
        avail_tx,
        initial_source,
        initial_hash_source,
        ext,
        reg_tx,
        leave_tx,
        block_tx,
        block_senders,
        block_sink,
        ledger_tx,
        guard,
        violation_tx,
        parent,
        crypto,
        conn_type,
        utp,
        dht,
        limits,
        redial,
        holepunch,
        hp_report,
        client_deny,
        read_pool,
        block_arena,
        punch,
        fails,
        // punch_mode stays out of the destructure: the mode gate
        // branches first at the top of the function (the whole job is
        // moved to [`punch_connect_window`]).
        ..
    } = job;
    // Filter point: the IpGuard is consulted before dialing (the
    // snapshot at connection time — after a ban/import hot-update even
    // an already-queued dial task is intercepted). An interception is
    // one of the dial outcomes: full INFO logging (failures are
    // logged wholesale).
    if let Some(block) = guard.load().blocks(addr.ip(), epoch_secs()) {
        info!(target: "taiji::core::engine", %addr, block = %block, class = "blocked",
            "dial skipped by IpGuard");
        super::run::dial::DialLogSampler::global().note_result(false, "blocked");
        // A banned peer's redial entry is removed here (never
        // re-dialed).
        redial_report(redial.as_ref(), addr, DialOutcome::Blocked).await;
        return;
    }
    // Per-transport failure classes (aggregated into one INFO line
    // per target; see the end of the function).
    let mut dial_attempts: Vec<&'static str> = Vec::new();
    // Dead-address uTP-arm trim switch (an event-level read: once per
    // dial, not hot path; the decision face = the
    // [`skip_dead_utp_arm`] pure function).
    let dead_tcp_only = taiji_io::knobs::dial_dead_tcp_only_enabled();
    // The uTP-preferred dial switch (an event-level read as above;
    // the decision face = the [`outbound_dial_plan`] pure function —
    // on = the prefer-tcp plan [Tcp, Utp] flips to [Utp, Tcp], the
    // uTP fallback arm becomes primary; inbound unaffected).
    let prefer_utp = taiji_io::knobs::dial_prefer_utp_enabled();
    // Connection metadata capture (getPeers): the peer id comes from
    // the handshake reply; the crypto level from the MSE negotiation
    // result (legacy direct = Plain); the transport from the actual
    // winner of the attempt order (the getPeers transport data
    // source).
    //
    // Each transport runs its own branch through connect -> handshake
    // -> attach (the Transit carrier type differs per transport;
    // attach's generic is monomorphized inside the branch; attach then
    // returns, with parameters consumed by arm-local moves). Plan
    // construction = outbound_dial_plan (the uTP-preferred flip seam;
    // default off = dial_plan(conn_type) unchanged).
    for transport in outbound_dial_plan(conn_type, prefer_utp)
        .into_iter()
        .flatten()
    {
        // Dead-address uTP-arm trim: fails >= 1 (silent-ledger
        // memory) AND the uTP arm AND the switch on -> skip (a second
        // uTP try on a dead address feeds the delegation queue /
        // leaves 120s of driver debris; rationale at
        // [`skip_dead_utp_arm`]). The utp-skip-dead class leaves a
        // trace (the INFO result line can answer why uTP was not
        // tried; the [`plan_is_silent`] criterion matches utp-connect
        // — a local decision, not peer evidence, not counted
        // silent).
        if skip_dead_utp_arm(fails, transport, dead_tcp_only) {
            debug!(target: "taiji::core::engine", %addr, fails,
                "utp arm skipped for dead address (silent book fails)");
            dial_attempts.push("utp-skip-dead");
            continue;
        }
        match transport {
            Transport::Tcp => {
                let tcp = match dial_tcp(addr).await {
                    Ok(tcp) => tcp,
                    Err(class) => {
                        dial_attempts.push(class);
                        continue;
                    }
                };
                let Some((stream, peer_dht, peer_ext, peer_fast, their_peer_id, level)) =
                    handshake_over(
                        tcp,
                        addr,
                        info_hash,
                        peer_id,
                        reserved,
                        crypto,
                        // MSE-first fallback redial = a fresh TCP
                        // connection (same budget; the failed
                        // connection's bytes are not reusable,
                        // InitiatorMSEHandshakeCommand.cc).
                        || async move { dial_tcp(addr).await.ok() },
                    )
                    .await
                else {
                    dial_attempts.push("handshake");
                    continue;
                };
                // Identity rule (at handshake completion): on a hit
                // the connection is dropped (a Violation event -> the
                // persisted reason=client-ban:* + same-IP online
                // disconnects), and redial reports Blocked (never
                // re-dialed).
                if let Some(v) = client_violation(&guard, &their_peer_id, addr.ip()) {
                    debug!(target: "taiji::core::engine", %addr, reason = %v.reason,
                        "outbound peer rejected by identity rule ");
                    let _ = violation_tx.send(v).await;
                    redial_report(redial.as_ref(), addr, DialOutcome::Blocked).await;
                    return;
                }
                debug!(target: "taiji::core::engine", %addr, ?level,
                    transport = transport.as_transport_str(), "outbound connected");
                // Counted into the periodic summary on success (the
                // per-target line keeps the DEBUG wording above — no
                // INFO spam).
                super::run::dial::DialLogSampler::global().note_result(true, "ok");
                // Report on the successful handshake (before attach
                // residency — the connection is rebuilt, the pool
                // entry removed; failure counts reset to zero).
                redial_report(redial.as_ref(), addr, DialOutcome::Connected).await;
                // Trigger bookkeeping cleared (the connection is
                // established). The punch marker rides along;
                // face/discovery ride along (the discovery source =
                // not a redial, not a punch).
                report_hp_dial(
                    addr,
                    face,
                    redial.is_none() && !punch,
                    true,
                    false,
                    punch,
                    hp_report.as_ref(),
                )
                .await;
                // The post-handshake transport stream is rate-limited
                // (two buckets in series; PeerTask read paths await
                // permits, compressing the TCP/uTP window, SPEC §3.3).
                // `Throttled::maybe`'s None/unlimited-bucket shape is
                // a zero-cost passthrough.
                attach_peer(
                    Throttled::maybe(stream, limits),
                    face,
                    cuid,
                    addr,
                    false,
                    their_peer_id,
                    level,
                    transport,
                    addressing,
                    piece_bytes,
                    block_tx,
                    block_senders,
                    block_sink,
                    ledger_tx,
                    avail_tx,
                    reg_tx,
                    leave_tx,
                    initial_source,
                    initial_hash_source,
                    violation_tx,
                    ext,
                    client_deny,
                    holepunch,
                    read_pool.clone(),
                    block_arena,
                    parent,
                    dht,
                    peer_dht,
                    peer_ext,
                    // BEP6 fast negotiation mirror (the outbound
                    // Reject gate).
                    peer_fast,
                )
                .await;
                return;
            }
            Transport::Utp => {
                let Some(stream) = utp.connect(addr).await else {
                    dial_attempts.push("utp-connect");
                    continue;
                };
                let Some((stream, peer_dht, peer_ext, peer_fast, their_peer_id, level)) =
                    handshake_over(
                        stream,
                        addr,
                        info_hash,
                        peer_id,
                        reserved,
                        crypto,
                        // Same shape — the fallback redial dials a fresh uTP connection.
                        || {
                            let utp = utp.clone();
                            async move { utp.connect(addr).await }
                        },
                    )
                    .await
                else {
                    dial_attempts.push("handshake");
                    continue;
                };
                // Identity rule (at handshake completion; the uTP
                // arm shares the TCP discipline).
                if let Some(v) = client_violation(&guard, &their_peer_id, addr.ip()) {
                    debug!(target: "taiji::core::engine", %addr, reason = %v.reason,
                        "outbound utp peer rejected by identity rule ");
                    let _ = violation_tx.send(v).await;
                    redial_report(redial.as_ref(), addr, DialOutcome::Blocked).await;
                    return;
                }
                debug!(target: "taiji::core::engine", %addr, ?level,
                    transport = transport.as_transport_str(), "outbound connected");
                // Counted into the periodic summary on success (the
                // same as the TCP arm).
                super::run::dial::DialLogSampler::global().note_result(true, "ok");
                // Report on the successful handshake (the same as the
                // TCP arm).
                redial_report(redial.as_ref(), addr, DialOutcome::Connected).await;
                // Trigger bookkeeping cleared (the same as the TCP
                // arm). The punch/face/discovery markers ride along.
                report_hp_dial(
                    addr,
                    face,
                    redial.is_none() && !punch,
                    true,
                    false,
                    punch,
                    hp_report.as_ref(),
                )
                .await;
                attach_peer(
                    Throttled::maybe(stream, limits),
                    face,
                    cuid,
                    addr,
                    false,
                    their_peer_id,
                    level,
                    transport,
                    addressing,
                    piece_bytes,
                    block_tx,
                    block_senders,
                    block_sink,
                    ledger_tx,
                    avail_tx,
                    reg_tx,
                    leave_tx,
                    initial_source,
                    initial_hash_source,
                    violation_tx,
                    ext,
                    client_deny,
                    holepunch,
                    read_pool,
                    block_arena,
                    parent,
                    dht,
                    peer_dht,
                    peer_ext,
                    // BEP6 fast negotiation mirror (the outbound
                    // Reject gate).
                    peer_fast,
                )
                .await;
                return;
            }
        }
    }
    // Dial-result INFO line (exactly one per target: addr + the
    // per-transport failure classes) — who was dialed and why it
    // failed stays diagnosable; the success path keeps the existing
    // DEBUG line + the periodic summary.
    info!(target: "taiji::core::engine", %addr,
        conn_type = peer_connection_type_str(conn_type),
        attempts = dial_attempts.join(","),
        "dial failed (plan exhausted)");
    super::run::dial::DialLogSampler::global().note_result(
        false,
        dial_attempts.last().copied().unwrap_or("no-transport"),
    );
    // Silent give-up classification (any arm classified handshake =
    // connected at the transport level but the BT handshake never
    // completed / the downstream shape of a silent uTP give-up) ->
    // the endpoint failure-ledger backoff/cooldown upgrade.
    let silent = plan_is_silent(&dial_attempts);
    // Dial plan exhausted -> failure backoff/eviction (the redial
    // module docs; only redial dials carry a report end — regular
    // paths are None, a no-op).
    redial_report(redial.as_ref(), addr, DialOutcome::Failed).await;
    // A real direct-connection failure -> trigger bookkeeping (the
    // introducer rendezvous decision lives in the main loop). `silent`
    // rides in the report (silent-ledger consumption); the punch
    // marker rides along; face/discovery ride along (failed discovery
    // candidates return to the table — the decision lives in the main
    // loop).
    report_hp_dial(
        addr,
        face,
        redial.is_none() && !punch,
        false,
        silent,
        punch,
        hp_report.as_ref(),
    )
    .await;
}

/// Silent give-up classification (the silent module docs): a
/// handshake class in the plan's failure sequence = silent (TCP
/// connected but the BT handshake never completed / silence within
/// budget after the uTP stream was obtained — the downstream shape of
/// io::utp's UtpError::Timeout give-up); connect-refused /
/// connect-timeout / connect-error = the endpoint is explicitly
/// unreachable, not a silent signal (transient network jitter is not
/// cooled down); utp-connect = the local uTP routing table full /
/// channel missing / dial budget timed out (local congestion or the
/// budget guard — not evidence of a silent peer, not counted);
/// utp-skip-dead = the dead-address plan trim (a local decision, also
/// not counted).
pub(super) fn plan_is_silent(attempts: &[&str]) -> bool {
    attempts.contains(&"handshake")
}

/// Punch-dedicated path: uTP sticky + in-window fast retry.
///
/// Reference (libtorrent RC_2_1): `bt_peer_connection.cpp` sets
/// `p->supports_utp = true` before `connect_to_peer(p, true)` in the
/// connect arm — punch connections force uTP; a uTP failure does not
/// degrade to TCP (the regular failure arm's mark-uTP-unsupported +
/// immediate-TCP-reconnect is skipped in holepunch mode, the
/// `peer_connection.cpp` `!m_holepunch_mode` gate). Fast retry =
/// `set_holepunch_mode()` + the failure arm's `fast_reconnect(true)`
/// — the reconnect gate re-arms so the `(f+1)x60s` door reopens
/// immediately. This side = [`PUNCH_ATTEMPT_MAX`] attempts with zero
/// inter-attempt gap (the reference's immediate redial, same shape),
/// each under the outer [`PUNCH_ATTEMPT_BUDGET`] (the 10s inner
/// budget unchanged; the outer 3s cancels first = attempt-level fast
/// pacing). Stop-loss: a window exhausted with total silence (zero
/// peer replies) -> the `punch_failed_nat` observation count
/// ([`punch_gave_up_nat`]; the symmetric-NAT presentation — both
/// sides' port prediction failing; NAT type is not directly
/// observable, so the absence of reachability evidence is the
/// attribution; libtorrent has no counterpart counter). The
/// punch-timeout class does NOT enter the silent ledger (intentional
/// divergence: the regular handshake class does — inside the window
/// the backoff semantics were already cashed by 3 fast retries, so
/// booking again would be double punishment; re-triggering is
/// rate-limited by the existing RENDEZVOUS_ASK_BACKOFF 60s + 10min
/// dial dedup gates).
///
/// The success tail = the regular uTP arm's table (violation ->
/// periodic summary -> reports -> attach); deliberately copied, not
/// extracted (the regular arm must stay untouched — changes must be
/// synchronized with [`peer_connect`]'s Utp arm tail). Dual reports:
/// redial is always None (the Punch-source assembly exemption);
/// hp_report carries the `punch` marker (the punch_established feed
/// predicate).
async fn punch_connect_window(job: DialJob) {
    let DialJob {
        addr,
        face,
        info_hash,
        peer_id,
        reserved,
        cuid,
        addressing,
        piece_bytes,
        avail_tx,
        initial_source,
        initial_hash_source,
        ext,
        reg_tx,
        leave_tx,
        block_tx,
        block_senders,
        block_sink,
        ledger_tx,
        guard,
        violation_tx,
        parent,
        crypto,
        utp,
        dht,
        limits,
        holepunch,
        hp_report,
        client_deny,
        read_pool,
        block_arena,
        punch,
        ..
    } = job;
    // Per-attempt failure classes (the same criterion as the regular
    // arm; one INFO line per target at the end).
    let mut attempts: Vec<&'static str> = Vec::new();
    for _attempt in 0..PUNCH_ATTEMPT_MAX {
        // uTP sticky (the reference connect arm's shape): the attempt
        // order contains only uTP. No uTP face for the address family
        // (demux bind failure / missing family) = the punching
        // capability is absent — stop immediately, no NAT attribution
        // (a local face being absent is not evidence of an unreachable
        // peer).
        let Some(stream) = utp.connect(addr).await else {
            attempts.push("utp-connect");
            break;
        };
        // The outer attempt budget runs first (the inner MSE/handshake
        // 10s budget unchanged — being cancelled by the outer one =
        // silence within budget); a None within budget = an explicit
        // peer refusal (not silent).
        let utp_retry = utp.clone();
        match tokio::time::timeout(
            PUNCH_ATTEMPT_BUDGET,
            handshake_over(
                stream,
                addr,
                info_hash,
                peer_id,
                reserved,
                crypto,
                // MSE-first fallback redial = a fresh uTP connection
                // (the regular Utp arm's shape).
                move || async move { utp_retry.connect(addr).await },
            ),
        )
        .await
        {
            Ok(Some((stream, peer_dht, peer_ext, peer_fast, their_peer_id, level))) => {
                // Identity rule (at handshake completion; the same
                // discipline as the regular uTP arm).
                if let Some(v) = client_violation(&guard, &their_peer_id, addr.ip()) {
                    debug!(target: "taiji::core::engine", %addr, reason = %v.reason,
                        "outbound punch peer rejected by identity rule ");
                    let _ = violation_tx.send(v).await;
                    return;
                }
                debug!(target: "taiji::core::engine", %addr, ?level,
                    transport = "utp", attempt = attempts.len() + 1,
                    "outbound connected (punch window)");
                super::run::dial::DialLogSampler::global().note_result(true, "ok");
                // Trigger bookkeeping cleared + the punch_established
                // feed (the main loop counts on the punch marker).
                // discovery = false: punch-window dials do not enter
                // the candidate table (Punch sources bypass the
                // candidate gate).
                report_hp_dial(addr, face, false, true, false, punch, hp_report.as_ref()).await;
                // Success tail = the regular Utp arm's table (the
                // sync discipline is in the function docs).
                attach_peer(
                    Throttled::maybe(stream, limits),
                    face,
                    cuid,
                    addr,
                    false,
                    their_peer_id,
                    level,
                    Transport::Utp,
                    addressing,
                    piece_bytes,
                    block_tx,
                    block_senders,
                    block_sink,
                    ledger_tx,
                    avail_tx,
                    reg_tx,
                    leave_tx,
                    initial_source,
                    initial_hash_source,
                    violation_tx,
                    ext,
                    client_deny,
                    holepunch,
                    read_pool,
                    block_arena,
                    parent,
                    dht,
                    peer_dht,
                    peer_ext,
                    // BEP6 fast negotiation mirror (the outbound Reject gate).
                    peer_fast,
                )
                .await;
                return;
            }
            Ok(None) => attempts.push("handshake"),
            Err(_) => attempts.push(PUNCH_CLASS_TIMEOUT),
        }
    }
    // Punch window exhausted: one INFO line per target (the same
    // who-was-dialed-why-it-failed criterion as the regular arm).
    let nat_exhausted = punch_gave_up_nat(&attempts);
    info!(target: "taiji::core::engine", %addr,
        attempts = attempts.join(","),
        punch_window = PUNCH_ATTEMPT_MAX,
        nat_class = nat_exhausted,
        "punch dial failed (window exhausted)");
    super::run::dial::DialLogSampler::global()
        .note_result(false, attempts.last().copied().unwrap_or("no-transport"));
    if nat_exhausted {
        // Observation family: a fully silent window = the port
        // prediction face never opened (the NAT attribution; a single
        // feed point — reachable-class failures do not touch this
        // counter).
        super::run::holepunch::HP_PUNCH_FAILED_NAT.fetch_add(1, Ordering::Relaxed);
    }
    // Trigger bookkeeping proceeds as usual (a punch failure is a
    // real direct-connection failure — the re-rendezvous decision
    // after the 60s backoff lives in the main loop; the silent
    // classification is the regular arm's criterion). discovery =
    // false: punch-window dials do not enter the candidate table.
    report_hp_dial(
        addr,
        face,
        false,
        false,
        plan_is_silent(&attempts),
        punch,
        hp_report.as_ref(),
    )
    .await;
}

/// Dial-outcome report (a None report end = a no-op; the channel is
/// bounded, await backpressure, and a channel closed at engine
/// shutdown drops silently). `punch` = the source marker riding
/// [`super::run::holepunch::HpDialReport`] — the punch_established
/// feed predicate, independent of the BH_HOLEPUNCH_MODE switch.
/// `face` = the owning face; `discovery` = a discovery-source dial
/// (the failed-candidates-return-to-table field and its source
/// predicate — always false in the punch window).
async fn report_hp_dial(
    addr: SocketAddr,
    face: usize,
    discovery: bool,
    connected: bool,
    silent: bool,
    punch: bool,
    tx: Option<&mpsc::Sender<super::run::holepunch::HpDialReport>>,
) {
    if let Some(tx) = tx {
        let _ = tx
            .send(super::run::holepunch::HpDialReport {
                addr,
                connected,
                silent,
                punch,
                face,
                discovery,
            })
            .await;
    }
}
/// The crypto shapes of the outbound dial order (the named carrier of
/// the [`CryptoPolicy`] -> dial-order shape mapping; the mapping
/// table is at [`outbound_crypto_shape`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CryptoShape {
    /// require-crypto: MSE only, drop the connection on failure (the
    /// existing behavior, no fallback).
    MseOnly,
    /// `min-crypto-level=arc4` AND !require: MSE-first — start with
    /// MSE and, on failure, fall back to legacy plaintext on a fresh
    /// connection (the fallback is a dial-order shape change, not a
    /// protocol violation: a non-encrypting inbound face accepts
    /// legacy outbound as usual).
    MseFirstThenLegacy,
    /// `min-crypto-level=plain` AND !require (the default): direct
    /// legacy (the existing behavior, zero change in the default
    /// plain shape).
    LegacyOnly,
}

/// The outbound crypto shape mapping (existing options reused; no new
/// session/RPC options):
///
/// - `require_crypto` -> [`CryptoShape::MseOnly`]: the existing
///   behavior; the same upstream stance — under force/require, aria2
///   forbids a legacy retry after an MSE failure
///   (`InitiatorMSEHandshakeCommand.cc`).
/// - `min_level = Arc4` AND !require ->
///   [`CryptoShape::MseFirstThenLegacy`]: raising the minimum crypto
///   level to arc4 = outbound prefers encryption. Upstream cross-check:
///   aria2's outbound default is MSE-first
///   (`PeerInitiateConnectionCommand.h` defaults
///   `mseHandshakeEnabled=true`) and on an MSE failure (non-force/
///   require) it retries legacy on a fresh connection
///   (`InitiatorMSEHandshakeCommand.cc` — the failed negotiation's
///   bytes are not reusable); libtorrent's `out_enc_policy=pe_enabled`
///   is the same shape (prefer/fallback alternation per-peer
///   `pe_support`, `bt_peer_connection.cpp`). This mapping is more
///   conservative than aria2's default: the default plain shape does
///   not probe (keeping legacy-only peers free of a protocol-probe
///   round trip); only explicit arc4 enables MSE-first.
/// - `min_level = Plain` AND !require -> [`CryptoShape::LegacyOnly`]:
///   the existing behavior (zero regression in the default plain
///   shape).
///
/// Announce-bit consistency check (a zero-change conclusion): the
/// arc4-prefer shape still announces supportcrypto=1 (assemble.rs via
/// `mse::announce_crypto_param`; only require adds requirecrypto=1,
/// the `DefaultBtAnnounce.cc` stance) — this side still accepts legacy
/// inbound and outbound fallback under arc4-prefer, a non-require
/// face, so supportcrypto=1 is correct.
pub(super) fn outbound_crypto_shape(crypto: CryptoPolicy) -> CryptoShape {
    if crypto.require_crypto {
        CryptoShape::MseOnly
    } else if crypto.min_level == CryptoLevel::Arc4 {
        CryptoShape::MseFirstThenLegacy
    } else {
        CryptoShape::LegacyOnly
    }
}

/// The outbound crypto/handshake order (semantics generalized over
/// the transport): the shape comes from the [`outbound_crypto_shape`]
/// three-branch mapping (require -> MSE only, no fallback; min=arc4 ->
/// MSE-first + a legacy fallback on a fresh connection; default plain
/// -> direct legacy). `S` = `TcpStream` | `UtpStream` — a uTP stream
/// buffers application writes during SynSent (the io conn driver,
/// flushed on Connected), so the handshake writes are naturally
/// equivalent to waiting for the connection; a connection failure
/// presents as a read-side error or a budget timeout (the same 10s
/// budget guards both).
///
/// `redial` = the fresh-connection closure for the same target
/// (consumed only by the MSE-first fallback arm, at most once — a
/// failed MSE connection is not reusable, so the fallback dials fresh
/// as the reference does). The fallback reuses the existing same-tier
/// budgets (the MSE phase [`MSE_HANDSHAKE_TIMEOUT`] + the existing
/// connect budget for the fallback dial + the legacy handshake
/// [`MSE_HANDSHAKE_TIMEOUT`]); no new constants. Trade-off: a
/// silent/legacy-only endpoint pays one extra MSE timeout window (10s)
/// on the first connect; repeated silent endpoints are escalated by
/// the silent ledger at the dial gate. This module keeps no per-peer
/// preference memory (libtorrent avoids the repeated cost with
/// per-peer `pe_support` state, `bt_peer_connection.cpp`).
///
/// The returned tuple = `(transport stream, peer DHT bit, peer ext
/// bit, peer fast bit, peer peer_id, crypto level)` — the three
/// negotiated bits all come from the peer's handshake reserved
/// (BEP5/BEP10/BEP6) and ride into the connection via
/// [`attach_peer`].
pub(super) async fn handshake_over<S, R, RF>(
    stream: S,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    reserved: Reserved,
    crypto: CryptoPolicy,
    redial: R,
) -> Option<(Transit<S>, bool, bool, bool, [u8; 20], CryptoLevel)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: FnOnce() -> RF,
    RF: std::future::Future<Output = Option<S>>,
{
    match outbound_crypto_shape(crypto) {
        CryptoShape::MseOnly => {
            let (enc, level) =
                match mse::connect(stream, info_hash, crypto, MSE_HANDSHAKE_TIMEOUT).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        debug!(target: "taiji::core::engine", %addr, %e,
                            "MSE failed and bt-require-crypto forbids legacy fallback");
                        return None;
                    }
                };
            shook_mse(enc, level, addr, info_hash, peer_id, reserved).await
        }
        CryptoShape::MseFirstThenLegacy => {
            match mse::connect(stream, info_hash, crypto, MSE_HANDSHAKE_TIMEOUT).await {
                Ok((enc, level)) => shook_mse(enc, level, addr, info_hash, peer_id, reserved).await,
                Err(e) => {
                    // Fallback arm: MSE-first failed (a legacy-only peer's refusal /
                    // no answer / a negotiation rejection incl. timeout, the whole
                    // MseError family) -> log debug + fall back to legacy plaintext
                    // on a fresh connection (same target; the IpGuard verdict from
                    // the job start is reused — the same checkpoint discipline as
                    // the first connect).
                    debug!(target: "taiji::core::engine", %addr, %e,
                        "MSE-preferred handshake failed; retrying legacy on a fresh connection ");
                    let fresh = redial().await?;
                    shook_legacy(fresh, addr, info_hash, peer_id, reserved).await
                }
            }
        }
        CryptoShape::LegacyOnly => shook_legacy(stream, addr, info_hash, peer_id, reserved).await,
    }
}

/// The BT handshake tail after a successful MSE negotiation (shared
/// by the require / MSE-first arms). The returned tuple = `(transport
/// stream, peer DHT bit, peer ext bit, peer fast bit, peer peer_id,
/// crypto level)` — the three negotiated bits all come from the
/// peer's handshake reserved.
async fn shook_mse<S>(
    enc: Encrypted<S>,
    level: CryptoLevel,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    reserved: Reserved,
) -> Option<(Transit<S>, bool, bool, bool, [u8; 20], CryptoLevel)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match handshake_exchange(enc, &info_hash, &peer_id, reserved, MSE_HANDSHAKE_TIMEOUT).await {
        Ok((s, theirs)) => {
            debug!(target: "taiji::core::engine", %addr, ?level, "outbound MSE negotiated");
            Some((
                Transit::Mse(Box::new(s)),
                theirs.reserved.supports_dht(),
                theirs.reserved.supports_extended(),
                theirs.reserved.supports_fast(),
                theirs.peer_id,
                level,
            ))
        }
        Err(e) => {
            debug!(target: "taiji::core::engine", %addr, %e, "post-MSE handshake failed");
            None
        }
    }
}

/// The legacy direct handshake tail (shared by the default plain and
/// the MSE-first fallback arms; a successful fallback reports level =
/// Plain, consistent with the getPeers `crypto` field). The returned
/// tuple is the same as [`shook_mse`].
async fn shook_legacy<S>(
    stream: S,
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    reserved: Reserved,
) -> Option<(Transit<S>, bool, bool, bool, [u8; 20], CryptoLevel)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match handshake_exchange(
        stream,
        &info_hash,
        &peer_id,
        reserved,
        MSE_HANDSHAKE_TIMEOUT,
    )
    .await
    {
        Ok((s, theirs)) => Some((
            Transit::Plain(s),
            theirs.reserved.supports_dht(),
            theirs.reserved.supports_extended(),
            theirs.reserved.supports_fast(),
            theirs.peer_id,
            CryptoLevel::Plain,
        )),
        Err(e) => {
            debug!(target: "taiji::core::engine", %addr, %e, "legacy handshake failed");
            None
        }
    }
}

#[cfg(test)]
mod dial_result_log_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// Leave-reason projection table: the PeerEnd six states -> the
    /// closed five-class LeaveKind mapping — Clean = we disconnected /
    /// Cancelled = shutdown / Closed = peer EOF / Io = transport error
    /// / Violation+Flooded = the protocol face (two classes in one
    /// slot: the connection-table protocol attribution; the ban face
    /// keeps its own counters).
    #[test]
    fn leave_kind_projection_table() {
        use taiji_bt::peer::PeerEnd;
        let cases: [(PeerEnd, LeaveKind); 6] = [
            (PeerEnd::Clean, LeaveKind::Local),
            (PeerEnd::Cancelled, LeaveKind::Cancelled),
            (PeerEnd::Closed, LeaveKind::PeerClosed),
            (
                PeerEnd::Io {
                    kind: std::io::ErrorKind::Other,
                    message: "utp timeout".into(),
                },
                LeaveKind::Io,
            ),
            (
                PeerEnd::Violation(taiji_bt::peer::PeerError::ClientBanned(
                    "client-ban:test".into(),
                )),
                LeaveKind::Protocol,
            ),
            (PeerEnd::Flooded, LeaveKind::Protocol),
        ];
        for (end, want) in cases {
            assert_eq!(LeaveKind::of(&end), want, "end={end:?}");
        }
    }

    /// Log-capturing writer (the sink for the thread-local
    /// set_default subscription).
    #[derive(Clone, Default)]
    struct CaptureBuf(Arc<StdMutex<Vec<u8>>>);

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

    /// Minimal DialJob (a pure Tcp plan; the channels are mutually
    /// disconnected — failure paths deliver no events).
    fn dial_job(addr: SocketAddr) -> DialJob {
        let (avail_tx, _r1) = mpsc::channel(1);
        let (reg_tx, _r2) = mpsc::channel(1);
        let (leave_tx, _r3) = mpsc::channel(1);
        let (block_tx, _r4) = mpsc::channel(1);
        let (violation_tx, _r5) = mpsc::channel(1);
        let (ledger_tx, _r6) = mpsc::channel(1);
        DialJob {
            addr,
            face: 0,
            info_hash: [0x11; 20],
            peer_id: [7u8; 20],
            reserved: Reserved::empty(),
            cuid: 1,
            addressing: Addressing::Flat,
            piece_bytes: Vec::new().into(),
            avail_tx,
            initial_source: None,
            initial_hash_source: None,
            ext: taiji_bt::peer::ExtConfig::default(),
            reg_tx,
            leave_tx,
            block_tx,
            block_senders: Arc::new(StdMutex::new(HashMap::new())),
            block_sink: None,
            ledger_tx,
            guard: IpGuardHandle::new(taiji_bt::peer_policy::IpGuard::new([], [])),
            violation_tx,
            parent: CancellationToken::new(),
            crypto: CryptoPolicy::optional(),
            conn_type: PeerConnectionType::Tcp,
            utp: UtpDial::default(),
            dht: None,
            limits: None,
            redial: None,
            holepunch: None,
            hp_report: None,
            client_deny: None,
            read_pool: None,
            block_arena: None,
            punch: false,
            punch_mode: false,
            // The silent-ledger reading defaults to 0 (the full
            // plan); the trim behavior tests override it.
            fails: 0,
        }
    }

    /// Smoke test (the who-was-dialed-why-it-failed INFO line): an
    /// outbound dial to a closed local port logs one INFO line (addr +
    /// the attempts failure classes); a pure Tcp plan yields exactly
    /// one connect-refused class.
    #[tokio::test]
    async fn dial_failure_info_line_per_target() {
        let buf = CaptureBuf::default();
        use tracing_subscriber::util::SubscriberInitExt as _;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish()
            .set_default();
        let closed = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            l.local_addr().unwrap_or_else(|e| panic!("{e}"))
        };
        peer_connect(dial_job(closed)).await;
        let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            text.contains("dial failed"),
            "missing the result line: {text}"
        );
        assert!(
            text.contains(&format!("addr={closed}")),
            "missing the dial target: {text}"
        );
        assert!(
            text.contains("connect-refused"),
            "missing the failure class: {text}"
        );
    }

    /// Smoke test (an interception is also an outcome): an IpGuard
    /// hit -> one INFO line with class=blocked (failures logged
    /// wholesale) and no connect attempt.
    #[tokio::test]
    async fn dial_blocked_info_line() {
        let buf = CaptureBuf::default();
        use tracing_subscriber::util::SubscriberInitExt as _;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish()
            .set_default();
        let addr: SocketAddr = "127.0.0.1:9400".parse().unwrap_or_else(|e| panic!("{e}"));
        let mut job = dial_job(addr);
        job.guard = IpGuardHandle::new(taiji_bt::peer_policy::IpGuard::new(
            [taiji_bt::peer_policy::FilterRule {
                action: taiji_bt::peer_policy::RuleAction::Deny,
                start: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                end: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            }],
            [],
        ));
        peer_connect(job).await;
        let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            text.contains("dial skipped by IpGuard") && text.contains("blocked"),
            "missing the blocked result line: {text}"
        );
        assert!(
            !text.contains("connect failed"),
            "a blocked dial must have no connect attempt: {text}"
        );
    }

    /// Silent give-up classification table (plan_is_silent): asserts
    /// the four plan-failure classes — a handshake arm present =
    /// silent (TCP connected without a BT handshake / a silent uTP
    /// give-up); pure connect-* = explicitly unreachable, not silent;
    /// utp-connect = local uTP routing-face congestion, not evidence
    /// of a silent peer.
    #[test]
    fn plan_silent_classification_table() {
        // All four classes include a uTP-arm handshake -> silent.
        assert!(plan_is_silent(&["connect-timeout", "handshake"]));
        assert!(plan_is_silent(&["connect-error", "handshake"]));
        assert!(plan_is_silent(&["handshake", "handshake"]));
        assert!(plan_is_silent(&["connect-refused", "handshake"]));
        // Not silent: a pure TCP plan that is explicitly unreachable;
        // local uTP congestion (a full routing table).
        assert!(!plan_is_silent(&["connect-refused", "utp-connect"]));
        assert!(!plan_is_silent(&["connect-timeout"]));
        assert!(!plan_is_silent(&["connect-refused"]));
        // Empty plan (the defensive face).
        assert!(!plan_is_silent(&[]));
    }

    /// Punch-window-exhaustion attribution table (punch_gave_up_nat):
    /// all attempts budget-exhausted (punch-timeout) = zero peer
    /// replies during the whole window -> NAT attribution (the port
    /// prediction face never opened); any attempt failing explicitly
    /// within budget (the peer responded) or a local uTP face missing
    /// -> non-NAT; an empty sequence (defensive) = non-NAT.
    #[test]
    fn punch_nat_classification_table() {
        // Silent throughout -> NAT attribution (the same verdict for
        // one or several attempts in the window).
        assert!(punch_gave_up_nat(&[PUNCH_CLASS_TIMEOUT]));
        assert!(punch_gave_up_nat(&[
            PUNCH_CLASS_TIMEOUT,
            PUNCH_CLASS_TIMEOUT,
            PUNCH_CLASS_TIMEOUT
        ]));
        // Peer reachable but refusing (an in-budget handshake
        // failure) -> non-NAT (the NAT count untouched).
        assert!(!punch_gave_up_nat(&["handshake"]));
        assert!(!punch_gave_up_nat(&[PUNCH_CLASS_TIMEOUT, "handshake"]));
        assert!(!punch_gave_up_nat(&["handshake", PUNCH_CLASS_TIMEOUT]));
        // The local uTP face absent (utp-connect stop-loss) ->
        // non-NAT.
        assert!(!punch_gave_up_nat(&["utp-connect"]));
        assert!(!punch_gave_up_nat(&[PUNCH_CLASS_TIMEOUT, "utp-connect"]));
        // Empty sequence (the defensive face).
        assert!(!punch_gave_up_nat(&[]));
    }

    /// Constant provenance lock: the attempt cap = libtorrent
    /// max_failcount = 3 (`settings_pack.cpp`); the per-attempt budget
    /// = utp_connect_timeout = 3s (`settings_pack.cpp` + the same
    /// value in utp_stream.cpp's no-RTT-estimate SYN timeout arm); the
    /// punch window ~9s <= the regular single-transport 10s budget
    /// (fast retry does not enlarge the per-target window).
    #[test]
    fn punch_window_constants_locked() {
        assert_eq!(
            PUNCH_ATTEMPT_MAX, 3,
            "max_failcount same value (provenance note lives at the constant)"
        );
        assert_eq!(
            PUNCH_ATTEMPT_BUDGET,
            Duration::from_secs(3),
            "utp_connect_timeout same value (provenance note lives at the constant)"
        );
        assert!(
            PUNCH_ATTEMPT_MAX as u64 * PUNCH_ATTEMPT_BUDGET.as_secs()
                <= MSE_HANDSHAKE_TIMEOUT.as_secs(),
            "the punch total window <= the regular single-transport budget (fast retry does not enlarge the occupied window)"
        );
    }

    // ---- uTP dial-queue hang governance ----

    /// The uTP dial total-budget mapping table
    /// (`utp_dial_budget_of_secs`): 0 -> None (the old unbounded
    /// behavior = the emergency fallback seam); positive -> a seconds
    /// budget. The parse face (default/0/invalid fallback) is locked
    /// in the `taiji_io::knobs` domain; this table locks the core-side
    /// mapping.
    #[test]
    fn utp_dial_budget_mapping_table() {
        assert_eq!(
            utp_dial_budget_of_secs(0),
            None,
            "0 = the unbounded fallback seam"
        );
        assert_eq!(utp_dial_budget_of_secs(10), Some(Duration::from_secs(10)));
        assert_eq!(utp_dial_budget_of_secs(25), Some(Duration::from_secs(25)));
    }

    /// Timeout -> None (short-budget injection drives
    /// [`UtpDial::connect_bounded`] directly, without really waiting
    /// for the 10s default): a pre-filled bounded(1) queue with no
    /// consumer leaves `tx.send().await` stuck forever (the original
    /// failure shape); the 100ms budget guard fires first -> None, in
    /// well under a second (if the budget face regresses, this test
    /// hangs until the outer test timeout and goes red).
    #[tokio::test]
    async fn utp_dial_budget_times_out_to_none() {
        let (req_tx, _req_rx_alive_never_consumed) = mpsc::channel::<UtpDialReq>(1);
        // Pre-fill one entry occupying the only slot (simulating a
        // stuck dead-address request).
        let (dummy_back, _dummy_rx) = oneshot::channel();
        req_tx
            .send((
                "127.0.0.1:9461".parse().unwrap_or_else(|e| panic!("{e}")),
                dummy_back,
            ))
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let dial = UtpDial {
            v4: Some(req_tx),
            v6: None,
        };
        let addr: SocketAddr = "127.0.0.1:9462".parse().unwrap_or_else(|e| panic!("{e}"));
        let started = std::time::Instant::now();
        let res = dial
            .connect_bounded(addr, Some(Duration::from_millis(100)))
            .await;
        assert!(
            res.is_none(),
            "budget exhaustion must settle at None (the utp-connect failure class upstream)"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the short budget must return first, measured {:?}",
            started.elapsed()
        );
    }

    /// The unbounded fallback seam (`BH_UTP_DIAL_TIMEOUT_SECS=0`
    /// semantics): budget None = the old behavior passes through —
    /// with a clear queue (a consumer replies immediately) it returns
    /// normally, with no extra timeout layer.
    #[tokio::test]
    async fn utp_dial_budget_none_passes_through() {
        let (req_tx, mut req_rx) = mpsc::channel::<UtpDialReq>(1);
        let dial = UtpDial {
            v4: Some(req_tx),
            v6: None,
        };
        let addr: SocketAddr = "127.0.0.1:9463".parse().unwrap_or_else(|e| panic!("{e}"));
        // None = the old unbounded behavior: served normally by a
        // concurrent consumer (zero budget-layer involvement — if a
        // timeout layer were wrongly added, this test still has to
        // return under an instant reply; it locks the passthrough).
        let call = tokio::spawn(async move { dial.connect_bounded(addr, None).await });
        let (_, back) = match req_rx.recv().await {
            Some(req) => req,
            None => panic!("the delegated-dial request channel closed early"),
        };
        let _ = back.send(None);
        let res = call.await.unwrap_or_else(|e| panic!("{e}"));
        assert!(
            res.is_none(),
            "the reply payload passes through unchanged (None = the face is absent)"
        );
    }

    /// Queue closed (all senders dropped / the consumer task dead) ->
    /// None and the existing utp-connect failure class (timeout / a
    /// dead reply end take the same route — the `peer_connect` Utp
    /// arm's else branch, existing semantics; this test locks the
    /// terminal classification): a pure Utp plan + a dead queue -> an
    /// INFO line with attempts=utp-connect (plan exhausted).
    #[tokio::test]
    async fn utp_dial_dead_queue_routes_to_utp_connect_class() {
        let buf = CaptureBuf::default();
        use tracing_subscriber::util::SubscriberInitExt as _;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish()
            .set_default();
        let (req_tx, req_rx) = mpsc::channel::<UtpDialReq>(1);
        drop(req_rx); // queue closed: send errs at once -> None (no budget wait).
        let addr: SocketAddr = "127.0.0.1:9464".parse().unwrap_or_else(|e| panic!("{e}"));
        let mut job = dial_job(addr);
        job.conn_type = PeerConnectionType::Utp;
        job.utp = UtpDial {
            v4: Some(req_tx),
            v6: None,
        };
        peer_connect(job).await;
        let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            text.contains("dial failed"),
            "missing the result line: {text}"
        );
        assert!(
            text.contains("attempts=\"utp-connect\""),
            "missing the utp-connect failure class: {text}"
        );
    }

    /// Dead-address uTP-arm trim four-quadrant table (the
    /// [`skip_dead_utp_arm`] pure function): fails 0/1 x transport
    /// Tcp/Utp x switch on/off — only fails>=1 AND Utp AND on trims;
    /// the first attempt (fails=0) always keeps the full plan.
    #[test]
    fn skip_dead_utp_arm_table() {
        // fails=0: the uTP arm is kept (good peers keep their uTP
        // path).
        assert!(!skip_dead_utp_arm(0, Transport::Utp, true));
        assert!(!skip_dead_utp_arm(0, Transport::Tcp, true));
        assert!(!skip_dead_utp_arm(0, Transport::Utp, false));
        // fails>=1 AND the TCP arm: no trim (the trim only removes
        // the uTP second try).
        assert!(!skip_dead_utp_arm(1, Transport::Tcp, true));
        assert!(!skip_dead_utp_arm(3, Transport::Tcp, false));
        // fails>=1 AND the uTP arm AND the switch on: trim (the only
        // true quadrant).
        assert!(skip_dead_utp_arm(1, Transport::Utp, true));
        assert!(skip_dead_utp_arm(3, Transport::Utp, true));
        // Switch off (BH_DIAL_DEAD_TCP_ONLY=0): the full plan is
        // restored.
        assert!(!skip_dead_utp_arm(1, Transport::Utp, false));
        assert!(!skip_dead_utp_arm(3, Transport::Utp, false));
    }

    /// The uTP-preferred dial-plan two-arm table (the
    /// [`outbound_dial_plan`] pure function): off = [Tcp, Utp]
    /// unchanged (the prefer-tcp default, zero behavior change,
    /// `dial_plan` as-is); on = [Utp, Tcp] (the uTP fallback arm
    /// becomes primary, BEP29 LEDBAT yields); pure types = the user's
    /// explicit only-type choices, never second-guessed; PreferUtp is
    /// already uTP-primary.
    #[test]
    fn outbound_dial_plan_prefer_utp_two_arm_table() {
        // Off arm: identical to dial_plan(PreferTcp) (the SPEC §6.1
        // default promise, zero change).
        assert_eq!(
            outbound_dial_plan(PeerConnectionType::PreferTcp, false),
            [Some(Transport::Tcp), Some(Transport::Utp)]
        );
        // On arm: [Tcp, Utp] flips to [Utp, Tcp] (uTP primary + one
        // TCP fallback).
        assert_eq!(
            outbound_dial_plan(PeerConnectionType::PreferTcp, true),
            [Some(Transport::Utp), Some(Transport::Tcp)]
        );
        // Pure types untouched (explicit only-type choices: tcp-only /
        // utp-only neither degrades nor gets second-guessed).
        assert_eq!(
            outbound_dial_plan(PeerConnectionType::Tcp, true),
            [Some(Transport::Tcp), None]
        );
        assert_eq!(
            outbound_dial_plan(PeerConnectionType::Utp, true),
            [Some(Transport::Utp), None]
        );
        // PreferUtp is the same in both arms (already [Utp, Tcp] —
        // the flip is idempotent).
        assert_eq!(
            outbound_dial_plan(PeerConnectionType::PreferUtp, false),
            [Some(Transport::Utp), Some(Transport::Tcp)]
        );
        assert_eq!(
            outbound_dial_plan(PeerConnectionType::PreferUtp, true),
            [Some(Transport::Utp), Some(Transport::Tcp)]
        );
    }

    /// Combined arms: the uTP-preferred flip x the dead-address trim
    /// are orthogonal — the flip acts on arm order, the trim on arm
    /// filtering, order-then-filter, each unaware of the other: both
    /// on AND fails >= 1 -> the flipped [Utp, Tcp] plan's uTP arm is
    /// trimmed and the TCP arm kept (the only attempt = TCP); trim off
    /// -> the flipped order is intact (uTP first).
    #[test]
    fn prefer_utp_flip_composes_with_dead_trim() {
        // Both on AND fails=1: the uTP first arm is trimmed, the TCP
        // arm kept.
        let arms: Vec<Transport> = outbound_dial_plan(PeerConnectionType::PreferTcp, true)
            .into_iter()
            .flatten()
            .filter(|&t| !skip_dead_utp_arm(1, t, true))
            .collect();
        assert_eq!(
            arms,
            vec![Transport::Tcp],
            "the µTP arm trimmed, the TCP arm kept"
        );
        // Trim off (flip on): both arms intact, uTP first (LEDBAT
        // primary order).
        let arms: Vec<Transport> = outbound_dial_plan(PeerConnectionType::PreferTcp, true)
            .into_iter()
            .flatten()
            .filter(|&t| !skip_dead_utp_arm(1, t, false))
            .collect();
        assert_eq!(arms, vec![Transport::Utp, Transport::Tcp]);
        // fails=0 (the first try): with both on, the uTP first arm is
        // kept (no dead-address memory — good peers keep their uTP
        // path).
        let arms: Vec<Transport> = outbound_dial_plan(PeerConnectionType::PreferTcp, true)
            .into_iter()
            .flatten()
            .filter(|&t| !skip_dead_utp_arm(0, t, true))
            .collect();
        assert_eq!(arms, vec![Transport::Utp, Transport::Tcp]);
    }

    /// `fails` passthrough behavior lock (DialJob.fails -> consumed by
    /// the plan loop): a fails>=1 prefer-tcp dial against a uTP face
    /// that stalls (a live queue with no consumer) converges in
    /// bounded time — with BH_DIAL_DEAD_TCP_ONLY defaulting off, the
    /// uTP arm is attempted and capped by the dial budget (the default
    /// 10s): this test locks the no-unbounded-hang invariant (the old
    /// behavior was send/rx forever). The trim behavior face (=1 ->
    /// utp-skip-dead sub-second convergence) is locked by the
    /// `skip_dead_utp_arm_table` pure-function test.
    #[tokio::test]
    async fn dead_address_utp_arm_trimmed() {
        let buf = CaptureBuf::default();
        use tracing_subscriber::util::SubscriberInitExt as _;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish()
            .set_default();
        let closed = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            l.local_addr().unwrap_or_else(|e| panic!("{e}"))
        };
        // A live queue but no consumer: the uTP arm is attempted (the
        // default off) and the connect converges bounded by the dial
        // budget (the default 10s window — the old behavior hung
        // forever).
        let (req_tx, _req_rx_alive) = mpsc::channel::<UtpDialReq>(1);
        let mut job = dial_job(closed);
        job.conn_type = PeerConnectionType::PreferTcp;
        job.utp = UtpDial {
            v4: Some(req_tx),
            v6: None,
        };
        job.fails = 2;
        let started = std::time::Instant::now();
        peer_connect(job).await;
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the µTP arm should converge bounded by the dial budget (the default \
             10s window), measured {:?}",
            started.elapsed()
        );
        let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            text.contains("utp-connect"),
            "with the default off, the µTP arm should be attempted (the budget-timeout \
             route): {text}"
        );
        assert!(
            !text.contains("utp-skip-dead"),
            "with the default off there should be no trim trace: {text}"
        );
        assert!(
            text.contains("connect-refused"),
            "the TCP arm attempted as usual: {text}"
        );
    }

    /// `fails` passthrough behavior lock, the counterpart arm (the
    /// first attempt keeps the full plan): with fails=0 in the same
    /// scenario the uTP arm is attempted as usual — a dead queue
    /// returns None quickly and the result line contains utp-connect
    /// (a good peer's uTP path is not lost to governance).
    #[tokio::test]
    async fn fresh_address_keeps_utp_arm() {
        let buf = CaptureBuf::default();
        use tracing_subscriber::util::SubscriberInitExt as _;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(buf.clone())
            .finish()
            .set_default();
        let closed = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            l.local_addr().unwrap_or_else(|e| panic!("{e}"))
        };
        let (req_tx, req_rx) = mpsc::channel::<UtpDialReq>(1);
        drop(req_rx); // dead queue: the uTP try returns None fast (no budget wait).
        let mut job = dial_job(closed);
        job.conn_type = PeerConnectionType::PreferTcp;
        job.utp = UtpDial {
            v4: Some(req_tx),
            v6: None,
        };
        job.fails = 0;
        peer_connect(job).await;
        let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            text.contains("attempts=\"connect-refused,utp-connect\""),
            "the full plan should contain the µTP attempt class: {text}"
        );
        assert!(
            !text.contains("utp-skip-dead"),
            "fails=0 should not trim: {text}"
        );
    }
}

/// Outbound crypto three-branch tests (the [`handshake_over`] face;
/// all in-process — loopback TCP + real MSE/BT handshake bytes, with
/// a mock peer task as the other end): MSE-first builds a duplex
/// connection to an encrypting peer (ARC4 both ways); against a
/// legacy-only peer it falls back to legacy on a fresh connection
/// (exactly one fallback redial); a require-crypto failure aborts
/// with the fallback forbidden (the existing behavior); the default
/// plain shape is always legacy-first (zero regression). The mapping
/// decision table also has a pure-function table test at
/// [`outbound_crypto_shape`].
#[cfg(test)]
mod outbound_crypto_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use taiji_io::mse as io_mse;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const IH: [u8; 20] = [0x3c; 20];
    const MY_PID: [u8; 20] = *b"-TJ0001-OUTBOUNDTEST";
    const PEER_PID: [u8; 20] = *b"-TJ0001-MOCKPEERTEST";
    /// BEP3 unchoke frame (written back peer-ward; the duplex
    /// carriage proof).
    const UNCHOKE: [u8; 5] = [0, 0, 0, 1, 1];

    /// Test helper for unwrapping Result (lints forbid
    /// unwrap/expect).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// Test helper for unwrapping Option.
    fn some<T>(v: Option<T>, what: &str) -> T {
        match v {
            Some(v) => v,
            None => panic!("{what}"),
        }
    }

    /// The new-shape policy: min=arc4 AND !require.
    fn arc4_prefer() -> CryptoPolicy {
        CryptoPolicy {
            require_crypto: false,
            min_level: CryptoLevel::Arc4,
        }
    }

    /// Fallback-redial counter probe (the no-fallback assertion:
    /// count = 0).
    fn probe() -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(0))
    }

    /// Mapping decision table (the pure-function face, no IO).
    #[test]
    fn outbound_shape_mapping_table() {
        // require wins over min-level (require-crypto semantics
        // as-is).
        assert_eq!(
            outbound_crypto_shape(CryptoPolicy {
                require_crypto: true,
                min_level: CryptoLevel::Plain
            }),
            CryptoShape::MseOnly
        );
        assert_eq!(
            outbound_crypto_shape(CryptoPolicy {
                require_crypto: true,
                min_level: CryptoLevel::Arc4
            }),
            CryptoShape::MseOnly
        );
        // Default (SPEC §11 optional+plain) -> direct legacy (zero
        // regression).
        assert_eq!(
            outbound_crypto_shape(CryptoPolicy::optional()),
            CryptoShape::LegacyOnly
        );
        // min=arc4 AND !require -> MSE-first + a legacy fallback on a
        // fresh connection.
        assert_eq!(
            outbound_crypto_shape(arc4_prefer()),
            CryptoShape::MseFirstThenLegacy
        );
    }

    /// Branch 1 (MSE success): MSE-first builds a duplex connection
    /// to an encryption-capable mock peer — the initiator's ARC4-only
    /// provide forces the receiver to pick ARC4, the BT handshake
    /// completes both ways over the Encrypted stream, and the
    /// peer-ward unchoke is readable ciphertext; zero fallback
    /// redials.
    #[tokio::test]
    async fn mse_first_duplex_negotiates_arc4() {
        let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
        let addr = ok(listener.local_addr(), "local_addr");
        let peer = tokio::spawn(async move {
            let (sock, _) = ok(listener.accept().await, "accept");
            // The receiver face is optional: the initiator's provide
            // contains only ARC4 (min=arc4 excludes the plain bit), so
            // select_from_provide has no plain to pick -> always ARC4.
            let (negotiated, _) = ok(
                io_mse::receive(
                    sock,
                    &[IH],
                    CryptoPolicy::optional(),
                    Duration::from_secs(10),
                )
                .await,
                "mse receive",
            );
            assert_eq!(
                negotiated.crypto,
                CryptoLevel::Arc4,
                "arc4-prefer initiator provide excludes plain"
            );
            let (mut stream, hs) = ok(
                taiji_bt::peer::handshake_accept(
                    negotiated.stream,
                    &IH,
                    &PEER_PID,
                    Reserved::aria2_default(),
                    Duration::from_secs(10),
                )
                .await,
                "bt accept over MSE",
            );
            assert_eq!(hs.peer_id, MY_PID, "the initiator identity carried via MSE");
            ok(stream.write_all(&UNCHOKE).await, "write unchoke");
        });

        let probe = probe();
        let p = probe.clone();
        let sock = ok(tokio::net::TcpStream::connect(addr).await, "connect");
        let (mut stream, _, _, _, their_pid, level) = some(
            handshake_over(
                sock,
                addr,
                IH,
                MY_PID,
                Reserved::aria2_default(),
                arc4_prefer(),
                move || {
                    let p = p.clone();
                    async move {
                        p.fetch_add(1, Ordering::SeqCst);
                        None
                    }
                },
            )
            .await,
            "MSE-first must establish the connection to an encrypting peer",
        );
        assert!(
            matches!(stream, Transit::Mse(_)),
            "the success path = MSE wrapper"
        );
        assert_eq!(level, CryptoLevel::Arc4, "negotiated level = ARC4");
        assert_eq!(their_pid, PEER_PID);
        assert_eq!(
            probe.load(Ordering::SeqCst),
            0,
            "the success path has zero fallback redials"
        );
        // Duplex proof: the engine-ward ARC4 ciphertext is decodable
        // (the unchoke reads back as written).
        let mut frame = [0u8; 5];
        let n = ok(
            ok(
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut frame)).await,
                "read unchoke over MSE: timeout",
            ),
            "read unchoke over MSE",
        );
        assert_eq!(n, 5);
        assert_eq!(frame, UNCHOKE);
        ok(
            ok(
                tokio::time::timeout(Duration::from_secs(10), peer).await,
                "peer join timeout",
            ),
            "peer join",
        );
    }

    /// Branch 2 (fallback success): arc4-prefer against a legacy-only
    /// peer — the first connection sends the MSE pubkey (96B fixed
    /// width; a legacy handshake is only 68B, so reading a full 96B
    /// proves the first connection was MSE-first), the peer drops it,
    /// and the fallback dials legacy plaintext on a fresh connection
    /// (exactly one fallback redial) -> a Plain-level duplex
    /// connection.
    #[tokio::test]
    async fn mse_first_falls_back_to_legacy_for_legacy_only_peer() {
        let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
        let addr = ok(listener.local_addr(), "local_addr");
        let peer = tokio::spawn(async move {
            // Connection 1: read a full MSE step1 pubkey (96B) ->
            // close without answering (the effective shape of a
            // legacy-only peer: unable to parse the MSE byte face ->
            // disconnect).
            let (mut s1, _) = ok(listener.accept().await, "accept 1");
            let mut step1 = [0u8; io_mse::KEY_LENGTH];
            ok(
                ok(
                    tokio::time::timeout(Duration::from_secs(10), s1.read_exact(&mut step1)).await,
                    "read mse pubkey: timeout",
                ),
                "read mse pubkey (proves MSE-first)",
            );
            drop(s1);
            // Connection 2: a legacy handshake + unchoke (the
            // plaintext face after the fallback).
            let (s2, _) = ok(listener.accept().await, "accept 2");
            let (mut stream, hs) = ok(
                taiji_bt::peer::handshake_accept(
                    s2,
                    &IH,
                    &PEER_PID,
                    Reserved::aria2_default(),
                    Duration::from_secs(10),
                )
                .await,
                "legacy accept",
            );
            assert_eq!(hs.peer_id, MY_PID);
            ok(stream.write_all(&UNCHOKE).await, "write unchoke");
        });

        let probe = probe();
        let p = probe.clone();
        let sock = ok(tokio::net::TcpStream::connect(addr).await, "connect");
        let (mut stream, _, _, _, their_pid, level) = some(
            handshake_over(
                sock,
                addr,
                IH,
                MY_PID,
                Reserved::aria2_default(),
                arc4_prefer(),
                // Fallback redial = a fresh connection (the same
                // shape as the peer_connect TCP arm; counted).
                move || {
                    let p = p.clone();
                    async move {
                        p.fetch_add(1, Ordering::SeqCst);
                        tokio::net::TcpStream::connect(addr).await.ok()
                    }
                },
            )
            .await,
            "the legacy fallback must establish the connection",
        );
        assert!(
            matches!(stream, Transit::Plain(_)),
            "the fallback path = plaintext"
        );
        assert_eq!(level, CryptoLevel::Plain, "fallback level = Plain");
        assert_eq!(their_pid, PEER_PID);
        assert_eq!(
            probe.load(Ordering::SeqCst),
            1,
            "exactly one fallback redial"
        );
        let mut frame = [0u8; 5];
        let n = ok(
            ok(
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut frame)).await,
                "read unchoke over legacy fallback: timeout",
            ),
            "read unchoke over legacy fallback",
        );
        assert_eq!(n, 5);
        assert_eq!(frame, UNCHOKE);
        ok(
            ok(
                tokio::time::timeout(Duration::from_secs(10), peer).await,
                "peer join timeout",
            ),
            "peer join",
        );
    }

    /// Branch 3 (require, the existing behavior): under require-crypto
    /// an MSE failure -> an immediate abort (None) and zero fallback
    /// redials — no silent plaintext fallback (semantics unchanged).
    #[tokio::test]
    async fn require_crypto_mse_failure_never_falls_back() {
        let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
        let addr = ok(listener.local_addr(), "local_addr");
        let peer = tokio::spawn(async move {
            // Close right after accept: the initiator's MSE first
            // step hits EOF reading the peer pubkey.
            let (s, _) = ok(listener.accept().await, "accept");
            drop(s);
        });
        let probe = probe();
        let p = probe.clone();
        let sock = ok(tokio::net::TcpStream::connect(addr).await, "connect");
        let result = handshake_over(
            sock,
            addr,
            IH,
            MY_PID,
            Reserved::aria2_default(),
            CryptoPolicy {
                require_crypto: true,
                min_level: CryptoLevel::Plain,
            },
            move || {
                let p = p.clone();
                async move {
                    p.fetch_add(1, Ordering::SeqCst);
                    None
                }
            },
        )
        .await;
        assert!(
            result.is_none(),
            "under require-crypto an MSE failure must abandon the connection"
        );
        assert_eq!(
            probe.load(Ordering::SeqCst),
            0,
            "require-crypto forbids a fallback redial"
        );
        let _ = ok(
            tokio::time::timeout(Duration::from_secs(10), peer).await,
            "peer join",
        );
    }

    /// Default plain zero regression: the optional policy is always
    /// legacy-first — the peer's legacy accept succeeding outright
    /// proves the first bytes were the 68B legacy handshake (MSE step1
    /// is a 96B random pubkey; `Handshake::decode`'s pstr check would
    /// fail); zero fallback redials.
    #[tokio::test]
    async fn optional_plain_stays_legacy_first() {
        let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
        let addr = ok(listener.local_addr(), "local_addr");
        let peer = tokio::spawn(async move {
            let (sock, _) = ok(listener.accept().await, "accept");
            let (mut stream, hs) = ok(
                taiji_bt::peer::handshake_accept(
                    sock,
                    &IH,
                    &PEER_PID,
                    Reserved::aria2_default(),
                    Duration::from_secs(10),
                )
                .await,
                "legacy accept (first bytes must be legacy handshake)",
            );
            assert_eq!(hs.peer_id, MY_PID);
            ok(stream.write_all(&UNCHOKE).await, "write unchoke");
        });
        let probe = probe();
        let p = probe.clone();
        let sock = ok(tokio::net::TcpStream::connect(addr).await, "connect");
        let (mut stream, _, _, _, their_pid, level) = some(
            handshake_over(
                sock,
                addr,
                IH,
                MY_PID,
                Reserved::aria2_default(),
                CryptoPolicy::optional(),
                move || {
                    let p = p.clone();
                    async move {
                        p.fetch_add(1, Ordering::SeqCst);
                        None
                    }
                },
            )
            .await,
            "the default plain legacy connection must succeed",
        );
        assert!(matches!(stream, Transit::Plain(_)));
        assert_eq!(level, CryptoLevel::Plain);
        assert_eq!(their_pid, PEER_PID);
        assert_eq!(
            probe.load(Ordering::SeqCst),
            0,
            "the legacy direct path has zero redials"
        );
        let mut frame = [0u8; 5];
        let n = ok(
            ok(
                tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut frame)).await,
                "read unchoke over legacy: timeout",
            ),
            "read unchoke over legacy",
        );
        assert_eq!(n, 5);
        assert_eq!(frame, UNCHOKE);
        ok(
            ok(
                tokio::time::timeout(Duration::from_secs(10), peer).await,
                "peer join timeout",
            ),
            "peer join",
        );
    }
}

/// [`FaceBlockSink`] unit tests: five points of direct-delivery seam
/// semantics — (1) to_flat conversion + an attribution insert + a
/// pre-registration count + the payload straight into the face
/// channel; (2) v2 PerFile addressing conversion; (3) out-of-range
/// defense = skip + `Ok(())` (the old forward path's continue, not
/// backpressure; zero count/attribution registration); (4) a full
/// channel returns the payload as-is (`Err`, no partial
/// registration), and the backpressure slow path completes the
/// count/attribution after its await delivery; (5) count conservation
/// is paired with the pipeline's decrement-on-confirm — this module
/// only locks the sink side's monotonic increment and that the full
/// path registers nothing.
#[cfg(test)]
mod block_sink_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    type Senders = Arc<std::sync::Mutex<HashMap<(u32, u32), u64>>>;

    struct Rig {
        sink: FaceBlockSink,
        rx: mpsc::Receiver<BlockMsg>,
        senders: Senders,
        inflight: Arc<AtomicU64>,
    }

    fn rig(addressing: Addressing, channel: usize) -> Rig {
        let (tx, rx) = mpsc::channel(channel);
        let senders: Senders = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let inflight = Arc::new(AtomicU64::new(0));
        Rig {
            sink: FaceBlockSink {
                addressing,
                cuid: 7,
                block_senders: Arc::clone(&senders),
                block_tx: tx,
                inflight: Arc::clone(&inflight),
            },
            rx,
            senders,
            inflight,
        }
    }

    /// (1) v1 identity conversion: coordinates/payload arrive verbatim
    /// at the channel; attribution records the cuid; count +1.
    #[tokio::test]
    async fn deliver_converts_attributes_counts_and_forwards() {
        let mut r = rig(Addressing::Flat, 4);
        let payload = Bytes::from_static(b"payload");
        r.sink
            .try_deliver(PieceId::V1(3), 16384, payload.clone())
            .unwrap_or_else(|_| panic!("with spare capacity this must succeed (no backpressure)"));
        let (index, begin, block) =
            r.rx.recv()
                .await
                .unwrap_or_else(|| panic!("the face channel closed"));
        assert_eq!(
            (index, begin),
            (3, 16384),
            "flat coordinates delivered verbatim"
        );
        assert_eq!(
            block, payload,
            "the payload delivered zero-copy (Bytes refcount)"
        );
        assert_eq!(
            r.senders
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&(3, 16384)),
            Some(&7),
            "attribution = this connection's cuid (the same insert point as the old forward path)"
        );
        assert_eq!(
            r.inflight.load(Ordering::Relaxed),
            1,
            "pre-registration count +1"
        );
    }

    /// (2) v2 PerFile: the wire-coordinate conversion stays in the
    /// core-side sink (the same point as the old forward path).
    #[tokio::test]
    async fn deliver_converts_per_file_addressing() {
        let mut r = rig(Addressing::per_file(&[70_000, 30_000], 16_384), 4);
        // File 0 spans 5 pieces (bases = [0, 5, 6]): file 1's in-file
        // piece 1 -> flat 6.
        r.sink
            .try_deliver(
                PieceId::V2 {
                    file_index: 1,
                    piece_in_file: 1,
                },
                0,
                Bytes::from_static(b"x"),
            )
            .unwrap_or_else(|_| panic!("a legal v2 coordinate"));
        let (index, begin, _) = r.rx.recv().await.unwrap_or_else(|| panic!("channel"));
        assert_eq!(
            (index, begin),
            (6, 0),
            "v2 -> synthetic flat piece index converted correctly"
        );
    }

    /// (3) Out-of-range defense: skip + `Ok(())` (consumed semantics,
    /// not backpressure — the bt side does not redeliver); zero
    /// count/attribution registration (the old forward path's
    /// warn+continue).
    #[tokio::test]
    async fn deliver_skips_out_of_range_like_forward_path() {
        let mut r = rig(Addressing::per_file(&[70_000, 30_000], 16_384), 4);
        r.sink
            .try_deliver(
                PieceId::V2 {
                    file_index: 9,
                    piece_in_file: 0,
                },
                0,
                Bytes::from_static(b"x"),
            )
            .unwrap_or_else(|b| {
                panic!("defensive skip = Ok (no backpressure, no redelivery), got {b:?}")
            });
        assert!(
            r.rx.try_recv().is_err(),
            "an out-of-range block never enters the face channel"
        );
        assert!(
            r.senders
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "out-of-range: zero attribution registration"
        );
        assert_eq!(
            r.inflight.load(Ordering::Relaxed),
            0,
            "out-of-range: zero count"
        );
    }

    /// (4) A full channel: the payload is returned as-is (`Err`) and
    /// pre-registration (count/attribution) does not happen; the
    /// backpressure slow path completes count/attribution after its
    /// await delivery — the bt-side call shape = a `try_deliver`
    /// failure turns into `deliver_backpressure().await` (pausing the
    /// read loop compresses the peer window, the reference's disk-I/O
    /// backpressure shape).
    #[tokio::test]
    async fn full_channel_returns_block_and_backpressure_path_delivers() {
        let mut r = rig(Addressing::Flat, 1);
        r.sink
            .try_deliver(PieceId::V1(0), 0, Bytes::from_static(b"a"))
            .unwrap_or_else(|_| panic!("the first block enqueued"));
        let block = Bytes::from_static(b"bbbb");
        let returned = match r.sink.try_deliver(PieceId::V1(1), 0, block.clone()) {
            Err(b) => b,
            Ok(()) => panic!("a full channel must return the payload (Err semantics)"),
        };
        assert_eq!(returned, block, "the full path returns the payload as-is");
        assert_eq!(
            r.inflight.load(Ordering::Relaxed),
            1,
            "the full path does not pre-register"
        );
        assert_eq!(
            r.senders.lock().unwrap_or_else(|e| e.into_inner()).len(),
            1,
            "the full path registers zero attribution (does not pollute the \
             last-arriver semantics)"
        );
        // Drain the first block first (the test isomorph of the
        // pipeline consuming independently): the backpressure await
        // can only return once the channel has room — in the real
        // face the pipeline task consumes independently; inside the
        // test the same task is serial, so it must recv before
        // awaiting (otherwise it waits on itself, deadlocked).
        let first = r.rx.recv().await.unwrap_or_else(|| panic!("channel"));
        assert_eq!(
            first.2,
            Bytes::from_static(b"a"),
            "the first block exits first"
        );
        r.sink.deliver_backpressure(PieceId::V1(1), 0, block).await;
        let (_, _, got) = r.rx.recv().await.unwrap_or_else(|| panic!("channel"));
        assert_eq!(
            got,
            Bytes::from_static(b"bbbb"),
            "the backpressure path delivers"
        );
        assert_eq!(
            r.inflight.load(Ordering::Relaxed),
            2,
            "the backpressure path completes the count"
        );
        assert_eq!(
            r.senders
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&(1, 0)),
            Some(&7),
            "the backpressure path completes the attribution"
        );
    }
}

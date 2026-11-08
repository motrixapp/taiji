//! UdpDemux: the shared v4/v6 UDP entry (SPEC §3.2 UdpDemuxTask row,
//! §6.6; a frozen dispatch contract — implementations must not change
//! the shape).
//!
//! DHT (BEP-5 KRPC), the UDP tracker (BEP-15) and µTP (BEP-29) share
//! one UDP port: one demux task per family (v4/v6) owns the
//! [`UdpSocket`] and dispatches inbound data into the DHT /
//! UDP-tracker / µTP bounded mpsc channels by packet signature; all
//! outbound traffic funnels through the [`OutboundPacket`] mpsc and
//! the demux task is the single `send_to` writer.
//!
//! # Classification rules (evaluated in order; the pure function
//! [`classify`] is independently testable)
//!
//! 1. First byte `0x64` ('d', bencode dict) -> DHT. BEP-5: "The KRPC
//!    protocol is a simple RPC mechanism consisting of bencoded
//!    dictionaries sent over UDP" — all three KRPC message kinds
//!    (query/response/error) are single dicts, so the first byte is
//!    'd';
//! 2. first 8 bytes == the BEP-15 connect magic `0x41727101980`
//!    (big-endian) -> a UDP tracker request. Magic source: the fixed
//!    connection_id first field of the BEP-15 connect request,
//!    matching aria2 `UDPTrackerClient.h UDPT_INITIAL_CONNECTION_ID`;
//! 3. tracker **reply**-class packets (connect/announce/scrape/error
//!    replies) -> tracker. Replies carry no magic; the first 4 bytes
//!    are a big-endian action ∈ {0,1,2,3} (the BEP-15 reply format),
//!    double-checked via the action field (aria2 `UDPTrackerClient.cc
//! receiveReply` dispatches by action; `UDPTrackerRequest.h
//! UDPT_ACT_{CONNECT=0,ANNOUNCE=1,SCRAPE=2,ERROR=3}`). Such packets
//!    are mutually exclusive with µTP shapes (first-byte low nibble:
//!    replies are always 0, µTP v1 always 1), independent of rule 4
//!    ordering. Safety hardening: also require packet length >=
//!    [`UDP_TRACKER_MIN_REPLY_LEN`] (16B, the shortest legal reply =
//!    a connect reply) — with only ">=4B and action <=3", legitimate
//!    16B replies (truncated / empty-message errors) would classify as
//!    Drop; integrity stays the consumer's job;
//! 4. `(b0 >> 4) <= 4 && (b0 & 0x0f) == 1` -> µTP v1. BEP-29 "header
//!    format": the first byte's high nibble = type, low nibble =
//!    version, "The current version is 1"; type only defines
//!    ST_DATA=0 / ST_FIN=1 / ST_STATE=2 / ST_RESET=3 / ST_SYN=4
//!    (aria2 has no µTP implementation, so this branch follows the
//!    BEP text directly);
//! 5. anything else is dropped and counted
//!    ([`DemuxStatsSnapshot::dropped_classify`]).
//!
//! Classification only classifies and forwards; it does **not** parse
//! DHT bencode / tracker packets / µTP header semantics (the design
//! forbids it): no packet-integrity checks — a truncated dict still
//! starts with 'd'; integrity and semantics are validated by the
//! consumers (DhtEngine / TrackerActor / UtpStream).
//!
//! # Backpressure policy (explicit; frozen semantics)
//!
//! When an inbound channel is full, `try_send` failure means **drop** +
//! sampled logging + a counter — UDP best-effort semantics: inbound
//! packets have no cross-await backpressure to apply (the source does
//! not retransmit), and blocking the recv loop would only amplify loss
//! to every consumer. The outbound channel (1024) applies `await`
//! backpressure to callers; socket write failures are only counted,
//! never retried (retransmission is protocol-layer business).
//!
//! # Lifecycle
//!
//! - [`spawn`] produces an independent instance per (bind_addr,
//!   config) (v4/v6 dual instances = the caller spawns twice, SPEC §3.2
//!   one per family);
//! - after `shutdown` ([`CancellationToken`]) the task exits promptly
//!   (a ≪1s budget); dropping the last [`UdpDemuxHandle`] also ends
//!   the task (RAII semantics);
//! - port semantics match `--listen-port`: an explicit port binds
//!   exactly; `port == 0` tries one by one from a random start within
//!   the default 6881-6999 range (aria2 `PeerListenCommand.cc
//! bindPort`: shuffle and take the first bindable; the default range
//!   from `OptionHandlerFactory.cc "6881-6999"`, SPEC §11 "random
//!   start");
//! - v6 creation point: `IPV6_V6ONLY=1` set before bind (the socket2
//!   safe wrapper, matching aria2 `SocketCore.cc`) — under the Linux
//!   ipv6(7) `bindv6only=0` default, a bare [::] is a dual-stack
//!   socket, mutually exclusive with 0.0.0.0 on the same port
//!   (EADDRINUSE), so the v6 face could never bind; with V6ONLY the
//!   v4/v6 dual instances coexist on one port. A v6 bind failure (no
//!   v6 kernel/address) propagates as-is and the caller degrades to
//!   v4 (existing semantics unchanged).
//!
//! Concurrency discipline: the module is lock-free (atomics for
//! counters), no lock across await, no unbounded channel.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// tracing target (`taiji::<crate>::<module>`).
const LOG_TARGET: &str = "taiji::io::udp_demux";

/// Sampled-log interval: high-frequency drops log one warn per 64,
/// otherwise debug.
const SAMPLE_LOG_EVERY: u64 = 64;

/// Max payload buffer for a single UDP datagram (the 16-bit IPv4/IPv6
/// datagram total-length cap is 65507 bytes).
const MAX_DATAGRAM: usize = 65536;

/// The BEP-15 connect magic `0x41727101980`, big-endian 8 bytes.
///
/// Source: the fixed first field of the BEP-15 connect request,
/// matching aria2 `UDPTrackerClient.h #define
/// UDPT_INITIAL_CONNECTION_ID 0x41727101980LL`.
const UDP_TRACKER_MAGIC: [u8; 8] = [0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80];

/// Legal upper bound of a tracker reply's leading action field (BEP-15:
/// connect=0/announce=1/scrape=2/error=3). Source: aria2
/// `UDPTrackerRequest.h UDPT_ACT_{CONNECT,ANNOUNCE,SCRAPE,ERROR}`,
/// `UDPTrackerClient.cc receiveReply` dispatching by action.
const UDP_TRACKER_MAX_ACTION: u32 = 3;

/// Minimum packet length for the tracker-reply classification (safety
/// hardening: the original check looked only at the first 4 bytes, so
/// any >=4B packet with first-4B <=3 could enter the tracker channel
/// and flood its finite capacity). 16B = the shortest legal reply —
/// the BEP-15 connect reply = action(4) + transaction_id(4) +
/// connection_id(8); announce/scrape replies are longer. Cost (known
/// and bounded): action-legal but shorter-than-16B truncated /
/// empty-message error replies fall into Drop — integrity is the
/// consumer's (TrackerActor) job anyway; the classification face owes
/// no parsing (module docs).
const UDP_TRACKER_MIN_REPLY_LEN: usize = 16;

/// Inbound DHT channel capacity (frozen at 1024, do not change).
pub const DHT_CHANNEL_CAPACITY: usize = 1024;
/// Inbound UDP-tracker channel capacity (frozen at 256, do not change).
pub const TRACKER_CHANNEL_CAPACITY: usize = 256;
/// Inbound µTP channel capacity (frozen at 512, do not change).
pub const UTP_CHANNEL_CAPACITY: usize = 512;
/// Outbound channel capacity (frozen at 1024, do not change).
pub const OUTBOUND_CHANNEL_CAPACITY: usize = 1024;

/// Default listen-port lower bound (`--listen-port` default
/// "6881-6999", aria2 `OptionHandlerFactory.cc`; SPEC §11).
pub const LISTEN_PORT_MIN: u16 = 6881;
/// Default listen-port upper bound (same source).
pub const LISTEN_PORT_MAX: u16 = 6999;

/// Inbound packet classification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemuxClass {
    /// DHT (BEP-5 KRPC, bencode dict).
    Dht,
    /// UDP tracker request (BEP-15 magic) or reply (action field).
    Tracker,
    /// µTP v1 packet (the BEP-29 header type/version nibbles).
    Utp,
    /// Unclassifiable: dropped and counted.
    Drop,
}

/// Classifies an inbound UDP payload by packet signature (pure
/// function; rules and sources in the module docs).
///
/// Reads only fixed-offset header bytes, parses no protocol semantics;
/// total over any input (never panics; guarded by the fuzz target
/// `udp_demux_classify`).
pub fn classify(packet: &[u8]) -> DemuxClass {
    // Empty packet: nothing classifiable, drop.
    let Some(&b0) = packet.first() else {
        return DemuxClass::Drop;
    };
    // Rule 1: first byte 'd' -> DHT (BEP-5 KRPC messages are all
    // bencode dicts).
    if b0 == b'd' {
        return DemuxClass::Dht;
    }
    // Rule 2: first 8B == the BEP-15 magic -> tracker request.
    if packet.len() >= UDP_TRACKER_MAGIC.len()
        && packet[..UDP_TRACKER_MAGIC.len()] == UDP_TRACKER_MAGIC
    {
        return DemuxClass::Tracker;
    }
    // Rule 3: tracker replies — first 4B big-endian action ∈ {0..=3}
    // and packet length >= [`UDP_TRACKER_MIN_REPLY_LEN`] (a reply
    // without the magic; the length floor is safety hardening, see the
    // constant docs — the shortest legal reply is a 16B connect reply).
    if packet.len() >= UDP_TRACKER_MIN_REPLY_LEN {
        let action = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        if action <= UDP_TRACKER_MAX_ACTION {
            return DemuxClass::Tracker;
        }
    }
    // Rule 4: µTP v1 — BEP-29 first byte = type (high nibble, <=4) |
    // version (low nibble, =1).
    if (b0 >> 4) <= 4 && (b0 & 0x0f) == 1 {
        return DemuxClass::Utp;
    }
    // Rule 5: everything else drops.
    DemuxClass::Drop
}

/// Inbound packet: source address + payload (value-semantic `Bytes`).
#[derive(Debug, Clone)]
pub struct InboundPacket {
    /// Sender address (consumers reply to the peer address / match
    /// transaction tables).
    pub from: SocketAddr,
    /// UDP payload.
    pub data: Bytes,
}

/// Outbound packet: target address + payload. The demux task is the
/// single `send_to` writer.
#[derive(Debug, Clone)]
pub struct OutboundPacket {
    /// Target address.
    pub to: SocketAddr,
    /// UDP payload.
    pub data: Bytes,
}

/// demux instance configuration.
#[derive(Debug, Clone)]
pub struct DemuxConfig {
    /// Listen port: non-0 binds exactly; 0 = try one by one from a
    /// random start within [`LISTEN_PORT_MIN`]..=[`LISTEN_PORT_MAX`]
    /// (the `--listen-port` default semantics, see the module docs).
    pub port: u16,
    /// Inbound DHT channel capacity (contract default
    /// [`DHT_CHANNEL_CAPACITY`]; tests may shrink it to exercise the
    /// queue-full drop path, production must not change the default).
    pub dht_capacity: usize,
    /// Inbound tracker channel capacity (default
    /// [`TRACKER_CHANNEL_CAPACITY`]).
    pub tracker_capacity: usize,
    /// Inbound µTP channel capacity (default [`UTP_CHANNEL_CAPACITY`]).
    pub utp_capacity: usize,
    /// Outbound channel capacity (default [`OUTBOUND_CHANNEL_CAPACITY`]).
    pub outbound_capacity: usize,
}

impl Default for DemuxConfig {
    fn default() -> Self {
        Self {
            port: 0,
            dht_capacity: DHT_CHANNEL_CAPACITY,
            tracker_capacity: TRACKER_CHANNEL_CAPACITY,
            utp_capacity: UTP_CHANNEL_CAPACITY,
            outbound_capacity: OUTBOUND_CHANNEL_CAPACITY,
        }
    }
}

/// Receive ends of the three inbound channels (consumers = DhtEngine /
/// TrackerActor / the µTP listener, each holding its receiver).
#[derive(Debug)]
pub struct DemuxChannels {
    /// DHT inbound (dict-class packets).
    pub dht: mpsc::Receiver<InboundPacket>,
    /// UDP tracker inbound (magic requests + action-class reply
    /// packets).
    pub tracker: mpsc::Receiver<InboundPacket>,
    /// µTP inbound (v1-nibble-class packets).
    pub utp: mpsc::Receiver<InboundPacket>,
}

/// Atomic counter group (lock-free; `Relaxed` is for observation only
/// and participates in no synchronization).
#[derive(Debug, Default)]
pub struct DemuxStats {
    received: AtomicU64,
    forwarded_dht: AtomicU64,
    forwarded_tracker: AtomicU64,
    forwarded_utp: AtomicU64,
    dropped_dht_full: AtomicU64,
    dropped_tracker_full: AtomicU64,
    dropped_utp_full: AtomicU64,
    dropped_classify: AtomicU64,
    consumer_closed: AtomicU64,
    recv_errors: AtomicU64,
    outbound_sent: AtomicU64,
    outbound_errors: AtomicU64,
}

/// A consistent snapshot of [`DemuxStats`] (queue-full drops + counters
/// are observable).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DemuxStatsSnapshot {
    /// Total successful recv_from calls.
    pub received: u64,
    /// Packets forwarded into the DHT channel.
    pub forwarded_dht: u64,
    /// Packets forwarded into the tracker channel.
    pub forwarded_tracker: u64,
    /// Packets forwarded into the µTP channel.
    pub forwarded_utp: u64,
    /// Drops from a full DHT channel.
    pub dropped_dht_full: u64,
    /// Drops from a full tracker channel.
    pub dropped_tracker_full: u64,
    /// Drops from a full µTP channel.
    pub dropped_utp_full: u64,
    /// Drops by rule 5 (unclassifiable).
    pub dropped_classify: u64,
    /// Drops caused by closed consumer channels.
    pub consumer_closed: u64,
    /// recv_from error count.
    pub recv_errors: u64,
    /// Successful outbound sends.
    pub outbound_sent: u64,
    /// Failed outbound sends.
    pub outbound_errors: u64,
}

impl DemuxStats {
    fn snapshot(&self) -> DemuxStatsSnapshot {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        DemuxStatsSnapshot {
            received: load(&self.received),
            forwarded_dht: load(&self.forwarded_dht),
            forwarded_tracker: load(&self.forwarded_tracker),
            forwarded_utp: load(&self.forwarded_utp),
            dropped_dht_full: load(&self.dropped_dht_full),
            dropped_tracker_full: load(&self.dropped_tracker_full),
            dropped_utp_full: load(&self.dropped_utp_full),
            dropped_classify: load(&self.dropped_classify),
            consumer_closed: load(&self.consumer_closed),
            recv_errors: load(&self.recv_errors),
            outbound_sent: load(&self.outbound_sent),
            outbound_errors: load(&self.outbound_errors),
        }
    }
}

/// demux handle: the single-writer outbound entry + stats snapshots.
/// Clones share one instance; dropping the last handle ends the demux
/// task (RAII).
#[derive(Clone)]
pub struct UdpDemuxHandle {
    outbound_tx: mpsc::Sender<OutboundPacket>,
    stats: Arc<DemuxStats>,
    bound_addr: SocketAddr,
}

/// The outbound channel is closed (the demux task exited / all handles
/// dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundClosed;

impl std::fmt::Display for OutboundClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("udp demux outbound channel closed")
    }
}

impl std::error::Error for OutboundClosed {}

impl UdpDemuxHandle {
    /// The address the demux actually bound (after port scanning, the
    /// caller obtains the final port here).
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Stats snapshot.
    pub fn stats(&self) -> DemuxStatsSnapshot {
        self.stats.snapshot()
    }

    /// The unified outbound entry: queued, then written by a single
    /// `send_to` in the demux task.
    ///
    /// Backpressure: the outbound channel is bounded
    /// ([`DemuxConfig::outbound_capacity`]); when full, the caller
    /// `await`s (protocol-layer tasks can absorb this; socket writes
    /// are best-effort).
    pub async fn send_packet(&self, to: SocketAddr, data: Bytes) -> Result<(), OutboundClosed> {
        self.outbound_tx
            .send(OutboundPacket { to, data })
            .await
            .map_err(|_| OutboundClosed)
    }
}

/// Binds and starts one demux instance (call once per family; the v4/v6
/// dual instance = two calls).
///
/// Returns the three inbound channel receivers + the outbound handle.
/// Task lifecycle in the module docs (a shutdown cancellation or all
/// handles dropped ends it).
pub async fn spawn(
    bind_addr: IpAddr,
    config: DemuxConfig,
    shutdown: CancellationToken,
) -> io::Result<(DemuxChannels, UdpDemuxHandle)> {
    let socket = bind_socket(bind_addr, config.port).await?;
    let bound_addr = socket.local_addr()?;
    let (dht_tx, dht_rx) = mpsc::channel(config.dht_capacity);
    let (tracker_tx, tracker_rx) = mpsc::channel(config.tracker_capacity);
    let (utp_tx, utp_rx) = mpsc::channel(config.utp_capacity);
    let (outbound_tx, outbound_rx) = mpsc::channel(config.outbound_capacity);
    let stats = Arc::new(DemuxStats::default());
    let handle = UdpDemuxHandle {
        outbound_tx,
        stats: Arc::clone(&stats),
        bound_addr,
    };
    tokio::spawn(run_demux(
        socket,
        dht_tx,
        tracker_tx,
        utp_tx,
        outbound_rx,
        stats,
        shutdown,
    ));
    Ok((
        DemuxChannels {
            dht: dht_rx,
            tracker: tracker_rx,
            utp: utp_rx,
        },
        handle,
    ))
}

/// Port semantics matching `--listen-port` (see the module docs):
/// non-0 binds exactly; 0 = scans the default range from a random
/// start, erroring when everything is taken.
async fn bind_socket(bind_addr: IpAddr, port: u16) -> io::Result<UdpSocket> {
    if port != 0 {
        return bind_single(bind_addr, port).await;
    }
    // aria2 bindPort (PeerListenCommand.cc) shuffles and takes the
    // first bindable; a random start + ring walk covers the interval
    // equivalently without the O(n) shuffle allocation.
    let span = u32::from(LISTEN_PORT_MAX - LISTEN_PORT_MIN + 1);
    let start = rand::random_range(0..span);
    for offset in 0..span {
        let port = LISTEN_PORT_MIN + ((start + offset) % span) as u16;
        match bind_single(bind_addr, port).await {
            Ok(socket) => return Ok(socket),
            // Taken -> try the next (matches aria2 catching
            // RecoverableException and continuing).
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!("no free UDP port in {LISTEN_PORT_MIN}-{LISTEN_PORT_MAX}"),
    ))
}

/// Single-port bind helper: one code path for both families, shared by
/// the explicit port and the port=0 scan loop.
///
/// v4 keeps the plain std bind (zero behavior change). v6 goes through
/// the socket2 safe wrapper (std has no sockopt face, no unsafe):
/// `Socket::new(Domain::IPV6, …)` -> `set_only_v6(true)` ->
/// `set_nonblocking(true)` (a tokio `from_std` precondition) -> bind ->
/// convert to a standard socket into tokio. `IPV6_V6ONLY` **must be
/// set before bind** (socket2 docs; setting it after bind does not
/// change the port-occupancy semantics fixed at bind time).
///
/// Semantics source (the defect itself): with Linux ipv6(7)
/// `bindv6only` defaulting to 0, a bare [::] yields a dual-stack
/// socket, mutually exclusive with 0.0.0.0 on the same port ->
/// EADDRINUSE -> the v6 face (the DHT v6 / µTP v6 / UDP tracker v6
/// carriers) can never bind; macOS/Windows default V6ONLY=1 and merely
/// look fine, invisible on dev machines. aria2 `SocketCore.cc` sets
/// `IPV6_V6ONLY=1` on AF_INET6 sockets uniformly before `::bind`. With
/// V6ONLY the v6 face only carries v6 packets, and the parallel v4
/// demux instance carries v4 (SPEC §3.2 one per family); without a v6
/// kernel/address the error propagates as-is and the caller degrades
/// to v4 (the core side's existing degradation semantics unchanged).
///
/// socket/setsockopt/bind are all non-blocking syscalls (no data wait,
/// outside the §2.5 "blocking operations" boundary).
fn bind_v6_std(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    Ok(s.into())
}

async fn bind_single(bind_addr: IpAddr, port: u16) -> io::Result<UdpSocket> {
    let addr = SocketAddr::new(bind_addr, port);
    match bind_addr {
        // v4: plain std bind (zero behavior change).
        IpAddr::V4(_) => UdpSocket::bind(addr).await,
        // v6: IPV6_V6ONLY set before bind (semantics and source at
        // [`bind_v6_std`]).
        IpAddr::V6(_) => UdpSocket::from_std(bind_v6_std(addr)?),
    }
}

/// Drain batch cap for one readiness event on the receive direction
/// (demux batching).
///
/// Rationale: rebuilding the three `select!` arm futures plus a
/// ready-arm repoll per packet costs user-space time on the same order
/// as the forwarding logic itself at real download packet rates.
/// Batching = drain to WouldBlock within one readiness event, so the
/// per-packet cost converges to one `try_recv_from` + classify +
/// forward; the cap is the fairness fuse — under a sustained storm the
/// outbound/shutdown arms still get scheduled between batches instead
/// of starving.
const RECV_DRAIN_BATCH_MAX: usize = 64;

/// Drain batch cap per select iteration on the outbound direction (same
/// as [`RECV_DRAIN_BATCH_MAX`]; the outbound side drains the existing
/// queue with `try_recv` and never waits for a new packet — semantics
/// identical to per-packet `send_to`).
const SEND_DRAIN_BATCH_MAX: usize = 64;

/// demux main loop: recv dispatch + single-writer outbound + shutdown
/// propagation.
///
/// Receiving uses `readable()` + [`UdpSocket::try_recv_from`] (an
/// equivalent unfolding of `recv_from().await`): the readiness check
/// awaits across arms while the fetch completes synchronously inside
/// the arm — sidestepping the `select!` cross-arm borrow restriction
/// (arm futures rebuild between iterations, so a buffer-holding async
/// recv future cannot reuse the receive buffer). The payload copies
/// once into `Bytes` for the consumer (`Bytes` value semantics). Both
/// directions drain in batches within a single readiness event (caps
/// [`RECV_DRAIN_BATCH_MAX`] / [`SEND_DRAIN_BATCH_MAX`]); per-packet
/// classify/forward/count/backpressure semantics unchanged.
async fn run_demux(
    socket: UdpSocket,
    dht_tx: mpsc::Sender<InboundPacket>,
    tracker_tx: mpsc::Sender<InboundPacket>,
    utp_tx: mpsc::Sender<InboundPacket>,
    mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    stats: Arc<DemuxStats>,
    shutdown: CancellationToken,
) {
    let mut scratch = vec![0u8; MAX_DATAGRAM];
    loop {
        tokio::select! {
            // shutdown: cancel = exit (within the 1s budget; the socket
            // closes with the task's drop and the three channel senders
            // close in step -> consumers observe the channel teardown).
            _ = shutdown.cancelled() => break,
            // All handles dropped: the outbound channel is permanently
            // closed, the instance is unused -> RAII exit.
            outbound = outbound_rx.recv() => match outbound {
                Some(packet) => {
                    // Batched drain: send the packet in hand, then
                    // drain the existing queue with try_recv up to the
                    // cap — never waiting for new packets, and an empty
                    // batch is free.
                    send_one(&socket, packet, &stats).await;
                    let mut batch = 1usize;
                    while batch < SEND_DRAIN_BATCH_MAX {
                        match outbound_rx.try_recv() {
                            Ok(packet) => {
                                batch += 1;
                                send_one(&socket, packet, &stats).await;
                            }
                            Err(_) => break,
                        }
                    }
                }
                None => break,
            },
            _ = socket.readable() => {
                // Batched drain: once ready, fetch per packet until
                // WouldBlock or the batch cap; error classification
                // and per-packet semantics unchanged (transient =
                // retry next round, fatal = the task exits to make
                // the failure boundary visible).
                let mut fatal = false;
                let mut drained = 0usize;
                while drained < RECV_DRAIN_BATCH_MAX {
                    match socket.try_recv_from(&mut scratch) {
                        Ok((n, from)) => {
                            drained += 1;
                            stats.received.fetch_add(1, Ordering::Relaxed);
                            let data = Bytes::copy_from_slice(&scratch[..n]);
                            let class = classify(&data);
                            forward_inbound(
                                class,
                                InboundPacket { from, data },
                                &dht_tx,
                                &tracker_tx,
                                &utp_tx,
                                &stats,
                            );
                        }
                        // A readable() false alarm (data already taken /
                        // edge-trigger semantics); this round ends.
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            let n = stats.recv_errors.fetch_add(1, Ordering::Relaxed) + 1;
                            // Transient errors (peer ICMP unreachable fed
                            // back as ECONNRESET/ECONNREFUSED, timeouts)
                            // count and continue; anything else is fatal
                            // and the task exits to make the failure
                            // boundary visible (the channel closing is
                            // the signal).
                            match e.kind() {
                                io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::TimedOut => {
                                    if n == 1 || n.is_multiple_of(SAMPLE_LOG_EVERY) {
                                        warn!(target: LOG_TARGET, total = n, error = %e, "transient recv error");
                                    } else {
                                        debug!(target: LOG_TARGET, total = n, error = %e, "transient recv error");
                                    }
                                    break;
                                }
                                _ => {
                                    warn!(target: LOG_TARGET, total = n, error = %e, "fatal recv error; demux exiting");
                                    fatal = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if fatal {
                    break;
                }
            },
        }
    }
}

/// Outbound single-packet send (`send_to` + success/failure counts +
/// sampled logging; the per-packet unit extracted for batching). A UDP
/// write failure is non-fatal: no retry (best-effort; retransmission
/// is protocol-layer), count and continue.
async fn send_one(socket: &UdpSocket, packet: OutboundPacket, stats: &DemuxStats) {
    match socket.send_to(&packet.data, packet.to).await {
        Ok(_) => {
            stats.outbound_sent.fetch_add(1, Ordering::Relaxed);
        }
        Err(e) => {
            // UDP write failures are never retried (best-effort;
            // retransmission is protocol-layer).
            let n = stats.outbound_errors.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(SAMPLE_LOG_EVERY) {
                warn!(target: LOG_TARGET, to = %packet.to, total = n, error = %e, "outbound send_to failed");
            } else {
                debug!(target: LOG_TARGET, to = %packet.to, total = n, error = %e, "outbound send_to failed");
            }
        }
    }
}

/// Forwards by classification (queue-full drop + sampled logging +
/// counting; the backpressure policy).
fn forward_inbound(
    class: DemuxClass,
    packet: InboundPacket,
    dht_tx: &mpsc::Sender<InboundPacket>,
    tracker_tx: &mpsc::Sender<InboundPacket>,
    utp_tx: &mpsc::Sender<InboundPacket>,
    stats: &DemuxStats,
) {
    match class {
        DemuxClass::Dht => forward(
            dht_tx,
            packet,
            (&stats.forwarded_dht, &stats.dropped_dht_full),
            "dht",
            stats,
        ),
        DemuxClass::Tracker => forward(
            tracker_tx,
            packet,
            (&stats.forwarded_tracker, &stats.dropped_tracker_full),
            "tracker",
            stats,
        ),
        DemuxClass::Utp => forward(
            utp_tx,
            packet,
            (&stats.forwarded_utp, &stats.dropped_utp_full),
            "utp",
            stats,
        ),
        DemuxClass::Drop => {
            let n = stats.dropped_classify.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(SAMPLE_LOG_EVERY) {
                warn!(target: LOG_TARGET, from = %packet.from, total = n, "unclassifiable packet dropped (rule 5)");
            } else {
                debug!(target: LOG_TARGET, from = %packet.from, total = n, "unclassifiable packet dropped (rule 5)");
            }
        }
    }
}

/// Single-channel forward: `try_send` full = drop (UDP best-effort; the
/// module-docs backpressure policy).
fn forward(
    tx: &mpsc::Sender<InboundPacket>,
    packet: InboundPacket,
    counters: (&AtomicU64, &AtomicU64),
    channel: &'static str,
    stats: &DemuxStats,
) {
    let (forwarded, dropped_full) = counters;
    match tx.try_send(packet) {
        Ok(()) => {
            forwarded.fetch_add(1, Ordering::Relaxed);
        }
        Err(mpsc::error::TrySendError::Full(pkt)) => {
            let n = dropped_full.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n % SAMPLE_LOG_EVERY == 0 {
                warn!(target: LOG_TARGET, channel, total = n, from = %pkt.from, "inbound channel full; best-effort drop (B.4a)");
            } else {
                debug!(target: LOG_TARGET, channel, total = n, "inbound channel full; best-effort drop (B.4a)");
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            let n = stats.consumer_closed.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(SAMPLE_LOG_EVERY) {
                warn!(target: LOG_TARGET, channel, total = n, "consumer channel closed; dropping (B.4a)");
            } else {
                debug!(target: LOG_TARGET, channel, total = n, "consumer channel closed; dropping (B.4a)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ---- Classifier vectors (each with its source) ----

    /// The BEP-5 §"KRPC" ping query example verbatim (first byte 'd',
    /// bencode dict).
    const KRPC_PING_QUERY: &[u8] = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
    /// BEP-5 KRPC response shape (also a 'd'-leading dict; 'y' = "r").
    const KRPC_RESPONSE: &[u8] = b"d1:rd2:id20:abcdefghij0123456789e5:nodes262:...e1:t2:aa1:y1:re";
    /// BEP-5 KRPC error shape ('y' = "e", still a dict).
    const KRPC_ERROR: &[u8] = b"d1:eli201eGeneric Errore1:t2:aa1:y1:ee";
    /// The BEP-15 magic, big-endian 8 bytes (UDPTrackerClient.h).
    const MAGIC: [u8; 8] = UDP_TRACKER_MAGIC;

    fn tracker_packet(action: u32, rest: &[u8]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.extend_from_slice(&action.to_be_bytes());
        v.extend_from_slice(rest);
        v
    }

    fn tracker_reply(action: u32, rest: &[u8]) -> Vec<u8> {
        let mut v = action.to_be_bytes().to_vec();
        v.extend_from_slice(rest);
        v
    }

    /// A 20B µTP header (BEP-29): b0 = type<<4 | 1, the rest
    /// placeholder.
    fn utp_header(type_and_version: u8) -> Vec<u8> {
        let mut v = vec![type_and_version, 0x00];
        v.extend_from_slice(&[0u8; 18]); // connection_id(2) + ts(4) + ts_diff(4) + wnd(4) + seq(2) + ack(2)
        v
    }

    #[test]
    fn classifier_vectors_with_provenance() {
        // 1-2. Empty / single-byte garbage: nothing classifiable -> Drop.
        assert_eq!(
            classify(&[]),
            DemuxClass::Drop,
            "empty packet (module rule 5)"
        );
        assert_eq!(
            classify(&[0xff]),
            DemuxClass::Drop,
            "0xff: type=15 undefined, ver=15 (BEP29 defines only type 0-4, ver=1)"
        );

        // 3-5. DHT: BEP-5 KRPC query/response/error are all bencode
        // dicts (first byte 'd').
        assert_eq!(
            classify(KRPC_PING_QUERY),
            DemuxClass::Dht,
            "BEP5 ping query sample"
        );
        assert_eq!(
            classify(KRPC_RESPONSE),
            DemuxClass::Dht,
            "BEP5 response (a reply is also a dict; rule 1 does not distinguish query/reply)"
        );
        assert_eq!(classify(KRPC_ERROR), DemuxClass::Dht, "BEP5 error shape");

        // 6. Single-byte 'd': classification looks only at the first
        // byte; a truncated dict's integrity is the DHT layer's job
        // (classify, not parse).
        assert_eq!(
            classify(b"d"),
            DemuxClass::Dht,
            "first byte 'd' decides (BEP5 dict)"
        );

        // 7-9. Tracker requests: magic (UDPTrackerClient.h) + action
        // (BEP-15).
        assert_eq!(
            classify(&tracker_packet(0, &[0, 0, 0x12, 0x34])),
            DemuxClass::Tracker,
            "BEP15 connect request: magic+action=0"
        );
        assert_eq!(
            classify(&tracker_packet(1, &[0u8; 98])),
            DemuxClass::Tracker,
            "BEP15 announce request: magic+action=1"
        );
        assert_eq!(
            classify(&tracker_packet(2, &[0u8; 40])),
            DemuxClass::Tracker,
            "BEP15 scrape request: magic+action=2"
        );

        // 10-13. Tracker replies: no magic, first 4B action
        // (UDPTrackerClient.cc receiveReply). connect reply = action0 +
        // txid + connection_id (BEP-15; 16B = the shortest legal reply,
        // the source of rule 3's length floor).
        assert_eq!(
            classify(&tracker_reply(
                0,
                &[0, 0, 0x12, 0x34, 0, 0, 4, 0x17, 0x27, 0x10, 0x19, 0x81]
            )),
            DemuxClass::Tracker,
            "connect reply: action=0 (exactly the 16B floor)"
        );
        assert_eq!(
            classify(&tracker_reply(1, &[0u8; 18])),
            DemuxClass::Tracker,
            "announce reply：action=1"
        );
        assert_eq!(
            classify(&tracker_reply(2, &[0u8; 12])),
            DemuxClass::Tracker,
            "error reply: action=2 (16B: action+txid+8B message)"
        );
        assert_eq!(
            classify(&tracker_reply(3, &[0u8; 24])),
            DemuxClass::Tracker,
            "scrape reply：action=3"
        );

        // 14-18. µTP v1: the BEP-29 header format (type high nibble
        // <= 4, version low nibble = 1).
        assert_eq!(
            classify(&utp_header(0x01)),
            DemuxClass::Utp,
            "ST_DATA=0|ver=1（BEP29）"
        );
        assert_eq!(
            classify(&utp_header(0x11)),
            DemuxClass::Utp,
            "ST_FIN=1|ver=1（BEP29）"
        );
        assert_eq!(
            classify(&utp_header(0x21)),
            DemuxClass::Utp,
            "ST_STATE=2|ver=1（BEP29）"
        );
        assert_eq!(
            classify(&utp_header(0x31)),
            DemuxClass::Utp,
            "ST_RESET=3|ver=1（BEP29）"
        );
        assert_eq!(
            classify(&utp_header(0x41)),
            DemuxClass::Utp,
            "ST_SYN=4|ver=1（BEP29）"
        );

        // 19-20. Non-v1 / undefined type: not µTP -> Drop.
        assert_eq!(
            classify(&utp_header(0x02)),
            DemuxClass::Drop,
            "ver=2 is not v1 (BEP29 defines only version 1)"
        );
        assert_eq!(
            classify(&utp_header(0x51)),
            DemuxClass::Drop,
            "type=5 undefined (BEP29 type 0-4)"
        );

        // 21. Truncated magic (7B): neither a full magic, nor does the
        // first 4B 0x00000417 fit under the action cap -> Drop.
        assert_eq!(
            classify(&MAGIC[..7]),
            DemuxClass::Drop,
            "truncated magic is not tracker (needs the full 8B)"
        );

        // 22. Ambiguity order (1): 'd' beats magic — b0='d' classifies
        // Dht even with the magic following.
        let mut d_then_magic = vec![b'd'];
        d_then_magic.extend_from_slice(&MAGIC);
        assert_eq!(
            classify(&d_then_magic),
            DemuxClass::Dht,
            "ambiguity order: 'd' first"
        );

        // 23. Ambiguity order (2): magic beats the µTP nibble — the
        // magic's b0=0x00 (high nibble 0 <= 4) and low nibble 0 != 1
        // never actually conflict; a magic hit is Tracker, no µTP
        // probe.
        assert_eq!(
            classify(&tracker_packet(0, &[])),
            DemuxClass::Tracker,
            "ambiguity order: magic second"
        );

        // 24. Magic followed by 'd': the first 8B magic decides; the
        // payload content plays no part.
        let mut magic_then_d = MAGIC.to_vec();
        magic_then_d.push(b'd');
        assert_eq!(
            classify(&magic_then_d),
            DemuxClass::Tracker,
            "payload content plays no part in classification"
        );

        // 25. Single 0x00 byte: no 4B action, no magic, version nibble
        // 0 -> Drop.
        assert_eq!(
            classify(&[0x00]),
            DemuxClass::Drop,
            "a lone 0x00 has no classifiable feature"
        );

        // 26-29. Safety-hardening regression (rule 3 used to be greedy
        // — any >=4B packet with first-4B <=3 entered the tracker
        // channel, so 4 bytes of garbage could flood the 256 capacity):
        // action-shaped packets shorter than the shortest legal reply
        // (16B) no longer classify as tracker.
        assert_eq!(
            classify(&[0, 0, 0, 1]),
            DemuxClass::Drop,
            "4B action=1 garbage packet: < 16B -> Drop (used to classify Tracker)"
        );
        assert_eq!(
            classify(&tracker_reply(2, b"nope")),
            DemuxClass::Drop,
            "8B (action+txid+4B): < 16B -> Drop"
        );
        assert_eq!(
            classify(&tracker_reply(1, &[0u8; 11])),
            DemuxClass::Drop,
            "15B: one byte short drops (the floor includes 16B)"
        );
        assert_eq!(
            classify(&tracker_reply(0, &[0u8; 8])),
            DemuxClass::Drop,
            "12B truncated connect reply: < 16B -> Drop"
        );
        assert_eq!(
            classify(&tracker_reply(3, &[0u8; 9])),
            DemuxClass::Drop,
            "13B truncated scrape reply: < 16B -> Drop"
        );
    }

    // Classifier invariants (proptest): total over any byte input, no
    // panic, and the rule priority order holds ('d' > magic > action >
    // µTP nibble).
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(2048))]

        #[test]
        fn classifier_total_and_ordered(packet in proptest::collection::vec(any::<u8>(), 0..96)) {
            let class = classify(&packet);
            // Total: the result is always one of the four classes
            // (exhaustive).
            prop_assert!(
                matches!(class, DemuxClass::Dht | DemuxClass::Tracker | DemuxClass::Utp | DemuxClass::Drop)
            );
            // Priority 1: first byte 'd' => Dht (unaffected by later
            // bytes).
            if packet.first() == Some(&b'd') {
                prop_assert_eq!(class, DemuxClass::Dht);
            }
            // Priority 2: full magic => Tracker (the magic's b0=0x00 !=
            // 'd', so priority 1 cannot hit first).
            if packet.len() >= 8 && packet[..8] == UDP_TRACKER_MAGIC {
                prop_assert_eq!(class, DemuxClass::Tracker);
            }
            // Priority 4 boundary: non-'d' first byte, type <= 4, ver =
            // 1 => certainly Utp (such b0 ∈ {0x01,0x11,0x21,0x31,0x41};
            // the 4B action >= 0x01000000 > 3, naturally exclusive with
            // priorities 2 and 3).
            if let Some(&b0) = packet.first()
                && b0 != b'd' && (b0 >> 4) <= 4 && (b0 & 0x0f) == 1 {
                    prop_assert_eq!(class, DemuxClass::Utp);
                }
        }
    }

    // ---- The v6 creation point: IPV6_V6ONLY (socket2, before bind) ----

    /// IPv6 environment probe (the same convention as the existing
    /// tests/udp_demux.rs tests: containers/CI without IPv6 cannot bind
    /// `::1`, skipped at runtime with a printed reason — an
    /// environment-driven skip, not a semantic exemption).
    fn ipv6_available() -> bool {
        std::net::UdpSocket::bind("[::1]:0").is_ok()
    }

    /// Direct read of V6ONLY taking effect: the socket produced by the
    /// v6 creation point must explicitly carry `IPV6_V6ONLY=1`.
    /// macOS/Windows default to 1, so this read pins "the creation
    /// point sets it explicitly, not relying on the OS default"; Linux
    /// ipv6(7) `bindv6only` defaults to 0, where the explicit set is
    /// the fix itself (the behavior face — v4/v6 coexisting on one port
    /// — is locked by the tests/udp_demux.rs integration assertions).
    #[test]
    fn v6_creation_point_sets_only_v6_before_bind() {
        if !ipv6_available() {
            eprintln!(
                "skip v6_creation_point_sets_only_v6_before_bind: ::1 unavailable (no IPv6 environment)"
            );
            return;
        }
        // Bind [::]:0 through the creation point itself (the same code
        // path as the bind_socket v6 branch).
        let probe = bind_v6_std(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            0,
        ))
        .unwrap_or_else(|e| panic!("v6 creation point failed to bind [::]:0: {e}"));
        let only_v6 = socket2::SockRef::from(&probe)
            .only_v6()
            .unwrap_or_else(|e| panic!("getsockopt IPV6_V6ONLY: {e}"));
        assert!(
            only_v6,
            "the v6 creation point must explicitly set IPV6_V6ONLY=1 (before bind)"
        );
    }
}

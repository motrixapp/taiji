//! `UtpListener`: conn_id routing table + inbound SYN acceptance +
//! [`UtpStream`] handle surface.
//!
//! - Consumes the uTP inbound channel from [`crate::udp_demux`] (uTP
//! packets are already classified by demux; this layer only does
//! table-lookup dispatch + SYN creation);
//! - Route key = (peer address, header conn_id): BEP-29 "connection_id" —
//! "Each socket has one connection ID for sending packets and a different
//! connection ID for receiving packets". The peer's send ID is our
//! receive ID, so looking up by the header conn_id hits our receive
//! channel;
//! - SYN without a table entry => create an inbound connection (acceptor
//! initial values in conn::Role::Acceptor, per BEP-29 "connection setup")
//! and push it to the accept queue; core wiring pops (peer address,
//! [`UtpStream`]) and feeds the bt::peer accept path, converging with
//! TCP inbound;
//! - SYN with a table entry => forward to the existing connection (the
//! connection itself applies the BEP-29 "connection setup" collision
//! semantics: ignore / resend SYN-ACK while in SynRecv);
//! - Outbound connections ([`UtpListenerHandle::connect`]) register into
//! the same route table, so inbound packets of a bidirectional
//! connection always reach the local driver.
//!
//! Back-pressure: all channels bounded. Per-connection inbound mpsc(64)
//! (frozen); full-queue drop + sampled logging (UDP best-effort,
//! retransmission backstops); a full accept queue mpsc(64) drops the SYN
//! (the peer's SYN timeout retransmit backstops; no connection resources
//! consumed).
//!
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::sync::PollSender;
use tracing::{debug, warn};

use super::conn::{CloseState, ConnSpec, Ctrl, Dereg, DriverChannels, Role};
use super::packet::{self, PacketType};
use super::{ConnKey, MAX_INBOUND_PAYLOAD, UtpConfig, UtpError};
use crate::udp_demux::{InboundPacket, OutboundPacket, UdpDemuxHandle};

/// tracing target.
const LOG_TARGET: &str = "taiji::io::utp";

/// Sampled-log interval.
const SAMPLE_LOG_EVERY: u64 = 64;

/// Connection route table (drivers remove their own entry on exit; the
/// Mutex guards only short critical sections, never held across an await).
type RouteTable = Arc<Mutex<HashMap<ConnKey, mpsc::Sender<InboundPacket>>>>;

/// Listener task: consumes the demux utp channel and routes packets.
struct Listener {
    cfg: UtpConfig,
    rx: mpsc::Receiver<InboundPacket>,
    out: mpsc::Sender<OutboundPacket>,
    table: RouteTable,
    /// The accept queue payload carries the SYN source address (core
    /// wiring needs it: pre-handshake IpGuard filtering and PeerMeta
    /// attribution are by peer address; protocol semantics unchanged).
    accept_tx: mpsc::Sender<(SocketAddr, UtpStream)>,
    token: CancellationToken,
}

impl Listener {
    async fn run(mut self) {
        let mut dropped_full: u64 = 0;
        loop {
            tokio::select! {
                _ = self.token.cancelled() => return,
                pkt = self.rx.recv() => {
                    let Some(pkt) = pkt else { return };
                    self.route(pkt, &mut dropped_full).await;
                }
            }
        }
    }

    async fn route(&self, pkt: InboundPacket, dropped_full: &mut u64) {
        let Ok(decoded) = packet::decode(&pkt.data) else {
            // demux only inspects the first byte; malformed uTP packets are filtered here.
            debug!(target: LOG_TARGET, from = %pkt.from, "malformed uTP packet; dropped");
            return;
        };
        // Inbound payload length check (hardening): payloads over the inbound
        // cap (truly oversized; derivation at MAX_INBOUND_PAYLOAD) are
        // dropped before a connection exists, so malformed large packets
        // never enter per-connection channels or drivers. The criterion is
        // decoupled from the send chunking parameter max_packet_payload:
        // legal full-size packets (libutp 1435/1452) must not be dropped at
        // the routing layer.
        if decoded.payload.len() > MAX_INBOUND_PAYLOAD {
            debug!(target: LOG_TARGET, from = %pkt.from, len = decoded.payload.len(),
                cap = MAX_INBOUND_PAYLOAD, "oversized uTP payload; dropped");
            return;
        }
        if decoded.header.packet_type == PacketType::Syn {
            let key: ConnKey = (pkt.from, decoded.header.connection_id.wrapping_add(1));
            let exists = self
                .table
                .lock()
                .map(|t| t.contains_key(&key))
                .unwrap_or(false);
            if exists {
                // Collides with an existing connection: forward (the connection
                // applies the BEP-29 collision ignore).
                self.forward(key, pkt, dropped_full);
                return;
            }
            // accept queue full => drop the SYN (peer SYN timeout retransmit backstops).
            if self.accept_tx.capacity() == 0 {
                debug!(target: LOG_TARGET, from = %pkt.from, "accept queue full; SYN dropped");
                return;
            }
            let syn_seq_nr = decoded.header.seq_nr;
            self.accept_inbound(key, pkt, syn_seq_nr);
            return;
        }
        let key: ConnKey = (pkt.from, decoded.header.connection_id);
        self.forward(key, pkt, dropped_full);
    }

    fn forward(&self, key: ConnKey, pkt: InboundPacket, dropped_full: &mut u64) {
        let sender = self.table.lock().ok().and_then(|t| t.get(&key).cloned());
        let Some(sender) = sender else {
            // No route: the peer points at an unknown connection (a late packet after
            // teardown) — drop it.
            debug!(target: LOG_TARGET, from = %pkt.from, "no route for uTP packet; dropped");
            return;
        };
        match sender.try_send(pkt) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Queue-full drop with retransmit backstop; sampled logging.
                *dropped_full += 1;
                if *dropped_full == 1 || (*dropped_full).is_multiple_of(SAMPLE_LOG_EVERY) {
                    warn!(target: LOG_TARGET, total = *dropped_full, "per-conn inbound full; drop (B.4e)");
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The connection exited without deregistering: clean up opportunistically.
                if let Ok(mut t) = self.table.lock() {
                    t.remove(&key);
                }
            }
        }
    }

    /// Create an inbound connection: register route -> spawn acceptor
    /// driver -> push to accept queue.
    fn accept_inbound(&self, key: ConnKey, syn: InboundPacket, syn_seq_nr: u16) {
        let syn_conn_id = key.1.wrapping_sub(1);
        // Route-table global cap (hardening): a full table drops the SYN —
        // peer SYN retransmit backstops; forged SYNs must not pile up
        // half-open connections and driver tasks indefinitely.
        {
            let t = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            if t.len() >= self.cfg.max_connections {
                drop(t);
                warn!(target: LOG_TARGET, from = %syn.from, cap = self.cfg.max_connections,
                    "uTP route table full; SYN dropped");
                return;
            }
        }
        let (in_tx, in_rx) = mpsc::channel(self.cfg.inbound_channel);
        let (write_tx, write_rx) = mpsc::channel(self.cfg.write_queue_packets);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(16);
        let (data_tx, data_rx) = mpsc::channel(self.cfg.data_queue_packets);
        let (err_tx, err_rx) = watch::channel(CloseState::Open);
        {
            let mut t = match self.table.lock() {
                Ok(t) => t,
                Err(_) => return,
            };
            // Re-check atomically: outbound connects can fill the table between
            // the pre-check and the insert.
            if t.len() >= self.cfg.max_connections {
                drop(t);
                warn!(target: LOG_TARGET, from = %syn.from, cap = self.cfg.max_connections,
                    "uTP route table full; SYN dropped");
                return;
            }
            t.insert(key, in_tx);
        }
        let stream = UtpStream {
            data_rx,
            read_leftover: None,
            write_tx: PollSender::new(write_tx),
            ctrl_tx,
            err_rx,
        };
        let ch = DriverChannels {
            inbound: in_rx,
            write: write_rx,
            ctrl: ctrl_rx,
            data: data_tx,
            out: self.out.clone(),
            err: err_tx,
        };
        let dereg: Dereg = Some((Arc::clone(&self.table), key));
        super::conn::spawn_driver(
            self.cfg.clone(),
            ConnSpec {
                addr: syn.from,
                role: Role::Acceptor {
                    syn_conn_id,
                    syn_seq_nr,
                },
            },
            ch,
            dereg,
            self.token.clone(),
        );
        // If the accept queue is full, the driver already exists: the
        // connection converges via its own timeout / peer retransmits; here
        // we only drop the handle (try_send; give up when full, never block
        // demux routing).
        if self.accept_tx.try_send((syn.from, stream)).is_err() {
            debug!(target: LOG_TARGET, from = %syn.from, "accept queue full; connection dropped");
        }
    }
}

/// Spawn the listener + handle (sink-injection form; the production path
/// wires the demux via [`spawn_utp`]; tests inject programmable channels).
///
/// - `rx`: uTP inbound packet stream (production = the demux utp channel);
/// - `out`: outbound packet sink (production = pumped to
/// [`UdpDemuxHandle::send_packet`]).
pub fn spawn_with_sink(
    cfg: UtpConfig,
    rx: mpsc::Receiver<InboundPacket>,
    out: mpsc::Sender<OutboundPacket>,
    token: CancellationToken,
) -> UtpListenerHandle {
    let table: RouteTable = Arc::new(Mutex::new(HashMap::new()));
    let (accept_tx, accept_rx) = mpsc::channel::<(SocketAddr, UtpStream)>(cfg.accept_queue);
    let listener = Listener {
        cfg: cfg.clone(),
        rx,
        out: out.clone(),
        table: Arc::clone(&table),
        accept_tx,
        token: token.clone(),
    };
    tokio::spawn(listener.run());
    UtpListenerHandle {
        cfg,
        table,
        accept_rx,
        out,
        token,
    }
}

/// `UtpListener` handle: accept queue + outbound connection initiation
/// (the accept receiver is not Clone; multi-task sharing forwards via mpsc).
pub struct UtpListenerHandle {
    cfg: UtpConfig,
    table: RouteTable,
    accept_rx: mpsc::Receiver<(SocketAddr, UtpStream)>,
    out: mpsc::Sender<OutboundPacket>,
    token: CancellationToken,
}

impl std::fmt::Debug for UtpListenerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written: the route table is a live mutex (Debug must not
        // lock) and the accept receiver is a bare channel endpoint —
        // both omitted; config and the outbound/cancel faces are shown.
        f.debug_struct("UtpListenerHandle")
            .field("cfg", &self.cfg)
            .field("out", &self.out)
            .field("token", &self.token)
            .finish()
    }
}

/// Outbound connect half: all of [`UtpListenerHandle::connect`]'s state
/// (cfg / route table / outbound pump sender / token) is `Clone`/`Arc`
/// shared, while the accept receiver requires `&mut self` and outbound
/// connect only reads `&self` — the two halves split naturally. Core
/// wiring uses this to run the uTP dial-consumer task and the accept
/// delivery task as two independent tasks (in the former single-task
/// select form, accept-queue back-pressure stalled the dial queue — the
/// root cause of fallback-to-dead-address requests wedging the whole
/// queue). Both tasks share one listener instance through this half,
/// preserving the "route table is the connection registry" invariant:
/// outbound connect and inbound routing must use the same table.
#[derive(Clone)]
pub struct UtpConnectHalf {
    cfg: UtpConfig,
    table: RouteTable,
    out: mpsc::Sender<OutboundPacket>,
    token: CancellationToken,
}

impl std::fmt::Debug for UtpConnectHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written: the route table is a live mutex (Debug must not
        // lock) and is omitted; config and the outbound/cancel faces
        // are shown.
        f.debug_struct("UtpConnectHalf")
            .field("cfg", &self.cfg)
            .field("out", &self.out)
            .field("token", &self.token)
            .finish()
    }
}

impl UtpConnectHalf {
    /// Start an outbound connection (the body moved verbatim from
    /// [`UtpListenerHandle::connect`]; the handle version delegates here,
    /// same implementation, zero behavior change).
    pub fn connect(&self, peer: SocketAddr) -> UtpStream {
        // Initiator initial values (BEP-29 "connection setup" diagram):
        // conn_id_recv = rand, send = recv+1, seq_nr = 1. The SYN carries
        // rcv_conn_id, so the route key = the ID the peer will send with =
        // recv (the peer's send = the conn_id in our SYN; its send ID = our
        // recv).
        let conn_id_recv: u16 = rand::random();
        let key: ConnKey = (peer, conn_id_recv);
        let (in_tx, in_rx) = mpsc::channel(self.cfg.inbound_channel);
        // Atomic table check + registration (hardening: the global cap;
        // outbound connections share it with inbound SYNs; a poisoned table
        // lock = routing unavailable, refuse likewise).
        let (err_tx, err_rx) = match self.table.lock() {
            Ok(mut t) => {
                if t.len() >= self.cfg.max_connections {
                    warn!(target: LOG_TARGET, to = %peer, cap = self.cfg.max_connections,
                        "uTP route table full; outbound connect refused");
                    return UtpStream::refused(self.cfg.data_queue_packets);
                }
                t.insert(key, in_tx);
                watch::channel(CloseState::Open)
            }
            Err(_) => {
                warn!(target: LOG_TARGET, to = %peer, "uTP route table poisoned; outbound connect refused");
                return UtpStream::refused(self.cfg.data_queue_packets);
            }
        };
        let (write_tx, write_rx) = mpsc::channel(self.cfg.write_queue_packets);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(16);
        let (data_tx, data_rx) = mpsc::channel(self.cfg.data_queue_packets);
        let ch = DriverChannels {
            inbound: in_rx,
            write: write_rx,
            ctrl: ctrl_rx,
            data: data_tx,
            out: self.out.clone(),
            err: err_tx,
        };
        let dereg: Dereg = Some((Arc::clone(&self.table), key));
        super::conn::spawn_driver(
            self.cfg.clone(),
            ConnSpec {
                addr: peer,
                role: Role::Initiator { conn_id_recv },
            },
            ch,
            dereg,
            self.token.clone(),
        );
        UtpStream {
            data_rx,
            read_leftover: None,
            write_tx: PollSender::new(write_tx),
            ctrl_tx,
            err_rx,
        }
    }
}

impl UtpListenerHandle {
    /// Take one inbound connection (SYN accept; the caller feeds the bt::peer accept path).
    pub async fn accept(&mut self) -> Option<UtpStream> {
        self.accept_from().await.map(|(_, stream)| stream)
    }

    /// Take one inbound connection plus its SYN source address (core
    /// wiring surface: the accept queue payload carries the peer address
    /// unchanged, for pre-handshake IpGuard filtering and connection
    /// metadata attribution; a pure addition — [`Self::accept`] delegates
    /// here, protocol semantics unchanged).
    pub async fn accept_from(&mut self) -> Option<(SocketAddr, UtpStream)> {
        self.accept_rx.recv().await
    }

    /// Current accept queue occupancy (observability).
    pub fn accept_pending(&self) -> usize {
        self.cfg.accept_queue - self.accept_rx.capacity()
    }

    /// Outbound connect half: clones sharing this handle's route table /
    /// outbound pump / token — the dial-consumer task and the accept
    /// delivery task each hold one. See [`UtpConnectHalf`] for the split
    /// semantics.
    pub fn connect_half(&self) -> UtpConnectHalf {
        UtpConnectHalf {
            cfg: self.cfg.clone(),
            table: Arc::clone(&self.table),
            out: self.out.clone(),
            token: self.token.clone(),
        }
    }

    /// Start an outbound connection (BEP-29 "connection setup" initiator
    /// semantics; SYN retransmit/give-up backstopped by driver timeout rounds).
    ///
    /// The returned [`UtpStream`] blocks reads/writes until Connected while
    /// the handshake is pending (the read side gets an error if the
    /// handshake fails). When the route table is at the global cap
    /// ([`UtpConfig::max_connections`], hardening), returns an
    /// immediately-failed stream (reads/writes yield a `Closed` error; the
    /// caller retries/degrades as for a failed connection; no route is
    /// registered and no driver spawned).
    pub fn connect(&self, peer: SocketAddr) -> UtpStream {
        self.connect_half().connect(peer)
    }

    /// Route-table entry count (observability/tests).
    pub fn routed_connections(&self) -> usize {
        self.table.lock().map(|t| t.len()).unwrap_or(0)
    }
}

/// uTP stream handle: an `AsyncRead + AsyncWrite` implementation of the
/// `PeerTransport` seam — the upper layer sees only the trait, so PeerTask
/// stays transport-agnostic.
///
/// Data plane: bytes delivered in order by the driver task arrive on a
/// bounded(64) downlink channel (`poll_read`); application writes go over
/// a bounded(64) uplink channel into the driver (`poll_write`), which
/// packs and sends them per the window rules. The rate limiter
/// (`Arc<SpeedLimiter>`) awaits permits on the PeerTask read path, which
/// naturally back-pressures this channel; this layer need not know.
pub struct UtpStream {
    data_rx: mpsc::Receiver<Bytes>,
    /// poll_read partial-delivery remainder: when a packet exceeds the
    /// caller's buffer, keep the truncated rest and hand it out first next
    /// time (AsyncRead contract: a single write must not exceed ReadBuf's
    /// remaining capacity).
    read_leftover: Option<Bytes>,
    /// Write uplink (poll-semantics wrapper: poll_reserve capacity permit ->
    /// send_item; bounded back-pressure propagates as Pending to the
    /// PeerTask write path).
    write_tx: PollSender<Bytes>,
    ctrl_tx: mpsc::Sender<Ctrl>,
    err_rx: watch::Receiver<CloseState>,
}

impl std::fmt::Debug for UtpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written: the live channel/watch endpoints are omitted
        // (Debug must not touch transport internals); the partial-read
        // remainder shows as a length only.
        f.debug_struct("UtpStream")
            .field(
                "read_leftover_bytes",
                &self.read_leftover.as_ref().map(Bytes::len),
            )
            .finish()
    }
}

impl UtpStream {
    /// In-crate constructor (for driver-direct tests; production goes through the listener).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_channels(
        data_rx: mpsc::Receiver<Bytes>,
        write_tx: mpsc::Sender<Bytes>,
        ctrl_tx: mpsc::Sender<Ctrl>,
        err_rx: watch::Receiver<CloseState>,
    ) -> Self {
        Self {
            data_rx,
            read_leftover: None,
            write_tx: PollSender::new(write_tx),
            ctrl_tx,
            err_rx,
        }
    }

    /// Immediately-failed stream (outbound connect refusal: table full /
    /// table lock unavailable; hardening). The terminal state is preset to
    /// `Abnormal(Closed)` — reads and writes error at once; no route-table
    /// entry, no driver task; the caller walks its existing retry/degrade
    /// path for a failed connection.
    fn refused(data_queue_packets: usize) -> Self {
        let (_, data_rx) = mpsc::channel(data_queue_packets);
        let (write_tx, _) = mpsc::channel(data_queue_packets);
        let (ctrl_tx, _) = mpsc::channel(1);
        let (_, err_rx) = watch::channel(CloseState::Abnormal(UtpError::Closed));
        Self {
            data_rx,
            read_leftover: None,
            write_tx: PollSender::new(write_tx),
            ctrl_tx,
            err_rx,
        }
    }

    /// Terminal error snapshot (None = no abnormal termination yet;
    /// EOF/graceful close not included).
    pub fn error(&self) -> Option<UtpError> {
        match &*self.err_rx.borrow() {
            CloseState::Abnormal(e) => Some(e.clone()),
            _ => None,
        }
    }

    /// Terminal-state test (includes graceful close; tests/observability).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_closed(&self) -> bool {
        matches!(
            &*self.err_rx.borrow(),
            CloseState::Graceful | CloseState::Abnormal(_)
        )
    }

    /// Force-terminate locally: send ST_RESET to the peer and close at once
    /// (BEP-29 "type" ST_RESET — no FIN handshake; for fast reclamation
    /// when the caller judges the connection unsalvageable).
    pub fn abort(&self) {
        let _ = self.ctrl_tx.try_send(Ctrl::Reset);
    }
}

impl AsyncRead for UtpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(b) = this.read_leftover.take() {
            let n = b.len().min(out.remaining());
            out.put_slice(&b[..n]);
            if n < b.len() {
                this.read_leftover = Some(b.slice(n..));
            }
            return Poll::Ready(Ok(()));
        }
        match this.data_rx.poll_recv(cx) {
            Poll::Ready(Some(b)) => {
                let n = b.len().min(out.remaining());
                out.put_slice(&b[..n]);
                if n < b.len() {
                    this.read_leftover = Some(b.slice(n..));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => match &*this.err_rx.borrow() {
                CloseState::Abnormal(e) => Poll::Ready(Err(e.clone().into())),
                // Channel closed after draining = EOF (ST_FIN) or graceful close.
                _ => Poll::Ready(Ok(())),
            },
            Poll::Pending => {
                // Channel empty: surface read-side EOF (half-close) or an
                // abnormal terminal state immediately (the driver sets
                // ReadEof once the peer's ST_FIN has been delivered).
                match &*this.err_rx.borrow() {
                    CloseState::ReadEof | CloseState::Graceful => Poll::Ready(Ok(())),
                    CloseState::Abnormal(e) => Poll::Ready(Err(e.clone().into())),
                    CloseState::Open => Poll::Pending,
                }
            }
        }
    }
}

impl AsyncWrite for UtpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // PollSender::poll_reserve is the poll form of a bounded-channel
        // capacity permit; when full it returns Pending and the channel wakes
        // us — write-side back-pressure is the propagation of driver
        let terminal = || match &*this.err_rx.borrow() {
            CloseState::Abnormal(e) => e.clone().into(),
            // ReadEof is read-side only; a broken write channel can only be treated as closed.
            _ => UtpError::Closed.into(),
        };
        match this.write_tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => match this.write_tx.send_item(Bytes::copy_from_slice(buf)) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(terminal())),
            },
            Poll::Ready(Err(_)) => Poll::Ready(Err(terminal())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send pacing belongs to the driver's window pump (uTP has no application-level flush).
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Graceful close: queue ST_FIN (BEP-29 "type" ST_FIN). If the ctrl
        // channel is full (theoretically impossible: capacity 16 and FIN is
        // sent once), the Drop path retries as a backstop.
        let this = self.get_mut();
        let _ = this.ctrl_tx.try_send(Ctrl::Fin);
        Poll::Ready(Ok(()))
    }
}

impl Drop for UtpStream {
    fn drop(&mut self) {
        // Dropping without an explicit shutdown also sends FIN (best
        // effort); driver timeouts backstop.
        let _ = self.ctrl_tx.try_send(Ctrl::Fin);
    }
}

/// Production assembly: wire the demux utp channel into the listener and
/// the outbound pump into the demux's single write entry
/// (`send_packet`).
///
/// Returns (handle, outbound pump task JoinHandle). The pump exits when
/// the demux closes (OutboundClosed) or on shutdown cancellation.
pub fn spawn_utp(
    utp_rx: mpsc::Receiver<InboundPacket>,
    demux: UdpDemuxHandle,
    cfg: UtpConfig,
    token: CancellationToken,
) -> (UtpListenerHandle, tokio::task::JoinHandle<()>) {
    let (out_tx, out_rx) = mpsc::channel(cfg.outbound_channel);
    let handle = spawn_with_sink(cfg, utp_rx, out_tx, token.clone());
    let pump = tokio::spawn(async move {
        let mut out_rx = out_rx;
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                pkt = out_rx.recv() => match pkt {
                    Some(p) => {
                        if demux.send_packet(p.to, p.data).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    });
    (handle, pump)
}

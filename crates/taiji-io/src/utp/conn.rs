//! µTP connection driver: state machine + reliability + window pump,
//! one task per connection (BEP-29).
//!
//! Wire behavior follows BEP-29 section by section; the handshake
//! seq_nr decision (the SYN-ACK consumes no sequence number) and the
//! full upstream anchor mapping live in docs/design/io.md
//! (`utp/conn.rs`). Implementation-local parameters (scan-round
//! period, consecutive-timeout round cap, reorder buffer cap, packet
//! size cap) are marked "implementation-local" in
//! [`crate::utp::UtpConfig`].
//!
//! Hard invariants:
//! - payload-less packets (ST_STATE) never advance `seq_nr`;
//! - the acceptor's first ST_DATA reuses the SYN-ACK's seq_nr, and the
//! initiator completes the connection with ack baseline
//! `SYN-ACK.seq_nr - 1`;
//! - per-connection receive caps: reorder <= `reorder_packets` packets
//! and <= `recv_buffer` bytes; pending <= `recv_buffer` bytes; the
//! process-wide aggregate is capped by `RECV_LEDGER_CAP`;
//! - the driver loop must never block on the application's read rate
//! (in-order delivery uses non-blocking `try_send` and retries next
//! round; backpressure reaches the peer via the advertised window).
//!
//! Concurrency: a single task owns all connection state (lock-free);
//! a five-way select over inbound packets / app writes / control /
//! delivery permits / the retransmit scan round. All channels are
//! bounded (capacity sources in the `UtpConfig` docs).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::ledbat::{Ledbat, Rtt};
use super::packet::{self, Header, PacketType};
use super::{ConnKey, MAX_INBOUND_PAYLOAD, State, UtpConfig, UtpError, wrapping_diff_us};
use crate::udp_demux::{InboundPacket, OutboundPacket};

/// tracing target.
const LOG_TARGET: &str = "taiji::io::utp";

/// Driver control commands (application side -> driver).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ctrl {
    /// Graceful close: queue an ST_FIN (BEP-29 §"type" ST_FIN).
    Fin,
    /// Local abort: send ST_RESET (best effort) and close immediately.
    Reset,
}

/// Process-wide µTP receive-byte ledger — an upper bound on the sum of
/// reorder + pending across all connections (default 64MiB).
/// Per-connection caps (reorder <= min(1024 packets, 256KiB); pending
/// <= 256KiB = `recv_buffer`) stay in place; this ledger bounds the
/// aggregate multiplication surface (512 conns x ~0.5MiB ≈ 358MiB
/// theoretical ceiling -> 64MiB + structural constants). Claim = enter
/// pending/reorder; release = deliver on the data channel / connection
/// teardown Drop. Rejection semantics: the pending arm = ST_RESET as a
/// window violation; the reorder arm = drop (peer retransmission
/// recovers, same as the queue-full semantics). Under honest load
/// (peers inside their advertised window) the ledger stays far from
/// the cap: zero behavior change.
static RECV_LEDGER: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
/// Ledger cap (i64 bytes).
pub(crate) const RECV_LEDGER_CAP: i64 = 64 * 1024 * 1024;

fn recv_ledger_claim(bytes: usize) -> bool {
    use std::sync::atomic::Ordering;
    let b = bytes as i64;
    let prev = RECV_LEDGER.fetch_add(b, Ordering::Relaxed);
    if prev + b <= RECV_LEDGER_CAP {
        true
    } else {
        RECV_LEDGER.fetch_sub(b, Ordering::Relaxed);
        false
    }
}

fn recv_ledger_release(bytes: usize) {
    use std::sync::atomic::Ordering;
    if bytes > 0 {
        RECV_LEDGER.fetch_sub(bytes as i64, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub(crate) fn recv_ledger_used() -> i64 {
    RECV_LEDGER.load(std::sync::atomic::Ordering::Relaxed)
}

/// Reliable outbound entries (ST_SYN/ST_DATA/ST_FIN; ST_STATE is a pure
/// ack and never queues — on loss the peer's data retransmission
/// triggers a fresh ack, BEP-29 §"type" ST_STATE semantics).
struct OutPkt {
    seq: u16,
    payload: Bytes,
    kind: Kind,
    /// Last send instant (monotonic µs); `None` = queued, not yet sent.
    sent_at: Option<u64>,
    /// Send count (BEP-29 §"timeouts": rtt updates only for
    /// transmissions == 1).
    transmissions: u32,
    /// Fast retransmit already fired for this loss event (once per round).
    loss_retransmitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Syn,
    Data,
    Fin,
}

impl OutPkt {
    /// In-flight size in bytes, header included (BEP-29 §"overview":
    /// cur_window is byte-counted).
    fn wire_size(&self) -> u32 {
        packet::HEADER_LEN as u32 + self.payload.len() as u32
    }
}

/// Connection terminal states (watch notification face; Open = still
/// running).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloseState {
    Open,
    /// Read-side EOF ready (half-close: the peer's ST_FIN and all data
    /// before it are delivered; BEP-29 §"type" ST_FIN — the write side
    /// may continue).
    ReadEof,
    /// Graceful close (FIN converged / local close).
    Graceful,
    /// Aborted (RESET / timeout / channel dropped).
    Abnormal(UtpError),
}

/// The driver's channel set (built by the listener / tests).
pub(crate) struct DriverChannels {
    pub inbound: mpsc::Receiver<InboundPacket>,
    pub write: mpsc::Receiver<Bytes>,
    pub ctrl: mpsc::Receiver<Ctrl>,
    pub data: mpsc::Sender<Bytes>,
    pub out: mpsc::Sender<OutboundPacket>,
    pub err: watch::Sender<CloseState>,
}

/// Connection role (determines the handshake initial values, BEP-29
/// §"connection setup").
pub(crate) enum Role {
    /// Initiator: conn_id_recv is chosen and pre-registered in the
    /// routing table by the caller (BEP-29 §"connection_id": "The
    /// endpoint initiating the connection decides which ID to use");
    /// conn_id_send = recv + 1, seq_nr = 1.
    Initiator {
        /// Receive id chosen by the initiator (the SYN carries it).
        conn_id_recv: u16,
    },
    /// Acceptor: conn_id_recv = syn.conn_id + 1, conn_id_send =
    /// syn.conn_id, seq_nr = rand, ack_nr = syn.seq_nr.
    Acceptor {
        /// conn_id carried by the received ST_SYN (BEP-29: pkt.conn_id).
        syn_conn_id: u16,
        /// seq_nr of the received ST_SYN (acceptor ack_nr init =
        /// pkt.seq_nr).
        syn_seq_nr: u16,
    },
}

/// Connection initial specification.
pub(crate) struct ConnSpec {
    pub addr: SocketAddr,
    pub role: Role,
}

/// Deregistration handle: removes this key from the listener routing
/// table when the connection ends (the Mutex is held only in short
/// critical sections, never across an await).
pub(crate) type Dereg = Option<(
    Arc<Mutex<std::collections::HashMap<ConnKey, mpsc::Sender<InboundPacket>>>>,
    ConnKey,
)>;

/// Spawns the connection driver task.
pub(crate) fn spawn_driver(
    cfg: UtpConfig,
    spec: ConnSpec,
    ch: DriverChannels,
    dereg: Dereg,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        let mut d = Driver::new(cfg, spec, ch, dereg);
        d.run(token).await;
    });
}

/// Drop safety net that releases the receive ledger (the normal path
/// releases at the delivery points; residue in reorder/pending on an
/// ST_RESET/timeout teardown is returned here — prevents a bookkeeping
/// leak across long sessions).
impl Drop for Driver {
    fn drop(&mut self) {
        recv_ledger_release(self.pending_bytes + self.reorder_bytes);
        self.pending_bytes = 0;
        self.reorder_bytes = 0;
    }
}

/// Connection driver (owns all connection state).
pub(crate) struct Driver {
    cfg: UtpConfig,
    addr: SocketAddr,
    state: State,
    /// Our receive id (packets from the peer carry it, BEP-29
    /// §"connection_id").
    conn_id_recv: u16,
    /// Our send id (packets we emit carry it).
    conn_id_send: u16,
    /// Next send sequence number (BEP-29 §"seq_nr").
    seq_nr: u16,
    /// Last in-order received peer sequence number (BEP-29 §"ack_nr").
    ack_nr: u16,
    /// Cumulative ack point for our data (send side; 0 before the SYN
    /// because BEP-29 starts seq_nr at 1).
    peer_ack: u16,
    /// Peer-advertised receive window (BEP-29 §"wnd_size"; 0 until the
    /// handshake completes).
    their_wnd: u32,

    /// Unacknowledged outbound packets (FIFO; BEP-29 §"overview": oldest
    /// unacked = seq_nr - cur_window).
    outq: VecDeque<OutPkt>,
    /// In-flight bytes (BEP-29 cur_window).
    cur_window: u32,
    /// Application data awaiting packetization.
    write_buf: BytesMut,
    /// FIN requested but not yet queued.
    fin_requested: bool,
    /// Our FIN sequence number (recorded once queued).
    fin_seq: Option<u16>,
    /// FIN acknowledged by the peer.
    fin_acked: bool,

    /// Out-of-order receive buffer (ascending by seq; FIN placeholders
    /// carry no payload).
    reorder: VecDeque<(u16, Option<Bytes>)>,
    reorder_bytes: usize,
    /// Peer's eof_pkt (BEP-29 §"type" ST_FIN).
    eof_pkt: Option<u16>,
    /// Read-side EOF ready (eof and all earlier data delivered in order).
    read_eof: bool,
    /// Data awaiting delivery (in order, waiting for data-channel room).
    pending: VecDeque<Bytes>,
    /// Current pending byte usage (per-connection cap =
    /// [`Driver::pending_cap`], exceeding it is an ST_RESET — a window
    /// violation disconnect; the process-wide aggregate cap =
    /// `RECV_LEDGER_CAP`, exceeding it also disconnects).
    pending_bytes: usize,

    /// Duplicate ack count (BEP-29 §"packet loss": 3 => ack_nr+1 lost).
    dup_acks: u32,
    /// RTT/timeout estimate (BEP-29 §"timeouts" formulas).
    rtt: Rtt,
    /// LEDBAT controller (BEP-29 §"congestion control").
    ledbat: Ledbat,
    /// Latest peer one-way delay sample (echoed back as
    /// timestamp_difference, BEP-29 §"overview" reply_micro; `None` = no
    /// sample, the wire field must then be 0).
    reply_micro: Option<i64>,
    /// Last activity instant (reset on every packet sent or received,
    /// BEP-29 §"timeouts").
    last_activity_us: u64,
    /// Last instant a packet arrived from the peer (baseline for the
    /// give-up decision; sends do not refresh it — whether the peer is
    /// alive depends only on it having something to say to us).
    last_recv: u64,
    /// Instant of the last retransmit round (timeout event); events
    /// reset the counter per BEP-29 §"timeouts" (a retransmit counts as
    /// a send).
    last_timeout_event: u64,
    closed: bool,
    /// Channel latches: once the application handles are dropped, recv()
    /// returns None forever and the arm must be latched off (otherwise
    /// the select hot loop spins and starves the runtime).
    ctrl_open: bool,
    write_open: bool,
    /// Consecutive silent retransmit rounds (capped at 4 => interval
    /// x16; the scan-round realization of BEP-29 §"timeouts" doubling).
    idle_rounds: u32,
    /// Retransmit-interval doubling shift (= idle_rounds).
    rtt_backoff_shift: u32,
    ch: DriverChannels,
    dereg: Dereg,
}

impl Driver {
    fn new(cfg: UtpConfig, spec: ConnSpec, ch: DriverChannels, dereg: Dereg) -> Self {
        // BEP-29 §"connection setup": initial values for both roles
        // (verbatim quotes in docs/design/io.md).
        let (state, conn_id_recv, conn_id_send, seq_nr, ack_nr, peer_ack) = match spec.role {
            Role::Initiator { conn_id_recv } => (
                State::SynSent,
                conn_id_recv,
                conn_id_recv.wrapping_add(1),
                1,
                0,
                0,
            ),
            Role::Acceptor {
                syn_conn_id,
                syn_seq_nr,
            } => {
                // The acceptor's first packet is the handshake ST_STATE
                // (seq = rand, see run()); the SYN-ACK consumes no
                // sequence number (rationale in docs/design/io.md: the
                // BEP-29 §"type" ST_STATE normative sentence + the
                // libutp/rqbit reference implementations), so the first
                // ST_DATA reuses the same seq. The peer's acks will
                // accumulate from "SYN-ACK seq - 1" — peer_ack takes
                // that baseline (the u16 wraparound space must share
                // this baseline with our own seq, otherwise the peer's
                // first cumulative ack can be misjudged as stale against
                // the random initial value).
                let first_seq: u16 = rand::random();
                (
                    State::SynRecv,
                    syn_conn_id.wrapping_add(1),
                    syn_conn_id,
                    first_seq,
                    syn_seq_nr,
                    first_seq.wrapping_sub(1),
                )
            }
        };
        // LEDBAT initial window = 2xMSS (RFC 6817 §2.5: "INIT_CWND and
        // MIN_CWND SHOULD both be 2." — MSS = this implementation's
        // packet size cap).
        let ledbat = Ledbat::new(
            cfg.ledbat.clone(),
            (cfg.max_packet_payload.saturating_mul(2)) as u32,
        );
        let mut d = Self {
            cfg,
            addr: spec.addr,
            state,
            conn_id_recv,
            conn_id_send,
            seq_nr,
            ack_nr,
            peer_ack,
            their_wnd: 0,
            outq: VecDeque::new(),
            cur_window: 0,
            write_buf: BytesMut::new(),
            fin_requested: false,
            fin_seq: None,
            fin_acked: false,
            reorder: VecDeque::new(),
            reorder_bytes: 0,
            eof_pkt: None,
            read_eof: false,
            pending: VecDeque::new(),
            pending_bytes: 0,
            dup_acks: 0,
            rtt: Rtt::default(),
            ledbat,
            reply_micro: None,
            last_activity_us: super::now_us(),
            last_recv: super::now_us(),
            last_timeout_event: 0,
            closed: false,
            ctrl_open: true,
            write_open: true,
            idle_rounds: 0,
            rtt_backoff_shift: 0,
            ch,
            dereg,
        };
        if d.state == State::SynSent {
            // SYN: seq_nr starts at 1 (BEP-29 §"type" ST_SYN: "The
            // sequence number is initialized to 1") and carries
            // rcv_conn_id (§"connection setup").
            d.seq_nr = d.seq_nr.wrapping_add(1);
            d.outq.push_back(OutPkt {
                seq: 1,
                payload: Bytes::new(),
                kind: Kind::Syn,
                sent_at: None,
                transmissions: 0,
                loss_retransmitted: false,
            });
        }
        d
    }

    /// Main loop (five-way select, see the module docs).
    async fn run(&mut self, token: CancellationToken) {
        // Acceptor's first handshake reply (BEP-29 figure: the acceptor
        // immediately answers ST_STATE with ack_nr=c.ack_nr;
        // fire-and-forget — if lost, the peer's SYN retransmission
        // triggers a resend, see the on_packet SYN branch). ST_STATE has
        // no payload and consumes no seq_nr (rationale in
        // docs/design/io.md): the seq stays at its current value and our
        // first ST_DATA reuses it; retransmits reuse it too (resending
        // the same packet does not advance the sequence).
        if self.state == State::SynRecv {
            let syn_seq = self.ack_nr;
            let seq = self.seq_nr;
            let _ = self.send_state(seq, syn_seq, None).await;
        }
        // Initiator: flush the SYN.
        if self.state == State::SynSent {
            self.send_new_entries().await;
        }

        loop {
            if self.closed {
                return;
            }
            // In-order delivery: non-blocking try_send (bounded(64)
            // downstream). On a full queue, do not wait — the whole
            // driver loop must never be blocked by the application's
            // read rate (otherwise acks / the retransmit scan / FIN all
            // freeze and the peer stalls with them); delivery is retried
            // on the next loop iteration (the scan round, period
            // <= 500ms, backstops the poll) and backpressure reaches the
            // peer via the advertised window.
            while let Some(front) = self.pending.front().cloned() {
                let n = front.len();
                match self.ch.data.try_send(front) {
                    Ok(()) => {
                        self.pending.pop_front();
                        self.pending_bytes = self.pending_bytes.saturating_sub(n);
                        recv_ledger_release(n);
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => break,
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // All read-side handles dropped: shut down.
                        self.shutdown(None);
                        return;
                    }
                }
            }
            // Pump once per iteration: packetize/send/FIN-queue converge
            // to the current state without depending on a particular
            // event — missing the pump call from any of the ack/write/
            // control sources stalls the write side.
            self.pump().await;
            // Retransmit scan round: period = clamp(RTT/2, min, max)
            // (SPEC §6.5 round semantics).
            let scan = tokio::time::sleep(self.cfg.retrans_scan_period(self.rtt.rtt_ms()));
            tokio::select! {
                _ = token.cancelled() => {
                    self.shutdown(None);
                    return;
                }
                pkt = self.ch.inbound.recv() => match pkt {
                    Some(p) => self.on_packet(p).await,
                    None => {
                        // Routing table / demux torn down: the
                        // peer-facing surface is gone.
                        self.shutdown(Some(UtpError::SinkClosed));
                        return;
                    }
                },
                ctrl = self.ch.ctrl.recv(), if self.ctrl_open => match ctrl {
                    Some(Ctrl::Fin) => {
                        self.fin_requested = true;
                    }
                    Some(Ctrl::Reset) => {
                        let _ = self.send_reset().await;
                        self.shutdown(None);
                        return;
                    }
                    None => {
                        // Stream handle dropped (the ctrl sender fell):
                        // latch the arm off (None is always ready; not
                        // latching = a hot select loop) and treat as a
                        // FIN request for a graceful finish.
                        self.ctrl_open = false;
                        self.fin_requested = true;
                        self.pump().await;
                    }
                },
                w = self.ch.write.recv(),
                    if self.write_open && self.write_buf.len() < self.max_write_buf() =>
                {
                    match w {
                        Some(b) => {
                            self.write_buf.extend_from_slice(&b);
                            self.pump().await;
                        }
                        None => {
                            // Write sender dropped: latch the arm off +
                            // treat as a FIN request.
                            self.write_open = false;
                            self.fin_requested = true;
                            self.pump().await;
                        }
                    }
                }
                _ = scan => {
                    self.scan_round().await;
                }
            }
            self.maybe_finish().await;
            if self.closed {
                return;
            }
        }
    }

    fn max_write_buf(&self) -> usize {
        self.cfg.write_queue_packets * self.cfg.max_packet_payload
    }

    /// pending (in-order received, not yet taken by the application)
    /// byte cap = [`UtpConfig::recv_buffer`] (implementation-local,
    /// safety hardening: the same order as the reorder buffer — an
    /// honest peer constrained by the advertised window never reaches
    /// it; reaching it is a window violation and disconnects as a
    /// protocol violation, see on_inbound_stream).
    fn pending_cap(&self) -> usize {
        self.cfg.recv_buffer as usize
    }

    /// Give-up threshold: the longest tolerated span with no inbound
    /// packet at all (implementation-local parameter).
    fn max_idle_us(&self) -> u64 {
        self.cfg.max_idle_secs * 1_000_000
    }

    // ---- Packet handling ----

    async fn on_packet(&mut self, p: InboundPacket) {
        if p.from != self.addr {
            return; // Routing key already includes the address; defensively ignored.
        }
        let now = super::now_us();
        let Ok(pkt) = packet::decode(&p.data) else {
            debug!(target: LOG_TARGET, from = %p.from, "malformed uTP packet dropped");
            return;
        };
        // Inbound payload length check (safety hardening): payloads over
        // the inbound cap (genuinely oversized — cannot legally arrive
        // under a 1500B ethernet MTU, derivation at MAX_INBOUND_PAYLOAD)
        // are dropped outright (no ack — the peer retransmits on loss; a
        // persistent violation is a window/protocol violation and the
        // timeout round gives up on the connection). The check is
        // decoupled from the send-side chunking parameter
        // max_packet_payload: a reference implementation's full-size
        // packets (libutp 1435/1452) are larger than our send parameter
        // and must still be accepted, otherwise interop breaks. Also in
        // force before the BT handshake (SynRecv/SynSent).
        if pkt.payload.len() > MAX_INBOUND_PAYLOAD {
            debug!(target: LOG_TARGET, from = %p.from, len = pkt.payload.len(),
                cap = MAX_INBOUND_PAYLOAD, "oversized uTP payload; dropped");
            return;
        }
        // The peer's send id = our receive id (BEP-29 §"connection_id"
        // +1 loop semantics). Exception: an ST_SYN retransmission in
        // SYN_RECV carries "our receive id - 1" (the original conn_id
        // from before acceptance — BEP-29 §"type" ST_SYN: "The
        // connection ID is what the other end is expected to use in its
        // responses"; the retransmission keeps the original id) and must
        // pass to trigger a SYN-ACK resend.
        let syn_retrans = pkt.header.packet_type == PacketType::Syn
            && self.state == State::SynRecv
            && pkt.header.connection_id == self.conn_id_recv.wrapping_sub(1);
        if pkt.header.connection_id != self.conn_id_recv && !syn_retrans {
            debug!(target: LOG_TARGET, from = %p.from, got = pkt.header.connection_id, want = self.conn_id_recv, "conn_id mismatch; dropped");
            return;
        }
        // reply_micro = now - peer timestamp (BEP-29 §"overview":
        // updated on every received packet, echoed on every sent packet
        // afterwards).
        self.last_recv = now;
        self.reply_micro = Some(wrapping_diff_us(now as u32, pkt.header.timestamp_micros));
        // Peer-advertised window (BEP-29 §"wnd_size").
        self.their_wnd = pkt.header.wnd_size;

        match pkt.header.packet_type {
            PacketType::Reset => {
                // BEP-29 §"type" ST_RESET: the peer has no state for
                // this connection; force terminate.
                debug!(target: LOG_TARGET, from = %p.from, "ST_RESET; closing");
                self.shutdown(Some(UtpError::Reset));
            }
            PacketType::Syn => {
                // ST_SYN on an existing connection = unexpected (BEP-29
                // §"connection setup": "unexpected in the existing
                // stream, and ignored"); SYN_RECV exception: resend
                // ST_STATE (reached when the SYN-ACK was lost and the
                // peer's SYN retransmission arrives; a retransmission of
                // the same SYN-ACK, seq does not advance).
                if self.state == State::SynRecv {
                    let syn_seq = self.ack_nr;
                    let seq = self.seq_nr;
                    let _ = self.send_state(seq, syn_seq, None).await;
                }
            }
            PacketType::State => {
                // Pure ack: advance the acknowledgment face; do not ack
                // back (BEP-29 §"type" ST_STATE).
                self.last_activity_us = now;
                self.on_ack_fields(&pkt.header, pkt.sack).await;
                if self.state == State::SynSent {
                    // Initiator connection completed (BEP-29 figure,
                    // CS_CONNECTED): ack baseline = SYN-ACK seq - 1 —
                    // the SYN-ACK consumes no sequence number and the
                    // acceptor's first ST_DATA reuses its seq; same
                    // reading as libutp's CS_SYN_SENT branch
                    // `conn->ack_nr = (pk_seq_nr - 1) & SEQ_NR_MASK`
                    // and rqbit's `new_outgoing`
                    // `last_consumed_remote_seq_nr = remote_ack.seq_nr - 1`;
                    // rqbit's accept-side SynAckSent guard (a first
                    // packet whose ack_nr != seq_nr-1 is dropped until
                    // MaxSynAckRetransmissionsReached — the direction-A
                    // root cause). Full rationale: docs/design/io.md.
                    self.state = State::Connected;
                    self.ack_nr = pkt.header.seq_nr.wrapping_sub(1);
                    self.pump().await;
                }
            }
            PacketType::Data | PacketType::Fin => {
                self.last_activity_us = now;
                self.on_ack_fields(&pkt.header, pkt.sack).await;
                match self.state {
                    State::SynSent => {
                        // Data stream before the handshake completed:
                        // unexpected (BEP-29 §"connection setup" orders
                        // ST_STATE first); ignored.
                        warn!(target: LOG_TARGET, from = %p.from, "stream packet before handshake; ignored");
                    }
                    State::SynRecv => {
                        self.state = State::Connected;
                        self.on_inbound_stream(&pkt.header, pkt.payload).await;
                    }
                    State::Connected | State::Fin | State::Closed => {
                        self.on_inbound_stream(&pkt.header, pkt.payload).await;
                    }
                }
            }
        }
    }

    /// Acknowledgment face: cumulative ack + sack + loss detection +
    /// LEDBAT (BEP-29 §"timeouts"/§"packet loss"/§"congestion control").
    async fn on_ack_fields(&mut self, h: &Header, sack: Option<packet::Sack<'_>>) {
        let new_ack = h.ack_nr;
        let now = super::now_us();
        let mut newly_acked_bytes: u32 = 0;
        let mut loss_detected = false;

        if packet::seq_gt(new_ack, self.peer_ack) {
            // Cumulative advance: acknowledge outbound packets in
            // (peer_ack, new_ack] (BEP-29 §"timeouts": "either by
            // falling in the range (last_ack_nr, ack_nr]").
            while let Some(front) = self.outq.front() {
                if !packet::seq_le(front.seq, new_ack) {
                    break;
                }
                let e = match self.outq.pop_front() {
                    Some(e) => e,
                    None => break,
                };
                newly_acked_bytes = newly_acked_bytes.saturating_add(e.wire_size());
                self.cur_window = self.cur_window.saturating_sub(e.wire_size());
                self.note_acked(e, now);
            }
            self.peer_ack = new_ack;
            self.dup_acks = 0;
        } else if packet::seq_lt(new_ack, self.peer_ack) {
            return; // Stale ack.
        } else if h.packet_type == PacketType::State && sack.is_none() {
            // Duplicate pure ack (BEP-29 §"packet loss": "when receiving
            // 3 duplicate acks, ack_nr + 1 is assumed to have been lost
            // (if a packet with that sequence number has been sent)").
            self.dup_acks += 1;
            if self.dup_acks == 3
                && let Some(front) = self.outq.front()
                && !front.loss_retransmitted
            {
                loss_detected = true;
                let seq = front.seq;
                self.retransmit(seq, now).await;
            }
        }

        // Selective ACK: bit i <-> ack_nr+2+i (BEP-29 §"Selective ACK").
        if let Some(sack) = sack {
            let sacked: Vec<u16> = self
                .outq
                .iter()
                .filter(|e| sack.acked(e.seq))
                .map(|e| e.seq)
                .collect();
            for seq in &sacked {
                if let Some(idx) = self.outq.iter().position(|e| e.seq == *seq)
                    && let Some(e) = self.outq.remove(idx)
                {
                    newly_acked_bytes = newly_acked_bytes.saturating_add(e.wire_size());
                    self.cur_window = self.cur_window.saturating_sub(e.wire_size());
                    self.note_acked(e, now);
                }
            }
            if !sacked.is_empty() {
                // Each sacked packet counts once toward duplicate acks;
                // >=3 sacked past the oldest unacked => lost, retransmit
                // (BEP-29 §"packet loss", quoted in docs/design/io.md).
                self.dup_acks += sacked.len() as u32;
                if let Some(front) = self.outq.front() {
                    let front_seq = front.seq;
                    let sacked_past = sacked
                        .iter()
                        .filter(|s| packet::seq_gt(**s, front_seq))
                        .count() as u32;
                    // >=3 sacked past the oldest packet => lost; at most
                    // one retransmit per >=1/2 RTT (repeated rounds of
                    // fast retransmit under sustained loss — otherwise a
                    // retransmit that is itself lost waits for the
                    // timeout round, whose interval has already doubled
                    // to the point of stalling the whole connection).
                    let rearm = front.loss_retransmitted
                        && front.sent_at.is_none_or(|t| {
                            now.saturating_sub(t) >= (self.rtt.timeout().as_micros() as u64) / 2
                        });
                    if sacked_past >= 3 && (!front.loss_retransmitted || rearm) {
                        loss_detected = true;
                        self.retransmit(front_seq, now).await;
                    }
                }
            }
        }

        if loss_detected {
            // Loss event (once per round): max_window x0.5 (BEP-29
            // §"packet loss").
            self.ledbat.on_loss();
        }

        // LEDBAT: sample = the peer-echoed timestamp_difference (0 = the
        // peer has no sample, skip; BEP-29
        // §"timestamp_difference_microseconds": "must be set to 0").
        let sample = h.timestamp_diff_micros as i32 as i64;
        self.ledbat
            .on_ack(sample, newly_acked_bytes, self.cur_window, now);

        // The window may have opened as acks advanced: keep pumping.
        self.pump().await;
    }

    /// Ack bookkeeping: rtt (single-transmission packets only, BEP-29
    /// §"timeouts") and the FIN flag.
    fn note_acked(&mut self, e: OutPkt, now: u64) {
        if e.transmissions == 1
            && let Some(sent_at) = e.sent_at
        {
            let rtt_ms = now.saturating_sub(sent_at) as f64 / 1000.0;
            self.rtt.update(rtt_ms);
        }
        if e.kind == Kind::Fin {
            self.fin_acked = true;
        }
    }

    /// Single-packet loss retransmit (BEP-29 §"packet loss").
    async fn retransmit(&mut self, seq: u16, now: u64) {
        if let Some(e) = self.outq.iter_mut().find(|e| e.seq == seq) {
            e.sent_at = Some(now);
            e.transmissions += 1;
            e.loss_retransmitted = true;
        }
        self.resend(seq).await;
    }

    /// Inbound data / in-order delivery + ack reply (BEP-29
    /// §"ack_nr"/§"Selective ACK").
    async fn on_inbound_stream(&mut self, h: &Header, payload: &[u8]) {
        let seq = h.seq_nr;
        if h.packet_type == PacketType::Fin {
            // eof_pkt record (BEP-29 §"type" ST_FIN, quoted in
            // docs/design/io.md); a retransmitted overlapping FIN is a
            // harmless overwrite.
            self.eof_pkt = Some(seq);
        }
        if packet::seq_le(seq, self.ack_nr) {
            // Duplicate/old packet: re-ack the current position (no
            // delivery).
            self.send_ack().await;
            return;
        }
        if seq == self.ack_nr.wrapping_add(1) {
            // Next in sequence: deliver, then absorb as many buffered
            // successors as possible.
            if !payload.is_empty() {
                // Safety cap: pending over its cap = the peer ignoring
                // the advertised window (advertised_wnd already counts
                // pending usage, an honest peer cannot reach it). Drop +
                // ST_RESET disconnect (BEP-29 §"type" ST_RESET: force
                // terminate), preventing remote unbounded-buffer OOM.
                let over_conn = self.pending_bytes + payload.len() > self.pending_cap();
                // Process-wide aggregate cap: a failed claim = the
                // global receive surface is full — disconnect as the
                // same window violation (backpressure face: an honest
                // connection's advertised window should not reach this;
                // reaching it is an aggregate anomaly, and yielding is
                // the correct action).
                if over_conn || !recv_ledger_claim(payload.len()) {
                    warn!(target: LOG_TARGET, from = %self.addr,
                        pending = self.pending_bytes, len = payload.len(),
                        "pending byte cap exceeded; resetting (window violation)");
                    self.shutdown(Some(UtpError::Reset));
                    return;
                }
                self.pending_bytes += payload.len();
                self.pending.push_back(Bytes::copy_from_slice(payload));
            }
            self.ack_nr = seq;
            while let Some(front) = self.reorder.front() {
                if front.0 != self.ack_nr.wrapping_add(1) {
                    break;
                }
                // Absorption is bound by the pending cap too: entries
                // that do not fit stay in reorder (the sack reports the
                // gap and the peer's retransmission recovers); once the
                // read side drains, later packets continue absorbing.
                if let Some((_, Some(d))) = self.reorder.front()
                    && self.pending_bytes + d.len() > self.pending_cap()
                {
                    break;
                }
                let (s, data) = match self.reorder.pop_front() {
                    Some(x) => x,
                    None => break,
                };
                self.ack_nr = s;
                if let Some(d) = data {
                    self.reorder_bytes -= d.len();
                    self.pending_bytes += d.len();
                    self.pending.push_back(d);
                }
            }
        } else {
            // Out of order: buffer within caps (feeds the sack and later
            // in-order delivery); overflow is dropped — the peer's
            // retransmission recovers (queue-full drop + retransmit
            // fallback semantics).
            // The ledger claim happens only on the definite-insert path
            // (a duplicate-seq hit does not insert — claiming before the
            // dup check would leak the claim on every hit, and repeated
            // duplicate out-of-order packets could irreversibly exhaust
            // the global ledger = a process-wide DoS on the µTP receive
            // surface).
            let len = payload.len();
            let caps_ok = self.reorder.len() < self.cfg.reorder_packets
                && self.reorder_bytes + len <= self.cfg.recv_buffer as usize;
            let pos = if caps_ok {
                self.reorder
                    .partition_point(|(s, _)| packet::seq_lt(*s, seq))
            } else {
                0
            };
            let dup = pos < self.reorder.len() && self.reorder[pos].0 == seq;
            let ledger_ok = caps_ok && !dup && recv_ledger_claim(len);
            if ledger_ok {
                let data = (!payload.is_empty()).then(|| Bytes::copy_from_slice(payload));
                self.reorder_bytes += len;
                self.reorder.insert(pos, (seq, data));
            } else if !caps_ok {
                debug!(target: LOG_TARGET, seq, "reorder overflow; dropped");
            } else if !dup {
                // Global receive ledger full: drops were previously
                // unobserved; debug level (high-frequency path, no warn;
                // the peer's retransmission self-heals the loss).
                debug!(target: LOG_TARGET, seq,
                    used = RECV_LEDGER.load(std::sync::atomic::Ordering::Relaxed),
                    "reorder dropped: global recv ledger exhausted");
            }
        }
        // Read EOF: eof and all earlier data delivered in order (BEP-29
        // ST_FIN semantics: "wait for packets that might still be
        // missing").
        if let Some(eof) = self.eof_pkt
            && packet::seq_ge(self.ack_nr, eof)
        {
            self.read_eof = true;
        }
        self.send_ack().await;
    }

    /// ST_STATE reply; carries a sack only when a gap exists (BEP-29
    /// §"Selective ACK": "only sent when at least one sequence number
    /// was skipped").
    async fn send_ack(&mut self) {
        let sack = self.build_sack();
        let seq = self.seq_nr; // no payload, seq_nr unchanged (BEP-29 §"type" ST_STATE).
        let _ = self.send_state(seq, self.ack_nr, sack.as_deref()).await;
    }

    fn build_sack(&self) -> Option<Vec<u8>> {
        if self.reorder.is_empty() {
            return None;
        }
        let received: Vec<u16> = self.reorder.iter().map(|(s, _)| *s).collect();
        packet::build_sack_mask(self.ack_nr, &received, self.cfg.sack_max_bytes)
    }

    async fn send_state(
        &mut self,
        seq_nr: u16,
        ack_nr: u16,
        sack: Option<&[u8]>,
    ) -> Result<(), UtpError> {
        let wire = self.build_wire(
            PacketType::State,
            seq_nr,
            ack_nr,
            &[],
            sack,
            self.conn_id_send,
        );
        self.send_wire(wire).await
    }

    async fn send_reset(&mut self) -> Result<(), UtpError> {
        let seq = self.seq_nr;
        let wire = self.build_wire(
            PacketType::Reset,
            seq,
            self.ack_nr,
            &[],
            None,
            self.conn_id_send,
        );
        self.send_wire(wire).await
    }

    fn build_wire(
        &self,
        ty: PacketType,
        seq_nr: u16,
        ack_nr: u16,
        payload: &[u8],
        sack: Option<&[u8]>,
        conn_id: u16,
    ) -> BytesMut {
        let now = super::now_us();
        let h = Header {
            packet_type: ty,
            extension: 0, // overwritten by encode
            connection_id: conn_id,
            timestamp_micros: now as u32,
            // No sample must encode as 0 (BEP-29
            // §"timestamp_difference_microseconds"); reply_micro can be
            // negative (clock skew), encoded with i32 bit-pattern
            // wraparound.
            timestamp_diff_micros: self.reply_micro.unwrap_or(0) as i32 as u32,
            wnd_size: self.advertised_wnd(),
            seq_nr,
            ack_nr,
        };
        packet::encode(&h, sack, payload)
    }

    async fn send_wire(&mut self, wire: BytesMut) -> Result<(), UtpError> {
        // Sending resets the timeout counter (BEP-29 §"timeouts": "Every
        // time a socket sends or receives a packet, it updates its
        // timeout counter").
        self.last_activity_us = super::now_us();
        self.ch
            .out
            .send(OutboundPacket {
                to: self.addr,
                data: wire.freeze(),
            })
            .await
            .map_err(|_| UtpError::SinkClosed)
    }

    /// Our advertised window ≈ receive buffer - reorder usage - pending
    /// not yet taken (pending actual bytes + data-channel occupancy x
    /// packet-cap approximation — BEP-29 §"wnd_size": "the number of
    /// bytes left in the socket's receive buffer"). Safety hardening:
    /// pending originally went uncounted — a peer could resend without
    /// bound after our ack and the to-be-delivered queue would grow
    /// without bound (OOM).
    fn advertised_wnd(&self) -> u32 {
        let queued = self
            .cfg
            .data_queue_packets
            .saturating_sub(self.ch.data.capacity());
        let approx_pending = queued * self.cfg.max_packet_payload;
        ((self.cfg.recv_buffer as usize)
            .saturating_sub(self.reorder_bytes)
            .saturating_sub(self.pending_bytes)
            .saturating_sub(approx_pending)) as u32
    }

    // ---- Send pump (BEP-29 §"overview" window rule) ----

    /// Packetizes new data and sends every ready entry.
    async fn pump(&mut self) {
        if !matches!(self.state, State::Connected | State::Fin) {
            return;
        }
        // Queue the FIN only after all data is packetized (BEP-29
        // §"type" ST_FIN: "This is the last packet."). The write channel
        // must also be drained — ctrl and write are two channels, and
        // writes issued before poll_shutdown may still sit in the
        // channel; queueing early would let the FIN overtake data.
        if self.fin_requested
            && self.fin_seq.is_none()
            && self.write_buf.is_empty()
            && (!self.write_open || self.ch.write.is_empty())
        {
            let seq = self.seq_nr;
            self.seq_nr = seq.wrapping_add(1);
            self.fin_seq = Some(seq);
            self.outq.push_back(OutPkt {
                seq,
                payload: Bytes::new(),
                kind: Kind::Fin,
                sent_at: None,
                transmissions: 0,
                loss_retransmitted: false,
            });
            if self.state == State::Connected {
                self.state = State::Fin;
            }
        }
        loop {
            let sent = self.send_new_entries().await;
            // Packetize new data when the window allows; with a collapsed
            // window and zero in-flight, let one probe packet through
            // (see send_new_entries — BEP-29 §"timeouts"/§"overview"
            // MAY).
            let mut packed = false;
            if !self.write_buf.is_empty() {
                let win = self.effective_window();
                let n = self.write_buf.len().min(self.cfg.max_packet_payload);
                let probe = self.cur_window == 0
                    && self.outq.is_empty()
                    && self.ledbat.max_window() < (packet::HEADER_LEN + n) as f64;
                if probe || self.cur_window + packet::HEADER_LEN as u32 + n as u32 <= win {
                    let chunk = self.write_buf.split_to(n).freeze();
                    let seq = self.seq_nr;
                    self.seq_nr = seq.wrapping_add(1);
                    self.outq.push_back(OutPkt {
                        seq,
                        payload: chunk,
                        kind: Kind::Data,
                        sent_at: None,
                        transmissions: 0,
                        loss_retransmitted: false,
                    });
                    packed = true;
                }
            }
            if !sent && !packed {
                break;
            }
        }
    }

    /// Sends every unsent entry in outq: handshake packets bypass the
    /// window gate (no peer window exists to consult during connection
    /// setup); data/FIN follow "cur_window + packet_size <=
    /// min(max_window, wnd_size)" (BEP-29 §"overview"). Exception (the
    /// same section's MAY clause + §"timeouts"): when max_window is
    /// already below one packet size and nothing is in flight, let one
    /// probe packet through — after a timeout squeezes the window to
    /// 150B, "This allows it to send one more packet, and this is how
    /// the socket gets started again if the window size goes down to
    /// zero". Returns whether anything was sent.
    async fn send_new_entries(&mut self) -> bool {
        let mut sent_any = false;
        let mut idx = 0;
        while idx < self.outq.len() {
            let e = &self.outq[idx];
            if e.sent_at.is_some() {
                idx += 1;
                continue;
            }
            let size = e.wire_size();
            let handshake = e.kind == Kind::Syn;
            let probe =
                !handshake && self.cur_window == 0 && self.ledbat.max_window() < size as f64;
            if !handshake && !probe && self.cur_window + size > self.effective_window() {
                break; // FIFO: later entries are even less likely to fit.
            }
            let (seq, payload, kind) = (e.seq, e.payload.clone(), e.kind);
            let e = &mut self.outq[idx];
            e.sent_at = Some(super::now_us());
            e.transmissions += 1;
            self.cur_window += size;
            // BEP-29 §"type" ST_SYN: the SYN carries rcv_conn_id; all
            // later packets (other retransmits included) use conn_id+1;
            // SYN retransmissions also use the original id.
            let conn_id = if kind == Kind::Syn {
                self.conn_id_recv
            } else {
                self.conn_id_send
            };
            let wire = self.build_wire(
                match kind {
                    Kind::Syn => PacketType::Syn,
                    Kind::Data => PacketType::Data,
                    Kind::Fin => PacketType::Fin,
                },
                seq,
                self.ack_nr,
                &payload,
                None,
                conn_id,
            );
            let _ = self.send_wire(wire).await;
            sent_any = true;
            idx += 1;
        }
        sent_any
    }

    /// Send window = min(max_window, peer wnd) (BEP-29 §"overview").
    fn effective_window(&self) -> u32 {
        self.ledbat.max_window().min(self.their_wnd as f64) as u32
    }

    // ---- Timeout scan round (BEP-29 §"timeouts") ----

    async fn scan_round(&mut self) {
        if self.closed {
            return;
        }
        let now = super::now_us();
        let timeout_us = self.rtt.timeout().as_micros() as u64;
        // The give-up check must precede the outq early exit (safety
        // hardening: it used to sit at the end of the retransmit round,
        // short-circuited by the `outq.is_empty()` early return — idle
        // connections with no unacknowledged packets (half-open SynRecv
        // accepts, fully acknowledged quiet streams) could never reach
        // the give-up/guard, letting a remote pile up connections and
        // driver tasks without bound).
        //
        // (1) The peer went fully silent (no inbound packet at all for
        // max_idle) => give up (implementation-local threshold; the
        // per-round semantics and the doubling = BEP-29 §"timeouts").
        if now.saturating_sub(self.last_recv) >= self.max_idle_us() {
            warn!(target: LOG_TARGET, to = %self.addr, idle_rounds = self.idle_rounds, "uTP peer unresponsive; giving up");
            self.shutdown(Some(UtpError::Timeout {
                rounds: self.idle_rounds,
            }));
            return;
        }
        // (2) SYN_RECV guard: the handshake is incomplete and there are
        // no unacknowledged entries to time; guard the half-open accept
        // by the no-activity span, retransmit ST_STATE on the timeout
        // round (a retransmission of the same SYN-ACK: seq does not
        // advance), and (1) gives up when silence exceeds the limit.
        if self.state == State::SynRecv {
            let idle = now.saturating_sub(self.last_activity_us);
            if idle >= timeout_us {
                let seq = self.seq_nr;
                let syn_seq = self.ack_nr;
                let _ = self.send_state(seq, syn_seq, None).await;
            }
            return; // SynRecv has no outbound queue to scan.
        }
        // Round trigger: the span since the last send/receive (or last
        // retransmit round) exceeds the current timeout; consecutive
        // silent rounds double the round interval per BEP-29 §"timeouts"
        // ("For every packet consecutive subsequent packet that times
        // out, the timeout is doubled." — capped at x16; recovery is
        // driven by the peer's traffic returning).
        let gate_us = timeout_us << self.idle_rounds.min(4);
        let last_reset = self.last_activity_us.max(self.last_timeout_event);
        if self.outq.is_empty() || now.saturating_sub(last_reset) < gate_us {
            return;
        }
        // A retransmit-round trigger is one timeout event: when no
        // inbound packet arrived between this round and the last, treat
        // it as consecutive timeouts per BEP-29 §"timeouts" (double the
        // next interval + squeeze the window to 150B); if the peer is
        // still talking (duplicate acks etc.), do not double or squeeze
        // — the connection is alive, individual packets are just lost.
        let saw_peer_traffic = self.last_recv > self.last_timeout_event;
        self.last_timeout_event = now;
        if !saw_peer_traffic {
            self.idle_rounds = (self.idle_rounds + 1).min(4);
            self.rtt_backoff_shift = self.idle_rounds;
            self.ledbat.on_timeout();
        } else {
            self.idle_rounds = 0;
            self.rtt_backoff_shift = 0;
        }
        // Resend expired entries (sent_at + timeout <= now; retransmits
        // bypass the send-window gate — the window may be blocked
        // precisely because loss feedback is missing, and
        // retransmission is the only way to open it again).
        let expired: Vec<u16> = self
            .outq
            .iter()
            .filter(|e| {
                e.sent_at
                    .is_some_and(|t| now.saturating_sub(t) >= timeout_us)
            })
            .map(|e| e.seq)
            .collect();
        for seq in &expired {
            if let Some(e) = self.outq.iter_mut().find(|e| e.seq == *seq) {
                e.sent_at = Some(now);
                e.transmissions += 1;
                e.loss_retransmitted = true;
            }
            self.resend(*seq).await;
        }
    }

    async fn resend(&mut self, seq: u16) {
        let Some(e) = self.outq.iter().find(|e| e.seq == seq) else {
            return;
        };
        let payload = e.payload.clone();
        let (ty, conn_id) = match e.kind {
            Kind::Syn => (PacketType::Syn, self.conn_id_recv),
            Kind::Data => (PacketType::Data, self.conn_id_send),
            Kind::Fin => (PacketType::Fin, self.conn_id_send),
        };
        let wire = self.build_wire(ty, seq, self.ack_nr, &payload, None, conn_id);
        let _ = self.send_wire(wire).await;
    }

    // ---- Teardown ----

    /// Close decision: FIN converged in both directions (our FIN
    /// acknowledged + read-side EOF / read channel closed); and the
    /// half-close read-side EOF presentation — once eof and all earlier
    /// data are delivered, drain the downstream channel (`close()`
    /// keeps already-queued messages, the reader sees EOF after
    /// draining, the write side keeps working — BEP-29 §"type" ST_FIN
    /// half-close semantics).
    async fn maybe_finish(&mut self) {
        if self.closed {
            return;
        }
        if self.read_eof && self.pending.is_empty() {
            let _ = self.ch.err.send(CloseState::ReadEof);
        }
        // Graceful close requires pending fully handed to the downstream
        // channel (otherwise tail data is lost).
        if self.fin_acked && self.read_eof && self.pending.is_empty() {
            self.shutdown(None);
        }
    }

    /// Teardown: notify the terminal state, remove the route, close the
    /// channels (dropping the senders -> reader sees EOF after
    /// draining).
    fn shutdown(&mut self, err: Option<UtpError>) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = self.ch.err.send(match err {
            Some(e) => CloseState::Abnormal(e),
            None => CloseState::Graceful,
        });
        if let Some((table, key)) = self.dereg.take()
            && let Ok(mut t) = table.lock()
        {
            t.remove(&key);
        }
        debug!(target: LOG_TARGET, to = %self.addr, "uTP connection closed");
    }
}

#[cfg(test)]
mod bt_recv_ledger {
    use super::*;

    /// Receive-ledger primitives + the 64MiB cap anchor.
    #[test]
    fn claim_release_primitives_and_cap_anchor() {
        assert_eq!(RECV_LEDGER_CAP, 64 * 1024 * 1024);
        let base = recv_ledger_used();
        assert!(recv_ledger_claim(1024), "claim within the cap");
        assert_eq!(recv_ledger_used(), base + 1024);
        // Fill to cap-1 -> a 2B claim is rejected and rolled back.
        recv_ledger_release(0); // zero-release no-op anchor
        let fill = RECV_LEDGER_CAP - 1 - (recv_ledger_used() - base);
        assert!(fill > 0, "parallel-test usage must leave headroom");
        assert!(recv_ledger_claim(fill as usize), "filled to cap-1");
        assert!(!recv_ledger_claim(2), "over-cap claim denied");
        assert_eq!(
            recv_ledger_used(),
            base + RECV_LEDGER_CAP - 1,
            "denial rolls back"
        );
        recv_ledger_release(fill as usize + 1024);
        assert_eq!(recv_ledger_used(), base, "release returns to baseline");
    }
}

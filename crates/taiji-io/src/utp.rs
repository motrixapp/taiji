//! `taiji_io::utp` — uTP transport (BEP-29, the BitTorrent uTorrent
//! transport protocol).
//!
//! - [`packet`]: 20-byte v1 big-endian header + extension chain + Selective
//! ACK bitmap codec (protocol facts cite BEP-29; aria2 has no uTP
//! implementation, so BEP-29 is the sole reference).
//! - [`ledbat`]: LEDBAT congestion control (CCONTROL_TARGET = 100ms, gain
//! formula, slow start, loss halving) + RTT/timeout estimation
//! (BEP-29 / RFC 6817 / RFC 5681).
//! - [`conn`]: connection driver task — Syn/SynRecv/Connected/Fin/Closed
//! state machine, in-order delivery, SACK selective retransmit, timeout
//! retransmit rounds, FIN/RESET paths.
//! - [`listener`]: `UtpListener` — consumes the uTP inbound channel from
//! [`crate::udp_demux`] and dispatches by (peer address, conn_id); a SYN
//! creates an inbound connection pushed onto the accept queue; this layer
//! only produces [`UtpStream`] (wiring into the bt peer accept path
//! belongs to core).
//!
//! [`UtpStream`] implements `AsyncRead + AsyncWrite`, so `PeerTransport`
//! gains an implementation without making PeerTask TCP/uTP aware.
//!
//! Back-pressure and concurrency:
//! - All channels are bounded: per-connection inbound packets mpsc(64),
//! outbound packets mpsc(64) (merged into the demux outbound
//! single-writer channel), app-data uplink/downlink mpsc(64), accept
//! queue mpsc(64). A full inbound packet queue drops — UDP best-effort
//! semantics, with reliability backstopped by retransmission.
//! - Lock-free module overall (the listener connection table uses a std
//! Mutex and is never held across an await).
//! - Retransmission is a periodic scan round, period = clamp(RTT/2) (see
//! [`UtpConfig::retrans_scan_period`]); timeout/doubling parameters come
//! from [`ledbat::Rtt`].
//!
//! Rate-limit cooperation: `Arc<SpeedLimiter>` permits are awaited on the
//! PeerTask read path, which naturally pushes back on the uTP send window
//! (app-data uplink channel fills -> the driver stops sending ->
//! cur_window stays). This layer never references the limiter directly.
//!
//! Public surface: [`packet::{decode, encode, Header, PacketType, Sack}`]
//! (the surface fuzzed by the `utp_header` target), [`UtpConfig`],
//! [`listener::{spawn_with_demux, spawn_with_sink, UtpListenerHandle}`],
//! and [`UtpStream`].
//!
//! Upstream anchor mapping: docs/design/io.md
//!
pub mod ledbat;
pub mod listener;
pub mod packet;

/// Connection driver (internal part; exposed upward via [`listener`]'s
/// [`UtpStream`]/accept surface; pub(crate) keeps the internal state
/// machine out of the public API).
pub(crate) mod conn;

#[cfg(test)]
mod tests;

// UtpConnectHalf: outbound connect half, dialed by the engine; the
// consumer task and the accept-delivery task share one source (see the
// listener module docs).
pub use listener::{UtpConnectHalf, UtpListenerHandle, UtpStream};

use std::io;
use std::net::SocketAddr;

use thiserror::Error;

pub use crate::udp_demux::{InboundPacket, OutboundPacket};

/// uTP inbound payload cap (bytes): the receive-side validation threshold,
/// decoupled from the send-side [`UtpConfig::max_packet_payload`] (a send
/// chunking parameter that only bounds local outbound writes).
///
/// Derivation: 1500 (ethernet MTU) - 20 (IPv4 header) - 8 (UDP header) -
/// 20 (uTP v1 header) = 1452, the largest ST_DATA payload that can legally
/// arrive over ethernet. Reference libutp `get_packet_size() = mtu - 20`
/// (utp_internal.cpp; 20 = uTP header): a conservative initial full size of
/// 1435, then 1452 after ethernet path MTU discovery. libtorrent,
/// Transmission, and uTorrent all send full-size ST_DATA payloads > 1400,
/// so rejecting inbound data by the send parameter would skip the ack,
/// trap the peer in a retransmit loop, and stall the connection until the
/// idle give-up (an interop breaker); the receive criterion must therefore
/// be independent of the send parameter.
///
/// Payloads above this value are still dropped (hardening: truly oversized
/// — malformed/flood packets that cannot legally arrive under a 1500-byte
/// ethernet MTU; the derivation above is what separates them from the
/// reference implementations' legal full-size packets). IPv6 jumbograms get
/// no slack: the real-world uTP ecosystem (libutp and derivatives) caps path
/// MTU discovery at ethernet 1500; no jumbo-frame form exists.
pub(crate) const MAX_INBOUND_PAYLOAD: usize = 1452;

/// uTP connection state (Syn/SynRecv/Connected/Fin/Closed; the mapping to
/// the BEP-29 "connection setup" CS_* states is noted per variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Initiator has sent ST_SYN (BEP-29 CS_SYN_SENT).
    SynSent,
    /// Acceptor has received ST_SYN and is about to send / has sent
    /// ST_STATE (BEP-29 CS_SYN_RECV).
    SynRecv,
    /// Handshake complete (BEP-29 CS_CONNECTED).
    Connected,
    /// FIN phase: local ST_FIN sent awaiting confirmation, or the peer's
    /// eof_pkt has not finished delivering (BEP-29 CS_FIN_SENT semantics;
    /// see the "type" section's ST_FIN eof_pkt note).
    Fin,
    /// Terminated (FIN done both ways / ST_RESET / retransmit give-up / local close).
    Closed,
}

/// uTP protocol/connection errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UtpError {
    /// Packet shorter than the 20-byte v1 header (BEP-29 "header format").
    #[error("uTP packet shorter than 20-byte v1 header")]
    Truncated,
    /// Not v1 (BEP-29 "version": "The current version is 1.").
    #[error("unsupported uTP version {0} (only version 1 is defined)")]
    Version(u8),
    /// Undefined packet type (BEP-29 "type" defines only 0-4).
    #[error("undefined uTP packet type {0}")]
    Type(u8),
    /// Malformed extension chain (BEP-29 "extension" / "Selective ACK" len rules).
    #[error("malformed uTP extension chain")]
    Extension,
    /// Peer forced termination with ST_RESET (BEP-29 "type" ST_RESET).
    #[error("connection reset by peer (uTP ST_RESET)")]
    Reset,
    /// Too many consecutive retransmit rounds; give up (the round count is
    /// a local parameter; per-round timeout semantics are BEP-29 "timeouts").
    #[error("uTP connection timed out (gave up after {rounds} retransmission rounds)")]
    Timeout {
        /// Consecutive timeout rounds that have occurred.
        rounds: u32,
    },
    /// Connection closed (FIN completed / use after local close).
    #[error("uTP connection closed")]
    Closed,
    /// Outbound packet channel closed (demux/listener already exited).
    #[error("uTP outbound channel closed")]
    SinkClosed,
}

impl UtpError {
    /// Map to [`io::ErrorKind`] (for the AsyncRead/AsyncWrite error surface).
    pub fn io_kind(&self) -> io::ErrorKind {
        match self {
            UtpError::Reset => io::ErrorKind::ConnectionReset,
            UtpError::Timeout { .. } => io::ErrorKind::TimedOut,
            UtpError::Closed | UtpError::SinkClosed => io::ErrorKind::BrokenPipe,
            UtpError::Truncated
            | UtpError::Version(_)
            | UtpError::Type(_)
            | UtpError::Extension => io::ErrorKind::InvalidData,
        }
    }
}

impl From<UtpError> for io::Error {
    fn from(e: UtpError) -> Self {
        io::Error::new(e.io_kind(), e)
    }
}

/// uTP connection configuration.
///
/// Unless a value is attributed to BEP-29/RFC, it is an implementation-local
/// parameter (protocol constants must cite their source; anything without
/// one is explicitly marked implementation-local and must not pose as a
/// protocol fact).
#[derive(Debug, Clone)]
pub struct UtpConfig {
    /// Max payload per packet (bytes) — a send-side chunking parameter only
    /// (write_buf packing granularity, approximate channel accounting).
    /// The inbound cap is the independent [`MAX_INBOUND_PAYLOAD`] receive
    /// criterion, unrelated to the peer's send parameter. Implementation
    /// local; BEP-29 "packet sizes" sets only the 150B floor and the
    /// direction "large packets for high speed, small for slow links".
    pub max_packet_payload: usize,
    /// Minimum packet size (BEP-29 "timeouts"/"packet sizes": 150 bytes).
    pub min_packet_size: u32,
    /// Local receive buffer (bytes) — the basis for the advertised wnd_size
    /// (BEP-29 "wnd_size": "the number of bytes left in the socket's
    /// receive buffer"; implemented as an out-of-order buffer occupancy
    /// approximation, see the conn comments).
    pub recv_buffer: u32,
    /// Out-of-order reorder queue cap (packets, local; overflow drops rely on peer retransmits).
    pub reorder_packets: usize,
    /// Per-connection inbound packet channel capacity (frozen at 64).
    pub inbound_channel: usize,
    /// Per-connection outbound packet channel capacity (local; merges into demux outbound 1024).
    pub outbound_channel: usize,
    /// App-data uplink channel capacity (packets, local).
    pub write_queue_packets: usize,
    /// App-data downlink channel capacity (packets, local).
    pub data_queue_packets: usize,
    /// Accept queue capacity (local; a full queue drops SYN, peer SYN retransmit backstops).
    pub accept_queue: usize,
    /// Selective ACK bitmap max bytes (local; BEP-29 sets no cap).
    pub sack_max_bytes: usize,
    /// Give-up threshold: abandon the connection after this long with no
    /// inbound packet at all (local; per-round timeout semantics and
    /// doubling are BEP-29 "timeouts" — giving up per consecutive round
    /// would kill live connections under sustained loss, since duplicate
    /// acks keep resetting the per-round timer).
    pub max_idle_secs: u64,
    /// Global cap on routing-table entries / concurrent connections (local,
    /// hardening — without a cap a remote peer could pile up half-open
    /// connections and driver tasks indefinitely with forged SYNs; over the
    /// cap, SYNs are dropped (peer SYN retransmit backstops) and outbound
    /// connect fails immediately).
    pub max_connections: usize,
    /// Retransmit scan-round period = clamp(RTT/2, min, max).
    pub retrans_scan_min: std::time::Duration,
    pub retrans_scan_max: std::time::Duration,
    /// LEDBAT parameters.
    pub ledbat: ledbat::LedbatConfig,
}

impl Default for UtpConfig {
    fn default() -> Self {
        Self {
            max_packet_payload: 1400,
            min_packet_size: ledbat::MIN_PACKET_SIZE,
            recv_buffer: 256 * 1024,
            reorder_packets: 1024,
            inbound_channel: 64,
            outbound_channel: 64,
            write_queue_packets: 64,
            data_queue_packets: 64,
            accept_queue: 64,
            sack_max_bytes: 16,
            max_idle_secs: 120,
            max_connections: 512,
            retrans_scan_min: std::time::Duration::from_millis(5),
            retrans_scan_max: std::time::Duration::from_millis(500),
            ledbat: ledbat::LedbatConfig::default(),
        }
    }
}

impl UtpConfig {
    /// Retransmit scan-round period (RTT/2, clamped to the configured range).
    pub fn retrans_scan_period(&self, rtt_ms: f64) -> std::time::Duration {
        let half = std::time::Duration::from_millis((rtt_ms / 2.0).max(0.0).round() as u64);
        half.max(self.retrans_scan_min).min(self.retrans_scan_max)
    }
}

/// Routing key: peer address + connection ID (BEP-29 "connection_id": each
/// socket has one ID per direction, "Connections are identified by their
/// conn_id header"). Inbound packets look up the table by the header
/// conn_id: the ID the peer sends with = our receive ID.
pub type ConnKey = (SocketAddr, u16);

/// Monotonic clock: microseconds since process start (BEP-29
/// "timestamp_microseconds" wants high resolution close to send time; the
/// 32-bit wire field is truncated in the packet layer).
pub(crate) fn now_us() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_micros() as u64
}

/// Wrapping subtraction of 32-bit microsecond timestamps (peer now - local
/// timestamp; 32-bit us wraps about every 71.6 minutes; the difference uses
/// i32 wraparound semantics).
pub(crate) fn wrapping_diff_us(later: u32, earlier: u32) -> i64 {
    (later.wrapping_sub(earlier)) as i32 as i64
}

#[cfg(test)]
mod root_tests {
    use super::*;

    #[test]
    fn error_io_kind_mapping() {
        assert_eq!(UtpError::Reset.io_kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(
            UtpError::Timeout { rounds: 3 }.io_kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(UtpError::Closed.io_kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(UtpError::Version(2).io_kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn retrans_scan_period_clamped() {
        let cfg = UtpConfig::default();
        assert_eq!(cfg.retrans_scan_period(0.0), cfg.retrans_scan_min);
        assert_eq!(
            cfg.retrans_scan_period(4.0),
            std::time::Duration::from_millis(2).max(cfg.retrans_scan_min)
        );
        let long = cfg.retrans_scan_period(10_000.0);
        assert_eq!(
            long, cfg.retrans_scan_max,
            "clamped when RTT/2 exceeds the cap (SPEC §6.5 round)"
        );
    }

    #[test]
    fn wrapping_us_diff() {
        assert_eq!(wrapping_diff_us(100, 40), 60);
        // Wraparound: earlier near 2^32, later small — i32 wraparound gives a positive diff.
        assert_eq!(wrapping_diff_us(10, u32::MAX - 5), 16);
        assert_eq!(wrapping_diff_us(40, 100), -60);
    }
}

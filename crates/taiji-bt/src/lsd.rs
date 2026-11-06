//! LSD / Local Service Discovery (BEP14; multicast 239.192.152.143:6771).
//!
//! Mechanism mirrors aria2's LPD implementation: a `BT-SEARCH * HTTP/1.1`
//! announce (Host/Port/Infohash headers, trailing `\r\n\r\n\r\n`) is sent
//! to the multicast group; receivers parse the header block and emit
//! PeerFound. An announce fires when the per-infohash timer has expired
//! (default 5 min, `LpdMessageDispatcher.h`); after 5 consecutive send
//! failures the timer resets (`LpdDispatchMessageCommand.cc`). Multicast
//! setup is TTL=1 / loop=1 (`BtSetup.cc`). Private torrents disable LPD
//! (BEP27; `BtSetup.cc` initializes only when `!privateTorrent`) — that
//! gate lives in the session actor task layer
//! (`taiji-core/src/session/actor/tasks.rs` skips announce registration
//! for `metainfo.private`).
//!
//! `bt-lsd` defaults to **false** (aria2 `PREF_BT_ENABLE_LPD` likewise).
//! Implementation notes (shared socket, REUSEADDR/REUSEPORT rationale) and
//! the full upstream anchor list live in `docs/design/peer-protocol.md`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::warn;

use thiserror::Error;

/// LPD multicast address (aria2 `BtConstants.h`).
pub const LPD_MULTICAST_ADDR: &str = "239.192.152.143";
/// LPD multicast port (aria2 `BtConstants.h`).
pub const LPD_MULTICAST_PORT: u16 = 6771;
/// Default announce interval (aria2 `LpdMessageDispatcher.h` default
/// argument `5_min`).
pub const DEFAULT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Consecutive-send-failure cap: at >= 5 failures the timer resets (aria2
/// `LpdDispatchMessageCommand.cc`).
pub const MAX_SEND_FAILURES: u32 = 5;

/// LSD construction error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LsdError {
    #[error("socket init: {0}")]
    Socket(String),
}

/// Build a BT-SEARCH announce packet (byte-for-byte aria2
/// `createLpdRequest`, `LpdMessageDispatcher.cc`; infohash = 40 lowercase
/// hex chars).
pub fn build_announce(
    info_hash: &[u8; 20],
    port: u16,
    multicast_addr: &str,
    multicast_port: u16,
) -> Vec<u8> {
    let mut hex = String::with_capacity(40);
    for b in info_hash {
        hex.push_str(&format!("{b:02x}"));
    }
    format!(
        "BT-SEARCH * HTTP/1.1\r\nHost: {multicast_addr}:{multicast_port}\r\nPort: {port}\r\nInfohash: {hex}\r\n\r\n\r\n",
    )
    .into_bytes()
}

/// A received LPD message (aria2 `LpdMessage`: peer + infohash;
/// `LpdMessageReceiver.cc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpdMessage {
    pub info_hash: [u8; 20],
    /// Source address + the port declared by the Port header
    /// (`LpdMessageReceiver.cc`).
    pub peer: SocketAddr,
}

/// Parse a BT-SEARCH packet (mirrors `LpdMessageReceiver.cc`): invalid or
/// incomplete packets return None (aria2 skips them with continue).
pub fn parse_packet(data: &[u8], from: SocketAddr) -> Option<LpdMessage> {
    // info_hash propagates via `?` (None = invalid packet, see the Infohash
    // branch below).
    // The UDP datagram must contain a complete HTTP header block.
    let head_end = data.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&data[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    // Request line: BT-SEARCH method (BEP14; aria2's SERVER_PARSER accepts
    // this form).
    let request_line = lines.next()?;
    if !request_line.starts_with("BT-SEARCH") {
        return None;
    }
    let mut info_hash = None;
    let mut port = 0u64;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            // Infohash must be 40 hex chars. The ASCII-hex precheck comes
            // first: a multi-byte UTF-8 string can be 40 bytes long, but
            // the byte slicing below would then land inside a character
            // boundary and panic (found by the fuzz udp/lsd target) —
            // non-ASCII is never a legal infohash, so reject directly.
            "infohash" => {
                if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                let mut h = [0u8; 20];
                for (i, b) in h.iter_mut().enumerate() {
                    *b = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
                }
                info_hash = Some(h);
            }
            // Port: numeric, <= 65535, != 0.
            "port" => {
                port = value.parse().ok()?;
            }
            _ => {}
        }
    }
    if port == 0 || port > u16::MAX as u64 {
        return None;
    }
    let info_hash = info_hash?;
    let peer = SocketAddr::new(from.ip(), port as u16);
    Some(LpdMessage { info_hash, peer })
}

/// Dispatcher timer state (mirrors `LpdMessageDispatcher`: timer/interval +
/// the tryCount semantics of `LpdDispatchMessageCommand`).
#[derive(Debug)]
pub struct DispatchState {
    interval: Duration,
    /// `None` = Timer::zero() (aria2's initial value; infinitely far from
    /// any wallclock -> immediately ready).
    last_sent: Option<Instant>,
    try_count: u32,
}

/// Outcome of one LSD announce send attempt (the
/// `LpdDispatchMessageCommand` success/error split).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The datagram was fully written to the socket.
    Sent,
    /// The send errored, or the written length did not cover the whole
    /// packet (a truncated datagram counts as failed at the call site).
    Failed,
}

impl DispatchState {
    pub fn new(interval: Duration) -> Self {
        DispatchState {
            interval,
            last_sent: None,
            try_count: 0,
        }
    }

    /// `isAnnounceReady` (`LpdMessageDispatcher.cc`; the Timer::zero
    /// initial value makes the first packet immediately ready).
    pub fn is_announce_ready(&self, now: Instant) -> bool {
        match self.last_sent {
            None => true,
            Some(at) => now.saturating_duration_since(at) >= self.interval,
        }
    }

    /// `resetAnnounceTimer`.
    pub fn reset_timer(&mut self, now: Instant) {
        self.last_sent = Some(now);
        self.try_count = 0;
    }

    /// Bookkeeping for one send attempt (mirrors
    /// `LpdDispatchMessageCommand.cc`): success/error -> reset + try=0;
    /// failure -> try+1, and at try >= 5 -> reset + try=0 (waits for the
    /// next cycle).
    pub fn on_send_result(&mut self, outcome: SendOutcome, now: Instant) {
        if outcome == SendOutcome::Sent || self.try_count + 1 >= MAX_SEND_FAILURES {
            self.reset_timer(now);
        } else {
            self.try_count += 1;
        }
    }
}

/// LSD service commands (per-torrent announce requests; private torrents
/// are filtered out by the caller's gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsdCommand {
    /// Start/refresh periodic announces for this infohash (port = our BT
    /// port).
    Announce { info_hash: [u8; 20], port: u16 },
    /// Stop announces for this infohash (task ended).
    Withdraw { info_hash: [u8; 20] },
}

/// LSD discovery event (the engine consumes it -> initiates peer
/// connections; connection gating lives in the engine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsdEvent {
    PeerFound {
        info_hash: [u8; 20],
        peer: SocketAddr,
    },
}

/// LSD configuration.
#[derive(Debug, Clone)]
pub struct LsdConfig {
    /// `bt-lsd` switch (default **false**); when false, [`spawn`] returns
    /// `Ok(None)` (no socket, no resources held).
    pub enabled: bool,
    /// Announce interval (default 5 min, `LpdMessageDispatcher.h`).
    pub interval: Duration,
    pub multicast_addr: String,
    pub multicast_port: u16,
    /// Multicast TTL=1 (BtSetup.cc).
    pub multicast_ttl: u8,
    /// Multicast loop=1 (BtSetup.cc; needed for multiple engines on one
    /// host to hear each other).
    pub multicast_loop: bool,
    /// Whether to join the multicast group (default true; unit tests over
    /// unicast set it to false).
    pub join_multicast: bool,
}

impl Default for LsdConfig {
    fn default() -> Self {
        LsdConfig {
            enabled: false,
            interval: DEFAULT_ANNOUNCE_INTERVAL,
            multicast_addr: LPD_MULTICAST_ADDR.to_string(),
            multicast_port: LPD_MULTICAST_PORT,
            multicast_ttl: 1,
            multicast_loop: true,
            join_multicast: true,
        }
    }
}

/// LSD service subscriber cap (each subscriber channel is bounded at 16;
/// on overflow the oldest subscriber is evicted — best-effort discovery
/// semantics with bounded backpressure).
const MAX_SUBSCRIBERS: usize = 8;

/// LSD handle (command channel bounded at 16).
///
/// Consumer side: events fan out to **multiple subscribers** — one
/// session-level service (aria2's receiver is a process-level singleton,
/// same shape as BtSetup.cc) plus one subscription receiver per magnet task
/// (consumers each hold one via [`LsdHandle::subscribe`]).
#[derive(Debug, Clone)]
pub struct LsdHandle {
    cmd_tx: mpsc::Sender<LsdCommand>,
    subs: Arc<std::sync::Mutex<Vec<mpsc::Sender<LsdEvent>>>>,
}

impl LsdHandle {
    pub async fn announce(&self, info_hash: [u8; 20], port: u16) -> Result<(), LsdError> {
        self.cmd_tx
            .send(LsdCommand::Announce { info_hash, port })
            .await
            .map_err(|_| LsdError::Socket("lsd service closed".into()))
    }

    pub async fn withdraw(&self, info_hash: [u8; 20]) -> Result<(), LsdError> {
        self.cmd_tx
            .send(LsdCommand::Withdraw { info_hash })
            .await
            .map_err(|_| LsdError::Socket("lsd service closed".into()))
    }

    /// Open a discovery-event subscription (bounded 16; events are dropped
    /// when the queue is full or the subscriber goes away — best effort).
    /// The std Mutex only guards Vec add/remove and try_send (synchronous,
    /// never held across an await).
    pub fn subscribe(&self) -> mpsc::Receiver<LsdEvent> {
        let (tx, rx) = mpsc::channel(16);
        let mut subs = crate::lock(&self.subs);
        if subs.len() >= MAX_SUBSCRIBERS {
            subs.remove(0); // Evict the oldest subscriber (its recv side then closes naturally).
        }
        subs.push(tx);
        rx
    }
}

/// Start the LSD service (`bt-lsd=false` returns `Ok(None)`, no socket is
/// created).
///
/// Returns `None` (disabled) or `(handle, bound address, service task)`;
/// discovery events fan out via [`LsdHandle::subscribe`] (bounded 16 per
/// subscriber, dropped when full — best-effort discovery semantics). With
/// no subscribers events are dropped on the floor (announce-only
/// consumption is a legal shape).
pub async fn spawn(
    cfg: &LsdConfig,
) -> Result<Option<(LsdHandle, SocketAddr, tokio::task::JoinHandle<()>)>, LsdError> {
    if !cfg.enabled {
        return Ok(None);
    }
    let bind_addr: std::net::SocketAddr = format!(
        "0.0.0.0:{cfg_multicast_port}",
        cfg_multicast_port = cfg.multicast_port
    )
    .parse()
    .map_err(|e| LsdError::Socket(format!("bind addr: {e}")))?;
    // socket2-built socket: SO_REUSEADDR (the reference sets it on every
    // socket, SocketCore.cc — the prerequisite for multiple consumers on
    // one host sharing the 6771 multicast port; on Linux REUSEADDR alone
    // suffices) before bind. BSD/macOS additionally require SO_REUSEPORT
    // for UDP port sharing (both sockets must set it to bind), so unix sets
    // it too — on Linux REUSEPORT for multicast is equally valid (effective
    // when both sides set it; no weaker than the reference's REUSEADDR).
    // std has no such knobs, hence the safe socket2 wrapper, no unsafe.
    let socket = {
        use socket2::{Domain, Protocol, Socket, Type};
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| LsdError::Socket(format!("socket: {e}")))?;
        s.set_reuse_address(true)
            .map_err(|e| LsdError::Socket(format!("reuse_address: {e}")))?;
        #[cfg(unix)]
        s.set_reuse_port(true)
            .map_err(|e| LsdError::Socket(format!("reuse_port: {e}")))?;
        s.set_nonblocking(true)
            .map_err(|e| LsdError::Socket(format!("nonblocking: {e}")))?;
        s.bind(&bind_addr.into())
            .map_err(|e| LsdError::Socket(format!("bind {bind_addr}: {e}")))?;
        let std_sock: std::net::UdpSocket = s.into();
        UdpSocket::from_std(std_sock).map_err(|e| LsdError::Socket(format!("from_std: {e}")))?
    };
    let group: std::net::IpAddr = cfg
        .multicast_addr
        .parse()
        .map_err(|e| LsdError::Socket(format!("multicast addr: {e}")))?;
    let std::net::IpAddr::V4(group_v4) = group else {
        return Err(LsdError::Socket("LSD is IPv4 multicast (BEP14)".into()));
    };
    let local_addr = socket
        .local_addr()
        .map_err(|e| LsdError::Socket(format!("local_addr: {e}")))?;
    // Join group + TTL/loop (LpdMessageReceiver.cc + BtSetup.cc).
    if cfg.join_multicast {
        socket
            .join_multicast_v4(group_v4, std::net::Ipv4Addr::UNSPECIFIED)
            .map_err(|e| LsdError::Socket(format!("join multicast: {e}")))?;
    }
    if let Err(e) = socket.set_multicast_loop_v4(cfg.multicast_loop) {
        warn!(target: "taiji::bt::lsd", %e, "set_multicast_loop failed");
    }
    if let Err(e) = socket.set_multicast_ttl_v4(u32::from(cfg.multicast_ttl)) {
        warn!(target: "taiji::bt::lsd", %e, "set_multicast_ttl failed");
    }
    let (cmd_tx, cmd_rx) = mpsc::channel::<LsdCommand>(16);
    let handle = LsdHandle {
        cmd_tx,
        subs: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let subs = Arc::clone(&handle.subs);
    let mc_addr = cfg.multicast_addr.clone();
    let mc_port = cfg.multicast_port;
    let interval = cfg.interval;
    let join = tokio::spawn(async move {
        lsd_loop(socket, cmd_rx, subs, mc_addr, mc_port, interval).await;
    });
    Ok(Some((handle, local_addr, join)))
}

/// Service main loop: commands + periodic dispatch (interval semantics
/// mirror `LpdMessageDispatcher.cc`) + inbound parsing
/// (`LpdMessageReceiver.cc`).
async fn lsd_loop(
    socket: UdpSocket,
    mut cmd_rx: mpsc::Receiver<LsdCommand>,
    subs: Arc<std::sync::Mutex<Vec<mpsc::Sender<LsdEvent>>>>,
    mc_addr: String,
    mc_port: u16,
    interval: Duration,
) {
    // Per-infohash dispatch state (aria2 has one dispatcher per torrent; an
    // equivalent map here).
    let mut dispatchers: HashMap<[u8; 20], (DispatchState, u16)> = HashMap::new();
    let target: SocketAddr = format!("{mc_addr}:{mc_port}")
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([239, 192, 152, 143], 6771)));
    let mut buf = [0u8; 200]; // LpdMessageReceiver.cc `unsigned char buf[200]`
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return; };
                match cmd {
                    LsdCommand::Announce { info_hash, port } => {
                        // New entries are immediately ready (Timer::zero
                        // semantics).
                        dispatchers
                            .entry(info_hash)
                            .or_insert_with(|| (DispatchState::new(interval), port))
                            .1 = port;
                    }
                    LsdCommand::Withdraw { info_hash } => {
                        dispatchers.remove(&info_hash);
                    }
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                for (info_hash, (state, port)) in dispatchers.iter_mut() {
                    if !state.is_announce_ready(now) {
                        continue;
                    }
                    let packet = build_announce(info_hash, *port, &mc_addr, mc_port);
                    let sent = socket.send_to(&packet, target).await;
                    // Send success/failure accounted per
                    // LpdDispatchMessageCommand semantics
                    // (LpdDispatchMessageCommand.cc). A datagram shorter
                    // than the packet counts as failed (partial write).
                    let outcome = match sent {
                        Ok(n) if n == packet.len() => SendOutcome::Sent,
                        _ => SendOutcome::Failed,
                    };
                    state.on_send_result(outcome, now);
                }
            }
            recv = socket.recv_from(&mut buf) => {
                let Ok((n, from)) = recv else { continue; };
                if let Some(msg) = parse_packet(&buf[..n], from) {
                    let ev = LsdEvent::PeerFound {
                        info_hash: msg.info_hash,
                        peer: msg.peer,
                    };
                    // Multi-subscriber fan-out: dropped when the queue is
                    // full or the subscriber is gone (best-effort discovery
                    // — bounded-16 backpressure); closed subscribers are
                    // harvested in passing (is_closed senders are not kept).
                    let mut subs = crate::lock(&subs);
                    subs.retain(|s| !s.is_closed());
                    for s in subs.iter() {
                        let _ = s.try_send(ev);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Announce packet byte vector (reference `createLpdRequest`,
    /// LpdMessageDispatcher.cc: note the trailing `\r\n\r\n\r\n` and the
    /// lowercase hex).
    #[test]
    fn announce_bytes_match_reference_format() {
        let ih = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        let pkt = build_announce(&ih, 6881, LPD_MULTICAST_ADDR, LPD_MULTICAST_PORT);
        let want = concat!(
            "BT-SEARCH * HTTP/1.1\r\n",
            "Host: 239.192.152.143:6771\r\n",
            "Port: 6881\r\n",
            "Infohash: 123456789abcdef0112233445566778899aabbcc\r\n",
            "\r\n\r\n",
        );
        assert_eq!(
            String::from_utf8(pkt).unwrap_or_else(|e| panic!("{e}")),
            want
        );
    }

    /// Packet parsing (LpdMessageReceiver.cc semantics table).
    #[test]
    fn parse_packet_semantics_table() {
        let from: SocketAddr = "192.168.1.5:5000".parse().unwrap_or_else(|e| panic!("{e}"));
        let ih_hex = "123456789abcdef0112233445566778899aabbcc";
        let pkt = format!(
            "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nPort: 6881\r\nInfohash: {ih_hex}\r\n\r\n\r\n"
        );
        let msg = parse_packet(pkt.as_bytes(), from).unwrap_or_else(|| panic!("want parse"));
        assert_eq!(
            msg.peer.to_string(),
            "192.168.1.5:6881",
            "Port header overrides the source port"
        );
        assert_eq!(msg.info_hash[0], 0x12);
        assert_eq!(msg.info_hash[19], 0xcc);
        // Port header = 0 -> rejected.
        let bad_port = format!("BT-SEARCH * HTTP/1.1\r\nPort: 0\r\nInfohash: {ih_hex}\r\n\r\n\r\n");
        assert!(parse_packet(bad_port.as_bytes(), from).is_none());
        // Port header > 65535 -> rejected.
        let big_port =
            format!("BT-SEARCH * HTTP/1.1\r\nPort: 70000\r\nInfohash: {ih_hex}\r\n\r\n\r\n");
        assert!(parse_packet(big_port.as_bytes(), from).is_none());
        // Infohash not 40 hex -> rejected.
        let short_ih = "BT-SEARCH * HTTP/1.1\r\nPort: 6881\r\nInfohash: abc\r\n\r\n\r\n";
        assert!(parse_packet(short_ih.as_bytes(), from).is_none());
        // Non-BT-SEARCH request line -> rejected.
        let http = format!("GET / HTTP/1.1\r\nPort: 6881\r\nInfohash: {ih_hex}\r\n\r\n");
        assert!(parse_packet(http.as_bytes(), from).is_none());
        // Incomplete header block (no \r\n\r\n) -> rejected.
        assert!(parse_packet(b"BT-SEARCH * HTTP/1.1\r\nPort: 6881", from).is_none());
    }

    /// Infohash containing multi-byte UTF-8 (exactly 40 bytes) -> rejected
    /// without panicking (a real panic found by fuzzing: byte slicing
    /// inside a character boundary).
    #[test]
    fn parse_packet_rejects_multibyte_infohash_without_panic() {
        let from: SocketAddr = "192.168.1.5:5000".parse().unwrap_or_else(|e| panic!("{e}"));
        // '¬' is 2-byte UTF-8: 33 ASCII + 2B + 5 ASCII = 40 bytes.
        let value = format!("{}¬nuSnf", "123456789abcdef011223344556677889");
        assert_eq!(
            value.len(),
            40,
            "fixture: value byte length must be exactly 40"
        );
        let pkt = format!("BT-SEARCH * HTTP/1.1\r\nPort: 6881\r\nInfohash: {value}\r\n\r\n\r\n");
        assert!(parse_packet(pkt.as_bytes(), from).is_none());
    }

    /// Dispatch timing table (LpdMessageDispatcher.cc +
    /// LpdDispatchMessageCommand.cc semantics).
    #[test]
    fn dispatch_timer_table() {
        let t0 = Instant::now();
        let mut st = DispatchState::new(Duration::from_secs(300));
        // Initial Timer::zero -> immediately ready.
        assert!(st.is_announce_ready(t0));
        // Successful send -> not ready within 5 min, ready after 300s.
        st.on_send_result(SendOutcome::Sent, t0);
        assert!(!st.is_announce_ready(t0 + Duration::from_secs(299)));
        assert!(st.is_announce_ready(t0 + Duration::from_secs(300)));
        // 4 failures: the timer is not reset (failures retry without
        // resetting).
        st.reset_timer(t0);
        st.on_send_result(SendOutcome::Failed, t0);
        st.on_send_result(SendOutcome::Failed, t0);
        st.on_send_result(SendOutcome::Failed, t0);
        st.on_send_result(SendOutcome::Failed, t0);
        // tryCount=4 < 5: the timer is not reset, but
        // LpdDispatchMessageCommand's retry is "retry shortly" (the next
        // engine tick; this state machine gates on is_ready, so it stays
        // not-ready until a reset).
        assert!(!st.is_announce_ready(t0 + Duration::from_secs(10)));
        // The 5th failure -> reset.
        st.on_send_result(SendOutcome::Failed, t0 + Duration::from_secs(11));
        assert!(st.try_count == 0, "5 consecutive failures reset try_count");
        assert!(!st.is_announce_ready(t0 + Duration::from_secs(12)));
        assert!(st.is_announce_ready(t0 + Duration::from_secs(11) + Duration::from_secs(300)));
    }

    /// End-to-end over unicast (no multicast dependency): a BT-SEARCH
    /// packet -> the service parses it into PeerFound (receive path mirrors
    /// LpdMessageReceiver.cc).
    #[tokio::test]
    async fn service_receives_unicast_bt_search() {
        let cfg = LsdConfig {
            enabled: true,
            multicast_port: 0,
            multicast_addr: "239.192.152.143".into(),
            join_multicast: false,
            ..LsdConfig::default()
        };
        let (handle, local, join) = match spawn(&cfg).await {
            Ok(Some(x)) => x,
            Ok(None) => panic!("enabled"),
            Err(e) => panic!("{e}"),
        };
        let mut event_rx = handle.subscribe();
        let ih = [0x42u8; 20];
        let packet = build_announce(&ih, 6881, "239.192.152.143", 6771);
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // bind 0.0.0.0:0 yields local_addr 0.0.0.0:port; unicast must
        // target the loopback address.
        let dst = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            local.port(),
        );
        sender
            .send_to(&packet, dst)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));
        let ev = tokio::time::timeout(Duration::from_secs(2), event_rx.recv()).await;
        match ev {
            Ok(Some(LsdEvent::PeerFound { info_hash, peer })) => {
                assert_eq!(info_hash, ih);
                assert_eq!(peer.port(), 6881, "Port header overrides the source port");
            }
            other => panic!("expected PeerFound, got {other:?}"),
        }
        drop(handle);
        let _ = join.await;
    }

    /// Consumer side: multi-subscriber fan-out — two subscriptions each
    /// receive the same event; with no subscribers events are silently
    /// dropped (announce-only shape, no panic, no backlog).
    #[tokio::test]
    async fn events_fan_out_to_all_subscribers() {
        let cfg = LsdConfig {
            enabled: true,
            multicast_port: 0,
            multicast_addr: "239.192.152.143".into(),
            join_multicast: false,
            ..LsdConfig::default()
        };
        let (handle, local, join) = match spawn(&cfg).await {
            Ok(Some(x)) => x,
            Ok(None) => panic!("enabled"),
            Err(e) => panic!("{e}"),
        };
        let mut sub_a = handle.subscribe();
        let mut sub_b = handle.subscribe();
        let ih = [0x7fu8; 20];
        let packet = build_announce(&ih, 9999, "239.192.152.143", 6771);
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let dst = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            local.port(),
        );
        sender
            .send_to(&packet, dst)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));
        for (tag, rx) in [("a", &mut sub_a), ("b", &mut sub_b)] {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
            match ev {
                Ok(Some(LsdEvent::PeerFound { info_hash, peer })) => {
                    assert_eq!(info_hash, ih, "sub {tag}");
                    assert_eq!(peer.port(), 9999, "sub {tag}");
                }
                other => panic!("sub {tag}: expected PeerFound, got {other:?}"),
            }
        }
        drop((sub_a, sub_b, handle));
        let _ = join.await;
    }

    /// announce/withdraw lifecycle (deterministic loopback: the service's
    /// "multicast target" is pointed at its own loopback port, so dispatched
    /// BT-SEARCH packets come back through the receive path — reusing
    /// build_announce/parse_packet to check both directions). The first 1s
    /// tick after the Announce command sends (Timer::zero semantics,
    /// LpdMessageDispatcher.cc); nothing is sent after Withdraw.
    #[tokio::test]
    async fn announce_dispatch_then_withdraw_stops() {
        // Grab a free port first, then release it (the service bind and the
        // dispatch target must use the same port).
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let lport = probe.local_addr().unwrap_or_else(|e| panic!("{e}")).port();
        drop(probe);
        let cfg = LsdConfig {
            enabled: true,
            multicast_port: lport,
            multicast_addr: "127.0.0.1".into(),
            join_multicast: false,
            ..LsdConfig::default()
        };
        let (handle, local, join) = match spawn(&cfg).await {
            Ok(Some(x)) => x,
            Ok(None) => panic!("enabled"),
            Err(e) => panic!("{e}"),
        };
        assert_eq!(
            local.port(),
            lport,
            "service bind port = dispatch target port"
        );
        let mut sub = handle.subscribe();
        let ih = [0x21u8; 20];
        handle
            .announce(ih, 6881)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Self-send loopback -> parse -> PeerFound (Infohash/Port checked
        // field by field).
        let ev = tokio::time::timeout(Duration::from_secs(5), sub.recv()).await;
        match ev {
            Ok(Some(LsdEvent::PeerFound { info_hash, peer })) => {
                assert_eq!(
                    info_hash, ih,
                    "announce Infohash must round-trip via loopback"
                );
                assert_eq!(peer.port(), 6881, "announce Port header");
            }
            other => panic!("expected PeerFound, got {other:?}"),
        }
        // Withdraw -> dispatcher removed; zero re-sends within a 3s
        // observation window (interval semantics closed off).
        handle.withdraw(ih).await.unwrap_or_else(|e| panic!("{e}"));
        let drained = tokio::time::timeout(Duration::from_secs(3), sub.recv()).await;
        assert!(drained.is_err(), "no announce after withdraw: {drained:?}");
        drop((sub, handle));
        let _ = join.await;
    }

    /// bt-lsd disabled by default: spawn returns Ok(None).
    #[tokio::test]
    async fn disabled_by_default() {
        let cfg = LsdConfig::default();
        assert!(!cfg.enabled, "bt-lsd defaults to false (SPEC §11)");
        assert!(matches!(spawn(&cfg).await, Ok(None)));
    }
}

//! NAT-PMP client (SPEC §6.8). Every protocol fact is anchored to an
//! RFC 6886 clause (aria2 has no NAT-PMP implementation, so there is no
//! upstream code reference); no constant is written from memory — every
//! byte layout and deadline here carries a section number.
//!
//! Structure:
//!
//! - pure codec [`Request::encode`]/[`decode_reply`]: total functions, no
//!   panic (the fuzz target `nat_pmp_reply` guards the same implementation);
//! - [`EpochTracker`]: pure state machine for §3.6 state-loss detection;
//! - [`NatPmpClient`]: async transactions (retransmission schedule +
//!   source-address check + opcode/internal-port attribution checks); the
//!   socket is injected by the caller (tokio::net::UdpSocket; mock tests
//!   bind loopback).
//!
//! The full packet facts and the SPEC-vs-RFC divergence notes live in
//! docs/design/io.md.
//!
//! Upstream anchor mapping: docs/design/io.md

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::debug;

/// tracing target.
const LOG_TARGET: &str = "taiji::io::nat::natpmp";

/// Protocol version (RFC 6886 §3.2/§3.3 packet diagrams, `Vers = 0`).
pub const VERSION: u8 = 0;

/// Server port (RFC 6886 §3.1 "port 5351 of its configured gateway
/// address"; §3.2.1: the server listens on UDP 5351).
pub const SERVER_PORT: u16 = 5351;

/// Opcode: external address request (RFC 6886 §3.2 packet diagram, `OP = 0`).
pub const OP_EXTERNAL_ADDRESS: u8 = 0;
/// Opcode: Map UDP (RFC 6886 §3.3 "Opcodes supported: 1 - Map UDP").
pub const OP_MAP_UDP: u8 = 1;
/// Opcode: Map TCP (RFC 6886 §3.3 "2 - Map TCP").
pub const OP_MAP_TCP: u8 = 2;

/// High bit of response opcodes (RFC 6886 §2 "Opcodes from 128 to 255 are
/// corresponding server responses"; §3.5 "the top bit of the opcode set").
pub const RESPONSE_OP_FLAG: u8 = 0x80;

/// Success (RFC 6886 §3.5 result codes).
pub const RESULT_SUCCESS: u16 = 0;
/// Unsupported Version (§3.5).
pub const RESULT_UNSUPPORTED_VERSION: u16 = 1;
/// Not Authorized/Refused (§3.5, "box supports mapping, but user has
/// turned feature off").
pub const RESULT_NOT_AUTHORIZED: u16 = 2;
/// Network Failure (§3.5, "NAT box itself has not obtained a DHCP lease").
pub const RESULT_NETWORK_FAILURE: u16 = 3;
/// Out of resources (§3.5, "NAT box cannot create any more mappings").
pub const RESULT_OUT_OF_RESOURCES: u16 = 4;
/// Unsupported opcode (§3.5).
pub const RESULT_UNSUPPORTED_OPCODE: u16 = 5;

/// Request retransmission waits (RFC 6886 §3.1: doubling from 250ms; after
/// the 9th send, wait 64s and deem the gateway unsupported — 9 sends, 9
/// wait windows).
pub const RETRANSMIT_SCHEDULE: [Duration; 9] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    Duration::from_secs(64),
];

/// SPEC §6.8 renewal cadence (60min; local policy — see docs/design/io.md
/// for the divergence note).
pub const SPEC_RENEW_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Requested lifetime for mapping requests (3600s; the RFC 6886 §3.3
/// RECOMMENDED 7200s is intentionally not used).
pub const REQUESTED_LEASE_SECS: u32 = 3600;

/// Sanity floor for lifetimes granted in success replies (local policy;
/// the RFC has no anchor).
///
/// Rationale: §3.3 lets the gateway reduce the lifetime ("MAY reduce"), but
/// a MITM-forged success reply can carry an arbitrarily small lifetime and
/// poison the renewal cadence (granted=1s -> a §3.3 halfway renewal burst
/// every 500ms, keeping the NAT actor's serial transaction surface busy).
/// Grants below the floor are treated as the requested value: the cadence
/// returns to the SPEC §6.8 60min mark, and if the mapping really was
/// reclaimed early, the renewal request itself is an idempotent recreate
/// (§3.3 packets are self-describing), so self-healing is unchanged. A
/// floor of 60s sits at the low percentile of one normal renewal period,
/// far below the grant distribution of legitimate gateways.
pub const MIN_GRANTED_LIFETIME_SECS: u32 = 60;

/// Short window for the epoch poisoning breaker's first tier (local
/// policy, no RFC anchor): a second regression inside the window does not
/// schedule a new recreate (§3.7 jitter plus full-round retries are
/// naturally slower than that rhythm); consecutive regressions reaching
/// [`EPOCH_POISON_STRIKES`] mean a forged-reply-driven permanent recreate
/// loop (attack path: one every ~5s) -> disable NAT-PMP. 60s is far above
/// the rhythm of one legitimate reboot (a single reboot yields a single
/// regression) and far below the poisoning loop's tempo.
pub const EPOCH_POISON_WINDOW: Duration = Duration::from_secs(60);

/// The Nth §3.6 regression within the short window = epoch poisoning
/// (disable NAT-PMP; local policy). 4 ensures one legitimate failure
/// (reboot + jittered reconnect) never trips, while sustained forged
/// replies trip the breaker within a few rounds.
pub const EPOCH_POISON_STRIKES: u32 = 4;

/// Long window for the epoch poisoning breaker's second tier (local
/// policy, no RFC anchor): a rate limit behind the short tier. A forger
/// pacing regressions at least [`EPOCH_POISON_WINDOW`] apart resets the
/// short count on every strike and would keep a recreate loop alive
/// forever (one full remap round per regression); this tier counts every
/// regression of a fixed window opened by its first one (a regression
/// at/after the window end opens the next window as its first strike), so
/// such a cadence is held under [`EPOCH_POISON_LONG_STRIKES`] regressions
/// per window.
pub const EPOCH_POISON_LONG_WINDOW: Duration = Duration::from_secs(60 * 60);

/// The Nth §3.6 regression within the long window = epoch poisoning
/// (disable NAT-PMP; local policy, no RFC anchor). A legitimate reboot
/// yields one regression, so 6 in an hour is already a pathological
/// gateway; after the trip the IGD backend carries on (`nat.rs`
/// `observe_pmp_reply`).
pub const EPOCH_POISON_LONG_STRIKES: u32 = 6;

/// Mapping protocol (RFC 6886 §3.3 opcode 1 = Map UDP, 2 = Map TCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Map UDP (opcode 1).
    Udp,
    /// Map TCP (opcode 2).
    Tcp,
}

impl Protocol {
    /// Matching map-request opcode (§3.3).
    pub fn opcode(self) -> u8 {
        match self {
            Protocol::Udp => OP_MAP_UDP,
            Protocol::Tcp => OP_MAP_TCP,
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Udp => f.write_str("udp"),
            Protocol::Tcp => f.write_str("tcp"),
        }
    }
}

/// Map request payload (§3.3; on renewal `suggested_external_port` = the
/// gateway-assigned value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapRequest {
    /// Mapping protocol (selects opcode 1/2).
    pub protocol: Protocol,
    /// Local listening port (§3.3 "The Internal Port is set to the local
    /// port on which the client is listening").
    pub internal_port: u16,
    /// Desired external port (§3.3: 0 = gateway's choice; renewal = the
    /// assigned value).
    pub suggested_external_port: u16,
    /// Requested lifetime in seconds (0 = delete semantics, §3.4).
    pub lifetime_secs: u32,
}

/// Request (RFC 6886 §3.2 external address / §3.3 mapping; §3.4 delete =
/// a mapping request with lifetime 0, expressed via [`Request::Map`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// External address request (2B, §3.2).
    ExternalAddress,
    /// Map request / renewal / delete (12B, §3.3; the delete form is §3.4:
    /// lifetime=0 and suggested_external_port=0 — guaranteed by
    /// [`Request::unmap`]).
    Map(MapRequest),
}

impl Request {
    /// §3.4 delete request form: lifetime=0 and SuggestedExternalPort=0
    /// (both MUSTs; see the quotes in docs/design/io.md).
    pub fn unmap(protocol: Protocol, internal_port: u16) -> Request {
        Request::Map(MapRequest {
            protocol,
            internal_port,
            suggested_external_port: 0,
            lifetime_secs: 0,
        })
    }

    /// Matching request opcode (for reply matching; §3.3 "'x' in the OP
    /// field MUST match what the client requested").
    pub fn opcode(&self) -> u8 {
        match self {
            Request::ExternalAddress => OP_EXTERNAL_ADDRESS,
            Request::Map(m) => m.protocol.opcode(),
        }
    }

    /// Encode as a UDP payload (§3.2/§3.3 packet diagrams; big endian —
    /// RFC 6886 §3.3 "transmitted in the traditional network byte order").
    ///
    /// Map request, 12B: Vers(8) + OP(8) + Reserved(16) + InternalPort(16) +
    /// SuggestedExternalPort(16) + Lifetime(32). In the §3.3 diagram the
    /// first row `| Vers = 0 | OP = x | Reserved |` fills one 32-bit row,
    /// so Reserved is 16 bits ("MUST be set to zero on transmission and
    /// MUST be ignored on reception").
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Request::ExternalAddress => vec![VERSION, OP_EXTERNAL_ADDRESS],
            Request::Map(m) => {
                let mut b = Vec::with_capacity(12);
                b.push(VERSION);
                b.push(m.protocol.opcode());
                b.extend_from_slice(&[0, 0]); // Reserved u16 = 0 (§3.3 MUST)
                b.extend_from_slice(&m.internal_port.to_be_bytes());
                b.extend_from_slice(&m.suggested_external_port.to_be_bytes());
                b.extend_from_slice(&m.lifetime_secs.to_be_bytes());
                b
            }
        }
    }
}

/// Decode errors (total over all inputs: any byte string yields Ok/Err,
/// never panic — fuzz contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Packet shorter than the minimum for its opcode (§3.2 address 12B /
    /// §3.3 map 16B).
    #[error("packet too short: {0} bytes")]
    TooShort(usize),
    /// Version != 0 (§3.2/§3.3 diagrams fix `Vers = 0`; only version-0
    /// replies are accepted).
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    /// High bit unset -> not a response (§2: opcodes 0-127 are requests).
    #[error("not a response: opcode {0} lacks the response bit")]
    NotAResponse(u8),
    /// Response opcode is neither address (128) nor map (129/130).
    #[error("unknown response opcode {0}")]
    UnknownOpcode(u8),
}

/// Reply (§3.2/§3.3 formats; the §3.2.1 gateway announcement reuses the
/// address-reply format — see the [`decode_reply`] docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Address reply (§3.2, 12B) / gateway announcement (§3.2.1, same
    /// format).
    ExternalAddress {
        /// Result code (§3.5; non-0 -> the address field must be ignored,
        /// §3.2 "MUST be ignored on reception" — callers only use it when
        /// success()).
        result: u16,
        /// Seconds Since Start of Epoch (§3.6).
        epoch_secs: u32,
        /// External IPv4; when result != 0 this is a placeholder the sender
        /// MUST zero — the semantic layer must ignore it.
        address: Ipv4Addr,
    },
    /// Map reply (§3.3, 16B; `protocol` recovered from the response opcode).
    Map {
        /// Mapping protocol (§3.3 "OP = 128 + x", x in {1, 2}).
        protocol: Protocol,
        /// Result code (§3.5).
        result: u16,
        /// Seconds Since Start of Epoch (§3.6).
        epoch_secs: u32,
        /// Internal port echo (§3.5: error replies MUST echo it too — the
        /// client attributes on it).
        internal_port: u16,
        /// Actually assigned external port (§3.3 "Mapped External Port";
        /// when result != 0 it decodes from the packet but is semantically
        /// void).
        external_port: u16,
        /// Gateway-granted lifetime (§3.3 "The NAT gateway MAY reduce the
        /// lifetime from what the client requested"; lifetime 0 belongs to
        /// the §3.4 delete reply).
        lifetime_secs: u32,
    },
}

impl Reply {
    /// Whether the transaction succeeded (result == 0, §3.5).
    pub fn success(&self) -> bool {
        self.result() == RESULT_SUCCESS
    }

    /// Result code.
    pub fn result(&self) -> u16 {
        match self {
            Reply::ExternalAddress { result, .. } | Reply::Map { result, .. } => *result,
        }
    }

    /// SSSoE (§3.6).
    pub fn epoch_secs(&self) -> u32 {
        match self {
            Reply::ExternalAddress { epoch_secs, .. } | Reply::Map { epoch_secs, .. } => {
                *epoch_secs
            }
        }
    }

    /// Response opcode (§3.2/§3.3 reply header, second byte).
    pub fn opcode(&self) -> u8 {
        match self {
            Reply::ExternalAddress { .. } => RESPONSE_OP_FLAG | OP_EXTERNAL_ADDRESS,
            Reply::Map { protocol, .. } => RESPONSE_OP_FLAG | protocol.opcode(),
        }
    }
}

/// Decode a reply from a UDP payload (§3.2/§3.3 formats; total over all
/// inputs — the fuzz target `nat_pmp_reply` guards this implementation).
///
/// Note: the gateway's unsolicited address announcement (§3.2.1: sent to
/// multicast 224.0.0.1:5350) has the same format as the point-to-point
/// address reply; this decoder does not distinguish origins — source
/// validation (the §3.2/§3.2.1 MUST) is the [`NatPmpClient`] transaction
/// layer's job.
pub fn decode_reply(buf: &[u8]) -> Result<Reply, DecodeError> {
    if buf.len() < 4 {
        return Err(DecodeError::TooShort(buf.len()));
    }
    let vers = buf[0];
    if vers != VERSION {
        return Err(DecodeError::UnsupportedVersion(vers));
    }
    let op = buf[1];
    if op & RESPONSE_OP_FLAG == 0 {
        return Err(DecodeError::NotAResponse(op));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    let epoch = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    match op & !RESPONSE_OP_FLAG {
        OP_EXTERNAL_ADDRESS => {
            if buf.len() < 12 {
                return Err(DecodeError::TooShort(buf.len()));
            }
            Ok(Reply::ExternalAddress {
                result,
                epoch_secs: epoch,
                address: Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]),
            })
        }
        base @ (OP_MAP_UDP | OP_MAP_TCP) => {
            if buf.len() < 16 {
                return Err(DecodeError::TooShort(buf.len()));
            }
            Ok(Reply::Map {
                protocol: if base == OP_MAP_TCP {
                    Protocol::Tcp
                } else {
                    Protocol::Udp
                },
                result,
                epoch_secs: epoch,
                internal_port: u16::from_be_bytes([buf[8], buf[9]]),
                external_port: u16::from_be_bytes([buf[10], buf[11]]),
                lifetime_secs: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            })
        }
        unknown => Err(DecodeError::UnknownOpcode(unknown | RESPONSE_OP_FLAG)),
    }
}

/// Pure state machine for §3.6 epoch state-loss detection.
///
/// "the client computes its own conservative estimate of the expected SSSoE
/// value by taking the SSSoE value in the last packet it received from the
/// gateway and adding 7/8 (87.5%) of the time elapsed according to the
/// client's local clock since that packet was received. If the SSSoE in the
/// newly received packet is less than the client's conservative estimate by
/// more than 2 seconds, then the client concludes that the NAT gateway has
/// undergone a reboot or other loss of port mapping state"。
#[derive(Debug, Clone, Default)]
pub struct EpochTracker {
    last_epoch: Option<(u32, Instant)>,
}

impl EpochTracker {
    /// Call once per packet received from the gateway (reply or
    /// announcement); returns true = state loss detected (=> §3.7 recreate
    /// all mappings immediately). The first observation only establishes
    /// the baseline.
    pub fn observe(&mut self, epoch_secs: u32, now: Instant) -> bool {
        let new = u64::from(epoch_secs);
        match self.last_epoch.replace((epoch_secs, now)) {
            None => false,
            Some((last, seen)) => {
                let elapsed = now.saturating_duration_since(seen);
                // Conservative estimate = last + 7/8 elapsed (§3.6, floored
                // at second granularity — flooring only raises the
                // estimate's safety margin and cannot create false
                // positives).
                let estimate = u64::from(last) + elapsed.as_secs() * 7 / 8;
                // new < estimate - 2 => state loss (§3.6 "less than the
                // conservative estimate by more than 2 seconds").
                new + 2 < estimate
            }
        }
    }
}

/// Epoch poisoning circuit breaker (pure state machine, consumed by
/// `observe_pmp_reply` in `nat.rs`).
///
/// §3.6 regression detection itself is [`EpochTracker`]'s job — but
/// "every regression => recreate after 0-5s" is undefended against forged
/// replies: a LAN man-in-the-middle alternating high/low epochs gets a
/// permanent recreate loop (a full remap round every ~5s). This guard adds
/// two tiers of regression bookkeeping; either tier filling => poisoning
/// (returns true; the caller disables NAT-PMP), terminating the loop:
///
/// - short tier (monotonicity): consecutive regressions within
///   [`EPOCH_POISON_WINDOW`] reaching [`EPOCH_POISON_STRIKES`]. Sparse
///   regressions (>= a window apart) reset this count;
/// - long tier (rate limit): regressions within one
///   [`EPOCH_POISON_LONG_WINDOW`] reaching [`EPOCH_POISON_LONG_STRIKES`] —
///   catches a forger pacing itself just past the short window, which
///   resets the short count on every strike.
///
/// Legitimate occasional gateway reboots (one regression each) fill
/// neither tier.
#[derive(Debug, Clone, Default)]
pub struct EpochPoisonGuard {
    last_regression: Option<Instant>,
    strikes: u32,
    /// Start of the current long-tier window (`None` = no regression yet).
    long_window_start: Option<Instant>,
    /// Regressions in the current long-tier window, its opener included.
    long_strikes: u32,
    poisoned: bool,
}

impl EpochPoisonGuard {
    /// Record one §3.6 regression (the instant is injected by the caller —
    /// the pure state machine is table-testable). Returns true = regressions
    /// filled the short or the long window, epoch poisoning declared
    /// (terminal state: all later calls return true).
    pub fn observe_regression(&mut self, now: Instant) -> bool {
        if self.poisoned {
            return true;
        }
        match self.last_regression {
            Some(at) if now.saturating_duration_since(at) < EPOCH_POISON_WINDOW => {
                self.strikes = self.strikes.saturating_add(1);
            }
            _ => self.strikes = 0,
        }
        self.last_regression = Some(now);
        // strikes = extra regressions after the first one inside the
        // window; full = the EPOCH_POISON_STRIKES-th regression.
        if self.strikes >= EPOCH_POISON_STRIKES - 1 {
            self.poisoned = true;
        }
        // Long tier: a fixed window opened by its first regression; one
        // at/after the window end rolls it over and counts as the new
        // window's first strike. Full = the EPOCH_POISON_LONG_STRIKES-th
        // regression of one window.
        match self.long_window_start {
            Some(start) if now.saturating_duration_since(start) < EPOCH_POISON_LONG_WINDOW => {
                self.long_strikes = self.long_strikes.saturating_add(1);
            }
            _ => {
                self.long_window_start = Some(now);
                self.long_strikes = 1;
            }
        }
        if self.long_strikes >= EPOCH_POISON_LONG_STRIKES {
            self.poisoned = true;
        }
        self.poisoned
    }

    /// Whether poisoning has been declared (terminal; NAT-PMP disabled for
    /// the session).
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
}

/// Renewal delay (pure function, locked by table-driven tests).
///
/// - granted == 0 => `None`: UPnP `NewLeaseDuration=0` means a permanent
///   mapping (WANIPConnection:2 spec §2.5.16.2: '0' denotes an out-of-band
///   permanent mapping interpreted as 604800s; §2.5.16.3 requires control
///   points to use 1..=604800) — permanent mappings need no renewal. A
///   NAT-PMP success reply never grants lifetime 0 (0 appears only in §3.4
///   delete replies, which callers do not feed in).
/// - granted >= 60min => 60min (the SPEC §6.8 renewal cadence; divergence
///   noted in docs/design/io.md).
/// - granted < 60min => granted/2 (RFC 6886 §3.3 "SHOULD begin trying to
///   renew the mapping halfway to expiry time"; the gateway "MAY reduce the
///   lifetime", so renewal must precede real expiry).
pub fn renew_delay(granted: Duration) -> Option<Duration> {
    if granted.is_zero() {
        return None;
    }
    if granted >= SPEC_RENEW_INTERVAL {
        Some(SPEC_RENEW_INTERVAL)
    } else {
        Some(granted / 2)
    }
}

/// Backoff table after a failed full transaction round (local policy, no
/// RFC/SPEC anchor — table-driven for testability; the tail value caps
/// retries: a persistent degradation keeps retrying and converges once the
/// device returns).
pub const ROUND_BACKOFF: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];

/// Backoff delay after the `attempt`-th failed full round (0-based); past
/// the table end, the tail value.
pub fn round_backoff(attempt: u32) -> Duration {
    match ROUND_BACKOFF.get(attempt as usize) {
        Some(d) => *d,
        None => ROUND_BACKOFF[ROUND_BACKOFF.len() - 1],
    }
}

/// §3.7 reboot recreate delay: uniform-random 0-5s ("the client MUST first
/// delay by a random amount of time selected with uniform random
/// distribution in the range 0 to 5 seconds").
pub fn reboot_recreate_delay() -> Duration {
    // rand 0.10: random_range moved to RngExt along with the old Rng rename.
    use rand::RngExt;
    let ms: u64 = rand::rng().random_range(0..=5000);
    Duration::from_millis(ms)
}

/// Transaction error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NatPmpError {
    /// Gateway address unknown (local policy: no explicit config and IGD
    /// derivation failed -> skip NAT-PMP; see the `crate::nat` notes in
    /// docs/design/io.md).
    #[error("nat-pmp: gateway address unknown (configure or derive via IGD)")]
    NoGateway,
    /// Schedule exhausted with no valid reply (§3.1: deem the gateway
    /// unsupported).
    #[error("nat-pmp: no valid response after {attempts} attempts (gateway unsupported?)")]
    NoResponse {
        /// Number of requests sent.
        attempts: usize,
    },
    /// Reply decoding failed (non-response packet / unknown opcode /
    /// version mismatch).
    #[error("nat-pmp: {0}")]
    Decode(#[from] DecodeError),
    /// Reply opcode does not match the request (§3.3 "'x' MUST match").
    #[error("nat-pmp: reply opcode {reply:#04x} does not match expected {expected:#04x}")]
    OpcodeMismatch {
        /// Response opcode.
        reply: u8,
        /// Expected response opcode.
        expected: u8,
    },
    /// Map reply's internal port differs from the request (§3.5 "The
    /// Internal Port MUST be set to the client's requested Internal Port"
    /// — the attribution basis; a mismatch means a stale stray packet).
    #[error("nat-pmp: reply internal port {reply} does not match request {request}")]
    InternalPortMismatch {
        /// Reply internal port.
        reply: u16,
        /// Request internal port.
        request: u16,
    },
    /// Result code != 0 (§3.5; undefined codes are treated as fatal, per
    /// the MUST).
    #[error("nat-pmp: gateway returned result {0}")]
    Result(u16),
    /// Success reply carries a semantically invalid field (reverse check: a
    /// map reply with external port 0 — §3.4 reserves external port 0 for
    /// delete replies; a map reply's "Mapped External Port" must be the
    /// gateway-assigned port).
    #[error("nat-pmp: success reply with invalid field: {0}")]
    InvalidReply(&'static str),
    /// Disabled for this session by the epoch poisoning breaker (no new
    /// transactions; the IGD backend continues).
    #[error("nat-pmp disabled: epoch poisoning circuit-breaker tripped")]
    Poisoned,
    /// Socket IO (including send/recv errors caused by ICMP unreachability,
    /// the §3.1 immediate-give-up path).
    #[error("nat-pmp: {0}")]
    Io(#[from] std::io::Error),
}

/// NAT-PMP client: one transaction = request + retransmission schedule +
/// source check + decode + attribution checks.
///
/// The socket is injected by the caller ([`UdpSocket`]): in production a
/// locally bound socket `connect`ed to the gateway (`connect` only sets the
/// default destination and pins the route's source address; sends remain
/// explicit `send_to`); mock tests inject a socket aimed at a loopback
/// server. Transactions are serial (RFC 6886 §3.1 "SHOULD NOT issue
/// multiple concurrent requests" — serialization is guaranteed by the
/// actor above).
#[derive(Debug)]
pub struct NatPmpClient {
    socket: UdpSocket,
    gateway: SocketAddr,
    schedule: Vec<Duration>,
}

impl NatPmpClient {
    /// Production constructor: the RFC 6886 §3.1 retransmission schedule +
    /// gateway `gateway:5351`.
    pub fn new(socket: UdpSocket, gateway: Ipv4Addr) -> Self {
        Self::with_schedule(
            socket,
            SocketAddr::from((gateway, SERVER_PORT)),
            RETRANSMIT_SCHEDULE.to_vec(),
        )
    }

    /// Test/policy injection constructor (mock server port and custom
    /// retransmission schedule).
    pub fn with_schedule(socket: UdpSocket, gateway: SocketAddr, schedule: Vec<Duration>) -> Self {
        Self {
            socket,
            gateway,
            schedule,
        }
    }

    /// Gateway address (for source checks and diagnostics).
    pub fn gateway(&self) -> SocketAddr {
        self.gateway
    }

    /// Run one transaction (§3.1 retransmission semantics + §3.2/§3.3
    /// source-address MUST check + §3.3 opcode match + §3.5 internal-port
    /// attribution). A non-zero result code returns
    /// [`NatPmpError::Result`].
    pub async fn transact(&self, request: &Request) -> Result<Reply, NatPmpError> {
        self.transact_with_schedule(&self.schedule, request).await
    }

    /// [`Self::transact`] with a different schedule (deletes use a short
    /// table per §3.1 "clients may choose not to try the full nine times";
    /// maps and address requests use the default).
    pub async fn transact_with_schedule(
        &self,
        schedule: &[Duration],
        request: &Request,
    ) -> Result<Reply, NatPmpError> {
        let payload = request.encode();
        let expected_op = request.opcode() | RESPONSE_OP_FLAG;
        for (attempt, window) in schedule.iter().copied().enumerate() {
            self.socket.send_to(&payload, self.gateway).await?;
            let attempts = attempt + 1;
            if let Some(reply) = self
                .await_matching_reply(expected_op, request, window)
                .await?
            {
                if !reply.success() {
                    return Err(NatPmpError::Result(reply.result()));
                }
                return Ok(reply);
            }
            debug!(target: LOG_TARGET, attempts, "no matching reply, retransmitting");
        }
        Err(NatPmpError::NoResponse {
            attempts: schedule.len(),
        })
    }

    /// Wait within one retransmission window for a reply matching the
    /// request.
    ///
    /// Discarded (keep waiting): non-gateway sources (§3.2/§3.3 MUST),
    /// undecodable packets, stale replies with a mismatched opcode. Returns
    /// `None` when the window expires (the caller retransmits).
    async fn await_matching_reply(
        &self,
        expected_op: u8,
        request: &Request,
        window: Duration,
    ) -> Result<Option<Reply>, NatPmpError> {
        let deadline = tokio::time::Instant::now() + window;
        let mut buf = [0u8; 64]; // max reply 16B (§3.3); slack absorbs junk packets
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let (n, src) =
                match tokio::time::timeout(remaining, self.socket.recv_from(&mut buf)).await {
                    Ok(Ok(io)) => io,
                    Ok(Err(e)) => return Err(NatPmpError::Io(e)),
                    Err(_elapsed) => return Ok(None),
                };
            // §3.2/§3.3: "MUST check the source IP address, and silently
            // discard the packet if the address is not the address of the
            // gateway" — non-gateway packets keep waiting within the
            // remaining window.
            if src != self.gateway {
                debug!(target: LOG_TARGET, %src, "discarding packet from non-gateway source");
                continue;
            }
            match decode_reply(&buf[..n]) {
                Ok(reply) if reply.opcode() == expected_op => {
                    if let (Request::Map(m), Reply::Map { internal_port, .. }) = (request, &reply) {
                        // §3.5: error replies must also echo the request's
                        // internal port; a mismatch is residue from an old
                        // transaction — drop and keep waiting.
                        if *internal_port != m.internal_port {
                            debug!(target: LOG_TARGET, reply = internal_port,
                                request = m.internal_port, "internal port mismatch");
                            continue;
                        }
                    }
                    return Ok(Some(reply));
                }
                Ok(reply) => {
                    debug!(target: LOG_TARGET, opcode = reply.opcode(), "opcode mismatch");
                    continue;
                }
                Err(e) => {
                    debug!(target: LOG_TARGET, error = %e, "discarding undecodable packet");
                    continue;
                }
            }
        }
    }
}

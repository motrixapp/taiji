//! ut_holepunch NAT hole-punching peer channel (carried over BEP10;
//! behavior modeled on libtorrent). Protocol + bookkeeping half only:
//! codec for the three sub-operations, pure relay-decision function, and
//! hole-punch trigger bookkeeping; wiring lives in `crate::peer` and the
//! core engine.
//!
//! # Authoritative sources (BEP text > libtorrent > aria2)
//!
//! - Carrier: BEP10 extended-handshake `m` dict negotiation ("message IDs
//! are local to the peer"). Outbound advertised id =
//! [`OUTBOUND_UT_HOLEPUNCH_ID`]; replies follow the peer's advertised id.
//! libtorrent reads the peer's `ut_holepunch` entry and advertises its own
//! (`src/bt_peer_connection.cpp`; its local id constant is 4,
//! `include/libtorrent/bt_peer_connection.hpp`) — under BEP10 the two
//! sides need not agree on the value and still interoperate.
//! - Wire format (libtorrent `write_holepunch_msg`,
//! `src/bt_peer_connection.cpp`): `[1B sub-op][1B address family]
//! [4B|16B address][2B port]`, with `failed` appending a **4B big-endian
//! error code** (read side `aux::read_uint32`, write side
//! `aux::write_uint32`). The design text said "1B error code"; libtorrent
//! is authoritative and the divergence is noted.
//! - Sub-operation semantics (`hp_message`/`hp_error`,
//! `include/libtorrent/bt_peer_connection.hpp`): rendezvous(0) =
//! introduction request, connect(1) = hole-punch dial instruction,
//! failed(2) = refusal reply (no_such_peer=1 / not_connected=2 /
//! no_support=3 / no_self=4).
//! - Relay decision (libtorrent `on_holepunch` rendezvous arm,
//! `src/bt_peer_connection.cpp`): target not connected ->
//! failed(not_connected); target did not negotiate -> failed(no_support);
//! target is the requester -> failed(no_self); otherwise send
//! connect(target ep) to the requester and connect(requester's remote
//! address) to the target — both sides dial simultaneously.
//! - Connect-arm dial-in: dial like a normal candidate (libtorrent
//! `add_peer` + `connect_to_peer`, new connection set to holepunch mode
//! for fast retry).
//! - Trigger surface (libtorrent connect-failure callback,
//! `src/peer_connection.cpp`): direct dial to the peer failed and an
//! introducer is known (`find_introducer`, `src/torrent.cpp` — the
//! connection that delivered the address via ut_pex) -> send rendezvous
//! to the introducer. Here: introducer bookkeeping is fed by ut_pex
//! discovery events; the trigger gate is "a dial plan actually ran out".
//! - failed(0x02) handling: libtorrent only logs it (handling is a TODO
//! there); same policy here — debug log, no action.
//!
//! Branch-by-branch notes: `docs/design/peer-protocol.md`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Our outbound ut_holepunch advertised id (BEP10 `m` dict; uTorrent
/// convention value 0x20). libtorrent advertises 4
/// (`bt_peer_connection.hpp`) — per BEP10 "message IDs are local to the
/// peer", the differing values do not hurt interop; messages to a peer use
/// its advertised id (same reply rule as ut_metadata/ut_pex, see the
/// `crate::peer::ext` routing docs).
pub const OUTBOUND_UT_HOLEPUNCH_ID: u8 = 0x20;

/// v4 address-family code (libtorrent `aux::is_v4(ep) -> write_uint8(0)`,
/// `bt_peer_connection.cpp`).
const AF_INET: u8 = 0;
/// v6 address-family code (the else branch's `write_uint8(1)`).
const AF_INET6: u8 = 1;

/// `failed` message error codes (`hp_error`, bt_peer_connection.hpp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum HpError {
    /// Write-side default (libtorrent `write_holepunch_msg` default
    /// argument, bt_peer_connection.hpp); never sent with this semantics.
    NoError = 0,
    NoSuchPeer = 1,
    NotConnected = 2,
    NoSupport = 3,
    NoSelf = 4,
}

impl HpError {
    fn from_u32(v: u32) -> Option<HpError> {
        match v {
            0 => Some(HpError::NoError),
            1 => Some(HpError::NoSuchPeer),
            2 => Some(HpError::NotConnected),
            3 => Some(HpError::NoSupport),
            4 => Some(HpError::NoSelf),
            _ => None,
        }
    }
}

/// ut_holepunch sub-operation message (payload level; no BEP10 ext frame
/// header).
///
/// Everything is big-endian; the `failed` error code is 4B big-endian (see
/// the module docs for the divergence from the design text's "1B").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtHolepunch {
    /// Introduction request (0x00): `ep` is the target the requester wants
    /// to reach (libtorrent rendezvous arm, `bt_peer_connection.cpp`:
    /// "this peer is asking us to introduce it to the peer at 'ep'").
    Rendezvous { ep: SocketAddr },
    /// Hole-punch dial instruction (0x01): `ep` is the address the
    /// recipient should dial (sent to the requester = target address; sent
    /// to the target = the requester's NAT-mapped address as observed by
    /// the relay).
    Connect { ep: SocketAddr },
    /// Refusal reply (0x02): `ep` + 4B error code.
    Failed { ep: SocketAddr, error: HpError },
}

/// Decode failure shapes (broken/alien peer implementations — always
/// "log and ignore", never escalate to a disconnect; every libtorrent
/// malformed branch is a silent return, `bt_peer_connection.cpp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HpDecodeError {
    #[error("payload shorter than sub-op + address-family")]
    Truncated,
    #[error("unknown address family")]
    UnknownAddrType,
    #[error("unknown message type")]
    UnknownMsgType,
    #[error("failed payload missing 4-byte error code")]
    TruncatedError,
}

impl UtHolepunch {
    fn type_byte(&self) -> u8 {
        match self {
            UtHolepunch::Rendezvous { .. } => 0,
            UtHolepunch::Connect { .. } => 1,
            UtHolepunch::Failed { .. } => 2,
        }
    }

    /// Encode the payload (no ext frame id byte; frame wrapping is done by
    /// PeerTask).
    pub fn encode(&self) -> Vec<u8> {
        let ep_of = |s: &SocketAddr| {
            let mut out = vec![if s.is_ipv4() { AF_INET } else { AF_INET6 }];
            match s.ip() {
                IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
                IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
            }
            out.extend_from_slice(&s.port().to_be_bytes());
            out
        };
        let mut out = vec![self.type_byte()];
        match self {
            UtHolepunch::Rendezvous { ep } | UtHolepunch::Connect { ep } => {
                out.extend_from_slice(&ep_of(ep));
            }
            UtHolepunch::Failed { ep, error } => {
                out.extend_from_slice(&ep_of(ep));
                // 4B big-endian error code (libtorrent bt_peer_connection.cpp
                // `aux::write_uint32`; divergence from the design text's "1B"
                // is noted in the module docs).
                out.extend_from_slice(&(*error as u32).to_be_bytes());
            }
        }
        out
    }

    /// Decode the payload (strict length checks; malformed = Err and the
    /// caller ignores it — libtorrent also returns silently without
    /// disconnecting).
    pub fn decode(payload: &[u8]) -> Result<UtHolepunch, HpDecodeError> {
        // Minimum = sub-op 1B + address family 1B (same as
        // bt_peer_connection.cpp `recv_buffer.size() < 2`).
        let [msg_type, af, rest @ ..] = payload else {
            return Err(HpDecodeError::Truncated);
        };
        let (addr, port_bytes, rest) = match *af {
            AF_INET => {
                let [a, b, c, d, p0, p1, rest @ ..] = rest else {
                    return Err(HpDecodeError::Truncated);
                };
                (IpAddr::from([*a, *b, *c, *d]), [*p0, *p1], rest)
            }
            AF_INET6 => {
                if rest.len() < 18 {
                    return Err(HpDecodeError::Truncated);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rest[..16]);
                (IpAddr::from(octets), [rest[16], rest[17]], &rest[18..])
            }
            // Unknown address family: ignore (bt_peer_connection.cpp return).
            _ => return Err(HpDecodeError::UnknownAddrType),
        };
        let ep = SocketAddr::new(addr, u16::from_be_bytes(port_bytes));
        match *msg_type {
            0 => {
                if !rest.is_empty() {
                    return Err(HpDecodeError::Truncated);
                }
                Ok(UtHolepunch::Rendezvous { ep })
            }
            1 => {
                if !rest.is_empty() {
                    return Err(HpDecodeError::Truncated);
                }
                Ok(UtHolepunch::Connect { ep })
            }
            2 => {
                // `failed` appends exactly 4 bytes of error code; short or
                // extra = drop the whole message (bt_peer_connection.cpp
                // `end - ptr < 4 -> return`; the trailing-bytes rejection is
                // this codebase's tightening, consistent with the strict
                // frame-length policy).
                let [e0, e1, e2, e3] = rest else {
                    return Err(HpDecodeError::TruncatedError);
                };
                let raw = u32::from_be_bytes([*e0, *e1, *e2, *e3]);
                // Unknown error codes are tolerated for logging: libtorrent
                // only logs and never acts; known values are mapped, unknown
                // ones become a NoError placeholder so the raw value shows
                // up in logs (the decode layer does not drop well-formed
                // messages).
                Ok(UtHolepunch::Failed {
                    ep,
                    error: HpError::from_u32(raw).unwrap_or(HpError::NoError),
                })
            }
            // Unknown sub-operation: ignore (bt_peer_connection.cpp).
            _ => Err(HpDecodeError::UnknownMsgType),
        }
    }
}

/// Relay-decision outcome (libtorrent `on_holepunch` rendezvous arm's four
/// branches, `bt_peer_connection.cpp`; check order = not_connected ->
/// no_support -> no_self -> introduce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAction {
    /// Two-way dial instruction: send connect(target ep) to the requester
    /// and connect(requester's mapped address) to the target. Both
    /// addresses belong to the relay's currently live handshakes —
    /// structurally no blind forwarding (anti-abuse property; same gate as
    /// libtorrent's find_peer check).
    Introduce,
    /// failed(not_connected): the relay is not connected to the target.
    ReplyNotConnected,
    /// failed(no_support): the target connection did not negotiate
    /// ut_holepunch.
    ReplyNoSupport,
    /// failed(no_self): the target is the requester's own connection.
    ReplyNoSelf,
}

/// Relay decision (pure function; `target` = (target connection cuid,
/// whether that connection negotiated ut_holepunch). None = the relay has
/// no connection to that ep).
pub fn relay_decision(requester: u64, target: Option<(u64, bool)>) -> RelayAction {
    match target {
        None => RelayAction::ReplyNotConnected,
        // Check order mirrors libtorrent: no_support before no_self (a
        // requester has necessarily negotiated, so the order is not
        // observable here; the upstream order is kept anyway).
        Some((_, false)) => RelayAction::ReplyNoSupport,
        Some((cuid, true)) if cuid == requester => RelayAction::ReplyNoSelf,
        Some(_) => RelayAction::Introduce,
    }
}

/// Bookkeeping capacity cap (bounded): shared by the failed-address book
/// and the introducer book — same magnitude as [`crate::redial`]
/// REDIAL_POOL_CAP (redial pool 512); holepunch targets are the
/// PEX-introduced subset of that, so 512 covers a single swarm's peak
/// discovery set.
pub const HOLEPUNCH_BOOK_CAP: usize = 512;

/// Entry lifetime (shared by the failure and introducer memories):
/// announce-interval magnitude (past the window the tracker re-supplies
/// addresses and PEX re-discovers, so stale entries add nothing);
/// libtorrent has no explicit equivalent (its introducer state lives in the
/// connection's ut_pex store and dies with the connection).
pub const HOLEPUNCH_ENTRY_TTL: Duration = Duration::from_secs(1800);

/// Backoff between rendezvous asks for the same target (trigger throttle):
/// libtorrent throttles implicitly via its connect-retry cadence (holepunch
/// mode fast_reconnect, `peer_connection.cpp`); this is explicit — same
/// value as `crate::redial::REDIAL_BASE` (60s), keeping "holepunch asks no
/// faster than redial asks".
pub const RENDEZVOUS_ASK_BACKOFF: Duration = Duration::from_secs(60);

/// Hole-punch trigger bookkeeping (owned by the engine main loop, no shared
/// locks; time is injected throughout, tests never sleep):
/// - `failed`: outbound addresses that **actually exhausted their dial
///   plan** (the trigger gate — bookkeeping for "only addresses with a
///   real handshake failure"; removed on successful connect);
/// - `introduced`: ut_pex-delivered address -> delivering connection cuid
///   (same bookkeeping as libtorrent's `find_introducer`, `torrent.cpp`);
/// - `next_ask`: per-target rendezvous backoff (window not elapsed =
///   the trigger is ignored).
#[derive(Debug, Default)]
pub struct HolepunchBook {
    failed: HashMap<SocketAddr, Instant>,
    introduced: HashMap<SocketAddr, (u64, Instant)>,
    next_ask: HashMap<SocketAddr, Instant>,
    cap: usize,
}

impl HolepunchBook {
    pub fn new(cap: usize) -> HolepunchBook {
        HolepunchBook {
            cap: cap.max(1),
            ..HolepunchBook::default()
        }
    }

    /// Dial plan exhausted (real direct-connect failure): register/refresh
    /// the failure memory (arms the trigger gate).
    pub fn note_dial_failed(&mut self, addr: SocketAddr, now: Instant) {
        self.prune(now);
        if !self.failed.contains_key(&addr) && self.failed.len() >= self.cap {
            // Evict the oldest failure entry (bounded; the introducer book
            // is independent).
            if let Some(oldest) = self
                .failed
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(k, _)| *k)
            {
                self.failed.remove(&oldest);
            }
        }
        self.failed.insert(addr, now);
    }

    /// Dial succeeded (connection established): clear the failure memory
    /// and the backoff together.
    pub fn note_dial_connected(&mut self, addr: &SocketAddr) {
        self.failed.remove(addr);
        self.next_ask.remove(addr);
    }

    /// ut_pex-delivered address (`from` = delivering connection cuid):
    /// first-wins — libtorrent's introducer semantics are "the connection
    /// that delivered this address"; repeated announcements from other
    /// sources do not overwrite (consistent with [`crate::pex::PexMessage`]
    /// idempotent consumption).
    pub fn note_introduced(&mut self, addr: SocketAddr, from: u64, now: Instant) {
        self.prune(now);
        if self.introduced.contains_key(&addr) {
            return;
        }
        if self.introduced.len() >= self.cap
            && let Some(oldest) = self
                .introduced
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(k, _)| *k)
        {
            self.introduced.remove(&oldest);
        }
        self.introduced.insert(addr, (from, now));
    }

    /// Trigger decision: `addr` really failed direct dialing AND a live
    /// introducer exists AND the backoff has elapsed -> `Some(introducer
    /// cuid)` (and records the backoff); otherwise None (out-of-window asks
    /// are ignored, not re-queued — libtorrent fires and forgets at its
    /// trigger point, `peer_connection.cpp`).
    pub fn failed_targets(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.prune(now);
        self.failed.keys().copied().collect()
    }
    pub fn remove_introducer(&mut self, connection: u64) {
        self.introduced.retain(|_, (from, _)| *from != connection);
    }
    pub fn introducer(&mut self, address: &SocketAddr, now: Instant) -> Option<u64> {
        self.prune(now);
        if !self.failed.contains_key(address) {
            return None;
        }
        self.introduced.get(address).map(|(from, _)| *from)
    }
    pub fn rendezvous_target(&mut self, addr: &SocketAddr, now: Instant) -> Option<u64> {
        self.prune(now);
        if !self.failed.contains_key(addr) {
            return None;
        }
        if self.next_ask.get(addr).is_some_and(|at| *at > now) {
            return None;
        }
        let (cuid, _) = *self.introduced.get(addr)?;
        self.next_ask.insert(*addr, now + RENDEZVOUS_ASK_BACKOFF);
        Some(cuid)
    }

    /// TTL sweep (run at every entry point; entry counts are <= cap, so a
    /// full scan per call is cheap).
    fn prune(&mut self, now: Instant) {
        self.failed
            .retain(|_, at| now.duration_since(*at) < HOLEPUNCH_ENTRY_TTL);
        self.introduced
            .retain(|_, (_, at)| now.duration_since(*at) < HOLEPUNCH_ENTRY_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(oct: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from(oct), port)
    }

    fn v6(segs: [u16; 8], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from(segs), port)
    }

    /// Encode vectors (table-driven; source = libtorrent
    /// `write_holepunch_msg` write order: type -> addr-type -> endpoint ->
    /// [uint32 error]).
    #[test]
    fn encode_vectors() {
        let rows: [(UtHolepunch, Vec<u8>); 5] = [
            // rendezvous v4: 203.0.113.5:6881 (6881 = 0x1AE1).
            (
                UtHolepunch::Rendezvous {
                    ep: v4([203, 0, 113, 5], 6881),
                },
                vec![0x00, 0x00, 203, 0, 113, 5, 0x1A, 0xE1],
            ),
            // connect v6: [2001:db8::1]:6882 (6882 = 0x1AE2).
            (
                UtHolepunch::Connect {
                    ep: v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], 6882),
                },
                {
                    let mut v = vec![0x01, 0x01];
                    v.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]);
                    v.extend_from_slice(&6882u16.to_be_bytes());
                    v
                },
            ),
            // failed v4 + error 2 (not_connected): 4B big-endian — the
            // divergence from the design text's "1B code" is noted in the
            // module docs.
            (
                UtHolepunch::Failed {
                    ep: v4([192, 0, 2, 7], 51413),
                    error: HpError::NotConnected,
                },
                vec![0x02, 0x00, 192, 0, 2, 7, 0xC8, 0xD5, 0, 0, 0, 2],
            ),
            // failed no_support (3).
            (
                UtHolepunch::Failed {
                    ep: v4([192, 0, 2, 7], 51413),
                    error: HpError::NoSupport,
                },
                vec![0x02, 0x00, 192, 0, 2, 7, 0xC8, 0xD5, 0, 0, 0, 3],
            ),
            // failed no_self (4).
            (
                UtHolepunch::Failed {
                    ep: v4([198, 51, 100, 9], 1),
                    error: HpError::NoSelf,
                },
                vec![0x02, 0x00, 198, 51, 100, 9, 0, 1, 0, 0, 0, 4],
            ),
        ];
        for (i, (msg, want)) in rows.into_iter().enumerate() {
            assert_eq!(msg.encode(), want, "vector #{i}");
        }
    }

    /// Decode vectors (table-driven) + roundtrip self-consistency (v4/v6 x
    /// three sub-ops).
    #[test]
    fn decode_vectors_and_roundtrip() {
        let rows: [(UtHolepunch, Vec<u8>); 3] = [
            (
                UtHolepunch::Rendezvous {
                    ep: v4([203, 0, 113, 5], 6881),
                },
                vec![0x00, 0x00, 203, 0, 113, 5, 0x1A, 0xE1],
            ),
            (
                UtHolepunch::Connect {
                    ep: v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1], 6882),
                },
                {
                    let mut v = vec![0x01, 0x01];
                    v.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]);
                    v.extend_from_slice(&6882u16.to_be_bytes());
                    v
                },
            ),
            (
                UtHolepunch::Failed {
                    ep: v4([192, 0, 2, 7], 51413),
                    error: HpError::NoSuchPeer,
                },
                vec![0x02, 0x00, 192, 0, 2, 7, 0xC8, 0xD5, 0, 0, 0, 1],
            ),
        ];
        for (i, (msg, bytes)) in rows.into_iter().enumerate() {
            assert_eq!(UtHolepunch::decode(&bytes), Ok(msg), "decode #{i}");
            assert_eq!(
                UtHolepunch::decode(&msg.encode()),
                Ok(msg),
                "roundtrip #{i}"
            );
        }
    }

    /// Malformed inputs (same policy as libtorrent's silent returns:
    /// ignore, do not disconnect).
    #[test]
    fn malformed_inputs_ignored() {
        let rows: [(HpDecodeError, Vec<u8>); 6] = [
            (HpDecodeError::Truncated, vec![]),     // no sub-op
            (HpDecodeError::Truncated, vec![0x00]), // no address family
            (HpDecodeError::Truncated, vec![0x00, 0x00, 203, 0, 113]), // v4 address truncated
            (HpDecodeError::Truncated, vec![0x00, 0x01, 0x20]), // v6 truncated
            (
                HpDecodeError::UnknownAddrType,
                vec![0x00, 0x02, 1, 2, 3, 4, 0, 1],
            ), // bad family code
            (
                HpDecodeError::UnknownMsgType,
                vec![0x03, 0x00, 1, 2, 3, 4, 0, 1],
            ), // bad sub-op
        ];
        for (i, (want, bytes)) in rows.into_iter().enumerate() {
            assert_eq!(UtHolepunch::decode(&bytes), Err(want), "case #{i}");
        }
        // failed error code shorter than 4B: whole message ignored
        // (bt_peer_connection.cpp).
        assert_eq!(
            UtHolepunch::decode(&[0x02, 0x00, 192, 0, 2, 7, 0xC8, 0xD5, 0, 0, 0]),
            Err(HpDecodeError::TruncatedError)
        );
        // Trailing extra bytes rejected (strict length — this codebase's
        // tightening; peer garbage frames are not silently swallowed).
        assert!(UtHolepunch::decode(&[0x00, 0x00, 203, 0, 113, 5, 0x1A, 0xE1, 0xFF]).is_err());
    }

    /// Relay-decision table (libtorrent on_holepunch four-branch order,
    /// bt_peer_connection.cpp).
    #[test]
    fn relay_decision_table() {
        #[expect(
            clippy::type_complexity,
            reason = "decision-table rows carry Option<(u64, bool)> payloads inline; a row struct would outgrow the table"
        )]
        let rows: [(u64, Option<(u64, bool)>, RelayAction); 5] = [
            // Target not connected -> not_connected.
            (7, None, RelayAction::ReplyNotConnected),
            // Target did not negotiate holepunch -> no_support (before
            // no_self).
            (7, Some((7, false)), RelayAction::ReplyNoSupport),
            // Target is the requester -> no_self.
            (7, Some((7, true)), RelayAction::ReplyNoSelf),
            // Normal introduction.
            (7, Some((9, true)), RelayAction::Introduce),
            (9, Some((7, true)), RelayAction::Introduce),
        ];
        for (i, (requester, target, want)) in rows.into_iter().enumerate() {
            assert_eq!(relay_decision(requester, target), want, "case #{i}");
        }
    }

    /// Trigger-decision table (rendezvous_target): failure gate / backoff
    /// gate / TTL gate / introducer gate, each table-driven.
    #[test]
    fn rendezvous_target_gates_table() {
        let t0 = Instant::now();
        let target = v4([203, 0, 113, 30], 6881);
        let mut book = HolepunchBook::new(HOLEPUNCH_BOOK_CAP);

        // No failure memory: no trigger (only addresses with a real
        // direct-dial failure).
        book.note_introduced(target, 11, t0);
        assert_eq!(book.rendezvous_target(&target, t0), None);

        // Failure + introducer: triggers and returns the introducer cuid.
        book.note_dial_failed(target, t0);
        assert_eq!(book.rendezvous_target(&target, t0), Some(11));

        // Backoff gate: ignored within 60s (ignore rather than retry-storm).
        assert_eq!(
            book.rendezvous_target(&target, t0 + Duration::from_secs(59)),
            None
        );
        assert_eq!(
            book.rendezvous_target(&target, t0 + RENDEZVOUS_ASK_BACKOFF),
            Some(11)
        );

        // Connect succeeded: failure memory cleared, never triggers again.
        book.note_dial_connected(&target);
        assert_eq!(
            book.rendezvous_target(&target, t0 + RENDEZVOUS_ASK_BACKOFF * 2),
            None
        );

        // No introducer (failure known but nobody PEXed the address): no
        // trigger (conservative introducer-only; libtorrent sends nothing
        // when find_introducer is None, peer_connection.cpp).
        let lonely = v4([203, 0, 113, 31], 6881);
        book.note_dial_failed(lonely, t0);
        assert_eq!(book.rendezvous_target(&lonely, t0), None);
    }

    /// Book TTL: failure/introducer memories expire past the window (no
    /// triggers after the announce-magnitude window).
    #[test]
    fn book_entries_expire() {
        let t0 = Instant::now();
        let target = v4([203, 0, 113, 32], 6881);
        let mut book = HolepunchBook::new(HOLEPUNCH_BOOK_CAP);
        book.note_dial_failed(target, t0);
        book.note_introduced(target, 5, t0);
        assert_eq!(book.rendezvous_target(&target, t0), Some(5));
        // After the backoff window (2xTTL) the entries have TTL-expired: no
        // trigger.
        let late = t0 + HOLEPUNCH_ENTRY_TTL * 2 + RENDEZVOUS_ASK_BACKOFF;
        assert_eq!(book.rendezvous_target(&target, late), None);
    }

    /// Bounded eviction: introducer and failure books each evict their
    /// oldest entry within cap (independently of each other).
    #[test]
    fn book_cap_evicts_oldest() {
        let t0 = Instant::now();
        let a = v4([203, 0, 113, 40], 1);
        let b = v4([203, 0, 113, 41], 2);
        let c = v4([203, 0, 113, 42], 3);
        let mut book = HolepunchBook::new(2);
        // Both books hold a/b; the third address c's introduction evicts
        // the oldest a (introducer book).
        book.note_dial_failed(a, t0);
        book.note_dial_failed(b, t0 + Duration::from_secs(10));
        book.note_introduced(a, 1, t0);
        book.note_introduced(b, 2, t0 + Duration::from_secs(10));
        book.note_introduced(c, 3, t0 + Duration::from_secs(20));
        // a: failure memory still present but introducer evicted -> no
        // trigger.
        assert_eq!(
            book.rendezvous_target(&a, t0 + Duration::from_secs(30)),
            None
        );
        // b: failure + introducer intact -> triggers (introducer cuid
        // returned).
        assert_eq!(
            book.rendezvous_target(&b, t0 + Duration::from_secs(30)),
            Some(2)
        );
        // c: introducer present, failure memory missing -> no trigger;
        // after registering the failure it triggers.
        assert_eq!(
            book.rendezvous_target(&c, t0 + Duration::from_secs(30)),
            None
        );
        // Failure book full (a/b) -> c's entry evicts the oldest a (failure
        // book); introducer book unaffected.
        book.note_dial_failed(c, t0 + Duration::from_secs(40));
        assert_eq!(
            book.rendezvous_target(&c, t0 + Duration::from_secs(50)),
            Some(3),
            "new failure + live introducer"
        );
        // a: failure memory evicted -> never triggers (its introducer was
        // evicted too; both gates unsatisfied).
        assert_eq!(
            book.rendezvous_target(&a, t0 + Duration::from_secs(50)),
            None
        );
    }
}

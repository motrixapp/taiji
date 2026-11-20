//! Built-in connection classes (local / tcp / utp) — the minimal
//! peer-class layer.
//!
//! Three fixed classes, no user-defined ones and no bitmask filter
//! surface: assignment is written directly at the two decision points
//! (the choke round and connection admission) plus the observation tick.
//! Two orthogonal assignment dimensions, mirroring libtorrent's session
//! built-ins (`src/session_impl.cpp:660-678`: the session pre-creates
//! `global`/`tcp`/`local`; two of its default policies are borrowed
//! here):
//!
//! - **address dimension**: an address inside the libtorrent default
//!   "local networks" table ([`is_local_address`]) assigns the `local`
//!   class — the table is reproduced segment-for-segment
//!   (`src/session_impl.cpp:357-400`, `init_peer_class_filter`);
//! - **transport dimension**: the connection's `bt::utp::Transport`
//!   assigns `utp` vs `tcp` (libtorrent maps TCP/SSL-TCP to the tcp
//!   class and keeps uTP out of it, `src/session_impl.cpp:672-678`).
//!
//! Composition: a connection is exactly one class for counting; for
//! policy the address dimension wins — a local uTP peer is `local`
//! (libtorrent unions class sets and the local class carries the
//! policy; collapsing to one class keeps the counting face
//! unambiguous).
//!
//! Policies hung off the classes (both default-on, `BH_PEER_CLASS=0`
//! rolls both back bit-for-bit):
//!
//! - `local`: exempt from unchoke-slot competition
//!   (`ignore_unchoke_slots = true`, "local peers are always unchoked",
//!   `src/session_impl.cpp:663-667`; enforced in `choke.rs`) and a
//!   connection budget of `ceil(cap x BH_LOCAL_CONN_FACTOR / 100)`
//!   (`connection_limit_factor = 150`, "allowed to exceed the normal
//!   connection limit by 50%", `src/session_impl.cpp:668-671`; the
//!   inbound-limit factor composition is `src/session_impl.cpp:3233-3250`;
//!   enforced in `run::state`/`run::dial`);
//! - `utp`: an independent connection budget `BH_UTP_MAX_PEERS` (default
//!   = the single total budget — the channel never binds until tuned;
//!   uTP is governed separately from TCP, the second borrowed policy).
//!
//! Layering note: the function lives engine-side (the only consumer
//! crate; `taiji-bt` is a frozen Phase A surface and the classification
//! is engine policy, not protocol knowledge). Reuse of the transport
//! enum is read-only (`taiji_bt::utp::Transport`).

use std::net::{IpAddr, SocketAddr};

use taiji_bt::utp::Transport;

/// The built-in connection classes (fixed set; `taiji_peers_by_class`
/// label range — local wins over the transport dimension for policy,
/// see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerClass {
    /// LAN/loopback address (the libtorrent default local-networks
    /// table, [`is_local_address`]).
    Local,
    /// Non-local TCP transport (libtorrent's tcp class).
    Tcp,
    /// Non-local uTP transport (uTP is not in the tcp class).
    Utp,
}

impl PeerClass {
    /// Label text (the `taiji_peers_by_class{class=...}` value range +
    /// the admission-drop log field).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PeerClass::Local => "local",
            PeerClass::Tcp => "tcp",
            PeerClass::Utp => "utp",
        }
    }
}

/// The v4 local-networks table (inclusive ranges), segment-for-segment
/// the libtorrent default peer-class filter: RFC1918 private nets +
/// link-local + loop-back (`src/session_impl.cpp:362-374`,
/// `init_peer_class_filter(true)`; range bounds verbatim from the
/// `v4_classes` array).
const LOCAL_V4: [([u8; 4], [u8; 4]); 5] = [
    // 10.0.0.0 - 10.255.255.255 (10/8, RFC1918)
    ([10, 0, 0, 0], [10, 255, 255, 255]),
    // 172.16.0.0 - 172.31.255.255 (172.16/12, RFC1918)
    ([172, 16, 0, 0], [172, 31, 255, 255]),
    // 192.168.0.0 - 192.168.255.255 (192.168/16, RFC1918)
    ([192, 168, 0, 0], [192, 168, 255, 255]),
    // 169.254.0.0 - 169.254.255.255 (link-local, RFC3927)
    ([169, 254, 0, 0], [169, 254, 255, 255]),
    // 127.0.0.0 - 127.255.255.255 (loop-back, RFC1122)
    ([127, 0, 0, 0], [127, 255, 255, 255]),
];

/// The v6 local-networks table (inclusive ranges), segment-for-segment
/// the libtorrent default filter (`src/session_impl.cpp:376-384`,
/// `v6_classes` array): ULA fc00::/7, link-local fe80::/10, loop-back
/// ::1.
const LOCAL_V6: [([u8; 16], [u8; 16]); 3] = [
    // fc00:: - fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff (fc00::/7, ULA)
    (
        [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ],
    ),
    // fe80:: - febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff (fe80::/10)
    (
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [
            0xfe, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ],
    ),
    // ::1 (loop-back, RFC4291)
    (
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    ),
];

/// Local (LAN/loopback) address classification — a table-driven pure
/// predicate over the libtorrent default local-networks segments (see
/// [`LOCAL_V4`]/[`LOCAL_V6`]).
///
/// v4-mapped v6 wrappers (`::ffff:a.b.c.d`) normalize to their v4 form
/// first (same rationale as `addr_hygiene`: classification, not the
/// wrapper encoding, decides; libtorrent makes the same conversion at
/// the peer-class filter boundary).
pub(crate) fn is_local_address(addr: &SocketAddr) -> bool {
    is_local_ip(&addr.ip())
}

/// `is_local_address` on the IP alone (the counting/policy callers hold
/// an [`IpAddr`], not a socket endpoint).
pub(crate) fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => LOCAL_V4
            .iter()
            .any(|&(lo, hi)| v4.octets() >= lo && v4.octets() <= hi),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // Mapped wrapper: classify the v4 form (see the function doc).
            Some(v4) => is_local_ip(&IpAddr::V4(v4)),
            None => LOCAL_V6
                .iter()
                .any(|&(lo, hi)| v6.octets() >= lo && v6.octets() <= hi),
        },
    }
}

/// Class assignment for one connection (exactly one class; the address
/// dimension wins over the transport dimension — a local uTP peer is
/// `local`, matching libtorrent's local-class policy precedence).
///
/// `None` inputs are the honest counting fallbacks of a
/// not-yet-registered / test-fixture row: no address = not local, no
/// meta = transport unknown = the tcp class (pre-µTP default shape).
pub(crate) fn classify(ip: Option<IpAddr>, transport: Option<Transport>) -> PeerClass {
    if ip.is_some_and(|ip| is_local_ip(&ip)) {
        PeerClass::Local
    } else if transport == Some(Transport::Utp) {
        PeerClass::Utp
    } else {
        PeerClass::Tcp
    }
}

/// Class assignment at a socket endpoint (the admission arms' form:
/// both dimensions fully known — [`is_local_address`] + the arm's
/// transport).
pub(crate) fn classify_endpoint(addr: &SocketAddr, transport: Transport) -> PeerClass {
    if is_local_address(addr) {
        PeerClass::Local
    } else if transport == Transport::Utp {
        PeerClass::Utp
    } else {
        PeerClass::Tcp
    }
}

/// Local-class connection budget: `ceil(max x factor_pct / 100)`
/// (`connection_limit_factor` composition — libtorrent scales the
/// connections limit by `100 / factor`, `src/session_impl.cpp:3244-3250`;
/// ceil keeps a fractional budget (55 x 1.5 = 82.5) from truncating
/// away a full connection slot). u128 intermediate: the hard cap may be
/// `usize::MAX` (the CLI override ceiling) and 150% of that overflows
/// u64 arithmetic.
pub(crate) fn local_budget(max: usize, factor_pct: u64) -> usize {
    let v = (max as u128 * factor_pct as u128).div_ceil(100);
    v.min(usize::MAX as u128) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(s: &str) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(s.parse::<Ipv4Addr>().unwrap_or_else(|e| panic!("{e}"))),
            6881,
        )
    }

    fn v6(s: &str) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(s.parse::<Ipv6Addr>().unwrap_or_else(|e| panic!("{e}"))),
            6881,
        )
    }

    /// The libtorrent default local-networks table, segment-for-segment
    /// (`src/session_impl.cpp:362-384`): both inclusive bounds of every
    /// v4 segment (10/8, 172.16/12, 192.168/16, 169.254/16, 127/8) and
    /// every v6 segment (fc00::/7, fe80::/10, ::1) classify local;
    /// representative interiors too. The port plays no role.
    #[test]
    fn is_local_address_table() {
        let local = [
            // 10/8 (bounds + interior).
            v4("10.0.0.0"),
            v4("10.255.255.255"),
            v4("10.1.2.3"),
            // 172.16/12 (bounds + interior + both edge /16s).
            v4("172.16.0.0"),
            v4("172.31.255.255"),
            v4("172.16.0.1"),
            v4("172.31.0.1"),
            v4("172.20.30.40"),
            // 192.168/16 (bounds + interior).
            v4("192.168.0.0"),
            v4("192.168.255.255"),
            v4("192.168.1.1"),
            // 169.254/16 link-local (bounds + interior).
            v4("169.254.0.0"),
            v4("169.254.255.255"),
            v4("169.254.7.7"),
            // 127/8 loop-back (bounds + interior; the whole /8, not just
            // 127.0.0.1).
            v4("127.0.0.0"),
            v4("127.255.255.255"),
            v4("127.0.0.1"),
            v4("127.4.5.6"),
            // fc00::/7 ULA (fc00 and fdff bounds + fd interior).
            v6("fc00::"),
            v6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            v6("fd00::1"),
            // fe80::/10 link-local (bounds + interior).
            v6("fe80::"),
            v6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            v6("fe80::1"),
            v6("fea9::2"),
            // ::1 loop-back.
            v6("::1"),
        ];
        for a in local {
            assert!(is_local_address(&a), "must classify local: {a}");
        }
        // The port never flips the verdict.
        let mut other_port = v4("10.0.0.9");
        other_port.set_port(1);
        assert!(is_local_address(&other_port));
    }

    /// Non-local negatives: every just-outside boundary of the table
    /// plus representative public v4/v6 addresses (a range table must
    /// reject its edges' neighbors, not just obvious globals).
    #[test]
    fn is_local_address_negatives_table() {
        let not_local = [
            // Below/above 10/8.
            v4("9.255.255.255"),
            v4("11.0.0.0"),
            // 172.15/16 (below the /12) and 172.32/16 (above).
            v4("172.15.255.255"),
            v4("172.32.0.0"),
            // 192.167/16 and 192.169/16.
            v4("192.167.255.255"),
            v4("192.169.0.0"),
            // Link-local neighbors.
            v4("169.253.255.255"),
            v4("169.255.0.0"),
            // Loop-back neighbor (126/8 is not 127/8).
            v4("126.255.255.255"),
            v4("128.0.0.0"),
            // Public / special v4 outside the table (CGN 100.64/10 is
            // not in libtorrent's local table either).
            v4("8.8.8.8"),
            v4("1.1.1.1"),
            v4("100.64.0.1"),
            v4("0.0.0.0"),
            v4("255.255.255.255"),
            // v6: below fc00::/7, fe00::, fe7f (below fe80::/10),
            // fec0:: (site-local, above the /10 — not in the table),
            // 2001:db8 (documentation), public 2606::.
            v6("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            v6("fe00::1"),
            v6("fe7f::1"),
            v6("fec0::1"),
            v6("2001:db8::1"),
            v6("2606:4700::1111"),
            // Unspecified v6.
            v6("::"),
        ];
        for a in not_local {
            assert!(!is_local_address(&a), "must NOT classify local: {a}");
        }
    }

    /// v4-mapped v6 wrappers classify by their v4 form (normalization,
    /// not the wrapper encoding — same stance as addr_hygiene).
    #[test]
    fn is_local_address_mapped_v6_normalizes() {
        assert!(is_local_address(&v6("::ffff:10.0.0.5")));
        assert!(is_local_address(&v6("::ffff:127.0.0.1")));
        assert!(!is_local_address(&v6("::ffff:8.8.8.8")));
    }

    /// Class assignment precedence: address dimension wins — a local
    /// uTP peer is `local`; a public uTP peer is `utp`; everything else
    /// `tcp`. Missing rows fall back honestly (no ip = not local; no
    /// meta = tcp).
    #[test]
    fn classify_precedence_table() {
        let lan = v4("192.168.1.50").ip();
        let wan = v4("203.0.113.7").ip();
        assert_eq!(classify(Some(lan), Some(Transport::Utp)), PeerClass::Local);
        assert_eq!(classify(Some(lan), Some(Transport::Tcp)), PeerClass::Local);
        assert_eq!(classify(Some(wan), Some(Transport::Utp)), PeerClass::Utp);
        assert_eq!(classify(Some(wan), Some(Transport::Tcp)), PeerClass::Tcp);
        // Honest fallbacks of an incomplete row.
        assert_eq!(classify(None, Some(Transport::Utp)), PeerClass::Utp);
        assert_eq!(classify(None, None), PeerClass::Tcp);
        assert_eq!(classify(Some(wan), None), PeerClass::Tcp);
        // Label text (the metrics value range).
        assert_eq!(PeerClass::Local.as_str(), "local");
        assert_eq!(PeerClass::Tcp.as_str(), "tcp");
        assert_eq!(PeerClass::Utp.as_str(), "utp");
        // Endpoint form (the admission arms): the same precedence over a
        // SocketAddr + the arm's transport.
        assert_eq!(
            classify_endpoint(&v6("::ffff:192.168.1.2"), Transport::Utp),
            PeerClass::Local
        );
        assert_eq!(
            classify_endpoint(&v4("203.0.113.7"), Transport::Utp),
            PeerClass::Utp
        );
        assert_eq!(
            classify_endpoint(&v4("203.0.113.7"), Transport::Tcp),
            PeerClass::Tcp
        );
    }

    /// Local budget arithmetic: ceil (fractional budgets keep the whole
    /// slot), exact multiples, factor extremes, and the usize::MAX
    /// overflow guard.
    #[test]
    fn local_budget_table() {
        // Exact multiples (120 x 1.5 = 180; 100 x 1.5 = 150).
        assert_eq!(local_budget(120, 150), 180);
        assert_eq!(local_budget(100, 150), 150);
        // Ceil: 55 x 150% = 82.5 -> 83; 7 x 150% = 10.5 -> 11.
        assert_eq!(local_budget(55, 150), 83);
        assert_eq!(local_budget(7, 150), 11);
        // Factor 100 = no headroom; factor > 100 scales up; 0 is
        // caller-clamped away (the knob floor is 100) but the pure
        // function still returns a sane 0-budget.
        assert_eq!(local_budget(120, 100), 120);
        assert_eq!(local_budget(120, 500), 600);
        assert_eq!(local_budget(120, 0), 0);
        // 1 stays 1 under any factor (ceil of any fraction >= 0 -> the
        // slot count).
        assert_eq!(local_budget(1, 150), 2);
        // Overflow guard: 150% of usize::MAX does not panic and clamps
        // at usize::MAX.
        assert_eq!(local_budget(usize::MAX, 150), usize::MAX);
    }
}

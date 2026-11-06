//! Discovery-source address hygiene.
//!
//! Peer addresses from the four discovery sources — tracker (peers/peers6),
//! DHT (`PeersFound` values), ut_pex (`added`/`added6`), and x.pe — are
//! untrusted input: a malicious tracker or peer can inject v4-mapped IPv6
//! wrappers (`::ffff:a.b.c.d`, riding a v6 carrier past the per-family
//! accounting / ban face's v4 keys) and bogon addresses (loopback /
//! link-local / multicast, probing the local host).
//! [`sanitize_discovered_addr`] is the single decision point: v4-mapped
//! forms normalize to IPv4 endpoints, bogons are rejected.
//!
//! Hard invariants:
//! - Every discovery-source entry (engine tracker/DHT/PEX arms, the
//! outbound-dial choke point `spawn_peer_dial`, the magnet metadata dial
//! `spawn_dial`) must reuse [`sanitize_discovered_addr`]; scattered
//! reimplementations are forbidden.
//! - A rejected address must not enter any derived bookkeeping (discovery
//! counters, dedup tables, introducer records) — zero-pollution
//! admission.
//! - v4 loopback (127.0.0.0/8) is allowed and v6 loopback (::1) is
//! rejected — an intentional divergence, argued in full in
//! docs/design/engine.md.
//! - Self-connect detection is the single predicate [`is_self_endpoint`]
//! (announce port equal AND loopback / unspecified / mapped-loopback /
//! local interface address); the former scattered `is_loopback()`
//! checks converge here. [`LocalIpSet`] enumerates once per process;
//! enumeration failure degrades to an empty set (fail-open to
//! loopback-only).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

use tracing::debug;

/// Discovery-source address hygiene gate (single decision point; reused
/// by every discovery-source entry).
///
/// Returns `Some` = the normalized dialable endpoint (v4-mapped already
/// converted to v4); `None` = rejected (bogon / invalid endpoint; the
/// caller skips it and must NOT enter it into discovery counters, dedup
/// tables, introducer bookkeeping, or any other derived state).
/// Cross-crate consumer: the sole dial gate for the core magnet's four
/// discovery paths; the engine's four arms reuse it with the same
/// semantics.
pub fn sanitize_discovered_addr(addr: SocketAddr) -> Option<SocketAddr> {
    // 1. v4-mapped normalization (RFC 4291 §2.5.5.2): `::ffff:a.b.c.d` is
    // the v6 wrapper of a v4 endpoint; converting back to v4 puts the
    // later classification, the IpGuard v4 rules, and per-family keyed
    // bookkeeping (dedup table / same-IP connected checks) all on the v4
    // face (libtorrent `make_address_v4(v4_mapped, ..)`,
    // bt_peer_connection.cpp).
    let addr = match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        v4 => v4,
    };
    // 2. Ports 0/1: no endpoint semantics (libtorrent peer_list.cpp).
    if addr.port() <= 1 {
        return None;
    }
    // 3. Bogon classification (per-class rationale in docs/design/engine.md).
    let bogon = match addr.ip() {
        IpAddr::V4(v4) => v4_bogon(v4),
        // v6 reuses the BEP42-side globality classifier (reuse, not a
        // rewrite, by design): security::is_global_v6 excludes
        // unspecified / loopback / link-local / ULA / multicast / mapped /
        // documentation ranges (per-class RFCs in its docs).
        IpAddr::V6(v6) => !taiji_bt::dht::security::is_global_v6(v6),
    };
    if bogon { None } else { Some(addr) }
}

/// v4 bogon classification (true = reject). Per-class rationale in
/// docs/design/engine.md; the ranges match the stable std predicates
/// (`is_reserved` / `is_shared` are still unstable; no invented
/// extensions). v4 loopback is NOT in the reject set (intentional
/// divergence; libtorrent `add_peer`'s reject set has the same shape).
fn v4_bogon(v4: Ipv4Addr) -> bool {
    v4.is_unspecified() || v4.is_link_local() || v4.is_multicast() || v4.is_documentation()
}

// ---- Self-connect detection extension (local address-set snapshot +
// single-point predicate; see docs/design/engine.md) ----

/// Snapshot of every local interface address (enumerated once at process
/// start; the trade-off rationale lives in docs/design/engine.md). Used
/// only for the "address is local" half of self-connect detection — it
/// carries no security semantics: dynamic bans go through the IpGuard
/// snapshot (two independent defenses, both must pass).
#[derive(Debug, Clone, Default)]
pub struct LocalIpSet {
    addrs: HashSet<IpAddr>,
}

impl LocalIpSet {
    /// Enumerates every local interface address (v4-mapped forms are
    /// normalized to v4 before insert — the same family unification as
    /// the hygiene gate). Enumeration failure = an empty set (fail-open
    /// to the original loopback-only semantics; logged at debug, not
    /// disguised as success).
    pub(crate) fn enumerate() -> LocalIpSet {
        let mut addrs = HashSet::new();
        match if_addrs::get_if_addrs() {
            Ok(ifaces) => {
                for iface in ifaces {
                    addrs.insert(normalize_ip(iface.ip()));
                }
            }
            Err(e) => {
                debug!(
                    target: "taiji::core::engine",
                    %e, "local interface enumeration failed; self-connect guard degrades to loopback-only"
                );
            }
        }
        LocalIpSet { addrs }
    }

    /// Test / explicit construction (no syscall; test-only — production
    /// always goes through the [`Self::enumerate`] / [`Self::shared`]
    /// snapshot path).
    #[cfg(test)]
    pub(crate) fn from_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> LocalIpSet {
        LocalIpSet {
            addrs: addrs.into_iter().map(normalize_ip).collect(),
        }
    }

    /// Whether the address is local (v4-mapped wrappers normalized
    /// before the lookup; families unified).
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        self.addrs.contains(&normalize_ip(ip))
    }

    /// Process-wide shared snapshot (enumerated once on first access;
    /// warmed at session start so the dial hot path only reads —
    /// enumeration is a local syscall, no network IO; rationale in
    /// docs/design/engine.md).
    /// Cross-crate consumer: the core magnet dial gate reuses this
    /// process-level snapshot.
    pub fn shared() -> &'static LocalIpSet {
        static SHARED: OnceLock<LocalIpSet> = OnceLock::new();
        SHARED.get_or_init(LocalIpSet::enumerate)
    }
}

/// v4-mapped wrapper normalization (`::ffff:a.b.c.d` -> v4; family
/// unification, the same step as [`sanitize_discovered_addr`] step 1).
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Self-connect IP predicate (design extension; the original form was
/// `is_loopback`): loopback OR unspecified (`0.0.0.0` / `::` — the
/// observable form of the kernel landing a connection back on the local
/// host) OR a v4-mapped loopback wrapper OR a member of the local
/// interface address set.
pub(crate) fn is_self_connect_ip(ip: IpAddr, local: &LocalIpSet) -> bool {
    let mapped_loopback = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        IpAddr::V4(_) => false,
    };
    ip.is_loopback() || ip.is_unspecified() || mapped_loopback || local.contains(ip)
}

/// Self-connect endpoint predicate (single point): announce port equal
/// AND [`is_self_connect_ip`]. The engine's tracker/DHT/PEX/holepunch
/// arms and the magnet `spawn_dial` all reuse it (the former scattered
/// `port == announce_port && ip.is_loopback()` checks converge here).
pub fn is_self_endpoint(addr: SocketAddr, announce_port: u16, local: &LocalIpSet) -> bool {
    addr.port() == announce_port && is_self_connect_ip(addr.ip(), local)
}

/// Epoch seconds (the clock for IpGuard ban-snapshot checks; the
/// crate-level reuse point matching engine `tracker.rs` — consumed by
/// the magnet metadata-phase dial gate).
pub fn epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use taiji_bt::peer_policy::{FilterRule, IpGuard};

    fn sa(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }
    fn v4(o: [u8; 4], port: u16) -> SocketAddr {
        sa(IpAddr::V4(Ipv4Addr::from(o)), port)
    }
    fn v6(o: [u8; 16], port: u16) -> SocketAddr {
        sa(IpAddr::V6(Ipv6Addr::from(o)), port)
    }
    fn mapped(o: [u8; 4], port: u16) -> SocketAddr {
        v6(
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2], o[3],
            ],
            port,
        )
    }

    /// Hygiene classification vector table (table-driven; per-vector
    /// rationale in the docs/design/engine.md classification table).
    #[test]
    fn sanitize_classification_vector_table() {
        // ---- reject: all v4 bogon classes ----
        let rejected_v4: &[([u8; 4], &'static str)] = &[
            ([0, 0, 0, 0], "unspecified RFC1122"),
            ([169, 254, 3, 7], "link-local RFC3927"),
            ([224, 0, 0, 1], "multicast RFC1112"),
            ([239, 255, 255, 250], "multicast in-segment RFC1112"),
            ([192, 0, 2, 1], "TEST-NET-1 RFC5737"),
            ([198, 51, 100, 7], "TEST-NET-2 RFC5737"),
            ([203, 0, 113, 9], "TEST-NET-3 RFC5737"),
        ];
        for (oct, why) in rejected_v4 {
            assert!(
                sanitize_discovered_addr(v4(*oct, 6881)).is_none(),
                "{oct:?} must be rejected ({why})"
            );
        }
        // ---- reject: all v6 bogon classes (reuses is_global_v6 semantics) ----
        let rejected_v6: &[([u8; 16], &'static str)] = &[
            ([0; 16], "unspecified RFC4291"),
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "loopback ::1 RFC4291",
            ),
            (
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "link-local fe80::/10 RFC4291",
            ),
            (
                [0xfe, 0xbf, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "link-local upper edge RFC4291",
            ),
            (
                [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "multicast ff02::1 RFC4291",
            ),
            (
                [0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "ULA fc00::/7 RFC4193",
            ),
            (
                [0xfd, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "ULA fd00::/8 RFC4193",
            ),
            (
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "documentation 2001:db8::/32 RFC3849",
            ),
        ];
        for (oct, why) in rejected_v6 {
            assert!(
                sanitize_discovered_addr(v6(*oct, 6881)).is_none(),
                "v6 {:02x?} must be rejected ({why})",
                &oct[..4]
            );
        }
        // ---- reject: ports 0/1 (libtorrent peer_list.cpp) ----
        for port in [0u16, 1] {
            assert!(
                sanitize_discovered_addr(v4([93, 184, 216, 34], port)).is_none(),
                "v4 port {port} must be rejected"
            );
            assert!(
                sanitize_discovered_addr(v6(
                    [
                        0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11
                    ],
                    port
                ))
                .is_none(),
                "v6 port {port} must be rejected"
            );
        }
        // ---- allow: normal addresses, zero regression ----
        let global_v6: &[([u8; 16], &'static str)] = &[
            (
                [
                    0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
                ],
                "GUA 2000::/3",
            ),
            (
                [
                    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
                ],
                "GUA 2001::",
            ),
            (
                [
                    0x2a, 0x02, 0x75, 0x2e, 0, 0, 0, 0x18, 0, 0, 0, 0, 0, 0, 0, 2,
                ],
                "GUA 2a00::/3 (adjacent to 2000::/3)",
            ),
            (
                [0x3f, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "2000::/3 upper edge (3fff::)",
            ),
        ];
        for (oct, why) in global_v6 {
            assert!(
                sanitize_discovered_addr(v6(*oct, 6881)).is_some(),
                "v6 {:02x?} must be allowed ({why} — false-positive red line)",
                &oct[..4]
            );
        }
        for (oct, why) in [
            ([93u8, 184, 216, 34], "public v4"),
            ([8, 8, 8, 8], "public v4"),
            (
                [10, 1, 2, 3],
                "RFC1918 10/8 allowed (LAN, in the spirit of the BEP42 exemption)",
            ),
            ([172, 16, 0, 9], "RFC1918 172.16/12 allowed"),
            ([192, 168, 1, 2], "RFC1918 192.168/16 allowed"),
            (
                [100, 64, 1, 1],
                "CGNAT 100.64/10 allowed (absent from the reject list)",
            ),
            // v4 loopback allowed = intentional divergence from the design
            // reject list (full rationale in docs/design/engine.md: libtorrent
            // add_peer's reject set has no v4 loopback, same-host swarms are
            // a real topology, existing regressions must keep passing);
            // v6 loopback (::1) is always rejected (v6 reject vectors above).
            (
                [127, 0, 0, 1],
                "v4 loopback allowed (intentional divergence, same shape as libtorrent)",
            ),
            (
                [127, 255, 1, 2],
                "v4 loopback in-segment allowed (same as above)",
            ),
        ] {
            assert!(
                sanitize_discovered_addr(v4(oct, 6881)).is_some(),
                "{oct:?} must be allowed ({why})"
            );
        }
        // Legal port range allowed (lower edge 2 / common 6881 / max 65535).
        for port in [2u16, 6881, 65535] {
            assert!(sanitize_discovered_addr(v4([93, 184, 216, 34], port)).is_some());
        }
    }

    /// v4-mapped normalization (the mapped-form fix core):
    /// `::ffff:a.b.c.d` is always converted to a v4 endpoint before
    /// classification; mapped wrappers of bogons are rejected too.
    #[test]
    fn v4_mapped_normalized_to_v4_face() {
        // Plain mapped -> v4 form (port preserved).
        let got = sanitize_discovered_addr(mapped([93, 184, 216, 34], 51413))
            .unwrap_or_else(|| panic!("mapped wrapper of a global v4 must be allowed"));
        assert_eq!(
            got,
            v4([93, 184, 216, 34], 51413),
            "after normalization it must be an IPv4 endpoint"
        );
        // Mapped wrappers of bogons: rejected by their v4 class after
        // normalization (v6-class bogons in the reject vectors above; a
        // mapped loopback is allowed like the v4 loopback — intentional
        // divergence; wrapper and literal judged alike = family
        // unification, docs/design/engine.md).
        for (oct, why) in [
            ([0u8, 0, 0, 0], "mapped unspecified"),
            ([224, 0, 0, 1], "mapped multicast"),
            ([169, 254, 9, 9], "mapped link-local"),
        ] {
            assert!(
                sanitize_discovered_addr(mapped(oct, 6881)).is_none(),
                "{oct:?} mapped wrapper must be rejected ({why})"
            );
        }
        // Mapped loopback: normalized onto the v4 face (families
        // unified); the wrapper produces no separate v6 key.
        let mapped_loop =
            sanitize_discovered_addr(mapped([127, 0, 0, 1], 6881)).unwrap_or_else(|| {
                panic!("mapped loopback allowed alongside v4 loopback (intentional divergence, family unification)")
            });
        assert_eq!(
            mapped_loop,
            v4([127, 0, 0, 1], 6881),
            "after normalization, same verdict as the literal v4 form"
        );
        // Non-mapped v6 is unaffected by normalization (no
        // ::ffff:0:0/96 prefix).
        let ulaprefix = v6(
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0x26, 0x06, 0x47, 0x00,
            ],
            6881,
        );
        assert!(sanitize_discovered_addr(ulaprefix).is_some());
    }

    /// Regression PoC for the mapped-form family split: a tracker peers6
    /// entry carrying the mapped form of a banned v4 -> normalized onto
    /// the v4 face -> the IpGuard v4 ban hits and rejects.
    ///
    /// Before the fix: the mapped form flowed through per-family
    /// bookkeeping as a v6 endpoint (dedup table / same-IP connected /
    /// self-connect guard compare `IpAddr` equality) -> family split:
    /// `1.2.3.4` and `::ffff:1.2.3.4` count as two endpoints. After:
    /// discovery normalizes at the entry, so every downstream key lands
    /// on the v4 face.
    #[test]
    fn poc_v6_1_mapped_banned_v4_rejected_via_v4_guard() {
        let banned: IpAddr = "1.2.3.4".parse().unwrap_or_else(|e| panic!("{e}"));
        let guard = IpGuard::new(
            [] as [FilterRule; 0],
            [(
                banned,
                taiji_bt::peer_policy::BanRecord {
                    reason: "test-ban".into(),
                    until: i64::MAX,
                },
            )],
        );
        // Malicious tracker response: peers6 = ::ffff:1.2.3.4:6881.
        let malicious = mapped([1, 2, 3, 4], 6881);
        // After normalization: a v4 endpoint.
        let sanitized = sanitize_discovered_addr(malicious)
            .unwrap_or_else(|| panic!("mapped wrapper must be normalized (not rejected as v6)"));
        assert_eq!(
            sanitized.ip(),
            banned,
            "normalization must land on the banned v4 address itself (family unification)"
        );
        // v4-face IpGuard check: ban hit -> the dial chain rejects at filter point 2.
        let block = guard
            .blocks(sanitized.ip(), 0)
            .unwrap_or_else(|| panic!("the normalized address must be blocked by the v4 ban rule"));
        assert!(
            matches!(block, taiji_bt::peer_policy::IpBlock::Banned(_)),
            "ban category, got {block:?}"
        );
    }

    /// Self-connect predicate vector table (table-driven): loopback (the
    /// original form) + unspecified / v4-mapped loopback / local
    /// interface addresses (new coverage); unequal ports and non-local
    /// addresses are always allowed.
    #[test]
    fn self_endpoint_extended_predicate_vector_table() {
        let local = LocalIpSet::from_addrs([
            "192.168.1.5".parse().unwrap_or_else(|e| panic!("{e}")),
            "fd00::5".parse().unwrap_or_else(|e| panic!("{e}")),
        ]);
        let announce: u16 = 6881;
        let mapped = |o: [u8; 4]| -> IpAddr {
            IpAddr::V6(std::net::Ipv6Addr::from([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2], o[3],
            ]))
        };
        // ---- hit face (announce port equal) ----
        let hit: &[(IpAddr, &str)] = &[
            (
                "127.0.0.1".parse().unwrap_or_else(|e| panic!("{e}")),
                "v4 loopback (original form)",
            ),
            (
                "::1".parse().unwrap_or_else(|e| panic!("{e}")),
                "v6 loopback (original form)",
            ),
            (
                "0.0.0.0".parse().unwrap_or_else(|e| panic!("{e}")),
                "v4 unspecified (new coverage)",
            ),
            (
                "::".parse().unwrap_or_else(|e| panic!("{e}")),
                "v6 unspecified (new coverage)",
            ),
            (
                mapped([127, 0, 0, 1]),
                "mapped loopback wrapper (new coverage)",
            ),
            (
                "192.168.1.5".parse().unwrap_or_else(|e| panic!("{e}")),
                "local interface address",
            ),
            (
                mapped([192, 168, 1, 5]),
                "mapped wrapper of a local address (family unification)",
            ),
            (
                "fd00::5".parse().unwrap_or_else(|e| panic!("{e}")),
                "local v6 ULA interface address",
            ),
        ];
        for (ip, why) in hit {
            assert!(
                is_self_endpoint(SocketAddr::new(*ip, announce), announce, &local),
                "{ip} must be judged self-connect ({why})"
            );
        }
        // ---- allow face ----
        let miss: &[(IpAddr, u16, &str)] = &[
            (
                "10.9.9.9".parse().unwrap_or_else(|e| panic!("{e}")),
                announce,
                "non-local address with equal port (a legitimate peer face)",
            ),
            (
                "192.168.1.5".parse().unwrap_or_else(|e| panic!("{e}")),
                6882,
                "local address but unequal port (peer happens to use an adjacent port)",
            ),
            (
                "127.0.0.1".parse().unwrap_or_else(|e| panic!("{e}")),
                6882,
                "loopback but unequal port (original-form semantics kept)",
            ),
            (
                mapped([10, 9, 9, 9]),
                announce,
                "non-local mapped wrapper with equal port",
            ),
        ];
        for (ip, port, why) in miss {
            assert!(
                !is_self_endpoint(SocketAddr::new(*ip, *port), announce, &local),
                "{ip}:{port} must not be judged self-connect ({why})"
            );
        }
    }

    /// LocalIpSet process enumeration snapshot: on POSIX the loopback
    /// interface always exists (lo0/lo), so enumeration must be
    /// non-empty and contain loopback; mapped wrappers are normalized
    /// before insert (the enumeration face produces no v6 wrapper keys).
    #[test]
    fn local_ip_set_enumerate_contains_loopback() {
        let shared = LocalIpSet::enumerate();
        assert!(
            shared.contains(IpAddr::from([127u8, 0, 0, 1])),
            "the POSIX loopback interface always exists (lo); an empty set = \
             the enumeration-failure face (fail-open semantics)"
        );
    }
}

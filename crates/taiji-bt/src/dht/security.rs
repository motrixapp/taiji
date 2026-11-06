//! DHT security extension (BEP42: node_id bound to the external IP).
//!
//! Mechanism: node ids derive from `crc32c((masked ip) | (r << k))` whose
//! top 21 bits must prefix the id (v4 mask 0x030f3fff over 4B; v6 mask
//! 0x0103070f1f3f7fff over the address's high 64 bits; r is random in
//! [0,7], carried in the last byte's low 3 bits). Enforcement is
//! storage-only: non-matching ids are never stored on but are still
//! serviced and routed; local-network addresses are exempt. CRC32C is a
//! hand-rolled table-driven implementation (no new dependencies),
//! anchored on the standard check value plus the BEP42 test vectors.
//!
//! Upstream anchor mapping: docs/design/dht.md

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

// rand 0.10: `&mut impl Rng` signatures keep the Rng trait; fill/random
// sampling live in RngExt (the old Rng renamed).
use rand::RngExt;

use super::node::{DHT_ID_LENGTH, NodeId};

/// BEP42 IPv4 mask (the byte form of the spec derivation `ip & 0x030f3fff`).
const V4_MASK: [u8; 4] = [0x03, 0x0f, 0x3f, 0xff];
/// BEP42 IPv6 mask (the byte form of the spec derivation
/// `ip & 0x0103070f1f3f7fff`; only the address's high 64 bits are used).
const V6_MASK: [u8; 8] = [0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];

// ---------------------------------------------------------------------------
// CRC32C (Castagnoli, reflected algorithm; hand-rolled table-driven —
// the design forbids adding dependencies)
// ---------------------------------------------------------------------------

/// The reversed form of reflected polynomial 0x1EDC6F41 (CRC-32C standard notation 0x82F63B78).
const CRC32C_POLY_REFLECTED: u32 = 0x82F63B78;

/// 256-entry table (built on first use; construction is a pure function
/// with no concurrently visible intermediate state).
fn table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut crc = i as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ CRC32C_POLY_REFLECTED
                } else {
                    crc >> 1
                };
            }
            *e = crc;
        }
        t
    })
}

/// CRC-32C (Castagnoli): poly 0x1EDC6F41, init 0xFFFFFFFF, reflected
/// in/out, xorout 0xFFFFFFFF — the parameter set of libtorrent
/// `src/crc32c.cpp`'s
/// `boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true>`
/// (byte-sequence processing, matching the input byte order).
pub fn crc32c(data: &[u8]) -> u32 {
    let t = table();
    let mut crc = 0xFFFF_FFFF_u32;
    for &b in data {
        crc = (crc >> 8) ^ t[((crc ^ u32::from(b)) & 0xFF) as usize];
    }
    crc ^ 0xFFFF_FFFF
}

// ---------------------------------------------------------------------------
// BEP42 derivation / verification
// ---------------------------------------------------------------------------

/// The masked CRC input (BEP42 derivation `crc32c((ip & MASK) | (r << k))`):
/// returns the network-order byte sequence and its active length. v4 uses
/// 4B, v6 the address's high 64 bits (8B); `r` occupies the top 3 bits of
/// the first byte (v4: `r << 29`; v6: `r << 61` — both are `r << 5` on
/// byte 0, mirroring node_id.cpp `ip[0] |= (r & 0x7) << 5`).
fn masked_input(ip: IpAddr, r: u8) -> ([u8; 8], usize) {
    let mut buf = [0u8; 8];
    let (mask, n): (&[u8], usize) = match ip {
        IpAddr::V4(v4) => {
            buf[..4].copy_from_slice(&v4.octets());
            (&V4_MASK, 4)
        }
        IpAddr::V6(v6) => {
            buf[..8].copy_from_slice(&v6.octets()[..8]);
            (&V6_MASK, 8)
        }
    };
    for (b, m) in buf.iter_mut().zip(mask) {
        *b &= m;
    }
    buf[0] |= (r & 0x07) << 5;
    (buf, n)
}

/// The BEP42 hash prefix (source of the node_id's top 21 bits):
/// `crc = crc32c(masked(ip, r))`, returning the three bytes
/// `(crc>>24, crc>>16, crc>>8)` (templates for id[0], id[1] and the top 5
/// bits of id[2]). `rand` is the node_id's last byte (its low 3 bits are
/// r, matching verify_id's recomputation from `nid[19]`, node_id.cpp).
fn hash_prefix(ip: IpAddr, rand: u8) -> [u8; 3] {
    let (buf, n) = masked_input(ip, rand);
    let crc = crc32c(&buf[..n]);
    [(crc >> 24) as u8, (crc >> 16) as u8, (crc >> 8) as u8]
}

/// Derives a complete node_id from controlled randomness (the shape of
/// the BEP42 spec's example code; the test-vector reproduction entry
/// point). `rand` = the last byte (low 3 bits are r); `rest` = the
/// remaining randomness: `rest[0] & 0x07` fills the low 3 bits of id[2]
/// (an independent random draw in both the spec and libtorrent), and
/// `rest[1..]` (16B) fills the middle id[3..19].
pub fn derive_node_id(ip: IpAddr, rand: u8, rest: [u8; 17]) -> NodeId {
    let prefix = hash_prefix(ip, rand);
    let mut id = [0u8; DHT_ID_LENGTH];
    id[0] = prefix[0];
    id[1] = prefix[1];
    id[2] = (prefix[2] & 0xf8) | (rest[0] & 0x07);
    id[3..19].copy_from_slice(&rest[1..]);
    id[19] = rand;
    NodeId(id)
}

/// Derives a valid node_id from the local external IP (session start /
/// re-derivation on IP change; libtorrent `generate_id`, node_id.cpp).
pub fn generate_node_id(ip: IpAddr, rng: &mut impl RngExt) -> NodeId {
    let mut rest = [0u8; 17];
    rng.fill(&mut rest);
    derive_node_id(ip, rng.random(), rest)
}

/// BEP42 exempt addresses (verification passes immediately): the spec's
/// enforcement section lists 10/8, 172.16/12, 192.168/16, 169.254/16 and
/// 127/8; the IPv6 forms and 100.64/10 (CGNAT) follow libtorrent
/// `is_local` (src/ip_helpers.cpp) — CGNAT is a libtorrent addition, not
/// in the BEP42 text.
pub fn is_exempt_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 // 10.0.0.0/8
                || (o[0] == 172 && o[1] & 0xf0 == 16) // 172.16.0.0/12
                || (o[0] == 192 && o[1] == 168) // 192.168.0.0/16
                || (o[0] == 169 && o[1] == 254) // 169.254.0.0/16
                || o[0] == 127 // 127.0.0.0/8
                || (o[0] == 100 && o[1] & 0xc0 == 64) // 100.64.0.0/10 (libtorrent addition)
        }
        IpAddr::V6(v6) => {
            // ip_helpers.cpp: loopback/link-local/site-local/multicast (the link/site
            // local shapes) / ULA fc00::/7.
            let o = v6.octets();
            v6.is_loopback() // ::1
                || v6.is_unspecified() // :: (defensive: unverifiable shapes pass)
                || (o[0] == 0xfe && o[1] & 0xc0 == 0x80) // fe80::/10 link-local
                || (o[0] == 0xfe && o[1] & 0xc0 == 0xc0) // fec0::/10 site-local (deprecated, RFC3879)
                || o[0] == 0xff // multicast (includes the link/site-local shapes)
                || (o[0] & 0xfe == 0xfc) // fc00::/7 ULA
        }
    }
}

/// Inbound node_id validity check (libtorrent `verify_id`, node_id.cpp):
/// exempt addresses always pass; otherwise the hash is recomputed with
/// the last byte `id[19]` as r and the top 21 bits compared (id[0], id[1]
/// in full plus the top 5 bits of id[2]).
pub fn verify_node_id(id: &NodeId, source: IpAddr) -> bool {
    if is_exempt_ip(source) {
        return true;
    }
    let prefix = hash_prefix(source, id.0[19]);
    id.0[0] == prefix[0] && id.0[1] == prefix[1] && (id.0[2] & 0xf8) == (prefix[2] & 0xf8)
}

// ---------------------------------------------------------------------------
// External address probing (session-start face; not protocol behavior — a local policy helper)
// ---------------------------------------------------------------------------

/// IPv6 global-unicast test (a local policy definition; std
/// `Ipv6Addr::is_global` is still unstable for v6, so the common
/// non-global shapes are excluded per RFC 4291/6890 scopes: unspecified /
/// loopback / link-local / ULA / multicast / IPv4-mapped / documentation
/// prefix).
pub fn is_global_v6(addr: Ipv6Addr) -> bool {
    let o = addr.octets();
    !(addr.is_unspecified()
        || addr.is_loopback()
        || (o[0] == 0xfe && o[1] & 0xc0 == 0x80) // fe80::/10 link-local
        || (o[0] & 0xfe == 0xfc) // fc00::/7 ULA
        || o[0] == 0xff // ff00::/8 multicast
        || o[..10] == [0u8; 10] && o[10] == 0xff && o[11] == 0xff // ::ffff:0:0/96
        || o[..4] == [0x20, 0x01, 0x0d, 0xb8]) // 2001:db8::/32 documentation prefix
}

/// v6 probe targets (public resolver anycast addresses; the values carry
/// no protocol semantics): connects **race concurrently** (each with its
/// own deadline) and the first success supplies the source (completion
/// order = success order); all failing → None. Multiple targets cover
/// different reachability domains — carriers filter differently, and a
/// single target can time out forever on a filtered network; racing caps
/// the latency at the fastest reachable target's RTT (rather than the sum
/// of serial attempts). The probe is awaited on the engine's assembly
/// critical path (the DHT v6 socket bind-address decision and the BEP7
/// `ipv6=` payload both take the value synchronously), so serial probing
/// of hundreds of milliseconds would squeeze time-sensitive startup
/// budgets. Port = TCP/53 (RFC 1035 section 4.2 requires DNS to be
/// carried over TCP as well; the major public resolvers serve DNS/TCP on
/// their anycast addresses).
const PROBE_TCP_TARGETS_V6: [Ipv6Addr; 3] = [
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x0001),
    Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
];
/// Target port TCP/53 (rationale at [`PROBE_TCP_TARGETS_V6`]).
const PROBE_TCP_PORT: u16 = 53;
/// Per-target TCP connect deadline (not a protocol constant — probe
/// policy): a TCP connect really sends a SYN, and when a target never
/// answers (filtered/lossy) the kernel's retransmit backoff can reach
/// minutes, so an application-level deadline is required; 2s covers the
/// global single-target RTT tail. Under the racing shape the worst case
/// with no answers at all is one 2s timeout (concurrent), absorbed by the
/// callers (startup assembly / actor command paths, all async tasks); the
/// tracker actor additionally rate-limits via a TTL cache.
const PROBE_TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// v6 TCP probe: three targets connect concurrently under deadline; the
/// **first successful** connection's local_addr is the source address
/// (the stream is dropped immediately — the probe carries no data); a
/// local_addr read failure counts as that target failing; the remaining
/// in-flight targets are aborted once one wins (their connections close
/// with the cancelled tasks); all failing → None.
async fn tcp_probe_v6_source() -> Option<IpAddr> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Option<IpAddr>>(PROBE_TCP_TARGETS_V6.len());
    let mut handles = Vec::with_capacity(PROBE_TCP_TARGETS_V6.len());
    for dst in PROBE_TCP_TARGETS_V6 {
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            let target = SocketAddr::new(IpAddr::V6(dst), PROBE_TCP_PORT);
            let source =
                tokio::time::timeout(PROBE_TCP_TIMEOUT, tokio::net::TcpStream::connect(target))
                    .await
                    .ok()
                    .and_then(|conn| conn.ok())
                    .and_then(|stream| stream.local_addr().ok())
                    .map(|local| local.ip());
            // Capacity = target count, at most one message per task: send never waits.
            let _ = tx.send(source).await;
        }));
    }
    drop(tx);
    let mut winner = None;
    for _ in 0..handles.len() {
        match rx.recv().await {
            Some(Some(source)) => {
                winner = Some(source);
                break;
            }
            Some(None) => continue,
            None => break,
        }
    }
    for handle in &handles {
        handle.abort();
    }
    winner
}

/// Probed-source acceptance classification (a pure-function seam, locked
/// by tests; the semantics are preserved, not weakened): loopback /
/// unspecified are always rejected; the v6 face additionally requires
/// global unicast — link-local/ULA addresses cannot be verified by
/// outsiders, so deriving from them is meaningless (a ULA source probed
/// via UDP on a ULA+GUA mixed network is rejected here, same verdict as
/// before); the v4 face keeps the existing rule (an RFC1918 source probed
/// behind NAT is accepted as usual — see the crate::dht module docs
/// divergence list).
fn accept_probed_source(v6: bool, ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return false;
    }
    if v6
        && let IpAddr::V6(v6addr) = ip
        && !is_global_v6(v6addr)
    {
        return false;
    }
    true
}

/// Probes the local outbound source address. v4: a UDP `connect` only
/// consults the route's source address and **sends no packets** (zero
/// change to the wire path). v6: a TCP `connect` probe (multiple targets
/// racing concurrently, first success supplies the source, see
/// [`PROBE_TCP_TARGETS_V6`]) — on ULA+GUA mixed networks the OS may pick
/// a ULA source (not globally routable) for UDP outbound while correctly
/// picking the GUA for TCP outbound, so the UDP connect method would keep
/// yielding a non-global source and v6 bootstrap would be skipped
/// incorrectly; the TCP method matches the host's real outbound behavior.
/// Failure / loopback / unspecified / non-global v6 → None (the caller
/// keeps the status quo: a random or persisted id, matching libtorrent
/// calculate_node_id's "unspecified → random" rule, node.cpp).
pub async fn probe_source_ip(v6: bool) -> Option<IpAddr> {
    let local = if v6 {
        tcp_probe_v6_source().await?
    } else {
        // v4 path unchanged (UDP connect only consults the route source address, sending nothing).
        let bind: SocketAddr = "0.0.0.0:0".parse().ok()?;
        let dst: SocketAddr = "8.8.8.8:80".parse().ok()?;
        let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
        sock.connect(dst).await.ok()?;
        sock.local_addr().ok()?.ip()
    };
    if !accept_probed_source(v6, local) {
        return None;
    }
    Some(local)
}

// ---------------------------------------------------------------------------
// Tests (cross-validation sources in per-test comments)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn v6(octets: [u8; 16]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(octets))
    }

    /// The CRC-32C standard check value (RFC 3720 / the CRC-32C catalogue B.2 check value).
    #[test]
    fn crc32c_matches_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0x0000_0000);
        // 32-byte zero vector (a CRC-32C catalogue vector).
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    /// The 5 vectors from BEP42's "test vectors" section, byte-exact:
    /// IP + rand + the spec's middle random bytes → the full node ID (the
    /// generation face is anchored).
    #[test]
    fn bep42_test_vectors_reproduced() {
        // (IP, rand, spec node ID) — the middle 16B + id[2]'s low 3 bits are the spec's randomness.
        let vectors: &[([u8; 4], u8, [u8; 20])] = &[
            (
                [124, 31, 75, 21],
                0x01,
                [
                    0x5f, 0xbf, 0xbf, 0xf1, 0x0c, 0x5d, 0x6a, 0x4e, 0xc8, 0xa8, 0x8e, 0x4c, 0x6a,
                    0xb4, 0xc2, 0x8b, 0x95, 0xee, 0xe4, 0x01,
                ],
            ),
            (
                [21, 75, 31, 124],
                0x56,
                [
                    0x5a, 0x3c, 0xe9, 0xc1, 0x4e, 0x7a, 0x08, 0x64, 0x56, 0x77, 0xbb, 0xd1, 0xcf,
                    0xe7, 0xd8, 0xf9, 0x56, 0xd5, 0x32, 0x56,
                ],
            ),
            (
                [65, 23, 51, 170],
                0x16,
                [
                    0xa5, 0xd4, 0x32, 0x20, 0xbc, 0x8f, 0x11, 0x2a, 0x3d, 0x42, 0x6c, 0x84, 0x76,
                    0x4f, 0x8c, 0x2a, 0x11, 0x50, 0xe6, 0x16,
                ],
            ),
            (
                [84, 124, 73, 14],
                0x41,
                [
                    0x1b, 0x03, 0x21, 0xdd, 0x1b, 0xb1, 0xfe, 0x51, 0x81, 0x01, 0xce, 0xef, 0x99,
                    0x46, 0x2b, 0x94, 0x7a, 0x01, 0xff, 0x41,
                ],
            ),
            (
                [43, 213, 53, 83],
                0x5a,
                [
                    0xe5, 0x6f, 0x6c, 0xbf, 0x5b, 0x7c, 0x4b, 0xe0, 0x23, 0x79, 0x86, 0xd5, 0x24,
                    0x3b, 0x87, 0xaa, 0x6d, 0x51, 0x30, 0x5a,
                ],
            ),
        ];
        for (ip, rand, expect) in vectors {
            // Spec randomness split: rest[0] = the spec value of id[2]'s low 3 bits; rest[1..] = the middle.
            let mut rest = [0u8; 17];
            rest[0] = expect[2] & 0x07;
            rest[1..].copy_from_slice(&expect[3..19]);
            let id = derive_node_id(v4(*ip), *rand, rest);
            assert_eq!(
                id.0, *expect,
                "BEP42 vector {ip:?} rand={rand:#04x} mismatch (got {:02x?})",
                id.0
            );
            // Verification-face cross-check: what is generated verifies (verify_id true, node_id.cpp).
            assert!(verify_node_id(&id, v4(*ip)), "generated id must verify");
        }
    }

    /// Verification matrix (table-driven): valid / forged / local-exempt / IPv6 shapes.
    #[test]
    fn verification_matrix() {
        let ip = v4([124, 31, 75, 21]);
        let good = derive_node_id(ip, 0x01, [0x07; 17]);
        assert!(
            verify_node_id(&good, ip),
            "valid id (BEP42 vector 1, same ip)"
        );

        // Forgery: flip each of the top 21 bits (0..21); any corrupted bit is rejected.
        for bit in 0..21u32 {
            let mut forged = good.0;
            forged[(bit / 8) as usize] ^= 0x80 >> (bit % 8);
            assert!(
                !verify_node_id(&NodeId(forged), ip),
                "bit {bit} tampered must fail"
            );
        }
        // The middle (21..152) and the last byte's top 5 bits (152..157) do not
        // participate in verification (verify_id compares exactly 21 bits,
        // node_id.cpp; only the last byte's low 3 bits are r).
        for bit in 21..157u32 {
            let mut forged = good.0;
            forged[(bit / 8) as usize] ^= 0x80 >> (bit % 8);
            assert!(
                verify_node_id(&NodeId(forged), ip),
                "bit {bit} out of prefix must still pass"
            );
        }
        // The last byte's low 3 bits (157..160) = r: changing them changes the
        // hash input → rejected (BEP42 "last byte ... MUST match the random
        // number (r)").
        for bit in 157..160u32 {
            let mut forged = good.0;
            forged[(bit / 8) as usize] ^= 0x80 >> (bit % 8);
            assert!(
                !verify_node_id(&NodeId(forged), ip),
                "bit {bit} (r) tampered must fail"
            );
        }

        // Exempt addresses always pass (the BEP42 enforcement section's 5 ranges + libtorrent's v6 shapes).
        for exempt in [
            v4([10, 0, 0, 1]),
            v4([172, 16, 0, 1]),
            v4([172, 31, 255, 254]),
            v4([192, 168, 1, 1]),
            v4([169, 254, 3, 4]),
            v4([127, 0, 0, 1]),
            v4([100, 64, 1, 1]), // CGNAT (libtorrent addition)
            v4([100, 127, 255, 255]),
            v6([0xfe, 0x80, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1]), // link-local
            v6([0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), // ULA
            v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),       // loopback
        ] {
            let garbage = NodeId([0xAB; 20]);
            assert!(verify_node_id(&garbage, exempt), "exempt {exempt}");
        }
        // Non-exempt boundaries (outside every exempt range).
        for public in [
            v4([11, 0, 0, 1]),
            v4([172, 32, 0, 1]),
            v4([192, 169, 0, 1]),
            v4([126, 255, 1, 1]),
            v4([100, 128, 0, 1]),
        ] {
            let garbage = NodeId([0xAB; 20]);
            assert!(!verify_node_id(&garbage, public), "public {public}");
        }

        // IPv6 rule: the high 64 bits are masked and derived (BEP42
        // `ip & 0x0103070f1f3f7fff`); the low 64 bits do not participate —
        // changing them leaves the derivation unchanged; generated ids verify.
        let a = v6([
            0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0c, 0x05, 0x0c, 0xde, 0xad, 0, 0, 0, 0, 0, 1,
        ]);
        let id_a = generate_node_id(a, &mut rand::make_rng::<rand::rngs::StdRng>());
        assert!(verify_node_id(&id_a, a), "v6 generated must verify");
        let low_flipped = v6([
            0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0c, 0x05, 0x0c, 0xbe, 0xef, 0xff, 0xff, 0, 0, 0, 7,
        ]);
        assert!(
            verify_node_id(&id_a, low_flipped),
            "same high 64 bits -> equivalent verification (BEP42 v6 rule only uses the high 64 bits)"
        );
        // A different high 64 bits → rejected (a non-exempt global address).
        let other = v6([
            0x26, 0x07, 0xf8, 0xb0, 0x40, 0x0c, 0x05, 0x0d, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        assert!(
            !verify_node_id(&id_a, other),
            "different /64 prefix must be rejected"
        );
    }

    /// Derivation determinism: the same (ip, rand, rest) always yields the
    /// same id; random generation faces a roundtrip (generate → verifies;
    /// the same shape as libtorrent test_dht.cpp
    /// node_id_bucket_distribution's generate_id → verify precondition).
    #[test]
    fn generate_is_random_but_always_verifies() {
        for _ in 0..256 {
            // Covers both the v4 and v6 rules (address shapes with varied post-mask bytes).
            let ips = [
                v4([203, 0, 113, 7]),
                v4([1, 129, 44, 9]),
                v6([
                    0x24, 0x01, 0xdb, 0x30, 0x12, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 9,
                ]),
            ];
            for ip in ips {
                let mut rng = rand::make_rng::<rand::rngs::StdRng>();
                let id = generate_node_id(ip, &mut rng);
                assert!(
                    verify_node_id(&id, ip),
                    "random-generated id must verify for {ip}"
                );
            }
        }
        // Determinism: same input, same output.
        let a = derive_node_id(v4([1, 2, 3, 4]), 5, [6; 17]);
        let b = derive_node_id(v4([1, 2, 3, 4]), 5, [6; 17]);
        assert_eq!(a, b);
    }

    /// Probed-address filter logic (the network-free pure half: the
    /// loopback/unspecified rejection semantics live in the call path's
    /// filter expression — this anchors the is_exempt x global-test
    /// combination).
    #[test]
    fn exempt_and_global_filters_agree() {
        // The is_exempt x global-test intersection: RFC1918 is non-global but exempt.
        assert!(is_exempt_ip(v4([192, 168, 1, 1])));
        // A global public address: not exempt.
        assert!(!is_exempt_ip(v4([203, 0, 113, 7])));
        // v6 global (2000::/3): not exempt, global.
        let g = Ipv6Addr::from([0x26, 0x07, 0xf8, 0xb0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert!(!is_exempt_ip(IpAddr::V6(g)));
        assert!(is_global_v6(g));
        let ll = Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert!(is_exempt_ip(IpAddr::V6(ll)));
        assert!(!is_global_v6(ll));
        // Non-global shapes: ULA / documentation prefix / IPv4-mapped.
        assert!(!is_global_v6(Ipv6Addr::from([
            0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ])));
        assert!(!is_global_v6(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ])));
        assert!(!is_global_v6(Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1
        ])));
    }

    /// Probed-source acceptance classification ([`accept_probed_source`], a
    /// pure function; the network-free half of the probe face): ULA (the
    /// non-global source shape seen on ULA+GUA mixed networks) / link-local /
    /// loopback / unspecified → rejected (the non-global verdict is preserved
    /// verbatim, not weakened); GUA (a 2000::/3 shape) → accepted; the v4
    /// face (v6=false) keeps its semantics: only loopback/unspecified are
    /// rejected, and an RFC1918 source behind NAT is accepted as usual (see
    /// the crate::dht module docs divergence list).
    #[test]
    fn accept_probed_source_rejects_ula_and_non_global_v6() {
        // The ULA source shape observed in the field (fd22:a7ae:a3ac:...) — the
        // UDP-probe era always got this source and rejected it; the TCP probe
        // must still reject it (a semantics-not-weakened assertion).
        let ula = Ipv6Addr::from([
            0xfd, 0x22, 0xa7, 0xae, 0xa3, 0xac, 0x34, 0x00, 0x08, 0x0c, 0x78, 0xed, 0xcf, 0x65,
            0x17, 0x83,
        ]);
        assert!(!accept_probed_source(true, IpAddr::V6(ula)));
        assert!(!accept_probed_source(
            true,
            v6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        )); // link-local
        assert!(!accept_probed_source(true, v6([0; 16]))); // unspecified
        assert!(!accept_probed_source(
            true,
            v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        )); // loopback
        // GUA accepted (a 2000::/3 GUA prefix shape).
        assert!(accept_probed_source(
            true,
            v6([0x24, 0x0e, 0x03, 0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        ));
        // v4 face semantics unchanged (identical before and after).
        assert!(accept_probed_source(false, v4([192, 168, 1, 10])));
        assert!(accept_probed_source(false, v4([203, 0, 113, 7])));
        assert!(!accept_probed_source(false, v4([127, 0, 0, 1])));
        assert!(!accept_probed_source(false, v4([0, 0, 0, 0])));
    }

    /// Criterion (the real-network face): the v6 probe agrees with the host's
    /// TCP outbound source — the probe uses TCP connect
    /// ([`PROBE_TCP_TARGETS_V6`]) and the return contract is locked: Some is
    /// always v6 and is_global_v6 (on a ULA+GUA mixed host, that GUA; the UDP
    /// connect method would keep yielding a rejected ULA source on the same
    /// host). None = no global v6 (ULA-only or no v6 host; the rejection
    /// semantics are unchanged — the ULA branch is locked network-free by
    /// [`accept_probed_source_rejects_ula_and_non_global_v6`]).
    #[tokio::test]
    async fn probe_v6_tcp_returns_global_v6_source_or_none() {
        match probe_source_ip(true).await {
            Some(IpAddr::V6(v6addr)) => {
                assert!(
                    is_global_v6(v6addr),
                    "probe result must be a global v6 address (got {v6addr})"
                );
            }
            Some(other) => panic!("v6 probe must not return a non-v6 source (got {other})"),
            None => {} // no global-v6 host: keep the status quo (skip the v6 face / random id).
        }
        // The v4 path's zero-change contract: the probe must not panic and the
        // return value passes through as-is (behind NAT it may be RFC1918 — the
        // divergence-list semantics).
        let _ = probe_source_ip(false).await;
    }
}

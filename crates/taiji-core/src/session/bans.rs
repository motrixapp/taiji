//! Manual ban bookkeeping (the session-side pure-function face of
//! `taiji.banAddr`/`unbanAddr`/`listBans`): target text
//! parsing/normalization, the `listBans` view, and source
//! classification. No IO — the actor call sites and the table-driven
//! tests share it; store writes / hot-push orchestration live on the
//! actor command face.
//!
//! # Target syntax (taiji.banAddr target)
//!
//! - Single IP: `192.0.2.1` / `2001:db8::1` (v4 tolerates the eMule
//! zero-padding convention — reuses
//! `bt::peer_policy::parse_ip_lenient`);
//! - CIDR: `10.9.9.0/24` / `2001:db8::/32` (reuses
//! [`taiji_bt::peer_policy::parse_cidr`], deny-range semantics).
//!
//! The normalized target text is the persisted form of the peer_ban.ip
//! column and the exact match key for unban: a single IP -> the
//! `IpAddr` standard display; CIDR -> `start/prefix length` (the prefix
//! length derived from start/end — any spelling such as `1.2.3.4/32`
//! or `1.2.3.4/8` normalizes to the same text).

use std::net::IpAddr;

use taiji_bt::peer_policy::{parse_cidr, parse_ip_lenient};

use super::view::BanSource;

/// The session_kv key: the `client_ban_prefixes` persisted mirror (a
/// JSON string array; the cross-restart truth source — a kv key present
/// overrides the option initial value).
pub const CLIENT_BAN_PREFIXES_KV: &str = "client_ban_prefixes";

/// now (epoch seconds) — the base value for until verdicts and
/// persistence (shared across the bans face).
pub fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A manual ban bookkeeping entry (the actor's in-memory truth source;
/// the persisted mirror = a peer_ban row with reason=manual, the `ip`
/// column = the normalized target text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualBan {
    /// Normalized target text (persisted/echoed/unban match key).
    pub target: String,
    /// Closed range (same family; the CIDR expansion).
    pub start: IpAddr,
    pub end: IpAddr,
    /// Expiry instant (epoch seconds); `i64::MAX` = permanent.
    pub until: i64,
}

/// Manual ban bookkeeping cap (an RPC intake-face abuse guard;
/// exceeding it rejects — the snapshot side is a linear scan, see the
/// `bt::peer_policy::IpGuard` doc). A pure config cap, not a protocol
/// constant.
pub const MAX_MANUAL_BANS: usize = 1024;

/// Parse and normalize a ban target (`IP` | `IP/prefix`). Returns
/// (normalized text, range). Illegal text = None (the RPC face reports
/// explicitly, never silently).
pub fn parse_manual_target(text: &str) -> Option<(String, IpAddr, IpAddr)> {
    let t = text.trim();
    if t.contains('/') {
        let rule = parse_cidr(t)?;
        let plen = prefix_len_of(rule.start, rule.end)?;
        Some((format!("{}/{}", rule.start, plen), rule.start, rule.end))
    } else {
        let ip = parse_ip_lenient(t)?;
        Some((ip.to_string(), ip, ip))
    }
}

/// Derive the prefix length from the range endpoints (start/end in the
/// same family and start a mask base — guaranteed by parse_cidr): the
/// difference bits' leading zeros.
fn prefix_len_of(start: IpAddr, end: IpAddr) -> Option<u32> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => Some((u32::from(s) ^ u32::from(e)).leading_zeros()),
        (IpAddr::V6(s), IpAddr::V6(e)) => Some((u128::from(s) ^ u128::from(e)).leading_zeros()),
        _ => None,
    }
}

/// Ban source classification (the `listBans` source field): the
/// peer_ban.reason prefix.
pub fn ban_source(reason: &str) -> BanSource {
    if reason == crate::peer_guard::REASON_MANUAL {
        BanSource::Manual
    } else if reason.starts_with(crate::peer_guard::REASON_CLIENT_BAN_PREFIX) {
        BanSource::ClientBan
    } else {
        BanSource::Auto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Target parsing/normalization: a single IP, zero-padded v4, CIDR
    /// normalization (any spelling -> the same text), rejection of the
    /// illegal face.
    #[test]
    fn target_parse_and_canonicalization() {
        let v4 = |a: [u8; 4]| IpAddr::from(a);
        // Single IP: standard display; range = itself; surrounding
        // whitespace stripped.
        let (t, s, e) = parse_manual_target(" 192.0.2.1 ").unwrap_or_else(|| panic!("plain ip"));
        assert_eq!(t, "192.0.2.1");
        assert_eq!((s, e), (v4([192, 0, 2, 1]), v4([192, 0, 2, 1])));
        // v4 zero-padding tolerance (the eMule convention) -> the
        // normalized standard display.
        let (t, s, e) = parse_manual_target("000.010.0.1").unwrap_or_else(|| panic!("lenient"));
        assert_eq!(
            t, "0.10.0.1",
            "octets 000=0, 010=10 — same face as peer_policy"
        );
        assert_eq!((s, e), (v4([0, 10, 0, 1]), v4([0, 10, 0, 1])));
        // CIDR: normalized to start/prefix length (any host-bit
        // spelling -> the same text).
        let (t, s, e) = parse_manual_target("10.9.9.123/24").unwrap_or_else(|| panic!("cidr"));
        assert_eq!(t, "10.9.9.0/24");
        assert_eq!((s, e), (v4([10, 9, 9, 0]), v4([10, 9, 9, 255])));
        // The /32 text is distinct from the bare IP (different match
        // keys); the range = itself.
        let (t32, s32, e32) = parse_manual_target("10.0.0.5/32").unwrap_or_else(|| panic!("/32"));
        assert_eq!(t32, "10.0.0.5/32");
        assert_eq!((s32, e32), (v4([10, 0, 0, 5]), v4([10, 0, 0, 5])));
        // v6 CIDR.
        let (t6, s6, e6) =
            parse_manual_target("2001:db8::dead/32").unwrap_or_else(|| panic!("v6 cidr"));
        assert_eq!(t6, "2001:db8::/32");
        assert_eq!(s6.to_string(), "2001:db8::");
        assert_eq!(e6.to_string(), "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff");
        // The illegal face.
        assert_eq!(parse_manual_target("nonsense"), None);
        assert_eq!(parse_manual_target("10.0.0.0/33"), None);
        assert_eq!(parse_manual_target("10.0.0.0/24/8"), None);
        assert_eq!(parse_manual_target(""), None);
    }

    /// Source classification: manual / the client-ban: prefix /
    /// everything else auto.
    #[test]
    fn source_classification_by_reason() {
        assert_eq!(ban_source("manual"), BanSource::Manual);
        assert_eq!(
            ban_source("client-ban: -XL"),
            BanSource::ClientBan,
            "client-ban prefix recognition"
        );
        assert_eq!(
            ban_source("hash verification failures (>=3 in 10min)"),
            BanSource::Auto
        );
        assert_eq!(ban_source("unsolicited piece 0+0+16384"), BanSource::Auto);
        assert_eq!(
            ban_source("manualish"),
            BanSource::Auto,
            "exact equality counts as manual"
        );
    }
}

//! Pure in-memory policy types: the [`IpGuard`] IP filter snapshot and the
//! violation-event contract (SPEC §13).
//!
//! # Responsibility boundary (dependency direction)
//!
//! This module is pure in-memory types with no IO inside bt — ban
//! bookkeeping (sliding-window counts), persistence, and blocklist file
//! import are orchestrated in `taiji-core::peer_guard`; filter-point
//! wiring (query before accept/dial + disconnecting online connections)
//! lives in the core engine.
//!
//! # Types
//!
//! - [`IpGuard`]: immutable filter snapshot (static rules cidr /
//! p2p-blocklist + a dynamic ban table), O(log n) queries (merged
//! sorted ranges + binary search; bans binary-searched in numeric IP
//! order). Shared via [`IpGuardHandle`] (arc-swap): lock-free `load` on
//! the read side, `store` hot-swap on the core orchestration side
//! (message contract).
//! - [`Violation`]: the peer violation-event contract
//! (`Violation{ip,reason}` over an mpsc(64) channel to core
//! bookkeeping).
//!
//! # Extensions: manual ban ranges + client identity rules
//!
//! - [`IpGuard::with_manual_bans`]: range bans from `taiji.banAddr`
//! (reason=manual) enter the snapshot at the same priority as automatic
//! bans (checked before allow rules);
//! - [`IpGuard::with_client_deny`] + [`IpGuard::client_blocks`]:
//! identity matching driven by the `client_ban_prefixes` config (peer_id
//! byte prefix OR ext-handshake `v` field substring), invoked by the
//! core engine at handshake completion. **The default empty list bans no
//! client (identification is not banning; the identifier lives in
//! `crate::client_id`).**
//!
//! # eMule `.dat` blocklist format
//!
//! Line syntax pinned by SPEC §13: `<deny|allow>,<from>,<to>` (three
//! comma-separated fields, case-insensitive action, whitespace tolerated
//! around fields, `#` line comments, blank lines ignored; v4 endpoints
//! tolerate the eMule-convention 3-digit zero padding such as
//! `000.010.0.1` — the std parser rejects leading zeros, so
//! [`parse_ip_lenient`] parses them itself). The deny/allow actions make
//! explicit the two outcomes of the eMule "IP Filters" help page (line
//! format `IP-Range , Access Level , Description`; access level < 127
//! denied, >= 127 permitted). That help page's `IP-Range , Access Level ,
//! Description` variant (` - ` separated + a level column) is not input
//! to this parser: such lines count into [`ParsedBlocklist::skipped`].
//!
//! Upstream note: aria2 has no IP filter/blocklist implementation; the
//! authority for this module is SPEC §13 and the format rules above.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;

/// Peer violation event (message contract: mpsc(64) to core bookkeeping;
/// the bt side only produces events and never executes bans —
/// bookkeeping/persistence/disconnect are core-side concerns).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub ip: IpAddr,
    /// Violation description (protocol violation = the PeerError text /
    /// "message flooding"; persisted into peer_ban.reason — bans are
    /// never silent).
    pub reason: String,
}

/// Rule action (eMule semantics: the explicit two actions of <127 denied
/// / >=127 permitted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Deny,
    Allow,
}

impl RuleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleAction::Deny => "deny",
            RuleAction::Allow => "allow",
        }
    }

    fn parse(s: &str) -> Option<RuleAction> {
        match s.trim().to_ascii_lowercase().as_str() {
            "deny" => Some(RuleAction::Deny),
            "allow" => Some(RuleAction::Allow),
            _ => None,
        }
    }
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rule provenance (the ipfilter table kind column, SPEC §5.3:
/// `cidr|p2p-blocklist`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// `a.b.c.d/prefix` (manual/RPC surface).
    Cidr,
    /// eMule `.dat` blocklist import (this module).
    P2PBlocklist,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleKind::Cidr => "cidr",
            RuleKind::P2PBlocklist => "p2p-blocklist",
        }
    }
}

/// One static filter rule: closed range `[start, end]` (same address
/// family; v4/v6 never match each other).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterRule {
    pub action: RuleAction,
    pub start: IpAddr,
    pub end: IpAddr,
}

impl FilterRule {
    /// Normalized rule text (the rule column of an ipfilter row with
    /// kind=p2p-blocklist; isomorphic to the import syntax — read back
    /// via [`parse_blocklist_rule`], lossless).
    pub fn to_blocklist_text(&self) -> String {
        format!("{},{},{}", self.action.as_str(), self.start, self.end)
    }
}

/// An active ban (peer_ban table row semantics: ip primary key + reason +
/// until epoch seconds, SPEC §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRecord {
    pub reason: String,
    /// Expiry instant (epoch seconds; blocking applies only while
    /// `until > now`).
    pub until: i64,
}

/// Normalized range (endpoints inclusive).
type Range32 = (u32, u32);
type Range128 = (u128, u128);

/// Range merge: sort, then fold overlapping/adjacent ranges (folding
/// adjacent ranges reduces binary-search fragmentation without changing
/// semantics). `succ` = value + 1 (returns None on overflow — a saturated
/// max endpoint no longer merges with anything adjacent).
fn merge_ranges<T: Copy + Ord>(mut rs: Vec<(T, T)>, succ: impl Fn(T) -> Option<T>) -> Vec<(T, T)> {
    rs.sort();
    let mut out: Vec<(T, T)> = Vec::with_capacity(rs.len());
    for (s, e) in rs {
        match out.last_mut() {
            Some(last) if Some(last.1) == succ(s) || last.1 >= s => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// Binary-search hit: `rs` is merged and sorted (non-overlapping); hits
/// `[start, end]` inclusive.
fn range_hit<T: Ord>(rs: &[(T, T)], x: T) -> bool {
    let i = rs.partition_point(|(s, _)| *s <= x);
    i > 0 && rs[i - 1].1 >= x
}

fn inc_u32(x: u32) -> Option<u32> {
    x.checked_add(1)
}
fn inc_u128(x: u128) -> Option<u128> {
    x.checked_add(1)
}

/// Block verdict (`blocks` returning `Some` = reject, carrying the
/// category; `None` = allow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpBlock {
    /// Automatic ban hit (peer_ban; carries the reason).
    Banned(String),
    /// Static filter hit (ipfilter: cidr / p2p-blocklist deny rule).
    Denied,
}

impl fmt::Display for IpBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpBlock::Banned(reason) => write!(f, "banned: {reason}"),
            IpBlock::Denied => f.write_str("denied by filter rule"),
        }
    }
}

/// IP filter snapshot (immutable; hot-swapped via [`IpGuardHandle`]
/// arc-swap).
///
/// Verdict order (local policy; the reason is the comment):
/// 1. **Automatic bans first**: a ban is reactive evidence of measured
/// misbehavior (hash-failure streaks / protocol violations) and is not
/// voided by a blocklist wildcard allow;
/// 2. **Manual bans rank with automatic bans**: ranges persisted from
/// `taiji.banAddr` with reason=manual are checked before allow rules —
/// an explicit user ban is not exempted by a blocklist wildcard allow
/// (same reasoning as for automatic bans);
/// 3. **allow wins** (eMule semantics): any covering allow rule permits
/// the address;
/// 4. a deny hit rejects.
///
/// Separately, the identity rules [`IpGuard::client_blocks`] are a
/// verdict over the peer_id/the `v` field dimension (invoked at handshake
/// completion, never mixed with IP verdicts).
///
/// Queries are O(log n): allow/deny are each merged sorted range tables
/// (binary search); bans are sorted in numeric IP order (binary search,
/// exact hit); manual bans are a linear scan (users enter them one by one
/// via RPC, so volumes are small — the session side caps the count, see
/// `taiji-core::session::bans`). IPv4-mapped IPv6 (::ffff:a.b.c.d) is
/// judged in the v4 domain — eMule lists are v4-domain, and under a
/// dual-stack listener such addresses are really v4 traffic.
#[derive(Debug, Clone, Default)]
pub struct IpGuard {
    allow4: Vec<Range32>,
    deny4: Vec<Range32>,
    allow6: Vec<Range128>,
    deny6: Vec<Range128>,
    bans4: Vec<(u32, BanRecord)>,
    bans6: Vec<(u128, BanRecord)>,
    /// Manual ban ranges (`taiji.banAddr`; [`BanRecord`] with
    /// reason=manual; expiry filtering happens at snapshot assembly time).
    manual4: Vec<(Range32, BanRecord)>,
    manual6: Vec<(Range128, BanRecord)>,
    /// Client identity rules: configured match strings (peer_id byte
    /// prefix OR case-insensitive `v` field substring). Default empty =
    /// ban no client (identification is not banning).
    client_deny: Vec<String>,
}

impl IpGuard {
    /// Assemble a snapshot from static rules + dynamic bans (duplicate
    /// ranges are absorbed by the merge; no pre-dedup needed).
    pub fn new(
        rules: impl IntoIterator<Item = FilterRule>,
        bans: impl IntoIterator<Item = (IpAddr, BanRecord)>,
    ) -> IpGuard {
        let mut g = IpGuard::default();
        for rule in rules {
            match (rule.action, rule.start, rule.end) {
                (RuleAction::Deny, IpAddr::V4(s), IpAddr::V4(e)) => {
                    g.deny4.push((u32::from(s), u32::from(e)))
                }
                (RuleAction::Allow, IpAddr::V4(s), IpAddr::V4(e)) => {
                    g.allow4.push((u32::from(s), u32::from(e)))
                }
                (RuleAction::Deny, IpAddr::V6(s), IpAddr::V6(e)) => {
                    g.deny6.push((u128::from(s), u128::from(e)))
                }
                (RuleAction::Allow, IpAddr::V6(s), IpAddr::V6(e)) => {
                    g.allow6.push((u128::from(s), u128::from(e)))
                }
                // Cross-family ranges are rejected at the parse surface; defensive skip.
                _ => continue,
            }
        }
        g.allow4 = merge_ranges(std::mem::take(&mut g.allow4), inc_u32);
        g.deny4 = merge_ranges(std::mem::take(&mut g.deny4), inc_u32);
        g.allow6 = merge_ranges(std::mem::take(&mut g.allow6), inc_u128);
        g.deny6 = merge_ranges(std::mem::take(&mut g.deny6), inc_u128);
        for (ip, rec) in bans {
            match ip {
                IpAddr::V4(a) => g.bans4.push((u32::from(a), rec)),
                IpAddr::V6(a) => g.bans6.push((u128::from(a), rec)),
            }
        }
        g.bans4.sort_by_key(|(ip, _)| *ip);
        g.bans6.sort_by_key(|(ip, _)| *ip);
        g
    }

    /// Append manual ban ranges (builder; the `new` signature is
    /// unchanged — existing assembly call sites are unaffected). Only
    /// same-family `start <= end` ranges are accepted; unsorted (linear
    /// scan, small volumes).
    pub fn with_manual_bans(
        mut self,
        bans: impl IntoIterator<Item = (IpAddr, IpAddr, BanRecord)>,
    ) -> IpGuard {
        for (start, end, rec) in bans {
            match (start, end) {
                (IpAddr::V4(s), IpAddr::V4(e)) if s <= e => {
                    self.manual4.push(((u32::from(s), u32::from(e)), rec))
                }
                (IpAddr::V6(s), IpAddr::V6(e)) if s <= e => {
                    self.manual6.push(((u128::from(s), u128::from(e)), rec))
                }
                _ => continue, // cross-family / inverted ranges: rejected upstream; defensive skip.
            }
        }
        self
    }

    /// Append client identity rules (builder). Normalization: trim
    /// whitespace, drop empty strings, dedup (order preserved — the
    /// first match decides the verdict).
    pub fn with_client_deny(mut self, prefixes: impl IntoIterator<Item = String>) -> IpGuard {
        for p in prefixes {
            let p = p.trim().to_string();
            if !p.is_empty() && !self.client_deny.contains(&p) {
                self.client_deny.push(p);
            }
        }
        self
    }

    /// Filter verdict: `Some` = block (with category and reason), `None`
    /// = allow.
    pub fn blocks(&self, ip: IpAddr, now: i64) -> Option<IpBlock> {
        // Family normalization: ::ffff:a.b.c.d -> v4 (see the type docs).
        let v4 = match ip {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(a) => a.to_ipv4_mapped(),
        };
        if let Some(a) = v4 {
            return self.verdict_v4(u32::from(a), now);
        }
        let x = match ip {
            IpAddr::V6(a) => u128::from(a),
            IpAddr::V4(_) => unreachable!("v4 handled above"),
        };
        if let Ok(i) = self.bans6.binary_search_by(|(b, _)| b.cmp(&x)) {
            let rec = &self.bans6[i].1;
            if rec.until > now {
                return Some(IpBlock::Banned(rec.reason.clone()));
            }
        }
        if let Some(rec) = self.manual6.iter().find(|((s, e), _)| *s <= x && x <= *e)
            && rec.1.until > now
        {
            return Some(IpBlock::Banned(rec.1.reason.clone()));
        }
        if range_hit(&self.allow6, x) {
            return None;
        }
        range_hit(&self.deny6, x).then_some(IpBlock::Denied)
    }

    fn verdict_v4(&self, x: u32, now: i64) -> Option<IpBlock> {
        if let Ok(i) = self.bans4.binary_search_by(|(b, _)| b.cmp(&x)) {
            let rec = &self.bans4[i].1;
            if rec.until > now {
                return Some(IpBlock::Banned(rec.reason.clone()));
            }
        }
        if let Some(rec) = self.manual4.iter().find(|((s, e), _)| *s <= x && x <= *e)
            && rec.1.until > now
        {
            return Some(IpBlock::Banned(rec.1.reason.clone()));
        }
        if range_hit(&self.allow4, x) {
            return None;
        }
        range_hit(&self.deny4, x).then_some(IpBlock::Denied)
    }

    /// Identity verdict (invoked at handshake completion — only then is
    /// peer_id available): a configured string hits as a peer_id byte
    /// prefix **or** a case-insensitive substring of the `v` field.
    /// Returns `Some(matched string)` = reject (disposal belongs to the
    /// caller — disconnect + persistence), `None` = allow. The default
    /// empty list always returns `None` (identification is not banning).
    /// The `v` field only becomes available after the ext handshake, so a
    /// call at handshake time passes `None` (verdict over the peer_id
    /// dimension only).
    pub fn client_blocks(&self, peer_id: Option<&[u8; 20]>, v: Option<&str>) -> Option<String> {
        self.client_deny
            .iter()
            .find(|p| {
                peer_id.is_some_and(|id| id.starts_with(p.as_bytes()))
                    || v.is_some_and(|s| {
                        let needle = p.to_ascii_lowercase();
                        s.to_ascii_lowercase().contains(&needle)
                    })
            })
            .cloned()
    }
}

// ---------------------------------------------------------------------------
// BEP-40 symmetric peer rank (connection-ecosystem ordering key).
// ---------------------------------------------------------------------------

/// BEP-40 symmetric rank: `crc32c(endpoint pair masked by their common
/// prefix)`. Direct translation of libtorrent RC_2_1 `src/torrent_peer.cpp`
/// `aux::peer_priority` (`rank()` = `peer_priority(our external endpoint,
/// peer endpoint)`; see also `torrent_peer.hpp` / `peer_connection.cpp`).
///
/// **Both sides compute the same value** (symmetry): the endpoint pair is
/// first put in canonical order (swap if `e1 > e2` — endpoint order =
/// address lexicographic then port; isomorphic to this repo's
/// `SocketAddr` Ord), and the mask depends only on the common prefix of
/// the two endpoints, so `rank(a,b) == rank(b,a)` always holds. Purpose =
/// a composite key for candidate ranking (the last key of `peer_list.cpp`
/// `compare_peer`: the higher-ranked side connects first) — a globally
/// consistent pair order makes both sides of a would-be connection
/// converge on the same initiator, eliminating interconnect storms (the
/// BEP-40 motivation).
///
/// Branch-by-branch translation:
/// - **same address**: ports in ascending order, then
/// `crc32c(port_lo_be || port_hi_be)` (4B);
/// - **v4, different addresses**: mask by common-prefix depth (memcmp
/// 2B/3B -> the three-row mask table
/// `{ff,ff,55,55}/{ff,ff,ff,55}/{ff,ff,ff,ff}`; endpoint pairs within
/// the same /16 get identical ranks — no difference within the prefix
/// is ranking-neutral), then `crc32c(b1||b2)` (8B);
/// - **v6, different addresses**: from the first differing byte `i`,
/// `offset = max(i+1, 5)`; bytes after that are masked with `0x55` on
/// both sides, then `crc32c(b1||b2)` (32B);
/// - **cross-family**: the reference asserts `is_v4(e1)==is_v4(e2)`
/// (cross-family endpoint pairs cannot interconnect) — this side
/// returns the fixed value 0 (ranking-neutral, both directions get 0,
/// symmetry preserved).
///
/// CRC32C reuses the BEP-42 table-driven implementation
/// ([`crate::dht::crc32c`]; standard check values anchored) with the same
/// byte-order semantics: the reference feeds the CRC the in-memory byte
/// sequence (memcpy shape), and IP octets are network-order bytes.
pub fn bep40_rank(local: SocketAddr, remote: SocketAddr) -> u32 {
    // Cross-family: the reference asserts this (see the fn docs) — ranking-neutral fixed value.
    if local.is_ipv4() != remote.is_ipv4() {
        return 0;
    }
    // Same address: ports ascending (`torrent_peer.cpp`; write_uint16 big-endian).
    if local.ip() == remote.ip() {
        let (lo, hi) = if local.port() <= remote.port() {
            (local.port(), remote.port())
        } else {
            (remote.port(), local.port())
        };
        let mut buf = [0u8; 4];
        buf[..2].copy_from_slice(&lo.to_be_bytes());
        buf[2..].copy_from_slice(&hi.to_be_bytes());
        return crate::dht::crc32c(&buf);
    }
    // Canonical order (swap if `e1 > e2`; endpoint order = address
    // lexicographic then port, isomorphic to this repo's `SocketAddr` Ord).
    let (e1, e2) = if local <= remote {
        (local, remote)
    } else {
        (remote, local)
    };
    match (e1, e2) {
        (SocketAddr::V4(a), SocketAddr::V4(b)) => {
            // v4, different addresses: common-prefix depth -> mask row (`torrent_peer.cpp`).
            const V4MASK: [[u8; 4]; 3] = [
                [0xff, 0xff, 0x55, 0x55],
                [0xff, 0xff, 0xff, 0x55],
                [0xff, 0xff, 0xff, 0xff],
            ];
            let m1 = a.ip().octets();
            let m2 = b.ip().octets();
            let idx = if m1[0..2] != m2[0..2] {
                0
            } else if m1[0..3] != m2[0..3] {
                1
            } else {
                2
            };
            let mask = V4MASK[idx];
            let mut buf = [0u8; 8];
            for i in 0..4 {
                buf[i] = m1[i] & mask[i];
                buf[4 + i] = m2[i] & mask[i];
            }
            crate::dht::crc32c(&buf)
        }
        (SocketAddr::V6(a), SocketAddr::V6(b)) => {
            // v6: first differing byte i -> offset = max(i+1, 5); later bytes
            // masked 0x55 on both sides (`torrent_peer.cpp`).
            let mut b1 = a.ip().octets();
            let mut b2 = b.ip().octets();
            let mut offset: usize = usize::MAX;
            for i in 0..16 {
                if offset == usize::MAX && b1[i] != b2[i] {
                    offset = (i + 1).max(5);
                } else if i > offset {
                    b1[i] &= 0x55;
                    b2[i] &= 0x55;
                }
            }
            let mut buf = [0u8; 32];
            buf[..16].copy_from_slice(&b1);
            buf[16..].copy_from_slice(&b2);
            crate::dht::crc32c(&buf)
        }
        // Cross-family was intercepted at fn entry (same-family assert); this arm is unreachable.
        _ => 0,
    }
}

/// Shared IpGuard snapshot handle (arc-swap hot swap).
///
/// - Read side (engine accept/dial filter points): `load()` is a lock-free
/// snapshot read;
/// - write side (core orchestration: ban activation / blocklist import /
/// expiry sweep): `store()` replaces the whole snapshot — the immutable
/// snapshot guarantees readers always see a consistent structure, with
/// no invalidation notifications needed.
#[derive(Clone, Default)]
pub struct IpGuardHandle(Arc<ArcSwap<IpGuard>>);

impl IpGuardHandle {
    pub fn new(guard: IpGuard) -> IpGuardHandle {
        IpGuardHandle(Arc::new(ArcSwap::new(Arc::new(guard))))
    }

    /// Current snapshot (lock-free; the returned Guard keeps this version
    /// visible while in use).
    pub fn load(&self) -> arc_swap::Guard<Arc<IpGuard>> {
        self.0.load()
    }

    /// Hot-swap in a new snapshot.
    pub fn store(&self, guard: IpGuard) {
        self.0.store(Arc::new(guard));
    }
}

impl fmt::Debug for IpGuardHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IpGuardHandle")
    }
}

/// Lenient IP text parsing: v4 tolerates 1-3 digit zero-padded decimal
/// octets (eMule convention `000.010.0.1`; std rejects leading zeros);
/// anything containing `:` is parsed strictly as v6.
pub fn parse_ip_lenient(s: &str) -> Option<IpAddr> {
    let t = s.trim();
    if t.contains(':') {
        return t.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut oct = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: u16 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        oct[i] = v as u8;
    }
    Some(IpAddr::V4(Ipv4Addr::from(oct)))
}

/// Single-line blocklist rule parsing: `<deny|allow>,<from>,<to>` (see
/// the module-doc format section). Valid only when same-family and
/// `start <= end`; `from > to` is invalid (rejected at the parse surface,
/// never silently swapped — swapping would amplify a maintenance typo
/// into a large wrongful ban).
pub fn parse_blocklist_rule(line: &str) -> Option<FilterRule> {
    let mut fields = line.split(',');
    let action = RuleAction::parse(fields.next()?)?;
    let start = parse_ip_lenient(fields.next()?)?;
    let end = parse_ip_lenient(fields.next()?)?;
    if fields.next().is_some() || std::mem::discriminant(&start) != std::mem::discriminant(&end) {
        return None;
    }
    if start > end {
        return None;
    }
    Some(FilterRule { action, start, end })
}

/// CIDR parsing (the read-back surface for ipfilter rows with kind=cidr):
/// `addr/prefix`. The action is always deny (cidr rows are the manual/RPC
/// surface; the parser carries no action).
pub fn parse_cidr(text: &str) -> Option<FilterRule> {
    let (addr, plen) = text.split_once('/')?;
    let addr = parse_ip_lenient(addr)?;
    let plen: u32 = plen.trim().parse().ok()?;
    match addr {
        IpAddr::V4(a) => {
            if plen > 32 {
                return None;
            }
            let mask = if plen == 0 {
                0
            } else {
                u32::MAX << (32 - plen)
            };
            let base = u32::from(a) & mask;
            Some(FilterRule {
                action: RuleAction::Deny,
                start: IpAddr::V4(Ipv4Addr::from(base)),
                end: IpAddr::V4(Ipv4Addr::from(base | !mask)),
            })
        }
        IpAddr::V6(a) => {
            if plen > 128 {
                return None;
            }
            let mask = if plen == 0 {
                0
            } else {
                u128::MAX << (128 - plen)
            };
            let base = u128::from(a) & mask;
            Some(FilterRule {
                action: RuleAction::Deny,
                start: IpAddr::V6(Ipv6Addr::from(base)),
                end: IpAddr::V6(Ipv6Addr::from(base | !mask)),
            })
        }
    }
}

/// eMule `.dat` parse result: valid rules + a count of non-conforming
/// lines (comments/blank lines are legal content and are not counted as
/// skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedBlocklist {
    pub rules: Vec<FilterRule>,
    pub skipped: usize,
}

/// eMule `.dat` blocklist parsing (line-by-line tolerance: bad lines are
/// skipped and counted, never a whole-file failure — wild lists often
/// contain junk lines; callers alert on [`ParsedBlocklist::skipped`]).
pub fn parse_emule_dat(data: &str) -> ParsedBlocklist {
    let mut rules = Vec::new();
    let mut skipped = 0usize;
    for line in data.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match parse_blocklist_rule(t) {
            Some(rule) => rules.push(rule),
            None => skipped += 1,
        }
    }
    ParsedBlocklist { rules, skipped }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: RuleAction, start: &str, end: &str) -> FilterRule {
        FilterRule {
            action,
            start: IpAddr::V4(
                parse_ip_lenient(start)
                    .and_then(|a| match a {
                        IpAddr::V4(v) => Some(v),
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("bad v4 {start}")),
            ),
            end: IpAddr::V4(
                parse_ip_lenient(end)
                    .and_then(|a| match a {
                        IpAddr::V4(v) => Some(v),
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("bad v4 {end}")),
            ),
        }
    }

    fn ip(s: &str) -> IpAddr {
        parse_ip_lenient(s).unwrap_or_else(|| panic!("bad ip {s}"))
    }

    fn guard_of(rules: Vec<FilterRule>) -> IpGuard {
        IpGuard::new(rules, [])
    }

    /// Merge/hit: overlapping ranges folded, adjacent folded,
    /// binary-search hits include endpoints, gaps allowed.
    #[test]
    fn merged_ranges_hit_boundaries() {
        let g = guard_of(vec![
            rule(RuleAction::Deny, "10.0.0.0", "10.0.0.255"),
            rule(RuleAction::Deny, "10.0.0.128", "10.0.1.127"), // overlapping fold
            rule(RuleAction::Deny, "10.0.2.0", "10.0.2.255"),   // adjacent fold
            rule(RuleAction::Deny, "10.0.4.0", "10.0.4.255"),   // not adjacent (10.0.3.x gap)
        ]);
        assert!(g.blocks(ip("10.0.0.0"), 0).is_some(), "start endpoint hit");
        assert!(
            g.blocks(ip("10.0.1.127"), 0).is_some(),
            "overlapping-fold end hit"
        );
        assert!(
            g.blocks(ip("10.0.2.255"), 0).is_some(),
            "adjacent-fold end hit"
        );
        assert_eq!(g.blocks(ip("10.0.3.5"), 0), None, "gap allowed");
        assert!(g.blocks(ip("10.0.4.255"), 0).is_some(), "endpoint hit");
        assert_eq!(
            g.blocks(ip("10.0.5.0"), 0),
            None,
            "outside the range allowed"
        );
    }

    /// allow-wins semantics (eMule): an allow cover permits, deny is not
    /// evaluated.
    #[test]
    fn allow_overrides_deny() {
        let g = guard_of(vec![
            rule(RuleAction::Deny, "0.0.0.0", "255.255.255.255"),
            rule(RuleAction::Allow, "192.168.0.0", "192.168.0.255"),
        ]);
        assert_eq!(
            g.blocks(ip("192.168.0.10"), 0),
            None,
            "allow overrides the wildcard deny"
        );
        assert!(g.blocks(ip("192.168.1.10"), 0).is_some());
        assert_eq!(
            g.blocks(ip("192.168.0.255"), 0),
            None,
            "allow endpoint allowed"
        );
    }

    /// Bans outrank allow (local policy: reactive misbehavior evidence is
    /// not exempted by a static allow); expiry (`until > now` to block)
    /// allows.
    #[test]
    fn ban_overrides_allow_and_expires() {
        let g = IpGuard::new(
            [rule(RuleAction::Allow, "0.0.0.0", "255.255.255.255")],
            [(
                ip("1.2.3.4"),
                BanRecord {
                    reason: "bad pieces".into(),
                    until: 1000,
                },
            )],
        );
        assert_eq!(
            g.blocks(ip("1.2.3.4"), 999),
            Some(IpBlock::Banned("bad pieces".into())),
            "ban hit and carries the reason"
        );
        assert_eq!(
            g.blocks(ip("1.2.3.4"), 1000),
            None,
            "until=1000, now=1000: until > now does not hold -> expired, allowed"
        );
        assert_eq!(
            g.blocks(ip("5.6.7.8"), 0),
            None,
            "a non-banned IP passes via allow"
        );
    }

    /// v6 judged independently + IPv4-mapped v6 judged in the v4 domain.
    #[test]
    fn v6_and_v4_mapped() {
        let g = IpGuard::new(
            [FilterRule {
                action: RuleAction::Deny,
                start: ip("2001:db8::"),
                end: ip("2001:db8::ff"),
            }],
            [(
                ip("10.0.0.5"),
                BanRecord {
                    reason: "r".into(),
                    until: 10,
                },
            )],
        );
        assert!(g.blocks(ip("2001:db8::10"), 0).is_some());
        assert_eq!(g.blocks(ip("2001:db9::1"), 0), None);
        // ::ffff:10.0.0.5 hits the v4 ban table.
        let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            g.blocks(mapped, 0),
            Some(IpBlock::Banned("r".into())),
            "v4-mapped reuses the v4 ban table"
        );
        assert_eq!(
            g.blocks(ip("::1"), 0),
            None,
            "a non-mapped v6 does not hit the v4 table"
        );
    }

    /// Lenient v4 parsing: zero padding, 3-digit cap, octet <= 255,
    /// exactly 4 parts.
    #[test]
    fn lenient_ipv4_parse() {
        assert_eq!(parse_ip_lenient("000.000.000.000"), Some(ip("0.0.0.0")));
        assert_eq!(parse_ip_lenient("127.000.000.001"), Some(ip("127.0.0.1")));
        assert_eq!(parse_ip_lenient(" 10.1.2.3 "), Some(ip("10.1.2.3")));
        assert_eq!(parse_ip_lenient("256.0.0.1"), None, "octet out of range");
        assert_eq!(
            parse_ip_lenient("1234.0.0.1"),
            None,
            "octet longer than 3 digits"
        );
        assert_eq!(parse_ip_lenient("1.2.3"), None, "wrong part count");
        assert_eq!(parse_ip_lenient("a.b.c.d"), None, "non-numeric");
    }

    /// CIDR parsing: v4/v6, the /0 and /32 boundaries, out-of-range
    /// prefixes rejected.
    #[test]
    fn cidr_parse() {
        let r = parse_cidr("10.9.9.0/24").unwrap_or_else(|| panic!("/24"));
        assert_eq!(r.start, ip("10.9.9.0"));
        assert_eq!(r.end, ip("10.9.9.255"));
        let r0 = parse_cidr("1.2.3.4/0").unwrap_or_else(|| panic!("/0"));
        assert_eq!(r0.end, ip("255.255.255.255"));
        let r32 = parse_cidr("1.2.3.4/32").unwrap_or_else(|| panic!("/32"));
        assert_eq!(r32.start, r32.end);
        assert!(parse_cidr("1.2.3.0/33").is_none());
        assert!(parse_cidr("1.2.3.0").is_none());
        let r6 = parse_cidr("2001:db8::/32").unwrap_or_else(|| panic!("v6"));
        assert_eq!(r6.start, ip("2001:db8::"));
        assert_eq!(parse_cidr("2001:db8::/129"), None, "v6 prefix out of range");
    }

    fn report(lines: &[&str]) -> ParsedBlocklist {
        parse_emule_dat(&lines.join("\n"))
    }

    /// eMule `.dat` positive/negative sample table (grammar = SPEC §13 /
    /// design-pinned `deny/allow,from,to`; deny/allow semantics mirror
    /// the eMule "IP Filters" help page — see the module-doc format
    /// section).
    #[test]
    fn emule_dat_positive_and_negative_samples() {
        let parsed = report(&[
            // ---- positive samples (6 valid rules) ----
            "deny,000.000.000.000,000.255.255.255", // 1. eMule zero-padded v4 range
            "allow,192.168.0.1,192.168.0.255",      // 2. allow action
            "DENY,10.0.0.1,10.0.0.1",               // 3. case-insensitive action + single-IP range
            "  deny , 172.16.0.0 , 172.31.255.255 ", // 4. whitespace around fields
            "# comment line",                       // 5. comment line ignored (not counted skipped)
            "",                                     // 6. blank line ignored
            "deny,2001:db8::,2001:db8::ff",         // 7. v6 range
            "allow,::1,::1",                        // 8. v6 single IP
        ]);
        assert_eq!(parsed.rules.len(), 6, "6 valid rules");
        assert_eq!(
            parsed.skipped, 0,
            "comments/blank lines not counted as skipped"
        );
        assert_eq!(parsed.rules[0].action, RuleAction::Deny);
        assert_eq!(parsed.rules[0].start, ip("0.0.0.0"));
        assert_eq!(parsed.rules[0].end, ip("0.255.255.255"));
        assert_eq!(parsed.rules[1].action, RuleAction::Allow);
        assert_eq!(
            parsed.rules[2].start, parsed.rules[2].end,
            "single-IP range"
        );
        assert_eq!(parsed.rules[4].start, ip("2001:db8::"));

        let parsed = report(&[
            // ---- negative samples (7; each counted skipped, no whole-file failure) ----
            "block,1.2.3.4,5.6.7.8",      // 9. unknown action
            "deny,1.2.3.4",               // 10. missing to field
            "deny,1.2.3.4,5.6.7.8,extra", // 11. extra field
            "deny,256.0.0.1,5.6.7.8",     // 12. octet out of range
            "deny,5.6.7.8,1.2.3.4",       // 13. start > end invalid (no silent swap)
            "deny,1.2.3.4,2001:db8::1",   // 14. v4/v6 cross-family
            "000.000.000.000 - 000.255.255.255 , 000 , invalid", // 15. eMule classic
                                          // "IP-Range , Access Level , Description" variant: not this parser's
                                          // input (see the module-doc format section) -> counted skipped.
        ]);
        assert_eq!(parsed.rules.len(), 0);
        assert_eq!(parsed.skipped, 7, "negative samples counted line by line");
    }

    /// Rule text roundtrip: to_blocklist_text -> parse_blocklist_rule is
    /// the identity.
    #[test]
    fn rule_text_roundtrip() {
        for r in [
            rule(RuleAction::Deny, "10.0.0.0", "10.0.255.255"),
            FilterRule {
                action: RuleAction::Allow,
                start: ip("2001:db8::"),
                end: ip("2001:db8::ff"),
            },
        ] {
            let t = r.to_blocklist_text();
            assert_eq!(parse_blocklist_rule(&t), Some(r), "roundtrip {t}");
        }
        // RuleKind table kind text (SPEC §5.3: cidr|p2p-blocklist).
        assert_eq!(RuleKind::Cidr.as_str(), "cidr");
        assert_eq!(RuleKind::P2PBlocklist.as_str(), "p2p-blocklist");
    }

    /// IpGuardHandle hot swap: load observes a store immediately (arc-swap
    /// semantics); Clone shares the same snapshot slot.
    #[test]
    fn handle_hot_swap_visible_to_loaders() {
        let handle = IpGuardHandle::new(guard_of(vec![rule(
            RuleAction::Deny,
            "10.0.0.0",
            "10.0.0.255",
        )]));
        assert!(handle.load().blocks(ip("10.0.0.1"), 0).is_some());
        handle.store(guard_of(vec![]));
        assert_eq!(
            handle.load().blocks(ip("10.0.0.1"), 0),
            None,
            "allowed after the hot swap"
        );
        let clone = handle.clone();
        clone.store(guard_of(vec![rule(
            RuleAction::Deny,
            "0.0.0.0",
            "255.255.255.255",
        )]));
        assert!(handle.load().blocks(ip("8.8.8.8"), 0).is_some());
    }

    /// Default empty list = no client ever banned (identification is not
    /// banning).
    #[test]
    fn client_deny_default_empty_never_blocks() {
        let g = IpGuard::default();
        assert_eq!(
            g.client_blocks(Some(b"-XL0011-0123456789AB"), Some("Xunlei 5")),
            None,
            "the default snapshot (no config) never rejects by identity"
        );
        // An explicitly empty config likewise always allows.
        let g = IpGuard::default().with_client_deny(["".to_string(), "  ".to_string()]);
        assert_eq!(g.client_blocks(Some(b"-XL0011-0123456789AB"), None), None);
        // A peer matching no configured prefix is allowed.
        let g = IpGuard::default().with_client_deny(["-XL".to_string()]);
        assert_eq!(g.client_blocks(Some(b"-qB4550-0123456789AB"), None), None);
    }

    /// Identity verdict: peer_id byte prefix OR `v` field substring
    /// (case-insensitive); the first matching config entry is returned;
    /// config normalization (trim / dedup).
    #[test]
    fn client_deny_prefix_and_v_matching() {
        let g = IpGuard::default().with_client_deny([
            " -XL ".to_string(),
            "-QD".to_string(),
            "-XL".to_string(), // duplicate: dedup, order preserved.
            "xunlei".to_string(),
        ]);
        assert_eq!(
            g.client_blocks(Some(b"-XL0011-0123456789AB"), None),
            Some("-XL".to_string()),
            "peer_id byte-prefix hit (after normalization)"
        );
        assert_eq!(
            g.client_blocks(Some(b"-QD0011-0123456789AB"), None),
            Some("-QD".to_string())
        );
        assert_eq!(
            g.client_blocks(None, Some("Xunlei 5.0.1.2")),
            Some("xunlei".to_string()),
            "v field substring hit (case-insensitive)"
        );
        // The prefix must match from the start (a substring at a non-prefix
        // position is not a peer_id hit).
        assert_eq!(
            g.client_blocks(Some(b"xx-XL0011-012345678A"), None),
            None,
            "no hit at a non-prefix position"
        );
    }

    /// Manual ban ranges: same priority as automatic bans (before allow),
    /// expiry allows, v6 ranges, cross-family ranges skipped.
    #[test]
    fn manual_ban_ranges_priority_and_expiry() {
        let rec = |until| BanRecord {
            reason: "manual".into(),
            until,
        };
        let g = IpGuard::new([rule(RuleAction::Allow, "0.0.0.0", "255.255.255.255")], [])
            .with_manual_bans([
                (ip("10.0.0.0"), ip("10.0.0.255"), rec(1000)),
                (ip("2001:db8::"), ip("2001:db8::ff"), rec(i64::MAX)),
                // Cross-family / inverted ranges are defensively skipped.
                (ip("1.2.3.4"), ip("2001:db8::1"), rec(1000)),
                (ip("9.9.9.9"), ip("9.9.9.0"), rec(1000)),
            ]);
        // A manual ban hit carries the reason (a blocklist wildcard allow does not exempt).
        assert_eq!(
            g.blocks(ip("10.0.0.77"), 999),
            Some(IpBlock::Banned("manual".into()))
        );
        // Blocks only while until > now: expired allows.
        assert_eq!(g.blocks(ip("10.0.0.77"), 1000), None);
        // Outside the range allows.
        assert_eq!(g.blocks(ip("10.0.1.1"), 0), None);
        // v6 range (permanent = until i64::MAX).
        assert_eq!(
            g.blocks(ip("2001:db8::10"), 0),
            Some(IpBlock::Banned("manual".into()))
        );
        assert_eq!(g.blocks(ip("2001:db9::1"), 0), None);
    }

    // ---- BEP-40 symmetric rank (structural properties; upstream has no
    // known value vectors or peer_priority test cases, so these are
    // anchored on structure — the crc32c primitive is anchored by standard
    // check values in security.rs) ----

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap_or_else(|e| panic!("bad addr {s}: {e}"))
    }

    /// Symmetry (an intrinsic BEP-40 property; both sides compute
    /// identically): v4 different addresses / v6 different addresses /
    /// same address different ports / identical endpoints —
    /// rank(a,b) == rank(b,a).
    #[test]
    fn bep40_rank_symmetric() {
        let v4a = sa("203.0.113.7:6881");
        let v4b = sa("198.51.100.9:51413");
        let v6a = sa("[2001:db8::10]:6881");
        let v6b = sa("[2620:0:2d0:200::7]:40000");
        let sameip1 = sa("203.0.113.7:6881");
        let sameip2 = sa("203.0.113.7:40000");
        for (a, b) in [
            (v4a, v4b),
            (v6a, v6b),
            (sameip1, sameip2),
            (v4a, v4a),
            (v6a, v6a),
        ] {
            assert_eq!(bep40_rank(a, b), bep40_rank(b, a), "symmetry {a} <-> {b}");
        }
        // Cross-family: ranking-neutral fixed value 0 (identical both ways).
        assert_eq!(bep40_rank(v4a, v6a), 0);
        assert_eq!(bep40_rank(v6a, v4a), 0);
    }

    /// v4 mask semantics (`torrent_peer.cpp`): memcmp differs within 2B ->
    /// row 0 `{ff,ff,55,55}` — bytes 0/1 kept, bytes 2/3 partially masked
    /// by 0x55 (even bits kept, odd bits erased). Property: candidates
    /// differing only in **erased bits** (odd bits of mask bytes) get
    /// identical ranks; differing in **kept bits** (bytes 0/1 and even
    /// bits of mask bytes) get different ranks. 0x55 is a partial mask —
    /// endpoint pairs within the same /16 generally get different ranks
    /// (low-order clustering is not neutralization; the BEP-40 intent).
    #[test]
    fn bep40_rank_v4_mask_erased_bits_neutral() {
        let self_ep = sa("203.0.113.1:6881");
        let a = sa("198.51.100.9:1000");
        // Row choice depends only on the first-differing depth between self
        // and the candidate (203 vs 198: byte 0 differs -> row 0); flipping
        // erased bits on the candidate (odd bits of bytes 2/3) changes
        // neither the row nor the masked input -> identical rank.
        let a_flip_erased = {
            let m = match a {
                SocketAddr::V4(v4) => v4.ip().octets(),
                _ => unreachable!(),
            };
            sa(&format!("198.51.{}.{}:1000", m[2] | 0xAA, m[3] | 0xAA))
        };
        assert_eq!(bep40_rank(self_ep, a), bep40_rank(self_ep, a_flip_erased));
        // Kept-bit flip (byte 1: 51 -> 52) -> different rank.
        let b = sa("198.52.100.9:1000");
        assert_ne!(bep40_rank(self_ep, a), bep40_rank(self_ep, b));
        // Kept-bit flip (even bit of mask byte 2: 0x64 -> 0x74, bit 4) -> differs.
        let c = sa("198.51.116.9:1000");
        assert_ne!(bep40_rank(self_ep, a), bep40_rank(self_ep, c));
        // Determinism: same input, same output across calls.
        assert_eq!(bep40_rank(self_ep, a), bep40_rank(self_ep, a));
    }

    /// v6 mask semantics (`torrent_peer.cpp`): first differing byte i ->
    /// offset = max(i+1, 5); bytes at positions > offset are partially
    /// masked 0x55 on both sides. Property: flipping erased bits (odd
    /// bits) inside the masked region -> identical rank; flipping
    /// kept-region bits (<= offset) -> different rank.
    #[test]
    fn bep40_rank_v6_mask_offset_semantics() {
        // self and a first differ at byte 8 (group[4] high byte 0x80 vs
        // 0x00) -> offset = max(9,5) = 9: bytes 0..9 kept, 10..15 masked.
        let self_ep = sa("[2001:db8::1]:6881");
        let a = sa("[2001:db8:0:0:8000::]:1000");
        let oct = |x: SocketAddr| match x {
            SocketAddr::V6(v6) => v6.ip().octets(),
            _ => unreachable!(),
        };
        // Masked-region erased-bit flip (byte 10 odd bit) -> masked input
        // unchanged -> identical rank.
        let mut erased = oct(a);
        erased[10] |= 0xAA;
        let a_erased = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(erased)), 1000);
        assert_eq!(bep40_rank(self_ep, a), bep40_rank(self_ep, a_erased));
        // Kept-region flip (byte 9 keeps every bit) -> different rank.
        let mut kept = oct(a);
        kept[9] |= 0xAA;
        let a_kept = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(kept)), 1000);
        assert_ne!(bep40_rank(self_ep, a), bep40_rank(self_ep, a_kept));
        // The offset floor of 5 in effect: base and x first differ at byte 3
        // (0c08 vs 0c09) -> offset = max(4,5) = 5 -> bytes 6..15 are the
        // masked region (a byte-7 flip is absorbed).
        let base = sa("[2001:0c08::1]:6881");
        let x = sa("[2001:0c09::3]:1000");
        let mut x_erased = oct(x);
        x_erased[7] |= 0xAA;
        let x_erased = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(x_erased)), 1000);
        assert_eq!(bep40_rank(base, x), bep40_rank(base, x_erased));
    }
}

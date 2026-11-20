//! Declarative multi-interface listen face
//! (`taiji.listen-interfaces`, the `taiji.*` extension namespace): parse
//! -> enumerate -> expand -> diff-rebuild, modeled on the libtorrent
//! `listen_interfaces` discipline.
//!
//! Pipeline (upstream anchors — the oracle is read-only
//! `third_party/libtorrent`):
//!
//! 1. **Parse** [`parse_listen_interfaces`]: a comma list of
//!    `device-or-IP:port` entries (`[v6]:port` bracket form; no suffix
//!    flags — ssl/local-network stay out of the grammar, a stated
//!    minimal-surface divergence). Invalid entries are collected and
//!    warned **individually**, never fatal (the per-entry discipline of
//!    `parse_listen_interfaces`, `src/string_util.cpp:180-250`).
//! 2. **Enumerate + expand** [`expand_listen_interfaces`]: device names
//!    resolve to one endpoint per interface address
//!    (`interface_to_endpoints`, `src/session_impl.cpp:2038-2074`);
//!    wildcard addresses (`0.0.0.0`/`::`) expand to one endpoint per
//!    enumerated interface address of the same family, deduplicated
//!    against explicit endpoints (`expand_unspecified_address`,
//!    `src/session_impl.cpp:254-309` — the BEP 32/45 multi-homed
//!    shape; the upstream `preferred`/up-state interface filter stays
//!    simplified away — every enumerated address counts, a declared
//!    residual in `docs/design/listen-interfaces.md`). Enumeration
//!    failure or an empty
//!    expansion degrades to the standing single-wildcard listen shape
//!    (the platform capability-fallback precedent: Android API>=24
//!    keeps the unspecified socket when route enumeration is
//!    unavailable, `src/session_impl.cpp:2178-2190`).
//! 3. **Bind** [`bind_listen_faces`]: one TCP listener + one UDP demux
//!    per endpoint (exact ports — a bind failure degrades that face's
//!    transport, it never silently moves the port; the single
//!    announce-port seam makes a per-face port walk counterproductive,
//!    a stated divergence from the upstream port-retry).
//! 4. **Diff rebuild** [`partition_listen_faces`]: reconfiguration
//!    partitions the existing face set against the desired endpoint
//!    set keyed by `(address, port)` — untouched faces (and their
//!    riders) stay exactly as-is, only removed faces close, only new
//!    endpoints open (`partition_listen_sockets`,
//!    `src/session_impl.cpp:218-248`, consumed at
//!    `src/session_impl.cpp:2194-2230`). Rebuild trigger today =
//!    engine assembly (the option is startup-only, the same rule as
//!    `--listen-port`); the partition function is the seam a future
//!    runtime-rebuild trigger plugs into.
//!
//! ID discipline: every bound face carries a
//! [`ListenFaceId`] from a process-wide monotonic counter — never
//! reused by a later face once its holder is dropped (the
//! `listen_socket_t::id` rule, `include/libtorrent/aux_/session_impl.hpp:
//! 168-170`), so long-lived referents (metrics, observation surfaces,
//! the route context) can hold ids safely.
//!
//! **Phase 3 — per-destination dispatch and ingress verification**
//! (this module's routing surface; upstream anchors):
//!
//! - Every expanded endpoint carries the **OS netmask** of its owning
//!   interface ([`ListenEndpoint::netmask`]; the `expand_devices`
//!   attachment, `src/session_impl.cpp:311-338`: a literal inside an
//!   interface's subnet adopts that interface's netmask and device
//!   name; an unresolvable literal gets the family's `/0` — which
//!   matches everything, the same upstream default) plus the
//!   **local-network classification** ([`ListenEndpoint::local_network`]:
//!   loopback/link-local addresses only — the route-table-dependent
//!   arm of the upstream classification stays a declared residual).
//! - [`can_route`] mirrors `listen_socket_t::can_route`
//!   (`src/session_impl.cpp:340-355`): family gate, v6 scope gate,
//!   exact/wildcard/subnet arms, and the final "a non-local face
//!   routes the rest" arm.
//! - [`pick_route_face`] is the per-destination face pick (the uTP
//!   socket-choice arm of `bind_outgoing_socket`,
//!   `src/session_impl.cpp:5408-5437` — "almost, but not quite, like
//!   can_route()"): the LAST netmask-matching face of the destination
//!   family wins; no match falls back to the first non-local face of
//!   the family (the deterministic stand-in for the upstream random
//!   gateway pick), then to the family primary — single-face and
//!   unset configs pick exactly the face the phase-2 primary
//!   discipline picked.
//! - [`IngressAllowlist`]: with `--interface` set, inbound peer
//!   connections are verified against the egress address
//!   (`verify_bound_address`, `src/session_impl.cpp:5483-5512` — the
//!   accept-path rejection at `src/session_impl.cpp:3146-3190`,
//!   `peer_blocked_alert::invalid_local_interface`); rejections are
//!   counter-observed (`taiji_peer_blocked_ingress_total`), never
//!   alerted or logged per packet.
//!
//! Interaction with the phase-1 egress bind (`--interface`,
//! [`crate::config::EngineConfig::egress`]): the egress family narrows
//! the expanded endpoint set (an egress-bound engine does not listen on
//! the other family — the same leak rationale as the UDP-face plan,
//! [`crate::dht::udp_face_plan`]). The full matrix lives in
//! `docs/design/listen-interfaces.md`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use taiji_bt::dht::DhtFamily;

/// Process-wide monotonic face-id source (starts at 1; 0 reserved as
/// the "never assigned" reading).
static NEXT_LISTEN_FACE_ID: AtomicU64 = AtomicU64::new(0);

/// Stable identity of one bound listen face. Monotonic and never
/// reused: closing a face retires its id permanently; a rebuilt face
/// for the same endpoint gets a fresh, strictly larger id (the
/// `listen_socket_t::id` discipline — references held across a
/// rebuild cannot alias an unrelated new face).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListenFaceId(u64);

/// Allocates the next face id (monotonic, never reused).
pub fn next_listen_face_id() -> ListenFaceId {
    ListenFaceId(NEXT_LISTEN_FACE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1)
}

/// One parsed `taiji.listen-interfaces` entry: a device name or IP
/// literal plus a port (the upstream `listen_interface_t` shape minus
/// the ssl/local flags, which this grammar does not carry). The
/// device-vs-literal verdict happens at expansion (parse stays
/// string-faithful so the raw value can be echoed/logged per entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenInterface {
    /// Device name or IP literal (brackets stripped from the `[v6]`
    /// form; the literal is parsed at expansion time — a syntactically
    /// legal but unbindable literal warns there, per-entry).
    pub device: String,
    /// Listen port (0 = OS-assigned per face; see the module docs on
    /// the exact-port rule).
    pub port: u16,
}

/// One expanded listen endpoint: the bind address a face will hold,
/// with the phase-3 routing context (upstream `listen_endpoint_t` minus
/// ssl/flags: the OS netmask of the owning interface, the local-network
/// classification, and the originating device name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenEndpoint {
    /// Concrete bind address (wildcards are fully expanded away; an
    /// expansion that yields nothing for a wildcard entry is the
    /// degradation path, never a wildcard bind sneaking through).
    pub addr: IpAddr,
    pub port: u16,
    /// Originating device name (empty for IP-literal entries that no
    /// interface row claims; device-name, wildcard-expanded, and
    /// subnet-adopted literal entries carry the owning device's name).
    pub device: String,
    /// OS netmask of the owning interface (the `expand_devices`
    /// attachment, `src/session_impl.cpp:311-338`): a literal inside an
    /// interface's subnet adopts that interface's netmask (and device
    /// name); an unresolvable literal gets the family's `/0`, which
    /// [`match_addr_mask`] treats as match-everything (the same
    /// upstream default for "we can't find which device this is for").
    pub netmask: IpAddr,
    /// Local-network classification (the address-classification subset
    /// of the upstream flag: loopback or link-local bind addresses on
    /// expanded endpoints — upstream `interface_to_endpoints`
    /// `src/session_impl.cpp:2066-2068` and `expand_unspecified_address`
    /// `:297-302`; the `!is_global` route-table-dependent arm and the
    /// user `l` suffix are not expressible here, a declared residual).
    /// Consumed by [`can_route`]'s final arm and the
    /// [`pick_route_face`] gateway fallback.
    pub local_network: bool,
}

impl ListenEndpoint {
    /// Diff key (upstream matches address+port; the device name is
    /// informational — two entries resolving to the same `(addr, port)`
    /// are the same bind).
    fn key(&self) -> (IpAddr, u16) {
        (self.addr, self.port)
    }

    /// Address family (the DHT/UDP-face grouping key).
    pub fn family(&self) -> DhtFamily {
        match self.addr {
            IpAddr::V4(_) => DhtFamily::V4,
            IpAddr::V6(_) => DhtFamily::V6,
        }
    }
}

/// The family's `/0` (match-everything) netmask for unresolvable
/// endpoints (upstream `build_netmask(0, family)`).
fn zero_netmask(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    }
}

/// `(a & mask) == (b & mask)` (upstream `match_addr_mask`,
/// `src/enum_net.cpp:582-604`): all three addresses must share one
/// family. The upstream v6 scope-id comparison lives in
/// [`can_route`] here instead (one gate, same verdict).
pub fn match_addr_mask(a: IpAddr, b: IpAddr, mask: IpAddr) -> bool {
    if a.is_ipv4() != b.is_ipv4() || a.is_ipv4() != mask.is_ipv4() {
        return false;
    }
    match (a, b, mask) {
        (IpAddr::V4(a), IpAddr::V4(b), IpAddr::V4(m)) => {
            (u32::from(a) & u32::from(m)) == (u32::from(b) & u32::from(m))
        }
        (IpAddr::V6(a), IpAddr::V6(b), IpAddr::V6(m)) => {
            let (a, b, m) = (a.octets(), b.octets(), m.octets());
            a.iter()
                .zip(b.iter())
                .zip(m.iter())
                .all(|((x, y), mm)| (x & mm) == (y & mm))
        }
        // unreachable: the family gate above already returned
        _ => false,
    }
}

/// Link-local predicate (upstream `is_link_local`,
/// `src/enum_net.cpp`): v4 `169.254.0.0/16` (RFC 3927), v6
/// `fe80::/10`.
fn is_link_local_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            let b = v6.octets();
            b[0] == 0xfe && (b[1] & 0xc0) == 0x80
        }
    }
}

/// Whether this endpoint's socket may reach `dest` (upstream
/// `listen_socket_t::can_route`, `src/session_impl.cpp:340-355`; the
/// proxy arm has no taiji counterpart — no proxy faces exist):
///
/// | arm | verdict |
/// |---|---|
/// | family mismatch | false |
/// | v6 and scope ids differ | false (taiji listen endpoints are scope-less `std` addresses — local scope is always 0, so a scoped destination never matches) |
/// | exact address equality | true |
/// | wildcard local address | true (the default-path faces) |
/// | netmask match | true |
/// | otherwise | `!local_network` (a gateway-classified face routes the rest; a local-network face refuses off-subnet destinations) |
pub fn can_route(endpoint: &ListenEndpoint, dest: SocketAddr) -> bool {
    if endpoint.addr.is_ipv4() != dest.is_ipv4() {
        return false;
    }
    // Scope gate: the local endpoint carries no scope id (std IpAddr
    // cannot represent one; the grammar cannot express scoped binds),
    // so any scoped destination mismatches — the oracle's
    // link-local cross-device disambiguation degenerates to "scoped
    // destinations only route via scoped faces", of which this build
    // has none.
    if let SocketAddr::V6(v6) = dest {
        if v6.scope_id() != 0 {
            return false;
        }
    }
    if endpoint.addr == dest.ip() {
        return true;
    }
    if endpoint.addr.is_unspecified() {
        return true;
    }
    if match_addr_mask(dest.ip(), endpoint.addr, endpoint.netmask) {
        return true;
    }
    !endpoint.local_network
}

/// One face's route-dispatch entry: the endpoint identity (address +
/// netmask + classification) with the primary marker, carrying the
/// per-face rider being dispatched to (a demux handle, a dial-service
/// channel, ...).
#[derive(Clone)]
pub struct RouteFace<T> {
    /// The face's endpoint (the dispatch predicate input).
    pub endpoint: ListenEndpoint,
    /// First-bound face of the family (the fallback rider; see
    /// [`pick_route_face`]).
    pub primary: bool,
    /// The dispatched rider.
    pub rider: T,
}

impl<T> RouteFace<T> {
    /// Address family (the dispatch grouping key).
    pub fn family(&self) -> DhtFamily {
        self.endpoint.family()
    }
}

/// Per-destination face pick across one family's faces (the uTP
/// socket-choice arm of upstream `bind_outgoing_socket`,
/// `src/session_impl.cpp:5408-5437` — "this is almost, but not quite,
/// like can_route()"): same-family faces only; the LAST netmask-matching
/// face wins (the upstream loop overwrites its match per hit); with no
/// netmask match the fallback is the first non-local face of the family
/// (the deterministic stand-in for the upstream random pick among
/// gateway faces — same candidate set, minus the randomness, for
/// observable dispatch), then the family primary (single-face configs
/// keep the phase-2 primary pick exactly). `None` = no same-family
/// face (the dial/send fails, the existing family-unavailable class).
pub fn pick_route_face<T>(faces: &[RouteFace<T>], dest: SocketAddr) -> Option<&RouteFace<T>> {
    let family = match dest {
        SocketAddr::V4(_) => DhtFamily::V4,
        SocketAddr::V6(_) => DhtFamily::V6,
    };
    let mut netmask_match = None;
    let mut gateway = None;
    let mut primary = None;
    for face in faces {
        if face.family() != family {
            continue;
        }
        if primary.is_none() && face.primary {
            primary = Some(face);
        }
        if gateway.is_none() && !face.endpoint.local_network {
            gateway = Some(face);
        }
        if match_addr_mask(face.endpoint.addr, dest.ip(), face.endpoint.netmask) {
            netmask_match = Some(face);
        }
    }
    netmask_match.or(gateway).or(primary)
}

/// Egress allowlist for ingress verification (upstream
/// `verify_bound_address`, `src/session_impl.cpp:5483-5512`, reduced to
/// taiji's single-value `--interface` semantics): when the egress bind
/// is armed, an inbound peer connection's local address must equal the
/// egress address. The upstream device-name arm (resolve the owning
/// device via the cached interface table) is structurally absorbed:
/// taiji's CLI resolves device names to one address before the engine
/// boundary, so the engine-side allowlist is always a literal. `None`
/// (egress unset) = zero verification, the status quo.
#[derive(Debug, Clone)]
pub struct IngressAllowlist {
    egress: IpAddr,
}

impl IngressAllowlist {
    /// Arm from the egress bind (`None` = unset = no verification).
    pub fn resolve(egress: Option<IpAddr>) -> Option<Self> {
        egress.map(|egress| Self { egress })
    }

    /// Whether an inbound connection with this local address may pass
    /// (the IP-literal arm; a family mismatch is inherently a
    /// non-match).
    pub fn allows(&self, local: IpAddr) -> bool {
        local == self.egress
    }
}

/// Ingress verification state for the accept paths (the TCP face
/// accept tasks, the default-path dual-stack merge, and the per-face
/// uTP inbound pumps): the egress allowlist plus the rejection
/// counter. Default (egress unset) admits every local address with
/// zero counting — the status quo. When armed, an inbound connection
/// whose local address is not on the egress allowlist is dropped at
/// the door and counted (`taiji_peer_blocked_ingress_total`) — the
/// upstream `invalid_local_interface` rejection, counter-observed
/// instead of alerted (no alert storms, no per-packet logs).
#[derive(Clone, Default)]
pub(crate) struct IngressVerify {
    allow: Option<IngressAllowlist>,
    metrics: Option<std::sync::Arc<crate::metrics::SessionMetrics>>,
}

impl IngressVerify {
    /// Arm from the egress bind and the session metrics slot
    /// (`None, None` = the status quo: no verification, no counting).
    pub(crate) fn new(
        egress: Option<IpAddr>,
        metrics: Option<std::sync::Arc<crate::metrics::SessionMetrics>>,
    ) -> Self {
        Self {
            allow: IngressAllowlist::resolve(egress),
            metrics,
        }
    }

    /// Verdict for one inbound connection's local address: `true` =
    /// admitted; `false` = rejected (the counter increment happens
    /// here — one feed point per rejected connection, Relaxed).
    pub(crate) fn admit(&self, local: IpAddr) -> bool {
        let Some(allow) = &self.allow else {
            return true;
        };
        let ok = allow.allows(local);
        if !ok {
            if let Some(m) = &self.metrics {
                m.note_peer_blocked_ingress();
            }
        }
        ok
    }
}

/// Parses the `taiji.listen-interfaces` value (upstream
/// `parse_listen_interfaces`, `src/string_util.cpp:180-250`): a comma
/// list of `device-or-IP:port`; `[v6]:port` for IPv6 literals; empty
/// elements between commas are skipped; each invalid entry is returned
/// in the error list **individually** (the caller warns per entry,
/// never fails wholesale). Divergence (stated): no quoted device names
/// and no `s`/`l` suffix flags — any trailing characters after the
/// port digits make the entry invalid (upstream consumes the flags;
/// this grammar has no SSL or local-network face to drive).
pub fn parse_listen_interfaces(input: &str) -> (Vec<ListenInterface>, Vec<String>) {
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for element in input.split(',') {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }
        // Bracket form: `[v6]:port` (a bare multi-colon v6 literal has
        // no unambiguous split — brackets are mandatory, the same rule
        // as upstream).
        let (device, port_str) = if let Some(rest) = element.strip_prefix('[') {
            let Some((dev, tail)) = rest.split_once(']') else {
                errs.push(element.to_string());
                continue;
            };
            match tail.strip_prefix(':') {
                Some(p) => (dev.trim(), p),
                None => {
                    errs.push(element.to_string());
                    continue;
                }
            }
        } else {
            match element.split_once(':') {
                // First colon = the separator (device names carry no
                // colons; a v6 literal must use brackets).
                Some((dev, p)) => (dev.trim(), p),
                None => {
                    errs.push(element.to_string());
                    continue;
                }
            }
        };
        // Port: leading digits, at most 5, value <= 65535 (the upstream
        // domain; 0 = OS-assigned). Any non-digit remainder is invalid
        // (no suffix flags in this grammar).
        let digits: String = port_str.chars().take_while(char::is_ascii_digit).collect();
        let mut invalid = || errs.push(element.to_string());
        if device.is_empty() || digits.is_empty() || digits.len() > 5 {
            invalid();
            continue;
        }
        let Ok(port) = digits.parse::<u32>() else {
            invalid();
            continue;
        };
        if port > u16::MAX as u32 || !port_str[digits.len()..].trim().is_empty() {
            invalid();
            continue;
        }
        out.push(ListenInterface {
            device: device.to_string(),
            port: port as u16,
        });
    }
    (out, errs)
}

/// One OS interface-table row (getifaddrs): device name, address, and
/// the address's OS netmask (the phase-3 route context source).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddr {
    pub name: String,
    pub addr: IpAddr,
    pub netmask: IpAddr,
}

/// OS interface-table enumeration (getifaddrs via if-addrs, an
/// existing workspace dependency — a local syscall, no network IO).
/// Returns rows in table order, each carrying the address's netmask.
pub fn enumerate_interface_addrs() -> std::io::Result<Vec<InterfaceAddr>> {
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .map(|i| InterfaceAddr {
            netmask: match &i.addr {
                if_addrs::IfAddr::V4(v4) => IpAddr::V4(v4.netmask),
                if_addrs::IfAddr::V6(v6) => IpAddr::V6(v6.netmask),
            },
            addr: i.ip(),
            name: i.name,
        })
        .collect())
}

/// Expands parsed entries into concrete endpoints against an interface
/// table (pure; the table is injected so tests pin the topology — no
/// real multi-NIC requirement). Warnings are per entry (unknown
/// device, wildcard with no matching address) and never fatal.
///
/// Steps (upstream `reopen_listen_sockets` shape,
/// `src/session_impl.cpp:2090-2230`):
///
/// 1. IP literals pass through as-is (device empty until the netmask
///    step backfills the owning device); an unspecified literal
///    (`0.0.0.0`/`::`) becomes a wildcard to expand;
/// 2. device names expand to one endpoint per matching interface
///    address (`interface_to_endpoints`), each carrying the row's
///    netmask and the loopback/link-local local-network
///    classification;
/// 3. wildcards expand to one endpoint per same-family interface
///    address, deduplicated against the explicit set
///    (`expand_unspecified_address` — the BEP 32/45 per-interface
///    shape, same netmask/classification attachment; the
///    `preferred`/up-state filters are simplified away, see the
///    module docs);
/// 4. literal endpoints adopt the owning interface's netmask: the
///    first row whose subnet contains the literal (`expand_devices`,
///    `src/session_impl.cpp:311-338` — device backfilled); a literal
///    no row claims keeps the family's `/0` (match-everything) and the
///    gateway classification;
/// 5. the egress bind family (`--interface`) narrows the set — an
///    egress-bound engine keeps only same-family endpoints (the UDP
///    leak rationale of [`crate::dht::udp_face_plan`]);
/// 6. the final list is deduplicated by `(addr, port)` (first entry
///    wins; stable order = spec order, then table order).
pub fn expand_listen_interfaces(
    specs: &[ListenInterface],
    ifaces: &[InterfaceAddr],
    egress: Option<IpAddr>,
) -> (Vec<ListenEndpoint>, Vec<String>) {
    let mut eps: Vec<ListenEndpoint> = Vec::new();
    let mut wildcards: Vec<ListenEndpoint> = Vec::new();
    let mut warns: Vec<String> = Vec::new();
    for spec in specs {
        if let Ok(addr) = spec.device.parse::<IpAddr>() {
            if addr.is_unspecified() {
                wildcards.push(ListenEndpoint {
                    addr,
                    port: spec.port,
                    device: String::new(),
                    netmask: zero_netmask(addr),
                    local_network: false,
                });
            } else {
                eps.push(ListenEndpoint {
                    addr,
                    port: spec.port,
                    device: String::new(),
                    netmask: zero_netmask(addr),
                    // Literals stay gateway-classified until (and
                    // unless) the netmask step adopts an owning row —
                    // upstream `interface_to_endpoints` flags literal
                    // entries only from the user `l` suffix.
                    local_network: false,
                });
            }
            continue;
        }
        // Device name: every address of the matching interface becomes
        // an endpoint (multi-address expansion — the phase-1
        // single-pick resolution gives way to the full set here),
        // carrying the row's netmask and classification.
        let mut matched = false;
        for row in ifaces {
            if row.name == spec.device {
                matched = true;
                eps.push(ListenEndpoint {
                    addr: row.addr,
                    port: spec.port,
                    device: spec.device.clone(),
                    netmask: row.netmask,
                    local_network: is_local_class(row.addr),
                });
            }
        }
        if !matched {
            warns.push(format!(
                "listen-interfaces entry `{}`: no interface with this name has addresses (skipped)",
                spec.device
            ));
        }
    }
    // Wildcard expansion: one endpoint per same-family interface
    // address, skipping (addr, port) pairs already explicit (upstream
    // dedups by address+port, ignoring the device name).
    for uep in wildcards {
        let mut expanded = 0;
        for row in ifaces {
            if row.addr.is_ipv4() != uep.addr.is_ipv4() {
                continue;
            }
            let candidate = ListenEndpoint {
                addr: row.addr,
                port: uep.port,
                device: row.name.clone(),
                netmask: row.netmask,
                local_network: is_local_class(row.addr),
            };
            if eps.iter().any(|e| e.key() == candidate.key()) {
                continue;
            }
            eps.push(candidate);
            expanded += 1;
        }
        if expanded == 0 {
            warns.push(format!(
                "listen-interfaces wildcard `{}` expanded to no interface address (skipped)",
                uep.addr
            ));
        }
    }
    // Netmask adoption for literals (`expand_devices`): the first row
    // whose subnet contains the literal donates netmask + device name;
    // unclaimed literals keep the /0 + gateway classification set
    // above (upstream: "we can't find which device this is for, just
    // assume we can't reach anything on it" — mechanically a /0 mask,
    // which matches everything).
    for ep in &mut eps {
        if !ep.device.is_empty() {
            continue;
        }
        if let Some(row) = ifaces
            .iter()
            .find(|row| match_addr_mask(row.addr, ep.addr, row.netmask))
        {
            ep.netmask = row.netmask;
            ep.device = row.name.clone();
        }
    }
    // Egress family narrowing (phase-1 interaction: an egress-bound
    // engine does not listen on the other family).
    if let Some(eg) = egress {
        let before = eps.len();
        eps.retain(|e| e.addr.is_ipv4() == eg.is_ipv4());
        if eps.len() < before {
            warns.push(format!(
                "listen-interfaces: {} endpoint(s) dropped by the --interface egress family narrowing",
                before - eps.len()
            ));
        }
    }
    // Final dedup by (addr, port), first-wins, order-preserving.
    let mut seen = std::collections::HashSet::new();
    eps.retain(|e| seen.insert(e.key()));
    (eps, warns)
}

/// Local-network classification of an expanded (non-literal) endpoint
/// address: loopback or link-local (the route-table-free subset of the
/// upstream disjunction; see [`ListenEndpoint::local_network`]).
fn is_local_class(addr: IpAddr) -> bool {
    addr.is_loopback() || is_link_local_addr(addr)
}

/// One bound listen face: the assembled socket set entry carrying the
/// stable id, the endpoint identity, and the per-transport sockets
/// (upstream `listen_socket_t`: "An entry does not necessarily have a
/// UDP or TCP socket. One of these pointers may be nullptr!" — a face
/// survives with either transport bound; both failing drops the face).
pub struct ListenFace {
    /// Monotonic never-reused identity (see [`ListenFaceId`]).
    pub id: ListenFaceId,
    /// The endpoint this face holds (the diff key source).
    pub endpoint: ListenEndpoint,
    /// Bound TCP listener (None = the TCP bind failed; UDP may still
    /// serve that endpoint).
    pub tcp: Option<tokio::net::TcpListener>,
    /// Bound UDP demux pair (None = the UDP bind failed; the demux
    /// riders — DHT gate, tracker dispatcher, uTP listener — are wired
    /// by the caller only when present).
    pub udp: Option<(
        taiji_io::udp_demux::DemuxChannels,
        taiji_io::udp_demux::UdpDemuxHandle,
    )>,
}

impl ListenFace {
    /// The face's actual TCP port (the OS-assigned value when the spec
    /// port was 0; None = no TCP on this face).
    pub fn tcp_port(&self) -> Option<u16> {
        self.tcp
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
    }

    /// The face's actual UDP port (the demux bound address; None = no
    /// UDP on this face).
    pub fn udp_port(&self) -> Option<u16> {
        self.udp.as_ref().map(|(_, h)| h.bound_addr().port())
    }
}

/// Diff-rebuild partition result (upstream
/// `partition_listen_sockets` + the close/open loop around it):
/// kept faces stay untouched with their riders; removed faces are
/// returned for closing; `to_open` are the unmatched desired endpoints
/// needing fresh faces.
pub struct ListenPartition {
    /// Faces whose endpoint is still desired — exactly as-is (ids,
    /// sockets, riders untouched).
    pub kept: Vec<ListenFace>,
    /// Faces whose endpoint is gone — the caller closes these (and
    /// their riders), then retires the ids.
    pub removed: Vec<ListenFace>,
    /// Desired endpoints with no matching face — the caller opens
    /// these (fresh ids).
    pub to_open: Vec<ListenEndpoint>,
}

/// Partitions the existing face set against the desired endpoint set
/// keyed by `(address, port)` (pure; the diff heart of the rebuild —
/// untouched faces keep their ids and sockets, only gone entries
/// close, only new entries open).
pub fn partition_listen_faces(
    desired: &[ListenEndpoint],
    existing: Vec<ListenFace>,
) -> ListenPartition {
    let mut remaining: Vec<ListenEndpoint> = desired.to_vec();
    let mut kept = Vec::new();
    let mut removed = Vec::new();
    for face in existing {
        // First matching desired endpoint claims the face (a face
        // cannot be claimed twice; the desired side dedups upstream in
        // expand, this is the belt-and-braces arm).
        if let Some(pos) = remaining
            .iter()
            .position(|e| e.key() == face.endpoint.key())
        {
            remaining.remove(pos);
            kept.push(face);
        } else {
            removed.push(face);
        }
    }
    ListenPartition {
        kept,
        removed,
        to_open: remaining,
    }
}

/// TCP listen-socket creation for a face endpoint (the
/// [`crate::run::bind_tcp_v6_only`] discipline generalized to any
/// address): `IPV6_V6ONLY` is set before bind on v6 so a v6 face never
/// becomes an implicit dual-stack socket (Linux `bindv6only` default
/// 0; macOS/Windows 1 — no reliance on OS defaults, the aria2
/// `SocketCore.cc` uniform shape; socket/setsockopt/bind/listen are
/// non-blocking syscalls). v4 goes through the async tokio wrapper
/// (SO_REUSEADDR on non-Windows, the std behavior the default listen
/// path uses).
async fn bind_tcp_face(endpoint: &ListenEndpoint) -> std::io::Result<tokio::net::TcpListener> {
    let addr = SocketAddr::new(endpoint.addr, endpoint.port);
    match endpoint.addr {
        IpAddr::V4(_) => tokio::net::TcpListener::bind(addr).await,
        IpAddr::V6(_) => {
            use socket2::{Domain, Protocol, Socket, Type};
            let s = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
            s.set_only_v6(true)?;
            #[cfg(not(windows))]
            s.set_reuse_address(true)?;
            s.bind(&addr.into())?;
            // backlog 128 = the std::net::TcpListener::bind value.
            s.listen(128)?;
            s.set_nonblocking(true)?;
            tokio::net::TcpListener::from_std(s.into())
        }
    }
}

/// Binds the expanded endpoint set into faces (the assembly-time arm
/// of the diff rebuild: the existing set is empty at engine start, so
/// every endpoint opens; the shutdown race cancels before any new
/// bind). Per face: TCP first (an OS-assigned port for a 0 port
/// propagates to the demux so the two transports share the face port,
/// the standing unified-port rule), then the UDP demux on the same
/// port. A failed transport degrades that face to the other transport
/// (warn); both failing drops the face (warn). An empty result = the
/// engine runs outbound-only (the same degradation as a total listen
/// failure on the default path — NOT a wildcard fallback: the user
/// pinned addresses).
pub async fn bind_listen_faces(
    endpoints: &[ListenEndpoint],
    token: &CancellationToken,
) -> Vec<ListenFace> {
    let mut faces = Vec::new();
    for ep in endpoints {
        if token.is_cancelled() {
            break;
        }
        let tcp = match bind_tcp_face(ep).await {
            Ok(l) => Some(l),
            Err(e) => {
                warn!(target: "taiji::core::engine", addr = %ep.addr, port = ep.port, %e,
                    "listen face tcp bind failed (face degraded to udp-only)");
                None
            }
        };
        // Unified face port: a TCP-assigned port (spec port 0)
        // propagates to the demux; without TCP the demux takes the
        // spec port (0 = the demux's own scan semantics).
        let udp_port = tcp
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(ep.port);
        let config = taiji_io::udp_demux::DemuxConfig {
            port: udp_port,
            ..taiji_io::udp_demux::DemuxConfig::default()
        };
        let udp = match taiji_io::udp_demux::spawn(ep.addr, config, token.clone()).await {
            Ok((channels, handle)) => Some((channels, handle)),
            Err(e) => {
                warn!(target: "taiji::core::engine", addr = %ep.addr, port = udp_port, %e,
                    "listen face udp bind failed (demux riders degraded for this face)");
                None
            }
        };
        if tcp.is_none() && udp.is_none() {
            warn!(target: "taiji::core::engine", addr = %ep.addr, port = ep.port,
                "listen face fully unavailable (no tcp, no udp) — dropped");
            continue;
        }
        let id = next_listen_face_id();
        info!(target: "taiji::core::engine", id = id.0, addr = %ep.addr,
            tcp_port = ?tcp.as_ref().and_then(|l| l.local_addr().ok()).map(|a| a.port()),
            device = %ep.device,
            "listen face bound");
        faces.push(ListenFace {
            id,
            endpoint: ep.clone(),
            tcp,
            udp,
        });
    }
    faces
}

// ---------------------------------------------------------------------------
// Tests: the parse -> expand -> diff pipeline against injected
// interface tables (no real multi-NIC requirement), the id discipline,
// and the diff semantics (kept ids stable, removed-only-gone,
// new-only-added).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }
    fn v6(seg: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, seg, 0, 0, 0, 0, 1))
    }
    /// /64 v6 netmask (the standard on-link prefix).
    fn v6_mask64() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0))
    }

    fn row(name: &str, addr: IpAddr, netmask: IpAddr) -> InterfaceAddr {
        InterfaceAddr {
            name: name.into(),
            addr,
            netmask,
        }
    }

    fn iface_table() -> Vec<InterfaceAddr> {
        vec![
            row("lo0", v4(127, 0, 0, 1), v4(255, 0, 0, 0)),
            row("en0", v4(192, 168, 1, 5), v4(255, 255, 255, 0)),
            row("en0", v6(1), v6_mask64()),
            row("en1", v4(10, 0, 0, 5), v4(255, 0, 0, 0)),
            row("utun0", v4(10, 8, 0, 2), v4(255, 255, 255, 0)),
            row("utun0", v6(2), v6_mask64()),
        ]
    }

    fn spec(s: &str) -> ListenInterface {
        let (mut out, errs) = parse_listen_interfaces(s);
        assert!(errs.is_empty(), "fixture spec `{s}` must parse cleanly");
        assert_eq!(out.len(), 1);
        out.remove(0)
    }

    // ---- parse ----

    /// Grammar table (the upstream string_util.cpp decision shape):
    /// v4 literal, bracketed v6, device name, port-0, empty elements,
    /// and each invalid form collecting individually.
    #[test]
    fn parse_grammar_table() {
        let (out, errs) = parse_listen_interfaces(
            "127.0.0.1:6881, [2001:db8::1]:6882, en0:6883, 0.0.0.0:0,, 10.0.0.5:65535",
        );
        assert!(
            errs.is_empty(),
            "no invalid entries in a legal list: {errs:?}"
        );
        let got: Vec<(&str, u16)> = out.iter().map(|i| (i.device.as_str(), i.port)).collect();
        assert_eq!(
            got,
            vec![
                ("127.0.0.1", 6881),
                ("2001:db8::1", 6882),
                ("en0", 6883),
                ("0.0.0.0", 0),
                ("10.0.0.5", 65535),
            ]
        );
    }

    /// Invalid entries are collected individually (never fatal) and
    /// the valid neighbors still parse: missing port, out-of-range
    /// port, trailing suffix characters (no flags in this grammar),
    /// unterminated bracket, bare multi-colon v6, empty device.
    #[test]
    fn parse_invalid_entries_collect_individually() {
        let (out, errs) = parse_listen_interfaces(
            "en0:6881, en1, 127.0.0.1:65536, 127.0.0.1:6881s, [::1:6881, ::1:6881, :6881",
        );
        assert_eq!(
            out,
            vec![ListenInterface {
                device: "en0".into(),
                port: 6881
            }],
            "only the legal first entry survives"
        );
        assert_eq!(errs.len(), 6, "each invalid entry reported: {errs:?}");
        assert!(errs.contains(&"en1".to_string()));
        assert!(errs.contains(&"127.0.0.1:6881s".to_string()));
        assert!(errs.contains(&"[::1:6881".to_string()));
    }

    /// Port-0 legality (the upstream 0..=65535 domain) and the
    /// five-digit boundary.
    #[test]
    fn parse_port_domain() {
        let (_, errs) = parse_listen_interfaces("h:0");
        assert!(errs.is_empty());
        let (_, errs) = parse_listen_interfaces("h:65535");
        assert!(errs.is_empty());
        // 6 digits and > 65535 both invalid.
        let (_, errs) = parse_listen_interfaces("h:100000");
        assert_eq!(errs.len(), 1);
        let (_, errs) = parse_listen_interfaces("h:65536");
        assert_eq!(errs.len(), 1);
    }

    // ---- expand ----

    /// Device names expand to every address of the matching interface
    /// (the multi-address expansion; upstream interface_to_endpoints).
    #[test]
    fn expand_device_name_to_all_addresses() {
        let specs = vec![spec("en0:6881")];
        let (eps, warns) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert!(warns.is_empty());
        let got: Vec<(IpAddr, u16, &str)> = eps
            .iter()
            .map(|e| (e.addr, e.port, e.device.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![(v4(192, 168, 1, 5), 6881, "en0"), (v6(1), 6881, "en0")],
            "both families of the device, device name carried"
        );
    }

    /// Wildcard expansion (upstream expand_unspecified_address /
    /// BEP 32-45): `0.0.0.0` -> one endpoint per v4 interface address,
    /// `::` -> one per v6 address; explicit endpoints dedup against the
    /// expansion.
    #[test]
    fn expand_wildcard_per_interface_address() {
        let specs = vec![spec("0.0.0.0:6881"), spec("127.0.0.1:6881")];
        let (eps, warns) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert!(warns.is_empty());
        let addrs: Vec<IpAddr> = eps.iter().map(|e| e.addr).collect();
        // 127.0.0.1 was explicit; the wildcard must not duplicate it.
        assert_eq!(
            addrs,
            vec![
                v4(127, 0, 0, 1),
                v4(192, 168, 1, 5),
                v4(10, 0, 0, 5),
                v4(10, 8, 0, 2)
            ]
        );
        // Wildcard entries carry the owning device name (informational
        // until can_route).
        assert!(
            eps.iter()
                .all(|e| !e.device.is_empty() || e.addr == v4(127, 0, 0, 1))
        );

        // v6 wildcard.
        let specs = vec![spec("[::]:6881")];
        let (eps, warns) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert!(warns.is_empty());
        let addrs: Vec<IpAddr> = eps.iter().map(|e| e.addr).collect();
        assert_eq!(addrs, vec![v6(1), v6(2)]);
    }

    /// Unknown device name and a wildcard with no same-family address
    /// warn individually and are skipped (never fatal, never a
    /// wildcard bind sneaking through).
    #[test]
    fn expand_unknown_device_and_dead_wildcard_warn() {
        let specs = vec![spec("doesnotexist0:6881")];
        let (eps, warns) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert!(eps.is_empty());
        assert_eq!(warns.len(), 1);

        // A v6 wildcard on a v4-only table.
        let v4_only: Vec<InterfaceAddr> = iface_table()
            .into_iter()
            .filter(|r| r.addr.is_ipv4())
            .collect();
        let specs = vec![spec("[::]:6881")];
        let (eps, warns) = expand_listen_interfaces(&specs, &v4_only, None);
        assert!(eps.is_empty());
        assert_eq!(
            warns.len(),
            1,
            "the wildcard expansion is empty -> one warn"
        );
    }

    /// Egress family narrowing (the phase-1 interaction): a v4 egress
    /// drops v6 endpoints; a v6 egress drops v4 ones; None keeps all.
    #[test]
    fn expand_egress_family_narrowing() {
        let specs = vec![spec("en0:6881"), spec("utun0:6881")];
        // None: all four endpoints.
        let (eps, _) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert_eq!(eps.len(), 4);
        // v4 egress: only the v4 subset.
        let (eps, warns) =
            expand_listen_interfaces(&specs, &iface_table(), Some(v4(192, 168, 1, 5)));
        assert!(eps.iter().all(|e| e.addr.is_ipv4()));
        assert_eq!(eps.len(), 2);
        assert!(warns.iter().any(|w| w.contains("egress family narrowing")));
        // v6 egress: only the v6 subset.
        let (eps, _) = expand_listen_interfaces(&specs, &iface_table(), Some(v6(1)));
        assert!(eps.iter().all(|e| e.addr.is_ipv6()));
        assert_eq!(eps.len(), 2);
    }

    /// Final dedup by (addr, port): a device and an explicit literal
    /// resolving to the same bind produce one endpoint (first wins —
    /// the surviving literal's device field is the netmask-adoption
    /// backfill, the upstream expand_devices rule).
    #[test]
    fn expand_dedups_same_bind() {
        let specs = vec![spec("192.168.1.5:6881"), spec("en0:6881")];
        let (eps, _) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert_eq!(
            eps.len(),
            2,
            "the explicit 192.168.1.5 + en0's v6, the en0 v4 arm deduped"
        );
        assert!(
            eps.iter()
                .any(|e| e.addr == v4(192, 168, 1, 5) && e.device == "en0")
        );
        assert!(eps.iter().any(|e| e.addr == v6(1)));
    }

    // ---- phase 3: netmask + classification attachment (expand_devices) ----

    /// A literal inside an interface's subnet adopts that interface's
    /// netmask and device name; a literal no row claims keeps the /0
    /// and stays gateway-classified (upstream expand_devices).
    #[test]
    fn expand_literal_adopts_owning_row_netmask() {
        // Same-subnet literal (192.168.1.77 inside en0's /24).
        let specs = vec![spec("192.168.1.77:6881")];
        let (eps, _) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].netmask, v4(255, 255, 255, 0), "en0's /24 adopted");
        assert_eq!(eps[0].device, "en0", "owning device backfilled");

        // Unclaimed literal: /0 netmask, no device, gateway class.
        let specs = vec![spec("203.0.113.9:6881")];
        let (eps, _) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].netmask, v4(0, 0, 0, 0), "no row -> /0");
        assert!(eps[0].device.is_empty());
        assert!(!eps[0].local_network);

        // v6 literal inside utun0's /64.
        let specs = vec![spec("[2001:db8:2::9]:6881")];
        let (eps, _) = expand_listen_interfaces(&specs, &iface_table(), None);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].netmask, v6_mask64());
        assert_eq!(eps[0].device, "utun0");
    }

    /// Expanded rows carry the table netmask; loopback/link-local
    /// expanded addresses classify local-network (the address-class
    /// subset of the upstream flag), global ones stay gateway.
    #[test]
    fn expand_rows_carry_netmask_and_classification() {
        let specs = vec![spec("lo0:6881"), spec("en0:6881"), spec("utun0:6881")];
        let (eps, _) = expand_listen_interfaces(&specs, &iface_table(), None);
        let find = |a: IpAddr| {
            eps.iter()
                .find(|e| e.addr == a)
                .unwrap_or_else(|| panic!("{a}"))
        };
        let lo = find(v4(127, 0, 0, 1));
        assert_eq!(lo.netmask, v4(255, 0, 0, 0));
        assert!(lo.local_network, "loopback row classifies local");
        let en0 = find(v4(192, 168, 1, 5));
        assert_eq!(en0.netmask, v4(255, 255, 255, 0));
        assert!(!en0.local_network, "global row stays gateway");

        // A link-local row classifies local too.
        let table = vec![row(
            "en2",
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            v6_mask64(),
        )];
        let (eps, _) = expand_listen_interfaces(&[spec("en2:6881")], &table, None);
        assert!(eps[0].local_network, "fe80:: row classifies local");

        // Wildcard expansion attaches the same way.
        let (eps, _) = expand_listen_interfaces(&[spec("0.0.0.0:6881")], &iface_table(), None);
        let lo = eps
            .iter()
            .find(|e| e.addr == v4(127, 0, 0, 1))
            .unwrap_or_else(|| panic!("lo"));
        assert!(lo.local_network);
        assert_eq!(lo.netmask, v4(255, 0, 0, 0));
    }

    // ---- phase 3: can_route / match_addr_mask / pick_route_face ----

    /// match_addr_mask truth table (upstream enum_net.cpp:582-604):
    /// subnet containment both ways, family mismatch no, mask family
    /// mismatch no, /0 matches everything.
    #[test]
    fn match_addr_mask_table() {
        let m24 = v4(255, 255, 255, 0);
        assert!(match_addr_mask(
            v4(192, 168, 1, 5),
            v4(192, 168, 1, 99),
            m24
        ));
        assert!(!match_addr_mask(
            v4(192, 168, 1, 5),
            v4(192, 168, 2, 99),
            m24
        ));
        // Cross-family never matches, regardless of mask family.
        assert!(!match_addr_mask(v4(10, 0, 0, 1), v6(1), m24));
        assert!(!match_addr_mask(
            v4(10, 0, 0, 1),
            v4(10, 0, 0, 2),
            v6_mask64()
        ));
        // /0 = match-everything (the unclaimed-literal netmask).
        assert!(match_addr_mask(
            v4(1, 2, 3, 4),
            v4(5, 6, 7, 8),
            v4(0, 0, 0, 0)
        ));
        // v6 /64 containment.
        assert!(match_addr_mask(
            v6(1),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x999)),
            v6_mask64()
        ));
        assert!(!match_addr_mask(v6(1), v6(2), v6_mask64()));
    }

    fn face_ep(addr: IpAddr, netmask: IpAddr, local_network: bool) -> ListenEndpoint {
        ListenEndpoint {
            addr,
            port: 6881,
            device: String::new(),
            netmask,
            local_network,
        }
    }

    fn dest(addr: IpAddr) -> SocketAddr {
        SocketAddr::new(addr, 4242)
    }

    /// can_route truth table (upstream session_impl.cpp:340-355 arms,
    /// in order): family gate, v6 scope gate, exact, wildcard, subnet,
    /// final local-network arm.
    #[test]
    fn can_route_table() {
        let en0 = face_ep(v4(192, 168, 1, 5), v4(255, 255, 255, 0), false);
        // Family gate.
        assert!(!can_route(&en0, dest(v6(1))), "cross-family no");
        assert!(!can_route(
            &face_ep(v6(1), v6_mask64(), false),
            dest(v4(192, 168, 1, 5))
        ));
        // Exact address equality.
        assert!(can_route(&en0, dest(v4(192, 168, 1, 5))));
        // Wildcard local (the default-path faces).
        assert!(can_route(
            &face_ep(v4(0, 0, 0, 0), v4(0, 0, 0, 0), false),
            dest(v4(8, 8, 8, 8))
        ));
        assert!(can_route(
            &face_ep(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                false
            ),
            dest(v6(1))
        ));
        // Netmask match.
        assert!(can_route(&en0, dest(v4(192, 168, 1, 99))));
        // Off-subnet destination from a gateway face: the final arm
        // routes it (a non-local face is a default-route candidate).
        assert!(can_route(&en0, dest(v4(8, 8, 8, 8))));
        // Loopback destination: routable from a gateway face via the
        // same final arm ("loopback always routable" for gateway
        // faces; from a local face via its /8).
        assert!(can_route(&en0, dest(v4(127, 0, 0, 1))));
        // Final arm: a local-network face refuses off-subnet
        // destinations; a gateway face routes them.
        let lo = face_ep(v4(127, 0, 0, 1), v4(255, 0, 0, 0), true);
        assert!(
            !can_route(&lo, dest(v4(8, 8, 8, 8))),
            "local face refuses internet"
        );
        assert!(
            can_route(&lo, dest(v4(127, 0, 0, 9))),
            "same /8 loopback subnet"
        );
        let claimed = face_ep(v4(203, 0, 113, 9), v4(0, 0, 0, 0), false);
        assert!(
            can_route(&claimed, dest(v4(8, 8, 8, 8))),
            "/0 matches everything"
        );
    }

    /// v6 scope gate (the oracle's link-local disambiguation): a
    /// scoped destination never matches a scope-less local endpoint
    /// (taiji listen endpoints cannot carry a scope id — std IpAddr).
    #[test]
    fn can_route_v6_scope_gate() {
        let ll = face_ep(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            v6_mask64(),
            true,
        );
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            4242,
            0,
            7,
        ));
        assert!(!can_route(&ll, scoped), "scope 7 != scope-less local 0");
        // Same address, no scope: falls through to the exact arm.
        assert!(can_route(
            &ll,
            dest(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
        ));
    }

    /// pick_route_face (the bind_outgoing_socket uTP arm): netmask
    /// match preferred (LAST match wins), same-family only, gateway
    /// fallback, primary fallback, absent family -> None.
    #[test]
    fn pick_route_face_table() {
        fn faces() -> Vec<RouteFace<&'static str>> {
            vec![
                RouteFace {
                    endpoint: face_ep(v4(10, 0, 0, 5), v4(255, 0, 0, 0), false),
                    primary: true,
                    rider: "en1",
                },
                RouteFace {
                    endpoint: face_ep(v4(10, 8, 0, 2), v4(255, 255, 255, 0), false),
                    primary: false,
                    rider: "utun0",
                },
                RouteFace {
                    endpoint: face_ep(v6(1), v6_mask64(), false),
                    primary: true,
                    rider: "v6",
                },
            ]
        }
        // Destination inside both subnets: both match, the LAST
        // (utun0's /24) wins — the upstream overwrite semantics.
        assert_eq!(
            pick_route_face(&faces(), dest(v4(10, 8, 0, 7))).map(|f| f.rider),
            Some("utun0")
        );
        // Destination only in en1's /8.
        assert_eq!(
            pick_route_face(&faces(), dest(v4(10, 9, 0, 1))).map(|f| f.rider),
            Some("en1")
        );
        // Off-subnet destination: gateway fallback = the first
        // non-local face (en1, also the primary).
        assert_eq!(
            pick_route_face(&faces(), dest(v4(8, 8, 8, 8))).map(|f| f.rider),
            Some("en1")
        );
        // v6 destination -> the v6 face.
        assert_eq!(
            pick_route_face(&faces(), dest(v6(1))).map(|f| f.rider),
            Some("v6")
        );
        // No v6 face at all -> None (the dial/send failure class).
        let v4_only = vec![RouteFace {
            endpoint: face_ep(v4(10, 0, 0, 5), v4(255, 0, 0, 0), false),
            primary: true,
            rider: "en1",
        }];
        assert!(pick_route_face(&v4_only, dest(v6(1))).is_none());
    }

    /// pick_route_face fallback ordering: a loopback primary is skipped
    /// for the gateway fallback when a non-local sibling exists (the
    /// upstream with_gateways candidate set); an all-local family
    /// falls back to the primary (single-face configs keep the
    /// phase-2 pick exactly).
    #[test]
    fn pick_route_face_gateway_fallback_skips_local_primary() {
        fn lo() -> RouteFace<&'static str> {
            RouteFace {
                endpoint: face_ep(v4(127, 0, 0, 1), v4(255, 0, 0, 0), true),
                primary: true,
                rider: "lo",
            }
        }
        fn en0() -> RouteFace<&'static str> {
            RouteFace {
                endpoint: face_ep(v4(192, 168, 1, 5), v4(255, 255, 255, 0), false),
                primary: false,
                rider: "en0",
            }
        }
        fn lo2() -> RouteFace<&'static str> {
            RouteFace {
                endpoint: face_ep(v4(127, 0, 0, 2), v4(255, 0, 0, 0), true),
                primary: false,
                rider: "lo2",
            }
        }
        // Internet destination: no netmask match; the loopback primary
        // is not a gateway candidate -> en0.
        assert_eq!(
            pick_route_face(&[lo(), en0()], dest(v4(8, 8, 8, 8))).map(|f| f.rider),
            Some("en0")
        );
        // Loopback destination: the lo face's /8 matches directly.
        assert_eq!(
            pick_route_face(&[lo(), en0()], dest(v4(127, 0, 0, 9))).map(|f| f.rider),
            Some("lo")
        );
        // All-local family: primary fallback (exact-degeneration rule).
        assert_eq!(
            pick_route_face(&[lo(), lo2()], dest(v4(8, 8, 8, 8))).map(|f| f.rider),
            Some("lo"),
            "no gateway candidate -> the family primary (phase-2 pick)"
        );
    }

    /// Single-face degeneration: one face per family picks that face
    /// for every destination of the family — exactly the phase-2
    /// primary discipline (the zero-change guarantee for default,
    /// egress-bound, and single-entry configs).
    #[test]
    fn pick_route_face_single_face_degenerates_to_primary() {
        let single = vec![RouteFace {
            endpoint: face_ep(v4(192, 168, 1, 5), v4(255, 255, 255, 0), false),
            primary: true,
            rider: "only",
        }];
        for d in [v4(192, 168, 1, 99), v4(8, 8, 8, 8), v4(127, 0, 0, 1)] {
            assert_eq!(
                pick_route_face(&single, dest(d)).map(|f| f.rider),
                Some("only"),
                "single face serves every same-family destination ({d})"
            );
        }
    }

    /// IngressAllowlist: armed from the egress bind; literal equality
    /// only (the upstream IP arm); family mismatch is a non-match.
    #[test]
    fn ingress_allowlist_literal_equality() {
        assert!(
            IngressAllowlist::resolve(None).is_none(),
            "unset = no verification"
        );
        let allow = IngressAllowlist::resolve(Some(v4(127, 0, 0, 1))).unwrap_or_else(|| panic!());
        assert!(allow.allows(v4(127, 0, 0, 1)));
        assert!(!allow.allows(v4(127, 0, 0, 2)));
        assert!(
            !allow.allows(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "::1 is not 127.0.0.1"
        );
    }

    // ---- diff ----

    fn face_for(ep: ListenEndpoint) -> ListenFace {
        ListenFace {
            id: next_listen_face_id(),
            endpoint: ep,
            tcp: None,
            udp: None,
        }
    }

    fn ep(addr: IpAddr, port: u16) -> ListenEndpoint {
        ListenEndpoint {
            addr,
            port,
            device: String::new(),
            netmask: zero_netmask(addr),
            local_network: false,
        }
    }

    /// Diff semantics: a reconfigure with an overlapping set keeps the
    /// untouched faces EXACTLY as-is (observable via the stable ids —
    /// the same (addr, port) keeps its id), removes only gone entries,
    /// opens only new endpoints.
    #[test]
    fn partition_keeps_untouched_removes_gone_opens_new() {
        let a = ep(v4(10, 0, 0, 5), 6881);
        let b = ep(v4(192, 168, 1, 5), 6881);
        let c = ep(v6(1), 6881);
        let fa = face_for(a.clone());
        let fb = face_for(b.clone());
        let fc = face_for(c.clone());
        let id_a = fa.id;
        let id_b = fb.id;
        let id_c = fc.id;
        // Reconfigure: keep a, drop b, add a new endpoint d.
        let d = ep(v4(10, 8, 0, 2), 6882);
        let part = partition_listen_faces(&[a.clone(), d.clone()], vec![fa, fb, fc]);
        assert_eq!(part.kept.len(), 1, "only the still-desired face is kept");
        assert_eq!(part.kept[0].id, id_a, "kept face keeps its stable id");
        assert_eq!(part.kept[0].endpoint, a);
        let removed: Vec<ListenFaceId> = part.removed.iter().map(|f| f.id).collect();
        assert_eq!(
            removed,
            vec![id_b, id_c],
            "only the gone entries are removed"
        );
        assert_eq!(part.to_open, vec![d], "only the new endpoint opens");
    }

    /// A desired set containing a face's (addr, port) under a
    /// different device label still matches (the diff key ignores the
    /// device name — the same bind is the same face).
    #[test]
    fn partition_keyed_by_addr_port_ignores_device() {
        let mut e = ep(v4(10, 0, 0, 5), 6881);
        e.device = "en1".into();
        let f = face_for(e);
        let id = f.id;
        let mut want = ep(v4(10, 0, 0, 5), 6881);
        want.device = String::new();
        let part = partition_listen_faces(&[want], vec![f]);
        assert_eq!(part.kept.len(), 1);
        assert_eq!(part.kept[0].id, id);
        assert!(part.removed.is_empty());
        assert!(part.to_open.is_empty());
    }

    /// Monotonic never-reused ids: successive allocations strictly
    /// increase; a rebuilt face for a removed endpoint gets a fresh id
    /// larger than every previous one (the listen_socket_t::id rule).
    #[test]
    fn face_ids_are_monotonic_and_never_reused() {
        let ids: Vec<ListenFaceId> = (0..8).map(|_| next_listen_face_id()).collect();
        for pair in ids.windows(2) {
            assert!(pair[0] < pair[1], "ids strictly increase: {ids:?}");
        }
        // The rebuild shape: partition removes a face, a fresh face
        // opens the same endpoint with a strictly larger id.
        let e = ep(v4(10, 0, 0, 5), 6881);
        let f1 = face_for(e.clone());
        let part = partition_listen_faces(&[], vec![f1]);
        assert_eq!(part.removed.len(), 1);
        let f2 = face_for(e);
        assert!(part.removed[0].id < f2.id, "the rebuilt face id is fresh");
    }

    /// Reconfigure to the identical set is a no-op: everything kept,
    /// nothing removed, nothing to open (the untouched-sockets rule).
    #[test]
    fn partition_identical_set_is_noop() {
        let eps: Vec<ListenEndpoint> = vec![ep(v4(10, 0, 0, 5), 6881), ep(v6(1), 6881)];
        let faces: Vec<ListenFace> = eps.iter().map(|e| face_for(e.clone())).collect();
        let ids: Vec<ListenFaceId> = faces.iter().map(|f| f.id).collect();
        let part = partition_listen_faces(&eps, faces);
        let kept_ids: Vec<ListenFaceId> = part.kept.iter().map(|f| f.id).collect();
        assert_eq!(kept_ids, ids);
        assert!(part.removed.is_empty());
        assert!(part.to_open.is_empty());
    }
}

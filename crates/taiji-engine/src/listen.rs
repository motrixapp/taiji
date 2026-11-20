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
//!    `src/session_impl.cpp:254-309` — the BEP 32/45 multi-homed shape;
//!    the upstream `preferred`/up-state interface filter and the
//!    local-network classification are simplified away: every
//!    enumerated address counts, and the route-aware classification is
//!    the later can_route phase). Enumeration failure or an empty
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
//! a future can_route cache) can hold ids safely.
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

/// One expanded listen endpoint: the bind address a face will hold
/// (upstream `listen_endpoint_t` minus ssl/flags; the OS netmask
/// attachment of `expand_devices` is deferred to the can_route phase).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenEndpoint {
    /// Concrete bind address (wildcards are fully expanded away; an
    /// expansion that yields nothing for a wildcard entry is the
    /// degradation path, never a wildcard bind sneaking through).
    pub addr: IpAddr,
    pub port: u16,
    /// Originating device name (empty for IP-literal entries; filled
    /// for device-name and device-expanded entries — informational
    /// until the can_route phase consumes it).
    pub device: String,
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

/// OS interface-table enumeration (getifaddrs via if-addrs, an
/// existing workspace dependency — a local syscall, no network IO).
/// Returns `(name, address)` pairs in table order.
pub fn enumerate_interface_addrs() -> std::io::Result<Vec<(String, IpAddr)>> {
    Ok(if_addrs::get_if_addrs()?
        .into_iter()
        .map(|i| {
            let ip = i.ip();
            (i.name, ip)
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
/// 1. IP literals pass through as-is (device empty); an unspecified
///    literal (`0.0.0.0`/`::`) becomes a wildcard to expand;
/// 2. device names expand to one endpoint per matching interface
///    address (`interface_to_endpoints`);
/// 3. wildcards expand to one endpoint per same-family interface
///    address, deduplicated against the explicit set
///    (`expand_unspecified_address` — the BEP 32/45 per-interface
///    shape; the `preferred`/up-state filters are simplified away, see
///    the module docs);
/// 4. the egress bind family (`--interface`) narrows the set — an
///    egress-bound engine keeps only same-family endpoints (the UDP
///    leak rationale of [`crate::dht::udp_face_plan`]);
/// 5. the final list is deduplicated by `(addr, port)` (first entry
///    wins; stable order = spec order, then table order).
pub fn expand_listen_interfaces(
    specs: &[ListenInterface],
    ifaces: &[(String, IpAddr)],
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
                });
            } else {
                eps.push(ListenEndpoint {
                    addr,
                    port: spec.port,
                    device: String::new(),
                });
            }
            continue;
        }
        // Device name: every address of the matching interface becomes
        // an endpoint (multi-address expansion — the phase-1
        // single-pick resolution gives way to the full set here).
        let mut matched = false;
        for (name, ip) in ifaces {
            if name == &spec.device {
                matched = true;
                eps.push(ListenEndpoint {
                    addr: *ip,
                    port: spec.port,
                    device: spec.device.clone(),
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
        for (name, ip) in ifaces {
            if ip.is_ipv4() != uep.addr.is_ipv4() {
                continue;
            }
            let candidate = ListenEndpoint {
                addr: *ip,
                port: uep.port,
                device: name.clone(),
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

    fn iface_table() -> Vec<(String, IpAddr)> {
        vec![
            ("lo0".into(), v4(127, 0, 0, 1)),
            ("en0".into(), v4(192, 168, 1, 5)),
            ("en0".into(), v6(1)),
            ("en1".into(), v4(10, 0, 0, 5)),
            ("utun0".into(), v4(10, 8, 0, 2)),
            ("utun0".into(), v6(2)),
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
        let v4_only: Vec<(String, IpAddr)> = iface_table()
            .into_iter()
            .filter(|(_, ip)| ip.is_ipv4())
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
    /// resolving to the same bind produce one endpoint (first wins).
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
                .any(|e| e.addr == v4(192, 168, 1, 5) && e.device.is_empty())
        );
        assert!(eps.iter().any(|e| e.addr == v6(1)));
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

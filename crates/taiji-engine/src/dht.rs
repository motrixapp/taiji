//! DHT/UDP surface wiring: `spawn_udp_face` dual-family demux, DHT
//! engine bootstrap entry resolution, announce registration,
//! restore-state readback/persist (dht_state), PeersFound dial dedup
//! (`DialDedup`).
//!
//! Scope: assembly/registration/persistence of the DHT engines and the
//! demux. Peer dialing itself (transit) and uTP accept merging (the run
//! main loop) live elsewhere.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use std::time::Instant;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use taiji_bt::dht::{
    DEFAULT_BOOTSTRAP_NODES, DhtEvent, DhtFamily, DhtHandle, DhtRestoreState, DhtSwarmKind,
    DhtTarget, DhtTransport, forward_outbound, spawn_dht_engine,
};
use taiji_io::udp_demux::{self, DemuxConfig, OutboundPacket, UdpDemuxHandle};
use tokio::sync::mpsc;

use crate::config::{DhtWireConfig, FaceKind};
use crate::faces::FaceState;
use crate::tracker::{TrackerPersistShared, epoch_secs};
/// Harvest budget for DHT halt-save: grace for Persist events to reach
/// the sink through the forwarder task after each family's Shutdown
/// receipt (bounded well under the 1s shutdown propagation budget; runs
/// after the tracker stopped sequence on its own budget).
pub(super) const DHT_HALT_SAVE_BUDGET: Duration = Duration::from_secs(5);
/// DHT dial dedup window (PeersFound dedup; repeated peers from
/// multi-source get_peers and within the 15min announce period do not
/// dial again).
pub(super) const DHT_DIAL_DEDUP_WINDOW: Duration = Duration::from_secs(10 * 60);
/// Failed-address dedup window (dead-address cache TTL
/// extension): an address whose dial **failed** keeps its dedup entry for
/// 30min instead of 10min — the announce-interval magnitude (by then every
/// discovery source has re-supplied fresh candidates). Never-tried
/// addresses keep the plain 10min window, so discovery breadth for new
/// peers is untouched; only endpoints with outcome memory wait longer.
/// `BH_DIAL_BACKOFF=0` reverts to the flat 10min window for all entries.
pub(super) const DHT_DIAL_DEDUP_FAILED_WINDOW: Duration = Duration::from_secs(30 * 60);
/// Dedup table capacity cap (bounds long-session memory growth; lazily
/// sweeps expired entries when full).
pub(super) const DHT_DIAL_DEDUP_CAP: usize = 4096;
/// Per-family DHT wiring (held inside `run`; torn down at engine
/// shutdown).
pub(super) struct DhtFamilyWiring {
    pub(super) family: DhtFamily,
    pub(super) handle: DhtHandle,
    /// The demux bound port (= PORT message payload; TCP/UDP share the
    /// same port semantics).
    pub(super) dht_port: u16,
    /// RAII keepalive handle (routing/bridging tasks hold their own
    /// clones; this one keeps the demux alive through the halt-save
    /// harvest window — closing the socket closes the dht inbound
    /// channel). Also the demux stats source (uTP packet-count sampling).
    pub(super) _demux_keepalive: UdpDemuxHandle,
    /// Actor task handle (aborted at shutdown; on the normal path it
    /// exits by itself after Shutdown).
    pub(super) join: tokio::task::JoinHandle<()>,
    /// Last-sampled uTP packet counts (atomics: the tick reads and
    /// replaces via an immutable borrow).
    pub(super) last_utp_recv: AtomicU64,
    pub(super) last_utp_drop: AtomicU64,
    /// Per-kind last-sampled DHT outbound query counts (snapshot-delta
    /// incremental feeds; atomics like the utp counters).
    pub(super) last_queries_ping: AtomicU64,
    pub(super) last_queries_find_node: AtomicU64,
    pub(super) last_queries_get_peers: AtomicU64,
    pub(super) last_queries_announce_peer: AtomicU64,
    /// Last-sampled DHT inbound counters (the inbound counting
    /// face — packets at `handle_packet` entry / queries admitted to
    /// decode / y="r"|"e" frames dropped before decode on no pending
    /// transaction — consumed as snapshot deltas exactly like the
    /// outbound query counters above; observation only, zero control
    /// flow).
    pub(super) last_inbound_packets: AtomicU64,
    pub(super) last_inbound_queries: AtomicU64,
    pub(super) last_inbound_unmatched_drops: AtomicU64,
}

/// Per-family cold DHT wiring (the runtime hot-toggle seam): holds the
/// inbound gate and demux keepalive from assembly. Runtime enable = this
/// seam spawns ("warms") a DhtEngine; runtime disable = engine Shutdown
/// while this seam is KEPT — enable/disable can repeat within one engine
/// lifetime (the gate's receiver is permanent, never consumed by an
/// engine).
pub(super) struct DhtColdWiring {
    pub(super) family: DhtFamily,
    pub(super) gate: std::sync::Arc<DhtInboundGate>,
    /// demux RAII keepalive (held from assembly — the gate pump task also
    /// holds its own clone; moved into
    /// [`DhtFamilyWiring::_demux_keepalive`] on warm-up for stats
    /// sampling).
    pub(super) demux: UdpDemuxHandle,
    /// The demux bound port (= the DHT port; TCP/UDP share the same port
    /// semantics).
    pub(super) dht_port: u16,
}

/// DHT inbound gate: the permanent holder of the demux dht channel
/// receiver. A resident pump task (built at assembly) forwards inbound
/// packets to the current engine per the watch slot (None = DHT
/// disabled: packets stay in the bounded channel, dropped best-effort by
/// the demux when full — the same semantics as the old "drop the
/// channel" disable form). Engine start/stop never consumes the
/// receiver, so runtime toggling is repeatable (mirrors libtorrent
/// apply_settings restarting DHT any number of times).
#[derive(Default)]
pub(super) struct DhtInboundGate {
    /// Sender to the current engine's inbound channel (None = disabled).
    /// watch is single-value bounded: new values overwrite old ones
    /// (low-frequency config surface, no backlog).
    engine: tokio::sync::watch::Sender<Option<mpsc::Sender<udp_demux::InboundPacket>>>,
}

impl DhtInboundGate {
    /// Pump channel capacity (gate -> engine inbound; same order as the
    /// demux dht channel — when full the pump task awaits, with demux
    /// best-effort drops as the backstop).
    const PUMP_CAPACITY: usize = 256;

    fn new() -> Self {
        let (engine, _) = tokio::sync::watch::channel(None);
        DhtInboundGate { engine }
    }

    /// Warm the engine: set the inbound forwarding target (Some when
    /// enabled; None when disabled — the pump then stops via send failure
    /// or slot flip, the receiver stays in the gate).
    pub(super) async fn set_engine(&self, tx: Option<mpsc::Sender<udp_demux::InboundPacket>>) {
        let _ = self.engine.send(tx);
    }
}

/// Resident inbound pump (one per family, from assembly; the demux dht
/// receiver lives permanently in this task): forwards inbound packets to
/// the current engine while the watch slot is non-empty; pauses on
/// emptying or engine shutdown.
pub(super) fn spawn_dht_inbound_gate(
    inbound: mpsc::Receiver<udp_demux::InboundPacket>,
    token: CancellationToken,
) -> std::sync::Arc<DhtInboundGate> {
    let gate = std::sync::Arc::new(DhtInboundGate::new());
    let mut engine_rx = gate.engine.subscribe();
    tokio::spawn(async move {
        let mut rx = inbound;
        loop {
            // Snapshot of the current engine slot (None = disabled: just
            // wait for watch changes).
            let cur = engine_rx.borrow().clone();
            tokio::select! {
                _ = token.cancelled() => break,
                changed = engine_rx.changed() => {
                    if changed.is_err() {
                        // Gate dropped (engine shutdown).
                        break;
                    }
                    continue;
                }
                pkt = rx.recv(), if cur.is_some() => match pkt {
                    Some(p) => {
                        let Some(tx) = &cur else { continue };
                        if tx.send(p).await.is_err() {
                            // Engine side closed (runtime disable or
                            // shutdown): stop forwarding and wait for the
                            // next warm-up (woken by watch changes);
                            // inbound packets stay in the demux channel
                            // (dropped when full — the existing disable
                            // semantics).
                            if engine_rx.changed().await.is_err() {
                                break;
                            }
                        }
                    }
                    // demux closed (socket shutdown — engine teardown
                    // path).
                    None => break,
                },
            }
        }
    });
    gate
}
/// DHT PeersFound dial dedup: addr -> last dial admission (plus the
/// failed mark that extends that address's window); duplicates
/// within the window are skipped (the same peer from multi-source
/// get_peers / announce-period re-sends). Lazy sweeps under the capacity
/// cap; no allocation pressure on the main loop.
#[derive(Debug)]
pub(super) struct DialDedupEntry {
    /// Most recent dial admission instant.
    admitted: Instant,
    /// The most recent dial outcome failed (the window extends to
    /// [`DHT_DIAL_DEDUP_FAILED_WINDOW`]); cleared by a success.
    failed: bool,
}

pub(super) struct DialDedup(pub(super) HashMap<SocketAddr, DialDedupEntry>);

impl DialDedup {
    pub(super) fn new() -> Self {
        DialDedup(HashMap::new())
    }

    fn window_of(entry: &DialDedupEntry) -> Duration {
        // The failed-window extension is the dial-backoff face;
        // with the switch off the flat 10min window applies to everyone.
        if entry.failed && taiji_io::knobs::dial_backoff_enabled() {
            DHT_DIAL_DEDUP_FAILED_WINDOW
        } else {
            DHT_DIAL_DEDUP_WINDOW
        }
    }

    /// Dialed within the (outcome-dependent) window -> false (skip);
    /// otherwise record and admit.
    pub(super) fn admit(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if let Some(entry) = self.0.get(&addr) {
            if now.duration_since(entry.admitted) < Self::window_of(entry) {
                return false;
            }
        }
        if self.0.len() >= DHT_DIAL_DEDUP_CAP {
            self.0
                .retain(|_, entry| now.duration_since(entry.admitted) < Self::window_of(entry));
        }
        self.0.insert(
            addr,
            DialDedupEntry {
                admitted: now,
                failed: false,
            },
        );
        true
    }

    /// Dial-outcome feed: a failed dial marks the entry —
    /// its dedup window extends to [`DHT_DIAL_DEDUP_FAILED_WINDOW`] (a
    /// re-supply of the same dead address within that window is skipped
    /// instead of re-dialed). No-op for addresses without an entry (the
    /// entry may have been swept; the next admit starts a plain window).
    pub(super) fn note_failed(&mut self, addr: &SocketAddr) {
        if let Some(entry) = self.0.get_mut(addr) {
            entry.failed = true;
        }
    }

    /// Dial-outcome feed: a successful handshake clears the failed mark
    /// (a revived peer is dialed on the plain 10min window again).
    pub(super) fn note_connected(&mut self, addr: &SocketAddr) {
        if let Some(entry) = self.0.get_mut(addr) {
            entry.failed = false;
        }
    }

    /// Time of the most recent dial admission (the candidate sort key's
    /// `last_connected` reading: admission time = most recent dial
    /// attempt; None = never — the same semantics as libtorrent's
    /// `last_connected` 0 = never-first, `peer_list.cpp`).
    pub(super) fn last_admitted(&self, addr: &SocketAddr) -> Option<Instant> {
        self.0.get(addr).map(|e| e.admitted)
    }

    /// Table size (the `pool_known` telemetry reading).
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
}
/// v6 face bind-address choice (pure function, test-locked): a probed
/// global v6 unicast (GUA) binds that address — outbound source = GUA
/// (globally routable), consistent with the BEP 42 node_id derivation
/// source, so the peer-visible source is no longer misjudged as ULA by
/// UDP source selection; anything else (probe None = no global v6, or
/// an anomalous shape) falls back to the unspecified `[::]` (status quo,
/// zero behavior change). probe contract: Some => global v6
/// (probe_source_ip already filters by is_global; not re-checked here —
/// same discipline as probe_allows_bootstrap).
fn v6_face_bind_addr(probed: Option<IpAddr>) -> IpAddr {
    match probed {
        Some(gua @ IpAddr::V6(_)) => gua,
        _ => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// Engine-level UDP face: [`udp_demux::spawn`] takes over the
/// listen-port UDP surface with one shared socket per family — DHT (the
/// dht channel) and UDP tracker (the tracker channel) share it,
/// replacing the old per-actor `udp_carrier` minimal stand-in. The uTP
/// channel (utp) is wired to the `io::utp` listener (inside the engine
/// assembly loop); its receiver is no longer dropped.
///
/// The v4 instance is the primary UDP face (bind failure = warn only;
/// UDP tracker/DHT degrade to unavailable, and the failure does not
/// infect the torrent data plane). The v6 instance binds best-effort
/// (macOS/BSD default to v6only and can coexist with v4 on one port;
/// Linux defaults to dual-stack, so v4 binds first and v6 hits
/// EADDRINUSE — degrade to v4-only with a warn). The v6 bind address
/// prefers the GUA probed by `probe_source_ip(true)`
/// ([`v6_face_bind_addr`]); if binding the GUA fails (the address
/// vanished between probe and bind, or policy rejected it), fall back
/// to `[::]` and retry once (the status-quo path), then degrade as
/// before. Known trade-off (by design): a GUA is a router-issued,
/// rotatable address (privacy extensions / PD renumbering); after a
/// rotation the face's inbound path is dead until engine restart —
/// traded for a globally routable outbound source (with `[::]` binding
/// on mixed networks, UDP source selection can pick a ULA, making v6
/// DHT effectively unusable).
pub(super) async fn spawn_udp_face(
    port: u16,
    token: &CancellationToken,
) -> Vec<(DhtFamily, udp_demux::DemuxChannels, UdpDemuxHandle)> {
    let mut faces = Vec::new();
    // One probe at the assembly point (the bootstrap task separately
    // probes for BEP 42 derivation + the gate, see assemble; both share
    // probe_source_ip semantics. The probe races multiple targets
    // concurrently; latency = the fastest reachable target's RTT, see
    // security.rs).
    let v6_bind = v6_face_bind_addr(taiji_bt::dht::security::probe_source_ip(true).await);
    for (family, bind) in [
        (DhtFamily::V4, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        (DhtFamily::V6, v6_bind),
    ] {
        let config = DemuxConfig {
            port,
            ..DemuxConfig::default()
        };
        match udp_demux::spawn(bind, config, token.clone()).await {
            Ok((channels, handle)) => {
                if family == DhtFamily::V6 && bind != IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
                    info!(target: "taiji::core::engine", bind = %bind, port,
                        "v6 udp face bound to probed global address ( outbound source = GUA)");
                }
                faces.push((family, channels, handle));
            }
            Err(e) if family == DhtFamily::V6 => {
                if bind != IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
                    info!(target: "taiji::core::engine", %e, bind = %bind, port,
                        "v6 udp face bind to probed address failed; falling back to [::]");
                    let config = DemuxConfig {
                        port,
                        ..DemuxConfig::default()
                    };
                    match udp_demux::spawn(IpAddr::V6(Ipv6Addr::UNSPECIFIED), config, token.clone())
                        .await
                    {
                        Ok((channels, handle)) => faces.push((family, channels, handle)),
                        Err(e) => {
                            info!(target: "taiji::core::engine", %e, port,
                                "v6 udp face unavailable (v4-only UDP: tracker/DHT)");
                        }
                    }
                } else {
                    info!(target: "taiji::core::engine", %e, port,
                        "v6 udp face unavailable (v4-only UDP: tracker/DHT)");
                }
            }
            Err(e) => {
                warn!(target: "taiji::core::engine", %e, port,
                    "udp face bind failed (tracker UDP + DHT disabled)");
            }
        }
    }
    faces
}

/// v6 router fallback bootstrap constants (same shape as the v4
/// [`DEFAULT_BOOTSTRAP_NODES`]; an intentional enhancement over upstream
/// — see the bt::dht engine module docs). aria2's
/// `--dht-entry-point[-6]` options have no default values at all
/// (`OptionHandlerFactory.cc` NO_DEFAULT_VALUE), so this table is not
/// aria2 behavior. The constants live on the core bootstrap side rather
/// than bt: the v4 table already lives in bt::dht and this module's
/// scope no longer extends the bt table (bt keeps only the rotation
/// mechanism); AAAA verification is a bootstrap-side duty.
///
/// Entries are hostnames only — hardcoded IP literals are forbidden
/// (AAAA is filtered per family at resolution time, see
/// [`bootstrap_entry_points`]). AAAA presence was vetted per entry:
///
/// - `dht.transmissionbt.com:6881`: stable AAAA; included.
/// - `dht.libtorrent.org:25401`: the libtorrent default bootstrap
///   (libtorrent `src/settings_pack.cpp`); long-TTL AAAA; included.
/// - `router.bittorrent.com:6881`: no real AAAA (one resolver returns a
///   NAT64-synthesized form); excluded.
/// - `router.utorrent.com:6881`: AAAA unstable and not a DHT service
///   (mostly CDN edge / NAT64-synthesized answers); excluded.
pub(super) const DEFAULT_BOOTSTRAP_NODES_V6: &[(&str, u16)] = &[
    ("dht.transmissionbt.com", 6881),
    ("dht.libtorrent.org", 25401),
];

/// Entry-source selection: explicit `--dht-entry-point[-6]` beats the
/// empty-table fallback constants (v4 = bt::dht
/// [`DEFAULT_BOOTSTRAP_NODES`]; v6 = [`DEFAULT_BOOTSTRAP_NODES_V6`]).
/// Persisted-table restore (dht_state) is not part of this selection —
/// restored nodes reach the engine through its own contact surface
/// (restore + bucket refresh, `DHTSetup.cc`); entry selection depends
/// only on (explicit table, family), the same priority as the
/// established v4 discipline (pure function: the presence of a restore
/// state does not change the fallback trigger).
pub(super) fn select_entry_sources(entries: &[String], family: DhtFamily) -> Vec<String> {
    if !entries.is_empty() {
        return entries.to_vec();
    }
    let table: &[(&str, u16)] = match family {
        DhtFamily::V4 => DEFAULT_BOOTSTRAP_NODES,
        DhtFamily::V6 => DEFAULT_BOOTSTRAP_NODES_V6,
    };
    table.iter().map(|(h, p)| format!("{h}:{p}")).collect()
}

/// v6 bootstrap connectivity gate: a probed source address allows
/// bootstrap; None (no global route) blocks bootstrap for the v6 face
/// only (entry resolution and pings would fail anyway — no blind
/// traffic). v4 always passes: on v4 the probe only serves BEP 42
/// node_id derivation (probe failure = keep the status quo, the same
/// rule as libtorrent `node.cpp`), so v4 bootstrap behavior is unchanged
/// (this module's hard line).
pub(super) fn probe_allows_bootstrap(probed: Option<IpAddr>, family: DhtFamily) -> bool {
    match family {
        DhtFamily::V4 => true,
        DhtFamily::V6 => probed.is_some(),
    }
}

/// DHT bootstrap entry resolution: explicit `--dht-entry-point[-6]`
/// first (host:port); an empty table falls back to the router fallback
/// constants (both families; an intentional enhancement over upstream —
/// bt::dht engine module docs; when v6 has no local global connectivity
/// the whole bootstrap is skipped at the bootstrap task, see the probe
/// gate in assemble — this function is connectivity-agnostic).
/// Production resolves through the shared resolver service's
/// process-level default instance (injection surface =
/// [`bootstrap_entry_points_with`] — TTL cache plus a 30s resolution
/// timeout backstop via the resolver stack's TimeoutResolver, so a hung
/// resolution can no longer stall the bootstrap task indefinitely): all
/// entries resolve concurrently (a serial per-entry await would let one
/// slow or unreachable resolver delay the ping start of every entry
/// after it).
pub(super) async fn bootstrap_entry_points(
    entries: &[String],
    family: DhtFamily,
) -> Vec<SocketAddr> {
    bootstrap_entry_points_with(entries, family, taiji_io::dns::SharedDns::shared_default()).await
}

/// Injection surface of [`bootstrap_entry_points`] (test seam:
/// `SharedDns::with_resolver` stub instance — real DNS forbidden).
async fn bootstrap_entry_points_with(
    entries: &[String],
    family: DhtFamily,
    dns: std::sync::Arc<taiji_io::dns::SharedDns>,
) -> Vec<SocketAddr> {
    let wanted = select_entry_sources(entries, family);
    let mut handles = Vec::new();
    for entry in wanted {
        // One resolution task per entry (awaiting the shared resolver;
        // concurrent issue keeps a slow/unreachable resolver from
        // delaying the other entries' ping start). Results are collected
        // owned inside the task.
        let dns = std::sync::Arc::clone(&dns);
        handles.push(tokio::spawn(async move {
            let resolved = resolve_entry(&entry, family, &dns).await;
            (entry, resolved)
        }));
    }
    let mut out = Vec::new();
    for handle in handles {
        match handle.await {
            Ok((_entry, Ok(addrs))) => out.extend(addrs),
            Ok((entry, Err(e))) => {
                warn!(target: "taiji::core::engine", entry = %entry, %e,
                    "dht entry point resolution failed");
            }
            Err(e) => {
                warn!(target: "taiji::core::engine", %e,
                    "dht entry point resolution task aborted");
            }
        }
    }
    out
}

/// Resolve one entry: an `ip:port` literal (bracketed v6 included) passes
/// through with zero resolution (same as the ToSocketAddrs literal fast
/// path of the current `lookup_host(&str)`); a hostname resolves the
/// full list through the shared resolver and filters by family (the
/// filter cross-section is unchanged). Failures are Strings (warn-log
/// payload — not an error classification).
async fn resolve_entry(
    entry: &str,
    family: DhtFamily,
    dns: &taiji_io::dns::SharedDns,
) -> Result<Vec<SocketAddr>, String> {
    let want_v4 = family == DhtFamily::V4;
    if let Ok(literal) = entry.parse::<SocketAddr>() {
        return Ok(if literal.is_ipv4() == want_v4 {
            vec![literal]
        } else {
            Vec::new()
        });
    }
    let invalid = || format!("invalid socket address: {entry}");
    let (host, port) = match entry.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h, port),
            Err(_) => return Err(invalid()),
        },
        None => return Err(invalid()),
    };
    // Bracketed v6 hostname form (same domain as lookup_host's parsing).
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs = dns
        .resolve_for_transport(host, port)
        .await
        .map_err(|e| e.to_string())?;
    Ok(addrs
        .into_iter()
        .filter(|a| a.is_ipv4() == want_v4)
        .collect())
}

/// `DhtFamily` -> the `dht_state.family` column text (DDL CHECK domain
/// 'v4'/'v6').
pub(super) fn family_key(family: DhtFamily) -> &'static str {
    match family {
        DhtFamily::V4 => "v4",
        DhtFamily::V6 => "v6",
    }
}

/// Announce-reported port per family (pure function, test-locked): v6
/// has no NAT semantics — the v6 face always announces `actual`; only
/// the v4 face uses the NAT external-port snapshot (`external`; the
/// caller passes actual as the fallback when unmapped).
///
/// Upstream anchor: libtorrent keeps an external port per listen socket
/// (v4/v6 sockets independent — `session_impl.cpp`
/// `get_listen_port(transport, s)` reads `udp_external_port()` per
/// socket, consumed by the DHT/UDP faces; a socket without NAT has
/// external = bound port). Feeding one port to both families (the tick
/// NAT coupling re-registering all families with the v4 external port)
/// let the v4 NAT port pollute v6 discovery.
pub(super) fn family_announce_port(family: DhtFamily, external: u16, actual: u16) -> u16 {
    match family {
        DhtFamily::V4 => external,
        DhtFamily::V6 => actual,
    }
}

/// DHT announce registration for all faces x all families (a torrent
/// task's announce via `DhtHandle::announce` — target = v1 sha1 | v2
/// truncated sha256, port = the local BT port; discovered peers return
/// via `DhtEvent::PeersFound`). One spawn per (face, family): one slow
/// actor does not delay the other registrations. Command channel
/// bounded(64): when full, backpressure lands on this module (announce
/// registration is an actor fast path).
///
/// Ports are taken per family ([`family_announce_port`]) — `v4_port` =
/// the NAT external-port snapshot (= actual when unmapped), `v6_port` =
/// actual (v6 has no NAT semantics; the snapshot must not feed the v6
/// face).
pub(super) fn spawn_dht_announces(
    wiring: &[DhtFamilyWiring],
    faces: &[FaceState],
    v4_port: u16,
    v6_port: u16,
) {
    if wiring.is_empty() {
        return;
    }
    for f in faces {
        let kind = match f.kind {
            FaceKind::V1 => DhtSwarmKind::V1,
            FaceKind::V2 => DhtSwarmKind::V2,
        };
        for w in wiring {
            let port = family_announce_port(w.family, v4_port, v6_port);
            // BEP 27 gate (enforced at the type level; private torrents
            // are already excluded by the engine gate — belt and braces).
            let target = match DhtTarget::new(f.info_hash, kind, false) {
                Ok(t) => t,
                Err(e) => {
                    debug!(target: "taiji::core::engine", %e, "dht target rejected");
                    continue;
                }
            };
            let handle = w.handle.clone();
            tokio::spawn(async move {
                if let Err(e) = handle.announce(target, port).await {
                    debug!(target: "taiji::core::engine", %e,
                        "dht announce registration failed");
                }
            });
        }
    }
}

/// Warm one family's DHT engine (the single point shared by assembly-time
/// direct start and runtime hot start; extracted verbatim from the
/// engine-assembly segment of the old `wire_dht_and_utp` loop body):
/// gate -> engine inbound channel + outbound bridge back to demux +
/// event forwarding (family tag) + restore-state readback + BEP 42
/// probe / bootstrap task. Returns the wiring (pushed into wiring).
pub(super) async fn spawn_dht_family(
    family: DhtFamily,
    gate: &std::sync::Arc<DhtInboundGate>,
    demux: UdpDemuxHandle,
    dht_port: u16,
    dht_cfg: &DhtWireConfig,
    persist_shared: Option<&TrackerPersistShared>,
    ev_tx: &mpsc::Sender<(DhtFamily, DhtEvent)>,
) -> DhtFamilyWiring {
    // Gate -> engine inbound channel (disabled face = the pump idles, see
    // DhtInboundGate).
    let (in_tx, in_rx) = mpsc::channel::<udp_demux::InboundPacket>(DhtInboundGate::PUMP_CAPACITY);
    gate.set_engine(Some(in_tx)).await;
    let restore = match persist_shared {
        Some(p) => load_dht_restore_state(&p.handle, family).await,
        None => None,
    };
    let (out_tx, out_rx) = mpsc::channel::<OutboundPacket>(64);
    // Event channel capacity = the frozen tracker-actor value (one
    // discipline for engine event surfaces).
    let (ev_chan_tx, mut ev_chan) =
        mpsc::channel::<DhtEvent>(taiji_bt::tracker::actor::EVENT_CHANNEL_CAPACITY);
    let (handle, join) = spawn_dht_engine(
        family,
        dht_port,
        dht_cfg.engine.clone(),
        DhtTransport {
            inbound: in_rx,
            outbound: out_tx,
        },
        restore,
        ev_chan_tx,
    );
    forward_outbound(out_rx, demux.clone());
    // Event forwarding: family tag (bounded 64; when full, backpressure
    // lands on the actor).
    let tag_tx = ev_tx.clone();
    tokio::spawn(async move {
        while let Some(ev) = ev_chan.recv().await {
            if tag_tx.send((family, ev)).await.is_err() {
                break;
            }
        }
    });
    // Bootstrap (entry + router-fallback resolution in a separate task:
    // DNS and ping round-trips never block the main loop).
    let entries = match family {
        DhtFamily::V4 => dht_cfg.entry_points_v4.clone(),
        DhtFamily::V6 => dht_cfg.entry_points_v6.clone(),
    };
    let boot_handle = handle.clone();
    tokio::spawn(async move {
        // BEP 42: external-address probe -> node_id
        // derivation/re-derivation (before bootstrap; probe failure =
        // keep the status quo — the same rule as libtorrent
        // calculate_node_id's unspecified -> random, `node.cpp`).
        let probed =
            taiji_bt::dht::security::probe_source_ip(matches!(family, DhtFamily::V6)).await;
        if let Some(ip) = probed
            && let Err(e) = boot_handle.set_external_ip(ip).await
        {
            debug!(target: "taiji::core::engine", family = family_key(family),
                %e, "dht set_external_ip failed");
        }
        // v6 connectivity gate: probe_source_ip(true) = None (no global
        // v6 route) -> the whole v6 bootstrap is skipped (entry
        // resolution and pings would fail anyway — no blind traffic).
        // Placement: at this existing probe point in the bootstrap task
        // rather than inside bootstrap_entry_points — one probe serves
        // both (BEP 42 node_id derivation + the gate); the separate
        // socket-bind probe lives in spawn_udp_face (bind-address
        // choice, semantically independent). The v6 face itself stays
        // alive (binding/inbound replies unaffected); only outbound
        // bootstrap is suppressed.
        if !probe_allows_bootstrap(probed, family) {
            info!(target: "taiji::core::engine", family = family_key(family),
                "v6 dht bootstrap skipped: no global ipv6 connectivity (probe_source_ip)");
            return;
        }
        let addrs = bootstrap_entry_points(&entries, family).await;
        if addrs.is_empty() {
            warn!(target: "taiji::core::engine", family = family_key(family),
                "no dht entry point resolved (bootstrap skipped)");
            return;
        }
        match boot_handle.bootstrap(addrs).await {
            Ok(n) => info!(target: "taiji::core::engine", family = family_key(family),
                reached = n, "dht bootstrap done"),
            Err(e) => warn!(target: "taiji::core::engine", family = family_key(family),
                %e, "dht bootstrap failed"),
        }
    });
    DhtFamilyWiring {
        family,
        handle,
        dht_port,
        _demux_keepalive: demux,
        join,
        last_utp_recv: AtomicU64::new(0),
        last_utp_drop: AtomicU64::new(0),
        last_queries_ping: AtomicU64::new(0),
        last_queries_find_node: AtomicU64::new(0),
        last_queries_get_peers: AtomicU64::new(0),
        last_queries_announce_peer: AtomicU64::new(0),
        last_inbound_packets: AtomicU64::new(0),
        last_inbound_queries: AtomicU64::new(0),
        last_inbound_unmatched_drops: AtomicU64::new(0),
    }
}

/// Runtime DHT surface (hot-toggle seam): cold wiring + channel
/// spares + config. Held by the engine main loop; consumed via
/// [`handle_set_dht_enabled`] on `EngineCommand::SetDhtEnabled`.
pub(super) struct DhtRuntimeSeam {
    /// Per-family cold wiring (always built at assembly — a hot wiring
    /// coexists when DHT is enabled).
    pub(super) cold: Vec<DhtColdWiring>,
    /// DHT wiring config (entry tables / engine intervals — consumed at
    /// warm-up; announce_interval has its own local binding in the main
    /// loop).
    pub(super) cfg: DhtWireConfig,
    /// Spare sender for the DHT event sink (cloned into the forwarding
    /// task at warm-up; also present in the initial-enabled shape — the
    /// forwarding task holds a clone, this copy guarantees repeated
    /// start/stop).
    pub(super) ev_tx: mpsc::Sender<(DhtFamily, DhtEvent)>,
    /// Spare sender for inbound PORT forwarding (cloned into AttachDht at
    /// warm-up).
    pub(super) port_tx: mpsc::Sender<(u64, u16)>,
}

/// Runtime slot for the attach-phase DHT wiring: DialCtx is shared
/// immutable, so hot start/stop swaps the value through this slot
/// (low-frequency command surface; new dials read it at dial assembly).
#[derive(Clone, Default)]
pub(super) struct AttachDhtSlot(
    std::sync::Arc<std::sync::RwLock<Option<super::transit::AttachDht>>>,
);

impl AttachDhtSlot {
    pub(super) fn get(&self) -> Option<super::transit::AttachDht> {
        crate::lock_read(&self.0).clone()
    }
    pub(super) fn set(&self, v: Option<super::transit::AttachDht>) {
        *crate::lock_write(&self.0) = v;
    }
}

/// dht_state row readback -> restore state (startup recovery; read +
/// bt::dht decode). No row -> None; node_id/BLOB decode failure -> warn +
/// None (start from zero, `DHTSetup.cc`). pub so integration tests
/// exercise the same assembly path.
pub async fn load_dht_restore_state(
    handle: &taiji_store::persist::PersistHandle,
    family: DhtFamily,
) -> Option<DhtRestoreState> {
    let row = match handle.load_dht_state(family_key(family)).await {
        Ok(r) => r?,
        Err(e) => {
            warn!(target: "taiji::core::engine", family = family_key(family), %e,
                "dht_state load failed (fresh start)");
            return None;
        }
    };
    let node_id: [u8; 20] = match row.node_id.try_into() {
        Ok(n) => n,
        Err(_) => {
            warn!(target: "taiji::core::engine", family = family_key(family),
                "dht_state node_id malformed (fresh start)");
            return None;
        }
    };
    match DhtRestoreState::from_state_row(node_id, &row.routing_table) {
        Ok(state) => Some(state),
        Err(e) => {
            warn!(target: "taiji::core::engine", family = family_key(family), %e,
                "dht_state blob decode failed (fresh start)");
            None
        }
    }
}

/// Persist the dht_state row (`DhtEvent::Persist` -> UpsertDhtState).
/// Without a persist handle the event is consumed but no row is written;
/// failures warn only (the routing table is a heuristic cache — losing
/// it means re-bootstrap, not correctness data).
pub(super) async fn persist_dht_state(
    persist: Option<&TrackerPersistShared>,
    family: DhtFamily,
    node_id: [u8; 20],
    routing_table: Vec<u8>,
) {
    let Some(p) = persist else {
        return;
    };
    let row = taiji_store::persist::DhtStateRow {
        family: family_key(family).to_string(),
        node_id: node_id.to_vec(),
        routing_table,
        saved_at: epoch_secs(),
    };
    match p.handle.upsert_dht_state(row).await {
        Ok(taiji_store::persist::PersistOutcome::Written) => {
            debug!(target: "taiji::core::engine", family = family_key(family),
                "dht_state row written")
        }
        Ok(taiji_store::persist::PersistOutcome::SkippedUnchanged) => {}
        Err(e) => {
            warn!(target: "taiji::core::engine", family = family_key(family), %e,
                "dht_state persist failed")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: per-family entry priority (explicit > fallback; persisted-table
// restore does not participate in entry selection — locked by the
// pure-function signature of [`select_entry_sources`]), the v6
// connectivity gate (no global v6 -> skip), and the fallback table
// format (hostname + port; IP literals forbidden).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Explicit v4 entries are kept verbatim; the fallback table never
    /// mixes in (priority: explicit > fallback, the original v4
    /// discipline).
    #[test]
    fn entry_source_explicit_v4_beats_fallback() {
        let explicit = vec!["127.0.0.1:9901".to_string()];
        let got = select_entry_sources(&explicit, DhtFamily::V4);
        assert_eq!(got, explicit);
        assert!(
            got.iter()
                .all(|e| !e.starts_with("router.") && !e.starts_with("dht."))
        );
    }

    /// Explicit v6 entries are kept verbatim; the fallback table never
    /// mixes in (v6 mirrors v4).
    #[test]
    fn entry_source_explicit_v6_beats_fallback() {
        let explicit = vec!["[::1]:9901".to_string()];
        let got = select_entry_sources(&explicit, DhtFamily::V6);
        assert_eq!(got, explicit);
        assert!(got.iter().all(|e| !e.starts_with("dht.")));
    }

    /// Empty v4 table -> the v4 fallback constants (the original bt::dht
    /// [`DEFAULT_BOOTSTRAP_NODES`] table, a zero-behavior-change
    /// regression lock; see the bt-side constant comments for the entry
    /// vetting and the libtorrent.org exclusion).
    #[test]
    fn entry_source_v4_empty_falls_back_to_v4_table() {
        let got = select_entry_sources(&[], DhtFamily::V4);
        let want: Vec<String> = DEFAULT_BOOTSTRAP_NODES
            .iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect();
        assert_eq!(got, want);
        assert_eq!(want.len(), 3, "v4 fallback table must stay untouched");
        assert!(
            want.iter().all(|e| !e.contains("libtorrent")),
            "the empirically degraded libtorrent bootstrap entry must not flow back into the v4 table"
        );
    }

    /// Empty v6 table -> the v6 fallback constants (before this, an empty
    /// entry table was a structural gap).
    #[test]
    fn entry_source_v6_empty_falls_back_to_v6_table() {
        let got = select_entry_sources(&[], DhtFamily::V6);
        let want: Vec<String> = DEFAULT_BOOTSTRAP_NODES_V6
            .iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect();
        assert_eq!(got, want);
        assert!(!got.is_empty(), "v6 fallback must not be an empty table");
        // AAAA-vetted-out entries must not flow back (see the constant
        // comment for the verdicts).
        assert!(
            got.iter().all(|e| !e.starts_with("router.bittorrent.com")
                && !e.starts_with("router.utorrent.com"))
        );
    }

    /// DialDedup failed-address window: a plain entry
    /// re-admits after 10min; a failed mark extends that address's
    /// window to 30min (re-supplies of dead endpoints are skipped); a
    /// success clears the mark (revived peers re-admit on the plain
    /// window); last_admitted keeps its semantics across the mark.
    /// (`BH_DIAL_BACKOFF` read: the window_of extension is keyed on the
    /// env switch; the test pins the marked-entry arithmetic by calling
    /// note_failed with the process env as-is — default on in test
    /// runners, and the plain-window rows hold under both values since
    /// they never mark.)
    #[test]
    fn dial_dedup_failed_window_extends_for_marked_entries() {
        let t0 = Instant::now();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 6881);
        let mut dedup = DialDedup::new();
        assert!(dedup.admit(a, t0), "first admit always passes");
        assert!(
            !dedup.admit(a, t0 + Duration::from_secs(599)),
            "plain window rejects within 10min"
        );
        assert!(
            dedup.admit(a, t0 + Duration::from_secs(600)),
            "plain window re-admits after expiry"
        );
        // Marked entry: 30min window.
        dedup.note_failed(&a);
        assert!(
            !dedup.admit(a, t0 + Duration::from_secs(600 + 1799)),
            "failed-mark window rejects within 30min"
        );
        assert!(
            dedup.admit(a, t0 + Duration::from_secs(600 + 1800)),
            "failed-mark window re-admits after expiry (mark cleared on re-admission)"
        );
        // The re-admission cleared the mark: the plain window applies again.
        assert!(
            !dedup.admit(a, t0 + Duration::from_secs(600 + 1800 + 599)),
            "back on the plain window after re-admission"
        );
        // A success clears an existing mark.
        dedup.note_failed(&a);
        dedup.note_connected(&a);
        assert!(
            dedup.admit(a, t0 + Duration::from_secs(600 + 1800 + 600)),
            "success clears the mark: plain-window verdict"
        );
        // Reports for unknown addresses are no-ops.
        let unknown = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 6881);
        dedup.note_failed(&unknown);
        dedup.note_connected(&unknown);
        assert_eq!(
            dedup.len(),
            1,
            "unknown-address reports have zero side effects"
        );
        assert_eq!(
            dedup.last_admitted(&a),
            Some(t0 + Duration::from_secs(600 + 1800 + 600))
        );
    }

    /// IP-literal entries go through each family's own filter: the v6
    /// face takes v6 literals and drops v4-only entries (unfiltered
    /// resolution would pollute the opposite face).
    #[tokio::test]
    async fn bootstrap_entry_points_filters_by_family() {
        let v4 = bootstrap_entry_points(&["127.0.0.1:9901".to_string()], DhtFamily::V4).await;
        assert_eq!(
            v4,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9901)]
        );
        let v6 = bootstrap_entry_points(&["[::1]:9901".to_string()], DhtFamily::V6).await;
        assert_eq!(
            v6,
            vec![SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9901)]
        );
        // v6 face given v4-only explicit entries -> all filtered (no v6
        // neighbor-discovery traffic to v4 addresses).
        let mixed = bootstrap_entry_points(&["127.0.0.1:9901".to_string()], DhtFamily::V6).await;
        assert!(mixed.is_empty());
    }

    /// v6 fallback-table resolution yields only v6 addresses (the AAAA
    /// filter cross-section: a stub mixing v4+v6 -> only v6 entries;
    /// deterministic stand-in for environment-dependent real resolution —
    /// real DNS forbidden). The v4 face yields only v4 from the same stub
    /// (each face applies its own filter).
    #[tokio::test]
    async fn bootstrap_entry_points_v6_fallback_yields_only_v6() {
        use taiji_io::dns::{HostResolver, ListResolverFuture, SharedDns};

        /// Mixed list stub (one v4 + one v6).
        struct MixedDual;
        impl HostResolver for MixedDual {
            fn resolve(&self, _host: String) -> taiji_io::dns::ResolverFuture {
                Box::pin(std::future::ready(Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))))
            }
            fn resolve_list(&self, _host: String) -> ListResolverFuture {
                Box::pin(std::future::ready(Ok(vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ])))
            }
        }
        let dns = std::sync::Arc::new(SharedDns::with_resolver(std::sync::Arc::new(MixedDual)));
        let out = bootstrap_entry_points_with(&[], DhtFamily::V6, dns).await;
        assert!(
            !out.is_empty() && out.iter().all(|a| a.is_ipv6()),
            "v6 face takes only v6 from a mixed list (got {out:?})"
        );
        // v4 face control: the same list yields only v4 (no cross-family
        // fallback).
        let dns = std::sync::Arc::new(SharedDns::with_resolver(std::sync::Arc::new(MixedDual)));
        let out = bootstrap_entry_points_with(&[], DhtFamily::V4, dns).await;
        assert!(
            !out.is_empty() && out.iter().all(|a| a.is_ipv4()),
            "v4 face takes only v4 from a mixed list (got {out:?})"
        );
    }

    /// Bootstrap entry resolution is timeout-bounded (the shared-resolver
    /// integration semantics): a hung entry mixed with a healthy one —
    /// concurrent issue plus an injected short timeout (a parameterized
    /// form of the production 30s backstop) closes out the hung entry
    /// (silently skipped with a warn) while the healthy entry still
    /// resolves (partial failure does not block bootstrap). Stub
    /// injected; real DNS forbidden.
    #[tokio::test]
    async fn bootstrap_entry_points_hang_is_bounded_and_partial() {
        use taiji_io::dns::{
            HostResolver, ResolverFuture, SharedDns as SharedDnsSvc, TimeoutResolver,
        };

        struct HangOneStub;
        impl HostResolver for HangOneStub {
            fn resolve(&self, host: String) -> ResolverFuture {
                if host == "hang.example" {
                    return Box::pin(std::future::pending());
                }
                Box::pin(std::future::ready(Ok(IpAddr::V4(Ipv4Addr::new(
                    192, 0, 2, 9,
                )))))
            }
        }
        let dns = std::sync::Arc::new(SharedDnsSvc::with_resolver(std::sync::Arc::new(
            TimeoutResolver::with_timeout(
                std::sync::Arc::new(HangOneStub),
                Duration::from_millis(50),
            ),
        )));
        let entries = vec![
            "ok.example:6881".to_string(),
            "hang.example:6881".to_string(),
        ];
        let t0 = Instant::now();
        let out = bootstrap_entry_points_with(&entries, DhtFamily::V4, dns).await;
        let elapsed = t0.elapsed();
        assert_eq!(
            out,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                6881
            )],
            "hung entry skipped, healthy entry produced"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "hang closed out by the short timeout (elapsed {elapsed:?})"
        );
    }

    /// Hostname entries: port composition and invalid forms — host:port
    /// split + port composition (the stub only returns IpAddr; the port
    /// is composed by the resolution surface — no port-carrying surface);
    /// bare host / invalid port -> resolution failure, skipped (warn
    /// surface, empty output).
    #[tokio::test]
    async fn bootstrap_entry_points_domain_port_and_invalid_forms() {
        use taiji_io::dns::{HostResolver, ResolverFuture, SharedDns};

        struct FixedV4;
        impl HostResolver for FixedV4 {
            fn resolve(&self, _host: String) -> ResolverFuture {
                Box::pin(std::future::ready(Ok(IpAddr::V4(Ipv4Addr::new(
                    198, 51, 100, 7,
                )))))
            }
        }
        let stub = std::sync::Arc::new(SharedDns::with_resolver(std::sync::Arc::new(FixedV4)));
        let out =
            bootstrap_entry_points_with(&["domain.example:6969".to_string()], DhtFamily::V4, stub)
                .await;
        assert_eq!(
            out,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                6969
            )],
            "port composed at the entry"
        );
        // Bare host (no port) and invalid port -> resolution failure,
        // skipped (empty output).
        let stub = std::sync::Arc::new(SharedDns::with_resolver(std::sync::Arc::new(FixedV4)));
        let out = bootstrap_entry_points_with(
            &[
                "bare.example".to_string(),
                "bad.example:notaport".to_string(),
            ],
            DhtFamily::V4,
            stub,
        )
        .await;
        assert!(
            out.is_empty(),
            "invalid entry forms silently skipped (got {out:?})"
        );
    }

    /// Connectivity gate: probe=None blocks bootstrap for the v6 face
    /// only (zero blind outbound traffic without v6); v4 always passes
    /// (probe failure does not affect v4 bootstrap — zero behavior
    /// change); probe=Some admits v6 (the gate does not re-judge
    /// globality — probe_source_ip's return already carries that
    /// semantics).
    #[test]
    fn probe_gate_skips_only_v6_without_connectivity() {
        let none = None;
        assert!(probe_allows_bootstrap(none, DhtFamily::V4));
        assert!(!probe_allows_bootstrap(none, DhtFamily::V6));

        let v4_src = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert!(probe_allows_bootstrap(v4_src, DhtFamily::V6));

        // A global v6 unicast shape (sample anycast address; the gate only
        // checks Some and does not re-judge globality — probe_source_ip's
        // return already filters for it).
        let v6_src = Some(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111,
        )));
        assert!(probe_allows_bootstrap(v6_src, DhtFamily::V6));
    }

    /// v6 fallback table format: hostnames + legal ports, no duplicates;
    /// IP literals FORBIDDEN (hostname + AAAA — filtered at resolution
    /// time rather than hardcoded direct addresses).
    #[test]
    fn v6_fallback_table_format() {
        assert!(!DEFAULT_BOOTSTRAP_NODES_V6.is_empty());
        let mut seen = Vec::new();
        for (host, port) in DEFAULT_BOOTSTRAP_NODES_V6 {
            assert!(!host.is_empty());
            // IP literals always rejected: entries must be hostnames
            // (AAAA verified and filtered at resolution time).
            assert!(
                host.parse::<IpAddr>().is_err(),
                "hardcoded IP entry `{host}` violates domain+AAAA policy"
            );
            assert!((1..=u16::MAX).contains(port), "port {port} out of range");
            seen.push((host, port));
        }
        let n = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), n, "duplicate entry in v6 fallback table");
    }

    /// Per-family announce port (table-driven): the NAT external-port
    /// snapshot feeds only the v4 face; the v6 face always uses actual —
    /// when `external != actual` the v6 announce port must equal actual
    /// (a v4 NAT port must not pollute v6 discovery); the unmapped
    /// fallback (external = actual) gives both families the same value =
    /// zero change from the previous discipline.
    #[test]
    fn family_announce_port_v6_always_actual() {
        let actual = 51420;
        // Gateway-granted external port != local port (the typical NAT
        // conflict shape).
        let external = 6881;
        assert_eq!(
            family_announce_port(DhtFamily::V4, external, actual),
            external,
            "v4 face takes the external-port snapshot (semantics unchanged)"
        );
        assert_eq!(
            family_announce_port(DhtFamily::V6, external, actual),
            actual,
            "v6 face always actual_port (assertion for the V6-2 fix)"
        );
        // Unmapped (external = actual): both families same value (zero
        // behavior change regression).
        assert_eq!(family_announce_port(DhtFamily::V4, actual, actual), actual);
        assert_eq!(family_announce_port(DhtFamily::V6, actual, actual), actual);
    }

    /// v6 face bind-address choice (pure function): probed GUA -> bind it
    /// (outbound source = GUA, globally routable); None / anomalous shape
    /// (a v4 source) -> `[::]` fallback (status quo, zero change).
    #[test]
    fn v6_face_bind_addr_prefers_probed_gua_else_unspecified() {
        let gua = IpAddr::V6(Ipv6Addr::new(0x240e, 0x0390, 0x1234, 0, 0, 0, 0, 0x1));
        assert_eq!(
            v6_face_bind_addr(Some(gua)),
            gua,
            "a probed GUA must be bound"
        );
        assert_eq!(
            v6_face_bind_addr(None),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            "no global v6 -> falls back to [::] (status quo)"
        );
        assert_eq!(
            v6_face_bind_addr(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            "anomalous shape (v4 source) -> falls back to [::]"
        );
    }

    /// Criteria (integration surface): the v6 face binds the probed GUA
    /// (host with global v6) or falls back to `[::]` (no global v6 host,
    /// status quo); and in either bind shape, KRPC bytes sent from local
    /// ::1 (leading 'd' -> the demux Dht channel, io::udp_demux classify
    /// rule 1) reach the face — loopback interoperability regression:
    /// binding a specific unicast address must not cut ::1 inbound
    /// (local-address traffic routes via lo0, same on macOS/BSD/Linux).
    #[tokio::test]
    async fn udp_face_v6_binds_probed_gua_and_serves_loopback() {
        // No v6 kernel environment (::1 unbindable): the v6 face is
        // structurally absent — environment skip with a reason (same
        // discipline as run::tests::ipv6_available; not a semantic
        // exemption).
        if std::net::UdpSocket::bind("[::1]:0").is_err() {
            eprintln!(
                "skip udp_face_v6_binds_probed_gua_and_serves_loopback: ::1 unavailable (no IPv6 environment)"
            );
            return;
        }
        let token = CancellationToken::new();
        let faces = spawn_udp_face(0, &token).await;
        let Some((mut dht_rx, handle)) = faces
            .into_iter()
            .find_map(|(f, ch, h)| (f == DhtFamily::V6).then_some((ch.dht, h)))
        else {
            eprintln!(
                "skip udp_face_v6_binds_probed_gua_and_serves_loopback: v6 face unbound (no v6 address environment)"
            );
            return;
        };
        // Bind criterion: probe Some => the face binds that GUA; None =>
        // falls back to [::] (status quo).
        match taiji_bt::dht::security::probe_source_ip(true).await {
            Some(gua) => assert_eq!(
                handle.bound_addr().ip(),
                gua,
                "v6 face must bind the probe-discovered GUA (outbound source = GUA)"
            ),
            None => assert_eq!(
                handle.bound_addr().ip(),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                "no global v6 -> falls back to [::] (previous status quo)"
            ),
        }
        // ::1 interoperability regression: a ::1-side socket sends to the
        // face's bound address; the 'd'-first-byte payload must land in
        // the dht channel. The destination is the concrete address (with
        // [::] binding, send [::1]:port — an unspecified bind receives
        // any local v6 address; with GUA binding, send [GUA]:port —
        // local-address traffic routes via lo0, same on macOS/BSD/Linux).
        let dst = match handle.bound_addr().ip() {
            IpAddr::V6(ip) if !ip.is_unspecified() => handle.bound_addr(),
            _ => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), handle.bound_addr().port()),
        };
        let sender = tokio::net::UdpSocket::bind("[::1]:0")
            .await
            .unwrap_or_else(|e| panic!("::1 sender bind: {e}"));
        let payload = b"d1:y1:q4:pinge";
        sender
            .send_to(payload, dst)
            .await
            .unwrap_or_else(|e| panic!("send_to {dst}: {e}"));
        let inbound = tokio::time::timeout(std::time::Duration::from_secs(5), dht_rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("::1 -> v6 face interoperability timed out (loopback inbound cut off?)")
            });
        let packet = inbound.unwrap_or_else(|| panic!("dht channel closed (demux exited)"));
        assert_eq!(
            packet.from,
            sender
                .local_addr()
                .unwrap_or_else(|e| panic!("local_addr: {e}"))
        );
        assert_eq!(packet.data.as_ref(), payload);
    }
}

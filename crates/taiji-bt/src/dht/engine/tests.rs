use super::super::persist::{DhtFamily, decode_table, encode_table};
use super::*;
use bytes::Bytes;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use taiji_io::udp_demux::{InboundPacket, OutboundPacket};
use tokio::sync::mpsc;
use tokio::time::timeout;

// The parent module's name-scope mirror keeps only names its glob consumes;
// symbols exclusive to these tests are imported here.
use super::super::compact::pack_peer;
use super::super::message::ERROR_METHOD_UNKNOWN;
use super::error_limit::ERROR_REPLY_BURST;
use super::wire::MAX_VALUES_PER_REPLY;

/// Test-only Result unwrapping (workspace lints forbid unwrap/expect).
fn t<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Oneshot-style command call with a total deadline: unwraps the timeout
/// layer, keeps the command result layer.
async fn call_res<T>(
    fut: impl Future<Output = Result<T, DhtEngineError>>,
) -> Result<T, DhtEngineError> {
    t(
        timeout(Duration::from_secs(10), fut).await,
        "actor call timeout",
    )
}

/// Oneshot-style command call with a total deadline: unwraps both layers
/// (the result must be Ok).
async fn call<T>(what: &str, fut: impl Future<Output = Result<T, DhtEngineError>>) -> T {
    t(call_res(fut).await, what)
}

/// Unwraps a channel recv: both the timeout(Elapsed) and the Option
/// (channel closed) layers.
fn chan<T>(r: Result<Option<T>, tokio::time::error::Elapsed>, what: &str) -> T {
    match r {
        Ok(Some(v)) => v,
        Ok(None) => panic!("{what}: channel closed"),
        Err(e) => panic!("{what}: timeout ({e})"),
    }
}

fn target_of(ih: [u8; 20], face: DhtSwarmKind) -> DhtTarget {
    t(DhtTarget::new(ih, face, false), "dht target")
}

fn v4_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

/// Fast-period config: drives the same maintenance table at millisecond
/// scale. Rate-limit parameters keep their defaults — the query volume of
/// the existing tests (single digits per source) is far below
/// 25pps/50burst, so behavior is unchanged (`..Default` merely fills
/// fields added to this module later).
fn fast_cfg() -> DhtEngineConfig {
    DhtEngineConfig {
        message_timeout: Duration::from_millis(400),
        bootstrap_ping_retry: 3,
        refresh_check_interval: Duration::from_millis(50),
        peer_announce_check_interval: Duration::from_millis(30),
        token_rotate_interval: Duration::from_secs(3600),
        autosave_interval: Duration::from_secs(3600),
        peer_announce_interval: Duration::from_millis(80),
        peer_announce_purge_interval: Duration::from_millis(600),
        ..DhtEngineConfig::default()
    }
}

/// Pure channel engine (no socket; outbound can be asserted, inbound can
/// be injected). The returned `_in_tx` keeps the inbound channel alive.
fn spawn_channel_engine(
    family: DhtFamily,
    dht_port: u16,
    cfg: DhtEngineConfig,
    restore: Option<DhtRestoreState>,
) -> (
    DhtHandle,
    mpsc::Receiver<DhtEvent>,
    mpsc::Receiver<OutboundPacket>,
    mpsc::Sender<InboundPacket>,
    tokio::task::JoinHandle<()>,
) {
    let (in_tx, in_rx) = mpsc::channel(256);
    let (out_tx, out_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (handle, join) = spawn(
        family,
        dht_port,
        cfg,
        DhtTransport {
            inbound: in_rx,
            outbound: out_tx,
        },
        restore,
        event_tx,
    );
    (handle, event_rx, out_rx, in_tx, join)
}

/// Real loopback UDP engine: instances talk through UdpDemux (in-process,
/// no external network). The returned token is held by the caller
/// (dropping it shuts the demux down).
async fn spawn_udp_engine(
    cfg: DhtEngineConfig,
) -> (
    DhtHandle,
    mpsc::Receiver<DhtEvent>,
    SocketAddr,
    tokio_util::sync::CancellationToken,
    taiji_io::udp_demux::UdpDemuxHandle,
) {
    let shutdown = tokio_util::sync::CancellationToken::new();
    let (channels, demux) = t(
        taiji_io::udp_demux::spawn(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            taiji_io::udp_demux::DemuxConfig::default(),
            shutdown.clone(),
        )
        .await,
        "bind loopback demux",
    );
    let bound = demux.bound_addr();
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (out_tx, out_rx) = mpsc::channel(256);
    let transport = DhtTransport {
        inbound: channels.dht,
        outbound: out_tx,
    };
    let (handle, _join) = spawn(DhtFamily::V4, bound.port(), cfg, transport, None, event_tx);
    // Engine outbound → a single writer into the demux (topology).
    let fwd_demux = demux.clone();
    let _fwd = forward_outbound(out_rx, fwd_demux);
    (handle, event_rx, bound, shutdown, demux)
}

/// Polls the snapshot until the condition holds (20ms steps plus a total deadline).
async fn wait_snapshot(handle: &DhtHandle, limit_ms: u64, cond: impl Fn(&DhtSnapshot) -> bool) {
    let start = std::time::Instant::now();
    loop {
        let snap = call("snapshot", handle.snapshot()).await;
        if cond(&snap) {
            return;
        }
        if start.elapsed() > Duration::from_millis(limit_ms) {
            panic!("snapshot condition not met within {limit_ms}ms; last = {snap:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ===== Private torrents refuse DHT (BEP27) =====

#[test]
fn private_torrent_is_rejected_at_target_gate() {
    // The gate function (the TorrentTask decision entry point).
    assert!(
        !DhtTarget::dht_allowed(true),
        "BEP27: private torrents refuse DHT"
    );
    assert!(DhtTarget::dht_allowed(false));
    // Type level: a private target cannot even be constructed.
    assert_eq!(
        DhtTarget::new([0x11; 20], DhtSwarmKind::V1, true),
        Err(DhtEngineError::PrivateTorrentDisabled)
    );
    assert_eq!(
        DhtTarget::new([0x11; 20], DhtSwarmKind::V2, true),
        Err(DhtEngineError::PrivateTorrentDisabled)
    );
    assert!(DhtTarget::new([0x11; 20], DhtSwarmKind::V1, false).is_ok());
    assert!(DhtTarget::new([0x22; 20], DhtSwarmKind::V2, false).is_ok());
}

// ===== Command face: announce port domain (same domain as the KRPC encoder) =====

#[tokio::test]
async fn announce_rejects_out_of_domain_ports() {
    let (handle, _ev, _out, _in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    // 0 and 65535 are rejected on the same domain as the KRPC encoder (validatePort).
    assert_eq!(
        call_res(handle.announce(target_of([5; 20], DhtSwarmKind::V1), 0)).await,
        Err(DhtEngineError::InvalidPort(0))
    );
    assert_eq!(
        call_res(handle.announce(target_of([5; 20], DhtSwarmKind::V1), 65535)).await,
        Err(DhtEngineError::InvalidPort(65535))
    );
    // A legal port is accepted (with an empty table the lookup completes
    // immediately — the offline degraded shape).
    call(
        "announce ok",
        handle.announce(target_of([5; 20], DhtSwarmKind::V1), 6881),
    )
    .await;
}

// ===== Maintenance timer table (interval boundaries) =====

#[test]
fn maintenance_timer_table_fires_on_interval_boundaries() {
    let cfg = DhtEngineConfig::default();
    let mut timers = MaintenanceTimers {
        due: [None; MAINT_KINDS.len()],
    };
    assert_eq!(timers.next_wake(), None, "nothing scheduled, no wake");

    let t0 = Instant::now();
    timers.schedule_all(&cfg, t0);
    assert!(timers.fire_due(t0).is_empty(), "nothing due at the start");
    assert!(
        timers.next_wake().is_some_and(|w| w > t0),
        "next_wake lies in the future"
    );

    // The shortest period is 5min (refresh check and peer announce check tie):
    // they fire exactly at the t0+5min boundary (due <= now test).
    let fired5 = timers.fire_due(t0 + cfg.refresh_check_interval);
    assert!(fired5.contains(&MaintKind::BucketRefreshCheck));
    assert!(fired5.contains(&MaintKind::PeerAnnounceCheck));
    assert!(
        !fired5.contains(&MaintKind::TokenRotate),
        "10min not reached"
    );
    assert!(!fired5.contains(&MaintKind::AutoSave), "30min not reached");

    // After harvesting, timers must be rescheduled — before rescheduling only
    // the token/autosave times remain.
    assert_eq!(
        timers.next_wake(),
        Some(t0 + cfg.token_rotate_interval),
        "the next wake = the token-rotate boundary"
    );
    // token 10min boundary (inclusive due <= now).
    assert_eq!(
        timers.fire_due(t0 + cfg.token_rotate_interval),
        vec![MaintKind::TokenRotate]
    );
    // After rescheduling the refresh/announce checks, the 30min boundary fires autosave.
    timers.schedule_after(
        MaintKind::BucketRefreshCheck,
        cfg.refresh_check_interval,
        t0,
    );
    timers.schedule_after(
        MaintKind::PeerAnnounceCheck,
        cfg.peer_announce_check_interval,
        t0,
    );
    let fired30 = timers.fire_due(t0 + cfg.autosave_interval);
    assert!(fired30.contains(&MaintKind::AutoSave));
    assert!(
        fired30.contains(&MaintKind::BucketRefreshCheck)
            && fired30.contains(&MaintKind::PeerAnnounceCheck),
        "rescheduled periodic checks keep firing on their own boundaries"
    );
    // Already-harvested timers do not re-fire (the engine reschedules at the
    // end of run_maintenance).
    assert!(timers.fire_due(t0 + cfg.autosave_interval).is_empty());
}

// ===== Announce registry: periodic reissue and sanitization =====
// (upstream ratios: 15min interval / 5min check / 30min sanitization,
// DHTConstants.h; the tests compress them proportionally on the same table.)

#[tokio::test]
async fn announce_registry_reissues_and_purges_table_driven() {
    let mut cfg = fast_cfg();
    cfg.peer_announce_purge_interval = Duration::from_millis(150);
    let (handle, _ev, _out, _in_tx, _join) = spawn_channel_engine(DhtFamily::V4, 6881, cfg, None);

    // Register an announce (empty table → the lookup completes immediately →
    // the periodic check reissues at the 15min interval, scaled).
    call(
        "announce",
        handle.announce(target_of([0x33; 20], DhtSwarmKind::V1), 6881),
    )
    .await;
    wait_snapshot(&handle, 5_000, |s| s.announce_lookups_started >= 2).await;
    let snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(snap.announce_entries, 1);

    // purge: after 30min (150ms here) without a reissue command → the entry
    // is removed from the registry.
    wait_snapshot(&handle, 5_000, |s| s.announce_entries == 0).await;
}

// ===== Per-kind outbound query counting (DhtSnapshot queries_*_total) =====

/// Each of the four query kinds lands in its own counter; the feeding
/// point is where `send_query` successfully enqueues an outbound message:
/// ping via the PORT message entry, find_node via the restore-state forced
/// refresh (LookupKind::Nodes), get_peers via an announce lookup
/// (LookupKind::Peers), announce_peer via the announce stage after a
/// lookup settles (127/8 exempt range, BEP42 does not block storage).
/// Observable behavior is unchanged — only counters and snapshot fields
/// were added.
#[tokio::test]
async fn outbound_queries_counted_per_kind() {
    // Restored nodes (127/8 exempt — BEP42 allows announce storage, so the
    // announce stage really goes outbound).
    let nodes = vec![
        TableNode {
            id: NodeId([0x11; 20]),
            addr: v4_addr(6884),
            last_seen_ago_secs: 1,
        },
        TableNode {
            id: NodeId([0x22; 20]),
            addr: v4_addr(6885),
            last_seen_ago_secs: 2,
        },
    ];
    let restore = t(
        DhtRestoreState::from_state_row([0xAB; 20], &encode_table(&nodes)),
        "restore",
    );
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), Some(restore));

    // ping: the PORT message entry pings immediately (the empty-table node_lookup completes at seed).
    call(
        "add_port_node",
        handle.add_port_node(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777),
    )
    .await;
    wait_snapshot(&handle, 5_000, |s| s.queries_ping_total >= 1).await;

    // find_node: non-empty restored nodes → the forced refresh dispatches a Nodes lookup.
    wait_snapshot(&handle, 5_000, |s| s.queries_find_node_total >= 1).await;

    // get_peers: announce registration → a Peers lookup is dispatched (outbound to the restored nodes).
    call(
        "announce",
        handle.announce(target_of([0x55; 20], DhtSwarmKind::V1), 6881),
    )
    .await;
    let (tid, from, node_id) = loop {
        let (to, msg) = recv_packet(&mut out_rx).await;
        if let DhtMessage::Query(q) = msg {
            if matches!(q.body, QueryBody::GetPeers { .. }) {
                // Outbound target port → restored node id (6884 → 0x11, 6885 → 0x22).
                let id = NodeId([if to.port() == 6884 { 0x11 } else { 0x22 }; 20]);
                break (q.transaction_id, to, id);
            }
        }
    };
    // Inject the token-bearing response (tid and route address must match) → the lookup settles.
    let response = DhtMessage::Response(ResponseMessage {
        transaction_id: tid,
        responder_id: node_id,
        body: ResponseBody::GetPeers {
            token: b"tok".to_vec(),
            nodes: Vec::new(),
            values: Vec::new(),
        },
        requester_endpoint: None,
        version: None,
    });
    let wire = t(encode_message(&response), "encode response");
    t(
        in_tx
            .send(InboundPacket {
                from,
                data: Bytes::from(wire),
            })
            .await,
        "inject response",
    );
    // announce stage: announce_peer is sent to the token-holding probed node (fire and forget).
    wait_snapshot(&handle, 5_000, |s| s.queries_announce_peer_total >= 1).await;

    // The four slots are independent (each accumulates on its own, no cross-slot leakage).
    let snap = call("snapshot", handle.snapshot()).await;
    assert!(snap.queries_ping_total >= 1, "{snap:?}");
    assert!(snap.queries_find_node_total >= 1, "{snap:?}");
    assert!(snap.queries_get_peers_total >= 1, "{snap:?}");
    assert!(snap.queries_announce_peer_total >= 1, "{snap:?}");
}

// ===== inbound hot path: early-drop of unmatched reply frames =====

/// Early-drop gate (wire.rs handle_packet): a well-formed y="r" frame
/// matching no pending transaction is dropped silently before the full
/// decode — zero outbound bytes for it — while the query face on the same
/// engine keeps answering (protocol semantics untouched); the three
/// inbound counters (packets / queries / unmatched drops) feed the
/// snapshot. The matched path (a reply that settles a live transaction)
/// is exercised end-to-end by the announce-flow tests above, which run
/// through the same gate (contains -> full decode -> pop).
#[tokio::test]
async fn unmatched_response_frames_drop_early_with_counter() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);

    // (1) An unsolicited, well-formed y="r" ping response (random tid, no
    // pending transaction): silently dropped — no outbound bytes follow it.
    let stray = DhtMessage::Response(ResponseMessage {
        transaction_id: vec![0x5a, 0x5a, 0x5a, 0x5a],
        responder_id: NodeId([0x33; 20]),
        body: ResponseBody::Ping,
        requester_endpoint: None,
        version: None,
    });
    let stray_wire = t(encode_message(&stray), "encode stray response");
    t(
        in_tx
            .send(InboundPacket {
                from: v4_addr(7001),
                data: Bytes::from(stray_wire),
            })
            .await,
        "inject stray response",
    );
    wait_snapshot(&handle, 5_000, |s| {
        s.inbound_packets_total >= 1 && s.inbound_unmatched_drops_total >= 1
    })
    .await;
    // Quiet beat: the stray response produced no outbound bytes.
    assert!(
        timeout(Duration::from_millis(150), out_rx.recv())
            .await
            .is_err(),
        "an unmatched response must not generate any outbound bytes"
    );

    // (2) The query face is intact on the same engine: a real ping query
    // is answered (the reply may queue behind maintenance-driven find_node
    // queries — match by tid).
    let q = DhtMessage::Query(QueryMessage {
        transaction_id: b"pq".to_vec(),
        sender_id: NodeId([0x44; 20]),
        body: QueryBody::Ping,
        version: None,
    });
    let q_wire = t(encode_message(&q), "encode ping query");
    t(
        in_tx
            .send(InboundPacket {
                from: v4_addr(7002),
                data: Bytes::from(q_wire),
            })
            .await,
        "inject ping query",
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("ping reply never arrived");
        }
        let (_to, msg) = match timeout(Duration::from_secs(2), recv_packet(&mut out_rx)).await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        if let DhtMessage::Response(r) = &msg
            && r.transaction_id == b"pq"
        {
            break;
        }
    }

    let snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(snap.inbound_packets_total, 2, "{snap:?}");
    assert_eq!(snap.inbound_queries_total, 1, "{snap:?}");
    assert_eq!(snap.inbound_unmatched_drops_total, 1, "{snap:?}");
    let _ = handle.shutdown().await;
}

// ===== autosave persist events + halt save =====

#[tokio::test]
async fn autosave_and_shutdown_emit_persist_events() {
    let mut cfg = fast_cfg();
    cfg.autosave_interval = Duration::from_millis(40);
    // One restored node → the blob is non-empty and the roundtrip can be checked.
    let nodes = vec![TableNode {
        id: NodeId([7; 20]),
        addr: v4_addr(6883),
        last_seen_ago_secs: 5,
    }];
    let blob = encode_table(&nodes);
    let restore = t(
        DhtRestoreState::from_state_row([9; 20], &blob),
        "restore state",
    );
    let (handle, mut events, _out, _in_tx, join) =
        spawn_channel_engine(DhtFamily::V4, 6881, cfg, Some(restore));

    // autosave due → a Persist event whose blob decodes back to the node list.
    let ev = chan(
        timeout(Duration::from_secs(5), events.recv()).await,
        "autosave event",
    );
    match ev {
        DhtEvent::Persist {
            family,
            node_id,
            routing_table,
        } => {
            assert_eq!(family, DhtFamily::V4);
            assert_eq!(node_id, [9; 20]);
            assert_eq!(
                t(decode_table(&routing_table), "decode autosave blob"),
                vec![TableNode {
                    id: NodeId([7; 20]),
                    addr: v4_addr(6883),
                    last_seen_ago_secs: u64::MAX,
                }],
                "a restored node was never contacted -> ago = u64::MAX"
            );
        }
        other => panic!("expected Persist event, got {other:?}"),
    }

    // shutdown → halt save + actor exit.
    call("shutdown", handle.shutdown()).await;
    let ev2 = chan(
        timeout(Duration::from_secs(5), events.recv()).await,
        "halt event",
    );
    assert!(matches!(ev2, DhtEvent::Persist { .. }));
    t(
        t(
            timeout(Duration::from_secs(2), join).await,
            "actor exit timeout",
        ),
        "actor join",
    );
}

// ===== dht_state row restore + forced refresh =====

#[tokio::test]
async fn restore_from_state_row_imports_nodes_and_forces_refresh() {
    let nodes = vec![
        TableNode {
            id: NodeId([1; 20]),
            addr: v4_addr(6884),
            last_seen_ago_secs: 1,
        },
        TableNode {
            id: NodeId([2; 20]),
            addr: v4_addr(6885),
            last_seen_ago_secs: 2,
        },
    ];
    let restore = t(
        DhtRestoreState::from_state_row([0xAB; 20], &encode_table(&nodes)),
        "restore",
    );
    let (handle, _ev, _out, _in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), Some(restore));
    let snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(
        snap.node_id, [0xAB; 20],
        "the persisted node ID is reused (DHTSetup.cc)"
    );
    assert_eq!(snap.num_nodes, 2, "addNode import (DHTSetup.cc)");
    wait_snapshot(&handle, 5_000, |s| s.num_buckets >= 1).await;
    let snap = call("snapshot", handle.snapshot()).await;
    assert!(
        snap.periodic_executing + snap.periodic_waiting >= 1 || snap.num_buckets >= 1,
        "a non-empty restored table -> forced refresh (DHTSetup.cc)"
    );
}

/// Full dht.dat import chain (DhtRestoreState::from_dht_dat): the vector
/// is built per the DHTRoutingTableSerializer.cc encoding rules (annotated
/// in the persist.rs tests); this test covers "file bytes → restore state
/// → engine".
#[tokio::test]
async fn restore_from_aria2_dht_dat_import() {
    // Build a v3 dht.dat (1 local node + 2 remote nodes).
    let mut data = Vec::new();
    data.extend_from_slice(&[0xa1, 0xa2, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03]);
    data.extend_from_slice(&0x65A1B2C3u64.to_be_bytes());
    data.extend_from_slice(&[0u8; 8]);
    data.extend_from_slice(&[0xAB; 20]);
    data.extend_from_slice(&[0u8; 4]);
    data.extend_from_slice(&2u32.to_be_bytes());
    data.extend_from_slice(&[0u8; 4]);
    for (compact, id) in [
        ([192u8, 168, 1, 5, 0x1A, 0xE1], [0x11u8; 20]),
        ([10, 0, 0, 9, 0x1E, 0x3D], [0x22; 20]),
    ] {
        data.push(6); // clen (v4)
        data.extend_from_slice(&[0u8; 7]);
        data.extend_from_slice(&compact);
        data.extend_from_slice(&[0u8; 18]);
        data.extend_from_slice(&id);
        data.extend_from_slice(&[0u8; 4]);
    }
    let restore = t(
        DhtRestoreState::from_dht_dat(DhtFamily::V4, &data),
        "dht.dat import",
    );
    assert_eq!(restore.node_id, NodeId([0xAB; 20]));
    assert_eq!(restore.nodes.len(), 2);

    let (handle, _ev, _out, _in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), Some(restore));
    let snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(snap.node_id, [0xAB; 20]);
    assert_eq!(snap.num_nodes, 2, "all dht.dat nodes imported");
}

// ===== PORT message receive side (BtPortMessage.cc) =====

#[tokio::test]
async fn port_message_pings_peer_and_ignores_port_zero() {
    let (handle, _ev, mut out_rx, _in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    call(
        "add_port_node",
        handle.add_port_node(IpAddr::V4(Ipv4Addr::LOCALHOST), 7777),
    )
    .await;

    // Immediate ping (the empty-table node_lookup completes at seed, sending nothing).
    let pkt = chan(
        timeout(Duration::from_secs(5), out_rx.recv()).await,
        "ping packet",
    );
    assert_eq!(pkt.to, v4_addr(7777));
    match t(decode_message(&pkt.data), "decode ping") {
        DhtMessage::Query(q) => assert_eq!(q.body, QueryBody::Ping),
        other => panic!("ping query expected, got {other:?}"),
    }

    // port = 0 is ignored: no new outbound within 300ms.
    call(
        "add port 0",
        handle.add_port_node(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .await;
    let quiet = timeout(Duration::from_millis(300), out_rx.recv()).await;
    assert!(
        quiet.is_err(),
        "port 0 must not trigger any outbound: {quiet:?}"
    );
}

// ===== In-process two-actor swarm over real loopback UDP =====

#[tokio::test]
async fn two_actor_swarm_discovers_mutually_and_recovers_announced_peer() {
    let (a, mut a_events, _a_addr, _tok_a, demux_a) = spawn_udp_engine(fast_cfg()).await;
    let (b, _b_events, b_addr, _tok_b, demux_b) = spawn_udp_engine(fast_cfg()).await;

    let info_hash = [0x42u8; 20];

    // 1) A bootstraps toward B: the entry ping succeeds → node_lookup +
    // refresh (DHTEntryPointNameResolveCommand.cc).
    // Robustness: the bootstrap result is asserted synchronously (no
    // wait_snapshot polling), and under load the loopback UDP reply can be
    // starved past the ping retry budget (3 x 400ms), giving a false
    // reached=0. Bounded retry: bootstrap is idempotent (re-entering on an
    // empty table has no side effects), so retry up to 3 times before
    // deciding.
    let mut reached = 0usize;
    for attempt in 0..3 {
        reached = call("bootstrap", a.bootstrap(vec![b_addr])).await;
        if reached >= 1 {
            break;
        }
        assert!(
            attempt < 2,
            "the entry ping never arrived across 3 bootstrap rounds; a-stats={:?} b-stats={:?}",
            demux_a.stats(),
            demux_b.stats()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        reached,
        1,
        "entry ping success count; a-stats={:?} b-stats={:?}",
        demux_a.stats(),
        demux_b.stats()
    );
    wait_snapshot(&a, 5_000, |s| s.num_nodes >= 1).await;

    // 2) A announces (get_peers iteration → B replies with a token →
    // announce_peer carries the token) → B records A's peer.
    let announce_port = 17999;
    call(
        "announce",
        a.announce(target_of(info_hash, DhtSwarmKind::V1), announce_port),
    )
    .await;
    wait_snapshot(&b, 10_000, |s| s.peer_record_keys >= 1).await;
    let b_snap = call("snapshot b", b.snapshot()).await;
    assert_eq!(b_snap.peer_record_keys, 1, "B recorded A's announce");

    // 3) A get_peers → B returns A's record as values → a PeersFound event on
    // A (the announce recovers the peer).
    call(
        "get_peers",
        a.get_peers(target_of(info_hash, DhtSwarmKind::V1)),
    )
    .await;
    let expected_peer = v4_addr(announce_port);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::time::Instant::now() > deadline {
            panic!("PeersFound not received within 10s");
        }
        let ev = chan(
            timeout(Duration::from_secs(10), a_events.recv()).await,
            "peers event",
        );
        match ev {
            DhtEvent::PeersFound {
                info_hash: ih,
                face,
                peers,
            } if ih == info_hash && face == DhtSwarmKind::V1 => {
                if peers.contains(&expected_peer) {
                    break;
                }
            }
            DhtEvent::PeersFound { .. } | DhtEvent::Persist { .. } => continue,
        }
    }

    // 4) v2 face: a truncated sha256 target runs the same pipeline (B
    // answers get_peers for a v2 target as well; a discovered peer joins
    // first as a handshake identity, pending hash-exchange verification —
    // see the crate::dht module docs).
    call(
        "v2 get_peers",
        b.get_peers(target_of([0x77; 20], DhtSwarmKind::V2)),
    )
    .await;
    // The quiet wait window is 10s, not 5s — a v2 lookup (400ms-level
    // transaction retries) plus the periodic tasks (30/50ms ticks) stretch
    // under load, and a "zero in-flight" snapshot frame may not appear within
    // 5s (false-negative timeout).
    wait_snapshot(&b, 10_000, |s| {
        s.periodic_executing + s.periodic_waiting == 0
    })
    .await;
}

// ===== Bootstrap degrades gracefully with no reachable entry =====

#[tokio::test]
async fn bootstrap_degrades_gracefully_without_reachable_entry() {
    let mut cfg = fast_cfg();
    cfg.message_timeout = Duration::from_millis(60);
    cfg.bootstrap_ping_retry = 1;
    let (handle, _ev, _bound, _tok, _demux) = spawn_udp_engine(cfg).await;

    // Port 9 (discard) has no listener → ICMP unreachable → all pings time out.
    let reached = call(
        "bootstrap unreachable",
        handle.bootstrap(vec![v4_addr(9), v4_addr(9)]),
    )
    .await;
    assert_eq!(reached, 0, "all entry points unreachable");

    // Degrades instead of crashing: the engine stays alive with no dispatches,
    // an empty table, and a snapshot that still answers.
    let snap = call("snapshot after degrade", handle.snapshot()).await;
    assert_eq!(snap.num_nodes, 0);
    assert_eq!(snap.periodic_executing, 0);
    assert_eq!(snap.periodic_waiting, 0);

    // An empty-table get_peers is accepted and the lookup completes
    // immediately (no leftover in-flight transactions).
    call(
        "get_peers degraded",
        handle.get_peers(target_of([9; 20], DhtSwarmKind::V1)),
    )
    .await;
    wait_snapshot(&handle, 2_000, |s| {
        s.periodic_executing == 0 && s.periodic_waiting == 0 && s.transactions == 0
    })
    .await;
}

// ===== Bootstrap parallel select: first success settles, the rest are cancelled =====

/// One good and two bad entries settle fast: with join semantics the
/// unreachable entries' retry budget would block for its full length
/// (60 x 150ms transaction timeouts ≈ 9s+), so the first reachable entry
/// must settle immediately — reported success count, dispatched
/// node_lookup + refresh, and the same-round pings cancelled. Upstream:
/// libtorrent `node::bootstrap` probes all entries concurrently at once
/// (`src/kademlia/node.cpp`); aria2 joins each entry round
/// (`DHTEntryPointNameResolveCommand.cc`), where unreachable entries delay
/// settlement.
#[tokio::test]
async fn bootstrap_first_success_settles_without_waiting_for_unreachable() {
    let mut cfg = fast_cfg();
    cfg.message_timeout = Duration::from_millis(150);
    cfg.bootstrap_ping_retry = 60; // idle budget for unreachable entries (cancelled by select)
    let (a, _ev_a, _a_addr, _tok_a, _demux_a) = spawn_udp_engine(cfg).await;
    let (_b, _ev_b, b_addr, _tok_b, _demux_b) = spawn_udp_engine(fast_cfg()).await;

    let started = std::time::Instant::now();
    let reached = call(
        "bootstrap one-good-two-bad",
        a.bootstrap(vec![v4_addr(9), b_addr, v4_addr(9)]),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(
        reached, 1,
        "the first reachable entry settles (success count = 1)"
    );
    // The wall-clock bound is 5s, not 2s — under load, command scheduling and
    // loopback round trips can break 2s (false negative); the join-semantics
    // lower bound (>=9s at 60 x 150ms) is unaffected, so the discrimination
    // holds (5s << 9s).
    assert!(
        elapsed < Duration::from_secs(5),
        "the first success is not blocked by the unreachable entries' retry budget: {elapsed:?} (join semantics >= 9s)"
    );

    // Settlement dispatches immediately: node_lookup (self) enters B → the
    // node joins the routing table.
    wait_snapshot(&a, 5_000, |s| s.num_nodes >= 1).await;

    // The same-round pings were cancelled: once the bad entries' transactions
    // are swept out by timeout, the engine returns to quiet (were it still
    // retrying, in-flight transactions/tasks would appear within
    // 60 x 150ms).
    wait_snapshot(&a, 3_000, |s| {
        s.transactions == 0 && s.periodic_executing == 0 && s.periodic_waiting == 0
    })
    .await;
}

// ===== Announce registration x bootstrap wiring race (discovery start) =====

/// An announce lookup that sent nothing must not enter the 15min (1h
/// here) quiet window: when registration precedes bootstrap settlement,
/// the first lookup sends zero queries on an empty table, and the old
/// implementation stamped last_announced anyway, suppressing the reissue
/// for a full interval — the main cause of "peer count always 0" in real
/// swarms. Now a zero-send leaves the stamp untouched, and the next
/// PeerAnnounceCheck (30ms tick) redispatches.
#[tokio::test]
async fn announce_zero_send_does_not_consume_announce_interval() {
    let mut cfg = fast_cfg();
    cfg.peer_announce_interval = Duration::from_secs(3600);
    let (handle, _ev, _out, _in_tx, _join) = spawn_channel_engine(DhtFamily::V4, 6881, cfg, None);

    // Empty-table registration: the lookup completes immediately with zero sends.
    call(
        "announce",
        handle.announce(target_of([0x66; 20], DhtSwarmKind::V1), 6881),
    )
    .await;
    // A redispatch must appear within the (1h) quiet window — zero sends do
    // not consume it (before the fix this assertion timed out).
    wait_snapshot(&handle, 5_000, |s| s.announce_lookups_started >= 2).await;
}

/// Bootstrap settlement redispatches registered entries that have never
/// been announced: registration precedes bootstrap (the wiring-race
/// shape), and PeerAnnounceCheck is stretched to 1h to isolate the
/// periodic leg — the redispatch is the only re-dispatch path. After
/// settlement the announce lookup goes outbound → B replies with a token
/// → announce_peer → B records A (127/8 exempt range, BEP42 allows
/// storage).
#[tokio::test]
async fn bootstrap_settlement_redispatches_pending_announces() {
    let mut cfg_a = fast_cfg();
    cfg_a.peer_announce_check_interval = Duration::from_secs(3600);
    let (a, _ev_a, _a_addr, _tok_a, _demux_a) = spawn_udp_engine(cfg_a).await;
    let (b, _b_events, b_addr, _tok_b, _demux_b) = spawn_udp_engine(fast_cfg()).await;

    // The wiring-race shape: announce registration is issued before bootstrap.
    call(
        "announce-before-bootstrap",
        a.announce(target_of([0x42; 20], DhtSwarmKind::V1), 17999),
    )
    .await;

    let mut reached = 0usize;
    for attempt in 0..3 {
        reached = call("bootstrap", a.bootstrap(vec![b_addr])).await;
        if reached >= 1 {
            break;
        }
        assert!(
            attempt < 2,
            "the entry ping never arrived across 3 bootstrap rounds"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        reached, 1,
        "the entry ping succeeds (the redispatch precondition)"
    );

    // Settlement redispatch: A's second announce lookup (the periodic leg is isolated at 1h).
    wait_snapshot(&a, 5_000, |s| s.announce_lookups_started >= 2).await;
    // The redispatched lookup gets a token from B → announce_peer → B records.
    wait_snapshot(&b, 10_000, |s| s.peer_record_keys >= 1).await;
}

// ===== Mutual discovery, reverse face: B's inbound queries record A =====

#[tokio::test]
async fn queried_node_adds_querier_to_its_routing_table() {
    let (a, _ev_a, _a_addr, _tok_a, _demux_a) = spawn_udp_engine(fast_cfg()).await;
    let (b, _ev_b, b_addr, _tok_b, _demux_b) = spawn_udp_engine(fast_cfg()).await;

    call("bootstrap", a.bootstrap(vec![b_addr])).await;
    // A pinged B → B's inbound query path records A in its routing table
    // (markGood + add, DHTMessageReceiver.cc).
    wait_snapshot(&b, 5_000, |s| s.num_nodes >= 1).await;
}

// ===== BEP42 security extension (algorithm vectors live in the security.rs tests) =====

/// A public-looking non-exempt address (TEST-NET-3, not an exempt range).
fn public_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), port))
}

/// Injects an inbound query.
async fn inject_query(
    in_tx: &mpsc::Sender<InboundPacket>,
    from: SocketAddr,
    sender_id: NodeId,
    body: QueryBody,
) {
    let query = QueryMessage {
        transaction_id: vec![1, 2, 3, 4],
        sender_id,
        body,
        version: None,
    };
    let wire = t(encode_message(&DhtMessage::Query(query)), "encode query");
    t(
        in_tx
            .send(InboundPacket {
                from,
                data: Bytes::from(wire),
            })
            .await,
        "inject query",
    );
}

/// Receives one outbound packet and decodes it.
async fn recv_packet(out_rx: &mut mpsc::Receiver<OutboundPacket>) -> (SocketAddr, DhtMessage) {
    let pkt = chan(
        timeout(Duration::from_secs(5), out_rx.recv()).await,
        "outbound packet",
    );
    (pkt.to, t(decode_message(&pkt.data), "decode outbound"))
}

/// BEP42 inbound check: a get_peers from an invalid id is still serviced
/// (answered, token still issued — "Requests ... should always be
/// serviced"); the node still enters the table (enforcement constrains
/// only the storage face — excluding it from the routing table has no
/// textual basis and would cut off non-compliant bootstrap routes, see
/// the on_query module docs).
#[tokio::test]
async fn bep42_noncompliant_get_peers_serviced_and_routed() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    let from = public_addr(6881);
    inject_query(
        &in_tx,
        from,
        NodeId([0xAB; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId([7; 20]),
            want: WantFamilies::default(),
        },
    )
    .await;

    // Service face: a normal reply (GetPeers body with the token still issued).
    let (to, msg) = recv_packet(&mut out_rx).await;
    assert_eq!(to, from, "the reply returns to its source");
    match msg {
        DhtMessage::Response(r) => match r.body {
            ResponseBody::GetPeers { token, .. } => {
                assert!(
                    !token.is_empty(),
                    "the token is still issued (service unaffected)"
                )
            }
            other => panic!("get_peers reply expected, got {other:?}"),
        },
        other => panic!("response expected, got {other:?}"),
    }
    // Enters the table (enforcement is storage-only; connectivity first —
    // excluding non-compliant bootstrap routes would sever the network).
    let snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(
        snap.num_nodes, 1,
        "the routing face performs no BEP42 exclusion (the text imposes none)"
    );
    assert_eq!(
        snap.transactions, 0,
        "inbound queries occupy no transaction slot"
    );
}

/// BEP42 exemption face: a local network address (127/8) skips the check —
/// the same-shaped query enters the table ("Any peer on a local network
/// address is exempt").
#[tokio::test]
async fn bep42_exempt_source_is_routed() {
    let (handle, _ev, _out, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    inject_query(
        &in_tx,
        v4_addr(6881),
        NodeId([0xCD; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId([7; 20]),
            want: WantFamilies::default(),
        },
    )
    .await;
    wait_snapshot(&handle, 5_000, |s| s.num_nodes == 1).await;
}

/// BEP42 announce storage rejection: an announce_peer with a valid token
/// from an invalid id is still answered, but the peer is not recorded
/// ("MUST never be used to store information on"); the same-shaped
/// announce from an exempt address is recorded normally (control).
#[tokio::test]
async fn bep42_noncompliant_announce_not_stored() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    let ih = [0x55; 20];

    // 1) An invalid-id side fetches a token via get_peers → the reply carries it (service as usual).
    let bad_from = public_addr(6881);
    inject_query(
        &in_tx,
        bad_from,
        NodeId([0xAB; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let bad_token = match recv_packet(&mut out_rx).await.1 {
        DhtMessage::Response(r) => match r.body {
            ResponseBody::GetPeers { token, .. } => token,
            other => panic!("get_peers reply expected, got {other:?}"),
        },
        other => panic!("response expected, got {other:?}"),
    };

    // 2) The same side announces (valid token) → a Ping reply, but nothing recorded.
    inject_query(
        &in_tx,
        bad_from,
        NodeId([0xAB; 20]),
        QueryBody::AnnouncePeer {
            info_hash: NodeId(ih),
            port: 7777,
            token: bad_token,
            implied_port: None,
        },
    )
    .await;
    let (to, msg) = recv_packet(&mut out_rx).await;
    assert_eq!(to, bad_from);
    assert!(
        matches!(msg, DhtMessage::Response(ref r) if matches!(r.body, ResponseBody::Ping)),
        "announce_peer is answered as usual (no error/silence)"
    );
    let snap = call("snapshot after bad announce", handle.snapshot()).await;
    assert_eq!(
        snap.peer_record_keys, 0,
        "an announce from an invalid id is not stored"
    );

    // 3) Control: the same-shaped announce from an exempt (127/8) address → recorded normally.
    inject_query(
        &in_tx,
        v4_addr(6882),
        NodeId([0xCD; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let good_token = match recv_packet(&mut out_rx).await.1 {
        DhtMessage::Response(r) => match r.body {
            ResponseBody::GetPeers { token, .. } => token,
            other => panic!("get_peers reply expected, got {other:?}"),
        },
        other => panic!("response expected, got {other:?}"),
    };
    inject_query(
        &in_tx,
        v4_addr(6882),
        NodeId([0xCD; 20]),
        QueryBody::AnnouncePeer {
            info_hash: NodeId(ih),
            port: 7778,
            token: good_token,
            implied_port: None,
        },
    )
    .await;
    let _ = recv_packet(&mut out_rx).await; // announce ack
    wait_snapshot(&handle, 5_000, |s| s.peer_record_keys == 1).await;
}

/// BEP42 "Bootstrapping": the ping reply frame carries a top-level `ip`
/// field whose value is the requester's endpoint as observed locally
/// (big-endian address 4B/16B + big-endian port 2B = 6B/18B). Spec text:
/// "all DHT responses SHOULD include a top-level field called ip,
/// containing a compact binary representation of the requestor's IP and
/// port. That is big endian IP followed by 2 bytes of big endian port" +
/// "It is important that the ip field is in the top level dictionary"
/// (bittorrent.org/beps/bep_0042.html). libtorrent's sender is shaped the
/// same: node.cpp `incoming_request` writes
/// `e["ip"] = endpoint_to_bytes(m.addr);` **before** building the r dict
/// (top level, not inside it); endpoint_to_bytes = write_address +
/// write_uint16(port) (socket_io.hpp, v4 6B / v6 18B). The assertion runs
/// on the raw outbound bytes (top-level key position and byte shape
/// anchored together, guarding against landing in the r dict or losing
/// the port).
#[tokio::test]
async fn bep42_ping_reply_carries_top_level_ip_field() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    let from = public_addr(51414);
    inject_query(&in_tx, from, NodeId([0x11; 20]), QueryBody::Ping).await;
    let pkt = chan(
        timeout(Duration::from_secs(5), out_rx.recv()).await,
        "ping reply",
    );
    // Expected payload: the top-level key `2:ip` plus the compact endpoint
    // (4B address + 2B port; pack_peer matches libtorrent's
    // endpoint_to_bytes layout).
    let mut needle = b"2:ip6:".to_vec();
    pack_peer(from, &mut needle);
    assert!(
        pkt.data.windows(needle.len()).any(|w| w == needle),
        "reply must carry top-level ip = requester endpoint; got {:?}",
        pkt.data
    );
    // The reported address must be the request source (the same observed
    // endpoint the reply returns to).
    assert_eq!(pkt.to, from);
    // Same anchor on the decoded face: the field carries the full observed
    // endpoint (address + port).
    match t(decode_message(&pkt.data), "decode reply") {
        DhtMessage::Response(r) => assert_eq!(r.requester_endpoint, Some(from)),
        other => panic!("response expected, got {other:?}"),
    }
    let _ = handle; // keep the engine alive until the assertions finish
}

/// BEP42 local derivation: SetExternalIp delivers an external address →
/// the node_id is re-derived and validates against the new address; the
/// id is stable while the address is unchanged; exempt addresses do not
/// trigger re-derivation (libtorrent node.cpp update_node_id semantics).
#[tokio::test]
async fn bep42_set_external_ip_rederives_node_id() {
    let (handle, _ev, _out, _in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    let id0 = call("snapshot", handle.snapshot()).await.node_id;

    let ext: IpAddr = Ipv4Addr::new(203, 0, 113, 9).into();
    call("set ext", handle.set_external_ip(ext)).await;
    wait_snapshot(&handle, 5_000, |s| s.node_id != id0).await;
    let id1 = call("snapshot", handle.snapshot()).await.node_id;
    assert!(
        verify_node_id(&NodeId(id1), ext),
        "the re-derived id must verify against the external address"
    );

    // Re-delivering the same address → the id is stable (node.cpp keeps the
    // current id while it still validates).
    call("set ext again", handle.set_external_ip(ext)).await;
    let id2 = call("snapshot", handle.snapshot()).await.node_id;
    assert_eq!(id1, id2, "the current id still validates -> kept");

    // A local address (exempt range) → verification always passes → no re-derivation.
    call(
        "set local",
        handle.set_external_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
    )
    .await;
    let id3 = call("snapshot", handle.snapshot()).await.node_id;
    assert_eq!(
        id2, id3,
        "exempt addresses do not trigger re-derivation (verify is always true)"
    );
}

/// BEP42 outbound storage limit: the lookup announce stage sends
/// announce_peer only to nodes with valid ids ("MUST never be used to
/// store information on, regardless of which request"). A non-compliant
/// node's token is never used even when obtained (service and lookup
/// progress are unaffected).
#[tokio::test]
async fn bep42_announce_peer_skipped_for_noncompliant_targets() {
    // An invalid-id node (public-looking) and an exempt-address node (any id
    // is valid) enter the table via the restore state — they are exactly the
    // lookup candidates.
    let bad_id = NodeId([0xAB; 20]);
    let bad_addr = public_addr(6881);
    let ok_id = NodeId([0xCD; 20]);
    let ok_addr = v4_addr(6882);
    let nodes = vec![
        TableNode {
            id: bad_id,
            addr: bad_addr,
            last_seen_ago_secs: 1,
        },
        TableNode {
            id: ok_id,
            addr: ok_addr,
            last_seen_ago_secs: 1,
        },
    ];
    let restore = t(
        DhtRestoreState::from_state_row([0x99; 20], &encode_table(&nodes)),
        "restore",
    );
    // The reissue cadence is slowed (fast_cfg's 80ms period would redispatch
    // a lookup within the quiet window, disturbing the "exactly one send"
    // assertion).
    let mut cfg = fast_cfg();
    cfg.peer_announce_check_interval = Duration::from_secs(3600);
    cfg.peer_announce_interval = Duration::from_secs(3600);
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, cfg, Some(restore));

    call(
        "announce",
        handle.announce(target_of([0x66; 20], DhtSwarmKind::V1), 6881),
    )
    .await;

    // Collect the two get_peers queries, matching transaction ids by peer
    // address. (Non-empty restored nodes first dispatch a forced-refresh
    // FindNode query — DHTSetup.cc — so non-GetPeers outbound is skipped.)
    let mut tids = HashMap::new();
    let collect_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while tids.len() < 2 {
        assert!(
            std::time::Instant::now() < collect_deadline,
            "timeout collecting get_peers queries"
        );
        let (to, msg) = recv_packet(&mut out_rx).await;
        if let DhtMessage::Query(q) = msg
            && matches!(q.body, QueryBody::GetPeers { .. })
        {
            tids.insert(to, q.transaction_id);
        }
    }
    assert_eq!(tids.len(), 2, "one send per candidate");

    // Both sides return a token (service as usual); after the lookup
    // completes the announce stage begins.
    for (addr, id, tok) in [
        (bad_addr, bad_id, vec![0xAAu8; 8]),
        (ok_addr, ok_id, vec![0xBBu8; 8]),
    ] {
        let Some(tid) = tids.get(&addr) else {
            panic!("missing tid for {addr}");
        };
        let resp = ResponseMessage {
            transaction_id: tid.clone(),
            responder_id: id,
            body: ResponseBody::GetPeers {
                token: tok,
                nodes: Vec::new(),
                values: Vec::new(),
            },
            requester_endpoint: None,
            version: None,
        };
        let wire = t(encode_message(&DhtMessage::Response(resp)), "encode resp");
        t(
            in_tx
                .send(InboundPacket {
                    from: addr,
                    data: Bytes::from(wire),
                })
                .await,
            "inject resp",
        );
    }

    // Announce stage: announce_peer goes only to the exempt-address node;
    // the invalid-id node receives none. (find_node outbound from the
    // restored nodes' forced refresh — DHTSetup.cc — is ignored in the
    // window; only announce_peer is collected.)
    // Robustness: this was a fixed 600ms collection window (the lookup's
    // token round trip can starve under load, yielding an empty false
    // negative). Now event-driven plus a quiet confirmation: after the first
    // announce_peer within the 3s deadline, wait a further 300ms quiet window
    // to confirm no violating additions (keeping the "only to compliant
    // nodes" detection face — early exit does not shrink the violation
    // exposure window).
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut announced_to = Vec::new();
    while std::time::Instant::now() < deadline {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
        let wait = if announced_to.is_empty() {
            remain
        } else {
            // Quiet confirmation window (up to 300ms from the first packet; no new announce settles it).
            remain.min(Duration::from_millis(300))
        };
        let Ok(Some(pkt)) = timeout(wait, out_rx.recv()).await else {
            if !announced_to.is_empty() {
                break; // quiet confirmation passed: no further announces.
            }
            continue;
        };
        if let Ok(DhtMessage::Query(q)) = decode_message(&pkt.data)
            && matches!(q.body, QueryBody::AnnouncePeer { .. })
        {
            announced_to.push(pkt.to);
        }
    }
    assert!(
        !announced_to.is_empty(),
        "announce_peer to compliant node expected"
    );
    assert_eq!(
        announced_to,
        vec![ok_addr],
        "announce only to the compliant node"
    );
}

// ===== Server error replies and per-source rate limiting =====

/// Injects raw inbound bytes (malformed or arbitrary messages).
async fn inject_raw(in_tx: &mpsc::Sender<InboundPacket>, from: SocketAddr, wire: &[u8]) {
    t(
        in_tx
            .send(InboundPacket {
                from,
                data: Bytes::from(wire.to_vec()),
            })
            .await,
        "inject raw packet",
    );
}

/// Builds raw query bytes (key order a < q < t < y, canonical; the id is
/// always "abcdefghij0123456789", the BEP5 example sender id).
fn raw_query(method: &[u8], tid: &[u8]) -> Vec<u8> {
    let mut wire = b"d1:ad2:id20:abcdefghij0123456789e1:q".to_vec();
    wire.extend_from_slice(format!("{}:", method.len()).as_bytes());
    wire.extend_from_slice(method);
    wire.extend_from_slice(b"1:t");
    wire.extend_from_slice(format!("{}:", tid.len()).as_bytes());
    wire.extend_from_slice(tid);
    wire.extend_from_slice(b"1:y1:qe");
    wire
}

/// Asserts the outbound channel stays quiet over the window (with an
/// empty engine table plus fast_cfg there is no maintenance outbound —
/// the same quiet-window convention as the port_message test).
async fn assert_quiet(out_rx: &mut mpsc::Receiver<OutboundPacket>, ms: u64, what: &str) {
    let quiet = timeout(Duration::from_millis(ms), out_rx.recv()).await;
    assert!(
        matches!(quiet, Err(_) | Ok(None)),
        "{what}: expected silence, got {:?}",
        quiet.map(|o| o.map(|p| decode_message(&p.data)))
    );
}

/// Trigger matrix (error-reply face): a malformed query (known method +
/// missing argument) → 203, unknown method → 204, tid echoed — the BEP5
/// "Errors" code list (203 "Protocol Error, such as a malformed packet,
/// invalid arguments, or bad token"; 204 "Method Unknown") plus
/// libtorrent's incoming_error default of 203 (node.cpp). A malformed
/// query never enters the routing table (decode failure never reaches
/// on_query).
#[tokio::test]
async fn error_reply_trigger_matrix_203_204_with_tid_echo() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    let src = public_addr(7001);

    // 1) find_node missing target (known method, malformed argument) → 203 + tid "aa".
    inject_raw(&in_tx, src, &raw_query(b"find_node", b"aa")).await;
    let (to, msg) = recv_packet(&mut out_rx).await;
    assert_eq!(to, src, "the error reply returns to its source");
    match msg {
        DhtMessage::Error(e) => {
            assert_eq!(
                e.code, ERROR_PROTOCOL,
                "malformed query -> 203 (the BEP5 code table)"
            );
            assert_eq!(e.transaction_id, b"aa", "tid echoed");
            assert_eq!(
                e.message, ERROR_MSG_PROTOCOL,
                "the message is short and fixed"
            );
        }
        other => panic!("error reply expected, got {other:?}"),
    }

    // 2) Unknown method → 204 + tid "bb" (BEP5 "Method Unknown").
    inject_raw(&in_tx, src, &raw_query(b"unknown", b"bb")).await;
    let (_, msg) = recv_packet(&mut out_rx).await;
    match msg {
        DhtMessage::Error(e) => {
            assert_eq!(e.code, ERROR_METHOD_UNKNOWN, "unknown method -> 204");
            assert_eq!(e.transaction_id, b"bb");
        }
        other => panic!("error reply expected, got {other:?}"),
    }

    let snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(
        snap.num_nodes, 0,
        "a malformed query never enters the routing table (on_query never reached)"
    );
}

/// Trigger matrix (silent face): bencode garbage / non-dict / missing y /
/// y not q/r/e / missing t (no tid to echo) / inbound response and error
/// messages — all get zero replies (anti-amplification, anti-reflection;
/// same policy as libtorrent node.cpp). 201 has no wire trigger: overload
/// is handled by silent rate limiting (see the error_limit module docs),
/// only the encoding vector remains.
#[tokio::test]
async fn error_reply_silent_for_non_query_and_unusable_shapes() {
    let (_handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, fast_cfg(), None);
    let src = public_addr(7002);
    let silent_cases: Vec<(&[u8], &str)> = vec![
        (b"\x00garbage", "bencode garbage"),
        (b"i1e", "top level is not a dict"),
        (b"d1:t2:aae", "y missing"),
        (b"d1:t2:aa1:y1:ze", "y not q/r/e"),
        (
            b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:y1:qe",
            "missing t (no tid to echo)",
        ),
        // Response face (no transaction match) — existing silence kept (anti-reflection).
        (
            b"d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re",
            "response with no transaction",
        ),
    ];
    for (wire, _what) in &silent_cases {
        inject_raw(&in_tx, src, wire).await;
    }
    assert_quiet(&mut out_rx, 300, "the whole silent-face group").await;
}

/// announce_peer with a bad token → 203 (BEP5 "bad token"; libtorrent
/// node.cpp "invalid token"), tid echoed; per-source rate limiting: after
/// [`ERROR_REPLY_BURST`] full-bucket replies, excess gets silence (the
/// anti-amplification assertion).
#[tokio::test]
async fn announce_peer_invalid_token_replies_203_until_budget_exhausted() {
    // All maintenance cadences are slowed: a bad-token announce does enter
    // the routing table (service as usual), and fast_cfg's 50ms refresh
    // check would dispatch find_node outbound within the quiet window,
    // disturbing the "silence after excess" assertion (same handling as
    // bep42_announce_peer_skipped_for_noncompliant_targets).
    let mut cfg = fast_cfg();
    cfg.refresh_check_interval = Duration::from_secs(3600);
    cfg.peer_announce_check_interval = Duration::from_secs(3600);
    cfg.peer_announce_interval = Duration::from_secs(3600);
    cfg.peer_announce_purge_interval = Duration::from_secs(3600);
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, cfg, None);
    let ih = [0x77; 20];
    let src = public_addr(7100);

    // Fetch the real token first (get_peers reply); the bad token shares nothing with it.
    inject_query(
        &in_tx,
        src,
        NodeId([0xAB; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let _real_token = match recv_packet(&mut out_rx).await.1 {
        DhtMessage::Response(r) => match r.body {
            ResponseBody::GetPeers { token, .. } => token,
            other => panic!("get_peers reply expected, got {other:?}"),
        },
        other => panic!("response expected, got {other:?}"),
    };

    // Fill the bucket plus one more bad-token announce (distinguished by tid).
    for i in 0..=ERROR_REPLY_BURST {
        let query = QueryMessage {
            transaction_id: vec![i as u8; 4],
            sender_id: NodeId([0xAB; 20]),
            body: QueryBody::AnnouncePeer {
                info_hash: NodeId(ih),
                port: 7777,
                token: vec![0xFF; 8],
                implied_port: None,
            },
            version: None,
        };
        let wire = t(encode_message(&DhtMessage::Query(query)), "encode announce");
        t(
            in_tx
                .send(InboundPacket {
                    from: src,
                    data: Bytes::from(wire),
                })
                .await,
            "inject announce",
        );
    }

    // Exactly the full-bucket count answers 203 (each tid echoed); beyond that, silence.
    for i in 0..ERROR_REPLY_BURST {
        let (to, msg) = recv_packet(&mut out_rx).await;
        assert_eq!(to, src);
        match msg {
            DhtMessage::Error(e) => {
                assert_eq!(e.code, ERROR_PROTOCOL, "bad token -> 203");
                assert_eq!(e.transaction_id, vec![i as u8; 4], "tid echoed");
            }
            other => panic!("error reply expected, got {other:?}"),
        }
    }
    assert_quiet(
        &mut out_rx,
        300,
        "zero answers once over the limit (anti-amplification)",
    )
    .await;

    // A bad token stores nothing (validation precedes the record path;
    // behavior matches the silent variant).
    let snap = call("snapshot after invalid token flood", handle.snapshot()).await;
    assert_eq!(
        snap.peer_record_keys, 0,
        "a bad-token announce is not recorded"
    );
}

// ===== Per-source inbound query rate limiting and suppression =====

/// Distinct TEST-NET source addresses (203.0.113.<octet>:<port>): rate
/// limiting and exemptions are keyed by IP, so test sources must differ
/// in IP (same IP shares the budget/exemption).
fn test_net_addr(octet: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, octet), port))
}

/// Micro rate-limit config: scales the limiting face down to test size
/// (rate per second, burst, suppression seconds); the rest matches
/// fast_cfg.
fn throttle_cfg(rate: u32, burst: u32, suppress_secs: u64) -> DhtEngineConfig {
    DhtEngineConfig {
        per_source_query_rate: rate,
        per_source_query_burst: burst,
        suppress_secs,
        ..fast_cfg()
    }
}

/// Receives a Response addressed to `from` (skips unrelated outbound, such as maintenance Queries).
async fn recv_response_from(
    out_rx: &mut mpsc::Receiver<OutboundPacket>,
    from: SocketAddr,
    what: &str,
) -> ResponseMessage {
    for _ in 0..64 {
        let pkt = chan(timeout(Duration::from_secs(5), out_rx.recv()).await, what);
        if pkt.to == from {
            match t(decode_message(&pkt.data), what) {
                DhtMessage::Response(r) => return r,
                _ => continue,
            }
        }
    }
    panic!("{what}: no response to {from}");
}

/// Receives an Error reply addressed to `from` (skips unrelated outbound).
async fn recv_error_from(
    out_rx: &mut mpsc::Receiver<OutboundPacket>,
    from: SocketAddr,
    what: &str,
) -> ErrorMessage {
    for _ in 0..64 {
        let pkt = chan(timeout(Duration::from_secs(5), out_rx.recv()).await, what);
        if pkt.to == from {
            match t(decode_message(&pkt.data), what) {
                DhtMessage::Error(e) => return e,
                _ => continue,
            }
        }
    }
    panic!("{what}: no error reply to {from}");
}

/// Receives an outbound Query addressed to `to` (bootstrap/PORT ping assertions).
async fn recv_query_to(out_rx: &mut mpsc::Receiver<OutboundPacket>, to: SocketAddr, what: &str) {
    for _ in 0..64 {
        let pkt = chan(timeout(Duration::from_secs(5), out_rx.recv()).await, what);
        if pkt.to == to {
            match t(decode_message(&pkt.data), what) {
                DhtMessage::Query(_) => return,
                _ => continue,
            }
        }
    }
    panic!("{what}: no query to {to}");
}

/// Asserts no Response addressed to `from` appears within the window
/// (over-limit/suppression means zero replies to that source; unrelated
/// maintenance outbound does not count — fast_cfg's millisecond timers
/// send refresh queries to table nodes).
async fn assert_no_response_to(
    out_rx: &mut mpsc::Receiver<OutboundPacket>,
    from: SocketAddr,
    ms: u64,
    what: &str,
) {
    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
        if remain.is_zero() {
            return;
        }
        match timeout(remain, out_rx.recv()).await {
            Err(_) | Ok(None) => return,
            Ok(Some(pkt)) => {
                if pkt.to == from
                    && let Ok(DhtMessage::Response(_)) = decode_message(&pkt.data)
                {
                    panic!("{what}: got response to {from}");
                }
            }
        }
    }
}

/// Rate-limit trigger: the (burst+1)-th query from one source is silently
/// dropped (no error reply — anti-amplification); other sources have
/// independent budgets (IP-keyed).
#[tokio::test]
async fn per_source_query_limit_drops_excess_and_isolates_sources() {
    let (_handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, throttle_cfg(1, 3, 3600), None);
    let a = test_net_addr(1, 7001);
    let b = test_net_addr(2, 7002);
    // Source A fills the bucket with 3 pings → each answered (tid echoed).
    for _ in 0..3 {
        inject_query(&in_tx, a, NodeId([0xA0; 20]), QueryBody::Ping).await;
        let r = recv_response_from(
            &mut out_rx,
            a,
            "queries inside the full bucket must be answered",
        )
        .await;
        assert_eq!(r.transaction_id, vec![1, 2, 3, 4], "tid echoed");
    }
    // The (burst+1)-th: bucket empty → silently dropped (no error reply; the
    // error face has its own budget).
    inject_query(&in_tx, a, NodeId([0xA0; 20]), QueryBody::Ping).await;
    assert_no_response_to(
        &mut out_rx,
        a,
        250,
        "over-limit queries must get zero replies",
    )
    .await;
    // Source B's budget is independent: answered as usual.
    inject_query(&in_tx, b, NodeId([0xB0; 20]), QueryBody::Ping).await;
    recv_response_from(
        &mut out_rx,
        b,
        "another source's budget must be independent",
    )
    .await;
}

/// Suppression entry and expiry recovery (not a permanent ban); during
/// suppression the error-reply path is not subject to this limit (they
/// coexist: a malformed query still gets 204, clamped independently by
/// error_limit).
#[tokio::test]
async fn suppression_silences_then_recovers_and_error_reply_coexists() {
    let (_handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, throttle_cfg(1, 1, 3), None);
    let a = test_net_addr(3, 7003);
    // burst=1: the first is answered; the first drop already meets the
    // suppression criterion (violations >= burst=1).
    inject_query(&in_tx, a, NodeId([0xA0; 20]), QueryBody::Ping).await;
    recv_response_from(
        &mut out_rx,
        a,
        "the first in a full bucket must be answered",
    )
    .await;
    inject_query(&in_tx, a, NodeId([0xA0; 20]), QueryBody::Ping).await;
    assert_no_response_to(
        &mut out_rx,
        a,
        200,
        "once suppression engages it must stay silent",
    )
    .await;
    // During suppression, even past a refill period (1s at rate=1;
    // suppress=3s > period, so tokens are refilled yet must still be
    // dropped) the source stays silent — suppression collapses the
    // per-source inbound query ceiling to 0.
    tokio::time::sleep(Duration::from_millis(1050)).await;
    inject_query(&in_tx, a, NodeId([0xA0; 20]), QueryBody::Ping).await;
    assert_no_response_to(
        &mut out_rx,
        a,
        200,
        "still silent past a refill period during suppression",
    )
    .await;
    // During suppression the error-reply face is unaffected: an echoable
    // malformed query (unknown method) still gets 204 — the query limiter and
    // the error limiter govern separate faces (they coexist).
    inject_raw(&in_tx, a, &raw_query(b"unknown", b"ee")).await;
    let e = recv_error_from(
        &mut out_rx,
        a,
        "error replies are not subject to the query limit",
    )
    .await;
    assert_eq!(e.code, ERROR_METHOD_UNKNOWN, "unknown method -> 204");
    // Suppression expiry (suppress_secs=3, >3s elapsed): automatic recovery,
    // queries are answered again (not a permanent ban).
    tokio::time::sleep(Duration::from_millis(2050)).await;
    inject_query(&in_tx, a, NodeId([0xA0; 20]), QueryBody::Ping).await;
    recv_response_from(
        &mut out_rx,
        a,
        "suppression expiry must recover answering automatically",
    )
    .await;
}

/// Bootstrap entry exemption: inbound queries from the entry IP bypass
/// rate limiting (preserving "Requests ... should always be serviced" —
/// the bootstrap path must not be starved); non-entry sources are limited
/// as usual.
#[tokio::test]
async fn bootstrap_entry_source_is_exempt_from_query_limit() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, throttle_cfg(1, 1, 3600), None);
    let entry = test_net_addr(10, 7010);
    // Entry registration (exempt from start_bootstrap) + the entry ping goes outbound.
    call("bootstrap", handle.bootstrap(vec![entry])).await;
    recv_query_to(
        &mut out_rx,
        entry,
        "the bootstrap entry ping must go outbound",
    )
    .await;
    // The entry IP sends 5 in a row (without exemption the 2nd would be
    // silent at burst=1) → all answered.
    for _ in 0..5 {
        inject_query(&in_tx, entry, NodeId([0xE0; 20]), QueryBody::Ping).await;
        recv_response_from(
            &mut out_rx,
            entry,
            "entry sources must be exempt from limiting",
        )
        .await;
    }
    // Control: a non-entry source (different IP) is limited as usual (first answered, next silent).
    let plain = test_net_addr(11, 7011);
    inject_query(&in_tx, plain, NodeId([0xF0; 20]), QueryBody::Ping).await;
    recv_response_from(
        &mut out_rx,
        plain,
        "a non-entry source is answered as usual",
    )
    .await;
    inject_query(&in_tx, plain, NodeId([0xF0; 20]), QueryBody::Ping).await;
    assert_no_response_to(
        &mut out_rx,
        plain,
        250,
        "a non-entry source over its bucket must stay silent",
    )
    .await;
}

/// PORT-introduced source exemption: the source IP registered by
/// AddPortNode bypasses rate limiting (keyed by IP — source port
/// irrelevant), so bootstrap interaction right after the handshake is not
/// starved; other sources are limited as usual.
#[tokio::test]
async fn port_node_source_is_exempt_from_query_limit() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, throttle_cfg(1, 1, 3600), None);
    let peer_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    call("add port node", handle.add_port_node(peer_ip, 6881)).await;
    // PORT → an immediate outbound ping (BtPortMessage.cc).
    recv_query_to(
        &mut out_rx,
        SocketAddr::new(peer_ip, 6881),
        "the PORT-triggered ping must go outbound",
    )
    .await;
    // The same source IP (varying ports) sends 5 in a row, all answered — the exemption is IP-keyed.
    for port in [7001u16, 7002, 7003, 7004, 7005] {
        let from = SocketAddr::new(peer_ip, port);
        inject_query(&in_tx, from, NodeId([0x77; 20]), QueryBody::Ping).await;
        recv_response_from(
            &mut out_rx,
            from,
            "PORT-introduced sources must be exempt from limiting",
        )
        .await;
    }
    // Control: a non-entry source (different IP) is limited as usual (first answered, next silent).
    let plain = test_net_addr(78, 7078);
    inject_query(&in_tx, plain, NodeId([0x78; 20]), QueryBody::Ping).await;
    recv_response_from(&mut out_rx, plain, "other sources are answered as usual").await;
    inject_query(&in_tx, plain, NodeId([0x78; 20]), QueryBody::Ping).await;
    assert_no_response_to(
        &mut out_rx,
        plain,
        250,
        "other sources over their bucket must stay silent",
    )
    .await;
}

// ===== DHT boundedness (regression tests for amplification PoC shapes) =====

/// Config with the query limiter raised out of the way and maintenance
/// cadences frozen: this group targets boundedness of the **storage and
/// assembly** faces (modeling a multi-source botnet where each source is
/// within budget or exempt — boundedness must not rely on the query
/// limiter as a backstop). With maintenance frozen, each accepted query
/// produces exactly one reply (strict 1:1; interleaved injection and
/// receipt never deadlocks and emits no noise).
fn boundedness_cfg() -> DhtEngineConfig {
    let mut cfg = fast_cfg();
    cfg.per_source_query_rate = 100_000;
    cfg.per_source_query_burst = 100_000;
    cfg.refresh_check_interval = Duration::from_secs(3600);
    cfg.peer_announce_check_interval = Duration::from_secs(3600);
    cfg.peer_announce_interval = Duration::from_secs(3600);
    cfg.peer_announce_purge_interval = Duration::from_secs(3600);
    cfg
}

/// Receives the next outbound Response (returns raw wire length +
/// decoded body; no noise under frozen maintenance).
async fn recv_response_with_len(
    out_rx: &mut mpsc::Receiver<OutboundPacket>,
    what: &'static str,
) -> (usize, ResponseMessage) {
    loop {
        let pkt = chan(timeout(Duration::from_secs(5), out_rx.recv()).await, what);
        if let Ok(DhtMessage::Response(r)) = decode_message(&pkt.data) {
            break (pkt.data.len(), r);
        }
    }
}

/// Anti-PoC assertion for reflection amplification: a malicious source
/// fetches a token then announces from many ports to flood one key (the
/// single-source equivalent of the PoC's "~120B query per port announce";
/// 700 > the 500 per-key cap >> the 50 reply cap). The following small
/// get_peers reply must be **bounded** — at most 50 values, all one
/// family, one packet <= 1400B (single MTU; before the fix a full
/// reflection was ≈5.6KB+), storage <= the per-key cap, and the
/// truncation counter recorded.
#[tokio::test]
async fn get_peers_reply_is_bounded_under_announce_flood() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, boundedness_cfg(), None);
    let ih = [0x99; 20];
    // A 127/8 exempt source (BEP42 storage exemption, the same convention as
    // the control in bep42_noncompliant_announce_not_stored) — announce
    // records are not refused by the storage check.
    let bot = v4_addr(9);
    let flood: u16 = 700;

    // 1) Fetch a token (the validity precondition for announce_peer).
    inject_query(
        &in_tx,
        bot,
        NodeId([0xB0; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let token = match recv_response_with_len(&mut out_rx, "token reply")
        .await
        .1
        .body
    {
        ResponseBody::GetPeers { token, .. } => token,
        other => panic!("get_peers reply expected, got {other:?}"),
    };

    // 2) Flood: per-port announces each become a new record (the
    // DHTPeerAnnounceStorage "one record per (ip,port)" rule).
    for port in 1000..1000 + flood {
        inject_query(
            &in_tx,
            bot,
            NodeId([0xB0; 20]),
            QueryBody::AnnouncePeer {
                info_hash: NodeId(ih),
                port,
                token: token.clone(),
                implied_port: None,
            },
        )
        .await;
        let _ = recv_response_with_len(&mut out_rx, "announce ack").await;
    }

    // 3) A victim-view small get_peers → the reply must be bounded.
    inject_query(
        &in_tx,
        bot,
        NodeId([0xB1; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let (wire_len, reply) = recv_response_with_len(&mut out_rx, "flooded reply").await;
    let ResponseBody::GetPeers { values, .. } = reply.body else {
        panic!("get_peers reply expected");
    };
    assert_eq!(
        values.len(),
        MAX_VALUES_PER_REPLY,
        "the values count must be bounded (pre-fix = the whole {flood} fed in)"
    );
    assert!(
        values.iter().all(|a| a.is_ipv4()),
        "the single-family semantics survive the truncation face"
    );
    assert!(
        wire_len < 1400,
        "one packet must stay under a single MTU of 1400B (reflection-amplification assertion), got {wire_len}B"
    );

    // 4) Storage face bounded: records per key <= the per-key cap (a 65k
    // flood cannot happen), and the truncation counter is recorded
    // (truncated = per-key cap − reply retention: the single key is all v4,
    // deterministically uncontended).
    let snap = call("snapshot after flood", handle.snapshot()).await;
    assert_eq!(
        snap.peer_record_keys, 1,
        "the flood concentrated on a single key"
    );
    assert!(
        snap.peer_records_total <= MAX_PEER_RECORDS_PER_KEY,
        "records per key must be <= {MAX_PEER_RECORDS_PER_KEY} (pre-fix had no bound)"
    );
    assert_eq!(
        snap.values_truncated_total,
        (MAX_PEER_RECORDS_PER_KEY - MAX_VALUES_PER_REPLY) as u64,
        "the truncation counter must be on record"
    );
}

/// Dedup face: repeated announces from the same (ip,port) add no records
/// (the engine-level O(1) hash dedup), so repeat flooding does not grow
/// storage.
#[tokio::test]
async fn duplicate_announce_does_not_grow_records() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, boundedness_cfg(), None);
    let ih = [0x98; 20];
    let bot = v4_addr(8);

    inject_query(
        &in_tx,
        bot,
        NodeId([0xC0; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let token = match recv_response_with_len(&mut out_rx, "token reply")
        .await
        .1
        .body
    {
        ResponseBody::GetPeers { token, .. } => token,
        other => panic!("get_peers reply expected, got {other:?}"),
    };
    // Three announces from the same (ip,port).
    for _ in 0..3 {
        inject_query(
            &in_tx,
            bot,
            NodeId([0xC0; 20]),
            QueryBody::AnnouncePeer {
                info_hash: NodeId(ih),
                port: 7001,
                token: token.clone(),
                implied_port: None,
            },
        )
        .await;
        let _ = recv_response_with_len(&mut out_rx, "announce ack").await;
    }
    let snap = call("snapshot after dup announce", handle.snapshot()).await;
    assert_eq!(snap.peer_record_keys, 1);
    assert_eq!(
        snap.peer_records_total, 1,
        "duplicate (ip,port) must not add a record"
    );
}

// ===== BEP32 want parameter + the 1024B whole-frame reply gate =====

/// A v6 loopback address (::1 exempt range, BEP42 storage allowed).
fn v6_addr(port: u16) -> SocketAddr {
    SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::LOCALHOST,
        port,
        0,
        0,
    ))
}

/// Builds raw get_peers query bytes with a BEP32 want (a-dict key order
/// id < info_hash < want, canonical ascending; the sender id is always
/// the BEP5 example). An empty `want` slice = the key is omitted (the
/// no-want shape).
fn raw_want_get_peers(ih: &[u8; 20], want: &[&[u8]], tid: &[u8]) -> Vec<u8> {
    let mut wire = b"d1:ad2:id20:abcdefghij01234567899:info_hash20:".to_vec();
    wire.extend_from_slice(ih);
    if !want.is_empty() {
        wire.extend_from_slice(b"4:wantl");
        for w in want {
            wire.extend_from_slice(format!("{}:", w.len()).as_bytes());
            wire.extend_from_slice(w);
        }
        wire.push(b'e');
    }
    wire.extend_from_slice(b"e1:q9:get_peers1:t");
    wire.extend_from_slice(format!("{}:", tid.len()).as_bytes());
    wire.extend_from_slice(tid);
    wire.extend_from_slice(b"1:y1:qe");
    wire
}

/// Receives the raw wire bytes and decoded body of a Response to `to`
/// (maintenance outbound Queries do not participate in the assertion).
async fn recv_response_bytes_to(
    out_rx: &mut mpsc::Receiver<OutboundPacket>,
    to: SocketAddr,
    what: &str,
) -> (Vec<u8>, DhtMessage) {
    for _ in 0..64 {
        let pkt = chan(timeout(Duration::from_secs(5), out_rx.recv()).await, what);
        if pkt.to == to
            && let Ok(m @ DhtMessage::Response(_)) = decode_message(&pkt.data)
        {
            return (pkt.data.to_vec(), m);
        }
    }
    panic!("{what}: no response to {to}");
}

/// BEP32 want reply keys: get_peers with want=[n4,n6] → the reply carries
/// both nodes and nodes6 in one frame; want=[n6] (a v4 request) → only
/// nodes6; no want → the single key of the request family (v4, the
/// status-quo regression anchor). Text: "A reply should include a "nodes"
/// parameter if the request's "want" parameter contained the string
/// "n4", and should include a "nodes6" parameter if the request's "want"
/// parameter contained the string "n6""; "In the absence of a "want"
/// parameter, the reply should include "nodes" if the request was sent
/// over IPv4, and should include "nodes6" if the request was sent over
/// IPv6" (bittorrent.org/beps/bep_0032.html). Before the fix: the receive
/// side did not parse want — reply keys ignored the request; with mixed
/// v4/v6 in the table, pack_nodes raised MixedAddressFamilies and the
/// whole reply was suppressed (receive timeout).
#[tokio::test]
async fn bep32_want_governs_get_peers_reply_node_keys() {
    // Table seed: 2 v6 nodes (restore) + the v4 querier (enters via on_query)
    // → the nearest-K set is mixed-family, so want filtering is the sole
    // decider of the reply keys.
    let v6_nodes = vec![
        TableNode {
            id: NodeId([0x21; 20]),
            addr: v6_addr(6881),
            last_seen_ago_secs: 1,
        },
        TableNode {
            id: NodeId([0x22; 20]),
            addr: v6_addr(6882),
            last_seen_ago_secs: 1,
        },
    ];
    let restore = t(
        DhtRestoreState::from_state_row([0x3A; 20], &encode_table(&v6_nodes)),
        "restore",
    );
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, boundedness_cfg(), Some(restore));
    let from = public_addr(7200);
    let ih = [0x31; 20];

    // 1) want=[n4,n6] → dual keys: nodes = the querier (v4 subset), nodes6 =
    // the 2 restored v6 nodes.
    inject_raw(
        &in_tx,
        from,
        &raw_want_get_peers(&ih, &[b"n4", b"n6"], b"wa1"),
    )
    .await;
    let (wire, msg) = recv_response_bytes_to(&mut out_rx, from, "want n4+n6 reply").await;
    assert!(
        wire.windows(7).any(|w| w == *b"5:nodes"),
        "want containing n4 -> must reply under the nodes key: {wire:?}"
    );
    assert!(
        wire.windows(8).any(|w| w == *b"6:nodes6"),
        "want containing n6 -> must reply under the nodes6 key: {wire:?}"
    );
    match msg {
        DhtMessage::Response(r) => match r.body {
            ResponseBody::GetPeers { nodes, .. } => {
                assert_eq!(nodes.len(), 3, "dual keys merged in full (v4 1 + v6 2)");
                assert_eq!(nodes.iter().filter(|n| n.addr.is_ipv4()).count(), 1);
            }
            other => panic!("get_peers reply expected, got {other:?}"),
        },
        other => panic!("response expected, got {other:?}"),
    }

    // 2) want=[n6] (a v4 request) → only nodes6 (the v4 querier is filtered out).
    inject_raw(&in_tx, from, &raw_want_get_peers(&ih, &[b"n6"], b"wa2")).await;
    let (wire, msg) = recv_response_bytes_to(&mut out_rx, from, "want n6 reply").await;
    assert!(
        wire.windows(8).any(|w| w == *b"6:nodes6"),
        "want containing n6 -> must reply under the nodes6 key: {wire:?}"
    );
    assert!(
        !wire.windows(7).any(|w| w == *b"5:nodes"),
        "want without n4 -> must not reply under the nodes key: {wire:?}"
    );
    match msg {
        DhtMessage::Response(r) => match r.body {
            ResponseBody::GetPeers { nodes, .. } => {
                assert_eq!(nodes.len(), 2, "the v6 subset only");
                assert!(nodes.iter().all(|n| n.addr.is_ipv6()));
            }
            other => panic!("get_peers reply expected, got {other:?}"),
        },
        other => panic!("response expected, got {other:?}"),
    }

    // 3) No want → the single key of the request family (v4) (BEP32 "In the
    // absence of a "want" parameter..."; the aria2 single-family status quo
    // as regression anchor).
    inject_raw(&in_tx, from, &raw_want_get_peers(&ih, &[], b"wa3")).await;
    let (wire, msg) = recv_response_bytes_to(&mut out_rx, from, "no-want reply").await;
    assert!(
        wire.windows(7).any(|w| w == *b"5:nodes"),
        "no want -> the request family v4 -> the nodes key: {wire:?}"
    );
    assert!(
        !wire.windows(8).any(|w| w == *b"6:nodes6"),
        "no want -> must not reply under the nodes6 key: {wire:?}"
    );
    match msg {
        DhtMessage::Response(r) => match r.body {
            ResponseBody::GetPeers { nodes, .. } => {
                assert_eq!(nodes.len(), 1, "the v4 subset only (the querier itself)");
                assert!(nodes.iter().all(|n| n.addr.is_ipv4()));
            }
            other => panic!("get_peers reply expected, got {other:?}"),
        },
        other => panic!("response expected, got {other:?}"),
    }
    let _ = handle;
}

/// BEP32 1024B whole-frame gate: the **encoded whole frame** of a v6
/// large-values reply must be <= 1024B — "A node obeying this
/// specification must not send UDP datagrams with a payload larger than
/// 1024 octets" (fits the IPv6 minimum MTU of 1280 without fragments,
/// bep_0032.html). Before the fix: the gate counted only the values
/// compact bytes (<= 1400B), so 50 v6 values (900B compact) + nodes6 +
/// frame shell ≈ 1.2KB went out as-is.
#[tokio::test]
async fn get_peers_reply_frame_capped_at_bep32_1024_octets() {
    let (handle, _ev, mut out_rx, in_tx, _join) =
        spawn_channel_engine(DhtFamily::V6, 6881, boundedness_cfg(), None);
    let ih = [0x97; 20];
    // A ::1 exempt source (BEP42 storage allowed; a v6 request → 18B value
    // units — the values family always follows the request's network layer
    // (BEP32), regardless of want).
    let bot = v6_addr(9);
    let flood: u16 = 700;

    // 1) Fetch a token.
    inject_query(
        &in_tx,
        bot,
        NodeId([0xB2; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let token = match recv_response_with_len(&mut out_rx, "token reply")
        .await
        .1
        .body
    {
        ResponseBody::GetPeers { token, .. } => token,
        other => panic!("get_peers reply expected, got {other:?}"),
    };

    // 2) Flood per-port announces (the 500 per-key cap >> the 50 reply cap).
    for port in 1000..1000 + flood {
        inject_query(
            &in_tx,
            bot,
            NodeId([0xB2; 20]),
            QueryBody::AnnouncePeer {
                info_hash: NodeId(ih),
                port,
                token: token.clone(),
                implied_port: None,
            },
        )
        .await;
        let _ = recv_response_with_len(&mut out_rx, "announce ack").await;
    }

    // 3) A small get_peers → the whole reply frame is <= 1024B and keeps the
    // token (the announce precondition must not be emptied).
    inject_query(
        &in_tx,
        bot,
        NodeId([0xB3; 20]),
        QueryBody::GetPeers {
            info_hash: NodeId(ih),
            want: WantFamilies::default(),
        },
    )
    .await;
    let (wire_len, reply) = recv_response_with_len(&mut out_rx, "capped reply").await;
    assert!(
        wire_len <= 1024,
        "BEP32: the whole frame must not exceed 1024 octets (got {wire_len}B)"
    );
    match reply.body {
        ResponseBody::GetPeers { token, values, .. } => {
            assert!(
                !token.is_empty(),
                "the token is kept (the announce precondition, the legal-shape lower bound)"
            );
            assert!(
                !values.is_empty(),
                "gate trimming must not empty out all values"
            );
            assert!(
                values.iter().all(|a| a.is_ipv6()),
                "values follow the request face's single family"
            );
        }
        other => panic!("get_peers reply expected, got {other:?}"),
    }

    // 4) The truncation counter is recorded (selection truncation + whole
    // frame clipping together >= the selection-truncation floor).
    let snap = call("snapshot after v6 flood", handle.snapshot()).await;
    assert!(
        snap.values_truncated_total >= (MAX_PEER_RECORDS_PER_KEY - MAX_VALUES_PER_REPLY) as u64,
        "the truncation counter must be on record (got {})",
        snap.values_truncated_total
    );
}

/// BEP32 want outbound: the find_node/get_peers outbound queries of
/// bootstrap/refresh/peer lookups must carry want=[n4,n6] — "The "want"
/// parameter is allowed in the find_nodes and get_peers requests"
/// (bep_0032.html); a dual-stack peer returns both families in one frame,
/// letting this node learn the other family through either route (the
/// fast path for a v6 table to bootstrap via v4 routes). Before the fix:
/// outbound queries carried no want key.
#[tokio::test]
async fn outbound_lookup_queries_carry_want_both_families() {
    // Restore 1 v4 node → the forced refresh dispatches find_node outbound
    // (DHTSetup.cc).
    let nodes = vec![TableNode {
        id: NodeId([0x41; 20]),
        addr: v4_addr(6901),
        last_seen_ago_secs: 1,
    }];
    let restore = t(
        DhtRestoreState::from_state_row([0x3B; 20], &encode_table(&nodes)),
        "restore",
    );
    let (handle, _ev, mut out_rx, _in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, boundedness_cfg(), Some(restore));
    // peer lookup (the get_peers face).
    call(
        "announce",
        handle.announce(target_of([0x52; 20], DhtSwarmKind::V1), 6881),
    )
    .await;

    let needle: &[u8] = b"4:wantl2:n42:n6e";
    let mut saw_find_node = false;
    let mut saw_get_peers = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !(saw_find_node && saw_get_peers) {
        assert!(
            std::time::Instant::now() < deadline,
            "timeout collecting lookup queries (find_node={saw_find_node}, get_peers={saw_get_peers})"
        );
        let pkt = chan(
            timeout(Duration::from_secs(5), out_rx.recv()).await,
            "outbound query",
        );
        let Ok(DhtMessage::Query(q)) = decode_message(&pkt.data) else {
            continue;
        };
        let is_find_node = matches!(q.body, QueryBody::FindNode { .. });
        let is_get_peers = matches!(q.body, QueryBody::GetPeers { .. });
        if !is_find_node && !is_get_peers {
            continue;
        }
        assert!(
            pkt.data.windows(needle.len()).any(|w| w == needle),
            "outbound find_node/get_peers must carry want=[n4,n6]: {:?}",
            pkt.data
        );
        saw_find_node |= is_find_node;
        saw_get_peers |= is_get_peers;
    }
    assert!(saw_find_node, "find_node (refresh dispatch) must appear");
    assert!(saw_get_peers, "get_peers (announce lookup) must appear");
}

/// Foreign-family candidate filtering: v6 nodes learned inside a v4
/// engine's table via want=[n4,n6] replies are **never query candidates**
/// (this engine is single-stack outbound: a v4-bound socket cannot send
/// v6 packets, and trying would just dead-wait on a doomed transaction);
/// the nodes stay in the table for the reply side's want dual-key
/// advertisement (see
/// `bep32_want_governs_get_peers_reply_node_keys`). Shape: a v6-only
/// restore into a v4 engine → forced refresh dispatches a lookup → all
/// candidates are foreign-family → zero outbound and the task completes
/// immediately.
#[tokio::test]
async fn foreign_family_candidates_are_not_queried() {
    let v6_nodes = vec![
        TableNode {
            id: NodeId([0x51; 20]),
            addr: v6_addr(6951),
            last_seen_ago_secs: 1,
        },
        TableNode {
            id: NodeId([0x52; 20]),
            addr: v6_addr(6952),
            last_seen_ago_secs: 1,
        },
    ];
    let restore = t(
        DhtRestoreState::from_state_row([0x3C; 20], &encode_table(&v6_nodes)),
        "restore",
    );
    let (handle, _ev, mut out_rx, _in_tx, _join) =
        spawn_channel_engine(DhtFamily::V4, 6881, boundedness_cfg(), Some(restore));
    // Quiet assertion: no queries to the v6 nodes at all (frozen maintenance
    // leaves no other outbound source).
    assert_quiet(
        &mut out_rx,
        400,
        "foreign-family candidates must not go outbound",
    )
    .await;
    // The task must not wedge on foreign-family candidates (after filtering
    // them out the lookup completes immediately).
    wait_snapshot(&handle, 2_000, |s| {
        s.periodic_executing == 0 && s.periodic_waiting == 0 && s.transactions == 0
    })
    .await;
    // The v6 nodes stay in the table (reply-side advertisement material, not filtered out).
    let snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(
        snap.num_nodes, 2,
        "foreign-family nodes stay in the table (advertisement material)"
    );
}

// ===== Inbound batch drain beyond one 64-packet batch =====

/// Per-iteration inbound drain cap of the run loop (`run::INBOUND_BATCH_MAX`,
/// the hot-path batch amortization constant; not exported — pinned here by
/// value).
/// The phase arithmetic of the fairness test below derives from it; changing
/// the cap must re-derive the test.
const TEST_INBOUND_BATCH_MAX: usize = 64;

/// Production-shaped channel engine for the batch-drain tests: the inbound
/// channel mirrors the demux dht-channel capacity (1024,
/// `taiji-io/src/udp_demux.rs`) so a >=130-packet flood queues without loss;
/// the outbound capacity is caller-chosen (the fairness test drives the
/// engine's position through outbound-channel backpressure — the reply path
/// is `send().await`, so a full channel parks the engine mid-batch).
fn spawn_batch_drain_engine(
    cfg: DhtEngineConfig,
    outbound_cap: usize,
) -> (
    DhtHandle,
    mpsc::Receiver<DhtEvent>,
    mpsc::Receiver<OutboundPacket>,
    mpsc::Sender<InboundPacket>,
    tokio::task::JoinHandle<()>,
) {
    let (in_tx, in_rx) = mpsc::channel(1024);
    let (out_tx, out_rx) = mpsc::channel(outbound_cap);
    let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (handle, join) = spawn(
        DhtFamily::V4,
        6881,
        cfg,
        DhtTransport {
            inbound: in_rx,
            outbound: out_tx,
        },
        None,
        event_tx,
    );
    (handle, event_rx, out_rx, in_tx, join)
}

/// 2-byte big-endian transaction id carrying the injection index (echoed
/// verbatim by the ping reply — the order reference of the drain tests).
fn batch_tid(i: usize) -> [u8; 2] {
    [(i >> 8) as u8, i as u8]
}

/// Flood source `i`: one query per distinct IP — the per-source query limiter
/// is IP-keyed, so one query per source never trips the 25pps/50burst bucket
/// and every injected ping is answered.
fn batch_src(i: usize) -> SocketAddr {
    test_net_addr((i + 1) as u8, 6881)
}

/// Every queued packet reaches the processing
/// plane: 130 inbound packets queued at once (> 2 x 64, i.e. the drain spans
/// >= 3 loop iterations) are all accounted. `inbound_packets_total` counts
/// every datagram at `handle_packet` entry and `inbound_queries_total`
/// every decoded query *before* the per-source limiter, so even the
/// over-burst queries silently dropped by the limiter must show up: the
/// multi-batch drain loses nothing between the channel and the processing
/// plane.
#[tokio::test]
async fn batch_drain_130_queued_packets_all_reach_processing_plane() {
    const N: usize = 130;
    let (handle, _ev, _out_rx, in_tx, _join) =
        spawn_batch_drain_engine(DhtEngineConfig::default(), 256);
    // One source, plain pings: burst 50 admitted, the remainder silently
    // dropped by the per-source limiter — arrival accounting must be
    // unaffected either way.
    let src = test_net_addr(200, 6881);
    for _ in 0..N {
        inject_raw(&in_tx, src, &raw_query(b"ping", b"zz")).await;
    }
    wait_snapshot(&handle, 5_000, |s| {
        s.inbound_packets_total == N as u64 && s.inbound_queries_total == N as u64
    })
    .await;
}

/// Batch-drain assertion 2 — packet order is unchanged across batches: 130
/// ping queries queued at once (>= 3 drain batches) are answered strictly in
/// injection order. Each reply echoes the query's tid (the injection index)
/// and is sent inline by the handling batch, so the outbound stream order is
/// exactly the per-batch processing order across the batch boundaries.
#[tokio::test]
async fn batch_drain_130_queued_packets_preserve_fifo_order_across_batches() {
    const N: usize = 130;
    let (_handle, _ev, mut out_rx, in_tx, _join) =
        spawn_batch_drain_engine(DhtEngineConfig::default(), 256);
    for i in 0..N {
        inject_raw(&in_tx, batch_src(i), &raw_query(b"ping", &batch_tid(i))).await;
    }
    for i in 0..N {
        let (to, msg) = recv_packet(&mut out_rx).await;
        assert_eq!(
            to,
            batch_src(i),
            "reply targets must follow injection order (#{i})"
        );
        match msg {
            DhtMessage::Response(r) => assert_eq!(
                r.transaction_id,
                batch_tid(i).to_vec(),
                "tid echoes must keep injection order (#{i})"
            ),
            other => panic!("expected a ping reply, got {other:?} (#{i})"),
        }
    }
    // Exactly N replies, nothing extra (default config: no maintenance
    // outbound within 5min).
    assert_quiet(&mut out_rx, 150, "no replies beyond the N").await;
}

/// Batch-drain assertion 3 — the tick and command faces are scheduled
/// between batches: with 130 packets queued (> 2 batches) and the engine
/// parked MID-BATCH on outbound backpressure (capacity 8), the loop-top
/// faces run between batch 1 and batch 2, observed deterministically via
/// the autosave timer (`DhtEvent::Persist` fires at a loop top only):
///
/// - phase 1 releases exactly 64-8 reply slots, so batch 1 (64 packets)
/// just completes and the due autosave fires strictly between reply 64
/// and reply 65 — a drain-until-empty regression would keep the engine
/// inside one mega-batch, the persist would never arrive and the poll
/// below would time out;
/// - phase 2 enqueues a Snapshot command while the engine is parked inside
/// batch 2 (reply 65 unsent, 66 packets still queued): it is serviced at
/// a batch-boundary select, pinning the snapshot's `inbound_packets_total`
/// to [2 x 64, 130] — command service never waits for the full drain
/// beyond the batch boundaries.
#[tokio::test]
async fn batch_drain_schedules_tick_and_command_faces_between_batches() {
    const N: usize = 130;
    const OUT_CAP: usize = 8;
    let cfg = DhtEngineConfig {
        autosave_interval: Duration::from_millis(30),
        ..DhtEngineConfig::default()
    };
    let (handle, mut ev_rx, mut out_rx, in_tx, _join) = spawn_batch_drain_engine(cfg, OUT_CAP);

    // Baseline snapshot synchronizes the engine to a select-parked idle
    // state (no packet or command in flight; autosave not yet due at 30ms).
    let base = call("snapshot", handle.snapshot()).await;
    assert_eq!(
        base.inbound_packets_total, 0,
        "no inbound packets before the baseline"
    );

    // Queue the flood: batch 1 runs until OUT_CAP ping replies fill the
    // outbound channel; the engine parks inside batch 1 at the next reply
    // send (the outbound backpressure is the drain valve).
    for i in 0..N {
        inject_raw(&in_tx, batch_src(i), &raw_query(b"ping", &batch_tid(i))).await;
    }
    // While parked, the autosave deadline (30ms) lapses.
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Phase 1: release exactly TEST_INBOUND_BATCH_MAX - OUT_CAP replies;
    // the engine advances one query per released slot and completes batch 1
    // (queries 1..=64) on the last one (sends = OUT_CAP + released).
    let mut received: usize = 0;
    while received < TEST_INBOUND_BATCH_MAX - OUT_CAP {
        let _ = recv_packet(&mut out_rx).await;
        received += 1;
    }

    // Loop top between batch 1 and batch 2: the due autosave fires and the
    // Persist event is emitted strictly between reply 64 and reply 65
    // (reply 65's send is still blocked — the channel is full again). Skip
    // any hypothetical pre-injection persist (empty routing table: nothing
    // was handled yet); the between-batches persist carries the contacted
    // node.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut persist_seen = false;
    while !persist_seen {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !remain.is_zero(),
            "autosave must fire at a between-batches loop top (after batch 1 completes, before reply 65)"
        );
        match chan(
            timeout(remain, ev_rx.recv()).await,
            "the between-batches autosave Persist event",
        ) {
            DhtEvent::Persist { routing_table, .. } => {
                let nodes = t(decode_table(&routing_table), "persist table decode");
                persist_seen = !nodes.is_empty();
            }
            other => panic!("expected a Persist event, got {other:?}"),
        }
    }

    // Phase 2: enqueue the Snapshot command while the engine is parked
    // inside batch 2 (reply 65 unsent; 66 packets still queued). The spawn
    // polls the call, so the command enters the channel during the drain.
    let snap_handle = handle.clone();
    let snap_task = tokio::spawn(async move { call("snapshot", snap_handle.snapshot()).await });

    // Phase 3: release the rest — batches 2 (65..=128) and 3 (129..=130)
    // drain and the engine services the Snapshot command at a
    // batch-boundary select.
    while received < N {
        let _ = recv_packet(&mut out_rx).await;
        received += 1;
    }
    assert_eq!(received, N, "exactly one reply per each of the 130 queries");

    let snap = t(
        t(
            timeout(Duration::from_secs(10), snap_task).await,
            "the Snapshot command must be serviced during the drain",
        ),
        "snapshot join",
    );
    // The command was enqueued while the engine was inside batch 2, so it
    // cannot be serviced before the post-batch-2 select (>= 128 handled)
    // and the counter cannot exceed the flood (130): the service point is
    // a batch boundary, not the post-drain floor.
    assert!(
        snap.inbound_packets_total >= (2 * TEST_INBOUND_BATCH_MAX) as u64
            && snap.inbound_packets_total <= N as u64,
        "the Snapshot service point must be pinned at a between-batch select (128..=130), got {}",
        snap.inbound_packets_total
    );
    // The full drain completed afterwards: every queued packet was handled.
    let final_snap = call("snapshot", handle.snapshot()).await;
    assert_eq!(
        final_snap.inbound_packets_total, N as u64,
        "after the multi-batch drain all 130 packets must reach the handling face"
    );
}

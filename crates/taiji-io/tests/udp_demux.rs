//! Integration tests: UdpDemux (contract).
//!
//! Covers: concurrent three-channel dispatch (duplex), queue-full drop with
//! observable counting, outbound single-writer roundtrip, shutdown
//! propagation (1s budget), v4/v6 dual instances (v6 skips conditionally
//! where no IPv6 loopback exists — see the in-test notes), and the
//! `--listen-port` port semantics.
//!
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use taiji_io::udp_demux::{
    DemuxClass, DemuxConfig, DemuxStatsSnapshot, LISTEN_PORT_MAX, LISTEN_PORT_MIN, classify, spawn,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// BEP-5 "KRPC" ping query example, verbatim (DHT class).
fn ping_query() -> &'static [u8] {
    b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
}

/// BEP-15 connect request: magic (UDPTrackerClient.h) + action=0 + transaction_id.
fn tracker_connect_request() -> Vec<u8> {
    let mut v = [0x00u8, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80].to_vec();
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0x1234u32.to_be_bytes());
    v
}

/// 20B uTP ST_SYN header (BEP-29: b0 = type(4)<<4 | ver(1); remaining fields zero-filled).
fn utp_syn() -> Vec<u8> {
    let mut v = vec![0x41u8, 0x00];
    v.extend_from_slice(&[0u8; 18]);
    v
}

/// Test failure exit (unwrap/expect are banned: workspace clippy `-D warnings`).
fn fail<T: std::fmt::Debug>(ctx: &str, e: T) -> ! {
    panic!("{ctx}: {e:?}")
}

/// Loopback client socket (same family as the instance under test).
async fn client_socket(family_hint: &str) -> UdpSocket {
    let bind: SocketAddr = if family_hint.contains(':') {
        format!("[{family_hint}]:0")
            .parse()
            .unwrap_or_else(|e| fail("v6 client addr", e))
    } else {
        format!("{family_hint}:0")
            .parse()
            .unwrap_or_else(|e| fail("v4 client addr", e))
    };
    UdpSocket::bind(bind)
        .await
        .unwrap_or_else(|e| fail("client bind", e))
}

/// Concurrent three-channel dispatch: each class's sample packet reaches
/// its consumer with byte-identical source address and payload, and the
/// forward counters are observable in step.
#[tokio::test]
async fn three_consumers_receive_by_class() {
    let shutdown = CancellationToken::new();
    let (mut chans, handle) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn demux", e));

    let demux_addr = handle.bound_addr();
    assert!(
        demux_addr.is_ipv4(),
        "an explicit v4 bind address must stay v4: {demux_addr}"
    );
    let client = client_socket("127.0.0.1").await;
    let client_addr = client
        .local_addr()
        .unwrap_or_else(|e| fail("local addr", e));

    // Three class samples sent back-to-back (before consumers read:
    // exercises channel buffering + concurrent dispatch).
    client
        .send_to(ping_query(), demux_addr)
        .await
        .unwrap_or_else(|e| fail("send dht", e));
    client
        .send_to(&tracker_connect_request(), demux_addr)
        .await
        .unwrap_or_else(|e| fail("send tracker", e));
    client
        .send_to(&utp_syn(), demux_addr)
        .await
        .unwrap_or_else(|e| fail("send utp", e));

    let dht_pkt = timeout(RECV_TIMEOUT, chans.dht.recv())
        .await
        .unwrap_or_else(|e| fail("dht recv timeout", e))
        .unwrap_or_else(|| panic!("dht channel closed"));
    let tracker_pkt = timeout(RECV_TIMEOUT, chans.tracker.recv())
        .await
        .unwrap_or_else(|e| fail("tracker recv timeout", e))
        .unwrap_or_else(|| panic!("tracker channel closed"));
    let utp_pkt = timeout(RECV_TIMEOUT, chans.utp.recv())
        .await
        .unwrap_or_else(|e| fail("utp recv timeout", e))
        .unwrap_or_else(|| panic!("utp channel closed"));

    assert_eq!(
        dht_pkt.data.as_ref(),
        ping_query(),
        "DHT payload byte-for-byte identical"
    );
    assert_eq!(dht_pkt.from, client_addr, "DHT source address");
    assert_eq!(
        tracker_pkt.data,
        tracker_connect_request(),
        "tracker payload"
    );
    assert_eq!(tracker_pkt.from, client_addr);
    assert_eq!(utp_pkt.data, utp_syn(), "uTP payload");
    assert_eq!(utp_pkt.from, client_addr);

    let s: DemuxStatsSnapshot = handle.stats();
    assert_eq!(
        s,
        DemuxStatsSnapshot {
            received: 3,
            forwarded_dht: 1,
            forwarded_tracker: 1,
            forwarded_utp: 1,
            outbound_sent: 0,
            ..DemuxStatsSnapshot::default()
        },
        "three-channel counts consistent with the inbound total"
    );

    shutdown.cancel();
}

/// Queue-full drop + observable counting (back-pressure policy: a failed
/// try_send on a full queue drops). Capacity squeezed to 1 (not the contract
/// default; test-only path).
#[tokio::test]
async fn queue_full_drop_is_counted() {
    let shutdown = CancellationToken::new();
    let config = DemuxConfig {
        dht_capacity: 1,
        ..DemuxConfig::default()
    };
    let (mut chans, handle) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        config,
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn demux", e));

    let demux_addr = handle.bound_addr();
    let client = client_socket("127.0.0.1").await;

    // Never drain the dht channel; send packet by packet with gaps so the
    // demux loop keeps up (avoids OS-buffer noise).
    for _ in 0..8 {
        client
            .send_to(ping_query(), demux_addr)
            .await
            .unwrap_or_else(|e| fail("send dht", e));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Let the demux loop finish the last packet.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let s = handle.stats();
    assert_eq!(s.received, 8, "all 8 inbound packets received");
    assert_eq!(
        s.forwarded_dht, 1,
        "capacity 1: only the first packet enqueued"
    );
    assert_eq!(
        s.dropped_dht_full, 7,
        "the other 7 packets dropped on a full queue and counted"
    );
    assert_eq!(s.dropped_classify, 0);
    assert_eq!(s.forwarded_tracker, 0);
    assert_eq!(s.forwarded_utp, 0);

    // Only the first packet remains in the channel; drops do not disturb later consumption.
    let pkt = timeout(RECV_TIMEOUT, chans.dht.recv())
        .await
        .unwrap_or_else(|e| fail("dht recv timeout", e))
        .unwrap_or_else(|| panic!("dht channel closed"));
    assert_eq!(pkt.data.as_ref(), ping_query());
    shutdown.cancel();
}

/// Outbound single-writer roundtrip: handle enqueue -> the demux task's
/// single-writer send_to -> the client receives.
#[tokio::test]
async fn outbound_single_writer_roundtrip() {
    let shutdown = CancellationToken::new();
    let (chans, handle) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn demux", e));

    let client = client_socket("127.0.0.1").await;
    let client_addr = client
        .local_addr()
        .unwrap_or_else(|e| fail("local addr", e));

    let payload = Bytes::from_static(b"pong");
    handle
        .send_packet(client_addr, payload.clone())
        .await
        .unwrap_or_else(|e| fail("outbound send", e));

    let mut buf = [0u8; 64];
    let (n, from) = timeout(RECV_TIMEOUT, client.recv_from(&mut buf))
        .await
        .unwrap_or_else(|e| fail("client recv timeout", e))
        .unwrap_or_else(|e| fail("client recv", e));
    assert_eq!(
        &buf[..n],
        payload.as_ref(),
        "outbound payload round-trips intact"
    );
    assert_eq!(
        from,
        handle.bound_addr(),
        "outbound source address = the demux bind address"
    );

    let s = handle.stats();
    assert_eq!(s.outbound_sent, 1);
    assert_eq!(s.outbound_errors, 0);

    drop(chans);
    shutdown.cancel();
}

/// shutdown propagation: cancelling the token stops the demux task at once
/// (well under the 1s budget); the three channel senders close with the
/// task, so consumers observe channel shutdown.
#[tokio::test]
async fn shutdown_propagates_within_budget() {
    let shutdown = CancellationToken::new();
    let (mut chans, handle) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn demux", e));

    let start = Instant::now();
    shutdown.cancel();
    let budget = Duration::from_secs(1);

    let dht_closed = timeout(budget, async {
        chans.dht.recv().await;
    })
    .await;
    let tracker_closed = timeout(budget, async {
        chans.tracker.recv().await;
    })
    .await;
    let utp_closed = timeout(budget, async {
        chans.utp.recv().await;
    })
    .await;

    assert!(
        dht_closed.is_ok() && tracker_closed.is_ok() && utp_closed.is_ok(),
        "all three channels must close after shutdown"
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "shutdown budget 1s (measured {:?})",
        start.elapsed()
    );

    // After the task exits the outbound channel closes: send_packet returns OutboundClosed.
    drop(chans);
    let err = handle
        .send_packet(
            "127.0.0.1:9".parse().unwrap_or_else(|e| fail("addr", e)),
            Bytes::from_static(b"x"),
        )
        .await;
    assert!(
        err.is_err(),
        "outbound sends must fail after the demux exits"
    );
}

/// Handle RAII: dropping the last handle (without an explicit shutdown) also stops the task.
#[tokio::test]
async fn dropping_handle_stops_task() {
    let shutdown = CancellationToken::new();
    let (mut chans, handle) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown,
    )
    .await
    .unwrap_or_else(|e| fail("spawn demux", e));

    drop(handle);
    let closed = timeout(Duration::from_secs(1), async {
        chans.dht.recv().await;
        chans.tracker.recv().await;
        chans.utp.recv().await;
    })
    .await;
    assert!(
        closed.is_ok(),
        "channels must close once every handle is dropped (RAII exit)"
    );
}

/// IPv6 instance: a separate demux exercised end to end.
///
/// Conditional skip: in container/CI environments without an IPv6 loopback
/// (`::1` cannot bind) the test cannot run; it prints the reason and returns.
#[tokio::test]
async fn ipv6_instance_conditional() {
    let v6_available = std::net::UdpSocket::bind("[::1]:0").is_ok();
    if !v6_available {
        eprintln!("skip ipv6_instance_conditional: ::1 loopback unavailable (no IPv6 environment)");
        return;
    }

    let shutdown = CancellationToken::new();
    let (mut chans, handle) = spawn(
        "::1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn v6 demux", e));

    let demux_addr = handle.bound_addr();
    assert!(
        demux_addr.is_ipv6(),
        "the v6 bind address must stay v6: {demux_addr}"
    );
    let client = client_socket("::1").await;
    let client_addr = client
        .local_addr()
        .unwrap_or_else(|e| fail("local addr", e));

    client
        .send_to(ping_query(), demux_addr)
        .await
        .unwrap_or_else(|e| fail("send v6", e));
    client
        .send_to(&utp_syn(), demux_addr)
        .await
        .unwrap_or_else(|e| fail("send v6 utp", e));

    let dht_pkt = timeout(RECV_TIMEOUT, chans.dht.recv())
        .await
        .unwrap_or_else(|e| fail("v6 dht recv timeout", e))
        .unwrap_or_else(|| panic!("v6 dht channel closed"));
    assert_eq!(dht_pkt.data.as_ref(), ping_query());
    assert_eq!(dht_pkt.from, client_addr);
    let utp_pkt = timeout(RECV_TIMEOUT, chans.utp.recv())
        .await
        .unwrap_or_else(|e| fail("v6 utp recv timeout", e))
        .unwrap_or_else(|| panic!("v6 utp channel closed"));
    assert_eq!(utp_pkt.data, utp_syn());

    shutdown.cancel();
}

/// `--listen-port` semantics: port=0 -> random start inside the default
/// 6881-6999 range; an explicit port binds exactly; an occupied port
/// reports AddrInUse.
#[tokio::test]
async fn listen_port_semantics() {
    let shutdown = CancellationToken::new();
    // Two port=0 instances: each lands in range without collision (random
    // start + sequential probing).
    let (chans_a, handle_a) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn a", e));
    let (chans_b, handle_b) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn b", e));

    let port_a = handle_a.bound_addr().port();
    let port_b = handle_b.bound_addr().port();
    assert!(
        (LISTEN_PORT_MIN..=LISTEN_PORT_MAX).contains(&port_a),
        "port_a={port_a} must be within 6881-6999"
    );
    assert!(
        (LISTEN_PORT_MIN..=LISTEN_PORT_MAX).contains(&port_b),
        "port_b={port_b} must be within 6881-6999"
    );
    assert_ne!(
        port_a, port_b,
        "the two instances must not bind the same port"
    );

    // Explicit port binds exactly (a fixed value outside the scan range, so
    // it does not race the port=0 scans of other cases).
    let (chans_c, handle_c) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig {
            port: 16980,
            ..DemuxConfig::default()
        },
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn c", e));
    assert_eq!(
        handle_c.bound_addr().port(),
        16980,
        "an explicit port binds exactly"
    );

    // Occupied explicit port -> AddrInUse surfaces.
    let occupied = std::net::UdpSocket::bind(SocketAddr::new(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        16979,
    ))
    .unwrap_or_else(|e| fail("occupy port", e));
    let clash = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig {
            port: 16979,
            ..DemuxConfig::default()
        },
        shutdown.clone(),
    )
    .await;
    match clash {
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::AddrInUse,
            "an occupied port must report AddrInUse"
        ),
        Ok(_) => panic!("binding an occupied port should fail"),
    }
    drop(occupied);

    drop((chans_a, chans_b, chans_c, handle_a, handle_b, handle_c));
    shutdown.cancel();
}

/// Consistency spot-check between classifier and live instance: packets
/// arriving over a real socket dispatch per classify (rule-5 drops are
/// observable).
#[tokio::test]
async fn unclassifiable_packets_are_counted() {
    let shutdown = CancellationToken::new();
    let (chans, handle) = spawn(
        "127.0.0.1".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn demux", e));
    let demux_addr = handle.bound_addr();
    let client = client_socket("127.0.0.1").await;

    client
        .send_to(&[0xffu8, 0x00, 0x01, 0x02], demux_addr)
        .await
        .unwrap_or_else(|e| fail("send garbage", e));
    client
        .send_to(&[0x02u8], demux_addr)
        .await
        .unwrap_or_else(|e| fail("send ver2", e));
    assert_eq!(classify(&[0xffu8, 0x00, 0x01, 0x02]), DemuxClass::Drop);
    assert_eq!(classify(&[0x02u8]), DemuxClass::Drop);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let s = handle.stats();
    assert_eq!(s.received, 2);
    assert_eq!(s.dropped_classify, 2, "rule-5 drop count");
    assert_eq!(s.forwarded_dht + s.forwarded_tracker + s.forwarded_utp, 0);

    drop(chans);
    shutdown.cancel();
}

// ---- v6 face V6ONLY (set at the socket2 creation point, before bind) ----
//
// Authoritative source: Linux ipv6(7) `bindv6only` defaults to 0 (a bare
// [::] socket is dual-stack and mutually exclusive with 0.0.0.0 on the same
// port); macOS/Windows default to V6ONLY=1. The behavior assertions have
// their discriminating power on Linux; the explicit-set semantics are pinned
// by the src unit test only_v6() reading it back. Upstream anchor: aria2
// `SocketCore.cc` (sets IPV6_V6ONLY=1 before ::bind for AF_INET6).

/// Behavior assertion: the v6 face and the v4 face coexist on the same port.
///
/// On Linux without V6ONLY, whichever side binds first makes the other fail
/// with EADDRINUSE (the v6 face could never bind); with V6ONLY each family
/// holds its own wildcard slot and both faces assemble on one port (the
/// core `spawn_udp_face` one-socket-per-family shape, dht.rs).
///
/// Conditional skip matches the existing tests: container/CI without IPv6
/// cannot bind `::1`; print the reason and return.
#[tokio::test]
async fn v6_v6only_allows_v4_same_port_coexist() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!(
            "skip v6_v6only_allows_v4_same_port_coexist: ::1 unavailable (no IPv6 environment)"
        );
        return;
    }
    let shutdown = CancellationToken::new();
    // The v6 face binds first (v6-first is the order that reproduces the
    // historical Linux conflict; with V6ONLY the families never overlap, so
    // the assembly order does not matter).
    let (v6_chans, v6_handle) = spawn(
        "::".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig {
            port: 16977,
            ..DemuxConfig::default()
        },
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn v6 face", e));
    let v6_addr = v6_handle.bound_addr();
    assert_eq!(v6_addr.port(), 16977, "the v6 explicit port binds exactly");
    assert!(
        v6_addr.is_ipv6(),
        "the v6 face bind address stays v6: {v6_addr}"
    );

    // Same-port v4 face: EADDRINUSE on dual-stack-overlap Linux; with V6ONLY they coexist.
    let (v4_chans, v4_handle) = spawn(
        "0.0.0.0".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig {
            port: 16977,
            ..DemuxConfig::default()
        },
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn v4 face same port as v6", e));
    assert_eq!(v4_handle.bound_addr().port(), 16977);
    assert!(
        v4_handle.bound_addr().is_ipv4(),
        "the v4 face bind address stays v4: {}",
        v4_handle.bound_addr()
    );

    drop((v6_chans, v4_chans, v6_handle, v4_handle));
    shutdown.cancel();
}

/// The v6 `port == 0` random-scan path works end to end (through the
/// socket2 v6 creation point; AddrInUse -> continue, same path as v4), and
/// the landed port is within 6881-6999. Skip rules as above.
#[tokio::test]
async fn v6_port_zero_scan_binds_in_range() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("skip v6_port_zero_scan_binds_in_range: ::1 unavailable (no IPv6 environment)");
        return;
    }
    let shutdown = CancellationToken::new();
    let (chans, handle) = spawn(
        "::".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig::default(),
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("spawn v6 port=0 scan", e));
    let addr = handle.bound_addr();
    assert!(addr.is_ipv6(), "the scan landing point stays v6: {addr}");
    assert!(
        (LISTEN_PORT_MIN..=LISTEN_PORT_MAX).contains(&addr.port()),
        "the v6 port=0 scan landing point {addr} must be within {LISTEN_PORT_MIN}-{LISTEN_PORT_MAX}"
    );
    drop(chans);
    shutdown.cancel();
}

/// Occupied-port simulation: a taken v6 explicit port still reports
/// AddrInUse (the degrade path's input surface is unchanged: core
/// `spawn_udp_face` drops the v6 face on this Err and degrades to v4);
/// after release the rebind succeeds (the failure was purely the occupied
/// port, not a creation-point regression).
///
/// The occupier is a bare std v6 socket: on Linux std [::] is exactly
/// dual-stack (the production conflict shape), which stays mutually
/// exclusive with a V6ONLY v6 socket -> AddrInUse, consistent across
/// families. Skip rules as above.
#[tokio::test]
async fn v6_explicit_port_in_use_reports_addrinuse() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!(
            "skip v6_explicit_port_in_use_reports_addrinuse: ::1 unavailable (no IPv6 environment)"
        );
        return;
    }
    let occupied = std::net::UdpSocket::bind(SocketAddr::new(
        "::".parse().unwrap_or_else(|e| fail("addr", e)),
        16976,
    ))
    .unwrap_or_else(|e| fail("occupy v6 port", e));
    let shutdown = CancellationToken::new();
    let clash = spawn(
        "::".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig {
            port: 16976,
            ..DemuxConfig::default()
        },
        shutdown.clone(),
    )
    .await;
    match clash {
        Err(e) => assert_eq!(
            e.kind(),
            io::ErrorKind::AddrInUse,
            "an occupied v6 port must report AddrInUse (the core degrade path's input surface unchanged)"
        ),
        Ok(_) => panic!("binding an occupied v6 port should fail"),
    }
    drop(occupied);

    // Rebind after release succeeds: the error was purely the occupied
    // port (the v6 creation point is healthy).
    let (chans, handle) = spawn(
        "::".parse().unwrap_or_else(|e| fail("addr", e)),
        DemuxConfig {
            port: 16976,
            ..DemuxConfig::default()
        },
        shutdown.clone(),
    )
    .await
    .unwrap_or_else(|e| fail("v6 rebind after release", e));
    assert_eq!(handle.bound_addr().port(), 16976);
    drop(chans);
    shutdown.cancel();
}

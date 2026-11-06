//! ut_holepunch three-party duplex integration tests.
//!
//! # NAT emulation contract (implemented by the test harness)
//!
//! The duplex channels only allow a direct connection when both sides
//! dial outward at the same time ([`FakeNat`]): a one-sided dial only
//! registers an intent; if the other side does not answer, the intent is
//! withdrawn = the direct connection is refused. Only simultaneous
//! registration on both sides (simultaneous dial) creates a new duplex
//! and completes the BT handshake + PeerTask attach — the essence of a
//! real NAT's simultaneous open. No listener exists behind A/C's public
//! mapping addresses (203.0.113.x, TEST-NET documentation ranges, tests
//! never leave the machine), so a one-way dial is structurally
//! impossible.
//!
//! # Harness wiring
//!
//! A<->B1 and C<->B2 are real PeerTask<->PeerTask direct connections
//! ([`wire_leg`]: two duplex halves joined by frame-level bidirectional
//! forwarding tasks; `LegEnd::seen` mirrors every frame the peer task on
//! that end emits, `LegEnd::inj` = the test plays the engine and injects
//! the peer handshake). All protocol data-plane frames are sent and
//! received by real PeerTasks; the test only plays the engine role
//! (bookkeeping + decisions + commands), isomorphic to the production
//! assembly.
//!
//! Full chain: A's direct dial to C fails (NAT) -> rendezvous to B via
//! the introducer bookkeeping (real wire frames) -> B's relay decision
//! ([`crate::holepunch::relay_decision`], target eligibility read from
//! the real handle negotiation mirror) -> connect both ways -> A/C dial
//! simultaneously -> the punch establishes the link -> a normal BT
//! handshake attaches -> HAVE frames flow through, proving the swarm
//! data plane is ready. Also includes the send-id negotiation probe and
//! table-driven wire tests of the fixed-window rendezvous/connect rate
//! limits.

use std::sync::Mutex;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::holepunch::{HOLEPUNCH_BOOK_CAP, HolepunchBook, RelayAction, relay_decision};
use crate::peer_wire::{FrameCodec, Reserved};

fn v4_sock(oct: [u8; 4], port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::from(oct), port)
}

type TapReader = FramedRead<ReadHalf<DuplexStream>, FrameCodec>;
type TapWriter = FramedWrite<WriteHalf<DuplexStream>, FrameCodec>;

/// Test observation/injection surface for one end of a real peer link:
/// `seen` = a mirror of every frame that end's peer task emits; `inj` =
/// inject a frame into that end's peer task (the peer's ext handshake).
struct LegEnd {
    seen: mpsc::Receiver<Message>,
    inj: mpsc::Sender<Message>,
}

/// Build one real peer link: returns both ends' (socket -> PeerTask,
/// LegEnd observation/injection). The forwarding tasks move + mirror
/// frames in both directions; they exit naturally when the pipes close
/// (test teardown).
fn wire_leg() -> ((DuplexStream, LegEnd), (DuplexStream, LegEnd)) {
    // A end: a_sock -> A's PeerTask; a_tap is the test-side window.
    let (a_sock, a_tap) = tokio::io::duplex(64 * 1024);
    let (b_sock, b_tap) = tokio::io::duplex(64 * 1024);
    let (a_tap_r, a_tap_w) = tokio::io::split(a_tap);
    let (b_tap_r, b_tap_w) = tokio::io::split(b_tap);
    let mut ar: TapReader = FramedRead::new(a_tap_r, FrameCodec::default());
    let mut br: TapReader = FramedRead::new(b_tap_r, FrameCodec::default());
    let mut aw: TapWriter = FramedWrite::new(a_tap_w, FrameCodec::default());
    let mut bw: TapWriter = FramedWrite::new(b_tap_w, FrameCodec::default());
    let (a_seen_tx, a_seen) = mpsc::channel::<Message>(64);
    let (b_seen_tx, b_seen) = mpsc::channel::<Message>(64);
    let (a_inj_tx, mut a_inj) = mpsc::channel::<Message>(8);
    let (b_inj_tx, mut b_inj) = mpsc::channel::<Message>(8);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                // A emits: mirror into a_seen + forward into B's socket.
                f = ar.next() => match f {
                    Some(Ok(m)) => {
                        let _ = a_seen_tx.try_send(m.clone());
                        if bw.send(m).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
                // B emits: mirror into b_seen + forward into A's socket.
                f = br.next() => match f {
                    Some(Ok(m)) => {
                        let _ = b_seen_tx.try_send(m.clone());
                        if aw.send(m).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
                // Inject toward A.
                inj = a_inj.recv() => match inj {
                    Some(m) => {
                        if aw.send(m).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                // Inject toward B.
                inj = b_inj.recv() => match inj {
                    Some(m) => {
                        if bw.send(m).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
    });
    (
        (
            a_sock,
            LegEnd {
                seen: a_seen,
                inj: a_inj_tx,
            },
        ),
        (
            b_sock,
            LegEnd {
                seen: b_seen,
                inj: b_inj_tx,
            },
        ),
    )
}

/// Node = one PeerTask connection (the B relay has two: B1<->A and
/// B2<->C, each with its own cuid — in the engine one connection is one
/// cuid, isomorphic).
struct Node {
    cuid: u64,
    ep: std::net::SocketAddr,
    handle: PeerTaskHandle,
    join: tokio::task::JoinHandle<PeerEnd>,
    hp_rx: mpsc::Receiver<HolepunchEvent>,
    end: LegEnd,
}

fn wire_node(
    root: &CancellationToken,
    cuid: u64,
    ep: std::net::SocketAddr,
    sock: DuplexStream,
    end: LegEnd,
) -> Node {
    let (hp_tx, hp_rx) = mpsc::channel::<HolepunchEvent>(16);
    let config = PeerConfig {
        cuid,
        flooding_interval: Duration::from_millis(20),
        // ext handshake enabled (empty serving surface); the holepunch slot
        // is independent of the ext gate: Some = advertise ut_holepunch +
        // consume inbound frames.
        ext: ExtConfig::serve(None),
        holepunch: Some(HolepunchExt { tx: hp_tx }),
        ..PeerConfig::flat()
    };
    let (handle, join, _data) = PeerTask::spawn(root, sock, config);
    Node {
        cuid,
        ep,
        handle,
        join,
        hp_rx,
        end,
    }
}

/// The punched connection (a new PeerTask after a successful
/// simultaneous dial): handle + availability event receiver (the
/// HAVE-through proof surface).
struct Punched {
    handle: PeerTaskHandle,
    join: tokio::task::JoinHandle<PeerEnd>,
    avail_rx: mpsc::Receiver<AvailEvent>,
}

fn wire_punched(root: &CancellationToken, cuid: u64, stream: DuplexStream) -> Punched {
    let (hp_tx, _hp_rx) = mpsc::channel::<HolepunchEvent>(16);
    let (avail_tx, avail_rx) = mpsc::channel::<AvailEvent>(8);
    let config = PeerConfig {
        cuid,
        flooding_interval: Duration::from_millis(20),
        ext: ExtConfig::serve(None),
        holepunch: Some(HolepunchExt { tx: hp_tx }),
        avail_tx: Some(avail_tx),
        ..PeerConfig::flat()
    };
    let (handle, join, _data) = PeerTask::spawn(root, stream, config);
    Punched {
        handle,
        join,
        avail_rx,
    }
}

/// FakeNat: the simultaneous-dial constraint (NAT emulation, see the
/// module docs). `dial` = initiate an outbound dial: if the reverse
/// intent is already present, the simultaneous dial succeeds, both
/// intents are consumed and a new stream pair is returned (punch
/// succeeded); otherwise the intent pends and None is returned.
/// `retract` = withdraw after a failed dial (a one-sided initiator cannot
/// open a real NAT — the refused-direct-connection shape).
#[derive(Default)]
struct FakeNat {
    pending: Mutex<Vec<(usize, usize)>>,
}

impl FakeNat {
    fn dial(&self, from: usize, to: usize) -> Option<(DuplexStream, DuplexStream)> {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if p.contains(&(to, from)) {
            p.retain(|&(f, t)| !((f == from && t == to) || (f == to && t == from)));
            drop(p);
            Some(tokio::io::duplex(64 * 1024))
        } else {
            p.push((from, to));
            None
        }
    }

    fn retract(&self, from: usize, to: usize) {
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        p.retain(|&(f, t)| !(f == from && t == to));
    }
}

/// Read this end's peer task's ext handshake off the observation surface
/// (skipping other frames).
async fn read_my_ext(node: &mut Node) -> crate::peer_wire::ExtHandshake {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), node.end.seen.recv())
            .await
            .unwrap_or_else(|e| panic!("ext handshake read budget: {e}"))
            .unwrap_or_else(|| panic!("{}: tap closed", node.ep));
        if let Message::Extended { ext_id: 0, payload } = msg {
            return crate::peer_wire::ExtHandshake::decode(&payload)
                .unwrap_or_else(|e| panic!("bad ext handshake: {e}"));
        }
    }
}

/// The test plays the engine and injects the peer's ext handshake
/// (advertising ut_holepunch = `hp_id`, chosen per test — verifying that
/// BEP10 ids are locally negotiated rather than hardcoded 0x20).
async fn send_peer_ext(node: &mut Node, hp_id: u8) {
    let hs = crate::peer_wire::ExtHandshake {
        m_ut_holepunch: Some(hp_id),
        ..crate::peer_wire::ExtHandshake::default()
    };
    node.end
        .inj
        .send(Message::Extended {
            ext_id: 0,
            payload: hs.encode().unwrap_or_else(|e| panic!("{e}")),
        })
        .await
        .unwrap_or_else(|e| panic!("inject peer ext: {e}"));
}

/// Poll until the condition holds (async surfaces such as the negotiation
/// mirror being set; 2s budget).
async fn wait_for(mut cond: impl FnMut() -> bool, name: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting for {name}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wait on the observation surface for one Extended frame with
/// ext_id = `ext_id` (wire-level assertion surface).
async fn expect_ext_frame(node: &mut Node, ext_id: u8, name: &str) -> bytes::Bytes {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let msg = tokio::time::timeout_at(deadline, node.end.seen.recv())
            .await
            .unwrap_or_else(|e| panic!("{name} budget: {e}"))
            .unwrap_or_else(|| panic!("{name}: tap closed"));
        if let Message::Extended {
            ext_id: id,
            payload,
        } = msg
        {
            assert_eq!(id, ext_id, "{name}: unexpected ext id");
            return payload;
        }
    }
}

/// Three-party full chain: A and C are behind NAT (only a simultaneous
/// dial establishes a link), B is reachable and relays: rendezvous ->
/// connect both ways -> A/C dial simultaneously -> BT handshake -> swarm
/// data plane flows (HAVE).
#[tokio::test]
async fn three_way_nat_punch_establishes_swarm_link() {
    let root = CancellationToken::new();
    let fake_nat = FakeNat::default();

    // Address plane: A/C = CGNAT-mapped addresses (no listener); B = a
    // reachable public endpoint.
    let ep_a = v4_sock([203, 0, 113, 1], 40001);
    let ep_b = v4_sock([198, 51, 100, 2], 6882);
    let ep_c = v4_sock([203, 0, 113, 3], 40003);

    // Two real peer links: A<->B1 and C<->B2.
    let ((a_sock, a_end), (b1_sock, b1_end)) = wire_leg();
    let ((c_sock, c_end), (b2_sock, b2_end)) = wire_leg();

    let mut a = wire_node(&root, 1, ep_a, a_sock, a_end);
    let mut b1 = wire_node(&root, 2, ep_b, b1_sock, b1_end);
    let mut b2 = wire_node(&root, 3, ep_b, b2_sock, b2_end);
    let mut c = wire_node(&root, 4, ep_c, c_sock, c_end);

    // Our advertise surface: enabled by default = the presence of the
    // holepunch slot advertises 0x20 (the wire half of the default-on
    // guarantee; asserted on all four connections).
    for n in [&mut a, &mut b1, &mut b2, &mut c] {
        let mine = read_my_ext(n).await;
        assert_eq!(
            mine.m_ut_holepunch,
            Some(OUTBOUND_UT_HOLEPUNCH_ID),
            "{} must advertise ut_holepunch",
            n.ep
        );
    }
    // Peer registration: the peer handshake's m dict = "the id to use when
    // sending to me". Our actual advertisement is always 0x20 (the
    // outbound constant), so all three injections are 0x20 — matching real
    // wire traffic. "Outbound follows the peer's advertised id when it is
    // not 0x20" is covered by the probe test (0x55).
    send_peer_ext(&mut a, 0x20).await;
    send_peer_ext(&mut b1, 0x20).await;
    send_peer_ext(&mut b2, 0x20).await;
    send_peer_ext(&mut c, 0x20).await;

    // Negotiation mirrors set (async processing): A/C's mirrors are the
    // precondition for outbound sends — without a registered peer
    // advertise, SendHolepunch is dropped as "not registered".
    wait_for(|| a.handle.supports_holepunch(), "A mirror").await;
    wait_for(|| b1.handle.supports_holepunch(), "B1 mirror").await;
    wait_for(|| b2.handle.supports_holepunch(), "B2 mirror").await;
    wait_for(|| c.handle.supports_holepunch(), "C mirror").await;

    // ---- Trigger surface: A's direct dial to C fails (same-source
    // failure bookkeeping) + introducer bookkeeping -> the rendezvous goes
    // only to the introducer (conservative, find_introducer-shaped). ----
    let mut book = HolepunchBook::new(HOLEPUNCH_BOOK_CAP);
    let t0 = std::time::Instant::now();
    book.note_dial_failed(ep_c, t0); // the "really failed a handshake" gate
    book.note_introduced(ep_c, b1.cuid, t0); // B delivered C via ut_pex (bookkeeping surface)
    assert_eq!(
        book.rendezvous_target(&ep_c, t0),
        Some(b1.cuid),
        "trigger must resolve to the introducer connection"
    );
    a.handle
        .command(PeerCommand::SendHolepunch(
            crate::holepunch::UtHolepunch::Rendezvous { ep: ep_c },
        ))
        .unwrap_or_else(|e| panic!("command rejected: {e:?}"));

    // Wire-level assertion: A really emits a rendezvous frame (ext_id =
    // B's advertised 0x20, payload = the target ep).
    let rv_payload = expect_ext_frame(&mut a, 0x20, "rendezvous wire frame").await;
    assert_eq!(
        crate::holepunch::UtHolepunch::decode(&rv_payload),
        Ok(crate::holepunch::UtHolepunch::Rendezvous { ep: ep_c })
    );

    // ---- Relay surface: B1 receives the rendezvous (event handed up) ->
    // decision -> connect both ways. ----
    let ev = tokio::time::timeout(Duration::from_secs(2), b1.hp_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("rendezvous event budget: {e}"))
        .unwrap_or_else(|| panic!("b1 holepunch channel closed"));
    assert_eq!(
        ev.from, b1.cuid,
        "event carries the receiving connection cuid"
    );
    assert_eq!(
        ev.msg,
        crate::holepunch::UtHolepunch::Rendezvous { ep: ep_c }
    );

    // Target eligibility = the real negotiation mirror of the B<->C
    // connection (lock-free handle read, not hardcoded).
    let target = (b2.cuid, b2.handle.supports_holepunch());
    assert_eq!(
        relay_decision(b1.cuid, Some(target)),
        RelayAction::Introduce,
        "B knows both sides and C negotiated holepunch"
    );
    // libtorrent: connect(target ep) to the requester, connect(requester's
    // mapped address) to the target — both addresses are live handshaked
    // relay connections, so structurally no amplification.
    b1.handle
        .command(PeerCommand::SendHolepunch(
            crate::holepunch::UtHolepunch::Connect { ep: ep_c },
        ))
        .unwrap_or_else(|e| panic!("command rejected: {e:?}"));
    b2.handle
        .command(PeerCommand::SendHolepunch(
            crate::holepunch::UtHolepunch::Connect { ep: ep_a },
        ))
        .unwrap_or_else(|e| panic!("command rejected: {e:?}"));

    // Wire-level assertion: both connect frames go outbound (ext_id = each
    // peer's advertised 0x20).
    let ct_a = expect_ext_frame(&mut b1, 0x20, "connect-to-A wire frame").await;
    assert_eq!(
        crate::holepunch::UtHolepunch::decode(&ct_a),
        Ok(crate::holepunch::UtHolepunch::Connect { ep: ep_c })
    );
    let ct_c = expect_ext_frame(&mut b2, 0x20, "connect-to-C wire frame").await;
    assert_eq!(
        crate::holepunch::UtHolepunch::decode(&ct_c),
        Ok(crate::holepunch::UtHolepunch::Connect { ep: ep_a })
    );

    // A / C's event surface (engine view) receives their dial instructions.
    let ev_a = tokio::time::timeout(Duration::from_secs(2), a.hp_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("connect event budget: {e}"))
        .unwrap_or_else(|| panic!("a holepunch channel closed"));
    assert_eq!(
        ev_a.msg,
        crate::holepunch::UtHolepunch::Connect { ep: ep_c },
        "A must be told to dial C"
    );
    let ev_c = tokio::time::timeout(Duration::from_secs(2), c.hp_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("connect event budget: {e}"))
        .unwrap_or_else(|| panic!("c holepunch channel closed"));
    assert_eq!(
        ev_c.msg,
        crate::holepunch::UtHolepunch::Connect { ep: ep_a },
        "C must be told to dial A"
    );

    // ---- Simultaneous dial: a one-sided initiator is refused by the NAT
    // (intent pends); when both sides meet, the hole opens. ----
    let node_a = 0;
    let node_c = 1;
    assert!(
        fake_nat.dial(node_a, node_c).is_none(),
        "lone dial must not establish (NAT refuses one-way open)"
    );
    let (mut pa, mut pc) = fake_nat
        .dial(node_c, node_a)
        .unwrap_or_else(|| panic!("simultaneous open must establish"));

    // Run a normal BT handshake on the punched stream (joined as a normal
    // outbound; handshake_exchange writes/reads symmetrically, so running
    // both sides concurrently works).
    const SWARM: [u8; 20] = *b"P78-HOLEPUNCH-SWARM\x00";
    let peer_id_a = *b"-TJ0001-AIDEAIDEID22";
    let peer_id_c = *b"-TJ0001-CIDECIDECID3";
    let reserved = Reserved::aria2_default();
    let (res_a, res_c) = tokio::join!(
        crate::peer::handshake_exchange(
            &mut pa,
            &SWARM,
            &peer_id_a,
            reserved,
            Duration::from_secs(2),
        ),
        crate::peer::handshake_exchange(
            &mut pc,
            &SWARM,
            &peer_id_c,
            reserved,
            Duration::from_secs(2),
        ),
    );
    let (_, theirs_a) = res_a.unwrap_or_else(|e| panic!("A handshake: {e}"));
    let (_, theirs_c) = res_c.unwrap_or_else(|e| panic!("C handshake: {e}"));
    assert_eq!(theirs_a.peer_id, peer_id_c, "A must shake hands with C");
    assert_eq!(theirs_c.peer_id, peer_id_a, "C must shake hands with A");

    // After the handshake, spawn PeerTasks as normal outbound (isomorphic
    // to the engine's attach_peer; this swarm surface is the input for
    // advertisement-aware dialing).
    let punch_a = wire_punched(&root, 10, pa);
    let mut punch_c = wire_punched(&root, 11, pc);

    // ---- Swarm data-plane proof: HAVE is consumed by the peer over the
    // new connection (the full frame path). ----
    punch_a
        .handle
        .command(PeerCommand::SendHave { index: 77 })
        .unwrap_or_else(|e| panic!("command rejected: {e:?}"));
    let have = tokio::time::timeout(Duration::from_secs(2), punch_c.avail_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("have budget: {e}"))
        .unwrap_or_else(|| panic!("punched c avail channel closed"));
    match have {
        AvailEvent::Have { peer, index } => {
            assert_eq!(peer, 11);
            assert_eq!(index, 77, "HAVE must cross the punched link into C's view");
        }
        other => panic!("expected Have event, got {other:?}"),
    }

    // The relay emits no extra events (not polluted by misdelivered
    // connect/failed frames).
    let quiet = tokio::time::timeout(Duration::from_millis(200), async {
        b1.hp_rx.recv().await;
        b2.hp_rx.recv().await;
    })
    .await;
    assert!(
        quiet.is_err(),
        "relay must not emit spurious holepunch events"
    );

    // Teardown: all tasks can exit (nothing hangs).
    root.cancel();
    for n in [&mut a, &mut b1, &mut b2, &mut c] {
        let end = tokio::time::timeout(Duration::from_secs(2), &mut n.join).await;
        assert!(end.is_ok(), "{} join budget", n.ep);
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), punch_a.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), punch_c.join).await;
}

/// The NAT refuses one-way initiation (the harness constraint itself):
/// after one side registers and withdraws, both sides dialing alone
/// establish nothing.
#[tokio::test]
async fn direct_dial_refused_without_simultaneous_open() {
    let nat = FakeNat::default();
    assert!(nat.dial(0, 1).is_none(), "first mover only registers");
    nat.retract(0, 1);
    assert!(nat.dial(1, 0).is_none(), "reverse-only dial also refused");
    nat.retract(1, 0);
}

/// Send-surface probe: a SendHolepunch command -> the frame goes outbound
/// with the **peer's advertised id** (BEP10 reply semantics; this test's
/// peer advertises 0x55). Commands issued before registration completes
/// (mirror set) are dropped as "not registered" — the engine must
/// likewise check the negotiation mirror before sending (the
/// precondition of relay/trigger eligibility decisions).
#[tokio::test]
async fn send_holepunch_uses_peers_advertised_id() {
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (hp_tx, _hp_rx) = mpsc::channel::<HolepunchEvent>(16);
    let config = PeerConfig {
        cuid: 7,
        flooding_interval: Duration::from_millis(20),
        ext: ExtConfig::serve(None),
        holepunch: Some(HolepunchExt { tx: hp_tx }),
        ..PeerConfig::flat()
    };
    let (handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (r, w) = tokio::io::split(remote);
    let mut w = FramedWrite::new(w, FrameCodec::default());
    let mut r = FramedRead::new(r, FrameCodec::default());

    // Our advertisement + the peer advertising 0x55.
    let first = tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|e| panic!("budget: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(first, Message::Extended { ext_id: 0, .. }));
    let hs = crate::peer_wire::ExtHandshake {
        m_ut_holepunch: Some(0x55),
        ..crate::peer_wire::ExtHandshake::default()
    };
    w.send(Message::Extended {
        ext_id: 0,
        payload: hs.encode().unwrap_or_else(|e| panic!("{e}")),
    })
    .await
    .unwrap_or_else(|e| panic!("write: {e}"));
    wait_for(|| handle.supports_holepunch(), "probe mirror").await;

    // Command outbound: the frame's ext_id must be the peer's
    // advertisement (0x55), payload = rendezvous.
    handle
        .command(PeerCommand::SendHolepunch(
            crate::holepunch::UtHolepunch::Rendezvous {
                ep: v4_sock([203, 0, 113, 60], 6881),
            },
        ))
        .unwrap_or_else(|e| panic!("command rejected: {e:?}"));
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(2), r.next())
            .await
            .unwrap_or_else(|e| panic!("budget: {e}"))
            .unwrap_or_else(|| panic!("closed"))
            .unwrap_or_else(|e| panic!("{e}"));
        if let Message::Extended { ext_id, payload } = frame {
            assert_eq!(ext_id, 0x55, "outbound must use the peer's advertised id");
            assert_eq!(
                crate::holepunch::UtHolepunch::decode(&payload),
                Ok(crate::holepunch::UtHolepunch::Rendezvous {
                    ep: v4_sock([203, 0, 113, 60], 6881)
                })
            );
            break;
        }
    }
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Rate-limit wire table test: within the 60s fixed window, rendezvous is
/// capped at [`HOLEPUNCH_REQUEST_LIMIT`] and connect at
/// [`HOLEPUNCH_CONNECT_LIMIT`]; over-limit frames are ignored without
/// disconnect (the connection stays servable; failed frames are
/// informational and consume no window).
#[tokio::test]
async fn rendezvous_and_connect_rate_limited_without_disconnect() {
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (hp_tx, mut hp_rx) = mpsc::channel::<HolepunchEvent>(16);
    let config = PeerConfig {
        cuid: 9,
        flooding_interval: Duration::from_millis(20),
        ext: ExtConfig::serve(None),
        holepunch: Some(HolepunchExt { tx: hp_tx }),
        ..PeerConfig::flat()
    };
    let (handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (r, w) = tokio::io::split(remote);
    let mut w = FramedWrite::new(w, FrameCodec::default());
    let mut r = FramedRead::new(r, FrameCodec::default());

    // Our advertisement (default on) + peer registration (advertising
    // 0x30 — the inbound main path keys on OUR advertised id, independent
    // of the peer's value).
    let first = tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|e| panic!("budget: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("{e}"));
    let Message::Extended { ext_id: 0, payload } = first else {
        panic!("expected ext handshake first");
    };
    let mine = crate::peer_wire::ExtHandshake::decode(&payload).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(mine.m_ut_holepunch, Some(OUTBOUND_UT_HOLEPUNCH_ID));
    let hs = crate::peer_wire::ExtHandshake {
        m_ut_holepunch: Some(0x30),
        ..crate::peer_wire::ExtHandshake::default()
    };
    w.send(Message::Extended {
        ext_id: 0,
        payload: hs.encode().unwrap_or_else(|e| panic!("{e}")),
    })
    .await
    .unwrap_or_else(|e| panic!("write: {e}"));

    let ep = v4_sock([203, 0, 113, 50], 6881);
    let frame = |msg: crate::holepunch::UtHolepunch| Message::Extended {
        ext_id: OUTBOUND_UT_HOLEPUNCH_ID,
        payload: bytes::Bytes::from(msg.encode()),
    };

    // rendezvous x6: only HOLEPUNCH_REQUEST_LIMIT pass within the window.
    for _ in 0..6 {
        w.send(frame(crate::holepunch::UtHolepunch::Rendezvous { ep }))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
    }
    for i in 0..HOLEPUNCH_REQUEST_LIMIT {
        let ev = tokio::time::timeout(Duration::from_secs(2), hp_rx.recv())
            .await
            .unwrap_or_else(|e| panic!("event #{i} budget: {e}"))
            .unwrap_or_else(|| panic!("channel closed"));
        assert_eq!(ev.from, 9);
        assert_eq!(ev.msg, crate::holepunch::UtHolepunch::Rendezvous { ep });
    }
    let over = tokio::time::timeout(Duration::from_millis(300), hp_rx.recv()).await;
    assert!(over.is_err(), "beyond-limit rendezvous must be ignored");

    // connect x6: an independent window, same cap (each frame gates one
    // engine-side holepunch dial).
    for _ in 0..6 {
        w.send(frame(crate::holepunch::UtHolepunch::Connect { ep }))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
    }
    for i in 0..HOLEPUNCH_CONNECT_LIMIT {
        let ev = tokio::time::timeout(Duration::from_secs(2), hp_rx.recv())
            .await
            .unwrap_or_else(|e| panic!("connect event #{i} budget: {e}"))
            .unwrap_or_else(|| panic!("channel closed"));
        assert_eq!(ev.msg, crate::holepunch::UtHolepunch::Connect { ep });
    }
    let over = tokio::time::timeout(Duration::from_millis(300), hp_rx.recv()).await;
    assert!(over.is_err(), "beyond-limit connect must be ignored");

    // failed frame: informational, not surfaced, consumes no window.
    w.send(frame(crate::holepunch::UtHolepunch::Failed {
        ep,
        error: crate::holepunch::HpError::NotConnected,
    }))
    .await
    .unwrap_or_else(|e| panic!("write: {e}"));
    let quiet = tokio::time::timeout(Duration::from_millis(300), hp_rx.recv()).await;
    assert!(quiet.is_err(), "failed frames must not surface as events");

    // Over-limit did not disconnect: the connection still serves (after
    // the have command the peer can read a frame = the write path is
    // healthy; the exit state Clean = no Violation/Flooded escalation).
    handle
        .command(PeerCommand::SendHave { index: 5 })
        .unwrap_or_else(|e| panic!("command rejected: {e:?}"));
    let frame = tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|e| panic!("budget: {e}"))
        .unwrap_or_else(|| panic!("closed"));
    assert_eq!(
        frame.unwrap_or_else(|e| panic!("{e}")),
        Message::Have { index: 5 },
        "connection must stay alive"
    );

    handle.shutdown();
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(end, PeerEnd::Clean | PeerEnd::Cancelled),
        "got {end:?}"
    );
}

//! ut_pex conformance vectors and semantics tests.
//!
//! Sources: vectors tagged `[aria2]` come from aria2
//! `test/UTPexExtensionMessageTest.cc`; `[strict]` marks this repo's
//! canonical tightenings (no interop impact).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use super::message::{
    FIRST_PEX_MAX, FLAG_ENCRYPTED, FLAG_SEEDER, MAX_DROPPED_PEER, MAX_FRESH_PEER,
};
use super::{
    GetMode, PexCandidate, PexContext, PexError, PexInboundSession, PexMessage, PexOffer, PexPeer,
    PexSwarmSender, PrefersEncryption, UploadOnly, apply_pex_negotiation, pex_offered,
};
use crate::peer_wire::ExtRegistry;

fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e:?}"),
    }
}

fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
}

fn v6(ip: [u8; 16], port: u16) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
}

/// The packcompact input set from aria2 UTPexExtensionMessageTest.cc.
fn reference_addrs() -> Vec<SocketAddr> {
    vec![
        v4([192, 168, 0, 1], 6881),
        v4([10, 1, 1, 2], 9999),
        v4([192, 168, 0, 2], 6882),
        v4([10, 1, 1, 3], 10000),
        v6(
            [
                0x10, 0x02, 0x10, 0x35, 0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47,
                0x32, 0x17,
            ],
            6881,
        ),
        v6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0xbd, 0x05, 0x01, 0xd2, 0x28, 0x8a, 0x1f, 0xc0, 0x00, 0x01,
                0x10, 0xee,
            ],
            6882,
        ),
    ]
}

/// [aria2] testGetBencodedData — encode vector:
/// fresh = {192.168.0.1:6881 (seeder), 10.1.1.2:9999, v6 ...:6881},
/// dropped = {192.168.0.2:6882, 10.1.1.3:10000, v6 ...:6882}.
/// Built through the same path as the reference: addFreshPeer/addDroppedPeer
/// (first contact / drop entry = now).
#[test]
fn vector_01_encode_matches_reference_payload() {
    let addrs = reference_addrs();
    let t0 = Instant::now();
    let mut msg = PexMessage::new();
    let seeder = PexCandidate::fresh(PexPeer::new(addrs[0], UploadOnly::Yes), t0);
    assert!(
        msg.add_fresh_peer(&seeder, t0),
        "added seeder, check added.f flag"
    );
    let p2 = PexCandidate::fresh(PexPeer::new(addrs[1], UploadOnly::No), t0);
    assert!(msg.add_fresh_peer(&p2, t0));
    let p3 = PexCandidate::dropped(PexPeer::new(addrs[2], UploadOnly::No), t0);
    assert!(msg.add_dropped_peer(&p3, t0));
    let p4 = PexCandidate::dropped(PexPeer::new(addrs[3], UploadOnly::No), t0);
    assert!(msg.add_dropped_peer(&p4, t0));
    let p5 = PexCandidate::fresh(PexPeer::new(addrs[4], UploadOnly::No), t0);
    assert!(msg.add_fresh_peer(&p5, t0));
    let p6 = PexCandidate::dropped(PexPeer::new(addrs[5], UploadOnly::No), t0);
    assert!(msg.add_dropped_peer(&p6, t0));
    let payload = ok(msg.encode(), "encode");
    let expected: &[u8] = &[
        // d5:added12:
        b'd', b'5', b':', b'a', b'd', b'd', b'e', b'd', b'1', b'2', b':', 0xc0, 0xa8, 0x00, 0x01,
        0x1a, 0xe1, // 192.168.0.1:6881
        0x0a, 0x01, 0x01, 0x02, 0x27, 0x0f, // 10.1.1.2:9999
        b'7', b':', b'a', b'd', b'd', b'e', b'd', b'.', b'f', b'2', b':', 0x02, 0x00, // flags
        b'6', b':', b'a', b'd', b'd', b'e', b'd', b'6', b'1', b'8', b':', 0x10, 0x02, 0x10, 0x35,
        0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47, 0x32, 0x17, 0x1a, 0xe1, b'8',
        b':', b'a', b'd', b'd', b'e', b'd', b'6', b'.', b'f', b'1', b':', 0x00, b'7', b':', b'd',
        b'r', b'o', b'p', b'p', b'e', b'd', b'1', b'2', b':', 0xc0, 0xa8, 0x00, 0x02, 0x1a,
        0xe2, // 192.168.0.2:6882
        0x0a, 0x01, 0x01, 0x03, 0x27, 0x10, // 10.1.1.3:10000
        b'8', b':', b'd', b'r', b'o', b'p', b'p', b'e', b'd', b'6', b'1', b'8', b':', 0x20, 0x01,
        0x0d, 0xb8, 0xbd, 0x05, 0x01, 0xd2, 0x28, 0x8a, 0x1f, 0xc0, 0x00, 0x01, 0x10, 0xee, 0x1a,
        0xe2, b'e',
    ];
    assert_eq!(
        payload, expected,
        "encoding must match the reference getPayload() bytes (key order/flags/compact addrs)"
    );
}

/// [aria2] testCreate — decode vector (2 v4 fresh + 1 v6 fresh,
/// 2 v4 dropped + 1 v6 dropped; note: added.f is parsed per the BEP11
/// text — this vector has all-zero flags, so the address assertions match
/// the reference).
#[test]
fn vector_02_decode_matches_reference_payload() {
    let mut payload = vec![1u8]; // ext msg id (this codec takes the dict after the id)
    payload.extend_from_slice(&ok(PexMessage::encode(&sample_wire_msg()), "inner"));
    let msg = ok(PexMessage::decode(&payload[1..]), "decode");
    assert_eq!(msg.fresh_peers().len(), 3);
    assert_eq!(msg.fresh_peers()[0].addr, v4([192, 168, 0, 1], 6881));
    assert_eq!(msg.fresh_peers()[1].addr, v4([10, 1, 1, 2], 9999));
    assert_eq!(
        msg.fresh_peers()[2].addr,
        v6(
            [
                0x10, 0x02, 0x10, 0x35, 0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47,
                0x32, 0x17
            ],
            6997
        )
    );
    assert_eq!(msg.dropped_peers().len(), 3);
    assert_eq!(msg.dropped_peers()[0].addr, v4([192, 168, 0, 2], 6882));
    assert_eq!(msg.dropped_peers()[1].addr, v4([10, 1, 1, 3], 10000));
    assert_eq!(
        msg.dropped_peers()[2].addr,
        v6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0xbd, 0x05, 0x01, 0xd2, 0x28, 0x8a, 0x1f, 0xc0, 0x00, 0x01,
                0x10, 0xee
            ],
            6998
        )
    );
    // Note (strictness only increased): the reference does not read added.f
    // -> the old assertion was "always false on decode"; this reader follows
    // the BEP11 flags — this vector's flags are all 0x00 so the semantics
    // are unchanged (field renamed seeder -> upload_only; BEP11 bit 1 =
    // seed/upload_only, BEP21 naming).
    assert_eq!(msg.fresh_peers()[0].upload_only, UploadOnly::No);
    assert_eq!(msg.fresh_peers()[0].encrypted, PrefersEncryption::No);
}

/// The original wire message of the testCreate case (port 6997/6998
/// variant).
fn sample_wire_msg() -> PexMessage {
    let t0 = Instant::now();
    let mut msg = PexMessage::new();
    for addr in [
        v4([192, 168, 0, 1], 6881),
        v4([10, 1, 1, 2], 9999),
        v6(
            [
                0x10, 0x02, 0x10, 0x35, 0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47,
                0x32, 0x17,
            ],
            6997,
        ),
    ] {
        let cand = PexCandidate::fresh(PexPeer::new(addr, UploadOnly::No), t0);
        assert!(msg.add_fresh_peer(&cand, t0));
    }
    for addr in [
        v4([192, 168, 0, 2], 6882),
        v4([10, 1, 1, 3], 10000),
        v6(
            [
                0x20, 0x01, 0x0d, 0xb8, 0xbd, 0x05, 0x01, 0xd2, 0x28, 0x8a, 0x1f, 0xc0, 0x00, 0x01,
                0x10, 0xee,
            ],
            6998,
        ),
    ] {
        let cand = PexCandidate::dropped(PexPeer::new(addr, UploadOnly::No), t0);
        assert!(msg.add_dropped_peer(&cand, t0));
    }
    msg
}

/// [aria2] testCreate negative case — a zero-length payload must error.
#[test]
fn vector_03_decode_rejects_empty_payload() {
    assert_eq!(PexMessage::decode(&[]), Err(PexError::TooSmall));
}

/// [aria2] decode leniency matrix: non-dict top level -> empty message (the
/// `if (dict)` guard); string length not a multiple of the unit size ->
/// skip (bittorrent_helper.h); unknown keys ignored. added.f is read per
/// the BEP11 text (an explicit divergence from the reference, which has no
/// read path; see the message.rs module docs and the note in vector_04).
#[test]
fn vector_04_decode_lenient_matrix() {
    // Top-level integer: empty message, no error.
    let msg = ok(PexMessage::decode(b"i1e"), "non-dict");
    assert!(msg.fresh_peers().is_empty() && msg.dropped_peers().is_empty());
    // added length 7 (not a multiple of 6) -> whole string skipped;
    // dropped6 length 17 (not a multiple of 18) -> skipped.
    let ragged = b"d5:added7:\x01\x02\x03\x04\x1a\xe1X8:dropped617:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x1ae";
    let msg = ok(PexMessage::decode(ragged), "ragged lengths");
    assert!(msg.fresh_peers().is_empty());
    assert!(msg.dropped_peers().is_empty());
    // Note (strictness only increased): the reference "has added.f but
    // never reads it" -> the old assertion was seeder=false; this reader
    // honors the BEP11 flags (bit1=0x02 -> upload_only=true) — an explicit
    // tightening; inbound no longer discards the flag bits. Unknown keys
    // are still ignored.
    let msg = ok(
        PexMessage::decode(b"d5:added6:\x01\x02\x03\x04\x1a\xe17:added.f1:\x02e" as &[u8]),
        "added.f honored",
    );
    assert_eq!(msg.fresh_peers().len(), 1);
    assert_eq!(msg.fresh_peers()[0].upload_only, UploadOnly::Yes);
    assert_eq!(msg.fresh_peers()[0].encrypted, PrefersEncryption::No);
    // Broken bencode -> error (the reference decode throws; a length beyond
    // the remaining bytes = Eof).
    assert!(PexMessage::decode(b"d5:added9:abc").is_err());
}

/// encode->decode roundtrip (self-consistent; the decode projection includes
/// the added.f flag bits — all flags are 0 in this vector, so roundtrip
/// values are unchanged).
#[test]
fn vector_05_roundtrip_preserves_addrs() {
    let msg = sample_wire_msg();
    let bytes = ok(msg.encode(), "encode");
    let back = ok(PexMessage::decode(&bytes), "decode");
    assert_eq!(back.fresh_peers(), msg.fresh_peers());
    assert_eq!(back.dropped_peers(), msg.dropped_peers());
}

// ---------------------------------------------------------------------------
// Inbound resource caps: MAX_FRESH_PEER/MAX_DROPPED_PEER previously only
// constrained our outbound side (the full guards on add_fresh_peer/
// add_dropped_peer callers); inbound added/dropped strings were uncapped —
// a single 64KiB extended frame decodes to ~10.9k v4 addresses (6B/unit),
// and the engine consumer (dial.rs handle_pex_event) scans the whole
// peer_ips table per address -> CPU amplification. Fix: added+added6 and
// dropped+dropped6 are each capped at the same values as outbound; over
// the cap the whole frame is rejected (Err).
// ---------------------------------------------------------------------------

/// bencode bytes entry (`<klen>:<key><vlen>:<value>`); the dict-building
/// helper for the tests (not on the codec's normal path — decode input is
/// assembled wire bytes directly).
fn bentry(key: &str, val: &[u8]) -> Vec<u8> {
    let mut out = format!("{}:{}{}:", key.len(), key, val.len()).into_bytes();
    out.extend_from_slice(val);
    out
}

/// dict payload (no ext msg id byte).
fn pex_frame(parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![b'd'];
    for (key, val) in parts {
        out.extend_from_slice(&bentry(key, val));
    }
    out.push(b'e');
    out
}

/// n distinct v4 compact units (6B = 4B IP + 2B port, network order).
fn v4_units(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * 6);
    for host in 1u32..=u32::try_from(n).unwrap_or(u32::MAX) {
        out.extend_from_slice(&host.to_be_bytes());
        out.extend_from_slice(&6881u16.to_be_bytes());
    }
    out
}

/// n distinct v6 compact units (18B = 16B IP + 2B port).
fn v6_units(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * 18);
    for host in 1u16..=u16::try_from(n).unwrap_or(u16::MAX) {
        let mut ip = [0u8; 16];
        ip[15] = host as u8;
        out.extend_from_slice(&ip);
        out.extend_from_slice(&6881u16.to_be_bytes());
    }
    out
}

/// decode inbound list caps — over the cap the whole frame is rejected.
#[test]
fn vector_08_decode_rejects_oversized_lists() {
    // added with 51 v4 units (> MAX_FRESH_PEER 50) -> whole frame Err.
    let payload = pex_frame(&[("added", v4_units(MAX_FRESH_PEER + 1))]);
    assert!(
        PexMessage::decode(&payload).is_err(),
        "added over MAX_FRESH_PEER must reject the whole frame"
    );
    // dropped with 51 -> also whole-frame Err.
    let payload = pex_frame(&[("dropped", v4_units(MAX_DROPPED_PEER + 1))]);
    assert!(
        PexMessage::decode(&payload).is_err(),
        "dropped over MAX_DROPPED_PEER must reject the whole frame"
    );
    // v4+v6 combined accounting (matching the constant docs): added 30 +
    // added6 21 = 51 -> whole-frame Err (per-family splits below 50 must
    // not bypass the cap).
    let payload = pex_frame(&[
        ("added", v4_units(30)),
        ("added6", v6_units(MAX_FRESH_PEER - 30 + 1)),
    ]);
    assert!(
        PexMessage::decode(&payload).is_err(),
        "added+added6 combined over the cap must reject the whole frame"
    );
    // Boundary: exactly 50 = legal (the cap must not reject a full frame).
    let payload = pex_frame(&[("added", v4_units(MAX_FRESH_PEER))]);
    let msg = ok(PexMessage::decode(&payload), "cap boundary");
    assert_eq!(msg.fresh_peers().len(), MAX_FRESH_PEER);
    // Boundary: fresh 50 + dropped 50 both full = legal (independent caps).
    let payload = pex_frame(&[
        ("added", v4_units(MAX_FRESH_PEER)),
        ("dropped", v4_units(MAX_DROPPED_PEER)),
    ]);
    let msg = ok(PexMessage::decode(&payload), "both lists at cap");
    assert_eq!(msg.fresh_peers().len(), MAX_FRESH_PEER);
    assert_eq!(msg.dropped_peers().len(), MAX_DROPPED_PEER);
}

// ---------------------------------------------------------------------------
// BEP11 first ut_pex exemption + outbound empty-frame skip.
// BEP11 text (bittorrent.org/beps/bep_0011.html):
// - "Except for the initial PEX message the combined amount of added
// v4/v6 contacts should not exceed 50 entries. The same applies to
// dropped entries." (the first message is exempt from the 50 cap; no
// replacement value is given);
// - "Messages must contain at least one of the following fields: added,
// added6, dropped, dropped6." (an empty dict frame violates a MUST).
// ---------------------------------------------------------------------------

/// The first ut_pex carrying 120 addresses (>50, the normal shape of
/// mainstream clients' first frames) is accepted under the exemption; a
/// first frame over 300 is truncated to the first 300; a second frame with
/// 120 keeps the 50 whole-frame rejection (regression anchor).
#[test]
fn pc10_first_frame_pex_exemption_tiered_caps() {
    // First ut_pex with 120 added -> all 120 accepted (within the
    // exemption, 120 < 300).
    let mut sess = PexInboundSession::new();
    let first = pex_frame(&[("added", v4_units(120))]);
    let msg = ok(sess.decode(&first), "first frame exempt");
    assert_eq!(
        msg.fresh_peers().len(),
        120,
        "a first frame of 120 addresses must be accepted (BEP11 exemption)"
    );
    // Regression anchor: the second frame with 120 -> whole-frame rejection
    // (the 50 cap stands).
    let second = pex_frame(&[("added", v4_units(120))]);
    assert!(
        sess.decode(&second).is_err(),
        "a later frame over 50 must reject the whole frame"
    );
    // First frame over FIRST_PEX_MAX (320 v4) -> truncated to the first 300
    // (rejecting the frame would lose the whole discovery set; truncation
    // only loses the tail).
    let mut sess = PexInboundSession::new();
    let big = pex_frame(&[("added", v4_units(FIRST_PEX_MAX + 20))]);
    let msg = ok(sess.decode(&big), "first frame truncated");
    assert_eq!(
        msg.fresh_peers().len(),
        FIRST_PEX_MAX,
        "an over-cap first frame is truncated to the first N"
    );
    // First-frame v4+v6 combined truncation (200 v4 + 150 v6 = 350 > 300 ->
    // all 200 added kept, added6 keeps the first 100 in order, tail
    // dropped).
    let mut sess = PexInboundSession::new();
    let mixed = pex_frame(&[
        ("added", v4_units(200)),
        ("added6", v6_units(FIRST_PEX_MAX - 200 + 50)),
    ]);
    let msg = ok(sess.decode(&mixed), "first frame mixed family");
    assert_eq!(
        msg.fresh_peers().len(),
        FIRST_PEX_MAX,
        "v4+v6 combined truncated to the cap"
    );
    assert_eq!(
        msg.fresh_peers()
            .iter()
            .filter(|p| p.addr.is_ipv4())
            .count(),
        200,
        "the v4 bucket comes first and is kept whole"
    );
    // The first-frame dropped side is exempt too (dropped 120 -> accepted).
    let mut sess = PexInboundSession::new();
    let dropped = pex_frame(&[("dropped", v4_units(120))]);
    let msg = ok(sess.decode(&dropped), "first frame dropped exempt");
    assert_eq!(
        msg.dropped_peers().len(),
        120,
        "dropped shares the first-frame exemption"
    );
    // Boundary: a first frame of exactly 300 is legal without truncation.
    let mut sess = PexInboundSession::new();
    let edge = pex_frame(&[("added", v4_units(FIRST_PEX_MAX))]);
    let msg = ok(sess.decode(&edge), "first frame at cap");
    assert_eq!(msg.fresh_peers().len(), FIRST_PEX_MAX);
}

/// A period with no changes must not produce an empty dict frame — when
/// maybe_build is due and all candidates are empty (or filtered out) it
/// must return None (otherwise it violates the BEP11 "Messages must contain
/// at least one of the following fields: added, added6, dropped,
/// dropped6."); qualified candidates still produce frames as usual
/// (anchor). Wire-level net-effect anchor: peer::tests
/// `pex_outbound_skips_empty_window`.
#[test]
fn pc10_outbound_empty_window_builds_no_frame() {
    let t0 = Instant::now();
    let interval = Duration::from_secs(60);
    // Empty-candidate period: due but no frame.
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(1), t0);
    assert!(
        sender.maybe_build(&[], &[], None, t0 + interval).is_none(),
        "a period with no changes must not produce an empty dict frame (BEP11 at-least-one-key MUST)"
    );
    // All filtered out (first contact exactly interval old = not fresh) ->
    // also empty -> no frame.
    let stale = PexCandidate::fresh(PexPeer::new(v4([10, 0, 0, 1], 6881), UploadOnly::No), t0);
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(1), t0);
    assert!(
        sender
            .maybe_build(&[stale], &[], None, t0 + interval)
            .is_none(),
        "an all-filtered-out period must likewise produce no frame"
    );
    // Qualified candidate -> frame as usual (anchor); the encoded frame
    // contains at least one address key (non-empty dict).
    let cand = PexCandidate::fresh(
        PexPeer::new(v4([10, 0, 0, 2], 6881), UploadOnly::No),
        t0 + interval,
    );
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(1), t0);
    let (id, msg) = sender
        .maybe_build(&[cand], &[], None, t0 + interval)
        .unwrap_or_else(|| panic!("qualified candidates must produce a frame"));
    assert_eq!(id, 1);
    assert_eq!(msg.fresh_peers().len(), 1);
    let bytes = ok(msg.encode(), "encode");
    assert!(
        bytes.len() > 2,
        "the produced frame must not encode as an empty dict (de) — BEP11 at-least-one-key"
    );
}

/// [aria2] testAddFreshPeer — table-driven:
/// a new outbound contact -> accepted; first contact 61s / exactly 60s ago
/// -> rejected (`difference < interval`); inbound connection -> rejected.
/// All clock values are expressed as "base instant + delta" (avoids Instant
/// underflow on low-uptime machines).
#[test]
fn vector_06_add_fresh_peer_eligibility_table() {
    let t0 = Instant::now();
    struct Case {
        name: &'static str,
        eval_at: Instant,
        incoming: bool,
        want: bool,
    }
    let cases = [
        Case {
            name: "fresh outbound (reference p1)",
            eval_at: t0,
            incoming: false,
            want: true,
        },
        Case {
            name: "61s old (reference p2)",
            eval_at: t0 + Duration::from_secs(61),
            incoming: false,
            want: false,
        },
        Case {
            name: "incoming (reference p3)",
            eval_at: t0,
            incoming: true,
            want: false,
        },
    ];
    for case in cases {
        let mut msg = PexMessage::new();
        let cand = PexCandidate {
            peer: PexPeer::new(v4([10, 0, 0, 1], 6881), UploadOnly::No),
            incoming: case.incoming,
            active: true,
            first_contact: t0,
            drop_started: None,
        };
        assert_eq!(
            msg.add_fresh_peer(&cand, case.eval_at),
            case.want,
            "case = {}",
            case.name
        );
    }
    // Boundary: exactly 60s -> `60s < 60s` is false -> rejected; 59s ->
    // accepted.
    let mut msg = PexMessage::new();
    let cand = PexCandidate::fresh(PexPeer::new(v4([10, 0, 0, 2], 6881), UploadOnly::No), t0);
    assert!(!msg.add_fresh_peer(&cand, t0 + Duration::from_secs(60)));
    assert!(msg.add_fresh_peer(&cand, t0 + Duration::from_secs(59)));
}

/// [aria2] testAddDroppedPeer — table-driven:
/// not dropped -> rejected; dropped and inside the window -> accepted;
/// inbound -> rejected.
#[test]
fn vector_07_add_dropped_peer_eligibility_table() {
    let t0 = Instant::now();
    let mut msg = PexMessage::new();
    // Not dropped (reference p1: startDrop not called).
    let cand = PexCandidate {
        peer: PexPeer::new(v4([192, 168, 0, 1], 6881), UploadOnly::No),
        incoming: false,
        active: true,
        first_contact: t0,
        drop_started: None,
    };
    assert!(
        !msg.add_dropped_peer(&cand, t0),
        "not dropped must be refused"
    );
    // Dropped (reference p2).
    let dropped = PexCandidate::dropped(PexPeer::new(v4([10, 1, 1, 2], 9999), UploadOnly::No), t0);
    assert!(msg.add_dropped_peer(&dropped, t0));
    // Inbound and dropped (reference p3).
    let incoming = PexCandidate {
        incoming: true,
        ..PexCandidate::dropped(PexPeer::new(v4([10, 1, 1, 3], 9999), UploadOnly::No), t0)
    };
    assert!(!msg.add_dropped_peer(&incoming, t0));
    // Boundary: exactly 60s -> rejected; 59s -> accepted.
    assert!(!msg.add_dropped_peer(&dropped, t0 + Duration::from_secs(60)));
    assert!(msg.add_dropped_peer(&dropped, t0 + Duration::from_secs(59)));
}

/// [aria2] testFreshPeersAreFull — default cap 50; after
/// setMaxFreshPeer(2) the third add still returns true (add does no
/// capacity check; the send loop guards capacity — reference semantics).
#[test]
fn vector_08_fresh_peers_are_full() {
    let msg = PexMessage::new();
    assert_eq!(msg.max_fresh(), MAX_FRESH_PEER);
    assert_eq!(MAX_FRESH_PEER, 50, "reference DEFAULT_MAX_FRESH_PEER");
    let mut msg = PexMessage::with_limits(2, 2, Duration::from_secs(60));
    let t0 = Instant::now();
    let c1 = PexCandidate::fresh(PexPeer::new(v4([192, 168, 0, 1], 6881), UploadOnly::No), t0);
    let c2 = PexCandidate::fresh(PexPeer::new(v4([10, 1, 1, 2], 9999), UploadOnly::No), t0);
    let c3 = PexCandidate::fresh(PexPeer::new(v4([10, 1, 1, 3], 9999), UploadOnly::No), t0);
    assert!(msg.add_fresh_peer(&c1, t0));
    assert!(!msg.fresh_peers_are_full());
    assert!(msg.add_fresh_peer(&c2, t0));
    assert!(msg.fresh_peers_are_full());
    assert!(
        msg.add_fresh_peer(&c3, t0),
        "reference :282 add beyond capacity still succeeds"
    );
    assert!(msg.fresh_peers_are_full());
}

/// [aria2] testDroppedPeersAreFull — same as above (dropped side).
#[test]
fn vector_09_dropped_peers_are_full() {
    let msg = PexMessage::new();
    assert_eq!(msg.max_dropped(), MAX_DROPPED_PEER);
    assert_eq!(MAX_DROPPED_PEER, 50, "reference DEFAULT_MAX_DROPPED_PEER");
    let mut msg = PexMessage::with_limits(2, 2, Duration::from_secs(60));
    let t0 = Instant::now();
    let d1 = PexCandidate::dropped(PexPeer::new(v4([192, 168, 0, 1], 6881), UploadOnly::No), t0);
    let d2 = PexCandidate::dropped(PexPeer::new(v4([10, 1, 1, 2], 9999), UploadOnly::No), t0);
    let d3 = PexCandidate::dropped(PexPeer::new(v4([10, 1, 1, 3], 9999), UploadOnly::No), t0);
    assert!(msg.add_dropped_peer(&d1, t0));
    assert!(!msg.dropped_peers_are_full());
    assert!(msg.add_dropped_peer(&d2, t0));
    assert!(msg.dropped_peers_are_full());
    assert!(msg.add_dropped_peer(&d3, t0));
    assert!(msg.dropped_peers_are_full());
}

/// Outbound cadence state machine: `DefaultBtInteractive.cc` semantics,
/// table-driven.
#[test]
fn vector_10_swarm_sender_cadence_and_gates() {
    let t0 = Instant::now();
    let interval = Duration::from_secs(60);
    let addr = v4([10, 0, 0, 9], 6881);
    let fresh = vec![PexCandidate::fresh(PexPeer::new(addr, UploadOnly::No), t0)];
    // Empty candidates: due but nothing is produced (BEP11 "Messages must
    // contain at least one of the following fields: added, added6,
    // dropped, dropped6."; aria2 enqueues an empty message unconditionally
    // — an explicit divergence, the BEP text wins).
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(1), t0);
    assert!(!sender.due(t0 + interval - Duration::from_secs(1)));
    assert!(sender.due(t0 + interval));
    assert!(
        sender.maybe_build(&[], &[], None, t0 + interval).is_none(),
        "empty candidates -> no frame (BEP11 at-least-one-key MUST)"
    );
    // Throttle: after a successful build nothing is produced within
    // interval (candidate first contact = build instant, inside the
    // freshness window).
    let cand = PexCandidate::fresh(PexPeer::new(addr, UploadOnly::No), t0 + interval);
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(1), t0);
    let (id, msg) = sender
        .maybe_build(std::slice::from_ref(&cand), &[], None, t0 + interval)
        .unwrap_or_else(|| panic!("due -> must produce"));
    assert_eq!(id, 1, "outbound uses the peer-negotiated msg id");
    assert_eq!(msg.fresh_peers().len(), 1);
    assert!(
        sender
            .maybe_build(&[cand], &[], None, t0 + interval)
            .is_none(),
        "nothing produced within interval after a reset"
    );
    // Unnegotiated (peer_msg_id=None) -> never produces.
    let mut sender = PexSwarmSender::new(PexOffer::On, None, t0);
    assert!(
        sender
            .maybe_build(&fresh, &[], None, t0 + interval)
            .is_none()
    );
    // Private / option off (enabled=false) -> never produces.
    let mut sender = PexSwarmSender::new(PexOffer::Off, Some(1), t0);
    assert!(
        sender
            .maybe_build(&fresh, &[], None, t0 + interval)
            .is_none()
    );
}

/// Candidate filtering and capacity guards: active filter / exclusion of
/// the peer's own address / capacity truncation
/// (`DefaultBtInteractive.cc`).
#[test]
fn vector_11_swarm_sender_candidate_filters() {
    let t0 = Instant::now();
    // Build instant = t0 + 60s (first send due); candidate first contacts /
    // drop entries at the same instant -> fresh.
    let t1 = t0 + Duration::from_secs(60);
    let peer_ip: IpAddr = Ipv4Addr::new(10, 9, 9, 9).into();
    let self_addr = v4([10, 9, 9, 9], 6881);
    let inactive = PexCandidate {
        active: false,
        ..PexCandidate::fresh(PexPeer::new(v4([10, 0, 0, 1], 1), UploadOnly::No), t1)
    };
    let self_peer = PexCandidate::fresh(PexPeer::new(self_addr, UploadOnly::No), t1);
    let normal = PexCandidate::fresh(PexPeer::new(v4([10, 0, 0, 2], 2), UploadOnly::No), t1);
    // active=false and the peer's own address are both skipped; normal is
    // included.
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(3), t0);
    let (_, msg) = sender
        .maybe_build(
            &[inactive, self_peer.clone(), normal],
            &[],
            Some(peer_ip),
            t1,
        )
        .unwrap_or_else(|| panic!("due -> must produce"));
    assert_eq!(
        msg.fresh_peers(),
        &[PexPeer::new(v4([10, 0, 0, 2], 2), UploadOnly::No)]
    );
    // Capacity guard: with max_fresh=1 the second candidate is cut off by
    // the loop break.
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(3), t0).with_limits(1, 50);
    let a = PexCandidate::fresh(PexPeer::new(v4([10, 0, 0, 3], 3), UploadOnly::No), t1);
    let b = PexCandidate::fresh(PexPeer::new(v4([10, 0, 0, 4], 4), UploadOnly::No), t1);
    let (_, msg) = sender
        .maybe_build(&[a, b], &[], Some(peer_ip), t1)
        .unwrap_or_else(|| panic!("due -> must produce"));
    assert_eq!(msg.fresh_peers().len(), 1);
    // The dropped side excludes the peer's own address too.
    let self_dropped = PexCandidate::dropped(self_peer.peer.clone(), t1);
    let d1 = PexCandidate::dropped(PexPeer::new(v4([10, 0, 0, 5], 5), UploadOnly::No), t1);
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(3), t0);
    let (_, msg) = sender
        .maybe_build(&[], &[self_dropped, d1], Some(peer_ip), t1)
        .unwrap_or_else(|| panic!("due -> must produce"));
    assert_eq!(
        msg.dropped_peers(),
        &[PexPeer::new(v4([10, 0, 0, 5], 5), UploadOnly::No)]
    );
    // Candidates first seen 60s before t1 are no longer fresh (60 < 60 is
    // false) -> not accepted; after filtering both lists are empty -> no
    // frame (BEP11 at-least-one-key MUST).
    let stale = PexCandidate::fresh(PexPeer::new(v4([10, 0, 0, 6], 6), UploadOnly::No), t0);
    let mut sender = PexSwarmSender::new(PexOffer::On, Some(3), t0);
    assert!(
        sender
            .maybe_build(&[stale], &[], Some(peer_ip), t1)
            .is_none(),
        "an all-empty result after filtering must produce no frame (candidates first seen exactly 60s ago are no longer fresh)"
    );
}

/// Private-torrent master gate (`PeerInteractionCommand.cc` table).
#[test]
fn vector_12_pex_offered_matrix() {
    assert!(
        pex_offered(GetMode::Torrent, PexContext::PublicEnabled),
        "public torrent + option on -> advertised"
    );
    assert!(
        !pex_offered(GetMode::Torrent, PexContext::Private),
        "private torrent -> forbidden (BEP27)"
    );
    assert!(
        !pex_offered(GetMode::Torrent, PexContext::PublicDisabled),
        "option off -> forbidden"
    );
    assert!(
        pex_offered(GetMode::Metadata, PexContext::Private),
        "metadataGetMode allowed even for private torrents (reference :233 metadataGetMode short-circuit)"
    );
    assert!(!pex_offered(GetMode::Metadata, PexContext::PublicDisabled));
}

/// Negotiation integration (dynamic registry id allocation): the peer
/// handshake dict (reference HandshakeExtensionMessageTest.cc sample)
/// decodes -> peer ids; our registry converges per `pex_offered`
/// (`DefaultBtInteractive.cc`); inbound extended frames are parsed against
/// our registry (after private removal, ut_pex frames are unparseable).
#[test]
fn vector_13_negotiation_registry_integration() {
    // Peer advertisement: ut_metadata=2, ut_pex=1 (reference byte sample).
    let peer_dict = b"d1:md11:ut_metadatai2e6:ut_pexi1ee13:metadata_sizei1024e1:v5:aria2e";
    let peer = ok(
        crate::peer_wire::ExtHandshake::decode(peer_dict),
        "peer handshake",
    );
    assert_eq!(peer.m_ut_pex, Some(1));

    // Public torrent: keep ut_pex=1 -> inbound ext_id=1 parses as ut_pex.
    let mut ours = ExtRegistry::aria2_default();
    apply_pex_negotiation(
        &mut ours,
        pex_offered(GetMode::Torrent, PexContext::PublicEnabled),
    );
    assert_eq!(
        ours.get("ut_pex"),
        Some(1),
        "public torrent keeps the advertisement"
    );
    assert_eq!(
        ours.get("ut_pex"),
        peer.m_ut_pex,
        "inbound id resolution holds"
    );

    // Private torrent: the registry removes ut_pex -> our m dict does not
    // advertise + inbound does not parse.
    let mut ours = ExtRegistry::aria2_default();
    apply_pex_negotiation(
        &mut ours,
        pex_offered(GetMode::Torrent, PexContext::Private),
    );
    assert_eq!(
        ours.get("ut_pex"),
        None,
        "a private torrent must not advertise ut_pex"
    );
    // Our outbound handshake dict contains no ut_pex.
    let hs = crate::peer_wire::ExtHandshake {
        m_ut_pex: ours.get("ut_pex"),
        m_ut_metadata: ours.get("ut_metadata"),
        ..crate::peer_wire::ExtHandshake::default()
    };
    let dict = ok(hs.encode(), "our dict");
    let ascii = ok(String::from_utf8(dict.to_vec()), "ascii");
    assert!(
        !ascii.contains("ut_pex"),
        "a private torrent's outbound dict must not contain ut_pex: {ascii}"
    );
    // Inbound ext_id=1 no longer resolves to ut_pex in our registry (the
    // getExtensionName failure path of DefaultExtensionMessageFactory).
    assert_ne!(ours.get("ut_pex"), Some(1));
}

/// Seeder flag constant and encoding (BEP11 added.f).
#[test]
fn vector_14_seeder_flag_bits() {
    assert_eq!(FLAG_SEEDER, 0x02);
    let t0 = Instant::now();
    let mut msg = PexMessage::new();
    let seeder = PexCandidate::fresh(PexPeer::new(v4([1, 2, 3, 4], 1), UploadOnly::Yes), t0);
    assert!(msg.add_fresh_peer(&seeder, t0));
    let bytes = ok(msg.encode(), "encode");
    // d5:added6:<6B>7:added.f1:\x02e -> the tail is flags + b'e'.
    assert_eq!(&bytes[bytes.len() - 2..], &[FLAG_SEEDER, b'e']);
    // Non-seeder -> 0x00.
    let mut msg = PexMessage::new();
    let leecher = PexCandidate::fresh(PexPeer::new(v4([1, 2, 3, 4], 1), UploadOnly::No), t0);
    assert!(msg.add_fresh_peer(&leecher, t0));
    let bytes = ok(msg.encode(), "encode");
    assert_eq!(&bytes[bytes.len() - 2..], &[0x00, b'e']);
}

/// Family split when v4/v6 share one list (added takes v4 / added6 takes
/// v6; createCompactPeerListAndFlag's single pass splits by family — on the
/// wire one fresh list becomes two keys, relative order within a family
/// preserved).
#[test]
fn vector_15_mixed_family_split() {
    let t0 = Instant::now();
    let mut msg = PexMessage::new();
    for addr in [v6([0x20; 16], 1), v4([1, 1, 1, 1], 2), v6([0x21; 16], 3)] {
        let cand = PexCandidate::fresh(PexPeer::new(addr, UploadOnly::No), t0);
        assert!(msg.add_fresh_peer(&cand, t0));
    }
    let bytes = ok(msg.encode(), "encode");
    // In the wire dict the added (v4 bucket) key precedes added6 (v6
    // bucket).
    let key_added: Vec<u8> = b"5:added".to_vec();
    let added_pos = bytes
        .windows(key_added.len())
        .position(|w| w == key_added.as_slice())
        .unwrap_or_else(|| panic!("added key must appear"));
    let key_added6: Vec<u8> = b"6:added6".to_vec();
    let added6_pos = bytes
        .windows(key_added6.len())
        .position(|w| w == key_added6.as_slice())
        .unwrap_or_else(|| panic!("added6 key must appear"));
    assert!(
        added_pos < added6_pos,
        "added (the v4 bucket) must precede added6"
    );
    let back = ok(PexMessage::decode(&bytes), "decode");
    // Decode rebuilds in dict order: the v4 bucket first, the v6 bucket
    // after, order within each family preserved.
    assert_eq!(back.fresh_peers().len(), 3);
    assert!(
        back.fresh_peers()[0].addr.is_ipv4(),
        "the v4 bucket must come entirely first"
    );
    assert!(back.fresh_peers()[1].addr.is_ipv6());
    assert!(back.fresh_peers()[2].addr.is_ipv6());
}

// ===== property tests: arbitrary bytes never panic (in-process twin of the
// fuzz target) =====

use proptest::prelude::*;

proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic_in_pex_decode(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = PexMessage::decode(&data);
    }
}

// ---------- added.f flag-bit completion (BEP11 bit0/bit1 tables) ----------

/// Encode vectors: combined flag bytes (bit0 encrypted / bit1 upload_only;
/// BEP11; aria2 UTPexExtensionMessage.cc's 0x02/0x00 planes are a subset).
#[test]
fn bep21_flags_encode_table() {
    // (name, encrypted, upload_only, expected flags byte).
    let rows: Vec<(&str, PrefersEncryption, UploadOnly, u8)> = vec![
        ("neither", PrefersEncryption::No, UploadOnly::No, 0x00),
        (
            "encrypted only (bit0)",
            PrefersEncryption::Yes,
            UploadOnly::No,
            FLAG_ENCRYPTED,
        ),
        (
            "upload_only only (bit1)",
            PrefersEncryption::No,
            UploadOnly::Yes,
            FLAG_SEEDER,
        ),
        (
            "both bits",
            PrefersEncryption::Yes,
            UploadOnly::Yes,
            FLAG_ENCRYPTED | FLAG_SEEDER,
        ),
    ];
    let t0 = Instant::now();
    for (name, enc, uo, expect) in rows {
        let mut msg = PexMessage::new();
        let cand =
            PexCandidate::fresh(PexPeer::with_flags(v4([203, 0, 113, 9], 6881), enc, uo), t0);
        assert!(msg.add_fresh_peer(&cand, t0), "{name}");
        let bytes = ok(msg.encode(), name);
        // added.f is the last segment (6B address + 1B flag; the dict
        // closer 'e' follows -> second-to-last byte).
        assert_eq!(&bytes[bytes.len() - 2], &expect, "{name}");
    }
    // Reserved bits are not produced (only bit0/bit1 are written).
    let mut msg = PexMessage::new();
    let cand = PexCandidate::fresh(
        PexPeer {
            addr: v4([203, 0, 113, 10], 6881),
            encrypted: PrefersEncryption::Yes,
            upload_only: UploadOnly::Yes,
        },
        t0,
    );
    assert!(msg.add_fresh_peer(&cand, t0));
    let bytes = ok(msg.encode(), "no reserved bits");
    assert_eq!(&bytes[bytes.len() - 2], &0x03);
}

/// Decode vectors: flags paired per unit + leniency matrix (missing = 0;
/// short strings pair on the short side; added.f / added6.f pair
/// independently for v4/v6).
#[test]
fn bep21_flags_decode_table() {
    // Two v4 units + two flag bytes: (encrypted, upload_only) combinations
    // read bit by bit.
    let payload = b"d5:added12:\x01\x02\x03\x04\x1a\xe1\x05\x06\x07\x08\x1a\xe2\
                   7:added.f2:\x01\x03e";
    let msg = ok(PexMessage::decode(payload.as_slice()), "paired flags");
    assert_eq!(msg.fresh_peers().len(), 2);
    assert_eq!(
        (
            msg.fresh_peers()[0].encrypted,
            msg.fresh_peers()[0].upload_only
        ),
        (PrefersEncryption::Yes, UploadOnly::No),
        "0x01 = bit0"
    );
    assert_eq!(
        (
            msg.fresh_peers()[1].encrypted,
            msg.fresh_peers()[1].upload_only
        ),
        (PrefersEncryption::Yes, UploadOnly::Yes),
        "0x03 = bit0|bit1"
    );
    // Flags missing -> all false (lenient).
    let payload = b"d5:added6:\x01\x02\x03\x04\x1a\xe1e";
    let msg = ok(PexMessage::decode(payload.as_slice()), "no flags");
    assert_eq!(
        (
            msg.fresh_peers()[0].encrypted,
            msg.fresh_peers()[0].upload_only
        ),
        (PrefersEncryption::No, UploadOnly::No)
    );
    // Short flags string (1B for 2 units) -> pair on the short side; the
    // remaining unit = 0.
    let payload = b"d5:added12:\x01\x02\x03\x04\x1a\xe1\x05\x06\x07\x08\x1a\xe2\
                   7:added.f1:\x02e";
    let msg = ok(PexMessage::decode(payload.as_slice()), "short flags");
    assert_eq!(
        (
            msg.fresh_peers()[0].encrypted,
            msg.fresh_peers()[0].upload_only
        ),
        (PrefersEncryption::No, UploadOnly::Yes),
        "the first unit consumes 0x02"
    );
    assert_eq!(
        (
            msg.fresh_peers()[1].encrypted,
            msg.fresh_peers()[1].upload_only
        ),
        (PrefersEncryption::No, UploadOnly::No),
        "out of bounds = 0"
    );
    // v6 pairs added6.f independently.
    let payload =
        b"d6:added618:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
                   8:added6.f1:\x02e";
    let msg = ok(PexMessage::decode(payload.as_slice()), "v6 flags");
    assert_eq!(msg.fresh_peers().len(), 1);
    assert_eq!(
        (
            msg.fresh_peers()[0].upload_only,
            msg.fresh_peers()[0].encrypted
        ),
        (UploadOnly::Yes, PrefersEncryption::No)
    );
}

/// Codec roundtrip: both flag bits survive (all encrypted/upload_only
/// combinations).
#[test]
fn bep21_flags_roundtrip_all_combinations() {
    let t0 = Instant::now();
    for enc in [PrefersEncryption::No, PrefersEncryption::Yes] {
        for uo in [UploadOnly::No, UploadOnly::Yes] {
            let mut msg = PexMessage::new();
            let cand =
                PexCandidate::fresh(PexPeer::with_flags(v4([192, 168, 7, 1], 6881), enc, uo), t0);
            assert!(msg.add_fresh_peer(&cand, t0));
            let back = ok(PexMessage::decode(&ok(msg.encode(), "enc")), "dec");
            assert_eq!(
                back.fresh_peers(),
                msg.fresh_peers(),
                "enc={enc:?} uo={uo:?}"
            );
        }
    }
}

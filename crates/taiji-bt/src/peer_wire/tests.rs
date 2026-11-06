//! Cross-validation vectors and tests, each annotated with its aria2 source.

use bytes::{BufMut, BytesMut};
use tokio_util::codec::Decoder;

use super::*;

/// Test-only unwrappers for Result/Option (the lint bans unwrap/expect).
fn ok<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e:?}"),
    }
}

fn some<T>(v: Option<T>, what: &str) -> T {
    match v {
        Some(v) => v,
        None => panic!("{what}: expected Some"),
    }
}

/// Framing mirrors aria2 bittorrent::createPeerMessageString plus
/// setIntParam/setShortIntParam (test/BtConstants.h): 4B big-endian payload
/// length + 1B id + fields.
fn frame(id: u8, payload: &[u8]) -> BytesMut {
    let mut f = BytesMut::new();
    f.put_u32(payload.len() as u32 + 1);
    f.put_u8(id);
    f.extend_from_slice(payload);
    f
}

fn u32be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

fn body_of(msg: &Message) -> Message {
    // Encode-decode roundtrip helper: strip the 4B prefix and decode the body.
    let full = msg.encode();
    ok(Message::decode_body(&full[4..]), "roundtrip body decode")
}

/// Registry of cross-validation vectors, including negatives, one per test below.
const VECTORS: &[&str] = &[
    "V01 handshake parse + re-encode (BtHandshakeMessageTest createHandshakeMessageData)",
    "V02 handshake default reserved layout (BtHandshakeMessage.cc init)",
    "V03 handshake rejects wrong pstr",
    "V04 handshake rejects truncated",
    "V05 reserved DHT bit (isDHTEnabled)",
    "V06 reserved v2 upgrade bit",
    "V07 keepalive zero-length frame decode",
    "V08 keepalive encode",
    "V09 choke create",
    "V10 choke negative payload 2B",
    "V11 interested",
    "V12 not_interested",
    "V13 have index=12345",
    "V14 have negative payload 6B",
    "V15 have roundtrip",
    "V16 bitfield min payload",
    "V17 bitfield negative empty payload",
    "V18 bitfield roundtrip multi-byte",
    "V19 request (12345,256,1024)",
    "V20 request negative payload 14B",
    "V21 cancel same layout",
    "V22 cancel id byte = 8",
    "V23 piece (12345,256,[0xff,0xff])",
    "V24 piece negative payload <8",
    "V25 piece zero-length block legal",
    "V26 port=12345",
    "V27 port negative payload 4B",
    "V28 unknown message id rejected",
    "V29 ext handshake sample :67 (ut_metadata=2, ut_pex=1, metadata_size=1024)",
    "V30 ext handshake sample :67 client version aria2",
    "V31 ext handshake sample :137 (int port 6881, unknown ext ignored)",
    "V32 ext handshake sample :180 stringnum fields ignored",
    "V33 ext handshake encode canonical + roundtrip + key order",
    "V34 ext handshake extended frame roundtrip",
    "V35 frame codec partial delivery",
    "V36 frame codec rejects oversized prefix",
    "V37 frame codec two frames back to back",
    "V38 registry default (ut_metadata=2, ut_pex=1)",
    "V39 registry set/remove + unknown name",
    "V40 ext handshake negative non-dict payload",
    "V41 ext handshake negative empty payload",
    "V42 frame codec one-shot exact reservation",
];

#[test]
fn vector_count_meets_cross_check_budget() {
    assert!(
        VECTORS.len() >= 30,
        "cross-validation vectors {} < 30",
        VECTORS.len()
    );
    for desc in VECTORS {
        assert!(!desc.is_empty());
    }
}

// ---------- handshake (BtHandshakeMessageTest.cc testCreate/testCreateMessage) ----------

#[test]
fn vector_01_handshake_create_from_reference_bytes() {
    // Source: aria2 BtHandshakeMessageTest.cc createHandshakeMessageData.
    let mut raw = [0u8; 68];
    raw[0] = 19;
    raw[1..20].copy_from_slice(b"BitTorrent protocol");
    raw[20..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04]);
    raw[28..48].fill(0xff);
    raw[48..68].fill(0xf0);
    let hs = ok(Handshake::decode(&raw), "reference handshake must parse");
    assert_eq!(
        hs.reserved,
        ok(
            Reserved::from_bytes(&[0, 0, 0, 0, 0, 0x10, 0, 0x04]),
            "8B reserved"
        )
    );
    assert!(hs.reserved.supports_extended());
    assert!(hs.reserved.supports_fast());
    assert!(!hs.reserved.supports_dht());
    assert_eq!(hs.info_hash, [0xff; 20]);
    assert_eq!(hs.peer_id, [0xf0; 20]);
    // Roundtrip: re-encoding matches the reference bytes (testCreateMessage).
    assert_eq!(hs.encode(), raw);
}

#[test]
fn vector_02_handshake_default_reserved_layout() {
    // Source: aria2 BtHandshakeMessage.cc init() — fast = [7]|0x04, ext = [5]|0x10.
    let hs = Handshake {
        reserved: Reserved::aria2_default(),
        info_hash: [0; 20],
        peer_id: [0; 20],
    };
    let raw = hs.encode();
    assert_eq!(&raw[20..28], &[0, 0, 0, 0, 0, 0x10, 0, 0x04]);
}

#[test]
fn vector_03_handshake_rejects_wrong_pstr() {
    // Strict check: a pstr other than the BEP3 fixed prefix is rejected.
    let mut raw = Handshake {
        reserved: Reserved::empty(),
        info_hash: [0; 20],
        peer_id: [0; 20],
    }
    .encode();
    raw[1] = b'X';
    assert!(matches!(
        Handshake::decode(&raw),
        Err(PeerWireError::InvalidHandshake(_))
    ));
}

#[test]
fn vector_04_handshake_rejects_truncated() {
    // Negative: fewer than 68 bytes.
    assert!(matches!(
        Handshake::decode(&[0u8; 67]),
        Err(PeerWireError::InvalidHandshake(_))
    ));
}

#[test]
fn vector_05_reserved_dht_bit() {
    // Source: aria2 BtHandshakeMessage.cc isDHTEnabled = [7]&0x01.
    let mut r = Reserved::empty();
    r.0[7] |= 0x01;
    assert!(r.supports_dht());
    assert!(!r.supports_fast());
}

#[test]
fn vector_06_reserved_v2_upgrade_bit() {
    // Source: the libtorrent convention reserved[7]&0x10 (BEP52 upgrade path).
    let mut r = Reserved::empty();
    r.0[7] |= 0x10;
    assert!(r.supports_v2());
    // Independent of the fast bit ([7]&0x04).
    assert!(!r.supports_fast());
}

// ---------- keepalive (BtKeepAliveMessageTest) ----------

#[test]
fn vector_07_keepalive_is_zero_length_frame() {
    // Source: aria2 BtKeepAliveMessageTest (zero-length frame).
    let mut f = BytesMut::new();
    f.put_u32(0);
    let mut codec = FrameCodec::default();
    let msg = some(
        codec
            .decode(&mut f)
            .map_err(|e| panic!("keepalive: {e:?}"))
            .ok(),
        "keepalive frame",
    );
    assert_eq!(msg, Some(Message::KeepAlive));
}

#[test]
fn vector_08_keepalive_encode() {
    assert_eq!(&Message::KeepAlive.encode()[..], &[0, 0, 0, 0]);
}

// ---------- choke/unchoke/interested/not_interested (BtChokeMessageTest) ----------

#[test]
fn vectors_09_10_choke_create_and_negative() {
    // Source: aria2 BtChokeMessageTest::testCreate — a 1-byte payload with
    // id=0 is legal; payload=2 or id=1 rejected (negatives).
    let f = frame(0, &[]);
    assert_eq!(ok(Message::decode_body(&f[4..]), "choke"), Message::Choke);
    // Negative 1: 2-byte payload.
    let bad = frame(0, &[0x00, 0x00]);
    assert!(matches!(
        Message::decode_body(&bad[4..]),
        Err(PeerWireError::InvalidPayload { id: 0, .. })
    ));
    // Negative 2: a shifted id is covered by frame-level id dispatch (id=1 parses as unchoke).
    let as_unchoke = frame(1, &[]);
    assert_eq!(
        ok(Message::decode_body(&as_unchoke[4..]), "unchoke"),
        Message::Unchoke
    );
}

#[test]
fn vectors_11_12_interested_not_interested() {
    // Source: aria2 BtInterestedMessageTest / BtNotInterestedMessageTest,
    // same shape (empty payload).
    assert_eq!(
        Message::decode_body(&frame(2, &[])[4..]),
        Ok(Message::Interested)
    );
    assert_eq!(
        Message::decode_body(&frame(3, &[])[4..]),
        Ok(Message::NotInterested)
    );
}

// ---------- have (BtHaveMessageTest::testCreate) ----------

#[test]
fn vectors_13_14_have_index_12345_and_negative() {
    // Source: aria2 BtHaveMessageTest — 4B payload, index=12345;
    // 6B payload or id=5 rejected.
    let f = frame(4, &u32be(12345));
    assert_eq!(
        Message::decode_body(&f[4..]),
        Ok(Message::Have { index: 12345 })
    );
    let mut bad6 = u32be(12345).to_vec();
    bad6.extend_from_slice(&[0, 0]); // 6B payload: reference negative (wrong size)
    let bad = frame(4, &bad6);
    assert!(matches!(
        Message::decode_body(&bad[4..]),
        Err(PeerWireError::InvalidPayload { id: 4, .. })
    ));
}

#[test]
fn vector_15_have_roundtrip() {
    assert_eq!(
        body_of(&Message::Have { index: 7 }),
        Message::Have { index: 7 }
    );
}

// ---------- bitfield (BtBitfieldMessageTest) ----------

#[test]
fn vectors_16_17_bitfield_min_payload_and_empty_negative() {
    // Source: aria2 BtBitfieldMessage::create (payload of at least 1 byte);
    // empty payload rejected.
    let f = frame(5, &[0b1010_1010]);
    assert_eq!(
        Message::decode_body(&f[4..]),
        Ok(Message::Bitfield {
            bits: Bytes::from_static(&[0b1010_1010])
        })
    );
    let bad = frame(5, &[]);
    assert!(matches!(
        Message::decode_body(&bad[4..]),
        Err(PeerWireError::InvalidPayload { id: 5, .. })
    ));
}

#[test]
fn vector_18_bitfield_roundtrip_multi_byte() {
    let msg = Message::Bitfield {
        bits: Bytes::from(vec![0xff, 0x00, 0xaa, 0x55]),
    };
    assert_eq!(body_of(&msg), msg);
}

// ---------- request/cancel (BtRequestMessageTest/BtCancelMessageTest) ----------

#[test]
fn vectors_19_20_request_12345_256_1024_and_negative() {
    // Source: aria2 BtRequestMessageTest::testCreate — (12345, 256, 1k);
    // 14B payload rejected.
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32be(12345));
    payload.extend_from_slice(&u32be(256));
    payload.extend_from_slice(&u32be(1024));
    let f = frame(6, &payload);
    assert_eq!(
        Message::decode_body(&f[4..]),
        Ok(Message::Request {
            index: 12345,
            begin: 256,
            length: 1024
        })
    );
    let mut bad = payload.clone();
    bad.push(0);
    let bf = frame(6, &bad);
    assert!(matches!(
        Message::decode_body(&bf[4..]),
        Err(PeerWireError::InvalidPayload { id: 6, .. })
    ));
}

#[test]
fn vectors_21_22_cancel_same_layout_and_roundtrip() {
    // Source: aria2 BtCancelMessageTest — same layout as request, id=8.
    let msg = Message::Cancel {
        index: 9,
        begin: 1,
        length: 16384,
    };
    assert_eq!(body_of(&msg), msg);
    let encoded = msg.encode();
    assert_eq!(&encoded[4], &8u8.to_be_bytes()[0]);
}

// ---------- piece (BtPieceMessageTest::testCreate) ----------

#[test]
fn vectors_23_24_piece_12345_256_ff_block_and_negative() {
    // Source: aria2 BtPieceMessageTest — (12345, 256, [0xff,0xff]);
    // 9B payload (no block, under 8) rejected.
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32be(12345));
    payload.extend_from_slice(&u32be(256));
    payload.extend_from_slice(&[0xff, 0xff]);
    let f = frame(7, &payload);
    assert_eq!(
        ok(Message::decode_body(&f[4..]), "piece"),
        Message::Piece {
            index: 12345,
            begin: 256,
            block: Bytes::from_static(&[0xff, 0xff])
        }
    );
    let short = frame(7, &[0, 0, 0, 1]);
    assert!(matches!(
        Message::decode_body(&short[4..]),
        Err(PeerWireError::InvalidPayload { id: 7, .. })
    ));
}

#[test]
fn vector_25_piece_zero_length_block_is_legal() {
    // A piece payload of 8+ bytes is enough; a zero-length block is legal
    // (aria2 create only checks dataLength < 8).
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32be(1));
    payload.extend_from_slice(&u32be(2));
    let f = frame(7, &payload);
    assert_eq!(
        Message::decode_body(&f[4..]),
        Ok(Message::Piece {
            index: 1,
            begin: 2,
            block: Bytes::new()
        })
    );
}

// ---------- port (BtPortMessageTest::testCreate) ----------

#[test]
fn vectors_26_27_port_12345_and_negative() {
    // Source: aria2 BtPortMessageTest — 2B payload, port=12345;
    // 4B payload rejected.
    let f = frame(9, &12345u16.to_be_bytes());
    assert_eq!(
        Message::decode_body(&f[4..]),
        Ok(Message::Port { port: 12345 })
    );
    let bad = frame(9, &[0, 1, 2, 3]);
    assert!(matches!(
        Message::decode_body(&bad[4..]),
        Err(PeerWireError::InvalidPayload { id: 9, .. })
    ));
}

// ---------- unknown id ----------

#[test]
fn vector_28_unknown_message_id_rejected() {
    // Defense: an id outside the BEP3/BEP5/BEP10 tables yields UnknownMessageId.
    let f = frame(42, &[0]);
    assert_eq!(
        Message::decode_body(&f[4..]),
        Err(PeerWireError::UnknownMessageId(42))
    );
}

// ---------- BEP10 extended handshake (HandshakeExtensionMessageTest.cc) ----------

#[test]
fn vectors_29_30_ext_handshake_parse_reference_sample() {
    // Source: aria2 HandshakeExtensionMessageTest.cc sample
    // "d1:md11:ut_metadatai2e6:ut_pexi1ee13:metadata_sizei1024e1:v5:aria2e".
    let dict = b"d1:md11:ut_metadatai2e6:ut_pexi1ee13:metadata_sizei1024e1:v5:aria2e";
    let hs = ok(ExtHandshake::decode(dict), "reference ext handshake");
    assert_eq!(hs.m_ut_metadata, Some(2));
    assert_eq!(hs.m_ut_pex, Some(1));
    assert_eq!(hs.metadata_size, Some(1024));
    assert_eq!(hs.v.as_deref(), Some("aria2"));
}

#[test]
fn vectors_31_32_ext_handshake_reference_port_and_stringnum() {
    // Source: aria2 HandshakeExtensionMessageTest.cc.
    // The reference create() skips the first byte (ext msg id); the dict
    // starts at byte 2. "p" is Integer(i6881e) -> 6881; unknown ext name
    // a2dh is ignored.
    let with_port = b"0d1:pi6881e1:v5:aria21:md5:a2dhti2e6:ut_pexi1ee13:metadata_sizei1024ee";
    let hs = ok(ExtHandshake::decode(&with_port[1..]), "sample :137");
    assert_eq!(hs.p, Some(6881));
    assert!(hs.m_ut_metadata.is_none());
    assert_eq!(hs.m_ut_pex, Some(1));
    assert_eq!(hs.metadata_size, Some(1024));

    // testCreate_stringnum: string-typed port/ext ids are not allowed (reference asserts 0).
    let stringnum = b"0d1:p4:68811:v5:aria21:md6:ut_pex1:1ee";
    let hs2 = ok(ExtHandshake::decode(&stringnum[1..]), "sample :180");
    assert_eq!(
        hs2.p, None,
        "string-typed port must be ignored (reference: getTCPPort()==0)"
    );
    assert_eq!(hs2.m_ut_pex, None, "string-typed ext id must be ignored");
    assert_eq!(hs2.v.as_deref(), Some("aria2"));
}

/// BEP10: an m-dict value of 0 means the extension is disabled — "Setting
/// an extension number to zero means that the extension is not
/// supported/disabled." (verbatim BEP10; 0 is also the reserved id of the
/// ext handshake itself: "0 = handshake, >0 = extended message"). Decoding
/// must filter 0 to None: Some(0) would read as a valid advertised id —
/// PEX would send Extended{0} (pex/mod.rs maybe_build), ut_holepunch would
/// mirror-enable (ext.rs is_some), and ut_metadata would still build a
/// fetch session (ext.rs m_ut_metadata arm).
#[test]
fn ext_handshake_m_dict_zero_id_means_disabled() {
    let dict = b"d1:md6:ut_pexi0e11:ut_metadatai0e12:ut_holepunchi0eee";
    let hs = ok(ExtHandshake::decode(dict), "m=0 ext handshake");
    assert_eq!(
        hs.m_ut_pex, None,
        "ut_pex=0 must be filtered out as disabled (BEP10)"
    );
    assert_eq!(
        hs.m_ut_metadata, None,
        "ut_metadata=0 must be filtered out as disabled (BEP10)"
    );
    assert_eq!(
        hs.m_ut_holepunch, None,
        "ut_holepunch=0 must be filtered out as disabled (BEP10)"
    );
}

#[test]
fn vector_33b_ext_handshake_rejects_non_dict_and_empty() {
    // Source: aria2 HandshakeExtensionMessageTest.cc testCreate negatives.
    // "011:hello world" = id byte '0' + invalid body; zero-length payload rejected.
    let bad = b"011:hello world";
    assert!(ExtHandshake::decode(&bad[1..]).is_err());
    assert!(ExtHandshake::decode(b"").is_err());
}

#[test]
fn vector_33_ext_handshake_encode_canonical_and_roundtrip() {
    let hs = ExtHandshake {
        m_ut_metadata: Some(2),
        m_ut_pex: Some(1),
        // Default None = the m dict omits the ut_holepunch key.
        m_ut_holepunch: None,
        p: Some(6881),
        v: Some("taiji/0.1.0".into()),
        metadata_size: Some(1024),
        reqq: Some(250),
        // BEP21 upload_only default false = the key is not sent.
        upload_only: false,
    };
    let bytes = ok(hs.encode(), "ext handshake encode");
    // Canonical form: decode(encode(x)) == x.
    let back = ok(ExtHandshake::decode(&bytes), "ext handshake roundtrip");
    assert_eq!(back, hs);
    // Keys in ascending byte order: m < metadata_size < p < reqq < v.
    let s = ok(String::from_utf8(bytes.to_vec()), "ascii");
    let m_pos = some(s.find("1:md"), "m key");
    let ms_pos = some(s.find("13:metadata_size"), "metadata_size key");
    let p_pos = some(s.find("1:p"), "p key");
    let rq_pos = some(s.find("4:reqq"), "reqq key");
    let v_pos = some(s.find("1:v"), "v key");
    assert!(m_pos < ms_pos && ms_pos < p_pos && p_pos < rq_pos && rq_pos < v_pos);
}

#[test]
fn vector_34_ext_handshake_extended_frame_roundtrip() {
    // Full-frame roundtrip with ext_id=0 (the BEP10 handshake id).
    let hs = ExtHandshake {
        m_ut_pex: Some(1),
        ..ExtHandshake::default()
    };
    let dict = ok(hs.encode(), "dict encode");
    let msg = Message::Extended {
        ext_id: 0,
        payload: dict,
    };
    let frame_bytes = msg.encode();
    let mut codec = FrameCodec::default();
    let decoded = some(
        codec
            .decode(&mut BytesMut::from(frame_bytes.as_ref()))
            .map_err(|e| panic!("no err: {e:?}"))
            .ok(),
        "extended frame",
    );
    assert_eq!(decoded, Some(msg));
}

// ---------- frame layer (FrameCodec: partial delivery / oversized guard) ----------

#[test]
fn vector_35_framecodec_partial_delivery() {
    // The frame body arrives in two chunks: first decode returns None, the second completes.
    let mut codec = FrameCodec::default();
    let mut src = BytesMut::new();
    src.put_u32(5);
    src.put_u8(4);
    src.extend_from_slice(&[0, 0]); // only 2 of 4 payload bytes so far
    let first = codec
        .decode(&mut src)
        .map_err(|e| panic!("no err: {e:?}"))
        .ok();
    assert!(
        first.clone().flatten().is_none(),
        "partial frame must return None, got {first:?}"
    );
    src.extend_from_slice(&u32be(9)[2..]); // remaining 2 bytes
    let m = some(
        codec
            .decode(&mut src)
            .map_err(|e| panic!("no err: {e:?}"))
            .ok(),
        "have frame",
    );
    assert_eq!(m, Some(Message::Have { index: 9 }));
}

#[test]
fn vector_36_framecodec_rejects_oversized_prefix() {
    // Guard: a length prefix above MAX_FRAME_LEN yields FrameTooLarge (disconnect).
    let mut src = BytesMut::new();
    src.put_u32((MAX_FRAME_LEN + 1) as u32);
    let mut codec = FrameCodec::default();
    assert!(matches!(
        codec.decode(&mut src),
        Err(PeerWireError::FrameTooLarge { .. })
    ));
}

#[test]
fn vector_37_framecodec_two_frames_back_to_back() {
    let mut codec = FrameCodec::default();
    let mut src = BytesMut::new();
    src.extend_from_slice(&Message::Choke.encode());
    src.extend_from_slice(&Message::Unchoke.encode());
    assert_eq!(
        some(
            codec.decode(&mut src).map_err(|e| panic!("ok: {e:?}")).ok(),
            "choke frame"
        ),
        Some(Message::Choke)
    );
    assert_eq!(
        some(
            codec.decode(&mut src).map_err(|e| panic!("ok: {e:?}")).ok(),
            "unchoke frame"
        ),
        Some(Message::Unchoke)
    );
}

/// Mechanism: after a length prefix is parsed, the shared
/// Framed buffer is grown by one exact reservation covering the whole
/// announced body — decode returning `None` on a missing body still
/// leaves `capacity >= announced length`, so the next read pulls the
/// entire frame in one shot (the pre-fix shape grew by per-poll doubling:
/// a 16KiB body cost ~9 grow-copy steps and as many short reads). Small
/// frames keep a small buffer (no over-growth face).
#[test]
fn vector_42_framecodec_exact_reserve_on_prefix() {
    let mut codec = FrameCodec::default();
    let mut src = BytesMut::new();
    src.put_u32(16 * 1024 + 9); // piece frame: 9B header + 16KiB body
    src.put_u8(7); // piece id byte arrived, coords + body still missing
    let pending = codec
        .decode(&mut src)
        .map_err(|e| panic!("partial decode must not err: {e:?}"))
        .ok()
        .flatten();
    assert!(
        pending.is_none(),
        "incomplete body -> None (got {pending:?})"
    );
    assert!(
        src.capacity() >= 16 * 1024 + 9,
        "one-shot reservation: capacity {} must cover the announced frame",
        src.capacity()
    );
    // Small frame: capacity stays under the 1KiB idle bar (no growth at
    // all once the frame is already buffered).
    let mut codec2 = FrameCodec::default();
    let mut src2 = BytesMut::new();
    src2.extend_from_slice(&Message::Choke.encode());
    assert_eq!(
        some(
            codec2
                .decode(&mut src2)
                .map_err(|e| panic!("ok: {e:?}"))
                .ok(),
            "choke frame"
        ),
        Some(Message::Choke)
    );
    assert!(
        src2.capacity() < 1024,
        "small frame keeps a small buffer (capacity {})",
        src2.capacity()
    );
}

// ---------- registry (ExtensionMessageRegistry) ----------

#[test]
fn vectors_38_39_registry_default_and_name_table() {
    // Source: aria2 ExtensionMessageRegistry.cc EXTENSION_NAMES={"ut_metadata","ut_pex"};
    // HandshakeExtensionMessageTest outbound sample ut_metadata=2, ut_pex=1.
    let reg = ExtRegistry::aria2_default();
    assert_eq!(reg.get("ut_metadata"), Some(2));
    assert_eq!(reg.get("ut_pex"), Some(1));
    assert_eq!(
        reg.get("ut_holepunch"),
        None,
        "not in the name table, not registered"
    );
    let mut reg2 = ExtRegistry::empty();
    reg2.set("ut_pex", 1);
    assert_eq!(reg2.get("ut_pex"), Some(1));
    reg2.remove("ut_pex");
    assert_eq!(reg2.get("ut_pex"), None);
}

// ---------- hardening: ExtHandshake out-of-domain integers ----------

#[test]
fn ext_handshake_out_of_domain_integers_treated_absent() {
    // Negative/out-of-domain bencode integers would silently truncate to
    // the target width (i-1e -> 255, i300e -> 44, i65536e -> 0, ...) and
    // forge wrong ext ids/ports/metadata_size. Contract: a value outside
    // the target integer domain is treated as absent (None).
    let bad =
        b"d13:metadata_sizei4294967296e1:md11:ut_metadatai300e6:ut_pexi-1ee1:pi-1e4:reqqi-5ee";
    let hs = ok(ExtHandshake::decode(bad), "out-of-domain ext handshake");
    assert_eq!(hs.m_ut_metadata, None, "i300e used to truncate to 44");
    assert_eq!(hs.m_ut_pex, None, "i-1e used to truncate to 255");
    assert_eq!(hs.p, None, "i-1e used to truncate to 65535");
    assert_eq!(hs.metadata_size, None, "2^32 used to wrap to 0");
    assert_eq!(hs.reqq, None, "i-5e used to truncate to a huge u32");
    // In-domain boundary values pass through (the guard must not reject legal input).
    let edge = b"d13:metadata_sizei4294967295e1:md11:ut_metadatai255e6:ut_pexi1ee1:pi65535e4:reqqi4294967295ee";
    let hs2 = ok(ExtHandshake::decode(edge), "in-domain ext handshake");
    assert_eq!(hs2.m_ut_metadata, Some(255));
    assert_eq!(hs2.m_ut_pex, Some(1));
    assert_eq!(hs2.p, Some(65535));
    assert_eq!(hs2.metadata_size, Some(u32::MAX));
    assert_eq!(hs2.reqq, Some(u32::MAX));
}

// ---------- property tests (proptest: arbitrary bytes never panic + roundtrip) ----------

use proptest::prelude::*;

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic_in_body_decode(data in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = Message::decode_body(&data);
    }

    #[test]
    fn arbitrary_bytes_never_panic_in_handshake_decode(data in proptest::collection::vec(any::<u8>(), 0..128)) {
        let _ = Handshake::decode(&data);
    }

    #[test]
    fn encoded_frames_always_decode_back(id in 0u8..=30, payload in proptest::collection::vec(any::<u8>(), 1..64)) {
        // Structurally valid messages (built per id) must roundtrip through FrameCodec.
        let msg = match id {
            0 => Message::Choke,
            1 => Message::Unchoke,
            2 => Message::Interested,
            3 => Message::NotInterested,
            4 => Message::Have { index: 5 },
            5 => Message::Bitfield { bits: Bytes::from(payload.clone()) },
            6 => Message::Request { index: 1, begin: 2, length: 3 },
            7 => Message::Piece { index: 1, begin: 2, block: Bytes::from(payload.clone()) },
            8 => Message::Cancel { index: 1, begin: 2, length: 3 },
            9 => Message::Port { port: 6881 },
            _ => Message::Extended { ext_id: 0, payload: Bytes::from(payload.clone()) },
        };
        let mut codec = FrameCodec::default();
        let mut src = BytesMut::from(msg.encode().as_ref());
        let got = some(codec.decode(&mut src).map_err(|e| panic!("decode must not error: {e:?}")).ok(), "decoded frame");
        assert_eq!(got, Some(msg));
    }
}

// ---------- BEP21 upload_only (table-driven; sources in the ExtHandshake docs) ----------

/// Encode table: the seed state sends `upload_only` i1 (BEP21 "Setting the
/// value of this key to 1"); the default state omits the key (libtorrent
/// bt_peer_connection.cpp writes the key only when set). Key order is
/// ascending byte order (upload_only < v).
#[test]
fn bep21_upload_only_encode_table() {
    // (name, upload_only, expected dict bytes).
    let rows: Vec<(&str, bool, &[u8])> = vec![
        // Set: the 11:upload_onlyi1e key is present (BEP21 value is always 1).
        (
            "seed state advertises upload_only=1",
            true,
            b"d11:upload_onlyi1e".as_slice(),
        ),
        // Default: key omitted (0 carries no meaning — BEP21 defines only 1).
        ("default omits key", false, b"d".as_slice()),
    ];
    for (name, flag, expect_prefix) in rows {
        let hs = ExtHandshake {
            upload_only: flag,
            ..ExtHandshake::default()
        };
        let bytes = ok(hs.encode(), name);
        let s = ok(String::from_utf8(bytes.to_vec()), "ascii");
        let prefix = some(
            std::str::from_utf8(expect_prefix).ok(),
            "expect_prefix utf8",
        );
        assert!(s.starts_with(prefix), "{name}: {s}");
    }
    // Key order: upload_only after reqq and before v (byte order 'r' < 'u' < 'v').
    let full = ExtHandshake {
        reqq: Some(250),
        v: Some("taiji/0.1.0".into()),
        upload_only: true,
        ..ExtHandshake::default()
    };
    let bytes = ok(full.encode(), "full encode");
    let s = ok(String::from_utf8(bytes.to_vec()), "ascii");
    let rq = some(s.find("4:reqq"), "reqq");
    let uo = some(s.find("11:upload_only"), "upload_only");
    let v = some(s.find("1:v"), "v");
    assert!(
        rq < uo && uo < v,
        "canonical order reqq < upload_only < v: {s}"
    );
}

/// Decode table: a nonzero integer is true (libtorrent
/// bt_peer_connection.cpp `dict_find_int_value("upload_only", 0)` applies
/// the same truthiness); missing is false; non-Int values are ignored
/// (BEP10 interop).
#[test]
fn bep21_upload_only_decode_table() {
    let rows: Vec<(&str, &[u8], bool)> = vec![
        ("value 1", b"d11:upload_onlyi1ee", true),
        ("nonzero truthy", b"d11:upload_onlyi2ee", true),
        ("zero is false", b"d11:upload_onlyi0ee", false),
        ("absent key", b"de", false),
        ("non-int value ignored", b"d11:upload_only3:yese", false),
    ];
    for (name, payload, expect) in rows {
        let hs = ok(ExtHandshake::decode(payload), name);
        assert_eq!(hs.upload_only, expect, "{name}");
    }
    // Roundtrip consistency.
    let hs = ExtHandshake {
        upload_only: true,
        ..ExtHandshake::default()
    };
    let bytes = ok(hs.encode(), "roundtrip encode");
    let back = ok(ExtHandshake::decode(&bytes), "roundtrip");
    assert_eq!(back, hs);
}

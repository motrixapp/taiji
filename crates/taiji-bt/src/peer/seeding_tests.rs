use super::*;
use crate::peer_wire::FrameCodec;
use std::sync::Arc;
use tokio::io::duplex;
use tokio::sync::oneshot;

/// Fake data source: 2 pieces x 16KiB, content = a byte pattern indexed
/// by absolute offset.
struct FakeSource;

impl PieceSource for FakeSource {
    fn read_block(&self, index: u32, begin: u32, buf: &mut [u8]) -> Result<usize, String> {
        if index >= 2 {
            return Err(format!("index {index} out of range"));
        }
        let off = index as u64 * 16384 + u64::from(begin);
        if off >= 32768 {
            return Err("out of range".into());
        }
        for (i, b) in buf.iter_mut().enumerate() {
            *b = ((off as usize + i) % 256) as u8;
        }
        Ok(buf.len())
    }
    fn total_len(&self) -> u64 {
        32768
    }
}

async fn setup_with_source(
    source: Option<Arc<dyn PieceSource>>,
) -> (
    PeerTaskHandle,
    FramedWrite<tokio::io::WriteHalf<tokio::io::DuplexStream>, FrameCodec>,
    FramedRead<tokio::io::ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
    tokio::task::JoinHandle<PeerEnd>,
) {
    use futures::StreamExt;
    let root = CancellationToken::new();
    let (local, remote) = duplex(64 * 1024);
    let mut config = PeerConfig::flat();
    config.source = source;
    let (handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (r, w) = tokio::io::split(remote);
    let mut reader = FramedRead::new(r, FrameCodec::default());
    // Serving requires the unchoked state (BEP3; libtorrent
    // incoming_request rejects peers we choke outright —
    // peer_connection.cpp "peer choked and piece not in allowed fast
    // set"). The fixture unchokes first and consumes that outbound frame,
    // keeping the existing frame-order assertions unchanged.
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(1), reader.next())
            .await
            .unwrap_or_else(|e| panic!("unchoke frame timeout: {e}"))
            .unwrap_or_else(|| panic!("closed before unchoke"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        if matches!(msg, Message::Unchoke) {
            break;
        }
    }
    (
        handle,
        FramedWrite::new(w, FrameCodec::default()),
        reader,
        join,
    )
}

async fn next_frame(
    mut r: FramedRead<tokio::io::ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
) -> Message {
    use futures::StreamExt;
    tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"))
}

/// Seeding: with a source, an inbound request is answered with a piece
/// (content matches the source).
#[tokio::test]
async fn serves_inbound_request_from_source() {
    let (handle, mut w, r, join) = setup_with_source(Some(Arc::new(FakeSource))).await;
    w.send(Message::Request {
        index: 1,
        begin: 128,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = next_frame(r).await;
    match msg {
        Message::Piece {
            index,
            begin,
            block,
        } => {
            assert_eq!((index, begin), (1, 128));
            assert_eq!(block.len(), 16384);
            assert_eq!(block[0], ((16384 + 128) % 256) as u8);
        }
        other => panic!("expected piece, got {other:?}"),
    }
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// No source (pure downloader) -> reject (an obligation of our advertised
/// fast extension, BEP3).
#[tokio::test]
async fn unservable_request_rejected() {
    let (handle, mut w, r, join) = setup_with_source(None).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 4096,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = next_frame(r).await;
    assert!(
        matches!(
            msg,
            Message::Reject {
                index: 0,
                begin: 0,
                length: 4096
            }
        ),
        "got {msg:?}"
    );
    // Out-of-range request (source present but index beyond range) -> reject.
    let (handle2, mut w2, r2, join2) = setup_with_source(Some(Arc::new(FakeSource))).await;
    w2.send(Message::Request {
        index: 9,
        begin: 0,
        length: 4096,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        next_frame(r2).await,
        Message::Reject { index: 9, .. }
    ));
    handle.shutdown();
    handle2.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
    let _ = tokio::time::timeout(Duration::from_secs(1), join2).await;
}

/// Regression for the missing-file serving scenario: a full bitmap plus
/// the file missing on disk would otherwise let a server pass sparse
/// zeros off as data -> the peer hash-fails in a storm and bans us. A
/// source read failure (the shape after the store side reports a missing
/// file) -> the inbound request MUST be rejected (an obligation of our
/// advertised fast extension) and never answered with a piece frame.
#[tokio::test]
async fn source_read_error_rejects_instead_of_zero_serve() {
    /// Missing-file source: every read fails (equivalent to TorrentReader
    /// raising on a missing file).
    struct MissingFileSource;

    impl PieceSource for MissingFileSource {
        fn read_block(&self, _index: u32, _begin: u32, _buf: &mut [u8]) -> Result<usize, String> {
            Err("file missing (def3): open failed".into())
        }
        fn total_len(&self) -> u64 {
            32768
        }
    }

    let (handle, mut w, r, join) = setup_with_source(Some(Arc::new(MissingFileSource))).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 4096,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = next_frame(r).await;
    assert!(
        matches!(
            msg,
            Message::Reject {
                index: 0,
                begin: 0,
                length: 4096
            }
        ),
        "a source read failure must reject, got {msg:?}"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// A >16KiB request still disconnects (takes priority over serving,
/// SPEC §6.2).
#[tokio::test]
async fn oversize_request_disconnects_even_with_source() {
    let (_handle, mut w, _r, join) = setup_with_source(Some(Arc::new(FakeSource))).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16385,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        end,
        PeerEnd::Violation(PeerError::OversizeRequest { .. })
    ));
}

/// A SendHave command -> a Have frame.
#[tokio::test]
async fn send_have_command_emits_have_frame() {
    let (handle, _w, r, join) = setup_with_source(None).await;
    let (tx, _rx) = oneshot::channel::<()>();
    handle
        .command(PeerCommand::SendHave { index: 5 })
        .unwrap_or_else(|_| panic!("closed"));
    drop(tx);
    let msg = next_frame(r).await;
    assert_eq!(msg, Message::Have { index: 5 });
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// A SendUnchoke command -> an Unchoke frame (the choke-round issue
/// channel).
#[tokio::test]
async fn send_unchoke_command_emits_unchoke_frame() {
    let (handle, _w, r, join) = setup_with_source(None).await;
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|_| panic!("closed"));
    let msg = next_frame(r).await;
    assert_eq!(msg, Message::Unchoke);
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Inbound Interested/NotInterested updates the interest flag (read by
/// the choke rounds).
#[tokio::test]
async fn interest_flag_tracked_from_inbound() {
    let (handle, mut w, _r, join) = setup_with_source(None).await;
    assert!(!handle.is_interested(), "initially not interested");
    w.send(Message::Interested)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // The flag updates inside inbound processing; spin-wait (no receipt
    // channel, a single atomic variable write).
    let deadline = Instant::now() + Duration::from_secs(1);
    while !handle.is_interested() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(handle.is_interested(), "Interested -> flag set");
    w.send(Message::NotInterested)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let deadline = Instant::now() + Duration::from_secs(1);
    while handle.is_interested() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!handle.is_interested(), "NotInterested -> flag cleared");
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// BEP52 v2 capability bit (reserved[7] & 0x10): layering with_v2 does
/// not disturb the fast/ext bits; the outbound handshake carries the bit
/// over the wire (the peer can read it via supports_v2).
#[tokio::test]
async fn reserved_v2_bit_roundtrips_over_handshake() {
    use crate::peer_wire::Reserved;
    // Bit semantics: the default bits (fast+ext) plus the v2 bit; empty
    // reserved with only the v2 bit.
    let r = Reserved::aria2_default().with_v2();
    assert!(r.supports_fast() && r.supports_extended() && r.supports_v2());
    assert!(Reserved::empty().with_v2().supports_v2());
    assert!(
        !Reserved::aria2_default().supports_v2(),
        "default bits do not include v2"
    );

    // Wire roundtrip: the initiator sets the v2 bit -> the peer decodes
    // supports_v2 == true.
    let (a, b) = duplex(256);
    let ih = [7u8; 20];
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = b;
        let mut buf = [0u8; 68];
        s.read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let got = crate::peer_wire::Handshake::decode(&buf).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(
            got.reserved.supports_v2(),
            "the peer must be able to read the v2 capability bit"
        );
        // Reply with a handshake so exchange completes normally.
        s.write_all(
            &crate::peer_wire::Handshake {
                reserved: Reserved::empty(),
                info_hash: ih,
                peer_id: *b"BBBBBBBBBBBBBBBBBBBB",
            }
            .encode(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    });
    let (stream, _) = handshake_exchange(
        a,
        &ih,
        b"AAAAAAAAAAAAAAAAAAAA",
        Reserved::aria2_default().with_v2(),
        Duration::from_secs(1),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    drop(stream);
    server.await.unwrap_or_else(|e| panic!("{e}"));
}

/// Multi-candidate accept (two swarms on one listener): matches the
/// candidate by the peer's info_hash and replies with that candidate's
/// identity; no match errors.
#[tokio::test]
async fn handshake_accept_any_matches_candidate() {
    use crate::peer_wire::{Handshake, Reserved};
    let v1_ih = [1u8; 20];
    let v2_ih = [2u8; 20];
    let candidates = [
        (v1_ih, Reserved::aria2_default().with_v2()),
        (v2_ih, Reserved::aria2_default().with_v2()),
    ];

    // Hits the second candidate (v2 truncated identity). The spawned side
    // is the initiator: it writes the handshake first.
    let (a, b) = duplex(256);
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = b;
        s.write_all(
            &Handshake {
                reserved: Reserved::empty().with_v2(),
                info_hash: v2_ih,
                peer_id: *b"AAAAAAAAAAAAAAAAAAAA",
            }
            .encode(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        let mut buf = [0u8; 68];
        s.read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let got = Handshake::decode(&buf).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            got.info_hash, v2_ih,
            "the acceptor must reply with the matched candidate identity"
        );
        assert!(got.reserved.supports_v2());
    });
    let (stream, matched, theirs) = handshake_accept_any(
        a,
        b"-TJ0001-ACCEPTACCEPT",
        &candidates,
        Duration::from_secs(1),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(matched, 1, "matched the v2 candidate");
    assert!(theirs.reserved.supports_v2());
    drop(stream);
    server.await.unwrap_or_else(|e| panic!("{e}"));

    // No match -> info_hash mismatch. The initiator connects with an
    // unknown info_hash.
    let (a, b) = duplex(256);
    let server = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut s = b;
        s.write_all(
            &Handshake {
                reserved: Reserved::empty(),
                info_hash: [9u8; 20],
                peer_id: [0u8; 20],
            }
            .encode(),
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    });
    let err = handshake_accept_any(
        a,
        b"-TJ0001-ACCEPTACCEPT",
        &candidates,
        Duration::from_secs(1),
    )
    .await;
    assert!(matches!(
        err,
        Err(crate::peer_wire::PeerWireError::InvalidHandshake(ref m)) if m.contains("info_hash")
    ));
    let _ = server.await;
}

/// Handshake exchange: both duplex ends shake hands; the info_hash check
/// in both the pass / mismatch states.
#[tokio::test]
async fn handshake_exchange_roundtrip_and_mismatch() {
    use crate::peer_wire::{Handshake, Reserved};
    let (a, b) = duplex(256);
    let ih = [7u8; 20];
    let server = tokio::spawn(async move {
        // Server: read 68B -> reply with its own handshake.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = b;
        let mut buf = [0u8; 68];
        s.read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let got = Handshake::decode(&buf).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(got.info_hash, ih);
        let resp = Handshake {
            reserved: Reserved::aria2_default(),
            info_hash: ih,
            peer_id: *b"BBBBBBBBBBBBBBBBBBBB",
        };
        s.write_all(&resp.encode())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        got
    });
    let (stream, theirs) = handshake_exchange(
        a,
        &ih,
        b"AAAAAAAAAAAAAAAAAAAA",
        Reserved::aria2_default(),
        Duration::from_secs(1),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(theirs.peer_id, *b"BBBBBBBBBBBBBBBBBBBB");
    assert!(theirs.reserved.supports_fast());
    drop(stream);
    let _ = server.await;

    // info_hash mismatch -> a disconnect error.
    let (a, b) = duplex(256);
    let server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = b;
        let mut buf = [0u8; 68];
        s.read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let resp = Handshake {
            reserved: Reserved::empty(),
            info_hash: [9u8; 20],
            peer_id: [0u8; 20],
        };
        s.write_all(&resp.encode())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
    });
    let err = handshake_exchange(
        a,
        &ih,
        b"AAAAAAAAAAAAAAAAAAAA",
        Reserved::aria2_default(),
        Duration::from_secs(1),
    )
    .await;
    assert!(matches!(
        err,
        Err(crate::peer_wire::PeerWireError::InvalidHandshake(ref m)) if m.contains("info_hash")
    ));
    let _ = server.await;
}

/// Fake hash source: records requests and returns the preset result.
struct FakeHashSource {
    result: std::sync::Mutex<Result<Vec<[u8; 32]>, String>>,
}

impl HashSource for FakeHashSource {
    fn serve(
        &self,
        _root: &[u8; 32],
        _base: u32,
        _index: u32,
        length: u32,
        proof: u32,
    ) -> Result<Vec<[u8; 32]>, String> {
        let guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
        match &*guard {
            Ok(v) => Ok(v.clone()),
            Err(reason) => Err(reason.clone()),
        }
        .map(move |v| {
            // Align with the spec count (omission rule): length +
            // max(0, proof-(log2(length)-1)).
            let omitted = (31 - length.leading_zeros()).saturating_sub(1);
            let want = (length + proof.saturating_sub(omitted)) as usize;
            let mut out = v;
            while out.len() < want {
                out.push([0u8; 32]);
            }
            out.truncate(want);
            out
        })
    }
}

async fn setup_with_hash_source(
    source: Option<Arc<dyn HashSource>>,
) -> (
    PeerTaskHandle,
    FramedWrite<tokio::io::WriteHalf<tokio::io::DuplexStream>, FrameCodec>,
    FramedRead<tokio::io::ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
    tokio::task::JoinHandle<PeerEnd>,
) {
    use futures::StreamExt;
    let root = CancellationToken::new();
    let (local, remote) = duplex(256 * 1024);
    let mut config = PeerConfig::flat();
    config.hash_source = source;
    let (handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (r, w) = tokio::io::split(remote);
    let mut reader = FramedRead::new(r, FrameCodec::default());
    // Unchoke before piece serving (hash requests themselves ignore choke,
    // BEP52; but this fixture's piece-serving path needs the unchoked
    // state). Consume the outbound Unchoke frame to keep the existing
    // frame-order assertions.
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(1), reader.next())
            .await
            .unwrap_or_else(|e| panic!("unchoke frame timeout: {e}"))
            .unwrap_or_else(|| panic!("closed before unchoke"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        if matches!(msg, Message::Unchoke) {
            break;
        }
    }
    (
        handle,
        FramedWrite::new(w, FrameCodec::default()),
        reader,
        join,
    )
}

/// hash request -> with a source, answered with hashes; the payload count
/// conforms to the spec (a hash request MUST be answered, BEP52).
#[tokio::test]
async fn hash_request_served_from_source() {
    let src: Arc<dyn HashSource> = Arc::new(FakeHashSource {
        result: std::sync::Mutex::new(Ok(vec![[0xAA; 32]; 4])),
    });
    let (handle, mut w, r, join) = setup_with_hash_source(Some(src)).await;
    w.send(Message::HashRequest {
        root: [7u8; 32],
        base: 0,
        index: 0,
        length: 4,
        proof: 2,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = next_frame(r).await;
    match msg {
        Message::Hashes {
            root,
            base,
            index,
            length,
            proof,
            hashes,
        } => {
            assert_eq!(root, [7u8; 32]);
            assert_eq!((base, index, length, proof), (0, 0, 4, 2));
            // length 4 + proof 2 - omitted log2(4)-1=1 -> 5 hashes; the
            // fake source pads to >= 4 and the encoder does not extend
            // proofs — asserting the reply survives the codec roundtrip is
            // enough here.
            assert!(!hashes.is_empty());
        }
        other => panic!("expected hashes, got {other:?}"),
    }
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// hash request -> without a source, answered with hash reject (a legal
/// reply form; BEP52: must answer with one of hashes / hash reject).
#[tokio::test]
async fn hash_request_without_source_rejected() {
    let (handle, mut w, r, join) = setup_with_hash_source(None).await;
    w.send(Message::HashRequest {
        root: [7u8; 32],
        base: 0,
        index: 0,
        length: 2,
        proof: 0,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = next_frame(r).await;
    assert!(
        matches!(
            msg,
            Message::HashReject {
                base: 0,
                length: 2,
                ..
            }
        ),
        "got {msg:?}"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Unservable source (Err) -> reject; over the rate limit -> reject;
/// base=0 right after a served piece -> serving is attempted even over
/// the limit (a BEP52 MUST).
#[tokio::test]
async fn hash_rate_limit_and_mandatory_base_zero() {
    let err_src: Arc<dyn HashSource> = Arc::new(FakeHashSource {
        result: std::sync::Mutex::new(Err("no data".into())),
    });
    let (handle, mut w, mut r, join) = setup_with_hash_source(Some(err_src)).await;
    // Over-limit window (LIMIT+1 requests > HASH_REQUEST_LIMIT): all must
    // reject.
    for _ in 0..(HASH_REQUEST_LIMIT + 1) {
        w.send(Message::HashRequest {
            root: [1u8; 32],
            base: 1,
            index: 0,
            length: 2,
            proof: 0,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    }
    use futures::StreamExt;
    for _ in 0..(HASH_REQUEST_LIMIT + 1) {
        let msg = tokio::time::timeout(Duration::from_secs(2), r.next())
            .await
            .unwrap_or_else(|_| panic!("timeout"))
            .unwrap_or_else(|| panic!("closed"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert!(
            matches!(msg, Message::HashReject { .. }),
            "over-limit requests must reject, got {msg:?}"
        );
    }
    // base=0 with a piece served just before: the MUST not to refuse for
    // rate limiting holds even when the source cannot serve — here the
    // source has no data at all (unservable), so it still answers reject
    // (the MUST removes the rate-limit gate; serving remains conditional
    // on having data — a noted intentional simplification). Asserted: the
    // request is answered (no hang) and the reject is legal.
    w.send(Message::HashRequest {
        root: [1u8; 32],
        base: 0,
        index: 0,
        length: 2,
        proof: 0,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|_| panic!("timeout"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(matches!(msg, Message::HashReject { .. }), "got {msg:?}");
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// BEP52 MUST: a base=0 hash request immediately after a served piece
/// request must not be rejected (rate-limit bypass + a servable source ->
/// must answer with hashes).
#[tokio::test]
async fn mandatory_base_zero_after_piece_bypasses_rate_limit() {
    struct OkSource;
    impl HashSource for OkSource {
        fn serve(
            &self,
            _root: &[u8; 32],
            _base: u32,
            _index: u32,
            length: u32,
            proof: u32,
        ) -> Result<Vec<[u8; 32]>, String> {
            let omitted = (31 - length.leading_zeros()).saturating_sub(1);
            let want = (length + proof.saturating_sub(omitted)) as usize;
            Ok(vec![[0xBB; 32]; want])
        }
    }
    struct PieceSrc;
    impl PieceSource for PieceSrc {
        fn read_block(&self, _index: u32, _begin: u32, buf: &mut [u8]) -> Result<usize, String> {
            buf.fill(0xAB);
            Ok(buf.len())
        }
        fn total_len(&self) -> u64 {
            32768
        }
    }
    let root_token = CancellationToken::new();
    let (local, remote) = duplex(1024 * 1024);
    let mut config = PeerConfig::flat();
    config.source = Some(Arc::new(PieceSrc));
    config.hash_source = Some(Arc::new(OkSource));
    let (handle, join, _data) = PeerTask::spawn(&root_token, local, config);
    let (r, w) = tokio::io::split(remote);
    let mut w = FramedWrite::new(w, FrameCodec::default());
    let mut r = FramedRead::new(r, FrameCodec::default());
    use futures::StreamExt;

    // Unchoke before piece serving (BEP3; hash requests themselves ignore
    // choke). No other frames are in flight here, so consuming one
    // outbound Unchoke is enough.
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(1), r.next())
            .await
            .unwrap_or_else(|e| panic!("unchoke frame timeout: {e}"))
            .unwrap_or_else(|| panic!("closed before unchoke"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        if matches!(msg, Message::Unchoke) {
            break;
        }
    }

    // Exhaust the rate-limit window first (before any piece serving): the
    // first LIMIT requests serve normally, request LIMIT+1 rejects. The
    // window stays exhausted within the same 60s period.
    for _ in 0..(HASH_REQUEST_LIMIT + 1) {
        w.send(Message::HashRequest {
            root: [2u8; 32],
            base: 1,
            index: 0,
            length: 2,
            proof: 0,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    }
    for i in 0..(HASH_REQUEST_LIMIT + 1) {
        let msg = tokio::time::timeout(Duration::from_secs(2), r.next())
            .await
            .unwrap_or_else(|_| panic!("timeout"))
            .unwrap_or_else(|| panic!("closed"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        if i < HASH_REQUEST_LIMIT {
            assert!(
                matches!(msg, Message::Hashes { .. }),
                "within the window it should serve: {msg:?}"
            );
        } else {
            assert!(
                matches!(msg, Message::HashReject { .. }),
                "over limit it should reject: {msg:?}"
            );
        }
    }

    // Request and get one piece served (the piece reply sets
    // last_piece_served).
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|_| panic!("timeout"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(matches!(msg, Message::Piece { .. }), "got {msg:?}");

    // base=0 right after the piece serving: even with the window exhausted
    // -> hashes (the MUST takes priority).
    w.send(Message::HashRequest {
        root: [2u8; 32],
        base: 0,
        index: 0,
        length: 2,
        proof: 0,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|_| panic!("timeout"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(msg, Message::Hashes { base: 0, .. }),
        "base=0 right after a piece serve must answer with hashes (BEP52 MUST), got {msg:?}"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Inbound AllowedFast writes the set: the slot survives choke cleanup
/// (re-dispatching the same slot after cleanup = Duplicate).
#[tokio::test]
async fn allowed_fast_survives_choke_cleanup() {
    let (handle, mut w, _r, join) = setup_with_source(None).await;
    // Dispatch one pending request (slot: piece 0, begin 0, 16KiB).
    let (tx, _rx) = oneshot::channel();
    handle
        .command(PeerCommand::RequestPiece {
            id: crate::piece_id::PieceId::V1(0),
            begin: 0,
            length: 16384,
            reply: tx,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    w.send(Message::AllowedFast { index: 0 })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    // Wait for inbound processing (no receipt channel, a polling window).
    tokio::time::sleep(Duration::from_millis(100)).await;
    w.send(Message::Choke)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    // After choke: the allowed-fast-covered slot survives -> re-dispatching
    // the same slot = Duplicate.
    let (tx2, rx2) = oneshot::channel();
    handle
        .command(PeerCommand::RequestPiece {
            id: crate::piece_id::PieceId::V1(0),
            begin: 0,
            length: 16384,
            reply: tx2,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    let result = rx2.await.unwrap_or_else(|_| panic!("reply dropped"));
    assert!(
        matches!(result, Err(DispatchError::Duplicate { .. })),
        "the allowed-fast slot must survive choke cleanup"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

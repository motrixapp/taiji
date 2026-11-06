//! bt::mse tests: inbound sniff-and-split + require-crypto rejecting
//! legacy + the full MSE both-level inbound chain (initiator <->
//! accept_any <-> legacy BT handshake carried on top).
//! The legacy path's "zero MSE cost" is structural: after the sniff
//! decision (a 20B + memcmp-shaped comparison) it goes straight into
//! [`crate::peer::handshake_accept_any`] without touching DH/ARC4 —
//! expressed by cases 1/2: a peer sending only legacy bytes completes the
//! handshake; any MSE state-machine read would fail or hang.

use std::time::Duration;

use super::{AcceptError, PeerStream, accept_any, announce_crypto_param, legacy_pstr};
use crate::peer::handshake_exchange;
use crate::peer_wire::{Handshake, Reserved};
use taiji_io::mse::{CryptoLevel, CryptoPolicy, Encrypted, Sniff, identify, initiate};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(5);
const PEER_A: &[u8; 20] = b"-TJ0001-ACCEPTACCEPT";

fn candidates(ihs: &[[u8; 20]]) -> Vec<([u8; 20], Reserved)> {
    ihs.iter()
        .map(|ih| (*ih, Reserved::aria2_default()))
        .collect()
}

/// Legacy peer: send a 68B handshake, read the peer's 68B reply.
async fn legacy_dial(mut s: tokio::io::DuplexStream, ih: [u8; 20]) -> Handshake {
    let mine = Handshake {
        reserved: Reserved::aria2_default(),
        info_hash: ih,
        peer_id: *b"-TJ0001-LEGACYDIALER",
    };
    s.write_all(&mine.encode())
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let mut buf = [0u8; 68];
    s.read_exact(&mut buf)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    Handshake::decode(&buf).unwrap_or_else(|e| panic!("{e:?}"))
}

/// The legacy inbound takes the zero-delay path — legacy bytes alone
/// complete the handshake (crypto optional).
#[tokio::test]
async fn accept_legacy_when_optional() {
    let ih = [7u8; 20];
    let (a, b) = tokio::io::duplex(1024);
    let dialer = tokio::spawn(legacy_dial(b, ih));
    let accepted = accept_any(
        a,
        PEER_A,
        &candidates(&[ih]),
        CryptoPolicy::optional(),
        TIMEOUT,
    )
    .await
    .unwrap_or_else(|e| panic!("accept: {e}"));
    assert!(matches!(accepted.stream, PeerStream::Legacy(_)));
    assert_eq!(0, accepted.matched);
    assert_eq!(ih, accepted.handshake.info_hash);
    assert_eq!(CryptoLevel::Plain, accepted.crypto);
    // The legacy stream is transparent: exchange one message frame
    // (keep-alive shape = 4B zero length).
    let mut s = accepted.stream;
    s.write_all(&[0, 0, 0, 0])
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    drop(dialer);
}

/// require-crypto rejects the legacy inbound
/// (ReceiverMSEHandshakeCommand.cc); a silent fallback to plaintext is
/// forbidden.
#[tokio::test]
async fn require_crypto_rejects_legacy() {
    let ih = [7u8; 20];
    let (a, b) = tokio::io::duplex(1024);
    let dialer = tokio::spawn(async move {
        let mut s = b;
        let mine = Handshake {
            reserved: Reserved::empty(),
            info_hash: ih,
            peer_id: [1u8; 20],
        };
        let _ = s.write_all(&mine.encode()).await;
        // The peer should reject and close: later writes fail or the
        // connection closes.
        let _ = s.write_all(&[0u8; 4]).await;
    });
    let policy = CryptoPolicy {
        require_crypto: true,
        min_level: CryptoLevel::Plain,
    };
    match accept_any(a, PEER_A, &candidates(&[ih]), policy, TIMEOUT).await {
        Err(AcceptError::LegacyRejected) => {}
        Ok(_) => panic!("require-crypto must reject a legacy inbound"),
        Err(other) => panic!("unexpected error: {other}"),
    }
    // The dialer task's peer-side write failure/close does not affect the
    // assertions.
    let _ = dialer.await;
}

/// MSE inbound (optional policy, initiator min=arc4 -> both sides ARC4):
/// sniff -> MSE receive handshake -> complete the legacy BT handshake on
/// the transparent stream -> bidirectional data.
#[tokio::test]
async fn accept_mse_arc4_end_to_end() {
    let ih = [0x42u8; 20];
    let (a, b) = tokio::io::duplex(8192);
    let policy = CryptoPolicy::optional();
    let dialer = tokio::spawn(async move {
        // Outbound MSE initiator: force ARC4 (require-crypto semantics).
        let req = CryptoPolicy {
            require_crypto: true,
            min_level: CryptoLevel::Plain,
        };
        let negotiated = initiate(b, ih, req, TIMEOUT)
            .await
            .unwrap_or_else(|e| panic!("initiate: {e}"));
        assert_eq!(CryptoLevel::Arc4, negotiated.crypto);
        let mut s = negotiated.stream;
        // Send the legacy BT handshake directly after negotiation
        // (transparent to upper layers).
        let mine = Handshake {
            reserved: Reserved::aria2_default(),
            info_hash: ih,
            peer_id: *b"-TJ0001-MSEINITIATOR",
        };
        s.write_all(&mine.encode())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut buf = [0u8; 68];
        s.read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let theirs = Handshake::decode(&buf).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(ih, theirs.info_hash);
        // Bidirectional data (through the Encrypted stream).
        s.write_all(b"ping-arc4")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut got = [0u8; 9];
        s.read_exact(&mut got)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(b"pong-arc4", &got);
        s
    });
    let accepted = accept_any(a, PEER_A, &candidates(&[ih]), policy, TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("accept: {e}"));
    assert!(matches!(accepted.stream, PeerStream::Encrypted(_)));
    assert_eq!(CryptoLevel::Arc4, accepted.crypto);
    assert_eq!(0, accepted.matched);
    assert_eq!(ih, accepted.handshake.info_hash);
    assert_eq!(
        *b"-TJ0001-MSEINITIATOR", accepted.handshake.peer_id,
        "BT handshake must be recovered from the MSE payload"
    );
    let mut s = accepted.stream;
    let mut ping = [0u8; 9];
    s.read_exact(&mut ping)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(b"ping-arc4", &ping);
    s.write_all(b"pong-arc4")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = dialer.await;
}

/// MSE inbound (both sides optional -> PLAIN): step2 is still encrypted,
/// the stream is plaintext after the handshake.
#[tokio::test]
async fn accept_mse_plain_end_to_end() {
    let ih = [0x24u8; 20];
    let (a, b) = tokio::io::duplex(8192);
    let dialer = tokio::spawn(async move {
        let negotiated = initiate(b, ih, CryptoPolicy::optional(), TIMEOUT)
            .await
            .unwrap_or_else(|e| panic!("initiate: {e}"));
        assert_eq!(CryptoLevel::Plain, negotiated.crypto);
        let mut s = negotiated.stream;
        let mine = Handshake {
            reserved: Reserved::empty(),
            info_hash: ih,
            peer_id: *b"-TJ0001-MSEPLAININIT",
        };
        s.write_all(&mine.encode())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut buf = [0u8; 68];
        s.read_exact(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        Handshake::decode(&buf).unwrap_or_else(|e| panic!("{e:?}"))
    });
    let accepted = accept_any(
        a,
        PEER_A,
        &candidates(&[ih]),
        CryptoPolicy::optional(),
        TIMEOUT,
    )
    .await
    .unwrap_or_else(|e| panic!("accept: {e}"));
    assert_eq!(CryptoLevel::Plain, accepted.crypto);
    assert_eq!(*b"-TJ0001-MSEPLAININIT", accepted.handshake.peer_id);
    let _ = dialer.await;
}

/// Hybrid dual candidates: the MSE payload's req2/req3 hits the second
/// candidate (the v2 truncated identity).
#[tokio::test]
async fn mse_accept_matches_second_candidate() {
    let v1 = [1u8; 20];
    let v2 = [2u8; 20];
    let (a, b) = tokio::io::duplex(8192);
    let dialer = tokio::spawn(async move {
        let negotiated = initiate(b, v2, CryptoPolicy::optional(), TIMEOUT)
            .await
            .unwrap_or_else(|e| panic!("initiate: {e}"));
        let mut s = negotiated.stream;
        let mine = Handshake {
            reserved: Reserved::empty().with_v2(),
            info_hash: v2,
            peer_id: [9u8; 20],
        };
        s.write_all(&mine.encode())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        s
    });
    let accepted = accept_any(
        a,
        PEER_A,
        &candidates(&[v1, v2]),
        CryptoPolicy::optional(),
        TIMEOUT,
    )
    .await
    .unwrap_or_else(|e| panic!("accept: {e}"));
    assert_eq!(1, accepted.matched, "must match the second candidate (v2)");
    assert_eq!(v2, accepted.handshake.info_hash);
    let _ = dialer.await;
}

/// Sniff boundary (the bt-layer vocabulary): the legacy prefix
/// "BitTorrent protocol" is passed in by this layer (io stays
/// protocol-agnostic); 0x13 with a mismatching pstr -> encrypted.
#[test]
fn sniff_routes_with_bt_legacy_prefix() {
    let pstr = legacy_pstr();
    assert_eq!(b"BitTorrent protocol", pstr);
    let mut legacy = vec![19u8];
    legacy.extend_from_slice(pstr);
    assert_eq!(Sniff::Legacy, identify(&legacy, pstr));
    let mut fake = vec![19u8];
    fake.extend_from_slice(b"XitTorrent protocol");
    assert_eq!(
        Sniff::Encrypted,
        identify(&fake, pstr),
        "0x13 but pstr mismatch -> MSE"
    );
    assert_eq!(
        Sniff::Encrypted,
        identify(&[0xff; 20], pstr),
        "public-key first byte -> MSE"
    );
    assert_eq!(Sniff::NeedMore, identify(&legacy[..19], pstr));
}

/// The announce crypto parameter (tracker linkage; DefaultBtAnnounce.cc).
#[test]
fn announce_crypto_params() {
    assert_eq!(
        "supportcrypto=1",
        announce_crypto_param(CryptoPolicy::optional())
    );
    assert_eq!(
        "requirecrypto=1",
        announce_crypto_param(CryptoPolicy {
            require_crypto: true,
            min_level: CryptoLevel::Plain,
        })
    );
}

/// The outbound connect wrapper: an Encrypted stream can run
/// [`handshake_exchange`] directly (the frozen PeerTransport seam
/// semantics; PeerTask is oblivious to MSE).
#[tokio::test]
async fn connect_then_legacy_exchange() {
    let ih = [0x33u8; 20];
    let (a, b) = tokio::io::duplex(8192);
    let acceptor = tokio::spawn(async move {
        accept_any(
            a,
            b"-TJ0001-ACCEPTACCEPT",
            &candidates(&[ih]),
            CryptoPolicy::optional(),
            TIMEOUT,
        )
        .await
        .unwrap_or_else(|e| panic!("accept: {e}"))
    });
    let (stream, crypto) = super::connect(b, ih, CryptoPolicy::optional(), TIMEOUT)
        .await
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let (stream, theirs) = handshake_exchange(
        stream,
        &ih,
        b"-TJ0001-DIALERDIALER",
        Reserved::aria2_default(),
        TIMEOUT,
    )
    .await
    .unwrap_or_else(|e| panic!("exchange: {e:?}"));
    let _stream: Encrypted<_> = stream;
    assert_eq!(CryptoLevel::Plain, crypto);
    assert_eq!(ih, theirs.info_hash);
    let accepted = acceptor.await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(CryptoLevel::Plain, accepted.crypto);
    assert_eq!(*b"-TJ0001-DIALERDIALER", accepted.handshake.peer_id);
}

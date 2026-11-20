//! Wire-level tests for the `ut_close` extension (the peer-visible
//! close-reason face, [`crate::close_reason`]): handshake advertisement,
//! both-sides negotiation gating, the disconnect frame round-trip, and
//! the inbound informational half. Same harness shape as the other
//! peer-extension tests (duplex + PeerTask::spawn + raw frame
//! injection/observation on the remote half).

use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio_util::codec::FramedRead;
use tokio_util::sync::CancellationToken;

use crate::close_reason::{CloseReason, close_reason_of_end, decode_close_frame};
use crate::peer::command::{PeerCommand, PeerHandle as _};
use crate::peer::{ExtConfig, PeerConfig, PeerEnd, PeerError, PeerTask};
use crate::peer_wire::{ExtHandshake, FrameCodec, Message};

/// Our advertised ut_close id (re-exported surface under test).
use crate::peer::OUTBOUND_UT_CLOSE_ID;

/// Remote test end: raw frame reader + writer over the duplex half.
struct Remote {
    reader: FramedRead<tokio::io::ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
}

impl Remote {
    /// Read the next frame (2s budget; EOF = the peer task closed; a
    /// decode error is a test bug — the frames are self-encoded).
    async fn next(&mut self) -> Option<Message> {
        tokio::time::timeout(Duration::from_secs(2), self.reader.next())
            .await
            .unwrap_or_else(|e| panic!("frame read budget: {e}"))
            .transpose()
            .unwrap_or_else(|e| panic!("frame decode: {e}"))
    }

    /// Write one raw encoded frame.
    async fn send(&mut self, msg: &Message) {
        self.writer
            .write_all(&msg.encode())
            .await
            .unwrap_or_else(|e| panic!("raw write: {e}"));
    }
}

/// Spawn a PeerTask on one duplex end with the ut_close gate pinned and
/// the ext handshake enabled (empty serving surface — the m dict is the
/// negotiation surface under test).
fn spawn_local(
    root: &CancellationToken,
    sock: tokio::io::DuplexStream,
    close_reason: Option<bool>,
) -> (
    crate::peer::PeerTaskHandle,
    tokio::task::JoinHandle<PeerEnd>,
) {
    let config = PeerConfig {
        flooding_interval: Duration::from_millis(50),
        ext: ExtConfig::serve(None),
        close_reason,
        ..PeerConfig::flat()
    };
    let (handle, join, _data) = PeerTask::spawn(root, sock, config);
    (handle, join)
}

/// Split the raw duplex half into the remote test end.
fn remote_end(raw: tokio::io::DuplexStream) -> Remote {
    let (rd, wr) = tokio::io::split(raw);
    Remote {
        reader: FramedRead::new(rd, FrameCodec::default()),
        writer: wr,
    }
}

/// Skip until the next ext handshake frame and decode it.
async fn read_ext_handshake(remote: &mut Remote) -> ExtHandshake {
    loop {
        match remote
            .next()
            .await
            .unwrap_or_else(|| panic!("ext handshake not received (stream closed)"))
        {
            Message::Extended { ext_id: 0, payload } => {
                return ExtHandshake::decode(&payload)
                    .unwrap_or_else(|e| panic!("bad ext handshake: {e}"));
            }
            _ => continue,
        }
    }
}

/// Encode an ext handshake payload (encode failures are test bugs).
fn hs_payload(hs: &ExtHandshake) -> Bytes {
    hs.encode()
        .unwrap_or_else(|e| panic!("ext handshake encode: {e}"))
}

/// Advertisement + both-sides negotiation + the disconnect frame
/// round-trip: with the gate on, our ext handshake carries
/// `ut_close = OUTBOUND_UT_CLOSE_ID`; after the peer's handshake
/// advertises its own (different) id — BEP-10 "message IDs are local to
/// the peer" — a command-driven shutdown sends exactly one Extended
/// frame on the PEER's advertised id whose payload decodes to the
/// table's close reason of `PeerEnd::Clean` (`LocalShutdown`).
#[tokio::test]
async fn ut_close_advertised_and_sent_on_shutdown() {
    let root = CancellationToken::new();
    let (sock, raw) = tokio::io::duplex(64 * 1024);
    let (handle, join) = spawn_local(&root, sock, Some(true));
    let mut remote = remote_end(raw);

    // (1) Our advertisement.
    let hs = read_ext_handshake(&mut remote).await;
    assert_eq!(
        hs.m_ut_close,
        Some(OUTBOUND_UT_CLOSE_ID),
        "gate on = the m dict must advertise ut_close"
    );

    // (2) The peer's half of the negotiation (its own local id, 7),
    // followed by an inbound Request while initially choked — its
    // Reject reply is the ordering proof that the handshake (sent
    // first on the same stream) was fully processed before the
    // shutdown command races the frame arm.
    remote
        .send(&Message::Extended {
            ext_id: 0,
            payload: hs_payload(&ExtHandshake {
                m_ut_close: Some(7),
                ..ExtHandshake::default()
            }),
        })
        .await;
    remote
        .send(&Message::Request {
            index: 0,
            begin: 0,
            length: 16 * 1024,
        })
        .await;
    loop {
        match remote.next().await {
            Some(Message::Reject { .. }) => break,
            Some(_) => continue,
            None => panic!("stream closed before the reject ordering proof"),
        }
    }

    // (3) Command-driven shutdown -> exactly one close frame, on the
    // peer's advertised id, carrying the table's reason for Clean. The
    // bare command (not PeerHandle::shutdown, which also cancels the
    // token -> the biased select's Cancelled arm) is the deterministic
    // Clean surface.
    handle
        .command(PeerCommand::Shutdown)
        .unwrap_or_else(|e| panic!("shutdown command: {e:?}"));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("join budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, PeerEnd::Clean));
    // The close frame is written BEFORE the task returns, so it is
    // guaranteed to precede EOF on the stream — drain to EOF and judge
    // every Extended frame found (no select race with the join).
    let mut saw_close = false;
    while let Some(frame) = remote.next().await {
        if let Message::Extended { ext_id, payload } = frame {
            assert_eq!(ext_id, 7, "close frame must use the peer's advertised id");
            let raw_value =
                decode_close_frame(&payload).unwrap_or_else(|e| panic!("close frame decode: {e}"));
            assert_eq!(
                CloseReason::from_wire(raw_value),
                Some(close_reason_of_end(&PeerEnd::Clean)),
                "payload must be the table's reason for PeerEnd::Clean"
            );
            assert_eq!(raw_value, CloseReason::LocalShutdown.wire_value());
            assert!(!saw_close, "exactly one close frame per connection");
            saw_close = true;
        }
    }
    assert!(saw_close, "the close frame must have been sent");
    root.cancel();
}

/// Never sent without negotiation: the peer's ext handshake WITHOUT a
/// `ut_close` key means no close frame at shutdown — the stream just
/// ends (zero wire change for non-negotiating peers).
#[tokio::test]
async fn no_close_frame_without_peer_negotiation() {
    let root = CancellationToken::new();
    let (sock, raw) = tokio::io::duplex(64 * 1024);
    let (handle, join) = spawn_local(&root, sock, Some(true));
    let mut remote = remote_end(raw);
    // Gate on but the peer does NOT advertise: no m key in its handshake.
    read_ext_handshake(&mut remote).await;
    remote
        .send(&Message::Extended {
            ext_id: 0,
            payload: hs_payload(&ExtHandshake::default()),
        })
        .await;
    handle
        .command(PeerCommand::Shutdown)
        .unwrap_or_else(|e| panic!("shutdown command: {e:?}"));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("join budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, PeerEnd::Clean));
    while let Some(frame) = remote.next().await {
        assert!(
            !matches!(frame, Message::Extended { .. }),
            "no Extended frame may follow a non-negotiated shutdown"
        );
    }
    root.cancel();
}

/// Rollback arm: with the gate pinned off (the `BH_CLOSE_NOTIFY=0`
/// shape), the m dict carries no `ut_close` key — no advertisement, so
/// peers never negotiate the extension with us and nothing is ever
/// sent.
#[tokio::test]
async fn gate_off_means_no_advertisement() {
    let root = CancellationToken::new();
    let (sock, raw) = tokio::io::duplex(64 * 1024);
    let (handle, join) = spawn_local(&root, sock, Some(false));
    let mut remote = remote_end(raw);
    let hs = read_ext_handshake(&mut remote).await;
    assert_eq!(hs.m_ut_close, None, "gate off = no ut_close advertisement");
    // Even a peer that advertises ut_close gets no frame from us.
    remote
        .send(&Message::Extended {
            ext_id: 0,
            payload: hs_payload(&ExtHandshake {
                m_ut_close: Some(7),
                ..ExtHandshake::default()
            }),
        })
        .await;
    handle
        .command(PeerCommand::Shutdown)
        .unwrap_or_else(|e| panic!("shutdown command: {e:?}"));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("join budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, PeerEnd::Clean));
    while let Some(frame) = remote.next().await {
        assert!(
            !matches!(frame, Message::Extended { .. }),
            "gate off = no close frame even to an advertising peer"
        );
    }
    root.cancel();
}

/// The inbound half is informational: close frames on our advertised id
/// — one with a KNOWN value, one with an UNKNOWN future value (a
/// reserved-gap slot, carried as the documented minimal dict `d1:ciXe`)
/// — must NOT disconnect the peer and must not change our own terminal
/// state; a later real violation still ends the connection through the
/// normal surface (the sentinel proves the close frames were processed,
/// not dropped unread).
#[tokio::test]
async fn inbound_close_frame_is_informational() {
    let root = CancellationToken::new();
    let (sock, raw) = tokio::io::duplex(64 * 1024);
    let (_handle, join) = spawn_local(&root, sock, Some(true));
    let mut remote = remote_end(raw);

    // Our ext handshake first (carries our advertised id).
    let hs = read_ext_handshake(&mut remote).await;
    let our_id = hs
        .m_ut_close
        .unwrap_or_else(|| panic!("gate on = advertised"));

    // Known value (peer-closed 131) and unknown future value (108, a
    // reserved local-group slot) — both consumed without a disconnect.
    for bytes in [b"d1:ci131ee".as_slice(), b"d1:ci108ee".as_slice()] {
        remote
            .send(&Message::Extended {
                ext_id: our_id,
                payload: Bytes::copy_from_slice(bytes),
            })
            .await;
    }

    // Sentinel: an unsolicited piece disconnects via the normal
    // violation surface — proving both close frames were processed
    // without ending the connection.
    remote
        .send(&Message::Piece {
            index: 9,
            begin: 0,
            block: Bytes::from_static(b"sentinel"),
        })
        .await;
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("join budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::UnsolicitedPiece { index: 9, .. })
        ),
        "sentinel must end the connection (close frames stayed informational), got {end:?}"
    );
    root.cancel();
}

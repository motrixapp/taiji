//! PeerTask unit/integration tests: token semantics + duplex-stream
//! driven data-plane behavior (request dispatch, piece matching,
//! protocol-violation disconnects, flooding, window budget).

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::oneshot;
use tokio_util::codec::{FramedRead, FramedWrite};

use super::*;
use crate::peer_wire::FrameCodec;

/// Build a duplex pair and spawn the PeerTask; returns the remote (the
/// test plays the peer) read/write halves.
async fn setup(
    config: PeerConfig,
) -> (
    CancellationToken,
    PeerTaskHandle,
    tokio::task::JoinHandle<PeerEnd>,
    FramedWrite<WriteHalf<tokio::io::DuplexStream>, FrameCodec>,
    FramedRead<ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
    tokio::sync::mpsc::Receiver<PieceData>,
) {
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (handle, join, data_rx) = PeerTask::spawn(&root, local, config);
    let (r, w) = tokio::io::split(remote);
    (
        root,
        handle,
        join,
        FramedWrite::new(w, FrameCodec::default()),
        FramedRead::new(r, FrameCodec::default()),
        data_rx,
    )
}

async fn request_via(
    handle: &PeerTaskHandle,
    id: PieceId,
    begin: u32,
) -> Result<(), DispatchError> {
    let (tx, rx) = oneshot::channel();
    handle
        .command(PeerCommand::RequestPiece {
            id,
            begin,
            length: 16384,
            reply: tx,
        })
        .unwrap_or_else(|_| panic!("command rejected"));
    match tokio::time::timeout(Duration::from_secs(1), rx).await {
        Ok(Ok(result)) => result,
        other => panic!("no dispatch reply: {other:?}"),
    }
}

/// Parent token cancel → PeerTask exits within the 1s budget.
#[tokio::test]
async fn peer_task_exits_on_token_cancel_within_budget() {
    let root = CancellationToken::new();
    let (local, _remote) = tokio::io::duplex(1024);
    let (handle, join, _data) = PeerTask::spawn(&root, local, PeerConfig::flat());

    let t0 = std::time::Instant::now();
    root.cancel();
    let joined = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(joined.is_ok(), "peer must exit within 1s shutdown budget");
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "shutdown propagation exceeded 1s: {:?}",
        t0.elapsed()
    );
    assert_eq!(
        handle.command(PeerCommand::Shutdown),
        Err(PeerCommandRejected::Closed)
    );
}

/// Explicit Shutdown command exits; end state Clean.
#[tokio::test]
async fn peer_task_exits_on_explicit_shutdown_command() {
    let root = CancellationToken::new();
    let (local, _remote) = tokio::io::duplex(1024);
    let (handle, join, _data) = PeerTask::spawn(&root, local, PeerConfig::flat());

    handle.shutdown();
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    // Both exit paths race: under the biased select the token is polled
    // before commands, so an explicit shutdown() firing both paths may
    // end as Cancelled; the essential part is that it exits.
    assert!(
        matches!(end, PeerEnd::Clean | PeerEnd::Cancelled),
        "got {end:?}"
    );
}

/// Parent token cancel → child PeerTask exits.
#[tokio::test]
async fn dropping_parent_token_cancels_child_peer() {
    let root = CancellationToken::new();
    let (local, _remote) = tokio::io::duplex(1024);
    let (_handle, join, _data) = PeerTask::spawn(&root, local, PeerConfig::flat());
    root.cancel();
    let joined = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(
        joined.is_ok(),
        "child peer must exit when parent token is cancelled"
    );
}

/// Request dispatch: command → RequestBook validation → wire Request
/// frame (per-file addressing conversion).
#[tokio::test]
async fn dispatch_sends_wire_request_with_addressing() {
    let mut config = PeerConfig::flat();
    // file 0 spans 5 pieces; file 1 piece 0 → wire index 5.
    config.addressing = Addressing::per_file(&[70000, 30000], 16384);
    let (_root, handle, _join, remote_w, mut remote_r, _data) = setup(config).await;

    let _ = request_via(
        &handle,
        PieceId::V2 {
            file_index: 1,
            piece_in_file: 0,
        },
        0,
    )
    .await;
    let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("remote closed before frame"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert_eq!(
        sent,
        Message::Request {
            index: 5,
            begin: 0,
            length: 16384
        },
        "wire index must be file-aligned base + in-file index"
    );
    drop(remote_w);
}

// ---------------------------------------------------------------------------
// Request coalescing: drain window + single outbound write
// ---------------------------------------------------------------------------

/// Outbound write-counting wrapper (test observation): the `poll_write`
/// count directly observes the outbound syscall face (batched = one
/// write per batch; fallback = one per frame). Reads and writes pass
/// through; counting only observes, never changes behavior.
/// `is_write_vectored` defaults to false, so FramedWrite takes the
/// `poll_write` path and the count is complete.
struct CountWrites<S> {
    inner: S,
    writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountWrites<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CountWrites<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Batched writes (core semantics): 6 RequestPiece commands in the same
/// drain window merge into a **single outbound write** (`poll_write`
/// count = 1) — one TCP segment carries the whole batch (losing one
/// segment affects one batch, not each request). Wire equivalence:
/// frame order matches command order exactly; the peer parses frame by
/// frame on the length prefix (BT streaming has no message-boundary
/// semantics, so the write count is unobservable). Replies are sent
/// after the flush and all Ok — the "reply success ⇒ request bytes are
/// out" invariant holds. Determinism: `#[tokio::test]` defaults to a
/// current_thread runtime and `try_send` never yields, so all 6
/// commands enqueue before the conn task's first poll = one drain
/// window (the switch is pinned via `PeerConfig::request_coalesce`, no
/// env dependency).
#[tokio::test]
async fn request_coalesce_batches_into_single_write() {
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut config = PeerConfig::flat();
    config.request_coalesce = Some(true);
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (handle, _join, _data) = PeerTask::spawn(
        &root,
        CountWrites {
            inner: local,
            writes: std::sync::Arc::clone(&writes),
        },
        config,
    );
    let mut remote_r = FramedRead::new(remote, FrameCodec::default());

    // Engine dispatch-round shape: 6 consecutive commands inside the
    // default window of 16 (`BH_REQ_WINDOW_INIT` default; the
    // full-window shape is window_budget_enforced_via_commands).
    let mut replies = Vec::new();
    for i in 0..6u32 {
        let (tx, rx) = oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(i),
                begin: 0,
                length: 16,
                reply: tx,
            })
            .unwrap_or_else(|_| panic!("command rejected"));
        replies.push(rx);
    }
    for rx in replies {
        let result = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .unwrap_or_else(|e| panic!("reply timeout: {e}"))
            .unwrap_or_else(|e| panic!("reply dropped: {e}"));
        assert!(result.is_ok(), "dispatch must succeed: {result:?}");
    }
    // One outbound write: all 6 frames (~102B) absorbed in one
    // poll_write.
    assert_eq!(
        writes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the whole request batch must coalesce into one outbound write"
    );
    // Wire equivalence: 6 frames parsed one by one, in command order.
    for i in 0..6u32 {
        let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .unwrap_or_else(|| panic!("remote closed before frame"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert_eq!(
            sent,
            Message::Request {
                index: i,
                begin: 0,
                length: 16
            },
            "frame order must match command order (i={i})"
        );
    }
    root.cancel();
}

/// Fallback path (`BH_REQUEST_COALESCE=0` semantics): the same 6
/// commands → 6 outbound writes (one flush per frame, preserving the
/// existing syscall cadence); wire frame order unchanged.
#[tokio::test]
async fn request_coalesce_off_writes_per_command() {
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut config = PeerConfig::flat();
    config.request_coalesce = Some(false);
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (handle, _join, _data) = PeerTask::spawn(
        &root,
        CountWrites {
            inner: local,
            writes: std::sync::Arc::clone(&writes),
        },
        config,
    );
    let mut remote_r = FramedRead::new(remote, FrameCodec::default());

    let mut replies = Vec::new();
    for i in 0..6u32 {
        let (tx, rx) = oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(i),
                begin: 0,
                length: 16,
                reply: tx,
            })
            .unwrap_or_else(|_| panic!("command rejected"));
        replies.push(rx);
    }
    for rx in replies {
        let result = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .unwrap_or_else(|e| panic!("reply timeout: {e}"))
            .unwrap_or_else(|e| panic!("reply dropped: {e}"));
        assert!(result.is_ok(), "dispatch must succeed: {result:?}");
    }
    assert_eq!(
        writes.load(std::sync::atomic::Ordering::SeqCst),
        6,
        "fallback mode must write one by one (one outbound write per frame)"
    );
    for i in 0..6u32 {
        let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .unwrap_or_else(|| panic!("remote closed before frame"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert_eq!(
            sent,
            Message::Request {
                index: i,
                begin: 0,
                length: 16
            }
        );
    }
    root.cancel();
}

/// Wire order preserved: after a batched pair of Requests, a
/// non-batched command (SendHave) in the same window flushes the batch
/// before its own frame goes out — the peer sees Request, Request,
/// Have (same as the command order; likewise when a Cancel follows
/// Requests, a re-dispatched cancel must not be reordered before the
/// requests). Outbound writes = 2 (batch 1 + Have 1).
#[tokio::test]
async fn request_coalesce_preserves_wire_order_with_interleaved_command() {
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut config = PeerConfig::flat();
    config.request_coalesce = Some(true);
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (handle, _join, _data) = PeerTask::spawn(
        &root,
        CountWrites {
            inner: local,
            writes: std::sync::Arc::clone(&writes),
        },
        config,
    );
    let mut remote_r = FramedRead::new(remote, FrameCodec::default());

    let mut replies = Vec::new();
    for i in 0..2u32 {
        let (tx, rx) = oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(i),
                begin: 0,
                length: 16,
                reply: tx,
            })
            .unwrap_or_else(|_| panic!("command rejected"));
        replies.push(rx);
    }
    handle
        .command(PeerCommand::SendHave { index: 7 })
        .unwrap_or_else(|_| panic!("command rejected"));
    for rx in replies {
        let result = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .unwrap_or_else(|e| panic!("reply timeout: {e}"))
            .unwrap_or_else(|e| panic!("reply dropped: {e}"));
        assert!(result.is_ok(), "dispatch must succeed: {result:?}");
    }
    // The batch was flushed before the Have command was processed (no
    // pending replies); the batch is empty at window end = no third
    // write.
    assert_eq!(
        writes.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "1 batched write + 1 write for the non-batched command"
    );
    let expected = [
        Message::Request {
            index: 0,
            begin: 0,
            length: 16,
        },
        Message::Request {
            index: 1,
            begin: 0,
            length: 16,
        },
        Message::Have { index: 7 },
    ];
    for want in expected {
        let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .unwrap_or_else(|| panic!("remote closed before frame"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert_eq!(sent, want, "wire order must match command order");
    }
    root.cancel();
}

/// Dispatch verdicts unchanged inside the batch window: the 17th
/// command is rejected in the same window (WindowFull{16,16} — the
/// default window is 16; the Nth dispatch sees the bookkeeping of the
/// first N-1, the same verdict order as per-command processing), with
/// no 17th frame and no 17th successful dispatch reply.
/// Mirrors window_budget_enforced_via_commands (the per-command shape).
#[tokio::test]
async fn request_coalesce_window_full_replies_are_per_command() {
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut config = PeerConfig::flat();
    config.request_coalesce = Some(true);
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (handle, _join, _data) = PeerTask::spawn(
        &root,
        CountWrites {
            inner: local,
            writes: std::sync::Arc::clone(&writes),
        },
        config,
    );
    let mut remote_r = FramedRead::new(remote, FrameCodec::default());

    let mut replies = Vec::new();
    for i in 0..17u32 {
        let (tx, rx) = oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(i),
                begin: 0,
                length: 16,
                reply: tx,
            })
            .unwrap_or_else(|_| panic!("command rejected"));
        replies.push(rx);
    }
    for (i, rx) in replies.into_iter().enumerate() {
        let result = tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .unwrap_or_else(|e| panic!("reply timeout: {e}"))
            .unwrap_or_else(|e| panic!("reply dropped: {e}"));
        if i < 16 {
            assert!(result.is_ok(), "i={i} must succeed: {result:?}");
        } else {
            assert!(
                matches!(
                    result,
                    Err(DispatchError::WindowFull {
                        window: 16,
                        outstanding: 16
                    })
                ),
                "i={i} must be WindowFull: {result:?}"
            );
        }
    }
    // 16 frames = one batch, one write; the 17th never entered the
    // bookkeeping and produced no frame.
    assert_eq!(writes.load(std::sync::atomic::Ordering::SeqCst), 1);
    for i in 0..16u32 {
        let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .unwrap_or_else(|| panic!("remote closed before frame"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert!(matches!(sent, Message::Request { index, .. } if index == i));
    }
    root.cancel();
}

/// Window budget: after 16 outstanding, the 17th dispatch is rejected
/// (WindowFull) — the default window is 16 (`BH_REQ_WINDOW_INIT`).
#[tokio::test]
async fn window_budget_enforced_via_commands() {
    let (_root, handle, _join, _w, _r, _data) = setup(PeerConfig::flat()).await;
    for i in 0..16u32 {
        assert!(
            request_via(&handle, PieceId::V1(i), 0).await.is_ok(),
            "i={i}"
        );
    }
    let err = request_via(&handle, PieceId::V1(17), 0).await;
    assert!(
        matches!(
            err,
            Err(DispatchError::WindowFull {
                window: 16,
                outstanding: 16
            })
        ),
        "got {err:?}"
    );
}

/// in-flight lock-free mirror wiring: dispatching a request →
/// `handle.in_flight()` reads 1; a piece frame reclaiming the slot →
/// back to 0 (the PeerTaskHandle readout is a live projection of the
/// RequestBook outstanding count, the engine's 1s tick sample point).
/// Blocks use 16-byte sizes (exactly matching the dispatched slot
/// length — the unsolicited red line).
#[tokio::test]
async fn in_flight_mirror_tracks_request_lifecycle() {
    let (_root, handle, _join, mut remote_w, mut remote_r, mut data) =
        setup(PeerConfig::flat()).await;
    assert_eq!(handle.in_flight(), 0, "honest zero starting value");

    // Dispatch 2 outstanding requests → mirror 2 (confirmed in the
    // bookkeeping by the replies).
    async fn request_small(handle: &PeerTaskHandle, begin: u32) -> Result<(), DispatchError> {
        let (tx, rx) = oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(0),
                begin,
                length: 16,
                reply: tx,
            })
            .unwrap_or_else(|_| panic!("command rejected"));
        match tokio::time::timeout(Duration::from_secs(1), rx).await {
            Ok(Ok(result)) => result,
            other => panic!("no dispatch reply: {other:?}"),
        }
    }
    assert!(request_small(&handle, 0).await.is_ok());
    assert!(request_small(&handle, 16).await.is_ok());
    // Wait for both wire Request frames to go out.
    for _ in 0..2 {
        let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .unwrap_or_else(|| panic!("remote closed before frame"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert!(matches!(sent, Message::Request { .. }), "got {sent:?}");
    }
    // The reply returns before the wire frame completes (dispatch
    // replies synchronously on success); the brief sleep gives the
    // mirror SET time to become visible (already SET in-task; pure
    // timing margin).
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(handle.in_flight(), 2, "two outstanding requests");

    // Two piece frames reclaim both slots → mirror 0 (the data face
    // still delivers on data_rx).
    for begin in [0u32, 16] {
        remote_w
            .send(Message::Piece {
                index: 0,
                begin,
                block: bytes::Bytes::from(vec![0u8; 16]),
            })
            .await
            .unwrap_or_else(|e| panic!("send piece: {e:?}"));
    }
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(1), data.recv())
            .await
            .unwrap_or_else(|e| panic!("data timeout: {e}"))
            .unwrap_or_else(|| panic!("data channel closed"));
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        handle.in_flight(),
        0,
        "mirror back to zero after slot reclaim"
    );
}

/// Adaptive timeout mirror wiring: a wire request → a delayed piece →
/// the slot-match arm samples → a live projection on
/// `handle.adaptive_request_timeout()`. Starting point: no samples = the
/// configured cap 60s (behavior unchanged); two delayed samples
/// (>=50ms, >=1500ms) → mean + 4σ >= 3.675s → second granularity >= 4s
/// (provable lower bound: mean >= 775ms, deviation >= 725ms) → the
/// mirror rises to the real sample face (the slow-peer shape; the
/// fast-peer floor / cap shapes are locked in the request_book tests).
#[tokio::test]
async fn adaptive_timeout_mirror_tracks_request_rtt() {
    let (_root, handle, _join, mut remote_w, mut remote_r, mut data) =
        setup(PeerConfig::flat()).await;
    assert_eq!(
        handle.adaptive_request_timeout(),
        crate::request_book::DEFAULT_REQUEST_TIMEOUT,
        "no samples = the configured cap (zero change to existing behavior)"
    );
    for delay in [50u64, 1500] {
        assert!(request_via(&handle, PieceId::V1(0), 0).await.is_ok());
        let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .unwrap_or_else(|| panic!("remote closed before frame"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        let (index, begin) = match sent {
            Message::Request { index, begin, .. } => (index, begin),
            other => panic!("expect Request, got {other:?}"),
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
        remote_w
            .send(Message::Piece {
                index,
                begin,
                block: bytes::Bytes::from(vec![0u8; 16384]),
            })
            .await
            .unwrap_or_else(|e| panic!("send piece: {e:?}"));
        // The data face still delivers on data_rx (slot matching
        // precedes delivery; sampling does not depend on consumption).
        tokio::time::timeout(Duration::from_secs(1), data.recv())
            .await
            .unwrap_or_else(|e| panic!("data timeout: {e}"))
            .unwrap_or_else(|| panic!("data channel closed"));
    }
    let t = handle.adaptive_request_timeout();
    assert!(
        t >= Duration::from_secs(4),
        "slow samples raise the adaptive value (mean+4σ lower bound 3.675s -> 4s at second granularity): {t:?}"
    );
    assert!(
        t < crate::request_book::DEFAULT_REQUEST_TIMEOUT,
        "real-sample face (below the configured cap): {t:?}"
    );
}

/// Adaptive window wiring (receive-round-driven window growth; the
/// fallback path `BH_REQUEST_WINDOW_BDP=0` semantics — aria2
/// `DefaultBtInteractive.cc` receiveMessages face): one round batch-
/// receives back-to-back frames within one readable window, and slots
/// retired inside the round drive doubling via `completed*4 >= window`
/// — all 6 slots retired in one round (6*4=24 >= 6) → 6→12→24: the
/// window budget genuinely grows with receive rounds. **Mode pinned**:
/// this test verifies the receive-round check-out wiring
/// (begin/end_receive_round call sites); that retirement-doubling
/// mechanism exists only in the fallback mode (`window_bdp:
/// Some(false)` — the default BDP mode grows the window by rate, a
/// decision table in request_book whose 1s rate-window boundary cannot
/// enter a real-time test).
#[tokio::test]
async fn adaptive_window_grows_on_batched_receive_round() {
    // This test carries its own setup: the remote needs a bare
    // WriteHalf for a single batched write_all (FramedWrite has no
    // AsyncWrite face); the shared setup's call sites stay untouched.
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let config = PeerConfig {
        window_bdp: Some(false),
        ..PeerConfig::flat()
    };
    let (handle, join, mut data_rx) = PeerTask::spawn(&root, local, config);
    let (_remote_r, mut remote_w) = tokio::io::split(remote);

    // 16-byte blocks avoid overflowing the duplex buffer: one round of
    // batched frames lands in the socket buffer in a single write_all,
    // and once the peer wakes it must consume them all in the same
    // drain round.
    async fn request_small(handle: &PeerTaskHandle, begin: u32) -> Result<(), DispatchError> {
        let (tx, rx) = oneshot::channel();
        handle
            .command(PeerCommand::RequestPiece {
                id: PieceId::V1(0),
                begin,
                length: 16,
                reply: tx,
            })
            .unwrap_or_else(|_| panic!("command rejected"));
        match tokio::time::timeout(Duration::from_secs(1), rx).await {
            Ok(Ok(result)) => result,
            other => panic!("no dispatch reply: {other:?}"),
        }
    }

    // Encode N Piece frames into one buffer and write once (the
    // deterministic shape of one batched receive round). The begin set
    // is caller-given (it must exactly match outstanding slots or the
    // connection dies as unsolicited).
    async fn send_piece_batch(
        remote_w: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
        begins: impl Iterator<Item = u32>,
    ) {
        use tokio::io::AsyncWriteExt;
        use tokio_util::codec::Encoder;
        let mut buf = bytes::BytesMut::new();
        let mut codec = FrameCodec::default();
        for begin in begins {
            codec
                .encode(
                    Message::Piece {
                        index: 0,
                        begin,
                        block: bytes::Bytes::from([0u8; 16].to_vec()),
                    },
                    &mut buf,
                )
                .unwrap_or_else(|e| panic!("encode: {e:?}"));
        }
        remote_w
            .write_all(&buf)
            .await
            .unwrap_or_else(|e| panic!("write batch: {e}"));
    }

    async fn drain_data(data_rx: &mut tokio::sync::mpsc::Receiver<PieceData>, n: usize) {
        for _ in 0..n {
            tokio::time::timeout(Duration::from_secs(1), data_rx.recv())
                .await
                .unwrap_or_else(|e| panic!("data timeout: {e}"))
                .unwrap_or_else(|| panic!("data channel closed"));
        }
    }

    // Round 1: fill 6 slots → one batched receive retires them all
    // (6*4=24 >= 6) → window 12.
    for i in 0..6u32 {
        assert!(request_small(&handle, i * 16).await.is_ok(), "fill {i}");
    }
    send_piece_batch(&mut remote_w, (0..6).map(|i| i * 16)).await;
    drain_data(&mut data_rx, 6).await;
    // The window is now >= 12: before the wiring it stayed 6 and the
    // 7th dispatch was rejected.
    for i in 0..12u32 {
        assert!(
            request_small(&handle, 1000 + i * 16).await.is_ok(),
            "window must have grown past 6 (dispatch {i})"
        );
    }

    // Round 2: all 12 slots retired in one batch (12*4=48 >= 12) →
    // window 24.
    send_piece_batch(&mut remote_w, (0..12).map(|i| 1000 + i * 16)).await;
    drain_data(&mut data_rx, 12).await;
    for i in 0..24u32 {
        assert!(
            request_small(&handle, 2000 + i * 16).await.is_ok(),
            "window must have grown past 12 (dispatch {i})"
        );
    }
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// BDP target window wiring: `PeerConfig::max_out_request_queue`
/// propagates PeerTask → RequestBook (window clamp) → PeerTaskHandle
/// lock-free mirror (published at attach) → the dispatch gate
/// (WindowFull carries the shrunk window); command channel capacity 64
/// (`COMMAND_CHANNEL_CAPACITY` raised with the target window clamp).
/// The cap clamp holds in both modes at any time (the initial value
/// min(6, 3) = 3 is published at construction, independent of rate
/// samples and 1s rate-window boundaries — deterministic).
#[tokio::test]
async fn bdp_target_window_cap_and_mirror_wiring() {
    let (_root, handle, _join, _w, _r, _data) = setup(PeerConfig {
        max_out_request_queue: 3,
        ..PeerConfig::flat()
    })
    .await;
    // Published at attach: the initial value after the cap clamp
    // (min(6, 3) = 3 — same for BDP and fallback modes).
    assert_eq!(
        handle.target_request_window(),
        3,
        "mirror initial value = min(initial window, configured cap)"
    );
    assert_eq!(
        handle.command_capacity(),
        64,
        "command channel capacity 64 (raised; was 8)"
    );
    // Dispatch gate: 3 slots filled → the 4th gets WindowFull carrying
    // the shrunk window (the cap propagates).
    for i in 0..3u32 {
        assert!(
            request_via(&handle, PieceId::V1(i), 0).await.is_ok(),
            "i={i}"
        );
    }
    let err = request_via(&handle, PieceId::V1(7), 0).await;
    assert!(
        matches!(
            err,
            Err(DispatchError::WindowFull {
                window: 3,
                outstanding: 3
            })
        ),
        "got {err:?}"
    );
}

/// Piece match → data delivery; the slot is removed after the match and
/// the window budget recovers.
#[tokio::test]
async fn matched_piece_forwarded_to_data_channel() {
    let (_root, handle, _join, mut remote_w, _remote_r, mut data_rx) =
        setup(PeerConfig::flat()).await;
    let _ = request_via(&handle, PieceId::V1(3), 16384).await;

    // Request 16KiB → the peer must return the full block: a piece with
    // a mismatched length is unsolicited (disconnect).
    let block = bytes::Bytes::from(vec![7u8; 16384]);
    remote_w
        .send(Message::Piece {
            index: 3,
            begin: 16384,
            block: block.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("send piece: {e}"));

    // Slot match → delivery: waiting for the data proves processing
    // finished, removing the race with later dispatches.
    let got = tokio::time::timeout(Duration::from_secs(1), data_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("data timeout: {e}"));
    let got = got.unwrap_or_else(|| panic!("data channel closed"));
    assert_eq!(got.id, PieceId::V1(3));
    assert_eq!(got.begin, 16384);
    assert_eq!(got.block, block);

    // Slot removed: re-dispatching the same slot is no longer rejected.
    let result = request_via(&handle, PieceId::V1(3), 16384).await;
    assert!(
        result.is_ok(),
        "slot must be free after matched piece: {result:?}"
    );
}

// ---- Session up/down byte counters (aria2 BtPieceMessage.cc count points) ----

/// Stub seeder source: index 0 is servable (blocks filled with 0xA5);
/// any other index is unservable (builds the reject path).
struct StubSource;

impl PieceSource for StubSource {
    fn read_block(&self, index: u32, _begin: u32, buf: &mut [u8]) -> Result<usize, String> {
        if index > 0 {
            return Err(format!("index {index} outside stub source"));
        }
        buf.fill(0xA5);
        Ok(buf.len())
    }
    fn total_len(&self) -> u64 {
        64 * 1024
    }
}

/// Fixture step for "servable only after unchoke" (BEP-3 semantics;
/// libtorrent incoming_request rejects choked peers): send SendUnchoke
/// and consume the outbound frames.
async fn unchoke_and_consume(
    handle: &PeerTaskHandle,
    remote_r: &mut FramedRead<ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
) {
    use futures::StreamExt;
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("unchoke frame timeout: {e}"))
            .unwrap_or_else(|| panic!("closed before unchoke"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        if matches!(msg, Message::Unchoke) {
            break;
        }
    }
}

/// Upload counter: a successfully served inbound request accumulates by
/// payload at piece send (aria2 BtPieceMessage.cc PieceSendUpdate);
/// rejects do not count.
#[tokio::test]
async fn upload_counter_counts_served_pieces_only() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let up = std::sync::Arc::new(AtomicU64::new(0));
    let mut config = PeerConfig::flat();
    config.source = Some(std::sync::Arc::new(StubSource));
    config.uploaded = Some(up.clone());
    config.downloaded = Some(std::sync::Arc::new(AtomicU64::new(0)));
    let (_root, handle, _join, mut remote_w, mut remote_r, _data) = setup(config).await;
    // unchoke before serving (BEP3).
    unchoke_and_consume(&handle, &mut remote_r).await;

    // Servable request (16KiB) → piece reply + counter 16384.
    remote_w
        .send(Message::Request {
            index: 0,
            begin: 0,
            length: 16384,
        })
        .await
        .unwrap_or_else(|e| panic!("send request: {e}"));
    let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("remote closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    match sent {
        Message::Piece { block, .. } => assert_eq!(block.len(), 16384),
        other => panic!("expected piece, got {other:?}"),
    }
    assert_eq!(up.load(Ordering::SeqCst), 16384);

    // Unservable request (out-of-range short read → reject) → not
    // counted.
    remote_w
        .send(Message::Request {
            index: 99,
            begin: 0,
            length: 64,
        })
        .await
        .unwrap_or_else(|e| panic!("send request 2: {e}"));
    let sent2 = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout 2: {e}"))
        .unwrap_or_else(|| panic!("remote closed 2"))
        .unwrap_or_else(|e| panic!("decode 2: {e:?}"));
    assert!(
        matches!(sent2, Message::Reject { .. }),
        "unservable request must reject: {sent2:?}"
    );
    assert_eq!(
        up.load(Ordering::SeqCst),
        16384,
        "reject must not count toward upload (the counting point = piece send)"
    );
    drop(remote_w);
}

/// Download counter: accumulated at piece frame receipt (before
/// bookkeeping/validation; late/duplicate blocks count too — the aria2
/// receive-side updateDownloadLength reading).
#[tokio::test]
async fn download_counter_counts_received_piece_frames() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let down = std::sync::Arc::new(AtomicU64::new(0));
    let mut config = PeerConfig::flat();
    config.downloaded = Some(down.clone());
    let (_root, handle, _join, mut remote_w, _remote_r, mut data_rx) = setup(config).await;
    let _ = request_via(&handle, PieceId::V1(3), 0).await;

    let block = bytes::Bytes::from(vec![9u8; 16384]);
    remote_w
        .send(Message::Piece {
            index: 3,
            begin: 0,
            block: block.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("send piece: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), data_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("data timeout: {e}"));
    assert_eq!(
        got.unwrap_or_else(|| panic!("data channel closed")).block,
        block
    );
    assert_eq!(down.load(Ordering::SeqCst), 16384);
    drop(remote_w);
}

/// No counters (None, the PeerConfig::flat default) → behavior
/// unchanged (the counters are optional injections).
#[tokio::test]
async fn counters_absent_keeps_serving() {
    let mut config = PeerConfig::flat();
    config.source = Some(std::sync::Arc::new(StubSource));
    let (_root, handle, _join, mut remote_w, mut remote_r, _data) = setup(config).await;
    // unchoke before serving (BEP3).
    unchoke_and_consume(&handle, &mut remote_r).await;
    remote_w
        .send(Message::Request {
            index: 0,
            begin: 0,
            length: 128,
        })
        .await
        .unwrap_or_else(|e| panic!("send request: {e}"));
    let sent = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("remote closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(matches!(sent, Message::Piece { .. }), "got {sent:?}");
    drop(remote_w);
}

/// Unsolicited piece → disconnect, end state Violation (mandatory).
#[tokio::test]
async fn unsolicited_piece_disconnects() {
    let (_root, _handle, join, mut remote_w, _r, _data) = setup(PeerConfig::flat()).await;
    remote_w
        .send(Message::Piece {
            index: 9,
            begin: 0,
            block: bytes::Bytes::from_static(b"unrequested"),
        })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::UnsolicitedPiece {
                index: 9,
                begin: 0,
                length: 11
            })
        ),
        "got {end:?}"
    );
}

/// Out-of-range wire index → disconnect (rejected by the addressing
/// layer).
#[tokio::test]
async fn out_of_range_piece_index_disconnects() {
    let mut config = PeerConfig::flat();
    config.addressing = Addressing::per_file(&[70000], 16384); // 5 pieces total
    let (_root, _handle, join, mut remote_w, _r, _data) = setup(config).await;
    remote_w
        .send(Message::Piece {
            index: 5, // out of range
            begin: 0,
            block: bytes::Bytes::from_static(b"x"),
        })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::BadPieceIndex { index: 5 })
        ),
        "got {end:?}"
    );
}

/// An inbound request over 16KiB → disconnect (mandatory).
#[tokio::test]
async fn oversize_request_disconnects() {
    let (_root, _handle, join, mut remote_w, _r, _data) = setup(PeerConfig::flat()).await;
    remote_w
        .send(Message::Request {
            index: 0,
            begin: 0,
            length: 16385,
        })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::OversizeRequest { length: 16385 })
        ),
        "got {end:?}"
    );
}

/// Flooding: the 5s interval semantics unchanged, tests inject 20ms;
/// choke⇄unchoke flips reaching `FLOODING_CHOKE_FLIP_THRESHOLD` (20) →
/// Flooded.
///
/// Threshold recalibration (a constant change only; the mechanism and
/// disconnect semantics are unchanged): the original "disconnect at 2
/// flips" misjudged legitimate choke rotations in real swarms; see
/// `request_book::FLOODING_CHOKE_FLIP_THRESHOLD` docs. The keepalive
/// dimension stays 2 (aria2 `DefaultBtInteractive.cc`).
#[tokio::test]
async fn flooding_disconnects() {
    let mut config = PeerConfig::flat();
    config.flooding_interval = Duration::from_millis(20);
    let (_root, _handle, join, mut remote_w, _r, _data) = setup(config).await;
    // The first choke does not count as a flip (aria2); each
    // alternating frame after counts one flip — 21 frames reach the
    // threshold 20.
    let msgs = std::iter::once(Message::Choke)
        .chain(
            std::iter::repeat([Message::Unchoke, Message::Choke])
                .flatten()
                .take(21),
        )
        .collect::<Vec<_>>();
    for msg in msgs {
        remote_w
            .send(msg)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));
    }
    let end = tokio::time::timeout(Duration::from_millis(500), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, PeerEnd::Flooded), "got {end:?}");
}

/// Companion case: 2 flips (a legitimate rotation shape in real swarms)
/// no longer disconnect (mechanism kept, threshold recalibrated — see
/// above).
#[tokio::test]
async fn flooding_two_flips_stays_connected() {
    let mut config = PeerConfig::flat();
    config.flooding_interval = Duration::from_millis(20);
    let (_root, handle, join, mut remote_w, _r, _data) = setup(config).await;
    for msg in [Message::Choke, Message::Unchoke, Message::Choke] {
        remote_w
            .send(msg)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));
    }
    // After several check windows (20ms x 6) the PeerTask is still
    // alive (join unfinished = not disconnected).
    tokio::time::sleep(Duration::from_millis(140)).await;
    assert!(
        !join.is_finished(),
        "2 flips must not disconnect (recalibration)"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Slot timeout: after request_timeout the slot is cleared and snub is
/// set (observable via re-dispatch).
#[tokio::test]
async fn slot_timeout_frees_budget_and_snubs() {
    let mut config = PeerConfig::flat();
    config.request_timeout = Duration::from_millis(50);
    config.flooding_interval = Duration::from_millis(20);
    let (_root, handle, join, _w, _r, _data) = setup(config).await;
    let _ = request_via(&handle, PieceId::V1(0), 0).await;
    // After 50ms the tick clears the timed-out slot; re-dispatching
    // after one tick period must succeed.
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        request_via(&handle, PieceId::V1(0), 0).await.is_ok(),
        "timed-out slot must free budget"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

// ---------------------------------------------------------------------------
// hash request requester mechanics (RequestHashes command + reply
// correlation matching).
// ---------------------------------------------------------------------------

/// RequestHashes: the outbound hash request frame carries the correct
/// tuple; injecting a matching hashes reply → the oneshot resolves to
/// HashFetch::Hashes (payload passed through).
#[tokio::test]
async fn request_hashes_roundtrip_matches_pending() {
    let (_root, handle, join, mut w, mut r, _data) = setup(PeerConfig::flat()).await;
    let (tx, rx) = oneshot::channel();
    handle
        .command(PeerCommand::RequestHashes {
            root: [7u8; 32],
            base: 0,
            index: 0,
            length: 8,
            proof: 0,
            reply: tx,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    // The peer (test side) sees hash request(21).
    let req = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert_eq!(
        req,
        Message::HashRequest {
            root: [7u8; 32],
            base: 0,
            index: 0,
            length: 8,
            proof: 0
        }
    );
    // Reply with hashes(22) (proof=0 → canonical count = length = 8).
    w.send(Message::Hashes {
        root: [7u8; 32],
        base: 0,
        index: 0,
        length: 8,
        proof: 0,
        hashes: vec![[0xAAu8; 32]; 8],
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("reply dropped: {e}"))
        .unwrap_or_else(|e| panic!("error: {e:?}"));
    assert_eq!(got, HashFetch::Hashes(vec![[0xAAu8; 32]; 8]));
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// hash reject(23) → HashFetch::Rejected (a legal answer form; the
/// degrade policy belongs to the caller).
#[tokio::test]
async fn request_hashes_reject_resolves() {
    let (_root, handle, join, mut w, mut r, _data) = setup(PeerConfig::flat()).await;
    let (tx, rx) = oneshot::channel();
    handle
        .command(PeerCommand::RequestHashes {
            root: [9u8; 32],
            base: 0,
            index: 4,
            length: 4,
            proof: 0,
            reply: tx,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    let req = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(matches!(req, Message::HashRequest { length: 4, .. }));
    w.send(Message::HashReject {
        root: [9u8; 32],
        base: 0,
        index: 4,
        length: 4,
        proof: 0,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("reply dropped: {e}"))
        .unwrap_or_else(|e| panic!("error: {e:?}"));
    assert_eq!(
        got,
        HashFetch::Rejected,
        "reject must be returned explicitly rather than swallowed"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Hash requests still send while choked (BEP-52: "Hash requests may be
/// sent to a peer regardless of its choke state"); choke also clears
/// piece slots but does not affect the hash channel.
#[tokio::test]
async fn request_hashes_sent_while_choked() {
    let (_root, handle, join, mut w, mut r, _data) = setup(PeerConfig::flat()).await;
    w.send(Message::Choke)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (tx, _rx) = oneshot::channel();
    handle
        .command(PeerCommand::RequestHashes {
            root: [3u8; 32],
            base: 0,
            index: 0,
            length: 2,
            proof: 0,
            reply: tx,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    let req = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(
            req,
            Message::HashRequest {
                base: 0,
                length: 2,
                ..
            }
        ),
        "the hash request must still send while choked, got {req:?}"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// At most one in-flight hash request per connection: a second
/// concurrent submission → Busy (while one is pending).
#[tokio::test]
async fn request_hashes_busy_while_pending() {
    let (_root, handle, join, _w, mut r, _data) = setup(PeerConfig::flat()).await;
    let (tx1, rx1) = oneshot::channel();
    handle
        .command(PeerCommand::RequestHashes {
            root: [1u8; 32],
            base: 0,
            index: 0,
            length: 2,
            proof: 0,
            reply: tx1,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    // Wait for the first request to hit the wire (pending established).
    let _ = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    let (tx2, rx2) = oneshot::channel();
    handle
        .command(PeerCommand::RequestHashes {
            root: [2u8; 32],
            base: 0,
            index: 0,
            length: 2,
            proof: 0,
            reply: tx2,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    let got = tokio::time::timeout(Duration::from_secs(1), rx2)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("reply dropped: {e}"));
    assert_eq!(
        got,
        Err(HashRequestError::Busy),
        "a second submission while one is pending must be Busy"
    );
    // Teardown: when the PeerTask shuts down, the pending request's
    // reply end drops with the task (the caller sees a closed channel).
    handle.shutdown();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), rx1)
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .is_err(),
        "a pending request must end with a closed channel when the task exits"
    );
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// An unrelated reply (header tuple mismatch) does not consume the
/// pending request: the real answer still gets through.
#[tokio::test]
async fn unrelated_hashes_do_not_consume_pending() {
    let (_root, handle, join, mut w, mut r, _data) = setup(PeerConfig::flat()).await;
    let (tx, rx) = oneshot::channel();
    handle
        .command(PeerCommand::RequestHashes {
            root: [5u8; 32],
            base: 0,
            index: 0,
            length: 2,
            proof: 0,
            reply: tx,
        })
        .unwrap_or_else(|e| panic!("{e:?}"));
    let _ = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    // Unrelated hashes (a different root): dropped, pending kept.
    w.send(Message::Hashes {
        root: [0xFFu8; 32],
        base: 0,
        index: 0,
        length: 2,
        proof: 0,
        hashes: vec![[0u8; 32]; 2],
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    // The correct answer arrives next → resolves normally.
    w.send(Message::Hashes {
        root: [5u8; 32],
        base: 0,
        index: 0,
        length: 2,
        proof: 0,
        hashes: vec![[0x11u8; 32]; 2],
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("reply dropped: {e}"))
        .unwrap_or_else(|e| panic!("error: {e:?}"));
    assert_eq!(got, HashFetch::Hashes(vec![[0x11u8; 32]; 2]));
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

// ===== BEP-10 extension face / ut_metadata =====

use crate::peer_wire::ExtHandshake;
use crate::ut_metadata::{DataOutcome, MetadataAssembler, UtMetadata};

/// Read one frame (with a timeout budget; closed/decode all panic
/// explicitly).
async fn read_frame(
    r: &mut FramedRead<tokio::io::ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
) -> Message {
    tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"))
}

/// Static metadata serving source (test).
struct StaticMeta(Bytes);

impl MetadataSource for StaticMeta {
    fn metadata(&self) -> &[u8] {
        &self.0
    }
}

/// Responder ext handshake frame (advertises ut_metadata=id +
/// metadata_size).
fn ext_handshake_frame(id: u8, metadata_size: Option<usize>) -> Message {
    let payload = ExtHandshake {
        m_ut_metadata: Some(id),
        metadata_size: metadata_size.map(|s| s as u32),
        ..ExtHandshake::default()
    };
    Message::Extended {
        ext_id: 0,
        payload: payload.encode().unwrap_or_else(|e| panic!("{e}")),
    }
}

/// Decode the dict from an ext handshake frame.
fn decode_ext(msg: &Message) -> ExtHandshake {
    let Message::Extended { ext_id: 0, payload } = msg else {
        panic!("expected extended handshake frame, got {msg:?}");
    };
    ExtHandshake::decode(payload).unwrap_or_else(|e| panic!("{e}"))
}

/// Decode a frame as a ut_metadata message (asserts the ext_id).
fn decode_ut(ext_id: u8, msg: &Message) -> UtMetadata {
    let Message::Extended {
        ext_id: got,
        payload,
    } = msg
    else {
        panic!("expected extended frame, got {msg:?}");
    };
    assert_eq!(*got, ext_id, "ut_metadata msg id");
    UtMetadata::decode(payload).unwrap_or_else(|e| panic!("{e}"))
}

fn ext_request_frame(ext_id: u8, index: usize) -> Message {
    Message::Extended {
        ext_id,
        payload: Bytes::from(
            UtMetadata::Request { index }
                .encode()
                .unwrap_or_else(|e| panic!("{e}")),
        ),
    }
}

fn ut_data_frame(ext_id: u8, index: usize, total: usize, data: &[u8]) -> Message {
    Message::Extended {
        ext_id,
        payload: Bytes::from(
            UtMetadata::Data {
                index,
                total_size: total,
                data: Bytes::copy_from_slice(data),
            }
            .encode()
            .unwrap_or_else(|e| panic!("{e}")),
        ),
    }
}

fn sha1_of(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest as _, Sha1};
    Sha1::digest(data).into()
}

/// Requester full chain (duplex): our ext handshake out → peer
/// registered → piece-by-piece requests → assemble + verify → Complete
/// reported (the verify anchor = sha1(info), BEP-9).
#[tokio::test]
async fn ut_metadata_fetch_completes_over_duplex() {
    let info: Bytes = Bytes::from(vec![0xA5u8; 20000]); // 2 pieces: 16KiB + remainder
    let sha1 = sha1_of(&info);
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        ext: ExtConfig::fetch(MetadataFetchSpec {
            expected: ExpectedInfoHash::V1(sha1),
            tx,
        }),
        ..PeerConfig::flat()
    };
    let (_root, handle, join, mut w, mut r, _data) = setup(config).await;

    // Our ext handshake goes first (outbound id=2, no metadata_size).
    let mine = decode_ext(&read_frame(&mut r).await);
    assert_eq!(mine.m_ut_metadata, Some(OUTBOUND_UT_METADATA_ID));
    assert_eq!(mine.metadata_size, None, "the requester holds no metadata");

    // Peer registration: ut_metadata=7 + metadata_size.
    w.send(ext_handshake_frame(7, Some(info.len())))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // First piece request (smallest ascending).
    let UtMetadata::Request { index } = decode_ut(7, &read_frame(&mut r).await) else {
        panic!("expected request");
    };
    assert_eq!(index, 0);
    // data reply → the second piece is requested immediately (a
    // round-trip pipeline, in-flight <= 1).
    let piece = crate::ut_metadata::METADATA_PIECE_SIZE;
    w.send(ut_data_frame(7, index, info.len(), &info[..piece]))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let UtMetadata::Request { index } = decode_ut(7, &read_frame(&mut r).await) else {
        panic!("expected second request");
    };
    assert_eq!(index, 1);
    w.send(ut_data_frame(7, index, info.len(), &info[piece..]))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));

    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("channel closed"));
    assert_eq!(got, MetadataFetched::Complete(info.clone()));
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// Regression (interop): inbound ut_metadata routes on **our
/// advertised** id — a peer advertising ut_metadata=3 (rqbit,
/// librqbit-peer-protocol `MY_EXTENDED_UT_METADATA`) that sends data on
/// our id=2 must still route; our outbound requests still go on the
/// peer's advertised id (3) (BEP-10 is bidirectional: the m dict value
/// is the id to use when sending to the advertiser).
#[tokio::test]
async fn ut_metadata_inbound_routes_on_our_advertised_id() {
    let info: Bytes = Bytes::from(vec![0xE7u8; 100]);
    let sha1 = sha1_of(&info);
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        ext: ExtConfig::fetch(MetadataFetchSpec {
            expected: ExpectedInfoHash::V1(sha1),
            tx,
        }),
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await; // our ext handshake (advertised id=2)
    // Peer advertises ut_metadata=3 + metadata_size.
    w.send(ext_handshake_frame(3, Some(info.len())))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // Our requests must go out on the peer's advertised id=3 (the
    // BEP-10 outbound half).
    let UtMetadata::Request { index } = decode_ut(3, &read_frame(&mut r).await) else {
        panic!("expected request");
    };
    // The peer's data arrives on our advertised id=2 (rqbit serializes
    // per the peer's m dict).
    w.send(ut_data_frame(
        OUTBOUND_UT_METADATA_ID,
        index,
        info.len(),
        &info,
    ))
    .await
    .unwrap_or_else(|e| panic!("write: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("channel closed"));
    assert_eq!(got, MetadataFetched::Complete(info));
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// Our outbound ext handshake `v` = PEER_AGENT (`taiji/<semver>`, the
/// same string as the HTTP announce UA — libtorrent defaults v to
/// user_agent, bt_peer_connection.cpp). Carried from the first send
/// (the `v` key was previously not sent; the identity is now unified).
#[tokio::test]
async fn our_ext_handshake_carries_peer_agent_as_v() {
    let config = PeerConfig {
        ext: ExtConfig::serve(None),
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, _w, mut r, _data) = setup(config).await;
    let Message::Extended { ext_id: 0, payload } = read_frame(&mut r).await else {
        panic!("first frame must be our ext handshake");
    };
    let hs = ExtHandshake::decode(&payload).unwrap_or_else(|e| panic!("decode: {e}"));
    assert_eq!(
        hs.v.as_deref(),
        Some(crate::tracker::PEER_AGENT),
        "ext handshake v must equal the UA identity string"
    );
    // No advertisement regression: ut_metadata still uses the existing
    // outbound id.
    assert_eq!(hs.m_ut_metadata, Some(OUTBOUND_UT_METADATA_ID));
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// reject → Failed reported + connection ends (reference
/// UTMetadataRejectExtensionMessage.cc).
#[tokio::test]
async fn ut_metadata_reject_fails_and_disconnects() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        ext: ExtConfig::fetch(MetadataFetchSpec {
            expected: ExpectedInfoHash::V1([7u8; 20]),
            tx,
        }),
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await; // consume our ext handshake
    w.send(ext_handshake_frame(9, Some(16384)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let UtMetadata::Request { index } = decode_ut(9, &read_frame(&mut r).await) else {
        panic!("expected request");
    };
    w.send(Message::Extended {
        ext_id: 9,
        payload: Bytes::from(
            UtMetadata::Reject { index }
                .encode()
                .unwrap_or_else(|e| panic!("{e}")),
        ),
    })
    .await
    .unwrap_or_else(|e| panic!("write: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("channel closed"));
    assert!(matches!(got, MetadataFetched::Failed(_)), "got {got:?}");
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, PeerEnd::Clean), "got {end:?}");
}

/// infohash mismatch → Failed (rejected by the post-assembly check;
/// surfaces as a clean connection end).
#[tokio::test]
async fn ut_metadata_infohash_mismatch_fails() {
    let wrong: Bytes = Bytes::from(vec![0x5Au8; 100]); // does not match the expected sha1
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        ext: ExtConfig::fetch(MetadataFetchSpec {
            expected: ExpectedInfoHash::V1([0x11u8; 20]),
            tx,
        }),
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await;
    w.send(ext_handshake_frame(5, Some(wrong.len())))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let UtMetadata::Request { index } = decode_ut(5, &read_frame(&mut r).await) else {
        panic!("expected request");
    };
    w.send(ut_data_frame(5, index, wrong.len(), &wrong))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("channel closed"));
    assert!(matches!(got, MetadataFetched::Failed(_)));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, PeerEnd::Clean));
}

/// V2 (btmh) expected identity: sha256(info) verifies → Complete.
#[tokio::test]
async fn ut_metadata_fetch_v2_identity_verified() {
    use sha2::{Digest as _, Sha256};
    let info: Bytes = Bytes::from(vec![0x3Cu8; 100]);
    let expect: [u8; 32] = Sha256::digest(&info).into();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        ext: ExtConfig::fetch(MetadataFetchSpec {
            expected: ExpectedInfoHash::V2(expect),
            tx,
        }),
        ..PeerConfig::flat()
    };
    let (_root, _handle, _join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await;
    w.send(ext_handshake_frame(4, Some(info.len())))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let UtMetadata::Request { index } = decode_ut(4, &read_frame(&mut r).await) else {
        panic!("expected request");
    };
    w.send(ut_data_frame(4, index, info.len(), &info))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("channel closed"));
    assert_eq!(got, MetadataFetched::Complete(info));
}

/// Serving face: holding metadata → data reply; out-of-range index →
/// disconnect (reference UTMetadataRequestExtensionMessage.cc).
#[tokio::test]
async fn ut_metadata_serve_answers_then_disconnects_on_out_of_range() {
    let meta: Bytes = Bytes::from(vec![0x77u8; 20000]);
    let config = PeerConfig {
        ext: ExtConfig::serve(Some(Arc::new(StaticMeta(meta.clone())))),
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;
    // Our ext handshake must carry metadata_size.
    let mine = decode_ext(&read_frame(&mut r).await);
    assert_eq!(mine.metadata_size, Some(meta.len() as u32));
    // The test client must also complete an ext handshake (routing keys
    // off its m dict).
    w.send(ext_handshake_frame(OUTBOUND_UT_METADATA_ID, None))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));

    // Valid request piece=0 → data.
    w.send(ext_request_frame(OUTBOUND_UT_METADATA_ID, 0))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let UtMetadata::Data {
        index,
        total_size,
        data,
    } = decode_ut(OUTBOUND_UT_METADATA_ID, &read_frame(&mut r).await)
    else {
        panic!("expected data");
    };
    assert_eq!(index, 0);
    assert_eq!(total_size, meta.len());
    assert_eq!(&data[..], &meta[..crate::ut_metadata::METADATA_PIECE_SIZE]);

    // Out-of-range request → disconnect.
    w.send(ext_request_frame(OUTBOUND_UT_METADATA_ID, 999))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, PeerEnd::Clean), "got {end:?}");
}

/// Serving face without metadata (serve(None)) → every request is
/// rejected (UTMetadataRequestExtensionMessage.cc).
#[tokio::test]
async fn ut_metadata_serve_without_metadata_rejects() {
    let config = PeerConfig {
        ext: ExtConfig::serve(None),
        ..PeerConfig::flat()
    };
    let (_root, _handle, _join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await;
    w.send(ext_handshake_frame(OUTBOUND_UT_METADATA_ID, None))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    w.send(ext_request_frame(OUTBOUND_UT_METADATA_ID, 0))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let reject = decode_ut(OUTBOUND_UT_METADATA_ID, &read_frame(&mut r).await);
    assert_eq!(reject, UtMetadata::Reject { index: 0 });
}

/// Assembler pre-checks data piece lengths (connection-face regression
/// of the fetcher's unit guarantee).
#[tokio::test]
async fn assembler_rejects_bad_piece_length() {
    let mut asm = MetadataAssembler::new(100).unwrap_or_else(|e| panic!("{e}"));
    let ok = asm.insert(0, &[0u8; 100]).is_ok();
    assert!(ok);
    assert!(matches!(
        asm.insert(0, &[0u8; 50]),
        Err(crate::ut_metadata::MetadataError::PieceLength { .. })
    ));
    assert!(matches!(
        asm.insert(1, &[0u8; 1]),
        Err(crate::ut_metadata::MetadataError::IndexOutOfRange { .. })
    ));
    assert!(asm.is_complete());
    assert_eq!(
        asm.assemble().map(|b| b.len()),
        Some(100),
        "DataOutcome::Complete does not reach this assertion (the fetcher face); this only proves assemble"
    );
    let _ = DataOutcome::Stored { remaining: 0 };
}

// ===== ut_pex advertise / consume / outbound (BEP-11) =====

/// Responder ext handshake frame variant: optional ut_pex advertised id.
fn ext_handshake_frame_pex(pex_id: Option<u8>) -> Message {
    let payload = ExtHandshake {
        m_ut_metadata: Some(2),
        m_ut_pex: pex_id,
        ..ExtHandshake::default()
    };
    Message::Extended {
        ext_id: 0,
        payload: payload.encode().unwrap_or_else(|e| panic!("{e}")),
    }
}

/// Inbound ut_pex frame (ext_id = the receiver's advertised msg id;
/// payload = dict).
fn ut_pex_frame(ext_id: u8, msg: &crate::pex::PexMessage) -> Message {
    Message::Extended {
        ext_id,
        payload: Bytes::from(msg.encode().unwrap_or_else(|e| panic!("{e}"))),
    }
}

fn v4_sock(a: [u8; 4], port: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::from((std::net::IpAddr::V4(a.into()), port))
}

/// Duplex full chain: we advertise ut_pex=1 (BEP-10 m dict) → the peer
/// advertises ut_pex=7 → the peer sends ut_pex (added/dropped) → we
/// decode and raise a PexEvent to the caller (both fresh and dropped
/// lists passed through; the caller-side projection of aria2
/// UTPexExtensionMessage::doReceivedAction).
#[tokio::test]
async fn pex_advertised_and_inbound_consumed_over_duplex() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        cuid: 42,
        ext: ExtConfig {
            enabled: true,
            metadata: None,
            fetch: None,
            pex: Some(PexExt {
                tx,
                interval: crate::pex::DEFAULT_INTERVAL,
            }),
        },
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;

    // Our ext handshake: advertises ut_metadata=2 + ut_pex=1 (the aria2
    // default face, HandshakeExtensionMessageTest.cc vectors).
    let mine = decode_ext(&read_frame(&mut r).await);
    assert_eq!(mine.m_ut_metadata, Some(OUTBOUND_UT_METADATA_ID));
    assert_eq!(mine.m_ut_pex, Some(OUTBOUND_UT_PEX_ID));

    // Peer advertises ut_pex=7.
    w.send(ext_handshake_frame_pex(Some(7)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // The peer's inbound ut_pex: ext_id = our advertised 1.
    let mut msg = crate::pex::PexMessage::new();
    let t0 = std::time::Instant::now();
    let cand = crate::pex::PexCandidate::fresh(
        crate::pex::PexPeer::new(v4_sock([203, 0, 113, 5], 6881), crate::pex::UploadOnly::No),
        t0,
    );
    assert!(msg.add_fresh_peer(&cand, t0));
    let drop = crate::pex::PexCandidate::dropped(
        crate::pex::PexPeer::new(v4_sock([203, 0, 113, 6], 6882), crate::pex::UploadOnly::No),
        t0,
    );
    assert!(msg.add_dropped_peer(&drop, t0));
    w.send(ut_pex_frame(OUTBOUND_UT_PEX_ID, &msg))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));

    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("pex channel closed"));
    assert_eq!(ev.from, 42, "cuid echoed back");
    assert_eq!(ev.fresh, vec![v4_sock([203, 0, 113, 5], 6881)]);
    assert_eq!(ev.dropped, vec![v4_sock([203, 0, 113, 6], 6882)]);
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Inbound ut_pex per-connection fixed-window rate limit (4/60s, the
/// ut_holepunch shape) — from the 5th frame in the window on, frames
/// are ignored (no PexEvent, no disconnect). Determinism: frames are
/// processed in order and a trailing out-of-set Piece (a guaranteed
/// Violation end) proves all preceding ut_pex frames were processed;
/// then the event channel must hold exactly 4 (no "sleep and hope
/// nothing arrives" race). Channel capacity 16 > 4 rules out confusing
/// a "full channel drop" with rate limiting.
#[tokio::test]
async fn pex_inbound_rate_limited_per_connection() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let config = PeerConfig {
        cuid: 43,
        ext: ExtConfig {
            enabled: true,
            metadata: None,
            fetch: None,
            pex: Some(PexExt {
                tx,
                interval: crate::pex::DEFAULT_INTERVAL,
            }),
        },
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;
    // Read our ext handshake first (contents unused; just clears the
    // sequence).
    let _ = decode_ext(&read_frame(&mut r).await);
    w.send(ext_handshake_frame_pex(Some(7)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // Send 5 frames in the window (limit 4): the first 4 are consumed,
    // the 5th ignored.
    let t0 = std::time::Instant::now();
    for host in 1u8..=5 {
        let mut msg = crate::pex::PexMessage::new();
        let cand = crate::pex::PexCandidate::fresh(
            crate::pex::PexPeer::new(
                v4_sock([203, 0, 113, host], 6881),
                crate::pex::UploadOnly::No,
            ),
            t0,
        );
        assert!(msg.add_fresh_peer(&cand, t0));
        w.send(ut_pex_frame(OUTBOUND_UT_PEX_ID, &msg))
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
    }
    // End sentinel: an out-of-set Piece → Violation (processing order
    // guarantees the preceding 5 ut_pex frames were fully processed).
    w.send(Message::Piece {
        index: 9,
        begin: 0,
        block: bytes::Bytes::from_static(b"sentinel"),
    })
    .await
    .unwrap_or_else(|e| panic!("write piece: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::UnsolicitedPiece { index: 9, .. })
        ),
        "the sentinel must disconnect via the unsolicited push (proves all frames were processed), got {end:?}"
    );
    // Exactly 4 events (the 5th frame was rate-limit dropped), cuid
    // checked per event.
    for i in 0..4 {
        match rx.try_recv() {
            Ok(ev) => {
                assert_eq!(ev.from, 43, "event #{} cuid echoed back", i + 1);
                assert_eq!(ev.fresh.len(), 1, "exactly 1 fresh address per frame");
            }
            other => panic!(
                "event #{} must exist (rate limiting only drops the 5th frame), got {:?}",
                i + 1,
                other
            ),
        }
    }
    assert!(
        rx.try_recv().is_err(),
        "the 5th frame in the window must be rate-limit dropped"
    );
}

/// BEP-11 first ut_pex frame exemption (wire face) — a first ut_pex
/// with 120 added (>50; mainstream clients' first frame, BEP-11 "Except
/// for the initial PEX message the combined amount of added v4/v6
/// contacts should not exceed 50 entries.") must decode and be raised;
/// a second one with 120 keeps the 50-cap whole-frame rejection
/// (regression anchor). Determinism: a frame-order sentinel (an
/// out-of-set Piece → Violation end) proves both ut_pex frames were
/// processed before the channel is checked (no timing race).
#[tokio::test]
async fn pex_inbound_first_frame_exemption_over_50() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        cuid: 44,
        ext: ExtConfig {
            enabled: true,
            metadata: None,
            fetch: None,
            pex: Some(PexExt {
                tx,
                interval: crate::pex::DEFAULT_INTERVAL,
            }),
        },
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;
    let _ = decode_ext(&read_frame(&mut r).await); // our ext handshake
    w.send(ext_handshake_frame_pex(Some(7)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // A ut_pex frame with n distinct v4 fresh entries (add/encode has no
    // capacity face — the cap lives at decode).
    let big = |n: usize| {
        let t0 = std::time::Instant::now();
        let mut msg = crate::pex::PexMessage::new();
        for host in 1..=n {
            let host = u8::try_from(host).unwrap_or_else(|e| panic!("{e}"));
            let cand = crate::pex::PexCandidate::fresh(
                crate::pex::PexPeer::new(
                    v4_sock([203, 0, 113, host], 6881),
                    crate::pex::UploadOnly::No,
                ),
                t0,
            );
            assert!(msg.add_fresh_peer(&cand, t0));
        }
        msg
    };
    // First ut_pex: 120 added (inside the first-frame exemption, 120 <
    // FIRST_PEX_MAX).
    w.send(ut_pex_frame(OUTBOUND_UT_PEX_ID, &big(120)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // Second ut_pex: also 120 → whole-frame rejection (regression
    // anchor, not raised).
    w.send(ut_pex_frame(OUTBOUND_UT_PEX_ID, &big(120)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // Sentinel: an out-of-set Piece → Violation (processing order
    // guarantees both preceding ut_pex frames were fully processed).
    w.send(Message::Piece {
        index: 9,
        begin: 0,
        block: bytes::Bytes::from_static(b"sentinel"),
    })
    .await
    .unwrap_or_else(|e| panic!("write piece: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::UnsolicitedPiece { index: 9, .. })
        ),
        "the sentinel must disconnect via the unsolicited push (proves all frames were processed), got {end:?}"
    );
    // Exactly 1 event: all 120 of the first frame accepted (exemption).
    let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("pex channel closed"));
    assert_eq!(ev.from, 44, "cuid echoed back");
    assert_eq!(
        ev.fresh.len(),
        120,
        "the first ut_pex's 120 addresses must all be accepted (BEP11 exemption)"
    );
    // Second frame over 50: whole-frame rejection → not raised.
    assert!(
        rx.try_recv().is_err(),
        "a second frame carrying 120 must reject the whole frame (the 50 cap)"
    );
}

/// Private torrent face: ExtConfig.pex = None (the assembled shape
/// after `pex_offered` decides no) → no advertisement (no ut_pex in the
/// m dict) and no consumption (same-id frames ignored as unknown — the
/// `apply_pex_negotiation` "registry removal" semantics,
/// DefaultBtInteractive.cc); the connection stays alive.
#[tokio::test]
async fn pex_gate_closed_no_advertise_no_consume() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        ext: ExtConfig {
            enabled: true,
            metadata: None,
            fetch: None,
            pex: None,
        },
        ..PeerConfig::flat()
    };
    let (_root, handle, join, mut w, mut r, _data) = setup(config).await;
    let _tx: tokio::sync::mpsc::Sender<PexEvent> = tx; // hold the sender: a recv timeout means not-consumed, not channel-closed

    let mine = decode_ext(&read_frame(&mut r).await);
    assert_eq!(
        mine.m_ut_pex, None,
        "with the gate closed, ut_pex must not be advertised"
    );
    assert_eq!(mine.m_ut_metadata, Some(OUTBOUND_UT_METADATA_ID));

    // The peer sends ut_pex regardless of negotiation (ext_id=1): not
    // consumed.
    let mut msg = crate::pex::PexMessage::new();
    let t0 = std::time::Instant::now();
    let cand = crate::pex::PexCandidate::fresh(
        crate::pex::PexPeer::new(v4_sock([203, 0, 113, 9], 6881), crate::pex::UploadOnly::No),
        t0,
    );
    assert!(msg.add_fresh_peer(&cand, t0));
    w.send(ut_pex_frame(OUTBOUND_UT_PEX_ID, &msg))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    let none = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
    assert!(
        none.is_err(),
        "ut_pex must not be consumed while the gate is closed, got {none:?}"
    );

    // Connection alive: after this it can still exit Clean (not
    // Io/Violation).
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

/// Outbound half: the peer advertises ut_pex=7 → the engine pushes a
/// candidate snapshot (SetPexCandidates) → at due time a frame is built
/// and sent (PexSwarmSender reused: admission filter + capacity + the
/// peer's own IP exclusion). A short interval drives the same 60s state
/// machine (a test-scaled `DefaultBtInteractive.cc` constant).
#[tokio::test]
async fn pex_outbound_sent_on_due_with_candidates() {
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        remote_ip: Some(v4_sock([192, 0, 2, 9], 0).ip()),
        flooding_interval: Duration::from_millis(20),
        ext: ExtConfig {
            enabled: true,
            metadata: None,
            fetch: None,
            pex: Some(PexExt {
                tx,
                interval: Duration::from_millis(120),
            }),
        },
        ..PeerConfig::flat()
    };
    let (_root, handle, _join, mut w, mut r, _data) = setup(config).await;

    let mine = decode_ext(&read_frame(&mut r).await);
    assert_eq!(mine.m_ut_pex, Some(OUTBOUND_UT_PEX_ID));
    w.send(ext_handshake_frame_pex(Some(7)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // The outbound window opens at handshake+interval; freshness
    // admission requires first_contact < interval
    // (UTPexExtensionMessage.cc) — push candidates after 100ms so at
    // build time (>= handshake+120ms) their age is < 120ms, still
    // inside the window.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Candidate snapshot: 1 eligible outbound fresh + 1 incoming
    // (excluded by admission) + 1 with the peer's own IP
    // (DefaultBtInteractive.cc exclusion).
    let t0 = std::time::Instant::now();
    let ok = crate::pex::PexCandidate::fresh(
        crate::pex::PexPeer::new(v4_sock([203, 0, 113, 5], 6881), crate::pex::UploadOnly::No),
        t0,
    );
    let incoming = crate::pex::PexCandidate {
        incoming: true,
        ..crate::pex::PexCandidate::fresh(
            crate::pex::PexPeer::new(v4_sock([203, 0, 113, 7], 6881), crate::pex::UploadOnly::No),
            t0,
        )
    };
    let self_ip = crate::pex::PexCandidate::fresh(
        crate::pex::PexPeer::new(v4_sock([192, 0, 2, 9], 6881), crate::pex::UploadOnly::No),
        t0,
    );
    handle
        .command(PeerCommand::SetPexCandidates {
            fresh: vec![ok, incoming, self_ip],
            dropped: Vec::new(),
        })
        .unwrap_or_else(|_| panic!("command rejected"));

    // Outbound after due (120ms) + tick (20ms); ext_id = the peer's
    // advertised 7.
    let sent = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut r))
        .await
        .unwrap_or_else(|e| panic!("no ut_pex outbound: {e}"));
    let Message::Extended { ext_id, payload } = sent else {
        panic!("expected extended frame, got {sent:?}");
    };
    assert_eq!(ext_id, 7, "outbound sends with the peer-advertised id");
    let back = crate::pex::PexMessage::decode(&payload).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        back.fresh_peers(),
        &[crate::pex::PexPeer::new(
            v4_sock([203, 0, 113, 5], 6881),
            crate::pex::UploadOnly::No
        )],
        "only eligible outbound candidates enter the message (incoming/peer's own IP excluded)"
    );
}

/// No outbound frame on an empty window ("send when there are new
/// peers"): empty candidates → no frame at due time (no ut_pex reaches
/// the peer side).
#[tokio::test]
async fn pex_outbound_skips_empty_window() {
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        flooding_interval: Duration::from_millis(20),
        ext: ExtConfig {
            enabled: true,
            metadata: None,
            fetch: None,
            pex: Some(PexExt {
                tx,
                interval: Duration::from_millis(80),
            }),
        },
        ..PeerConfig::flat()
    };
    let (_root, handle, _join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await; // our ext handshake
    w.send(ext_handshake_frame_pex(Some(7)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    handle
        .command(PeerCommand::SetPexCandidates {
            fresh: Vec::new(),
            dropped: Vec::new(),
        })
        .unwrap_or_else(|_| panic!("command rejected"));
    // No ut_pex frame across several ticks + interval windows.
    let quiet = tokio::time::timeout(Duration::from_millis(400), r.next()).await;
    match quiet {
        Err(_) => {} // timeout = no frame (expected)
        Ok(Some(Ok(m))) => panic!("an empty candidate window must not send ut_pex, got {m:?}"),
        Ok(other) => panic!("the connection terminated unexpectedly: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// BEP-10 m dict value 0 = extension disabled ("Setting an extension
// number to zero means that the extension is not supported/disabled." —
// BEP-10 wording; 0 is also the ext handshake's own reserved id). The
// three consumers (PEX outbound / ut_holepunch negotiation mirror /
// ut_metadata fetch session) must not treat 0 as a valid advertised id.
// ---------------------------------------------------------------------------

/// Peer advertises `ut_pex: 0` = explicitly disabled → no outbound
/// sender is built: a candidate push + due time must not produce any
/// Extended frame.
#[tokio::test]
async fn pex_peer_m_zero_disables_outbound_pex() {
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        flooding_interval: Duration::from_millis(20),
        ext: ExtConfig {
            enabled: true,
            metadata: None,
            fetch: None,
            pex: Some(PexExt {
                tx,
                interval: Duration::from_millis(120),
            }),
        },
        ..PeerConfig::flat()
    };
    let (_root, handle, join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await; // our ext handshake
    w.send(ext_handshake_frame_pex(Some(0)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // Timing aligned with pex_outbound_sent_on_due_with_candidates:
    // push candidates after 100ms so at build time (>= handshake+120ms)
    // their age is < 120ms, deterministically passing freshness
    // admission (the Some(7) control row sends a frame; this Some(0)
    // row must not).
    tokio::time::sleep(Duration::from_millis(100)).await;
    let t0 = std::time::Instant::now();
    let ok = crate::pex::PexCandidate::fresh(
        crate::pex::PexPeer::new(v4_sock([203, 0, 113, 5], 6881), crate::pex::UploadOnly::No),
        t0,
    );
    handle
        .command(PeerCommand::SetPexCandidates {
            fresh: vec![ok],
            dropped: Vec::new(),
        })
        .unwrap_or_else(|_| panic!("command rejected"));
    // No Extended frame at all across several ticks + interval windows.
    let quiet = tokio::time::timeout(Duration::from_millis(400), r.next()).await;
    match quiet {
        Err(_) => {} // timeout = no frame (expected)
        Ok(Some(Ok(m))) => {
            panic!(
                "ut_pex=0 (BEP10 disabled) must not build an outbound sender / send an Extended frame, got {m:?}"
            )
        }
        Ok(other) => panic!("the connection terminated unexpectedly: {other:?}"),
    }
    handle.shutdown();
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(end, PeerEnd::Clean | PeerEnd::Cancelled),
        "disable semantics must not escalate to a disconnect, got {end:?}"
    );
}

/// Peer advertises `ut_holepunch: 0` = explicitly disabled → the
/// negotiation mirror must stay unset (libtorrent
/// `supports_holepunch()` = `m_holepunch_id != 0`,
/// bt_peer_connection.cpp). Determinism: a frame-order sentinel (an
/// out-of-set Piece → Violation end) — join returning proves the ext
/// handshake was fully processed (same method as
/// pex_inbound_rate_limited_per_connection).
#[tokio::test]
async fn holepunch_peer_m_zero_means_unsupported() {
    let (_root, handle, join, mut w, _r, _data) = setup(PeerConfig::flat()).await;
    let hs = ExtHandshake {
        m_ut_holepunch: Some(0),
        ..ExtHandshake::default()
    };
    w.send(Message::Extended {
        ext_id: 0,
        payload: hs.encode().unwrap_or_else(|e| panic!("{e}")),
    })
    .await
    .unwrap_or_else(|e| panic!("write: {e}"));
    // Sentinel: an out-of-set Piece → Violation (processing order
    // proves the handshake was fully consumed).
    w.send(Message::Piece {
        index: 9,
        begin: 0,
        block: bytes::Bytes::from_static(b"sentinel"),
    })
    .await
    .unwrap_or_else(|e| panic!("write piece: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::UnsolicitedPiece { index: 9, .. })
        ),
        "the sentinel must disconnect via the unsolicited push (proves all frames were processed), got {end:?}"
    );
    assert!(
        !handle.supports_holepunch(),
        "ut_holepunch=0 (BEP10 disabled) must not set the negotiation mirror"
    );
}

/// Peer advertises `ut_metadata: 0` = explicitly disabled → no fetch
/// session, no fetch requests, and the spec immediately reports Failed
/// (the existing "peer does not support ut_metadata" semantics — the
/// same aria2 outcome of not enabling metadata mode; the orchestration
/// layer retries on another peer).
#[tokio::test]
async fn ut_metadata_peer_m_zero_builds_no_fetch() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let config = PeerConfig {
        ext: ExtConfig::fetch(MetadataFetchSpec {
            expected: ExpectedInfoHash::V1([7u8; 20]),
            tx,
        }),
        ..PeerConfig::flat()
    };
    let (_root, _handle, _join, mut w, mut r, _data) = setup(config).await;
    let _ = read_frame(&mut r).await; // our ext handshake
    // The peer explicitly disables ut_metadata (0) yet announces
    // metadata_size.
    w.send(ext_handshake_frame(0, Some(16384)))
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    // Verdict 1 (deterministic channel): the spec immediately reports
    // Failed.
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|e| {
            panic!("red test (pre-fix): ut_metadata=0 still built a session, no Failed reply: {e}")
        })
        .unwrap_or_else(|| panic!("channel closed"));
    assert!(
        matches!(got, MetadataFetched::Failed(_)),
        "a disabled advertisement must report Failed under the unsupported semantics, got {got:?}"
    );
    // Verdict 2: no fetch request goes out (it used to send an
    // Extended{0} ut_metadata request on the peer's advertised id=0).
    let quiet = tokio::time::timeout(Duration::from_millis(300), r.next()).await;
    match quiet {
        Err(_) => {} // timeout = no frame (expected)
        Ok(Some(Ok(m))) => {
            panic!("ut_metadata=0 (BEP10 disabled) must not send fetch requests, got {m:?}")
        }
        Ok(other) => panic!("the connection terminated unexpectedly: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// BEP-6 semantics (unsolicited = neither an in-flight request/timeout
// grace, nor in the allowed-fast/suggest sets) + choke keeps in-flight
// slots.
//
// Reference: the BEP-6 Allowed Fast/Suggest sections; libtorrent
// peer_connection.cpp incoming_piece records redundant bytes for
// non-requested blocks without disconnecting, timed-out blocks stay in
// m_download_queue (waste_reason::piece_timed_out), and incoming_choke
// clears only unsent requests (+ clear_request_queue).
// ---------------------------------------------------------------------------

/// Table-driven (an in-set allowed-fast push accepted / an out-of-set
/// push still disconnects).
#[tokio::test]
async fn allowed_fast_push_accepted_out_of_set_still_violates() {
    // Row 1: AllowedFast{5} then push piece 5 (unrequested) → accepted
    // (delivered on the data face).
    let (_root, _handle, join, mut w, _r, mut data) = setup(PeerConfig::flat()).await;
    w.send(Message::AllowedFast { index: 5 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    let block = bytes::Bytes::from_static(b"allowed-fast-push");
    w.send(Message::Piece {
        index: 5,
        begin: 0,
        block: block.clone(),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), data.recv()).await;
    match got {
        Ok(Some(pd)) => assert_eq!(pd.block, block, "an in-set push must be accepted"),
        other => panic!("allowed-fast push must be accepted, got {other:?}"),
    }
    assert!(
        !join.is_finished(),
        "an in-set push must not disconnect (removing the false ban)"
    );
    drop(w);

    // Row 2: an out-of-set push (no AllowedFast first) → Violation
    // disconnect (semantics not loosened).
    let (_root, _handle, join, mut w, _r, _data) = setup(PeerConfig::flat()).await;
    w.send(Message::Piece {
        index: 9,
        begin: 0,
        block: bytes::Bytes::from_static(b"unrequested"),
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::UnsolicitedPiece { index: 9, .. })
        ),
        "an out-of-set push keeps the disconnect semantics, got {end:?}"
    );
}

/// allowed-fast/suggest acceptance-arm block coordinate check — set
/// membership only waives the "not requested" dimension; coordinates
/// must still satisfy the slot-matching wire request geometry (begin
/// 16KiB-aligned, length in (0,16KiB], begin+length within the piece's
/// expected bytes, index inside the piece table). A malicious peer can
/// use AllowedFast{0} + Piece{begin=1} to feed a misaligned block into
/// the store and poison its accounting — the acceptance arm must reject
/// (Violation disconnect, never into the store).
/// `piece_bytes` table = [16384] (the wire index equals the flat order
/// for v1 and v2 alike).
#[tokio::test]
async fn allowed_fast_push_with_bad_coords_violates() {
    // Row 1: AllowedFast{0} + Piece{begin=1, 16383B} — a misaligned
    // begin → Violation disconnect.
    let config = PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64]),
        ..PeerConfig::flat()
    };
    let (_root, _handle, join, mut w, _r, _data) = setup(config).await;
    w.send(Message::AllowedFast { index: 0 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    w.send(Message::Piece {
        index: 0,
        begin: 1,
        block: bytes::Bytes::from_static(&[0xAA; 16383]),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("a violation must disconnect promptly: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::BadBlockCoords {
                index: 0,
                begin: 1,
                length: 16383
            })
        ),
        "a misaligned block must not pass into the store, got {end:?}"
    );

    // Row 2: aligned but overflowing the piece bound (begin=16384 +
    // 16384B > piece 0's 16384B) → also Violation (otherwise the
    // store's check_range hits Internal → Fatal).
    let (_root, _handle, join, mut w, _r, _data) = setup(PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64]),
        ..PeerConfig::flat()
    })
    .await;
    w.send(Message::AllowedFast { index: 0 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    w.send(Message::Piece {
        index: 0,
        begin: 16384,
        block: bytes::Bytes::from_static(&[0xBB; 16384]),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("a violation must disconnect promptly: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(end, PeerEnd::Violation(PeerError::BadBlockCoords { .. })),
        "a block overflowing the piece bound must not pass, got {end:?}"
    );

    // Row 3: an index outside the piece table (the AllowedFast set
    // itself is peer-controlled; membership does not legalize the
    // index) → Violation. An out-of-range index is rejected right at
    // the AllowedFast registration frame (BadPieceIndex, before a later
    // Piece push reaches the coordinate check); the semantics are
    // unchanged — an index outside the piece table must never reach the
    // acceptance face.
    let (_root, _handle, join, mut w, _r, _data) = setup(PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64]),
        ..PeerConfig::flat()
    })
    .await;
    w.send(Message::AllowedFast { index: 7 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("a violation must disconnect promptly: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::BadPieceIndex { index: 7 })
        ),
        "an index outside the piece table must not pass (rejected at the registration frame), got {end:?}"
    );

    // Row 4 (control): a geometrically legal in-set push is accepted as
    // usual (the check must not break existing BEP-6 semantics).
    let (_root, _handle, join, mut w, _r, mut data) = setup(PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64]),
        ..PeerConfig::flat()
    })
    .await;
    w.send(Message::AllowedFast { index: 0 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    let block = bytes::Bytes::from_static(&[0xDD; 16384]);
    w.send(Message::Piece {
        index: 0,
        begin: 0,
        block: block.clone(),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), data.recv()).await;
    match got {
        Ok(Some(pd)) => assert_eq!(pd.block, block, "a legal in-set push must be accepted"),
        other => panic!("legal allowed-fast push must be accepted, got {other:?}"),
    }
    assert!(
        !join.is_finished(),
        "a legal in-set push must not disconnect"
    );
    drop(w);
}

/// allowed-fast receive-arm resource cap — the set previously had no
/// capacity bound, so a malicious peer could feed distinct indices
/// frame by frame without bound (HashSet memory amplification + a wider
/// unsolicited acceptance surface). The cap semantics match suggested
/// (clear and rebuild at the cap): after flooding 5000 in-range
/// indices, an early member (0) left the set with the clear → its push
/// falls back to out-of-set semantics (Violation); members rebuilt
/// inside the new window (4500) are still accepted (no over-pruning).
/// `piece_bytes` table = 8192 pieces (all flooded indices in range,
/// isolating the index-bound check dimension).
#[tokio::test]
async fn allowed_fast_flood_capped() {
    // Row 1: after 5000 frames the early member (0) has left the set →
    // the out-of-set push is a Violation.
    let (_root, _handle, join, mut w, _r, _data) = setup(PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64; 8192]),
        ..PeerConfig::flat()
    })
    .await;
    for index in 0..5000u32 {
        w.send(Message::AllowedFast { index })
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    w.send(Message::Piece {
        index: 0,
        begin: 0,
        block: bytes::Bytes::from_static(&[0xAA; 16384]),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("a violation must disconnect promptly: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::UnsolicitedPiece { index: 0, .. })
        ),
        "an early member must not survive the at-cap clear (an out-of-set push keeps disconnecting), got {end:?}"
    );

    // Row 2 (control): members inside the rebuilt window (4096..5000)
    // are accepted as usual — the cap must not invalidate legitimate
    // set semantics wholesale.
    let (_root, _handle, join, mut w, _r, mut data) = setup(PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64; 8192]),
        ..PeerConfig::flat()
    })
    .await;
    for index in 0..5000u32 {
        w.send(Message::AllowedFast { index })
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));
    }
    tokio::time::sleep(Duration::from_millis(80)).await;
    let block = bytes::Bytes::from_static(&[0xBB; 16384]);
    w.send(Message::Piece {
        index: 4500,
        begin: 0,
        block: block.clone(),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), data.recv()).await;
    match got {
        Ok(Some(pd)) => assert_eq!(
            pd.block, block,
            "a member push inside the rebuilt window must be accepted"
        ),
        other => panic!("post-cap member push must be accepted, got {other:?}"),
    }
    assert!(
        !join.is_finished(),
        "a push inside the rebuilt window must not disconnect"
    );
    drop(w);
}

/// AllowedFast index bound check — the `piece_bytes` table length =
/// piece count (PeerConfig semantics); an out-of-range index has no
/// legal meaning (its Piece pushes would be rejected by the piece table
/// at the unsolicited acceptance arm anyway), and accepting it only
/// widens set residency and the acceptance surface → Violation
/// disconnect (the same semantic slot as `addressing.from_wire`
/// validation in the Piece/Reject arms).
#[tokio::test]
async fn allowed_fast_out_of_range_index_violates() {
    // Row 1: a 1-piece table, AllowedFast{7} → Violation.
    let (_root, _handle, join, mut w, _r, _data) = setup(PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64]),
        ..PeerConfig::flat()
    })
    .await;
    w.send(Message::AllowedFast { index: 7 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("a violation must disconnect promptly: {e:?}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::BadPieceIndex { index: 7 })
        ),
        "an out-of-table AllowedFast index must not be accepted, got {end:?}"
    );

    // Row 2 (control): an in-range index registers normally, the
    // connection stays (BEP-6 semantics intact).
    let (_root, _handle, join, mut w, _r, _data) = setup(PeerConfig {
        piece_bytes: std::sync::Arc::from(vec![16384u64]),
        ..PeerConfig::flat()
    })
    .await;
    w.send(Message::AllowedFast { index: 0 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(!join.is_finished(), "an in-range index must not disconnect");
    drop(w);
}

/// The race window after a suggest, before our request arrives: an
/// early delivery inside the suggest set is accepted.
#[tokio::test]
async fn suggested_push_accepted() {
    let (_root, _handle, join, mut w, _r, mut data) = setup(PeerConfig::flat()).await;
    w.send(Message::Suggest { index: 3 })
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    let block = bytes::Bytes::from_static(b"suggested-push");
    w.send(Message::Piece {
        index: 3,
        begin: 0,
        block: block.clone(),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), data.recv()).await;
    match got {
        Ok(Some(pd)) => assert_eq!(
            pd.block, block,
            "an early delivery inside the suggest set must be accepted"
        ),
        other => panic!("suggested push must be accepted, got {other:?}"),
    }
    assert!(!join.is_finished());
}

/// Choke does not clear in-flight slots (the anti-misban core case): a
/// dispatched request delivered after the choke still matches
/// (libtorrent keeps m_download_queue; aria2's wholesale clear is
/// exactly the late-delivery unsolicited misban this row guards
/// against).
#[tokio::test]
async fn in_flight_piece_survives_inbound_choke() {
    let (_root, handle, join, mut w, _r, mut data) = setup(PeerConfig::flat()).await;
    let _ = request_via(&handle, PieceId::V1(2), 0).await;
    // The peer chokes us (it may already be serving the outstanding
    // request — a wire crossing race).
    w.send(Message::Choke)
        .await
        .unwrap_or_else(|e| panic!("send choke: {e}"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    // Late delivery: must be accepted as the in-flight request, never
    // judged unsolicited.
    let block = bytes::Bytes::from(vec![7u8; 16384]);
    w.send(Message::Piece {
        index: 2,
        begin: 0,
        block: block.clone(),
    })
    .await
    .unwrap_or_else(|e| panic!("send piece: {e}"));
    let got = tokio::time::timeout(Duration::from_secs(1), data.recv()).await;
    match got {
        Ok(Some(pd)) => assert_eq!(
            pd.block, block,
            "an in-flight delivery after choke must be accepted"
        ),
        other => panic!("in-flight piece must survive choke, got {other:?}"),
    }
    assert!(
        !join.is_finished(),
        "must not disconnect (canonical misban regression)"
    );
    drop(w);
}

/// While we choke, an inbound request → reject (BEP-3; libtorrent
/// incoming_request "peer choked and piece not in allowed fast set").
/// The connection starts with both sides choking (the BEP-3 state
/// table).
#[tokio::test]
async fn request_while_am_choking_rejects() {
    let (_root, _handle, join, mut w, mut r, _data) = setup(PeerConfig::flat()).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    let msg = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(msg, Message::Reject { .. }),
        "a request while choked must reject, got {msg:?}"
    );
    assert!(
        !join.is_finished(),
        "reject does not disconnect (a legal answer)"
    );
    drop(w);
}

// ---- BEP-6 outbound message fast negotiation gate ----

/// Helper: no outbound frame may appear within the budget window (the
/// BEP-6 silent face for peers without fast). Budget 300ms: existing
/// reply-frame tests observe frames from the same synchronous
/// processing path arriving within 1s, so a frame would arrive far
/// earlier than this window.
async fn assert_no_outbound_frame(
    r: &mut FramedRead<ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
) {
    match tokio::time::timeout(Duration::from_millis(300), r.next()).await {
        Err(_) => {}
        Ok(Some(Ok(msg))) => {
            panic!("a peer without negotiated fast must not receive BEP6 frames, got {msg:?}")
        }
        Ok(Some(Err(e))) => panic!("decode: {e:?}"),
        Ok(None) => panic!("the connection closed unexpectedly"),
    }
}

/// With the peer's handshake fast bit = 0 (`PeerConfig::peer_fast =
/// false`), an inbound request while we choke must NOT get a Reject —
/// BEP-6 "If the fast extension is disabled and a peer receives a
/// reject request then the peer MUST close the connection": sending
/// Reject to a non-negotiating peer forces the disconnect (a MUST-close
/// violation). The BEP-3 fallback = silent drop; the peer's request
/// timeout converges (aria2 BtRequestMessage.cc queues a reject in the
/// else branch only when `isFastExtensionEnabled()`; libtorrent
/// `write_reject_request`'s `if (!m_supports_fast) return;` is the same
/// rule). The connection stays (grace/violation disconnect semantics
/// are orthogonal to the negotiation gate — libtorrent evaluates the
/// disconnect after the reject write, independently).
#[tokio::test]
async fn request_while_am_choking_silent_without_fast() {
    let mut config = PeerConfig::flat();
    config.peer_fast = false;
    let (_root, _handle, join, mut w, mut r, _data) = setup(config).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    assert_no_outbound_frame(&mut r).await;
    assert!(
        !join.is_finished(),
        "requests while choked drop silently; the connection must stay up"
    );
    drop(w);
}

/// fast bit = 0 and already unchoked — servable requests still get a
/// piece (serving is independent of fast negotiation); unservable
/// requests (an out-of-range index) are silently dropped, no Reject
/// (same spec basis; BEP-6 reject obligations only hold for connections
/// where "The extension is enabled only if both ends of the connection
/// set this bit").
#[tokio::test]
async fn unservable_request_silent_without_fast_but_serving_continues() {
    let mut config = PeerConfig::flat();
    config.peer_fast = false;
    config.source = Some(std::sync::Arc::new(StubSource));
    let (_root, handle, join, mut w, mut r, _data) = setup(config).await;
    unchoke_and_consume(&handle, &mut r).await;
    // Servable request → piece (serving ignores the negotiation gate).
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    let msg = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(msg, Message::Piece { ref block, .. } if block.len() == 16384),
        "a servable request must still get a piece, got {msg:?}"
    );
    // Unservable request (an out-of-range index) → no outbound frame.
    w.send(Message::Request {
        index: 99,
        begin: 0,
        length: 64,
    })
    .await
    .unwrap_or_else(|e| panic!("send 2: {e}"));
    assert_no_outbound_frame(&mut r).await;
    assert!(
        !join.is_finished(),
        "unservable requests drop silently; the connection must stay up"
    );
    drop(w);
}

/// Control anchor: fast bit = 1 (the same fixture with negotiation
/// present) → a request while we choke is still rejected (BEP-6 "If a
/// peer receives a request from a peer its choking, the peer receiving
/// the request SHOULD send a reject unless the piece is in the allowed
/// fast set").
#[tokio::test]
async fn request_while_am_choking_rejects_with_fast() {
    let mut config = PeerConfig::flat();
    config.peer_fast = true;
    let (_root, _handle, _join, mut w, mut r, _data) = setup(config).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    let msg = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(msg, Message::Reject { .. }),
        "a request while choked must reject when fast is negotiated, got {msg:?}"
    );
    drop(w);
}

/// Reject-pump guard decision table (libtorrent peer_connection.cpp
/// "allow peers to send request up to 2 seconds after getting choke,
/// then disconnect them" — see the `CHOKE_REQUEST_GRACE` docs for the
/// constant and the divergence).
/// Row 1: within the grace after our Choke, a request → reject only, no
/// disconnect.
/// Row 2: still requesting past the grace →
/// Violation(RequestsWhileChoked) disconnect (a leecher pumping
/// requests under our choke otherwise gets infinite rejects, draining
/// serving cycles for nothing).
/// Row 3: initially choked (never sent a Choke frame), an early request
/// → reject only, no disconnect (interop leniency for optimistic
/// pipelining, one notch wider than the reference).
#[tokio::test]
async fn requests_while_choked_grace_table() {
    fn grace_config() -> PeerConfig {
        let mut config = PeerConfig::flat();
        config.choke_grace = Duration::from_millis(60);
        config
    }

    // Row 1: within the grace after Choke (<60ms) → reject, no
    // disconnect.
    let (_root, handle, join, mut w, mut r, _data) = setup(grace_config()).await;
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    handle
        .command(PeerCommand::SendChoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    // Consume the outbound Unchoke/Choke frames first, then send the
    // request.
    use futures::StreamExt;
    for _ in 0..2 {
        let _ = tokio::time::timeout(Duration::from_secs(1), r.next())
            .await
            .unwrap_or_else(|e| panic!("timeout: {e}"))
            .unwrap_or_else(|| panic!("closed"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
    }
    w.send(Message::Request {
        index: 1,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    let msg = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(msg, Message::Reject { .. }),
        "row 1: reject within the grace window, got {msg:?}"
    );
    assert!(
        !join.is_finished(),
        "row 1: no disconnect within the grace window"
    );
    drop(w);
    handle.shutdown();

    // Row 2: requesting past the grace (>60ms) after Choke → violation
    // disconnect.
    let (_root, handle, join, mut w, _r, _data) = setup(grace_config()).await;
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    handle
        .command(PeerCommand::SendChoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    tokio::time::sleep(Duration::from_millis(140)).await;
    w.send(Message::Request {
        index: 2,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(
            end,
            PeerEnd::Violation(PeerError::RequestsWhileChoked { index: 2, .. })
        ),
        "row 2: requesting past the grace must violate-disconnect, got {end:?}"
    );
    drop(w);

    // Row 3: initially choked (never unchoke/choke = no Choke frame),
    // an early request → reject, no disconnect (wider than the
    // reference).
    let (_root, _handle, join, mut w, mut r, _data) = setup(grace_config()).await;
    tokio::time::sleep(Duration::from_millis(140)).await;
    w.send(Message::Request {
        index: 3,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("send: {e}"));
    let msg = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(msg, Message::Reject { .. }),
        "row 3: initially choked, reject only"
    );
    assert!(
        !join.is_finished(),
        "row 3: no Choke frame means no disconnect"
    );
    drop(w);
}

/// SendChoke command → Choke frame; a repeated SendChoke does not
/// resend (idempotent).
#[tokio::test]
async fn send_choke_command_sends_frame_once() {
    let (_root, handle, join, _w, mut r, _data) = setup(PeerConfig::flat()).await;
    handle
        .command(PeerCommand::SendUnchoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    handle
        .command(PeerCommand::SendChoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    handle
        .command(PeerCommand::SendChoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    use futures::StreamExt;
    let first = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(first, Message::Unchoke),
        "the first frame = Unchoke, got {first:?}"
    );
    let second = tokio::time::timeout(Duration::from_secs(1), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert!(
        matches!(second, Message::Choke),
        "the next frame = Choke, got {second:?}"
    );
    // A third SendChoke (already choked) → no new frame.
    let quiet = tokio::time::timeout(Duration::from_millis(150), r.next()).await;
    assert!(
        quiet.is_err(),
        "a repeated SendChoke must be idempotent, got {quiet:?}"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// Peer choke mirror: Choke/Unchoke frames drive is_choking_us (input
/// to dispatch peer selection).
#[tokio::test]
async fn peer_choking_mirror_tracks_frames() {
    let (_root, handle, join, mut w, _r, _data) = setup(PeerConfig::flat()).await;
    assert!(handle.is_choking_us(), "the BEP3 initial value = choke");
    w.send(Message::Unchoke)
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while handle.is_choking_us() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!handle.is_choking_us(), "Unchoke -> mirror cleared");
    w.send(Message::Choke)
        .await
        .unwrap_or_else(|e| panic!("send: {e}"));
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while !handle.is_choking_us() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(handle.is_choking_us(), "Choke -> mirror set");
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

// ---- BEP-6 have_all/have_none availability events ----

/// A fast-negotiating seeder's have_all/have_none inbound frames →
/// AvailEvent raised (previously only debug-logged, so the engine saw
/// no pieces and the seeder was never dispatched). Wire-driven (raw
/// frames injected from the duplex remote); a trailing HAVE still
/// eventizes — an explicit empty have_none does not cut off later
/// HAVEs.
#[tokio::test]
async fn have_all_and_have_none_emit_avail_events() {
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (avail_tx, mut avail_rx) = tokio::sync::mpsc::channel(8);
    let config = PeerConfig {
        cuid: 42,
        avail_tx: Some(avail_tx),
        ..PeerConfig::flat()
    };
    let (_handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (_r, mut w) = tokio::io::split(remote);
    use tokio::io::AsyncWriteExt as _;

    // have_all: <len=1><op=0x0E> (BEP-6).
    w.write_all(&[0, 0, 0, 1, 0x0E])
        .await
        .unwrap_or_else(|e| panic!("inject have_all: {e}"));
    let ev = tokio::time::timeout(Duration::from_secs(2), avail_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("have_all budget: {e}"))
        .unwrap_or_else(|| panic!("avail channel closed"));
    match ev {
        AvailEvent::HaveAll { peer } => assert_eq!(peer, 42, "the event echoes cuid"),
        other => panic!("expected HaveAll, got {other:?}"),
    }

    // have_none: <len=1><op=0x0F> (BEP-6).
    w.write_all(&[0, 0, 0, 1, 0x0F])
        .await
        .unwrap_or_else(|e| panic!("inject have_none: {e}"));
    let ev = tokio::time::timeout(Duration::from_secs(2), avail_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("have_none budget: {e}"))
        .unwrap_or_else(|| panic!("avail channel closed"));
    match ev {
        AvailEvent::HaveNone { peer } => assert_eq!(peer, 42),
        other => panic!("expected HaveNone, got {other:?}"),
    }

    // HAVE(3) increment as usual (a HAVE after HaveNone still reaches
    // the engine).
    w.write_all(&[0, 0, 0, 5, 4, 0, 0, 0, 3])
        .await
        .unwrap_or_else(|e| panic!("inject have: {e}"));
    let ev = tokio::time::timeout(Duration::from_secs(2), avail_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("have budget: {e}"))
        .unwrap_or_else(|| panic!("avail channel closed"));
    match ev {
        AvailEvent::Have { peer, index } => {
            assert_eq!(peer, 42);
            assert_eq!(index, 3);
        }
        other => panic!("expected Have, got {other:?}"),
    }

    drop(w);
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// An inbound Unchoke frame → `AvailEvent::Unchoked` edge event to the
/// engine (the re-dispatch trigger — the dispatch face sends zero
/// requests to a choking peer, so supply recovery after an unchoke
/// depends on this edge; no other natural event fires in the stall
/// window). This layer only proves the "unchoke → event" path; the edge
/// semantics are defined by engine-side consumption.
#[tokio::test]
async fn unchoke_emits_avail_event_edge() {
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (avail_tx, mut avail_rx) = tokio::sync::mpsc::channel(8);
    let config = PeerConfig {
        cuid: 42,
        avail_tx: Some(avail_tx),
        ..PeerConfig::flat()
    };
    let (_handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (_r, mut w) = tokio::io::split(remote);
    use tokio::io::AsyncWriteExt as _;

    // Unchoke: <len=1><op=0x01>.
    w.write_all(&[0, 0, 0, 1, 0x01])
        .await
        .unwrap_or_else(|e| panic!("inject unchoke: {e}"));
    let ev = tokio::time::timeout(Duration::from_secs(2), avail_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("unchoke budget: {e}"))
        .unwrap_or_else(|| panic!("avail channel closed"));
    match ev {
        AvailEvent::Unchoked { peer } => assert_eq!(peer, 42, "the event echoes cuid"),
        other => panic!("expected Unchoked, got {other:?}"),
    }

    drop(w);
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// An inbound Interested frame → `AvailEvent::Interested` **rising
/// edge** (the preemptive unchoke trigger; libtorrent
/// peer_connection.cpp). Edge table: row 1 first Interested → exactly
/// one event; row 2 a repeated Interested → no re-emit (quiet window);
/// row 3 NotInterested → Interested flip → one more event.
#[tokio::test]
async fn interested_emits_avail_event_edge() {
    let root = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (avail_tx, mut avail_rx) = tokio::sync::mpsc::channel(8);
    let config = PeerConfig {
        cuid: 42,
        avail_tx: Some(avail_tx),
        ..PeerConfig::flat()
    };
    let (_handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (_r, mut w) = tokio::io::split(remote);
    use tokio::io::AsyncWriteExt as _;

    // Row 1: Interested <len=1><op=0x02> → a rising-edge event (cuid
    // echoed).
    w.write_all(&[0, 0, 0, 1, 0x02])
        .await
        .unwrap_or_else(|e| panic!("inject interested: {e}"));
    let ev = tokio::time::timeout(Duration::from_secs(2), avail_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("interested budget: {e}"))
        .unwrap_or_else(|| panic!("avail channel closed"));
    match ev {
        AvailEvent::Interested { peer } => assert_eq!(peer, 42, "the event echoes cuid"),
        other => panic!("expected Interested, got {other:?}"),
    }

    // Row 2: a repeated Interested (level) → no re-emit (quiet window).
    w.write_all(&[0, 0, 0, 1, 0x02])
        .await
        .unwrap_or_else(|e| panic!("inject interested dup: {e}"));
    let quiet = tokio::time::timeout(Duration::from_millis(300), avail_rx.recv()).await;
    assert!(
        quiet.is_err(),
        "row 2: a repeated Interested must not re-emit (got {quiet:?})"
    );

    // Row 3: NotInterested (<len=1><op=0x03>) → Interested again → one
    // more rising edge.
    w.write_all(&[0, 0, 0, 1, 0x03])
        .await
        .unwrap_or_else(|e| panic!("inject not interested: {e}"));
    w.write_all(&[0, 0, 0, 1, 0x02])
        .await
        .unwrap_or_else(|e| panic!("inject interested again: {e}"));
    let ev = tokio::time::timeout(Duration::from_secs(2), avail_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("re-interested budget: {e}"))
        .unwrap_or_else(|| panic!("avail channel closed"));
    match ev {
        AvailEvent::Interested { peer } => assert_eq!(peer, 42, "row 3: re-raised after the flip"),
        other => panic!("row 3: expected Interested, got {other:?}"),
    }

    drop(w);
    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

// ---------- idle-gated keepalive outbound ----------

/// An idle connection emits a zero-length keepalive (BEP-3 `<len=0>`)
/// after keepalive_interval, and sending resets the timer — two
/// keepalives are >= interval apart (if the timer did not reset on
/// send, the next tick would resend ≈ flooding_interval=10ms and be
/// caught in the quiet window). The interval defaults to 120s (aria2
/// `--bt-keep-alive-interval`, OptionHandlerFactory.cc); tests inject a
/// short value (the `flooding_interval` precedent) instead of really
/// sleeping.
#[tokio::test]
async fn keepalive_sent_periodically_when_idle() {
    let mut config = PeerConfig::flat();
    config.flooding_interval = Duration::from_millis(10);
    config.keepalive_interval = Duration::from_millis(80);
    let (_root, handle, join, _w, mut remote_r, _data) = setup(config).await;

    // With no self-initiated outbound (ext off), the first frame the
    // peer receives is the keepalive (the idle origin = connection
    // assembly, like aria2 resetting `keepAliveTimer_` after the
    // handshake, DefaultBtInteractive.cc).
    let first = tokio::time::timeout(Duration::from_secs(2), remote_r.next())
        .await
        .unwrap_or_else(|e| panic!("no first keepalive within budget: {e}"))
        .unwrap_or_else(|| panic!("remote closed before keepalive"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert_eq!(
        first,
        Message::KeepAlive,
        "idle connection must emit keepalive"
    );

    // Sending resets the timer: any frame within a 30ms quiet window
    // (<< interval=80ms) would be a redundant frame.
    let quiet = tokio::time::timeout(Duration::from_millis(30), remote_r.next()).await;
    assert!(
        quiet.is_err(),
        "keepalive timer must reset on send, got {quiet:?}"
    );

    // The timer reset and the cycle continues: the second keepalive
    // arrives after the next idle window.
    let second = tokio::time::timeout(Duration::from_secs(2), remote_r.next())
        .await
        .unwrap_or_else(|e| panic!("no periodic keepalive within budget: {e}"))
        .unwrap_or_else(|| panic!("remote closed before second keepalive"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"));
    assert_eq!(second, Message::KeepAlive);
    assert!(!join.is_finished(), "keepalive must not terminate the loop");
    handle.shutdown();
}

/// An active connection emits zero redundant frames — any outbound
/// frame (here a Have via the command face) keeps refreshing the idle
/// timer so keepalive never fires (mirrors libtorrent
/// `peer_connection.cpp` keep_alive's `m_last_sent` gate): the peer
/// receives N Have frames with no keepalive mixed in.
#[tokio::test]
async fn active_connection_suppresses_keepalive() {
    let mut config = PeerConfig::flat();
    config.flooding_interval = Duration::from_millis(10);
    config.keepalive_interval = Duration::from_millis(60);
    let (_root, handle, _join, _w, mut remote_r, _data) = setup(config).await;

    const N: u32 = 12;
    for i in 0..N {
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle
            .command(PeerCommand::SendHave { index: i })
            .unwrap_or_else(|e| panic!("command rejected: {e:?}"));
    }
    // Outbound cadence ≈ 10ms << interval=60ms → the idle timer must
    // never be satisfied. Receive all N frames: any keepalive mixed in
    // = the timer not refreshing on outbound (regression).
    for i in 0..N {
        let frame = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("have {i} not received within budget: {e}"))
            .unwrap_or_else(|| panic!("remote closed at have {i}"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert!(
            matches!(frame, Message::Have { .. }),
            "active connection must not emit keepalive, got {frame:?}"
        );
    }
    // Quiet window 25ms << interval: a frame readable right after is a
    // regression signal.
    let quiet = tokio::time::timeout(Duration::from_millis(25), remote_r.next()).await;
    assert!(
        quiet.is_err(),
        "no frame expected while outbound stays active, got {quiet:?}"
    );
    handle.shutdown();
}

/// Our own keepalives never count toward flood detection — FloodGuard
/// observes inbound only (inbound.rs `Message::KeepAlive =>
/// flood.observe_keepalive()`; aria2 `DefaultBtInteractive.cc`
/// likewise counts the receive side only). A sub-tick interval keeps
/// the connection sending keepalives (300ms ≈ 15 check windows, far
/// past the keepalive dimension threshold of 2/window): the connection
/// stays alive the whole time, the peer receives only keepalives, and
/// the end state is not Flooded.
#[tokio::test]
async fn outbound_keepalive_never_counts_toward_flood_guard() {
    let mut config = PeerConfig::flat();
    config.flooding_interval = Duration::from_millis(20);
    config.keepalive_interval = Duration::from_millis(5);
    let (_root, handle, join, _w, mut remote_r, _data) = setup(config).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !join.is_finished(),
        "our own keepalives must never trip the flood guard"
    );
    // The peer really keeps receiving (all keepalives — the assertion
    // target is non-empty).
    for i in 0..5 {
        let frame = tokio::time::timeout(Duration::from_secs(1), remote_r.next())
            .await
            .unwrap_or_else(|e| panic!("keepalive {i} not received within budget: {e}"))
            .unwrap_or_else(|| panic!("remote closed at keepalive {i}"))
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        assert_eq!(frame, Message::KeepAlive, "expected keepalive frame {i}");
    }
    handle.shutdown();
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("shutdown budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(end, PeerEnd::Clean | PeerEnd::Cancelled),
        "connection must not end Flooded, got {end:?}"
    );
}

// ---- Direct block delivery seam (BlockSink): dual-path equivalence ----
// ---- and backpressure semantics ----

/// Mock direct sink: a capacity-1 recording channel + a backpressure-
/// path flag (the slow path is observable).
struct MockSink {
    tx: tokio::sync::mpsc::Sender<(PieceId, u32, Bytes)>,
    backpressure_used: std::sync::atomic::AtomicBool,
}

impl BlockSink for MockSink {
    fn try_deliver(&self, id: PieceId, begin: u32, block: Bytes) -> Result<(), Bytes> {
        match self.tx.try_send((id, begin, block)) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full((_, _, b))) => Err(b),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(()),
        }
    }

    fn deliver_backpressure(
        &self,
        id: PieceId,
        begin: u32,
        block: Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let tx = self.tx.clone();
        self.backpressure_used
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            let _ = tx.send((id, begin, block)).await;
        })
    }
}

/// The direct path is frame-for-frame equivalent to the legacy data_tx
/// path: a slot-matched piece is delivered to the sink with the same
/// coordinates (PieceId/begin) and payload; the legacy channel gets
/// zero deliveries (the data face no longer borrows that path).
#[tokio::test]
async fn direct_sink_delivers_matched_piece_identically() {
    let (tx, mut sink_rx) = tokio::sync::mpsc::channel(8);
    let sink = Arc::new(MockSink {
        tx,
        backpressure_used: std::sync::atomic::AtomicBool::new(false),
    });
    let mut config = PeerConfig::flat();
    config.direct_block_sink = Some(Arc::clone(&sink) as Arc<dyn BlockSink>);
    let (_root, handle, join, mut remote_w, _remote_r, mut data_rx) = setup(config).await;
    let _ = request_via(&handle, PieceId::V1(3), 16384).await;

    let block = Bytes::from(vec![7u8; 16384]);
    remote_w
        .send(Message::Piece {
            index: 3,
            begin: 16384,
            block: block.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("send piece: {e}"));

    let (id, begin, got) = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("sink timeout: {e}"))
        .unwrap_or_else(|| panic!("sink channel closed"));
    // Same coordinates and payload as
    // [`matched_piece_forwarded_to_data_channel`] (that test locks
    // (V1(3), 16384, block) — aligned verbatim here).
    assert_eq!(id, PieceId::V1(3));
    assert_eq!(begin, 16384);
    assert_eq!(got, block);
    // Zero legacy deliveries: with the direct sink present the data
    // face never enters data_tx.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), data_rx.recv())
            .await
            .is_err(),
        "with the direct sink present, data_tx must receive no delivery"
    );
    assert!(
        !sink
            .backpressure_used
            .load(std::sync::atomic::Ordering::SeqCst),
        "the normal path takes the try_deliver fast path (zero backpressure)"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

/// With the direct sink present the wire violation face is unchanged: an
/// out-of-range wire index still disconnects with BadPieceIndex
/// (addressing validation stays on the bt side as-is; the sink only
/// receives legal PieceIds — conversion/out-of-range defense lives on
/// the core side).
#[tokio::test]
async fn direct_sink_keeps_out_of_range_index_violation() {
    let (tx, _sink_rx) = tokio::sync::mpsc::channel(8);
    let sink = Arc::new(MockSink {
        tx,
        backpressure_used: std::sync::atomic::AtomicBool::new(false),
    });
    let mut config = PeerConfig::flat();
    config.direct_block_sink = Some(Arc::clone(&sink) as Arc<dyn BlockSink>);
    let (_root, _handle, join, mut remote_w, _remote_r, _data) = setup(config).await;
    remote_w
        .send(Message::Piece {
            index: 999,
            begin: 0,
            block: Bytes::from(vec![0u8; 16]),
        })
        .await
        .unwrap_or_else(|e| panic!("send piece: {e}"));
    let end = tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .unwrap_or_else(|e| panic!("budget: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"));
    assert!(
        matches!(end, PeerEnd::Violation(_)),
        "an out-of-range index must disconnect (got {end:?}) — consistent with the old path"
    );
}

/// Backpressure slow path: sink capacity 1, the second block's try
/// returns full → the read loop turns to deliver_backpressure await
/// (this connection's frame reading pauses = the face channel is full);
/// after draining, both blocks arrive and the backpressure flag is set.
#[tokio::test]
async fn direct_sink_backpressures_when_channel_full() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    let sink = Arc::new(MockSink {
        tx,
        backpressure_used: std::sync::atomic::AtomicBool::new(false),
    });
    let mut config = PeerConfig::flat();
    config.direct_block_sink = Some(Arc::clone(&sink) as Arc<dyn BlockSink>);
    let (_root, handle, join, mut remote_w, _remote_r, _data) = setup(config).await;
    // Two slot requests + two blocks back to back (sink capacity 1: the
    // second block must take the backpressure path).
    let _ = request_via(&handle, PieceId::V1(0), 0).await;
    let _ = request_via(&handle, PieceId::V1(1), 0).await;
    for index in 0..2u32 {
        remote_w
            .send(Message::Piece {
                index,
                begin: 0,
                block: Bytes::from(vec![index as u8; 16384]),
            })
            .await
            .unwrap_or_else(|e| panic!("send piece {index}: {e}"));
    }
    drop(remote_w);
    let mut seen = Vec::new();
    while let Some((id, _, block)) = rx.recv().await {
        seen.push((id, block[0]));
        if seen.len() == 2 {
            break;
        }
    }
    seen.sort_by_key(|(id, _)| *id);
    assert_eq!(
        seen,
        vec![(PieceId::V1(0), 0), (PieceId::V1(1), 1)],
        "both blocks arrive (including the backpressure-path delivery)"
    );
    assert!(
        sink.backpressure_used
            .load(std::sync::atomic::Ordering::SeqCst),
        "with capacity 1, the second block must take the backpressure slow path"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

//! Acceptance tests for the pooled serve read path (`PeerConfig::read_pool = Some`):
//! commands stay responsive while a read blocks, out-of-order completions
//! replay in request order (matching the inline path), and a pooled read
//! failure rejects (BEP3 fast-extension advertiser duty).

use super::*;
use crate::peer_wire::FrameCodec;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::duplex;

/// Slow-disk source: read_block blocks for `delay` (the spawn_blocking
/// form of a real disk syscall), then fills the buffer with
/// index-identifiable bytes.
struct SlowSource {
    delay: Duration,
}

impl PieceSource for SlowSource {
    fn read_block(&self, index: u32, _begin: u32, buf: &mut [u8]) -> Result<usize, String> {
        std::thread::sleep(self.delay);
        buf.fill(if index == 0 { 0xAB } else { 0xBB });
        Ok(buf.len())
    }
    fn total_len(&self) -> u64 {
        2 * 16384
    }
}

/// Gated source: the index 0 read parks on a test gate (sets `started`,
/// then waits for release) while the others finish immediately (sets
/// `fast_done`) — deterministic out-of-order completion. With a pool of 2
/// dispatchers / batch 1, seq0 holds dispatcher 0 and seq1 finishes first
/// on dispatcher 1.
struct GatedSource {
    started: Arc<AtomicU32>,
    fast_done: Arc<AtomicU32>,
    release: StdMutex<std::sync::mpsc::Receiver<()>>,
    completion_order: Arc<StdMutex<Vec<u32>>>,
}

impl PieceSource for GatedSource {
    fn read_block(&self, index: u32, _begin: u32, buf: &mut [u8]) -> Result<usize, String> {
        if index == 0 {
            self.started.fetch_add(1, Ordering::SeqCst);
            match self
                .release
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv()
            {
                Ok(()) => {}
                Err(_) => panic!("release channel closed"),
            }
        }
        buf.fill(if index == 0 { 0xAB } else { 0xBB });
        self.completion_order
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(index);
        if index != 0 {
            self.fast_done.fetch_add(1, Ordering::SeqCst);
        }
        Ok(buf.len())
    }
    fn total_len(&self) -> u64 {
        2 * 16384
    }
}

/// Duplex harness for pooled serve (same shape as
/// seeding_tests::setup_with_source plus a read_pool injection; starts
/// serving by unchoking and consumes that frame). `peer_fast` injects the
/// peer's BEP6 fast bit.
async fn setup_with_pool(
    peer_fast: bool,
    source: Option<Arc<dyn PieceSource>>,
    hash_source: Option<Arc<dyn HashSource>>,
    pool: Option<Arc<ReadPool>>,
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
    config.peer_fast = peer_fast;
    config.source = source;
    config.hash_source = hash_source;
    config.read_pool = pool;
    let (handle, join, _data) = PeerTask::spawn(&root, local, config);
    let (r, w) = tokio::io::split(remote);
    let mut reader = FramedRead::new(r, FrameCodec::default());
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
    r: &mut FramedRead<tokio::io::ReadHalf<tokio::io::DuplexStream>, FrameCodec>,
) -> Message {
    use futures::StreamExt;
    tokio::time::timeout(Duration::from_secs(2), r.next())
        .await
        .unwrap_or_else(|e| panic!("timeout: {e}"))
        .unwrap_or_else(|| panic!("closed"))
        .unwrap_or_else(|e| panic!("decode: {e:?}"))
}

/// While a slow disk (400ms blocking read) is being served, the peer's
/// command response (SendHave -> Have frame) is unaffected; the piece is
/// then delivered as usual with correct contents.
#[tokio::test]
async fn slow_disk_serve_keeps_peer_loop_responsive() {
    let pool = ReadPool::with_limits(2, 4);
    let (handle, mut w, mut r, join) = setup_with_pool(
        true,
        Some(Arc::new(SlowSource {
            delay: Duration::from_millis(400),
        })),
        None,
        Some(pool),
    )
    .await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    // While the read blocks inside the pool (400ms), command responses stay unaffected.
    let t0 = Instant::now();
    handle
        .command(PeerCommand::SendHave { index: 7 })
        .unwrap_or_else(|e| panic!("{e:?}"));
    match next_frame(&mut r).await {
        Message::Have { index } => assert_eq!(index, 7),
        other => panic!("expected have, got {other:?}"),
    }
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(200),
        "command responses are not blocked by the disk read (acceptance item): {elapsed:?}"
    );
    // The piece is still delivered in the end (no zero-content fallback on the pooled path).
    match next_frame(&mut r).await {
        Message::Piece {
            index,
            begin,
            block,
        } => {
            assert_eq!((index, begin), (0, 0));
            assert_eq!(block.len(), 16384);
            assert!(block.iter().all(|&b| b == 0xAB));
        }
        other => panic!("expected piece, got {other:?}"),
    }
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// Out-of-order completions replay in request order: seq0 parks on the
/// gate (dispatcher 0) while seq1 completes immediately (dispatcher 1) —
/// completion order [1, 0] but wire frame order [0, 1] (ServeQueue replays
/// by request slot; frame order matches the inline path).
#[tokio::test]
async fn pooled_serve_replays_pieces_in_request_order() {
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let started = Arc::new(AtomicU32::new(0));
    let fast_done = Arc::new(AtomicU32::new(0));
    let completion_order = Arc::new(StdMutex::new(Vec::new()));
    let src = Arc::new(GatedSource {
        started: Arc::clone(&started),
        fast_done: Arc::clone(&fast_done),
        release: StdMutex::new(release_rx),
        completion_order: Arc::clone(&completion_order),
    });
    let pool = ReadPool::with_limits(2, 1);
    let (handle, mut w, mut r, join) = setup_with_pool(true, Some(src), None, Some(pool)).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    // seq0 has entered the source (parked on the gate).
    for _ in 0..2000 {
        if started.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        started.load(Ordering::SeqCst) >= 1,
        "seq0 never entered the source"
    );
    w.send(Message::Request {
        index: 1,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    // Wait for seq1 to finish outside the gate (fast_done set) while seq0
    // is still parked: completion order starts [1, ...] — the deterministic
    // precondition for out-of-order delivery.
    for _ in 0..2000 {
        if fast_done.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        fast_done.load(Ordering::SeqCst) >= 1,
        "seq1 did not finish before the gate released"
    );
    // Release seq0; the two pieces arrive in request order.
    release_tx
        .send(())
        .unwrap_or_else(|e| panic!("release: {e}"));
    match next_frame(&mut r).await {
        Message::Piece { index, block, .. } => {
            assert_eq!(
                index, 0,
                "the first frame must be seq0's piece (request order)"
            );
            assert!(block.iter().all(|&b| b == 0xAB));
        }
        other => panic!("expected piece 0, got {other:?}"),
    }
    match next_frame(&mut r).await {
        Message::Piece { index, block, .. } => {
            assert_eq!(index, 1);
            assert!(block.iter().all(|&b| b == 0xBB));
        }
        other => panic!("expected piece 1, got {other:?}"),
    }
    // Prove the replay happened: sending in completion order would give wire order [1, 0].
    assert_eq!(
        *completion_order.lock().unwrap_or_else(|e| e.into_inner()),
        vec![1, 0],
        "the source-side completion order must be out of order (1 before 0), otherwise this test does not cover the replay path"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// A pooled read failure rejects (BEP3 fast-extension duty; the reject
/// semantics hold through the pool).
#[tokio::test]
async fn pooled_serve_read_error_rejects() {
    struct ErrSource;
    impl PieceSource for ErrSource {
        fn read_block(&self, _: u32, _: u32, _: &mut [u8]) -> Result<usize, String> {
            Err("missing file (pool path)".into())
        }
        fn total_len(&self) -> u64 {
            32768
        }
    }
    let pool = ReadPool::with_limits(1, 4);
    let (handle, mut w, mut r, join) =
        setup_with_pool(true, Some(Arc::new(ErrSource)), None, Some(pool)).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 4096,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(
            next_frame(&mut r).await,
            Message::Reject {
                index: 0,
                begin: 0,
                length: 4096
            }
        ),
        "a pooled read failure must reject"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// With the peer's fast bit = 0, a pooled read failure must not send
/// Reject — BEP6: "If the fast extension is disabled and a peer receives a
/// reject request then the peer MUST close the connection" (rejecting an
/// unadvertised peer would force that close; the BEP3 fallback drops
/// silently, the same rule as aria2 BtRequestMessage.cc and libtorrent
/// bt_peer_connection.cpp `write_reject_request`:
/// `if (!m_supports_fast) return;`). The connection stays up.
#[tokio::test]
async fn pooled_serve_read_error_silent_without_fast() {
    struct ErrSource;
    impl PieceSource for ErrSource {
        fn read_block(&self, _: u32, _: u32, _: &mut [u8]) -> Result<usize, String> {
            Err("missing file (pool path, no fast)".into())
        }
        fn total_len(&self) -> u64 {
            32768
        }
    }
    let pool = ReadPool::with_limits(1, 4);
    let (handle, mut w, mut r, join) =
        setup_with_pool(false, Some(Arc::new(ErrSource)), None, Some(pool)).await;
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 4096,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    // Silence window: a Reject, if one were sent, would arrive far inside it.
    use futures::StreamExt;
    match tokio::time::timeout(Duration::from_millis(300), r.next()).await {
        Err(_) => {}
        Ok(Some(Ok(msg))) => {
            panic!("a peer without negotiated fast must not receive Reject, got {msg:?}")
        }
        Ok(Some(Err(e))) => panic!("decode: {e:?}"),
        Ok(None) => panic!("the connection closed unexpectedly"),
    }
    assert!(
        !join.is_finished(),
        "unservable requests drop silently; the connection must stay up"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// SendChoke pruning with a fast-negotiated peer: seq0 has been taken by
/// the only dispatcher (a gated read in progress = being processed) while
/// seq1 still sits in the job queue (read not started). Our SendChoke must
/// reject unstarted seq1 slot by slot — BEP6: "If a peer sends a choke, it
/// MUST reject all requests from the peer to whom the choke was sent"
/// (frame order follows "A peer SHOULD choke first and then reject
/// requests so that the peer receiving the choke does not re-request the
/// pieces" — the Choke frame comes first). The started seq0 is allowed to
/// complete — "requests that are being processed are allowed to complete"
/// — and delivers its piece once released.
#[tokio::test]
async fn choke_rejects_unstarted_pooled_requests_but_started_completes() {
    /// Canonical-count hash stub (same shape as the BEP52 case below): a
    /// deterministic "requests are pooled" barrier before SendChoke — the
    /// Hashes reply arriving means the Request frames sent in the same
    /// window were processed and enqueued by peer_loop (FIFO frame
    /// handling). Without it, the biased select could run SendChoke before
    /// the read arm and hit the choked inbound-reject path instead of
    /// queue pruning.
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
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let started = Arc::new(AtomicU32::new(0));
    let fast_done = Arc::new(AtomicU32::new(0));
    let completion_order = Arc::new(StdMutex::new(Vec::new()));
    let src = Arc::new(GatedSource {
        started: Arc::clone(&started),
        fast_done: Arc::clone(&fast_done),
        release: StdMutex::new(release_rx),
        completion_order: Arc::clone(&completion_order),
    });
    // 1 dispatcher / batch 1: seq0 occupies the only dispatcher (parked on
    // the gate), so seq1 necessarily stays in the job queue — a
    // deterministic "read not started".
    let pool = ReadPool::with_limits(1, 1);
    let (handle, mut w, mut r, join) =
        setup_with_pool(true, Some(src), Some(Arc::new(OkSource)), Some(pool)).await;

    // seq0: pooled and taken by the dispatcher (gated read in progress = being processed).
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    for _ in 0..2000 {
        if started.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        started.load(Ordering::SeqCst) >= 1,
        "seq0 never entered the source (read not started -> test premise broken)"
    );

    // seq1: the only dispatcher is held by seq0, so it stays in the job queue (read not started).
    w.send(Message::Request {
        index: 1,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    // Barrier: the Hashes reply arriving means Request(seq1) was processed and pooled.
    w.send(Message::HashRequest {
        root: [2u8; 32],
        base: 1,
        index: 0,
        length: 2,
        proof: 0,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    match next_frame(&mut r).await {
        Message::Hashes { .. } => {}
        other => panic!("the barrier frame must be Hashes, got {other:?}"),
    }

    // Our SendChoke: the Choke frame arrives first (SHOULD choke first and then reject).
    handle
        .command(PeerCommand::SendChoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    match next_frame(&mut r).await {
        Message::Choke => {}
        other => panic!("expected choke, got {other:?}"),
    }
    // Unstarted seq1: rejected slot by slot (BEP6 MUST).
    match next_frame(&mut r).await {
        Message::Reject {
            index,
            begin,
            length,
        } => {
            assert_eq!(
                (index, begin, length),
                (1, 0, 16384),
                "pruned slot coordinates = seq1's request coordinates"
            );
        }
        other => panic!(
            "an unstarted in-flight request must Reject after choke (BEP6 MUST), got {other:?}"
        ),
    }
    // Started seq0: released, its piece is delivered as usual (allowed to complete).
    release_tx
        .send(())
        .unwrap_or_else(|e| panic!("release: {e}"));
    match next_frame(&mut r).await {
        Message::Piece { index, block, .. } => {
            assert_eq!(index, 0, "a started read must complete delivery");
            assert_eq!(block.len(), 16384);
            assert!(block.iter().all(|&b| b == 0xAB));
        }
        other => panic!("a started read must complete delivery (BEP6), got {other:?}"),
    }
    // Exactly one answer: seq1 was already rejected, so no further piece may arrive.
    use futures::StreamExt;
    match tokio::time::timeout(Duration::from_millis(300), r.next()).await {
        Err(_) => {}
        Ok(Some(Ok(msg))) => {
            panic!("an already-rejected slot must not deliver a second answer, got {msg:?}")
        }
        Ok(Some(Err(e))) => panic!("decode: {e:?}"),
        Ok(None) => panic!("the connection closed unexpectedly"),
    }
    assert!(!join.is_finished(), "pruning must not disconnect");
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// With fast not negotiated, SendChoke pruning is silent: unstarted slots
/// get no Reject (BEP6: "If the fast extension is disabled and a peer
/// receives a reject request then the peer MUST close the connection" —
/// rejecting such a peer would force it to disconnect; the BEP3 fallback
/// drops silently and the peer's request times out; see
/// [`OutboundWriter::send_reject`] for the outbound side) and are no
/// longer served (no piece after pruning). Started slots still complete —
/// serving is orthogonal to fast negotiation.
#[tokio::test]
async fn choke_cuts_unstarted_silently_without_fast() {
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
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let started = Arc::new(AtomicU32::new(0));
    let fast_done = Arc::new(AtomicU32::new(0));
    let completion_order = Arc::new(StdMutex::new(Vec::new()));
    let src = Arc::new(GatedSource {
        started: Arc::clone(&started),
        fast_done: Arc::clone(&fast_done),
        release: StdMutex::new(release_rx),
        completion_order: Arc::clone(&completion_order),
    });
    let pool = ReadPool::with_limits(1, 1);
    let (handle, mut w, mut r, join) =
        setup_with_pool(false, Some(src), Some(Arc::new(OkSource)), Some(pool)).await;

    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    for _ in 0..2000 {
        if started.load(Ordering::SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        started.load(Ordering::SeqCst) >= 1,
        "seq0 never entered the source (read not started -> test premise broken)"
    );
    w.send(Message::Request {
        index: 1,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    w.send(Message::HashRequest {
        root: [2u8; 32],
        base: 1,
        index: 0,
        length: 2,
        proof: 0,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    match next_frame(&mut r).await {
        Message::Hashes { .. } => {}
        other => panic!("the barrier frame must be Hashes, got {other:?}"),
    }

    handle
        .command(PeerCommand::SendChoke)
        .unwrap_or_else(|e| panic!("{e:?}"));
    match next_frame(&mut r).await {
        Message::Choke => {}
        other => panic!("expected choke, got {other:?}"),
    }
    // Silence window: without fast, unstarted slots get no Reject.
    use futures::StreamExt;
    match tokio::time::timeout(Duration::from_millis(300), r.next()).await {
        Err(_) => {}
        Ok(Some(Ok(msg))) => {
            panic!("a peer without negotiated fast must not receive Reject, got {msg:?}")
        }
        Ok(Some(Err(e))) => panic!("decode: {e:?}"),
        Ok(None) => panic!("the connection closed unexpectedly"),
    }
    // Started seq0: released, its piece is delivered as usual.
    release_tx
        .send(())
        .unwrap_or_else(|e| panic!("release: {e}"));
    match next_frame(&mut r).await {
        Message::Piece { index, block, .. } => {
            assert_eq!(
                index, 0,
                "a started read must complete delivery (serving is orthogonal to negotiation)"
            );
            assert!(block.iter().all(|&b| b == 0xAB));
        }
        other => panic!("a started read must complete delivery (BEP6), got {other:?}"),
    }
    // The pruned seq1 must not deliver a piece.
    match tokio::time::timeout(Duration::from_millis(300), r.next()).await {
        Err(_) => {}
        Ok(Some(Ok(msg))) => {
            panic!("a choke-pruned unstarted slot must not deliver afterwards, got {msg:?}")
        }
        Ok(Some(Err(e))) => panic!("decode: {e:?}"),
        Ok(None) => panic!("the connection closed unexpectedly"),
    }
    assert!(!join.is_finished(), "pruning must not disconnect");
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
}

/// BEP52 mandatory-item regression on the pooled path (mirrors the
/// seeding_tests case with read_pool = Some; the completion arm sets
/// last_piece_served before the piece is actually sent): once the rate
/// window is exhausted, a base=0 hash request right after a piece delivery
/// must still be answered with hashes (MUST takes priority over rate
/// limiting, SPEC §13).
#[tokio::test]
async fn pooled_piece_served_makes_following_hash_request_mandatory() {
    /// Canonical-count hash stub (same shape as seeding_tests::OkSource).
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
        fn read_block(&self, _: u32, _: u32, buf: &mut [u8]) -> Result<usize, String> {
            buf.fill(0xAB);
            Ok(buf.len())
        }
        fn total_len(&self) -> u64 {
            32768
        }
    }
    let pool = ReadPool::with_limits(2, 4);
    let (handle, mut w, mut r, join) = setup_with_pool(
        true,
        Some(Arc::new(PieceSrc)),
        Some(Arc::new(OkSource)),
        Some(pool),
    )
    .await;

    // Exhaust the rate window before serving the piece: the first
    // HASH_REQUEST_LIMIT requests are served, the next one is rejected
    // (the window stays exhausted within the same 60s period).
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
        let msg = next_frame(&mut r).await;
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

    // Request one piece and serve it through the pooled path (sets the marker on actual send).
    w.send(Message::Request {
        index: 0,
        begin: 0,
        length: 16384,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = next_frame(&mut r).await;
    assert!(matches!(msg, Message::Piece { .. }), "got {msg:?}");

    // base=0 right after the piece delivery: hashes even with the window exhausted (MUST wins).
    w.send(Message::HashRequest {
        root: [2u8; 32],
        base: 0,
        index: 0,
        length: 2,
        proof: 0,
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let msg = next_frame(&mut r).await;
    assert!(
        matches!(msg, Message::Hashes { base: 0, .. }),
        "base=0 right after a piece delivery must answer with hashes (BEP52 MUST), got {msg:?}"
    );
    handle.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(1), join).await;
}

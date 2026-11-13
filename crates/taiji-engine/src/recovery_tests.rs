//! hash recovery tests (peer-selection table / data-plane registration /
//! bounded in-flight cap / duplex integration delivering a complete
//! layer / reject-timeout-disconnect branch convergence).
//!
//! Cross-check sources (same as the dispatch recovery section): at most
//! 1 in-flight request per peer (libtorrent `bt_peer_connection.cpp`);
//! coverage-first peer choice (the dual of the BEP52 serving obligation +
//! `hash_picker.cpp`); timeout/retry constants follow the lazy-fetch
//! face (`hash_fetch.rs`).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use taiji_bt::peer::{HashSource as _, PeerTaskHandle, PieceSource as _};
use taiji_bt::peer_wire::Message;
use taiji_bt::piece_id::Addressing;
use taiji_bt::piece_stat::PieceStatMan;
use taiji_store::merkle;
use taiji_store::torrent_writer::TorrentReader;

use super::*;
use std::collections::HashMap;

use taiji_bt::choke::{LeecherChoke, SeederChoke};
use taiji_bt::peer_wire::Reserved;

use crate::bitmap::PieceBitmap;
use crate::dispatch::{
    FileRecovery, HashFetchEvent, LayerFetchState, RECOVERY_DELIVER_CAPACITY,
    RECOVERY_TRIED_COOLDOWN, RecoveryBook, RecoveryFetchFail, RecoveryFetchState, active_tried,
    build_v2_data_plane, dispatch_face_selected_with_stream, drive_recovery,
    handle_recovery_reply_and_drive, note_peer_bitfield, note_recovery_evidence,
    recovery_peer_order,
};
use crate::faces::{FaceState, FaceView, PexCandidates, SwarmSnapshot, XorShift};
use crate::pipeline::DataFlushState;
use crate::run::recovery_admit::{
    RecoveryAdmissionStats, activate_recovered_file, consume_recovered_layer_core,
};
use crate::strategy::RarestFirstStrategy;
use crate::tracker::TrackerMirror;
use crate::upload::PartialFaceSource;
use taiji_domain::hash_fetch::{HashRequestPlan, RecoveredPieceLayer};
use taiji_domain::progress::ProgressModel;
// Explicit mode constructors keep tests deterministic: no drift with the
// env fallback switch.
use taiji_bt::choke::{ChokeMode, SeedingPolicy};
use taiji_domain::hash_fetch::HASH_FETCH_MAX_ATTEMPTS;
use taiji_domain::hash_source::MetaHashSource;
use taiji_domain::metainfo::MetaFile;

type RemoteReader = tokio::io::ReadHalf<tokio::io::DuplexStream>;
type RemoteWriter = tokio::io::WriteHalf<tokio::io::DuplexStream>;

/// Recovery piece root (bpp leaf folding; a 32KiB piece at bpp=2).
fn piece_root(leaves: &[[u8; 32]], bpp: usize) -> [u8; 32] {
    merkle::piece_root_from_block_hashes(leaves, bpp)
}

/// Recovery face fixture (v2 face, `piece_count` pieces of `piece_len`,
/// no peers). pub(crate): consumer-side tests (run::recovery_admit)
/// reuse this same-shaped face.
pub(crate) fn recovery_face(piece_count: usize, piece_len: u32) -> FaceState {
    let (block_tx, _rx) = mpsc::channel(1);
    let (fetch_tx, _frx) = mpsc::channel(16);
    // Final-barrier seam: the fixture has no pipeline counterpart — the
    // trigger end has no consumer and the barrier stays Pending (the
    // final-row wait face is not on the fixture's consumption path).
    let (final_flush_tx, _final_flush_rx) = mpsc::channel::<()>(1);
    let (_data_flush_gate, data_flush_gate) = tokio::sync::watch::channel(DataFlushState::Pending);
    let mut stat_rng = XorShift(0x853C49E6748FEA9Bu64);
    let file_len = piece_count as u64 * u64::from(piece_len);
    FaceState {
        kind: FaceKind::V2,
        info_hash: [0u8; 20],
        reserved: Reserved::aria2_default(),
        addressing: Addressing::PerFile {
            piece_bases: vec![0],
        },
        piece_bytes: vec![u64::from(piece_len); piece_count].into(),
        piece_goffs: Arc::new(
            (0..piece_count as u64)
                .map(|k| k * u64::from(piece_len))
                .collect(),
        ),
        progress: ProgressModel::from_lengths(&[file_len], piece_len),
        piece_count,
        verified_count: 0,
        stat_man: PieceStatMan::new(piece_count as u64, &mut |n| stat_rng.next(n)),
        peer_avail: std::collections::HashMap::new(),
        peer_seeds: std::collections::HashSet::new(),
        peers: Vec::new(),
        peer_cuids: Vec::new(),
        // The per-peer unified row table.
        peer_state: std::collections::HashMap::new(),
        block_senders: Arc::new(Mutex::new(HashMap::new())),
        choke: SeederChoke::with(ChokeMode::Libtorrent, SeedingPolicy::FastestUpload),
        leecher_choke: LeecherChoke::with_mode(ChokeMode::Libtorrent),
        regular_unchoked: std::collections::HashSet::new(),
        download_source: None,
        written_bits: Arc::new(PieceBitmap::new(piece_count)),
        // Same shape as progress (production clones it after recovery;
        // the two models diverge from here).
        written_progress: ProgressModel::from_lengths(&[file_len], piece_len),
        written_count: 0,
        selected_written_count: 0,
        completed: false,
        hash_files: None,
        swarm: FaceView(Arc::new(Mutex::new(SwarmSnapshot {
            total: file_len,
            completed: 0,
            all_finished: false,
            peers: 0,
            uploaded: 0,
            downloaded: 0,
        }))),
        mirror: TrackerMirror::new(&[], ""),
        block_cursor: 0,
        block_tx,
        trees: None,
        flat_coords: Arc::new((0..piece_count as u64).map(|i| (0, i as u32)).collect()),
        layers: Vec::new(),
        fetch_tx,
        refetch: Vec::new(),
        dispatch_replies: Vec::new(),
        // Dispatch-round scratch pool starts empty.
        dispatch_scratch: Default::default(),
        endgame_live: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        endgame_edge: None,
        endgame_cum: Duration::ZERO,
        last_mile_edge: None,
        last_mile_final: None,
        last8_edge: None,
        last8_final: None,
        endgame_deadline: std::collections::HashMap::new(),
        write_adjacent: 0,
        write_isolated: 0,
        blocks_sent: std::collections::HashMap::new(),
        parole_peers: std::collections::HashSet::new(),
        block_arena: None,
        block_inflight: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        pex_candidates: PexCandidates::default(),
        read_pool: None,
        final_flush_tx,
        data_flush_gate,
        // Snapshot barrier face: dirty flag starts false; the cell stays
        // empty (no pipeline counterpart fills it) — the consumer face
        // is not on the fixture path.
        dirty_since_snapshot: false,
        snapshot_sync: Arc::new(std::sync::OnceLock::new()),
    }
}

/// Duplex pair: PeerTask + the test side's raw read/write end (the test
/// plays the layer-serving peer). Reciprocity: the fake peer sends
/// Unchoke immediately and the fixture waits for the mirror to flip
/// (the request dispatch face sends nothing to a choking peer — the
/// dispatch.rs main-loop gate; a serving peer must be unchoked).
async fn peer_pair(root: &CancellationToken) -> (PeerTaskHandle, RemoteWriter, RemoteReader) {
    let (local, mut remote) = tokio::io::duplex(64 * 1024);
    let (handle, _join, _data) =
        taiji_bt::peer::PeerTask::spawn(root, local, taiji_bt::peer::PeerConfig::flat());
    use tokio::io::AsyncWriteExt as _;
    remote
        .write_all(&Message::Unchoke.encode())
        .await
        .unwrap_or_else(|e| panic!("write unchoke: {e}"));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while handle.is_choking_us() {
        assert!(
            std::time::Instant::now() < deadline,
            "the unchoke mirror did not flip within the deadline"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let (r, w) = tokio::io::split(remote);
    (handle, w, r)
}

/// Layer geometry of a 3-piece x 32KiB (bpp = 2) file: content /
/// piece-root layer / file root.
fn layer_fixture() -> (Vec<u8>, Vec<[u8; 32]>, [u8; 32]) {
    const PIECE: u32 = 32768;
    let content: Vec<u8> = (0..3 * PIECE as usize).map(|i| (i % 249) as u8).collect();
    let leaves: Vec<[u8; 32]> = content
        .chunks(merkle::BLOCK_SIZE as usize)
        .map(merkle::block_hash)
        .collect();
    let piece_hashes: Vec<[u8; 32]> = leaves.chunks(2).map(|p| piece_root(p, 2)).collect();
    let root = merkle::file_root_from_piece_roots(&piece_hashes, 2);
    (content, piece_hashes, root)
}

/// Send one wire frame (`Message::encode` directly; no futures
/// dependency).
async fn send_frame(remote_w: &mut RemoteWriter, msg: Message) {
    remote_w
        .write_all(&msg.encode())
        .await
        .unwrap_or_else(|e| panic!("write frame: {e}"));
}

/// Read one peer frame (the only outbound frame before the layer reply
/// should be a hash request).
async fn next_request(remote_r: &mut RemoteReader) -> Message {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(2), remote_r.read_exact(&mut len_buf))
        .await
        .unwrap_or_else(|e| panic!("timeout reading frame prefix: {e}"))
        .unwrap_or_else(|e| panic!("read prefix: {e}"));
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Message::KeepAlive;
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(2), remote_r.read_exact(&mut body))
        .await
        .unwrap_or_else(|e| panic!("timeout reading frame body: {e}"))
        .unwrap_or_else(|e| panic!("read body: {e}"));
    Message::decode_body(&body).unwrap_or_else(|e| panic!("decode: {e:?}"))
}

/// Recovery reply events flow back over the fetch channel -> bookkeeping
/// decision + drive round (the test-side drive shape = the Recovery
/// branch of arms::handle_hash_fetch). Returns the event itself.
async fn pump_event(
    face: &mut FaceState,
    book: &mut RecoveryBook,
    deliver: &mpsc::Sender<RecoveredPieceLayer>,
    fetch_rx: &mut mpsc::Receiver<(usize, usize, HashFetchEvent)>,
) -> HashFetchEvent {
    let (fi, file_idx, evt) = fetch_rx
        .recv()
        .await
        .unwrap_or_else(|| panic!("fetch channel closed"));
    if let HashFetchEvent::Recovery { block, reply } = &evt {
        handle_recovery_reply_and_drive(fi, face, book, deliver, file_idx, *block, reply.clone());
        return evt;
    }
    panic!("unexpected lazy-fetch event: {evt:?}");
}

// ---------------------------------------------------------------------------
// Peer-selection table (coverage-first + v2 hash-exchange capability
// fallback + in-flight / tried-peer exclusion; see the recovery_peer_order
// docs for the libtorrent cross-check sources).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_peer_selection_table() {
    let root = CancellationToken::new();
    let mut face = recovery_face(6, 32768);
    // Three peers: cuid 1 (no advertised row), cuid 2 (covers piece 2 —
    // inside file range [2,6)), cuid 3 (all-zero advertised row).
    for cuid in 1..=3u64 {
        let (handle, _w, _r) = peer_pair(&root).await;
        face.peers.push(handle);
        face.peer_cuids.push(cuid);
    }
    // (Rows are bitmaps — literals are written through the from_bools
    // bridge; semantics unchanged.)
    face.peer_avail.insert(
        2,
        PieceBitmap::from_bools(&[false, false, true, false, false, false]),
    );
    face.peer_avail.insert(3, PieceBitmap::new(6));
    let busy = std::collections::HashSet::new();
    let tried = std::collections::HashSet::new();

    // Row 1: coverage first (cuid 2 ahead); evidence-free / zero-holding
    // peers fall back in connection order.
    assert_eq!(
        recovery_peer_order(&face, 2, 6, &busy, &tried),
        vec![1, 0, 2],
        "coverage first + fallback connection order"
    );
    // Row 2: coverage outside the range doesn't count (file range [0,2)
    // excludes piece 2).
    assert_eq!(
        recovery_peer_order(&face, 0, 2, &busy, &tried),
        vec![0, 1, 2],
        "coverage outside the range = all fallback"
    );
    // Row 3: in-flight peer excluded (<=1 in-flight per peer —
    // bt_peer_connection.cpp cross-check; the covering cuid 2 is busy ->
    // the coverage group is empty, fallback = the other two peers in
    // connection order).
    let busy = [2u64].into_iter().collect();
    assert_eq!(
        recovery_peer_order(&face, 2, 6, &busy, &tried),
        vec![0, 2],
        "busy peers are not selected"
    );
    // Row 4: tried-peer memory exclusion (the tried coverer is skipped).
    let busy = std::collections::HashSet::new();
    let tried = [2u64].into_iter().collect();
    assert_eq!(
        recovery_peer_order(&face, 2, 6, &busy, &tried),
        vec![0, 2],
        "tried peers excluded"
    );
    // Row 5: after busy ∪ tried exclusion only the fallback order
    // remains (cuid 2 in flight, cuid 1 tried -> only cuid 3).
    let busy = [2u64].into_iter().collect();
    let tried = [1u64].into_iter().collect();
    assert_eq!(recovery_peer_order(&face, 2, 6, &busy, &tried), vec![2]);
    // Row 6: all excluded = empty selection (the drive round waits, no
    // wasted requests).
    let tried = [1u64, 3u64].into_iter().collect();
    assert!(recovery_peer_order(&face, 2, 6, &busy, &tried).is_empty());

    // Row 7: a v1 face has no hash-exchange semantics (libtorrent
    // protocol_v2 gate cross-check) -> empty selection.
    let mut v1 = recovery_face(6, 32768);
    v1.kind = FaceKind::V1;
    v1.peer_cuids.push(1);
    v1.peer_avail.insert(1, PieceBitmap::ones(6));
    assert!(recovery_peer_order(&v1, 0, 6, &busy, &tried).is_empty());
    root.cancel();
}

// ---------------------------------------------------------------------------
// Data-plane registration dispatch (boundary: register only when the
// entry is missing; a bad entry / single-piece file stays out of
// recovery).
// ---------------------------------------------------------------------------

#[test]
fn data_plane_registers_recovery_for_missing_layer_only() {
    const PIECE: u32 = 32768;
    let (_, piece_hashes, root) = layer_fixture();
    let layer_bytes: bytes::Bytes = piece_hashes
        .iter()
        .flat_map(|h| h.iter())
        .copied()
        .collect::<Vec<u8>>()
        .into();
    let mk = |length: u64, layer: Option<bytes::Bytes>| MetaFile {
        path: PathBuf::from("f.bin"),
        length,
        padding: false,
        pieces_root: Some(root),
        piece_layer: layer,
        v1_offset: Some(0),
    };
    let files = vec![
        mk(3 * u64::from(PIECE), None), // f0 multi-piece, missing layer -> registers
        mk(3 * u64::from(PIECE), Some(layer_bytes.clone())), // f1 multi-piece, has layer -> lazy-fetch face
        mk(u64::from(PIECE), None), // f2 single piece, missing layer -> not registered
        mk(3 * u64::from(PIECE), Some(layer_bytes.slice(..32))), // f3 wrong size -> not registered
    ];
    let addressing = Addressing::PerFile {
        piece_bases: vec![0, 3, 6, 7],
    };
    let plane = build_v2_data_plane(Some(&files), addressing, PIECE);
    let keys: Vec<usize> = plane.recovery.files.keys().copied().collect();
    assert_eq!(
        keys,
        vec![0],
        "only layer-missing multi-piece files register recovery (the resolution-6 split)"
    );
    let rec = &plane.recovery.files[&0];
    assert_eq!(rec.staging.pieces(), 3);
    assert_eq!(rec.piece_base, 0);
    // Plan = one pass over the piece layer (512 cap, power-of-two
    // decomposition).
    assert_eq!(
        rec.staging.plans(),
        &[
            HashRequestPlan {
                index: 0,
                length: 2
            },
            HashRequestPlan {
                index: 2,
                length: 2
            },
        ]
    );
    // Lazy-fetch face: f0 missing layer -> Pending placeholder (a
    // semantics upgrade: the old Failed would let dispatch through,
    // causing a verify-failure refetch storm against the placeholder
    // expected root; Pending = the lazy-fetch gate's "Pending => continue"
    // dispatch ban); f1 has a layer -> normal Queued.
    assert!(matches!(plane.layers[0].state, LayerFetchState::Pending));
    assert!(matches!(
        plane.layers[1].state,
        LayerFetchState::Queued { .. }
    ));
    // Single-piece missing-layer file: recovery not registered (a single
    // piece with no entry is spec behavior); the lazy-fetch face
    // continues (a leaf-layer lazy-fetch plan for a 32KiB piece's 2
    // leaves).
    assert!(matches!(
        plane.layers[2].state,
        LayerFetchState::Queued { .. }
    ));
}

// ---------------------------------------------------------------------------
// Duplex integration: the mock peer serves the layer -> complete ->
// delivery interface.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplex_recovery_fetch_delivers_complete_layer() {
    const PIECE: u32 = 32768;
    let (_, piece_hashes, root) = layer_fixture();
    let root_token = CancellationToken::new();
    let (handle, mut remote_w, mut remote_r) = peer_pair(&root_token).await;

    let mut face = recovery_face(3, PIECE);
    face.peers.push(handle);
    face.peer_cuids.push(1);
    face.peer_avail.insert(1, PieceBitmap::ones(3));
    let (fetch_tx, mut fetch_rx) = mpsc::channel(16);
    face.fetch_tx = fetch_tx;

    let mut book = RecoveryBook::default();
    book.files.insert(
        0,
        FileRecovery::new(root, 3 * u64::from(PIECE), PIECE, 0)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let (deliver, mut deliver_rx) = mpsc::channel::<RecoveredPieceLayer>(RECOVERY_DELIVER_CAPACITY);

    // Drive round 1: coverage-first peer choice -> block 0 on the wire
    // (base = the piece level = 1).
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(
        book.files[&0].state,
        RecoveryFetchState::Requesting { block: 0, cuid: 1 }
    ));
    let req = next_request(&mut remote_r).await;
    assert_eq!(
        req,
        Message::HashRequest {
            root,
            base: 1,
            index: 0,
            length: 2,
            proof: 0
        },
        "hash request five-tuple: base = the piece layer, index = a length multiple, proof = 0"
    );

    // Reply block 0 (true piece roots) -> event -> bookkeeping advances
    // -> the drive round automatically requests block 1.
    send_frame(
        &mut remote_w,
        Message::Hashes {
            root,
            base: 1,
            index: 0,
            length: 2,
            proof: 0,
            hashes: vec![piece_hashes[0], piece_hashes[1]],
        },
    )
    .await;
    let _ = pump_event(&mut face, &mut book, &deliver, &mut fetch_rx).await;
    let req = next_request(&mut remote_r).await;
    assert_eq!(
        req,
        Message::HashRequest {
            root,
            base: 1,
            index: 2,
            length: 2,
            proof: 0
        }
    );

    // Reply block 1: true last piece root + an out-of-range zero-filled
    // slot (the empty piece root — the server pad semantics).
    send_frame(
        &mut remote_w,
        Message::Hashes {
            root,
            base: 1,
            index: 2,
            length: 2,
            proof: 0,
            hashes: vec![piece_hashes[2], merkle::empty_piece_root(2)],
        },
    )
    .await;
    let _ = pump_event(&mut face, &mut book, &deliver, &mut fetch_rx).await;

    // Complete -> delivery seam (the admission consumer): the whole
    // layer, exactly 3 entries, the zero slot truncated off.
    let rec = tokio::time::timeout(Duration::from_secs(2), deliver_rx.recv())
        .await
        .unwrap_or_else(|e| panic!("delivery timeout: {e}"))
        .unwrap_or_else(|| panic!("deliver channel closed"));
    assert_eq!(rec.root, root);
    assert_eq!(
        rec.layer, piece_hashes,
        "the whole-file layer delivered complete"
    );
    assert!(matches!(
        book.files[&0].state,
        RecoveryFetchState::Delivered
    ));
    // Trust-anchor sanity (math side): recomputing the delivered layer
    // converges to the pieces root inside info.
    let bytes: Vec<u8> = rec.layer.iter().flat_map(|h| h.iter()).copied().collect();
    assert!(
        merkle::validate_piece_layer(&root, &bytes, 3 * u64::from(PIECE), PIECE).is_ok(),
        "the delivered layer must pass the admission criteria"
    );
    root_token.cancel();
}

// ---------------------------------------------------------------------------
// Bounded caps: <=1 in-flight per peer across files, <=1 in-flight per
// file.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_bounded_one_inflight_per_peer_across_files() {
    const PIECE: u32 = 32768;
    let (_, ph0, root0) = layer_fixture();
    // A second missing-layer file (same geometry, independent root).
    let content1: Vec<u8> = (0..3 * PIECE as usize).map(|i| (i % 253) as u8).collect();
    let leaves1: Vec<[u8; 32]> = content1
        .chunks(merkle::BLOCK_SIZE as usize)
        .map(merkle::block_hash)
        .collect();
    let ph1: Vec<[u8; 32]> = leaves1.chunks(2).map(|p| piece_root(p, 2)).collect();
    let root1 = merkle::file_root_from_piece_roots(&ph1, 2);

    let root_token = CancellationToken::new();
    let (handle, mut remote_w, mut remote_r) = peer_pair(&root_token).await;
    let mut face = recovery_face(6, PIECE);
    face.peers.push(handle);
    face.peer_cuids.push(1);
    face.peer_avail.insert(1, PieceBitmap::ones(6));
    let (fetch_tx, mut fetch_rx) = mpsc::channel(16);
    face.fetch_tx = fetch_tx;

    let mut book = RecoveryBook::default();
    book.files.insert(
        0,
        FileRecovery::new(root0, 3 * u64::from(PIECE), PIECE, 0)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    book.files.insert(
        1,
        FileRecovery::new(root1, 3 * u64::from(PIECE), PIECE, 3)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let (deliver, mut deliver_rx) = mpsc::channel::<RecoveredPieceLayer>(RECOVERY_DELIVER_CAPACITY);

    // Drive round: the only peer is occupied by file 0 (BTreeMap order
    // picks file 0 first) — file 1 must wait (the busy exclusion = the
    // bookkeeping guarantee of <=1 in-flight per peer).
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(
        book.files[&0].state,
        RecoveryFetchState::Requesting { block: 0, .. }
    ));
    assert!(
        matches!(book.files[&1].state, RecoveryFetchState::Missing),
        "a busy peer must not get a second file dispatched concurrently"
    );
    let req = next_request(&mut remote_r).await;
    assert!(
        matches!(req, Message::HashRequest { index: 0, .. }),
        "only file 0 goes on the wire"
    );

    // Both blocks of file 0 complete -> the delivery seam receives
    // (consumer present, Received -> Delivered).
    for round in 0..2usize {
        let hashes = if round == 0 {
            vec![ph0[0], ph0[1]]
        } else {
            vec![ph0[2], merkle::empty_piece_root(2)]
        };
        send_frame(
            &mut remote_w,
            Message::Hashes {
                root: root0,
                base: 1,
                index: (round * 2) as u32,
                length: 2,
                proof: 0,
                hashes,
            },
        )
        .await;
        let _ = pump_event(&mut face, &mut book, &deliver, &mut fetch_rx).await;
        if round == 0 {
            // The reply arm's drive round already auto-continued to
            // block 1 (consume the request frame on the wire).
            let req = next_request(&mut remote_r).await;
            assert!(
                matches!(req, Message::HashRequest { root, index: 2, .. } if root == root0),
                "block 1 auto-continues after block 0 settles"
            );
        }
    }
    assert!(
        matches!(book.files[&0].state, RecoveryFetchState::Delivered),
        "a consumer present = delivery complete"
    );
    let rec = deliver_rx.try_recv().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        rec.layer, ph0,
        "file 0's layer delivered complete (zero-slot truncation)"
    );
    // After file 0 settles, the same peer can serve file 1
    // (serialization = <=1 in-flight per peer).
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(
        book.files[&1].state,
        RecoveryFetchState::Requesting { block: 0, .. }
    ));
    let req = next_request(&mut remote_r).await;
    assert!(
        matches!(req, Message::HashRequest { root, .. } if root == root1),
        "file 1 reuses the same peer"
    );
    root_token.cancel();
}

// ---------------------------------------------------------------------------
// reject / timeout / disconnect branch convergence: a unified retry
// count + tried-peer memory + waiting for a fresh peer after exhaustion
// (no terminal failure).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn recovery_reject_retries_then_holds_for_fresh_peer() {
    const PIECE: u32 = 32768;
    let (_, _, root) = layer_fixture();
    let root_token = CancellationToken::new();
    let (handle, mut remote_w, mut remote_r) = peer_pair(&root_token).await;
    let mut face = recovery_face(3, PIECE);
    face.peers.push(handle);
    face.peer_cuids.push(1);
    face.peer_avail.insert(1, PieceBitmap::ones(3));
    let (fetch_tx, mut fetch_rx) = mpsc::channel(16);
    face.fetch_tx = fetch_tx;
    let mut book = RecoveryBook::default();
    book.files.insert(
        0,
        FileRecovery::new(root, 3 * u64::from(PIECE), PIECE, 0)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let (deliver, mut deliver_rx) = mpsc::channel::<RecoveredPieceLayer>(RECOVERY_DELIVER_CAPACITY);

    // Reject rounds: while attempts < MAX the reply arm auto-sends the
    // next request; after the last round is exhausted it stops.
    for round in 0..HASH_FETCH_MAX_ATTEMPTS {
        drive_recovery(&mut face, 0, &mut book, &deliver);
        assert!(
            matches!(book.files[&0].state, RecoveryFetchState::Requesting { .. }),
            "round {round}: should issue the request"
        );
        let _ = next_request(&mut remote_r).await;
        send_frame(
            &mut remote_w,
            Message::HashReject {
                root,
                base: 1,
                index: 0,
                length: 2,
                proof: 0,
            },
        )
        .await;
        let _ = pump_event(&mut face, &mut book, &deliver, &mut fetch_rx).await;
        assert_eq!(
            book.files[&0].attempts,
            round + 1,
            "a reject counts toward consecutive failures"
        );
        if round + 1 < HASH_FETCH_MAX_ATTEMPTS {
            assert!(
                matches!(book.files[&0].state, RecoveryFetchState::Requesting { .. }),
                "round {round}: budget remaining = resend immediately (the reply arm's drive round)"
            );
        } else {
            assert!(
                matches!(book.files[&0].state, RecoveryFetchState::Missing),
                "round {round}: budget exhausted = wait for a new peer"
            );
        }
    }
    // Exhausted (attempts == MAX): no fresh peer -> no more resends (no
    // retry storm); the file stays Missing (the recovering gated state —
    // no terminal failure).
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(book.files[&0].state, RecoveryFetchState::Missing));
    // A fresh peer connects (tried memory passes the new cuid) ->
    // immediate retry.
    let (handle2, mut remote_w2, mut remote_r2) = peer_pair(&root_token).await;
    face.peers.push(handle2);
    face.peer_cuids.push(2);
    face.peer_avail.insert(2, PieceBitmap::ones(3));
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(
        book.files[&0].state,
        RecoveryFetchState::Requesting { cuid: 2, .. }
    ));
    let req = next_request(&mut remote_r2).await;
    assert!(matches!(req, Message::HashRequest { .. }));
    // The fresh peer serves successfully -> attempts reset to zero,
    // tried cleared (peer-rotation memory reset).
    send_frame(
        &mut remote_w2,
        Message::Hashes {
            root,
            base: 1,
            index: 0,
            length: 2,
            proof: 0,
            hashes: vec![[1u8; 32], [2u8; 32]],
        },
    )
    .await;
    let _ = pump_event(&mut face, &mut book, &deliver, &mut fetch_rx).await;
    assert_eq!(
        book.files[&0].attempts, 0,
        "any block success resets the retry counter"
    );
    assert!(book.files[&0].tried.is_empty());
    assert!(
        deliver_rx.try_recv().is_err(),
        "a single block does not deliver (whole-file admission granularity)"
    );
    root_token.cancel();
}

/// Timeout branch: reply-wait timeout -> failure event -> retry
/// convergence. Driven by the real clock (the tokio test-util feature is
/// not enabled — the workspace dep set is frozen, no feature added):
/// this test actually waits one round of [`HASH_FETCH_TIMEOUT`] (10s),
/// the only wall-clock case; the write end held alive = the connection
/// stays up, it just never replies.
#[tokio::test]
async fn recovery_timeout_retries() {
    const PIECE: u32 = 32768;
    let (_, _, root) = layer_fixture();
    let root_token = CancellationToken::new();
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (handle, _join, _data) =
        taiji_bt::peer::PeerTask::spawn(&root_token, local, taiji_bt::peer::PeerConfig::flat());
    let (r, w) = tokio::io::split(remote);
    // The write end held alive (dropping it = EOF disconnect); the read
    // end verifies the request hits the wire.
    let mut remote_r: RemoteReader = r;
    let _no_reply_keep_alive: RemoteWriter = w;

    let mut face = recovery_face(3, PIECE);
    face.peers.push(handle);
    face.peer_cuids.push(1);
    face.peer_avail.insert(1, PieceBitmap::ones(3));
    let (fetch_tx, mut fetch_rx) = mpsc::channel(16);
    face.fetch_tx = fetch_tx;
    let mut book = RecoveryBook::default();
    book.files.insert(
        0,
        FileRecovery::new(root, 3 * u64::from(PIECE), PIECE, 0)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let (deliver, _deliver_rx) = mpsc::channel::<RecoveredPieceLayer>(RECOVERY_DELIVER_CAPACITY);

    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(
        book.files[&0].state,
        RecoveryFetchState::Requesting { .. }
    ));
    let req = next_request(&mut remote_r).await;
    assert!(matches!(req, Message::HashRequest { .. }));
    // Never replying -> watcher timeout (HASH_FETCH_TIMEOUT, this
    // side's policy value) -> failure event -> retry count +1; budget
    // remaining -> the reply arm's drive round resends immediately.
    let evt = pump_event(&mut face, &mut book, &deliver, &mut fetch_rx).await;
    assert!(
        matches!(
            evt,
            HashFetchEvent::Recovery {
                reply: Err(RecoveryFetchFail::Timeout),
                ..
            }
        ),
        "the timeout must be classified explicitly on the way back"
    );
    assert_eq!(book.files[&0].attempts, 1);
    assert!(
        matches!(book.files[&0].state, RecoveryFetchState::Requesting { .. }),
        "budget remaining = resend immediately after the timeout (convergence)"
    );
    root_token.cancel();
}

/// Disconnect branch: the peer task exits -> the pending request's reply
/// end closes -> failure event -> no more dispatch to the dead
/// connection (command channel closed, the send is skipped, state stays
/// Missing).
#[tokio::test]
async fn recovery_disconnect_retries_and_skips_dead_peer() {
    const PIECE: u32 = 32768;
    let (_, _, root) = layer_fixture();
    let root_token = CancellationToken::new();
    let (handle, _remote_w, _remote_r) = peer_pair(&root_token).await;
    let mut face = recovery_face(3, PIECE);
    face.peers.push(handle);
    face.peer_cuids.push(1);
    face.peer_avail.insert(1, PieceBitmap::ones(3));
    let (fetch_tx, mut fetch_rx) = mpsc::channel(16);
    face.fetch_tx = fetch_tx;
    let mut book = RecoveryBook::default();
    book.files.insert(
        0,
        FileRecovery::new(root, 3 * u64::from(PIECE), PIECE, 0)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let (deliver, _deliver_rx) = mpsc::channel::<RecoveredPieceLayer>(RECOVERY_DELIVER_CAPACITY);

    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(
        book.files[&0].state,
        RecoveryFetchState::Requesting { .. }
    ));
    // The peer task exits (token cancelled) -> the pending request's
    // reply end drops with the task.
    root_token.cancel();
    let evt = tokio::time::timeout(
        Duration::from_secs(2),
        pump_event(&mut face, &mut book, &deliver, &mut fetch_rx),
    )
    .await
    .unwrap_or_else(|e| panic!("closed-event timeout: {e}"));
    assert!(
        matches!(
            evt,
            HashFetchEvent::Recovery {
                reply: Err(RecoveryFetchFail::Closed),
                ..
            }
        ),
        "a disconnect must be classified explicitly on the way back"
    );
    assert_eq!(book.files[&0].attempts, 1);
    // No dispatch to a dead connection: the drive round picks it -> the
    // command channel is closed -> the send fails -> Requesting is not
    // set, no retry storm.
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(book.files[&0].state, RecoveryFetchState::Missing));
    root_token.cancel();
}

// ---------------------------------------------------------------------------
// Server-side cross-check: this side's MetaHashSource serving obligation
// for the recovery request shape (base=piece-level whole segments +
// out-of-range zero slots) — the requester's planner and the server are
// two sides of the same spec.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Gated three-face table + hybrid dual-face + unlock propagation
// integration.
//
// Cross-check source (libtorrent RC_2_0): a missing-layer torrent still
// loads and connects (torrent.cpp `valid = false; continue`), but
// `we_have` is only set after hash verification passes — the advertise /
// request / serve faces see only verified pieces (this side's structural
// equivalent of the checking state = a placeholder zero root that can
// never converge); a hybrid's v1 face proceeds without waiting for
// recovery (the cross = None downgrade is locked by the metainfo tests).
// ---------------------------------------------------------------------------

/// Missing-layer gated face: `recovery_face(3, PIECE)` re-equipped with
/// a missing-layer file's data plane — f0 missing (Pending gate +
/// recovery bookkeeping registered), trees/coords/layers are data-plane
/// products, the hash-serving file face in place (piece_layer None = the
/// missing-layer shape).
fn gated_face() -> (FaceState, RecoveryBook, [u8; 32]) {
    const PIECE: u32 = 32768;
    let (_, _, root) = layer_fixture();
    let file_len = 3 * u64::from(PIECE);
    let files = vec![MetaFile {
        path: PathBuf::from("missing.bin"),
        length: file_len,
        padding: false,
        pieces_root: Some(root),
        piece_layer: None,
        v1_offset: Some(0),
    }];
    let addressing = Addressing::per_file(&[file_len], PIECE);
    let plane = build_v2_data_plane(Some(&files), addressing.clone(), PIECE);
    let mut face = recovery_face(3, PIECE);
    face.addressing = addressing;
    face.trees = plane.trees.clone();
    face.layers = plane.layers;
    face.flat_coords = plane.coords.clone();
    face.hash_files = Some(files);
    (face, plane.recovery, root)
}

/// Gated three-face table: while the layer is missing — no download
/// (dispatch sends zero block requests), no seeding (upload serving
/// gated on the verified bitmap + hash serving exits via hash-reject),
/// no advertising (the verified bitmap is all zero -> the bitfield/HAVE
/// carry none of its pieces); after the layer completes (admission ->
/// gate upgrade) all three faces unlock — the existing lazy-fetch-then-
/// block-dispatch path takes over and hash serving answers with the
/// recovered layer.
#[tokio::test]
async fn missing_layer_gate_three_faces_table() {
    const PIECE: u32 = 32768;
    let (content, piece_hashes, root) = layer_fixture();
    let (mut face, mut book, gate_root) = gated_face();
    assert_eq!(gate_root, root);
    let root_token = CancellationToken::new();
    let (handle, _remote_w, mut remote_r) = peer_pair(&root_token).await;
    face.peers.push(handle);
    face.peer_cuids.push(1);
    // Bitfield advertising bookkeeping (row creation + rarest-first
    // counting engaged — the real advertising path).
    note_peer_bitfield(&mut face, 1, &[0xFF; 1]);

    let tmp = std::env::temp_dir().join(format!(
        "taiji-c3-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));
    let entries = vec![taiji_store::layout::PlanEntry {
        path: PathBuf::from("missing.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = taiji_store::layout::Layout::plan_v1_padded(&entries, PIECE)
        .unwrap_or_else(|e| panic!("{e}"));

    // ── Row group A: layer missing (all three faces gated) ──
    // Row A1 download face: dispatch sends zero block requests (done
    // folding + Pending defense in depth).
    dispatch_face_selected_with_stream(&mut face, 0, None, &RarestFirstStrategy, None, None);
    assert!(
        face.blocks_sent.is_empty() && face.dispatch_replies.is_empty(),
        "layer-missing file download-banned: zero block requests on the dispatch face"
    );
    // Row A2 advertising face: verified bitmap all zero -> synthesized
    // bitfield all zero (the registration arm does not send an all-zero
    // bitfield — forensic semantics); HAVE fires only on PieceVerified
    // -> none of its pieces.
    assert!(
        face.bitfield_bytes().iter().all(|&b| b == 0),
        "layer-missing file advertise-banned: zero verification verdicts means zero have semantics"
    );
    // Row A3 seeding-upload serving face (PartialFaceSource): the
    // written bit unset -> read_block Err -> the peer side rejects
    // (bytes not on disk never leave; the gate checks the written bit —
    // a hash-passed piece already advertised but still being written is
    // still refused).
    {
        let partial = PartialFaceSource {
            reader: TorrentReader::new(layout.clone(), tmp.clone()),
            goffs: face.piece_goffs.clone(),
            written: face.written_bits.clone(),
        };
        let mut buf = vec![0u8; 16384];
        assert!(
            partial.read_block(0, 0, &mut buf).is_err(),
            "layer-missing file seed-banned: unverified-piece upload serving refuses"
        );
    }
    // Row A4 seeding-hash serving face: a piece-level request with
    // piece_layer None -> Err (the peer side turns it into a hash reject
    // — the legitimate exit BEP52 allows).
    {
        let src = MetaHashSource::new(
            face.hash_files
                .clone()
                .unwrap_or_else(|| panic!("hash files")),
            TorrentReader::new(layout.clone(), tmp.clone()),
            PIECE,
        );
        assert!(
            src.serve(&root, 1, 0, 2, 0).is_err(),
            "layer-missing file hash-service banned: a piece-layer request answers with the reject exit"
        );
    }

    // ── Layer completion event -> gate upgrade propagation (admission ->
    // activation chain) ──
    book.files
        .get_mut(&0)
        .unwrap_or_else(|| panic!("booked"))
        .state = RecoveryFetchState::Delivered;
    let rec = RecoveredPieceLayer {
        root,
        file_len: 3 * u64::from(PIECE),
        piece_len: PIECE,
        layer: piece_hashes.clone(),
    };
    let mut stats = RecoveryAdmissionStats::default();
    let admitted = consume_recovered_layer_core(
        std::slice::from_mut(&mut face),
        std::slice::from_mut(&mut book),
        &mut stats,
        rec.clone(),
    );
    assert_eq!(admitted, Some((0, 0)));
    assert!(activate_recovered_file(&mut face, None, 0, &rec));
    assert!(matches!(
        face.layers[0].state,
        LayerFetchState::Queued { next: 0 }
    ));

    // ── Row group B: unlocked after completion (the existing path takes
    // over unchanged) ──
    // Row B1 download face: Queued -> the first selected piece of the
    // missing-layer file triggers the existing leaf-layer lazy fetch
    // (hash request base=0 on the wire; block dispatch deferred).
    dispatch_face_selected_with_stream(&mut face, 0, None, &RarestFirstStrategy, None, None);
    let req = next_request(&mut remote_r).await;
    assert!(
        matches!(req, Message::HashRequest { base: 0, .. }),
        "the lazy-fetch plan ready = the existing path takes over (base=0 leaf layer)"
    );
    assert!(
        face.blocks_sent.is_empty(),
        "zero block requests while the lazy fetch is in flight (the Pending gate semantics)"
    );
    // Row B2 download face: lazy fetch done -> block dispatch unlocks.
    face.layers[0].state = LayerFetchState::Done;
    dispatch_face_selected_with_stream(&mut face, 0, None, &RarestFirstStrategy, None, None);
    assert!(
        !face.blocks_sent.is_empty(),
        "block requests dispatch normally after backfill (the download ban lifted)"
    );
    // Row B3 seeding-hash serving face: after the recovered layer is
    // backfilled, answers per the BEP52 serving obligation (true piece
    // roots + out-of-range zero slots).
    {
        let src = MetaHashSource::new(
            face.hash_files
                .clone()
                .unwrap_or_else(|| panic!("hash files")),
            TorrentReader::new(layout, tmp.clone()),
            PIECE,
        );
        let hashes = src
            .serve(&root, 1, 0, 2, 0)
            .unwrap_or_else(|e| panic!("hash service unlocked after backfill: {e}"));
        assert_eq!(hashes[0], piece_hashes[0]);
        assert_eq!(
            hashes[1], piece_hashes[1],
            "the requested range fully in bounds = true piece roots"
        );
    }
    // Row B4 advertising face (structural): before verification passes
    // the written bit stays unset — the bitmap/HAVE advance only with
    // PieceVerified, completion itself creates no false advertising; the
    // upload-serving gate advances only with PieceWritten.
    assert!(!face.written_bits.get(0));
    let _ = std::fs::remove_dir_all(&tmp);
    root_token.cancel();
}

/// Hybrid downgrade dual-face scenario: the same missing-layer file —
/// the v1 face (no trees/layers; the cross = None downgrade is locked by
/// the metainfo tests) downloads unrestricted (the v1 face works
/// independently); the v2 face stays download-gated (a placeholder root
/// cannot be verified) and unlocks after completion. The two faces'
/// piece spaces are k <-> k identical (the BEP52 aligned mapping).
#[tokio::test]
async fn hybrid_missing_file_v1_face_downloads_v2_gated() {
    const PIECE: u32 = 32768;
    let root_token = CancellationToken::new();
    // v1 face: normal dispatch (a missing-layer file sets no v1 gate —
    // expected hashes come from the pieces field inside info,
    // independent of piece layers).
    let mut v1 = recovery_face(3, PIECE);
    v1.kind = FaceKind::V1;
    v1.addressing = Addressing::per_file(&[3 * u64::from(PIECE)], PIECE);
    let (h1, _w1, _r1) = peer_pair(&root_token).await;
    v1.peers.push(h1);
    v1.peer_cuids.push(1);
    note_peer_bitfield(&mut v1, 1, &[0xFF; 1]);
    dispatch_face_selected_with_stream(&mut v1, 0, None, &RarestFirstStrategy, None, None);
    assert!(
        !v1.blocks_sent.is_empty(),
        "the hybrid v1 face downloads independently (resolution 4, unrestricted before backfill)"
    );

    // v2 face: missing-layer Pending -> zero block requests (download
    // gated); completion upgrade -> unlock.
    let (mut v2, mut book, root) = gated_face();
    let (_, piece_hashes, _) = layer_fixture();
    let (h2, _w2, _r2) = peer_pair(&root_token).await;
    v2.peers.push(h2);
    v2.peer_cuids.push(1);
    note_peer_bitfield(&mut v2, 1, &[0xFF; 1]);
    dispatch_face_selected_with_stream(&mut v2, 0, None, &RarestFirstStrategy, None, None);
    assert!(
        v2.blocks_sent.is_empty() && v2.dispatch_replies.is_empty(),
        "the hybrid v2 face is download-gated before backfill"
    );
    book.files
        .get_mut(&0)
        .unwrap_or_else(|| panic!("booked"))
        .state = RecoveryFetchState::Delivered;
    let rec = RecoveredPieceLayer {
        root,
        file_len: 3 * u64::from(PIECE),
        piece_len: PIECE,
        layer: piece_hashes,
    };
    let mut stats = RecoveryAdmissionStats::default();
    let admitted = consume_recovered_layer_core(
        std::slice::from_mut(&mut v2),
        std::slice::from_mut(&mut book),
        &mut stats,
        rec.clone(),
    );
    assert_eq!(admitted, Some((0, 0)));
    assert!(activate_recovered_file(&mut v2, None, 0, &rec));
    // After the upgrade the lazy fetch would be in flight (no wire
    // consumer here — skip the lazy-fetch step, set Done directly to
    // verify where dispatch unlock lands).
    v2.layers[0].state = LayerFetchState::Done;
    dispatch_face_selected_with_stream(&mut v2, 0, None, &RarestFirstStrategy, None, None);
    assert!(
        !v2.blocks_sent.is_empty(),
        "the hybrid v2 face unlocks after backfill (both faces in parallel)"
    );
    root_token.cancel();
}

#[test]
fn meta_hash_source_serves_recovery_shape() {
    const PIECE: u32 = 32768;
    let (content, piece_hashes, root) = layer_fixture();
    let tmp = std::env::temp_dir().join(format!(
        "taiji-recovery-src-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));
    let entries = vec![taiji_store::layout::PlanEntry {
        path: PathBuf::from("f.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout = taiji_store::layout::Layout::plan_v1_padded(&entries, PIECE)
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(tmp.join("f.bin"), &content).unwrap_or_else(|e| panic!("{e}"));
    let reader = TorrentReader::new(layout, tmp.clone());
    let src = MetaHashSource::new(
        vec![MetaFile {
            path: PathBuf::from("f.bin"),
            length: content.len() as u64,
            padding: false,
            pieces_root: Some(root),
            piece_layer: Some(bytes::Bytes::from(
                piece_hashes
                    .iter()
                    .flat_map(|h| h.iter())
                    .copied()
                    .collect::<Vec<u8>>(),
            )),
            v1_offset: Some(0),
        }],
        reader,
        PIECE,
    );
    // The planner's final segment shape (index=2, length=2, 1
    // out-of-range slot) is servable by the server per the BEP52
    // zero-filled tree; the reply slice = true piece root + empty piece
    // root.
    let hashes = src
        .serve(&root, 1, 2, 2, 0)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(hashes.len(), 2);
    assert_eq!(hashes[0], piece_hashes[2]);
    assert_eq!(hashes[1], merkle::empty_piece_root(2));
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// The tried-peer memory cooldown window — refuse inside the window /
// release at expiry / reset on fresh evidence (re-advertising); after
// budget exhaustion a single malicious peer can no longer pin us at
// "waiting for a fresh peer".
// ---------------------------------------------------------------------------

/// Cooldown table (pure function driven; window source in the
/// [`RECOVERY_TRIED_COOLDOWN`] docs — the 90s midpoint of the 60-120s
/// recommended range; libtorrent's nearest face is the 512-piece bucket
/// minimum re-request interval of 3s, `hash_picker.cpp` — same semantics
/// family, but the window takes the recommended range).
#[test]
fn rec2_tried_cooldown_table() {
    let mut book = RecoveryBook::default();
    book.files.insert(
        0,
        FileRecovery::new([1u8; 32], 3 * 32768, 32768, 0)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let t0 = std::time::Instant::now();
    let rec = book.files.get_mut(&0).unwrap_or_else(|| panic!("booked"));
    let attempts_before = rec.attempts;

    // Row 1 refuse-in-window: after a failure is booked the peer stays
    // in active memory during cooldown (excluded from selection).
    rec.note_failure_at(7, t0);
    assert_eq!(
        rec.attempts,
        attempts_before + 1,
        "the failure-count semantics unchanged"
    );
    let tried = active_tried(
        book.files.get_mut(&0).unwrap_or_else(|| panic!("booked")),
        t0 + Duration::from_secs(89),
    );
    assert!(
        tried.contains(&7),
        "in-window: the cooling peer stays in the exclusion set"
    );

    // Row 2 release-at-expiry: >= the cooldown window the entry is
    // dropped (back into candidate order), bookkeeping cleaned in step.
    let rec = book.files.get_mut(&0).unwrap_or_else(|| panic!("booked"));
    let tried = active_tried(rec, t0 + RECOVERY_TRIED_COOLDOWN);
    assert!(
        tried.is_empty(),
        "at expiry: the cooled-out peer returns to candidate order"
    );
    assert!(
        rec.tried.is_empty(),
        "expired entries pruned immediately (bounded-bookkeeping self-heal)"
    );

    // Row 3 fresh-evidence reset: re-advertising (the
    // Have/Bitfield/HaveAll arms) clears the cooldown.
    let rec = book.files.get_mut(&0).unwrap_or_else(|| panic!("booked"));
    rec.note_failure_at(7, t0);
    assert!(!rec.tried.is_empty());
    note_recovery_evidence(&mut book, 7);
    assert!(
        book.files[&0].tried.is_empty(),
        "fresh evidence (the peer reachable again) resets the cooldown"
    );
    // Fresh evidence for a peer that never failed = a no-op; attempts
    // only increment on failure bookkeeping (twice); evidence resets
    // never touch the budget.
    note_recovery_evidence(&mut book, 99);
    note_recovery_evidence(&mut book, 7);
    assert_eq!(
        book.files[&0].attempts,
        attempts_before + 2,
        "the evidence reset clears memory only, never the budget"
    );
    // Multi-file face: evidence clears that peer's entries across all
    // files.
    book.files.insert(
        1,
        FileRecovery::new([2u8; 32], 3 * 32768, 32768, 3)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let now = std::time::Instant::now();
    for idx in [0usize, 1] {
        book.files
            .get_mut(&idx)
            .unwrap_or_else(|| panic!("booked"))
            .note_failure_at(5, now);
    }
    note_recovery_evidence(&mut book, 5);
    assert!(book.files[&0].tried.is_empty() && book.files[&1].tried.is_empty());
}

/// Drive-level behavior: budget exhausted + a single peer serving
/// corrupt content -> no longer pinned forever — pick a fresh peer
/// inside the window, no wasted requests while all peers cool, re-probe
/// connected peers at cooldown expiry, immediate re-probe on fresh
/// evidence (the cadence is clamped by one in-flight per file + the
/// drive round; see note_recovery_evidence).
#[tokio::test]
async fn rec2_cooldown_gates_expires_and_resets_in_drive() {
    const PIECE: u32 = 32768;
    let (_, _, root) = layer_fixture();
    let root_token = CancellationToken::new();
    let mut face = recovery_face(6, PIECE);
    // Two peers: cuid 1 (serves corrupt content — the malicious face),
    // cuid 2 (honest but failed in flight before). The remote halves are
    // collected and kept alive until the end of the test (dropping one =
    // EOF = the peer task exits = the command channel closes).
    let mut remotes = Vec::new();
    for cuid in 1..=2u64 {
        let (handle, w, r) = peer_pair(&root_token).await;
        face.peers.push(handle);
        face.peer_cuids.push(cuid);
        remotes.push((w, r));
    }
    let _keep_alive = remotes;
    let (fetch_tx, _fetch_rx) = mpsc::channel(16);
    face.fetch_tx = fetch_tx;
    let mut book = RecoveryBook::default();
    book.files.insert(
        0,
        FileRecovery::new(root, 3 * u64::from(PIECE), PIECE, 0)
            .unwrap_or_else(|| panic!("multi-piece file must register recovery")),
    );
    let (deliver, _deliver_rx) = mpsc::channel::<RecoveredPieceLayer>(RECOVERY_DELIVER_CAPACITY);
    let now = std::time::Instant::now();

    // Malicious cuid 1 serves corrupt content (tried) + the retry budget
    // exhausted; cuid 2 is booked and untried.
    {
        let rec = book.files.get_mut(&0).unwrap_or_else(|| panic!("booked"));
        rec.attempts = HASH_FETCH_MAX_ATTEMPTS;
        rec.note_failure_at(1, now);
    }
    // Refuse-in-window: cooling cuid 1 is excluded (not re-probed even
    // with the budget exhausted); fresh cuid 2 is chosen.
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(
        matches!(
            book.files[&0].state,
            RecoveryFetchState::Requesting { cuid: 2, .. }
        ),
        "refuse-in-window: even with the budget spent a cooling peer is not re-probed; a fresh peer is chosen"
    );
    // cuid 2 also fails into cooldown -> all cooling + budget spent ->
    // no wasted requests (wait for cooldown / a fresh peer).
    book.files
        .get_mut(&0)
        .unwrap_or_else(|| panic!("booked"))
        .note_failure_at(2, now);
    assert!(matches!(book.files[&0].state, RecoveryFetchState::Missing));
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(
        matches!(book.files[&0].state, RecoveryFetchState::Missing),
        "all cooling + budget spent: the drive round idles (no retry storm)"
    );
    // Release-at-expiry: cuid 1's cooldown is backfilled as expired ->
    // connected peers are re-probed (the self-heal for "a malicious peer
    // that keeps the connection pins us indefinitely").
    book.files
        .get_mut(&0)
        .unwrap_or_else(|| panic!("booked"))
        .tried
        .insert(1, now - RECOVERY_TRIED_COOLDOWN);
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(
        matches!(
            book.files[&0].state,
            RecoveryFetchState::Requesting { cuid: 1, .. }
        ),
        "release-at-expiry: the cooled-out peer returns to candidate order (connection order first)"
    );
    // Fresh-evidence reset: cuid 1 fails again into cooldown (cuid 2
    // still cooling) -> a Have evidence arrives -> immediately
    // re-probeable, without waiting out the window.
    book.files
        .get_mut(&0)
        .unwrap_or_else(|| panic!("booked"))
        .note_failure_at(1, now);
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(matches!(book.files[&0].state, RecoveryFetchState::Missing));
    note_recovery_evidence(&mut book, 1);
    drive_recovery(&mut face, 0, &mut book, &deliver);
    assert!(
        matches!(
            book.files[&0].state,
            RecoveryFetchState::Requesting { cuid: 1, .. }
        ),
        "fresh-evidence reset: a re-advertising peer becomes re-probeable immediately"
    );
    root_token.cancel();
}

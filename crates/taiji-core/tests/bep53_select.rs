//! Acceptance: BEP 53 magnet `so=` select-file end to end + the default
//! face.
//!
//! Multi-file fixture (synthesized in this file from content hashes — not
//! a real client sample): `part0.bin` = piece 0, `part1.bin` = piece 1
//! (piece-aligned, zero pad).
//!
//! Topology: S = a mini seeder serving all pieces and **recording the
//! requested piece indices**; B = a DownloadEngine that, once active,
//! selects only file 0 via `set_file_selection(&[0])`.
//!
//! End-to-end assertions (selecting 1 of 2 files lands only the selected
//! one):
//! 1. S receives requests only for piece 0 (zero network traffic for
//! unselected pieces — the BEP 53 selection face);
//! 2. `part0.bin` on disk matches the source;
//! 3. `part1.bin` stays at preallocated zero bytes (the engine's trunc
//! allocation semantics — unselected piece content never lands; aria2
//! instead does not allocate; the difference is deliberate and noted);
//! 4. **the completion criterion is the selected piece count**:
//! `EngineEnd::Completed` with only 1/2 pieces done (the previous
//! criterion is all pieces; selection narrows it to the masked piece
//! count).
//!
//! Added v2-only face: `bep53_select_file_v2_only_downloads_only_
//! selection` — multiple files (file lengths with non-piece-multiple
//! tails), only the selected file downloads, criteria of the same shape;
//! the seeder additionally answers BEP 52 hash requests (id 21 -> 22).
//!
//! Default-face assertion: `SeedPolicy::default().super_seeding == false`
//! (BEP 16 defaults off — defaulting it on is explicitly forbidden).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, EngineEnd, FaceConfig, FaceKind};
use taiji_core::metainfo::MetaFile;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use taiji_store::merkle;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const PIECE_LEN: usize = 16384;
const PIECES: usize = 2;
const INFO_HASH: [u8; 20] = [9u8; 20];

/// 2 files x 1 piece-aligned content (synthesized fixture; deterministic
/// pseudo-random to avoid all-zero pieces).
fn file_content(seed: u8) -> Vec<u8> {
    (0..PIECE_LEN)
        .map(|i| (i as u8).wrapping_add(seed))
        .collect()
}

async fn read_msg<S>(sock: &mut S) -> Option<(u8, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match tokio::time::timeout(Duration::from_millis(1000), sock.read_exact(&mut len_buf)).await {
        Err(_) | Ok(Err(_)) => return None,
        Ok(Ok(_)) => {}
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Some((0, Vec::new()));
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(Duration::from_millis(1000), sock.read_exact(&mut body))
        .await
        .ok()?
        .ok()?;
    Some((body[0], body[1..].to_vec()))
}

/// Mini seeder: serves all pieces; records the requested piece indices
/// (shared set).
async fn spawn_seeder(
    content: Vec<u8>,
    requested: Arc<std::sync::Mutex<BTreeSet<u32>>>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[27] = 0x04;
        resp[28..48].copy_from_slice(&hs[28..48]);
        resp[48..68].copy_from_slice(b"SELECTORSEEDERSEEDX0");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Reciprocity: unchoke (dispatch sends zero requests to a peer that
        // chokes us — direct translation of aria2 fillPiece; the serving
        // peer must allow requests, same precedent as seeder2 in this
        // file).
        sock.write_all(&[0, 0, 0, 1, 1])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        loop {
            let Some((id, body)) = read_msg(&mut sock).await else {
                continue;
            };
            if id == 6 && body.len() == 12 {
                let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let begin = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                let length = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
                requested
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(index);
                if (index as usize) < PIECES {
                    let off = index as usize * PIECE_LEN + begin as usize;
                    let block = &content[off..off + length as usize];
                    let mut frame = Vec::with_capacity(13 + block.len());
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    frame.push(7u8);
                    frame.extend_from_slice(&index.to_be_bytes());
                    frame.extend_from_slice(&begin.to_be_bytes());
                    frame.extend_from_slice(block);
                    sock.write_all(&frame)
                        .await
                        .unwrap_or_else(|e| panic!("{e}"));
                }
            }
        }
    });
    addr
}

/// Fake tracker: a single announce replies with the seeder.
async fn fake_tracker(seeder: std::net::SocketAddr) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = sock
                .read(&mut chunk)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            if n == 0 {
                break;
            }
            req.extend_from_slice(&chunk[..n]);
        }
        let mut peers = Vec::new();
        let std::net::IpAddr::V4(v4) = seeder.ip() else {
            panic!("expects IPv4");
        };
        peers.extend_from_slice(&v4.octets());
        peers.extend_from_slice(&seeder.port().to_be_bytes());
        let mut raw = Vec::new();
        raw.extend_from_slice(b"d8:intervali60e5:peers");
        raw.extend_from_slice(peers.len().to_string().as_bytes());
        raw.push(b':');
        raw.extend_from_slice(&peers);
        raw.push(b'e');
        let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
        sock.write_all(head.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        sock.write_all(&raw).await.unwrap_or_else(|e| panic!("{e}"));
    });
    addr
}

#[tokio::test]
async fn bep53_select_file_downloads_only_selection() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .try_init();

    // ---- Synthesized multi-file fixture (piece-aligned, zero pad) ----
    let f0 = file_content(0x30);
    let f1 = file_content(0xA0);
    let content = [f0.clone(), f1.clone()].concat();
    let entries = vec![
        PlanEntry {
            path: std::path::PathBuf::from("part0.bin"),
            length: f0.len() as u64,
            padding: false,
        },
        PlanEntry {
            path: std::path::PathBuf::from("part1.bin"),
            length: f1.len() as u64,
            padding: false,
        },
    ];
    let layout =
        Layout::plan_v1_padded(&entries, PIECE_LEN as u32).unwrap_or_else(|e| panic!("{e}"));
    let roots: Vec<ExpectedPieceHash> = content
        .chunks(PIECE_LEN)
        .map(|c| ExpectedPieceHash::V1(Sha1::digest(c).into()))
        .collect();

    let requested: Arc<std::sync::Mutex<BTreeSet<u32>>> =
        Arc::new(std::sync::Mutex::new(BTreeSet::new()));
    let seeder_addr = spawn_seeder(content.clone(), Arc::clone(&requested)).await;
    let tracker_addr = fake_tracker(seeder_addr).await;

    let tmp = std::env::temp_dir().join(format!(
        "taiji-bep53-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: format!("http://{tracker_addr}/announce"),
        listen_port: 0,
        piece_len: PIECE_LEN as u32,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        // Default throughput tier (no behavior change).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![FaceConfig {
            kind: FaceKind::V1,
            info_hash: INFO_HASH,
            reserved: Reserved::aria2_default(),
            addressing: Addressing::Flat,
            piece_goffs: (0..PIECES as u64).map(|k| k * PIECE_LEN as u64).collect(),
            piece_bytes: vec![PIECE_LEN as u64; PIECES],
            expected: roots.clone(),
            plan_file_lengths: vec![f0.len() as u64, f1.len() as u64],
            progress_file_lens: vec![f0.len() as u64, f1.len() as u64],
            cross: Vec::new(),
            hash_files: None,
        }],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    // Controlled spawn + the BEP 53 selection face (only file 0).
    let (engine, join) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig::default(),
        &root,
        taiji_bt::utp::PeerConnectionType::default(),
    );
    engine
        .set_file_selection(Arc::from(&[0u32][..]))
        .await
        .unwrap_or_else(|e| panic!("set_file_selection: {e}"));

    // Out-of-range index = explicit failure (an invalid so= must never be
    // silently ignored).
    let (engine2, join2) = DownloadEngine::spawn_controlled(
        {
            let mut c = EngineConfig {
                preset_progress: None, // default None, zero behavior delta
                tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
                peer_id: *b"-TJ0001-ENGINEENGIN1",
                // Verification-only engine: unreachable tracker (never
                // connects to the seeder, keeping the request record clean
                // — the shared seeder belongs to the engine under test).
                announce: "http://127.0.0.1:1/announce".into(),
                listen_port: 0,
                piece_len: PIECE_LEN as u32,
                layout: Layout::plan_v1_padded(&entries, PIECE_LEN as u32)
                    .unwrap_or_else(|e| panic!("{e}")),
                dest: tmp.clone(),
                seed_after_complete: false,
                seed: taiji_core::seed::SeedPolicy::default(),
                writer_factory: None,
                // Default throughput tier (no behavior change).
                disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
                faces: vec![],
                crypto: taiji_bt::mse::CryptoPolicy::optional(),
                dht: taiji_core::engine::DhtWireConfig::default(),
                private: false,
                peer_exchange: false,
                metadata_serve: None,
                limiter: None,
                hook: None,
                nat: None,
                stats: None,
                webseeds: Vec::new(),
            };
            c.faces.push(FaceConfig {
                kind: FaceKind::V1,
                info_hash: INFO_HASH,
                reserved: Reserved::aria2_default(),
                addressing: Addressing::Flat,
                piece_goffs: (0..PIECES as u64).map(|k| k * PIECE_LEN as u64).collect(),
                piece_bytes: vec![PIECE_LEN as u64; PIECES],
                expected: roots.clone(),
                plan_file_lengths: vec![f0.len() as u64, f1.len() as u64],
                progress_file_lens: vec![f0.len() as u64, f1.len() as u64],
                cross: Vec::new(),
                hash_files: None,
            });
            c
        },
        taiji_core::engine::TrackerWireConfig::default(),
        &root,
        taiji_bt::utp::PeerConnectionType::default(),
    );
    assert!(
        engine2
            .set_file_selection(Arc::from(&[5u32][..]))
            .await
            .is_err(),
        "an out-of-bounds file index must be explicitly rejected"
    );
    join2.abort();

    // The completion criterion = the selected piece count (1/2 pieces
    // completes).
    let end = tokio::time::timeout(Duration::from_secs(45), join)
        .await
        .unwrap_or_else(|e| panic!("engine timed out: {e}"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // Only the selection downloads: the seeder saw requests for piece 0
    // only.
    let seen = requested.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        seen,
        BTreeSet::from([0u32]),
        "unselected pieces produce no requests"
    );

    // The selected file's content is correct; the unselected file stays at
    // preallocated zero bytes (trunc allocation semantics).
    let got0 = std::fs::read(tmp.join("part0.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got0, f0, "the selected file must match the source");
    let got1 = std::fs::read(tmp.join("part1.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got1.iter().all(|&b| b == 0),
        "no data bytes may be written into an unselected file"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Default face: BEP 16 super-seeding defaults **off** (defaulting it on
/// is explicitly forbidden; the SPEC section 11 frozen defaults face +
/// config_json serde default false/None).
#[test]
fn super_seeding_defaults_off() {
    let p = taiji_core::seed::SeedPolicy::default();
    assert!(!p.super_seeding, "super-seeding must default to off");
}

// ---- v2-only multi-file select-file end to end (mask cursor projection)
// ----

/// A single file tree of the v2-only fixture (synthesized in-process from
/// content hashes — not a real client sample; piece_len = 16 KiB = block
/// length => bpp = 1, one block per piece (short last piece), the leaf
/// layer = per-piece block hashes, BEP 52 tree rules).
struct V2FileTree {
    content: Vec<u8>,
    /// File root (pieces root; BEP 52 file tree root).
    root: [u8; 32],
    /// Leaf layer = per-piece block hashes (bpp=1 domain, index = in-piece
    /// order).
    leafs: Vec<[u8; 32]>,
}

impl V2FileTree {
    fn new(seed: u8, len: usize) -> V2FileTree {
        let content: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
        let leafs: Vec<[u8; 32]> = content.chunks(PIECE_LEN).map(merkle::block_hash).collect();
        let piece_roots: Vec<[u8; 32]> = leafs
            .iter()
            .map(|h| merkle::piece_root_from_block_hashes(&[*h], 1))
            .collect();
        let root = merkle::file_root_from_piece_roots(&piece_roots, 1);
        V2FileTree {
            content,
            root,
            leafs,
        }
    }

    fn pieces(&self) -> usize {
        self.content.len().div_ceil(PIECE_LEN)
    }
}

/// v2-only mini seeder: serves all pieces + answers hash requests (BEP 52
/// id 21 -> id 22, the 5-tuple echoed verbatim, payload = the requested
/// leaf-layer block hashes); records the requested **flat piece indices**
/// (the wire index under the PerFile base table).
async fn spawn_v2_seeder(
    files: Vec<V2FileTree>,
    requested: Arc<std::sync::Mutex<BTreeSet<u32>>>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap_or_else(|e| panic!("{e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[27] = 0x04;
        resp[28..48].copy_from_slice(&hs[28..48]);
        resp[48..68].copy_from_slice(b"V2SELECTSEEDERSEED00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // bitfield (all pieces advertised) + unchoke.
        let total_pieces: usize = files.iter().map(V2FileTree::pieces).sum();
        let mut bf = vec![0u8; total_pieces.div_ceil(8)];
        for i in 0..total_pieces {
            bf[i / 8] |= 0x80 >> (i % 8);
        }
        let mut frame = Vec::with_capacity(5 + bf.len());
        frame.extend_from_slice(((1 + bf.len()) as u32).to_be_bytes().as_slice());
        frame.push(5u8);
        frame.extend_from_slice(&bf);
        sock.write_all(&frame)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        sock.write_all(&[0, 0, 0, 1, 1])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // Flat piece -> (file, in-piece index) cursor (expanded from the
        // same source as the face plan).
        let mut flat: Vec<(usize, usize)> = Vec::new();
        for (fi, f) in files.iter().enumerate() {
            for p in 0..f.pieces() {
                flat.push((fi, p));
            }
        }
        loop {
            let Some((id, body)) = read_msg(&mut sock).await else {
                continue;
            };
            match id {
                // request: serve source data via the flat piece cursor.
                6 if body.len() == 12 => {
                    let index = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let begin = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                    let length = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
                    requested
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(index);
                    let Some((fi, pif)) = flat.get(index as usize).copied() else {
                        continue;
                    };
                    let off = pif * PIECE_LEN + begin as usize;
                    let block = &files[fi].content[off..off + length as usize];
                    let mut out = Vec::with_capacity(13 + block.len());
                    out.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
                    out.push(7u8);
                    out.extend_from_slice(&index.to_be_bytes());
                    out.extend_from_slice(&begin.to_be_bytes());
                    out.extend_from_slice(block);
                    sock.write_all(&out).await.unwrap_or_else(|e| panic!("{e}"));
                }
                // hash request (BEP 52 id 21; 48B payload = 32 root +
                // 4x4 five-tuple, the id byte already stripped by
                // read_msg): echo the five-tuple + the leaf-layer segment.
                21 if body.len() == 48 => {
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&body[0..32]);
                    let base = u32::from_be_bytes([body[32], body[33], body[34], body[35]]);
                    let index = u32::from_be_bytes([body[36], body[37], body[38], body[39]]);
                    let length = u32::from_be_bytes([body[40], body[41], body[42], body[43]]);
                    let proof = u32::from_be_bytes([body[44], body[45], body[46], body[47]]);
                    let Some(file) = files.iter().find(|f| f.root == root) else {
                        continue;
                    };
                    let hashes: Vec<[u8; 32]> = (0..length)
                        .map(|i| {
                            file.leafs
                                .get(index as usize + i as usize)
                                .copied()
                                .unwrap_or([0u8; 32])
                        })
                        .collect();
                    let mut out = Vec::with_capacity(53 + 32 * hashes.len());
                    out.extend_from_slice((49 + 32 * hashes.len() as u32).to_be_bytes().as_slice());
                    out.push(22u8);
                    out.extend_from_slice(&root);
                    out.extend_from_slice(&base.to_be_bytes());
                    out.extend_from_slice(&index.to_be_bytes());
                    out.extend_from_slice(&length.to_be_bytes());
                    out.extend_from_slice(&proof.to_be_bytes());
                    for h in &hashes {
                        out.extend_from_slice(h);
                    }
                    sock.write_all(&out).await.unwrap_or_else(|e| panic!("{e}"));
                }
                _ => {}
            }
        }
    });
    addr
}

/// Acceptance: v2-only multi-file (file lengths with non-piece-multiple
/// tails — f0 = f1 = 20_000B with a 3_616B short last piece, f2 = 10_000B
/// single piece) selecting only the middle file. End-to-end criteria of
/// the same shape as the v1 face (cross-check
/// `bep53_select_file_downloads_only_selection`):
/// 1. S receives requests only for the **selected file's segments** (flat
/// pieces 2, 3) — before the fix a mask flattened on the byte grid
/// wrongly picked f0's piece 1 and missed f1's piece 3 (the observed
/// misalignment shape);
/// 2. the selected file's content matches the source; unselected files
/// stay at preallocated zero bytes;
/// 3. the completion criterion = the selected piece count (2/5 pieces
/// completes).
#[tokio::test]
async fn bep53_select_file_v2_only_downloads_only_selection() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .try_init();

    // ---- v2-only multi-file fixture (unaligned file boundaries + short
    // last piece) ----
    let trees: Vec<V2FileTree> = vec![
        V2FileTree::new(0x11, 20_000),
        V2FileTree::new(0x22, 20_000),
        V2FileTree::new(0x33, 10_000),
    ];
    let lens: Vec<u64> = trees.iter().map(|f| f.content.len() as u64).collect();
    let names = ["part0.bin", "part1.bin", "part2.bin"];
    let entries: Vec<PlanEntry> = names
        .iter()
        .zip(&lens)
        .map(|(name, &len)| PlanEntry {
            path: std::path::PathBuf::from(name),
            length: len,
            padding: false,
        })
        .collect();
    let layout =
        Layout::plan_v2_compact(&entries, PIECE_LEN as u32).unwrap_or_else(|e| panic!("{e}"));

    // Face plan (expanded from the same source as v2_face): flat-order
    // expected hashes / goffs / piece byte counts.
    let mut expected: Vec<ExpectedPieceHash> = Vec::new();
    let mut piece_goffs: Vec<u64> = Vec::new();
    let mut piece_bytes: Vec<u64> = Vec::new();
    let mut file_offset = 0u64;
    let mut meta_files: Vec<MetaFile> = Vec::new();
    for (fi, f) in trees.iter().enumerate() {
        let len = f.content.len() as u64;
        for (p, h) in f.leafs.iter().enumerate() {
            expected.push(ExpectedPieceHash::V2(*h));
            piece_goffs.push(file_offset + p as u64 * PIECE_LEN as u64);
            piece_bytes.push((len - p as u64 * PIECE_LEN as u64).min(PIECE_LEN as u64));
        }
        let multi = f.leafs.len() > 1;
        meta_files.push(MetaFile {
            path: std::path::PathBuf::from(names[fi]),
            length: len,
            padding: false,
            pieces_root: Some(f.root),
            piece_layer: multi.then(|| Bytes::from(f.leafs.concat())),
            v1_offset: None,
        });
        file_offset += len;
    }
    let total_pieces = expected.len();

    let requested: Arc<std::sync::Mutex<BTreeSet<u32>>> =
        Arc::new(std::sync::Mutex::new(BTreeSet::new()));
    let seeder_addr = spawn_v2_seeder(
        trees
            .iter()
            .map(|f| V2FileTree {
                content: f.content.clone(),
                root: f.root,
                leafs: f.leafs.clone(),
            })
            .collect(),
        Arc::clone(&requested),
    )
    .await;
    let tracker_addr = fake_tracker(seeder_addr).await;

    let tmp = std::env::temp_dir().join(format!(
        "taiji-bep53-v2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = EngineConfig {
        preset_progress: None, // default None, zero behavior delta
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // default announce client options (aria2-equal values)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
        announce: format!("http://{tracker_addr}/announce"),
        listen_port: 0,
        piece_len: PIECE_LEN as u32,
        layout,
        dest: tmp.clone(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
        faces: vec![FaceConfig {
            kind: FaceKind::V2,
            info_hash: [7u8; 20],
            reserved: Reserved::aria2_default().with_v2(),
            addressing: Addressing::per_file(&lens, PIECE_LEN as u32),
            piece_goffs,
            piece_bytes,
            expected,
            plan_file_lengths: lens.clone(),
            progress_file_lens: lens,
            cross: Vec::new(),
            hash_files: Some(meta_files),
        }],
        crypto: taiji_bt::mse::CryptoPolicy::optional(),
        dht: taiji_core::engine::DhtWireConfig::default(),
        private: false,
        peer_exchange: false,
        metadata_serve: None,
        limiter: None,
        hook: None,
        nat: None,
        stats: None,
        webseeds: Vec::new(),
    };
    // Controlled spawn + the BEP 53 selection face (v2-only, only the
    // middle file part1).
    let (engine, join) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig::default(),
        &root,
        taiji_bt::utp::PeerConnectionType::default(),
    );
    engine
        .set_file_selection(Arc::from(&[1u32][..]))
        .await
        .unwrap_or_else(|e| panic!("set_file_selection: {e}"));

    // The completion criterion = the selected piece count (2/5 pieces
    // completes).
    let end = tokio::time::timeout(Duration::from_secs(45), join)
        .await
        .unwrap_or_else(|e| panic!("engine timed out: {e}"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // Only the selection downloads: the seeder saw requests for the
    // selected file's segments (flat pieces 2, 3) only.
    let seen = requested.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        seen,
        BTreeSet::from([2u32, 3u32]),
        "unselected pieces produce no requests (the v2-only mask's per-bit semantics)"
    );
    assert_eq!(total_pieces, 5, "the fixture face's piece count");

    // The selected file's content is correct; the unselected file stays at
    // preallocated zero bytes (trunc allocation semantics).
    let got1 = std::fs::read(tmp.join("part1.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got1, trees[1].content,
        "the selected file must match the source"
    );
    let got0 = std::fs::read(tmp.join("part0.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got0.iter().all(|&b| b == 0),
        "no data bytes may be written into an unselected file"
    );
    let got2 = std::fs::read(tmp.join("part2.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got2.iter().all(|&b| b == 0),
        "no data bytes may be written into an unselected file"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

//! Acceptance: v2-only download loop plus hybrid dual-swarm parallelism
//! (both infohashes download the same bytes at the same time).
//!
//! Per case: build a metainfo locally (BEP 52 structure; the piece-layers
//! load check must pass) -> fake tracker (records info_hash for the dual
//! identity assertion) -> mini-seeder (routes on the handshake info_hash:
//! v1 = stream piece space, v2 = file-aligned piece space, both serving
//! the same on-disk bytes) -> engine downloads -> byte-for-byte file
//! comparison.
//!
//! BEP 52 upgrade-path source: dual swarm = "join both swarms by
//! calculating the new and old infohashes"; handshake = reserved[7] &
//! 0x10 (the seeder asserts our outbound bit); v2 identity = truncated
//! 20 bytes.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::bencode::{self, Value};
use taiji_bt::filetree::SwarmKind;
use taiji_core::engine::{DownloadEngine, EngineEnd};
use taiji_core::metainfo::Metainfo;
use taiji_store::merkle;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const L: u64 = 16384;

fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
}

/// Dict with dynamic keys (hex roots): bencode dict keys must be sorted.
fn dict_dyn(mut pairs: Vec<(Vec<u8>, Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Dict(pairs)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}

/// v2-only metainfo (single file; bpp = 1, so the piece layer = leaf
/// layer).
fn build_v2_only_torrent(content: &[u8], announce: &str) -> Vec<u8> {
    let leaves: Vec<[u8; 32]> = content.chunks(L as usize).map(merkle::block_hash).collect();
    let root = merkle::file_root(&leaves, L as u32).unwrap_or_else(|e| panic!("{e}"));
    let layer: Vec<u8> = leaves.iter().flat_map(|h| h.iter()).copied().collect();
    let file_entry = dict(vec![(
        b"",
        dict(vec![
            (b"length", Value::Int(content.len() as i64)),
            (b"pieces root", Value::Bytes(root.to_vec())),
        ]),
    )]);
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![(b"v2.bin".to_vec(), file_entry)]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(L as i64)),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(announce.as_bytes().to_vec())),
        (b"info", info),
        (
            b"piece layers",
            dict_dyn(vec![(root.to_vec(), Value::Bytes(layer))]),
        ),
    ]);
    bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"))
}

/// Hybrid metainfo (a.bin + .pad + b.bin; dual representation with v1
/// pieces + v2 file tree). Returns (torrent bytes, v1 stream bytes).
fn build_hybrid_torrent(content_a: &[u8], content_b: &[u8], announce: &str) -> (Vec<u8>, Vec<u8>) {
    let pad = (L - (content_a.len() as u64 % L)) % L;
    let mut stream = Vec::new();
    stream.extend_from_slice(content_a);
    stream.extend(std::iter::repeat_n(0u8, pad as usize));
    stream.extend_from_slice(content_b);
    // v1 pieces: whole-piece SHA-1 over the stream (pad included; per
    // BEP 47 the pad is all zeros).
    let v1_pieces: Vec<u8> = stream.chunks(L as usize).flat_map(Sha1::digest).collect();
    // v2: per-file piece hashes (bpp = 1, i.e. leaf hashes) -> file root.
    let piece_hashes =
        |c: &[u8]| -> Vec<[u8; 32]> { c.chunks(L as usize).map(merkle::block_hash).collect() };
    let ha = piece_hashes(content_a);
    let hb = piece_hashes(content_b);
    let bpp = (L / u64::from(merkle::BLOCK_SIZE)) as usize;
    let root_a = merkle::file_root_from_piece_roots(&ha, bpp);
    let root_b = merkle::file_root_from_piece_roots(&hb, bpp);
    let layer_bytes =
        |h: &[[u8; 32]]| -> Vec<u8> { h.iter().flat_map(|x| x.iter()).copied().collect() };
    let leaf = |name: &[u8], len: i64, root: &[u8; 32]| -> (Vec<u8>, Value) {
        (
            name.to_vec(),
            dict(vec![(
                b"",
                dict(vec![
                    (b"length", Value::Int(len)),
                    (b"pieces root", Value::Bytes(root.to_vec())),
                ]),
            )]),
        )
    };
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![
                leaf(b"a.bin", content_a.len() as i64, &root_a),
                leaf(b"b.bin", content_b.len() as i64, &root_b),
            ]),
        ),
        (
            b"files",
            Value::List(vec![
                dict(vec![
                    (b"length", Value::Int(content_a.len() as i64)),
                    (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                ]),
                dict(vec![
                    (b"attr", Value::Bytes(b"p".to_vec())),
                    (b"length", Value::Int(pad as i64)),
                    (
                        b"path",
                        Value::List(vec![
                            Value::Bytes(b".pad".to_vec()),
                            Value::Bytes(pad.to_string().into_bytes()),
                        ]),
                    ),
                ]),
                dict(vec![
                    (b"length", Value::Int(content_b.len() as i64)),
                    (b"path", Value::List(vec![Value::Bytes(b"b.bin".to_vec())])),
                ]),
            ]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(L as i64)),
        (b"pieces", Value::Bytes(v1_pieces)),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(announce.as_bytes().to_vec())),
        (b"info", info),
        (
            b"piece layers",
            dict_dyn(vec![
                (root_a.to_vec(), Value::Bytes(layer_bytes(&ha))),
                (root_b.to_vec(), Value::Bytes(layer_bytes(&hb))),
            ]),
        ),
    ]);
    let torrent = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    (torrent, stream)
}

/// Fake tracker: records the info_hash of every request verbatim
/// (percent-encoded; the test side compares in percent-encoded form) and
/// answers with the seeder address.
async fn fake_tracker(
    seeder: SocketAddr,
    expected_requests: usize,
    seen: Arc<Mutex<HashSet<String>>>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
        for _ in 0..expected_requests {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut req = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                if sock.read(&mut chunk).await.unwrap_or(0) == 0 {
                    break;
                }
                req.extend_from_slice(&chunk);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&req).into_owned();
            if let Some(i) = text.find("info_hash=") {
                let rest = &text[i + "info_hash=".len()..];
                let end = rest.find('&').unwrap_or(rest.len());
                let _ = seen
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(rest[..end].to_string());
            }
            let std::net::IpAddr::V4(v4) = seeder.ip() else {
                panic!("test expects IPv4");
            };
            let mut peers = Vec::new();
            peers.extend_from_slice(&v4.octets());
            peers.extend_from_slice(&seeder.port().to_be_bytes());
            let mut raw = Vec::new();
            raw.extend_from_slice(b"d8:intervali60e5:peers");
            raw.extend_from_slice(peers.len().to_string().as_bytes());
            raw.push(b':');
            raw.extend_from_slice(&peers);
            raw.push(b'e');
            let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", raw.len());
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&raw).await;
            let _ = sock.shutdown().await;
        }
    });
    addr
}

/// Dual-protocol mini-seeder; routes serving on the handshake info_hash.
///
/// - v1 connections: stream space (index*L + begin; pad bytes are zeros
/// within the stream);
/// - v2 connections: file-aligned space (v2_wire_goffs[index] + begin);
/// - hash request (21) (the supply side of the requester's lazy fetch):
/// computes the leaf layer on the fly per `hash_files`
/// (root, stream offset, length) and answers hashes (22); slots past
/// EOF get zero hashes (the BEP 52 tree zero-fill rule; the requester
/// trims those slots).
///
/// Both serve the same `stream` bytes (the hybrid's dual representation
/// of one set of on-disk data). Asserts that our outbound handshake
/// carries the v2 capability bit (reserved[7] & 0x10).
async fn dual_seeder(
    listener: tokio::net::TcpListener,
    stream: Arc<Vec<u8>>,
    v2_wire_goffs: Arc<Vec<u64>>,
    v1_hash: [u8; 20],
    v2_hash20: [u8; 20],
    expect_handshakes: usize,
    hash_files: Arc<Vec<([u8; 32], u64, u64)>>,
) {
    for _ in 0..expect_handshakes {
        let (mut sock, _) = listener
            .accept()
            .await
            .unwrap_or_else(|e| panic!("accept: {e}"));
        let mut hs = [0u8; 68];
        sock.read_exact(&mut hs)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            hs[20..28],
            [0u8, 0, 0, 0, 0, 0x10, 0, 0x14],
            "outbound reserved = ext(0x10@5) + fast(0x04@7) + v2(0x10@7), BEP52"
        );
        let ih: [u8; 20] = hs[28..48].try_into().unwrap_or_else(|_| panic!("slice"));
        // Route: the handshake identity picks the piece coordinate space
        // (v1 stream / v2 file-aligned).
        let is_v2 = ih == v2_hash20;
        assert!(
            ih == v1_hash || is_v2,
            "the handshake identity must be one of the dual identities, got {}",
            hex(&ih)
        );
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10; // extended
        resp[27] = 0x04; // fast
        resp[29] = 0x10; // v2 capability bit (peer echo, BEP 52)
        resp[28..48].copy_from_slice(&ih);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // After the handshake the mini-seeder sends a full bitfield per
        // BEP 3 (piece count = goffs.len(); under the BEP 52 alignment
        // map the v1/v2 wire spaces have equal length). It used to send
        // no ad and rely on the dispatcher's blind-select fallback; that
        // fallback went away with ad-aware dispatch.
        {
            let n = v2_wire_goffs.len();
            let mut bits = vec![0u8; n.div_ceil(8)];
            for i in 0..n {
                bits[i / 8] |= 0x80 >> (i % 8);
            }
            let mut frame = Vec::with_capacity(5 + bits.len());
            frame.extend_from_slice(((1 + bits.len()) as u32).to_be_bytes().as_slice());
            frame.push(5u8);
            frame.extend_from_slice(&bits);
            sock.write_all(&frame)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        let stream = Arc::clone(&stream);
        let goffs = Arc::clone(&v2_wire_goffs);
        let hash_files = Arc::clone(&hash_files);
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 4];
                if sock.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len == 0 {
                    continue;
                }
                let mut body = vec![0u8; len];
                if sock.read_exact(&mut body).await.is_err() {
                    break;
                }
                match body[0] {
                    2 => {
                        // interested -> unchoke.
                        let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                    }
                    21 => {
                        // hash request (BEP 52): root(32) +
                        // base/index/length/proof.
                        use sha2::{Digest as _, Sha256};
                        if body.len() < 49 {
                            break;
                        }
                        let root: [u8; 32] =
                            body[1..33].try_into().unwrap_or_else(|_| panic!("root"));
                        let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                        let base = be32(&body[33..]);
                        let index = be32(&body[37..]);
                        let length = be32(&body[41..]);
                        let proof = be32(&body[45..]);
                        assert_eq!(base, 0, "the fixture requester only fetches the leaf layer");
                        assert_eq!(
                            proof, 0,
                            "the fixture requester holds a piece-layer anchor, no proof needed"
                        );
                        let Some((_, off, flen)) = hash_files.iter().find(|(r, _, _)| *r == root)
                        else {
                            panic!("hash request with an unknown pieces root: {}", hex(&root));
                        };
                        let (off, flen) = (*off, *flen);
                        let block = 16384u64;
                        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(length as usize);
                        for i in index..index.saturating_add(length) {
                            let s = u64::from(i) * block;
                            if s >= flen {
                                // Out-of-range leaf slot = zero-filled
                                // tree node (BEP 52).
                                hashes.push([0u8; 32]);
                                continue;
                            }
                            let e = (s + block).min(flen);
                            let seg = &stream[(off + s) as usize..(off + e) as usize];
                            hashes.push(Sha256::digest(seg).into());
                        }
                        let mut frame = Vec::with_capacity(49 + 32 * hashes.len());
                        frame.extend_from_slice(&((49 + 32 * hashes.len()) as u32).to_be_bytes());
                        frame.push(22u8);
                        frame.extend_from_slice(&body[1..49]);
                        for h in hashes {
                            frame.extend_from_slice(&h);
                        }
                        if sock.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                    6 => {
                        let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                        let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                        let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                        let off = if is_v2 {
                            goffs[index as usize] + u64::from(begin)
                        } else {
                            index as u64 * L + u64::from(begin)
                        };
                        let end = (off + length as u64) as usize;
                        let block = stream[off as usize..end].to_vec();
                        let mut frame = Vec::with_capacity(13 + block.len());
                        frame.extend_from_slice(&((9 + block.len()) as u32).to_be_bytes());
                        frame.push(7u8);
                        frame.extend_from_slice(&index.to_be_bytes());
                        frame.extend_from_slice(&begin.to_be_bytes());
                        frame.extend_from_slice(&block);
                        if sock.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        });
    }
    // Keep the listener alive until the test ends (dropping it early
    // sends RST to the engine side).
    tokio::time::sleep(Duration::from_secs(120)).await;
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p17-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// v2-only: a single v2 face end to end — truncated identity handshake +
/// PerFile addressing + piece-root verification + compact layout on disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v2_only_downloads_via_truncated_identity() {
    let content: Vec<u8> = (0..2 * L as usize).map(|i| (i * 31 % 251) as u8).collect();
    let tmp = tmp_dir("v2only");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let seen = Arc::new(Mutex::new(HashSet::new()));
    let tracker_addr = fake_tracker(seeder_addr, 1, Arc::clone(&seen)).await;

    let torrent = build_v2_only_torrent(&content, &format!("http://{tracker_addr}/announce"));
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));
    assert_eq!(meta.meta.kind, SwarmKind::V2Only);
    let v2_hash20 = {
        let mut t = [0u8; 20];
        t.copy_from_slice(&meta.meta.identity.v2.unwrap_or_else(|| panic!("v2"))[..20]);
        t
    };

    // Compact single-file layout: goffs = k*L; the seeder stream is the
    // content itself.
    let goffs: Arc<Vec<u64>> = Arc::new((0..2u64).map(|k| k * L).collect());
    // Hash-request supply: single file root @ stream offset 0.
    let file_root = merkle::file_root(
        &content
            .chunks(L as usize)
            .map(merkle::block_hash)
            .collect::<Vec<_>>(),
        L as u32,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let seeder_task = tokio::spawn(dual_seeder(
        seeder_listener,
        Arc::new(content.clone()),
        goffs,
        [0u8; 20], // v2-only has no v1 identity (routing never hits it)
        v2_hash20,
        1,
        Arc::new(vec![(file_root, 0, content.len() as u64)]),
    ));

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = taiji_core::engine::engine_config(
        &meta,
        tmp.clone(),
        0,
        *b"-TJ0001-ENGINEENGIN1",
        taiji_core::engine::CompletionMode::ReturnOnComplete,
    )
    .unwrap_or_else(|e| panic!("engine_config: {e}"));
    assert_eq!(cfg.faces.len(), 1);
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    let got = std::fs::read(tmp.join("v2.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got, content,
        "v2-only downloaded content must match the source"
    );
    let _ = std::fs::remove_dir_all(&tmp);
    seeder_task.abort();
}

/// hybrid: dual swarm in parallel — the same seeder takes one connection
/// under the v1 identity (stream space) and one under the v2 truncated
/// identity (file-aligned space); the engine downloads on both faces at
/// once, cross-face propagation avoids duplicate work, the BEP 52 dual
/// checks pass, and pad zeros never reach disk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hybrid_dual_swarm_downloads_in_parallel() {
    let content_a: Vec<u8> = (0..70000).map(|i| (i * 17 % 253) as u8).collect();
    let content_b: Vec<u8> = (0..30000).map(|i| (i * 7 % 249) as u8).collect();
    let tmp = tmp_dir("hybrid");

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let seen = Arc::new(Mutex::new(HashSet::new()));
    let tracker_addr = fake_tracker(seeder_addr, 2, Arc::clone(&seen)).await;

    let (torrent, stream) = build_hybrid_torrent(
        &content_a,
        &content_b,
        &format!("http://{tracker_addr}/announce"),
    );
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));
    assert_eq!(meta.meta.kind, SwarmKind::Hybrid);
    let v1_hash = meta.meta.identity.v1.unwrap_or_else(|| panic!("v1"));
    let v2_hash32 = meta.meta.identity.v2.unwrap_or_else(|| panic!("v2"));
    let v2_hash20 = {
        let mut t = [0u8; 20];
        t.copy_from_slice(&v2_hash32[..20]);
        t
    };

    // v2-face wire coordinate -> stream-offset table (file-aligned:
    // a's pieces 0..5 at 0.., b's pieces 0..2 at 81920..; identical to
    // the v1 stream coordinates k*L for the first 5 pieces — the BEP 52
    // alignment map).
    let v2_goffs: Arc<Vec<u64>> = Arc::new(vec![0, L, 2 * L, 3 * L, 4 * L, 81920, 98304]);
    // Hash-request supply: a.bin @ 0 (70000 B), b.bin @ 81920 (30000 B).
    let piece_hashes =
        |c: &[u8]| -> Vec<[u8; 32]> { c.chunks(L as usize).map(merkle::block_hash).collect() };
    let ha = piece_hashes(&content_a);
    let hb = piece_hashes(&content_b);
    let bpp = (L / u64::from(merkle::BLOCK_SIZE)) as usize;
    let root_a = merkle::file_root_from_piece_roots(&ha, bpp);
    let root_b = merkle::file_root_from_piece_roots(&hb, bpp);
    let seeder_task = tokio::spawn(dual_seeder(
        seeder_listener,
        Arc::new(stream),
        v2_goffs,
        v1_hash,
        v2_hash20,
        2,
        Arc::new(vec![
            (root_a, 0, content_a.len() as u64),
            (root_b, 81920, content_b.len() as u64),
        ]),
    ));

    let root = tokio_util::sync::CancellationToken::new();
    let cfg = taiji_core::engine::engine_config(
        &meta,
        tmp.clone(),
        0,
        *b"-TJ0001-ENGINEENGIN1",
        taiji_core::engine::CompletionMode::ReturnOnComplete,
    )
    .unwrap_or_else(|e| panic!("engine_config: {e}"));
    assert_eq!(cfg.faces.len(), 2, "the hybrid's dual faces");
    // v2-face identity = first 20 bytes of the truncated SHA-256.
    assert_eq!(cfg.faces[1].info_hash[..], v2_hash32[..20]);
    let engine = DownloadEngine::spawn(cfg, &root);
    let end = tokio::time::timeout(Duration::from_secs(30), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out"));
    root.cancel();
    let end = end.unwrap_or_else(|e| panic!("join: {e}"));
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");

    // Both infohash announces reach the tracker (external evidence of
    // dual-swarm parallelism). percent_encode keeps unreserved bytes and
    // escapes all binary bytes as %XX — compare under the same rule.
    let want_v1 = pct(&v1_hash);
    let want_v2 = pct(&v2_hash20);
    let got = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        got.contains(&want_v1),
        "the v1 infohash was not announced: {got:?}"
    );
    assert!(
        got.contains(&want_v2),
        "the v2 truncated form was not announced: {got:?}"
    );

    // Content and pad semantics: files land on disk correctly; pad files
    // never do (BEP 47).
    let got_a = std::fs::read(tmp.join("a.bin")).unwrap_or_else(|e| panic!("{e}"));
    let got_b = std::fs::read(tmp.join("b.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got_a, content_a);
    assert_eq!(got_b, content_b);
    let names: Vec<String> = tmp
        .read_dir()
        .unwrap_or_else(|e| panic!("{e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().all(|n| n == "a.bin" || n == "b.bin"),
        "no pad files may appear in the directory: {names:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
    seeder_task.abort();
}

/// percent-encode (same rule as bt::tracker::percent_encode; unreserved
/// bytes kept as-is).
fn pct(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

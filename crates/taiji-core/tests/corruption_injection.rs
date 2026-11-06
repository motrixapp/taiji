//! End-to-end 1-bit corruption injection.
//!
//! Chain: build a v2-only metainfo locally (64KiB pieces = 4 blocks/piece
//! x 2 pieces = 8 blocks) -> fake tracker -> mock seeder (supplies the
//! leaf layer for hash requests (21); the piece data plane returns a
//! **1-bit-flipped** block the first time for (piece 1, begin 32KiB) and
//! correct blocks afterwards; requests are counted per (index, begin))
//! -> engine downloads -> assert:
//!
//! 1. the download completes and the file matches byte for byte (all
//! correct blocks are kept; no whole-piece refetch);
//! 2. only the corrupt block is refetched: the seeder-side request count
//! is (1, 32768) = 2 and 1 for each of the other 7 blocks;
//! 3. log surface: capture the tracing output — BlockRejected and the
//! single-block refetch request both appear with (file_index,
//! piece_in_file, block) coordinates, and there is no whole-piece
//! drop event (PieceFailed semantics do not trigger — the isolation
//! property of v2 per-block verification).
//!
//! Protocol source: BEP 52 hash exchange (lazy fetch base=0, length a
//! power of two <= 512) and v2 block granularity 16KiB; upstream aria2
//! (read-only reference) has no v2 implementation, so both ends here are
//! taiji — a normative self-check (SPEC §6.3 requester policy).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use sha2::{Digest as _, Sha256};
use taiji_bt::bencode::{self, Value};
use taiji_bt::filetree::SwarmKind;
use taiji_core::engine::{DownloadEngine, EngineEnd};
use taiji_core::metainfo::Metainfo;
use taiji_store::merkle;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Piece length: 64KiB (4 blocks/piece) — the prerequisite for observing
/// block-level isolation (with 16KiB pieces a piece is one block and the
/// semantics degrade to whole-piece).
const P: u64 = 64 * 1024;
const BLOCK: u64 = 16 * 1024;
/// Corruption injection coordinates: piece 1, begin 32KiB (block 2 in
/// the piece; global leaf 6).
const BAD_PIECE: u32 = 1;
const BAD_BEGIN: u32 = 32 * 1024;

fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
}

fn dict_dyn(mut pairs: Vec<(Vec<u8>, Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Dict(pairs)
}

/// v2-only metainfo (single 128KiB file = 2 pieces x 64KiB; the piece
/// layer = piece-root layer).
fn build_torrent(content: &[u8], announce: &str) -> Vec<u8> {
    let bpp = (P / BLOCK) as usize;
    let piece_roots: Vec<[u8; 32]> = content
        .chunks(P as usize)
        .map(|c| {
            let blocks: Vec<[u8; 32]> = c.chunks(BLOCK as usize).map(merkle::block_hash).collect();
            merkle::root_from_block_hashes(&blocks)
        })
        .collect();
    let root = merkle::file_root_from_piece_roots(&piece_roots, bpp);
    let mut layer = Vec::new();
    for r in &piece_roots {
        layer.extend_from_slice(r);
    }
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
        (b"piece length", Value::Int(P as i64)),
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

/// Seeder-side request ledger: (wire index, begin) -> count.
type ReqLog = Arc<Mutex<HashMap<(u32, u32), u32>>>;

/// Mock seeder: serves the v2 piece space + supplies hash-request leaf
/// layers + flips 1 bit in the designated block on its first request
/// (correct afterwards).
async fn corrupting_seeder(
    listener: tokio::net::TcpListener,
    content: Arc<Vec<u8>>,
    log: ReqLog,
    expect_handshakes: usize,
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
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10; // extended
        resp[27] = 0x04; // fast
        resp[29] = 0x10; // v2 capability bit (BEP 52 upgrade path)
        resp[28..48].copy_from_slice(&hs[28..48]);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        sock.write_all(&resp)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        // After the handshake the seeder sends a full bitfield per BEP 3
        // (2 pieces in this fixture = 0b1100_0000). It used to send no
        // ad and rely on the dispatcher's blind-select fallback
        // (unwrap_or(current)); that fallback went away with ad-aware
        // dispatch (upstream anchor: libtorrent request_blocks.cpp —
        // picking only draws candidates from the peer bitfield). Real
        // clients holding data always advertise.
        sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000])
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let content = Arc::clone(&content);
        let log = Arc::clone(&log);
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
                        let _ = sock.write_all(&[0, 0, 0, 1, 1]).await;
                    }
                    21 => {
                        // hash request: compute the leaf layer on the fly
                        // (base=0, proof=0 asserted).
                        if body.len() < 49 {
                            break;
                        }
                        let be32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                        let base = be32(&body[33..]);
                        let index = be32(&body[37..]);
                        let length = be32(&body[41..]);
                        let proof = be32(&body[45..]);
                        assert_eq!(
                            (base, proof),
                            (0, 0),
                            "the fixture only needs the leaf layer, no proof"
                        );
                        assert!(
                            length.is_power_of_two() && (2..=512).contains(&length),
                            "BEP52 MUST (power of two >= 2) / SHOULD (<= 512): {length}"
                        );
                        let mut hashes = Vec::with_capacity(length as usize);
                        for i in index..index + length {
                            let s = u64::from(i) * BLOCK;
                            if s >= content.len() as u64 {
                                hashes.push([0u8; 32]);
                                continue;
                            }
                            let e = (s + BLOCK).min(content.len() as u64) as usize;
                            hashes.push(Sha256::digest(&content[s as usize..e]).into());
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
                        let req_len = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                        let count = {
                            let mut m = log.lock().unwrap_or_else(|e| e.into_inner());
                            let c = m.entry((index, begin)).or_insert(0);
                            *c += 1;
                            *c
                        };
                        let off = index as u64 * P + u64::from(begin);
                        let end = off + u64::from(req_len);
                        let mut block = content[off as usize..end as usize].to_vec();
                        if index == BAD_PIECE && begin == BAD_BEGIN && count == 1 {
                            // 1-bit flip (first request only; the refetch
                            // gets the correct block — models transient
                            // corruption, not a persistently hostile
                            // peer).
                            assert_eq!(
                                block.len(),
                                BLOCK as usize,
                                "the injection target = a whole block"
                            );
                            block[0] ^= 0x01;
                        }
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
    // Keep the listener alive until the test ends.
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
}

async fn fake_tracker(seeder: SocketAddr) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    tokio::spawn(async move {
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
    });
    addr
}

/// Log-capture handle: reads the captured tracing output (the log
/// surface under assertion).
struct LogCapture {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl LogCapture {
    fn install() -> LogCapture {
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let writer = CaptureWriter(Arc::clone(&buf));
        // with_max_level set explicitly (the test only cares about this
        // engine's info events); the default subscriber is process-global
        // — run this case serially within the test process.
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        );
        LogCapture { buf }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    }
}

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl Clone for CaptureWriter {
    fn clone(&self) -> Self {
        CaptureWriter(Arc::clone(&self.0))
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn tmp_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "taiji-p19-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// End-to-end corruption injection: a 1-bit flip -> only that block is
/// refetched (confirmed by both the seeder count and the logs), every
/// other block is fetched once and kept, and the file ends up
/// byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_bit_flip_refetches_only_that_block() {
    let _log = LogCapture::install();
    let content: Vec<u8> = (0..2 * P as usize).map(|i| (i * 13 % 251) as u8).collect();
    let tmp = tmp_dir();

    let seeder_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let seeder_addr = seeder_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"));
    let tracker_addr = fake_tracker(seeder_addr).await;

    let torrent = build_torrent(&content, &format!("http://{tracker_addr}/announce"));
    let meta = Metainfo::parse(&torrent).unwrap_or_else(|e| panic!("parse: {e}"));
    assert_eq!(meta.meta.kind, SwarmKind::V2Only);

    let log: ReqLog = Arc::new(Mutex::new(HashMap::new()));
    let seeder_task = tokio::spawn(corrupting_seeder(
        seeder_listener,
        Arc::new(content.clone()),
        Arc::clone(&log),
        1,
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
    let end = tokio::time::timeout(std::time::Duration::from_secs(60), engine)
        .await
        .unwrap_or_else(|_| panic!("engine timed out\n--- captured log ---\n{}", _log.text()))
        .unwrap_or_else(|e| panic!("join: {e}"));
    root.cancel();
    assert!(
        matches!(end, EngineEnd::Completed),
        "got {end:?}\n--- captured log ---\n{}\n--- reqlog ---\n{:?}",
        _log.text(),
        log.lock().unwrap_or_else(|e| e.into_inner())
    );

    // The file is byte-identical (the corruption never reached disk; the
    // correct refetch repairs it).
    let got = std::fs::read(tmp.join("v2.bin")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, content, "downloaded content must match the source");

    // Seeder-side request counts: the corrupt block exactly 2 times, the
    // other 7 blocks exactly once.
    let counts = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        counts.len(),
        8,
        "all 8 blocks requested, no out-of-bounds requests: {counts:?}"
    );
    for (piece, block) in [(0u32, 0u32), (0, 16384), (0, 32768), (0, 49152)] {
        assert_eq!(
            counts.get(&(piece, block)),
            Some(&1),
            "a correct block is requested exactly once: ({piece},{block}) {counts:?}"
        );
    }
    for (piece, block) in [(1u32, 0u32), (1, 16384), (1, 49152)] {
        assert_eq!(
            counts.get(&(piece, block)),
            Some(&1),
            "an uncorrupted block is requested exactly once: ({piece},{block}) {counts:?}"
        );
    }
    assert_eq!(
        counts.get(&(BAD_PIECE, BAD_BEGIN)),
        Some(&2),
        "the corrupted block is refetched exactly once: {counts:?}"
    );

    // The log surface ("visible in logs" acceptance):
    let text = _log.text();
    assert!(
        text.contains("block rejected by v2 per-block verification"),
        "a per-block rejection event must appear:\n{text}"
    );
    assert!(
        text.contains("re-fetch request sent (single 16KiB block)"),
        "a single-block refetch request log must appear:\n{text}"
    );
    assert!(
        text.contains("base layer fetched + verified to piece root: cached"),
        "a lazy layer fetch verify-and-cache log must appear:\n{text}"
    );
    // The reject and refetch logs carry (file_index, piece_in_file,
    // block) coordinates: the bad block = piece_in_file 1 / block 2
    // (32KiB / 16KiB).
    let bad_block_line = text
        .lines()
        .find(|l| l.contains("block rejected by v2 per-block verification"))
        .unwrap_or_else(|| panic!("the rejection event line is missing:\n{text}"));
    assert!(
        bad_block_line.contains("piece_in_file=1") && bad_block_line.contains("block=2"),
        "the rejection log must carry the (piece_in_file=1, block=2) fields: {bad_block_line}"
    );
    let refetch_line = text
        .lines()
        .find(|l| l.contains("re-fetch request sent (single 16KiB block)"))
        .unwrap_or_else(|| panic!("the refetch request line is missing:\n{text}"));
    assert!(
        refetch_line.contains("piece_in_file=1") && refetch_line.contains("block=2"),
        "the refetch log must carry the (piece_in_file=1, block=2) fields: {refetch_line}"
    );
    // No whole-piece drop (v1 semantics not triggered —
    // counter-evidence of v2 isolation).
    assert!(
        !text.contains("piece hash mismatch: dropped for re-fetch"),
        "the per-block verification chain must not trigger a whole-piece drop:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
    seeder_task.abort();
}

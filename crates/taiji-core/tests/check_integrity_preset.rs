//! Acceptance: the preset injection path of a bare `--check-integrity`
//! run (engine-level vehicle; the rig mirrors recheck_restore.rs but
//! does **not** touch the session store — the bare CLI form: on-disk
//! recheck -> `EngineConfig.preset_progress` -> the build_faces bitmap
//! restore point).
//!
//! Test 1 (rescan means complete): a complete file on disk -> recheck
//! measures a full bitmap (with the progress sink piece count) -> preset
//! injection -> the engine is Completed right after spawn (the announce
//! points at an unreachable port — completion comes from the restored
//! bitmap, not the network).
//!
//! Test 2 (partial bitmap refetches only missing pieces): piece 0
//! correct on disk, piece 1 corrupt -> recheck measures 0b1000_0000 ->
//! the engine downloads only piece 1 (the seeder asserts piece 0 is
//! never requested — direct evidence that preset bitmap restore is
//! lossless) -> the file is complete.
//!
//! Test 3 (default zero behavior change): the `engine_config()` assembly
//! always leaves preset_progress None (a field-level pin that the
//! existing test surface is unchanged).
//!
//! Red line: the preset does not participate in resume_existing
//! (allocate still runs allocation — missing-file creation + preservation of
//! the existing bytes); in test 2 the on-disk data changing
//! only in piece 1 across the engine run is that red line's executing
//! evidence.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_core::engine::{
    CompletionMode, DownloadEngine, EngineEnd, PresetProgress, engine_config,
};
use taiji_core::metainfo::Metainfo;
use taiji_core::session::{RecheckOutcome, recheck_on_disk_recovering_with_progress};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: u32 = 16384;

fn test_content() -> Vec<u8> {
    const P: &[u8] = b"taiji-check-integrity-preset-";
    P.iter()
        .cycle()
        .take(2 * PIECE_LEN as usize)
        .copied()
        .collect()
}

/// Test-side Result unwrapping (lint forbids unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn tmp_root(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "bh-check-integrity-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    ok(std::fs::create_dir_all(&d), "mkdir");
    d
}

/// bencode byte string `<len>:<bytes>`.
fn bstr(b: &[u8]) -> Vec<u8> {
    let mut out = format!("{}:", b.len()).into_bytes();
    out.extend_from_slice(b);
    out
}

/// Single-file v1 torrent (2 pieces) -> bytes.
fn build_v1_torrent(announce: &str, content: &[u8]) -> Vec<u8> {
    let mut pieces = Vec::new();
    for c in content.chunks(PIECE_LEN as usize) {
        pieces.extend_from_slice(&Sha1::digest(c));
    }
    let mut info = Vec::new();
    info.extend_from_slice(b"d");
    info.extend_from_slice(&bstr(b"length"));
    info.extend_from_slice(format!("i{}e", content.len()).as_bytes());
    info.extend_from_slice(&bstr(b"name"));
    info.extend_from_slice(&bstr(b"blob.bin"));
    info.extend_from_slice(&bstr(b"piece length"));
    info.extend_from_slice(format!("i{}e", PIECE_LEN).as_bytes());
    info.extend_from_slice(&bstr(b"pieces"));
    info.extend_from_slice(format!("{}:", pieces.len()).as_bytes());
    info.extend_from_slice(&pieces);
    info.extend_from_slice(b"e");
    let mut raw = Vec::new();
    raw.extend_from_slice(b"d");
    raw.extend_from_slice(&bstr(b"announce"));
    raw.extend_from_slice(&bstr(announce.as_bytes()));
    raw.extend_from_slice(&bstr(b"info"));
    raw.extend_from_slice(&info);
    raw.extend_from_slice(b"e");
    raw
}

/// Engine-side replica of the CLI mapping (same shape as main.rs
/// `preset_progress_from_outcome`) — carried in-test to avoid
/// referencing a binary-private function across crates.
fn preset_from_outcome(outcome: &RecheckOutcome) -> PresetProgress {
    PresetProgress {
        v1_bitfield: outcome.v1_bitfield.clone(),
        v2_file_bits: outcome.v2_file_bits.clone(),
    }
}

/// On-disk rescan (same entry point and parameter shape as the CLI seam:
/// no recovery layer + progress sink).
fn rescan(meta: &Metainfo, dir: &std::path::Path, sink: &AtomicU64) -> RecheckOutcome {
    recheck_on_disk_recovering_with_progress(meta, dir, &[], Some(sink))
        .unwrap_or_else(|e| panic!("recheck must succeed on valid metainfo: {e}"))
}

/// Rescan means complete: a complete disk -> measured full bitmap (sink
/// count = total pieces) -> preset injection -> Completed right after
/// spawn (unreachable announce: completion does not come from the
/// network).
#[tokio::test]
async fn preset_full_bitfield_completes_without_download() {
    let content = test_content();
    let raw = build_v1_torrent("http://127.0.0.1:1/announce", &content);
    let meta = ok(Metainfo::parse(&raw), "parse metainfo");
    let root = tmp_root("full");
    let dir = root.join("dl");
    ok(std::fs::create_dir_all(&dir), "mkdir dl");
    ok(
        std::fs::write(dir.join("blob.bin"), &content),
        "write full data",
    );

    // On-disk rescan: the measured bitmap is full (2/2) + the progress
    // sink fed (piece counts).
    let sink = AtomicU64::new(0);
    let outcome = rescan(&meta, &dir, &sink);
    assert_eq!(outcome.total, 2, "face 0 piece-count semantics");
    assert_eq!(outcome.verified, 2, "a complete disk verifies all pieces");
    assert_eq!(outcome.v1_bitfield, Some(vec![0b1100_0000]), "full bitmap");
    assert_eq!(
        sink.load(Ordering::Relaxed),
        2,
        "the sink is fed as each piece verifies"
    );

    // Preset injection (no persist row — the bare-run form always takes
    // the preset arm).
    let mut cfg = ok(
        engine_config(
            &meta,
            dir.clone(),
            0,
            *b"-TJ0001-PRESETENGIN1",
            CompletionMode::ReturnOnComplete,
        ),
        "engine config",
    );
    cfg.preset_progress = Some(preset_from_outcome(&outcome));
    let root_token = CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root_token);
    let end = ok(
        ok(
            tokio::time::timeout(Duration::from_secs(30), engine).await,
            "engine must settle",
        ),
        "engine task join",
    );
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    // On-disk bytes preserved (the rescan never touches the write path —
    // zero interaction under the verify-before-write red line).
    assert_eq!(
        ok(std::fs::read(dir.join("blob.bin")), "read back"),
        content,
        "the complete file's bytes must not be rewritten"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Partial bitmap refetches only the missing piece: piece 0 correct +
/// piece 1 corrupt -> measured 0b1000_0000 -> the engine downloads only
/// piece 1 (the seeder is never asked for piece 0) -> the file is
/// complete.
#[tokio::test]
async fn preset_partial_bitfield_redownloads_only_corrupt_piece() {
    let tracker_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "bind tracker",
    );
    let tracker_addr = ok(tracker_listener.local_addr(), "tracker addr");
    let seeder_listener = ok(
        tokio::net::TcpListener::bind("127.0.0.1:0").await,
        "bind seeder",
    );
    let seeder_addr = ok(seeder_listener.local_addr(), "seeder addr");

    let content = test_content();
    let raw = build_v1_torrent(&format!("http://{tracker_addr}/announce"), &content);
    let meta = ok(Metainfo::parse(&raw), "parse metainfo");
    let root = tmp_root("partial");
    let dir = root.join("dl");
    ok(std::fs::create_dir_all(&dir), "mkdir dl");
    // Disk: piece 0 correct, piece 1 corrupt (first byte flipped).
    let mut corrupt = content.clone();
    corrupt[PIECE_LEN as usize] ^= 0xff;
    ok(
        std::fs::write(dir.join("blob.bin"), &corrupt),
        "write corrupt data",
    );

    let sink = AtomicU64::new(0);
    let outcome = rescan(&meta, &dir, &sink);
    assert_eq!(outcome.verified, 1, "only piece 0 actually verifies");
    assert_eq!(
        outcome.v1_bitfield,
        Some(vec![0b1000_0000]),
        "the corrupt piece is cleared"
    );
    assert_eq!(
        sink.load(Ordering::Relaxed),
        2,
        "the per-piece walk covers everything (including the failed piece)"
    );

    // Fake tracker: answers compact peers = the seeder address (one
    // request, one answer, then exits).
    tokio::spawn(async move {
        let (mut sock, _) = match tracker_listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            req.extend_from_slice(&chunk[..n]);
        }
        let std::net::IpAddr::V4(v4) = seeder_addr.ip() else {
            return;
        };
        let mut peers = Vec::new();
        peers.extend_from_slice(&v4.octets());
        peers.extend_from_slice(&seeder_addr.port().to_be_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(b"d8:intervali60e5:peers");
        body.extend_from_slice(peers.len().to_string().as_bytes());
        body.push(b':');
        body.extend_from_slice(&peers);
        body.push(b'e');
        let head = format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
        let _ = sock.write_all(head.as_bytes()).await;
        let _ = sock.write_all(&body).await;
    });
    // Mini-seeder: request -> piece; piece 0 is never requested (the
    // preset-restored bitmap).
    let serve_content = content.clone();
    tokio::spawn(async move {
        let (mut sock, _) = match seeder_listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let mut hs = [0u8; 68];
        if sock.read_exact(&mut hs).await.is_err() {
            return;
        }
        let mut resp = [0u8; 68];
        resp[0] = 19;
        resp[1..20].copy_from_slice(b"BitTorrent protocol");
        resp[25] = 0x10;
        resp[27] = 0x04;
        // The infohash echo = the value the peer's handshake carried
        // (this test surface does no second parse).
        resp[28..48].copy_from_slice(&hs[28..48]);
        resp[48..68].copy_from_slice(b"SEEDERSEEDERSEEDER00");
        if sock.write_all(&resp).await.is_err() {
            return;
        }
        // BEP 3 full bitfield (2 pieces).
        if sock.write_all(&[0, 0, 0, 2, 5, 0b1100_0000]).await.is_err() {
            return;
        }
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
                6 => {
                    let index = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                    assert_ne!(
                        index, 0,
                        "piece 0 was confirmed by the rescan; it must not be re-downloaded"
                    );
                    let begin = u32::from_be_bytes([body[5], body[6], body[7], body[8]]);
                    let length = u32::from_be_bytes([body[9], body[10], body[11], body[12]]);
                    let offset = index as usize * PIECE_LEN as usize + begin as usize;
                    let block = serve_content[offset..offset + length as usize].to_vec();
                    let mut frame = Vec::new();
                    frame.extend_from_slice(((9 + block.len()) as u32).to_be_bytes().as_slice());
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

    let mut cfg = ok(
        engine_config(
            &meta,
            dir.clone(),
            0,
            *b"-TJ0001-PRESETENGIN2",
            CompletionMode::ReturnOnComplete,
        ),
        "engine config",
    );
    cfg.preset_progress = Some(preset_from_outcome(&outcome));
    let root_token = CancellationToken::new();
    let engine = DownloadEngine::spawn(cfg, &root_token);
    let end = ok(
        ok(
            tokio::time::timeout(Duration::from_secs(30), engine).await,
            "engine must settle",
        ),
        "engine task join",
    );
    assert!(matches!(end, EngineEnd::Completed), "got {end:?}");
    // Only the corrupt piece refetched: the final disk = the original
    // content (piece-0 bytes preserved = the preserve-existing-bytes red line's
    // evidence).
    assert_eq!(
        ok(std::fs::read(dir.join("blob.bin")), "read back"),
        content,
        "the file must be complete after refetching only piece 1"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Default zero behavior change: the `engine_config()` assembly always
/// leaves preset_progress None (--check-integrity off = the existing
/// bare-run/session paths' fields unchanged).
#[test]
fn engine_config_defaults_to_no_preset_progress() {
    let content = test_content();
    let raw = build_v1_torrent("http://127.0.0.1:1/announce", &content);
    let meta = ok(Metainfo::parse(&raw), "parse metainfo");
    let cfg = ok(
        engine_config(
            &meta,
            std::path::PathBuf::from("/tmp/bh-check-integrity-default"),
            0,
            *b"-TJ0001-PRESETENGIN3",
            CompletionMode::ReturnOnComplete,
        ),
        "engine config",
    );
    assert_eq!(
        cfg.preset_progress, None,
        "the default must be None (zero behavior delta)"
    );
}

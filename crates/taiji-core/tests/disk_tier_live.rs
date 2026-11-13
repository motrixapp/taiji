//! Acceptance (the live-application assertion half): the engine effect of
//! `taiji.setDiskTier` — `EngineCommand::SetDiskPolicy` goes out over the
//! watch single-value channel and the store pipeline **really shifts
//! gears** (the three parameters IoGate ops quota / flush beat / write
//! merge window change with the tier, asserted via the `QueryDiskPolicy`
//! live reading — atomic values written after the pipeline applies them,
//! not a config mirror).
//!
//! Self-built fixture (a 1-piece v1 torrent + unreachable tracker, same
//! shape as scheduler_policy.rs): the engine starts on the throughput
//! tier (0 quota / no beat / 0 merge window) -> switches in turn to
//! ssd-protect / hdd-sequential / throughput, polling each time until the
//! live reading converges to the tier parameter table's values
//! (including the "reading unchanged = not applied" negative guard: the
//! values before and after a switch are distinguishable). The allocation
//! mode only affects new allocations (no run state here, so it is not
//! asserted).

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{
    DiskTier, DownloadEngine, EngineConfig, EngineHandle, FaceConfig, FaceKind,
};
use taiji_store::disk_policy::{DiskPolicy, LivePolicy};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: usize = 16384;
const INFO_HASH: [u8; 20] = [0x5Bu8; 20];

/// Minimal controlled engine (same fixture as scheduler_policy.rs;
/// defaults to the throughput tier).
fn spawn_test_engine(root: &CancellationToken, dest: &std::path::Path) -> EngineHandle {
    let content = vec![0xABu8; PIECE_LEN];
    let entries = vec![PlanEntry {
        path: std::path::PathBuf::from("part0.bin"),
        length: content.len() as u64,
        padding: false,
    }];
    let layout =
        Layout::plan_v1_padded(&entries, PIECE_LEN as u32).unwrap_or_else(|e| panic!("plan: {e}"));
    let roots: Vec<ExpectedPieceHash> = content
        .chunks(PIECE_LEN)
        .map(|c| ExpectedPieceHash::V1(Sha1::digest(c).into()))
        .collect();
    let cfg = EngineConfig {
        initial_selection: None,
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN2",
        // Unreachable tracker: the engine command surface has no network
        // interaction with this test.
        announce: "http://127.0.0.1:1/announce".into(),
        listen_port: 0,
        piece_len: PIECE_LEN as u32,
        layout,
        dest: dest.to_path_buf(),
        seed_after_complete: false,
        seed: taiji_core::seed::SeedPolicy::default(),
        writer_factory: None,
        faces: vec![FaceConfig {
            kind: FaceKind::V1,
            info_hash: INFO_HASH,
            reserved: Reserved::aria2_default(),
            addressing: Addressing::Flat,
            piece_goffs: vec![0],
            piece_bytes: vec![PIECE_LEN as u64],
            expected: roots,
            plan_file_lengths: vec![content.len() as u64],
            progress_file_lens: vec![content.len() as u64],
            cross: Vec::new(),
            hash_files: None,
        }],
        disk_policy: DiskPolicy::default(),
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
    let (engine, _join) = DownloadEngine::spawn_controlled(
        cfg,
        taiji_core::engine::TrackerWireConfig::default(),
        root,
        taiji_bt::utp::PeerConnectionType::default(),
    );
    engine
}

/// Poll the live reading until it converges on the expected value (a
/// pipeline gear shift is asynchronous — the watch arm applies it when
/// the next select round is ready; the 5s budget is the test surface's
/// convergence bound, not a production-path latency).
async fn wait_live(engine: &EngineHandle, want: LivePolicy) -> LivePolicy {
    for _ in 0..500 {
        let live = engine
            .query_disk_policy()
            .await
            .unwrap_or_else(|e| panic!("query_disk_policy: {e}"));
        if live == want {
            return live;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("live policy did not converge to {want:?} within 5s (last read diverged)");
}

fn tier_live(tier: DiskTier) -> LivePolicy {
    let p = tier.policy();
    LivePolicy {
        io_ops_per_sec: p.io_ops_per_sec,
        flush_interval: p.flush_interval,
        write_merge_max_bytes: p.write_merge_max_bytes,
    }
}

#[tokio::test]
async fn disk_tier_live_application_changes_gate_flush_and_merge() {
    let root = CancellationToken::new();
    let tmp = std::env::temp_dir().join(format!(
        "taiji-p96-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    let engine = spawn_test_engine(&root, &tmp);

    // Starting point = the throughput tier (0 quota / no beat / 0 merge —
    // the zero-change default tier).
    let start = engine
        .query_disk_policy()
        .await
        .unwrap_or_else(|e| panic!("initial query: {e}"));
    assert_eq!(
        start,
        tier_live(DiskTier::Throughput),
        "the default tier at build time"
    );

    // throughput -> ssd-protect: all three parameters (quota / beat /
    // merge window) really change (each distinguishable from the starting
    // values — the "reading unchanged = not applied" negative guard).
    let before = start;
    let want = tier_live(DiskTier::SsdProtect);
    assert_ne!(
        want, before,
        "the ssd tier's parameters are distinguishable from throughput"
    );
    engine
        .set_disk_policy(DiskTier::SsdProtect.policy())
        .await
        .unwrap_or_else(|e| panic!("set ssd-protect: {e}"));
    let after = wait_live(&engine, want).await;
    assert_eq!(
        after,
        LivePolicy {
            io_ops_per_sec: 4096,
            flush_interval: Some(Duration::from_secs(30)),
            write_merge_max_bytes: 1024 * 1024,
        },
        "the ssd tier = the parameter table (4096 ops/s / 30s fsync / 1MiB merge window)"
    );

    // ssd -> hdd-sequential: shift again (low quota + 60s beat + 4MiB
    // merge window).
    let want = tier_live(DiskTier::HddSequential);
    engine
        .set_disk_policy(DiskTier::HddSequential.policy())
        .await
        .unwrap_or_else(|e| panic!("set hdd-sequential: {e}"));
    let after = wait_live(&engine, want).await;
    assert_eq!(
        after,
        LivePolicy {
            io_ops_per_sec: 512,
            flush_interval: Some(Duration::from_secs(60)),
            write_merge_max_bytes: 4 * 1024 * 1024,
        },
        "the hdd tier = the parameter table (512 ops/s / 60s fsync / 4MiB merge window)"
    );

    // hdd -> throughput: back to unlimited / no beat / no merge (live
    // reversibility — not a one-way gate).
    engine
        .set_disk_policy(DiskTier::Throughput.policy())
        .await
        .unwrap_or_else(|e| panic!("set throughput: {e}"));
    wait_live(&engine, tier_live(DiskTier::Throughput)).await;

    // The engine keeps running after the shift (live application has zero
    // side effects — the command loop completes).
    engine
        .query_status()
        .await
        .unwrap_or_else(|e| panic!("query after tier swap: {e}"));

    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), root.cancelled()).await;
    let _ = std::fs::remove_dir_all(&tmp);
}

//! Acceptance: the scheduler-policy skeleton + runtime switch surface +
//! the stream-while-downloading playhead (engine command surface end to
//! end).
//!
//! Self-built fixture (a 1-piece v1 torrent, assembled in-process — same
//! shape as bep53_select). The engine points at an unreachable tracker
//! (no peers, zero dispatch traffic) — this module only exercises the
//! command surface:
//!
//! 1. switching to default (rarest_first) = the engine arm accepts (the
//!    oneshot round-trip completes) and the engine stays queryable
//!    afterwards (the loop undisturbed);
//! 2. the sequential policy accepts + is idempotent (the engine half
//!    validated here, the session/engine split validated on both sides;
//!    no silent fallback to default); streaming= accepts;
//! 3. after switching, the engine keeps running (the policy-object swap
//!    has zero side effects — an atomic object swap inside the
//!    single-writer loop, lock-free);
//! 4. the playhead surface: a valid call returns Ok + a repeated call
//!    (advance) returns Ok; out-of-range file/position returns an
//!    explicit Err (the engine-side validation half).
//!
//! Evidence that default piece selection is behavior-unchanged lives in
//! the unit tests (the engine::strategy decision table, the existing
//! dispatch tests unchanged and green) and in engine::tests' switch
//! atomicity test; not repeated here.

use std::time::Duration;

use sha1::{Digest as _, Sha1};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_core::engine::{DownloadEngine, EngineConfig, FaceConfig, FaceKind, SchedulerPolicy};
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::layout::{Layout, PlanEntry};
use tokio_util::sync::CancellationToken;

const PIECE_LEN: usize = 16384;
const INFO_HASH: [u8; 20] = [0x5Au8; 20];

/// Minimal controlled engine: a 1-piece v1 face + an unreachable tracker
/// (no peers; the command loop stays active).
fn spawn_test_engine(
    root: &CancellationToken,
    dest: &std::path::Path,
) -> taiji_core::engine::EngineHandle {
    let content = vec![0xCDu8; PIECE_LEN];
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
        preset_progress: None, // default None, no behavior change
        tracker_options: taiji_bt::tracker::TrackerOptions::default(), // announce client options at defaults (same values as aria2)
        peer_id: *b"-TJ0001-ENGINEENGIN1",
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
        // Default throughput profile (no behavior change — this module
        // only exercises the command surface; the disk surface is covered
        // by disk_policy.rs).
        disk_policy: taiji_store::disk_policy::DiskPolicy::default(),
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

/// The named `sequential()` constructor is the panic-free consume face:
/// production callers must go through it instead of
/// `"sequential".parse().unwrap_or_else(panic!)` (a string lookup whose
/// Err arm would turn an engine-side rename into a remote panic on the
/// single-writer session actor). Locks: the constructor equals the
/// string-lookup verdict (behavior-preserving swap) and echoes the frozen
/// "sequential" name.
#[test]
fn sequential_named_constructor_matches_from_str() {
    let ctor = SchedulerPolicy::sequential();
    let parsed: SchedulerPolicy = "sequential".parse().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(ctor, parsed, "named ctor = the string-lookup verdict");
    assert_eq!(ctor.name(), "sequential", "frozen name (serde/echo face)");
    assert!(ctor.is_supported(), "sequential stays configurable");
}

#[tokio::test]
async fn scheduler_policy_engine_roundtrip_and_rejection() {
    let root = CancellationToken::new();
    let tmp = std::env::temp_dir().join(format!(
        "taiji-p85-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&tmp).unwrap_or_else(|e| panic!("{e}"));

    let engine = spawn_test_engine(&root, &tmp);

    // 1. The default (rarest_first) switch = the engine arm accepts (the
    // command loop's receipt completes).
    engine
        .set_scheduler_policy(SchedulerPolicy::default())
        .await
        .unwrap_or_else(|e| panic!("set rarest_first: {e}"));

    // 2. streaming= accepts; a valid playhead call + a repeated call
    // (advance) both return Ok.
    let streaming: SchedulerPolicy = "streaming".parse().unwrap_or_else(|e| panic!("{e}"));
    engine
        .set_scheduler_policy(streaming)
        .await
        .unwrap_or_else(|e| panic!("set streaming: {e}"));
    engine
        .set_streaming_playhead(0, PIECE_LEN as u64, None)
        .await
        .unwrap_or_else(|e| panic!("playhead set: {e}"));
    engine
        .set_streaming_playhead(0, PIECE_LEN as u64 / 2, Some(1024))
        .await
        .unwrap_or_else(|e| panic!("playhead advance: {e}"));

    // 3. sequential = the engine side accepts + an idempotent replay.
    let seq: SchedulerPolicy = "sequential".parse().unwrap_or_else(|e| panic!("{e}"));
    engine
        .set_scheduler_policy(seq.clone())
        .await
        .unwrap_or_else(|e| panic!("sequential accepted: {e}"));
    engine
        .set_scheduler_policy(seq)
        .await
        .unwrap_or_else(|e| panic!("sequential idempotent: {e}"));

    // 4. An out-of-range playhead = an explicit Err (no silent clamping).
    for (file, position) in [(7u32, 0u64), (0, PIECE_LEN as u64 + 1)] {
        let outcome = engine.set_streaming_playhead(file, position, None).await;
        let Err(err) = outcome else {
            panic!("playhead ({file}, {position}) must be rejected");
        };
        assert!(
            err.to_string().starts_with("playhead "),
            "the out-of-bounds error text: {err}"
        );
    }

    // 5. The engine keeps running after the swap (atomic object swap,
    // zero side effects; live queries complete).
    engine
        .query_status()
        .await
        .unwrap_or_else(|e| panic!("query after swap: {e}"));
    // A second default switch (harmless idempotent replay) + query again.
    engine
        .set_scheduler_policy(SchedulerPolicy::default())
        .await
        .unwrap_or_else(|e| panic!("re-set rarest_first: {e}"));
    engine
        .query_status()
        .await
        .unwrap_or_else(|e| panic!("query after re-swap: {e}"));

    root.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(2), root.cancelled()).await;
    let _ = std::fs::remove_dir_all(&tmp);
    // No assertion on the engine's end state (no peer task surface;
    // Cancelled/SeedStopped are both possible — this module's
    // command-surface facts are already settled by the receipts above;
    // the join handle is dropped with the test).
}

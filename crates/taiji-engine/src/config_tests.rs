//! metainfo -> engine config assembly behavior tests.
//!
//! Ownership constraint: the assembly function lives on the engine side
//! (the domain model does not reference engine types), so its behavior
//! tests live here with the function; fixtures and assertions keep the
//! metadata-face conventions (the domain-side taiji_domain::metainfo
//! tests keep only the pure parsing face); the method-call shape goes
//! through the trait adaptation seam at the end of this file, pointing
//! at the assembly function itself — a single source for the assembly
//! logic.

use std::path::PathBuf;

use taiji_bt::bencode::{self, Value};
use taiji_bt::filetree::SwarmKind;
use taiji_bt::info_hash::truncated_v2;
use taiji_bt::piece_id::Addressing;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::merkle;
use taiji_store::verified::CrossRule;

use super::config::{CompletionMode, EngineConfig, FaceKind};
use taiji_domain::metainfo::{Metainfo, MetainfoError};

/// Method-shape adaptation seam (in-test): an equivalent method-call
/// shape for the assembly function — test bodies keep the original
/// method-chain style, delegating to the real body without holding a
/// second copy of the assembly logic.
trait EngineConfigAssembly {
    fn engine_config(
        &self,
        dest: PathBuf,
        listen_port: u16,
        peer_id: [u8; 20],
        completion: CompletionMode,
    ) -> Result<EngineConfig, MetainfoError>;
}

impl EngineConfigAssembly for Metainfo {
    fn engine_config(
        &self,
        dest: PathBuf,
        listen_port: u16,
        peer_id: [u8; 20],
        completion: CompletionMode,
    ) -> Result<EngineConfig, MetainfoError> {
        super::config::engine_config(self, dest, listen_port, peer_id, completion)
    }
}

/// Hybrid fixture (from the bt crate): the dual infohashes match the
/// libtorrent cross-validated values, the v1_offset union is correct,
/// and the layout derivation includes the pad.
#[test]
fn parse_hybrid_fixture_dual_identity() {
    const EXPECTED_V1: &str = "9e4fb011b72c9ebdf1152175a20fe4e9f5a866a0";
    const EXPECTED_V2: &str = "d7f59962f0b19ab34dbad44ea906d9f270806fedab6eff552ebef9cfa8f8cb40";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../taiji-bt/tests/fixtures/hybrid_16k.torrent");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture: {e}"));

    let m = Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("parse: {e}"));
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let v1_hash = m
        .meta
        .identity
        .v1
        .unwrap_or_else(|| panic!("a hybrid must have v1"));
    let v2_hash = m
        .meta
        .identity
        .v2
        .unwrap_or_else(|| panic!("a hybrid must have v2"));
    assert_eq!(hex(&v1_hash), EXPECTED_V1);
    assert_eq!(hex(&v2_hash), EXPECTED_V2);
    assert_eq!(m.meta.kind, SwarmKind::Hybrid);
    assert_eq!(m.announce, "http://example.invalid/announce");
    assert_eq!(m.meta.piece_length, 16384);
    assert_eq!(m.v1_pieces.len(), 7);

    // The hybrid main view = DFS order, no pad entries; v1_offset comes
    // from the v1 view's union.
    assert_eq!(
        m.meta.files.len(),
        2,
        "pad absent from the main view (derived from offset differences)"
    );
    let (a, b) = (&m.meta.files[0], &m.meta.files[1]);
    assert_eq!(a.path, std::path::Path::new("a.bin"));
    assert_eq!(a.length, 70000);
    assert_eq!(a.v1_offset, Some(0));
    assert!(
        a.pieces_root.is_some(),
        "a v2 non-empty file must have a root"
    );
    assert!(
        a.piece_layer.is_some(),
        "a >1-piece file must have a metadata layer"
    );
    assert_eq!(b.path, std::path::Path::new("b.bin"));
    assert_eq!(b.length, 30000);
    assert_eq!(
        b.v1_offset,
        Some(81920),
        "the file after the pad starts at a piece boundary"
    );
    assert_eq!(
        m.meta.total_len(),
        100_000,
        "main view = the real file sum (no pad)"
    );

    // Layout derivation: a + pad(11920) + b, total 111920
    // (BEP47-aligned).
    let entries = m.meta.plan_entries().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(entries.len(), 3);
    assert!(entries[1].padding);
    assert_eq!(entries[1].length, 11920);
    assert_eq!(entries[1].path, std::path::Path::new(".pad/11920"));
    let layout = m.meta.layout().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(layout.total(), 111920);

    // engine_config: hybrid dual face — the v1 face and v2 face each
    // have 7 pieces.
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/unused"),
            6881,
            *b"-TJ0001-ENGINEENGIN1",
            CompletionMode::Seed,
        )
        .unwrap_or_else(|e| panic!("engine_config: {e}"));
    assert_eq!(cfg.layout.total(), 111920);
    assert_eq!(cfg.faces.len(), 2, "hybrid dual face");
    let (v1f, v2f) = (&cfg.faces[0], &cfg.faces[1]);
    assert_eq!(v1f.kind, FaceKind::V1);
    assert_eq!(v1f.expected.len(), 7);
    assert_eq!(
        v1f.info_hash,
        m.meta
            .identity
            .v1
            .unwrap_or_else(|| panic!("a hybrid must have v1"))
    );
    assert_eq!(v1f.addressing, Addressing::Flat);
    assert_eq!(
        v1f.piece_goffs,
        (0..7u64).map(|k| k * 16384).collect::<Vec<_>>()
    );
    // Cross-check table: each piece recomputes a v2 root from its
    // content prefix (k4 = a's last piece, 4464B content + pad; k5/k6 =
    // b's two pieces).
    assert_eq!(v1f.cross.len(), 7);
    assert!(v1f.cross.iter().all(|c| c.is_some()));
    if let Some(CrossRule::V2Root { content_bytes, .. }) = v1f.cross[4] {
        assert_eq!(content_bytes, 4464);
    } else {
        panic!("k4 must be a V2Root rule");
    }
    // The v2 face identity = truncated sha256 (first 20B).
    assert_eq!(v2f.kind, FaceKind::V2);
    assert_eq!(v2f.expected.len(), 7, "a's 5 pieces + b's 2 pieces");
    assert_eq!(
        v2f.info_hash,
        truncated_v2(
            &m.meta
                .identity
                .v2
                .unwrap_or_else(|| panic!("a hybrid must have v2"))
        )
    );
    assert_eq!(v2f.addressing, Addressing::per_file(&[70000, 30000], 16384));
    // v2 compact addressing vs v1 layout offsets: b's first piece disk
    // offset = 81920 (after the pad), the same position as v1 stream
    // piece k5 (layout-face evidence that the unified piece space is
    // identity).
    assert_eq!(v2f.piece_goffs[5], 81920);
    assert_eq!(v2f.piece_goffs[6], 81920 + 16384);
    assert_eq!(
        v2f.piece_bytes[4], 4464,
        "a's last piece sized by the file remainder"
    );
    assert_eq!(
        v2f.piece_bytes[6], 13616,
        "b's last piece sized by the file remainder"
    );
    // v2 face cross-check: the pad zero segment (k4 = 16384-4464 =
    // 11920).
    if let Some(CrossRule::V1Hash { pad_zeros, .. }) = v2f.cross[4] {
        assert_eq!(pad_zeros, 11920);
    } else {
        panic!("k4 must be a V1Hash rule");
    }
    // v2 face hash-serving file face: layout offsets backfilled.
    let hf = v2f
        .hash_files
        .as_ref()
        .unwrap_or_else(|| panic!("the v2 face must have a hash file face"));
    assert_eq!(hf[1].v1_offset, Some(81920));
    assert!(
        v1f.hash_files.is_none(),
        "the v1 face has no hash-service face"
    );
    assert!(
        v1f.reserved.supports_v2(),
        "the hybrid v1 face's handshake carries the v2 capability bit"
    );
    assert!(v2f.reserved.supports_v2());
    assert!(cfg.seed_after_complete);
}

/// Disk view layout — a multi-file hybrid nests under the `<name>/`
/// directory (BEP3 files[].path is relative to the name dir; aria2
/// `bittorrent_helper.cc` follows the same rule); the wire view stays
/// unprefixed (the hash-serving face's `Layout::find` depends on the
/// same shape); the two views' offsets/totals are identical; a single
/// file = the name itself, no prefix (the correct flat shape).
#[test]
fn disk_layout_nests_multi_file_under_name_dir() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../taiji-bt/tests/fixtures/hybrid_16k.torrent");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture: {e}"));
    let m = Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("parse: {e}"));
    assert_eq!(m.name.as_deref(), Some("taiji-p01-hybrid"));
    assert!(m.multi_file);

    // Wire view: unprefixed (MetaFile.path same shape).
    let wire = m.meta.layout().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire.files()[0].path, std::path::Path::new("a.bin"));
    assert_eq!(wire.files()[2].path, std::path::Path::new("b.bin"));

    // Disk view: nested under the name dir (including the pad
    // placeholder entry, never written to disk).
    let disk = m.disk_layout().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        disk.files()[0].path,
        std::path::Path::new("taiji-p01-hybrid/a.bin")
    );
    assert_eq!(
        disk.files()[1].path,
        std::path::Path::new("taiji-p01-hybrid/.pad/11920")
    );
    assert_eq!(
        disk.files()[2].path,
        std::path::Path::new("taiji-p01-hybrid/b.bin")
    );
    // Offsets/totals identical to the wire view (the prefix changes only
    // paths, not the byte stream).
    for (w, d) in wire.files().iter().zip(disk.files()) {
        assert_eq!(
            (w.offset, w.length, w.padding),
            (d.offset, d.length, d.padding)
        );
    }
    assert_eq!(wire.total(), disk.total());

    // engine_config delivers the disk view (writer/reader join paths by
    // it on disk).
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/unused"),
            6881,
            *b"-TJ0001-ENGINEENGIN1",
            CompletionMode::Seed,
        )
        .unwrap_or_else(|e| panic!("engine_config: {e}"));
    assert_eq!(cfg.layout.files()[0].path, disk.files()[0].path);
}

/// v2-only missing-layer degradation: a multi-piece file with no `piece
/// layers` entry -> load not rejected (degrades to `layer_missing`), the
/// v2 face assembles as usual — missing-layer pieces' expected roots are
/// placeholder all-zero roots (SHA-256 is preimage-resistant =>
/// structurally unable to pass verification or reach disk);
/// piece count / addressing / goffs align with the full configuration;
/// the hash-serving file face is in place (its piece-layer serving path
/// answers hash reject because the layer is None).
#[test]
fn v2_only_layer_missing_degrades_and_builds_face() {
    let content: Vec<u8> = (0..3 * 16384).map(|i| (i % 249) as u8).collect();
    let leaves: Vec<[u8; 32]> = content.chunks(16384).map(merkle::block_hash).collect();
    let root = merkle::file_root(&leaves, 16384).unwrap_or_else(|e| panic!("{e}"));
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![(
                b"m.bin".to_vec(),
                Value::Dict(vec![(
                    b"".to_vec(),
                    Value::Dict(vec![
                        (b"length".to_vec(), Value::Int(3 * 16384)),
                        (b"pieces root".to_vec(), Value::Bytes(root.to_vec())),
                    ]),
                )]),
            )]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(16384)),
        // Note: no top-level `piece layers`, and no `pieces` inside info
        // (v2-only).
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw)
        .unwrap_or_else(|e| panic!("a missing layer must downgrade and keep loading: {e}"));
    assert!(
        m.meta.files[0].layer_missing(16384),
        "layer_missing projection"
    );
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("missing-layer face build: {e}"));
    assert_eq!(cfg.faces.len(), 1);
    let f = &cfg.faces[0];
    // Face geometry aligned with the full configuration: 3 pieces,
    // placeholder expected roots (all-zero roots that cannot pass
    // verification).
    assert_eq!(f.expected.len(), 3);
    assert!(
        f.expected
            .iter()
            .all(|h| matches!(h, ExpectedPieceHash::V2(z) if *z == [0u8; 32])),
        "missing-layer piece expectations = all-zero placeholder roots (cannot \
         converge -> verify-before-persist holds the gate)"
    );
    assert_eq!(f.piece_goffs.len(), 3);
    // The hash-serving file face is in place (the serving obligation
    // exits via hash reject on layer None).
    assert!(f.hash_files.is_some());
    // Contrast: a fully configured file's expectations = true piece
    // roots (not placeholders).
    let layer_bytes: Vec<u8> = leaves.iter().flat_map(|h| h.iter()).copied().collect();
    let info_full = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![(
                b"m.bin".to_vec(),
                Value::Dict(vec![(
                    b"".to_vec(),
                    Value::Dict(vec![
                        (b"length".to_vec(), Value::Int(3 * 16384)),
                        (b"pieces root".to_vec(), Value::Bytes(root.to_vec())),
                    ]),
                )]),
            )]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(16384)),
    ]);
    let top_full = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info_full),
        (
            b"piece layers",
            dict(vec![(root.as_slice(), Value::Bytes(layer_bytes))]),
        ),
    ]);
    let raw_full = bencode::encode(&top_full).unwrap_or_else(|e| panic!("{e}"));
    let m_full = Metainfo::parse(&raw_full).unwrap_or_else(|e| panic!("full-config parse: {e}"));
    assert!(!m_full.meta.files[0].layer_missing(16384));
    let cfg_full = m_full
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cfg_full.faces[0].expected,
        vec![
            ExpectedPieceHash::V2(leaves[0]),
            ExpectedPieceHash::V2(leaves[1]),
            ExpectedPieceHash::V2(leaves[2]),
        ],
        "full config = the real piece roots cut from the metadata layer"
    );
}

/// Hybrid missing layer: the v1 face builds as usual with expected
/// hashes from info `pieces` (independent of piece layers); the
/// cross-check degrades to None for the missing-layer file's pieces
/// (V2Root needs piece roots from the layer — not built while the layer
/// is missing, so CrossCheckFailed never fires); the fully configured
/// file's pieces still get V2Root.
#[test]
fn hybrid_layer_missing_cross_degrades_to_none() {
    use sha1::{Digest as _, Sha1};
    let p0 = Sha1::digest([0u8; 16384]);
    let p1 = Sha1::digest([1u8; 16384]);
    let p2 = Sha1::digest([2u8; 16384]);
    let mut pieces = Vec::new();
    pieces.extend_from_slice(&p0);
    pieces.extend_from_slice(&p1);
    pieces.extend_from_slice(&p2);
    let content_a: Vec<u8> = (0..2 * 16384).map(|i| (i % 249) as u8).collect();
    let leaves_a: Vec<[u8; 32]> = content_a.chunks(16384).map(merkle::block_hash).collect();
    let root_a = merkle::file_root(&leaves_a, 16384).unwrap_or_else(|e| panic!("{e}"));
    // a.bin (2 pieces, missing layer) + b.bin (1 piece = fully
    // configured single piece; no entry is spec behavior).
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![
                (
                    b"a.bin".to_vec(),
                    Value::Dict(vec![(
                        b"".to_vec(),
                        Value::Dict(vec![
                            (b"length".to_vec(), Value::Int(2 * 16384)),
                            (b"pieces root".to_vec(), Value::Bytes(root_a.to_vec())),
                        ]),
                    )]),
                ),
                (
                    b"b.bin".to_vec(),
                    Value::Dict(vec![(
                        b"".to_vec(),
                        Value::Dict(vec![
                            (b"length".to_vec(), Value::Int(16384)),
                            (b"pieces root".to_vec(), Value::Bytes(vec![0xbb; 32])),
                        ]),
                    )]),
                ),
            ]),
        ),
        (
            b"files",
            Value::List(vec![
                dict(vec![
                    (b"length", Value::Int(2 * 16384)),
                    (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                ]),
                dict(vec![
                    (b"length", Value::Int(16384)),
                    (b"path", Value::List(vec![Value::Bytes(b"b.bin".to_vec())])),
                ]),
            ]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(16384)),
        (b"pieces", Value::Bytes(pieces)),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("hybrid missing-layer downgrade: {e}"));
    assert!(m.meta.files[0].layer_missing(16384));
    assert!(
        !m.meta.files[1].layer_missing(16384),
        "a single-piece file is never flagged"
    );
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(cfg.faces.len(), 2, "hybrid dual face");
    let (v1f, v2f) = (&cfg.faces[0], &cfg.faces[1]);
    // v1 face: expected hashes = info pieces (real SHA-1,
    // layer-independent); cross table: a.bin's two pieces = None
    // (missing-layer degradation), b.bin's one piece = V2Root (fully
    // configured).
    assert_eq!(v1f.expected.len(), 3);
    assert_eq!(v1f.cross.len(), 3);
    assert!(
        v1f.cross[0].is_none() && v1f.cross[1].is_none(),
        "a missing-layer piece's cross = None"
    );
    assert!(
        matches!(v1f.cross[2], Some(CrossRule::V2Root { .. })),
        "the full-config single-piece file still gets its V2Root counterpart"
    );
    // v2 face: a.bin's two pieces get placeholder roots + b.bin's single
    // piece = its pieces root (real).
    assert_eq!(v2f.expected.len(), 3);
    assert!(matches!(&v2f.expected[0], ExpectedPieceHash::V2(z) if *z == [0u8; 32]));
    assert!(matches!(&v2f.expected[1], ExpectedPieceHash::V2(z) if *z == [0u8; 32]));
    assert_eq!(v2f.expected[2], ExpectedPieceHash::V2([0xbb; 32]));
}

/// Malformed hybrid, v2 piece count > v1 pieces: the v2 face's cross rule
/// reads the v1 hash by the v2 piece index (k <-> k), while the face
/// piece-count equality check runs only after both faces assemble — the
/// magnet/ut_metadata metadata surface is remotely reachable, so the
/// mismatch must surface as a MetainfoError (the same FacePieceCountMismatch
/// variant the equality check uses), never an out-of-bounds index panic.
/// Fixture: two 1-byte files — v1 stream space = 2 bytes = 1 piece, v2
/// per-file space = 1 + 1 = 2 pieces (sum-of-ceils > ceil-of-sum).
#[test]
fn hybrid_v2_pieces_exceed_v1_rejected_not_panic() {
    use sha1::{Digest as _, Sha1};
    let p0 = Sha1::digest([0u8; 16384]);
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![
                (
                    b"a.bin".to_vec(),
                    Value::Dict(vec![(
                        b"".to_vec(),
                        Value::Dict(vec![
                            (b"length".to_vec(), Value::Int(1)),
                            (b"pieces root".to_vec(), Value::Bytes(vec![0xaa; 32])),
                        ]),
                    )]),
                ),
                (
                    b"b.bin".to_vec(),
                    Value::Dict(vec![(
                        b"".to_vec(),
                        Value::Dict(vec![
                            (b"length".to_vec(), Value::Int(1)),
                            (b"pieces root".to_vec(), Value::Bytes(vec![0xbb; 32])),
                        ]),
                    )]),
                ),
            ]),
        ),
        (
            b"files",
            Value::List(vec![
                dict(vec![
                    (b"length", Value::Int(1)),
                    (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                ]),
                dict(vec![
                    (b"length", Value::Int(1)),
                    (b"path", Value::List(vec![Value::Bytes(b"b.bin".to_vec())])),
                ]),
            ]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(16384)),
        // v1 stream count = 1: the pieces string matches the v1 face
        // (v1_face's PiecesCountMismatch check passes) — the mismatch is
        // v2-only.
        (b"pieces", Value::Bytes(p0.to_vec())),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw)
        .unwrap_or_else(|e| panic!("malformed piece count accepted at parse: {e}"));
    assert_eq!(m.meta.files.len(), 2);
    let Err(err) = m.engine_config(
        PathBuf::from("/tmp/x"),
        0,
        [0u8; 20],
        CompletionMode::ReturnOnComplete,
    ) else {
        panic!("v2 piece count > v1 piece count must be rejected (not an out-of-bounds panic)");
    };
    assert!(
        matches!(err, MetainfoError::FacePieceCountMismatch { v1: 1, v2: 2 }),
        "rejection variant = FacePieceCountMismatch (the same variant as the \
         post-hoc equality check): {err:?}"
    );
}

/// RPC query view convention check (the event face): after a
/// layer_missing task loads in degraded mode, total = all files (layout
/// total / face piece count / progress denominator all include the
/// missing-layer file), completed = verified bytes only (missing-layer
/// pieces contribute 0 until completed and verified) — the degradation
/// neither shrinks the task's total denominator nor inflates completed.
#[test]
fn layer_missing_total_reflects_all_files() {
    use sha1::{Digest as _, Sha1};
    let p0 = Sha1::digest([0u8; 16384]);
    let p1 = Sha1::digest([1u8; 16384]);
    let p2 = Sha1::digest([2u8; 16384]);
    let mut pieces = Vec::new();
    pieces.extend_from_slice(&p0);
    pieces.extend_from_slice(&p1);
    pieces.extend_from_slice(&p2);
    let content_a: Vec<u8> = (0..2 * 16384).map(|i| (i % 249) as u8).collect();
    let leaves_a: Vec<[u8; 32]> = content_a.chunks(16384).map(merkle::block_hash).collect();
    let root_a = merkle::file_root(&leaves_a, 16384).unwrap_or_else(|e| panic!("{e}"));
    // Same shape as the hybrid degradation test (a.bin 2 pieces missing
    // layer + b.bin 1 piece full).
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![
                (
                    b"a.bin".to_vec(),
                    Value::Dict(vec![(
                        b"".to_vec(),
                        Value::Dict(vec![
                            (b"length".to_vec(), Value::Int(2 * 16384)),
                            (b"pieces root".to_vec(), Value::Bytes(root_a.to_vec())),
                        ]),
                    )]),
                ),
                (
                    b"b.bin".to_vec(),
                    Value::Dict(vec![(
                        b"".to_vec(),
                        Value::Dict(vec![
                            (b"length".to_vec(), Value::Int(16384)),
                            (b"pieces root".to_vec(), Value::Bytes(vec![0xbb; 32])),
                        ]),
                    )]),
                ),
            ]),
        ),
        (
            b"files",
            Value::List(vec![
                dict(vec![
                    (b"length", Value::Int(2 * 16384)),
                    (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                ]),
                dict(vec![
                    (b"length", Value::Int(16384)),
                    (b"path", Value::List(vec![Value::Bytes(b"b.bin".to_vec())])),
                ]),
            ]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(16384)),
        (b"pieces", Value::Bytes(pieces)),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("hybrid missing-layer downgrade: {e}"));
    assert!(m.meta.files[0].layer_missing(16384));
    // The total denominator (tellStatus totalLength = layout total;
    // QueryStatus passes layout.total()): all bytes including the
    // missing-layer file.
    let layout = m.disk_layout().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        layout.total(),
        3 * 16384,
        "the layout total includes the missing-layer file"
    );
    // Face piece count / progress denominator (the composition behind
    // numPieces / bitfield length / completedLength): all 3 pieces (the
    // missing layer does not shrink the face).
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    let v1f = &cfg.faces[0];
    assert_eq!(
        v1f.expected.len(),
        3,
        "face piece count = the full 3 pieces"
    );
    let progress =
        taiji_domain::progress::ProgressModel::from_lengths(&v1f.progress_file_lens, 16384);
    assert_eq!(progress.global_piece_count(), 3);
    assert_eq!(
        progress.completed_length(),
        0,
        "unverified missing-layer pieces -> zero completed contribution (never inflated)"
    );
}

/// v2-only: both the parse face and the data plane work — a single v2
/// face with PerFile addressing + truncated identity + piece-root
/// expected hashes.
#[test]
fn v2_only_parses_and_builds_v2_face() {
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![(
                b"x.bin".to_vec(),
                Value::Dict(vec![(
                    b"".to_vec(),
                    Value::Dict(vec![
                        (b"length".to_vec(), Value::Int(16384)),
                        (b"pieces root".to_vec(), Value::Bytes(vec![0xaa; 32])),
                    ]),
                )]),
            )]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(16384)),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("v2-only should parse: {e}"));
    assert_eq!(m.meta.kind, SwarmKind::V2Only);
    assert!(m.meta.identity.v1.is_none(), "v2-only has no v1 face");
    assert!(m.meta.identity.v2.is_some());
    assert_eq!(m.v1_pieces.len(), 0);
    assert!(m.meta.files[0].pieces_root.is_some());
    // Data plane: a single v2 face, Addressing::PerFile + truncated
    // identity.
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("v2-only data plane: {e}"));
    assert_eq!(cfg.faces.len(), 1);
    let f = &cfg.faces[0];
    assert_eq!(f.kind, FaceKind::V2);
    assert_eq!(
        f.info_hash,
        truncated_v2(&m.meta.identity.v2.unwrap_or_else(|| panic!("v2 identity")))
    );
    assert_eq!(f.addressing, Addressing::per_file(&[16384], 16384));
    assert_eq!(f.expected.len(), 1);
    assert_eq!(
        f.expected[0],
        ExpectedPieceHash::V2([0xaa; 32]),
        "the single-piece file's expectation = its pieces root"
    );
    assert!(f.reserved.supports_v2());
    assert!(f.hash_files.is_some());
}

/// Single-file v1 torrent: announce-list fallback + engine_config.
#[test]
fn parse_single_file_with_announce_list_fallback() {
    use sha1::{Digest as _, Sha1};
    let p0 = Sha1::digest([0u8; 16384]);
    let p1 = Sha1::digest([1u8; 16384]);
    let mut pieces = Vec::new();
    pieces.extend_from_slice(&p0);
    pieces.extend_from_slice(&p1);
    let info = dict(vec![
        (b"length", Value::Int(32768)),
        (b"name", Value::Bytes(b"blob.bin".to_vec())),
        (b"piece length", Value::Int(16384)),
        (b"pieces", Value::Bytes(pieces)),
    ]);
    let top = dict(vec![
        (
            b"announce-list",
            Value::List(vec![Value::List(vec![Value::Bytes(
                b"http://tracker.invalid/a".to_vec(),
            )])]),
        ),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        m.announce, "http://tracker.invalid/a",
        "the announce-list fallback"
    );
    assert_eq!(m.meta.kind, SwarmKind::V1Only);
    assert!(m.meta.identity.v2.is_none(), "v1-only has no v2 face");
    assert_eq!(m.meta.files.len(), 1);
    assert!(!m.meta.files[0].padding);
    assert_eq!(m.meta.total_len(), 32768);
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!cfg.seed_after_complete);
    assert_eq!(cfg.faces.len(), 1, "v1-only single face");
    assert_eq!(cfg.faces[0].kind, FaceKind::V1);
    assert_eq!(cfg.faces[0].expected.len(), 2);
    assert!(
        !cfg.faces[0].reserved.supports_v2(),
        "v1-only handshake carries no v2 capability bit (honest advertising)"
    );
    assert!(
        cfg.faces[0].cross.is_empty(),
        "single format has no cross-check pair"
    );
}

/// Trackerless flip regression: no announce / announce-list -> the parse
/// face accepts with an empty string; the intake gate has two arms —
/// DHT off = accept + WARN (the text anchors the action guidance:
/// hot-enable DHT / add a tracker / restart; the rejection face was
/// removed — with the stalled-state recovery path in place, fail-fast
/// would make revival unreachable), DHT on = accepted and engine
/// assembly is not blocked by the empty announce (pure DHT discovery
/// face).
#[test]
fn trackerless_intake_gate_conditional() {
    let info = dict(vec![
        (b"length", Value::Int(1)),
        (b"name", Value::Bytes(b"x".to_vec())),
        (b"piece length", Value::Int(16384)),
        (b"pieces", Value::Bytes(vec![0u8; 20])),
    ]);
    let top = dict(vec![(b"info", info)]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("trackerless must be accepted: {e}"));
    assert_eq!(
        m.announce, "",
        "both missing = the empty-string sentinel (no fabricated URL)"
    );

    // DHT-off arm (after the flip): accept + WARN, the text carries the
    // full action guidance.
    let warn = m
        .check_intake(false)
        .unwrap_or_else(|| panic!("DHT off + no tracker must produce a stalled-state WARN"));
    assert!(warn.contains("no announce URL"), "{warn}");
    assert!(
        warn.contains("accepted but has no discovery source"),
        "{warn}"
    );
    assert!(
        warn.contains("enable-dht") && warn.contains("bt-disable-dht"),
        "the WARN must point at the hot-enable path (session-level + per-task): {warn}"
    );
    assert!(
        warn.contains("taiji.addTracker"),
        "the WARN must point at adding a tracker: {warn}"
    );
    assert!(
        warn.contains("--enable-dht=true"),
        "the WARN must point at the restart path: {warn}"
    );

    // DHT-on arm: accepted with zero WARN; engine assembly does not fail
    // on the empty announce (pure DHT discovery face = the existing BEP5
    // announce/lookup pipeline).
    assert!(
        m.check_intake(true).is_none(),
        "DHT on + no tracker = no notice"
    );
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("trackerless engine assembly: {e}"));
    assert_eq!(cfg.faces.len(), 1);
    assert_eq!(cfg.announce, "");
}

/// private interaction (BEP27) regression: private + no tracker + DHT
/// on -> the intake gate only handles acceptance (it holds no BEP27
/// gate); the private bit passes through to the engine config as-is;
/// DHT interaction disabling stays owned by the engine's interaction
/// face (the existing gate does not regress).
#[test]
fn private_trackerless_dht_on_intake_accepts_bep27_gate_stays_in_engine() {
    let info = dict(vec![
        (b"length", Value::Int(1)),
        (b"name", Value::Bytes(b"x".to_vec())),
        (b"piece length", Value::Int(16384)),
        (b"pieces", Value::Bytes(vec![0u8; 20])),
        (b"private", Value::Int(1)),
    ]);
    let top = dict(vec![(b"info", info)]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("{e}"));
    assert!(m.private);
    assert!(
        m.check_intake(true).is_none(),
        "the BEP27 gate is not on the intake face (accepted)"
    );
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        cfg.private,
        "the BEP27 bit passes through to the engine (the DHT gate lives on the interaction face)"
    );
}

/// BEP19 `url-list` parsing decision table + engine_config projection
/// assertions: both shapes (single string / list) accepted; entry-level
/// leniency (non-Bytes / non-UTF-8 / non-http(s) scheme skipped); an
/// invalid whole-field shape (Int/Dict) ->
/// [`MetainfoError::MalformedUrlList`] (same precedent as
/// `MalformedAnnounceList` — a metadata defect, independent of the
/// discovery-source switches); missing = empty set (no webseed sentinel,
/// never fabricated). Projection: the `url_list` original values (order
/// preserved) go into `EngineConfig.webseeds` (switch clearing happens
/// in the assembly/activation chain; the parse face always keeps the
/// original values).
#[test]
fn url_list_decision_table_and_engine_config_projection() {
    let info = || {
        dict(vec![
            (b"length", Value::Int(1)),
            (b"name", Value::Bytes(b"x".to_vec())),
            (b"piece length", Value::Int(16384)),
            (b"pieces", Value::Bytes(vec![0u8; 20])),
        ])
    };
    let parse_with = |url_list: Option<Value>| -> Result<Metainfo, MetainfoError> {
        let mut top = vec![(b"info".to_vec(), info())];
        if let Some(v) = url_list {
            top.push((b"url-list".to_vec(), v));
        }
        let raw = bencode::encode(&Value::Dict(top))?;
        Metainfo::parse(&raw)
    };
    // Decision table (input shape -> expected url_list / error).
    // Field missing -> empty set (no webseeds, not an error —
    // discovery-source presence is not adjudicated at this layer).
    let m = parse_with(None).unwrap_or_else(|e| panic!("{e}"));
    assert!(m.url_list.is_empty(), "field missing = empty set");
    // Single-string shape (BEP19): equivalent to [url].
    let m = parse_with(Some(Value::Bytes(b"http://seed.invalid/f".to_vec())))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        m.url_list,
        vec!["http://seed.invalid/f"],
        "the single-string shape is collected"
    );
    // List shape: http + https mixed, all kept, order preserved.
    let m = parse_with(Some(Value::List(vec![
        Value::Bytes(b"http://a.invalid/f".to_vec()),
        Value::Bytes(b"https://b.invalid/g".to_vec()),
    ])))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        m.url_list,
        vec!["http://a.invalid/f", "https://b.invalid/g"],
        "the list shape keeps everything in order"
    );
    // Mixed malformed entries: Int/Dict/non-UTF-8 inside the list are
    // skipped per entry (lenient — no consumer outside the HTTP
    // semantics face); valid entries kept.
    let m = parse_with(Some(Value::List(vec![
        Value::Int(1),
        Value::Dict(vec![]),
        Value::Bytes(vec![0xff, 0xfe]),
        Value::Bytes(b"http://ok.invalid/f".to_vec()),
    ])))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        m.url_list,
        vec!["http://ok.invalid/f"],
        "malformed entries skipped, valid entries kept"
    );
    // Empty list -> empty set (a legal shape, not an error).
    let m = parse_with(Some(Value::List(vec![]))).unwrap_or_else(|e| panic!("{e}"));
    assert!(m.url_list.is_empty(), "empty list = empty set");
    // Invalid whole-field shape (Int / Dict) -> MalformedUrlList (the
    // field is present but is neither a single string nor a list = a
    // metadata defect, same rejection face as MalformedAnnounceList).
    for bad in [Value::Int(3), Value::Dict(vec![])] {
        assert!(
            matches!(parse_with(Some(bad)), Err(MetainfoError::MalformedUrlList)),
            "an invalid whole-field shape must be MalformedUrlList"
        );
    }
    // Non-http(s) scheme filter: ftp/udp/scheme-less are all rejected
    // (a BEP19 webseed is always HTTP GET Range semantics).
    let m = parse_with(Some(Value::List(vec![
        Value::Bytes(b"ftp://x.invalid/f".to_vec()),
        Value::Bytes(b"udp://x.invalid:6969".to_vec()),
        Value::Bytes(b"not-a-url".to_vec()),
        // Scheme case-insensitive (RFC 3986 §3.1).
        Value::Bytes(b"HTTP://cased.invalid/f".to_vec()),
    ])))
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        m.url_list,
        vec!["HTTP://cased.invalid/f"],
        "non-http(s) schemes filtered; case-insensitive"
    );
    // Projection assertion: engine_config always projects the original
    // values (switch clearing belongs to the assembly/activation chain;
    // the parse face holds no switch — the premise of lossless
    // round-trips).
    let m = parse_with(Some(Value::List(vec![
        Value::Bytes(b"http://proj.invalid/f".to_vec()),
        Value::Bytes(b"https://proj.invalid/g".to_vec()),
    ])))
    .unwrap_or_else(|e| panic!("{e}"));
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cfg.webseeds,
        vec!["http://proj.invalid/f", "https://proj.invalid/g"],
        "the url-list original values project into EngineConfig.webseeds"
    );
}

/// A pieces count mismatching the layout -> rejected (prevents a
/// truncated pieces string from passing silently).
#[test]
fn pieces_count_mismatch_rejected() {
    let info = dict(vec![
        (b"length", Value::Int(32768)),
        (b"name", Value::Bytes(b"x".to_vec())),
        (b"piece length", Value::Int(16384)),
        (b"pieces", Value::Bytes(vec![0u8; 20])), // should be 2 pieces
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        m.engine_config(
            PathBuf::from("/tmp/y"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete
        ),
        Err(MetainfoError::PiecesCountMismatch {
            got: 1,
            expected: 2
        })
    ));
}

/// v2 declared length vs the piece-vector budget cap. A malicious v2
/// .torrent of a few hundred bytes can declare a (2^22+1)×16384 length
/// (single file, arbitrary 32B pieces root, metadata layer omitted ->
/// layer_missing degraded load); at assembly, expected/piece_goffs/
/// piece_bytes (and downstream ClaimedSet / progress bitmaps) allocate
/// linearly with the piece count at ~49B/piece => 200MB+ of unbounded
/// amplification. The v1 face is intercepted up front by the
/// pieces-string 20B×piece-count consistency check
/// (`PiecesCountMismatch`); v2 has no equivalent — the budget cap must
/// be decided before any piece-level Vec allocation (deciding only after
/// incremental allocation = the amplification has already happened).
#[test]
fn v2_declared_length_piece_budget_rejected() {
    const PIECE_LEN: u64 = 16384;
    // Cap + 1: 4,194,305 pieces (16KiB each).
    let over_len = (super::config::MAX_TORRENT_PIECES + 1) * PIECE_LEN;
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![(
                b"huge.bin".to_vec(),
                Value::Dict(vec![(
                    b"".to_vec(),
                    Value::Dict(vec![
                        (b"length".to_vec(), Value::Int(over_len as i64)),
                        (b"pieces root".to_vec(), Value::Bytes(vec![0xcc; 32])),
                    ]),
                )]),
            )]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(PIECE_LEN as i64)),
        // No `piece layers` (layer omitted -> layer_missing degradation;
        // v2 lacks v1's pieces-string consistency backstop — this is
        // exactly the attack window).
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse accepted: {e}"));
    assert!(
        m.meta.files[0].layer_missing(16384),
        "the attack shape = missing-layer degraded load (not rejected at the parse face)"
    );
    // Assembly must reject: PieceBudgetExceeded, piece count = the value
    // derived from the declared length.
    assert!(
        matches!(
            m.engine_config(
                PathBuf::from("/tmp/x"),
                0,
                [0u8; 20],
                CompletionMode::ReturnOnComplete,
            ),
            Err(MetainfoError::PieceBudgetExceeded { pieces, max })
                if pieces == super::config::MAX_TORRENT_PIECES + 1 && max == super::config::MAX_TORRENT_PIECES
        ),
        "an over-cap v2 declaration must be rejected before any piece-level Vec allocation"
    );
}

/// Contrast (in budget, not rejected): a 16MiB piece length +
/// 2^22×16384 (64GiB) single file = 4096 pieces, deep inside the cap —
/// the legitimate real-world domain (16KiB pieces correspond to 64GiB,
/// 4MiB pieces to 16TiB, both in budget) is not hurt by the budget cap;
/// the same shape (missing-layer degradation) still assembles.
#[test]
fn v2_in_budget_torrent_assembles_unchanged() {
    let info = dict(vec![
        (
            b"file tree",
            Value::Dict(vec![(
                b"big.bin".to_vec(),
                Value::Dict(vec![(
                    b"".to_vec(),
                    Value::Dict(vec![
                        (
                            b"length".to_vec(),
                            Value::Int((super::config::MAX_TORRENT_PIECES * 16384) as i64),
                        ),
                        (b"pieces root".to_vec(), Value::Bytes(vec![0xdd; 32])),
                    ]),
                )]),
            )]),
        ),
        (b"meta version", Value::Int(2)),
        (b"piece length", Value::Int(16 * 1024 * 1024)),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("in-budget parse: {e}"));
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("in-budget must not be mis-rejected: {e}"));
    let f = &cfg.faces[0];
    // 64GiB / 16MiB = 4096 pieces (missing-layer degradation, all-zero
    // placeholders; geometry as usual).
    assert_eq!(f.expected.len(), 4096);
    assert_eq!(f.piece_goffs.len(), 4096);
    assert_eq!(f.piece_bytes.len(), 4096);
}

/// Boundary function unit test: the budget verdict is a half-open
/// interval — exactly at the cap (2^22 pieces, the legitimate 64GiB at
/// 16KiB pieces) accepted, cap + 1 rejected.
#[test]
fn piece_budget_boundary() {
    assert!(
        super::config::ensure_piece_budget(super::config::MAX_TORRENT_PIECES).is_ok(),
        "accepted exactly at the cap (only > is rejected)"
    );
    assert!(
        matches!(
            super::config::ensure_piece_budget(super::config::MAX_TORRENT_PIECES + 1),
            Err(MetainfoError::PieceBudgetExceeded { pieces, max })
                if pieces == super::config::MAX_TORRENT_PIECES + 1
                    && max == super::config::MAX_TORRENT_PIECES
        ),
        "cap + 1 rejected"
    );
}

/// v1-only small piece length (non-power-of-two) assembly geometry. With
/// piece length 20000: piece count = ceil(total/20000), goff = k*20000,
/// the last piece truncated by the remainder; the BEP47 pad-alignment
/// boundary granularity follows the piece length (30000 -> pad 10000 ->
/// the following file lands at 40000 = a 2×20000 boundary);
/// non-power-of-two piece lengths take no special-case path (div_ceil /
/// multiplication hold for any positive integer piece length).
#[test]
fn v1_only_small_piece_length_assembly_geometry() {
    // a.bin 30000 + .pad/10000 + b.bin 30000 = 70000 -> 4 pieces (last
    // piece 10000).
    let info = dict(vec![
        (
            b"files",
            Value::List(vec![
                dict(vec![
                    (b"length", Value::Int(30000)),
                    (b"path", Value::List(vec![Value::Bytes(b"a.bin".to_vec())])),
                ]),
                dict(vec![
                    (b"attr", Value::Bytes(b"p".to_vec())),
                    (b"length", Value::Int(10000)),
                    (
                        b"path",
                        Value::List(vec![
                            Value::Bytes(b".pad".to_vec()),
                            Value::Bytes(b"10000".to_vec()),
                        ]),
                    ),
                ]),
                dict(vec![
                    (b"length", Value::Int(30000)),
                    (b"path", Value::List(vec![Value::Bytes(b"b.bin".to_vec())])),
                ]),
            ]),
        ),
        (b"name", Value::Bytes(b"geo".to_vec())),
        (b"piece length", Value::Int(20000)),
        // 4 pieces x 20B (the PiecesCountMismatch consistency face).
        (b"pieces", Value::Bytes(vec![0x55; 80])),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("v1-only 20000 must be accepted: {e}"));
    assert_eq!(m.meta.kind, SwarmKind::V1Only);
    assert_eq!(m.meta.piece_length, 20000);

    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| {
            panic!("small-piece-length v1-only assembly must not be rejected: {e}")
        });
    assert_eq!(cfg.piece_len, 20000);
    assert_eq!(cfg.faces.len(), 1);
    let f = &cfg.faces[0];
    assert_eq!(f.kind, FaceKind::V1);
    assert_eq!(f.expected.len(), 4, "ceil(70000/20000) = 4 pieces");
    assert_eq!(
        f.piece_goffs,
        vec![0, 20000, 40000, 60000],
        "goff = k*20000"
    );
    assert_eq!(
        f.piece_bytes,
        vec![20000, 20000, 20000, 10000],
        "the last piece truncated by the remainder (no 16KiB alignment assumption)"
    );
    assert_eq!(f.total(), 70000);
    // The pad stays out of the progress file table (the v1 face = a
    // single-file plan of [stream total]).
    assert_eq!(f.plan_file_lengths, vec![70000]);
}

/// Combined small-piece-length x piece-budget case: with the 16KiB
/// minimum piece length dropped, the same metadata volume can derive
/// more pieces (the count scales as 1/piece_len); the budget is judged
/// by piece count (not bytes), so over-cap is still rejected before any
/// piece-level Vec allocation. The v1 face has a separate
/// metadata-consistency backstop in the pieces string (20B x piece
/// count, `PiecesCountMismatch` at assembly — a real attacker must carry
/// a hash string as long as the piece count), so small piece lengths do
/// not amplify the budget face.
#[test]
fn v1_only_small_piece_length_budget_capped() {
    // 8192 piece length + (2^22+1) pieces total (~32GiB): the metadata
    // itself is tiny (the pieces string holds only 1 hash — the budget
    // check precedes PiecesCountMismatch, so the amplification is
    // stopped at the budget face without forging an 80MB hash string).
    let over_len = (super::config::MAX_TORRENT_PIECES + 1) * 8192;
    let info = dict(vec![
        (b"length", Value::Int(over_len as i64)),
        (b"name", Value::Bytes(b"huge.bin".to_vec())),
        (b"piece length", Value::Int(8192)),
        (b"pieces", Value::Bytes(vec![0x66; 20])),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse accepted: {e}"));
    assert_eq!(
        m.meta.piece_length, 8192,
        "v1-only 8192 accepted at the parse face"
    );
    assert!(
        matches!(
            m.engine_config(
                PathBuf::from("/tmp/x"),
                0,
                [0u8; 20],
                CompletionMode::ReturnOnComplete,
            ),
            Err(MetainfoError::PieceBudgetExceeded { pieces, max })
                if pieces == super::config::MAX_TORRENT_PIECES + 1
                    && max == super::config::MAX_TORRENT_PIECES
        ),
        "a small piece length over the cap is still rejected before any \
         piece-level Vec allocation (the budget judged by piece count)"
    );
}

/// Tracker announce client-option assembly face — the assembly default =
/// the aria2 values (interval 0 = no override + both timeouts 60s, zero
/// behavior difference); the fields can be overwritten by injection (the
/// CLI/session chain overwrites per options before spawn; assemble
/// projects them per face for consumption).
#[test]
fn tracker_options_default_and_overwrite_roundtrip() {
    let info = dict(vec![
        (b"length", Value::Int(8192)),
        (b"name", Value::Bytes(b"f.bin".to_vec())),
        (b"piece length", Value::Int(8192)),
        (b"pieces", Value::Bytes(vec![0x66; 20])),
    ]);
    let top = dict(vec![
        (b"announce", Value::Bytes(b"http://t.invalid".to_vec())),
        (b"info", info),
    ]);
    let raw = bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"));
    let m = Metainfo::parse(&raw).unwrap_or_else(|e| panic!("parse accepted: {e}"));
    // Assembly default = TrackerOptions::default (the same values as
    // aria2's defaults).
    let cfg = m
        .engine_config(
            PathBuf::from("/tmp/x"),
            0,
            [0u8; 20],
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cfg.tracker_options,
        taiji_bt::tracker::TrackerOptions::default(),
        "the assembly face's defaults differ zero in behavior"
    );
    // Overwrite injection passes straight through (the CLI/session-chain
    // injection shape).
    let mut cfg = cfg;
    cfg.tracker_options = taiji_bt::tracker::TrackerOptions {
        bt_tracker_interval: 120,
        bt_tracker_timeout: std::time::Duration::from_secs(90),
        bt_tracker_connect_timeout: std::time::Duration::from_secs(30),
        ..taiji_bt::tracker::TrackerOptions::default()
    };
    assert_eq!(cfg.tracker_options.bt_tracker_interval, 120);
    assert_eq!(
        cfg.tracker_options.bt_tracker_timeout,
        std::time::Duration::from_secs(90)
    );
    assert_eq!(
        cfg.tracker_options.bt_tracker_connect_timeout,
        std::time::Duration::from_secs(30)
    );
}

fn dict(pairs: Vec<(&[u8], Value)>) -> Value {
    let mut v: Vec<(Vec<u8>, Value)> = pairs.into_iter().map(|(k, x)| (k.to_vec(), x)).collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    Value::Dict(v)
}

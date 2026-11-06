//! hash request serving source (BEP52 hash exchange).
//!
//! # Serving obligations and rules (BEP52 text,
//! bittorrent.org/beps/bep_0052.html)
//!
//! - "Clients must be able to service requests for hash blocks covering
//! pieces which they have announced" — this source is installed only for
//! fully seeded data (the engine mounts it after whole-piece validation
//! passes, same timing as ReaderSource);
//! - Only the leaf (0) and piece base layers must be supported ("Clients
//! are only required to support setting the base layer to the leaf and
//! piece layers"); other layers explicitly Err (turned into a hash
//! reject by peer.rs — a legal answer);
//! - Proof layer: derived upward from the base layer data; once the range
//! folds to a single node, each level takes the sibling uncle ("at most
//! one uncle hash is needed per proof layer"); the omission rule (the
//! first log2(length)-1 proof layers) and peer_wire::hashes_count_for
//! are two sides of the same spec;
//! - Self-check: rebuilding the file root from the base layer data must
//! equal the requested pieces root; a mismatch = corrupted data or
//! metadata -> Err (never emit wrong hashes).
//! - Short count (the file shallower than the requested proof) -> Err
//! reject: sending a malformed count frame gets the peer to disconnect
//! per spec; reject is the only legal exit (BEP52 allows any request to
//! be answered with a reject).
//! - Tree shape (corrected): files whose leaf count is not a power of two
//! are balanced by BEP52 **zero-leaf padding** — "The remaining leaf
//! hashes beyond the end of the file required to construct upper layers
//! of the merkle tree are set to zero" (the piece layer completes to a
//! zero-leaf tree root, matching the creator reference implementation).
//! The earlier "odd last node self-pairs" folding was a misreading of
//! an early draft: the current text has no such rule, and it disagreed
//! with the metadata validation side (`store::merkle`), so base=0
//! requests on non-power-of-two files failed the rebuilt-root
//! self-check and were wrongly rejected.
//!
//! # Cost containment (honesty) -> budgeting
//!
//! A base=0 request needs the whole file's leaf layer (proof climbing
//! needs sibling subtrees). Computing per request (read the whole file,
//! hash every 16 KiB) costs O(file size) per request, and that path is
//! exempt from rate limiting for "base=0 requests immediately following a
//! piece" (a BEP52 mandatory serving item) — an amplification surface in
//! seeding state. Now budgeted (trade-offs in the const docs):
//!
//! - **Layer cache**: whole-file leaf layers for base=0 are LRU-cached by
//! root (resident cap [`HASH_LEAF_CACHE_CAP_BYTES`]) — completed
//! seeding data is immutable (the write path closes with whole-piece
//! validation), so a cache hit is always O(1) and repeated requests for
//! the same file no longer amplify;
//! - **Compute budget**: cache misses (first touch / re-touch after
//! eviction) account compute as file-byte equivalents into a rolling
//! window ledger ([`HASH_SERVE_WINDOW`] /
//! [`HASH_SERVE_WINDOW_BUDGET_BYTES`]). Over budget **we still answer
//! and only count** (a BEP52 mandatory obligation cannot be refused —
//! "add budget, never refuse the obligation"); the over-limit count is
//! the observable surface (`LeafLayerCache::over_budget_serves`).
//!
//! The requester-side HashTreeCache ships with the v2 data face.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::debug;

use taiji_bt::peer::HashSource;
use taiji_store::merkle;
use taiji_store::torrent_writer::TorrentReader;

use crate::metainfo::MetaFile;

/// Leaf granularity (always 16 KiB in BEP52).
const BLOCK: u64 = merkle::BLOCK_SIZE as u64;

/// Resident half of the byte-equivalent budget: total byte cap for the
/// base=0 leaf layer cache (LRU eviction). Value = 1/4 of the verified
/// write-cache resident cap `taiji_store::cache::DEFAULT_CACHE_LIMIT`
/// (16MiB) — seeding hash-serving residency is capped at 1/4 of the main
/// write cache. Layer bytes = 32B x piece count, so 4MiB covers the
/// whole-layer working set of ~2GiB of files. A single layer over the cap
/// is not cached (computed on demand + budgeted); a full cache evicts by
/// LRU.
pub const HASH_LEAF_CACHE_CAP_BYTES: usize = 4 * 1024 * 1024;

/// Compute-budget window length (same shape as the responder's hash
/// request rate-limit window — `taiji_bt::peer::inbound::
/// HASH_REQUEST_WINDOW` = 60s; the symmetric face for seeding-side
/// compute).
pub const HASH_SERVE_WINDOW: Duration = Duration::from_secs(60);

/// In-window compute byte-equivalent budget: 64MiB/window is about
/// 1.1MiB/s sustained compute throughput. A legitimate lazy fetch pays
/// the first touch of each file only once (cache hits are O(1)
/// afterwards); this budget leaves headroom for ~4GiB/minute of new
/// first touches. Trade-off (a BEP52 mandatory obligation cannot be
/// refused — "a base=0 request immediately following a piece must not be
/// rejected"; "add budget, never refuse the obligation"): over budget,
/// neither refuse nor throttle (throttling is a disguised refusal);
/// over-limit compute answers normally and is counted in the over-limit
/// counter (observable). The budget's real clamp is the cache — repeated
/// requests for the same file are always O(1) via the layer cache, and
/// compute happens only on first touch / after cache eviction; residency
/// (cache cap) and compute cadence (window ledger) are thus doubly
/// bounded, and the over-limit count preserves criteria for future
/// connection-level handling.
pub const HASH_SERVE_WINDOW_BUDGET_BYTES: u64 = 64 * 1024 * 1024;

/// Zero-value padding node when folding this layer upward (BEP52
/// zero-leaf padding; see module docs): leaf layer = the 32B zero value
/// itself; piece layer = the root of the all-zero-leaf tree (bpp leaves)
/// — two sides of the same spec as `merkle::root_from_block_hashes` /
/// `merkle::file_root_from_piece_roots`.
fn layer_pad(base: u32, piece_len: u32) -> [u8; 32] {
    if base == 0 {
        merkle::ZERO_HASH
    } else {
        merkle::empty_piece_root(merkle::blocks_per_piece(piece_len) as usize)
    }
}

/// Folds one level by adjacent pairing (caller guarantees even length:
/// after zero-padding to a power of two, always even).
fn fold(layer: &[[u8; 32]]) -> Vec<[u8; 32]> {
    layer
        .chunks_exact(2)
        .map(|pair| merkle::node_hash(&pair[0], &pair[1]))
        .collect()
}

/// base=0 leaf layer LRU cache + compute budget ledger. Completed seeding
/// data is immutable (see module docs), so the cached layer is
/// bit-identical to per-request compute. Boundedness: residency <=
/// [`HASH_LEAF_CACHE_CAP_BYTES`] (LRU eviction; an over-cap single layer
/// is not cached); the ledger is a fixed set of scalars, no unbounded
/// bookkeeping.
struct LeafLayerCache {
    /// root -> complete leaf layer (LRU order maintained by `order`).
    map: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// LRU order (front = oldest). Entries correspond one-to-one with
    /// `map` keys (insert dedupes).
    order: VecDeque<[u8; 32]>,
    /// Current resident bytes (sum of layer.len() x 32).
    resident: usize,
    /// Residency cap (production = [`HASH_LEAF_CACHE_CAP_BYTES`]; tests
    /// inject smaller caps).
    cap_bytes: usize,
    /// Budget window start.
    window_start: Instant,
    /// Window length (production = [`HASH_SERVE_WINDOW`]; tests inject).
    window: Duration,
    /// In-window computed byte equivalents (leaf_layer's disk read + hash
    /// cost = file length).
    window_bytes: u64,
    /// In-window compute budget (production =
    /// [`HASH_SERVE_WINDOW_BUDGET_BYTES`]; tests inject).
    budget_bytes: u64,
    /// Over-budget compute serves (session cumulative, observable; over
    /// budget we still answer — the obligation is unchanged; see
    /// [`HASH_SERVE_WINDOW_BUDGET_BYTES`]).
    over_budget_serves: u64,
}

impl LeafLayerCache {
    fn new(now: Instant) -> LeafLayerCache {
        LeafLayerCache::with_limits(
            now,
            HASH_LEAF_CACHE_CAP_BYTES,
            HASH_SERVE_WINDOW,
            HASH_SERVE_WINDOW_BUDGET_BYTES,
        )
    }

    /// Injectable-limits form (drives table-driven tests; production
    /// always [`Self::new`]).
    fn with_limits(
        now: Instant,
        cap_bytes: usize,
        window: Duration,
        budget_bytes: u64,
    ) -> LeafLayerCache {
        LeafLayerCache {
            map: HashMap::new(),
            order: VecDeque::new(),
            resident: 0,
            cap_bytes,
            window_start: now,
            window,
            window_bytes: 0,
            budget_bytes,
            over_budget_serves: 0,
        }
    }

    /// Window rollover (reset on expiry — the time-floor half's tick).
    fn roll_window(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= self.window {
            self.window_start = now;
            self.window_bytes = 0;
        }
    }

    /// Cache hit (LRU touch moves to the back; linear scan — a small set
    /// bounded by cap / layer bytes, no performance face).
    fn get(&mut self, root: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        let layer = self.map.get(root)?;
        if let Some(pos) = self.order.iter().position(|r| r == root) {
            if let Some(r) = self.order.remove(pos) {
                self.order.push_back(r);
            }
        }
        Some(layer.clone())
    }

    /// Accounts compute (file byte equivalents) + attempts caching (an
    /// over-cap single layer is not cached).
    fn account_and_insert(
        &mut self,
        root: [u8; 32],
        file_len: u64,
        layer: &[[u8; 32]],
        now: Instant,
    ) {
        self.roll_window(now);
        self.window_bytes = self.window_bytes.saturating_add(file_len);
        if self.window_bytes > self.budget_bytes {
            self.over_budget_serves += 1;
            debug!(target: "taiji::core::hash_source",
                window_bytes = self.window_bytes, budget = self.budget_bytes,
                "mandatory leaf compute over window budget (served anyway: BEP52 MUST)");
        }
        let bytes = layer.len() * 32;
        if bytes > self.cap_bytes || self.map.contains_key(&root) {
            return;
        }
        while self.resident + bytes > self.cap_bytes {
            let Some(evict) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.map.remove(&evict) {
                self.resident = self.resident.saturating_sub(old.len() * 32);
            }
        }
        self.map.insert(root, layer.to_vec());
        self.order.push_back(root);
        self.resident += bytes;
    }
}

/// Metadata-driven hash request serving source (hybrid/v2 face).
pub struct MetaHashSource {
    files: Vec<MetaFile>,
    reader: TorrentReader,
    piece_len: u32,
    /// base=0 leaf layer cache + compute budget ledger (serve is &self
    /// and shared by multiple connections — Mutex with short critical
    /// sections, no await).
    leaf_cache: Mutex<LeafLayerCache>,
}

impl MetaHashSource {
    pub fn new(files: Vec<MetaFile>, reader: TorrentReader, piece_len: u32) -> MetaHashSource {
        MetaHashSource {
            files,
            reader,
            piece_len,
            leaf_cache: Mutex::new(LeafLayerCache::new(Instant::now())),
        }
    }

    /// Injectable cache/budget limits form (drives budget boundary tests;
    /// production always [`Self::new`]).
    #[cfg(test)]
    fn with_limits(
        files: Vec<MetaFile>,
        reader: TorrentReader,
        piece_len: u32,
        cap_bytes: usize,
        window: Duration,
        budget_bytes: u64,
    ) -> MetaHashSource {
        MetaHashSource {
            files,
            reader,
            piece_len,
            leaf_cache: Mutex::new(LeafLayerCache::with_limits(
                Instant::now(),
                cap_bytes,
                window,
                budget_bytes,
            )),
        }
    }

    /// The base number of the piece layer (the layer where each hash
    /// covers piece_len bytes; base 0 = the 16 KiB leaf layer).
    fn piece_layer_level(&self) -> u32 {
        self.piece_len.trailing_zeros() - merkle::BLOCK_SIZE.trailing_zeros()
    }

    /// The file's leaf layer (base 0): reads the whole file, hashing every
    /// 16 KiB (last block by actual length; pad-region zero semantics
    /// handled by TorrentReader, BEP47). Cost O(file size), see module
    /// docs.
    fn leaf_layer(&self, f: &MetaFile) -> Result<Vec<[u8; 32]>, String> {
        let v1_off = f
            .v1_offset
            .ok_or_else(|| "leaf serving needs v1 layout offset (hybrid face)".to_string())?;
        let leaves = f.length.div_ceil(BLOCK) as usize;
        let mut out = Vec::with_capacity(leaves);
        let mut buf = vec![0u8; BLOCK as usize];
        for i in 0..leaves {
            let start = v1_off + i as u64 * BLOCK;
            let take = (f.length - i as u64 * BLOCK).min(BLOCK) as usize;
            let n = self
                .reader
                .read_at(start, &mut buf[..take])
                .map_err(|e| format!("leaf read: {e}"))?;
            if n != take {
                return Err(format!("leaf short read {n}/{take}"));
            }
            out.push(merkle::block_hash(&buf[..take]));
        }
        Ok(out)
    }
}

impl HashSource for MetaHashSource {
    fn serve(
        &self,
        root: &[u8; 32],
        base: u32,
        index: u32,
        length: u32,
        proof: u32,
    ) -> Result<Vec<[u8; 32]>, String> {
        let f = self
            .files
            .iter()
            .find(|f| f.pieces_root.as_ref() == Some(root))
            .ok_or_else(|| "unknown pieces root (not our announced file)".to_string())?;

        // Full base layer data. base=0 is the O(whole file) compute
        // amplification surface — prefer the layer cache (hit = O(1)); on
        // miss, compute and account file-byte equivalents into the budget
        // ledger (over budget, answer anyway and only count — the BEP52
        // mandatory obligation stands; see HASH_SERVE_WINDOW_BUDGET_BYTES).
        let base_hashes = if base == 0 {
            let now = Instant::now();
            let cached = {
                let mut cache = crate::lock(&self.leaf_cache);
                cache.roll_window(now);
                cache.get(root)
            };
            match cached {
                Some(hit) => hit,
                None => {
                    let leaves = self.leaf_layer(f)?;
                    let mut cache = crate::lock(&self.leaf_cache);
                    cache.account_and_insert(*root, f.length, &leaves, now);
                    leaves
                }
            }
        } else if base == self.piece_layer_level() {
            let layer = f
                .piece_layer
                .as_ref()
                .ok_or_else(|| "no metadata piece layer for file".to_string())?;
            let mut hashes = Vec::with_capacity(layer.len() / 32);
            for c in layer.chunks_exact(32) {
                // chunks_exact(32) guarantees the length; map_err just
                // avoids a panic-based conversion.
                let arr: [u8; 32] = c
                    .try_into()
                    .map_err(|_| "piece layer chunk not 32B".to_string())?;
                hashes.push(arr);
            }
            let pieces_total = f.length.div_ceil(u64::from(self.piece_len)) as usize;
            if hashes.len() != pieces_total {
                return Err(format!(
                    "piece layer size {} != derived {}",
                    hashes.len(),
                    pieces_total
                ));
            }
            hashes
        } else {
            return Err(format!(
                "base layer {base} unsupported (leaf and piece layers only, BEP52)"
            ));
        };

        // BEP52 tree shape: out-of-domain slots are padded to a power of
        // two with this layer's zero value; request slicing and proof
        // climbing both operate on the padded tree (requests covering
        // zero slots past EOF are legal — the lazy-fetch last segment's
        // length=1 -> widen-to-2 plan relies on this path; the admit side
        // trims by leaf domain).
        let pad = layer_pad(base, self.piece_len);
        let mut tree = base_hashes;
        tree.resize(tree.len().next_power_of_two(), pad);

        // Request slice out of range = unservable (beyond even the padded
        // tree).
        let end = index as u64 + length as u64;
        if end > tree.len() as u64 {
            return Err(format!(
                "range {index}+{length} beyond base layer size {}",
                tree.len()
            ));
        }

        // Proof climb: after the range folds to a single node, take the
        // sibling uncle per level (level order = base side first, BEP52
        // "end with the uncle hash closest to the root"). The padded tree
        // is always a power of two, so the sibling always exists
        // (zero-value slots fold normally).
        //
        // `length >= 2` is a codec MUST (peer_wire rejects `length < 2` or a
        // non-power-of-two before the request reaches a hash source); the
        // `31 - leading_zeros` / `log_len - 1` arithmetic below underflows
        // for 0 and 1, so the invariant is pinned here for direct callers.
        debug_assert!(
            length >= 2,
            "hash request length {length} < 2 violates the codec MUST"
        );
        let log_len = 31 - length.leading_zeros(); // length >= 2 (codec MUST)
        let wanted = proof.saturating_sub(log_len - 1);
        let mut out: Vec<[u8; 32]> = tree[index as usize..end as usize].to_vec();
        let mut collected = 0u32;
        let mut idx = index as usize;
        let mut cnt = length as usize;
        while tree.len() > 1 {
            if cnt == 1 && collected < wanted {
                let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
                out.push(tree[sib]);
                collected += 1;
            }
            tree = fold(&tree);
            idx /= 2;
            cnt = cnt.div_ceil(2);
        }
        // Self-check: the rebuilt root must match (emitting wrong hashes
        // is worse than refusing).
        if tree.len() == 1 && tree[0] != *root {
            debug!(target: "taiji::core::hash_source", "rebuilt root mismatch -> reject");
            return Err("rebuilt root mismatch (data/metadata inconsistent)".into());
        }
        // Short count (the file shallower than the requested proof) ->
        // cannot serve in the requested shape.
        if collected < wanted {
            return Err(format!(
                "cannot provide {wanted} proof hashes (tree depth allows {collected})"
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::path::PathBuf;
    use taiji_store::layout::{Layout, PlanEntry};

    /// Deep-tree fixture: 32 KiB pieces (2 leaves/piece) x 8 pieces =
    /// 256 KiB file. Levels: leaf(16) -> piece(8, base=1) -> 4 -> 2 ->
    /// 1(root).
    struct Fixture {
        src: MetaHashSource,
        root: [u8; 32],
        piece_hashes: Vec<[u8; 32]>,
        _tmp: TempDir,
    }

    fn build_fixture() -> Fixture {
        const PIECE: u32 = 32768;
        let content: Vec<u8> = (0..8 * PIECE as usize).map(|i| (i % 251) as u8).collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK as usize)
            .map(merkle::block_hash)
            .collect();
        let piece_hashes: Vec<[u8; 32]> = leaves
            .chunks(2)
            .map(|p| merkle::node_hash(&p[0], &p[1]))
            .collect();
        let root = fold_to_root(piece_hashes.clone());

        let tmp = TempDir::new();
        let entries = vec![PlanEntry {
            path: PathBuf::from("f.bin"),
            length: content.len() as u64,
            padding: false,
        }];
        let layout = Layout::plan_v1_padded(&entries, PIECE).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(tmp.0.join("f.bin"), &content).unwrap_or_else(|e| panic!("{e}"));
        let reader = TorrentReader::new(layout, tmp.0.clone());
        let meta_file = MetaFile {
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
        };
        Fixture {
            src: MetaHashSource::new(vec![meta_file], reader, PIECE),
            root,
            piece_hashes,
            _tmp: tmp,
        }
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            // Uniqueness = pid (cross-process) + in-process monotonic
            // counter + nanos. The nanos-only suffix was insufficient
            // under the parallel test harness: two threads inside one
            // clock-granularity tick got the SAME subsec_nanos, so two
            // fixtures shared one directory and whichever test finished
            // first removed the other's files in `Drop` (observed as a
            // scheduler-gate flake: `leaf read: ... f.bin: No such file
            // or directory`). The counter makes in-process collisions
            // impossible by construction.
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let uniq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let d = std::env::temp_dir().join(format!(
                "taiji-hashsrc-{}-{}-{}",
                std::process::id(),
                uniq,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.subsec_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("{e}"));
            TempDir(d)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Independent verifier (simulated requester): folds the base hashes
    /// to a single node, then merges each uncle by `idx` position (left
    /// child H(node, sib) / right child H(sib, node)).
    fn verify_to_root_at(
        base_hashes: &[[u8; 32]],
        mut idx: usize,
        uncles: &[[u8; 32]],
        expect_root: &[u8; 32],
    ) -> bool {
        let mut layer = base_hashes.to_vec();
        while layer.len() > 1 {
            layer = layer
                .chunks_exact(2)
                .map(|pair| merkle::node_hash(&pair[0], &pair[1]))
                .collect();
            idx /= 2;
        }
        for u in uncles {
            layer = vec![if idx % 2 == 0 {
                merkle::node_hash(&layer[0], u)
            } else {
                merkle::node_hash(u, &layer[0])
            }];
            idx /= 2;
        }
        layer.len() == 1 && layer[0] == *expect_root
    }

    /// Verifier for index=0 ranges (folded nodes are always the left
    /// child; parent = H(node, sib)).
    fn verify_to_root(
        base_hashes: &[[u8; 32]],
        uncles: &[[u8; 32]],
        expect_root: &[u8; 32],
    ) -> bool {
        verify_to_root_at(base_hashes, 0, uncles, expect_root)
    }

    /// In-test tree root (BEP52 zero-leaf padding to a power of two, then
    /// pairwise folding; mirrors `merkle::root_from_block_hashes`).
    fn fold_to_root(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
        layer.resize(layer.len().next_power_of_two(), merkle::ZERO_HASH);
        while layer.len() > 1 {
            layer = layer
                .chunks_exact(2)
                .map(|pair| merkle::node_hash(&pair[0], &pair[1]))
                .collect();
        }
        layer[0]
    }

    /// Piece layer request (base=1): correct slice + a proof chain that
    /// independently recomputes to the root.
    #[test]
    fn serves_piece_layer_with_proofs_to_root() {
        let fx = build_fixture();
        // base=1 (piece layer, 8 nodes), index=0, length=2, proof=2:
        // wanted = 2 - (1-1) = 2; the range folds 1 level to cnt=1
        // (4-node level), uncle@4-node level + uncle@2-node level.
        let hashes = fx
            .src
            .serve(&fx.root, 1, 0, 2, 2)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hashes.len(), 2 + 2, "length 2 + 2 uncle");
        assert_eq!(&hashes[..2], &fx.piece_hashes[0..2], "base layer slice");
        // Requester view: 2 piece hashes + 2 uncles recompute to the file
        // root.
        assert!(
            verify_to_root(&hashes[..2], &hashes[2..], &fx.root),
            "proof chain must independently recompute to the root"
        );
    }

    /// Leaf layer request (base=0): disk recomputation matches content +
    /// the proof chain closes.
    #[test]
    fn serves_leaf_layer_from_disk() {
        let fx = build_fixture();
        // base=0, index=0, length=4 (2 leaves per piece x 2 pieces),
        // proof=3: wanted = 3 - (2-1) = 2; cnt=1 after folding 2 levels.
        let hashes = fx
            .src
            .serve(&fx.root, 0, 0, 4, 3)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hashes.len(), 4 + 2);
        // Leaf hashes independently recompute from on-disk content.
        let content: Vec<u8> = (0..8 * 32768usize).map(|i| (i % 251) as u8).collect();
        for (i, h) in hashes[..4].iter().enumerate() {
            let want: [u8; 32] = Sha256::digest(&content[i * 16384..(i + 1) * 16384]).into();
            assert_eq!(*h, want, "leaf {i}");
        }
        // Requester validation: 4 leaves + 2 uncles recompute to the root.
        // The leaf range spans 2 pieces: folding 1 level yields 2 piece
        // hashes (matching metadata), further levels need uncles.
        let layer1 = fold(&hashes[..4]);
        assert_eq!(
            &layer1[..2],
            &fx.piece_hashes[0..2],
            "folded layer = piece-layer slice"
        );
        assert!(
            verify_to_root(&layer1, &hashes[4..], &fx.root),
            "proof chain must independently recompute to the root"
        );
    }

    /// Unknown root / out of range / unsupported base layer / insufficient
    /// depth -> Err (turned into reject).
    #[test]
    fn unservable_requests_error() {
        let fx = build_fixture();
        assert!(
            fx.src.serve(&[0u8; 32], 1, 0, 2, 1).is_err(),
            "unknown root"
        );
        assert!(
            fx.src.serve(&fx.root, 1, 8, 2, 1).is_err(),
            "out of range (8 pieces)"
        );
        assert!(
            fx.src.serve(&fx.root, 2, 0, 2, 1).is_err(),
            "base=2 unsupported (only leaf and piece layers)"
        );
        // Insufficient depth: piece layer request length=2, proof=3 ->
        // wanted=3, but only 2 uncle levels exist up to the root -> Err
        // (counts are never fabricated).
        assert!(
            fx.src.serve(&fx.root, 1, 0, 2, 3).is_err(),
            "proof exceeding tree depth must be rejected"
        );
    }

    /// Correction: base=0 serving of a file whose leaf count is not a
    /// power of two (3 leaves, 64 KiB pieces) — with the zero-leaf padded
    /// tree shape the rebuilt-root self-check must pass (the earlier
    /// odd-level self-pairing fold disagreed with the metadata root and
    /// wrongly rejected this whole request class).
    #[test]
    fn serves_non_pow2_leaf_layer_with_zero_padding() {
        const PIECE: u32 = 64 * 1024;
        let content: Vec<u8> = (0..3 * merkle::BLOCK_SIZE as usize)
            .map(|i| (i % 253) as u8)
            .collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK as usize)
            .map(merkle::block_hash)
            .collect();
        let root = merkle::root_from_block_hashes(&leaves);
        let fx = build_file_fixture(PIECE, content.clone(), root, None);
        // Last planned segment (hash_fetch len=1 -> widen to 2): index=2,
        // length=2 covers [l2, zero slot] — previously rejected because
        // end=4 > layer length 3.
        let hashes = fx
            .src
            .serve(&root, 0, 2, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hashes.len(), 2 + 1, "length 2 + 1 uncle");
        let want_leaf: [u8; 32] = Sha256::digest(&content[2 * 16384..3 * 16384]).into();
        assert_eq!(hashes[0], want_leaf, "l2 = the real last leaf");
        assert_eq!(
            hashes[1],
            merkle::ZERO_HASH,
            "post-EOF slot = the zero value itself"
        );
        // Requester independent recompute: [l2, 0] fold + uncle -> file
        // root (right-child position).
        assert!(
            verify_to_root_at(&hashes[..2], 2, &hashes[2..], &root),
            "zero-padded proof chain must close to the metadata root"
        );
        // First segment [l0, l1]: uncle = H(l2, 0).
        let hashes = fx
            .src
            .serve(&root, 0, 0, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hashes.len(), 2 + 1);
        assert!(
            verify_to_root(&hashes[..2], &hashes[2..], &root),
            "first-segment proof chain closes"
        );
    }

    /// Correction: base=1 serving with a non-power-of-two piece root
    /// count (3 pieces x 32 KiB pieces) — the piece layer pads to a power
    /// of two with the all-zero-leaf tree root; the proof chain closes to
    /// the file root.
    #[test]
    fn serves_non_pow2_piece_layer_with_zero_padding() {
        const PIECE: u32 = 32 * 1024;
        let content: Vec<u8> = (0..3 * PIECE as usize).map(|i| (i % 249) as u8).collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK as usize)
            .map(merkle::block_hash)
            .collect();
        let piece_hashes: Vec<[u8; 32]> = leaves
            .chunks(2)
            .map(|p| merkle::node_hash(&p[0], &p[1]))
            .collect();
        let root = merkle::file_root_from_piece_roots(
            &piece_hashes,
            merkle::blocks_per_piece(PIECE) as usize,
        );
        let layer = piece_hashes
            .iter()
            .flat_map(|h| h.iter())
            .copied()
            .collect::<bytes::Bytes>();
        let fx = build_file_fixture(PIECE, content, root, Some(layer));
        let hashes = fx
            .src
            .serve(&root, 1, 0, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hashes.len(), 2 + 1, "length 2 + 1 uncle");
        assert_eq!(&hashes[..2], &piece_hashes[0..2], "piece-layer slice");
        assert!(
            verify_to_root(&hashes[..2], &hashes[2..], &root),
            "zero-padded proof chain must close to the file root"
        );
    }

    /// Single-file fixture (assembles disk and metadata from
    /// content/piece_len/root/piece_layer).
    fn build_file_fixture(
        piece_len: u32,
        content: Vec<u8>,
        root: [u8; 32],
        piece_layer: Option<bytes::Bytes>,
    ) -> Fixture {
        let tmp = TempDir::new();
        let entries = vec![PlanEntry {
            path: PathBuf::from("f.bin"),
            length: content.len() as u64,
            padding: false,
        }];
        let layout = Layout::plan_v1_padded(&entries, piece_len).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(tmp.0.join("f.bin"), &content).unwrap_or_else(|e| panic!("{e}"));
        let reader = TorrentReader::new(layout, tmp.0.clone());
        let meta_file = MetaFile {
            path: PathBuf::from("f.bin"),
            length: content.len() as u64,
            padding: false,
            pieces_root: Some(root),
            piece_layer,
            v1_offset: Some(0),
        };
        Fixture {
            src: MetaHashSource::new(vec![meta_file], reader, piece_len),
            root,
            piece_hashes: Vec::new(),
            _tmp: tmp,
        }
    }

    // -------------------------------------------------------------------
    // base=0 serving budget: layer-cache amortization + compute
    // byte-equivalent budget boundaries (over budget never refuses the
    // obligation, only counts).
    // -------------------------------------------------------------------

    /// Fixture with injectable cache/budget limits (assembled like
    /// [`build_file_fixture`]).
    fn build_limited_fixture(
        piece_len: u32,
        content: Vec<u8>,
        root: [u8; 32],
        cap_bytes: usize,
        window: Duration,
        budget_bytes: u64,
    ) -> Fixture {
        let tmp = TempDir::new();
        let entries = vec![PlanEntry {
            path: PathBuf::from("f.bin"),
            length: content.len() as u64,
            padding: false,
        }];
        let layout = Layout::plan_v1_padded(&entries, piece_len).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(tmp.0.join("f.bin"), &content).unwrap_or_else(|e| panic!("{e}"));
        let reader = TorrentReader::new(layout, tmp.0.clone());
        let meta_file = MetaFile {
            path: PathBuf::from("f.bin"),
            length: content.len() as u64,
            padding: false,
            pieces_root: Some(root),
            piece_layer: None,
            v1_offset: Some(0),
        };
        Fixture {
            src: MetaHashSource::with_limits(
                vec![meta_file],
                reader,
                piece_len,
                cap_bytes,
                window,
                budget_bytes,
            ),
            root,
            piece_hashes: Vec::new(),
            _tmp: tmp,
        }
    }

    fn leaf_count(content: &[u8]) -> usize {
        content.len().div_ceil(BLOCK as usize)
    }

    /// Layer cache amortization: first touch computes and caches; repeated
    /// base=0 requests hit at O(1) (zero ledger growth, residency
    /// unchanged) with bit-identical replies; piece layer requests do not
    /// enter this cache.
    #[test]
    fn rec3_leaf_cache_amortizes_base0_serving() {
        const PIECE: u32 = 32 * 1024;
        let content: Vec<u8> = (0..16 * merkle::BLOCK_SIZE as usize)
            .map(|i| (i % 241) as u8)
            .collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK as usize)
            .map(merkle::block_hash)
            .collect();
        let root = merkle::root_from_block_hashes(&leaves);
        let fx = build_limited_fixture(
            PIECE,
            content.clone(),
            root,
            1024,
            Duration::from_secs(60),
            u64::MAX,
        );
        // First touch: computed and cached (layer bytes = 16 leaves x 32B
        // = 512B <= cap).
        let first = fx
            .src
            .serve(&root, 0, 0, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        {
            let cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                cache.resident,
                leaf_count(&content) * 32,
                "first touch cached"
            );
            assert_eq!(cache.over_budget_serves, 0, "ample budget, no overrun");
        }
        // Repeated requests: cache hits, bit-identical replies, zero
        // ledger growth.
        for _ in 0..3 {
            let again = fx
                .src
                .serve(&root, 0, 0, 2, 1)
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(again, first, "cache hit bit-identical to fresh compute");
        }
        {
            let cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                cache.resident,
                leaf_count(&content) * 32,
                "hit does not grow residency"
            );
            assert_eq!(
                cache.window_bytes,
                content.len() as u64,
                "hit adds no compute ledger (ledger stays at first-touch compute)"
            );
            assert_eq!(
                cache.over_budget_serves, 0,
                "ample budget, zero overruns on hit"
            );
        }
        // Piece layer requests use metadata (no disk compute); they
        // neither enter nor grow this cache.
        let piece_hashes: Vec<[u8; 32]> = leaves
            .chunks(2)
            .map(|p| merkle::node_hash(&p[0], &p[1]))
            .collect();
        let layer = piece_hashes
            .iter()
            .flat_map(|h| h.iter())
            .copied()
            .collect::<bytes::Bytes>();
        let fx2 = build_file_fixture(PIECE, content, root, Some(layer));
        let _ = fx2
            .src
            .serve(&root, 1, 0, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        {
            let cache = fx2.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                cache.resident, 0,
                "piece-layer requests do not enter the leaf cache"
            );
        }
    }

    /// Budget boundaries (over residency cap + over window budget): an
    /// over-cap layer is never cached (always computed); over budget
    /// **answers normally and only counts** (BEP52 mandatory obligation —
    /// the served result is bit-identical to in-limit serving); the
    /// ledger resets when the window expires.
    #[test]
    fn rec3_budget_boundary_serves_despite_overrun() {
        const PIECE: u32 = 32 * 1024;
        let content: Vec<u8> = (0..16 * merkle::BLOCK_SIZE as usize)
            .map(|i| (i % 239) as u8)
            .collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK as usize)
            .map(merkle::block_hash)
            .collect();
        let root = merkle::root_from_block_hashes(&leaves);
        // cap 64B < layer 512B (not cached); budget 128B equivalents < one
        // compute (256KiB file bytes) — every compute necessarily
        // exceeds.
        let fx = build_limited_fixture(
            PIECE,
            content.clone(),
            root,
            64,
            Duration::from_secs(60),
            128,
        );
        let served = fx
            .src
            .serve(&root, 0, 0, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            &served[..2],
            &leaves[..2],
            "over-budget still served in full (obligation unchanged)"
        );
        {
            let cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                cache.resident, 0,
                "layer above the residency cap is not cached"
            );
            assert_eq!(cache.over_budget_serves, 1, "overrun counted");
            assert_eq!(
                cache.window_bytes,
                content.len() as u64,
                "compute accounted by file-byte equivalent"
            );
        }
        // Second request: still over-limit compute, still fully served
        // (bit-identical to the first answer).
        let again = fx
            .src
            .serve(&root, 0, 2, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(&again[..2], &leaves[2..4]);
        {
            let cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(cache.over_budget_serves, 2);
        }
        // Window expiry reset (time-floor half): rewind the window start
        // -> next accounting starts from zero.
        {
            let mut cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            let window = cache.window;
            cache.window_start -= window;
        }
        let _ = fx
            .src
            .serve(&root, 0, 4, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        {
            let cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(
                cache.window_bytes,
                content.len() as u64,
                "ledger recomputed from zero after window roll (reset effective)"
            );
            assert_eq!(
                cache.over_budget_serves, 3,
                "after reset first touch still overruns (tiny budget)"
            );
        }
    }

    /// LRU eviction boundary: once residency is full the oldest layer is
    /// evicted (re-touch = recompute + accounting); after eviction,
    /// residency stays <= cap.
    #[test]
    fn rec3_lru_eviction_bounds_residency() {
        const PIECE: u32 = 32 * 1024;
        let mk = |seed: u8| -> (Vec<u8>, [u8; 32]) {
            let content: Vec<u8> = (0..16 * merkle::BLOCK_SIZE as usize)
                .map(|i| (i % 251 + seed as usize) as u8)
                .collect();
            let leaves: Vec<[u8; 32]> = content
                .chunks(BLOCK as usize)
                .map(merkle::block_hash)
                .collect();
            let root = merkle::root_from_block_hashes(&leaves);
            (content, root)
        };
        let (content_a, root_a) = mk(0);
        let (content_b, root_b) = mk(1);
        // Two files cannot share one reader (each fixture is
        // single-file), so the eviction loop is validated on a single
        // file with cap = one layer's bytes: A enters -> B enters,
        // evicting A -> A re-touches and recomputes.
        let fx = build_limited_fixture(
            PIECE,
            content_a.clone(),
            root_a,
            512,
            Duration::from_secs(60),
            u64::MAX,
        );
        let _ = fx
            .src
            .serve(&root_a, 0, 0, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        {
            let cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(cache.resident, 512, "A resident (16 leaves x 32B)");
            assert_eq!(cache.order.len(), 1);
        }
        // Injects a second root's layer directly into the cache (bypassing
        // serve's single-file lookup — exercising the cache eviction
        // boundary); B's layer is as wide as A's -> residency caps -> A
        // evicted.
        {
            let mut cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.account_and_insert(
                root_b,
                content_b.len() as u64,
                &leaves_of(&content_b),
                std::time::Instant::now(),
            );
            assert_eq!(cache.resident, 512, "residency <= cap after B enters");
            assert_eq!(cache.order.len(), 1, "A evicted by LRU");
            assert!(!cache.map.contains_key(&root_a), "A not in cache");
            assert!(cache.map.contains_key(&root_b), "B in cache");
        }
        // A re-touch = cache miss -> recomputed and re-cached (B evicted —
        // LRU order).
        let _ = fx
            .src
            .serve(&root_a, 0, 0, 2, 1)
            .unwrap_or_else(|e| panic!("{e}"));
        {
            let cache = fx.src.leaf_cache.lock().unwrap_or_else(|e| e.into_inner());
            assert!(cache.map.contains_key(&root_a), "A re-touch refills");
            assert!(!cache.map.contains_key(&root_b), "B evicted by LRU");
        }
    }

    /// Content leaf layer (independently recomputed in-test to avoid
    /// cross-fixture coupling).
    fn leaves_of(content: &[u8]) -> Vec<[u8; 32]> {
        content
            .chunks(BLOCK as usize)
            .map(merkle::block_hash)
            .collect()
    }
}

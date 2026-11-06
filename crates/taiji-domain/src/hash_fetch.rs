//! Lazy hash-exchange fetching on the requester side (BEP52 hash exchange).
//!
//! # Rules (BEP52 text, bittorrent.org/beps/bep_0052.html)
//!
//! - `hash request` field constraints (MUST, enforced by the codec):
//! `index` must be a multiple of `length` (including 0); `length` >= 2
//! and a power of two; `length` SHOULD NOT exceed 512;
//! - Requester policy: lazily fetch the base layer (leaf layer, base = 0)
//! spanning the file before downloading blocks; a fetched layer enters
//! the HashTreeCache only after verifying up to the piece root
//! ([`HashTreeCache::verify_and_put_layer`]: recompute the root per
//! piece and compare against the metadata anchor; a bad segment rejects
//! the whole segment from the cache);
//! - Proof layer: this side already holds the metadata piece layer
//! (trusted anchor); lazy fetch targets the leaf layer, `proof = 0` (no
//! proof hashes needed — the reply is the leaf layer itself, and the
//! per-piece root recomputation is the check);
//! - Choke: the requester's sends are unaffected by choke ("Hash requests
//! may be sent to a peer regardless of its choke state"); responder-side
//! semantics are out of scope for this module.
//!
//! # Degradation (honesty)
//!
//! On lazy-fetch failure (hash reject / timeout / disconnect / bad
//! segment), after [`HASH_FETCH_MAX_ATTEMPTS`] retries the engine falls
//! back to whole-piece buffering (the existing v2 whole-piece validation
//! path). The fallback is not a silent default: the engine logs a warn at
//! the switch (dispatch side); the block-level validation side likewise
//! falls back and logs when it meets an unready leaf layer.
//!
//! # Planner ([`plan_base_layer_fetch`])
//!
//! HashTreeCache lazy-fetch admission requires segments to be **piece
//! aligned**: `start % bpp == 0` and `len % bpp == 0` (bpp =
//! blocks_per_piece, a power of two). Combined with the BEP52 MUSTs
//! (`length` a power of two >= 2, `index` a multiple of `length`):
//! - decompose by **pieces** into powers of two (binary decomposition);
//! each segment has len = unit x bpp and starts at a piece boundary, so
//! index = start x bpp is a multiple of len;
//! - len <= 512: unit capped at 512/bpp (when bpp > 512, len = bpp,
//! exceeding only the SHOULD, not the MUST — triggered only by extreme
//! configs with piece_len > 8 MiB);
//! - bpp = 1 with an odd piece count P: the last piece cannot be covered
//! in-bounds by any legal request (even start, len an even power of
//! two — BEP52 requests always cover [even, even) ranges). Handling: the
//! final request covers [P-1, P+1) (len = 2, even start), and the
//! response is trimmed by [`admit_hashes`] to the admission domain
//! [0, P) — leaf P is the zero-padded slot of the BEP52 tree ("The
//! remaining leaf hashes beyond the end of file ... are set to zero");
//! after trimming, the remaining leaves still pass the piece root
//! anchor check, so a malicious filler value cannot enter the cache;
//! - P == 1 and bpp == 1 (single-block file <= 16 KiB): the leaf hash
//! equals the metadata pieces root (the tree is a single leaf); it is
//! anchored into the cache at load time, no network lazy fetch (empty
//! plan).

use std::time::Duration;

use taiji_bt::peer::HashFetch;
use taiji_store::hashtree::HashTreeCache;

/// Lazy-fetch retry cap (per file; exceeded -> whole-piece buffer
/// fallback). Local policy value — BEP52 sets no numbers and aria2 has no
/// v2 implementation to compare against (self-chosen policy).
pub const HASH_FETCH_MAX_ATTEMPTS: u32 = 3;

/// Per-fetch timeout (including waiting for the reply). Local policy value
/// (same as above; no normative source).
pub const HASH_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// A single lazy-fetch request (base = 0 leaf layer; BEP52 field semantics
/// in the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashRequestPlan {
    /// Starting hash index within the base layer (= starting piece number
    /// x bpp; MUST be a multiple of length).
    pub index: u32,
    /// Number of requested hashes (MUST be >= 2 and a power of two; SHOULD
    /// <= 512).
    pub length: u32,
}

/// Lazy-fetch plan: decomposes the file's leaf layer (base = 0) for
/// piece_len into piece-aligned segments.
///
/// An empty plan = no network fetch needed (single-block file <= 16 KiB;
/// the leaf is the pieces root, anchored into the cache at load).
pub fn plan_base_layer_fetch(file_len: u64, piece_len: u32) -> Vec<HashRequestPlan> {
    let bpp = u64::from(piece_len / taiji_store::merkle::BLOCK_SIZE);
    let pieces = file_len.div_ceil(u64::from(piece_len));
    if pieces == 0 {
        return Vec::new();
    }
    if pieces == 1 && bpp == 1 {
        // Single-block file: leaf hash == pieces root; no fetch needed
        // (see module docs).
        return Vec::new();
    }
    let mut plans = Vec::new();
    let mut start = 0u64; // piece number
    let mut remaining = pieces;
    while remaining > 0 {
        // Largest power-of-two unit in piece space (<= remaining);
        // len = unit x bpp <= 512 (SHOULD).
        let mut unit = if remaining.is_power_of_two() {
            remaining
        } else {
            remaining.next_power_of_two() >> 1
        };
        let max_unit = (512u64 / bpp).max(1);
        unit = unit.min(max_unit).max(1);
        let mut len = unit * bpp;
        // bpp = 1 odd last piece: unit = 1 gives len = 1, violating MUST
        // (>= 2). Widen to len = 2 covering [start, start+2) (includes the
        // out-of-domain zero-padded slot; the response is trimmed by
        // admit_hashes to the admission domain; the even start satisfies
        // the multiple-of rule).
        if len == 1 {
            len = 2;
        }
        debug_assert!(len.is_power_of_two() && len >= 2);
        debug_assert_eq!(
            (start * bpp) % len,
            0,
            "binary decomposition keeps index (= start x bpp) a multiple of len"
        );
        plans.push(HashRequestPlan {
            index: u32::try_from(start * bpp).unwrap_or(u32::MAX),
            length: u32::try_from(len).unwrap_or(u32::MAX),
        });
        start += unit;
        remaining = remaining.saturating_sub(unit);
    }
    plans
}

// ---------------------------------------------------------------------------
// Piece-layer whole-file fetch (hash recovery).
// ---------------------------------------------------------------------------
//
// # Rules
//
// - Request shape: base = the piece layer ([`piece_layer_level`], same
// formula as `hash_source::MetaHashSource::piece_layer_level`), covering
// all piece root hashes of the file, [0, ceil(len/piece_len)); one-shot
// coverage (a single layer collected in full), not leaf-to-root
// climbing (the HashPool's expected root only accepts the piece layer —
// pulling leaf layers first could not unblock the download face).
// proof = 0: the trust anchor is that the whole-file layer recomputes
// to the per-file pieces root inside info; a single-block proof chain
// has no downstream consumer (face assembly must wait for the whole
// layer). The canonical reply count = length
// (peer_wire::hashes_count_for).
// - Chunking (BEP52 hash request field constraints): <= 512 hashes per
// request (SHOULD; libtorrent uses 512-piece buckets, hash_picker.cpp),
// power-of-two decomposition, index a multiple of length (MUST,
// enforced by the peer_wire codec); the last segment may include
// zero-padded slots (the BEP52 piece layer completed to a zero-leaf
// tree root = [`taiji_store::merkle::empty_piece_root`]; the responder
// side already accepts out-of-domain slot requests), trimmed on
// delivery by `ceil(len/piece_len)` (same trimming semantics as
// [`admit_hashes`]).
// - Single-piece files (pieces <= 1) never trigger recovery: BEP52 — a
// file <= piece size has no piece layers entry; the trust anchor is the
// pieces root itself.
// - Staging and delivery ("transfer by block, isolate by block, admit per
// whole file"): replies are staged into per-plan block slots (idempotent
// under reordering / re-sends / extra hashes); this face performs no
// admission — once all blocks arrive it delivers a
// [`RecoveredPieceLayer`] for one-shot `validate_piece_layer` (count +
// root convergence). One bad block = the whole file is not admitted
// (the decision belongs to the delivery side; this face has neither
// criteria nor authority to judge).
//
// # Relation to lazy fetch ([`plan_base_layer_fetch`])
//
// Same [`HashRequestPlan`] encoding (codec unchanged); only the unit and
// base differ: lazy fetch's unit = leaf (len = unit x bpp, base always 0);
// recovery's unit = piece (len = unit, base = the piece layer). The
// leaf/piece pair is exactly the two layers a BEP52 responder needs to
// support.

/// Maximum hashes per recovery request (BEP52 "SHOULD NOT > 512";
/// matches libtorrent's 512-piece buckets, hash_picker.cpp).
pub const PIECE_LAYER_FETCH_MAX: u32 = 512;

/// The base number of the piece layer (the layer where each hash covers
/// piece_len bytes; base 0 = the 16 KiB leaf layer). Same formula as the
/// hash_source responder's `piece_layer_level` — requester and responder
/// must number the same layer identically.
pub fn piece_layer_level(piece_len: u32) -> u32 {
    piece_len.trailing_zeros() - taiji_store::merkle::BLOCK_SIZE.trailing_zeros()
}

/// Piece-layer whole-file fetch plan (one-shot coverage).
///
/// Decomposes by **pieces** into powers of two (high to low), each segment
/// len <= [`PIECE_LAYER_FETCH_MAX`] and starting at a segment boundary, so
/// index (= starting piece number) is a multiple of len (BEP52 MUST,
/// codec-enforced). An odd last piece (unit = 1) widens to len = 2
/// covering [P-1, P+1): slot P is the piece layer's zero-padded slot
/// (empty piece root), the even start satisfies the multiple-of rule, and
/// delivery trims by piece count.
///
/// An empty plan = no network fetch (pieces <= 1: a single-piece file has
/// no piece layers entry; recovery never triggers — BEP52).
pub fn plan_piece_layer_fetch(file_len: u64, piece_len: u32) -> Vec<HashRequestPlan> {
    if piece_len == 0 {
        // Defensive: invalid piece_len (already rejected at parse); no
        // plan.
        return Vec::new();
    }
    let pieces = file_len.div_ceil(u64::from(piece_len));
    if pieces <= 1 {
        return Vec::new();
    }
    let mut plans = Vec::new();
    let mut start = 0u64; // piece number (= piece-layer hash index)
    let mut remaining = pieces;
    while remaining > 0 {
        // Largest power-of-two unit in piece space (<= remaining, <= 512
        // SHOULD).
        let mut unit = if remaining.is_power_of_two() {
            remaining
        } else {
            remaining.next_power_of_two() >> 1
        };
        unit = unit.min(u64::from(PIECE_LAYER_FETCH_MAX)).max(1);
        let mut len = unit;
        // Odd last piece: len=1 violates MUST (>= 2); widen to 2 to cover
        // the zero-padded slot (see fn docs; the even start satisfies the
        // multiple-of rule).
        if len == 1 {
            len = 2;
        }
        debug_assert!(len.is_power_of_two() && (2..=512).contains(&len));
        debug_assert_eq!(
            start % len,
            0,
            "binary decomposition keeps index a multiple of len"
        );
        plans.push(HashRequestPlan {
            index: u32::try_from(start).unwrap_or(u32::MAX),
            length: u32::try_from(len).unwrap_or(u32::MAX),
        });
        start += unit;
        remaining = remaining.saturating_sub(unit);
    }
    plans
}

/// Delivery seam for a whole-file piece layer once fully collected: bytes
/// complete (exactly `ceil(file_len/piece_len)` entries, trailing
/// zero-padded slots trimmed) plus the associated file root. **Trust not
/// yet established** — admission (count + root convergence via
/// `merkle::validate_piece_layer` + insert into the HashTreeCache)
/// happens on the receiving side; the receiver must verify before caching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPieceLayer {
    /// This file's pieces root (inside the info dict, protected by the
    /// infohash — the trust anchor).
    pub root: [u8; 32],
    /// File length (input to the entry-count criterion).
    pub file_len: u64,
    /// Piece length (input to the level criterion).
    pub piece_len: u32,
    /// Complete piece layer hashes (entry count =
    /// ceil(file_len/piece_len)).
    pub layer: Vec<[u8; 32]>,
}

/// Result of handling a reply for a staging slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageOutcome {
    /// Staged (`complete` = whole file collected; the deliverable can be
    /// built).
    Staged { complete: bool },
    /// Re-sent / multi-source reply for the same block: slot already full;
    /// first arrival wins (idempotent drop).
    Duplicate,
}

/// Staging rejection forms (all peer/caller anomalies; nothing is staged —
/// the caller runs the failure-retry path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StageError {
    /// No such planned block (out of range).
    UnknownBlock { block: usize },
    /// Reply hash count too small (the codec already enforces the
    /// canonical count — defensive).
    ShortReply { want: u32, got: usize },
}

/// Per-file piece-layer block staging bookkeeping (the transfer side of
/// "transfer by block, isolate by block, admit per whole file").
///
/// # Boundedness
///
/// Slot count = [`Self::plans`] length <= ceil(pieces/512)+1; each slot
/// <= 512 x 32B. Whole-file staging upper bound is about (pieces+1) x 32B
/// (the layer itself plus at most one zero-padded slot), asserted by
/// [`assert_staging_bounds`]. No timers, no tasks — a pure data structure;
/// timeouts/retries belong to the caller (engine bookkeeping).
#[derive(Debug)]
pub struct PieceLayerStaging {
    root: [u8; 32],
    file_len: u64,
    piece_len: u32,
    plans: Vec<HashRequestPlan>,
    /// Reply slot per planned block (None = not received).
    slots: Vec<Option<Vec<[u8; 32]>>>,
    staged: usize,
    delivered: bool,
}

impl PieceLayerStaging {
    /// Builds from file geometry (plans derived by
    /// [`plan_piece_layer_fetch`]).
    pub fn new(root: [u8; 32], file_len: u64, piece_len: u32) -> PieceLayerStaging {
        let plans = plan_piece_layer_fetch(file_len, piece_len);
        PieceLayerStaging {
            root,
            file_len,
            piece_len,
            slots: vec![None; plans.len()],
            plans,
            staged: 0,
            delivered: false,
        }
    }

    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    pub fn piece_len(&self) -> u32 {
        self.piece_len
    }

    pub fn plans(&self) -> &[HashRequestPlan] {
        &self.plans
    }

    /// Planned block count (= slot count).
    pub fn block_count(&self) -> usize {
        self.plans.len()
    }

    /// File piece count (delivery entry-count criterion).
    pub fn pieces(&self) -> u64 {
        self.file_len.div_ceil(u64::from(self.piece_len))
    }

    /// First unfilled block (sequential dispatch cursor; None = all
    /// filled).
    pub fn next_block(&self) -> Option<usize> {
        self.slots.iter().position(Option::is_none)
    }

    /// Is the block staged?
    pub fn slot_filled(&self, block: usize) -> bool {
        self.slots.get(block).is_some_and(Option::is_some)
    }

    /// Stages a reply; idempotent for out-of-order (per block-slot
    /// indexing, any order), re-sends (first arrival wins), and extra
    /// hashes (trimmed to the requested length, excess dropped). A short
    /// count = [`StageError::ShortReply`] (not staged; the canonical count
    /// is codec-enforced — this is defensive).
    ///
    /// **No admission here**: staged is not cached; bad hashes have no
    /// criteria at this point — judgment happens once per whole file at
    /// delivery.
    pub fn stage(&mut self, block: usize, hashes: &[[u8; 32]]) -> Result<StageOutcome, StageError> {
        let Some(plan) = self.plans.get(block) else {
            return Err(StageError::UnknownBlock { block });
        };
        if self.slots[block].is_some() {
            return Ok(StageOutcome::Duplicate);
        }
        if (hashes.len() as u64) < u64::from(plan.length) {
            return Err(StageError::ShortReply {
                want: plan.length,
                got: hashes.len(),
            });
        }
        self.slots[block] = Some(hashes[..plan.length as usize].to_vec());
        self.staged += 1;
        Ok(StageOutcome::Staged {
            complete: self.staged == self.slots.len(),
        })
    }

    /// Delivery payload (all blocks collected and not yet delivered):
    /// concatenates the whole layer after trimming trailing zero-padded
    /// slots by piece count. Does not consume staging (can be rebuilt
    /// while the delivery channel is full — idempotent); call
    /// [`Self::mark_delivered`] after confirmed delivery.
    pub fn build_deliverable(&self) -> Option<RecoveredPieceLayer> {
        if self.staged != self.slots.len() || self.delivered {
            return None;
        }
        let pieces = self.pieces();
        let mut layer = Vec::with_capacity(pieces as usize);
        for (i, slot) in self.slots.iter().enumerate() {
            let hashes = slot.as_ref()?;
            let start = u64::from(self.plans[i].index);
            for (k, hash) in hashes.iter().enumerate() {
                if start + k as u64 >= pieces {
                    break; // trailing zero-padded slot: trim by piece count
                }
                layer.push(*hash);
            }
        }
        debug_assert_eq!(
            layer.len() as u64,
            pieces,
            "coverage invariant: slot union is exactly [0, pieces)"
        );
        Some(RecoveredPieceLayer {
            root: self.root,
            file_len: self.file_len,
            piece_len: self.piece_len,
            layer,
        })
    }

    /// Delivery confirmation (call after the receiver's try_send succeeds;
    /// no further deliverables are produced).
    pub fn mark_delivered(&mut self) {
        self.delivered = true;
    }
}

/// Staging-face bound assertion (shared by tests and CI): slot blocks
/// <= `pieces/512 + 10` (512-capped blocks plus at most 9 one-bits from
/// binary decomposition plus the widened odd last segment); with all slots
/// full, total staged hashes <= pieces+1 (coverage invariant — at most one
/// zero-padded slot in the last segment; this is the tight staging-memory
/// bound); delivery entries exactly = pieces.
pub fn assert_staging_bounds(staging: &PieceLayerStaging) {
    let pieces = staging.pieces();
    let max_blocks = (pieces / u64::from(PIECE_LAYER_FETCH_MAX)) as usize + 10;
    assert!(
        staging.block_count() <= max_blocks,
        "slot bound: {} > {max_blocks}",
        staging.block_count()
    );
    let covered: u64 = staging.plans().iter().map(|p| u64::from(p.length)).sum();
    assert!(
        covered >= pieces && covered <= pieces + 1,
        "coverage in [pieces, pieces+1]: {covered} vs {pieces}"
    );
}

/// Lazy-fetch reply handling result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchError {
    /// Peer hash reject (a legal answer; retry/degrade policy belongs to
    /// the caller).
    Rejected,
    /// Reply is not a hashes form (disconnect/timeout are expressed via
    /// the caller's await result).
    Closed,
    /// Reply failed verification: a bad segment rejects the whole segment
    /// from the cache (details logged via tracing debug).
    BadSegment,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Rejected => f.write_str("hash request rejected by peer"),
            FetchError::Closed => f.write_str("hash fetch closed before reply"),
            FetchError::BadSegment => {
                f.write_str("lazy layer segment rejected (piece-root anchor mismatch)")
            }
        }
    }
}

/// Reply -> verify up to the piece root -> cache (the only lazy-fetch
/// admission path).
///
/// `total_leaves` = the file's lazy-fetch admission domain leaf count
/// (pieces x bpp); out-of-domain leaves (zero-padded slots or peer
/// extras) are trimmed and dropped; in-domain leaves must pass the
/// per-piece root anchor check as a whole before entering the cache.
pub fn admit_hashes(
    trees: &mut HashTreeCache,
    root: &[u8; 32],
    plan: HashRequestPlan,
    total_leaves: u64,
    fetch: HashFetch,
) -> Result<(), FetchError> {
    let HashFetch::Hashes(hashes) = fetch else {
        return Err(FetchError::Rejected);
    };
    // proof=0 means the canonical count is exactly length
    // (peer_wire::hashes_count_for); the codec enforces count agreement —
    // this trim is defensive.
    let base = &hashes[..hashes.len().min(plan.length as usize)];
    let start = u64::from(plan.index);
    let end = (start + plan.length as u64).min(total_leaves);
    if start >= end {
        return Err(FetchError::BadSegment);
    }
    let seg: Vec<[u8; 32]> = base[..((end - start) as usize).min(base.len())].to_vec();
    if seg.len() as u64 != end - start {
        return Err(FetchError::BadSegment);
    }
    trees
        .verify_and_put_layer(root, 0, start, seg)
        .map_err(|e| {
            tracing::debug!(target: "taiji::core::hash_fetch", %e, index = plan.index,
            length = plan.length, "lazy layer segment rejected (bad segment, none admitted)");
            FetchError::BadSegment
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_store::merkle;

    fn leaf_layer(content: &[u8]) -> Vec<[u8; 32]> {
        content
            .chunks(merkle::BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect()
    }

    /// Plan constraint assertions: length a power of two >= 2; index a
    /// multiple of length; length <= 512 (except the bpp > 512 SHOULD
    /// case); segments cover exactly [0, P).
    fn assert_plan_invariants(plans: &[HashRequestPlan], pieces: u64, bpp: u64, leaf_domain: u64) {
        let mut covered = 0u64;
        for p in plans {
            assert!(p.length >= 2 && p.length.is_power_of_two(), "MUST: {p:?}");
            if bpp <= 512 {
                assert!(p.length as u64 <= 512, "SHOULD ≤512（bpp={}）: {p:?}", bpp);
            }
            assert_eq!(
                p.index % p.length,
                0,
                "MUST: index a multiple of length: {p:?}"
            );
            // Piece alignment (admission-domain constraint).
            assert_eq!(p.index as u64 % bpp, 0, "start piece-aligned: {p:?}");
            covered += p.length as u64;
        }
        // Coverage (the last segment may include an out-of-domain
        // zero-padded slot — after trimming, admitted <= leaf_domain).
        assert!(
            covered >= pieces * bpp,
            "covers all pieces: {covered} vs {}",
            pieces * bpp
        );
        assert!(
            plans.iter().map(|p| p.index as u64).min().unwrap_or(0) == 0,
            "coverage starts at 0"
        );
        assert!(
            covered < leaf_domain + 2 * bpp,
            "at most one out-of-domain slot"
        );
    }

    /// Common shape: 16 KiB pieces (bpp = 1).
    #[test]
    fn plan_16k_pieces() {
        // 5 pieces -> 4 + 2 (last segment over by 1 slot, trimmed):
        // 4+2=6 >= 5.
        let plans = plan_base_layer_fetch(5 * 16384, 16384);
        assert_eq!(
            plans,
            vec![
                HashRequestPlan {
                    index: 0,
                    length: 4
                },
                HashRequestPlan {
                    index: 4,
                    length: 2
                },
            ]
        );
        assert_plan_invariants(&plans, 5, 1, 5);
        // 4 pieces -> a single segment of 4.
        let plans = plan_base_layer_fetch(4 * 16384, 16384);
        assert_eq!(
            plans,
            vec![HashRequestPlan {
                index: 0,
                length: 4
            }]
        );
        // Large file: 600 pieces -> 512 + 64 + 16 + 8 (all <=512 and
        // aligned).
        let plans = plan_base_layer_fetch(600 * 16384, 16384);
        assert_eq!(plans.len(), 4);
        assert_eq!(
            plans[0],
            HashRequestPlan {
                index: 0,
                length: 512
            }
        );
        assert_eq!(
            plans[1],
            HashRequestPlan {
                index: 512,
                length: 64
            }
        );
        assert_eq!(
            plans[2],
            HashRequestPlan {
                index: 576,
                length: 16
            }
        );
        assert_eq!(
            plans[3],
            HashRequestPlan {
                index: 592,
                length: 8
            }
        );
        assert_plan_invariants(&plans, 600, 1, 600);
        // Single-block file (<=16KiB) -> empty plan (leaf == root, no
        // fetch needed).
        assert!(plan_base_layer_fetch(16384, 16384).is_empty());
        assert!(plan_base_layer_fetch(90, 16384).is_empty());
    }

    /// 64 KiB pieces (bpp = 4): binary decomposition of 3 pieces = 2+1:
    /// unit 2 -> len 8; unit 1 -> len 4. All <= 512.
    #[test]
    fn plan_64k_pieces() {
        let plans = plan_base_layer_fetch(3 * 65536, 65536);
        assert_eq!(
            plans,
            vec![
                HashRequestPlan {
                    index: 0,
                    length: 8
                },
                HashRequestPlan {
                    index: 8,
                    length: 4
                },
            ]
        );
        assert_plan_invariants(&plans, 3, 4, 12);
        // Two pieces: a single segment of 8 (this plan shape is the
        // request form injected by the end-to-end test fixture).
        let plans = plan_base_layer_fetch(2 * 65536, 65536);
        assert_eq!(
            plans,
            vec![HashRequestPlan {
                index: 0,
                length: 8
            }]
        );
    }

    /// End-to-end simulation: plan -> admit all replies -> the leaf layer
    /// is complete and block-verifiable (16 KiB pieces, 5 pieces with the
    /// odd-last-segment trimming path).
    #[test]
    fn plan_admit_loop_covers_file() {
        const PIECE: u32 = 16384;
        let content: Vec<u8> = (0..5 * PIECE as usize).map(|i| (i % 249) as u8).collect();
        let leaves = leaf_layer(&content);
        let pieces: Vec<[u8; 32]> = leaves.clone(); // bpp = 1
        let root = merkle::file_root(&leaves, PIECE).unwrap_or_else(|e| panic!("{e}"));
        let mut trees = HashTreeCache::new(PIECE);
        trees.add_file(root, pieces);
        for plan in plan_base_layer_fetch(content.len() as u64, PIECE) {
            // Simulated responder: true in-domain leaves + out-of-domain
            // zero-padded slot (leaf 5 of the last segment [4,6)).
            let mut resp: Vec<[u8; 32]> = Vec::new();
            for i in plan.index..plan.index + plan.length {
                resp.push(leaves.get(i as usize).copied().unwrap_or([0u8; 32]));
            }
            admit_hashes(
                &mut trees,
                &root,
                plan,
                5, // total_leaves = 5 pieces x bpp 1
                HashFetch::Hashes(resp),
            )
            .unwrap_or_else(|e| panic!("{e:?}"));
        }
        // Whole-file block-level verification ready.
        for (i, block) in content.chunks(16384).enumerate() {
            assert!(
                trees
                    .verify_block(&root, i as u64, block)
                    .unwrap_or_else(|e| panic!("{e}")),
                "block {i}"
            );
        }
        assert_eq!(
            trees.leaf_layer_len(&root),
            Some(5),
            "exactly 5 leaves after trimming"
        );
    }

    /// Bad-segment defense: any piece whose recomputed root mismatches ->
    /// the whole segment is refused.
    #[test]
    fn bad_segment_rejected_whole() {
        const PIECE: u32 = 16384;
        let content: Vec<u8> = (0..4 * PIECE as usize).map(|i| (i % 251) as u8).collect();
        let leaves = leaf_layer(&content);
        let root = merkle::file_root(&leaves, PIECE).unwrap_or_else(|e| panic!("{e}"));
        let mut trees = HashTreeCache::new(PIECE);
        trees.add_file(root, leaves.clone());
        let plan = HashRequestPlan {
            index: 0,
            length: 4,
        };
        let mut bad = leaves.clone();
        bad[1] = [0xFF; 32]; // the single leaf of piece 1 swapped -> its root mismatches
        let err = admit_hashes(&mut trees, &root, plan, 4, HashFetch::Hashes(bad));
        assert!(matches!(err, Err(FetchError::BadSegment)), "got {err:?}");
        assert_eq!(
            trees.leaf_layer_len(&root),
            None,
            "bad segment admitted nothing"
        );
        // A reject answer -> Rejected (retry/degrade decisions belong to
        // the caller).
        let err = admit_hashes(&mut trees, &root, plan, 4, HashFetch::Rejected);
        assert_eq!(err, Err(FetchError::Rejected));
    }

    // -----------------------------------------------------------------------
    // hash recovery: piece-layer whole-file fetch (one-shot coverage).
    // -----------------------------------------------------------------------

    /// Plan constraint assertions (recovery version; same style as
    /// [`assert_plan_invariants`]): length a power of two, >= 2, <= 512;
    /// index a multiple of length (MUST); contiguous coverage from 0;
    /// total coverage in [pieces, pieces+1] (at most one zero-padded slot
    /// in the last segment).
    fn assert_piece_plan_invariants(plans: &[HashRequestPlan], pieces: u64) {
        let mut covered = 0u64;
        let mut expect_start = 0u64;
        for p in plans {
            assert!(p.length >= 2 && p.length.is_power_of_two(), "MUST: {p:?}");
            assert!(
                p.length as u64 <= u64::from(PIECE_LAYER_FETCH_MAX),
                "SHOULD ≤512: {p:?}"
            );
            assert_eq!(
                p.index % p.length,
                0,
                "MUST: index a multiple of length: {p:?}"
            );
            assert_eq!(p.index as u64, expect_start, "contiguous coverage: {p:?}");
            covered += p.length as u64;
            // The len=1->2 last-segment widening does not advance the unit
            // (covers 2 slots but the file only advances 1 piece).
            expect_start += (p.length as u64).min(pieces - expect_start);
        }
        assert!(
            covered >= pieces,
            "covers all pieces: {covered} vs {pieces}"
        );
        assert!(
            covered <= pieces + 1,
            "at most one zero-padded out-of-domain slot: {covered} vs {pieces}"
        );
        let max_blocks = (pieces / u64::from(PIECE_LAYER_FETCH_MAX)) as usize + 10;
        assert!(
            plans.len() <= max_blocks,
            "block-count bound: {} > {max_blocks}",
            plans.len()
        );
    }

    /// Planner vectors: 3 pieces / 513 pieces / trailing-zero-slot shapes;
    /// one-shot coverage.
    #[test]
    fn plan_piece_layer_fetch_vectors() {
        use taiji_store::merkle::BLOCK_SIZE;
        let piece = u64::from(BLOCK_SIZE);
        // 3 pieces: 2 + 2 (last segment over by one zero-padded slot).
        let plans = plan_piece_layer_fetch(3 * piece, BLOCK_SIZE);
        assert_eq!(
            plans,
            vec![
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
        assert_piece_plan_invariants(&plans, 3);
        // 513 pieces: 512 + 2 (trailing zero slot).
        let plans = plan_piece_layer_fetch(513 * piece, BLOCK_SIZE);
        assert_eq!(
            plans,
            vec![
                HashRequestPlan {
                    index: 0,
                    length: 512
                },
                HashRequestPlan {
                    index: 512,
                    length: 2
                },
            ]
        );
        assert_piece_plan_invariants(&plans, 513);
        // 600 pieces: 512 + 64 + 16 + 8 (exact coverage, no slots).
        let plans = plan_piece_layer_fetch(600 * piece, BLOCK_SIZE);
        assert_eq!(plans.len(), 4);
        assert_eq!(
            plans[0],
            HashRequestPlan {
                index: 0,
                length: 512
            }
        );
        assert_eq!(
            plans[1],
            HashRequestPlan {
                index: 512,
                length: 64
            }
        );
        assert_eq!(
            plans[2],
            HashRequestPlan {
                index: 576,
                length: 16
            }
        );
        assert_eq!(
            plans[3],
            HashRequestPlan {
                index: 592,
                length: 8
            }
        );
        assert_piece_plan_invariants(&plans, 600);
        // 2 pieces: a single segment (minimal one-shot coverage).
        let plans = plan_piece_layer_fetch(2 * piece, BLOCK_SIZE);
        assert_eq!(
            plans,
            vec![HashRequestPlan {
                index: 0,
                length: 2
            }]
        );
        // 1024 pieces: exactly two segments of 512 (no slots).
        let plans = plan_piece_layer_fetch(1024 * piece, BLOCK_SIZE);
        assert_eq!(
            plans,
            vec![
                HashRequestPlan {
                    index: 0,
                    length: 512
                },
                HashRequestPlan {
                    index: 512,
                    length: 512
                },
            ]
        );
        // Single-piece file: empty plan (no piece layers entry; recovery
        // never triggers).
        assert!(plan_piece_layer_fetch(piece, BLOCK_SIZE).is_empty());
        assert!(plan_piece_layer_fetch(90, BLOCK_SIZE).is_empty());
        assert!(plan_piece_layer_fetch(0, BLOCK_SIZE).is_empty());
        // The piece layer level is piece-count independent: the 5-piece
        // shape with 64KiB pieces is isomorphic to 16KiB pieces.
        let plans = plan_piece_layer_fetch(5 * 65536, 65536);
        assert_eq!(plans.len(), 2);
        assert_piece_plan_invariants(&plans, 5);
    }

    // MUST invariant proptest: for any legal (piece_len, file_len)
    // combination all plan constraints pass (same style as the progress.rs
    // proptest).
    proptest::proptest! {
        #[test]
        fn plan_piece_layer_fetch_must_invariants_prop(
            piece_shift in 14u32..=24u32,
            len in 1u64..=(64 * 1024 * 1024),
        ) {
            let piece_len = 1u32 << piece_shift;
            let plans = plan_piece_layer_fetch(len, piece_len);
            let pieces = len.div_ceil(u64::from(piece_len));
            if pieces <= 1 {
                assert!(plans.is_empty(), "single-piece file yields no plans: {plans:?}");
            } else {
                assert_piece_plan_invariants(&plans, pieces);
                assert_staging_bounds(&PieceLayerStaging::new([0u8; 32], len, piece_len));
            }
        }
    }

    /// Staging-face semantics, table-driven: out-of-order staging /
    /// re-send idempotence (first arrival wins) / extra-hash trimming /
    /// short-count refusal / unknown-block refusal; once complete, the
    /// deliverable = the whole layer with exactly pieces entries.
    #[test]
    fn piece_layer_staging_semantics() {
        use taiji_store::merkle::BLOCK_SIZE;
        let piece = u64::from(BLOCK_SIZE);
        // 3-piece file: true layer = [h0, h1, h2]; the last planned
        // segment [2,4) includes a zero-padded slot.
        let h: Vec<[u8; 32]> = (0..3u64).map(|i| [i as u8; 32]).collect();
        let mut st = PieceLayerStaging::new([9u8; 32], 3 * piece, BLOCK_SIZE);
        assert_eq!(st.block_count(), 2);
        assert_staging_bounds(&st);
        // Unknown block refused.
        assert_eq!(
            st.stage(2, &h[..2]),
            Err(StageError::UnknownBlock { block: 2 })
        );
        // Out of order: block 1 first (contains an out-of-domain slot
        // value — extras trimmed later).
        assert_eq!(
            st.stage(1, &[h[2], [0xFFu8; 32]]),
            Ok(StageOutcome::Staged { complete: false })
        );
        assert!(st.slot_filled(1));
        assert_eq!(st.next_block(), Some(0));
        // Re-send same block: first arrival wins (idempotent).
        assert_eq!(st.stage(1, &h[2..]), Ok(StageOutcome::Duplicate));
        // Short count refused (nothing staged).
        assert_eq!(
            st.stage(0, &h[..1]),
            Err(StageError::ShortReply { want: 2, got: 1 })
        );
        // Block 0 received (1 extra -> trimmed to length=2).
        assert_eq!(
            st.stage(0, &[h[0], h[1], [0xEEu8; 32]]),
            Ok(StageOutcome::Staged { complete: true })
        );
        assert_eq!(st.next_block(), None, "whole file collected");
        // Delivery: zero-padded slot trimmed, exactly 3 entries.
        let rec = st
            .build_deliverable()
            .unwrap_or_else(|| panic!("incomplete"));
        assert_eq!(rec.root, [9u8; 32]);
        assert_eq!(
            rec.layer, h,
            "out-of-domain slots and extra hashes excluded from the payload"
        );
        assert_eq!(
            rec,
            RecoveredPieceLayer {
                root: [9u8; 32],
                file_len: 3 * piece,
                piece_len: BLOCK_SIZE,
                layer: h,
            }
        );
        // After confirmation no further deliverables (idempotent terminal
        // state).
        st.mark_delivered();
        assert!(st.build_deliverable().is_none());
    }

    /// Staging-face bounds (bounded assertion): slot block count and total
    /// staging upper bound for large files; delivery entries always =
    /// ceil(file_len/piece_len).
    #[test]
    fn piece_layer_staging_bounds_scale() {
        use taiji_store::merkle::BLOCK_SIZE;
        let piece = u64::from(BLOCK_SIZE);
        for pieces in [2u64, 3, 511, 512, 513, 1024, 4097, 100_000] {
            let mut st = PieceLayerStaging::new([0u8; 32], pieces * piece, BLOCK_SIZE);
            assert_staging_bounds(&st);
            // Simulates full collection: delivery entries exactly pieces
            // (trailing zero slot trimmed).
            let plans = st.plans().to_vec();
            for (i, plan) in plans.iter().enumerate() {
                let filler: Vec<[u8; 32]> = (0..plan.length)
                    .map(|k| {
                        let mut h = [0u8; 32];
                        h[0] = i as u8;
                        h[1] = k as u8;
                        h
                    })
                    .collect();
                let _ = st.stage(i, &filler).unwrap_or_else(|e| panic!("{e:?}"));
            }
            let rec = st
                .build_deliverable()
                .unwrap_or_else(|| panic!("incomplete"));
            assert_eq!(rec.layer.len() as u64, pieces, "delivered entries = pieces");
        }
    }
}

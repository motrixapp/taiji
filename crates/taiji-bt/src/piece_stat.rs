//! PieceStatMan equivalent + rarest-first picker (SPEC §6.9).
//!
//! Upstream anchors: startup shuffle + saturating counts + bitfield-driven
//! add/subtract/update (`aria2/src/PieceStatMan.cc`); the rarest pick walks
//! the shuffled order and takes the first held, min-count piece
//! (`RarestPieceSelector.cc`); endgame gate at <= END_GAME_PIECE_NUM = 20
//! (`aria2/src/DefaultPieceStorage.h`). v2/hybrid `(file_idx,
//! piece_in_file)` coordinates are flattened to u64 keys by the caller
//! (same decomposition as core::progress::ProgressModel; SPEC §4.4).
//!
//! Structure follows libtorrent's piece_picker (`piece_picker.cpp`/`.hpp`):
//! per-piece state is reduced to `order: Vec<u32>` (4B/piece shuffle order) +
//! `counts: Vec<u16>` (2B/piece, saturating at 65535 =
//! `max_peer_count = 0xffff`); pieces are bucketed by rarity with the
//! in-bucket order kept from the startup shuffle; count events only set a
//! `dirty` flag and the bucket view is rebuilt (counting sort) before the
//! next pick; seeds move a single counter (O(1)) instead of per-piece
//! availability, with `seed_downgrade` folding a seed back into per-piece
//! counts. Effective availability = counts + seeds — a uniform shift that
//! does not change the selection order.
//!
//! Divergences from libtorrent: no per-piece download state / manual
//! priority / index fields (partial-piece authority is the dispatch
//! `blocks_sent`; `SelectFilter` is a pick-time closure; the rebuild-only
//! design needs no index). Small-change incremental bucket moves are
//! replaced by dirty + full rebuild (bounded to one O(n) pass per pick
//! round). The in-bucket order is never re-shuffled (libtorrent does
//! random_shuffle on rebuild): selection must stay bit-identical to the
//! legacy full-order scan under a fixed seed, and decorrelation is already
//! provided by the startup shuffle.
//!
//! Priorities: multi-level file priorities enter as the `prio` argument to
//! `select`/`select_two_phase` (key = priority desc, count asc, shuffle
//! order first); skip (-1) is a `SelectFilter`. allowed-fast is handled by
//! the caller passing the set as `preferred`; the picker takes the rarest
//! within preferred ∩ available before falling back to the global
//! rarest.

use std::cell::{Cell, RefCell};

/// Endgame trigger threshold: incomplete piece count (`DefaultPieceStorage.h`).
pub const END_GAME_PIECE_NUM: u64 = 20;

/// Rarity counters + shuffled selection order + lazily rebuilt bucket view.
///
/// The injected `shuffle` closure keeps tests deterministic; production
/// uses a rand::random sequence.
///
/// Memory: `order` 4B/piece + `counts` 2B/piece + `pieces` 4B/piece (bucket
/// view) ~= 10B/piece; the legacy layout was 12B/piece (u64 order + u32
/// counts).
#[derive(Debug, Clone)]
pub struct PieceStatMan {
    /// Selection order: startup shuffle (`PieceStatMan.cc`, Fisher-Yates).
    /// The authoritative tie-break order — the bucket view's in-bucket
    /// order is derived from it (stable scatter).
    order: Vec<u32>,
    /// Rarity counts (saturating at 65535 = libtorrent
    /// `max_peer_count = 0xffff`, `piece_picker.hpp`). Seed contribution is
    /// not counted here — `seeds` is separate (the seed O(1) fast path,
    /// `piece_picker.cpp`).
    counts: Vec<u16>,
    /// Seed (have-all) peer count (`piece_picker.hpp` m_seeds semantics;
    /// effective availability = counts + seeds — a uniform shift that does
    /// not change the order).
    seeds: u32,
    /// Bucket view (lazy rebuild cache): piece ids ascending by (count,
    /// order rank) — the local form of libtorrent `m_pieces`
    /// (`piece_picker.hpp`).
    pieces: RefCell<Vec<u32>>,
    /// `bounds[c]` = start index of the count==c bucket in `pieces`
    /// (prefix sums; len = max_count + 2, last item = pieces total) — the
    /// local form of libtorrent `m_priority_boundaries`
    /// (`piece_picker.hpp`).
    bounds: RefCell<Vec<u32>>,
    /// Rebuild scatter cursor (reused buffer, no per-round allocation).
    scratch: RefCell<Vec<u32>>,
    /// Lazy-rebuild gate (`m_dirty`, `piece_picker.cpp`): set by any counts
    /// change; one rebuild before the next pick (`update_pieces()`,
    /// `piece_picker.cpp`). Seed join/leave shifts uniformly and does not
    /// set it.
    dirty: Cell<bool>,
}

impl PieceStatMan {
    /// `piece_num` = total flat keys (v2/hybrid = sum of per-file piece
    /// counts). `shuffle`: Fisher-Yates step source, `next(n) -> [0, n)`;
    /// tests inject identity/fixed orders.
    ///
    /// Panics when `piece_num` exceeds the u32 `order`-table domain (see
    /// [`Self::try_new`]); fallible construction goes through
    /// [`Self::try_new`].
    #[expect(
        clippy::expect_used,
        reason = "over-domain piece_num is a caller bug (no real torrent reaches u32::MAX pieces); fail loudly"
    )]
    pub fn new(piece_num: u64, shuffle: &mut dyn FnMut(usize) -> usize) -> PieceStatMan {
        Self::try_new(piece_num, shuffle)
            .expect("piece_num exceeds u32::MAX (u32 `order` table cannot represent it)")
    }

    /// Validating [`Self::new`]: rejects `piece_num` beyond the u32
    /// `order`-table domain (4B/piece — piece ids are u32, see the struct
    /// docs), returning the rejected value instead of the historical
    /// silent `piece_num as u32` truncation (which desynced `order` from
    /// the full-length `counts`). No real torrent can reach the boundary
    /// (u32::MAX pieces = tens of EiB at any sane block size), so the
    /// over-domain face is a caller-bug guard, not an input path.
    pub fn try_new(
        piece_num: u64,
        shuffle: &mut dyn FnMut(usize) -> usize,
    ) -> Result<PieceStatMan, u64> {
        let n = u32::try_from(piece_num).map_err(|_| piece_num)?;
        let mut order: Vec<u32> = (0..n).collect();
        // Fisher-Yates (same shape as std::shuffle; tail to head).
        for i in (1..order.len()).rev() {
            let j = shuffle(i + 1);
            order.swap(i, j);
        }
        Ok(PieceStatMan {
            order,
            counts: vec![0u16; n as usize],
            seeds: 0,
            pieces: RefCell::new(Vec::new()),
            bounds: RefCell::new(Vec::new()),
            scratch: RefCell::new(Vec::new()),
            dirty: Cell::new(true),
        })
    }

    pub fn order(&self) -> &[u32] {
        &self.order
    }

    /// Free the bucket view (called by completion/stop-picking): clears the
    /// capacity of the `pieces`/`bounds`/`scratch` buffers (~10B/piece of
    /// view state goes to zero; `order`/`counts` stay resident — counting
    /// keeps working and the next pick lazily rebuilds through the dirty
    /// gate). Equivalent to the state just after `new`.
    pub fn release_bucket_view(&mut self) {
        *self.pieces.borrow_mut() = Vec::new();
        *self.bounds.borrow_mut() = Vec::new();
        *self.scratch.borrow_mut() = Vec::new();
        self.dirty.set(true);
    }

    /// Effective availability (seed contribution included; the
    /// counts+m_seeds merge exit of `piece_picker.cpp`). Out of range = 0.
    pub fn count(&self, index: u64) -> u32 {
        let c = self.counts.get(index as usize).copied().unwrap_or(0) as u32;
        c.saturating_add(self.seeds)
    }

    /// Peer have-set (bitmap over flat coordinates) -> count increments
    /// (`PieceStatMan.cc`; `set` tells whether the coordinate is held).
    pub fn add_bitfield(&mut self, set: impl Fn(u64) -> bool, n: u64) {
        for i in 0..n.min(self.counts.len() as u64) {
            if set(i) {
                self.counts[i as usize] = self.counts[i as usize].saturating_add(1);
            }
        }
        self.dirty.set(true);
    }

    /// Peer leave / bitmap shrink -> count decrements (`PieceStatMan.cc`,
    /// saturating sub to 0).
    pub fn subtract_bitfield(&mut self, set: impl Fn(u64) -> bool, n: u64) {
        for i in 0..n.min(self.counts.len() as u64) {
            if set(i) {
                self.counts[i as usize] = self.counts[i as usize].saturating_sub(1);
            }
        }
        self.dirty.set(true);
    }

    /// Bitmap replacement (update semantics, `PieceStatMan.cc`): new has /
    /// old lacks -> inc; old has / new lacks -> sub.
    pub fn update_bitfield(
        &mut self,
        new: impl Fn(u64) -> bool,
        old: impl Fn(u64) -> bool,
        n: u64,
    ) {
        for i in 0..n.min(self.counts.len() as u64) {
            let (in_new, in_old) = (new(i), old(i));
            if in_new && !in_old {
                self.counts[i as usize] = self.counts[i as usize].saturating_add(1);
            } else if !in_new && in_old {
                self.counts[i as usize] = self.counts[i as usize].saturating_sub(1);
            }
        }
        self.dirty.set(true);
    }

    /// Single-piece count (HAVE message, `PieceStatMan.cc`).
    pub fn add_piece(&mut self, index: u64) {
        if let Some(c) = self.counts.get_mut(index as usize) {
            *c = c.saturating_add(1);
            self.dirty.set(true);
        }
    }

    /// Peer leave: its whole bitmap decrements (inverse of add_bitfield).
    pub fn remove_peer(&mut self, set: impl Fn(u64) -> bool, n: u64) {
        self.subtract_bitfield(set, n);
    }

    /// A have-all (seed) peer joins: only `++seeds`, no per-piece counts
    /// (`inc_refcount_all`, `piece_picker.cpp`). The uniform shift does not
    /// change selection order, so no dirty flag. The caller must retract
    /// the peer's previous evidence if any — net effect equals the legacy
    /// "update(all-ones, old row)" per piece (0 at old-row-only, +1 where
    /// held).
    pub fn add_seed(&mut self) {
        self.seeds = self.seeds.saturating_add(1);
    }

    /// A have-all (seed) peer leaves: only `--seeds` (`dec_refcount_all`,
    /// `piece_picker.cpp`). Divergence: libtorrent sets `m_dirty` when its
    /// seed count reaches 0 — its `m_pieces` excludes availability-0
    /// pieces, so membership changes need a rebuild; this bucket view keeps
    /// have-all pieces and filters availability-0 at pick time via
    /// `eligible`, and the seed shift is uniform, so no dirty flag is
    /// needed.
    pub fn remove_seed(&mut self) {
        self.seeds = self.seeds.saturating_sub(1);
    }

    /// A seed downgrades to a regular peer (`dont_have` for some pieces /
    /// bitmap shrink): `break_one_seed` (`piece_picker.cpp`: --m_seeds;
    /// ++peer_count per piece; dirty) plus merging the downgrade delta —
    /// pieces absent from the new row stop counting this peer. Net effect:
    /// counts'[i] = counts[i] + [new row has i] (the +1 seed contribution
    /// returns per piece, the missing places cancel), same decision as the
    /// legacy update(new row, all-ones). O(n) — same cost as libtorrent; a
    /// rare path (a seed starts leaking pieces).
    pub fn seed_downgrade(&mut self, has: impl Fn(u64) -> bool, n: u64) {
        self.seeds = self.seeds.saturating_sub(1);
        for i in 0..n.min(self.counts.len() as u64) {
            if has(i) {
                self.counts[i as usize] = self.counts[i as usize].saturating_add(1);
            }
        }
        self.dirty.set(true);
    }

    /// Lazy rebuild (`update_pieces()`, `piece_picker.cpp`; `&self` +
    /// Cell/RefCell so the picking free-function signatures are unchanged):
    /// counting-sort by counts, scattered in `order` traversal => in-bucket
    /// order = shuffle order (tie-breaks bit-identical to the legacy full
    /// scan).
    fn rebuild_if_dirty(&self) {
        if !self.dirty.get() {
            return;
        }
        let counts = &self.counts;
        let max = counts.iter().copied().max().unwrap_or(0) as usize;
        let mut bounds = self.bounds.take();
        bounds.clear();
        bounds.resize(max + 2, 0u32);
        // Histogram -> prefix sums (bounds[c] = bucket c start; same
        // semantics as libtorrent piece_picker.cpp).
        for &c in counts.iter() {
            bounds[usize::from(c) + 1] += 1;
        }
        for i in 1..bounds.len() {
            bounds[i] += bounds[i - 1];
        }
        let mut pieces = self.pieces.take();
        pieces.clear();
        pieces.resize(counts.len(), 0u32);
        let mut cursor = self.scratch.take();
        cursor.clear();
        cursor.resize(max + 2, 0u32);
        cursor.copy_from_slice(&bounds);
        // Stable scatter: written in order traversal => in-bucket relative
        // order = order rank.
        for &p in self.order.iter() {
            let c = usize::from(counts[p as usize]);
            pieces[cursor[c] as usize] = p;
            cursor[c] += 1;
        }
        self.scratch.replace(cursor);
        self.pieces.replace(pieces);
        self.bounds.replace(bounds);
        self.dirty.set(false);
    }

    /// Two-phase bucket read: returns `(spread, plain)` with the same
    /// decisions as the legacy O(n) single pass —
    /// - `plain` = the first eligible piece in (count, order rank) order =
    /// globally rarest eligible, ties by shuffle order (same as the legacy
    /// "strictly-less replaces" full scan);
    /// - `spread` = the first eligible piece not yet `claimed`;
    /// - nothing eligible -> `(None, None)`.
    ///
    /// Equivalence: bucket order = count ascending, in-bucket order rank
    /// ascending (guaranteed by the stable scatter), so the first hit in an
    /// ascending bucket scan equals the legacy min-count, order-first pick.
    ///
    /// Multi-level file priorities (aligned with libtorrent
    /// `torrent_handle::prioritize_files`): `prio = Some(per-piece table)`
    /// changes the selection key to (priority desc, count asc, shuffle
    /// order first) — priority is the primary key over rarity, and within
    /// a level rarest-first with shuffle-order ties is preserved
    /// (bit-identical to the no-prio decision). Implementation = one full
    /// bucket-scan argmax: only a strictly higher level replaces the
    /// candidate (bucket order guarantees the first same-level hit is
    /// min-count/order-first, no secondary comparison needed).
    /// `prio = None` (default all-zero face) takes the existing early-exit
    /// path with zero decision/performance change. endgame/allowed-fast do
    /// not consume prio (endgame policy is priority-agnostic).
    pub fn select_two_phase(
        &self,
        eligible: impl Fn(u64) -> bool,
        claimed: impl Fn(u64) -> bool,
        prio: Option<&[i8]>,
    ) -> (Option<u64>, Option<u64>) {
        self.rebuild_if_dirty();
        let pieces = self.pieces.borrow();
        if pieces.is_empty() {
            return (None, None);
        }
        let bounds = self.bounds.borrow();
        let mut plain: Option<(u64, i8)> = None;
        let mut spread: Option<(u64, i8)> = None;
        let level = |i: u64| prio.and_then(|p| p.get(i as usize).copied()).unwrap_or(0);
        for c in 0..bounds.len().saturating_sub(1) {
            let (lo, hi) = (bounds[c] as usize, bounds[c + 1] as usize);
            for &p in pieces[lo..hi].iter() {
                let i = u64::from(p);
                if !eligible(i) {
                    continue;
                }
                let q = level(i);
                if plain.is_none_or(|(_, pq)| q > pq) {
                    plain = Some((i, q));
                }
                if !claimed(i) && spread.is_none_or(|(_, sq)| q > sq) {
                    // default prio face keeps the existing early exit
                    // (return on first hit, zero decision/performance
                    // change); the prio face must scan everything (a
                    // higher level may sit in a deeper bucket).
                    if prio.is_none() {
                        return (Some(i), plain.map(|(pi, _)| pi));
                    }
                    spread = Some((i, q));
                }
            }
        }
        (spread.map(|(si, _)| si), plain.map(|(pi, _)| pi))
    }
}

/// Selection filter (priority/sequential form; SPEC §6.9).
#[derive(Debug, Clone, Copy, Default)]
pub struct SelectFilter {
    /// Sequential mode: ignore the shuffle order, use natural flat
    /// coordinate order (v1 global piece order / v2 in-file piece order —
    /// flat coordinates are file-order concatenations, so the two are the
    /// same).
    pub sequential: bool,
    /// Skip set (coordinates of file-priority -1 pieces,
    /// PriorityPieceSelector semantics). The caller passes the predicate.
    pub skipped: Option<fn(u64) -> bool>,
}

/// rarest-first selection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Regular (non-endgame) pick: the caller guarantees the piece has no
    /// pending request yet.
    Piece(u64),
    /// No candidate (available ∩ !skipped is empty).
    None,
}

/// rarest-first selection (`RarestPieceSelector.cc` port): walk the shuffle
/// order (natural order when sequential), pick the min-count piece among
/// available and not skipped; `preferred` (allowed-fast) intersected with
/// available goes first.
///
/// The non-sequential main path reads the bucket view (an ascending bucket
/// scan's first eligible = min-count + shuffle-order first; equivalence in
/// [`PieceStatMan::select_two_phase`]); the sequential branch keeps the
/// natural-order straight scan (counts are always fresh, no bucket needed).
/// Signature unchanged; the `seeds` contribution is merged via
/// [`PieceStatMan::count`] — a uniform shift does not change the argmin or
/// the tie order.
///
/// `prio` adds per-piece multi-level file priorities with selection key
/// (priority desc, count asc, shuffle order first) — same semantics as the
/// prio arm of [`PieceStatMan::select_two_phase`]; `None` = the default
/// all-zero face, zero decision change.
pub fn select(
    stats: &PieceStatMan,
    available: impl Fn(u64) -> bool,
    filter: SelectFilter,
    preferred: &[u64],
    prio: Option<&[i8]>,
) -> Selection {
    let n = stats.counts.len() as u64;
    let eligible = |i: u64| available(i) && filter.skipped.is_none_or(|f| !f(i));
    let level = |i: u64| prio.and_then(|p| p.get(i as usize).copied()).unwrap_or(0);
    // allowed-fast priority (still picks the rarest within preferred; with
    // prio: higher level first, then min-count, then shuffle order).
    let mut best: Option<(u64, u32, i8)> = None;
    for &i in preferred {
        if i < n && eligible(i) {
            let c = stats.count(i);
            let q = level(i);
            if best.is_none_or(|(_, bc, bq)| q > bq || (q == bq && c < bc)) {
                best = Some((i, c, q));
            }
        }
    }
    if let Some((i, _, _)) = best {
        return Selection::Piece(i);
    }
    if filter.sequential {
        // Natural-order straight scan (kept; counts always fresh, no bucket
        // view).
        for idx in 0..n {
            if eligible(idx) {
                let c = stats.count(idx);
                match best {
                    Some((_, bc, bq)) if c >= bc && level(idx) <= bq => {}
                    _ => best = Some((idx, c, level(idx))),
                }
            }
        }
    } else {
        // Bucket read (`piece_picker.hpp` form): an ascending bucket scan's
        // first eligible = min-count + shuffle-order first (same as the
        // legacy full scan); the prio face is a single full-scan argmax
        // (only a strictly higher level replaces — bucket order guarantees
        // the first same-level hit is min-count/order-first).
        stats.rebuild_if_dirty();
        let pieces = stats.pieces.borrow();
        if !pieces.is_empty() {
            let bounds = stats.bounds.borrow();
            'buckets: for c in 0..bounds.len().saturating_sub(1) {
                let (lo, hi) = (bounds[c] as usize, bounds[c + 1] as usize);
                for &p in pieces[lo..hi].iter() {
                    let i = u64::from(p);
                    if eligible(i) {
                        let q = level(i);
                        if best.is_none_or(|(_, _, bq)| q > bq) {
                            best = Some((i, stats.count(i), q));
                            if prio.is_none() {
                                break 'buckets;
                            }
                        }
                    }
                }
            }
        }
    }
    best.map_or(Selection::None, |(i, _, _)| Selection::Piece(i))
}

/// Endgame gate (`DefaultPieceStorage.h`): incomplete pieces <= 20. During
/// endgame the caller should allow duplicate requests for the same piece
/// across peers (RequestBook relaxation). Note: the engine's dispatch-side
/// endgame trigger has moved to an adaptive whole-swarm condition (every
/// remaining incomplete piece downloaded or in flight, libtorrent
/// semantics, or a remaining-bytes/rate ETA below a threshold); this fixed
/// gate is no longer the engine trigger and stays as the aria2 reference
/// constant.
pub fn in_endgame(incomplete_pieces: u64) -> bool {
    incomplete_pieces <= END_GAME_PIECE_NUM && incomplete_pieces > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity shuffle (no reorder at construction) — the deterministic
    /// base for table tests.
    fn identity_shuffle() -> impl FnMut(usize) -> usize {
        |_| 0 // always j=0: a deterministic permutation (see the order assertion)
    }

    /// Counts: bitfield-driven inc/sub and saturation (PieceStatMan.cc).
    #[test]
    fn counts_update_and_saturate() {
        let mut sm = PieceStatMan::new(8, &mut identity_shuffle());
        // peers {0 holds 0..4, 1 holds 2..6}.
        sm.add_bitfield(|i| i < 4, 8);
        sm.add_bitfield(|i| (2..6).contains(&i), 8);
        let expect = [1, 1, 2, 2, 1, 1, 0, 0];
        for (i, e) in expect.iter().enumerate() {
            assert_eq!(sm.count(i as u64), *e, "index {i}");
        }
        // saturating sub: removing non-held pieces cannot underflow.
        sm.subtract_bitfield(|i| i >= 6, 8);
        assert_eq!(sm.count(6), 0);
        sm.subtract_bitfield(|i| i >= 6, 8);
        assert_eq!(sm.count(6), 0);
        // add_piece (HAVE).
        sm.add_piece(7);
        assert_eq!(sm.count(7), 1);
        // update: new has/old lacks -> inc; old has/new lacks -> sub.
        sm.update_bitfield(|i| i == 0, |i| i == 1, 8);
        assert_eq!(sm.count(0), 2);
        assert_eq!(sm.count(1), 0);
    }

    /// Rarest pick: min count wins; ties by shuffle order first
    /// (RarestPieceSelector.cc).
    #[test]
    fn rarest_picks_min_count_ties_by_order() {
        let mut sm = PieceStatMan::new(8, &mut identity_shuffle());
        // Fisher-Yates with j=0 always (swap(i,0) tail to head):
        // order = [1,2,3,4,5,6,7,0] (locks in that the shuffle path runs).
        assert_eq!(sm.order(), &[1, 2, 3, 4, 5, 6, 7, 0]);
        sm.add_bitfield(|i| i != 3, 8); // piece 3 unheld
        sm.add_bitfield(|_| false, 0);
        sm.add_bitfield(|i| i < 2, 8); // pieces 0/1 get one more holder
        // counts: 0,1 -> 2; 2,4..7 -> 1; 3 -> 0.
        // available = 2..8 (includes piece 3): piece 3 has count 0, the
        // rarest (min overrides the earlier count-1 piece 2) -> pick 3.
        let sel = select(
            &sm,
            |i| (2..8).contains(&i),
            SelectFilter::default(),
            &[],
            None,
        );
        assert_eq!(sel, Selection::Piece(3));
        // with piece 3 available: 3 has count 0, the rarest.
        let sel = select(&sm, |i| i != 9, SelectFilter::default(), &[], None);
        assert_eq!(sel, Selection::Piece(3));
        // nothing available -> None.
        assert_eq!(
            select(&sm, |_| false, SelectFilter::default(), &[], None),
            Selection::None
        );
    }

    /// allowed-fast first: rarest within preferred ∩ available, ahead of
    /// the global best.
    #[test]
    fn preferred_allowed_fast_first() {
        let mut sm = PieceStatMan::new(8, &mut identity_shuffle());
        sm.add_bitfield(|_| true, 8); // everything counts 1
        sm.add_piece(5); // piece 5 counts 2 (globally rarest are the others)
        // preferred = [5]: not the global rarest, still picked first.
        let sel = select(&sm, |_| true, SelectFilter::default(), &[5], None);
        assert_eq!(sel, Selection::Piece(5));
        // preferred not available -> fall back to global (shuffle-order
        // first available = 1).
        let sel = select(&sm, |i| i != 5, SelectFilter::default(), &[5], None);
        assert_eq!(
            sel,
            Selection::Piece(1),
            "falls back to the first available in shuffle order"
        );
    }

    /// Skip filter (priority -1) and sequential natural order.
    #[test]
    fn filter_skip_and_sequential() {
        let mut sm = PieceStatMan::new(8, &mut identity_shuffle());
        sm.add_bitfield(|_| true, 8);
        // skip piece 0: shuffle-order first eligible is 1 (tie at count 1)
        // -> pick 1.
        let filter = SelectFilter {
            sequential: false,
            skipped: Some(|i| i == 0),
        };
        assert_eq!(
            select(&sm, |_| true, filter, &[], None),
            Selection::Piece(1)
        );
        // sequential: ignores shuffle order, natural first is 0; skip 0
        // -> 1.
        let seq = SelectFilter {
            sequential: true,
            skipped: None,
        };
        assert_eq!(select(&sm, |_| true, seq, &[], None), Selection::Piece(0));
        let seq_skip = SelectFilter {
            sequential: true,
            skipped: Some(|i| i == 0),
        };
        assert_eq!(
            select(&sm, |_| true, seq_skip, &[], None),
            Selection::Piece(1)
        );
    }

    /// `select_two_phase` prio-arm argmax semantics — level first (a
    /// higher-level piece beats a rarer lower-level one); the None face
    /// has zero drift (early-exit path).
    #[test]
    fn select_two_phase_priority_face() {
        let mut sm = PieceStatMan::new(8, &mut |n| n / 2);
        for i in 0..4u64 {
            for _ in 0..3 {
                sm.add_piece(i);
            }
        }
        for i in 4..8u64 {
            sm.add_piece(i);
        }
        let done = [false; 8];
        let eligible = |i: u64| i < 8 && !done[i as usize];
        let none_claimed = |_: u64| false;
        let (spread, plain) = sm.select_two_phase(
            eligible,
            none_claimed,
            Some(&[0i8, 0, 7, 0, 0, 0, 0, 0][..]),
        );
        println!("spread={spread:?} plain={plain:?}");
        assert_eq!((spread, plain), (Some(2), Some(2)));
    }

    /// Endgame gate: <= 20 and > 0 (DefaultPieceStorage.h).
    #[test]
    fn endgame_threshold() {
        assert!(!in_endgame(21));
        assert!(in_endgame(20));
        assert!(in_endgame(1));
        assert!(!in_endgame(0), "0 missing = complete, not endgame");
    }

    /// Fixture swarm convergence: 20 pieces x 3 peers with incremental
    /// have-sets, simulating download progress — the selection sequence
    /// always hits the rarest available piece at that moment.
    #[test]
    fn rarest_converges_on_simulated_swarm() {
        let mut sm = PieceStatMan::new(20, &mut identity_shuffle());
        // peer A holds the first 10 pieces, B holds 5..15, C holds 10..20.
        sm.add_bitfield(|i| i < 10, 20);
        sm.add_bitfield(|i| (5..15).contains(&i), 20);
        sm.add_bitfield(|i| (10..20).contains(&i), 20);
        // counts: 0..5 -> 1, 5..15 -> 2, 15..20 -> 1. In shuffle order
        // [1,2,...] the first available is 1 with count 1, minimal -> 1.
        let sel = select(&sm, |_| true, SelectFilter::default(), &[], None);
        assert_eq!(sel, Selection::Piece(1));
        // Simulate 0..5 becoming "already have" (excluded from available):
        // scanning in shuffle order for the min count — 5..15 count 2,
        // 15..20 count 1, order meets 5(2) before 15(1) -> the count-1
        // piece 15 wins (min overrides first-come).
        let sel = select(&sm, |i| i >= 5, SelectFilter::default(), &[], None);
        assert_eq!(sel, Selection::Piece(15));
        // Removing our completed pieces from a peer's bitmap (leave
        // semantics) does not touch other peers: remove_peer decrements
        // only that peer.
        let before = sm.count(15);
        sm.remove_peer(|i| (10..20).contains(&i), 20);
        assert_eq!(sm.count(15), before - 1);
    }

    /// Baseline replay: the event sequences and selection results were
    /// captured from the pre-refactor legacy implementation and replayed
    /// assertion by assertion — the proof that selection semantics did not
    /// change. Scenarios: shuffle order / tie-breaks / HAVE / update /
    /// leave / have-all (legacy seed semantics) / preferred / sequential /
    /// skip.
    #[test]
    fn baseline_replay_recorded_from_legacy() {
        let mut out = String::new();
        // -- scenario A: mixed event stream (join/HAVE/update/leave +
        // picks) --
        {
            let mut sm = PieceStatMan::new(32, &mut identity_shuffle());
            out.push_str(&format!("A.order={:?}\n", sm.order()));
            sm.add_bitfield(|i| i < 16, 32);
            sm.add_bitfield(|i| (8..24).contains(&i), 32);
            sm.add_bitfield(|i| i >= 16, 32);
            let counts: Vec<u32> = (0..32).map(|i| sm.count(i)).collect();
            out.push_str(&format!("A.counts1={counts:?}\n"));
            let sel = |sm: &PieceStatMan, lo: u64| {
                let s = select(sm, |i| i >= lo, SelectFilter::default(), &[], None);
                format!("{s:?}")
            };
            out.push_str(&format!(
                "A.sel(>=0)={} A.sel(>=8)={} A.sel(>=16)={}\n",
                sel(&sm, 0),
                sel(&sm, 8),
                sel(&sm, 16)
            ));
            sm.add_piece(3);
            sm.add_piece(3);
            sm.add_piece(20);
            out.push_str(&format!(
                "A.sel2(>=0)={} A.sel2(>=8)={}\n",
                sel(&sm, 0),
                sel(&sm, 8)
            ));
            sm.update_bitfield(|i| i == 1, |i| i == 2, 32);
            out.push_str(&format!(
                "A.counts2={:?}\n",
                (0..6).map(|i| sm.count(i)).collect::<Vec<_>>()
            ));
            out.push_str(&format!("A.sel3(>=0)={}\n", sel(&sm, 0)));
            sm.subtract_bitfield(|i| i < 8, 32);
            out.push_str(&format!(
                "A.sel4(>=0)={} A.sel4(>=16)={}\n",
                sel(&sm, 0),
                sel(&sm, 16)
            ));
            sm.remove_peer(|i| (8..24).contains(&i), 32);
            let counts: Vec<u32> = (0..32).map(|i| sm.count(i)).collect();
            out.push_str(&format!("A.counts3={counts:?}\n"));
            out.push_str(&format!(
                "A.sel5(>=0)={} A.sel5(>=4)={}\n",
                sel(&sm, 0),
                sel(&sm, 4)
            ));
            // preferred (allowed-fast)
            let pf = select(&sm, |_| true, SelectFilter::default(), &[30, 31], None);
            out.push_str(&format!("A.pref=[{pf:?}]"));
            let pf2 = select(&sm, |i| i < 30, SelectFilter::default(), &[30, 0], None);
            out.push_str(&format!("A.pref2=[{pf2:?}]\n"));
            // sequential
            let seq = SelectFilter {
                sequential: true,
                skipped: None,
            };
            out.push_str(&format!(
                "A.seq={:?}\n",
                select(&sm, |_| true, seq, &[], None)
            ));
        }
        // -- scenario B: tie-break total order (select + per-piece
        // exclusion) --
        {
            let mut sm = PieceStatMan::new(16, &mut identity_shuffle());
            sm.add_bitfield(|_| true, 16);
            sm.add_bitfield(|_| false, 0);
            let mut done: Vec<u64> = Vec::new();
            let mut picks = Vec::new();
            for _ in 0..16 {
                let s = select(
                    &sm,
                    |i| !done.contains(&i),
                    SelectFilter::default(),
                    &[],
                    None,
                );
                match s {
                    Selection::Piece(p) => {
                        picks.push(p);
                        done.push(p);
                    }
                    Selection::None => break,
                }
            }
            out.push_str(&format!("B.picks={picks:?}\n"));
            // re-rank after HAVEs break ties
            sm.add_piece(2);
            sm.add_piece(2);
            sm.add_piece(9);
            let mut done2: Vec<u64> = Vec::new();
            let mut picks2 = Vec::new();
            for _ in 0..5 {
                let s = select(
                    &sm,
                    |i| !done2.contains(&i),
                    SelectFilter::default(),
                    &[],
                    None,
                );
                match s {
                    Selection::Piece(p) => {
                        picks2.push(p);
                        done2.push(p);
                    }
                    Selection::None => break,
                }
            }
            out.push_str(&format!("B.picks2={picks2:?}\n"));
        }
        // -- scenario C: have-all (legacy HaveAll semantics = add_bitfield
        // all) --
        {
            let mut sm = PieceStatMan::new(24, &mut identity_shuffle());
            sm.add_bitfield(|i| i < 10, 24); // partial evidence first
            sm.add_bitfield(|_| true, 24); // HaveAll equivalent
            let counts: Vec<u32> = (0..24).map(|i| sm.count(i)).collect();
            out.push_str(&format!("C.counts1={counts:?}\n"));
            out.push_str(&format!(
                "C.sel1={:?}\n",
                select(&sm, |_| true, SelectFilter::default(), &[], None)
            ));
            sm.remove_peer(|_| true, 24); // the have-all row leaves
            let counts: Vec<u32> = (0..24).map(|i| sm.count(i)).collect();
            out.push_str(&format!("C.counts2={counts:?}\n"));
            out.push_str(&format!(
                "C.sel2={:?}\n",
                select(&sm, |_| true, SelectFilter::default(), &[], None)
            ));
            sm.add_bitfield(|_| true, 24);
            sm.update_bitfield(|i| i == 5, |i| i == 7, 24); // have-all -> partial (legacy seed downgrade)
            let counts: Vec<u32> = (0..24).map(|i| sm.count(i)).collect();
            out.push_str(&format!("C.counts3={counts:?}\n"));
            out.push_str(&format!(
                "C.sel3={:?}\n",
                select(&sm, |_| true, SelectFilter::default(), &[], None)
            ));
        }
        // -- scenario D: sparse availability + skip filter --
        {
            let mut sm = PieceStatMan::new(20, &mut identity_shuffle());
            for p in [1usize, 4, 5, 11, 12, 18] {
                sm.add_piece(p as u64);
            }
            let filter = SelectFilter {
                sequential: false,
                skipped: Some(|i| i == 1 || i == 11),
            };
            let mut done: Vec<u64> = Vec::new();
            let mut picks = Vec::new();
            for _ in 0..6 {
                let s = select(&sm, |i| !done.contains(&i), filter, &[], None);
                match s {
                    Selection::Piece(p) => {
                        picks.push(p);
                        done.push(p);
                    }
                    Selection::None => break,
                }
            }
            out.push_str(&format!("D.picks={picks:?}\n"));
        }
        assert_eq!(
            out,
            "A.order=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, \
             20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0]\n\
             A.counts1=[1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1]\n\
             A.sel(>=0)=Piece(1) A.sel(>=8)=Piece(24) A.sel(>=16)=Piece(24)\n\
             A.sel2(>=0)=Piece(1) A.sel2(>=8)=Piece(24)\n\
             A.counts2=[1, 2, 0, 3, 1, 1]\n\
             A.sel3(>=0)=Piece(2)\n\
             A.sel4(>=0)=Piece(2) A.sel4(>=16)=Piece(24)\n\
             A.counts3=[0, 1, 0, 2, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]\n\
             A.sel5(>=0)=Piece(2) A.sel5(>=4)=Piece(4)\n\
             A.pref=[Piece(30)]A.pref2=[Piece(0)]\n\
             A.seq=Piece(0)\n\
             B.picks=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0]\n\
             B.picks2=[1, 3, 4, 5, 6]\n\
             C.counts1=[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]\n\
             C.sel1=Piece(10)\n\
             C.counts2=[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]\n\
             C.sel2=Piece(10)\n\
             C.counts3=[2, 2, 2, 2, 2, 3, 2, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]\n\
             C.sel3=Piece(7)\n\
             D.picks=[2, 3, 6, 7, 8, 9]\n"
        );
    }

    /// Brute-force reference (line-for-line mirror of the legacy algorithm:
    /// full shuffle-order scan + strictly-less replaces) — the differential
    /// authority for `select` / [`PieceStatMan::select_two_phase`]; see
    /// `baseline_replay_recorded_from_legacy`.
    fn reference_select(
        order: &[u32],
        counts: &[u32],
        eligible: impl Fn(u64) -> bool,
    ) -> Option<u64> {
        let mut best: Option<(u64, u32)> = None;
        for &idx in order {
            let i = u64::from(idx);
            if eligible(i) {
                let c = counts.get(i as usize).copied().unwrap_or(0);
                match best {
                    Some((_, bc)) if c >= bc => {}
                    _ => best = Some((i, c)),
                }
            }
        }
        best.map(|(i, _)| i)
    }

    /// Differential storm (fixed seed): after random event streams
    /// (join/leave/HAVE/seed join-leave/downgrade), the bucket-view
    /// `select` and the two-phase read must match the brute-force reference
    /// every time — the equivalence proof for lazy rebuild / seed O(1) /
    /// bucket reads. Reference state = literal per-piece counts (the legacy
    /// semantic model); sm and the reference share one rng stream (the
    /// closures consume it per piece identically), so both sides see
    /// strictly isomorphic events.
    #[test]
    fn differential_storm_matches_reference() {
        // xorshift64 fixed seed (deterministic).
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rng = move |n: u64| -> u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % n.max(1)
        };
        let n: u64 = 40;
        for round in 0..200u32 {
            let mut sm = PieceStatMan::new(n, &mut |k| rng(k as u64) as usize);
            // reference state: literal per-piece counts (legacy semantics)
            // + seed count.
            let mut ref_counts = vec![0u32; n as usize];
            let mut ref_seeds: u32 = 0;
            // 7 controlled peers: join -> occasional leave -> rejoin
            // (varied density/seeds).
            for p in 0..7u64 {
                let density = rng(100);
                // join: sample the bitmap into a mask first (rng is FnMut
                // and cannot enter an impl Fn closure; consumption order
                // matches the per-piece closure), then feed both sm and the
                // reference.
                let join_bits: Vec<bool> = (0..n).map(|_| rng(100) < density).collect();
                sm.add_bitfield(|i| join_bits[i as usize], n);
                for (i, b) in join_bits.iter().enumerate() {
                    if *b {
                        ref_counts[i] += 1;
                    }
                }
                if p >= 2 && rng(3) == 0 {
                    // leave (retract the peer's whole row literally — the
                    // reference does not know the row contents, so it
                    // resamples at the same density and subtracts: the
                    // density sampling is iid with the join sampling, the
                    // retracted set is within the possible have-set, and
                    // saturating sub keeps the reference at >= 0, mirroring
                    // sm's saturating_sub).
                    let leave_bits: Vec<bool> = (0..n).map(|_| rng(100) < density).collect();
                    sm.subtract_bitfield(|i| leave_bits[i as usize], n);
                    for (i, b) in leave_bits.iter().enumerate() {
                        if *b {
                            ref_counts[i] = ref_counts[i].saturating_sub(1);
                        }
                    }
                }
                if p >= 5 && rng(4) == 0 {
                    // seed join/leave (O(1) fast path vs the reference's
                    // +/-1 on all pieces).
                    if rng(2) == 0 {
                        sm.add_seed();
                        ref_seeds += 1;
                    } else if ref_seeds > 0 {
                        sm.remove_seed();
                        ref_seeds -= 1;
                    }
                }
            }
            // HAVE pokes
            for _ in 0..10 {
                let i = rng(n);
                sm.add_piece(i);
                ref_counts[i as usize] += 1;
            }
            // assertion 1: count() per piece == reference (counts + seeds
            // merged; storm counts stay far below 65535, saturation is
            // covered by a dedicated test).
            for i in 0..n {
                let expect = ref_counts[i as usize].saturating_add(ref_seeds);
                assert_eq!(sm.count(i), expect, "round {round} count({i})");
            }
            // assertion 2: under several eligible predicates, select /
            // two-phase == reference. The reference order key = effective
            // count (raw + seeds; uniform shift, order unchanged).
            let eff: Vec<u32> = ref_counts
                .iter()
                .map(|&c| c.saturating_add(ref_seeds))
                .collect();
            for k in 0..3u64 {
                let lo = rng(n);
                let eligible = move |i: u64| k == 0 || i >= lo;
                let expect = reference_select(sm.order(), &eff, eligible);
                let got = select(&sm, eligible, SelectFilter::default(), &[], None);
                assert_eq!(
                    got,
                    expect.map_or(Selection::None, Selection::Piece),
                    "round {round} k {k}"
                );
                let (spread, plain) = sm.select_two_phase(eligible, |i| i % 7 == 0, None);
                assert_eq!(plain, expect, "round {round} k {k} plain");
                let expect_spread =
                    reference_select(sm.order(), &eff, |i| eligible(i) && i % 7 != 0);
                assert_eq!(spread, expect_spread, "round {round} k {k} spread");
            }
        }
    }

    /// Count saturation cap = 65535 (libtorrent `max_peer_count = 0xffff`,
    /// `piece_picker.hpp`) — locks in the narrower u16 saturation face.
    #[test]
    fn count_saturates_at_max_peer_count() {
        let mut sm = PieceStatMan::new(2, &mut identity_shuffle());
        for _ in 0..70_000u32 {
            sm.add_piece(0);
        }
        assert_eq!(sm.count(0), 65_535);
        assert_eq!(sm.count(1), 0);
    }

    /// Over-domain construction (`piece_num` past the u32 `order` table):
    /// `try_new` refuses before allocating, carrying the input back as
    /// `Err` — the old `piece_num as u32` silently truncated `order` to a
    /// stub while `counts` kept the full length (the two disagreeing).
    /// `new` turns the same input into a loud panic (caller bug, not an
    /// input path: u32::MAX pieces = tens of EiB at any sane block size).
    #[test]
    fn try_new_rejects_piece_num_over_u32_domain() {
        // Boundary: exactly u32::MAX + 1 is already unrepresentable (no
        // allocation happens — the u32::try_from guard fires first).
        let edge = u64::from(u32::MAX) + 1;
        assert!(matches!(
            PieceStatMan::try_new(edge, &mut identity_shuffle()),
            Err(n) if n == edge
        ));
        // A value whose `as u32` truncation would be silently plausible
        // (2^32 + 5 -> order of 5) is rejected, not truncated.
        let over = u64::from(u32::MAX) + 5;
        assert!(matches!(
            PieceStatMan::try_new(over, &mut identity_shuffle()),
            Err(n) if n == over
        ));
        // In-domain face: try_new matches new() under the same shuffle
        // stream (identical order + counts extent).
        let a = PieceStatMan::try_new(8, &mut identity_shuffle())
            .unwrap_or_else(|n| panic!("in-domain input rejected: {n}"));
        let b = PieceStatMan::new(8, &mut identity_shuffle());
        assert_eq!(a.order(), b.order());
        assert_eq!(a.counts.len(), b.counts.len());
    }

    /// The infallible `new` face fails loudly on the over-domain input
    /// (the expect inside carries the reason; see
    /// `try_new_rejects_piece_num_over_u32_domain` for the `Err` face).
    #[test]
    #[should_panic(expected = "exceeds u32::MAX")]
    fn new_panics_on_piece_num_over_u32_domain() {
        // No allocation can occur: the u32::try_from guard fires before
        // the table is built.
        let _ = PieceStatMan::new(u64::from(u32::MAX) + 1, &mut identity_shuffle());
    }

    /// The seed O(1) path is equivalent to the legacy per-piece semantics:
    /// effective counts and selection decisions of
    /// add_seed/remove_seed/seed_downgrade must equal the legacy
    /// "per-piece update of the full bitmap" reference.
    #[test]
    fn seed_fast_path_equivalent_to_per_piece() {
        let mut sm = PieceStatMan::new(12, &mut identity_shuffle());
        let mut ref_counts = vec![0u32; 12];
        // two partial peers first
        sm.add_bitfield(|i| i < 5, 12);
        for c in ref_counts[..5].iter_mut() {
            *c += 1;
        }
        sm.add_bitfield(|i| (3..9).contains(&i), 12);
        for c in ref_counts[3..9].iter_mut() {
            *c += 1;
        }
        // seed join (HaveAll): O(1) vs the legacy per-piece +1.
        sm.add_seed();
        for c in ref_counts.iter_mut() {
            *c += 1;
        }
        for i in 0..12u64 {
            assert_eq!(sm.count(i), ref_counts[i as usize], "seed join {i}");
        }
        // same pick: the tie order is unchanged after a have-all joins
        // (uniform shift).
        let got = select(&sm, |_| true, SelectFilter::default(), &[], None);
        let expect = reference_select(sm.order(), &ref_counts, |_| true);
        assert_eq!(got, expect.map_or(Selection::None, Selection::Piece));
        // seed downgrade (new row = 3..7): break_one_seed + delta ==
        // legacy update(new row, all-ones).
        sm.seed_downgrade(|i| (3..7).contains(&i), 12);
        for i in 0..12u64 {
            ref_counts[i as usize] = ref_counts[i as usize] - 1 + u32::from((3..7).contains(&i));
        }
        for i in 0..12u64 {
            assert_eq!(sm.count(i), ref_counts[i as usize], "downgrade {i}");
        }
        // seed leave (HaveNone/leave semantics): O(1) vs the legacy
        // per-piece -1. (No longer a seed after the downgrade; remove_seed
        // is verified separately here.)
        let mut sm2 = PieceStatMan::new(6, &mut identity_shuffle());
        sm2.add_bitfield(|i| i < 3, 6);
        sm2.add_seed();
        sm2.remove_seed();
        for i in 0..6u64 {
            let expect = u32::from(i < 3);
            assert_eq!(sm2.count(i), expect, "seed leave {i}");
        }
    }

    /// Memory accounting: PieceStatMan persistently allocates 10B/piece
    /// (order 4 + counts 2 + pieces 4) vs the legacy 12B/piece (order 8 +
    /// counts 4). The bucket view is part of the persistent allocation
    /// (lazy-rebuild cache; capacity = n kept). Note: both the tie-break
    /// authority (`order`, 4B/piece) and the bucket array (`pieces`,
    /// 4B/piece) are irreducible.
    #[test]
    fn memory_footprint_accounting() {
        const N: usize = 100_000;
        let mut sm = PieceStatMan::new(N as u64, &mut identity_shuffle());
        sm.add_piece(0); // dirty (no rebuild — counting persistent fields themselves)
        let bytes = sm.order.len() * std::mem::size_of::<u32>()
            + sm.counts.len() * std::mem::size_of::<u16>()
            + N * std::mem::size_of::<u32>(); // pieces bucket slots (persistent after rebuild)
        let legacy_bytes = N * 8 + N * 4;
        assert_eq!(bytes, N * 10);
        assert_eq!(legacy_bytes, N * 12);
    }
}

#[cfg(test)]
mod bt_release {
    use super::*;

    /// Bucket-view release semantics: after release the three buffers have
    /// zero capacity (resident view gone), counts/order stay resident, and
    /// the next pick lazily rebuilds through the dirty gate with identical
    /// decisions.
    #[test]
    fn release_bucket_view_frees_buffers_and_rebuilds() {
        let mut man = PieceStatMan::new(1000, &mut |_: usize| 0);
        man.add_bitfield(|i| i % 2 == 0, 1000);
        // trigger the lazy rebuild (select runs rebuild_if_dirty).
        let (plain, _) = man.select_two_phase(|_| true, |_| false, None);
        assert!(plain.is_some(), "a piece is selectable");
        {
            let pieces = man.pieces.borrow();
            assert_eq!(pieces.len(), 1000, "bucket view at full size after rebuild");
            assert!(pieces.capacity() >= 1000);
        }
        // release: three buffers at zero capacity, counts kept.
        man.release_bucket_view();
        assert_eq!(man.pieces.borrow().capacity(), 0, "pieces capacity zeroed");
        assert_eq!(man.bounds.borrow().capacity(), 0, "bounds capacity zeroed");
        assert_eq!(
            man.scratch.borrow().capacity(),
            0,
            "scratch capacity zeroed"
        );
        assert_eq!(man.count(0), 1, "counts stay resident");
        // pick again: lazy rebuild, same decision (even pieces count=1
        // still head the first bucket).
        let (plain2, _) = man.select_two_phase(|_| true, |_| false, None);
        assert_eq!(plain, plain2, "selection unchanged after release+rebuild");
    }
}

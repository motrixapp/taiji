//! WrDiskCache direct translation: write-cache index + per-piece cell
//! buffers (SPEC §5.2).
//!
//! Upstream anchor mapping: docs/design/store.md (aria2
//! `WrDiskCacheEntry.h/.cc`, `WrDiskCache.cc`, `Piece.cc`,
//! `BtPieceMessage.cc`, `OptionHandlerFactory.cc`).
//!
//! Intentional divergence from aria2: aria2 lets **unverified** data
//! reach disk through the cache and verifies whole pieces on completion;
//! here the cache holds only unverified data and evicting an unverified
//! piece means **destroy-and-refetch** (see `verified.rs`), not a disk
//! write. The accounting/touch machinery mirrors aria2; the eviction
//! order is an intentional divergence — aria2's largest-first eviction
//! is replaced by the min-loss model (rationale and termination in the
//! `update_min_loss` docs).

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::Arc;

use taiji_io::block_arena::{BlockArena, BlockLease};

/// Default cache capacity (aria2 `PREF_DISK_CACHE` default 16M,
/// `OptionHandlerFactory.cc`).
pub const DEFAULT_CACHE_LIMIT: usize = 16 * 1024 * 1024;

/// Cell buffer storage: a pooled lease, a shared reference-counted
/// buffer, or a fallback heap Vec.
///
/// - [`CellBuf::Pooled`]: a face-level [`BlockArena`] lease (16KiB main
///   bucket); a Drop guard returns the block to the pool — every
///   ownership endpoint (write-out/eviction/refetch) converges on lease
///   destruction, eliminating per-block malloc/mmap churn (upstream
///   anchor: libtorrent's disk-buffer malloc+free reuse with watermark
///   accounting, `src/disk_buffer_pool.cpp`; uTP size-bucketed free
///   lists, `packet_pool.hpp`).
/// - [`CellBuf::Shared`]: an adopted `Bytes` (the wire decode slice
///   itself — reference-counted, immutable). Built only by
///   [`DataCell::with_shared`] at exact capacity, so the append face
///   never reaches its storage (zero room by construction). When the
///   adopted `Bytes` is an arena-owner view, the pool return rides its
///   reference count — the same Drop-guard convergence as `Pooled`.
/// - [`CellBuf::Heap`]: the `with_data` form (test/assembly surfaces and
///   the over-main-bucket capacity fallback), byte-identical semantics
///   to pre-pool.
#[derive(Debug)]
pub enum CellBuf {
    Heap(Vec<u8>),
    Pooled(BlockLease),
    Shared(bytes::Bytes),
}

impl CellBuf {
    fn len(&self) -> usize {
        match self {
            CellBuf::Heap(v) => v.len(),
            CellBuf::Pooled(l) => l.len(),
            CellBuf::Shared(b) => b.len(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            CellBuf::Heap(v) => v.as_slice(),
            CellBuf::Pooled(l) => l.filled(),
            CellBuf::Shared(b) => &b[..],
        }
    }

    /// Append at the tail (the capacity red line is the cell capacity,
    /// enforced by [`DataCell::try_append`]; lease capacity ≥ cell
    /// capacity always holds — leases are taken at cell capacity and
    /// bucket sizes ≥ the request size). `Shared` cells are built only
    /// at exact capacity (zero room), so the push arm is unreachable by
    /// construction — the debug_assert documents the invariant rather
    /// than defending it.
    fn push(&mut self, data: &[u8]) {
        match self {
            CellBuf::Heap(v) => v.extend_from_slice(data),
            CellBuf::Pooled(l) => {
                let pushed = l.push_bytes(data);
                debug_assert_eq!(pushed, data.len(), "lease capacity >= cell capacity");
            }
            CellBuf::Shared(_) => {
                debug_assert!(
                    data.is_empty(),
                    "a shared cell is always full, appending is impossible"
                );
            }
        }
    }
}

impl PartialEq for CellBuf {
    /// Storage-independent byte equivalence (pooled vs heap compared by
    /// live bytes).
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for CellBuf {}

impl Clone for CellBuf {
    /// Deep-copy into an independent heap buffer (Clone never enters the
    /// pool — production never clones cells; only tests/assembly can
    /// reach this).
    fn clone(&self) -> Self {
        CellBuf::Heap(self.as_slice().to_vec())
    }
}

/// One contiguous write span (goff = layout global offset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataCell {
    pub goff: u64,
    data: CellBuf,
    /// Cell capacity ceiling (aria2: fixed at cell creation; append must
    /// not exceed it).
    capacity: usize,
}

impl DataCell {
    /// Create a cell: initial data + capacity (`len <= capacity`;
    /// upstream anchor `Piece.cc` `updateWrCache`, block-length capacity
    /// from `BtPieceMessage.cc`). Heap-allocation form (the semantic
    /// baseline of the pooled `with_data_in`; fallback switch and test
    /// surface).
    ///
    /// # Panics
    ///
    /// Debug builds assert `data.len() <= capacity` and panic on
    /// violation. Release builds do not panic: the over-capacity state
    /// is carried as constructed (the heap buffer keeps all bytes), and
    /// [`Self::try_append`] saturates its room to zero — absorbs nothing,
    /// so the violation cannot silently grow the cell.
    pub fn with_data(goff: u64, data: Vec<u8>, capacity: usize) -> DataCell {
        debug_assert!(data.len() <= capacity);
        DataCell {
            goff,
            data: CellBuf::Heap(data),
            capacity,
        }
    }

    /// Create a cell (pooled form): the data is copied into an arena
    /// lease (16KiB main bucket; pooled when `capacity ≤ 16KiB` —
    /// download blocks always qualify); Drop (write-out done/eviction/
    /// refetch) returns it to the pool. The copy count is identical to
    /// the heap form (exactly one placement copy per block), only the
    /// allocation source becomes the reuse pool.
    ///
    /// # Panics
    ///
    /// Debug builds assert `data.len() <= capacity` and panic on
    /// violation. Release builds do not panic: the over-capacity state
    /// is carried as constructed (the pooled branch retains up to the
    /// lease bucket size — bucket capacity ≥ the requested cell
    /// capacity), and [`Self::try_append`] saturates its room to zero —
    /// absorbs nothing, so the violation cannot silently grow the cell.
    pub fn with_data_in(
        goff: u64,
        data: &[u8],
        capacity: usize,
        arena: &Arc<BlockArena>,
    ) -> DataCell {
        debug_assert!(data.len() <= capacity);
        if capacity <= taiji_io::block_arena::BLOCK_SIZE {
            let mut lease = arena.lease(capacity);
            let pushed = lease.push_bytes(data);
            debug_assert_eq!(pushed, data.len());
            DataCell {
                goff,
                data: CellBuf::Pooled(lease),
                capacity,
            }
        } else {
            DataCell {
                goff,
                data: CellBuf::Heap(data.to_vec()),
                capacity,
            }
        }
    }

    /// Create a cell (adopted form): the wire decode slice itself
    /// becomes the cell storage — zero placement copies (the block's
    /// journey from the socket ends here). Capacity is exactly the
    /// buffer length (the append face therefore never reaches the
    /// immutable storage; see [`CellBuf::Shared`]). When `data` is an
    /// arena-owner view, the pool return rides its reference count —
    /// identical convergence to the `Pooled` form, one buffer earlier
    /// in the chain.
    ///
    /// The adoption contract: the caller guarantees `data` outlives the
    /// refcount (always true — the cell holds its own clone of the
    /// `Bytes` handle); over-main-bucket sizes are legal here (no
    /// bucket is consulted; the buffer already exists).
    pub fn with_shared(goff: u64, data: bytes::Bytes) -> DataCell {
        let capacity = data.len();
        DataCell {
            goff,
            data: CellBuf::Shared(data),
            capacity,
        }
    }

    pub fn goff(&self) -> u64 {
        self.goff
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Contiguous extension (`WrDiskCacheEntry.cc`): `goff` must equal
    /// `self.goff + self.len`; returns the absorbed byte count (short
    /// capacity absorbs only part).
    ///
    /// Wrap defense: an over-capacity cell state (constructible in
    /// release builds, where the constructors only `debug_assert`
    /// `len <= capacity`; see their `# Panics`) must not wrap
    /// `capacity - len` into a huge room — the room saturates to 0 and
    /// the call early-exits with the same return-0 face as the
    /// contiguity refusal, so a violated precondition can never grow
    /// the cell further (no silent over-capacity).
    pub fn try_append(&mut self, goff: u64, data: &[u8]) -> usize {
        if self.goff + self.len() as u64 != goff {
            return 0;
        }
        let room = self.capacity.saturating_sub(self.data.len());
        if room == 0 {
            return 0;
        }
        let wlen = room.min(data.len());
        self.data.push(&data[..wlen]);
        wlen
    }
}

/// Per-piece buffer: cells (goff ascending) + buffered size.
#[derive(Debug, Clone, Default)]
pub struct CacheEntry {
    cells: Vec<DataCell>,
    size: usize,
}

impl CacheEntry {
    /// Deduplicating insert (`WrDiskCacheEntry.cc`: the same goff is
    /// refused).
    pub fn cache_data(&mut self, cell: DataCell) -> bool {
        match self.cells.binary_search_by(|c| c.goff.cmp(&cell.goff)) {
            Ok(_) => false,
            Err(pos) => {
                self.size += cell.len();
                self.cells.insert(pos, cell);
                true
            }
        }
    }

    /// Contiguous append to the last cell (`WrDiskCacheEntry.cc`).
    /// Returns the absorbed byte count; the caller must report it as the
    /// delta to [`WrDiskCache::update_min_loss`].
    pub fn append(&mut self, goff: u64, data: &[u8]) -> usize {
        let Some(last) = self.cells.last_mut() else {
            return 0;
        };
        let wlen = last.try_append(goff, data);
        self.size += wlen;
        wlen
    }

    /// Whether `[goff, goff+len)` is fully covered by existing cells
    /// (the duplicate-block surface: a delivery for "data already at
    /// this goff" = a coverage hit). Cells are goff-ascending and
    /// non-overlapping (structural invariant), so coverage accumulates
    /// sequentially from the first cell intersecting goff; a hole or the
    /// cursor passing the range end decides.
    pub fn covers(&self, goff: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let end = goff + len as u64;
        let mut cursor = goff;
        for cell in &self.cells {
            let cell_end = cell.goff + cell.len() as u64;
            if cell_end <= cursor {
                continue;
            }
            if cell.goff > cursor {
                return false;
            }
            cursor = cell_end;
            if cursor >= end {
                return true;
            }
        }
        false
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    pub fn cells(&self) -> &[DataCell] {
        &self.cells
    }

    /// Clear the cells (the settled post-`writeToDisk`/`clear` state,
    /// `WrDiskCacheEntry.cc`).
    pub fn clear(&mut self) {
        self.cells.clear();
        self.size = 0;
    }

    /// Take all cells (ownership moves to the caller; size resets to
    /// zero — entry rebuild re-accounting goes through
    /// [`Self::cache_data`]). Consumed by the completed-piece
    /// "cache + spill" merge surface
    /// ([`crate::verified::VerifiedWriter::take_complete_entry`]).
    pub fn take_cells(&mut self) -> Vec<DataCell> {
        self.size = 0;
        std::mem::take(&mut self.cells)
    }
}

/// Eviction product: all cells of one piece handed over; the caller
/// decides write-out or discard.
#[derive(Debug)]
pub struct Evicted<K> {
    pub key: K,
    pub cells: Vec<DataCell>,
    pub bytes: usize,
}

/// Write-cache index (LRU + capacity control), `K` = piece key.
///
/// Semantics mirror `aria2/src/WrDiskCache.cc` item by item (anchors in
/// the module docs).
#[derive(Debug)]
pub struct WrDiskCache<K: Copy + Ord + Eq + std::hash::Hash + Debug> {
    limit: usize,
    total: usize,
    /// Monotonic clock: +1 per touch (`WrDiskCache.cc` `clock_`).
    clock: u64,
    entries: HashMap<K, CacheEntry>,
    /// (size descending, clock ascending) → key: the front evicts first
    /// (`WrDiskCacheEntry.h`). A key appears at most once in the index.
    index: BTreeMap<(std::cmp::Reverse<usize>, u64), K>,
    /// Reverse-lookup companion of `index`: key → the key's current
    /// index entry. A key is in the index at most once, so a value scan
    /// to locate it would be O(n) (touch fires on every block push via
    /// the `update_min_loss` path, O(pieces) per block with many
    /// in-flight pieces); the reverse map fetches the stale index key in
    /// O(1), making touch/remove O(log n). Invariant: the key sets
    /// mirror each other exactly — every `(k, ik)` in `pos` has
    /// `index[ik] == k`, and both maps hold the same key count;
    /// maintained only at touch/remove (all write points of `index`).
    pos: HashMap<K, (std::cmp::Reverse<usize>, u64)>,
    /// Bytes claimed from the process-wide unverified-byte ledger
    /// (invariant = total; debug_assert anchored at method boundaries).
    claimed: usize,
    /// Ledger wiring switch: always on in production; off by default
    /// under cfg(test) in [`Self::new`] (parallel tests share the global
    /// ledger and would disturb each other); cross-surface semantics are
    /// tested explicitly via [`Self::new_with_ledger_for_tests`].
    use_ledger: bool,
}

impl<K: Copy + Ord + Eq + std::hash::Hash + Debug> Drop for WrDiskCache<K> {
    fn drop(&mut self) {
        if self.use_ledger && self.claimed > 0 {
            taiji_io::unverified_budget::release(self.claimed);
        }
        self.claimed = 0;
    }
}

impl<K: Copy + Ord + Eq + std::hash::Hash + Debug> WrDiskCache<K> {
    pub fn new(limit: usize) -> WrDiskCache<K> {
        WrDiskCache {
            limit,
            total: 0,
            clock: 0,
            entries: HashMap::new(),
            index: BTreeMap::new(),
            pos: HashMap::new(),
            // Bytes claimed from the process-wide unverified-byte ledger
            // (invariant = total; Drop releases as a backstop against
            // pipeline-teardown leaks).
            claimed: 0,
            use_ledger: !cfg!(test),
        }
    }

    /// Test seam: constructor explicitly wired to the ledger (production
    /// [`Self::new`] is always wired; for the cfg(test) default see the
    /// `use_ledger` docs).
    pub fn new_with_ledger_for_tests(limit: usize) -> WrDiskCache<K> {
        let mut c = Self::new(limit);
        c.use_ledger = true;
        c
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn entry(&self, key: &K) -> Option<&CacheEntry> {
        self.entries.get(key)
    }

    pub fn entry_mut(&mut self, key: &K) -> Option<&mut CacheEntry> {
        self.entries.get_mut(key)
    }

    /// Remove the key's stale index entry and reinsert with current size +
    /// a fresh clock (mirrors aria2's set_.erase + insert refreshing
    /// sizeKey_/lastUpdate_). The stale index key is located O(1) via
    /// the reverse map (a key is in the index at most once, equivalent
    /// to a value scan); the reinserted key is still (current size,
    /// fresh clock), so the eviction order is unchanged.
    fn touch(&mut self, key: &K) {
        if let Some(stale) = self.pos.remove(key) {
            self.index.remove(&stale);
        }
        self.clock += 1;
        let size = self.entries.get(key).map_or(0, CacheEntry::size);
        let ik = (std::cmp::Reverse(size), self.clock);
        self.index.insert(ik, *key);
        self.pos.insert(*key, ik);
    }

    /// Register a new entry (`add`, `WrDiskCache.cc`). Duplicate
    /// registration returns false.
    pub fn add(&mut self, key: K) -> bool {
        if self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(key, CacheEntry::default());
        self.touch(&key);
        true
    }

    /// Report a cache-size change (`update`, `WrDiskCache.cc`): total
    /// accumulates, the index re-ranks, and eviction triggers. Returns
    /// the evicted pieces. Eviction policy (intentional divergence):
    ///
    /// - **Victim order = smallest size first (oldest on ties)** — the
    ///   opposite of aria2's largest-first (`WrDiskCacheEntry.h`) and
    ///   deliberate: aria2's eviction **writes the cells to disk**
    ///   (flush), where largest-first maximizes the bytes freed per
    ///   flush (a flush-efficiency goal). Here, under
    ///   verify-before-write, eviction = **destruction**, so the
    ///   flush-efficiency goal does not exist and the goal becomes
    ///   minimizing received bytes discarded per eviction. largest-first
    ///   under destroy semantics systematically kills near-complete
    ///   pieces (near-complete pieces are always the largest entries, so
    ///   at saturation completion self-destructs) = the main loop of the
    ///   long-run progress-stall pathology.
    /// - **Protect `key`** (the piece this delta just credited):
    ///   self-eviction would destroy just-received bytes outright, and
    ///   the upstream `received` bitmap/in-flight bookkeeping would
    ///   afterwards swallow re-delivered blocks as silent duplicates.
    ///
    /// Termination: stops when no size>0 unprotected entry remains
    /// (total may transiently stay above limit; the next update
    /// converges it).
    pub fn update_min_loss(&mut self, key: &K, delta: isize) -> Vec<Evicted<K>> {
        if !self.entries.contains_key(key) {
            return Vec::new();
        }
        // Two eviction sources share this return surface: the global
        // ledger yielding + the face-level limit gate — every evicted
        // entry must be handed back to the caller (the refetch surface).
        let mut evicted = Vec::new();
        if delta >= 0 {
            self.total += delta as usize;
            // Second gate of the global ledger — when over cap,
            // self-evict first to make room (other faces' data
            // untouched); when nothing here can yield, force-claim (the
            // arrived bytes are already in RAM and cannot be dropped —
            // soft cap, total bound = cap + one delta).
            let grow = delta as usize;
            if self.use_ledger {
                while taiji_io::unverified_budget::claim(grow).is_err() {
                    match self.evict_one(key) {
                        Some(e) => evicted.push(e),
                        None => {
                            taiji_io::unverified_budget::force_claim(grow);
                            break;
                        }
                    }
                }
            }
            self.claimed += grow;
        } else {
            // aria2's assert(total_ >= -delta) (`WrDiskCache.cc`) assumes
            // delta reflects the real cell accounting change; this
            // implementation defends against underflow with saturating
            // ops and keeps total == Σ entry.size (the flush side clears
            // cells before reporting -size; see verified.rs/proptest).
            let shrink = (-delta) as usize;
            self.total = self.total.saturating_sub(shrink);
            if self.use_ledger {
                taiji_io::unverified_budget::release(shrink);
            }
            self.claimed = self.claimed.saturating_sub(shrink);
        }
        debug_assert_eq!(
            self.claimed, self.total,
            "ledger invariant: claimed == total"
        );
        self.touch(key);
        evicted.extend(self.ensure_limit_min_loss(key));
        evicted
    }

    /// Capacity control (min-loss victim order; see the
    /// [`Self::update_min_loss`] docs). Eviction order = (size ascending,
    /// last_update ascending); the `protect` key and 0-size entries are
    /// never victims.
    fn ensure_limit_min_loss(&mut self, protect: &K) -> Vec<Evicted<K>> {
        let mut evicted = Vec::new();
        while self.total > self.limit {
            match self.evict_one(protect) {
                Some(e) => evicted.push(e),
                None => break,
            }
        }
        evicted
    }

    /// Evict a single victim (min-loss victim order, see the
    /// [`Self::update_min_loss`] docs; split out as a primitive shared by
    /// the face-level limit gate and the global ledger gate). On a hit,
    /// the global ledger is released synchronously (claimed/total both
    /// decrease).
    fn evict_one(&mut self, protect: &K) -> Option<Evicted<K>> {
        // Linear victim scan: the entry count is bounded by concurrent
        // in-flight pieces (far below the cache's piece-granularity
        // total), and eviction is low-frequency (at most a few per push)
        // — not a hot path.
        let mut choice: Option<((usize, u64), K)> = None;
        for ((_, clock), k) in self.index.iter() {
            if k == protect {
                continue;
            }
            let size = self.entries.get(k).map_or(0, CacheEntry::size);
            if size == 0 {
                continue; // No cells to hand over: eviction is zero-gain (termination guard).
            }
            let better = match &choice {
                None => true,
                Some((best, _)) => size < best.0 || (size == best.0 && *clock < best.1),
            };
            if better {
                choice = Some(((size, *clock), *k));
            }
        }
        let (_, victim) = choice?;
        let entry = self.entries.get_mut(&victim)?;
        let bytes = entry.size();
        self.total -= bytes;
        self.claimed -= bytes;
        if self.use_ledger {
            taiji_io::unverified_budget::release(bytes);
        }
        let cells = std::mem::take(&mut entry.cells);
        entry.size = 0;
        self.touch(&victim);
        Some(Evicted {
            key: victim,
            cells,
            bytes,
        })
    }

    /// Remove an entry (`remove`, `WrDiskCache.cc`), its cells returned
    /// to the caller.
    pub fn remove(&mut self, key: &K) -> Option<CacheEntry> {
        let entry = self.entries.remove(key)?;
        self.total -= entry.size();
        self.claimed -= entry.size();
        if self.use_ledger {
            taiji_io::unverified_budget::release(entry.size());
        }
        if let Some(stale) = self.pos.remove(key) {
            self.index.remove(&stale);
        }
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pooled cells are byte-identical to heap cells (append/len/data),
    /// and Drop returns the block to the pool (a subsequent lease hits —
    /// the return guard behind the write-out/eviction/refetch paths).
    #[test]
    fn pooled_cell_equivalent_to_heap_and_returns_to_pool() {
        let arena = taiji_io::block_arena::BlockArena::new(64 * 1024);
        // Heap baseline.
        let mut heap = DataCell::with_data(100, vec![1u8; 10], 16);
        // Pooled (same data, same capacity).
        let mut pooled = DataCell::with_data_in(100, &[1u8; 10], 16, &arena);
        let r0 = arena.readout();
        assert_eq!(r0.outstanding_blocks, 1, "the pooled cell is outstanding");
        assert_eq!(r0.alloc_fallback_total, 0);
        // Semantic equivalence: len/data/append.
        assert_eq!(pooled.len(), heap.len());
        assert_eq!(pooled.data(), heap.data());
        assert_eq!(
            pooled.try_append(110, &[2u8; 10]),
            heap.try_append(110, &[2u8; 10])
        );
        assert_eq!(pooled.data(), heap.data(), "byte-identical after append");
        assert_eq!(pooled.len(), 16);
        assert_eq!(
            pooled.try_append(116, &[3u8; 4]),
            0,
            "the capacity red line matches"
        );
        // Non-contiguous refusals match.
        assert_eq!(pooled.try_append(0, &[9u8; 4]), 0);
        // Over-main-bucket capacity falls back to heap (semantics
        // unchanged).
        let big = DataCell::with_data_in(0, &[5u8; 100], 17 * 1024, &arena);
        assert_eq!(big.data(), &[5u8; 100]);
        // Drop returns → the next lease hits.
        drop(pooled);
        let r = arena.readout();
        assert_eq!(
            r.outstanding_blocks, 0,
            "dropping the cell returns the block"
        );
        let lease = arena.lease(16);
        assert_eq!(
            arena.readout().lease_hits_total,
            1,
            "the returned block is reused"
        );
        drop(lease);
    }

    /// Shared-cell adoption: the adopted `Bytes` becomes the cell
    /// storage with zero placement copies. Lifetime is
    /// reference-counted — a view (slice) held past the cell's drop
    /// keeps the arena block outstanding (no use-after-free by
    /// construction: the last view's drop is the return point), and
    /// the exact-capacity cell has zero append room (the immutable
    /// storage is never reached by the append face).
    #[test]
    fn shared_cell_adoption_lifetime_and_append_room() {
        let arena = taiji_io::block_arena::BlockArena::new(64 * 1024);
        let bytes = {
            let mut lease = arena.lease(taiji_io::block_arena::BLOCK_SIZE);
            lease.push_bytes(&[7u8; taiji_io::block_arena::BLOCK_SIZE]);
            lease.freeze(taiji_io::block_arena::BLOCK_SIZE)
        };
        let mut cell = DataCell::with_shared(4096, bytes.clone());
        assert_eq!(cell.goff(), 4096);
        assert_eq!(cell.len(), taiji_io::block_arena::BLOCK_SIZE);
        assert_eq!(
            cell.data(),
            &bytes[..],
            "adoption is the storage, zero copies"
        );
        assert_eq!(
            arena.readout().outstanding_blocks,
            1,
            "the wire lease stays outstanding while adopted (the cell holds it)"
        );
        // Exact capacity: no room — append refuses regardless of
        // contiguity (immutable storage never written through).
        let end = 4096 + taiji_io::block_arena::BLOCK_SIZE as u64;
        assert_eq!(cell.try_append(end, b"tail"), 0);
        // A view held past the cell's drop delays the pool return.
        let view = bytes.slice(0..8);
        drop(bytes);
        drop(cell);
        assert_eq!(
            arena.readout().outstanding_blocks,
            1,
            "no return while a view is held (reference-counted lifetime)"
        );
        drop(view);
        assert_eq!(
            arena.readout().outstanding_blocks,
            0,
            "releasing the last view returns the block"
        );
        // Clone deep-copies into independent heap storage (pool
        // untouched).
        let b2 = bytes::Bytes::from_static(b"abcdefgh");
        let c2 = DataCell::with_shared(0, b2.clone());
        let c3 = c2.clone();
        assert_eq!(c2.data(), c3.data());
        drop(c2);
        assert_eq!(
            c3.data(),
            b"abcdefgh",
            "the original data is unaffected after clone"
        );
    }

    /// Cell contiguous extension is bounded by capacity
    /// (`WrDiskCacheEntry.cc`).
    #[test]
    fn cell_append_respects_capacity_and_contiguity() {
        let mut cell = DataCell::with_data(100, vec![1u8; 10], 16);
        assert_eq!(cell.len(), 10);
        // Contiguous + room → fully absorbed.
        assert_eq!(cell.try_append(110, &[2u8; 10]), 6);
        assert_eq!(cell.len(), 16);
        // Full → 0.
        assert_eq!(cell.try_append(116, &[3u8; 4]), 0);
        // Non-contiguous → 0.
        let mut other = DataCell::with_data(0, vec![1u8; 4], 16);
        assert_eq!(other.try_append(5, &[2u8; 4]), 0);
    }

    /// P0 regression: an over-capacity cell (a release-only state — the
    /// constructors only `debug_assert` `len <= capacity`) must not make
    /// `try_append` wrap `capacity - len` into a huge room (silent
    /// over-capacity growth in release; a subtraction-overflow panic in
    /// debug). The state is built by direct field construction so the
    /// test also runs in debug builds, where the public constructors
    /// would `debug_assert` first: the contiguous append must absorb
    /// nothing (return 0, len unchanged) and the contiguity refusal must
    /// keep returning 0.
    #[test]
    fn over_capacity_cell_does_not_panic_and_absorbs_nothing() {
        let mut cell = DataCell {
            goff: 0,
            data: CellBuf::Heap(vec![1u8; 32]),
            capacity: 16,
        };
        assert_eq!(cell.len(), 32);
        // Contiguous cursor (0 + 32 == 32): room saturates to 0.
        assert_eq!(
            cell.try_append(32, &[2u8; 8]),
            0,
            "over-capacity state must not wrap into a huge room"
        );
        assert_eq!(cell.len(), 32, "append must not grow the cell further");
        // Non-contiguous refusal unchanged.
        assert_eq!(cell.try_append(0, &[3u8; 4]), 0);

        // Release leg through the public constructors (debug builds
        // panic at their `debug_assert` — documented in `# Panics`):
        // construction must not panic, and a following contiguous
        // append must stay a no-op.
        #[cfg(not(debug_assertions))]
        {
            let mut heap = DataCell::with_data(0, vec![7u8; 32], 16);
            assert_eq!(heap.try_append(32, &[8u8; 8]), 0);
            assert_eq!(heap.len(), 32);
            let arena = taiji_io::block_arena::BlockArena::new(64 * 1024);
            let mut pooled = DataCell::with_data_in(0, &[9u8; 32], 16, &arena);
            assert_eq!(pooled.try_append(32, &[1u8; 8]), 0);
        }
    }

    /// entry.append only extends the last cell; cache_data refuses a
    /// duplicate goff (`WrDiskCacheEntry.cc`).
    #[test]
    fn entry_cache_and_append() {
        let mut e = CacheEntry::default();
        assert!(e.cache_data(DataCell::with_data(0, vec![1u8; 8], 16)));
        assert!(
            !e.cache_data(DataCell::with_data(0, vec![9u8; 8], 8)),
            "same goff refused"
        );
        assert_eq!(e.size(), 8);
        // Contiguous: absorbed.
        assert_eq!(e.append(8, &[2u8; 8]), 8);
        assert_eq!(e.size(), 16);
        // Non-contiguous: not absorbed.
        assert_eq!(e.append(20, &[3u8; 4]), 0);
        assert_eq!(e.cells().len(), 1, "still exactly one cell");
        assert!(e.cells()[0].goff() == 0);
    }

    /// add duplicate refusal / remove returns cells / negative delta
    /// (flush semantics: -size then clear cells, mirroring `Piece.cc`
    /// flushWrCache).
    #[test]
    fn add_remove_and_negative_update() {
        let mut c: WrDiskCache<u32> = WrDiskCache::new(1024);
        assert!(c.add(1));
        assert!(!c.add(1), "duplicate registration refused");
        c.entry_mut(&1)
            .unwrap_or_else(|| panic!("added"))
            .cache_data(DataCell::with_data(0, vec![0u8; 100], 100));
        let _ = c.update_min_loss(&1, 100);
        assert_eq!(c.total(), 100);
        // Flush: update(-size) + clear cells (together total drops 100).
        let size = c.entry(&1).map_or(0, CacheEntry::size) as isize;
        let _ = c.update_min_loss(&1, -size);
        c.entry_mut(&1).unwrap_or_else(|| panic!("added")).clear();
        assert_eq!(c.total(), 0);
        let entry = c.remove(&1);
        assert!(entry.is_some());
        assert!(c.remove(&1).is_none());
    }

    // proptest: under arbitrary add/update_min_loss/remove sequences —
    // 1) after accounting, total ≤ limit, or only protected size>0
    // entries remain (the min-loss contract: the protected key cannot
    // self-evict; the excess converges on the next update); 2) entry
    // cells are goff ascending and non-overlapping; 3) total ==
    // Σ entry.size.
    proptest::proptest! {
        #[test]
        fn invariants_hold_under_random_operations(ops in proptest::prelude::prop::collection::vec(
            (0u8..3, 0u32..4, 0u64..8, 1usize..64usize),
            0..64,
        )) {
            let mut c: WrDiskCache<u32> = WrDiskCache::new(256);
            for (op, key, goff, len) in ops {
                match op {
                    0 => {
                        c.add(key);
                        let appended = c.entry_mut(&key).unwrap_or_else(|| panic!("added")).append(goff * 1000, &vec![0u8; len]);
                        let _ = c.update_min_loss(&key, appended as isize);
                        if appended < len {
                            let cell = DataCell::with_data(goff * 1000 + appended as u64, vec![0u8; len - appended], len);
                            let cached = c.entry_mut(&key).unwrap_or_else(|| panic!("added")).cache_data(cell);
                            if cached {
                                let _ = c.update_min_loss(&key, (len - appended) as isize);
                            }
                        }
                    }
                    1 => {
                        // Flush semantics (Piece.cc): clear cells first,
                        // then report -size, keeping the
                        // total == Σ entry.size invariant.
                        let size = c.entry(&key).map_or(0, CacheEntry::size);
                        if size > 0 {
                            c.entry_mut(&key).unwrap_or_else(|| panic!("exists")).clear();
                            let _ = c.update_min_loss(&key, -(size as isize));
                        }
                    }
                    _ => {
                        let _ = c.remove(&key);
                    }
                }
                let live = c.entries.values().filter(|e| e.size() > 0).count();
                assert!(
                    c.total() <= c.limit() || live <= 1,
                    "total {} > limit {} and live entries {} > 1",
                    c.total(),
                    c.limit(),
                    live
                );
                for key in c.index.values() {
                    if let Some(e) = c.entries.get(key) {
                        let cells = e.cells();
                        assert!(cells.windows(2).all(|w| w[0].goff() + w[0].len() as u64 <= w[1].goff()),
                            "cells must be ascending and non-overlapping");
                    }
                }
                let sum: usize = c.entries.values().map(CacheEntry::size).sum();
                assert_eq!(sum, c.total());
                // Reverse-map mirror invariant: pos and index have equal
                // cardinality and map entry-by-entry.
                assert_eq!(
                    c.pos.len(),
                    c.index.len(),
                    "the reverse map has the same cardinality as index"
                );
                for (k, ik) in &c.pos {
                    assert_eq!(
                        c.index.get(ik),
                        Some(k),
                        "each reverse-map entry must mirror index"
                    );
                }
            }
        }
    }
    /// Process-wide unverified-byte ledger (cross-surface yielding
    /// semantics): (a) in-cap growth evicts nothing (existing behavior);
    /// (b) global over-cap → this face self-evicts LRU (non-protected
    /// keys evicted, protected keys survive); (c) nothing to yield →
    /// force-claim (soft cap, no data dropped); (d) Drop/negative deltas
    /// release everything, used() returns to baseline.
    #[test]
    fn global_ledger_self_eviction_and_release() {
        let key = |p: u32| (p, 0u16);
        // Real-flow shape: cells append first (entry.size grows), then
        // update reports.
        let grow = |c: &mut WrDiskCache<(u32, u16)>, k: (u32, u16), n: usize| {
            let start = c.entry(&k).map_or(0, CacheEntry::size) as u64;
            let appended = c
                .entry_mut(&k)
                .unwrap_or_else(|| panic!("added"))
                .append(start, &vec![0u8; n]);
            if appended < n {
                let cell = DataCell::with_data(start, vec![0u8; n - appended], n);
                assert!(
                    c.entry_mut(&k)
                        .unwrap_or_else(|| panic!("added"))
                        .cache_data(cell),
                    "an empty entry's first span / a full entry's new span goes through cache_data (goff={start})"
                );
            }
            c.update_min_loss(&k, n as isize)
        };
        // (a) In cap: two-key growth, zero evictions.
        let mut a = WrDiskCache::new_with_ledger_for_tests(1024);
        assert!(a.add(key(1)));
        assert!(a.add(key(2)));
        let base = global_ledger_used_baseline();
        assert!(grow(&mut a, key(1), 100).is_empty());
        assert!(grow(&mut a, key(2), 100).is_empty());
        assert_eq!(
            global_ledger_used_baseline() - base,
            200,
            "both keys on the ledger: 200B"
        );

        // (b) Fill the ledger globally → new growth refused → self-evict
        // the oldest non-protected key (key1 is older than key2 in touch
        // order). Fill = cap - 1B of headroom.
        let fill = (global_ledger_cap() as i64 - 1) - global_ledger_used_baseline();
        assert!(
            fill > 0,
            "parallel tests must leave at least 1B of headroom inside the cap"
        );
        global_ledger_force_fill(fill as usize);
        let evicted = grow(&mut a, key(2), 50);
        assert!(
            !evicted.is_empty(),
            "global over-cap must self-yield (protected keys survive under the soft cap)"
        );
        assert_eq!(
            evicted[0].key,
            key(1),
            "victim = the oldest non-protected key"
        );

        // (c) Empty self, then over-cap growth → force-claim (nothing
        // dropped).
        let mut b = WrDiskCache::new_with_ledger_for_tests(1024);
        assert!(b.add(key(9)));
        let evicted = grow(&mut b, key(9), 50);
        assert!(
            evicted.is_empty(),
            "nothing to yield = force-claim evicts nothing"
        );
        assert_eq!(b.total(), 50, "data retained");

        // (d) Release back to baseline: negative delta + Drop + the fill
        // returned.
        let sz = a.entry(&key(2)).map_or(0, CacheEntry::size) as isize;
        a.update_min_loss(&key(2), -sz);
        drop(a);
        drop(b);
        global_ledger_release_fill(fill as usize);
        assert_eq!(
            global_ledger_used_baseline(),
            base,
            "back to baseline after full release (the Drop fallback plus manual release)"
        );
    }

    fn global_ledger_used_baseline() -> i64 {
        taiji_io::unverified_budget::used()
    }

    fn global_ledger_cap() -> usize {
        taiji_io::unverified_budget::cap_value()
    }

    fn global_ledger_force_fill(bytes: usize) {
        taiji_io::unverified_budget::force_claim(bytes);
    }

    fn global_ledger_release_fill(bytes: usize) {
        taiji_io::unverified_budget::release(bytes);
    }
}

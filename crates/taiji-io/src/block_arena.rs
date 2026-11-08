//! BlockArena: block-buffer arena pool (eliminates per-block VM churn).
//!
//! Upstream anchors (libtorrent pooling motif):
//! - Size-bucketed free lists with malloc fallback when the pool is empty:
//!   libtorrent `packet_pool::acquire/release` dispatches by allocation
//!   size (`include/libtorrent/aux_/packet_pool.hpp`). This implementation
//!   keeps two buckets (1KiB control frames / 16KiB main); over-main
//!   allocations bypass the pool (oversized bitfields / extension metadata
//!   are low-frequency, once per connection).
//! - Block size 16KiB: `default_block_size = 0x4000`
//!   (`include/libtorrent/disk_interface.hpp`; taiji merkle BLOCK_SIZE is
//!   the same value).
//! - malloc-direct + free reuse with in-use accounting (`m_in_use`):
//!   `src/disk_buffer_pool.cpp` (allocate_buffer_impl / free_buffer). The
//!   libtorrent 2.x "pool" is allocator-level reuse plus watermark
//!   accounting; this crate lifts reuse above the allocator into an
//!   explicit free list, so mmap/munmap/first-touch page faults go to zero
//!   at steady state regardless of allocator behavior.
//!
//! Discipline:
//! - No unsafe: the pool is a `Vec<Box<[u8; N]>>` free list inside a
//!   `Mutex`; the [`BlockLease`] rental returns through a `Drop` guard
//!   (reference count to zero = owner drop = return; the
//!   [`Bytes::from_owner`] custom-owner pattern, bytes 1.9+).
//! - Memory budget: the pool cap (bytes) is an explicit component of a
//!   face's unverified-byte budget (sized on the same basis as the write
//!   cache `BH_WR_CACHE_BYTES`, see engine `pipeline.rs`
//!   `block_arena_for_face`): rented bytes stay <= the cap (over-cap falls
//!   back to direct allocation, counted in `alloc_fallback_total`); the
//!   free-list block counts are bounded by the same cap. A face's budget =
//!   write-cache cap + pool cap (both demand-grown, never preallocated;
//!   watermarks exposed via [`BlockArena::readout`] and the
//!   `taiji_block_arena_*` metrics).
//! - Kill switch: `BH_BLOCK_ARENA=0` (recognized at the engine assembly
//!   point) => the face builds no pool and the wire/cell sides fall back
//!   to direct allocation (existing behavior, unchanged).
//! - Page-returnable main bucket: the 16KiB blocks are individual
//!   anonymous mmaps (memmap2 `MmapMut`), so memory leaves with the
//!   drop — munmap returns the pages on every unix. musl mallocng
//!   retains freed size-class groups (measured: 4,000 x 16KiB freed =>
//!   RSS unchanged on ext-server/musl 1.2.x), so heap-backed blocks cannot
//!   shrink RSS at all; the mapping-backed form also drops the fresh
//!   block's 16KiB zeroing (anon pages arrive zero lazily).
//!   [`BlockArena::release_idle`] (the download-complete hook) drops
//!   idle main blocks beyond a small floor; the small bucket (1KiB,
//!   sub-page — a mapping per block would waste 4x) stays heap-backed
//!   and release truncates its free list instead.
//!
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;

/// Main bucket size: the 16KiB BT block (`default_block_size = 0x4000`,
/// libtorrent `disk_interface.hpp`).
pub const BLOCK_SIZE: usize = 16 * 1024;

/// Main-bucket block: one 16KiB anonymous mapping (see the module docs'
/// storage note). Built through [`main_block_mapping`].
type MainBlock = memmap2::MmapMut;

/// Idle-release floor for the main bucket (blocks kept after
/// [`BlockArena::release_idle`]; seeding-phase stragglers — a late block
/// here, a large control frame there — refault lazily from an empty
/// pool anyway, the floor just keeps the common ones free of the mmap
/// round-trip).
const MAIN_IDLE_FLOOR: usize = 16;

/// Idle-release floor for the small bucket (blocks kept after
/// [`BlockArena::release_idle`]; seeding-phase control frames —
/// request/have/reject bodies — keep hitting the 1KiB bucket, the floor
/// absorbs them without per-frame realloc churn).
const SMALL_IDLE_FLOOR: usize = 256;

/// Secondary bucket size: control-frame level (have/request/cancel/choke
/// payloads are <= 17B; a 1KiB bucket absorbs them, avoiding a 64x blow-up
/// in the 16KiB main bucket; the libtorrent `packet_pool::alloc` size-tier
/// dispatch motif, `packet_pool.hpp`).
const SMALL: usize = 1024;

/// Pool readout snapshot (each atomic read independently; fields are not
/// cross-field consistent — metrics only, never assert on them).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ArenaReadout {
    /// Pool hits (free-list pop and reuse) cumulative.
    pub lease_hits_total: u64,
    /// Fresh allocations on an empty pool (still pooled; a hit source after return).
    pub alloc_fresh_total: u64,
    /// Direct-allocation fallbacks (over budget / over main bucket; never pooled).
    pub alloc_fallback_total: u64,
    /// Currently outstanding (leased, unreturned) blocks (watermark gauge).
    pub outstanding_blocks: u64,
    /// Currently outstanding leased bytes (watermark gauge; accounted by bucket size).
    pub outstanding_bytes: u64,
    /// Pool cap in bytes (a component of the face's unverified-byte budget).
    pub cap_bytes: u64,
    /// Cumulative bytes handed back to the OS by [`BlockArena::release_idle`]
    /// (the download-complete memory-release face).
    pub released_idle_bytes_total: u64,
}

#[derive(Debug, Default)]
struct ArenaState {
    // Box keeps lease/checkin a pointer move (the spec-mandated shape
    // `Vec<Box<[u8; 16384]>>`); with a bare `Vec<[u8; N]>`, pop/push would
    // add a full-block memcpy per lease (16KiB — same order as the copy
    // home), hence the deliberate Box — a granted clippy::vec_box exception.
    // Only the small bucket needs the attribute: the main bucket is mapping
    // storage (not Box), where the lint never fires.
    #[expect(
        clippy::vec_box,
        reason = "boxed on purpose: pop/push must stay a pointer move"
    )]
    free_small: Vec<Box<[u8; SMALL]>>,
    free_main: Vec<MainBlock>,
}

/// Size buckets (the libtorrent `packet_pool::alloc` size-tier dispatch,
/// `packet_pool.hpp` — two of its three slab tiers + direct-alloc fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Small,
    Main,
}

impl Bucket {
    fn size(self) -> u64 {
        match self {
            Bucket::Small => SMALL as u64,
            Bucket::Main => BLOCK_SIZE as u64,
        }
    }
}

/// `len` -> bucket (None = over the main bucket, direct-alloc fallback).
fn bucket_for(len: usize) -> Option<Bucket> {
    if len <= SMALL {
        Some(Bucket::Small)
    } else if len <= BLOCK_SIZE {
        Some(Bucket::Main)
    } else {
        None
    }
}

/// Face-level block buffer pool (thread-safe; hot-path critical sections
/// are free-list pop/push only, never across an await — lock discipline).
pub struct BlockArena {
    state: Mutex<ArenaState>,
    /// Free-list block cap (main) = cap_bytes / BLOCK_SIZE.
    cap_blocks_main: usize,
    cap_blocks_small: usize,
    hits: AtomicU64,
    fresh: AtomicU64,
    fallbacks: AtomicU64,
    outstanding_blocks: AtomicU64,
    outstanding_bytes: AtomicU64,
    cap_bytes: u64,
    released_idle_bytes: AtomicU64,
}

impl std::fmt::Debug for BlockArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockArena")
            .field("readout", &self.readout())
            .finish()
    }
}

/// The three shapes of a leased buffer (2 pooled buckets + direct-alloc fallback).
enum Leased {
    Small(Box<[u8; SMALL]>),
    Main(MainBlock),
    /// Over-budget fallback at main-bucket size: a fresh anonymous
    /// mapping that is NOT pooled (no budget claimed at lease); Drop
    /// munmaps it, so budget-overflow churn leaves no resident residue
    /// (musl mallocng keeps freed size-class groups — a heap fallback
    /// would ride RSS at the churn high-water forever).
    ScratchMain(MainBlock),
    /// Fallback: plain heap allocation when over the main bucket (the
    /// low-frequency large-frame path); Drop does not pool it.
    Heap(Vec<u8>),
}

impl Leased {
    fn as_slice(&self) -> &[u8] {
        match self {
            Leased::Small(b) => &b[..],
            Leased::Main(b) => &b[..],
            Leased::ScratchMain(b) => &b[..],
            Leased::Heap(v) => v.as_slice(),
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Leased::Small(b) => &mut b[..],
            Leased::Main(b) => &mut b[..],
            Leased::ScratchMain(b) => &mut b[..],
            Leased::Heap(v) => v.as_mut_slice(),
        }
    }

    fn capacity(&self) -> usize {
        match self {
            Leased::Small(_) => SMALL,
            Leased::Main(_) => BLOCK_SIZE,
            Leased::ScratchMain(_) => BLOCK_SIZE,
            Leased::Heap(v) => v.len(),
        }
    }
}

/// Return guard: when the lease/Bytes reference count hits zero, the pool
/// gets the buffer back through this Drop (the guard invariant — every
/// ownership endpoint across cell flush/evict/re-fetch converges here).
struct LeaseInner {
    buf: Leased,
    /// None = direct-alloc fallback (no pool to return to).
    arena: Option<Arc<BlockArena>>,
    /// Valid byte length (lease form; carried by the Bytes view after `freeze`).
    len: usize,
}

impl LeaseInner {
    fn push_bytes(&mut self, data: &[u8]) -> usize {
        // Saturating room (same wrap defense as cache::DataCell::
        // try_append): `len` only grows through this method and is
        // bounded by capacity, so the subtraction cannot wrap today —
        // saturate anyway so a hypothetical over-fill state truncates to
        // "absorbs nothing" instead of wrapping into a huge room and
        // slicing out of range. Zero-room early-exit also skips the
        // pointless empty-slice copy on a full lease.
        let room = self.buf.capacity().saturating_sub(self.len);
        if room == 0 {
            return 0;
        }
        let n = room.min(data.len());
        self.buf.as_mut_slice()[self.len..self.len + n].copy_from_slice(&data[..n]);
        self.len += n;
        n
    }
}

impl Drop for LeaseInner {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.take() {
            // By-value return: an empty-Vec `Heap` placeholder (zero-cost)
            // swaps the box out, so checkin moves the buffer without
            // allocating a fresh block-sized zeroed replacement (the old
            // `mem::replace` shape paid one zeroed 16KiB alloc per checkin).
            let buf = std::mem::replace(&mut self.buf, Leased::Heap(Vec::new()));
            arena.checkin(buf);
        }
    }
}

impl AsRef<[u8]> for LeaseInner {
    /// Full-capacity view (`Bytes::from_owner` reads it once; the caller
    /// slices `..len` for the logical length — bytes crate contract: the
    /// owner's as_ref is called exactly once).
    fn as_ref(&self) -> &[u8] {
        self.buf.as_slice()
    }
}

/// Custom owner for [`Bytes::from_owner`]: when the last `Bytes` clone
/// drops, the buffer returns to the pool via `LeaseInner::drop`.
struct LeaseOwner(LeaseInner);

impl AsRef<[u8]> for LeaseOwner {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Block lease: exclusive handle to a pooled (or fallback) buffer. Dual
/// use — 1) after writing, [`BlockLease::freeze`] turns it into an
/// arena-returning [`Bytes`] (the wire decoded-frame-body surface);
/// 2) hold it directly as a growable buffer (the cache cell surface);
/// Drop returns it.
pub struct BlockLease {
    inner: Option<LeaseInner>,
}

impl std::fmt::Debug for BlockLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Some(inner) => f
                .debug_struct("BlockLease")
                .field("capacity", &inner.buf.capacity())
                .field("len", &inner.len)
                .field("pooled", &inner.arena.is_some())
                .finish(),
            None => f.write_str("BlockLease(frozen)"),
        }
    }
}

impl BlockLease {
    fn new(buf: Leased, arena: Option<Arc<BlockArena>>) -> BlockLease {
        BlockLease {
            inner: Some(LeaseInner { buf, arena, len: 0 }),
        }
    }

    /// Full-capacity writable view (for filling; valid length is accounted
    /// by [`Self::push_bytes`]/[`Self::freeze`]). `None` = already frozen
    /// (unreachable by construction; debug_assert backstop, benign empty
    /// slice).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.inner {
            Some(inner) => inner.buf.as_mut_slice(),
            None => {
                debug_assert!(false, "lease already frozen");
                &mut []
            }
        }
    }

    /// Number of bytes filled.
    pub fn len(&self) -> usize {
        self.inner.as_ref().map_or(0, |i| i.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lease capacity (pooled = bucket size; heap = direct-alloc length).
    pub fn capacity(&self) -> usize {
        self.inner.as_ref().map_or(0, |i| i.buf.capacity())
    }

    /// Append at the tail (the cache cell surface's `extend_from_slice`
    /// equivalent); returns how many bytes were actually absorbed (a short
    /// lease capacity absorbs only part — the cell capacity invariant is
    /// enforced above, see `cache::DataCell::try_append`).
    pub fn push_bytes(&mut self, data: &[u8]) -> usize {
        match &mut self.inner {
            Some(inner) => inner.push_bytes(data),
            None => {
                debug_assert!(false, "lease already frozen");
                0
            }
        }
    }

    /// View of the filled region.
    pub fn filled(&self) -> &[u8] {
        match &self.inner {
            Some(inner) => &inner.buf.as_slice()[..inner.len],
            None => {
                debug_assert!(false, "lease already frozen");
                &[]
            }
        }
    }

    /// Turn into an arena-returning `Bytes`: the pool gets the buffer back
    /// when the reference count hits zero (the last clone drops). `len` =
    /// valid prefix (the view is sliced `..len`).
    pub fn freeze(mut self, len: usize) -> Bytes {
        let Some(inner) = self.inner.take() else {
            debug_assert!(false, "lease already frozen");
            return Bytes::new();
        };
        assert!(
            len <= inner.buf.capacity(),
            "freeze len {len} over capacity"
        );
        let bytes = Bytes::from_owner(LeaseOwner(inner));
        if len == bytes.len() {
            bytes
        } else {
            bytes.slice(..len)
        }
    }
}

impl Drop for BlockLease {
    fn drop(&mut self) {
        // inner's Drop is the return guard.
        self.inner.take();
    }
}

impl BlockArena {
    /// Build the pool: `cap_bytes` = the outstanding-rented-bytes cap (a
    /// component of the face's unverified-byte budget; see the module doc's
    /// memory budget). Free-list caps derive from the cap (main:
    /// cap/16KiB blocks; small: cap/1KiB blocks). Zero preallocation —
    /// everything is demand-grown.
    pub fn new(cap_bytes: u64) -> Arc<BlockArena> {
        Arc::new(BlockArena {
            state: Mutex::new(ArenaState::default()),
            cap_blocks_main: (cap_bytes as usize / BLOCK_SIZE).max(1),
            cap_blocks_small: (cap_bytes as usize / SMALL).max(1),
            hits: AtomicU64::new(0),
            fresh: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            outstanding_blocks: AtomicU64::new(0),
            outstanding_bytes: AtomicU64::new(0),
            cap_bytes,
            released_idle_bytes: AtomicU64::new(0),
        })
    }

    /// Lease a block fitting `len` bytes. Pooled (<= main bucket) leases are
    /// budget-bound — over budget -> direct-alloc fallback; pool empty ->
    /// fresh allocation (pooled on return). `len > BLOCK_SIZE` -> always
    /// the direct-alloc fallback (low-frequency large frames).
    pub fn lease(self: &Arc<Self>, len: usize) -> BlockLease {
        let Some(bucket) = bucket_for(len) else {
            return self.fallback_lease(len);
        };
        if !self.claim_budget(bucket.size()) {
            return self.fallback_lease(len);
        }
        // None = the main bucket could not grow a fresh mapping (the
        // exhausted-resource degrade; see `main_block_mapping`) — the
        // caller rolls the budget back and takes the fallback lease.
        let leased_opt = {
            let mut state = crate::lock(&self.state);
            match bucket {
                Bucket::Small => Some(match state.free_small.pop() {
                    Some(b) => (Leased::Small(b), true),
                    None => (Leased::Small(Box::new([0u8; SMALL])), false),
                }),
                Bucket::Main => match state.free_main.pop() {
                    Some(b) => Some((Leased::Main(b), true)),
                    None => main_block_mapping().map(|m| (Leased::Main(m), false)),
                },
            }
        };
        let Some((leased, hit)) = leased_opt else {
            self.outstanding_bytes
                .fetch_sub(bucket.size(), Ordering::Relaxed);
            return self.fallback_lease(len);
        };
        if hit {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.fresh.fetch_add(1, Ordering::Relaxed);
        }
        self.outstanding_blocks.fetch_add(1, Ordering::Relaxed);
        BlockLease::new(leased, Some(Arc::clone(self)))
    }

    /// Direct-alloc fallback: never pooled, counted for observability (the
    /// exception path of "zero per-block malloc"). Main-bucket sizes get
    /// the mapping form (drop = munmap = pages returned); larger sizes
    /// keep the plain `Vec`.
    fn fallback_lease(&self, len: usize) -> BlockLease {
        self.fallbacks.fetch_add(1, Ordering::Relaxed);
        let leased = if len <= BLOCK_SIZE {
            match main_block_mapping() {
                Some(m) => Leased::ScratchMain(m),
                None => Leased::Heap(vec![0u8; len]),
            }
        } else {
            Leased::Heap(vec![0u8; len])
        };
        BlockLease::new(leased, None)
    }

    /// Atomically claim outstanding-byte budget (fetch_add then test, roll
    /// back over the limit) — the cap is strict, a full pool falls back to
    /// direct allocation (the observable exception path).
    fn claim_budget(&self, bucket: u64) -> bool {
        let prev = self.outstanding_bytes.fetch_add(bucket, Ordering::Relaxed);
        if prev + bucket <= self.cap_bytes {
            true
        } else {
            self.outstanding_bytes.fetch_sub(bucket, Ordering::Relaxed);
            false
        }
    }

    /// Return (`LeaseInner::drop` guard endpoint): pool for reuse if the
    /// free list has room, otherwise release outright (the block-count cap
    /// bounds the free list — a dropped main mapping munmaps back to the
    /// OS, so cap overflow during churn leaves no resident residue).
    fn checkin(&self, buf: Leased) {
        let mut state = crate::lock(&self.state);
        match buf {
            Leased::Small(b) => {
                self.outstanding_blocks.fetch_sub(1, Ordering::Relaxed);
                self.outstanding_bytes
                    .fetch_sub(SMALL as u64, Ordering::Relaxed);
                if state.free_small.len() < self.cap_blocks_small {
                    state.free_small.push(b);
                }
            }
            Leased::Main(b) => {
                self.outstanding_blocks.fetch_sub(1, Ordering::Relaxed);
                self.outstanding_bytes
                    .fetch_sub(BLOCK_SIZE as u64, Ordering::Relaxed);
                if state.free_main.len() < self.cap_blocks_main {
                    state.free_main.push(b);
                }
            }
            // Non-pooled fallbacks (no budget claimed at lease, no
            // outstanding accounting): drop = munmap (mapping form) /
            // allocator-owned (heap form).
            Leased::ScratchMain(_) | Leased::Heap(_) => {}
        }
    }

    /// Release idle (free-list resident) memory back to the OS — the
    /// download-complete hook: a face entering seeding needs none of the
    /// download-phase block working set, so the idle main mappings beyond
    /// a small floor munmap away (pages returned on every unix) and the
    /// small free list truncates to its floor. Kept: the floor blocks
    /// (straggler absorption without an mmap round-trip), the outstanding
    /// leases, and every cap (a later burst regrows the pool on demand).
    ///
    /// Returns the bytes handed back. Idempotent; safe under concurrency
    /// — only free-list blocks are touched (a concurrent lease pops under
    /// the same lock first; outstanding leases are untouched).
    pub fn release_idle(&self) -> u64 {
        let mut released: u64 = 0;
        {
            let mut state = crate::lock(&self.state);
            if state.free_main.len() > MAIN_IDLE_FLOOR {
                let dropped = state.free_main.len() - MAIN_IDLE_FLOOR;
                state.free_main.truncate(MAIN_IDLE_FLOOR);
                released += dropped as u64 * BLOCK_SIZE as u64;
            }
            if state.free_small.len() > SMALL_IDLE_FLOOR {
                let dropped = state.free_small.len() - SMALL_IDLE_FLOOR;
                state.free_small.truncate(SMALL_IDLE_FLOOR);
                state.free_small.shrink_to_fit();
                released += dropped as u64 * SMALL as u64;
            }
        }
        if released > 0 {
            self.released_idle_bytes
                .fetch_add(released, Ordering::Relaxed);
        }
        released
    }

    /// Metrics readout (atomic snapshot, not cross-field consistent).
    pub fn readout(&self) -> ArenaReadout {
        ArenaReadout {
            lease_hits_total: self.hits.load(Ordering::Relaxed),
            alloc_fresh_total: self.fresh.load(Ordering::Relaxed),
            alloc_fallback_total: self.fallbacks.load(Ordering::Relaxed),
            outstanding_blocks: self.outstanding_blocks.load(Ordering::Relaxed),
            outstanding_bytes: self.outstanding_bytes.load(Ordering::Relaxed),
            cap_bytes: self.cap_bytes,
            released_idle_bytes_total: self.released_idle_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Fresh main-bucket block: one 16KiB anonymous mapping. The syscall
/// count is identical to the old `Box::new([0u8; 16384])` shape's
/// allocator call, and the lazily-zeroed pages skip the 16KiB memset the
/// Box form paid on every fresh block. None = the mapping could not be
/// created (VMA/fd exhaustion states; unreachable in practice) — the
/// caller degrades to the non-pooled fallback lease, an observable,
/// counted exception path rather than a panic.
fn main_block_mapping() -> Option<MainBlock> {
    memmap2::MmapOptions::new().len(BLOCK_SIZE).map_anon().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Main-bucket storage is a whole anonymous mapping per block: the
    /// exact-length contract the lease/freeze paths rely on.
    #[test]
    fn main_block_mapping_is_exact_length() {
        let b = main_block_mapping().unwrap_or_else(|| panic!("16KiB anon mmap"));
        assert_eq!(b.len(), BLOCK_SIZE);
        assert_eq!(b[..].len(), BLOCK_SIZE);
    }

    /// Release-then-reuse: `release_idle` drops idle main mappings
    /// beyond the floor and truncates the small free list (both counted
    /// on every platform — munmap is universal), and the free list keeps
    /// working — a post-release lease gets a zeroed block with unchanged
    /// lease/freeze semantics.
    #[test]
    fn release_idle_returns_pages_and_keeps_reuse() {
        // Cap large enough that both buckets retain their returns within
        // the shared byte budget (1MiB => main cap 64 blocks, small cap
        // 1024 blocks > the 256-block floor; 20x16KiB + 300x1KiB stays
        // under the 1MiB budget so nothing overflows to fallback).
        let arena = BlockArena::new(1024 * 1024);
        // Grow the free list: lease 20 main blocks (floor keeps 16) +
        // small blocks, return.
        let leases: Vec<_> = (0..20).map(|_| arena.lease(BLOCK_SIZE)).collect();
        let smalls: Vec<_> = (0..300).map(|_| arena.lease(SMALL)).collect();
        drop(leases);
        drop(smalls);
        let before = arena.readout();
        assert_eq!(before.outstanding_blocks, 0);
        let released = arena.release_idle();
        assert_eq!(
            released,
            4 * BLOCK_SIZE as u64 + 44 * SMALL as u64,
            "munmap of main-bucket blocks above the 16-block floor + truncation of small-bucket blocks above floor"
        );
        let after = arena.readout();
        assert_eq!(
            after.released_idle_bytes_total, released,
            "readout cumulative semantics match"
        );
        // Reuse still works: fresh leases hit the retained free list,
        // content zeroed (fresh anon mapping semantics), freeze unchanged.
        let mut lease = arena.lease(BLOCK_SIZE);
        assert_eq!(lease.capacity(), BLOCK_SIZE);
        assert!(lease.filled().is_empty());
        lease.push_bytes(b"abc");
        let bytes = lease.freeze(3);
        assert_eq!(&bytes[..], b"abc");
        // Idempotent on a quiet pool: the floor stays, nothing new drops.
        let released_again = arena.release_idle();
        assert_eq!(released_again, 0, "nothing released within the floor");
        drop(bytes);
    }

    /// A concurrent-style outstanding lease is untouched by
    /// `release_idle` (only free-list blocks are released; the
    /// outstanding block's data survives).
    #[test]
    fn release_idle_spares_outstanding_leases() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 8);
        let mut held = arena.lease(BLOCK_SIZE);
        held.push_bytes(&[7u8; 32]);
        let idle = arena.lease(BLOCK_SIZE); // lease + return => idle list entry
        drop(idle);
        let _ = arena.release_idle();
        assert_eq!(
            &held.filled()[..4],
            &[7u8; 4],
            "outstanding block data unaffected by release"
        );
        let bytes = held.freeze(32);
        assert_eq!(&bytes[..], &[7u8; 32]);
    }

    /// Over-budget fallback at main size is a scratch mapping whose drop
    /// returns the pages (munmap): a cap-1 arena overflows to fallback,
    /// and the outstanding accounting stays untouched by the scratch
    /// path.
    #[test]
    fn over_budget_fallback_is_scratch_and_unaccounted() {
        let arena = BlockArena::new(BLOCK_SIZE as u64);
        let held = arena.lease(BLOCK_SIZE); // cap reached
        let fb = arena.lease(BLOCK_SIZE); // over budget -> scratch
        let r = arena.readout();
        assert_eq!(r.alloc_fallback_total, 1);
        assert_eq!(
            r.outstanding_bytes, BLOCK_SIZE as u64,
            "scratch does not count against the budget"
        );
        drop(fb); // Drop munmaps; no pool return, no accounting.
        assert_eq!(arena.readout().outstanding_bytes, BLOCK_SIZE as u64);
        drop(held);
        assert_eq!(arena.readout().outstanding_bytes, 0);
    }

    /// Lease -> freeze -> Bytes drop -> return -> re-lease hits the same
    /// pool block (zero-malloc reuse).
    #[test]
    fn lease_freeze_drop_then_reuse_hits_pool() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 4);
        let bytes = {
            let mut lease = arena.lease(BLOCK_SIZE);
            lease.as_mut_slice()[..4].copy_from_slice(&[1, 2, 3, 4]);
            lease.freeze(4)
        };
        assert_eq!(&bytes[..], &[1, 2, 3, 4]);
        let r = arena.readout();
        assert_eq!(r.outstanding_blocks, 1, "held Bytes count as outstanding");
        assert_eq!(r.alloc_fresh_total, 1);
        drop(bytes);
        let r = arena.readout();
        assert_eq!(
            r.outstanding_blocks, 0,
            "refcount reaching zero returns the block"
        );
        // Re-lease: free-list hit.
        let lease = arena.lease(BLOCK_SIZE);
        let r = arena.readout();
        assert_eq!(r.lease_hits_total, 1);
        assert_eq!(r.alloc_fresh_total, 1, "no fresh allocation");
        assert_eq!(lease.capacity(), BLOCK_SIZE);
        drop(lease);
        assert_eq!(arena.readout().outstanding_blocks, 0);
    }

    /// Multiple Bytes clones share one owner; only the last clone's drop returns it.
    #[test]
    fn bytes_clones_share_owner_until_last_drop() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 4);
        let lease = arena.lease(BLOCK_SIZE);
        let b0 = lease.freeze(BLOCK_SIZE);
        let b1 = b0.clone();
        let b2 = b0.slice(0..8);
        assert_eq!(arena.readout().outstanding_blocks, 1);
        drop(b0);
        drop(b2);
        assert_eq!(arena.readout().outstanding_blocks, 1, "b1 still holds");
        drop(b1);
        assert_eq!(arena.readout().outstanding_blocks, 0);
    }

    /// Over-main-bucket direct-alloc fallback (not pooled, counted).
    #[test]
    fn oversize_lease_falls_back_to_heap() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 4);
        let lease = arena.lease(BLOCK_SIZE + 1);
        assert_eq!(lease.capacity(), BLOCK_SIZE + 1);
        let r = arena.readout();
        assert_eq!(r.alloc_fallback_total, 1);
        assert_eq!(r.outstanding_blocks, 0, "fallback block not pooled");
        drop(lease);
        assert_eq!(arena.readout().outstanding_blocks, 0);
    }

    /// Budget cap: once outstanding bytes reach the cap, leases fall back
    /// to direct allocation; pooling resumes after returns.
    #[test]
    fn budget_cap_enforced_with_fallback() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 2);
        let a = arena.lease(BLOCK_SIZE);
        let b = arena.lease(BLOCK_SIZE);
        assert_eq!(arena.readout().outstanding_bytes, BLOCK_SIZE as u64 * 2);
        // Budget full -> fallback.
        let c = arena.lease(BLOCK_SIZE);
        assert_eq!(c.capacity(), BLOCK_SIZE);
        let r = arena.readout();
        assert_eq!(r.alloc_fallback_total, 1);
        assert_eq!(r.outstanding_blocks, 2, "fallback block not pooled");
        drop(c);
        drop(a);
        assert_eq!(arena.readout().outstanding_bytes, BLOCK_SIZE as u64);
        drop(b);
        assert_eq!(arena.readout().outstanding_bytes, 0);
        // After returns, leasing pools again (hit).
        let d = arena.lease(BLOCK_SIZE);
        assert_eq!(arena.readout().alloc_fallback_total, 1, "no new fallback");
        drop(d);
    }

    /// Small bucket: control-frame-level leases use the 1KiB bucket
    /// (accounted separately from main).
    #[test]
    fn small_bucket_lease_and_reuse() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 4);
        let mut lease = arena.lease(24);
        assert_eq!(lease.capacity(), SMALL);
        assert_eq!(lease.push_bytes(&[7u8; 24]), 24);
        assert_eq!(lease.filled(), &[7u8; 24]);
        let b = lease.freeze(24);
        assert_eq!(b.len(), 24);
        drop(b);
        let again = arena.lease(24);
        assert_eq!(arena.readout().lease_hits_total, 1);
        drop(again);
    }

    /// push_bytes capacity semantics: a full lease truncates (the cell layer
    /// enforces its own capacity invariant above). `lease(8)` rents a 1KiB
    /// bucket (bucket size >= request size — the semantic contract).
    #[test]
    fn push_bytes_respects_lease_capacity() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 4);
        let mut lease = arena.lease(8);
        assert_eq!(lease.capacity(), SMALL);
        // Fill to bucket capacity.
        assert_eq!(lease.push_bytes(&[1u8; SMALL - 2]), SMALL - 2);
        assert_eq!(
            lease.push_bytes(&[2u8; 6]),
            2,
            "only 2 remaining bytes accepted"
        );
        assert_eq!(lease.len(), SMALL);
        assert_eq!(lease.push_bytes(&[3u8; 1]), 0, "full -> 0");
        assert_eq!(&lease.filled()[SMALL - 2..], &[2u8, 2][..]);
    }

    /// Concurrent lease/checkin stress: block counts conserve (outstanding +
    /// free list <= cap), nothing lost.
    #[test]
    fn concurrent_lease_checkin_conserves_blocks() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 8);
        let live = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let arena = Arc::clone(&arena);
            let live = Arc::clone(&live);
            handles.push(std::thread::spawn(move || {
                for _ in 0..2000 {
                    let lease = arena.lease(BLOCK_SIZE);
                    live.fetch_add(1, Ordering::Relaxed);
                    assert!(live.load(Ordering::Relaxed) >= 1);
                    live.fetch_sub(1, Ordering::Relaxed);
                    drop(lease);
                }
            }));
        }
        for h in handles {
            h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
        }
        let r = arena.readout();
        assert_eq!(r.outstanding_blocks, 0);
        assert!(
            r.alloc_fresh_total + r.lease_hits_total + r.alloc_fallback_total == 8 * 2000,
            "exactly one ledger entry per lease: {:?}",
            r
        );
        // After returns the free list is usable: one more lease should hit
        // (free list non-empty).
        let _ = arena.lease(BLOCK_SIZE);
        assert!(arena.readout().lease_hits_total > 0);
    }

    /// Ownership moves on freeze: dropping BlockLease does not return again (freeze took inner).
    #[test]
    fn freeze_moves_ownership_no_double_return() {
        let arena = BlockArena::new(BLOCK_SIZE as u64 * 4);
        let bytes = {
            let lease = arena.lease(BLOCK_SIZE);
            lease.freeze(16)
        };
        drop(bytes);
        assert_eq!(arena.readout().outstanding_blocks, 0);
        // Exactly one pool entry after return (free list = 1): the next
        // lease should hit without panicking.
        let _ = arena.lease(BLOCK_SIZE);
        assert_eq!(arena.readout().lease_hits_total, 1);
    }
}

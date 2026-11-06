//! `taiji-store` — the storage layer (SPEC §5).
//!
//! Responsibilities:
//! - disk writes: `write_all_at` (unix) / `seek_write` positioned writes
//! (Windows); multi-file layout (v2-only compact / v1 / hybrid adopts the
//! v1 layout + `.pad` placeholders); lazy-opened handles +
//! `OpenedFileCounter`;
//! - file allocation: `none|trunc|falloc|prealloc` (Adaptive probes 4 KiB
//! falloc);
//! - write cache: WrDiskCache direct translation (DataCells merged in goff
//! order; eviction = smallest min-loss size first — aria2's largest-first
//! eviction was removed with the min-loss eviction model);
//! - persistence: `taiji.sqlite3` (WAL, `user_version` migration ledger,
//! single-writer PersistWriter, SHA-256 digest dedup skip-write; the
//! `persist` module);
//! - v2 data model: file tree, per-file piece-layer bitmaps, synthetic
//! bitmaps.
//!
//! Red lines: SPEC §2.1 (no global piece index; `.pad` never hits disk),
//! §2.3 (persistence contract: single writer, dedup before write,
//! migrations via the user_version ledger, never writing the aria2-fork
//! store), §2.5 (blocking IO through spawn_blocking / dedicated blocking
//! tasks).
//!
//! This crate must not depend on any other workspace crate.

pub mod cache;
pub mod disk;
pub mod disk_policy;
pub mod error;
pub mod handle_pool;
pub mod hashpool;

pub mod hashtree;
pub mod layout;
pub mod merkle;
pub mod persist;
pub mod precomputed_block_hashes;
pub mod recovery;
pub mod spill;
pub mod torrent_writer;
pub mod verified;

/// Lock-poisoning policy (batch-wide decision): a poisoned `std::sync::Mutex`
/// means a panic happened mid-critical-section and an invariant may be lost —
/// recovery via `into_inner` is not permitted. The `expect` is fatal by
/// policy: the process teardown is carried to its terminal state by the
/// existing panic-watcher, so failing loudly here is the intended behavior.
///
/// All non-test lock acquisitions in this crate must go through this helper
/// (and its [`read_lock`]/[`write_lock`] twins for `RwLock`).
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock()
        .expect("lock poisoned: invariant lost, fail loudly")
}

/// [`RwLock`] twin of [`lock`] (shared side): same poisoning-is-fatal
/// policy, same panic-watcher terminal state.
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn read_lock<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read()
        .expect("lock poisoned: invariant lost, fail loudly")
}

/// [`RwLock`] twin of [`lock`] (exclusive side): same poisoning-is-fatal
/// policy, same panic-watcher terminal state.
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn write_lock<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write()
        .expect("lock poisoned: invariant lost, fail loudly")
}

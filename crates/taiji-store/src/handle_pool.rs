//! OpenedFileCounter: global open-file cap + LRU closing (SPEC §5.1).
//!
//! Reference: aria2 `OpenedFileCounter.cc` counts globally and, over the
//! limit, closes a **random** requesting group (`tryCloseFile`); default
//! 100 (`aria2/src/OptionHandlerFactory.cc` `--bt-max-open-files`).
//! Intentional improvement (SPEC §5.1): this implementation closes LRU
//! (least recently touched first); the remaining semantics (global count,
//! closing as many as newly opened) align with aria2.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::hash::Hash;

/// Handle pool: `K` = file key (path), `V` = an opened handle.
///
/// `opener`/`closer` are injected by the caller (open failures propagate
/// as-is; closing is idempotent).
#[derive(Debug)]
pub struct HandlePool<K: Eq + Hash + Clone + Debug, V> {
    max_open: usize,
    handles: HashMap<K, V>,
    /// LRU order: clock ascending -> key; the front (smallest clock) is the
    /// oldest (least recently touched).
    order: BTreeMap<u64, K>,
    /// Companion reverse lookup for order: key -> its current clock.
    /// touch/close use it to locate the old-order entry in O(1) (a key
    /// appears in order at most once), removing the linear scan by value;
    /// invariant: the pos and order key sets mirror each other exactly and
    /// are maintained in sync only at the write points touch / close /
    /// close_all / ensure_capacity.
    pos: HashMap<K, u64>,
    /// Monotonic clock: +1 per touch (semantics match
    /// [`crate::cache::WrDiskCache`]'s `clock`; each touch takes a fresh
    /// clock value, so equal-clock key collisions cannot happen).
    clock: u64,
}

impl<K: Eq + Hash + Clone + Debug, V> HandlePool<K, V> {
    pub fn new(max_open: usize) -> HandlePool<K, V> {
        HandlePool {
            max_open,
            handles: HashMap::new(),
            order: BTreeMap::new(),
            pos: HashMap::new(),
            clock: 0,
        }
    }

    pub fn max_open(&self) -> usize {
        self.max_open
    }

    pub fn open_count(&self) -> usize {
        self.handles.len()
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.handles.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.touch(key);
        self.handles.get_mut(key)
    }

    /// Get a handle, opening it via `opener` if not open; over capacity,
    /// close by LRU first (the `OpenedFileCounter.cc` counting semantics).
    pub fn get_or_open_with<E>(
        &mut self,
        key: &K,
        opener: impl FnOnce(&K) -> Result<V, E>,
        closer: impl FnMut(K, V),
    ) -> Result<&mut V, E> {
        if !self.handles.contains_key(key) {
            self.ensure_capacity(closer);
            let handle = opener(key)?;
            self.handles.insert(key.clone(), handle);
        }
        // Newly opened and already-open both go through touch to enter /
        // refresh the order (the net effect of the original push_back +
        // touch = the key ends up at the newest end, equivalent).
        self.touch(key);
        Ok(self
            .handles
            .get_mut(key)
            .unwrap_or_else(|| unreachable!("inserted above")))
    }

    /// Close one handle (explicit close / file deletion; idempotent).
    pub fn close(&mut self, key: &K, closer: impl FnOnce(K, V)) {
        if let Some(handle) = self.handles.remove(key) {
            closer(key.clone(), handle);
            if let Some(clock) = self.pos.remove(key) {
                self.order.remove(&clock);
            }
        }
    }

    /// Close all (torrent wrap-up; aria2 `MultiDiskAdaptor::closeFile`
    /// semantics).
    pub fn close_all(&mut self, mut closer: impl FnMut(K, V)) {
        for (k, v) in self.handles.drain() {
            closer(k.clone(), v);
        }
        self.order.clear();
        self.pos.clear();
    }

    /// Capacity guarantee: when one slot must be freed, close by LRU
    /// (`OpenedFileCounter.cc` `numClose = numOpenFiles_ + numNewFiles -
    /// maxOpenFiles_`).
    fn ensure_capacity(&mut self, mut closer: impl FnMut(K, V)) {
        while self.handles.len() >= self.max_open {
            // Smallest clock = least recently touched; pop_first takes the
            // oldest at the front, LRU discipline intact.
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.pos.remove(&oldest);
            if let Some(handle) = self.handles.remove(&oldest) {
                closer(oldest, handle);
            }
        }
    }

    /// Refresh key to the newest end: remove the old clock entry (located
    /// in O(1) via the companion reverse lookup) and re-insert with a new
    /// clock — LRU order and per-object uniqueness preserved, single
    /// O(log n).
    fn touch(&mut self, key: &K) {
        if self.handles.contains_key(key) {
            if let Some(old) = self.pos.remove(key) {
                self.order.remove(&old);
            }
            self.clock += 1;
            self.order.insert(self.clock, key.clone());
            self.pos.insert(key.clone(), self.clock);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LRU closing: capacity 2, opening a third handle closes the least
    /// recently touched (the SPEC §5.1 improvement: aria2
    /// OpenedFileCounter.cc closes randomly).
    #[test]
    fn lru_eviction_closes_oldest_touched() {
        let mut pool: HandlePool<&str, u32> = HandlePool::new(2);
        let mut closed: Vec<&str> = Vec::new();
        let _ = pool.get_or_open_with(&"a", |_| Ok::<u32, ()>(1), |k, _| closed.push(k));
        let _ = pool.get_or_open_with(&"b", |_| Ok::<u32, ()>(2), |k, _| closed.push(k));
        // Touch a (make it newest).
        let _ = pool.get_mut(&"a");
        let _ = pool.get_or_open_with(&"c", |_| Ok::<u32, ()>(3), |k, _| closed.push(k));
        assert_eq!(
            closed,
            ["b"],
            "the least recently touched is closed (a was just touched)"
        );
        assert_eq!(pool.open_count(), 2);
        assert!(pool.get(&"a").is_some());
        assert!(pool.get(&"b").is_none());
        assert!(pool.get(&"c").is_some());
    }

    /// Repeated get_or_open does not re-open; explicit close is idempotent.
    #[test]
    fn idempotent_open_and_close() {
        let mut opened = 0u32;
        let mut pool: HandlePool<u32, ()> = HandlePool::new(4);
        for _ in 0..3 {
            let _ = pool.get_or_open_with(
                &1u32,
                |_| {
                    opened += 1;
                    Ok::<(), ()>(())
                },
                |_, _| {},
            );
        }
        assert_eq!(opened, 1);
        pool.close(&1, |_, _| {});
        pool.close(&1, |_, _| {});
        assert_eq!(pool.open_count(), 0);
    }

    /// Capacity 1: every file switch closes the old one
    /// (OpenedFileCounter.cc counting semantics).
    #[test]
    fn capacity_one_churn() {
        let mut pool: HandlePool<u32, ()> = HandlePool::new(1);
        let mut closed = Vec::new();
        for k in 0..4u32 {
            let _ = pool.get_or_open_with(&k, |_| Ok::<(), ()>(()), |k, _| closed.push(k));
        }
        assert_eq!(closed, [0, 1, 2]);
    }
}

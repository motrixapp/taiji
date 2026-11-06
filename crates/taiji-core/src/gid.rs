//! GID allocator.
//!
//! GIDs the taiji engine allocates are always
//! `random u64 | 0x8000_0000_0000_0000`, output as hex16. Setting the
//! top bit is the foundation of GID-space isolation from the aria2 fork
//! (top bit = 0; the compatibility face is frozen, see SPEC §8.3): the
//! Motrix frontend routes the dual engines by prefix, transparent to
//! clients.
//!
//! Dedup policy: a session-local HashSet membership check (the random
//! space is 2^63, collision probability negligible, but the loop check
//! costs nearly nothing, so it stays). Cross-restart dedup relies on
//! the persistence layer (the session-recovery reserve path); the
//! skeleton stage deliberately does not do it.
//!
//! Ownership constraint: the type/constant vocabulary ([`Gid`]/
//! [`GID_HIGH_BIT`]) is a frozen public face across
//! core{session, engine, hook} and the RPC layer, so it lives in the
//! shared vocabulary layer `taiji_domain::gid` (in-domain modules like
//! hook reference the same source); this module only carries the
//! allocation executor [`GidAllocator`] (rand allocation with a dedup
//! check, held exclusively by SessionActor), with the types re-exported
//! so `taiji_core::gid::Gid` keeps its existing public path unchanged.

use std::collections::HashSet;

pub use taiji_domain::gid::{GID_HIGH_BIT, Gid};

/// GID allocator: held exclusively by SessionActor (lock-free).
#[derive(Debug, Default)]
pub struct GidAllocator {
    used: HashSet<u64>,
}

impl GidAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a new GID: random u64 | high bit 1, deduped against the
    /// allocated set.
    pub fn allocate(&mut self) -> Gid {
        loop {
            let raw = rand::random::<u64>() | GID_HIGH_BIT;
            if self.used.insert(raw) {
                return Gid::from_u64(raw);
            }
        }
    }

    /// Record a foreign GID as used (avoids re-issuing after persisted
    /// recovery: the session-recovery startup paths call this for every
    /// restored torrent/http row before rebuilding it).
    pub fn reserve(&mut self, raw: u64) {
        self.used.insert(raw);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocated_gids_have_high_bit_and_hex16_form() {
        let mut alloc = GidAllocator::new();
        for _ in 0..1000 {
            let gid = alloc.allocate();
            assert_eq!(
                gid.as_u64() & GID_HIGH_BIT,
                GID_HIGH_BIT,
                "high bit must be set"
            );
            assert_eq!(gid.as_u64() & !GID_HIGH_BIT, gid.as_u64() - GID_HIGH_BIT);
            let hex = gid.to_string();
            assert_eq!(hex.len(), 16, "hex16 required, got {hex}");
            assert!(
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
        }
    }

    #[test]
    fn allocations_are_unique_over_volume() {
        let mut alloc = GidAllocator::new();
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let gid = alloc.allocate();
            assert!(seen.insert(gid.as_u64()), "duplicate GID: {gid}");
        }
    }

    #[test]
    fn reserved_values_are_never_reissued() {
        let mut alloc = GidAllocator::new();
        let first = alloc.allocate();
        // Register a "foreign" value as used, proving the dedup path
        // really works.
        let reserved = first.as_u64().rotate_left(1) | GID_HIGH_BIT;
        alloc.reserve(reserved);
        for _ in 0..1000 {
            assert_ne!(alloc.allocate().as_u64(), reserved);
        }
    }
}

//! v2 block-hash write-path precompute table, cross-validated against
//! libtorrent `src/precomputed_block_hashes.cpp`.
//!
//! Stores each block hash at the moment the write path computes it, keyed
//! per face by `(flat piece index, block within piece)`; a completed
//! piece's entry moves out whole with its PieceJob. Rule anchors and the
//! intentional divergences (no hasher thread, key surface, trust
//! unchanged): docs/design/store.md.

use std::collections::HashMap;

/// Per-face precomputed block-hash table: `(flat piece index, block within
/// piece) -> [u8; 32]`.
///
/// Lifetime discipline:
/// - entries exist only while a piece is in flight (lazily allocated at
/// block granularity); at piece completion [`Self::take_piece`] moves the
/// entry out whole with [`PieceJob`](crate::verified::PieceJob)
/// (cross-validation `take`, `precomputed_block_hashes.cpp`);
/// - piece reset/eviction syncs through [`Self::drop_piece`] with the pool
/// reset (cross-validation `drop`, same file) — re-fetched bytes re-enter
/// the table;
/// - an empty table allocates nothing (HashMap empty state); the v1 face /
/// disabled switch carries no table (zero overhead).
#[derive(Debug)]
pub struct PrecomputedBlockHashes {
    /// Slots per piece (`piece_len / 16KiB`; fixed at construction).
    blocks_per_piece: usize,
    /// Flat piece index -> per-block slots (`None` = uncomputed/miss;
    /// lazily allocated, moved out at completion).
    per_piece: HashMap<u64, Box<[Option<[u8; 32]>]>>,
}

impl PrecomputedBlockHashes {
    /// Build a table: `blocks_per_piece` = 16 KiB blocks per piece (BEP-52
    /// constant granularity).
    pub fn new(blocks_per_piece: usize) -> PrecomputedBlockHashes {
        PrecomputedBlockHashes {
            blocks_per_piece,
            per_piece: HashMap::new(),
        }
    }

    /// Store a write-path precomputed hash (cross-validation `store`,
    /// `precomputed_block_hashes.cpp`): entries are lazily allocated,
    /// positioned by block index, duplicate writes overwrite (a
    /// re-submitted block = same bytes same hash, idempotent). Only called
    /// for pool-accepted blocks (see the verified.rs buffer step order) —
    /// an out-of-range `block_idx` is an invariant break, defensively
    /// dropped (debug_assert makes it visible).
    pub fn store(&mut self, piece: u64, block_idx: usize, hash: [u8; 32]) {
        debug_assert!(
            block_idx < self.blocks_per_piece,
            "precomputed block index {block_idx} beyond {bpp} blocks/piece",
            bpp = self.blocks_per_piece
        );
        if block_idx >= self.blocks_per_piece {
            return;
        }
        let entry = self
            .per_piece
            .entry(piece)
            .or_insert_with(|| vec![None; self.blocks_per_piece].into_boxed_slice());
        entry[block_idx] = Some(hash);
    }

    /// Move a completed piece's entry out whole (cross-validation `take`,
    /// `precomputed_block_hashes.cpp`): ownership travels with the
    /// [`PieceJob`](crate::verified::PieceJob); the table keeps nothing
    /// (released with the job once the completed piece is promoted). None =
    /// the piece has no precomputed slots.
    pub fn take_piece(&mut self, piece: u64) -> Option<Box<[Option<[u8; 32]>]>> {
        self.per_piece.remove(&piece)
    }

    /// Drop in sync with piece reset/eviction (cross-validation `drop`,
    /// `precomputed_block_hashes.cpp`): the evicted piece's cached bytes
    /// are destroyed and the pool digest reset, so stale slots must be
    /// cleared together (re-fetched blocks re-enter the table).
    pub fn drop_piece(&mut self, piece: u64) {
        self.per_piece.remove(&piece);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// store/take lifecycle: lazy allocation, positioned by block index,
    /// take moves the entry out whole and the table is empty afterward
    /// (cross-validation precomputed_block_hashes.cpp store / take).
    #[test]
    fn store_then_take_moves_entry_out() {
        let mut t = PrecomputedBlockHashes::new(4);
        assert!(t.take_piece(7).is_none(), "take on an empty table = None");
        t.store(7, 1, [1; 32]);
        t.store(7, 0, [0; 32]);
        t.store(7, 1, [9; 32]); // duplicate write overwrites (idempotent re-submit).
        let slots = t.take_piece(7).unwrap_or_else(|| panic!("entry"));
        assert_eq!(slots.len(), 4, "slot count = blocks_per_piece");
        assert_eq!(slots[0], Some([0; 32]));
        assert_eq!(
            slots[1],
            Some([9; 32]),
            "a duplicate store keeps the last write"
        );
        assert_eq!(slots[2], None, "an uncomputed slot = None (miss)");
        assert!(t.take_piece(7).is_none(), "the table is emptied after take");
    }

    /// drop syncs with the pool reset (cross-validation drop): the evicted
    /// piece's slots are cleared; other pieces are unaffected.
    #[test]
    fn drop_piece_clears_only_that_piece() {
        let mut t = PrecomputedBlockHashes::new(2);
        t.store(1, 0, [1; 32]);
        t.store(2, 0, [2; 32]);
        t.drop_piece(1);
        assert!(t.take_piece(1).is_none());
        let slots = t.take_piece(2).unwrap_or_else(|| panic!("entry 2"));
        assert_eq!(
            slots[0],
            Some([2; 32]),
            "the neighbor piece's slots are unaffected"
        );
    }

    /// Out-of-range block index: debug builds surface it via debug_assert
    /// (the assertion face of an invariant break, cross-validation
    /// libtorrent `TORRENT_ASSERT`, precomputed_block_hashes.cpp); release
    /// builds take the defensive drop (no stale slot left) — that half is
    /// guaranteed by the in-range short-circuit before the debug_assert and
    /// cannot be exercised in the same test build.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "beyond")]
    fn store_out_of_range_block_panics_in_debug() {
        let mut t = PrecomputedBlockHashes::new(2);
        t.store(0, 5, [5; 32]);
    }
}

//! BEP16 super-seeding distribution bookkeeping.
//!
//! # Semantics authority (BEP text > libtorrent)
//!
//! - **BEP16**: the super-seed presents itself as a client with no data;
//! each peer is told about one piece that has **never been sent out**
//! (or, if all pieces were already sent, the rarest one); the peer does
//! not learn of other pieces until it completes that piece and the seed
//! confirms it propagated — "send only unpropagated pieces; send a new
//! piece only after the peer completes".
//! - Piece choice = a port of libtorrent `torrent::get_piece_to_super_seed`
//! (`src/torrent.cpp`): candidates = pieces the peer does **not** have;
//! pieces already claimed by **another** peer get their availability
//! raised to 999 ("avoid super-seeding the same piece to more than one
//! peer if we can avoid it"); availability = the count of other peers
//! holding the piece; ties on the lowest availability -> pick one at
//! random.
//! - Completion rotation = `peer_connection::incoming HAVE`
//! (`src/peer_connection.cpp`: the peer completes its assigned piece ->
//! `superseed_piece(index, get_piece_to_super_seed(m_have_piece))`) plus
//! the two-slot assignment rotation (current -> previous, new piece ->
//! current).
//! - Bootstrap = `bt_peer_connection::write_bitfield`'s super-seeding
//! branch (`src/bt_peer_connection.cpp`): no bitfield is sent (the fast
//! side's have-none is the caller's job); at most **two** HAVE messages
//! in a row.
//! - Serve gate = `peer_connection::incoming_request`
//! (`src/peer_connection.cpp`): under super-seeding a request for a piece
//! **not assigned** to that peer is rejected ("piece not super-seeded").
//!
//! # Placement in this codebase
//!
//! Swarm-level knowledge (per-peer bitmaps, the cross-connection assignment
//! table) belongs to the engine main loop; the per-connection wire surface
//! (HAVE sends, request rejects) belongs to PeerTask. This type is the pure
//! bookkeeping shared by both (`Arc`-shared; internal locks only guard the
//! table structures, never held across an await): the engine feeds peer
//! bitmaps/leave events and makes assignment decisions; PeerTask queries
//! the serve gate with [`SuperSeedBook::serves`]. The allowed assignment
//! state is a (current, previous) two-slot pair per peer — same shape as
//! libtorrent's `m_superseed_piece[0..2]`.

use std::collections::HashMap;

/// Assignment-exclusion penalty (libtorrent torrent.cpp: a piece claimed by
/// another peer gets availability 999 — avoid sending the same piece to two
/// peers when possible).
const CLAIMED_PENALTY: u32 = 999;
/// Availability scan initial value (torrent.cpp `int min_availability =
/// 9999`).
const MIN_AVAILABILITY_INIT: u32 = 9999;

/// xorshift64 (minimal copy of the engine.rs `XorShift` family; carried
/// here to avoid a bt -> core reverse dependency).
#[derive(Debug)]
struct XorShift(u64);

impl XorShift {
    fn next(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

/// Super-seeding swarm bookkeeping: per-peer two-slot assignments + a swarm
/// bitmap projection.
///
/// Peer bitmaps are fed by the engine main loop (bitfield/HAVE via
/// [`Self::note_bitfield`]/[`Self::note_have`]); completion self-reports
/// set bits immediately inside [`Self::on_completed`] (the arrival order of
/// engine feeds vs self-reports does not affect correctness — same piece,
/// same value, idempotent).
pub struct SuperSeedBook {
    num_pieces: u64,
    /// cuid -> (current, previous) (same shape as libtorrent's
    /// m_superseed_piece[0..2]).
    assigned: std::sync::Mutex<HashMap<u64, (u64, Option<u64>)>>,
    /// cuid -> bitmap (what the peer actually holds; engine feeds +
    /// completion self-reports set bits).
    bits: std::sync::Mutex<HashMap<u64, Vec<bool>>>,
    rng: std::sync::Mutex<XorShift>,
}

impl SuperSeedBook {
    pub fn new(num_pieces: u64, rng_seed: u64) -> SuperSeedBook {
        SuperSeedBook {
            num_pieces,
            assigned: std::sync::Mutex::new(HashMap::new()),
            bits: std::sync::Mutex::new(HashMap::new()),
            rng: std::sync::Mutex::new(XorShift(rng_seed | 1)),
        }
    }

    pub fn num_pieces(&self) -> u64 {
        self.num_pieces
    }

    /// Engine feed: the peer's bitfield arrived (after the BEP3 handshake).
    /// Bits are taken through a closure (`has(i)`, window =
    /// min(n, num_pieces)) — the engine side avoids materializing an
    /// N-byte `Vec<bool>` from the wire bitmap (reading the bit-compressed
    /// row directly), and the check is the same bitwise-OR merge as the
    /// old `&[bool]` form.
    pub fn note_bitfield(&self, cuid: u64, n: u64, has: impl Fn(u64) -> bool) {
        let mut map = crate::lock(&self.bits);
        let row = map
            .entry(cuid)
            .or_insert_with(|| vec![false; self.num_pieces as usize]);
        for i in 0..n.min(row.len() as u64) {
            row[i as usize] = row[i as usize] || has(i);
        }
    }

    /// Engine feed: the peer's HAVE arrived (idempotent — repeated HAVEs do
    /// not double count).
    pub fn note_have(&self, cuid: u64, index: u64) {
        let mut map = crate::lock(&self.bits);
        if let Some(row) = map.get_mut(&cuid)
            && let Some(slot) = row.get_mut(index as usize)
        {
            *slot = true;
        }
    }

    /// Peer left: drop its bitmap and assignment (engine leave path; the
    /// assignment slots return to the pool).
    pub fn leave(&self, cuid: u64) {
        crate::lock(&self.bits).remove(&cuid);
        crate::lock(&self.assigned).remove(&cuid);
    }

    /// Bootstrap assignment (bt_peer_connection.cpp: "bootstrap
    /// super-seeding by sending two have messages"): take at most two
    /// pieces for a peer with **no assignment yet**. Returns the piece
    /// order for the HAVEs to send (empty = nothing to assign — a
    /// single-piece torrent may have only one piece).
    pub fn bootstrap(&self, cuid: u64) -> Vec<u64> {
        let mut picks = Vec::with_capacity(2);
        for _ in 0..2 {
            let Some(piece) = self.pick_for(cuid) else {
                break;
            };
            // The two pieces within one bootstrap must differ
            // (write_bitfield takes twice independently — after the first
            // pick that piece is "claimed", so the second pick naturally
            // avoids it).
            self.assign(cuid, piece, picks.is_empty());
            picks.push(piece);
        }
        picks
    }

    /// Peer completion report (BEP16: "send a new piece only after the peer
    /// completes"; peer_connection.cpp): when `index` is that peer's
    /// currently assigned piece, set the bit + pick a new piece + rotate
    /// the two slots; returns the newly assigned piece (None = a report for
    /// a non-assigned piece / nothing to assign — the caller sends no new
    /// HAVE).
    ///
    /// Lock discipline: piece selection ([`Self::pick_for`]) must run
    /// outside the `assigned` lock (it re-locks the same table — std Mutex
    /// is not reentrant); the re-entry check `entry.0 == index` ensures the
    /// rotation only applies to a slot still pointing at the completed
    /// piece (trivially true on the single-writer engine surface).
    pub fn on_completed(&self, cuid: u64, index: u64) -> Option<u64> {
        {
            let mut bits = crate::lock(&self.bits);
            let row = bits
                .entry(cuid)
                .or_insert_with(|| vec![false; self.num_pieces as usize]);
            if let Some(slot) = row.get_mut(index as usize) {
                *slot = true;
            }
        }
        {
            let assigned = crate::lock(&self.assigned);
            let entry = assigned.get(&cuid)?;
            if entry.0 != index {
                return None;
            }
        }
        let next = self.pick_for(cuid)?;
        let mut assigned = crate::lock(&self.assigned);
        let entry = assigned.get_mut(&cuid)?;
        if entry.0 != index {
            return None;
        }
        // Two-slot rotation (peer_connection.cpp): current -> previous, new
        // piece -> current (previous stays inside the serve gate — it can
        // keep being served during rotation propagation).
        entry.1 = Some(entry.0);
        entry.0 = next;
        Some(next)
    }

    /// Serve gate (peer_connection.cpp): whether `piece` is assigned to
    /// that peer (either slot of current/previous). Under super-seeding a
    /// request for a non-assigned piece must be rejected — the honest
    /// enforcement of "send only unpropagated pieces".
    pub fn serves(&self, cuid: u64, piece: u64) -> bool {
        crate::lock(&self.assigned)
            .get(&cuid)
            .is_some_and(|(cur, prev)| *cur == piece || *prev == Some(piece))
    }

    /// Assignment registration: `bootstrap_first` = the bootstrap path when
    /// no assignment exists yet (first -> straight into the empty current
    /// slot; second -> current moves to previous, the new piece takes
    /// current).
    fn assign(&self, cuid: u64, piece: u64, bootstrap_first: bool) {
        let mut assigned = crate::lock(&self.assigned);
        let entry = assigned.entry(cuid).or_insert((piece, None));
        if !bootstrap_first {
            entry.1 = Some(entry.0);
            entry.0 = piece;
        }
    }

    /// Port of [`torrent::get_piece_to_super_seed`] (torrent.cpp): linear
    /// scan of all pieces; candidates = pieces this peer lacks; availability
    /// = the count of other peers holding the piece, pieces claimed by
    /// another peer penalized straight to 999; collect ties at the lowest
    /// availability and pick one at random; no candidate -> None (every
    /// piece already sent — the BEP16 "or, if all pieces were already sent"
    /// case).
    fn pick_for(&self, cuid: u64) -> Option<u64> {
        let bits = crate::lock(&self.bits);
        let assigned = crate::lock(&self.assigned);
        let peer_has = |i: u64| -> bool {
            bits.get(&cuid)
                .and_then(|row| row.get(i as usize))
                .copied()
                .unwrap_or(false)
        };
        let mut min_availability = MIN_AVAILABILITY_INIT;
        let mut avail_vec: Vec<u64> = Vec::new();
        for i in 0..self.num_pieces {
            if peer_has(i) {
                continue;
            }
            let mut availability: u32 = 0;
            let mut claimed = false;
            for (other, entry) in assigned.iter() {
                if *other == cuid {
                    continue;
                }
                if entry.0 == i || entry.1 == Some(i) {
                    // avoid super-seeding the same piece to more than one
                    // peer if we can avoid it (torrent.cpp).
                    availability = CLAIMED_PENALTY;
                    claimed = true;
                    break;
                }
            }
            if !claimed {
                for (other, row) in bits.iter() {
                    if *other == cuid {
                        continue;
                    }
                    if row.get(i as usize).copied().unwrap_or(false) {
                        availability += 1;
                    }
                }
            }
            if availability > min_availability {
                continue;
            }
            if availability == min_availability {
                avail_vec.push(i);
                continue;
            }
            min_availability = availability;
            avail_vec.clear();
            avail_vec.push(i);
        }
        let mut rng = crate::lock(&self.rng);
        let pick = avail_vec.get(rng.next(avail_vec.len()))?;
        Some(*pick)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Single peer, no other holders: min-availability = all-zero
    /// availability -> the whole pool ties on the random surface (torrent.cpp
    /// avail_vec semantics); repeated picks stay in bounds and do not
    /// double-assign others (single peer here; the second pick avoids
    /// already-assigned pieces via the claimed penalty).
    #[test]
    fn bootstrap_picks_two_pieces_and_claims_them() {
        let book = SuperSeedBook::new(8, 0x1234);
        let picks = book.bootstrap(1);
        assert_eq!(
            picks.len(),
            2,
            "bootstrap yields at most two pieces (bt_peer_connection.cpp)"
        );
        assert_ne!(picks[0], picks[1], "the two bootstrap pieces differ");
        // A second peer's bootstrap: pieces claimed by peer 1 get the 999
        // penalty and are avoided while unclaimed pieces suffice (torrent.cpp
        // claimed-penalty semantics).
        let picks2 = book.bootstrap(2);
        assert_eq!(picks2.len(), 2);
        for p in &picks2 {
            assert!(
                !picks.contains(p),
                "peer 2's bootstrap must not collide with claimed pieces in an 8-piece pool (penalty semantics): {picks:?} vs {picks2:?}"
            );
        }
    }

    /// Table-driven: pick availability ordering (torrent.cpp).
    #[test]
    fn pick_prefers_lowest_availability_and_avoids_claimed() {
        let book = SuperSeedBook::new(4, 0xBEEF);
        // Peer 1's bootstrap claims pieces (availability 0 under an empty
        // pool — random; fix its assignment as the "already propagated"
        // observation noise).
        let p1 = book.bootstrap(1);
        // Peer 2 advertises two pieces (if one is p1's current, it is
        // simultaneously "assigned to peer 1" and "held by peer 2" — both
        // effects depress availability).
        let held = p1.first().copied().unwrap_or(0);
        book.note_bitfield(2, 4, |i| i == held || i == 1);
        // Peer 3's pick: exclude piece 1 held by peer 2 (an invariant
        // independent of whether held == 0: a piece held by peer 2 must not
        // be chosen for peer 3).
        for _ in 0..16 {
            let piece = book
                .pick_for(3)
                .unwrap_or_else(|| panic!("a 4-piece pool must have candidates"));
            assert_ne!(
                piece, 1,
                "a piece held by peer 2 must not be re-assigned (candidates = pieces the peer lacks)"
            );
        }
        // Every piece held by peer 3 -> None (torrent.cpp empty avail case).
        book.note_bitfield(3, 4, |_| true);
        assert_eq!(book.pick_for(3), None, "everything held -> no candidates");
    }

    /// Completion rotation (peer_connection.cpp + the two-slot rotation):
    /// the peer completes its assigned piece -> a new piece returns and the
    /// slots rotate; a report for a non-assigned piece -> None.
    #[test]
    fn on_completed_rotates_and_rejects_unassigned_reports() {
        let book = SuperSeedBook::new(6, 0x51D);
        let picks = book.bootstrap(7);
        // bootstrap assigns twice in a row: after the second rotation
        // current = picks[1], previous = picks[0] (m_superseed_piece[0] =
        // the latest assignment).
        let prev = picks[0];
        let cur = picks[1];
        // Report for an unassigned piece -> None (missing-entry branch).
        book.note_bitfield(9, 6, |_| false);
        assert_eq!(book.on_completed(9, 0), None, "no assignment, no rotation");
        // Assigned piece completed -> a new piece; previous = the old
        // current stays in the serve gate.
        let next = book.on_completed(7, cur).unwrap_or_else(|| {
            panic!("completion rotation in a 6-piece pool must yield a new piece")
        });
        assert_ne!(next, cur);
        assert_ne!(
            next, prev,
            "held pieces do not enter the candidate set (peer_has exclusion)"
        );
        assert!(book.serves(7, next), "the new piece enters the serve gate");
        assert!(
            book.serves(7, cur),
            "the previous slot stays in the serve gate (rotation propagation window)"
        );
        // Other pieces are outside the serve gate (peer_connection.cpp
        // reject).
        assert!(
            !(0..6u64)
                .filter(|&i| i != next && i != cur)
                .any(|i| book.serves(7, i)),
            "pieces outside the two slots must be rejected"
        );
        // Repeated report for the same piece: current already points at
        // next -> the index check fails -> None (no duplicate dispatch).
        assert_eq!(
            book.on_completed(7, cur),
            None,
            "a duplicate report for the same piece does not rotate again"
        );
    }

    /// Leave cleanup: bitmap and assignment slots dropped together (engine
    /// leave path).
    #[test]
    fn leave_releases_assignment_and_bits() {
        let book = SuperSeedBook::new(4, 0x99);
        assert!(!book.bootstrap(1).is_empty());
        assert!(book.serves(1, 0) || book.serves(1, 1) || book.serves(1, 2) || book.serves(1, 3));
        book.leave(1);
        assert!(!book.serves(1, 0), "assignments cleared after leaving");
        // Slot release: a new peer's bootstrap can fill the piece pool
        // again, unaffected by the departed peer's penalty.
        let again = book.bootstrap(2);
        assert_eq!(again.len(), 2);
    }
}

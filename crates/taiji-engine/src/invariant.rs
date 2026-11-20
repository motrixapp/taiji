//! State-consistency invariant sweep — the per-round self-audit
//! vehicle for the engine's remotely influenced, multi-writer
//! structures (the selection discipline: a structure earns a
//! `check_invariant` when remote input can reach it, several writers
//! mutate it, and its integrity is re-derivable wholesale from its own
//! fields; the upstream counterpart is libtorrent's per-class
//! `check_invariant` + per-tick sweep, reduced to a test hook — Rust
//! panics already carry the fail-fast semantics a C++ assertion
//! checker must emulate).
//!
//! First batch (each check's WHY lives on the check itself):
//! - the request-window book ([`crate::dispatch::PieceSentLedger`] +
//!   `FaceState::blocks_sent`): coordinates, row widths, done-piece
//!   clearance, owner indexes, phase reachability;
//! - the choke-round book (`FaceState` peer tables): parallel order,
//!   key agreement, leave-arm scrub closures, clock-stamp sanity;
//! - the piece-completion faces (verified/written models, counters,
//!   the written bitmap): encoding agreement + the
//!   bitmap-never-leads invariant.
//!
//! Vehicle discipline: test-build only — `swarm_sim` sweeps after
//! every virtual-time round and the in-crate suites sweep at their
//! flow milestones; the module is compiled only under `cfg(test)`, so
//! nothing of it exists in non-test compilation (release or debug).
//! The per-structure checks hold `debug_assert!` inside so they stay
//! assertion-shaped (and would survive a future promotion to a
//! debug-build production sweep, the libtorrent model).

use crate::dispatch::check_blocks_sent_invariant;
use crate::faces::FaceState;

/// Sweep one face's engine-side invariants (all first-batch structures
/// at once). `now` comes from the face's own seam clock so the
/// stamp-ordering checks observe the same time face the writers used.
pub(crate) fn sweep_face(face: &FaceState) {
    check_blocks_sent_invariant(face);
    face.check_peer_book_invariant(face.clock.now());
    face.check_completion_invariant();
}

/// Sweep every face of a multi-face slice (the hybrid pair shares one
/// piece space; each face's own encodings must still agree with
/// itself).
pub(crate) fn sweep_faces(faces: &[FaceState]) {
    for face in faces {
        sweep_face(face);
    }
}

/// Mutation validation (anti-vacuity): each test deliberately corrupts
/// one structure the sweep audits and asserts the check fires — a
/// check that cannot go red is not a check. One mutation per audited
/// property; the fixtures come from the shared in-crate face builder.
#[cfg(test)]
mod mutation_tests {
    use super::*;
    use crate::bitmap::PieceBitmap;
    use crate::dispatch::PieceSentLedger;
    use crate::faces::{on_piece_verified, on_piece_written};
    use crate::tests::adv_face;

    /// Row width drift: a row built from a different block grid than
    /// the face's piece table must go red.
    #[test]
    #[should_panic(expected = "blocks_sent row width")]
    fn mutation_blocks_sent_row_width_fires() {
        let mut face = adv_face(4);
        // Piece 0 is one 16KiB block; a 2-slot row mis-places begin ->
        // slot coordinates.
        face.blocks_sent
            .insert(0, PieceSentLedger::new(2, std::time::Instant::now()));
        sweep_face(&face);
    }

    /// A row surviving piece verification must go red (the settle-clear
    /// path lost a case).
    #[test]
    #[should_panic(expected = "survived verification")]
    fn mutation_blocks_sent_done_piece_row_fires() {
        let mut face = adv_face(4);
        on_piece_verified(std::slice::from_mut(&mut face), 0, 0);
        face.blocks_sent
            .insert(0, PieceSentLedger::new(1, std::time::Instant::now()));
        sweep_face(&face);
    }

    /// An owner index outside peer_cuids (a lost leave repair) must go
    /// red.
    #[test]
    #[should_panic(expected = "outside peer_cuids")]
    fn mutation_blocks_sent_owner_out_of_range_fires() {
        let mut face = adv_face(4);
        let now = std::time::Instant::now();
        let mut row = PieceSentLedger::new(1, now);
        row.set_inflight(0, Some(99), now);
        face.blocks_sent.insert(0, row);
        sweep_face(&face);
    }

    /// peers/peer_cuids parallel-order break must go red.
    #[test]
    #[should_panic(expected = "parallel order broken")]
    fn mutation_peer_book_parallel_order_fires() {
        let mut face = adv_face(4);
        face.peer_cuids.push(1); // no matching PeerTaskHandle push
        sweep_face(&face);
    }

    /// An orphaned advertisement bitmap (leave arm lost the avail
    /// removal) must go red.
    #[test]
    #[should_panic(expected = "orphaned bitmap")]
    fn mutation_peer_book_orphan_avail_fires() {
        let mut face = adv_face(4);
        face.peer_avail.insert(42, PieceBitmap::new(4));
        sweep_face(&face);
    }

    /// A stale regular-slot member (leave arm lost the set scrub) must
    /// go red.
    #[test]
    #[should_panic(expected = "regular_unchoked holds unregistered")]
    fn mutation_peer_book_stale_regular_set_fires() {
        let mut face = adv_face(4);
        face.regular_unchoked.insert(99);
        sweep_face(&face);
    }

    /// The bitmap-never-leads direction (written without verified) must
    /// go red.
    #[test]
    #[should_panic(expected = "written but not verified")]
    fn mutation_completion_written_leads_fires() {
        let mut face = adv_face(4);
        let need = [face.piece_count];
        // A written event without a prior verify event: only bytes that
        // passed verification may be on disk.
        on_piece_written(std::slice::from_mut(&mut face), 0, 0, &need, None);
        sweep_face(&face);
    }

    /// Counter/model drift (the redundant encoding disagrees) must go
    /// red.
    #[test]
    #[should_panic(expected = "verified_count")]
    fn mutation_completion_counter_drift_fires() {
        let mut face = adv_face(4);
        face.verified_count = 1; // no progress bit set
        sweep_face(&face);
    }
}

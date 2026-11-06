//! Seeding-state entry wiring (idempotent): the BEP21 `upload_only`
//! announce broadcast + BEP16 super-seeding bookkeeping mounting
//! (`enter_seeding_state`).
//!
//! Owns: the seeding-state switch shared by the download-complete and
//! recovery-as-complete paths.
//! Does not own: super-seed assignment decisions (bt::superseed +
//! main-loop consumption).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::sync::Arc;

use tracing::info;

use taiji_bt::peer::PeerHandle as _;

use crate::faces::{FaceState, XorShift};
/// Enter the seeding state (idempotent; shared by the download-complete
/// and recovery-as-complete paths):
///
/// - **BEP21**: broadcast the `upload_only` announce — the state
/// transition is itself the re-advertise (BEP21 semantics; the same
/// shape as libtorrent's state-change broadcast `torrent::
/// send_upload_only`, torrent.cpp). Connections registered afterwards
/// catch up via the registration arm's SetUploadOnly.
/// - **BEP16**: when the master switch `super_seeding`
/// (`SeedPolicy::super_seeding`, default off) is on, create the
/// super-seed book and mount all existing connections (matching
/// libtorrent `torrent::set_super_seeding(on)`, torrent.cpp — the off
/// face is unsupported locally: the switch is a task-static policy
/// and never flips mid-run).
pub(super) fn enter_seeding_state(
    faces: &mut [FaceState],
    upload_only: &mut bool,
    super_seed: &mut Option<Arc<taiji_bt::superseed::SuperSeedBook>>,
    super_seeding: bool,
    rng: &mut XorShift,
) {
    if !*upload_only {
        *upload_only = true;
        for f in faces.iter() {
            for p in &f.peers {
                let _ = p.command(taiji_bt::peer::PeerCommand::SetUploadOnly(true));
            }
        }
        info!(target: "taiji::core::engine",
            peers = faces.iter().map(|f| f.peers.len()).sum::<usize>(),
            "seed state entered: upload_only advertised (BEP21)");
    }
    if super_seeding && super_seed.is_none() {
        let piece_count = faces.first().map(|f| f.piece_count as u64).unwrap_or(0);
        let book = Arc::new(taiji_bt::superseed::SuperSeedBook::new(
            piece_count,
            rng.next(1usize << 62) as u64 | 1,
        ));
        for f in faces.iter() {
            for p in &f.peers {
                let _ = p.command(taiji_bt::peer::PeerCommand::SetSuperSeed(book.clone()));
            }
        }
        *super_seed = Some(book);
        info!(target: "taiji::core::engine", pieces = piece_count,
            "super-seeding enabled (BEP16)");
    }
}

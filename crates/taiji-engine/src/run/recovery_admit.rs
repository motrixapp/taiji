//! Hash-recovery consumer: the admission side of the
//! [`taiji_domain::hash_fetch::RecoveredPieceLayer`] delivery seam
//! (whole-file layer convergence → anchor-domain insertion → runtime
//! representation upgrade).
//!
//! Responsibilities and bounds:
//! - Admission: `merkle::validate_piece_layer` converges entry count + root
//! recomputation once; on success `taiji_store::recovery::admit_piece_layer`
//! inserts into the `HashTreeCache` anchor domain — the same trust level as
//! a metadata-carried layer (the root is protected by the infohash, so
//! convergence implies trust: single source, no voting);
//! - Bad-layer handling: failed convergence = the whole file is not admitted +
//! a drop counter (never a load failure, never a degradation, the peer
//! source is noted) + re-staging for a refetch from another peer; the
//! retry budget follows the lazy-fetch
//! [`taiji_domain::hash_fetch::HASH_FETCH_MAX_ATTEMPTS`], tried-peer memory
//! is kept, and an exhausted budget waits for a new peer (no retry storm);
//! - Gated promotion: admission = trust established + gates released —
//! [`activate_recovered_file`] lifts the file from the layer-missing gated
//! state (lazy-fetch `Pending`: no download/seed/advertise) to fully
//! enabled (lazy-fetch `Queued`: the existing lazy-fetch/download/seed
//! paths take over unchanged), while (1) backfilling the storage
//! pipeline's live expected-root seam (placeholder zero roots → true piece
//! roots; the pipeline rebuilds via `watch` with no restart) and (2)
//! unlocking the seeding hash service (the recovery layer backfills
//! `hash_files`, so the [`taiji_domain::hash_source::MetaHashSource`]
//! mounted at completion can serve the file's piece-layer requests — the
//! BEP-52 service obligation);
//! - recheck linkage (recovered-layer reverification / suspend re-entry /
//! hybrid v1 on-disk v2 backfill) is out of scope here; the only touch
//! point is the persistence half — a successful admission writes the
//! derived table through the PersistWriter seam via
//! [`persist_recovered_layer`] (read-back / reverification / suspend
//! re-entry live in the session face and `session::recheck`).
//!
//! # AlreadyAnchored unified promotion
//!
//! An established anchor (admission succeeded OR the root was already
//! anchored) = trust established — all layer-missing Pending files with the
//! same root are promoted together, removing the scattered per-consumer
//! handling of AlreadyAnchored. Design choice: promote uniformly at the
//! consume point rather than de-duplicating recovery entries by root at
//! build time — the latter would change the merged data-plane registration
//! semantics (out of scope for this module), and per-file entries keep
//! independent re-stage/reset bookkeeping; the consumer converges once and
//! removes entries one by one. Safety: the same root cryptographically
//! implies the same layer, but the delivered bytes are unverified —
//! AlreadyAnchored is an admission short-circuit (the store-side anchor
//! check precedes validation), so that arm first runs
//! `merkle::validate_piece_layer` and only then promotes; a failed
//! validation counts a drop and promotes nothing.
//!
//! In scope: the delivery-channel consumer + admission verdicts +
//! bookkeeping convergence + gated-promotion propagation. Out of scope: pull
//! driving (dispatch::drive_recovery); persistence proper (the sqlite face:
//! store::persist + session reload).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::sync::Arc;

use tracing::{debug, info, warn};

use taiji_store::hashpool;
use taiji_store::hashpool::ExpectedPieceHash;
use taiji_store::merkle;
use taiji_store::recovery::{AdmissionError, admit_piece_layer};

use crate::recovery::{RecoveryEventKind, RecoveryNotice, recovered_layer_row};

/// Pipeline expected-root payload for gated promotion (re-export alias: the
/// engine-side assembly/activation and the pipeline consumption share one
/// structure, see [`super::super::pipeline::ExpectedRoots`]).
use super::super::pipeline::ExpectedRoots;
use super::state::EngineLoop;
use crate::dispatch::{LayerFetchState, RECOVERY_TRIED_CAP, RecoveryBook, RecoveryFetchState};
use crate::faces::FaceState;
use crate::tracker::TrackerPersistShared;
use taiji_domain::hash_fetch::RecoveredPieceLayer;
use taiji_domain::hash_fetch::plan_base_layer_fetch;

/// Gated-promotion carrier (one per v2 face; parallel to faces in
/// `EngineLoop::recovery_upgrade`, None = v1 face / no base — expected roots
/// are always complete there, nothing to promote).
///
/// Holds a live full copy of the expected roots / block-check file roots (at
/// build time = placeholder zero roots for layer-missing pieces, matching the
/// pipeline's initial snapshot): as several layer-missing files are admitted
/// one after another, each promotion accumulates backfills on the copy (a
/// later admission never overwrites an earlier true root), then the whole
/// book is published to the pipeline via `watch` (latest-wins, idempotent).
pub(crate) struct RecoveryUpgrade {
    /// Synthetic flat piece order → expected hash per piece (live copy).
    pub(super) expected: Vec<ExpectedPieceHash>,
    /// Synthetic flat piece order → (file pieces root, first leaf index) (live copy).
    pub(super) piece_leaves: Arc<Vec<([u8; 32], u64)>>,
    /// Pipeline seam sender (consumed by the store_pipeline gate-promotion arm).
    pub(super) tx: tokio::sync::watch::Sender<Arc<ExpectedRoots>>,
}

/// Admission counters (session-cumulative; EngineLoop single-writer fields,
/// read directly by the main-loop arm and tests — the observable face of
/// failure → drop counting).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveryAdmissionStats {
    /// Whole-file layers that converged and were admitted (same trust level
    /// as a metadata-carried layer).
    pub(super) admitted: u64,
    /// Deliveries dropped after failed convergence (the peer source is noted
    /// in logs; each drop re-stages for refetch, converging within budget —
    /// see `consume_recovered_layer_unified`).
    pub(super) rejected: u64,
}

/// Main-loop `select!` arm body (EngineLoop single-writer discipline):
/// consumes one recovery-layer delivery; once the anchor is established, runs
/// the gated-promotion propagation (pipeline expected-root seam +
/// lazy-fetch/dispatch unlock + seeding hash service backfill) — promotion
/// coordinates = the primary ∪ same-root siblings (unified promotion, see
/// [`consume_recovered_layer_unified`]). Returns every promoted coordinate
/// with the delivery snapshot — the trigger input for the persistence half
/// (derived recovered-layer rows persisted through the PersistWriter seam,
/// surviving restarts), one row per coordinate (same-root sibling files each
/// hold their own derived row by file_index; the read-back side re-validates
/// with admission semantics, idempotent). An empty Vec = stale delivery /
/// bad layer / defensive drop.
pub(super) fn consume_recovered_layer(
    state: &mut EngineLoop,
    rec: RecoveredPieceLayer,
) -> Vec<(usize, usize, RecoveredPieceLayer)> {
    // Snapshot the activation payload (rec is moved into the core consumer;
    // Clone is cheap: at most a few thousand 32 B layer entries).
    let snapshot = rec.clone();
    let outcome = consume_recovered_layer_unified(
        &mut state.faces,
        &mut state.recovery,
        &mut state.recovery_admission,
        rec,
    );
    let mut lifted = Vec::with_capacity(1 + outcome.siblings.len());
    // Unified activation: primary + same-root sibling coordinates each run
    // the activation chain ([`activate_recovered_file`] is idempotent — a
    // non-`Pending` file is a no-op).
    for (fi, file_idx) in outcome.primary.into_iter().chain(outcome.siblings) {
        let upgrade = state.recovery_upgrade.get_mut(fi).and_then(Option::as_mut);
        activate_recovered_file(&mut state.faces[fi], upgrade, file_idx, &snapshot);
        lifted.push((fi, file_idx, snapshot.clone()));
    }
    lifted
}

/// Persistence half: assembles a derived row for an admitted recovery layer
/// and writes the `recovered_layer` table through the PersistWriter seam
/// (key = torrent gid + file index, value = layer bytes; single-writer).
/// The cross-restart write half — on task activation/promotion the read-back
/// side re-validates with admission semantics and inserts
/// (`session::persist::recovery`). Persistence is best-effort (failure only
/// warns): the worst case is the file falling back to the layer-missing
/// state after restart and refetching from the swarm; correctness is
/// unaffected (the same tolerance as the progress row).
pub(crate) async fn persist_recovered_layer(
    persist: Option<&TrackerPersistShared>,
    file_index: usize,
    rec: &RecoveredPieceLayer,
) {
    let Some(p) = persist else {
        return; // no persistence face (CLI direct run / test assembly) = in-memory, zero behavior
    };
    let row = recovered_layer_row(&p.gid, file_index, rec);
    match p.handle.upsert_recovered_layer(row).await {
        Ok(taiji_store::persist::PersistOutcome::Written) => {
            debug!(target: "taiji::core::engine", gid = %p.gid, file_index,
                bytes = rec.layer.len() * 32,
                "recovered layer persisted (cross-restart anchor source)");
        }
        Ok(taiji_store::persist::PersistOutcome::SkippedUnchanged) => {}
        Err(e) => {
            warn!(target: "taiji::core::engine", gid = %p.gid, file_index, %e,
                "recovered layer persist failed (refetch on next start)");
        }
    }
}

/// Unified consumption result: the coordinates awaiting activation once the
/// anchor is established.
pub(crate) struct RecoveryConsumeOutcome {
    /// Primary `Some((face, file_index))` = the matched entry's
    /// admission/anchored coordinate (the trigger input for activation and
    /// persistence; the test-only legacy call surface returns only this
    /// coordinate — see `consume_recovered_layer_core`).
    pub(crate) primary: Option<(usize, usize)>,
    /// Same-root sibling coordinates = the other booked files sharing the
    /// delivery's root and geometry, promoted with this anchoring; their
    /// entries are removed and runtime representations upgraded
    /// ([`unify_same_root`]) — the caller only executes the seam half via
    /// [`activate_recovered_file`].
    pub(crate) siblings: Vec<(usize, usize)>,
}

/// Consumption core (the unified form; decoupled from EngineLoop for unit
/// testing, same style as `drain_dispatch_replies_core`): locate the
/// delivery's source → admit → bookkeeping convergence → the same-root
/// unified promotion (bookkeeping half).
///
/// Locating: the delivery payload carries no face/file coordinates (the seam
/// signature is frozen) — match `(root, piece_len, piece count, Delivered
/// state)` across the faces' recovery books; no match = a stale delivery
/// (entry already admitted-and-removed or reset), benignly dropped.
///
/// Returns [`RecoveryConsumeOutcome`] (primary + same-root sibling
/// coordinates).
pub(crate) fn consume_recovered_layer_unified(
    faces: &mut [FaceState],
    recovery: &mut [RecoveryBook],
    stats: &mut RecoveryAdmissionStats,
    rec: RecoveredPieceLayer,
) -> RecoveryConsumeOutcome {
    let pieces = rec.layer.len() as u64;
    let mut hit: Option<(usize, usize)> = None;
    'outer: for (fi, book) in recovery.iter().enumerate() {
        for (&file_idx, entry) in book.files.iter() {
            if matches!(entry.state, RecoveryFetchState::Delivered)
                && entry.staging.piece_len() == rec.piece_len
                && entry.staging.pieces() == pieces
                && entry.staging.root() == &rec.root
            {
                hit = Some((fi, file_idx));
                break 'outer;
            }
        }
    }
    let Some((fi, file_idx)) = hit else {
        debug!(target: "taiji::core::engine", root = ?rec.root,
            "stale recovery delivery dropped (entry already admitted or reset)");
        return RecoveryConsumeOutcome {
            primary: None,
            siblings: Vec::new(),
        };
    };

    // Admission: writes face.trees — shares the same
    // Arc<Mutex<HashTreeCache>> as the storage pipeline's BlockCheck; a short
    // critical section, no cross-await.
    let face = &mut faces[fi];
    let verdict = face.trees.as_ref().map(|trees| {
        let mut trees = crate::lock(trees);
        admit_piece_layer(
            &mut trees,
            &rec.root,
            &rec.layer,
            rec.file_len,
            rec.piece_len,
        )
    });
    let book = &mut recovery[fi];
    match verdict {
        Some(Ok(())) => {
            stats.admitted += 1;
            info!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                pieces, "recovered piece layer admitted: whole-file convergence to info \
                 pieces root reached (same trust as the metadata-layer resolution)");
            // Runtime representation upgraded to fully enabled: true root +
            // lazy-fetch plans ready (the ready state from which the existing
            // lazy-fetch/download/seed paths take over unchanged). Gate
            // release (Pending → Queued) and the pipeline expected-root live
            // backfill are executed by the caller's activation chain
            // (activate_recovered_file).
            upgrade_file_runtime(face, file_idx, &rec);
            book.files.remove(&file_idx);
            // Unified promotion: remaining same-root booked files are
            // promoted with this anchoring.
            let siblings = unify_same_root(fi, book, face, &rec);
            RecoveryConsumeOutcome {
                primary: Some((fi, file_idx)),
                siblings,
            }
        }
        Some(Err(AdmissionError::AlreadyAnchored)) => {
            // Root already anchored (metadata layer present or previously
            // admitted) = trust established — validate the delivered layer
            // first, then promote uniformly. AlreadyAnchored is an admission
            // short-circuit (the anchor check precedes validation) and the
            // delivered bytes are unverified; promoting them directly would
            // violate verify-before-persist. Validation passing puts the
            // delivery at the same trust level as the existing anchor, and
            // every same-root Pending file goes through the promotion
            // propagation (curing the "second file gated forever" stall).
            let bytes: Vec<u8> = rec.layer.iter().flat_map(|h| h.iter()).copied().collect();
            if merkle::validate_piece_layer(&rec.root, &bytes, rec.file_len, rec.piece_len).is_err()
            {
                // Convergence failed: the anchor is unaffected, no promotion
                // coordinates — count a drop (the peer source is noted at the
                // delivery face).
                stats.rejected += 1;
                warn!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                    pieces, source = "peer hash exchange (recovery)",
                    "redundant delivery for anchored root failed convergence; discarded \
                     (anchor unaffected, no promotion)");
                book.files.remove(&file_idx);
                return RecoveryConsumeOutcome {
                    primary: None,
                    siblings: Vec::new(),
                };
            }
            info!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                pieces, "recovery delivery redundant but convergent: pieces root already \
                 anchored = trust established; promoting all same-root gated files ()");
            upgrade_file_runtime(face, file_idx, &rec);
            book.files.remove(&file_idx);
            let siblings = unify_same_root(fi, book, face, &rec);
            RecoveryConsumeOutcome {
                primary: Some((fi, file_idx)),
                siblings,
            }
        }
        Some(Err(e)) => {
            // Convergence failure (count / root recomputation / empty
            // payload): the whole file is not admitted (zero anchor-domain
            // writes — the store::recovery contract); count a drop, note the
            // peer source, and re-stage for a refetch from another peer.
            // Budget +1, tried-peer memory kept: once exhausted, wait for a
            // new peer (no retry storm). Divergence: libtorrent drops bad
            // hashes and disconnects (bt_peer_connection.cpp) as its local
            // policy; here the entry refetches from another peer (BEP-52
            // only mandates disconnecting on malformed frames).
            stats.rejected += 1;
            warn!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                pieces, source = "peer hash exchange (recovery)", error = %e,
                "recovered piece layer rejected at whole-file convergence; discarded \
                 (none admitted) and re-staged for re-fetch from another peer");
            if let Some(entry) = book.files.get_mut(&file_idx) {
                entry.staging = taiji_domain::hash_fetch::PieceLayerStaging::new(
                    rec.root,
                    rec.file_len,
                    rec.piece_len,
                );
                entry.state = RecoveryFetchState::Missing;
                entry.attempts = entry.attempts.saturating_add(1);
                if entry.tried.len() >= RECOVERY_TRIED_CAP {
                    entry.tried.clear();
                }
            }
            RecoveryConsumeOutcome {
                primary: None,
                siblings: Vec::new(),
            }
        }
        None => {
            // v2 face missing trees: assembly anomaly (a v2 face always has
            // the base) — defensively remove the entry and count the drop
            // (never swallowed silently).
            warn!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                "v2 face has no hash tree base; recovery delivery dropped (assembly anomaly)");
            stats.rejected += 1;
            book.files.remove(&file_idx);
            RecoveryConsumeOutcome {
                primary: None,
                siblings: Vec::new(),
            }
        }
    }
}

/// Legacy call surface of the consumption core (a signature/semantics-
/// compatible projection for existing tests only — production consumption
/// goes through [`consume_recovered_layer`]): exposes only the primary
/// coordinate; same-root unified promotion coordinates are carried by the
/// second return value of [`consume_recovered_layer_unified`].
#[cfg(test)]
pub(crate) fn consume_recovered_layer_core(
    faces: &mut [FaceState],
    recovery: &mut [RecoveryBook],
    stats: &mut RecoveryAdmissionStats,
    rec: RecoveredPieceLayer,
) -> Option<(usize, usize)> {
    consume_recovered_layer_unified(faces, recovery, stats, rec).primary
}

/// Runtime representation upgrade (core half, extracted from the former Ok
/// arm): true root + leaf total + lazy-fetch plans ready. The gate flip /
/// seam backfill / dispatch bookkeeping reset belong to
/// [`activate_recovered_file`]'s seam half.
fn upgrade_file_runtime(face: &mut FaceState, file_idx: usize, rec: &RecoveredPieceLayer) {
    let pieces = rec.layer.len() as u64;
    let bpp = u64::from(rec.piece_len / hashpool::BLOCK_SIZE);
    if let Some(layer) = face.layers.get_mut(file_idx) {
        layer.root = rec.root;
        layer.leaf_total = pieces * bpp;
        layer.plans = plan_base_layer_fetch(rec.file_len, rec.piece_len);
    }
}

/// Bookkeeping half of the same-root unified promotion: removes the other
/// booked entries matching the delivery's root and geometry (piece length
/// and count — the same root cryptographically implies the same layer; the
/// geometry check is defensive re-verification) and completes their runtime
/// upgrades; returns the coordinates awaiting activation (the seam half is
/// executed by the caller via [`activate_recovered_file`], idempotent).
/// Entries removed here no longer drive repeated fetches from
/// [`drive_recovery`]; surplus later deliveries converge as stale drops.
fn unify_same_root(
    fi: usize,
    book: &mut RecoveryBook,
    face: &mut FaceState,
    rec: &RecoveredPieceLayer,
) -> Vec<(usize, usize)> {
    let pieces = rec.layer.len() as u64;
    let same_root: Vec<usize> = book
        .files
        .iter()
        .filter(|(_, e)| {
            e.staging.root() == &rec.root
                && e.staging.piece_len() == rec.piece_len
                && e.staging.pieces() == pieces
        })
        .map(|(&f, _)| f)
        .collect();
    for f in &same_root {
        upgrade_file_runtime(face, *f, rec);
        book.files.remove(f);
    }
    same_root.into_iter().map(|f| (fi, f)).collect()
}

/// Gated-promotion activation chain (called by [`consume_recovered_layer`]
/// once admission succeeds — the full propagation from gated to fully
/// enabled for a layer-missing file):
///
/// 1. Pipeline expected-root live seam: backfill the placeholder zero roots
/// for the file's flat piece range with true piece roots (expected-root
/// table + block-check file-root table; multi-file admissions accumulate
/// on the live copy), publishing the whole book via `watch` — the store
/// pipeline's gate-promotion arm rebuilds `VerifiedWriter` live (no
/// restart);
/// 2. Download gate promotion: lazy-fetch layer `Pending → Queued { next: 0 }`
/// — the selector's candidate fold lifts and the piece returns to the
/// candidate set; the first hit triggers the existing leaf-layer lazy
/// fetch (plans already ready); after Done, block dispatch proceeds as
/// usual;
/// 3. Seeding hash service unlock: the recovery layer backfills
/// `hash_files[file].piece_layer` — the
/// [`taiji_domain::hash_source::MetaHashSource`] mounted at completion by
/// `attach_seeding_sources` can then serve the file's piece-layer requests
/// (the BEP-52 service obligation; before promotion, requests for this
/// file could only be hash-rejected — a BEP-52-legal exit);
/// 4. Dispatch bookkeeping reset: the pipeline rebuild destroys its write
/// cache (unverified data never persists) — in-flight / buffered / refetch
/// bookkeeping clears in sync; unsettled bytes are refetched by the
/// existing dispatch path.
///
/// Returns whether a promotion happened (idempotent defense: a non-`Pending`
/// file is already promoted / not layer-missing; no-op). Only
/// [`LayerFetchState::Pending`] responds — the single exit of the gate state
/// machine (the "ready" landing of the recovery bookkeeping missing →
/// recovering → (admission) → ready progression; there is no terminal failed
/// state — with the budget exhausted the entry stays recovering, waiting for
/// a new peer).
pub(crate) fn activate_recovered_file(
    face: &mut FaceState,
    upgrade: Option<&mut RecoveryUpgrade>,
    file_idx: usize,
    rec: &RecoveredPieceLayer,
) -> bool {
    if !matches!(
        face.layers.get(file_idx).map(|l| &l.state),
        Some(LayerFetchState::Pending)
    ) {
        return false;
    }
    let pieces = rec.layer.len() as u64;
    let base = face.layers[file_idx].piece_base;
    // 1. Pipeline expected-root live backfill + publish (the seam; multi-file
    // accumulation — a later admission never rewrites slots backfilled by an
    // earlier one; slots are disjoint by flat piece range).
    if let Some(up) = upgrade {
        let slot_range = (base as usize)..(base + pieces) as usize;
        for (slot, root) in slot_range.clone().zip(rec.layer.iter()) {
            if let Some(e) = up.expected.get_mut(slot) {
                *e = ExpectedPieceHash::V2(*root);
            }
        }
        let mut leaves: Vec<([u8; 32], u64)> = (*up.piece_leaves).clone();
        for (slot, _) in slot_range.clone().zip(rec.layer.iter()) {
            if let Some(entry) = leaves.get_mut(slot) {
                entry.0 = rec.root;
            }
        }
        up.piece_leaves = Arc::new(leaves);
        let _ = up.tx.send(Arc::new(ExpectedRoots {
            expected: up.expected.clone(),
            piece_leaves: Arc::clone(&up.piece_leaves),
        }));
    }
    // 2. Download gate promotion (the existing lazy-fetch/dispatch paths take
    // over unchanged).
    face.layers[file_idx].state = LayerFetchState::Queued { next: 0 };
    // 3. Seeding hash service unlock (the recovery layer has the metadata layer's trust level).
    if let Some(files) = face.hash_files.as_mut() {
        if let Some(f) = files.get_mut(file_idx) {
            if f.piece_layer.is_none() {
                f.piece_layer = Some(
                    rec.layer
                        .iter()
                        .flat_map(|h| h.iter())
                        .copied()
                        .collect::<Vec<u8>>()
                        .into(),
                );
            }
        }
    }
    // 4. Dispatch bookkeeping reset (the pipeline write cache is destroyed
    // with the rebuild; bookkeeping stays in sync).
    face.blocks_sent.clear();
    face.dispatch_replies.clear();
    face.refetch.clear();
    info!(target: "taiji::core::engine", file_index = file_idx,
        pieces, piece_base = base,
        "layer-missing file gate lifted: lazy-fetch queued, pipeline expected \
         roots re-armed, hash service enabled (C-3)");
    true
}

/// # Session recovery event surface (taiji.recoveryStarted/Completed)
///
/// Engine half: events are emitted at points the engine state machine
/// already has (the RPC face only consumes and forwards) —
/// - Started = task activation (activation chain: the set of files still
/// layer-missing after assembly is non-empty — the `run()`
/// assembly-complete point). The engine emits on every activation;
/// exactly-once across repeated activations is enforced by the session
/// face deduplicating on gid (session rebuild = new bookkeeping =
/// re-emit).
/// - Completed = the promotion-propagation convergence point: emitted
/// exactly once when the activation missing-set is fully promoted (gates
/// Pending → Queued; the remaining set is monotonically decreasing, so the
/// emptying transition happens at most once). Terminal-failure choice: no
/// third event — there is no failure terminal (an exhausted budget stays
/// recovering, waiting for a new peer); a stuck gate is observable as
/// started without completed; the completed payload's status key is a
/// reserved extension slot (the RPC render layer pins "ready").
///
/// Payloads relay through [`taiji_domain::hook::HookRunner::notify_recovery`]
/// (isomorphic relay slots; no user hook command triggers this) — the file
/// set is 1-based client file order (the same anchor as getFiles `index`).
///
/// getFiles layer-missing projection reads via [`recovery_file_states`]
/// (carried on the QueryStatus snapshot; the session face merges it into the
/// file entries).
///
/// Recovery projection state values (the wire value domain; the RPC layer's
/// `recoveryStatus` maps directly, snake_case matching the existing policy
/// values).
pub(crate) const RECOVERY_LAYER_MISSING: &str = "layer_missing";
pub(crate) const RECOVERY_RECOVERING: &str = "recovering";
pub(crate) const RECOVERY_READY: &str = "ready";

/// Event tracking (EngineLoop single-writer field; initialized at the
/// activation emit point, the consumer arm monotonically drains the open
/// set).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct RecoveryEventTrack {
    /// The layer-missing file set at activation (0-based meta.files
    /// positions, ascending) — the payload source for started/completed and
    /// the "was layer-missing" projection predicate.
    pub(super) started: Vec<usize>,
    /// The open set not yet promoted (started − promoted; empty = the
    /// completed emit point, exactly once).
    pub(super) open: Vec<usize>,
}

/// Extract the activation missing set (pure function): the union of
/// bookkeeping keys across faces (the v1 book is always empty — layer-missing
/// registers only on v2 faces; both faces key the same meta.files coordinate
/// space, so no duplicates), ascending.
pub(super) fn activation_missing_files(recovery: &[RecoveryBook]) -> Vec<usize> {
    let mut files: Vec<usize> = recovery
        .iter()
        .flat_map(|book| book.files.keys().copied())
        .collect();
    files.sort_unstable();
    files.dedup();
    files
}

/// Register promotions (pure function): move the files whose gates genuinely
/// lifted this wave out of the open set; an emptied set = convergence done,
/// returning the completed payload file set (1-based client file order). The
/// open set shrinks monotonically → the emptying transition happens at most
/// once, the engine half of "completed exactly once"; unrelated coordinates
/// (stale/duplicate reports) are no-ops (idempotent).
pub(super) fn note_promotions_core(
    track: &mut RecoveryEventTrack,
    promoted: &[usize],
) -> Option<Vec<u32>> {
    if track.started.is_empty() || track.open.is_empty() {
        return None;
    }
    for &f in promoted {
        track.open.retain(|&x| x != f);
    }
    if track.open.is_empty() {
        Some(track.started.iter().map(|&f| f as u32 + 1).collect())
    } else {
        None
    }
}

/// getFiles layer-missing projection (pure function): files involved in
/// recovery (booked ∪ was-missing) → 0-based meta.files position + state:
/// - Booked: `Missing` = no hashes in flight/staged yet ("waiting for hash
/// recovery") → [`RECOVERY_LAYER_MISSING`]; `Requesting/Received/Delivered`
/// = fetch in progress → [`RECOVERY_RECOVERING`];
/// - Was-missing (in the started set) and promoted (not in the open set) →
/// [`RECOVERY_READY`];
/// - Was-missing, bookkeeping removed but the gate still closed (the benign
/// edge of bad-layer redundant removal) → [`RECOVERY_LAYER_MISSING`]
/// (the gate is still shut; the miss stays observable);
/// - Other files are not projected (metadata-carried layers / v1 /
/// single-piece files — keys absent by default).
pub(super) fn recovery_file_states_core(
    faces: &[FaceState],
    recovery: &[RecoveryBook],
    track: &RecoveryEventTrack,
) -> Vec<(u32, &'static str)> {
    let mut out: Vec<(usize, &'static str)> = Vec::new();
    for book in recovery {
        for (&file_idx, entry) in &book.files {
            let state = match entry.state {
                RecoveryFetchState::Missing => RECOVERY_LAYER_MISSING,
                RecoveryFetchState::Requesting { .. }
                | RecoveryFetchState::Received
                | RecoveryFetchState::Delivered => RECOVERY_RECOVERING,
            };
            out.push((file_idx, state));
        }
    }
    for f in &track.started {
        // Booked files are already projected by their live fetch state (the
        // loop above); the started loop only adds was-missing files whose
        // bookkeeping has been removed.
        if recovery.iter().any(|book| book.files.contains_key(f)) {
            continue;
        }
        let promoted = !track.open.contains(f);
        // Gate lookup: the layer-missing lazy-fetch layer exists only on v2
        // faces (v1 layers are empty — find_map takes the first face holding
        // the position).
        let gate = faces
            .iter()
            .find_map(|face| face.layers.get(*f).map(|l| &l.state));
        let state = if promoted {
            RECOVERY_READY
        } else {
            match gate {
                Some(LayerFetchState::Pending) | None => RECOVERY_LAYER_MISSING,
                Some(_) => RECOVERY_READY,
            }
        };
        out.push((*f, state));
    }
    out.sort_unstable();
    out.dedup();
    out.into_iter()
        .map(|(f, s)| (u32::try_from(f).unwrap_or(u32::MAX), s))
        .collect()
}

/// Activation emit point (called after `run()` assembly completes, before the
/// main loop): a non-empty missing set → initialize event tracking + relay
/// Started (the engine emits on every activation; exactly-once dedup is the
/// session face's job).
pub(super) fn emit_recovery_activation(
    state: &mut EngineLoop,
    hook: &Option<Arc<taiji_domain::hook::HookRunner>>,
) {
    let started = activation_missing_files(&state.recovery);
    if started.is_empty() {
        return;
    }
    info!(target: "taiji::core::engine", files = ?started,
        "recovery event surface armed: layer-missing files at activation \
         (taiji.recoveryStarted relayed once per session by the actor)");
    state.recovery_track = RecoveryEventTrack {
        started: started.clone(),
        open: started.clone(),
    };
    if let Some(hook) = hook {
        hook.notify_recovery(RecoveryNotice {
            kind: RecoveryEventKind::Started,
            files: started.iter().map(|&f| f as u32 + 1).collect(),
        });
    }
}

/// Promotion registration point (consumer arm, after
/// `activate_recovered_file`): registers only the coordinates whose gates
/// genuinely lifted (idempotent no-op coordinates are not re-registered —
/// the lifted list from `consume_recovered_layer` contains activation
/// no-ops); an emptied open set relays Completed (exactly once).
pub(super) fn note_promotions(
    state: &mut EngineLoop,
    lifted: &[(usize, usize, RecoveredPieceLayer)],
    hook: &Option<Arc<taiji_domain::hook::HookRunner>>,
) {
    if state.recovery_track.started.is_empty() {
        return;
    }
    let promoted: Vec<usize> = lifted
        .iter()
        .filter(|(fi, file_idx, _)| {
            matches!(
                state.faces[*fi].layers.get(*file_idx).map(|l| &l.state),
                Some(LayerFetchState::Queued { .. }) | Some(LayerFetchState::Done)
            )
        })
        .map(|(_, file_idx, _)| *file_idx)
        .collect();
    if let Some(files) = note_promotions_core(&mut state.recovery_track, &promoted) {
        info!(target: "taiji::core::engine", files = ?files,
            "all layer-missing files promoted to ready (taiji.recoveryCompleted)");
        if let Some(hook) = hook {
            hook.notify_recovery(RecoveryNotice {
                kind: RecoveryEventKind::Completed,
                files,
            });
        }
    }
}

/// getFiles layer-missing projection (QueryStatus snapshot half; the
/// EngineLoop wrapper of [`recovery_file_states_core`]).
pub(super) fn recovery_file_states(state: &EngineLoop) -> Vec<(u32, &'static str)> {
    recovery_file_states_core(&state.faces, &state.recovery, &state.recovery_track)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{FileLayerState, FileRecovery, PieceSentLedger};
    use crate::dispatch::{build_v2_data_plane, drive_recovery};
    use std::path::PathBuf;
    use taiji_bt::piece_id::Addressing;
    use taiji_domain::hash_fetch::PieceLayerStaging;
    use taiji_domain::metainfo::MetaFile;
    use taiji_store::merkle::{self, BLOCK_SIZE};

    /// 3-piece × 16 KiB (bpp = 1) file geometry: content / true piece-root layer / file root.
    fn fixture() -> (Vec<u8>, Vec<[u8; 32]>, [u8; 32]) {
        let content: Vec<u8> = (0..3 * BLOCK_SIZE as usize)
            .map(|i| (i % 249) as u8)
            .collect();
        let leaves: Vec<[u8; 32]> = content
            .chunks(BLOCK_SIZE as usize)
            .map(merkle::block_hash)
            .collect();
        let root = merkle::file_root(&leaves, BLOCK_SIZE).unwrap_or_else(|e| panic!("{e}"));
        (content, leaves, root)
    }

    /// Layer-missing file data plane (isomorphic to assemble::build_faces):
    /// f0 layer-missing (recovery path + Pending gate), f1 fully enabled
    /// (control). Returns (face, book, root).
    fn fixture_plane() -> (FaceState, RecoveryBook, [u8; 32]) {
        let (_, piece_roots, root) = fixture();
        let layer_bytes: bytes::Bytes = piece_roots
            .iter()
            .flat_map(|h| h.iter())
            .copied()
            .collect::<Vec<u8>>()
            .into();
        let files = vec![
            MetaFile {
                path: PathBuf::from("missing.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some(root),
                piece_layer: None,
                v1_offset: Some(0),
            },
            MetaFile {
                path: PathBuf::from("full.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some([0xEE; 32]),
                piece_layer: Some(layer_bytes),
                v1_offset: Some(3 * u64::from(BLOCK_SIZE)),
            },
        ];
        let addressing = Addressing::PerFile {
            piece_bases: vec![0, 3],
        };
        let plane = build_v2_data_plane(Some(&files), addressing, BLOCK_SIZE);
        // Face: the minimal v2 face of recovery_tests::recovery_face, with
        // trees/layers/coords swapped in from the data-plane products.
        let mut face = crate::recovery_tests::recovery_face(6, BLOCK_SIZE);
        face.trees = plane.trees.clone();
        face.layers = plane.layers;
        face.flat_coords = plane.coords.clone();
        (face, plane.recovery, root)
    }

    fn delivered(rec_root: [u8; 32], layer: Vec<[u8; 32]>) -> RecoveredPieceLayer {
        RecoveredPieceLayer {
            root: rec_root,
            file_len: 3 * u64::from(BLOCK_SIZE),
            piece_len: BLOCK_SIZE,
            layer,
        }
    }

    /// Push a bookkeeping entry to Delivered (the terminal state after the
    /// delivery path completes collection — the consumer only treats
    /// Delivered entries as delivery sources).
    fn mark_delivered(book: &mut RecoveryBook) {
        if let Some(entry) = book.files.get_mut(&0) {
            entry.state = RecoveryFetchState::Delivered;
        }
    }

    /// Activation-chain integration: data-plane registration (layer_missing →
    /// Pending gate + recovery book + planner vector) → delivery consumption
    /// → whole-file convergence into the anchor domain (the metadata layer's
    /// trust level) → bookkeeping removal + lazy-fetch plans ready (the gate
    /// stays Pending — activation is a separate step) → the admitted count.
    #[test]
    fn activation_chain_admits_and_upgrades_runtime() {
        let (mut face, mut book, root) = fixture_plane();
        let (_, piece_roots, _) = fixture();
        let mut stats = RecoveryAdmissionStats::default();
        // Registration: layer-missing file 0 booked + Pending gate + empty
        // plans + planner ready (single-pass chunk coverage).
        let rec = book
            .files
            .get(&0)
            .unwrap_or_else(|| panic!("the layer-missing file is booked"));
        assert!(matches!(rec.state, RecoveryFetchState::Missing));
        assert_eq!(rec.staging.pieces(), 3);
        assert_eq!(
            rec.staging.block_count(),
            2,
            "3 pieces -> a 2+2 single-pass coverage plan"
        );
        assert!(matches!(face.layers[0].state, LayerFetchState::Pending));
        assert!(
            face.layers[0].plans.is_empty(),
            "the lazy-fetch domain stays detached before convergence"
        );
        // The fully-enabled control file is not booked.
        assert!(!book.files.contains_key(&1));

        // Consume the delivery (good layer; the entry is pushed to Delivered
        // first — the collection-complete terminal state).
        mark_delivered(&mut book);
        consume_recovered_layer_core(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            delivered(root, piece_roots.clone()),
        );
        // Admission complete: count +1, bookkeeping removed, anchor-domain registered.
        assert_eq!(stats.admitted, 1);
        assert_eq!(stats.rejected, 0);
        assert!(
            !book.files.contains_key(&0),
            "bookkeeping removed after convergence"
        );
        {
            let trees = face.trees.as_ref().unwrap_or_else(|| panic!("v2 base"));
            let trees = trees.lock().unwrap_or_else(|e| e.into_inner());
            assert!(trees.has_file(&root), "the anchor domain registered");
        }
        // Runtime upgrade: true root + lazy-fetch plans ready; the gate stays Pending.
        assert_eq!(face.layers[0].root, root);
        assert_eq!(
            face.layers[0].plans,
            plan_base_layer_fetch(3 * u64::from(BLOCK_SIZE), BLOCK_SIZE)
        );
        assert!(
            matches!(face.layers[0].state, LayerFetchState::Pending),
            "download activation belongs to C-3: the gate is held"
        );
    }

    /// Bad-layer drop and refetch convergence: flipping any hash → the whole
    /// file is not admitted (zero anchor-domain writes) + drop counter +
    /// re-stage (Missing, attempts+1, tried-peer memory kept); the driver can
    /// then issue again (closing the activation loop), and a good refetched
    /// layer converges into the store.
    #[test]
    fn bad_layer_discarded_counted_and_refetch_converges() {
        let (mut face, mut book, root) = fixture_plane();
        let (content, mut piece_roots, _) = fixture();
        let mut stats = RecoveryAdmissionStats::default();
        // Bad layer: flip 1 bit of the second piece root (the entry is pushed to Delivered first).
        piece_roots[1][0] ^= 0x01;
        mark_delivered(&mut book);
        consume_recovered_layer_core(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            delivered(root, piece_roots.clone()),
        );
        assert_eq!(stats.rejected, 1, "the drop counter");
        assert_eq!(stats.admitted, 0);
        {
            let trees = face.trees.as_ref().unwrap_or_else(|| panic!("v2 base"));
            let trees = trees.lock().unwrap_or_else(|e| e.into_inner());
            assert!(
                !trees.has_file(&root),
                "a bad layer keeps the whole file out of the store"
            );
        }
        // Re-stage: Missing + budget spent +1 (input to the from-another-peer refetch convergence).
        let entry = book.files.get(&0).unwrap_or_else(|| panic!("still booked"));
        assert!(matches!(entry.state, RecoveryFetchState::Missing));
        assert_eq!(entry.attempts, 1, "refetch budget consumed");
        assert!(
            entry.staging.build_deliverable().is_none(),
            "staging was reset: a full re-collection is required before another delivery"
        );
        // The driver can keep issuing fetches for the file (reply arm →
        // consumer arm → driver loop closes; with no peer it stays Missing
        // and never sends blind).
        let (deliver, _rx) = tokio::sync::mpsc::channel::<RecoveredPieceLayer>(8);
        drive_recovery(&mut face, 0, &mut book, &deliver);
        assert!(matches!(book.files[&0].state, RecoveryFetchState::Missing));

        // Good refetched layer → converges into the store (closing the
        // refetch loop; a completed refetch is delivered through Delivered as
        // well).
        let (_, good_roots, _) = fixture();
        mark_delivered(&mut book);
        consume_recovered_layer_core(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            delivered(root, good_roots),
        );
        assert_eq!(stats.admitted, 1);
        assert!(!book.files.contains_key(&0));
        {
            let trees = face.trees.as_ref().unwrap_or_else(|| panic!("v2 base"));
            let mut trees = trees.lock().unwrap_or_else(|e| e.into_inner());
            assert!(trees.has_file(&root));
            // Post-admission downstream equivalence: the lazy leaf layer
            // backfills through the same path; block checks pass true blocks
            // and reject bad ones — bit-identical to a metadata-carried
            // layer.
            let leaves: Vec<[u8; 32]> = content
                .chunks(BLOCK_SIZE as usize)
                .map(merkle::block_hash)
                .collect();
            trees
                .verify_and_put_layer(&root, 0, 0, leaves)
                .unwrap_or_else(|e| panic!("lazy admission after recovery: {e}"));
            assert!(
                trees
                    .verify_block(&root, 0, &content[..BLOCK_SIZE as usize])
                    .unwrap_or_else(|e| panic!("{e}"))
            );
            let mut bad = content.clone();
            bad[BLOCK_SIZE as usize] ^= 0x01;
            assert!(
                !trees
                    .verify_block(&root, 1, &bad[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize])
                    .unwrap_or_else(|e| panic!("{e}")),
                "the admission layer's bad-block verdict matches the metadata layer"
            );
        }
    }

    /// Re-admission of an already-anchored root → the benign AlreadyAnchored
    /// arm (not counted as a bad layer; the same trust level); stale
    /// deliveries (no Delivered match) leave the counters untouched.
    #[test]
    fn redundant_and_stale_deliveries_dropped_benignly() {
        let (mut face, mut book, root) = fixture_plane();
        let (_, piece_roots, _) = fixture();
        let mut stats = RecoveryAdmissionStats::default();
        // Stale delivery: the entry is still Missing (never fetched/delivered)
        // → no match, counters untouched.
        consume_recovered_layer_core(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            delivered(root, piece_roots.clone()),
        );
        assert_eq!(stats.admitted, 0);
        assert_eq!(stats.rejected, 0);
        assert!(
            book.files.contains_key(&0),
            "a stale delivery does not touch the booked entry"
        );
        // Same-root re-admission → AlreadyAnchored (the consumer's branch for
        // this case is a benign drop — see `consume_recovered_layer_unified`).
        let mut direct = taiji_store::hashtree::HashTreeCache::new(BLOCK_SIZE);
        direct.add_file(root, piece_roots.clone());
        assert!(matches!(
            admit_piece_layer(
                &mut direct,
                &root,
                &piece_roots,
                3 * u64::from(BLOCK_SIZE),
                BLOCK_SIZE
            ),
            Err(AdmissionError::AlreadyAnchored)
        ));
    }

    /// Staging → delivery → consumption payload consistency: a
    /// PieceLayerStaging delivery payload feeds the consumer's admission
    /// directly (the seam signature unchanged).
    #[test]
    fn staging_deliverable_feeds_admission() {
        let (_, piece_roots, root) = fixture();
        let mut st = PieceLayerStaging::new(root, 3 * u64::from(BLOCK_SIZE), BLOCK_SIZE);
        for (i, plan) in st.plans().to_vec().iter().enumerate() {
            let mut hashes: Vec<[u8; 32]> = Vec::new();
            for k in 0..plan.length {
                let idx = plan.index + k;
                hashes.push(if (idx as usize) < piece_roots.len() {
                    piece_roots[idx as usize]
                } else {
                    [0u8; 32] // zero-filled slot (server pad semantics)
                });
            }
            let _ = st.stage(i, &hashes).unwrap_or_else(|e| panic!("{e:?}"));
        }
        let rec = st.build_deliverable().unwrap_or_else(|| panic!("complete"));
        assert_eq!(
            rec.layer, piece_roots,
            "after zero-slot truncation = the true layer"
        );
        // The payload feeds admission directly.
        let mut trees = taiji_store::hashtree::HashTreeCache::new(BLOCK_SIZE);
        admit_piece_layer(
            &mut trees,
            &rec.root,
            &rec.layer,
            rec.file_len,
            rec.piece_len,
        )
        .unwrap_or_else(|e| panic!("the delivery payload must pass admission: {e}"));
        assert!(trees.has_file(&root));
    }

    // -----------------------------------------------------------------------
    // Gated promotion ("gated" → "released"): admission → activation-chain
    // propagation + the pipeline expected-root seam payload proof.
    // -----------------------------------------------------------------------

    use taiji_store::layout::Layout as SwapLayout;
    use taiji_store::layout::PlanEntry;
    use taiji_store::torrent_writer::TorrentWriter;
    use taiji_store::verified::VerifiedWriter;

    /// Pipeline seam carrier (isomorphic to assemble::build_faces): a live
    /// copy + watch channel, initial = the build-time shape (placeholder zero
    /// roots for layer-missing pieces). 6 slots = two 3-piece files.
    fn upgrade_harness() -> (
        RecoveryUpgrade,
        tokio::sync::watch::Receiver<std::sync::Arc<ExpectedRoots>>,
        Vec<ExpectedPieceHash>,
    ) {
        let master_expected = vec![ExpectedPieceHash::V2([0u8; 32]); 6];
        let master_leaves = vec![([0u8; 32], 0u64); 6];
        let (tx, rx) = tokio::sync::watch::channel(std::sync::Arc::new(ExpectedRoots {
            expected: master_expected.clone(),
            piece_leaves: std::sync::Arc::new(master_leaves.clone()),
        }));
        let up = RecoveryUpgrade {
            expected: master_expected.clone(),
            piece_leaves: std::sync::Arc::new(master_leaves),
            tx,
        };
        (up, rx, master_expected)
    }

    /// Gate-promotion propagation integration: delivery → whole-file
    /// admission → full activation-chain propagation — (1) download gate
    /// Pending → Queued (dispatch unlocked, lazy-fetch plans ready); (2)
    /// pipeline expected-root live backfill (true piece roots + true file
    /// roots, non-missing slots untouched, the payload can build a HashPool
    /// plan); (3) seeding hash service backfill (layer None → recovery
    /// layer); (4) dispatch bookkeeping cleared; idempotent (a second
    /// activation is a no-op); a bad-layer delivery yields no activation
    /// coordinate (the gate stays closed — the negative case).
    #[test]
    fn gate_lift_propagates_to_seam_service_and_dispatch_state() {
        let (mut face, mut book, root) = fixture_plane();
        let (_, piece_roots, _) = fixture();
        let mut stats = RecoveryAdmissionStats::default();
        let (mut upgrade, rx, master_expected) = upgrade_harness();
        // Seeding hash service face (attach_seeding_sources consumption
        // shape; f0 layer-missing None).
        let hash_files = vec![
            MetaFile {
                path: PathBuf::from("missing.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some(root),
                piece_layer: None,
                v1_offset: Some(0),
            },
            MetaFile {
                path: PathBuf::from("full.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some([0xEE; 32]),
                piece_layer: None,
                v1_offset: Some(3 * u64::from(BLOCK_SIZE)),
            },
        ];
        face.hash_files = Some(hash_files);
        // Dispatch bookkeeping junk (another file's in-flight/buffered/
        // refetch shape; promotion must clear it in sync with the pipeline
        // write-cache destruction).
        face.blocks_sent
            .insert(3, PieceSentLedger::new(1, std::time::Instant::now()));
        if let Some(ledger) = face.blocks_sent.get_mut(&3) {
            ledger.mark_buffered(0);
        }
        face.refetch.push((4, 16384, 16384));
        let (_junk_tx, junk_rx) = tokio::sync::oneshot::channel();
        face.dispatch_replies.push((4, 16384, junk_rx));

        // Bad-layer delivery (1 bit flipped) → convergence fails → no
        // activation coordinate (the gate stays).
        let mut bad = piece_roots.clone();
        bad[1][0] ^= 0x01;
        mark_delivered(&mut book);
        let admitted = consume_recovered_layer_core(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            delivered(root, bad),
        );
        assert_eq!(
            admitted, None,
            "a bad layer must not trigger gate promotion"
        );
        assert!(matches!(face.layers[0].state, LayerFetchState::Pending));

        // Good-layer delivery → admission → activation (EngineLoop arm
        // order: core → activate).
        mark_delivered(&mut book);
        let rec = delivered(root, piece_roots.clone());
        let admitted = consume_recovered_layer_core(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            rec.clone(),
        );
        assert_eq!(
            admitted,
            Some((0, 0)),
            "admission success = the activation coordinate"
        );
        assert!(activate_recovered_file(
            &mut face,
            Some(&mut upgrade),
            0,
            &rec
        ));

        // (1) Download gate promotion (dispatch unlocked; the existing
        // lazy-fetch/dispatch paths take over).
        assert!(matches!(
            face.layers[0].state,
            LayerFetchState::Queued { next: 0 }
        ));
        // (2) Pipeline expected-root live backfill (the seam payload = the latest watch snapshot).
        let payload = rx.borrow().clone();
        for (k, r) in piece_roots.iter().enumerate() {
            assert_eq!(
                payload.expected[k],
                ExpectedPieceHash::V2(*r),
                "missing-layer slot {k} backfilled with the true piece root"
            );
            assert_eq!(
                payload.piece_leaves[k].0, root,
                "block-check file root backfilled"
            );
        }
        assert_eq!(
            payload.expected[3], master_expected[3],
            "non-missing-layer slots (the control file) are unaffected by activation"
        );
        // The payload is isomorphic to the pipeline rebuild: it can build a
        // HashPool plan directly (same face geometry).
        taiji_store::hashpool::HashPool::new_plan(
            payload.expected.to_vec(),
            BLOCK_SIZE,
            &[3 * u64::from(BLOCK_SIZE), 3 * u64::from(BLOCK_SIZE)],
        )
        .unwrap_or_else(|e| panic!("the seam payload builds a pool plan: {e}"));
        // (3) Seeding hash service backfill (the recovery layer = the
        // metadata layer's trust level).
        let files = face
            .hash_files
            .as_ref()
            .unwrap_or_else(|| panic!("hash files"));
        let layer = files[0]
            .piece_layer
            .as_ref()
            .unwrap_or_else(|| panic!("f0 recovery layer backfilled"));
        assert_eq!(layer.len(), piece_roots.len() * 32);
        assert!(files[1].piece_layer.is_none(), "the control file untouched");
        // (4) Dispatch bookkeeping cleared.
        assert!(
            face.blocks_sent.is_empty()
                && face.refetch.is_empty()
                && face.dispatch_replies.is_empty(),
            "the pipeline write cache is destroyed with the rebuild -> dispatch \
             in-flight/buffered/refetch bookkeeping cleared in step"
        );
        // Idempotent: re-activating a promoted file is a no-op (the promoted
        // state is never downgraded/replayed).
        assert!(!activate_recovered_file(
            &mut face,
            Some(&mut upgrade),
            0,
            &rec
        ));
        assert!(matches!(
            face.layers[0].state,
            LayerFetchState::Queued { next: 0 }
        ));
    }

    /// Pipeline expected-root seam payload proof (the persist half): with
    /// placeholder zero roots, piece-completion verification structurally
    /// cannot pass (SHA-256 preimage resistance — the basis for the gate);
    /// after the seam backfills true roots, the same pipeline construction
    /// verifies — verify-before-persist holds on both sides of the gate, so
    /// download completes naturally once the layer arrives (no restart).
    #[test]
    fn seam_payload_piece_verification_round_trip() {
        let (content, piece_roots, _root) = fixture();
        let file_len = 3 * u64::from(BLOCK_SIZE);
        let entries = vec![PlanEntry {
            path: PathBuf::from("f.bin"),
            length: file_len,
            padding: false,
        }];
        let layout =
            SwapLayout::plan_v1_padded(&entries, BLOCK_SIZE).unwrap_or_else(|e| panic!("{e}"));
        let push_all = |expected: Vec<ExpectedPieceHash>| {
            let pool = taiji_store::hashpool::HashPool::new_plan(expected, BLOCK_SIZE, &[file_len])
                .unwrap_or_else(|e| panic!("{e}"));
            let mut vw = VerifiedWriter::new(
                Box::new(TorrentWriter::new(
                    layout.clone(),
                    PathBuf::from("/nonexistent"),
                    100,
                )),
                pool,
                taiji_store::cache::DEFAULT_CACHE_LIMIT,
            );
            let mut jobs = Vec::new();
            for (p, chunk) in content.chunks(BLOCK_SIZE as usize).enumerate() {
                match vw
                    .push_block_pooled_at(
                        p as u64,
                        p as u64 * u64::from(BLOCK_SIZE),
                        0,
                        &bytes::Bytes::copy_from_slice(chunk),
                    )
                    .unwrap_or_else(|e| panic!("push: {e}"))
                {
                    taiji_store::verified::PooledOutcome::PieceCompleted(job) => jobs.push(job),
                    other => panic!("unexpected outcome: {other:?}"),
                }
            }
            jobs
        };
        // Placeholder zero roots (the layer not yet filled): verification
        // must fail — the structural basis for withholding download.
        for job in push_all(vec![ExpectedPieceHash::V2([0u8; 32]); 3]) {
            assert_eq!(
                job.verify(),
                Ok(false),
                "zero roots cannot converge — releasing dispatch would only create \
                 a verify-failure refetch storm"
            );
        }
        // Seam backfilled with true roots (the filled shape): the same
        // construction verifies → persistable.
        let real = piece_roots
            .iter()
            .map(|r| ExpectedPieceHash::V2(*r))
            .collect();
        for job in push_all(real) {
            assert_eq!(
                job.verify(),
                Ok(true),
                "verification passes once roots are backfilled"
            );
        }
    }

    // -----------------------------------------------------------------------
    // AlreadyAnchored unified promotion: every layer-missing Pending file
    // sharing the root is promoted with the anchor, eliminating the
    // "second file gated forever" stall.
    // -----------------------------------------------------------------------

    /// Push an arbitrary bookkeeping entry to Delivered (the
    /// coordinate-parameterized [`mark_delivered`]; the existing helper is
    /// untouched).
    fn mark_delivered_idx(book: &mut RecoveryBook, file_idx: usize) {
        if let Some(entry) = book.files.get_mut(&file_idx) {
            entry.state = RecoveryFetchState::Delivered;
        }
    }

    /// Same-root dual layer-missing data plane: f0 and f1 share a root and
    /// length, both layer-missing (duplicate-content files), f2 the fully
    /// enabled control. Returns (face, book, root).
    fn same_root_plane() -> (FaceState, RecoveryBook, [u8; 32]) {
        let (_, piece_roots, root) = fixture();
        let layer_bytes: bytes::Bytes = piece_roots
            .iter()
            .flat_map(|h| h.iter())
            .copied()
            .collect::<Vec<u8>>()
            .into();
        let missing = |path: &str, offset: u64| MetaFile {
            path: PathBuf::from(path),
            length: 3 * u64::from(BLOCK_SIZE),
            padding: false,
            pieces_root: Some(root),
            piece_layer: None,
            v1_offset: Some(offset),
        };
        let files = vec![
            missing("dup-a.bin", 0),
            missing("dup-b.bin", 3 * u64::from(BLOCK_SIZE)),
            MetaFile {
                path: PathBuf::from("full.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some([0xEE; 32]),
                piece_layer: Some(layer_bytes),
                v1_offset: Some(6 * u64::from(BLOCK_SIZE)),
            },
        ];
        let plane = build_v2_data_plane(
            Some(&files),
            Addressing::PerFile {
                piece_bases: vec![0, 3, 6],
            },
            BLOCK_SIZE,
        );
        let mut face = crate::recovery_tests::recovery_face(9, BLOCK_SIZE);
        face.trees = plane.trees.clone();
        face.layers = plane.layers;
        face.flat_coords = plane.coords.clone();
        assert!(
            book_has(&plane.recovery, 0) && book_has(&plane.recovery, 1),
            "same-root dual layer-missing files each hold one recovery entry"
        );
        (face, plane.recovery, root)
    }

    fn book_has(book: &RecoveryBook, file_idx: usize) -> bool {
        book.files.contains_key(&file_idx)
    }

    /// n-slot pipeline seam carrier (the slot-parameterized [`upgrade_harness`]).
    fn upgrade_harness_n(
        slots: usize,
    ) -> (
        RecoveryUpgrade,
        tokio::sync::watch::Receiver<std::sync::Arc<ExpectedRoots>>,
        Vec<ExpectedPieceHash>,
    ) {
        let master_expected = vec![ExpectedPieceHash::V2([0u8; 32]); slots];
        let master_leaves = vec![([0u8; 32], 0u64); slots];
        let (tx, rx) = tokio::sync::watch::channel(std::sync::Arc::new(ExpectedRoots {
            expected: master_expected.clone(),
            piece_leaves: std::sync::Arc::new(master_leaves.clone()),
        }));
        let up = RecoveryUpgrade {
            expected: master_expected.clone(),
            piece_leaves: std::sync::Arc::new(master_leaves),
            tx,
        };
        (up, rx, master_expected)
    }

    /// Admission-arm unified promotion (both files reach ready): after a
    /// single delivery (f0's layer) is admitted, the same-root f1 entry is
    /// removed in sync + its runtime representation upgraded + the activation
    /// chain propagates — both files Queued in the same round, both slot
    /// groups backfilled in the seam payload, double hash-service backfill.
    #[test]
    fn rec1_admission_promotes_all_same_root_files() {
        let (mut face, mut book, root) = same_root_plane();
        let (_, piece_roots, _) = fixture();
        let mut stats = RecoveryAdmissionStats::default();
        let (mut upgrade, rx, master_expected) = upgrade_harness_n(9);
        // Seeding hash service face (f0/f1 layer-missing None).
        let hash_files = vec![
            MetaFile {
                path: PathBuf::from("dup-a.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some(root),
                piece_layer: None,
                v1_offset: Some(0),
            },
            MetaFile {
                path: PathBuf::from("dup-b.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some(root),
                piece_layer: None,
                v1_offset: Some(3 * u64::from(BLOCK_SIZE)),
            },
            MetaFile {
                path: PathBuf::from("full.bin"),
                length: 3 * u64::from(BLOCK_SIZE),
                padding: false,
                pieces_root: Some([0xEE; 32]),
                piece_layer: None,
                v1_offset: Some(6 * u64::from(BLOCK_SIZE)),
            },
        ];
        face.hash_files = Some(hash_files);

        // Single delivery (the f0 entry Delivered) → admission + f1's
        // unified promotion coordinate.
        mark_delivered_idx(&mut book, 0);
        let rec = delivered(root, piece_roots.clone());
        let outcome = consume_recovered_layer_unified(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            rec.clone(),
        );
        let (primary, siblings) = (outcome.primary, outcome.siblings);
        assert_eq!(
            primary,
            Some((0, 0)),
            "primary coordinate = the delivery-matched entry"
        );
        assert_eq!(
            siblings,
            vec![(0, 1)],
            "same-root siblings unify to the promotion coordinate"
        );
        assert_eq!(stats.admitted, 1);
        assert_eq!(stats.rejected, 0);
        assert!(
            !book_has(&book, 0) && !book_has(&book, 1),
            "both entries removed with the anchor (the driver wheel stops refetching)"
        );
        // f1's runtime representation is upgraded (true root + lazy-fetch plans ready).
        assert_eq!(face.layers[1].root, root);
        assert_eq!(
            face.layers[1].plans,
            plan_base_layer_fetch(3 * u64::from(BLOCK_SIZE), BLOCK_SIZE)
        );

        // Activation-chain propagation (both files in the same round).
        assert!(activate_recovered_file(
            &mut face,
            Some(&mut upgrade),
            0,
            &rec
        ));
        assert!(activate_recovered_file(
            &mut face,
            Some(&mut upgrade),
            1,
            &rec
        ));
        assert!(matches!(
            face.layers[0].state,
            LayerFetchState::Queued { next: 0 }
        ));
        assert!(
            matches!(face.layers[1].state, LayerFetchState::Queued { next: 0 }),
            "the second file no longer stalls forever (the PoC's reverse assertion)"
        );
        // Seam payload: both slot groups [0,6) backfilled with true piece +
        // file roots; the control [6,9) untouched.
        let payload = rx.borrow().clone();
        for k in 0..6usize {
            assert_eq!(
                payload.expected[k],
                ExpectedPieceHash::V2(piece_roots[k % 3]),
                "slot {k} backfilled with the true piece root"
            );
            assert_eq!(
                payload.piece_leaves[k].0, root,
                "slot {k} file root backfilled"
            );
        }
        assert_eq!(
            payload.expected[6], master_expected[6],
            "the control slot untouched"
        );
        // Double seeding-hash-service backfill.
        let files = face
            .hash_files
            .as_ref()
            .unwrap_or_else(|| panic!("hash files"));
        assert!(files[0].piece_layer.is_some() && files[1].piece_layer.is_some());
        assert!(files[2].piece_layer.is_none(), "the control file untouched");
    }

    /// AlreadyAnchored-arm cure (the main stall scenario): the root is
    /// already anchored (a prior admission / the metadata layer present)
    /// while a same-root file entry is still booked and its delivery arrives
    /// — on AlreadyAnchored the delivery is no longer benignly dropped;
    /// convergence validation runs first (verify-before-persist) and passing
    /// it promotes uniformly, so the gate never sticks permanently.
    #[test]
    fn rec1_already_anchored_delivery_promotes_gated_file() {
        let (mut face, mut book, root) = same_root_plane();
        let (_, piece_roots, _) = fixture();
        let mut stats = RecoveryAdmissionStats::default();
        let (mut upgrade, _rx, _master) = upgrade_harness_n(9);

        // Pre-anchor: f0's true layer goes straight into the store (simulating
        // a prior admission / the metadata layer present) — f1's entry stays
        // booked (Missing, its fetch not yet converged).
        {
            let trees = face.trees.as_ref().unwrap_or_else(|| panic!("v2 base"));
            let mut trees = trees.lock().unwrap_or_else(|e| e.into_inner());
            trees.add_file(root, piece_roots.clone());
        }
        assert!(matches!(face.layers[1].state, LayerFetchState::Pending));

        // f1's own delivery arrives → admission hits AlreadyAnchored →
        // validation passes → unified promotion (f0's entry is undelivered,
        // but the same-root anchor exists — promoted along with this one).
        mark_delivered_idx(&mut book, 1);
        let rec = delivered(root, piece_roots.clone());
        let outcome = consume_recovered_layer_unified(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            rec.clone(),
        );
        let (primary, siblings) = (outcome.primary, outcome.siblings);
        assert_eq!(primary, Some((0, 1)), "the anchored coordinate = f1 itself");
        assert_eq!(
            siblings,
            vec![(0, 0)],
            "the same-root sibling (f0) promoted along"
        );
        assert_eq!(
            stats.admitted, 0,
            "a duplicate admission is not counted as a new admission"
        );
        assert_eq!(
            stats.rejected, 0,
            "a redundant delivery that passes convergence is not a bad layer"
        );
        assert!(
            !book_has(&book, 1) && !book_has(&book, 0),
            "both entries removed"
        );
        assert_eq!(face.layers[1].root, root);
        assert!(activate_recovered_file(
            &mut face,
            Some(&mut upgrade),
            1,
            &rec
        ));
        assert!(matches!(
            face.layers[1].state,
            LayerFetchState::Queued { .. }
        ));
    }

    /// Safety: a bad-layer redundant delivery on an anchored root — failed
    /// convergence validation = zero promotion (unverified bytes never enter
    /// the seam) + the drop counter; the gate stays Pending.
    #[test]
    fn rec1_anchored_root_bad_layer_never_promotes() {
        let (mut face, mut book, root) = same_root_plane();
        let (_, mut piece_roots, _) = fixture();
        let mut stats = RecoveryAdmissionStats::default();
        // Pre-anchor (f0's true layer straight into the store, simulating a
        // prior admission / the metadata layer present).
        {
            let trees = face.trees.as_ref().unwrap_or_else(|| panic!("v2 base"));
            let mut trees = trees.lock().unwrap_or_else(|e| e.into_inner());
            trees.add_file(root, piece_roots.clone());
        }
        // f1's delivery with 1 bit flipped → convergence validation fails
        // inside the AlreadyAnchored arm.
        piece_roots[2][0] ^= 0x01;
        mark_delivered_idx(&mut book, 1);
        let outcome = consume_recovered_layer_unified(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut stats,
            delivered(root, piece_roots),
        );
        assert_eq!(
            outcome.primary, None,
            "a bad layer yields zero promotion coordinates"
        );
        assert!(outcome.siblings.is_empty());
        assert_eq!(
            stats.rejected, 1,
            "bad-layer drop counter (visible per AGENTS §2.6)"
        );
        assert!(
            !book_has(&book, 1),
            "the redundant bad-layer entry removed benignly (the anchor unaffected)"
        );
        assert!(
            matches!(face.layers[1].state, LayerFetchState::Pending),
            "the gate must not be released by unverified bytes"
        );
        assert_eq!(
            face.layers[1].root, [0u8; 32],
            "the runtime representation un-promoted"
        );
    }

    // -----------------------------------------------------------------------
    // Recovery event surface (taiji.recoveryStarted/Completed): activation
    // missing-set extraction / exactly-once promotion registration /
    // getFiles layer-missing projection table.
    // -----------------------------------------------------------------------

    /// Single-file face with the given lazy-fetch gate states (for projection
    /// tables; the other fields = the minimal
    /// [`crate::recovery_tests::recovery_face`] face).
    fn face_with_layer_states(states: Vec<LayerFetchState>) -> FaceState {
        let mut face = crate::recovery_tests::recovery_face(states.len(), BLOCK_SIZE);
        face.layers = states
            .into_iter()
            .map(|state| FileLayerState {
                root: [0u8; 32],
                piece_base: 0,
                leaf_total: 0,
                plans: Vec::new(),
                state,
                attempts: 0,
            })
            .collect();
        face
    }

    /// Activation missing-set extraction: the union of bookkeeping keys
    /// across faces (empty v1 books do not count, ascending, deduped); after
    /// the promotion consumes the book, the set empties (repeated activation
    /// emits nothing).
    #[test]
    fn activation_files_extracts_book_keys() {
        let (mut face, mut book, root) = fixture_plane();
        let (_, piece_roots, _) = fixture();
        // Empty v1 face (control: layer-missing registers only on v2 faces).
        let v1_book = RecoveryBook::default();
        assert_eq!(
            activation_missing_files(std::slice::from_ref(&v1_book)),
            Vec::<usize>::new()
        );
        assert_eq!(
            activation_missing_files(std::slice::from_ref(&book)),
            vec![0]
        );
        mark_delivered(&mut book);
        consume_recovered_layer_core(
            std::slice::from_mut(&mut face),
            std::slice::from_mut(&mut book),
            &mut RecoveryAdmissionStats::default(),
            delivered(root, piece_roots),
        );
        assert_eq!(
            activation_missing_files(std::slice::from_ref(&book)),
            Vec::<usize>::new()
        );
    }

    /// Promotion registration: the open set empties monotonically →
    /// completed exactly once; stale/duplicate coordinates are no-ops; the
    /// stuck scenario (the open set never empties) never emits.
    #[test]
    fn note_promotions_completes_exactly_once() {
        let mut track = RecoveryEventTrack {
            started: vec![0, 3],
            open: vec![0, 3],
        };
        // Partial (f0) promotion → not converged.
        assert_eq!(note_promotions_core(&mut track, &[0]), None);
        assert_eq!(track.open, vec![3]);
        // Re-registering the same coordinate (idempotent) → not converged.
        assert_eq!(note_promotions_core(&mut track, &[0]), None);
        // Coordinate not in the open set (stale/defensive) → no-op.
        assert_eq!(note_promotions_core(&mut track, &[999]), None);
        // f3 promoted → converged; the payload = the full started set
        // (1-based client file order).
        assert_eq!(note_promotions_core(&mut track, &[3]), Some(vec![1, 4]));
        // Registering again after convergence → None (exactly once: the
        // emptying transition happens at most once).
        assert_eq!(note_promotions_core(&mut track, &[0, 3]), None);
        // Stuck-gate scenario: started non-empty, no promotions → always
        // None (the observable failure face of started without completed).
        let mut stuck = RecoveryEventTrack {
            started: vec![2],
            open: vec![2],
        };
        assert_eq!(note_promotions_core(&mut stuck, &[]), None);
        // Never activated (no missing set) → always None.
        let mut idle = RecoveryEventTrack::default();
        assert_eq!(note_promotions_core(&mut idle, &[0]), None);
    }

    /// getFiles layer-missing projection table: booked states →
    /// layer_missing/recovering; promoted → ready; the bad-layer-removal
    /// edge (started∩open, bookkeeping removed, gate Pending) →
    /// layer_missing; files not involved in recovery are not projected.
    #[test]
    fn recovery_file_states_projection_table() {
        // f0 Missing (booked), f1 Requesting (booked), f2 promoted (not
        // booked, not open), f3 = the stuck edge (bookkeeping gone, the gate
        // still closed).
        let face = face_with_layer_states(vec![
            LayerFetchState::Pending,
            LayerFetchState::Pending,
            LayerFetchState::Queued { next: 0 },
            LayerFetchState::Pending,
        ]);
        let mut book = RecoveryBook::default();
        let (_, _, root) = fixture();
        for (idx, st) in [
            (0usize, RecoveryFetchState::Missing),
            (1, RecoveryFetchState::Requesting { block: 0, cuid: 7 }),
        ] {
            let mut entry = FileRecovery::new(root, 3 * u64::from(BLOCK_SIZE), BLOCK_SIZE, 0)
                .unwrap_or_else(|| panic!("multi-piece registers"));
            entry.state = st;
            book.files.insert(idx, entry);
        }
        let track = RecoveryEventTrack {
            started: vec![0, 1, 2, 3],
            open: vec![0, 1, 3],
        };
        let states = recovery_file_states_core(
            std::slice::from_ref(&face),
            std::slice::from_ref(&book),
            &track,
        );
        assert_eq!(
            states,
            vec![
                (0, RECOVERY_LAYER_MISSING),
                (1, RECOVERY_RECOVERING),
                (2, RECOVERY_READY),
                (3, RECOVERY_LAYER_MISSING),
            ],
            "projection value range item by item: missing/recovering/ready/the stuck edge, accurately"
        );
    }
}

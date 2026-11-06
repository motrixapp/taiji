//! Engine teardown sequence: the stopped announce sequence, DHT
//! halt-save, and the final-value persistence flush.
//!
//! Scope: the protocol-mandated closing order before engine exit
//! (shutdown sequencing toward tracker/DHT/persistence); main-loop
//! decisions live in arms/dial/tick.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use tokio::sync::mpsc;
use tracing::{debug, warn};

use taiji_bt::dht::{DhtEvent, DhtFamily};
use taiji_bt::tracker::actor::{TrackerActorEvent, TrackerCommand};
use taiji_store::persist::TrackerRow;

use crate::metrics::SessionMetrics;

use super::state::EngineLoop;
use std::time::Duration;

use tokio::sync::oneshot;

use crate::dht::{DHT_HALT_SAVE_BUDGET, DhtFamilyWiring, family_key, persist_dht_state};
use crate::faces::FaceState;
use crate::pipeline::DataFlushState;
use crate::progress::{flush_progress_row, progress_row};
use crate::query::drain_peer_counters;
use crate::run::tick::{checkpoint_endgame, note_supply_down};
use crate::tracker::{STOPPED_ANNOUNCE_BUDGET, handle_tracker_bookkeeping};
/// Shutdown stopped sequence (user-stop path only — aria2 drives stopped
/// announce until noMoreAnnounce before shutdown, the
/// TrackerWatcherCommand shutdown semantics): Stop -> the actor drives
/// the stopped event sequence -> Halted; peers/store are torn down only
/// after every face completes or the budget expires. Completed/Failed do
/// not drive it (the RPC pause/remove shutdown semantics are owned
/// elsewhere; the actor terminates when the command channel drops).
/// Detached and SeedStopped are both "seeding ended" paths.
pub(super) async fn drive_stopped_sequence(
    state: &mut EngineLoop,
    actor_cmds: &[Option<mpsc::Sender<TrackerCommand>>],
    tracker_ev_rx: &mut mpsc::Receiver<(usize, TrackerActorEvent)>,
    metrics: Option<&SessionMetrics>,
) {
    for (fi, cmd) in actor_cmds.iter().enumerate() {
        let Some(cmd) = cmd else { continue };
        // Mirror halt flips at the same instant as the actor (the
        // attribution source for the stopped sequence's adjust).
        if let Some(face) = state.faces.get_mut(fi) {
            face.mirror.halt = true;
        }
        let (tx, rx) = oneshot::channel();
        if cmd.send(TrackerCommand::Stop { reply: tx }).await.is_ok() {
            // The reply only confirms acceptance; the stopped sequence is
            // driven by the actor's own tick.
            let _ = rx.await;
        }
    }
    let wait = async {
        let mut halted = vec![false; state.faces.len()];
        while halted.iter().any(|h| !*h) {
            match tracker_ev_rx.recv().await {
                None => break,
                Some((fi, TrackerActorEvent::Halted)) => {
                    if let Some(h) = halted.get_mut(fi) {
                        *h = true;
                    }
                }
                // Events inside the shutdown window are attributed and
                // persisted as usual (success/failure receipts of the
                // stopped announce); no more dialing (the engine is
                // tearing down).
                Some((fi, ev)) => {
                    if let Some(face) = state.faces.get_mut(fi) {
                        handle_tracker_bookkeeping(
                            face,
                            ev,
                            state.persist_shared.as_ref(),
                            metrics,
                        );
                    }
                }
            }
        }
    };
    if tokio::time::timeout(STOPPED_ANNOUNCE_BUDGET, wait)
        .await
        .is_err()
    {
        warn!(target: "taiji::core::engine",
            budget = ?STOPPED_ANNOUNCE_BUDGET,
            "stopped announce sequence budget exceeded; exiting without Halted");
    }
}

/// DHT halt-save (`DHTSetup.cc` + `DHTAutoSaveCommand.cc` shutdown-save
/// semantics): per-family Shutdown (the actor replies after its internal
/// emit_persist) -> harvest Persist events within the budget and persist
/// them (exactly one save per family).
pub(super) async fn dht_halt_save(
    state: &mut EngineLoop,
    dht_wiring: &[DhtFamilyWiring],
    dht_ev_rx: &mut mpsc::Receiver<(DhtFamily, DhtEvent)>,
) {
    if dht_wiring.is_empty() {
        return;
    }
    for w in dht_wiring {
        if let Err(e) = w.handle.shutdown().await {
            debug!(target: "taiji::core::engine", family = family_key(w.family),
                %e, "dht shutdown failed (actor already down)");
        }
    }
    let deadline = tokio::time::Instant::now() + DHT_HALT_SAVE_BUDGET;
    let mut saved = 0usize;
    while saved < dht_wiring.len() {
        match tokio::time::timeout_at(deadline, dht_ev_rx.recv()).await {
            Ok(Some((
                family,
                DhtEvent::Persist {
                    node_id,
                    routing_table,
                    ..
                },
            ))) => {
                persist_dht_state(
                    state.persist_shared.as_ref(),
                    family,
                    node_id,
                    routing_table,
                )
                .await;
                saved += 1;
            }
            Ok(Some(_)) => {}
            _ => break, // budget exhausted / channel closed (forwarder exited).
        }
    }
    if saved < dht_wiring.len() {
        warn!(target: "taiji::core::engine",
            saved, total = dht_wiring.len(),
            "dht halt-save budget exceeded; remaining families exit without save");
    }
    // Abort the actor tasks once saving is done (Shutdown already made
    // run() return; abort is idempotent).
    for w in dht_wiring {
        w.join.abort();
    }
}

/// Final data-flush barrier wait budget (hang fallback): the upper bound
/// for waiting on each face's store pipeline to "drain in-flight writes +
/// fsync data files". fsync is local IO; its cost bound = dirty page
/// volume / disk speed (the default throughput tier has no periodic
/// fsync, so the dirty set can reach GB scale — tens of seconds on HDD
/// is a real magnitude, not an anomaly). The budget only guards against
/// hung IO / a pipeline dying abnormally; on timeout the barrier counts
/// as not reached (the final progress row is refused — the safe
/// direction; resume-time recheck covers the loss).
const DATA_FLUSH_BUDGET: Duration = Duration::from_secs(120);

/// Barrier read-end collection (synchronous face): face state is not
/// `Sync`, references must not cross `await` — `final_flush` collects
/// owned values before the first wait point (clones start from the
/// current value; an already-set barrier returns at the wait point
/// immediately).
fn data_flush_gates(
    faces: &[FaceState],
) -> Vec<(usize, tokio::sync::watch::Receiver<DataFlushState>)> {
    faces
        .iter()
        .enumerate()
        .map(|(fi, f)| (fi, f.data_flush_gate.clone()))
        .collect()
}

/// Final data-flush barrier wait face: waits per face for that face's
/// store pipeline to complete "in-flight write drain + data file fsync"
/// (the pipeline::store_pipeline teardown segment; barrier state
/// [`DataFlushState`]).
///
/// Ordering invariant (the data half lives in the pipeline, the commit
/// half in this function's caller): **data fsync first, progress row
/// upsert second** — the same convention as the HTTP side (counterpart =
/// the `session/http/snapshot.rs` module-doc invariant "a crashed bitmap
/// must never get ahead of the data" plus its exit guard "a final row
/// carrying an unpersisted bitmap is refused"; on the BT side any set
/// value other than `Flushed` / a timeout = refuse to persist the final
/// progress row — under-record progress rather than ever over-record).
/// No artificial small budget: fsync cost is determined by dirty page
/// volume ([`DATA_FLUSH_BUDGET`] is only a hang fallback). Returns true
/// = all faces Flushed; the caller may persist the final progress row.
async fn data_flush_barrier(
    mut gates: Vec<(usize, tokio::sync::watch::Receiver<DataFlushState>)>,
) -> bool {
    let deadline = tokio::time::Instant::now() + DATA_FLUSH_BUDGET;
    let mut all_flushed = true;
    for (fi, gate) in gates.iter_mut() {
        let waited = tokio::time::timeout_at(
            deadline,
            gate.wait_for(|s| !matches!(s, DataFlushState::Pending)),
        )
        .await;
        match waited {
            // Set = Flushed: this face's data fsync is achieved (the
            // data-fsync-first half done; the caller persists the
            // progress row next).
            Ok(Ok(guard)) if matches!(&*guard, DataFlushState::Flushed) => {}
            // Set = Failed: fsync failure / pipeline teardown error —
            // refuse the final progress row (under-record rather than
            // over-record; the error escalation matches the periodic
            // flush arm's Fatal). (The predicate excludes Pending:
            // `wait_for` returns only at a set value; a set value that
            // is not Flushed is Failed.)
            Ok(Ok(guard)) => {
                warn!(target: "taiji::core::engine", face = fi, state = ?*guard,
                    "data flush barrier failed: final progress row refused");
                all_flushed = false;
            }
            // Barrier sender gone (the pipeline task died abnormally
            // without reaching the teardown segment) = barrier not
            // reached.
            Ok(Err(_)) => {
                warn!(target: "taiji::core::engine", face = fi,
                    "data flush barrier sender gone: final progress row refused");
                all_flushed = false;
            }
            Err(_) => {
                warn!(target: "taiji::core::engine", face = fi,
                    budget = ?DATA_FLUSH_BUDGET,
                    "data flush barrier budget exceeded: final progress row refused");
                all_flushed = false;
            }
        }
    }
    all_flushed
}

/// Final flush: serially writes the dirty rows attributed during the
/// shutdown window; persists the final counter-row values: the session's
/// final uploaded/downloaded/time totals; the next task registration
/// reads them back via LoadTorrentProgress as the ratio base. This is
/// the last counter bridge before the final values (peer tasks are
/// already aborted, so the atomics are stable; the convergence point
/// from per-peer counters to session totals). Same-increment metric
/// closing (the flusher abort is executed by the caller afterwards —
/// single-writer discipline). The parameters are the run() locals this
/// teardown step consumes.
///
/// Final-state persistence barrier: before the final progress row is
/// persisted it passes the data flush barrier ([`data_flush_barrier`] —
/// each face's store pipeline drains in-flight writes and fsyncs data
/// files). The trigger is sent first (the barrier window overlaps the
/// tracker row persistence); the progress row is assembled/persisted
/// only after the barrier is reached; barrier not reached = the progress
/// row is refused (tracker rows are a counting face with unchanged
/// tolerance — the loss converges via the next save's overwrite). The
/// 60s regular autosave (run/tick.rs) has its own snapshot write barrier
/// (dirty-face fsync before the bitmap row upsert, fail-closed) — this
/// barrier remains the zero-overrecord closing point for the final row.
#[expect(
    clippy::too_many_arguments,
    reason = "tail body: parameters mirror the run() locals the original exit path captured"
)]
pub(super) async fn final_flush(
    state: &mut EngineLoop,
    metrics: Option<&SessionMetrics>,
    session_up: &AtomicU64,
    session_down: &AtomicU64,
    piece_len: u32,
    startup_uploaded: u64,
    startup_downloaded: u64,
    startup_active_s: u64,
    startup_seed_s: u64,
) {
    if let Some(p) = state.persist_shared.as_ref() {
        // gid for log attribution (owned value: the barrier-refusal warn
        // must not extend the persist borrow — avoids conflicting with
        // the &mut state bookkeeping below).
        let gid = p.gid.clone();
        // Barrier trigger sent first: the pipeline teardown
        // (drain+fsync) overlaps the tracker row persistence; the
        // progress row comes after the barrier wait point. Clone the
        // senders first (face state is not `Sync`; references must not
        // cross `await`).
        let flush_txs: Vec<mpsc::Sender<()>> = state
            .faces
            .iter()
            .map(|f| f.final_flush_tx.clone())
            .collect();
        for tx in &flush_txs {
            // Send failure = the pipeline already exited (its barrier
            // was set on the teardown or abnormal path / the sender is
            // gone) — the wait point decides from the barrier reading.
            let _ = tx.send(()).await;
        }
        let rows: Vec<TrackerRow> = {
            let mut d = crate::lock(&p.dirty);
            std::mem::take(&mut *d)
        };
        for row in rows {
            if let Err(e) = p.handle.upsert_tracker(row).await {
                warn!(target: "taiji::core::engine", gid = %p.gid, %e,
                    "final tracker row flush failed");
            }
        }
        let drained = drain_peer_counters(
            &mut state.faces,
            &mut state.last_up_total,
            &mut state.last_down_total,
            &mut state.last_down_tcp_total,
            &mut state.last_down_utp_total,
            session_up,
            session_down,
            &mut state.speed_up,
            &mut state.speed_down,
        );
        note_supply_down(state, metrics, drained.down_tcp, drained.down_utp);
        // Final endgame in-flight slice checkpoint (the teardown must
        // not drop the endgame segment).
        checkpoint_endgame(metrics, state.faces.iter_mut());
        // Barrier wait: data fsync first, progress row persistence
        // second — the bitmap snapshot is read after Flushed (this
        // torrent's data files receive no further writes, so the
        // snapshot is stable and every completed piece's bytes are on
        // disk).
        if data_flush_barrier(data_flush_gates(&state.faces)).await {
            let row = progress_row(
                &state.faces,
                state.persist_shared.as_ref(),
                piece_len,
                startup_uploaded,
                startup_downloaded,
                startup_active_s,
                startup_seed_s,
                session_up.load(Ordering::Relaxed),
                session_down.load(Ordering::Relaxed),
                state.active_secs,
                state.seed_secs,
            );
            flush_progress_row(state.persist_shared.as_ref(), row).await;
        } else {
            warn!(target: "taiji::core::engine", gid = %gid,
                "final progress row refused: data flush barrier not reached \
                 (resume will recheck; no progress is claimed without data on disk)");
        }
    }
}

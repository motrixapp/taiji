//! Engine choke rounds (dual mode: libtorrent semantics by default, the
//! aria2 port as fallback via `BH_CHOKE_ARIA2=1`): the seeding face
//! (`choke_round` — libtorrent fastest_upload / aria2 ordering), the
//! download-phase leecher round (`leecher_choke_round`) and preemptive
//! unchoke (`preemptive_unchoke` — INTERESTED rising edge + free-slot
//! check).
//!
//! Scope: round decisions and their command effects, preemptive passes;
//! unchoke-state / down-window bookkeeping ownership stays in
//! faces/upload. Upstream anchor mapping: docs/design/engine.md.

use std::time::Instant;

use tracing::debug;

use taiji_bt::choke::{ChokeMode, PeerStat, UNCHOKE_SLOTS};
use taiji_bt::peer::PeerHandle as _;
use taiji_io::rate_limit::LimiterSet;

use crate::dispatch::{endgame_tail_active, peer_holds_missing_piece};
use crate::faces::{FaceState, XorShift};
/// Assembly point for budget-derived unchoke slots (opt-in switch
/// `BH_UNCHOKE_BUDGET_SLOTS`; off by default — zero behavior change).
/// When the switch is on and the engine limiter is present, N =
/// [`taiji_bt::choke::budget_unchoke_slots`] over the `per_torrent.up`
/// bucket rate (the session upload limit; `--max-upload-limit` reaches
/// the bucket via SpeedLimits -> LimiterSet), the per-peer floor
/// `BH_UNCHOKE_PER_PEER_FLOOR_BPS`, and the static fallback
/// `BH_UNCHOKE_SLOTS` (with upload unlimited, rate = 0, the pure
/// function falls back to static internally — a missing budget face is
/// never guessed). Otherwise None = the existing static-slot path,
/// unchanged.
///
/// How the limiter reaches the choke decision: the decision face
/// (taiji-bt `LeecherChoke`) cannot see the `LimiterSet` (the rate
/// topology lives engine-side on `DialCtx.limiter`, outside the bt
/// crate), so this engine-side assembly point computes N once per choke
/// round (15s) and passes it in via
/// [`taiji_bt::choke::LeecherChoke::select_with_slots`]'s `total_slots`
/// parameter. `enabled` is a parameter so tests can drive this function
/// directly; production reads
/// [`taiji_io::knobs::unchoke_budget_slots_enabled`].
pub(super) fn budget_derived_slots(enabled: bool, limiter: Option<&LimiterSet>) -> Option<usize> {
    if !enabled {
        return None;
    }
    Some(taiji_bt::choke::budget_unchoke_slots(
        limiter?.per_torrent.up.rate(),
        taiji_io::knobs::unchoke_per_peer_floor_bps(),
        taiji_io::knobs::unchoke_slots(),
    ))
}
/// Seeding choke round: libtorrent mode = fastest_upload (`choker.cpp`,
/// sort key `peer_rates.up` 10s sliding window; see
/// `bt::choke::SeederChoke::select_libtorrent` for the divergences).
/// aria2 fallback mode = the ported ordering (outstanding > recent >
/// rate, preserved as-is). Unchoke interested peers once complete.
pub(super) fn choke_round(face: &mut FaceState) {
    let mode = face.choke.mode();
    let now = Instant::now();
    let mut stats: Vec<PeerStat> = Vec::new();
    for (i, p) in face.peers.iter().enumerate() {
        if !p.is_interested() {
            continue;
        }
        // fastest_upload sort key (libtorrent mode): the peer's
        // `peer_rates.up` sliding-window rate. The aria2 fallback keeps a
        // constant 0.0 key, so the ported ordering (third key) is
        // unchanged — fallback semantics locked. Missing rows/fields
        // sample as 0.0 (same verdict as a missing legacy table).
        let cuid = face.peer_cuids.get(i).copied().unwrap_or(u64::MAX);
        let upload_speed = if mode == ChokeMode::Libtorrent {
            face.peer_state
                .get_mut(&cuid)
                .and_then(|ps| ps.rates.as_mut())
                .map(|r| r.up.calculate(now))
                .unwrap_or(0) as f64
        } else {
            0.0
        };
        stats.push(PeerStat {
            // Seeder path id = peers index (the decision maps back to
            // connections by index; last_unchoke shares the keyspace).
            id: i as u64,
            interested: true,
            snubbed: false,
            outstanding_upload: false,
            // last_unchoke keyspace is unified on cuid: the seeder path
            // resolves the row through peer_cuids (see PeerState docs).
            last_am_unchoking: face.peer_state.get(&cuid).and_then(|ps| ps.last_unchoke),
            download_speed: 0.0,
            upload_speed,
            regular_unchoker: false,
            opt_unchoked: false,
            last_optimistically_unchoked: None,
            // The tail face never fires on the seeder path (completed =
            // zero missing pieces; [`endgame_tail_active`] is false).
            endgame_holder: false,
        });
    }
    let decision = face.choke.select(&mut stats, Instant::now());
    for id in &decision.regular {
        let _ = face.peers[*id as usize].command(taiji_bt::peer::PeerCommand::SendUnchoke);
        // Unchoke time/state bookkeeping lands in the peer_state row
        // (index -> cuid); a missing row (test fixture without the
        // table) is skipped.
        if let Some(&cuid) = face.peer_cuids.get(*id as usize) {
            let row = face.peer_state_row(cuid);
            row.last_unchoke = Some(Instant::now());
            // am_unchoked bookkeeping feeds the preemptive free-slot
            // count (without it, edge-triggered passes could overshoot
            // slots). Bookkeeping only: losers are not re-choked (seeder
            // wire behavior unchanged); a stale true keeps the free-slot
            // check conservative (never overshoots).
            row.am_unchoked = true;
        }
    }
}

/// Leecher choke round (download-phase tit-for-tat): one decision per
/// round interval (`taiji_bt::choke::round_interval`, 15s/10s by mode)
/// via [`taiji_bt::choke::LeecherChoke::select`]. Dual mode:
///
/// - libtorrent (default): 8 total slots (optimistic 1 included) = 7
///   regular + 1 optimistic; optimism reselected every 30s (2-round
///   phase) by `last_optimistically_unchoked` ascending (waits longest
///   first, fed across rounds by the `peer_state` row's
///   `last_opt_unchoke`); regular keys follow the aria2 port
///   (divergences below).
/// - aria2 fallback (`BH_CHOKE_ARIA2=1`): 3 regular + planned optimistic
///   shuffle + fast handoff (`BtLeecherStateChoke` port, unchanged).
///
/// Input stats: interested/snubbed (lock-free PeerTaskHandle mirror),
/// regular_unchoker (last round's regular slots; keep-position key),
/// download_speed (30s design window; the peer's download rate to us,
/// descending — same key direction as aria2/libtorrent),
/// last_optimistically_unchoked (waits-longest optimistic key),
/// endgame_holder (the first regular-sort key while the
/// torrent is in its endgame tail — peers advertising at least one
/// still-missing piece; all false outside the tail, the sort unchanged).
///
/// Effects: unchoke = in the decision set and currently choked ->
/// SendUnchoke; choke = unchoke'd last round and not selected this
/// round -> SendChoke (per BEP3 the peer answers requests with reject;
/// `am_choking` is owned by the peer side).
///
/// Divergence from libtorrent (`choker.cpp`): libtorrent's regular keys
/// are bandwidth priority -> bytes received last round
/// (`downloaded_in_last_round`) -> state-keeping preference (quota
/// completion / wait time). This side keeps the aria2 port key (30s
/// window, download rate descending); the libtorrent upgrade covers
/// slots / optimistic choice / round interval / preemptive unchoke
/// only.
///
/// `budget_slots`: budget-derived total slots (computed at the
/// [`budget_derived_slots`] assembly point — the limiter -> decision
/// seam); None = the existing static `BH_UNCHOKE_SLOTS` path unchanged
/// (off by default, zero behavior difference).
pub(super) fn leecher_choke_round(
    face: &mut FaceState,
    rng: &mut XorShift,
    budget_slots: Option<usize>,
) {
    // Endgame-tail holder gate (the same [`endgame_tail_active`] supply face
    // as the dispatch round's tail policies; the missing inventory is
    // rebuilt here — the choke round runs on its own 15s/10s cadence and
    // shares no round state with dispatch). `BH_ENDGAME_UNCHOKE_HOLDER=0`
    // detaches the flag (all false = the sort keys bit-for-bit).
    let holder_priority = taiji_io::knobs::endgame_unchoke_holder_enabled()
        && endgame_tail_active(
            taiji_io::knobs::endgame_tail_pct(),
            (0..face.piece_count as u64)
                .filter(|&i| !face.progress.piece_done_global(i))
                .count() as u64,
            face.piece_count as u64,
        );
    // The missing-piece list for holder detection (<= 5% of the piece
    // count by the gate; O(N) build per round — the choke round's own
    // cadence is 10-15s).
    let missing: Vec<u64> = if holder_priority {
        (0..face.piece_count as u64)
            .filter(|&i| !face.progress.piece_done_global(i))
            .collect()
    } else {
        Vec::new()
    };
    let mut stats: Vec<PeerStat> = face
        .peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let cuid = face.peer_cuids.get(i).copied().unwrap_or(u64::MAX);
            // Three reads from one row lookup (last_unchoke, down window,
            // optimistic key); missing rows/fields fall back like a
            // missing legacy table.
            let row = face.peer_state.get(&cuid);
            PeerStat {
                // id = cuid (decisions map back to connections by cuid;
                // same keyspace as am_unchoked / regular_unchoked / the
                // down window — no re-mapping when a peer leaves).
                id: cuid,
                interested: p.is_interested(),
                snubbed: p.is_snubbed(),
                outstanding_upload: false,
                last_am_unchoking: row.and_then(|ps| ps.last_unchoke),
                download_speed: row
                    .and_then(|ps| ps.down_window.as_ref())
                    .map(|w| w.rate())
                    .unwrap_or(0.0),
                upload_speed: 0.0,
                regular_unchoker: face.regular_unchoked.contains(&cuid),
                opt_unchoked: false,
                last_optimistically_unchoked: row.and_then(|ps| ps.last_opt_unchoke),
                endgame_holder: holder_priority
                    && face
                        .peer_avail
                        .get(&cuid)
                        .is_some_and(|avail| peer_holds_missing_piece(avail, &missing)),
            }
        })
        .collect();
    // The Rng closure must be 'static (`choke::Rng =
    // dyn FnMut(usize) -> usize`): derive this round's seed from the
    // caller's state and capture an independent generator by value.
    // libtorrent-mode optimistic choice is deterministic (waits longest
    // first) and never calls it; only the fallback shuffle does.
    let round_seed = rng.next(usize::MAX) as u64;
    let mut shuffle = XorShift(round_seed);
    let decision = face.leecher_choke.select_with_slots(
        &mut stats,
        &mut move |n: usize| shuffle.next(n),
        budget_slots,
    );
    let unchoked: std::collections::HashSet<u64> = decision
        .regular
        .iter()
        .chain(decision.optimistic.iter())
        .copied()
        .collect();
    face.regular_unchoked = decision.regular.iter().copied().collect();
    let now = Instant::now();
    // Cross-round optimistic key (input to libtorrent-mode waits-longest
    // choice; the aria2 fallback never reads it — planned optimism
    // shuffles — so the write is harmless there).
    for id in &decision.optimistic {
        face.peer_state_row(*id).last_opt_unchoke = Some(now);
    }
    let mut unchoke_n = 0usize;
    let mut choke_n = 0usize;
    for i in 0..face.peers.len() {
        let Some(cuid) = face.peer_cuids.get(i).copied() else {
            continue;
        };
        let want = unchoked.contains(&cuid);
        let current = face.peer_state.get(&cuid).is_some_and(|ps| ps.am_unchoked);
        if want && !current {
            let _ = face.peers[i].command(taiji_bt::peer::PeerCommand::SendUnchoke);
            let row = face.peer_state_row(cuid);
            row.am_unchoked = true;
            row.last_unchoke = Some(now);
            unchoke_n += 1;
        } else if !want && current {
            let _ = face.peers[i].command(taiji_bt::peer::PeerCommand::SendChoke);
            face.peer_state_row(cuid).am_unchoked = false;
            choke_n += 1;
        }
    }
    if unchoke_n > 0 || choke_n > 0 {
        debug!(target: "taiji::core::engine",
            unchoked = unchoke_n, choked = choke_n,
            regular = decision.regular.len(), optimistic = decision.optimistic.len(),
            "leecher choke round applied");
    }
}

/// Preemptive unchoke (libtorrent `peer_connection.cpp` unchoke on
/// INTERESTED + `session_impl.cpp` free-slot check): on the INTERESTED
/// rising edge ([`taiji_bt::peer::AvailEvent::Interested`], delivered by
/// the taiji-bt inbound edge), if currently choked and a slot is free,
/// send SendUnchoke immediately — saving one round of latency.
///
/// - Free-slot check = current unchoke count < [`UNCHOKE_SLOTS`] (8;
///   optimistic counts against the total — leecher 7+1 and seeder 8
///   share the same cap; fixed slots is the only choke mode here,
///   `rate_based_choker` is not modeled, so the gate is always open).
/// - A pass does not enter `regular_unchoked` (the keep-position key
///   belongs to the round decision); the next round converges normally —
///   same shape as libtorrent's momentary overshoot reined in by the
///   regular round (`torrent.cpp` comment).
/// - aria2 fallback mode returns immediately (aria2 has no such
///   semantics; the fallback keeps the existing round cadence).
/// - Lossy events (avail channel full, dropped) degrade to waiting for
///   the next round (consistent with round semantics).
pub(super) fn preemptive_unchoke(face: &mut FaceState, cuid: u64) {
    let mode = if face.completed {
        face.choke.mode()
    } else {
        face.leecher_choke.mode()
    };
    if mode == ChokeMode::Aria2 {
        return;
    }
    if face.peer_state.get(&cuid).is_some_and(|ps| ps.am_unchoked) {
        return; // already unchoke'd: level-idempotent (an edge fires once).
    }
    let unchoked = face.peer_state.values().filter(|ps| ps.am_unchoked).count();
    if unchoked >= UNCHOKE_SLOTS {
        return; // no free slot: wait for the next round.
    }
    let Some(pos) = face.peer_cuids.iter().position(|&c| c == cuid) else {
        return; // peer already left (out-of-order event).
    };
    let _ = face.peers[pos].command(taiji_bt::peer::PeerCommand::SendUnchoke);
    // last_unchoke keyspace unified on cuid (the old seeder/leecher dual
    // keyspace is gone): the pass keys the peer's own row, read the same
    // way by both faces.
    let row = face.peer_state_row(cuid);
    row.am_unchoked = true;
    row.last_unchoke = Some(Instant::now());
    debug!(target: "taiji::core::engine", cuid, slots_before = unchoked,
        "preemptive unchoke (interested edge, free slot)");
}

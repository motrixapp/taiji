//! The dispatch face: advertisement-aware / spread-round piece selection
//! (via [`crate::strategy::PieceSelectionStrategy`] strategy objects;
//! default rarest-first), the `dispatch_face(_selected)` dispatch loop,
//! in-flight / reply / refetch bookkeeping, BEP 53 selection-mask
//! projection, and the v2-face lazy hash fetch (`V2DataPlane` /
//! `issue_fetch` / the layer state machine).
//!
//! Mechanism: on the rarest-first path it layers adaptive full endgame
//! ([`endgame_triggered`]): the claimed input is blanked and two-level
//! restraint applies — the cursor prefers unowned pieces, and busy-piece
//! picks pass the [`endgame_busy_admitted`] two-level gate (at most 1 busy
//! piece per peer + the strict gate); [`BlockState::InFlightDup`] is a
//! controlled duplicate capped at x2, demoted to the slow-peer fallback,
//! with [`endgame_peer_order`] as the bandwidth-aware / reciprocity
//! tie-break dispatch order. Two-phase in-flight bookkeeping (default on;
//! `BH_TWO_PHASE_LEDGER=0` reverts the whole face) splits in-flight state
//! into a network phase (`InFlight`/`InFlightDup`, peer RequestBook slots,
//! adaptive-window timeout -> snub/reissue) and a store phase (`Settling`,
//! awaiting pipeline confirmation; guard = [`STORE_PENDING_GUARD`], whose
//! action is warn + count only — takeover without cancel, zero new wire
//! traffic). Full design notes and upstream anchors:
//!
//! Upstream anchor mapping: docs/design/engine.md
//!
//! # Hard invariants
//!
//! - Non-endgame behavior is unchanged bit-for-bit (default semantics
//! preserved); endgame gates apply only to the rarest-first strategy.
//! - Only a network-phase timeout produces a wire resend. The port of
//! libtorrent's block tri-state requested/writing/finished
//! (`piece_picker.hpp`, `torrent.cpp` mark_as_writing /
//! mark_as_finished) judges reissue by the requested age only; the
//! writing (store) phase never triggers reissue — store-confirmation
//! lag never re-dispatches.
//! - Endgame copies are capped at x2 per piece; relaxed to the holder
//! count only inside last-mile, relax-only.
//! - An explicit `=0` on a knob restores the fallback behavior
//! bit-for-bit.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use taiji_bt::peer::{HashFetch, PeerHandle as _};
use taiji_bt::piece_id::Addressing;
use taiji_bt::piece_stat::{PieceStatMan, SelectFilter, Selection, select as select_piece};
use taiji_store::hashtree::HashTreeCache;
use taiji_store::layout::Layout;
use taiji_store::merkle;

use taiji_domain::hash_fetch::{
    self, HASH_FETCH_MAX_ATTEMPTS, HASH_FETCH_TIMEOUT, HashRequestPlan, PieceLayerStaging,
    RecoveredPieceLayer, StageOutcome,
};
use taiji_domain::metainfo::MetaFile;

use tokio::sync::mpsc;

use crate::bitmap::PieceBitmap;
use crate::config::FaceKind;
use crate::faces::{FaceState, face_transport_supply};
#[cfg(test)]
use crate::strategy::RarestFirstStrategy;
use crate::strategy::{PieceSelectionStrategy, SelectionCtx, StreamPlan, stream_ctx_for};
/// Lazy-fetch / recovery events (watcher task -> main loop; bounded
/// channel, 16 slots per face).
#[derive(Debug, Clone)]
pub(super) enum HashFetchEvent {
    /// Plan block admitted (`next` = the completed plan index; queue the
    /// next block if any).
    Admitted { next: usize },
    /// Failed (hash reject / timeout / connection closed / bad segment
    /// refused): the caller accumulates attempts.
    Failed { next: usize },
    /// Recovery block reply (bookkeeping in [`RecoveryBook`]): reject /
    /// timeout / disconnect / busy all converge into the `Err`
    /// classification — retries and peer switching are recovery
    /// bookkeeping decisions (all three branches share one convergence
    /// path).
    Recovery {
        block: usize,
        reply: Result<HashFetch, RecoveryFetchFail>,
    },
}

/// Recovery request failure classification (assigned by the watcher).
/// Local mechanism-layer failures and a legitimate peer reject share one
/// retry / peer-switch convergence path — a reject passes through
/// verbatim as `Ok(HashFetch::Rejected)` and does not use this
/// classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryFetchFail {
    /// The connection already has a pending hash request (the bt-side
    /// receipt; at most 1 in flight per connection).
    Busy,
    /// Connection closed (the peer task exited; no reply will come).
    Closed,
    /// Reply wait timed out
    /// ([`taiji_domain::hash_fetch::HASH_FETCH_TIMEOUT`]).
    Timeout,
}

/// Instrumentation: the count of requests whose dispatch target is in the
/// locally completed bitmap (a global atomic, sparing the FaceState test
/// fixtures). Should always be 0 — the selector filters candidates by the
/// done bitmap; nonzero = completion bookkeeping and the dispatch bitmap
/// have diverged, the direct check of the "re-select a completed piece"
/// hypothesis.
static DISPATCH_DONE_PIECE_REQUESTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Per-file lazy-fetch progress state.
#[derive(Debug)]
pub(super) enum LayerFetchState {
    /// Waiting to send (`next` = the index of the next plan block).
    Queued { next: usize },
    /// In flight (the watcher holds the timeout; completion / failure come
    /// back as events).
    Pending,
    /// The whole-file leaf layer is admitted.
    Done,
    /// Retries exhausted -> the whole-piece buffered fallback (warned on
    /// entry, never silent).
    Failed,
}

/// Per-file lazy-fetch context on the v2 face.
pub(super) struct FileLayerState {
    pub(super) root: [u8; 32],
    /// The file's wire/flat piece base.
    pub(super) piece_base: u64,
    /// Total leaves in the lazy-fetch admission domain = pieces x bpp.
    pub(super) leaf_total: u64,
    pub(super) plans: Vec<HashRequestPlan>,
    pub(super) state: LayerFetchState,
    pub(super) attempts: u32,
}
/// Dispatch-face reissue window: if a block is not confirmed by the store
/// pipeline (BlockSettled etc.) within this window after being sent, the
/// dispatcher re-sends at the original coordinates. Local policy value
/// (BEP 3/aria2 have no counterpart constant — aria2's reissue is driven
/// by the RequestBook slot timeout; the local wire-level in-flight dedup
/// is still the RequestBook's job, this window only keeps a stuck store
/// pipeline from starving the download). Semantics narrowed to the
/// reissue-window floor / no-owner fallback (fast peers and blocks without
/// bookkeeping keep the existing 2s behavior) — adaptive consumption in
/// [`reissue_window`].
pub(super) const DISPATCH_REISSUE_WINDOW: Duration = Duration::from_secs(2);

/// Reissue-window ceiling fallback default; configurable via
/// `BH_REISSUE_CEIL_SECS` (read point in [`reissue_ceil`]; this constant
/// anchors the unset/unparseable default and the existing decision-table /
/// wiring assertion baselines; `=5` restores bit-for-bit). Local policy
/// value — BEP 3/aria2/libtorrent have no "standalone reissue window"
/// constant (libtorrent's reissue is driven directly by the per-peer
/// `request_timeout()`, `peer_connection.cpp`; the local engine-level
/// in-flight bookkeeping is a structural difference). The value is the
/// spec clamp upper bound: a slow peer's reissue window extends to at
/// most 5s, so store-stall self-healing latency stays bounded.
pub(super) const REISSUE_WINDOW_CEIL: Duration = Duration::from_secs(5);

// Drift pin on the default anchor: taiji-io's parse surface (the fallback
// literal 5 in `reissue_ceil_secs_of_raw`) must equal this constant —
// cross-crate the in-function literal cannot be asserted, so this side is
// pinned: changing the anchor requires updating both sides (changing only
// this constant = a silent fake change, caught here at compile time).
const _: () = assert!(REISSUE_WINDOW_CEIL.as_secs() == 5);

/// Reissue-window ceiling read point: `BH_REISSUE_CEIL_SECS` (u64 seconds;
/// unset/unparseable falls back to the default 5 = [`REISSUE_WINDOW_CEIL`]
/// bit-for-bit; the effective value clamps to [2, 300] — the lower bound 2
/// = the reissue-window floor of 2s (a ceiling below the floor would make
/// the knob dead), the upper bound 300 defends against unbounded
/// store-stall self-healing latency). rqbit anchor: no block-level reissue
/// (in-flight is only reclaimed when the peer dies, librqbit `live/mod.rs`
/// `mark_chunk_requests_canceled`) — a deep queue is never disturbed
/// there; this knob makes the reissue ceiling configurable. Read lazily
/// once per process ([`multi_piece_budget_floor`] same shape — consumed
/// per block in the dispatch round, quasi-static configuration, never an
/// environment read on the hot path). Parse and read-timing registration
/// in `taiji_io::knobs` (process-level OnceLock).
fn reissue_ceil() -> Duration {
    Duration::from_secs(taiji_io::knobs::reissue_ceil_secs())
}

/// Per-peer reissue window (production entry point — the ceiling reads the
/// `BH_REISSUE_CEIL_SECS` knob via [`reissue_ceil`]; the pure decision
/// surface [`reissue_window_ceiled`] takes it injected):
/// `max(2s, min(adaptive, ceiling))` — adaptive = the block's current
/// dispatch target peer's `PeerTaskHandle::adaptive_request_timeout`
/// lock-free mirror reading (no samples = the configured 60s cap ->
/// window = ceiling; fast peers <= 2s -> window 2s, the existing behavior;
/// slow peers -> the window extends with the adaptive value, capped at the
/// ceiling). Upstream anchor: libtorrent's reissue/timeout surface is
/// `request_timeout()` (`peer_connection.cpp`; 0 samples returns the
/// settings default — waiting is not scaled up without evidence; the local
/// 5s cap leans the same way). Two-phase scoping: this window judges the
/// **network phase** (`InFlight` family) fresh/expired; the store phase
/// (`Settling`) is not timed by this window — its guard is
/// [`STORE_PENDING_GUARD`] (zero new wire traffic). The windows used by
/// endgame in-flight metering and the claimed spread switch with the
/// [`two_phase_ledger`] knob (off = the fixed 2s existing reading).
pub(super) fn reissue_window(adaptive_timeout: Duration) -> Duration {
    reissue_window_ceiled(adaptive_timeout, reissue_ceil())
}

/// Pure decision surface of [`reissue_window`] (ceiling injected;
/// decision-table tests): `max(2s, min(adaptive, ceil))` — the default
/// ceil = 5s (the [`REISSUE_WINDOW_CEIL`] fallback arm, bit-for-bit the old
/// behavior); the 2s floor ([`DISPATCH_REISSUE_WINDOW`]) and the adaptive
/// semantics are unchanged.
pub(super) fn reissue_window_ceiled(adaptive_timeout: Duration, ceil: Duration) -> Duration {
    ceil.min(adaptive_timeout).max(DISPATCH_REISSUE_WINDOW)
}

/// Dispatch-round supply cap (the spec formula; pure function, decision
/// table tests drive it directly): `min(target window - in flight,
/// command-channel room)`.
///
/// - Target window = the peer's `PeerTaskHandle::target_request_window`
/// lock-free mirror reading (BDP:
/// `clamp(3s x payload-rate EWMA / 16KiB, 2, configurable cap)`, the
/// libtorrent `peer_connection.cpp` port; fallback mode = the doubling
/// heuristic reading);
/// - In flight = `PeerTaskHandle::in_flight` lock-free mirror reading (the
/// RequestBook outstanding count);
/// - Room = `PeerTaskHandle::command_capacity` (remaining permits on the
/// tokio bounded command channel; capacity 64, provenance in the bt
/// side's `COMMAND_CHANNEL_CAPACITY`).
///
/// Saturation semantics: in-flight >= target -> cap 0 (never overshoot);
/// room 0 -> 0 (the channel-full leave-in-queue behavior, moved early to
/// the read side — the try_send Full fallback remains). The cap only
/// **tightens** supply, never amplifies (the one-piece-per-peer-per-round
/// dispatch rhythm is unchanged). Endgame interaction: endgame rounds are
/// bound by the same cap (copy-cap gates: strict domain x2
/// [`ENDGAME_MAX_COPIES`] / last-mile domain holder count — wide fan-out is
/// clamped block-by-block by this cap; a fast peer's window depth is its
/// fan-out depth).
pub(super) fn supply_cap(target_window: u64, in_flight: u64, channel_room: usize) -> usize {
    let depth = usize::try_from(target_window.saturating_sub(in_flight)).unwrap_or(usize::MAX);
    depth.min(channel_room)
}
/// Reissue-window reading for a (piece, begin) coordinate (the single
/// source of the adaptive-mirror consumption; shared by network-phase
/// fresh/expired judgments): via the in-row owner
/// ([`PieceSentLedger::owner_of`]; the owner IS the peer_cuids index —
/// dissolves the old `block_dispatch` cuid->position linear scan) ->
/// peer handle -> [`reissue_window`]; no owner (missing bookkeeping /
/// peer gone — the owner sentinel) falls back to the existing
/// [`DISPATCH_REISSUE_WINDOW`]. Candidate filtering (the closure inside
/// the dispatch round) and the metering surfaces (claimed build / x2
/// counting / the busy in-flight count) take the value from the same
/// source — one partition decision; two different windows at the two
/// sites would corrupt the duplicate marking.
pub(super) fn block_reissue_window(face: &FaceState, piece: u64, begin: u32) -> Duration {
    face.blocks_sent
        .get(&piece)
        .and_then(|ledger| ledger.owner_of(begin))
        .and_then(|owner| face.peers.get(owner as usize))
        .map(|h| reissue_window(h.adaptive_request_timeout()))
        .unwrap_or(DISPATCH_REISSUE_WINDOW)
}

/// Store-phase guard: a `Settling` entry older than this -> warn + count.
/// **Local policy value** — libtorrent has no standalone "store guard"
/// constant (its writing phase is untimed; the `piece_picker` writing
/// state has no timeout surface); 30s is the empirical upper-bound
/// magnitude of a slow disk's worst-case flush cycle (a deliberate
/// structural divergence: the local side has a separate store-phase state
/// the reference lacks, not a value divergence). The action is **warn +
/// count only** (zero new wire traffic, never a resend — reissue
/// decisions consult only the network phase; takeover without cancel, the
/// claim/checkout was already released at arrival). Planned retirement:
/// once write-cache watermark backflow drives flushing, this constant
/// retires into a watermark function (a behavior-neutral replacement —
/// the guard action has no wire face).
pub(super) const STORE_PENDING_GUARD: Duration = Duration::from_secs(30);

/// Dispatch-debt settlement: event arms (BlockSettled / PieceVerified /
/// availability advertisements) no longer dispatch fully per event; they
/// only record the face number (dispatch debt,
/// [`super::run::state::EngineLoop::note_dispatch_debt`]). Any one
/// condition settles all debt —
/// 1. **Supply quiet**: every debted face has no unsettled in-flight
/// requests (no InFlight/InFlightDuplicate entries in `blocks_sent`) —
/// no coalescing gain, settle immediately;
/// 2. **Settle batch**: the face accrued >= [`DISPATCH_DEBT_SETTLE_BATCH`]
/// block/piece settle events since the last settlement — batch-coalesce
/// within a supply stream;
/// 3. **Debt-age backstop**: [`DISPATCH_DEBT_MAX_AGE`] — a latency upper
/// bound for pure-advertisement periods (HAVE storms) and all
/// long-quiet faces (including main-loop park gaps — the debt ticker
/// arm shares the period).
///
/// Rationale: a dispatch round is an O(peers x pieces) full-order rarity
/// scan (`select_piece` two-phase x P peers), so rounds must not be driven
/// per block or per HAVE. Condition 2 compresses settle-driven rounds;
/// condition 3 caps HAVE-storm rounds. In-round decision order is
/// unchanged — decision-table tests drive `dispatch_face_selected_with_stream`
/// directly, not through the debt surface.
pub(super) const DISPATCH_DEBT_MAX_AGE: Duration = Duration::from_millis(5);

/// Clamp bounds for the dispatch-debt settle batch threshold (condition
/// 2): the actual threshold adapts per face peer count,
/// `K = clamp(peers / 2, 1, 16)` — a round costs proportionally to the
/// peer count (full-order rarity scan), so more peers want more coalescing.
/// Few peers keep re-dispatch urgency close to the baseline (baseline =
/// the first settle refills the next wave); many peers compress round
/// counts. At low block-flow rates the batch condition rarely fires; the
/// debt-age backstop ([`DISPATCH_DEBT_MAX_AGE`]) carries the latency
/// bound.
pub(super) const DISPATCH_DEBT_SETTLE_BATCH_MIN: u32 = 1;
pub(super) const DISPATCH_DEBT_SETTLE_BATCH_MAX: u32 = 16;

/// Endgame ETA threshold (seconds; trigger condition B): remaining
/// unfinished bytes / the face's aggregate download rate below this
/// triggers full endgame. Local policy value (a designed condition;
/// libtorrent/aria2 have no counterpart constant — libtorrent only has the
/// condition-A shape, see [`endgame_triggered`]). 30s matches the 30s rate
/// statistics window (`upload::RateWindow::WINDOW_SECS`, the download
/// window, a choke sort-key input) — the ETA estimate is only
/// statistically meaningful once the rate evidence fills the window;
/// smaller -> an earlier tail but more duplicate overhead; larger ->
/// endgame benefits arrive too late (the tail speedup is lost).
/// qBittorrent's "tail speedup" behavior is the behavioral reference (its
/// endgame trigger is also the libtorrent condition-A shape: no ETA gate,
/// no public constant to cite).
pub(super) const ENDGAME_ETA_THRESHOLD_SECS: u64 = 30;

/// Endgame per-piece in-flight copy cap ("controlled duplicate x2"): a
/// missing piece has at most the first copy plus one duplicate hop in
/// flight at once. libtorrent has no explicit per-piece cap — its
/// busy-block duplication is gated by `dont_pick_busy_blocks` in
/// `request_blocks.cpp` (including the `strict_end_game_mode` setting);
/// this explicit x2 constant is the stronger bounded guarantee, implemented
/// per block in [`BlockState::InFlightDup`].
///
/// Division of labor with the picker-side gate: the **busy gate governs
/// generation** ([`endgame_busy_admitted`] — who may create a duplicate
/// copy under what conditions, the `request_blocks.cpp` anchor), the **x2
/// gate governs timeouts** (the concurrency ceiling on duplicate copies
/// plus the takeover-and-reissue fallback for expired blocks, the hedge
/// against slow-peer late blocks). The gates are in series: without the
/// busy gate the x2 gate is unreachable; past the busy gate the x2 gate
/// still caps.
///
/// Inside last-mile the cap relaxes to the holder count
/// ([`endgame_lastmile_copies_limit`]); outside last-mile (missing > N)
/// strict semantics are unchanged bit-for-bit — the constant keeps its
/// dual identity as the x2 default and the strict-domain cap.
pub(super) const ENDGAME_MAX_COPIES: u64 = 2;

/// Fast-tier median multiple (d): a peer whose 30s download rate is >= 2x
/// the median rate across connected peers is "significantly faster than
/// the swarm body". Local policy value (no reference constant —
/// libtorrent's busy gate has no rate-tiering face, `request_blocks.cpp`
/// judges all peers alike; rqbit's first-wins broadcast has no gate). 2 =
/// the conservative "double the median" boundary (1x always passes half
/// the peers; 3x leaves the fast window too sparse).
pub(super) const ENDGAME_FAST_TIER_MEDIAN_MULT: f64 = 2.0;

/// Fast-tier rate floor (d): 100KiB/s. Guards against a phantom fast tier
/// on a dead swarm — with the median near 0, "2x median" is trivially
/// true, so an absolute floor is needed. Magnitude: half of the observed
/// fast-peer lower band (the gate errs conservative: a false fast tier
/// risks the slow-peer serial-wait recurrence; a missed fast peer only
/// delays the benefit).
pub(super) const ENDGAME_FAST_TIER_FLOOR_BPS: f64 = 100.0 * 1024.0;

/// Endgame last-mile piece threshold (tail-serial-wait relief). With
/// missing pieces <= N the face enters last-mile: the strict busy gate
/// lifts (each block may go to every holder reachable through the unchoke
/// path, no more 1-busy-piece-per-peer cap), the x2 copy gate relaxes to
/// the holder count, and fast holders get dispatch priority
/// ([`endgame_lastmile_peer_order`]). Rationale: the strict endgame busy
/// gate with a slow holder parked on the last piece serializes the tail;
/// this gate relieves that.
///
/// Numeric-parameter style (like the bt-side
/// `BH_REQ_WINDOW_FLOOR`/`bdp_window_floor` in request_book.rs — a fresh
/// env read each round, parse failure falls back to the default; separate
/// from [`endgame_strict_mode`]'s OnceLock boolean): `BH_ENDGAME_LASTMILE`
/// (default 4) — **=0 is the fallback switch** (N=0 -> the gate never
/// fires, strict semantics bit-for-bit; the [`endgame_lastmile_active`]
/// always-false arm).
///
/// # Upstream anchors (divergence note)
///
/// rqbit: no strict endgame — the request face is first-arrival-wins
/// broadcast (the same block may be requested from several peers at once,
/// first delivery wins, later ones discarded); the tail has no serial wait
/// and no copy accounting. libtorrent: the `strict_end_game_mode` surface
/// (busy-block duplication gating, `request_blocks.cpp`). The local side
/// takes a domain-split compromise: outside last-mile keep libtorrent
/// strict bit-for-bit (the decision-table pinned face); inside last-mile
/// switch to rqbit-style broadcast (first-wins) with the gate width =
/// N pieces.
///
/// # Duplicate-waste guard (upper bound)
///
/// The last-mile duplicate byte bound = N x piece length x peer count
/// (default 4 x 256KiB x ~60, tens of MB); first-wins lands far below
/// (first delivery wins; duplicates hit the existing dup/bookkeeping face
/// plus the store-side covers benign drop, observed by the `endgame_dup`
/// counter). The exactly-once `was_dup` semantics are unaffected: the
/// block state machine has one entry per coordinate, the first arrival
/// exclusively owns the `InFlight -> Settling` transition (later arrivals
/// are no-ops, total function), and the sibling cancel still fires exactly
/// once (`run::arms::on_block_settled`).
fn endgame_lastmile_pieces() -> u64 {
    // N is read fresh each round (numeric-parameter style, not OnceLock;
    // read-timing registration in `taiji_io::knobs` — the
    // "per-round/event-level" class, no caching change).
    taiji_io::knobs::endgame_lastmile_pieces()
}

/// Endgame busy-gate rate-tiering knob (d; `BH_ENDGAME_FAST_BUSY_K`,
/// default 2; `=0` explicitly restores the strict busy gate
/// `my_inflight == 0` bit-for-bit). With K >= 1, fast-tier peers
/// ([`endgame_fast_tier`]) may hold at most K busy pieces at once;
/// slow-tier peers keep strict. The x2 copy cap and the last-mile boundary
/// are untouched (red lines in [`endgame_busy_admitted_tiered`]). Read
/// lazily once per process ([`multi_piece_checkout_cap`] same shape —
/// consumed per peer in the dispatch round, quasi-static configuration).
/// Parse and read-timing registration in `taiji_io::knobs` (process-level
/// OnceLock).
pub(super) fn endgame_fast_busy_k() -> u64 {
    taiji_io::knobs::endgame_fast_busy_k()
}

/// Last-mile predicate (pure function; decision-table tests drive it
/// directly): active when missing pieces ∈ [1, N]. N=0 is always false
/// (the fallback switch — strict semantics bit-for-bit); missing 0 =
/// download complete, no dispatch face, always false.
pub(super) fn endgame_lastmile_active(n: u64, missing_pieces: u64) -> bool {
    n > 0 && missing_pieces > 0 && missing_pieces <= n
}

/// Last-mile wide-fan-out copy cap (pure function; decision-table tests):
/// `max(holders, [`ENDGAME_MAX_COPIES`])` — a **relax-only** widening of
/// the x2 gate (single-piece forms with fewer than 2 holders do not
/// tighten: an expired block on a 1-holder piece still reissues under the
/// x2 default; the widening is one-way, "from 2 up to the holder count").
/// Holders = connected peers advertising the piece AND not choking us
/// (peers on the interested-unchoke dispatch path — peers choking us are
/// skipped in the dispatch round, so counting and dispatch eligibility
/// share one face; parole-suspect peers count in and are not excluded: the
/// cap only widens generation-side permission, the suspects themselves are
/// still skipped by the dispatch round, the `endgame_busy_admitted` parole
/// face unchanged).
pub(super) fn endgame_lastmile_copies_limit(holders: u64) -> u64 {
    holders.max(ENDGAME_MAX_COPIES)
}

/// Piece holder count (pure function; decision-table tests): counts peers
/// with "advertises the piece AND not choking us" — the same
/// dispatch-eligibility face (unchoke path) as
/// [`endgame_lastmile_peer_order`], feeding
/// [`endgame_lastmile_copies_limit`]. Production consumption = the
/// [`endgame_piece_holders_face`] bitmap-read form; this pure function
/// remains for the decision-table and equivalence-lock tests.
#[cfg(test)]
pub(super) fn endgame_piece_holders(advertisers: &[bool], choking: &[bool]) -> u64 {
    advertisers
        .iter()
        .zip(choking.iter())
        .filter(|&(adv, choke)| *adv && !choke)
        .count() as u64
}

/// Dispatch-round direct-read form of [`endgame_piece_holders`]
/// (bitmapized): per peer a bit-read count of "advertises the piece AND
/// not choking us" — identical verdicts to the pure function (equivalence
/// lock in tests); removes the per-piece `Vec<bool>` materialization of
/// last-mile table construction (missing x P allocations plus bit writes
/// -> zero-allocation bit reads).
pub(super) fn endgame_piece_holders_face(face: &FaceState, piece: u64, choking: &[bool]) -> u64 {
    face.peer_cuids
        .iter()
        .enumerate()
        .filter(|&(i, cuid)| {
            face.peer_avail
                .get(cuid)
                .is_some_and(|row| row.get(piece as usize))
                && !choking.get(i).copied().unwrap_or(false)
        })
        .count() as u64
}

/// Last-mile dispatch peer order (pure function; decision-table tests):
/// **primary key = 30s-window download rate descending** (fast holders
/// first — relief for "slow holder parked, fast peer joined late": the
/// fastest peer gets the last-piece request slot first); **final key =
/// cuid ascending** (a deterministic tie-break on rate ties, reproducible
/// in tests). Rate readings share the source with the leecher choke sort
/// key (the `peer_state` row `down_window`; `download_speed` is the same
/// face as the choke.rs / `endgame_peer_order` precedents).
///
/// Divergence from [`endgame_peer_order`] (intentional): the latter carries
/// an interested reciprocity tie-break (tit-for-tat still participates in
/// ordering); the last-mile order does not consume interested — within a
/// seconds-scale tail window reciprocity gains are meaningless, and a pure
/// rate order relieves the serial wait (the rqbit-style "broadcast to the
/// fastest peers" anchor).
pub(super) fn endgame_lastmile_peer_order(rates: &[f64], cuids: &[u64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..rates.len()).collect();
    order.sort_by(|&a, &b| {
        rates[b].total_cmp(&rates[a]).then_with(|| {
            cuids
                .get(a)
                .copied()
                .unwrap_or(u64::MAX)
                .cmp(&cuids.get(b).copied().unwrap_or(u64::MAX))
        })
    });
    order
}

/// Partial hard-gate total-block cap (goal 5): once partial pieces hold
/// more than 2048 blocks total (≈32MiB @16KiB/block), `prioritize_partials`
/// is forced. libtorrent `piece_picker.cpp`: `num_partials *
/// blocks_per_piece() > 2048` (source comment: "2048 corresponds to
/// 32 MiB"). The local side sums each partial piece's own uncovered block
/// count instead of the reference's "partial count x blocks_per_piece()"
/// constant multiply — more precise for short tail pieces, same intent
/// (divergence note).
pub(super) const PARTIAL_BLOCK_GATE: u64 = 2048;

/// Partial hard-gate predicate (pure function, decision-table tests; goal
/// 5): partial piece count > connected peers x 3/2 OR partial block total >
/// [`PARTIAL_BLOCK_GATE`]. libtorrent `piece_picker.cpp` (both
/// inequalities strictly >).
pub(super) fn partial_gate_triggered(
    num_partials: u64,
    num_peers: u64,
    partial_blocks: u64,
) -> bool {
    num_partials > num_peers * 3 / 2 || partial_blocks > PARTIAL_BLOCK_GATE
}

/// Adaptive full-endgame trigger (pure function, table-driven tests).
/// Recomputed statelessly every dispatch round (libtorrent's shape: each
/// pick round re-judges via `set_endgame` — set false in
/// `request_blocks.cpp`, true at the endgame branch).
///
/// # Condition A (libtorrent semantics: every remaining unfinished piece
/// is "downloaded or in flight")
///
/// `in_flight_pieces >= missing_pieces`. Anchors (libtorrent):
/// `request_blocks.cpp` — "if the number of pieces we have + the number
/// of pieces we're requesting from is less than the number of pieces in
/// the torrent, there are still some unrequested pieces and we're not
/// strictly speaking in end-game mode yet"; its non-endgame test is
/// `get_download_queue_size() < num_want_left()`, and this condition is
/// its complement. `num_want_left()` = "the number of pieces we want and
/// don't have" (`piece_picker.hpp`); `get_download_queue_size()` counts
/// pieces in the download queue (piece granularity, `piece_picker.cpp`,
/// summing `m_downloads` across states). The local in-flight piece set =
/// pieces holding InFlight blocks not past their reissue window (the same
/// granularity as the download queue).
///
/// # Condition B (ETA: remaining bytes / current aggregate rate <
/// [`ENDGAME_ETA_THRESHOLD_SECS`])
///
/// A zero rate (no statistical evidence) does not trigger — avoids a
/// cold-start false positive; condition A takes precedence (OR set).
pub(super) fn endgame_triggered(
    missing_pieces: u64,
    in_flight_pieces: u64,
    missing_bytes: u64,
    download_rate_bps: f64,
) -> bool {
    if missing_pieces == 0 {
        // All complete = not endgame (download finished, nothing to dispatch).
        return false;
    }
    if in_flight_pieces >= missing_pieces {
        return true;
    }
    download_rate_bps > 0.0
        && missing_bytes as f64 / download_rate_bps < ENDGAME_ETA_THRESHOLD_SECS as f64
}

/// Endgame dispatch peer order (bandwidth-aware dispatch +
/// reciprocity-aware tie-break; pure function).
///
/// - Primary key = 30s-window download rate descending. libtorrent anchor
/// for rate-ordered picking: `torrent.cpp` sorts peers by
/// `download_queue_time(16*1024)` ascending ("The earlier a peer is in
/// the list, the sooner we will fully download the block"), re-sorted
/// after each request; that queue time derives from the peer's current
/// download payload rate (`peer_connection.cpp`, falls back to the peak
/// rate after 30s without data, floored at 50 B/s). The local side sorts
/// the same way on the 30s-window rate (`down_windows`, the same
/// statistics face as the choke sort key).
/// - Tie-break = interested first (reciprocity: among equal-rate
/// candidates prefer peers that want our pieces — tit-for-tat credit,
/// the BiToS idea). The tie-break layer does not disturb the
/// rarest-first primary: selection is still the strategy's decision;
/// this order only decides who gets the dispatch slot first when several
/// candidates share a piece.
/// - Final key = connection index ascending (stable within a rank,
/// deterministic for tests).
pub(super) fn endgame_peer_order(rates: &[f64], interested: &[bool]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..rates.len()).collect();
    order.sort_by(|&a, &b| {
        let (ia, ib) = (
            interested.get(a).copied().unwrap_or(false),
            interested.get(b).copied().unwrap_or(false),
        );
        rates[b]
            .total_cmp(&rates[a])
            .then_with(|| ib.cmp(&ia))
            .then_with(|| a.cmp(&b))
    });
    order
}

/// Peer rate median (the d fast-tier criterion input; pure function,
/// decision-table tests): copy+sort, take the middle element
/// (`sorted[len/2]`, upper median for even lengths, the same reading as
/// the tick.rs rate-distribution telemetry). Empty slice = 0.0 (no peers,
/// no evidence). Computed once per dispatch round, O(n) (consumed at the
/// top of the endgame branch, not recomputed per peer).
pub(super) fn rates_median(rates: &[f64]) -> f64 {
    let mut sorted = rates.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted.get(sorted.len() / 2).copied().unwrap_or(0.0)
}

/// Fast-tier predicate (d; pure function, decision-table tests): the
/// peer's 30s download rate >= [`ENDGAME_FAST_TIER_MEDIAN_MULT`] x the
/// connected-peer rate median ([`rates_median`]) AND >= the
/// [`ENDGAME_FAST_TIER_FLOOR_BPS`] floor — an adaptive, non-absolute
/// threshold (the fast/slow boundary floats with the swarm's rate
/// distribution), with the floor guarding against the phantom fast tier of
/// a dead swarm (median ≈ 0 makes "2x median" trivially true). Rate
/// readings share the choke sort-key source (`peer_state` row
/// `down_window`, the same face as [`endgame_peer_order`]).
pub(super) fn endgame_fast_tier(rate_bps: f64, median_bps: f64) -> bool {
    rate_bps >= ENDGAME_FAST_TIER_MEDIAN_MULT * median_bps
        && rate_bps >= ENDGAME_FAST_TIER_FLOOR_BPS
}

/// Endgame-tail predicate (pure function, decision-table tests):
/// active when the missing-piece count is in `(0, pct% of the torrent]`
/// (`missing x 100 <= total x pct`, saturating). `pct = 0` = the whole
/// endgame-tail supply face off (the fallback switch — non-tail behavior
/// bit-for-bit); missing 0 = complete, never active. This gate is the
/// **piece-supply face alone** — deliberately NOT [`endgame_triggered`]:
/// the adaptive endgame trigger's condition B (ETA = missing / rate)
/// collapses exactly in the hard tail stall it should cover (rate -> 0
/// makes ETA infinite), so the tail policies key on the supply inventory,
/// not on the rate evidence.
pub(super) fn endgame_tail_active(pct: u64, missing: u64, total: u64) -> bool {
    pct > 0 && missing > 0 && missing.saturating_mul(100) <= total.saturating_mul(pct)
}

/// Holder predicate (pure function, decision-table tests): does
/// the peer's advertisement bitmap cover at least one of the still-missing
/// pieces? Empty missing list = false (nothing to hold). Consumption: the
/// window-floor write pass and the choke-round holder flags (the
/// endgame piece-availability face — `peer_avail` — is the single source).
pub(super) fn peer_holds_missing_piece(avail: &PieceBitmap, missing: &[u64]) -> bool {
    missing.iter().any(|&p| avail.get(p as usize))
}

/// Tail window-floor value (pure function, decision-table
/// tests): `min(k x missing_blocks, UB 256)` — a holder peer's
/// outstanding-request window should at least cover the remaining tail's
/// block volume k times over (k = `BH_ENDGAME_TAIL_WINDOW`, default 1).
/// k = 0 = off (the caller writes 0 = detach); the product is clamped to
/// the aria2 UB cap (`taiji_bt::request_book`'s
/// `UB_MAX_OUTSTANDING_REQUEST` literal — duplicated rather than imported
/// across the crate boundary only where that constant is private; the
/// RequestBook side re-clamps under its configured cap regardless).
pub(super) fn endgame_tail_window_floor(k: u64, missing_blocks: u64) -> u64 {
    if k == 0 {
        return 0;
    }
    k.saturating_mul(missing_blocks).min(256)
}

/// Per-piece deadline bookkeeping (pure function, decision-table
/// tests): a busy missing piece's deadline expires when
/// `now >= first_observed + deadline` — the anti-mask face for the
/// piece-level shared timestamp approximation
/// ([`PieceSentLedger::dispatched_at`] is refreshed by every dispatch
/// write, so a re-dispatch trickle keeps stale blocks looking fresh
/// forever; the per-piece deadline is monotone and only re-armed on
/// actual supply movement). `deadline` zero = never overdue (the fallback
/// switch).
pub(super) fn endgame_piece_overdue(
    deadline: Duration,
    first_observed: Instant,
    now: Instant,
) -> bool {
    !deadline.is_zero() && now.duration_since(first_observed) >= deadline
}

/// A piece's in-flight copy count (x2-gate metering; pure function): a
/// fresh InFlight block -> 1; any fresh InFlightDup block -> 2 (the
/// duplicate state is the one-shot "already duplicated" mark — once a
/// request lands in [`BlockState::InFlightDup`] no third hop is
/// permitted). Expired blocks (>= `window`) do not count (presumed
/// stalled dead; eligible for takeover reissue). Merged with max: any live
/// duplicate counts the piece as 2.
///
/// Two-phase scoping: `window` is parameterized (the network-phase
/// freshness input — callers pass the piece's adaptive window upper bound;
/// knob off falls back to the fixed 2s reading). `Settling*` rows **count
/// 0** — the arrived block's bytes are already local, no duplicate
/// coverage needed (the store phase does not join the x2 gate; aligned
/// with libtorrent's writing phase not joining reissue/duplicate
/// decisions). Freshness reads the piece-level shared timestamp
/// (approximation note in [`PieceSentLedger`]).
pub(super) fn endgame_inflight_copies(
    sent: Option<&PieceSentLedger>,
    now: Instant,
    window: Duration,
) -> u64 {
    let Some(ledger) = sent else {
        return 0;
    };
    let fresh = now.duration_since(ledger.dispatched_at()) < window;
    let mut copies = 0u64;
    for slot in ledger.slots() {
        match slot.state {
            BlockState::InFlight if fresh => copies = copies.max(1),
            BlockState::InFlightDup if fresh => copies = copies.max(2),
            _ => {}
        }
    }
    copies
}

/// Two-level eligibility gate for busy-piece picks (pure function;
/// decision-table tests). The endgame cursor's second-level pick (a
/// missing piece "advertised AND held fresh in flight by **another**
/// peer" — a busy piece, manufacturing a controlled duplicate) is admitted
/// only when all of the following hold:
///
/// 1. **Strict gate inactive**: in-flight pieces >= missing pieces.
/// libtorrent `strict_end_game_mode` — `dont_pick_busy_blocks` is set
/// when `p.get_download_queue_size() < p.num_want_left()`
/// (`request_blocks.cpp`; download-queue granularity = pieces,
/// `piece_picker.cpp`; `num_want_left()` = the still-needed piece
/// count, `piece_picker.hpp`). Both local inputs share the source of
/// [`endgame_triggered`] condition A (in-flight pieces = fresh claimed
/// bits, missing pieces = the !done count) — rounds triggered by
/// condition A always pass this gate; rounds triggered only by ETA
/// (condition B) while unowned pieces remain are stopped here: no
/// duplicates while unowned work exists.
/// 2. **Peer empty-handed**: the peer's fresh in-flight block count = 0.
/// Reference: `dq.size() + rq.size() > 0` skips busy picks
/// (`request_blocks.cpp`, re-checked before busy selection) — a peer
/// with outstanding requests stops manufacturing duplicates, giving the
/// steady-state invariant **at most 1 busy allocation per peer at a
/// time** (picking 1 busy piece makes in-flight nonzero; later rounds
/// are stopped by 2 until its in-flight settles or expires). busy count
/// <= in-flight count (a busy allocation IS an in-flight block), so
/// "empty-handed" ⟺ "busy count < 1" — two formulations of one
/// decision.
///
/// # Deliberate divergence notes
///
/// - **Granularity**: libtorrent's busy granularity is the **block**, at
/// most 1 busy block per round (`piece_picker.cpp` picks a random piece
/// from the piece_full bucket and takes one busy block not requested by
/// this peer; `request_blocks.cpp` issues a single `add_request(busy)`;
/// and only interesting+backup peers that cannot fill their request
/// count enter — failing to fill sets `set_endgame(true)`). Local
/// dispatch allocates by **piece** (one piece per peer per round), so
/// the busy cap becomes at most 1 busy piece per peer at a time; the
/// counterpart of "only when requests cannot be filled" is the
/// first-level unowned pick coming up empty (the cursor's first-level
/// `find` finds nothing) before this gate is consulted — wire shape
/// equivalent (the duplicate-request volume is bounded at the same
/// level); the granularity structure differs.
/// - **Fresh window**: the in-flight count input is
/// [`endgame_peer_inflight`] (construction switches with
/// [`two_phase_ledger`]: on = network phase + adaptive window, the same
/// value source as claimed / [`endgame_inflight_copies`] via
/// [`block_reissue_window`]; off = the fixed [`DISPATCH_REISSUE_WINDOW`]
/// single-state reading).
/// - **Ownership overwrite corner**: the in-row owner is single-owner
/// bookkeeping per coordinate — when a busy hop lands in
/// [`BlockState::InFlightDup`] the coordinate's ownership is overwritten
/// by the second hop, and in the accounting face the original holder
/// becomes "empty-handed", free to issue its first busy allocation on
/// **another** missing piece (on the wire that peer transiently holds
/// two busy requests). The per-piece x2 cap does not go through
/// ownership (`round_copies` counts states, not owners), so the
/// amplification bound holds.
pub(super) fn endgame_busy_admitted(
    in_flight_pieces: u64,
    missing_pieces: u64,
    peer_inflight_blocks: u64,
) -> bool {
    peer_inflight_blocks == 0 && in_flight_pieces >= missing_pieces
}

/// Rate-tiered busy-pick gate (d; pure function, decision-table tests):
/// with `BH_ENDGAME_FAST_BUSY_K` (K) >= 1, **fast-tier peers**
/// ([`endgame_fast_tier`]) may hold at most K busy pieces at once
/// (`my_inflight_pieces < K` — the Kth pick fills the tier; later rounds
/// block until its busy pieces settle or expire); **slow-tier peers** keep
/// strict `== 0` (the old two-level gate 2, bit-for-bit). Strict gate 1
/// (in-flight pieces >= missing pieces) judges both tiers identically,
/// unchanged. The K=0 arm = [`endgame_busy_admitted`] bit-for-bit (the
/// zero checks are granularity-equivalent: busy pieces = 0 ⟺ fresh
/// in-flight blocks = 0 — passing the block count into the old gate
/// decides identically).
///
/// # Red lines
///
/// - The per-piece copy cap x2 ([`ENDGAME_MAX_COPIES`]) is **untouched** —
/// K only widens the per-peer concurrent busy-piece count; the per-piece
/// concurrency ceiling still caps at x2 (the anti-pileup gate as before).
/// - The last-mile boundary (`BH_ENDGAME_LASTMILE`) is **untouched** —
/// missing <= N still opens fully (the
/// [`endgame_busy_admitted_dispatch`] last_mile arm runs first; K
/// tiering only applies in the strict segment).
/// - The busy-piece count granularity = **pieces** (the number of distinct
/// pieces on which the peer currently holds fresh in-flight blocks,
/// [`endgame_peer_busy_pieces`]) — equivalent to the old gate 2's block
/// count at the zero check, and taking the local dispatch allocation
/// granularity (piece) for the tier cap.
pub(super) fn endgame_busy_admitted_tiered(
    my_inflight_pieces: u64,
    is_fast_tier: bool,
    k: u64,
    in_flight_pieces: u64,
    missing_pieces: u64,
) -> bool {
    if k == 0 {
        return endgame_busy_admitted(in_flight_pieces, missing_pieces, my_inflight_pieces);
    }
    let busy_ok = if is_fast_tier {
        my_inflight_pieces < k
    } else {
        my_inflight_pieces == 0
    };
    busy_ok && in_flight_pieces >= missing_pieces
}

/// Dispatch-round busy-gate consolidation (the d wiring face; pure
/// function, decision-table tests): the two existing arms run first,
/// bit-for-bit — the last-mile full bypass (wide fan-out, K not involved —
/// the last-mile busy-gate-lift semantics as before) and the strict-off
/// bypass (`BH_ENDGAME_STRICT=0` reverts to the x2 reading, busy gate
/// unreachable); K=0 = the old two-level gate (`my_busy_count` = the
/// block-count input, bit-for-bit); K>=1 = the tiered gate
/// (`my_busy_count` = the busy-piece count plus the `is_fast_tier`
/// criterion). Structurally identical to the original inline expression
/// `last_mile || (strict && endgame_busy_admitted(..))` (short-circuit
/// order preserved).
pub(super) fn endgame_busy_admitted_dispatch(
    last_mile: bool,
    strict: bool,
    fast_busy_k: u64,
    my_busy_count: u64,
    is_fast_tier: bool,
    in_flight_pieces: u64,
    missing_pieces: u64,
) -> bool {
    if last_mile {
        return true;
    }
    if !strict {
        return false;
    }
    if fast_busy_k == 0 {
        return endgame_busy_admitted(in_flight_pieces, missing_pieces, my_busy_count);
    }
    endgame_busy_admitted_tiered(
        my_busy_count,
        is_fast_tier,
        fast_busy_k,
        in_flight_pieces,
        missing_pieces,
    )
}

/// Strict endgame switch (the fallback face; the spec's "independent
/// endgame switch"): default **on**. `BH_ENDGAME_STRICT=0` turns it off —
/// the endgame cursor reverts to the x2 reading (the
/// [`endgame_cursor_pick`] `strict = false` branch: a single-level
/// "advertised AND copies < x2" pick; the unowned-first and busy two-level
/// gates are all bypassed). Read lazily once per process (stable after
/// startup). Parse and read-timing registration in `taiji_io::knobs`
/// (process-level OnceLock).
pub(super) fn endgame_strict_mode() -> bool {
    taiji_io::knobs::endgame_strict_enabled()
}

/// Two-phase in-flight bookkeeping switch (the fallback face): default
/// **on**. `BH_TWO_PHASE_LEDGER=0` turns it off — **full-face revert**:
/// arrival events are not emitted (the transit emission point is
/// knob-gated), `Settling` is unreachable, every consumer arm falls back
/// to the single-state semantics (candidate filter / claimed / x2 metering
/// / the busy in-flight count never see the `Settling` variants = current
/// behavior), and metering windows fall back to the fixed
/// [`DISPATCH_REISSUE_WINDOW`]. Additivity guarantee: the state-machine
/// extension is purely additive (new variants + arrival transitions); the
/// old three-state semantics and transitions are untouched. OFF-state
/// equivalence is proven by all existing tests passing unchanged (domain
/// tests rerun with `BH_TWO_PHASE_LEDGER=0`). Read lazily once per process
/// (same shape as [`endgame_strict_mode`]). Parse and read-timing
/// registration in `taiji_io::knobs` (process-level OnceLock).
pub(super) fn two_phase_ledger() -> bool {
    taiji_io::knobs::two_phase_ledger_enabled()
}

/// Whole-piece judgment window. Upstream: `whole_pieces_threshold`,
/// default 20s (`settings_pack.cpp`
/// `SET(whole_pieces_threshold, 20, nullptr)`); consumption in
/// `request_blocks.cpp`: rate x window decides how many whole
/// (cross-piece) pieces to prefer.
pub(super) const WHOLE_PIECES_THRESHOLD_SECS: u64 = 20;

/// Cross-piece supply byte cap. Upstream: `request_blocks.cpp`
/// `std::min(download_window, std::int64_t(8 * 1024 * 1024))` — the byte
/// cap on merging adjacent whole pieces into the request queue.
pub(super) const WHOLE_PIECE_SUPPLY_CAP_BYTES: u64 = 8 * 1024 * 1024;

/// Per-peer concurrent checkout piece cap (spec invariant 3, configurable;
/// default now 16, having stepped 4 -> 8 -> 16): the reference bound is
/// 8MiB / 256KiB = 32 pieces (`request_blocks.cpp`); the default started
/// conservatively below it. At high-RTT direct connections the BDP is
/// large and a 4-piece pipe depth (256KiB x 4 = 1MiB in flight per peer)
/// cannot fill the bandwidth-delay product. With soft accounting on (see
/// [`checkout_soft_accounting`]) the cap becomes the only depth governor
/// for fast peers (the window dimension is still clamped block-by-block by
/// `supply_cap`); cap 8 x 16 blocks = 128 in flight sits below the request
/// window, so 16 x 16 = 256 >= window lifts that ceiling (within the
/// 256-block BDP cap = 16 pieces). `BH_MULTI_PIECE_SUPPLY_MAX` is read
/// lazily once per process (same shape as [`endgame_strict_mode`]); parse
/// failure / zero falls back to the default 16 (zero would amount to
/// bypassing the whole append arm — that is the fallback switches' job; an
/// explicit `=4`/`=8` steps back through the history bit-for-bit). The
/// budget coupling is in [`super::spill_floor`] — the cap is not
/// preallocated; the RSS impact is assessed on the arena face. Parse and
/// read-timing registration in `taiji_io::knobs` (process-level OnceLock).
pub(super) fn multi_piece_checkout_cap() -> u64 {
    taiji_io::knobs::multi_piece_supply_max()
}

/// Cross-piece supply switch (the fallback face, spec option 4): default
/// **on**. `BH_MULTI_PIECE_SUPPLY=0` reverts the whole face to the
/// single-piece rhythm — the append arm is bypassed wholesale and the
/// existing single-piece path is untouched (OFF-state equivalence proven
/// by all existing dispatch tests passing unchanged plus domain reruns
/// with `BH_MULTI_PIECE_SUPPLY=0`). Read lazily once per process (same
/// shape as [`two_phase_ledger`]). Parse and read-timing registration in
/// `taiji_io::knobs` (process-level OnceLock).
pub(super) fn multi_piece_supply_enabled() -> bool {
    taiji_io::knobs::multi_piece_supply_enabled()
}

/// Cross-piece supply budget floor (knob 2; default 4, previously opt-in
/// 0): `BH_MULTI_PIECE_BUDGET_FLOOR` (u64; default 4 — the cross-piece
/// budget floor for slow peers; an explicit `=0` turns it off, restoring
/// the single-piece budget bit-for-bit; the effective value clamps to
/// [0, 8] — the ceiling keeps the budget <= the checkout cap, preserving
/// "budget never exceeds the checkout cap"). Anchor: at ~10KiB/s per peer,
/// `rate x 20s / piece_len` stays 0-1, so a slow peer's standing depth is
/// pinned by the single-piece rhythm (a peer's supply rate responds
/// causally to our request depth); rqbit runs a standing 128-deep request
/// window (`live/mod.rs`) with no such gate. The effective budget =
/// `max(computed, floor)`. Read lazily once per process
/// ([`multi_piece_checkout_cap`] same shape — consumed per peer in the
/// dispatch round; quasi-static configuration, no hot-path env reads).
/// Parse and read-timing registration in `taiji_io::knobs` (process-level
/// OnceLock).
pub(super) fn multi_piece_budget_floor() -> u64 {
    taiji_io::knobs::multi_piece_budget_floor()
}

/// Checkout-slot soft-accounting switch (the fallback face; default now
/// on, having stepped off -> on in the same package as the
/// [`multi_piece_checkout_cap`] cap 8 -> 16): `BH_CHECKOUT_SOFT_ACCOUNTING=0`
/// (off/false alike) restores off — the whole-piece counting old behavior
/// bit-for-bit. With it on, the append arm `supply_adjacent_pieces`'s
/// `checked_out` count changes from whole pieces to folded occupancy:
/// secondary occupancy = `ceil(sum of remaining outstanding blocks /
/// blocks per piece)` ([`checkout_weight`]), so half-arrived pieces
/// release slots in proportion to their remaining in-flight blocks (the
/// sawtooth of refilling a whole batch at 128 -> 0 becomes a continuous
/// block-by-block flow; rqbit has no piece-level checkout and runs a
/// standing 128-deep window — the anchor in librqbit `live/mod.rs`).
/// **Red line**: only the cap dimension (checkout piece count) is
/// widened, never the window dimension (total in flight stays clamped by
/// supply_cap); the checkout bookkeeping structure / `own_piece_continuable`
/// / the continuation arm / claimed semantics are unchanged (this change
/// only moves append eligibility earlier). Parse and read-timing
/// registration in `taiji_io::knobs` (process-level OnceLock — consumed
/// per peer in the dispatch round, quasi-static configuration).
pub(super) fn checkout_soft_accounting() -> bool {
    taiji_io::knobs::checkout_soft_accounting_enabled()
}

/// Adjacent chain-break softening hop knob (e; `BH_ADJACENT_SKIP_N`,
/// default 2; `=0` explicitly restores the
/// [`next_adjacent_supply_piece`] soft-breakpoint-breaks-the-chain old
/// behavior bit-for-bit). With N >= 1, a cross-piece append chain that
/// hits a soft breakpoint (done / claimed / unadvertised but goff
/// contiguous) skips <= N pieces to continue the chain (minimal hop
/// distance); hard breakpoints (goff discontinuous) still break; the
/// round's cumulative skips stay <= N, and skipped pieces count no
/// checkout occupancy (red lines in
/// [`next_adjacent_supply_piece_skipping`]). Read lazily once per process
/// ([`multi_piece_checkout_cap`] same shape — consumed per peer by the
/// cross-piece append arm in the dispatch round). Parse and read-timing
/// registration in `taiji_io::knobs` (process-level OnceLock).
pub(super) fn adjacent_skip_n() -> u64 {
    taiji_io::knobs::adjacent_skip_n()
}

/// Cross-piece supply budget (production entry; the reference-port surface
/// is [`multi_piece_supply_budget_floored`]): applies the knob-2 floor on
/// top (default 4; an explicit `=0` is bit-for-bit the old behavior).
/// Rate input = the engine's 30s download-window reading (the scoping note
/// below).
pub(super) fn multi_piece_supply_budget(rate_bps: u64, piece_bytes: u64) -> u64 {
    multi_piece_supply_budget_floored(rate_bps, piece_bytes, multi_piece_budget_floor())
}

/// Pure decision surface of the above (floor injected; decision-table
/// tests): the reference `request_blocks.cpp` port `contiguous =
/// min(rate x whole_pieces_threshold, 8MiB) / piece_len`, with a floor on
/// top, `effective = max(ported value, floor)` (the floor's effective
/// value is clamped to [0, 8] by the knobs parse surface; default 4; an
/// explicit `=0` = the old value bit-for-bit).
///
/// Rate input = the engine's 30s download-window reading
/// (`down_windows.rate()`, the same source as the choke/sorting keys).
/// **Intentional divergence**: the reference rate is the per-connection
/// payload-rate 5s average (the `stat.cpp` `m_5_sec_average` shape); the
/// local counterpart reading (the bt-side RequestBook `RateEwma`) has no
/// engine-side projection, so the existing engine rate reading is the
/// single source — 30s vs 5s windows are conservatively equivalent for
/// the gate (a slow peer's reading decays more slowly = cross-piece
/// eligibility is revoked later; the byte count includes protocol
/// overhead so the reading runs slightly high, conservative in the same
/// direction). A zero reading (new connection / no evidence / no tick
/// yet) -> the ported budget 0 — a floor > 0 lifts it past the gate (the
/// `budget < 2` gate in `supply_adjacent_pieces`).
pub(super) fn multi_piece_supply_budget_floored(
    rate_bps: u64,
    piece_bytes: u64,
    floor: u64,
) -> u64 {
    if piece_bytes == 0 {
        return 0;
    }
    let window_bytes = rate_bps.saturating_mul(WHOLE_PIECES_THRESHOLD_SECS);
    let capped = window_bytes.min(WHOLE_PIECE_SUPPLY_CAP_BYTES);
    (capped / piece_bytes).max(floor)
}

/// Checkout-slot soft-accounting weight (pure function; decision-table
/// tests): `ceil(live_blocks / blocks_per_piece)` — folds the in-flight
/// (network-phase outstanding) block total into whole-piece occupancy.
/// Anchor (256KiB pieces = 16 blocks/piece): live=0 -> 0 (a completed /
/// fully-arrived piece releases fully), live <= 16 -> 1, 17-32 -> 2, ...
/// (may exceed one piece's block count — the consumer passes the
/// **secondary-piece set's** total in-flight blocks). Zero-length-piece
/// defense: `blocks_per_piece = 0` -> 0 (no blocks, no occupancy; the same
/// shape as `next_adjacent_supply_piece`'s zero-length chain break).
pub(super) fn checkout_weight(live_blocks: u32, blocks_per_piece: u32) -> u64 {
    if blocks_per_piece == 0 {
        return 0;
    }
    u64::from(live_blocks).div_ceil(u64::from(blocks_per_piece))
}

/// Append-arm checkout occupancy count (pure decision surface; both switch
/// arms driven by decision tables): the single source of `checked_out` in
/// [`supply_adjacent_pieces`] step 3.
///
/// - OFF arm (the explicit `=0` fallback, the earlier default): the old
/// whole-piece count `1 + continuable count` (the primary counts 1
/// whole plus each still-continuable secondary counts 1) —
/// `live_total`/`blocks_per_piece` are not consumed (decision-table rows
/// pin the ignored inputs).
/// - ON arm (soft accounting): `1 + checkout_weight(sum of secondary
/// in-flight blocks, blocks per piece)` — the primary still counts 1
/// whole (at this arm's entry the primary just dispatched via the
/// primary arm, in-flight ≈ a full piece; secondaries are folded by
/// their remaining in-flight blocks, so half-arrived pieces release
/// slots proportionally).
///
/// Red line: this surface only changes the "cap" dimension comparison
/// value — the append loop in `supply_adjacent_pieces` is still clamped
/// block-by-block by `supply_cap` (target window - in flight); the window
/// dimension does not widen.
pub(super) fn checkout_occupancy(
    soft: bool,
    continuable_len: usize,
    live_total: u32,
    blocks_per_piece: u32,
) -> u64 {
    if soft {
        1u64.saturating_add(checkout_weight(live_total, blocks_per_piece))
    } else {
        1u64.saturating_add(continuable_len as u64)
    }
}

/// Adjacent-piece scan for cross-piece append (pure function;
/// decision-table tests): the next wire piece after `from`, which must be
/// **goff-contiguous** (`goffs[from] + piece_len[from] == goffs[next]` —
/// file-boundary padding or gaps break the chain; the seed-side
/// read-ahead-friendly contiguous-run semantics; spec option 1 "adjacent
/// first"). Eligibility = not done (`done`; mask/missing-layer folding
/// shares the source) AND spread-exclusive (!claimed — another peer's
/// fresh in-flight and this round's instant claims judge the same) AND
/// advertisement-aware (the peer bitmap, consistent with primary
/// selection). Any failure -> None (the chain terminates this round).
/// **Intentional narrowing**: continuing across a gap would break the
/// read-ahead run, and gap pieces are being fetched elsewhere (the claimed
/// test); libtorrent's `prefer_contiguous_blocks` acts on the picker's
/// block scan with no explicit adjacent-piece gate (`piece_picker.cpp`,
/// block-level contiguity) — the local structure is piece-level checkout,
/// and the scan stops at the first undispatchable adjacent piece (the
/// "no contiguous dispatchable piece" exit; spec option 1 "until the cap
/// or no contiguous piece").
pub(super) fn next_adjacent_supply_piece(
    face: &FaceState,
    from: u64,
    done: &[bool],
    claimed: &ClaimedSet,
    peer_i: usize,
) -> Option<u64> {
    let next = from.checked_add(1)?;
    if next >= face.piece_count as u64 {
        return None;
    }
    let g_from = face.piece_goffs.get(from as usize).copied()?;
    let len_from = face.piece_bytes.get(from as usize).copied()?;
    let g_next = face.piece_goffs.get(next as usize).copied()?;
    if g_next != g_from.checked_add(len_from)? {
        return None;
    }
    if done.get(next as usize).copied().unwrap_or(true) {
        return None;
    }
    if claimed.contains(next) {
        return None;
    }
    let avail = face
        .peer_cuids
        .get(peer_i)
        .and_then(|c| face.peer_avail.get(c))?;
    if !avail.get(next as usize) {
        return None;
    }
    Some(next)
}

/// Adjacent-piece scan with chain-break softening (e; pure function,
/// decision-table tests): with `BH_ADJACENT_SKIP_N` (N) >= 1, the first
/// ineligible piece no longer breaks the chain immediately — **soft
/// breakpoints** (done / claimed / unadvertised, but goff still
/// contiguous) may be skipped; the lookahead window is the remaining skip
/// budget `max_skip` (candidates at distance d ∈ [1, max_skip+1] from
/// `from`), taking the **first** eligible piece (the smallest gap —
/// minimal-hop chain continuation). **Hard breakpoints** (a goff
/// discontinuity along the walk = file-boundary padding / gap / zero-length
/// piece, or past the torrent's end) still return None and break.
///
/// Returns `(piece, skipped_count)` — skipped = the soft-breakpoint pieces
/// crossed (d - 1); the caller deducts from the round-level budget (at
/// most N per round); skipped pieces are not dispatched, not claimed, and
/// do not count toward checkout occupancy. The `max_skip = 0` arm = the
/// old function bit-for-bit (only d=1, zero soft-breakpoint tolerance —
/// existing strict-chain / supply_adjacent tests pass unchanged under the
/// explicit `=0` fallback arm).
///
/// # Red lines
///
/// Selection-side only — checkout bookkeeping (`peer_extra_pieces` /
/// [`own_piece_continuable`]), the window-dimension `supply_cap` block
/// clamp, and claim/spread exclusivity semantics are unchanged; a skipped
/// piece is by definition claimed by another peer or already done, so
/// skipping yields to it.
///
/// # Rationale
///
/// In claim-dense regions (spread rounds interleaving claims across peers)
/// an adjacent chain often breaks at its first piece — the chain degrades
/// to the single-piece rhythm and the contiguous-run benefit (seed-side
/// read-ahead sequential reads) zeroes out. Skipping <= N soft breakpoints
/// pushes the chain front to the first still-dispatchable piece,
/// preserving the run semantics (the goff-contiguity constraint still
/// guards every step of the walk).
pub(super) fn next_adjacent_supply_piece_skipping(
    face: &FaceState,
    from: u64,
    max_skip: u64,
    done: &[bool],
    claimed: &ClaimedSet,
    peer_i: usize,
) -> Option<(u64, u64)> {
    let avail = face
        .peer_cuids
        .get(peer_i)
        .and_then(|c| face.peer_avail.get(c))?;
    let mut prev_goff = face.piece_goffs.get(from as usize).copied()?;
    let mut prev_len = face.piece_bytes.get(from as usize).copied()?;
    for d in 1..=max_skip.saturating_add(1) {
        let next = from.checked_add(d)?;
        if next >= face.piece_count as u64 {
            return None;
        }
        let g_next = face.piece_goffs.get(next as usize).copied()?;
        // Hard breakpoint: every step of the walk must stay goff-contiguous
        // (from→from+1→…→from+d); skipping a gap (file-boundary padding /
        // zero-length piece) would break the read-ahead run semantics.
        if g_next != prev_goff.checked_add(prev_len)? {
            return None;
        }
        if !done.get(next as usize).copied().unwrap_or(true)
            && !claimed.contains(next)
            && avail.get(next as usize)
        {
            return Some((next, d - 1));
        }
        // Soft breakpoint (done/claimed/unadvertised): goff still
        // contiguous; keep looking ahead within budget.
        prev_goff = g_next;
        prev_len = face.piece_bytes.get(next as usize).copied()?;
    }
    None
}

/// Endgame cursor pick (pure function; decision-table tests). Table order
/// = the [`endgame_pieces`] rarity-ordered missing table (built in the
/// dispatch round).
///
/// - strict = true (default): two-level pick — level 1 **unowned first**
/// (the first missing piece "advertised AND held by nobody fresh in
/// flight"); level 2 busy (the first "advertised AND held by others AND
/// copies < cap" missing piece, reachable only when
/// [`endgame_busy_admitted`] admits). References in those functions'
/// docs.
/// - strict = false (the `BH_ENDGAME_STRICT=0` fallback): single-level
/// pick = the x2 reading byte-for-byte restored (the first "advertised
/// AND copies < cap" missing piece — unowned vs other-held not
/// distinguished).
/// - `copies_limit` (parameterized): the per-piece copy-cap lookup
/// closure — non-last-mile rounds always [`ENDGAME_MAX_COPIES`] (the x2
/// gate, the same verdicts as the existing tables); last-mile rounds use
/// [`endgame_lastmile_copies_limit`] (the holder count, relax-only). The
/// strict=false fallback arm does not consume the relaxed value (the
/// closure always passes x2 — the two fallback switches are orthogonal:
/// with strict off the last-mile gate never fires).
pub(super) fn endgame_cursor_pick(
    pieces: &[u64],
    avail: Option<&PieceBitmap>,
    claimed: &ClaimedSet,
    round_copies: &std::collections::HashMap<u64, u64>,
    strict: bool,
    busy_admitted: bool,
    copies_limit: &dyn Fn(u64) -> u64,
) -> Option<u64> {
    let avail = avail?;
    if !strict {
        return pieces.iter().copied().find(|&p| {
            avail.get(p as usize) && round_copies.get(&p).copied().unwrap_or(0) < copies_limit(p)
        });
    }
    pieces
        .iter()
        .copied()
        .find(|&p| avail.get(p as usize) && !claimed.contains(p))
        .or_else(|| {
            if busy_admitted {
                pieces.iter().copied().find(|&p| {
                    avail.get(p as usize)
                        && claimed.contains(p)
                        && round_copies.get(&p).copied().unwrap_or(0) < copies_limit(p)
                })
            } else {
                None
            }
        })
}

/// Block in-flight bookkeeping state (the inline fixed-width form; a 1-byte
/// compressed projection of the old inner `HashMap<u32, BlockSentState>`
/// value enum).
///
/// The state machine maps one-to-one onto the old enum (red line: zero
/// change):
/// - `None` = the old inner HashMap absent (no bookkeeping — dispatchable);
/// - `InFlight`/`InFlightDup` = **network phase** (the old
/// `InFlight(t)`/`InFlightDuplicate(t)`; the per-block `Instant`
/// collapses into the piece-level shared timestamp
/// [`PieceSentLedger::dispatched_at`] — approximation note in that
/// struct's docs);
/// - `Settling`/`SettlingDup` = **store phase** (the old
/// `Settling { at, dup }` with the `dup` bool split into its own variant
/// — keeping the sibling-cancel criterion alive across phases; `at`
/// likewise approximated by the piece-level timestamp);
/// - `Buffered` = bytes are in the write cache — never re-dispatch.
///
/// Two-phase lifecycle (per coordinate): `InFlight --arrival-->
/// Settling/SettlingDup --BlockSettled--> Buffered --piece settle-->
/// clear`. Network-phase expiry -> wire resend (re-pick + transfer-cancel
/// of the old slot + overwrite of the coordinate, existing); store-phase
/// guard overrun -> warn + count (zero new wire traffic). Reply-drain
/// `WindowFull`/`Closed` affect both phases alike (clear + refetch, total
/// function). With the knob off, `Settling*` is unreachable
/// ([`two_phase_ledger`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum BlockState {
    /// No bookkeeping (the old inner map absent).
    None,
    /// Sent; not yet confirmed by the store pipeline (the old `InFlight`).
    InFlight,
    /// Endgame duplicate copy in flight (the old `InFlightDuplicate`): a
    /// second-hop request for the same (piece, begin) (the block-level
    /// implementation of the "x2 in flight per piece" cap — first copy
    /// [`Self::InFlight`] + at most one duplicate hop; a block already
    /// duplicated is not doubled again, except on the last-mile
    /// wide-fan-out face — see candidate filtering). All other semantics
    /// (expiry takeover reissue, piece-settle clearing, the Buffered
    /// transition, reply drain) match [`Self::InFlight`]; non-endgame
    /// dispatch never produces this state.
    InFlightDup,
    /// Store phase, non-duplicate origin: the block's bytes have arrived
    /// locally, awaiting store-pipeline confirmation (`BlockSettled` ->
    /// [`Self::Buffered`]). This state **never joins reissue decisions**
    /// (the candidate filter is always false, including past the guard
    /// age — store-confirmation lag never triggers a resend; the port of
    /// libtorrent's writing phase not joining reissue, reference in the
    /// module docs).
    Settling,
    /// Store phase, duplicate origin (the old `Settling { dup: true }`):
    /// the sibling-cancel criterion survives across phases — the sibling
    /// is still cancelled at settle time
    /// ([`crate::run::arms::on_block_settled`]).
    SettlingDup,
    /// Bytes are in the write cache (Buffered confirmation) — never
    /// re-dispatch.
    Buffered,
}

/// In-row ownership sentinel ([`BlockSlot::owner`]): no owner (missing
/// bookkeeping / peer gone / slot cleared). The old `block_dispatch` "key
/// absent" semantics.
pub(super) const NO_OWNER: u32 = u32::MAX;

/// Per-block slot: state + owning peer index. Fixed 8B (1B state +
/// alignment padding + 4B owner) — 16 blocks/piece = 128B per piece row
/// (vs ~700B/piece for the old two-level HashMap structure).
#[derive(Debug, Clone, Copy)]
pub(super) struct BlockSlot {
    pub(super) state: BlockState,
    /// Owning peer = the `FaceState::peer_cuids` index ([`NO_OWNER`] =
    /// none). The in-lining of the old global
    /// `block_dispatch: HashMap<(piece, block), cuid>`: cuid <-> index is
    /// a bijection (peers/peer_cuids run in parallel order); index shifts
    /// on peer departure are repaired by
    /// [`PieceSentLedger::reindex_owners`] (wired in the departure arm,
    /// [`crate::run::arms::handle_peer_left`]).
    pub(super) owner: u32,
}

/// Piece-level inline fixed-width ledger (the `FaceState::blocks_sent`
/// value type): `slots[bi]` = the state and owner of block bi (bi = begin
/// / block length).
///
/// Structure: 8B per slot, 16 blocks/piece = **128B per piece row** (vs
/// ~700B/piece for the old `HashMap<u32, BlockSentState>` + global
/// `block_dispatch` pair); the outer `HashMap<u64 piece, PieceSentLedger>`
/// is unchanged (piece -> row). Access: one `blocks_sent.get(&piece)`
/// takes the row, then index reads — the hot paths
/// ([`block_reissue_window`] / candidate filter / metering) drop the
/// double HashMap lookup plus the owner cuid->position linear scan (the
/// owner IS the index).
///
/// # Piece-level time approximation
///
/// `dispatched_at` is set on the piece's first dispatch, and **every
/// dispatch write (first send / refill / expiry takeover / endgame
/// duplicate hop) refreshes it** — all blocks in the piece share the
/// timestamp (an approximation). The old per-block `Instant`
/// fresh/expired judgments (`InFlight*` vs [`reissue_window`], `Settling*`
/// vs [`STORE_PENDING_GUARD`]) now read the shared value: a
/// later-dispatched block refreshes the apparent age of earlier ones (and
/// a re-dispatch refresh masks their staleness). Exact per-block timeouts
/// (adaptive) are independently handled by the RequestBook side (bt
/// crate); the engine-side timestamp only feeds the claimed projection /
/// reissue-candidate derivation / guard warnings (warn + count only, no
/// wire behavior). Under the common shape (one `Instant::now()` per round
/// covering all candidate blocks) this matches per-block values
/// bit-for-bit.
///
/// # Out-of-range defense
///
/// A block index from `begin` >= `slots.len()` (malformed coordinates not
/// aligned to 16KiB — production write sites always construct
/// `bi * BLOCK_SIZE`) is treated as unbookkept: read =
/// [`BlockState::None`], write = ignored (the old HashMap could store any
/// key, with no observable difference).
pub(super) struct PieceSentLedger {
    /// Per-block slots (index = block order).
    slots: Box<[BlockSlot]>,
    /// The piece's unified timestamp (shared across blocks, an
    /// approximation replacing per-block `Instant`s; see the struct docs'
    /// "Piece-level time approximation").
    dispatched_at: Instant,
}

impl PieceSentLedger {
    /// A `blocks`-block row, all `None`/unowned, timestamp anchored at `at`.
    pub(super) fn new(blocks: usize, at: Instant) -> Self {
        PieceSentLedger {
            slots: vec![
                BlockSlot {
                    state: BlockState::None,
                    owner: NO_OWNER,
                };
                blocks
            ]
            .into(),
            dispatched_at: at,
        }
    }

    /// begin -> block index (the 16KiB block grid; block length =
    /// [`taiji_store::merkle::BLOCK_SIZE`]).
    fn block_index(begin: u32) -> usize {
        begin as usize / merkle::BLOCK_SIZE as usize
    }

    fn slot(&self, begin: u32) -> Option<&BlockSlot> {
        self.slots.get(Self::block_index(begin))
    }

    fn slot_mut(&mut self, begin: u32) -> Option<&mut BlockSlot> {
        self.slots.get_mut(Self::block_index(begin))
    }

    /// Block state (out of range / unwritten = [`BlockState::None`], the
    /// same verdict as the old map's absence).
    pub(super) fn block_state(&self, begin: u32) -> BlockState {
        self.slot(begin).map_or(BlockState::None, |s| s.state)
    }

    /// Block owner index (no owner / out of range = None; the same verdict
    /// as the old `block_dispatch.get`).
    pub(super) fn owner_of(&self, begin: u32) -> Option<u32> {
        let owner = self.slot(begin)?.owner;
        (owner != NO_OWNER).then_some(owner)
    }

    /// Network-phase first mark (the inline merge of the old
    /// `insert(begin, InFlight(now))` + `block_dispatch.insert`): sets the
    /// state + refreshes the piece-level timestamp; `owner = None` =
    /// ownership unavailable (peer bookkeeping absent) keeps the existing
    /// owner (aligned with the old form, where block_dispatch was not
    /// written).
    pub(super) fn set_inflight(&mut self, begin: u32, owner: Option<u32>, now: Instant) {
        let Some(slot) = self.slot_mut(begin) else {
            return;
        };
        slot.state = BlockState::InFlight;
        if let Some(o) = owner {
            slot.owner = o;
        }
        self.dispatched_at = now;
    }

    /// Network-phase duplicate-hop mark (the old `InFlightDuplicate(now)`;
    /// semantics in [`BlockState::InFlightDup`]).
    pub(super) fn set_inflight_dup(&mut self, begin: u32, owner: Option<u32>, now: Instant) {
        let Some(slot) = self.slot_mut(begin) else {
            return;
        };
        slot.state = BlockState::InFlightDup;
        if let Some(o) = owner {
            slot.owner = o;
        }
        self.dispatched_at = now;
    }

    /// Block-arrival transition (the arrival arm; `now` unconsumed — the
    /// `Settling*` age reading approximates via the piece-level timestamp,
    /// see the struct docs): `InFlight -> Settling`,
    /// `InFlightDup -> SettlingDup` (the dup mark survives the phase
    /// change); `Settling*` is an idempotent no-op; `Buffered`/unbookkept
    /// -> no-op. Total function.
    pub(super) fn arrive(&mut self, begin: u32) {
        let Some(slot) = self.slot_mut(begin) else {
            return;
        };
        slot.state = match slot.state {
            BlockState::InFlight => BlockState::Settling,
            BlockState::InFlightDup => BlockState::SettlingDup,
            other => other,
        };
    }

    /// Settle transition (the settle arm): any booked state ->
    /// `Buffered` (owner kept — the sibling cancel reads the owner after
    /// settle), returning `Some(was_dup)`; an unbookkept slot (out of
    /// range / unwritten `None`) = `None` (the caller no-ops — the same
    /// verdict as the old inner map's absence; must not invent a
    /// Buffered).
    pub(super) fn settle_buffered(&mut self, begin: u32) -> Option<bool> {
        let slot = self.slot_mut(begin)?;
        if slot.state == BlockState::None {
            return None;
        }
        let was_dup = matches!(
            slot.state,
            BlockState::InFlightDup | BlockState::SettlingDup
        );
        slot.state = BlockState::Buffered;
        Some(was_dup)
    }

    /// Direct store-phase write (test fixture — production goes through
    /// the [`Self::arrive`] total function).
    #[cfg(test)]
    pub(super) fn mark_settling(&mut self, begin: u32, dup: bool) {
        let Some(slot) = self.slot_mut(begin) else {
            return;
        };
        slot.state = if dup {
            BlockState::SettlingDup
        } else {
            BlockState::Settling
        };
    }

    /// Direct Buffered write (test fixture — production goes through
    /// [`Self::settle_buffered`]).
    #[cfg(test)]
    pub(super) fn mark_buffered(&mut self, begin: u32) {
        let Some(slot) = self.slot_mut(begin) else {
            return;
        };
        slot.state = BlockState::Buffered;
    }

    /// Owner-only write (test fixture bridging the old
    /// `block_dispatch.insert((p, b), cuid)` in index form); None = clear
    /// the owner.
    #[cfg(test)]
    pub(super) fn set_owner(&mut self, begin: u32, owner: Option<u32>) {
        let Some(slot) = self.slot_mut(begin) else {
            return;
        };
        slot.owner = owner.unwrap_or(NO_OWNER);
    }

    /// Clear the slot (the old inner `map.remove(&begin)` + ownership
    /// invalidation for the coordinate): back to `None`/unowned. Ownership
    /// and slot state share one lifecycle (absorbs the old corner where
    /// block_dispatch entries lingered until piece settle — ownership in
    /// the unbookkept state has no consumer).
    pub(super) fn clear_slot(&mut self, begin: u32) {
        let Some(slot) = self.slot_mut(begin) else {
            return;
        };
        slot.state = BlockState::None;
        slot.owner = NO_OWNER;
    }

    /// All slots `None` (the empty-row sweep criterion — a row that is
    /// all-empty after slot clears is reclaimed immediately, not held
    /// until piece settle; closes the residue face of stalled tails whose
    /// missing pieces never complete).
    pub(super) fn all_clear(&self) -> bool {
        self.slots.iter().all(|s| s.state == BlockState::None)
    }

    /// Whether any network-phase block is in flight (the old "inner values
    /// contain the `InFlight` family" existence test; shared by
    /// [`own_piece_continuable`] and the supply-quiet gate).
    pub(super) fn has_live_inflight(&self) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s.state, BlockState::InFlight | BlockState::InFlightDup))
    }

    /// Network-phase in-flight block count (the old inner
    /// `InFlight`-family entry count; the same reading as
    /// [`piece_live_inflight_blocks`] — fresh or expired, both
    /// outstanding).
    pub(super) fn live_inflight_count(&self) -> u32 {
        self.slots
            .iter()
            .filter(|s| matches!(s.state, BlockState::InFlight | BlockState::InFlightDup))
            .count() as u32
    }

    /// Bookkept slot count (the old inner map `len()` — the numerator of
    /// the partial hard gate's "row does not cover all of the piece's
    /// blocks" criterion).
    pub(super) fn tracked_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state != BlockState::None)
            .count()
    }

    /// Piece-level timestamp (the shared reading for fresh/expired
    /// judgments and the guard age).
    pub(super) fn dispatched_at(&self) -> Instant {
        self.dispatched_at
    }

    /// Slot view (consumers read by index; begin rebuilds as index x block
    /// length).
    pub(super) fn slots(&self) -> &[BlockSlot] {
        &self.slots
    }

    /// Owner index repair on peer departure (the wiring face: owner = the
    /// peer_cuids index; after `Vec::remove` shifts indices it must be
    /// re-marked — `owner == removed` -> no owner (in the old cuid form:
    /// the position lookup fails and falls back), `owner > removed` ->
    /// shift left by one. O(live slots), bounded by the in-flight block
    /// count.
    pub(super) fn reindex_owners(&mut self, removed: usize) {
        for slot in self.slots.iter_mut() {
            if slot.owner == NO_OWNER {
                continue;
            }
            let o = slot.owner as usize;
            if o == removed {
                slot.owner = NO_OWNER;
            } else if o > removed {
                slot.owner -= 1;
            }
        }
    }
}

/// Block-arrival event (the transit forwarding task -> the main loop's
/// arrival arm; one bounded engine-level channel of 1024 — capacity = 4 x
/// [`crate::pipeline::BLOCK_CHANNEL_CAPACITY`]; full -> degrade without
/// blocking the forwarding task). `cuid` is observational provenance only
/// (attributing duplicate arrivals / guard warnings); the transition
/// decision does not consume it (`blocks_sent` keys on coordinates).
pub(super) struct LedgerArrival {
    pub(super) face: usize,
    pub(super) index: u32,
    pub(super) begin: u32,
    pub(super) cuid: u64,
}

/// Observation counters (process-level atomics — the same shape as
/// `DISPATCH_DONE_PIECE_REQUESTS`, sparing the test fixtures; bridged into
/// `SessionMetrics` by the 1s seed tick deltas, observation only): arrival
/// phase transitions / arrival-channel-full degradations (degrade = keep
/// InFlight, self-healing and safe).
pub(super) static LEDGER_ARRIVALS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub(super) static LEDGER_DEGRADES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
/// Store-phase guard violations, entries x occurrences (accumulated by the
/// scan feed point; warn accompanies).
pub(super) static STORE_PENDING_GUARD_HITS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// A receipt entry for an enqueued request command: (wire piece, begin,
/// reply receiver).
pub(super) type DispatchReply = (
    u64,
    u32,
    oneshot::Receiver<Result<(), taiji_bt::request_book::DispatchError>>,
);

/// The first peer index whose bitmap covers the `wire` piece (the pick
/// point for refetch / lazy fetch; no bitmap evidence -> None). Peers
/// choking us are never picked — only unchoked candidates (a request can
/// only be served once it enters the peer's outstanding window; while
/// choked only allowed-fast set requests are accepted, BEP 6; the local
/// side has no allowed-fast request face). **If every advertising peer
/// chokes us -> None** (the reciprocity fix: the old "fall back to the
/// first" blind send vanished into non-fast-ext peers -> our slot timed
/// out at 60s -> snub -> the choke decision permanently excluded that peer
/// -> never supplied -> the peer's tit-for-tat choked us forever). Waiting
/// in the queue resolves on the unchoke edge (`AvailEvent::Unchoked`) /
/// new peer registration / HAVE advertisements, each of which triggers a
/// re-dispatch.
pub(super) fn peer_with_piece(face: &FaceState, wire: u64) -> Option<usize> {
    for (i, _) in face.peers.iter().enumerate() {
        let has = face
            .peer_cuids
            .get(i)
            .and_then(|c| face.peer_avail.get(c))
            .is_some_and(|v| v.get(wire as usize));
        if !has {
            continue;
        }
        if let Some(p) = face.peers.get(i) {
            if !p.is_choking_us() {
                return Some(i);
            }
        }
    }
    None
}

/// HAVE advertisement -> selectable-set bookkeeping (extracted face;
/// shared by the main loop's AvailEvent::Have and unit tests): sets the
/// bit in `cuid`'s advertisement bitmap row immediately, feeding the new
/// piece into the rarest-first counts (libtorrent `peer_connection.cpp`
/// `m_have_piece.set_bit` — a HAVE is reflected into that peer's piece map
/// at once, the pick candidate face).
pub(super) fn note_peer_have(face: &mut FaceState, cuid: u64, index: u64) {
    let n = face.piece_count;
    let entry = face
        .peer_avail
        .entry(cuid)
        .or_insert_with(|| PieceBitmap::new(n));
    // Bitmap set returns the old value (false = was 0 / out of range not
    // set) — HAVE idempotence and out-of-range defense judge as before.
    let idx = index as usize;
    if idx < entry.len() && !entry.set(idx) {
        face.stat_man.add_piece(index);
    }
}

/// Bitfield advertisement -> selectable-set bookkeeping (extracted face;
/// shared by the main loop's AvailEvent::Bitfield and unit tests): sets
/// bits (BEP 3 MSB order) and feeds the delta into the rarest-first counts
/// (libtorrent `peer_connection.cpp` `incoming_bitfield`).
///
/// Seed promotion/demotion (`piece_picker.cpp` semantics): the new row
/// all-1 while previously not a seed -> subtract the old row + `add_seed`
/// (promotion in O(valid changes)); previously a seed and the new row
/// shrank -> `seed_downgrade` (the break_one_seed port + delta merge,
/// `piece_picker.cpp`); seed AND still all-1 -> the count face is a no-op
/// (the old implementation's update(all-1, all-1) verdict, O(1)). All
/// three branches net out per-piece identical to the old "indiscriminate
/// update(new row, old row)" (the seed contribution = a uniform +1 on the
/// counters).
pub(super) fn note_peer_bitfield(face: &mut FaceState, cuid: u64, bits: &[u8]) {
    let n = face.piece_count;
    let entry = face
        .peer_avail
        .entry(cuid)
        .or_insert_with(|| PieceBitmap::new(n));
    // Stage the delta base at write time: a bitmap clone, O(words)
    // (replaces the old two full-row byte clones — old_mask and the update
    // arm's entry clone).
    let old_mask = entry.clone();
    // The wire boundary (the MSB-order parse window = min(n, bytes x 8),
    // set-only) is handled inside the bitmap's or_from_packed_msb, same
    // verdicts as the old per-bit loop.
    entry.or_from_packed_msb(bits);
    let was_seed = face.peer_seeds.contains(&cuid);
    let now_full = entry.is_full();
    if !was_seed && now_full {
        // Promote to seed: subtract the old row's evidence + the seed
        // counter (the same bookkeeping as note_peer_have_all; net effect =
        // 0 at old-row positions, +1 at new holdings, the same verdict as
        // the old update).
        let stat = &mut face.stat_man;
        stat.subtract_bitfield(|i| old_mask.get(i as usize), n as u64);
        stat.add_seed();
        face.peer_seeds.insert(cuid);
    } else if was_seed && !now_full {
        // Seed demotion: break_one_seed (the seed contribution falls back
        // to per-piece) + merge the new row's delta.
        let stat = &mut face.stat_man;
        stat.seed_downgrade(|i| entry.get(i as usize), n as u64);
        face.peer_seeds.remove(&cuid);
    } else if !was_seed {
        // Regular delta (the existing path, verdicts unchanged): the stat
        // closure form is kept, reading the changed bits inside the closure
        // (the bt side untouched).
        let stat = &mut face.stat_man;
        stat.update_bitfield(
            |i| entry.get(i as usize),
            |i| old_mask.get(i as usize),
            n as u64,
        );
    }
    // was_seed AND now_full: the count face is unchanged (the seed
    // contribution already sits in the counters, O(1)).
}

/// HaveAll advertisement -> selectable-set bookkeeping (shared by the main
/// loop's AvailEvent::HaveAll and unit tests): synthesizes an all-1 bitmap
/// (piece count = the face's flat space [`FaceState::piece_count`];
/// trailing out-of-range bits are ignored by [`note_peer_bitfield`]'s parse
/// window) and then runs the **identical** bookkeeping / dispatch-unlock
/// path as a bitfield (row build/replace + delta feed into the
/// rarest-first counts — the local equivalence face of BEP 6 have_all and
/// bitfield). Anchors (in authority order): libtorrent
/// `incoming_have_all` (`peer_connection.cpp`, `m_have_piece.set_all()` +
/// `t->peer_has_all`; old evidence first withdrawn via peer_lost); aria2
/// `BtHaveAllMessage.cc` subtractPieceStats -> setAllBitfield ->
/// addPieceStats. Locally the old evidence row ⊆ all-1, so the set-only
/// delta nets out the same as withdraw-then-add.
///
/// Seed O(1) fast path (the `piece_picker.cpp` `inc_refcount_all` port:
/// `++m_seeds`, no per-piece availability bump): the row evidence is still
/// fully materialized (the pick/dispatch bitmap consumer face unchanged);
/// rarity counting goes through the seed counter — subtracting the old row +
/// `add_seed` nets out per-piece identical to the old "update(all-1, old
/// row)" (0 at old-row positions, +1 at new holdings). A repeated HaveAll
/// (already in the seed set) = a pure row refresh, the count face
/// untouched (the same verdict as the old update(all-1, all-1)).
pub(super) fn note_peer_have_all(face: &mut FaceState, cuid: u64) {
    let n = face.piece_count;
    let old = face.peer_avail.insert(cuid, PieceBitmap::ones(n));
    if !face.peer_seeds.contains(&cuid) {
        let stat = &mut face.stat_man;
        if let Some(old) = &old {
            stat.subtract_bitfield(|i| old.get(i as usize), n as u64);
        }
        stat.add_seed();
        face.peer_seeds.insert(cuid);
    }
}

/// HaveNone advertisement -> explicit zero-holding bookkeeping: the row is
/// replaced with all-0 and the old evidence withdrawn via
/// [`PieceStatMan::remove_peer`] (replace semantics; libtorrent anchor:
/// `incoming_have_none` in `peer_connection.cpp` does a preceding
/// peer_lost + `m_have_piece.clear_all()` — aria2 `BtHaveNoneMessage.cc`
/// leaves the bitmap alone, its empty holding being the initial state; the
/// local side takes the libtorrent reading to correctly withdraw late
/// evidence). Trade-off note: an all-0 row and a missing row are
/// observationally equivalent ([`select_advertised_piece`] returns None
/// for both = no dispatch unlock, zero requests while waiting for a real
/// advertisement); the explicit row exists only to retain the peer's
/// declared evidence and make departure withdrawal idempotent (a zero
/// subtraction), not as a new unlock criterion. Seed rows go through
/// `remove_seed` (the `piece_picker.cpp` `dec_refcount_all` port) — a
/// uniform -1 with the same verdict as the old per-piece withdrawal.
pub(super) fn note_peer_have_none(face: &mut FaceState, cuid: u64) {
    let n = face.piece_count;
    let old = face.peer_avail.insert(cuid, PieceBitmap::new(n));
    if face.peer_seeds.remove(&cuid) {
        face.stat_man.remove_seed();
    } else if let Some(old) = old {
        let stat = &mut face.stat_man;
        stat.remove_peer(|i| old.get(i as usize), n as u64);
    }
}

/// Peer departure -> selectable-set row withdrawal (extracted from
/// handle_peer_left; the extracted face is shared with unit tests):
/// removes the row and withdraws its contribution to the rarity counts
/// (the aria2 `PieceStatMan.cc` semantics; `remove_peer` =
/// subtract_bitfield). bitfield/HAVE/HAVE_ALL/HAVE_NONE bookkeeping all
/// live in [`FaceState::peer_avail`], so the departure withdrawal is
/// inherited naturally. Seed peers (full rows) go through `remove_seed`
/// (the seed O(1) fast path).
pub(super) fn remove_peer_avail(face: &mut FaceState, cuid: u64) {
    if face.peer_seeds.remove(&cuid) {
        face.peer_avail.remove(&cuid);
        face.stat_man.remove_seed();
    } else if let Some(bits) = face.peer_avail.remove(&cuid) {
        let n = face.piece_count as u64;
        let stat = &mut face.stat_man;
        stat.remove_peer(|i| bits.get(i as usize), n);
    }
}

/// Advertisement-aware selection: the candidate set = the peer's
/// advertised bitmap (bitfield/HAVE accumulation) ∩ locally unfinished
/// pieces; returning None = **zero requests** to that peer.
///
/// Missing bitmap evidence (`avail = None`, the peer sent no
/// bitfield/HAVE) -> None — BEP 3 semantics: treat as have_none (libtorrent
/// `peer_connection.cpp`: "if we haven't received a bitfield, it was
/// probably omitted, which is the same as 'have_none'"). No unfinished
/// piece inside the advertised set -> also None (the `piece_picker.cpp`
/// `Selection::None` semantics).
///
/// Dual-reference anchors (in authority order):
/// - libtorrent (primary): request candidates come only from the peer's
/// piece map — `request_blocks.cpp` `auto const* bits =
/// &c.get_bitfield();` -> `p.pick_pieces(*bits, …)`; `piece_picker.cpp`
/// `pick_pieces(typed_bitfield const& pieces, …)` takes the peer's
/// bitmap as the candidate set; HAVE updates the bitmap immediately
/// (`peer_connection.cpp`).
/// - aria2 (secondary): `DefaultPieceStorage.cc` getMissingPiece filters
/// request targets by `peer->getBitfield()`; `DefaultBtInteractive.cc`.
///
/// On None the caller must skip the peer (wait for advertisements / a new
/// peer) and must **not** fall back to a blind pick: the legacy
/// `unwrap_or(current)` used to request pieces the peer never advertised,
/// and real seeds refuse with FIN (disconnecting within ~250-500ms) —
/// eradicated in this module. Waiting != disconnecting (an explicit
/// prohibition: never disconnect for missing advertisements).
///
/// Selection unification: this function = [`select_advertised_piece_spread`]
/// given an **empty claim set** (on an empty set `!claimed.contains(i)` is
/// always true = pure advertisement-aware semantics), one selection
/// implementation; every caller (the strategy two-phase / streaming
/// fallback layer + engine unit tests) keeps signature and behavior.
/// Continuation eligibility for a peer's checkout piece (lazy
/// invalidation, phase 3): the piece is unfinished AND bookkeeping exists
/// AND **network-phase blocks are still in flight** (`InFlight` family).
/// Store-phase `Settling` = the block bytes are local, no wire work left
/// to continue — treated as the checkout returned (the peer rejoins
/// normal selection); `Buffered` / a cleared entry (completion / eviction
/// / abort / reject reset) likewise returned. With the knob off `Settling`
/// is unreachable and behavior matches the old "continuable unless
/// Buffered" bit-for-bit.
fn own_piece_continuable(face: &FaceState, piece: u64) -> bool {
    if face.progress.piece_done_global(piece) {
        return false;
    }
    match face.blocks_sent.get(&piece) {
        Some(ledger) => ledger.has_live_inflight(),
        None => false,
    }
}

/// The piece's remaining outstanding (network-phase in-flight) block count
/// (the soft-accounting data source, a minimally invasive row-level
/// reading): the InFlight-family slot count in the `blocks_sent[p]` row —
/// fresh or expired both count as outstanding (expired only means takeover
/// reissue is possible, the bytes have not arrived; the continuation arm's
/// step 2 refreshes first, making them fresh). Settling/Buffered = already
/// local, not counted (a fully arrived piece -> 0 = the slot fully
/// released); a cleared entry (piece settle / eviction) or no bookkeeping
/// -> 0. The same InFlight-family reading as [`own_piece_continuable`]
/// (the count face vs the existence face).
fn piece_live_inflight_blocks(face: &FaceState, piece: u64) -> u32 {
    face.blocks_sent
        .get(&piece)
        .map(|l| l.live_inflight_count())
        .unwrap_or(0)
}

/// Parole-peer selection (pure function): the first missing piece in
/// rarity order ([`PieceStatMan::order`], the same order source as regular
/// selection) satisfying all conditions —
/// 1. this peer advertised it (the advertisement-aware semantics are not
/// waived: a piece the peer never advertised cannot be delivered by it);
/// 2. unfinished (`done` already folds the mask / missing-layer gating);
/// 3. not claimed this round (spread exclusivity as usual);
/// 4. **an unowned whole piece** — `blocks_sent` has no entry at all (no
/// peer delivered or buffered any block of the piece within this
/// dispatch cycle).
/// Condition 4 is the necessary-and-sufficient unambiguous-attribution
/// face: once the suspect exclusively owns the whole piece, another
/// failure ⟹ the bad block necessarily came from that peer (the
/// dispatch-side premise of the smart_ban evidence chain; the structural
/// counterpart of libtorrent's parole `prioritize_partials`,
/// `torrent.cpp`). No qualifying piece -> None (skip the peer; waiting !=
/// disconnecting — the same exit semantics as advertisement-aware
/// selection).
pub(super) fn parole_pick_piece(
    face: &FaceState,
    peer_i: usize,
    done: &[bool],
    claimed: &ClaimedSet,
) -> Option<u64> {
    let avail = face
        .peer_cuids
        .get(peer_i)
        .and_then(|c| face.peer_avail.get(c))?;
    // order() is u32 after the compaction (this function predates it and
    // consumes u64 — the seam conversion).
    face.stat_man
        .order()
        .iter()
        .copied()
        .map(u64::from)
        .find(|&i| {
            (i as usize) < done.len()
                && !done[i as usize]
                && !claimed.contains(i)
                && avail.get(i as usize)
                && !face.blocks_sent.contains_key(&i)
        })
}

pub(super) fn select_advertised_piece(
    avail: Option<&PieceBitmap>,
    done: &[bool],
    stat_man: &PieceStatMan,
    prio: Option<&[i8]>,
) -> Option<u64> {
    let no_claims = ClaimedSet::empty();
    select_advertised_piece_spread(avail, done, stat_man, &no_claims, prio)
}

/// The spread-round claim set: the dense-bitmap form of a `HashSet<u64>` —
/// the `select` scan's hot path does one `contains` per piece per peer,
/// and SipHash hashing was an observable dispatch-face leaf in flame
/// graphs; the dense bitmap reduces the query to a bit read. The decision
/// semantics are identical to `HashSet<u64>` (membership + count); in-round
/// instant claims (`mark_claimed`) and the "blank this round" view
/// (`ClaimedSet::empty`) are expressed through the construction face.
/// Capacity = the face's piece count (a few KiB at 3024 pieces), rebuilt
/// per round through the scratch-reuse face.
#[derive(Debug, Clone, Default)]
pub(super) struct ClaimedSet {
    bits: Vec<bool>,
    count: usize,
}

impl ClaimedSet {
    /// The empty view (the endgame spread round's blanked claimed input;
    /// the equivalent of the old empty `empty_claimed` HashSet —
    /// `contains` always false).
    pub(super) fn empty() -> ClaimedSet {
        ClaimedSet::default()
    }

    /// A zero bitmap at the face's piece count (the test-driven face — the
    /// production dispatch round reuses in place via [`ClaimedSet::reset`]
    /// instead of discarding and rebuilding).
    #[cfg(test)]
    pub(super) fn with_len(piece_count: usize) -> ClaimedSet {
        ClaimedSet {
            bits: vec![false; piece_count],
            count: 0,
        }
    }

    /// In-place reset to the face's piece count (the scratch-reuse face):
    /// bitmap clear + resize keeps capacity (grow-only), count zeroed —
    /// semantics identical to discard-and-rebuild
    /// ([`ClaimedSet::with_len`]).
    pub(super) fn reset(&mut self, piece_count: usize) {
        self.bits.clear();
        self.bits.resize(piece_count, false);
        self.count = 0;
    }

    /// In-round instant claim (the old `HashSet::insert` semantics;
    /// repeated claims are idempotent).
    pub(super) fn mark_claimed(&mut self, piece: u64) {
        let slot = self.bits.get_mut(piece as usize);
        if let Some(slot) = slot {
            if !*slot {
                *slot = true;
                self.count += 1;
            }
        }
    }

    /// Claim withdrawal (the old `HashSet::remove` semantics; the
    /// production dispatch round rebuilds each round and never takes this
    /// path — for the test simulators' (strategy tests) end-of-round
    /// cleanup).
    #[cfg(test)]
    pub(super) fn remove(&mut self, piece: u64) {
        if let Some(slot) = self.bits.get_mut(piece as usize) {
            if *slot {
                *slot = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Membership (the old `HashSet::contains`; out of range = unclaimed).
    pub(super) fn contains(&self, piece: u64) -> bool {
        self.bits.get(piece as usize).copied().unwrap_or(false)
    }

    /// Claimed piece count (the old `HashSet::len`; the in-flight piece
    /// set input to the endgame trigger).
    pub(super) fn len(&self) -> usize {
        self.count
    }
}

/// Dispatch spread-round selection: on top of the
/// [`select_advertised_piece`] candidates (the peer-advertised bitmap ∩
/// locally unfinished), exclude `claimed` (pieces in flight elsewhere; the
/// caller delimits them by InFlight bookkeeping not past
/// [`DISPATCH_REISSUE_WINDOW`]) — each peer claims a different piece,
/// preventing deterministic-order selection from funneling every peer onto
/// the same piece and clamping aggregate throughput to a single
/// connection.
///
/// Anchors:
/// - aria2 (the direct reference for this semantics):
/// `DefaultPieceStorage.cc` getMissingPiece(index) returns null outright
/// for `isPieceUsed(index)` (checked out in flight elsewhere) — an
/// in-flight piece is not re-allocated; getMissingPiece(peer) checks out
/// one piece per peer (usedPieces_ bookkeeping); `getMissingFastPiece`
/// is the fast-face fallback when regular selection is empty — the
/// counterpart of the caller falling back to
/// [`select_advertised_piece`] when this function returns None (the
/// tail / few-pieces-many-peers case stays busy).
/// - libtorrent: block-level claims spread naturally — `piece_picker.cpp`
/// mark_as_downloading records blocks under the claiming peer, and
/// `request_blocks.cpp` picks per peer only unclaimed blocks.
///
/// Deliberate divergence from aria2: aria2 holds the whole-piece checkout
/// exclusively until the piece completes or is cancelled; locally the
/// claim ages out at [`DISPATCH_REISSUE_WINDOW`] (2s) — past the window
/// without confirmation a piece counts as stalled and can be taken over
/// by another peer (anti-store-stall starvation, a more aggressive
/// self-healing than whole-piece exclusivity, not a line-by-line port).
/// Duplicate requests onto in-flight blocks are still blocked by the
/// candidates' InFlight filter (no resend).
pub(super) fn select_advertised_piece_spread(
    avail: Option<&PieceBitmap>,
    done: &[bool],
    stat_man: &PieceStatMan,
    claimed: &ClaimedSet,
    prio: Option<&[i8]>,
) -> Option<u64> {
    let avail = avail?;
    let avail_fn = |i: u64| avail.get(i as usize) && !done[i as usize] && !claimed.contains(i);
    match select_piece(stat_man, avail_fn, SelectFilter::default(), &[], prio) {
        Selection::Piece(x) => Some(x),
        _ => None,
    }
}

/// The **single-pass dual-record** form of the two-phase selection (the
/// in-round cost reduction; verdicts identical to
/// [`select_advertised_piece_spread`] `.or_else([`select_advertised_piece`])`
/// — mathematical identity: the two phases are "min-count with / without
/// the `claimed` filter over the same traversal order (strictly-less
/// replaces = ties keep the earlier order)", and a single pass maintaining
/// both mins per piece yields the same pair; when phase 1 hits, phase 2's
/// record is discarded, and when phase 1 is None the second record is
/// taken directly — no second scan).
///
/// Rationale: `piece_stat::select` was the largest single user-CPU leaf;
/// the non-endgame path could run up to two full-order scans per peer per
/// round (the spread round plus the all-claimed fallback), and the single
/// pass folds the fallback shape's 2xO(N) back to 1xO(N). The endgame path
/// does not go through this function (the cursor pick inside
/// `dispatch_face_selected_with_stream`); spread/fallback semantics are
/// unchanged, locked by decision-table tests.
///
/// Bucket-read form (spec goal 2, the `piece_picker.hpp` shape): the dual
/// record sinks into [`PieceStatMan::select_two_phase`] — an ascending
/// bucket scan takes the first eligible (plain) and the first
/// eligible-and-unclaimed (spread), mathematically the same verdicts as
/// the old O(N) full-order scan (bucket order = (count, shuffle rank)
/// ascending, see that method's equivalence docs); one O(N) lazy rebuild
/// per round (the dirty gate, the `piece_picker.cpp` port) + O(bucket
/// distance) pick per peer replaces the old O(N) per peer per round.
///
/// `preferred` = the partial hard-gate round's partial-piece table
/// ([`SelectionCtx::preferred`], always empty in non-gate rounds): within
/// the table take the first eligible-and-rarest (the same-shape verdict as
/// the existing preferred/allowed-fast handling — strictly-less replaces =
/// table order wins; the local consumption point of the reference
/// `piece_picker.cpp` prioritize_partials).
pub(super) fn select_rarest_two_phase_one_pass(
    avail: Option<&PieceBitmap>,
    done: &[bool],
    stat_man: &PieceStatMan,
    claimed: &ClaimedSet,
    preferred: &[u64],
    prio: Option<&[i8]>,
) -> Option<u64> {
    let avail = avail?;
    let eligible = |i: u64| avail.get(i as usize) && !done[i as usize];
    if !preferred.is_empty() {
        // The preferred face judges identically (level-first — higher
        // level wins, then min-count within a level, then shuffle order;
        // the same reading as select()'s preferred arm).
        let level = |i: u64| prio.and_then(|p| p.get(i as usize).copied()).unwrap_or(0);
        let mut best: Option<(u64, u32, i8)> = None;
        for &i in preferred {
            if eligible(i) {
                let c = stat_man.count(i);
                let q = level(i);
                if best.is_none_or(|(_, bc, bq)| q > bq || (q == bq && c < bc)) {
                    best = Some((i, c, q));
                }
            }
        }
        if let Some((i, _, _)) = best {
            return Some(i);
        }
    }
    let (spread, plain) = stat_man.select_two_phase(eligible, |i| claimed.contains(i), prio);
    spread.or(plain)
}

/// Sends one plan block of a single-file lazy fetch: RequestHashes -> the
/// watcher awaits the reply, verifies, and admits -> an event returns to
/// the main loop. A send failure (channel full / peer gone) does not set
/// Pending; the next tick retries.
pub(super) fn issue_fetch(
    face: &mut FaceState,
    fi: usize,
    file_idx: usize,
    next: usize,
    peer_pos: usize,
) {
    let layer = &face.layers[file_idx];
    let Some(plan) = layer.plans.get(next).copied() else {
        face.layers[file_idx].state = LayerFetchState::Done;
        return;
    };
    let root = layer.root;
    let leaf_total = layer.leaf_total;
    let trees = face
        .trees
        .clone()
        .unwrap_or_else(|| unreachable!("issue_fetch only on v2 faces with trees"));
    let evt_tx = face.fetch_tx.clone();
    let (tx, rx) = oneshot::channel::<Result<HashFetch, taiji_bt::peer::HashRequestError>>();
    let sent = face.peers[peer_pos]
        .command(taiji_bt::peer::PeerCommand::RequestHashes {
            root,
            base: 0,
            index: plan.index,
            length: plan.length,
            proof: 0,
            reply: tx,
        })
        .is_ok();
    if !sent {
        return;
    }
    face.layers[file_idx].state = LayerFetchState::Pending;
    tokio::spawn(async move {
        // The timeout lives in the watcher (Pending needs no main-loop tick
        // patrol; HASH_FETCH_TIMEOUT is a local policy value, see the
        // hash_fetch constant docs).
        let event = match tokio::time::timeout(HASH_FETCH_TIMEOUT, rx).await {
            Ok(Ok(Ok(fetch))) => {
                let mut trees = crate::lock(&trees);
                match hash_fetch::admit_hashes(&mut trees, &root, plan, leaf_total, fetch) {
                    Ok(()) => HashFetchEvent::Admitted { next },
                    Err(e) => {
                        debug!(target: "taiji::core::engine", face = fi, plan = next,
                            %e, "hash fetch admit failed");
                        HashFetchEvent::Failed { next }
                    }
                }
            }
            _ => HashFetchEvent::Failed { next },
        };
        let _ = evt_tx.send((fi, file_idx, event)).await;
    });
}

// ---------------------------------------------------------------------------
// Piece-layer recovery fetch (hash recovery C-1).
//
// Multi-piece files missing their piece layers entry: pull the whole layer
// in one covering fetch from base = the piece layer (planner in
// [`taiji_domain::hash_fetch::plan_piece_layer_fetch`]); replies are
// staged per block with no admission — trust comes from the whole-file
// layer recompute converging to the info's pieces root — and delivery to
// C-2 happens over a bounded channel once complete.
//
// Trigger and cadence: parse-time rejection was downgraded to a
// `layer_missing` mark (the bt::filetree missing/corrupt boundary); this
// bookkeeping is registered by build_v2_data_plane for layer-missing
// multi-piece files (the live path), driven by the 1s tick and reply
// events; delivery runs the whole-file convergence admission in the
// consumer ([`super::recovery_admit`]).
//
// Upstream anchors (libtorrent):
// - At most 1 in-flight hash request per peer: bt_peer_connection.cpp
// `if (is_disconnecting() || m_hash_requests.size() > 1) return;` (the
// bt connection layer already forces Busy; this bookkeeping also skips
// in-flight peers at pick time — no wasted sends);
// - Peer coverage evidence: hash_picker.cpp (pick_hashes only requests
// when the bitfield covers at least one piece in the 512-piece bucket;
// BEP 52 "prioritize requests where they can be certain that the other
// party must have the necessary data"); falling back to any v2 peer is
// a local engine freedom;
// - Timeout/retry constants follow the download-face lazy fetch
// (hash_fetch.rs); libtorrent instead uses a 3s per-bucket minimum
// re-request interval (hash_picker.cpp) — an engine-freedom difference,
// recorded here.
// ---------------------------------------------------------------------------

/// Recovery peer-switch memory cap (the cuid-set clear-everything
/// threshold; the normal bound = the connected peer count — guards the
/// aging set against unbounded growth on long runs, the bounded-bookkeeping
/// discipline).
pub(super) const RECOVERY_TRIED_CAP: usize = 64;

/// The cooldown window for peer-switch memory. Without a TTL on the tried
/// memory, a single malicious peer (a wrong-content reply also enters the
/// memory) plus an exhausted retry budget would pin recovery on "wait for
/// a new peer" forever — after the cooldown the connected peers become
/// explorable again (self-healing). Window length: the midpoint 90s of the
/// audit-recommended 60-120s range (a local policy value — BEP
/// 52/libtorrent have no citable constant; libtorrent's closest face is
/// the 512-piece-bucket minimum re-request interval
/// `min_request_interval = seconds(3)`, `hash_picker.cpp`, the same
/// bucket-throttle semantics but too short a suppression for bad-content
/// peers). Lower-bound constraint: the window >= 9 x
/// [`taiji_domain::hash_fetch::HASH_FETCH_TIMEOUT`] (10s) — at most one
/// full in-flight request cycle inside the cooldown, so the post-budget
/// re-probe cadence = 1 per window per file, no retry storm.
pub(super) const RECOVERY_TRIED_COOLDOWN: Duration = Duration::from_secs(90);

/// Recovery -> delivery channel capacity (bounded; full = backpressure —
/// keep the Received state and retry next round, no drops, no main-loop
/// blocking).
pub(super) const RECOVERY_DELIVER_CAPACITY: usize = 8;

/// Per-file recovery fetch state machine (missing -> requesting ->
/// received -> delivered).
#[derive(Debug)]
pub(super) enum RecoveryFetchState {
    /// Awaiting fetch (including retry waits: once retries are exhausted,
    /// wait for a new peer to connect — a whole-file failure stays
    /// recovering and retries periodically as new peers are discovered; no
    /// terminal failure).
    Missing,
    /// One block in flight (the watcher holds the timeout — like lazy-fetch
    /// Pending, no main-loop patrol; completion / failure return as
    /// events).
    Requesting { block: usize, cuid: u64 },
    /// All blocks staged, awaiting delivery (held while the channel is
    /// full; retried next round).
    Received,
    /// Delivered to C-2 (terminal; the file-level gate flip belongs to the
    /// admission face).
    Delivered,
}

/// Per-file recovery bookkeeping: staging + dispatch-face retry /
/// peer-switch memory.
#[derive(Debug)]
pub(super) struct FileRecovery {
    pub(super) staging: PieceLayerStaging,
    /// The file's flat piece-range base (the bitmap-window start of the
    /// peer coverage-evidence test).
    pub(super) piece_base: u64,
    pub(super) state: RecoveryFetchState,
    /// Consecutive failure count (any block success zeroes it; follows the
    /// lazy-fetch [`HASH_FETCH_MAX_ATTEMPTS`] reading — retries exhausted
    /// waits for a new peer, never downgrades).
    pub(super) attempts: u32,
    /// Peers that failed this file: cuid -> failure timestamp (re-fetch
    /// from a different peer; any block success clears it). Entries are
    /// time-limited — peers past [`RECOVERY_TRIED_COOLDOWN`] become
    /// explorable again (the driver round consumes them via the
    /// [`active_tried`] view, pruning expired entries on the spot;
    /// bounded-bookkeeping self-healing).
    pub(super) tried: std::collections::HashMap<u64, Instant>,
}

impl FileRecovery {
    /// Registers a layer-missing file (multi-piece files; single-piece
    /// files = None — recovery never fires, BEP 52).
    pub(super) fn new(
        root: [u8; 32],
        file_len: u64,
        piece_len: u32,
        piece_base: u64,
    ) -> Option<FileRecovery> {
        let staging = PieceLayerStaging::new(root, file_len, piece_len);
        if staging.block_count() == 0 {
            return None;
        }
        Some(FileRecovery {
            staging,
            piece_base,
            state: RecoveryFetchState::Missing,
            attempts: 0,
            tried: std::collections::HashMap::new(),
        })
    }

    /// Records a failure (peer-switch memory + the consecutive failure
    /// count; the over-cap fallback clears the set — see
    /// [`RECOVERY_TRIED_CAP`]).
    pub(super) fn note_failure(&mut self, cuid: u64) {
        self.note_failure_at(cuid, Instant::now());
    }

    /// Clock-injectable form of [`Self::note_failure`] (drives the
    /// cooldown-table tests; production always uses [`Instant::now`]).
    pub(super) fn note_failure_at(&mut self, cuid: u64, now: Instant) {
        self.attempts = self.attempts.saturating_add(1);
        if self.tried.len() >= RECOVERY_TRIED_CAP {
            self.tried.clear();
        }
        self.tried.insert(cuid, now);
        self.state = RecoveryFetchState::Missing;
    }
}

/// The cooldown view (pure function, table-driven tests): the effective
/// peer-switch memory after pruning tried entries past
/// [`RECOVERY_TRIED_COOLDOWN`] (pruned in passing — bounded-bookkeeping
/// self-healing). A peer inside the cooldown does not join peer selection
/// (rejected within the window); once expired it rejoins the candidate
/// order (released at expiry).
pub(super) fn active_tried(rec: &mut FileRecovery, now: Instant) -> std::collections::HashSet<u64> {
    rec.tried
        .retain(|_, t| now.duration_since(*t) < RECOVERY_TRIED_COOLDOWN);
    rec.tried.keys().copied().collect()
}

/// Fresh-evidence reset: when a peer re-advertises holding evidence (Have
/// / Bitfield / HaveAll), clear its cooldown in every recovery entry's
/// peer-switch memory — the earlier failure may have been transient (the
/// peer did not yet hold the data / temporarily refused); reachable again
/// and declaring possession = immediately explorable, without waiting out
/// the window. Storm bound: re-probing stays triple-clamped by one
/// in-flight per file, at most 1 in-flight hash request per peer (the
/// bt-side Busy gate), and the driver-round cadence (1s tick /
/// event-driven) — at most 1 req/s per connection. HaveNone is
/// counter-evidence and does not reset.
pub(super) fn note_recovery_evidence(book: &mut RecoveryBook, cuid: u64) {
    for (file_idx, rec) in book.files.iter_mut() {
        if rec.tried.remove(&cuid).is_some() {
            debug!(target: "taiji::core::engine", file_index = file_idx, cuid,
                "recovery tried-cooldown reset by fresh availability evidence ()");
        }
    }
}

/// Per-face recovery bookkeeping (keyed by file_index; entries = the
/// layer-missing multi-piece files, bounded by the file count; at most 1
/// in-flight request per file and at most 1 in-flight per peer across
/// files).
#[derive(Debug, Default)]
pub(super) struct RecoveryBook {
    pub(super) files: std::collections::BTreeMap<usize, FileRecovery>,
}

/// Recovery peer selection (pure function, table-driven tests).
///
/// Candidate order = **coverage first** (peers whose bitfield/have
/// evidence covers any piece of the file's piece range [lo, hi) come
/// first — the dual of the BEP 52 service obligation, the same reading as
/// libtorrent `hash_picker.cpp`) -> **any v2 peer fallback** (trust is
/// guaranteed by the convergence criterion, not by the peer holding data —
/// seeders usually carry complete metadata layers). Excluded: in-flight
/// peers (at most 1 in flight per peer; the libtorrent
/// `bt_peer_connection.cpp` anchor — the bt side enforces Busy, so no
/// wasted sends here) and `tried`-memory peers (re-fetch from a different
/// peer; the input = the effective memory view filtered through the
/// [`active_tried`] cooldown window, expired entries already pruned by the
/// caller). v2 faces only (hash exchange is a v2 semantic — the same gate
/// as libtorrent `bt_peer_connection.cpp` protocol_v2); within a rank,
/// connection order (deterministic, assertable in tests).
pub(super) fn recovery_peer_order(
    face: &FaceState,
    piece_lo: u64,
    piece_hi: u64,
    busy: &std::collections::HashSet<u64>,
    tried: &std::collections::HashSet<u64>,
) -> Vec<usize> {
    if face.kind != FaceKind::V2 {
        return Vec::new();
    }
    let mut covering = Vec::new();
    let mut fallback = Vec::new();
    for (i, cuid) in face.peer_cuids.iter().enumerate() {
        if busy.contains(cuid) || tried.contains(cuid) {
            continue;
        }
        let covers = face
            .peer_cuids
            .get(i)
            .and_then(|c| face.peer_avail.get(c))
            .is_some_and(|row| (piece_lo..piece_hi).any(|p| row.get(p as usize)));
        if covers {
            covering.push(i);
        } else {
            fallback.push(i);
        }
    }
    covering.into_iter().chain(fallback).collect()
}

/// Sends one plan block of a single-file recovery fetch: RequestHashes
/// (base = the piece layer, proof = 0) -> the watcher awaits the reply ->
/// an event returns to the main loop (staging / retry decisions live in
/// the main-loop bookkeeping — the single-writer discipline). A send
/// failure (channel full / peer gone) does not set Requesting; the next
/// round retries.
pub(super) fn issue_recovery_fetch(
    face: &mut FaceState,
    fi: usize,
    file_idx: usize,
    rec: &mut FileRecovery,
    block: usize,
    peer_pos: usize,
) {
    if !matches!(rec.state, RecoveryFetchState::Missing) {
        return;
    }
    let Some(plan) = rec.staging.plans().get(block).copied() else {
        return;
    };
    let root = *rec.staging.root();
    let base = hash_fetch::piece_layer_level(rec.staging.piece_len());
    let Some(cuid) = face.peer_cuids.get(peer_pos).copied() else {
        return;
    };
    let (tx, rx) = oneshot::channel::<Result<HashFetch, taiji_bt::peer::HashRequestError>>();
    let sent = face.peers[peer_pos]
        .command(taiji_bt::peer::PeerCommand::RequestHashes {
            root,
            base,
            index: plan.index,
            length: plan.length,
            proof: 0,
            reply: tx,
        })
        .is_ok();
    if !sent {
        debug!(target: "taiji::core::engine", face = fi, file_index = file_idx,
            block, peer = peer_pos, "recovery fetch command dropped (peer gone/channel full)");
        return;
    }
    rec.state = RecoveryFetchState::Requesting { block, cuid };
    let evt_tx = face.fetch_tx.clone();
    tokio::spawn(async move {
        // The timeout lives in the watcher (same as lazy fetch;
        // HASH_FETCH_TIMEOUT is a local policy value).
        let reply = match tokio::time::timeout(HASH_FETCH_TIMEOUT, rx).await {
            Ok(Ok(Ok(fetch))) => Ok(fetch),
            Ok(Ok(Err(_))) => Err(RecoveryFetchFail::Busy),
            Ok(Err(_)) => Err(RecoveryFetchFail::Closed),
            Err(_) => Err(RecoveryFetchFail::Timeout),
        };
        let event = HashFetchEvent::Recovery { block, reply };
        let _ = evt_tx.send((fi, file_idx, event)).await;
    });
}

/// Recovery block-reply decision (main-loop single writer): staging
/// progress / failure retry bookkeeping; delivery progress is left to
/// [`drive_recovery`] (the caller drives it right after).
pub(super) fn handle_recovery_reply(
    fi: usize,
    book: &mut RecoveryBook,
    file_idx: usize,
    block: usize,
    reply: Result<HashFetch, RecoveryFetchFail>,
) {
    let Some(rec) = book.files.get_mut(&file_idx) else {
        return;
    };
    // Stale replies are dropped: only the currently in-flight block is
    // honored (defense against same-file re-sends / late-event races).
    let cuid = match &rec.state {
        RecoveryFetchState::Requesting { block: b, cuid, .. } if *b == block => *cuid,
        _ => {
            debug!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                block, "stale recovery reply dropped (block not in flight)");
            return;
        }
    };
    match reply {
        Ok(HashFetch::Hashes(hashes)) => match rec.staging.stage(block, &hashes) {
            Ok(StageOutcome::Staged { complete }) => {
                rec.attempts = 0;
                rec.tried.clear();
                rec.state = if complete {
                    info!(target: "taiji::core::engine", face = fi,
                        file_index = file_idx, blocks = rec.staging.block_count(),
                        "recovery piece layer fully staged; delivering to admission (C-2)");
                    RecoveryFetchState::Received
                } else {
                    RecoveryFetchState::Missing
                };
            }
            Ok(StageOutcome::Duplicate) => {
                // Duplicate/multi-source reply for the same block: first
                // arrival wins; treat the block as progressed (idempotent).
                rec.state = RecoveryFetchState::Missing;
            }
            Err(e) => {
                debug!(target: "taiji::core::engine", face = fi,
                    file_index = file_idx, block, error = ?e, "recovery reply not stageable");
                rec.note_failure(cuid);
            }
        },
        Ok(HashFetch::Rejected) => {
            debug!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                block, "recovery fetch rejected by peer");
            rec.note_failure(cuid);
        }
        Err(e) => {
            debug!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                block, fail = ?e, "recovery fetch failed");
            rec.note_failure(cuid);
        }
    }
    if rec.attempts == HASH_FETCH_MAX_ATTEMPTS {
        // Retries exhausted: no downgrade, no deletion — wait for a new
        // peer to connect (warn once; only later reply events can re-enter
        // this path).
        warn!(target: "taiji::core::engine", face = fi, file_index = file_idx,
            attempts = rec.attempts,
            "recovery retries exhausted; holding layer-missing state until a \
             fresh peer appears (BEP52 hash exchange optional on remote peers)");
    }
}

/// Recovery delivery progress (Received -> Delivered; a full channel or
/// absent receiver keeps Received — bounded backpressure, retried next
/// round, no drops, no blocking).
pub(super) fn try_deliver_recovery(
    fi: usize,
    file_idx: usize,
    rec: &mut FileRecovery,
    deliver: &mpsc::Sender<RecoveredPieceLayer>,
) {
    if !matches!(rec.state, RecoveryFetchState::Received) {
        return;
    }
    let Some(layer) = rec.staging.build_deliverable() else {
        return;
    };
    let pieces = layer.layer.len();
    match deliver.try_send(layer) {
        Ok(()) => {
            rec.staging.mark_delivered();
            rec.state = RecoveryFetchState::Delivered;
            info!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                pieces,
                "recovered piece layer delivered to admission seam (C-2)");
        }
        Err(e) => {
            debug!(target: "taiji::core::engine", face = fi, file_index = file_idx,
                error = %e, "recovery delivery pending (channel full or consumer absent); will retry");
        }
    }
}

/// The recovery driver round (trigger points: the 1s tick and post-reply
/// events): delivery progress + peer pick and next-block issue for Missing
/// files (at most 1 in flight per peer and per file — guaranteed naturally
/// by the bookkeeping: the state machine holds one request, plus the busy
/// set excludes across files).
pub(super) fn drive_recovery(
    face: &mut FaceState,
    fi: usize,
    book: &mut RecoveryBook,
    deliver: &mpsc::Sender<RecoveredPieceLayer>,
) {
    if book.files.is_empty() || face.completed || face.kind != FaceKind::V2 {
        return;
    }
    let mut busy: std::collections::HashSet<u64> = book
        .files
        .values()
        .filter_map(|r| match r.state {
            RecoveryFetchState::Requesting { cuid, .. } => Some(cuid),
            _ => None,
        })
        .collect();
    for (&file_idx, rec) in book.files.iter_mut() {
        match rec.state {
            RecoveryFetchState::Received => try_deliver_recovery(fi, file_idx, rec, deliver),
            RecoveryFetchState::Missing => {
                let lo = rec.piece_base;
                let hi = lo + rec.staging.pieces();
                // Coverage first + peer-switch memory exclusion (tried
                // carries the cooldown window; expired entries are pruned
                // on the spot = released for re-probing at expiry); if
                // every candidate sits in the effective memory but the
                // retry budget is not exhausted -> retrying tried peers is
                // allowed (bounded by the attempts cap, no retry storm);
                // budget exhausted -> wait for a new peer or cooldown
                // expiry (self-healing: no re-probing tried peers before
                // expiry, allowed after).
                let tried_now = active_tried(rec, Instant::now());
                let mut order = recovery_peer_order(face, lo, hi, &busy, &tried_now);
                if order.is_empty() && rec.attempts < HASH_FETCH_MAX_ATTEMPTS {
                    order =
                        recovery_peer_order(face, lo, hi, &busy, &std::collections::HashSet::new());
                }
                let Some(peer_pos) = order.first().copied() else {
                    continue;
                };
                let Some(block) = rec.staging.next_block() else {
                    // Defense: fully staged but still Missing (a lost-event
                    // window) -> promote.
                    rec.state = RecoveryFetchState::Received;
                    try_deliver_recovery(fi, file_idx, rec, deliver);
                    continue;
                };
                // In-round instant accounting (the driver-round guarantee
                // of at most 1 in flight per peer — later files this round
                // must not reuse the just-occupied peer).
                if let Some(cuid) = face.peer_cuids.get(peer_pos).copied() {
                    busy.insert(cuid);
                }
                issue_recovery_fetch(face, fi, file_idx, rec, block, peer_pos);
            }
            RecoveryFetchState::Requesting { .. } | RecoveryFetchState::Delivered => {}
        }
    }
}

/// The recovery reply-event arm body (the EngineLoop glue lives in
/// run::arms — EngineLoop's visibility domain; this function only makes
/// bookkeeping decisions).
pub(super) fn handle_recovery_reply_and_drive(
    fi: usize,
    face: &mut FaceState,
    book: &mut RecoveryBook,
    deliver: &mpsc::Sender<RecoveredPieceLayer>,
    file_idx: usize,
    block: usize,
    reply: Result<HashFetch, RecoveryFetchFail>,
) {
    handle_recovery_reply(fi, book, file_idx, block, reply);
    drive_recovery(face, fi, book, deliver);
}
/// Dispatch-reply drain entry: takes the [`FaceState`] receipt / in-flight
/// / refetch / piece-length bookkeeping and hands it to
/// [`drain_dispatch_replies_core`].
///
/// Kept as a wrapper by design: its single production caller is the top of
/// the [`dispatch_face_selected_with_stream`] dispatch round; the core
/// form's "decoupled from FaceState for unit testing" rationale holds —
/// engine::tests drive [`drain_dispatch_replies_core`] with bare
/// Vec/HashMap fixtures, not FaceState. The wrapper concentrates the four
/// disjoint production borrows in one place (keeping the dispatch-loop
/// call site single-line); the design accepts either keeping or inlining.
pub(super) fn drain_dispatch_replies(face: &mut FaceState) {
    drain_dispatch_replies_core(
        &mut face.dispatch_replies,
        &mut face.blocks_sent,
        &mut face.refetch,
        &face.piece_bytes,
    );
}

/// Reply-drain core (decoupled from FaceState for unit testing):
/// `try_recv` each enqueued request command's receipt —
///
/// - `Ok(())`: the request entered the peer's RequestBook -> the in-flight
/// mark is kept, converging on BlockSettled / piece settle;
/// - `WindowFull`: the peer's adaptive window was full and the request
/// **did not** enter its bookkeeping (the peer's RequestBook is the
/// single decision point) -> clear the in-flight mark immediately +
/// re-enter the refetch queue, so the next dispatch trigger refills per
/// the peer's current window (the aria2 supply semantics: `window -
/// outstanding` refill, `DefaultBtInteractive.cc`);
/// - `Duplicate`: the peer already holds the same slot (genuinely in
/// flight) -> keep the mark;
/// - `BadPieceId`/`Io`: keep the mark and let [`DISPATCH_REISSUE_WINDOW`]
/// backstop it; do not re-queue (deterministic errors get no retry
/// storm);
/// - Receipt side Closed (the peer task exited without replying) -> clear
/// the mark + re-enter the refetch queue (continue from another peer, no
/// 2s wait).
///
/// Unanswered (Empty) entries are kept as-is. No new per-request
/// allocations: the oneshot pairs and entry pushes reuse the allocations
/// made at dispatch time; the drain is pure `Vec` shuffling (lock-free).
pub(super) fn drain_dispatch_replies_core(
    replies: &mut Vec<DispatchReply>,
    blocks_sent: &mut std::collections::HashMap<u64, PieceSentLedger>,
    refetch: &mut Vec<(u32, u32, u32)>,
    piece_bytes: &[u64],
) {
    let pending = std::mem::take(replies);
    let mut requeue: Vec<(u32, u32, u32)> = Vec::new();
    for (piece, begin, mut rx) in pending {
        use tokio::sync::oneshot::error::TryRecvError;
        match rx.try_recv() {
            Err(TryRecvError::Empty) => {
                // The peer has not processed the command yet: keep waiting
                // for the receipt.
                replies.push((piece, begin, rx));
            }
            Err(TryRecvError::Closed) => {
                if let Some(ledger) = blocks_sent.get_mut(&piece) {
                    ledger.clear_slot(begin);
                    if ledger.all_clear() {
                        blocks_sent.remove(&piece);
                    }
                }
                if let Some(entry) = refetch_entry_for(piece_bytes, piece, begin) {
                    requeue.push(entry);
                }
            }
            Ok(Ok(())) => {}
            Ok(Err(taiji_bt::request_book::DispatchError::WindowFull { .. })) => {
                if let Some(ledger) = blocks_sent.get_mut(&piece) {
                    ledger.clear_slot(begin);
                    if ledger.all_clear() {
                        blocks_sent.remove(&piece);
                    }
                }
                if let Some(entry) = refetch_entry_for(piece_bytes, piece, begin) {
                    requeue.push(entry);
                }
            }
            Ok(Err(_)) => {}
        }
    }
    for (piece, begin, length) in requeue {
        let dup = refetch.iter().any(|(p, b, _)| *p == piece && *b == begin);
        if !dup {
            refetch.push((piece, begin, length));
        }
    }
}

/// The refetch entry for a (wire piece, begin) (length recomputed,
/// truncated to the piece's actual bytes; out-of-range defense).
pub(super) fn refetch_entry_for(
    piece_bytes: &[u64],
    piece: u64,
    begin: u32,
) -> Option<(u32, u32, u32)> {
    let piece_u32 = u32::try_from(piece).ok()?;
    let nbytes = piece_bytes.get(piece as usize).copied()?;
    let block = u64::from(merkle::BLOCK_SIZE);
    let length = nbytes.saturating_sub(u64::from(begin)).min(block).max(1) as u32;
    Some((piece_u32, begin, length))
}

// ---------------------------------------------------------------------------
// Two-phase in-flight bookkeeping: arrival transitions / metering pure
// functions (decision-table tests drive them directly)
// ---------------------------------------------------------------------------

/// Block-arrival transition (the arrival arm body, extracted; a pure test
/// surface with an injectable `now` clock): the block's bytes have entered
/// the store pipeline (emitted at the transit forwarding loop's successful
/// `block_tx.send`) = the network phase ends -> the store phase.
/// Rationale: arrival ends the phase — the peer's wire slot retired at
/// frame reception, so however slow the pipeline, resending the wire
/// request is pure waste (the peer re-reads disk and retransmits, and the
/// late copy lands in duplicate-drop). Reference: libtorrent marks
/// `mark_as_writing` as soon as a block is fully received (network phase
/// ends) and `mark_as_finished` on the write callback (store phase ends)
/// (`torrent.cpp`; the writing phase does not join reissue,
/// `piece_picker.hpp`).
///
/// Transition table (the arrival rows of the decision table):
/// - `InFlight` -> `Settling`;
/// - `InFlightDup` -> `SettlingDup` (the dup mark survives the phase
/// change — the sibling-cancel criterion, consumed by
/// `on_block_settled`);
/// - `Settling*` -> idempotent no-op (a repeat arrival keeps the first
/// arrival moment; the guard age takes the conservative reading —
/// approximated by the piece-level shared timestamp);
/// - `Buffered` (the out-of-order window where the confirmation beat the
/// arrival) / missing bookkeeping (the arrival event was not emitted
/// because the channel was full / the entry was already cleared by
/// piece settle) -> no-op.
///
/// Total-function discipline: arrival and confirmation travel separate
/// channels; any interleaving is harmless (a `Settling` row meeting
/// `BlockSettled` first goes straight to `Buffered` — the existing path,
/// unchanged).
pub(super) fn on_block_arrived(face: &mut FaceState, index: u32, begin: u32, now: Instant) {
    let Some(ledger) = face.blocks_sent.get_mut(&u64::from(index)) else {
        return;
    };
    ledger.arrive(begin);
    // `now` semantic anchor: under the piece-level time approximation this
    // parameter no longer lands in the ledger (the old row's
    // `Settling{at: now}` arrival moment is carried by the shared
    // `dispatched_at`, see the [`PieceSentLedger`] docs); the signature is
    // kept so the arrival-arm call face / injectable-clock test shape
    // stays unchanged.
    let _ = now;
}

/// Builds the dispatch spread's "claimed" set (extracted from the dispatch
/// round; a pure test surface — production goes through the
/// [`rebuild_claimed_into`] scratch in-place form, this returning entry is
/// test-driven only): a piece with any block still in a fresh network
/// phase = the piece is being fetched by some peer. Reading: only the
/// `InFlight` family counts (`Settling*`/`Buffered` do not claim — the
/// arrived piece's wire work has ended and the spread round does not yield
/// to it); the window is per-block adaptive ([`block_reissue_window`]
/// source) when `adaptive`, the fixed [`DISPATCH_REISSUE_WINDOW`] when off
/// (full-face revert = current behavior). Equivalence gate: with the
/// adaptive input window pinned at 2s this matches the old table
/// bit-for-bit (the same 2s equivalence lower bound as
/// [`endgame_inflight_copies`]'s window input). Freshness reads the
/// piece-level shared timestamp (approximation note in
/// [`PieceSentLedger`]).
#[cfg(test)]
pub(super) fn rebuild_claimed(face: &FaceState, now: Instant, adaptive: bool) -> ClaimedSet {
    let mut claimed = ClaimedSet::with_len(face.piece_count);
    rebuild_claimed_into(face, now, adaptive, &mut claimed);
    claimed
}

/// The in-place fill form of [`rebuild_claimed`] (dispatch-round scratch
/// reuse: the caller `reset`s and passes a resident [`ClaimedSet`];
/// verdicts identical to the returning form — [`rebuild_claimed`] remains
/// as the test-driven face).
pub(super) fn rebuild_claimed_into(
    face: &FaceState,
    now: Instant,
    adaptive: bool,
    claimed: &mut ClaimedSet,
) {
    for (&piece, ledger) in face.blocks_sent.iter() {
        let fresh = ledger
            .slots()
            .iter()
            .enumerate()
            .any(|(bi, slot)| match slot.state {
                BlockState::InFlight | BlockState::InFlightDup => {
                    let begin = (bi as u64 * u64::from(merkle::BLOCK_SIZE)) as u32;
                    let window = if adaptive {
                        block_reissue_window(face, piece, begin)
                    } else {
                        DISPATCH_REISSUE_WINDOW
                    };
                    now.duration_since(ledger.dispatched_at()) < window
                }
                _ => false,
            });
        if fresh {
            claimed.mark_claimed(piece);
        }
    }
}

/// Per-peer fresh in-flight block count (the input build face of the busy
/// eligibility gate 2, extracted from the dispatch round; a pure test
/// surface — see [`endgame_busy_admitted`]). Ownership = the in-row owner
/// (formerly `block_dispatch`; the owner IS the peer_cuids index, mapped
/// to cuid in the table). Reading: only the network phase counts (the
/// `InFlight` family — `Settling*` = arrived, occupying no peer in-flight
/// account); the fresh window switches with `adaptive` (on = per-block
/// adaptive [`block_reissue_window`]; off = the fixed
/// [`DISPATCH_REISSUE_WINDOW`] single-state reading). Blocks without
/// bookkeeping (no owner / peer gone) do not count — the same conservative
/// direction as the candidate filter's "never resend when ownership cannot
/// be confirmed".
#[cfg(test)]
pub(super) fn endgame_peer_inflight(
    face: &FaceState,
    now: Instant,
    adaptive: bool,
) -> std::collections::HashMap<u64, u64> {
    let mut m: std::collections::HashMap<u64, u64> = Default::default();
    fill_endgame_peer_inflight(face, now, adaptive, &mut m);
    m
}

/// The in-place fill form of [`endgame_peer_inflight`] (dispatch-round
/// scratch reuse: the caller clears and passes a resident table — verdicts
/// identical to the returning form; the returning entry remains as the
/// test-driven face).
pub(super) fn fill_endgame_peer_inflight(
    face: &FaceState,
    now: Instant,
    adaptive: bool,
    m: &mut std::collections::HashMap<u64, u64>,
) {
    for (&piece, ledger) in face.blocks_sent.iter() {
        for (bi, slot) in ledger.slots().iter().enumerate() {
            let fresh = match slot.state {
                BlockState::InFlight | BlockState::InFlightDup => {
                    let begin = (bi as u64 * u64::from(merkle::BLOCK_SIZE)) as u32;
                    let window = if adaptive {
                        block_reissue_window(face, piece, begin)
                    } else {
                        DISPATCH_REISSUE_WINDOW
                    };
                    now.duration_since(ledger.dispatched_at()) < window
                }
                _ => false,
            };
            if fresh
                && let Some(owner) = ledger_owner(slot)
                && let Some(&cuid) = face.peer_cuids.get(owner as usize)
            {
                *m.entry(cuid).or_insert(0) += 1;
            }
        }
    }
}

/// Per-peer busy-piece count (the input build face of the d tiered gate
/// [`endgame_busy_admitted_tiered`], extracted from the dispatch round; a
/// pure test surface): the number of **distinct pieces** on which the peer
/// currently holds fresh in-flight blocks — the same ownership face
/// (in-row owner) and fresh reading (network phase + the
/// [`two_phase_ledger`] window switch) as [`endgame_peer_inflight`] (the
/// block count); the count granularity = pieces (the local dispatch
/// allocation granularity: several blocks of one piece count 1; when a
/// reissue takeover splits ownership, each owner counts the piece — the
/// same single-owner-per-coordinate approximation as
/// [`endgame_busy_admitted`]'s divergence note). The zero value is
/// equivalent to the block count (no fresh in-flight blocks ⟺ no busy
/// pieces) — the K=0 fallback arm does not build this table (the old gate
/// consumes only the block count's zero check).
#[cfg(test)]
pub(super) fn endgame_peer_busy_pieces(
    face: &FaceState,
    now: Instant,
    adaptive: bool,
) -> std::collections::HashMap<u64, u64> {
    let mut m: std::collections::HashMap<u64, u64> = Default::default();
    fill_endgame_peer_busy_pieces(face, now, adaptive, &mut m);
    m
}

/// The in-place fill form of [`endgame_peer_busy_pieces`] (dispatch-round
/// scratch reuse; verdicts identical to the returning form, which remains
/// as the test-driven face).
pub(super) fn fill_endgame_peer_busy_pieces(
    face: &FaceState,
    now: Instant,
    adaptive: bool,
    m: &mut std::collections::HashMap<u64, u64>,
) {
    for (&piece, ledger) in face.blocks_sent.iter() {
        let mut holders: Vec<u64> = Vec::new();
        for (bi, slot) in ledger.slots().iter().enumerate() {
            let fresh = match slot.state {
                BlockState::InFlight | BlockState::InFlightDup => {
                    let begin = (bi as u64 * u64::from(merkle::BLOCK_SIZE)) as u32;
                    let window = if adaptive {
                        block_reissue_window(face, piece, begin)
                    } else {
                        DISPATCH_REISSUE_WINDOW
                    };
                    now.duration_since(ledger.dispatched_at()) < window
                }
                _ => false,
            };
            if fresh
                && let Some(owner) = ledger_owner(slot)
                && let Some(&cuid) = face.peer_cuids.get(owner as usize)
                && !holders.contains(&cuid)
            {
                holders.push(cuid);
            }
        }
        for cuid in holders {
            *m.entry(cuid).or_insert(0) += 1;
        }
    }
}

/// Slot owner reading (unwraps the [`BlockSlot::owner`] sentinel —
/// None = unowned).
fn ledger_owner(slot: &BlockSlot) -> Option<u32> {
    (slot.owner != NO_OWNER).then_some(slot.owner)
}

/// The piece-level adaptive window upper bound (the x2 metering freshness
/// input; the metering-face switch): the maximum adaptive reissue window
/// across the piece's dispatched blocks ([`block_reissue_window`] source;
/// ownerless blocks contribute the 2s floor) — taking the max gives a slow
/// peer's piece the most conservative freshness reading (the claim duration
/// <= the piece's download duration). `adaptive = false` (knob off) is
/// always [`DISPATCH_REISSUE_WINDOW`] (full-face revert).
pub(super) fn piece_reissue_window_max(face: &FaceState, piece: u64, adaptive: bool) -> Duration {
    if !adaptive {
        return DISPATCH_REISSUE_WINDOW;
    }
    let block = u64::from(merkle::BLOCK_SIZE);
    let nbytes = face
        .piece_bytes
        .get(piece as usize)
        .copied()
        .unwrap_or(block);
    let blocks = nbytes.div_ceil(block).max(1);
    let mut w = DISPATCH_REISSUE_WINDOW;
    for bi in 0..blocks {
        w = w.max(block_reissue_window(face, piece, (bi * block) as u32));
    }
    w
}

/// The store-phase guard scan (fed by the 1s seed tick; a pure test
/// surface): returns the count and max age of `Settling*` entries past
/// [`STORE_PENDING_GUARD`] (the warn + count input; O(in-flight entries),
/// bounded — the entry bound is <= the in-flight piece blocks, clamped by
/// the write-cache capacity). The action is warn + count only: zero new
/// wire traffic, never a resend (reissue decisions consult only the
/// network phase); the claim/checkout was already released at arrival
/// ([`own_piece_continuable`]). The guard age reads the piece-level shared
/// timestamp approximately (the [`PieceSentLedger`] docs note — it only
/// shifts when the warning/count fires, no wire face).
pub(super) fn store_pending_guard_scan(face: &FaceState, now: Instant) -> (u64, Duration) {
    let mut overdue = 0u64;
    let mut worst = Duration::ZERO;
    for ledger in face.blocks_sent.values() {
        let any_settling = ledger
            .slots()
            .iter()
            .any(|s| matches!(s.state, BlockState::Settling | BlockState::SettlingDup));
        if !any_settling {
            continue;
        }
        let age = now.duration_since(ledger.dispatched_at());
        if age > STORE_PENDING_GUARD {
            overdue += ledger
                .slots()
                .iter()
                .filter(|s| matches!(s.state, BlockState::Settling | BlockState::SettlingDup))
                .count() as u64;
            worst = worst.max(age);
        }
    }
    (overdue, worst)
}

/// Dispatch (advertisement-aware): **requests are sent only for pieces the
/// peer has advertised** ([`select_advertised_piece`]; candidates = the
/// peer's advertised bitmap ∩ locally unfinished); missing bitmap evidence
/// or no selectable piece in the advertised set -> zero requests to that
/// peer. The requested block count is truncated to the piece's actual byte
/// length (a v2 last piece < piece_len: an out-of-range request would be
/// rejected by the peer, or worse served out-of-range data).
///
/// Gating: when the selected piece's file leaf layer is not ready on a v2
/// face —
/// - Queued -> issue the lazy-fetch plan block to that peer; no blocks
/// dispatch this tick;
/// - Pending -> wait for the reply (lazy fetch is RTT-scale; block
/// dispatch defers one tick);
/// - Done / Failed -> dispatch normally (Failed = the whole-piece buffered
/// fallback, warned on entry).
///
/// Wiring: the round first drains dispatch replies
/// ([`drain_dispatch_replies`]) — a peer's `WindowFull` request has its
/// in-flight mark cleared and re-enters the refetch queue on the spot, so
/// request supply refills in step with the peer's target window (BDP
/// rate-driven: the PeerTask side recomputes on each sample; the fallback
/// mode uses the doubling heuristic). Call triggers = store-pipeline
/// confirmations (BlockSettled / PieceVerified / BlockRejected /
/// PieceDropped) + peer registration + HAVE/bitfield advertisement events
/// (dispatch on advertisement arrival, not waiting for the 1s tick) + the
/// 1s tick backstop (the aria2 semantics: `addRequests` refill after each
/// round's receives, `DefaultBtInteractive.cc`).
///
/// BEP 53 select-file: selected file indexes -> a flat piece mask (the
/// engine-side projection of SetFileSelection). The mask must be
/// isomorphic to the **flat piece space of the face consuming it**; two
/// projections, dispatched by layout kind —
///
/// - **Index reading** (both faces): the client file list order = the
/// layout's **non-padding entry** order (0-based, BEP 53 "Files are
/// zero-indexed"; padding is a transport placeholder, not a file —
/// BEP 47). Out-of-range indexes / an empty selection = Err (by design:
/// illegal input is rejected explicitly, never silently ignored — an
/// empty selection would mean zero dispatch and zero completion, so
/// refusing is the honest form).
/// - **v2-only (V2Compact layout)**: the face's flat piece space = the
/// cursor expansion of per-file `pieces_f = ceil(len_f/piece_len)` (the
/// same walk as `session/recheck.rs` `encode_v2_file_bits` /
/// `verify_face`; BEP 52 piece addressing = `(file_index,
/// piece_in_file)`) — a selected file -> its flat segment all-1,
/// unselected -> 0; mask length = the face's piece count = sum of
/// pieces_f. The old implementation flattened by the byte grid
/// `ceil(total/piece_len)`: misaligned when file boundaries were not
/// piece-aligned (wrong pieces selected/unselected + mask length != the
/// face's piece count — half of enforcing "no global piece index
/// assumptions").
/// - **v1/hybrid (V1Padded layout)**: the face's flat piece space = the
/// contiguous piece stream over the layout range (the byte grid); the
/// projection rule = a piece's byte range `[k·pL, (k+1)·pL)` is selected
/// when it intersects any selected real file's range (under
/// piece-granularity download semantics, cross-file pieces must be
/// fetched whole). On the pad-aligned face (BEP 47), file starts are
/// piece-aligned so this reading is always bit-identical to the cursor
/// projection (regression lock
/// `selection_mask_v1_padded_face_bit_equivalence_lock` in engine::tests);
/// this branch's code is unchanged.
pub(super) fn selection_mask(
    layout: &Layout,
    piece_len: u32,
    files: &[u32],
) -> Result<Vec<bool>, String> {
    if files.is_empty() {
        return Err("empty file selection".into());
    }
    let selected: std::collections::BTreeSet<u32> = files.iter().copied().collect();
    // Non-padding entry order = the client file list (the BEP 53 index
    // anchor); an out-of-range index = an explicit error (both faces, same
    // semantics, before any projection decision).
    let real_count = layout.files().iter().filter(|f| !f.padding).count() as u32;
    if let Some(bad) = selected.iter().find(|&&f| f >= real_count) {
        return Err(format!(
            "file index {bad} out of range ({real_count} files)"
        ));
    }
    match layout.kind() {
        // v2-only: the face-plan cursor projection (segments of sum
        // ceil(len_f/piece_len)).
        taiji_store::layout::LayoutKind::V2Compact => {
            let mut mask: Vec<bool> = Vec::new();
            for (i, f) in layout.files().iter().filter(|f| !f.padding).enumerate() {
                let pieces = f.length.div_ceil(u64::from(piece_len)) as usize;
                let on = selected.contains(&(i as u32));
                mask.extend(std::iter::repeat_n(on, pieces));
            }
            Ok(mask)
        }
        // v1/hybrid: byte-grid intersection projection (existing behavior,
        // bit-equivalence locked).
        taiji_store::layout::LayoutKind::V1Padded => {
            let mut real: Vec<(u64, u64)> = Vec::new();
            let mut idx = 0u32;
            for f in layout.files() {
                if f.padding {
                    continue;
                }
                if selected.contains(&idx) {
                    real.push((f.offset, f.offset + f.length));
                }
                idx += 1;
            }
            let piece_count = if layout.total() == 0 {
                0usize
            } else {
                layout.total().div_ceil(u64::from(piece_len)) as usize
            };
            let mut mask = vec![false; piece_count];
            for (i, slot) in mask.iter_mut().enumerate() {
                let lo = i as u64 * u64::from(piece_len);
                let hi = lo.saturating_add(u64::from(piece_len));
                *slot = real.iter().any(|&(start, end)| start < hi && lo < end);
            }
            Ok(mask)
        }
        // Forward-compat (LayoutKind is #[non_exhaustive]): an unknown
        // future layout kind fails explicitly - never a silent projection
        // onto a known face.
        _ => Err("unknown layout kind".into()),
    }
}
/// File multi-level priority -> a flat piece-level table projection (the
/// level-valued variant of [`selection_mask`]; the index reading and
/// per-face walks follow it exactly):
/// - input `prio` = client file index (0-based non-padding order) -> level
/// (-1 skip / 0 normal / 1..7 high) pairs; unlisted files default to 0.
/// An empty table = Err (the same verdict as an empty selection — the
/// caller fails explicitly);
/// - **v2-only**: each file's cursor segment takes that file's level whole
/// (piece addressing (file_index, piece_in_file) has no cross-file
/// pieces);
/// - **v1/hybrid**: when a piece's byte range intersects several real
/// files, take the **highest level among the intersecting files** (under
/// piece-granularity download semantics cross-file pieces are fetched
/// whole — the strongest demand is served first; -1 does not join the
/// max: the skip face is already invisible to the selector via the
/// selection_mask -> done folding, and -1 segments here exist only for
/// mirror consistency);
/// - consumer: the selection key (priority desc, count asc) (the `prio`
/// arm of `select`/`select_two_phase`); endgame/allowed-fast do not
/// consume it.
pub(super) fn priority_mask(
    layout: &Layout,
    piece_len: u32,
    prio: &[(u32, i8)],
) -> Result<Vec<i8>, String> {
    if prio.is_empty() {
        return Err("empty file priority table".into());
    }
    let table: std::collections::BTreeMap<u32, i8> = prio.iter().copied().collect();
    let real_count = layout.files().iter().filter(|f| !f.padding).count() as u32;
    if let Some(&bad) = table.keys().find(|&&f| f >= real_count) {
        return Err(format!(
            "file index {bad} out of range ({real_count} files)"
        ));
    }
    if let Some(&bad) = table.values().find(|&&q| !(-1..=7).contains(&q)) {
        return Err(format!("file priority {bad} out of range (-1..=7)"));
    }
    let level_of = |idx: u32| table.get(&idx).copied().unwrap_or(0);
    match layout.kind() {
        // v2-only: the face-plan cursor projection (segments of sum
        // ceil(len_f/piece_len)).
        taiji_store::layout::LayoutKind::V2Compact => {
            let mut mask: Vec<i8> = Vec::new();
            for (i, f) in layout.files().iter().filter(|f| !f.padding).enumerate() {
                let pieces = f.length.div_ceil(u64::from(piece_len)) as usize;
                mask.extend(std::iter::repeat_n(level_of(i as u32), pieces));
            }
            Ok(mask)
        }
        // v1/hybrid: byte-grid intersection takes the highest level
        // (0..7; -1 does not join the max).
        taiji_store::layout::LayoutKind::V1Padded => {
            let mut spans: Vec<(u64, u64, i8)> = Vec::new();
            let mut idx = 0u32;
            for f in layout.files() {
                if f.padding {
                    continue;
                }
                let q = level_of(idx);
                if q > 0 {
                    spans.push((f.offset, f.offset + f.length, q));
                }
                idx += 1;
            }
            let piece_count = if layout.total() == 0 {
                0usize
            } else {
                layout.total().div_ceil(u64::from(piece_len)) as usize
            };
            let mut mask = vec![0i8; piece_count];
            for (i, slot) in mask.iter_mut().enumerate() {
                let lo = i as u64 * u64::from(piece_len);
                let hi = lo.saturating_add(u64::from(piece_len));
                *slot = spans
                    .iter()
                    .filter(|&&(start, end, _)| start < hi && lo < end)
                    .map(|&(_, _, q)| q)
                    .max()
                    .unwrap_or(0);
            }
            Ok(mask)
        }
        // Forward-compat (LayoutKind is #[non_exhaustive]): an unknown
        // future layout kind fails explicitly - never a silent projection
        // onto a known face.
        _ => Err("unknown layout kind".into()),
    }
}
/// Dispatch-round scratch (resident transient-buffer reuse): the buffers
/// discarded and rebuilt at the top of every dispatch round — the done
/// bitmap, the [`ClaimedSet`] inner bitmap, the endgame aux tables
/// (round_copies / per-peer in-flight / busy-piece counts / the last-mile
/// copy-cap table) and the partial-piece tables — merged into this struct,
/// resident in [`FaceState::dispatch_scratch`]: the round takes it out
/// with `std::mem::take` at entry and puts it back whole at the end, each
/// buffer cleared then reused (**capacity grow-only**: after the first
/// allocation later rounds are zero-alloc).
///
/// Why take/put-back rather than `RefCell` + `RefMut`: inside the peer
/// loop, `issue_piece_blocks`/`supply_adjacent_pieces`/`parole_pick_piece`
/// all take `&mut FaceState`, which conflicts with a live RefMut (nested
/// calls) — move-out/move-back is the design's "pass it as an argument"
/// fallback: the scratch is function-local and never overlaps `face`'s
/// mutable borrow. The dispatch path is single-writer (the engine main
/// loop calls `dispatch_face*` sequentially), no concurrency; a panic
/// mid-round = an engine-face fault (losing the scratch only costs the
/// reuse capacity, no semantic face).
#[derive(Default)]
pub(super) struct DispatchScratch {
    /// The dispatch done bitmap (the three-source fold: complete / outside
    /// the mask / layer-gated; read-only within the round).
    pub(super) done: Vec<bool>,
    /// The spread claim set (rebuilt in place by
    /// [`rebuild_claimed_into`]; in-round instant claims write into it).
    pub(super) claimed: ClaimedSet,
    /// The endgame rarity-ascending missing-piece table (the cursor pick
    /// input; empty in non-endgame rounds).
    pub(super) endgame_pieces: Vec<u64>,
    /// The partial hard gate's measured partial-piece table (the
    /// `partial_preferred` build input).
    pub(super) partial_pieces: Vec<u64>,
    /// The partial-gate round's partial-piece priority table (empty in
    /// non-gate rounds).
    pub(super) partial_preferred: Vec<u64>,
    /// The endgame in-round copy counts (the x2 discipline; always empty
    /// outside endgame).
    pub(super) round_copies: std::collections::HashMap<u64, u64>,
    /// The last-mile wide-fan-out copy-cap table (holder count,
    /// relax-only; empty outside last-mile).
    pub(super) lastmile_copies_limit: std::collections::HashMap<u64, u64>,
    /// Per-peer fresh in-flight block counts (the K=0 arm's busy-gate
    /// input; empty in rounds that skip building it).
    pub(super) endgame_peer_inflight: std::collections::HashMap<u64, u64>,
    /// Per-peer busy-piece counts (the d tiered-gate input; empty in
    /// rounds that skip building it).
    pub(super) endgame_busy_pieces: std::collections::HashMap<u64, u64>,
    /// The endgame-tail missing-piece table (empty outside the
    /// tail): the holder-scan input for the window-floor write pass and
    /// the deadline seeding sweep.
    pub(super) endgame_tail_pieces: Vec<u64>,
    /// This round's overdue pieces (tail deadline expired):
    /// their whole network-phase in-flight set becomes takeover
    /// candidates (the freshness bypass). Empty when the deadline face is
    /// off / no piece is overdue.
    pub(super) endgame_overdue: std::collections::HashSet<u64>,
    /// Pieces already overdue-dispatched this round (the
    /// one-shot-per-round stampede guard: after the first holder's
    /// bypass dispatch re-arms the shared timestamp, later peers in the
    /// same round fall back to the normal freshness rules for the piece).
    pub(super) endgame_overdue_done: std::collections::HashSet<u64>,
}

impl DispatchScratch {
    /// Clears every buffer in place (called at round entry; capacity is
    /// resident — clear does not free the heap, Vec/HashMap lengths drop
    /// to zero and the next fill is zero-alloc).
    pub(super) fn clear(&mut self) {
        self.done.clear();
        self.claimed.reset(0);
        self.endgame_pieces.clear();
        self.partial_pieces.clear();
        self.partial_preferred.clear();
        self.round_copies.clear();
        self.lastmile_copies_limit.clear();
        self.endgame_peer_inflight.clear();
        self.endgame_busy_pieces.clear();
        self.endgame_tail_pieces.clear();
        self.endgame_overdue.clear();
        self.endgame_overdue_done.clear();
    }
}

/// Dispatch with the full selection (the existing unit-test call face; a
/// None mask = unchanged semantics — the prior behavior).
#[cfg(test)]
pub(super) fn dispatch_face(face: &mut FaceState, fi: usize) {
    dispatch_face_selected(face, fi, None, &RarestFirstStrategy);
}

/// The existing 4-argument dispatch form (the engine tests'
/// strategy-injection face; playhead/priority = None — streaming and
/// priority semantics go through the full form).
#[cfg(test)]
pub(super) fn dispatch_face_selected(
    face: &mut FaceState,
    fi: usize,
    mask: Option<&[bool]>,
    strategy: &dyn PieceSelectionStrategy,
) {
    dispatch_face_selected_with_stream(face, fi, mask, strategy, None, None);
}

/// The BEP 53 select-file dispatch face: `mask` = the flat piece selection
/// mask (None = all selected). Unselected pieces fold into the done bitmap
/// — the selectors (advertisement-aware / spread round) never hit them
/// ("dispatch only the selected"); v2 lazy fetch triggers only for
/// selected pieces, no extra gate needed. Unit tests and existing call
/// sites go through [`dispatch_face`] (None = unchanged semantics).
///
/// `strategy` = the current scheduling strategy object (atomically
/// replaced inside the single-writer engine loop via `SetSchedulerPolicy`;
/// default = [`RarestFirstStrategy`] = the port, unchanged behavior).
/// Switching only affects selection decisions from this round on;
/// in-flight bookkeeping / the refetch queue / the claim set are
/// strategy-independent and not cleared on switch.
///
/// `stream` = the playhead + streaming geometry (maintained by the engine
/// command `SetStreamingPlayhead`; None = no playhead). The dispatch round
/// builds the bounded priority graph once ([`stream_ctx_for`], shared by
/// all peers) and injects it via [`SelectionCtx::stream`]; non-streaming
/// strategies ignore the input (unchanged behavior).
///
/// `prio` = the file multi-level priority piece table (maintained by the
/// engine command `SetFilePriority`, projected by [`priority_mask`]; None
/// = the default all-0 face, selection verdicts unchanged). Injected via
/// [`SelectionCtx::priority`] — consumption is per-strategy (rarest_first:
/// the primary key ahead of rarity; streaming: outside the window only;
/// sequential: reserved layered-order semantics for the unimplemented
/// face).
pub(super) fn dispatch_face_selected_with_stream(
    face: &mut FaceState,
    fi: usize,
    mask: Option<&[bool]>,
    strategy: &dyn PieceSelectionStrategy,
    stream: Option<&StreamPlan>,
    prio: Option<&[i8]>,
) {
    if face.completed {
        return;
    }
    // The playhead priority graph (once per round; bounded entries —
    // capped by the window byte limit).
    let stream_ctx =
        stream.and_then(|p| stream_ctx_for(&p.playhead, &p.geo, face.piece_count as u64));
    // Dispatch-reply drain runs before the refetch queue — a block freed
    // by WindowFull can re-dispatch within this very call.
    drain_dispatch_replies(face);
    // Single-block refetch precedes regular dispatch: only the rejected
    // 16KiB is refetched.
    let mut still_waiting = Vec::new();
    let reqs = std::mem::take(&mut face.refetch);
    for (piece, begin, length) in reqs {
        // Root-cause fix (the refetch x completion-bookkeeping divergence
        // loop): a refetch entry whose piece is already locally verified is
        // **voided in place** — the data is complete, so a resend only buys
        // duplicate service from the peer plus the pipeline's silent "late
        // block for verified piece" drop (no event convergence; the entry
        // would re-queue forever through the WindowFull/Closed receipts).
        // BEP 6 semantics unchanged: a rejected-block refetch
        // (BlockRejected) only arises for unsettled pieces; a late refetch
        // entry for a settled piece is pure stale bookkeeping, and voiding
        // it restores the invariant.
        if face.progress.piece_done_global(u64::from(piece)) {
            debug!(target: "taiji::core::engine", face = fi, piece, begin,
                "stale refetch for locally verified piece: discarded");
            continue;
        }
        // Pick point (advertisement-aware): only to a peer currently
        // advertising the piece. The old fallback
        // `or(if face.peers.is_empty() { None } else { Some(0) })` is
        // removed too — the old note "the rejected block came from that
        // peer, so its holding is given" does not hold under
        // advertisement-aware semantics (the original request may itself
        // have been a blind send); the re-dispatch target must lie inside
        // the current advertised bitmap. No connected peer advertising the
        // piece -> stay queued (new-peer registration / HAVE / bitfield
        // events trigger a re-dispatch; waiting != disconnecting).
        let target = peer_with_piece(face, u64::from(piece));
        match target {
            Some(peer_pos) => {
                let Some(id) = face.addressing.from_wire(piece) else {
                    debug!(target: "taiji::core::engine", piece, "refetch piece outside addressing");
                    continue;
                };
                let (file_index, piece_in_file, blk) = face
                    .flat_coords
                    .get(piece as usize)
                    .map(|(f, p)| (*f, *p, begin / merkle::BLOCK_SIZE))
                    .unwrap_or((u32::MAX, u32::MAX, 0));
                let (tx, rx) = tokio::sync::oneshot::channel();
                let queued = face.peers[peer_pos]
                    .command(taiji_bt::peer::PeerCommand::RequestPiece {
                        id,
                        begin,
                        length,
                        reply: tx,
                    })
                    .is_ok();
                if queued {
                    debug!(target: "taiji::core::engine", face = fi, file_index,
                        piece_in_file, block = blk, begin, length,
                        "re-fetch request sent (single 16KiB block)");
                    // In-flight bookkeeping + receipt tracking: only an
                    // enqueued request is marked in flight (a WindowFull
                    // receipt clears the mark and re-queues at the next
                    // trigger). In-row single write: state + owner (the
                    // peer_cuids index, replacing the block_dispatch global
                    // table) + one piece-level timestamp refresh.
                    let at = Instant::now();
                    let row_blocks = face
                        .piece_bytes
                        .get(piece as usize)
                        .copied()
                        .unwrap_or(u64::from(merkle::BLOCK_SIZE))
                        .div_ceil(u64::from(merkle::BLOCK_SIZE))
                        .max(1) as usize;
                    let owner = face.peer_cuids.get(peer_pos).map(|_| peer_pos as u32);
                    face.blocks_sent
                        .entry(u64::from(piece))
                        .or_insert_with(|| PieceSentLedger::new(row_blocks, at))
                        .set_inflight(begin, owner, at);
                    face.dispatch_replies.push((u64::from(piece), begin, rx));
                } else {
                    // Channel full / peer gone: not enqueued = not marked
                    // in flight; stays queued for the next trigger
                    // (previously it was unconditionally phantom-marked and
                    // idled out the 2s reissue window).
                    still_waiting.push((piece, begin, length));
                }
            }
            None => still_waiting.push((piece, begin, length)),
        }
    }
    face.refetch = still_waiting;
    if face.progress.first_incomplete_global().is_none() {
        return;
    };
    let block = u64::from(merkle::BLOCK_SIZE);
    let count = face.piece_count as u64;
    // Materialize the bitmap first (avoids overlapping mutable/immutable
    // borrows of the same struct); pieces false in the mask fold into done
    // = invisible to the selector (the select-file "dispatch only the
    // selected" semantics, BEP 53). Layer-gated pieces of files not yet
    // promoted (the lazy-fetch layer Pending — the pre-admission gated
    // state) fold into done as well — invisible to the selector, dispatch
    // forbidden until the layer lands. libtorrent anchor: a missing-layer
    // torrent still loads and connects, but `we_have` is only set after
    // the hash check passes and the advertisement/request faces see only
    // verified pieces — the structural equivalent of torrent.cpp's
    // "finished but not hash checked" pending-verification state (a
    // placeholder root cannot verify; the dispatch-face fold plus
    // Pending => continue are the two guards). The fold lets the strategy
    // face keep supplying all other pieces normally (never funneled into
    // repeatedly hitting the missing-layer rare piece); once promoted
    // (Queued) the piece naturally rejoins the candidate set.
    let layer_gated = |i: u64| -> bool {
        face.flat_coords
            .get(i as usize)
            .and_then(|(f, _)| face.layers.get(*f as usize))
            .is_some_and(|l| matches!(l.state, LayerFetchState::Pending))
    };
    // Dispatch-round scratch reuse: the round's transient buffers
    // (done/claimed bitmaps + endgame aux tables + partial-piece tables)
    // take out of the resident pool and fill after clear — capacity
    // grow-only, zero-alloc after the first round (this function has no
    // early return before the end of the round, so the scratch is always
    // put back; see the [`DispatchScratch`] docs for the shape).
    let mut scratch = std::mem::take(&mut face.dispatch_scratch);
    scratch.clear();
    // Materialize the bitmap first (avoids overlapping mutable/immutable
    // borrows of the same struct); pieces false in the mask fold into done
    // = invisible to the selector (the select-file "dispatch only the
    // selected" semantics, BEP 53).
    scratch.done.resize(count as usize, false);
    for (i, slot) in scratch.done.iter_mut().enumerate() {
        *slot = face.progress.piece_done_global(i as u64)
            || mask.is_some_and(|m| !m.get(i).copied().unwrap_or(false))
            || layer_gated(i as u64);
    }
    let done: &Vec<bool> = &scratch.done;
    // The dispatch spread's "claimed" set (dense-bitmap form, type
    // semantics in [`ClaimedSet`]; build = one full pass over `blocks_sent`,
    // queries are bit reads): a piece with any InFlight block not past its
    // reissue window is being fetched by some peer. Spread-round selection
    // skips such pieces (the source in [`select_advertised_piece_spread`]),
    // so each peer claims a **different** piece — otherwise
    // deterministic-order selection funnels every connected peer onto the
    // same piece and a single connection's throttle becomes the aggregate
    // cap. Switching: the build delegates to [`rebuild_claimed_into`]
    // (only fresh network-phase blocks count; the window switches with
    // [`two_phase_ledger`] — on = per-block adaptive, off = the fixed 2s
    // current behavior); the bitmap is rebuilt in place (`reset` keeps
    // capacity).
    let two_phase = two_phase_ledger();
    let claims_now = Instant::now();
    scratch.claimed.reset(face.piece_count);
    rebuild_claimed_into(face, claims_now, two_phase, &mut scratch.claimed);
    let claimed = &mut scratch.claimed;
    // Partial hard-gate metering (a separate pass — it only counts rows,
    // never reads the state machine; the claimed build was extracted into
    // [`rebuild_claimed_into`]; the reference is the num_partials gate at
    // the `piece_picker.cpp` pick_pieces entry): a partial piece = a
    // blocks_sent row not covering all of the piece's blocks. The gate =
    // partial piece count > connected peers x 3/2 OR partial block total
    // > [`PARTIAL_BLOCK_GATE`].
    let mut num_partials = 0u64;
    let mut partial_blocks_total = 0u64;
    let partial_pieces: &mut Vec<u64> = &mut scratch.partial_pieces;
    for (&piece, ledger) in face.blocks_sent.iter() {
        let total = face
            .piece_bytes
            .get(piece as usize)
            .copied()
            .unwrap_or(block)
            .div_ceil(block)
            .max(1);
        if (ledger.tracked_count() as u64) < total {
            num_partials += 1;
            partial_blocks_total += total;
            partial_pieces.push(piece);
        }
    }
    let partial_gate =
        partial_gate_triggered(num_partials, face.peers.len() as u64, partial_blocks_total);
    // Adaptive full-endgame trigger (recomputed statelessly each dispatch
    // round, the source in [`endgame_triggered`]): the in-flight piece set
    // = claimed (pieces holding fresh InFlight blocks; an unverified piece
    // whose blocks are all Buffered does not count — the bytes are local,
    // duplicate requests are meaningless; a fine divergence from
    // libtorrent's download queue, whose finished/writing blocks stay
    // queued — the local reading makes the endgame trigger slightly
    // conservative). Once triggered, missing pieces are requested from
    // **all** peers holding them (the selection face = the claimed input
    // blanked below); controlled duplication is provided by the x2 gate
    // plus the block-level one-hop duplicate permission; a duplicate
    // block's arrival is absorbed by the covers check (the store's
    // verified::buffer_block coverage check -> benign drop counted by
    // note_duplicate_drop).
    // Missing-piece count and missing bytes: merged into one pass — the
    // old missing_pieces O(N) pass plus the endgame ETA's missing_bytes
    // O(N) pass collapse into a single side accumulation after `done` is
    // built (values identical to the two-pass version).
    let mut missing_pieces = 0u64;
    let mut missing_bytes = 0u64;
    for (i, &d) in done.iter().enumerate() {
        if !d {
            missing_pieces += 1;
            missing_bytes += face.piece_bytes.get(i).copied().unwrap_or(block);
        }
    }
    let endgame = missing_pieces > 0
        && endgame_triggered(
            missing_pieces,
            claimed.len() as u64,
            missing_bytes,
            face.peer_cuids
                .iter()
                .filter_map(|c| face.peer_state.get(c))
                .filter_map(|ps| ps.down_window.as_ref())
                .map(|w| w.rate())
                .sum::<f64>(),
        );
    // Scoping: the endgame dispatch gates (blanked claims + x2 duplicate
    // permission + the rate order) apply only to the rarest-first strategy
    // — streaming playhead semantics untouched (a frozen design face);
    // sequential is unreachable (rejected by SetSchedulerPolicy
    // validation).
    let endgame_rf = endgame && strategy.name() == "rarest_first";
    // Endgame-tail supply face (pure gate
    // [`endgame_tail_active`]): the tail band keys the three tail policies
    // — the holder window-floor write pass, the per-piece deadline
    // table, and the choke-round holder flags (the choke round reads its own
    // gate, `crate::choke::leecher_choke_round`). Deliberately NOT gated
    // on `endgame_rf`/`endgame_triggered`: the adaptive trigger's ETA
    // condition collapses exactly in the hard tail stall it must cover
    // (rate -> 0 makes ETA infinite), so the tail keys on the supply
    // inventory; the deadline bypass below lands in
    // [`issue_piece_blocks`], which the non-endgame selection paths share.
    // Outside the tail every tail policy is inert (floor writes = 0, the
    // deadline table swept, no overdue set) — non-tail rounds are
    // bit-for-bit the old behavior.
    let tail_pct = taiji_io::knobs::endgame_tail_pct();
    let tail_active = endgame_tail_active(tail_pct, missing_pieces, count);
    let tail_window_k = taiji_io::knobs::endgame_tail_window();
    let tail_deadline = Duration::from_secs(taiji_io::knobs::endgame_piece_deadline_secs());
    // The tail missing-piece table (the holder-scan input + the deadline
    // seeding sweep; <= 5% of the piece count by the gate).
    let tail_pieces: &mut Vec<u64> = &mut scratch.endgame_tail_pieces;
    if tail_active {
        tail_pieces.extend(
            done.iter()
                .enumerate()
                .filter(|&(_, &d)| !d)
                .map(|(i, _)| i as u64),
        );
    }
    let tail_pieces: &Vec<u64> = tail_pieces;
    // Per-piece deadline maintenance (tail-gated): sweep entries whose
    // piece is no longer busy-and-missing, seed first-observation deadlines
    // for busy missing pieces, and project this round's overdue set. The
    // anchor is the first TAIL-round observation of the piece's
    // [`PieceSentLedger`] row (a resume-mid-tail seeds at the resume round
    // — bounded over-wait of one deadline, the conservative direction).
    if tail_active && !tail_deadline.is_zero() {
        let now_tail = Instant::now();
        face.endgame_deadline.retain(|&p, _| {
            !done.get(p as usize).copied().unwrap_or(true) && face.blocks_sent.contains_key(&p)
        });
        let deadline_table = &mut face.endgame_deadline;
        // Anchor semantics: the stored instant is the piece's last supply
        // movement (first observation here; re-armed on each deadline-driven
        // dispatch in [`issue_piece_blocks`]) — the deadline expires at
        // `anchor + tail_deadline` ([`endgame_piece_overdue`]).
        for &p in tail_pieces.iter() {
            if face.blocks_sent.contains_key(&p) && !deadline_table.contains_key(&p) {
                deadline_table.insert(p, now_tail);
            }
        }
        scratch.endgame_overdue.extend(
            face.endgame_deadline
                .iter()
                .filter(|&(&p, &at)| {
                    endgame_piece_overdue(tail_deadline, at, now_tail)
                        && !done.get(p as usize).copied().unwrap_or(true)
                })
                .map(|(&p, _)| p),
        );
    } else {
        // Inactive face: drop the table (cheap guard — an empty table
        // stays empty; a knob flip mid-flight converges immediately).
        face.endgame_deadline.clear();
    }
    let endgame_overdue: &std::collections::HashSet<u64> = &scratch.endgame_overdue;
    let endgame_overdue_done: &mut std::collections::HashSet<u64> =
        &mut scratch.endgame_overdue_done;
    // Holder window-floor write pass (tail-gated): holders of missing
    // pieces get their RequestBook floor raised to the tail's missing-block
    // volume (`BH_ENDGAME_TAIL_WINDOW` k-multiplier, UB-clamped; 0 =
    // face off), everyone else (and every inactive round) gets 0 = the
    // generic floor. One atomic store per peer per round — negligible
    // next to the round's O(peers x pieces) selection scans; the book
    // consumes the value lazily at its next refresh_window.
    let tail_floor = endgame_tail_window_floor(tail_window_k, missing_bytes.div_ceil(block));
    for i in 0..face.peers.len() {
        let lift = if tail_active && tail_floor > 0 {
            face.peer_cuids
                .get(i)
                .and_then(|c| face.peer_avail.get(c))
                .is_some_and(|avail| peer_holds_missing_piece(avail, tail_pieces))
        } else {
            false
        };
        face.peers[i].set_endgame_window_floor(if lift { tail_floor } else { 0 });
    }
    // Strict gate input (see [`endgame_busy_admitted`] 1): the round-start
    // claimed snapshot — the same value as the in-flight piece set fed to
    // [`endgame_triggered`] (one decision face); in-round claim growth
    // inside the peer loop does not feed back into this gate (the "at
    // endgame start" reading).
    let claimed_at_round = claimed.len() as u64;
    // Fallback switch ([`endgame_strict_mode`]): off = restore the x2
    // reading (the single-level cursor pick, the two-level gates
    // bypassed). Read once per round (process-lazy cache, not on the hot
    // path).
    let strict_endgame = endgame_strict_mode();
    // The last-mile gate (wide fan-out, [`endgame_lastmile_pieces`]):
    // missing pieces <= N AND strict on (the two fallback switches are
    // orthogonal — with `BH_ENDGAME_STRICT=0` the last-mile gate does not
    // fire and the x2 fallback reading stands unchanged). N is read fresh
    // once per round (the `BH_REQ_WINDOW_FLOOR` numeric-parameter style,
    // not OnceLock).
    let lastmile_n = endgame_lastmile_pieces();
    let last_mile =
        endgame_rf && strict_endgame && endgame_lastmile_active(lastmile_n, missing_pieces);
    // Tail observation edges (observation only, zero behavior): the first
    // time missing pieces drop to <= N (the last-mile entry edge) and <= 8
    // (the last-8-pieces window) each records a moment — final values land
    // in [`FaceState::last_mile_final`] / [`FaceState::last8_final`] at
    // completion via `recheck_face_completion`, bridged into the session
    // counters by `checkpoint_endgame`. Missing 0 does not enter (a
    // completed face has no tail semantics); scoped to rarest_first (the
    // same range as the endgame gate — endgame_rf always implies it).
    if endgame_rf {
        let now_edge = Instant::now();
        if face.last_mile_edge.is_none() && missing_pieces > 0 && missing_pieces <= lastmile_n {
            face.last_mile_edge = Some(now_edge);
        }
        if face.last8_edge.is_none() && missing_pieces > 0 && missing_pieces <= 8 {
            face.last8_edge = Some(now_edge);
        }
    }
    // Redundancy-economy observation face (observation only, dispatch
    // semantics untouched): the endgame enter/exit edges. (1) A live flag
    // (the criterion for the store pipeline's duplicate/buffered split
    // counters, shared with the pipeline via Arc, single writer here);
    // (2) edge timestamps (sliced into the session duration totals by
    // checkpoint_endgame); (3) a supply-face INFO log (missing / in-flight
    // pieces, the per-transport connection mix, per-transport supplied
    // bytes) capturing the trigger-period supply shape. The hybrid face's
    // two piece sets are isomorphic with a shared trigger, and each face
    // records its own edges; non-rarest_first strategies never pass the
    // endgame gate — zero instrumentation, zero behavior difference.
    let edge_live = face.endgame_live.load(std::sync::atomic::Ordering::Relaxed);
    if endgame_rf && !edge_live {
        face.endgame_live
            .store(true, std::sync::atomic::Ordering::Relaxed);
        face.endgame_edge = Some(Instant::now());
        let (tcp_down, utp_down, tcp_conns, utp_conns) = face_transport_supply(face);
        info!(target: "taiji::core::engine", face = fi,
            missing = missing_pieces, in_flight = claimed.len(),
            tcp_conns, utp_conns, tcp_down, utp_down,
            "endgame entered (supply face)");
    } else if !endgame_rf && edge_live {
        face.endgame_live
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let seg = face.endgame_edge.take().map(|t| t.elapsed());
        if let Some(seg) = seg {
            face.endgame_cum += seg;
        }
        let (tcp_down, utp_down, tcp_conns, utp_conns) = face_transport_supply(face);
        info!(target: "taiji::core::engine", face = fi,
            missing = missing_pieces,
            seg_ms = seg
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            tcp_conns, utp_conns, tcp_down, utp_down,
            "endgame exited");
    }
    if endgame_rf {
        debug!(target: "taiji::core::engine", face = fi,
            missing = missing_pieces, in_flight = claimed.len(),
            "adaptive full endgame active ");
    }
    // Bandwidth-aware dispatch order (endgame-only; the anchors and key
    // order in [`endgame_peer_order`]): primary = 30s-window download rate
    // descending (reusing the choke statistics face down_windows),
    // tie-break = interested first (peers that want our pieces —
    // reciprocity), final = stable connection order. Non-endgame keeps
    // connection order (default semantics unchanged). Last-mile rounds
    // switch to [`endgame_lastmile_peer_order`] (fast holders first — a
    // pure rate order with a deterministic cuid tie-break; the interested
    // tie-break is not consumed, divergence note in its docs).
    let peer_order: Vec<usize> = if last_mile {
        let rates: Vec<f64> = (0..face.peers.len())
            .map(|i| {
                face.peer_cuids
                    .get(i)
                    .and_then(|c| face.peer_state.get(c))
                    .and_then(|ps| ps.down_window.as_ref())
                    .map(|w| w.rate())
                    .unwrap_or(0.0)
            })
            .collect();
        let cuids: Vec<u64> = (0..face.peers.len())
            .map(|i| face.peer_cuids.get(i).copied().unwrap_or(u64::MAX))
            .collect();
        endgame_lastmile_peer_order(&rates, &cuids)
    } else if endgame_rf {
        let rates: Vec<f64> = (0..face.peers.len())
            .map(|i| {
                face.peer_cuids
                    .get(i)
                    .and_then(|c| face.peer_state.get(c))
                    .and_then(|ps| ps.down_window.as_ref())
                    .map(|w| w.rate())
                    .unwrap_or(0.0)
            })
            .collect();
        let interested: Vec<bool> = (0..face.peers.len())
            .map(|i| face.peers.get(i).is_some_and(|p| p.is_interested()))
            .collect();
        endgame_peer_order(&rates, &interested)
    } else {
        (0..face.peers.len()).collect()
    };
    // The endgame selection's claimed view: blanked = the spread round
    // takes the globally rarest across all missing pieces (the "request
    // missing pieces from every holder" selection face); non-endgame
    // unchanged (spread semantics intact).
    let empty_claimed = ClaimedSet::empty();
    // The x2 copy cursor tables (the tail funnel fix): the endgame round
    // builds the "rarity-ascending missing-piece table + this round's
    // in-flight copy counts" once, and peers pick pieces by cursor over
    // the table. Mechanism: blanking claimed makes every peer converge on
    // the same globally rarest piece, and the x2 gate then idles the rest —
    // when the remaining piece count is below the peer count, supply
    // funnels into piece-by-piece serialization. The table costs one O(N)
    // build per round (the endgame gate only fires at <= 20 missing
    // pieces) and O(20) cursor per peer. The cursor pick is two-level (see
    // the peer-loop comments and [`endgame_busy_admitted`]): unowned
    // pieces are taken directly (not through the x2 gate); busy pieces
    // pass the two-level gate + the x2 gate — the x2 gate demotes from
    // "the only throttle on duplicate generation" to the slow-peer-fallback
    // concurrency ceiling; generation is governed by the two-level gate.
    let endgame_pieces: &mut Vec<u64> = &mut scratch.endgame_pieces;
    if endgame_rf {
        // Table order = the missing pieces of `order()` in the same stable
        // rarity order as `piece_stat::select`'s tie order (the first
        // cursor pick = the old "everyone converges on the globally
        // rarest piece" first choice; behavior diverges only once pieces
        // are taken). order() elements are u32 -> u64 (piece ids are a
        // 4-byte wire field).
        endgame_pieces.extend(
            face.stat_man
                .order()
                .iter()
                .copied()
                .map(u64::from)
                .filter(|&i| !done[i as usize]),
        );
        endgame_pieces.sort_by_key(|&i| face.stat_man.count(i));
        // Deadline cursor focus: overdue pieces (tail deadline expired)
        // sort ahead of the rarity order (stable partition — each group
        // keeps its internal order) so every holder's cursor tries the
        // structurally stuck piece before fresh rarity picks. Empty
        // overdue set = no reordering (bit-for-bit).
        if !endgame_overdue.is_empty() {
            endgame_pieces.sort_by_key(|&p| !endgame_overdue.contains(&p));
        }
    }
    let endgame_pieces: &Vec<u64> = endgame_pieces;
    let round_copies: &mut std::collections::HashMap<u64, u64> = &mut scratch.round_copies;
    if endgame_rf {
        let now_round = Instant::now();
        for &p in endgame_pieces.iter() {
            // The window switch (on = the piece's adaptive window upper
            // bound, see [`piece_reissue_window_max`]; off = the fixed 2s
            // existing reading).
            round_copies.insert(
                p,
                endgame_inflight_copies(
                    face.blocks_sent.get(&p),
                    now_round,
                    piece_reissue_window_max(face, p, two_phase),
                ),
            );
        }
    }
    // The last-mile wide-fan-out copy-cap table (built only when missing
    // <= N — table length <= N, O(peers) bit reads per piece): each piece's
    // cap = max(holders, x2) (the [`endgame_lastmile_copies_limit`]
    // relax-only semantics). Empty tables in non-last-mile rounds — the
    // cursor's copies_limit closure always falls back to
    // [`ENDGAME_MAX_COPIES`] (the strict x2 gate, pinned by the
    // decision-table face). Holder counting uses the
    // [`endgame_piece_holders_face`] direct bitmap read (removing the
    // per-piece intermediate Vec<bool> materialization — missing x P
    // allocations and bit writes).
    if last_mile {
        let choking: Vec<bool> = (0..face.peers.len())
            .map(|i| face.peers.get(i).is_some_and(|p| p.is_choking_us()))
            .collect();
        for &p in endgame_pieces.iter() {
            scratch.lastmile_copies_limit.insert(
                p,
                endgame_lastmile_copies_limit(endgame_piece_holders_face(face, p, &choking)),
            );
        }
    }
    let lastmile_copies_limit: &std::collections::HashMap<u64, u64> =
        &scratch.lastmile_copies_limit;
    // The partial hard-gate (gate-round) partial-piece table: table order
    // = the (count, order rank) stable order (built like the endgame
    // table; the tie order matches piece_stat selection), injected into
    // rarest-first selection via [`SelectionCtx::preferred`] — within the
    // table take the first eligible-and-rarest (the local consumption
    // point of prioritize_partials; reference `piece_picker.cpp`:
    // options |= prioritize_partials and clears prefer_contiguous; the
    // local side has no prefer_contiguous consumer, so the clear has no
    // counterpart — divergence note). Scoping matches the endgame gate:
    // rarest_first only (streaming playhead semantics untouched,
    // sequential unreachable). Non-gate rounds = an empty table (selection
    // verdicts unchanged). Block-level dedup is the candidates'
    // InFlight/Buffered filter's job: a claimed partial piece, even when
    // priority-hit, only fills blocks not already in flight (speeding
    // convergence, not duplicating requests).
    let partial_preferred: &mut Vec<u64> = &mut scratch.partial_preferred;
    if partial_gate && !endgame_rf {
        let pset: std::collections::HashSet<u64> = partial_pieces.iter().copied().collect();
        partial_preferred.extend(
            face.stat_man
                .order()
                .iter()
                .copied()
                .map(u64::from)
                .filter(|i| pset.contains(i)),
        );
        partial_preferred.sort_by_key(|&i| face.stat_man.count(i));
    }
    let partial_preferred: &Vec<u64> = partial_preferred;

    // Per-peer fresh in-flight block counts (the busy eligibility gate 2
    // input, see [`endgame_busy_admitted`]): ownership = the in-row owner
    // (the refetch arm and the primary dispatch arm bookkeep alike); the
    // fresh reading switches with [`two_phase_ledger`] (on = network phase
    // + adaptive window; off = the fixed 2s single-state reading, current
    // behavior). Built once per round, O(in-flight blocks), zero extra
    // scans in the peer loop. Not built when the fallback switch is off
    // (the two-level gate is bypassed, zero added cost); last-mile rounds
    // skip it too (the busy gate is fully lifted there, no consumer). With
    // d tiering (K >= 1) the busy-gate input switches to the busy-piece
    // count table (below) and this block-count table becomes K=0-arm-only
    // (the block-level zero check input bit-for-bit — the explicit `=0`
    // fallback arm). Both tables live in the scratch (built via the
    // `_into` in-place fills [`fill_endgame_peer_inflight`] /
    // [`fill_endgame_peer_busy_pieces`] — the returning forms remain as
    // test-driven faces).
    let fast_busy_k = endgame_fast_busy_k();
    if endgame_rf && strict_endgame && !last_mile && fast_busy_k == 0 {
        let now_inflight = Instant::now();
        fill_endgame_peer_inflight(
            face,
            now_inflight,
            two_phase,
            &mut scratch.endgame_peer_inflight,
        );
    }
    let endgame_peer_inflight: &std::collections::HashMap<u64, u64> =
        &scratch.endgame_peer_inflight;
    // The d tiering inputs (built at the default K=2; not built on the
    // explicit `=0` fallback = zero added cost): (1) the busy-piece count
    // table ([`endgame_peer_busy_pieces`] — the tier cap's granularity
    // face); (2) the fast-tier criterion median ([`rates_median`], once
    // per dispatch round O(n) — the rate readings share the choke sort-key
    // source `down_windows`; the peer loop only looks it up, no recompute).
    // The x2 copy cap and the last-mile boundary are untouched (red
    // lines).
    if endgame_rf && strict_endgame && !last_mile && fast_busy_k >= 1 {
        fill_endgame_peer_busy_pieces(
            face,
            Instant::now(),
            two_phase,
            &mut scratch.endgame_busy_pieces,
        );
    }
    let endgame_busy_pieces: &std::collections::HashMap<u64, u64> = &scratch.endgame_busy_pieces;
    let fast_tier_median = if endgame_rf && strict_endgame && !last_mile && fast_busy_k >= 1 {
        let rates: Vec<f64> = (0..face.peers.len())
            .map(|i| {
                face.peer_cuids
                    .get(i)
                    .and_then(|c| face.peer_state.get(c))
                    .and_then(|ps| ps.down_window.as_ref())
                    .map(|w| w.rate())
                    .unwrap_or(0.0)
            })
            .collect();
        rates_median(&rates)
    } else {
        0.0
    };
    for peer_i in peer_order {
        let my_cuid = face.peer_cuids.get(peer_i).copied();
        // Reciprocity fix (the aria2 `DefaultBtInteractive::fillPiece`
        // port; the request-face choke gate): when the peer chokes us,
        // **zero requests this round** — while choked only requests in the
        // peer's allowed-fast set are accepted (the local side has no
        // allowed-fast request face), so injecting is pure waste (fast-ext
        // peers reject-bounce; non-fast-ext peers swallow the request ->
        // our slot times out at 60s -> snub -> the choke decision excludes
        // that peer until a block arrives -> never supplied -> the peer's
        // tit-for-tat chokes us forever = a reciprocity deadlock; the gate
        // guards the poisoning loop when interested peers exist, aligned
        // with aria2's same gate). Skipping != disconnecting; the unchoke
        // edge registers dispatch debt via `AvailEvent::Unchoked` for an
        // immediate refill (run/arms.rs). The seeding supply face
        // (choke_round/serve) does not pass this gate; seeder semantics
        // untouched.
        if face.peers[peer_i].is_choking_us() {
            continue;
        }
        // Supply cap (the spec formula, pure function [`supply_cap`]): at
        // most `min(target window - in flight, command-channel room)`
        // further requests queued for this peer this round — target window
        // / in flight are both PeerTaskHandle lock-free mirror reads (BDP
        // rate-driven: fast peers get deep supply, slow peers do not pile
        // up); the cap only tightens supply, and the one-piece-per-round
        // rhythm and the continuation / spread / endgame selection faces
        // are untouched. The single-block refetch arm (the top of this
        // function) bypasses this cap (the transfer-cancel's single 16KiB
        // refill takes priority, existing semantics).
        let mut supply_cap = supply_cap(
            face.peers[peer_i].target_request_window(),
            face.peers[peer_i].in_flight(),
            face.peers[peer_i].command_capacity(),
        );

        // The parole gate (the libtorrent `torrent.cpp` parole chain
        // port): a suspect peer (a participant in a hash-failed piece) —
        // (1) barred from endgame busy (it does not join duplicate-copy
        // rounds; duplicate delivery blurs block attribution, so that form
        // is excluded during the suspect period); (2) selection sees only
        // "unowned whole pieces" (see [`parole_pick_piece`]) — if the
        // suspect's download fails again, every byte of the piece can only
        // have come from that peer: unambiguous attribution; (3)
        // continuation of its own checkout piece is unrestricted (the
        // piece is already exclusively its own — the
        // [`own_piece_continuable`] lazy invalidation reading). Suspect
        // status lifts when a piece it participated in passes verification
        // (removed in the event arm, see the faces::parole_peers docs);
        // peer departure hard-clears it.
        if endgame_rf && my_cuid.is_some_and(|c| face.parole_peers.contains(&c)) {
            continue;
        }
        // The continuation arm (phase 3): on the non-endgame rarest_first
        // download path, if the peer already has an unfinished checkout
        // piece, this round **continues that piece** instead of claiming a
        // new one. Reference: aria2 `DefaultPieceStorage.cc`
        // getMissingPiece(peer) checks out one whole piece per peer
        // (usedPieces_ bookkeeping, held until the piece completes or is
        // cancelled) — previously each dispatch round re-selected
        // statelessly, so a peer whose window was already full of claimed
        // pieces kept claiming new ones: under slow-RTT convergence each
        // peer's partial pieces multiplied by the round count (30 peers x
        // k rounds x 256KiB fills the 16MiB write cache -> unverified
        // pieces evicted -> refetched). Continuation presses partial piece
        // occupancy back to O(1) per peer; spread exclusivity, the x2
        // gate, and block-level dedup semantics do not pass through this
        // arm (endgame / streaming / sequential keep the existing
        // selection face).
        let continued = if !endgame_rf && strategy.name() == "rarest_first" {
            my_cuid
                .and_then(|c| face.peer_state.get(&c))
                .and_then(|ps| ps.piece)
                .filter(|&p| own_piece_continuable(face, p))
        } else {
            None
        };
        // Advertisement-aware selection: pick only from the pieces this
        // peer has advertised; no advertisement or no unfinished piece
        // inside it -> zero requests (skip the peer, wait for
        // advertisements / a new peer). The old blind fallback
        // `.unwrap_or(current)` (requesting even unadvertised pieces) is
        // removed — real peers answer that with FIN (the anchors in
        // [`select_advertised_piece`]). The selection decision is
        // delegated to the current strategy object (the default
        // [`RarestFirstStrategy`] = the two-phase port — the spread round
        // first skips pieces in flight elsewhere, falling back to the
        // original pick when everything is claimed; peers never idle, and
        // duplicates in flight are still blocked by the candidates'
        // InFlight filter (no resend, semantics unchanged)).
        let pick = if endgame_rf {
            // Cursor pick (the funnel fix; table semantics in the
            // endgame_pieces docs): the strategy object is consumed only
            // in the non-endgame spread round — the endgame selection face
            // = the rarity missing table (the same global-rarest order),
            // and the cursor preserves the "request missing pieces from
            // every holder" face without funneling.
            //
            // Two-level restraint (anchors in [`endgame_busy_admitted`]):
            // level 1 **unowned first** — take directly a missing piece
            // "advertised AND held fresh in flight by nobody" (the
            // counterpart of libtorrent's pick loop filling the request
            // count with non-busy blocks first, `request_blocks.cpp`:
            // busy blocks are only registered, not consumed); this peer's
            // own in-flight pieces are skipped too (refetching their
            // unrequested blocks is the refetch arm's job). Level 2
            // **busy** — only when the [`endgame_busy_admitted`] two-level
            // gate admits, take a missing piece "advertised AND held by
            // others AND copies < cap" (the x2 copy gate stays as the
            // slow-peer fallback: the busy gate governs generation, x2
            // governs timeouts, see [`ENDGAME_MAX_COPIES`]; duplicates
            // made via busy pieces land in [`BlockState::InFlightDup`]
            // through the existing block-level one-hop permission).
            //
            // Last-mile lift (wide fan-out): with missing <= N the
            // two-level busy gate is bypassed wholesale — every peer
            // (advertised AND on the unchoke path) may take busy pieces,
            // no more 1-busy-piece-per-peer cap (relief for the "slow
            // holder parked, fast peer joined late" serial wait); the copy
            // cap switches to the holder count
            // ([`endgame_lastmile_copies_limit`]) with block-level
            // first-wins (the candidate-filter fan-out face in
            // [`issue_piece_blocks`]). With missing > N this branch takes
            // no part — strict verdicts bit-for-bit (the decision-table
            // pinned face).
            let avail = face
                .peer_cuids
                .get(peer_i)
                .and_then(|c| face.peer_avail.get(c));
            let my_inflight = my_cuid
                .and_then(|c| endgame_peer_inflight.get(&c))
                .copied()
                .unwrap_or(0);
            // d: the busy-gate input switches on K — K=0 = the block count
            // (the old input bit-for-bit, the explicit `=0` fallback arm);
            // K>=1 = the busy-piece count (the tier-cap granularity) + the
            // fast-tier criterion ([`endgame_fast_tier`], median = the
            // round-start `fast_tier_median`). The last-mile / strict-off
            // bypasses and the two-tier verdict consolidate in
            // [`endgame_busy_admitted_dispatch`] (decision-table driven).
            let my_busy_count = if fast_busy_k == 0 {
                my_inflight
            } else {
                my_cuid
                    .and_then(|c| endgame_busy_pieces.get(&c))
                    .copied()
                    .unwrap_or(0)
            };
            let is_fast_tier = fast_busy_k >= 1
                && my_cuid.is_some_and(|c| {
                    let rate = face
                        .peer_state
                        .get(&c)
                        .and_then(|ps| ps.down_window.as_ref())
                        .map(|w| w.rate())
                        .unwrap_or(0.0);
                    endgame_fast_tier(rate, fast_tier_median)
                });
            let busy_admitted = endgame_busy_admitted_dispatch(
                last_mile,
                strict_endgame,
                fast_busy_k,
                my_busy_count,
                is_fast_tier,
                claimed_at_round,
                missing_pieces,
            );
            // The copy-cap lookup: last-mile rounds = the holder count
            // (relax-only), otherwise always x2 (the empty-table fallback —
            // strict bit-for-bit).
            let copies_limit = |p: u64| {
                lastmile_copies_limit
                    .get(&p)
                    .copied()
                    .unwrap_or(ENDGAME_MAX_COPIES)
            };
            endgame_cursor_pick(
                endgame_pieces,
                avail,
                claimed,
                round_copies,
                strict_endgame,
                busy_admitted,
                &copies_limit,
            )
        } else if let Some(own) = continued {
            Some(own)
        } else if my_cuid.is_some_and(|c| face.parole_peers.contains(&c)) {
            // The parole selection face: only unowned whole pieces (the
            // unambiguous-attribution face — every byte of the piece can
            // only have come from this peer). The strategy object
            // (including streaming playhead priority) is not consumed for
            // suspects this round — suspect handling takes precedence over
            // the selection strategy (the libtorrent parole structure: the
            // `prioritize_partials` forced face; piece_picker.cpp orders
            // "parole peers barred from endgame" the same way).
            parole_pick_piece(face, peer_i, done, claimed)
        } else {
            let avail = face
                .peer_cuids
                .get(peer_i)
                .and_then(|c| face.peer_avail.get(c));
            avail.and_then(|avail| {
                strategy.select_piece(&SelectionCtx {
                    advertised: Some(avail),
                    done,
                    stats: &face.stat_man,
                    // Non-endgame spread round: claimed exclusivity (endgame
                    // does not pass this arm — its selection face is the
                    // cursor above).
                    claimed: if endgame_rf { &empty_claimed } else { claimed },
                    // The partial hard-gate round's partial-piece table
                    // (non-gate rounds = an empty table — verdicts
                    // unchanged; endgame rounds are also empty, their
                    // selection face being the cursor arm).
                    preferred: partial_preferred,
                    stream: stream_ctx.as_ref(),
                    // The file multi-level priority piece table (None = the
                    // default face, unchanged).
                    priority: prio,
                })
            })
        };
        let Some(piece_for_peer) = pick else {
            continue;
        };
        // The cross-piece supply flag: enabled only on the non-endgame
        // rarest_first primary selection face (the continuation arm /
        // spread round — spec option 1 "after the continuation arm /
        // selection"). The endgame cursor face is untouched (option 3);
        // streaming/sequential strategy faces unchanged; parole suspects
        // stay single-piece (conservatively no cross-piece on the
        // unambiguous-attribution face — even when their primary came from
        // the continuation arm).
        let multi_piece = !endgame_rf
            && strategy.name() == "rarest_first"
            && multi_piece_supply_enabled()
            && !my_cuid.is_some_and(|c| face.parole_peers.contains(&c));
        let mut ctx = PieceIssueCtx {
            fi,
            peer_i,
            my_cuid,
            block,
            endgame_rf,
            last_mile,
            supply_cap: &mut supply_cap,
            claimed: &mut *claimed,
            round_copies: &mut *round_copies,
            endgame_overdue,
            endgame_overdue_done: &mut *endgame_overdue_done,
            endgame_tail_deadline: tail_deadline,
        };
        // Primary piece dispatch (extracted from the former inline
        // single-piece face, see [`issue_piece_blocks`]).
        let primary_queued = issue_piece_blocks(face, &mut ctx, piece_for_peer);
        // Checkout bookkeeping (the continuation arm's input; formerly
        // inlined per block): any primary block enqueued registers the
        // piece (re-dispatch overwrites with the same value, idempotent;
        // an endgame one-hop duplicate does not rewrite the checkout — a
        // duplicate copy is not a claim transfer). Secondary registration
        // in [`supply_adjacent_pieces`] (the peer_state row's
        // extra_pieces, never rewriting the primary).
        if primary_queued > 0
            && !endgame_rf
            && let Some(cuid) = my_cuid
        {
            face.peer_state_row(cuid).piece = Some(piece_for_peer);
        }
        // Cross-piece supply append (the core face).
        if multi_piece {
            supply_adjacent_pieces(face, &mut ctx, piece_for_peer, done);
        }
    }
    // Put the scratch back (capacity resident — the next round clears and
    // reuses).
    face.dispatch_scratch = scratch;
}

/// The round-level context of single-piece dispatch (the extraction face):
/// the bundle of invariants reused across pieces within a dispatch round —
/// the primary and the cross-piece appended secondaries share one supply
/// cap / claim set / copy ledger (the round's supply budget is conserved;
/// the bookkeeping face of the spec's "while the supply cap has room").
/// `pub(super)` = the test fixture face (engine::tests drive
/// [`supply_adjacent_pieces`] directly).
pub(super) struct PieceIssueCtx<'a> {
    /// Face number (the logging face).
    pub(super) fi: usize,
    /// This peer's position (command channel / advertisement bitmap
    /// index).
    pub(super) peer_i: usize,
    /// This peer's cuid (the bookkeeping key; None = no bookkeeping
    /// identity, e.g. synthetic endgame states).
    pub(super) my_cuid: Option<u64>,
    /// Block length in bytes.
    pub(super) block: u64,
    /// The endgame dispatch gate flag (the candidate-filter and
    /// dup-semantics branch input).
    pub(super) endgame_rf: bool,
    /// The last-mile wide-fan-out flag (missing <= N AND strict on):
    /// widens the candidate filter's duplicate permission — fresh
    /// `InFlightDuplicate` (other-owned) coordinates may also re-dispatch
    /// (block-level first-wins multi-copy). Always false outside last-mile
    /// (the one-hop duplicate permission as before).
    pub(super) last_mile: bool,
    /// This round's remaining supply cap for this peer (the
    /// [`supply_cap`] product; shared across pieces, one slot deducted per
    /// enqueue).
    pub(super) supply_cap: &'a mut usize,
    /// This round's spread claim set (shared across pieces — a secondary's
    /// claim is immediately visible to later peers).
    pub(super) claimed: &'a mut ClaimedSet,
    /// The endgame in-round copy counts (the cursor x2 discipline; always
    /// empty outside endgame).
    pub(super) round_copies: &'a mut std::collections::HashMap<u64, u64>,
    /// This round's overdue pieces (the tail deadline face —
    /// empty when the face is off / nothing overdue): a piece in this set
    /// takes the candidate-filter freshness bypass (its whole
    /// network-phase in-flight set becomes takeover candidates) until the
    /// first bypass dispatch lands (then [`Self::endgame_overdue_done`]
    /// restores the normal rules for the rest of the round).
    pub(super) endgame_overdue: &'a std::collections::HashSet<u64>,
    /// The one-shot-per-round stampede guard: pieces whose
    /// freshness bypass already fired this round — later peers fall back
    /// to the normal rules (the first takeover re-armed the shared
    /// timestamp; a second bypass in the same round would cancel the
    /// first taker's just-issued requests).
    pub(super) endgame_overdue_done: &'a mut std::collections::HashSet<u64>,
    /// The tail deadline window (zero = the face is off):
    /// a successful dispatch of an overdue piece re-arms its deadline to
    /// `now + this` (the "deadline until next supply movement" semantic).
    pub(super) endgame_tail_deadline: Duration,
}

/// Single-piece dispatch (the extraction face): the former single-piece
/// face moved verbatim out of the dispatch round's peer loop (alarm
/// instrumentation -> v2 lazy-fetch gating -> in-flight pre-registration ->
/// candidate filtering -> endgame dup marking -> per-block enqueue /
/// transfer cancel / in-flight bookkeeping / receipt -> block-cursor
/// advance). Verdicts unchanged (the equivalence proof = all existing
/// dispatch tests passing unmodified); the old `continue` (skip the peer)
/// semantics becomes `return 0` (nothing dispatchable on this piece this
/// round — caller semantics unchanged: a dry primary moves to the next
/// peer, a dry append breaks the chain).
///
/// Returns the number of blocks actually enqueued (the supply slots
/// consumed; 0 = dry — v2 gating / addressing missing / empty candidates /
/// cap and channel interception).
fn issue_piece_blocks(face: &mut FaceState, ctx: &mut PieceIssueCtx<'_>, piece: u64) -> usize {
    let mut queued_ct = 0usize;
    // Instrumentation: a dispatch target inside the completed bitmap = a
    // bookkeeping-divergence alarm (should always be 0 — the candidate set
    // is already filtered by the done bitmap; this counter is the direct
    // check of the "completed pieces being re-requested" hypothesis).
    if face.progress.piece_done_global(piece) {
        let hits =
            DISPATCH_DONE_PIECE_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        warn!(target: "taiji::core::engine", face = ctx.fi, piece = piece, hits,
            "dispatch alarm: selected piece already verified locally \
             (done-bitmap / dispatch bookkeeping divergence)");
    }
    // Lazy-fetch gating (v2 faces only). Defense in depth: a Pending
    // (layer missing, not yet promoted) piece already folds into done and
    // is unreachable from selection — this arm stays so that any future
    // path that misses the fold still cannot dispatch (a placeholder root
    // cannot pass verification; letting it through would only manufacture
    // a verification-failure refetch storm).
    if face.trees.is_some() {
        let file_idx = face
            .flat_coords
            .get(piece as usize)
            .map(|(f, _)| *f as usize)
            .unwrap_or(usize::MAX);
        match face.layers.get(file_idx).map(|l| &l.state) {
            Some(LayerFetchState::Done) | Some(LayerFetchState::Failed) | None => {}
            Some(LayerFetchState::Pending) => return 0,
            Some(LayerFetchState::Queued { next }) => {
                // Pick point: prefer a peer whose bitmap covers this file,
                // else the current peer.
                let base = face.layers[file_idx].piece_base;
                let target = peer_with_piece(face, base).unwrap_or(ctx.peer_i);
                issue_fetch(face, ctx.fi, file_idx, *next, target);
                return 0;
            }
        }
    }
    face.progress.mark_block_in_flight_global(piece);
    let nbytes = face
        .piece_bytes
        .get(piece as usize)
        .copied()
        .unwrap_or(ctx.block);
    let blocks = nbytes.div_ceil(ctx.block).max(1);
    let Some(id) = face
        .addressing
        .from_wire(u32::try_from(piece).unwrap_or(u32::MAX))
    else {
        return 0;
    };
    let now = Instant::now();
    // Take the row once; block state / owner / piece-level timestamp all
    // read inline (dissolves the old double lookup of the blocks_sent
    // inner map + the block_dispatch global map; freshness reads the
    // piece-level shared timestamp, approximation note in
    // [`PieceSentLedger`]).
    let sent_now = face.blocks_sent.get(&piece);
    // In-flight blocks are not resent (dispatch-face dedup of the
    // single-block refetch reading; a block is removed once confirmed by
    // the store pipeline; past the window unconfirmed -> reissue — keeps a
    // stuck store pipeline from starving the download).
    // Endgame one-hop duplicate: in endgame a fresh InFlight block permits
    // **one** duplicate request (it lands in [`BlockState::InFlightDup`]
    // and is not doubled again = at most first copy + one duplicate per
    // block). The duplicate targets only blocks attributable to another
    // peer — missing ownership (a duplicate's owner cannot be confirmed:
    // synthetic states / missing bookkeeping, conservatively no resend) or
    // ownership by this peer (the peer's own in-flight block; resending
    // only buys a RequestBook Duplicate) are both refused. A duplicate
    // block's arrival is absorbed by the covers check (the store's
    // verified `buffer_block` coverage check -> benign drop + count,
    // note_duplicate_drop) -> the piece still verifies from the
    // first-arriving blocks, no data pollution. (ctx.my_cuid is read at
    // round start.)
    // Last-mile wide fan-out: with missing <= N, fresh InFlightDup
    // (other-owned) coordinates may also re-dispatch (first-wins
    // multi-copy, bounded by the holder count) — see the candidate-filter
    // branch below; outside last-mile the one-hop semantics are unchanged
    // bit-for-bit.
    // Per-block reissue window (the read-side consumption): the window
    // follows the block's current dispatch target peer's adaptive timeout —
    // fast peers (adaptive <= 2s) keep the existing 2s; slow peers extend
    // to the adaptive value (<= 5s cap), so store/delivery confirmation
    // lag is no longer misjudged by a flat 2s (the wire-amplification /
    // late-block root cause); no owner (missing bookkeeping / peer gone)
    // falls back to the existing 2s. Window readings take the single
    // source [`block_reissue_window`] (the same source as claimed / x2
    // metering / the busy in-flight count); candidate filtering and dup
    // marking share this closure (one partition decision).
    let reissue_for = |begin: u32| -> Duration { block_reissue_window(face, piece, begin) };
    // Overdue bypass (one-shot per round): a piece whose tail
    // deadline expired takes the freshness bypass — every InFlight /
    // InFlightDup coordinate becomes a takeover candidate regardless of
    // the shared timestamp (the anti-mask face: re-dispatch trickles
    // refresh dispatched_at and keep stale blocks looking fresh
    // indefinitely; see [`endgame_piece_overdue`]). The bypass is not a
    // dup hop: candidates taken this way are takeover re-issues (cancel
    // displaced + InFlight), NOT InFlightDup marks — the dup_marks closure
    // below reads the same flag. After the first bypass dispatch this
    // round ([`PieceIssueCtx::endgame_overdue_done`]) the normal rules
    // resume for the piece (a second holder bypassing in the same round
    // would cancel the first taker's just-issued requests).
    let overdue_takeover =
        ctx.endgame_overdue.contains(&piece) && !ctx.endgame_overdue_done.contains(&piece);
    let candidates: Vec<u32> = {
        (0..blocks)
            .map(|bi| (face.block_cursor + bi) % blocks)
            .filter(|bi| {
                let begin = (*bi * ctx.block) as u32;
                let Some(ledger) = sent_now else {
                    return true;
                };
                match ledger.block_state(begin) {
                    BlockState::Buffered => false,
                    // Store phase: the block's bytes are local, resending
                    // the wire request is pure waste — arrived coordinates
                    // are **never candidates (even expired)**, and past the
                    // [`STORE_PENDING_GUARD`] age they are still not
                    // candidates (the guard's action is warn + count only).
                    // Expiry-as-candidate exists only in the network phase.
                    BlockState::Settling | BlockState::SettlingDup => false,
                    BlockState::InFlight | BlockState::InFlightDup => {
                        if overdue_takeover
                            || now.duration_since(ledger.dispatched_at()) >= reissue_for(begin)
                        {
                            // Expired and stalled: takeover reissue (both
                            // states alike).
                            true
                        } else {
                            // Fresh in flight: non-endgame never resends;
                            // endgame permits only blocks never duplicated
                            // (InFlight) and owned by a known other peer
                            // (one-hop duplicate — ownership is the in-row
                            // owner; the this-peer comparison is a peer_i
                            // index comparison, the cuid<->index bijection).
                            // Last-mile wide fan-out (block-level
                            // first-wins): a fresh `InFlightDup`
                            // (other-owned) is likewise permitted to
                            // re-dispatch — multi-copy concurrency up to
                            // the holder count (the piece-level cap
                            // [`endgame_lastmile_copies_limit`]), first
                            // delivery wins (on the arrival face the first
                            // arrival exclusively owns the Settling
                            // transition, later arrivals are no-ops plus
                            // the store-side covers benign drop; the
                            // exactly-once was_dup is unaffected — the red
                            // line holds).
                            ctx.endgame_rf
                                && ctx.my_cuid.is_some()
                                && match ledger.owner_of(begin) {
                                    Some(owner) if owner as usize != ctx.peer_i => {
                                        match ledger.block_state(begin) {
                                            BlockState::InFlight => true,
                                            BlockState::InFlightDup => ctx.last_mile,
                                            _ => false,
                                        }
                                    }
                                    _ => false,
                                }
                        }
                    }
                    BlockState::None => true,
                }
            })
            .map(|bi| (bi * ctx.block) as u32)
            .collect()
    };
    // Blocks that become duplicate copies this round (candidates whose
    // snapshot state is fresh InFlight — the endgame eligibility filter
    // has already ensured they were never duplicated and are other-owned):
    // the request lands in [`BlockState::InFlightDup`] (the one-shot
    // duplicate mark). The freshness test shares the candidate filter's
    // adaptive reissue window (one partition decision; two different
    // windows would corrupt the duplicate marking). Fresh eligibility
    // naturally recognizes only `InFlight` (the match-arm shape) —
    // `SettlingDup` grants no third hop (the store phase joins no
    // duplicate coverage, counting 0 like [`endgame_inflight_copies`]).
    // Last-mile: fresh `InFlightDup` candidates (the multi-copy
    // re-dispatch already permitted by the wide-fan-out face) join the
    // mark set too — the mark lands in InFlightDup so the state does not
    // downgrade (the piece-level timestamp refresh = the duplicate resend
    // moment; the window reading follows the row's new owner,
    // self-consistent).
    let dup_marks: std::collections::HashSet<u32> = if ctx.endgame_rf {
        candidates
            .iter()
            .copied()
            .filter(|&begin| {
                let Some(ledger) = sent_now else {
                    return false;
                };
                // The overdue bypass is a takeover, not a dup hop: its
                // candidates are never fresh (no InFlightDup mark, the
                // displaced owner is cancelled instead).
                let fresh = !overdue_takeover
                    && now.duration_since(ledger.dispatched_at()) < reissue_for(begin);
                match ledger.block_state(begin) {
                    BlockState::InFlight => fresh,
                    BlockState::InFlightDup => ctx.last_mile && fresh,
                    _ => false,
                }
            })
            .collect()
    } else {
        Default::default()
    };
    if candidates.is_empty() {
        return 0;
    }
    // This round's copy count +1 (the cursor face: the x2 discipline's
    // in-round ledger — issuing an in-flight request for the piece occupies
    // one copy slot; the metering face is in the endgame_pieces docs).
    if ctx.endgame_rf {
        *ctx.round_copies.entry(piece).or_insert(0) += 1;
    }
    for begin in candidates {
        // Supply cap: target depth full or the command channel out of
        // room -> the remaining candidates stay queued for the next
        // trigger (the same semantics as the channel-full skip — not
        // enqueued means not marked in flight, not claimed).
        if *ctx.supply_cap == 0 {
            break;
        }
        let bi = begin as u64 / ctx.block;
        let length = (nbytes - bi * ctx.block).min(ctx.block) as u32;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let queued = face.peers[ctx.peer_i]
            .command(taiji_bt::peer::PeerCommand::RequestPiece {
                id,
                begin,
                length,
                reply: tx,
            })
            .is_ok();
        if queued {
            *ctx.supply_cap -= 1;
            queued_ct += 1;
            // Transfer-cancel (lever 2, slow-peer reissue amortization):
            // when taking over an expired stalled block, the original
            // holder's outstanding request is **cancelled on the spot,
            // back to the pool** (this peer takes over the coordinate;
            // block-level in-flight does not zero) instead of keeping both
            // copies in transit. Reference: aria2
            // `DefaultBtMessageDispatcher.cc` — a slot timeout ->
            // `cancelBlock` (the block returns to the pool) + snubbing,
            // and a block obtained elsewhere -> Cancel to the holder. The
            // local side previously had only the "block back to the pool"
            // half (expiry permitted takeover) and lacked the "cancel"
            // half, so a slow peer's late delivery raced the new copy
            // (goodput dilution). An endgame one-hop duplicate is a
            // deliberate controlled copy (the x2 gate) and is not
            // cancelled; neither is the case where the original holder is
            // this peer (self-continuation); a cancelled slot's late
            // delivery is accepted by the peer-side grace
            // (`RequestBook::cancel_with_grace` — do not misjudge slow
            // peers). Two-phase note: this arm naturally touches only
            // network-phase coordinates — `Settling*` coordinates are
            // never candidates (the candidate filter's store-phase arm is
            // always false), so the transfer cancel and the enqueue
            // marking need zero changes to compose with the new state
            // machine (total functions).
            // displaced = the in-row owner (owner IS the peer_cuids index
            // — dissolves the old cuid->position linear scan; missing
            // ownership / peer gone = no cancel, the same verdict as the
            // old position-lookup-failure fallback). Read before the state
            // write below (the write overwrites ownership); the borrow is
            // short-lived (the `sent_now` row borrow does not live past
            // the write points).
            let displaced = face.blocks_sent.get(&piece).and_then(|l| l.owner_of(begin));
            let dup = dup_marks.contains(&begin);
            if !dup
                && let Some(old) = displaced
                && old as usize != ctx.peer_i
                && let Some(peer) = face.peers.get(old as usize)
            {
                let from_cuid = face
                    .peer_cuids
                    .get(old as usize)
                    .copied()
                    .unwrap_or(u64::from(old));
                debug!(target: "taiji::core::engine", face = ctx.fi, piece = piece,
                    begin, from_cuid, to_cuid = ctx.my_cuid,
                    "re-dispatch transfer: cancel displaced request ");
                let _ =
                    peer.command(taiji_bt::peer::PeerCommand::CancelPiece { id, begin, length });
            }
            // Only an enqueued block is marked in flight + keeps a receipt:
            // a peer's WindowFull receipt clears the mark and re-queues in
            // the next dispatch trigger's reply drain; a full command
            // channel skips (the supply cap
            // `min(target window - in flight, channel room)` usually
            // intercepts first — the room reading IS the channel's
            // remaining permits), and the block stays a candidate for the
            // next trigger — previously an un-enqueued block was still
            // phantom-marked and request supply was pinned by the 2s
            // reissue window. An endgame one-hop duplicate lands in
            // InFlightDup (all other cases — first sends or expiry
            // takeovers — land in InFlight). In-row single write: state +
            // owner (owner = peer_i; absent peer bookkeeping keeps the
            // current owner) + one piece-level timestamp refresh (the old
            // blocks_sent insert + block_dispatch insert double-table
            // write -> one row write).
            let owner = face.peer_cuids.get(ctx.peer_i).map(|_| ctx.peer_i as u32);
            {
                let row = face
                    .blocks_sent
                    .entry(piece)
                    .or_insert_with(|| PieceSentLedger::new(blocks as usize, now));
                if dup {
                    row.set_inflight_dup(begin, owner, now);
                } else {
                    row.set_inflight(begin, owner, now);
                }
            }
            // Spread: claim instantly within this call (later peers' spread
            // rounds see it at once; peers within the round claim different
            // pieces).
            ctx.claimed.mark_claimed(piece);
            // Checkout bookkeeping (the continuation arm's input): the
            // former per-block inline registration moved up to the caller —
            // any primary block enqueued registers
            // [`FaceState::peer_piece`] (re-dispatch overwrites with the
            // same value, idempotent); cross-piece appended secondaries
            // register [`FaceState::peer_extra_pieces`] (never rewriting
            // the primary checkout, keeping the continuation arm's
            // priority). An endgame one-hop duplicate still does not
            // rewrite the checkout — a duplicate copy is not a claim
            // transfer (this function touches neither table).
            face.dispatch_replies.push((piece, begin, rx));
        }
    }
    face.block_cursor = (face.block_cursor + 4) % blocks;
    // Deadline re-arm + guard: supply moved on an overdue piece — its
    // deadline restarts from now (the "deadline until next supply
    // movement" semantic; the table write needs no separate sweep — the
    // next round's retain keeps the re-armed entry while the piece stays
    // busy-and-missing), and when this was the round's bypass dispatch
    // the piece joins the one-shot set (later peers this round resume
    // the normal freshness rules).
    if queued_ct > 0 && ctx.endgame_overdue.contains(&piece) {
        if !ctx.endgame_tail_deadline.is_zero() {
            face.endgame_deadline.insert(piece, now);
        }
        if overdue_takeover {
            ctx.endgame_overdue_done.insert(piece);
        }
    }
    queued_ct
}

/// Cross-piece supply append (the core face; spec options 1-3): after the
/// primary dispatches, if the peer is "fast" (its 30s-window rate reading
/// yields a [`multi_piece_supply_budget`] >= 2 — the window can finish the
/// current piece and secondaries) and the checkout cap
/// ([`multi_piece_checkout_cap`]) has room, append secondary pieces in
/// adjacent order ([`next_adjacent_supply_piece`], the goff-contiguous
/// chain) until the supply cap is exhausted or no contiguous piece is
/// dispatchable. Secondaries are independent pieces: candidate filtering /
/// claims / spread / x2 / transfer-cancel semantics all go through
/// [`issue_piece_blocks`]' existing discipline (the spec's "secondaries
/// are independent pieces; claim/spread semantics as usual").
///
/// Dispatch order = **primary -> old-secondary continuation -> new
/// append** (in-flight chains are finished first — when old-chain blocks
/// consume the supply, no new piece opens this round, converging the
/// spread; an old secondary's expired blocks are taken over and resent
/// here every round, independent of the primary's contiguity — nothing
/// strands).
///
/// Soft accounting (`BH_CHECKOUT_SOFT_ACCOUNTING`, default on): with it
/// on, step 3's checkout count goes through the [`checkout_occupancy`] ON
/// arm (secondary occupancy = the in-flight block total folded into whole
/// pieces) — half-arrived pieces release slots proportionally and new
/// pieces append earlier (the sawtooth of refilling a whole batch at once
/// -> a continuous block-by-block flow); `=0` restores the old whole-piece
/// count bit-for-bit. The append loop's `supply_cap` (window dimension)
/// and steps 1-2 (the continuable filter / continuation / claimed) are
/// structurally identical — soft accounting only widens the cap
/// dimension.
///
/// e chain-break softening (`BH_ADJACENT_SKIP_N`, default 2; `=0` is the
/// explicit fallback arm): step 4's chain scan goes through
/// [`next_adjacent_supply_piece_skipping`] — soft breakpoints (done /
/// claimed / unadvertised but goff-contiguous) skip <= N pieces to
/// continue the chain (at most N per round; skipped pieces count no
/// checkout occupancy); hard breakpoints (goff discontinuity) still
/// break; `=0` = the old [`next_adjacent_supply_piece`] break behavior
/// bit-for-bit. Selection-side only — checkout bookkeeping / the
/// window-dimension `supply_cap` / claim semantics unchanged.
pub(super) fn supply_adjacent_pieces(
    face: &mut FaceState,
    ctx: &mut PieceIssueCtx<'_>,
    primary: u64,
    done: &[bool],
) {
    supply_adjacent_pieces_with(
        face,
        ctx,
        primary,
        done,
        checkout_soft_accounting(),
        adjacent_skip_n(),
    )
}

/// The switch-injection form of the above (the test seam — the environment
/// is process-immutable (edition 2024 has no set_var), so both switch arms
/// are driven by parameters; the production entry reads
/// [`checkout_soft_accounting`] / [`adjacent_skip_n`]).
pub(super) fn supply_adjacent_pieces_with(
    face: &mut FaceState,
    ctx: &mut PieceIssueCtx<'_>,
    primary: u64,
    done: &[bool],
    soft: bool,
    max_skip: u64,
) {
    let Some(cuid) = ctx.my_cuid else {
        return;
    };
    // 1. Secondary inventory (lazy invalidation): keep only entries still
    // continuable (done / cleared bookkeeping counts as returned —
    // [`own_piece_continuable`], the same criterion as the primary
    // checkout); the vector order = the append order.
    let continuable: Vec<u64> = face
        .peer_state
        .get(&cuid)
        .map(|ps| {
            ps.extra_pieces
                .iter()
                .copied()
                .filter(|&p| own_piece_continuable(face, p))
                .collect()
        })
        .unwrap_or_default();
    if let Some(ps) = face.peer_state.get_mut(&cuid) {
        ps.extra_pieces = continuable.clone();
    }
    // 2. Old-secondary continuation (the primary already dispatched;
    // within the supply room, take over expired blocks / fill outstanding
    // ones).
    for p in &continuable {
        if *p == primary {
            continue;
        }
        if *ctx.supply_cap == 0 {
            break;
        }
        let _ = issue_piece_blocks(face, ctx, *p);
    }
    // 3. Append budget: stop when the checkout count (primary +
    // secondaries) reaches the cap; if the rate gate (the 30s-window
    // reading -> budget >= 2) is not met the whole arm is bypassed (the
    // single-piece rhythm). The count goes through the
    // [`checkout_occupancy`] single source — soft on = the secondaries'
    // in-flight block total folded into whole pieces (the data source
    // [`piece_live_inflight_blocks`]; after step 2's continuation the
    // reading IS the current outstanding; the folding unit = the primary's
    // blocks-per-piece — adjacent chains share the nominal piece length,
    // and a shorter last piece only under-counts its occupancy =
    // conservative); soft off = the whole-piece count `1 + continuable`
    // bit-for-bit (the folding inputs are not computed or consumed — the
    // OFF arm, `=0` fallback, adds zero scans; the `0/0` placeholders pin
    // the decision table's "OFF row ignores inputs").
    let cap = multi_piece_checkout_cap();
    let mut checked_out = if soft {
        let primary_len = face.piece_bytes.get(primary as usize).copied().unwrap_or(0);
        let bpp = primary_len.div_ceil(ctx.block).max(1) as u32;
        let live_total: u32 = continuable
            .iter()
            .copied()
            .map(|p| piece_live_inflight_blocks(face, p))
            .sum();
        checkout_occupancy(true, continuable.len(), live_total, bpp)
    } else {
        checkout_occupancy(false, continuable.len(), 0, 0)
    };
    if checked_out >= cap {
        return;
    }
    let rate_bps = face
        .peer_state
        .get(&cuid)
        .and_then(|ps| ps.down_window.as_ref())
        .map(|w| w.rate())
        .unwrap_or(0.0);
    let primary_len = face.piece_bytes.get(primary as usize).copied().unwrap_or(0);
    let budget = multi_piece_supply_budget(rate_bps as u64, primary_len);
    if budget < 2 {
        return;
    }
    // 4. Adjacent append: the chain front = the last secondary (continuing
    // the existing chain's read-ahead run); with no secondaries, start
    // from the primary. A dry piece (no dispatchable blocks / cap
    // interception) does not advance the count but does advance the front
    // (the front piece is already on this peer's claim face — the chain
    // keeps extending). e: the scan goes through
    // [`next_adjacent_supply_piece_skipping`] — soft breakpoints are
    // skipped, deducting the round-level `skip_budget` per hop (at most N
    // per round; an exhausted budget returns to zero tolerance of soft
    // breakpoints = the old break behavior); skipped pieces are not
    // dispatched, not claimed, and do not enter checked_out (occupancy
    // counts only actually enqueued pieces — the selection-side-only red
    // line).
    let mut frontier = continuable.last().copied().unwrap_or(primary);
    let mut appended = 0u64;
    let mut skip_budget = max_skip;
    while *ctx.supply_cap > 0 && checked_out < cap {
        // With the budget exhausted (including the N=0 default-off), take
        // the old scan function bit-for-bit — zero soft-breakpoint
        // tolerance (a code-path-level guarantee of zero behavior
        // difference when off); with budget left, take the skipping scan.
        let picked = if skip_budget == 0 {
            next_adjacent_supply_piece(face, frontier, done, ctx.claimed, ctx.peer_i)
                .map(|next| (next, 0u64))
        } else {
            next_adjacent_supply_piece_skipping(
                face,
                frontier,
                skip_budget,
                done,
                ctx.claimed,
                ctx.peer_i,
            )
        };
        let Some((next, skipped)) = picked else {
            break;
        };
        skip_budget -= skipped;
        frontier = next;
        let queued = issue_piece_blocks(face, ctx, next);
        if queued > 0 {
            let extras = &mut face.peer_state_row(cuid).extra_pieces;
            if !extras.contains(&next) {
                extras.push(next);
            }
            checked_out += 1;
            appended += 1;
        }
    }
    if appended > 0 {
        debug!(target: "taiji::core::engine", face = ctx.fi, peer = ctx.peer_i,
            budget, checked_out, appended,
            "multi-piece supply: adjacent pieces appended");
    }
}

/// Cancel in-flight on piece verify (cancel-on-verified): the moment a
/// piece passes verification, send Cancel to every known request holder
/// for that piece (fire-and-forget; the peer-side
/// `RequestBook::cancel_with_grace` silently skips when there is no slot,
/// withdraws the slot and sends a wire Cancel when there is, and accepts a
/// late delivery as redundancy under the grace — slow peers are not
/// misjudged). `targets` = the caller's `take_piece_dispatch_targets`
/// product (begin -> cuid, the same extraction order as the forensics
/// face; read-only here).
///
/// # Reference
///
/// libtorrent `torrent::cancel_block` (`torrent.cpp`: `cancel_request` on
/// every connection; the block-level form `num_peers(block) > 1` ->
/// cancel) — this anchor generalizes the same discipline to the **piece
/// completion moment**: after verification, every in-flight delivery of
/// the piece is pure redundancy (the pipeline drops "late block for
/// verified piece"), and not cancelling lets the remaining blocks keep
/// flowing from every delivering peer's send queue. aria2's same-effect
/// structure: per-peer whole-piece checkout (`DefaultPieceStorage.cc`) +
/// the receiving side's "Already have this block." drop
/// (`BtPieceMessage.cc`) + fillPiece no longer requesting finished pieces
/// — the local side was missing the "cancel issued requests at piece
/// completion" half.
///
/// # Deliberately NOT cancelled (the dual face)
///
/// PieceDropped (hash failure) / PieceEvicted (cache eviction): the
/// `received` bitmap has reset with the event, so the in-flight delivery
/// **is exactly the refetch** — cancelling it would self-inflict (a
/// refetch amplification); the bookkeeping cleanup at those two moments is
/// the existing face, untouched.
pub(super) fn cancel_piece_requests_on_verify(
    faces: &mut [FaceState],
    fi: usize,
    index: u64,
    targets: &std::collections::HashMap<u32, u64>,
) {
    if targets.is_empty() {
        return;
    }
    let face = &mut faces[fi];
    let Some(id) = face.addressing.from_wire(index as u32) else {
        return;
    };
    // The request length must match dispatch time byte-for-byte (the
    // RequestBook slot key = (id, begin, length); a mismatch = a silently
    // ineffective cancel): the same `min(nbytes - bi*block, block)` formula
    // and the same `piece_bytes` source.
    let block = u64::from(merkle::BLOCK_SIZE);
    let nbytes = face.piece_bytes.get(index as usize).copied().unwrap_or(0);
    let mut cancels = 0usize;
    for (&begin, &cuid) in targets {
        let length = nbytes.saturating_sub(u64::from(begin) * block).min(block) as u32;
        let Some(pos) = face.peer_cuids.iter().position(|&c| c == cuid) else {
            continue;
        };
        if face.peers[pos]
            .command(taiji_bt::peer::PeerCommand::CancelPiece { id, begin, length })
            .is_ok()
        {
            cancels += 1;
        }
    }
    if cancels > 0 {
        debug!(target: "taiji::core::engine", face = fi, piece = index,
            cancels, holders = targets.len(),
            "piece verified: cancel in-flight requests to holders");
    }
}
/// The v2 face's requester-side data plane (the [`build_v2_data_plane`]
/// product).
pub(super) struct V2DataPlane {
    pub(super) trees: Option<Arc<Mutex<HashTreeCache>>>,
    /// Flat piece order -> (file root, the file-internal leaf index of the
    /// piece's first leaf).
    pub(super) piece_leaves: Arc<Vec<([u8; 32], u64)>>,
    /// Flat piece order -> (file_index, piece_in_file) (the logging
    /// reading and lazy-fetch gating).
    pub(super) coords: Arc<Vec<(u32, u32)>>,
    pub(super) layers: Vec<FileLayerState>,
    /// Recovery bookkeeping (entries = multi-piece files missing their
    /// piece layers entry; an entry present but corrupt is the
    /// reject-at-load face's job, not covered by recovery).
    pub(super) recovery: RecoveryBook,
}

impl V2DataPlane {
    pub(super) fn empty() -> V2DataPlane {
        V2DataPlane {
            trees: None,
            piece_leaves: Arc::new(Vec::new()),
            coords: Arc::new(Vec::new()),
            layers: Vec::new(),
            recovery: RecoveryBook::default(),
        }
    }
}

/// Builds the v2 face's requester-side data plane:
/// - HashTreeCache: the metadata piece layer is the trusted anchor
/// (verified at bt::filetree load); for <= 16KiB single-block files the
/// leaf hash == the pieces root, admitted at load (the tree IS the
/// single leaf, the BEP 52 tree rule);
/// - flat piece -> (file, piece_in_file) coordinate table (the logging
/// reading) and flat -> (root, first-leaf index) table (block-level
/// verification);
/// - per-file lazy-fetch plans (base=0, length <= 512, see
/// [`taiji_domain::hash_fetch`]).
///
/// Non-v2 faces (hash_files = None) get the all-empty shell (v1 path
/// behavior unchanged).
pub(super) fn build_v2_data_plane(
    hash_files: Option<&[MetaFile]>,
    addressing: Addressing,
    piece_len: u32,
) -> V2DataPlane {
    let files = match hash_files {
        Some(f) if !f.is_empty() => f,
        _ => return V2DataPlane::empty(),
    };
    let Addressing::PerFile { piece_bases } = &addressing else {
        // Unreachable fail-fast (the original form swallowed this branch
        // into an empty data plane — a real occurrence would silently
        // disable v2 instead of erroring). Construction-path proof (v2
        // faces are always PerFile): this function only gets here with
        // `hash_files = Some(non-empty)`, and the repo's production
        // FaceConfig constructors are metainfo `v1_face` (Flat +
        // hash_files = None) and `v2_face` (`Addressing::per_file` +
        // hash_files = Some, produced by the same struct literal); every
        // other literal is a test fixture with hash_files = None (the only
        // Some integration face, bep53_select, also pairs
        // `Addressing::per_file`). The `addressing` and `hash_files`
        // fields are type-independent and the invariant is not bound by
        // the type system — a future caller's violation surfaces here
        // explicitly; silent degradation is forbidden.
        unreachable!(
            "v2 data plane requires PerFile addressing (metainfo v2_face construction invariant)"
        )
    };
    let bpp = u64::from(piece_len / merkle::BLOCK_SIZE);
    let mut trees = HashTreeCache::new(piece_len);
    let mut piece_leaves = Vec::new();
    let mut coords: Vec<(u32, u32)> = Vec::new();
    let mut layers = Vec::new();
    let mut recovery = RecoveryBook::default();
    for (fi, f) in files.iter().enumerate() {
        let pieces = f.length.div_ceil(u64::from(piece_len));
        // The file's flat piece base (extracted once per loop iteration,
        // shared by the root-present/absent/missing branches — the old
        // happy path re-derived the same expression). `unwrap_or(0)` = a
        // base-table mismatch defense (the `Addressing::per_file`
        // construction guarantees fi < len and bases[0] = 0; never taken
        // on normal paths).
        let base = piece_bases.get(fi).copied().unwrap_or(0);
        let Some(root) = f.pieces_root else {
            // A non-empty v2 file must have a root (guaranteed by the parse
            // face) — a defensive path: the placeholder keeps flat
            // coordinates aligned and the whole file is marked fallback
            // (neither lazy fetch nor block verification applies).
            for p in 0..pieces as u32 {
                coords.push((fi as u32, p));
                piece_leaves.push(([0u8; 32], u64::from(p) * bpp));
            }
            layers.push(FileLayerState {
                root: [0u8; 32],
                piece_base: base,
                leaf_total: pieces * bpp,
                plans: Vec::new(),
                state: LayerFetchState::Failed,
                attempts: 0,
            });
            continue;
        };
        let anchors: Vec<[u8; 32]> = match &f.piece_layer {
            Some(layer) if layer.len() == pieces as usize * 32 => layer
                .chunks_exact(32)
                .map(|c| {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(c);
                    h
                })
                .collect(),
            _ if pieces == 1 => vec![root],
            // Metadata piece layer missing or size mismatch. Missing (the
            // parse face downgraded to layer_missing and continues loading
            // — this branch is the production live path):
            // - register in the recovery bookkeeping (the planner
            // activates: layer_missing -> a whole-file piece-layer
            // fetch);
            // - FileLayerState set **Pending** (the lazy-fetch gate
            // "Pending => continue" = no dispatch until the layer lands
            // — a missing-layer piece's expected root can only be the
            // placeholder root, which structurally cannot pass
            // verification (verify-before-write); letting dispatch
            // through would only manufacture a verification-failure
            // refetch storm; the gate release after admission belongs to
            // the C-3 / pipeline expected-root seam).
            // Size mismatch (a corrupt form — the parse face rejects at
            // load and never reaches here; a defensive branch) registers
            // no recovery and the whole-file fallback stands (the
            // libtorrent torrent.cpp hard-error split).
            _ => {
                let layer_absent = f.piece_layer.is_none();
                if layer_absent {
                    match FileRecovery::new(root, f.length, piece_len, base) {
                        Some(rec) => {
                            recovery.files.insert(fi, rec);
                        }
                        None => {
                            debug!(target: "taiji::core::engine", file_index = fi,
                                pieces, "layer-missing file needs no recovery (single piece)");
                        }
                    }
                }
                for p in 0..pieces as u32 {
                    coords.push((fi as u32, p));
                    piece_leaves.push(([0u8; 32], u64::from(p) * bpp));
                }
                layers.push(FileLayerState {
                    root: [0u8; 32],
                    piece_base: base,
                    leaf_total: pieces * bpp,
                    plans: Vec::new(),
                    state: if layer_absent {
                        LayerFetchState::Pending
                    } else {
                        LayerFetchState::Failed
                    },
                    attempts: 0,
                });
                continue;
            }
        };
        trees.add_file(root, anchors);
        if pieces == 1 && bpp == 1 {
            // Single-block file: the leaf == the pieces root (the tree IS
            // the single leaf); no lazy fetch needed.
            let _ = trees.verify_and_put_layer(&root, 0, 0, vec![root]);
        }
        for p in 0..pieces as u32 {
            coords.push((fi as u32, p));
            // The leaf index is this file's own tree order (0-based per
            // file — HashTreeCache keeps one tree per file; verify_block's
            // leaf_index is file-internal).
            piece_leaves.push((root, u64::from(p) * bpp));
        }
        let plans = hash_fetch::plan_base_layer_fetch(f.length, piece_len);
        let state = if plans.is_empty() {
            LayerFetchState::Done
        } else {
            LayerFetchState::Queued { next: 0 }
        };
        layers.push(FileLayerState {
            root,
            piece_base: base,
            leaf_total: pieces * bpp,
            plans,
            state,
            attempts: 0,
        });
    }
    V2DataPlane {
        trees: Some(Arc::new(Mutex::new(trees))),
        piece_leaves: Arc::new(piece_leaves),
        coords: Arc::new(coords),
        layers,
        recovery,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PieceSentLedger structure test: set / owner / time expiry /
    /// out-of-range / lifecycle transitions / index re-marking — the
    /// structural contract of the inline fixed-width ledger (a shape lock
    /// on the unchanged four-state machine semantics).
    #[test]
    fn piece_sent_ledger_struct_contract() {
        let t0 = Instant::now();
        let mut l = PieceSentLedger::new(4, t0);
        let blk = u64::from(merkle::BLOCK_SIZE);

        // Initial face: all None/unowned, counts 0.
        assert_eq!(l.block_state(0), BlockState::None);
        assert_eq!(l.owner_of(0), None);
        assert_eq!(l.tracked_count(), 0);
        assert!(!l.has_live_inflight());
        assert_eq!(l.live_inflight_count(), 0);

        // Set + own: set_inflight writes state / owner / refreshes the
        // piece-level timestamp.
        let t1 = t0 + Duration::from_secs(1);
        l.set_inflight(0, Some(2), t1);
        assert_eq!(l.block_state(0), BlockState::InFlight);
        assert_eq!(l.owner_of(0), Some(2));
        assert_eq!(
            l.dispatched_at(),
            t1,
            "dispatch write refreshes the shared timestamp"
        );
        assert_eq!(l.tracked_count(), 1);
        assert!(l.has_live_inflight());
        // An owner = None write does not overwrite existing ownership
        // (absent peer bookkeeping keeps the old value — aligned with the
        // old block_dispatch not writing).
        l.set_inflight(0, None, t1);
        assert_eq!(l.owner_of(0), Some(2));

        // Duplicate hop: InFlightDup + arrival across phases (the dup
        // criterion survives) + settle.
        l.set_inflight_dup(blk as u32, Some(3), t1);
        assert_eq!(l.block_state(blk as u32), BlockState::InFlightDup);
        assert_eq!(l.live_inflight_count(), 2);
        l.arrive(blk as u32);
        assert_eq!(l.block_state(blk as u32), BlockState::SettlingDup);
        assert_eq!(
            l.live_inflight_count(),
            1,
            "SettlingDup takes no wire-segment accounting"
        );
        assert_eq!(
            l.settle_buffered(blk as u32),
            Some(true),
            "dup criterion survives across phases"
        );
        assert_eq!(l.block_state(blk as u32), BlockState::Buffered);
        assert_eq!(
            l.owner_of(blk as u32),
            Some(3),
            "ownership survives across phases with the slot"
        );
        // A non-dup settle does not trigger the sibling-cancel criterion.
        l.arrive(0);
        assert_eq!(l.block_state(0), BlockState::Settling);
        l.arrive(0);
        assert_eq!(
            l.block_state(0),
            BlockState::Settling,
            "repeated arrival is idempotent"
        );
        assert_eq!(l.settle_buffered(0), Some(false));
        // Arrival and settle on Buffered/absent coordinates = no-op.
        l.arrive(blk as u32);
        assert_eq!(l.block_state(blk as u32), BlockState::Buffered);
        assert_eq!(
            l.settle_buffered(49_152),
            None,
            "settle on an unbooked slot is a no-op"
        );
        l.arrive(49_152);
        assert_eq!(l.block_state(49_152), BlockState::None);

        // Time expiry (piece-level shared): fresh/expired judged against
        // the window via dispatched_at.
        let window = Duration::from_secs(2);
        assert!(
            t1.duration_since(l.dispatched_at()) < window,
            "shared timestamp = the last dispatch write"
        );
        let stale = t0 - window - Duration::from_millis(50);
        let mut ls = PieceSentLedger::new(1, stale);
        ls.set_inflight(0, Some(7), stale);
        assert!(
            Instant::now().duration_since(ls.dispatched_at()) >= window,
            "expired reading face (the freshness window is taken at the consumption point)"
        );

        // Clear slot: state + owner removed together; counts fall back.
        l.clear_slot(0);
        assert_eq!(l.block_state(0), BlockState::None);
        assert_eq!(l.owner_of(0), None);
        assert_eq!(l.tracked_count(), 1, "only the Buffered slot remains");

        // Out-of-range defense: block coordinates >= slots.len() read as
        // None/unowned, writes ignored.
        let oob = (4 * blk) as u32;
        assert_eq!(l.block_state(oob), BlockState::None);
        assert_eq!(l.owner_of(oob), None);
        l.set_inflight(oob, Some(1), t1);
        l.clear_slot(oob);
        assert_eq!(l.tracked_count(), 1, "out-of-bounds writes are not booked");

        // Index re-marking (peer departure): == -> unowned; > -> shift
        // left one; < untouched.
        l.set_inflight((2 * blk) as u32, Some(0), t1);
        l.set_inflight((3 * blk) as u32, Some(1), t1);
        l.reindex_owners(1);
        assert_eq!(l.owner_of(0), None, "cleared slot has no owner");
        assert_eq!(
            l.owner_of((3 * blk) as u32),
            None,
            "== removed -> unowned (same verdict as the old cuid-lookup failure fallback)"
        );
        assert_eq!(l.owner_of((2 * blk) as u32), Some(0), "< removed untouched");
        assert_eq!(
            l.owner_of(blk as u32),
            Some(2),
            "> removed shifts left one (Buffered slot owner 3 -> 2 — ownership survives across phases with the slot)"
        );
    }

    /// The in-row memory anchor: 8B slots x 16 blocks = 128B per piece row
    /// — the spec's structural budget pinned at compile time (after
    /// alignment BlockSlot = 1B state + 4B owner).
    #[test]
    fn piece_sent_ledger_slot_budget() {
        assert_eq!(std::mem::size_of::<BlockSlot>(), 8);
        assert_eq!(
            std::mem::size_of::<PieceSentLedger>() - std::mem::size_of::<Box<[BlockSlot]>>(),
            std::mem::size_of::<Instant>(),
            "row header = the shared timestamp (zero payload beyond the Box \
             slice fat pointer for the slots array)"
        );
        let l = PieceSentLedger::new(16, Instant::now());
        assert_eq!(
            std::mem::size_of_val(l.slots()),
            16 * 8,
            "16 blocks/piece = 128B per piece row"
        );
    }

    /// Fail-fast lock: the v2 data plane accepts only PerFile addressing
    /// (the construction-path invariant, evidence chain in the
    /// [`build_v2_data_plane`] branch comments) — a non-PerFile input must
    /// panic explicitly, never be swallowed into an empty data plane (the
    /// old form that silently disabled v2 is eradicated).
    #[test]
    #[should_panic(expected = "v2 data plane requires PerFile addressing")]
    fn v2_data_plane_non_per_file_addressing_fails_fast() {
        let files = vec![MetaFile {
            path: std::path::PathBuf::from("f.bin"),
            length: 16384,
            padding: false,
            pieces_root: Some([0u8; 32]),
            piece_layer: None,
            v1_offset: None,
        }];
        let _ = build_v2_data_plane(Some(&files), Addressing::Flat, 16384);
    }

    /// The partial hard-gate decision table (goal 5; the
    /// [`partial_gate_triggered`] pure function; reference
    /// `piece_picker.cpp`, both inequalities strictly >).
    #[test]
    fn partial_gate_decision_table() {
        // Row 1: partials > peers x 3/2 (3 x 3/2 = 4; 5 > 4 triggers).
        assert!(partial_gate_triggered(5, 3, 10));
        // Row 2: exactly at the threshold (4 = 4) does not trigger —
        // strictly > (the same verdict as the cpp).
        assert!(!partial_gate_triggered(4, 3, 10));
        // Row 3: piece count under, but partial block total > 2048 (= the
        // 32MiB reading) triggers.
        assert!(partial_gate_triggered(2, 10, PARTIAL_BLOCK_GATE + 1));
        // Row 4: exactly 2048 does not trigger (strictly >, the same
        // verdict as the cpp).
        assert!(!partial_gate_triggered(2, 10, PARTIAL_BLOCK_GATE));
        // Row 5: with zero peers any partial piece triggers (3/2 x 0 = 0;
        // > 0 triggers).
        assert!(partial_gate_triggered(1, 0, 1));
        // Row 6: both zero is safe.
        assert!(!partial_gate_triggered(0, 5, 0));
    }

    /// The gate-round selection decision table (the `preferred`
    /// consumption face of [`select_rarest_two_phase_one_pass`] = the
    /// local prioritize_partials landing; reference `piece_picker.cpp`):
    /// in gate rounds the partial-piece table hits first, within the table
    /// the rarest wins, and an all-unavailable table falls back to the
    /// bucket-read two-phase; in non-gate rounds (empty table) verdicts
    /// match the old two-phase bit-for-bit.
    #[test]
    fn partial_preferred_selection_table() {
        let mut stat = PieceStatMan::new(6, &mut |n| n / 2);
        // Counts: piece 2 has count 1 (the globally unique rarest); pieces
        // 0/1/3/5 have count 2; piece 4 has count 3 (a partial-table
        // member). Shuffle order (|n| n/2) = [0,5,1,4,2,3].
        stat.add_bitfield(|i| i != 2 && i != 4, 6); // 0,1,3,5 → 1
        stat.add_bitfield(|i| i != 2 && i != 4, 6); // 0,1,3,5 → 2
        stat.add_piece(2); // piece 2 -> count 1
        stat.add_piece(4);
        stat.add_piece(4);
        stat.add_piece(4); // piece 4 -> count 3
        let avail = Some(PieceBitmap::ones(6));
        let done = [false; 6];
        let claimed = ClaimedSet::empty();
        // Row 1 (gate round): table = [4] — piece 4 wins despite piece 2
        // being rarer.
        assert_eq!(
            select_rarest_two_phase_one_pass(avail.as_ref(), &done, &stat, &claimed, &[4], None),
            Some(4),
            "gate round: partial-piece table wins (prioritize_partials semantics)"
        );
        // Row 2 (gate round, rarest within the table): table = [4, 0];
        // piece 0 (count 2) is rarer than piece 4 (count 3) -> 0.
        assert_eq!(
            select_rarest_two_phase_one_pass(avail.as_ref(), &done, &stat, &claimed, &[4, 0], None),
            Some(0),
            "gate round: rarest within the table wins"
        );
        // Row 3 (gate round, table all unavailable): every member done ->
        // fall back to the bucket-read two-phase (the globally unique
        // rarest piece 2).
        let done_4 = [false, false, false, false, true, false];
        assert_eq!(
            select_rarest_two_phase_one_pass(avail.as_ref(), &done_4, &stat, &claimed, &[4], None),
            Some(2),
            "gate round: all-unavailable table falls back to the globally rarest"
        );
        // Row 4 (non-gate round, empty table): the same verdict as the old
        // two-phase — the globally unique rarest piece 2.
        assert_eq!(
            select_rarest_two_phase_one_pass(avail.as_ref(), &done, &stat, &claimed, &[], None),
            Some(2),
            "non-gate round: empty table = zero verdict change"
        );
        // Row 5 (claim exclusivity survives the gate wiring): the globally
        // rarest piece 2 (count-1 bucket) is claimed -> spread falls to
        // the count-2 bucket, first unclaimed eligible in shuffle order =
        // piece 0 (first in order).
        let mut claimed2 = ClaimedSet::with_len(6);
        claimed2.mark_claimed(2);
        assert_eq!(
            select_rarest_two_phase_one_pass(avail.as_ref(), &done, &stat, &claimed2, &[], None),
            Some(0),
            "spread-round claim exclusivity unaffected by the gate wiring"
        );
        // Row 6: nothing selectable -> None.
        let all_done = [true; 6];
        assert_eq!(
            select_rarest_two_phase_one_pass(
                avail.as_ref(),
                &all_done,
                &stat,
                &claimed,
                &[4],
                None
            ),
            None,
            "all done -> None"
        );
    }
}

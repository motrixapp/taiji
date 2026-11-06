//! Per-source health ledger and EWMA-weighted share arbitration
//! (multi-source allocation).
//!
//! Division of labor (health vs rate): the two ledgers do not
//! substitute for each other — rate weights are driven by the
//! per-source EWMA in [`crate::rate`] (fast sources claim more —
//! allocation preference); demotion/removal is driven by
//! **transport-class extent failures** (source reliability — the
//! admission decision). Windowed failure-rate thresholds: within the
//! last [`OUTCOME_WINDOW`] extent outcomes, failures >=
//! [`DEMOTE_THRESHOLD`] demote (weight halved) and >=
//! [`REMOVE_THRESHOLD`] remove (the source leaves the task's source
//! set); when in-window failures fall back below the demotion
//! threshold, full weight is restored; removal is terminal (all
//! sources removed → `taiji.http.no_source` — re-entry would let a
//! faulty source pollute shard progress over and over).
//!
//! Why the verdict domain is a **window** and not "consecutive in
//! decision order": under concurrent workers, success and failure
//! reports arrive interleaved, and an isolated success would zero a
//! consecutive counter — failure/success flapping could evade
//! demotion/removal forever, and the worker failure-cap rebirth loop
//! (spawn → fail 5 extents → exit → respawn) would never converge on
//! budget. The window is robust to interleaving: failures keep
//! accumulating inside it and an isolated success does not clear the
//! account (yet a long-term healthy source is not wronged either —
//! successes push failures out of the window and it recovers).
//!
//! Runtime length mismatch is re-decided in this ledger too:
//! probe-time mismatches are decided by the [`crate::probe`] merge
//! table (`mirror_mismatch` / `--checksum` length-group elimination);
//! runtime source length drift (authoritative total change) surfaces
//! as that source's Range/transport-class failure → booked here →
//! removal, and the surviving sources take over; all removed →
//! `no_source`.
//!
//! EWMA-weighted share arbitration: the rate composition of the
//! allocation size still belongs to the single coordinator formula
//! (this module does not rewrite the formula); weighted rotation is a
//! **cross-source share arbitration** layered on top of the formula
//! output: source i's holdings (in-flight undecided bytes) must not
//! exceed `live × w_i / Σw` (w = rate EWMA, demoted sources halved,
//! unestablished sources anchored to the established-source mean —
//! see [`SourceBook::weights`]; weights share the unit/magnitude of
//! rate: "no evidence, no favoritism"). An over-share source's
//! allocation is clamped to the min-chunk floor (claims less, leaves
//! the pool to fast sources); within share, the formula output passes
//! through unchanged.
//!
//! The ledger is owned exclusively by the ExtentCoordinator actor
//! (message passing is the synchronization point; no shared locks).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::{BTreeMap, VecDeque};

/// Extent-failure demotion threshold (3 extent failures demote;
/// the verdict domain is the windowed failure rate — see
/// [`OUTCOME_WINDOW`]).
pub const DEMOTE_THRESHOLD: u32 = 3;

/// Extent-failure removal threshold (5 removes; same windowed
/// domain).
pub const REMOVE_THRESHOLD: u32 = 5;

/// Decision-window capacity (the sample domain of the windowed
/// failure rate): each source keeps its last `OUTCOME_WINDOW` extent
/// outcomes (failures/successes); demotion/removal compares the
/// in-window failure count against the thresholds above. The capacity
/// is several times the removal threshold — a healthy source's
/// isolated failures are pushed out of the window by successes and
/// never accumulate into a transition.
pub const OUTCOME_WINDOW: usize = 8;

/// Weight reduction factor for demoted sources: the quantification of
/// "demoted" (share halved; fast sources take over first).
pub const DEMOTED_WEIGHT_FACTOR: f64 = 0.5;

/// Equal weight when no source has an established rate EWMA (no
/// evidence, equal shares — isomorphic to the rate term's +∞ pure
/// guided). When established sources exist, unestablished sources
/// anchor to the established-source rate mean
/// ([`SourceBook::weights`]) — weights keep the same unit/magnitude
/// as rate (bytes/s), so a 1.0 constant beside MB/s-scale EWMAs
/// cannot dilute an unestablished source's share below the minimum
/// granule (the starvation shape).
pub const DEFAULT_WEIGHT: f64 = 1.0;

/// Source health state (removal is terminal; demotion can recover via
/// successes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceState {
    /// Full-weight participation in allocation.
    #[default]
    Active,
    /// Demoted (in-window failures >= [`DEMOTE_THRESHOLD`]): weight ×
    /// [`DEMOTED_WEIGHT_FACTOR`]; recovers to
    /// [`SourceState::Active`] once in-window failures fall below the
    /// threshold.
    Demoted,
    /// Removed (in-window failures >= [`REMOVE_THRESHOLD`]): leaves
    /// the task's source set (terminal; Acquire closes out).
    Removed,
}

/// One health-state transition (the return face of
/// [`SourceBook::note_failure`] / [`SourceBook::note_success`]; the
/// value domain of `taiji_http_mirror_events_total{kind}` —
/// demote/remove/restore aligned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceEvent {
    /// Failures reached [`DEMOTE_THRESHOLD`]: demoted.
    Demoted,
    /// Failures reached [`REMOVE_THRESHOLD`]: removed (terminal).
    Removed,
    /// A demoted source's in-window failures fell below the threshold:
    /// full weight restored (the success arm's recovery transition —
    /// the decision logic is unchanged; the return face merely makes
    /// the recovery transition explicit).
    Restored,
}

/// Single-source health bookkeeping.
#[derive(Debug)]
struct SourceHealth {
    state: SourceState,
    /// Recent extent-outcome window (`true` = failure; capacity
    /// [`OUTCOME_WINDOW`], oldest evicted when full).
    window: VecDeque<bool>,
    /// In-window failure count (cache maintained incrementally on
    /// push/evict).
    window_failures: u32,
}

impl SourceHealth {
    /// Records one extent outcome (`failed` = failure) and trims
    /// window overflow.
    fn record(&mut self, failed: bool) {
        self.window.push_back(failed);
        if failed {
            self.window_failures += 1;
        }
        if self.window.len() > OUTCOME_WINDOW && self.window.pop_front() == Some(true) {
            self.window_failures = self.window_failures.saturating_sub(1);
        }
    }
}

/// Per-source health ledger (exclusive to the ExtentCoordinator
/// actor): the task source set `0..source_count` registers once;
/// demotion/removal state is maintained at runtime.
#[derive(Debug)]
pub struct SourceBook {
    entries: BTreeMap<u32, SourceHealth>,
}

impl SourceBook {
    /// Registers the task source set (the segmenting source count =
    /// the source count of the probe merge table's `Segmented`
    /// product; source ordinals are the
    /// [`crate::traits::SegId::source`] accounting domain).
    pub fn new(source_count: u32) -> Self {
        SourceBook {
            entries: (0..source_count)
                .map(|s| {
                    (
                        s,
                        SourceHealth {
                            state: SourceState::Active,
                            window: VecDeque::with_capacity(OUTCOME_WINDOW),
                            window_failures: 0,
                        },
                    )
                })
                .collect(),
        }
    }

    /// Source health state; unregistered sources (out-of-range
    /// ordinals) count as removed (not in the source set = no
    /// participation eligibility).
    pub fn state(&self, source: u32) -> SourceState {
        self.entries
            .get(&source)
            .map_or(SourceState::Removed, |h| h.state)
    }

    /// Whether the source is removed (or unregistered) — the Acquire
    /// close-out criterion.
    pub fn is_removed(&self, source: u32) -> bool {
        self.state(source) == SourceState::Removed
    }

    /// Whether every registered source is removed (→
    /// `taiji.http.no_source`). No registered sources at all
    /// (degenerate form) is also true — no usable source is the fact.
    pub fn all_removed(&self) -> bool {
        self.entries
            .values()
            .all(|h| h.state == SourceState::Removed)
    }

    /// Extent succeeded: enters the window; a demoted source recovers
    /// full weight only once in-window failures fall below the
    /// demotion threshold (an isolated success does not clear the
    /// account — flapping must not evade demotion; see
    /// [`OUTCOME_WINDOW`]). Removal is terminal and irreversible;
    /// unregistered sources are ignored. Returns `Some(event)` when a
    /// state transition happened (the recovery decision logic is
    /// untouched — the return face only makes the recovery transition
    /// explicit as [`SourceEvent::Restored`] for mirror_events
    /// counting; no transition / unregistered source → `None`).
    pub fn note_success(&mut self, source: u32) -> Option<SourceEvent> {
        let h = self.entries.get_mut(&source)?;
        h.record(false);
        if h.state == SourceState::Demoted && h.window_failures < DEMOTE_THRESHOLD {
            h.state = SourceState::Active;
            return Some(SourceEvent::Restored);
        }
        None
    }

    /// Extent failed: enters the window; threshold crossings produce
    /// demote/remove transitions. Returns `Some(event)` when a state
    /// transition happened (repeat failures / already-removed sources
    /// yield no new transition → `None`).
    pub fn note_failure(&mut self, source: u32) -> Option<SourceEvent> {
        let h = self.entries.get_mut(&source)?;
        h.record(true);
        match h.state {
            SourceState::Active if h.window_failures >= DEMOTE_THRESHOLD => {
                h.state = SourceState::Demoted;
                Some(SourceEvent::Demoted)
            }
            SourceState::Demoted if h.window_failures >= REMOVE_THRESHOLD => {
                h.state = SourceState::Removed;
                Some(SourceEvent::Removed)
            }
            _ => None,
        }
    }

    /// Source health snapshot (ascending source order;
    /// `(source, state, in-window failure count)`). The /metrics
    /// source face and the fixture reconciliation face.
    pub fn snapshot(&self) -> Vec<(u32, SourceState, u32)> {
        self.entries
            .iter()
            .map(|(&s, h)| (s, h.state, h.window_failures))
            .collect()
    }

    /// Weight iteration over registered sources (removed sources weigh
    /// 0 — outside the share denominator).
    ///
    /// Weight units match rate (bytes/s): an established-EWMA source
    /// takes its rate; an unestablished source anchors to the
    /// **established-source rate mean** (equal [`DEFAULT_WEIGHT`] when
    /// no established evidence exists). Why anchored rather than a
    /// constant 1.0: shares normalize by `w_i / Σw`; a 1.0 constant
    /// beside MB/s-scale EWMAs would dilute the unestablished source's
    /// share below the minimum granule (clamped starvation). Mean
    /// anchoring lets a new source arbitrate at "the average expected
    /// rate of proven sources" and transition smoothly to measured
    /// weights once its own EWMA establishes. Non-finite / non-positive
    /// rates do not count as evidence (defensive face; [`weight_of`]
    /// follows the same rule).
    pub fn weights(&self, rate_of: &dyn Fn(u32) -> Option<f64>) -> BTreeMap<u32, f64> {
        let established: Vec<f64> = self
            .entries
            .keys()
            .filter_map(|&s| rate_of(s))
            .filter(|r| r.is_finite() && *r > 0.0)
            .collect();
        let anchor = if established.is_empty() {
            DEFAULT_WEIGHT
        } else {
            let total: f64 = established.iter().sum();
            total / established.len() as f64
        };
        self.entries
            .iter()
            .map(|(&s, h)| {
                let rate = rate_of(s).filter(|r| r.is_finite() && *r > 0.0);
                (s, weight_of(h.state, Some(rate.unwrap_or(anchor))))
            })
            .collect()
    }
}

/// Source weight (the w of weighted rotation): rate EWMA as the base
/// (bytes/s; non-finite/non-positive defensively falls back to equal
/// weight — the normal anchoring face is [`SourceBook::weights`]),
/// demotion halves, removal is zero.
pub fn weight_of(state: SourceState, rate_bps: Option<f64>) -> f64 {
    let base = match rate_bps {
        Some(r) if r.is_finite() && r > 0.0 => r,
        _ => DEFAULT_WEIGHT,
    };
    match state {
        SourceState::Active => base,
        SourceState::Demoted => base * DEMOTED_WEIGHT_FACTOR,
        SourceState::Removed => 0.0,
    }
}

/// Share arbitration (the clamp face of weighted rotation): with the
/// source holding `holdings_bytes`, the byte ceiling for this
/// allocation = weighted share − holdings. `live_bytes` = pool
/// remainder + all sources' in-flight undecided bytes; when
/// `total_weight` <= 0 (all-removed degenerate form) or `live_bytes`
/// = 0, no limit is imposed ([`u64::MAX`] — the caller separately
/// handles removal/pool-empty close-out).
pub fn share_cap(holdings_bytes: u64, weight: f64, total_weight: f64, live_bytes: u64) -> u64 {
    if !total_weight.is_finite() || total_weight <= 0.0 || live_bytes == 0 {
        return u64::MAX;
    }
    let share = live_bytes as f64 * weight.max(0.0) / total_weight;
    // f64 multiply/divide upper bound clamped into the u64 domain
    // before integer deduction (negative share saturates to 0 —
    // over-holdings means clamped).
    let share_u = if share >= u64::MAX as f64 {
        u64::MAX
    } else {
        share.max(0.0) as u64
    };
    share_u.saturating_sub(holdings_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windowed failure-rate threshold table (thresholds 3/5 on the
    /// window domain): failures >= 3 within the last
    /// [`OUTCOME_WINDOW`] outcomes demote, >= 5 remove; an isolated
    /// success does not clear the account (no recovery while in-window
    /// failures >= threshold); removal is terminal and irreversible.
    #[test]
    fn window_failure_rate_demotes_at_three_and_removes_at_five() {
        let mut book = SourceBook::new(2);

        // 2 in-window failures: still Active, no transition.
        assert_eq!(book.note_failure(1), None);
        assert_eq!(book.note_failure(1), None);
        assert_eq!(book.state(1), SourceState::Active);

        // 3rd (in-window >= 3): demote transition.
        assert_eq!(book.note_failure(1), Some(SourceEvent::Demoted));
        assert_eq!(book.state(1), SourceState::Demoted);

        // Isolated success does not clear the account: in-window
        // failures still >= demotion threshold → no recovery.
        let _ = book.note_success(1);
        assert_eq!(
            book.state(1),
            SourceState::Demoted,
            "an isolated success does not clear the account"
        );

        // 4th failure: in-window 4 < removal threshold, no new
        // transition.
        assert_eq!(book.note_failure(1), None);
        // 5th (in-window >= 5): removed (terminal); further failures
        // yield no new transition.
        assert_eq!(book.note_failure(1), Some(SourceEvent::Removed));
        assert_eq!(book.state(1), SourceState::Removed);
        assert_eq!(
            book.note_failure(1),
            None,
            "no new transition after removal"
        );
        let _ = book.note_success(1);
        assert_eq!(
            book.state(1),
            SourceState::Removed,
            "removal is irreversible"
        );

        assert!(!book.all_removed(), "source 0 still Active");
        book.note_failure(0);
        assert!(!book.all_removed());
        for _ in 0..REMOVE_THRESHOLD {
            book.note_failure(0);
        }
        assert!(book.all_removed(), "both sources removed");
        assert_eq!(
            book.state(9),
            SourceState::Removed,
            "an unregistered source counts as removed"
        );
    }

    /// Concurrency-interleaving regression (the motivation for the
    /// window domain): when failures and successes arrive interleaved,
    /// an isolated success does not zero the failure account —
    /// failure/success flapping still demotes/removes under the window
    /// domain (a "consecutive in decision order" count would be zeroed
    /// by an interleaved success and evade transitions forever; the
    /// worker failure-cap rebirth loop would never converge on
    /// budget).
    #[test]
    fn interleaved_successes_cannot_evade_demotion_or_removal() {
        let mut book = SourceBook::new(1);

        // F F S flapping: failures keep accumulating in the window.
        assert_eq!(book.note_failure(0), None); // in-window failures 1
        assert_eq!(book.note_failure(0), None); // in-window failures 2
        let _ = book.note_success(0); // isolated success: no clear
        // 3rd failure (in-window 3 >= demotion threshold) → demoted
        // (a consecutive count would have been zeroed by the success
        // here and never demote).
        assert_eq!(book.note_failure(0), Some(SourceEvent::Demoted));
        assert_eq!(book.state(0), SourceState::Demoted);

        // Flapping continues after demotion: F (4) → S (still >= 3, no
        // recovery) → F (5) → removed — the rebirth loop converges on
        // budget.
        assert_eq!(book.note_failure(0), None);
        let _ = book.note_success(0);
        assert_eq!(
            book.state(0),
            SourceState::Demoted,
            "an isolated success does not restore"
        );
        assert_eq!(book.note_failure(0), Some(SourceEvent::Removed));
        assert_eq!(book.state(0), SourceState::Removed);
    }

    /// In-window healthy recovery: a demoted source recovers full
    /// weight once successes push its in-window failures below the
    /// demotion threshold — the window domain does not wrong
    /// long-term healthy sources.
    #[test]
    fn demoted_source_recovers_when_window_turns_healthy() {
        let mut book = SourceBook::new(1);
        for _ in 0..DEMOTE_THRESHOLD {
            book.note_failure(0);
        }
        assert_eq!(book.state(0), SourceState::Demoted);

        // Successes push failures out of the window one by one; the
        // push that brings in-window failures < 3 recovers (capacity
        // 8: 3 failures + 5 successes fill the window; the 6th success
        // evicts the first failure).
        for _ in 0..(OUTCOME_WINDOW - DEMOTE_THRESHOLD as usize) {
            assert_eq!(
                book.note_success(0),
                None,
                "in-window failures still >= 3: success yields no transition on the return face"
            );
            assert_eq!(
                book.state(0),
                SourceState::Demoted,
                "in-window failures still >= 3"
            );
        }
        // Recovery transition made explicit (the return face of the
        // signature tweak): success pushes in-window failures below
        // the threshold → Some(Restored).
        assert_eq!(book.note_success(0), Some(SourceEvent::Restored));
        assert_eq!(
            book.state(0),
            SourceState::Active,
            "in-window failures fall back -> restore"
        );
        // Further successes on an Active source yield no transition.
        assert_eq!(book.note_success(0), None);
    }

    /// Snapshot face: ascending source order, counts consistent with
    /// state (the /metrics reconciliation domain).
    #[test]
    fn snapshot_is_ordered_and_faithful() {
        let mut book = SourceBook::new(3);
        book.note_failure(2);
        book.note_failure(2);
        book.note_failure(2);
        assert_eq!(
            book.snapshot(),
            vec![
                (0, SourceState::Active, 0),
                (1, SourceState::Active, 0),
                (2, SourceState::Demoted, 3)
            ],
        );
    }

    /// Weight function: rate as base, unestablished equal weight,
    /// demotion halves, removal zero.
    #[test]
    fn weight_combines_rate_and_state() {
        assert_eq!(weight_of(SourceState::Active, None), DEFAULT_WEIGHT);
        assert_eq!(weight_of(SourceState::Active, Some(0.0)), DEFAULT_WEIGHT);
        assert_eq!(weight_of(SourceState::Active, Some(-1.0)), DEFAULT_WEIGHT);
        assert_eq!(
            weight_of(SourceState::Active, Some(f64::INFINITY)),
            DEFAULT_WEIGHT
        );
        assert_eq!(weight_of(SourceState::Active, Some(3.0)), 3.0);
        assert_eq!(weight_of(SourceState::Demoted, Some(3.0)), 1.5);
        assert_eq!(
            weight_of(SourceState::Demoted, None),
            DEFAULT_WEIGHT * DEMOTED_WEIGHT_FACTOR
        );
        assert_eq!(weight_of(SourceState::Removed, Some(3.0)), 0.0);
    }

    /// Share arbitration: 3:1 weights → 75%/25% shares; holdings
    /// deduction; demotion halves the share; degenerate inputs impose
    /// no limit.
    #[test]
    fn share_cap_splits_live_by_weights() {
        // live = 400 units, weights 3:1 → source 0 share 300, source 1
        // share 100.
        assert_eq!(share_cap(0, 3.0, 4.0, 400), 300);
        assert_eq!(share_cap(0, 1.0, 4.0, 400), 100);
        // Holdings deduction: already holding 250 → 50 remain.
        assert_eq!(share_cap(250, 3.0, 4.0, 400), 50);
        // Over-holdings → 0 (the caller clamps to the min-chunk
        // floor).
        assert_eq!(share_cap(350, 3.0, 4.0, 400), 0);
        // All-zero weights (all removed) and empty pool: no limit
        // (removal/pool-empty close out elsewhere).
        assert_eq!(share_cap(0, 0.0, 0.0, 400), u64::MAX);
        assert_eq!(share_cap(0, 3.0, 4.0, 0), u64::MAX);
    }

    /// Weight units (unestablished vs MB/s source share comparison):
    /// an unestablished source anchors to the established-source mean
    /// — beside an MB/s-scale EWMA its share keeps half-pool
    /// magnitude, not diluted by a 1.0 constant (regression: the old
    /// shape w=1.0 vs w=5MiB gave the unestablished source a share
    /// ≈ live/5e6 → clamped to min granule, starved).
    #[test]
    fn unestablished_source_anchors_to_established_mean_scale() {
        let mib: f64 = 5.0 * 1024.0 * 1024.0;
        let rates = |s: u32| (s == 0).then_some(mib);
        let w = SourceBook::new(2).weights(&rates);
        assert_eq!(
            w[&0], mib,
            "an established source's weight = the measured EWMA"
        );
        assert_eq!(
            w[&1], mib,
            "an unestablished source anchors to the established-source mean \
             (unit-consistent face)"
        );
        // Share comparison: live = 5MiB → the unestablished source's
        // share = half the pool, not 1:5e6 dilution.
        let total = w.values().copied().sum();
        assert_eq!(share_cap(0, w[&1], total, mib as u64), mib as u64 / 2);
        // Control anchor (the old-behavior shape): a 1.0 constant
        // beside 5MiB → share ≈ 1 byte.
        let legacy_cap = share_cap(0, DEFAULT_WEIGHT, DEFAULT_WEIGHT + mib, mib as u64);
        assert!(
            legacy_cap < 1024,
            "the constant-1.0 dilution shape is reproducible: {legacy_cap}"
        );
    }

    /// Anchoring-face details: the mean counts only established
    /// evidence; demotion stacks on top of the anchor; no evidence at
    /// all → all equal weight; removed sources weigh zero.
    #[test]
    fn anchor_uses_mean_of_established_rates_only() {
        let mib: f64 = 1024.0 * 1024.0;
        // Three sources: 0/1 established (1MiB, 3MiB), 2 removed —
        // mean = 2MiB; the removed source enters neither the evidence
        // nor a nonzero weight.
        let mut book = SourceBook::new(3);
        for _ in 0..REMOVE_THRESHOLD {
            book.note_failure(2);
        }
        let rates = |s: u32| match s {
            0 => Some(mib),
            1 => Some(3.0 * mib),
            _ => None,
        };
        let w = book.weights(&rates);
        assert_eq!(w[&0], mib);
        assert_eq!(w[&1], 3.0 * mib);
        assert_eq!(
            w[&2], 0.0,
            "a removed source weighs zero (not in the anchored mean)"
        );

        // Demoted unestablished source = anchor × reduction factor.
        let mut book = SourceBook::new(2);
        for _ in 0..DEMOTE_THRESHOLD {
            book.note_failure(1);
        }
        let rates = |s: u32| (s == 0).then_some(2.0 * mib);
        let w = book.weights(&rates);
        assert_eq!(w[&1], mib, "a demoted unestablished source = anchor halved");

        // No established evidence at all (non-finite values do not
        // count as evidence) → all equal DEFAULT_WEIGHT.
        let w = SourceBook::new(2).weights(&|_| None);
        assert_eq!(w[&0], DEFAULT_WEIGHT);
        assert_eq!(w[&1], DEFAULT_WEIGHT);
        let w = SourceBook::new(2).weights(&|s| (s == 0).then_some(f64::NAN));
        assert_eq!(
            w[&1], DEFAULT_WEIGHT,
            "non-finite rates do not count as evidence"
        );
    }
}

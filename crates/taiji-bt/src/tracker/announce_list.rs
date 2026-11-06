//! Tracker tier state machine (BEP12 multi-tracker).
//!
//! One-to-one port of aria2's `AnnounceTier`/`AnnounceList`: the seven
//! event states, `nextEvent`/`nextEventIfAfterStarted` transitions,
//! construction in the STARTED state, success advancing the event + moving
//! the current URL to the tier front + returning to the first tier, and
//! failure advancing URL/tier with a forced `nextEventIfAfterStarted` at
//! the end of the tiers. aria2 expresses "end of tiers / all failed" with
//! deque iterators plus `currentTrackerInitialized_`; this port uses
//! indices (`current_tier == tiers.len()` is equivalent to
//! `currentTier_ == end(tiers_)`).
//!
//! Upstream anchor mapping: docs/design/tracker.md

use std::collections::VecDeque;

use rand::seq::SliceRandom;

/// The seven tier event states (aria2 `AnnounceTier.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierEvent {
    Started,
    StartedAfterCompletion,
    Downloading,
    Stopped,
    Completed,
    Seeding,
    Halted,
}

impl TierEvent {
    /// Value of the announce URL's `event=` parameter (aria2
    /// `AnnounceList.cc` `getEventString`: STARTED/STARTED_AFTER_COMPLETION
    /// -> "started", STOPPED -> "stopped", COMPLETED -> "completed",
    /// otherwise "").
    pub fn event_str(self) -> &'static str {
        match self {
            TierEvent::Started | TierEvent::StartedAfterCompletion => "started",
            TierEvent::Stopped => "stopped",
            TierEvent::Completed => "completed",
            TierEvent::Downloading | TierEvent::Seeding | TierEvent::Halted => "",
        }
    }
}

/// A single tier: event + URL queue (aria2 `AnnounceTier.h`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceTier {
    pub event: TierEvent,
    pub urls: VecDeque<String>,
}

impl AnnounceTier {
    /// Constructed already in the STARTED state (aria2 `AnnounceTier.cc`).
    pub fn new(urls: VecDeque<String>) -> Self {
        AnnounceTier {
            event: TierEvent::Started,
            urls,
        }
    }

    /// Event advance on success (aria2 `AnnounceTier.cc`):
    /// STARTED -> DOWNLOADING, STARTED_AFTER_COMPLETION -> SEEDING,
    /// STOPPED -> HALTED, COMPLETED -> SEEDING; the rest are unchanged.
    pub fn next_event(&mut self) {
        self.event = match self.event {
            TierEvent::Started => TierEvent::Downloading,
            TierEvent::StartedAfterCompletion => TierEvent::Seeding,
            TierEvent::Stopped => TierEvent::Halted,
            TierEvent::Completed => TierEvent::Seeding,
            other => other,
        };
    }

    /// Forced advance when a failure reaches the end of the tiers (aria2
    /// `AnnounceTier.cc`): STOPPED -> HALTED, COMPLETED -> SEEDING; the
    /// rest are unchanged.
    pub fn next_event_if_after_started(&mut self) {
        self.event = match self.event {
            TierEvent::Stopped => TierEvent::Halted,
            TierEvent::Completed => TierEvent::Seeding,
            other => other,
        };
    }
}

/// Tier-list state machine (aria2 `AnnounceList`, `AnnounceList.cc`).
#[derive(Debug, Clone)]
pub struct AnnounceList {
    tiers: Vec<AnnounceTier>,
    /// `currentTier_`; `== tiers.len()` means `end(tiers_)`
    /// (allTiersFailed, `AnnounceList.cc`).
    current_tier: usize,
    /// `currentTracker_` (URL index within the current tier).
    current_tracker: usize,
    /// `currentTrackerInitialized_` (starts false in `AnnounceList.cc`).
    current_tracker_initialized: bool,
}

impl AnnounceList {
    /// Empty list (aria2 `AnnounceList.cc`).
    pub fn new() -> Self {
        AnnounceList {
            tiers: Vec::new(),
            current_tier: 0,
            current_tracker: 0,
            current_tracker_initialized: false,
        }
    }

    /// Build from a tier-of-urls table (aria2 `AnnounceList.cc`
    /// `reconfigure`: empty tiers are skipped, each tier starts at
    /// STARTED).
    pub fn from_tiers(announce_list: Vec<Vec<String>>) -> Self {
        let mut list = AnnounceList::new();
        list.reconfigure(announce_list);
        list
    }

    /// Build directly from tier objects (aria2 `AnnounceList.cc`; the event
    /// is whatever the tier carries).
    pub fn from_tier_objects(tiers: Vec<AnnounceTier>) -> Self {
        let mut list = AnnounceList {
            tiers,
            ..AnnounceList::new()
        };
        list.reset_iterator();
        list
    }

    /// Rebuild the tiers (aria2 `AnnounceList.cc`: empty tiers are
    /// skipped), then `resetIterator`.
    pub fn reconfigure(&mut self, announce_list: Vec<Vec<String>>) {
        for urls in announce_list {
            if urls.is_empty() {
                continue;
            }
            self.tiers
                .push(AnnounceTier::new(urls.into_iter().collect()));
        }
        self.reset_iterator();
    }

    /// `resetIterator` (aria2 `AnnounceList.cc`): back to the first URL of
    /// the first tier; empty list / empty first tier -> uninitialized.
    pub fn reset_iterator(&mut self) {
        self.current_tier = 0;
        if let Some(first) = self.tiers.first()
            && !first.urls.is_empty()
        {
            self.current_tracker = 0;
            self.current_tracker_initialized = true;
            return;
        }
        self.current_tracker_initialized = false;
    }

    /// `resetTier` (aria2 `AnnounceList.cc`; identical to `resetIterator`).
    pub fn reset_tier(&mut self) {
        self.reset_iterator();
    }

    /// Whether the current tier/URL is valid (`None` when uninitialized;
    /// aria2 `AnnounceList.cc`).
    pub fn get_announce(&self) -> Option<&str> {
        if self.current_tracker_initialized {
            Some(self.tiers[self.current_tier].urls[self.current_tracker].as_str())
        } else {
            None
        }
    }

    /// `announceSuccess` (aria2 `AnnounceList.cc`): advance the tier event,
    /// move the current URL to the front of its tier, and return the cursor
    /// to the first URL of the first tier.
    pub fn announce_success(&mut self) {
        if !self.current_tracker_initialized {
            return;
        }
        self.tiers[self.current_tier].next_event();
        let tier = &mut self.tiers[self.current_tier];
        // current_tracker_initialized implies the index is valid
        // (AnnounceList.cc).
        let url = match tier.urls.remove(self.current_tracker) {
            Some(u) => u,
            None => panic!("announce_success: invalid current_tracker index"),
        };
        tier.urls.push_front(url);
        self.current_tier = 0;
        self.current_tracker = 0;
    }

    /// `announceFailure` (aria2 `AnnounceList.cc`): advance the URL; at the
    /// end of a tier -> `nextEventIfAfterStarted` + advance the tier; all
    /// tiers exhausted -> uninitialized (allTiersFailed).
    pub fn announce_failure(&mut self) {
        if !self.current_tracker_initialized {
            return;
        }
        self.current_tracker += 1;
        if self.current_tracker == self.tiers[self.current_tier].urls.len() {
            // force next event (aria2 AnnounceList.cc)
            self.tiers[self.current_tier].next_event_if_after_started();
            self.current_tier += 1;
            if self.current_tier == self.tiers.len() {
                self.current_tracker_initialized = false;
            } else {
                self.current_tracker = 0;
            }
        }
    }

    /// Current tier event (aria2 `AnnounceList.cc`; STARTED when
    /// uninitialized).
    pub fn get_event(&self) -> TierEvent {
        if self.current_tracker_initialized {
            self.tiers[self.current_tier].event
        } else {
            TierEvent::Started
        }
    }

    /// Set the current tier event (aria2 `AnnounceList.cc`).
    pub fn set_event(&mut self, event: TierEvent) {
        if self.current_tracker_initialized {
            self.tiers[self.current_tier].event = event;
        }
    }

    /// `getEventString` (aria2 `AnnounceList.cc`; "" when uninitialized).
    pub fn get_event_string(&self) -> &'static str {
        if self.current_tracker_initialized {
            self.tiers[self.current_tier].event.event_str()
        } else {
            ""
        }
    }

    /// stopped allowed-set check (aria2 `AnnounceList.cc`:
    /// DOWNLOADING/STOPPED/COMPLETED/SEEDING).
    pub fn stopped_allowed(event: TierEvent) -> bool {
        matches!(
            event,
            TierEvent::Downloading | TierEvent::Stopped | TierEvent::Completed | TierEvent::Seeding
        )
    }

    /// completed allowed-set check (aria2 `AnnounceList.cc`:
    /// DOWNLOADING/COMPLETED).
    pub fn completed_allowed(event: TierEvent) -> bool {
        matches!(event, TierEvent::Downloading | TierEvent::Completed)
    }

    /// `countStoppedAllowedTier` (aria2 `AnnounceList.cc`).
    pub fn count_stopped_allowed_tier(&self) -> usize {
        self.tiers
            .iter()
            .filter(|t| Self::stopped_allowed(t.event))
            .count()
    }

    /// `countCompletedAllowedTier` (aria2 `AnnounceList.cc`).
    pub fn count_completed_allowed_tier(&self) -> usize {
        self.tiers
            .iter()
            .filter(|t| Self::completed_allowed(t.event))
            .count()
    }

    /// `setCurrentTier` (aria2 `AnnounceList.cc`: only accepts a valid
    /// iterator; on a hit the URL cursor resets to the front).
    fn set_current_tier(&mut self, tier: usize) {
        if tier != self.tiers.len() {
            self.current_tier = tier;
            self.current_tracker = 0;
        }
    }

    /// Ring-search start point (aria2 `a2algo.h` `find_wrap_if`: first
    /// `[current, last)`, then `[first, current)`; a hit on end means no
    /// match).
    fn find_wrap(&self, pred: impl Fn(&AnnounceTier) -> bool) -> usize {
        for i in self.current_tier..self.tiers.len() {
            if pred(&self.tiers[i]) {
                return i;
            }
        }
        for i in 0..self.current_tier {
            if pred(&self.tiers[i]) {
                return i;
            }
        }
        self.tiers.len()
    }

    /// `moveToStoppedAllowedTier` (aria2 `AnnounceList.cc`).
    pub fn move_to_stopped_allowed_tier(&mut self) {
        let tier = self.find_wrap(|t| Self::stopped_allowed(t.event));
        self.set_current_tier(tier);
    }

    /// `moveToCompletedAllowedTier` (aria2 `AnnounceList.cc`).
    pub fn move_to_completed_allowed_tier(&mut self) {
        let tier = self.find_wrap(|t| Self::completed_allowed(t.event));
        self.set_current_tier(tier);
    }

    /// Shuffle the URLs within each tier (aria2 `AnnounceList.cc`
    /// `shuffle`).
    pub fn shuffle(&mut self, rng: &mut impl rand::Rng) {
        for tier in &mut self.tiers {
            tier.urls.make_contiguous().shuffle(rng);
        }
    }

    /// `allTiersFailed` (aria2 `AnnounceList.cc`).
    pub fn all_tiers_failed(&self) -> bool {
        self.current_tier == self.tiers.len()
    }

    /// `currentTierAcceptsStoppedEvent` (aria2 `AnnounceList.cc`; false
    /// when uninitialized).
    pub fn current_tier_accepts_stopped_event(&self) -> bool {
        self.current_tracker_initialized
            && Self::stopped_allowed(self.tiers[self.current_tier].event)
    }

    /// `currentTierAcceptsCompletedEvent` (aria2 `AnnounceList.cc`).
    pub fn current_tier_accepts_completed_event(&self) -> bool {
        self.current_tracker_initialized
            && Self::completed_allowed(self.tiers[self.current_tier].event)
    }

    /// Number of tiers (aria2 `AnnounceList.cc`).
    pub fn count_tier(&self) -> usize {
        self.tiers.len()
    }
}

impl Default for AnnounceList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Semantic baseline: aria2 `test/AnnounceListTest.cc` (reference
    /// commit in docs/design/tracker.md, read-only). The tests below port
    /// the same-named cases assertion for assertion.
    fn tiers_of(groups: &[&[&str]]) -> AnnounceList {
        AnnounceList::from_tiers(
            groups
                .iter()
                .map(|g| g.iter().map(|s| s.to_string()).collect())
                .collect(),
        )
    }

    fn expect_announce(list: &AnnounceList, url: &str) {
        assert_eq!(list.get_announce(), Some(url));
    }

    /// AnnounceListTest::testSingleElementList
    #[test]
    fn single_element_list() {
        let mut list = tiers_of(&[&["tracker1"], &["tracker2"], &["tracker3"]]);
        assert!(!list.all_tiers_failed());
        expect_announce(&list, "tracker1");
        assert_eq!(list.get_event_string(), "started");
        list.announce_failure();
        expect_announce(&list, "tracker2");
        list.announce_failure();
        expect_announce(&list, "tracker3");
        list.announce_failure();
        assert!(list.all_tiers_failed());
        list.reset_tier();
        assert!(!list.all_tiers_failed());
        expect_announce(&list, "tracker1");
        assert_eq!(list.get_event_string(), "started");
        list.announce_failure();
        expect_announce(&list, "tracker2");
        assert_eq!(list.get_event_string(), "started");
        // tracker2 succeeds -> back to the first tier's front (tracker1).
        list.announce_success();
        expect_announce(&list, "tracker1");
        assert_eq!(list.get_event_string(), "started");
        // The first tier already failed once and the cursor is on tracker2;
        // another failure advances further.
        list.announce_failure();
        expect_announce(&list, "tracker2");
        // After the second failure the tier event has advanced (success
        // moved STARTED -> DOWNLOADING, event_str = "").
        assert_eq!(list.get_event_string(), "");
    }

    /// AnnounceListTest::testMultiElementList
    #[test]
    fn multi_element_list() {
        let mut list = tiers_of(&[&["tracker1", "tracker2", "tracker3"]]);
        assert!(!list.all_tiers_failed());
        expect_announce(&list, "tracker1");
        list.announce_failure();
        expect_announce(&list, "tracker2");
        // tracker2 succeeds -> tracker2 moves to the tier front.
        list.announce_success();
        expect_announce(&list, "tracker2");
        list.announce_failure();
        expect_announce(&list, "tracker1");
        list.announce_failure();
        expect_announce(&list, "tracker3");
        list.announce_failure();
        assert!(list.all_tiers_failed());
        list.reset_tier();
        assert!(!list.all_tiers_failed());
        // The front is still tracker2 from the last success.
        expect_announce(&list, "tracker2");
    }

    /// AnnounceListTest::testSingleAndMulti
    #[test]
    fn single_and_multi() {
        let mut list = tiers_of(&[&["tracker1", "tracker2"], &["tracker3"]]);
        expect_announce(&list, "tracker1");
        list.announce_success();
        expect_announce(&list, "tracker1");
        list.announce_failure();
        expect_announce(&list, "tracker2");
        list.announce_failure();
        expect_announce(&list, "tracker3");
        list.announce_success();
        // After tier3 succeeds the cursor returns to the first tier's front
        // (tracker1).
        expect_announce(&list, "tracker1");
    }

    /// AnnounceListTest::testNoGroup
    #[test]
    fn no_group() {
        let list = tiers_of(&[&[], &[]]);
        assert_eq!(list.count_tier(), 0);
    }

    /// AnnounceListTest::testNextEventIfAfterStarted
    #[test]
    fn next_event_if_after_started() {
        let mut list = tiers_of(&[&["tracker1"]]);
        list.set_event(TierEvent::Stopped);
        list.announce_failure();
        list.reset_tier();
        assert_eq!(list.get_event_string(), "");
        assert_eq!(list.get_event(), TierEvent::Halted);

        list.set_event(TierEvent::Completed);
        list.announce_failure();
        list.reset_tier();
        assert_eq!(list.get_event_string(), "");
        assert_eq!(list.get_event(), TierEvent::Seeding);
    }

    /// AnnounceListTest::testEvent
    #[test]
    fn event_transitions_on_success() {
        let mut list = tiers_of(&[&["tracker1"], &["tracker2"], &["tracker3"]]);
        list.set_event(TierEvent::Stopped);
        list.announce_success();
        assert_eq!(list.get_event_string(), "");
        assert_eq!(list.get_event(), TierEvent::Halted);

        list.set_event(TierEvent::Completed);
        list.announce_success();
        assert_eq!(list.get_event_string(), "");
        assert_eq!(list.get_event(), TierEvent::Seeding);

        list.set_event(TierEvent::StartedAfterCompletion);
        assert_eq!(list.get_event_string(), "started");
        list.announce_success();
        assert_eq!(list.get_event(), TierEvent::Seeding);
    }

    /// AnnounceListTest::testCountStoppedAllowedTier
    #[test]
    fn count_stopped_allowed_tier() {
        let mut list = tiers_of(&[&["tracker1"], &["tracker2"], &["tracker3"]]);
        assert_eq!(list.count_stopped_allowed_tier(), 0);
        for ev in [
            TierEvent::Started,
            TierEvent::StartedAfterCompletion,
            TierEvent::Halted,
        ] {
            list.set_event(ev);
            assert_eq!(list.count_stopped_allowed_tier(), 0, "event={ev:?}");
        }
        for ev in [
            TierEvent::Downloading,
            TierEvent::Stopped,
            TierEvent::Completed,
            TierEvent::Seeding,
        ] {
            list.set_event(ev);
            assert_eq!(list.count_stopped_allowed_tier(), 1, "event={ev:?}");
        }
    }

    /// AnnounceListTest::testCountCompletedAllowedTier
    #[test]
    fn count_completed_allowed_tier() {
        let mut list = tiers_of(&[&["tracker1"], &["tracker2"], &["tracker3"]]);
        assert_eq!(list.count_completed_allowed_tier(), 0);
        for ev in [
            TierEvent::Started,
            TierEvent::StartedAfterCompletion,
            TierEvent::Stopped,
            TierEvent::Seeding,
            TierEvent::Halted,
        ] {
            list.set_event(ev);
            assert_eq!(list.count_completed_allowed_tier(), 0, "event={ev:?}");
        }
        for ev in [TierEvent::Downloading, TierEvent::Completed] {
            list.set_event(ev);
            assert_eq!(list.count_completed_allowed_tier(), 1, "event={ev:?}");
        }
    }

    /// AnnounceListTest::testMoveToStoppedAllowedTier (with ring search)
    #[test]
    fn move_to_stopped_allowed_tier() {
        let mut tiers = vec![
            AnnounceTier::new(["tracker1"].iter().map(|s| s.to_string()).collect()),
            AnnounceTier::new(["tracker2"].iter().map(|s| s.to_string()).collect()),
            AnnounceTier::new(["tracker3"].iter().map(|s| s.to_string()).collect()),
        ];
        tiers[1].event = TierEvent::Completed;
        let mut list = AnnounceList::from_tier_objects(tiers);

        assert!(!list.current_tier_accepts_stopped_event());
        expect_announce(&list, "tracker1");
        list.move_to_stopped_allowed_tier();
        assert!(list.current_tier_accepts_stopped_event());
        expect_announce(&list, "tracker2");
        list.announce_failure();
        assert!(!list.current_tier_accepts_stopped_event());
        expect_announce(&list, "tracker3");
        // Ring search: no match after tracker3 -> wraps around to tracker2.
        list.move_to_stopped_allowed_tier();
        expect_announce(&list, "tracker2");
    }

    /// AnnounceListTest::testMoveToCompletedAllowedTier (implementation
    /// semantics: when the current tier is not allowed, ring-search for the
    /// nearest allowed tier)
    #[test]
    fn move_to_completed_allowed_tier() {
        let mut tiers = vec![
            AnnounceTier::new(["tracker1"].iter().map(|s| s.to_string()).collect()),
            AnnounceTier::new(["tracker2"].iter().map(|s| s.to_string()).collect()),
            AnnounceTier::new(["tracker3"].iter().map(|s| s.to_string()).collect()),
        ];
        tiers[1].event = TierEvent::Downloading;
        let mut list = AnnounceList::from_tier_objects(tiers);
        assert!(!list.current_tier_accepts_completed_event());
        list.move_to_completed_allowed_tier();
        assert!(list.current_tier_accepts_completed_event());
        expect_announce(&list, "tracker2");
    }

    /// reconfigure skips empty tiers (`AnnounceList.cc`; AnnounceListTest
    /// has no standalone case, semantics covered by from_tiers + no_group).
    #[test]
    fn reconfigure_skips_empty_tiers() {
        let list = tiers_of(&[&[], &["a"], &[]]);
        assert_eq!(list.count_tier(), 1);
        expect_announce(&list, "a");
    }

    /// Seven-state next_event transition table (line for line from aria2
    /// AnnounceTier.cc).
    #[test]
    fn next_event_table() {
        use TierEvent as E;
        let table = [
            (E::Started, E::Downloading),
            (E::StartedAfterCompletion, E::Seeding),
            (E::Stopped, E::Halted),
            (E::Completed, E::Seeding),
            (E::Downloading, E::Downloading),
            (E::Seeding, E::Seeding),
            (E::Halted, E::Halted),
        ];
        for (from, to) in table {
            let mut tier = AnnounceTier::new(["u"].iter().map(|s| s.to_string()).collect());
            tier.event = from;
            tier.next_event();
            assert_eq!(tier.event, to, "next_event {from:?}");
        }
    }

    /// nextEventIfAfterStarted transition table (line for line from aria2
    /// AnnounceTier.cc).
    #[test]
    fn next_event_if_after_started_table() {
        use TierEvent as E;
        let table = [
            (E::Stopped, E::Halted),
            (E::Completed, E::Seeding),
            (E::Started, E::Started),
            (E::StartedAfterCompletion, E::StartedAfterCompletion),
            (E::Downloading, E::Downloading),
            (E::Seeding, E::Seeding),
            (E::Halted, E::Halted),
        ];
        for (from, to) in table {
            let mut tier = AnnounceTier::new(["u"].iter().map(|s| s.to_string()).collect());
            tier.event = from;
            tier.next_event_if_after_started();
            assert_eq!(tier.event, to, "next_event_if_after_started {from:?}");
        }
    }
}

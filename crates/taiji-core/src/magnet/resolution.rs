//! Per-attempt monotonic timings. Records are bounded and contain no peer or URL data.
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::gid::Gid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolutionMilestone {
    Admitted,
    FirstCandidate,
    FirstHandshake,
    FirstInfoBlock,
    InfoVerified,
    VerificationReady,
    MetadataReady,
    SelectionCommitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheOrigin {
    Memory,
    Persistent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionState {
    Queued,
    Resolving,
    Ready,
    Paused,
    Failed,
}

/// Offsets are milliseconds from acceptance into the session queue, never wall-clock time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolutionSnapshot {
    pub state: ResolutionState,
    pub attempt_id: u64,
    pub revision: u64,
    pub elapsed_ms: u64,
    pub milestones: BTreeMap<ResolutionMilestone, u64>,
    pub cache: Option<CacheOrigin>,
}

#[derive(Default)]
struct State {
    claimed: bool,
    revision: u64,
    milestones: BTreeMap<ResolutionMilestone, u64>,
    cache: Option<CacheOrigin>,
}

pub struct MagnetResolution {
    start: Instant,
    attempt_id: u64,
    state: Mutex<State>,
}

impl MagnetResolution {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            attempt_id: rand::random(),
            state: Mutex::new(State::default()),
        }
    }
    pub fn mark(&self, milestone: ResolutionMilestone) {
        self.mark_at(milestone, Instant::now());
    }
    pub fn mark_at(&self, milestone: ResolutionMilestone, at: Instant) {
        let mut state = crate::lock(&self.state);
        if state.milestones.contains_key(&milestone) {
            return;
        }
        state.milestones.insert(
            milestone,
            at.saturating_duration_since(self.start)
                .as_millis()
                .min(u64::MAX as u128) as u64,
        );
        state.revision += 1;
    }
    pub fn cache_hit(&self, origin: CacheOrigin) {
        let mut state = crate::lock(&self.state);
        if state.cache != Some(origin) {
            state.cache = Some(origin);
            state.revision += 1;
        }
    }
    pub fn snapshot(&self) -> ResolutionSnapshot {
        let state = crate::lock(&self.state);
        ResolutionSnapshot {
            state: if state
                .milestones
                .contains_key(&ResolutionMilestone::MetadataReady)
            {
                ResolutionState::Ready
            } else if state
                .milestones
                .contains_key(&ResolutionMilestone::Admitted)
            {
                ResolutionState::Resolving
            } else {
                ResolutionState::Queued
            },
            attempt_id: self.attempt_id,
            revision: state.revision,
            elapsed_ms: self.start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            milestones: state.milestones.clone(),
            cache: state.cache,
        }
    }
}

#[derive(Default)]
pub(super) struct ResolutionBook(Mutex<VecDeque<(Gid, Arc<MagnetResolution>)>>);
impl ResolutionBook {
    pub fn queued(&self, gid: Gid) -> Arc<MagnetResolution> {
        let mut records = crate::lock(&self.0);
        records.retain(|(id, _)| *id != gid);
        let resolution = Arc::new(MagnetResolution::new());
        records.push_back((gid, resolution.clone()));
        // Covers the 1024 reserved tasks plus recent resolutions. Old records
        // may expire, but running work retains its own attempt handle.
        while records.len() > 2048 {
            records.pop_front();
        }
        resolution
    }
    pub fn get(&self, gid: Gid) -> Option<Arc<MagnetResolution>> {
        crate::lock(&self.0)
            .iter()
            .find(|(id, _)| *id == gid)
            .map(|(_, r)| r.clone())
    }
    pub fn admit(&self, gid: Gid) -> Arc<MagnetResolution> {
        let resolution = self
            .get(gid)
            .filter(|r| {
                !r.snapshot()
                    .milestones
                    .contains_key(&ResolutionMilestone::Admitted)
            })
            .unwrap_or_else(|| self.queued(gid));
        resolution.mark(ResolutionMilestone::Admitted);
        resolution
    }
    pub fn claim(&self, gid: Gid) -> Arc<MagnetResolution> {
        if let Some(resolution) = self.get(gid) {
            let claimed = {
                let mut state = crate::lock(&resolution.state);
                if !state.claimed
                    && state
                        .milestones
                        .contains_key(&ResolutionMilestone::Admitted)
                {
                    state.claimed = true;
                    true
                } else {
                    false
                }
            };
            if claimed {
                return resolution;
            }
        }
        let resolution = self.admit(gid);
        crate::lock(&resolution.state).claimed = true;
        resolution
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_marks_and_retired_attempts_cannot_rewrite_current_timings() {
        let book = ResolutionBook::default();
        let gid = Gid::from_u64(1);
        let queued = book.queued(gid);
        let first = book.admit(gid);
        assert!(Arc::ptr_eq(&queued, &first));
        assert!(Arc::ptr_eq(&first, &book.claim(gid)));
        let at = Instant::now();
        first.mark_at(ResolutionMilestone::FirstInfoBlock, at);
        let once = first.snapshot();
        first.mark_at(
            ResolutionMilestone::FirstInfoBlock,
            at + std::time::Duration::from_secs(1),
        );
        assert_eq!(first.snapshot().milestones, once.milestones);
        assert_eq!(first.snapshot().revision, once.revision);
        let second = book.admit(gid);
        first.mark(ResolutionMilestone::MetadataReady);
        assert_ne!(first.snapshot().attempt_id, second.snapshot().attempt_id);
        assert!(
            !book
                .get(gid)
                .unwrap_or_else(|| panic!("current"))
                .snapshot()
                .milestones
                .contains_key(&ResolutionMilestone::MetadataReady)
        );
    }
}

//! Request bookkeeping `RequestTracker` (mirrors aria2
//! `UTMetadataRequestTracker.{h,cc}`).
//!
//! The requester records one (index, dispatch instant) entry per piece a
//! request(0) was sent for; entries are removed when data(1)/reject(2)
//! arrives; the 20s sweep reclaims timed-out entries (reference
//! `UTMetadataRequestTracker.cc constexpr auto TIMEOUT = 20_s`; the "1s"
//! in the design spec was a typo). The in-flight cap is 1.

use std::time::Instant;

use crate::ut_metadata::TIMEOUT;

/// One in-flight request (aria2 `RequestEntry`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestEntry {
    index: usize,
    dispatched: Instant,
}

impl RequestEntry {
    /// `elapsed(t)`: `dispatchedTime.difference(wallclock) >= t` — the
    /// boundary is inclusive (exactly TIMEOUT also counts as timed out).
    fn elapsed(&self, t: std::time::Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.dispatched) >= t
    }
}

/// In-flight request table. Operation complexity mirrors the reference
/// (linear `std::find`; piece count <= 512).
#[derive(Debug, Clone, Default)]
pub struct RequestTracker {
    entries: Vec<RequestEntry>,
}

impl RequestTracker {
    pub fn new() -> Self {
        RequestTracker {
            entries: Vec::new(),
        }
    }

    /// Record one dispatch.
    pub fn add(&mut self, index: usize, now: Instant) {
        self.entries.push(RequestEntry {
            index,
            dispatched: now,
        });
    }

    /// Whether the index is being tracked.
    pub fn tracks(&self, index: usize) -> bool {
        self.entries.iter().any(|e| e.index == index)
    }

    /// Remove (no-op when absent).
    pub fn remove(&mut self, index: usize) {
        if let Some(pos) = self.entries.iter().position(|e| e.index == index) {
            self.entries.remove(pos);
        }
    }

    /// Current in-flight count.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Remaining dispatch budget: `MAX_OUTSTANDING_REQUEST(=1) - count`,
    /// floored at 0.
    pub fn avail(&self) -> usize {
        const MAX_OUTSTANDING_REQUEST: usize = 1;
        MAX_OUTSTANDING_REQUEST.saturating_sub(self.count())
    }

    /// All in-flight indices (in insertion order).
    pub fn all_tracked_indices(&self) -> Vec<usize> {
        self.entries.iter().map(|e| e.index).collect()
    }

    /// 20s timeout sweep (`removeTimeoutEntry`): remove timed-out entries
    /// and return their indices (the caller can redispatch or switch
    /// peers).
    pub fn remove_timeout_entries(&mut self, now: Instant) -> Vec<usize> {
        let mut timed_out = Vec::new();
        self.entries.retain(|e| {
            if e.elapsed(TIMEOUT, now) {
                timed_out.push(e.index);
                false
            } else {
                true
            }
        });
        timed_out
    }
}

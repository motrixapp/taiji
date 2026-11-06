//! PersistWriter observation callback seam: store and taiji-io do not
//! depend on each other (per the crate direction table); this trait lets
//! the writer thread hand over commit durations and job-channel retained
//! depth without pulling in the observation types — core (which depends on
//! both sides) injects an adapter that lands in the io metrics registry
//! (production = the process default instance; tests inject an isolated
//! instance). None = zero-overhead pass-through (existing behavior
//! unchanged).

use std::sync::Arc;
use std::time::Duration;

/// Persistence writer-thread observation callbacks (called by the writer
/// thread per job; implementers must be non-blocking — the callback runs on
/// the dedicated blocking writer thread and should only write atomics).
pub trait PersistObserve: Send + Sync + 'static {
    /// Single-job commit duration (writer-thread dispatch start to row-write
    /// completion; excludes channel queueing — see
    /// [`Self::set_queue_depth`] for the queueing face).
    fn observe_commit(&self, elapsed: Duration);

    /// Job-channel retained depth sample (the number of messages still
    /// retained in the channel after the most recent job completed; gauge
    /// SET semantics = last observed value).
    fn set_queue_depth(&self, depth: u64);
}

/// Convenience alias (used in the spawn injection-face signature).
pub type SharedPersistObserve = Option<Arc<dyn PersistObserve>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Callback-seam mechanism face: a recording implementation (same shape
    /// as the core-side adapter).
    #[derive(Default)]
    struct Recording {
        commits: Mutex<Vec<u128>>,
        depths: Mutex<Vec<u64>>,
    }

    impl PersistObserve for Recording {
        fn observe_commit(&self, elapsed: Duration) {
            self.commits
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(elapsed.as_micros());
        }

        fn set_queue_depth(&self, depth: u64) {
            self.depths
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(depth);
        }
    }

    #[test]
    fn observer_receives_commit_and_depth() {
        let obs = Arc::new(Recording::default());
        obs.observe_commit(Duration::from_millis(2));
        obs.set_queue_depth(5);
        assert_eq!(
            obs.commits.lock().unwrap_or_else(|e| e.into_inner()).len(),
            1
        );
        assert_eq!(
            *obs.depths
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .last()
                .unwrap_or(&0),
            5
        );
        // SharedPersistObserve = None pass-through (locked at the type
        // level: the spawn default form).
        let none: SharedPersistObserve = None;
        assert!(none.is_none());
    }
}

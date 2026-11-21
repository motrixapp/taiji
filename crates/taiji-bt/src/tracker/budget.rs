//! Shared announce capacity with fair shares and bounded exploratory borrowing.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CAPACITY: usize = 32;

pub struct AnnounceBudget {
    permits: Arc<Semaphore>,
    owners: AtomicUsize,
    waiting: AtomicUsize,
}
pub struct AnnounceParticipant {
    budget: Arc<AnnounceBudget>,
    waiting: bool,
}
impl Default for AnnounceBudget {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(CAPACITY)),
            owners: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
        }
    }
}
impl AnnounceBudget {
    pub fn register(self: &Arc<Self>) -> AnnounceParticipant {
        self.owners.fetch_add(1, Ordering::Relaxed);
        AnnounceParticipant {
            budget: self.clone(),
            waiting: false,
        }
    }
}
impl AnnounceParticipant {
    pub fn capacity(&self) -> usize {
        CAPACITY
    }
    pub fn fair_share(&self) -> usize {
        (CAPACITY / self.budget.owners.load(Ordering::Relaxed).max(1)).max(1)
    }
    pub fn set_waiting(&mut self, waiting: bool) {
        if self.waiting == waiting {
            return;
        }
        self.waiting = waiting;
        if waiting {
            self.budget.waiting.fetch_add(1, Ordering::Relaxed);
        } else {
            self.budget.waiting.fetch_sub(1, Ordering::Relaxed);
        }
    }
    pub fn try_acquire(&self, active: usize) -> Option<OwnedSemaphorePermit> {
        let others_waiting =
            self.budget.waiting.load(Ordering::Relaxed) > usize::from(self.waiting);
        if others_waiting && active >= self.fair_share() {
            return None;
        }
        self.budget.permits.clone().try_acquire_owned().ok()
    }
    /// Stalled borrowed slots yield under pressure. Reserve four exploration
    /// opportunities even for one task with a long untried tracker list.
    pub fn should_yield(&self, active: usize) -> bool {
        let retained = if self.waiting {
            self.fair_share().saturating_sub(4)
        } else {
            self.fair_share()
        };
        self.budget.waiting.load(Ordering::Relaxed) > 0 && active > retained
    }
}
impl Drop for AnnounceParticipant {
    fn drop(&mut self) {
        self.set_waiting(false);
        self.budget.owners.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn equally_loaded_tasks_continue_exploring_without_new_spare_capacity() {
        let shared = Arc::new(AnnounceBudget::default());
        let mut tasks: Vec<_> = (0..4).map(|_| shared.register()).collect();
        let mut held: Vec<Vec<_>> = tasks
            .iter()
            .map(|task| {
                (0..task.fair_share())
                    .map(|n| task.try_acquire(n).unwrap_or_else(|| panic!("permit")))
                    .collect()
            })
            .collect();
        for task in &mut tasks {
            task.set_waiting(true);
        }
        for (task, permits) in tasks.iter().zip(&mut held) {
            assert!(task.should_yield(permits.len()));
            while task.should_yield(permits.len()) {
                permits.pop();
            }
            assert!(task.try_acquire(permits.len()).is_some());
            assert_eq!(permits.len(), 4);
        }
    }

    #[test]
    fn borrowing_is_bounded_and_yields_to_another_owner() {
        let shared = Arc::new(AnnounceBudget::default());
        let a = shared.register();
        let mut permits: Vec<_> = (0..CAPACITY)
            .map(|n| a.try_acquire(n).unwrap_or_else(|| panic!("permit")))
            .collect();
        assert!(a.try_acquire(CAPACITY).is_none());
        let mut b = shared.register();
        b.set_waiting(true);
        assert!(a.should_yield(permits.len()));
        permits.truncate(a.fair_share());
        assert!(!a.should_yield(permits.len()));
        assert!(a.try_acquire(permits.len()).is_none());
        assert!(b.try_acquire(0).is_some());
        drop(b);
        assert!(a.try_acquire(permits.len()).is_some());
    }
}

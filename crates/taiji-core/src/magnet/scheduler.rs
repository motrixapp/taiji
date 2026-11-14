//! Session-wide metadata dial admission: bounded queues, fair turns and pacing.
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const MAX_PENDING: usize = 512;

#[derive(Clone, Copy)]
struct Limits {
    rate: f64,
    burst: f64,
    active: usize,
    soft_timeout: Duration,
}

struct Flight {
    owner: u64,
    started: Instant,
    cancel: CancellationToken,
}
struct State {
    next: u64,
    foreground_turns: u8,
    queue: VecDeque<(u64, u64, bool)>, // ticket, task owner, foreground
    flights: BTreeMap<u64, Flight>,
    tokens: f64,
    replenished: Instant,
}
pub(super) struct DialScheduler {
    state: Mutex<State>,
    changed: Notify,
    limits: Limits,
}
pub(super) struct DialPermit {
    scheduler: Arc<DialScheduler>,
    id: u64,
    pub cancel: CancellationToken,
}
struct Waiting {
    scheduler: Arc<DialScheduler>,
    id: u64,
}
impl Drop for Waiting {
    fn drop(&mut self) {
        crate::lock(&self.scheduler.state)
            .queue
            .retain(|(id, _, _)| *id != self.id);
        self.scheduler.changed.notify_waiters();
    }
}
impl Drop for DialPermit {
    fn drop(&mut self) {
        crate::lock(&self.scheduler.state).flights.remove(&self.id);
        self.scheduler.changed.notify_waiters();
    }
}
impl DialScheduler {
    pub fn new() -> Arc<Self> {
        Self::with_limits(Limits {
            rate: 30.0,
            burst: 30.0,
            active: 128,
            soft_timeout: Duration::from_secs(2),
        })
    }
    fn with_limits(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                next: 0,
                foreground_turns: 0,
                queue: VecDeque::new(),
                flights: BTreeMap::new(),
                tokens: limits.burst,
                replenished: Instant::now(),
            }),
            changed: Notify::new(),
            limits,
        })
    }
    pub fn retire_stalled(&self, owner: u64) {
        let state = crate::lock(&self.state);
        let now = Instant::now();
        if let Some(flight) = state
            .flights
            .values()
            .filter(|flight| flight.owner == owner && !flight.cancel.is_cancelled())
            .min_by_key(|flight| flight.started)
        {
            if now.duration_since(flight.started) >= self.limits.soft_timeout {
                flight.cancel.cancel();
            }
        }
    }
    pub async fn acquire(
        self: &Arc<Self>,
        owner: u64,
        foreground: bool,
        parent: &CancellationToken,
    ) -> Option<DialPermit> {
        let id = {
            let mut state = crate::lock(&self.state);
            if parent.is_cancelled()
                || state.queue.len()
                    >= if foreground {
                        MAX_PENDING
                    } else {
                        MAX_PENDING - 4
                    }
            {
                return None;
            }
            state.next = state.next.wrapping_add(1);
            let id = state.next;
            state.queue.push_back((id, owner, foreground));
            if foreground && state.foreground_turns < 4 {
                if let Some(index) = state.queue.iter().position(|(_, _, fg)| *fg) {
                    state.queue.rotate_left(index);
                }
            }
            id
        };
        self.changed.notify_waiters();
        let _waiting = Waiting {
            scheduler: self.clone(),
            id,
        };
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let wait = {
                let mut state = crate::lock(&self.state);
                let now = Instant::now();
                state.tokens = (state.tokens
                    + now.duration_since(state.replenished).as_secs_f64() * self.limits.rate)
                    .min(self.limits.burst);
                state.replenished = now;
                if parent.is_cancelled() {
                    return None;
                }
                if state
                    .queue
                    .front()
                    .is_some_and(|(ticket, _, _)| *ticket == id)
                {
                    if state.flights.len() < self.limits.active && state.tokens >= 1.0 {
                        state.queue.pop_front();
                        state.foreground_turns = if foreground {
                            state.foreground_turns.saturating_add(1)
                        } else {
                            0
                        };
                        let prefer_foreground = state.queue.iter().any(|(_, _, fg)| *fg)
                            && (state.foreground_turns < 4
                                || state.queue.iter().all(|(_, _, fg)| *fg));
                        let next = state
                            .queue
                            .iter()
                            .position(|(_, task, fg)| *task != owner && *fg == prefer_foreground)
                            .or_else(|| {
                                state
                                    .queue
                                    .iter()
                                    .position(|(_, _, fg)| *fg == prefer_foreground)
                            });
                        if let Some(index) = next {
                            state.queue.rotate_left(index);
                        }
                        state.tokens -= 1.0;
                        let cancel = parent.child_token();
                        state.flights.insert(
                            id,
                            Flight {
                                owner,
                                started: now,
                                cancel: cancel.clone(),
                            },
                        );
                        drop(state);
                        self.changed.notify_waiters();
                        return Some(DialPermit {
                            scheduler: self.clone(),
                            id,
                            cancel,
                        });
                    }
                    if state.flights.len() >= self.limits.active {
                        // Only pressure retires stale handshakes. A slow but
                        // uncontended attempt retains the transport's hard budget.
                        if let Some(flight) = state
                            .flights
                            .values()
                            .filter(|f| !f.cancel.is_cancelled())
                            .min_by_key(|f| f.started)
                        {
                            if now.duration_since(flight.started) >= self.limits.soft_timeout {
                                flight.cancel.cancel();
                            }
                        }
                    }
                }
                if !state
                    .queue
                    .front()
                    .is_some_and(|(ticket, _, _)| *ticket == id)
                {
                    Duration::from_secs(60)
                } else if state.flights.len() >= self.limits.active {
                    state
                        .flights
                        .values()
                        .filter(|f| !f.cancel.is_cancelled())
                        .map(|f| {
                            self.limits
                                .soft_timeout
                                .saturating_sub(now.duration_since(f.started))
                        })
                        .min()
                        .unwrap_or(Duration::from_secs(1))
                        .max(Duration::from_millis(1))
                } else {
                    Duration::from_secs_f64(
                        ((1.0 - state.tokens).max(0.0) / self.limits.rate).max(0.001),
                    )
                }
            };
            tokio::select! {
                _ = parent.cancelled() => return None,
                _ = &mut changed => {},
                _ = tokio::time::sleep(wait) => {},
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn queued_task_batches_receive_round_robin_turns() {
        let scheduler = DialScheduler::with_limits(Limits {
            rate: 1000.0,
            burst: 8.0,
            active: 1,
            soft_timeout: Duration::from_secs(5),
        });
        let root = CancellationToken::new();
        let holder = scheduler
            .acquire(0, true, &root)
            .await
            .unwrap_or_else(|| panic!("holder"));
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut joins = Vec::new();
        for owner in [1, 1, 2, 2] {
            let scheduler = scheduler.clone();
            let root = root.clone();
            let tx = tx.clone();
            joins.push(tokio::spawn(async move {
                if let Some(permit) = scheduler.acquire(owner, true, &root).await {
                    let _ = tx.send((owner, permit)).await;
                }
            }));
            tokio::task::yield_now().await;
        }
        drop(holder);
        let mut owners = Vec::new();
        for _ in 0..4 {
            let (owner, permit) = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .unwrap_or_else(|| panic!("grant"));
            assert_eq!(crate::lock(&scheduler.state).flights.len(), 1);
            owners.push(owner);
            drop(permit);
        }
        assert_eq!(owners, vec![1, 2, 1, 2]);
        for join in joins {
            join.await.unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[tokio::test]
    async fn foreground_preempts_background_but_background_still_gets_a_turn() {
        let scheduler = DialScheduler::with_limits(Limits {
            rate: 1000.0,
            burst: 16.0,
            active: 1,
            soft_timeout: Duration::from_secs(5),
        });
        let root = CancellationToken::new();
        let holder = scheduler
            .acquire(0, false, &root)
            .await
            .unwrap_or_else(|| panic!("holder"));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut joins = Vec::new();
        for (owner, foreground) in [
            (1, false),
            (2, true),
            (3, true),
            (4, true),
            (5, true),
            (6, true),
        ] {
            let scheduler = scheduler.clone();
            let root = root.clone();
            let tx = tx.clone();
            joins.push(tokio::spawn(async move {
                if let Some(permit) = scheduler.acquire(owner, foreground, &root).await {
                    let _ = tx.send((foreground, permit)).await;
                }
            }));
            tokio::task::yield_now().await;
        }
        drop(holder);
        let mut order = Vec::new();
        for _ in 0..6 {
            let (foreground, permit) = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .unwrap_or_else(|| panic!("grant"));
            order.push(foreground);
            drop(permit);
        }
        assert_eq!(order, vec![true, true, true, true, false, true]);
        for join in joins {
            join.await.unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[tokio::test]
    async fn a_second_task_does_not_get_a_second_startup_burst() {
        let scheduler = DialScheduler::with_limits(Limits {
            rate: 10.0,
            burst: 1.0,
            active: 8,
            soft_timeout: Duration::from_secs(5),
        });
        let root = CancellationToken::new();
        let _first = scheduler.acquire(1, true, &root).await;
        let start = Instant::now();
        let _second =
            tokio::time::timeout(Duration::from_secs(2), scheduler.acquire(2, true, &root))
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        assert!(start.elapsed() >= Duration::from_millis(80));
    }

    #[tokio::test]
    async fn cancellation_releases_waiters_and_capacity_is_never_oversubscribed() {
        let scheduler = DialScheduler::with_limits(Limits {
            rate: 1000.0,
            burst: 8.0,
            active: 1,
            soft_timeout: Duration::from_secs(5),
        });
        let root = CancellationToken::new();
        let first = scheduler
            .acquire(1, true, &root)
            .await
            .unwrap_or_else(|| panic!("first"));
        let cancelled = root.child_token();
        let waiting = tokio::spawn({
            let s = scheduler.clone();
            let c = cancelled.clone();
            async move { s.acquire(2, true, &c).await }
        });
        tokio::task::yield_now().await;
        cancelled.cancel();
        assert!(waiting.await.unwrap_or_else(|e| panic!("{e}")).is_none());
        assert_eq!(crate::lock(&scheduler.state).flights.len(), 1);
        assert!(crate::lock(&scheduler.state).queue.is_empty());
        drop(first);
        assert!(scheduler.acquire(3, true, &root).await.is_some());
    }

    #[tokio::test]
    async fn pressure_retires_an_unproductive_attempt_without_cancelling_its_task() {
        let scheduler = DialScheduler::with_limits(Limits {
            rate: 1000.0,
            burst: 8.0,
            active: 1,
            soft_timeout: Duration::from_millis(20),
        });
        let root = CancellationToken::new();
        let first = scheduler
            .acquire(1, true, &root)
            .await
            .unwrap_or_else(|| panic!("first"));
        let next = tokio::spawn({
            let s = scheduler.clone();
            let c = root.clone();
            async move { s.acquire(2, true, &c).await }
        });
        tokio::time::timeout(Duration::from_secs(1), first.cancel.cancelled())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!root.is_cancelled());
        drop(first);
        assert!(next.await.unwrap_or_else(|e| panic!("{e}")).is_some());
    }
}

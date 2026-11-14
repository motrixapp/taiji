//! Bounded OS resolver work. Logical cancellation never pretends an already
//! running getaddrinfo call has released its thread or concurrency permit.
use super::*;
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use tokio::sync::{Semaphore, watch};

pub trait BlockingHostLookup: Send + Sync + 'static {
    fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError>;
}
struct OsLookup;
impl BlockingHostLookup for OsLookup {
    fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let addresses: Vec<_> = (host, 0)
            .to_socket_addrs()
            .map_err(|error| ResolveError::Failed(error.to_string()))?
            .map(|address| address.ip())
            .collect();
        if addresses.is_empty() {
            Err(ResolveError::Failed("no address resolved".into()))
        } else {
            Ok(addresses)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SystemDnsPolicy {
    pub max_active: usize,
    /// Includes executing and queued physical jobs, including retired generations.
    pub max_in_flight: usize,
    pub admission_timeout: Duration,
}
impl Default for SystemDnsPolicy {
    fn default() -> Self {
        Self {
            max_active: 32,
            max_in_flight: 256,
            admission_timeout: DNS_TIMEOUT,
        }
    }
}

type Answer = Result<Vec<IpAddr>, ResolveError>;
struct Flight {
    result: watch::Sender<Option<Answer>>,
    deadline: Instant,
    abandoned: AtomicBool,
}
struct Inner {
    lookup: Arc<dyn BlockingHostLookup>,
    policy: SystemDnsPolicy,
    permits: Arc<Semaphore>,
    admission: Arc<Semaphore>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    metrics: Arc<MetricsRegistry>,
    generation: AtomicU64,
}

/// A constructible OS resolver with a real physical-work budget. The blocking
/// seam permits deterministic resource/lifecycle tests without changing DNS.
#[derive(Clone)]
pub struct SystemResolver {
    inner: Arc<Inner>,
}
impl SystemResolver {
    pub fn with_lookup(
        lookup: Arc<dyn BlockingHostLookup>,
        policy: SystemDnsPolicy,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                lookup,
                permits: Arc::new(Semaphore::new(policy.max_active)),
                admission: Arc::new(Semaphore::new(policy.max_in_flight)),
                policy,
                flights: Mutex::new(HashMap::new()),
                metrics,
                generation: AtomicU64::new(0),
            }),
        }
    }
    fn shared_default() -> Arc<Self> {
        static DEFAULT: OnceLock<Arc<SystemResolver>> = OnceLock::new();
        DEFAULT
            .get_or_init(|| {
                Arc::new(Self::with_lookup(
                    Arc::new(OsLookup),
                    SystemDnsPolicy::default(),
                    crate::metrics::registry_default(),
                ))
            })
            .clone()
    }
    async fn query(&self, host: String) -> Answer {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let host = host.to_ascii_lowercase();
        let caller_deadline = Instant::now() + self.inner.policy.admission_timeout;
        loop {
            let mut pending_guard = None;
            let (receiver, flight, generation) = {
                let mut flights = crate::lock(&self.inner.flights);
                let generation = self.inner.generation.load(Ordering::Acquire);
                if let Some(flight) = flights.get(&host) {
                    self.inner.metrics.dns().note_system_coalesced();
                    (flight.result.subscribe(), flight.clone(), generation)
                } else {
                    let slot = match self.inner.admission.clone().try_acquire_owned() {
                        Ok(slot) => slot,
                        Err(_) => {
                            self.inner.metrics.dns().note_capacity_rejected();
                            return Err(ResolveError::Capacity);
                        }
                    };
                    if Instant::now() >= caller_deadline {
                        return Err(ResolveError::Timeout(self.inner.policy.admission_timeout));
                    }
                    let (result, receiver) = watch::channel(None);
                    let flight = Arc::new(Flight {
                        result,
                        deadline: caller_deadline,
                        abandoned: AtomicBool::new(false),
                    });
                    flights.insert(host.clone(), flight.clone());
                    self.inner.metrics.dns().system_queued_inc();
                    let guard = PhysicalGuard {
                        inner: self.inner.clone(),
                        host: host.clone(),
                        flight: flight.clone(),
                        queued_at: Some(Instant::now()),
                        started_at: None,
                        finished: false,
                        fallback: ResolveError::Cancelled,
                        slot: Some(slot),
                        execution: None,
                    };
                    pending_guard = Some(guard);
                    (receiver, flight, generation)
                }
            };
            // Never submit a cleanup-owning task while holding its registry
            // lock: runtime shutdown can drop that task before polling it.
            if let Some(guard) = pending_guard {
                tokio::spawn(admit(guard));
            }
            let mut waiter = Waiter {
                inner: self.inner.clone(),
                flight,
                receiver,
            };
            let remaining = caller_deadline.saturating_duration_since(Instant::now());
            let answer = tokio::time::timeout(remaining, async {
                loop {
                    let answer = waiter.receiver.borrow_and_update().clone();
                    if let Some(answer) = answer {
                        return answer;
                    }
                    if waiter.receiver.changed().await.is_err() {
                        return Err(ResolveError::Cancelled);
                    }
                }
            })
            .await
            .unwrap_or(Err(ResolveError::Timeout(
                self.inner.policy.admission_timeout,
            )));
            // A new cohort can wait for an abandoned/expired syscall to end,
            // then replace it. The old result is not trusted and the caller's
            // original deadline never moves when a replacement is admitted.
            // finish() validates success at publication under the registry
            // lock. A waiter scheduled after the physical deadline can still
            // consume that timely success within its own remaining budget.
            let stale = generation != self.inner.generation.load(Ordering::Acquire)
                || waiter.flight.abandoned.load(Ordering::Acquire)
                || (matches!(answer, Err(ResolveError::Timeout(_)))
                    && Instant::now() >= waiter.flight.deadline);
            drop(waiter);
            if Instant::now() >= caller_deadline {
                return Err(ResolveError::Timeout(self.inner.policy.admission_timeout));
            }
            if stale {
                continue;
            }
            return answer;
        }
    }
}

// A last-waiter cancellation makes the eventual answer unusable. Keep the
// physical entry until the syscall really ends, so retries cannot duplicate it.
struct Waiter {
    inner: Arc<Inner>,
    flight: Arc<Flight>,
    receiver: watch::Receiver<Option<Answer>>,
}
impl Drop for Waiter {
    fn drop(&mut self) {
        let _flights = crate::lock(&self.inner.flights);
        if self.flight.result.receiver_count() == 1 && self.flight.result.borrow().is_none() {
            self.flight.abandoned.store(true, Ordering::Release);
        }
    }
}

impl HostResolver for SystemResolver {
    fn invalidate_all(&self) {
        let mut flights = crate::lock(&self.inner.flights);
        for (_, flight) in flights.drain() {
            flight.abandoned.store(true, Ordering::Release);
            flight
                .result
                .send_replace(Some(Err(ResolveError::Cancelled)));
        }
        self.inner.generation.fetch_add(1, Ordering::Release);
        // Running guards still own both permits. New-network queries can use
        // free capacity without joining old-network work for the same name.
    }

    fn invalidate_host(&self, host: &str) {
        if let Some(flight) = crate::lock(&self.inner.flights).get(&host.to_ascii_lowercase()) {
            flight.abandoned.store(true, Ordering::Release);
        }
    }
    fn resolve(&self, host: String) -> ResolverFuture {
        let this = self.clone();
        Box::pin(async move {
            pick_ip(
                &this
                    .query(host)
                    .await
                    .map_err(ResolveError::into_trait_err)?,
            )
            .ok_or_else(|| "no address resolved".into())
        })
    }
    fn resolve_family(&self, host: String, family: ResolveFamily) -> ResolverFuture {
        let this = self.clone();
        Box::pin(async move {
            pick_ip_family(
                &this
                    .query(host)
                    .await
                    .map_err(ResolveError::into_trait_err)?,
                family,
            )
        })
    }
    fn resolve_list(&self, host: String) -> ListResolverFuture {
        let this = self.clone();
        Box::pin(async move { this.query(host).await.map_err(ResolveError::into_trait_err) })
    }
    fn resolve_list_classified(&self, host: String) -> ClassifiedListFuture {
        let this = self.clone();
        Box::pin(async move { this.query(host).await })
    }
}

/// Existing construction syntax stays usable; every instance delegates to the
/// same bounded OS service, including callers outside SharedDns.
pub struct TokioHostResolver;
impl HostResolver for TokioHostResolver {
    fn invalidate_all(&self) {
        SystemResolver::shared_default().invalidate_all();
    }

    fn invalidate_host(&self, host: &str) {
        SystemResolver::shared_default().invalidate_host(host);
    }
    fn resolve(&self, host: String) -> ResolverFuture {
        SystemResolver::shared_default().resolve(host)
    }
    fn resolve_family(&self, host: String, family: ResolveFamily) -> ResolverFuture {
        SystemResolver::shared_default().resolve_family(host, family)
    }
    fn resolve_list(&self, host: String) -> ListResolverFuture {
        SystemResolver::shared_default().resolve_list(host)
    }
    fn resolve_list_classified(&self, host: String) -> ClassifiedListFuture {
        SystemResolver::shared_default().resolve_list_classified(host)
    }
}

struct PhysicalGuard {
    inner: Arc<Inner>,
    host: String,
    flight: Arc<Flight>,
    queued_at: Option<Instant>,
    started_at: Option<Instant>,
    finished: bool,
    fallback: ResolveError,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
    execution: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl PhysicalGuard {
    fn stop_metrics(&mut self) {
        if let Some(queued_at) = self.queued_at.take() {
            self.inner.metrics.dns().system_queued_dec();
            self.inner
                .metrics
                .dns()
                .observe_system_queue(queued_at.elapsed());
        }
        if let Some(started_at) = self.started_at.take() {
            self.inner.metrics.dns().system_active_dec();
            self.inner
                .metrics
                .dns()
                .observe_system_lookup(started_at.elapsed());
        }
    }
    fn try_start(&mut self) -> Result<(), ResolveError> {
        let inner = self.inner.clone();
        let _flights = crate::lock(&inner.flights);
        // This is the physical job's start linearization point. A last-waiter
        // cancellation before this lock cannot be undone by a new subscriber.
        if Instant::now() >= self.flight.deadline {
            return Err(ResolveError::Timeout(inner.policy.admission_timeout));
        }
        if self.flight.abandoned.load(Ordering::Acquire) || self.flight.result.receiver_count() == 0
        {
            return Err(ResolveError::Cancelled);
        }
        self.stop_metrics();
        self.inner.metrics.dns().note_system_started();
        self.inner.metrics.dns().system_active_inc();
        self.started_at = Some(Instant::now());
        Ok(())
    }
    fn finish(&mut self, mut answer: Answer) {
        self.stop_metrics();
        self.finished = true;
        let mut flights = crate::lock(&self.inner.flights);
        // Cancellation, invalidation and subscriptions use this same lock.
        // Validate immediately before publication: a result computed before
        // the last old waiter left must never serve a new generation.
        if matches!(answer, Ok(_) | Err(ResolveError::Failed(_))) {
            if Instant::now() >= self.flight.deadline {
                answer = Err(ResolveError::Timeout(self.inner.policy.admission_timeout));
            } else if self.flight.abandoned.load(Ordering::Acquire) {
                answer = Err(ResolveError::Cancelled);
            }
        }
        if flights
            .get(&self.host)
            .is_some_and(|current| Arc::ptr_eq(current, &self.flight))
        {
            flights.remove(&self.host);
        }
        drop(self.slot.take());
        self.flight.result.send_replace(Some(answer));
        // Own the execution permit through cleanup even when lookup panics.
        drop(self.execution.take());
    }
    fn unobserved(&self) -> bool {
        // Subscribing requires the same lock, so the zero-reader decision and
        // removal cannot race a new waiter joining this admission.
        let mut flights = crate::lock(&self.inner.flights);
        if self.flight.result.receiver_count() != 0 {
            return false;
        }
        if flights
            .get(&self.host)
            .is_some_and(|current| Arc::ptr_eq(current, &self.flight))
        {
            flights.remove(&self.host);
        }
        true
    }
}
impl Drop for PhysicalGuard {
    fn drop(&mut self) {
        if !self.finished {
            if self.fallback == ResolveError::Capacity {
                self.inner.metrics.dns().note_capacity_rejected();
            }
            self.finish(Err(self.fallback.clone()));
        }
    }
}

async fn admit(mut guard: PhysicalGuard) {
    let deadline = guard.flight.deadline;
    let semaphore = guard.inner.permits.clone();
    let mut admission = Box::pin(tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        semaphore.acquire_owned(),
    ));
    let permit = loop {
        tokio::select! {
            result = &mut admission => match result {
                Ok(Ok(permit)) => break permit,
                Ok(Err(_)) => { guard.finish(Err(ResolveError::Cancelled)); return; }
                Err(_) => { guard.finish(Err(ResolveError::Timeout(guard.inner.policy.admission_timeout))); return; }
            },
            _ = guard.flight.result.closed() => { if guard.unobserved() { return; } }
        }
    };
    guard.execution = Some(permit);
    if guard.flight.abandoned.load(Ordering::Acquire) {
        guard.finish(Err(ResolveError::Cancelled));
        return;
    }
    // Detached dedicated DNS threads do not occupy Tokio's filesystem pool
    // or delay runtime shutdown. Admission still strictly bounds their number.
    // The guard/permits move into the closure before submission, so thread
    // creation failure, lookup panic and normal completion all clean up.
    guard.fallback = ResolveError::Capacity;
    if let Ok(thread) = std::thread::Builder::new()
        .name("taiji-dns".into())
        .spawn(move || run_lookup(guard))
    {
        drop(thread);
    }
}

fn run_lookup(mut guard: PhysicalGuard) {
    guard.fallback = ResolveError::Cancelled;
    let answer = match guard.try_start() {
        Ok(()) => guard.inner.lookup.lookup(&guard.host),
        Err(error) => Err(error),
    };
    guard.finish(answer);
}

#[cfg(test)]
mod tests;

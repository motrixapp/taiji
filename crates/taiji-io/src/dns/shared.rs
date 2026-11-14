//! Shared logical DNS queries, bounded positive/negative caching and waiter isolation.
use super::*;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use tokio::sync::watch;

/// Resolver policy. Failed answers live briefly; a caller cancellation or
/// admission failure is never evidence about a hostname and is not cached.
#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub positive_ttl: Duration,
    pub failure_ttl: Duration,
    pub timeout_ttl: Duration,
    pub cache_capacity: usize,
    pub max_in_flight: usize,
    pub lookup_timeout: Duration,
}
impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            positive_ttl: HOST_CACHE_TTL,
            failure_ttl: Duration::from_secs(2),
            timeout_ttl: Duration::from_secs(1),
            cache_capacity: HOST_CACHE_CAPACITY,
            max_in_flight: 256,
            lookup_timeout: DNS_TIMEOUT,
        }
    }
}

type Answer = Result<Vec<IpAddr>, ResolveError>;
struct Flight {
    result: watch::Sender<Option<Answer>>,
}
struct State {
    cache: HostCache,
    flights: HashMap<String, Arc<Flight>>,
    active_queries: usize,
}
struct Inner {
    resolver: Arc<dyn HostResolver>,
    policy: DnsPolicy,
    state: Mutex<State>,
    metrics: Arc<MetricsRegistry>,
}

/// One process-wide production instance is shared by HTTP, FTP, trackers and
/// DHT. Owned query tasks isolate each waiter's cancellation from the others.
#[derive(Clone)]
pub struct SharedDns {
    inner: Arc<Inner>,
}
impl std::fmt::Debug for SharedDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedDns")
            .field("policy", &self.inner.policy)
            .finish_non_exhaustive()
    }
}

impl SharedDns {
    pub fn with_resolver(resolver: Arc<dyn HostResolver>) -> Self {
        Self::with_registry(resolver, Arc::new(MetricsRegistry::new()))
    }
    pub fn with_registry(resolver: Arc<dyn HostResolver>, metrics: Arc<MetricsRegistry>) -> Self {
        Self::with_policy(resolver, metrics, DnsPolicy::default())
    }
    pub fn with_policy(
        resolver: Arc<dyn HostResolver>,
        metrics: Arc<MetricsRegistry>,
        policy: DnsPolicy,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                resolver,
                state: Mutex::new(State {
                    cache: HostCache::with_metrics(
                        policy.positive_ttl,
                        policy.cache_capacity,
                        metrics.clone(),
                    ),
                    flights: HashMap::new(),
                    active_queries: 0,
                }),
                policy,
                metrics,
            }),
        }
    }
    pub fn with_timeout_resolver(
        timed: Arc<TimeoutResolver>,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self::with_registry(timed, metrics)
    }
    pub fn production() -> Self {
        Self::with_registry(
            Arc::new(TokioHostResolver),
            crate::metrics::registry_default(),
        )
    }
    pub fn shared_default() -> Arc<Self> {
        static DEFAULT: OnceLock<Arc<SharedDns>> = OnceLock::new();
        DEFAULT.get_or_init(|| Arc::new(Self::production())).clone()
    }

    /// Invalidation advances the logical generation. Existing callers can
    /// finish, but their late answer cannot overwrite the new cache generation.
    /// It does not forcibly cancel a system getaddrinfo call already running.
    pub fn invalidate(&self, host: &str) {
        let key = host.to_ascii_lowercase();
        let mut state = crate::lock(&self.inner.state);
        state.cache.remove(&key);
        state.flights.remove(&key);
        self.inner.resolver.invalidate_host(&key);
    }

    pub fn cached_family_list(
        &self,
        host: &str,
        family: ResolveFamily,
        now: Instant,
    ) -> Option<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(filter_family(vec![ip], family));
        }
        crate::lock(&self.inner.state)
            .cache
            .get_list(&host.to_ascii_lowercase(), now)
            .map(|list| filter_family(list, family))
    }
    pub fn cached_family(&self, host: &str, family: ResolveFamily, now: Instant) -> Option<IpAddr> {
        self.cached_family_list(host, family, now)?
            .into_iter()
            .next()
    }

    async fn list_cached_or_resolve(&self, host: &str) -> Answer {
        let started = Instant::now();
        let metrics = self.inner.metrics.dns();
        let result = self.query(host).await;
        if let Err(error) = &result {
            metrics.note_lookup(if matches!(error, ResolveError::Timeout(_)) {
                DnsLookupResult::Timeout
            } else {
                DnsLookupResult::Error
            });
        }
        metrics.observe_resolve(started.elapsed());
        result
    }

    async fn query(&self, host: &str) -> Answer {
        // DNS names are case insensitive, but the final dot changes OS search
        // semantics and therefore remains part of the cache/flight identity.
        let key = host.to_ascii_lowercase();
        let mut receiver = {
            let mut state = crate::lock(&self.inner.state);
            if let Some(answer) = state.cache.get_result(&key, Instant::now()) {
                if answer.is_ok() {
                    self.inner.metrics.dns().note_lookup(DnsLookupResult::Hit);
                } else {
                    self.inner.metrics.dns().note_negative_hit();
                }
                return answer;
            }
            self.inner.metrics.dns().note_lookup(DnsLookupResult::Miss);
            if let Some(flight) = state.flights.get(&key) {
                self.inner.metrics.dns().note_coalesced();
                flight.result.subscribe()
            } else {
                if state.active_queries >= self.inner.policy.max_in_flight {
                    self.inner.metrics.dns().note_capacity_rejected();
                    return Err(ResolveError::Capacity);
                }
                let (result, receiver) = watch::channel(None);
                let flight = Arc::new(Flight { result });
                state.flights.insert(key.clone(), flight.clone());
                state.active_queries += 1;
                let guard = FlightGuard {
                    inner: self.inner.clone(),
                    key,
                    flight,
                };
                tokio::spawn(run_query(guard));
                receiver
            }
        };
        loop {
            let answer = receiver.borrow_and_update().clone();
            if let Some(answer) = answer {
                return answer;
            }
            if receiver.changed().await.is_err() {
                return Err(ResolveError::Cancelled);
            }
        }
    }

    pub async fn resolve_family_list(
        &self,
        host: String,
        family: ResolveFamily,
    ) -> Result<Vec<IpAddr>, String> {
        let list = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            self.list_cached_or_resolve(&host)
                .await
                .map_err(ResolveError::into_trait_err)?
        };
        let filtered = filter_family(list, family);
        if filtered.is_empty() {
            return pick_ip_family(&filtered, family).map(|ip| vec![ip]);
        }
        Ok(filtered)
    }
    pub async fn resolve_family(
        &self,
        host: String,
        family: ResolveFamily,
    ) -> Result<IpAddr, String> {
        let list = self.resolve_family_list(host, family).await?;
        pick_ip_family(&list, family)
    }
    pub async fn resolve_for_transport(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, ResolveError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        Ok(self
            .list_cached_or_resolve(host)
            .await?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

fn filter_family(list: Vec<IpAddr>, family: ResolveFamily) -> Vec<IpAddr> {
    list.into_iter()
        .filter(|ip| ResolveFamily::of_ip(*ip) == family)
        .collect()
}

struct FlightGuard {
    inner: Arc<Inner>,
    key: String,
    flight: Arc<Flight>,
}
impl FlightGuard {
    fn is_current(&self, state: &State) -> bool {
        state
            .flights
            .get(&self.key)
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
    }
    fn finish(&self, answer: Answer) {
        let mut state = crate::lock(&self.inner.state);
        if self.is_current(&state) {
            let ttl = match &answer {
                Ok(_) => self.inner.policy.positive_ttl,
                Err(ResolveError::Failed(_)) => self.inner.policy.failure_ttl,
                Err(ResolveError::Timeout(_)) => self.inner.policy.timeout_ttl,
                Err(ResolveError::Capacity | ResolveError::Cancelled) => Duration::ZERO,
            };
            match &answer {
                Ok(list) => state
                    .cache
                    .insert_list(self.key.clone(), list.clone(), Instant::now()),
                Err(_) => {
                    state
                        .cache
                        .insert_result(self.key.clone(), answer.clone(), Instant::now(), ttl)
                }
            }
            state.flights.remove(&self.key);
        }
        self.flight.result.send_replace(Some(answer));
    }
    fn abandon_if_unobserved(&self) -> bool {
        let mut state = crate::lock(&self.inner.state);
        if self.flight.result.receiver_count() != 0 {
            return false;
        }
        if self.is_current(&state) {
            state.flights.remove(&self.key);
        }
        true
    }
}
impl Drop for FlightGuard {
    fn drop(&mut self) {
        let mut state = crate::lock(&self.inner.state);
        if self.is_current(&state) {
            state.flights.remove(&self.key);
        }
        state.active_queries -= 1;
        let empty = self.flight.result.borrow().is_none();
        if empty {
            self.flight
                .result
                .send_replace(Some(Err(ResolveError::Cancelled)));
        }
    }
}

async fn run_query(guard: FlightGuard) {
    if guard.abandon_if_unobserved() {
        return;
    }
    guard.inner.metrics.dns().note_backend_started();
    let timeout = guard.inner.policy.lookup_timeout;
    let future = guard
        .inner
        .resolver
        .resolve_list_classified(guard.key.clone());
    let mut future = Box::pin(tokio::time::timeout(timeout, future));
    loop {
        tokio::select! {
            result = &mut future => {
                let answer = result.unwrap_or(Err(ResolveError::Timeout(timeout))).and_then(|list| {
                    let mut seen = HashSet::new();
                    let list: Vec<_> = list.into_iter().filter(|ip| seen.insert(*ip)).collect();
                    if list.is_empty() { Err(ResolveError::Failed("no address resolved".into())) } else { Ok(list) }
                });
                if let Ok(list) = &answer { guard.inner.metrics.dns().note_family_mix(family_mix_of(list)); }
                guard.finish(answer);
                return;
            }
            _ = guard.flight.result.closed() => {
                if guard.abandon_if_unobserved() { return; }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Semaphore;

    struct HeldResolver {
        started: Arc<AtomicUsize>,
        gate: Arc<Semaphore>,
        hold_first_only: bool,
    }
    impl HostResolver for HeldResolver {
        fn resolve(&self, _: String) -> ResolverFuture {
            Box::pin(std::future::pending())
        }
        fn resolve_list_classified(&self, _: String) -> ClassifiedListFuture {
            let started = self.started.clone();
            let gate = self.gate.clone();
            let hold_first_only = self.hold_first_only;
            Box::pin(async move {
                let call = started.fetch_add(1, Ordering::SeqCst) + 1;
                if !hold_first_only || call == 1 {
                    let _permit = gate.acquire().await.map_err(|_| ResolveError::Cancelled)?;
                }
                Ok(vec![IpAddr::V4(std::net::Ipv4Addr::new(
                    192, 0, 2, call as u8,
                ))])
            })
        }
    }
    async fn until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("condition did not become true"));
    }
    fn query(shared: &SharedDns) -> tokio::task::JoinHandle<Result<Vec<SocketAddr>, ResolveError>> {
        let shared = shared.clone();
        tokio::spawn(async move { shared.resolve_for_transport("generation.test", 80).await })
    }
    #[tokio::test]
    async fn retired_logical_generations_keep_admission_until_they_finish() {
        let started = Arc::new(AtomicUsize::new(0));
        let shared = SharedDns::with_policy(
            Arc::new(HeldResolver {
                started: started.clone(),
                gate: Arc::new(Semaphore::new(0)),
                hold_first_only: false,
            }),
            Arc::new(MetricsRegistry::new()),
            DnsPolicy {
                max_in_flight: 2,
                ..DnsPolicy::default()
            },
        );
        let first = query(&shared);
        until(|| started.load(Ordering::SeqCst) == 1).await;
        shared.invalidate("generation.test");
        let second = query(&shared);
        until(|| started.load(Ordering::SeqCst) == 2).await;
        shared.invalidate("generation.test");
        for _ in 0..20 {
            assert_eq!(
                shared.resolve_for_transport("generation.test", 80).await,
                Err(ResolveError::Capacity)
            );
            shared.invalidate("generation.test");
        }
        assert_eq!(started.load(Ordering::SeqCst), 2);
        first.abort();
        second.abort();
        let _ = (first.await, second.await);
        until(|| crate::lock(&shared.inner.state).active_queries == 0).await;
        assert!(crate::lock(&shared.inner.state).flights.is_empty());
    }

    #[tokio::test]
    async fn retired_logical_answer_cannot_overwrite_new_cache_generation() {
        let old_gate = Arc::new(Semaphore::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let shared = SharedDns::with_resolver(Arc::new(HeldResolver {
            started: started.clone(),
            gate: old_gate.clone(),
            hold_first_only: true,
        }));
        let first = query(&shared);
        until(|| started.load(Ordering::SeqCst) == 1).await;
        shared.invalidate("generation.test");
        let second = query(&shared);
        until(|| started.load(Ordering::SeqCst) == 2).await;
        assert!(second.await.unwrap_or_else(|e| panic!("{e}")).is_ok());
        // The new answer is already cached before the old generation returns.
        old_gate.add_permits(1);
        assert!(first.await.unwrap_or_else(|e| panic!("{e}")).is_ok());
        assert_eq!(
            shared.cached_family_list("generation.test", ResolveFamily::V4, Instant::now()),
            Some(vec![IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2))])
        );
    }
}

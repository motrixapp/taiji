use super::*;
use std::sync::Condvar;
use std::sync::atomic::AtomicUsize;

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last))
}

#[derive(Default)]
struct Gate {
    released: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn wait(&self) {
        let mut released = crate::lock(&self.released);
        while !*released {
            released = self
                .changed
                .wait(released)
                .unwrap_or_else(|e| e.into_inner());
        }
    }
    fn release(&self) {
        *crate::lock(&self.released) = true;
        self.changed.notify_all();
    }
}
// Every test owns this before starting work, including the runtime-shutdown
// test. A failed assertion must never leave a blocked DNS worker behind.
struct ReleaseOnDrop(Arc<Gate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct GatedLookup {
    gate: Arc<Gate>,
    blocked_calls: usize,
    calls: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    hosts: Mutex<Vec<String>>,
}
impl GatedLookup {
    fn new(blocked_calls: usize) -> (Arc<Self>, ReleaseOnDrop) {
        let gate = Arc::new(Gate::default());
        (
            Arc::new(Self {
                gate: gate.clone(),
                blocked_calls,
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                hosts: Mutex::new(Vec::new()),
            }),
            ReleaseOnDrop(gate),
        )
    }
}
impl BlockingHostLookup for GatedLookup {
    fn lookup(&self, host: &str) -> Answer {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        crate::lock(&self.hosts).push(host.into());
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        if call <= self.blocked_calls {
            self.gate.wait();
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(vec![ip(if call == 1 { 1 } else { 2 })])
    }
}
fn service(
    lookup: Arc<dyn BlockingHostLookup>,
    max_active: usize,
    max_in_flight: usize,
) -> (SystemResolver, Arc<MetricsRegistry>) {
    let metrics = Arc::new(MetricsRegistry::new());
    (
        SystemResolver::with_lookup(
            lookup,
            SystemDnsPolicy {
                max_active,
                max_in_flight,
                admission_timeout: Duration::from_secs(2),
            },
            metrics.clone(),
        ),
        metrics,
    )
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("condition did not become true"));
}
fn query(resolver: &SystemResolver, host: &str) -> tokio::task::JoinHandle<Answer> {
    let resolver = resolver.clone();
    let host = host.to_owned();
    tokio::spawn(async move { resolver.query(host).await })
}

#[tokio::test]
async fn physical_work_and_queue_remain_bounded_until_real_return() {
    let (lookup, _release) = GatedLookup::new(2);
    let (resolver, metrics) = service(lookup.clone(), 2, 4);
    let a = query(&resolver, "a.test");
    let b = query(&resolver, "b.test");
    until(|| lookup.calls.load(Ordering::SeqCst) == 2).await;
    let c = query(&resolver, "c.test");
    let d = query(&resolver, "d.test");
    until(|| metrics.dns().snapshot().system_queued == 2).await;
    assert_eq!(
        resolver.query("e.test".into()).await,
        Err(ResolveError::Capacity)
    );
    a.abort();
    b.abort();
    c.abort();
    let _ = (a.await, b.await, c.await);
    until(|| metrics.dns().snapshot().system_queued == 1).await;
    assert_eq!(metrics.dns().snapshot().system_active, 2);
    assert_eq!(resolver.inner.permits.available_permits(), 0);
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
    lookup.gate.release();
    assert!(d.await.unwrap_or_else(|e| panic!("{e}")).is_ok());
    until(|| metrics.dns().snapshot().system_active == 0).await;
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 3);
    assert_eq!(lookup.peak.load(Ordering::SeqCst), 2);
    assert!(
        !crate::lock(&lookup.hosts)
            .iter()
            .any(|host| host == "c.test")
    );
    assert!(crate::lock(&resolver.inner.flights).is_empty());
    assert_eq!(resolver.inner.admission.available_permits(), 4);
    assert_eq!(resolver.inner.permits.available_permits(), 2);
}

#[tokio::test]
async fn repeated_logical_timeouts_reuse_physical_work_and_new_cohort_recovers() {
    let (lookup, _release) = GatedLookup::new(1);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let shared = SharedDns::with_policy(
        Arc::new(resolver.clone()),
        metrics.clone(),
        DnsPolicy {
            lookup_timeout: Duration::from_millis(40),
            timeout_ttl: Duration::from_millis(4),
            ..DnsPolicy::default()
        },
    );
    for _ in 0..3 {
        assert!(matches!(
            shared.resolve_for_transport("held.test", 80).await,
            Err(ResolveError::Timeout(_))
        ));
        tokio::time::sleep(Duration::from_millis(6)).await;
        assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.dns().snapshot().system_active, 1);
        assert_eq!(resolver.inner.permits.available_permits(), 0);
    }
    let previous_joins = metrics.dns().snapshot().system_coalesced;
    let resumed = {
        let shared = shared.clone();
        tokio::spawn(async move { shared.resolve_for_transport("held.test", 80).await })
    };
    until(|| metrics.dns().snapshot().system_coalesced > previous_joins).await;
    lookup.gate.release();
    let answer = resumed
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(answer, vec![SocketAddr::new(ip(2), 80)]);
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
    assert_eq!(lookup.peak.load(Ordering::SeqCst), 1);
    assert_eq!(
        shared.cached_family_list("held.test", ResolveFamily::V4, Instant::now()),
        Some(vec![ip(2)])
    );
}

#[tokio::test]
async fn invalidation_waits_for_old_physical_generation_then_caches_fresh_answer() {
    let (lookup, _release) = GatedLookup::new(1);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let shared = SharedDns::with_policy(Arc::new(resolver), metrics.clone(), DnsPolicy::default());
    let first = {
        let shared = shared.clone();
        tokio::spawn(async move { shared.resolve_for_transport("version.test", 80).await })
    };
    until(|| lookup.calls.load(Ordering::SeqCst) == 1).await;
    shared.invalidate("version.test");
    let next = {
        let shared = shared.clone();
        tokio::spawn(async move { shared.resolve_for_transport("version.test", 80).await })
    };
    until(|| metrics.dns().snapshot().system_coalesced >= 1).await;
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
    lookup.gate.release();
    let answer = next
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(answer, vec![SocketAddr::new(ip(2), 80)]);
    assert!(first.await.unwrap_or_else(|e| panic!("{e}")).is_ok());
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        shared.cached_family_list("version.test", ResolveFamily::V4, Instant::now()),
        Some(vec![ip(2)])
    );
}

fn registered_guard(
    resolver: &SystemResolver,
    host: &str,
) -> (PhysicalGuard, watch::Receiver<Option<Answer>>) {
    registered_guard_before(resolver, host, Instant::now() + Duration::from_secs(2))
}

fn registered_guard_before(
    resolver: &SystemResolver,
    host: &str,
    deadline: Instant,
) -> (PhysicalGuard, watch::Receiver<Option<Answer>>) {
    let (result, receiver) = watch::channel(None);
    let flight = Arc::new(Flight {
        result,
        deadline,
        abandoned: AtomicBool::new(false),
    });
    crate::lock(&resolver.inner.flights).insert(host.into(), flight.clone());
    resolver.inner.metrics.dns().system_queued_inc();
    let slot = resolver
        .inner
        .admission
        .clone()
        .try_acquire_owned()
        .unwrap_or_else(|e| panic!("{e}"));
    (
        PhysicalGuard {
            inner: resolver.inner.clone(),
            host: host.into(),
            flight,
            queued: true,
            active: false,
            finished: false,
            fallback: ResolveError::Cancelled,
            slot: Some(slot),
            execution: None,
        },
        receiver,
    )
}

#[tokio::test]
async fn abandoned_queued_generation_cannot_be_revived_by_new_subscriber() {
    let (lookup, _release) = GatedLookup::new(0);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let (guard, receiver) = registered_guard(&resolver, "queued.test");
    // Represents the old cohort leaving while a later cohort is subscribed.
    // Admission must inspect abandonment, not merely receiver_count > 0.
    guard.flight.abandoned.store(true, Ordering::Release);
    admit(guard).await;
    assert_eq!(*receiver.borrow(), Some(Err(ResolveError::Cancelled)));
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 0);
    assert_eq!(metrics.dns().snapshot().system_started, 0);
    assert_eq!(resolver.query("queued.test".into()).await, Ok(vec![ip(1)]));
}

#[tokio::test]
async fn cancelled_waiter_and_new_subscriber_cannot_revive_job_before_start_commit() {
    let (lookup, _lookup_release) = GatedLookup::new(0);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let (mut guard, receiver) = registered_guard(&resolver, "start-race.test");
    let old_waiter = Waiter {
        inner: resolver.inner.clone(),
        flight: guard.flight.clone(),
        receiver,
    };
    let permit = resolver
        .inner
        .permits
        .clone()
        .try_acquire_owned()
        .unwrap_or_else(|e| panic!("{e}"));
    guard.execution = Some(permit);
    let before_start = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(before_start.clone());
    let inspected = Arc::new(AtomicBool::new(false));
    let worker_inspected = inspected.clone();
    let worker_gate = before_start.clone();
    let worker = std::thread::spawn(move || {
        // The previous implementation trusted this observation across the
        // later subscription check. Force that exact ordering with real
        // waiter cancellation and a new subscriber before the start commit.
        assert!(!guard.flight.abandoned.load(Ordering::Acquire));
        worker_inspected.store(true, Ordering::Release);
        worker_gate.wait();
        run_lookup(guard);
    });
    until(|| inspected.load(Ordering::Acquire)).await;
    drop(old_waiter);
    let new_waiter = query(&resolver, "start-race.test");
    until(|| metrics.dns().snapshot().system_coalesced == 1).await;
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 0);
    before_start.release();
    assert_eq!(
        new_waiter.await.unwrap_or_else(|e| panic!("{e}")),
        Ok(vec![ip(1)])
    );
    worker
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
    // Only the new physical generation reaches the actual blocking seam.
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
    assert_eq!(metrics.dns().snapshot().system_started, 1);
    assert_eq!(metrics.dns().snapshot().system_active, 0);
    assert_eq!(metrics.dns().snapshot().system_queued, 0);
    assert!(crate::lock(&resolver.inner.flights).is_empty());
}

#[tokio::test]
async fn final_publication_rechecks_invalidation_after_lookup_computed_success() {
    let (lookup, _release) = GatedLookup::new(0);
    let (resolver, _) = service(lookup, 1, 4);
    let (mut guard, receiver) = registered_guard(&resolver, "late.test");
    let computed_answer = Ok(vec![ip(1)]);
    resolver.invalidate_host("late.test");
    guard.finish(computed_answer);
    assert_eq!(*receiver.borrow(), Some(Err(ResolveError::Cancelled)));
    assert!(crate::lock(&resolver.inner.flights).is_empty());
    assert_eq!(resolver.inner.admission.available_permits(), 4);
}

#[test]
fn blocked_system_lookup_does_not_delay_runtime_destruction() {
    let (lookup, _release) = GatedLookup::new(1);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let worker_resolver = resolver.clone();
    let worker_lookup = lookup.clone();
    let (exited, received) = std::sync::mpsc::channel();
    let driver = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        runtime.block_on(async move {
            let waiter = query(&worker_resolver, "shutdown.test");
            until(|| worker_lookup.calls.load(Ordering::SeqCst) == 1).await;
            waiter.abort();
            let _ = waiter.await;
        });
        drop(runtime);
        let _ = exited.send(());
    });
    received
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_else(|e| panic!("runtime did not exit: {e}"));
    assert_eq!(metrics.dns().snapshot().system_active, 1);
    assert_eq!(resolver.inner.permits.available_permits(), 0);
    lookup.gate.release();
    driver
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
    let deadline = Instant::now() + Duration::from_secs(2);
    while resolver.inner.permits.available_permits() != 1
        || resolver.inner.admission.available_permits() != 4
    {
        assert!(
            Instant::now() < deadline,
            "physical resources were not released"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(metrics.dns().snapshot().system_active, 0);
    assert!(crate::lock(&resolver.inner.flights).is_empty());
}

#[tokio::test]
async fn timely_published_success_survives_delayed_waiter_scheduling() {
    let (lookup, _release) = GatedLookup::new(0);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let deadline = Instant::now() + Duration::from_millis(100);
    let (mut guard, _receiver) = registered_guard_before(&resolver, "scheduled.test", deadline);
    let waiter = query(&resolver, "scheduled.test");
    until(|| metrics.dns().snapshot().system_coalesced == 1).await;
    assert!(Instant::now() < deadline);
    guard.finish(Ok(vec![ip(1)]));
    // Deterministically advance the old flight's observation time by holding
    // this current-thread runtime after publication. Its caller has more time.
    std::thread::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
    );
    assert_eq!(
        waiter.await.unwrap_or_else(|e| panic!("{e}")),
        Ok(vec![ip(1)])
    );
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn panicking_worker_releases_registry_and_permits_for_retry() {
    struct PanicOnce(AtomicUsize);
    impl BlockingHostLookup for PanicOnce {
        fn lookup(&self, _: &str) -> Answer {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("injected lookup panic");
            }
            Ok(vec![ip(2)])
        }
    }
    let (resolver, metrics) = service(Arc::new(PanicOnce(AtomicUsize::new(0))), 1, 1);
    assert_eq!(
        resolver.query("panic.test".into()).await,
        Err(ResolveError::Cancelled)
    );
    assert_eq!(resolver.inner.permits.available_permits(), 1);
    assert_eq!(resolver.query("panic.test".into()).await, Ok(vec![ip(2)]));
    assert_eq!(metrics.dns().snapshot().system_started, 2);
    assert_eq!(metrics.dns().snapshot().system_active, 0);
}

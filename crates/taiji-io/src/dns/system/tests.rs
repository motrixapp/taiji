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
struct ReleaseOnDrop(Vec<Arc<Gate>>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        for gate in &self.0 {
            gate.release();
        }
    }
}
struct GatedLookup {
    gate: Arc<Gate>,
    /// Per-call gates: physical call n waits on `gates[n - 1]`. `None`
    /// (the default rig) blocks every call up to `blocked_calls` on the
    /// single shared `gate` instead.
    call_gates: Option<Vec<Arc<Gate>>>,
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
                call_gates: None,
                blocked_calls,
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                hosts: Mutex::new(Vec::new()),
            }),
            ReleaseOnDrop(vec![gate]),
        )
    }
    /// One independent gate per blocked physical call (`release_call`),
    /// so a test can hold one generation inside the flight registry while
    /// the coalescing of further retries against it is observed.
    fn with_call_gates(blocked_calls: usize) -> (Arc<Self>, ReleaseOnDrop) {
        let gates: Vec<_> = (0..blocked_calls)
            .map(|_| Arc::new(Gate::default()))
            .collect();
        (
            Arc::new(Self {
                gate: Arc::new(Gate::default()),
                call_gates: Some(gates.clone()),
                blocked_calls,
                calls: AtomicUsize::new(0),
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                hosts: Mutex::new(Vec::new()),
            }),
            ReleaseOnDrop(gates),
        )
    }
    fn release_call(&self, call: usize) {
        self.call_gates
            .as_ref()
            .unwrap_or_else(|| panic!("per-call gates not configured"))
            .get(call - 1)
            .unwrap_or_else(|| panic!("physical call {call} has no gate"))
            .release();
    }
}
impl BlockingHostLookup for GatedLookup {
    fn lookup(&self, host: &str) -> Answer {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        crate::lock(&self.hosts).push(host.into());
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        if call <= self.blocked_calls {
            match &self.call_gates {
                Some(gates) => gates[call - 1].wait(),
                None => self.gate.wait(),
            }
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

/// Causal model, made deterministic: the first request starts physical
/// call 1 (gated). `invalidate` retires that generation; a
/// post-invalidation request must WAIT for the old physical call (it
/// coalesces onto the old flight instead of preempting it) and must never
/// receive the old generation's answer. When the old call returns, its
/// already-computed success is discarded and BOTH cohorts' retries
/// coalesce into exactly ONE replacement physical generation — the
/// replacement call is gated inside the flight registry, so the second
/// retry cannot miss it regardless of task-wakeup order — which serves
/// and caches the fresh answer.
///
/// Why the test side is the right side: the resolver's guarantees (the
/// retired generation's stale answer is rewritten to `Cancelled` under
/// the registry lock, retries that overlap coalesce, physical lookups
/// never run concurrently for one host) hold under every scheduling
/// order, but the previously asserted "exactly two physical calls" also
/// required the two retries to OVERLAP the replacement flight's
/// microseconds-long registry lifetime — a scheduling assumption, not a
/// resolver property. The companion test
/// [`late_retry_after_replacement_completes_starts_one_fresh_bounded_call`]
/// forces the other interleaving deterministically (one retry's poll held
/// back until the replacement generation completed) and shows the third
/// call it produces is a bounded, fresh re-resolution by the retired
/// cohort — not a stale answer and not a concurrent duplicate. Gating the
/// replacement call here pins the same coalescing property without
/// depending on that scheduling luck.
#[tokio::test]
async fn invalidation_waits_for_old_physical_generation_then_caches_fresh_answer() {
    let (lookup, _release) = GatedLookup::with_call_gates(2);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let shared = SharedDns::with_policy(
        Arc::new(resolver.clone()),
        metrics.clone(),
        DnsPolicy::default(),
    );
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
    // The retired generation is still the only physical call: the new
    // cohort waits for the old flight instead of preempting it.
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
    lookup.release_call(1);
    // The old generation's success is discarded (its flight was marked
    // abandoned before it returned); both cohorts retry into ONE
    // replacement generation, held in the registry on its own gate.
    until(|| lookup.calls.load(Ordering::SeqCst) == 2).await;
    until(|| metrics.dns().snapshot().system_coalesced >= 2).await;
    {
        let flights = crate::lock(&resolver.inner.flights);
        assert_eq!(flights.len(), 1, "exactly one replacement flight exists");
        assert_eq!(
            flights
                .get("version.test")
                .map(|flight| flight.result.receiver_count()),
            Some(2),
            "both cohorts' retries joined the replacement flight"
        );
    }
    lookup.release_call(2);
    let answer = next
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    // Fresh post-invalidation answer (call 2's ip(2)), never call 1's
    // stale ip(1).
    assert_eq!(answer, vec![SocketAddr::new(ip(2), 80)]);
    assert!(first.await.unwrap_or_else(|e| panic!("{e}")).is_ok());
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        lookup.peak.load(Ordering::SeqCst),
        1,
        "physical lookups never overlap"
    );
    assert_eq!(
        shared.cached_family_list("version.test", ResolveFamily::V4, Instant::now()),
        Some(vec![ip(2)])
    );
}

/// Deterministic reproduction of the scheduling interleaving behind this
/// test family's historic flake ("3 vs 2 physical calls"): the first
/// cohort runs on its own runtime/thread, and THIS runtime is pinned
/// (blocked inside the test task) while the retired old generation
/// publishes and the first cohort's replacement generation runs to
/// completion and leaves the flight registry. Only then is the new
/// cohort's retry polled — into an empty registry, so it starts one
/// fresh physical call. This pins that the extra call is the correct
/// outcome of that order: the answer served and cached is fresh (never
/// the retired generation's stale ip(1); `finish` rewrote it to
/// `Cancelled` under the registry lock), physical lookups never overlap
/// (peak == 1), and the total stays bounded at one physical call per
/// waiter — the resolver's invariants hold in BOTH interleavings, so the
/// old un-gated "exactly two calls" assertion encoded a scheduler
/// assumption, not a production bug.
#[tokio::test]
async fn late_retry_after_replacement_completes_starts_one_fresh_bounded_call() {
    let (lookup, _release) = GatedLookup::new(1);
    let (resolver, metrics) = service(lookup.clone(), 1, 4);
    let shared = SharedDns::with_policy(
        Arc::new(resolver.clone()),
        metrics.clone(),
        DnsPolicy::default(),
    );
    // The first cohort runs on its own runtime/thread, so its
    // post-invalidation retry proceeds even while THIS runtime is pinned.
    let first_shared = shared.clone();
    let first = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("{e}"));
        runtime
            .block_on(async move { first_shared.resolve_for_transport("version.test", 80).await })
    });
    until(|| lookup.calls.load(Ordering::SeqCst) == 1).await;
    shared.invalidate("version.test");
    let next = {
        let shared = shared.clone();
        tokio::spawn(async move { shared.resolve_for_transport("version.test", 80).await })
    };
    until(|| metrics.dns().snapshot().system_coalesced >= 1).await;
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
    // Pin this current-thread runtime: the new cohort's system retry task
    // is woken by the old flight's publication but cannot be polled while
    // the test task blocks here. The first cohort's retry runs to
    // completion on its own thread; its replacement generation completes
    // and leaves the registry (calls == 2 and an empty flight map).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut released = false;
    while !(lookup.calls.load(Ordering::SeqCst) >= 2
        && crate::lock(&resolver.inner.flights).is_empty())
    {
        assert!(
            Instant::now() < deadline,
            "replacement generation did not settle"
        );
        if !released {
            lookup.gate.release();
            released = true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // Unpin: the held-back cohort retries into an empty registry and
    // starts one fresh physical generation (call 3).
    let answer = next
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(answer, vec![SocketAddr::new(ip(2), 80)]);
    let first_answer = first
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
    assert_eq!(first_answer, Ok(vec![SocketAddr::new(ip(2), 80)]));
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        lookup.peak.load(Ordering::SeqCst),
        1,
        "physical lookups never overlap, even across the extra retry"
    );
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
            queued_at: Some(Instant::now()),
            started_at: None,
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
    let _release = ReleaseOnDrop(vec![before_start.clone()]);
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

#[tokio::test]
async fn network_change_rejects_a_published_result_not_yet_consumed() {
    let (lookup, _release) = GatedLookup::new(1);
    let (resolver, _) = service(lookup.clone(), 1, 4);
    let waiting = query(&resolver, "published.test");
    until(|| lookup.calls.load(Ordering::SeqCst) == 1).await;
    lookup.gate.release();
    // Keep this current-thread runtime on the test task while the dedicated
    // system thread publishes. The waiting task cannot consume its result yet.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !crate::lock(&resolver.inner.flights).is_empty() {
        assert!(Instant::now() < deadline, "system lookup did not publish");
        std::thread::sleep(Duration::from_millis(1));
    }
    resolver.invalidate_all();
    assert_eq!(
        waiting.await.unwrap_or_else(|e| panic!("{e}")),
        Ok(vec![ip(2)])
    );
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn closed_runtime_submission_releases_guards_without_locking_itself() {
    let (done, completed) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let (lookup, _release) = GatedLookup::new(0);
        let (resolver, metrics) = service(lookup.clone(), 1, 1);
        let shared = SharedDns::with_policy(
            Arc::new(resolver.clone()),
            metrics.clone(),
            DnsPolicy {
                max_in_flight: 1,
                ..DnsPolicy::default()
            },
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("runtime: {error}"));
        let handle = runtime.handle().clone();
        drop(runtime);
        let entered = handle.enter();
        // A stopped runtime may reject a timer as well as cancel a new task.
        // Either result must leave the resolver usable, without a lock held
        // by a synchronously dropped admission/query guard.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures::executor::block_on(resolver.query("closed.test".into()))
        }));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            futures::executor::block_on(shared.resolve_for_transport("closed.test", 80))
        }));
        drop(entered);
        assert_eq!(lookup.calls.load(Ordering::SeqCst), 0);
        assert_eq!(metrics.snapshot().dns.system_queued, 0);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("replacement runtime: {error}"));
        let answer = runtime.block_on(shared.resolve_for_transport("closed.test", 80));
        assert_eq!(answer.map(|values| values[0].ip()), Ok(ip(1)));
        done.send(())
            .unwrap_or_else(|error| panic!("completion: {error}"));
    });
    completed
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or_else(|error| panic!("closed-runtime cleanup did not finish: {error}"));
    worker
        .join()
        .unwrap_or_else(|error| std::panic::resume_unwind(error));
}

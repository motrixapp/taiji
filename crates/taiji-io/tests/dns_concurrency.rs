//! Independent acceptance of the public shared DNS service. All DNS answers
//! are injected; no test alters or queries the machine's DNS configuration.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use taiji_io::dns::{
    DnsPolicy, HostResolver, ListResolverFuture, ResolveError, ResolveFamily, ResolverFuture,
    SharedDns,
};
use taiji_io::metrics::MetricsRegistry;
use tokio::sync::{Barrier, watch};
use tokio::task::JoinSet;

#[derive(Clone)]
struct Resolver {
    calls: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    release: watch::Receiver<bool>,
    failures_left: Arc<AtomicUsize>,
    addresses: Vec<IpAddr>,
}
struct ActiveGuard(Arc<AtomicUsize>);
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Resolver {
    fn gated(addresses: Vec<IpAddr>) -> (Self, watch::Sender<bool>) {
        let (release, receiver) = watch::channel(false);
        (
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                active: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
                release: receiver,
                failures_left: Arc::new(AtomicUsize::new(0)),
                addresses,
            },
            release,
        )
    }
}
impl HostResolver for Resolver {
    fn resolve(&self, host: String) -> ResolverFuture {
        let future = self.resolve_list(host);
        Box::pin(async move {
            future
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| "empty fixture".into())
        })
    }
    fn resolve_list(&self, _host: String) -> ListResolverFuture {
        let state = self.clone();
        Box::pin(async move {
            state.calls.fetch_add(1, Ordering::SeqCst);
            let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
            state.peak.fetch_max(active, Ordering::SeqCst);
            let _active = ActiveGuard(Arc::clone(&state.active));
            let mut gate = state.release.clone();
            while !*gate.borrow_and_update() {
                gate.changed().await.map_err(|error| error.to_string())?;
            }
            let failed = state
                .failures_left
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
            if failed {
                Err("controlled transient resolution failure".into())
            } else {
                Ok(state.addresses)
            }
        })
    }
}
fn v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
}
fn service(resolver: Resolver, policy: DnsPolicy) -> (Arc<SharedDns>, Arc<MetricsRegistry>) {
    let registry = Arc::new(MetricsRegistry::new());
    (
        Arc::new(SharedDns::with_policy(
            Arc::new(resolver),
            Arc::clone(&registry),
            policy,
        )),
        registry,
    )
}
async fn wait_for(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|error| panic!("condition not reached: {error}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cold_requests_share_one_lookup_across_ports_and_families() {
    let v6: IpAddr = "2001:db8::10"
        .parse()
        .unwrap_or_else(|error| panic!("{error}"));
    let (resolver, release) = Resolver::gated(vec![v4(), v6, v4()]);
    let calls = Arc::clone(&resolver.calls);
    let (dns, registry) = service(resolver, DnsPolicy::default());
    let barrier = Arc::new(Barrier::new(129));
    let mut callers = JoinSet::new();
    for index in 0..128 {
        let dns = Arc::clone(&dns);
        let barrier = Arc::clone(&barrier);
        callers.spawn(async move {
            barrier.wait().await;
            let name = if index % 2 == 0 {
                "TRACKER.example"
            } else {
                "tracker.example"
            };
            dns.resolve_for_transport(name, 4000 + index).await
        });
    }
    barrier.wait().await;
    wait_for(|| registry.snapshot().dns.lookups_miss == 128 && calls.load(Ordering::SeqCst) > 0)
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    release
        .send(true)
        .unwrap_or_else(|error| panic!("release: {error}"));
    while let Some(caller) = callers.join_next().await {
        let addresses = caller
            .unwrap_or_else(|error| panic!("join: {error}"))
            .unwrap_or_else(|error| panic!("resolve: {error}"));
        assert_eq!(addresses.len(), 2);
        assert_eq!(
            addresses
                .iter()
                .map(|address| address.ip())
                .collect::<Vec<_>>(),
            vec![v4(), v6]
        );
    }
    assert_eq!(
        dns.resolve_family_list("tracker.example".into(), ResolveFamily::V4)
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        vec![v4()]
    );
    assert_eq!(
        dns.resolve_family_list("tracker.example".into(), ResolveFamily::V6)
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        vec![v6]
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "warm and per-family reads reuse the same list"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_the_leader_and_one_waiter_does_not_cancel_the_shared_work() {
    let (resolver, release) = Resolver::gated(vec![v4()]);
    let calls = Arc::clone(&resolver.calls);
    let (dns, registry) = service(resolver, DnsPolicy::default());
    let first_dns = Arc::clone(&dns);
    let first =
        tokio::spawn(async move { first_dns.resolve_for_transport("cancel.example", 80).await });
    wait_for(|| calls.load(Ordering::SeqCst) == 1).await;
    let single_dns = Arc::clone(&dns);
    let single = tokio::spawn(async move {
        single_dns
            .resolve_for_transport("cancel.example", 443)
            .await
    });
    let mut followers = JoinSet::new();
    for _ in 0..32 {
        let dns = Arc::clone(&dns);
        followers.spawn(async move { dns.resolve_for_transport("cancel.example", 443).await });
    }
    wait_for(|| registry.snapshot().dns.lookups_miss == 34).await;
    first.abort();
    single.abort();
    assert!(first.await.is_err());
    assert!(single.await.is_err());
    release
        .send(true)
        .unwrap_or_else(|error| panic!("release: {error}"));
    while let Some(result) = followers.join_next().await {
        assert!(result.unwrap_or_else(|error| panic!("{error}")).is_ok());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distinct_hosts_run_concurrently_and_admission_failures_are_not_cached() {
    let (resolver, release) = Resolver::gated(vec![v4()]);
    let active = Arc::clone(&resolver.active);
    let peak = Arc::clone(&resolver.peak);
    let calls = Arc::clone(&resolver.calls);
    let (dns, _) = service(
        resolver,
        DnsPolicy {
            max_in_flight: 4,
            ..DnsPolicy::default()
        },
    );
    let mut work = JoinSet::new();
    for index in 0..4 {
        let dns = Arc::clone(&dns);
        work.spawn(async move {
            dns.resolve_for_transport(&format!("h{index}.example"), 80)
                .await
        });
    }
    wait_for(|| active.load(Ordering::SeqCst) == 4).await;
    assert!(matches!(
        dns.resolve_for_transport("overflow.example", 80).await,
        Err(ResolveError::Capacity)
    ));
    release.send(true).unwrap_or_else(|error| panic!("{error}"));
    while let Some(result) = work.join_next().await {
        assert!(result.unwrap_or_else(|error| panic!("{error}")).is_ok());
    }
    assert!(
        dns.resolve_for_transport("overflow.example", 80)
            .await
            .is_ok()
    );
    assert_eq!(peak.load(Ordering::SeqCst), 4);
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn failed_lookup_is_short_cached_then_recovers_with_a_fresh_query() {
    let (resolver, release) = Resolver::gated(vec![v4()]);
    resolver.failures_left.store(1, Ordering::SeqCst);
    let calls = Arc::clone(&resolver.calls);
    let (dns, _) = service(
        resolver,
        DnsPolicy {
            failure_ttl: Duration::from_millis(100),
            ..DnsPolicy::default()
        },
    );
    release.send(true).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        dns.resolve_for_transport("recover.example", 80)
            .await
            .is_err()
    );
    assert!(
        dns.resolve_for_transport("recover.example", 443)
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(130)).await;
    let mut work = JoinSet::new();
    for _ in 0..128 {
        let dns = Arc::clone(&dns);
        work.spawn(async move { dns.resolve_for_transport("recover.example", 80).await });
    }
    while let Some(result) = work.join_next().await {
        assert!(result.unwrap_or_else(|error| panic!("{error}")).is_ok());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn missing_ipv6_records_do_not_poison_ipv4_and_absolute_names_stay_distinct() {
    let (resolver, release) = Resolver::gated(vec![v4()]);
    let calls = Arc::clone(&resolver.calls);
    let (dns, _) = service(resolver, DnsPolicy::default());
    release.send(true).unwrap_or_else(|error| panic!("{error}"));
    assert!(
        dns.resolve_family_list("family.example".into(), ResolveFamily::V6)
            .await
            .is_err()
    );
    assert_eq!(
        dns.resolve_family_list("FAMILY.example".into(), ResolveFamily::V4)
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        vec![v4()]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        dns.resolve_for_transport("family.example.", 80)
            .await
            .is_ok()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "absolute and search-suffix names are not interchangeable"
    );
}

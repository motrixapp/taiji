use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use taiji_io::dns::{
    BlockingHostLookup, ClassifiedListFuture, DnsPolicy, HostResolver, ResolveError,
    ResolverFuture, SharedDns, SystemDnsPolicy, SystemResolver,
};
use taiji_io::metrics::MetricsRegistry;

fn ip(version: u8) -> IpAddr {
    Ipv4Addr::new(192, 0, 2, version).into()
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|error| panic!("condition not reached: {error}"));
}

struct VersionedResolver {
    version: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}
impl HostResolver for VersionedResolver {
    fn resolve(&self, _: String) -> ResolverFuture {
        Box::pin(std::future::pending())
    }
    fn resolve_list_classified(&self, host: String) -> ClassifiedListFuture {
        let version = self.version.load(Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if host == "private.example" && version == 1 {
                Err(ResolveError::Failed("not available on old network".into()))
            } else {
                Ok(vec![ip(version as u8)])
            }
        })
    }
}

#[tokio::test]
async fn network_change_invalidates_positive_and_negative_answers_together() {
    let version = Arc::new(AtomicUsize::new(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let metrics = Arc::new(MetricsRegistry::new());
    let dns = SharedDns::with_registry(
        Arc::new(VersionedResolver {
            version: version.clone(),
            calls: calls.clone(),
        }),
        metrics.clone(),
    );
    assert_eq!(
        dns.resolve_for_transport("public.example", 80)
            .await
            .map(|v| v[0].ip()),
        Ok(ip(1))
    );
    assert!(
        dns.resolve_for_transport("private.example", 80)
            .await
            .is_err()
    );
    version.store(2, Ordering::SeqCst);
    assert_eq!(
        dns.resolve_for_transport("public.example", 80)
            .await
            .map(|v| v[0].ip()),
        Ok(ip(1))
    );
    assert!(
        dns.resolve_for_transport("private.example", 80)
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    dns.network_changed();
    for host in ["public.example", "private.example"] {
        assert_eq!(
            dns.resolve_for_transport(host, 80).await.map(|v| v[0].ip()),
            Ok(ip(2))
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(dns.generation(), 1);
    assert_eq!(metrics.snapshot().dns.network_changes, 1);
}

#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    condition: Condvar,
}
impl Gate {
    fn wait(&self) {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        while !*open {
            open = self.condition.wait(open).unwrap_or_else(|e| e.into_inner());
        }
    }
    fn release(&self) {
        *self.open.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.condition.notify_all();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct BlockingVersion {
    calls: AtomicUsize,
    gate: Arc<Gate>,
}
impl BlockingHostLookup for BlockingVersion {
    fn lookup(&self, _: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let version = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if version == 1 {
            self.gate.wait();
        }
        Ok(vec![ip(version as u8)])
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiting_callers_move_to_new_network_without_accepting_the_late_system_answer() {
    let gate = Arc::new(Gate::default());
    let _release = Release(gate.clone());
    let lookup = Arc::new(BlockingVersion {
        calls: AtomicUsize::new(0),
        gate: gate.clone(),
    });
    let metrics = Arc::new(MetricsRegistry::new());
    let system = SystemResolver::with_lookup(
        lookup.clone(),
        SystemDnsPolicy {
            max_active: 2,
            max_in_flight: 4,
            admission_timeout: Duration::from_secs(3),
        },
        metrics.clone(),
    );
    let dns = SharedDns::with_registry(Arc::new(system), metrics.clone());
    let waiting = {
        let dns = dns.clone();
        tokio::spawn(async move { dns.resolve_for_transport("same.example", 80).await })
    };
    until(|| lookup.calls.load(Ordering::SeqCst) == 1).await;
    dns.network_changed();
    let answer = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .unwrap_or_else(|e| panic!("new network must not wait for retired work: {e}"))
        .unwrap_or_else(|e| panic!("join: {e}"))
        .unwrap_or_else(|e| panic!("resolve: {e}"));
    assert_eq!(answer[0].ip(), ip(2));
    assert_eq!(
        metrics.snapshot().dns.system_active,
        1,
        "old syscall still owns its real budget"
    );
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 2);
    gate.release();
    until(|| metrics.snapshot().dns.system_active == 0).await;
    assert_eq!(
        dns.resolve_for_transport("same.example", 80)
            .await
            .map(|v| v[0].ip()),
        Ok(ip(2))
    );
    assert_eq!(
        lookup.calls.load(Ordering::SeqCst),
        2,
        "late old result never replaced the fresh cache"
    );
    let snapshot = metrics.snapshot().dns;
    assert_eq!(snapshot.system_queued, 0);
    assert_eq!(snapshot.system_queue_seconds.count, 2);
    assert_eq!(snapshot.system_lookup_seconds.count, 2);
}

#[tokio::test]
async fn repeated_network_changes_do_not_restart_the_callers_deadline() {
    struct Never;
    impl HostResolver for Never {
        fn resolve(&self, _: String) -> ResolverFuture {
            Box::pin(std::future::pending())
        }
        fn resolve_list_classified(&self, _: String) -> ClassifiedListFuture {
            Box::pin(std::future::pending())
        }
    }
    let budget = Duration::from_millis(100);
    let dns = SharedDns::with_policy(
        Arc::new(Never),
        Arc::new(MetricsRegistry::new()),
        DnsPolicy {
            lookup_timeout: budget,
            ..DnsPolicy::default()
        },
    );
    let changes = {
        let dns = dns.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                dns.network_changed();
            }
        })
    };
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        dns.resolve_for_transport("changing.example", 80),
    )
    .await;
    changes.abort();
    assert_eq!(
        result.unwrap_or_else(|e| panic!("network changes extended deadline: {e}")),
        Err(ResolveError::Timeout(budget))
    );
    assert!(dns.generation() > 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn physical_queue_and_lookup_durations_are_measured_separately() {
    let gate = Arc::new(Gate::default());
    let _release = Release(gate.clone());
    let lookup = Arc::new(BlockingVersion {
        calls: AtomicUsize::new(0),
        gate: gate.clone(),
    });
    let metrics = Arc::new(MetricsRegistry::new());
    let dns = SharedDns::with_registry(
        Arc::new(SystemResolver::with_lookup(
            lookup.clone(),
            SystemDnsPolicy {
                max_active: 1,
                max_in_flight: 4,
                admission_timeout: Duration::from_secs(3),
            },
            metrics.clone(),
        )),
        metrics.clone(),
    );
    let first = {
        let dns = dns.clone();
        tokio::spawn(async move { dns.resolve_for_transport("first.example", 80).await })
    };
    until(|| lookup.calls.load(Ordering::SeqCst) == 1).await;
    let second = {
        let dns = dns.clone();
        tokio::spawn(async move { dns.resolve_for_transport("second.example", 80).await })
    };
    until(|| metrics.snapshot().dns.system_queued == 1).await;
    // Inject a known queue wait; completion is still driven by the real gate.
    tokio::time::sleep(Duration::from_millis(30)).await;
    gate.release();
    assert!(first.await.unwrap_or_else(|e| panic!("{e}")).is_ok());
    assert!(second.await.unwrap_or_else(|e| panic!("{e}")).is_ok());
    let snapshot = metrics.snapshot().dns;
    assert_eq!(snapshot.system_queue_seconds.count, 2);
    assert_eq!(snapshot.system_lookup_seconds.count, 2);
    assert!(snapshot.system_queue_seconds.sum_us >= 30_000);
    assert!(snapshot.system_lookup_seconds.sum_us >= 30_000);
    assert_eq!(snapshot.system_active, 0);
    assert_eq!(snapshot.system_queued, 0);
}

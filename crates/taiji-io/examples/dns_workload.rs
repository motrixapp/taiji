//! Controlled resolver workload. This is not a real DNS latency benchmark.
//! Uses the public 0.4.0 API so the same source can run on a clean baseline.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use taiji_io::dns::{HostResolver, ListResolverFuture, ResolverFuture, SharedDns};
use taiji_io::metrics::MetricsRegistry;
use tokio::sync::{Barrier, watch};
use tokio::task::JoinSet;

const CALLERS: usize = 128;
const RESOLVER_DELAY: Duration = Duration::from_millis(40);

struct ControlledResolver {
    calls: Arc<AtomicUsize>,
    release: watch::Receiver<bool>,
    fail: bool,
}
impl HostResolver for ControlledResolver {
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
        let calls = Arc::clone(&self.calls);
        let mut release = self.release.clone();
        let fail = self.fail;
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            while !*release.borrow_and_update() {
                release.changed().await.map_err(|error| error.to_string())?;
            }
            tokio::time::sleep(RESOLVER_DELAY).await;
            if fail {
                Err("controlled lookup failure".into())
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
            }
        })
    }
}

async fn burst(
    dns: Arc<SharedDns>,
    metrics: &MetricsRegistry,
    calls: &AtomicUsize,
    release: Option<&watch::Sender<bool>>,
    expected_failure: bool,
    scenario: &str,
    iteration: usize,
) -> serde_json::Value {
    let barrier = Arc::new(Barrier::new(CALLERS + 1));
    let before = calls.load(Ordering::SeqCst);
    let misses = metrics.snapshot().dns.lookups_miss;
    let started = Instant::now();
    let mut work = JoinSet::new();
    for index in 0..CALLERS {
        let dns = Arc::clone(&dns);
        let barrier = Arc::clone(&barrier);
        work.spawn(async move {
            barrier.wait().await;
            let start = Instant::now();
            let outcome = dns
                .resolve_for_transport("workload.test", 8080 + (index % 3) as u16)
                .await;
            (start.elapsed().as_micros() as u64, outcome.is_err())
        });
    }
    barrier.wait().await;
    if let Some(release) = release {
        let all_entered = tokio::time::timeout(Duration::from_secs(5), async {
            while metrics.snapshot().dns.lookups_miss < misses + CALLERS as u64 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let _ = release.send(true);
        assert!(
            all_entered.is_ok(),
            "callers did not enter the controlled cold lookup"
        );
    }
    let mut samples = Vec::with_capacity(CALLERS);
    let mut expected_errors = 0;
    let mut unexpected_errors = 0;
    let mut unexpected_successes = 0;
    while let Some(outcome) = work.join_next().await {
        let (elapsed, failed) = outcome.unwrap_or_else(|error| panic!("caller failed: {error}"));
        samples.push(elapsed);
        match (expected_failure, failed) {
            (true, true) => expected_errors += 1,
            (false, true) => unexpected_errors += 1,
            (true, false) => unexpected_successes += 1,
            (false, false) => {}
        }
    }
    samples.sort_unstable();
    serde_json::json!({
        "scenario": scenario, "iteration": iteration, "callers": CALLERS,
        "backend_calls": calls.load(Ordering::SeqCst) - before,
        "expected_errors": expected_errors, "unexpected_errors": unexpected_errors,
        "unexpected_successes": unexpected_successes,
        "p50_us": samples[(CALLERS * 50).div_ceil(100) - 1],
        "p95_us": samples[(CALLERS * 95).div_ceil(100) - 1],
        "batch_us": started.elapsed().as_micros() as u64,
    })
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let iterations = std::env::var("DNS_WORKLOAD_ITERS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(12)
        .clamp(1, 100);
    let mut rows = Vec::new();
    for iteration in 0..iterations {
        for fail in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let metrics = Arc::new(MetricsRegistry::new());
            let (release, gate) = watch::channel(false);
            let resolver = Arc::new(ControlledResolver {
                calls: Arc::clone(&calls),
                release: gate,
                fail,
            });
            let dns = Arc::new(SharedDns::with_registry(resolver, Arc::clone(&metrics)));
            rows.push(
                burst(
                    Arc::clone(&dns),
                    &metrics,
                    &calls,
                    Some(&release),
                    fail,
                    if fail { "failure_cold" } else { "success_cold" },
                    iteration,
                )
                .await,
            );
            rows.push(
                burst(
                    dns,
                    &metrics,
                    &calls,
                    None,
                    fail,
                    if fail {
                        "failure_repeat"
                    } else {
                        "success_warm"
                    },
                    iteration,
                )
                .await,
            );
        }
    }
    let unexpected: u64 = rows
        .iter()
        .map(|row| {
            row["unexpected_errors"].as_u64().unwrap_or(0)
                + row["unexpected_successes"].as_u64().unwrap_or(0)
        })
        .sum();
    println!(
        "{}",
        serde_json::json!({
            "schema": 1, "kind": "controlled_resolver", "resolver_delay_ms": RESOLVER_DELAY.as_millis() as u64,
            "concurrency": CALLERS, "iterations": iterations, "rows": rows, "unexpected_outcomes": unexpected,
        })
    );
    assert_eq!(unexpected, 0, "workload returned an unexpected outcome");
}

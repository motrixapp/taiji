//! Connection-reuse-pool e2e (small-task path): `HttpClient::new` with
//! the same [`ClientConfig`] shares one keep-alive pool across "task
//! lifecycles" — in the many-small batch shape (each round = one task:
//! new client → 16 concurrent Range knives → all knives complete →
//! drop client), the new-connection count drops from 16 per task
//! (per-task isolated transport instances/pools, all connections
//! dropped when the task ends) to first-round connects plus in-pool
//! reuse, and wall clock improves along with the connect tax.
//!
//! The mock origin is keep-alive h1 (hand-written frame layer, zero
//! new dependencies, same discipline as `h2_mock`): the accept count =
//! new-connection count (the only server-side truth). An optional
//! per-connection first-request connect tax simulates real handshake
//! latency (on loopback connecting is nearly free; the tax pulls the
//! wall-clock improvement out of the structural assertion).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_http::cookies::CookieJar;
use taiji_http::traits::RequestCtx;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Concurrent Range knives per task (round): split = 16.
const KNIVES: usize = 16;

/// Test-only Result unwrap (lints forbid unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Keep-alive h1 mock origin observation surface.
#[derive(Default, Clone)]
struct Obs {
    /// TCP accept count = new-connection count (what the reuse
    /// assertions read).
    accepts: Arc<AtomicUsize>,
    /// Total requests answered (guards that the full load was served).
    requests: Arc<AtomicUsize>,
}

/// Per-connection keep-alive serve loop: read the GET request head →
/// (the first request pays the connect tax) → reply with a 206 echoing
/// the Range (1-byte body, Content-Length delimited) → next request.
/// The client's `validate_range_echo` requires the 206 to echo the
/// requested range, so the `Range: bytes=s-e` header is parsed per
/// request and filled back in.
async fn serve_conn(mut stream: TcpStream, obs: Obs, connect_tax: Duration) {
    let mut first_on_conn = true;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        // Read to the end-of-headers marker (GET has no body; the cap
        // bounds malformed input).
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            if buf.len() > 16 * 1024 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
        let range = head.split("\r\n").find_map(|l| {
            let v = l.strip_prefix("range: bytes=")?;
            let (s, e) = v.trim().split_once('-')?;
            Some((s.trim().parse::<u64>().ok()?, e.trim().parse::<u64>().ok()?))
        });
        if first_on_conn {
            first_on_conn = false;
            if !connect_tax.is_zero() {
                tokio::time::sleep(connect_tax).await;
            }
        }
        obs.requests.fetch_add(1, Ordering::SeqCst);
        let resp = match range {
            // A 206 echoing the range (1-byte body; the client
            // validates the echo per response).
            Some((s, e)) => format!(
                "HTTP/1.1 206 Partial Content\r\n\
                 Content-Range: bytes {s}-{e}/1048576\r\n\
                 Content-Length: 1\r\nConnection: keep-alive\r\n\r\nx"
            ),
            None => "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\
                     Connection: keep-alive\r\n\r\nx"
                .to_string(),
        };
        if stream.write_all(resp.as_bytes()).await.is_err() {
            return;
        }
        buf.clear();
    }
}

/// Start the mock origin (random port); `connect_tax` = the
/// per-connection first-request tax.
async fn spawn_origin(connect_tax: Duration) -> (String, Obs) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "addr");
    let obs = Obs::default();
    let accept_obs = obs.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            accept_obs.accepts.fetch_add(1, Ordering::SeqCst);
            let obs = accept_obs.clone();
            let tax = connect_tax;
            tokio::spawn(serve_conn(tcp, obs, tax));
        }
    });
    (format!("http://{addr}"), obs)
}

/// One "task lifecycle": `HttpClient::new` (the per-task creation
/// point, the same shape the http_task driver uses) → 16 concurrent
/// Range knives → all complete → drop (task over, handle released).
/// Returns the wall clock for the round.
async fn one_task_lifecycle(base: &str, cfg: &ClientConfig) -> Duration {
    let client = ok(HttpClient::new(cfg.clone()), "client");
    let ctx = RequestCtx::default();
    let start = Instant::now();
    let mut knives = Vec::with_capacity(KNIVES);
    for i in 0..KNIVES {
        let client = client.clone();
        let url = format!("{base}/small{i}.bin");
        let ctx = ctx.clone();
        knives.push(tokio::spawn(async move {
            let followed = ok(client.get_range(&url, &ctx, 0, 0).await, "range get");
            ok(followed.response.bytes().await, "body")
        }));
    }
    for k in knives {
        assert_eq!(ok(k.await, "join").as_ref(), b"x");
    }
    drop(client);
    start.elapsed()
}

fn bench_cfg() -> ClientConfig {
    ClientConfig {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    }
}

/// Warm-pool signal: a data-plane success lights it, a probe-plane
/// success does not, and an untouched host stays cold — the stagger
/// decision site uses this to skip or keep the ramp.
#[tokio::test]
async fn warm_signal_lights_on_data_plane_only() {
    let (base, _obs) = spawn_origin(Duration::ZERO).await;
    let (probe_base, _probe_obs) = spawn_origin(Duration::ZERO).await;
    let cfg = bench_cfg();
    let client = ok(HttpClient::new(cfg), "client");
    let ctx = RequestCtx::default();

    // A data-plane (get_range / inner instance) success lights it.
    assert!(
        !taiji_http::client::uri_on_warm_pool(&format!("{base}/f.bin")),
        "an untouched host stays cold (random ports avoid cross-test collisions)"
    );
    let followed = ok(
        client.get_range(&format!("{base}/f.bin"), &ctx, 0, 0).await,
        "data-plane get_range",
    );
    assert_eq!(ok(followed.response.bytes().await, "body").as_ref(), b"x");
    assert!(
        taiji_http::client::uri_on_warm_pool(&format!("{base}/other.bin")),
        "after a data-plane success the same host key lights up (paths are not part of the key)"
    );

    // A probe-plane (get_range_raw / raw instance) success does NOT
    // light it (probe connections live on a separate pool that
    // data-plane knives cannot reuse — lighting it would mean skipping
    // without reuse).
    let followed = ok(
        client
            .get_range_raw(&format!("{probe_base}/probe.bin"), &ctx, 0, 0)
            .await,
        "probe-plane get_range_raw",
    );
    assert_eq!(ok(followed.response.bytes().await, "body").as_ref(), b"x");
    assert!(
        !taiji_http::client::uri_on_warm_pool(&format!("{probe_base}/other.bin")),
        "a probe-plane success must not light the warm-pool signal"
    );
}

/// Timeline equivalent of zero-delay staggering: the signal flips warm
/// exactly after the first task lifecycle (all 16 knives complete,
/// connections back in the pool) — the second same-host task's stagger
/// site (core `stagger_delay(ordinal, warmth)`) then gives every knife
/// zero delay. The decision function (warm=true → 0 / cold → ramp) is
/// pinned by taiji-core
/// `stagger_delay_precise_warm_skip_and_cold_ramp`; this test pins the
/// flip moment.
#[tokio::test]
async fn warm_signal_flips_between_first_and_second_task_lifecycles() {
    let (base, _obs) = spawn_origin(Duration::ZERO).await;
    let cfg = bench_cfg();
    assert!(
        !taiji_http::client::uri_on_warm_pool(&format!("{base}/cold-check.bin")),
        "before the first task spawns (batch start): \
         the signal is cold = the first-wave stagger ramp is kept"
    );
    one_task_lifecycle(&base, &cfg).await;
    assert!(
        taiji_http::client::uri_on_warm_pool(&format!("{base}/warm-check.bin")),
        "after the first task closes out: the signal is warm = \
         every knife staggers with zero delay from the second task on"
    );
    one_task_lifecycle(&base, &cfg).await;
    assert!(
        taiji_http::client::uri_on_warm_pool(&format!("{base}/warm-check.bin")),
        "sustained success = sustained warmth (monotone refresh within the 90s window)"
    );
}

/// Main assertion: for a same-host many-small batch (8 tasks x 16
/// knives) the new-connection count — with the shared pool, keep-alive
/// connections stay pooled across tasks after the first 16 connects
/// and later tasks reuse them; per-task isolated pools would need
/// 8×16 = 128 new connections. The upper bound sits far below that
/// baseline (64 < 128/2); the lower bound keeps the load complete
/// (requests = 128).
#[tokio::test]
async fn same_config_clients_share_keepalive_pool_across_task_lifecycles() {
    const TASKS: usize = 8;
    let (base, obs) = spawn_origin(Duration::ZERO).await;
    let cfg = bench_cfg();
    for _ in 0..TASKS {
        one_task_lifecycle(&base, &cfg).await;
    }
    let accepts = obs.accepts.load(Ordering::SeqCst);
    let requests = obs.requests.load(Ordering::SeqCst);
    assert_eq!(
        requests,
        TASKS * KNIVES,
        "full load must be served (a task = {KNIVES} range knives)"
    );
    assert!(
        accepts < TASKS * KNIVES / 2,
        "new-connection count must drop sharply with the shared pool: \
         accepts={accepts}, per-task-isolated baseline={}",
        TASKS * KNIVES
    );
    assert!(
        accepts >= KNIVES,
        "first task's {KNIVES} concurrent knives must each hold a connection"
    );
}

/// Wall-clock improvement (loose upper bound to avoid flakes): each
/// connection's first request pays a 40ms connect tax (a loopback
/// stand-in for real handshakes). With per-task pools every task pays >=
/// 40ms (16 connections pay in parallel, tasks accumulate serially);
/// with the shared pool only the first task pays. 10 tasks must finish
/// in < 240ms — 60% of the 10×40 = 400ms per-task floor, leaving room
/// for scheduling noise and an occasional reuse-health reconnect.
#[tokio::test]
async fn shared_pool_amortizes_connect_tax_wall_clock() {
    const TASKS: usize = 10;
    const TAX: Duration = Duration::from_millis(40);
    let (base, _obs) = spawn_origin(TAX).await;
    let cfg = bench_cfg();
    let start = Instant::now();
    for _ in 0..TASKS {
        one_task_lifecycle(&base, &cfg).await;
    }
    let elapsed = start.elapsed();
    let baseline_floor = TAX * TASKS as u32;
    assert!(
        elapsed < baseline_floor.mul_f64(0.6),
        "wall clock must improve once only the first task pays the connect \
         tax: elapsed={elapsed:?}, per-task-rebuild floor={baseline_floor:?}"
    );
}

/// Isolation guard: different [`ClientConfig`]s (any transport-relevant
/// difference; here timeouts) each build their own connections — the
/// shared-pool bucket key is the full config; over-sharing that ignored
/// config differences would fail this assertion (each config should
/// open one connection, accepts = 2).
#[tokio::test]
async fn distinct_configs_keep_distinct_connection_pools() {
    let (base, obs) = spawn_origin(Duration::ZERO).await;
    let ctx = RequestCtx::default();
    for cfg in [bench_cfg(), ClientConfig::default()] {
        let client = ok(HttpClient::new(cfg), "client");
        let followed = ok(client.get(&format!("{base}/f.bin"), &ctx).await, "get");
        assert_eq!(ok(followed.response.bytes().await, "body").as_ref(), b"x");
        drop(client);
    }
    // Each config opens its own connection: the reqwest pool isolates
    // by instance (key = the full config).
    assert_eq!(obs.accepts.load(Ordering::SeqCst), 2);
}

/// Isolation guard: `--load-cookies` ([`HttpClient::with_jar`] carries
/// a task-private jar) stays out of the shared pool — two constructions
/// each hold their own connections (the conservative side of cookie
/// isolation; an implementation that pooled with_jar clients too would
/// fail this assertion).
#[tokio::test]
async fn jar_bearing_clients_stay_out_of_the_shared_pool() {
    let (base, obs) = spawn_origin(Duration::ZERO).await;
    let ctx = RequestCtx::default();
    let cfg = bench_cfg();
    let jar = CookieJar::parse_netscape(
        "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t0\tsid\ttask-private\n",
    );
    for _ in 0..2 {
        let client = ok(HttpClient::with_jar(cfg.clone(), jar.clone()), "client");
        let followed = ok(client.get(&format!("{base}/f.bin"), &ctx).await, "get");
        assert_eq!(ok(followed.response.bytes().await, "body").as_ref(), b"x");
        drop(client);
    }
    // Two with_jar constructions (same cfg) share nothing: one
    // connection each.
    assert_eq!(obs.accepts.load(Ordering::SeqCst), 2);
    // Independent of the pooled path: a new with the same cfg uses the
    // shared pool (the third connection).
    let shared = ok(HttpClient::new(cfg), "client");
    let followed = ok(shared.get(&format!("{base}/f.bin"), &ctx).await, "get");
    assert_eq!(ok(followed.response.bytes().await, "body").as_ref(), b"x");
    assert_eq!(obs.accepts.load(Ordering::SeqCst), 3);
}

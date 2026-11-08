//! Smoke acceptance: an in-process mock replica of the 94s smoke-probe
//! scenario, asserting that the new logs can answer the three questions
//! the probe could not —
//! 1. where tier 0 is stuck (attempt/result lines + tier/scheme/elapsed);
//! 2. who was dialed (same-line coverage for the dial arm lives in the
//!    engine transit/dial unit tests — this file focuses on the announce
//!    surface; the dial surface is engine-internal and unreachable from
//!    integration tests);
//! 3. why it failed (failure class + reason string).
//!
//! Replica shape: tier 0 = an HTTP tracker on a closed local port (the
//! reproducible equivalent of the probe's
//! `https://torrent.ubuntu.com/announce` producing 92s of silence —
//! failures only land in sqlite last_error); tier 33 = a local mock
//! tracker (the shape of the probe's HTTP tiers 21/33 succeeding first).
//! All mock, no real network; the runtime is far below 94s (~0.2s).
//!
//! Same-line assertions for the dial surface ("who was dialed, why it
//! failed") live in `crates/taiji-core/src/engine/transit.rs`
//! `dial_result_log_tests` (dial_failure_info_line_per_target /
//! dial_blocked_info_line) and the `engine/run/dial.rs` sampler unit
//! tests.

use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

use taiji_bt::tracker::actor::{
    COMMAND_CHANNEL_CAPACITY, EVENT_CHANNEL_CAPACITY, SwarmView, TrackerActor, TrackerActorConfig,
    TrackerActorEvent, UDP_INBOUND_CAPACITY, UDP_OUTBOUND_CAPACITY, UdpTransport,
};

/// Log-capture writer (the landing spot for the thread-local default
/// subscriber).
#[derive(Clone, Default)]
struct CaptureBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CaptureBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for CaptureBuf {
    type Writer = CaptureBuf;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Static swarm view (downloading, short of peers).
struct FixedView;

impl SwarmView for FixedView {
    fn total_length(&self) -> u64 {
        1000
    }
    fn completed_length(&self) -> u64 {
        0
    }
    fn session_uploaded(&self) -> u64 {
        5
    }
    fn session_downloaded(&self) -> u64 {
        7
    }
    fn all_download_finished(&self) -> bool {
        false
    }
    fn less_than_min_peers(&self) -> bool {
        true
    }
}

/// Local mock tracker: answers any request with a minimal announce
/// response (BEP 3, interval=60).
async fn start_mock_tracker() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Read until the request head ends (single HTTP/1.1 GET).
                let mut req = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&chunk[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                // bencode keys ascending: interval < peers (empty list).
                let mut body = Vec::from(&b"d8:intervali60e5:peersle"[..]);
                body.push(b'e');
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (format!("http://{addr}/announce"), task)
}

/// Probe-scenario smoke: tier 0's fast failure is visible and
/// classifiable; tier 33's success line lands.
#[tokio::test]
async fn probe_scenario_tier0_failure_is_diagnosable() {
    let buf = CaptureBuf::default();
    use tracing_subscriber::util::SubscriberInitExt as _;
    let _guard = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish()
        .set_default();

    // tier 0: bind then immediately drop = a closed port (the
    // deterministic connect-refused shape; equivalent to the probe's
    // tier-0 HTTPS "sent and vanished" observation gap).
    let tier0_closed = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        l.local_addr().unwrap_or_else(|e| panic!("{e}"))
    };
    let tier0_url = format!("http://{tier0_closed}/announce");
    // tier 33: local mock (the shape of the probe's HTTP tier succeeding
    // first).
    let (tier33_url, mock_task) = start_mock_tracker().await;

    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let (event_tx, mut event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    let (out_tx, _out_rx) = mpsc::channel(UDP_OUTBOUND_CAPACITY);
    let (in_tx, in_rx) = mpsc::channel(UDP_INBOUND_CAPACITY);
    let _keep_in_tx = in_tx; // keep the inbound channel alive (the actor must not stall on a closed channel)
    let mut actor = TrackerActor::new(
        TrackerActorConfig {
            info_hash: [0x11; 20],
            peer_id: *b"-TJ0001-AAAAAAAAAAAA",
            listen_port: 6881,
            options: Default::default(),
            require_crypto: false,
            private: false,
            tiers: vec![(0, tier0_url.clone()), (33, tier33_url.clone())],
            scrape_hashes: vec![[0x11; 20]],
        },
        Arc::new(FixedView),
        cmd_rx,
        event_tx,
        UdpTransport {
            outbound: out_tx,
            inbound: in_rx,
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));

    // Mock driving at the probe's beat (under the single-flight gate: a
    // tick starts -> the result lands -> failover).
    actor.tick(Instant::now()).await; // tier 0 starts
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    actor.tick(Instant::now()).await; // tier 0's failure lands + tier 33 starts
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    actor.tick(Instant::now()).await; // tier 33's success lands
    let _ = cmd_tx; // the command channel lives until actor driving ends

    // Structured event surface (cross-checking the log surface): tier
    // 0's failure event carries a classified reason.
    let mut tier0_failed = false;
    let mut tier33_ok = false;
    while let Ok(ev) = event_rx.try_recv() {
        match ev {
            TrackerActorEvent::AnnounceFailed { url, reason } if url == tier0_url => {
                assert!(
                    reason.starts_with("connect:"),
                    "tier 0's failure should classify as connect (reason={reason})"
                );
                tier0_failed = true;
            }
            TrackerActorEvent::IntervalUpdated { interval, .. } => {
                assert_eq!(interval, 60, "tier 33's mock response interval");
                tier33_ok = true;
            }
            _ => {}
        }
    }
    assert!(
        tier0_failed && tier33_ok,
        "the event face is missing the failure/success pair"
    );

    // The log surface (this module's core deliverable): the three
    // questions are answerable.
    let text = String::from_utf8(buf.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
        .unwrap_or_else(|e| panic!("{e}"));

    // Where tier 0 is: the attempt line (URL/scheme/tier/event) + the
    // failure line. Note: tracing renders str value fields quoted
    // (url="…"), so assert the value bodies.
    assert!(
        text.contains("announce attempt") && text.contains(tier0_url.as_str()),
        "missing the tier 0 attempt line: {text}"
    );
    assert!(
        text.contains("scheme=") && text.contains("tier=0") && text.contains("event="),
        "the attempt line is missing scheme/tier/event: {text}"
    );
    // Why it failed: the failure line carries the class + reason +
    // elapsed (str values are quoted -> assert `class=` and the reason
    // string body).
    assert!(
        text.contains("announce failed")
            && text.contains("class=")
            && text.contains("elapsed_ms=")
            && text.contains("connect: error sending request"),
        "the failure line is missing the class/elapsed fields: {text}"
    );
    // tier 33 waits for tier 0's failure first (the result surface of
    // the first-round tier priority) + the success line.
    assert!(
        text.contains("tier=33"),
        "missing the tier 33 attempt line: {text}"
    );
    assert!(
        text.contains("announce ok") && text.contains(tier33_url.as_str()),
        "missing the tier 33 success line: {text}"
    );

    mock_task.abort();
}

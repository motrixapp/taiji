//! Wire-level tests for the h2/h2c option surface: ① https ALPN
//! negotiation (default auto = rustls advertises h2; an origin without
//! h2 falls back to h1); ② the h2c prior-knowledge plaintext switch,
//! positive and negative (default off); ③ h2 single-connection
//! multiplexing vs the h1 connection storm (many-small shape); ④ wire
//! advertisement of the h2 flow-control window knobs (initial SETTINGS +
//! stream 0 WINDOW_UPDATE); ⑤ the h2 max-connections cap (K → origin
//! TCP accept count); ⑥ h2 PING keep-alive probing of idle connections.
//!
//! # Zero-dependency h2 mock origin
//!
//! The mock h2 server is a hand-written frame layer (no `h2`/hyper
//! server dependency): client preface check (RFC 7540 §3.5 24-byte
//! magic) + empty SETTINGS + a frame loop (SETTINGS→ACK;
//! HEADERS→timed `:status 200` (HPACK static-table byte 0x88) + 1-byte
//! DATA). Beyond POST no HPACK decoding is needed: GET request HEADERS
//! carry END_STREAM and the response stream id is read back from the
//! frame header. The server observation surface (connection count /
//! stream concurrency peak / preface validity) feeds the assertions.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use suppaftp::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use suppaftp::tokio_rustls::TlsAcceptor;
use suppaftp::tokio_rustls::rustls;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use taiji_http::client::{ClientConfig, HttpClient, HttpProtocol};
use taiji_http::traits::RequestCtx;

/// Client connection preface (RFC 7540 §3.5, 24-byte magic string).
const H2_PREFACE: [u8; 24] = *b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HPACK static-table entry 8 = `:status 200` (one indexed byte).
const HPACK_STATUS_200: [u8; 1] = [0x88];

/// Frame types (RFC 7540 §6).
const F_DATA: u8 = 0x0;
const F_HEADERS: u8 = 0x1;
const F_SETTINGS: u8 = 0x4;
/// END_HEADERS flag (HEADERS/CONTINUATION).
const F_END_HEADERS: u8 = 0x4;
/// END_STREAM flag (HEADERS/DATA).
const F_END_STREAM: u8 = 0x1;
/// SETTINGS ACK flag.
const F_ACK: u8 = 0x1;
/// `SETTINGS_MAX_CONCURRENT_STREAMS` identifier (RFC 7540 §6.5.2).
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
/// `SETTINGS_INITIAL_WINDOW_SIZE` identifier (RFC 7540 §6.5.2): the
/// stream-level initial receive-window advertisement.
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
/// WINDOW_UPDATE frame type (RFC 7540 §6.9).
const F_WINDOW_UPDATE: u8 = 0x8;
/// PING frame type (RFC 7540 §6.7; payload is always 8 opaque bytes,
/// stream id always 0).
const F_PING: u8 = 0x6;
/// RFC 7540 §6.9.1 initial flow-control window. SETTINGS cannot carry
/// the connection window; connection-level growth is only advertised
/// via stream 0 WINDOW_UPDATE increments.
const FLOW_CONTROL_INITIAL: u64 = 65535;

/// Test-only Result unwrap (lints forbid unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Server observation surface
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Obs {
    /// TCP accept count (storm vs single-connection multiplexing).
    accepts: Arc<AtomicUsize>,
    /// Currently open connections (h1 concurrent-connect peak).
    conns_open: Arc<AtomicUsize>,
    conns_peak: Arc<AtomicUsize>,
    /// Preface check: good = a real h2/h2c client; bad = stray h1 bytes.
    good_preface: Arc<AtomicUsize>,
    bad_preface: Arc<AtomicUsize>,
    /// h2 streams: total HEADERS and peak concurrent unanswered streams
    /// (multiplexing depth on the single connection).
    streams: Arc<AtomicUsize>,
    streams_peak: Arc<AtomicUsize>,
    /// Total h1 requests (keep-alive reuse counter).
    h1_requests: Arc<AtomicUsize>,
    /// TLS ALPN negotiation result (server view).
    alpn: Arc<Mutex<String>>,
    /// INITIAL_WINDOW_SIZE advertised in the client's initial SETTINGS
    /// (stream-level receive window; hyper default = 2MiB).
    initial_stream_window: Arc<AtomicU64>,
    /// Peak single-frame increment of stream 0 WINDOW_UPDATE
    /// (connection-level window growth; hyper default = 5MiB-65535;
    /// the initial burst is the largest single increment).
    conn_window_delta_peak: Arc<AtomicU64>,
    /// Count of received keep-alive PING frames (non-ACK, stream 0):
    /// wire evidence that client `http2_keep_alive_while_idle` is in
    /// effect.
    keep_alive_pings: Arc<AtomicUsize>,
}

impl Obs {
    fn note_conn_open(&self) {
        let cur = self.conns_open.fetch_add(1, Ordering::SeqCst) + 1;
        self.conns_peak.fetch_max(cur, Ordering::SeqCst);
    }

    fn note_stream_open(&self, open: &Mutex<HashSet<u32>>, sid: u32) {
        lock(open).insert(sid);
        self.streams.fetch_add(1, Ordering::SeqCst);
        self.streams_peak
            .fetch_max(lock(open).len(), Ordering::SeqCst);
    }

    fn alpn(&self) -> String {
        lock(&self.alpn).clone()
    }
}

// ---------------------------------------------------------------------------
// Hand-written h2 frame-layer mock origin
// ---------------------------------------------------------------------------

/// Assemble one frame (9-byte header: len u24 | type | flags | R + stream id).
fn frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..4]);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Per-connection h2 serve loop, shared by plaintext h2c and TLS-h2
/// (the frame layer is transport-agnostic). A bad preface is recorded
/// as stray h1 bytes and the connection is dropped.
async fn serve_h2_conn<S>(stream: S, obs: Obs, hold: Duration, max_streams: Option<u32>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut preface = [0u8; 24];
    match rd.read_exact(&mut preface).await {
        Ok(_) if preface == H2_PREFACE => {
            obs.good_preface.fetch_add(1, Ordering::SeqCst);
        }
        _ => {
            obs.bad_preface.fetch_add(1, Ordering::SeqCst);
            return;
        }
    }
    // Initial SETTINGS: may carry MAX_CONCURRENT_STREAMS (RFC 7540 §6.5.2).
    let mut initial = Vec::new();
    if let Some(n) = max_streams {
        let mut payload = Vec::with_capacity(6);
        payload.extend_from_slice(&SETTINGS_MAX_CONCURRENT_STREAMS.to_be_bytes());
        payload.extend_from_slice(&n.to_be_bytes());
        initial = frame(F_SETTINGS, 0, 0, &payload);
    }
    if wr.write_all(&initial).await.is_err() {
        return;
    }
    // Single writer task: stream tasks submit frames via a channel to
    // avoid concurrent writes.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let writer = tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            if wr.write_all(&buf).await.is_err() {
                break;
            }
        }
    });
    let open: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut hdr = [0u8; 9];
    loop {
        if rd.read_exact(&mut hdr).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let sid = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
        let mut payload = vec![0u8; len];
        if len > 0 && rd.read_exact(&mut payload).await.is_err() {
            break;
        }
        match ftype {
            // Client SETTINGS → ACK; parse non-ACK frames pairwise
            // (id u16 | value u32) to extract the INITIAL_WINDOW_SIZE
            // advertisement; client ACKs (flags=1) are ignored.
            F_SETTINGS if flags & F_ACK == 0 => {
                let mut i = 0;
                while i + 6 <= payload.len() {
                    let id = u16::from_be_bytes([payload[i], payload[i + 1]]);
                    let val = u32::from_be_bytes([
                        payload[i + 2],
                        payload[i + 3],
                        payload[i + 4],
                        payload[i + 5],
                    ]);
                    if id == SETTINGS_INITIAL_WINDOW_SIZE {
                        obs.initial_stream_window
                            .store(u64::from(val), Ordering::SeqCst);
                    }
                    i += 6;
                }
                let _ = tx.send(frame(F_SETTINGS, F_ACK, 0, &[])).await;
            }
            // stream 0 WINDOW_UPDATE = connection-level window growth
            // (RFC 7540 §6.9/§6.9.1: the window starts at 65535 and
            // SETTINGS cannot carry it; the peak single frame is the
            // advertised connection window - 65535).
            F_WINDOW_UPDATE if sid == 0 && payload.len() == 4 => {
                let delta = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                    & 0x7fff_ffff;
                obs.conn_window_delta_peak
                    .fetch_max(u64::from(delta), Ordering::SeqCst);
            }
            // Keep-alive PING (non-ACK, stream 0, 8-byte opaque payload):
            // count it and mirror a PONG (RFC 7540 §6.7 ACK flag + same
            // payload). The probe policy lives on the client; the mock
            // must answer so the connection survives the observation
            // window instead of being killed by a 2x-interval timeout.
            F_PING if flags & F_ACK == 0 && sid == 0 => {
                obs.keep_alive_pings.fetch_add(1, Ordering::SeqCst);
                let _ = tx.send(frame(F_PING, F_ACK, 0, &payload)).await;
            }
            F_HEADERS => {
                obs.note_stream_open(&open, sid);
                let tx = tx.clone();
                let open = open.clone();
                tokio::spawn(async move {
                    // Hold before replying: the window in which concurrent
                    // streams overlap (multiplexing depth = HEADERS
                    // arriving within the window).
                    tokio::time::sleep(hold).await;
                    let _ = tx
                        .send(frame(F_HEADERS, F_END_HEADERS, sid, &HPACK_STATUS_200))
                        .await;
                    let _ = tx.send(frame(F_DATA, F_END_STREAM, sid, b"x")).await;
                    lock(&open).remove(&sid);
                });
            }
            _ => {}
        }
    }
    drop(tx);
    let _ = writer.await;
}

/// Plaintext h2c accept loop (prior-knowledge endpoint; bad prefaces
/// are recorded and the connection dropped).
async fn serve_h2c(listener: TcpListener, obs: Obs, hold: Duration) {
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => break,
        };
        obs.accepts.fetch_add(1, Ordering::SeqCst);
        obs.note_conn_open();
        let obs = obs.clone();
        tokio::spawn(async move {
            serve_h2_conn(tcp, obs.clone(), hold, None).await;
            // Read loop exit: the in-flight connection count drops back.
            obs.conns_open.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// h1 accept loop (the connection-storm contrast): keep-alive loop that
/// reads request headers, holds, then replies with a fixed 200; the
/// open-connection peak is the concurrency depth.
async fn serve_h1(listener: TcpListener, obs: Obs, hold: Duration) {
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => break,
        };
        obs.accepts.fetch_add(1, Ordering::SeqCst);
        obs.note_conn_open();
        let obs = obs.clone();
        tokio::spawn(async move {
            serve_h1_conn(tcp, obs.clone(), hold).await;
            obs.conns_open.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

async fn serve_h1_conn<S>(mut stream: S, obs: Obs, hold: Duration)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\n\r\nx";
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
        obs.h1_requests.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(hold).await;
        if stream.write_all(RESP).await.is_err() {
            return;
        }
        buf.clear();
    }
}

// ---------------------------------------------------------------------------
// https (rustls ALPN) mock origin
// ---------------------------------------------------------------------------

const SERVER_CERT: &[u8] = include_bytes!("fixtures/ftp-test-ca/server_cert.der");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/ftp-test-ca/server_key.der");

/// ALPN advertisement list in server preference order; rustls picks the
/// first entry the client also offers. An empty list means no
/// advertisement (the client picks from its own offer).
async fn serve_https(listener: TcpListener, alpn: Vec<Vec<u8>>, obs: Obs, hold: Duration) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("protocol versions: {e}"))
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(SERVER_CERT.to_vec())],
            PrivatePkcs8KeyDer::from(SERVER_KEY.to_vec()).into(),
        )
        .unwrap_or_else(|e| panic!("server cert: {e}"));
    let mut cfg = config;
    cfg.alpn_protocols = alpn;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => break,
        };
        obs.accepts.fetch_add(1, Ordering::SeqCst);
        let acceptor = acceptor.clone();
        let obs = obs.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(_) => return,
            };
            let proto = tls
                .get_ref()
                .1
                .alpn_protocol()
                .map(|p| p.to_vec())
                .unwrap_or_default();
            *lock(&obs.alpn) = String::from_utf8_lossy(&proto).into_owned();
            match proto.as_slice() {
                b"h2" => serve_h2_conn(tls, obs, hold, None).await,
                _ => serve_h1_conn(tls, obs, hold).await,
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Client assembly and observation
// ---------------------------------------------------------------------------

fn client(protocol: HttpProtocol) -> HttpClient {
    let cfg = ClientConfig {
        // Self-signed fixture: certificate validation is off. These tests
        // observe ALPN and protocol shape, not TLS validation (the
        // ftp_mock matrix covers that).
        accept_invalid_certs: true,
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        http_protocol: protocol,
        ..ClientConfig::default()
    };
    HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"))
}

async fn spawn_h2c(hold: Duration) -> (String, Obs) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "addr");
    let obs = Obs::default();
    tokio::spawn(serve_h2c(listener, obs.clone(), hold));
    (format!("http://{addr}"), obs)
}

async fn spawn_h1(hold: Duration) -> (String, Obs) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "addr");
    let obs = Obs::default();
    tokio::spawn(serve_h1(listener, obs.clone(), hold));
    (format!("http://{addr}"), obs)
}

async fn spawn_https(alpn: &[&[u8]], hold: Duration) -> (String, Obs) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "addr");
    let obs = Obs::default();
    tokio::spawn(serve_https(
        listener,
        alpn.iter().map(|p| p.to_vec()).collect(),
        obs.clone(),
        hold,
    ));
    (format!("https://{addr}"), obs)
}

async fn body_x(followed: taiji_http::client::Followed) -> String {
    String::from_utf8_lossy(&ok(followed.response.bytes().await, "body")).into_owned()
}

// ---------------------------------------------------------------------------
// ① https ALPN negotiation (default auto) and h1 fallback
// ---------------------------------------------------------------------------

/// Default (auto) shape: the reqwest rustls client advertises h2 +
/// http/1.1, the origin advertises h2, ALPN selects h2, and the
/// response version is HTTP/2.
#[tokio::test]
async fn https_alpn_negotiates_h2_by_default() {
    let (base, obs) = spawn_https(&[b"h2", b"http/1.1"], Duration::ZERO).await;
    let followed = ok(
        client(HttpProtocol::Auto)
            .get(&format!("{base}/f.bin"), &RequestCtx::default())
            .await,
        "get",
    );
    assert_eq!(
        followed.response.version(),
        reqwest::Version::HTTP_2,
        "default client must ride ALPN h2 against an h2-capable origin"
    );
    assert_eq!(body_x(followed).await, "x");
    assert_eq!(obs.alpn(), "h2");
    assert_eq!(obs.good_preface.load(Ordering::SeqCst), 1);
}

/// h1 fallback: when the origin only advertises http/1.1, ALPN lands on
/// http/1.1 and the default client works unchanged (ALPN always has a
/// common protocol or falls back to http/1.1).
#[tokio::test]
async fn https_falls_back_to_h1_when_origin_lacks_h2() {
    let (base, obs) = spawn_https(&[b"http/1.1"], Duration::ZERO).await;
    let followed = ok(
        client(HttpProtocol::Auto)
            .get(&format!("{base}/f.bin"), &RequestCtx::default())
            .await,
        "get",
    );
    assert_eq!(followed.response.version(), reqwest::Version::HTTP_11);
    assert_eq!(body_x(followed).await, "x");
    assert_eq!(obs.alpn(), "http/1.1");
    assert_eq!(obs.h1_requests.load(Ordering::SeqCst), 1);
}

/// `--http-protocol=h1` forces http/1.1 against an h2-capable origin:
/// ALPN only advertises http/1.1, so the server can never pick h2.
#[tokio::test]
async fn protocol_h1_forces_http1_against_h2_capable_origin() {
    let (base, obs) = spawn_https(&[b"h2", b"http/1.1"], Duration::ZERO).await;
    let followed = ok(
        client(HttpProtocol::Http1)
            .get(&format!("{base}/f.bin"), &RequestCtx::default())
            .await,
        "get",
    );
    assert_eq!(followed.response.version(), reqwest::Version::HTTP_11);
    assert_eq!(body_x(followed).await, "x");
    assert_eq!(
        obs.alpn(),
        "http/1.1",
        "server can only pick what client offers"
    );
}

// ---------------------------------------------------------------------------
// ② h2c prior-knowledge plaintext switch (default off)
// ---------------------------------------------------------------------------

/// Positive: `--http-protocol=h2` makes the prior-knowledge client speak
/// h2c directly to a plaintext endpoint (proven by the preface), with no
/// Upgrade and no h1 fallback.
#[tokio::test]
async fn h2c_prior_knowledge_opt_in_speaks_h2c() {
    let (base, obs) = spawn_h2c(Duration::ZERO).await;
    let followed = ok(
        client(HttpProtocol::Http2)
            .get(&format!("{base}/f.bin"), &RequestCtx::default())
            .await,
        "get",
    );
    assert_eq!(followed.response.version(), reqwest::Version::HTTP_2);
    assert_eq!(body_x(followed).await, "x");
    assert_eq!(obs.good_preface.load(Ordering::SeqCst), 1);
    assert_eq!(obs.bad_preface.load(Ordering::SeqCst), 0);
}

/// Negative (default off): the default (auto) client sends h1 bytes to
/// an h2c-only endpoint; the server rejects them at the preface check
/// and the request fails. Plaintext h2 is never enabled by default.
#[tokio::test]
async fn h2c_default_off_h1_bytes_rejected_by_h2c_origin() {
    let (base, obs) = spawn_h2c(Duration::ZERO).await;
    let res = client(HttpProtocol::Auto)
        .get(&format!("{base}/f.bin"), &RequestCtx::default())
        .await;
    assert!(res.is_err(), "default client must not speak h2c unprompted");
    assert_eq!(obs.bad_preface.load(Ordering::SeqCst), 1);
    assert_eq!(obs.good_preface.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// ③ h2 single-connection multiplexing vs the h1 connection storm
// ---------------------------------------------------------------------------

/// h2 multiplexing: 16 concurrent requests against a 250ms server hold
/// → exactly one TCP connection carrying at least 12 overlapping
/// streams (connections stay at 1 while streams scale with the
/// requested concurrency).
#[tokio::test]
async fn h2_multiplexes_concurrent_streams_on_one_connection() {
    let (base, obs) = spawn_h2c(Duration::from_millis(250)).await;
    let cli = Arc::new(client(HttpProtocol::Http2));
    let url = format!("{base}/f.bin");
    let mut handles = Vec::new();
    for _ in 0..16 {
        let cli = cli.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let followed = ok(
                cli.get(&url, &RequestCtx::default()).await,
                "concurrent get",
            );
            ok(followed.response.bytes().await, "body")
        }));
    }
    for h in handles {
        assert_eq!(ok(h.await, "join").as_ref(), b"x");
    }
    assert_eq!(
        obs.accepts.load(Ordering::SeqCst),
        1,
        "h2 must carry all concurrency on one pooled connection"
    );
    assert_eq!(obs.streams.load(Ordering::SeqCst), 16);
    assert!(
        obs.streams_peak.load(Ordering::SeqCst) >= 12,
        "streams must genuinely overlap on the single connection (peak={})",
        obs.streams_peak.load(Ordering::SeqCst)
    );
}

/// h1 contrast: the same 16 concurrent requests with a 250ms hold open
/// a connection storm — 16 TCP connections, one per in-flight request
/// (the h2 side uses exactly 1 for the same load).
#[tokio::test]
async fn h1_same_concurrency_opens_one_connection_per_request() {
    let (base, obs) = spawn_h1(Duration::from_millis(250)).await;
    let cli = Arc::new(client(HttpProtocol::Auto));
    let url = format!("{base}/f.bin");
    let mut handles = Vec::new();
    for _ in 0..16 {
        let cli = cli.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let followed = ok(
                cli.get(&url, &RequestCtx::default()).await,
                "concurrent get",
            );
            ok(followed.response.bytes().await, "body")
        }));
    }
    for h in handles {
        assert_eq!(ok(h.await, "join").as_ref(), b"x");
    }
    assert_eq!(
        obs.accepts.load(Ordering::SeqCst),
        16,
        "h1 has no multiplexing: each in-flight request holds its own connection"
    );
}

/// Server stream cap: the origin advertises MAX_CONCURRENT_STREAMS=4.
/// The client does NOT open new connections; requests beyond the cap
/// queue locally on the same connection (stream establishment is paced:
/// the server observes a stream-concurrency peak of 4), and every
/// request still completes. Concurrency past the peer cap becomes local
/// backpressure (waiting for a stream slot) rather than extra TCP
/// connections.
#[tokio::test]
async fn server_stream_cap_paces_streams_without_new_connections() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "addr");
    let obs = Obs::default();
    let base = format!("http://{addr}");
    let accept_obs = obs.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            accept_obs.accepts.fetch_add(1, Ordering::SeqCst);
            let conn_obs = accept_obs.clone();
            tokio::spawn(serve_h2_conn(
                tcp,
                conn_obs,
                Duration::from_millis(120),
                Some(4),
            ));
        }
    });
    let cli = Arc::new(client(HttpProtocol::Http2));
    // Warm-up hop: the server SETTINGS (stream cap 4) must reach the
    // client session before the capped requests; frame ordering
    // guarantees SETTINGS is processed before the warm-up response.
    let url = format!("{base}/warmup");
    let warm = ok(cli.get(&url, &RequestCtx::default()).await, "warmup");
    assert_eq!(ok(warm.response.bytes().await, "warm body").as_ref(), b"x");
    let url = format!("{base}/f.bin");
    let mut handles = Vec::new();
    for _ in 0..16 {
        let cli = cli.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let followed = ok(cli.get(&url, &RequestCtx::default()).await, "capped get");
            ok(followed.response.bytes().await, "body")
        }));
    }
    for h in handles {
        assert_eq!(ok(h.await, "join").as_ref(), b"x");
    }
    assert_eq!(
        obs.accepts.load(Ordering::SeqCst),
        1,
        "hyper must NOT fan out new connections at the peer stream cap; \
         excess requests are buffered locally on the same connection"
    );
    assert_eq!(
        obs.streams_peak.load(Ordering::SeqCst),
        4,
        "stream establishment must be paced at the advertised cap"
    );
    assert_eq!(obs.streams.load(Ordering::SeqCst), 17); // warmup + 16
}

/// many-small contrast baseline: 160 small requests x 16 concurrency
/// against a 3ms server hold. h2c carries everything on 1 connection;
/// h1 opens a storm. Timing is printed for the record only, never
/// asserted: loopback cannot reproduce real-RTT connection
/// amplification, so the structural difference (connection count) is
/// the pinned invariant.
#[tokio::test]
async fn many_small_h2c_vs_h1_structural_contrast() {
    const TOTAL: usize = 160;
    const CONC: usize = 16;
    let (h2c_base, h2c_obs) = spawn_h2c(Duration::from_millis(3)).await;
    let (h1_base, h1_obs) = spawn_h1(Duration::from_millis(3)).await;

    async fn run_many(base: &str, protocol: HttpProtocol, total: usize, conc: usize) -> Duration {
        let cli = Arc::new(client(protocol));
        let url = format!("{base}/f.bin");
        let start = Instant::now();
        let mut inflight = Vec::new();
        for i in 0..total {
            let cli = cli.clone();
            let url = url.clone();
            inflight.push(tokio::spawn(async move {
                let followed = ok(cli.get(&url, &RequestCtx::default()).await, "get");
                ok(followed.response.bytes().await, "body");
                i
            }));
            if inflight.len() >= conc {
                for h in std::mem::take(&mut inflight) {
                    ok(h.await, "join");
                }
            }
        }
        for h in inflight {
            ok(h.await, "join");
        }
        start.elapsed()
    }

    let h2c_elapsed = run_many(&h2c_base, HttpProtocol::Http2, TOTAL, CONC).await;
    let h1_elapsed = run_many(&h1_base, HttpProtocol::Auto, TOTAL, CONC).await;
    let h2c_conns = h2c_obs.accepts.load(Ordering::SeqCst);
    let h1_conns = h1_obs.accepts.load(Ordering::SeqCst);
    assert_eq!(h2c_obs.streams.load(Ordering::SeqCst), TOTAL);
    assert_eq!(h2c_conns, 1, "h2c many-small must stay on one connection");
    assert!(
        h1_conns > 1,
        "h1 many-small at concurrency {CONC} must exceed one connection (got {h1_conns})"
    );
    println!(
        "many-small contrast: total={TOTAL} conc={CONC} | h2c: conns={h2c_conns} \
         elapsed={h2c_elapsed:?} | h1: conns={h1_conns} elapsed={h1_elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// ④ h2 flow-control window advertisement
// ---------------------------------------------------------------------------

/// The advertised receive window is the client's data ceiling on the
/// wire (RFC 7540 §5.2/§6.5.2/§6.9.1). The default client advertises
/// an 8MiB stream window in its initial SETTINGS plus a 16MiB-65535
/// peak stream-0 WINDOW_UPDATE; an explicitly overridden client
/// (4MiB/8MiB) advertises accordingly, proving the option override
/// path. The knobs are orthogonal to protocol shape: a plaintext h2c
/// prior-knowledge endpoint is enough to observe them.
#[tokio::test]
async fn http2_window_options_advertise_on_wire() {
    // Default anchor: 8MiB stream window / 16MiB connection window.
    let (base, obs) = spawn_h2c(Duration::from_millis(5)).await;
    let cli = client(HttpProtocol::Http2);
    let url = format!("{base}/warmup");
    let warm = ok(cli.get(&url, &RequestCtx::default()).await, "warm get");
    let _ = ok(warm.response.bytes().await, "warm body");
    assert_eq!(
        obs.initial_stream_window.load(Ordering::SeqCst),
        8 * 1024 * 1024,
        "the default stream window advertised = the engine default 8MiB (engine default)"
    );
    assert_eq!(
        obs.conn_window_delta_peak.load(Ordering::SeqCst),
        16 * 1024 * 1024 - FLOW_CONTROL_INITIAL,
        "the default connection window expansion = \
         the engine default 16MiB - 65535 (engine default)"
    );

    // Override: explicit 4MiB stream / 8MiB connection windows.
    let (base, obs) = spawn_h2c(Duration::from_millis(5)).await;
    let tuned = HttpClient::new(ClientConfig {
        accept_invalid_certs: true,
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        http_protocol: HttpProtocol::Http2,
        http2_stream_window: Some(4 * 1024 * 1024),
        http2_connection_window: Some(8 * 1024 * 1024),
        ..ClientConfig::default()
    })
    .unwrap_or_else(|e| panic!("tuned client: {e}"));
    let url = format!("{base}/warmup");
    let warm = ok(tuned.get(&url, &RequestCtx::default()).await, "tuned get");
    let _ = ok(warm.response.bytes().await, "tuned body");
    assert_eq!(
        obs.initial_stream_window.load(Ordering::SeqCst),
        4 * 1024 * 1024,
        "the explicit stream-window override is advertised via SETTINGS_INITIAL_WINDOW_SIZE"
    );
    assert_eq!(
        obs.conn_window_delta_peak.load(Ordering::SeqCst),
        8 * 1024 * 1024 - FLOW_CONTROL_INITIAL,
        "the explicit connection-window override is advertised via a stream 0 WINDOW_UPDATE"
    );
}

// ---------------------------------------------------------------------------
// ⑤ h2 max-connections on the wire
// ---------------------------------------------------------------------------

/// `http2_max_connections = K` opens K TCP connections to the same
/// origin (each pool instance is its own connection; a single reqwest
/// instance coalesces onto 1 — see test ③). The default anchor (K=1)
/// is covered there too.
#[tokio::test]
async fn http2_max_connections_opens_k_tcp_connections() {
    let (base, obs) = spawn_h2c(Duration::from_millis(250)).await;
    let cli = Arc::new(
        HttpClient::new(ClientConfig {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            http_protocol: HttpProtocol::Http2,
            http2_max_connections: 4,
            ..ClientConfig::default()
        })
        .unwrap_or_else(|e| panic!("client: {e}")),
    );
    let url = format!("{base}/f.bin");
    // 8 concurrent requests round-robin over K=4 instances: each
    // instance gets at least one request, so all 4 connections open;
    // requests within an instance reuse one connection (pool
    // coalescing), so accepts stay exactly at 4.
    let mut handles = Vec::new();
    for i in 0..8 {
        let cli = cli.clone();
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let followed = ok(cli.get(&url, &RequestCtx::default()).await, "get");
            ok(followed.response.bytes().await, "body");
            i
        }));
    }
    for h in handles {
        ok(h.await, "join");
    }
    assert_eq!(
        obs.accepts.load(Ordering::SeqCst),
        4,
        "K=4 -> the origin sees exactly 4 TCP connections \
         (the wire face of the multi-connection cap)"
    );
    assert_eq!(
        obs.streams.load(Ordering::SeqCst),
        8,
        "all 8 requests complete multiplexed over the 4 connections"
    );
}

// ---------------------------------------------------------------------------
// ⑥ h2 PING keep-alive probing
// ---------------------------------------------------------------------------

/// Keep-alive idle probing on the wire: with `--http2-keep-alive-interval`
/// set, idle pooled connections receive PING frames within the interval —
/// the behavior of `http2_keep_alive_while_idle(true)` (with reqwest's
/// default false, hyper skips pings for idle connections, so the
/// advertised idle-pool liveness probe never fires). Construction: one
/// request completes and returns the connection to the pool, the
/// connection goes idle, then wait 3x interval and count frames at the
/// origin. The mock answers PONG (mirroring the 8-byte payload) so the
/// connection is not killed by a 2x-interval timeout.
#[tokio::test]
async fn keep_alive_pings_idle_pooled_connection() {
    const INTERVAL: Duration = Duration::from_millis(150);
    let (base, obs) = spawn_h2c(Duration::ZERO).await;
    let cli = HttpClient::new(ClientConfig {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_secs(5),
        http_protocol: HttpProtocol::Http2,
        http2_keep_alive_interval: Some(INTERVAL),
        ..ClientConfig::default()
    })
    .unwrap_or_else(|e| panic!("client: {e}"));
    // One request completes and the connection returns to the pool
    // idle (pool_idle_timeout 90s far exceeds the observation window,
    // so the connection is not evicted first).
    let url = format!("{base}/warmup");
    let warm = ok(cli.get(&url, &RequestCtx::default()).await, "warm get");
    let _ = ok(warm.response.bytes().await, "warm body");
    assert_eq!(
        obs.accepts.load(Ordering::SeqCst),
        1,
        "must stay the same pooled connection throughout the observation window \
         (multiple connections = observing the wrong object)"
    );
    // Wait 3x interval: with while_idle in effect, the idle connection
    // receives a PING every interval; the lower bound of 2 frames
    // tolerates scheduling jitter (450ms window / 150ms interval).
    // Ping cadence anchor: proto/h2/ping.rs maybe_ping.
    tokio::time::sleep(INTERVAL * 3).await;
    let pings = obs.keep_alive_pings.load(Ordering::SeqCst);
    assert!(
        pings >= 2,
        "the idle pooled connection must receive PING frames within the interval \
         (got {pings} in 450ms) \
         — http2_keep_alive_while_idle is not in effect"
    );
    // Liveness: PONGs keep the probe from killing the connection, so
    // the next request reuses it (accept count unchanged) — keep-alive
    // still guards against silent middlebox drops without breaking
    // reuse.
    let url = format!("{base}/after-idle");
    let after = ok(cli.get(&url, &RequestCtx::default()).await, "after get");
    assert_eq!(
        ok(after.response.bytes().await, "after body").as_ref(),
        b"x"
    );
    assert_eq!(
        obs.accepts.load(Ordering::SeqCst),
        1,
        "the connection must stay alive and reusable during keep-alive probing \
         (PONG answered, not killed-and-reconnected)"
    );
}

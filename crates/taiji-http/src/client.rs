//! reqwest client wrapper: **manual redirects** (20-hop cap + visited-set
//! loop detection + WHATWG URL relative `Location` resolution +
//! https->http downgrade rejected by default + cross-host credential
//! stripping, monotonic and irreversible + layered task-cookie replay),
//! **401 authentication challenge answering** (Basic pre-sent + Digest
//! challenge re-answer, [`crate::auth`]), UA/timeout/retry/proxy
//! surfaces, and the data-plane `Accept-Encoding: identity` policy.
//!
//! Hard invariants:
//! - Redirect loop control lives entirely in this layer (reqwest runs
//!   with `redirect(Policy::none)`); the loop key is
//!   (scheme, host, port, path) — a query-variant loop rejects as
//!   RedirectLoop, never burning the hop budget into a RedirectLimit
//!   misreport.
//! - Credential scope = (scheme, host, port); stripping is monotonic and
//!   irreversible: once stripped, no later hop revives credentials.
//! - Redirect-target IP hygiene ([`crate::redirect_guard`]): the initial
//!   URL is classified once under the `all` rule, every hop target under
//!   `any` (resolution failure fail-closed); a restricted target with a
//!   non-restricted initial aborts with
//!   [`HttpError::RedirectToRestrictedIp`].
//! - The probe plane must read raw headers: it uses a transport with
//!   auto-decompression off, since decompression strips the raw
//!   `Content-Encoding` header.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, StatusCode, Url};

use crate::auth::{self, Challenge, Credentials};
use crate::cookies::CookieJar;
use crate::error::HttpError;
use crate::retry::RetryPolicy;
use crate::traits::{AuthScheme, RequestCtx};
// PEM parsing (`--ca-certificate`) goes through rustls' pki-types
// re-export (same shape as ftp.rs's suppaftp re-export, no new
// dependency): rustls-pki-types 1.15+ ships the `pem` module by default
// with alloc — no feature changes.
use suppaftp::rustls::pki_types::pem::PemObject;
use taiji_io::dns::SharedDns;
use taiji_io::metrics::{MetricsRegistry, RequestPhase, registry_default};

/// Redirect hop cap (cross-checked against aria2 `--max-redirect`, default 20).
pub const MAX_REDIRECTS: u32 = 20;

/// Credential-class headers (stripped on a cross-host redirect; compared
/// lowercase). `Proxy-Authorization` is stripped with the same family:
/// when the credential scope changes, the proxy-side identity must not
/// leak either.
const CREDENTIAL_HEADERS: [&str; 4] = ["authorization", "cookie", "cookie2", "proxy-authorization"];

/// Drain cap for 3xx hop response bodies: reading to EOF lets the
/// connection be reused; past the cap reuse is abandoned (Response drop
/// closes the connection). The drain never blocks the hop.
pub const MAX_REDIRECT_DRAIN_BYTES: u64 = 64 * 1024;

/// Default h2 engine receive windows: stream 8MiB + connection 16MiB.
/// hyper's library defaults (2MiB/5MiB) are reachable only through the
/// programmatic `None` control path.
pub const DEFAULT_H2_STREAM_WINDOW: u32 = 8 * 1024 * 1024;
pub const DEFAULT_H2_CONN_WINDOW: u32 = 16 * 1024 * 1024;

/// HTTP protocol shape (`--http-protocol=auto|h1|h2`; default `Auto` =
/// current behavior, unchanged).
///
/// - `Auto` (default): plaintext endpoints use http/1.1; https
///   negotiates via rustls ALPN (h2 when the server advertises it,
///   http/1.1 fallback otherwise). This is the status quo once reqwest's
///   `http2` feature is enabled — the anchor value for unchanged
///   default behavior.
/// - `Http1`: http/1.1 only ([`reqwest::ClientBuilder::
/// http1_only`]; the ALPN advertisement narrows to http/1.1) — a
///   fallback/control knob that shuts the h2 upgrade path.
/// - `Http2`: HTTP/2 prior knowledge (RFC 7540 §3.5,
///   [`reqwest::ClientBuilder::
/// http2_prior_knowledge`]): plaintext endpoints speak h2c directly
///   (no Upgrade, **no h1 fallback**); https endpoints speak h2
///   directly over TLS (no ALPN). Experimental: it fails outright
///   against h1-only peers, hence off by default.
///
/// No separate `h2c` value and no `h2c-auto` naming: reqwest prior
/// knowledge is a single transport-level shape with no "automatic
/// fallback" semantics ("auto" would mislead); h2c is only `Http2`
/// projected onto plaintext endpoints, and splitting construction by
/// scheme would duplicate transport instances (inner/raw are built in
/// pairs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HttpProtocol {
    /// Negotiated status quo (default): plaintext h1 + https ALPN (h2 preferred, h1 fallback).
    #[default]
    Auto,
    /// Force http/1.1 (h2 upgrade shut off).
    Http1,
    /// HTTP/2 prior knowledge (plaintext = h2c; no fallback; experimental).
    Http2,
}

/// TLS minimum protocol version (`--min-tls-version`; value range
/// tls1.2|tls1.3 — the aria2 `--min-tls-version` TLSv1.2/TLSv1.3 face in
/// lowercase form with the `v` dropped).
///
/// A first-party enum rather than storing `reqwest::tls::Version`
/// directly: the latter derives no `Hash` (reqwest 0.13 `tls.rs` has
/// only PartialEq/Eq), so it cannot enter the [`ClientConfig`] bucket-key
/// face. The mapping to the reqwest side is pinned at the
/// [`build_transport`] consumption point (`ClientBuilder::tls_version_min`
/// — the 0.13 non-deprecated name; `min_tls_version` is the deprecated
/// alias).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MinTlsVersion {
    /// TLS 1.2 floor (1.0/1.1 refuse to negotiate; the workspace rustls
    /// "tls12" feature is enabled — 1.2 is expressible).
    #[default]
    Tls12,
    /// TLS 1.3 floor (1.2 is refused too — only 1.3 negotiates).
    Tls13,
}

impl MinTlsVersion {
    /// Option value -> enum (one source for the value range; the CLI clap
    /// value_parser and the conf value-range check share the same domain:
    /// `tls1.2|tls1.3`). Outside the domain = None.
    pub fn from_value(value: &str) -> Option<Self> {
        match value {
            "tls1.2" => Some(MinTlsVersion::Tls12),
            "tls1.3" => Some(MinTlsVersion::Tls13),
            _ => None,
        }
    }

    /// -> the reqwest version floor (projected at the [`build_transport`]
    /// consumption point).
    fn to_reqwest(self) -> reqwest::tls::Version {
        match self {
            MinTlsVersion::Tls12 => reqwest::tls::Version::TLS_1_2,
            MinTlsVersion::Tls13 => reqwest::tls::Version::TLS_1_3,
        }
    }
}

/// Client configuration (defaults). The `PartialEq`/`Hash` impls key the
/// process-level shared pool of [`HttpClient::new`]: tasks with equal
/// configs share transport instances / connection pools (see the
/// [`SHARED_CLIENTS`] isolation boundary).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientConfig {
    /// Default UA (honest identity `taiji/<semver>`; spoofing is set explicitly by the user).
    pub user_agent: String,
    /// Read idle timeout (`--timeout`, default 60s).
    pub read_timeout: Duration,
    /// Connect timeout (`--connect-timeout`, default 60s).
    pub connect_timeout: Duration,
    /// Connection pool idle keep-alive (fixed 90s).
    pub pool_idle_timeout: Duration,
    /// Redirect hop cap (default 20).
    pub max_redirects: u32,
    /// Allow https->http downgrade (rejected by default).
    pub allow_insecure_downgrade: bool,
    /// Data-plane `Accept-Encoding: identity` (default true; false = let
    /// reqwest negotiate automatically — reserved).
    pub identity_encoding: bool,
    /// Retry parameters (default 5 attempts / 0s / 30s cap; driven by the extent-level consumer).
    pub retry: RetryPolicy,
    /// Hostname->address pinning (DNS override; keys are hostnames,
    /// matched lowercase on the reqwest side; an explicit URL port wins
    /// over the pinned address port). Production face of the
    /// media SSRF line: the line pins each judged hostname to the address
    /// its judgment resolved (one resolution, the connection lands on
    /// it — Host/SNI keep the URL's name), closing the DNS-rebinding
    /// TOCTOU between the SSRF judgment query and the transport's own
    /// connection resolution. Wire-level cross-validation of hostname
    /// normalization (case, IDN) rides the same surface.
    pub pinned_resolve: Vec<(String, SocketAddr)>,
    /// Global proxy (`--all-proxy`; http/https proxy URL, auth via URL
    /// userinfo). socks5(h) needs the reqwest `socks` feature (not
    /// enabled — rejected explicitly at option parsing). `None` =
    /// direct connection.
    pub proxy: Option<String>,
    /// Dedicated HTTPS proxy (`--https-proxy`; http/https proxy URL,
    /// auth via URL userinfo). Precedence = **dedicated slot > global
    /// slot**: this slot registers before [`Self::proxy`] (reqwest
    /// evaluates multiple proxies first-match-wins by registration
    /// order, and the `Proxy::https` matcher only intercepts https
    /// targets) — https targets are captured by the dedicated slot,
    /// every other scheme falls to the global slot; both slots `None`
    /// = direct connection. Part of the pool bucket key.
    pub proxy_https: Option<String>,
    /// TLS certificate verification off (`--check-certificate=false`;
    /// default false = verification on).
    pub accept_invalid_certs: bool,
    /// Task-level CA file (`--ca-certificate`, PEM `CERTIFICATE`
    /// sections): when non-empty and verification is on, the transport
    /// roots are the file's CAs, **replacing** the platform trust store
    /// (aria2 replacement semantics, not append). Part of the pool
    /// bucket key (a different CA = a different transport instance,
    /// zero cross-config connection sharing). File loading / PEM parse
    /// failure = client build error (never silently ignored); combined
    /// with `accept_invalid_certs`, the latter wins (verification is
    /// already off and this file is ignored unread — aria2 same
    /// semantics, see [`build_transport`]).
    pub ca_cert_path: Option<std::path::PathBuf>,
    /// Client mTLS certificate (`--certificate`, a PEM `CERTIFICATE`
    /// section): consumed in pair with [`Self::identity_key_path`] (one
    /// side given = a client build error — a TLS client identity cannot
    /// hold with half of it missing, the aria2 two-option shape). Part of
    /// the bucket key. Load/parse failure = a client build error (never
    /// silently allowed through; the single load point =
    /// [`load_client_identity_pem`]).
    pub identity_cert_path: Option<std::path::PathBuf>,
    /// Client private key (`--private-key`, PEM; a PKCS#8 `PRIVATE KEY` /
    /// RSA `RSA PRIVATE KEY` / EC `EC PRIVATE KEY` section, any of the
    /// three — the reqwest `Identity::from_pem` value range). Consumed in
    /// pair with [`Self::identity_cert_path`]. The key material itself is
    /// never logged (only the path and the error shape).
    pub identity_key_path: Option<std::path::PathBuf>,
    /// TLS minimum protocol version (`--min-tls-version`; default None =
    /// the engine default is not tightened — the rustls platform policy).
    /// Part of the bucket key. Effective surface =
    /// [`build_transport`] `ClientBuilder::tls_version_min`.
    pub min_tls_version: Option<MinTlsVersion>,
    /// HTTP protocol shape (`--http-protocol`; default `Auto` = current
    /// behavior, plaintext h2c is experimental).
    pub http_protocol: HttpProtocol,
    /// h2 adaptive flow-control receive window (`--http2-adaptive-window`,
    /// experimental; default false = static engine defaults 8MiB/16MiB —
    /// hyper's library defaults 2MiB/5MiB are reachable only via the
    /// programmatic `None` control path): when on, receive windows grow
    /// dynamically from ping/BDP estimation (the common dynamic-window
    /// approach, hedging the ~2MiB/RTT single-stream ceiling of long-fat
    /// transcontinental pipes). Only affects h2 transports.
    pub http2_adaptive_window: bool,
    /// h2 stream-level initial receive window in bytes
    /// (`--http2-stream-window`, experimental; default = engine default
    /// **8MiB**; `None` = hyper's library default 2MiB, reachable only
    /// via the programmatic control path). Explicit values
    /// 65535..=2^31-1 (RFC 7540 §5.2.2) are validated at option parsing.
    pub http2_stream_window: Option<u32>,
    /// h2 connection-level initial receive window in bytes
    /// (`--http2-connection-window`, experimental; default = engine
    /// default **16MiB**, shared by all streams; `None` = hyper's
    /// library default 5MiB). Only affects the unlimited full-speed
    /// path — rate-limit backpressure semantics (flow-control waits are
    /// excluded from stall detection, see `stall.rs`) are unchanged by
    /// this knob.
    pub http2_connection_window: Option<u32>,
    /// h2 per-origin connection cap (`--http2-max-connections`,
    /// experimental; default 1 = status quo: one multiplexed
    /// connection). Implementation = K independent transport instances
    /// (reqwest merges pools by origin and has no K-connection API —
    /// each instance's independent pool is an independent connection);
    /// data-plane requests spread by atomic round-robin. Ineffective
    /// when negotiation lands on h1 (h1 connection count is governed by
    /// the split logic). Part of the shared pool bucket key.
    pub http2_max_connections: u32,
    /// h2 PING keep-alive interval (`--http2-keep-alive-interval`,
    /// experimental; `None` = off = hyper status quo): liveness probes
    /// for idle pooled connections — guards against dead-connection
    /// tail latency after silent middlebox drops. Timeout = 2x the
    /// interval (fixed internally, reqwest `http2_keep_alive_timeout`);
    /// **always on while idle** (`http2_keep_alive_while_idle` — with
    /// reqwest's default false, hyper only pings with active streams
    /// and pooled idle connections are never probed).
    pub http2_keep_alive_interval: Option<Duration>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            user_agent: format!("taiji/{}", env!("CARGO_PKG_VERSION")),
            read_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(60),
            pool_idle_timeout: Duration::from_secs(90),
            max_redirects: MAX_REDIRECTS,
            allow_insecure_downgrade: false,
            identity_encoding: true,
            retry: RetryPolicy::default(),
            pinned_resolve: Vec::new(),
            proxy: None,
            proxy_https: None,
            accept_invalid_certs: false,
            ca_cert_path: None,
            identity_cert_path: None,
            identity_key_path: None,
            min_tls_version: None,
            http_protocol: HttpProtocol::default(),
            http2_adaptive_window: false,
            http2_stream_window: Some(DEFAULT_H2_STREAM_WINDOW),
            http2_connection_window: Some(DEFAULT_H2_CONN_WINDOW),
            http2_max_connections: 1,
            http2_keep_alive_interval: None,
        }
    }
}

/// Response after following redirects: `final_url` feeds the probe
/// layer's ResumeValidator bookkeeping.
#[derive(Debug)]
pub struct Followed {
    /// Final response (a 3xx without Location is returned as-is;
    /// classification is left to the caller).
    pub response: reqwest::Response,
    /// Final URL after redirect convergence.
    pub final_url: Url,
    /// Number of redirects actually followed (0 = the first hop was terminal).
    pub hops: u32,
}

impl Followed {
    /// Normalized final URL path (path only, query stripped) — the value
    /// source for ResumeValidator `final_url_path`.
    pub fn final_url_path(&self) -> String {
        self.final_url.path().to_string()
    }
}

/// HTTP client (manual redirects + cookie jar). Cheap to clone; safe to
/// share across workers.
///
/// Transport instances differ only in auto-decompression (all other
/// settings identical item by item):
/// - `inner` (data plane, K instances): reqwest's gzip feature is on by
///   default, so responses are auto-decompressed — "reqwest
///   decompresses, checksums apply to the decompressed bytes". When
///   decompression happens, reqwest strips the
///   `Content-Encoding`/`Content-Length` headers. K =
///   `http2_max_connections` (default 1; K>1 spreads requests
///   round-robin, each instance's independent pool = independent
///   connections).
/// - `raw` (probe plane, one instance): explicit `gzip(false)` — the
///   probe decision needs the unstripped raw `Content-Encoding` header.
#[derive(Clone)]
pub struct HttpClient {
    /// Data-plane transport instances (multiple connections): length =
    /// `cfg.http2_max_connections` (K=1 degrades to the single-instance
    /// semantics, unchanged). Requests spread via
    /// [`HttpClient::data_transport`] atomic round-robin — one h2
    /// connection's concurrent streams spread over K connections
    /// (reqwest merges pools by origin; K instances = K connections).
    inner: Box<[Client]>,
    raw: Client,
    cfg: Arc<ClientConfig>,
    jar: Arc<CookieJar>,
    /// Round-robin counter (Arc shared by all clones — a task's workers share it).
    rr: Arc<AtomicU64>,
    /// Shared resolver service (decision input for redirect IP hygiene,
    /// [`crate::redirect_guard`]): the same process-level instance
    /// [`SharedDns::shared_default`] used by [`DnsAdapter`] for
    /// transport connection setup — decisions and connections share one
    /// source and cache (TTL). **Not** part of the [`ClientConfig`]
    /// bucket key (same note as the [`DnsAdapter`] resolver).
    dns: Arc<SharedDns>,
    /// Metrics registry (feed-point seam — classification seam / request
    /// latency; production = the process default instance
    /// [`registry_default`], tests inject an isolated instance via
    /// [`HttpClient::with_metrics`]). **Not** part of the
    /// [`ClientConfig`] bucket key — the registry is observability
    /// wiring, not transport configuration (same rule as the
    /// [`DnsAdapter`] resolver note).
    metrics: Arc<MetricsRegistry>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (no derive): the fields are live Arc'd handles
        // (reqwest clients with their connection pools, the cookie jar,
        // the resolver) that implement no `Debug` — the diagnostic face
        // lists the shared-pool bucket key (the configuration) only.
        f.debug_struct("HttpClient")
            .field("cfg", &self.cfg)
            .finish()
    }
}

/// Process-level shared client pool (small-task path pooling — the
/// landing point of "reuse connections across slices and files").
///
/// [`HttpClient::new`] (empty jar) returns a cheap Clone of the **same
/// transport instance** for the same [`ClientConfig`] key — the reqwest
/// connection pool (`pool_idle_timeout` 90s, value unchanged) thereby
/// outlives task lifetimes: keep-alive connections returned to the pool
/// by one task are reused directly by the concurrent Range slices of
/// later tasks against the same host.
///
/// # Isolation boundary (no existing external semantics change)
///
/// - Key = the full [`ClientConfig`] (proxy/TLS/protocol
///   shape/timeouts/retry/DNS pinning, field by field): any transport
///   configuration difference means an independent instance, zero
///   cross-config connection sharing.
/// - [`HttpClient::with_jar`] (the `--load-cookies` surface) **never
///   enters the pool**: clients carrying a task-private jar stay
///   per-instance (the conservative cookie-isolation boundary).
/// - Task cookies do not go through this jar (`RequestCtx.task_cookies`
///   is a per-task store, layered separately) — no cookie cross-talk
///   between users of a shared instance; the shared empty jar is
///   read-only at runtime (parse-time construction + `header_for`
///   replay, no runtime write path).
/// - Zero involvement in pool semantics: connection liveness/eviction
///   is managed entirely by the reqwest pool's own 90s idle recycling
///   (no pre-warming, no eviction in this layer — surge-prewarm warm
///   pooling is policy-level, not this layer's concern). The FTP reuse
///   pool is unrelated to this pool.
///
/// # Lifetime
///
/// Pool entries are never evicted: the set of config combinations is
/// finite (option value ranges are finite), and connection resources
/// converge via reqwest idle recycling. Safe to use across tokio
/// runtimes: hyper's connection pool dials lazily, and dead connections
/// (whose runtime closed since they were made) are health-checked and
/// re-dialed on use.
static SHARED_CLIENTS: OnceLock<StdMutex<HashMap<ClientConfig, HttpClient>>> = OnceLock::new();

/// Warm-pool signal window (precise connection staggering): equal to
/// `pool_idle_timeout` (90s) — the longest an idle connection survives
/// in the reqwest pool; beyond the window connections have been evicted
/// and the signal cools, restoring the stagger ramp.
const HOST_WARM_WINDOW: Duration = Duration::from_secs(90);

/// Process-level per-host warm-pool signal (precise staggering: the
/// stagger applies only when a connect would really happen; pooled
/// reuse stays zero-latency).
///
/// When the **data plane** (inner transport instances) gets a successful
/// response on the shared pool for a host within the window, that host
/// key is marked lit (instant of last success). The core stagger site
/// (a task's first-wave connection ramp) queries [`uri_on_warm_pool`]:
/// a warm host's slice most likely hits a pooled keep-alive connection
/// (zero connect) and skips the ramp; a cold host keeps the ramp
/// (guards against same-instant connection storms causing RSTs).
///
/// # Approximate semantics (directional argument)
///
/// - The signal is not "an idle connection exists in the pool right
///   now" (reqwest's pool internals are opaque to this layer): it is a
///   timestamp approximation of "the data plane succeeded on this host
///   within the window" — it can only err warm (a fresh connect still
///   happens on an occasional reuse miss; the per-host cap and the ramp
///   retained for cold tasks bound the storm risk), never cold (an
///   unlit host always takes the ramp).
/// - The **probe plane (raw instance) never lights it**: probe
///   connections live in a separate pool that data-plane slices cannot
///   reuse — lighting it would mean "skip the ramp with no reuse", a
///   pure misjudgment.
/// - Races: std Mutex with nanosecond-scale critical sections, at most
///   one read/write per request, no lock held across an await.
/// - **Capacity bound**: the warm table is a process-wide singleton;
///   the grow-only shape would increase monotonically in long sessions
///   with many hosts (the 90s window expiry applies implicitly at read
///   time only; entries themselves are never reclaimed) —
///   [`HOST_WARMTH_CAP`] entries with LRU eviction
///   (least-recently-lit first). [`SHARED_CLIENTS`] is untouched (the
///   set of config combinations is finite).
static HOST_WARMTH: OnceLock<StdMutex<WarmthTable>> = OnceLock::new();

/// Warm table capacity bound: real download source sets have far lower
/// host diversity than this (same order as the per-host connect cap);
/// 512 entries is imperceptible to the warm decision. Eviction happens
/// only in extreme over-capacity shapes (scanning / misconfigured
/// source lists).
const HOST_WARMTH_CAP: usize = 512;

/// Warm-pool signal table: `host -> last lit instant` + capacity-bound
/// LRU.
///
/// Hand-rolled without new dependencies (HashMap + BTreeMap ordering):
/// lighting (write side) refreshes recency and evicts the
/// least-recently-lit entry past capacity; queries (read side) are pure
/// lookups that **never touch recency** (neither the warm decision nor
/// the lighting semantics changes because of a query — reads do not
/// alter the eviction order, equivalent to "evict by lighting
/// freshness"). All operations are O(log cap) (cap = 512, lock-held
/// critical sections are nanosecond-scale).
struct WarmthTable {
    /// Host key -> (lit instant, lit sequence): the instant feeds window
    /// checks, the sequence feeds LRU re-ordering/removal (O(1)
    /// location of the old sequence, no reverse scan).
    entries: HashMap<String, (Instant, u64)>,
    /// Lit sequence (monotonic seq -> host): the LRU order;
    /// `first_key` = least recently lit.
    order: BTreeMap<u64, String>,
    /// Monotonically increasing lighting sequence number.
    next_seq: u64,
}

impl WarmthTable {
    fn new() -> Self {
        WarmthTable {
            entries: HashMap::new(),
            order: BTreeMap::new(),
            next_seq: 0,
        }
    }

    /// Light/refresh (write-side recency): an existing key is re-ordered
    /// (old sequence removed); past capacity, the least-recently-lit
    /// entry is evicted.
    fn note(&mut self, host: String, at: Instant) {
        if let Some((_, old_seq)) = self.entries.get(&host) {
            self.order.remove(old_seq);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.order.insert(seq, host.clone());
        self.entries.insert(host, (at, seq));
        while self.entries.len() > HOST_WARMTH_CAP {
            // Capacity-bound eviction: the oldest sequence (least
            // recently lit) leaves first (saturation-path defense — the
            // normal single-insert path never overflows).
            let Some((_, evicted)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&evicted);
        }
    }

    /// Warm query (read side never touches recency): `Some(t)` is window-checked by the caller.
    fn warm_at(&self, host: &str) -> Option<Instant> {
        self.entries.get(host).map(|(t, _)| *t)
    }

    /// Current entry count (test observation).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Data-plane successful-response feed point (only at the terminal
/// return of [`HttpClient::execute`]; probe-plane callers must not
/// feed).
fn note_host_warm(url: &Url) {
    let Some(key) = crate::perhost::HostCap::host_key(url.as_str()) else {
        return;
    };
    crate::lock(HOST_WARMTH.get_or_init(|| StdMutex::new(WarmthTable::new())))
        .note(key, Instant::now());
}

/// Whether this URL's host is "warm" on the shared pool (a data-plane
/// success within the [`HOST_WARM_WINDOW`] window): true -> the stagger
/// site skips the ramp (pooled reuse likely, zero connect); false ->
/// the first-wave stagger is kept. Key shape matches
/// [`crate::perhost::HostCap::host_key`] (scheme://host:port, default
/// port normalized). Unparseable URLs are always cold (conservative:
/// never skip the stagger).
pub fn uri_on_warm_pool(url: &str) -> bool {
    let Some(key) = crate::perhost::HostCap::host_key(url) else {
        return false;
    };
    crate::lock(HOST_WARMTH.get_or_init(|| StdMutex::new(WarmthTable::new())))
        .warm_at(&key)
        .is_some_and(|t| t.elapsed() < HOST_WARM_WINDOW)
}

impl HttpClient {
    /// Build a client (empty cookie jar): for the same [`ClientConfig`],
    /// the process-level shared pool ([`SHARED_CLIENTS`]) returns the
    /// same transport instance — keep-alive connections are reused
    /// across tasks (files) and across a task's Range slices.
    pub fn new(cfg: ClientConfig) -> Result<Self, HttpError> {
        let pool = SHARED_CLIENTS.get_or_init(|| StdMutex::new(HashMap::new()));
        let mut guard = crate::lock(pool);
        if let Some(shared) = guard.get(&cfg) {
            return Ok(shared.clone());
        }
        let built = Self::build_standalone(cfg.clone(), CookieJar::new(), registry_default())?;
        guard.insert(cfg, built.clone());
        Ok(built)
    }

    /// Build a client and attach the jar parsed from `--load-cookies`.
    /// **Each call builds independently and never enters the shared
    /// pool** ([`SHARED_CLIENTS`] isolation boundary: instances with a
    /// task-private jar are never shared across tasks).
    pub fn with_jar(cfg: ClientConfig, jar: CookieJar) -> Result<Self, HttpError> {
        Self::build_standalone(cfg, jar, registry_default())
    }

    /// Build a client bound to the given metrics registry
    /// (observability seam injection — tests assert feed-point deltas on
    /// an isolated registry, avoiding parallel-test pollution of the
    /// process default). **Not in the shared pool** (same isolation
    /// boundary as [`HttpClient::with_jar`]).
    pub fn with_metrics(
        cfg: ClientConfig,
        metrics: Arc<MetricsRegistry>,
    ) -> Result<Self, HttpError> {
        Self::build_standalone(cfg, CookieJar::new(), metrics)
    }

    /// A variant of this client whose transport pins the given
    /// hostnames to the given addresses (production face of
    /// [`ClientConfig::pinned_resolve`] — the media SSRF
    /// connection pin: the judgment layer's resolved address is
    /// pinned onto the fetch transport, so the connection lands on
    /// the judged address even if a rebinding DNS would answer
    /// differently at connect time). Same timeouts/TLS/proxy shape,
    /// same jar contents and metrics registry; the pin table extends
    /// this client's (first entry wins, matching reqwest's override
    /// layer). **Never enters the shared pool**: the pin table is
    /// task-scope (one task's judgments must not steer another
    /// task's connections), so the variant builds standalone.
    pub fn with_pinned_resolve(&self, pins: &[(String, SocketAddr)]) -> Result<Self, HttpError> {
        let mut cfg = (*self.cfg).clone();
        for (host, addr) in pins {
            if !cfg
                .pinned_resolve
                .iter()
                .any(|(h, _)| h.eq_ignore_ascii_case(host))
            {
                cfg.pinned_resolve.push((host.clone(), *addr));
            }
        }
        Self::build_standalone(cfg, (*self.jar).clone(), Arc::clone(&self.metrics))
    }

    /// The active pin table (read face for the pin consumers and the
    /// regression probes).
    pub fn pinned_resolve(&self) -> &[(String, SocketAddr)] {
        &self.cfg.pinned_resolve
    }

    /// Actual construction (K data-plane transport instances + probe
    /// instance + jar wiring; shared by the pooled and standalone
    /// paths). With K > 1, a per-instance build failure fails the whole
    /// build (a half-built product never enters the pool — pool entries
    /// must be fully usable).
    fn build_standalone(
        cfg: ClientConfig,
        jar: CookieJar,
        metrics: Arc<MetricsRegistry>,
    ) -> Result<Self, HttpError> {
        let k = cfg.http2_max_connections.max(1) as usize;
        let mut inners = Vec::with_capacity(k);
        for _ in 0..k {
            inners.push(build_transport(&cfg, true, &metrics)?);
        }
        let raw = build_transport(&cfg, false, &metrics)?;
        Ok(Self {
            inner: inners.into_boxed_slice(),
            raw,
            cfg: Arc::new(cfg),
            jar: Arc::new(jar),
            rr: Arc::new(AtomicU64::new(0)),
            dns: SharedDns::shared_default(),
            metrics,
        })
    }

    /// Data-plane instance selection: atomic counter modulo — concurrent
    /// requests spread evenly over the K instances (each instance's
    /// independent pool = independent h2/h1 connections); with a single
    /// instance the modulo is always 0 (one branch, same semantics).
    fn data_transport(&self) -> &Client {
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % self.inner.len() as u64;
        &self.inner[i as usize]
    }

    /// Data-plane GET (default `Accept-Encoding: identity`), following redirects manually.
    pub async fn get(&self, url: &str, ctx: &RequestCtx) -> Result<Followed, HttpError> {
        self.execute(
            self.data_transport(),
            url,
            ctx,
            None,
            self.cfg.identity_encoding,
        )
        .await
    }

    /// Retry parameter surface (read by URI-level consumers such as the
    /// probe layer; the client itself never retries implicitly — the
    /// consumer drives, avoiding double counting).
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.cfg.retry
    }

    /// Range/probe GET: adds `Range: bytes=<start>-<end>` (inclusive);
    /// otherwise identical to [`HttpClient::get`].
    pub async fn get_range(
        &self,
        url: &str,
        ctx: &RequestCtx,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Followed, HttpError> {
        self.execute(
            self.data_transport(),
            url,
            ctx,
            Some((start, end_inclusive)),
            self.cfg.identity_encoding,
        )
        .await
    }

    /// Probe-plane GET (raw headers preserved): the same
    /// redirect/credential/identity policy as [`HttpClient::get_range`],
    /// but through the transport instance with auto-decompression off —
    /// the probe decision (`Content-Encoding` other than identity) must
    /// read the unstripped raw header (data-plane auto-decompression
    /// strips it, see the struct docs).
    pub async fn get_range_raw(
        &self,
        url: &str,
        ctx: &RequestCtx,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Followed, HttpError> {
        self.execute(
            &self.raw,
            url,
            ctx,
            Some((start, end_inclusive)),
            self.cfg.identity_encoding,
        )
        .await
    }

    /// Manual redirect loop. `transport` is chosen by the caller
    /// (data-plane/probe-plane instance; the only difference is
    /// auto-decompression).
    async fn execute(
        &self,
        transport: &Client,
        url: &str,
        ctx: &RequestCtx,
        range: Option<(u64, u64)>,
        identity_encoding: bool,
    ) -> Result<Followed, HttpError> {
        let first =
            Url::parse(url).map_err(|e| HttpError::Transport(format!("invalid url: {e}")))?;
        // Redirect IP hygiene: classify the initial URL exactly once
        // (before the first hop) under the **all** rule (all resolved
        // addresses must be restricted to form a restricted anchor — a
        // mixed-family host must not dissolve the guard through the
        // "restricted initial -> allow all hops" short circuit). The
        // decision shares the resolver with actual connection setup (a
        // TTL cache narrows the rebinding window; residual risk
        // registered in the [`crate::redirect_guard`] module docs). A
        // missing host (defensive: the url crate always has a host for
        // http/https) or resolution failure counts as non-restricted
        // (guard stays armed) — an unreachable host is reported by the
        // connection layer's existing errors.
        let initial_ip_class = crate::redirect_guard::classify_host_all(
            &self.cfg.pinned_resolve,
            &self.dns,
            first.host_str().unwrap_or(""),
        )
        .await;
        let mut current = first;
        // Loop detection key = (scheme, host, port, path): query
        // variants (/a?i=1 -> /a?i=2 -> ...) reject as a loop
        // (RedirectLoop), never burning the hop budget into a
        // RedirectLimit misreport.
        let mut visited: HashSet<(String, String, u16, String)> = HashSet::new();
        // Credential scope: the first hop always carries credentials;
        // any (scheme, host, port) change strips them, and stripping is
        // monotonic and irreversible — once stripped, all later hops
        // (including same-host self-hops and hops back into the
        // first-hop scope) stay stripped.
        let mut keep_credentials = true;
        let mut hops: u32 = 0;
        // 401 challenge surface: `pending_auth` = the Authorization
        // value to resend (consumed exactly once); `answered` = URLs
        // whose challenge was already answered (one answer per URL, a
        // further 401 = AuthFailed); `stale_retried` = URLs already
        // re-answered due to Digest stale=true (RFC 7616 §3.6 — only
        // the nonce expired, credentials valid; at most once per URL —
        // a second stale is still AuthFailed, preventing an infinite
        // re-answer loop against a malicious server); `nonce_nc` =
        // nonce -> request count (Digest qop, 8 hex digits, keyed by
        // nonce — a fresh nonce issued via stale restarts from 1).
        let mut pending_auth: Option<String> = None;
        let mut answered: HashSet<(String, String, u16, String)> = HashSet::new();
        let mut stale_retried: HashSet<(String, String, u16, String)> = HashSet::new();
        let mut nonce_nc: HashMap<String, u32> = HashMap::new();
        // Request latency phase (the first_byte feed point of
        // `taiji_http_request_seconds{phase=first_byte|total}` — the
        // whole redirect chain is one logical request; the sample is
        // taken when the terminal response arrives; failed requests are
        // not sampled).
        let t0 = Instant::now();

        loop {
            // Challenge re-answers skip loop detection (same URL resent); new URLs enter the set.
            if pending_auth.is_none() && !visited.insert(loop_key(&current)) {
                return Err(HttpError::RedirectLoop);
            }

            let rb = self.build_request(
                transport,
                &current,
                ctx,
                range,
                keep_credentials,
                identity_encoding,
                pending_auth.take().as_deref(),
            );
            let mut resp = rb
                .send()
                .await
                .map_err(|e| transport_err_counted(self.metrics.http(), e))?;
            let status = resp.status();

            // Task cookie capture: Set-Cookie from both 3xx hop and
            // terminal responses is absorbed into the task store.
            self.absorb_set_cookies(&current, ctx, &resp);

            // 401 challenge answer (Basic/Digest): with credentials
            // present and answerable, rebuild the Authorization and
            // resend (once per URL); unanswerable/exhausted -> re-raise
            // as-is or AuthFailed.
            if status == StatusCode::UNAUTHORIZED
                && let Some(auth_value) = self.on_unauthorized(
                    &current,
                    ctx,
                    resp.headers(),
                    keep_credentials,
                    &mut answered,
                    &mut stale_retried,
                    &mut nonce_nc,
                )?
            {
                // Drain the 401 response body (connection reuse, same discipline as 3xx).
                drain_redirect_body(&mut resp).await;
                tracing::debug!(
                    target: "taiji::http::client",
                    url = %redact_or_verbatim(&current),
                    "answering auth challenge"
                );
                pending_auth = Some(auth_value);
                continue;
            }

            if !is_redirect(status) {
                // Not a redirect, or a 3xx without Location (returned
                // as-is; classification is left to the caller). For
                // ranged requests, validate the 206 echo per response
                // (data plane and probe plane share the discipline,
                // [`validate_range_echo`]): the check anchors only the
                // **start** (the end no longer participates).
                if let Some((start, _end)) = range
                    && status == StatusCode::PARTIAL_CONTENT
                {
                    validate_range_echo(resp.headers(), start)?;
                }
                // Warm-pool feed point (precise staggering): a terminal
                // response means this host's connection was established
                // and, once the response is consumed, returns to the
                // pool — light the signal only for the **data plane**
                // (the inner instances; with K>1 any round-robin hit is
                // data plane). The probe plane's raw connections live in
                // a separate pool that data-plane slices cannot reuse.
                // The signal is per-host, not per-instance: cold
                // instances that did not serve this host may still each
                // open one connection on the first wave (bounded by K);
                // per-instance warm tracking is deliberately not done —
                // the per-host cap bounds the storm risk.
                if self.inner.iter().any(|c| std::ptr::eq(transport, c)) {
                    note_host_warm(&current);
                }
                tracing::debug!(
                    target: "taiji::http::client",
                    status = status.as_u16(),
                    hops,
                    url = %redact_or_verbatim(&current),
                    "request settled"
                );
                self.metrics
                    .http()
                    .observe_request(RequestPhase::FirstByte, t0.elapsed());
                return Ok(Followed {
                    response: resp,
                    final_url: current,
                    hops,
                });
            }

            let location = resp.headers().get(header::LOCATION).map(|v| {
                // Non-UTF-8 Location: convert lossily and join as usual
                // (with an explicit warning), never silently treat it
                // as a terminal 3xx without Location — real servers
                // with IDN/localized paths commonly emit obs-text bytes.
                if v.to_str().is_err() {
                    tracing::warn!(
                        target: "taiji::http::client",
                        url = %redact_or_verbatim(&current),
                        "location header is not utf-8; decoding lossily"
                    );
                }
                String::from_utf8_lossy(v.as_bytes()).into_owned()
            });

            let Some(loc) = location else {
                tracing::debug!(
                    target: "taiji::http::client",
                    status = status.as_u16(),
                    hops,
                    url = %redact_or_verbatim(&current),
                    "3xx without location; returning as terminal"
                );
                self.metrics
                    .http()
                    .observe_request(RequestPhase::FirstByte, t0.elapsed());
                return Ok(Followed {
                    response: resp,
                    final_url: current,
                    hops,
                });
            };

            // Drain the 3xx hop response body (up to the cap): reading
            // to EOF returns the connection to the pool for reuse; past
            // the cap / on error, abandon reuse without blocking the
            // hop.
            drain_redirect_body(&mut resp).await;

            // WHATWG URL relative-reference resolution (url crate `join` = the standard algorithm).
            let next = current
                .join(&loc)
                .map_err(|e| HttpError::Transport(format!("bad location header: {e}")))?;
            match next.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(HttpError::Transport(format!(
                        "redirect to unsupported scheme: {other}"
                    )));
                }
            }
            if is_https_to_http_downgrade(&current, &next) && !self.cfg.allow_insecure_downgrade {
                return Err(HttpError::InsecureRedirect);
            }

            // Redirect target IP hygiene: decide the target only when
            // the initial URL was non-restricted (a public task) — a
            // restricted initial (localhost/LAN) allows every hop
            // (trusted topology, zero impact on existing tests; the
            // short circuit also avoids per-hop resolution traffic).
            // Target rule = **any** (any resolved address restricted ->
            // reject); resolution failure / an empty list is likewise
            // rejected as restricted (fail-closed — negatives are not
            // cached, so allowing would leave the two-query bypass of
            // "the guard query answers SERVFAIL / the connect query
            // answers a private address"; a hop whose resolution failed
            // could not have downloaded anyway, so rejecting costs
            // nothing).
            if initial_ip_class != crate::redirect_guard::IpClass::Restricted {
                let target_host = next.host_str().unwrap_or("");
                let target_class = crate::redirect_guard::classify_host_any(
                    &self.cfg.pinned_resolve,
                    &self.dns,
                    target_host,
                )
                .await;
                if let Err(e) =
                    crate::redirect_guard::hop_decision(initial_ip_class, target_class, target_host)
                {
                    tracing::warn!(
                        target: "taiji::http::client",
                        host = target_host,
                        "redirect to restricted address space refused"
                    );
                    return Err(e);
                }
            }

            hops += 1;
            if hops > self.cfg.max_redirects {
                return Err(HttpError::RedirectLimit {
                    max: self.cfg.max_redirects,
                });
            }
            tracing::debug!(
                target: "taiji::http::client",
                hops,
                from = %redact_or_verbatim(&current),
                to = %redact(&next),
                credentials_kept = keep_credentials,
                "following redirect"
            );
            // Monotonic AND: still kept after the previous hop AND the
            // adjacent hops share a scope — once cross-host stripping
            // happened, no "same-host self-hop" may revive credentials.
            keep_credentials = credentials_survive_hop(keep_credentials, &current, &next);
            current = next;
        }
    }

    /// Absorb response `Set-Cookie` into the task store (task cookie
    /// layer). No-op when the task carries no store (e.g. the probe
    /// plane).
    fn absorb_set_cookies(&self, url: &Url, ctx: &RequestCtx, resp: &reqwest::Response) {
        let Some(store) = &ctx.task_cookies else {
            return;
        };
        for value in resp.headers().get_all(header::SET_COOKIE) {
            store.absorb(url, &String::from_utf8_lossy(value.as_bytes()));
        }
    }

    /// Single-hop request build: user headers (order preserved) +
    /// Referer/UA overrides + Basic pre-set + three-layer cookie
    /// synthesis (explicit pairs / loaded jar / task store) +
    /// Range/identity.
    ///
    /// `extra_auth` = the 401 challenge-answer header (produced by
    /// [`Self::on_unauthorized`], consumed exactly once); when present
    /// it owns Authorization exclusively (reqwest appends same-name
    /// headers — stacking it over the pre-set Basic would let the
    /// server read Basic and void the challenge answer).
    #[expect(
        clippy::too_many_arguments,
        reason = "the request build face carries the full context explicitly (headers/cookies/Range/auth answer); the arity is the seam contract"
    )]
    fn build_request(
        &self,
        transport: &Client,
        url: &Url,
        ctx: &RequestCtx,
        range: Option<(u64, u64)>,
        keep_credentials: bool,
        identity_encoding: bool,
        extra_auth: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut rb = transport.get(url.clone());
        if identity_encoding {
            rb = apply_header(rb, "accept-encoding", "identity");
        }
        if let Some((s, e)) = range {
            rb = apply_header(rb, "range", &format!("bytes={s}-{e}"));
        }
        if let Some(referer) = &ctx.referer {
            rb = apply_header(rb, "referer", referer);
        }
        if let Some(ua) = &ctx.user_agent {
            rb = apply_header(rb, "user-agent", ua);
        }
        for (name, value) in &ctx.headers {
            if !keep_credentials && is_credential_header(name) {
                continue;
            }
            rb = apply_header(rb, name, value);
        }
        if keep_credentials && extra_auth.is_none() {
            // Basic pre-set; when the 401 challenge-answer header
            // (extra_auth) is present, it owns Authorization exclusively
            // — two values in one header would let the server read the
            // pre-set Basic (reqwest appends same-name headers) and the
            // challenge answer would never verify.
            if let Some(AuthScheme::Basic { user, passwd }) = &ctx.auth {
                rb = rb.basic_auth(user, Some(passwd));
            }
        }
        let mut cookie_parts: Vec<String> = Vec::new();
        if keep_credentials {
            for (n, v) in &ctx.cookies {
                cookie_parts.push(format!("{n}={v}"));
            }
        }
        if let Some(jar_cookies) = self.jar.header_for(url) {
            cookie_parts.push(jar_cookies);
        }
        // Task-store cookies are layered under cross-host credential
        // stripping (task cookie surface): explicit cookie pairs /
        // credential headers are still stripped; store cookies are
        // bounded by domain matching on replay, and Secure entries are
        // suppressed by `header_for` on non-https targets (no Secure
        // cookie on an https->http downgrade).
        if let Some(store) = &ctx.task_cookies
            && let Some(v) = store.header_for(url)
        {
            cookie_parts.push(v);
        }
        if !cookie_parts.is_empty() {
            rb = apply_header(rb, "cookie", &cookie_parts.join("; "));
        }
        // The 401 challenge-answer header (Digest/Basic re-answer)
        // overrides the pre-set Basic — the value produced by the auth
        // layer is this hop's single Authorization fact.
        if let Some(value) = extra_auth {
            rb = apply_header(rb, "authorization", value);
        }
        rb
    }

    /// 401 challenge-answer decision (returns `Some(auth)` = resend the
    /// same URL request with that Authorization).
    ///
    /// - Credentials absent (`ctx.auth` None) or already stripped
    ///   cross-host -> `None`: the 401 is re-raised as-is (the probe
    ///   layer's classification semantics unchanged);
    /// - Digest challenge -> [`auth::respond_digest`] (exactly once per
    ///   URL, a further 401 = [`HttpError::AuthFailed`]); exception: a
    ///   challenge carrying `stale=true` (RFC 7616 §3.6 — only the
    ///   nonce expired, the credentials themselves were verified) ->
    ///   one re-answer allowed, at most once per URL (the
    ///   `stale_retried` gate; a second stale is still AuthFailed);
    /// - Basic challenge: `AuthScheme::Basic` was already pre-sent (a
    ///   resend with the same credentials is pointless) -> AuthFailed;
    ///   `AuthScheme::Digest` credentials meeting a Basic challenge ->
    ///   answer with the pre-set Basic once;
    /// - Unrecognized challenge -> `None` (re-raised as-is).
    ///
    /// Multiple challenges in one header (RFC 9110 §11.6.1 `#challenge`)
    /// are merged segment by segment through
    /// [`auth::parse_www_authenticate`]'s list parsing into the same
    /// selection.
    #[expect(
        clippy::too_many_arguments,
        reason = "the 401 face carries the full challenge context explicitly; the arity is the seam contract"
    )]
    fn on_unauthorized(
        &self,
        url: &Url,
        ctx: &RequestCtx,
        headers: &HeaderMap,
        keep_credentials: bool,
        answered: &mut HashSet<(String, String, u16, String)>,
        stale_retried: &mut HashSet<(String, String, u16, String)>,
        nonce_nc: &mut HashMap<String, u32>,
    ) -> Result<Option<String>, HttpError> {
        let Some(scheme) = &ctx.auth else {
            return Ok(None);
        };
        if !keep_credentials {
            return Ok(None);
        }
        let creds = Credentials::from_scheme(scheme);
        let key = loop_key(url);

        // Challenge selection: Digest preferred (RFC 7616), Basic
        // fallback. Multiple segments in one header merge segment by
        // segment (later-seen overrides earlier-seen, matching the
        // existing single-challenge behavior).
        let mut digest: Option<auth::DigestChallenge> = None;
        let mut basic = false;
        for value in headers.get_all(header::WWW_AUTHENTICATE) {
            let text = String::from_utf8_lossy(value.as_bytes());
            for challenge in auth::parse_www_authenticate(&text) {
                match challenge {
                    Challenge::Digest(c) => digest = Some(c),
                    Challenge::Basic => basic = true,
                }
            }
        }

        if let Some(c) = digest {
            let first_answer = answered.insert(key.clone());
            // stale=true renegotiation gate (RFC 7616 §3.6 SHOULD
            // retry): only the nonce expired (credentials verified) ->
            // allow exactly one re-answer.
            let stale_retry = !first_answer && c.stale && stale_retried.insert(key);
            if !first_answer && !stale_retry {
                return Err(HttpError::AuthFailed(
                    "digest challenge rejected the answered credentials".into(),
                ));
            }
            let nonce = c.nonce.clone().unwrap_or_default();
            let nc = nonce_nc.entry(nonce).or_insert(0);
            *nc = nc.saturating_add(1);
            // Request target = path (including query, matching the
            // request line — RFC 7616's `uri` parameter definition).
            let target = match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_string(),
            };
            let value = auth::respond_digest(&c, &creds, &target, *nc, &auth::fresh_cnonce())?;
            return Ok(Some(value));
        }
        if basic {
            if let AuthScheme::Basic { .. } = scheme {
                // Basic was pre-sent on the first hop: resending the
                // same credentials cannot flip the result -> fail
                // explicitly (no wasted round trips).
                return Err(HttpError::AuthFailed(
                    "server rejected basic credentials".into(),
                ));
            }
            if !answered.insert(key.clone()) {
                return Err(HttpError::AuthFailed(
                    "basic challenge rejected the answered credentials".into(),
                ));
            }
            let raw = format!("{}:{}", creds.user, creds.passwd);
            return Ok(Some(format!("Basic {}", base64_std(raw.as_bytes()))));
        }
        Ok(None)
    }
}

/// Standard base64 (used only for the Digest Basic challenge answer;
/// alphabet = STD with padding. Self-contained, no new dependency —
/// credential sizes are tiny, performance irrelevant).
fn base64_std(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// 3xx following surface (GET keeps its method; no POST surface).
fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

/// Per-response echo validation for 206s of ranged requests
/// (cross-checked against aria2 `HttpResponse.cc` validateResponse +
/// `HttpRequest.cc` isRangeSatisfied) — the echoed start must equal the
/// requested start: a misaligned range would silently corrupt the file
/// within the body bounds; the start is the single point of evidence
/// for data alignment and this dimension is **never relaxed**.
/// Missing / unparseable / non-bytes units are all rejected.
///
/// **Length dimension relaxed**: the echoed end is no longer required
/// to equal the requested end — for a 206 whose start matches, a body
/// length (Content-Length or the chunked final length) differing from
/// the requested remainder is a length deviation, not a protocol
/// contradiction: over-shoot (echo/body longer than requested) is
/// handled by the data-plane read loop taking the amount it needs and
/// closing (extra body discarded, connection closed early); under-shoot
/// (EOF before the requested end) books the bytes already read as
/// partial progress and the unsatisfied remainder goes through the
/// existing retry path. The fast-fail philosophy for deterministic
/// contradictions is unchanged: a start mismatch still fails fast with
/// [`HttpError::BadRange`]. The probe decision table is unaffected by
/// this relaxation — for probe requests `bytes=0-0`, an end-deviating
/// echo is still rejected by the probe layer's own table
/// ([`crate::probe::classify`]) as a `Partial` shape (`BadRange`).
///
/// A total echo must satisfy total > end (the `bytes 0-0/0`
/// pathological shape is in the same family); `*` (no total) passes —
/// total-length authority belongs to the probe/merge layers; the
/// transport layer does not overstep into length judgments.
fn validate_range_echo(headers: &reqwest::header::HeaderMap, start: u64) -> Result<(), HttpError> {
    let echo = headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::probe::parse_content_range);
    match echo {
        Some(crate::probe::ContentRange::Partial {
            start: echo_start,
            end: echo_end,
            total,
        }) if echo_start == start => {
            if total.is_some_and(|t| t <= echo_end) {
                return Err(HttpError::BadRange);
            }
            Ok(())
        }
        _ => Err(HttpError::BadRange),
    }
}

/// reqwest DNS adapter, a **zero-logic thin shell**: the orphan rule
/// requires `impl reqwest::dns::Resolve` to live in the same crate as
/// the type, so all bridging logic is single-sourced in taiji-io
/// `SharedDns::resolve_for_transport` — this shell only calls the
/// bridge function and converts types, with no branching (logic growing
/// in the shell is the design-guard signal to re-open the wiring
/// approach). The process-level default instance is wired via
/// [`SharedDns::shared_default`] (TTL cache + 30s resolve timeout +
/// cache shared with the BT tracker surface; behavior described in the
/// taiji-io `dns` module docs). **Not part of the [`ClientConfig`]
/// bucket key**: the resolver is process-level wiring, not task
/// configuration (equal-config tasks still share transport instances —
/// [`SHARED_CLIENTS`] bucketing regression-locked).
struct DnsAdapter(std::sync::Arc<SharedDns>);

impl reqwest::dns::Resolve for DnsAdapter {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let dns = self.0.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port always passed as 0: hyper-util completes a port 0 in
            // resolver results per scheme convention / overrides it with
            // the explicit URL port (cache entries hold only IpAddr; the
            // port is synthesized by hyper-util, nothing carries it).
            match dns.resolve_for_transport(&host, 0).await {
                Ok(addrs) => Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs),
                Err(e) => Err(taiji_io::dns::box_resolve_error(e)),
            }
        })
    }
}

/// Transport instance construction (shared by data/probe planes; the
/// `auto_decompress` semantic difference is in the [`HttpClient`] struct
/// docs). Manual redirects, timeouts, and pool settings identical item
/// by item. `metrics` = the registry wiring for the connection-timing
/// layer (not part of [`ClientConfig`] — observability wiring, not
/// transport configuration, bucket key unchanged; see the
/// [`HttpClient::metrics`] note).
fn build_transport(
    cfg: &ClientConfig,
    auto_decompress: bool,
    metrics: &Arc<MetricsRegistry>,
) -> Result<Client, HttpError> {
    // TLS provider: the workspace TLS stack is uniformly ring — with the
    // rustls-no-provider setup, every reqwest build point reads the
    // process-level default at build; the idempotent installer lives
    // in taiji-io (the bt/http common base; the tracker client shares
    // it).
    taiji_io::tls::install_ring_provider_default();
    let mut builder = Client::builder()
        // DNS surface: process-level shared resolver service (the
        // resolver is not part of ClientConfig — bucket key unchanged,
        // see the [`DnsAdapter`] note).
        .dns_resolver(Arc::new(DnsAdapter(SharedDns::shared_default())))
        .user_agent(cfg.user_agent.clone())
        // Manual redirects: reqwest does not follow; the loop is controlled in this layer.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(cfg.connect_timeout)
        .read_timeout(cfg.read_timeout)
        .pool_idle_timeout(cfg.pool_idle_timeout)
        // Connection-profile observation (pool reuse bypasses the
        // connector — the count naturally covers fresh connects only;
        // the combined DNS+TCP+TLS timing and the DNS-component
        // deduction rule are in the [`crate::conn_timing`] module
        // docs). The layer sits below connect_timeout (reqwest wraps the
        // user connect_timeout as the outermost connector layer); the
        // resolver/pinning table live in the base connector below this
        // layer, so pinning stacking semantics are unchanged. Data/probe
        // instances feed at the same layer and share one registry.
        .connector_layer(crate::conn_timing::ConnTimingLayer::new(Arc::clone(
            metrics,
        )));
    // DNS pinning (the media SSRF connection-pin face;
    // also the wire-cross-validation surface): keys matched lowercase
    // per reqwest normalization. reqwest's overrides layer wraps **above**
    // the injected resolver (`DnsResolverWithOverrides` checks the pin
    // table first and only falls through to [`DnsAdapter`] on a miss) —
    // pinning semantics stack unchanged with the custom resolver in
    // place (locked by wire cross-validation).
    for (host, addr) in &cfg.pinned_resolve {
        builder = builder.resolve(host, *addr);
    }
    // Proxy surface (`--all-proxy` + `--https-proxy` as scheme-split
    // slots): the scheme value range is validated at option parsing;
    // here only http/https proxy URLs are accepted (auth travels via
    // URL userinfo, carried by reqwest). socks5(h) needs the reqwest
    // `socks` feature (not enabled; rejected explicitly at parsing).
    //
    // Registration order = **dedicated slot before the global slot**:
    // reqwest evaluates multiple proxies first-match-wins by
    // registration order (the proxy-selection loop in its `connect.rs`
    // takes the first hit `intercept`), and the `Proxy::https` matcher
    // only intercepts https targets — https targets are captured by
    // the dedicated slot, every other scheme falls to the global slot
    // (precedence "dedicated slot > --all-proxy"). With only one slot
    // configured, the other simply never registers (semantics
    // unchanged).
    if let Some(https_proxy_url) = &cfg.proxy_https {
        let proxy = reqwest::Proxy::https(https_proxy_url)
            .map_err(|e| HttpError::Transport(format!("invalid proxy url: {e}")))?;
        builder = builder.proxy(proxy);
    }
    if let Some(proxy_url) = &cfg.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| HttpError::Transport(format!("invalid proxy url: {e}")))?;
        builder = builder.proxy(proxy);
    }
    // `--check-certificate=false` surface (default false = verification on).
    builder = builder.danger_accept_invalid_certs(cfg.accept_invalid_certs);
    // Task-level CA surface (`--ca-certificate`): with verification on
    // and a path present, the transport roots = the file's CAs
    // (`tls_certs_only` replaces the platform trust store — aria2
    // replacement semantics, not append). Precedence =
    // `--check-certificate=false` wins: verification is already off, so
    // the CA file is ignored unread (same semantics as aria2).
    // Loading / PEM parse failure = client build error (never silently
    // allowed through).
    if let Some(path) = cfg
        .ca_cert_path
        .as_ref()
        .filter(|_| !cfg.accept_invalid_certs)
    {
        let certs = load_ca_certificates_der(path)?
            .iter()
            .map(|der| reqwest::Certificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| HttpError::Transport(format!("ca certificate: {e}")))?;
        builder = builder.tls_certs_only(certs);
    }
    // Client mTLS face (`--certificate` + `--private-key`): the two PEM
    // files -> reqwest `Identity::from_pem` (it scans a single buffer for
    // the private key + certificate sections — the two PEM streams are
    // concatenated and parsed by it, section order irrelevant). One side
    // given = a build error (explicit refusal, not a silent run without
    // identity — a TLS client identity with half of it missing fails at
    // the handshake for sure; expose that early at build time). A
    // concurrent `--check-certificate=false` does not waive this face:
    // identity is "who I am", not "whom to trust" (a server with
    // verification off + a client still proving itself is a legitimate
    // scenario — the aria2 two options are orthogonal in the same way).
    if cfg.identity_cert_path.is_some() || cfg.identity_key_path.is_some() {
        let (cert_path, key_path) = match (
            cfg.identity_cert_path.as_ref(),
            cfg.identity_key_path.as_ref(),
        ) {
            (Some(c), Some(k)) => (c, k),
            _ => {
                return Err(HttpError::Transport(
                    "client certificate and private key must be given together \
                     (--certificate / --private-key)"
                        .to_string(),
                ));
            }
        };
        let identity_pem = load_client_identity_pem(cert_path, key_path)?;
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .map_err(|e| HttpError::Transport(format!("client identity: {e}")))?;
        builder = builder.identity(identity);
    }
    // TLS minimum-version face (`--min-tls-version`): None = the engine
    // default (the platform/rustls policy is not tightened — the
    // zero-behavior-change anchor). `tls_version_min` = the reqwest 0.13
    // non-deprecated name (`min_tls_version` is the deprecated alias, not
    // used).
    if let Some(v) = cfg.min_tls_version {
        builder = builder.tls_version_min(v.to_reqwest());
    }
    // Protocol shape (`--http-protocol`): Auto = status quo (reqwest's
    // default already advertises h2+http/1.1 via ALPN); Http1 = upgrade
    // path shut; Http2 = prior knowledge (plaintext h2c, no fallback —
    // experimental, semantics in [`HttpProtocol`]).
    builder = match cfg.http_protocol {
        HttpProtocol::Auto => builder,
        HttpProtocol::Http1 => builder.http1_only(),
        HttpProtocol::Http2 => builder.http2_prior_knowledge(),
    };
    // h2 flow-control windows (experimental): both default to the engine
    // defaults (stream 8MiB / connection 16MiB — the DEFAULT_H2_*
    // constants); adaptive stays off. Explicit values (option surface)
    // and None (the programmatic control path = hyper's library
    // defaults) both override; rate-limit backpressure semantics are
    // unchanged (flow-control waits stay excluded from stall
    // detection).
    if cfg.http2_adaptive_window {
        builder = builder.http2_adaptive_window(true);
    }
    if let Some(w) = cfg.http2_stream_window {
        builder = builder.http2_initial_stream_window_size(w);
    }
    if let Some(w) = cfg.http2_connection_window {
        builder = builder.http2_initial_connection_window_size(w);
    }
    // h2 PING keep-alive (experimental): default off = hyper status quo;
    // an explicit interval enables liveness probes, timeout = 2x the
    // interval (fixed internally — one lost PING round trip declares
    // death instead of waiting for the read timeout). while_idle must be
    // on: with reqwest/hyper's default false, idle connections are never
    // pinged (the ping scheduler returns early on
    // `!while_idle && is_idle`) — pooled idle connections would never be
    // probed and "idle-pool liveness probing" would be entirely void;
    // wire evidence in tests/h2_mock.rs (removing this flag turns it
    // red).
    if let Some(d) = cfg.http2_keep_alive_interval.filter(|d| !d.is_zero()) {
        builder = builder
            .http2_keep_alive_interval(d)
            .http2_keep_alive_timeout(d * 2)
            .http2_keep_alive_while_idle(true);
    }
    // The probe plane must turn auto-decompression off: reqwest (gzip
    // feature on by default) strips Content-Encoding/Content-Length when
    // it decompresses, blinding the probe decision table.
    builder
        .gzip(auto_decompress)
        .build()
        .map_err(|e| HttpError::Transport(error_chain(&e.without_url())))
}

/// Credential survival decision (monotonic AND): credentials survive
/// only if they survived the previous hop **and** the adjacent hops
/// share a scope — equivalent to a monotonic AND against the first-hop
/// scope, but implemented with an adjacent comparison and one boolean.
/// Once cross-host stripping happened, a "same-host self-hop" must not
/// revive credentials (a plain adjacent-hop overwrite assignment let
/// A->B->B' revive the origin credentials).
fn credentials_survive_hop(kept: bool, prev: &Url, next: &Url) -> bool {
    kept && credential_scope(prev) == credential_scope(next)
}

/// CA file loading (the single load point for the `--ca-certificate`
/// option value; the HTTP surface consumes it via
/// [`ClientConfig::ca_cert_path`] at transport build time, the FTP
/// surface feeds a DER snapshot from taiji-core option parsing into
/// `FtpConfig::extra_ca_certs_der` — both consumers express the
/// replacement semantics at their own root-wiring points: roots are
/// replaced, not appended).
///
/// Value range = PEM (`CERTIFICATE` sections, possibly several — same
/// rule as aria2 `--ca-certificate` "must be in PEM format"; bare
/// DER/other encodings are not accepted). Returns the DER sequence. An
/// unreadable file / no `CERTIFICATE` section / PEM parse failure =
/// `Err` — mapped to a `taiji.option.invalid` task rejection at the
/// option layer and to a client build error at the build layer; never
/// silently allowed through at either point.
pub fn load_ca_certificates_der(path: &std::path::Path) -> Result<Vec<Vec<u8>>, HttpError> {
    let bytes = std::fs::read(path)
        .map_err(|e| HttpError::Transport(format!("ca certificate {}: {e}", path.display())))?;
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    if !bytes.windows(BEGIN.len()).any(|w| w == BEGIN) {
        return Err(HttpError::Transport(format!(
            "ca certificate {}: PEM 'CERTIFICATE' section required \
             (aria2 parity; DER/other encodings not accepted)",
            path.display()
        )));
    }
    let ders: Vec<Vec<u8>> = pem_certificate_slice(&bytes)
        .map_err(|e| HttpError::Transport(format!("ca certificate {}: {e}", path.display())))?;
    if ders.is_empty() {
        return Err(HttpError::Transport(format!(
            "ca certificate {}: no certificate found in PEM",
            path.display()
        )));
    }
    Ok(ders)
}

/// PEM byte stream -> `CERTIFICATE`-section DER sequence (pki-types
/// `pem` surface; corrupt base64 inside a section surfaces as an
/// iteration error, no matching section = an empty vec for the caller
/// to decide on).
fn pem_certificate_slice(
    pem: &[u8],
) -> Result<Vec<Vec<u8>>, suppaftp::rustls::pki_types::pem::Error> {
    use suppaftp::rustls::pki_types::CertificateDer;
    CertificateDer::pem_slice_iter(pem)
        .map(|r| r.map(|cert| cert.as_ref().to_vec()))
        .collect()
}

/// Client mTLS identity loading (the single load point for
/// `--certificate` + `--private-key`; the HTTP surface consumes it via
/// [`ClientConfig::identity_cert_path`]/[`identity_key_path`] at
/// transport build time).
///
/// Value range = PEM: the certificate file must contain a `CERTIFICATE`
/// section, the key file a private key section (PKCS#8 `PRIVATE KEY` /
/// `RSA PRIVATE KEY` / `EC PRIVATE KEY`, any of the three — the reqwest
/// `Identity::from_pem` value range). Returns the **concatenated PEM**
/// (key first, certificate after — `Identity::from_pem` scans a single
/// buffer for section types, order irrelevant; the order follows the
/// keychain-listing convention of reading naturally). Either file
/// unreadable / the required section missing = `Err` — the build surface
/// maps it to a client build error, never silently allowed through. Key
/// bytes only flow through this function's memory; error messages contain
/// no file content (only the path and the failure stage).
pub fn load_client_identity_pem(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<Vec<u8>, HttpError> {
    use suppaftp::rustls::pki_types::PrivateKeyDer;
    let cert_bytes = std::fs::read(cert_path).map_err(|e| {
        HttpError::Transport(format!("client certificate {}: {e}", cert_path.display()))
    })?;
    let key_bytes = std::fs::read(key_path).map_err(|e| {
        HttpError::Transport(format!("client private key {}: {e}", key_path.display()))
    })?;
    // Section-presence precheck (fail-fast, pinpointing the specific
    // file; deep parsing belongs to Identity::from_pem — the X.509/key
    // structure is adjudicated at the reqwest build surface).
    let has_cert = has_certificate_section(&cert_bytes);
    let key_ok = PrivateKeyDer::pem_slice_iter(&key_bytes).next().is_some();
    if !has_cert {
        return Err(HttpError::Transport(format!(
            "client certificate {}: PEM 'CERTIFICATE' section required",
            cert_path.display()
        )));
    }
    if !key_ok {
        return Err(HttpError::Transport(format!(
            "client private key {}: PEM private key section required \
             (PRIVATE KEY / RSA PRIVATE KEY / EC PRIVATE KEY)",
            key_path.display()
        )));
    }
    let mut out = key_bytes;
    out.extend_from_slice(&cert_bytes);
    Ok(out)
}

/// `CERTIFICATE` section start-marker scan (the
/// [`load_client_identity_pem`] precheck face; the same byte-window
/// comparison as the BEGIN sentinel in [`load_ca_certificates_der`]).
fn has_certificate_section(bytes: &[u8]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    bytes.windows(BEGIN.len()).any(|w| w == BEGIN)
}

/// Loop detection key: (scheme, host lowercased, port default-normalized,
/// path). Query is not part of the key — query is not resource identity;
/// query-variant loops reject as RedirectLoop.
fn loop_key(url: &Url) -> (String, String, u16, String) {
    (
        url.scheme().to_ascii_lowercase(),
        url.host_str().unwrap_or("").to_ascii_lowercase(),
        url.port_or_known_default().unwrap_or(0),
        url.path().to_string(),
    )
}

/// Drain a 3xx hop response body (up to [`MAX_REDIRECT_DRAIN_BYTES`]):
/// reading to EOF returns the connection to the pool; past the cap / on
/// error, give up (Response drop closes the connection). The drain never
/// blocks the hop.
async fn drain_redirect_body(resp: &mut reqwest::Response) {
    let mut drained: u64 = 0;
    while drained < MAX_REDIRECT_DRAIN_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => drained += chunk.len() as u64,
            Ok(None) => return,
            Err(e) => {
                let msg = error_chain(&e.without_url());
                tracing::debug!(
                    target: "taiji::http::client",
                    error = %msg,
                    "redirect body drain aborted; connection dropped"
                );
                return;
            }
        }
    }
    tracing::debug!(
        target: "taiji::http::client",
        cap = MAX_REDIRECT_DRAIN_BYTES,
        "redirect body exceeds drain cap; connection dropped"
    );
}

/// https->http downgrade detection (adjacent-hop comparison; rejected by default).
fn is_https_to_http_downgrade(current: &Url, next: &Url) -> bool {
    current.scheme().eq_ignore_ascii_case("https") && next.scheme().eq_ignore_ascii_case("http")
}

/// Credential scope key: (scheme, host, port-with-default). Credentials
/// survive only when all three match.
fn credential_scope(url: &Url) -> Option<(String, String, u16)> {
    Some((
        url.scheme().to_ascii_lowercase(),
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default().unwrap_or(0),
    ))
}

/// Credential-class header check (lowercase comparison).
fn is_credential_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    CREDENTIAL_HEADERS.contains(&lower.as_str())
}

/// Apply a request header; an invalid name/value (control characters
/// etc.) is dropped with a warning — the user configuration surface
/// must not become an injection / request-failure surface.
fn apply_header(rb: reqwest::RequestBuilder, name: &str, value: &str) -> reqwest::RequestBuilder {
    match (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        (Ok(n), Ok(v)) => rb.header(n, v),
        _ => {
            tracing::warn!(
                target: "taiji::http::client",
                header = %redact_str(name),
                "dropping invalid outbound header"
            );
            rb
        }
    }
}

/// Outbound URL log shape: scheme://host/path (userinfo/query stripped).
fn redact(url: &Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or("?"),
        url.path()
    )
}

/// URL log shape + verbatim gate (unified across protocols): default =
/// the [`redact`] stripped form; `--log-verbatim-urls` (the
/// `taiji_io::redact` process-level switch, shared with the BT
/// tracker/webseed surface) on = verbatim (full query, credentials
/// included — local deep diagnostics only; sanitize before sharing
/// logs). Every URL log point on this surface goes through here.
fn redact_or_verbatim(url: &Url) -> String {
    if taiji_io::redact::url_log_verbatim() {
        url.to_string()
    } else {
        redact(url)
    }
}

fn redact_str(s: &str) -> impl std::fmt::Display + '_ {
    // Header names are already a restricted charset; this only routes logs through redact.
    s.split(['?', '#']).next().unwrap_or("")
}

/// reqwest error -> engine error (URL stripped + error chain expanded;
/// no URL means no query/credential leak surface). **Classification
/// seam**: before the reqwest error chain is flattened into
/// `Transport(String)`, it is mapped single-sourced through
/// [`taiji_io::dns::classify_error_chain`] (type downcast first + text
/// fallback + reqwest kind hints) into `taiji_http_errors_total{class}`;
/// **permanent** DNS failures (NXDOMAIN-class) are carried typed as
/// [`HttpError::DnsPermanent`] (retry semantics cross-checked against
/// aria2 `NAME_RESOLVE_ERROR` direct failure, `AbstractCommand.cc`) —
/// the code surface is unchanged (string code same as
/// `taiji.http.transport`). `Other` is not counted.
fn transport_err_counted(metrics: &taiji_io::metrics::HttpMetrics, e: reqwest::Error) -> HttpError {
    let stripped = e.without_url();
    let class = taiji_io::dns::classify_error_chain(
        taiji_io::dns::TransportHints {
            connect: stripped.is_connect(),
            timeout: stripped.is_timeout(),
        },
        &stripped,
    );
    if let Some(metric) = taiji_io::metrics::http_error_class_of(class) {
        metrics.note_error(metric);
    }
    http_error_of_class(class, error_chain(&stripped))
}

/// Class -> engine error variant (the classification seam's landing):
/// **permanent** DNS failures are carried typed (retry semantics —
/// consumed by [`crate::retry::transport_retryable`]); all other
/// classes keep the existing `Transport` shape (payload = error chain
/// text, redact discipline unchanged).
fn http_error_of_class(class: taiji_io::dns::TransportErrorClass, text: String) -> HttpError {
    match class {
        taiji_io::dns::TransportErrorClass::Dns(taiji_io::dns::DnsPersistence::Permanent) => {
            HttpError::DnsPermanent(text)
        }
        _ => HttpError::Transport(text),
    }
}

/// reqwest error -> engine error (the classification seam at the
/// process-default registry wiring point; isolated registries injected
/// via [`HttpClient`] go through [`transport_err_counted`]).
fn transport_err(e: reqwest::Error) -> HttpError {
    transport_err_counted(registry_default().http(), e)
}

/// Public wiring point for the streaming body read path (the same seam
/// as [`transport_err`]): the body-read map_err lives in the core
/// consumer (the per-read loop of the `http_task` fetch) — the error
/// **chain** text is the payload domain of the
/// [`crate::aimd::CongestionKind::Reset`] discrimination (a mid-body RST
/// from the peer must be detectable; reqwest's top-level Display lacks
/// the chain, so a flat `to_string` is not discriminable).
pub fn transport_error(e: reqwest::Error) -> HttpError {
    transport_err(e)
}

/// Expand an error chain into single-line text (for logs / error messages).
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap_or_else(|e| panic!("url {s}: {e}"))
    }

    /// HTTP download surface's URL log verbatim gate — the same switch
    /// source as the BT side (tracker/webseed; the `taiji_io::redact`
    /// process-level switch). Off = stripped form (scheme://host/path);
    /// on = verbatim (full query, credentials included). Reset at phase
    /// end (process-level global).
    #[test]
    fn redact_or_verbatim_phase() {
        let u = url("https://h.example/p/file.bin?token=sekrit");
        taiji_io::redact::set_url_log_verbatim(false);
        assert_eq!(redact_or_verbatim(&u), "https://h.example/p/file.bin");
        taiji_io::redact::set_url_log_verbatim(true);
        assert_eq!(
            redact_or_verbatim(&u),
            "https://h.example/p/file.bin?token=sekrit"
        );
        taiji_io::redact::set_url_log_verbatim(false);
    }

    #[test]
    fn redirect_statuses_and_hop_defaults() {
        for s in [301, 302, 303, 307, 308] {
            assert!(is_redirect(
                StatusCode::from_u16(s).unwrap_or(StatusCode::OK)
            ));
        }
        for s in [200, 206, 304, 404, 416] {
            assert!(!is_redirect(
                StatusCode::from_u16(s).unwrap_or(StatusCode::OK)
            ));
        }
        assert_eq!(ClientConfig::default().max_redirects, 20);
        assert!(!ClientConfig::default().allow_insecure_downgrade);
        assert_eq!(
            ClientConfig::default().user_agent,
            format!("taiji/{}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn credential_scope_covers_scheme_host_port() {
        let a = credential_scope(&url("http://example.com/path?q=1"));
        let b = credential_scope(&url("http://example.com:80/other"));
        assert_eq!(a, b); // default port normalized

        let https = credential_scope(&url("https://example.com/"));
        assert_ne!(a, https); // scheme change = cross-scope (a downgrade strips credentials)

        let other_host = credential_scope(&url("http://mirror.example.com/"));
        assert_ne!(a, other_host);

        let other_port = credential_scope(&url("http://example.com:8080/"));
        assert_ne!(a, other_port);

        // No host (data: etc.) -> no scope (comparisons are unequal; conservatively stripped).
        assert_eq!(credential_scope(&url("data:text/plain,hi")), None);
    }

    #[test]
    fn downgrade_detection() {
        assert!(is_https_to_http_downgrade(
            &url("https://a.example/x"),
            &url("http://a.example/x")
        ));
        assert!(!is_https_to_http_downgrade(
            &url("http://a.example/x"),
            &url("https://a.example/x")
        ));
        assert!(!is_https_to_http_downgrade(
            &url("https://a.example/x"),
            &url("https://b.example/x")
        ));
    }

    #[test]
    fn credential_header_classification() {
        assert!(is_credential_header("Authorization"));
        assert!(is_credential_header("COOKIE"));
        assert!(is_credential_header("cookie2"));
        assert!(is_credential_header("Proxy-Authorization"));
        assert!(!is_credential_header("x-custom"));
        assert!(!is_credential_header("authorizationx"));
    }

    /// Credential stripping monotonicity: once cross-host stripping
    /// happened, neither a same-host self-hop nor a hop back into the
    /// first-hop scope may recompute keep back to true.
    #[test]
    fn credential_strip_is_monotonic_across_hops() {
        let origin = url("https://origin.example/x");
        let evil = url("https://evil.example/hop");
        let evil_prime = url("https://evil.example/hop2"); // same-host self-hop
        let origin_again = url("https://origin.example/back");

        // A->B cross-host -> stripped.
        let kept = credentials_survive_hop(true, &origin, &evil);
        assert!(!kept);
        // B->B' same-host self-hop -> must not revive.
        assert!(!credentials_survive_hop(kept, &evil, &evil_prime));
        // B'->A back into the first-hop scope -> still must not revive.
        assert!(!credentials_survive_hop(kept, &evil_prime, &origin_again));

        // Control: without stripping, a same-host hop keeps credentials.
        assert!(credentials_survive_hop(true, &evil, &evil_prime));

        // Plaintext downgrade allowed (allow_insecure_downgrade=true):
        // after https->http strips by scheme change, an http->http
        // same-host hop does not revive.
        let secure = url("https://origin.example/x");
        let plain = url("http://origin.example/x");
        let kept = credentials_survive_hop(true, &secure, &plain);
        assert!(!kept);
        assert!(!credentials_survive_hop(kept, &plain, &plain));
    }

    /// Hostname normalization dimensions of the credential scope:
    /// case / explicit default port / IDN (punycode) / IPv6 forms are
    /// equivalent on the scope key.
    #[test]
    fn credential_scope_normalization_dimensions() {
        assert_eq!(
            credential_scope(&url("http://EXAMPLE.test:80/x")),
            credential_scope(&url("http://example.test/x"))
        );
        assert_eq!(
            credential_scope(&url("http://пример.test/x")),
            credential_scope(&url("http://xn--e1afmkfd.test:80/x"))
        );
        assert_eq!(
            credential_scope(&url("http://[0:0:0:0:0:0:0:1]:8080/x")),
            credential_scope(&url("http://[::1]:8080/x"))
        );
    }

    /// Loop detection key: query is not in the key (query-variant loops
    /// reject as loops); path/scheme/host changes remain distinguishable.
    #[test]
    fn loop_key_ignores_query_and_normalizes_host() {
        assert_eq!(
            loop_key(&url("http://a.example/x?i=1")),
            loop_key(&url("http://A.example:80/x?i=2"))
        );
        assert_ne!(
            loop_key(&url("http://a.example/x")),
            loop_key(&url("http://a.example/y"))
        );
        assert_ne!(
            loop_key(&url("http://a.example/x")),
            loop_key(&url("https://a.example/x"))
        );
    }

    #[test]
    fn whatwg_url_relative_location_resolution() {
        // The url crate implements the WHATWG URL standard; `join` is
        // its reference-resolution algorithm (dot segments / relative /
        // protocol-relative).
        let base = url("https://cdn.example.com/dir/page");
        assert_eq!(
            base.join("file.bin")
                .unwrap_or_else(|e| panic!("{e}"))
                .as_str(),
            "https://cdn.example.com/dir/file.bin"
        );
        assert_eq!(
            base.join("../up.bin")
                .unwrap_or_else(|e| panic!("{e}"))
                .as_str(),
            "https://cdn.example.com/up.bin"
        );
        assert_eq!(
            base.join("/abs.bin")
                .unwrap_or_else(|e| panic!("{e}"))
                .as_str(),
            "https://cdn.example.com/abs.bin"
        );
        assert_eq!(
            base.join("//other.example.com/x")
                .unwrap_or_else(|e| panic!("{e}"))
                .as_str(),
            "https://other.example.com/x"
        );
        assert_eq!(
            base.join("?q=2").unwrap_or_else(|e| panic!("{e}")).as_str(),
            "https://cdn.example.com/dir/page?q=2"
        );
        // An absolute URL overrides the base.
        assert_eq!(
            base.join("http://plain.example/f")
                .unwrap_or_else(|e| panic!("{e}"))
                .as_str(),
            "http://plain.example/f"
        );
    }

    /// Header name/value injection surface: invalid headers are dropped
    /// rather than failing construction.
    #[tokio::test]
    async fn invalid_headers_dropped_on_build() {
        let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
        let ctx = RequestCtx {
            headers: vec![
                ("x-good".into(), "1".into()),
                ("bad header".into(), "1".into()), // space -> illegal name
                ("x-bad".into(), "bad\nvalue".into()), // CRLF -> illegal value
            ],
            ..RequestCtx::default()
        };
        // Sending to an unreachable address fails, but the build path (header filter) must work.
        let res = client.get("http://127.0.0.1:1/unreachable", &ctx).await;
        assert!(matches!(res, Err(HttpError::Transport(_))));
    }

    /// https->http downgrade rejected by default (no wire-level TLS
    /// dependency here: the predicate function plus the allow switch's
    /// configuration semantics are under test; wire-level loop detection
    /// lives in tests/).
    #[test]
    fn downgrade_config_semantics() {
        let mut cfg = ClientConfig::default();
        assert!(!cfg.allow_insecure_downgrade);
        cfg.allow_insecure_downgrade = true;
        assert!(cfg.allow_insecure_downgrade);
    }

    /// Protocol shape switch: default Auto (the status quo anchor);
    /// transport instances build for all three values (builder branches —
    /// wire-level assertions for negotiation/fallback/h2c live in
    /// tests/h2_mock.rs).
    #[test]
    fn http_protocol_default_and_builder_branches() {
        assert_eq!(ClientConfig::default().http_protocol, HttpProtocol::Auto);
        for protocol in [HttpProtocol::Auto, HttpProtocol::Http1, HttpProtocol::Http2] {
            let cfg = ClientConfig {
                http_protocol: protocol,
                ..ClientConfig::default()
            };
            let client = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
            // The cheap-clone sharing convention holds under every switch value.
            let _clone = client.clone();
        }
    }

    /// h2 flow-control windows: default = the status quo anchor (adaptive
    /// off, both windows = engine defaults 8MiB/16MiB —
    /// Some(DEFAULT_H2_*), not None); transport instances build at the
    /// value-range ceiling (RFC 7540 §5.2.2 window cap 2^31-1) and with
    /// adaptive alone on. Wire-level advertisement assertions live in
    /// tests/h2_mock.rs.
    #[test]
    fn http2_window_options_default_and_bounds() {
        let dflt = ClientConfig::default();
        assert!(!dflt.http2_adaptive_window);
        // Default = engine defaults 8MiB/16MiB (static windows).
        assert_eq!(dflt.http2_stream_window, Some(DEFAULT_H2_STREAM_WINDOW));
        assert_eq!(dflt.http2_connection_window, Some(DEFAULT_H2_CONN_WINDOW));
        let cfg = ClientConfig {
            http2_adaptive_window: true,
            http2_stream_window: Some(u32::MAX >> 1),
            http2_connection_window: Some(u32::MAX >> 1),
            ..ClientConfig::default()
        };
        let client = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
        let _clone = client.clone();
    }

    /// h2 multi-connection + keep-alive: the default anchor (K=1,
    /// keep-alive off = status quo); transport instances build with K=4
    /// and 30s keep-alive; cheap clones share the round-robin counter
    /// (wire-level K-connection evidence in tests/h2_mock.rs).
    #[test]
    fn http2_multi_conn_and_keepalive_default_and_build() {
        let dflt = ClientConfig::default();
        assert_eq!(dflt.http2_max_connections, 1);
        assert_eq!(dflt.http2_keep_alive_interval, None);
        let cfg = ClientConfig {
            http2_max_connections: 4,
            http2_keep_alive_interval: Some(Duration::from_secs(30)),
            ..ClientConfig::default()
        };
        let client = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
        let c2 = client.clone();
        // Round-robin advances across clones (one Arc counter; the modulo stays in range with K=4).
        let _ = c2.data_transport();
        let _ = client.data_transport();
    }

    // ---- Warm table capacity-bound LRU ----

    /// Evict oldest past capacity (drives [`WarmthTable`] directly — the
    /// process-level singleton stays out of tests to avoid
    /// cross-contamination with other cases): after inserting CAP+64
    /// hosts, the entry count is clamped at the bound, the first-lit
    /// host is evicted, the last-lit host remains.
    #[test]
    fn warmth_table_lru_evicts_oldest_beyond_cap() {
        let mut t = WarmthTable::new();
        let n = HOST_WARMTH_CAP + 64;
        for i in 0..n {
            t.note(format!("http://host-{i}:80"), Instant::now());
        }
        assert_eq!(
            t.len(),
            HOST_WARMTH_CAP,
            "the capacity bound must clamp the entry count"
        );
        assert!(
            t.warm_at("http://host-0:80").is_none(),
            "the oldest entry (host-0) must be evicted"
        );
        assert!(
            t.warm_at(&format!("http://host-{}:80", n - 1)).is_some(),
            "the newest entry must be in the table"
        );
        // Exactly the oldest 64 are evicted (boundary: host number 64 is the oldest survivor).
        assert!(
            t.warm_at(&format!("http://host-{}:80", n - HOST_WARMTH_CAP - 1))
                .is_none(),
            "the boundary of the last evicted entry in the over-cap segment"
        );
        assert!(
            t.warm_at(&format!("http://host-{}:80", n - HOST_WARMTH_CAP))
                .is_some(),
            "the oldest within the bound must survive"
        );
    }

    /// Lighting semantics (refresh = re-order): a host lit early but
    /// refreshed recently is "newer" than a mid-age host — eviction
    /// order follows the last-lit instant, not the first-insert order.
    #[test]
    fn warmth_table_refresh_moves_recency() {
        let mut t = WarmthTable::new();
        for i in 0..HOST_WARMTH_CAP {
            t.note(format!("http://mid-{i}:80"), Instant::now());
        }
        // The earliest insert is refreshed (moved to the newest order).
        t.note("http://mid-0:80".to_string(), Instant::now());
        // Inserting one new host evicts mid-1 (not the refreshed mid-0).
        t.note("http://newcomer:80".to_string(), Instant::now());
        assert_eq!(t.len(), HOST_WARMTH_CAP);
        assert!(
            t.warm_at("http://mid-0:80").is_some(),
            "a refreshed host must not be evicted"
        );
        assert!(
            t.warm_at("http://mid-1:80").is_none(),
            "eviction must land on the longest-unlit host"
        );
        assert!(t.warm_at("http://newcomer:80").is_some());
    }

    /// Warm decision / lighting semantics (process-level truth): after
    /// `note_host_warm` lights a host, `uri_on_warm_pool` is true for
    /// any path on that host and false for unknown hosts; repeated
    /// lighting is idempotent (same key re-orders, no new entry).
    #[test]
    fn warmth_note_and_query_semantics_unchanged() {
        let mut t = WarmthTable::new();
        let at = Instant::now();
        t.note("http://warmth-p85.example:8080".to_string(), at);
        t.note("http://warmth-p85.example:8080".to_string(), at);
        assert_eq!(t.len(), 1, "repeated lighting must not add an entry");
        assert_eq!(t.warm_at("http://warmth-p85.example:8080"), Some(at));
        assert!(t.warm_at("http://unknown:80").is_none());
        // Global surface (normalized key: default-port form) — a
        // process-level singleton, so an independent host namespace
        // isolates this case.
        note_host_warm(&url("http://warmth-global-p85.example/f.bin"));
        assert!(uri_on_warm_pool(
            "http://warmth-global-p85.example/any/other/path.bin"
        ));
        assert!(!uri_on_warm_pool("http://warmth-unknown-p85.example/f.bin"));
    }

    // ===== Shared DNS wiring (wire-level cross-validation; real DNS forbidden — stubs) =====

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use taiji_io::dns::{HostResolver, ResolverFuture};

    /// Counting stub resolver (test seam; real DNS forbidden):
    /// host -> fixed address, counts resolve calls (cache-hit
    /// assertions); unknown hosts -> Err.
    #[derive(Clone)]
    struct WireStubResolver {
        table: std::collections::HashMap<String, IpAddr>,
        queries: Arc<AtomicUsize>,
    }

    impl WireStubResolver {
        fn new(entries: &[&str]) -> Self {
            WireStubResolver {
                table: entries
                    .iter()
                    .map(|h| ((*h).to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST)))
                    .collect(),
                queries: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn queries(&self) -> usize {
            self.queries.load(AtomicOrdering::SeqCst)
        }
    }

    impl HostResolver for WireStubResolver {
        fn resolve(&self, host: String) -> ResolverFuture {
            self.queries.fetch_add(1, AtomicOrdering::SeqCst);
            let result = self
                .table
                .get(&host)
                .copied()
                .ok_or_else(|| format!("wire stub resolver: unexpected host {host}"));
            Box::pin(std::future::ready(result))
        }
    }

    /// reqwest client with an independently injected instance
    /// (`SharedDns::with_resolver(stub)` — the same [`DnsAdapter`] shell
    /// as the production wiring, only the service instance injected;
    /// `pool_max_idle_per_host(0)` = a fresh connection per request —
    /// count changes are attributable to the DNS cache alone, undiluted
    /// by pool reuse).
    async fn stub_dns_client(stub: &WireStubResolver) -> Client {
        Client::builder()
            .dns_resolver(Arc::new(DnsAdapter(Arc::new(
                taiji_io::dns::SharedDns::with_resolver(Arc::new(stub.clone())),
            ))))
            .pool_max_idle_per_host(0)
            .build()
            .unwrap_or_else(|e| panic!("build client: {e}"))
    }

    /// Local marker server: any path returns a fixed body (the wire
    /// criterion for "which port was reached").
    async fn marker_server(marker: &'static str) -> u16 {
        let app = axum::Router::new().fallback(move || async move { marker.to_string() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"))
            .port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        port
    }

    /// Wire-level cross-validation: two-sided stub-count assertions
    /// (the first connection resolves >= 1 + a second connection on the
    /// same host adds zero resolutions) + port normalization both ways
    /// (cache entries hold only IpAddr — same-host requests on different
    /// ports each reach the correct server, no port leaks from the
    /// cache).
    #[tokio::test]
    async fn dns_adapter_wire_cache_counting_and_port_normalization() {
        let stub = WireStubResolver::new(&["wire-dns-p105.example"]);
        let client = stub_dns_client(&stub).await;
        let p1 = marker_server("one").await;
        let p2 = marker_server("two").await;

        // First connection: resolution happens (>= 1; guards a pre-warmed false pass).
        let body = client
            .get(format!("http://wire-dns-p105.example:{p1}/"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("first: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("first body: {e}"));
        assert_eq!(
            body, "one",
            "connected to the P1 server via stub resolution"
        );
        let after_first = stub.queries();
        assert!(
            after_first >= 1,
            "the first connection resolves >= 1 time (actual {after_first})"
        );

        // Second connection, same host (same port): zero new resolutions
        // (cache hit — the zero-delta side of the two-sided assertion,
        // guarding against a "never reached the resolver" false pass).
        let body = client
            .get(format!("http://wire-dns-p105.example:{p1}/again"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("second: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("second body: {e}"));
        assert_eq!(body, "one");
        assert_eq!(
            stub.queries(),
            after_first,
            "a second connection on the same host adds zero resolutions (TTL cache hit)"
        );

        // Port normalization: a same-host request on a **different
        // port** reaches the P2 server (the port is synthesized from
        // this URL's explicit port — hyper-util completes the resolver's
        // port 0 with the URL port; cache entries hold only IpAddr, so
        // nothing can leak: if the shape carried a port, this request
        // would mis-connect to P1 and return "one") and still adds zero
        // new resolutions (same-host cache reuse).
        let body = client
            .get(format!("http://wire-dns-p105.example:{p2}/"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("port-normalization: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("port body: {e}"));
        assert_eq!(
            body, "two",
            "the port is synthesized from this request (the cache carries no port)"
        );
        assert_eq!(
            stub.queries(),
            after_first,
            "across ports the same-host cache still hits"
        );

        // IP-literal URL: hyper-util's `try_parse` short-circuits before
        // the resolver — the injected resolver is untouched (the bridge
        // function's built-in literal passthrough is dead code on the
        // reqwest path; this is its wire-level proof).
        let body = client
            .get(format!("http://127.0.0.1:{p1}/literal"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("literal: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("literal body: {e}"));
        assert_eq!(body, "one");
        assert_eq!(
            stub.queries(),
            after_first,
            "a literal URL bypasses the resolver \
             (hyper-util short-circuits before the injection face)"
        );
    }

    /// The proxy surface is not special-cased: an http proxy host
    /// resolves through the injected resolver too (a proxy host is an
    /// ordinary resolver input — the same seam as direct hosts, no
    /// bypass).
    #[tokio::test]
    async fn proxy_host_resolution_goes_through_dns_adapter() {
        let stub = WireStubResolver::new(&["proxy-p105.example"]);
        let proxy_port = marker_server("via-proxy").await;
        let client = Client::builder()
            .dns_resolver(Arc::new(DnsAdapter(Arc::new(
                taiji_io::dns::SharedDns::with_resolver(Arc::new(stub.clone())),
            ))))
            .pool_max_idle_per_host(0)
            .proxy(
                reqwest::Proxy::all(format!("http://proxy-p105.example:{proxy_port}"))
                    .unwrap_or_else(|e| panic!("proxy url: {e}")),
            )
            .build()
            .unwrap_or_else(|e| panic!("build: {e}"));

        // Requesting any external host via the proxy: the client
        // connects only to the proxy (absolute-form left to the proxy);
        // the proxy host resolves through the **injected resolver**
        // (stub count >= 1).
        let body = client
            .get("http://target-via-proxy-p105.example:81/x")
            .send()
            .await
            .unwrap_or_else(|e| panic!("via proxy: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("proxy body: {e}"));
        assert_eq!(
            body, "via-proxy",
            "the request reaches the marker server via the proxy"
        );
        assert!(
            stub.queries() >= 1,
            "the proxy host resolves through the injected resolver (no bypass): {}",
            stub.queries()
        );
    }

    /// Dedicated HTTPS proxy slot (`--https-proxy`) wire proof: with the
    /// dedicated slot registered, an **http target is not captured by
    /// it** — the `Proxy::https` matcher only intercepts https targets
    /// (reqwest matcher domain), so http falls to the global slot (the
    /// dedicated > global reordering only happens for https targets;
    /// the https-side registration-order first-match-wins is pinned by
    /// the `build_transport` inline note + reqwest's `connect.rs`
    /// proxy-selection loop). Zero TLS dependency: each proxy host
    /// points at its own marker server, and the response body tells
    /// "which slot was taken".
    #[tokio::test]
    async fn dedicated_https_proxy_slot_does_not_capture_http_targets() {
        let stub = WireStubResolver::new(&["https-slot-proxy.example", "all-slot-proxy.example"]);
        let all_port = marker_server("via-all-slot").await;
        let https_port = marker_server("via-https-slot").await;
        // Both slots registered in the transport's own assembly order
        // (the `build_transport` shape): the https dedicated slot first,
        // the global slot second.
        let client = Client::builder()
            .dns_resolver(Arc::new(DnsAdapter(Arc::new(
                taiji_io::dns::SharedDns::with_resolver(Arc::new(stub)),
            ))))
            .pool_max_idle_per_host(0)
            .proxy(
                reqwest::Proxy::https(format!("http://https-slot-proxy.example:{https_port}"))
                    .unwrap_or_else(|e| panic!("https proxy url: {e}")),
            )
            .proxy(
                reqwest::Proxy::all(format!("http://all-slot-proxy.example:{all_port}"))
                    .unwrap_or_else(|e| panic!("all proxy url: {e}")),
            )
            .build()
            .unwrap_or_else(|e| panic!("build: {e}"));

        // http target: the https dedicated slot does not match (outside
        // its matcher domain) -> falls to the global slot.
        let body = client
            .get("http://http-target.example:81/x")
            .send()
            .await
            .unwrap_or_else(|e| panic!("http target via proxy: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("body: {e}"));
        assert_eq!(
            body, "via-all-slot",
            "http target must take the global slot (outside the dedicated slot's domain)"
        );
    }

    /// `ClientConfig` bucket key covers `proxy_https`: a dedicated-slot
    /// value difference = a separate transport instance (bucketing
    /// consistency is guaranteed by the derive(Hash) all-fields key
    /// surface — a regression pin against the new field dropping out
    /// of the key).
    #[test]
    fn shared_clients_bucketing_covers_proxy_https() {
        let a = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
        let b = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            Arc::ptr_eq(&a.rr, &b.rr),
            "equal configs share the transport instance"
        );
        let c = HttpClient::new(ClientConfig {
            proxy_https: Some("http://https-slot.example:8080".into()),
            ..ClientConfig::default()
        })
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !Arc::ptr_eq(&a.rr, &c.rr),
            "a dedicated-slot value difference buckets separately \
             (different proxy = different transport instance)"
        );
        assert_eq!(ClientConfig::default().proxy_https, None);
    }

    /// `with_pinned_resolve` (the production pin face): the
    /// variant's connection lands on the pinned address (wire truth:
    /// the marker server echoes the Host header it received) with the
    /// URL's hostname preserved, and the pin table extension is
    /// first-wins idempotent.
    #[tokio::test]
    async fn with_pinned_resolve_routes_to_the_pin() {
        // The marker echoes the request's Host header in the body —
        // the wire proof that the pin steers the CONNECTION while the
        // URL's name survives as the Host.
        async fn host_echo_server() -> (std::net::SocketAddr, Arc<StdMutex<Vec<String>>>) {
            let seen = Arc::new(StdMutex::new(Vec::new()));
            let seen2 = Arc::clone(&seen);
            let app =
                axum::Router::new().fallback(move |headers: axum::http::HeaderMap| async move {
                    let host = headers
                        .get(axum::http::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("?")
                        .to_string();
                    seen2
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(host.clone());
                    host
                });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap_or_else(|e| panic!("bind: {e}"));
            let addr = listener
                .local_addr()
                .unwrap_or_else(|e| panic!("local_addr: {e}"));
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            (addr, seen)
        }
        let (pin_addr, seen) = host_echo_server().await;
        let base = HttpClient::new(ClientConfig {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            ..ClientConfig::default()
        })
        .unwrap_or_else(|e| panic!("base: {e}"));
        let pinned = base
            .with_pinned_resolve(&[("pin-address.example".to_string(), pin_addr)])
            .unwrap_or_else(|e| panic!("variant: {e}"));
        // The pin table carries the pin; the base does not.
        assert_eq!(base.pinned_resolve().len(), 0);
        assert_eq!(
            pinned.pinned_resolve(),
            &[("pin-address.example".to_string(), pin_addr)]
        );
        // The unresolvable hostname would fail under real DNS; with
        // the pin the connection lands on the marker (body = the Host
        // header the marker received = the URL's hostname).
        let body = pinned
            .get(
                "http://pin-address.example/pinned.bin",
                &RequestCtx::default(),
            )
            .await
            .unwrap_or_else(|e| panic!("pinned get: {e}"))
            .response
            .text()
            .await
            .unwrap_or_else(|e| panic!("body: {e}"));
        assert!(
            body.starts_with("pin-address.example"),
            "the connection landed on the pinned address with the URL's Host: {body}"
        );
        assert_eq!(
            seen.lock().unwrap_or_else(|e| e.into_inner()).len(),
            1,
            "exactly the pinned connection"
        );
        // A re-pin of the same host is first-wins idempotent (no
        // duplicate table entries).
        let again = pinned
            .with_pinned_resolve(&[("pin-address.example".to_string(), pin_addr)])
            .unwrap_or_else(|e| panic!("re-pin: {e}"));
        assert_eq!(again.pinned_resolve().len(), 1);
    }

    /// `pinned_resolve` stacking semantics: reqwest's overrides layer
    /// wraps **above** the injected resolver — a pinned host never
    /// touches the stub (it connects to the pin address), an unpinned
    /// host goes through the injected resolver (the stub is queried,
    /// proving the zero count came from override interception rather
    /// than broken wiring).
    #[tokio::test]
    async fn pinned_resolve_stacks_above_dns_adapter() {
        let stub = WireStubResolver::new(&["open-p105.example"]);
        let direct_port = marker_server("direct").await;
        let pinned_port = marker_server("pinned").await;
        let pin_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pinned_port);
        let client = Client::builder()
            .dns_resolver(Arc::new(DnsAdapter(Arc::new(
                taiji_io::dns::SharedDns::with_resolver(Arc::new(stub.clone())),
            ))))
            .resolve("pin-p105.example", pin_addr)
            .build()
            .unwrap_or_else(|e| panic!("build: {e}"));

        // Pinned host: goes through the override (pin address + explicit URL port), stub untouched.
        let body = client
            .get(format!("http://pin-p105.example:{pinned_port}/"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("pinned: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("pinned body: {e}"));
        assert_eq!(body, "pinned", "connected to the pinned-address server");
        assert_eq!(
            stub.queries(),
            0,
            "a pinned host does not touch the injected resolver"
        );

        // Unpinned host: goes through the injected resolver (the stub is
        // queried) — proving the zero count above was override
        // interception, not broken wiring.
        let body = client
            .get(format!("http://open-p105.example:{direct_port}/"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("open: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("open body: {e}"));
        assert_eq!(
            body, "direct",
            "an unpinned host goes through the injected resolver"
        );
        assert!(
            stub.queries() >= 1,
            "the injected resolver is in effect (the stub was queried)"
        );
    }

    /// [`SHARED_CLIENTS`] bucketing regression: the resolver is
    /// process-level wiring and **not** part of the `ClientConfig` key —
    /// equal-config tasks still share the transport instance (the `rr`
    /// counter Arc is the shared-identity witness across pool-entry
    /// clones); a config difference buckets separately; the `with_jar`
    /// surface stays out of the pool.
    #[test]
    fn shared_clients_bucketing_unchanged_by_dns_adapter() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let cfg_hash = |c: &ClientConfig| {
            let mut h = DefaultHasher::new();
            c.hash(&mut h);
            h.finish()
        };

        // Key surface: equal configs hash equal (fields unchanged by resolver wiring).
        assert_eq!(
            cfg_hash(&ClientConfig::default()),
            cfg_hash(&ClientConfig::default())
        );

        // Bucketing: equal config -> same pool entry (shared rr); a difference -> separate entry.
        let a = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
        let b = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            Arc::ptr_eq(&a.rr, &b.rr),
            "equal-config tasks share the transport instance (bucketing is unchanged by DNS wiring)"
        );
        let other = ClientConfig {
            user_agent: "taiji/bucket-probe".to_string(),
            ..ClientConfig::default()
        };
        let c = HttpClient::new(other).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !Arc::ptr_eq(&a.rr, &c.rr),
            "a config difference buckets separately"
        );

        // with_jar surface: not pooled (built independently).
        let j1 = HttpClient::with_jar(ClientConfig::default(), crate::cookies::CookieJar::new())
            .unwrap_or_else(|e| panic!("{e}"));
        let j2 = HttpClient::with_jar(ClientConfig::default(), crate::cookies::CookieJar::new())
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !Arc::ptr_eq(&j1.rr, &j2.rr),
            "with_jar stays out of the shared pool"
        );
    }

    /// Classification seam landing: permanent DNS failure -> the typed
    /// [`HttpError::DnsPermanent`] (consumed by retry semantics); all
    /// other classes keep the existing [`HttpError::Transport`] shape
    /// (payload = error chain text).
    #[test]
    fn seam_permanent_dns_typed_other_classes_transport() {
        use taiji_io::dns::{DnsPersistence, TransportErrorClass};
        // Permanent DNS: the typed variant (same code surface as transport; see error.rs tests).
        assert!(matches!(
            http_error_of_class(
                TransportErrorClass::Dns(DnsPersistence::Permanent),
                "dns error: nxdomain".into()
            ),
            HttpError::DnsPermanent(_)
        ));
        // Transient DNS and all other classes: Transport shape unchanged.
        for class in [
            TransportErrorClass::Dns(DnsPersistence::Transient),
            TransportErrorClass::Timeout,
            TransportErrorClass::Tls,
            TransportErrorClass::Connect,
            TransportErrorClass::Refused,
            TransportErrorClass::Reset,
            TransportErrorClass::Other,
        ] {
            assert!(
                matches!(
                    http_error_of_class(class, "chain text".into()),
                    HttpError::Transport(_)
                ),
                "class {class:?} must keep the Transport shape"
            );
        }
    }

    /// Classification seam wire proof (isolated registry injection): a
    /// request to a closed port -> classified refused + the `Transport`
    /// shape unchanged + failed requests stay out of the first_byte
    /// phase histogram (the sampling rule). Real DNS forbidden: the
    /// refusal comes from a closed loopback port, zero name resolution
    /// throughout.
    #[tokio::test]
    async fn seam_counts_refused_via_injected_registry() {
        // Open then close: obtain a loopback port guaranteed to have no listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("{e}"))
            .port();
        drop(listener);

        let registry = Arc::new(MetricsRegistry::new());
        let client = HttpClient::with_metrics(ClientConfig::default(), registry.clone())
            .unwrap_or_else(|e| panic!("{e}"));
        let url = format!("http://127.0.0.1:{port}/seam");
        let err = match client.get(&url, &RequestCtx::default()).await {
            Err(e) => e,
            Ok(_) => panic!("closed-port request must fail"),
        };
        // Shape: refused is not a DNS verdict -> the Transport shape
        // (the payload carries the errno chain text; the Reset
        // discrimination payload domain unchanged).
        assert!(
            matches!(err, HttpError::Transport(ref msg) if msg.to_ascii_lowercase().contains("refused")),
            "expected refused Transport error, got {err:?}"
        );
        let s = registry.snapshot().http;
        assert_eq!(
            s.errors_refused, 1,
            "the classification seam counts exactly 1 (per failed request)"
        );
        assert_eq!(s.errors_dns_permanent + s.errors_dns_transient, 0);
        assert_eq!(
            s.request_first_byte.count, 0,
            "failed requests stay out of the first_byte phase (profile semantics)"
        );
    }

    /// Connection-profile wire proof 1 (literal URL, zero connect
    /// counts; isolated registry injection): a literal IP aimed at a
    /// closed port -> connect failure, `taiji_http_conn_establishments_total`
    /// and `taiji_http_conn_establish_seconds` stay zero (failed
    /// attempts are not counted — the latency profile takes successful
    /// samples only, failures classify through the errors seam); an IP
    /// literal also performs zero name resolution (all four DNS counters
    /// and the resolve histogram zero). Real DNS forbidden: the request
    /// has no hostname.
    #[tokio::test]
    async fn conn_profile_counts_nothing_on_failed_literal_url() {
        // Open then close: obtain a loopback port guaranteed to have no listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let port = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("{e}"))
            .port();
        drop(listener);

        let registry = Arc::new(MetricsRegistry::new());
        let client = HttpClient::with_metrics(ClientConfig::default(), registry.clone())
            .unwrap_or_else(|e| panic!("{e}"));
        // Literal URL (IP host, zero resolution surface).
        let url = format!("http://127.0.0.1:{port}/profile");
        let err = match client.get(&url, &RequestCtx::default()).await {
            Err(e) => e,
            Ok(_) => panic!("closed-port request must fail"),
        };
        assert!(
            matches!(err, HttpError::Transport(ref msg) if msg.to_ascii_lowercase().contains("refused")),
            "expected refused Transport error, got {err:?}"
        );
        let s = registry.snapshot();
        assert_eq!(
            s.http.conn_establishments_total, 0,
            "connect failures do not enter the count (only fresh successes count)"
        );
        assert_eq!(
            s.http.conn_establish_seconds.count, 0,
            "failed attempts stay out of the latency profile"
        );
        assert_eq!(
            s.http.conn_establishments_total, s.http.conn_establish_seconds.count,
            "counter and histogram always equal (zero-value shape)"
        );
        let dns = registry.snapshot().dns;
        assert_eq!(
            dns.lookups_hit + dns.lookups_miss + dns.lookups_error + dns.lookups_timeout,
            0,
            "IP literal performs zero resolution: all DNS-family counters zero"
        );
        assert_eq!(dns.resolve_seconds.count, 0);
    }

    /// keep-alive h1 mock origin (hand-written framing, the same
    /// discipline as reuse_pool_mock — no new dependency; the accept
    /// count is the server-side ground truth for fresh connections).
    async fn spawn_keepalive_origin() -> (String, Arc<AtomicU64>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let accepts = Arc::new(AtomicU64::new(0));
        let acc = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok(mut stream) = listener.accept().await.map(|(s, _)| s) else {
                    break;
                };
                acc.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 2048];
                    loop {
                        // Read until the head terminates (GET has no body; the cap guards memory).
                        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                            if buf.len() > 16 * 1024 {
                                return;
                            }
                        }
                        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\
                                    Connection: keep-alive\r\n\r\nx";
                        if stream.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                        buf.clear();
                    }
                });
            }
        });
        (format!("http://{addr}"), accepts)
    }

    /// Connection-profile wire proof 2 (DNS counters vs connect counts +
    /// pool reuse not counted; isolated registry injection — real DNS
    /// forbidden: the hostname is pinned to the loopback mock via
    /// `pinned_resolve`, whose override layer short-circuits before the
    /// shared resolver service). Asserts: (1) the first request makes
    /// exactly one fresh connection (counter and histogram equal), while
    /// the pinned path's DNS counters stay zero — a pinned connect has
    /// no DNS component (the degenerate case of DNS deduction: combined
    /// latency = the connect+TLS value); (2) the second same-host
    /// request, after fully reading the body and returning the
    /// connection to the pool, hits keep-alive reuse — connect counts
    /// unchanged and the server-side accept count stays 1 (pool reuse
    /// bypasses the connector, so counts naturally cover fresh connects
    /// only; cross-checked against server-side truth).
    #[tokio::test]
    async fn conn_profile_counts_fresh_only_and_pinned_dns_relation() {
        let (base, accepts) = spawn_keepalive_origin().await;
        // Pinned host = an unresolvable fake domain -> if the pin failed
        // to short-circuit, real DNS would be hit (the test fails
        // itself); the no-real-DNS red line is self-evident by
        // construction.
        let addr = base
            .trim_start_matches("http://")
            .parse()
            .unwrap_or_else(|e| panic!("socket addr: {e}"));
        let cfg = ClientConfig {
            pinned_resolve: vec![("profile-mock.invalid".to_string(), addr)],
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            ..ClientConfig::default()
        };
        let registry = Arc::new(MetricsRegistry::new());
        let client =
            HttpClient::with_metrics(cfg, registry.clone()).unwrap_or_else(|e| panic!("{e}"));
        let ctx = RequestCtx::default();
        // The request uses the fake domain (the pin key); the connection lands on the mock.
        let url = "http://profile-mock.invalid/profile.bin";

        // Request 1: exactly one fresh connection; the pinned path's DNS counters all zero.
        let followed = client
            .get(url, &ctx)
            .await
            .unwrap_or_else(|e| panic!("first get: {e}"));
        assert_eq!(
            followed
                .response
                .bytes()
                .await
                .unwrap_or_else(|e| panic!("body: {e}"))
                .as_ref(),
            b"x",
            "reading the body fully returns the connection to the pool (the reuse precondition)"
        );
        let s = registry.snapshot();
        assert_eq!(
            s.http.conn_establishments_total, 1,
            "the first request makes exactly 1 fresh connection"
        );
        assert_eq!(
            s.http.conn_establishments_total, s.http.conn_establish_seconds.count,
            "counter and histogram always equal (dual-slot accounting of success events)"
        );
        let dns = &s.dns;
        assert_eq!(
            dns.lookups_hit + dns.lookups_miss + dns.lookups_error + dns.lookups_timeout,
            0,
            "a pinned-host connect produces no DNS counters \
             (the override short-circuits before the shared resolver service)"
        );
        assert_eq!(dns.resolve_seconds.count, 0);
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            1,
            "server-side accept ground truth"
        );

        // Request 2: pooled keep-alive reuse — zero connect-count delta, zero new accepts.
        let followed = client
            .get(url, &ctx)
            .await
            .unwrap_or_else(|e| panic!("second get: {e}"));
        assert_eq!(
            followed
                .response
                .bytes()
                .await
                .unwrap_or_else(|e| panic!("body: {e}"))
                .as_ref(),
            b"x"
        );
        let s = registry.snapshot();
        assert_eq!(
            s.http.conn_establishments_total, 1,
            "pool reuse bypasses the connector — the count naturally covers \
             fresh connects only (zero delta on the second request)"
        );
        assert_eq!(s.http.conn_establish_seconds.count, 1);
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            1,
            "zero new accepts (reuse ground truth)"
        );
    }
}

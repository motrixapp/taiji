//! Shared DNS for HTTP, FTP, trackers and DHT bootstrap.
//!
//! [`SharedDns`] merges concurrent same-host requests and caches complete
//! address lists. Positive and short-lived negative entries share a bounded
//! cache. Hostname case is normalized; a final dot is preserved because it
//! changes system search-domain semantics. Address-family projection never
//! turns an absent AAAA record into a host-wide failure that hides valid A.
//!
//! [`SystemResolver`] preserves the OS resolver and scoped/VPN DNS behavior.
//! Its physical flight table and semaphore bound queued/running system calls.
//! The semaphore permit and cleanup guard live inside the blocking closure;
//! cancelling a waiter cannot falsely release a running getaddrinfo call.
//! Timeouts abandon logical waits, not OS calls. Retries join an outstanding
//! physical call within that network generation; stale answers are discarded before
//! a new cohort retries within its own remaining deadline.
//!
//! Metrics keep cache hit/miss and caller error/latency semantics separate
//! from owned backend queries, coalesced calls and actual system occupancy.
//! Tests inject resolvers and blocking gates; they never query real DNS.
//!
//! Upstream anchor mapping: docs/design/io.md

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::metrics::{DnsCacheEvent, DnsFamilyMix, DnsLookupResult, MetricsRegistry};

mod shared;
mod system;
pub use shared::{DnsPolicy, SharedDns};
pub use system::{BlockingHostLookup, SystemDnsPolicy, SystemResolver, TokioHostResolver};

/// Typed resolver seam; opaque string resolvers use its default adapter.
pub type ClassifiedListFuture =
    Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send>>;

/// Address-family composition of a resolver list (non-empty premise —
/// guaranteed by `resolve_list`'s Ok contract; callers guard with the
/// non-empty check).
fn family_mix_of(list: &[IpAddr]) -> DnsFamilyMix {
    if list.iter().all(IpAddr::is_ipv4) {
        DnsFamilyMix::V4Only
    } else if list.iter().all(IpAddr::is_ipv6) {
        DnsFamilyMix::V6Only
    } else {
        DnsFamilyMix::Dual
    }
}

/// Application positive-cache TTL. System getaddrinfo does not expose DNS
/// record TTLs; reads do not extend this fixed lifetime.
pub const HOST_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
/// host→IpAddr cache capacity cap (default 256; beyond it the oldest by
/// insertion order is evicted).
pub const HOST_CACHE_CAPACITY: usize = 256;

/// Resolution-timeout backstop (the [`TimeoutResolver`] default
/// deadline).
///
/// Value anchor: aria2 `--dns-timeout` default 30
/// (`OptionHandlerFactory.cc`, hidden option; read-only reference).
pub const DNS_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolution-result future (object-safe seam: callers hold
/// `Arc<dyn HostResolver>`, avoiding an async-trait dependency).
pub type ResolverFuture = Pin<Box<dyn Future<Output = Result<IpAddr, String>> + Send>>;

/// Whole-list resolution future (the object-safe seam of
/// [`HostResolver::resolve_list`]; no new dependency, like
/// [`ResolverFuture`]).
pub type ListResolverFuture = Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send>>;

/// Resolution address family: the BEP15 carrier family equals the
/// transport family (libtorrent `src/udp_tracker_connection.cpp` picks
/// the peers stride 6/18 by the destination address family), so the
/// requested family is the resolved record family (A/AAAA) — no
/// cross-family fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolveFamily {
    /// IPv4 (A records; 6B per carried peer, BEP23).
    V4,
    /// IPv6 (AAAA records; 18B per carried peer, BEP32 form).
    V6,
}

impl ResolveFamily {
    /// Address → family.
    pub fn of_ip(ip: IpAddr) -> Self {
        if ip.is_ipv4() {
            ResolveFamily::V4
        } else {
            ResolveFamily::V6
        }
    }

    /// Family name for log/event reasons.
    pub fn as_str(self) -> &'static str {
        match self {
            ResolveFamily::V4 => "v4",
            ResolveFamily::V6 => "v6",
        }
    }
}

/// Domain resolution seam: `resolve(host)` returns one routed address —
/// IPv4 preferred, taking the first address ([`pick_addr`]); when only
/// v6 exists, the first v6 (callers then use the v6 carrier face for
/// that address family).
///
/// Errors retain the string seam for existing callers; the typed list method
/// preserves timeout, capacity and cancellation facts for the shared service.
pub trait HostResolver: Send + Sync + 'static {
    /// Forget an outstanding physical generation if the backend maintains one.
    /// Existing system work is not forcibly stopped; its answer must be ignored.
    fn invalidate_host(&self, _host: &str) {}

    /// Retire lookups issued under a previous network configuration.
    /// Stateless backends need no action; caching backends must override this.
    fn invalidate_all(&self) {}

    fn resolve(&self, host: String) -> ResolverFuture;

    /// Per-family resolution: the result family must equal the requested
    /// family.
    ///
    /// Default impl: V4 → run [`Self::resolve`] (v4-first) and pass the
    /// result through if it is v4, else Err (the host has no A record or
    /// resolution failed); V6 → Err — a single-address resolver has no
    /// AAAA face, so dual-stack implementations must override this
    /// method (e.g. [`TokioHostResolver`]; test stubs keep the v4
    /// semantics naturally via the default impl).
    fn resolve_family(&self, host: String, family: ResolveFamily) -> ResolverFuture {
        match family {
            ResolveFamily::V4 => {
                let fut = self.resolve(host);
                Box::pin(async move {
                    match fut.await {
                        Ok(ip) if ResolveFamily::of_ip(ip) == ResolveFamily::V4 => Ok(ip),
                        Ok(_) => Err("no ipv4 address (A) resolved".to_string()),
                        Err(e) => Err(e),
                    }
                })
            }
            ResolveFamily::V6 => Box::pin(std::future::ready(Err(
                "AAAA resolution unsupported by this resolver".to_string(),
            ))),
        }
    }

    /// Whole-list resolution (host → all A/AAAA addresses, no
    /// single-address routing): the query face of the shared service
    /// [`SharedDns`] — one query fetches the whole list, the whole list
    /// goes into the cache, and consumers project per family / on demand
    /// (the mechanism behind the 2→1 query count for dual-stack hosts).
    ///
    /// Default impl = query both families via the per-family view
    /// [`Self::resolve_family`] and merge (V4 first); it targets injected
    /// stubs (existing stubs gain the whole-list face with zero
    /// changes), while the production resolver ([`TokioHostResolver`])
    /// overrides it with one whole-list system `ToSocketAddrs` query — the real
    /// 2→1 win comes from that override. Error semantics: any one family
    /// succeeding is `Ok` (the other family failing only means no
    /// records of that family); both failing = Err (the V4-side error is
    /// reported — the V6 "unsupported" is a default-impl artifact; the
    /// real failure detail is on the V4 side).
    fn resolve_list(&self, host: String) -> ListResolverFuture {
        let v4 = self.resolve_family(host.clone(), ResolveFamily::V4);
        let v6 = self.resolve_family(host, ResolveFamily::V6);
        Box::pin(async move {
            let mut addrs = Vec::new();
            let mut err = None;
            let (v4, v6) = tokio::join!(v4, v6);
            match v4 {
                Ok(ip) => addrs.push(ip),
                Err(e) => err = Some(e),
            }
            if let Ok(ip) = v6 {
                addrs.push(ip);
            }
            if addrs.is_empty() {
                Err(err.unwrap_or_else(|| "no address resolved".to_string()))
            } else {
                Ok(addrs)
            }
        })
    }
    /// Preserve error classes when the implementation knows them. The default
    /// keeps string failures opaque; caching never guesses NXDOMAIN by text.
    fn resolve_list_classified(&self, host: String) -> ClassifiedListFuture {
        let future = self.resolve_list(host);
        Box::pin(async move { future.await.map_err(ResolveError::Failed) })
    }
}

/// Resolution-timeout decorator: wraps **over** the [`HostResolver`]
/// injection seam (one line at the production wiring site, e.g.
/// `Arc::new(TimeoutResolver::new(Arc::new(TokioHostResolver)))`); the
/// deadline is injected via [`Self::with_timeout`] — tests parameterize
/// with a "hanging stub + short deadline" (real DNS is never hit: a real
/// hung getaddrinfo cannot be constructed reliably in tests).
///
/// The timeout is deliberately **not built into** [`TokioHostResolver`]:
/// built in, the test stubs injected at the seam would also carry the
/// timeout layer and stop being testable — the decorator must be
/// independently attachable/detachable at the seam; that is the direct
/// reason for its placement.
///
/// Timeout ends the logical wait. SystemResolver keeps a physical flight and
/// its permit until the actual syscall returns; repeated timed-out calls do
/// not create more same-host blocking work.
pub struct TimeoutResolver {
    inner: Arc<dyn HostResolver>,
    timeout: Duration,
}

impl std::fmt::Debug for TimeoutResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written: `inner` is a `dyn HostResolver` trait object (no
        // Debug face) and is omitted; the deadline is the observable
        // configuration.
        f.debug_struct("TimeoutResolver")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl TimeoutResolver {
    /// Default deadline ([`DNS_TIMEOUT`] = 30s; value anchor in the
    /// constant docs).
    pub fn new(inner: Arc<dyn HostResolver>) -> Self {
        Self::with_timeout(inner, DNS_TIMEOUT)
    }

    /// Injected deadline (test parameterization seam).
    pub fn with_timeout(inner: Arc<dyn HostResolver>, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl HostResolver for TimeoutResolver {
    fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }
    fn invalidate_host(&self, host: &str) {
        self.inner.invalidate_host(host);
    }
    fn resolve(&self, host: String) -> ResolverFuture {
        let fut = self.inner.resolve(host);
        let timeout = self.timeout;
        Box::pin(async move {
            tokio::time::timeout(timeout, fut)
                .await
                .unwrap_or_else(|_| Err(format!("dns resolution timed out after {timeout:?}")))
        })
    }

    fn resolve_family(&self, host: String, family: ResolveFamily) -> ResolverFuture {
        let fut = self.inner.resolve_family(host, family);
        let timeout = self.timeout;
        Box::pin(async move {
            tokio::time::timeout(timeout, fut)
                .await
                .unwrap_or_else(|_| Err(format!("dns resolution timed out after {timeout:?}")))
        })
    }

    fn resolve_list(&self, host: String) -> ListResolverFuture {
        let future = self.resolve_list_classified(host);
        Box::pin(async move { future.await.map_err(|error| error.into_trait_err()) })
    }

    fn resolve_list_classified(&self, host: String) -> ClassifiedListFuture {
        let future = self.inner.resolve_list_classified(host);
        let timeout = self.timeout;
        Box::pin(async move {
            tokio::time::timeout(timeout, future)
                .await
                .unwrap_or(Err(ResolveError::Timeout(timeout)))
        })
    }
}

/// Typed resolution-boundary error (the taiji-io error surface).
///
/// The typed HostResolver list seam and transport wrappers preserve this
/// payload. Older string-based resolvers use the trait's default adapter.
///
/// Value semantics (Clone/PartialEq/Eq): carried as the typed payload of
/// transport-layer error enums (e.g. the taiji-http FTP DNS-failure
/// variant), following the host error surface's value requirements.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResolveError {
    /// Resolution timed out ([`TimeoutResolver`] deadline; carries the
    /// effective limit).
    #[error("dns resolution timed out after {0:?}")]
    Timeout(Duration),
    /// Underlying resolution failure (the trait `String` error text
    /// passes through unchanged — the typed boundary does not drop
    /// inner detail).
    #[error("dns resolution failed: {0}")]
    Failed(String),
    #[error("dns resolver capacity exhausted")]
    Capacity,
    #[error("dns resolution cancelled")]
    Cancelled,
}

impl ResolveError {
    fn into_trait_err(self) -> String {
        match self {
            Self::Failed(message) => message,
            other => other.to_string(),
        }
    }
}

/// Error-chain DNS attribution core (single source, reqwest-free):
/// decides for any error stack whether the failure originated in domain
/// resolution, for thin wrappers in transport error classification
/// (tracker transport error classes, etc.).
///
/// Attribution order (types first, then text):
/// 1. **source-chain downcast of [`ResolveError`] first** — after the
///    shared resolver's type-preserving boxing via
///    [`box_resolve_error`], reqwest/hyper-util layer errors pass
///    through the source chain unflattened, so type detection cannot
///    shatter with library Display wording. Discipline: adapter layers
///    must not box via `to_string()` (breaking the chain loses this
///    arm — the text fallback still applies but degraded);
/// 2. **Display text matching as the fallback** ("dns error" / "failed
///    to lookup" — hyper_util legacy `ConnectError` historical
///    wording): covers chains that bypass the shared resolver or broke
///    type preservation; they still classify.
///
/// The argument is `&(dyn Error + 'static)`: the chain walk starts at
/// the error itself and follows `source()` layer by layer (the
/// `source()` contract itself requires 'static payloads), so any error
/// stack (reqwest or custom wrappers) can be classified without
/// binding to a specific transport library.
pub fn error_chain_is_dns(err: &(dyn std::error::Error + 'static)) -> bool {
    matches!(
        classify_error_chain(TransportHints::default(), err),
        TransportErrorClass::Dns(_)
    )
}

/// Persistence of a resolution failure (the `persistence` label domain;
/// the attribution face of retry semantics): **Permanent** =
/// NXDOMAIN-class terminal failure (the domain does not exist / has no
/// address — retrying is worthless; retry semantics align with aria2
/// `NAME_RESOLVE_ERROR` direct failure, `AbstractCommand.cc`
/// DL_ABORT_EX2). **Transient** = timeouts, EAI_AGAIN temporary
/// failures, and other self-healing forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPersistence {
    /// NXDOMAIN-class terminal failure (retrying is worthless).
    Permanent,
    /// Timeout/EAI_AGAIN and other self-healing forms.
    Transient,
}

/// Transport error classification (the single-source mapping domain of
/// the HTTP data-plane classification seam; the label domain of metric
/// `taiji_http_errors_total{class=…}` — non-Other variants map 1:1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorClass {
    /// DNS resolution failure (payload = persistence; permanent/
    /// transient close-out in [`DnsPersistence`]).
    Dns(DnsPersistence),
    /// Timeout (connect/read).
    Timeout,
    /// TLS handshake/certificate failure.
    Tls,
    /// Connection establishment failure (forms not refined as
    /// refused/reset).
    Connect,
    /// Connection refused (peer port not listening, etc.).
    Refused,
    /// Connection reset/interrupted (peer RST / broken pipe /
    /// mid-stream close).
    Reset,
    /// Everything else (protocol-level / unclassifiable — not counted
    /// in the errors metric).
    Other,
}

/// Upper-layer transport-library error-kind facts (reqwest-free
/// surface): the host crate (taiji-http) reads reqwest::Error kind
/// predicates mechanically and passes them in — this crate does not
/// depend on reqwest, and classification stays single-sourced in
/// [`classify_error_chain`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportHints {
    /// Host says "connection-establishment class error".
    pub connect: bool,
    /// Host says "timeout class error".
    pub timeout: bool,
}

/// Text marker table (the Display fallback path; downcast takes
/// priority — this table only serves chains that bypass the shared
/// resolver or broke type preservation; a superset of the original
/// `error_chain_is_dns` matching).
const DNS_TEXT_MARKERS: &[&str] = &[
    "dns error",
    "failed to lookup",
    "name or service not known",
    "nodename nor servname",
    "no such host",
    "no address resolved",
    "no address returned",
    "name resolution",
];
/// NXDOMAIN-class permanent-failure markers (EAI_NONAME family wording +
/// the empty-address terminal message + the resolver's own "nxdomain").
const DNS_PERMANENT_MARKERS: &[&str] = &["not known", "no such host", "no address", "nxdomain"];
const TLS_TEXT_MARKERS: &[&str] = &["tls", "ssl", "certificate"];
const RESET_TEXT_MARKERS: &[&str] = &[
    "connection reset",
    "broken pipe",
    "connection closed before message completed",
];
const TIMEOUT_TEXT_MARKERS: &[&str] = &["timed out", "timeout"];
const REFUSED_TEXT_MARKERS: &[&str] = &["connection refused"];
const CONNECT_TEXT_MARKERS: &[&str] = &["tcp connect error", "connect error"];

fn text_matches(lower: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| lower.contains(m))
}

/// [`ResolveError`] → persistence: timeout = self-healing (transient);
/// the failure payload is trait `String` error text — mapped by
/// EAI-family markers, and **conservatively transient** when no marker
/// matches (misreading transient only burns retries, misreading
/// permanent loses a self-healing opportunity — the asymmetric risk
/// resolves to the safe side).
pub fn dns_persistence_of(err: &ResolveError) -> DnsPersistence {
    match err {
        ResolveError::Timeout(_) | ResolveError::Capacity | ResolveError::Cancelled => {
            DnsPersistence::Transient
        }
        ResolveError::Failed(msg) => persistence_by_text(msg),
    }
}

/// Text → persistence (EAI-family markers; no marker is conservatively
/// transient).
fn persistence_by_text(text: &str) -> DnsPersistence {
    let lower = text.to_ascii_lowercase();
    if text_matches(&lower, DNS_PERMANENT_MARKERS) {
        DnsPersistence::Permanent
    } else {
        DnsPersistence::Transient
    }
}

/// Single-source transport error classification (the HTTP data-plane
/// classification seam; reqwest-free): maps any error stack (a
/// host-stripped reqwest error chain / a typed FtpDns payload /
/// engine-side text payload) to a [`TransportErrorClass`].
///
/// Attribution order (types first, then text — the generalization of
/// the [`error_chain_is_dns`] discipline):
/// 1. **type downcast over the whole chain** — [`ResolveError`] (boxed
///    type-preserving by the shared resolver; persistence read straight
///    off the variant) → [`std::io::Error`] kind (refused/reset/timeout
///    as kernel errno facts, immune to wording drift);
/// 2. **Display text markers scanned per class** (dns → tls → reset →
///    timeout → refused → connect) — the whole chain is scanned per
///    class rather than judged node-locally: connect-class wrapper
///    wording (e.g. "client error (Connect)") must not shadow a dns
///    attribution deeper in the chain;
/// 3. host kind facts ([`TransportHints`]) as the backstop; no match =
///    [`TransportErrorClass::Other`].
///
/// The argument is `&(dyn Error + 'static)`: the same contract as
/// [`error_chain_is_dns`] (layer-by-layer source walk; any transport
/// library's error stack can be classified).
pub fn classify_error_chain(
    hints: TransportHints,
    err: &(dyn std::error::Error + 'static),
) -> TransportErrorClass {
    // 1. Typed chain: ResolveError (persistence read directly) →
    // io::Error kind.
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(re) = e.downcast_ref::<ResolveError>() {
            return TransportErrorClass::Dns(dns_persistence_of(re));
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            let class = match io.kind() {
                std::io::ErrorKind::ConnectionRefused => TransportErrorClass::Refused,
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe => TransportErrorClass::Reset,
                std::io::ErrorKind::TimedOut => TransportErrorClass::Timeout,
                _ => TransportErrorClass::Other,
            };
            if class != TransportErrorClass::Other {
                return class;
            }
        }
        cur = e.source();
    }
    // 2. Text markers scanned per class over the whole chain (dns
    // first — the main attribution face of the classification seam).
    let chain_lower = chain_display_lower(err);
    let dns_markers: &[&str] = DNS_TEXT_MARKERS;
    if text_matches(&chain_lower, dns_markers) {
        // Persistence: map the whole-chain text by EAI-family markers
        // (permanent markers gate the verdict — misreading transient
        // only costs retries while misreading permanent loses
        // self-healing, so the conservative order judges permanent only
        // on a permanent-marker hit).
        let persistence = if text_matches(&chain_lower, DNS_PERMANENT_MARKERS) {
            DnsPersistence::Permanent
        } else {
            DnsPersistence::Transient
        };
        return TransportErrorClass::Dns(persistence);
    }
    for (markers, class) in [
        (TLS_TEXT_MARKERS, TransportErrorClass::Tls),
        (RESET_TEXT_MARKERS, TransportErrorClass::Reset),
        (TIMEOUT_TEXT_MARKERS, TransportErrorClass::Timeout),
        (REFUSED_TEXT_MARKERS, TransportErrorClass::Refused),
        (CONNECT_TEXT_MARKERS, TransportErrorClass::Connect),
    ] {
        if text_matches(&chain_lower, markers) {
            return class;
        }
    }
    // 3. Host kind facts as the backstop.
    if hints.connect {
        return TransportErrorClass::Connect;
    }
    if hints.timeout {
        return TransportErrorClass::Timeout;
    }
    TransportErrorClass::Other
}

/// Lowercased concatenation of the whole chain's Display text (per-node
/// `to_string` + source walk; the one-shot scan face of the text
/// fallback path).
fn chain_display_lower(err: &(dyn std::error::Error + 'static)) -> String {
    let mut text = String::new();
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        text.push_str(&e.to_string().to_ascii_lowercase());
        text.push('\n');
        cur = e.source();
    }
    text
}

/// Type-preserving boxing of a resolution error (transport adapter
/// layers only): boxes [`ResolveError`] directly as
/// `Box<dyn Error + Send + Sync>` — upper layers (the reqwest `Resolve`
/// error surface is exactly that Box type; the classification face
/// [`error_chain_is_dns`]) depend on the type staying alive for
/// source-chain downcast; any `to_string()` boxing breaks the chain
/// (this discipline is single-pointed here; adapter shells must not box
/// on their own).
pub fn box_resolve_error(err: ResolveError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(err)
}

/// Resolution routing: first IPv4 preferred; v6-only → first v6;
/// empty → Err (retryable). Upstream anchor: aria2
/// `NameResolveCommand.cc` (see docs/design/io.md).
pub fn pick_addr(addrs: &[SocketAddr]) -> Result<IpAddr, String> {
    if let Some(a) = addrs.iter().find(|a| a.is_ipv4()) {
        return Ok(a.ip());
    }
    addrs
        .iter()
        .find(|a| a.is_ipv6())
        .map(|a| a.ip())
        .ok_or_else(|| "no address resolved".to_string())
}

/// Per-family routing: the first address of the requested family; no
/// record for it → Err (retryable, the same contract as
/// [`pick_addr`]'s "empty → Err"). No cross-family fallback (the
/// module-header note).
pub fn pick_addr_family(addrs: &[SocketAddr], family: ResolveFamily) -> Result<IpAddr, String> {
    let want_v4 = family == ResolveFamily::V4;
    addrs
        .iter()
        .find(|a| a.is_ipv4() == want_v4)
        .map(|a| a.ip())
        .ok_or_else(|| match family {
            ResolveFamily::V4 => "no ipv4 address (A) resolved".to_string(),
            ResolveFamily::V6 => "no ipv6 address (AAAA) resolved".to_string(),
        })
}

/// [`pick_addr`] over an `IpAddr` list (single-address projection of a
/// whole-list cache entry): first v4 preferred, v6-only → first v6,
/// empty → None.
pub fn pick_ip(addrs: &[IpAddr]) -> Option<IpAddr> {
    addrs
        .iter()
        .copied()
        .find(|ip| ip.is_ipv4())
        .or_else(|| addrs.iter().copied().find(|ip| ip.is_ipv6()))
}

/// [`pick_addr_family`] over an `IpAddr` list (per-family projection):
/// the first address of the family; no record → Err (same messages as
/// [`pick_addr_family`]).
pub fn pick_ip_family(addrs: &[IpAddr], family: ResolveFamily) -> Result<IpAddr, String> {
    addrs
        .iter()
        .copied()
        .find(|ip| ResolveFamily::of_ip(*ip) == family)
        .ok_or_else(|| match family {
            ResolveFamily::V4 => "no ipv4 address (A) resolved".to_string(),
            ResolveFamily::V6 => "no ipv6 address (AAAA) resolved".to_string(),
        })
}

/// Complete DNS answers with bounded storage. Positive and negative entries
/// use the same capacity and ordering; expiry removes both data and its index.
/// Explicit `now` parameters keep TTL behavior deterministic in unit tests.
type CachedAnswer = (Result<Vec<IpAddr>, ResolveError>, Instant, Duration);

#[derive(Debug)]
pub struct HostCache {
    ttl: Duration,
    capacity: usize,
    entries: HashMap<String, CachedAnswer>,
    /// Insertion order (oldest evicted; a get hit does not reorder —
    /// "oldest by insertion" rather than strict LRU; either eviction
    /// rule serves, and this implementation takes the simpler one).
    order: VecDeque<String>,
    /// Metrics registry (`None` = not counted — [`Self::new`]'s
    /// existing signature unchanged; [`SharedDns`] wiring injects via
    /// [`Self::with_metrics`]; eviction events are counted at the two
    /// feed points commented below).
    metrics: Option<Arc<MetricsRegistry>>,
}

impl HostCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: HashMap::new(),
            order: VecDeque::new(),
            metrics: None,
        }
    }

    /// Default parameters (TTL 5min / capacity 256).
    pub fn with_defaults() -> Self {
        Self::new(HOST_CACHE_TTL, HOST_CACHE_CAPACITY)
    }

    /// Constructs with a metrics registry (the eviction-counting seam:
    /// the two `taiji_dns_events_total` feed points — TTL expiry /
    /// capacity eviction — count through the bound registry; tests
    /// inject an independent instance).
    pub fn with_metrics(ttl: Duration, capacity: usize, metrics: Arc<MetricsRegistry>) -> Self {
        Self {
            metrics: Some(metrics),
            ..Self::new(ttl, capacity)
        }
    }

    /// Whole-list snapshot read (the transport-bridge face: the list
    /// goes to consumers like hyper's Happy Eyeballs). Hit domain and
    /// eviction semantics as in [`Self::get_family`].
    pub fn get_list(&mut self, host: &str, now: Instant) -> Option<Vec<IpAddr>> {
        self.get_result(host, now)?.ok()
    }

    fn get_result(
        &mut self,
        host: &str,
        now: Instant,
    ) -> Option<Result<Vec<IpAddr>, ResolveError>> {
        let (result, inserted_at, ttl) = self.entries.get(host)?;
        if now.saturating_duration_since(*inserted_at) >= *ttl {
            self.entries.remove(host);
            self.order.retain(|entry| entry != host);
            if let Some(metrics) = &self.metrics {
                metrics.dns().note_cache_event(DnsCacheEvent::EvictTtl);
            }
            return None;
        }
        Some(result.clone())
    }

    fn remove(&mut self, host: &str) {
        self.entries.remove(host);
        self.order.retain(|entry| entry != host);
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// Per-family projection read: the **first** address of the family
    /// in the list; a present list with no record for the family = None
    /// (for [`SharedDns`] this is still a "hit" — the whole list is the
    /// authoritative answer, and an empty projection must not trigger a
    /// re-query).
    pub fn get_family(
        &mut self,
        host: &str,
        family: ResolveFamily,
        now: Instant,
    ) -> Option<IpAddr> {
        let addrs = self.get_list(host, now)?;
        pick_ip_family(&addrs, family).ok()
    }

    /// Single-address view (read = v4-first, else the first v6).
    pub fn get(&mut self, host: &str, now: Instant) -> Option<IpAddr> {
        let addrs = self.get_list(host, now)?;
        pick_ip(&addrs)
    }

    /// Positive whole-list backfill. Empty successful lists are not stored.
    /// An existing entry refreshes its list and timestamp (order
    /// position unchanged); at capacity the oldest by insertion order is
    /// evicted.
    pub(crate) fn insert_list(&mut self, host: String, addrs: Vec<IpAddr>, now: Instant) {
        if !addrs.is_empty() {
            self.insert_result(host, Ok(addrs), now, self.ttl);
        }
    }

    fn insert_result(
        &mut self,
        host: String,
        result: Result<Vec<IpAddr>, ResolveError>,
        now: Instant,
        ttl: Duration,
    ) {
        if self.capacity == 0 || ttl.is_zero() {
            return;
        }
        if !self.entries.contains_key(&host) {
            while self.entries.len() >= self.capacity {
                if let Some(oldest) = self.order.pop_front() {
                    self.entries.remove(&oldest);
                    if let Some(metrics) = &self.metrics {
                        metrics.dns().note_cache_event(DnsCacheEvent::EvictCapacity);
                    }
                } else {
                    break;
                }
            }
            self.order.push_back(host.clone());
        }
        self.entries.insert(host, (result, now, ttl));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_expiry_reinsertion_and_negative_entries_share_bounded_order() {
        let ttl = Duration::from_secs(1);
        let mut cache = HostCache::new(ttl, 2);
        let mut now = Instant::now();
        let address = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        for _ in 0..10_000 {
            cache.insert_list("repeated.test".into(), vec![address], now);
            now += ttl;
            assert!(cache.get_result("repeated.test", now).is_none());
            assert!(cache.order.is_empty());
        }
        cache.insert_list("older.test".into(), vec![address], now);
        cache.insert_list("repeated.test".into(), vec![address], now);
        cache.insert_result(
            "negative.test".into(),
            Err(ResolveError::Failed("temporary".into())),
            now,
            ttl,
        );
        assert_eq!(cache.entries.len(), 2);
        assert_eq!(cache.order.len(), 2);
        assert_eq!(cache.get_list("repeated.test", now), Some(vec![address]));
        assert!(cache.get_result("older.test", now).is_none());
    }

    /// Routing table: v4-first takes the first v4 (even if v6 comes
    /// first); v6-only → first v6; empty → Err.
    #[test]
    fn pick_addr_prefers_first_ipv4_then_first_ipv6() {
        let v4a = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 0);
        let v4b = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)), 0);
        let v6a = SocketAddr::new(
            IpAddr::V6("2001:db8::1".parse().unwrap_or_else(|e| panic!("{e}"))),
            0,
        );
        let v6b = SocketAddr::new(
            IpAddr::V6("2001:db8::2".parse().unwrap_or_else(|e| panic!("{e}"))),
            0,
        );
        let cases: &[(Vec<SocketAddr>, Result<IpAddr, &str>)] = &[
            (vec![v6a, v4a, v6b, v4b], Ok(v4a.ip())),
            (vec![v4a, v4b], Ok(v4a.ip())),
            (vec![v6a, v6b], Ok(v6a.ip())),
            (vec![], Err("no address resolved")),
        ];
        for (addrs, want) in cases {
            let got = pick_addr(addrs);
            match want {
                Ok(ip) => assert_eq!(got.unwrap_or_else(|e| panic!("{e}")), *ip),
                Err(msg) => assert!(
                    matches!(&got, Err(e) if e.as_str() == *msg),
                    "want Err({msg}), got {got:?}"
                ),
            }
        }
    }

    /// Hit domain = [insert, insert+TTL) (evicted exactly at expiry);
    /// an expired get returns None and the entry is cleared.
    #[test]
    fn host_cache_hit_within_ttl_and_expiry() {
        let mut cache = HostCache::with_defaults();
        let t0 = Instant::now();
        let ip: IpAddr = "127.0.0.1".parse().unwrap_or_else(|e| panic!("{e}"));
        cache.insert_list("t.example".to_string(), vec![ip], t0);
        assert_eq!(cache.get("t.example", t0), Some(ip));
        assert_eq!(
            cache.get("t.example", t0 + HOST_CACHE_TTL - Duration::from_nanos(1)),
            Some(ip),
            "hit within TTL (including the instant before expiry)"
        );
        assert!(
            cache.get("t.example", t0 + HOST_CACHE_TTL).is_none(),
            "evicted exactly at expiry"
        );
        // After eviction the capacity slot is freed (reinsertion does
        // not grow it).
        assert_eq!(cache.entries.len(), 0);
        assert_eq!(
            cache.order.len(),
            0,
            "expiration removes ordering state too"
        );
    }

    /// Reinsertion refreshes the list and timestamp (order position
    /// unchanged, no duplicates).
    #[test]
    fn host_cache_reinsert_refreshes_without_duplicating_order() {
        let mut cache = HostCache::with_defaults();
        let t0 = Instant::now();
        let a: IpAddr = "127.0.0.1".parse().unwrap_or_else(|e| panic!("{e}"));
        let b: IpAddr = "127.0.0.2".parse().unwrap_or_else(|e| panic!("{e}"));
        cache.insert_list("t.example".to_string(), vec![a], t0);
        cache.insert_list(
            "t.example".to_string(),
            vec![b],
            t0 + Duration::from_secs(1),
        );
        assert_eq!(cache.order.len(), 1);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(
            cache.get("t.example", t0 + Duration::from_secs(2)),
            Some(b),
            "refreshed list returned"
        );
        // TTL restarts from the refreshed timestamp (hit domain
        // [insert, insert+TTL)).
        assert!(
            cache
                .get(
                    "t.example",
                    t0 + Duration::from_secs(1) + HOST_CACHE_TTL - Duration::from_nanos(1)
                )
                .is_some()
        );
    }

    /// Capacity-bounded: beyond it the oldest by insertion order is
    /// evicted (256 → the 257th evicts the earliest; small capacities
    /// prove the order directly). Capacity counts host entries (per-host
    /// whole lists; both families of one domain share one entry).
    #[test]
    fn host_cache_capacity_evicts_oldest() {
        // Default capacity constants locked.
        assert_eq!(HOST_CACHE_CAPACITY, 256);
        assert!(
            HOST_CACHE_TTL >= Duration::from_secs(300),
            "default TTL >= 5min"
        );
        let mut cache = HostCache::new(Duration::from_secs(300), 2);
        let t0 = Instant::now();
        let ip_of = |o: u8| -> IpAddr { IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, o)) };
        cache.insert_list("a".to_string(), vec![ip_of(1)], t0);
        cache.insert_list("b".to_string(), vec![ip_of(2)], t0);
        cache.insert_list("c".to_string(), vec![ip_of(3)], t0); // evicts "a"
        assert!(cache.get("a", t0).is_none(), "oldest entry a evicted");
        assert_eq!(cache.get("b", t0), Some(ip_of(2)));
        assert_eq!(cache.get("c", t0), Some(ip_of(3)));
        assert_eq!(cache.entries.len(), 2, "capacity bounded");
        // A dual-family whole list is a single entry (families do not
        // split capacity).
        cache.insert_list(
            "d".to_string(),
            vec![ip_of(4), v6_addr(4)],
            t0 + Duration::from_secs(1),
        );
        assert_eq!(
            cache.entries.len(),
            2,
            "d (dual-family list) is a single cache entry after b is evicted"
        );
        assert_eq!(cache.get("d", t0 + Duration::from_secs(1)), Some(ip_of(4)));
    }

    // ===== Per-family resolution + per-family cache =====

    fn v6_addr(octet: u8) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            0,
            0,
            0,
            0,
            u16::from(octet),
        ))
    }

    fn sa(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 0)
    }

    /// Per-family routing table: only the first address of the requested
    /// family, no cross-family fallback (module-header note).
    #[test]
    fn pick_addr_family_filters_without_cross_family_fallback() {
        let v4a = sa(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        let v4b = sa(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)));
        let v6a = sa(v6_addr(1));
        let v6b = sa(v6_addr(2));
        let cases: &[(Vec<SocketAddr>, ResolveFamily, Result<IpAddr, &str>)] = &[
            // Mixed list: take the first of the family (order-independent).
            (vec![v6a, v4a, v6b, v4b], ResolveFamily::V4, Ok(v4a.ip())),
            (vec![v6a, v4a, v6b, v4b], ResolveFamily::V6, Ok(v6a.ip())),
            // v6-only: a V4 request = Err (no fallback).
            (
                vec![v6a, v6b],
                ResolveFamily::V4,
                Err("no ipv4 address (A) resolved"),
            ),
            // v4-only: a V6 request = Err (no fallback).
            (
                vec![v4a],
                ResolveFamily::V6,
                Err("no ipv6 address (AAAA) resolved"),
            ),
            (
                vec![],
                ResolveFamily::V6,
                Err("no ipv6 address (AAAA) resolved"),
            ),
        ];
        for (addrs, family, want) in cases {
            let got = pick_addr_family(addrs, *family);
            match want {
                Ok(ip) => assert_eq!(
                    got.unwrap_or_else(|e| panic!("{e}")),
                    *ip,
                    "family={family:?}"
                ),
                Err(msg) => assert!(
                    matches!(&got, Err(e) if e.as_str() == *msg),
                    "family={family:?} want Err({msg}), got {got:?}"
                ),
            }
        }
    }

    /// Fixed-address stub (validates the default
    /// [`HostResolver::resolve_family`] behavior).
    struct FixedResolver(IpAddr);

    impl HostResolver for FixedResolver {
        fn resolve(&self, _host: String) -> ResolverFuture {
            Box::pin(std::future::ready(Ok(self.0)))
        }
    }

    /// Default resolve_family: a V4 request filters the resolve result
    /// by family (a v6 result → Err "no A record"); a V6 request is an
    /// explicit Err (a single-address resolver has no AAAA face and does
    /// not call the underlying resolve).
    #[tokio::test]
    async fn resolve_family_default_v4_filters_and_v6_unsupported() {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        // V4 request + v4 result → pass-through.
        let got = FixedResolver(v4)
            .resolve_family("h.example".to_string(), ResolveFamily::V4)
            .await;
        assert_eq!(got.unwrap_or_else(|e| panic!("{e}")), v4);
        // V4 request + v6-only result → Err (no cross-family fallback).
        let got = FixedResolver(v6_addr(1))
            .resolve_family("h.example".to_string(), ResolveFamily::V4)
            .await;
        assert!(
            matches!(&got, Err(e) if e == "no ipv4 address (A) resolved"),
            "v4 face of a v6-only host = no A record (retryable dns class): {got:?}"
        );
        // V6 request → AAAA unsupported by default (Err).
        let got = FixedResolver(v4)
            .resolve_family("h.example".to_string(), ResolveFamily::V6)
            .await;
        assert!(
            matches!(&got, Err(e) if e == "AAAA resolution unsupported by this resolver"),
            "default V6 path is explicitly unsupported: {got:?}"
        );
    }

    /// Per-host whole-list entries: one domain's A/AAAA share an entry;
    /// the per-family projection read = the list's first address of that
    /// family; the single-address view (read) keeps v4-first.
    #[test]
    fn host_cache_per_host_list_projection_views() {
        let mut cache = HostCache::with_defaults();
        let t0 = Instant::now();
        let v4a = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7));
        let v4b = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 8));
        let v6 = v6_addr(7);
        // A dual-family mixed list (two v4 + one v6) enters as a single
        // entry.
        cache.insert_list("d.example".to_string(), vec![v4a, v6, v4b], t0);
        assert_eq!(
            cache.entries.len(),
            1,
            "both families of one host share one entry (capacity semantics)"
        );
        // Per-family projection = the first address of that family
        // (list order, not "newest").
        assert_eq!(
            cache.get_family("d.example", ResolveFamily::V4, t0),
            Some(v4a)
        );
        assert_eq!(
            cache.get_family("d.example", ResolveFamily::V6, t0),
            Some(v6),
            "v6 projection read from the same entry"
        );
        // Whole-list snapshot (transport bridge face) preserves order
        // in full.
        assert_eq!(cache.get_list("d.example", t0), Some(vec![v4a, v6, v4b]));
        // Single-address view: v4-first.
        assert_eq!(cache.get("d.example", t0), Some(v4a));
        // v6-only list: the V4 projection is empty (None — "a hit is
        // authoritative" for that projection, interpreted by SharedDns);
        // the single-address view falls back to the first v6.
        cache.insert_list("solo.example".to_string(), vec![v6], t0);
        assert_eq!(
            cache.get_family("solo.example", ResolveFamily::V4, t0),
            None
        );
        assert_eq!(cache.get("solo.example", t0), Some(v6));
        // Empty successful lists are not stored as positive cache entries.
        cache.insert_list("empty.example".to_string(), vec![], t0);
        assert!(cache.get_list("empty.example", t0).is_none());
    }

    /// `IpAddr` list-projection routing table (pick_ip / pick_ip_family).
    #[test]
    fn pick_ip_helpers_table() {
        let v4a = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let v4b = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
        let v6a = v6_addr(1);
        let v6b = v6_addr(2);
        // pick_ip: v4-first (even if v6 comes first); v6-only → first
        // v6; empty → None.
        assert_eq!(pick_ip(&[v6a, v4a, v6b, v4b]), Some(v4a));
        assert_eq!(pick_ip(&[v6a, v6b]), Some(v6a));
        assert_eq!(pick_ip(&[]), None);
        // pick_ip_family: first of the family, no cross-family fallback;
        // no record → Err.
        assert_eq!(pick_ip_family(&[v6a, v4a], ResolveFamily::V4), Ok(v4a));
        assert_eq!(pick_ip_family(&[v6a, v4a], ResolveFamily::V6), Ok(v6a));
        assert!(matches!(
            pick_ip_family(&[v6a], ResolveFamily::V4),
            Err(e) if e == "no ipv4 address (A) resolved"
        ));
        assert!(matches!(
            pick_ip_family(&[v4a], ResolveFamily::V6),
            Err(e) if e == "no ipv6 address (AAAA) resolved"
        ));
    }

    // ===== Resolution timeout decorator =====

    /// Hanging stub (resolution never completes — models a hung
    /// getaddrinfo; timeout behavior is driven entirely by the injected
    /// short deadline, no real DNS — the design ban migrated with the
    /// module covers this side).
    struct HangingResolver;

    impl HostResolver for HangingResolver {
        fn resolve(&self, _host: String) -> ResolverFuture {
            Box::pin(std::future::pending())
        }

        fn resolve_family(&self, _host: String, _family: ResolveFamily) -> ResolverFuture {
            Box::pin(std::future::pending())
        }
    }

    /// Hanging inner + injected short deadline → timeout Err (message
    /// contains "timed out"), and the return latency is bounded (far
    /// below the default 30s — direct proof that the parameterized
    /// deadline is testable).
    #[tokio::test]
    async fn timeout_resolver_hanging_inner_times_out_with_injected_short_duration() {
        let resolver =
            TimeoutResolver::with_timeout(Arc::new(HangingResolver), Duration::from_millis(50));
        let t0 = Instant::now();
        let got = resolver.resolve("h.example".to_string()).await;
        assert!(
            matches!(&got, Err(e) if e.contains("timed out")),
            "timeout shape Err(...timed out...), got {got:?}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "short deadline returns promptly, does not hang on the default 30s (elapsed {:?})",
            t0.elapsed()
        );
    }

    /// The per-family path is timeout-protected too (both families
    /// proven directly — the decorator overrides `resolve_family`, not
    /// just the default impl indirectly via `resolve`).
    #[tokio::test]
    async fn timeout_resolver_covers_resolve_family_both_families() {
        for family in [ResolveFamily::V4, ResolveFamily::V6] {
            let resolver =
                TimeoutResolver::with_timeout(Arc::new(HangingResolver), Duration::from_millis(50));
            let got = resolver
                .resolve_family("h.example".to_string(), family)
                .await;
            assert!(
                matches!(&got, Err(e) if e.contains("timed out")),
                "family={family:?} timeout shape Err, got {got:?}"
            );
        }
    }

    /// The whole-list path is timeout-protected too (the decorator
    /// overrides `resolve_list`, not the default impl's two per-family
    /// queries indirectly): hanging inner + short deadline → timeout
    /// Err.
    #[tokio::test]
    async fn timeout_resolver_covers_resolve_list() {
        let resolver =
            TimeoutResolver::with_timeout(Arc::new(HangingResolver), Duration::from_millis(50));
        let t0 = Instant::now();
        let got = resolver.resolve_list("h.example".to_string()).await;
        assert!(
            matches!(&got, Err(e) if e.contains("timed out")),
            "whole-list timeout shape Err, got {got:?}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "short deadline returns promptly (elapsed {:?})",
            t0.elapsed()
        );
    }

    /// The decorator **forwards the inner `resolve_list` whole** (no
    /// per-family split): the counting list stub is called exactly once
    /// and the within-deadline result passes through unchanged — direct
    /// proof that [`TokioHostResolver`]'s single whole-list query reaches
    /// through the decorator (a split would lose the 2→1 win).
    #[tokio::test]
    async fn timeout_resolver_forwards_resolve_list_without_family_split() {
        #[derive(Clone)]
        struct ListCounting {
            addrs: Vec<IpAddr>,
            calls: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl HostResolver for ListCounting {
            fn resolve(&self, _host: String) -> ResolverFuture {
                // The single-address face must not be reached by the
                // whole-list path.
                Box::pin(std::future::ready(Ok(self.addrs[0])))
            }
            fn resolve_list(&self, _host: String) -> ListResolverFuture {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let addrs = self.addrs.clone();
                Box::pin(std::future::ready(Ok(addrs)))
            }
        }
        let v4 = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let inner = ListCounting {
            addrs: vec![v4],
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let resolver =
            TimeoutResolver::with_timeout(Arc::new(inner.clone()), Duration::from_secs(5));
        let got = resolver.resolve_list("h.example".to_string()).await;
        assert_eq!(
            got.unwrap_or_else(|e| panic!("{e}")),
            vec![v4],
            "within-deadline result passes through unchanged"
        );
        assert_eq!(
            inner.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "inner resolve_list called exactly once (forwarded whole, no family split)"
        );
    }

    /// Within-deadline inner results pass through unchanged (neither Ok
    /// nor Err is rewritten by the decorator — the timeout layer only
    /// adds a failure face, it does not alter existing semantics).
    #[tokio::test]
    async fn timeout_resolver_passthrough_within_deadline() {
        let ok_v4 = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let resolver =
            TimeoutResolver::with_timeout(Arc::new(FixedResolver(ok_v4)), Duration::from_secs(5));
        let got = resolver.resolve("h.example".to_string()).await;
        assert_eq!(got, Ok(ok_v4), "Ok passes through");

        struct FailingResolver;
        impl HostResolver for FailingResolver {
            fn resolve(&self, _host: String) -> ResolverFuture {
                Box::pin(std::future::ready(Err("stub failure".to_string())))
            }
        }
        let resolver =
            TimeoutResolver::with_timeout(Arc::new(FailingResolver), Duration::from_secs(5));
        let got = resolver.resolve("h.example".to_string()).await;
        assert!(
            matches!(&got, Err(e) if e == "stub failure"),
            "inner Err passes through unchanged (not rewritten by the timeout layer), got {got:?}"
        );
    }

    /// Default deadline constant = 30s (reference anchor: aria2
    /// `--dns-timeout` default 30, `OptionHandlerFactory.cc`).
    #[test]
    fn dns_timeout_default_is_30s() {
        assert_eq!(DNS_TIMEOUT, Duration::from_secs(30));
    }

    /// Typed boundary error Display contract (consumed at the transport
    /// wiring layer — see the type docs; locks the message shape against
    /// drift).
    #[test]
    fn resolve_error_display_contract() {
        assert_eq!(
            ResolveError::Timeout(Duration::from_secs(30)).to_string(),
            "dns resolution timed out after 30s"
        );
        assert_eq!(
            ResolveError::Failed("no address resolved".to_string()).to_string(),
            "dns resolution failed: no address resolved"
        );
    }

    // ===== Whole-list resolution (resolve_list) and the shared service
    // (SharedDns) =====

    /// Counting stub (single-address face): counts resolve calls; a
    /// table miss → Err.
    #[derive(Clone)]
    struct CountingStub {
        result: Result<IpAddr, String>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingStub {
        fn ok(ip: IpAddr) -> Self {
            CountingStub {
                result: Ok(ip),
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn err(msg: &str) -> Self {
            CountingStub {
                result: Err(msg.to_string()),
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl HostResolver for CountingStub {
        fn resolve(&self, _host: String) -> ResolverFuture {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let result = self.result.clone();
            Box::pin(std::future::ready(result))
        }
    }

    /// Default resolve_list (single-address stub): resolve called
    /// exactly once (the default V6 face is explicitly unsupported and
    /// does not touch the underlying call) → a single-address list.
    #[tokio::test]
    async fn resolve_list_default_single_address_stub_queries_once() {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let stub = CountingStub::ok(v4);
        let got = stub.resolve_list("h.example".to_string()).await;
        assert_eq!(got.unwrap_or_else(|e| panic!("{e}")), vec![v4]);
        assert_eq!(stub.calls(), 1, "single-address stub resolves exactly once");
    }

    /// Default resolve_list with both families failing: Err takes the
    /// V4-side error (the real failure detail is on the V4 face; the V6
    /// "unsupported" is a default-impl artifact).
    #[tokio::test]
    async fn resolve_list_default_both_fail_prefers_v4_error() {
        let stub = CountingStub::err("nxdomain");
        let got = stub.resolve_list("dead.example".to_string()).await;
        assert!(
            matches!(&got, Err(e) if e == "nxdomain"),
            "V4-side error passes through, got {got:?}"
        );
        assert_eq!(stub.calls(), 1);
    }

    /// Default resolve_list (per-family stub override): both families
    /// merged into a whole list; any one family succeeding is Ok (the
    /// other failing = no records of that family, not an overall
    /// failure).
    #[tokio::test]
    async fn resolve_list_default_merges_both_families_partial_ok() {
        let v6 = v6_addr(3);
        struct V6Only;
        impl HostResolver for V6Only {
            fn resolve(&self, _host: String) -> ResolverFuture {
                Box::pin(std::future::ready(Err("no A record".to_string())))
            }
            fn resolve_family(&self, _host: String, family: ResolveFamily) -> ResolverFuture {
                match family {
                    ResolveFamily::V4 => {
                        Box::pin(std::future::ready(Err("no A record".to_string())))
                    }
                    ResolveFamily::V6 => Box::pin(std::future::ready(Ok(IpAddr::V6(
                        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3),
                    )))),
                }
            }
        }
        let got = V6Only.resolve_list("v6.example".to_string()).await;
        assert_eq!(got.unwrap_or_else(|e| panic!("{e}")), vec![v6]);
    }

    /// SharedDns counting assertions (both directions: first query ≥1 +
    /// a second query on the same host adds 0) and whole-list caching +
    /// per-family projection (v6-only list: V6 Ok / V4 Err without
    /// re-query).
    #[tokio::test]
    async fn shared_dns_caches_whole_list_and_projects_by_family() {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::new(10, 9, 9, 9));
        let stub = CountingStub::ok(v4);
        let dns = SharedDns::with_resolver(Arc::new(stub.clone()));

        // First query: miss → resolve_list (stub resolve once) →
        // projection.
        let got = dns
            .resolve_family("a.example".to_string(), ResolveFamily::V4)
            .await;
        assert_eq!(got.unwrap_or_else(|e| panic!("{e}")), v4);
        assert_eq!(
            stub.calls(),
            1,
            "exactly one underlying call on first query"
        );

        // Second query on the same host (both families + transport
        // face): cache hit, zero added calls.
        assert_eq!(
            dns.resolve_family("a.example".to_string(), ResolveFamily::V4)
                .await
                .unwrap_or_else(|e| panic!("{e}")),
            v4
        );
        let transport = dns
            .resolve_for_transport("a.example", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(transport, vec![SocketAddr::new(v4, 0)]);
        assert_eq!(
            stub.calls(),
            1,
            "cache hit sends no query (zero-added side of the bidirectional assertion)"
        );

        // The V6 face of a v4-only list: empty-projection Err without
        // re-query (whole list authoritative).
        let got = dns
            .resolve_family("a.example".to_string(), ResolveFamily::V6)
            .await;
        assert!(
            matches!(&got, Err(e) if e == "no ipv6 address (AAAA) resolved"),
            "empty-projection Err shape, got {got:?}"
        );
        assert_eq!(
            stub.calls(),
            1,
            "empty projection does not re-query (pinned within TTL)"
        );

        // Failed lookups are cached briefly to suppress repeated bursts.
        let dead = CountingStub::err("nxdomain");
        let dns = SharedDns::with_resolver(Arc::new(dead.clone()));
        for i in 1..=2 {
            let got = dns
                .resolve_family("dead.example".to_string(), ResolveFamily::V4)
                .await;
            assert!(
                matches!(&got, Err(e) if e == "nxdomain"),
                "failure on attempt {i}"
            );
        }
        assert_eq!(
            dead.calls(),
            1,
            "short negative cache coalesces repeated failure"
        );
    }

    /// Transport-bridge literal passthrough (zero resolution — stub
    /// count 0) and port synthesis, positive and negative: the port is
    /// always synthesized from the call arguments (the reqwest face's
    /// port 0 goes to hyper-util as-is to fill; direct faces use the real
    /// port directly); cache entries carry no port.
    #[tokio::test]
    async fn resolve_for_transport_literal_bypass_and_port_synthesis() {
        let stub = CountingStub::ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let dns = SharedDns::with_resolver(Arc::new(stub.clone()));
        let v4: IpAddr = "192.0.2.10".parse().unwrap_or_else(|e| panic!("{e}"));
        let v6: IpAddr = "2001:db8::10".parse().unwrap_or_else(|e| panic!("{e}"));

        // Literal passthrough: v4/v6 both resolve zero times, the port
        // is synthesized from the argument (reqwest face 0).
        let got = dns
            .resolve_for_transport("192.0.2.10", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, vec![SocketAddr::new(v4, 0)]);
        let got = dns
            .resolve_for_transport("2001:db8::10", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, vec![SocketAddr::new(v6, 0)]);
        // Direct faces use the real port directly.
        let got = dns
            .resolve_for_transport("192.0.2.10", 8080)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, vec![SocketAddr::new(v4, 8080)]);
        assert_eq!(stub.calls(), 0, "literal hosts cost zero resolutions");

        // Domain path: first query with port 0 (reqwest shape) →
        // backfills the cache; second query with port 6969 (direct
        // shape) → the port is synthesized from **this request's**
        // argument (cache entries are IpAddr only, no port carried —
        // different port requests do not cross-contaminate) with zero
        // added queries.
        let stub_ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let got = dns
            .resolve_for_transport("p.example", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got.last().copied(), Some(SocketAddr::new(stub_ip, 0)));
        assert_eq!(stub.calls(), 1);
        let got = dns
            .resolve_for_transport("p.example", 6969)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            got.last().copied(),
            Some(SocketAddr::new(stub_ip, 6969)),
            "port re-synthesized from this call's arguments (cache entries carry IpAddr only)"
        );
        assert_eq!(
            stub.calls(),
            1,
            "second query on the same host adds zero (cache hit)"
        );

        // Failure face: ResolveError::Failed carries the trait String
        // type-preserving.
        let dead = CountingStub::err("nxdomain");
        let dns = SharedDns::with_resolver(Arc::new(dead));
        let got = dns.resolve_for_transport("dead.example", 0).await;
        assert!(
            matches!(&got, Err(ResolveError::Failed(e)) if e == "nxdomain"),
            "got {got:?}"
        );
    }

    /// Type-preserving boxing helper: downcast recovers the
    /// [`ResolveError`] (direct proof of type survival, which the
    /// source-chain classification face depends on; `to_string()` boxing
    /// loses this ability).
    #[test]
    fn box_resolve_error_keeps_type_alive_for_downcast() {
        let boxed = box_resolve_error(ResolveError::Timeout(DNS_TIMEOUT));
        let down = boxed
            .downcast_ref::<ResolveError>()
            .unwrap_or_else(|| panic!("downcast failed = type chain broken"));
        assert!(
            matches!(down, ResolveError::Timeout(d) if *d == DNS_TIMEOUT),
            "got {down:?}"
        );
    }

    // ===== Error-chain DNS attribution core (error_chain_is_dns) =====

    /// Test chain construction: single-layer wrappers (custom Display
    /// text + source pointing at the inner layer) modeling reqwest/
    /// hyper-util's layer-by-layer source passthrough — the downcast arm
    /// must pass through the wrappers to hit the inner
    /// [`ResolveError`].
    struct ChainLink {
        display: String,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    }

    impl std::fmt::Display for ChainLink {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.display)
        }
    }

    impl std::fmt::Debug for ChainLink {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ChainLink({:?})", self.display)
        }
    }

    impl std::error::Error for ChainLink {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source
                .as_ref()
                .map(|b| b.as_ref() as &(dyn std::error::Error + 'static))
        }
    }

    /// Table-driven positives and negatives: a real type-preserving
    /// [`ResolveError`] chain hits (no dns text on the chain — only
    /// downcast can); pure io errors are not misattributed; a
    /// `to_string()`-broken chain still reaches the text fallback;
    /// chains without dns text are always false.
    #[test]
    fn error_chain_is_dns_downcast_first_text_fallback() {
        // Positive 1 (downcast arm proven): ResolveError is carried
        // type-preserving under two wrappers, and the whole chain's
        // Display **lacks** "dns error"/"failed to lookup" text
        // (ResolveError's own Display is "dns resolution ...") — a hit
        // can only come from the source-chain downcast.
        let inner = box_resolve_error(ResolveError::Timeout(Duration::from_millis(50)));
        let wrapped = ChainLink {
            display: "client error (connect)".to_string(),
            source: Some(Box::new(ChainLink {
                display: "wrapped transport failure".to_string(),
                source: Some(inner),
            })),
        };
        assert!(
            error_chain_is_dns(&wrapped),
            "type-preserving chain (no dns text) must hit via downcast"
        );

        // Positive 2 (direct form): a bare ResolveError.
        assert!(error_chain_is_dns(&ResolveError::Failed(
            "nxdomain".to_string()
        )));

        // Positive 3 (text fallback): the `to_string()` broken-chain
        // case — only a string remains (no ResolveError type to
        // downcast), but the Display text still carries the historical
        // wording → the fallback arm hits (degraded, not dead).
        let stringified = ChainLink {
            display: "dns error: failed to lookup address information: \
                      name or service not known"
                .to_string(),
            source: None,
        };
        assert!(
            error_chain_is_dns(&stringified),
            "broken-chain form still attributes to dns via the text fallback"
        );

        // Negative 1 (pure io not misattributed): a connection-refused
        // io error chain (no dns type, no dns text).
        let io_refused = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "tcp connect error: connection refused (os error 61)",
        );
        assert!(
            !error_chain_is_dns(&io_refused),
            "pure io errors must not be misattributed to dns"
        );

        // Negative 2: io wrapping io (multi-layer chain, no dns face).
        let io_wrapped = ChainLink {
            display: "client error (connect)".to_string(),
            source: Some(Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused",
            ))),
        };
        assert!(!error_chain_is_dns(&io_wrapped));

        // Negative 3 (broken chain, no dns text): neither type nor text
        // → not dns (an honest miss — the reason the type-preservation
        // discipline exists).
        let broken = ChainLink {
            display: "dns resolution failed: nxdomain".to_string(),
            source: None,
        };
        assert!(
            !error_chain_is_dns(&broken),
            "broken chain with no historical wording = not attributable (ResolveError's own \
             Display stays out of the fallback word list to prevent a self-confirming loop)"
        );
    }

    // ===== Transport error classification single source
    // (classify_error_chain) table positives/negatives =====

    /// Classification-seam positives: typed chains attributed
    /// type-preserving (the shared resolver's [`box_resolve_error`] box
    /// still downcasts under reqwest-style wrappers) and pure io kind
    /// attribution (errno facts, immune to wording drift).
    #[test]
    fn classify_chain_positive_table() {
        use DnsPersistence::{Permanent, Transient};
        // Positive 1: a real ResolveError passes type-preserving through
        // two wrappers (connect-class wording in the upper layers must
        // not shadow a deep dns attribution — the regression face of the
        // per-class scan order).
        let inner = box_resolve_error(ResolveError::Failed("nxdomain".into()));
        let wrapped = ChainLink {
            display: "client error (connect)".to_string(),
            source: Some(Box::new(ChainLink {
                display: "error sending request".to_string(),
                source: Some(inner),
            })),
        };
        assert_eq!(
            classify_error_chain(
                TransportHints {
                    connect: true,
                    timeout: false
                },
                &wrapped
            ),
            TransportErrorClass::Dns(Permanent),
            "type-preserving chain downcast first; the connect hint does not shadow it"
        );
        // Positive 2: ResolveError::Timeout = transient.
        let boxed = box_resolve_error(ResolveError::Timeout(Duration::from_millis(50)));
        assert_eq!(
            classify_error_chain(TransportHints::default(), boxed.as_ref()),
            TransportErrorClass::Dns(Transient),
            "resolution timeout classified transient"
        );
        // Positive 3: EAI_NONAME text (Linux form) → permanent.
        let linux = ChainLink {
            display: "error sending request for url (redacted)".to_string(),
            source: Some(Box::new(ChainLink {
                display: "client error (connect): dns error: failed to lookup \
                          address information: Name or service not known"
                    .to_string(),
                source: None,
            })),
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &linux),
            TransportErrorClass::Dns(Permanent),
            "EAI_NONAME text classified permanent (NXDOMAIN class)"
        );
        // Positive 4: EAI_AGAIN text → transient.
        let again = ChainLink {
            display: "dns error: failed to lookup address information: \
                      Temporary failure in name resolution"
                .to_string(),
            source: None,
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &again),
            TransportErrorClass::Dns(Transient),
            "EAI_AGAIN classified transient"
        );
        // Positive 5: io kind read directly — refused/reset/timeout
        // (kernel errno).
        let io_refused = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "tcp connect error: connection refused (os error 61)",
        );
        assert_eq!(
            classify_error_chain(TransportHints::default(), &io_refused),
            TransportErrorClass::Refused
        );
        let io_reset_wrapped = ChainLink {
            display: "error decoding response body: connection error".to_string(),
            source: Some(Box::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection reset by peer (os error 54)",
            ))),
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &io_reset_wrapped),
            TransportErrorClass::Reset
        );
        let io_timeout = ChainLink {
            display: "error reading a body from connection".to_string(),
            source: Some(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "operation timed out",
            ))),
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &io_timeout),
            TransportErrorClass::Timeout
        );
        // Positive 6: TLS text (rustls errors do not surface as io
        // kinds — the text fallback reaches).
        let tls = ChainLink {
            display: "client error (connect)".to_string(),
            source: Some(Box::new(ChainLink {
                display: "invalid peer certificate: UnknownIssuer".to_string(),
                source: None,
            })),
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &tls),
            TransportErrorClass::Tls
        );
        // Positive 7: hyper mid-stream close text (a broken chain with
        // no io source) → reset.
        let halfclosed = ChainLink {
            display: "error decoding response body: connection closed before \
                      message completed"
                .to_string(),
            source: None,
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &halfclosed),
            TransportErrorClass::Reset
        );
    }

    /// Classification-seam negatives: pure io connection refusal is not
    /// misattributed to dns; a chain with no markers classifies Other
    /// (not counted — the honest reading); the hints backstop applies
    /// when text matches nothing.
    #[test]
    fn classify_chain_negative_table() {
        // Negative 1: a pure io refused chain is not misattributed to
        // dns (connect text in the upper layer likewise causes no dns
        // misattribution).
        let io_refused =
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        assert_eq!(
            classify_error_chain(TransportHints::default(), &io_refused),
            TransportErrorClass::Refused,
            "pure io errors classify refused, not misattributed to dns"
        );
        // Negative 2: no type, no marker text → Other (Other does not
        // enter the errors count — upper-layer note_error always
        // skips).
        let opaque = ChainLink {
            display: "error sending request for url (redacted)".to_string(),
            source: None,
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &opaque),
            TransportErrorClass::Other,
            "marker-free chain honestly classifies Other"
        );
        // Negative 2b: broken chain with only ResolveError's own
        // Display wording ("dns resolution ...") → not dns
        // (self-confirmation-loop defense, same rule as `is_dns` — that
        // wording is deliberately absent from the text table).
        let broken = ChainLink {
            display: "dns resolution failed: nxdomain".to_string(),
            source: None,
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &broken),
            TransportErrorClass::Other,
            "broken chain with no historical wording = not attributable (honest miss)"
        );
        // Negative 3: the hints backstop applies only when the whole
        // chain has no markers (connect/timeout hints stand alone).
        assert_eq!(
            classify_error_chain(
                TransportHints {
                    connect: true,
                    timeout: false
                },
                &ChainLink {
                    display: "error sending request".into(),
                    source: None
                },
            ),
            TransportErrorClass::Connect,
            "connect hint fallback"
        );
        assert_eq!(
            classify_error_chain(
                TransportHints {
                    connect: false,
                    timeout: true
                },
                &ChainLink {
                    display: "error sending request".into(),
                    source: None
                },
            ),
            TransportErrorClass::Timeout,
            "timeout hint fallback"
        );
        // Negative 4: the text fallback still reaches (broken-chain
        // degradation is not dead) — the historical wording "dns error"
        // is in the table; the empty-address terminal message lands
        // permanent.
        let noaddr = ChainLink {
            display: "dns error: no address resolved".to_string(),
            source: None,
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &noaddr),
            TransportErrorClass::Dns(DnsPersistence::Permanent),
            "broken-chain text fallback still attributable (degraded, not dead; persistence judged by markers)"
        );
        // Negative 5: a dns word hits but no permanent marker →
        // transient by default (the misattribution direction takes the
        // safe side — burning retries beats losing self-healing).
        let plain_dns = ChainLink {
            display: "dns error: failed to lookup address information".to_string(),
            source: None,
        };
        assert_eq!(
            classify_error_chain(TransportHints::default(), &plain_dns),
            TransportErrorClass::Dns(DnsPersistence::Transient)
        );
    }

    /// ResolveError → persistence mapping table (reused by the FtpDns
    /// typed payload): timeout = transient; Failed by markers (nxdomain/
    /// no address = permanent, unknown wording conservatively
    /// transient).
    #[test]
    fn resolve_error_persistence_table() {
        use DnsPersistence::{Permanent, Transient};
        assert_eq!(
            dns_persistence_of(&ResolveError::Timeout(Duration::from_secs(30))),
            Transient
        );
        assert_eq!(
            dns_persistence_of(&ResolveError::Failed("nxdomain".into())),
            Permanent
        );
        assert_eq!(
            dns_persistence_of(&ResolveError::Failed("no address resolved".into())),
            Permanent
        );
        assert_eq!(
            dns_persistence_of(&ResolveError::Failed(
                "failed to lookup address information: \
                 Temporary failure in name resolution"
                    .into()
            )),
            Transient
        );
        assert_eq!(
            dns_persistence_of(&ResolveError::Failed("unmapped resolver text".into())),
            Transient,
            "marker-free wording conservatively transient (misattribution takes the safe side)"
        );
    }

    // ===== DNS metric feed points (independently injected registries;
    // stub faces, no real DNS) =====

    /// Whole-list stub (overrides `resolve_list` for whole-list
    /// production — direct proof of the family_mix three states; the
    /// single-address face only falls back to the first address).
    struct ListStub {
        addrs: Vec<IpAddr>,
    }

    impl HostResolver for ListStub {
        fn resolve(&self, _host: String) -> ResolverFuture {
            let first = self.addrs.first().copied();
            Box::pin(std::future::ready(
                first.ok_or_else(|| "empty stub".to_string()),
            ))
        }

        fn resolve_list(&self, _host: String) -> ListResolverFuture {
            let addrs = self.addrs.clone();
            Box::pin(std::future::ready(Ok(addrs)))
        }
    }

    /// hit/miss attribution + family_mix three states + histogram
    /// samples: first query miss, second hit (cache behavior); family_mix
    /// is counted only at the resolver's list production point (cache
    /// hits do not recount); the transport bridge and per-family faces
    /// share the single feed point.
    #[tokio::test]
    async fn shared_dns_metrics_hit_miss_family_mix_and_histogram() {
        let v4 = IpAddr::V4(std::net::Ipv4Addr::new(10, 20, 0, 1));
        let v6 = v6_addr(9);
        let registry = Arc::new(MetricsRegistry::new());
        let dns = SharedDns::with_registry(
            Arc::new(ListStub {
                addrs: vec![v4, v6],
            }),
            registry.clone(),
        );

        // First query: miss + dual-family list → dual.
        dns.resolve_family("mix.example".to_string(), ResolveFamily::V4)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let s = registry.snapshot().dns;
        assert_eq!(s.lookups_miss, 1);
        assert_eq!(s.lookups_hit, 0);
        assert_eq!(s.family_mix_dual, 1);
        assert_eq!(
            s.resolve_seconds.count, 1,
            "one histogram sample at the resolution exit"
        );

        // Second query (cache hit): hit; family_mix not recounted; the
        // histogram takes 1 more sample (no bucket-bound assertion — the
        // anti-flaky stance for near-zero real-clock samples).
        dns.resolve_family("mix.example".to_string(), ResolveFamily::V6)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let s = registry.snapshot().dns;
        assert_eq!(s.lookups_hit, 1);
        assert_eq!(s.lookups_miss, 1);
        assert_eq!(
            s.family_mix_dual, 1,
            "cache hit does not recount family_mix"
        );
        assert_eq!(s.resolve_seconds.count, 2);

        // The transport bridge shares the same feed point
        // (resolve_for_transport goes through the single source).
        dns.resolve_for_transport("mix.example", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let s = registry.snapshot().dns;
        assert_eq!(s.lookups_hit, 2, "bridge hit also counts hit");

        // Single-family list three-state proof: v4_only / v6_only
        // (independent registries each).
        let r4 = Arc::new(MetricsRegistry::new());
        let dns4 = SharedDns::with_registry(Arc::new(ListStub { addrs: vec![v4] }), r4.clone());
        dns4.resolve_for_transport("v4.example", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r4.snapshot().dns.family_mix_v4_only, 1);

        let r6 = Arc::new(MetricsRegistry::new());
        let dns6 = SharedDns::with_registry(Arc::new(ListStub { addrs: vec![v6] }), r6.clone());
        dns6.resolve_for_transport("v6.example", 0)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r6.snapshot().dns.family_mix_v6_only, 1);
    }

    /// Failure outcomes count per caller; a negative hit does not issue a
    /// backend query or increment cache misses.
    #[tokio::test]
    async fn shared_dns_metrics_error_double_counts_miss_and_error() {
        let registry = Arc::new(MetricsRegistry::new());
        let dead = CountingStub::err("nxdomain");
        let dns = SharedDns::with_registry(Arc::new(dead), registry.clone());
        for i in 1..=2 {
            let got = dns
                .resolve_family("dead.example".to_string(), ResolveFamily::V4)
                .await;
            assert!(
                matches!(&got, Err(e) if e == "nxdomain"),
                "failure on attempt {i}"
            );
        }
        let s = registry.snapshot().dns;
        assert_eq!(s.lookups_miss, 1, "only the first call misses the cache");
        assert_eq!(s.negative_hit, 1);
        assert_eq!(
            s.lookups_error, 2,
            "resolution failure +1 per attempt (miss+error double-count semantics)"
        );
        assert_eq!(
            s.lookups_timeout, 0,
            "error and timeout are mutually exclusive"
        );
        assert_eq!(s.lookups_hit, 0);
        assert_eq!(
            s.resolve_seconds.count, 2,
            "failure exits also observe latency"
        );
    }

    /// Timeout classification: the stack carries [`TimeoutResolver`]
    /// (hanging stub + short deadline injected) → the timeout fact is
    /// typed-produced at the decorator layer and classifies as
    /// `lookups{result=timeout}` rather than error (mutual exclusion
    /// proven); the trait-surface wording is verbatim-identical to the
    /// existing timeout path (zero behavior change).
    #[tokio::test]
    async fn shared_dns_metrics_timeout_classified_at_decorator_layer() {
        let registry = Arc::new(MetricsRegistry::new());
        let timed = Arc::new(TimeoutResolver::with_timeout(
            Arc::new(HangingResolver),
            Duration::from_millis(50),
        ));
        let dns = SharedDns::with_timeout_resolver(timed, registry.clone());
        let got = dns
            .resolve_family("hang.example".to_string(), ResolveFamily::V4)
            .await;
        assert!(
            matches!(&got, Err(e) if e == "dns resolution timed out after 50ms"),
            "trait-surface wording verbatim-identical to the existing timeout path: {got:?}"
        );
        let s = registry.snapshot().dns;
        assert_eq!(s.lookups_miss, 1);
        assert_eq!(
            s.lookups_timeout, 1,
            "timeout classified as timeout (typed exit, not text matching)"
        );
        assert_eq!(s.lookups_error, 0, "timeout does not recount error");
        assert_eq!(s.resolve_seconds.count, 1);
    }

    /// HostCache's two eviction feed points: capacity eviction (an
    /// insert evicts the oldest) and TTL expiry (cleared on an expired
    /// read) each count once (synthetic clocks — no real waiting).
    #[test]
    fn host_cache_metrics_counts_both_eviction_points() {
        let registry = Arc::new(MetricsRegistry::new());
        let mut cache = HostCache::with_metrics(Duration::from_secs(60), 1, registry.clone());
        let t0 = Instant::now();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 30, 0, 1));
        cache.insert_list("a".to_string(), vec![ip], t0);
        // Capacity eviction: with capacity 1, inserting b evicts a.
        cache.insert_list("b".to_string(), vec![ip], t0);
        let s = registry.snapshot().dns;
        assert_eq!(s.events_evict_capacity, 1, "capacity-eviction feed point");
        assert_eq!(s.events_evict_ttl, 0);
        // TTL eviction: cleared by a read at expiry (hit domain
        // [insert, insert+TTL)).
        assert!(cache.get_list("b", t0 + Duration::from_secs(60)).is_none());
        let s = registry.snapshot().dns;
        assert_eq!(s.events_evict_ttl, 1, "TTL-expiry feed point");
        assert_eq!(
            s.events_evict_capacity, 1,
            "capacity count does not drift on TTL-expiry reads"
        );
    }
}

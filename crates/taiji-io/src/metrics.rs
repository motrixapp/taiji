//! Process-wide observability types and registry (counter / histogram).
//!
//! Placement in taiji-io: the observability primitives ([`Counter`] /
//! [`Histogram`]) let this crate's transport faces (the shared DNS
//! resolver layer and friends) count in place, aggregated and read out
//! by core's session snapshot over the crate's existing dependency
//! edge (`taiji-core -> taiji-io`) — zero dependency change on the rpc
//! rendering face. The histogram shape mirrors the core rpc latency
//! histogram: **non-cumulative bucket storage + rendering-side
//! cumulative conversion + microsecond integer sum + samples beyond
//! every bucket land only in count/sum** (the +Inf bucket equals
//! count, produced at the rendering face).
//!
//! # Injection seam (bare global counters banned)
//!
//! The registry is constructible and injectable
//! ([`MetricsRegistry::new`]); the production assembly point takes the
//! process-wide default instance [`registry_default`] (OnceLock —
//! cannot be swapped or reset, the same pattern as the shared resolver
//! service's process default instance). Components hosting feed points
//! (e.g. [`crate::dns::SharedDns`]) bind the process default instance
//! by default; tests inject an **independent registry** through the
//! construction seam so parallel tests in one process cannot pollute
//! each other's counts. A snapshot is a non-consistent read of many
//! atomics (each counter read independently with Relaxed; no
//! cross-field atomicity promise) — consumer projection tests must not
//! assert cross-field consistency.
//!
//! Feed-point discipline: no metric without a feed point; atomic
//! orderings are always `Ordering::Relaxed` (monotonic counters need
//! no synchronizing order).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// DNS resolve-latency histogram buckets (seconds; upper bound
/// inclusive). Arranged around consumer thresholds: sub-millisecond to
/// seconds covers the normal resolution domain (ms-level sightings);
/// the 30s upper bound = the [`crate::dns::DNS_TIMEOUT`] backstop (a
/// hung resolution's timeout lands in the last bucket). Consumers: the
/// DNS load-test resolve-latency component and the timeout observation.
pub const DNS_RESOLVE_BUCKETS_SECONDS: &[f64] =
    &[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0];

/// HTTP request-latency histogram buckets (seconds; upper bound
/// inclusive). Arranged around the extent-level consumption domain:
/// sub-100ms (pooled reuse / near source) to 5 minutes (slow-source
/// long extents — the "extent-level minutes domain"); consumers: the
/// TTFB / whole-request latency profiles.
pub const HTTP_REQUEST_BUCKETS_SECONDS: &[f64] =
    &[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 60.0, 300.0];

/// HTTP connection-establishment histogram buckets (seconds; upper
/// bound inclusive). Arranged around the connection-profile consumption
/// domain: sub-millisecond (loopback / the occasional post-warmup new
/// build) to 30s (the connect-timeout domain backstop); the 0.25 and
/// 0.5 buckets **straddle the 300ms happy-eyeballs interleave point**
/// (the typical interleave duration of v6 failing first and falling
/// back to v4 under dual-stack resolution); consumers: the connection
/// tax / connection profile.
pub const HTTP_CONN_ESTABLISH_BUCKETS_SECONDS: &[f64] =
    &[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0];

/// HTTP slow-start duration histogram buckets (seconds; upper bound
/// inclusive). Arranged around the AIMD slow-start ramp domain
/// (500ms..120s — the order-of-magnitude ceiling of the evaluation
/// window's doubling ramp x the cap of 16); consumers: slow-start
/// share / ramp-loss observations.
pub const HTTP_SLOWSTART_BUCKETS_SECONDS: &[f64] = &[0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0];

/// Disk/finalize completion histogram buckets (seconds; upper bound
/// inclusive; prealloc shares them). Arranged around the **SMB
/// long-tail domain**: millisecond local-disk positioning operations up
/// to 30s network-drive fsync / directory-flush tails (consumer: the
/// finalize/prealloc completion-phase profile — the observability face
/// of the Motrix PR #2132 SMB lesson).
pub const DISK_FINALIZE_BUCKETS_SECONDS: &[f64] = &[0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0];

/// Persistence commit histogram buckets (seconds; upper bound
/// inclusive). Arranged around the **single-row sqlite commit domain**:
/// sub-millisecond (near-zero samples from the WAL-hit / digest-dedup
/// skip-write path) to 1s (the slow-disk / checkpoint-contention tail);
/// a single-row write beyond the 1s upper bound is the observed signal
/// of storage health degradation (consumer: the PersistWriter
/// commit-phase profile).
pub const PERSIST_COMMIT_BUCKETS_SECONDS: &[f64] = &[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0];

/// Monotonic counter (the observability primitive behind
/// `_total`-suffixed metrics; Relaxed increments).
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Counts one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds n (0 is harmless — feed points may call unconditionally).
    pub fn add(&self, n: u64) {
        if n > 0 {
            self.0.fetch_add(n, Ordering::Relaxed);
        }
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Histogram (seconds-domain latencies; non-cumulative bucket storage —
/// each bucket counts the samples landing within that bucket's bounds;
/// the cumulative form is derived at the rendering face). sum
/// accumulates in integer microseconds (floating-point summation drift
/// never enters storage); samples beyond every bucket land only in
/// count/sum (the +Inf bucket equals count, derived at the rendering
/// face).
#[derive(Debug)]
pub struct Histogram {
    bounds: &'static [f64],
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    sum_us: AtomicU64,
}

impl Histogram {
    /// Builds from a bucket-upper-bound table (a compile-time constant;
    /// bucket slots align 1:1 with it).
    pub fn new(bounds: &'static [f64]) -> Self {
        Histogram {
            buckets: (0..bounds.len()).map(|_| AtomicU64::new(0)).collect(),
            bounds,
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
        }
    }

    /// Observes one sample (a duration; internally compared against
    /// buckets in seconds, sum accumulated in microseconds).
    pub fn observe(&self, elapsed: Duration) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        let secs = elapsed.as_secs_f64();
        for (i, bound) in self.bounds.iter().enumerate() {
            if secs <= *bound {
                if let Some(b) = self.buckets.get(i) {
                    b.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
        // Beyond every bucket: lands only in count/sum (the
        // rendering-side +Inf bucket = count).
    }

    /// Non-cumulative bucket snapshot (the rendering face derives the
    /// cumulative form and +Inf).
    fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            bounds: self.bounds,
            buckets: self
                .buckets
                .iter()
                .map(|b| b.load(Ordering::Relaxed))
                .collect(),
            count: self.count.load(Ordering::Relaxed),
            sum_us: self.sum_us.load(Ordering::Relaxed),
        }
    }
}

/// [`Histogram`] snapshot (pure values; `bounds` points at the
/// compile-time constant table).
#[derive(Debug, Clone, PartialEq)]
pub struct HistogramSnapshot {
    /// Bucket upper-bound table (aligned 1:1 with [`Self::buckets`]).
    pub bounds: &'static [f64],
    /// Non-cumulative bucket counts (index i = samples with value
    /// <= bounds[i]).
    pub buckets: Vec<u64>,
    /// Total sample count (overflow samples included; the rendered
    /// +Inf bucket = this value).
    pub count: u64,
    /// Total sample duration in microseconds (converted to seconds at
    /// the rendering face).
    pub sum_us: u64,
}

/// DNS shared-resolver metric family (feed points in the
/// [`crate::dns`] module docs and at each feed-point comment).
///
/// Value domain (Prometheus naming, all labels fixed enums):
/// - `taiji_dns_lookups_total{result=hit|miss|error|timeout}` —
///   hit/miss count **cache behavior**, error/timeout count
///   **resolution outcome**; a resolution failure after a miss is
///   **double-counted** (miss + error|timeout, one each); that is the
///   defined caliber, not a defect;
/// - `taiji_dns_resolve_seconds` (histogram) — resolution egress
///   latency (cache hits contribute near-zero samples);
/// - `taiji_dns_family_mix_total{mix=v4_only|v6_only|dual}` — the
///   address-family composition at the resolver-list production point
///   (cache hits do not recount);
/// - `taiji_dns_events_total{kind=evict_ttl|evict_capacity}` — the two
///   HostCache eviction points (TTL expiry / capacity evicts the
///   oldest).
#[derive(Debug)]
pub struct DnsMetrics {
    backend_started: Counter,
    coalesced: Counter,
    negative_hit: Counter,
    capacity_rejected: Counter,
    system_started: Counter,
    system_coalesced: Counter,
    system_active: AtomicU64,
    system_queued: AtomicU64,
    lookups_hit: Counter,
    lookups_miss: Counter,
    lookups_error: Counter,
    lookups_timeout: Counter,
    family_mix_v4_only: Counter,
    family_mix_v6_only: Counter,
    family_mix_dual: Counter,
    events_evict_ttl: Counter,
    events_evict_capacity: Counter,
    resolve_seconds: Histogram,
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsMetrics {
    fn new() -> Self {
        DnsMetrics {
            backend_started: Counter::default(),
            coalesced: Counter::default(),
            negative_hit: Counter::default(),
            capacity_rejected: Counter::default(),
            system_started: Counter::default(),
            system_coalesced: Counter::default(),
            system_active: AtomicU64::new(0),
            system_queued: AtomicU64::new(0),
            lookups_hit: Counter::default(),
            lookups_miss: Counter::default(),
            lookups_error: Counter::default(),
            lookups_timeout: Counter::default(),
            family_mix_v4_only: Counter::default(),
            family_mix_v6_only: Counter::default(),
            family_mix_dual: Counter::default(),
            events_evict_ttl: Counter::default(),
            events_evict_capacity: Counter::default(),
            resolve_seconds: Histogram::new(DNS_RESOLVE_BUCKETS_SECONDS),
        }
    }

    pub(crate) fn note_backend_started(&self) {
        self.backend_started.inc();
    }
    pub(crate) fn note_coalesced(&self) {
        self.coalesced.inc();
    }
    pub(crate) fn note_negative_hit(&self) {
        self.negative_hit.inc();
    }
    pub(crate) fn note_capacity_rejected(&self) {
        self.capacity_rejected.inc();
    }
    pub(crate) fn note_system_started(&self) {
        self.system_started.inc();
    }
    pub(crate) fn note_system_coalesced(&self) {
        self.system_coalesced.inc();
    }
    pub(crate) fn system_active_inc(&self) {
        self.system_active.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn system_active_dec(&self) {
        self.system_active.fetch_sub(1, Ordering::Relaxed);
    }
    pub(crate) fn system_queued_inc(&self) {
        self.system_queued.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn system_queued_dec(&self) {
        self.system_queued.fetch_sub(1, Ordering::Relaxed);
    }

    /// Attributes a resolution lookup (cache hit / miss / failure /
    /// timeout).
    pub fn note_lookup(&self, result: DnsLookupResult) {
        let c = match result {
            DnsLookupResult::Hit => &self.lookups_hit,
            DnsLookupResult::Miss => &self.lookups_miss,
            DnsLookupResult::Error => &self.lookups_error,
            DnsLookupResult::Timeout => &self.lookups_timeout,
        };
        c.inc();
    }

    /// Attributes the address-family mix (resolver-list production
    /// point).
    pub fn note_family_mix(&self, mix: DnsFamilyMix) {
        let c = match mix {
            DnsFamilyMix::V4Only => &self.family_mix_v4_only,
            DnsFamilyMix::V6Only => &self.family_mix_v6_only,
            DnsFamilyMix::Dual => &self.family_mix_dual,
        };
        c.inc();
    }

    /// Attributes a cache eviction event (TTL expiry / capacity).
    pub fn note_cache_event(&self, kind: DnsCacheEvent) {
        let c = match kind {
            DnsCacheEvent::EvictTtl => &self.events_evict_ttl,
            DnsCacheEvent::EvictCapacity => &self.events_evict_capacity,
        };
        c.inc();
    }

    /// Observes resolve latency (includes cache hits' near-zero samples
    /// — the feed point sits at the resolution egress).
    pub fn observe_resolve(&self, elapsed: Duration) {
        self.resolve_seconds.observe(elapsed);
    }

    /// Snapshot (a non-consistent read of many atomics — see the module
    /// docs).
    pub fn snapshot(&self) -> DnsMetricsSnapshot {
        DnsMetricsSnapshot {
            backend_started: self.backend_started.get(),
            coalesced: self.coalesced.get(),
            negative_hit: self.negative_hit.get(),
            capacity_rejected: self.capacity_rejected.get(),
            system_started: self.system_started.get(),
            system_coalesced: self.system_coalesced.get(),
            system_active: self.system_active.load(Ordering::Relaxed),
            system_queued: self.system_queued.load(Ordering::Relaxed),
            lookups_hit: self.lookups_hit.get(),
            lookups_miss: self.lookups_miss.get(),
            lookups_error: self.lookups_error.get(),
            lookups_timeout: self.lookups_timeout.get(),
            family_mix_v4_only: self.family_mix_v4_only.get(),
            family_mix_v6_only: self.family_mix_v6_only.get(),
            family_mix_dual: self.family_mix_dual.get(),
            events_evict_ttl: self.events_evict_ttl.get(),
            events_evict_capacity: self.events_evict_capacity.get(),
            resolve_seconds: self.resolve_seconds.snapshot(),
        }
    }
}

/// Resolution lookup attribution (the label `result` value domain;
/// semantics in [`DnsMetrics`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsLookupResult {
    /// Cache hit (no query issued).
    Hit,
    /// Cache miss (a query is issued).
    Miss,
    /// Resolution failure (non-timeout; double-counted as miss+error
    /// after a miss).
    Error,
    /// Resolution timeout (produced at the timeout-decorator layer;
    /// double-counted as miss+timeout after a miss).
    Timeout,
}

/// Address-family mix (the label `mix` value domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsFamilyMix {
    /// The list contains only IPv4 addresses.
    V4Only,
    /// The list contains only IPv6 addresses.
    V6Only,
    /// The list mixes both families.
    Dual,
}

/// Cache eviction event (the label `kind` value domain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsCacheEvent {
    /// TTL expiry eviction (lazily cleared on the read path).
    EvictTtl,
    /// Capacity eviction (an insert displaces the oldest-by-insertion
    /// entry).
    EvictCapacity,
}

/// [`DnsMetrics`] snapshot (pure values, consumed directly by
/// projection/rendering faces).
#[derive(Debug, Clone, PartialEq)]
pub struct DnsMetricsSnapshot {
    pub backend_started: u64,
    pub coalesced: u64,
    pub negative_hit: u64,
    pub capacity_rejected: u64,
    pub system_started: u64,
    pub system_coalesced: u64,
    pub system_active: u64,
    pub system_queued: u64,
    pub lookups_hit: u64,
    pub lookups_miss: u64,
    pub lookups_error: u64,
    pub lookups_timeout: u64,
    pub family_mix_v4_only: u64,
    pub family_mix_v6_only: u64,
    pub family_mix_dual: u64,
    pub events_evict_ttl: u64,
    pub events_evict_capacity: u64,
    pub resolve_seconds: HistogramSnapshot,
}

/// Transport class -> metric class mapping (single source; `Other` =
/// unclassifiable -> `None`, not counted — the honest face of "no
/// metric without a feed point"). The classification-seam host
/// (taiji-http) lands count slots only through this function; per-
/// caller mapping tables are banned.
pub fn http_error_class_of(class: crate::dns::TransportErrorClass) -> Option<HttpErrorClass> {
    use crate::dns::{DnsPersistence, TransportErrorClass};
    match class {
        TransportErrorClass::Dns(DnsPersistence::Permanent) => {
            Some(HttpErrorClass::Dns(DnsPersistence::Permanent))
        }
        TransportErrorClass::Dns(DnsPersistence::Transient) => {
            Some(HttpErrorClass::Dns(DnsPersistence::Transient))
        }
        TransportErrorClass::Timeout => Some(HttpErrorClass::Timeout),
        TransportErrorClass::Tls => Some(HttpErrorClass::Tls),
        TransportErrorClass::Connect => Some(HttpErrorClass::Connect),
        TransportErrorClass::Refused => Some(HttpErrorClass::Refused),
        TransportErrorClass::Reset => Some(HttpErrorClass::Reset),
        TransportErrorClass::Other => None,
    }
}

/// HTTP transport error class (the label value domain of metric
/// `taiji_http_errors_total{class}`; 1:1 with
/// [`crate::dns::TransportErrorClass`] — Other is not counted and so
/// has no slot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpErrorClass {
    /// DNS resolution failure (payload = persistence: the
    /// permanent/transient slots — NXDOMAIN-like terminal outcomes and
    /// self-healing forms count in separate slots).
    Dns(crate::dns::DnsPersistence),
    /// Timeout.
    Timeout,
    /// TLS face.
    Tls,
    /// Connection establishment.
    Connect,
    /// Connection refused.
    Refused,
    /// Connection reset / aborted.
    Reset,
    /// HTTP 4xx (status-code failure face).
    Http4xx,
    /// HTTP 5xx (status-code failure face).
    Http5xx,
}

/// Source health transition (the label value domain of metric
/// `taiji_http_mirror_events_total{kind}`; a structural projection of
/// taiji-http's `SourceEvent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorEventKind {
    /// Demoted (in-window failures reached the threshold).
    Demote,
    /// Removed (terminal).
    Remove,
    /// A demoted source regained full weight.
    Restore,
}

/// AIMD decision direction (the label value domain of metric
/// `taiji_http_aimd_events_total{dir}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AimdDirection {
    /// Grow (slow-start doubling confirmed).
    Grow,
    /// Shrink (congestion signal).
    Shrink,
}

/// HTTP request-latency phase (the label value domain of metric
/// `taiji_http_request_seconds{phase}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPhase {
    /// Request issued -> terminal response arrives (TTFB face).
    FirstByte,
    /// Request issued -> response body fully streamed (extent-level
    /// minutes domain).
    Total,
}

/// HTTP transport metric family (feed points in the taiji-http seam
/// docs; caliber notes — `errors` counts per failed request (retries /
/// multi-hop amplify by N, not the failed-task count); hit/miss-style
/// double counting does not exist in this family. All counting goes
/// through the registry injection pattern; bare globals banned).
///
/// # Connection-profile family (`conn_establish_*`) caliber notes
///
/// Feed point = the tower timing layer hung off reqwest
/// `ClientBuilder::connector_layer` (innermost in the connector stack,
/// under the `connect_timeout` layer): the connector stack is the
/// mandatory path for building connections and pool-hit requests never
/// pass through it — **counts naturally cover only new connections**
/// (the first observable face of pool behavior; the pool's direct hit
/// rate stays unmeasurable, so this family proxies the new-connection
/// face).
///
/// - `conn_establish_seconds` = **DNS+TCP+TLS combined timing** (the
///   data-plane/probe-plane transport instances share the layer;
///   includes tunnel establishment under proxy config). Phase splits
///   are not available: connect+TLS ≈ combined latency -
///   `dns_resolve_seconds` (an analysis-side **mean-caliber component
///   subtraction** — the two families have no per-sample
///   reconciliation seam, so no per-sample differences); the caliber
///   notes land in SPEC §12 with the value-domain tables;
/// - pinned-host (DNS override) connections produce no DNS component
///   and no `taiji_dns_lookups_*` counts (the override layer
///   short-circuits ahead of the shared resolver) — combined latency ≈
///   the raw connect+TLS value;
/// - `establishments_total` and `establish_seconds.count` are always
///   equal (one success event, two bookkeeping slots); **failed
///   attempts are not counted** (failures are classified through the
///   `errors{class=connect|refused|...}` seam; the latency profile
///   accepts successful samples only).
#[derive(Debug)]
pub struct HttpMetrics {
    errors_dns_permanent: Counter,
    errors_dns_transient: Counter,
    errors_timeout: Counter,
    errors_tls: Counter,
    errors_connect: Counter,
    errors_refused: Counter,
    errors_reset: Counter,
    errors_http_4xx: Counter,
    errors_http_5xx: Counter,
    retries_total: Counter,
    extent_reassign_total: Counter,
    mirror_demote: Counter,
    mirror_remove: Counter,
    mirror_restore: Counter,
    stall_detected_total: Counter,
    aimd_grow: Counter,
    aimd_shrink: Counter,
    request_first_byte: Histogram,
    request_total: Histogram,
    slowstart_seconds: Histogram,
    conn_establishments_total: Counter,
    conn_establish_seconds: Histogram,
}

impl Default for HttpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpMetrics {
    fn new() -> Self {
        HttpMetrics {
            errors_dns_permanent: Counter::default(),
            errors_dns_transient: Counter::default(),
            errors_timeout: Counter::default(),
            errors_tls: Counter::default(),
            errors_connect: Counter::default(),
            errors_refused: Counter::default(),
            errors_reset: Counter::default(),
            errors_http_4xx: Counter::default(),
            errors_http_5xx: Counter::default(),
            retries_total: Counter::default(),
            extent_reassign_total: Counter::default(),
            mirror_demote: Counter::default(),
            mirror_remove: Counter::default(),
            mirror_restore: Counter::default(),
            stall_detected_total: Counter::default(),
            aimd_grow: Counter::default(),
            aimd_shrink: Counter::default(),
            request_first_byte: Histogram::new(HTTP_REQUEST_BUCKETS_SECONDS),
            request_total: Histogram::new(HTTP_REQUEST_BUCKETS_SECONDS),
            slowstart_seconds: Histogram::new(HTTP_SLOWSTART_BUCKETS_SECONDS),
            conn_establishments_total: Counter::default(),
            conn_establish_seconds: Histogram::new(HTTP_CONN_ESTABLISH_BUCKETS_SECONDS),
        }
    }

    /// Transport error classification counts (classification-seam feed
    /// points — before the reqwest chain flattens / the FTP face / the
    /// status-code failure face; `Other` not counted = the honest "no
    /// metric without a feed point" caliber).
    pub fn note_error(&self, class: HttpErrorClass) {
        let c = match class {
            HttpErrorClass::Dns(crate::dns::DnsPersistence::Permanent) => {
                &self.errors_dns_permanent
            }
            HttpErrorClass::Dns(crate::dns::DnsPersistence::Transient) => {
                &self.errors_dns_transient
            }
            HttpErrorClass::Timeout => &self.errors_timeout,
            HttpErrorClass::Tls => &self.errors_tls,
            HttpErrorClass::Connect => &self.errors_connect,
            HttpErrorClass::Refused => &self.errors_refused,
            HttpErrorClass::Reset => &self.errors_reset,
            HttpErrorClass::Http4xx => &self.errors_http_4xx,
            HttpErrorClass::Http5xx => &self.errors_http_5xx,
        };
        c.inc();
    }

    /// Retry counts (the retry helper's decision point; n = the retries
    /// decided by this call — always 1).
    pub fn note_retries(&self, n: u64) {
        self.retries_total.add(n);
    }

    /// Extent non-steal reassignment counts (the coordinator's abandon
    /// decision face — a real release by the current write holder sends
    /// the extent back to the pool for reassignment; steal grants go
    /// through the existing stolen face and never enter this counter).
    pub fn note_extent_reassign(&self) {
        self.extent_reassign_total.inc();
    }

    /// Source health transition counts (demote/remove/restore — the
    /// sources-ledger decision points).
    pub fn note_mirror_event(&self, kind: MirrorEventKind) {
        let c = match kind {
            MirrorEventKind::Demote => &self.mirror_demote,
            MirrorEventKind::Remove => &self.mirror_remove,
            MirrorEventKind::Restore => &self.mirror_restore,
        };
        c.inc();
    }

    /// Stall-evidence counts (a read-only consumer of StallWatch's
    /// verdict).
    pub fn note_stall_detected(&self) {
        self.stall_detected_total.inc();
    }

    /// AIMD decision-direction counts (read-only consumption at the
    /// decision return point).
    pub fn note_aimd_event(&self, dir: AimdDirection) {
        let c = match dir {
            AimdDirection::Grow => &self.aimd_grow,
            AimdDirection::Shrink => &self.aimd_shrink,
        };
        c.inc();
    }

    /// Request-latency observation (phase face — first_byte fed at the
    /// response arrival point, total at body-stream completion).
    pub fn observe_request(&self, phase: RequestPhase, elapsed: Duration) {
        let h = match phase {
            RequestPhase::FirstByte => &self.request_first_byte,
            RequestPhase::Total => &self.request_total,
        };
        h.observe(elapsed);
    }

    /// Slow-start duration observation (start = task activation; end =
    /// the driver tick where AIMD first reaches steady state / the cap;
    /// tasks never reaching steady state are not sampled — honest
    /// right-censoring).
    pub fn observe_slowstart(&self, elapsed: Duration) {
        self.slowstart_seconds.observe(elapsed);
    }

    /// New-connection establishment observation (connection-profile
    /// family feed point — the tower timing layer's **successful** exit
    /// inside the connector stack; pool reuse never touches the
    /// connector, so counts naturally cover only new connections).
    /// `establishments_total` and `establish_seconds` bookkeep as
    /// always-equal dual slots; failed attempts never pass here
    /// (classified through the errors seam).
    pub fn note_conn_established(&self, elapsed: Duration) {
        self.conn_establishments_total.inc();
        self.conn_establish_seconds.observe(elapsed);
    }

    /// Snapshot (a non-consistent read of many atomics — see the module
    /// docs).
    pub fn snapshot(&self) -> HttpMetricsSnapshot {
        HttpMetricsSnapshot {
            errors_dns_permanent: self.errors_dns_permanent.get(),
            errors_dns_transient: self.errors_dns_transient.get(),
            errors_timeout: self.errors_timeout.get(),
            errors_tls: self.errors_tls.get(),
            errors_connect: self.errors_connect.get(),
            errors_refused: self.errors_refused.get(),
            errors_reset: self.errors_reset.get(),
            errors_http_4xx: self.errors_http_4xx.get(),
            errors_http_5xx: self.errors_http_5xx.get(),
            retries_total: self.retries_total.get(),
            extent_reassign_total: self.extent_reassign_total.get(),
            mirror_demote: self.mirror_demote.get(),
            mirror_remove: self.mirror_remove.get(),
            mirror_restore: self.mirror_restore.get(),
            stall_detected_total: self.stall_detected_total.get(),
            aimd_grow: self.aimd_grow.get(),
            aimd_shrink: self.aimd_shrink.get(),
            request_first_byte: self.request_first_byte.snapshot(),
            request_total: self.request_total.snapshot(),
            slowstart_seconds: self.slowstart_seconds.snapshot(),
            conn_establishments_total: self.conn_establishments_total.get(),
            conn_establish_seconds: self.conn_establish_seconds.snapshot(),
        }
    }
}

/// [`HttpMetrics`] snapshot (pure values, consumed directly by
/// projection/rendering faces).
#[derive(Debug, Clone, PartialEq)]
pub struct HttpMetricsSnapshot {
    pub errors_dns_permanent: u64,
    pub errors_dns_transient: u64,
    pub errors_timeout: u64,
    pub errors_tls: u64,
    pub errors_connect: u64,
    pub errors_refused: u64,
    pub errors_reset: u64,
    pub errors_http_4xx: u64,
    pub errors_http_5xx: u64,
    pub retries_total: u64,
    pub extent_reassign_total: u64,
    pub mirror_demote: u64,
    pub mirror_remove: u64,
    pub mirror_restore: u64,
    pub stall_detected_total: u64,
    pub aimd_grow: u64,
    pub aimd_shrink: u64,
    pub request_first_byte: HistogramSnapshot,
    pub request_total: HistogramSnapshot,
    pub slowstart_seconds: HistogramSnapshot,
    /// New-connection establishment total (caliber in the
    /// [`HttpMetrics`] connection-profile family note — always equal to
    /// `conn_establish_seconds.count`).
    pub conn_establishments_total: u64,
    /// Connection-establishment histogram (DNS+TCP+TLS combined; the
    /// DNS component-subtraction caliber is in the [`HttpMetrics`]
    /// note).
    pub conn_establish_seconds: HistogramSnapshot,
}

/// finalize completion operation (the label value domain of metric
/// `taiji_disk_finalize_seconds{op}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizeOp {
    /// Task-file fsync (merged caliber: counts **all production
    /// task-file fsyncs** — the grid path's 2s-debounced snapshot beats
    /// and the finalize forced beat share one seam (the core snapshot
    /// pipeline fsync seam), as do the EOF/degraded-chain
    /// `PartFile::sync_all` calls; the seam cannot tell the phases
    /// apart, so they merge into one count, disclosed here. The
    /// `fsync_dir`/`rename` ops arise only on the finalize teardown
    /// face).
    FileFsync,
    /// Directory fsync (rename durability; finalize teardown face
    /// only).
    FsyncDir,
    /// Atomic rename (finalize teardown face only).
    Rename,
}

/// Disk sink in-flight write guard (the enter/exit pair carrier of
/// `taiji_disk_sink_inflight`: construction = the enter point +1, drop
/// = the exit point -1 — write-failure early-return paths also
/// restore, the gauge does not leak).
#[derive(Debug)]
pub struct SinkWriteGuard {
    inflight: Arc<AtomicU64>,
}

impl Drop for SinkWriteGuard {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Disk/finalize metric family (feed points: core `HttpGridSink::
/// write_at` (the disk sink write path), taiji-http `PartFile`
/// (prealloc `set_len` / file fsync), the core snapshot pipeline fsync
/// seam `PartFileSync::sync`, taiji-http `Finalizer` (rename /
/// directory fsync). All through the registry injection pattern —
/// components bind the process default instance by default, tests
/// inject independent instances).
///
/// Caliber notes (honest face):
/// - `sink_inflight` semantics = **the concurrent in-flight write_at
///   count** (paired enter/exit counting) — the production write path
///   is direct positioned writes with no queue structure, so a "queue
///   depth" is neither measurable nor invented;
/// - the merged caliber of `finalize_seconds{op=file_fsync}` is
///   documented at [`FinalizeOp::FileFsync`] (2s snapshot-beat samples
///   mix in, disclosed there; given fsync is itself the slow operation
///   on SMB, the long-tail observation stays valid with both phases in
///   the same bucket domain).
#[derive(Debug)]
pub struct DiskMetrics {
    sink_writes_total: Counter,
    sink_writes_bytes_total: Counter,
    sink_inflight: Arc<AtomicU64>,
    finalize_file_fsync: Histogram,
    finalize_fsync_dir: Histogram,
    finalize_rename: Histogram,
    prealloc_seconds: Histogram,
}

impl Default for DiskMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DiskMetrics {
    fn new() -> Self {
        DiskMetrics {
            sink_writes_total: Counter::default(),
            sink_writes_bytes_total: Counter::default(),
            sink_inflight: Arc::new(AtomicU64::new(0)),
            finalize_file_fsync: Histogram::new(DISK_FINALIZE_BUCKETS_SECONDS),
            finalize_fsync_dir: Histogram::new(DISK_FINALIZE_BUCKETS_SECONDS),
            finalize_rename: Histogram::new(DISK_FINALIZE_BUCKETS_SECONDS),
            prealloc_seconds: Histogram::new(DISK_FINALIZE_BUCKETS_SECONDS),
        }
    }

    /// Disk sink write counts (feed point = `HttpGridSink::write_at`'s
    /// disk-write initiation; pre-write rejection does not count — that
    /// path never touches the disk).
    pub fn note_sink_write(&self, bytes: u64) {
        self.sink_writes_total.inc();
        self.sink_writes_bytes_total.add(bytes);
    }

    /// Enters an in-flight write (gauge +1; returns a guard whose drop
    /// is the exit point -1).
    pub fn enter_sink_write(&self) -> SinkWriteGuard {
        self.sink_inflight.fetch_add(1, Ordering::Relaxed);
        SinkWriteGuard {
            inflight: Arc::clone(&self.sink_inflight),
        }
    }

    /// Observes finalize/prealloc operation latency (`op` picks the
    /// slot; prealloc goes through [`Self::observe_prealloc`]).
    pub fn observe_finalize(&self, op: FinalizeOp, elapsed: Duration) {
        let h = match op {
            FinalizeOp::FileFsync => &self.finalize_file_fsync,
            FinalizeOp::FsyncDir => &self.finalize_fsync_dir,
            FinalizeOp::Rename => &self.finalize_rename,
        };
        h.observe(elapsed);
    }

    /// Observes prealloc `set_len` latency (open-time preallocation and
    /// resume growth share the slot).
    pub fn observe_prealloc(&self, elapsed: Duration) {
        self.prealloc_seconds.observe(elapsed);
    }

    /// Snapshot (a non-consistent read of many atomics — see the module
    /// docs; `sink_inflight` is the reading at sampling time, and
    /// finished tasks falling back to 0 is expected).
    pub fn snapshot(&self) -> DiskMetricsSnapshot {
        DiskMetricsSnapshot {
            sink_writes_total: self.sink_writes_total.get(),
            sink_writes_bytes_total: self.sink_writes_bytes_total.get(),
            sink_inflight: self.sink_inflight.load(Ordering::Relaxed),
            finalize_file_fsync: self.finalize_file_fsync.snapshot(),
            finalize_fsync_dir: self.finalize_fsync_dir.snapshot(),
            finalize_rename: self.finalize_rename.snapshot(),
            prealloc_seconds: self.prealloc_seconds.snapshot(),
        }
    }
}

/// [`DiskMetrics`] snapshot (pure values, consumed directly by
/// projection/rendering faces).
#[derive(Debug, Clone, PartialEq)]
pub struct DiskMetricsSnapshot {
    pub sink_writes_total: u64,
    pub sink_writes_bytes_total: u64,
    pub sink_inflight: u64,
    pub finalize_file_fsync: HistogramSnapshot,
    pub finalize_fsync_dir: HistogramSnapshot,
    pub finalize_rename: HistogramSnapshot,
    pub prealloc_seconds: HistogramSnapshot,
}

/// Persistence metric family (feed point: the taiji-store PersistWriter
/// write-thread main loop — store and io do not depend on each other
/// (the crate direction table), so the feed point lands here through
/// the store-side `PersistObserve` callback seam (store defines the
/// trait, core injects the adapter); production assembly binds the
/// process default registry, tests inject independent instances
/// through the registry construction seam).
///
/// Caliber notes (honest face):
/// - `commit_seconds` = the execution time inside the write thread for
///   one job (from job dispatch to row-write completion), **not
///   including** channel-queueing wait (the queue face is covered by
///   `queue_depth`);
/// - `queue_depth` = write-thread-side sampling: the number of
///   messages still parked in the job channel after the most recent
///   job completed (a gauge = the last observed value, not the
///   real-time length at read time — the reading can go stale at low
///   traffic).
#[derive(Debug)]
pub struct PersistMetrics {
    queue_depth: std::sync::atomic::AtomicU64,
    commit_seconds: Histogram,
}

impl Default for PersistMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistMetrics {
    fn new() -> Self {
        PersistMetrics {
            queue_depth: std::sync::atomic::AtomicU64::new(0),
            commit_seconds: Histogram::new(PERSIST_COMMIT_BUCKETS_SECONDS),
        }
    }

    /// Observes single-job commit duration (the write thread's dispatch
    /// point).
    pub fn observe_commit(&self, elapsed: Duration) {
        self.commit_seconds.observe(elapsed);
    }

    /// Samples the job-channel parked depth (gauge SET semantics — the
    /// last observed value).
    pub fn set_queue_depth(&self, depth: u64) {
        self.queue_depth.store(depth, Ordering::Relaxed);
    }

    /// Snapshot (`queue_depth` is the last observed value —
    /// non-consistent snapshot, see the module docs).
    pub fn snapshot(&self) -> PersistMetricsSnapshot {
        PersistMetricsSnapshot {
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            commit_seconds: self.commit_seconds.snapshot(),
        }
    }
}

/// [`PersistMetrics`] snapshot (pure values, consumed directly by
/// projection/rendering faces).
#[derive(Debug, Clone, PartialEq)]
pub struct PersistMetricsSnapshot {
    pub queue_depth: u64,
    pub commit_seconds: HistogramSnapshot,
}

/// Whole-registry snapshot (the pull face of core's aggregation seam).
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrySnapshot {
    /// DNS shared-resolver family.
    pub dns: DnsMetricsSnapshot,
    /// HTTP transport family.
    pub http: HttpMetricsSnapshot,
    /// Disk/finalize family.
    pub disk: DiskMetricsSnapshot,
    /// Persistence family.
    pub persist: PersistMetricsSnapshot,
}

/// taiji-io's process-wide metrics registry (feed-point components
/// bind their families; future transport families extend additively
/// here).
#[derive(Debug)]
pub struct MetricsRegistry {
    dns: DnsMetrics,
    http: HttpMetrics,
    disk: DiskMetrics,
    persist: PersistMetrics,
}

impl MetricsRegistry {
    /// Independent registry (the test injection seam; zero sharing with
    /// the process default instance).
    pub fn new() -> Self {
        MetricsRegistry {
            dns: DnsMetrics::new(),
            http: HttpMetrics::new(),
            disk: DiskMetrics::new(),
            persist: PersistMetrics::new(),
        }
    }

    /// DNS metric family.
    pub fn dns(&self) -> &DnsMetrics {
        &self.dns
    }

    /// HTTP transport metric family.
    pub fn http(&self) -> &HttpMetrics {
        &self.http
    }

    /// Disk/finalize metric family.
    pub fn disk(&self) -> &DiskMetrics {
        &self.disk
    }

    /// Persistence metric family.
    pub fn persist(&self) -> &PersistMetrics {
        &self.persist
    }

    /// Whole-registry snapshot.
    pub fn snapshot(&self) -> RegistrySnapshot {
        RegistrySnapshot {
            dns: self.dns.snapshot(),
            http: self.http.snapshot(),
            disk: self.disk.snapshot(),
            persist: self.persist.snapshot(),
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide default registry (lazily built on OnceLock; the single
/// production assembly point — components share this one registry;
/// cannot be swapped or reset, tests inject independent instances
/// through the construction seam).
pub fn registry_default() -> Arc<MetricsRegistry> {
    static DEFAULT: OnceLock<Arc<MetricsRegistry>> = OnceLock::new();
    DEFAULT
        .get_or_init(|| Arc::new(MetricsRegistry::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Histogram buckets: inclusive upper bounds, count/sum in step,
    /// overflow lands only in count/sum (the assertion face of the
    /// core rpc latency histogram shape).
    #[test]
    fn histogram_buckets_inclusive_and_overflow_to_count_sum() {
        let h = Histogram::new(DNS_RESOLVE_BUCKETS_SECONDS);
        h.observe(Duration::from_millis(1)); // -> le=0.001
        h.observe(Duration::from_millis(4)); // -> le=0.005
        h.observe(Duration::from_millis(60)); // -> le=0.1
        h.observe(Duration::from_secs(9)); // -> le=30
        h.observe(Duration::from_secs(45)); // beyond every bucket (> the DNS_TIMEOUT backstop)
        let s = h.snapshot();
        assert_eq!(s.bounds, DNS_RESOLVE_BUCKETS_SECONDS);
        assert_eq!(
            s.buckets[0], 1,
            "1ms lands in le=0.001 (inclusive upper bound)"
        );
        assert_eq!(s.buckets[1], 1, "4ms lands in le=0.005");
        assert_eq!(s.buckets[4], 1, "60ms lands in le=0.1");
        assert_eq!(s.buckets[8], 1, "9s lands in le=30");
        assert_eq!(
            s.buckets.iter().sum::<u64>(),
            4,
            "45s overflows into no bucket"
        );
        assert_eq!(s.count, 5);
        assert!(s.sum_us >= 54_000_000, "sum in microseconds >= 9s+45s");
        // The snapshot is non-cumulative: a single bucket's count does
        // not grow monotonically with index (the cumulative conversion
        // happens at the rendering face).
        assert_eq!(s.buckets[0], 1);
    }

    /// Bucket tables pinned to consumer thresholds (the stress-test
    /// resolve component + the DNS_TIMEOUT backstop upper bound).
    #[test]
    fn dns_resolve_bucket_table_is_pinned() {
        assert_eq!(
            DNS_RESOLVE_BUCKETS_SECONDS,
            [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0].as_slice()
        );
        assert_eq!(
            DNS_RESOLVE_BUCKETS_SECONDS.last().copied(),
            Some(30.0),
            "upper bound = the DNS_TIMEOUT fallback (crate::dns::DNS_TIMEOUT = 30s)"
        );
    }

    /// Counter: inc/add semantics and the zero-increment no-op.
    #[test]
    fn counter_inc_add() {
        let c = Counter::default();
        c.inc();
        c.inc();
        c.add(3);
        c.add(0);
        assert_eq!(c.get(), 5);
    }

    /// DNS family feed points -> snapshot: four-way attribution, the
    /// three-state family mix, and both evictions all in place (the
    /// mechanism face of independent-instance feed-point assertions).
    #[test]
    fn dns_metrics_feed_points_land_in_snapshot() {
        let m = DnsMetrics::new();
        let zero = m.snapshot();
        assert_eq!(zero.lookups_hit, 0, "honest zero-value start");
        assert_eq!(zero.resolve_seconds.count, 0);

        m.note_lookup(DnsLookupResult::Hit);
        m.note_lookup(DnsLookupResult::Miss);
        m.note_lookup(DnsLookupResult::Error);
        m.note_lookup(DnsLookupResult::Timeout);
        m.note_family_mix(DnsFamilyMix::V4Only);
        m.note_family_mix(DnsFamilyMix::V6Only);
        m.note_family_mix(DnsFamilyMix::Dual);
        m.note_cache_event(DnsCacheEvent::EvictTtl);
        m.note_cache_event(DnsCacheEvent::EvictCapacity);
        m.observe_resolve(Duration::from_millis(2));

        let s = m.snapshot();
        assert_eq!(s.lookups_hit, 1);
        assert_eq!(s.lookups_miss, 1);
        assert_eq!(s.lookups_error, 1);
        assert_eq!(s.lookups_timeout, 1);
        assert_eq!(s.family_mix_v4_only, 1);
        assert_eq!(s.family_mix_v6_only, 1);
        assert_eq!(s.family_mix_dual, 1);
        assert_eq!(s.events_evict_ttl, 1);
        assert_eq!(s.events_evict_capacity, 1);
        assert_eq!(s.resolve_seconds.count, 1);
        assert_eq!(s.resolve_seconds.buckets[1], 1, "2ms lands in le=0.005");
    }

    /// Registry: independent instances never cross-talk (bare global
    /// counters banned — the constructible/injectable mechanism face);
    /// the process default instance is one stable Arc.
    #[test]
    fn registry_instances_are_independent_and_default_is_stable() {
        let a = MetricsRegistry::new();
        let b = MetricsRegistry::new();
        a.dns().note_lookup(DnsLookupResult::Hit);
        assert_eq!(
            b.snapshot().dns,
            DnsMetricsSnapshot {
                backend_started: 0,
                coalesced: 0,
                negative_hit: 0,
                capacity_rejected: 0,
                system_started: 0,
                system_coalesced: 0,
                system_active: 0,
                system_queued: 0,
                lookups_hit: 0,
                lookups_miss: 0,
                lookups_error: 0,
                lookups_timeout: 0,
                family_mix_v4_only: 0,
                family_mix_v6_only: 0,
                family_mix_dual: 0,
                events_evict_ttl: 0,
                events_evict_capacity: 0,
                resolve_seconds: HistogramSnapshot {
                    bounds: DNS_RESOLVE_BUCKETS_SECONDS,
                    buckets: vec![0; DNS_RESOLVE_BUCKETS_SECONDS.len()],
                    count: 0,
                    sum_us: 0,
                },
            },
            "independent instances share nothing"
        );
        let d1 = registry_default();
        let d2 = registry_default();
        assert!(
            Arc::ptr_eq(&d1, &d2),
            "the process default instance is one stable Arc"
        );
    }

    /// HTTP family bucket tables pinned to consumer thresholds (the
    /// extent-level minutes domain + the slow-start ramp domain + the
    /// connection-establishment domain).
    #[test]
    fn http_bucket_tables_are_pinned() {
        assert_eq!(
            HTTP_REQUEST_BUCKETS_SECONDS,
            [0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 60.0, 300.0].as_slice()
        );
        assert_eq!(
            HTTP_SLOWSTART_BUCKETS_SECONDS,
            [0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0].as_slice()
        );
        // Connection domain: the 0.25/0.5 buckets straddle the 300ms
        // happy-eyeballs interleave point.
        assert_eq!(
            HTTP_CONN_ESTABLISH_BUCKETS_SECONDS,
            [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0].as_slice()
        );
    }

    /// HTTP family feed points -> snapshot: nine error classes
    /// (including the dns permanent/transient slot split), retry /
    /// reassign / source transition / stall / AIMD, and the three
    /// histograms all in place (the mechanism face of
    /// independent-instance feed-point assertions — the criteria face
    /// for feed-point unit tests asserting count changes).
    #[test]
    fn http_metrics_feed_points_land_in_snapshot() {
        let m = HttpMetrics::new();
        let zero = m.snapshot();
        assert_eq!(zero.errors_dns_permanent, 0, "honest zero-value start");
        assert_eq!(zero.request_first_byte.count, 0);
        assert_eq!(zero.slowstart_seconds.count, 0);

        use crate::dns::DnsPersistence;
        m.note_error(HttpErrorClass::Dns(DnsPersistence::Permanent));
        m.note_error(HttpErrorClass::Dns(DnsPersistence::Transient));
        m.note_error(HttpErrorClass::Timeout);
        m.note_error(HttpErrorClass::Tls);
        m.note_error(HttpErrorClass::Connect);
        m.note_error(HttpErrorClass::Refused);
        m.note_error(HttpErrorClass::Reset);
        m.note_error(HttpErrorClass::Http4xx);
        m.note_error(HttpErrorClass::Http5xx);
        m.note_retries(1);
        m.note_extent_reassign();
        m.note_mirror_event(MirrorEventKind::Demote);
        m.note_mirror_event(MirrorEventKind::Remove);
        m.note_mirror_event(MirrorEventKind::Restore);
        m.note_stall_detected();
        m.note_aimd_event(AimdDirection::Grow);
        m.note_aimd_event(AimdDirection::Shrink);
        m.observe_request(RequestPhase::FirstByte, Duration::from_millis(30));
        m.observe_request(RequestPhase::Total, Duration::from_secs(45));
        m.observe_slowstart(Duration::from_secs(3));

        let s = m.snapshot();
        assert_eq!(s.errors_dns_permanent, 1);
        assert_eq!(s.errors_dns_transient, 1);
        assert_eq!(s.errors_timeout, 1);
        assert_eq!(s.errors_tls, 1);
        assert_eq!(s.errors_connect, 1);
        assert_eq!(s.errors_refused, 1);
        assert_eq!(s.errors_reset, 1);
        assert_eq!(s.errors_http_4xx, 1);
        assert_eq!(s.errors_http_5xx, 1);
        assert_eq!(s.retries_total, 1);
        assert_eq!(s.extent_reassign_total, 1);
        assert_eq!(s.mirror_demote, 1);
        assert_eq!(s.mirror_remove, 1);
        assert_eq!(s.mirror_restore, 1);
        assert_eq!(s.stall_detected_total, 1);
        assert_eq!(s.aimd_grow, 1);
        assert_eq!(s.aimd_shrink, 1);
        // Request latency: 30ms lands le=0.05 (first_byte); 45s lands
        // le=60 (total).
        assert_eq!(s.request_first_byte.count, 1);
        assert_eq!(s.request_first_byte.buckets[1], 1);
        assert_eq!(s.request_total.buckets[7], 1);
        // Slow start: 3s lands le=5.
        assert_eq!(s.slowstart_seconds.count, 1);
        assert_eq!(s.slowstart_seconds.buckets[3], 1);
    }

    /// Connection-profile family feed points -> snapshot (the mechanism
    /// face of connection-profile observation): one
    /// `note_conn_established` call = counter +1 and one histogram
    /// sample, the always-equal dual slots; a 200ms sample lands
    /// exactly in the le=0.25 bucket at the 300ms happy-eyeballs
    /// interleave point; honest zero-value start (the criteria face of
    /// independent-instance feed-point assertions).
    #[test]
    fn conn_establish_feed_points_land_in_snapshot() {
        let m = HttpMetrics::new();
        let zero = m.snapshot();
        assert_eq!(zero.conn_establishments_total, 0, "honest zero-value start");
        assert_eq!(zero.conn_establish_seconds.count, 0);

        m.note_conn_established(Duration::from_millis(2));
        m.note_conn_established(Duration::from_millis(40));
        m.note_conn_established(Duration::from_millis(200)); // the happy-eyeballs interleave point
        m.note_conn_established(Duration::from_secs(45)); // beyond every bucket -> only count/sum

        let s = m.snapshot();
        assert_eq!(
            s.conn_establishments_total, 4,
            "counter and histogram totals stay equal (one success event, dual slots)"
        );
        assert_eq!(s.conn_establish_seconds.count, 4);
        assert_eq!(
            s.conn_establish_seconds.buckets[1], 1,
            "2ms lands in le=0.005 (inclusive upper bound)"
        );
        assert_eq!(
            s.conn_establish_seconds.buckets[3], 1,
            "40ms lands in le=0.05"
        );
        assert_eq!(
            s.conn_establish_seconds.buckets[5], 1,
            "200ms lands in le=0.25 (the bucket straddling the 300ms happy-eyeballs interleave point)"
        );
        assert_eq!(
            s.conn_establish_seconds.buckets.iter().sum::<u64>(),
            3,
            "45s overflows into no bucket"
        );
        assert!(s.conn_establish_seconds.sum_us >= 45_242_000);
    }

    /// Disk family bucket table pinned to consumer thresholds (the SMB
    /// long-tail domain — local millisecond positioning operations up
    /// to 30s network-drive fsync tails; finalize's three ops and
    /// prealloc share the buckets).
    #[test]
    fn disk_bucket_table_is_pinned() {
        assert_eq!(
            DISK_FINALIZE_BUCKETS_SECONDS,
            [0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0].as_slice()
        );
    }

    /// Persistence family bucket table pinned to consumer thresholds
    /// (the single-row sqlite commit domain — sub-millisecond WAL hits
    /// up to 1s slow-disk tails).
    #[test]
    fn persist_bucket_table_is_pinned() {
        assert_eq!(
            PERSIST_COMMIT_BUCKETS_SECONDS,
            [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0].as_slice()
        );
    }

    /// Persistence family feed points -> snapshot: commit durations
    /// land in buckets, queue_depth SET semantics (the last observed
    /// value; the mechanism face of independent-instance feed-point
    /// assertions).
    #[test]
    fn persist_metrics_feed_points_land_in_snapshot() {
        let m = PersistMetrics::new();
        let zero = m.snapshot();
        assert_eq!(zero.queue_depth, 0, "honest zero-value start");
        assert_eq!(zero.commit_seconds.count, 0);

        m.observe_commit(Duration::from_millis(2));
        m.observe_commit(Duration::from_millis(40));
        m.observe_commit(Duration::from_secs(2)); // beyond every bucket -> only count/sum
        m.set_queue_depth(7);
        m.set_queue_depth(3);

        let s = m.snapshot();
        assert_eq!(s.commit_seconds.count, 3);
        assert_eq!(
            s.commit_seconds.buckets[1], 1,
            "2ms lands in le=0.005 (inclusive upper bound)"
        );
        assert_eq!(s.commit_seconds.buckets[3], 1, "40ms lands in le=0.05");
        assert_eq!(
            s.commit_seconds.buckets.iter().sum::<u64>(),
            2,
            "2s overflows into no bucket"
        );
        assert!(
            s.commit_seconds.sum_us >= 2_042_000,
            "sum in microseconds >= 2s+40ms"
        );
        assert_eq!(
            s.queue_depth, 3,
            "gauge SET semantics = last observed value"
        );
    }

    /// Disk family feed points -> snapshot: write counts/bytes, the
    /// in-flight pairing (the guard's drop restores — early-return
    /// paths do not leak), finalize's three op slots, and prealloc's
    /// own slot (the mechanism face of independent-instance feed-point
    /// assertions).
    #[test]
    fn disk_metrics_feed_points_land_in_snapshot() {
        let m = DiskMetrics::new();
        let zero = m.snapshot();
        assert_eq!(zero.sink_writes_total, 0, "honest zero-value start");
        assert_eq!(zero.sink_inflight, 0);

        m.note_sink_write(4096);
        m.note_sink_write(512);
        let guard = m.enter_sink_write();
        let during = m.snapshot();
        assert_eq!(during.sink_writes_total, 2);
        assert_eq!(during.sink_writes_bytes_total, 4096 + 512);
        assert_eq!(during.sink_inflight, 1, "entry point +1");
        drop(guard);
        assert_eq!(m.snapshot().sink_inflight, 0, "exit point (drop) restores");

        m.observe_finalize(FinalizeOp::FileFsync, Duration::from_millis(2));
        m.observe_finalize(FinalizeOp::FsyncDir, Duration::from_millis(8));
        m.observe_finalize(FinalizeOp::Rename, Duration::from_secs(9));
        m.observe_prealloc(Duration::from_millis(40));
        let s = m.snapshot();
        assert_eq!(s.finalize_file_fsync.count, 1);
        assert_eq!(s.finalize_file_fsync.buckets[1], 1, "2ms lands in le=0.01");
        assert_eq!(s.finalize_fsync_dir.count, 1);
        assert_eq!(s.finalize_fsync_dir.buckets[1], 1, "8ms lands in le=0.01");
        assert_eq!(s.finalize_rename.count, 1);
        assert_eq!(
            s.finalize_rename.buckets[7], 1,
            "9s lands in le=30 (long-tail domain fallback)"
        );
        assert_eq!(s.prealloc_seconds.count, 1);
        assert_eq!(s.prealloc_seconds.buckets[2], 1, "40ms lands in le=0.05");
    }

    /// In-flight write guard: concurrent writes enter and their exits
    /// restore (gauge semantics = the concurrency at sampling time, not
    /// cumulative).
    #[test]
    fn sink_inflight_gauge_pairs_enter_exit() {
        let m = DiskMetrics::new();
        let g1 = m.enter_sink_write();
        let g2 = m.enter_sink_write();
        assert_eq!(m.snapshot().sink_inflight, 2);
        drop(g1);
        assert_eq!(m.snapshot().sink_inflight, 1);
        drop(g2);
        assert_eq!(m.snapshot().sink_inflight, 0);
    }
}

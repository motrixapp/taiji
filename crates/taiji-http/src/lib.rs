//! `taiji-http` — the HTTP download foundation crate.
//!
//! Responsibilities: the reqwest client wrapper ([`client`]: manual
//! redirects, credential stripping, UA, timeouts, retry parameters,
//! identity-only compression policy; URI probe transport),
//! connection-timing middleware ([`conn_timing`]), cookies
//! ([`cookies`]), retry knobs ([`retry`]), the block-grid +
//! dynamic-extent two-layer scheduler ([`grid`]/[`scheduler`]/
//! [`coordinator`] and friends), multi-source allocation
//! ([`sources`]), AIMD connection adaptation ([`aimd`]/[`pool`]),
//! rate limiting ([`limiter`]), URI probing ([`probe`]), naming /
//! `.part` persistence / completion rename ([`naming`]/[`partfile`]/
//! [`finalize`]), the single-connection degraded path ([`degraded`]),
//! FTP/FTPS transport adapters ([`ftp`]), the HTTP SegmentTransport
//! ([`transport`]), and grid workers ([`worker`]). Full module map and
//! design notes: docs/design/http.md.
//!
//! Hard invariant: this crate depends on neither taiji-store nor
//! taiji-core — disk writes go through the `SegmentSink` trait
//! injected by core, and journal/rename semantics through
//! [`finalize::RenameJournal`].
//!
//! Upstream anchor mapping: docs/design/http.md

pub mod aimd;
pub mod auth;
pub mod batch;
pub mod checksum;
pub mod client;
pub mod conn_timing;
pub mod coordinator;
pub mod degraded;
pub mod finalize;
pub mod ftp;
pub mod grid;
pub mod heartbeat;
pub mod limiter;
pub mod naming;
pub mod partfile;
pub mod perhost;
pub mod pool;
pub mod probe;
pub mod rate;
pub mod redirect_guard;
pub mod remotetime;
pub mod retry;
pub mod scheduler;
pub mod sequence;
pub mod sources;
pub mod stall;
pub mod transport;
pub mod worker;

// The segment vocabulary
// moved verbatim into taiji-segment (three traits + signature
// closure: cookies/error); these re-exports are the path-stable
// transition face — every existing `taiji_http::{traits, cookies,
// error}::` path (incl. the taiji-rpc HttpError mapping face) keeps
// resolving unchanged. New consumers depend on taiji-segment
// directly. `traits` remains a local module (it also keeps the
// HTTP-only free function same_origin).
pub use taiji_segment::cookies;
pub use taiji_segment::error;
pub mod traits;

/// The URI type as the base uses it (re-export: downstream consumers
/// resolve relative manifest/segment URIs against fetched absolute
/// URLs — RFC 3986 joining is the same face the client layer uses;
/// re-exporting avoids a direct reqwest dependency edge for one
/// type).
pub use reqwest;

/// Lock-poisoning policy (batch-wide decision): a poisoned `std::sync::Mutex`
/// means a panic happened mid-critical-section and an invariant may be lost —
/// recovery via `into_inner` is not permitted. The `expect` is fatal by
/// policy: the process teardown is carried to its terminal state by the
/// existing panic-watcher, so failing loudly here is the intended behavior.
///
/// All non-test lock acquisitions in this crate must go through this helper.
#[expect(
    clippy::expect_used,
    reason = "lock poisoning is fatal by policy; terminal state handled by the panic-watcher"
)]
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock()
        .expect("lock poisoned: invariant lost, fail loudly")
}

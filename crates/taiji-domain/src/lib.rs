//! `taiji-domain` — shared vocabulary layer (domain model / method-surface
//! contracts / event vocabulary).
//!
//! Single point for vocabulary consumed by core session/engine and by future
//! protocol crates. Carries three kinds of frozen cross-layer vocabulary:
//!
//! - **Method surface** ([`methods`]): the RPC method promise table
//!   (consts / type literals);
//! - **Domain model**: metainfo (.torrent parsing into a unified metadata
//!   model), seed (seeding stop policy), progress (progress model), hook
//!   (hook subset execution model), nat (NAT assembly surface),
//!   hash_fetch/hash_source (v2 hash exchange planner / source ledger),
//!   peer_guard (peer ban accounting + blocklist import), redial (peer
//!   redial pool), silent (silent-abandon failure ledger), gid (GID type
//!   vocabulary; the allocator itself lives in core session);
//! - **Event vocabulary** ([`recovery`]): recovery event relay payloads plus
//!   recovery-layer row assembly (a neutral payload surface produced by the
//!   engine and consumed by the session).
//!
//! Dependency discipline: must not depend on core/rpc/cli. Within the
//! workspace only the three companion crates bt/store/io may be used (for
//! type surfaces of the domain models, never execution semantics); third
//! parties are limited to literal/process-level vocabulary (bytes, sha1,
//! sha2, thiserror, tokio, tracing, rand).

pub mod gid;
pub mod hash_fetch;
pub mod hash_source;

/// Hook subset execution model; see the module docs for how it narrows the
/// upstream reference (argv-passing util.cc, no placeholder substitution).
pub mod hook;
pub mod metainfo;

/// NAT assembly: single-instance NatActor supervisor, engine consumption
/// surface, external port watch.
pub mod nat;

/// Peer ban accounting plus eMule blocklist import orchestration.
pub mod peer_guard;
pub mod progress;

/// Engine recovery surface: recovery event relay payloads plus
/// recovery-layer row assembly (neutral engine-to-session event vocabulary;
/// production points live on the core engine side).
pub mod recovery;

/// Peer redial pool (libtorrent `min_reconnect_time` semantics).
pub mod redial;
pub mod seed;

/// Silent-abandon failure ledger for endpoints (libtorrent
/// `max_failcount`/`failcount` semantics; see the module docs).
pub mod silent;

pub mod methods;

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

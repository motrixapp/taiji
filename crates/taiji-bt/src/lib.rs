//! `taiji-bt` — the BitTorrent protocol layer.
//!
//! Responsibilities:
//! - peer wire (unified v1 + v2 framing): handshake (including the BEP52
//!   `reserved[7] & 0x10` upgrade path), message codec, request bookkeeping
//!   (adaptive outstanding window 6->256), flood control, HAVE advertising;
//! - v2 hash exchange (BEP52 messages 21/22/23), both endpoint semantics;
//! - MSE/PE: DH-768 + ARC4 (dropping the first 1024B of keystream) +
//!   PLAIN negotiation;
//! - tracker: HTTP / UDP (BEP15) / announce tier state machine / scrape /
//!   LSD (BEP14);
//! - DHT (BEP5): K=8 routing table, dual identity of v1 sha1 and v2
//!   truncated sha256;
//! - PEX (BEP11), ut_metadata (BEP9);
//! - piece selection (rarest-first / endgame / priority) and choking
//!   (10s rounds).
//!
//! Status: bencode, peer wire framing, and file tree + Merkle parsing are
//! in place; tracker/DHT/PEX/PE proceed per the milestone plan in `docs/`.
//! Protocol behavior invariants (BEP52 big-endian, `.pad` semantics,
//! disconnect on unsolicited pieces, etc.) must only change with BEP-text
//! justification and tests.
//!
//! Dependency direction: only `taiji-io` and `taiji-store` may be depended
//! on.

pub mod bencode;

/// Client identification: peer_id Azureus-style prefix table + ext
/// handshake `v` field matching -> [`client_id::PeerClient`].
/// Identification != banning.
pub mod client_id;

/// .torrent creator: v1/v2/hybrid generation + piece layers + dual
/// infohash. The writer is the canonical mirror of the [`filetree`]
/// parser.
pub mod creator;

/// DHT (BEP5) protocol foundation: KRPC codec, K=8 routing table,
/// transaction table, tokens; actor integration lives elsewhere.
pub mod dht;

pub mod filetree;

/// ut_holepunch NAT hole-punching peer channel: three-sub-op message
/// codec, pure relay-decision function, hole-punch trigger bookkeeping.
/// Carrier = BEP10 m dict negotiation; the behavioral authority is
/// libtorrent (the BEP text does not cover it; file:symbol anchors in the
/// module docs).
pub mod holepunch;

pub mod info_hash;

/// LSD / Local Service Discovery (BEP14; `bt-lsd` defaults to off).
pub mod lsd;

/// ut_pex peer exchange (BEP11): message codec, <=50 / 60s semantics,
/// private-torrent disable and negotiation convergence. Protocol half
/// only (engine wiring lives elsewhere).
pub mod pex;

pub mod peer;

pub mod peer_wire;

/// BEP16 super-seeding distribution bookkeeping: piece choice ported from
/// torrent.cpp semantics + two-slot assignment + request serve gate. Pure
/// bookkeeping half (engine/peer wiring elsewhere).
pub mod superseed;

/// Peer-policy pure type surface: IpGuard IP-filter snapshots + violation
/// event semantics + eMule `.dat` parsing (no IO inside bt;
/// accounting/persistence live in core).
pub mod peer_policy;

pub mod tracker;

/// ut_metadata metadata exchange (BEP9, including the 20s timeout
/// correction): three-message codec, request bookkeeping, assembly +
/// infohash verification. Protocol half only (magnet-chain wiring
/// elsewhere).
pub mod ut_metadata;

pub mod piece_id;

pub mod piece_stat;

pub mod request_book;

pub mod choke;

pub mod magnet;

pub mod mse;

/// µTP integration placeholder: outbound connection-type policy /
/// downgrade sequence / `getPeers` transport data source; the protocol
/// itself lives in `taiji_io::utp`.
pub mod utp;

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

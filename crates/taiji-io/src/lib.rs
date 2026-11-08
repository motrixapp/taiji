//! `taiji-io` — transport layer (SPEC §3.3, §6.1).
//!
//! Responsibilities:
//! - Unified peer transport abstraction: TCP and µTP (BEP-29) with an
//!   MSE/PE encryption layer stackable on top, exposing only
//!   `AsyncRead + AsyncWrite` upward;
//! - Outbound dialing: dual-stack Happy Eyeballs (IPv6 racing IPv4 with a
//!   300ms head start);
//! - DNS resolution and caching (with bad-IP marking);
//! - Connection pool (TTL 15s, FIN probe before checkout);
//! - Rate-limited streams (global + per-torrent dual token buckets; the
//!   read path `await`s permits for backpressure).
//! - UdpDemux: a shared v4/v6 UDP entry dispatching DHT / UDP-tracker /
//!   µTP into three bounded channels by packet signature.
//! - MSE/PE: DH-768 + ARC4 (first 1024B of keystream dropped) + PLAIN
//!   negotiation + the `Encrypted<S>` wrapper stream and an inbound
//!   sniffing pure function (SPEC §6.4/§6.1).
//! - µTP (BEP-29): v1 header/extension codec, Syn/SynRecv/Connected/Fin/
//!   Closed state machine, sack selective retransmit, LEDBAT congestion
//!   control, UtpListener (SPEC §6.5; `UtpStream` added at the frozen
//!   PeerTransport seam).
//! - NAT: NAT-PMP (RFC 6886 hand-written packets) + UPnP IGD (rupnp)
//!   port mapping with 60min renewal, NatActor command/event face
//!   (SPEC §6.8; `Mapped`/`Failed` events feed the announce port view).
//! - winpath: Windows long-path verbatim conversion — a uniform wrapper
//!   applied at each crate's fs choke point just before a path is handed
//!   to the OS (zero-cost identity off Windows).
//!
//! Status: udp_demux, mse, utp, nat, dns implemented; the remaining
//! faces are scaffolding. Hard constraints: SPEC §2 (unsafe banned
//! repo-wide; disk/blocking IO always via `spawn_blocking`).
//!
//! This crate must not depend on other workspace crates.

pub mod block_arena;

pub mod dns;

// `BH_*` env-knob central registry (the single read face shared by all
// downstream public consumers; registry and read-timing classes in the
// module docs).
pub mod knobs;

pub mod metrics;

pub mod mse;

pub mod nat;

pub mod rate_limit;

// Unified URL log-redaction face — the lowest common reachable layer
// shared by bt/http across protocols (promoted from the taiji-bt
// tracker; placement rationale as for `text`).
pub mod redact;

// Single source for file-name display-spoofing / hidden-injection code
// point classification — the lowest common reachable layer for the
// bt/http/core consumers (rationale in the module docs).
pub mod text;

pub mod udp_demux;
pub mod unverified_budget;

pub mod utp;

pub mod tls;

pub mod winpath;

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

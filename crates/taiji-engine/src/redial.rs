//! Redial outcome event wiring: `RedialReport`/`DialOutcome`/
//! `redial_report`.
//!
//! Owns: the dial-task -> main-loop outcome report channel shape.
//! Does not own: the redial pool itself and its sweep cadence
//! (taiji_domain::redial + the run main loop).

use std::net::SocketAddr;

use tokio::sync::mpsc;

/// Redial outcome event (peer_connect -> main loop; only redial dials
/// carry a report sender).
#[derive(Debug)]
pub(super) struct RedialReport {
    pub(super) addr: SocketAddr,
    pub(super) outcome: DialOutcome,
}

/// Redial dial outcome.
#[derive(Debug)]
pub(super) enum DialOutcome {
    /// A transport's handshake succeeded (the connection is rebuilt;
    /// the registration event arrives later — this event converges the
    /// pool state first).
    Connected,
    /// The dial plan is exhausted (all transports failed) -> failure
    /// backoff / eviction (the redial module docs).
    Failed,
    /// IpGuard interception (the peer is banned) -> the entry is
    /// removed, never redialed.
    Blocked,
}
/// Redial outcome report (a None sender = a regular dial, no-op; the
/// channel is bounded at 64 and a full channel awaits = backpressure;
/// at engine teardown the channel closes -> silently dropped).
pub(super) async fn redial_report(
    redial: Option<&mpsc::Sender<RedialReport>>,
    addr: SocketAddr,
    outcome: DialOutcome,
) {
    if let Some(tx) = redial {
        let _ = tx.send(RedialReport { addr, outcome }).await;
    }
}

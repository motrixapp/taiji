//! Communication-handle surface for [`crate::peer::PeerTask`]:
//! [`PeerTaskHandle`] implements the [`PeerHandle`] trait (Clone: the
//! engine registry and the layers prefetch pool share one connection's
//! command surface), plus lock-free state-mirror reads (interested /
//! peer_choking / snubbed — inputs to the choking rounds and dispatch
//! pick points).

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::command::{PeerCommand, PeerCommandRejected, PeerHandle};

/// Communication handle for [`PeerTask`]: implements the `PeerHandle`
/// trait (Clone: multiple holders — the engine registry and the layers
/// prefetch pool share one connection's command surface).
///
/// Fields are `pub(super)`: constructed only by
/// [`crate::peer::PeerTask::spawn`] in this module; external access stays
/// on the trait methods.
#[derive(Clone)]
pub struct PeerTaskHandle {
    pub(super) cmd_tx: mpsc::Sender<PeerCommand>,
    pub(super) token: CancellationToken,
    pub(super) interested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Mirror of the peer's choke state toward us: initial value true
    /// (BEP3: both sides start choked when the connection opens);
    /// updated by Choke/Unchoke frames. Read by the choking rounds and
    /// dispatch pick points.
    pub(super) peer_choking: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Snub mirror: set on a request-slot timeout, cleared on a matching
    /// piece (lock-free projection of `RequestBook::is_snubbed`;
    /// leecher-side exclusion input for the choking round,
    /// `BtLeecherStateChoke::executeChoke`).
    pub(super) snubbed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Mirror of the peer's ut_holepunch negotiation: set once the peer's
    /// ext-handshake m dict advertises `ut_holepunch` (equivalent to
    /// libtorrent `supports_holepunch()`, i.e. `m_holepunch_id != 0`, in
    /// bt_peer_connection.cpp). Lock-free read surface for relay-target /
    /// introducer eligibility (used by the engine main loop).
    pub(super) supports_holepunch: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Lock-free mirror of this connection's in-flight (outstanding)
    /// request count: projected from RequestBook pending requests (SET on
    /// every change of the slot set; the single write point lives in the
    /// bookkeeping). The engine's 1s tick samples it per connection as
    /// per-peer request-window depth telemetry.
    pub(super) in_flight: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Mirror of this connection's adaptive request timeout (ms):
    /// RequestBook SETs the current adaptive value on every sample (single
    /// write point `RequestBook::publish_timeout`; lock-free single
    /// writer — the peer task writes, the engine reads, same discipline as
    /// the in_flight mirror). The engine's reissue window consumes it as
    /// `max(2s, min(this value, 5s))` (engine `dispatch::reissue_window`).
    pub(super) adaptive_timeout: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Mirror of this connection's BDP target request window (blocks):
    /// RequestBook SETs it on every window change (single write point
    /// `RequestBook::sync_window`; lock-free single writer — the peer task
    /// writes, the engine reads). The engine dispatch round's supply cap
    /// is `min(this value - in_flight, command-channel capacity)`
    /// (engine `dispatch::supply_cap`).
    pub(super) target_window: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Endgame-tail window-floor override (the reverse
    /// direction of the mirrors above — the engine writes, the peer
    /// task's RequestBook reads it inside `refresh_window`): the dispatch
    /// round raises a holder peer's floor to the tail's missing-block
    /// volume when the torrent enters its endgame tail, and drops it back
    /// to 0 otherwise. 0 = no effect (relax-only `max` in the book).
    pub(super) endgame_window_floor: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl PeerTaskHandle {
    /// Whether the peer is currently interested in us (choking-round
    /// input; lock-free single-variable read).
    pub fn is_interested(&self) -> bool {
        self.interested.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the peer currently chokes us (dispatch pick-point
    /// preference + gauge read).
    pub fn is_choking_us(&self) -> bool {
        self.peer_choking.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether our requests on this connection are snubbed (slot timed
    /// out without an answer; leecher choking-round exclusion input,
    /// `BtLeecherStateChoke::executeChoke`).
    pub fn is_snubbed(&self) -> bool {
        self.snubbed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the peer negotiated ut_holepunch (true as soon as the
    /// peer's m dict advertises it — equivalent to libtorrent
    /// `bt_peer_connection::supports_holepunch`).
    pub fn supports_holepunch(&self) -> bool {
        self.supports_holepunch
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Current number of outstanding requests on this connection
    /// (lock-free mirror of RequestBook in-flight; the 1s-tick sampling
    /// granularity suffices — window depth is a slowly varying quantity).
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Lock-free mirror read of this connection's adaptive request
    /// timeout, millisecond precision. Before any sample = the
    /// `--bt-request-timeout` config cap (default 60s — identical to the
    /// previous fixed-timeout behavior); after sampling = clamp(mean +
    /// 4σ, 2s, config cap) (same formula as libtorrent
    /// `peer_connection.cpp`).
    pub fn adaptive_request_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.adaptive_timeout
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Lock-free mirror read of this connection's BDP target request
    /// window, in blocks. Initial value 6 (both modes); in BDP mode after
    /// sampling = `clamp(3s x payload-rate EWMA / 16KiB, 2, config cap)`
    /// (same formula as libtorrent `peer_connection.cpp`; +1 per received
    /// block during slow start); in fallback mode
    /// (`BH_REQUEST_WINDOW_BDP=0`) = a doubling heuristic (6 -> 256). The
    /// window half of the engine dispatch round's supply cap.
    pub fn target_request_window(&self) -> u64 {
        self.target_window
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Current command-channel capacity (the channel half of the supply
    /// cap): tokio `Sender::capacity()` = remaining permits. Read-only
    /// observation; the bounded discipline is unchanged (on a full
    /// channel, `try_send` still errs and the existing rejected-command
    /// semantics remain as the fallback).
    pub fn command_capacity(&self) -> usize {
        self.cmd_tx.capacity()
    }

    /// Endgame-tail window-floor override write (the engine
    /// dispatch round is the single writer): `blocks` = the tail's
    /// missing-block volume for a peer advertising a missing piece, 0
    /// otherwise. The peer task's RequestBook consumes the value
    /// lazily (its next `refresh_window`) as `max(generic floor,
    /// override)` — relax-only, under the configured cap; 0 detaches
    /// the lift. Lock-free single-variable store, same discipline as
    /// the mirrors (Relaxed — the next book refresh is the consumption
    /// point).
    pub fn set_endgame_window_floor(&self, blocks: u64) {
        self.endgame_window_floor
            .store(blocks, std::sync::atomic::Ordering::Relaxed);
    }

    /// Endgame-tail window-floor override read-back (the observability
    /// seam of [`Self::set_endgame_window_floor`]; the book-side
    /// consumption is lazy, so this reads the commanded value, not the
    /// applied window).
    pub fn endgame_window_floor(&self) -> u64 {
        self.endgame_window_floor
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl PeerHandle for PeerTaskHandle {
    fn command(&self, cmd: PeerCommand) -> Result<(), PeerCommandRejected> {
        self.cmd_tx.try_send(cmd).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => PeerCommandRejected::Full,
            mpsc::error::TrySendError::Closed(_) => PeerCommandRejected::Closed,
        })
    }

    fn shutdown(&self) {
        // Two channels: send the command first (graceful path), then
        // cancel the token (fallback; idempotent).
        let _ = self.cmd_tx.try_send(PeerCommand::Shutdown);
        self.token.cancel();
    }
}

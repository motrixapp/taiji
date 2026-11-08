//! PeerTask: the peer connection task — a message loop driving
//! RequestBook / FloodGuard / HaveAdvertiser over the frame codec.
//!
//! # Scope
//!
//! - Input is a byte stream whose handshake is already complete (the
//!   handshake and the BEP-52 upgrade path live elsewhere; `reserved[7] &
//! 0x10` decides the v2 surface). This module neither sends nor receives
//!   handshakes.
//! - Upload serving (inbound request -> fetch the block from disk, reply
//!   with a piece) is injected via [`PeerConfig::source`]. Our outbound
//!   handshakes always set the fast bit (`Reserved::aria2_default`; the
//!   engine-side reserved comes from the same source). Outbound Reject
//!   passes the gate according to the bits negotiated in the peer's
//!   handshake ([`PeerConfig::peer_fast`] — BEP-6 requires both ends to set
//!   the bit; for a peer that did not negotiate, silent drop = BEP3
//!   fallback, see conn.rs `OutboundWriter::send_reject`); `length > 16KiB`
//!   disconnects immediately.
//! - On receiving choke, clear our pending slots locally (aria2
//!   equivalent); whether the peer answers our cleared slots with reject is
//!   its decision — this side does not retry.
//! - Piece selection lives above this module: Have/Bitfield are
//!   debug-logged only.
//!
//! Concurrency discipline:
//! - control commands on a bounded channel (capacity 64 — raised from the
//!   original 8 as the target window clamps up; see
//!   `conn::COMMAND_CHANNEL_CAPACITY`; full = backpressure the caller;
//!   unbounded is forbidden);
//! - piece data channel bounded ([`PeerConfig::data_channel`], default
//!   16): when the read loop's `send().await` has no capacity it stops
//!   reading frames, propagating backpressure to TCP;
//! - shutdown is dual-channel: parent-token hierarchical propagation
//!   plus an explicit `PeerCommand::Shutdown`;
//! - no blocking operations, no locks held across await.
//!
//! # Module layout
//!
//! - `command`: control-command surface ([`PeerCommand`] / [`HashFetch`] /
//!   [`HashRequestError`] / [`PeerCommandRejected`] / [`PeerHandle`]);
//! - `config`: [`PeerConfig`] (+Debug/flat) and the connection event /
//!   final-state types ([`AvailEvent`] / [`PexEvent`] / [`PexExt`] /
//!   [`PieceData`] / [`PeerError`] / [`PeerEnd`]);
//! - `sources`: [`PieceSource`] / [`HashSource`] data-source traits;
//! - `ext`: BEP10 extension surface ([`ExtConfig`], requester fetch
//!   sessions, and `handle_extended` / ut_metadata / ut_pex frame dispatch);
//! - `handle`: [`PeerTaskHandle`] ([`PeerHandle`] impl + state mirrors);
//! - `handshake`: BEP3 handshake exchange surface (exchange / accept_any /
//!   accept);
//! - `conn`: [`PeerTask`] spawning and the message-loop body (connection
//!   state machine);
//! - `inbound`: inbound message handling (`serve_request` / `InboundCtx` /
//!   `handle_inbound`) and the hash-request rate-limit constants;
//! - `read_pool`: face-level read pool (serve_request disk reads moved off
//!   the event loop: bounded queue + spawn_blocking dispatcher + in-order
//!   per-request re-injection + 16KiB aligned block-buffer reuse);
//! - `tests` / `seeding_tests`: unit tests.
//!
//! Upstream anchor mapping: docs/design/peer-protocol.md

use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;

use crate::piece_id::PieceId;

// Test submodules consume these via `use super::*` (no bindings in lib
// builds, so no unused warnings).
#[cfg(test)]
use crate::peer_wire::Message;
#[cfg(test)]
use crate::piece_id::Addressing;
#[cfg(test)]
use crate::request_book::DispatchError;
#[cfg(test)]
use futures::SinkExt;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::time::{Duration, Instant};
#[cfg(test)]
use tokio_util::codec::{FramedRead, FramedWrite};
#[cfg(test)]
use tokio_util::sync::CancellationToken;

/// Block-data direct-delivery seam (data-plane bypass): when `Some`, a
/// `Message::Piece` received by PeerTask no longer hops through
/// `data_tx` -> attach_peer forwarding task -> face channel; instead the
/// protocol-verified block payload is delivered, within the same task,
/// straight to the face-level store pipeline channel — the engine select
/// loop receives control signals only.
///
/// Neutral types: bt does not depend on core; [`PieceId`]/[`Bytes`] are
/// owned by bt/shared dependencies. Addressing layering is unchanged —
/// the wire-index bounds check (`from_wire` returning None ->
/// [`PeerError::BadPieceIndex`] disconnect) still runs as-is in the
/// `Message::Piece` arm on the bt side (protocol-violation surface
/// unchanged), so the `id` this trait receives is already a valid
/// [`PieceId`]; `to_flat` flat-offset conversion and its bounds defense
/// stay on the core side (the same conversion point as the old forwarding
/// path, with identical behavior).
///
/// Divergence note: libtorrent receives and dispatches on the single
/// network thread; here the peer task and the store pipeline task are
/// separate tokio tasks, so "direct" removes only the intermediate
/// forwarding-task hop — the task boundary still crosses a bounded
/// channel, and a full channel backpressures: while
/// [`BlockSink::deliver_backpressure`] awaits, this connection's frame
/// reading pauses and the peer's send window closes.
///
/// Upstream anchor mapping: docs/design/peer-protocol.md
pub trait BlockSink: Send + Sync + 'static {
    /// Fast path: synchronous direct delivery while the channel has
    /// capacity (zero allocation, zero await). `Err(block)` = channel
    /// full; the payload is returned to the caller unchanged and the
    /// [`BlockSink::deliver_backpressure`] slow path is used.
    fn try_deliver(&self, id: PieceId, begin: u32, block: Bytes) -> Result<(), Bytes>;

    /// Slow-path backpressured delivery (boxed future; called only when
    /// `try_deliver` is full — required for object safety, so the normal
    /// hot path pays no boxing cost).
    fn deliver_backpressure(
        &self,
        id: PieceId,
        begin: u32,
        block: Bytes,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

pub use command::{HashFetch, HashRequestError, PeerCommand, PeerCommandRejected, PeerHandle};
pub use config::{
    AvailEvent, ClientDenyCheck, HolepunchEvent, HolepunchExt, KEEPALIVE_INTERVAL, PeerConfig,
    PeerEnd, PeerError, PexEvent, PexExt, PieceData,
};
pub use conn::PeerTask;
pub use ext::{
    ExpectedInfoHash, ExtConfig, HOLEPUNCH_CONNECT_LIMIT, HOLEPUNCH_CONNECT_WINDOW,
    HOLEPUNCH_REQUEST_LIMIT, HOLEPUNCH_REQUEST_WINDOW, MetadataBytes, MetadataFetchSpec,
    MetadataFetched, MetadataSource, OUTBOUND_UT_HOLEPUNCH_ID, OUTBOUND_UT_METADATA_ID,
    OUTBOUND_UT_PEX_ID,
};
pub use handle::PeerTaskHandle;
pub use handshake::{handshake_accept, handshake_accept_any, handshake_exchange};
pub use inbound::{HASH_REQUEST_LIMIT, HASH_REQUEST_WINDOW};
pub use read_pool::ReadPool;
pub use sources::{HashSource, PieceSource};

mod command;
mod config;
mod conn;
mod ext;
mod handle;
mod handshake;
mod inbound;
mod read_pool;
mod sources;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod serve_pool_tests;

#[cfg(test)]
mod holepunch_tests;

#[cfg(test)]
mod seeding_tests;

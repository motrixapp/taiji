//! PeerTask connection state machine: [`PeerTask::spawn`] (bounded
//! command channel + lock-free state mirrors, assembled atomically) and
//! the message loop [`peer_loop`] — `select { token, cmd, frame, tick }`
//! (biased: token first) driving RequestBook / FloodGuard /
//! HaveAdvertiser, choking state, pending hash-request bookkeeping,
//! ut_pex outbound cadence, and idle-gated keepalive. [`OutboundWriter`]
//! is the single point recording outbound activity.
//!
//! Upstream anchor mapping: docs/design/peer-protocol.md

use std::time::Instant;

use bytes::Bytes;
use futures::{FutureExt, SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::command::{HashFetch, HashRequestError};
use super::ext::{MetadataFetchSession, OUTBOUND_UT_METADATA_ID, OUTBOUND_UT_PEX_ID};
use super::handle::PeerTaskHandle;
use super::inbound::{InboundCtx, ServeCtx, handle_inbound};
use super::read_pool::ServeQueue;
use super::{ExtConfig, PeerCommand, PeerConfig, PeerEnd, PieceData};
use crate::peer_wire::{ExtHandshake, FrameCodec, Message, PeerWireError};
use crate::pex::{PexCandidate, PexOffer, PexSwarmSender};
use crate::request_book::{DispatchError, FloodGuard, HaveAdvertiser, RequestBook, WindowMode};

/// Control command channel capacity. Sized as `min(target window, 64)` =
/// 64: this is the command queue buffer, not the supply window — the
/// authoritative supply cap is the RequestBook window plus the engine
/// dispatch round's `min(target − in-flight, channel slack)` bound
/// (taiji-core `dispatch::supply_cap`). Bounded-channel discipline
/// unchanged: when full, `try_send` returns Err and the caller retries
/// on its next dispatch round.
pub(super) const COMMAND_CHANNEL_CAPACITY: usize = 64;

/// Request coalescing fallback switch: `BH_REQUEST_COALESCE=0` falls
/// back to one flush per command (the existing per-command syscall
/// cadence preserved bit-for-bit); any other value (including unset)
/// batches. Evaluated once when `peer_loop` assembles (process-level
/// switch, not hot reloaded; same shape as
/// [`crate::request_book::WindowMode::from_env`]). Deterministic tests
/// pin it via [`PeerConfig::request_coalesce`] and do not depend on the
/// environment variable. Parsing and read timing are registered in
/// `taiji_io::knobs` (read at construction).
fn request_coalesce_enabled() -> bool {
    taiji_io::knobs::request_coalesce_enabled()
}

/// Idle Framed-buffer shrink threshold: a connection whose
/// last inbound frame is older than this gets its FramedRead / FramedWrite
/// internal `BytesMut` swapped down to zero capacity at the next flooding
/// tick (5s cadence — so the effective detection window is 5-10s). aria2
/// keeps an idle receive buffer small (`receiveBufferSize` 4KiB class) and
/// grows on demand; `BytesMut` never shrinks on `advance`, so without this
/// a 16-32KiB read high-water (one piece burst) stays resident per
/// connection for its whole life — 36-90 connections of mostly-idle
/// seeding peers hold ~1-3MB of dead capacity. Checked only when the
/// buffer is fully drained: a partially received frame is never dropped.
pub(super) const READ_BUF_IDLE_SHRINK: std::time::Duration = std::time::Duration::from_secs(5);

/// Idle-buffer shrink fallback switch (`BH_READ_BUF_SHRINK=0` = off, the
/// frozen never-shrink behavior); same read-timing class as
/// [`request_coalesce_enabled`].
fn read_buf_shrink_enabled() -> bool {
    taiji_io::knobs::read_buf_shrink_enabled()
}

/// Swap a fully-drained Framed buffer down to zero capacity.
///
/// Returns the freed capacity (0 = nothing done). Safety contract: only
/// called when the buffer holds no unparsed bytes (`is_empty`) — a partial
/// frame must never be discarded. The decoder's length-prefix state is
/// untouched: an empty buffer satisfies every "need more bytes" wait, so
/// the codec resumes correctly on the next read (and its one-shot exact
/// `reserve` regrows the buffer to the next frame's full size, see
/// `FrameCodec::decode`). Previously frozen zero-copy bodies (`Bytes`
/// sharing the old allocation) keep it alive by refcount — the swap is a
/// plain drop of the `BytesMut` handle.
fn shrink_drained_framed_buf(buf: &mut bytes::BytesMut) -> usize {
    let cap = buf.capacity();
    if cap > 0 && buf.is_empty() {
        *buf = bytes::BytesMut::new();
        cap
    } else {
        0
    }
}

/// Flush the Request batch accumulated by the command drain window:
/// batched frames go out in one write ([`OutboundWriter::send_batch`]),
/// then replies are sent uniformly. Invariant preserved: a successful
/// reply means the request bytes have been written out (the engine
/// consumes replies by polling `try_recv`, never blocking). On flush
/// failure every batched reply gets `Err(DispatchError::Io)` — the
/// same shape as a single-write failure, left to the engine's
/// re-dispatch window — and the connection is not torn down here (a
/// later read/write ends it).
async fn flush_coalesced<W>(
    writer: &mut OutboundWriter<W>,
    batch: &mut Vec<Message>,
    replies: &mut Vec<oneshot::Sender<Result<(), DispatchError>>>,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    if batch.is_empty() {
        return;
    }
    let result = writer.send_batch(batch.drain(..)).await;
    for reply in replies.drain(..) {
        let _ = match &result {
            Ok(()) => reply.send(Ok(())),
            Err(e) => reply.send(Err(DispatchError::Io(e.to_string()))),
        };
    }
}

/// Outbound write face: a [`FramedWrite`] wrapper where every outbound
/// frame refreshes `last_sent_at` via [`OutboundWriter::send`] — the
/// single point for the keepalive idle check. The single point matters
/// because outbound frames are scattered across three faces: the
/// command face, the inbound serving face (piece / reject replies in
/// inbound.rs), and the extension face (ut_metadata / ut_pex /
/// holepunch in ext.rs); per-call-site bookkeeping would leak.
/// `last_sent_at` starts at connection assembly (aria2
/// `DefaultBtInteractive.cc` `doPostHandshakeProcessing` resets
/// `keepAliveTimer_` the same way).
///
/// `peer_fast` is the peer's BEP-6 fast negotiation mirror, read once
/// from [`PeerConfig::peer_fast`] at assembly and fixed for the
/// connection's life (negotiation bits only change during the
/// handshake). BEP-6 outbound messages (currently only Reject) all go
/// through [`OutboundWriter::send_reject`], mirroring libtorrent's
/// `m_supports_fast` on the connection object with
/// `write_reject_request` early-returning when unset
/// (bt_peer_connection.cpp).
pub(super) struct OutboundWriter<W> {
    inner: FramedWrite<W, FrameCodec>,
    last_sent_at: Instant,
    peer_fast: bool,
}

impl<W> OutboundWriter<W> {
    /// `now` is the idle timer origin (connection assembly; see the
    /// struct docs).
    pub(super) fn new(inner: FramedWrite<W, FrameCodec>, now: Instant, peer_fast: bool) -> Self {
        OutboundWriter {
            inner,
            last_sent_at: now,
            peer_fast,
        }
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> OutboundWriter<W> {
    /// Send one frame and refresh the outbound-activity timestamp
    /// (refresh before writing: a write failure is the disconnect path,
    /// where the timer has no observers). Outbound activity is what the
    /// peer can observe of us; it is unrelated to flood counting
    /// (FloodGuard watches inbound only).
    pub(super) async fn send(&mut self, msg: Message) -> Result<(), PeerWireError> {
        self.last_sent_at = Instant::now();
        self.inner.send(msg).await
    }

    /// Batched outbound: the whole batch is encoded into the
    /// [`FramedWrite`] internal `BytesMut` and flushed once — one
    /// outbound `write` carries every frame (partial writes continue
    /// through the flush loop, `write_all` semantics), i.e. one TCP
    /// segment carries the whole request batch (libtorrent writes
    /// batches under a cork; upstream anchor mapping in
    /// docs/design/peer-protocol.md).
    ///
    /// Wire bytes are bit-identical: encoding goes through the same
    /// `FrameCodec` / `Message::encode` (4-byte length prefix
    /// included); only the flush rhythm changes from per-frame to once
    /// per batch — BT stream framing splits on the length prefix and
    /// has no message-boundary semantics (BEP3), so the peer cannot
    /// observe write granularity. Not feeding a flush per frame and
    /// flushing once at the end is observationally equivalent to a
    /// local `BytesMut` batch plus one `write_all` (only the buffer
    /// ownership differs: it lives in FramedWrite's existing capacity
    /// management).
    pub(super) async fn send_batch<I>(&mut self, msgs: I) -> Result<(), PeerWireError>
    where
        I: IntoIterator<Item = Message>,
    {
        self.last_sent_at = Instant::now();
        for msg in msgs {
            self.inner.feed(msg).await?;
        }
        self.inner.flush().await
    }

    /// Keepalive check input: idle time since the last outbound frame.
    pub(super) fn idle_for(&self, now: Instant) -> std::time::Duration {
        now.duration_since(self.last_sent_at)
    }

    /// Idle-buffer shrink face: swap the FramedWrite internal
    /// `BytesMut` down to zero capacity when it is fully flushed. Safe at
    /// any await point of this loop: every outbound path (`send`,
    /// `send_batch`) flushes to completion before returning, so the buffer
    /// only holds bytes mid-call. The 16-32KiB high-water from serving
    /// piece frames would otherwise stay resident for the connection's
    /// life. Returns the freed capacity (0 = nothing done).
    pub(super) fn shrink_idle_write_buffer(&mut self) -> usize {
        shrink_drained_framed_buf(self.inner.write_buffer_mut())
    }

    /// Single gate for BEP-6 Reject outbound (the only path for reject
    /// frames): never send to a peer that did not negotiate fast
    /// (handshake reserved[7]&0x04 missing) — per BEP-6, "If the fast
    /// extension is disabled and a peer receives a reject request then
    /// the peer MUST close the connection", so sending Reject would
    /// force that disconnect. Fall back to BEP-3 semantics: unservable
    /// requests (choked / out of range / no source) are dropped
    /// silently and left to the peer's request timeouts — the same rule
    /// as aria2 `BtRequestMessage.cc` (the else branch queues a reject
    /// only when `isFastExtensionEnabled()`) and libtorrent
    /// `write_reject_request`'s `if (!m_supports_fast) return;`
    /// (bt_peer_connection.cpp). Servable requests are served as
    /// usual: `send` is untouched by this gate; serving is orthogonal
    /// to fast negotiation.
    pub(super) async fn send_reject(
        &mut self,
        index: u32,
        begin: u32,
        length: u32,
    ) -> Result<(), PeerWireError> {
        if !self.peer_fast {
            debug!(target: "taiji::bt::peer", index, begin, length,
                "request dropped without reject (BEP6 not negotiated; BEP3 timeout semantics)");
            return Ok(());
        }
        self.send(Message::Reject {
            index,
            begin,
            length,
        })
        .await
    }
}

/// PeerTask: the message loop for a post-handshake connection.
#[derive(Debug)]
pub struct PeerTask;

impl PeerTask {
    /// Spawn the PeerTask (`socket` is a byte stream past the
    /// handshake).
    ///
    /// Returns `(PeerTaskHandle, JoinHandle<PeerEnd>, piece data
    /// receiver)`.
    pub fn spawn<S>(
        parent: &CancellationToken,
        socket: S,
        config: PeerConfig,
    ) -> (
        PeerTaskHandle,
        tokio::task::JoinHandle<PeerEnd>,
        mpsc::Receiver<PieceData>,
    )
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let token = parent.child_token();
        let handle_token = token.clone();
        // Capacity 64: see [`COMMAND_CHANNEL_CAPACITY`]. A full channel
        // backpressures the caller (unbounded channels are not allowed).
        let (cmd_tx, cmd_rx) = mpsc::channel::<PeerCommand>(COMMAND_CHANNEL_CAPACITY);
        let (data_tx, data_rx) = mpsc::channel(config.data_channel);
        // Peer interest flag: written by the read loop, read lock-free
        // by the choking layer via the handle (single AtomicBool, no
        // lock across awaits).
        let interested = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let loop_interested = std::sync::Arc::clone(&interested);
        // Peer choke mirror + snub mirror (BEP3: a fresh connection
        // starts with the peer choking us).
        let peer_choking = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let loop_choking = std::sync::Arc::clone(&peer_choking);
        let snubbed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let loop_snubbed = std::sync::Arc::clone(&snubbed);
        // Peer ut_holepunch negotiation mirror: set when the peer's ext
        // handshake advertises it (lock-free read = the engine's
        // relay/introducer eligibility check, see PeerTaskHandle).
        let supports_holepunch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let loop_supports_holepunch = std::sync::Arc::clone(&supports_holepunch);
        // Lock-free in-flight mirror for this connection: SET on every
        // RequestBook slot change (single sync point:
        // `RequestBook::sync_in_flight`); the engine samples it per 1s
        // tick via the handle (per-peer request window telemetry).
        let in_flight = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let loop_in_flight = std::sync::Arc::clone(&in_flight);
        // Lock-free adaptive request timeout mirror: SET by RequestBook
        // on every sample (sync point: `RequestBook::publish_timeout`);
        // consumed by the engine's reissue window =
        // max(2s, min(adaptive, 5s)) (engine dispatch::reissue_window
        // reads via the handle, lock-free). Initialized at construction
        // to the configured cap (no samples yet — RequestBook
        // republishes the same value on attach): the handle is readable
        // from spawn on and must never expose an unpublished 0ms (0
        // would clamp to the 2s floor, i.e. the fallback window).
        let adaptive_timeout = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            u64::try_from(config.request_timeout.as_millis()).unwrap_or(u64::MAX),
        ));
        let loop_adaptive_timeout = std::sync::Arc::clone(&adaptive_timeout);
        // Lock-free BDP target request window mirror: SET on every
        // RequestBook window change (sync point:
        // `RequestBook::sync_window`); consumed as the engine
        // dispatch-round supply cap = min(target − in-flight, channel
        // slack) (engine dispatch::supply_cap reads via the handle,
        // lock-free). Initialized at construction to the initial window
        // (same starting window in both modes, configurable via
        // `BH_REQ_WINDOW_INIT` — default 16, `6` restores the aria2
        // value — read at the same point and value as
        // `RequestBook::new`, and clamped to the cap exactly like
        // `RequestBook::with_max_out_request_queue`): the handle is
        // readable from spawn on and must never expose an unpublished 0
        // (0 would read as zero supply).
        let target_window = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
            u64::try_from(taiji_io::knobs::req_window_init().min(config.max_out_request_queue))
                .unwrap_or(u64::MAX),
        ));
        let loop_target_window = std::sync::Arc::clone(&target_window);
        // Endgame-tail window-floor override (the engine ->
        // book seam, the reverse direction of the three read mirrors
        // above): starts at 0 (= no effect), the engine's dispatch round
        // raises it for holder peers when the torrent enters its
        // endgame tail; RequestBook::refresh_window consumes it as
        // `max(generic floor, override)` (relax-only, under the cap).
        let endgame_window_floor = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let loop_endgame_window_floor = std::sync::Arc::clone(&endgame_window_floor);

        let join = tokio::spawn(async move {
            peer_loop(
                socket,
                config,
                token,
                cmd_rx,
                data_tx,
                loop_interested,
                loop_choking,
                loop_snubbed,
                loop_supports_holepunch,
                loop_in_flight,
                loop_adaptive_timeout,
                loop_target_window,
                loop_endgame_window_floor,
            )
            .await
        });

        (
            PeerTaskHandle {
                cmd_tx,
                token: handle_token,
                interested,
                peer_choking,
                snubbed,
                supports_holepunch,
                in_flight,
                adaptive_timeout,
                target_window,
                endgame_window_floor,
            },
            join,
            data_rx,
        )
    }
}

/// The requester's pending hash request: snapshot of the outbound
/// header tuple + the reply channel.
pub(super) struct HashRequestPending {
    root: [u8; 32],
    base: u32,
    index: u32,
    length: u32,
    proof: u32,
    pub(super) reply: oneshot::Sender<Result<HashFetch, HashRequestError>>,
}

impl HashRequestPending {
    pub(super) fn matches(
        &self,
        root: &[u8; 32],
        base: u32,
        index: u32,
        length: u32,
        proof: u32,
    ) -> bool {
        self.root == *root
            && self.base == base
            && self.index == index
            && self.length == length
            && self.proof == proof
    }
}

/// Message loop body: select { token, cmd, frame, tick } (biased: token
/// first).
#[expect(
    clippy::too_many_arguments,
    reason = "spawn-wired loop surface: each argument is a distinct channel/flag half, consumed exactly once"
)]
async fn peer_loop<S>(
    socket: S,
    config: PeerConfig,
    token: CancellationToken,
    mut cmd_rx: mpsc::Receiver<PeerCommand>,
    data_tx: mpsc::Sender<PieceData>,
    interested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    peer_choking: std::sync::Arc<std::sync::atomic::AtomicBool>,
    snubbed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    supports_holepunch: std::sync::Arc<std::sync::atomic::AtomicBool>,
    in_flight: std::sync::Arc<std::sync::atomic::AtomicU64>,
    adaptive_timeout: std::sync::Arc<std::sync::atomic::AtomicU64>,
    target_window: std::sync::Arc<std::sync::atomic::AtomicU64>,
    endgame_window_floor: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> PeerEnd
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let PeerConfig {
        addressing,
        piece_bytes,
        allowed_fast,
        request_timeout,
        max_out_request_queue,
        window_bdp,
        request_coalesce,
        read_buf_shrink,
        flooding_interval,
        keepalive_interval,
        choke_grace,
        mut source,
        mut hash_source,
        cuid,
        avail_tx,
        port_tx,
        uploaded,
        downloaded,
        remote_ip,
        ext,
        upload_only: mut my_upload_only,
        listen_port: mut my_listen_port,
        peer_upload_only,
        mut super_seed,
        holepunch: hp_ext,
        client_deny,
        read_pool,
        block_arena,
        direct_block_sink,
        peer_fast,
        ..
    } = config;
    let ExtConfig {
        enabled: ext_enabled,
        metadata: metadata_serve,
        fetch: fetch_spec,
        pex: pex_ext,
    } = ext;
    let mut allowed_fast = allowed_fast;
    // Window mode (test injection face): None = environment default
    // (`BH_REQUEST_WINDOW_BDP=0` falls back to the doubling heuristic).
    let window_mode = match window_bdp {
        Some(true) => WindowMode::Bdp,
        Some(false) => WindowMode::LegacyDoubling,
        None => WindowMode::from_env(),
    };
    // Request batching (test injection face): None = environment
    // default (`BH_REQUEST_COALESCE=0` writes per command).
    let request_coalesce = request_coalesce.unwrap_or_else(request_coalesce_enabled);
    // Idle Framed-buffer shrink (test injection face): None = environment
    // default (`BH_READ_BUF_SHRINK=0` keeps the frozen never-shrink
    // behavior).
    let read_buf_shrink = read_buf_shrink.unwrap_or_else(read_buf_shrink_enabled);
    // Inbound-activity origin for the idle-buffer shrink (refreshed at
    // every frame-arm entry; the tick arm compares it against
    // [`READ_BUF_IDLE_SHRINK`]).
    let mut last_inbound_at = Instant::now();
    // Duplex split: separate Framed read/write halves, usable
    // concurrently inside select (FrameCodec has no shared state). The
    // write half is wrapped by OutboundWriter: any outbound frame
    // refreshes the idle timer.
    let (read_half, write_half) = tokio::io::split(socket);
    // The read half decodes into face-level pooled blocks
    // (PeerConfig::block_arena; None = the existing frozen shared
    // buffer path). The write half needs no pool.
    let reader_codec = match &block_arena {
        Some(arena) => FrameCodec::with_arena(std::sync::Arc::clone(arena)),
        None => FrameCodec::default(),
    };
    // Initial read-buffer capacity record: the capacity deliberately
    // stays at the tokio-util 8KiB default. `Throttled`'s staging read
    // caps its chunk at the caller-side `out.remaining()`
    // (io/rate_limit.rs poll_read_gated, Gate::Idle), so the FramedRead
    // initial capacity IS the rate-limit permit granularity — a 1KiB
    // start measurably reshapes throttled transfer pacing
    // (rate_limit_engine's floor assertion fails at ~63% of the
    // theoretical wall). The freeze seam "initial buffer does not
    // change behavior" is falsified on the throttled face; decoupling
    // the permit granularity from the caller buffer is a rate-limit
    // semantics change, out of scope here. The idle-buffer shrink
    // already takes steady-state idle capacity to zero.
    let mut reader = FramedRead::new(read_half, reader_codec);
    let mut writer = OutboundWriter::new(
        FramedWrite::new(write_half, FrameCodec::default()),
        Instant::now(),
        peer_fast,
    );
    // Request bookkeeping: attach the in-flight lock-free mirror (slot
    // changes sync immediately; the default-None path costs nothing —
    // see RequestBook docs), the adaptive timeout mirror (published on
    // every sample; engine reissue-window read side), the BDP target
    // window mirror with configurable cap (published on every window
    // change; engine supply-cap read side), and the endgame-tail
    // window-floor override (engine write side, book read
    // side inside refresh_window).
    let mut book = RequestBook::new(request_timeout)
        .with_window_mode(window_mode)
        .with_max_out_request_queue(max_out_request_queue)
        .with_in_flight_mirror(std::sync::Arc::clone(&in_flight))
        .with_adaptive_timeout_mirror(std::sync::Arc::clone(&adaptive_timeout))
        .with_target_window_mirror(std::sync::Arc::clone(&target_window))
        .with_endgame_window_floor(std::sync::Arc::clone(&endgame_window_floor));
    let mut flood = FloodGuard::new(flooding_interval, Instant::now());
    // Our choke state: BEP3 starts both sides choked; choking rounds
    // flip it via SendUnchoke/SendChoke. While choked, an inbound
    // request → reject (BEP3; an obligation of fast-extension
    // advertisers).
    let mut am_choking = true;
    // When we last actually sent a Choke frame (reject-pump guard):
    // within `config.choke_grace` an inbound request is only rejected;
    // past the grace = [`PeerError::RequestsWhileChoked`] disconnect
    // (libtorrent peer_connection.cpp). None = this connection never
    // sent Choke (early requests while initially choked are only
    // rejected — the deliberate divergence).
    let mut choke_sent_at: Option<Instant> = None;
    // Pieces suggested by the peer (BEP-6 suggest): inside the race
    // window between a suggest and our request arriving, deliveries of
    // these pieces are not judged unsolicited (libtorrent
    // incoming_piece tolerates all non-requested blocks as redundant
    // bytes — peer_connection.cpp; this implementation deliberately
    // narrows tolerance to the suggest / allowed-fast sets). Capped
    // defensively: cleared at the cap (suggest is a heuristic hint).
    let mut suggested: std::collections::HashSet<u32> = std::collections::HashSet::new();
    // Hash request rate limit (fixed window) + the base=0 "immediately
    // follows piece serving" rule state.
    let mut hash_window_start = Instant::now();
    let mut hash_window_count: u32 = 0;
    let mut last_piece_served = false;
    let mut have = HaveAdvertiser::new();
    let mut tick = tokio::time::interval(flooding_interval);
    let mut metadata_tick = tokio::time::interval(std::time::Duration::from_millis(250));
    metadata_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The requester's pending hash request: header tuple + reply
    // channel. BEP-52 requires hashes to correlate with hash request —
    // matched by full tuple equality; at most one in flight per
    // connection (lazy serial fetch semantics, see
    // PeerCommand::RequestHashes).
    let mut pending_hash: Option<HashRequestPending> = None;
    // ---- BEP-10 extension face ----
    // Our ext handshake: advertise the ut_metadata outbound id; attach
    // metadata_size when we hold metadata (aria2
    // `HandshakeExtensionMessage` face: the m dict + metadata_size is
    // the holder's announcement). When the ut_pex gate is on, advertise
    // it too (`m_ut_pex = Some(OUTBOUND_UT_PEX_ID)`; None = private /
    // disabled — not advertised and not consumed, the
    // apply_pex_negotiation "registry removal" semantics).
    // BEP-21: attach `upload_only: 1` while seeding; suppressed under
    // super-seeding — "if we're super seeding, don't say we're upload
    // only, since it might make peers disconnect" (libtorrent
    // bt_peer_connection.cpp; a super-seed advertises one piece and
    // upload_only would make peers misjudge it and disconnect early).
    // `v` = [`crate::tracker::PEER_AGENT`] (the same string as the HTTP
    // announce UA — libtorrent defaults v to user_agent,
    // bt_peer_connection.cpp; identity unified as taiji/<semver>,
    // separate from the configurable peer_id prefix).
    let my_ext = ExtHandshake {
        m_ut_metadata: Some(OUTBOUND_UT_METADATA_ID),
        m_ut_pex: pex_ext.as_ref().map(|_| OUTBOUND_UT_PEX_ID),
        // Advertise ut_holepunch when the gate is on (None = not
        // advertised and not consumed — the "registry removal"
        // semantics, same shape as the ut_pex gate).
        m_ut_holepunch: hp_ext
            .as_ref()
            .map(|_| crate::holepunch::OUTBOUND_UT_HOLEPUNCH_ID),
        metadata_size: metadata_serve.as_ref().map(|m| m.metadata().len() as u32),
        upload_only: my_upload_only && super_seed.is_none(),
        p: (my_listen_port != 0).then_some(my_listen_port),
        v: Some(crate::tracker::PEER_AGENT.to_string()),
        ..ExtHandshake::default()
    };
    if ext_enabled {
        match my_ext.encode() {
            Ok(payload) => {
                // Advertise sampling (debug): the m dict keys (once per
                // connection, low frequency).
                debug!(target: "taiji::bt::peer",
                    ut_metadata = my_ext.m_ut_metadata,
                    ut_pex = my_ext.m_ut_pex,
                    ut_holepunch = my_ext.m_ut_holepunch,
                    "ext handshake advertised");
                let _ = writer.send(Message::Extended { ext_id: 0, payload }).await;
            }
            Err(e) => debug!(target: "taiji::bt::peer", %e, "ext handshake encode failed"),
        }
    }
    // The peer's inbound ut_metadata id (from its m dict; unknown
    // extension names are not registered — ExtensionMessageRegistry
    // name-table filtering).
    let mut peer_ut_metadata_id: Option<u8> = None;
    // ---- ut_holepunch face ----
    // The peer's inbound ut_holepunch id (from its m dict — our
    // outbound keys off it).
    let mut peer_ut_holepunch_id: Option<u8> = None;
    // Fixed-window rate-limit state, separate windows for rendezvous /
    // connect (60s window; values in the ext module constants).
    let mut hp_rv_window = Instant::now();
    let mut hp_rv_count: u32 = 0;
    let mut hp_ct_window = Instant::now();
    let mut hp_ct_count: u32 = 0;
    // Inbound ut_pex fixed-window rate-limit state (values in the ext
    // module constants).
    let mut pex_window = Instant::now();
    let mut pex_count: u32 = 0;
    // Tiered inbound ut_pex decode session (the first frame of a
    // connection is exempt and truncated at FIRST_PEX_MAX; later
    // frames keep the 50-cap whole-frame rejection).
    let mut pex_inbound = crate::pex::PexInboundSession::new();
    // ---- ut_pex face ----
    // The peer's inbound ut_pex id (from its m dict — our outbound keys
    // off it).
    let mut peer_ut_pex_id: Option<u8> = None;
    // Outbound cadence state machine (negotiation gate + 60s throttle +
    // capacity + window). Built here and rebuilt when the peer's
    // handshake arrives (peer_msg_id = the peer's advertised id); until
    // then peer_msg_id = None so maybe_build is always None and early
    // frames are not lost.
    let mut pex_sender = PexSwarmSender::new(
        PexOffer::from_negotiation(pex_ext.is_some()),
        None,
        Instant::now(),
    )
    .with_interval(
        pex_ext
            .as_ref()
            .map(|p| p.interval)
            .unwrap_or(crate::pex::DEFAULT_INTERVAL),
    );
    // Session-level candidate snapshot (overwritten by
    // SetPexCandidates; an aria2 peerStorage projection).
    let mut pex_fresh_cands: Vec<PexCandidate> = Vec::new();
    let mut pex_dropped_cands: Vec<PexCandidate> = Vec::new();
    // Requester fetch session (created once the peer's ext handshake
    // carries metadata_size).
    let mut fetch_session: Option<MetadataFetchSession> = None;
    // metadata_size out-of-domain / mismatch failure: the fetch face is
    // disabled (Failed already returned to the caller).
    let mut fetch_spec = fetch_spec;
    // Metadata-path abort flag (set by handle_inbound → clean exit).
    let mut metadata_abort = false;
    // Pooled serve bookkeeping: completions are sent back in request
    // order (the inbound arm pushes, the completion arm sends in
    // ascending seq order). With `read_pool` = None (no pool) this
    // stays idle at zero cost.
    let (mut serving_queue, mut serving_rx) = ServeQueue::new();
    let serve_out_tx = serving_queue.out_tx();

    let end = loop {
        tokio::select! {
            biased;
            _ = token.cancelled() => break PeerEnd::Cancelled,
            cmd = cmd_rx.recv() => {
                // ======== command drain window (request coalescing) ========
                // The first command enters the window immediately;
                // `now_or_never()` then drains subsequent
                // immediately-ready commands (the same shape as the
                // inbound receive round: Pending ends the window without
                // waiting for new data — on Pending the waker is
                // re-registered and later select polls wake normally).
                // Window upper bound = command channel capacity (64): at
                // most that many commands can be in flight, and the
                // engine dispatch round's supply cap is itself bounded
                // by channel slack (taiji-core `dispatch::supply_cap`),
                // so draining cannot starve the other select arms. With
                // `BH_REQUEST_COALESCE=0` (or a test-injected off) no
                // draining happens — the window is always one command
                // and the end-of-batch flush becomes per-command
                // writes, preserving the existing syscall cadence
                // bit-for-bit.
                //
                // Motivation: an engine dispatch round pushes a burst of
                // RequestPiece commands; per-command `writer.send` means
                // one small 17-byte TCP segment per request — losing one
                // segment loses one request and the pipeline idles
                // through TCP retransmission (200ms RTO to start).
                // Batched, one segment carries the whole batch and a
                // loss only affects one batch. Upstream anchor:
                // [`OutboundWriter::send_batch`] (libtorrent cork +
                // chained_buffer write path;
                // docs/design/peer-protocol.md).
                let mut window: Vec<PeerCommand> = Vec::new();
                let mut closed = false;
                match cmd {
                    None => break PeerEnd::Clean,
                    Some(command) => window.push(command),
                }
                if request_coalesce {
                    while window.len() < COMMAND_CHANNEL_CAPACITY {
                        match cmd_rx.recv().now_or_never() {
                            Some(Some(command)) => window.push(command),
                            Some(None) => {
                                // Channel empty and all senders gone:
                                // finish after this window (equivalent
                                // to the previous behavior — recv
                                // returning None only happens when the
                                // queue is empty, so no command is
                                // lost).
                                closed = true;
                                break;
                            }
                            None => break,
                        }
                    }
                }
                // Batch buffer: wire Request frames from RequestPiece
                // commands in the window accumulate and are written once
                // at the end; every other command flushes the batch
                // first, preserving wire message order = command order —
                // when Cancel/Have follow a Request batch, the peer must
                // see the requests first. Replies are sent after the
                // flush (the "reply success ⇒ bytes are out" invariant,
                // see [`flush_coalesced`]).
                let mut batch: Vec<Message> = Vec::new();
                let mut batch_replies: Vec<oneshot::Sender<Result<(), DispatchError>>> =
                    Vec::new();
                let mut stop: Option<PeerEnd> = None;
                for command in window {
                    match command {
                        PeerCommand::RequestPiece { id, begin, length, reply } => {
                            // Dispatch bookkeeping stays synchronous
                            // (same point, same order as before:
                            // window-full / duplicate / bad-id verdicts
                            // unchanged — the Nth dispatch sees the
                            // bookkeeping of the first N-1); the wire
                            // frame goes to the batch buffer, the reply
                            // waits for the flush.
                            match book.dispatch(id, begin, length, Instant::now()) {
                                Err(e) => {
                                    // A dropped receiver = fire-and-
                                    // forget; ignore the send failure.
                                    let _ = reply.send(Err(e));
                                }
                                Ok(()) => match addressing.to_wire(id) {
                                    Some(index) => {
                                        batch.push(Message::Request { index, begin, length });
                                        batch_replies.push(reply);
                                    }
                                    None => {
                                        let _ = reply.send(Err(DispatchError::BadPieceId));
                                    }
                                },
                            }
                        }
                        PeerCommand::Shutdown => {
                            // Shutdown inside the drain window: later
                            // commands are not processed (same as
                            // before — the select loop stops and
                            // trailing commands are dropped).
                            stop = Some(PeerEnd::Clean);
                            break;
                        }
                        other => {
                            // Non-batched command: flush the batch
                            // first to preserve wire order.
                            flush_coalesced(&mut writer, &mut batch, &mut batch_replies).await;
                            match other {
                                PeerCommand::CancelPiece { id, begin, length } => {
                                    // Late-delivery grace for
                                    // re-dispatched cancels: the
                                    // cancelled slot is registered for
                                    // grace — in the race between Cancel
                                    // and an in-flight piece frame, the
                                    // late delivery is accepted as
                                    // redundant (libtorrent
                                    // peer_connection.cpp keeps late
                                    // pieces; a re-dispatch must not
                                    // kill a slow peer as unsolicited).
                                    if book.cancel_with_grace(id, begin, length, Instant::now())
                                        && let Some(index) = addressing.to_wire(id)
                                    {
                                        let _ = writer.send(Message::Cancel { index, begin, length }).await;
                                    }
                                }
                                PeerCommand::SendHave { index } => {
                                    let _ = writer.send(Message::Have { index }).await;
                                }
                                PeerCommand::SendBitfield { packed } => {
                                    let _ = writer
                                        .send(Message::Bitfield {
                                            bits: Bytes::from(packed),
                                        })
                                        .await;
                                }
                                PeerCommand::SendInterest => {
                                    let _ = writer.send(Message::Interested).await;
                                }
                                PeerCommand::SendPort { dht_port } => {
                                    // BEP-5 PORT (id=9): payload = a 2-byte
                                    // big-endian port (peer_wire encoding).
                                    let _ = writer.send(Message::Port { port: dht_port }).await;
                                }
                                PeerCommand::SendUnchoke => {
                                    am_choking = false;
                                    let _ = writer.send(Message::Unchoke).await;
                                }
                                PeerCommand::SendChoke => {
                                    if !am_choking {
                                        am_choking = true;
                                        choke_sent_at = Some(Instant::now());
                                        let _ = writer.send(Message::Choke).await;
                                        // BEP-6: "If a peer sends a
                                        // choke, it MUST reject all requests
                                        // from the peer to whom the choke was
                                        // sent except it SHOULD NOT reject
                                        // requests for pieces that are in the
                                        // allowed fast set". We never send
                                        // AllowedFast outbound (the only
                                        // outbound BEP-6 message is Reject),
                                        // so the exemption set is always
                                        // empty and every in-flight slot can
                                        // be pruned. Frame order follows
                                        // "A peer SHOULD choke first and then
                                        // reject requests" (the Choke frame
                                        // was already sent, so the peer
                                        // cannot re-request before seeing the
                                        // Rejects).
                                        // Only pooled slots whose read has
                                        // not started are pruned
                                        // (ServeQueue::take_unstarted — the
                                        // dispatcher marks a slot started
                                        // when it takes the job); slots
                                        // already reading honor "requests
                                        // that are being processed are
                                        // allowed to complete" and are
                                        // delivered by the completion arm as
                                        // usual. Per-slot Rejects go through
                                        // the send_reject negotiation gate:
                                        // silently dropped for peers without
                                        // fast (BEP-3 fallback — the peer's
                                        // request timeout converges), and the
                                        // slot is pruned either way (no
                                        // serving after choke). Note:
                                        // libtorrent's upload side also
                                        // rejects slot by slot on choke;
                                        // its clear_request_queue is the
                                        // download-side path (clearing our
                                        // own unsent requests when we
                                        // receive a choke) and is not the
                                        // basis for this arm.
                                        for (index, begin, length) in
                                            serving_queue.take_unstarted()
                                        {
                                            let _ = writer
                                                .send_reject(index, begin, length)
                                                .await;
                                        }
                                    }
                                }
                                PeerCommand::AttachSource(src) => {
                                    source = Some(src);
                                }
                                PeerCommand::AttachHashSource(h) => {
                                    hash_source = Some(h);
                                }
                                PeerCommand::SetListenPort(port) => {
                                    // BEP10 advertises the current mapped listener,
                                    // preserving all negotiated extensions.
                                    if my_listen_port != port {
                                        my_listen_port = port;
                                        let handshake = ExtHandshake {
                                            m_ut_metadata: Some(OUTBOUND_UT_METADATA_ID),
                                            m_ut_pex: pex_ext.as_ref().map(|_| OUTBOUND_UT_PEX_ID),
                                            m_ut_holepunch: hp_ext
                                                .as_ref()
                                                .map(|_| crate::holepunch::OUTBOUND_UT_HOLEPUNCH_ID),
                                            metadata_size: metadata_serve
                                                .as_ref()
                                                .map(|m| m.metadata().len() as u32),
                                            upload_only: my_upload_only && super_seed.is_none(),
                                            p: (my_listen_port != 0).then_some(my_listen_port),
                                            // Same identity as the initial
                                            // send (v = PEER_AGENT, see
                                            // my_ext).
                                            v: Some(crate::tracker::PEER_AGENT.to_string()),
                                            ..ExtHandshake::default()
                                        };
                                        if let Ok(payload) = handshake.encode() {
                                            let _ = writer.send(Message::Extended { ext_id: 0, payload }).await;
                                        }
                                    }
                                }
                                PeerCommand::SetUploadOnly(flag) => {
                                    // BEP-21 state transition: update the
                                    // flag and resend the ext handshake
                                    // (super-seeding suppression matches
                                    // the initial send — see the my_ext
                                    // construction).
                                    if my_upload_only != flag {
                                        my_upload_only = flag;
                                        let handshake = ExtHandshake {
                                            m_ut_metadata: Some(OUTBOUND_UT_METADATA_ID),
                                            m_ut_pex: pex_ext.as_ref().map(|_| OUTBOUND_UT_PEX_ID),
                                            m_ut_holepunch: hp_ext
                                                .as_ref()
                                                .map(|_| crate::holepunch::OUTBOUND_UT_HOLEPUNCH_ID),
                                            metadata_size: metadata_serve
                                                .as_ref()
                                                .map(|m| m.metadata().len() as u32),
                                            upload_only: my_upload_only && super_seed.is_none(),
                                            p: (my_listen_port != 0).then_some(my_listen_port),
                                            // Same identity as the initial
                                            // send (v = PEER_AGENT, see
                                            // my_ext).
                                            v: Some(crate::tracker::PEER_AGENT.to_string()),
                                            ..ExtHandshake::default()
                                        };
                                        if let Ok(payload) = handshake.encode() {
                                            let _ = writer.send(Message::Extended { ext_id: 0, payload }).await;
                                        }
                                    }
                                }
                                PeerCommand::SetPexCandidates { fresh, dropped } => {
                                    // Overwriting snapshot (the engine
                                    // already prunes by the 60s window);
                                    // admission filtering (incoming /
                                    // freshness / capacity / the peer's
                                    // own IP exclusion) happens in
                                    // maybe_build.
                                    pex_fresh_cands = fresh;
                                    pex_dropped_cands = dropped;
                                }
                                PeerCommand::SetSuperSeed(book) => {
                                    // BEP-16 super-seeding: attach the
                                    // serving gate in seeding state (see
                                    // the command definition; the download
                                    // state is not gated — tit-for-tat is
                                    // not bound by piece assignment).
                                    super_seed = Some(book);
                                }
                                PeerCommand::SendHolepunch(msg) => {
                                    // Send only when the peer advertised
                                    // ut_holepunch (BEP-10 — keyed by its
                                    // advertised id; no advertisement =
                                    // unsupported, not an error, drop).
                                    match peer_ut_holepunch_id {
                                        Some(id) => {
                                            let payload = Bytes::from(msg.encode());
                                            debug!(target: "taiji::bt::peer", msg = ?msg,
                                                "ut_holepunch sent");
                                            let _ = writer
                                                .send(Message::Extended { ext_id: id, payload })
                                                .await;
                                        }
                                        None => {
                                            debug!(target: "taiji::bt::peer",
                                                "ut_holepunch send skipped: peer did not advertise");
                                        }
                                    }
                                }
                                PeerCommand::RequestHashes {
                                    root,
                                    base,
                                    index,
                                    length,
                                    proof,
                                    reply,
                                } => {
                                    if pending_hash.is_some() {
                                        let _ = reply.send(Err(HashRequestError::Busy));
                                    } else {
                                        // No choke check: BEP-52 "Hash requests may be sent to a
                                        // peer regardless of its choke state".
                                        let sent = writer
                                            .send(Message::HashRequest {
                                                root,
                                                base,
                                                index,
                                                length,
                                                proof,
                                            })
                                            .await;
                                        match sent {
                                            Ok(()) => {
                                                pending_hash = Some(HashRequestPending {
                                                    root,
                                                    base,
                                                    index,
                                                    length,
                                                    proof,
                                                    reply,
                                                });
                                            }
                                            Err(e) => {
                                                debug!(target: "taiji::bt::peer", %e, "hash request send failed");
                                                let _ = reply.send(Err(HashRequestError::Closed));
                                            }
                                        }
                                    }
                                }
                                // RequestPiece/Shutdown are handled by the outer arm.
                                PeerCommand::RequestPiece { .. } | PeerCommand::Shutdown => {
                                    unreachable!("handled by outer arm")
                                }
                            }
                        }
                    }
                }
                // End of window: the batched frames go out in one write
                // (the core of the batching semantics — the whole batch
                // in one TCP segment), then replies are sent uniformly.
                flush_coalesced(&mut writer, &mut batch, &mut batch_replies).await;
                if let Some(end) = stop {
                    break end;
                }
                if closed {
                    break PeerEnd::Clean;
                }
            }
            outcome = serving_rx.recv() => {
                // Pooled serve completions are sent back in request order
                // (ascending seq): out-of-order completions wait in
                // ServeQueue so the wire frame order matches the inline
                // path. Choke boundary: unstarted in-flight slots were
                // already pruned slot by slot at SendChoke
                // (ServeQueue::take_unstarted — the MUST-reject duty
                // lives in the SendChoke arm); only started slots reach
                // this arm and are delivered as usual — BEP-6 "requests
                // that are being processed are allowed to complete"; no
                // choke re-check here.
                // BEP-52 "immediately follows": last_piece_served is set
                // at the same point as the inline path (before the piece
                // is actually sent, same order as serve_and_reply), so
                // the mandatory-reply decision is identical; the pooled
                // regression tests mirror the inline decision table.
                if let Some(o) = outcome {
                    serving_queue.note_result(o.seq, o.result);
                    for (index, begin, length, uploaded, result) in serving_queue.drain_ready() {
                        match result {
                            Ok(block) => {
                                if let Some(counter) = uploaded {
                                    counter.fetch_add(
                                        u64::from(block.len() as u32),
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                                }
                                // BEP-52: a base=0 hash request immediately
                                // following this piece request must not be
                                // rejected (mandatory) — set before the
                                // piece is actually sent, same point and
                                // order as the inline path
                                // (serve_and_reply).
                                last_piece_served = true;
                                let _ = writer
                                    .send(Message::Piece {
                                        index,
                                        begin,
                                        block,
                                    })
                                    .await;
                            }
                            Err(reason) => {
                                debug!(target: "taiji::bt::peer", %reason, index, begin,
                                    "pooled request unservable -> reject if fast negotiated");
                                let _ = writer.send_reject(index, begin, length).await;
                            }
                        }
                    }
                }
            }
            frame = reader.next() => match frame {
                None => break PeerEnd::Closed,
                Some(Err(e)) => break wire_io_end(&e),
                Some(Ok(msg)) => {
                    // Inbound-activity timestamp for the idle-buffer
                    // shrink (one stamp per receive round is
                    // the right granularity — the shrink compares against
                    // a 5s threshold on a 5s tick).
                    last_inbound_at = Instant::now();
                    // Receive round (aria2 `DefaultBtInteractive.cc`
                    // receiveMessages): one round drains the currently
                    // readable window batchwise — snapshot outstanding,
                    // process frames until the read side is Pending (the
                    // socket is drained), then settle the window doubling
                    // by the retirement rate.
                    book.begin_receive_round();
                    let mut round_exit: Option<PeerEnd> = None;
                    let mut current = Some(msg);
                    while let Some(msg) = current.take() {
                        let ctx = InboundCtx {
                            book: &mut book,
                            flood: &mut flood,
                            addressing: &addressing,
                            piece_bytes: &piece_bytes,
                            allowed_fast: &mut allowed_fast,
                            data_tx: &data_tx,
                            block_sink: direct_block_sink.as_ref(),
                            source: source.as_ref(),
                            hash_source: hash_source.as_ref(),
                            writer: &mut writer,
                            avail_tx: avail_tx.as_ref(),
                            port_tx: port_tx.as_ref(),
                            cuid,
                            interested: &interested,
                            peer_choking: &peer_choking,
                            snubbed: &snubbed,
                            am_choking: &mut am_choking,
                            choke_sent_at: &choke_sent_at,
                            choke_grace,
                            suggested: &mut suggested,
                            hash_window_start: &mut hash_window_start,
                            hash_window_count: &mut hash_window_count,
                            last_piece_served: &mut last_piece_served,
                            pending_hash: &mut pending_hash,
                            peer_ut_metadata_id: &mut peer_ut_metadata_id,
                            peer_ut_pex_id: &mut peer_ut_pex_id,
                            metadata_serve: metadata_serve.as_ref(),
                            fetch_session: &mut fetch_session,
                            fetch_spec: &mut fetch_spec,
                            metadata_abort: &mut metadata_abort,
                            uploaded: uploaded.as_ref(),
                            downloaded: downloaded.as_ref(),
                            pex_ext: pex_ext.as_ref(),
                            pex_sender: &mut pex_sender,
                            super_seed: super_seed.as_ref(),
                            holepunch: hp_ext.as_ref(),
                            peer_ut_holepunch_id: &mut peer_ut_holepunch_id,
                            peer_supports_holepunch: &supports_holepunch,
                            hp_rv_window: &mut hp_rv_window,
                            hp_rv_count: &mut hp_rv_count,
                            hp_ct_window: &mut hp_ct_window,
                            hp_ct_count: &mut hp_ct_count,
                            pex_window: &mut pex_window,
                            pex_count: &mut pex_count,
                            pex_inbound: &mut pex_inbound,
                            client_deny: client_deny.as_ref(),
                            peer_upload_only: peer_upload_only.as_ref(),
                            serve: read_pool.as_ref().map(|pool| ServeCtx {
                                pool,
                                out_tx: &serve_out_tx,
                                queue: &mut serving_queue,
                            }),
                        };
                        match handle_inbound(msg, ctx).await {
                            Ok(()) => {}
                            Err(violation) => {
                                round_exit = Some(PeerEnd::Violation(violation));
                                break;
                            }
                        }
                        if metadata_abort {
                            // The metadata fetch finished abnormally
                            // (reject / infohash mismatch — the reference
                            // aborts the connection here); Failed was
                            // already returned to the caller.
                            round_exit = Some(PeerEnd::Clean);
                            break;
                        }
                        // Consume only immediately-ready frames: None =
                        // Pending = the round is over, no waiting for new
                        // data (now_or_never cannot swallow frames — on
                        // Pending the waker is re-registered and later
                        // selects wake normally).
                        match reader.next().now_or_never() {
                            Some(Some(Ok(next))) => current = Some(next),
                            Some(Some(Err(e))) => {
                                round_exit = Some(wire_io_end(&e));
                                break;
                            }
                            Some(None) => {
                                round_exit = Some(PeerEnd::Closed);
                                break;
                            }
                            None => {}
                        }
                    }
                    if let Some(end) = round_exit {
                        break end;
                    }
                    // Round over: the retirement rate drives window
                    // doubling, capped at 256 (aria2
                    // `DefaultBtInteractive.cc`; slots retired by
                    // choke/timeout also count toward this round's
                    // retirement).
                    book.end_receive_round();
                }
            },
            _ = metadata_tick.tick(), if fetch_session.as_ref().is_some_and(MetadataFetchSession::is_shared) => {
                if let Some(session) = fetch_session.as_mut() {
                    if let Err(e) = session.issue(&mut writer, Instant::now()).await { break wire_io_end(&e); }
                }
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let expired = book.expire_timed_out(now);
                if !expired.is_empty() {
                    // Snub event: the leecher choking round excludes this
                    // peer (aria2 BtLeecherStateChoke executeChoke).
                    snubbed.store(true, std::sync::atomic::Ordering::Relaxed);
                    debug!(target: "taiji::bt::peer", count = expired.len(),
                        "request slots timed out -> snub");
                }
                // The disconnect log carries the triggering dimensions
                // (flip / keepalive counts and their thresholds; see
                // FloodGuard::check).
                let flood_dims = flood.trigger_counts();
                if flood.check(now) {
                    warn!(target: "taiji::bt::peer",
                        choke_unchoke_flips = flood_dims.0,
                        flip_threshold = crate::request_book::FLOODING_CHOKE_FLIP_THRESHOLD,
                        keepalives = flood_dims.1,
                        keepalive_threshold = crate::request_book::FLOODING_THRESHOLD,
                        "message flooding detected, disconnecting");
                    break PeerEnd::Flooded;
                }
                have.remove_expired(now);
                // ut_metadata timeout sweep (20s,
                // UTMetadataRequestTracker; swept indices leave
                // in-flight and are re-requested on the next issue).
                if let Some(session) = fetch_session.as_mut() {
                    session.sweep(now);
                    if let Err(e) = session.issue(&mut writer, now).await {
                        debug!(target: "taiji::bt::peer", %e, "ut_metadata reissue write failed");
                        break wire_io_end(&e);
                    }
                }
                // ut_pex outbound: at due time PexSwarmSender filters and
                // builds (`DefaultBtInteractive::addPeerExchangeMessage`
                // face: gate / throttle / candidate admission / capacity /
                // empty-frame skip all live in maybe_build — an empty dict
                // frame is never produced, per BEP-11 "Messages must
                // contain at least one of the following fields: added,
                // added6, dropped, dropped6.").
                if let Some((id, msg)) = pex_sender.maybe_build(
                    &pex_fresh_cands,
                    &pex_dropped_cands,
                    remote_ip,
                    now,
                ) {
                    match msg.encode() {
                            Ok(payload) => {
                                debug!(target: "taiji::bt::peer",
                                    added = msg.fresh_peers().len(),
                                    dropped = msg.dropped_peers().len(),
                                    "ut_pex sent");
                                let _ = writer
                                    .send(Message::Extended {
                                        ext_id: id,
                                        payload: Bytes::from(payload),
                                    })
                                    .await;
                            }
                            Err(e) => {
                                debug!(target: "taiji::bt::peer", %e, "ut_pex encode failed")
                            }
                        }
                    }
                // Idle Framed-buffer shrink: past the inbound
                // idle threshold, swap both Framed buffers (read high-water
                // from received piece bursts, write high-water from served
                // pieces) down to zero capacity — but only when fully
                // drained (a partial frame is never discarded, see
                // [`shrink_drained_framed_buf`]). Wire-visible behavior is
                // untouched: the codec's one-shot exact reservation regrows
                // each buffer to the next frame's full length on the
                // resumed read/write, and the keepalive path below is the
                // only outbound this idle connection still makes (17B —
                // regrown capacity stays at the floor).
                if read_buf_shrink
                    && now.duration_since(last_inbound_at) >= READ_BUF_IDLE_SHRINK
                {
                    let freed_read = shrink_drained_framed_buf(reader.read_buffer_mut());
                    let freed_write = writer.shrink_idle_write_buffer();
                    if freed_read + freed_write > 0 {
                        debug!(target: "taiji::bt::peer",
                            idle_secs = now.duration_since(last_inbound_at).as_secs(),
                            freed_read_b = freed_read,
                            freed_write_b = freed_write,
                            "idle framed buffers shrunk");
                    }
                }
                // Idle-gated keepalive outbound (the BEP-3 zero-length
                // frame): sent only after outbound silence >=
                // keepalive_interval (active connections emit zero
                // redundant frames — mirrors libtorrent
                // `peer_connection.cpp` keep_alive's `m_last_sent` gate),
                // and `send` resets the timer. Placed at the end of the
                // tick arm: real ut_metadata/ut_pex outbound in the same
                // tick refreshes the timer first, so this arm does not
                // fire. The check period stays flooding_interval (the
                // existing cadence), so an actual send lags the threshold
                // by at most one check interval. Our own keepalives do
                // not count toward the flood guard (FloodGuard observes
                // inbound only, see the inbound.rs KeepAlive arm).
                if writer.idle_for(now) >= keepalive_interval {
                    debug!(target: "taiji::bt::peer",
                        idle_secs = writer.idle_for(now).as_secs(),
                        "keepalive sent");
                    let _ = writer.send(Message::KeepAlive).await;
                }
            }
        }
    };
    // Terminal state returns immediately: unprocessed commands are
    // dropped with cmd_rx and the caller learns via
    // PeerCommandRejected::Closed. (A 500ms drain was removed: waiting
    // for all senders to close would stretch every connection teardown
    // to the full budget for no real benefit — TorrentTask holds its
    // handles long-term.)
    debug!(target: "taiji::bt::peer", end = ?end, "peer task exited");
    end
}

/// Wire-layer error → `PeerEnd::Io` projection: kind passes through from
/// [`PeerWireError::Io`]; other variants have no IO semantics and map to
/// `Other` — upstream redial/backoff classifies by kind
/// (ConnectionReset/TimedOut/ConnectionRefused) and must never depend on
/// error text. The message keeps the wire error Display, matching the
/// existing end-state log text.
fn wire_io_end(err: &PeerWireError) -> PeerEnd {
    let kind = match err {
        PeerWireError::Io { kind, .. } => *kind,
        _ => std::io::ErrorKind::Other,
    };
    PeerEnd::Io {
        kind,
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mechanism: a fully-drained buffer is swapped down to zero
    /// capacity and the freed capacity is reported; the swap is a no-op
    /// when capacity is already zero (no per-tick churn).
    #[test]
    fn shrink_swaps_only_drained_buffer_with_capacity() {
        // Drained buffer holding a grown capacity (the post-piece-burst
        // shape): simulate by reserving, filling and consuming.
        let mut buf = bytes::BytesMut::new();
        buf.reserve(16 * 1024);
        buf.extend_from_slice(&[0u8; 32]);
        let cap = buf.capacity();
        assert!(cap >= 16 * 1024, "fixture must hold a grown capacity");
        buf.clear();
        let freed = shrink_drained_framed_buf(&mut buf);
        assert_eq!(freed, cap, "freed = the whole high-water capacity");
        assert_eq!(buf.capacity(), 0, "idle buffer below the 1KiB bar");
        // Already at zero: repeated ticks are no-ops.
        assert_eq!(shrink_drained_framed_buf(&mut buf), 0);
    }

    /// Safety: a buffer holding unparsed bytes (a partially
    /// received frame) is never touched — the partial frame must survive
    /// an idle-window tick verbatim.
    #[test]
    fn shrink_never_touches_partial_frame() {
        let mut buf = bytes::BytesMut::new();
        buf.extend_from_slice(&[0, 0, 0, 5, 0x04]); // Have prefix, index missing
        let (len_before, cap_before) = (buf.len(), buf.capacity());
        assert_eq!(shrink_drained_framed_buf(&mut buf), 0);
        assert_eq!(buf.len(), len_before, "partial-frame bytes preserved");
        assert_eq!(buf.capacity(), cap_before, "capacity preserved");
    }
}

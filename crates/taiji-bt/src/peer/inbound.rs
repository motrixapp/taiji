//! Inbound message handling: [`handle_inbound`] dispatches frame by
//! frame (piece / request / choke / hashes / PORT / Extended etc.) with
//! the shared [`InboundCtx`]; [`serve_request`] reads a block from a
//! [`PieceSource`] to serve an inbound request (BEP-47 zero-padding and
//! short-read semantics). The hash request rate-limit constants are
//! defined here.
//!
//! Upstream anchor mapping: docs/design/peer-protocol.md

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::debug;

use super::command::HashFetch;
use super::conn::{HashRequestPending, OutboundWriter};
use super::ext::{
    ExtendedCtx, MetadataFetchSession, MetadataFetchSpec, MetadataSource, handle_extended,
};
use super::read_pool::{ReadPool, ServeOutcome, ServeQueue};
use super::{
    AvailEvent, BlockSink, HashSource, HolepunchExt, PeerError, PexExt, PieceData, PieceSource,
};
use crate::peer_wire::Message;
use crate::pex::PexSwarmSender;
use crate::piece_id::Addressing;
use crate::request_book::{FloodGuard, PieceError, RequestBook};
/// Hash request rate limit (a local resource bound — BEP-52 sets no
/// numbers and only permits independent rate limiting; the choke state
/// does not affect this limit since BEP-52 allows hash requests
/// regardless of choke).
pub const HASH_REQUEST_WINDOW: Duration = Duration::from_secs(60);
pub const HASH_REQUEST_LIMIT: u32 = 40;
/// Inbound allowed-fast set capacity cap (a local resource bound; BEP-6
/// sets no number): at the cap the set is cleared and rebuilt — same
/// shape and value as the Suggest arm's 1024 cap in this file. A
/// legitimate peer's set is bounded by the piece count; without a cap a
/// malicious peer can feed distinct u32 indices frame by frame and grow
/// the HashSet without bound (memory amplification plus a wider
/// unsolicited-acceptance surface).
pub const ALLOWED_FAST_SET_CAP: usize = 1024;

/// Pooled serving wiring (built by peer_loop, passed per message inside
/// [`InboundCtx`]): the read pool + this connection's completion
/// channel + in-order re-injection bookkeeping.
pub(super) struct ServeCtx<'a> {
    pub(super) pool: &'a ReadPool,
    pub(super) out_tx: &'a mpsc::Sender<ServeOutcome>,
    pub(super) queue: &'a mut ServeQueue,
}

/// Request length validation shared by the inline and pooled serving
/// paths (reject semantics: length 0 or > 16KiB).
fn validate_request_length(length: u32) -> Result<(), String> {
    if length == 0 || length as usize > crate::peer_wire::MAX_FRAME_LEN {
        Err(format!("bad request length {length}"))
    } else {
        Ok(())
    }
}

/// Block coordinate validation for the unsolicited acceptance arm
/// (pushes inside the allowed-fast/suggest sets): the same wire request
/// geometry as slot matching —
///
/// - `begin` is a multiple of 16KiB;
/// - `length ∈ (0, 16KiB]` (wire decoding tolerates empty/oversized
/// frame bodies; this closes it at request granularity);
/// - when the `piece_bytes` table is non-empty: index in bounds and
/// `begin + length <= the piece's expected bytes` (table length = piece
/// count, entries = expected bytes after last-piece truncation; the
/// wire index equals the flat piece order for v1 and v2). An empty
/// table = unknown piece geometry (degenerate; geometry checks only).
///
/// The slot-matching path needs no check: its begin/length equal our
/// dispatched slot exactly, guaranteed by the dispatch face (the engine
/// dispatch slices by the same `piece_bytes` table). Mismatch →
/// [`PeerError::BadBlockCoords`] disconnect (Violation semantics) — set
/// membership (AllowedFast/Suggest frames) is peer-controlled and does
/// not make coordinates legal; letting them through would feed
/// misaligned / out-of-bounds blocks into the store and poison its
/// accounting.
fn validate_block_coords(
    index: u32,
    begin: u32,
    length: u32,
    piece_bytes: &[u64],
) -> Result<(), PeerError> {
    const BLOCK: u32 = 16 * 1024;
    let in_piece_bound = piece_bytes.is_empty()
        || piece_bytes
            .get(index as usize)
            .is_some_and(|&bytes| u64::from(begin) + u64::from(length) <= bytes);
    if length == 0 || length > BLOCK || !begin.is_multiple_of(BLOCK) || !in_piece_bound {
        return Err(PeerError::BadBlockCoords {
            index,
            begin,
            length,
        });
    }
    Ok(())
}

/// Serve one inbound request: addressing / zero-padding is the
/// [`PieceSource`]'s job (BEP-47); a short read (out of range /
/// unallocated) → Err → reject.
async fn serve_request(
    source: Option<&std::sync::Arc<dyn PieceSource>>,
    index: u32,
    begin: u32,
    length: u32,
) -> Result<Bytes, String> {
    let Some(src) = source else {
        return Err("no data source (download-only peer)".into());
    };
    validate_request_length(length)?;
    let mut buf = vec![0u8; length as usize];
    let n = src.read_block(index, begin, &mut buf)?;
    if n < buf.len() {
        return Err(format!(
            "short read {n}/{length} (unallocated or out of range)"
        ));
    }
    Ok(Bytes::from(buf))
}

/// Inline serving path (the only path for pool-less callers, and the
/// pooled path's fallback): [`serve_request`] reads and replies with
/// piece / reject (an obligation of BEP-3 fast-extension advertisers).
async fn serve_and_reply<S>(
    source: Option<&std::sync::Arc<dyn PieceSource>>,
    index: u32,
    begin: u32,
    length: u32,
    writer: &mut OutboundWriter<tokio::io::WriteHalf<S>>,
    last_piece_served: &mut bool,
    uploaded: Option<&std::sync::Arc<std::sync::atomic::AtomicU64>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match serve_request(source, index, begin, length).await {
        Ok(block) => {
            // BEP-52: a base=0 hash request immediately following this
            // piece request must not be rejected (mandatory) — record
            // state for the HashRequest arm.
            *last_piece_served = true;
            // Session upload counter: piece sends accumulate by payload
            // (aria2 BtPieceMessage.cc PieceSendUpdate).
            if let Some(counter) = uploaded {
                counter.fetch_add(
                    u64::from(block.len() as u32),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
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
                "request unservable -> reject if fast negotiated");
            // Silently dropped for peers without fast (BEP-3 fallback —
            // gate and spec basis in [`OutboundWriter::send_reject`]).
            let _ = writer.send_reject(index, begin, length).await;
        }
    }
}

/// Shared context for inbound handling (avoids a long parameter list).
pub(super) struct InboundCtx<'a, S: AsyncRead + AsyncWrite + Unpin> {
    pub(super) book: &'a mut RequestBook,
    pub(super) flood: &'a mut FloodGuard,
    pub(super) addressing: &'a Addressing,
    /// Per-piece expected byte counts (the upper-bound criterion for
    /// the unsolicited acceptance arm; see
    /// [`super::PeerConfig::piece_bytes`]).
    pub(super) piece_bytes: &'a [u64],
    /// Wire indices the peer allowed us to request while choked
    /// (written by inbound AllowedFast frames).
    pub(super) allowed_fast: &'a mut HashSet<u32>,
    pub(super) data_tx: &'a mpsc::Sender<PieceData>,
    /// Direct block delivery seam: `Some` = deliver `Message::Piece`
    /// straight to the face-level channel within this task, skipping
    /// the attach forwarding task; `None` = the legacy `data_tx` path.
    /// Both present = dual paths; the default None changes no behavior.
    pub(super) block_sink: Option<&'a Arc<dyn BlockSink>>,
    pub(super) source: Option<&'a std::sync::Arc<dyn PieceSource>>,
    pub(super) hash_source: Option<&'a std::sync::Arc<dyn HashSource>>,
    pub(super) writer: &'a mut OutboundWriter<tokio::io::WriteHalf<S>>,
    /// Peer interest flag (read by the choking layer; written by
    /// Interested/NotInterested).
    pub(super) interested: &'a std::sync::atomic::AtomicBool,
    /// Peer choke mirror (written by Choke/Unchoke frames).
    pub(super) peer_choking: &'a std::sync::atomic::AtomicBool,
    /// Snub mirror (cleared by a slot-matching piece).
    pub(super) snubbed: &'a std::sync::atomic::AtomicBool,
    /// Our choke state: true → inbound request → reject.
    pub(super) am_choking: &'a mut bool,
    /// When we last actually sent a Choke frame (reject-pump guard
    /// grace timer; None = never sent Choke — while initially choked,
    /// only reject, no disconnect).
    pub(super) choke_sent_at: &'a Option<Instant>,
    /// Grace duration (PeerConfig::choke_grace; default
    /// CHOKE_REQUEST_GRACE).
    pub(super) choke_grace: Duration,
    /// Pieces suggested by the peer (push acceptance decision).
    pub(super) suggested: &'a mut std::collections::HashSet<u32>,
    pub(super) hash_window_start: &'a mut Instant,
    pub(super) hash_window_count: &'a mut u32,
    pub(super) last_piece_served: &'a mut bool,
    /// The requester's pending hash request (matched by inbound
    /// hashes/reject).
    pub(super) pending_hash: &'a mut Option<HashRequestPending>,
    /// BEP-10 face: the peer's inbound ut_metadata id.
    pub(super) peer_ut_metadata_id: &'a mut Option<u8>,
    /// BEP-10 face: the peer's inbound ut_pex id (our outbound keys off
    /// it; BEP-10 — the m dict value is the id other peers should use
    /// when sending to the advertiser).
    pub(super) peer_ut_pex_id: &'a mut Option<u8>,
    /// Metadata serving source (passed through from ExtConfig; None =
    /// every request is rejected).
    pub(super) metadata_serve: Option<&'a Arc<dyn MetadataSource>>,
    /// Requester fetch session (created after the peer's ext
    /// handshake).
    pub(super) fetch_session: &'a mut Option<MetadataFetchSession>,
    /// The not-yet-consumed fetch spec (consumed by the peer's first
    /// ext handshake).
    pub(super) fetch_spec: &'a mut Option<MetadataFetchSpec>,
    /// Metadata-path connection abort flag (reject / infohash mismatch
    /// — the aria2 equivalent aborts; semantically "fetch finished",
    /// not a protocol violation: peer_loop exits Clean after checking).
    pub(super) metadata_abort: &'a mut bool,
    /// Availability event reporting (HAVE/bitfield → engine; None = the
    /// upper layer does not care).
    pub(super) avail_tx: Option<&'a mpsc::Sender<AvailEvent>>,
    /// Inbound PORT forwarding (BEP-5; None = DHT off, dropped).
    pub(super) port_tx: Option<&'a mpsc::Sender<(u64, u16)>>,
    /// This connection's cuid (echoed on events).
    pub(super) cuid: u64,
    /// Session upload counter (accumulated after a piece is served;
    /// None = not counted).
    pub(super) uploaded: Option<&'a std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// Session download counter (accumulated at piece frame receipt;
    /// None = not counted).
    pub(super) downloaded: Option<&'a std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// ut_pex advertise/consume wiring (None = disabled — not consumed).
    pub(super) pex_ext: Option<&'a PexExt>,
    /// Outbound cadence state machine (rebuilt when the ext handshake
    /// arrives, keyed by the peer's advertised id).
    pub(super) pex_sender: &'a mut PexSwarmSender,
    /// BEP-16 super-seeding bookkeeping (None = not super-seeding;
    /// request serving is not bound by piece assignment). Passed
    /// through in the same slot as PeerConfig::super_seed.
    pub(super) super_seed: Option<&'a std::sync::Arc<crate::superseed::SuperSeedBook>>,
    /// ut_holepunch advertise/consume wiring (None = disabled — not
    /// consumed).
    pub(super) holepunch: Option<&'a HolepunchExt>,
    /// The peer's inbound ut_holepunch id (from its m dict; our
    /// outbound keys off it).
    pub(super) peer_ut_holepunch_id: &'a mut Option<u8>,
    /// Peer negotiation mirror (the handle's lock-free read face; set
    /// by the handshake branch).
    pub(super) peer_supports_holepunch: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// ut_holepunch fixed-window rate-limit state (separate windows:
    /// rendezvous / connect).
    pub(super) hp_rv_window: &'a mut Instant,
    pub(super) hp_rv_count: &'a mut u32,
    pub(super) hp_ct_window: &'a mut Instant,
    pub(super) hp_ct_count: &'a mut u32,
    /// Inbound ut_pex fixed-window rate-limit state (see the ext module
    /// constants).
    pub(super) pex_window: &'a mut Instant,
    pub(super) pex_count: &'a mut u32,
    /// Tiered inbound ut_pex decode session (the first frame of a
    /// connection is exempt, truncated at [`crate::pex::FIRST_PEX_MAX`];
    /// later frames are rejected whole above the 50 cap).
    pub(super) pex_inbound: &'a mut crate::pex::PexInboundSession,
    /// Client identity re-check callback (None = no re-check).
    pub(super) client_deny: Option<&'a super::ClientDenyCheck>,
    /// Inbound BEP-21 upload_only mirror (None = not recorded — see
    /// [`super::PeerConfig::peer_upload_only`]).
    pub(super) peer_upload_only: Option<&'a std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Pooled serving wiring (None = the inline form — pool-less
    /// callers keep the exact same behavior). When Some, an inbound
    /// request's disk read goes into the pool and the completion is
    /// sent back in request order by peer_loop.
    pub(super) serve: Option<ServeCtx<'a>>,
}

/// Inbound message handling; `Err` = protocol violation (the caller
/// disconnects).
pub(super) async fn handle_inbound<S>(msg: Message, ctx: InboundCtx<'_, S>) -> Result<(), PeerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let InboundCtx {
        book,
        flood,
        addressing,
        piece_bytes,
        allowed_fast,
        data_tx,
        block_sink,
        source,
        hash_source,
        writer,
        interested,
        peer_choking,
        snubbed,
        am_choking,
        choke_sent_at,
        choke_grace,
        suggested,
        hash_window_start,
        hash_window_count,
        last_piece_served,
        pending_hash,
        peer_ut_metadata_id,
        peer_ut_pex_id,
        metadata_serve,
        fetch_session,
        fetch_spec,
        metadata_abort,
        avail_tx,
        port_tx,
        cuid,
        uploaded,
        downloaded,
        pex_ext,
        pex_sender,
        super_seed,
        holepunch,
        peer_ut_holepunch_id,
        peer_supports_holepunch,
        hp_rv_window,
        hp_rv_count,
        hp_ct_window,
        hp_ct_count,
        pex_window,
        pex_count,
        pex_inbound,
        client_deny,
        peer_upload_only,
        serve,
    } = ctx;
    // BEP-52 "immediately follows": any inbound message clears the
    // flag; the piece-serving arm sets it and the hash request arm
    // consumes this snapshot to decide the mandatory reply.
    let follows_piece = *last_piece_served;
    *last_piece_served = false;
    match msg {
        Message::KeepAlive => flood.observe_keepalive(),
        Message::Choke => {
            flood.observe_choke();
            peer_choking.store(true, std::sync::atomic::Ordering::Relaxed);
            // A choke does NOT clear dispatched in-flight slots.
            // libtorrent clears only the not-yet-sent m_request_queue on
            // choke and keeps already-sent m_download_queue entries
            // (peer_connection.cpp + clear_request_queue, which touches
            // only m_request_queue) — requests the peer accepted before
            // choking still arrive, and clearing the slots would
            // misjudge those legitimate deliveries as unsolicited.
            // aria2's doChokedAction clears all non-allowed-fast slots
            // (BtChokeMessage.cc + DefaultBtMessageDispatcher.cc); the
            // libtorrent reading is taken as the authority. Slots
            // converge via reject (fast ext) or the timeout grace.
        }
        Message::Unchoke => {
            flood.observe_unchoke();
            // Unchoke edge reported to the engine: the dispatch face
            // sends zero requests to a choking peer (aria2 fillPiece),
            // so supply recovery after an unchoke depends on this edge —
            // no other natural event fires in the stall window. Lossy on
            // a full channel (the next choke round or re-dispatch
            // heals).
            if let Some(tx) = &avail_tx {
                let _ = tx.try_send(AvailEvent::Unchoked { peer: cuid });
            }
            peer_choking.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        Message::Piece {
            index,
            begin,
            block,
        } => {
            let id = addressing
                .from_wire(index)
                .ok_or(PeerError::BadPieceIndex { index })?;
            let length = block.len() as u32;
            // Session download counter: counted at wire receipt (aria2
            // BtPieceMessage receive-side updateDownloadLength), before
            // bookkeeping/validation.
            if let Some(counter) = downloaded {
                counter.fetch_add(u64::from(length), std::sync::atomic::Ordering::Relaxed);
            }
            // Freeze the receive time (the slot-match arm samples
            // now − dispatched in RequestBook::on_piece).
            let received_at = Instant::now();
            book.on_piece(id, begin, length, received_at)
                .or_else(|e| match e {
                    PieceError::Unsolicited { .. } => {
                        // Unsolicited = neither an in-flight request of
                        // ours (including the timeout grace, RequestBook),
                        // nor inside this connection's allowed-fast set,
                        // nor suggested by the peer. BEP-6 allowed-fast:
                        // set members may be delivered while we are
                        // choked (BEP-6 Allowed Fast section); suggest
                        // race: a delivery arriving after the suggest but
                        // before our request (libtorrent tolerates all
                        // non-requested blocks as redundant bytes,
                        // peer_connection.cpp — this implementation
                        // deliberately narrows that to the two sets).
                        // Pushes outside the sets keep the disconnect
                        // semantics.
                        let in_allowed_fast = allowed_fast.contains(&index);
                        let in_suggested = suggested.remove(&index);
                        if in_allowed_fast || in_suggested {
                            // Set membership only waives the "not
                            // requested" dimension; the coordinates still
                            // pass the same geometry check as slot
                            // matching (criterion in
                            // [`validate_block_coords`]) — mismatch =
                            // Violation disconnect, never into the store.
                            validate_block_coords(index, begin, length, piece_bytes)?;
                            debug!(target: "taiji::bt::peer", index, begin, length,
                            allowed_fast = in_allowed_fast, suggested = in_suggested,
                            "unsolicited piece within allowed-fast/suggest set: accepted");
                            Ok(())
                        } else {
                            Err(PeerError::UnsolicitedPiece {
                                index,
                                begin,
                                length,
                            })
                        }
                    }
                })?;
            // Slot match (or in-set acceptance) passes the protocol-level
            // check; pre-write block verification lives in the
            // store/HashPool.
            snubbed.store(false, std::sync::atomic::Ordering::Relaxed);
            // Dual delivery: with the direct sink present, deliver within
            // this task (removes the intermediate forwarding-task hop;
            // the common path try_deliver is allocation-free and a full
            // channel turns into awaited backpressure — see the BlockSink
            // docs). Absent → the legacy `data_tx` path unchanged.
            // Addressing conversion / out-of-range defense stays out of
            // bt: `id` already passed `from_wire` validation (out of
            // range = BadPieceIndex disconnect, above); `to_flat` stays
            // on the core side of the sink.
            if let Some(sink) = block_sink {
                if let Err(block) = sink.try_deliver(id, begin, block) {
                    sink.deliver_backpressure(id, begin, block).await;
                }
            } else {
                let _ = data_tx.send(PieceData { id, begin, block }).await;
            }
        }
        Message::Request { length, .. } if length > 16 * 1024 => {
            // A request over 16KiB must disconnect.
            return Err(PeerError::OversizeRequest { length });
        }
        Message::Request {
            index,
            begin,
            length,
        } if *am_choking => {
            // While we choke, an inbound request → reject (BEP-3
            // choking semantics: pending requests after a choke must be
            // answered with reject, and later requests on the connected
            // peer get the same; fast extension is advertised).
            //
            // Reject-pump guard (libtorrent peer_connection.cpp):
            // beyond rejecting, "allow peers to send request up to 2
            // seconds after getting choke, then disconnect them" —
            // still requesting past the grace is a protocol violation.
            // Divergence: libtorrent starts the clock per connection;
            // here the 2s grace starts only after we actually sent a
            // Choke frame — early requests while initially choked (the
            // BEP-3 state table) are only rejected, never disconnected
            // (interop leniency for optimistic pipelining, one notch
            // wider than the reference).
            if let Some(t) = *choke_sent_at
                && t.elapsed() > choke_grace
            {
                return Err(PeerError::RequestsWhileChoked {
                    index,
                    begin,
                    length,
                });
            }
            debug!(target: "taiji::bt::peer", index, begin,
                "request while am choking -> reject if fast negotiated");
            // Silently dropped for peers without fast, relying on choke
            // semantics (the peer stops requesting / its timeouts
            // converge; the grace disconnect decision ran outside the
            // gate unchanged — gate and spec basis in
            // [`OutboundWriter::send_reject`]).
            let _ = writer.send_reject(index, begin, length).await;
        }
        Message::Request {
            index,
            begin,
            length,
        } => {
            // BEP-16 super-seeding serving gate (libtorrent
            // peer_connection.cpp "piece not super-seeded" →
            // reject_request): requests for non-assigned pieces (outside
            // the two slots) are always rejected — the honest execution
            // of "send only the piece that has not spread yet". The gate
            // runs before the source read.
            if let Some(book) = super_seed
                && !book.serves(cuid, u64::from(index))
            {
                debug!(target: "taiji::bt::peer", index, begin, cuid,
                        "super-seeding: piece not assigned -> reject if fast negotiated");
                let _ = writer.send_reject(index, begin, length).await;
                // A gate reject is not an unservable violation; the
                // connection stays.
                return Ok(());
            }
            // Seeding service: prefer pooled reads (disk reads leave the
            // event loop via a spawn_blocking dispatcher); no pool (None
            // = the existing inline form) / no source / bad length /
            // queue full → inline path (semantics unchanged: no source
            // and bad length are rejected inline; a full queue degrades
            // to the existing synchronous service and no request is
            // lost); pending at cap → Reject (the memory guard, see the
            // else arm below).
            let mut inlined = true;
            if let Some(serve) = serve
                && let Some(src) = source
                && validate_request_length(length).is_ok()
            {
                if let Some(slot) = serve.queue.push(index, begin, length, uploaded.cloned()) {
                    match serve.pool.try_serve(
                        std::sync::Arc::clone(src),
                        index,
                        begin,
                        length as usize,
                        &slot,
                        serve.out_tx.clone(),
                    ) {
                        Ok(()) => inlined = false,
                        Err(()) => {
                            // Queue full: undo the registration (a broken
                            // seq chain must not wedge the re-injection
                            // order); the inline fallback is the existing
                            // synchronous serving path.
                            serve.queue.remove(slot.seq);
                        }
                    }
                } else {
                    // Pending at cap (OOM guard): in-flight serve
                    // bookkeeping >= the cap (default 256 ≈ the peer
                    // target-window upper bound — normal pipelining
                    // cannot reach it; hitting it means the peer exceeds
                    // the window or completion draining stalled) → BEP-6
                    // Reject Request (same semantics as unservable →
                    // reject; the send_reject negotiation gate silently
                    // drops for peers without fast), and skip
                    // enqueueing — a rejected push burns no seq (no
                    // chain break, no remove needed); no inline fallback
                    // (the cap itself is the backpressure signal; inline
                    // serving would bypass the cap's memory guard and
                    // re-accumulate).
                    inlined = false;
                    let _ = writer.send_reject(index, begin, length).await;
                }
            }
            if inlined {
                serve_and_reply(
                    source,
                    index,
                    begin,
                    length,
                    writer,
                    last_piece_served,
                    uploaded,
                )
                .await;
            }
        }
        Message::Reject {
            index,
            begin,
            length,
        } => {
            // The peer rejected our request: clear the slot (the peer's
            // obligation as a fast-extension advertiser; peers without
            // fast never send reject, slots are reclaimed by timeout).
            let id = addressing
                .from_wire(index)
                .ok_or(PeerError::BadPieceIndex { index })?;
            let _ = book.cancel(id, begin, length);
        }
        Message::Cancel { .. } => {
            debug!(target: "taiji::bt::peer", "cancel ignored")
        }
        Message::Have { index } => {
            if let Some(tx) = &avail_tx {
                // Lossy on a full channel: the rarity heuristic tolerates
                // loss, see the PeerConfig comment.
                let _ = tx.try_send(AvailEvent::Have { peer: cuid, index });
            }
        }
        Message::Bitfield { bits } => {
            if let Some(tx) = &avail_tx {
                let _ = tx.try_send(AvailEvent::Bitfield { peer: cuid, bits });
            }
        }
        Message::Interested | Message::NotInterested => {
            use std::sync::atomic::Ordering::Relaxed;
            let now_interested = matches!(msg, Message::Interested);
            let was = interested.swap(now_interested, Relaxed);
            if was != now_interested {
                debug!(target: "taiji::bt::peer", interested = now_interested,
                    "peer interest state changed (choking rounds read this)");
            }
            // An INTERESTED rising edge → AvailEvent::Interested (the
            // preemptive unchoke trigger; libtorrent
            // peer_connection.cpp). Low-frequency edge, not level (a
            // repeated Interested does not re-emit); lossy on full — a
            // missed edge is covered by the next choke round (degrades
            // to no preemptive unchoke, same as the round-only
            // semantics).
            if now_interested
                && !was
                && let Some(tx) = &avail_tx
            {
                let _ = tx.try_send(AvailEvent::Interested { peer: cuid });
            }
        }
        Message::Suggest { index } => {
            // BEP-6 suggest: the peer proposes prioritized downloading;
            // consumed by piece selection. Registered for the
            // unsolicited decision (the early-delivery race window for
            // suggested pieces).
            if suggested.len() >= 1024 {
                suggested.clear();
            }
            suggested.insert(index);
            debug!(target: "taiji::bt::peer", index, "peer suggested piece");
        }
        Message::HaveAll => {
            // BEP-6: have_all = a full-possession announcement ("replace
            // the Have Bitfield", BEP-6 wording). Previously only logged,
            // so the engine saw a fast-negotiating seeder as empty and
            // never dispatched to it (a main data source lost). The event
            // goes up like Have/Bitfield (lossy on full). Divergence
            // noted: BEP-6 requires non-fast faces to "MUST close the
            // connection" (libtorrent bt_peer_connection.cpp agrees) —
            // the connection layer does not track fast negotiation, so
            // we accept leniently (trusting an advertisement carries no
            // extra risk); the disconnect gate is out of scope here.
            if let Some(tx) = &avail_tx {
                let _ = tx.try_send(AvailEvent::HaveAll { peer: cuid });
            }
            debug!(target: "taiji::bt::peer", "peer has all pieces (BEP6)");
        }
        Message::HaveNone => {
            // BEP-6: have_none = an explicit zero-possession announcement
            // (the same acceptance trade-off as have_all).
            if let Some(tx) = &avail_tx {
                let _ = tx.try_send(AvailEvent::HaveNone { peer: cuid });
            }
            debug!(target: "taiji::bt::peer", "peer has no pieces (BEP6)");
        }
        Message::AllowedFast { index } => {
            // BEP-6 allowed-fast: the peer lets us request while choked;
            // these slots survive choke clearing (PeerConfig::allowed_fast
            // semantics).
            //
            // index bound: the `piece_bytes` table length = piece count
            // (PeerConfig semantics; the same criterion as
            // validate_block_coords in the unsolicited acceptance arm) —
            // an out-of-range index has no legal meaning, and its Piece
            // pushes would be rejected by the piece table at the
            // acceptance arm anyway; accepting it only widens set
            // residency and the acceptance surface → Violation disconnect
            // (the same semantic slot as from_wire validation in the
            // Piece/Reject arms). An empty table = piece geometry not
            // wired (degenerate); nothing to bound, cap only.
            if !piece_bytes.is_empty() && index as usize >= piece_bytes.len() {
                return Err(PeerError::BadPieceIndex { index });
            }
            // Capacity cap: cleared and rebuilt at the cap (the same
            // shape as the Suggest arm's 1024; see
            // [`ALLOWED_FAST_SET_CAP`]).
            if allowed_fast.len() >= ALLOWED_FAST_SET_CAP {
                allowed_fast.clear();
            }
            allowed_fast.insert(index);
            debug!(target: "taiji::bt::peer", index, "peer allowed-fast");
        }
        Message::HashRequest {
            root,
            base,
            index,
            length,
            proof,
        } => {
            // BEP-52: a hash request MUST be answered with hashes or
            // hash reject, and may be sent regardless of choke (only
            // independent rate limiting is allowed).
            let now = Instant::now();
            // The base=0 "immediately follows piece serving" rule: must
            // not be rejected (BEP-52 mandatory); the rate limit does
            // not apply to it (the MUST outranks the local limit).
            let mandatory = follows_piece && base == 0;
            if now.duration_since(*hash_window_start) >= HASH_REQUEST_WINDOW {
                *hash_window_start = now;
                *hash_window_count = 0;
            }
            *hash_window_count += 1;
            let over_limit = !mandatory && *hash_window_count > HASH_REQUEST_LIMIT;
            let answer = if over_limit {
                Err("rate limited (SPEC §13)".into())
            } else {
                match hash_source {
                    Some(src) => src.serve(&root, base, index, length, proof),
                    None => Err("no hash source".into()),
                }
            };
            match answer {
                Ok(hashes) => {
                    // Defense: the source must return the canonical count
                    // (trait contract); otherwise reject as unservable
                    // (a malformed frame would let the peer MUST-
                    // disconnect on us).
                    if hashes.len() as u32 != crate::peer_wire::hashes_count_for(length, proof) {
                        let _ = writer
                            .send(Message::HashReject {
                                root,
                                base,
                                index,
                                length,
                                proof,
                            })
                            .await;
                    } else {
                        let _ = writer
                            .send(Message::Hashes {
                                root,
                                base,
                                index,
                                length,
                                proof,
                                hashes,
                            })
                            .await;
                    }
                }
                Err(reason) => {
                    debug!(target: "taiji::bt::peer", %reason, base, index, length,
                        "hash request -> reject");
                    let _ = writer
                        .send(Message::HashReject {
                            root,
                            base,
                            index,
                            length,
                            proof,
                        })
                        .await;
                }
            }
        }
        Message::Hashes {
            root,
            base,
            index,
            length,
            proof,
            hashes,
        } => {
            // Requester side: full tuple equality with this connection's
            // pending hash request = related (BEP-52 "This message MUST
            // correlate with a 'hash request' message"); piece-root
            // verification and storage happen in the caller. No pending /
            // header mismatch = an unrelated reply: log and drop (the
            // pending request stays in flight and the real answer can
            // still arrive; the payload is inert, no disconnect).
            let related = pending_hash
                .as_ref()
                .is_some_and(|p| p.matches(&root, base, index, length, proof));
            if related {
                let pending = pending_hash
                    .take()
                    .unwrap_or_else(|| unreachable!("related"));
                debug!(target: "taiji::bt::peer", base, index, length,
                    count = hashes.len(), "hashes received for pending request");
                let _ = pending.reply.send(Ok(HashFetch::Hashes(hashes)));
            } else {
                debug!(target: "taiji::bt::peer", base, index, length,
                    "unrelated inbound hashes dropped (no matching pending request)");
            }
        }
        Message::HashReject {
            root,
            base,
            index,
            length,
            proof,
        } => {
            // Requester side: a reject answer to the pending request (a
            // legal answer form, BEP-52); the retry/degrade policy
            // belongs to the caller. No pending = log and ignore.
            let related = pending_hash
                .as_ref()
                .is_some_and(|p| p.matches(&root, base, index, length, proof));
            if related {
                let pending = pending_hash
                    .take()
                    .unwrap_or_else(|| unreachable!("related"));
                debug!(target: "taiji::bt::peer", base, index, length,
                    "hash request rejected by peer");
                let _ = pending.reply.send(Ok(HashFetch::Rejected));
            } else {
                debug!(target: "taiji::bt::peer", base, index, length,
                    "unrelated hash reject dropped (no matching pending request)");
            }
        }
        Message::Port { port } => {
            // BEP-5 PORT receipt: port=0 ignored (BtPortMessage.cc
            // "Ignored port 0"); a valid port is forwarded to the engine
            // → AddPortNode (the node ID is corrected by the ping reply,
            // same as aria2).
            if let Some(tx) = port_tx {
                if port != 0 {
                    // PORT is low-frequency; dropped on full (a repeated
                    // PORT only means a repeated ping, benign).
                    let _ = tx.try_send((cuid, port));
                } else {
                    debug!(target: "taiji::bt::peer", "ignored PORT 0 (BtPortMessage.cc)");
                }
            }
        }
        Message::Extended { ext_id, payload } => {
            // An ext handshake `v` matching the deny list → the verdict
            // lands in deny_hit and the connection ends as ClientBanned
            // (the violation channel takes effect).
            let mut deny_hit: Option<String> = None;
            handle_extended(
                ext_id,
                &payload,
                ExtendedCtx {
                    writer,
                    peer_ut_metadata_id,
                    peer_ut_pex_id,
                    metadata_serve,
                    fetch_session,
                    fetch_spec,
                    metadata_abort,
                    pex_ext,
                    pex_sender,
                    cuid,
                    holepunch,
                    peer_ut_holepunch_id,
                    peer_supports_holepunch,
                    hp_rv_window,
                    hp_rv_count,
                    hp_ct_window,
                    hp_ct_count,
                    pex_window,
                    pex_count,
                    pex_inbound,
                    client_deny,
                    client_deny_hit: &mut deny_hit,
                    peer_upload_only,
                },
            )
            .await;
            if let Some(reason) = deny_hit {
                return Err(PeerError::ClientBanned(reason));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The allowed-fast cap is anchored at 1024 (aligned with the
    /// Suggest arm's 1024 shape; flooding the cap costs ~40KiB of
    /// residency instead of ~160KiB). The clear-and-rebuild behavior is
    /// covered by existing tests; this one only pins the constant
    /// against accidental rebound.
    #[test]
    fn allowed_fast_set_cap_anchored_at_1024() {
        assert_eq!(ALLOWED_FAST_SET_CAP, 1024);
    }
}

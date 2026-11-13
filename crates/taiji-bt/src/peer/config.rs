//! PeerTask construction config and the connection event / final-state
//! type surface: [`PeerConfig`] (post-handshake connection + swarm
//! addressing context, the engine assembly entry point), availability
//! events ([`AvailEvent`]), ut_pex discovery events ([`PexEvent`]) and
//! wiring parameters ([`PexExt`]), verified inbound blocks
//! ([`PieceData`]), protocol violations ([`PeerError`]) and connection
//! final states ([`PeerEnd`]).

use std::collections::HashSet;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use super::ExtConfig;
use super::sources::{HashSource, PieceSource};
use crate::piece_id::{Addressing, PieceId};

/// keepalive idle send interval, default 120s.
///
/// - Value: aria2 `--bt-keep-alive-interval` default "120"
///   (`OptionHandlerFactory.cc`, domain 1..=120 seconds; the constructor
///   default is the same, `DefaultBtInteractive.cc`
///   `keepAliveInterval_(120)`).
/// - Semantics (idle-gated, zero redundant frames on active connections):
///   BEP3 keepalive = the zero-length message (`<len=0>`); BEP does not
///   specify when to send. Aligned with libtorrent `keep_alive()`
///   (`peer_connection.cpp` — returns early when less than the threshold
///   has passed since `m_last_sent`; its threshold is half the connection
///   timeout, not numerically aligned) and aria2 `sendKeepAlive()`
///   (`DefaultBtInteractive.cc`, purely periodic); this side gates on
///   idleness to suppress redundant frames.
///
/// Compatibility surface frozen: no session/RPC option is exposed; tests
/// inject short values (precedent:
/// [`PeerConfig::flooding_interval`]).
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);

/// PeerTask construction parameters (post-handshake connection + swarm
/// addressing context).
pub struct PeerConfig {
    pub addressing: Addressing,
    /// Expected byte count per piece (wire index -> bytes): the block
    /// coordinate upper-bound criterion for the unsolicited-accept arm
    /// (pushes inside the allowed-fast/suggest sets) — table length =
    /// piece count (index bound), entry = that piece's expected bytes
    /// (final piece truncated). For both v1 and v2 the wire index equals
    /// the flat piece order (`Addressing::to_wire`/`to_flat` compute the
    /// same thing), so one table serves both kinds. Empty table = piece
    /// geometry unknown (degenerate form: only alignment/granularity
    /// checks, no piece bounds or index upper bound).
    pub piece_bytes: std::sync::Arc<[u64]>,
    /// Wire indexes the peer allowed us to request while it chokes us
    /// (BEP3; often empty early on). These slots survive choke clearing.
    pub allowed_fast: HashSet<u32>,
    pub request_timeout: Duration,
    /// BDP-target request window cap (the `bt-max-out-request-queue`
    /// configurable): target window = `clamp(3s x payload-rate EWMA /
    /// 16KiB, 2, this value)` (a libtorrent `peer_connection.cpp`
    /// translation). Default
    /// [`crate::request_book::UB_MAX_OUTSTANDING_REQUEST`] (256 — the
    /// aria2 `BtConstants.h` current cap, unchanged; the reference
    /// `settings_pack.cpp` default of 500 is cited for comparison only,
    /// this side keeps the conservative default). With BDP off (fallback
    /// mode) this is the doubled cap (same semantics as the default).
    pub max_out_request_queue: usize,
    /// Request-window mode injection (test surface): None = environment
    /// default (`BH_REQUEST_WINDOW_BDP=0` -> fallback doubling heuristic,
    /// otherwise BDP — [`crate::request_book::WindowMode::from_env`]);
    /// Some pins the mode (for deterministic tests — the window-growth
    /// verdicts of live duplex tests must not depend on environment
    /// variables or 1s rate-window boundaries). Production assembly
    /// always passes None.
    pub window_bdp: Option<bool>,
    /// Request-message batched-write injection (test surface): None =
    /// environment default (`BH_REQUEST_COALESCE=0` -> write one by one,
    /// otherwise batched — default on); Some pins the mode (deterministic
    /// tests — outbound write-count verdicts must not depend on
    /// environment variables). Production assembly always passes None.
    pub request_coalesce: Option<bool>,
    /// Idle Framed-buffer shrink injection (test surface): None =
    /// environment default (`BH_READ_BUF_SHRINK=0` -> off, otherwise on —
    /// default on); Some pins the mode (deterministic tests — buffer-size
    /// verdicts must not depend on environment variables). On = a
    /// connection with no inbound frame for
    /// [`super::conn::READ_BUF_IDLE_SHRINK`] (5s) has its FramedRead /
    /// FramedWrite internal `BytesMut` swapped down to zero capacity when
    /// fully drained (the codec's one-shot exact reservation regrows them
    /// on the next frame; partially-received frames are never touched).
    /// Idle connections stop holding the read high-water (16-32KiB after a
    /// piece burst; aria2 `receive_buffer` analog: idle 4KiB, grown on
    /// demand). Production assembly always passes None.
    pub read_buf_shrink: Option<bool>,
    /// Flood-check interval: default 5s (aria2 `DefaultBtInteractive.cc`);
    /// tests inject small values.
    pub flooding_interval: Duration,
    /// keepalive idle interval: when outbound silence (no frame of any
    /// kind sent) reaches this duration, the tick arm sends a zero-length
    /// keepalive (BEP3) and resets the timer; zero redundant frames on
    /// active connections. Default [`KEEPALIVE_INTERVAL`] (120s, see the
    /// constant docs); tests inject short values.
    pub keepalive_interval: Duration,
    /// Grace period after our Choke frame during which the peer may still
    /// send requests (requesting beyond the grace = violation disconnect
    /// [`PeerError::RequestsWhileChoked`]). Default
    /// [`crate::request_book::CHOKE_REQUEST_GRACE`] (libtorrent
    /// `peer_connection.cpp` "allow peers to send request up to 2
    /// seconds after getting choke, then disconnect them"); tests inject
    /// small values.
    pub choke_grace: Duration,
    /// Piece data channel capacity (bounded; full = backpressure the read
    /// loop).
    pub data_channel: usize,
    /// Block-data direct-delivery seam. None = the legacy path —
    /// `Message::Piece` goes through `data_tx` -> the attach forwarding
    /// task (default, zero behavior change). When `Some`, the read loop
    /// delivers straight to the face-level channel within the same task
    /// (semantics in [`BlockSink`]); the `data_channel` channel itself is
    /// kept unchanged (legacy path / fallback surface).
    pub direct_block_sink: Option<std::sync::Arc<dyn super::BlockSink>>,
    /// Seeding data source (None = pure downloader, inbound requests are
    /// ignored). v1 global addressing reads; pad regions are zero-filled
    /// by the implementor (BEP47).
    pub source: Option<std::sync::Arc<dyn PieceSource>>,
    /// hash request serving source (BEP52; None = every request gets a
    /// hash reject).
    pub hash_source: Option<std::sync::Arc<dyn HashSource>>,
    /// Stable identifier of this connection (engine-side cuid; echoed in
    /// availability events).
    pub cuid: u64,
    /// Availability event channel (bounded; full = drop — HAVE is high
    /// frequency and rarity is heuristic rather than correctness data, so
    /// lossy is acceptable).
    pub avail_tx: Option<mpsc::Sender<AvailEvent>>,
    /// Inbound PORT message forwarding (BEP5 id=9). `(cuid, dht_port)`
    /// goes to the engine -> `DhtCommand::AddPortNode` (`BtPortMessage.cc`
    /// receive semantics; port=0 is ignored at the peer layer — "Ignored
    /// port 0"). None = DHT disabled, messages dropped. bounded(16): PORT
    /// is low frequency; full = drop (a repeated PORT from the same peer
    /// only causes a duplicate ping — benign).
    pub port_tx: Option<mpsc::Sender<(u64, u16)>>,
    /// Session upload byte counter (None = not counted). Accumulated by
    /// block length after a piece is served successfully — aria2 counts
    /// at piece message send (`BtPieceMessage.cc` `PieceSendUpdate` ->
    /// `dctx->updateUploadLength`, payload only, no frame header).
    pub uploaded: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// Session download byte counter (None = not counted). Accumulated
    /// when a piece frame is received — aria2 counts at message receive
    /// (`BtPieceMessage` receive side `updateDownloadLength`, before
    /// verification; late/duplicate blocks also count toward session
    /// download).
    pub downloaded: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    /// Peer IP (PEX outbound candidate filter: exclude the peer's own
    /// address, the aria2 `peer_->getIPAddress()` comparison in
    /// `DefaultBtInteractive.cc`). None = no filtering (unit-test form).
    pub remote_ip: Option<std::net::IpAddr>,
    /// BEP10 extension surface (ext handshake / ut_metadata serving and
    /// requesting; default off = no ext handshake sent, the frozen
    /// surface's behavior).
    pub ext: ExtConfig,
    /// BEP21 upload_only initial value: true = our ext handshake carries
    /// `upload_only: 1` (seeding-state advertisement). Re-send on
    /// seeding-state transitions = [`PeerCommand::SetUploadOnly`].
    /// Default false (downloading).
    pub upload_only: bool,
    /// Actual advertised peer-listener port (0 omits the BEP10 p field).
    pub listen_port: u16,
    /// Inbound mirror of the peer's BEP21 upload_only: the `upload_only`
    /// advertisement in the peer's ext handshake (seeding/partial
    /// seeding — "Setting the value of this key to 1 indicates that this
    /// peer is not interested in downloading anything."). Each arrival
    /// overwrites the stored value (follows updates; same rule as
    /// libtorrent on_extended_handshake reading the dict frame by frame,
    /// bt_peer_connection.cpp; missing key = false). The engine-side peer
    /// profile (`PeerMeta`) holds the same Arc (assembled at transit
    /// attach, same pipeline as the `uploaded`/`downloaded` counters);
    /// None = not recorded (unit tests / the metadata surface have no
    /// profile consumer).
    pub peer_upload_only: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// BEP16 super-seeding serving gate: Some = this connection is on the
    /// super-seeding seeding face — inbound requests are served only for
    /// the assigned piece (two slots), everything else rejected
    /// (libtorrent `peer_connection.cpp`). Default None = normal
    /// seeding/downloading face, request serving is not
    /// assignment-constrained.
    pub super_seed: Option<std::sync::Arc<crate::superseed::SuperSeedBook>>,
    /// ut_holepunch event return path: Some = our ext handshake
    /// advertises `ut_holepunch`
    /// ([`crate::holepunch::OUTBOUND_UT_HOLEPUNCH_ID`]) and inbound frames
    /// are consumed (rendezvous/connect are handed up as events for the
    /// caller to decide — relaying and holepunch dialing both need a
    /// swarm-global view; PeerTask does not decide locally). None = no
    /// advertise, no consume (frames with the id are ignored as unknown
    /// extensions; the "registry removal" semantics, same shape as the
    /// ut_pex gate). Default None = off (zero change to existing call
    /// sites).
    pub holepunch: Option<HolepunchExt>,
    /// Client identity re-check callback (-6): called with the `v` field
    /// when the peer's ext handshake carries one (engine-injected list
    /// check — the second matching dimension of `client_ban_prefixes`).
    /// `Some(reason)` = hit, the connection ends in a
    /// [`PeerError::ClientBanned`] disconnect (-> engine persists + blocks
    /// the IP). None = no re-check (unit tests / default).
    pub client_deny: Option<ClientDenyCheck>,
    /// Face-level read pool (async upload read path): Some = inbound
    /// request disk reads go into the pool (a dedicated `spawn_blocking`
    /// dispatcher, replies re-injected to this connection's sender in
    /// request order) — the peer event loop no longer executes blocking
    /// syscalls (libtorrent runs one network thread + a disk thread pool,
    /// `session_impl.hpp`/`settings_pack.cpp`; see the peer::read_pool
    /// module docs). None = the existing inline synchronous read form
    /// (unit tests / metadata surface unchanged).
    pub read_pool: Option<std::sync::Arc<super::read_pool::ReadPool>>,
    /// Face-level block buffer pool: when present, this connection's
    /// read-side FrameCodec frame bodies borrow from the arena (pooled
    /// wire decode buffers, removing per-block VM churn; refcount zero
    /// returns the block to the pool). None = the existing frozen shared
    /// read-buffer path, unchanged (`BH_BLOCK_ARENA=0` / unit-test form).
    pub block_arena: Option<std::sync::Arc<taiji_io::block_arena::BlockArena>>,
    /// Mirror of the peer's fast-extension negotiation (BEP6
    /// `reserved[7] & 0x04`): BEP6 — "The extension is enabled only if
    /// both ends of the connection set this bit". Outbound Reject is sent
    /// only when this bit is true (sending reject to a peer that did not
    /// negotiate would force it to disconnect per BEP6 "If the fast
    /// extension is disabled and a peer receives a reject request then
    /// the peer MUST close the connection" — a MUST-close violation).
    /// Default true: our outbound handshakes always set the fast bit
    /// (`Reserved::aria2_default`; engine-side reserved from the same
    /// source), so the `PeerConfig::flat` minimal default matches the
    /// existing fast-enabled test semantics; production assembly
    /// overwrites this explicitly with the peer's handshake bit (transit
    /// `attach_peer`, same pipeline as the `peer_dht`/ext negotiation
    /// gates).
    pub peer_fast: bool,
}

/// Client identity re-check callback (-6): input = the peer's
/// self-reported ext handshake `v` field; output =
/// `Some(ban hit string)` (the violation reason payload, same shape as
/// the engine's handshake-time `client-ban:<hit string>`). Implemented
/// engine-side from the IpGuard snapshot (`client_ban_prefixes`
/// hot-swapped) — the bt layer carries only the callback and does not
/// depend on the snapshot.
pub type ClientDenyCheck = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("addressing", &self.addressing)
            .field("piece_bytes", &self.piece_bytes.len())
            .field("allowed_fast", &self.allowed_fast)
            .field("request_timeout", &self.request_timeout)
            .field("max_out_request_queue", &self.max_out_request_queue)
            .field("window_bdp", &self.window_bdp)
            .field("request_coalesce", &self.request_coalesce)
            .field("read_buf_shrink", &self.read_buf_shrink)
            .field("flooding_interval", &self.flooding_interval)
            .field("keepalive_interval", &self.keepalive_interval)
            .field("data_channel", &self.data_channel)
            .field(
                "direct_block_sink",
                &self.direct_block_sink.as_ref().map(|_| "BlockSink"),
            )
            .field("source", &self.source.as_ref().map(|_| "PieceSource"))
            .field(
                "hash_source",
                &self.hash_source.as_ref().map(|_| "HashSource"),
            )
            .field("uploaded", &self.uploaded.as_ref().map(|_| "AtomicU64"))
            .field("downloaded", &self.downloaded.as_ref().map(|_| "AtomicU64"))
            .field(
                "peer_upload_only",
                &self.peer_upload_only.as_ref().map(|_| "AtomicBool"),
            )
            .field("remote_ip", &self.remote_ip)
            .field("avail_tx", &self.avail_tx.as_ref().map(|_| "Sender"))
            .field("port_tx", &self.port_tx.as_ref().map(|_| "Sender"))
            .field("ext", &self.ext)
            .field("holepunch", &self.holepunch)
            .field(
                "client_deny",
                &self.client_deny.as_ref().map(|_| "ClientDenyCheck"),
            )
            .field("read_pool", &self.read_pool.as_ref().map(|_| "ReadPool"))
            .field(
                "block_arena",
                &self.block_arena.as_ref().map(|_| "BlockArena"),
            )
            .field("peer_fast", &self.peer_fast)
            .finish()
    }
}

impl PeerConfig {
    /// Minimal config: v1 flat addressing + default timeouts
    /// (integration-test / wiring use).
    pub fn flat() -> PeerConfig {
        PeerConfig {
            addressing: Addressing::Flat,
            piece_bytes: Vec::new().into(),
            allowed_fast: HashSet::new(),
            request_timeout: crate::request_book::DEFAULT_REQUEST_TIMEOUT,
            max_out_request_queue: crate::request_book::UB_MAX_OUTSTANDING_REQUEST,
            window_bdp: None,
            request_coalesce: None,
            read_buf_shrink: None,
            flooding_interval: crate::request_book::FLOODING_CHECK_INTERVAL,
            keepalive_interval: KEEPALIVE_INTERVAL,
            choke_grace: crate::request_book::CHOKE_REQUEST_GRACE,
            data_channel: 16,
            direct_block_sink: None,
            source: None,
            hash_source: None,
            cuid: 0,
            avail_tx: None,
            port_tx: None,
            uploaded: None,
            downloaded: None,
            peer_upload_only: None,
            remote_ip: None,
            ext: ExtConfig::default(),
            upload_only: false,
            listen_port: 0,
            super_seed: None,
            holepunch: None,
            client_deny: None,
            read_pool: None,
            block_arena: None,
            peer_fast: true,
        }
    }
}

/// Peer possession events (HAVE/bitfield -> engine PieceStatMan counts).
/// v1 wire index coordinates; bitfield is raw bits (big-endian bit order,
/// zero tail padding, BEP3). HaveAll/HaveNone = BEP6 full/empty
/// possession advertisements — "When present, Have All or Have None
/// replace the Have Bitfield" (the main interop form: a fast-negotiated
/// seeder replaces the bitfield with have_all).
#[derive(Debug, Clone)]
pub enum AvailEvent {
    Have {
        peer: u64,
        index: u32,
    },
    Bitfield {
        peer: u64,
        bits: Bytes,
    },
    /// BEP6 have_all (`<len=1><op=0x0E>`): the peer declares it holds all
    /// pieces.
    HaveAll {
        peer: u64,
    },
    /// BEP6 have_none (`<len=1><op=0x0F>`): the peer declares it holds
    /// nothing.
    HaveNone {
        peer: u64,
    },
    /// Edge event of the peer going choke -> unchoke (trigger paired with
    /// the reciprocity-economy fix): the request dispatch arm sends zero
    /// requests to choked peers per aria2 `fillPiece`
    /// (`DefaultBtInteractive.cc`); without this trigger after the peer
    /// unchokes, supply would not resume until the next natural dispatch
    /// event (in a stall window with BlockSettled silent and no
    /// advertisements this can reach minutes). Low-frequency edge (not a
    /// level).
    Unchoked {
        peer: u64,
    },
    /// Rising edge of the peer's INTERESTED (preemptive unchoke trigger;
    /// libtorrent `peer_connection.cpp` + `session_impl.cpp`: on
    /// receiving INTERESTED while we are choked, with fixed slots and a
    /// free slot -> unchoke immediately, saving one round-trip; the
    /// engine-side free-slot verdict lives in the engine choke module's
    /// preemptive_unchoke). Low-frequency edge (not a level; repeated
    /// Interested does not re-fire); lossy drop when full — a missed edge
    /// is covered by the next choke round (degradation = no preemptive
    /// unchoke, consistent with the existing round semantics).
    Interested {
        peer: u64,
    },
}

/// Peers discovered via inbound ut_pex (consumer surface): after PeerTask
/// decodes [`crate::pex::PexMessage`] it hands them to the caller via
/// [`PexExt::tx`] (engine connection management; reference
/// `UTPexExtensionMessage::doReceivedAction` — fresh and dropped both go
/// into PeerStorage; this side passes both lists through the same way,
/// dialing decisions belong to the caller).
#[derive(Debug, Clone)]
pub struct PexEvent {
    /// Source connection of the report (the engine locates the owning
    /// torrent by it).
    pub from: u64,
    /// `added`/`added6` endpoint compatibility view.
    pub fresh: Vec<std::net::SocketAddr>,
    /// Transport capabilities retained from BEP11 added.f.
    pub capabilities: Vec<crate::pex::PexPeer>,
    /// `dropped`/`dropped6`.
    pub dropped: Vec<std::net::SocketAddr>,
}

/// ut_pex advertise/consume wiring parameters (the [`ExtConfig::pex`]
/// payload).
#[derive(Clone)]
pub struct PexExt {
    /// Channel for reporting peers discovered via inbound ut_pex
    /// (bounded; full = drop — ut_pex sends at most one frame per peer
    /// per >=60s and the caller dedups repeated discoveries, so the
    /// semantics are lossless).
    pub tx: mpsc::Sender<PexEvent>,
    /// Outbound interval (production assembly always
    /// [`crate::pex::DEFAULT_INTERVAL`]; tests inject short values to
    /// drive the same 60s state machine — aria2 keeps this value
    /// constant, with no option surface).
    pub interval: Duration,
}

impl std::fmt::Debug for PexExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PexExt")
            .field("tx", &"Sender<PexEvent>")
            .field("interval", &self.interval)
            .finish()
    }
}

/// Verified inbound block data (delivered to TorrentTask -> the
/// write-cache path, receive side).
#[derive(Debug)]
pub struct PieceData {
    pub id: PieceId,
    pub begin: u32,
    pub block: Bytes,
}

/// ut_holepunch advertise/consume wiring (the [`PeerConfig::holepunch`]
/// payload; isomorphic to [`PexExt`]).
#[derive(Clone)]
pub struct HolepunchExt {
    /// Channel for inbound rendezvous/connect events (bounded 16: both
    /// event kinds are rate-limited by a fixed per-peer window (60s), so
    /// low frequency; `send().await` backpressures — losing an event
    /// loses one holepunch opportunity (protocol-safe, the peer can retry
    /// later), hence not try_send's drop semantics). Failed frames are
    /// informational and not surfaced (libtorrent only logs them,
    /// bt_peer_connection.cpp).
    pub tx: mpsc::Sender<HolepunchEvent>,
}

impl std::fmt::Debug for HolepunchExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HolepunchExt")
            .field("tx", &"Sender<HolepunchEvent>")
            .finish()
    }
}

/// Inbound ut_holepunch event: a projection of the three sub-operations
/// (`msg` see [`crate::holepunch::UtHolepunch`] — that module's docs hold
/// the wire format / behavioral authority).
#[derive(Debug, Clone)]
pub struct HolepunchEvent {
    /// cuid of the connection the frame arrived on (the engine locates
    /// the owning torrent and the peer address by it).
    pub from: u64,
    /// rendezvous = relay-decision input; connect = holepunch dial
    /// instruction (join the swarm as a normal outbound); failed =
    /// informational (the engine only logs it too).
    pub msg: crate::holepunch::UtHolepunch,
}

/// Protocol violations (must disconnect, SPEC §6.2).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PeerError {
    #[error("piece index {index} outside swarm addressing")]
    BadPieceIndex { index: u32 },
    #[error("unsolicited piece {index}+{begin}+{length}")]
    UnsolicitedPiece { index: u32, begin: u32, length: u32 },
    /// Block coordinates of an unsolicited push inside the
    /// allowed-fast/suggest sets violate wire request geometry — begin
    /// not 16KiB aligned, length outside (0,16KiB], piece-bound overflow,
    /// or index beyond the piece table. Set membership is peer-controlled
    /// and does not make coordinates legal; the slot-matched path needs
    /// no such check (begin/length equal our dispatched slot exactly;
    /// legality is guaranteed by the dispatch side).
    #[error(
        "piece block {index}+{begin}+{length} violates wire request geometry \
         (16KiB-aligned begin, (0,16KiB] length, in-piece bound)"
    )]
    BadBlockCoords { index: u32, begin: u32, length: u32 },
    #[error("request length {length} > 16KiB: must disconnect (SPEC §6.2)")]
    OversizeRequest { length: u32 },
    #[error(
        "request {index}+{begin}+{length} while choked beyond {}s grace: \
         disconnect (libtorrent peer_connection.cpp)",
        crate::request_book::CHOKE_REQUEST_GRACE.as_secs()
    )]
    RequestsWhileChoked { index: u32, begin: u32, length: u32 },
    /// Client identity ban (-6): the peer's ext handshake `v` field hit
    /// the `client_ban_prefixes` list (via the engine-injected
    /// [`ClientDenyCheck`] callback). The payload is the violation reason
    /// (`client-ban:<hit string>`, same shape as the handshake-time
    /// peer_id verdict — one engine persistence/disconnect surface).
    #[error("{0}")]
    ClientBanned(String),
}

/// Connection final state (produced by the JoinHandle, for TorrentTask
/// bookkeeping / redial decisions).
#[derive(Debug)]
pub enum PeerEnd {
    Clean,
    Cancelled,
    /// The peer closed the connection normally (EOF).
    Closed,
    /// kind extracted from the underlying io error: callers can classify
    /// redial/backoff by kind
    /// (ConnectionReset/TimedOut/ConnectionRefused) and must not depend
    /// on error-text substrings.
    Io {
        kind: std::io::ErrorKind,
        message: String,
    },
    /// Protocol violation: peer-level errors do not contaminate the
    /// torrent.
    Violation(PeerError),
    /// Message flooding: disconnect (aria2 `DefaultBtInteractive.cc`).
    Flooded,
}

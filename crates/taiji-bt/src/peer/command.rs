//! Control-command surface between the upper layers and PeerTask
//! (`crate::peer::PeerTask`): the command enum [`PeerCommand`] and its
//! submission-failure form [`PeerCommandRejected`], the hash-request
//! requester's reply [`HashFetch`] / error [`HashRequestError`], and the
//! communication trait [`PeerHandle`] (TorrentTask / the engine issue
//! commands through it). Channel discipline: bounded mpsc(8); a full
//! channel backpressures the caller (unbounded channels are forbidden).

use tokio::sync::oneshot;

use super::sources::{HashSource, PieceSource};
use crate::piece_id::PieceId;
use crate::request_book::DispatchError;

/// Control commands sent to a PeerTask by the upper layers.
pub enum PeerCommand {
    Shutdown,
    /// Dispatch one block request: passes RequestBook budget/duplicate
    /// checks, then sends a wire request. The result comes back over the
    /// oneshot (the caller may drop the receiver for fire-and-forget).
    RequestPiece {
        id: PieceId,
        begin: u32,
        length: u32,
        reply: oneshot::Sender<Result<(), DispatchError>>,
    },
    /// Cancel one of our outstanding requests: clear the slot (ignored if
    /// absent) and send a cancel.
    CancelPiece {
        id: PieceId,
        begin: u32,
        length: u32,
    },
    /// Broadcast HAVE (sent per connection by TorrentTask after a piece
    /// completes; BEP3).
    SendHave {
        index: u32,
    },
    /// Send a bitfield right after registration to advertise our holdings
    /// (BEP3: the bitfield follows the handshake; `packed` is big-endian
    /// bit order with trailing pad bits 0 — BEP3 forbids pad bits of 1).
    SendBitfield {
        packed: Vec<u8>,
    },
    /// Express download interest (BEP3: a precondition for requests).
    SendInterest,
    /// Send a PORT message (BEP5 id=9, payload = our DHT UDP port).
    /// Issued by the engine after the handshake when DHT is enabled and
    /// the peer's reserved bits declare support
    /// (`DefaultBtInteractive.cc`: `peer_->isDHTEnabled() &&
    /// dhtEnabled_` -> `addPortMessageToQueue()`).
    SendPort {
        dht_port: u16,
    },
    /// Allow the peer to download (BEP3 unchoke; driven by the choking
    /// skeleton's 10s rounds).
    SendUnchoke,
    /// Forbid the peer from downloading (BEP3 choke; driven by the
    /// leecher choking round: a peer unchoked in the previous round that
    /// loses its unchoke slot must be re-choked, otherwise the slot is
    /// never reclaimed). BEP3 semantics: after we choke, this peer's
    /// subsequent requests are answered with reject (an obligation for
    /// fast-ext advertisers).
    SendChoke,
    /// Attach the seeding data source once the download completes (issued
    /// per connection by the engine on the TorrentTask -> Seeding
    /// transition).
    AttachSource(std::sync::Arc<dyn PieceSource>),
    /// BEP-21 upload_only announcement update: true/false = seeding state
    /// start/stop. The announcement is re-sent on every state transition —
    /// update the local flag and re-send the ext handshake (BEP10 id=0)
    /// verbatim (the m dict is unchanged; it is safe for the peer to
    /// re-read the key; the libtorrent equivalent is
    /// `torrent::send_upload_only`'s state-change broadcast, torrent.cpp).
    SetUploadOnly(bool),
    /// Refresh the advertised listener after a NAT mapping changes.
    SetListenPort(u16),
    /// Attach BEP-16 super-seeding bookkeeping: issued by the engine when
    /// entering seeding state or when a new connection registers while
    /// seeding; Some = enable the request-serving gate (libtorrent
    /// `peer_connection.cpp`). Downloading connections get no bookkeeping —
    /// tit-for-tat upload service is not constrained by the assignment.
    SetSuperSeed(std::sync::Arc<crate::superseed::SuperSeedBook>),
    /// Attach the hash-request serving source once the download completes
    /// (BEP-52; same timing as AttachSource).
    AttachHashSource(std::sync::Arc<dyn HashSource>),
    /// Session-level PEX candidate snapshot (outbound surface): the engine
    /// pushes candidates from the trailing 60s window after outbound
    /// connection register/leave events (a windowed projection of aria2
    /// `peerStorage` getUsedPeers/getDroppedPeers); PeerTask filters,
    /// builds, and sends it when [`PexSwarmSender::due`] fires (a covering
    /// snapshot — the last push wins).
    SetPexCandidates {
        fresh: Vec<crate::pex::PexCandidate>,
        dropped: Vec<crate::pex::PexCandidate>,
    },
    /// Requester lazy-fetch (BEP-52 hash exchange): send a hash request
    /// (21) and deliver the reply over the oneshot — `hashes`(22) is
    /// passed through as-is, `hash reject`(23) maps to
    /// [`HashFetch::Rejected`]. Reply/request correlation is a five-tuple
    /// match against this connection's pending request header (BEP-52:
    /// "This message MUST correlate with a 'hash request' message");
    /// verifying to the piece root and storing the result belong to the
    /// caller (bt does not depend on store). Choke does not block sending
    /// (BEP-52: "Hash requests may be sent to a peer regardless of its
    /// choke state").
    RequestHashes {
        root: [u8; 32],
        base: u32,
        index: u32,
        length: u32,
        proof: u32,
        reply: oneshot::Sender<Result<HashFetch, HashRequestError>>,
    },
    /// Send a ut_holepunch message: rendezvous = ask the introducer for a
    /// connect; connect = bidirectional introduction over the relay;
    /// failed = relay-refusal answer. Sent only when the peer's ext
    /// handshake advertised ut_holepunch (BEP10: use its advertised id;
    /// not advertised = the command is dropped with a debug log — a peer
    /// lacking support is not an error).
    SendHolepunch(crate::holepunch::UtHolepunch),
}

/// Hash-request requester reply (BEP-52: must be answered with either
/// hashes or hash reject).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashFetch {
    /// `hashes`(22): base-layer hashes plus proof hashes (count
    /// consistency is enforced by the codec).
    Hashes(Vec<[u8; 32]>),
    /// `hash reject`(23): the peer refused to serve (a legal answer; the
    /// downgrade policy is the caller's job).
    Rejected,
}

/// Hash-request submission failed (local mechanism layer, not a peer
/// answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashRequestError {
    /// This connection already has a pending hash request (at most one in
    /// flight per connection — requester lazy-fetch is naturally serial:
    /// blocks depending on that layer are not dispatched until the hashes
    /// arrive).
    Busy,
    /// The PeerTask has exited (connection closed); no reply is coming.
    Closed,
}

/// Control-command submission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerCommandRejected {
    /// The PeerTask has exited; the command channel is closed.
    Closed,
    /// Channel full (capacity 8): the caller is backpressured and may
    /// retry.
    Full,
}

/// Communication trait between TorrentTask / the upper layers and
/// PeerTask.
pub trait PeerHandle: Send + Sync {
    /// Submit a control command. `Err(())` means the PeerTask has exited
    /// or the channel is full (backpressure policy: never block the
    /// caller; the caller decides whether to retry or give up).
    fn command(&self, cmd: PeerCommand) -> Result<(), PeerCommandRejected>;

    /// Ask the PeerTask to shut down gracefully (idempotent).
    fn shutdown(&self);
}

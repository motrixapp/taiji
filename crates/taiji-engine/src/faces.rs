//! Swarm-face runtime state: `FaceState` and its bookkeeping views
//! (`SwarmSnapshot`/`FaceView`, `PeerMeta`/`PeerRate`/
//! `PeerRegistration`), the seeding source (`FaceSource`), the shuffle
//! source (`XorShift`), PEX candidate bookkeeping, seeding-source
//! attachment, and piece-completion propagation.
//!
//! Covers: one face's connection/availability/progress/choke
//! bookkeeping fields and its pure-function faces. Does not cover:
//! block dispatch (dispatch), choking decisions (choke), persistence
//! (tracker/progress).
//!
//! Upstream anchor mapping: docs/design/engine.md.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::{debug, info};

use taiji_bt::choke::{LeecherChoke, SeederChoke};
use taiji_bt::mse::CryptoLevel;
use taiji_bt::peer::{HashSource, PeerHandle as _, PeerTaskHandle, PieceSource};
use taiji_bt::peer_wire::Reserved;
use taiji_bt::piece_id::Addressing;
use taiji_bt::piece_stat::PieceStatMan;
use taiji_bt::tracker::actor::SwarmView;
use taiji_bt::utp::Transport;
use taiji_store::hashtree::HashTreeCache;
use taiji_store::layout::Layout;
use taiji_store::torrent_writer::{READER_MAX_OPEN_HANDLES, ReadSpec, TorrentReader};

use taiji_domain::metainfo::MetaFile;
use taiji_domain::progress::ProgressModel;
use taiji_domain::seed::SessionSpeedCalc;

use std::time::Duration;

use crate::bitmap::PieceBitmap;
use crate::config::FaceKind;
use crate::dispatch::{DispatchReply, FileLayerState, HashFetchEvent, PieceSentLedger};
use crate::pipeline::{BlockMsg, BlockSenders, DataFlushState};
use crate::tracker::TrackerMirror;
use crate::upload::RateWindow;
/// The serve-face coalesced read cap — bytes (the same cap basis as
/// the store `read_coalesced` test tier 1MiB; libtorrent
/// `docs/manual.rst` coalesce-the-small-bittorrent-requests, the same
/// source as the store disk_policy read-coalescing reference; a
/// first-cut engineering value, to be tuned with the seeder
/// benchmarks).
pub(super) const FACE_READ_COALESCE_MAX_BYTES: usize = 1 << 20;
/// The serve-face coalesced read cap — absorbed segments per range
/// (the same source as above).
pub(super) const FACE_READ_COALESCE_MAX_RANGES: usize = 64;

/// The numwant gate threshold: the default = the outbound target
/// reading [`crate::run::peer_connections_target`] (100; semantics:
/// keep requesting peers until the outbound target is reached), with
/// the numeric override seam `BH_TRACKER_MIN_PEERS` (trim + usize
/// parse; failure/0 falls back to the default — the `BH_PEER_MAX`
/// pattern, a process-level OnceLock).
///
/// # Divergence note (the aria2 port -> the supply stance)
///
/// The old threshold was the direct port of aria2 `BtRuntime.h`
/// DEFAULT_MIN_PEERS 40 (`BtRuntime.h` `lessThanMinPeers` = the
/// connection count below min peers; the consumer chain
/// `DefaultBtAnnounce.cc` asks for numwant=0 once 40 is reached). In
/// swarms heavy with dead candidates, a registered count stalled in
/// the 40-100 band switched the tracker's peer supply off entirely —
/// the window needing supply most got the least. This side takes
/// keep-requesting-until-the-outbound-target (closer to libtorrent,
/// whose announce always requests numwant — `announce_entry.cpp` has
/// no aria2-style min-peers shutoff); the aria2 stance is reachable
/// via env (`BH_TRACKER_MIN_PEERS=40`).
///
/// Consumer audit: this gate's only runtime consumer is FaceView's
/// `less_than_min_peers` (the tracker actor's numwant decision). The
/// metadata-phase gate is taiji-core magnet.rs's separate `MIN_PEERS`
/// = 40 (no outbound-target reading there — magnet dialing sits far
/// below 40 connections, so the gate stays open; unchanged).
pub(super) fn tracker_min_peers() -> usize {
    // Parse and read-timing registration in `taiji_io::knobs` (a
    // process-level OnceLock).
    taiji_io::knobs::tracker_min_peers(crate::run::peer_connections_target())
}

/// The numwant gate decision core (the threshold is an explicit
/// parameter — decision-table tests drive it directly; the runtime
/// face composes through [`tracker_min_peers`], the same pattern as
/// `admission_verdict_limits`): registered below the threshold ->
/// request peers (numwant=DEFAULT_NUMWANT).
pub(super) fn less_than_min_peers_of(registered: usize, min_peers: usize) -> bool {
    registered < min_peers
}

/// SwarmView reading snapshot (refreshed by the main loop's 2s tick;
/// short std Mutex critical sections, no lock across await — the
/// actor reads asynchronously inside its own task).
pub(super) struct SwarmSnapshot {
    pub(super) total: u64,
    pub(super) completed: u64,
    pub(super) all_finished: bool,
    pub(super) peers: usize,
    /// Torrent-level session upload (the announce `uploaded`
    /// reading, `DefaultBtAnnounce.cc`).
    pub(super) uploaded: u64,
    /// Torrent-level session download (the announce `downloaded`
    /// reading).
    pub(super) downloaded: u64,
}

/// The per-swarm-face statistics view (bt does not depend on core:
/// the actor reads through the injected trait).
#[derive(Clone)]
pub(super) struct FaceView(pub(super) Arc<Mutex<SwarmSnapshot>>);

impl FaceView {
    pub(super) fn with<R>(&self, f: impl FnOnce(&SwarmSnapshot) -> R) -> R {
        let guard = crate::lock(&self.0);
        f(&guard)
    }
}

impl SwarmView for FaceView {
    fn total_length(&self) -> u64 {
        self.with(|s| s.total)
    }
    fn completed_length(&self) -> u64 {
        self.with(|s| s.completed)
    }
    /// Session upload count (the sum of served piece bytes across
    /// all connections; see the [`PeerConfig::uploaded`] counting
    /// point).
    fn session_uploaded(&self) -> u64 {
        self.with(|s| s.uploaded)
    }
    /// Session download count (the sum of received piece-frame
    /// bytes).
    fn session_downloaded(&self) -> u64 {
        self.with(|s| s.downloaded)
    }
    fn all_download_finished(&self) -> bool {
        self.with(|s| s.all_finished)
    }
    /// Fewer peers than the gate threshold (the threshold =
    /// [`tracker_min_peers`]'s default outbound-target reading; the
    /// aria2-port stance and divergence note are in that function's
    /// docs). The threshold is read outside the lock, then the
    /// critical section is entered (no env/OnceLock reads inside the
    /// Mutex closure — the short-critical-section discipline).
    fn less_than_min_peers(&self) -> bool {
        let min = tracker_min_peers();
        self.with(|s| less_than_min_peers_of(s.peers, min))
    }
}
/// The seeding data-source adapter: store::TorrentReader ->
/// bt::peer::PieceSource (the core->{bt, store} dependency direction
/// is legal). The wire index -> disk offset goes through the face's
/// goff table (v1 = k*piece_len; v2 = v2_piece_offset; pad regions
/// are zero-filled by TorrentReader, BEP47).
pub(super) struct FaceSource {
    pub(super) reader: TorrentReader,
    pub(super) goffs: Arc<Vec<u64>>,
}

impl PieceSource for FaceSource {
    fn read_block(&self, index: u32, begin: u32, buf: &mut [u8]) -> Result<usize, String> {
        let goff = self
            .goffs
            .get(index as usize)
            .ok_or_else(|| format!("wire index {index} outside face goff table"))?;
        self.reader
            .read_at(goff + u64::from(begin), buf)
            .map_err(|e| e.to_string())
    }

    /// Batched read: adjacent segments merge into one large
    /// sequential read ([`TorrentReader::read_coalesced_bufs`] —
    /// adjacent cursors in the same file merge through the existing
    /// `coalesce_reads` logic, one handle + one read per coalesced
    /// range per file; an HDD seek win, the libtorrent
    /// `docs/manual.rst` coalesce reference). gate = None: the serve
    /// face does not yet share the write flush's IoGate quota bucket
    /// (a DiskPolicy pipeline concern; the quota wiring is deferred).
    /// A short read / addressing miss / IO error -> per-request Err
    /// (the caller rejects, legal per BEP3); an IO error inside a
    /// batch fails the whole batch (coalesced-read atomicity) —
    /// rejecting any request at any time is legal, wire behavior
    /// compatible.
    fn read_batch(
        &self,
        reqs: &[(u32, u32)],
        bufs: &mut [&mut [u8]],
    ) -> Vec<Result<usize, String>> {
        debug_assert_eq!(reqs.len(), bufs.len());
        // Addressing misses do not enter the coalesced batch (the
        // error message is verbatim-identical to read_block's).
        let mut specs: Vec<ReadSpec> = Vec::with_capacity(reqs.len());
        let mut addressed = vec![true; reqs.len()];
        let mut miss_index: Vec<Option<u32>> = vec![None; reqs.len()];
        for (i, &(index, begin)) in reqs.iter().enumerate() {
            match self.goffs.get(index as usize) {
                Some(&goff) => specs.push(ReadSpec {
                    goff: goff + u64::from(begin),
                    len: bufs[i].len(),
                }),
                None => {
                    addressed[i] = false;
                    miss_index[i] = Some(index);
                }
            }
        }
        if specs.is_empty() {
            return miss_index
                .into_iter()
                .map(|miss| match miss {
                    Some(index) => Err(format!("wire index {index} outside face goff table")),
                    None => unreachable!("specs empty ⇒ all miss"),
                })
                .collect();
        }
        let outs: Vec<&mut [u8]> = bufs.iter_mut().map(|b| &mut **b).collect();
        // Compact out the miss entries (parallel specs/outs trimming;
        // &mut is not Copy, consumed positionally).
        let mut kept_outs: Vec<&mut [u8]> = Vec::with_capacity(specs.len());
        let mut kept_at: Vec<usize> = Vec::with_capacity(specs.len());
        for (i, o) in outs.into_iter().enumerate() {
            if addressed[i] {
                kept_at.push(i);
                kept_outs.push(o);
            }
        }
        let filled = match self.reader.read_coalesced_bufs(
            &specs,
            &mut kept_outs,
            FACE_READ_COALESCE_MAX_BYTES,
            FACE_READ_COALESCE_MAX_RANGES,
            None,
        ) {
            Ok(f) => f,
            Err(e) => {
                // The whole batch errs (a missing file / unopenable
                // = unservable).
                let msg = e.to_string();
                return (0..reqs.len())
                    .map(|i| match miss_index[i] {
                        Some(index) => Err(format!("wire index {index} outside face goff table")),
                        None => Err(msg.clone()),
                    })
                    .collect();
            }
        };
        let mut results: Vec<Result<usize, String>> = Vec::with_capacity(reqs.len());
        let mut k = 0usize;
        for (i, ok) in addressed.iter().enumerate() {
            if *ok {
                let len = specs[k].len;
                let f = filled[k];
                k += 1;
                results.push(if f == len {
                    Ok(f)
                } else {
                    Err(format!(
                        "short read {f}/{len} (unallocated or out of range)"
                    ))
                });
            } else {
                let index = miss_index[i].unwrap_or_else(|| unreachable!("miss marked above"));
                results.push(Err(format!("wire index {index} outside face goff table")));
            }
        }
        results
    }

    fn total_len(&self) -> u64 {
        self.reader.layout().total()
    }
}
/// The peer connection metadata captured at registration (the
/// getPeers data source; an attach-time snapshot + per-peer
/// counters). Peer id / port / inbound flag / crypto level are
/// available at the handshake/negotiation point (outbound = the
/// `handshake_exchange` reply; inbound = `mse::accept_any`'s
/// [`taiji_bt::mse::Accepted::Accepted`]) and are handed to the main
/// loop through the registration channel.
pub(super) struct PeerMeta {
    pub(super) ip: IpAddr,
    /// The peer's TCP port (for inbound connections the semantic
    /// port = 0 in aria2's `isIncomingPeer` branch, RpcMethodImpl.cc
    /// — this side stores the real port; the snapshot layer zeroes it
    /// for inbound).
    pub(super) port: u16,
    pub(super) inbound: bool,
    pub(super) peer_id: [u8; 20],
    pub(super) crypto: CryptoLevel,
    /// The transport kind (the getPeers transport data source; a
    /// dial/accept connect-point snapshot, the tcp|utp domain).
    pub(super) transport: Transport,
    /// Per-peer session upload counters (the PeerConfig counter
    /// face; the torrent-level totals are bridged from deltas by the
    /// main loop, see [`crate::query::drain_peer_counters`]).
    pub(super) up: Arc<AtomicU64>,
    pub(super) down: Arc<AtomicU64>,
    /// The peer's BEP21 upload_only inbound mirror (the peer-profile
    /// seed flag): the seeding / partial-seeding announcement (ext
    /// handshake `upload_only=1` — "Setting the value of this key to
    /// 1 indicates that this peer is not interested in downloading
    /// anything."; a missing key / 0 = false, overwritten on every
    /// handshake). The same pipeline as up/down (assembled at transit
    /// attach: the PeerConfig write face and this profile read face
    /// share one Arc; the PeerTask-side write point =
    /// handle_extended). Consumption note: libtorrent `compare_peer`'s
    /// `finished && maybe_upload_only` candidate demotion key
    /// (peer_list.cpp, see run::ecology) needs a cross-connection
    /// address-level projection before it can enter the candidate
    /// table; this record is a connected-peer profile — the candidate
    /// key slot is documented for future adoption. Connected-peer
    /// governance (the turnover is_seed key) uses the all-ones bitmap
    /// instead (a partial seed lacks pieces and must not enter the
    /// `peer_seeds` rarity counts).
    /// (expect = the write face lives in the bt crate (PeerTask stores
    /// through the same Arc) while the read face awaits its consumer
    /// — no production read point in this crate, not dead data; the
    /// `DialSourceRank::Lsd` reserved-face pattern. The expectation is
    /// cfg-gated: the profile test reads the flag, so the lint only
    /// fires in the non-test build.)
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "written by the bt-side PeerTask via the shared Arc; no production read yet"
        )
    )]
    pub(super) upload_only: Arc<AtomicBool>,
}

/// Per-peer 10s sliding-window rate sampling (SpeedCalc.cc
/// WINDOW_TIME=10_s; the 1s seed tick feeds deltas, QueryPeers
/// reads).
pub(super) struct PeerRate {
    pub(super) up: SessionSpeedCalc,
    pub(super) down: SessionSpeedCalc,
    pub(super) last_up: u64,
    pub(super) last_down: u64,
}

/// Peer registration payload (the attach task -> the engine main
/// loop; the former four-tuple expanded).
pub(super) struct PeerRegistration {
    pub(super) face: usize,
    pub(super) cuid: u64,
    pub(super) meta: PeerMeta,
    pub(super) handle: PeerTaskHandle,
}

/// The single-peer bookkeeping row (the per-peer map merge): cuid ->
/// row. `FaceState::peer_state` replaces the previous 11 independent
/// keyed tables (faces.rs's peer_ips/peer_meta/peer_rates/
/// down_windows/last_unchoke/am_unchoked/last_opt_unchoke/
/// utp_mute_since/peer_piece/peer_extra_pieces +
/// EngineLoop.peer_registered_at) — registration and leave both land
/// here (arms.rs), and every consumer face
/// (tick/ecology/choke/query/turnover/stall/dispatch) does one hash
/// lookup with row locality instead of N lookups + 1, saving the
/// per-table node overhead of 11 HashMaps.
///
/// Two field tiers:
/// - Written at registration: `cuid`/`registered_at` (the anchor of
///   the slow-peer-eviction observation age; the former EngineLoop
///   table merged in) + `ip`/`meta`/`rates`/`down_window` (filled in
///   one shot by the registration arm — production is always Some;
///   the `Option` shape serves test fixtures with partial assembly,
///   and the consumers' `unwrap_or` fallback = the same verdict as
///   the old tables' absence);
/// - Lazily written: `last_unchoke`/`am_unchoked`/`last_opt_unchoke`/
///   `utp_mute_since`/`piece`/`extra_pieces` — zero values at
///   registration (`am_unchoked = false` = BEP3's connect default
///   choke; an empty `Vec` = no secondary pieces), with write points
///   one-to-one with the old tables.
///
/// The keyspace is unified on cuid (the old last_unchoke/am_unchoked
/// dual keyspace written/read by peers index on the seeder path is
/// dissolved by the merge — the seeder round converts the peer_cuids
/// index to cuid before landing the row, and the leave arm removes by
/// cuid so no orphan keys remain; the misread face of index keys
/// after a peer-leave shift is gone too).
pub(super) struct PeerState {
    pub(super) cuid: u64,
    /// The registration instant (the anchor of the
    /// slow-peer-eviction observation-period age; the former
    /// EngineLoop `peer_registered_at` table merged in — inserted by
    /// the registration arm, removed by the leave arm).
    pub(super) registered_at: Instant,
    /// The peer's IP (locates hash-failure attribution and ban
    /// disconnects; formerly `peer_ips`).
    pub(super) ip: Option<IpAddr>,
    /// The connection metadata (the getPeers data source; formerly
    /// `peer_meta`).
    pub(super) meta: Option<PeerMeta>,
    /// The per-peer rate sampling (deltas fed by the 1s tick;
    /// formerly `peer_rates`).
    pub(super) rates: Option<PeerRate>,
    /// The 30s download-byte window (the observation window behind
    /// the leecher sort key `download_speed`; formerly
    /// `down_windows`). Design-fixed 30s; divergence note: aria2
    /// `BtLeecherStateChoke.cc` TIME_FRAME=20s, libtorrent uses a
    /// per-round delta + 5s low-pass — this side keeps the fixed
    /// window, and the sort direction (download rate descending)
    /// matches both.
    pub(super) down_window: Option<RateWindow>,
    /// Our most recent unchoke instant toward the peer (formerly
    /// `last_unchoke`; None = never unchoked = the am_choking
    /// reading).
    pub(super) last_unchoke: Option<Instant>,
    /// Our unchoke state toward the peer (formerly `am_unchoked`;
    /// false = BEP3's connect default choke. The round-decision
    /// landing: a previous round's unchoke that loses its slot
    /// returns to choke).
    pub(super) am_unchoked: bool,
    /// The most recent optimistic-unchoke instant (formerly
    /// `last_opt_unchoke`; libtorrent mode's optimistic-choice key
    /// `last_optimistically_unchoked` ascending, the cross-round
    /// input; None = never = waiting longest, `session_impl.cpp`. The
    /// landing = the round decision's optimistic set; a preemptive
    /// pass is regular-slot semantics and does not touch this field).
    pub(super) last_opt_unchoke: Option<Instant>,
    /// The first both-directions-zero-throughput observation instant
    /// (formerly `utp_mute_since`; the uTP zero-throughput connection
    /// governance bookkeeping — decided in
    /// `run::ecology::utp_mute_step`, wired in `utp_mute_tick`,
    /// removed synchronously by the leave arm). Only uTP connections
    /// are recorded — `Transport::Tcp` zero throughput is governed by
    /// turnover/the stall valve; this field is untouched.
    pub(super) utp_mute_since: Option<Instant>,
    /// The peer's in-progress piece checkout (formerly
    /// `peer_piece`; the port of aria2 `DefaultPieceStorage.cc`
    /// getMissingPiece(peer) whole-piece checkout — the unfinished
    /// piece this peer has claimed). Consumed by the dispatch round's
    /// continue arm: while the peer still holds unfinished claimed
    /// pieces, that piece is continued instead of claiming a new one,
    /// pressing per-peer partial-piece occupancy from O(rounds) back
    /// to O(1) — the new-claim-per-round x slow-RTT-convergence
    /// partial-piece proliferation used to fill the 16MiB write
    /// cache. Entries invalidate lazily (done/blocks_sent cleared =
    /// treated as no checkout, see dispatch::own_piece_continuable);
    /// None = no claim.
    pub(super) piece: Option<u64>,
    /// The secondary-piece checkout vector (formerly
    /// `peer_extra_pieces`; cross-piece supply): pieces a fast peer
    /// picks in addition to its main checkout piece ([`Self::piece`]),
    /// appended in adjacent order (goff-contiguous chains); vector
    /// order = append scan order. The main checkout keeps priority —
    /// secondary pieces do not rewrite `piece` (the continue arm still
    /// takes main first, then secondary, per
    /// dispatch::supply_adjacent_pieces's scan order). Entries
    /// invalidate lazily like `piece` (done/`blocks_sent` cleared =
    /// returned); empty = no secondary pieces.
    pub(super) extra_pieces: Vec<u64>,
}

impl PeerState {
    /// Registration-arm row constructor: required fields filled in +
    /// lazy fields starting at zero values.
    pub(super) fn registered(cuid: u64, ip: IpAddr, meta: PeerMeta, at: Instant) -> Self {
        PeerState {
            cuid,
            registered_at: at,
            ip: Some(ip),
            meta: Some(meta),
            rates: Some(PeerRate {
                up: SessionSpeedCalc::default(),
                down: SessionSpeedCalc::default(),
                last_up: 0,
                last_down: 0,
            }),
            down_window: Some(RateWindow::new()),
            last_unchoke: None,
            am_unchoked: false,
            last_opt_unchoke: None,
            utp_mute_since: None,
            piece: None,
            extra_pieces: Vec::new(),
        }
    }

    /// Minimal row constructor (cuid + registration instant; lazy
    /// fields zero) — the bookkeeping write points' row-fetch entry
    /// (the equivalent of the old tables' insert-on-absence).
    pub(super) fn new(cuid: u64) -> Self {
        PeerState {
            cuid,
            registered_at: Instant::now(),
            ip: None,
            meta: None,
            rates: None,
            down_window: None,
            last_unchoke: None,
            am_unchoked: false,
            last_opt_unchoke: None,
            utp_mute_since: None,
            piece: None,
            extra_pieces: Vec::new(),
        }
    }
}

/// Face runtime state (held by the main loop; spec in the module
/// docs' swarm-face section).
pub(super) struct FaceState {
    pub(super) kind: FaceKind,
    pub(super) info_hash: [u8; 20],
    pub(super) reserved: Reserved,
    pub(super) addressing: Addressing,
    /// Flat piece index -> piece byte length (the last block
    /// truncated). Shared by `Arc`: beyond the dispatch face's block
    /// slicing, each connection assembly (the PeerConfig unsolicited
    /// upper-bound input) reference-counts a clone of this table,
    /// avoiding a per-connection O(piece count) copy.
    pub(super) piece_bytes: std::sync::Arc<[u64]>,
    pub(super) piece_goffs: Arc<Vec<u64>>,
    /// The verified progress model (the hash-pass basis): the
    /// advance source for HAVE/bitfield advertisement,
    /// completedLength readings, and dispatch done gating (libtorrent
    /// RC_2_1 commit `7f691246a` passed->have rename, the have half —
    /// a piece passing verification is advertised / may count into
    /// progress without waiting for the write; persistence does not
    /// use this model, see [`FaceState::written_progress`]).
    pub(super) progress: ProgressModel,
    pub(super) piece_count: usize,
    pub(super) verified_count: usize,
    pub(super) stat_man: PieceStatMan,
    /// cuid -> the peer's advertised row (bitfield/HAVE/HAVE_ALL/
    /// HAVE_NONE accumulated evidence). Bitmap-compressed: the old
    /// `Vec<bool>` cost 1 byte per piece, the bitmap row costs
    /// ceil(N/64)x8 bytes (100k pieces x 500 peers: 50MB -> 6.25MB),
    /// and holder-count / interesting checks gain the O(N/64) bit-word
    /// dividend. Row width is always piece_count (guaranteed at the
    /// write points); MSB wire conversion happens only at the
    /// dispatch::note_peer_bitfield / query::pack_bitfield boundaries.
    pub(super) peer_avail: std::collections::HashMap<u64, PieceBitmap>,
    /// The full-possession (seed) peer set (the peer-side flag of the
    /// seeding O(1) fast path: cuid in the set <=> that peer's rarity
    /// contribution goes through [`PieceStatMan::add_seed`]/
    /// `remove_seed` counters instead of per-piece counting; the row
    /// evidence (an all-ones `peer_avail` row) is still materialized
    /// for selection/dispatch). Reference: libtorrent
    /// `piece_picker.cpp` inc/dec_refcount_all's m_seeds single
    /// counter. Seed demotion (bitmap shrink) and leave revoke here.
    pub(super) peer_seeds: std::collections::HashSet<u64>,
    pub(super) peers: Vec<PeerTaskHandle>,
    pub(super) peer_cuids: Vec<u64>,
    /// cuid -> the single-peer bookkeeping row (the merge of the ten
    /// peer_ips/peer_meta/peer_rates/down_windows/last_unchoke/
    /// am_unchoked/last_opt_unchoke/utp_mute_since/peer_piece/
    /// peer_extra_pieces tables plus the former
    /// EngineLoop.peer_registered_at — field semantics / write points
    /// / lazy basis in the [`PeerState`] docs). The registration arm
    /// creates the row (arms.rs), the leave arm removes it (after the
    /// meta/rates counters are extracted); keys = cuid, unique per
    /// connection. Red lines: the `peers`/`peer_cuids` parallel order
    /// never changes (the owner-index scheme depends on it);
    /// `peer_avail` (bitmap) / `peer_seeds` / `regular_unchoked` /
    /// `parole_peers` (set semantics) are not merged in.
    pub(super) peer_state: std::collections::HashMap<u64, PeerState>,
    /// (wire piece, begin) -> sender cuid (the hash-failure
    /// attribution bookkeeping; same-coordinate re-receipt overwrites
    /// — nearly exact under single-requester dispatch, last arrival
    /// wins with endgame multi-source). Cleared on piece settle /
    /// failure ([`crate::ban::take_block_sender_map`]).
    pub(super) block_senders: BlockSenders,
    pub(super) choke: SeederChoke,
    /// The leecher-state choke (the `bt::choke::LeecherChoke` port;
    /// dual mode: the libtorrent 15s round default / the aria2
    /// fallback 10s (`BH_CHOKE_ARIA2=1` — `bt::choke::round_interval`)).
    /// Download-phase round decisions unchoke/choke.
    pub(super) leecher_choke: LeecherChoke,
    /// cuid -> the previous round's regular unchoke (the cross-round
    /// input to LeecherChoke's keep-position `regular_unchoker`
    /// partition key).
    pub(super) regular_unchoked: std::collections::HashSet<u64>,
    /// The download-phase upload-service source: a PieceSource serving
    /// only written pieces (the tit-for-tat upload face; unwritten
    /// pieces -> reject, the obligation of a fast-ext advertiser). On
    /// completion, attach_seeding_sources's full source overrides it
    /// per connection.
    pub(super) download_source: Option<Arc<dyn PieceSource>>,
    /// The written-pieces bitmap (shared with PartialFaceSource; set
    /// by the main loop's PieceWritten, initializes the restored
    /// bitmap): upload service gating = the written basis (libtorrent
    /// RC_2_1 commit `7f691246a` have->flushed rename, the flushed
    /// half — advertisement moved up to hash-pass, but serving stays
    /// bounded by the write: the local read path reads disk directly,
    /// and a verified-but-unwritten piece reads back as sparse zeros).
    /// Vec<AtomicU64> bitmap = lock-free cross-task reads.
    pub(super) written_bits: Arc<PieceBitmap>,
    /// The written progress model (the on-disk basis): the persisted
    /// bitmap's only source (v1_bitfield / v2_file_bits persistence
    /// reads this model) — this keeps the bitmap-never-leads invariant
    /// (only verified bytes are on disk): only PieceWritten (the
    /// verify->write double confirmation) advances it,
    /// verified-but-unwritten pieces stay out of the persisted bitmap,
    /// and a crash-restart treats them as unfinished (existing
    /// semantics, no fallback face).
    pub(super) written_progress: ProgressModel,
    /// The written piece count (the face-completion basis = the
    /// written basis: the seeding full source reads disk ungated, so
    /// seeding requires everything written).
    pub(super) written_count: usize,
    pub(super) completed: bool,
    /// The hash request serving file face (the v2 face; MetaHashSource
    /// built at completion).
    pub(super) hash_files: Option<Vec<MetaFile>>,
    /// The SwarmView reading snapshot (2s tick refresh; the
    /// TrackerActor announce reading source).
    pub(super) swarm: FaceView,
    /// The tracker-row attribution mirror (event-side updates).
    pub(super) mirror: TrackerMirror,
    /// The dispatch block cursor (the start block index within the
    /// rarest-selected piece).
    pub(super) block_cursor: u64,
    pub(super) block_tx: mpsc::Sender<BlockMsg>,
    /// The per-file hash tree cache (the v2 face; requester lazy
    /// fetch + block-level verification sharing).
    pub(super) trees: Option<Arc<Mutex<HashTreeCache>>>,
    /// Flat piece index -> (file_index, piece_in_file) (the log basis
    /// and lazy-fetch gate).
    pub(super) flat_coords: Arc<Vec<(u32, u32)>>,
    /// Per-file lazy-fetch state (the v2 face; index = file_index).
    pub(super) layers: Vec<FileLayerState>,
    /// The lazy-fetch event return channel (watcher -> main loop).
    pub(super) fetch_tx: mpsc::Sender<(usize, usize, HashFetchEvent)>,
    /// The single-block refetch queue (BlockRejected -> dispatch;
    /// deduped).
    pub(super) refetch: Vec<(u32, u32, u32)>,
    /// In-flight / buffered block bookkeeping (a fixed-width row
    /// keyed inline: flat piece index -> a [`PieceSentLedger`] row —
    /// 8B per block slot (1B state + the owner peer index), 16 blocks
    /// = 128B per piece row, replacing the old `HashMap<u32,
    /// BlockSentState>` + global `block_dispatch` two-table form; the
    /// hot path fetches the row once and indexes it directly, and
    /// ownership queries skip the cuid->position linear scan).
    /// Two-phase semantics: the `InFlight` family = the network
    /// segment (sent, not yet pipeline-confirmed; re-dispatched past
    /// the adaptive reissue window — prevents a stuck store from
    /// starving the download); the `Settling` family = the store
    /// segment (block bytes arrived, awaiting pipeline confirmation;
    /// past [`crate::dispatch::STORE_PENDING_GUARD`] only warn +
    /// count, never re-dispatched — zero wire additions); `Buffered`
    /// = bytes in the write cache (re-dispatch is pointless, kept
    /// skipped until piece settle / reject). A piece passing
    /// verification or being dropped clears the whole piece. The
    /// arrival transition = `InFlight -> Settling` (transit emits ->
    /// main-loop arrival arm, [`crate::dispatch::on_block_arrived`];
    /// with the switch off `Settling` is unreachable = the old
    /// single-state basis, see [`crate::dispatch::two_phase_ledger`]).
    /// Block ownership (formerly the `block_dispatch` evidence face:
    /// on hash-failure bans, did we request this block from this peer)
    /// is inlined as the slot owner (a peer_cuids index; a peer
    /// leave's index shift is repaired by
    /// [`PieceSentLedger::reindex_owners`], wired in
    /// `crate::run::arms::handle_peer_left`); ownership lives across
    /// segments with the block lifecycle (network -> store) — shared
    /// by the reissue-window reading
    /// ([`crate::dispatch::block_reissue_window`]) and guard-warn
    /// attribution, semantics unchanged. The piece-level shared
    /// timestamp approximation is noted in the [`PieceSentLedger`]
    /// docs.
    pub(super) blocks_sent: std::collections::HashMap<u64, PieceSentLedger>,
    /// The face-level block arena: the shared rental source for wire
    /// decoding (passed through PeerConfig to the connection) and
    /// cache cells (passed through StoreJob to the pipeline); None =
    /// fall back to direct allocation (`BH_BLOCK_ARENA=0`).
    pub(super) block_arena: Option<Arc<taiji_io::block_arena::BlockArena>>,
    /// (The piece checkout / secondary-piece bookkeeping merged into
    /// [`Self::peer_state`]'s `piece`/`extra_pieces` fields — the
    /// semantics and lazy-invalidation notes moved there.)
    /// Dispatch-round scratch: a pooled reuse home for each round's
    /// transient buffers — the done bitmap / ClaimedSet bitmap /
    /// endgame aux tables (round_copies etc.), taken out at the start
    /// of [`crate::dispatch::dispatch_face_selected_with_stream`] and
    /// put back at round end (capacity only grows; after the first
    /// allocation later rounds are zero-alloc). Single writer on the
    /// dispatch path (the engine main loop), no concurrency face.
    pub(super) dispatch_scratch: crate::dispatch::DispatchScratch,
    /// PEX outbound-candidate bookkeeping: outbound connections and
    /// leaves within a 60s window — the window projection of aria2
    /// `peerStorage` getUsedPeers/getDroppedPeers; the tick pushes a
    /// dirty `SetPexCandidates` snapshot (a structure independent of
    /// FaceState so pure functions are unit-testable).
    pub(super) pex_candidates: PexCandidates,
    /// Dispatch replies: the reply receivers of every enqueued
    /// request command, along with their (wire piece, begin)
    /// coordinates, drained at the top of
    /// [`crate::dispatch::dispatch_face`] via try_recv — WindowFull /
    /// peer exit = the request never entered the peer's RequestBook,
    /// so the in-flight mark is released immediately and the block
    /// re-enters the refetch queue (the old fire-and-forget phantom
    /// in-flight waited out the full 2s reissue window, starving
    /// supply); Ok = entered the peer's bookkeeping, the mark awaits
    /// the store-pipeline confirmation. Capacity bound = the per-peer
    /// in-flight requests (<= the peer window 256), no leak.
    pub(super) dispatch_replies: Vec<DispatchReply>,
    /// The endgame live flag (observation only, zero behavior change
    /// — dispatch semantics untouched): dispatch flips it on
    /// enter/exit edges, and the store pipeline reads it to split the
    /// duplicate / buffered block counts during the trigger period (an
    /// Arc shared across tasks — the pipeline task and the main loop
    /// are two tasks; lock-free single writer: only dispatch edges
    /// write, the pipeline reads).
    pub(super) endgame_live: Arc<std::sync::atomic::AtomicBool>,
    /// The endgame in-segment edge instant (registered at the enter
    /// edge; the 1s seed tick and the final flush slice it into
    /// `endgame_cum` via [`crate::run::tick::checkpoint_endgame`] —
    /// the last segment is not lost when the engine shuts down
    /// mid-endgame).
    pub(super) endgame_edge: Option<Instant>,
    /// The endgame duration-slice accumulation (un-fed in-flight
    /// stock; a non-zero checkpoint is fed whole into
    /// `SessionMetrics::note_endgame_elapsed` and cleared).
    pub(super) endgame_cum: Duration,
    /// The last-mile enter edge (observation only, zero behavior):
    /// the first instant missing pieces drop to <=
    /// `BH_ENDGAME_LASTMILE` (N), registered by the dispatch round
    /// (zero missing does not enter); with the N=0 fallback this stays
    /// None — the gate never triggers, no tail readings
    /// (self-consistent).
    pub(super) last_mile_edge: Option<Instant>,
    /// The last-mile final value (completion instant - enter edge;
    /// booked once by the face completion check
    /// [`recheck_face_completion`], bridged via checkpoint into
    /// `SessionMetrics::last_mile_ms_total`). None = never entered /
    /// finished.
    pub(super) last_mile_final: Option<Duration>,
    /// The last-8-pieces window enter edge (as above; missing pieces
    /// first <= 8 — a fixed tail window independent of N).
    pub(super) last8_edge: Option<Instant>,
    /// The last-8-pieces window final value (completion - enter
    /// edge; booked/bridged as above).
    pub(super) last8_final: Option<Duration>,
    /// Per-piece endgame-tail deadlines (tail-gated —
    /// maintained only while the tail is active and
    /// `BH_ENDGAME_PIECE_DEADLINE_SECS` > 0): busy missing piece ->
    /// the **supply-movement anchor** (the piece's first observation
    /// with a [`crate::dispatch::PieceSentLedger`] row in a tail round;
    /// re-anchored on each deadline-driven re-dispatch). A piece whose
    /// anchor is older than the deadline is "overdue" — its whole
    /// network-phase in-flight set becomes takeover candidates in the
    /// dispatch round (the anti-mask face for the piece-level shared
    /// timestamp; see
    /// [`crate::dispatch::endgame_piece_overdue`]). Swept by the
    /// dispatch round (entries for pieces no longer busy-and-missing
    /// drop).
    pub(super) endgame_deadline: std::collections::HashMap<u64, Instant>,
    /// The write-locality observation (observation only, zero
    /// behavior): of pieces written to disk, how many had index +/-1
    /// already written (inside the read-ahead run). A face-level
    /// cumulative stock, bridged by
    /// [`crate::run::tick::checkpoint_endgame`] (take-and-reset, the
    /// `endgame_cum` shape) into `SessionMetrics`. Fed at the
    /// [`on_piece_written`] first-time arm.
    pub(super) write_adjacent: u64,
    /// The isolated arm of the same observation: pieces written with
    /// neither index-1 nor index+1 written (the first piece / a
    /// jumped-to piece). The two counters sum to the total written
    /// pieces (the first-time-arm basis).
    pub(super) write_isolated: u64,
    /// The face-level read pool: the serve read service shared by all
    /// of the face's connections (a spawn_blocking dispatcher +
    /// in-order reply injection, see taiji_bt::peer::ReadPool).
    /// Always Some at construction (production); test fixtures may
    /// use None (the inline form).
    pub(super) read_pool: Option<Arc<taiji_bt::peer::ReadPool>>,
    /// The parole suspect set (cuid-keyed; the port of the
    /// libtorrent `torrent.cpp` parole chain): peers involved with a
    /// hash-failed piece enter the suspect state — the dispatch round
    /// claims only unowned whole pieces (unambiguous attribution) and
    /// endgame busy is forbidden (repeat-copy rounds excluded, the
    /// unattributable bad-block shape). A passing piece clears it
    /// (that peer's blocks delivered that cycle digest-matched good
    /// data = suspicion dissolved); a peer leaving clears it (cuids
    /// are never reused, keeping the set bounded). Read by the
    /// dispatch gate, written by main-loop event arms — the
    /// single-writer discipline (dispatch is a pure read face). With
    /// `BH_SMART_BAN_PAROLE=0` the set stays empty (the write-side
    /// gate).
    pub(super) parole_peers: std::collections::HashSet<u64>,
    /// The block in-flight pre-registration count (the observation
    /// face of the data-plane bypass): +1 when the direct sink
    /// delivers into the face channel, -1 when the store pipeline's
    /// batch confirm settles — the handed-to-pipeline-not-yet-
    /// confirmed waterline (~ the face channel occupancy + the in-
    /// batch in-flight). Observation only (metrics/snapshot
    /// readings), never part of dispatch/choke decisions — the bypass
    /// owns no decision state; decision consumption belongs to the
    /// regular bookkeeping faces.
    pub(super) block_inflight: Arc<AtomicU64>,
    /// The final data-flush trigger end: engine shutdown (run/tail.rs
    /// `final_flush`) requests this face's store pipeline into its
    /// final wrap-up (drain in-flight jobs -> data file fsync ->
    /// barrier set). The payload is empty (the result travels the
    /// barrier watch; single sender = engine shutdown, capacity 1
    /// suffices).
    pub(super) final_flush_tx: mpsc::Sender<()>,
    /// The data-flush barrier read end: before the final progress row
    /// is persisted, wait for the face-wide `Flushed` (data fsync
    /// first, progress row upsert after — the invariant chain is in
    /// the pipeline::DataFlushState docs).
    pub(super) data_flush_gate: tokio::sync::watch::Receiver<DataFlushState>,
    /// The snapshot write barrier: whether this face's written bitmap
    /// has advanced since the last successful snapshot (set by
    /// [`on_piece_written`] — including cross-face propagation, since
    /// a hybrid pair shares one dest and one write advances both face
    /// models at the same instant; cleared after `autosave_snapshot`'s
    /// fsync + persist succeed). Always false at restore: the restored
    /// bitmap comes from a previous session's barrier-cleared row, the
    /// bytes were on disk then. Main-loop single writer (event arms
    /// set, the seed tick clears, same task) — a plain bool suffices.
    pub(super) dirty_since_snapshot: bool,
    /// The snapshot write barrier fsync face (the write-handle cell
    /// shared with the store pipeline; why a handle is delivered
    /// instead of a pipeline arm is in the pipeline::SnapshotSyncCell
    /// docs).
    pub(super) snapshot_sync: crate::pipeline::SnapshotSyncCell,
}

/// The face's transport-composition supply reading (observation; for
/// endgame edge logs and diagnostics): `(tcp_down, utp_down,
/// tcp_conns, utp_conns)`. Bytes = each peer's wire receive total
/// (`PeerMeta::down` — counted on receipt, redundant duplicates
/// included), summed per the registration-time `PeerMeta::transport`.
pub(super) fn face_transport_supply(face: &FaceState) -> (u64, u64, u64, u64) {
    use std::sync::atomic::Ordering;
    let mut tcp_down = 0u64;
    let mut utp_down = 0u64;
    let mut tcp_conns = 0u64;
    let mut utp_conns = 0u64;
    for ps in face.peer_state.values() {
        let Some(meta) = ps.meta.as_ref() else {
            continue;
        };
        let d = meta.down.load(Ordering::Relaxed);
        match meta.transport {
            Transport::Tcp => {
                tcp_down += d;
                tcp_conns += 1;
            }
            Transport::Utp => {
                utp_down += d;
                utp_conns += 1;
            }
        }
    }
    (tcp_down, utp_down, tcp_conns, utp_conns)
}

impl FaceState {
    /// cuid row fetch-or-create (the shared bookkeeping write-point
    /// entry): a missing key creates the minimal row
    /// (`PeerState::new`) — the equivalent of the old tables'
    /// insert-on-absence; the registration arm creates rows first in
    /// production, so this entry normally creates nothing.
    pub(super) fn peer_state_row(&mut self, cuid: u64) -> &mut PeerState {
        let row = self
            .peer_state
            .entry(cuid)
            .or_insert_with(|| PeerState::new(cuid));
        // Row key self-consistency (a debug-build invariant; zero
        // cost in release).
        debug_assert_eq!(row.cuid, cuid, "peer_state row key/cuid mismatch");
        row
    }
    /// The verified-basis synthesized bitmap (the wire advertisement
    /// face: the registration arm's SendBitfield and RPC query
    /// readings — hash-passed pieces are advertised, matching the HAVE
    /// broadcast moment; libtorrent RC_2_1 commit `7f691246a`
    /// passed->have). The persisted bitmap goes through
    /// [`Self::written_bitfield_bytes`].
    pub(super) fn bitfield_bytes(&self) -> Vec<u8> {
        let (packed, _) = self.progress.synthesized_bitfield();
        packed
    }

    /// The written-basis synthesized bitmap (the persistence face:
    /// the v1_bitfield's only source — the bitmap-never-leads
    /// invariant: only verified bytes are on disk, so only verify+write
    /// double-confirmed pieces are recorded).
    pub(super) fn written_bitfield_bytes(&self) -> Vec<u8> {
        let (packed, _) = self.written_progress.synthesized_bitfield();
        packed
    }

    /// The block direct-delivery seam factory: switch on -> mint a
    /// [`FaceBlockSink`] per connection (captures the addressing /
    /// attribution bookkeeping / the face channel / the
    /// pre-registration counter — a per-connection instance with cuid
    /// attribution); off -> `None` (the bt side falls back to the old
    /// `data_tx` path, zero behavior change). Read at attach assembly
    /// (the outbound DialJob / inbound accept snapshot), never on the
    /// block hot path.
    pub(super) fn block_sink_for(&self, cuid: u64) -> Option<Arc<dyn taiji_bt::peer::BlockSink>> {
        if !super::block_bypass_enabled() {
            return None;
        }
        Some(Arc::new(super::transit::FaceBlockSink {
            addressing: self.addressing.clone(),
            cuid,
            block_senders: Arc::clone(&self.block_senders),
            block_tx: self.block_tx.clone(),
            inflight: Arc::clone(&self.block_inflight),
        }))
    }
}

/// PEX outbound-candidate bookkeeping — three pure-function faces,
/// unit-test driven ([`tests`]).
///
/// The session-side projection of aria2 `PeerStorage`'s PEX view:
/// fresh = outbound connections within the window (the local shape of
/// getUsedPeers INTERSECT isActive), dropped = outbound connections
/// that left within the same window (getDroppedPeers); window pruning
/// happens uniformly at snapshot projection. The seeder flag = false:
/// the engine has no per-peer completeness reading, and the BEP11
/// flags is an optional hint bit (0x00 = not a known seeder; the bit
/// face is frozen by the codec, `UTPexExtensionMessage.cc`).
#[derive(Default)]
pub(super) struct PexCandidates {
    /// Outbound connections within the window (cuid, addr,
    /// first_contact) (the addFreshPeer admission precondition: only
    /// outbound connections are booked, `UTPexExtensionMessage.cc`).
    pub(super) fresh: Vec<(u64, SocketAddr, Instant)>,
    /// Outbound connections that left within the same window (addr,
    /// drop start).
    pub(super) dropped: Vec<(SocketAddr, Instant)>,
    /// The dirty flag (set by reg/leave; cleared after the tick
    /// pushes [`taiji_bt::peer::PeerCommand::SetPexCandidates`]).
    pub(super) dirty: bool,
}

/// Outbound registration -> a fresh record (inbound is not booked; a
/// re-registration with the same cuid overwrites the old entry).
pub(super) fn pex_note_registered(
    cands: &mut PexCandidates,
    cuid: u64,
    addr: SocketAddr,
    inbound: bool,
    now: Instant,
) {
    if inbound {
        return;
    }
    cands.fresh.retain(|(c, _, _)| *c != cuid);
    cands.fresh.push((cuid, addr, now));
    cands.dirty = true;
}

/// Peer left: remove from fresh (by cuid); if it was an outbound
/// connection -> a dropped record (an old dropped entry for the same
/// address is overwritten — the same dedup as aria2's dropped list).
pub(super) fn pex_note_left(cands: &mut PexCandidates, cuid: u64, now: Instant) {
    let Some(pos) = cands.fresh.iter().position(|(c, _, _)| *c == cuid) else {
        return;
    };
    let (_, addr, _) = cands.fresh.remove(pos);
    cands.dropped.retain(|(a, _)| *a != addr);
    cands.dropped.push((addr, now));
    cands.dirty = true;
}

/// Candidate snapshot projection: prune out-of-window entries and
/// map to [`taiji_bt::pex::PexCandidate`] (fresh: active=true +
/// first_contact; dropped: drop_started = the leave instant).
pub(super) fn pex_snapshot(
    cands: &mut PexCandidates,
    now: Instant,
) -> (
    Vec<taiji_bt::pex::PexCandidate>,
    Vec<taiji_bt::pex::PexCandidate>,
) {
    let window = taiji_bt::pex::DEFAULT_INTERVAL;
    cands
        .fresh
        .retain(|(_, _, at)| now.saturating_duration_since(*at) < window);
    cands
        .dropped
        .retain(|(_, at)| now.saturating_duration_since(*at) < window);
    let fresh = cands
        .fresh
        .iter()
        .map(|(_, addr, at)| {
            taiji_bt::pex::PexCandidate::fresh(
                taiji_bt::pex::PexPeer::new(*addr, taiji_bt::pex::UploadOnly::No),
                *at,
            )
        })
        .collect();
    let dropped = cands
        .dropped
        .iter()
        .map(|(addr, at)| {
            taiji_bt::pex::PexCandidate::dropped(
                taiji_bt::pex::PexPeer::new(*addr, taiji_bt::pex::UploadOnly::No),
                *at,
            )
        })
        .collect();
    (fresh, dropped)
}
/// xorshift64 state (the PieceStatMan startup shuffle; the same
/// family as aria2 `PieceStatMan`).
pub(super) struct XorShift(pub(super) u64);

/// Seeding-source attachment after all pieces complete (shared by the
/// online-completion path and the restore-as-complete path): build
/// the face's FaceSource (goff table = wire index -> disk offset) +
/// the v2 face's MetaHashSource (the hash request service), mount
/// them into the seeding slots, and push to connected peers (later
/// connections get them through DialJob's initial_source slot).
pub(super) fn attach_seeding_sources(
    faces: &mut [FaceState],
    seeding_sources: &mut [Option<Arc<dyn PieceSource>>],
    seeding_hash_sources: &mut [Option<Arc<dyn HashSource>>],
    layout: &Layout,
    dest: &std::path::Path,
    piece_len: u32,
) {
    for (fi, f) in faces.iter_mut().enumerate() {
        let src: Arc<dyn PieceSource> = Arc::new(FaceSource {
            // The read-side handle pool: open drops from
            // O(requests) to O(active files) (the aria2
            // `--bt-max-open-files` 100 default basis; see the
            // READER_MAX_OPEN_HANDLES note).
            reader: TorrentReader::with_handle_pool(
                layout.clone(),
                dest.to_path_buf(),
                READER_MAX_OPEN_HANDLES,
            ),
            goffs: f.piece_goffs.clone(),
        });
        seeding_sources[fi] = Some(src.clone());
        for p in &f.peers {
            let _ = p.command(taiji_bt::peer::PeerCommand::AttachSource(src.clone()));
        }
        if let Some(files) = f.hash_files.clone() {
            let hs: Arc<dyn HashSource> = Arc::new(taiji_domain::hash_source::MetaHashSource::new(
                files,
                TorrentReader::new(layout.clone(), dest.to_path_buf()),
                piece_len,
            ));
            seeding_hash_sources[fi] = Some(hs.clone());
            for p in &f.peers {
                let _ = p.command(taiji_bt::peer::PeerCommand::AttachHashSource(hs.clone()));
            }
        }
    }
}

/// Download-state memory release at seeding entry (the completion
/// counterpart of [`attach_seeding_sources`], shared by both completion
/// paths): a face that finished downloading needs none of the
/// download-phase block working set, so every face's block-arena idle
/// pages go back to the OS ([`BlockArena::release_idle`]; the
/// wire-decode and write-cache cell buffers all lease from the same
/// face arena and are back on the free list by the written-everywhere
/// completion point). Seeding keeps what it actually uses: the hash
/// tables/bitmaps/ledgers (engine-side, untouched here), the connection
/// write buffers, and the read-service buffer pool (its own 64-block
/// pool, not the arena). Returns the total bytes handed back
/// (observability face of the memory release; 0 on platforms without a
/// page-return madvise).
pub(super) fn release_download_state(faces: &[FaceState]) -> u64 {
    let mut released = 0u64;
    for (fi, f) in faces.iter().enumerate() {
        if let Some(arena) = &f.block_arena {
            let face_released = arena.release_idle();
            if face_released > 0 {
                tracing::info!(
                    target: "taiji::core::engine",
                    face = fi,
                    bytes = face_released,
                    "download complete: idle block-arena pages released to OS"
                );
            }
            released += face_released;
        }
    }
    released
}

impl XorShift {
    pub(super) fn next(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}
/// Piece verification completion (at the hash-pass moment, before the
/// disk write): face marking + HAVE broadcast + cross-face
/// propagation (a hybrid pair shares one piece space).
///
/// Semantics = libtorrent RC_2_1 commit `7f691246a`'s passed->have
/// rename: a piece passing hash verification is advertised (HAVE) /
/// may count into progress immediately, without waiting for the write
/// — under a slow disk, peers need not wait for the write to start
/// requesting other pieces / trading theirs, fixing the pipeline
/// stall of advertise-only-after-the-write. Upload service does not
/// unlock with this event (`PartialFaceSource` consults the written
/// bitmap; the write face is [`on_piece_written`]); face completion
/// is not triggered by this event either (the seeding full source
/// reads disk ungated; everything must be written —
/// [`on_piece_written`]).
pub(super) fn on_piece_verified(faces: &mut [FaceState], fi: usize, index: u64) {
    let count = faces[fi].piece_count;
    {
        let face = &mut faces[fi];
        // Piece settled: clear the in-flight block bookkeeping (later
        // late blocks for the same piece are authoritatively dropped
        // store-side).
        face.blocks_sent.remove(&index);
        if !face.progress.set_piece_done_global(index) {
            debug!(target: "taiji::core::engine", face = fi, index,
                "duplicate verified event (store pipeline authoritative)");
        } else {
            face.verified_count += 1;
            // Per-piece verified logs are forensic-grade noise, not
            // product-grade logging (per-piece write amplification +
            // tracing formatting cost) — demoted to debug! by default
            // (under an INFO filter the macro arguments are not
            // evaluated = zero cost); BH_QUIET_PIECE_LOG=0 restores
            // the old INFO behavior. The two arms' field sets are
            // identical; parse registration in `taiji_io::knobs` (a
            // process-level OnceLock).
            if taiji_io::knobs::quiet_piece_log() {
                debug!(target: "taiji::core::engine", face = fi, index,
                    done = face.verified_count, total = face.piece_count,
                    "piece verified (advertise at hash-pass, write in flight)");
            } else {
                info!(target: "taiji::core::engine", face = fi, index,
                    done = face.verified_count, total = face.piece_count,
                    "piece verified (advertise at hash-pass, write in flight)");
            }
        }
    }
    // Cross-face propagation: the BEP52 alignment mapping means both
    // faces have equal piece counts and identical coordinates (k <->
    // k); one face verifying a piece exempts the other from
    // re-downloading the same k.
    for (oi, other) in faces.iter_mut().enumerate() {
        if oi == fi || other.piece_count != count {
            continue;
        }
        other.blocks_sent.remove(&index);
        if other.progress.set_piece_done_global(index) {
            other.verified_count += 1;
            debug!(target: "taiji::core::engine", face = oi, index,
                "cross-face completion propagated");
        }
    }
    // HAVE broadcast: coordinates mean the same thing in both faces
    // (k); every peer must learn (broadcast at hash-pass — this
    // function is the early-advertisement point).
    for f in faces.iter() {
        for p in &f.peers {
            let _ = p.command(taiji_bt::peer::PeerCommand::SendHave {
                index: u32::try_from(index).unwrap_or(u32::MAX),
            });
        }
    }
}

/// Piece write completion (at the write-commit moment): the written
/// bitmap / persistence model advance + per-face completion checks.
/// Returns whether all faces are complete (the written basis).
///
/// Semantics = libtorrent RC_2_1 commit `7f691246a`'s have->flushed
/// rename, the flushed half: upload service gating
/// (`PartialFaceSource` written bits) and the persisted bitmap
/// (verify+write double confirmation, the bitmap-never-leads
/// invariant — only verified bytes are on disk) are bounded by this
/// event; the seeding full source reads disk ungated, and face
/// completion (entering the seeding state / EngineEnd::Completed,
/// verified and written) follows only this event.
pub(super) fn on_piece_written(
    faces: &mut [FaceState],
    fi: usize,
    index: u64,
    required: &[usize],
) -> bool {
    let count = faces[fi].piece_count;
    {
        let face = &mut faces[fi];
        // Set the written bitmap (the point where PartialFaceSource's
        // upload service gate lifts).
        face.written_bits.set(index as usize);
        // Dirty mark: the written model is about to advance, so the
        // data fsync barrier must pass before the next bitmap row
        // (consumed by autosave_snapshot; set before the model
        // advances — better one extra fsync than a missed one).
        face.dirty_since_snapshot = true;
        if !face.written_progress.set_piece_done_global(index) {
            debug!(target: "taiji::core::engine", face = fi, index,
                "duplicate written event (store pipeline authoritative)");
        } else {
            face.written_count += 1;
            // Write locality (observation only): index +/-1 already
            // written at write time = adjacent (a goff-contiguous
            // run, read-ahead friendly), otherwise isolated (the
            // first piece / a jumped-to piece). Counted at the first-
            // time arm (duplicate written events do not double count);
            // the cross-face propagation arm does not count (one
            // write, one count).
            let idx = index as usize;
            let adjacent = (idx > 0 && face.written_bits.get(idx - 1))
                || (idx + 1 < face.piece_count && face.written_bits.get(idx + 1));
            if adjacent {
                face.write_adjacent += 1;
            } else {
                face.write_isolated += 1;
            }
            debug!(target: "taiji::core::engine", face = fi, index,
                written = face.written_count, total = face.piece_count,
                "piece written");
        }
    }
    // Cross-face propagation: a written bit is a disk fact (both
    // faces write the same dest), so under the BEP52 alignment one
    // write is effective for both faces.
    for (oi, other) in faces.iter_mut().enumerate() {
        if oi == fi || other.piece_count != count {
            continue;
        }
        other.written_bits.set(index as usize);
        // The dirty mark is set with cross-face propagation too (one
        // write advances both face models).
        other.dirty_since_snapshot = true;
        if other.written_progress.set_piece_done_global(index) {
            other.written_count += 1;
        }
    }
    // Completion check = the written basis (the single source of
    // truth, [`recheck_face_completion`]).
    recheck_face_completion(faces, required)
}

/// Face completion recheck (the ONLY completion criterion, the
/// written basis): `!completed && written_count >= need` ->
/// completed. Returns whether all faces are complete. Call sites:
/// [`on_piece_written`] (each piece written), the SetFileSelection
/// command arm (a mask landing later than the restore / in-download
/// recheck), and the main loop's startup pre-loop
/// (restore-as-complete).
///
/// The criterion reads ONLY `written_count` (the written count) —
/// verified (hash-pass) counts do not participate: hash-pass
/// increments verified while only the write advances written_count
/// (`on_piece_verified` / `on_piece_written`), so a face with
/// selected pieces verified-but-unwritten must not complete (the
/// seeding full source reads disk ungated / EngineEnd::Completed
/// means verified and written). `need` = the piece count a face
/// needs to complete (BEP53 select-file: with a mask active = the
/// piece count inside the mask, unselected pieces do not count
/// toward completion; the all-selected semantics = piece_count,
/// maintained by the caller).
pub(super) fn recheck_face_completion(faces: &mut [FaceState], required: &[usize]) -> bool {
    let mut all = true;
    for (fi, f) in faces.iter_mut().enumerate() {
        let need = required.get(fi).copied().unwrap_or(f.piece_count);
        if !f.completed && f.written_count >= need {
            f.completed = true;
            // On completion release the dispatch-round scratch (the
            // grow-only endgame working set) and the stat_man bucket
            // view — selection no longer runs during seeding, so the
            // resident capacity is pure waste; re-taking it (re-
            // dispatch after recheck) self-heals via lazy rebuild.
            f.dispatch_scratch = crate::dispatch::DispatchScratch::default();
            f.stat_man.release_bucket_view();
            // Tail-segment final values (observation only, one shot —
            // completed is one-way so the booking happens once): the
            // enter-edge -> completion-instant durations for last-mile
            // / the last-8 window. The completion check itself is
            // untouched (the written basis, the single source of
            // truth).
            let now = Instant::now();
            if f.last_mile_final.is_none() {
                f.last_mile_final = f.last_mile_edge.map(|t| now - t);
            }
            if f.last8_final.is_none() {
                f.last8_final = f.last8_edge.map(|t| now - t);
            }
            info!(target: "taiji::core::engine", kind = ?f.kind, "face complete");
        }
        if !f.completed {
            all = false;
        }
    }
    all
}

#[cfg(test)]
mod numwant_gate_tests {
    use super::*;

    /// numwant gate decision table: registered in {39, 55, 99, 100} x
    /// the new/old thresholds — the slow-window stall band 55-99 must
    /// request peers (numwant=DEFAULT_NUMWANT); the =40 fallback arm
    /// (BH_TRACKER_MIN_PEERS=40) restores the old aria2 behavior.
    #[test]
    fn less_than_min_peers_decision_table() {
        // New threshold (the default = the outbound-target reading
        // 100).
        for &registered in &[39usize, 55, 99] {
            assert!(
                less_than_min_peers_of(registered, 100),
                "registered={registered} < 100 -> request peers (numwant=50)"
            );
        }
        assert!(
            !less_than_min_peers_of(100, 100),
            "registered=100 = target met -> numwant=0 (same verdict for the halt/full stall surface)"
        );
        // Old-threshold fallback arm (the aria2 40).
        assert!(
            less_than_min_peers_of(39, 40),
            "old behavior: 39 < 40 requests peers"
        );
        for &registered in &[55usize, 99, 100] {
            assert!(
                !less_than_min_peers_of(registered, 40),
                "old behavior: registered={registered} >= 40 -> numwant=0 (slow-window disqualified surface)"
            );
        }
    }

    /// FaceView runtime reading (the same-source coupling lock):
    /// under default env the gate threshold = the
    /// [`crate::run::peer_connections_target`] reading (100), and the
    /// snapshot peers go through [`FaceView::less_than_min_peers`].
    #[test]
    fn face_view_gate_reads_target_by_default() {
        // env is process-immutable (no set_var face): the test
        // process sets neither BH_TRACKER_MIN_PEERS/BH_PEER_TARGET,
        // so the default chain tracker_min_peers() =
        // peer_connections_target() = 100.
        assert_eq!(tracker_min_peers(), crate::run::peer_connections_target());
        assert_eq!(tracker_min_peers(), 100);
        let view = |peers: usize| {
            FaceView(std::sync::Arc::new(std::sync::Mutex::new(SwarmSnapshot {
                total: 0,
                completed: 0,
                all_finished: false,
                peers,
                uploaded: 0,
                downloaded: 0,
            })))
        };
        // The slow-window stall band 55-99: the gate is open (the
        // tracker keeps supplying peers).
        assert!(view(55).less_than_min_peers());
        assert!(view(99).less_than_min_peers());
        // At the 100 target: the gate is closed (numwant=0).
        assert!(!view(100).less_than_min_peers());
        // The old-disqualification regression anchor: the 40-100 band
        // is closed under the old threshold, open under the new.
        assert!(view(65).less_than_min_peers());
    }
}

#[cfg(test)]
mod read_batch_tests {
    use super::*;
    use std::path::PathBuf;
    use taiji_store::disk::DiskWriter;
    use taiji_store::layout::PlanEntry;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "taiji-fs-rb-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const PIECE_LEN: u32 = 16384;

    /// hybrid fixture same-shape layout: a.bin 70000 -> pad 11920 ->
    /// b.bin 30000 (total 111920 = 7 pieces x 16384 truncated; the
    /// v1 flat goff table = k*16384).
    fn fixture(tag: &str) -> (TempDir, FaceSource) {
        let tmp = TempDir::new(tag);
        let entries = vec![
            PlanEntry {
                path: PathBuf::from("a.bin"),
                length: 70000,
                padding: false,
            },
            PlanEntry {
                path: PathBuf::from(".pad/11920"),
                length: 11920,
                padding: true,
            },
            PlanEntry {
                path: PathBuf::from("b.bin"),
                length: 30000,
                padding: false,
            },
        ];
        let layout = Layout::plan_v1_padded(&entries, PIECE_LEN).unwrap_or_else(|e| panic!("{e}"));
        let mut w =
            taiji_store::torrent_writer::TorrentWriter::new(layout.clone(), tmp.0.clone(), 8);
        w.allocate().unwrap_or_else(|e| panic!("{e}"));
        let mut stream = Vec::new();
        stream.extend((0..70000u32).map(|i| (i % 251) as u8));
        stream.extend(std::iter::repeat_n(0u8, 11920));
        stream.extend((0..30000u32).map(|i| (i % 253) as u8));
        w.write_at(0, &stream).unwrap_or_else(|e| panic!("{e}"));
        let goffs: Arc<Vec<u64>> = Arc::new((0..7u64).map(|k| k * 16384).collect());
        let src = FaceSource {
            // Pooled reader (the same construction as the read-side
            // wiring).
            reader: TorrentReader::with_handle_pool(layout, tmp.0.clone(), 8),
            goffs,
        };
        (tmp, src)
    }

    /// FaceSource::read_batch: the coalesced read is byte-identical
    /// to per-segment read_block (including segments crossing a.bin
    /// tail -> pad -> b.bin head); addressing misses match
    /// read_block's error messages; an EOF-past-total segment =
    /// reject-equivalent (read_block Ok(short) / batch Err(short
    /// read) — both reject at the serve face).
    #[test]
    fn face_source_read_batch_matches_per_block_reads() {
        let (_tmp, src) = fixture("rb");
        let reqs: Vec<(u32, u32)> = vec![
            (0, 0),    // a.bin head
            (1, 0),    // adjacent segment (goff 16384)
            (3, 4096), // a.bin middle (goff 53248)
            (4, 0),    // a.bin tail + full pad + b.bin head (goff 65536)
            (9, 0),    // addressing miss (the goff table has 7 entries)
            (6, 0),    // EOF short read past total (goff 98304 + 16384 > 111920)
        ];
        let lens = [16384usize, 16384, 16384, 16384, 1024, 16384];
        let mut bufs: Vec<Vec<u8>> = lens.iter().map(|&l| vec![0u8; l]).collect();
        {
            let mut refs: Vec<&mut [u8]> = bufs.iter_mut().map(|v| v.as_mut_slice()).collect();
            let got = src.read_batch(&reqs, &mut refs);
            // (1) Adjacent / pad-crossing segments match per-segment
            // read_block byte for byte.
            for i in 0..4 {
                let (index, begin) = reqs[i];
                let mut expect = vec![0u8; lens[i]];
                let n = src
                    .read_block(index, begin, &mut expect)
                    .unwrap_or_else(|e| panic!("read_block {index}: {e}"));
                assert_eq!(n, lens[i]);
                match &got[i] {
                    Ok(f) => assert_eq!(f, &lens[i], "spec {i} fully filled"),
                    other => panic!("spec {i} should succeed, got {other:?}"),
                }
                assert_eq!(bufs[i], expect, "spec {i} bytes identical");
            }
            // (2) Addressing miss: the error message matches
            // read_block verbatim.
            let miss_expect = match src.read_block(9, 0, &mut []) {
                Err(e) => e,
                Ok(_) => panic!("miss index must be Err"),
            };
            let got_miss = match &got[4] {
                Err(e) => e.clone(),
                Ok(_) => panic!("miss index must be Err"),
            };
            assert_eq!(got_miss, miss_expect);
            // (3) The EOF-past-total segment: serve semantics
            // equivalent (read_block Ok(short) -> serve_request
            // reject; batch Err(short read) -> reject).
            let mut buf6 = vec![0u8; 16384];
            assert!(
                matches!(src.read_block(6, 0, &mut buf6), Ok(n) if n < 16384),
                "per-segment shape = Ok(short read)"
            );
            assert!(
                got[5].is_err(),
                "batch shape = Err (reject equivalent): {:?}",
                got[5]
            );
        }
        // (4) Side evidence that coalescing worked: pool handles
        // after the batch = active files (a/b; pads never hit disk —
        // the open O(requests) -> O(files) goal).
        assert_eq!(src.reader.open_handles(), 2);
    }
}

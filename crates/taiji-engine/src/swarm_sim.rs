//! Swarm simulation harness (SPEC G6's "many peers + virtual clock"
//! layer): a `fake_peer + setup_swarm` shape driving the engine's
//! decision rounds under a [`ManualClock`], for the timing regressions
//! real-time tests cannot cover (optimistic-unchoke rotation, endgame
//! duplicate caps) — the first users of the determinism seams.
//!
//! Shape and scope (deliberately narrow — not a general link simulator):
//! - The engine is assembled through its public surface
//!   ([`crate::config::engine_config`]) over a real v1 metainfo; the
//!   seams are injected through `EngineConfig`'s public fields
//!   (`clock` = a [`ManualClock`] handle, `rng` = a pinned seed; the
//!   peer-id/listen-port are pinned through the same public fields).
//! - Fake peers attach at the engine's peer face the way the in-crate
//!   suites do: one `tokio::io::duplex` +
//!   [`taiji_bt::peer::PeerTask`] per peer, the test playing the remote
//!   over raw wire frames. No RTT/loss/bandwidth modeling —
//!   link-level impairment stays with the taiji-io uTP duplex mock,
//!   which owns that topology.
//! - Virtual time moves only when the driver says so: [`Swarm::step`]
//!   advances the manual clock and runs the same round functions the
//!   run loop's tickers would fire over that interval (one leecher
//!   choke round per 15s boundary crossed, one dispatch round per
//!   step), settling between advances so the peer tasks consume the
//!   frames the rounds wrote (poll-with-deadline, the in-crate
//!   convention — never a fixed sleep-and-pray).
//! - Out of scope by design (mirroring the seam module docs): the tokio
//!   timer wheel is NOT virtualized — the harness drives the engine's
//!   decision surface directly, not a spawned `run()` loop.
//!
//! Performance budget (SPEC G6 "60 virtual seconds <= a few wall
//! seconds"; measured on the dev machine this branch was authored on,
//! Apple silicon, debug test profile): the two-phase
//! optimistic-rotation scenario (105 + 105 virtual seconds, 14 choke
//! rounds across 12 attached peers) completes in ~0.9s of wall time;
//! the 40-piece endgame convergence scenario (~95% pre-complete, 4
//! serving peers, dispatch+arrival rounds to completion) in ~0.3s.
//! [`virtual_time_scenarios_run_in_a_few_wall_seconds`] pins the bound
//! (a 90-virtual-second drive must stay under a few wall seconds; the
//! measured cost is ~0.2s).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use taiji_bt::bencode::{self, Value};
use taiji_bt::choke::{ChokeMode, LeecherChoke, SeederChoke, SeedingPolicy};
use taiji_bt::peer::PeerTask;
use taiji_bt::peer_wire::{Message, Reserved};
use taiji_bt::piece_id::Addressing;
use taiji_bt::piece_stat::PieceStatMan;
use taiji_domain::metainfo::Metainfo;
use taiji_domain::progress::ProgressModel;

use crate::bitmap::PieceBitmap;
use crate::config::{CompletionMode, FaceKind, engine_config};
use crate::dispatch::{
    BlockState, ENDGAME_MAX_COPIES, dispatch_face, endgame_inflight_copies,
    endgame_lastmile_active, endgame_lastmile_copies_limit, endgame_piece_holders_face,
    note_peer_bitfield, note_peer_have_all, on_block_arrived,
};
use crate::faces::{
    FaceState, FaceView, PeerMeta, PexCandidates, SwarmSnapshot, XorShift, on_piece_verified,
    on_piece_written, recheck_face_completion,
};
use crate::pipeline::DataFlushState;
use crate::seam::{ManualClock, Rng};
use crate::tracker::TrackerMirror;
use crate::upload::RateWindow;

/// Choke round interval this harness advances per round (the libtorrent
/// default the run loop's choke ticker uses; `bt::choke`'s
/// `CHOKE_ROUND_INTERVAL`). The optimistic reselection period the
/// rotation regression asserts against is every second round (30s =
/// libtorrent `optimistic_unchoke_interval`, `bt::choke`'s
/// `OPTIMISTIC_UNCHOKE_INTERVAL`).
const CHOKE_ROUND: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------
// Fixture: a real v1 metainfo through the public assembly surface
// ---------------------------------------------------------------------

fn dict(mut pairs: Vec<(&[u8], Value)>) -> Value {
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    Value::Dict(pairs.into_iter().map(|(k, v)| (k.to_vec(), v)).collect())
}

/// A deterministic single-file v1 metainfo: `piece_count` pieces of
/// `piece_len` over a pattern payload (the same byte generator the wire
/// rigs use). The content is returned alongside so fake peers can serve
/// real blocks.
pub(crate) fn v1_metainfo(piece_count: usize, piece_len: u32) -> (Metainfo, Vec<u8>) {
    let total = piece_count as u64 * u64::from(piece_len);
    let content: Vec<u8> = (0..total as usize).map(|i| (i * 31 % 251) as u8).collect();
    use sha1::{Digest as _, Sha1};
    let pieces: Vec<u8> = content
        .chunks(piece_len as usize)
        .flat_map(Sha1::digest)
        .collect();
    let info = dict(vec![
        (b"length", Value::Int(total as i64)),
        (b"name", Value::Bytes(b"swarm-sim.bin".to_vec())),
        (b"piece length", Value::Int(i64::from(piece_len))),
        (b"pieces", Value::Bytes(pieces)),
    ]);
    let top = dict(vec![
        (
            b"announce",
            Value::Bytes(b"http://127.0.0.1:1/announce".to_vec()),
        ),
        (b"info", info),
    ]);
    let bytes = bencode::encode(&top).unwrap_or_else(|e| panic!("bencode: {e}"));
    let meta = Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("parse: {e}"));
    (meta, content)
}

// ---------------------------------------------------------------------
// Fake peer
// ---------------------------------------------------------------------

/// What a fake peer advertises (and serves).
#[derive(Clone)]
pub(crate) enum Holds {
    /// Every piece (HaveAll).
    All,
    /// Only these flat piece indices.
    Pieces(Vec<u64>),
}

/// Per-peer behavior knobs: the pieces the peer holds, its observed
/// download rate (the leecher regular-slot sort key), and whether it is
/// interested in us.
pub(crate) struct FakePeerSpec {
    /// Last octet of the peer's public IPv4 (203.0.113.`octet`; TEST-NET-3
    /// — never a local-class address, so the connection-class (BH_PEER_CLASS) exemption
    /// must not lift any of these peers out of the slot competition).
    pub(crate) octet: u8,
    /// The peer's download rate to us in B/s (distinct rates keep the
    /// regular top-N deterministic).
    pub(crate) rate_bps: u64,
    /// Whether the peer sends Interested (the choke-round input).
    pub(crate) interested: bool,
    /// Advertisement (and serving) surface.
    pub(crate) holds: Holds,
}

/// One attached fake peer: the duplex remote halves (the test plays the
/// remote over raw frames), the live PeerTask handle, and the drained
/// data-channel arrival count (a cross-check that every served block
/// matched a booked request — the peer task would have disconnected on
/// an unsolicited piece otherwise).
pub(crate) struct FakePeer {
    pub(crate) cuid: u64,
    pub(crate) handle: taiji_bt::peer::PeerTaskHandle,
    join: tokio::task::JoinHandle<taiji_bt::peer::PeerEnd>,
    reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    arrivals: Arc<AtomicU64>,
    /// Wire frames tallyed by message id (the protocol-consistency
    /// observation face: Request/Cancel/Reject accounting).
    frames_by_id: HashMap<u8, u64>,
}

impl FakePeer {
    /// Blocks the peer task forwarded to its data channel (each one
    /// matched a booked request; unsolicited pieces would have ended
    /// the task instead).
    pub(crate) fn arrivals(&self) -> u64 {
        self.arrivals.load(Ordering::Relaxed)
    }

    /// Whether the peer task is still alive (a Violation — unsolicited
    /// piece, malformed frame — ends it; aliveness at the end of a
    /// scenario is the no-protocol-violation assertion).
    pub(crate) fn alive(&self) -> bool {
        !self.join.is_finished()
    }

    /// Send one raw wire frame.
    async fn send(&mut self, msg: &Message) {
        self.writer
            .write_all(&msg.encode())
            .await
            .unwrap_or_else(|e| panic!("fake peer write: {e}"));
    }

    /// Read one wire frame (length prefix + body); None on timeout/EOF
    /// (the drain convention of the in-crate suites). The idle timeout
    /// is the drain's "no more frames" signal — short for per-round
    /// drains, generous for the settled final tally.
    async fn read_frame(&mut self, idle: Duration) -> Option<Message> {
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(idle, self.reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => return None,
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Some(Message::KeepAlive);
        }
        let mut body = vec![0u8; len];
        match tokio::time::timeout(idle, self.reader.read_exact(&mut body)).await {
            Ok(Ok(_)) => {
                Some(Message::decode_body(&body).unwrap_or_else(|e| panic!("decode: {e:?}")))
            }
            _ => None,
        }
    }

    /// Drain every currently queued frame (tallying by message id);
    /// returns the decoded frames in arrival order. `idle` = how long a
    /// quiet wire ends the drain.
    async fn drain_frames(&mut self, idle: Duration) -> Vec<Message> {
        let mut out = Vec::new();
        while let Some(frame) = self.read_frame(idle).await {
            if !matches!(frame, Message::KeepAlive) {
                out.push(frame);
            }
        }
        for f in &out {
            if let Some(id) = f.id() {
                *self.frames_by_id.entry(id as u8).or_default() += 1;
            }
        }
        out
    }

    /// Total frames of one message id seen so far.
    pub(crate) fn count(&self, id: u8) -> u64 {
        self.frames_by_id.get(&id).copied().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------
// Swarm (the setup_swarm shape)
// ---------------------------------------------------------------------

/// A face-level engine swarm under virtual time: the assembled face (from
/// the public config surface, held as a one-face slice so the multi-face
/// bookkeeping APIs run verbatim), N fake peers at the peer face, and
/// the manual clock every driver-path read observes.
pub(crate) struct Swarm {
    faces: Vec<FaceState>,
    pub(crate) clock: ManualClock,
    pub(crate) content: Vec<u8>,
    pub(crate) piece_len: u32,
    pub(crate) peers: Vec<FakePeer>,
    choke_rng: XorShift,
    root: CancellationToken,
    /// Virtual time advanced so far (the round-cadence observation face).
    pub(crate) virtual_elapsed: Duration,
}

/// Mirrors the seeded-arm shape of `run::assemble`'s generator derivation
/// (a fixed nonzero XorShift state; the derivation table itself is
/// pinned in assemble's tests — here only determinism matters).
fn sim_choke_rng(seed: u64) -> XorShift {
    XorShift((seed ^ 0x9E37_79B9_7F4A_7C15) | 1)
}

impl Swarm {
    /// setup_swarm: assemble the engine config through the public surface
    /// (a real v1 metainfo), inject the seams through the public fields
    /// (ManualClock + pinned RNG + pinned peer-id/listen-port), and build
    /// the v1 face the way `run::assemble` wires it (the seam clock clone
    /// included). No listener, tracker actor or pipeline is spawned: the
    /// harness drives the decision rounds directly.
    pub(crate) async fn build(piece_count: usize, piece_len: u32, seed: u64) -> Swarm {
        let (meta, content) = v1_metainfo(piece_count, piece_len);
        let mut cfg = engine_config(
            &meta,
            std::env::temp_dir(),
            // Pinning through the public fields (port/peer-id): the
            // assembled config round-trips them — the replay contract of
            // the RNG seam.
            41715,
            *b"-TJ0001-SWARMSIMSEED",
            CompletionMode::ReturnOnComplete,
        )
        .unwrap_or_else(|e| panic!("engine_config: {e}"));
        assert_eq!(cfg.faces.len(), 1, "v1-only: one face");
        assert_eq!(cfg.listen_port, 41715);
        assert_eq!(cfg.peer_id, *b"-TJ0001-SWARMSIMSEED");
        let manual = ManualClock::new(Instant::now());
        cfg.clock = manual.clock();
        cfg.rng = Rng::from_seed(seed);
        assert_eq!(cfg.rng.seed(), Some(seed), "the pinned seed round-trips");

        let f = &cfg.faces[0];
        assert_eq!(f.kind, FaceKind::V1);
        let total: u64 = f.piece_bytes.iter().sum();
        let (block_tx, _rx) = mpsc::channel(1);
        let (fetch_tx, _frx) = mpsc::channel(16);
        let (final_flush_tx, _final_flush_rx) = mpsc::channel::<()>(1);
        let (_data_flush_gate, data_flush_gate) =
            tokio::sync::watch::channel(DataFlushState::Pending);
        let mut stat_rng = XorShift(0x853C49E6748FEA9Bu64);
        let face = FaceState {
            // The seam clock: a clone of the injected handle — every
            // driver-path "now" read below observes the manual clock.
            clock: cfg.clock.clone(),
            kind: f.kind,
            info_hash: f.info_hash,
            reserved: Reserved::aria2_default(),
            addressing: Addressing::Flat,
            piece_bytes: f.piece_bytes.clone().into(),
            piece_goffs: Arc::from(f.piece_goffs.clone()),
            progress: ProgressModel::from_lengths(&[total], piece_len),
            piece_count,
            verified_count: 0,
            stat_man: PieceStatMan::new(piece_count as u64, &mut |n| stat_rng.next(n)),
            peer_avail: HashMap::new(),
            peer_seeds: std::collections::HashSet::new(),
            peers: Vec::new(),
            peer_cuids: Vec::new(),
            peer_state: HashMap::new(),
            block_senders: Arc::new(Mutex::new(HashMap::new())),
            choke: SeederChoke::with(ChokeMode::Libtorrent, SeedingPolicy::FastestUpload),
            leecher_choke: LeecherChoke::with_mode(ChokeMode::Libtorrent),
            regular_unchoked: std::collections::HashSet::new(),
            download_source: None,
            written_bits: Arc::new(PieceBitmap::new(piece_count)),
            written_progress: ProgressModel::from_lengths(&[total], piece_len),
            written_count: 0,
            selected_written_count: 0,
            completed: false,
            hash_files: None,
            swarm: FaceView(Arc::new(Mutex::new(SwarmSnapshot {
                total,
                completed: 0,
                all_finished: false,
                peers: 0,
                uploaded: 0,
                downloaded: 0,
            }))),
            mirror: TrackerMirror::new(&[], ""),
            block_cursor: 0,
            block_tx,
            trees: None,
            flat_coords: Arc::from(
                (0..piece_count as u64)
                    .map(|i| (0u32, i as u32))
                    .collect::<Vec<_>>(),
            ),
            layers: Vec::new(),
            fetch_tx,
            refetch: Vec::new(),
            dispatch_replies: Vec::new(),
            dispatch_scratch: Default::default(),
            endgame_live: Arc::new(AtomicBool::new(false)),
            endgame_edge: None,
            endgame_cum: Duration::ZERO,
            last_mile_edge: None,
            last_mile_final: None,
            last8_edge: None,
            last8_final: None,
            endgame_deadline: HashMap::new(),
            write_adjacent: 0,
            write_isolated: 0,
            blocks_sent: HashMap::new(),
            parole_peers: std::collections::HashSet::new(),
            block_arena: None,
            block_inflight: Arc::new(AtomicU64::new(0)),
            pex_candidates: PexCandidates::default(),
            read_pool: None,
            final_flush_tx,
            data_flush_gate,
            dirty_since_snapshot: false,
            snapshot_sync: Arc::new(std::sync::OnceLock::new()),
        };
        Swarm {
            faces: vec![face],
            clock: manual,
            content,
            piece_len,
            peers: Vec::new(),
            choke_rng: sim_choke_rng(seed),
            root: CancellationToken::new(),
            virtual_elapsed: Duration::ZERO,
        }
    }

    /// The single face (the decision surface the harness drives).
    pub(crate) fn face(&self) -> &FaceState {
        &self.faces[0]
    }

    /// Attach one fake peer at the peer face: duplex + PeerTask (the
    /// in-crate convention), the registration row (meta with a public
    /// TEST-NET address + the download-rate window), the advertisement
    /// bitmap, and the Unchoke (+ Interested) wire frames with the
    /// mirror-set wait (the dispatch request face sends nothing to a
    /// peer that is choking us). Returns the peer's cuid.
    pub(crate) async fn add_peer(&mut self, spec: FakePeerSpec) -> u64 {
        let cuid = self.peers.len() as u64 + 1;
        let (local, remote) = tokio::io::duplex(64 * 1024);
        let (handle, join, data_rx) =
            PeerTask::spawn(&self.root, local, taiji_bt::peer::PeerConfig::flat());
        // Keep the peer task's data channel drained (a full channel would
        // stall its read loop); every drained block is one that matched a
        // booked request — the count is the protocol-consistency face.
        let arrivals = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&arrivals);
        tokio::spawn(async move {
            let mut data_rx = data_rx;
            while data_rx.recv().await.is_some() {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
        let (reader, writer) = tokio::io::split(remote);
        let mut peer = FakePeer {
            cuid,
            handle,
            join,
            reader,
            writer,
            arrivals,
            frames_by_id: HashMap::new(),
        };

        // Registration row (the register arm's shape): meta + rate window.
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, spec.octet));
        {
            let row = self.faces[0].peer_state_row(cuid);
            row.meta = Some(PeerMeta {
                ip,
                port: 6881,
                inbound: false,
                peer_id: [spec.octet; 20],
                crypto: taiji_bt::mse::CryptoLevel::Plain,
                transport: taiji_bt::utp::Transport::Tcp,
                up: Arc::new(AtomicU64::new(0)),
                down: Arc::new(AtomicU64::new(0)),
                upload_only: Arc::new(AtomicBool::new(false)),
            });
            let mut w = RateWindow::new();
            for _ in 0..RateWindow::WINDOW_SECS {
                w.advance();
                w.add(spec.rate_bps);
            }
            row.down_window = Some(w);
        }
        self.faces[0].peers.push(peer.handle.clone());
        self.faces[0].peer_cuids.push(cuid);

        // Advertisement bitmap (the fake serves exactly what it holds).
        match &spec.holds {
            Holds::All => note_peer_have_all(&mut self.faces[0], cuid),
            Holds::Pieces(held) => {
                let mut bits = vec![0u8; self.faces[0].piece_count.div_ceil(8)];
                for &p in held {
                    bits[p as usize / 8] |= 0x80 >> (p as usize % 8);
                }
                note_peer_bitfield(&mut self.faces[0], cuid, &bits);
            }
        }

        // Wire-side reciprocity: Unchoke (+ Interested), then wait for the
        // lock-free mirrors to flip (poll-with-deadline, never a fixed
        // sleep).
        peer.send(&Message::Unchoke).await;
        if spec.interested {
            peer.send(&Message::Interested).await;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while peer.handle.is_choking_us() || (spec.interested && !peer.handle.is_interested()) {
            assert!(
                Instant::now() < deadline,
                "the unchoke/interested mirrors did not flip in time"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        self.peers.push(peer);
        cuid
    }

    /// Advance virtual time by `step`, running the driver rounds the run
    /// loop would have fired over that interval: one leecher choke round
    /// per 15s boundary crossed (the choke ticker's cadence, class switch
    /// on = the production default), then one dispatch round, then a
    /// settle so the peer tasks consume the frames the rounds wrote.
    /// Returns the new virtual instant.
    pub(crate) async fn step(&mut self, step: Duration) -> Instant {
        let target = self.clock.now() + step;
        while self.clock.now() + CHOKE_ROUND <= target {
            self.clock.advance(CHOKE_ROUND);
            self.virtual_elapsed += CHOKE_ROUND;
            crate::choke::leecher_choke_round(&mut self.faces[0], &mut self.choke_rng, None, true);
        }
        if self.clock.now() < target {
            let rest = target - self.clock.now();
            self.clock.advance(rest);
            self.virtual_elapsed += rest;
        }
        dispatch_face(&mut self.faces[0], 0);
        // Post-round invariant sweep (the state-audit vehicle: the
        // request-window book, the choke-round book and the completion
        // faces re-derive themselves after every virtual-time round —
        // a mid-round corruption surfaces here, at the round boundary).
        crate::invariant::sweep_face(&self.faces[0]);
        self.settle().await;
        self.clock.now()
    }

    /// Let the peer tasks process the frames this step wrote (bounded
    /// yield points; a wedged task fails the mirror waits loudly rather
    /// than hanging the test).
    async fn settle(&mut self) {
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(2)).await;
            tokio::task::yield_now().await;
        }
    }

    /// The current optimistic-seat holder: the peer with the most recent
    /// `last_opt_unchoke` stamp (only optimistic picks write that field).
    pub(crate) fn optimistic_holder(&self) -> Option<u64> {
        self.faces[0]
            .peer_state
            .iter()
            .filter_map(|(cuid, ps)| ps.last_opt_unchoke.map(|at| (*cuid, at)))
            .max_by_key(|&(_, at)| at)
            .map(|(cuid, _)| cuid)
    }

    /// Cuids currently unchoked (the landing-state mirror).
    pub(crate) fn unchoked(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.faces[0]
            .peer_state
            .iter()
            .filter(|(_, ps)| ps.am_unchoked)
            .map(|(cuid, _)| *cuid)
            .collect();
        v.sort_unstable();
        v
    }

    /// Serve one round: every fake peer drains its wire frames (a short
    /// idle — a straggler frame is simply served next round), answers
    /// each Request with the real content block (only pieces it holds),
    /// and drives the face-side arrival bookkeeping the main loop's
    /// arrival arm would run (`on_block_arrived`; the transit layer's
    /// stand-in). Cancels are tallied and their blocks skipped (the
    /// sibling copy settled first). Returns (blocks served, cancels
    /// seen).
    pub(crate) async fn serve_round(&mut self) -> (u64, u64) {
        let mut served = 0u64;
        let mut cancels = 0u64;
        let piece_len = self.piece_len as usize;
        // Drain every peer first (arrival order), then answer: a Cancel
        // read in the same batch precedes its Request's service.
        let mut batches = Vec::new();
        for peer in &mut self.peers {
            batches.push((peer.cuid, peer.drain_frames(Duration::from_millis(8)).await));
        }
        for (peer, (cuid, frames)) in self.peers.iter_mut().zip(batches) {
            let mut cancelled: Vec<(u32, u32)> = Vec::new();
            for frame in &frames {
                if let Message::Cancel { index, begin, .. } = frame {
                    cancelled.push((*index, *begin));
                }
            }
            cancels += cancelled.len() as u64;
            for frame in frames {
                let Message::Request {
                    index,
                    begin,
                    length,
                } = frame
                else {
                    continue;
                };
                if cancelled.iter().any(|&(ci, cb)| ci == index && cb == begin) {
                    // Cancelled before service: the sibling copy settled
                    // first; skipping keeps the peer's answers consistent.
                    continue;
                }
                let held = self.faces[0]
                    .peer_avail
                    .get(&cuid)
                    .is_some_and(|avail| avail.get(index as usize));
                if !held {
                    continue;
                }
                let off = index as usize * piece_len + begin as usize;
                let block = self.content[off..off + length as usize].to_vec();
                peer.send(&Message::Piece {
                    index,
                    begin,
                    block: bytes::Bytes::from(block),
                })
                .await;
                served += 1;
                on_block_arrived(&mut self.faces[0], index, begin, self.clock.now());
            }
        }
        (served, cancels)
    }

    /// Complete one piece whose blocks have all arrived (the store
    /// pipeline's verify+write stand-in): verified + written events and
    /// the completion recheck, through the multi-face slice APIs the
    /// arms use. Returns whether the face completed.
    pub(crate) fn settle_piece(&mut self, index: u64) -> bool {
        let need = [self.faces[0].piece_count];
        on_piece_verified(&mut self.faces, 0, index);
        on_piece_written(&mut self.faces, 0, index, &need, None);
        let done = recheck_face_completion(&mut self.faces, &need, false);
        // Post-completion sweep: the verify/write/clear chain moved all
        // five completion encodings at once — re-derive their agreement
        // (plus the blocks_sent row clearance) at every piece boundary.
        crate::invariant::sweep_faces(&self.faces);
        done
    }

    /// Pieces whose ledgers are fully settled (every block in a
    /// Settling state) but not yet verified.
    pub(crate) fn arrived_pieces(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for (&piece, ledger) in &self.faces[0].blocks_sent {
            if self.faces[0].progress.piece_done_global(piece) {
                continue;
            }
            let blocks = ledger.slots();
            if !blocks.is_empty()
                && blocks
                    .iter()
                    .all(|s| matches!(s.state, BlockState::Settling | BlockState::SettlingDup))
            {
                out.push(piece);
            }
        }
        out.sort_unstable();
        out
    }

    /// Per-piece in-flight copy count (the x2-gate metering face,
    /// `endgame_inflight_copies`) over the still-missing pieces.
    pub(crate) fn piece_copies(&self, piece: u64, window: Duration) -> u64 {
        endgame_inflight_copies(
            self.faces[0].blocks_sent.get(&piece),
            self.clock.now(),
            window,
        )
    }

    /// Connected non-choking holders of `piece` (the copies-limit input,
    /// `endgame_piece_holders_face`).
    pub(crate) fn holders_of(&self, piece: u64) -> u64 {
        let choking: Vec<bool> = self.faces[0]
            .peers
            .iter()
            .map(|p| p.is_choking_us())
            .collect();
        endgame_piece_holders_face(&self.faces[0], piece, &choking)
    }

    /// Still-missing piece count.
    pub(crate) fn missing(&self) -> u64 {
        (0..self.faces[0].piece_count as u64)
            .filter(|&i| !self.faces[0].progress.piece_done_global(i))
            .count() as u64
    }

    /// Settled final tally drain: every peer's wire drained with a
    /// generous idle (frames written rounds earlier are already queued
    /// — only the final idle wait costs; the per-message tallies are the
    /// assertion face).
    pub(crate) async fn drain_all_settled(&mut self) {
        for peer in &mut self.peers {
            let _ = peer.drain_frames(Duration::from_millis(40)).await;
        }
    }
}

// ---------------------------------------------------------------------
// Timing regression 1: optimistic unchoke rotation (virtual clock)
// ---------------------------------------------------------------------

/// Optimistic-unchoke rotation timing (the `choke.rs` semantics, driven
/// by virtual time instead of wall sleeping). Two phases:
///
/// Phase 1 — slot competition under load: a downloading engine with 10
/// interested remote peers — all public TEST-NET addresses, so the
/// connection-class (BH_PEER_CLASS) exemption must NOT lift any of them out of the
/// 8-slot competition — advanced 105 virtual seconds in 15s choke
/// rounds. Asserts:
/// - the slot structure holds every round: exactly 8 unchoked (7 regular
///   by download rate + 1 optimistic); the two slowest-rate peers never
///   seat (evidence the fakes compete inside the budget — no class
///   bypass, which would show up as a 9th always-unchoked seat);
/// - the optimistic seat rotates ONLY on every second round (the 30s
///   re-election phase, `OPTIMISTIC_ROUND_EVERY` = 30s/15s = 2): holder
///   changes at t=45/75/105 exactly, never on the 15s rounds between;
/// - waits-longest-first among the never-picked: each re-election takes
///   the next never-picked peer in input order (a None stamp = never =
///   waited longest, `last_optimistically_unchoked` ascending);
/// - wire consistency: exactly one Unchoke per newly-seated peer (8
///   total — the first round's seating) and zero frames on the
///   idempotent rounds (the landing state machine).
///
/// Phase 2 — the timestamp half of waits-longest-first (never-picked
/// candidates exhausted): two interested peers only; after both hold the
/// seat once, re-elections alternate by earliest stamp (the t=15 holder
/// wins back at t=75, the t=45 holder at t=105) — the strict
/// `last_optimistically_unchoked`-ascending revisit that None-first
/// pools cannot exhibit.
#[tokio::test]
async fn optimistic_unchoke_rotates_on_30s_boundaries_longest_waited_first() {
    // ---- Phase 1: 10 interested peers, 105 virtual seconds ----
    let mut swarm = Swarm::build(8, 16384, 0x5EED_0000_0000_00A1).await;
    // Descending rates: the regular top-7 = cuids 1..=7 deterministically;
    // cuids 8..=10 never win a regular slot.
    for i in 1..=10u8 {
        swarm
            .add_peer(FakePeerSpec {
                octet: i,
                rate_bps: u64::from(11 - i) * 100,
                interested: true,
                holds: Holds::All,
            })
            .await;
    }

    let mut holders: Vec<(u64, Option<u64>)> = Vec::new();
    for round in 0..7u64 {
        swarm.step(CHOKE_ROUND).await;
        let t = (round + 1) * 15;
        holders.push((t, swarm.optimistic_holder()));
        assert_eq!(
            swarm.unchoked(),
            (1u64..=8).collect::<Vec<_>>(),
            "t={t}s: exactly the 8 slots (7 regular by rate + 1 optimistic), \
             no exemption seat",
        );
    }
    let seq: Vec<Option<u64>> = holders.iter().map(|(_, h)| *h).collect();
    assert_eq!(
        seq,
        vec![
            Some(1),
            Some(1),
            Some(2),
            Some(2),
            Some(3),
            Some(3),
            Some(4)
        ],
        "holder kept on the 15s rounds; each 30s re-election takes the next \
         never-picked peer in input order (None = waited longest)"
    );
    // Boundary discipline: changes land exactly on t=45/75/105 — every
    // OPTIMISTIC_INTERVAL since the first round, never a 15s round.
    let changes: Vec<u64> = holders
        .windows(2)
        .filter(|w| w[0].1 != w[1].1)
        .map(|w| w[1].0)
        .collect();
    assert_eq!(changes, vec![45, 75, 105], "rotation cadence = 30s exactly");
    // Wire consistency: the first round seats 8 peers (8 Unchoke frames);
    // the stable set afterwards emits zero frames; nobody loses a seat.
    swarm.drain_all_settled().await;
    let unchokes: u64 = swarm.peers.iter().map(|p| p.count(1)).sum();
    let chokes: u64 = swarm.peers.iter().map(|p| p.count(0)).sum();
    assert_eq!(
        unchokes, 8,
        "exactly the first round's seating emits Unchoke"
    );
    assert_eq!(chokes, 0, "no seat is ever lost (the set is stable)");
    assert!(
        swarm.peers.iter().all(|p| p.alive()),
        "no peer task may end (a protocol violation would have)"
    );
    swarm.root.cancel();

    // ---- Phase 2: earliest-stamp revisit (two peers, stamps exhausted) ----
    let mut swarm = Swarm::build(8, 16384, 0x5EED_0000_0000_00A2).await;
    for i in 1..=2u8 {
        swarm
            .add_peer(FakePeerSpec {
                octet: i,
                rate_bps: 1000,
                interested: true,
                holds: Holds::All,
            })
            .await;
    }
    let mut holders = Vec::new();
    for round in 0..7u64 {
        swarm.step(CHOKE_ROUND).await;
        let t = (round + 1) * 15;
        holders.push((t, swarm.optimistic_holder()));
        assert_eq!(
            swarm.unchoked(),
            vec![1u64, 2],
            "t={t}s: with 2 interested peers both sit (regular + optimistic)"
        );
    }
    let seq: Vec<Option<u64>> = holders.iter().map(|(_, h)| *h).collect();
    assert_eq!(
        seq,
        vec![
            Some(1),
            Some(1),
            Some(2),
            Some(2),
            Some(1),
            Some(1),
            Some(2)
        ],
        "stamps exhausted -> re-elections alternate by earliest \
         last_optimistically_unchoked (t=15 holder back at 75, t=45 at 105)"
    );
    let changes: Vec<u64> = holders
        .windows(2)
        .filter(|w| w[0].1 != w[1].1)
        .map(|w| w[1].0)
        .collect();
    assert_eq!(changes, vec![45, 75, 105], "same 30s cadence");
    swarm.root.cancel();
}

// ---------------------------------------------------------------------
// Timing regression 2: endgame duplicate-request cap + convergence
// ---------------------------------------------------------------------

/// Endgame duplicate-request cap under virtual time: a ~95%-complete
/// download (38/40 pieces verified+written) with four fast fake peers
/// holding the last two pieces, driven to completion through dispatch
/// rounds and served arrivals. Asserts:
///
/// - convergence: the face completes (all 40 pieces verified+written)
///   within the iteration budget;
/// - the documented copy cap holds at every observation point: each
///     missing piece's in-flight copies (x2-gate metering,
///     `endgame_inflight_copies`) stay <= the limit —
///     [`ENDGAME_MAX_COPIES`] = 2 (dispatch.rs) outside last-mile,
///     `max(holders, 2)` (`endgame_lastmile_copies_limit`, dispatch.rs)
///     inside the last-mile tail (missing <= `BH_ENDGAME_LASTMILE`
///     default 4) — and the cap is actually exercised (at least one
///     InFlightDup mark observed; the test is not vacuous);
/// - protocol consistency: every served block matched a booked request
///   (peer data-channel arrivals == served count; an unsolicited piece
///   would have disconnected the peer task), all peer tasks still alive
///   at completion, and zero Reject frames on any wire.
#[tokio::test]
async fn endgame_duplicate_copies_stay_capped_and_converge() {
    let mut swarm = Swarm::build(40, 16384, 0x5EED_0000_0000_00B2).await;
    // 95% complete: pieces 0..=37 verified + written through the same
    // bookkeeping the store pipeline's events drive.
    for piece in 0..38u64 {
        let done = swarm.settle_piece(piece);
        assert!(!done, "the face must not complete at {piece}/40");
    }
    assert_eq!(swarm.missing(), 2, "the last-mile tail: pieces 38 and 39");
    // Four fast peers, all holding both tail pieces.
    for i in 1..=4u8 {
        swarm
            .add_peer(FakePeerSpec {
                octet: i,
                rate_bps: 400 * 1024,
                interested: false,
                holds: Holds::Pieces(vec![38, 39]),
            })
            .await;
    }

    let mut saw_dup = false;
    let mut served_total = 0u64;
    let mut completed = false;
    for _round in 0..64 {
        // One second of virtual time per round (below the reissue
        // window: nothing times out, the cap is exercised by the busy
        // gate alone).
        swarm.step(Duration::from_secs(1)).await;
        // Cap observation (post-dispatch, pre-arrival): every missing
        // piece's copies within the documented limit.
        let missing = swarm.missing();
        if missing == 0 {
            break;
        }
        let lastmile = endgame_lastmile_active(4, missing);
        for piece in (0..40u64).filter(|&p| !swarm.face().progress.piece_done_global(p)) {
            let holders = swarm.holders_of(piece);
            let limit = if lastmile {
                endgame_lastmile_copies_limit(holders)
            } else {
                ENDGAME_MAX_COPIES
            };
            let copies = swarm.piece_copies(piece, Duration::from_secs(2));
            assert!(
                copies <= limit,
                "piece {piece}: {copies} in-flight copies exceed the documented \
                 cap {limit} (lastmile={lastmile}, holders={holders})"
            );
        }
        saw_dup |= swarm
            .face()
            .blocks_sent
            .values()
            .any(|l| l.slots().iter().any(|s| s.state == BlockState::InFlightDup));
        // Serve: the fakes answer every booked request with real blocks
        // and drive the arrival bookkeeping.
        let (served, _cancels) = swarm.serve_round().await;
        served_total += served;
        for piece in swarm.arrived_pieces() {
            if swarm.settle_piece(piece) {
                completed = true;
            }
        }
    }
    assert!(completed, "the endgame must converge to completion");
    assert!(
        swarm.face().completed && swarm.missing() == 0,
        "all 40 pieces verified+written"
    );
    assert!(
        saw_dup,
        "the duplicate path must actually fire (non-vacuous)"
    );
    swarm.drain_all_settled().await;
    // The data-channel drainer counts asynchronously: poll to the
    // expected total within a deadline (the peer tasks forward each
    // served block after parsing it; the drain settle already covered
    // all but the last in-flight items).
    let arrivals = {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let n: u64 = swarm.peers.iter().map(|p| p.arrivals()).sum();
            if n == served_total || Instant::now() > deadline {
                break n;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    assert_eq!(
        arrivals, served_total,
        "every served block matched a booked request (data-channel accounting)"
    );
    assert!(
        swarm.peers.iter().all(|p| p.alive()),
        "no peer task may end (a protocol violation would have)"
    );
    swarm.drain_all_settled().await;
    let rejects: u64 = swarm.peers.iter().map(|p| p.count(16)).sum();
    assert_eq!(rejects, 0, "no Reject frames on any wire");
    swarm.root.cancel();
}

// ---------------------------------------------------------------------
// Performance budget (SPEC G6: 60 virtual seconds <= a few wall seconds)
// ---------------------------------------------------------------------

/// The virtual-time budget: a 90-virtual-second scenario (10 attached
/// peers, 6+ choke rounds, dispatch rounds and wire-frame drains each
/// step — the optimistic-rotation shape above) must complete well
/// within a few wall seconds. The bound asserted here (10s) is the CI
/// safety margin; the measured number on the dev machine is recorded in
/// the module docs.
#[tokio::test]
async fn virtual_time_scenarios_run_in_a_few_wall_seconds() {
    let start = Instant::now();
    let mut swarm = Swarm::build(8, 16384, 0x5EED_0000_0000_00C3).await;
    for i in 1..=10u8 {
        swarm
            .add_peer(FakePeerSpec {
                octet: i,
                rate_bps: u64::from(11 - i) * 100,
                interested: true,
                holds: Holds::All,
            })
            .await;
    }
    for _ in 0..6 {
        swarm.step(CHOKE_ROUND).await;
    }
    let wall = start.elapsed();
    assert!(
        wall < Duration::from_secs(10),
        "90 virtual seconds must cost well under a few wall seconds, took {wall:?}"
    );
}

// ---------------------------------------------------------------------
// Startup-ordering regression: same-beat advertisement + unchoke
// ---------------------------------------------------------------------

/// Same-beat startup ordering (the recorded stall shape): a seeder
/// whose Bitfield lands in the same event-loop beat as its handshake
/// response gets its availability bookkeeping processed BEFORE the
/// connection's registration row lands (the run loop's biased select
/// polls the avail arm ahead of the register arm, so the interleaving
/// is real), and the peer's Unchoke — answering the attach-time
/// Interested — can flip the choke mirror inside the same window. This
/// test drives the three inputs in exactly that adversarial order and
/// pins the recovery property: every pre-registration dispatch round is
/// a no-op (the peer is invisible while unregistered), and the FIRST
/// round after the registration writes must issue wire requests — a
/// download that never issues requests in this state is the recorded
/// permanent stall (dispatch is advertisement-aware; the bitfield is
/// one-shot, so a state where the round sequence never supplies again
/// never recovers).
#[tokio::test]
async fn same_beat_bitfield_and_unchoke_before_registration_still_supplies() {
    let mut swarm = Swarm::build(8, 16384, 0x5EED_0000_0000_00D4).await;

    // Attach the wire + PeerTask the add_peer way, but keep the
    // registration writes out — the adversarial ordering below is the
    // point of the test.
    let (local, remote) = tokio::io::duplex(64 * 1024);
    let (handle, join, data_rx) =
        PeerTask::spawn(&swarm.root, local, taiji_bt::peer::PeerConfig::flat());
    let arrivals = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&arrivals);
    tokio::spawn(async move {
        let mut data_rx = data_rx;
        while data_rx.recv().await.is_some() {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let (reader, writer) = tokio::io::split(remote);
    let mut peer = FakePeer {
        cuid: 1,
        handle,
        join,
        reader,
        writer,
        arrivals,
        frames_by_id: HashMap::new(),
    };

    // (1) The Bitfield bookkeeping lands FIRST (the biased avail arm
    // runs before the register arm; 8 pieces all present).
    let bits = [0xFFu8; 1];
    note_peer_bitfield(&mut swarm.faces[0], 1, &bits);
    // (2) The pre-registration dispatch round: a no-op over an empty
    // peer table (the same-beat window's wasted round).
    dispatch_face(&mut swarm.faces[0], 0);
    swarm.settle().await;
    // (3) The Unchoke frame is consumed inside the same window (the
    // mirror flip — poll-with-deadline, never a fixed sleep).
    peer.send(&Message::Unchoke).await;
    let deadline = Instant::now() + Duration::from_secs(2);
    while peer.handle.is_choking_us() {
        assert!(
            Instant::now() < deadline,
            "the unchoke mirror did not flip in time"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // (4) Another pre-registration round: still a no-op — and the wire
    // must show zero requests (the peer is invisible while
    // unregistered).
    dispatch_face(&mut swarm.faces[0], 0);
    swarm.settle().await;
    let pre = peer.drain_frames(Duration::from_millis(20)).await;
    assert!(
        pre.iter().all(|f| !matches!(f, Message::Request { .. })),
        "no requests may issue before registration (got {pre:?})"
    );

    // (5) The registration writes (the register arm's row shape: meta +
    // rate window + the peer_cuids/peers push).
    {
        let row = swarm.faces[0].peer_state_row(1);
        row.meta = Some(PeerMeta {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1)),
            port: 6881,
            inbound: false,
            peer_id: [1u8; 20],
            crypto: taiji_bt::mse::CryptoLevel::Plain,
            transport: taiji_bt::utp::Transport::Tcp,
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            upload_only: Arc::new(AtomicBool::new(false)),
        });
        let mut w = RateWindow::new();
        for _ in 0..RateWindow::WINDOW_SECS {
            w.advance();
            w.add(100 * 1024);
        }
        row.down_window = Some(w);
    }
    swarm.faces[0].peer_cuids.push(1);
    swarm.faces[0].peers.push(peer.handle.clone());

    // (6) The registration round: wire requests MUST issue now — the
    // advertisement row, the unchoked mirror and the registration are
    // all in place regardless of the order they landed.
    dispatch_face(&mut swarm.faces[0], 0);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_request = false;
    while Instant::now() < deadline {
        for f in peer.drain_frames(Duration::from_millis(8)).await {
            if matches!(f, Message::Request { .. }) {
                saw_request = true;
            }
        }
        if saw_request {
            break;
        }
    }
    assert!(
        saw_request,
        "the first post-registration dispatch round must issue wire requests \
         (the same-beat stall shape: advertisement + unchoke processed before \
         the registration row)"
    );
    swarm.root.cancel();
}

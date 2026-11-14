//! Status synthesis views: tellStatus / getPeers / getServers snapshot
//! synthesis, per-peer counter -> session-total bridging
//! ([`drain_peer_counters`]), gauge readings ([`count_peer_gauges`]),
//! bitfield packing ([`pack_bitfield`]).
//!
//! Owns: the read-only projection served to external queries and the
//! counter advances behind it.
//! Does not own: the command-channel shape (command) and RPC string
//! serialization (taiji-rpc).
//!
//! Upstream anchor mapping: docs/design/engine.md

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use taiji_bt::mse::CryptoLevel;
use taiji_bt::utp::Transport;
use taiji_store::persist::TrackerRow;

use taiji_domain::seed::SessionSpeedCalc;

use crate::bitmap::PieceBitmap;
use crate::faces::FaceState;
use crate::recovery::RecoveryStatus;
/// Bitmap row -> compact bytes (big-endian bit order, trailing pad bits
/// zero; the BEP3 wire layout).
/// `bits = None` (no peer bitfield/have received yet) -> an all-zero
/// bitmap.
/// Bitmap form: the `Some` arm copies the bitmap words bit-reversed
/// ([`PieceBitmap::to_packed_msb`] — the row width is constant
/// `piece_count` and equals `count`), avoiding bit-by-bit probing and
/// an N-byte expansion.
pub(super) fn pack_bitfield(bits: Option<&PieceBitmap>, count: usize) -> Vec<u8> {
    match bits {
        Some(row) => row.to_packed_msb(),
        None => vec![0u8; count.div_ceil(8)],
    }
}

/// One incremental output of the per-peer counter bridge (the
/// [`drain_peer_counters`] return value).
///
/// Observability: the downlink delta splits by the connection's
/// registration-time transport face (`PeerMeta::transport`, SPEC §8.2
/// values tcp|utp) — the prerequisite for re-estimating the transport
/// lever (µTP's per-packet syscall CPU overhead) per window: whichever
/// window holds a high µTP connection share / byte share, the data
/// says. Scope = wire-received bytes (counted at Piece frame reception,
/// before duplicate-block discrimination — duplicate redundancy is
/// included; same source as `bytes_down_total`, so they cross-check
/// additively: `down == down_tcp + down_utp`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct CounterDrain {
    /// All-connection downlink delta (session-total scope, feeds
    /// `bytes_down_total`).
    pub(super) down: u64,
    /// All-connection uplink delta.
    pub(super) up: u64,
    /// Of which: the downlink delta over TCP connections.
    pub(super) down_tcp: u64,
    /// Of which: the downlink delta over µTP connections.
    pub(super) down_utp: u64,
}

/// Per-peer counter delta -> session-total bridge + speed sampling
/// (called on the 1s/2s ticks and before final values are persisted).
/// With PeerConfig counters moved to per-peer atomics, the torrent-level
/// readings (announce uploaded / stop-timeout / persisted rows) advance
/// through this function by delta — same semantics, granularity <= the
/// tick period. Baseline semantics: `last_*_total` = the counter sum of
/// all registered connections at the previous bridge (a departed
/// connection's synchronized share is deducted by the departure arm;
/// the downlink baselines are kept one per transport family, and the
/// departure arm deducts the same-family share in step).
/// Returns this bridge's deltas (including the transport-split downlink
/// differences) — byte-count feeds consume on demand.
#[expect(
    clippy::too_many_arguments,
    reason = "the counter baselines are distinct &mut slots owned by the caller's tick state"
)]
pub(super) fn drain_peer_counters(
    faces: &mut [FaceState],
    last_up_total: &mut u64,
    last_down_total: &mut u64,
    last_down_tcp_total: &mut u64,
    last_down_utp_total: &mut u64,
    session_up: &AtomicU64,
    session_down: &AtomicU64,
    speed_up: &mut SessionSpeedCalc,
    speed_down: &mut SessionSpeedCalc,
) -> CounterDrain {
    let mut sum_up = 0u64;
    let mut sum_down = 0u64;
    let mut sum_down_tcp = 0u64;
    let mut sum_down_utp = 0u64;
    for face in faces.iter_mut() {
        // The meta/rates/down_window tables merge into one row walk
        // (missing meta = the same skip as an old peer_meta without an
        // entry; missing rates/down_window fields = the same skip as the
        // old split tables being absent).
        for ps in face.peer_state.values_mut() {
            let Some(meta) = ps.meta.as_ref() else {
                continue;
            };
            let u = meta.up.load(Ordering::Relaxed);
            let d = meta.down.load(Ordering::Relaxed);
            let mut delta_down = 0u64;
            if let Some(rate) = ps.rates.as_mut() {
                delta_down = d.saturating_sub(rate.last_down);
                rate.up.add(u.saturating_sub(rate.last_up));
                rate.down.add(delta_down);
                rate.last_up = u;
                rate.last_down = d;
            }
            // Download-window advance + this second's delta bucketed
            // (the leecher choking sort key).
            if let Some(w) = ps.down_window.as_mut() {
                w.advance();
                w.add(delta_down);
            }
            sum_up += u;
            sum_down += d;
            match meta.transport {
                Transport::Tcp => sum_down_tcp += d,
                Transport::Utp => sum_down_utp += d,
            }
        }
    }
    let delta_up = sum_up.saturating_sub(*last_up_total);
    let delta_down = sum_down.saturating_sub(*last_down_total);
    if delta_up > 0 {
        session_up.fetch_add(delta_up, Ordering::Relaxed);
    }
    if delta_down > 0 {
        session_down.fetch_add(delta_down, Ordering::Relaxed);
    }
    speed_up.add(delta_up);
    speed_down.add(delta_down);
    *last_up_total = sum_up;
    *last_down_total = sum_down;
    let drain = CounterDrain {
        down: delta_down,
        up: delta_up,
        down_tcp: sum_down_tcp.saturating_sub(*last_down_tcp_total),
        down_utp: sum_down_utp.saturating_sub(*last_down_utp_total),
    };
    *last_down_tcp_total = sum_down_tcp;
    *last_down_utp_total = sum_down_utp;
    drain
}

/// Connection gauge readings (1s tick; the same judgment face as
/// getPeers): inbound/outbound by registration-time
/// `PeerMeta::inbound`; the transport dimension splits by
/// registration-time `PeerMeta::transport` (after µTP joined the data
/// plane, the utp slots are live readings); choke mirror = not in the
/// unchoke set (the same rule as `peer_snapshots` am_choking).
pub(super) fn count_peer_gauges(faces: &[FaceState]) -> (u64, u64, u64, u64, u64) {
    let (mut tcp_in, mut tcp_out, mut utp_in, mut utp_out, mut choked) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    for face in faces {
        for ps in face.peer_state.values() {
            let Some(meta) = ps.meta.as_ref() else {
                continue;
            };
            match (meta.transport, meta.inbound) {
                (Transport::Tcp, true) => tcp_in += 1,
                (Transport::Tcp, false) => tcp_out += 1,
                (Transport::Utp, true) => utp_in += 1,
                (Transport::Utp, false) => utp_out += 1,
            }
            if !ps.am_unchoked {
                choked += 1;
            }
        }
    }
    (tcp_in, tcp_out, utp_in, utp_out, choked)
}

/// tellStatus live snapshot synthesis (face 0 is the canonical face:
/// hybrid dual faces always have equal piece counts and completion
/// state propagates across faces — the BEP52-aligned mapping).
pub(super) fn status_snapshot(
    faces: &[FaceState],
    piece_len: u32,
    total_length: u64,
    upload_length: u64,
    upload_speed: u64,
    download_speed: u64,
    recovery_files: Vec<(u32, RecoveryStatus)>,
) -> EngineStatusSnapshot {
    let (completed, bitfield, num_pieces, connections, seeder) = match faces.first() {
        None => (0, None, 0, 0, true),
        Some(f) => {
            let completed = f.progress.completed_length();
            let bitfield = if f.piece_count > 0 {
                Some(f.bitfield_bytes())
            } else {
                None
            };
            let connections: usize = faces.iter().map(|x| x.peers.len()).sum();
            (
                completed,
                bitfield,
                f.piece_count as u64,
                connections,
                faces.iter().all(|x| x.completed),
            )
        }
    };
    EngineStatusSnapshot {
        total_length,
        completed_length: completed,
        download_speed,
        upload_speed,
        upload_length,
        connections: u64::try_from(connections).unwrap_or(u64::MAX),
        bitfield,
        piece_length: piece_len,
        num_pieces,
        seeder,
        recovery_files,
    }
}

/// getPeers snapshot synthesis (the gatherPeer reading face: the full
/// picture, in registration order).
/// `&mut`: SessionSpeedCalc::calculate prunes old slots (SpeedCalc
/// semantics).
pub(super) fn peer_snapshots(
    faces: &mut [FaceState],
    want_bitfield: bool,
) -> Vec<EnginePeerSnapshot> {
    let mut out = Vec::new();
    for face in faces {
        for cuid in &face.peer_cuids {
            let Some(ps) = face.peer_state.get_mut(cuid) else {
                continue;
            };
            let Some(meta) = ps.meta.as_ref() else {
                continue;
            };
            // Bitmaps materialize on demand: internal faces such as
            // seeder counts (want_bitfield=false) do zero packing (no
            // transient N/8 x P allocation).
            let bits = if want_bitfield {
                pack_bitfield(face.peer_avail.get(cuid), face.piece_count)
            } else {
                Vec::new()
            };
            let (down_speed, up_speed) = match ps.rates.as_mut() {
                Some(r) => {
                    let now = Instant::now();
                    (r.down.calculate(now), r.up.calculate(now))
                }
                None => (0, 0),
            };
            // Seeder judgment = the bitmap row is all ones (an is_full
            // bit-word read, the same verdict as re-parsing the old
            // packed bytes bit by bit; missing row / zero piece count ->
            // false).
            let seeder =
                face.piece_count > 0 && face.peer_avail.get(cuid).is_some_and(|row| row.is_full());
            out.push(EnginePeerSnapshot {
                peer_id: meta.peer_id,
                ip: meta.ip.to_string(),
                // Inbound connections report port 0 (aria2 isIncomingPeer branch).
                port: if meta.inbound { 0 } else { meta.port },
                bitfield: bits,
                // Live bool (aria2 RpcMethodImpl.cc reads the current
                // am-choking state; a stale last_unchoke after a re-choke
                // must still read true — the same face as tick's am_unchoked).
                am_choking: !ps.am_unchoked,
                peer_choking: false,
                download_speed: down_speed,
                upload_speed: up_speed,
                seeder,
                transport: meta.transport,
                crypto: meta.crypto,
            });
        }
    }
    out
}

/// getServers tracker-row snapshot (union of the shadow row sets;
/// hybrid dual faces dedup by the same tier/url).
pub(super) fn tracker_snapshots(faces: &[FaceState]) -> Vec<TrackerRow> {
    let mut seen = std::collections::BTreeSet::new();
    let mut rows = Vec::new();
    for face in faces {
        let mut sorted: Vec<&TrackerRow> = face.mirror.rows.values().collect();
        sorted.sort_by(|a, b| (a.tier, &a.url).cmp(&(b.tier, &b.url)));
        for row in sorted {
            if seen.insert((row.tier, row.url.clone())) {
                rows.push(row.clone());
            }
        }
    }
    rows
}
/// tellStatus live snapshot (the query seam; the
/// [`crate::command::EngineHandle::query_status::query_status`]
/// payload). Field semantics = the aria2 gatherProgressCommon reading
/// face (RpcMethodImpl.cc); the payload keeps core numeric semantics
/// (JSON stringification lives in the RPC layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineStatusSnapshot {
    /// Face-canonical total (v1/hybrid = the v1 layout total including
    /// pad; the announce `left` denominator).
    pub total_length: u64,
    /// Synthesized completion (face 0: sum of per-file verified +
    /// padding counted as full).
    pub completed_length: u64,
    /// 10s sliding-window speed (SpeedCalc.cc scope; sampled via the
    /// per-peer delta bridge).
    pub download_speed: u64,
    pub upload_speed: u64,
    /// Session cumulative upload (including the pre-start baseline, the
    /// allTimeUploadLength scope).
    pub upload_length: u64,
    /// Active connection count (sum over all faces).
    pub connections: u64,
    /// Synthesized bitfield (face 0; `Some` = valid bits > 0 — the same
    /// rule as aria2 `getBitfieldLength() > 0`; v1 real bitmap / v2
    /// synthesized concat, SPEC §4.4).
    pub bitfield: Option<Vec<u8>>,
    pub piece_length: u32,
    /// Global piece count (face 0's piece count; hybrid dual faces are
    /// always equal — the BEP52-aligned mapping).
    pub num_pieces: u64,
    /// All faces complete (the aria2 group->isSeeder judgment face).
    pub seeder: bool,
    /// getFiles missing-layer projection: files involving a missing
    /// layer -> recovery status (0-based meta.files position; the
    /// enum's semantics live in
    /// `run::recovery_admit::recovery_file_states_core`, the rendered
    /// words in the RPC adapter). The session face merges it into the
    /// file entries (the RPC layer `recoveryStatus` key); an empty
    /// table = this module has no missing-layer files.
    pub recovery_files: Vec<(u32, RecoveryStatus)>,
}

/// getPeers per-connection snapshot (the query seam; the
/// [`crate::command::EngineHandle::query_peers::query_peers`] payload;
/// field semantics = gatherPeer, RpcMethodImpl.cc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnginePeerSnapshot {
    /// Peer id captured at the handshake (20B raw; the RPC layer
    /// torrentPercentEncode).
    pub peer_id: [u8; 20],
    pub ip: String,
    /// Peer port (inbound = 0, the same rule as aria2).
    pub port: u16,
    /// Peer possession bitmap (accumulated from local bitfield/have
    /// events; trailing pad bits zero).
    pub bitfield: Vec<u8>,
    /// Mirror of the local choke decision (not in the unchoke set =
    /// true; the BEP3 initial state).
    pub am_choking: bool,
    /// Value domain narrowed (same rule): PeerTask internal state has no
    /// reading face here; this engine's dispatch face never backs off on
    /// peer choke, so false always = the engine's effective assumption
    /// for every connection.
    pub peer_choking: bool,
    /// Per-peer 10s sliding-window speed (per-peer counters + 1s
    /// sampling).
    pub download_speed: u64,
    pub upload_speed: u64,
    /// Possession = all pieces (the bitmap judgment face).
    pub seeder: bool,
    /// Transport kind (live at registration: a snapshot at the
    /// dial/accept connection points; SPEC §8.2 values tcp|utp, direct
    /// map to the RPC layer `getPeers.transport` field).
    pub transport: Transport,
    /// MSE encryption level (the real negotiated result; a legacy direct
    /// connection = Plain).
    pub crypto: CryptoLevel,
}

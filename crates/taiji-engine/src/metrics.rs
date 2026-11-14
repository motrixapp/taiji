//! Session-level metric counting face.
//!
//! The implementation lives in the engine subtree (engine feed points
//! are the main producers; the session side re-exports this module as
//! `session::metrics` - the existing public path is unchanged).
//!
//! Upstream anchor mapping: docs/design/engine.md
//!
//! Structure and discipline:
//! - Every counter is an `AtomicU64` (Relaxed). Feed points sit inside
//! existing main-loop/teardown paths: no locks, nothing held across
//! await, no channels. A missed feed point = a missing metric, never
//! a false one.
//! - [`SessionMetrics`] is created by the session actor (session
//! namespace, SessionActor) and shared to the rpc rendering face via
//! SessionHandle (read side [`SessionMetrics::snapshot`]); the engine
//! side receives it through [`crate::EngineConfig::stats`].
//! - Multi-engine gauge aggregation: one [`EngineGauges`] slot per
//! engine (registered on spawn; when an engine finishes it drops the
//! slot and the `Weak` dies); rendering sums the live slots.
//! SET-semantics gauges never go straight into shared atomics - that
//! would let engines overwrite each other.
//! - Label cardinality is bounded: method names anchor to the
//! `RPC_METHODS` list (unknown methods collapse into a single
//! `unknown` slot); state/transport/direction/family/kind are fixed
//! enums; gids/paths/info-hashes/URLs/rpc-secrets never become
//! labels.
//! - io registry aggregation seam: taiji-io transport metrics (the DNS
//! family) are pulled into the snapshot over the existing core->io
//! dependency edge - io feed points write the process-default
//! registry (`taiji_io::metrics::registry_default`, the default
//! binding in [`SessionMetrics::new`]; tests inject an isolated
//! registry via [`SessionMetrics::with_io_metrics`]).
//! - Snapshot fields are independent Relaxed loads = a NON-consistent
//! snapshot (no cross-field atomicity; projection tests must not
//! assert cross-field consistency).
//!
//! Data sources (session/task/connection/RPC families ride the existing
//! snapshots and feed points; hash-pool/WrCache/protocol faces are
//! engine-internal increments):
//!
//! | Metric | Feed point |
//! |---|---|
//! | `taiji_build_info` / `_session_uptime_seconds` | rpc side (process facts) |
//! | `taiji_panic_total` | actor engine watcher (`JoinError::is_panic`) |
//! | `taiji_torrent_completed_total` | actor terminal teardown (retire into the table) |
//! | `taiji_torrent_bytes_total{direction}` | engine 1s tick delta bridge + terminal flush |
//! | `taiji_peer_supply_bytes_total{transport}` | same bridge, split by transport (tcp|utp) |
//! | `taiji_peer_connections{...}` / `_choked` | engine 1s tick (peer_meta/choke mirror) |
//! | `taiji_peer_bans_total` | engine `BanBook::enact` (ban enforcement) |
//! | `taiji_redial_attempts_total` / `_connected_total` | redial arm (dial / handshake ok) |
//! | `taiji_redial_pool_size` | engine 1s gauge tick |
//! | `taiji_dht_nodes{family}` | engine 1s tick (`DhtHandle::snapshot`) |
//! | `taiji_dht_queries_total{kind}` | engine 1s tick (`DhtSnapshot` deltas) |
//! | `taiji_dht_inbound_*_total` | engine 1s tick (`DhtSnapshot` inbound deltas) |
//! | `taiji_tracker_announces_total{result}` | engine tracker event attribution |
//! | `taiji_mse_handshakes_total{result}` | engine peer registration (negotiation result) |
//! | `taiji_utp_packets_total{kind}` | engine 1s tick (`UdpDemuxHandle::stats`) |
//! | `taiji_hashpool_queue_depth` | engine 1s tick (pipeline block channel occupancy) |
//! | `taiji_block_arena_lease_hits_total` / `_alloc_fallback_total` | pool reuse / fallback (SET) |
//! | `taiji_block_arena_outstanding_blocks` / `_cap_bytes` | pool watermark gauge / cap bytes |
//! | `taiji_block_inflight` | engine 1s tick (sink in, pipeline batch-ack out; observation only) |
//! | `taiji_hashpool_blocks_verified_total` | store pipeline piece-verify pass point |
//! | `taiji_wrcache_events_total{kind}` | store pipeline (flush / evict) |
//! | `taiji_wrcache_evict_bytes_total` | batch buffering (`evicted_unverified_bytes` delta) |
//! | `taiji_spill_write_bytes_total` / `_read_bytes_total` | spill faces (`spill_*` deltas) |
//! | `taiji_spill_readback_pieces_total` | same delta feed; 0 with spill off |
//! | `taiji_spill_fallback_destroy_bytes_total` | over-budget destroy bytes (same delta) |
//! | `taiji_holepunch_*` | seven counters (1s seed tick delta bridge) |
//! | `taiji_peer_leaves_total{reason}` | five leave reasons (leave arm) |
//! | `taiji_store_write_calls_total` | write calls at the `dyn DiskWriter` boundary |
//! | `taiji_peer_inflight_depth` / `_active` | 1s tick per-connection sampling |
//! | `taiji_block_stage_seconds{stage}` | pipeline buffer + verify_pool verify/write |
//! | `taiji_http_extents_active` / `taiji_http_conn_aimd` | HttpTask 500ms tick (SET) |
//! | `taiji_http_stolen_total` | HttpTask tick (coordinator grants) |
//! | `taiji_rpc_requests_total{method}` / `_duration` | rpc dispatch entry (process_call) |
//! | `taiji_rpc_conn_rejected_total{scope}` | rpc transport guard (conn gate) |
//! | `taiji_rpc_auth_fail_total` | rpc transport guard (auth failure) |
//! | `taiji_dns_*` | taiji-io shared resolver (io registry seam) |
//!
//! Value-range narrowing (honest terms; the ranges below are revised
//! alongside the observation faces):
//! - `taiji_dht_queries_total{kind}`: kind = the four BEP5 message-set
//! kinds (ping/find_node/get_peers/announce_peer, [`DhtQueryKind`]);
//! fed from per-kind engine counts at the `send_query`
//! outbound-enqueue success point -> `DhtSnapshot` additive fields ->
//! 1s tick deltas (v4/v6 dual-engine sum semantics; utp packet counts
//! follow the same pattern).
//! - `taiji_wrcache_events_total` has only `flush`/`evict`: `hit` is a
//! cache-internal folding concept (in-place cell extension) with no
//! event source on the core side.
//! - `taiji_torrents{state}` state = the six aria2 status values
//! (StatusKind, session namespace), not nine; derived by the rpc layer
//! from the existing query faces (getGlobalStat/tellWaiting/
//! tellStopped share the source).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

// rpc method promise list (single source = taiji_domain::methods;
// cross-crate consumers read this source directly - slot counts are not
// duplicated; the method-surface vocabulary depends engine -> domain).
use taiji_domain::methods::RPC_METHODS;

/// DNS resolve-latency histogram buckets (re-exported from the io side
/// over the aggregation seam - the rpc rendering face depends on core
/// one-way, so the bucket tables stay reachable; values and consumer
/// anchors live at the io-side definitions).
pub use taiji_io::metrics::{
    DISK_FINALIZE_BUCKETS_SECONDS, DNS_RESOLVE_BUCKETS_SECONDS,
    HTTP_CONN_ESTABLISH_BUCKETS_SECONDS, HTTP_REQUEST_BUCKETS_SECONDS,
    HTTP_SLOWSTART_BUCKETS_SECONDS, PERSIST_COMMIT_BUCKETS_SECONDS,
};

/// rpc request latency histogram buckets (seconds; upper bound
/// inclusive). Neighbor buckets around the 50ms mark keep p99 readable.
pub const RPC_DURATION_BUCKETS_SECONDS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Per-peer in-flight depth histogram buckets (blocks; upper bound
/// inclusive). Observes the 1s engine tick sampling each connection's
/// `RequestBook` pending count. The buckets cover the adaptive window's
/// whole value range (doubling up to the `UB_MAX_OUTSTANDING_REQUEST`
/// 256 cap): the 0/1/2 low end is finest (the main serialization
/// diagnostic range), the high end aligns with the window cap.
pub const PEER_INFLIGHT_BUCKETS: &[f64] =
    &[0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0];

/// Block/piece processing stage duration histogram buckets (seconds;
/// upper bound inclusive). Three stages share one table
/// ([`BlockStage`]): buffer once per 16KiB block (low buckets down to
/// 100us); verify/write once per completed piece (healthy 256KiB-piece
/// shapes are ms-scale, write stalls reach seconds - high buckets to
/// 5s).
pub const BLOCK_STAGE_BUCKETS_SECONDS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Block/piece processing stages (the `taiji_block_stage_seconds{stage}`
/// label range; the duration decomposition of the parse -> verify ->
/// cache-write hot path, fed at [`SessionMetrics::observe_block_stage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStage {
    /// Buffer face (once per 16KiB block): range/dup checks + v2 block
    /// hash + digest accumulation + write-cache merge (inline in the
    /// store pipeline's batched `push_block_pooled_at`; eviction
    /// bookkeeping happens in this segment).
    Buffer,
    /// Verify face (once per completed piece): whole-piece assembly +
    /// primary format hash (+ hybrid cross-check), on a verify_pool
    /// worker.
    Verify,
    /// Write face (once per completed piece): the `write_at` syscall
    /// segment with cells in goff order (on a verify_pool worker; the
    /// coalescing window does not change these terms - total write
    /// syscall time only).
    Write,
}

impl BlockStage {
    /// Slot index (internal storage is flattened in this order).
    fn slot(self) -> usize {
        match self {
            BlockStage::Buffer => 0,
            BlockStage::Verify => 1,
            BlockStage::Write => 2,
        }
    }

    /// Label text (the rpc rendering face's value range).
    pub fn as_str(self) -> &'static str {
        match self {
            BlockStage::Buffer => "buffer",
            BlockStage::Verify => "verify",
            BlockStage::Write => "write",
        }
    }
}

/// Slot-count constants for rpc methods (the full `RPC_METHODS` set + one unknown slot).
pub const RPC_METHOD_SLOTS: usize = RPC_METHODS.len() + 1;

/// Slot index for unknown methods (dispatch calls outside `RPC_METHODS`,
/// including arbitrary client-invented names - collapsed into one slot
/// against high-cardinality injection).
pub const RPC_METHOD_SLOT_UNKNOWN: usize = RPC_METHODS.len();

/// WrCache event kinds (the observable core subset of the kind range;
/// `hit` has no event source - see the module doc's range note).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrcacheEvent {
    /// Piece written to disk (the store pipeline's PieceWritten path;
    /// counted at the write-segment verdict - the hash-pass Verified
    /// phase does not count a flush).
    Flush,
    /// Cache over limit, unverified piece evicted (drop and refetch;
    /// the `PieceAbortedUnverified` path).
    Evict,
}

/// DHT outbound query kind (`taiji_dht_queries_total{kind}` label range;
/// the four BEP5 KRPC message kinds, an isomorphic projection of bt::dht
/// `MessageKind` - anchored at bt::dht `message.rs`
/// `MessageKind::method_name`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhtQueryKind {
    /// ping (liveness / reachability probe).
    Ping,
    /// find_node (node lookup / bucket refresh).
    FindNode,
    /// get_peers (peer discovery).
    GetPeers,
    /// announce_peer (peer advertisement, fire-and-forget).
    AnnouncePeer,
}

/// Per-engine gauge slots (SET semantics; refreshed by the engine 1s
/// tick, rendering sums live slots). The engine holds the Arc; on exit
/// it drops and the registry's `Weak` dies.
#[derive(Debug, Default)]
pub struct EngineGauges {
    /// TCP connection counts (inbound/outbound).
    conn_tcp_in: AtomicU64,
    conn_tcp_out: AtomicU64,
    /// uTP connection counts (inbound/outbound).
    conn_utp_in: AtomicU64,
    conn_utp_out: AtomicU64,
    /// Mirror of our choke decisions (not in the unchoke set = choked;
    /// the same judgment as getPeers am_choking).
    conn_choked: AtomicU64,
    /// Redial pool size (main-loop pool len; bounded by REDIAL_POOL_CAP).
    redial_pool_size: AtomicU64,
    /// DHT routing table node count (v4/v6 entry; SET per family engine-side).
    dht_nodes_v4: AtomicU64,
    dht_nodes_v6: AtomicU64,
    /// Store pipeline block channel occupancy depth (the hash/write
    /// in-flight upper bound, 256-capacity terms).
    hash_queue_depth: AtomicU64,
    /// Peers with in-flight requests > 0 (1s tick samples each
    /// connection's RequestBook pending count; depth > 0 counts 1, then
    /// SETs this slot - the live "is this peer actually supplying"
    /// criterion during download).
    peer_inflight_active: AtomicU64,
    /// Block pool: hit/fallback totals (SET snapshots) + watermark/cap
    /// gauges (sum of face readings; a None face = pool off, zero).
    block_arena_lease_hits_total: AtomicU64,
    block_arena_alloc_fallback_total: AtomicU64,
    block_arena_outstanding_blocks: AtomicU64,
    block_arena_cap_bytes: AtomicU64,
    /// Pre-registered in-flight block counter (data-plane bypass,
    /// observation only; the sum of all faces' `FaceState::block_inflight`:
    /// sink increments, pipeline batch-ack decrements - the "handed to
    /// the pipeline, not yet confirmed" watermark; feeds no decisions).
    block_inflight: AtomicU64,
}

impl EngineGauges {
    pub(crate) fn set_conn_tcp(&self, inbound: u64, outbound: u64) {
        self.conn_tcp_in.store(inbound, Ordering::Relaxed);
        self.conn_tcp_out.store(outbound, Ordering::Relaxed);
    }

    pub(crate) fn set_conn_utp(&self, inbound: u64, outbound: u64) {
        self.conn_utp_in.store(inbound, Ordering::Relaxed);
        self.conn_utp_out.store(outbound, Ordering::Relaxed);
    }

    pub(crate) fn set_conn_choked(&self, choked: u64) {
        self.conn_choked.store(choked, Ordering::Relaxed);
    }

    pub(crate) fn set_redial_pool_size(&self, size: u64) {
        self.redial_pool_size.store(size, Ordering::Relaxed);
    }

    pub(crate) fn set_dht_nodes(&self, v4: u64, v6: u64) {
        self.dht_nodes_v4.store(v4, Ordering::Relaxed);
        self.dht_nodes_v6.store(v6, Ordering::Relaxed);
    }

    pub(crate) fn set_hash_queue_depth(&self, depth: u64) {
        self.hash_queue_depth.store(depth, Ordering::Relaxed);
    }

    /// Peers with in-flight requests > 0 (1s tick SET).
    pub(crate) fn set_peer_inflight_active(&self, active: u64) {
        self.peer_inflight_active.store(active, Ordering::Relaxed);
    }

    /// Block pool four readings (1s tick, summed over faces, then SET).
    pub(crate) fn set_block_arena(
        &self,
        hits: u64,
        fallbacks: u64,
        outstanding: u64,
        cap_bytes: u64,
    ) {
        self.block_arena_lease_hits_total
            .store(hits, Ordering::Relaxed);
        self.block_arena_alloc_fallback_total
            .store(fallbacks, Ordering::Relaxed);
        self.block_arena_outstanding_blocks
            .store(outstanding, Ordering::Relaxed);
        self.block_arena_cap_bytes
            .store(cap_bytes, Ordering::Relaxed);
    }

    /// Pre-registered in-flight block counter (1s tick, summed over all faces, SET).
    pub(crate) fn set_block_inflight(&self, inflight: u64) {
        self.block_inflight.store(inflight, Ordering::Relaxed);
    }

    fn conn_tcp_in(&self) -> u64 {
        self.conn_tcp_in.load(Ordering::Relaxed)
    }

    fn conn_tcp_out(&self) -> u64 {
        self.conn_tcp_out.load(Ordering::Relaxed)
    }

    fn conn_utp_in(&self) -> u64 {
        self.conn_utp_in.load(Ordering::Relaxed)
    }

    fn conn_utp_out(&self) -> u64 {
        self.conn_utp_out.load(Ordering::Relaxed)
    }

    fn conn_choked(&self) -> u64 {
        self.conn_choked.load(Ordering::Relaxed)
    }

    fn redial_pool_size(&self) -> u64 {
        self.redial_pool_size.load(Ordering::Relaxed)
    }

    fn dht_nodes_v4(&self) -> u64 {
        self.dht_nodes_v4.load(Ordering::Relaxed)
    }

    fn dht_nodes_v6(&self) -> u64 {
        self.dht_nodes_v6.load(Ordering::Relaxed)
    }

    fn hash_queue_depth(&self) -> u64 {
        self.hash_queue_depth.load(Ordering::Relaxed)
    }

    fn peer_inflight_active(&self) -> u64 {
        self.peer_inflight_active.load(Ordering::Relaxed)
    }

    fn block_arena_lease_hits_total(&self) -> u64 {
        self.block_arena_lease_hits_total.load(Ordering::Relaxed)
    }

    fn block_arena_alloc_fallback_total(&self) -> u64 {
        self.block_arena_alloc_fallback_total
            .load(Ordering::Relaxed)
    }

    fn block_arena_outstanding_blocks(&self) -> u64 {
        self.block_arena_outstanding_blocks.load(Ordering::Relaxed)
    }

    fn block_arena_cap_bytes(&self) -> u64 {
        self.block_arena_cap_bytes.load(Ordering::Relaxed)
    }

    fn block_inflight(&self) -> u64 {
        self.block_inflight.load(Ordering::Relaxed)
    }
}

/// Per-HTTP-task gauge slots (SET semantics; refreshed by the driver's
/// 500ms tick, rendering sums live slots). The task holds the Arc;
/// teardown drops it and the registry's `Weak` dies.
/// Sources: extents_active = worker claim/finish write-back (HttpLive);
/// aimd = the driver tick polling the coordinator's `RuntimeStats`
/// (the AIMD snapshot's same ledger, the `conn_aimd` gauge; the static
/// baseline is an honest constant zero).
#[derive(Debug, Default)]
pub struct HttpTaskGauges {
    extents_active: AtomicU64,
    aimd_connections: AtomicU64,
}

impl HttpTaskGauges {
    /// Cross-crate feed point: the session http_task face injects readings (only write site).
    pub fn set(&self, extents_active: u64, aimd_connections: u64) {
        self.extents_active.store(extents_active, Ordering::Relaxed);
        self.aimd_connections
            .store(aimd_connections, Ordering::Relaxed);
    }

    fn extents_active(&self) -> u64 {
        self.extents_active.load(Ordering::Relaxed)
    }

    fn aimd_connections(&self) -> u64 {
        self.aimd_connections.load(Ordering::Relaxed)
    }
}

/// `/metrics` rendering input snapshot (the product of
/// [`SessionMetrics::snapshot`]; plain u64 values - the rpc side's
/// table-driven tests construct this struct directly).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Process uptime seconds (counted from SessionActor creation).
    pub uptime_seconds: u64,
    /// Engine task panic count (JoinError::is_panic; aborts do not count).
    pub panic_total: u64,
    /// Task completions (terminal entry into the DownloadResult table with status=Complete).
    pub torrent_completed_total: u64,
    /// Session byte counts (delta-bridge terms; cross-session baselines
    /// excluded - historical traffic belongs to the progress-row
    /// baseline, not this process's counter).
    pub bytes_down_total: u64,
    pub bytes_up_total: u64,
    /// Supply bytes per transport family (label = the fixed transport
    /// enum tcp|utp, no host/gid. Terms = wire received bytes; the two
    /// families sum to the same source as `bytes_down_total`).
    pub bytes_down_tcp_total: u64,
    pub bytes_down_utp_total: u64,
    /// Connection gauges (sum of engine slots).
    pub conn_tcp_in: u64,
    pub conn_tcp_out: u64,
    pub conn_utp_in: u64,
    pub conn_utp_out: u64,
    pub conn_choked: u64,
    /// Ban enforcement total (BanBook::enact).
    pub peer_bans_total: u64,
    /// Redial dial attempts (spawn point of the redial scan arm).
    pub redial_attempts_total: u64,
    /// Redial handshake successes (the Connected result convergence point).
    pub redial_connected_total: u64,
    /// Redial pool size (sum of engine slots; bounded by REDIAL_POOL_CAP).
    pub redial_pool_size: u64,
    /// DHT routing table node counts (sum of engine slots, per family).
    pub dht_nodes_v4: u64,
    pub dht_nodes_v6: u64,
    /// DHT outbound queries per kind (engine 1s tick deltas from
    /// `DhtSnapshot` fields; v4/v6 engines summed. Feed = the bt::dht
    /// `send_query` outbound-enqueue success point - encode failures and
    /// closed channels do not count).
    pub dht_queries_ping_total: u64,
    pub dht_queries_find_node_total: u64,
    pub dht_queries_get_peers_total: u64,
    pub dht_queries_announce_peer_total: u64,
    /// DHT inbound observation family (engine 1s tick deltas
    /// from the `DhtSnapshot` counting face,
    /// v4/v6 engines summed): every datagram at `handle_packet` entry /
    /// queries admitted to decode / y="r"|"e" frames dropped before
    /// decode on no pending transaction (the early-drop rate reading:
    /// packets_total - queries_total ≈ replies+errors, of which
    /// unmatched_drops never paid a decode). Observation only.
    pub dht_inbound_packets_total: u64,
    pub dht_inbound_queries_total: u64,
    pub dht_inbound_unmatched_drops_total: u64,
    /// Tracker announce attribution (IntervalUpdated=ok / AnnounceFailed=fail).
    pub tracker_ok_total: u64,
    pub tracker_fail_total: u64,
    /// MSE negotiation results (registration point; arc4 = encryption
    /// established, plain = cleartext).
    pub mse_arc4_total: u64,
    pub mse_plain_total: u64,
    /// uTP packet counts (demux stats deltas: forwarded into the uTP
    /// stack / dropped on full queue).
    pub utp_recv_total: u64,
    pub utp_drop_total: u64,
    /// Store pipeline block channel occupancy (sum of engine slots).
    pub hashpool_queue_depth: u64,
    /// Pre-registered in-flight block counter (sum of engine slots -
    /// sink increments, pipeline batch-ack decrements; observation only).
    pub block_inflight: u64,
    /// Verified block count (16KiB granularity; pieces credited by their byte count).
    pub blocks_verified_total: u64,
    /// WrCache events (flush/evict - see the module doc's range note).
    pub wrcache_flush_total: u64,
    pub wrcache_evict_total: u64,
    /// Evicted unverified data, cumulative bytes (feed = the store
    /// pipeline's before/after delta of
    /// `VerifiedWriter::evicted_unverified_bytes`).
    pub wrcache_evict_bytes_total: u64,
    /// Spill cumulative write bytes (sidecar on disk; feed = the store
    /// pipeline's delta of `VerifiedWriter::spill_write_bytes`).
    pub spill_write_bytes_total: u64,
    /// Spill cumulative readback bytes (read back at assembly; same delta feed).
    pub spill_read_bytes_total: u64,
    /// Readback piece count (the readback hit-rate numerator; the
    /// denominator = this value + the residual-eviction count in
    /// `wrcache_evict_total` - with spill on, the evict event is the
    /// "residual eviction" count).
    pub spill_readback_pieces_total: u64,
    /// Over-budget fallback destroy bytes (FIFO victims + unabsorbed
    /// fallback ledger; feed = the store pipeline's delta of
    /// `VerifiedWriter::spill_fallback_destroy_bytes`; constant 0 with
    /// spill off).
    pub spill_fallback_destroy_bytes_total: u64,
    /// Holepunch observation family, seven counters (semantics in the
    /// [`SessionMetrics`] field docs; 1s seed tick delta bridge, rendered
    /// as `taiji_holepunch_*_total`).
    pub holepunch_rendezvous_sent_total: u64,
    pub holepunch_relayed_connects_total: u64,
    pub holepunch_punch_dials_total: u64,
    pub holepunch_punch_established_total: u64,
    pub holepunch_introducer_hits_total: u64,
    pub holepunch_no_introducer_total: u64,
    pub holepunch_punch_failed_nat_total: u64,
    /// Peer leave reasons, five kinds (rendered as
    /// `taiji_peer_leaves_total{reason=local|peer-closed|io|protocol|cancelled}`;
    /// semantics in the same-named [`SessionMetrics`] field docs).
    pub peer_leaves_local_total: u64,
    pub peer_leaves_peer_closed_total: u64,
    pub peer_leaves_io_total: u64,
    pub peer_leaves_protocol_total: u64,
    pub peer_leaves_cancelled_total: u64,
    /// Block pool reuse hits (sum of engine slot SETs; a None face = pool off, zero).
    pub block_arena_lease_hits_total: u64,
    /// Block pool direct-allocation fallbacks (over budget / over main
    /// bucket - the observable exception path of "zero mallocs per
    /// block").
    pub block_arena_alloc_fallback_total: u64,
    /// Block pool watermark (currently leased-out blocks, sum of engine slot SETs).
    pub block_arena_outstanding_blocks: u64,
    /// Block pool cap bytes (a component of the face unverified-byte budget, sum of face caps).
    pub block_arena_cap_bytes: u64,
    /// Per-peer in-flight depth histogram (1s engine tick samples each
    /// connection's pending request count; indices align with
    /// [`PEER_INFLIGHT_BUCKETS`]).
    pub peer_inflight_depth_buckets: Vec<u64>,
    pub peer_inflight_depth_count: u64,
    /// Depth total (the histogram `_sum` counts blocks - mean =
    /// sum/count, p99 read via the bucket table).
    pub peer_inflight_depth_sum: u64,
    /// Peers with in-flight requests > 0 (sum of engine slots, last observed value).
    pub peer_inflight_active: u64,
    /// Block/piece stage duration histograms (buffer once per 16KiB
    /// block, verify/write once per completed piece; indices align with
    /// [`BLOCK_STAGE_BUCKETS_SECONDS`]).
    pub block_buffer_seconds_buckets: Vec<u64>,
    pub block_buffer_seconds_count: u64,
    pub block_buffer_seconds_sum_us: u64,
    pub block_verify_seconds_buckets: Vec<u64>,
    pub block_verify_seconds_count: u64,
    pub block_verify_seconds_sum_us: u64,
    pub block_write_seconds_buckets: Vec<u64>,
    pub block_write_seconds_count: u64,
    pub block_write_seconds_sum_us: u64,
    /// HTTP scheduling face: in-flight extents (live task
    /// slots), AIMD connection count (live task slots; the static
    /// baseline is constant zero), steal grants (single decision point).
    /// `conn_aimd{task}` renders as one aggregate gauge (label
    /// cardinality discipline - gid never becomes a label; the per-task
    /// face goes through tellStatus's `http` sub-dictionary).
    pub http_extents_active: u64,
    pub http_conn_aimd: u64,
    pub http_stolen_total: u64,
    /// rpc method call counts (index = the `RPC_METHODS` position; last slot = unknown methods).
    pub rpc_requests: Vec<u64>,
    /// rpc latency histogram: non-cumulative bucket counts (indices align
    /// with [`RPC_DURATION_BUCKETS_SECONDS`]) + total count + total
    /// duration in microseconds (the renderer converts to seconds and
    /// cumulative buckets).
    pub rpc_duration_buckets: Vec<u64>,
    pub rpc_duration_count: u64,
    pub rpc_duration_sum_us: u64,
    /// Exposure guard counts: connection-gate overruns (scope=total /
    /// scope=per_ip series) and token+Basic auth failures (merged
    /// failures, no IP label - label cardinality discipline; see the rpc
    /// metrics rendering face). The backoff-active gauge is derived by
    /// rpc at render time, not through this snapshot.
    pub rpc_conn_rejected_total_scope_total: u64,
    pub rpc_conn_rejected_total_scope_per_ip: u64,
    pub rpc_auth_fail_total: u64,
    /// DNS resolver family (io registry seam; feed terms and the
    /// double-count policy in the `taiji_io::dns` module doc's metrics
    /// section). Multiple atomics, non-consistent snapshot - each count
    /// read independently; do not assert cross-field consistency.
    /// DNS work and admission counters; active/queued track physical system queries.
    pub dns_network_changes_total: u64,
    pub dns_backend_queries_total: u64,
    pub dns_coalesced_total: u64,
    pub dns_negative_hits_total: u64,
    pub dns_capacity_rejected_total: u64,
    pub dns_system_queries_total: u64,
    pub dns_system_coalesced_total: u64,
    pub dns_system_active: u64,
    pub dns_system_queued: u64,
    pub dns_lookups_hit_total: u64,
    pub dns_lookups_miss_total: u64,
    pub dns_lookups_error_total: u64,
    pub dns_lookups_timeout_total: u64,
    pub dns_family_mix_v4_only_total: u64,
    pub dns_family_mix_v6_only_total: u64,
    pub dns_family_mix_dual_total: u64,
    pub dns_events_evict_ttl_total: u64,
    pub dns_events_evict_capacity_total: u64,
    /// DNS resolve latency histogram: non-cumulative bucket counts
    /// (indices align with [`DNS_RESOLVE_BUCKETS_SECONDS`]) + count +
    /// microseconds total (converted at render time).
    pub dns_resolve_seconds_buckets: Vec<u64>,
    pub dns_resolve_seconds_count: u64,
    pub dns_system_queue_seconds_buckets: Vec<u64>,
    pub dns_system_queue_seconds_count: u64,
    pub dns_system_queue_seconds_sum_us: u64,
    pub dns_system_lookup_seconds_buckets: Vec<u64>,
    pub dns_system_lookup_seconds_count: u64,
    pub dns_system_lookup_seconds_sum_us: u64,
    pub dns_resolve_seconds_sum_us: u64,
    /// HTTP transport family (io registry seam; feed terms in the taiji-io
    /// `metrics` module's `HttpMetrics` doc - errors count each failed
    /// request, retries/source switches amplify N-fold; the two dns slots
    /// = NXDOMAIN-class terminal / self-healing shapes). Multiple
    /// atomics, non-consistent snapshot.
    pub http_errors_dns_permanent_total: u64,
    pub http_errors_dns_transient_total: u64,
    pub http_errors_timeout_total: u64,
    pub http_errors_tls_total: u64,
    pub http_errors_connect_total: u64,
    pub http_errors_refused_total: u64,
    pub http_errors_reset_total: u64,
    pub http_errors_http_4xx_total: u64,
    pub http_errors_http_5xx_total: u64,
    pub http_retries_total: u64,
    /// Extent reassignment without stealing (the current writer genuinely
    /// gave it back; steal grants go through `http_stolen_total` - the
    /// two terms are mutually exclusive).
    pub http_extent_reassign_total: u64,
    pub http_mirror_demote_total: u64,
    pub http_mirror_remove_total: u64,
    pub http_mirror_restore_total: u64,
    pub http_stall_detected_total: u64,
    pub http_aimd_grow_total: u64,
    pub http_aimd_shrink_total: u64,
    /// HTTP request latency, two-phase histograms (first_byte/total;
    /// non-cumulative bucket counts + count + microseconds, indices align
    /// with [`HTTP_REQUEST_BUCKETS_SECONDS`]).
    pub http_request_first_byte_buckets: Vec<u64>,
    pub http_request_first_byte_count: u64,
    pub http_request_first_byte_sum_us: u64,
    pub http_request_total_buckets: Vec<u64>,
    pub http_request_total_count: u64,
    pub http_request_total_sum_us: u64,
    /// Slow-start duration histogram (indices align with
    /// [`HTTP_SLOWSTART_BUCKETS_SECONDS`]; tasks that never reach steady
    /// state are not sampled - right-censoring, honest terms).
    pub http_slowstart_seconds_buckets: Vec<u64>,
    pub http_slowstart_seconds_count: u64,
    pub http_slowstart_seconds_sum_us: u64,
    /// New connection establishments (io registry seam; pool reuse never
    /// passes the connector - the count naturally counts new connections
    /// only; always equal to `http_conn_establish_seconds_count`. DNS
    /// component deduction in the taiji-io `metrics` module's
    /// `HttpMetrics` note).
    pub http_conn_establishments_total: u64,
    /// Connection-establishment latency histogram (DNS+TCP+TLS combined;
    /// indices align with [`HTTP_CONN_ESTABLISH_BUCKETS_SECONDS`]).
    pub http_conn_establish_seconds_buckets: Vec<u64>,
    pub http_conn_establish_seconds_count: u64,
    pub http_conn_establish_seconds_sum_us: u64,
    /// Disk/finalize family (io registry seam; terms in the taiji-io
    /// `metrics` module's `DiskMetrics` doc - `sink_inflight` = concurrent
    /// in-flight write_at calls (not queue depth); `finalize_seconds
    /// {op=file_fsync}` counts every task file fsync (the merged terms,
    /// including the 2s snapshot beat). Multiple atomics, non-consistent
    /// snapshot.
    pub disk_sink_writes_total: u64,
    pub disk_sink_writes_bytes_total: u64,
    pub disk_sink_inflight: u64,
    /// Finalize histogram, three ops (file_fsync/fsync_dir/rename;
    /// non-cumulative bucket counts + count + microseconds, indices align
    /// with [`DISK_FINALIZE_BUCKETS_SECONDS`]).
    pub disk_finalize_file_fsync_buckets: Vec<u64>,
    pub disk_finalize_file_fsync_count: u64,
    pub disk_finalize_file_fsync_sum_us: u64,
    pub disk_finalize_fsync_dir_buckets: Vec<u64>,
    pub disk_finalize_fsync_dir_count: u64,
    pub disk_finalize_fsync_dir_sum_us: u64,
    pub disk_finalize_rename_buckets: Vec<u64>,
    pub disk_finalize_rename_count: u64,
    pub disk_finalize_rename_sum_us: u64,
    /// prealloc `set_len` latency histogram (same bucket table).
    pub disk_prealloc_seconds_buckets: Vec<u64>,
    pub disk_prealloc_seconds_count: u64,
    pub disk_prealloc_seconds_sum_us: u64,
    /// Persistence family (io registry seam; feed = the store
    /// PersistWriter thread via the `PersistObserve` callback seam).
    /// `queue_depth` = the write thread's latest observation (gauge SET
    /// semantics; the reading can be stale at low traffic); commit
    /// duration = one job's in-thread execution time (channel queueing
    /// excluded). Multiple atomics, non-consistent snapshot.
    pub persist_queue_depth: u64,
    /// Persistence commit latency histogram (indices align with
    /// [`PERSIST_COMMIT_BUCKETS_SECONDS`]).
    pub persist_commit_seconds_buckets: Vec<u64>,
    pub persist_commit_seconds_count: u64,
    pub persist_commit_seconds_sum_us: u64,
}

impl Default for MetricsSnapshot {
    fn default() -> Self {
        MetricsSnapshot {
            uptime_seconds: 0,
            panic_total: 0,
            torrent_completed_total: 0,
            bytes_down_total: 0,
            bytes_up_total: 0,
            bytes_down_tcp_total: 0,
            bytes_down_utp_total: 0,
            conn_tcp_in: 0,
            conn_tcp_out: 0,
            conn_utp_in: 0,
            conn_utp_out: 0,
            conn_choked: 0,
            peer_bans_total: 0,
            redial_attempts_total: 0,
            redial_connected_total: 0,
            redial_pool_size: 0,
            dht_nodes_v4: 0,
            dht_nodes_v6: 0,
            dht_queries_ping_total: 0,
            dht_queries_find_node_total: 0,
            dht_queries_get_peers_total: 0,
            dht_queries_announce_peer_total: 0,
            dht_inbound_packets_total: 0,
            dht_inbound_queries_total: 0,
            dht_inbound_unmatched_drops_total: 0,
            tracker_ok_total: 0,
            tracker_fail_total: 0,
            mse_arc4_total: 0,
            mse_plain_total: 0,
            utp_recv_total: 0,
            utp_drop_total: 0,
            hashpool_queue_depth: 0,
            block_inflight: 0,
            blocks_verified_total: 0,
            wrcache_flush_total: 0,
            wrcache_evict_total: 0,
            wrcache_evict_bytes_total: 0,
            spill_write_bytes_total: 0,
            spill_read_bytes_total: 0,
            spill_readback_pieces_total: 0,
            spill_fallback_destroy_bytes_total: 0,
            holepunch_rendezvous_sent_total: 0,
            holepunch_relayed_connects_total: 0,
            holepunch_punch_dials_total: 0,
            holepunch_punch_established_total: 0,
            holepunch_introducer_hits_total: 0,
            holepunch_no_introducer_total: 0,
            holepunch_punch_failed_nat_total: 0,
            peer_leaves_local_total: 0,
            peer_leaves_peer_closed_total: 0,
            peer_leaves_io_total: 0,
            peer_leaves_protocol_total: 0,
            peer_leaves_cancelled_total: 0,
            block_arena_lease_hits_total: 0,
            block_arena_alloc_fallback_total: 0,
            block_arena_outstanding_blocks: 0,
            block_arena_cap_bytes: 0,
            peer_inflight_depth_buckets: vec![0; PEER_INFLIGHT_BUCKETS.len()],
            peer_inflight_depth_count: 0,
            peer_inflight_depth_sum: 0,
            peer_inflight_active: 0,
            block_buffer_seconds_buckets: vec![0; BLOCK_STAGE_BUCKETS_SECONDS.len()],
            block_buffer_seconds_count: 0,
            block_buffer_seconds_sum_us: 0,
            block_verify_seconds_buckets: vec![0; BLOCK_STAGE_BUCKETS_SECONDS.len()],
            block_verify_seconds_count: 0,
            block_verify_seconds_sum_us: 0,
            block_write_seconds_buckets: vec![0; BLOCK_STAGE_BUCKETS_SECONDS.len()],
            block_write_seconds_count: 0,
            block_write_seconds_sum_us: 0,
            http_extents_active: 0,
            http_conn_aimd: 0,
            http_stolen_total: 0,
            rpc_requests: vec![0; RPC_METHOD_SLOTS],
            rpc_duration_buckets: vec![0; RPC_DURATION_BUCKETS_SECONDS.len()],
            rpc_duration_count: 0,
            rpc_duration_sum_us: 0,
            rpc_conn_rejected_total_scope_total: 0,
            rpc_conn_rejected_total_scope_per_ip: 0,
            rpc_auth_fail_total: 0,
            dns_network_changes_total: 0,
            dns_backend_queries_total: 0,
            dns_coalesced_total: 0,
            dns_negative_hits_total: 0,
            dns_capacity_rejected_total: 0,
            dns_system_queries_total: 0,
            dns_system_coalesced_total: 0,
            dns_system_active: 0,
            dns_system_queued: 0,
            dns_lookups_hit_total: 0,
            dns_lookups_miss_total: 0,
            dns_lookups_error_total: 0,
            dns_lookups_timeout_total: 0,
            dns_family_mix_v4_only_total: 0,
            dns_family_mix_v6_only_total: 0,
            dns_family_mix_dual_total: 0,
            dns_events_evict_ttl_total: 0,
            dns_events_evict_capacity_total: 0,
            dns_resolve_seconds_buckets: vec![0; DNS_RESOLVE_BUCKETS_SECONDS.len()],
            dns_resolve_seconds_count: 0,
            dns_system_queue_seconds_buckets: vec![0; DNS_RESOLVE_BUCKETS_SECONDS.len()],
            dns_system_queue_seconds_count: 0,
            dns_system_queue_seconds_sum_us: 0,
            dns_system_lookup_seconds_buckets: vec![0; DNS_RESOLVE_BUCKETS_SECONDS.len()],
            dns_system_lookup_seconds_count: 0,
            dns_system_lookup_seconds_sum_us: 0,
            dns_resolve_seconds_sum_us: 0,
            http_errors_dns_permanent_total: 0,
            http_errors_dns_transient_total: 0,
            http_errors_timeout_total: 0,
            http_errors_tls_total: 0,
            http_errors_connect_total: 0,
            http_errors_refused_total: 0,
            http_errors_reset_total: 0,
            http_errors_http_4xx_total: 0,
            http_errors_http_5xx_total: 0,
            http_retries_total: 0,
            http_extent_reassign_total: 0,
            http_mirror_demote_total: 0,
            http_mirror_remove_total: 0,
            http_mirror_restore_total: 0,
            http_stall_detected_total: 0,
            http_aimd_grow_total: 0,
            http_aimd_shrink_total: 0,
            http_request_first_byte_buckets: vec![0; HTTP_REQUEST_BUCKETS_SECONDS.len()],
            http_request_first_byte_count: 0,
            http_request_first_byte_sum_us: 0,
            http_request_total_buckets: vec![0; HTTP_REQUEST_BUCKETS_SECONDS.len()],
            http_request_total_count: 0,
            http_request_total_sum_us: 0,
            http_slowstart_seconds_buckets: vec![0; HTTP_SLOWSTART_BUCKETS_SECONDS.len()],
            http_slowstart_seconds_count: 0,
            http_slowstart_seconds_sum_us: 0,
            http_conn_establishments_total: 0,
            http_conn_establish_seconds_buckets: vec![0; HTTP_CONN_ESTABLISH_BUCKETS_SECONDS.len()],
            http_conn_establish_seconds_count: 0,
            http_conn_establish_seconds_sum_us: 0,
            disk_sink_writes_total: 0,
            disk_sink_writes_bytes_total: 0,
            disk_sink_inflight: 0,
            disk_finalize_file_fsync_buckets: vec![0; DISK_FINALIZE_BUCKETS_SECONDS.len()],
            disk_finalize_file_fsync_count: 0,
            disk_finalize_file_fsync_sum_us: 0,
            disk_finalize_fsync_dir_buckets: vec![0; DISK_FINALIZE_BUCKETS_SECONDS.len()],
            disk_finalize_fsync_dir_count: 0,
            disk_finalize_fsync_dir_sum_us: 0,
            disk_finalize_rename_buckets: vec![0; DISK_FINALIZE_BUCKETS_SECONDS.len()],
            disk_finalize_rename_count: 0,
            disk_finalize_rename_sum_us: 0,
            disk_prealloc_seconds_buckets: vec![0; DISK_FINALIZE_BUCKETS_SECONDS.len()],
            disk_prealloc_seconds_count: 0,
            disk_prealloc_seconds_sum_us: 0,
            persist_queue_depth: 0,
            persist_commit_seconds_buckets: vec![0; PERSIST_COMMIT_BUCKETS_SECONDS.len()],
            persist_commit_seconds_count: 0,
            persist_commit_seconds_sum_us: 0,
        }
    }
}

/// PersistWriter observation bridge (the store `PersistObserve` callback
/// seam -> the io metric family): store and io do not depend on each
/// other; core (depending on both) is the single adapter. Feed
/// discipline follows the SharedDns pattern - constructible and
/// injectable ([`Self::for_registry`]); production assembly takes the
/// process-default registry ([`persist_observer_default`]); tests
/// inject an isolated instance via [`Self::for_registry`].
#[derive(Debug)]
pub struct PersistMetricsBridge {
    registry: Arc<taiji_io::metrics::MetricsRegistry>,
}

impl taiji_store::persist::PersistObserve for PersistMetricsBridge {
    fn observe_commit(&self, elapsed: Duration) {
        self.registry.persist().observe_commit(elapsed);
    }

    fn set_queue_depth(&self, depth: u64) {
        self.registry.persist().set_queue_depth(depth);
    }
}

impl PersistMetricsBridge {
    /// Bind a specific registry (the test injection seam).
    pub fn for_registry(
        registry: Arc<taiji_io::metrics::MetricsRegistry>,
    ) -> Arc<dyn taiji_store::persist::PersistObserve> {
        Arc::new(PersistMetricsBridge { registry })
    }
}

/// Production assembly point: the observation callbacks bound to the
/// process-default registry (injected where PersistWriter opens; the
/// session side's `persist::import` carries the seam).
pub fn persist_observer_default() -> Arc<dyn taiji_store::persist::PersistObserve> {
    PersistMetricsBridge::for_registry(taiji_io::metrics::registry_default())
}

/// Session-level metric counting face (atomics only; structure in the module docs).
#[derive(Debug)]
pub struct SessionMetrics {
    started: Instant,
    torrent_completed_total: AtomicU64,
    bytes_down_total: AtomicU64,
    bytes_up_total: AtomicU64,
    /// Supply bytes per transport family (feed = the engine counting
    /// bridge's 1s/2s ticks + terminal-value flush + the leave arm's
    /// final-value delta, closed at the single point
    /// `engine::run::tick::note_supply_down`). Terms = wire received
    /// bytes (counted on Piece frame receipt, duplicates included); the
    /// two families sum to `bytes_down_total` for cross-checking.
    bytes_down_tcp_total: AtomicU64,
    bytes_down_utp_total: AtomicU64,
    /// Endgame cumulative in-flight duration (redundancy-economics
    /// observation face; feed = dispatch enter/exit edges + 1s tick and
    /// terminal-flush checkpoint slices).
    endgame_ms_total: AtomicU64,
    /// Duplicate blocks received during the endgame window (a subset of
    /// `duplicate_blocks_total`; the paired denominator =
    /// [`Self::buffered_blocks_endgame_total`]). Read by the shutdown
    /// summary, not rendered into /metrics (the same frozen-domain
    /// precedent as `duplicate_blocks_total`).
    duplicate_blocks_endgame_total: AtomicU64,
    /// Blocks entering the buffer path during the endgame window (as
    /// above; the denominator of the duplicate/total received ratio.
    /// Late-block drops for verified pieces stay out of both families -
    /// consistent with the totals family).
    buffered_blocks_endgame_total: AtomicU64,
    /// Last-mile tail duration (observation face; first moment missing
    /// pieces <= `BH_ENDGAME_LASTMILE` (N) -> completion. Feed = one-time
    /// accounting at face completion + the `checkpoint_endgame` bridge,
    /// the same site as `endgame_ms_total`). Constant 0 in the N=0
    /// fallback (the gate never triggers, no reading). Read by the
    /// shutdown summary (the endgame economics row `last_mile_secs`).
    last_mile_ms_total: AtomicU64,
    /// Last-8-pieces window duration (first moment missing pieces <= 8 ->
    /// completion; a fixed tail window independent of N. Feed as above).
    /// Read by the shutdown summary (the endgame economics row
    /// `last8_pieces_secs`).
    last8_pieces_ms_total: AtomicU64,
    /// Write locality, adjacent arm (observation only): pieces whose
    /// index±1 neighbor was already written at write time (contiguous
    /// goff runs). Feed = the `on_piece_written` face-level total + the
    /// `checkpoint_endgame` take-and-reset bridge (the same site as
    /// `endgame_ms_total`). Read by the shutdown summary (the endgame
    /// economics row `write_adj`); not in [`MetricsSnapshot`] (the same
    /// frozen-domain precedent as `last_mile_ms_total`).
    write_adjacent_total: AtomicU64,
    /// The isolated arm: pieces with neither index±1 neighbor written at
    /// write time (first pieces / jumps; the `write_iso` field) - the
    /// write-run continuity criterion for the adjacent-chain softening
    /// knob `BH_ADJACENT_SKIP_N` (the adjacent/(adjacent+isolated)
    /// ratio).
    write_isolated_total: AtomicU64,
    panic_total: AtomicU64,
    peer_bans_total: AtomicU64,
    redial_attempts_total: AtomicU64,
    redial_connected_total: AtomicU64,
    /// Peer leave reasons, five kinds (feed = the engine leave arm
    /// `handle_peer_left`, the leave event carrying
    /// [`crate::LeaveKind`]) - the `taiji_peer_leaves_total{reason}`
    /// rendering family. Cancelled = engine teardown (excluded from
    /// diagnostic denominators).
    peer_leave_local_total: AtomicU64,
    peer_leave_peer_closed_total: AtomicU64,
    peer_leave_io_total: AtomicU64,
    peer_leave_protocol_total: AtomicU64,
    peer_leave_cancelled_total: AtomicU64,
    mse_arc4_total: AtomicU64,
    mse_plain_total: AtomicU64,
    tracker_ok_total: AtomicU64,
    tracker_fail_total: AtomicU64,
    utp_recv_total: AtomicU64,
    utp_drop_total: AtomicU64,
    /// DHT outbound queries per kind (engine tick snapshot-delta feed).
    dht_queries_ping_total: AtomicU64,
    dht_queries_find_node_total: AtomicU64,
    dht_queries_get_peers_total: AtomicU64,
    dht_queries_announce_peer_total: AtomicU64,
    /// DHT inbound observation family (engine tick snapshot-delta feed;
    /// the inbound counting face's consumption seam - counters only, no
    /// control-flow read anywhere).
    dht_inbound_packets_total: AtomicU64,
    dht_inbound_queries_total: AtomicU64,
    dht_inbound_unmatched_drops_total: AtomicU64,
    blocks_verified_total: AtomicU64,
    wrcache_flush_total: AtomicU64,
    wrcache_evict_total: AtomicU64,
    /// Evicted unverified data, cumulative bytes (pipeline batch-buffer delta feed).
    wrcache_evict_bytes_total: AtomicU64,
    /// Spill three faces (write bytes / readback bytes / readback pieces; same delta feed).
    spill_write_bytes_total: AtomicU64,
    spill_read_bytes_total: AtomicU64,
    spill_readback_pieces_total: AtomicU64,
    /// Over-budget fallback destroy bytes (victims + unabsorbed arms; same delta feed).
    spill_fallback_destroy_bytes_total: AtomicU64,
    /// Store completed-piece write calls issued (`write_at` +
    /// `write_vectored_at` at the `dyn DiskWriter` boundary; single-file
    /// layout = syscall count; multi-file layouts issue one write_at
    /// syscall per segment - this counts the issuing side). The
    /// cross-check reading for "write syscalls per block" - feed = the
    /// pipeline Written verdict arm (the group's first Written carries
    /// the whole group's call count; see verify_pool `run_piece_jobs`
    /// write-observation granularity).
    store_write_calls_total: AtomicU64,
    /// Per-peer in-flight depth histogram (1s tick sampled feed).
    peer_inflight_depth_count: AtomicU64,
    peer_inflight_depth_sum: AtomicU64,
    peer_inflight_depth_buckets: Vec<AtomicU64>,
    /// Block/piece stage durations (three stages share the bucket table,
    /// slots flattened by [`BlockStage::slot`] - count/sum 3 slots each,
    /// buckets 3xN slots).
    block_stage_count: Vec<AtomicU64>,
    block_stage_sum_us: Vec<AtomicU64>,
    block_stage_buckets: Vec<AtomicU64>,
    /// Discovery counts (engine-level contribution observation): every
    /// discovered address passing the self-connect guard into the dial
    /// decision (tracker/DHT/PEX counted at the same point).
    discovered_peers_total: AtomicU64,
    /// Of those, PEX-sourced (discovered via ut_pex messages) count.
    discovered_peers_pex: AtomicU64,
    /// Cross-peer duplicate blocks benignly dropped (counted at both the
    /// store pipeline's caller-side bitmap filter and the store coverage
    /// backstop. aria2 receive-path filter anchor:
    /// `BtPieceMessage.cc` `piece->hasBlock(...)` -> "Already have
    /// this block."). Not in [`MetricsSnapshot`] - the /metrics
    /// rendering face is a frozen domain, same precedent as
    /// [`Self::discovered_peers`].
    duplicate_blocks_total: AtomicU64,
    /// Late blocks for verified pieces (observation face): the pipeline
    /// drain arm's `writer_verified` pre-filter - the block arrived when
    /// its piece had already passed verification, so the data is dropped
    /// with zero redundancy value. The criterion face of the
    /// cancel-on-verified fix (before/after comparison readings).
    /// Not in [`MetricsSnapshot`] (the `duplicate_blocks_total`
    /// frozen-domain precedent).
    late_blocks_verified_total: AtomicU64,
    /// Two-phase in-flight bookkeeping observation family (observation
    /// only; 1s seed tick delta bridge, the engine-side process atomics
    /// are the only writers): (1) arrival stage transitions (network ->
    /// storage); (2) arrival channel-full degradations (staying InFlight,
    /// self-healing); (3) store_pending guard violations, entry-hits
    /// (Settling older than the guard, zero new wire). Not in
    /// [`MetricsSnapshot`] (the `late_blocks_verified_total` frozen-domain
    /// precedent).
    block_arrivals_total: AtomicU64,
    ledger_degrades_total: AtomicU64,
    store_pending_guard_total: AtomicU64,
    /// Holepunch observation family (observation only; 1s seed tick delta
    /// bridge, the engine-side process atomics are the only writers -
    /// each trigger/relay/punch-dial feed point has a single source, the
    /// `engine::run::holepunch` module docs): rendezvous sent / relay
    /// introductions / punch dials / punch handshakes established /
    /// introducer hits / no introducer / punch window exhausted silently
    /// (NAT attribution). Rendered as the seven `taiji_holepunch_*_total`
    /// series.
    hp_rendezvous_sent_total: AtomicU64,
    hp_relayed_connects_total: AtomicU64,
    hp_punch_dials_total: AtomicU64,
    hp_punch_established_total: AtomicU64,
    hp_introducer_hits_total: AtomicU64,
    hp_no_introducer_total: AtomicU64,
    hp_punch_failed_nat_total: AtomicU64,
    /// rpc method slots (length fixed after construction -> element addresses are stable).
    rpc_requests: Vec<AtomicU64>,
    rpc_duration_count: AtomicU64,
    rpc_duration_sum_us: AtomicU64,
    rpc_duration_buckets: Vec<AtomicU64>,
    /// Exposure guard counts (rpc transport feed points: connection-gate overrun / auth failure).
    rpc_conn_rejected_total: AtomicU64,
    rpc_conn_rejected_per_ip: AtomicU64,
    rpc_auth_fail_total: AtomicU64,
    /// HTTP steal grants (single decision point; the driver feeds
    /// increments polled from runtime stats, the `stolen_total` counter).
    http_stolen_total: AtomicU64,
    /// Engine gauge registry (`Weak`: slots die automatically on engine
    /// exit; the lock guards only the table structure, never held across
    /// await). Length bound = the number of engines ever activated.
    engine_gauges: Mutex<Vec<Weak<EngineGauges>>>,
    /// HTTP task gauge registry (same; bound = the number of HttpTasks ever active).
    http_task_gauges: Mutex<Vec<Weak<HttpTaskGauges>>>,
    /// io metric registry (the aggregation seam; `new()` binds the
    /// process-default instance - the same source as io-side production
    /// assembly; tests inject an isolated instance via
    /// [`Self::with_io_metrics`]).
    io_metrics: Arc<taiji_io::metrics::MetricsRegistry>,
}

impl Default for SessionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Cumulative histogram quantile (us): the Prometheus
/// histogram_quantile convention - find the first cumulative bucket
/// reaching `q x total`, linear interpolation assuming a uniform
/// distribution within the bucket. `bounds` = bucket upper bounds
/// (seconds, inclusive); returns us.
fn hist_quantile_us(buckets: &[u64], total: u64, bounds: &[f64], q: f64) -> Option<f64> {
    if total == 0 || buckets.is_empty() {
        return None;
    }
    let target = q * total as f64;
    let mut cum = 0u64;
    let mut lower = 0f64;
    for (i, &b) in buckets.iter().enumerate() {
        let upper = bounds.get(i).copied().unwrap_or(0.0);
        if b > 0 && cum as f64 + b as f64 >= target {
            let frac = (target - cum as f64) / b as f64;
            return Some((lower + (upper - lower) * frac) * 1_000_000.0);
        }
        cum += b;
        lower = upper;
    }
    // Overflow bucket (past every bound): a tail approximation with the
    // last bound as the lower edge (no upper-bound information; the last
    // bound is taken - acceptable for a summary).
    Some(lower * 1_000_000.0)
}

/// Compact log format for us values: us below 1ms, otherwise ms (two decimals).
fn fmt_us(v_us: f64) -> String {
    if v_us >= 1_000.0 {
        format!("{:.2}ms", v_us / 1_000.0)
    } else {
        format!("{v_us:.0}us")
    }
}

impl SessionMetrics {
    pub fn new() -> Self {
        Self::with_io_metrics(taiji_io::metrics::registry_default())
    }

    /// Construct with an injected io metric registry (the aggregation-seam
    /// test face: an isolated registry shares nothing with the process
    /// default - parallel tests pollute nothing).
    pub fn with_io_metrics(io_metrics: Arc<taiji_io::metrics::MetricsRegistry>) -> Self {
        SessionMetrics {
            started: Instant::now(),
            torrent_completed_total: AtomicU64::new(0),
            bytes_down_total: AtomicU64::new(0),
            bytes_up_total: AtomicU64::new(0),
            bytes_down_tcp_total: AtomicU64::new(0),
            bytes_down_utp_total: AtomicU64::new(0),
            endgame_ms_total: AtomicU64::new(0),
            duplicate_blocks_endgame_total: AtomicU64::new(0),
            buffered_blocks_endgame_total: AtomicU64::new(0),
            last_mile_ms_total: AtomicU64::new(0),
            last8_pieces_ms_total: AtomicU64::new(0),
            write_adjacent_total: AtomicU64::new(0),
            write_isolated_total: AtomicU64::new(0),
            panic_total: AtomicU64::new(0),
            peer_bans_total: AtomicU64::new(0),
            redial_attempts_total: AtomicU64::new(0),
            redial_connected_total: AtomicU64::new(0),
            peer_leave_local_total: AtomicU64::new(0),
            peer_leave_peer_closed_total: AtomicU64::new(0),
            peer_leave_io_total: AtomicU64::new(0),
            peer_leave_protocol_total: AtomicU64::new(0),
            peer_leave_cancelled_total: AtomicU64::new(0),
            mse_arc4_total: AtomicU64::new(0),
            mse_plain_total: AtomicU64::new(0),
            tracker_ok_total: AtomicU64::new(0),
            tracker_fail_total: AtomicU64::new(0),
            utp_recv_total: AtomicU64::new(0),
            utp_drop_total: AtomicU64::new(0),
            dht_queries_ping_total: AtomicU64::new(0),
            dht_queries_find_node_total: AtomicU64::new(0),
            dht_queries_get_peers_total: AtomicU64::new(0),
            dht_queries_announce_peer_total: AtomicU64::new(0),
            dht_inbound_packets_total: AtomicU64::new(0),
            dht_inbound_queries_total: AtomicU64::new(0),
            dht_inbound_unmatched_drops_total: AtomicU64::new(0),
            blocks_verified_total: AtomicU64::new(0),
            wrcache_flush_total: AtomicU64::new(0),
            wrcache_evict_total: AtomicU64::new(0),
            wrcache_evict_bytes_total: AtomicU64::new(0),
            spill_write_bytes_total: AtomicU64::new(0),
            spill_read_bytes_total: AtomicU64::new(0),
            spill_readback_pieces_total: AtomicU64::new(0),
            spill_fallback_destroy_bytes_total: AtomicU64::new(0),
            store_write_calls_total: AtomicU64::new(0),
            peer_inflight_depth_count: AtomicU64::new(0),
            peer_inflight_depth_sum: AtomicU64::new(0),
            peer_inflight_depth_buckets: (0..PEER_INFLIGHT_BUCKETS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            block_stage_count: (0..3).map(|_| AtomicU64::new(0)).collect(),
            block_stage_sum_us: (0..3).map(|_| AtomicU64::new(0)).collect(),
            block_stage_buckets: (0..3 * BLOCK_STAGE_BUCKETS_SECONDS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            discovered_peers_total: AtomicU64::new(0),
            discovered_peers_pex: AtomicU64::new(0),
            duplicate_blocks_total: AtomicU64::new(0),
            late_blocks_verified_total: AtomicU64::new(0),
            block_arrivals_total: AtomicU64::new(0),
            ledger_degrades_total: AtomicU64::new(0),
            store_pending_guard_total: AtomicU64::new(0),
            hp_rendezvous_sent_total: AtomicU64::new(0),
            hp_relayed_connects_total: AtomicU64::new(0),
            hp_punch_dials_total: AtomicU64::new(0),
            hp_punch_established_total: AtomicU64::new(0),
            hp_introducer_hits_total: AtomicU64::new(0),
            hp_no_introducer_total: AtomicU64::new(0),
            hp_punch_failed_nat_total: AtomicU64::new(0),
            rpc_requests: (0..RPC_METHOD_SLOTS).map(|_| AtomicU64::new(0)).collect(),
            rpc_duration_count: AtomicU64::new(0),
            rpc_duration_sum_us: AtomicU64::new(0),
            rpc_duration_buckets: (0..RPC_DURATION_BUCKETS_SECONDS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            rpc_conn_rejected_total: AtomicU64::new(0),
            rpc_conn_rejected_per_ip: AtomicU64::new(0),
            rpc_auth_fail_total: AtomicU64::new(0),
            http_stolen_total: AtomicU64::new(0),
            engine_gauges: Mutex::new(Vec::new()),
            http_task_gauges: Mutex::new(Vec::new()),
            io_metrics,
        }
    }

    /// Read-only handle to the io metric registry (the core-side feed
    /// seam - feed points such as the HTTP transport face's
    /// `request_seconds{phase=total}` book through the session metric
    /// face; the injection seam and the aggregation seam share the same
    /// source: tests assert deltas on the isolated registry from
    /// [`Self::with_io_metrics`], production uses the process default).
    pub fn io_registry(&self) -> &Arc<taiji_io::metrics::MetricsRegistry> {
        &self.io_metrics
    }

    /// Engine registration (once at spawn): returns the slot, held by the engine until exit.
    pub fn register_engine(&self) -> Arc<EngineGauges> {
        let slot = Arc::new(EngineGauges::default());
        if let Ok(mut table) = self.engine_gauges.lock() {
            table.push(Arc::downgrade(&slot));
        }
        slot
    }

    /// HTTP task registration (once at driver activation): returns the slot, held until teardown.
    pub fn register_http_task(&self) -> Arc<HttpTaskGauges> {
        let slot = Arc::new(HttpTaskGauges::default());
        if let Ok(mut table) = self.http_task_gauges.lock() {
            table.push(Arc::downgrade(&slot));
        }
        slot
    }

    // ---- Feed points (engine internals + rpc dispatch entry; Relaxed
    // monotonic counters need no sync order) ----

    /// Task terminal completions (actor teardown: terminal entry into
    /// the DownloadResult table with Complete).
    pub fn note_task_completed(&self) {
        self.torrent_completed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Byte delta bridge (engine 1s tick + terminal values; down/up directions).
    pub fn add_bytes(&self, down_delta: u64, up_delta: u64) {
        if down_delta > 0 {
            self.bytes_down_total
                .fetch_add(down_delta, Ordering::Relaxed);
        }
        if up_delta > 0 {
            self.bytes_up_total.fetch_add(up_delta, Ordering::Relaxed);
        }
    }

    /// Supply bytes per transport family (observation infrastructure;
    /// the single feed = `engine::run::tick::note_supply_down` - three
    /// counting bridges + the leave arm's final-value delta close at the
    /// same point; the two families always sum to `add_bytes`'s downlink
    /// terms). Label range = the fixed transport enum (tcp|utp), no
    /// host/gid.
    pub fn add_transport_down_bytes(&self, tcp_delta: u64, utp_delta: u64) {
        if tcp_delta > 0 {
            self.bytes_down_tcp_total
                .fetch_add(tcp_delta, Ordering::Relaxed);
        }
        if utp_delta > 0 {
            self.bytes_down_utp_total
                .fetch_add(utp_delta, Ordering::Relaxed);
        }
    }

    /// Supply bytes per transport family reading (shutdown summary consumer; `(tcp, utp)`).
    pub fn transport_supply_bytes(&self) -> (u64, u64) {
        (
            self.bytes_down_tcp_total.load(Ordering::Relaxed),
            self.bytes_down_utp_total.load(Ordering::Relaxed),
        )
    }

    /// Endgame in-flight duration slice accounting (dispatch enter/exit
    /// edges + 1s tick / terminal-flush checkpoints feed together;
    /// granularity = the checkpoint interval).
    pub fn note_endgame_elapsed(&self, elapsed: Duration) {
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        if ms > 0 {
            self.endgame_ms_total.fetch_add(ms, Ordering::Relaxed);
        }
    }

    /// Duplicate blocks during the endgame window (the pipeline
    /// duplicate-drop point reads the live flag to split).
    pub fn note_duplicate_blocks_endgame(&self, n: u64) {
        if n > 0 {
            self.duplicate_blocks_endgame_total
                .fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Buffered blocks during the endgame window (the pipeline
    /// batch-assembly point reads the live flag to split).
    pub fn note_buffered_blocks_endgame(&self, n: u64) {
        if n > 0 {
            self.buffered_blocks_endgame_total
                .fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Last-mile tail duration accounting (one-time feed at face
    /// completion; the `checkpoint_endgame` bridge closes the site).
    pub fn note_last_mile_elapsed(&self, elapsed: Duration) {
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        if ms > 0 {
            self.last_mile_ms_total.fetch_add(ms, Ordering::Relaxed);
        }
    }

    /// Last-8-pieces window duration accounting (same feed; the fixed tail-window reading).
    pub fn note_last8_pieces_elapsed(&self, elapsed: Duration) {
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        if ms > 0 {
            self.last8_pieces_ms_total.fetch_add(ms, Ordering::Relaxed);
        }
    }

    /// Write locality accounting (fed via the `checkpoint_endgame`
    /// bridge - the face-level take-and-reset delta; zero deltas pollute
    /// nothing).
    pub fn note_write_locality(&self, adjacent: u64, isolated: u64) {
        if adjacent > 0 {
            self.write_adjacent_total
                .fetch_add(adjacent, Ordering::Relaxed);
        }
        if isolated > 0 {
            self.write_isolated_total
                .fetch_add(isolated, Ordering::Relaxed);
        }
    }

    /// Write locality reading (consumed by the shutdown summary's endgame
    /// economics rows `write_adj`/`write_iso`): `(adjacent pieces
    /// written, isolated pieces written)` - the ratio is the criterion
    /// for how much chain softening improved write-run continuity.
    pub fn write_locality(&self) -> (u64, u64) {
        (
            self.write_adjacent_total.load(Ordering::Relaxed),
            self.write_isolated_total.load(Ordering::Relaxed),
        )
    }

    /// Endgame redundancy-economics reading (shutdown summary consumer):
    /// `(endgame seconds, window duplicates, window buffered, last-mile
    /// seconds, last-8-pieces seconds)` - the last two fields extend the
    /// tuple (existing field names unchanged): last-mile = first moment
    /// missing <= `BH_ENDGAME_LASTMILE` (N) -> completion (constant 0.0
    /// in the N=0 fallback); last8 = first moment missing <= 8 ->
    /// completion.
    pub fn endgame_economics(&self) -> (f64, u64, u64, f64, f64) {
        (
            self.endgame_ms_total.load(Ordering::Relaxed) as f64 / 1_000.0,
            self.duplicate_blocks_endgame_total.load(Ordering::Relaxed),
            self.buffered_blocks_endgame_total.load(Ordering::Relaxed),
            self.last_mile_ms_total.load(Ordering::Relaxed) as f64 / 1_000.0,
            self.last8_pieces_ms_total.load(Ordering::Relaxed) as f64 / 1_000.0,
        )
    }

    /// Engine task panic (JoinError::is_panic; abort/teardown does not count).
    pub fn note_panic(&self) {
        self.panic_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Peer ban enforced (BanBook::enact).
    pub fn note_peer_ban(&self) {
        self.peer_bans_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Redial dial attempt (the redial scan arm's spawn point).
    pub fn note_redial_attempt(&self) {
        self.redial_attempts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Redial handshake success (the Connected result convergence point).
    pub fn note_redial_connected(&self) {
        self.redial_connected_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Peer leave reason count (feed = the engine leave arm
    /// `handle_peer_left`, the leave event carrying a
    /// [`crate::LeaveKind`] five-way projection. Observation only - the
    /// quantitative carrier of connection-table attrition attribution
    /// (peer closed / we closed / transport error).
    /// pub(crate) = every feed point lives in this crate (the engine
    /// leave arm); LeaveKind is a crate-level type not promoted to the
    /// pub face).
    pub(crate) fn note_peer_leave(&self, kind: crate::LeaveKind) {
        let slot = match kind {
            crate::LeaveKind::Local => &self.peer_leave_local_total,
            crate::LeaveKind::PeerClosed => &self.peer_leave_peer_closed_total,
            crate::LeaveKind::Io => &self.peer_leave_io_total,
            crate::LeaveKind::Protocol => &self.peer_leave_protocol_total,
            crate::LeaveKind::Cancelled => &self.peer_leave_cancelled_total,
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }

    /// MSE negotiation result (the engine peer registration point; true = arc4 established).
    pub fn note_mse_result(&self, is_arc4: bool) {
        let slot = if is_arc4 {
            &self.mse_arc4_total
        } else {
            &self.mse_plain_total
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }

    /// Tracker announce attribution (true = IntervalUpdated success; false = failure).
    pub fn note_tracker_result(&self, ok: bool) {
        let slot = if ok {
            &self.tracker_ok_total
        } else {
            &self.tracker_fail_total
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }

    /// uTP packet delta (the caller converts demux stats sampled twice into a delta).
    pub fn add_utp_packets(&self, recv_delta: u64, drop_delta: u64) {
        if recv_delta > 0 {
            self.utp_recv_total.fetch_add(recv_delta, Ordering::Relaxed);
        }
        if drop_delta > 0 {
            self.utp_drop_total.fetch_add(drop_delta, Ordering::Relaxed);
        }
    }

    /// DHT outbound queries per kind (engine 1s tick: the caller converts
    /// `DhtSnapshot` counts sampled twice into a delta - each engine's
    /// delta accumulates into the sum; utp packet counts follow the same
    /// pattern).
    pub fn add_dht_queries(&self, kind: DhtQueryKind, delta: u64) {
        if delta == 0 {
            return;
        }
        let slot = match kind {
            DhtQueryKind::Ping => &self.dht_queries_ping_total,
            DhtQueryKind::FindNode => &self.dht_queries_find_node_total,
            DhtQueryKind::GetPeers => &self.dht_queries_get_peers_total,
            DhtQueryKind::AnnouncePeer => &self.dht_queries_announce_peer_total,
        };
        slot.fetch_add(delta, Ordering::Relaxed);
    }

    /// DHT inbound observation family (engine 1s tick: the caller
    /// converts the `DhtSnapshot` inbound counters sampled twice into
    /// deltas - per-engine deltas accumulate into the sum, the same
    /// pattern as [`Self::add_dht_queries`]). Counting only: nothing in
    /// any control flow reads these back.
    pub fn add_dht_inbound(&self, packets: u64, queries: u64, unmatched_drops: u64) {
        if packets > 0 {
            self.dht_inbound_packets_total
                .fetch_add(packets, Ordering::Relaxed);
        }
        if queries > 0 {
            self.dht_inbound_queries_total
                .fetch_add(queries, Ordering::Relaxed);
        }
        if unmatched_drops > 0 {
            self.dht_inbound_unmatched_drops_total
                .fetch_add(unmatched_drops, Ordering::Relaxed);
        }
    }

    /// Verified 16KiB block count (pieces credited by byte count, tail piece floored).
    pub fn add_blocks_verified(&self, blocks: u64) {
        if blocks > 0 {
            self.blocks_verified_total
                .fetch_add(blocks, Ordering::Relaxed);
        }
    }

    /// Discovery count (engine-level contribution observation): every
    /// discovered address **passing the self-connect guard** into the
    /// dial decision counts once - tracker (Peers events) / DHT
    /// (PeersFound) / PEX (ut_pex messages) all counted at the same point
    /// in the engine main loop; dial dedup and connection failure do not
    /// affect the discovery terms (discovery != connection success).
    pub fn note_peer_discovered(&self, source_pex: bool) {
        self.discovered_peers_total.fetch_add(1, Ordering::Relaxed);
        if source_pex {
            self.discovered_peers_pex.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Engine-level PEX contribution reading (read-only observation):
    /// `(pex-sourced, total discovered)`. Not in [`MetricsSnapshot`] -
    /// the /metrics rendering face is a frozen domain; current consumers
    /// are the discovery baseline and diagnostics.
    pub fn discovered_peers(&self) -> (u64, u64) {
        (
            self.discovered_peers_pex.load(Ordering::Relaxed),
            self.discovered_peers_total.load(Ordering::Relaxed),
        )
    }

    /// WrCache event (flush/evict).
    pub fn note_wrcache(&self, ev: WrcacheEvent) {
        let slot = match ev {
            WrcacheEvent::Flush => &self.wrcache_flush_total,
            WrcacheEvent::Evict => &self.wrcache_evict_total,
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }

    /// Evicted unverified data, cumulative bytes (feed = the store
    /// pipeline's before/after reads of
    /// `VerifiedWriter::evicted_unverified_bytes` - the delta is exact
    /// inside the single-writer pipeline, no concurrent consumer).
    pub fn note_wrcache_evict_bytes(&self, bytes: u64) {
        if bytes > 0 {
            self.wrcache_evict_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Spill three-face feed (write/readback bytes + readback pieces;
    /// feed = the store pipeline's before/after reads of
    /// `VerifiedWriter::spill_*` - the same delta method as
    /// [`Self::note_wrcache_evict_bytes`]). The readback hit-rate
    /// numerator = `readback_pieces`; the denominator = this value +
    /// `note_wrcache(WrcacheEvent::Evict)` (with spill on, that is the
    /// "residual eviction" count).
    pub fn note_spill(&self, write_bytes: u64, read_bytes: u64, readback_pieces: u64) {
        if write_bytes > 0 {
            self.spill_write_bytes_total
                .fetch_add(write_bytes, Ordering::Relaxed);
        }
        if read_bytes > 0 {
            self.spill_read_bytes_total
                .fetch_add(read_bytes, Ordering::Relaxed);
        }
        if readback_pieces > 0 {
            self.spill_readback_pieces_total
                .fetch_add(readback_pieces, Ordering::Relaxed);
        }
    }

    /// Over-budget fallback destroy bytes feed (feed = the store
    /// pipeline's before/after reads of
    /// `VerifiedWriter::spill_fallback_destroy_bytes` - the same delta
    /// method as [`Self::note_spill`]). With spill on, this count is the
    /// budget-attributed slice of "residual evictions" (a lower bound on
    /// destroy-and-refetch traffic).
    pub fn note_spill_fallback_destroy(&self, bytes: u64) {
        if bytes > 0 {
            self.spill_fallback_destroy_bytes_total
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Store completed-piece write-call issue feed (feed = the pipeline
    /// Written verdict arm - the group's first Written carries the whole
    /// group's call count; atomic direct add, zero allocation). The
    /// cross-check reading for "write syscalls per block".
    pub fn note_store_write_calls(&self, calls: u64) {
        if calls > 0 {
            self.store_write_calls_total
                .fetch_add(calls, Ordering::Relaxed);
        }
    }

    /// Store completed-piece write-call issue reading (observation face;
    /// the benchmark log output - the `tests/throughput.rs` final summary
    /// line).
    pub fn store_write_calls(&self) -> u64 {
        self.store_write_calls_total.load(Ordering::Relaxed)
    }

    /// Per-peer in-flight depth sample (feed = the engine 1s tick reading
    /// each connection's `PeerTaskHandle::in_flight` - a lock-free mirror
    /// of the RequestBook pending count; one observation per connection
    /// per tick, atomic direct adds, zero allocation).
    pub fn observe_peer_inflight(&self, depth: u64) {
        self.peer_inflight_depth_count
            .fetch_add(1, Ordering::Relaxed);
        self.peer_inflight_depth_sum
            .fetch_add(depth, Ordering::Relaxed);
        let secs = depth as f64;
        for (i, bound) in PEER_INFLIGHT_BUCKETS.iter().enumerate() {
            if secs <= *bound {
                if let Some(b) = self.peer_inflight_depth_buckets.get(i) {
                    b.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
        // Past every bucket: only count/sum (the renderer's +Inf bucket = count).
    }

    /// Block/piece stage duration observation (the spec's per-block
    /// duration decomposition lands as metric histograms - at tens of
    /// thousands of blocks per minute, per-block tracing span streams and
    /// formatted allocations are forbidden; two Instant::now calls plus
    /// atomic adds are the entire cost). Buffer once per 16KiB block;
    /// verify/write once per completed piece.
    pub fn observe_block_stage(&self, stage: BlockStage, elapsed: Duration) {
        let slot = stage.slot();
        if let Some(c) = self.block_stage_count.get(slot) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(s) = self.block_stage_sum_us.get(slot) {
            s.fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        }
        let secs = elapsed.as_secs_f64();
        let base = slot * BLOCK_STAGE_BUCKETS_SECONDS.len();
        for (i, bound) in BLOCK_STAGE_BUCKETS_SECONDS.iter().enumerate() {
            if secs <= *bound {
                if let Some(b) = self.block_stage_buckets.get(base + i) {
                    b.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
        // Past every bucket: only count/sum (the renderer's +Inf bucket = count).
    }

    /// Block three-stage histogram summary: the CLI bare-run download
    /// mode has no /metrics face, so on graceful shutdown (SIGTERM /
    /// completion) this method logs p50/p90/p99/mean/count per stage.
    /// Quantiles = cumulative-bucket linear interpolation (the Prometheus
    /// histogram_quantile convention: uniform distribution within the
    /// hit bucket, upper bounds inclusive; samples past every bucket
    /// approximate at the last bound - such samples carry no diagnostic
    /// value in a shutdown summary). All three stage counts zero = None
    /// (the caller logs no empty line).
    pub fn block_stage_log_summary(&self) -> Option<String> {
        let mut out = String::new();
        for (stage, slot) in [
            (BlockStage::Buffer, BlockStage::Buffer.slot()),
            (BlockStage::Verify, BlockStage::Verify.slot()),
            (BlockStage::Write, BlockStage::Write.slot()),
        ] {
            let count = self
                .block_stage_count
                .get(slot)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            if count == 0 {
                continue;
            }
            let sum_us = self
                .block_stage_sum_us
                .get(slot)
                .map(|c| c.load(Ordering::Relaxed))
                .unwrap_or(0);
            let base = slot * BLOCK_STAGE_BUCKETS_SECONDS.len();
            let buckets: Vec<u64> = (0..BLOCK_STAGE_BUCKETS_SECONDS.len())
                .map(|i| {
                    self.block_stage_buckets
                        .get(base + i)
                        .map(|c| c.load(Ordering::Relaxed))
                        .unwrap_or(0)
                })
                .collect();
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(stage.as_str());
            out.push_str("{count=");
            out.push_str(&count.to_string());
            for (label, q) in [
                ("mean", None),
                ("p50", Some(0.5)),
                ("p90", Some(0.9)),
                ("p99", Some(0.99)),
            ] {
                let v_us = match q {
                    None => sum_us as f64 / count as f64,
                    Some(q) => hist_quantile_us(&buckets, count, BLOCK_STAGE_BUCKETS_SECONDS, q)
                        .unwrap_or(0.0),
                };
                out.push_str(&format!(" {}={}", label, fmt_us(v_us)));
            }
            out.push('}');
        }
        if out.is_empty() { None } else { Some(out) }
    }

    /// Cross-peer duplicate blocks benignly dropped: counted at both the
    /// store pipeline's received-bitmap hit and the store coverage
    /// backstop (a drop is not a swallowed error - counting is the
    /// observation; the `BtPieceMessage.cc` receive-path filter anchor).
    pub fn note_duplicate_blocks(&self, n: u64) {
        if n > 0 {
            self.duplicate_blocks_total.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// HTTP steal grant delta (the driver tick polls the coordinator's
    /// runtime stats; monotonic cumulative, the `stolen_total` counter).
    pub fn note_http_stolen(&self, n: u64) {
        if n > 0 {
            self.http_stolen_total.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Duplicate-block drop reading (read-only observation; not rendered
    /// into /metrics, the `discovered_peers` precedent).
    pub fn duplicate_blocks_dropped(&self) -> u64 {
        self.duplicate_blocks_total.load(Ordering::Relaxed)
    }

    /// Late blocks for verified pieces delta (fed at the pipeline drain
    /// arm's `writer_verified` pre-filter - the fix's criterion face;
    /// rides the shutdown summary).
    pub fn note_late_blocks_verified(&self, n: u64) {
        if n > 0 {
            self.late_blocks_verified_total
                .fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Late blocks for verified pieces reading (read-only observation;
    /// not rendered into /metrics, the `duplicate_blocks_dropped`
    /// precedent).
    pub fn late_blocks_verified(&self) -> u64 {
        self.late_blocks_verified_total.load(Ordering::Relaxed)
    }

    /// Two-phase in-flight bookkeeping observation family delta (1s seed
    /// tick delta-bridge feed; observation only - arrival/degrade/guard
    /// counters, semantics in the field docs).
    pub fn note_two_phase_ledger(&self, arrivals: u64, degrades: u64, guard_hits: u64) {
        if arrivals > 0 {
            self.block_arrivals_total
                .fetch_add(arrivals, Ordering::Relaxed);
        }
        if degrades > 0 {
            self.ledger_degrades_total
                .fetch_add(degrades, Ordering::Relaxed);
        }
        if guard_hits > 0 {
            self.store_pending_guard_total
                .fetch_add(guard_hits, Ordering::Relaxed);
        }
    }

    /// Two-phase bookkeeping observation reading (read-only; shutdown
    /// summary and in-domain tests): `(block_arrivals, ledger_degrades,
    /// store_pending_guard)`.
    pub fn two_phase_ledger_obs(&self) -> (u64, u64, u64) {
        (
            self.block_arrivals_total.load(Ordering::Relaxed),
            self.ledger_degrades_total.load(Ordering::Relaxed),
            self.store_pending_guard_total.load(Ordering::Relaxed),
        )
    }

    /// Holepunch family delta (1s seed tick delta-bridge feed;
    /// observation only - seven counters, semantics in the field docs;
    /// monotonic cumulative).
    #[expect(
        clippy::too_many_arguments,
        reason = "seven holepunch counters delivered as one delta bridge; see the field docs"
    )]
    pub fn note_holepunch(
        &self,
        rendezvous_sent: u64,
        relayed_connects: u64,
        punch_dials: u64,
        punch_established: u64,
        introducer_hits: u64,
        no_introducer: u64,
        punch_failed_nat: u64,
    ) {
        if rendezvous_sent > 0 {
            self.hp_rendezvous_sent_total
                .fetch_add(rendezvous_sent, Ordering::Relaxed);
        }
        if relayed_connects > 0 {
            self.hp_relayed_connects_total
                .fetch_add(relayed_connects, Ordering::Relaxed);
        }
        if punch_dials > 0 {
            self.hp_punch_dials_total
                .fetch_add(punch_dials, Ordering::Relaxed);
        }
        if punch_established > 0 {
            self.hp_punch_established_total
                .fetch_add(punch_established, Ordering::Relaxed);
        }
        if introducer_hits > 0 {
            self.hp_introducer_hits_total
                .fetch_add(introducer_hits, Ordering::Relaxed);
        }
        if no_introducer > 0 {
            self.hp_no_introducer_total
                .fetch_add(no_introducer, Ordering::Relaxed);
        }
        if punch_failed_nat > 0 {
            self.hp_punch_failed_nat_total
                .fetch_add(punch_failed_nat, Ordering::Relaxed);
        }
    }

    /// rpc method call count (`slot` = the `RPC_METHODS` position or
    /// [`RPC_METHOD_SLOT_UNKNOWN`]; out of range silently ignored - the
    /// defense face).
    pub fn note_rpc_request(&self, slot: usize) {
        if let Some(c) = self.rpc_requests.get(slot) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// rpc latency observation (all of process_call; includes auth and
    /// parameter decoding, excludes transport-layer pre-auth delay -
    /// that happens later at the HTTP layer).
    pub fn observe_rpc_duration(&self, elapsed: Duration) {
        self.rpc_duration_count.fetch_add(1, Ordering::Relaxed);
        self.rpc_duration_sum_us
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
        let secs = elapsed.as_secs_f64();
        for (i, bound) in RPC_DURATION_BUCKETS_SECONDS.iter().enumerate() {
            if secs <= *bound {
                if let Some(b) = self.rpc_duration_buckets.get(i) {
                    b.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
        // Past every bucket: only count/sum (the renderer's +Inf bucket = count).
    }

    /// rpc connection-gate overrun (scope=total - the global concurrency cap tripped).
    pub fn note_rpc_conn_rejected_total(&self) {
        self.rpc_conn_rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    /// rpc connection-gate overrun (scope=per_ip - the per-source cap tripped).
    pub fn note_rpc_conn_rejected_per_ip(&self) {
        self.rpc_conn_rejected_per_ip
            .fetch_add(1, Ordering::Relaxed);
    }

    /// rpc auth failure (token and Basic gates merged; credentials never
    /// enter metrics - counting only, no IP label).
    pub fn note_rpc_auth_fail(&self) {
        self.rpc_auth_fail_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Rendering input snapshot (the rpc `/metrics` read entry; live
    /// engine slots summed + all counters).
    pub fn snapshot(&self) -> MetricsSnapshot {
        let mut snap = MetricsSnapshot {
            uptime_seconds: self.started.elapsed().as_secs(),
            ..MetricsSnapshot::default()
        };
        snap.panic_total = self.panic_total.load(Ordering::Relaxed);
        snap.torrent_completed_total = self.torrent_completed_total.load(Ordering::Relaxed);
        snap.bytes_down_total = self.bytes_down_total.load(Ordering::Relaxed);
        snap.bytes_up_total = self.bytes_up_total.load(Ordering::Relaxed);
        snap.bytes_down_tcp_total = self.bytes_down_tcp_total.load(Ordering::Relaxed);
        snap.bytes_down_utp_total = self.bytes_down_utp_total.load(Ordering::Relaxed);
        snap.peer_bans_total = self.peer_bans_total.load(Ordering::Relaxed);
        snap.redial_attempts_total = self.redial_attempts_total.load(Ordering::Relaxed);
        snap.redial_connected_total = self.redial_connected_total.load(Ordering::Relaxed);
        snap.mse_arc4_total = self.mse_arc4_total.load(Ordering::Relaxed);
        snap.mse_plain_total = self.mse_plain_total.load(Ordering::Relaxed);
        snap.tracker_ok_total = self.tracker_ok_total.load(Ordering::Relaxed);
        snap.tracker_fail_total = self.tracker_fail_total.load(Ordering::Relaxed);
        snap.utp_recv_total = self.utp_recv_total.load(Ordering::Relaxed);
        snap.utp_drop_total = self.utp_drop_total.load(Ordering::Relaxed);
        snap.dht_queries_ping_total = self.dht_queries_ping_total.load(Ordering::Relaxed);
        snap.dht_queries_find_node_total = self.dht_queries_find_node_total.load(Ordering::Relaxed);
        snap.dht_queries_get_peers_total = self.dht_queries_get_peers_total.load(Ordering::Relaxed);
        snap.dht_queries_announce_peer_total =
            self.dht_queries_announce_peer_total.load(Ordering::Relaxed);
        snap.dht_inbound_packets_total = self.dht_inbound_packets_total.load(Ordering::Relaxed);
        snap.dht_inbound_queries_total = self.dht_inbound_queries_total.load(Ordering::Relaxed);
        snap.dht_inbound_unmatched_drops_total = self
            .dht_inbound_unmatched_drops_total
            .load(Ordering::Relaxed);
        snap.blocks_verified_total = self.blocks_verified_total.load(Ordering::Relaxed);
        snap.wrcache_flush_total = self.wrcache_flush_total.load(Ordering::Relaxed);
        snap.wrcache_evict_total = self.wrcache_evict_total.load(Ordering::Relaxed);
        snap.wrcache_evict_bytes_total = self.wrcache_evict_bytes_total.load(Ordering::Relaxed);
        snap.spill_write_bytes_total = self.spill_write_bytes_total.load(Ordering::Relaxed);
        snap.spill_read_bytes_total = self.spill_read_bytes_total.load(Ordering::Relaxed);
        snap.spill_readback_pieces_total = self.spill_readback_pieces_total.load(Ordering::Relaxed);
        snap.spill_fallback_destroy_bytes_total = self
            .spill_fallback_destroy_bytes_total
            .load(Ordering::Relaxed);
        snap.holepunch_rendezvous_sent_total =
            self.hp_rendezvous_sent_total.load(Ordering::Relaxed);
        snap.holepunch_relayed_connects_total =
            self.hp_relayed_connects_total.load(Ordering::Relaxed);
        snap.holepunch_punch_dials_total = self.hp_punch_dials_total.load(Ordering::Relaxed);
        snap.holepunch_punch_established_total =
            self.hp_punch_established_total.load(Ordering::Relaxed);
        snap.holepunch_introducer_hits_total =
            self.hp_introducer_hits_total.load(Ordering::Relaxed);
        snap.holepunch_no_introducer_total = self.hp_no_introducer_total.load(Ordering::Relaxed);
        snap.holepunch_punch_failed_nat_total =
            self.hp_punch_failed_nat_total.load(Ordering::Relaxed);
        snap.peer_leaves_local_total = self.peer_leave_local_total.load(Ordering::Relaxed);
        snap.peer_leaves_peer_closed_total =
            self.peer_leave_peer_closed_total.load(Ordering::Relaxed);
        snap.peer_leaves_io_total = self.peer_leave_io_total.load(Ordering::Relaxed);
        snap.peer_leaves_protocol_total = self.peer_leave_protocol_total.load(Ordering::Relaxed);
        snap.peer_leaves_cancelled_total = self.peer_leave_cancelled_total.load(Ordering::Relaxed);
        snap.peer_inflight_depth_count = self.peer_inflight_depth_count.load(Ordering::Relaxed);
        snap.peer_inflight_depth_sum = self.peer_inflight_depth_sum.load(Ordering::Relaxed);
        snap.peer_inflight_depth_buckets = self
            .peer_inflight_depth_buckets
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        // Block/piece stage durations (three stage slots flattened by
        // BlockStage::slot, restored to per-stage bucket series on read).
        let stage_buckets = |slot: usize| -> Vec<u64> {
            let base = slot * BLOCK_STAGE_BUCKETS_SECONDS.len();
            (0..BLOCK_STAGE_BUCKETS_SECONDS.len())
                .map(|i| {
                    self.block_stage_buckets
                        .get(base + i)
                        .map(|c| c.load(Ordering::Relaxed))
                        .unwrap_or(0)
                })
                .collect()
        };
        snap.block_buffer_seconds_buckets = stage_buckets(BlockStage::Buffer.slot());
        snap.block_buffer_seconds_count = self
            .block_stage_count
            .get(BlockStage::Buffer.slot())
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        snap.block_buffer_seconds_sum_us = self
            .block_stage_sum_us
            .get(BlockStage::Buffer.slot())
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        snap.block_verify_seconds_buckets = stage_buckets(BlockStage::Verify.slot());
        snap.block_verify_seconds_count = self
            .block_stage_count
            .get(BlockStage::Verify.slot())
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        snap.block_verify_seconds_sum_us = self
            .block_stage_sum_us
            .get(BlockStage::Verify.slot())
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        snap.block_write_seconds_buckets = stage_buckets(BlockStage::Write.slot());
        snap.block_write_seconds_count = self
            .block_stage_count
            .get(BlockStage::Write.slot())
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        snap.block_write_seconds_sum_us = self
            .block_stage_sum_us
            .get(BlockStage::Write.slot())
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        snap.rpc_requests = self
            .rpc_requests
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        snap.rpc_duration_buckets = self
            .rpc_duration_buckets
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect();
        snap.rpc_duration_count = self.rpc_duration_count.load(Ordering::Relaxed);
        snap.rpc_duration_sum_us = self.rpc_duration_sum_us.load(Ordering::Relaxed);
        snap.http_stolen_total = self.http_stolen_total.load(Ordering::Relaxed);
        snap.rpc_conn_rejected_total_scope_total =
            self.rpc_conn_rejected_total.load(Ordering::Relaxed);
        snap.rpc_conn_rejected_total_scope_per_ip =
            self.rpc_conn_rejected_per_ip.load(Ordering::Relaxed);
        snap.rpc_auth_fail_total = self.rpc_auth_fail_total.load(Ordering::Relaxed);
        // io registry aggregation seam (DNS family + HTTP transport
        // family; multiple atomics, non-consistent snapshot - see the
        // module and field docs).
        let io = self.io_metrics.snapshot();
        snap.dns_network_changes_total = io.dns.network_changes;
        snap.dns_backend_queries_total = io.dns.backend_started;
        snap.dns_coalesced_total = io.dns.coalesced;
        snap.dns_negative_hits_total = io.dns.negative_hit;
        snap.dns_capacity_rejected_total = io.dns.capacity_rejected;
        snap.dns_system_queries_total = io.dns.system_started;
        snap.dns_system_coalesced_total = io.dns.system_coalesced;
        snap.dns_system_active = io.dns.system_active;
        snap.dns_system_queued = io.dns.system_queued;
        snap.dns_lookups_hit_total = io.dns.lookups_hit;
        snap.dns_lookups_miss_total = io.dns.lookups_miss;
        snap.dns_lookups_error_total = io.dns.lookups_error;
        snap.dns_lookups_timeout_total = io.dns.lookups_timeout;
        snap.dns_family_mix_v4_only_total = io.dns.family_mix_v4_only;
        snap.dns_family_mix_v6_only_total = io.dns.family_mix_v6_only;
        snap.dns_family_mix_dual_total = io.dns.family_mix_dual;
        snap.dns_events_evict_ttl_total = io.dns.events_evict_ttl;
        snap.dns_events_evict_capacity_total = io.dns.events_evict_capacity;
        snap.dns_resolve_seconds_buckets = io.dns.resolve_seconds.buckets;
        snap.dns_resolve_seconds_count = io.dns.resolve_seconds.count;
        snap.dns_system_queue_seconds_buckets = io.dns.system_queue_seconds.buckets;
        snap.dns_system_queue_seconds_count = io.dns.system_queue_seconds.count;
        snap.dns_system_queue_seconds_sum_us = io.dns.system_queue_seconds.sum_us;
        snap.dns_system_lookup_seconds_buckets = io.dns.system_lookup_seconds.buckets;
        snap.dns_system_lookup_seconds_count = io.dns.system_lookup_seconds.count;
        snap.dns_system_lookup_seconds_sum_us = io.dns.system_lookup_seconds.sum_us;
        snap.dns_resolve_seconds_sum_us = io.dns.resolve_seconds.sum_us;
        let http = &io.http;
        snap.http_errors_dns_permanent_total = http.errors_dns_permanent;
        snap.http_errors_dns_transient_total = http.errors_dns_transient;
        snap.http_errors_timeout_total = http.errors_timeout;
        snap.http_errors_tls_total = http.errors_tls;
        snap.http_errors_connect_total = http.errors_connect;
        snap.http_errors_refused_total = http.errors_refused;
        snap.http_errors_reset_total = http.errors_reset;
        snap.http_errors_http_4xx_total = http.errors_http_4xx;
        snap.http_errors_http_5xx_total = http.errors_http_5xx;
        snap.http_retries_total = http.retries_total;
        snap.http_extent_reassign_total = http.extent_reassign_total;
        snap.http_mirror_demote_total = http.mirror_demote;
        snap.http_mirror_remove_total = http.mirror_remove;
        snap.http_mirror_restore_total = http.mirror_restore;
        snap.http_stall_detected_total = http.stall_detected_total;
        snap.http_aimd_grow_total = http.aimd_grow;
        snap.http_aimd_shrink_total = http.aimd_shrink;
        snap.http_request_first_byte_buckets = http.request_first_byte.buckets.clone();
        snap.http_request_first_byte_count = http.request_first_byte.count;
        snap.http_request_first_byte_sum_us = http.request_first_byte.sum_us;
        snap.http_request_total_buckets = http.request_total.buckets.clone();
        snap.http_request_total_count = http.request_total.count;
        snap.http_request_total_sum_us = http.request_total.sum_us;
        snap.http_slowstart_seconds_buckets = http.slowstart_seconds.buckets.clone();
        snap.http_slowstart_seconds_count = http.slowstart_seconds.count;
        snap.http_slowstart_seconds_sum_us = http.slowstart_seconds.sum_us;
        snap.http_conn_establishments_total = http.conn_establishments_total;
        snap.http_conn_establish_seconds_buckets = http.conn_establish_seconds.buckets.clone();
        snap.http_conn_establish_seconds_count = http.conn_establish_seconds.count;
        snap.http_conn_establish_seconds_sum_us = http.conn_establish_seconds.sum_us;
        let disk = &io.disk;
        snap.disk_sink_writes_total = disk.sink_writes_total;
        snap.disk_sink_writes_bytes_total = disk.sink_writes_bytes_total;
        snap.disk_sink_inflight = disk.sink_inflight;
        snap.disk_finalize_file_fsync_buckets = disk.finalize_file_fsync.buckets.clone();
        snap.disk_finalize_file_fsync_count = disk.finalize_file_fsync.count;
        snap.disk_finalize_file_fsync_sum_us = disk.finalize_file_fsync.sum_us;
        snap.disk_finalize_fsync_dir_buckets = disk.finalize_fsync_dir.buckets.clone();
        snap.disk_finalize_fsync_dir_count = disk.finalize_fsync_dir.count;
        snap.disk_finalize_fsync_dir_sum_us = disk.finalize_fsync_dir.sum_us;
        snap.disk_finalize_rename_buckets = disk.finalize_rename.buckets.clone();
        snap.disk_finalize_rename_count = disk.finalize_rename.count;
        snap.disk_finalize_rename_sum_us = disk.finalize_rename.sum_us;
        snap.disk_prealloc_seconds_buckets = disk.prealloc_seconds.buckets.clone();
        snap.disk_prealloc_seconds_count = disk.prealloc_seconds.count;
        snap.disk_prealloc_seconds_sum_us = disk.prealloc_seconds.sum_us;
        let persist = &io.persist;
        snap.persist_queue_depth = persist.queue_depth;
        snap.persist_commit_seconds_buckets = persist.commit_seconds.buckets.clone();
        snap.persist_commit_seconds_count = persist.commit_seconds.count;
        snap.persist_commit_seconds_sum_us = persist.commit_seconds.sum_us;
        // Engine gauge totals: sum over live slots (a dead `Weak` = the
        // engine exited, not counted; dead slots compacted - the registry
        // does not grow with engine history).
        if let Ok(mut table) = self.engine_gauges.lock() {
            table.retain(|w| w.upgrade().is_some());
            for w in table.iter() {
                if let Some(g) = w.upgrade() {
                    snap.conn_tcp_in += g.conn_tcp_in();
                    snap.conn_tcp_out += g.conn_tcp_out();
                    snap.conn_utp_in += g.conn_utp_in();
                    snap.conn_utp_out += g.conn_utp_out();
                    snap.conn_choked += g.conn_choked();
                    snap.redial_pool_size += g.redial_pool_size();
                    snap.dht_nodes_v4 += g.dht_nodes_v4();
                    snap.dht_nodes_v6 += g.dht_nodes_v6();
                    snap.hashpool_queue_depth += g.hash_queue_depth();
                    snap.block_inflight += g.block_inflight();
                    snap.peer_inflight_active += g.peer_inflight_active();
                    snap.block_arena_lease_hits_total += g.block_arena_lease_hits_total();
                    snap.block_arena_alloc_fallback_total += g.block_arena_alloc_fallback_total();
                    snap.block_arena_outstanding_blocks += g.block_arena_outstanding_blocks();
                    snap.block_arena_cap_bytes += g.block_arena_cap_bytes();
                }
            }
        }
        // HTTP task gauge totals (same compaction semantics).
        if let Ok(mut table) = self.http_task_gauges.lock() {
            table.retain(|w| w.upgrade().is_some());
            for w in table.iter() {
                if let Some(g) = w.upgrade() {
                    snap.http_extents_active += g.extents_active();
                    snap.http_conn_aimd += g.aimd_connections();
                }
            }
        }
        snap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed points -> monotonic snapshot readings; slots default to zero
    /// (honest zeros, no fabrication). The io registry binds an
    /// **isolated instance** - the process default registry would be
    /// polluted by other tests' shared resolver feed points in the same
    /// binary (parallel execution); equality assertions must be isolated.
    #[test]
    fn feed_points_land_in_snapshot() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        let zero = m.snapshot();
        assert_eq!(zero, MetricsSnapshot::default());
        assert_eq!(zero.rpc_requests.len(), RPC_METHOD_SLOTS);
        assert_eq!(
            zero.rpc_duration_buckets.len(),
            RPC_DURATION_BUCKETS_SECONDS.len()
        );

        m.note_task_completed();
        m.add_bytes(10, 3);
        m.note_panic();
        m.note_peer_ban();
        m.note_mse_result(true);
        m.note_mse_result(false);
        m.note_tracker_result(true);
        m.note_tracker_result(false);
        m.add_utp_packets(7, 2);
        m.add_blocks_verified(9);
        m.note_wrcache(WrcacheEvent::Flush);
        m.note_wrcache(WrcacheEvent::Evict);
        let s = m.snapshot();
        assert_eq!(s.torrent_completed_total, 1);
        assert_eq!(s.bytes_down_total, 10);
        assert_eq!(s.bytes_up_total, 3);
        assert_eq!(s.panic_total, 1);
        assert_eq!(s.peer_bans_total, 1);
        assert_eq!(s.mse_arc4_total, 1);
        assert_eq!(s.mse_plain_total, 1);
        assert_eq!(s.tracker_ok_total, 1);
        assert_eq!(s.tracker_fail_total, 1);
        assert_eq!(s.utp_recv_total, 7);
        assert_eq!(s.utp_drop_total, 2);
        assert_eq!(s.blocks_verified_total, 9);
        assert_eq!(s.wrcache_flush_total, 1);
        assert_eq!(s.wrcache_evict_total, 1);
        // Zero deltas pollute nothing (the add_* >0 gates).
        m.add_bytes(0, 0);
        m.add_utp_packets(0, 0);
        m.add_blocks_verified(0);
        assert_eq!(m.snapshot().bytes_down_total, 10);
    }

    /// Instrumentation feed points: evicted-byte deltas, per-peer
    /// in-flight histogram + active-peer gauge, and the block/piece
    /// three-stage duration histograms - buckets align with their tables,
    /// zero deltas pollute nothing, unfed = honest zero.
    #[test]
    fn perf05_instrumentation_feed_points_land_in_snapshot() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        let zero = m.snapshot();
        assert_eq!(
            zero.wrcache_evict_bytes_total, 0,
            "honest zero-value baseline"
        );
        assert_eq!(zero.peer_inflight_depth_count, 0);
        assert_eq!(zero.peer_inflight_active, 0);
        assert_eq!(zero.block_buffer_seconds_count, 0);
        assert_eq!(
            zero.peer_inflight_depth_buckets.len(),
            PEER_INFLIGHT_BUCKETS.len()
        );
        assert_eq!(
            zero.block_buffer_seconds_buckets.len(),
            BLOCK_STAGE_BUCKETS_SECONDS.len()
        );
        assert_eq!(zero.block_verify_seconds_count, 0);
        assert_eq!(zero.block_write_seconds_count, 0);

        // Evicted bytes: zero deltas pollute nothing.
        m.note_wrcache_evict_bytes(0);
        m.note_wrcache_evict_bytes(4096);
        m.note_wrcache_evict_bytes(12288);
        assert_eq!(m.snapshot().wrcache_evict_bytes_total, 16384);

        // Spill three faces: zero deltas pollute nothing; write bytes /
        // readback bytes / readback pieces accumulate independently
        // (hit-rate numerator = pieces, denominator = pieces + the evict
        // above).
        m.note_spill(0, 0, 0);
        m.note_spill(32768, 16384, 2);
        m.note_spill(4096, 16384, 0);
        let s = m.snapshot();
        assert_eq!(s.spill_write_bytes_total, 36864);
        assert_eq!(s.spill_read_bytes_total, 32768);
        assert_eq!(s.spill_readback_pieces_total, 2);

        // Per-peer in-flight: depth 0/1/2/4 land in their buckets; mean = sum/count.
        m.observe_peer_inflight(0);
        m.observe_peer_inflight(1);
        m.observe_peer_inflight(1);
        m.observe_peer_inflight(2);
        m.observe_peer_inflight(4);
        m.observe_peer_inflight(600); // past every bucket (>256): only count/sum
        let s = m.snapshot();
        assert_eq!(s.peer_inflight_depth_count, 6);
        assert_eq!(s.peer_inflight_depth_sum, 608);
        assert_eq!(
            s.peer_inflight_depth_buckets[0], 1,
            "depth 0 -> le=0 bucket"
        );
        assert_eq!(
            s.peer_inflight_depth_buckets[1], 2,
            "depth 1 -> le=1 bucket"
        );
        assert_eq!(
            s.peer_inflight_depth_buckets[2], 1,
            "depth 2 -> le=2 bucket"
        );
        assert_eq!(
            s.peer_inflight_depth_buckets[3], 1,
            "depth 4 -> le=4 bucket"
        );
        assert_eq!(
            s.peer_inflight_depth_buckets[9], 0,
            "600 out of range, never enters a window bucket"
        );

        // Engine slots: active-peer gauge SET -> sum; drops back after drop.
        let g = m.register_engine();
        g.set_peer_inflight_active(7);
        assert_eq!(m.snapshot().peer_inflight_active, 7);
        drop(g);
        assert_eq!(
            m.snapshot().peer_inflight_active,
            0,
            "slot deactivation drops it back"
        );

        // Block/piece three stages: independent slots per stage (1ms ->
        // the le=0.001 bucket; 5s over the top).
        m.observe_block_stage(BlockStage::Buffer, Duration::from_millis(1));
        m.observe_block_stage(BlockStage::Verify, Duration::from_millis(1));
        m.observe_block_stage(BlockStage::Write, Duration::from_secs(9));
        let s = m.snapshot();
        assert_eq!(s.block_buffer_seconds_count, 1);
        assert_eq!(s.block_verify_seconds_count, 1);
        assert_eq!(s.block_write_seconds_count, 1);
        assert_eq!(
            s.block_buffer_seconds_buckets[3], 1,
            "1ms -> le=0.001 bucket (buffer slot)"
        );
        assert_eq!(
            s.block_verify_seconds_buckets[3], 1,
            "1ms -> le=0.001 bucket (verify slot)"
        );
        assert_eq!(
            s.block_write_seconds_buckets.iter().sum::<u64>(),
            0,
            "9s exceeds all buckets (write slot)"
        );
        assert!(s.block_write_seconds_sum_us >= 9_000_000);
    }

    /// Observation feed points: per-transport supply bytes (snapshot
    /// projection + reader accessor agree; zero deltas pollute nothing) +
    /// the endgame redundancy trio (duration / window duplicates /
    /// window buffered; honest zero start) + the two tail fields
    /// (last-mile / last-8-pieces durations - one-time terminal feed,
    /// zero start).
    #[test]
    fn supply_bytes_by_transport_and_endgame_economics() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        let zero = m.snapshot();
        assert_eq!(zero.bytes_down_tcp_total, 0, "honest zero-value baseline");
        assert_eq!(zero.bytes_down_utp_total, 0);
        assert_eq!(m.endgame_economics(), (0.0, 0, 0, 0.0, 0.0));

        // Two-family delta: snapshot and reader accessor agree; the sum
        // cross-checks the total downlink terms (768 + 256 = 1024).
        m.add_transport_down_bytes(768, 256);
        m.add_bytes(1024, 0);
        let s = m.snapshot();
        assert_eq!(s.bytes_down_tcp_total, 768);
        assert_eq!(s.bytes_down_utp_total, 256);
        assert_eq!(
            s.bytes_down_tcp_total + s.bytes_down_utp_total,
            s.bytes_down_total,
            "the two families always sum to the total-download terms"
        );
        assert_eq!(m.transport_supply_bytes(), (768, 256));

        // Zero deltas pollute nothing (the add_* >0 gates).
        m.add_transport_down_bytes(0, 0);
        assert_eq!(m.transport_supply_bytes(), (768, 256));

        // Endgame redundancy economics: duration slices accumulate + the window pair counts.
        m.note_endgame_elapsed(Duration::from_millis(1500));
        m.note_endgame_elapsed(Duration::from_millis(500));
        m.note_duplicate_blocks_endgame(0); // zero deltas pollute nothing
        m.note_duplicate_blocks_endgame(3);
        m.note_duplicate_blocks_endgame(4);
        m.note_buffered_blocks_endgame(40);
        // Tail terminal values (one-time feed; zero pollutes nothing).
        m.note_last_mile_elapsed(Duration::ZERO);
        m.note_last8_pieces_elapsed(Duration::ZERO);
        m.note_last_mile_elapsed(Duration::from_millis(1200));
        m.note_last8_pieces_elapsed(Duration::from_millis(3000));
        let (eg_secs, eg_dup, eg_buf, lm_secs, l8_secs) = m.endgame_economics();
        assert_eq!(eg_secs, 2.0);
        assert_eq!(eg_dup, 7);
        assert_eq!(eg_buf, 40);
        assert_eq!(
            lm_secs, 1.2,
            "last-mile = first missing piece <= N -> completion final value"
        );
        assert_eq!(l8_secs, 3.0, "last-8-pieces window final value");
    }

    /// Observation feed: late blocks for verified pieces (zero deltas
    /// pollute nothing + deltas accumulate; the reader accessor shares
    /// the source - the cancel-on-verified fix's criterion face, riding
    /// the shutdown summary).
    #[test]
    fn late_blocks_verified_counter_projects() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        assert_eq!(m.late_blocks_verified(), 0, "honest zero-value baseline");
        m.note_late_blocks_verified(0); // zero deltas pollute nothing
        assert_eq!(m.late_blocks_verified(), 0);
        m.note_late_blocks_verified(1);
        m.note_late_blocks_verified(9);
        assert_eq!(m.late_blocks_verified(), 10);
    }

    /// Write-locality count projection (observation only; feed = the
    /// `on_piece_written` face-level total bridged through
    /// `checkpoint_endgame` as a take-and-reset delta): zero start / zero
    /// deltas pollute nothing / deltas accumulate; the reader accessor
    /// shares the source with the shutdown summary's endgame economics
    /// rows `write_adj`/`write_iso`.
    #[test]
    fn write_locality_counter_projects() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        assert_eq!(m.write_locality(), (0, 0), "honest zero-value baseline");
        m.note_write_locality(0, 0); // zero deltas pollute nothing
        assert_eq!(m.write_locality(), (0, 0));
        // Checkpoint delta form: two bridges accumulate.
        m.note_write_locality(3, 1);
        m.note_write_locality(2, 0);
        assert_eq!(
            m.write_locality(),
            (5, 1),
            "face-level delta accumulation (write_adj/write_iso)"
        );
    }

    /// Two-phase bookkeeping observation family (observation only):
    /// arrival/degrade/guard counter delta feed (zero deltas pollute
    /// nothing + independent accumulation per family; the reader accessor
    /// shares the source - the 1s seed tick delta-bridge projection).
    #[test]
    fn two_phase_ledger_counters_project() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        assert_eq!(
            m.two_phase_ledger_obs(),
            (0, 0, 0),
            "honest zero-value baseline"
        );
        m.note_two_phase_ledger(0, 0, 0); // zero deltas pollute nothing
        assert_eq!(m.two_phase_ledger_obs(), (0, 0, 0));
        m.note_two_phase_ledger(3, 1, 0);
        m.note_two_phase_ledger(4, 0, 2);
        assert_eq!(
            m.two_phase_ledger_obs(),
            (7, 1, 2),
            "three families accumulate independently (arrival/degrade/guard)"
        );
    }

    /// Holepunch family delta + snapshot projection (the tick bridge
    /// face): zero deltas pollute nothing, seven counters accumulate
    /// independently, snapshot fields correspond one to one (the
    /// rendering input face).
    #[test]
    fn holepunch_family_notes_and_snapshots() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        // Zero deltas pollute nothing.
        m.note_holepunch(0, 0, 0, 0, 0, 0, 0);
        let snap = m.snapshot();
        assert_eq!(snap.holepunch_punch_dials_total, 0);
        // Two rounds accumulate independently (feed = the tick bridge's per-field deltas).
        m.note_holepunch(1, 2, 3, 0, 4, 5, 0);
        m.note_holepunch(0, 0, 1, 1, 0, 1, 2);
        let snap = m.snapshot();
        assert_eq!(snap.holepunch_rendezvous_sent_total, 1);
        assert_eq!(snap.holepunch_relayed_connects_total, 2);
        assert_eq!(snap.holepunch_punch_dials_total, 4);
        assert_eq!(snap.holepunch_punch_established_total, 1);
        assert_eq!(snap.holepunch_introducer_hits_total, 4);
        assert_eq!(snap.holepunch_no_introducer_total, 6);
        assert_eq!(snap.holepunch_punch_failed_nat_total, 2);
    }

    /// Leave-reason five-kind counts + snapshot projection (the leave-arm
    /// direct feed): five slots accumulate independently, snapshot fields
    /// correspond one to one (rendering input; all five LeaveKind arms
    /// exercised).
    #[test]
    fn peer_leave_family_notes_and_snapshots() {
        use crate::LeaveKind;
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        // All-zero start (honest zero).
        let snap = m.snapshot();
        assert_eq!(snap.peer_leaves_local_total, 0);
        assert_eq!(snap.peer_leaves_peer_closed_total, 0);
        // Five kinds, independent slots (feed = one leave-arm event each).
        m.note_peer_leave(LeaveKind::PeerClosed);
        m.note_peer_leave(LeaveKind::PeerClosed);
        m.note_peer_leave(LeaveKind::Local);
        m.note_peer_leave(LeaveKind::Io);
        m.note_peer_leave(LeaveKind::Protocol);
        m.note_peer_leave(LeaveKind::Cancelled);
        let snap = m.snapshot();
        assert_eq!(snap.peer_leaves_peer_closed_total, 2);
        assert_eq!(snap.peer_leaves_local_total, 1);
        assert_eq!(snap.peer_leaves_io_total, 1);
        assert_eq!(snap.peer_leaves_protocol_total, 1);
        assert_eq!(snap.peer_leaves_cancelled_total, 1);
    }

    /// rpc method slots: known methods by position, unknown collapsed
    /// into one slot; out of range harmless.
    #[test]
    fn rpc_request_slots_are_bounded() {
        let m = SessionMetrics::new();
        m.note_rpc_request(0);
        m.note_rpc_request(0);
        m.note_rpc_request(RPC_METHOD_SLOT_UNKNOWN);
        m.note_rpc_request(RPC_METHOD_SLOT_UNKNOWN);
        m.note_rpc_request(RPC_METHOD_SLOT_UNKNOWN);
        // Out of range (past the method face + unknown): the defense face ignores silently.
        m.note_rpc_request(RPC_METHOD_SLOTS + 5);
        let s = m.snapshot();
        assert_eq!(s.rpc_requests[0], 2);
        assert_eq!(s.rpc_requests[RPC_METHOD_SLOT_UNKNOWN], 3);
        assert_eq!(s.rpc_requests.len(), RPC_METHOD_SLOTS);
    }

    /// Latency histogram: buckets by inclusive upper bound, count/sum in
    /// sync; over the top only count/sum.
    #[test]
    fn rpc_duration_histogram_buckets() {
        let m = SessionMetrics::new();
        m.observe_rpc_duration(Duration::from_millis(1));
        m.observe_rpc_duration(Duration::from_millis(4));
        m.observe_rpc_duration(Duration::from_millis(60));
        m.observe_rpc_duration(Duration::from_secs(9));
        let s = m.snapshot();
        // 1ms -> the le=0.001 bucket (inclusive).
        assert_eq!(s.rpc_duration_buckets[0], 1);
        // 4ms -> the le=0.005 bucket.
        assert_eq!(s.rpc_duration_buckets[2], 1);
        // 60ms -> the le=0.1 bucket.
        assert_eq!(s.rpc_duration_buckets[6], 1);
        // 9s -> past every bucket.
        assert_eq!(s.rpc_duration_buckets.iter().sum::<u64>(), 3);
        assert_eq!(s.rpc_duration_count, 4);
        // sum >= 9s (microsecond terms).
        assert!(s.rpc_duration_sum_us >= 9_000_000);
    }

    /// Engine slots: register -> SET -> snapshot totals; after drop the
    /// totals fall back and the registry compacts.
    #[test]
    fn engine_gauge_slots_aggregate_and_expire() {
        let m = SessionMetrics::new();
        let g1 = m.register_engine();
        let g2 = m.register_engine();
        g1.set_conn_tcp(3, 4);
        g1.set_conn_choked(1);
        g1.set_dht_nodes(100, 7);
        g1.set_hash_queue_depth(5);
        g2.set_conn_tcp(10, 20);
        let s = m.snapshot();
        assert_eq!(s.conn_tcp_in, 13);
        assert_eq!(s.conn_tcp_out, 24);
        assert_eq!(s.conn_choked, 1);
        assert_eq!(s.dht_nodes_v4, 100);
        assert_eq!(s.dht_nodes_v6, 7);
        assert_eq!(s.hashpool_queue_depth, 5);
        // Slot death (engine exit) -> totals fall back, no dead entries remain.
        drop(g2);
        let s = m.snapshot();
        assert_eq!(s.conn_tcp_in, 3);
        assert_eq!(s.conn_tcp_out, 4);
        assert_eq!(
            m.engine_gauges.lock().map(|t| t.len()).unwrap_or(99),
            1,
            "dead slots compacted"
        );
    }

    /// HTTP task slots (the observability integration face): register ->
    /// SET -> snapshot totals; stolen counter delta feed; slot drop
    /// falls back and the registry compacts.
    #[test]
    fn http_task_gauges_aggregate_and_expire() {
        let m = SessionMetrics::new();
        let zero = m.snapshot();
        assert_eq!(zero.http_extents_active, 0);
        assert_eq!(zero.http_conn_aimd, 0);
        assert_eq!(zero.http_stolen_total, 0, "honest zero-value baseline");

        let t1 = m.register_http_task();
        let t2 = m.register_http_task();
        t1.set(3, 8);
        t2.set(2, 0);
        m.note_http_stolen(1);
        m.note_http_stolen(2);
        m.note_http_stolen(0); // zero deltas pollute nothing
        let s = m.snapshot();
        assert_eq!(s.http_extents_active, 5, "sum of active task slots");
        assert_eq!(
            s.http_conn_aimd, 8,
            "sum of active task slots (static-baseline tasks contribute 0)"
        );
        assert_eq!(s.http_stolen_total, 3, "monotonic accumulation");

        drop(t2);
        let s = m.snapshot();
        assert_eq!(s.http_extents_active, 3, "slot deactivation drops it back");
        assert_eq!(
            m.http_task_gauges.lock().map(|t| t.len()).unwrap_or(99),
            1,
            "dead slots compacted"
        );
    }

    /// uptime advances with real time (1.01s window; no virtual clock -
    /// second granularity suffices).
    #[test]
    fn uptime_advances() {
        let m = SessionMetrics::new();
        std::thread::sleep(Duration::from_millis(1010));
        assert!(m.snapshot().uptime_seconds >= 1);
    }

    /// io registry aggregation seam: inject an isolated registry -> io
    /// feed points count -> the snapshot pulls in the DNS family fields
    /// (bucket slots align with [`DNS_RESOLVE_BUCKETS_SECONDS`]); an
    /// unfed isolated registry = honest zeros (field reads under the
    /// non-consistent-snapshot terms).
    #[test]
    fn io_registry_dns_metrics_aggregate_into_snapshot() {
        let registry = Arc::new(taiji_io::metrics::MetricsRegistry::new());
        let m = SessionMetrics::with_io_metrics(registry.clone());
        let zero = m.snapshot();
        assert_eq!(zero.dns_lookups_hit_total, 0, "honest zero-value baseline");
        assert_eq!(zero.dns_resolve_seconds_count, 0);
        assert_eq!(
            zero.dns_resolve_seconds_buckets.len(),
            DNS_RESOLVE_BUCKETS_SECONDS.len()
        );

        let dns = registry.dns();
        dns.note_lookup(taiji_io::metrics::DnsLookupResult::Hit);
        dns.note_lookup(taiji_io::metrics::DnsLookupResult::Miss);
        dns.note_lookup(taiji_io::metrics::DnsLookupResult::Error);
        dns.note_lookup(taiji_io::metrics::DnsLookupResult::Timeout);
        dns.note_family_mix(taiji_io::metrics::DnsFamilyMix::V4Only);
        dns.note_family_mix(taiji_io::metrics::DnsFamilyMix::V6Only);
        dns.note_family_mix(taiji_io::metrics::DnsFamilyMix::Dual);
        dns.note_cache_event(taiji_io::metrics::DnsCacheEvent::EvictTtl);
        dns.note_cache_event(taiji_io::metrics::DnsCacheEvent::EvictCapacity);
        dns.observe_resolve(Duration::from_millis(40));

        let s = m.snapshot();
        assert_eq!(s.dns_lookups_hit_total, 1);
        assert_eq!(s.dns_lookups_miss_total, 1);
        assert_eq!(s.dns_lookups_error_total, 1);
        assert_eq!(s.dns_lookups_timeout_total, 1);
        assert_eq!(s.dns_family_mix_v4_only_total, 1);
        assert_eq!(s.dns_family_mix_v6_only_total, 1);
        assert_eq!(s.dns_family_mix_dual_total, 1);
        assert_eq!(s.dns_events_evict_ttl_total, 1);
        assert_eq!(s.dns_events_evict_capacity_total, 1);
        assert_eq!(s.dns_resolve_seconds_count, 1);
        assert_eq!(
            s.dns_resolve_seconds_buckets[3], 1,
            "40ms lands in the le=0.05 bucket"
        );
        assert!(s.dns_resolve_seconds_sum_us >= 40_000);
    }

    /// io registry aggregation seam (HTTP transport family): inject an
    /// isolated registry -> feed points via the
    /// [`SessionMetrics::io_registry`] handle -> the snapshot pulls in
    /// the `http_*` fields (nine error classes / retries / reassign /
    /// mirror / stall / aimd / three histogram tables aligned with
    /// [`HTTP_REQUEST_BUCKETS_SECONDS`] /
    /// [`HTTP_SLOWSTART_BUCKETS_SECONDS`]); unfed = honest zeros.
    #[test]
    fn io_registry_http_metrics_aggregate_into_snapshot() {
        let registry = Arc::new(taiji_io::metrics::MetricsRegistry::new());
        let m = SessionMetrics::with_io_metrics(registry.clone());
        let zero = m.snapshot();
        assert_eq!(
            zero.http_errors_dns_permanent_total, 0,
            "honest zero-value baseline"
        );
        assert_eq!(zero.http_request_total_count, 0);
        assert_eq!(zero.http_slowstart_seconds_count, 0);
        assert_eq!(
            zero.http_request_first_byte_buckets.len(),
            HTTP_REQUEST_BUCKETS_SECONDS.len()
        );
        assert_eq!(
            zero.http_slowstart_seconds_buckets.len(),
            HTTP_SLOWSTART_BUCKETS_SECONDS.len()
        );

        let http = registry.http();
        use taiji_io::dns::DnsPersistence;
        http.note_error(taiji_io::metrics::HttpErrorClass::Dns(
            DnsPersistence::Permanent,
        ));
        http.note_error(taiji_io::metrics::HttpErrorClass::Dns(
            DnsPersistence::Transient,
        ));
        http.note_error(taiji_io::metrics::HttpErrorClass::Timeout);
        http.note_error(taiji_io::metrics::HttpErrorClass::Tls);
        http.note_error(taiji_io::metrics::HttpErrorClass::Connect);
        http.note_error(taiji_io::metrics::HttpErrorClass::Refused);
        http.note_error(taiji_io::metrics::HttpErrorClass::Reset);
        http.note_error(taiji_io::metrics::HttpErrorClass::Http4xx);
        http.note_error(taiji_io::metrics::HttpErrorClass::Http5xx);
        http.note_retries(1);
        http.note_extent_reassign();
        http.note_mirror_event(taiji_io::metrics::MirrorEventKind::Demote);
        http.note_mirror_event(taiji_io::metrics::MirrorEventKind::Remove);
        http.note_mirror_event(taiji_io::metrics::MirrorEventKind::Restore);
        http.note_stall_detected();
        http.note_aimd_event(taiji_io::metrics::AimdDirection::Grow);
        http.note_aimd_event(taiji_io::metrics::AimdDirection::Shrink);
        http.observe_request(
            taiji_io::metrics::RequestPhase::FirstByte,
            Duration::from_millis(30),
        );
        http.observe_request(
            taiji_io::metrics::RequestPhase::Total,
            Duration::from_secs(45),
        );
        http.observe_slowstart(Duration::from_secs(3));
        // Connection-profile family (same registry seam): counter + histogram always equal twins.
        http.note_conn_established(Duration::from_millis(40));

        let s = m.snapshot();
        assert_eq!(s.http_errors_dns_permanent_total, 1);
        assert_eq!(s.http_errors_dns_transient_total, 1);
        assert_eq!(s.http_errors_timeout_total, 1);
        assert_eq!(s.http_errors_tls_total, 1);
        assert_eq!(s.http_errors_connect_total, 1);
        assert_eq!(s.http_errors_refused_total, 1);
        assert_eq!(s.http_errors_reset_total, 1);
        assert_eq!(s.http_errors_http_4xx_total, 1);
        assert_eq!(s.http_errors_http_5xx_total, 1);
        assert_eq!(s.http_retries_total, 1);
        assert_eq!(s.http_extent_reassign_total, 1);
        assert_eq!(s.http_mirror_demote_total, 1);
        assert_eq!(s.http_mirror_remove_total, 1);
        assert_eq!(s.http_mirror_restore_total, 1);
        assert_eq!(s.http_stall_detected_total, 1);
        assert_eq!(s.http_aimd_grow_total, 1);
        assert_eq!(s.http_aimd_shrink_total, 1);
        assert_eq!(s.http_request_first_byte_count, 1);
        assert_eq!(
            s.http_request_first_byte_buckets[1], 1,
            "30ms lands in the le=0.05 bucket"
        );
        assert_eq!(s.http_request_total_count, 1);
        assert_eq!(
            s.http_request_total_buckets[7], 1,
            "45s lands in the le=60 bucket"
        );
        assert_eq!(s.http_slowstart_seconds_count, 1);
        assert_eq!(
            s.http_slowstart_seconds_buckets[3], 1,
            "3s lands in the le=5 bucket"
        );
        assert!(s.http_request_total_sum_us >= 45_000_000);
        // Connection-profile aggregation: 40ms lands in the le=0.05
        // bucket (aligned with HTTP_CONN_ESTABLISH_BUCKETS_SECONDS).
        assert_eq!(s.http_conn_establishments_total, 1);
        assert_eq!(s.http_conn_establish_seconds_count, 1);
        assert_eq!(
            s.http_conn_establish_seconds_buckets[3], 1,
            "40ms lands in the le=0.05 bucket (index aligned with HTTP_CONN_ESTABLISH_BUCKETS_SECONDS)"
        );
        assert!(
            s.http_conn_establish_seconds_sum_us >= 40_000,
            "sum in microseconds >= 40ms"
        );
    }

    /// io registry aggregation seam (disk/finalize family): inject an
    /// isolated registry -> feed points via the
    /// [`SessionMetrics::io_registry`] handle -> the snapshot pulls in
    /// the `disk_*` fields (write count/bytes, in-flight gauge, finalize
    /// three ops and prealloc histograms aligned with
    /// [`DISK_FINALIZE_BUCKETS_SECONDS`]); unfed = honest zeros.
    #[test]
    fn io_registry_disk_metrics_aggregate_into_snapshot() {
        let registry = Arc::new(taiji_io::metrics::MetricsRegistry::new());
        let m = SessionMetrics::with_io_metrics(registry.clone());
        let zero = m.snapshot();
        assert_eq!(zero.disk_sink_writes_total, 0, "honest zero-value baseline");
        assert_eq!(zero.disk_sink_inflight, 0);
        assert_eq!(zero.disk_finalize_rename_count, 0);
        assert_eq!(
            zero.disk_finalize_file_fsync_buckets.len(),
            DISK_FINALIZE_BUCKETS_SECONDS.len()
        );
        assert_eq!(
            zero.disk_prealloc_seconds_buckets.len(),
            DISK_FINALIZE_BUCKETS_SECONDS.len()
        );

        let disk = registry.disk();
        disk.note_sink_write(4096);
        let guard = disk.enter_sink_write();
        disk.observe_finalize(
            taiji_io::metrics::FinalizeOp::FileFsync,
            Duration::from_millis(2),
        );
        disk.observe_finalize(
            taiji_io::metrics::FinalizeOp::FsyncDir,
            Duration::from_millis(8),
        );
        disk.observe_finalize(
            taiji_io::metrics::FinalizeOp::Rename,
            Duration::from_secs(9),
        );
        disk.observe_prealloc(Duration::from_millis(40));

        let s = m.snapshot();
        assert_eq!(s.disk_sink_writes_total, 1);
        assert_eq!(s.disk_sink_writes_bytes_total, 4096);
        assert_eq!(
            s.disk_sink_inflight, 1,
            "in-flight sampled reading (guard not dropped)"
        );
        assert_eq!(s.disk_finalize_file_fsync_count, 1);
        assert_eq!(
            s.disk_finalize_file_fsync_buckets[1], 1,
            "2ms lands in the le=0.01 bucket"
        );
        assert_eq!(s.disk_finalize_fsync_dir_count, 1);
        assert_eq!(
            s.disk_finalize_fsync_dir_buckets[1], 1,
            "8ms lands in the le=0.01 bucket"
        );
        assert_eq!(s.disk_finalize_rename_count, 1);
        assert_eq!(
            s.disk_finalize_rename_buckets[7], 1,
            "9s lands in the le=30 bucket"
        );
        assert_eq!(s.disk_prealloc_seconds_count, 1);
        assert_eq!(
            s.disk_prealloc_seconds_buckets[2], 1,
            "40ms lands in the le=0.05 bucket"
        );
        assert!(s.disk_finalize_rename_sum_us >= 9_000_000);
        drop(guard);
        assert_eq!(
            m.snapshot().disk_sink_inflight,
            0,
            "returns to its resting value at the exit point"
        );
    }

    /// DHT outbound per-kind counts: feed = engine tick snapshot deltas
    /// (`add_dht_queries`) - four kinds land in their slots, zero deltas
    /// have no effect; unfed = honest zeros.
    #[test]
    fn dht_queries_feed_points_land_in_snapshot() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        let zero = m.snapshot();
        assert_eq!(zero.dht_queries_ping_total, 0, "honest zero-value baseline");
        assert_eq!(zero.dht_queries_announce_peer_total, 0);

        m.add_dht_queries(DhtQueryKind::Ping, 3);
        m.add_dht_queries(DhtQueryKind::FindNode, 1);
        m.add_dht_queries(DhtQueryKind::GetPeers, 5);
        m.add_dht_queries(DhtQueryKind::AnnouncePeer, 2);
        m.add_dht_queries(DhtQueryKind::Ping, 0);
        // Dual-engine sum semantics: a second delta of the same kind accumulates.
        m.add_dht_queries(DhtQueryKind::Ping, 4);

        let s = m.snapshot();
        assert_eq!(s.dht_queries_ping_total, 7);
        assert_eq!(s.dht_queries_find_node_total, 1);
        assert_eq!(s.dht_queries_get_peers_total, 5);
        assert_eq!(s.dht_queries_announce_peer_total, 2);
    }

    /// The DHT inbound observation family follows the same
    /// delta-accumulate pattern (per-engine deltas sum; zero deltas are
    /// no-ops; unfed = honest zeros).
    #[test]
    fn dht_inbound_feed_points_land_in_snapshot() {
        let m =
            SessionMetrics::with_io_metrics(Arc::new(taiji_io::metrics::MetricsRegistry::new()));
        let zero = m.snapshot();
        assert_eq!(
            zero.dht_inbound_packets_total, 0,
            "honest zero-value baseline"
        );
        assert_eq!(zero.dht_inbound_queries_total, 0);
        assert_eq!(zero.dht_inbound_unmatched_drops_total, 0);

        m.add_dht_inbound(30, 8, 19);
        m.add_dht_inbound(0, 0, 0);
        // Dual-engine sum semantics: a second engine's delta accumulates.
        m.add_dht_inbound(10, 4, 6);

        let s = m.snapshot();
        assert_eq!(s.dht_inbound_packets_total, 40);
        assert_eq!(s.dht_inbound_queries_total, 12);
        assert_eq!(s.dht_inbound_unmatched_drops_total, 25);
    }

    /// io registry aggregation seam (persistence family):
    /// `PersistMetricsBridge` adapts the store `PersistObserve` callback
    /// seam -> the injected isolated registry feeds -> the snapshot pulls
    /// in the `persist_*` fields (commit histogram aligned with
    /// [`PERSIST_COMMIT_BUCKETS_SECONDS`]; queue_depth SET semantics);
    /// unfed = honest zeros.
    #[test]
    fn persist_metrics_bridge_aggregates_into_snapshot() {
        let registry = Arc::new(taiji_io::metrics::MetricsRegistry::new());
        let observer = PersistMetricsBridge::for_registry(registry.clone());
        let m = SessionMetrics::with_io_metrics(registry);
        let zero = m.snapshot();
        assert_eq!(zero.persist_queue_depth, 0, "honest zero-value baseline");
        assert_eq!(zero.persist_commit_seconds_count, 0);
        assert_eq!(
            zero.persist_commit_seconds_buckets.len(),
            PERSIST_COMMIT_BUCKETS_SECONDS.len()
        );

        observer.observe_commit(Duration::from_millis(2));
        observer.observe_commit(Duration::from_secs(3));
        observer.set_queue_depth(4);

        let s = m.snapshot();
        assert_eq!(s.persist_commit_seconds_count, 2);
        assert_eq!(
            s.persist_commit_seconds_buckets[1], 1,
            "2ms lands in the le=0.005 bucket"
        );
        assert_eq!(
            s.persist_commit_seconds_buckets.iter().sum::<u64>(),
            1,
            "3s exceeds all buckets, only count/sum advance"
        );
        assert!(s.persist_commit_seconds_sum_us >= 3_002_000);
        assert_eq!(s.persist_queue_depth, 4, "gauge = last observed value");
    }
}

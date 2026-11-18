//! Opt-in session-metrics JSONL capture (the offline observability
//! artifact; knob-driven, default off).
//!
//! Why: `SessionMetrics` + the rpc `/metrics` text face are pull-based
//! observation — performance issues are reported after the fact, and
//! post-hoc analysis then has nothing but log text. With
//! `BH_METRICS_TRACE=<path>` set, one full
//! [`MetricsSnapshot`](crate::metrics::MetricsSnapshot) per 1s session
//! tick is appended to that file as a single JSON line, giving the
//! offline report script (`scripts/metrics_report.py`) a standard
//! input format. Upstream anchor: libtorrent's `session_log_alert`
//! capture tooling (`tools/session_log_alerts.cpp`) — observability
//! artifacts get a stable offline format so analysis never depends on
//! "what happened to be open at the time".
//!
//! Budget discipline (bounded capture):
//! - the file is capped at `BH_METRICS_TRACE_BYTES` (default 64MiB,
//!   clamped [1MiB, 1GiB]); when the next line would exceed the cap,
//!   the file is **truncated to zero and rewritten from the start**
//!   (truncate, not roll: rolling would multiply cap x retained
//!   generations and turn a bounded diagnostic into an unbounded one —
//!   the exact failure mode the memory/IO budget discipline exists to
//!   prevent; a single capped file is a hard total-bytes bound and
//!   always holds the most recent <= cap of capture);
//! - open truncates any previous capture (each process run starts a
//!   fresh capture: mixed-session counter resets inside one file would
//!   read as counter regressions; `ts_ms` disambiguates nothing that
//!   a fresh file does not).
//!
//! Failure policy: capture is a diagnostic, never a dependency — open
//! failures, per-line IO errors, and a full writer queue all warn and
//! continue (the session runs on unchanged; a full queue drops the
//! line: at 1 line/s the writer would have to stall for the channel
//! window before any drop, and dropping the oldest-unsent line is the
//! correct degradation for a tail-focused trace).
//!
//! Zero-cost contract when the knob is unset: the disabled state holds
//! no thread, no channel, no file, and no path string;
//! [`MetricsTrace::record`] returns without touching the serializer.
//! The rpc `/metrics` render face is completely unchanged — this
//! module only *reads* the same snapshot source.
//!
//! Concurrency: the writer is a dedicated `std::thread` (disk IO off
//! the async runtime, per the blocking-operations rule); the async
//! side only serializes (~3KiB string build at 1Hz) and `try_send`s
//! into a bounded `sync_channel` (capacity 4 — about four seconds of
//! burst headroom; never blocks the session tick).

use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

use crate::metrics::MetricsSnapshot;

/// Bounded hand-off depth between the session tick and the writer
/// thread (lines; ~4s of 1Hz capture burst headroom before drops).
const TRACE_CHANNEL_CAPACITY: usize = 4;

/// Enabled-state handle: the sender half plus the drop/error
/// observation counters (the writer thread never panics by
/// construction — every IO result is matched, never unwrapped).
#[derive(Debug)]
struct TraceHandle {
    tx: SyncSender<String>,
    dropped_lines: AtomicU64,
    /// Warn-once latch for the first dropped line (a steady warn rate
    /// would add noise to the very session being diagnosed).
    warned_drop: std::sync::atomic::AtomicBool,
}

/// Opt-in session-metrics JSONL capture writer (structure in the
/// module docs). Cheap to hold in the disabled state; `Clone` is
/// deliberately absent (single owner = the session actor).
#[derive(Debug)]
pub struct MetricsTrace {
    inner: Option<TraceHandle>,
}

impl MetricsTrace {
    /// The disabled state (knob unset / open failed): `record` is a
    /// no-op, zero I/O, zero threads.
    pub fn disabled() -> Self {
        MetricsTrace { inner: None }
    }

    /// Open a capture at `path` with an explicit byte cap. The file is
    /// created/truncated (fresh capture per run) and a writer thread
    /// is spawned; dropping every [`MetricsTrace`] clone of the sender
    /// flushes and closes it.
    ///
    /// # Errors
    ///
    /// The `std::fs::OpenOptions` open error as-is (parent missing,
    /// permission denied, ...). The caller decides the degradation —
    /// production uses [`Self::open_or_warn`] (warn + disabled).
    pub fn open(path: &Path, cap_bytes: u64) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        let (tx, rx) = sync_channel::<String>(TRACE_CHANNEL_CAPACITY);
        let spawned = std::thread::Builder::new()
            .name("taiji-metrics-trace".to_owned())
            .spawn(move || writer_loop(file, cap_bytes, rx));
        match spawned {
            Ok(_join) => {
                info!(target: "taiji::engine::metrics_trace",
                    path = %path.display(), cap_bytes,
                    "session metrics trace open (one MetricsSnapshot JSONL line per 1s tick)");
                Ok(MetricsTrace {
                    inner: Some(TraceHandle {
                        tx,
                        dropped_lines: AtomicU64::new(0),
                        warned_drop: std::sync::atomic::AtomicBool::new(false),
                    }),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Open-or-degrade: open failure (or writer-thread spawn failure)
    /// warns once and returns the disabled state — capture is never
    /// fatal (the module's failure policy).
    pub fn open_or_warn(path: &Path, cap_bytes: u64) -> Self {
        match Self::open(path, cap_bytes) {
            Ok(t) => t,
            Err(e) => {
                warn!(target: "taiji::engine::metrics_trace",
                    path = %path.display(), error = %e,
                    "session metrics trace open failed; continuing without capture");
                Self::disabled()
            }
        }
    }

    /// Production assembly: `BH_METRICS_TRACE` unset/blank = disabled
    /// (zero I/O — no path is touched); set = open at that path with
    /// the `BH_METRICS_TRACE_BYTES` cap (warn-and-continue on open
    /// failure).
    pub fn from_env() -> Self {
        match taiji_io::knobs::metrics_trace_path() {
            None => Self::disabled(),
            Some(path) => Self::open_or_warn(&path, taiji_io::knobs::metrics_trace_cap_bytes()),
        }
    }

    /// Whether lines are being captured (the tick-arm assembly input;
    /// false in the disabled state).
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Lines dropped on a full writer queue (the honest-degradation
    /// observation face; 0 in the disabled state).
    pub fn dropped_lines(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |h| h.dropped_lines.load(Ordering::Relaxed))
    }

    /// Serialize and hand one snapshot to the writer thread. No-op in
    /// the disabled state (the zero-I/O contract). A full queue drops
    /// the line (counted; the first drop warns once).
    pub fn record(&self, snap: &MetricsSnapshot) {
        let Some(h) = self.inner.as_ref() else {
            return;
        };
        let line = snapshot_line(unix_epoch_ms(), snap);
        if let Err(err) = h.tx.try_send(line) {
            let _line = match err {
                TrySendError::Full(line) => line,
                TrySendError::Disconnected(line) => line,
            };
            h.dropped_lines.fetch_add(1, Ordering::Relaxed);
            if !h.warned_drop.swap(true, Ordering::Relaxed) {
                warn!(target: "taiji::engine::metrics_trace",
                    "session metrics trace writer fell behind; dropping capture lines \
                     (capture only — the session is unaffected)");
            }
        }
    }
}

/// Writer thread body: serial line writes with truncate-at-cap (the
/// bounded-budget policy in the module docs; line granularity — a
/// line is never split across a wrap). IO errors warn and the capture
/// continues (a transient error must not kill the whole session's
/// trace).
fn writer_loop(mut file: std::fs::File, cap_bytes: u64, rx: Receiver<String>) {
    use std::io::Seek as _;
    let mut written = 0u64;
    while let Ok(line) = rx.recv() {
        let line_len = line.len() as u64;
        if written.saturating_add(line_len.saturating_add(1)) > cap_bytes {
            // Wrap: truncate and restart from offset 0 (the file keeps
            // the most recent <= cap of capture; see module docs for
            // the truncate-vs-roll rationale).
            if let Err(e) = file
                .set_len(0)
                .and_then(|()| file.seek(std::io::SeekFrom::Start(0)))
            {
                warn!(target: "taiji::engine::metrics_trace", error = %e,
                    "session metrics trace cap reset failed; stopping capture");
                return;
            }
            written = 0;
        }
        match file
            .write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
        {
            Ok(()) => written = written.saturating_add(line_len + 1),
            Err(e) => {
                warn!(target: "taiji::engine::metrics_trace", error = %e,
                    "session metrics trace write failed; continuing (next tick retries)");
            }
        }
    }
    // Sender dropped (session teardown): flush the OS-side file state
    // before exiting so a reader right after shutdown sees every
    // drained line. std File has no user-space buffer; sync_data is
    // the honest durability gesture, failures irrelevant at teardown.
    let _ = file.sync_data();
}

/// Unix epoch milliseconds (saturating; u64 ms is valid far past any
/// plausible session lifetime).
fn unix_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Minimal JSON object writer for the capture line. Every value is a
/// u64 or an array of u64 and every key is static ASCII, so no string
/// escaping can ever be needed — validity is pinned by the parse test
/// below rather than by pulling a JSON dependency onto the engine's
/// runtime face.
struct LineWriter {
    buf: String,
    first: bool,
}

impl LineWriter {
    fn new() -> Self {
        LineWriter {
            // The object opens here so every writer method can assume
            // it is appending after a possible comma only.
            buf: String::from("{"),
            first: true,
        }
    }

    fn key(&mut self, k: &str) {
        if self.first {
            self.first = false;
        } else {
            self.buf.push(',');
        }
        self.buf.push('"');
        self.buf.push_str(k);
        self.buf.push_str("\":");
    }

    fn u64(&mut self, k: &str, v: u64) {
        self.key(k);
        let _ = std::fmt::Write::write_fmt(&mut self.buf, format_args!("{v}"));
    }

    fn arr(&mut self, k: &str, vs: &[u64]) {
        self.key(k);
        self.buf.push('[');
        for (i, v) in vs.iter().enumerate() {
            if i > 0 {
                self.buf.push(',');
            }
            let _ = std::fmt::Write::write_fmt(&mut self.buf, format_args!("{v}"));
        }
        self.buf.push(']');
    }

    fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

/// One capture line: `ts_ms` (unix epoch milliseconds) followed by
/// every [`MetricsSnapshot`] field, key = the struct field name
/// (labels already inlined by the snapshot's flat shape — e.g.
/// `bytes_down_tcp_total` is the `{transport="tcp"}` slice of the
/// rpc face's `taiji_peer_supply_bytes_total`). Field order follows
/// the struct declaration; consumers must not rely on ordering, only
/// on the key set.
pub fn snapshot_line(ts_ms: u64, s: &MetricsSnapshot) -> String {
    let mut w = LineWriter::new();
    w.u64("ts_ms", ts_ms);
    w.u64("uptime_seconds", s.uptime_seconds);
    w.u64("panic_total", s.panic_total);
    w.u64("torrent_completed_total", s.torrent_completed_total);
    w.u64("bytes_down_total", s.bytes_down_total);
    w.u64("bytes_up_total", s.bytes_up_total);
    w.u64("bytes_down_tcp_total", s.bytes_down_tcp_total);
    w.u64("bytes_down_utp_total", s.bytes_down_utp_total);
    w.u64("rpc_error_misuse_total", s.rpc_error_misuse_total);
    w.u64("rpc_error_internal_total", s.rpc_error_internal_total);
    w.u64("conn_tcp_in", s.conn_tcp_in);
    w.u64("conn_tcp_out", s.conn_tcp_out);
    w.u64("conn_utp_in", s.conn_utp_in);
    w.u64("conn_utp_out", s.conn_utp_out);
    w.u64("conn_choked", s.conn_choked);
    w.u64("peers_by_class_local", s.peers_by_class_local);
    w.u64("peers_by_class_tcp", s.peers_by_class_tcp);
    w.u64("peers_by_class_utp", s.peers_by_class_utp);
    w.u64("peer_bans_total", s.peer_bans_total);
    w.u64("redial_attempts_total", s.redial_attempts_total);
    w.u64("redial_connected_total", s.redial_connected_total);
    w.u64("redial_pool_size", s.redial_pool_size);
    w.u64("dht_nodes_v4", s.dht_nodes_v4);
    w.u64("dht_nodes_v6", s.dht_nodes_v6);
    w.u64("dht_queries_ping_total", s.dht_queries_ping_total);
    w.u64("dht_queries_find_node_total", s.dht_queries_find_node_total);
    w.u64("dht_queries_get_peers_total", s.dht_queries_get_peers_total);
    w.u64(
        "dht_queries_announce_peer_total",
        s.dht_queries_announce_peer_total,
    );
    w.u64("dht_inbound_packets_total", s.dht_inbound_packets_total);
    w.u64("dht_inbound_queries_total", s.dht_inbound_queries_total);
    w.u64(
        "dht_inbound_unmatched_drops_total",
        s.dht_inbound_unmatched_drops_total,
    );
    w.u64("tracker_ok_total", s.tracker_ok_total);
    w.u64("tracker_fail_total", s.tracker_fail_total);
    w.u64("mse_arc4_total", s.mse_arc4_total);
    w.u64("mse_plain_total", s.mse_plain_total);
    w.u64("utp_recv_total", s.utp_recv_total);
    w.u64("utp_drop_total", s.utp_drop_total);
    w.u64("hashpool_queue_depth", s.hashpool_queue_depth);
    w.u64("block_inflight", s.block_inflight);
    w.u64("blocks_verified_total", s.blocks_verified_total);
    w.u64("wrcache_flush_total", s.wrcache_flush_total);
    w.u64("wrcache_evict_total", s.wrcache_evict_total);
    w.u64("wrcache_evict_bytes_total", s.wrcache_evict_bytes_total);
    w.u64("spill_write_bytes_total", s.spill_write_bytes_total);
    w.u64("spill_read_bytes_total", s.spill_read_bytes_total);
    w.u64("spill_readback_pieces_total", s.spill_readback_pieces_total);
    w.u64(
        "spill_fallback_destroy_bytes_total",
        s.spill_fallback_destroy_bytes_total,
    );
    w.u64(
        "holepunch_rendezvous_sent_total",
        s.holepunch_rendezvous_sent_total,
    );
    w.u64(
        "holepunch_relayed_connects_total",
        s.holepunch_relayed_connects_total,
    );
    w.u64("holepunch_punch_dials_total", s.holepunch_punch_dials_total);
    w.u64(
        "holepunch_punch_established_total",
        s.holepunch_punch_established_total,
    );
    w.u64(
        "holepunch_introducer_hits_total",
        s.holepunch_introducer_hits_total,
    );
    w.u64(
        "holepunch_no_introducer_total",
        s.holepunch_no_introducer_total,
    );
    w.u64(
        "holepunch_punch_failed_nat_total",
        s.holepunch_punch_failed_nat_total,
    );
    w.u64("peer_leaves_local_total", s.peer_leaves_local_total);
    w.u64(
        "peer_leaves_peer_closed_total",
        s.peer_leaves_peer_closed_total,
    );
    w.u64("peer_leaves_io_total", s.peer_leaves_io_total);
    w.u64("peer_leaves_protocol_total", s.peer_leaves_protocol_total);
    w.u64("peer_leaves_cancelled_total", s.peer_leaves_cancelled_total);
    w.u64(
        "block_arena_lease_hits_total",
        s.block_arena_lease_hits_total,
    );
    w.u64(
        "block_arena_alloc_fallback_total",
        s.block_arena_alloc_fallback_total,
    );
    w.u64(
        "block_arena_outstanding_blocks",
        s.block_arena_outstanding_blocks,
    );
    w.u64("block_arena_cap_bytes", s.block_arena_cap_bytes);
    w.arr(
        "peer_inflight_depth_buckets",
        &s.peer_inflight_depth_buckets,
    );
    w.u64("peer_inflight_depth_count", s.peer_inflight_depth_count);
    w.u64("peer_inflight_depth_sum", s.peer_inflight_depth_sum);
    w.u64("peer_inflight_active", s.peer_inflight_active);
    w.arr(
        "block_buffer_seconds_buckets",
        &s.block_buffer_seconds_buckets,
    );
    w.u64("block_buffer_seconds_count", s.block_buffer_seconds_count);
    w.u64("block_buffer_seconds_sum_us", s.block_buffer_seconds_sum_us);
    w.arr(
        "block_verify_seconds_buckets",
        &s.block_verify_seconds_buckets,
    );
    w.u64("block_verify_seconds_count", s.block_verify_seconds_count);
    w.u64("block_verify_seconds_sum_us", s.block_verify_seconds_sum_us);
    w.arr(
        "block_write_seconds_buckets",
        &s.block_write_seconds_buckets,
    );
    w.u64("block_write_seconds_count", s.block_write_seconds_count);
    w.u64("block_write_seconds_sum_us", s.block_write_seconds_sum_us);
    w.u64("http_extents_active", s.http_extents_active);
    w.u64("http_conn_aimd", s.http_conn_aimd);
    w.u64("http_stolen_total", s.http_stolen_total);
    w.arr("rpc_requests", &s.rpc_requests);
    w.arr("rpc_duration_buckets", &s.rpc_duration_buckets);
    w.u64("rpc_duration_count", s.rpc_duration_count);
    w.u64("rpc_duration_sum_us", s.rpc_duration_sum_us);
    w.u64(
        "rpc_conn_rejected_total_scope_total",
        s.rpc_conn_rejected_total_scope_total,
    );
    w.u64(
        "rpc_conn_rejected_total_scope_per_ip",
        s.rpc_conn_rejected_total_scope_per_ip,
    );
    w.u64("rpc_auth_fail_total", s.rpc_auth_fail_total);
    w.u64("dns_network_changes_total", s.dns_network_changes_total);
    w.u64("dns_backend_queries_total", s.dns_backend_queries_total);
    w.u64("dns_coalesced_total", s.dns_coalesced_total);
    w.u64("dns_negative_hits_total", s.dns_negative_hits_total);
    w.u64("dns_capacity_rejected_total", s.dns_capacity_rejected_total);
    w.u64("dns_system_queries_total", s.dns_system_queries_total);
    w.u64("dns_system_coalesced_total", s.dns_system_coalesced_total);
    w.u64("dns_system_active", s.dns_system_active);
    w.u64("dns_system_queued", s.dns_system_queued);
    w.u64("dns_lookups_hit_total", s.dns_lookups_hit_total);
    w.u64("dns_lookups_miss_total", s.dns_lookups_miss_total);
    w.u64("dns_lookups_error_total", s.dns_lookups_error_total);
    w.u64("dns_lookups_timeout_total", s.dns_lookups_timeout_total);
    w.u64(
        "dns_family_mix_v4_only_total",
        s.dns_family_mix_v4_only_total,
    );
    w.u64(
        "dns_family_mix_v6_only_total",
        s.dns_family_mix_v6_only_total,
    );
    w.u64("dns_family_mix_dual_total", s.dns_family_mix_dual_total);
    w.u64("dns_events_evict_ttl_total", s.dns_events_evict_ttl_total);
    w.u64(
        "dns_events_evict_capacity_total",
        s.dns_events_evict_capacity_total,
    );
    w.arr(
        "dns_resolve_seconds_buckets",
        &s.dns_resolve_seconds_buckets,
    );
    w.u64("dns_resolve_seconds_count", s.dns_resolve_seconds_count);
    w.arr(
        "dns_system_queue_seconds_buckets",
        &s.dns_system_queue_seconds_buckets,
    );
    w.u64(
        "dns_system_queue_seconds_count",
        s.dns_system_queue_seconds_count,
    );
    w.u64(
        "dns_system_queue_seconds_sum_us",
        s.dns_system_queue_seconds_sum_us,
    );
    w.arr(
        "dns_system_lookup_seconds_buckets",
        &s.dns_system_lookup_seconds_buckets,
    );
    w.u64(
        "dns_system_lookup_seconds_count",
        s.dns_system_lookup_seconds_count,
    );
    w.u64(
        "dns_system_lookup_seconds_sum_us",
        s.dns_system_lookup_seconds_sum_us,
    );
    w.u64("dns_resolve_seconds_sum_us", s.dns_resolve_seconds_sum_us);
    w.u64(
        "http_errors_dns_permanent_total",
        s.http_errors_dns_permanent_total,
    );
    w.u64(
        "http_errors_dns_transient_total",
        s.http_errors_dns_transient_total,
    );
    w.u64("http_errors_timeout_total", s.http_errors_timeout_total);
    w.u64("http_errors_tls_total", s.http_errors_tls_total);
    w.u64("http_errors_connect_total", s.http_errors_connect_total);
    w.u64("http_errors_refused_total", s.http_errors_refused_total);
    w.u64("http_errors_reset_total", s.http_errors_reset_total);
    w.u64("http_errors_http_4xx_total", s.http_errors_http_4xx_total);
    w.u64("http_errors_http_5xx_total", s.http_errors_http_5xx_total);
    w.u64("http_retries_total", s.http_retries_total);
    w.u64("http_extent_reassign_total", s.http_extent_reassign_total);
    w.u64("http_mirror_demote_total", s.http_mirror_demote_total);
    w.u64("http_mirror_remove_total", s.http_mirror_remove_total);
    w.u64("http_mirror_restore_total", s.http_mirror_restore_total);
    w.u64("http_stall_detected_total", s.http_stall_detected_total);
    w.u64("http_aimd_grow_total", s.http_aimd_grow_total);
    w.u64("http_aimd_shrink_total", s.http_aimd_shrink_total);
    w.arr(
        "http_request_first_byte_buckets",
        &s.http_request_first_byte_buckets,
    );
    w.u64(
        "http_request_first_byte_count",
        s.http_request_first_byte_count,
    );
    w.u64(
        "http_request_first_byte_sum_us",
        s.http_request_first_byte_sum_us,
    );
    w.arr("http_request_total_buckets", &s.http_request_total_buckets);
    w.u64("http_request_total_count", s.http_request_total_count);
    w.u64("http_request_total_sum_us", s.http_request_total_sum_us);
    w.arr(
        "http_slowstart_seconds_buckets",
        &s.http_slowstart_seconds_buckets,
    );
    w.u64(
        "http_slowstart_seconds_count",
        s.http_slowstart_seconds_count,
    );
    w.u64(
        "http_slowstart_seconds_sum_us",
        s.http_slowstart_seconds_sum_us,
    );
    w.u64(
        "http_conn_establishments_total",
        s.http_conn_establishments_total,
    );
    w.arr(
        "http_conn_establish_seconds_buckets",
        &s.http_conn_establish_seconds_buckets,
    );
    w.u64(
        "http_conn_establish_seconds_count",
        s.http_conn_establish_seconds_count,
    );
    w.u64(
        "http_conn_establish_seconds_sum_us",
        s.http_conn_establish_seconds_sum_us,
    );
    w.u64("disk_sink_writes_total", s.disk_sink_writes_total);
    w.u64(
        "disk_sink_writes_bytes_total",
        s.disk_sink_writes_bytes_total,
    );
    w.u64("disk_sink_inflight", s.disk_sink_inflight);
    w.u64("disk_volatile_reads_total", s.disk_volatile_reads_total);
    w.u64(
        "disk_cache_advise_failures_total",
        s.disk_cache_advise_failures_total,
    );
    w.arr(
        "disk_finalize_file_fsync_buckets",
        &s.disk_finalize_file_fsync_buckets,
    );
    w.u64(
        "disk_finalize_file_fsync_count",
        s.disk_finalize_file_fsync_count,
    );
    w.u64(
        "disk_finalize_file_fsync_sum_us",
        s.disk_finalize_file_fsync_sum_us,
    );
    w.arr(
        "disk_finalize_fsync_dir_buckets",
        &s.disk_finalize_fsync_dir_buckets,
    );
    w.u64(
        "disk_finalize_fsync_dir_count",
        s.disk_finalize_fsync_dir_count,
    );
    w.u64(
        "disk_finalize_fsync_dir_sum_us",
        s.disk_finalize_fsync_dir_sum_us,
    );
    w.arr(
        "disk_finalize_rename_buckets",
        &s.disk_finalize_rename_buckets,
    );
    w.u64("disk_finalize_rename_count", s.disk_finalize_rename_count);
    w.u64("disk_finalize_rename_sum_us", s.disk_finalize_rename_sum_us);
    w.arr(
        "disk_prealloc_seconds_buckets",
        &s.disk_prealloc_seconds_buckets,
    );
    w.u64("disk_prealloc_seconds_count", s.disk_prealloc_seconds_count);
    w.u64(
        "disk_prealloc_seconds_sum_us",
        s.disk_prealloc_seconds_sum_us,
    );
    w.u64("persist_queue_depth", s.persist_queue_depth);
    w.arr(
        "persist_commit_seconds_buckets",
        &s.persist_commit_seconds_buckets,
    );
    w.u64(
        "persist_commit_seconds_count",
        s.persist_commit_seconds_count,
    );
    w.u64(
        "persist_commit_seconds_sum_us",
        s.persist_commit_seconds_sum_us,
    );
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique temp path (the crate's test convention: no tempfile
    /// dependency on this crate's unit tests, same shape as the
    /// verify_pool fixtures).
    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "taiji-metrics-trace-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("mkdir: {e}"));
        d
    }

    /// Poll until the complete (newline-terminated) lines of the file
    /// at `path` satisfy `pred` (the writer thread drains
    /// asynchronously, so intermediate states are observable — the
    /// predicate must match only the settled final state; 5s budget).
    fn wait_lines<F>(path: &Path, mut pred: F) -> Vec<String>
    where
        F: FnMut(&[String]) -> bool,
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let text = std::fs::read_to_string(path).unwrap_or_default();
            // Only newline-terminated text counts (a half-written tail
            // line is not a settled state).
            if text.ends_with('\n') {
                let lines: Vec<String> = text.lines().map(str::to_owned).collect();
                if pred(&lines) {
                    return lines;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "capture file did not reach the expected state in time (content: {text:?})"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// The capture line must be valid JSON carrying ts_ms plus the
    /// diagnostic core of the snapshot (keys = the struct field names;
    /// arrays inlined).
    #[test]
    fn snapshot_line_parses_as_json_with_expected_keys() {
        let snap = MetricsSnapshot {
            uptime_seconds: 7,
            bytes_down_total: 123456,
            peers_by_class_tcp: 3,
            dht_nodes_v4: 17,
            rpc_duration_buckets: vec![1, 2, 3],
            ..MetricsSnapshot::default()
        };
        let line = snapshot_line(1_700_000_000_123, &snap);
        let v: serde_json::Value =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("line not valid JSON: {e}"));
        let obj = v.as_object().unwrap_or_else(|| panic!("not an object"));
        assert_eq!(
            obj.get("ts_ms").and_then(|v| v.as_u64()),
            Some(1_700_000_000_123)
        );
        assert_eq!(obj.get("uptime_seconds").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(
            obj.get("bytes_down_total").and_then(|v| v.as_u64()),
            Some(123456)
        );
        assert_eq!(
            obj.get("peers_by_class_tcp").and_then(|v| v.as_u64()),
            Some(3)
        );
        assert_eq!(obj.get("dht_nodes_v4").and_then(|v| v.as_u64()), Some(17));
        assert_eq!(
            obj.get("rpc_duration_buckets"),
            Some(&serde_json::json!([1, 2, 3]))
        );
        // Field-count sanity: the full snapshot projection is not a
        // hollow subset (>= the /metrics family order of magnitude).
        assert!(obj.len() > 120, "line carries only {} keys", obj.len());
    }

    /// Disabled state: no file, no thread, record() is a silent no-op
    /// (the zero-added-I/O contract when the knob is unset).
    #[test]
    fn disabled_trace_performs_no_io() {
        let dir = tmp_path("disabled");
        let trace = MetricsTrace::disabled();
        assert!(!trace.is_enabled());
        assert_eq!(trace.dropped_lines(), 0);
        trace.record(&MetricsSnapshot::default());
        assert_eq!(trace.dropped_lines(), 0);
        // Nothing was created anywhere under the scratch dir.
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir: {e}"))
            .count();
        assert_eq!(entries, 0, "disabled trace must not create files");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// from_env with the knob unset (the test environment does not set
    /// it) = disabled — the production assembly path performs zero I/O.
    #[test]
    fn from_env_unset_is_disabled() {
        // Guard: if the environment ever sets the knob, this test
        // would silently stop covering the unset arm.
        assert!(
            std::env::var("BH_METRICS_TRACE").is_err(),
            "BH_METRICS_TRACE is set in the test environment; unset it for this arm"
        );
        assert!(!MetricsTrace::from_env().is_enabled());
    }

    /// Open failure degrades to disabled with no panic (warn-and-
    /// continue; a path under a missing parent directory).
    #[test]
    fn open_failure_degrades_to_disabled() {
        let bad = tmp_path("nope").join("missing-parent").join("t.jsonl");
        let trace = MetricsTrace::open_or_warn(&bad, 1024 * 1024);
        assert!(!trace.is_enabled());
    }

    /// Open + record + drop: each snapshot becomes one JSONL line; the
    /// writer drains everything queued before exit (close-on-lifecycle).
    #[test]
    fn records_land_as_jsonl_lines() {
        let dir = tmp_path("record");
        let path = dir.join("trace.jsonl");
        let trace =
            MetricsTrace::open(&path, 64 * 1024 * 1024).unwrap_or_else(|e| panic!("open: {e}"));
        assert!(trace.is_enabled());
        for i in 0..3u64 {
            trace.record(&MetricsSnapshot {
                uptime_seconds: i,
                bytes_down_total: i * 1024,
                ..MetricsSnapshot::default()
            });
        }
        drop(trace);
        let lines = wait_lines(&path, |ls| ls.len() == 3);
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line {i} not valid JSON: {e}"));
            assert_eq!(
                v.get("uptime_seconds").and_then(|v| v.as_u64()),
                Some(i as u64)
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cap enforcement (truncate-at-cap, line granularity): with a cap
    /// smaller than three full lines but larger than one, the wrap
    /// keeps the file within the cap and every surviving line stays
    /// whole/parseable.
    #[test]
    fn cap_truncates_and_keeps_lines_whole() {
        let dir = tmp_path("cap");
        let path = dir.join("trace.jsonl");
        let probe = snapshot_line(0, &MetricsSnapshot::default());
        // Cap = one line + change, < two lines: after the second record
        // the file must wrap back to exactly one line.
        let cap = (probe.len() as u64) + 64;
        assert!(cap < 2 * probe.len() as u64, "probe line len unexpected");
        let trace = MetricsTrace::open(&path, cap).unwrap_or_else(|e| panic!("open: {e}"));
        for i in 0..2u64 {
            trace.record(&MetricsSnapshot {
                uptime_seconds: i,
                ..MetricsSnapshot::default()
            });
        }
        // Dropping the trace closes the writer after it drains every
        // queued line — the settled file state is deterministic.
        drop(trace);
        // Settled state = exactly one line, the most recent snapshot
        // (the wrap dropped the older segment). Waiting on the uptime
        // value (not just the line count — the pre-wrap intermediate
        // state also holds one complete line).
        let lines = wait_lines(&path, |ls| {
            ls.len() == 1
                && serde_json::from_str::<serde_json::Value>(&ls[0])
                    .is_ok_and(|v| v.get("uptime_seconds").and_then(|v| v.as_u64()) == Some(1))
        });
        let v: serde_json::Value = serde_json::from_str(&lines[0])
            .unwrap_or_else(|e| panic!("post-wrap line not valid JSON: {e}"));
        assert_eq!(v.get("uptime_seconds").and_then(|v| v.as_u64()), Some(1));
        let size = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("metadata: {e}"))
            .len();
        assert!(size <= cap, "file size {size} exceeds cap {cap}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

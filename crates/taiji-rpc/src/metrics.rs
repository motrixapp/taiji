//! Prometheus `/metrics` rendering surface.
//!
//! Exposed as `GET /metrics` on the same port and bind face as
//! `/jsonrpc`, behind the same Basic gate via the server-layer
//! `metrics_gate` (with no `--rpc-user` configured the gate is always
//! open — in that case the bind face is loopback-only). Hard invariants:
//! the metric face carries no sensitive fields — rpc-secret/user/passwd
//! never appear in any metric or label; label cardinality is bounded —
//! every label value is a fixed enum
//! (state/transport/direction/family/kind/method), and gids, paths,
//! info-hashes, and tracker URLs never become labels; the `method`
//! label is anchored to the frozen [`RPC_METHODS`] table, with unknown
//! method names merged into one `unknown` slot. Prometheus text format
//! 0.0.4, hand-rendered, no exporter dependency.
//!
//! Family inventory, data sources, and value-range notes:
//! docs/design/rpc.md.
//!
//! Upstream anchor mapping: docs/design/rpc.md

use std::sync::Arc;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

use taiji_core::session::{
    BLOCK_STAGE_BUCKETS_SECONDS, CommandReply, DISK_FINALIZE_BUCKETS_SECONDS,
    DNS_RESOLVE_BUCKETS_SECONDS, HTTP_CONN_ESTABLISH_BUCKETS_SECONDS, HTTP_REQUEST_BUCKETS_SECONDS,
    HTTP_SLOWSTART_BUCKETS_SECONDS, MetricsSnapshot, PEER_INFLIGHT_BUCKETS,
    PERSIST_COMMIT_BUCKETS_SECONDS, RPC_DURATION_BUCKETS_SECONDS, RPC_METHOD_SLOT_UNKNOWN,
    RPC_METHODS, SessionCommand, SessionHandle, StatusKind,
};

use crate::dispatch::AppState;

/// `/metrics` response Content-Type (Prometheus text 0.0.4).
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Task-state distribution (derived in the rpc layer via the existing
/// query face; label values = the six aria2 status states, rendered
/// through the adapter word table — see the render loop).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TorrentStateCounts {
    pub active: u64,
    pub waiting: u64,
    pub paused: u64,
    pub complete: u64,
    pub error: u64,
    pub removed: u64,
}

impl TorrentStateCounts {
    /// The count of one [`StatusKind`] (the render loop's only field
    /// access point — exhaustive, so a new METRICS_STATES member that
    /// lacks a counter breaks here at compile time).
    pub(crate) fn count(&self, kind: StatusKind) -> u64 {
        match kind {
            StatusKind::Active => self.active,
            StatusKind::Waiting => self.waiting,
            StatusKind::Paused => self.paused,
            StatusKind::Complete => self.complete,
            StatusKind::Error => self.error,
            StatusKind::Removed => self.removed,
            StatusKind::Seeding | StatusKind::Checking => 0,
        }
    }
}

/// `GET /metrics` rendering (the Basic gate lives in the server layer's
/// `metrics_gate`; this function only collects and renders).
/// `auth_backoff_active` = the active-window count from the auth-backoff
/// ledger (computed at render time; the render access point doubles as
/// the lazy cleanup point).
pub(crate) async fn metrics_handler(State(state): State<Arc<AppState>>) -> Response {
    let snap = state.session.metrics().snapshot();
    let states = collect_states(&state.session).await;
    let version = taiji_core::version_string();
    let auth_backoff_active = state.auth_backoff.active_windows() as u64;
    let body = render(&snap, &states, &version, auth_backoff_active);
    ([(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)], body).into_response()
}

/// Task-state collection (the existing snapshot face: same source as
/// getGlobalStat/tellWaiting/tellStopped; core always returns the full
/// view, counting happens in this layer). An exited session yields all
/// zeros (the metric face still renders, no 5xx).
async fn collect_states(session: &SessionHandle) -> TorrentStateCounts {
    let mut counts = TorrentStateCounts::default();
    if let Ok(CommandReply::GlobalStat(stat)) = session.call(SessionCommand::GetGlobalStat).await {
        counts.active = stat.num_active;
    }
    if let Ok(CommandReply::StatusList(waiting)) = session
        .call(SessionCommand::TellWaiting {
            offset: 0,
            num: u32::MAX,
            keys: Vec::new(),
        })
        .await
    {
        for v in waiting {
            match v.status {
                StatusKind::Waiting => counts.waiting += 1,
                StatusKind::Paused => counts.paused += 1,
                _ => {}
            }
        }
    }
    if let Ok(CommandReply::StatusList(stopped)) = session
        .call(SessionCommand::TellStopped {
            offset: 0,
            num: u32::MAX,
            keys: Vec::new(),
        })
        .await
    {
        for v in stopped {
            match v.status {
                StatusKind::Complete => counts.complete += 1,
                StatusKind::Error => counts.error += 1,
                StatusKind::Removed => counts.removed += 1,
                _ => {}
            }
        }
    }
    counts
}

/// Label value escaping (Prometheus text format: backslash, double quote, newline).
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// f64 text form (le/sum values; Prometheus accepts integer-form floats).
fn fmt_float(v: f64) -> String {
    if v == f64::INFINITY {
        "+Inf".to_string()
    } else if v == f64::NEG_INFINITY {
        "-Inf".to_string()
    } else {
        format!("{v}")
    }
}

struct Sample<'a> {
    name: &'a str,
    labels: &'a [(&'a str, String)],
    value: String,
}

/// One sample line (labels rendered in order; value already text).
fn write_sample(out: &mut String, s: Sample) {
    out.push_str(s.name);
    if !s.labels.is_empty() {
        out.push('{');
        for (i, (k, v)) in s.labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_label(v));
            out.push('"');
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&s.value);
    out.push('\n');
}

/// Render the `/metrics` body (pure function; table-driven tests
/// construct inputs directly).
///
/// Family order: session -> torrent -> connection -> protocol ->
/// internal pools (the rpc families follow the internal-pool rows).
/// `auth_backoff_active` = the active auth-backoff window count (no
/// label — the IP dimension never becomes a label).
pub(crate) fn render(
    snap: &MetricsSnapshot,
    states: &TorrentStateCounts,
    version: &str,
    auth_backoff_active: u64,
) -> String {
    let mut out = String::with_capacity(4096);

    // ---- session families ----
    out.push_str("# HELP taiji_build_info Engine build metadata.\n");
    out.push_str("# TYPE taiji_build_info gauge\n");
    write_sample(
        &mut out,
        Sample {
            name: "taiji_build_info",
            labels: &[("version", version.to_string())],
            value: "1".to_string(),
        },
    );
    out.push_str(
        "# HELP taiji_session_uptime_seconds Session uptime in seconds.\n\
         # TYPE taiji_session_uptime_seconds gauge\n",
    );
    out.push_str("taiji_session_uptime_seconds ");
    out.push_str(&snap.uptime_seconds.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_panic_total Engine task panics observed by the session.\n\
         # TYPE taiji_panic_total counter\n",
    );
    out.push_str("taiji_panic_total ");
    out.push_str(&snap.panic_total.to_string());
    out.push('\n');

    // ---- torrent families ----
    out.push_str(
        "# HELP taiji_torrents Torrent count by aria2 status (bounded label set).\n\
         # TYPE taiji_torrents gauge\n",
    );
    // Label set + words share one source with the wire table
    // (crate::aria2::status::METRICS_STATES + status_word — no
    // second handwritten list).
    for kind in crate::aria2::status::METRICS_STATES {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_torrents",
                labels: &[("state", crate::aria2::status::status_word(kind).to_string())],
                value: states.count(kind).to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_torrent_bytes_total Cumulative payload bytes transferred this session.\n\
         # TYPE taiji_torrent_bytes_total counter\n",
    );
    for (direction, n) in [("down", snap.bytes_down_total), ("up", snap.bytes_up_total)] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_torrent_bytes_total",
                labels: &[("direction", direction.to_string())],
                value: n.to_string(),
            },
        );
    }
    // Observability plumbing: two supply-byte counters by transport
    // (label = the fixed tcp|utp enum, no host/gid — cardinality
    // discipline; accounting = wire-received bytes, and the two families
    // sum to the bytes_down_total down value).
    out.push_str(
        "# HELP taiji_peer_supply_bytes_total Cumulative wire-received payload bytes by peer transport (tcp|utp; sums to bytes_down down direction).\n\
         # TYPE taiji_peer_supply_bytes_total counter\n",
    );
    for (transport, n) in [
        ("tcp", snap.bytes_down_tcp_total),
        ("utp", snap.bytes_down_utp_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_peer_supply_bytes_total",
                labels: &[("transport", transport.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_torrent_completed_total Torrents reached complete status.\n\
         # TYPE taiji_torrent_completed_total counter\n",
    );
    out.push_str("taiji_torrent_completed_total ");
    out.push_str(&snap.torrent_completed_total.to_string());
    out.push('\n');

    // ---- connection families ----
    out.push_str(
        "# HELP taiji_peer_connections Live peer connections by transport and direction.\n\
         # TYPE taiji_peer_connections gauge\n",
    );
    for (transport, direction, n) in [
        ("tcp", "in", snap.conn_tcp_in),
        ("tcp", "out", snap.conn_tcp_out),
        // µTP is not merged into the data plane yet: the series is
        // always 0 (honest zero; the feed point exists).
        ("utp", "in", snap.conn_utp_in),
        ("utp", "out", snap.conn_utp_out),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_peer_connections",
                labels: &[
                    ("transport", transport.to_string()),
                    ("direction", direction.to_string()),
                ],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_peer_connections_choked Live connections we currently choke.\n\
         # TYPE taiji_peer_connections_choked gauge\n",
    );
    out.push_str("taiji_peer_connections_choked ");
    out.push_str(&snap.conn_choked.to_string());
    out.push('\n');
    // Instrumentation: the per-peer in-flight depth histogram (sampled
    // per connection at the 1s engine tick; cardinality discipline — no
    // per-peer label, gids/addresses never become labels) + an
    // active-peer gauge.
    out.push_str(
        "# HELP taiji_peer_inflight_depth Per-peer outstanding request depth sampled at the 1s engine tick (mean = sum/count; buckets cover the adaptive window up to 256).\n\
         # TYPE taiji_peer_inflight_depth histogram\n",
    );
    let mut inflight_cumulative = 0u64;
    for (i, bound) in PEER_INFLIGHT_BUCKETS.iter().enumerate() {
        inflight_cumulative += snap
            .peer_inflight_depth_buckets
            .get(i)
            .copied()
            .unwrap_or(0);
        write_sample(
            &mut out,
            Sample {
                name: "taiji_peer_inflight_depth_bucket",
                labels: &[("le", fmt_float(*bound))],
                value: inflight_cumulative.to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_peer_inflight_depth_bucket",
            labels: &[("le", "+Inf".to_string())],
            value: snap.peer_inflight_depth_count.to_string(),
        },
    );
    out.push_str("taiji_peer_inflight_depth_sum ");
    out.push_str(&snap.peer_inflight_depth_sum.to_string());
    out.push('\n');
    out.push_str("taiji_peer_inflight_depth_count ");
    out.push_str(&snap.peer_inflight_depth_count.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_peer_inflight_active Peers with at least one outstanding request at the last engine tick.\n\
         # TYPE taiji_peer_inflight_active gauge\n",
    );
    out.push_str("taiji_peer_inflight_active ");
    out.push_str(&snap.peer_inflight_active.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_peer_bans_total Peer bans enacted (auto rules, SPEC §13).\n\
         # TYPE taiji_peer_bans_total counter\n",
    );
    out.push_str("taiji_peer_bans_total ");
    out.push_str(&snap.peer_bans_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_redial_attempts_total Redial-pool dial attempts (, libtorrent min_reconnect_time semantics).\n\
         # TYPE taiji_redial_attempts_total counter\n",
    );
    out.push_str("taiji_redial_attempts_total ");
    out.push_str(&snap.redial_attempts_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_redial_connected_total Redial dial attempts that completed a BT handshake .\n\
         # TYPE taiji_redial_connected_total counter\n",
    );
    out.push_str("taiji_redial_connected_total ");
    out.push_str(&snap.redial_connected_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_redial_pool_size Known-good disconnected peers awaiting redial (, bounded).\n\
         # TYPE taiji_redial_pool_size gauge\n",
    );
    out.push_str("taiji_redial_pool_size ");
    out.push_str(&snap.redial_pool_size.to_string());
    out.push('\n');

    // ---- holepunch observation family (rendered after redial, before
    // the protocol families) ----
    // The measured face for direct-connect punching: introducer hit
    // rate, rendezvous asks sent, punch dials and established dials.
    // Rendered names carry the `_total` suffix per the repo counter
    // naming discipline; single feed source, bridged as 1s-tick deltas.
    out.push_str(
        "# HELP taiji_holepunch_rendezvous_sent_total Rendezvous asks sent to PEX introducers (trigger face, sent = counted; no receipt accounting).\n\
         # TYPE taiji_holepunch_rendezvous_sent_total counter\n",
    );
    out.push_str("taiji_holepunch_rendezvous_sent_total ");
    out.push_str(&snap.holepunch_rendezvous_sent_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_holepunch_relayed_connects_total Rendezvous introductions relayed (one connect load to each side; counted per introduction action).\n\
         # TYPE taiji_holepunch_relayed_connects_total counter\n",
    );
    out.push_str("taiji_holepunch_relayed_connects_total ");
    out.push_str(&snap.holepunch_relayed_connects_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_holepunch_punch_dials_total Outbound punch dials spawned after all admission gates passed.\n\
         # TYPE taiji_holepunch_punch_dials_total counter\n",
    );
    out.push_str("taiji_holepunch_punch_dials_total ");
    out.push_str(&snap.holepunch_punch_dials_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_holepunch_punch_established_total Punch-sourced dials that completed a BT handshake (counts in fallback mode too).\n\
         # TYPE taiji_holepunch_punch_established_total counter\n",
    );
    out.push_str("taiji_holepunch_punch_established_total ");
    out.push_str(&snap.holepunch_punch_established_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_holepunch_introducer_hits_total Dial failures with a live PEX introducer whose ask-backoff has elapsed (numerator of the punchable-share ratio).\n\
         # TYPE taiji_holepunch_introducer_hits_total counter\n",
    );
    out.push_str("taiji_holepunch_introducer_hits_total ");
    out.push_str(&snap.holepunch_introducer_hits_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_holepunch_no_introducer_total Dial failures without a usable introducer (no PEX delivery / backoff pending / TTL expired; denominator pair of introducer_hits).\n\
         # TYPE taiji_holepunch_no_introducer_total counter\n",
    );
    out.push_str("taiji_holepunch_no_introducer_total ");
    out.push_str(&snap.holepunch_no_introducer_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_holepunch_punch_failed_nat_total Punch windows exhausted with zero peer response across all attempts (port-prediction plane never opened; symmetric-NAT shape).\n\
         # TYPE taiji_holepunch_punch_failed_nat_total counter\n",
    );
    out.push_str("taiji_holepunch_punch_failed_nat_total ");
    out.push_str(&snap.holepunch_punch_failed_nat_total.to_string());
    out.push('\n');

    // ---- peer-leave reason family (connection-retention
    // observability; label = the closed five-value reason set; the
    // single label-contract source is the taiji-core
    // session::MetricsSnapshot field docs, a LeaveKind five-way
    // projection) ----
    // Attribution carriers: peer-closed (the peer closed) / local (we
    // closed) / io (transport error) / protocol; cancelled = the engine
    // teardown cancellation, excluded from diagnosis denominators.
    out.push_str(
        "# HELP taiji_peer_leaves_total Peer connection departures by terminal reason ( connection-retention face; cancelled = engine teardown, excluded from bleed diagnosis).\n\
         # TYPE taiji_peer_leaves_total counter\n",
    );
    for (reason, n) in [
        ("peer-closed", snap.peer_leaves_peer_closed_total),
        ("local", snap.peer_leaves_local_total),
        ("io", snap.peer_leaves_io_total),
        ("protocol", snap.peer_leaves_protocol_total),
        ("cancelled", snap.peer_leaves_cancelled_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_peer_leaves_total",
                labels: &[("reason", reason.to_string())],
                value: n.to_string(),
            },
        );
    }

    // ---- protocol families ----
    out.push_str(
        "# HELP taiji_dht_nodes DHT routing table nodes by address family.\n\
         # TYPE taiji_dht_nodes gauge\n",
    );
    for (family, n) in [("v4", snap.dht_nodes_v4), ("v6", snap.dht_nodes_v6)] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_dht_nodes",
                labels: &[("family", family.to_string())],
                value: n.to_string(),
            },
        );
    }
    // Per-kind outbound DHT queries (the four BEP5 message kinds; feed
    // point = successful outbound enqueue at the engine send_query choke
    // point; engine snapshot fields enter the snapshot as 1s-tick deltas
    // — summed over the v4/v6 engines).
    out.push_str(
        "# HELP taiji_dht_queries_total Outbound DHT queries by BEP5 message kind (feed point = successful transport enqueue at the engine send_query choke point; encode/transport failures not counted).\n\
         # TYPE taiji_dht_queries_total counter\n",
    );
    for (kind, n) in [
        ("ping", snap.dht_queries_ping_total),
        ("find_node", snap.dht_queries_find_node_total),
        ("get_peers", snap.dht_queries_get_peers_total),
        ("announce_peer", snap.dht_queries_announce_peer_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_dht_queries_total",
                labels: &[("kind", kind.to_string())],
                value: n.to_string(),
            },
        );
    }
    // DHT inbound observation family: the passive-seed counting face
    // consumed as 1s-tick deltas, summed over the v4/v6 engines.
    // packets = every datagram at handle_packet entry; queries = admitted
    // to decode; unmatched_drops = y="r"/y="e" frames dropped before the
    // full decode on no pending transaction (the early-drop rate reading:
    // rate(packets - queries) ≈ reply+error load, of which
    // rate(unmatched_drops) never paid a decode). Counters are
    // monotonic; observation only.
    out.push_str(
        "# HELP taiji_dht_inbound_packets_total Inbound DHT datagrams at the engine handle_packet entry (observation only; summed v4+v6 engines, 1s-tick delta feed).\n\
         # TYPE taiji_dht_inbound_packets_total counter\n",
    );
    write_sample(
        &mut out,
        Sample {
            name: "taiji_dht_inbound_packets_total",
            labels: &[],
            value: snap.dht_inbound_packets_total.to_string(),
        },
    );
    out.push_str(
        "# HELP taiji_dht_inbound_queries_total Inbound DHT datagrams admitted to full bencode decode (queries face of the inbound family).\n\
         # TYPE taiji_dht_inbound_queries_total counter\n",
    );
    write_sample(
        &mut out,
        Sample {
            name: "taiji_dht_inbound_queries_total",
            labels: &[],
            value: snap.dht_inbound_queries_total.to_string(),
        },
    );
    out.push_str(
        "# HELP taiji_dht_inbound_unmatched_drops_total Reply/error DHT frames dropped before decode on no pending transaction (the early-drop face; packets - queries - other-drops context).\n\
         # TYPE taiji_dht_inbound_unmatched_drops_total counter\n",
    );
    write_sample(
        &mut out,
        Sample {
            name: "taiji_dht_inbound_unmatched_drops_total",
            labels: &[],
            value: snap.dht_inbound_unmatched_drops_total.to_string(),
        },
    );
    out.push_str(
        "# HELP taiji_tracker_announces_total Tracker announces by attributed result.\n\
         # TYPE taiji_tracker_announces_total counter\n",
    );
    for (result, n) in [
        ("ok", snap.tracker_ok_total),
        ("fail", snap.tracker_fail_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_tracker_announces_total",
                labels: &[("result", result.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_mse_handshakes_total Registered connections by negotiated crypto.\n\
         # TYPE taiji_mse_handshakes_total counter\n",
    );
    for (result, n) in [
        ("arc4", snap.mse_arc4_total),
        ("plain", snap.mse_plain_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_mse_handshakes_total",
                labels: &[("result", result.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_utp_packets_total µTP datagrams by demux outcome.\n\
         # TYPE taiji_utp_packets_total counter\n",
    );
    for (kind, n) in [("recv", snap.utp_recv_total), ("drop", snap.utp_drop_total)] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_utp_packets_total",
                labels: &[("kind", kind.to_string())],
                value: n.to_string(),
            },
        );
    }

    // ---- internal pool families ----
    out.push_str(
        "# HELP taiji_hashpool_queue_depth Store pipeline inbound block channel occupancy (hash/write backlog upper bound).\n\
         # TYPE taiji_hashpool_queue_depth gauge\n",
    );
    out.push_str("taiji_hashpool_queue_depth ");
    out.push_str(&snap.hashpool_queue_depth.to_string());
    out.push('\n');
    // Block-pool face: reuse/fallback counters + watermark/cap gauges
    // (a None pool face renders as an honest zero; cap_bytes is an
    // explicit component of the face unverified-byte budget).
    out.push_str(
        "# HELP taiji_block_arena_lease_hits_total Block-buffer pool reuse hits zero malloc steady state).\n\
         # TYPE taiji_block_arena_lease_hits_total counter\n",
    );
    out.push_str("taiji_block_arena_lease_hits_total ");
    out.push_str(&snap.block_arena_lease_hits_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_block_arena_alloc_fallback_total Direct-alloc fallbacks (over budget or oversize frame; exempt path of per-block zero-malloc).\n\
         # TYPE taiji_block_arena_alloc_fallback_total counter\n",
    );
    out.push_str("taiji_block_arena_alloc_fallback_total ");
    out.push_str(&snap.block_arena_alloc_fallback_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_block_arena_outstanding_blocks Leased-out (in-use) pool blocks watermark.\n\
         # TYPE taiji_block_arena_outstanding_blocks gauge\n",
    );
    out.push_str("taiji_block_arena_outstanding_blocks ");
    out.push_str(&snap.block_arena_outstanding_blocks.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_block_arena_cap_bytes Pool byte cap (explicit component of face unverified-byte budget).\n\
         # TYPE taiji_block_arena_cap_bytes gauge\n",
    );
    out.push_str("taiji_block_arena_cap_bytes ");
    out.push_str(&snap.block_arena_cap_bytes.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_hashpool_blocks_verified_total 16KiB blocks passed verification.\n\
         # TYPE taiji_hashpool_blocks_verified_total counter\n",
    );
    out.push_str("taiji_hashpool_blocks_verified_total ");
    out.push_str(&snap.blocks_verified_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_wrcache_events_total Write-cache lifecycle events (flush = piece written; evict = unverified piece dropped).\n\
         # TYPE taiji_wrcache_events_total counter\n",
    );
    for (kind, n) in [
        ("flush", snap.wrcache_flush_total),
        ("evict", snap.wrcache_evict_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_wrcache_events_total",
                labels: &[("kind", kind.to_string())],
                value: n.to_string(),
            },
        );
    }
    // Instrumentation: cumulative bytes destroyed by eviction (fed at
    // the same point as the evict count — the recycle amplification
    // ratio = this counter / total payload).
    out.push_str(
        "# HELP taiji_wrcache_evict_bytes_total Unverified bytes destroyed by write-cache eviction (compare against payload total for the recycle amplification ratio).\n\
         # TYPE taiji_wrcache_evict_bytes_total counter\n",
    );
    out.push_str("taiji_wrcache_evict_bytes_total ");
    out.push_str(&snap.wrcache_evict_bytes_total.to_string());
    out.push('\n');
    // Unverified spill trio (increments only when spill is enabled —
    // `BH_SPILL_UNVERIFIED` defaults off, so the rows are always 0 by
    // default). Read-back hit rate = readback_pieces /
    // (readback_pieces + wrcache_evict_total).
    out.push_str(
        "# HELP taiji_spill_write_bytes_total Unverified bytes spilled to the sidecar instead of being destroyed on write-cache eviction.\n\
         # TYPE taiji_spill_write_bytes_total counter\n",
    );
    out.push_str("taiji_spill_write_bytes_total ");
    out.push_str(&snap.spill_write_bytes_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_spill_read_bytes_total Spill sidecar bytes read back at piece assembly.\n\
         # TYPE taiji_spill_read_bytes_total counter\n",
    );
    out.push_str("taiji_spill_read_bytes_total ");
    out.push_str(&snap.spill_read_bytes_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_spill_readback_pieces_total Pieces whose spilled cells were read back for verification (hit-rate numerator; denominator adds wrcache evictions).\n\
         # TYPE taiji_spill_readback_pieces_total counter\n",
    );
    out.push_str("taiji_spill_readback_pieces_total ");
    out.push_str(&snap.spill_readback_pieces_total.to_string());
    out.push('\n');
    // Bytes destroyed on budget-overflow fallback (the destroy ledger of
    // the FIFO-displacement and refused-absorption arms — the
    // budget-attributable share of evictions; always 0 with spill off).
    out.push_str(
        "# HELP taiji_spill_fallback_destroy_bytes_total Unverified bytes destroyed because the spill budget could not absorb them (FIFO displacement or absorption refusal; the budget-attributable share of wrcache evictions).\n\
         # TYPE taiji_spill_fallback_destroy_bytes_total counter\n",
    );
    out.push_str("taiji_spill_fallback_destroy_bytes_total ");
    out.push_str(&snap.spill_fallback_destroy_bytes_total.to_string());
    out.push('\n');
    // Instrumentation: block/piece stage-duration histograms at three
    // cut points (buffer per 16KiB block, verify/write per completed
    // piece; stage label = a fixed three-value enum). HELP/TYPE emitted
    // once (Prometheus forbids duplicate metadata); the other stages
    // emit sample lines only.
    out.push_str(
        "# HELP taiji_block_stage_seconds Store-pipeline stage duration (buffer = per-16KiB-block intake incl. per-block hash and cache write; verify = whole-piece hash; write = disk write syscalls).\n\
         # TYPE taiji_block_stage_seconds histogram\n",
    );
    for (stage, buckets, count, sum_us) in [
        (
            "buffer",
            &snap.block_buffer_seconds_buckets,
            snap.block_buffer_seconds_count,
            snap.block_buffer_seconds_sum_us,
        ),
        (
            "verify",
            &snap.block_verify_seconds_buckets,
            snap.block_verify_seconds_count,
            snap.block_verify_seconds_sum_us,
        ),
        (
            "write",
            &snap.block_write_seconds_buckets,
            snap.block_write_seconds_count,
            snap.block_write_seconds_sum_us,
        ),
    ] {
        let mut cumulative = 0u64;
        for (i, bound) in BLOCK_STAGE_BUCKETS_SECONDS.iter().enumerate() {
            cumulative += buckets.get(i).copied().unwrap_or(0);
            write_sample(
                &mut out,
                Sample {
                    name: "taiji_block_stage_seconds_bucket",
                    labels: &[("stage", stage.to_string()), ("le", fmt_float(*bound))],
                    value: cumulative.to_string(),
                },
            );
        }
        write_sample(
            &mut out,
            Sample {
                name: "taiji_block_stage_seconds_bucket",
                labels: &[("stage", stage.to_string()), ("le", "+Inf".to_string())],
                value: count.to_string(),
            },
        );
        out.push_str("taiji_block_stage_seconds_sum{stage=\"");
        out.push_str(stage);
        out.push_str("\"} ");
        out.push_str(&fmt_float(sum_us as f64 / 1_000_000.0));
        out.push('\n');
        out.push_str("taiji_block_stage_seconds_count{stage=\"");
        out.push_str(stage);
        out.push_str("\"} ");
        out.push_str(&count.to_string());
        out.push('\n');
    }

    // ---- HTTP scheduling families ----
    // `conn_aimd{task}` renders as an aggregate gauge (cardinality
    // discipline — gid never becomes a label; the per-task face goes
    // through the tellStatus `http` sub-dict). The static baseline
    // task's AIMD/steal readings are always zero (not assembled;
    // honest zero).
    out.push_str(
        "# HELP taiji_http_extents_active In-flight HTTP extents across active tasks.\n\
         # TYPE taiji_http_extents_active gauge\n",
    );
    out.push_str("taiji_http_extents_active ");
    out.push_str(&snap.http_extents_active.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_http_conn_aimd AIMD connection budget summed over HTTP task sources (per-task face via tellStatus http sub-dict).\n\
         # TYPE taiji_http_conn_aimd gauge\n",
    );
    out.push_str("taiji_http_conn_aimd ");
    out.push_str(&snap.http_conn_aimd.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_http_stolen_total Stall-steal grants at the single adjudication point (cumulative).\n\
         # TYPE taiji_http_stolen_total counter\n",
    );
    out.push_str("taiji_http_stolen_total ");
    out.push_str(&snap.http_stolen_total.to_string());
    out.push('\n');

    // ---- DNS resolution family (the io shared resolver layer via the
    // core snapshot aggregation seam; all labels fixed enums). hit/miss
    // count cache behavior, error/timeout count resolution outcomes — a
    // failed miss counts twice (one miss + one error|timeout);
    // accounting in the taiji-io dns module doc.
    out.push_str(
        "# HELP taiji_dns_lookups_total Shared-DNS lookups: hit/miss count cache behavior, error/timeout count resolution outcomes (a failed miss counts both miss and its outcome).\n\
         # TYPE taiji_dns_lookups_total counter\n",
    );
    for (result, n) in [
        ("hit", snap.dns_lookups_hit_total),
        ("miss", snap.dns_lookups_miss_total),
        ("error", snap.dns_lookups_error_total),
        ("timeout", snap.dns_lookups_timeout_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_dns_lookups_total",
                labels: &[("result", result.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_dns_resolve_seconds Host resolution duration at the shared resolver exit (cache hits contribute near-zero samples; upper bound covers the resolver timeout).\n\
         # TYPE taiji_dns_resolve_seconds histogram\n",
    );
    let mut dns_cumulative = 0u64;
    for (i, bound) in DNS_RESOLVE_BUCKETS_SECONDS.iter().enumerate() {
        dns_cumulative += snap
            .dns_resolve_seconds_buckets
            .get(i)
            .copied()
            .unwrap_or(0);
        write_sample(
            &mut out,
            Sample {
                name: "taiji_dns_resolve_seconds_bucket",
                labels: &[("le", fmt_float(*bound))],
                value: dns_cumulative.to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_dns_resolve_seconds_bucket",
            labels: &[("le", "+Inf".to_string())],
            value: snap.dns_resolve_seconds_count.to_string(),
        },
    );
    out.push_str("taiji_dns_resolve_seconds_sum ");
    out.push_str(&fmt_float(
        snap.dns_resolve_seconds_sum_us as f64 / 1_000_000.0,
    ));
    out.push('\n');
    out.push_str("taiji_dns_resolve_seconds_count ");
    out.push_str(&snap.dns_resolve_seconds_count.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_dns_family_mix_total Resolved address lists by family composition (per resolver-produced list; cache hits not re-counted).\n\
         # TYPE taiji_dns_family_mix_total counter\n",
    );
    for (mix, n) in [
        ("v4_only", snap.dns_family_mix_v4_only_total),
        ("v6_only", snap.dns_family_mix_v6_only_total),
        ("dual", snap.dns_family_mix_dual_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_dns_family_mix_total",
                labels: &[("mix", mix.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_dns_events_total Host-cache evictions by kind (ttl = expiry on read, capacity = oldest-entry displacement on insert).\n\
         # TYPE taiji_dns_events_total counter\n",
    );
    for (kind, n) in [
        ("evict_ttl", snap.dns_events_evict_ttl_total),
        ("evict_capacity", snap.dns_events_evict_capacity_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_dns_events_total",
                labels: &[("kind", kind.to_string())],
                value: n.to_string(),
            },
        );
    }

    // ---- HTTP transport families (the io shared layer via the core
    // snapshot aggregation seam; all labels fixed enums). errors counts
    // per failed request (retries/source switches amplify it — a retry
    // decision counts in retries, a status-code failure in
    // http_4xx/5xx; class=dns rows carry a persistence label:
    // permanent = NXDOMAIN-like resolution dead-end, transient =
    // timeout/EAI_AGAIN-like recoverable).
    out.push_str(
        "# HELP taiji_http_errors_total Failed HTTP requests by transport error class (dns rows carry persistence: permanent = NXDOMAIN-like resolution dead-end, transient = timeout/EAI_AGAIN-like recoverable).\n\
         # TYPE taiji_http_errors_total counter\n",
    );
    for (class, persistence, n) in [
        (
            "dns",
            Some("permanent"),
            snap.http_errors_dns_permanent_total,
        ),
        (
            "dns",
            Some("transient"),
            snap.http_errors_dns_transient_total,
        ),
        ("timeout", None, snap.http_errors_timeout_total),
        ("tls", None, snap.http_errors_tls_total),
        ("connect", None, snap.http_errors_connect_total),
        ("refused", None, snap.http_errors_refused_total),
        ("reset", None, snap.http_errors_reset_total),
        ("http_4xx", None, snap.http_errors_http_4xx_total),
        ("http_5xx", None, snap.http_errors_http_5xx_total),
    ] {
        let labels: &[(&str, String)] = match persistence {
            Some(p) => &[("class", class.to_string()), ("persistence", p.to_string())],
            None => &[("class", class.to_string())],
        };
        write_sample(
            &mut out,
            Sample {
                name: "taiji_http_errors_total",
                labels,
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_http_request_seconds HTTP request duration by phase (first_byte = request issued to terminal response arrival; total = request issued to body fully read, extent-scale).\n\
         # TYPE taiji_http_request_seconds histogram\n",
    );
    for (phase, buckets, count, sum_us) in [
        (
            "first_byte",
            &snap.http_request_first_byte_buckets,
            snap.http_request_first_byte_count,
            snap.http_request_first_byte_sum_us,
        ),
        (
            "total",
            &snap.http_request_total_buckets,
            snap.http_request_total_count,
            snap.http_request_total_sum_us,
        ),
    ] {
        let mut cumulative = 0u64;
        for (i, bound) in HTTP_REQUEST_BUCKETS_SECONDS.iter().enumerate() {
            cumulative += buckets.get(i).copied().unwrap_or(0);
            write_sample(
                &mut out,
                Sample {
                    name: "taiji_http_request_seconds_bucket",
                    labels: &[("phase", phase.to_string()), ("le", fmt_float(*bound))],
                    value: cumulative.to_string(),
                },
            );
        }
        write_sample(
            &mut out,
            Sample {
                name: "taiji_http_request_seconds_bucket",
                labels: &[("phase", phase.to_string()), ("le", "+Inf".to_string())],
                value: count.to_string(),
            },
        );
        out.push_str("taiji_http_request_seconds_sum{phase=\"");
        out.push_str(phase);
        out.push_str("\"} ");
        out.push_str(&fmt_float(sum_us as f64 / 1_000_000.0));
        out.push('\n');
        out.push_str("taiji_http_request_seconds_count{phase=\"");
        out.push_str(phase);
        out.push_str("\"} ");
        out.push_str(&count.to_string());
        out.push('\n');
    }
    out.push_str(
        "# HELP taiji_http_retries_total HTTP retry decisions at the shared retry helper (per-decision; retries amplify per-request counts).\n\
         # TYPE taiji_http_retries_total counter\n",
    );
    out.push_str("taiji_http_retries_total ");
    out.push_str(&snap.http_retries_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_http_extent_reassign_total Extent reassignments by current-writer abandon at the single adjudication point (non-steal only; steals are counted in taiji_http_stolen_total).\n\
         # TYPE taiji_http_extent_reassign_total counter\n",
    );
    out.push_str("taiji_http_extent_reassign_total ");
    out.push_str(&snap.http_extent_reassign_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_http_mirror_events_total Source health transitions (demote/remove on windowed extent failures, restore when a demoted source recovers; removal is terminal).\n\
         # TYPE taiji_http_mirror_events_total counter\n",
    );
    for (kind, n) in [
        ("demote", snap.http_mirror_demote_total),
        ("remove", snap.http_mirror_remove_total),
        ("restore", snap.http_mirror_restore_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_http_mirror_events_total",
                labels: &[("kind", kind.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_http_stall_detected_total Stall detections confirmed at the steal-adjudication evidence gate (byte-level zero growth over the full window; limiter waits excluded).\n\
         # TYPE taiji_http_stall_detected_total counter\n",
    );
    out.push_str("taiji_http_stall_detected_total ");
    out.push_str(&snap.http_stall_detected_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_http_aimd_events_total AIMD window decisions by direction (grow = multiplicative-increase probe confirmed, shrink = congestion multiplicative-decrease; holds not counted).\n\
         # TYPE taiji_http_aimd_events_total counter\n",
    );
    for (dir, n) in [
        ("grow", snap.http_aimd_grow_total),
        ("shrink", snap.http_aimd_shrink_total),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_http_aimd_events_total",
                labels: &[("dir", dir.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_http_slowstart_seconds Slow-start phase duration (task activation until connections reach cap or any source AIMD first settles; tasks that never settle are not sampled — right-censored).\n\
         # TYPE taiji_http_slowstart_seconds histogram\n",
    );
    let mut slowstart_cumulative = 0u64;
    for (i, bound) in HTTP_SLOWSTART_BUCKETS_SECONDS.iter().enumerate() {
        slowstart_cumulative += snap
            .http_slowstart_seconds_buckets
            .get(i)
            .copied()
            .unwrap_or(0);
        write_sample(
            &mut out,
            Sample {
                name: "taiji_http_slowstart_seconds_bucket",
                labels: &[("le", fmt_float(*bound))],
                value: slowstart_cumulative.to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_http_slowstart_seconds_bucket",
            labels: &[("le", "+Inf".to_string())],
            value: snap.http_slowstart_seconds_count.to_string(),
        },
    );
    out.push_str("taiji_http_slowstart_seconds_sum ");
    out.push_str(&fmt_float(
        snap.http_slowstart_seconds_sum_us as f64 / 1_000_000.0,
    ));
    out.push('\n');
    out.push_str("taiji_http_slowstart_seconds_count ");
    out.push_str(&snap.http_slowstart_seconds_count.to_string());
    out.push('\n');

    // ---- connection profile family (feed point = the tower timing
    // layer hooked into the reqwest connector_layer; pool reuse bypasses
    // the connector, so the count naturally covers only fresh
    // establishments). establish_seconds = combined DNS+TCP+TLS timing;
    // a connect+TLS phase split is unavailable — analysis subtracts
    // dns_resolve_seconds from the combined latency (mean-level, no
    // per-sample pairing). Failed attempts are not counted here (they
    // are classified via the errors{class} seam) — the counter and the
    // histogram count are always equal.
    out.push_str(
        "# HELP taiji_http_conn_establishments_total New connections established at the connector stack (pool hits bypass the connector, so this counts only fresh establishments; failed attempts feed the errors family instead).\n\
         # TYPE taiji_http_conn_establishments_total counter\n",
    );
    out.push_str("taiji_http_conn_establishments_total ");
    out.push_str(&snap.http_conn_establishments_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_http_conn_establish_seconds Fresh-connection establishment duration (DNS+TCP+TLS combined; connect+TLS approximated by subtracting dns_resolve_seconds at analysis time — mean-level, no per-sample pairing; buckets straddle the 300ms happy-eyeballs interleave).\n\
         # TYPE taiji_http_conn_establish_seconds histogram\n",
    );
    let mut establish_cumulative = 0u64;
    for (i, bound) in HTTP_CONN_ESTABLISH_BUCKETS_SECONDS.iter().enumerate() {
        establish_cumulative += snap
            .http_conn_establish_seconds_buckets
            .get(i)
            .copied()
            .unwrap_or(0);
        write_sample(
            &mut out,
            Sample {
                name: "taiji_http_conn_establish_seconds_bucket",
                labels: &[("le", fmt_float(*bound))],
                value: establish_cumulative.to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_http_conn_establish_seconds_bucket",
            labels: &[("le", "+Inf".to_string())],
            value: snap.http_conn_establish_seconds_count.to_string(),
        },
    );
    out.push_str("taiji_http_conn_establish_seconds_sum ");
    out.push_str(&fmt_float(
        snap.http_conn_establish_seconds_sum_us as f64 / 1_000_000.0,
    ));
    out.push('\n');
    out.push_str("taiji_http_conn_establish_seconds_count ");
    out.push_str(&snap.http_conn_establish_seconds_count.to_string());
    out.push('\n');

    // ---- disk/finalize family (the io shared layer via the core
    // snapshot aggregation seam; all labels fixed enums). sink_inflight
    // = in-flight write_at concurrency (not queue depth);
    // finalize_seconds{op=file_fsync} counts fsync for all task files
    // (merged accounting, including the 2s snapshot beat);
    // fsync_dir/rename are finalize-teardown-only.
    out.push_str(
        "# HELP taiji_disk_sink_writes_total Positioned disk writes at the HTTP grid sink write path (prefetch-rejected duplicates excluded — they never touch disk).\n\
         # TYPE taiji_disk_sink_writes_total counter\n",
    );
    out.push_str("taiji_disk_sink_writes_total ");
    out.push_str(&snap.disk_sink_writes_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_disk_sink_writes_bytes_total Payload bytes submitted to positioned disk writes at the HTTP grid sink write path.\n\
         # TYPE taiji_disk_sink_writes_bytes_total counter\n",
    );
    out.push_str("taiji_disk_sink_writes_bytes_total ");
    out.push_str(&snap.disk_sink_writes_bytes_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_disk_sink_inflight In-flight write_at concurrency at the disk sink (enter/exit paired; production write path is direct positioned IO — no queue depth exists to report).\n\
         # TYPE taiji_disk_sink_inflight gauge\n",
    );
    out.push_str("taiji_disk_sink_inflight ");
    out.push_str(&snap.disk_sink_inflight.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_disk_finalize_seconds Finalize/durability operation duration by op (file_fsync = per-task-file fsync — merged accounting includes periodic snapshot beats, not finalize-only; fsync_dir = directory flush after rename; rename = atomic rename; SMB long-tail domain).\n\
         # TYPE taiji_disk_finalize_seconds histogram\n",
    );
    for (op, buckets, count, sum_us) in [
        (
            "file_fsync",
            &snap.disk_finalize_file_fsync_buckets,
            snap.disk_finalize_file_fsync_count,
            snap.disk_finalize_file_fsync_sum_us,
        ),
        (
            "fsync_dir",
            &snap.disk_finalize_fsync_dir_buckets,
            snap.disk_finalize_fsync_dir_count,
            snap.disk_finalize_fsync_dir_sum_us,
        ),
        (
            "rename",
            &snap.disk_finalize_rename_buckets,
            snap.disk_finalize_rename_count,
            snap.disk_finalize_rename_sum_us,
        ),
    ] {
        let mut cumulative = 0u64;
        for (i, bound) in DISK_FINALIZE_BUCKETS_SECONDS.iter().enumerate() {
            cumulative += buckets.get(i).copied().unwrap_or(0);
            write_sample(
                &mut out,
                Sample {
                    name: "taiji_disk_finalize_seconds_bucket",
                    labels: &[("op", op.to_string()), ("le", fmt_float(*bound))],
                    value: cumulative.to_string(),
                },
            );
        }
        write_sample(
            &mut out,
            Sample {
                name: "taiji_disk_finalize_seconds_bucket",
                labels: &[("op", op.to_string()), ("le", "+Inf".to_string())],
                value: count.to_string(),
            },
        );
        out.push_str("taiji_disk_finalize_seconds_sum{op=\"");
        out.push_str(op);
        out.push_str("\"} ");
        out.push_str(&fmt_float(sum_us as f64 / 1_000_000.0));
        out.push('\n');
        out.push_str("taiji_disk_finalize_seconds_count{op=\"");
        out.push_str(op);
        out.push_str("\"} ");
        out.push_str(&count.to_string());
        out.push('\n');
    }
    out.push_str(
        "# HELP taiji_disk_prealloc_seconds Preallocation set_len duration at task-file open (truncate-growth and explicit prealloc landings; same long-tail buckets as finalize).\n\
         # TYPE taiji_disk_prealloc_seconds histogram\n",
    );
    let mut prealloc_cumulative = 0u64;
    for (i, bound) in DISK_FINALIZE_BUCKETS_SECONDS.iter().enumerate() {
        prealloc_cumulative += snap
            .disk_prealloc_seconds_buckets
            .get(i)
            .copied()
            .unwrap_or(0);
        write_sample(
            &mut out,
            Sample {
                name: "taiji_disk_prealloc_seconds_bucket",
                labels: &[("le", fmt_float(*bound))],
                value: prealloc_cumulative.to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_disk_prealloc_seconds_bucket",
            labels: &[("le", "+Inf".to_string())],
            value: snap.disk_prealloc_seconds_count.to_string(),
        },
    );
    out.push_str("taiji_disk_prealloc_seconds_sum ");
    out.push_str(&fmt_float(
        snap.disk_prealloc_seconds_sum_us as f64 / 1_000_000.0,
    ));
    out.push('\n');
    out.push_str("taiji_disk_prealloc_seconds_count ");
    out.push_str(&snap.disk_prealloc_seconds_count.to_string());
    out.push('\n');

    // ---- persistence family (the store PersistWriter thread via the
    // PersistObserve callback seam -> the io registry persistence family
    // via the core snapshot aggregation seam; store and io do not depend
    // on each other, core is the single adapter point). queue_depth =
    // the latest writer-thread observation (gauge SET semantics, can be
    // stale at low traffic); commit_seconds = per-job execution inside
    // the writer thread (channel queuing excluded).
    out.push_str(
        "# HELP taiji_persist_queue_depth PersistWriter job channel backlog as sampled by the writer thread after its most recent commit (gauge = last observation, may be stale at low traffic).\n\
         # TYPE taiji_persist_queue_depth gauge\n",
    );
    out.push_str("taiji_persist_queue_depth ");
    out.push_str(&snap.persist_queue_depth.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_persist_commit_seconds Per-job execution duration inside the persist writer thread (channel queuing excluded — see taiji_persist_queue_depth).\n\
         # TYPE taiji_persist_commit_seconds histogram\n",
    );
    let mut persist_cumulative = 0u64;
    for (i, bound) in PERSIST_COMMIT_BUCKETS_SECONDS.iter().enumerate() {
        persist_cumulative += snap
            .persist_commit_seconds_buckets
            .get(i)
            .copied()
            .unwrap_or(0);
        write_sample(
            &mut out,
            Sample {
                name: "taiji_persist_commit_seconds_bucket",
                labels: &[("le", fmt_float(*bound))],
                value: persist_cumulative.to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_persist_commit_seconds_bucket",
            labels: &[("le", "+Inf".to_string())],
            value: snap.persist_commit_seconds_count.to_string(),
        },
    );
    out.push_str("taiji_persist_commit_seconds_sum ");
    out.push_str(&fmt_float(
        snap.persist_commit_seconds_sum_us as f64 / 1_000_000.0,
    ));
    out.push('\n');
    out.push_str("taiji_persist_commit_seconds_count ");
    out.push_str(&snap.persist_commit_seconds_count.to_string());
    out.push('\n');

    // ---- rpc families (internal-pool rows) ----
    out.push_str(
        "# HELP taiji_rpc_requests_total JSON-RPC calls by frozen method name (unknown methods merged to one slot).\n\
         # TYPE taiji_rpc_requests_total counter\n",
    );
    for (i, method) in RPC_METHODS.iter().enumerate() {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_rpc_requests_total",
                labels: &[("method", (*method).to_string())],
                value: snap.rpc_requests.get(i).copied().unwrap_or(0).to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_rpc_requests_total",
            labels: &[("method", "unknown".to_string())],
            value: snap
                .rpc_requests
                .get(RPC_METHOD_SLOT_UNKNOWN)
                .copied()
                .unwrap_or(0)
                .to_string(),
        },
    );
    out.push_str(
        "# HELP taiji_rpc_request_duration_seconds JSON-RPC call latency (dispatch entry; gate for RPC p99).\n\
         # TYPE taiji_rpc_request_duration_seconds histogram\n",
    );
    let mut cumulative = 0u64;
    for (i, bound) in RPC_DURATION_BUCKETS_SECONDS.iter().enumerate() {
        cumulative += snap.rpc_duration_buckets.get(i).copied().unwrap_or(0);
        write_sample(
            &mut out,
            Sample {
                name: "taiji_rpc_request_duration_seconds_bucket",
                labels: &[("le", fmt_float(*bound))],
                value: cumulative.to_string(),
            },
        );
    }
    write_sample(
        &mut out,
        Sample {
            name: "taiji_rpc_request_duration_seconds_bucket",
            labels: &[("le", "+Inf".to_string())],
            value: snap.rpc_duration_count.to_string(),
        },
    );
    out.push_str("taiji_rpc_request_duration_seconds_sum ");
    out.push_str(&fmt_float(snap.rpc_duration_sum_us as f64 / 1_000_000.0));
    out.push('\n');
    out.push_str("taiji_rpc_request_duration_seconds_count ");
    out.push_str(&snap.rpc_duration_count.to_string());
    out.push('\n');

    // ---- rpc guard families (surface hardening: connection gate / auth backoff) ----
    out.push_str(
        "# HELP taiji_rpc_conn_rejected_total Connections rejected at the RPC concurrency cap by scope (total|per_ip).\n\
         # TYPE taiji_rpc_conn_rejected_total counter\n",
    );
    for (scope, n) in [
        ("total", snap.rpc_conn_rejected_total_scope_total),
        ("per_ip", snap.rpc_conn_rejected_total_scope_per_ip),
    ] {
        write_sample(
            &mut out,
            Sample {
                name: "taiji_rpc_conn_rejected_total",
                labels: &[("scope", scope.to_string())],
                value: n.to_string(),
            },
        );
    }
    out.push_str(
        "# HELP taiji_rpc_auth_fail_total Auth failures at the token/basic gates (credentials never in metrics).\n\
         # TYPE taiji_rpc_auth_fail_total counter\n",
    );
    out.push_str("taiji_rpc_auth_fail_total ");
    out.push_str(&snap.rpc_auth_fail_total.to_string());
    out.push('\n');
    out.push_str(
        "# HELP taiji_rpc_auth_backoff_active Source IPs currently inside an auth backoff window.\n\
         # TYPE taiji_rpc_auth_backoff_active gauge\n",
    );
    out.push_str("taiji_rpc_auth_backoff_active ");
    out.push_str(&auth_backoff_active.to_string());
    out.push('\n');

    out
}

// ---- Prometheus text 0.0.4 parse validation (test face) ----

/// Strict Prometheus text format validation: comment/TYPE/HELP
/// structure, sample-line syntax, label shape, parsable values, families
/// declared before sampled, no duplicate time series. Returns a
/// description of the first violation.
#[cfg(test)]
fn validate_prom_text(text: &str) -> Result<(), String> {
    fn valid_name(n: &str) -> bool {
        let mut chars = n.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':')
            && n.chars()
                .skip(1)
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    }
    fn valid_value(v: &str) -> bool {
        matches!(v, "+Inf" | "-Inf" | "NaN") || v.parse::<f64>().is_ok()
    }
    fn parse_labels(s: &str) -> Result<Vec<(String, String)>, String> {
        let mut labels = Vec::new();
        if s.is_empty() {
            return Ok(labels);
        }
        for part in s.split(',') {
            let Some((k, v)) = part.split_once('=') else {
                return Err(format!("label without '=': {part:?}"));
            };
            if !valid_name(k) {
                return Err(format!("invalid label name: {k:?}"));
            }
            let Some(v) = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
                return Err(format!("label value not quoted: {part:?}"));
            };
            // Escape validation: backslash sequences outside \" \\ \n are invalid.
            let mut chars = v.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some('\\' | '"' | 'n') => {}
                        other => return Err(format!("bad escape: \\{other:?}")),
                    }
                }
            }
            labels.push((k.to_string(), v.to_string()));
        }
        Ok(labels)
    }

    let mut declared_type: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    let mut declared_help: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut seen_series: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut sampled: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (lineno, line) in text.lines().enumerate() {
        let fail = |msg: String| -> String { format!("line {}: {msg}", lineno + 1) };
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            if let Some(rest) = rest.strip_prefix("HELP ") {
                let name = rest
                    .split_whitespace()
                    .next()
                    .ok_or_else(|| fail("empty HELP".into()))?;
                if !valid_name(name) {
                    return Err(fail(format!("bad HELP metric name {name:?}")));
                }
                if !declared_help.insert(name) {
                    return Err(fail(format!("duplicate HELP for {name:?}")));
                }
            } else if let Some(rest) = rest.strip_prefix("TYPE ") {
                let mut it = rest.split_whitespace();
                let name = it.next().ok_or_else(|| fail("empty TYPE".into()))?;
                let ty = it.next().ok_or_else(|| fail("TYPE without type".into()))?;
                if it.next().is_some() {
                    return Err(fail("trailing tokens after TYPE".into()));
                }
                if !matches!(
                    ty,
                    "counter" | "gauge" | "histogram" | "summary" | "untyped"
                ) {
                    return Err(fail(format!("unknown TYPE {ty:?}")));
                }
                if declared_type.insert(name, ty).is_some() {
                    return Err(fail(format!("duplicate TYPE for {name:?}")));
                }
            } else {
                return Err(fail(format!("unknown comment form: {line:?}")));
            }
            continue;
        }
        // Sample line: name{labels} value [timestamp], or name value.
        let (name, label_src, value_src) = match line.find('{') {
            Some(i) => {
                let rest = &line[i + 1..];
                let close = rest
                    .rfind('}')
                    .ok_or_else(|| fail("unbalanced braces".into()))?;
                let value_src = rest[close + 1..].trim();
                if value_src.is_empty() {
                    return Err(fail("sample without value".into()));
                }
                (line[..i].trim(), &rest[..close], value_src)
            }
            None => {
                let mut it = line.split_whitespace();
                let name = it.next().ok_or_else(|| fail("empty sample line".into()))?;
                let value = it
                    .next()
                    .ok_or_else(|| fail("sample without value".into()))?;
                (name, "", value)
            }
        };
        if !valid_name(name) {
            return Err(fail(format!("bad metric name {name:?}")));
        }
        let labels = parse_labels(label_src).map_err(fail)?;
        let mut it = value_src.split_whitespace();
        let value = it
            .next()
            .ok_or_else(|| fail("sample without value".into()))?;
        if it.next().is_some() {
            return Err(fail("timestamp not supported".into()));
        }
        if !valid_value(value) {
            return Err(fail(format!("unparsable value {value:?}")));
        }
        // Family attribution: the exact name or one of the three
        // histogram suffixes; must be TYPE-declared first.
        let family = declared_type
            .keys()
            .copied()
            .find(|f| {
                *f == name
                    || (name.starts_with(f)
                        && matches!(&name[f.len()..], "_bucket" | "_sum" | "_count"))
            })
            .ok_or_else(|| fail(format!("sample {name:?} before any TYPE declaration")))?;
        let ty = declared_type[family];
        if matches!(ty, "gauge" | "counter" | "untyped") && name != family {
            return Err(fail(format!("{ty} family {family:?} sampled as {name:?}")));
        }
        if ty == "histogram" && name == family {
            return Err(fail(
                "histogram family must expose suffixed series only".into(),
            ));
        }
        let series_key = format!("{name}{{{:?}}}", {
            let mut ls: Vec<(String, String)> = labels.clone();
            ls.sort();
            ls
        });
        if !seen_series.insert(series_key) {
            return Err(fail(format!("duplicate time series for {name:?}")));
        }
        sampled.insert(family.to_string());
    }
    for f in declared_type.keys() {
        if !sampled.contains(*f) {
            return Err(format!("family {f:?} declared but never sampled"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_states() -> TorrentStateCounts {
        TorrentStateCounts {
            active: 2,
            waiting: 3,
            paused: 1,
            complete: 7,
            error: 4,
            removed: 5,
        }
    }

    /// Table-driven: one representative sample asserted per family.
    #[test]
    fn render_emits_representative_series_per_family() {
        let mut snap = MetricsSnapshot {
            uptime_seconds: 61,
            ..MetricsSnapshot::default()
        };
        snap.panic_total = 1;
        snap.torrent_completed_total = 7;
        snap.bytes_down_total = 1024;
        snap.bytes_up_total = 512;
        // Supply-byte pair projection (the two families sum to the down total).
        snap.bytes_down_tcp_total = 768;
        snap.bytes_down_utp_total = 256;
        snap.conn_tcp_in = 3;
        snap.conn_tcp_out = 9;
        snap.conn_choked = 6;
        snap.peer_bans_total = 2;
        snap.dht_nodes_v4 = 120;
        snap.dht_nodes_v6 = 8;
        snap.dht_queries_ping_total = 21;
        snap.dht_queries_find_node_total = 4;
        snap.dht_queries_get_peers_total = 9;
        snap.dht_queries_announce_peer_total = 3;
        snap.dht_inbound_packets_total = 40;
        snap.dht_inbound_queries_total = 12;
        snap.dht_inbound_unmatched_drops_total = 25;
        snap.tracker_ok_total = 11;
        snap.tracker_fail_total = 3;
        snap.mse_arc4_total = 5;
        snap.mse_plain_total = 7;
        snap.utp_recv_total = 13;
        snap.utp_drop_total = 1;
        snap.hashpool_queue_depth = 17;
        snap.blocks_verified_total = 29;
        snap.wrcache_flush_total = 12;
        snap.wrcache_evict_total = 4;
        snap.http_extents_active = 4;
        snap.http_conn_aimd = 12;
        snap.http_stolen_total = 2;
        let version_idx = RPC_METHODS
            .iter()
            .position(|m| *m == "getVersion")
            .unwrap_or(RPC_METHOD_SLOT_UNKNOWN);
        snap.rpc_requests[version_idx] = 3;
        snap.rpc_requests[RPC_METHOD_SLOT_UNKNOWN] = 1;
        snap.rpc_duration_buckets[0] = 2;
        snap.rpc_duration_count = 4;
        snap.rpc_duration_sum_us = 6_000_000;
        snap.rpc_conn_rejected_total_scope_total = 3;
        snap.rpc_conn_rejected_total_scope_per_ip = 1;
        snap.rpc_auth_fail_total = 2;
        // The five peer-leave reasons (explicit rows in the render family).
        snap.peer_leaves_local_total = 3;
        snap.peer_leaves_peer_closed_total = 11;
        snap.peer_leaves_io_total = 5;
        snap.peer_leaves_protocol_total = 2;
        snap.peer_leaves_cancelled_total = 1;

        let out = render(&snap, &full_states(), "taiji/9.9.9", 1);
        let expect: &[&str] = &[
            "taiji_build_info{version=\"taiji/9.9.9\"} 1",
            "taiji_session_uptime_seconds 61",
            "taiji_panic_total 1",
            "taiji_torrents{state=\"active\"} 2",
            "taiji_torrents{state=\"waiting\"} 3",
            "taiji_torrents{state=\"paused\"} 1",
            "taiji_torrents{state=\"complete\"} 7",
            "taiji_torrents{state=\"error\"} 4",
            "taiji_torrents{state=\"removed\"} 5",
            "taiji_torrent_bytes_total{direction=\"down\"} 1024",
            "taiji_torrent_bytes_total{direction=\"up\"} 512",
            "taiji_peer_supply_bytes_total{transport=\"tcp\"} 768",
            "taiji_peer_supply_bytes_total{transport=\"utp\"} 256",
            "taiji_peer_leaves_total{reason=\"peer-closed\"} 11",
            "taiji_peer_leaves_total{reason=\"local\"} 3",
            "taiji_peer_leaves_total{reason=\"io\"} 5",
            "taiji_peer_leaves_total{reason=\"protocol\"} 2",
            "taiji_peer_leaves_total{reason=\"cancelled\"} 1",
            "taiji_torrent_completed_total 7",
            "taiji_peer_connections{transport=\"tcp\",direction=\"in\"} 3",
            "taiji_peer_connections{transport=\"tcp\",direction=\"out\"} 9",
            "taiji_peer_connections{transport=\"utp\",direction=\"in\"} 0",
            "taiji_peer_connections{transport=\"utp\",direction=\"out\"} 0",
            "taiji_peer_connections_choked 6",
            "taiji_peer_bans_total 2",
            "taiji_dht_nodes{family=\"v4\"} 120",
            "taiji_dht_nodes{family=\"v6\"} 8",
            "taiji_dht_queries_total{kind=\"ping\"} 21",
            "taiji_dht_queries_total{kind=\"find_node\"} 4",
            "taiji_dht_queries_total{kind=\"get_peers\"} 9",
            "taiji_dht_queries_total{kind=\"announce_peer\"} 3",
            "taiji_tracker_announces_total{result=\"ok\"} 11",
            "taiji_tracker_announces_total{result=\"fail\"} 3",
            "taiji_mse_handshakes_total{result=\"arc4\"} 5",
            "taiji_mse_handshakes_total{result=\"plain\"} 7",
            "taiji_utp_packets_total{kind=\"recv\"} 13",
            "taiji_utp_packets_total{kind=\"drop\"} 1",
            "taiji_hashpool_queue_depth 17",
            "taiji_hashpool_blocks_verified_total 29",
            "taiji_wrcache_events_total{kind=\"flush\"} 12",
            "taiji_wrcache_events_total{kind=\"evict\"} 4",
            "taiji_http_extents_active 4",
            "taiji_http_conn_aimd 12",
            "taiji_http_stolen_total 2",
            "taiji_rpc_requests_total{method=\"getVersion\"} 3",
            "taiji_rpc_requests_total{method=\"unknown\"} 1",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.001\"} 2",
            "taiji_rpc_request_duration_seconds_bucket{le=\"+Inf\"} 4",
            "taiji_rpc_request_duration_seconds_sum 6",
            "taiji_rpc_request_duration_seconds_count 4",
            "taiji_rpc_conn_rejected_total{scope=\"total\"} 3",
            "taiji_rpc_conn_rejected_total{scope=\"per_ip\"} 1",
            "taiji_rpc_auth_fail_total 2",
            "taiji_rpc_auth_backoff_active 1",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing series line {line:?} in:\n{out}"
            );
        }
    }

    /// Instrumentation render projection: the eviction-bytes counter,
    /// the per-peer in-flight histogram trio + active gauge, and the
    /// three-stage block/piece histogram (bucket/sum/count per stage;
    /// the render side converts per-bucket counts to cumulative).
    #[test]
    fn perf05_instrumentation_series_render() {
        let mut snap = MetricsSnapshot {
            wrcache_evict_bytes_total: 20480,
            peer_inflight_depth_count: 3,
            peer_inflight_depth_sum: 2,
            peer_inflight_active: 5,
            block_buffer_seconds_count: 1,
            block_buffer_seconds_sum_us: 120,
            block_verify_seconds_count: 2,
            block_verify_seconds_sum_us: 4_000_000,
            block_write_seconds_count: 2,
            block_write_seconds_sum_us: 500,
            ..MetricsSnapshot::default()
        };
        snap.peer_inflight_depth_buckets[0] = 1; // le=0
        snap.peer_inflight_depth_buckets[1] = 2; // le=1 (cumulative 3)
        snap.block_buffer_seconds_buckets[0] = 1;
        snap.block_write_seconds_buckets[1] = 1;

        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_wrcache_evict_bytes_total counter",
            "taiji_wrcache_evict_bytes_total 20480",
            "# TYPE taiji_peer_inflight_depth histogram",
            "taiji_peer_inflight_depth_bucket{le=\"0\"} 1",
            "taiji_peer_inflight_depth_bucket{le=\"1\"} 3",
            "taiji_peer_inflight_depth_bucket{le=\"+Inf\"} 3",
            "taiji_peer_inflight_depth_sum 2",
            "taiji_peer_inflight_depth_count 3",
            "# TYPE taiji_peer_inflight_active gauge",
            "taiji_peer_inflight_active 5",
            "# TYPE taiji_block_stage_seconds histogram",
            "taiji_block_stage_seconds_bucket{stage=\"buffer\",le=\"0.0001\"} 1",
            "taiji_block_stage_seconds_bucket{stage=\"buffer\",le=\"+Inf\"} 1",
            "taiji_block_stage_seconds_sum{stage=\"buffer\"} 0.00012",
            "taiji_block_stage_seconds_count{stage=\"buffer\"} 1",
            "taiji_block_stage_seconds_bucket{stage=\"verify\",le=\"0.0001\"} 0",
            "taiji_block_stage_seconds_bucket{stage=\"verify\",le=\"+Inf\"} 2",
            "taiji_block_stage_seconds_sum{stage=\"verify\"} 4",
            "taiji_block_stage_seconds_count{stage=\"verify\"} 2",
            "taiji_block_stage_seconds_bucket{stage=\"write\",le=\"0.00025\"} 1",
            "taiji_block_stage_seconds_bucket{stage=\"write\",le=\"+Inf\"} 2",
            "taiji_block_stage_seconds_sum{stage=\"write\"} 0.0005",
            "taiji_block_stage_seconds_count{stage=\"write\"} 2",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing series line {line:?} in:\n{out}"
            );
        }
    }

    /// Spill family render projection: spill write/read bytes +
    /// read-back pieces + budget-fallback destroy bytes, four counters
    /// (name/type/value asserted line by line; the read-back hit-rate
    /// formula is in the HELP text); the default snapshot's honest zeros
    /// are present too.
    #[test]
    fn spill_family_projects_into_metrics() {
        let snap = MetricsSnapshot {
            spill_write_bytes_total: 32768,
            spill_read_bytes_total: 32768,
            spill_readback_pieces_total: 4,
            spill_fallback_destroy_bytes_total: 65536,
            ..MetricsSnapshot::default()
        };
        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_spill_write_bytes_total counter",
            "taiji_spill_write_bytes_total 32768",
            "# TYPE taiji_spill_read_bytes_total counter",
            "taiji_spill_read_bytes_total 32768",
            "# TYPE taiji_spill_readback_pieces_total counter",
            "taiji_spill_readback_pieces_total 4",
            "# TYPE taiji_spill_fallback_destroy_bytes_total counter",
            "taiji_spill_fallback_destroy_bytes_total 65536",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing series line {line:?} in:\n{out}"
            );
        }
        // Default snapshot honest zeros: the new counters render
        // alongside the three faces (value 0 — the always-0 form while
        // spill is off).
        let zero = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        for line in [
            "taiji_spill_write_bytes_total 0",
            "taiji_spill_readback_pieces_total 0",
            "taiji_spill_fallback_destroy_bytes_total 0",
        ] {
            assert!(
                zero.lines().any(|l| l == line),
                "missing zero-value spill series {line:?}"
            );
        }
    }

    /// Holepunch family render projection: seven counters (name/type/
    /// value asserted line by line; rendered names carry the `_total`
    /// suffix per the repo counter naming discipline); the default
    /// snapshot's honest zeros are present too.
    #[test]
    fn holepunch_family_projects_into_metrics() {
        let snap = MetricsSnapshot {
            holepunch_rendezvous_sent_total: 3,
            holepunch_relayed_connects_total: 2,
            holepunch_punch_dials_total: 4,
            holepunch_punch_established_total: 1,
            holepunch_introducer_hits_total: 3,
            holepunch_no_introducer_total: 11,
            holepunch_punch_failed_nat_total: 2,
            ..MetricsSnapshot::default()
        };
        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_holepunch_rendezvous_sent_total counter",
            "taiji_holepunch_rendezvous_sent_total 3",
            "# TYPE taiji_holepunch_relayed_connects_total counter",
            "taiji_holepunch_relayed_connects_total 2",
            "# TYPE taiji_holepunch_punch_dials_total counter",
            "taiji_holepunch_punch_dials_total 4",
            "# TYPE taiji_holepunch_punch_established_total counter",
            "taiji_holepunch_punch_established_total 1",
            "# TYPE taiji_holepunch_introducer_hits_total counter",
            "taiji_holepunch_introducer_hits_total 3",
            "# TYPE taiji_holepunch_no_introducer_total counter",
            "taiji_holepunch_no_introducer_total 11",
            "# TYPE taiji_holepunch_punch_failed_nat_total counter",
            "taiji_holepunch_punch_failed_nat_total 2",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing series line {line:?} in:\n{out}"
            );
        }
        // Default snapshot honest zeros (the observation face is purely
        // additive; mode off / no punch activity always renders 0 rows).
        let zero = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        for line in [
            "taiji_holepunch_rendezvous_sent_total 0",
            "taiji_holepunch_punch_dials_total 0",
            "taiji_holepunch_punch_failed_nat_total 0",
        ] {
            assert!(
                zero.lines().any(|l| l == line),
                "missing zero-value holepunch series {line:?}"
            );
        }
    }

    /// DNS family projection: the four-counter series (full label enum) +
    /// the histogram trio (per-bucket counts converted to cumulative
    /// on the render side; +Inf bucket = count; sum microseconds
    /// converted to seconds). Name/type/label/value asserted line by
    /// line.
    #[test]
    fn dns_family_projects_into_metrics() {
        let mut snap = MetricsSnapshot {
            dns_lookups_hit_total: 3,
            dns_lookups_miss_total: 7,
            dns_lookups_error_total: 2,
            dns_lookups_timeout_total: 1,
            dns_family_mix_v4_only_total: 5,
            dns_family_mix_v6_only_total: 1,
            dns_family_mix_dual_total: 2,
            dns_events_evict_ttl_total: 4,
            dns_events_evict_capacity_total: 6,
            ..MetricsSnapshot::default()
        };
        // Per-bucket (non-cumulative) injection: le=0.001 <- 2, le=0.005
        // <- 3 (rendered cumulative 2, 5); the 4th sample is over-range
        // (count/sum only).
        snap.dns_resolve_seconds_buckets[0] = 2;
        snap.dns_resolve_seconds_buckets[1] = 3;
        snap.dns_resolve_seconds_count = 5;
        snap.dns_resolve_seconds_sum_us = 1_500_000;

        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_dns_lookups_total counter",
            "taiji_dns_lookups_total{result=\"hit\"} 3",
            "taiji_dns_lookups_total{result=\"miss\"} 7",
            "taiji_dns_lookups_total{result=\"error\"} 2",
            "taiji_dns_lookups_total{result=\"timeout\"} 1",
            "# TYPE taiji_dns_resolve_seconds histogram",
            "taiji_dns_resolve_seconds_bucket{le=\"0.001\"} 2",
            "taiji_dns_resolve_seconds_bucket{le=\"0.005\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"0.01\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"0.05\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"0.1\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"0.5\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"1\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"5\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"30\"} 5",
            "taiji_dns_resolve_seconds_bucket{le=\"+Inf\"} 5",
            "taiji_dns_resolve_seconds_sum 1.5",
            "taiji_dns_resolve_seconds_count 5",
            "# TYPE taiji_dns_family_mix_total counter",
            "taiji_dns_family_mix_total{mix=\"v4_only\"} 5",
            "taiji_dns_family_mix_total{mix=\"v6_only\"} 1",
            "taiji_dns_family_mix_total{mix=\"dual\"} 2",
            "# TYPE taiji_dns_events_total counter",
            "taiji_dns_events_total{kind=\"evict_ttl\"} 4",
            "taiji_dns_events_total{kind=\"evict_capacity\"} 6",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing DNS series line {line:?} in:\n{out}"
            );
        }
    }

    /// HTTP transport family projection: the nine errors series (full
    /// class enum + the two dns persistence slots), the two-phase
    /// request_seconds histogram trio, five counters and the slowstart
    /// histogram — name/type/label/value asserted line by line.
    #[test]
    fn http_transport_family_projects_into_metrics() {
        let mut snap = MetricsSnapshot {
            http_errors_dns_permanent_total: 2,
            http_errors_dns_transient_total: 5,
            http_errors_timeout_total: 1,
            http_errors_tls_total: 1,
            http_errors_connect_total: 3,
            http_errors_refused_total: 4,
            http_errors_reset_total: 6,
            http_errors_http_4xx_total: 7,
            http_errors_http_5xx_total: 8,
            http_retries_total: 9,
            http_extent_reassign_total: 10,
            http_mirror_demote_total: 11,
            http_mirror_remove_total: 12,
            http_mirror_restore_total: 13,
            http_stall_detected_total: 14,
            http_aimd_grow_total: 15,
            http_aimd_shrink_total: 16,
            ..MetricsSnapshot::default()
        };
        // Per-bucket injection: le=0.01 <- 2, le=0.05 <- 3 (first_byte
        // cumulative 2, 5; the 4th sample over-range, count/sum only);
        // the total phase gets a single bucket + a single slowstart
        // bucket.
        snap.http_request_first_byte_buckets[0] = 2;
        snap.http_request_first_byte_buckets[1] = 3;
        snap.http_request_first_byte_count = 5;
        snap.http_request_first_byte_sum_us = 1_200_000;
        snap.http_request_total_buckets[8] = 4;
        snap.http_request_total_count = 4;
        snap.http_request_total_sum_us = 900_000_000;
        snap.http_slowstart_seconds_buckets[2] = 1;
        snap.http_slowstart_seconds_count = 1;
        snap.http_slowstart_seconds_sum_us = 2_500_000;

        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_http_errors_total counter",
            "taiji_http_errors_total{class=\"dns\",persistence=\"permanent\"} 2",
            "taiji_http_errors_total{class=\"dns\",persistence=\"transient\"} 5",
            "taiji_http_errors_total{class=\"timeout\"} 1",
            "taiji_http_errors_total{class=\"tls\"} 1",
            "taiji_http_errors_total{class=\"connect\"} 3",
            "taiji_http_errors_total{class=\"refused\"} 4",
            "taiji_http_errors_total{class=\"reset\"} 6",
            "taiji_http_errors_total{class=\"http_4xx\"} 7",
            "taiji_http_errors_total{class=\"http_5xx\"} 8",
            "# TYPE taiji_http_request_seconds histogram",
            "taiji_http_request_seconds_bucket{phase=\"first_byte\",le=\"0.01\"} 2",
            "taiji_http_request_seconds_bucket{phase=\"first_byte\",le=\"0.05\"} 5",
            "taiji_http_request_seconds_bucket{phase=\"first_byte\",le=\"+Inf\"} 5",
            "taiji_http_request_seconds_sum{phase=\"first_byte\"} 1.2",
            "taiji_http_request_seconds_count{phase=\"first_byte\"} 5",
            "taiji_http_request_seconds_bucket{phase=\"total\",le=\"300\"} 4",
            "taiji_http_request_seconds_bucket{phase=\"total\",le=\"+Inf\"} 4",
            "taiji_http_request_seconds_sum{phase=\"total\"} 900",
            "taiji_http_request_seconds_count{phase=\"total\"} 4",
            "# TYPE taiji_http_retries_total counter",
            "taiji_http_retries_total 9",
            "# TYPE taiji_http_extent_reassign_total counter",
            "taiji_http_extent_reassign_total 10",
            "# TYPE taiji_http_mirror_events_total counter",
            "taiji_http_mirror_events_total{kind=\"demote\"} 11",
            "taiji_http_mirror_events_total{kind=\"remove\"} 12",
            "taiji_http_mirror_events_total{kind=\"restore\"} 13",
            "# TYPE taiji_http_stall_detected_total counter",
            "taiji_http_stall_detected_total 14",
            "# TYPE taiji_http_aimd_events_total counter",
            "taiji_http_aimd_events_total{dir=\"grow\"} 15",
            "taiji_http_aimd_events_total{dir=\"shrink\"} 16",
            "# TYPE taiji_http_slowstart_seconds histogram",
            "taiji_http_slowstart_seconds_bucket{le=\"2\"} 1",
            "taiji_http_slowstart_seconds_bucket{le=\"+Inf\"} 1",
            "taiji_http_slowstart_seconds_sum 2.5",
            "taiji_http_slowstart_seconds_count 1",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing HTTP transport series line {line:?} in:\n{out}"
            );
        }
        // Default snapshot honest zeros: the two dns persistence slots
        // and the other class series (value 0).
        let zero = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        for line in [
            "taiji_http_errors_total{class=\"dns\",persistence=\"permanent\"} 0",
            "taiji_http_errors_total{class=\"http_5xx\"} 0",
            "taiji_http_retries_total 0",
            "taiji_http_slowstart_seconds_count 0",
        ] {
            assert!(
                zero.lines().any(|l| l == line),
                "missing zero-value series {line:?}"
            );
        }
    }

    /// Connection-profile family projection: the
    /// `taiji_http_conn_establishments_total` counter + the
    /// `taiji_http_conn_establish_seconds` histogram trio (per-bucket
    /// counts converted to cumulative on the render side; +Inf bucket =
    /// count; sum microseconds to seconds). Name/type/label/value
    /// asserted line by line; the default snapshot's honest zeros are
    /// present too.
    #[test]
    fn conn_profile_family_projects_into_metrics() {
        let mut snap = MetricsSnapshot {
            http_conn_establishments_total: 4,
            ..MetricsSnapshot::default()
        };
        // Per-bucket injection: le=0.25 <- 1, le=0.5 <- 2 (cumulative
        // 1, 3); the 5th sample over-range, count/sum only (count=4
        // keeps the counter equality).
        snap.http_conn_establish_seconds_buckets[5] = 1;
        snap.http_conn_establish_seconds_buckets[6] = 2;
        snap.http_conn_establish_seconds_count = 4;
        snap.http_conn_establish_seconds_sum_us = 1_040_000;

        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_http_conn_establishments_total counter",
            "taiji_http_conn_establishments_total 4",
            "# TYPE taiji_http_conn_establish_seconds histogram",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.001\"} 0",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.005\"} 0",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.01\"} 0",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.05\"} 0",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.1\"} 0",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.25\"} 1",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.5\"} 3",
            "taiji_http_conn_establish_seconds_bucket{le=\"1\"} 3",
            "taiji_http_conn_establish_seconds_bucket{le=\"5\"} 3",
            "taiji_http_conn_establish_seconds_bucket{le=\"30\"} 3",
            "taiji_http_conn_establish_seconds_bucket{le=\"+Inf\"} 4",
            "taiji_http_conn_establish_seconds_sum 1.04",
            "taiji_http_conn_establish_seconds_count 4",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing conn-profile series line {line:?} in:\n{out}"
            );
        }
        // Default snapshot honest zeros (the zero form of the
        // counter/histogram equality).
        let zero = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        for line in [
            "taiji_http_conn_establishments_total 0",
            "taiji_http_conn_establish_seconds_bucket{le=\"0.25\"} 0",
            "taiji_http_conn_establish_seconds_sum 0",
            "taiji_http_conn_establish_seconds_count 0",
        ] {
            assert!(
                zero.lines().any(|l| l == line),
                "missing zero-value conn-profile series {line:?}"
            );
        }
    }

    /// Disk/finalize family projection: the sink write count/bytes/
    /// in-flight gauge + the three-op finalize histogram (full op enum,
    /// trio) + the prealloc histogram. Name/type/label/value asserted
    /// line by line.
    #[test]
    fn disk_family_projects_into_metrics() {
        let mut snap = MetricsSnapshot {
            disk_sink_writes_total: 3,
            disk_sink_writes_bytes_total: 12288,
            disk_sink_inflight: 1,
            ..MetricsSnapshot::default()
        };
        // Per-bucket injection: rename le=5 <- 1, le=30 <- 2 (cumulative
        // 1, 2); the 4th sample over-range, count/sum only.
        // file_fsync/fsync_dir/prealloc single buckets.
        snap.disk_finalize_rename_buckets[6] = 1;
        snap.disk_finalize_rename_buckets[7] = 2;
        snap.disk_finalize_rename_count = 4;
        snap.disk_finalize_rename_sum_us = 61_000_000;
        snap.disk_finalize_file_fsync_buckets[1] = 2;
        snap.disk_finalize_file_fsync_count = 2;
        snap.disk_finalize_file_fsync_sum_us = 16_000;
        snap.disk_finalize_fsync_dir_buckets[4] = 1;
        snap.disk_finalize_fsync_dir_count = 1;
        snap.disk_finalize_fsync_dir_sum_us = 300_000;
        snap.disk_prealloc_seconds_buckets[0] = 1;
        snap.disk_prealloc_seconds_count = 1;
        snap.disk_prealloc_seconds_sum_us = 500;

        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_disk_sink_writes_total counter",
            "taiji_disk_sink_writes_total 3",
            "# TYPE taiji_disk_sink_writes_bytes_total counter",
            "taiji_disk_sink_writes_bytes_total 12288",
            "# TYPE taiji_disk_sink_inflight gauge",
            "taiji_disk_sink_inflight 1",
            "# TYPE taiji_disk_finalize_seconds histogram",
            "taiji_disk_finalize_seconds_bucket{op=\"file_fsync\",le=\"0.01\"} 2",
            "taiji_disk_finalize_seconds_bucket{op=\"file_fsync\",le=\"+Inf\"} 2",
            "taiji_disk_finalize_seconds_sum{op=\"file_fsync\"} 0.016",
            "taiji_disk_finalize_seconds_count{op=\"file_fsync\"} 2",
            "taiji_disk_finalize_seconds_bucket{op=\"fsync_dir\",le=\"0.5\"} 1",
            "taiji_disk_finalize_seconds_bucket{op=\"fsync_dir\",le=\"+Inf\"} 1",
            "taiji_disk_finalize_seconds_sum{op=\"fsync_dir\"} 0.3",
            "taiji_disk_finalize_seconds_count{op=\"fsync_dir\"} 1",
            "taiji_disk_finalize_seconds_bucket{op=\"rename\",le=\"5\"} 1",
            "taiji_disk_finalize_seconds_bucket{op=\"rename\",le=\"30\"} 3",
            "taiji_disk_finalize_seconds_bucket{op=\"rename\",le=\"+Inf\"} 4",
            "taiji_disk_finalize_seconds_sum{op=\"rename\"} 61",
            "taiji_disk_finalize_seconds_count{op=\"rename\"} 4",
            "# TYPE taiji_disk_prealloc_seconds histogram",
            "taiji_disk_prealloc_seconds_bucket{le=\"0.001\"} 1",
            "taiji_disk_prealloc_seconds_bucket{le=\"+Inf\"} 1",
            "taiji_disk_prealloc_seconds_sum 0.0005",
            "taiji_disk_prealloc_seconds_count 1",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing disk family series line {line:?} in:\n{out}"
            );
        }
        // Default snapshot honest zeros: the three ops and the prealloc
        // series (value 0).
        let zero = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        for line in [
            "taiji_disk_sink_writes_total 0",
            "taiji_disk_sink_inflight 0",
            "taiji_disk_finalize_seconds_count{op=\"file_fsync\"} 0",
            "taiji_disk_finalize_seconds_count{op=\"fsync_dir\"} 0",
            "taiji_disk_finalize_seconds_count{op=\"rename\"} 0",
            "taiji_disk_prealloc_seconds_count 0",
        ] {
            assert!(
                zero.lines().any(|l| l == line),
                "missing zero-value disk series {line:?}"
            );
        }
    }

    /// DHT queries + inbound + persistence family projection: the
    /// `taiji_dht_queries_total` counter four-kind series (the full BEP5
    /// enum) + the inbound trio + `taiji_persist_queue_depth`
    /// gauge + `taiji_persist_commit_seconds` histogram trio. Name/type/
    /// label/value asserted line by line; the default snapshot's honest
    /// zeros are present too.
    #[test]
    fn dht_and_persist_families_project_into_metrics() {
        let mut snap = MetricsSnapshot {
            dht_queries_ping_total: 21,
            dht_queries_find_node_total: 4,
            dht_queries_get_peers_total: 9,
            dht_queries_announce_peer_total: 3,
            dht_inbound_packets_total: 40,
            dht_inbound_queries_total: 12,
            dht_inbound_unmatched_drops_total: 25,
            persist_queue_depth: 6,
            ..MetricsSnapshot::default()
        };
        // Per-bucket injection: le=0.001 <- 2, le=0.005 <- 3 (rendered
        // cumulative 2, 5); the 5th sample over-range, count/sum only.
        snap.persist_commit_seconds_buckets[0] = 2;
        snap.persist_commit_seconds_buckets[1] = 3;
        snap.persist_commit_seconds_count = 5;
        snap.persist_commit_seconds_sum_us = 750_000;

        let out = render(&snap, &TorrentStateCounts::default(), "taiji/0.1.0", 0);
        let expect: &[&str] = &[
            "# TYPE taiji_dht_queries_total counter",
            "taiji_dht_queries_total{kind=\"ping\"} 21",
            "taiji_dht_queries_total{kind=\"find_node\"} 4",
            "taiji_dht_queries_total{kind=\"get_peers\"} 9",
            "taiji_dht_queries_total{kind=\"announce_peer\"} 3",
            "# TYPE taiji_dht_inbound_packets_total counter",
            "taiji_dht_inbound_packets_total 40",
            "# TYPE taiji_dht_inbound_queries_total counter",
            "taiji_dht_inbound_queries_total 12",
            "# TYPE taiji_dht_inbound_unmatched_drops_total counter",
            "taiji_dht_inbound_unmatched_drops_total 25",
            "# TYPE taiji_persist_queue_depth gauge",
            "taiji_persist_queue_depth 6",
            "# TYPE taiji_persist_commit_seconds histogram",
            "taiji_persist_commit_seconds_bucket{le=\"0.001\"} 2",
            "taiji_persist_commit_seconds_bucket{le=\"0.005\"} 5",
            "taiji_persist_commit_seconds_bucket{le=\"0.01\"} 5",
            "taiji_persist_commit_seconds_bucket{le=\"0.05\"} 5",
            "taiji_persist_commit_seconds_bucket{le=\"0.1\"} 5",
            "taiji_persist_commit_seconds_bucket{le=\"0.5\"} 5",
            "taiji_persist_commit_seconds_bucket{le=\"1\"} 5",
            "taiji_persist_commit_seconds_bucket{le=\"+Inf\"} 5",
            "taiji_persist_commit_seconds_sum 0.75",
            "taiji_persist_commit_seconds_count 5",
        ];
        for line in expect {
            assert!(
                out.lines().any(|l| l == *line),
                "missing C-period family series line {line:?} in:\n{out}"
            );
        }
        // Default snapshot honest zeros: the four kinds and the persist
        // series (value 0).
        let zero = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        for line in [
            "taiji_dht_queries_total{kind=\"ping\"} 0",
            "taiji_dht_queries_total{kind=\"find_node\"} 0",
            "taiji_dht_queries_total{kind=\"get_peers\"} 0",
            "taiji_dht_queries_total{kind=\"announce_peer\"} 0",
            "taiji_dht_inbound_packets_total 0",
            "taiji_dht_inbound_queries_total 0",
            "taiji_dht_inbound_unmatched_drops_total 0",
            "taiji_persist_queue_depth 0",
            "taiji_persist_commit_seconds_count 0",
        ] {
            assert!(
                zero.lines().any(|l| l == line),
                "missing zero-value C-period series {line:?}"
            );
        }
    }

    /// Non-destructive guard: the newer family projections are
    /// additive-only. After filtering out `taiji_dns_*` and the newer
    /// families (HTTP transport, disk/finalize, DHT queries/persist,
    /// connection-profile, instrumentation), the default-snapshot render
    /// must equal the captured baseline line by line (the baseline
    /// literal is the full pre-extension default-snapshot render,
    /// captured once; any later render change must update the baseline
    /// explicitly).
    #[test]
    fn dns_projection_is_additive_and_existing_face_unchanged() {
        let out = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        const A1_FAMILIES: [&str; 8] = [
            "taiji_http_errors_total",
            "taiji_http_request_seconds",
            "taiji_http_retries_total",
            "taiji_http_extent_reassign_total",
            "taiji_http_mirror_events_total",
            "taiji_http_stall_detected_total",
            "taiji_http_aimd_events_total",
            "taiji_http_slowstart_seconds",
        ];
        // Connection-profile families (part of the additive-only guard).
        const CONN_FAMILIES: [&str; 2] = [
            "taiji_http_conn_establishments_total",
            "taiji_http_conn_establish_seconds",
        ];
        // Instrumentation families (part of the additive-only guard):
        // eviction bytes, the per-peer in-flight histogram/gauge, the
        // three-stage block/piece duration histogram.
        const PERF05_FAMILIES: [&str; 3] = [
            "taiji_wrcache_evict_bytes_total",
            "taiji_peer_inflight",
            "taiji_block_stage_seconds",
        ];
        // Disk/finalize families (part of the additive-only guard).
        const B_DISK_FAMILIES: [&str; 5] = [
            "taiji_disk_sink_writes_total",
            "taiji_disk_sink_writes_bytes_total",
            "taiji_disk_sink_inflight",
            "taiji_disk_finalize_seconds",
            "taiji_disk_prealloc_seconds",
        ];
        // DHT queries + persistence families (same guard).
        const C_FAMILIES: [&str; 3] = [
            "taiji_dht_queries_total",
            "taiji_persist_queue_depth",
            "taiji_persist_commit_seconds",
        ];
        let non_dns: Vec<&str> = out
            .lines()
            .filter(|l| {
                !l.contains("taiji_dns")
                    && !A1_FAMILIES.iter().any(|f| l.contains(f))
                    && !B_DISK_FAMILIES.iter().any(|f| l.contains(f))
                    && !C_FAMILIES.iter().any(|f| l.contains(f))
                    && !CONN_FAMILIES.iter().any(|f| l.contains(f))
                    && !PERF05_FAMILIES.iter().any(|f| l.contains(f))
            })
            .collect();
        const GOLDEN_BASELINE: &[&str] = &[
            "# HELP taiji_build_info Engine build metadata.",
            "# TYPE taiji_build_info gauge",
            "taiji_build_info{version=\"taiji/0.1.0\"} 1",
            "# HELP taiji_session_uptime_seconds Session uptime in seconds.",
            "# TYPE taiji_session_uptime_seconds gauge",
            "taiji_session_uptime_seconds 0",
            "# HELP taiji_panic_total Engine task panics observed by the session.",
            "# TYPE taiji_panic_total counter",
            "taiji_panic_total 0",
            "# HELP taiji_torrents Torrent count by aria2 status (bounded label set).",
            "# TYPE taiji_torrents gauge",
            "taiji_torrents{state=\"active\"} 0",
            "taiji_torrents{state=\"waiting\"} 0",
            "taiji_torrents{state=\"paused\"} 0",
            "taiji_torrents{state=\"complete\"} 0",
            "taiji_torrents{state=\"error\"} 0",
            "taiji_torrents{state=\"removed\"} 0",
            "# HELP taiji_torrent_bytes_total Cumulative payload bytes transferred this session.",
            "# TYPE taiji_torrent_bytes_total counter",
            "taiji_torrent_bytes_total{direction=\"down\"} 0",
            "taiji_torrent_bytes_total{direction=\"up\"} 0",
            // Newer face (the supply-byte pair; the baseline was updated
            // explicitly).
            "# HELP taiji_peer_supply_bytes_total Cumulative wire-received payload bytes by peer transport (tcp|utp; sums to bytes_down down direction).",
            "# TYPE taiji_peer_supply_bytes_total counter",
            "taiji_peer_supply_bytes_total{transport=\"tcp\"} 0",
            "taiji_peer_supply_bytes_total{transport=\"utp\"} 0",
            "# HELP taiji_torrent_completed_total Torrents reached complete status.",
            "# TYPE taiji_torrent_completed_total counter",
            "taiji_torrent_completed_total 0",
            "# HELP taiji_peer_connections Live peer connections by transport and direction.",
            "# TYPE taiji_peer_connections gauge",
            "taiji_peer_connections{transport=\"tcp\",direction=\"in\"} 0",
            "taiji_peer_connections{transport=\"tcp\",direction=\"out\"} 0",
            "taiji_peer_connections{transport=\"utp\",direction=\"in\"} 0",
            "taiji_peer_connections{transport=\"utp\",direction=\"out\"} 0",
            "# HELP taiji_peer_connections_choked Live connections we currently choke.",
            "# TYPE taiji_peer_connections_choked gauge",
            "taiji_peer_connections_choked 0",
            "# HELP taiji_peer_bans_total Peer bans enacted (auto rules, SPEC §13).",
            "# TYPE taiji_peer_bans_total counter",
            "taiji_peer_bans_total 0",
            "# HELP taiji_redial_attempts_total Redial-pool dial attempts (, libtorrent min_reconnect_time semantics).",
            "# TYPE taiji_redial_attempts_total counter",
            "taiji_redial_attempts_total 0",
            "# HELP taiji_redial_connected_total Redial dial attempts that completed a BT handshake .",
            "# TYPE taiji_redial_connected_total counter",
            "taiji_redial_connected_total 0",
            "# HELP taiji_redial_pool_size Known-good disconnected peers awaiting redial (, bounded).",
            "# TYPE taiji_redial_pool_size gauge",
            "taiji_redial_pool_size 0",
            // Holepunch family, seven counters (+21 baseline rows:
            // HELP/TYPE/sample per counter; rendered after redial, before
            // the protocol families, matching the render() insertion
            // order).
            "# HELP taiji_holepunch_rendezvous_sent_total Rendezvous asks sent to PEX introducers (trigger face, sent = counted; no receipt accounting).",
            "# TYPE taiji_holepunch_rendezvous_sent_total counter",
            "taiji_holepunch_rendezvous_sent_total 0",
            "# HELP taiji_holepunch_relayed_connects_total Rendezvous introductions relayed (one connect load to each side; counted per introduction action).",
            "# TYPE taiji_holepunch_relayed_connects_total counter",
            "taiji_holepunch_relayed_connects_total 0",
            "# HELP taiji_holepunch_punch_dials_total Outbound punch dials spawned after all admission gates passed.",
            "# TYPE taiji_holepunch_punch_dials_total counter",
            "taiji_holepunch_punch_dials_total 0",
            "# HELP taiji_holepunch_punch_established_total Punch-sourced dials that completed a BT handshake (counts in fallback mode too).",
            "# TYPE taiji_holepunch_punch_established_total counter",
            "taiji_holepunch_punch_established_total 0",
            "# HELP taiji_holepunch_introducer_hits_total Dial failures with a live PEX introducer whose ask-backoff has elapsed (numerator of the punchable-share ratio).",
            "# TYPE taiji_holepunch_introducer_hits_total counter",
            "taiji_holepunch_introducer_hits_total 0",
            "# HELP taiji_holepunch_no_introducer_total Dial failures without a usable introducer (no PEX delivery / backoff pending / TTL expired; denominator pair of introducer_hits).",
            "# TYPE taiji_holepunch_no_introducer_total counter",
            "taiji_holepunch_no_introducer_total 0",
            "# HELP taiji_holepunch_punch_failed_nat_total Punch windows exhausted with zero peer response across all attempts (port-prediction plane never opened; symmetric-NAT shape).",
            "# TYPE taiji_holepunch_punch_failed_nat_total counter",
            "taiji_holepunch_punch_failed_nat_total 0",
            // Peer-leave reason family (+7 baseline rows; any render
            // change must update this baseline).
            "# HELP taiji_peer_leaves_total Peer connection departures by terminal reason ( connection-retention face; cancelled = engine teardown, excluded from bleed diagnosis).",
            "# TYPE taiji_peer_leaves_total counter",
            "taiji_peer_leaves_total{reason=\"peer-closed\"} 0",
            "taiji_peer_leaves_total{reason=\"local\"} 0",
            "taiji_peer_leaves_total{reason=\"io\"} 0",
            "taiji_peer_leaves_total{reason=\"protocol\"} 0",
            "taiji_peer_leaves_total{reason=\"cancelled\"} 0",
            "# HELP taiji_dht_nodes DHT routing table nodes by address family.",
            "# TYPE taiji_dht_nodes gauge",
            "taiji_dht_nodes{family=\"v4\"} 0",
            "taiji_dht_nodes{family=\"v6\"} 0",
            // DHT inbound observation family: three
            // counters x (HELP/TYPE/sample), rendered between the
            // (C_FAMILIES-excluded) query counter block and the tracker
            // family. Baseline updated explicitly per the guard's design
            // intent (render-face reshapes must re-review the baseline).
            "# HELP taiji_dht_inbound_packets_total Inbound DHT datagrams at the engine handle_packet entry (observation only; summed v4+v6 engines, 1s-tick delta feed).",
            "# TYPE taiji_dht_inbound_packets_total counter",
            "taiji_dht_inbound_packets_total 0",
            "# HELP taiji_dht_inbound_queries_total Inbound DHT datagrams admitted to full bencode decode (queries face of the inbound family).",
            "# TYPE taiji_dht_inbound_queries_total counter",
            "taiji_dht_inbound_queries_total 0",
            "# HELP taiji_dht_inbound_unmatched_drops_total Reply/error DHT frames dropped before decode on no pending transaction (the early-drop face; packets - queries - other-drops context).",
            "# TYPE taiji_dht_inbound_unmatched_drops_total counter",
            "taiji_dht_inbound_unmatched_drops_total 0",
            "# HELP taiji_tracker_announces_total Tracker announces by attributed result.",
            "# TYPE taiji_tracker_announces_total counter",
            "taiji_tracker_announces_total{result=\"ok\"} 0",
            "taiji_tracker_announces_total{result=\"fail\"} 0",
            "# HELP taiji_mse_handshakes_total Registered connections by negotiated crypto.",
            "# TYPE taiji_mse_handshakes_total counter",
            "taiji_mse_handshakes_total{result=\"arc4\"} 0",
            "taiji_mse_handshakes_total{result=\"plain\"} 0",
            "# HELP taiji_utp_packets_total µTP datagrams by demux outcome.",
            "# TYPE taiji_utp_packets_total counter",
            "taiji_utp_packets_total{kind=\"recv\"} 0",
            "taiji_utp_packets_total{kind=\"drop\"} 0",
            "# HELP taiji_hashpool_queue_depth Store pipeline inbound block channel occupancy (hash/write backlog upper bound).",
            "# TYPE taiji_hashpool_queue_depth gauge",
            "taiji_hashpool_queue_depth 0",
            "# HELP taiji_block_arena_lease_hits_total Block-buffer pool reuse hits zero malloc steady state).",
            "# TYPE taiji_block_arena_lease_hits_total counter",
            "taiji_block_arena_lease_hits_total 0",
            "# HELP taiji_block_arena_alloc_fallback_total Direct-alloc fallbacks (over budget or oversize frame; exempt path of per-block zero-malloc).",
            "# TYPE taiji_block_arena_alloc_fallback_total counter",
            "taiji_block_arena_alloc_fallback_total 0",
            "# HELP taiji_block_arena_outstanding_blocks Leased-out (in-use) pool blocks watermark.",
            "# TYPE taiji_block_arena_outstanding_blocks gauge",
            "taiji_block_arena_outstanding_blocks 0",
            "# HELP taiji_block_arena_cap_bytes Pool byte cap (explicit component of face unverified-byte budget).",
            "# TYPE taiji_block_arena_cap_bytes gauge",
            "taiji_block_arena_cap_bytes 0",
            "# HELP taiji_hashpool_blocks_verified_total 16KiB blocks passed verification.",
            "# TYPE taiji_hashpool_blocks_verified_total counter",
            "taiji_hashpool_blocks_verified_total 0",
            "# HELP taiji_wrcache_events_total Write-cache lifecycle events (flush = piece written; evict = unverified piece dropped).",
            "# TYPE taiji_wrcache_events_total counter",
            "taiji_wrcache_events_total{kind=\"flush\"} 0",
            "taiji_wrcache_events_total{kind=\"evict\"} 0",
            // Unverified-spill trio (additive-only: spill defaults off,
            // the default snapshot is always 0 — +9 baseline rows, same
            // pattern as the block-pool families).
            "# HELP taiji_spill_write_bytes_total Unverified bytes spilled to the sidecar instead of being destroyed on write-cache eviction.",
            "# TYPE taiji_spill_write_bytes_total counter",
            "taiji_spill_write_bytes_total 0",
            "# HELP taiji_spill_read_bytes_total Spill sidecar bytes read back at piece assembly.",
            "# TYPE taiji_spill_read_bytes_total counter",
            "taiji_spill_read_bytes_total 0",
            "# HELP taiji_spill_readback_pieces_total Pieces whose spilled cells were read back for verification (hit-rate numerator; denominator adds wrcache evictions).",
            "# TYPE taiji_spill_readback_pieces_total counter",
            "taiji_spill_readback_pieces_total 0",
            // +3 baseline rows (HELP/TYPE/sample — budget-fallback
            // destroy bytes; always 0 with spill off).
            "# HELP taiji_spill_fallback_destroy_bytes_total Unverified bytes destroyed because the spill budget could not absorb them (FIFO displacement or absorption refusal; the budget-attributable share of wrcache evictions).",
            "# TYPE taiji_spill_fallback_destroy_bytes_total counter",
            "taiji_spill_fallback_destroy_bytes_total 0",
            "# HELP taiji_http_extents_active In-flight HTTP extents across active tasks.",
            "# TYPE taiji_http_extents_active gauge",
            "taiji_http_extents_active 0",
            "# HELP taiji_http_conn_aimd AIMD connection budget summed over HTTP task sources (per-task face via tellStatus http sub-dict).",
            "# TYPE taiji_http_conn_aimd gauge",
            "taiji_http_conn_aimd 0",
            "# HELP taiji_http_stolen_total Stall-steal grants at the single adjudication point (cumulative).",
            "# TYPE taiji_http_stolen_total counter",
            "taiji_http_stolen_total 0",
            "# HELP taiji_rpc_requests_total JSON-RPC calls by frozen method name (unknown methods merged to one slot).",
            "# TYPE taiji_rpc_requests_total counter",
            "taiji_rpc_requests_total{method=\"addUri\"} 0",
            "taiji_rpc_requests_total{method=\"addTorrent\"} 0",
            "taiji_rpc_requests_total{method=\"tellStatus\"} 0",
            "taiji_rpc_requests_total{method=\"getFiles\"} 0",
            "taiji_rpc_requests_total{method=\"getPeers\"} 0",
            "taiji_rpc_requests_total{method=\"getServers\"} 0",
            "taiji_rpc_requests_total{method=\"getUris\"} 0",
            "taiji_rpc_requests_total{method=\"pause\"} 0",
            "taiji_rpc_requests_total{method=\"forcePause\"} 0",
            "taiji_rpc_requests_total{method=\"unpause\"} 0",
            // forceRecheck: a new registry method slot (the render face
            // projects RPC_METHODS name by name — the baseline grows with
            // the method face).
            "taiji_rpc_requests_total{method=\"forceRecheck\"} 0",
            "taiji_rpc_requests_total{method=\"pauseAll\"} 0",
            "taiji_rpc_requests_total{method=\"forcePauseAll\"} 0",
            "taiji_rpc_requests_total{method=\"unpauseAll\"} 0",
            "taiji_rpc_requests_total{method=\"remove\"} 0",
            "taiji_rpc_requests_total{method=\"forceRemove\"} 0",
            "taiji_rpc_requests_total{method=\"purgeDownloadResult\"} 0",
            "taiji_rpc_requests_total{method=\"removeDownloadResult\"} 0",
            "taiji_rpc_requests_total{method=\"changeUri\"} 0",
            "taiji_rpc_requests_total{method=\"changePosition\"} 0",
            "taiji_rpc_requests_total{method=\"changeOption\"} 0",
            "taiji_rpc_requests_total{method=\"getOption\"} 0",
            "taiji_rpc_requests_total{method=\"changeGlobalOption\"} 0",
            "taiji_rpc_requests_total{method=\"getGlobalOption\"} 0",
            "taiji_rpc_requests_total{method=\"getGlobalStat\"} 0",
            "taiji_rpc_requests_total{method=\"getVersion\"} 0",
            "taiji_rpc_requests_total{method=\"getSessionInfo\"} 0",
            "taiji_rpc_requests_total{method=\"tellActive\"} 0",
            "taiji_rpc_requests_total{method=\"tellWaiting\"} 0",
            "taiji_rpc_requests_total{method=\"tellStopped\"} 0",
            "taiji_rpc_requests_total{method=\"saveSession\"} 0",
            "taiji_rpc_requests_total{method=\"shutdown\"} 0",
            "taiji_rpc_requests_total{method=\"forceShutdown\"} 0",
            "taiji_rpc_requests_total{method=\"system.listMethods\"} 0",
            "taiji_rpc_requests_total{method=\"system.multicall\"} 0",
            "taiji_rpc_requests_total{method=\"system.listNotifications\"} 0",
            "taiji_rpc_requests_total{method=\"addMetalink\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.moveStorage\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.renameFile\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.banAddr\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.unbanAddr\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.listBans\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.setSchedulerPolicy\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.getSchedulerPolicy\"} 0",
            // setFilePriority: a new registry method slot (the render
            // face projects RPC_METHODS name by name — the baseline grows
            // with the method face).
            "taiji_rpc_requests_total{method=\"taiji.setFilePriority\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.setStreamingPlayhead\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.getHttpOutput\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.finalizeHttp\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.getDiskTier\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.setDiskTier\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.getCapabilities\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.addTracker\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.removeTracker\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.addUriWithCookies\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.setTaskCookies\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.createTorrent\"} 0",
            // Media line (the four media codes plus the archive clear —
            // the table order follows the registration face).
            "taiji_rpc_requests_total{method=\"taiji.addMedia\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.probeMedia\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.getMediaFormats\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.stopRecording\"} 0",
            "taiji_rpc_requests_total{method=\"taiji.clearMediaArchive\"} 0",
            "taiji_rpc_requests_total{method=\"unknown\"} 0",
            "# HELP taiji_rpc_request_duration_seconds JSON-RPC call latency (dispatch entry; gate for RPC p99).",
            "# TYPE taiji_rpc_request_duration_seconds histogram",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.001\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.0025\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.005\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.01\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.025\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.05\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.1\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.25\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"0.5\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"1\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"2.5\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"5\"} 0",
            "taiji_rpc_request_duration_seconds_bucket{le=\"+Inf\"} 0",
            "taiji_rpc_request_duration_seconds_sum 0",
            "taiji_rpc_request_duration_seconds_count 0",
            "# HELP taiji_rpc_conn_rejected_total Connections rejected at the RPC concurrency cap by scope (total|per_ip).",
            "# TYPE taiji_rpc_conn_rejected_total counter",
            "taiji_rpc_conn_rejected_total{scope=\"total\"} 0",
            "taiji_rpc_conn_rejected_total{scope=\"per_ip\"} 0",
            "# HELP taiji_rpc_auth_fail_total Auth failures at the token/basic gates (credentials never in metrics).",
            "# TYPE taiji_rpc_auth_fail_total counter",
            "taiji_rpc_auth_fail_total 0",
            "# HELP taiji_rpc_auth_backoff_active Source IPs currently inside an auth backoff window.",
            "# TYPE taiji_rpc_auth_backoff_active gauge",
            "taiji_rpc_auth_backoff_active 0",
        ];
        // The metalink-off build legitimately drops the feature-gated
        // addMetalink slot from the method table (the baseline is pinned
        // against the feature-on face); filter it out of the expectation
        // under --no-default-features so the off-state leg compares the
        // same face it renders.
        #[cfg(not(feature = "metalink"))]
        let baseline: Vec<&str> = GOLDEN_BASELINE
            .iter()
            .copied()
            .filter(|l| !l.contains("addMetalink"))
            .collect();
        #[cfg(feature = "metalink")]
        let baseline: Vec<&str> = GOLDEN_BASELINE.to_vec();
        assert_eq!(
            non_dns.len(),
            baseline.len(),
            "non-DNS line-count drift (reshaping the render face requires an explicit baseline review)"
        );
        for (got, want) in non_dns.iter().zip(baseline.iter()) {
            assert_eq!(
                got, want,
                "existing metric projection drift (the add-only guarantee is broken)"
            );
        }
    }

    /// The render output passes strict Prometheus text validation (empty and populated forms).
    #[test]
    fn render_passes_prometheus_text_validation() {
        let empty = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        validate_prom_text(&empty)
            .unwrap_or_else(|e| panic!("default render violates prom text: {e}"));
        let full = render(
            &MetricsSnapshot::default(),
            &full_states(),
            "taiji/0.1.0",
            2,
        );
        validate_prom_text(&full).unwrap_or_else(|e| panic!("full render violates prom text: {e}"));
        // Validator self-check: malformed input must be caught (guards
        // against an always-true validator).
        assert!(validate_prom_text("garbage_line 1").is_err());
        assert!(validate_prom_text("taiji_x abc").is_err());
        assert!(
            validate_prom_text("taiji_x{method=\"a} 1\ntaiji_x 1").is_err(),
            "unbalanced label brace must fail"
        );
        assert!(
            validate_prom_text("# TYPE taiji_x counter\ntaiji_x 1\ntaiji_x 2").is_err(),
            "duplicate series must fail"
        );
        assert!(
            validate_prom_text("taiji_y 1").is_err(),
            "sample before TYPE must fail"
        );
    }

    /// Cardinality guard: with 1000 tasks / all methods fed, the series
    /// set stays bounded — the output line count is independent of the
    /// task count, and gid-like values never become labels.
    #[test]
    fn cardinality_is_bounded_under_1000_tasks() {
        let base = render(
            &MetricsSnapshot::default(),
            &TorrentStateCounts::default(),
            "taiji/0.1.0",
            0,
        );
        let big_states = TorrentStateCounts {
            active: 1000,
            waiting: 1000,
            paused: 1000,
            complete: 1000,
            error: 1000,
            removed: 1000,
        };
        let mut big_snap = MetricsSnapshot::default();
        for slot in big_snap.rpc_requests.iter_mut() {
            *slot = 1000;
        }
        big_snap.rpc_duration_count = 1000;
        let big = render(&big_snap, &big_states, "taiji/0.1.0", 0);

        // Line count equality: the rendered line count is a function of
        // the label value domains, not of counts/task numbers.
        assert_eq!(base.lines().count(), big.lines().count());
        // The torrents series is always 6 (six-state enum).
        for text in [&base, &big] {
            assert_eq!(
                text.lines()
                    .filter(|l| l.starts_with("taiji_torrents{"))
                    .count(),
                6
            );
        }
        // The rpc method series is always |RPC_METHODS| + unknown.
        assert_eq!(
            big.lines()
                .filter(|l| l.starts_with("taiji_rpc_requests_total{"))
                .count(),
            RPC_METHODS.len() + 1
        );
        // The connection series is always 4 (tcp/utp x in/out).
        assert_eq!(
            big.lines()
                .filter(|l| l.starts_with("taiji_peer_connections{"))
                .count(),
            4
        );
        // No gid-shaped hex value appears anywhere (hex16 task ids never
        // become labels).
        assert!(!big.contains("gid="), "gid must never appear as a label");
    }

    /// Credentials never echoed (render layer): secret/user/passwd-shaped
    /// strings are absent from the output.
    #[test]
    fn render_never_contains_credentials() {
        let out = render(
            &MetricsSnapshot::default(),
            &full_states(),
            "taiji/0.1.0",
            0,
        );
        for secret in ["token12secret", "rpc-user", "rpc-passwd", "authorization"] {
            assert!(!out.contains(secret), "credential-like {secret:?} leaked");
        }
    }

    // ---- End to end: route mounting + credential-free bind face + no
    // credential echo ----

    async fn get_metrics(addr: std::net::SocketAddr) -> (u16, String, String) {
        get_metrics_with_auth(addr, None).await
    }

    /// /metrics GET with/without an Authorization header (Basic-gate
    /// regression: with credentials configured, /metrics shares the
    /// /jsonrpc gate).
    async fn get_metrics_with_auth(
        addr: std::net::SocketAddr,
        authorization: Option<&str>,
    ) -> (u16, String, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        let auth_line = authorization
            .map(|v| format!("Authorization: {v}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\n{auth_line}Connection: close\r\n\r\n"
        );
        sock.write_all(req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        let mut raw = Vec::new();
        sock.read_to_end(&mut raw)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        let text = String::from_utf8(raw).unwrap_or_else(|e| panic!("utf8: {e}"));
        let (head, body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("no header/body split"));
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(0);
        let content_type = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-type:"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        (status, content_type, body.to_string())
    }

    /// Without credentials: loopback-only bind (regression) + /metrics
    /// readable without auth + output passes Prometheus validation +
    /// method counters fed by real RPC calls land.
    #[tokio::test]
    async fn metrics_endpoint_loopback_without_credentials() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server = crate::server::serve(
            crate::RpcConfig {
                port: 0,
                ..Default::default()
            },
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        assert_eq!(
            server.local_addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "no-credential bind face must be loopback only"
        );
        // Feed one known + one unknown method through the dispatcher
        // (the end-to-end counter feed point).
        let ok = crate::server::process_text(
            &app_state_for(session.clone(), &shutdown),
            r#"{"id":1,"method":"getVersion"}"#,
        )
        .await;
        assert!(ok.is_ok(), "getVersion must succeed");
        let unknown = crate::server::process_text(
            &app_state_for(session.clone(), &shutdown),
            r#"{"id":2,"method":"totally.not.a.method"}"#,
        )
        .await
        .unwrap_or_else(|()| panic!("fixture must parse"));
        assert!(
            unknown["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .starts_with("No such method"),
            "unknown method surfaces the frozen error face: {unknown}"
        );

        let (status, content_type, body) = get_metrics(server.local_addr).await;
        assert_eq!(status, 200, "/metrics requires no auth");
        assert!(
            content_type.contains("text/plain"),
            "content-type: {content_type}"
        );
        validate_prom_text(&body)
            .unwrap_or_else(|e| panic!("/metrics output invalid: {e}\n{body}"));
        assert!(body.contains("taiji_build_info{version=\"taiji/"));
        assert!(
            body.contains("taiji_rpc_requests_total{method=\"getVersion\"} 1"),
            "known-method counter fed: {body}"
        );
        assert!(
            body.contains("taiji_rpc_requests_total{method=\"unknown\"} 1"),
            "unknown-method counter merged into single slot: {body}"
        );
        assert!(
            body.contains("taiji_rpc_request_duration_seconds_count 2"),
            "histogram counts both dispatch calls: {body}"
        );
        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), actor_join).await;
    }

    /// With credentials (secret + Basic): the bind face stays loopback
    /// (the two axes are decoupled — credentials only decide the auth
    /// gate, they no longer widen the face implicitly); /metrics shares
    /// the Basic gate with /jsonrpc (401 anonymous, 200 with
    /// credentials), and the secret/credentials never appear in the
    /// output.
    #[tokio::test]
    async fn metrics_endpoint_never_echoes_credentials() {
        let secret = "p47-secret-token-9f3a";
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let server = crate::server::serve(
            crate::RpcConfig {
                port: 0,
                secret: Some(secret.to_string()),
                rpc_user: Some("p47user".to_string()),
                rpc_passwd: Some("p47pass".to_string()),
                ..Default::default()
            },
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        assert_eq!(
            server.local_addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "credentials alone must stay loopback (bind axis = listen_all only)"
        );
        // Anonymous -> Basic-gate 401 (the same gate as /jsonrpc).
        let (status, _, _) = get_metrics(server.local_addr).await;
        assert_eq!(status, 401, "anonymous /metrics must hit the basic gate");
        // Correct Basic credentials -> 200, with no credential echo in the metric body.
        let credentials = format!("Basic {}", b64_of_test(b"p47user:p47pass"));
        let (status, _, body) = get_metrics_with_auth(server.local_addr, Some(&credentials)).await;
        assert_eq!(status, 200, "/metrics with basic credentials");
        assert!(!body.contains(secret), "secret leaked in /metrics body");
        assert!(
            !body.contains("p47user") && !body.contains("p47pass"),
            "basic credentials leaked in /metrics body"
        );
        assert!(!body.contains("Authorization"), "auth header name leaked");
        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), actor_join).await;
    }

    /// Test-side standard base64 (Basic credential encoding; same rule as the auth.rs tests).
    fn b64_of_test(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// Test-side AppState (mirrors the server.rs tests; no secret injected).
    fn app_state_for(
        session: Arc<taiji_core::session::SessionHandle>,
        shutdown: &tokio_util::sync::CancellationToken,
    ) -> AppState {
        AppState {
            session,
            secret: None,
            basic: None,
            allow_origin_all: false,
            max_request_size: 1 << 20,
            shutdown: shutdown.clone(),
            aria2_compat: false,
            listen_all: false,
            conn: std::sync::Arc::new(crate::guards::ConnLedger::new(
                crate::guards::DEFAULT_MAX_TOTAL_CONNS,
                crate::guards::DEFAULT_MAX_PER_IP_CONNS,
            )),
            auth_backoff: std::sync::Arc::new(crate::guards::AuthBackoff::new(
                crate::guards::DEFAULT_AUTH_FAIL_THRESHOLD,
            )),
        }
    }
}

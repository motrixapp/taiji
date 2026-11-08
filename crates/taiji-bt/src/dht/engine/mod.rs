//! DhtEngine actor: one per family (v4/v6) (SPEC §3.2).
//!
//! # Topology (actor message contract)
//!
//! ```text
//! UdpDemux (dht channel) ──InboundPacket──▶ ┌──────────────────┐
//! │ DhtEngine │ ──DhtEvent──▶ engine/TorrentTask
//! DhtHandle (DhtCommand, mpsc(64)) ─────────▶ │ (one per family) │ (mpsc(64))
//! │ routing table / transactions / │ ──OutboundPacket──▶ single-writer egress
//! core (restore: dht_state row / dht.dat) ──▶ │ tokens / task queues │
//! └──────────────────┘
//! ```
//!
//! - Command `mpsc(64)` + oneshot replies, event `mpsc(64)` (frozen values);
//! - Inbound packets consume the dht channel, outbound writes
//!   `OutboundPacket` (demux single-writer discipline; core bridges the
//!   `UdpDemuxHandle` via [`forward_outbound`]);
//! - Task queues = immediate + periodic, 15 concurrent each (simplification,
//!   [`super::task`]).
//!
//! The behavior mapping against aria2/libtorrent and the intentional
//! divergence list live in docs/design/dht.md ("Upstream anchor mapping").
//! None of the divergences affect interoperability.
//!
//! # Security extensions (BEP42)
//!
//! [`super::security`] implements the derive/verify algorithms (BEP42 text
//! plus libtorrent node_id.cpp). The engine wires it at three points:
//!
//! 1. Local derive: `DhtCommand::SetExternalIp` supplies the external
//!    address; the current id is kept if it still verifies, otherwise
//!    re-derived (libtorrent `node::update_node_id`, node.cpp; table nodes
//!    are kept, the bucket skeleton is rebuilt around the new id — same
//!    rule as routing_table.cpp);
//! 2. Inbound queries: an invalid sender id means its announce_peer is not
//!    stored (storage refusal); queries are still answered, tokens still
//!    issued, nodes still enter the table (the BEP42 text constrains only
//!    storage: "MUST never be used to store information on" + "Requests
//!    ... should always be serviced"; excluding such nodes from the routing
//!    table has no textual basis — mainstream bootstrap routers ship
//!    non-compliant ids, so exclusion would sever bootstrapping);
//! 3. Outbound storage: announce_peer goes only to id-compliant nodes
//!    (the BEP42 "MUST never be used to store information on" clause).
//!
//! # Persistence
//!
//! Write: on autosave/halt/shutdown the good nodes of every bucket are
//! serialized into the own-format BLOB ([`super::persist`]) and delivered
//! as `DhtEvent::Persist` to the PersistWriter (SPEC §2.3 single writer;
//! the dht_state table schema v1). Read: core reads the row at startup ->
//! [`DhtRestoreState::from_state_row`]; if the table is empty and the
//! `--dht-file-path[-6]` file exists -> [`DhtRestoreState::from_dht_dat`]
//! compatible import (file parsing is disk IO, carried by the caller's
//! `spawn_blocking` — the engine does no blocking IO).
//!
//! # Concurrency discipline
//!
//! All state is actor-owned (no Mutex); all channels bounded; no blocking
//! IO; `unsafe` forbidden.
//!
//! # Module layout
//!
//! This file is a facade: module docs + public re-exports (`dht::engine::*`
//! paths identical to before the split) + submodule-shared symbols
//! (`LOG_TARGET`/`hex_id`) and a name-domain mirror (submodules/tests
//! reach them via `use super::*`; split discipline as for the core engine
//! split). Submodules: `config` (configuration and the maintenance timer
//! table), `contract` (actor command/event contract), `handle` (spawn/
//! handle/outbound bridge), `state` (actor-owned state and assembly),
//! `tasks` (task queues and driving), `bootstrap` (bootstrap rounds +
//! PORT wiring), `command` (command dispatch + announce registry),
//! `node_id` (BEP42 node_id derive/verify wiring), `wire` (inbound/outbound
//! messages + transaction routing), `maintenance` (maintenance ticks +
//! events/persistence), `run` (main loop), `error_limit` (per-source
//! error-reply limiting), `query_limit` (per-source inbound query limiting
//! and suppression), `tests` (existing tests, moved verbatim).

mod bootstrap;
mod command;
mod config;
mod contract;
mod error_limit;
mod handle;
mod maintenance;
mod node_id;
mod query_limit;
mod run;
mod state;
mod tasks;
mod wire;

#[cfg(test)]
mod tests;

// ---- Public facade (all pre-existing `dht::engine::*` paths resolve) ----
pub use bootstrap::DEFAULT_BOOTSTRAP_NODES;
pub use config::{
    DHT_AUTOSAVE_INTERVAL, DHT_BUCKET_REFRESH_CHECK_INTERVAL, DHT_PEER_ANNOUNCE_CHECK_INTERVAL,
    DHT_PEER_ANNOUNCE_INTERVAL, DHT_PEER_ANNOUNCE_PURGE_INTERVAL, DHT_PER_SOURCE_QUERY_BURST,
    DHT_PER_SOURCE_QUERY_RATE, DHT_SOURCE_SUPPRESS_SECS, DhtEngineConfig, MAINT_KINDS, MaintKind,
};
pub use contract::{
    COMMAND_CHANNEL_CAPACITY, DhtCommand, DhtEngineError, DhtEvent, DhtRestoreState, DhtSnapshot,
    DhtTarget, DhtTransport, EVENT_CHANNEL_CAPACITY,
};
pub use handle::{DhtHandle, forward_outbound, spawn};
pub use state::DhtEngine;

// Internal symbols still consumed by submodules/tests via the glob after
// the split.
use config::MaintenanceTimers;
use state::{AnnounceEntry, BootstrapRound, PeerRecordSet, RouteTarget};

// ---- Name-domain mirror (submodules and tests rely on `use super::*` for
// the following names; not a behavior face. Every name has an in-tree
// consumer: a submodule glob or a call in this module — the lib build proves
// it via unused_imports; test-only names are imported by the tests
// themselves and stay out of this block) ----
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use super::message::{
    DhtMessage, ERROR_MSG_PROTOCOL, ERROR_PROTOCOL, ErrorMessage, MessageKind, QueryBody,
    QueryMessage, ResponseBody, ResponseMessage, WantFamilies, decode_message, encode_message,
    encode_response, incoming_error_reply, scan_transaction_header,
};
use super::node::{DhtNode, NodeId};
use super::persist::{self, TableNode};
use super::routing_table::RoutingTable;
use super::security::{self, verify_node_id};
use super::task::{
    DhtSwarmKind, LookupKind, LookupTask, PingTask, QueueKind, RefreshTask, Task, TaskId, TaskQueue,
};
use super::transaction::{TransactionFailure, TransactionKey, TransactionOutcome};
// Boundedness constants (defined in wire) consumed by submodules/tests via
// `use super::*`; doc links always use the fully qualified path (`wire::…`)
// rather than keeping a dead import in this file's scope.
use wire::MAX_PEER_RECORDS_PER_KEY;
// Error-reply limiter (state field type consumed via super::*; the
// test-only ERROR_REPLY_BURST is imported by the tests themselves).
use error_limit::ErrorReplyLimiter;
// Per-source inbound query limiter (state field type consumed via super::*).
use query_limit::QueryRateLimiter;

// ---- Submodule-shared symbols ----

/// Tracing target.
pub(super) const LOG_TARGET: &str = "taiji::bt::dht::engine";

/// Hex form of a node ID for logs (same hex-id discipline as GIDs).
pub(super) fn hex_id(id: &NodeId) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

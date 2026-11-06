//! DhtEngine actor public contract (split out of engine.rs; pure move).
//!
//! Owns: the command/event enums (frozen values), `DhtTarget` (the BEP27
//! gate), `DhtEngineError`, `DhtSnapshot`, `DhtRestoreState`,
//! `DhtTransport`, and the channel capacity constants.
//! Does not own: command consumption (see `command`/`run`) and the
//! handle/spawn side (see `handle`).

use std::net::{IpAddr, SocketAddr};

use taiji_io::udp_demux::{InboundPacket, OutboundPacket};
use tokio::sync::{mpsc, oneshot};

use crate::dht::node::NodeId;
use crate::dht::persist;
use crate::dht::task::DhtSwarmKind;

/// Command channel capacity (mpsc(64)).
pub const COMMAND_CHANNEL_CAPACITY: usize = 64;
/// Event channel capacity (mpsc(64)).
pub const EVENT_CHANNEL_CAPACITY: usize = 64;

/// Actor commands (contract + PORT/persistence wiring).
#[derive(Debug)]
pub enum DhtCommand {
    /// Announce (get_peers iteration + announce_peer on completion; also
    /// registers in the auto-resend registry).
    Announce {
        target: DhtTarget,
        port: u16,
        reply: oneshot::Sender<Result<(), DhtEngineError>>,
    },
    /// get_peers iteration only (discovered peers come back via
    /// [`DhtEvent::PeersFound`]).
    GetPeers {
        target: DhtTarget,
        reply: oneshot::Sender<Result<(), DhtEngineError>>,
    },
    /// Bootstrap: ping each entry (retrying
    /// [`crate::dht::engine::DhtEngineConfig::bootstrap_ping_retry`]
    /// times); the reply is the number of successful entries; on >=1 a
    /// node_lookup(self) + refresh are appended automatically
    /// (`DHTEntryPointNameResolveCommand.cc`).
    Bootstrap {
        entry_points: Vec<SocketAddr>,
        reply: oneshot::Sender<usize>,
    },
    /// PORT message receive side (`BtPortMessage.cc`; called by the peer
    /// layer after receiving Port{id=9}).
    AddPortNode { ip: IpAddr, dht_port: u16 },
    /// BEP42 external address delivery: the startup probe and later
    /// changes both arrive through this command; the engine re-derives
    /// node_id per libtorrent `node::update_node_id` (node.cpp) semantics
    /// (the current id is kept if it still verifies for the new address).
    /// See docs/design/dht.md, the security extensions section.
    SetExternalIp { ip: IpAddr },
    /// Runtime snapshot (observability/tests).
    Snapshot { reply: oneshot::Sender<DhtSnapshot> },
    /// Save and exit (halt-save semantics, `DHTAutoSaveCommand.cc`).
    Shutdown { reply: oneshot::Sender<()> },
}

/// Actor events (mpsc(64) -> engine/TorrentTask).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtEvent {
    /// Peers discovered by the get_peers iteration (may include our own
    /// record; consumers dedupe).
    PeersFound {
        /// 20B transport identifier (V1 = sha1; V2 = truncated sha256).
        info_hash: [u8; 20],
        face: DhtSwarmKind,
        peers: Vec<SocketAddr>,
    },
    /// autosave/halt: the `dht_state` row payload (family + node_id column +
    /// routing_table own-format BLOB) — persisted via the PersistWriter.
    Persist {
        family: persist::DhtFamily,
        node_id: [u8; 20],
        routing_table: Vec<u8>,
    },
}

/// Target of announce/get_peers (carries the BEP27 private-torrent gate).
///
/// Construction validates: private torrents are rejected (BEP27; the
/// conformance matrix "DHT/PEX/LSD forbidden" row) — callers (TorrentTask, core scope)
/// must build targets through this type, making private swarms unable to
/// enter DHT at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DhtTarget {
    pub(super) info_hash: [u8; 20],
    pub(super) face: DhtSwarmKind,
}

impl DhtTarget {
    /// Build a target; rejected when `is_private` is true (BEP27).
    pub fn new(
        info_hash: [u8; 20],
        face: DhtSwarmKind,
        is_private: bool,
    ) -> Result<Self, DhtEngineError> {
        if is_private {
            return Err(DhtEngineError::PrivateTorrentDisabled);
        }
        Ok(DhtTarget { info_hash, face })
    }

    /// BEP27 gate (equivalent entry for direct TorrentTask checks).
    pub const fn dht_allowed(is_private: bool) -> bool {
        !is_private
    }

    pub fn info_hash(&self) -> [u8; 20] {
        self.info_hash
    }

    pub fn face(&self) -> DhtSwarmKind {
        self.face
    }

    pub(super) fn target_id(&self) -> NodeId {
        NodeId(self.info_hash)
    }
}

/// Engine-level errors (as opposed to the message-layer
/// [`super::super::DhtError`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DhtEngineError {
    #[error("dht actor command channel closed")]
    Closed,
    /// BEP27: private torrents disable DHT.
    #[error("private torrent: DHT disabled (BEP27)")]
    PrivateTorrentDisabled,
    /// Announce port range matches the KRPC encoder (0 < p < 65535, same
    /// domain as `DHTMessageFactoryImpl.cc`).
    #[error("invalid announce port {0} (must satisfy 0 < port < 65535)")]
    InvalidPort(u16),
}

/// Engine runtime snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhtSnapshot {
    pub family: persist::DhtFamily,
    pub node_id: [u8; 20],
    pub dht_port: u16,
    pub num_nodes: usize,
    pub num_buckets: usize,
    pub transactions: usize,
    pub immediate_executing: usize,
    pub immediate_waiting: usize,
    pub periodic_executing: usize,
    pub periodic_waiting: usize,
    /// Auto-resend registry entry count.
    pub announce_entries: usize,
    /// Number of recorded (other-announced) info-hash keys.
    pub peer_record_keys: usize,
    /// Total peer records across keys (boundedness observability).
    pub peer_records_total: usize,
    /// Cumulative get_peers reply values truncations (anti-reflection
    /// amplification observability).
    pub values_truncated_total: u64,
    /// Announce-capable lookups started (resend observability).
    pub announce_lookups_started: u64,
    /// Outbound queries per kind (counting semantics in the same-named
    /// [`DhtEngine`] fields — fed where `send_query` enqueues outbound
    /// successfully; the kind domain is the four BEP5 kinds, message-name
    /// anchor [`crate::dht::message::MessageKind::method_name`]: ping /
    /// find_node / get_peers / announce_peer).
    pub queries_ping_total: u64,
    pub queries_find_node_total: u64,
    pub queries_get_peers_total: u64,
    pub queries_announce_peer_total: u64,
    /// Inbound packet counters (observability; counting-only, no
    /// control-flow reads them): every inbound datagram; the y="q" subset
    /// (decoded queries, before the per-source limiter); and the y="r"/e
    /// frames dropped by the early-drop gate for matching no pending
    /// transaction (the inbound hot-path attribution face).
    pub inbound_packets_total: u64,
    pub inbound_queries_total: u64,
    pub inbound_unmatched_drops_total: u64,
}

/// Restore state (the unified carrier for a `dht_state` row or an aria2
/// `dht.dat` import).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtRestoreState {
    pub node_id: NodeId,
    pub nodes: Vec<(NodeId, SocketAddr)>,
}

impl DhtRestoreState {
    /// Build from a `dht_state` row (node_id column + routing_table
    /// own-format BLOB). Decode failure -> Err (the caller logs and starts
    /// fresh, `DHTSetup.cc`).
    pub fn from_state_row(node_id: [u8; 20], blob: &[u8]) -> Result<Self, persist::StateBlobError> {
        let nodes = persist::decode_table(blob)?
            .into_iter()
            .map(|n| (n.id, n.addr))
            .collect();
        Ok(DhtRestoreState {
            node_id: NodeId(node_id),
            nodes,
        })
    }

    /// Build from aria2 `dht.dat` file bytes (`--dht-file-path[-6]`
    /// compatible import: used when the table is empty and the file
    /// exists; parse failure -> Err, the caller logs and skips).
    pub fn from_dht_dat(
        family: persist::DhtFamily,
        data: &[u8],
    ) -> Result<Self, persist::DhtDatError> {
        let dat = persist::parse_dht_dat(family, data)?;
        Ok(DhtRestoreState {
            node_id: dat.node_id,
            nodes: dat.nodes,
        })
    }
}

/// Transport endpoints: inbound from the dht channel; outbound enqueued as
/// [`OutboundPacket`] (sent by the bridge task / the demux single writer).
/// Tests connect with plain channels (no socket).
pub struct DhtTransport {
    pub inbound: mpsc::Receiver<InboundPacket>,
    pub outbound: mpsc::Sender<OutboundPacket>,
}

//! DHT / Kademlia (BEP5) protocol foundation (SPEC §6.7).
//!
//! # Scope
//!
//! Pure state-machine side, no network IO (integration is actor-based):
//!
//! - [`message`]: KRPC message types and codec (ping/find_node/get_peers/
//! announce_peer + response + error); bencode reuse of [`crate::bencode`];
//! - [`compact`]: compact peer (6B/18B) and compact node info (26B/38B)
//! codecs;
//! - [`node`]: node identity and state scoring (good/questionable/bad,
//! DHTNode semantics);
//! - [`routing_table`]: 160-bit distance K-bucket binary tree (DHTBucket/
//! DHTBucketTree/DHTRoutingTable semantics: LRS eviction, replacement
//! cache, bucket split, closest-K);
//! - [`transaction`]: transaction_id/(addr) -> oneshot table, 10s timeout
//! sweep;
//! - [`token`]: announce token generation/validation (two secrets; the
//! caller drives the 10min rotation window);
//! - [`task`]: tasks and the dual-queue executor (immediate+periodic, 15
//! concurrent each);
//! - [`persist`]: the `dht_state` own-format BLOB + aria2 `dht.dat`
//! compatible import;
//! - [`engine`]: the DhtEngine actor (one per family: inbound packet ->
//! message handling -> outbound, bootstrap, automatic maintenance timers,
//! PORT message wiring, v2/private gates).
//!
//! Protocol facts (constants and their aria2 anchors) and the intentional
//! divergence list vs the reference implementations are in
//! docs/design/dht.md ("Upstream anchor mapping"); none of the divergences
//! affect interoperability.

use thiserror::Error;

pub mod compact;
pub mod engine;
pub mod message;
pub mod node;
pub mod persist;
pub mod routing_table;
pub mod security;
pub mod task;
pub mod token;
pub mod transaction;

pub use compact::{
    NODE_INFO_LEN_V4, NODE_INFO_LEN_V6, NodeInfo, pack_node_info, pack_peer,
    unpack_node_infos_with_unit, unpack_peer,
};
pub use engine::{
    COMMAND_CHANNEL_CAPACITY, DEFAULT_BOOTSTRAP_NODES, DhtCommand, DhtEngineConfig, DhtEngineError,
    DhtEvent, DhtHandle, DhtRestoreState, DhtSnapshot, DhtTarget, DhtTransport,
    EVENT_CHANNEL_CAPACITY, MAINT_KINDS, MaintKind, forward_outbound, spawn as spawn_dht_engine,
};
pub use message::{
    DhtMessage, ErrorMessage, MessageKind, QueryBody, QueryMessage, ResponseBody, ResponseMessage,
    WantFamilies, decode_message, encode_message,
};
pub use node::{DHT_ID_LENGTH, DhtNode, NodeId};
pub use persist::{
    DhtDatError, DhtFamily, StateBlobError, decode_table, encode_table, parse_dht_dat,
};
pub use routing_table::{Bucket, K, RoutingTable};
pub use security::{
    crc32c, derive_node_id, generate_node_id, is_exempt_ip, probe_source_ip, verify_node_id,
};
pub use task::{ALPHA, DhtSwarmKind, LookupKind, NUM_CONCURRENT_TASK, QueueKind};
pub use token::TokenTracker;
pub use transaction::{
    DHT_MESSAGE_TIMEOUT, PendingTransaction, TransactionFailure, TransactionOutcome,
    TransactionTable,
};

/// DHT subsystem errors (codec / transaction / token).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DhtError {
    /// Underlying bencode error (passed through from the strict decoder).
    #[error("bencode: {0}")]
    Bencode(#[from] crate::bencode::BencodeError),
    /// Top-level KRPC value is not a dict (BEP5: every KRPC message is a
    /// single bencode dict).
    #[error("KRPC payload is not a bencode dict")]
    NotADict,
    /// Required field missing or of wrong type (mirrors aria2
    /// `DHTMessageFactoryImpl.cc` getDictionary/getString/getInteger).
    #[error("malformed DHT message: field `{field}` missing or of wrong type")]
    MalformedField { field: &'static str },
    /// ID field length != 20 (mirrors `DHTMessageFactoryImpl.cc`
    /// validateID).
    #[error("invalid id length for field `{field}`: expected {expected}, got {got}")]
    InvalidIdLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    /// announce_peer port out of range (mirrors `DHTMessageFactoryImpl.cc`
    /// validatePort: requires `0 < port < 65535`, so both 0 and 65535 are
    /// rejected).
    #[error("invalid announce port {port} (must satisfy 0 < port < 65535)")]
    InvalidPort { port: i64 },
    /// Query method name outside the BEP5 message set (mirrors
    /// `DHTMessageFactoryImpl.cc` "Unsupported message type").
    #[error("unsupported DHT query method {0:?}")]
    UnsupportedMethod(Vec<u8>),
    /// `y` is not "q"/"r"/"e" (mirrors `DHTMessageFactoryImpl.cc`).
    #[error("malformed DHT message: y != q/r/e")]
    MalformedY,
    /// nodes/nodes6 string length is not a multiple of the unit length
    /// (mirrors `DHTMessageFactoryImpl.cc` "Nodes length is not multiple
    /// of").
    #[error("nodes length {len} is not a multiple of {unit}")]
    NodesLength { len: usize, unit: usize },
    /// `values` present but `token` missing (the get_peers response token
    /// is a required field; mirrors `DHTMessageFactoryImpl.cc`
    /// getString(TOKEN)).
    #[error("`values` present but `token` missing in get_peers reply")]
    ValuesWithoutToken,
    /// Response body type does not match the pending transaction (aria2
    /// picks the parse branch by the transaction's message type,
    /// `DHTMessageTracker.cc`).
    #[error("response kind mismatch for expected {expected:?}")]
    ResponseKindMismatch {
        expected: crate::dht::message::MessageKind,
    },
    /// Compact peer string length is not 6/18 (BEP5; aria2
    /// `BtConstants.h`).
    #[error("compact peer length must be 6 or 18, got {got}")]
    CompactPeerLength { got: usize },
    /// A get_peers response values list mixes v4/v6 addresses and cannot be
    /// encoded compliantly: values is always a single key ("values6" is
    /// retired — BEP32 post-history "Drop values6."), and BEP32 forbids
    /// sending hybrid lists ("must not send hybrid lists",
    /// `message::pack_peer_values`); the sending family is filtered by the
    /// engine per the request's network layer, engine/wire.rs. `nodes` is
    /// not subject to this — split across the `nodes`/`nodes6` keys,
    /// `message::pack_nodes_split`.
    #[error("mixed IPv4/IPv6 addresses in one values list cannot be encoded")]
    MixedAddressFamilies,
    /// The reply frame exceeds the BEP32 1024-octet cap with nothing left
    /// to trim (e.g. a ping reply echoing an oversized tid) — better not
    /// to send than violate the cap ("A node obeying this specification
    /// must not send UDP datagrams with a payload larger than 1024
    /// octets").
    #[error("reply frame {len}B exceeds BEP32 1024-octet cap with nothing left to trim")]
    ReplyFrameTooLarge { len: usize },
    /// Duplicate registration on the same (transaction_id, addr) (this
    /// implementation applies replace semantics).
    #[error("duplicate transaction registration")]
    DuplicateTransaction,
}

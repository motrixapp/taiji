//! KRPC message types and codec (BEP5).
//!
//! Message model: the three top-level dict shapes (`y = "q"/"r"/"e"`), the
//! per-method `a`/`r` field sets of aria2's message classes, the optional
//! top-level `ip` field (BEP42 "Bootstrapping") and the optional client
//! version `v` field. Response bodies are decoded by content sniffing and
//! checked against the expected kind via [`ResponseBody::as_kind`].
//!
//! Mechanism summary:
//! - Encoding emits canonical bencode (keys sorted ascending by [`dict`]);
//!   strict decoding rejects out-of-order keys, so `encode(decode(x)) == x`
//!   does not hold (unknown fields are projected away); the roundtrip
//!   invariant is `decode(encode(m)) == m`.
//! - find_node replies always carry a nodes-family key (possibly empty);
//!   get_peers replies write `nodes`/`nodes6`/`values` only when non-empty.
//! - `values` is always a single key of single-family compact units (BEP32);
//!   hybrid lists are forbidden on send, mandatory to parse on receive.
//! - Mixed-family node lists split into `nodes` (v4) + `nodes6` (v6) per the
//!   BEP32 want reply shape; decoding merges both keys, v4 entries first.
//! - Strict field validation: 20-byte ids, `0 < port < 65535`, known-field
//!   types enforced; unknown `want` entries silently ignored (BEP32).
//!
//! Upstream anchor mapping: docs/design/dht.md

use std::net::SocketAddr;

use crate::bencode::{self, Value};

use super::compact::{
    COMPACT_LEN_IPV4, COMPACT_LEN_IPV6, NODE_INFO_LEN_V4, NODE_INFO_LEN_V6, NodeInfo,
    pack_node_info, pack_peer, unpack_node_infos_with_unit, unpack_peer,
};
use super::{DHT_ID_LENGTH, DhtError, NodeId};

/// Transaction ID byte length as generated locally. Upstream: aria2
/// `src/DHTConstants.h`.
pub const DHT_TRANSACTION_ID_LENGTH: usize = 4;

// BEP5 KRPC error codes (BEP5 "Errors" section; aria2 only parses error
// messages, never generates them; see DHTMessageFactoryImpl.cc).
/// Generic error (201). This implementation has no wire trigger for 201:
/// overload is handled by silent per-source rate limiting (see the module
/// docs and [`incoming_error_reply`]). Kept only so the BEP5 example error
/// message can be encoded in tests.
pub const ERROR_GENERIC: i64 = 201;
/// Protocol error (malformed packet, invalid token, ...).
pub const ERROR_PROTOCOL: i64 = 203;
/// Method unknown.
pub const ERROR_METHOD_UNKNOWN: i64 = 204;

// Fixed phrases for server error replies: short, fixed, and free of
// peer-controlled content. Echoing the peer's message bytes in `msg` would
// extend the reflection surface from reply metadata to attacker text
// (libtorrent echoes the verify_message dynamic string; this implementation
// is more conservative). The wording matches the BEP5 code descriptions.
/// Fixed msg for [`ERROR_PROTOCOL`].
pub const ERROR_MSG_PROTOCOL: &[u8] = b"Protocol Error";
/// Fixed msg for [`ERROR_METHOD_UNKNOWN`].
pub const ERROR_MSG_METHOD_UNKNOWN: &[u8] = b"Method Unknown";

/// KRPC query method names (BEP5 message set; aria2 constants live in
/// `DHTPingMessage.cc`, `DHTFindNodeMessage.cc`, `DHTGetPeersMessage.cc`,
/// `DHTAnnouncePeerMessage.cc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    Ping,
    FindNode,
    GetPeers,
    AnnouncePeer,
}

impl MessageKind {
    pub fn method_name(&self) -> &'static str {
        match self {
            MessageKind::Ping => "ping",
            MessageKind::FindNode => "find_node",
            MessageKind::GetPeers => "get_peers",
            MessageKind::AnnouncePeer => "announce_peer",
        }
    }

    fn from_method_name(name: &[u8]) -> Option<Self> {
        match name {
            b"ping" => Some(MessageKind::Ping),
            b"find_node" => Some(MessageKind::FindNode),
            b"get_peers" => Some(MessageKind::GetPeers),
            b"announce_peer" => Some(MessageKind::AnnouncePeer),
            _ => None,
        }
    }
}

/// Address-family set of the BEP32 `want` parameter (optional in
/// find_node/get_peers queries).
///
/// BEP32 text (bittorrent.org/beps/bep_0032.html): "The "want" parameter
/// is allowed in the find_nodes and get_peers requests, and governs
/// the presence or absence of the "nodes" and "nodes6" parameters in
/// the requested reply". Both flags false = the parameter is absent (or
/// present without a recognized value); the reply then carries a single
/// key for the request's network layer ("In the absence of a "want"
/// parameter, the reply should include "nodes" if the request was sent
/// over IPv4, and should include "nodes6" if the request was sent over
/// IPv6"). That fallback is decided by the engine (the codec does not
/// see the request face).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WantFamilies {
    /// "n4": request the `nodes` key (v4 nodes).
    pub v4: bool,
    /// "n6": request the `nodes6` key (v6 nodes).
    pub v6: bool,
}

impl WantFamilies {
    /// Request both stacks (local outbound policy: the peer returns both
    /// families in one frame, so the v6 table can learn v6 nodes through v4
    /// routes and vice versa; single-stack outbound still filters candidates
    /// by engine family, see engine/tasks.rs).
    pub const BOTH: Self = Self { v4: true, v6: true };

    /// Single v4 family (`want = ["n4"]`).
    pub fn single_v4() -> Self {
        Self {
            v4: true,
            v6: false,
        }
    }

    /// Single v6 family (`want = ["n6"]`).
    pub fn single_v6() -> Self {
        Self {
            v4: false,
            v6: true,
        }
    }

    /// Whether any family was requested (false = absent semantics, fallback to the request family).
    pub fn any(self) -> bool {
        self.v4 || self.v6
    }

    /// Whether the address family was requested (reply-side nodes filter).
    pub fn accepts(self, addr: &SocketAddr) -> bool {
        if addr.is_ipv4() { self.v4 } else { self.v6 }
    }
}

/// KRPC query (`y = "q"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMessage {
    /// Peer transaction id (unbounded on decode, see module docs; locally generated ids are 4B).
    pub transaction_id: Vec<u8>,
    /// `a.id` (sender node ID, 20B).
    pub sender_id: NodeId,
    pub body: QueryBody,
    /// Optional client version `v` (raw bytes).
    pub version: Option<Vec<u8>>,
}

/// Query method and parameters (the method-specific fields of the `a` dict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryBody {
    Ping,
    FindNode {
        target: NodeId,
        /// BEP32 optional `want` (absent = all false; see the [`WantFamilies`]
        /// docs for the decode/encode rules).
        want: WantFamilies,
    },
    GetPeers {
        info_hash: NodeId,
        /// BEP32 optional `want` (same as above).
        want: WantFamilies,
    },
    /// `implied_port`: optional BEP5 field (0/1; when 1 the receiver replaces
    /// `port` with the UDP source port — the engine applies that; the codec
    /// only carries it). aria2 never parses the field
    /// (`DHTMessageFactoryImpl.cc`) and validates the port domain
    /// unconditionally (`validatePort`: `0 < p < 65535`), so port=0/65535 is
    /// rejected even when implied_port=1; this implementation matches. This
    /// implementation accepts and validates implied_port in {0,1} per BEP5.
    AnnouncePeer {
        info_hash: NodeId,
        port: u16,
        token: Vec<u8>,
        implied_port: Option<bool>,
    },
}

/// KRPC response (`y = "r"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseMessage {
    pub transaction_id: Vec<u8>,
    /// `r.id` (responder node ID, 20B).
    pub responder_id: NodeId,
    pub body: ResponseBody,
    /// Top-level `ip` field (BEP42 "Bootstrapping"): the responder echoes back
    /// the requester's endpoint as observed by the responder, encoded as a
    /// big-endian compact endpoint (v4 6B / v6 18B, same layout as
    /// [`pack_peer`]). None = absent (local replies always carry it; decode
    /// yields None when the peer's frame lacks the field or its length is not
    /// 6/18B). Lets the requester learn its externally observed address
    /// (consumed by BEP42 id derivation / re-derivation voting, see the
    /// security.rs module docs).
    pub requester_endpoint: Option<SocketAddr>,
    pub version: Option<Vec<u8>>,
}

/// Response body (content-sniffed, context-free; see
/// [`ResponseBody::as_kind`] for the kind check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseBody {
    /// id-only (ping and announce_peer responses are byte-identical, BEP5).
    Ping,
    FindNode {
        nodes: Vec<NodeInfo>,
    },
    GetPeers {
        token: Vec<u8>,
        nodes: Vec<NodeInfo>,
        values: Vec<SocketAddr>,
    },
}

impl ResponseBody {
    /// Check and convert by the message type the transaction expects (aria2
    /// selects the parse branch from the type recorded in its transaction
    /// table, `DHTMessageTracker.cc` → `DHTMessageFactoryImpl.cc`). An
    /// id-only body is valid for both ping and announce_peer; any other
    /// mismatch is an error.
    pub fn as_kind(&self, expected: MessageKind) -> Result<&Self, DhtError> {
        let compatible = matches!(
            (expected, self),
            (MessageKind::Ping, ResponseBody::Ping)
                | (MessageKind::AnnouncePeer, ResponseBody::Ping)
                | (MessageKind::FindNode, ResponseBody::FindNode { .. })
                | (MessageKind::GetPeers, ResponseBody::GetPeers { .. })
        );
        if compatible {
            Ok(self)
        } else {
            Err(DhtError::ResponseKindMismatch { expected })
        }
    }
}

/// KRPC error (`y = "e"`, `e = [code, msg]`, BEP5 "Errors").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    pub transaction_id: Vec<u8>,
    pub code: i64,
    pub message: Vec<u8>,
    pub version: Option<Vec<u8>>,
}

/// Any KRPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtMessage {
    Query(QueryMessage),
    Response(ResponseMessage),
    Error(ErrorMessage),
}

impl DhtMessage {
    /// Message transaction id (common to all three kinds).
    pub fn transaction_id(&self) -> &[u8] {
        match self {
            DhtMessage::Query(m) => &m.transaction_id,
            DhtMessage::Response(m) => &m.transaction_id,
            DhtMessage::Error(m) => &m.transaction_id,
        }
    }
}

// ===== Encoding =====

/// Encode a KRPC message as canonical bencode (key order handled by the
/// shared sort; field set matches aria2's per-message
/// `getBencodedMessage()`, `DHTAbstractMessage.cc`: t, y, v?, plus q/a
/// for queries, r for responses, e for errors).
pub fn encode_message(msg: &DhtMessage) -> Result<Vec<u8>, DhtError> {
    let top = match msg {
        DhtMessage::Query(m) => {
            let a = match &m.body {
                QueryBody::Ping => dict(vec![("id", Value::Bytes(m.sender_id.0.to_vec()))]),
                QueryBody::FindNode { target, want } => {
                    let mut fields = vec![
                        ("id", Value::Bytes(m.sender_id.0.to_vec())),
                        ("target", Value::Bytes(target.0.to_vec())),
                    ];
                    push_want(&mut fields, *want);
                    dict(fields)
                }
                QueryBody::GetPeers { info_hash, want } => {
                    let mut fields = vec![
                        ("id", Value::Bytes(m.sender_id.0.to_vec())),
                        ("info_hash", Value::Bytes(info_hash.0.to_vec())),
                    ];
                    push_want(&mut fields, *want);
                    dict(fields)
                }
                QueryBody::AnnouncePeer {
                    info_hash,
                    port,
                    token,
                    implied_port,
                } => {
                    // Encode-side domain guard: same acceptance domain as the decode-side
                    // validatePort (DHTMessageFactoryImpl.cc, 0<p<65535), so the encoder never
                    // produces a message its own decoder would reject (same stance as
                    // bencode::encode rejecting out-of-order keys; strict validation stays).
                    if !(1..u16::MAX).contains(port) {
                        return Err(DhtError::InvalidPort {
                            port: i64::from(*port),
                        });
                    }
                    let mut fields = vec![
                        ("id", Value::Bytes(m.sender_id.0.to_vec())),
                        ("info_hash", Value::Bytes(info_hash.0.to_vec())),
                        ("port", Value::Int(i64::from(*port))),
                        ("token", Value::Bytes(token.clone())),
                    ];
                    if let Some(imp) = implied_port {
                        fields.push(("implied_port", Value::Int(i64::from(*imp))));
                    }
                    dict(fields)
                }
            };
            top_level_dict(
                vec![
                    ("a", a),
                    ("q", Value::Bytes(q_name(&m.body).as_bytes().to_vec())),
                ],
                &m.transaction_id,
                b"q",
                m.version.as_deref(),
            )
        }
        DhtMessage::Response(m) => return encode_response(m),
        DhtMessage::Error(m) => {
            let e = Value::List(vec![Value::Int(m.code), Value::Bytes(m.message.clone())]);
            top_level_dict(
                vec![("e", e)],
                &m.transaction_id,
                b"e",
                m.version.as_deref(),
            )
        }
    };
    Ok(bencode::encode(&top)?)
}

/// Response encoding (the `DhtMessage::Response` arm of [`encode_message`],
/// extracted so the BEP32 frame gate's trim loop can re-encode from a
/// borrow without cloning the message per step — the inbound
/// hot-path shape;
/// byte-identical output to the arm it was lifted from).
pub(crate) fn encode_response(m: &ResponseMessage) -> Result<Vec<u8>, DhtError> {
    let r = match &m.body {
        ResponseBody::Ping => dict(vec![("id", Value::Bytes(m.responder_id.0.to_vec()))]),
        // find_node replies always write a nodes-family key (possibly empty;
        // aria2 DHTFindNodeReplyMessage.cc puts unconditionally). BEP32 want
        // dual-key shape: v4 subset → nodes, v6 subset → nodes6 (each key only
        // when its subset is non-empty); an all-empty list keeps the single
        // empty-string key: after the engine filters by want, an empty set only
        // occurs as "no nodes in the request family", and an empty v4 key is
        // byte-identical to the pre-BEP32 single-family form.
        ResponseBody::FindNode { nodes } => {
            let (v4, v6) = pack_nodes_split(nodes);
            let mut fields = vec![("id", Value::Bytes(m.responder_id.0.to_vec()))];
            match (v4, v6) {
                (Some(b4), Some(b6)) => {
                    fields.push(("nodes", Value::Bytes(b4)));
                    fields.push(("nodes6", Value::Bytes(b6)));
                }
                (Some(b4), None) => fields.push(("nodes", Value::Bytes(b4))),
                (None, Some(b6)) => fields.push(("nodes6", Value::Bytes(b6))),
                (None, None) => fields.push(("nodes", Value::Bytes(Vec::new()))),
            }
            dict(fields)
        }
        // get_peers replies: nodes/values written only when non-empty (aria2
        // DHTGetPeersReplyMessage.cc; the dual-key shape applies the same per-key
        // rule: each family's key only when its subset is non-empty). values is
        // always a single key of single-family 6B/18B compact units (BEP32; mixed
        // families are an error, and the family sent is filtered by the engine per
        // the request's network layer — want does not govern values: BEP32 only
        // "governs ... the "nodes" and "nodes6" parameters").
        ResponseBody::GetPeers {
            token,
            nodes,
            values,
        } => {
            let mut fields = vec![
                ("id", Value::Bytes(m.responder_id.0.to_vec())),
                ("token", Value::Bytes(token.clone())),
            ];
            let (v4, v6) = pack_nodes_split(nodes);
            if let Some(b4) = v4 {
                fields.push(("nodes", Value::Bytes(b4)));
            }
            if let Some(b6) = v6 {
                fields.push(("nodes6", Value::Bytes(b6)));
            }
            if !values.is_empty() {
                let items = pack_peer_values(values)?
                    .into_iter()
                    .map(Value::Bytes)
                    .collect();
                fields.push(("values", Value::List(items)));
            }
            dict(fields)
        }
    };
    Ok(bencode::encode(&top_level_dict(
        response_top_fields(m, r),
        &m.transaction_id,
        b"r",
        m.version.as_deref(),
    ))?)
}

/// Response top-level field assembly: the `r` dict plus the optional
/// BEP42 top-level `ip` compact endpoint (see
/// [`ResponseMessage::requester_endpoint`]). `ip` sits at top level, not
/// inside `r` — BEP42: "It is important that the ip field is in the top
/// level dictionary"; key order ip < r is guaranteed by the [`dict`]
/// sort.
fn response_top_fields(m: &ResponseMessage, r: Value) -> Vec<(&'static str, Value)> {
    let mut fields = vec![("r", r)];
    if let Some(ep) = m.requester_endpoint {
        let mut bytes = Vec::with_capacity(COMPACT_LEN_IPV6);
        pack_peer(ep, &mut bytes);
        fields.push(("ip", Value::Bytes(bytes)));
    }
    fields
}

/// Shared top-level assembly for all three message kinds
/// (`DHTAbstractMessage.cc`: t, y, v?; the caller supplies the body key
/// a/q/r/e and its fields). Canonical ascending order is enforced by the
/// [`dict`] sort; field insertion order does not affect wire bytes.
fn top_level_dict(
    mut body_fields: Vec<(&'static str, Value)>,
    transaction_id: &[u8],
    kind: &[u8],
    version: Option<&[u8]>,
) -> Value {
    body_fields.push(("t", Value::Bytes(transaction_id.to_vec())));
    body_fields.push(("y", Value::Bytes(kind.to_vec())));
    if let Some(v) = version {
        body_fields.push(("v", Value::Bytes(v.to_vec())));
    }
    dict(body_fields)
}

fn q_name(body: &QueryBody) -> &'static str {
    match body {
        QueryBody::Ping => MessageKind::Ping.method_name(),
        QueryBody::FindNode { .. } => MessageKind::FindNode.method_name(),
        QueryBody::GetPeers { .. } => MessageKind::GetPeers.method_name(),
        QueryBody::AnnouncePeer { .. } => MessageKind::AnnouncePeer.method_name(),
    }
}

/// Encode the BEP32 `want` key (only the find_node/get_peers bodies call
/// this): absent (empty set) writes no key; element order is fixed
/// n4 → n6 (BEP32 imposes no order; the fixed order makes the encoded
/// bytes deterministic; set semantics deduplicate naturally).
fn push_want(fields: &mut Vec<(&'static str, Value)>, want: WantFamilies) {
    if !want.any() {
        return;
    }
    let mut items = Vec::with_capacity(2);
    if want.v4 {
        items.push(Value::Bytes(b"n4".to_vec()));
    }
    if want.v6 {
        items.push(Value::Bytes(b"n6".to_vec()));
    }
    fields.push(("want", Value::List(items)));
}

/// Mixed-family guard (values only; nodes uses dual-key splitting): a
/// values list mixing v4/v6 → [`DhtError::MixedAddressFamilies`] (BEP32
/// forbids sending hybrid values lists and the key cannot be split by
/// family — "values6" was dropped, see the module docs). On success
/// returns whether all entries are v6 (empty list → false, the v4
/// convention).
fn require_single_family(
    addrs: impl ExactSizeIterator<Item = SocketAddr>,
) -> Result<bool, DhtError> {
    let total = addrs.len();
    let v6_count = addrs.filter(SocketAddr::is_ipv6).count();
    if v6_count != 0 && v6_count != total {
        return Err(DhtError::MixedAddressFamilies);
    }
    Ok(v6_count > 0)
}

/// Pack nodes and split by address family into the BEP32 want dual-key
/// payloads: the v4 subset (26B units, order preserved) becomes the
/// `nodes` payload and the v6 subset (38B units, order preserved) the
/// `nodes6` payload; an empty subset → None (whether an empty key is
/// written is decided per response body: find_node always writes,
/// get_peers only when non-empty, see [`encode_message`]). Mixed-family
/// lists are no longer rejected — dual-key replies to a peer's
/// want=[n4,n6] request are the norm (aria2's single-key shape in
/// `DHTFindNodeReplyMessage.cc` is the single-family special case).
fn pack_nodes_split(nodes: &[NodeInfo]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let v4_count = nodes.iter().filter(|n| n.addr.is_ipv4()).count();
    let mut v4 = Vec::with_capacity(v4_count * NODE_INFO_LEN_V4);
    let mut v6 = Vec::with_capacity((nodes.len() - v4_count) * NODE_INFO_LEN_V6);
    for n in nodes {
        if n.addr.is_ipv4() {
            pack_node_info(n, &mut v4);
        } else {
            pack_node_info(n, &mut v6);
        }
    }
    let v4 = (!v4.is_empty()).then_some(v4);
    let v6 = (!v6.is_empty()).then_some(v6);
    (v4, v6)
}

/// Pack the get_peers values list (one compact string per peer, BEP5
/// "compact peer"): all v4 → 6B each, all v6 → 18B each. BEP32
/// "Changes to get_peers": "a list of 6-octet strings if the request was
/// sent over IPv4, and a list of 18-octet strings if the request was sent
/// over IPv6". Hybrid families are a forbidden send shape
/// ("implementations should not send such hybrid lists...") and yield
/// [`DhtError::MixedAddressFamilies`]. The key is never split by family —
/// "values6" was dropped by the BEP32 Post-History ("15-Oct-2009: ...
/// Drop values6."). Which family is sent is chosen by the engine
/// filtering per the request's network layer (engine/wire.rs; libtorrent
/// `dht_storage.cpp`).
fn pack_peer_values(values: &[SocketAddr]) -> Result<Vec<Vec<u8>>, DhtError> {
    let all_v6 = require_single_family(values.iter().copied())?;
    let unit = if all_v6 {
        COMPACT_LEN_IPV6
    } else {
        COMPACT_LEN_IPV4
    };
    let mut out = Vec::with_capacity(values.len());
    for a in values {
        let mut buf = Vec::with_capacity(unit);
        pack_peer(*a, &mut buf);
        out.push(buf);
    }
    Ok(out)
}

// ===== Decoding =====

/// Decode a KRPC message (strict canonical bencode, see the module docs
/// divergence list).
///
/// Validation rules mirror aria2 `DHTMessageFactoryImpl.cc` rule by rule
/// (anchors in branch comments); violations return [`DhtError`] and
/// callers drop under UDP best-effort semantics (aria2
/// `DHTMessageReceiver.cc` catches and treats as unknown message).
pub fn decode_message(data: &[u8]) -> Result<DhtMessage, DhtError> {
    let value = bencode::decode(data)?;
    let dict = value.as_dict().ok_or(DhtError::NotADict)?;
    let transaction_id = get_bytes(dict, b"t")?.to_vec();
    let version = get_opt_bytes(dict, b"v")?.map(<[u8]>::to_vec);
    let y = get_bytes(dict, b"y")?;
    match y {
        b"q" => Ok(DhtMessage::Query(decode_query(
            dict,
            transaction_id,
            version,
        )?)),
        b"r" => Ok(DhtMessage::Response(decode_response(
            dict,
            transaction_id,
            version,
        )?)),
        b"e" => Ok(DhtMessage::Error(decode_error(
            dict,
            transaction_id,
            version,
        )?)),
        // aria2: the query path errors on y != q; the response path errors on
        // y != r (DHTMessageFactoryImpl.cc).
        _ => Err(DhtError::MalformedY),
    }
}

fn decode_query(
    dict: &[(Vec<u8>, Value)],
    transaction_id: Vec<u8>,
    version: Option<Vec<u8>>,
) -> Result<QueryMessage, DhtError> {
    // q: string (getString, DHTMessageFactoryImpl.cc).
    let q = get_bytes(dict, b"q")?;
    // a: dict (getDictionary, DHTMessageFactoryImpl.cc).
    let a = get_dict(dict, b"a")?;
    // a.id: 20B (validateID, DHTMessageFactoryImpl.cc).
    let sender_id = get_id(a, "id")?;
    let method =
        MessageKind::from_method_name(q).ok_or_else(|| DhtError::UnsupportedMethod(q.to_vec()))?;
    let body = match method {
        MessageKind::Ping => QueryBody::Ping,
        // target: 20B; want: BEP32 optional (see parse_want).
        MessageKind::FindNode => QueryBody::FindNode {
            target: get_id(a, "target")?,
            want: parse_want(a)?,
        },
        // info_hash: 20B; want as above.
        MessageKind::GetPeers => QueryBody::GetPeers {
            info_hash: get_id(a, "info_hash")?,
            want: parse_want(a)?,
        },
        // info_hash: 20B; port: 0 < p < 65535 (validatePort,
        // DHTMessageFactoryImpl.cc); token: string.
        MessageKind::AnnouncePeer => {
            let implied_port = match get_opt_int(a, b"implied_port")? {
                None => None,
                Some(0) => Some(false),
                Some(1) => Some(true),
                Some(_) => {
                    return Err(DhtError::MalformedField {
                        field: "implied_port",
                    });
                }
            };
            QueryBody::AnnouncePeer {
                info_hash: get_id(a, "info_hash")?,
                port: get_announce_port(a)?,
                token: get_bytes(a, b"token")?.to_vec(),
                implied_port,
            }
        }
    };
    Ok(QueryMessage {
        transaction_id,
        sender_id,
        body,
        version,
    })
}

fn decode_response(
    dict: &[(Vec<u8>, Value)],
    transaction_id: Vec<u8>,
    version: Option<Vec<u8>>,
) -> Result<ResponseMessage, DhtError> {
    // r: dict (getDictionary, DHTMessageFactoryImpl.cc).
    let r = get_dict(dict, b"r")?;
    // r.id: 20B (DHTMessageFactoryImpl.cc).
    let responder_id = get_id(r, "id")?;
    // Top-level ip (BEP42 "Bootstrapping"; encoding in
    // [`ResponseMessage::requester_endpoint`]): missing → None; 6B/18B
    // compact endpoint → Some. A length other than 6/18B: the field is
    // ignored without failing the frame (libtorrent's inbound read is
    // similarly lenient — node.cpp `incoming` takes the leading address bytes
    // when `string_length() >= address_size(v4/v6)` rather than checking
    // exact length); a non-string type → MalformedField (known field types
    // are strict, same policy as v/implied_port).
    let requester_endpoint = match get_opt_bytes(dict, b"ip")? {
        None => None,
        Some(b) => unpack_peer(b).ok(),
    };
    // Response body sniffing (see module docs): token present → get_peers
    // (token is a required string; aria2's getString throws on absence).
    if let Some(token) = get_opt_bytes(r, b"token")? {
        let nodes = parse_optional_nodes(r)?;
        return Ok(ResponseMessage {
            transaction_id,
            responder_id,
            body: ResponseBody::GetPeers {
                token: token.to_vec(),
                nodes,
                values: parse_values(r)?,
            },
            requester_endpoint,
            version,
        });
    }
    // values present but token missing: token is required in get_peers replies; reject strictly.
    if has_key(r, b"values") {
        return Err(DhtError::ValuesWithoutToken);
    }
    // nodes/nodes6 present → find_node (dual keys coexisting is legal — the
    // normal reply to a BEP32 want=[n4,n6] request; parse_optional_nodes
    // merges both keys, so AmbiguousNodes no longer applies).
    if has_key(r, b"nodes") || has_key(r, b"nodes6") {
        let nodes = parse_optional_nodes(r)?;
        return Ok(ResponseMessage {
            transaction_id,
            responder_id,
            body: ResponseBody::FindNode { nodes },
            requester_endpoint,
            version,
        });
    }
    // Otherwise → id-only (ping/announce_peer are byte-identical).
    Ok(ResponseMessage {
        transaction_id,
        responder_id,
        body: ResponseBody::Ping,
        requester_endpoint,
        version,
    })
}

fn decode_error(
    dict: &[(Vec<u8>, Value)],
    transaction_id: Vec<u8>,
    version: Option<Vec<u8>>,
) -> Result<ErrorMessage, DhtError> {
    // e: list (getList, DHTMessageFactoryImpl.cc).
    let e = match lookup(dict, b"e") {
        Some(Value::List(l)) => l,
        _ => return Err(DhtError::MalformedField { field: "e" }),
    };
    // Exactly two elements [code, msg] (aria2 also rejects other lengths).
    if e.len() != 2 {
        return Err(DhtError::MalformedField { field: "e" });
    }
    let code = e[0]
        .as_int()
        .ok_or(DhtError::MalformedField { field: "e" })?;
    let message = e[1]
        .as_bytes()
        .ok_or(DhtError::MalformedField { field: "e" })?
        .to_vec();
    Ok(ErrorMessage {
        transaction_id,
        code,
        message,
        version,
    })
}

/// Parse the optional nodes/nodes6 pair (dual keys coexisting is legal
/// per BEP32: the normal reply to a want=[n4,n6] request — merged in
/// canonical order with v4 entries (nodes key, 26B units) first and v6
/// entries (nodes6 key, 38B units) after; the inverse of the
/// order-preserving encode-side split). A string length that is not a
/// unit multiple → [`DhtError::NodesLength`]
/// (`DHTMessageFactoryImpl.cc`); a non-string key type → MalformedField
/// (known field types are strict).
fn parse_optional_nodes(r: &[(Vec<u8>, Value)]) -> Result<Vec<NodeInfo>, DhtError> {
    let mut nodes = match lookup(r, b"nodes") {
        None => Vec::new(),
        Some(Value::Bytes(b)) => unpack_node_infos_with_unit(b, NODE_INFO_LEN_V4)?,
        Some(_) => return Err(DhtError::MalformedField { field: "nodes" }),
    };
    match lookup(r, b"nodes6") {
        None => {}
        Some(Value::Bytes(b)) => nodes.extend(unpack_node_infos_with_unit(b, NODE_INFO_LEN_V6)?),
        Some(_) => return Err(DhtError::MalformedField { field: "nodes6" }),
    }
    Ok(nodes)
}

/// Parse the BEP32 want (optional a-dict key of find_node/get_peers).
/// Elements other than "n4"/"n6" (including non-string elements) are
/// silently ignored — "For future extensibility, other strings may be
/// present in the list, and must be silently ignored on reception"; a
/// non-list key → MalformedField (known field types are strict, same
/// policy as v/implied_port); absent or no recognized value → the empty
/// set (absent semantics; the reply falls back to the request family,
/// decided by the engine).
fn parse_want(a: &[(Vec<u8>, Value)]) -> Result<WantFamilies, DhtError> {
    match lookup(a, b"want") {
        None => Ok(WantFamilies::default()),
        Some(Value::List(list)) => {
            let mut want = WantFamilies::default();
            for item in list {
                if let Value::Bytes(b) = item {
                    match b.as_slice() {
                        b"n4" => want.v4 = true,
                        b"n6" => want.v6 = true,
                        // Unknown strings / non-string elements: silently ignored (BEP32 forward-extension domain).
                        _ => {}
                    }
                }
            }
            Ok(want)
        }
        Some(_) => Err(DhtError::MalformedField { field: "want" }),
    }
}

/// Parse the get_peers values list: elements that are not strings or not
/// a compact length (6/18) are skipped (aria2 `DHTMessageFactoryImpl.cc`
/// filters per element on `size == clen`). Hybrid 6/18B lists must parse
/// — BEP32 "Changes to get_peers" mandates it ("must be able to properly
/// parse hybrid "values" lists"), preserving interop with legacy peers
/// that send mixed lists. The send/receive asymmetry is BEP32's explicit
/// rule: receivers parse hybrid lists, senders must not send them.
/// Missing key → empty list; key present but not a list → error (strict;
/// aria2 would silently ignore).
fn parse_values(r: &[(Vec<u8>, Value)]) -> Result<Vec<SocketAddr>, DhtError> {
    match lookup(r, b"values") {
        None => Ok(Vec::new()),
        Some(Value::List(list)) => {
            let mut out = Vec::with_capacity(list.len());
            for item in list {
                if let Value::Bytes(b) = item
                    && let Ok(addr) = unpack_peer(b)
                {
                    out.push(addr);
                }
            }
            Ok(out)
        }
        Some(_) => Err(DhtError::MalformedField { field: "values" }),
    }
}

// ===== Inbound hot-path header scan =====

/// Early-drop header scan (inbound hot path): locate the top-level `t` and
/// `y` **string** values of a KRPC frame without building the decoded tree.
///
/// Purpose: an inbound y="r"/y="e" packet whose (t, addr) matches no
/// pending transaction is droppable before the full bencode decode — the
/// decode-then-pop path's pop-None arm is also a silent drop, so the
/// observable outcome is identical while the per-packet work shrinks to a
/// linear skip-walk over the frame (no allocations; values of uninteresting
/// keys are jumped over, not parsed). This is a pure fast path, **not** a
/// validator:
///
/// - The scanner is lenient (it never rejects); on any anomaly (not a dict,
///   a truncated token, nesting deeper than [`bencode::MAX_DEPTH`], a
///   captured key whose value is not a string) it returns `None` and the
///   caller falls back to the full strict decode — malformed-input
///   handling (including the y="q" 203/204 error-reply classification) is
///   unchanged and stays on the strict path.
/// - With both keys found the returned slices borrow `data` (zero-copy);
///   a duplicate key keeps the first occurrence (strict decode would reject
///   the frame anyway; the gate only drops packets that were heading for a
///   silent drop regardless).
pub(crate) fn scan_transaction_header(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut pos = 0usize;
    if data.first() != Some(&b'd') {
        return None;
    }
    pos += 1;
    let mut tid: Option<&[u8]> = None;
    let mut y: Option<&[u8]> = None;
    loop {
        match data.get(pos) {
            Some(b'e') => {
                return match (tid, y) {
                    (Some(t), Some(y)) => Some((t, y)),
                    _ => None,
                };
            }
            Some(b'0'..=b'9') => {
                let (key, after_key) = scan_string(data, pos)?;
                pos = after_key;
                let capture = match key {
                    b"t" if tid.is_none() => Some(&mut tid),
                    b"y" if y.is_none() => Some(&mut y),
                    _ => None,
                };
                match capture {
                    Some(slot) => {
                        let is_string = matches!(data.get(pos), Some(b'0'..=b'9'));
                        let (value, after_value) = scan_string(data, pos)?;
                        if !is_string {
                            // t/y present but not a string: leave the
                            // decision to the strict decoder (MalformedField).
                            return None;
                        }
                        *slot = Some(value);
                        pos = after_value;
                    }
                    None => pos = skip_value(data, pos, 1)?,
                }
            }
            _ => return None,
        }
    }
}

/// Scans `<len>:<bytes>` at `pos`; returns (payload slice, position after
/// the payload). No strictness checks beyond well-formedness of the length
/// prefix and the payload being in bounds (strict-canonical validation of
/// leading zeros etc. belongs to the strict decoder).
fn scan_string(data: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let mut p = pos;
    let digits_start = p;
    while matches!(data.get(p), Some(b'0'..=b'9')) {
        p += 1;
    }
    if p == digits_start || data.get(p) != Some(&b':') {
        return None;
    }
    let mut len: u64 = 0;
    for &d in &data[digits_start..p] {
        len = len
            .checked_mul(10)
            .and_then(|l| l.checked_add(u64::from(d - b'0')))?;
    }
    p += 1; // ':'
    let len = usize::try_from(len).ok()?;
    let end = p.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((&data[p..end], end))
}

/// Jumps over one bencode value of any type at `pos` (no allocation, no
/// semantic validation); returns the position after it. `depth` guards the
/// same nesting bound as the strict parser.
fn skip_value(data: &[u8], pos: usize, depth: usize) -> Option<usize> {
    if depth > bencode::MAX_DEPTH {
        return None;
    }
    match data.get(pos).copied()? {
        b'0'..=b'9' => scan_string(data, pos).map(|(_, end)| end),
        b'i' => {
            let mut p = pos + 1;
            loop {
                match data.get(p).copied()? {
                    b'e' => return Some(p + 1),
                    b'-' | b'0'..=b'9' => p += 1,
                    _ => return None,
                }
            }
        }
        b'l' => {
            let mut p = pos + 1;
            loop {
                match data.get(p).copied()? {
                    b'e' => return Some(p + 1),
                    // List elements are bare values (ints/lists/dicts too,
                    // not only strings).
                    _ => p = skip_value(data, p, depth + 1)?,
                }
            }
        }
        b'd' => {
            let mut p = pos + 1;
            loop {
                match data.get(p).copied()? {
                    b'e' => return Some(p + 1),
                    b'0'..=b'9' => {
                        let (_, after_key) = scan_string(data, p)?;
                        p = skip_value(data, after_key, depth + 1)?;
                    }
                    _ => return None,
                }
            }
        }
        _ => None,
    }
}

// ===== Field access helpers (mirror DHTMessageFactoryImpl.cc's
// getString/getInteger/getDictionary family; missing or mistyped →
// MalformedField) =====

fn lookup<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.binary_search_by(|(k, _)| k.as_slice().cmp(key))
        .ok()
        .map(|i| &dict[i].1)
}

/// Error field name (`MalformedField.field`): every call site passes a
/// BEP5 field-name literal (`&'static [u8]` pinned by the signature), so
/// `from_utf8` always succeeds and maps ASCII to itself, equivalent to
/// the former 16-entry lookup table; the `_ => "?"` fallback is only
/// reachable for non-UTF-8 input. Called via the fully qualified
/// `std::str::` path — a bare `str::from_utf8` trips a clippy
/// incompatible_msrv false positive at the workspace MSRV 1.85
fn field_of(key: &'static [u8]) -> &'static str {
    std::str::from_utf8(key).unwrap_or("?")
}

/// The key must exist and be a string, else MalformedField.
fn get_bytes<'a>(dict: &'a [(Vec<u8>, Value)], key: &'static [u8]) -> Result<&'a [u8], DhtError> {
    match lookup(dict, key) {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(DhtError::MalformedField {
            field: field_of(key),
        }),
    }
}

/// Three states: key missing → Ok(None); present as string → Ok(Some);
/// present with another type → Err.
fn get_opt_bytes<'a>(
    dict: &'a [(Vec<u8>, Value)],
    key: &'static [u8],
) -> Result<Option<&'a [u8]>, DhtError> {
    match lookup(dict, key) {
        None => Ok(None),
        Some(Value::Bytes(b)) => Ok(Some(b)),
        Some(_) => Err(DhtError::MalformedField {
            field: field_of(key),
        }),
    }
}

/// Three-state integer variant.
fn get_opt_int(dict: &[(Vec<u8>, Value)], key: &'static [u8]) -> Result<Option<i64>, DhtError> {
    match lookup(dict, key) {
        None => Ok(None),
        Some(Value::Int(i)) => Ok(Some(*i)),
        Some(_) => Err(DhtError::MalformedField {
            field: field_of(key),
        }),
    }
}

fn get_dict<'a>(
    dict: &'a [(Vec<u8>, Value)],
    key: &'static [u8],
) -> Result<&'a [(Vec<u8>, Value)], DhtError> {
    match lookup(dict, key) {
        Some(Value::Dict(d)) => Ok(d),
        _ => Err(DhtError::MalformedField {
            field: field_of(key),
        }),
    }
}

/// 20-byte ID validation (validateID, DHTMessageFactoryImpl.cc).
fn get_id(dict: &[(Vec<u8>, Value)], field: &'static str) -> Result<NodeId, DhtError> {
    let b = get_bytes(dict, field.as_bytes())?;
    if b.len() != DHT_ID_LENGTH {
        return Err(DhtError::InvalidIdLength {
            field,
            expected: DHT_ID_LENGTH,
            got: b.len(),
        });
    }
    let mut id = [0u8; DHT_ID_LENGTH];
    id.copy_from_slice(b);
    Ok(NodeId(id))
}

/// announce_peer port: integer with 0 < p < 65535 (validatePort,
/// DHTMessageFactoryImpl.cc — note the open upper bound: 65535 is rejected).
fn get_announce_port(a: &[(Vec<u8>, Value)]) -> Result<u16, DhtError> {
    let p = match get_opt_int(a, b"port")? {
        Some(p) => p,
        None => return Err(DhtError::MalformedField { field: "port" }),
    };
    if !(0 < p && p < i64::from(u16::MAX)) {
        return Err(DhtError::InvalidPort { port: p });
    }
    Ok(p as u16)
}

fn has_key(dict: &[(Vec<u8>, Value)], key: &[u8]) -> bool {
    lookup(dict, key).is_some()
}

// ===== Server error reply classification =====

/// Error-reply classification for inbound malformed messages (BEP5
/// "Errors" duty: when a query cannot be processed, answer `y = "e"`,
/// `e = [code, msg]`; `None` = the message must be dropped silently).
///
/// # Classification (BEP5 code list)
///
/// - 203 = "Protocol Error, such as a malformed packet, invalid
///   arguments, or bad token": `y = "q"` with a known method name but
///   malformed arguments (missing or mistyped `a`/`id`/`target`/
///   `info_hash`/`port`/...), or `q` missing/non-string. Matches libtorrent
///   `node::incoming_error`, whose default code is 203
///   (`src/kademlia/node.cpp`; every verify_message failure path keeps the
///   default);
/// - 204 = "Method Unknown": `y = "q"` with a method name outside the
///   BEP5 message set;
/// - 201 = "Generic Error": no wire trigger in this implementation —
///   BEP5 defines no "overload" code; overload and limit excess are
///   handled by per-source rate limiting (`engine::error_limit`) with a
///   silent non-reply (anti-amplification first; libtorrent also defaults
///   to silence there). 201 remains only as an encoding-side vector (the
///   BEP5 example message).
///
/// # Silent faces (return None; anti-amplification, anti-reflection)
///
/// - Undecodable bencode (including strict-canonical violations) or a
///   non-dict top level: there is no reliable structure to echo; libtorrent
///   also drops outright when bdecode fails;
/// - `y` missing/non-string/other: never answer an error to a
///   response/error/unknown face — an error reply would be a reflection
///   surface; libtorrent explicitly does not reply to "missing 'y'" and
///   notes "We don't want to open up a magnification opportunity"
///   (`src/kademlia/node.cpp`);
/// - `t` missing/non-string: BEP5 KRPC requires the response to echo the
///   query's transaction id ("This transaction ID is generated by the
///   querying node and is echoed in the response"); an error without an
///   echoable tid cannot be matched by the peer and is outbound bytes with
///   no protocol value;
/// - The message decodes cleanly (defense: proves the classifier only
///   serves malformed paths).
///
/// Note: strict canonical decoding means a malformed query with
/// out-of-order keys fails in the bencode arm → silent (libtorrent's
/// bdecode is lenient and would answer 203). This is the existing
/// strictness divergence (see the crate::dht module docs) extended to the
/// error face; decoding is not relaxed for error replies.
pub fn incoming_error_reply(data: &[u8]) -> Option<ErrorMessage> {
    if decode_message(data).is_ok() {
        return None;
    }
    let value = bencode::decode(data).ok()?;
    let dict = value.as_dict()?;
    let transaction_id = get_opt_bytes(dict, b"t").ok()??.to_vec();
    // y not "q" (missing/non-string/other) is always silent (anti-reflection, see function docs).
    match get_opt_bytes(dict, b"y") {
        Ok(Some(b"q")) => {}
        _ => return None,
    }
    // Known method name → malformed arguments (203); unknown method name →
    // 204; q missing or non-string → 203 ("malformed packet" per the BEP5
    // code list, tiered apart from 204 "Method Unknown").
    let (code, message) = match get_opt_bytes(dict, b"q") {
        Ok(Some(name)) => match MessageKind::from_method_name(name) {
            Some(_) => (ERROR_PROTOCOL, ERROR_MSG_PROTOCOL),
            None => (ERROR_METHOD_UNKNOWN, ERROR_MSG_METHOD_UNKNOWN),
        },
        _ => (ERROR_PROTOCOL, ERROR_MSG_PROTOCOL),
    };
    Some(ErrorMessage {
        transaction_id,
        code,
        message: message.to_vec(),
        version: None,
    })
}

// Built uniformly by `dict(fields)`: the field table is sorted → an
// ascending Value::Dict (satisfying bencode::encode's canonical
// constraint).

fn dict(fields: Vec<(&'static str, Value)>) -> Value {
    let mut pairs: Vec<(Vec<u8>, Value)> = fields
        .into_iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), v))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    for w in pairs.windows(2) {
        debug_assert!(w[0].0 < w[1].0, "dict keys must be unique");
    }
    Value::Dict(pairs)
}

// ===== Tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    // ===== Vector source conventions =====
    // [BEP5 KRPC] = bittorrent.org/beps/bep_0005.html "KRPC protocol" example
    // messages (verbatim bytes).
    // [aria2 9e727358] = test/DHTMessageFactoryImplTest.cc of aria2 commit
    // 9e7273583f83e881e3ec067b523ba88724088d2f (equivalent messages built by
    // hand), or src/DHT*Message.cc's getArgument()/getResponse().
    // [strict-divergence] = aria2 accepts leniently, taiji rejects strictly
    // (see the crate::dht module docs divergence list).

    fn sid() -> NodeId {
        // "abcdefghij0123456789" (BEP5 example sender id)
        NodeId(*b"abcdefghij0123456789")
    }

    fn rid() -> NodeId {
        // "mnopqrstuvwxyz123456" (BEP5 example target/responder id)
        NodeId(*b"mnopqrstuvwxyz123456")
    }

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), port))
    }

    fn dec(data: &[u8]) -> DhtMessage {
        match decode_message(data) {
            Ok(m) => m,
            Err(e) => panic!("decode({data:?}) unexpectedly failed: {e:?}"),
        }
    }

    /// Test-only IPv6 literal parsing (a parse failure is a bug in the test itself, so panic).
    fn lit6(s: &str) -> Ipv6Addr {
        match s.parse::<Ipv6Addr>() {
            Ok(ip) => ip,
            Err(e) => panic!("bad literal {s}: {e}"),
        }
    }

    fn enc(msg: &DhtMessage) -> Vec<u8> {
        match encode_message(msg) {
            Ok(b) => b,
            Err(e) => panic!("encode({msg:?}) unexpectedly failed: {e:?}"),
        }
    }

    /// Header scan (early-drop gate input): the BEP5 reference
    /// frames' t/y pairs are located byte-exactly (both orders — key order
    /// in the dict is irrelevant to the scan), and the lenient-fallback
    /// contract holds (garbage / non-dict / missing keys / non-string t or
    /// y -> None, never a wrong Some). Encoded outputs of all three kinds
    /// scan to their own (t, y).
    #[test]
    fn scan_transaction_header_locates_t_and_y() {
        // [BEP5 KRPC] ping query (t between a and q alphabetically).
        let ping_q = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        assert_eq!(
            scan_transaction_header(ping_q),
            Some((&b"aa"[..], &b"q"[..]))
        );
        // [BEP5 KRPC] ping response (t first alphabetically).
        let ping_r = b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re";
        assert_eq!(
            scan_transaction_header(ping_r),
            Some((&b"aa"[..], &b"r"[..]))
        );
        // Error frame with a nested e list: the non-captured values are
        // skipped structurally (list walk), t/y still found.
        let err = b"d1:eli201e13:generic errore1:t2:aa1:y1:ee";
        assert_eq!(scan_transaction_header(err), Some((&b"aa"[..], &b"e"[..])));
        // Round-trip: every encoded kind scans back to its own (t, y).
        let cases = vec![
            DhtMessage::Query(QueryMessage {
                transaction_id: b"tqx".to_vec(),
                sender_id: sid(),
                body: QueryBody::Ping,
                version: Some(b"AB1000".to_vec()),
            }),
            DhtMessage::Response(ResponseMessage {
                transaction_id: vec![9, 9, 9, 9],
                responder_id: rid(),
                body: ResponseBody::FindNode {
                    nodes: vec![NodeInfo {
                        id: rid(),
                        addr: v4(6881),
                    }],
                },
                requester_endpoint: Some(v4(7777)),
                version: None,
            }),
            DhtMessage::Error(ErrorMessage {
                transaction_id: b"zz".to_vec(),
                code: 204,
                message: b"x".to_vec(),
                version: None,
            }),
        ];
        for m in &cases {
            let wire = enc(m);
            let expected_y: &[u8] = match m {
                DhtMessage::Query(_) => b"q",
                DhtMessage::Response(_) => b"r",
                DhtMessage::Error(_) => b"e",
            };
            assert_eq!(
                scan_transaction_header(&wire),
                Some((m.transaction_id(), expected_y)),
                "encoded frame scans to its own (t, y)"
            );
        }
        // Lenient fallback: None for every shape the gate must not decide
        // on (the strict decoder stays the sole authority).
        for bad in [
            &b""[..],             // empty
            b"i42e",              // not a dict
            b"d1:y1:qe",          // no t
            b"d1:t2:aae",         // no y
            b"d1:t2:aa1:yi42ee",  // y present but not a string
            b"d1:t2:aa1:y1:qX",   // trailing junk (dict never closed)
            b"d3:fooi1e1:t2:aaZ", // value-skip anomaly (Z unterminated)
        ] {
            assert_eq!(
                scan_transaction_header(bad),
                None,
                "anomalous input must fall back to strict decode: {bad:?}"
            );
        }
        // A packet whose t/y live after a large skipped subtree still scans
        // (skip walks nesting without parsing).
        let deep = b"d1:ad3:barl3:bazi1eee1:t2:aa1:y1:re";
        assert_eq!(scan_transaction_header(deep), Some((&b"aa"[..], &b"r"[..])));
    }

    /// Byte-exact decoding of the BEP5 example messages (7 vectors, every message
    /// shape of the KRPC section).
    #[test]
    fn decodes_bep5_reference_packets() {
        let cases: Vec<(&[u8], DhtMessage)> = vec![
// [BEP5 KRPC] ping query example
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
                DhtMessage::Query(QueryMessage {
                    transaction_id: b"aa".to_vec(),
                    sender_id: sid(),
                    body: QueryBody::Ping,
                    version: None,
                }),
            ),
// [BEP5 KRPC] ping response example
            (
                b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
                DhtMessage::Response(ResponseMessage {
                    transaction_id: b"aa".to_vec(),
                    responder_id: rid(),
                    body: ResponseBody::Ping,
                    requester_endpoint: None,
                    version: None,
                }),
            ),
// [BEP5 KRPC] find_node query example
            (
                b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe",
                DhtMessage::Query(QueryMessage {
                    transaction_id: b"aa".to_vec(),
                    sender_id: sid(),
                    body: QueryBody::FindNode {
                        target: rid(),
                        want: WantFamilies::default(),
                    },
                    version: None,
                }),
            ),
// [BEP5 KRPC] get_peers query example
            (
                b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe",
                DhtMessage::Query(QueryMessage {
                    transaction_id: b"aa".to_vec(),
                    sender_id: sid(),
                    body: QueryBody::GetPeers {
                        info_hash: rid(),
                        want: WantFamilies::default(),
                    },
                    version: None,
                }),
            ),
// [BEP5 KRPC] get_peers response (values shape) example:
// "axje.u" / "idhtnm" are 6B compact peers
            (
                b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re",
                DhtMessage::Response(ResponseMessage {
                    transaction_id: b"aa".to_vec(),
                    responder_id: sid(),
                    body: ResponseBody::GetPeers {
                        token: b"aoeusnth".to_vec(),
                        nodes: Vec::new(),
                        values: vec![
                            SocketAddr::V4(SocketAddrV4::new(
                                Ipv4Addr::new(0x61, 0x78, 0x6a, 0x65),
                                u16::from_be_bytes(*b".u"),
                            )),
                            SocketAddr::V4(SocketAddrV4::new(
                                Ipv4Addr::new(0x69, 0x64, 0x68, 0x74),
                                u16::from_be_bytes(*b"nm"),
                            )),
                        ],
                    },
                    requester_endpoint: None,
                    version: None,
                }),
            ),
// [BEP5 KRPC] announce_peer query example (with implied_port)
            (
                b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe",
                DhtMessage::Query(QueryMessage {
                    transaction_id: b"aa".to_vec(),
                    sender_id: sid(),
                    body: QueryBody::AnnouncePeer {
                        info_hash: rid(),
                        port: 6881,
                        token: b"aoeusnth".to_vec(),
                        implied_port: Some(true),
                    },
                    version: None,
                }),
            ),
// [BEP5 KRPC] error example ("Ocurred" is the upstream typo)
            (
                b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
                DhtMessage::Error(ErrorMessage {
                    transaction_id: b"aa".to_vec(),
                    code: 201,
                    message: b"A Generic Error Ocurred".to_vec(),
                    version: None,
                }),
            ),
        ];
        for (input, expected) in &cases {
            assert_eq!(&dec(input), expected, "input = {input:?}");
        }
    }

    /// Forward encoding of the BEP5 example messages: the same logical
    /// objects must encode back to the verbatim bytes (an executable spec of
    /// the encoder's field set and order).
    #[test]
    fn encodes_bep5_reference_packets() {
        let cases: Vec<(DhtMessage, &[u8])> = vec![
            (
                DhtMessage::Query(QueryMessage {
                    transaction_id: b"aa".to_vec(),
                    sender_id: sid(),
                    body: QueryBody::Ping,
                    version: None,
                }),
                b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
            ),
            (
                DhtMessage::Response(ResponseMessage {
                    transaction_id: b"aa".to_vec(),
                    responder_id: rid(),
                    body: ResponseBody::Ping,
                    requester_endpoint: None,
                    version: None,
                }),
                b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
            ),
            (
                DhtMessage::Error(ErrorMessage {
                    transaction_id: b"aa".to_vec(),
                    code: ERROR_GENERIC,
                    message: b"A Generic Error Ocurred".to_vec(),
                    version: None,
                }),
                b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
            ),
        ];
        for (msg, expected) in &cases {
            assert_eq!(&enc(msg), expected, "msg = {msg:?}");
        }
    }

    /// aria2 decode vectors (a bytified reconstruction of
    /// test/DHTMessageFactoryImplTest.cc; t/id use that test's 0xff/0x0f
    /// constants).
    #[test]
    fn decodes_aria2_factory_test_packets() {
        let tid = [0xffu8; DHT_TRANSACTION_ID_LENGTH];
        let remote = NodeId([0x0fu8; DHT_ID_LENGTH]);

        // [aria2 9e727358] testCreatePingMessage
        let mut ping = b"d1:ad2:id20:".to_vec();
        ping.extend_from_slice(&remote.0);
        ping.extend_from_slice(b"e1:q4:ping1:t4:");
        ping.extend_from_slice(&tid);
        ping.extend_from_slice(b"1:y1:qe");
        match dec(&ping) {
            DhtMessage::Query(m) => {
                assert_eq!(m.transaction_id, tid);
                assert_eq!(m.sender_id, remote);
                assert_eq!(m.body, QueryBody::Ping);
            }
            other => panic!("ping query expected, got {other:?}"),
        }

        // [aria2 9e727358] testCreatePingReplyMessage
        let mut ping_reply = b"d1:rd2:id20:".to_vec();
        ping_reply.extend_from_slice(&remote.0);
        ping_reply.extend_from_slice(b"e1:t4:");
        ping_reply.extend_from_slice(&tid);
        ping_reply.extend_from_slice(b"1:y1:re");
        match dec(&ping_reply) {
            DhtMessage::Response(m) => {
                assert_eq!(m.transaction_id, tid);
                assert_eq!(m.responder_id, remote);
                assert_eq!(m.body, ResponseBody::Ping);
            }
            other => panic!("ping reply expected, got {other:?}"),
        }
    }

    /// find_node reply nodes string (26B/38B units) decoding:
    /// [aria2 9e727358] testCreateFindNodeReplyMessage (v4) and
    /// testCreateFindNodeReplyMessage6 (v6, "2001::000x" shape).
    #[test]
    fn decodes_find_node_reply_nodes_v4_v6() {
        let tid = [0xffu8; DHT_TRANSACTION_ID_LENGTH];
        let remote = NodeId([0x0fu8; DHT_ID_LENGTH]);

        // v4: 8 nodes 192.168.0.x:6881+i (the same address grid as the test).
        let mut nodes_field = Vec::new();
        for i in 0u8..8 {
            let mut id = [0u8; 20];
            id[19] = i;
            nodes_field.extend_from_slice(&id);
            nodes_field.extend_from_slice(&[192, 168, 0, 1 + i]);
            nodes_field.extend_from_slice((6881u16 + u16::from(i)).to_be_bytes().as_slice());
        }
        let mut wire = b"d1:rd2:id20:".to_vec();
        wire.extend_from_slice(&remote.0);
        wire.extend_from_slice(format!("5:nodes{}:", nodes_field.len()).as_bytes());
        wire.extend_from_slice(&nodes_field);
        wire.extend_from_slice(b"e1:t4:");
        wire.extend_from_slice(&tid);
        wire.extend_from_slice(b"1:y1:re");
        match dec(&wire) {
            DhtMessage::Response(m) => {
                assert_eq!(m.transaction_id, tid);
                let ResponseBody::FindNode { nodes } = m.body else {
                    panic!("find_node body expected, got {:?}", m.body);
                };
                assert_eq!(nodes.len(), 8);
                for (i, node) in nodes.iter().enumerate() {
                    assert_eq!(node.id.0[19], i as u8);
                    assert_eq!(
                        node.addr,
                        SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::new(192, 168, 0, 1 + i as u8),
                            6881 + i as u16
                        ))
                    );
                }
            }
            other => panic!("find_node reply expected, got {other:?}"),
        }

        // v6: 2 nodes as 38B units, 2001::1/2001::2.
        let mut nodes6 = Vec::new();
        for i in 0u8..2 {
            let mut id = [0u8; 20];
            id[19] = i;
            nodes6.extend_from_slice(&id);
            let mut octets = [0u8; 16];
            octets[0] = 0x20;
            octets[1] = 0x01;
            octets[15] = 1 + i;
            nodes6.extend_from_slice(&octets);
            nodes6.extend_from_slice((6881u16 + u16::from(i)).to_be_bytes().as_slice());
        }
        let mut wire6 = b"d1:rd2:id20:".to_vec();
        wire6.extend_from_slice(&remote.0);
        wire6.extend_from_slice(format!("6:nodes6{}:", nodes6.len()).as_bytes());
        wire6.extend_from_slice(&nodes6);
        wire6.extend_from_slice(b"e1:t4:");
        wire6.extend_from_slice(&tid);
        wire6.extend_from_slice(b"1:y1:re");
        match dec(&wire6) {
            DhtMessage::Response(m) => {
                let ResponseBody::FindNode { nodes } = m.body else {
                    panic!("find_node body expected, got {:?}", m.body);
                };
                assert_eq!(nodes.len(), 2);
                assert_eq!(
                    nodes[1].addr,
                    SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 2),
                        6882,
                        0,
                        0
                    ))
                );
            }
            other => panic!("find_node reply6 expected, got {other:?}"),
        }
    }

    /// get_peers response (nodes + values + token triple):
    /// [aria2 9e727358] testCreateGetPeersReplyMessage.
    #[test]
    fn decodes_get_peers_reply_with_nodes_values_token() {
        let tid = [0xffu8; DHT_TRANSACTION_ID_LENGTH];
        let remote = NodeId([0x0fu8; DHT_ID_LENGTH]);
        let mut nodes_field = Vec::new();
        for i in 0u8..8 {
            let mut id = [0u8; 20];
            id[19] = i;
            nodes_field.extend_from_slice(&id);
            nodes_field.extend_from_slice(&[192, 168, 0, 1 + i]);
            nodes_field.extend_from_slice((6881u16 + u16::from(i)).to_be_bytes().as_slice());
        }
        // values: 192.168.0.1..4:6881+i (the same 4-value list as the test).
        let mut values_field = Vec::new();
        for i in 0u8..4 {
            values_field.extend_from_slice(b"6:");
            values_field.extend_from_slice(&[192, 168, 0, 1 + i]);
            values_field.extend_from_slice((6881u16 + u16::from(i)).to_be_bytes().as_slice());
        }
        let mut wire = b"d1:rd2:id20:".to_vec();
        wire.extend_from_slice(&remote.0);
        wire.extend_from_slice(format!("5:nodes{}:", nodes_field.len()).as_bytes());
        wire.extend_from_slice(&nodes_field);
        wire.extend_from_slice(b"5:token5:token6:valuesl");
        wire.extend_from_slice(&values_field);
        wire.extend_from_slice(b"ee1:t4:");
        wire.extend_from_slice(&tid);
        wire.extend_from_slice(b"1:y1:re");
        match dec(&wire) {
            DhtMessage::Response(m) => {
                let ResponseBody::GetPeers {
                    token,
                    nodes,
                    values,
                } = m.body
                else {
                    panic!("get_peers body expected, got {:?}", m.body);
                };
                assert_eq!(token, b"token".to_vec());
                assert_eq!(nodes.len(), 8);
                assert_eq!(values.len(), 4);
                for (i, addr) in values.iter().enumerate() {
                    assert_eq!(
                        addr,
                        &SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::new(192, 168, 0, 1 + i as u8),
                            6881 + i as u16
                        ))
                    );
                }
            }
            other => panic!("get_peers reply expected, got {other:?}"),
        }
    }

    /// get_peers values encoding per family: always a single "values" key of
    /// single-family compact units (v4 → 6B each / v6 → 18B each), empty
    /// omitted, mixed families rejected. References: BEP32 "Changes to
    /// get_peers" (quotes in docs/design/dht.md); the v4 forward vector is
    /// the BEP5 example ("axje.u"/"idhtnm" shape); the v6 18B unit follows
    /// aria2 BittorrentHelperTest.cc packcompact vectors. Key order inside
    /// r: id < token < values (canonical ascending).
    #[test]
    fn get_peers_values_single_key_single_family_per_bep32() {
        let v6_addr = SocketAddr::V6(SocketAddrV6::new(
            lit6("1002:1035:4527:3546:7854:1237:3247:3217"),
            6881,
            0,
            0,
        ));
        let body = |values: Vec<SocketAddr>| ResponseBody::GetPeers {
            token: b"aoeusnth".to_vec(),
            nodes: Vec::new(),
            values,
        };
        let msg = |values: Vec<SocketAddr>| {
            DhtMessage::Response(ResponseMessage {
                transaction_id: b"aa".to_vec(),
                responder_id: rid(),
                body: body(values),
                requester_endpoint: None,
                version: None,
            })
        };

        // v4 only: 6B unit each (same shape as the BEP5 get_peers response
        // values example — one 6B string per peer in the list).
        let v4b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 2), 6882));
        let wire_v4 = enc(&msg(vec![v4(6881), v4b]));
        let mut expect_v4 =
            b"d1:rd2:id20:mnopqrstuvwxyz1234565:token8:aoeusnth6:valuesl6:".to_vec();
        expect_v4.extend_from_slice(&[192, 168, 0, 1, 0x1a, 0xe1]);
        expect_v4.extend_from_slice(b"6:");
        expect_v4.extend_from_slice(&[192, 168, 0, 2, 0x1a, 0xe2]);
        expect_v4.extend_from_slice(b"ee1:t2:aa1:y1:re");
        assert_eq!(wire_v4, expect_v4, "v4-only values wire");

        // v6 only: 18B unit each (no "values6" key — dropped by the BEP32
        // Post-History; the family is expressed by the request's network layer).
        let wire_v6 = enc(&msg(vec![v6_addr]));
        let mut expect_v6 =
            b"d1:rd2:id20:mnopqrstuvwxyz1234565:token8:aoeusnth6:valuesl18:".to_vec();
        expect_v6.extend_from_slice(&[
            0x10, 0x02, 0x10, 0x35, 0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47,
            0x32, 0x17, 0x1a, 0xe1,
        ]);
        expect_v6.extend_from_slice(b"ee1:t2:aa1:y1:re");
        assert_eq!(wire_v6, expect_v6, "v6-only values wire");

        // All empty: the values key omitted entirely (same policy as the nodes
        // key: aria2 DHTGetPeersReplyMessage.cc only puts when non-empty).
        let wire_none = enc(&msg(Vec::new()));
        assert_eq!(
            wire_none,
            b"d1:rd2:id20:mnopqrstuvwxyz1234565:token8:aoeusnthe1:t2:aa1:y1:re".to_vec()
        );

        // Hybrid families are forbidden to send (BEP32: "must not send hybrid
        // lists in a reply to an IPv4 request that doesn't contain a "want"
        // parameter") — both orders are rejected.
        assert_eq!(
            encode_message(&msg(vec![v4(6881), v6_addr])),
            Err(DhtError::MixedAddressFamilies)
        );
        assert_eq!(
            encode_message(&msg(vec![v6_addr, v4(6881)])),
            Err(DhtError::MixedAddressFamilies)
        );

        // Both family-split encodings decode back to the original object
        // (roundtrip semantics unchanged; only the unit length follows the
        // family).
        assert_eq!(dec(&wire_v4), msg(vec![v4(6881), v4b]), "v4-only roundtrip");
        assert_eq!(dec(&wire_v6), msg(vec![v6_addr]), "v6-only roundtrip");
        assert_eq!(dec(&wire_none), msg(Vec::new()), "empty roundtrip");
    }

    /// Legacy-peer hybrid "values" decode regression: a single values key
    /// alternating 6B v4 and 18B v6 entries still parses fully — BEP32
    /// "Changes to get_peers" mandates it ("Implementations of this
    /// specification must be able to properly parse hybrid "values" lists --
    /// lists containing an arbitrary mixture of 6-octet IPv4 values and
    /// 18-octet IPv6 values"), matching aria2's per-element clen filter.
    /// Note: the local **send** side forbids hybrids (the encoder rejects,
    /// see [`get_peers_values_single_key_single_family_per_bep32`]).
    #[test]
    fn decodes_legacy_hybrid_values_regression() {
        let tid = [0xffu8; DHT_TRANSACTION_ID_LENGTH];
        let remote = NodeId([0x0fu8; DHT_ID_LENGTH]);
        let mut wire = b"d1:rd2:id20:".to_vec();
        wire.extend_from_slice(&remote.0);
        wire.extend_from_slice(b"5:token5:token6:valuesl");
        // 6B v4: 192.168.0.1:6881.
        wire.extend_from_slice(b"6:");
        wire.extend_from_slice(&[192, 168, 0, 1, 0x1a, 0xe1]);
        // 18B v6: 1002:...:3217:6881 (aria2 packcompact vector).
        wire.extend_from_slice(b"18:");
        wire.extend_from_slice(&[
            0x10, 0x02, 0x10, 0x35, 0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47,
            0x32, 0x17, 0x1a, 0xe1,
        ]);
        // 6B v4: 192.168.0.2:6882.
        wire.extend_from_slice(b"6:");
        wire.extend_from_slice(&[192, 168, 0, 2, 0x1a, 0xe2]);
        wire.extend_from_slice(b"ee1:t4:");
        wire.extend_from_slice(&tid);
        wire.extend_from_slice(b"1:y1:re");
        match dec(&wire) {
            DhtMessage::Response(m) => {
                assert_eq!(m.transaction_id, tid);
                let ResponseBody::GetPeers { values, .. } = m.body else {
                    panic!("get_peers body expected, got {:?}", m.body);
                };
                assert_eq!(
                    values,
                    vec![
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 6881)),
                        SocketAddr::V6(SocketAddrV6::new(
                            lit6("1002:1035:4527:3546:7854:1237:3247:3217"),
                            6881,
                            0,
                            0,
                        )),
                        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 2), 6882)),
                    ]
                );
            }
            other => panic!("get_peers reply expected, got {other:?}"),
        }
    }

    /// Regression test (BEP32 dual-key nodes reply, receive side): a
    /// requester carrying want=[n4,n6] gets a reply with both nodes and
    /// nodes6 keys in one frame — "A reply should include a "nodes"
    /// parameter if the request's "want" parameter contained the string
    /// "n4", and should include a "nodes6" parameter if the request's
    /// "want" parameter contained the string "n6""
    /// (bittorrent.org/beps/bep_0032.html). The receiver must merge both
    /// keys without losing nodes (the former AmbiguousNodes rejection
    /// dropped the whole frame). Merge order: v4 entries (nodes key) first,
    /// v6 entries (nodes6 key) after (canonical order, the inverse of the
    /// encode-side split).
    #[test]
    fn decodes_dual_key_nodes_reply_per_bep32() {
        let tid = [0xffu8; DHT_TRANSACTION_ID_LENGTH];
        let remote = NodeId([0x0fu8; DHT_ID_LENGTH]);
        let mut wire = b"d1:rd2:id20:".to_vec();
        wire.extend_from_slice(&remote.0);
        // nodes: 1 x 26B v4 unit (192.168.0.7:6881).
        wire.extend_from_slice(b"5:nodes26:");
        let mut v4_id = [0u8; 20];
        v4_id[19] = 1;
        wire.extend_from_slice(&v4_id);
        wire.extend_from_slice(&[192, 168, 0, 7, 0x1a, 0xe1]);
        // nodes6: 1 x 38B v6 unit (2001::2:6882).
        wire.extend_from_slice(b"6:nodes638:");
        let mut v6_id = [0u8; 20];
        v6_id[19] = 2;
        wire.extend_from_slice(&v6_id);
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        octets[15] = 2;
        wire.extend_from_slice(&octets);
        wire.extend_from_slice(&6882u16.to_be_bytes());
        wire.extend_from_slice(b"e1:t4:");
        wire.extend_from_slice(&tid);
        wire.extend_from_slice(b"1:y1:re");
        match dec(&wire) {
            DhtMessage::Response(m) => {
                let ResponseBody::FindNode { nodes } = m.body else {
                    panic!("find_node body expected, got {:?}", m.body);
                };
                assert_eq!(nodes.len(), 2, "merged dual-family entries lose no nodes");
                assert_eq!(
                    nodes[0].addr,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 7), 6881))
                );
                assert_eq!(
                    nodes[1].addr,
                    SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 2),
                        6882,
                        0,
                        0
                    ))
                );
            }
            other => panic!("find_node reply expected, got {other:?}"),
        }
    }

    /// Regression test (BEP32 dual-key split, send side): a mixed-family
    /// nodes list must be encodable — the v4 subset lands in `nodes`, the
    /// v6 subset in `nodes6` (each subset order-preserving); the former
    /// MixedAddressFamilies rejection suppressed the whole reply. An empty
    /// list keeps the always-written single empty-string key (aria2
    /// DHTFindNodeReplyMessage.cc puts unconditionally).
    #[test]
    fn encodes_mixed_nodes_as_dual_keys_per_bep32() {
        let v6_a = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            6882,
            0,
            0,
        ));
        let nodes = vec![
            NodeInfo {
                id: rid(),
                addr: v4(6881),
            },
            NodeInfo {
                id: rid(),
                addr: v6_a,
            },
        ];
        let msg = |nodes: Vec<NodeInfo>| {
            DhtMessage::Response(ResponseMessage {
                transaction_id: b"aa".to_vec(),
                responder_id: rid(),
                body: ResponseBody::FindNode { nodes },
                requester_endpoint: None,
                version: None,
            })
        };
        let wire = enc(&msg(nodes.clone()));
        assert!(
            wire.windows(7).any(|w| w == *b"5:nodes"),
            "v4 subset must land under the nodes key: {wire:?}"
        );
        assert!(
            wire.windows(8).any(|w| w == *b"6:nodes6"),
            "v6 subset must land under the nodes6 key: {wire:?}"
        );
        // roundtrip: canonical merged order (v4 first, v6 after).
        assert_eq!(dec(&wire), msg(nodes));
        // Empty-list always-write shape preserved (byte-identical to the BEP5/aria2 single-key form).
        assert_eq!(
            enc(&msg(Vec::new())),
            b"d1:rd2:id20:mnopqrstuvwxyz1234565:nodes0:e1:t2:aa1:y1:re".to_vec()
        );
    }

    /// BEP32 want parameter encode/decode vectors: a query carrying
    /// want=[n4,n6] emits `4:wantl2:n42:n6e` in the a-dict (key order
    /// id < target/info_hash < want, canonical); element order is fixed
    /// n4 → n6; absent (∅) writes no key; the decoder silently ignores
    /// unknown entries ("nX"/non-string elements) — "For future
    /// extensibility, other strings may be present in the list, and must be
    /// silently ignored on reception" (bep_0032.html).
    #[test]
    fn want_param_encode_decode_vectors_bep32() {
        // Encode: find_node want=[n4,n6] (outbound dual-stack shape, the codec
        // face of engine::tasks OUTBOUND_WANT).
        let wire = enc(&DhtMessage::Query(QueryMessage {
            transaction_id: b"aa".to_vec(),
            sender_id: sid(),
            body: QueryBody::FindNode {
                target: rid(),
                want: WantFamilies::BOTH,
            },
            version: None,
        }));
        assert_eq!(
            wire,
            b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz1234564:wantl2:n42:n6ee1:q9:find_node1:t2:aa1:y1:qe".to_vec()
        );
        // Encode: get_peers want=[n6] (a v4 request asking only for v6 nodes).
        let wire6 = enc(&DhtMessage::Query(QueryMessage {
            transaction_id: b"aa".to_vec(),
            sender_id: sid(),
            body: QueryBody::GetPeers {
                info_hash: rid(),
                want: WantFamilies::single_v6(),
            },
            version: None,
        }));
        assert_eq!(
            wire6,
            b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:wantl2:n6ee1:q9:get_peers1:t2:aa1:y1:qe".to_vec()
        );
        // Encode: absent (∅) writes no key (verbatim BEP5 bytes, regression anchor).
        let wire_none = enc(&DhtMessage::Query(QueryMessage {
            transaction_id: b"aa".to_vec(),
            sender_id: sid(),
            body: QueryBody::FindNode {
                target: rid(),
                want: WantFamilies::default(),
            },
            version: None,
        }));
        assert_eq!(
            wire_none,
            b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe".to_vec()
        );

        // Decode: want=[n4,n6] mixed with unknown string "nX" and a non-string
        // element — recognized values form the set, unknowns silently ignored.
        let mixed = b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz1234564:wantl2:n42:nX2:n6i7eee1:q9:find_node1:t2:aa1:y1:qe";
        match dec(mixed) {
            DhtMessage::Query(m) => match m.body {
                QueryBody::FindNode { want, .. } => {
                    assert_eq!(want, WantFamilies::BOTH, "nX / i7e silently ignored");
                }
                other => panic!("find_node body expected, got {other:?}"),
            },
            other => panic!("query expected, got {other:?}"),
        }
        // Decode: an empty want list (present, no recognized value) → ∅ (absent
        // semantics; the fallback is the engine's decision).
        let empty = b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:wantlee1:q9:get_peers1:t2:aa1:y1:qe";
        match dec(empty) {
            DhtMessage::Query(m) => match m.body {
                QueryBody::GetPeers { want, .. } => {
                    assert_eq!(want, WantFamilies::default());
                }
                other => panic!("get_peers body expected, got {other:?}"),
            },
            other => panic!("query expected, got {other:?}"),
        }
        // roundtrip: all four shapes.
        for want in [
            WantFamilies::default(),
            WantFamilies::single_v4(),
            WantFamilies::single_v6(),
            WantFamilies::BOTH,
        ] {
            let m = DhtMessage::Query(QueryMessage {
                transaction_id: b"aa".to_vec(),
                sender_id: sid(),
                body: QueryBody::GetPeers {
                    info_hash: rid(),
                    want,
                },
                version: None,
            });
            assert_eq!(dec(&enc(&m)), m, "want = {want:?}");
        }
    }

    /// announce_peer query (the aria2 shape without implied_port):
    /// [aria2 9e727358] testCreateAnnouncePeerMessage
    /// (port 6881, token "ffff", info_hash = 0x11 x 20).
    #[test]
    fn decodes_aria2_announce_peer() {
        let tid = [0xffu8; DHT_TRANSACTION_ID_LENGTH];
        let remote = NodeId([0x0fu8; DHT_ID_LENGTH]);
        let info_hash = [0x11u8; 20];
        let mut wire = b"d1:ad2:id20:".to_vec();
        wire.extend_from_slice(&remote.0);
        wire.extend_from_slice(b"9:info_hash20:");
        wire.extend_from_slice(&info_hash);
        wire.extend_from_slice(b"4:porti6881e5:token4:ffffe1:q13:announce_peer1:t4:");
        wire.extend_from_slice(&tid);
        wire.extend_from_slice(b"1:y1:qe");
        match dec(&wire) {
            DhtMessage::Query(m) => {
                assert_eq!(m.transaction_id, tid);
                assert_eq!(m.sender_id, remote);
                match m.body {
                    QueryBody::AnnouncePeer {
                        info_hash: ih,
                        port,
                        token,
                        implied_port,
                    } => {
                        assert_eq!(ih, NodeId(info_hash));
                        assert_eq!(port, 6881);
                        assert_eq!(token, b"ffff".to_vec());
                        assert_eq!(implied_port, None);
                    }
                    other => panic!("announce_peer body expected, got {other:?}"),
                }
            }
            other => panic!("announce_peer query expected, got {other:?}"),
        }
    }

    /// Strict validation matrix (each case annotated with its source; mirrors
    /// DHTMessageFactoryImpl.cc).
    #[test]
    fn rejects_malformed_messages() {
        let cases: Vec<(&[u8], DhtError)> = vec![
// Top level not a dict (BEP5: a KRPC message is a single bencode dict)
            (b"i1e", DhtError::NotADict),
// Missing t (getString(dict, T))
            (b"d1:y1:qe", DhtError::MalformedField { field: "t" }),
// Missing y
            (b"d1:t2:aae", DhtError::MalformedField { field: "y" }),
// y not q/r/e (the query path errors on y != q)
            (b"d1:t2:aa1:y1:ze", DhtError::MalformedY), // y="z" is not q/r/e (keys stay canonically sorted)
// Query missing a (getDictionary(dict, A))
            (
                b"d1:q4:ping1:t2:aa1:y1:qe",
                DhtError::MalformedField { field: "a" },
            ),
// a.id length 19 (validateID)
            (
                b"d1:ad2:id19:abcdefghij012345678e1:q4:ping1:t2:aa1:y1:qe",
                DhtError::InvalidIdLength {
                    field: "id",
                    expected: 20,
                    got: 19,
                },
            ),
// Unknown method name ("Unsupported message type")
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:q7:unknown1:t2:aa1:y1:qe",
                DhtError::UnsupportedMethod(b"unknown".to_vec()),
            ),
// find_node missing target
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:q9:find_node1:t2:aa1:y1:qe",
                DhtError::MalformedField { field: "target" },
            ),
// announce_peer port=0 (validatePort requires 0 < p)
            (
                b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti0e5:token4:aaaae1:q13:announce_peer1:t2:aa1:y1:qe",
                DhtError::InvalidPort { port: 0 },
            ),
// announce_peer port=65535 (validatePort open upper bound, p < 65535)
            (
                b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti65535e5:token4:aaaae1:q13:announce_peer1:t2:aa1:y1:qe",
                DhtError::InvalidPort { port: 65535 },
            ),
// announce_peer port type error (getInteger)
            (
                b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:port4:68815:token4:aaaae1:q13:announce_peer1:t2:aa1:y1:qe",
                DhtError::MalformedField { field: "port" },
            ),
// announce_peer missing token (getString)
            (
                b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:porti6881ee1:q13:announce_peer1:t2:aa1:y1:qe",
                DhtError::MalformedField { field: "token" },
            ),
// implied_port not 0/1 (BEP5: "0 or 1"; [strict-divergence] strictness)
            (
                b"d1:ad2:id20:abcdefghij012345678912:implied_porti2e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token4:aaaae1:q13:announce_peer1:t2:aa1:y1:qe",
                DhtError::MalformedField { field: "implied_port" },
            ),
// Response missing r (getDictionary(dict, R))
            (b"d1:t2:aa1:y1:re", DhtError::MalformedField { field: "r" }),
// Response r.id length 21 (validateID)
            (
                b"d1:rd2:id21:mnopqrstuvwxyz1234567e1:t2:aa1:y1:re",
                DhtError::InvalidIdLength {
                    field: "id",
                    expected: 20,
                    got: 21,
                },
            ),
// get_peers reply with values but no token (token is required)
// [strict-divergence]: aria2 only errors when its transaction table
// already says get_peers; context-free decoding rejects outright
// (stricter, see the module docs).
            (
                b"d1:rd2:id20:abcdefghij01234567896:valuesl6:axje.uee1:t2:aa1:y1:re",
                DhtError::ValuesWithoutToken,
            ),
// nodes length not a multiple of 26 ("Nodes length is not multiple")
            (
                b"d1:rd2:id20:abcdefghij01234567895:nodes27:abcdefghij0123456789aaaaaaae1:t2:aa1:y1:re",
                DhtError::NodesLength { len: 27, unit: 26 },
            ),
// want not a list (BEP32 optional key; known-field types strict, same policy as v/ip)
            (
                b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:want2:n4e1:q9:get_peers1:t2:aa1:y1:qe",
                DhtError::MalformedField { field: "want" },
            ),
// Error message e not a [code, msg] pair
            (b"d1:eli201ee1:t2:aa1:y1:ee", DhtError::MalformedField { field: "e" }),
// Error message code not an integer
            (
                b"d1:el4:201e5:helloe1:t2:aa1:y1:ee",
                DhtError::MalformedField { field: "e" },
            ),
// v field type error (setVersion downcast<String>; [strict-divergence])
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:vi1e1:y1:qe",
                DhtError::MalformedField { field: "v" },
            ),
        ];
        for (input, expected) in &cases {
            match decode_message(input) {
                Ok(v) => panic!("decode({input:?}) unexpectedly succeeded: {v:?}"),
                Err(e) => assert_eq!(&e, expected, "input = {input:?}"),
            }
        }
    }

    /// Encode → decode roundtrip for every message shape (with v field,
    /// empty nodes, dual-stack addresses, implied_port present/absent).
    #[test]
    fn encode_decode_roundtrip_all_shapes() {
        let mut v6 = [0x20u8; 16];
        v6[15] = 1;
        let messages = vec![
            DhtMessage::Query(QueryMessage {
                transaction_id: vec![1, 2, 3, 4],
                sender_id: sid(),
                body: QueryBody::Ping,
                version: Some(b"A2\x00\x03".to_vec()),
            }),
            DhtMessage::Query(QueryMessage {
                transaction_id: b"t!".to_vec(),
                sender_id: sid(),
                body: QueryBody::FindNode {
                    target: rid(),
                    want: WantFamilies::BOTH,
                },
                version: None,
            }),
            DhtMessage::Query(QueryMessage {
                transaction_id: Vec::new(),
                sender_id: rid(),
                body: QueryBody::GetPeers {
                    info_hash: sid(),
                    want: WantFamilies::single_v6(),
                },
                version: None,
            }),
            DhtMessage::Query(QueryMessage {
                transaction_id: vec![9; 4],
                sender_id: sid(),
                body: QueryBody::AnnouncePeer {
                    info_hash: rid(),
                    port: 6881,
                    token: b"tok".to_vec(),
                    implied_port: Some(true),
                },
                version: None,
            }),
            DhtMessage::Query(QueryMessage {
                transaction_id: vec![9; 4],
                sender_id: sid(),
                body: QueryBody::AnnouncePeer {
                    info_hash: rid(),
                    port: 1,
                    token: Vec::new(),
                    implied_port: Some(false),
                },
                version: None,
            }),
            DhtMessage::Response(ResponseMessage {
                transaction_id: vec![1, 2, 3, 4],
                responder_id: rid(),
                body: ResponseBody::Ping,
                requester_endpoint: None,
                version: None,
            }),
            DhtMessage::Response(ResponseMessage {
                transaction_id: vec![5],
                responder_id: rid(),
                body: ResponseBody::FindNode { nodes: Vec::new() },
                requester_endpoint: None,
                version: Some(b"bb\x00\x01".to_vec()),
            }),
            DhtMessage::Response(ResponseMessage {
                transaction_id: vec![6, 6],
                responder_id: sid(),
                body: ResponseBody::FindNode {
                    nodes: vec![NodeInfo {
                        id: rid(),
                        addr: v4(6881),
                    }],
                },
                requester_endpoint: None,
                version: None,
            }),
            DhtMessage::Response(ResponseMessage {
                transaction_id: vec![7, 7, 7],
                responder_id: sid(),
                body: ResponseBody::GetPeers {
                    token: b"aoeusnth".to_vec(),
                    nodes: Vec::new(),
                    values: vec![SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(v6),
                        6881,
                        0,
                        0,
                    ))],
                },
                requester_endpoint: None,
                version: None,
            }),
            DhtMessage::Error(ErrorMessage {
                transaction_id: b"aa".to_vec(),
                code: ERROR_METHOD_UNKNOWN,
                message: b"Method Unknown".to_vec(),
                version: None,
            }),
        ];
        for msg in &messages {
            let wire = enc(msg);
            let back = match decode_message(&wire) {
                Ok(m) => m,
                Err(e) => panic!("re-decode failed for {msg:?}: {e:?}"),
            };
            assert_eq!(&back, msg, "wire = {wire:?}");
            // Re-encoding is stable at the same canonical bytes.
            assert_eq!(enc(&back), wire);
        }
    }

    /// Response body kind check (aria2 dispatches parsing by the
    /// transaction-table message type, DHTMessageTracker.cc): id-only is
    /// interpretable as ping/announce_peer; find_node/get_peers bodies are
    /// incompatible with the other kinds.
    #[test]
    fn response_body_as_kind_semantics() {
        let ping = ResponseBody::Ping;
        assert!(ping.as_kind(MessageKind::Ping).is_ok());
        assert!(ping.as_kind(MessageKind::AnnouncePeer).is_ok());
        assert!(ping.as_kind(MessageKind::GetPeers).is_err());
        assert!(ping.as_kind(MessageKind::FindNode).is_err());

        let find = ResponseBody::FindNode { nodes: Vec::new() };
        assert!(find.as_kind(MessageKind::FindNode).is_ok());
        assert!(find.as_kind(MessageKind::Ping).is_err());

        let gp = ResponseBody::GetPeers {
            token: b"t".to_vec(),
            nodes: Vec::new(),
            values: Vec::new(),
        };
        assert!(gp.as_kind(MessageKind::GetPeers).is_ok());
        assert!(gp.as_kind(MessageKind::FindNode).is_err());
    }

    /// BEP42 top-level `ip` field frame vectors. Encoding: `ip` sits at top
    /// level (outside the r dict), value = compact endpoint (big-endian
    /// address + big-endian port, v4 6B / v6 18B), per BEP42
    /// "Bootstrapping" (quotes in docs/design/dht.md); libtorrent's sender
    /// is structured the same way (node.cpp `incoming_request` writes
    /// `e["ip"] = endpoint_to_bytes(m.addr);` before building the r dict;
    /// endpoint_to_bytes = write_address + write_uint16(port),
    /// socket_io.hpp). Decoding: 6B/18B → full endpoint; other lengths are
    /// ignored (libtorrent's inbound `string_length() >= address_size`
    /// lenient read has the same flavor); a non-string type →
    /// MalformedField.
    #[test]
    fn bep42_top_level_ip_field_wire_vectors() {
        let v4_ep = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(124, 31, 75, 21), 39501));
        let v6_ep = SocketAddr::V6(SocketAddrV6::new(lit6("2001:db8::1"), 6881, 0, 0));
        let msg = |ep: Option<SocketAddr>| {
            DhtMessage::Response(ResponseMessage {
                transaction_id: b"aa".to_vec(),
                responder_id: rid(),
                body: ResponseBody::Ping,
                requester_endpoint: ep,
                version: None,
            })
        };

        // v4: top-level key order ip < r < t < y (canonical ascending).
        let mut expect_v4 = b"d2:ip6:".to_vec();
        expect_v4.extend_from_slice(&[124, 31, 75, 21, 0x9a, 0x4d]); // 39501 = 0x9a4d
        expect_v4.extend_from_slice(b"1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re");
        assert_eq!(enc(&msg(Some(v4_ep))), expect_v4, "v4 top-level ip wire");

        // v6: 16B address + 2B port = 18B unit.
        let mut expect_v6 = b"d2:ip18:".to_vec();
        expect_v6.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x1a, 0xe1,
        ]);
        expect_v6.extend_from_slice(b"1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re");
        assert_eq!(enc(&msg(Some(v6_ep))), expect_v6, "v6 top-level ip wire");

        // None: the frame falls back to the ip-less shape (byte-identical to the BEP5 ping reply).
        assert_eq!(
            enc(&msg(None)),
            b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re".to_vec()
        );

        // Decode: 6B/18B full-endpoint roundtrip (interop with the libtorrent frame shape).
        assert_eq!(dec(&expect_v4), msg(Some(v4_ep)), "v4 ip roundtrip");
        assert_eq!(dec(&expect_v6), msg(Some(v6_ep)), "v6 ip roundtrip");

        // Decode: a length other than 6/18B (e.g. a bare 4B address) → the
        // field is ignored and the frame still parses (lenient policy, matching
        // libtorrent's inbound minimum-length read).
        let mut short = b"d2:ip4:".to_vec();
        short.extend_from_slice(&[124, 31, 75, 21]);
        short.extend_from_slice(b"1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re");
        assert_eq!(
            dec(&short),
            msg(None),
            "non-compact endpoint length -> ip field ignored"
        );

        // Decode: a non-string ip type → MalformedField (known-field types are strict).
        assert_eq!(
            decode_message(b"d2:ipi7e1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"),
            Err(DhtError::MalformedField { field: "ip" })
        );
    }

    /// Pin the upstream behavior: announce_peer port=65535 →
    /// decode == Err(InvalidPort). Upstream rule: validatePort
    /// (DHTMessageFactoryImpl.cc) requires the open interval
    /// `0 < p < 65535`, and the check is unconditional (aria2 never parses
    /// implied_port), so implied_port=1 does not relax it. The encode-side
    /// domain guard mirrors it: encode(port=0/65535) also errors, so the
    /// encoder never produces a message its own decoder would reject.
    #[test]
    fn announce_peer_port_domain_matches_validate_port() {
        let base = |port: u16, implied: Option<bool>| {
            // Key order: id < implied_port < info_hash < port < token.
            let mut wire = b"d1:ad2:id20:abcdefghij0123456789".to_vec();
            if let Some(imp) = implied {
                wire.extend_from_slice(format!("12:implied_porti{}e", u8::from(imp)).as_bytes());
            }
            wire.extend_from_slice(b"9:info_hash20:");
            wire.extend_from_slice(&[0x11u8; 20]);
            wire.extend_from_slice(
                format!("4:porti{port}e5:token4:aaaae1:q13:announce_peer1:t2:aa1:y1:qe").as_bytes(),
            );
            wire
        };
        // Decode side: 65535 rejected (open upper bound), 0 rejected (lower bound).
        assert_eq!(
            decode_message(&base(65535, None)),
            Err(DhtError::InvalidPort { port: 65535 })
        );
        assert_eq!(
            decode_message(&base(0, None)),
            Err(DhtError::InvalidPort { port: 0 })
        );
        // implied_port=1 does not relax the domain (the upstream check is unconditional).
        assert_eq!(
            decode_message(&base(65535, Some(true))),
            Err(DhtError::InvalidPort { port: 65535 })
        );
        // 65534 is the legal maximum (inside the open interval).
        match decode_message(&base(65534, None)) {
            Ok(DhtMessage::Query(m)) => match m.body {
                QueryBody::AnnouncePeer { port, .. } => assert_eq!(port, 65534),
                other => panic!("announce_peer body expected, got {other:?}"),
            },
            other => panic!("65534 must decode, got {other:?}"),
        }
        // Encode-side domain guard: out-of-domain ports cannot be encoded.
        let out_of_domain = |port: u16| {
            encode_message(&DhtMessage::Query(QueryMessage {
                transaction_id: b"aa".to_vec(),
                sender_id: sid(),
                body: QueryBody::AnnouncePeer {
                    info_hash: rid(),
                    port,
                    token: b"aaaa".to_vec(),
                    implied_port: None,
                },
                version: None,
            }))
        };
        assert_eq!(
            out_of_domain(65535),
            Err(DhtError::InvalidPort { port: 65535 })
        );
        assert_eq!(out_of_domain(0), Err(DhtError::InvalidPort { port: 0 }));
        assert!(out_of_domain(65534).is_ok());
        assert!(out_of_domain(1).is_ok());
    }

    /// The v field (client version) round-trips verbatim (aria2 setVersion,
    /// DHTMessageFactoryImpl.cc; the default version string is "A2" +
    /// htons(3), getDefaultVersion).
    #[test]
    fn version_field_roundtrip() {
        let wire = enc(&DhtMessage::Query(QueryMessage {
            transaction_id: b"tt".to_vec(),
            sender_id: sid(),
            body: QueryBody::Ping,
            version: Some(b"A2\x00\x03".to_vec()),
        }));
        assert!(wire.windows(2).any(|w| w == *b"A2"));
        match dec(&wire) {
            DhtMessage::Query(m) => assert_eq!(m.version, Some(b"A2\x00\x03".to_vec())),
            other => panic!("query expected, got {other:?}"),
        }
    }

    /// Error reply encoding vectors (three codes): 201 = the verbatim BEP5
    /// "Errors" example message; 203/204 = canonical encodings of the
    /// code-table phrases (key order e < t < y). All three decode back to
    /// the original object (roundtrip).
    #[test]
    fn error_reply_encoding_vectors_three_codes() {
        let cases: Vec<(i64, &[u8], &[u8])> = vec![
            // [BEP5 Errors] "generic error = {"t":"aa", "y":"e",
            // "e":[201, "A Generic Error Ocurred"]}"
            (
                ERROR_GENERIC,
                b"A Generic Error Ocurred",
                b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
            ),
            (
                ERROR_PROTOCOL,
                ERROR_MSG_PROTOCOL,
                b"d1:eli203e14:Protocol Errore1:t2:aa1:y1:ee",
            ),
            (
                ERROR_METHOD_UNKNOWN,
                ERROR_MSG_METHOD_UNKNOWN,
                b"d1:eli204e14:Method Unknowne1:t2:aa1:y1:ee",
            ),
        ];
        for (code, message, wire) in &cases {
            let msg = DhtMessage::Error(ErrorMessage {
                transaction_id: b"aa".to_vec(),
                code: *code,
                message: message.to_vec(),
                version: None,
            });
            assert_eq!(&enc(&msg), wire, "code = {code}");
            assert_eq!(dec(wire), msg, "code = {code} roundtrip");
        }
    }

    /// Error reply classification matrix (table-driven; sources and the
    /// silent-face rationale are in the [`incoming_error_reply`] docs —
    /// BEP5 "Errors" code list + libtorrent node.cpp).
    #[test]
    fn incoming_error_reply_classification_matrix() {
        #![allow(clippy::type_complexity)] // single table-driven (message, expected) tuple
        // (message, expected classification)
        let cases: Vec<(&[u8], Option<(i64, &[u8], &[u8])>)> = vec![
            // Known method + missing argument (find_node without target) → 203.
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:q9:find_node1:t2:aa1:y1:qe",
                Some((ERROR_PROTOCOL, b"aa", ERROR_MSG_PROTOCOL)),
            ),
            // q missing (y="q" but no method name, only a/t/y) → 203 (malformed packet).
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:t2:aa1:y1:qe",
                Some((ERROR_PROTOCOL, b"aa", ERROR_MSG_PROTOCOL)),
            ),
            // Unknown method name → 204 (BEP5 "Method Unknown").
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:q7:unknown1:t2:bb1:y1:qe",
                Some((ERROR_METHOD_UNKNOWN, b"bb", ERROR_MSG_METHOD_UNKNOWN)),
            ),
            // ---- Silent faces ----
            // bencode garbage.
            (b"\x00garbage", None),
            // Top level not a dict.
            (b"i1e", None),
            // y missing.
            (b"d1:t2:aae", None),
            // y not q/r/e.
            (b"d1:t2:aa1:y1:ze", None),
            // Response face (y="r") never gets an error reply (anti-reflection).
            (b"d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re", None),
            // Error face (y="e") never gets an error reply.
            (b"d1:eli201e3:erre1:t2:aa1:y1:ee", None),
            // t missing (no tid to echo).
            (b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:y1:qe", None),
            // A well-formed query (proves the classifier only serves malformed paths).
            (
                b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
                None,
            ),
        ];
        for (input, expected) in &cases {
            let got = incoming_error_reply(input);
            let expected = expected.map(|(code, tid, message)| ErrorMessage {
                transaction_id: tid.to_vec(),
                code,
                message: message.to_vec(),
                version: None,
            });
            assert_eq!(&got, &expected, "input = {input:?}");
        }
        // The tid echoes at any length (decode is unbounded, see module docs; local generation is 4B).
        let got = incoming_error_reply(
            b"d1:ad2:id20:abcdefghij0123456789e1:q7:unknown1:t7:abcdeef1:y1:qe",
        );
        assert_eq!(
            got.map(|e| e.transaction_id),
            Some(b"abcdeef".to_vec()),
            "tid echoed verbatim"
        );
    }

    // ===== property tests =====

    use proptest::prelude::*;

    fn arb_id() -> impl Strategy<Value = NodeId> {
        (prop::collection::vec(any::<u8>(), 20..=20)).prop_map(|v| {
            let mut a = [0u8; 20];
            a.copy_from_slice(&v);
            NodeId(a)
        })
    }

    fn arb_addr_v4() -> impl Strategy<Value = SocketAddr> {
        (any::<[u8; 4]>(), any::<u16>())
            .prop_map(|(o, p)| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(o), p.max(1))))
    }

    fn arb_addr_v6() -> impl Strategy<Value = SocketAddr> {
        (any::<[u8; 16]>(), any::<u16>())
            .prop_map(|(o, p)| SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(o), p.max(1), 0, 0)))
    }

    /// get_peers values list: single family only (the generator was narrowed
    /// from per-element v4/v6 mixing — BEP32 forbids sending hybrid lists
    /// and the encoder rejects them, so the domain shrinks to one family;
    /// hybrid **decode** compatibility is unaffected and covered by the
    /// legacy mixed-list regression test).
    fn arb_values() -> impl Strategy<Value = Vec<SocketAddr>> {
        any::<bool>().prop_flat_map(|is_v4| {
            let addr: proptest::strategy::BoxedStrategy<SocketAddr> = if is_v4 {
                arb_addr_v4().boxed()
            } else {
                arb_addr_v6().boxed()
            };
            prop::collection::vec(addr, 0..10)
        })
    }

    fn arb_token() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..32)
    }

    /// BEP32 want, all four shapes (∅/n4/n6/dual stack). ∅ (absent) writes
    /// no key when encoding and decodes back to default — the roundtrip
    /// closes.
    fn arb_want() -> impl Strategy<Value = WantFamilies> {
        (any::<bool>(), any::<bool>()).prop_map(|(v4, v6)| WantFamilies { v4, v6 })
    }

    fn arb_query() -> impl Strategy<Value = QueryMessage> {
        (
            prop::collection::vec(any::<u8>(), 0..8),
            arb_id(),
            prop_oneof![
                Just(QueryBody::Ping),
                (arb_id(), arb_want())
                    .prop_map(|(t, w)| QueryBody::FindNode { target: t, want: w }),
                (arb_id(), arb_want()).prop_map(|(h, w)| QueryBody::GetPeers {
                    info_hash: h,
                    want: w
                }),
                (
                    arb_id(),
                    // port generation domain = the upstream acceptance domain 1..=65534
                    // (validatePort, DHTMessageFactoryImpl.cc: open interval 0<p<65535;
                    // implied_port does not relax it — aria2 never parses that field, so
                    // validatePort applies unconditionally).
                    (1u16..65535),
                    arb_token(),
                    proptest::option::of(any::<bool>()),
                )
                    .prop_map(|(h, p, tok, imp)| QueryBody::AnnouncePeer {
                        info_hash: h,
                        port: p,
                        token: tok,
                        implied_port: imp,
                    }),
            ],
            proptest::option::of(prop::collection::vec(any::<u8>(), 0..8)),
        )
            .prop_map(|(tid, id, body, v)| QueryMessage {
                transaction_id: tid,
                sender_id: id,
                body,
                version: v,
            })
    }

    /// nodes list: v4 entries first, v6 entries after (canonical merged
    /// order — the dual-key decode concatenates nodes then nodes6, so the
    /// roundtrip `decode(encode(m)) == m` is anchored to that order; mixed
    /// lists are encodable since the BEP32 want dual-key split).
    fn arb_nodes() -> impl Strategy<Value = Vec<NodeInfo>> {
        prop::collection::vec((arb_id(), prop_oneof![arb_addr_v4(), arb_addr_v6()]), 0..10)
            .prop_map(|v| {
                let infos: Vec<NodeInfo> = v
                    .into_iter()
                    .map(|(id, addr)| NodeInfo { id, addr })
                    .collect();
                let mut v4: Vec<NodeInfo> =
                    infos.iter().filter(|n| n.addr.is_ipv4()).cloned().collect();
                let v6: Vec<NodeInfo> =
                    infos.iter().filter(|n| n.addr.is_ipv6()).cloned().collect();
                v4.extend(v6);
                v4
            })
    }

    fn arb_response() -> impl Strategy<Value = ResponseMessage> {
        (
            prop::collection::vec(any::<u8>(), 0..8),
            arb_id(),
            prop_oneof![
                Just(ResponseBody::Ping),
                arb_nodes().prop_map(|nodes| ResponseBody::FindNode { nodes }),
                (arb_token(), arb_nodes(), arb_values()).prop_map(|(token, nodes, values)| {
                    ResponseBody::GetPeers {
                        token,
                        nodes,
                        values,
                    }
                }),
            ],
            // Top-level ip (BEP42): all three shapes None / v4 / v6 join the roundtrip.
            proptest::option::of(prop_oneof![arb_addr_v4(), arb_addr_v6()]),
            proptest::option::of(prop::collection::vec(any::<u8>(), 0..8)),
        )
            .prop_map(|(tid, id, body, ip, v)| ResponseMessage {
                transaction_id: tid,
                responder_id: id,
                body,
                requester_endpoint: ip,
                version: v,
            })
    }

    fn arb_error() -> impl Strategy<Value = ErrorMessage> {
        (
            prop::collection::vec(any::<u8>(), 0..8),
            any::<i64>(),
            prop::collection::vec(any::<u8>(), 0..32),
        )
            .prop_map(|(tid, code, message)| ErrorMessage {
                transaction_id: tid,
                code,
                message,
                version: None,
            })
    }

    proptest! {
            #![proptest_config(proptest::test_runner::Config::with_cases(512))]

    /// Decoding arbitrary bytes never panics (message layer; the bencode layer has its own coverage).
            #[test]
            fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..4096)) {
                let _ = decode_message(&data);
                }

    /// Encode → decode roundtrip for query/response/error messages.
            #[test]
            fn query_roundtrip(m in arb_query()) {
                let wire = match encode_message(&DhtMessage::Query(m.clone())) {
                    Ok(w) => w,
                    Err(e) => panic!("encode failed: {e:?}"),
                    };
                let back = decode_message(&wire);
                prop_assert_eq!(back, Ok(DhtMessage::Query(m)));
                }

            #[test]
            fn response_roundtrip(m in arb_response()) {
                let wire = match encode_message(&DhtMessage::Response(m.clone())) {
                    Ok(w) => w,
                    Err(e) => panic!("encode failed: {e:?}"),
                    };
                let back = decode_message(&wire);
                prop_assert_eq!(back, Ok(DhtMessage::Response(m)));
                }

            #[test]
            fn error_roundtrip(m in arb_error()) {
                let wire = match encode_message(&DhtMessage::Error(m.clone())) {
                    Ok(w) => w,
                    Err(e) => panic!("encode failed: {e:?}"),
                    };
                let back = decode_message(&wire);
                prop_assert_eq!(back, Ok(DhtMessage::Error(m)));
                }
            }
}

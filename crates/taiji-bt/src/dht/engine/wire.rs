//! Inbound/outbound message face: query sending with transaction
//! registration (send_query), inbound packet dispatch (handle_packet →
//! on_query / transaction settlement in on_transaction_done), peer-record
//! storage for other nodes' announces, and transaction timeout sweeps.
//!
//! Scope: KRPC messages in and out plus transaction routing (mirrors
//! DHTMessageReceiver/DHTMessageTracker). Out of scope: task state-machine
//! progress (tasks) and the command/maintenance faces
//! (command/maintenance).
//!
//! Upstream anchor mapping: docs/design/dht.md

use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use rand::RngExt;
use std::collections::HashMap;

use taiji_io::udp_demux::{InboundPacket, OutboundPacket};
use tokio::sync::oneshot;
use tracing::{debug, warn};

use super::*;
use crate::dht::compact::NodeInfo;
use crate::dht::transaction::PendingTransaction;

/// Cap on peer-record info_hash keys: an engineering hardening (see the
/// crate::dht module docs).
pub(super) const MAX_PEER_RECORD_KEYS: usize = 4096;

/// Cap on peer records per info_hash key (previously an unbounded Vec per
/// key: a 65k-entry flood implied ~10GB of memory). The value mirrors
/// libtorrent's per-torrent storage capacity `dht_max_peers` (default 500,
/// src/settings_pack.cpp; at capacity "we're at capacity, drop the
/// announce", src/kademlia/dht_storage.cpp). Eviction evicts the oldest
/// entries when full (by updated time); the intentional divergence from
/// upstream's "drop the new announce" and its rationale live in the
/// `state::PeerRecordSet` docs.
pub(super) const MAX_PEER_RECORDS_PER_KEY: usize = 500;

/// Hard cap on **total** peer records across all keys: the key cap x
/// per-key cap product (4096 x 500 x ~64B/entry ≈ 131MB per instance, and
/// DHT engines run multiple instances per task x family) collapses to a
/// total bound. 8192 covers real shapes — honest swarms announce at most
/// a few hundred entries per infohash and active infohashes are far below
/// the key cap — for a structural bound of ≈8192 x ~64B + 4096 keys of
/// overhead ≈ **~1MB per instance** (vs 131MB). Over the cap, whole keys
/// are evicted in ascending "newest update" order (the just-admitted
/// anchor key is spared the first cut — with <= 500 entries per key <<
/// the cap, skipping it does not prevent convergence).
pub(super) const MAX_PEER_RECORDS_TOTAL: usize = 8192;

/// Cap on get_peers reply values entries. Mirrors libtorrent's reply
/// sampling cap `dht_max_peers_reply` (default 100, src/settings_pack.cpp,
/// dht_storage.cpp); this implementation takes the more conservative half,
/// further narrowing the small-query-large-reply reflection surface.
pub(super) const MAX_VALUES_PER_REPLY: usize = 50;

/// Cap on the encoded whole reply frame (the hard BEP32 "DHT Size" limit,
/// replacing the old values-only 1400B byte gate): "A node obeying this
/// specification must not send UDP datagrams with a payload larger than
/// 1024 octets" — justified by "a UDP datagram with a payload of 1024
/// octets easily fits within the IPv6 minimum maximum packet size, which
/// is 1280 octets" (fragment-free). The unit is the **encoded complete
/// KRPC frame** (bencode shell + id/token/ip + nodes/nodes6 + per-value
/// string shells); enforcement is [`fit_reply_frame`] (trim values entry
/// by entry, then nodes).
pub(super) const MAX_REPLY_FRAME_BYTES: usize = 1024;

fn key_of(transaction_id: &[u8], addr: SocketAddr) -> Option<TransactionKey> {
    let transaction_id: [u8; 4] = transaction_id.try_into().ok()?;
    Some(TransactionKey {
        transaction_id,
        addr,
    })
}

/// Bounded selection of get_peers reply values (anti-reflection
/// amplification).
///
/// Records are first filtered by the request's network layer (family
/// semantics as-is: the values family always follows the request's network
/// layer; BEP32 want does not govern values), then capped at
/// [`MAX_VALUES_PER_REPLY`] entries; the byte face is guarded by the
/// whole-frame gate [`fit_reply_frame`] (BEP32 1024B, superseding the old
/// values-only 1400B gate). The number of truncated **same-family**
/// records is returned for the counter (filtering of other-family records
/// is family semantics and does not count as truncation). Upstream
/// anchor: libtorrent samples replies at `dht_max_peers_reply` (default
/// 100, src/settings_pack.cpp) randomly (src/kademlia/dht_storage.cpp);
/// this implementation keeps the more conservative 50, and its
/// non-deterministic subset (HashMap iteration order) matches upstream's
/// random-sampling flavor.
///
/// # Interaction with the two existing limiters (complementary, disjoint)
///
/// Reflected traffic = accepted queries x bytes per reply; two independent
/// mechanisms clamp the two factors: the inbound per-source query limiter
/// (`query_limit`, 25pps + suppression) governs the **count**; this
/// truncation governs **bytes per reply** (get_peers face; the error face
/// answers nothing once over budget). This module does not change either
/// limiter's semantics — even for sources within budget (multi-source
/// botnets / exempt sources) a single reply stays bounded:
/// **boundedness does not rely on rate limiting as a backstop**, and the
/// limiters do not rely on reply size.
fn bounded_values(set: &PeerRecordSet, request_v4: bool) -> (Vec<SocketAddr>, usize) {
    let mut values = Vec::new();
    let mut dropped = 0usize;
    for addr in set.iter().map(|(addr, _)| addr) {
        if addr.is_ipv4() != request_v4 {
            continue; // family filter, not truncation.
        }
        if values.len() >= MAX_VALUES_PER_REPLY {
            dropped += 1;
            continue;
        }
        values.push(*addr);
    }
    (values, dropped)
}

/// Trim bookkeeping for the whole-frame gate (folded into `values_truncated_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct FrameTrim {
    values: usize,
    nodes: usize,
}

/// BEP32 whole-reply-frame gate (pure function): the **encoded complete
/// KRPC frame** must be <= [`MAX_REPLY_FRAME_BYTES`] (1024B, quote in the
/// constant docs). Over the limit, values are trimmed entry by entry
/// first, then nodes (a get_peers reply keeps at least the legal id +
/// token shape — the token is the announce_peer precondition and must not
/// be emptied), re-encoding after each trim until compliant. With nothing
/// left to trim (Ping body / both lists empty) and still over the limit —
/// e.g. a peer queried with an oversized tid that the reply must echo —
/// returns [`crate::dht::DhtError::ReplyFrameTooLarge`]: better to skip
/// the reply than violate the 1024 cap (the querier loses one reply; no
/// protocol state is corrupted).
///
/// Hot-path shape: the common case (a frame already within the
/// cap) encodes exactly once from the borrowed reply with **no clone**;
/// the trim loop — one message clone per removed entry and one re-encode
/// per step — runs only for over-cap frames (get_peers replies carrying
/// stored values; the trim result is byte-identical to the previous
/// unconditional-clone shape).
fn fit_reply_frame(reply: &ResponseMessage) -> Result<(Vec<u8>, FrameTrim), crate::dht::DhtError> {
    // Clone-on-demand: only an over-cap frame pays for a mutable copy.
    let mut cur: Option<ResponseMessage> = None;
    let mut trim = FrameTrim::default();
    loop {
        let wire = match &cur {
            Some(msg) => encode_response(msg)?,
            None => encode_response(reply)?,
        };
        if wire.len() <= MAX_REPLY_FRAME_BYTES {
            return Ok((wire, trim));
        }
        // First overflow: take the mutable copy the trim loop mutates.
        let msg = match cur.as_mut() {
            Some(m) => m,
            None => cur.insert(reply.clone()),
        };
        if !shrink_one(msg, &mut trim) {
            return Err(crate::dht::DhtError::ReplyFrameTooLarge { len: wire.len() });
        }
    }
}

/// One trim step: values first, then nodes (the documented order); returns
/// whether anything was trimmed (false = nothing left to trim).
fn shrink_one(reply: &mut ResponseMessage, trim: &mut FrameTrim) -> bool {
    match &mut reply.body {
        ResponseBody::GetPeers { values, nodes, .. } => {
            if !values.is_empty() {
                values.pop();
                trim.values += 1;
                true
            } else if !nodes.is_empty() {
                nodes.pop();
                trim.nodes += 1;
                true
            } else {
                false
            }
        }
        ResponseBody::FindNode { nodes } => {
            if !nodes.is_empty() {
                nodes.pop();
                trim.nodes += 1;
                true
            } else {
                false
            }
        }
        ResponseBody::Ping => false,
    }
}

/// BEP32 want → the reply's nodes family set: an explicit non-empty want
/// is used as-is; otherwise the request family ("In the absence of a
/// "want" parameter, the reply should include "nodes" if the request was
/// sent over IPv4, and should include "nodes6" if the request was sent
/// over IPv6"). A want present without recognized values (empty list /
/// all-unknown strings) falls back to the request family too — an
/// "explicitly empty" set gets a BEP5-equivalent reply rather than zero
/// node keys (a lenient-side choice; the codec-side element-ignoring rule
/// is `message::parse_want`).
fn effective_want(want: WantFamilies, from: SocketAddr) -> WantFamilies {
    if want.any() {
        want
    } else if from.is_ipv4() {
        WantFamilies::single_v4()
    } else {
        WantFamilies::single_v6()
    }
}

fn to_dht_nodes(infos: &[NodeInfo]) -> Vec<DhtNode> {
    infos.iter().map(|i| DhtNode::new(i.id, i.addr)).collect()
}

/// Total-cap enforcer (pure function): while `total > cap`, whole keys are
/// evicted in ascending "newest update" order; `anchor` (the key just
/// admitted) is spared the first cut — with <= [`MAX_PEER_RECORDS_PER_KEY`]
/// entries per key << the cap, skipping it does not prevent convergence
/// (cap 8192, <=500 per key: at most 500 entries are skipped while >= 7692
/// can still be released). On return `total` matches the entries in
/// `records` (saturating convergence).
fn enforce_peer_records_total_cap(
    records: &mut HashMap<NodeId, PeerRecordSet>,
    total: &mut usize,
    anchor: &NodeId,
) {
    if *total <= MAX_PEER_RECORDS_TOTAL {
        return;
    }
    let mut victims: Vec<(NodeId, Option<Instant>)> =
        records.iter().map(|(k, set)| (*k, set.newest())).collect();
    // None (an empty set, theoretically only in a maintenance gap) sorts as the oldest, evicted first.
    victims.sort_by_key(|(_, newest)| *newest);
    for (key, _) in victims {
        if *total <= MAX_PEER_RECORDS_TOTAL {
            break;
        }
        if &key == anchor {
            continue;
        }
        if let Some(evicted) = records.remove(&key) {
            *total = total.saturating_sub(evicted.len());
        }
    }
}

impl DhtEngine {
    /// Sends a query; with `task_id` = Some it registers the transaction +
    /// route (tracked), with None it is fire-and-forget (announce_peer;
    /// upstream DHTPeerLookupTask::onFinish enqueues no callback). Returns
    /// false = the send failed (outbound channel closed / encoding error).
    ///
    /// Observation feeding point: one per-kind query is counted by `method`
    /// only after the outbound enqueue **succeeds** (encode failures / channel
    /// closure do not count — nothing left the machine, so no query happened).
    /// No behavior change — counting only; no control-flow branch reads the
    /// counters.
    pub(super) async fn send_query(
        &mut self,
        task_id: Option<TaskId>,
        node: &DhtNode,
        body: QueryBody,
        method: MessageKind,
        now: Instant,
    ) -> bool {
        let mut transaction_id = [0u8; 4];
        self.rng.fill(&mut transaction_id);
        let query = QueryMessage {
            transaction_id: transaction_id.to_vec(),
            sender_id: self.local_id,
            body,
            version: None,
        };
        let wire = match encode_message(&DhtMessage::Query(query)) {
            Ok(w) => w,
            Err(e) => {
                warn!(target: LOG_TARGET, error = %e, "encode query failed");
                return false;
            }
        };
        let pkt = OutboundPacket {
            to: node.addr(),
            data: Bytes::from(wire),
        };
        if self.transport.outbound.send(pkt).await.is_err() {
            warn!(target: LOG_TARGET, "outbound channel closed; query dropped");
            return false;
        }
        match method {
            MessageKind::Ping => self.queries_ping_total += 1,
            MessageKind::FindNode => self.queries_find_node_total += 1,
            MessageKind::GetPeers => self.queries_get_peers_total += 1,
            MessageKind::AnnouncePeer => self.queries_announce_peer_total += 1,
        }
        if let Some(id) = task_id {
            // oneshot receipt: the engine is a single-task actor and consumes the
            // transaction result inline in this module (responses/sweeps drive the
            // task state machine directly); the channel exists only to satisfy the
            // transaction-table signature, the receiver is discarded immediately.
            let (tx, _rx) = oneshot::channel();
            let _ = self.txns.register(
                transaction_id,
                node.addr(),
                method,
                self.cfg.message_timeout,
                tx,
                now,
            );
            let key = TransactionKey {
                transaction_id,
                addr: node.addr(),
            };
            self.route.insert(
                key,
                RouteTarget {
                    task_id: id,
                    node: node.clone(),
                },
            );
        }
        true
    }

    pub(super) async fn handle_packet(&mut self, pkt: InboundPacket, now: Instant) {
        self.inbound_packets_total = self.inbound_packets_total.saturating_add(1);
        // Early-drop gate (inbound hot path): a y="r"/y="e" frame whose
        // (t, addr) matches no pending transaction is dropped before the
        // full bencode decode. Outcome-equivalent to the previous shape —
        // the decode-then-pop path's pop-None arm is also a silent drop,
        // and a decode-failing r/e frame was silent too (the y != q face
        // of incoming_error_reply) with the transaction left pending for
        // the timeout sweep; the lenient header scanner falls back to the
        // full strict decode whenever it cannot locate both keys, so
        // malformed-input handling (including the 203/204 query-face
        // classification) is untouched.
        if let Some((tid, y)) = scan_transaction_header(&pkt.data)
            && (y == b"r" || y == b"e")
            && !self.txns.contains(tid, pkt.from)
        {
            self.inbound_unmatched_drops_total =
                self.inbound_unmatched_drops_total.saturating_add(1);
            return;
        }
        let msg = match decode_message(&pkt.data) {
            Ok(m) => m,
            Err(e) => {
                // Malformed packets: a query face that is decodable bencode with y="q"
                // and an echoable t answers 203/204 per BEP5 "Errors" (via the per-source
                // limiter); everything else (bencode garbage / non-dict / y != q / t not
                // extractable) is silent — libtorrent explicitly does not answer
                // missing-y to prevent amplification (src/kademlia/node.cpp). The
                // classification sources are in the message::incoming_error_reply docs.
                debug!(target: LOG_TARGET, from = %pkt.from, error = %e, "malformed dht packet");
                if let Some(err) = incoming_error_reply(&pkt.data) {
                    self.send_error_reply(pkt.from, err, now).await;
                }
                return;
            }
        };
        match msg {
            DhtMessage::Query(q) => {
                self.inbound_queries_total = self.inbound_queries_total.saturating_add(1);
                self.on_query(q, pkt.from, now).await;
            }
            DhtMessage::Response(r) => {
                let Some(key) = key_of(&r.transaction_id, pkt.from) else {
                    debug!(target: LOG_TARGET, "reply with non-4B tid dropped");
                    return;
                };
                let Some(pending) = self.txns.pop(&r.transaction_id, pkt.from) else {
                    debug!(target: LOG_TARGET, from = %pkt.from, "reply without transaction dropped");
                    return;
                };
                self.on_transaction_done(
                    key,
                    pending,
                    TransactionOutcome::Response(Box::new(r)),
                    now,
                )
                .await;
            }
            DhtMessage::Error(e) => {
                let Some(key) = key_of(&e.transaction_id, pkt.from) else {
                    debug!(target: LOG_TARGET, "error reply with non-4B tid dropped");
                    return;
                };
                let Some(pending) = self.txns.pop(&e.transaction_id, pkt.from) else {
                    debug!(target: LOG_TARGET, from = %pkt.from, "error reply without transaction dropped");
                    return;
                };
                self.on_transaction_done(key, pending, TransactionOutcome::Error(Box::new(e)), now)
                    .await;
            }
        }
    }

    /// Single exit for error replies: per-source token-bucket limiting
    /// ([`ERROR_REPLY_BURST`] / `ERROR_REPLY_RATE_PER_MIN`; trade-offs in the
    /// error_limit module docs); **over budget = silent, no reply** — an
    /// error reply returns bytes roughly 1:1 to the malformed query, so
    /// unbounded error replies are an amplification surface. Admitted replies
    /// go through the existing outbound channel (topology). Called only on
    /// the query path (inbound responses/errors never reach here, preventing
    /// reflection).
    async fn send_error_reply(&mut self, to: SocketAddr, mut err: ErrorMessage, now: Instant) {
        if !self.error_limiter.admit(to.ip(), now) {
            debug!(target: LOG_TARGET, to = %to, "error reply budget exhausted; dropped silently");
            return;
        }
        err.version = None;
        match encode_message(&DhtMessage::Error(err)) {
            Ok(wire) => {
                let pkt = OutboundPacket {
                    to,
                    data: Bytes::from(wire),
                };
                if self.transport.outbound.send(pkt).await.is_err() {
                    warn!(target: LOG_TARGET, "outbound channel closed; error reply dropped");
                }
            }
            Err(e) => warn!(target: LOG_TARGET, error = %e, "encode error reply failed"),
        }
    }

    /// Query answering (mirrors each `DHT*Message::doReceivedAction`; the
    /// query sender is markGood + addGoodNode, `DHTMessageReceiver.cc`).
    ///
    /// BEP42 enforcement applies only to the **storage face** (enforcement
    /// section: "MUST never be used to store information on"; the routing/
    /// service face has no exclusion requirement — "Requests ... should
    /// always be serviced"). Mainstream bootstrap routers
    /// (dht.transmissionbt.com) carry non-compliant ids, so excluding them
    /// would cut off bootstrap; libtorrent also keeps them in the table
    /// (node_entry verified flag + replacement preference, node_entry.cpp /
    /// routing_table.cpp). This implementation neither excludes nor
    /// downranks (the preference face remains open).
    async fn on_query(&mut self, q: QueryMessage, from: SocketAddr, now: Instant) {
        // Per-source inbound query rate limiting + offender suppression (the
        // pre-check of query handling; rules in the query_limit module docs): an
        // empty bucket drops silently; sustained excess suppresses the source for
        // suppress_secs, then auto-recovers; bootstrap/PORT entry sources are
        // exempt (preserving BEP42 "Requests ... should always be serviced", see
        // the engine module docs security-extension section). Inbound
        // responses/errors never pass here (closing the reflection loop); the
        // decode-failure arm and bad-token error replies are not subject to this
        // limiter — error_limit clamps them per source independently (the two
        // limiter tiers govern separate faces and coexist).
        if !self.query_limiter.admit_query(from.ip(), now) {
            debug!(target: LOG_TARGET, from = %from, "inbound query dropped (per-source rate limit/suppression)");
            return;
        }
        // Queries carrying our own id are dropped (DHTMessageReceiver.cc).
        if q.sender_id == self.local_id {
            debug!(target: LOG_TARGET, from = %from, "drop query from localnode id");
            return;
        }
        let sender_verified = self.inbound_id_ok(&q.sender_id, from);
        self.table
            .add_contacted_node(DhtNode::new(q.sender_id, from), now);
        let body = match &q.body {
            QueryBody::Ping => ResponseBody::Ping,
            // BEP32 want reply keys: the nodes family set follows the request's want
            // (n4 → nodes key, n6 → nodes6 key; no want → the request family's single
            // key, quote in [`effective_want`]); the codec splits the dual keys by
            // family (`message::pack_nodes_split`), this side only filters the family
            // set.
            QueryBody::FindNode { target, want } => ResponseBody::FindNode {
                nodes: self.closest_nodes_for_want(target, effective_want(*want, from)),
            },
            QueryBody::GetPeers { info_hash, want } => {
                // token + local peer records + closest K (DHTGetPeersMessage
                // doReceivedAction; nodes/values encoded only when non-empty, codec).
                let token = self.token.generate(from).to_vec();
                // values is always a single key of a single family: peer records are
                // filtered by the **request's network layer** — BEP32 "Changes to
                // get_peers": "a list of 6-octet strings if the request was sent over
                // IPv4, and a list of 18-octet strings if the request was sent over
                // IPv6"; hybrid lists must not be sent ("must not send hybrid lists in a
                // reply to an IPv4 request that doesn't contain a "want" parameter"; the
                // codec enforces the same rule via MixedAddressFamilies). want does not
                // govern values (BEP32 only "governs ... the "nodes" and "nodes6"
                // parameters"). Upstream anchors: libtorrent dht_storage.cpp
                // (`requester.is_v4() ? peers4 : peers6`, single-key values); aria2 is
                // shaped the same (DHTGetPeersReplyMessage.cc filters by family_).
                //
                // Selection is truncated by the entry cap plus the 1024B whole-frame gate
                // (anti-reflection-amplification; libtorrent samples replies in
                // dht_storage.cpp): the reply a ~90B query buys is always bounded,
                // complementing the per-source query limiter (inbound count) and the
                // error limiter (error-reply face) — bytes-per-reply x accepted-queries
                // are clamped as two independent factors (boundary interaction in the
                // `bounded_values` docs).
                let (values, dropped) = match self.peer_records.get(info_hash) {
                    Some(set) => bounded_values(set, from.is_ipv4()),
                    None => (Vec::new(), 0),
                };
                if dropped > 0 {
                    self.values_truncated_total = self
                        .values_truncated_total
                        .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
                    debug!(target: LOG_TARGET, from = %from, kept = values.len(),
                        dropped, total = self.values_truncated_total,
                        "get_peers values truncated (boundedness)");
                }
                let nodes = self.closest_nodes_for_want(info_hash, effective_want(*want, from));
                ResponseBody::GetPeers {
                    token,
                    nodes,
                    values,
                }
            }
            QueryBody::AnnouncePeer {
                info_hash,
                port,
                token,
                implied_port,
            } => {
                // The token matches either of the last two generations
                // (DHTTokenTracker.cc); a mismatch → a 203 error reply (BEP5 "Errors"
                // code list, 203 = "Protocol Error, such as a malformed packet, invalid
                // arguments, or bad token"; libtorrent's verify_token failure answers
                // incoming_error(e, "invalid token") with the default 203,
                // src/kademlia/node.cpp). Subject to the per-source limiter; over budget
                // it is silent.
                if !self.token.validate(token, from) {
                    debug!(target: LOG_TARGET, from = %from,
                        "announce_peer with invalid token; replying 203 (rate-limited)");
                    let err = ErrorMessage {
                        transaction_id: q.transaction_id.clone(),
                        code: ERROR_PROTOCOL,
                        message: ERROR_MSG_PROTOCOL.to_vec(),
                        version: None,
                    };
                    self.send_error_reply(from, err, now).await;
                    return;
                }
                // implied_port=1 → the UDP source port (BEP5; aria2 never parses the
                // field — see the crate::dht module docs divergence list). The port is
                // already domain-validated by the codec (0 < p < 65535).
                let port = if *implied_port == Some(true) {
                    from.port()
                } else {
                    *port
                };
                if sender_verified {
                    self.record_announced_peer(*info_hash, from, port, now);
                } else {
                    // BEP42: an announce from a non-compliant id is not stored (enforcement
                    // section); the reply is still sent (the Ping body below covers both).
                    debug!(target: LOG_TARGET, from = %from,
                        "announce_peer from non-compliant node id not stored (BEP42)");
                }
                ResponseBody::Ping
            }
        };
        let reply = ResponseMessage {
            transaction_id: q.transaction_id,
            responder_id: self.local_id,
            body,
            // BEP42 "Bootstrapping": the reply's top-level `ip` reports the
            // requester's observed endpoint ("all DHT responses SHOULD include a
            // top-level field called ip, containing a compact binary representation
            // of the requestor's IP and port"; the 6B/18B encoding and the
            // upstream/libtorrent comparison are in message.rs
            // `ResponseMessage::requester_endpoint`). Error replies (y=e, the
            // bad-token path above) do not carry it — libtorrent's `incoming_request`
            // writes `e["ip"]` after the verify_message failure branch, so the
            // incoming_error path has no ip.
            requester_endpoint: Some(from),
            version: None,
        };
        // BEP32 whole-frame gate: the encoded complete frame is <= 1024B (over
        // the limit, values are trimmed first, then nodes; with nothing trimmable
        // the reply is not sent, see [`fit_reply_frame`]). The values entries
        // trimmed by the frame gate join the truncation counter (together with
        // the selection truncation from the entry cap; counter
        // `values_truncated_total`).
        match fit_reply_frame(&reply) {
            Ok((wire, trim)) => {
                if trim.values > 0 {
                    self.values_truncated_total = self
                        .values_truncated_total
                        .saturating_add(u64::try_from(trim.values).unwrap_or(u64::MAX));
                    debug!(target: LOG_TARGET, from = %from, values_trimmed = trim.values,
                        nodes_trimmed = trim.nodes, total = self.values_truncated_total,
                        "reply frame trimmed to BEP32 1024-octet cap");
                }
                let pkt = OutboundPacket {
                    to: from,
                    data: Bytes::from(wire),
                };
                if self.transport.outbound.send(pkt).await.is_err() {
                    warn!(target: LOG_TARGET, "outbound channel closed; reply dropped");
                }
            }
            Err(e) => warn!(target: LOG_TARGET, error = %e, "reply dropped (frame gate)"),
        }
    }

    /// Peer records for other nodes' announces
    /// (DHTPeerAnnounceStorage::addPeerAnnounce: addr dedup + notifyUpdate;
    /// the key-count cap is an engineering hardening, see the crate::dht
    /// module docs; the per-key cap, dedup and eviction rules are in the
    /// `state::PeerRecordSet` docs — O(1) hash dedup + evict-oldest when
    /// full).
    fn record_announced_peer(
        &mut self,
        info_hash: NodeId,
        from: SocketAddr,
        port: u16,
        now: Instant,
    ) {
        let addr = SocketAddr::new(from.ip(), port);
        let set = self.peer_records.entry(info_hash).or_default();
        let before = set.len();
        set.admit(addr, now);
        self.peer_records_total = self
            .peer_records_total
            .saturating_add(set.len().saturating_sub(before));
        if self.peer_records.len() > MAX_PEER_RECORD_KEYS {
            // Evict the oldest key (engineering hardening; upstream has no such cap).
            // The current key was just touched, so it cannot be the oldest.
            let oldest = self
                .peer_records
                .iter()
                .min_by_key(|(_, set)| set.newest())
                .map(|(k, _)| *k);
            if let Some(oldest) = oldest {
                if let Some(evicted) = self.peer_records.remove(&oldest) {
                    self.peer_records_total = self.peer_records_total.saturating_sub(evicted.len());
                }
            }
        }
        enforce_peer_records_total_cap(
            &mut self.peer_records,
            &mut self.peer_records_total,
            &info_hash,
        );
    }

    fn closest_node_infos(&self, target: &NodeId) -> Vec<NodeInfo> {
        self.table
            .get_closest_k_nodes(target)
            .into_iter()
            .map(|n| NodeInfo {
                id: *n.id(),
                addr: n.addr(),
            })
            .collect()
    }

    /// Filters the closest K nodes by the BEP32 want family set (the
    /// reply-key decider: a family not in want is filtered out whole — the
    /// codec writes no empty keys after the family split, see
    /// `message::pack_nodes_split` and [`effective_want`]). Foreign-family
    /// nodes in the table are still advertised in full to want=[n4,n6]
    /// queries (the dual-stack fast path: this node can learn the other
    /// family via either route).
    fn closest_nodes_for_want(&self, target: &NodeId, want: WantFamilies) -> Vec<NodeInfo> {
        self.closest_node_infos(target)
            .into_iter()
            .filter(|n| want.accepts(&n.addr))
            .collect()
    }

    /// Response/error settlement: table insert + RTT (responses) or timeout
    /// scoring (errors/timeouts, `DHTMessageTracker.cc`), then route back to
    /// the task.
    async fn on_transaction_done(
        &mut self,
        key: TransactionKey,
        pending: PendingTransaction,
        outcome: TransactionOutcome,
        now: Instant,
    ) {
        let route = self.route.remove(&key);
        match outcome {
            TransactionOutcome::Response(resp) => {
                let rtt = now.saturating_duration_since(pending.registered_at);
                // The responder enters the table by its wire r.id (see the crate::dht
                // module docs divergence list; BEP42 does not exclude the routing face —
                // see the on_query docs) + RTT recorded
                // (DHTMessageTracker.cc updateRTT).
                self.table
                    .add_contacted_node(DhtNode::new(resp.responder_id, key.addr), now);
                self.table
                    .record_response_rtt(&resp.responder_id, key.addr, rtt);
                let Some(RouteTarget { task_id, node }) = route else {
                    return;
                };
                let Some((queue, mut task)) = self.take_task(task_id) else {
                    return;
                };
                let mut peers_found: Vec<SocketAddr> = Vec::new();
                let mut face = DhtSwarmKind::V1;
                match &mut task {
                    Task::Ping(p) => p.on_response(),
                    Task::Lookup(l) => match &resp.body {
                        ResponseBody::GetPeers {
                            token,
                            nodes,
                            values,
                        } => {
                            face = l.face;
                            peers_found.clone_from(values);
                            l.on_response(&node, Some(token), to_dht_nodes(nodes), &self.local_id);
                        }
                        ResponseBody::FindNode { nodes } => {
                            face = l.face;
                            l.on_response(&node, None, to_dht_nodes(nodes), &self.local_id);
                        }
                        ResponseBody::Ping => {
                            face = l.face;
                            l.on_response(&node, None, Vec::new(), &self.local_id);
                        }
                    },
                    Task::Refresh(_) => {}
                }
                if !peers_found.is_empty() {
                    let info_hash = match &task {
                        Task::Lookup(l) => l.target.0,
                        _ => [0u8; 20],
                    };
                    self.emit_event(DhtEvent::PeersFound {
                        info_hash,
                        face,
                        peers: peers_found,
                    })
                    .await;
                }
                self.progress_task(queue, task_id, task, None, now).await;
            }
            TransactionOutcome::Error(_) | TransactionOutcome::Failed(_) => {
                // Error replies and timeouts share the same treatment: node scoring +
                // task onTimeout (DHTMessageTracker.cc).
                if let Some(RouteTarget { task_id, node }) = route {
                    self.table.record_timeout(node.id(), key.addr);
                    if let Some((queue, task)) = self.take_task(task_id) {
                        self.progress_task(queue, task_id, task, Some((&node, key.addr)), now)
                            .await;
                    }
                }
            }
        }
    }

    /// Transaction timeout sweep (`DHTMessageTracker.cc` handleTimeout).
    pub(super) async fn sweep_timeouts(&mut self, now: Instant) {
        for pending in self.txns.handle_timeout(now) {
            let outcome = TransactionOutcome::Failed(TransactionFailure::Timeout);
            self.on_transaction_done(pending.key, pending, outcome, now)
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            port,
        )
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port,
        )
    }

    fn addrs(n: u16, f: fn(u16) -> SocketAddr) -> Vec<SocketAddr> {
        (0..n).map(f).collect()
    }

    /// Table row: input (address set, request family) and expected (kept, truncated).
    struct SelectionCase {
        addrs: Vec<SocketAddr>,
        request_v4: bool,
        want: (usize, usize),
    }

    /// Bounded values selection (table-driven): the entry gate
    /// [`MAX_VALUES_PER_REPLY`], family filtering not counted as truncation
    /// (the byte face is guarded by the whole-frame gate [`fit_reply_frame`],
    /// see its dedicated test).
    #[test]
    fn values_selection_is_bounded_table() {
        let cases = vec![
            // Empty set → all zeros.
            SelectionCase {
                addrs: vec![],
                request_v4: true,
                want: (0, 0),
            },
            // Below the cap: all kept, zero truncated.
            SelectionCase {
                addrs: addrs(10, v4),
                request_v4: true,
                want: (10, 0),
            },
            // Entry gate: 400 v4 → exactly 50 kept, 350 truncated (the record set's
            // per-key cap is 500; the build stays under the cap to keep eviction out).
            SelectionCase {
                addrs: addrs(400, v4),
                request_v4: true,
                want: (50, 350),
            },
            // v6 has the same bound (18B/entry; the whole-frame byte face trims separately).
            SelectionCase {
                addrs: addrs(400, v6),
                request_v4: false,
                want: (50, 350),
            },
            // Family filtering is not truncation: with a v4 request the 200 v6
            // entries are all filtered (family semantics), while the 200 v4 entries
            // keep 50 under the entry gate and truncate 150.
            SelectionCase {
                addrs: addrs(200, v4).into_iter().chain(addrs(200, v6)).collect(),
                request_v4: true,
                want: (50, 150),
            },
        ];
        for (i, case) in cases.into_iter().enumerate() {
            let mut set = PeerRecordSet::default();
            let now = Instant::now();
            for a in &case.addrs {
                set.admit(*a, now);
            }
            let (values, dropped) = bounded_values(&set, case.request_v4);
            assert_eq!(values.len(), case.want.0, "case #{i}: kept");
            assert_eq!(dropped, case.want.1, "case #{i}: dropped");
        }
    }

    /// Conservative bound under production constants: same-family selection
    /// is at most [`MAX_VALUES_PER_REPLY`] entries (either family; the record
    /// set is filled to the per-key cap [`MAX_PEER_RECORDS_PER_KEY`] with no
    /// eviction involved; the byte face's whole-frame bound is locked by the
    /// `fit_reply_frame` test).
    #[test]
    fn values_production_constants_count_bound() {
        for request_v4 in [true, false] {
            let mut set = PeerRecordSet::default();
            let now = Instant::now();
            for a in addrs(
                MAX_PEER_RECORDS_PER_KEY as u16,
                if request_v4 { v4 } else { v6 },
            ) {
                set.admit(a, now);
            }
            let (values, dropped) = bounded_values(&set, request_v4);
            assert_eq!(values.len(), MAX_VALUES_PER_REPLY);
            assert_eq!(dropped, MAX_PEER_RECORDS_PER_KEY - MAX_VALUES_PER_REPLY);
        }
    }

    /// BEP32 whole-frame gate (pure function, table-driven): "A node obeying
    /// this specification must not send UDP datagrams with a payload larger
    /// than 1024 octets". A v6 large-values frame trims values until
    /// compliant while the token survives (the legal-shape floor); values
    /// exhausted and still over → trim nodes; nothing trimmable (Ping body +
    /// oversized tid echo) → [`crate::dht::DhtError::ReplyFrameTooLarge`]
    /// (better to skip the reply than violate the cap).
    #[test]
    fn fit_reply_frame_trims_to_bep32_cap() {
        // A fully loaded v6 get_peers reply: 50 values + 8 nodes + 8B token + ip.
        let reply = ResponseMessage {
            transaction_id: vec![1, 2, 3, 4],
            responder_id: NodeId([0x0f; 20]),
            body: ResponseBody::GetPeers {
                token: vec![0xAAu8; 8],
                nodes: (0..8)
                    .map(|i| NodeInfo {
                        id: NodeId([(i % 8) as u8; 20]),
                        addr: v6(6881 + i),
                    })
                    .collect(),
                values: addrs(50, v6),
            },
            requester_endpoint: Some(v6(7777)),
            version: None,
        };
        let pre = match encode_message(&DhtMessage::Response(reply.clone())) {
            Ok(w) => w,
            Err(e) => panic!("encode unexpectedly failed: {e:?}"),
        };
        assert!(
            pre.len() > MAX_REPLY_FRAME_BYTES,
            "test premise: the ungated frame really is over budget (got {}B)",
            pre.len()
        );
        let (wire, trim) = match fit_reply_frame(&reply) {
            Ok(ok) => ok,
            Err(e) => panic!("fit unexpectedly failed: {e:?}"),
        };
        assert!(
            wire.len() <= MAX_REPLY_FRAME_BYTES,
            "whole frame <= 1024B (got {}B)",
            wire.len()
        );
        assert!(
            trim.values > 0,
            "an oversized values frame must trim values first"
        );
        assert_eq!(
            trim.nodes, 0,
            "nodes untouched until values is fully trimmed"
        );
        // The trimmed frame decodes and is shape-legal (token kept, counts match, nodes intact).
        match decode_message(&wire) {
            Ok(DhtMessage::Response(r)) => match r.body {
                ResponseBody::GetPeers {
                    token,
                    nodes,
                    values,
                } => {
                    assert_eq!(
                        token.len(),
                        8,
                        "the token must not be trimmed (the announce precondition)"
                    );
                    assert_eq!(values.len(), 50 - trim.values);
                    assert_eq!(nodes.len(), 8);
                }
                other => panic!("get_peers body expected, got {other:?}"),
            },
            other => panic!("response expected, got {other:?}"),
        }

        // values exhausted and still over → trim nodes (artificially oversized: 60 x 38B units).
        let nodes_heavy = ResponseMessage {
            transaction_id: vec![1, 2, 3, 4],
            responder_id: NodeId([0x0f; 20]),
            body: ResponseBody::GetPeers {
                token: vec![0xAA; 8],
                nodes: (0..60)
                    .map(|i| NodeInfo {
                        id: NodeId([(i % 8) as u8; 20]),
                        addr: v6(6881 + i),
                    })
                    .collect(),
                values: Vec::new(),
            },
            requester_endpoint: Some(v6(7777)),
            version: None,
        };
        let (wire, trim) = match fit_reply_frame(&nodes_heavy) {
            Ok(ok) => ok,
            Err(e) => panic!("fit unexpectedly failed: {e:?}"),
        };
        assert!(wire.len() <= MAX_REPLY_FRAME_BYTES);
        assert_eq!(trim.values, 0);
        assert!(
            trim.nodes > 0,
            "nodes must be trimmed once values is exhausted"
        );
        match decode_message(&wire) {
            Ok(DhtMessage::Response(r)) => match r.body {
                ResponseBody::GetPeers { token, nodes, .. } => {
                    assert_eq!(token.len(), 8);
                    assert_eq!(nodes.len(), 60 - trim.nodes);
                }
                other => panic!("get_peers body expected, got {other:?}"),
            },
            other => panic!("response expected, got {other:?}"),
        }

        // Nothing trimmable (Ping body) + an oversized tid echo → ReplyFrameTooLarge.
        let oversize_ping = ResponseMessage {
            transaction_id: vec![0x55; 1100],
            responder_id: NodeId([0x0f; 20]),
            body: ResponseBody::Ping,
            requester_endpoint: Some(v6(7777)),
            version: None,
        };
        let got = match fit_reply_frame(&oversize_ping) {
            Err(crate::dht::DhtError::ReplyFrameTooLarge { len }) => len,
            other => panic!("ReplyFrameTooLarge expected, got {other:?}"),
        };
        assert!(
            got > MAX_REPLY_FRAME_BYTES,
            "oversized frame length reported as-is (got {got})"
        );
    }

    /// want → reply family set fallback table: explicit non-empty is used
    /// as-is (including cross-family want); absent / empty → the request
    /// family ("In the absence of a "want" parameter ...").
    #[test]
    fn effective_want_falls_back_to_request_family() {
        assert_eq!(
            effective_want(WantFamilies::BOTH, v4(1)),
            WantFamilies::BOTH
        );
        assert_eq!(
            effective_want(WantFamilies::single_v6(), v4(1)),
            WantFamilies::single_v6(),
            "v4 request + want=[n6]: explicit cross-family want takes effect as-is"
        );
        assert_eq!(
            effective_want(WantFamilies::default(), v4(1)),
            WantFamilies::single_v4(),
            "no want -> the v4 request family"
        );
        assert_eq!(
            effective_want(WantFamilies::default(), v6(1)),
            WantFamilies::single_v6(),
            "no/empty want (present but no recognized value) -> the v6 request family"
        );
    }
}

#[cfg(test)]
mod bt_total_cap {
    use super::*;
    use crate::dht::NodeId;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    type RecordMap = HashMap<NodeId, super::state::PeerRecordSet>;

    fn key(n: u8) -> NodeId {
        NodeId([n; 20])
    }

    fn fill(set: &mut super::state::PeerRecordSet, n: usize, at: Instant) {
        for i in 0..n {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, n as u8, (i >> 8) as u8, i as u8)),
                6881,
            );
            set.admit(addr, at);
        }
    }

    /// peer_records total-entry hard cap:
    /// (a) under the cap, no action; (b) over the cap (17 keys x 500 = 8500 >
    /// 8192) whole keys are evicted in ascending newest order down to the
    /// cap, the total matches the entries, the anchor survives, and the
    /// oldest key is evicted; (c) the cap value is pinned (4096 x 500 x ~64B
    /// ≈ 131MB → 8192 entries ≈ 1MB/instance).
    #[test]
    fn total_cap_evicts_oldest_keys_to_bound() {
        let t0 = Instant::now();
        // (a) Under the cap: 3 keys x 100 = 300 → no action.
        let mut records: RecordMap = HashMap::new();
        for i in 1u8..=3 {
            let mut s = super::state::PeerRecordSet::default();
            fill(&mut s, 100, t0 + Duration::from_secs(i as u64));
            records.insert(key(i), s);
        }
        let mut total: usize = records.values().map(|s| s.len()).sum();
        enforce_peer_records_total_cap(&mut records, &mut total, &key(1));
        assert_eq!(records.len(), 3, "no eviction under the cap");
        assert_eq!(total, 300);

        // (b) 17 keys x 500 = 8500 > 8192: the oldest keys are evicted whole until <= the cap.
        let mut records: RecordMap = HashMap::new();
        for i in 0u8..17 {
            let mut s = super::state::PeerRecordSet::default();
            fill(&mut s, 500, t0 + Duration::from_secs(i as u64));
            records.insert(key(i), s);
        }
        let mut total: usize = records.values().map(|s| s.len()).sum();
        assert_eq!(total, 8500, "fed 17x500");
        enforce_peer_records_total_cap(&mut records, &mut total, &key(16));
        assert!(
            total <= MAX_PEER_RECORDS_TOTAL,
            "ledger converges <= cap: {total}"
        );
        assert_eq!(
            total,
            records.values().map(|s| s.len()).sum::<usize>(),
            "ledger agrees with the entries"
        );
        assert!(records.contains_key(&key(16)), "anchor kept");
        assert!(!records.contains_key(&key(0)), "oldest key evicted whole");
    }

    /// (c) The cap value is pinned (guards against accidental rebound).
    #[test]
    fn total_cap_constant_anchored() {
        assert_eq!(MAX_PEER_RECORD_KEYS, 4096);
        assert_eq!(MAX_PEER_RECORDS_PER_KEY, 500);
        assert_eq!(MAX_PEER_RECORDS_TOTAL, 8192);
    }
}

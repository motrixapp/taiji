//! BEP42 security extension wiring: re-deriving the local node_id from
//! the external address (libtorrent `node::update_node_id`,
//! src/kademlia/node.cpp semantics) and the inbound node_id validation
//! face. The derive/verify algorithms live in [`crate::dht::security`]
//! (BEP42 text plus libtorrent node_id.cpp).
//!
//! Module name = node_id (domain-concept naming, mirroring libtorrent
//! `src/kademlia/node_id.cpp`; not BEP-number naming — consistent with
//! routing_table/security/token in this crate).
//!
//! Owns: the two engine-side wiring faces (local derive + inbound check).
//! Does not own: the outbound storage restriction (announce goes only to
//! compliant nodes, see tasks complete_task) and the algorithm
//! implementation (security).

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use tracing::{debug, info};

use super::*;

impl DhtEngine {
    /// External address update (libtorrent `node::update_node_id`,
    /// src/kademlia/node.cpp semantics): keep the current id if it still
    /// verifies for the new address (or the address is unchanged);
    /// otherwise re-derive and rebuild the routing table skeleton (every
    /// table node is kept and re-inserted — routing_table.cpp
    /// update_node_id's rule: a new id keeps the nodes, bucket boundaries
    /// are re-ranked around the new id).
    pub(super) fn update_external_ip(&mut self, ip: IpAddr) {
        if self.external_ip == Some(ip) {
            return;
        }
        let changed = self.external_ip.is_some();
        self.external_ip = Some(ip);
        if verify_node_id(&self.local_id, ip) {
            // Current id still valid (node.cpp: If our current ID is still
            // valid, don't do anything).
            return;
        }
        let new_id = security::generate_node_id(ip, &mut self.rng);
        info!(
            target: LOG_TARGET,
            family = ?self.family,
            node_id = %hex_id(&new_id),
            changed,
            "node id re-derived from external ip (BEP42)"
        );
        self.local_id = new_id;
        let nodes: Vec<DhtNode> = self
            .table
            .buckets()
            .iter()
            .flat_map(|b| b.nodes().cloned())
            .collect();
        let mut table = RoutingTable::new(new_id, Instant::now());
        for node in &nodes {
            table.add_node(node, Instant::now());
        }
        self.table = table;
    }

    /// Inbound node_id validity (BEP42 enforcement; the local-network
    /// exemption is built into security::verify_node_id). `false` = that
    /// node's announce_peer is *not stored* (the storage-refusal face);
    /// queries are still served and the node still enters the table (see
    /// [`Self::on_query`] — the BEP42 text constrains storage only).
    pub(super) fn inbound_id_ok(&self, id: &NodeId, from: SocketAddr) -> bool {
        // Exempt-address fast path and verification combined; failures
        // only log (a high-frequency face).
        let ok = verify_node_id(id, from.ip());
        if !ok {
            debug!(
                target: LOG_TARGET,
                from = %from,
                "query sender node id failed BEP42 check; not routed, service continues"
            );
        }
        ok
    }
}

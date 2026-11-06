//! K=8 K-bucket binary routing table (a direct translation of aria2
//! `DHTBucket.{h,cc}` / `DHTBucketTree.{h,cc}` / `DHTRoutingTable.{h,cc}`;
//! upstream commit 9e7273583f83e881e3ec067b523ba88724088d2f).
//!
//! Mechanism: buckets are closed [min, max] id ranges (20B byte order)
//! holding an LRS node queue plus a 2-slot replacement cache; leaves split
//! only along the local node's path (prefix < 159), and closest-K queries
//! walk down the key leaf's subtree (leaf side first) then upward over
//! sibling subtrees, filtering bad nodes.
//!
//! Hard invariant: internal tree nodes lie exactly on the local node's
//! path, so any sibling subtree hanging off the key leaf's ancestor path
//! is always a leaf and the collectUpward-style sibling collection is
//! safe (`DHTBucketTree.cc`).
//!
//! Time convention: aria2 reads `Timer`/`global::wallclock()`; this
//! implementation threads `now: Instant` explicitly so tests can inject a
//! deterministic clock.
//!
//! Upstream anchor mapping: docs/design/dht.md

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::RngExt;

use super::node::{DHT_ID_LENGTH, DhtNode, NodeId};

/// Bucket capacity. aria2 `src/DHTBucket.h` (`static const size_t K = 8`).
pub const K: usize = 8;
/// Replacement cache capacity. aria2 `src/DHTBucket.h` (`CACHE_SIZE = 2`).
pub const CACHE_SIZE: usize = 2;
/// Bucket refresh interval. aria2 `src/DHTConstants.h`
/// (`DHT_BUCKET_REFRESH_INTERVAL`).
pub const DHT_BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// One K-bucket: a closed `[min, max]` range + an LRS node queue + a replacement cache.
#[derive(Debug, Clone)]
pub struct Bucket {
    prefix_len: u32,
    min: NodeId,
    max: NodeId,
    /// Front = least recently seen (LRS). Mirrors `DHTBucket.h` ("sorted in
    /// ascending order") and the addNode push_back / moveToHead semantics.
    nodes: VecDeque<DhtNode>,
    /// Sorted by most recently seen, newest at the front (`DHTBucket.h`).
    cached: VecDeque<DhtNode>,
    last_updated: Instant,
}

impl Bucket {
    /// The full-space root bucket `[0x00…00, 0xff…ff]` (mirrors `DHTBucket.cc`).
    pub fn root(now: Instant) -> Self {
        Bucket {
            prefix_len: 0,
            min: NodeId([0u8; DHT_ID_LENGTH]),
            max: NodeId([0xffu8; DHT_ID_LENGTH]),
            nodes: VecDeque::new(),
            cached: VecDeque::new(),
            last_updated: now,
        }
    }

    /// Builds by range (for tests; mirrors `DHTBucket.cc`).
    pub fn from_range(prefix_len: u32, min: NodeId, max: NodeId, now: Instant) -> Self {
        Bucket {
            prefix_len,
            min,
            max,
            nodes: VecDeque::new(),
            cached: VecDeque::new(),
            last_updated: now,
        }
    }

    pub fn prefix_len(&self) -> u32 {
        self.prefix_len
    }

    pub fn min_id(&self) -> &NodeId {
        &self.min
    }

    pub fn max_id(&self) -> &NodeId {
        &self.max
    }

    pub fn nodes(&self) -> impl Iterator<Item = &DhtNode> {
        self.nodes.iter()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// `node_id ∈ [min, max]` (20B byte order; mirrors `DHTBucket.cc`).
    pub fn in_range(&self, node_id: &NodeId) -> bool {
        &self.min <= node_id && node_id <= &self.max
    }

    /// Appends a node (mirrors `DHTBucket.cc`, see module docs). Returns
    /// whether it entered the bucket; on failure `node` is not stored (the
    /// caller caches it as needed).
    pub fn add_node(&mut self, node: &DhtNode, now: Instant) -> bool {
        self.notify_update(now);
        match self.nodes.iter().position(|n| n.id() == node.id()) {
            Some(pos) => {
                // Already present: move to the tail (most recently seen; upstream erase + push_back).
                self.nodes.remove(pos);
                self.nodes.push_back(node.clone());
                true
            }
            None if self.nodes.len() < K => {
                self.nodes.push_back(node.clone());
                true
            }
            None => {
                // Full: the front (LRS) is evicted only when bad, then replaced (upstream DHTBucket.cc).
                if self.nodes.front().is_some_and(DhtNode::is_bad) {
                    self.nodes.pop_front();
                    self.nodes.push_back(node.clone());
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Replacement cache: push to the front, truncate to [`CACHE_SIZE`]
    /// (mirrors `DHTBucket.cc`).
    pub fn cache_node(&mut self, node: &DhtNode) {
        self.cached.push_front(node.clone());
        self.cached.truncate(CACHE_SIZE);
    }

    /// Replaces the given node with the cache front; a no-op when the cache is
    /// empty or the node is absent (mirrors `DHTBucket.cc` — aria2's dropNode
    /// is really a replacement).
    pub fn drop_node(&mut self, id: &NodeId) {
        if let Some(replacement) = self.cached.pop_front()
            && let Some(pos) = self.nodes.iter().position(|n| n.id() == id)
        {
            self.nodes.remove(pos);
            self.nodes.push_back(replacement);
        }
    }

    /// Moves to the tail (most recently seen; mirrors `DHTBucket.cc` moveToTail).
    pub fn move_to_tail(&mut self, id: &NodeId) {
        if let Some(pos) = self.nodes.iter().position(|n| n.id() == id)
            && let Some(node) = self.nodes.remove(pos)
        {
            self.nodes.push_back(node);
        }
    }

    /// Whether splitting is allowed: prefix < 159 and the local node in range
    /// (mirrors `DHTBucket.cc`).
    pub fn split_allowed(&self, local_id: &NodeId) -> bool {
        self.prefix_len < (DHT_ID_LENGTH * 8) as u32 - 1 && self.in_range(local_id)
    }

    /// Splits (mirrors `DHTBucket.cc`): returns the **lower half** as a new
    /// bucket (`[old min, max with bit prefix_len cleared]`) and turns self
    /// into the **upper half** (`[min with that bit set, old max]`); both
    /// prefix_lens increment; nodes and cache are sorted by id ownership.
    /// The new bucket gets last_updated = now (aria2's constructor reads the
    /// wallclock).
    pub fn split(&mut self, now: Instant) -> Bucket {
        let bit = self.prefix_len;
        let byte = (bit / 8) as usize;
        let mask = 0x80u8 >> (bit % 8);
        let mut left_max = self.max;
        left_max.0[byte] &= !mask;
        let mut right_min = self.min;
        right_min.0[byte] |= mask;
        let left = Bucket {
            prefix_len: self.prefix_len + 1,
            min: self.min,
            max: left_max,
            nodes: VecDeque::new(),
            cached: VecDeque::new(),
            last_updated: now,
        };
        self.prefix_len += 1;
        self.min = right_min;
        let mut left = left;
        for node in std::mem::take(&mut self.nodes) {
            if node.id() <= &left_max {
                left.nodes.push_back(node);
            } else {
                self.nodes.push_back(node);
            }
        }
        for node in std::mem::take(&mut self.cached) {
            if node.id() <= &left_max {
                left.cached.push_back(node);
            } else {
                self.cached.push_back(node);
            }
        }
        left
    }

    /// Whether the bucket needs refreshing: fewer than K nodes or not updated
    /// for 15min (mirrors `DHTBucket.cc`).
    pub fn needs_refresh(&self, now: Instant) -> bool {
        self.nodes.len() < K || now.duration_since(self.last_updated) >= DHT_BUCKET_REFRESH_INTERVAL
    }

    fn notify_update(&mut self, now: Instant) {
        self.last_updated = now;
    }

    /// Marks this bucket refreshed (engine maintenance path; mirrors
    /// `DHTBucket::notifyUpdate` — aria2's DHTBucketRefreshTask.cc calls it
    /// before dispatching a refresh lookup, preventing repeated dispatches for
    /// the same bucket within one refresh window).
    pub fn notify_refreshed(&mut self, now: Instant) {
        self.notify_update(now);
    }

    /// Exact node lookup by ID + address (mirrors `DHTBucket.cc`).
    pub fn get_node(&self, id: &NodeId, addr: SocketAddr) -> Option<&DhtNode> {
        self.nodes.iter().find(|n| n.id() == id && n.addr() == addr)
    }

    /// Mutable borrow of a bucket node (the engine-side scoring path; tests use it too).
    pub fn get_node_mut(&mut self, id: &NodeId, addr: SocketAddr) -> Option<&mut DhtNode> {
        self.nodes
            .iter_mut()
            .find(|n| n.id() == id && n.addr() == addr)
    }

    /// Collects non-bad nodes (mirrors getGoodNodes, `DHTBucket.cc`: only
    /// isBad is removed, questionable entries stay).
    fn good_nodes(&self) -> impl Iterator<Item = &DhtNode> {
        self.nodes.iter().filter(|n| !n.is_bad())
    }

    /// The first questionable node from the front (mirrors
    /// getLRUQuestionableNode, `DHTBucket.cc`).
    pub fn lru_questionable_node(&self, now: Instant) -> Option<&DhtNode> {
        self.nodes.iter().find(|n| n.is_questionable(now))
    }

    /// Generates a random ID inside the bucket range: prefix bytes copied from
    /// min, the rest random (mirrors getRandomNodeID, `DHTBucket.cc`; used by
    /// bucket refresh).
    pub fn random_id_in_range(&self, rng: &mut impl RngExt) -> NodeId {
        let mut id = [0u8; DHT_ID_LENGTH];
        rng.fill(&mut id);
        if self.prefix_len > 0 {
            // Copy min's first (prefix_len-1)/8+1 whole bytes; the tail byte's low
            // bits after the prefix are filled by min's zeros (as in aria2).
            let last = ((self.prefix_len - 1) / 8) as usize;
            id[..=last].copy_from_slice(&self.min.0[..=last]);
        }
        NodeId(id)
    }
}

/// Binary tree node: leaves hold a bucket; internal nodes hold both
/// children plus their own range (mirrors DHTBucketTreeNode; resetRelation
/// maintains min/max, `DHTBucketTree.cc`).
#[derive(Debug, Clone)]
enum TreeNode {
    Leaf(Bucket),
    Internal {
        min: NodeId,
        max: NodeId,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
}

impl TreeNode {
    fn min(&self) -> &NodeId {
        match self {
            TreeNode::Leaf(b) => b.min_id(),
            TreeNode::Internal { min, .. } => min,
        }
    }

    /// Whether the key falls inside this subtree's range (O(1); mirrors
    /// isInRange, `DHTBucketTree.cc`).
    fn in_range(&self, key: &NodeId) -> bool {
        match self {
            TreeNode::Leaf(b) => b.in_range(key),
            TreeNode::Internal { min, max, .. } => min <= key && key <= max,
        }
    }

    /// Splits a leaf's bucket (mirrors DHTBucketTreeNode::split,
    /// `DHTBucketTree.cc`): left = the lower half returned by
    /// `Bucket::split()`, right = the original bucket (upper half).
    /// Precondition: self is a leaf and the caller has confirmed
    /// `split_allowed`.
    fn split_leaf(self, now: Instant) -> TreeNode {
        let TreeNode::Leaf(mut bucket) = self else {
            unreachable!("split_leaf is only called on leaves")
        };
        let old_min = *bucket.min_id();
        let old_max = *bucket.max_id();
        let left = bucket.split(now);
        TreeNode::Internal {
            min: old_min,
            max: old_max,
            left: Box::new(TreeNode::Leaf(left)),
            right: Box::new(TreeNode::Leaf(bucket)),
        }
    }

    /// The leaf where the key lands (mirrors dht::findTreeNodeFor, `DHTBucketTree.cc`).
    fn leaf_for(&self, key: &NodeId) -> &TreeNode {
        let mut cur = self;
        loop {
            match cur {
                TreeNode::Leaf(_) => return cur,
                TreeNode::Internal { left, right, .. } => {
                    cur = if left.in_range(key) { left } else { right };
                }
            }
        }
    }

    fn leaf_for_mut(&mut self, key: &NodeId) -> &mut TreeNode {
        let mut cur = self;
        loop {
            match cur {
                TreeNode::Leaf(_) => return cur,
                TreeNode::Internal { left, right, .. } => {
                    cur = if left.in_range(key) { left } else { right };
                }
            }
        }
    }

    /// In-order enumeration of all leaf buckets (mirrors dht::enumerateBucket,
    /// `DHTBucketTree.cc`).
    fn enumerate<'a>(&'a self, out: &mut Vec<&'a Bucket>) {
        match self {
            TreeNode::Leaf(b) => out.push(b),
            TreeNode::Internal { left, right, .. } => {
                left.enumerate(out);
                right.enumerate(out);
            }
        }
    }
}

/// The 160-bit Kademlia routing table (mirrors DHTRoutingTable).
#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_id: NodeId,
    root: TreeNode,
}

impl RoutingTable {
    /// Starts from a single root bucket (mirrors `DHTRoutingTable.cc`).
    pub fn new(local_id: NodeId, now: Instant) -> Self {
        RoutingTable {
            local_id,
            root: TreeNode::Leaf(Bucket::root(now)),
        }
    }

    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    /// Adds a node (the good=false rule: a full unsplittable bucket fails
    /// outright, `DHTRoutingTable.cc`).
    pub fn add_node(&mut self, node: &DhtNode, now: Instant) -> bool {
        self.add_node_inner(node, false, now)
    }

    /// Adds a node (the good=true rule: a full unsplittable bucket sends the
    /// node to the replacement cache, `DHTRoutingTable.cc`).
    pub fn add_good_node(&mut self, node: &DhtNode, now: Instant) -> bool {
        self.add_node_inner(node, true, now)
    }

    /// The inbound-message contact path (mirrors `DHTMessageReceiver.cc`
    /// onMessageReceived: markGood + updateLastContact + addGoodNode).
    pub fn add_contacted_node(&mut self, mut node: DhtNode, now: Instant) -> bool {
        node.mark_good();
        node.update_last_contact(now);
        self.add_good_node(&node, now)
    }

    fn add_node_inner(&mut self, node: &DhtNode, good: bool, now: Instant) -> bool {
        // The local ID is refused (DHTRoutingTable.cc).
        if node.id() == &self.local_id {
            return false;
        }
        loop {
            let local_id = self.local_id;
            let target_id = *node.id();
            let leaf = self.root.leaf_for_mut(&target_id);
            let action = match leaf {
                TreeNode::Leaf(bucket) => {
                    if bucket.add_node(node, now) {
                        AddAction::Done
                    } else if bucket.split_allowed(&local_id) {
                        AddAction::Split
                    } else {
                        AddAction::Reject
                    }
                }
                TreeNode::Internal { .. } => unreachable!("leaf_for returns a leaf"),
            };
            match action {
                AddAction::Done => return true,
                AddAction::Split => {
                    // Split the bucket, then loop and re-walk the root→leaf path downward
                    // (equivalent to aria2's treeNode pointer descent).
                    let leaf = self.root.leaf_for_mut(&target_id);
                    let taken = std::mem::replace(leaf, TreeNode::Leaf(Bucket::root(now)));
                    *leaf = taken.split_leaf(now);
                }
                AddAction::Reject => {
                    if good {
                        let leaf = self.root.leaf_for_mut(&target_id);
                        if let TreeNode::Leaf(bucket) = leaf {
                            bucket.cache_node(node);
                        }
                    }
                    return false;
                }
            }
        }
    }

    /// The bucket where the key lands (mirrors getBucketFor, `DHTRoutingTable.cc`).
    pub fn get_bucket_for(&self, id: &NodeId) -> &Bucket {
        match self.root.leaf_for(id) {
            TreeNode::Leaf(b) => b,
            TreeNode::Internal { .. } => unreachable!("leaf_for returns a leaf"),
        }
    }

    /// Marks the bucket where `id` lands as refreshed (the bucket-refresh
    /// maintenance path; mirrors `DHTBucket::notifyUpdate` — aria2's
    /// DHTBucketRefreshTask.cc resets the `needs_refresh` window before
    /// dispatching a refresh lookup).
    pub fn notify_refreshed(&mut self, id: &NodeId, now: Instant) {
        let target_id = *id;
        let leaf = self.root.leaf_for_mut(&target_id);
        if let TreeNode::Leaf(bucket) = leaf {
            bucket.notify_refreshed(now);
        }
    }

    /// Node lookup by ID + address (mirrors getNode, `DHTRoutingTable.cc`).
    pub fn get_node(&self, id: &NodeId, addr: SocketAddr) -> Option<&DhtNode> {
        self.get_bucket_for(id).get_node(id, addr)
    }

    /// Replacing removal (mirrors dropNode, `DHTRoutingTable.cc`; whether a
    /// replacement actually happens depends on the bucket's replacement cache,
    /// see [`Bucket::drop_node`]).
    pub fn drop_node(&mut self, id: &NodeId) {
        let target_id = *id;
        let leaf = self.root.leaf_for_mut(&target_id);
        if let TreeNode::Leaf(bucket) = leaf {
            bucket.drop_node(id);
        }
    }

    /// Moves to the bucket tail (mirrors moveBucketTail, `DHTRoutingTable.cc`).
    pub fn move_bucket_tail(&mut self, id: &NodeId) {
        let target_id = *id;
        let leaf = self.root.leaf_for_mut(&target_id);
        if let TreeNode::Leaf(bucket) = leaf {
            bucket.move_to_tail(id);
        }
    }

    /// Transaction timeout scoring (mirrors
    /// DHTMessageTracker::handleTimeoutEntry, `DHTMessageTracker.cc`:
    /// node.timeout(); isBad → dropNode). A node not in the table (a
    /// transaction target created by wire) is recorded only, not scored —
    /// same as aria2 (its tracker's shared_ptr is the same object as the
    /// table's, so dropNode on an out-of-table object finds nothing and does
    /// nothing).
    pub fn record_timeout(&mut self, id: &NodeId, addr: SocketAddr) {
        let target_id = *id;
        let became_bad = {
            let leaf = self.root.leaf_for_mut(&target_id);
            match leaf {
                TreeNode::Leaf(bucket) => match bucket.get_node_mut(id, addr) {
                    Some(node) => {
                        node.timeout();
                        node.is_bad()
                    }
                    None => false,
                },
                TreeNode::Internal { .. } => false,
            }
        };
        if became_bad {
            self.drop_node(id);
        }
    }

    /// Transaction reply RTT recording (mirrors
    /// DHTMessageTracker::messageArrived's updateRTT, `DHTMessageTracker.cc`;
    /// ignored when the node is not in the table).
    pub fn record_response_rtt(&mut self, id: &NodeId, addr: SocketAddr, rtt: Duration) {
        let target_id = *id;
        let leaf = self.root.leaf_for_mut(&target_id);
        if let TreeNode::Leaf(bucket) = leaf
            && let Some(node) = bucket.get_node_mut(id, addr)
        {
            node.update_rtt(rtt);
        }
    }

    /// The closest K nodes (mirrors dht::findClosestKNodes, `DHTBucketTree.cc`;
    /// bad nodes filtered, at most K; fewer returned when fewer exist).
    pub fn get_closest_k_nodes(&self, key: &NodeId) -> Vec<DhtNode> {
        let mut out: Vec<DhtNode> = Vec::new();
        // The root→leaf path (path[0] = root, path[last] = the key leaf).
        let mut path: Vec<&TreeNode> = Vec::new();
        let mut cur = &self.root;
        loop {
            path.push(cur);
            match cur {
                TreeNode::Leaf(_) => break,
                TreeNode::Internal { left, right, .. } => {
                    cur = if left.in_range(key) { left } else { right };
                }
            }
        }
        if path.len() == 1 {
            // leaf == root: collect only that bucket (upstream DHTBucketTree.cc).
            match path[0] {
                TreeNode::Leaf(b) => collect_nodes(&mut out, b),
                TreeNode::Internal { .. } => unreachable!("path[0] is a leaf"),
            }
        } else {
            let parent = path[path.len() - 2];
            // Whether the leaf is its parent's left child: the left child's range ==
            // the leaf's range (same min).
            let leaf_is_left = match parent {
                TreeNode::Internal { left, .. } => left.min() == path[path.len() - 1].min(),
                TreeNode::Leaf(_) => unreachable!("parent must be an internal node"),
            };
            // Downward: leaf side first (the upstream branch between
            // collectDownwardLeftFirst / collectDownwardRightFirst).
            collect_downward(&mut out, parent, leaf_is_left);
            // Upward: collect sibling subtrees level by level (collectUpward, DHTBucketTree.cc).
            if out.len() < K {
                for i in (1..path.len() - 1).rev() {
                    let child = path[i];
                    let parent = path[i - 1];
                    let TreeNode::Internal { left, right, .. } = parent else {
                        unreachable!("interior path nodes must be Internal")
                    };
                    let is_child_left =
                        std::ptr::eq(&**left as *const TreeNode, child as *const TreeNode);
                    let sibling: &TreeNode = if is_child_left { right } else { left };
                    // A sibling subtree is always a leaf (tree invariant); defensively collected as a downward walk.
                    collect_downward(&mut out, sibling, true);
                    if out.len() >= K {
                        break;
                    }
                }
            }
        }
        // Finally truncated to K (upstream DHTBucketTree.cc).
        out.truncate(K);
        out
    }

    /// All leaf buckets (in order; mirrors getBuckets → enumerateBucket).
    pub fn buckets(&self) -> Vec<&Bucket> {
        let mut out = Vec::new();
        self.root.enumerate(&mut out);
        out
    }

    /// Bucket count (mirrors getNumBucket, `DHTRoutingTable.cc`).
    pub fn num_buckets(&self) -> usize {
        self.buckets().len()
    }

    /// Total node count in the table (the sum over buckets).
    pub fn num_nodes(&self) -> usize {
        self.buckets().iter().map(|b| b.len()).sum()
    }
}

enum AddAction {
    Done,
    Split,
    Reject,
}

/// Collects a bucket's non-bad nodes (mirrors collectNodes → getGoodNodes).
fn collect_nodes(out: &mut Vec<DhtNode>, bucket: &Bucket) {
    out.extend(bucket.good_nodes().cloned());
}

/// Leaf-side-first subtree collection (mirrors collectDownwardLeftFirst /
/// RightFirst, `DHTBucketTree.cc`).
fn collect_downward(out: &mut Vec<DhtNode>, node: &TreeNode, leaf_is_left: bool) {
    if out.len() >= K {
        return;
    }
    match node {
        TreeNode::Leaf(b) => collect_nodes(out, b),
        TreeNode::Internal { left, right, .. } => {
            let (first, second) = if leaf_is_left {
                (left, right)
            } else {
                (right, left)
            };
            collect_downward(out, first, leaf_is_left);
            if out.len() < K {
                collect_downward(out, second, leaf_is_left);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::node::{BAD_CONDITION, DHT_NODE_CONTACT_INTERVAL};
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    // Vector source conventions: [aria2 9e727358] = test/DHT{Bucket,BucketTree,
    // RoutingTable}Test.cc / src/DHT*.{h,cc} of aria2 commit
    // 9e7273583f83e881e3ec067b523ba88724088d2f (file anchors in the module docs).

    struct XorShift(u64);

    impl XorShift {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    // rand 0.10: a custom RNG implementing TryRng (Error = Infallible) gets
    // Rng/RngExt automatically via the blanket impl (same as tracker/udp.rs).
    impl rand::rand_core::TryRng for XorShift {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next_u64() as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next_u64())
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port))
    }

    fn node(id_bytes: [u8; 20], port: u16) -> DhtNode {
        DhtNode::new(NodeId(id_bytes), v4(port))
    }

    /// Assembles an id: first byte = head, last byte = tail, zeros elsewhere
    /// (mirrors DHTRoutingTableTest.cc createID).
    fn make_id(head: u8, tail: u8) -> [u8; 20] {
        let mut id = [0u8; 20];
        id[0] = head;
        id[19] = tail;
        id
    }

    /// [aria2 9e727358] DHTBucketTest.cc testIsInRange: the full-space bucket
    /// [0..ff] contains 0 and ff; the closed range [0101 00..00, 0101 ff..ff]
    /// contains both ends and excludes below/above.
    #[test]
    fn bucket_range_is_inclusive() {
        let now = Instant::now();
        let root = Bucket::root(now);
        assert!(root.in_range(&NodeId([0u8; 20])));
        assert!(root.in_range(&NodeId([0xffu8; 20])));

        let mut min = [0u8; 20];
        min[0] = 0x01;
        min[1] = 0x01;
        let mut max = [0xffu8; 20];
        max[0] = 0x01;
        max[1] = 0x01;
        let bucket = Bucket::from_range(16, NodeId(min), NodeId(max), now);

        assert!(bucket.in_range(&NodeId(min))); // min endpoint
        assert!(bucket.in_range(&NodeId(max))); // max endpoint
        let mut inside = [0u8; 20];
        inside[0] = 0x01;
        inside[1] = 0x01;
        inside[9] = 0xff;
        assert!(bucket.in_range(&NodeId(inside)));
        let mut below = [0u8; 20];
        below[19] = 0x01; // all zeros < min
        assert!(!bucket.in_range(&NodeId(below)));
        let mut above = [0xffu8; 20];
        above[1] = 0x02; // 0x0102.. > max
        assert!(!bucket.in_range(&NodeId(above)));
    }

    /// [aria2 9e727358] DHTBucketTest.cc testSplit (first part): splitting the
    /// root bucket returns the lower half [00..00, 7f..ff] with prefix=1, and
    /// self becomes the upper half [80..00, ff..ff] with prefix=1.
    #[test]
    fn root_split_ranges_match_aria2() {
        let now = Instant::now();
        let mut bucket = Bucket::root(now);
        let local = NodeId([0u8; 20]);
        assert!(bucket.split_allowed(&local));
        let left = bucket.split(now);

        assert_eq!(left.prefix_len(), 1);
        assert_eq!(*left.min_id(), NodeId([0u8; 20]));
        let mut expect_left_max = [0xffu8; 20];
        expect_left_max[0] = 0x7f;
        assert_eq!(*left.max_id(), NodeId(expect_left_max));

        assert_eq!(bucket.prefix_len(), 1);
        let mut expect_right_min = [0u8; 20];
        expect_right_min[0] = 0x80;
        assert_eq!(*bucket.min_id(), NodeId(expect_right_min));
        assert_eq!(*bucket.max_id(), NodeId([0xffu8; 20]));
    }

    /// [aria2 9e727358] DHTBucketTest.cc testSplit (second part): splitting
    /// down the lower half 159 times — for splits 1..158 splitAllowed is true
    /// before and false after; after 159 splits prefix=159 over the range
    /// [00..00, 00..01] and further splits are refused (the prefix bound
    /// 159 = 160-1, DHTBucket.cc).
    #[test]
    fn split_chain_stops_at_159() {
        let now = Instant::now();
        let local = NodeId([0u8; 20]);
        let mut bucket = Bucket::root(now);
        for _ in 0..159 {
            assert!(bucket.split_allowed(&local));
            let lower = bucket.split(now);
            assert!(!bucket.split_allowed(&local)); // the upper half lacks local → unsplittable
            bucket = lower; // descend along the lower half (contains local)
        }
        assert!(!bucket.split_allowed(&local));
        let mut expect_max = [0u8; 20];
        expect_max[19] = 0x01;
        assert_eq!(*bucket.min_id(), NodeId([0u8; 20]));
        assert_eq!(*bucket.max_id(), NodeId(expect_max));
        assert_eq!(bucket.prefix_len(), 159);
    }

    /// [aria2 9e727358] DHTBucketTest.cc testAddNode: a full bucket refuses a
    /// new node; once the front (LRS) is bad the new node takes its place at
    /// the tail.
    #[test]
    fn full_bucket_rejects_then_replaces_bad_lrs_front() {
        let now = Instant::now();
        let mut bucket = Bucket::root(now);
        let mut nodes = Vec::new();
        for i in 0u8..8 {
            let n = node(make_id(0xf0, i), 6881);
            assert!(bucket.add_node(&n, now));
            nodes.push(n);
        }
        // Full bucket: the new node is refused.
        let new_node = node(make_id(0xf0, 0xff), 6882);
        assert!(!bucket.add_node(&new_node, now));
        // The front = the earliest-added nodes[0] (LRS); marked bad in place, it can then be replaced.
        let head_id = *nodes[0].id();
        let head_addr = nodes[0].addr();
        match bucket.get_node_mut(&head_id, head_addr) {
            Some(n) => n.mark_bad(),
            None => panic!("head node missing"),
        }
        assert!(bucket.add_node(&new_node, now));
        let last = bucket
            .nodes()
            .last()
            .map(|n| *n.id())
            .unwrap_or(NodeId([0u8; 20]));
        assert_eq!(last, *new_node.id());
        assert_eq!(bucket.len(), K);
    }

    /// Re-adding an existing node (by ID) → moves to the tail (aria2
    /// DHTBucket.cc).
    #[test]
    fn existing_node_moves_to_tail() {
        let now = Instant::now();
        let mut bucket = Bucket::root(now);
        for i in 0u8..4 {
            assert!(bucket.add_node(&node(make_id(0xf0, i), 6881), now));
        }
        let first_id = NodeId(make_id(0xf0, 0));
        bucket.move_to_tail(&first_id);
        let last = bucket
            .nodes()
            .last()
            .map(|n| *n.id())
            .unwrap_or(NodeId([0u8; 20]));
        assert_eq!(last, first_id);
    }

    /// [aria2 9e727358] DHTBucketTest.cc testCacheNode/testDropNode semantics:
    /// the cache truncates to 2; dropNode is a no-op with an empty cache; with
    /// a cache it replaces the dropped node with the cache front.
    #[test]
    fn drop_node_replaces_from_cache_only() {
        let now = Instant::now();
        let mut bucket = Bucket::root(now);
        let mut first = node(make_id(0xf0, 0), 6881);
        assert!(bucket.add_node(&first, now));
        assert!(bucket.add_node(&node(make_id(0xf0, 1), 6881), now));

        // Empty cache: drop = no-op (DHTBucket.cc).
        bucket.drop_node(first.id());
        assert_eq!(bucket.len(), 2);
        assert!(bucket.get_node(first.id(), first.addr()).is_some());

        // Cached via the good path (same-ID nodes on new addresses are distinguishable).
        let c1 = node(make_id(0xf0, 0), 7001);
        let c2 = node(make_id(0xf0, 1), 7002);
        let c3 = node(make_id(0xf0, 2), 7003);
        bucket.cache_node(&c1);
        bucket.cache_node(&c2);
        bucket.cache_node(&c3); // truncated to CACHE_SIZE=2 → only c3, c2 remain
        assert_eq!(
            bucket.get_node(first.id(), first.addr()).map(|n| *n.id()),
            Some(*first.id())
        );

        bucket.drop_node(first.id());
        assert_eq!(bucket.len(), 2);
        // first was replaced by the cache front (c3).
        assert!(bucket.get_node(first.id(), first.addr()).is_none());
        assert!(bucket.get_node(c3.id(), c3.addr()).is_some());
        let _ = &mut first;
    }

    /// needs_refresh: always true below K nodes; once full, the 15min
    /// inclusive threshold (DHTBucket.cc / DHTConstants.h).
    #[test]
    fn needs_refresh_boundary() {
        let t0 = Instant::now();
        let mut bucket = Bucket::root(t0);
        assert!(bucket.needs_refresh(t0)); // empty bucket < K
        for i in 0u8..8 {
            assert!(bucket.add_node(&node(make_id(0xf0, i), 6881), t0));
        }
        assert!(!bucket.needs_refresh(t0));
        assert!(!bucket.needs_refresh(t0 + DHT_BUCKET_REFRESH_INTERVAL - Duration::from_secs(1)));
        assert!(bucket.needs_refresh(t0 + DHT_BUCKET_REFRESH_INTERVAL));
    }

    /// [aria2 9e727358] DHTBucketTest.cc testGetRandomNodeID: in a prefix=16
    /// bucket ([0101 00.., 0101 ff..]) a random ID's first two bytes are
    /// always 0101.
    #[test]
    fn random_id_in_range_honors_prefix() {
        let now = Instant::now();
        let mut min = [0u8; 20];
        min[0] = 0x01;
        min[1] = 0x01;
        let mut max = [0xffu8; 20];
        max[0] = 0x01;
        max[1] = 0x01;
        let bucket = Bucket::from_range(16, NodeId(min), NodeId(max), now);
        let mut rng = XorShift(0xfeed_beef_cafe_0001);
        for _ in 0..64 {
            let id = bucket.random_id_in_range(&mut rng);
            assert_eq!(id.0[0], 0x01);
            assert_eq!(id.0[1], 0x01);
            assert!(bucket.in_range(&id));
        }
        let root = Bucket::root(now);
        for _ in 0..16 {
            assert!(root.in_range(&root.random_id_in_range(&mut rng)));
        }
    }

    /// [aria2 9e727358] DHTRoutingTableTest.cc testAddNode_localNode: a node
    /// with the local node's ID is refused.
    #[test]
    fn local_node_id_rejected() {
        let now = Instant::now();
        let local_id = NodeId(make_id(0x81, 0));
        let mut table = RoutingTable::new(local_id, now);
        assert!(!table.add_node(&node(local_id.0, 6881), now));
        assert_eq!(table.num_nodes(), 0);
    }

    /// [aria2 9e727358] DHTRoutingTableTest.cc testGetClosestKNodes:
    /// local = 0x81..00; add three groups of 8 nodes with heads 0xf0, 0x80,
    /// 0x70; the closest K for key=0x80..10 is exactly the 0x80 bucket's 8
    /// nodes.
    #[test]
    fn closest_k_nodes_matches_aria2_scenario() {
        let now = Instant::now();
        let local = NodeId(make_id(0x81, 0));
        let mut table = RoutingTable::new(local, now);
        let mut nodes2 = Vec::new();
        for head in [0xf0u8, 0x80, 0x70] {
            for i in 0u8..8 {
                let n = node(make_id(head, i), 6881);
                assert!(table.add_node(&n, now), "add {head:02x}..{i:02x}");
                if head == 0x80 {
                    nodes2.push(*n.id());
                }
            }
        }
        assert_eq!(table.num_nodes(), 24);
        // Three buckets: [00..7f] / [80..bf] / [c0..ff] (0x81 shares the 0x80 side prefix).
        assert_eq!(table.num_buckets(), 3);

        let key = NodeId(make_id(0x80, 0x10));
        let closest = table.get_closest_k_nodes(&key);
        assert_eq!(closest.len(), 8);
        for n in &closest {
            assert_eq!(n.id().0[0], 0x80);
        }
        // In-bucket LRS order: the front is the earliest-added 0x80..00.
        assert_eq!(*closest[0].id(), nodes2[0]);
    }

    /// Splitting happens only along the local node's path (tree invariant):
    /// with local 0x81, adding the remote 0x01 group fills that bucket, which
    /// then cannot split → only K are kept, extras refused.
    #[test]
    fn remote_full_bucket_never_splits() {
        let now = Instant::now();
        let local = NodeId(make_id(0x81, 0));
        let mut table = RoutingTable::new(local, now);
        // Local-neighborhood nodes (trigger the split along the local path).
        for i in 0u8..8 {
            assert!(table.add_node(&node(make_id(0x80, i), 6881), now));
        }
        // Remote nodes: 9 with the 0x01.. prefix → after the bucket fills, the
        // 9th is refused (the 0x01 bucket lacks local, split_allowed is false).
        for i in 0u8..8 {
            assert!(table.add_node(&node(make_id(0x01, i), 6881), now));
        }
        assert!(!table.add_node(&node(make_id(0x01, 8), 6881), now));
        // The 0x01 bucket does not split merely because the remote side is full.
        let bucket = table.get_bucket_for(&NodeId(make_id(0x01, 0)));
        assert_eq!(bucket.len(), K);
    }

    /// Transaction timeout scoring (mirrors
    /// DHTMessageTracker::handleTimeoutEntry, DHTMessageTracker.cc): timeout
    /// x5 reaching BAD_CONDITION → dropNode; with an empty cache the node
    /// stays (DHTBucket.cc), with a cache it is swapped for the cache front.
    /// Note: Kademlia splits buckets along the local path (splitAllowed), so
    /// new nodes near local always land in an unfilled leaf bucket — the
    /// table-level "full bucket + cache" is not a steady state; the swap
    /// sequence is checked at bucket level (same rule as aria2
    /// DHTBucketTest::testDropNode).
    #[test]
    fn record_timeout_scores_to_bad_and_drops_only_with_cache() {
        let now = Instant::now();
        let local = NodeId(make_id(0x81, 0));

        // Table level: no cache — after 5 timeouts the node is bad but retained (nothing to swap in).
        let mut table = RoutingTable::new(local, now);
        let target = node(make_id(0x81, 1), 6881);
        assert!(table.add_contacted_node(target.clone(), now));
        for i in 1..=4u32 {
            table.record_timeout(target.id(), target.addr());
            let cond = table
                .get_node(target.id(), target.addr())
                .map(|n: &DhtNode| n.condition());
            assert_eq!(cond, Some(i), "timeout #{i}");
        }
        table.record_timeout(target.id(), target.addr());
        let stored = table
            .get_node(target.id(), target.addr())
            .map(|n: &DhtNode| (n.is_bad(), n.condition()));
        assert_eq!(stored, Some((true, BAD_CONDITION)));

        // Bucket level: with a cache — once scored out, dropNode swaps in the cache front.
        let mut bucket = Bucket::root(now);
        for i in 0u8..8 {
            let mut n = node(make_id(0x81, i), 6881);
            n.mark_good();
            assert!(bucket.add_node(&n, now));
        }
        let cached = node(make_id(0x81, 9), 7001);
        bucket.cache_node(&cached);
        let head = node(make_id(0x81, 0), 6881);
        for _ in 0..5 {
            match bucket.get_node_mut(head.id(), head.addr()) {
                Some(n) => n.timeout(),
                None => panic!("target missing"),
            }
        }
        bucket.drop_node(head.id());
        assert!(bucket.get_node(head.id(), head.addr()).is_none());
        assert!(bucket.get_node(cached.id(), cached.addr()).is_some());
    }

    /// Inbound contact path (mirrors DHTMessageReceiver.cc): a wire-new node
    /// (condition=1, questionable) becomes good and is stored after
    /// add_contacted_node.
    #[test]
    fn contacted_node_becomes_good_and_stored() {
        let now = Instant::now();
        let local = NodeId(make_id(0x81, 0));
        let mut table = RoutingTable::new(local, now);
        let n = node(make_id(0x33, 7), 6881);
        assert!(n.is_questionable(now)); // wire-new node: condition=1, no contact yet
        assert!(table.add_contacted_node(n.clone(), now));
        let stored = table.get_node(n.id(), n.addr()).map(|s| s.is_good(now));
        assert_eq!(stored, Some(true));
    }

    /// lru_questionable_node: the bucket's earliest-lost-contact node is
    /// chosen (mirrors DHTBucket.cc; the refresh task's ping candidate).
    #[test]
    fn lru_questionable_node_found() {
        let now = Instant::now();
        let mut bucket = Bucket::root(now);
        let fresh_at = now;
        for i in 0u8..4 {
            let mut n = node(make_id(0xf0, i), 6881);
            n.mark_good();
            n.update_last_contact(fresh_at);
            assert!(bucket.add_node(&n, now));
        }
        assert!(bucket.lru_questionable_node(now).is_none());
        let stale_at = match now.checked_sub(DHT_NODE_CONTACT_INTERVAL) {
            Some(t) => t,
            None => panic!("clock too small"),
        };
        let mut stale = node(make_id(0xf0, 0), 6881);
        stale.mark_good();
        stale.update_last_contact(stale_at);
        assert!(bucket.add_node(&stale, now)); // already present → moved to the tail
        let q = bucket.lru_questionable_node(now).map(|n| *n.id());
        assert_eq!(q, Some(NodeId(make_id(0xf0, 0))));
    }

    /// Stress: 300 random node inserts do not panic and the table conserves
    /// nodes (the count of successful inserts); closest-K queries return at
    /// most K for any key (a property-shaped smoke test).
    #[test]
    fn random_inserts_keep_table_consistent() {
        let now = Instant::now();
        let mut rng = XorShift(0xa5a5_5a5a_dead_10cc);
        let local = NodeId::random(&mut rng);
        let mut table = RoutingTable::new(local, now);
        let mut accepted = 0usize;
        for _ in 0..300 {
            let id = NodeId::random(&mut rng);
            if id == local {
                continue;
            }
            let n = DhtNode::new(id, v4(6881));
            if table.add_good_node(&n, now) || !table.get_node(n.id(), n.addr()).is_some() {
                accepted += 1;
            }
        }
        assert!(table.num_nodes() >= 1);
        assert!(accepted <= 300);
        for _ in 0..32 {
            let key = NodeId::random(&mut rng);
            assert!(table.get_closest_k_nodes(&key).len() <= K);
        }
    }
}

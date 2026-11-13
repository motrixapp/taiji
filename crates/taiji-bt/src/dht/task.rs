//! DHT tasks and the dual-queue executor (the actor-driven half).
//!
//! Mechanism: two queues with 15 concurrent slots each and refill
//! semantics (remove finished tasks, then start tasks from the queue
//! head; tasks that finish during startup do not occupy a slot); a
//! node/peer lookup state machine with an ALPHA=5 in-flight cap; ping
//! tasks with bounded retry; bucket refresh that dispatches one node
//! lookup per due bucket and completes immediately. Two queues are an
//! intentional simplification of upstream's three (periodic1/periodic2
//! merged into one Periodic queue) — queue assignment only affects
//! scheduling priority, not protocol behavior.
//!
//! Tasks do no IO themselves: packet sends and transaction registration
//! are performed by the engine ([`super::engine`]) while driving the
//! tasks — this module is pure state machines, synchronously testable.
//!
//! Upstream anchor mapping: docs/design/dht.md

use std::collections::HashMap;
use std::net::SocketAddr;

use super::node::{DHT_ID_LENGTH, DhtNode, NodeId};
use super::routing_table::K;

/// Concurrent tasks per queue. aria2 `src/DHTTaskQueueImpl.cc`.
pub const NUM_CONCURRENT_TASK: usize = 15;

/// Per-lookup in-flight query cap. aria2 `src/DHTAbstractNodeLookupTask.h`
/// (initial width follows libtorrent RC_2_0; the aria2 reference used 3).
pub const ALPHA: usize = 5;

/// Default get_peers/find_node candidate frontier width: the truncation
/// bound applied after the candidate table is sorted and deduplicated
/// ([`LookupTask::sort_dedup_truncate`]). aria2's
/// `DHTAbstractNodeLookupTask.h` uses the routing bucket width K=8; this
/// side takes 16 (width x2) to widen discovery — the per-iteration
/// contacted-node count grows with the frontier while the ALPHA=5
/// in-flight cap is untouched (each new contactable candidate is still
/// probed 3 at a time) and outbound politeness is independently limited
/// by the DHT per-source query token bucket (engine/query_limit.rs); the
/// announce stage is unchanged (`announce_targets` still take(K) — the K
/// closest probed nodes, per DHTPeerLookupTask.cc). Combines with the
/// engine ramp cadence (core run/ecology.rs `BH_DHT_RAMP_INTERVAL_SECS`).
///
/// Knob: `BH_DHT_FRONTIER_K` overrides (trim + usize parse; failure/0 →
/// the default; `=8` restores the aria2 K=8 width exactly).
pub const LOOKUP_FRONTIER_K: usize = 16;

/// Frontier-width read (at construction time): the `BH_DHT_FRONTIER_K`
/// override, defaulting to [`LOOKUP_FRONTIER_K`]. Evaluated each time a
/// lookup task is constructed (lookups are low-frequency: announce /
/// bucket refresh cadences, not a hot path). Parsing and read timing are
/// registered in `taiji_io::knobs` (read at construction, no caching —
/// the same pattern as `BH_CHOKE_ARIA2` in choke.rs).
pub fn lookup_frontier_k() -> usize {
    taiji_io::knobs::dht_frontier_k(LOOKUP_FRONTIER_K)
}

/// Bootstrap entry ping retry count. aria2
/// `src/DHTEntryPointNameResolveCommand.cc` (`createPingTask(entryNode, 10)`).
pub const BOOTSTRAP_PING_RETRY: u32 = 10;

/// The queue a task lives in (periodic1/2 merged, see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueKind {
    /// Immediate queue (ping/node_lookup triggered by PORT messages; mirrors BtPortMessage.cc).
    Immediate,
    /// Periodic queue (bootstrap / bucket refresh / peer announce / user
    /// lookup; mirrors upstream's periodic1+periodic2).
    Periodic,
}

/// Task serial number (monotonically assigned within the engine; routes responses back to tasks).
pub type TaskId = u64;

/// Swarm identity face (SPEC §4.1: the transport-layer 20B identifier is
/// either the V1 sha1 value as-is or the first 20B of a V2 truncated
/// sha256 — truncation is applied by the caller via
/// `crate::info_hash::truncated_v2` before passing it in; the DHT face
/// only ever sees 20B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhtSwarmKind {
    /// v1 swarm (target = sha1 info-hash).
    V1,
    /// v2 swarm (target = truncated sha256; a discovered peer joins first
    /// under its handshake identity, with hash-exchange identity verification
    /// dependent on the requester side — the transitional rule until that is
    /// merged).
    V2,
}

/// Lookup category (node_lookup / peer_lookup).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKind {
    /// A find_node iteration (the vehicle for node_lookup / bucket refresh).
    Nodes,
    /// A get_peers iteration; when `announce_port` is Some, the completion
    /// stage sends announce_peer to the K probed nodes (DHTPeerLookupTask.cc).
    Peers { announce_port: Option<u16> },
}

impl LookupKind {
    /// Whether it carries an announce stage.
    pub fn announces(&self) -> bool {
        matches!(
            self,
            LookupKind::Peers {
                announce_port: Some(_)
            }
        )
    }
}

/// Candidate table entry (`DHTNodeLookupEntry`: node + used flag).
#[derive(Debug, Clone)]
struct LookupEntry {
    node: DhtNode,
    used: bool,
}

/// The node/peer lookup state machine (a direct translation of
/// DHTAbstractNodeLookupTask).
///
/// Lifecycle: `seed()` (startup: take the routing table's closest K) →
/// the engine loops `next_outgoing()` + send (in-flight <= ALPHA) → and
/// keeps driving after each response `on_response` / timeout `on_timeout`;
/// when `check_finished()` turns true the engine runs the announce stage
/// (peer lookup) and removes the task.
#[derive(Debug)]
pub struct LookupTask {
    /// Lookup target (node_lookup = target ID; peer_lookup = the info_hash's
    /// 20B transport-face identifier).
    pub target: NodeId,
    pub kind: LookupKind,
    /// Swarm identity face (PeersFound events carry it back to the caller for swarm attribution).
    pub face: DhtSwarmKind,
    /// Candidate frontier width, default [`lookup_frontier_k`]; tests inject
    /// it explicitly via [`LookupTask::with_frontier`] (env reads stay out of
    /// the pure state-machine assertion face).
    frontier: usize,
    entries: Vec<LookupEntry>,
    in_flight: usize,
    // Value=true means this request yielded its concurrency slot on soft timeout.
    pending: HashMap<SocketAddr, bool>,
    /// Announce tokens of probed nodes (DHTPeerLookupTask.cc, keyed by node
    /// ID).
    tokens: HashMap<NodeId, Vec<u8>>,
    finished: bool,
}

impl LookupTask {
    pub fn new(target: NodeId, kind: LookupKind, face: DhtSwarmKind) -> Self {
        Self::with_frontier(target, kind, face, lookup_frontier_k())
    }

    /// Explicit frontier-width constructor (a direct-drive seam for tests
    /// pinning the fallback value).
    pub fn with_frontier(
        target: NodeId,
        kind: LookupKind,
        face: DhtSwarmKind,
        frontier: usize,
    ) -> Self {
        LookupTask {
            target,
            kind,
            face,
            frontier,
            entries: Vec::new(),
            in_flight: 0,
            pending: HashMap::new(),
            tokens: HashMap::new(),
            finished: false,
        }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    pub fn finished(&self) -> bool {
        self.finished
    }

    /// startup (`DHTAbstractNodeLookupTask.cc`): candidates = the routing
    /// table's closest K (upstream relies on getClosestKNodes returning in
    /// distance order; this sorts again to pin the invariant); an empty table
    /// → finishes immediately (the offline degraded path).
    pub fn seed(&mut self, closest: Vec<DhtNode>) {
        self.entries = closest
            .into_iter()
            .map(|node| LookupEntry { node, used: false })
            .collect();
        self.sort_dedup_truncate();
        if self.entries.is_empty() {
            self.finished = true;
        }
    }

    /// Takes the next entry to send (marks it used, in-flight +1; the
    /// per-entry shape of upstream `sendMessage`). None when in-flight is at
    /// ALPHA or no unused candidate remains.
    pub fn next_outgoing(&mut self) -> Option<DhtNode> {
        if self.finished || self.in_flight >= ALPHA || self.pending.len() >= ALPHA * 3 {
            return None;
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|e| !e.used && !self.pending.contains_key(&e.node.addr()))?;
        entry.used = true;
        self.in_flight += 1;
        self.pending.insert(entry.node.addr(), false);
        Some(entry.node.clone())
    }

    /// A response arrived (upstream `onReceived`).
    ///
    /// - in-flight -1; the entry's node is replaced by address;
    /// - peer lookup: the response token is cached (the engine reads it back
    ///   before calling);
    /// - nodes carried by the response merge into the candidates (skipping
    ///   the local ID) → stable sort by XOR distance → dedup → truncate to
    ///   the frontier.
    pub fn on_response(
        &mut self,
        from: &DhtNode,
        token: Option<&[u8]>,
        nodes: Vec<DhtNode>,
        local_id: &NodeId,
    ) {
        if !self.pending.remove(&from.addr()).unwrap_or(false) {
            self.in_flight = self.in_flight.saturating_sub(1);
        }
        for entry in &mut self.entries {
            if entry.node.addr() == from.addr() {
                entry.node = from.clone();
            }
        }
        if let Some(t) = token
            && !t.is_empty()
        {
            self.tokens.insert(*from.id(), t.to_vec());
        }
        for node in nodes {
            if node.id() == local_id {
                continue;
            }
            self.entries.push(LookupEntry { node, used: false });
        }
        self.sort_dedup_truncate();
    }

    /// Transaction timeout / send failure (upstream `onTimeout`): in-flight -1, entry removed.
    pub fn on_timeout(&mut self, id: &NodeId, addr: SocketAddr) {
        if !self.pending.remove(&addr).unwrap_or(false) {
            self.in_flight = self.in_flight.saturating_sub(1);
        }
        self.entries
            .retain(|e| !(e.node.id() == id && e.node.addr() == addr));
    }

    /// Release only the scheduling opportunity; late replies remain valid.
    pub fn on_soft_timeout(&mut self, address: SocketAddr) {
        if let Some(soft) = self.pending.get_mut(&address) {
            if !*soft {
                *soft = true;
                self.in_flight = self.in_flight.saturating_sub(1);
            }
        }
    }

    /// Completion check (the closing half of upstream
    /// `sendMessageAndCheckFinish`: once the engine has drained the
    /// candidates, `in_flight == 0` means finished).
    pub fn check_finished(&mut self) -> bool {
        if !self.finished && self.in_flight == 0 && self.pending.is_empty() {
            self.finished = true;
        }
        self.finished
    }

    /// Announce stage targets (upstream `onFinish`: used entries holding a
    /// token, at most K in distance order).
    pub fn announce_targets(&self) -> Vec<(DhtNode, Vec<u8>)> {
        self.entries
            .iter()
            .filter(|e| e.used)
            .filter_map(|e| {
                self.tokens
                    .get(e.node.id())
                    .cloned()
                    .map(|token| (e.node.clone(), token))
            })
            .take(K)
            .collect()
    }

    /// Candidate table maintenance: stable sort (ascending XOR distance) +
    /// dedup + truncate to the frontier width (default [`LOOKUP_FRONTIER_K`]
    /// = 16; the aria2-translation K=8 is restored via `BH_DHT_FRONTIER_K=8`;
    /// a deliberate widening of upstream's truncate-to-K, see the constant
    /// docs).
    fn sort_dedup_truncate(&mut self) {
        let target = self.target;
        self.entries.sort_by(|a, b| {
            xor_distance(&target, a.node.id()).cmp(&xor_distance(&target, b.node.id()))
        });
        self.entries
            .dedup_by(|a, b| a.node.id() == b.node.id() && a.node.addr() == b.node.addr());
        self.entries.truncate(self.frontier);
        // Closer discoveries get query opportunities immediately; outstanding
        // distant requests remain correlated and can still deliver late peers.
        let closest: std::collections::HashSet<_> = self
            .entries
            .iter()
            .filter(|entry| !entry.used || self.pending.contains_key(&entry.node.addr()))
            .take(ALPHA)
            .map(|entry| entry.node.addr())
            .collect();
        for (address, soft) in &mut self.pending {
            if !*soft && !closest.contains(address) {
                *soft = true;
                self.in_flight = self.in_flight.saturating_sub(1);
            }
        }
    }
}

/// 160-bit XOR distance (byte-order comparison = numeric order; the Kademlia distance metric).
fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; DHT_ID_LENGTH] {
    let mut out = [0u8; DHT_ID_LENGTH];
    for (o, (x, y)) in out.iter_mut().zip(a.0.iter().zip(b.0.iter())) {
        *o = x ^ y;
    }
    out
}

/// Ping task (a direct translation of `DHTPingTask.cc`): pings one node,
/// retrying on timeout up to `num_max_retry` (inclusive-bound semantics,
/// see the module docs).
#[derive(Debug)]
pub struct PingTask {
    pub node: DhtNode,
    pub num_max_retry: u32,
    num_retry: u32,
    pub success: bool,
    finished: bool,
    /// Owning bootstrap round (None = a standalone ping, e.g. triggered by a PORT message).
    pub round: Option<usize>,
}

impl PingTask {
    pub fn new(node: DhtNode, num_max_retry: u32) -> Self {
        PingTask {
            node,
            num_max_retry,
            num_retry: 0,
            success: false,
            finished: false,
            round: None,
        }
    }

    pub fn finished(&self) -> bool {
        self.finished
    }

    /// A response arrived (upstream `onReceived`).
    pub fn on_response(&mut self) {
        self.success = true;
        self.finished = true;
    }

    /// Cancels the round's remaining pings once its first success settles
    /// (sets the finished flag — no more retries, frames or bookkeeping; the
    /// queue removes it via the existing retain_finished/refill path).
    pub fn cancel(&mut self) {
        self.finished = true;
    }

    /// Timeout (upstream `onTimeout`): returns true = resend; false = finished.
    pub fn on_timeout(&mut self) -> bool {
        self.num_retry += 1;
        if self.num_retry >= self.num_max_retry {
            self.finished = true;
            false
        } else {
            true
        }
    }
}

/// Bucket refresh task (a direct translation of
/// `DHTBucketRefreshTask.cc`): at startup dispatches a node lookup with a
/// range-random ID for each bucket where `force || needsRefresh`, then
/// completes immediately.
#[derive(Debug)]
pub struct RefreshTask {
    /// Force-refresh every bucket (DHTSetup.cc's `setForceRefresh(true)` when
    /// deserialized nodes are non-empty).
    pub force: bool,
    finished: bool,
}

impl RefreshTask {
    /// Startup sweep: dispatch a lookup for **every** bucket regardless
    /// of the staleness check (DHTSetup.cc's `setForceRefresh(true)` when
    /// deserialized nodes are non-empty).
    pub fn forced() -> Self {
        RefreshTask {
            force: true,
            finished: false,
        }
    }

    /// Periodic sweep: only buckets failing `needsRefresh` dispatch a
    /// lookup (`DHTBucketRefreshTask.cc`).
    pub fn scheduled() -> Self {
        RefreshTask {
            force: false,
            finished: false,
        }
    }

    pub fn finished(&self) -> bool {
        self.finished
    }

    /// Startup completion (called by the engine after dispatching the child lookups).
    pub fn complete(&mut self) {
        self.finished = true;
    }
}

/// Engine tasks.
#[derive(Debug)]
pub enum Task {
    Ping(PingTask),
    Lookup(LookupTask),
    Refresh(RefreshTask),
}

impl Task {
    pub fn is_finished(&self) -> bool {
        match self {
            Task::Ping(t) => t.finished(),
            Task::Lookup(t) => t.finished(),
            Task::Refresh(t) => t.finished(),
        }
    }
}

/// Single-queue executor (`DHTTaskExecutor` translation: capacity + FIFO + an executing set).
#[derive(Debug)]
pub struct TaskQueue {
    pub capacity: usize,
    waiting: std::collections::VecDeque<(TaskId, Task)>,
    executing: Vec<(TaskId, Task)>,
}

impl Default for TaskQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskQueue {
    pub fn cancel_peer_lookups(&mut self, target: NodeId) -> Vec<TaskId> {
        let mut cancelled = Vec::new();
        let mut retain = |(id, task): &(TaskId, Task)| {
            let matches = matches!(task,Task::Lookup(lookup) if lookup.target==target && matches!(lookup.kind,LookupKind::Peers {..}));
            if matches {
                cancelled.push(*id);
            }
            !matches
        };
        self.waiting.retain(&mut retain);
        self.executing.retain(&mut retain);
        cancelled
    }

    pub fn references_bootstrap_round(&self, round: usize) -> bool {
        self.waiting
            .iter()
            .chain(self.executing.iter())
            .any(|(_, task)| matches!(task,Task::Ping(ping) if ping.round==Some(round)))
    }

    pub fn has_peer_lookup(&self, target: NodeId) -> bool {
        self.waiting.iter().chain(self.executing.iter()).any(|(_, task)| matches!(task, Task::Lookup(lookup) if lookup.target == target && matches!(lookup.kind, LookupKind::Peers { .. })))
    }

    pub fn new() -> Self {
        TaskQueue {
            capacity: NUM_CONCURRENT_TASK,
            waiting: std::collections::VecDeque::new(),
            executing: Vec::new(),
        }
    }

    pub fn push_waiting(&mut self, id: TaskId, task: Task) {
        self.waiting.push_back((id, task));
    }

    /// Removes finished executing tasks (`DHTTaskExecutor.cc` remove_if).
    pub fn retain_finished(&mut self) -> Vec<(TaskId, Task)> {
        let (done, keep): (Vec<_>, Vec<_>) =
            self.executing.drain(..).partition(|(_, t)| t.is_finished());
        self.executing = keep;
        done
    }

    /// Pops the queue-head task while a concurrency slot is free (the
    /// task-taking half of upstream `update()`).
    pub fn pop_next(&mut self) -> Option<(TaskId, Task)> {
        if self.executing.len() >= self.capacity {
            return None;
        }
        self.waiting.pop_front()
    }

    pub fn push_executing(&mut self, id: TaskId, task: Task) {
        self.executing.push((id, task));
    }

    pub fn len_executing(&self) -> usize {
        self.executing.len()
    }

    pub fn len_waiting(&self) -> usize {
        self.waiting.len()
    }

    /// Removes an executing task by id (the response-routing path;
    /// swap_remove — the executing set is unordered, equivalent to aria2's
    /// erase).
    pub fn take_executing(&mut self, id: TaskId) -> Option<(TaskId, Task)> {
        let pos = self.executing.iter().position(|(tid, _)| *tid == id)?;
        Some(self.executing.swap_remove(pos))
    }

    /// Cancels all unfinished pings of the given bootstrap round (executing
    /// ones are marked finished and removed by retain_finished; queued ones
    /// are removed directly). Returns the cancel count.
    pub fn cancel_bootstrap_pings(&mut self, round: usize) -> usize {
        let mut cancelled = 0;
        for (_, task) in &mut self.executing {
            if let Task::Ping(p) = task
                && p.round == Some(round)
                && !p.finished
            {
                p.cancel();
                cancelled += 1;
            }
        }
        self.waiting.retain_mut(|(_, task)| match task {
            Task::Ping(p) if p.round == Some(round) && !p.finished => {
                p.cancel();
                cancelled += 1;
                false
            }
            _ => true,
        });
        cancelled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Test-only Option unwrapping (workspace lints forbid unwrap/expect).
    fn some<T>(o: Option<T>, what: &str) -> T {
        match o {
            Some(v) => v,
            None => panic!("{what}: None"),
        }
    }

    fn node(id_byte: u8, port: u16) -> DhtNode {
        let mut id = [0u8; DHT_ID_LENGTH];
        id[19] = id_byte;
        DhtNode::new(
            NodeId(id),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)),
        )
    }

    fn target(byte: u8) -> NodeId {
        let mut id = [0u8; DHT_ID_LENGTH];
        id[19] = byte;
        NodeId(id)
    }

    /// Drives at full speed: every send is answered immediately (in-flight
    /// back to zero); returns the send count.
    fn drive_all(l: &mut LookupTask, local: &NodeId, token: bool) -> usize {
        let mut sent = 0;
        while let Some(n) = l.next_outgoing() {
            let tok = if token {
                Some(format!("tok{}", n.id().0[19]).into_bytes())
            } else {
                None
            };
            l.on_response(&n, tok.as_deref(), Vec::new(), local);
            sent += 1;
        }
        sent
    }

    /// After seed, candidates ascend by XOR distance; the ALPHA in-flight cap
    /// (upstream sendMessage/ALPHA).
    #[test]
    fn lookup_seeds_sorted_and_caps_in_flight_at_alpha() {
        let mut l = LookupTask::new(target(0x00), LookupKind::Nodes, DhtSwarmKind::V1);
        // Feed 10 candidates out of order (ids 9..0) + 1 far node.
        let mut closest: Vec<DhtNode> = (0u8..10)
            .rev()
            .map(|i| node(i, 1000 + u16::from(i)))
            .collect();
        closest.push(node(0xAA, 9999));
        l.seed(closest);
        assert!(!l.finished());
        let s1 = some(l.next_outgoing(), "first");
        assert_eq!(s1.id().0[19], 0x00, "the closest sends first");
        let s2 = some(l.next_outgoing(), "second");
        assert_eq!(s2.id().0[19], 0x01);
        let s3 = some(l.next_outgoing(), "third");
        assert_eq!(s3.id().0[19], 0x02);
        for index in 3..ALPHA {
            let node = some(l.next_outgoing(), "remaining initial concurrency");
            assert_eq!(usize::from(node.id().0[19]), index);
        }
        assert!(
            l.next_outgoing().is_none(),
            "initial concurrency is bounded"
        );
        assert_eq!(l.in_flight(), ALPHA);
        let _ = (s1, s2, s3);
    }

    /// Candidate frontier truncation table: default 16 / the
    /// `BH_DHT_FRONTIER_K=8` fallback (the aria2-translation old width,
    /// truncate to K) / too few candidates (no tail truncation, all are
    /// contactable). Driving 20 candidates at full speed → sends =
    /// min(candidates, frontier).
    #[test]
    fn lookup_truncates_candidates_to_frontier() {
        let local = target(0xFF);
        // Default frontier 16 (LOOKUP_FRONTIER_K; env unset → lookup_frontier_k
        // returns the constant): 20 candidates, 16 sent.
        let mut l = LookupTask::new(target(0x00), LookupKind::Nodes, DhtSwarmKind::V1);
        assert_eq!(
            lookup_frontier_k(),
            LOOKUP_FRONTIER_K,
            "default chain locked"
        );
        l.seed((0u8..20).map(|i| node(i, 2000 + u16::from(i))).collect());
        let sent = drive_all(&mut l, &local, false);
        assert_eq!(sent, LOOKUP_FRONTIER_K);
        assert!(l.check_finished(), "in-flight zeroed means finished");
        // Fallback arm (=8, the aria2-translation old width): 20 candidates send
        // only K=8 (the old behavior).
        let mut l8 =
            LookupTask::with_frontier(target(0x00), LookupKind::Nodes, DhtSwarmKind::V1, K);
        l8.seed((0u8..20).map(|i| node(i, 2100 + u16::from(i))).collect());
        let sent8 = drive_all(&mut l8, &local, false);
        assert_eq!(
            sent8, K,
            "BH_DHT_FRONTIER_K=8 fallback = the old truncate-to-K behavior"
        );
        // Too few candidates (10 < frontier 16): no truncation, all 10 contactable.
        let mut l10 = LookupTask::new(target(0x00), LookupKind::Nodes, DhtSwarmKind::V1);
        l10.seed((0u8..10).map(|i| node(i, 2200 + u16::from(i))).collect());
        let sent10 = drive_all(&mut l10, &local, false);
        assert_eq!(
            sent10, 10,
            "fewer candidates than the frontier -> no truncation loss"
        );
    }

    /// An empty-table seed → finishes immediately (the offline degraded path, aria2 startup).
    #[test]
    fn lookup_with_empty_table_finishes_immediately() {
        let mut l = LookupTask::new(target(0x01), LookupKind::Nodes, DhtSwarmKind::V1);
        l.seed(Vec::new());
        assert!(l.finished());
        assert!(l.check_finished());
    }

    /// Response merge: entry node replaced by address, local ID skipped, dedup (upstream onReceived).
    #[test]
    fn lookup_response_replaces_merges_dedups() {
        let local = target(0xFF);
        let mut l = LookupTask::new(target(0x00), LookupKind::Nodes, DhtSwarmKind::V1);
        l.seed(vec![node(0x01, 1001)]);
        let first = some(l.next_outgoing(), "send");

        // The responder shares first's address with a newer id → the entry is replaced by address.
        let mut rid = [0u8; DHT_ID_LENGTH];
        rid[19] = 0x42;
        let responder = DhtNode::new(NodeId(rid), first.addr());
        let dup = node(0x01, 1001);
        let self_node = DhtNode::new(local, first.addr());
        l.on_response(
            &responder,
            Some(b"tok42".as_slice()),
            vec![dup, self_node],
            &local,
        );

        assert_eq!(l.in_flight(), 0);
        assert!(l.check_finished());
        // The used entry = the original one (replaced by the responder identity)
        // — the duplicate deduped, the local id skipped.
        let targets = l.announce_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].0.id().0[19],
            0x42,
            "entry replaced by the responder identity"
        );
    }

    /// A timeout removes the entry; finished once in-flight zeroes (upstream onTimeout).
    #[test]
    fn lookup_timeout_removes_entry_and_finishes() {
        let mut l = LookupTask::new(target(0x00), LookupKind::Nodes, DhtSwarmKind::V1);
        l.seed(vec![node(0x01, 1001)]);
        let n = some(l.next_outgoing(), "send");
        l.on_timeout(n.id(), n.addr());
        assert_eq!(l.in_flight(), 0);
        assert!(l.check_finished());
    }

    /// Announce targets = used entries holding a token (DHTPeerLookupTask.cc).
    /// The frontier is pinned to K=8 (this test locks token semantics; the
    /// width face lives in [`lookup_truncates_candidates_to_frontier`]).
    #[test]
    fn announce_targets_only_used_with_token() {
        let local = target(0xFF);
        let mut l = LookupTask::with_frontier(
            target(0x00),
            LookupKind::Peers {
                announce_port: Some(6881),
            },
            DhtSwarmKind::V1,
            K,
        );
        l.seed((0u8..10).map(|i| node(i, 2000 + u16::from(i))).collect());
        let sent = drive_all(&mut l, &local, true);
        assert_eq!(sent, K);
        let targets = l.announce_targets();
        assert_eq!(targets.len(), K, "all used and carrying a token");
        assert!(targets.iter().all(|(_, t)| t.starts_with(b"tok")));
        assert!(l.kind.announces());
    }

    /// Used entries without a token stay out of the announce targets (upstream skips empty tokens).
    #[test]
    fn announce_targets_skip_missing_token() {
        let local = target(0xFF);
        let mut l = LookupTask::new(
            target(0x00),
            LookupKind::Peers {
                announce_port: Some(6881),
            },
            DhtSwarmKind::V1,
        );
        l.seed(vec![node(0x01, 1001), node(0x02, 1002)]);
        let mut sent = 0;
        while let Some(n) = l.next_outgoing() {
            // Only the first response carries a token.
            let tok = if sent == 0 {
                Some(b"tok".to_vec())
            } else {
                None
            };
            l.on_response(&n, tok.as_deref(), Vec::new(), &local);
            sent += 1;
        }
        let targets = l.announce_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].1, b"tok".to_vec());
    }

    /// Ping retry inclusive-bound semantics (DHTPingTask.cc): max=0 → the
    /// first timeout finishes; max=10 → the 10th timeout finishes (the
    /// initial send plus 10 resend chances).
    #[test]
    fn ping_retry_matches_reference_semantics() {
        let mut p0 = PingTask::new(node(1, 1), 0);
        assert!(
            !p0.on_timeout(),
            "numRetry=1 >= max=0 -> finishes immediately"
        );
        assert!(p0.finished());
        assert!(!p0.success);

        let mut p10 = PingTask::new(node(1, 1), 10);
        for i in 0..9 {
            assert!(p10.on_timeout(), "timeout #{} should resend", i + 1);
        }
        assert!(!p10.finished());
        assert!(!p10.on_timeout(), "the 10th timeout finishes");
        assert!(p10.finished());
        assert!(!p10.success);

        let mut ok = PingTask::new(node(1, 1), 10);
        ok.on_response();
        assert!(ok.success);
        assert!(ok.finished());
    }

    /// Queue executor (DHTTaskExecutor.cc + DHTTaskQueueImpl.cc): 15
    /// concurrency slots, startup-time finishers occupy no slot, over-capacity
    /// does not dequeue.
    #[test]
    fn queue_refill_semantics() {
        let mut q = TaskQueue::new();
        assert_eq!(q.capacity, NUM_CONCURRENT_TASK);
        // 18 live tasks + 2 that finish during startup (empty table).
        for i in 0..20u8 {
            let mut t = LookupTask::new(target(i), LookupKind::Nodes, DhtSwarmKind::V1);
            if i < 18 {
                t.seed(vec![node(i, 3000 + u16::from(i))]);
            } else {
                t.seed(Vec::new());
            }
            q.push_waiting(u64::from(i), Task::Lookup(t));
        }
        // The engine refill loop: take only with a free slot; startup-time
        // finishers exit immediately without a slot.
        while let Some((id, task)) = q.pop_next() {
            if task.is_finished() {
                continue;
            }
            q.push_executing(id, task);
        }
        assert_eq!(
            q.len_executing(),
            NUM_CONCURRENT_TASK,
            "15 concurrent slots"
        );
        // Waiting = 5: the 15 slots were filled by live tasks before tasks 18/19
        // (the startup-time finishers) were consumed — they stay in waiting for
        // the next refill round (occupying no slot, DHTTaskExecutor.cc semantics).
        assert_eq!(q.len_waiting(), 5);
    }

    /// retain_finished removes finished items and frees their slots.
    #[test]
    fn queue_drains_finished_tasks() {
        let mut q = TaskQueue::new();
        for i in 0..3u8 {
            let mut t = LookupTask::new(target(i), LookupKind::Nodes, DhtSwarmKind::V1);
            t.seed(vec![node(i, 4000 + u16::from(i))]);
            q.push_waiting(u64::from(i), Task::Lookup(t));
        }
        while let Some((id, task)) = q.pop_next() {
            q.push_executing(id, task);
        }
        assert_eq!(q.len_executing(), 3);
        // Manually remove one; the rest remain.
        let taken = q.take_executing(1);
        assert!(taken.is_some());
        assert_eq!(q.len_executing(), 2);
        assert!(
            q.retain_finished().is_empty(),
            "unfinished tasks are not removed"
        );
        assert_eq!(q.len_executing(), 2);
    }

    /// XOR distance order (byte-order comparison = numeric order).
    #[test]
    fn xor_distance_ordering() {
        let t = target(0x00);
        let a = node(0x01, 1);
        let b = node(0x02, 2);
        assert_eq!(distance_cmp(&t, &a, &b), Ordering::Less);
        assert_eq!(distance_cmp(&t, &b, &a), Ordering::Greater);
        assert_eq!(distance_cmp(&t, &a, &a), Ordering::Equal);
    }

    fn distance_cmp(target: &NodeId, a: &DhtNode, b: &DhtNode) -> Ordering {
        xor_distance(target, a.id()).cmp(&xor_distance(target, b.id()))
    }
}

#[cfg(test)]
mod adaptive_lookup_tests {
    use super::*;
    fn node(n: u8) -> DhtNode {
        DhtNode::new(
            NodeId([n; 20]),
            std::net::SocketAddr::from(([127, 0, 0, 1], 1000 + u16::from(n))),
        )
    }
    #[test]
    fn soft_timeout_replaces_opportunity_without_losing_late_response_or_exceeding_cap() {
        let mut lookup = LookupTask::new(
            NodeId([0; 20]),
            LookupKind::Peers {
                announce_port: None,
            },
            DhtSwarmKind::V1,
        );
        lookup.seed((1..=16).map(node).collect());
        let mut sent = Vec::new();
        for _ in 0..ALPHA {
            sent.push(lookup.next_outgoing().unwrap_or_else(|| panic!("initial")));
        }
        assert!(lookup.next_outgoing().is_none());
        lookup.on_soft_timeout(sent[0].addr());
        assert_eq!(lookup.in_flight(), ALPHA - 1);
        let replacement = lookup
            .next_outgoing()
            .unwrap_or_else(|| panic!("replacement"));
        lookup.on_response(&sent[0], Some(b"token"), Vec::new(), &NodeId([0; 20]));
        assert_eq!(
            lookup.in_flight(),
            ALPHA,
            "late reply must not release an active replacement slot"
        );
        sent.push(replacement);
        loop {
            for peer in &sent {
                lookup.on_soft_timeout(peer.addr());
            }
            let Some(peer) = lookup.next_outgoing() else {
                break;
            };
            sent.push(peer);
        }
        assert!(lookup.pending.len() <= ALPHA * 3);
        assert!(!lookup.check_finished());
        for peer in &sent {
            lookup.on_timeout(peer.id(), peer.addr());
        }
        while let Some(peer) = lookup.next_outgoing() {
            lookup.on_timeout(peer.id(), peer.addr());
        }
        assert!(lookup.check_finished());
    }
    #[test]
    fn newly_discovered_closer_nodes_do_not_wait_for_far_queries() {
        let mut lookup = LookupTask::new(NodeId([0; 20]), LookupKind::Nodes, DhtSwarmKind::V1);
        lookup.seed((100..110).map(node).collect());
        let first = lookup.next_outgoing().unwrap_or_else(|| panic!("first"));
        for _ in 1..ALPHA {
            lookup.next_outgoing();
        }
        lookup.on_response(&first, None, (1..=5).map(node).collect(), &NodeId([0; 20]));
        let mut fresh = Vec::new();
        while let Some(peer) = lookup.next_outgoing() {
            fresh.push(peer);
        }
        assert_eq!(fresh.len(), ALPHA);
        assert!(fresh.iter().all(|peer| peer.id().0[0] <= 5));
    }
}

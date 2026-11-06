//! Task registration and driving: immediate/periodic dual-queue
//! registration (alloc/enqueue/take), task lifecycle (startup -> reply-
//! driven -> completion) and queue refill (execution order mirrors
//! `DHTTaskExecutor`/`DHTTaskQueueImpl`).
//!
//! Owns: the task state machine.
//! Does not own: network send/receive (wire) and post-completion
//! bootstrap/announce bookkeeping (bootstrap/command).

use std::time::Instant;

use tracing::debug;

use super::*;

/// Outbound find_node/get_peers always carry want=[n4,n6] (BEP32): "The
/// "want" parameter is allowed in the find_nodes and get_peers requests"
/// — dual-stack peers return nodes and nodes6 in one frame, so this node
/// can learn the other family from either family's routes (bootstrap
/// node_lookup / bucket refresh / peer lookups all egress through the
/// single drive_lookup point). Single-stack candidate filtering: see
/// drive_lookup.
const OUTBOUND_WANT: WantFamilies = WantFamilies::BOTH;

impl DhtEngine {
    // ===== Task registration / queues =====

    fn alloc_task_id(&mut self) -> TaskId {
        let id = self.next_task_id;
        self.next_task_id += 1;
        id
    }

    pub(super) fn enqueue(&mut self, kind: QueueKind, task: Task) {
        let id = self.alloc_task_id();
        self.queue_mut(kind).push_waiting(id, task);
    }

    fn queue_mut(&mut self, kind: QueueKind) -> &mut TaskQueue {
        match kind {
            QueueKind::Immediate => &mut self.immediate,
            QueueKind::Periodic => &mut self.periodic,
        }
    }

    pub(super) fn take_task(&mut self, id: TaskId) -> Option<(QueueKind, Task)> {
        for kind in [QueueKind::Periodic, QueueKind::Immediate] {
            if let Some((_, task)) = self.queue_mut(kind).take_executing(id) {
                return Some((kind, task));
            }
        }
        None
    }

    // ===== Task driving (startup / replies / completion) =====

    /// Task startup (mirrors `DHTTaskExecutor::update`'s `task->startup()`;
    /// a task may complete during startup — empty-table lookup, a refresh
    /// with nothing to fan out).
    async fn startup_task(&mut self, id: TaskId, task: &mut Task, now: Instant) {
        match task {
            Task::Ping(p) => {
                // DHTPingTask::startup -> addMessage; send failure is folded
                // into a synchronous retry loop under timeout accounting
                // (the reference reaches the same state machine
                // asynchronously via tracker timeout=0; the retry cap is
                // unchanged).
                loop {
                    let node = p.node.clone();
                    if self
                        .send_query(Some(id), &node, QueryBody::Ping, MessageKind::Ping, now)
                        .await
                    {
                        break;
                    }
                    if !p.on_timeout() {
                        break;
                    }
                }
            }
            Task::Lookup(l) => {
                // DHTAbstractNodeLookupTask::startup: candidates = the
                // closest K from the routing table; empty table -> complete
                // immediately (offline degrade).
                let closest = self.table.get_closest_k_nodes(&l.target);
                l.seed(closest);
                self.drive_lookup(id, l, now).await;
            }
            Task::Refresh(r) => {
                // DHTBucketRefreshTask::startup: for each bucket with
                // force || needsRefresh, take a random ID in range,
                // notifyUpdate, dispatch a node lookup (periodic), then
                // complete.
                let mut targets = Vec::new();
                for bucket in self.table.buckets() {
                    if r.force || bucket.needs_refresh(now) {
                        targets.push(bucket.random_id_in_range(&mut self.rng));
                    }
                }
                for target in &targets {
                    self.table.notify_refreshed(target, now);
                }
                for target in targets {
                    debug!(target: LOG_TARGET, "dispatching bucket refresh lookup");
                    let id = self.alloc_task_id();
                    self.periodic.push_waiting(
                        id,
                        Task::Lookup(LookupTask::new(target, LookupKind::Nodes, DhtSwarmKind::V1)),
                    );
                }
                r.complete();
            }
        }
    }

    /// Drive a lookup: keep ALPHA queries in flight (`sendMessage`). Send
    /// failure removes the entry under timeout accounting (reference: a
    /// dispatcher send failure registers the tracker entry as an immediate
    /// timeout, `DHTMessageDispatcherImpl.cc`). The end of the drive runs
    /// the finish check (the checkFinish half of `sendMessageAndCheckFinish`:
    /// complete when nothing is in flight) — a zero-outbound shape (all
    /// candidates wrong-family and dropped) never reaches the transaction
    /// layer; without this check the task would stay in the executing set
    /// forever.
    ///
    /// Wrong-family candidate filtering: this engine is single-stack per
    /// instance (a v4-bound socket cannot emit v6 packets) — foreign-family
    /// nodes learned from want=[n4,n6] replies are not query candidates
    /// and are dropped under timeout accounting (not the 400ms transaction
    /// timeout wait); their presence in the table still serves the reply
    /// side's dual-key advertisement. next_outgoing already counted
    /// in_flight and on_timeout exactly offsets it.
    async fn drive_lookup(&mut self, id: TaskId, l: &mut LookupTask, now: Instant) {
        let family_v4 = self.family == persist::DhtFamily::V4;
        while !l.finished() {
            let Some(node) = l.next_outgoing() else {
                break;
            };
            if node.addr().is_ipv4() != family_v4 {
                l.on_timeout(node.id(), node.addr());
                continue;
            }
            let (body, method) = match l.kind {
                LookupKind::Nodes => (
                    QueryBody::FindNode {
                        target: l.target,
                        want: OUTBOUND_WANT,
                    },
                    MessageKind::FindNode,
                ),
                LookupKind::Peers { .. } => (
                    QueryBody::GetPeers {
                        info_hash: l.target,
                        want: OUTBOUND_WANT,
                    },
                    MessageKind::GetPeers,
                ),
            };
            let sent = self.send_query(Some(id), &node, body, method, now).await;
            if !sent {
                l.on_timeout(node.id(), node.addr());
            }
        }
        l.check_finished();
    }

    /// Advance a task after its transaction settles: apply timeout side
    /// effects -> drive -> on completion remove and finish, otherwise put
    /// the task back into the executing set.
    pub(super) async fn progress_task(
        &mut self,
        queue: QueueKind,
        id: TaskId,
        mut task: Task,
        timed_out: Option<(&DhtNode, SocketAddr)>,
        now: Instant,
    ) {
        let mut finished = task.is_finished();
        match &mut task {
            Task::Ping(p) => {
                if timed_out.is_some() && !finished {
                    let mut resend = p.on_timeout();
                    while resend {
                        let node = p.node.clone();
                        let sent = self
                            .send_query(Some(id), &node, QueryBody::Ping, MessageKind::Ping, now)
                            .await;
                        resend = if sent { false } else { p.on_timeout() };
                    }
                    finished = p.finished();
                }
            }
            Task::Lookup(l) => {
                if let Some((node, addr)) = timed_out {
                    l.on_timeout(node.id(), addr);
                }
                self.drive_lookup(id, l, now).await;
                finished = l.check_finished();
            }
            Task::Refresh(_) => {}
        }
        if finished {
            self.complete_task(&task, now).await;
        } else {
            self.queue_mut(queue).push_executing(id, task);
        }
    }

    /// Task completion: bootstrap round accounting / announce phase
    /// dispatch (DHTPeerLookupTask.cc onFinish: send announce_peer to the
    /// K probed nodes, fire-and-forget) + registry backfill.
    async fn complete_task(&mut self, task: &Task, now: Instant) {
        match task {
            Task::Ping(p) => {
                if let Some(round) = p.round {
                    self.advance_bootstrap(round, p.success);
                }
            }
            Task::Lookup(l) => {
                if let LookupKind::Peers {
                    announce_port: Some(port),
                } = l.kind
                {
                    let mut sent = 0usize;
                    for (node, token) in l.announce_targets() {
                        // BEP42 enforcement: never store on a node whose id
                        // does not match its source IP — announce_peer is
                        // storage ("MUST never be used to store information
                        // on, regardless of which request").
                        if !verify_node_id(node.id(), node.addr().ip()) {
                            debug!(target: LOG_TARGET, addr = %node.addr(),
                                "announce_peer skipped: target node id not BEP42 compliant");
                            continue;
                        }
                        if self
                            .send_query(
                                None,
                                &node,
                                QueryBody::AnnouncePeer {
                                    info_hash: l.target,
                                    port,
                                    token,
                                    implied_port: None,
                                },
                                MessageKind::AnnouncePeer,
                                now,
                            )
                            .await
                        {
                            sent += 1;
                        }
                    }
                    if let Some(entry) = self.our_announces.get_mut(&l.target) {
                        entry.inflight = false;
                        // Only a round that actually sent >=1 announce_peer
                        // enters the 15min quiet window (last_announced =
                        // the start of the resend cadence); zero sent
                        // (empty-table seed / no tokens — the cold-start
                        // assembly race where announce registration
                        // precedes bootstrap settling) does not occupy the
                        // window; the next PeerAnnounceCheck re-dispatches.
                        if sent > 0 {
                            entry.last_announced = Some(now);
                        }
                    }
                }
            }
            Task::Refresh(_) => {}
        }
    }

    /// Queue refill (`DHTTaskExecutor.cc`; periodic first, then immediate,
    /// mirroring the `DHTTaskQueueImpl.cc` execution order).
    pub(super) async fn refill(&mut self, kind: QueueKind, now: Instant) {
        let done = self.queue_mut(kind).retain_finished();
        for (_, task) in done {
            self.complete_task(&task, now).await;
        }
        loop {
            let next = self.queue_mut(kind).pop_next();
            let Some((id, mut task)) = next else {
                break;
            };
            if task.is_finished() {
                // A cancelled bootstrap ping is not started (no frame, no
                // concurrency slot; accounting already settled by the
                // settle path).
                continue;
            }
            self.startup_task(id, &mut task, now).await;
            if task.is_finished() {
                self.complete_task(&task, now).await;
            } else {
                self.queue_mut(kind).push_executing(id, task);
            }
        }
    }
}

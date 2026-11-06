//! DHT transaction table: transaction_id/(addr) -> oneshot reply channel
//! registration and timeout sweep (mirrors aria2
//! `DHTMessageTracker.{h,cc}` + `DHTMessageTrackerEntry.cc`).
//!
//! # Semantics
//!
//! - Transaction timeout 10s (`DHTConstants.h` `DHT_MESSAGE_TIMEOUT`,
//! matching the `--dht-message-timeout` option); expiry is
//! `elapsed >= timeout` (`DHTMessageTrackerEntry.cc`, closed boundary);
//! - Reply match key: transaction id + peer (ip, port)
//! (`DHTMessageTrackerEntry.cc` match; aria2 additionally tolerates
//! `::ffff:` IPv4-mapped string forms — an artifact of storing IPs as
//! strings; with [`SocketAddr`] value semantics the dual form does not
//! exist, see docs/design/dht.md);
//! - One sweep removes all expired entries in a single pass
//! (`DHTMessageTracker.cc` handleTimeout's remove_if);
//! - Node scoring after expiry (timeout + bad -> replace) does not happen
//! in the table — the engine calls `RoutingTable::record_timeout` on the
//! [`PendingTransaction`] (aria2 handleTimeoutEntry,
//! `DHTMessageTracker.cc`);
//! - Error replies (y="e") take the exception path in aria2 and are
//! treated as timeouts (`DHTMessageTracker.cc` catch
//! RecoverableException -> handleTimeoutEntry); this implementation's
//! [`TransactionOutcome::Error`] lets the engine run `record_timeout`
//! the same way.
//!
//! # Concurrency
//!
//! The table is owned by the DhtEngine actor (&mut self methods, no
//! internal lock — "no Mutex across await"); the oneshot reply half is
//! kept by the registrant.
//!
//! # Boundedness audit (code-reading record, no behavior
//! change)
//!
//! The table cannot grow past a small structural ceiling, so no hard cap
//! was added (a cap would be dead defensive code):
//!
//! - Registrations happen only on **our own outbound queries** with a
//! tracking task (`engine/wire.rs send_query(task_id: Some)`);
//! announce_peer is fire-and-forget (`task_id: None`, no entry);
//! inbound query floods never register.
//! - The registration rate is engine-driven and alpha-capped: each
//! lookup keeps at most [`super::task::ALPHA`] (= 3) queries in flight
//! (`LookupTask::next_outgoing` gates on `in_flight >= ALPHA`), and
//! the concurrent task population is itself bounded (bucket refresh ≤ 1
//! lookup per stale bucket × 8 buckets, peer lookups single-flight per
//! announce entry — `engine/state.rs` `AnnounceEntry::inflight`,
//! bootstrap rounds ≤ entry count). Worst case is tens of entries ×
//! ~150B ≈ a few KiB.
//! - Reclamation has no delay gap: the main loop runs the sweep every
//! iteration and its wake deadline includes
//! [`TransactionTable::next_deadline`], so a lost reply costs exactly
//! `message_timeout` (10s); the parallel `route` map
//! (`HashMap<TransactionKey, RouteTarget>`) is removed on **every**
//! settlement path (`on_transaction_done` covers response / error /
//! timeout / sweep / duplicate-replace) — no residue.
//! - Autosave (`emit_persist`) serializes only the K-bucket routing table
//! (`persist.rs` `encode_table`, ≤ K×buckets nodes plus replacement
//! candidates); transactions, routes and peer-records are never
//! persisted, and the in-memory peer-record store has its own caps
//! (500/key, 8192 total, 30min sanitization — `engine/wire.rs` +
//! `engine/state.rs`), so no save/load cycle can accumulate stale
//! HashMap entries across restarts.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use super::DhtError;
use super::message::{ErrorMessage, MessageKind, ResponseMessage};

/// Transaction timeout. aria2 `src/DHTConstants.h`
/// (`DHT_MESSAGE_TIMEOUT = 10_s`).
pub const DHT_MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Transaction key: local 4B transaction id + peer address
/// (`DHTMessageTrackerEntry.cc`; the id is locally generated, 4B,
/// `DHTConstants.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    pub transaction_id: [u8; 4],
    pub addr: SocketAddr,
}

/// Transaction outcome (oneshot payload).
#[derive(Debug)]
pub enum TransactionOutcome {
    /// Response received (already decoded at the message layer; the engine
    /// checks the body type against `method`).
    Response(Box<ResponseMessage>),
    /// Error reply received (y="e"; the engine should also score the node
    /// as a timeout, mirroring `DHTMessageTracker.cc`).
    Error(Box<ErrorMessage>),
    /// Transaction failed.
    Failed(TransactionFailure),
}

/// Failure reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionFailure {
    /// Timed out in the sweep (10s, closed boundary).
    Timeout,
    /// Duplicate key registration; the old transaction was replaced and
    /// cancelled.
    Cancelled,
}

/// Registered transaction (bookkeeping + reply half).
#[derive(Debug)]
pub struct PendingTransaction {
    pub key: TransactionKey,
    /// Query method at initiation (how the reply body type is checked;
    /// mirrors DHTMessageTrackerEntry's messageType_).
    pub method: MessageKind,
    pub registered_at: Instant,
    pub timeout: Duration,
    pub reply: oneshot::Sender<TransactionOutcome>,
}

impl PendingTransaction {
    /// Expired? (`elapsed >= timeout`, closed boundary; mirrors
    /// `DHTMessageTrackerEntry.cc`).
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.registered_at) >= self.timeout
    }
}

/// Transaction table (HashMap; owned by the engine actor).
#[derive(Debug, Default)]
pub struct TransactionTable {
    entries: HashMap<TransactionKey, PendingTransaction>,
}

impl TransactionTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an outbound query transaction. On a duplicate key the old
    /// transaction's reply receives [`TransactionFailure::Cancelled`] and
    /// the entry is replaced (aria2 appends to a deque and consumes the
    /// first hit, `DHTMessageTracker.cc`; with 4B random ids collisions
    /// are negligible; replacement prevents table growth, see
    /// docs/design/dht.md).
    pub fn register(
        &mut self,
        transaction_id: [u8; 4],
        addr: SocketAddr,
        method: MessageKind,
        timeout: Duration,
        reply: oneshot::Sender<TransactionOutcome>,
        now: Instant,
    ) -> Result<(), DhtError> {
        let key = TransactionKey {
            transaction_id,
            addr,
        };
        let pending = PendingTransaction {
            key,
            method,
            registered_at: now,
            timeout,
            reply,
        };
        if let Some(old) = self.entries.insert(key, pending) {
            let _ = old
                .reply
                .send(TransactionOutcome::Failed(TransactionFailure::Cancelled));
        }
        Ok(())
    }

    /// Non-consuming membership check (same key shape as [`Self::pop`]):
    /// the inbound hot path's early-drop gate — a y="r"/y="e" packet whose
    /// (transaction_id, addr) has no pending transaction is dropped before
    /// the full bencode decode (identical outcome to the decode-then-pop
    /// path, whose pop-None arm is also a silent drop). A wire transaction
    /// id not 4B long can never match a local transaction.
    pub fn contains(&self, transaction_id: &[u8], addr: SocketAddr) -> bool {
        if transaction_id.len() != 4 {
            return false;
        }
        let mut tid = [0u8; 4];
        tid.copy_from_slice(transaction_id);
        self.entries.contains_key(&TransactionKey {
            transaction_id: tid,
            addr,
        })
    }

    /// Reply arrived: take the transaction by exact (transaction_id, addr)
    /// (mirrors messageArrived's lookup + erase, `DHTMessageTracker.cc`).
    /// A wire transaction id not 4B long can never match a local
    /// transaction.
    pub fn pop(&mut self, transaction_id: &[u8], addr: SocketAddr) -> Option<PendingTransaction> {
        if transaction_id.len() != 4 {
            return None;
        }
        let mut tid = [0u8; 4];
        tid.copy_from_slice(transaction_id);
        self.entries.remove(&TransactionKey {
            transaction_id: tid,
            addr,
        })
    }

    /// Timeout sweep: remove and return all expired transactions (mirrors
    /// handleTimeout's remove_if, `DHTMessageTracker.cc`; expiry per
    /// `DHTMessageTrackerEntry.cc`).
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<PendingTransaction> {
        let expired: Vec<TransactionKey> = self
            .entries
            .values()
            .filter(|e| e.is_expired(now))
            .map(|e| e.key)
            .collect();
        expired
            .into_iter()
            .filter_map(|k| self.entries.remove(&k))
            .collect()
    }

    /// Number of registered transactions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Earliest transaction deadline (the engine's in-loop wake source:
    /// the main loop's `select` sleep deadline must include transaction
    /// timeouts — otherwise, after packet loss, resends sleep until the
    /// next inbound packet or maintenance timer (5min scale) and
    /// bootstrap/lookups cannot converge at the
    /// [`super::transaction::DHT_MESSAGE_TIMEOUT`] pace on lossy networks;
    /// aria2 covers the same need with second-level TimeBasedCommand
    /// ticks).
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .values()
            .map(|e| e.registered_at + e.timeout)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port))
    }

    /// 10s transaction timeout boundary (closed `>=` boundary per
    /// DHTMessageTrackerEntry.cc; constant DHTConstants.h).
    #[test]
    fn timeout_boundary_is_inclusive_at_ten_seconds() {
        let t0 = Instant::now();
        let (tx, _rx) = oneshot::channel();
        let mut table = TransactionTable::new();
        if let Err(e) = table.register(
            [1, 2, 3, 4],
            addr(6881),
            MessageKind::Ping,
            DHT_MESSAGE_TIMEOUT,
            tx,
            t0,
        ) {
            panic!("register failed: {e:?}");
        }
        // At 9.999s: not expired.
        let almost = t0 + Duration::from_nanos(9_999_999_999);
        assert!(table.handle_timeout(almost).is_empty());
        // Exactly 10s: expired (closed boundary).
        let exact = t0 + DHT_MESSAGE_TIMEOUT;
        let expired = table.handle_timeout(exact);
        assert_eq!(expired.len(), 1);
        assert!(table.is_empty());
    }

    /// Reply matching: both tid and addr must be equal
    /// (DHTMessageTrackerEntry.cc).
    #[test]
    fn pop_requires_exact_tid_and_addr() {
        let t0 = Instant::now();
        let (tx, _rx) = oneshot::channel();
        let mut table = TransactionTable::new();
        if let Err(e) = table.register(
            [0xaa, 0xbb, 0xcc, 0xdd],
            addr(6881),
            MessageKind::GetPeers,
            DHT_MESSAGE_TIMEOUT,
            tx,
            t0,
        ) {
            panic!("register failed: {e:?}");
        }
        assert!(table.pop(&[0xaa, 0xbb, 0xcc, 0xdd], addr(6882)).is_none());
        assert!(table.pop(&[0xaa, 0xbb, 0xcc, 0xdc], addr(6881)).is_none());
        assert!(table.pop(&[0xaa, 0xbb, 0xcc], addr(6881)).is_none());
        let hit = table.pop(&[0xaa, 0xbb, 0xcc, 0xdd], addr(6881));
        assert!(matches!(hit, Some(ref p) if p.method == MessageKind::GetPeers));
    }

    /// Non-consuming membership check (the inbound early-drop gate's key
    /// face): same key shape as pop, never removes — a contains
    /// hit is followed by the full decode + pop on the strict path, and
    /// the entry survives the check; a non-4B tid never matches.
    #[test]
    fn contains_matches_key_shape_without_consuming() {
        let t0 = Instant::now();
        let (tx, _rx) = oneshot::channel();
        let mut table = TransactionTable::new();
        if let Err(e) = table.register(
            [0x11, 0x22, 0x33, 0x44],
            addr(6881),
            MessageKind::Ping,
            DHT_MESSAGE_TIMEOUT,
            tx,
            t0,
        ) {
            panic!("register failed: {e:?}");
        }
        assert!(table.contains(&[0x11, 0x22, 0x33, 0x44], addr(6881)));
        assert!(!table.contains(&[0x11, 0x22, 0x33, 0x44], addr(6882)));
        assert!(!table.contains(&[0x11, 0x22, 0x33, 0x45], addr(6881)));
        assert!(!table.contains(&[0x11, 0x22, 0x33], addr(6881)));
        // Non-consuming: the entry is still there for the strict path's pop.
        assert_eq!(table.len(), 1);
        assert!(table.pop(&[0x11, 0x22, 0x33, 0x44], addr(6881)).is_some());
        assert!(!table.contains(&[0x11, 0x22, 0x33, 0x44], addr(6881)));
    }

    /// Duplicate registration: the old transaction receives Cancelled, the
    /// new one takes effect (replacement semantics in the module docs).
    #[test]
    fn duplicate_registration_cancels_old() {
        let t0 = Instant::now();
        let mut table = TransactionTable::new();
        let (tx_old, mut rx_old) = oneshot::channel();
        let (tx_new, _rx_new) = oneshot::channel();
        for tx in [tx_old, tx_new] {
            if let Err(e) = table.register(
                [9; 4],
                addr(6881),
                MessageKind::Ping,
                DHT_MESSAGE_TIMEOUT,
                tx,
                t0,
            ) {
                panic!("register failed: {e:?}");
            }
        }
        assert!(matches!(
            rx_old.try_recv().ok(),
            Some(TransactionOutcome::Failed(TransactionFailure::Cancelled))
        ));
        assert_eq!(table.len(), 1);
    }

    /// Mixed sweep: only expired entries are removed (DHTMessageTracker.cc).
    #[test]
    fn sweep_removes_only_expired() {
        let t0 = Instant::now();
        let mut table = TransactionTable::new();
        for (tid, timeout) in [([1; 4], 5u64), ([2; 4], 10), ([3; 4], 15)] {
            let (tx, _rx) = oneshot::channel();
            if let Err(e) = table.register(
                tid,
                addr(6881),
                MessageKind::Ping,
                Duration::from_secs(timeout),
                tx,
                t0,
            ) {
                panic!("register failed: {e:?}");
            }
        }
        let expired = table.handle_timeout(t0 + Duration::from_secs(10));
        assert_eq!(expired.len(), 2);
        assert_eq!(table.len(), 1);
        assert!(table.pop(&[3, 3, 3, 3], addr(6881)).is_some());
    }
}

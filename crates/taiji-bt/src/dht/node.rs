//! DHT node identity and state scoring (mirrors aria2 `DHTNode.{h,cc}`).
//!
//! # State machine (DHTNode.cc)
//!
//! - `condition` score: new nodes start at 1 (the constructor sets
//! `condition_` to 1 — a node never verified by contact is not good);
//! - Bad threshold `BAD_CONDITION = 5` (`DHTNode.cc`): `condition >= 5`
//! is bad;
//! - `timeout()`: condition + 1 (the transaction timeout path,
//! `DHTMessageTracker.cc`);
//! - `mark_good()`: condition reset to zero (`DHTNode.cc`);
//! - questionable: not bad and last contact >= 15min ago (`DHTNode.cc`,
//! interval constant `DHTConstants.h` `DHT_NODE_CONTACT_INTERVAL`);
//! - good: not bad and not questionable (`DHTNode.cc`).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::RngExt;

/// Node ID byte length. aria2 `src/DHTConstants.h` (`DHT_ID_LENGTH`).
pub const DHT_ID_LENGTH: usize = 20;
/// Bad-node score threshold. aria2 `src/DHTNode.cc` (`BAD_CONDITION`).
pub const BAD_CONDITION: u32 = 5;
/// Node contact interval (the questionable threshold). aria2
/// `src/DHTConstants.h`.
pub const DHT_NODE_CONTACT_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// 160-bit Kademlia node ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct NodeId(pub [u8; DHT_ID_LENGTH]);

impl NodeId {
    /// Read bit `bit` (0 = MSB of the first byte, 159 = LSB of the last;
    /// the same bit order as aria2 `bitfield::flipBit`, used by
    /// `DHTBucket.cc`).
    pub fn bit(&self, bit: u32) -> bool {
        debug_assert!(bit < 160);
        self.0[(bit / 8) as usize] & (0x80 >> (bit % 8)) != 0
    }

    /// Random node ID (for the local node; aria2 `DHTNode.cc` `generateID`
    /// -> `util::generateRandomKey`).
    pub fn random(rng: &mut impl RngExt) -> Self {
        let mut id = [0u8; DHT_ID_LENGTH];
        rng.fill(&mut id);
        NodeId(id)
    }
}

/// Routing table node (DhtNode): identity + address + RTT + score + last
/// contact.
#[derive(Clone, Debug)]
pub struct DhtNode {
    id: NodeId,
    addr: SocketAddr,
    rtt: Duration,
    condition: u32,
    /// None = never contacted (aria2 `Timer::zero()`, `DHTNode.cc`).
    last_contact: Option<Instant>,
}

impl DhtNode {
    /// Build from wire: condition = 1, no contact instant (mirrors
    /// `DHTNode.cc`'s parameterized constructor).
    pub fn new(id: NodeId, addr: SocketAddr) -> Self {
        DhtNode {
            id,
            addr,
            rtt: Duration::ZERO,
            condition: 1,
            last_contact: None,
        }
    }

    pub fn id(&self) -> &NodeId {
        &self.id
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn rtt(&self) -> Duration {
        self.rtt
    }

    /// Condition score (tests/persistence).
    pub fn condition(&self) -> u32 {
        self.condition
    }

    /// Last contact instant (None = never contacted).
    pub fn last_contact(&self) -> Option<Instant> {
        self.last_contact
    }

    /// `condition >= BAD_CONDITION`. aria2 `DHTNode.cc`.
    pub fn is_bad(&self) -> bool {
        self.condition >= BAD_CONDITION
    }

    /// Not bad and last contact >= [`DHT_NODE_CONTACT_INTERVAL`] ago (never
    /// contacted counts as questionable). aria2 `DHTNode.cc`.
    pub fn is_questionable(&self, now: Instant) -> bool {
        !self.is_bad()
            && match self.last_contact {
                // aria2's Timer::zero() differs from wallclock by an
                // epoch-scale gap, equivalent to "never contacted ->
                // necessarily questionable".
                None => true,
                Some(t) => now.duration_since(t) >= DHT_NODE_CONTACT_INTERVAL,
            }
    }

    /// good = not bad and not questionable. aria2 `DHTNode.cc`.
    pub fn is_good(&self, now: Instant) -> bool {
        !self.is_bad() && !self.is_questionable(now)
    }

    /// Reset condition to zero. aria2 `DHTNode.cc` (does not touch
    /// last_contact — the caller updates the contact instant separately,
    /// per the `DHTMessageReceiver.cc` ordering).
    pub fn mark_good(&mut self) {
        self.condition = 0;
    }

    /// Mark bad directly. aria2 `DHTNode.cc`.
    pub fn mark_bad(&mut self) {
        self.condition = BAD_CONDITION;
    }

    /// Timeout score +1. aria2 `DHTNode.cc` (called from the transaction
    /// timeout path, `DHTMessageTracker.cc`).
    pub fn timeout(&mut self) {
        self.condition += 1;
    }

    /// Update last contact. aria2 `DHTNode.cc`.
    pub fn update_last_contact(&mut self, now: Instant) {
        self.last_contact = Some(now);
    }

    /// Update the RTT. aria2 `DHTNode.cc` (transaction reply path,
    /// `DHTMessageTracker.cc`).
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    // Vector source: aria2 test/DHTNodeTest.cc.

    fn test_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 6881))
    }

    fn node(cond: u32, last_contact: Option<Instant>) -> DhtNode {
        let mut n = DhtNode::new(NodeId([0u8; 20]), test_addr());
        n.condition = cond;
        n.last_contact = last_contact;
        n
    }

    /// An instant 15min minus `s` seconds before `now` (derived from the
    /// same `now` to avoid two-clock skew).
    fn before(now: Instant, s: u64) -> Instant {
        match now.checked_sub(Duration::from_secs(15 * 60 - s)) {
            Some(t) => t,
            None => panic!("monotonic clock uptime < 15min, cannot build vector"),
        }
    }

    /// aria2 test/DHTNodeTest.cc (isGood/isBad/isQuestionable matrix):
    /// condition 0-4 not bad, >=5 bad.
    #[test]
    fn bad_threshold_is_five_timeouts() {
        let now = Instant::now();
        for cond in 0..5u32 {
            assert!(!node(cond, Some(now)).is_bad(), "condition={cond}");
        }
        assert!(node(5, Some(now)).is_bad());
        assert!(node(6, Some(now)).is_bad());
    }

    /// aria2 test/DHTNodeTest.cc: just contacted = good; 15min without
    /// contact = questionable (still not bad); never contacted =
    /// questionable.
    #[test]
    fn questionable_after_contact_interval() {
        let now = Instant::now();
        let fresh = node(0, Some(now));
        assert!(fresh.is_good(now));
        assert!(!fresh.is_questionable(now));

        let stale = node(0, Some(before(now, 0)));
        assert!(stale.is_questionable(now));
        assert!(!stale.is_good(now));
        assert!(!stale.is_bad());

        let never = node(0, None);
        assert!(never.is_questionable(now));
        assert!(!never.is_good(now));

        // 15min minus one second: still good (closed boundary, DHTNode.cc
        // uses >=).
        let almost = node(0, Some(before(now, 1)));
        assert!(!almost.is_questionable(now));
        assert!(almost.is_good(now));
    }

    /// aria2 test/DHTNodeTest.cc: markGood resets to zero; timeout adds 1
    /// per step; isBad after the 5th timeout.
    #[test]
    fn timeout_scoring_reaches_bad() {
        let mut n = DhtNode::new(NodeId([7u8; 20]), test_addr());
        n.mark_good();
        assert_eq!(n.condition(), 0);
        // New nodes start with condition=1 (DHTNode.cc).
        let mut fresh = DhtNode::new(NodeId([1u8; 20]), test_addr());
        assert_eq!(fresh.condition(), 1);
        for expect in 2..=5u32 {
            fresh.timeout();
            assert_eq!(fresh.condition(), expect);
            assert_eq!(fresh.is_bad(), expect >= BAD_CONDITION);
        }
        // mark_bad sets the threshold directly (DHTNode.cc).
        let mut bad = node(0, None);
        bad.mark_bad();
        assert!(bad.is_bad());
    }
}

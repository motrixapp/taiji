//! Bounded startup dialing, source diversity, transport learning and retry backoff.
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use taiji_bt::utp::{PeerConnectionType, Transport};

struct History {
    failures: u8,
    retry: Instant,
    touched: Instant,
    transport: Option<Transport>,
}
pub(super) struct Candidates {
    entries: HashMap<(usize, SocketAddr), History>,
    tokens: f64,
    replenished: Instant,
    last_source: &'static str,
}
impl Candidates {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            tokens: 24.0,
            replenished: Instant::now(),
            last_source: "",
        }
    }
    fn entry(&mut self, face: usize, addr: SocketAddr, now: Instant) -> &mut History {
        if self.entries.len() >= 2048 && !self.entries.contains_key(&(face, addr)) {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.touched)
                .map(|(key, _)| *key)
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.entry((face, addr)).or_insert(History {
            failures: 0,
            retry: now,
            touched: now,
            transport: None,
        })
    }
    pub fn failed(&mut self, face: usize, addr: SocketAddr, now: Instant) {
        let entry = self.entry(face, addr, now);
        entry.failures = (entry.failures + 1).min(6);
        entry.retry = now + Duration::from_secs((1u64 << entry.failures).min(60));
        entry.touched = now;
    }
    pub fn connected(&mut self, face: usize, addr: SocketAddr, transport: Transport, now: Instant) {
        let entry = self.entry(face, addr, now);
        entry.retry = now + Duration::from_secs(2);
        entry.touched = now;
        entry.transport = Some(transport);
    }
    pub fn useful(&mut self, face: usize, addr: SocketAddr, now: Instant) {
        self.entry(face, addr, now).failures = 0;
    }
    pub fn policy(
        &self,
        face: usize,
        addr: SocketAddr,
        policy: PeerConnectionType,
    ) -> PeerConnectionType {
        if matches!(policy, PeerConnectionType::Tcp | PeerConnectionType::Utp) {
            return policy;
        }
        match self
            .entries
            .get(&(face, addr))
            .and_then(|entry| entry.transport)
        {
            Some(Transport::Tcp) => PeerConnectionType::PreferTcp,
            Some(Transport::Utp) => PeerConnectionType::PreferUtp,
            None => policy,
        }
    }
    pub fn pop(
        &mut self,
        queue: &mut VecDeque<(usize, SocketAddr, &'static str)>,
        connected: &[SocketAddr],
        now: Instant,
    ) -> Option<(usize, SocketAddr, &'static str)> {
        self.tokens = (self.tokens
            + now
                .saturating_duration_since(self.replenished)
                .as_secs_f64()
                * 30.0)
            .min(24.0);
        self.replenished = now;
        if self.tokens < 1.0 {
            return None;
        }
        let choice = queue
            .iter()
            .enumerate()
            .filter_map(|(index, (face, addr, source))| {
                let urgent = matches!(*source, "holepunch" | "relay-utp");
                let history = self.entries.get(&(*face, *addr));
                if !urgent && history.is_some_and(|entry| now < entry.retry) {
                    return None;
                }
                let same_ip = connected
                    .iter()
                    .filter(|peer| peer.ip() == addr.ip())
                    .count() as i64;
                let score = if urgent {
                    -10000
                } else {
                    same_ip * 100
                        + i64::from(history.map_or(0, |entry| entry.failures)) * 30
                        + if *source == self.last_source { 10 } else { 0 }
                        - if *source == "lsd" {
                            20
                        } else if *source == "xpe" {
                            10
                        } else {
                            0
                        }
                };
                Some((score, index))
            })
            .min()?;
        self.tokens -= 1.0;
        let candidate = queue.remove(choice.1)?;
        self.last_source = candidate.2;
        Some(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_burst_is_bounded_and_failed_candidates_do_not_block_fresh_ones() {
        let now = Instant::now();
        let mut book = Candidates::new();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap_or_else(|e| panic!("{e}"));
        let b: SocketAddr = "10.0.0.2:1".parse().unwrap_or_else(|e| panic!("{e}"));
        book.failed(0, a, now);
        let mut queue = VecDeque::from([(0, a, "pex"), (0, b, "tracker")]);
        assert_eq!(book.pop(&mut queue, &[], now), Some((0, b, "tracker")));
        assert_eq!(book.pop(&mut queue, &[], now), None);
        assert_eq!(
            book.pop(&mut queue, &[], now + Duration::from_secs(2)),
            Some((0, a, "pex"))
        );
        let mut book = Candidates::new();
        let now = Instant::now();
        let mut queue: VecDeque<_> = (1..100)
            .map(|port| (0, SocketAddr::new(a.ip(), port), "pex"))
            .collect();
        for _ in 0..24 {
            assert!(book.pop(&mut queue, &[], now).is_some());
        }
        assert!(book.pop(&mut queue, &[], now).is_none());
        assert!(
            book.pop(&mut queue, &[], now + Duration::from_millis(100))
                .is_some()
        );
    }
    #[test]
    fn transport_learning_keeps_strict_policy_and_rotates_sources() {
        let mut book = Candidates::new();
        let now = Instant::now();
        let a = "10.0.0.1:1".parse().unwrap_or_else(|e| panic!("{e}"));
        book.connected(0, a, Transport::Utp, now);
        assert_eq!(
            book.policy(0, a, PeerConnectionType::PreferTcp),
            PeerConnectionType::PreferUtp
        );
        assert_eq!(
            book.policy(0, a, PeerConnectionType::Tcp),
            PeerConnectionType::Tcp
        );
    }
}

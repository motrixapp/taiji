//! Torrent-wide BEP9 scheduling. Connections share verified completion, partial
//! blocks and bounded request leases; disconnects never discard useful blocks.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use super::{DataOutcome, FetchError, METADATA_PIECE_SIZE, MetadataAssembler, MetadataError};
use crate::peer::ExpectedInfoHash;

const WINDOW: usize = 1;
const SMALL_METADATA_BLOCKS: usize = 4;
const MAX_WINDOW: usize = 8;
const MAX_PEERS: usize = 128;
const MAX_SIZES: usize = 4;
const LEASE_TIMEOUT: Duration = Duration::from_secs(10);
const HEDGE_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct SharedMetadataSpec {
    pub coordinator: Arc<MetadataCoordinator>,
    pub source: [u8; 20],
}

pub struct MetadataCoordinator {
    changes: tokio::sync::watch::Sender<u64>,
    first_block: std::sync::OnceLock<Instant>,
    expected: ExpectedInfoHash,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    peers: HashMap<u64, Member>,
    groups: HashMap<usize, Group>,
    banned: HashSet<[u8; 20]>,
    completed: Option<Bytes>,
}
struct Member {
    source: [u8; 20],
    size: Option<usize>,
    epoch: u64,
    probe: Option<Instant>,
    received: u64,
    cooldown: Option<Instant>,
    rejected: HashSet<usize>,
    latency: Option<Duration>,
}
struct Group {
    assembler: MetadataAssembler,
    leases: Vec<Vec<Lease>>,
    sources: HashSet<[u8; 20]>,
    epoch: u64,
    isolate: bool,
    owner: Option<u64>,
    hedges: usize,
}
#[derive(Clone, Copy)]
struct Lease {
    peer: u64,
    sent: Instant,
}

/// RAII ownership releases request slots immediately when a connection leaves.
pub struct SharedMetadataPeer {
    coordinator: Arc<MetadataCoordinator>,
    peer: u64,
    changes: tokio::sync::watch::Receiver<u64>,
}

impl MetadataCoordinator {
    pub fn new(expected: ExpectedInfoHash) -> Self {
        Self {
            changes: tokio::sync::watch::channel(0).0,
            expected,
            first_block: std::sync::OnceLock::new(),
            state: Mutex::new(State::default()),
        }
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn attach(
        self: &Arc<Self>,
        peer: u64,
        source: [u8; 20],
        size: Option<usize>,
    ) -> Result<SharedMetadataPeer, MetadataError> {
        let mut state = self.lock();
        if state.peers.len() >= MAX_PEERS
            || state.banned.contains(&source)
            || state.peers.contains_key(&peer)
        {
            return Err(MetadataError::InfoHashMismatch);
        }
        let epoch = match size {
            Some(size) => Self::group(&mut state, size)?.epoch,
            None => 0,
        };
        state.peers.insert(
            peer,
            Member {
                source,
                size,
                epoch,
                probe: None,
                received: 0,
                cooldown: None,
                rejected: HashSet::new(),
                latency: None,
            },
        );
        self.changed();
        Ok(SharedMetadataPeer {
            coordinator: self.clone(),
            peer,
            changes: self.changes.subscribe(),
        })
    }
    fn group(state: &mut State, size: usize) -> Result<&mut Group, MetadataError> {
        if !state.groups.contains_key(&size) {
            // A few peers lying about size must not permanently occupy all
            // cohorts. Prefer retaining cohorts with actual block progress.
            if state.groups.len() >= MAX_SIZES {
                let victim = state
                    .groups
                    .iter()
                    .min_by_key(|(size, group)| {
                        (
                            group.assembler.num_pieces() - group.assembler.missing_indices().len(),
                            state
                                .peers
                                .values()
                                .filter(|peer| peer.size == Some(**size))
                                .count(),
                        )
                    })
                    .map(|(size, _)| *size);
                if let Some(size) = victim {
                    state.groups.remove(&size);
                }
            }
            let assembler = MetadataAssembler::new(size)?;
            let leases = vec![Vec::new(); assembler.num_pieces()];
            state.groups.insert(
                size,
                Group {
                    assembler,
                    leases,
                    sources: HashSet::new(),
                    epoch: 0,
                    isolate: false,
                    owner: None,
                    hedges: 0,
                },
            );
        }
        Ok(state
            .groups
            .get_mut(&size)
            .unwrap_or_else(|| unreachable!("group inserted")))
    }
    fn verified(&self, bytes: &[u8]) -> bool {
        match self.expected {
            ExpectedInfoHash::V1(expected) => <[u8; 20]>::from(Sha1::digest(bytes)) == expected,
            ExpectedInfoHash::V2(expected) => <[u8; 32]>::from(Sha256::digest(bytes)) == expected,
        }
    }
    /// Monotonic reception time of the first accepted metadata block.
    pub fn first_block_at(&self) -> Option<Instant> {
        self.first_block.get().copied()
    }

    pub fn peer_progress(&self, peer: u64) -> u64 {
        self.lock().peers.get(&peer).map_or(0, |p| p.received)
    }
    pub fn completed(&self) -> Option<Bytes> {
        self.lock().completed.clone()
    }
    fn changed(&self) {
        self.changes
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }
}

impl SharedMetadataPeer {
    pub fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.clone()
    }
    pub fn size(&self) -> Option<usize> {
        self.coordinator
            .lock()
            .peers
            .get(&self.peer)
            .and_then(|p| p.size)
    }
    pub fn progress(&self) -> (usize, usize) {
        let state = self.coordinator.lock();
        let Some(size) = state.peers.get(&self.peer).and_then(|p| p.size) else {
            return (0, 0);
        };
        let Some(group) = state.groups.get(&size) else {
            return (0, size);
        };
        let missing = group.assembler.missing_indices();
        let bytes_missing: usize = missing
            .iter()
            .map(|i| (size - i * METADATA_PIECE_SIZE).min(METADATA_PIECE_SIZE))
            .sum();
        (size - bytes_missing, size)
    }
    pub fn requests(&mut self, now: Instant) -> Result<Vec<usize>, FetchError> {
        self.changes.borrow_and_update();
        let mut state = self.coordinator.lock();
        if state.completed.is_some() {
            return Ok(Vec::new());
        }
        let source = state
            .peers
            .get(&self.peer)
            .ok_or(FetchError::Rejected)?
            .source;
        if state.banned.contains(&source) {
            return Err(MetadataError::InfoHashMismatch.into());
        }
        let member = state
            .peers
            .get_mut(&self.peer)
            .ok_or(FetchError::Rejected)?;
        if member.cooldown.is_some_and(|until| now < until) {
            return Ok(Vec::new());
        }
        let Some(size) = member.size else {
            if member
                .probe
                .is_some_and(|sent| now.saturating_duration_since(sent) < LEASE_TIMEOUT)
            {
                return Ok(Vec::new());
            }
            member.probe = Some(now);
            return Ok(vec![0]);
        };
        let progressed = member.received > 0;
        let hedge_delay = member.latency.map_or(HEDGE_DELAY, |latency| {
            latency
                .saturating_mul(4)
                .clamp(Duration::from_millis(200), HEDGE_DELAY)
        });
        let rejected = member.rejected.clone();
        let active = state
            .peers
            .values()
            .filter(|member| {
                member.size == Some(size) && !member.cooldown.is_some_and(|until| now < until)
            })
            .count()
            .max(1);
        let epoch = state.groups.get(&size).ok_or(FetchError::Rejected)?.epoch;
        state
            .peers
            .get_mut(&self.peer)
            .ok_or(FetchError::Rejected)?
            .epoch = epoch;
        let group = state.groups.get_mut(&size).ok_or(FetchError::Rejected)?;
        if group.isolate {
            if !rejected.is_empty() {
                return Ok(Vec::new());
            }
            let owner = *group.owner.get_or_insert(self.peer);
            if owner != self.peer {
                return Ok(Vec::new());
            }
        }
        // Bootstrap peers with one block, then share remaining work across
        // active suppliers. A lone useful supplier may fill the whole window.
        let remaining_blocks = group.assembler.missing_indices().len();
        let window = if !progressed {
            WINDOW
        } else if group.isolate || active == 1 {
            MAX_WINDOW
        } else {
            remaining_blocks.div_ceil(active).clamp(1, MAX_WINDOW)
        };
        for leases in &mut group.leases {
            leases.retain(|lease| now.saturating_duration_since(lease.sent) < LEASE_TIMEOUT);
        }
        let outstanding = group
            .leases
            .iter()
            .flatten()
            .filter(|lease| lease.peer == self.peer)
            .count();
        let mut remaining = window.saturating_sub(outstanding);
        let missing = group.assembler.missing_indices();
        let mut requests = Vec::new();
        // Every unrequested block gets an owner before any duplicate is sent.
        for hedge in [false, true] {
            for &piece in &missing {
                if remaining == 0 {
                    break;
                }
                if rejected.contains(&piece) {
                    continue;
                }
                let leases = &mut group.leases[piece];
                let eligible = if hedge {
                    leases.len() == 1
                        && leases[0].peer != self.peer
                        && group.hedges < (group.assembler.num_pieces() / 4).max(2)
                        && (group.assembler.num_pieces() <= SMALL_METADATA_BLOCKS
                            || now.saturating_duration_since(leases[0].sent) >= hedge_delay)
                } else {
                    leases.is_empty()
                };
                if eligible {
                    if hedge {
                        group.hedges += 1;
                    }
                    leases.push(Lease {
                        peer: self.peer,
                        sent: now,
                    });
                    requests.push(piece);
                    remaining -= 1;
                }
            }
        }
        Ok(requests)
    }
    pub fn reject(&mut self, index: usize, now: Instant) {
        let mut state = self.coordinator.lock();
        self.coordinator.changed();
        let Some(size) = state.peers.get(&self.peer).and_then(|member| member.size) else {
            if index == 0 {
                if let Some(member) = state.peers.get_mut(&self.peer) {
                    member.cooldown = Some(now + Duration::from_secs(10));
                }
            }
            return;
        };
        let Some(group) = state.groups.get_mut(&size) else {
            return;
        };
        let Some(leases) = group.leases.get_mut(index) else {
            return;
        };
        if !leases.iter().any(|lease| lease.peer == self.peer) {
            return;
        }
        leases.retain(|lease| lease.peer != self.peer);
        if group.owner == Some(self.peer) {
            group.owner = None;
            group.assembler.reset();
            group.sources.clear();
            group.leases.iter_mut().for_each(Vec::clear);
        }
        if let Some(member) = state.peers.get_mut(&self.peer) {
            member.rejected.insert(index);
            if member.received == 0 && member.rejected.len() >= SMALL_METADATA_BLOCKS {
                member.cooldown = Some(now + Duration::from_secs(10));
            }
        }
    }

    pub fn observe_size(&mut self, size: usize) -> Result<(), MetadataError> {
        let mut state = self.coordinator.lock();
        self.coordinator.changed();
        let previous = state.peers.get(&self.peer).and_then(|member| member.size);
        if let Some(previous) = previous {
            return if previous == size {
                Ok(())
            } else {
                Err(MetadataError::SizeOutOfRange {
                    got: size,
                    max: previous,
                })
            };
        }
        let epoch = MetadataCoordinator::group(&mut state, size)?.epoch;
        if let Some(member) = state.peers.get_mut(&self.peer) {
            member.size = Some(size);
            member.epoch = epoch;
            member.probe = None;
            member.cooldown = None;
        }
        Ok(())
    }

    pub fn data(
        &mut self,
        index: usize,
        total_size: usize,
        data: &[u8],
        now: Instant,
    ) -> Result<DataOutcome, FetchError> {
        let mut state = self.coordinator.lock();
        if state.completed.is_some() {
            return Ok(DataOutcome::Untracked);
        }
        let member = state.peers.get(&self.peer).ok_or(FetchError::Rejected)?;
        let (size, source, epoch, probe) = (member.size, member.source, member.epoch, member.probe);
        if let Some(size) = size {
            if size != total_size {
                return Err(MetadataError::SizeOutOfRange {
                    got: total_size,
                    max: size,
                }
                .into());
            }
        } else {
            if index != 0 || probe.is_none() {
                return Ok(DataOutcome::Untracked);
            }
            let group = MetadataCoordinator::group(&mut state, total_size)?;
            group.leases[0].push(Lease {
                peer: self.peer,
                sent: now,
            });
            let epoch = group.epoch;
            let member = state
                .peers
                .get_mut(&self.peer)
                .unwrap_or_else(|| unreachable!());
            member.size = Some(total_size);
            member.epoch = epoch;
            member.probe = None;
        }
        let group = state
            .groups
            .get_mut(&total_size)
            .ok_or(FetchError::Rejected)?;
        if size.is_some() && epoch != group.epoch {
            return Ok(DataOutcome::Untracked);
        }
        let Some(leases) = group.leases.get(index) else {
            return Err(MetadataError::IndexOutOfRange {
                index,
                num_pieces: group.assembler.num_pieces(),
            }
            .into());
        };
        let Some(lease) = leases.iter().find(|lease| lease.peer == self.peer) else {
            return Ok(DataOutcome::Untracked);
        };
        let latency = now.saturating_duration_since(lease.sent);
        group.assembler.insert(index, data)?;
        self.coordinator.changed();
        self.coordinator.first_block.get_or_init(|| now);
        group.leases[index].clear();
        group.sources.insert(source);
        let remaining = group.assembler.missing_indices().len();
        if remaining > 0 {
            if let Some(peer) = state.peers.get_mut(&self.peer) {
                peer.received += data.len() as u64;
                peer.latency = Some(latency);
            }
            return Ok(DataOutcome::Stored { remaining });
        }
        let metadata = group
            .assembler
            .assemble()
            .unwrap_or_else(|| unreachable!("complete assembler"));
        if !self.coordinator.verified(&metadata) {
            // Mixed unverified blocks cannot identify the culprit. Retry this
            // size with one source at a time; never poison other size cohorts.
            let proven_bad = if group.sources.len() == 1 {
                group.sources.iter().next().copied()
            } else {
                None
            };
            group.assembler.reset();
            group.leases.iter_mut().for_each(Vec::clear);
            group.sources.clear();
            group.epoch = group.epoch.wrapping_add(1);
            group.isolate = true;
            group.owner = None;
            group.hedges = 0;
            if let Some(source) = proven_bad {
                if state.banned.len() < MAX_PEERS {
                    state.banned.insert(source);
                }
            }
            return if proven_bad.is_some() {
                Err(MetadataError::InfoHashMismatch.into())
            } else {
                Ok(DataOutcome::Untracked)
            };
        }
        state.completed = Some(metadata.clone());
        // Keep only the verified result; release partial-block memory claims.
        state.groups.clear();
        Ok(DataOutcome::Complete { metadata })
    }
}

impl Drop for SharedMetadataPeer {
    fn drop(&mut self) {
        let mut state = self.coordinator.lock();
        state.peers.remove(&self.peer);
        for group in state.groups.values_mut() {
            for leases in &mut group.leases {
                leases.retain(|lease| lease.peer != self.peer);
            }
            if group.owner == Some(self.peer) {
                // An isolated retry must never combine different sources.
                group.owner = None;
                group.assembler.reset();
                group.sources.clear();
                group.leases.iter_mut().for_each(Vec::clear);
            }
        }
        self.coordinator.changed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ut_metadata::MAX_METADATA_SIZE;
    fn pool(data: &[u8]) -> Arc<MetadataCoordinator> {
        Arc::new(MetadataCoordinator::new(ExpectedInfoHash::V1(
            Sha1::digest(data).into(),
        )))
    }
    fn feed(
        peer: &mut SharedMetadataPeer,
        data: &[u8],
        indices: &[usize],
        now: Instant,
    ) -> Vec<DataOutcome> {
        indices
            .iter()
            .map(|&i| {
                peer.data(
                    i,
                    data.len(),
                    &data[i * METADATA_PIECE_SIZE..((i + 1) * METADATA_PIECE_SIZE).min(data.len())],
                    now,
                )
                .unwrap_or_else(|e| panic!("{e}"))
            })
            .collect()
    }
    #[test]
    fn four_suppliers_finish_nine_blocks_in_three_service_rounds() {
        let data = vec![23; METADATA_PIECE_SIZE * 9];
        let pool = pool(&data);
        let mut peers: Vec<_> = (0..4)
            .map(|index| {
                pool.attach(index, [index as u8; 20], Some(data.len()))
                    .unwrap_or_else(|e| panic!("{e}"))
            })
            .collect();
        let start = Instant::now();
        let mut queues: Vec<Vec<usize>> = peers
            .iter_mut()
            .map(|peer| peer.requests(start).unwrap_or_default())
            .collect();
        assert!(queues.iter().all(|queue| queue.len() == 1));
        let mut served = HashSet::new();
        for round in 1..=3 {
            let now = start + Duration::from_millis(round * 50);
            for (peer, queue) in peers.iter_mut().zip(&mut queues) {
                if !queue.is_empty() {
                    let index = queue.remove(0);
                    assert!(
                        served.insert(index),
                        "healthy suppliers must not duplicate blocks"
                    );
                    feed(peer, &data, &[index], now);
                }
            }
            for (peer, queue) in peers.iter_mut().zip(&mut queues) {
                queue.extend(peer.requests(now).unwrap_or_default());
            }
        }
        assert_eq!(pool.completed().as_deref(), Some(data.as_slice()));
        assert_eq!(served.len(), 9);
    }

    #[tokio::test]
    async fn disconnect_notifies_an_idle_supplier_without_waiting_for_a_tick() {
        let data = vec![23; METADATA_PIECE_SIZE * 9];
        let pool = pool(&data);
        let mut a = pool
            .attach(1, [1; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut b = pool
            .attach(2, [2; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let now = Instant::now();
        let abandoned = a.requests(now).unwrap_or_default();
        b.requests(now).unwrap_or_default();
        let mut changed = b.changes();
        drop(a);
        tokio::time::timeout(Duration::from_millis(100), changed.changed())
            .await
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|e| panic!("{e}"));
        // Free b's first lease and verify that the abandoned block is reusable.
        let own = pool.lock().groups[&data.len()]
            .leases
            .iter()
            .position(|leases| leases.iter().any(|l| l.peer == 2))
            .unwrap_or_else(|| panic!("lease"));
        feed(&mut b, &data, &[own], now);
        assert!(b.requests(now).unwrap_or_default().contains(&abandoned[0]));
    }

    #[test]
    fn peers_split_work_and_disconnect_preserves_blocks() {
        let data = vec![19; METADATA_PIECE_SIZE * 9];
        let pool = pool(&data);
        let now = Instant::now();
        let mut a = pool
            .attach(1, [1; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut b = pool
            .attach(2, [2; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let ar = a.requests(now).unwrap_or_else(|e| panic!("{e}"));
        let br = b.requests(now).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(ar.len(), WINDOW);
        assert!(br.iter().all(|p| !ar.contains(p)));
        feed(&mut a, &data, &ar, now);
        let abandoned = a.requests(now).unwrap_or_default();
        assert!(!abandoned.is_empty());
        drop(a);
        feed(&mut b, &data, &br, now);
        while pool.completed().is_none() {
            let next = b.requests(now).unwrap_or_else(|e| panic!("{e}"));
            assert!(!next.is_empty());
            feed(&mut b, &data, &next, now);
        }
        assert_eq!(pool.completed().as_deref(), Some(data.as_slice()));
    }
    #[test]
    fn slow_blocks_are_hedged_but_duplicates_are_bounded() {
        let data = vec![1; METADATA_PIECE_SIZE];
        let pool = pool(&data);
        let now = Instant::now();
        let mut a = pool
            .attach(1, [1; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut b = pool
            .attach(2, [2; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut c = pool
            .attach(3, [3; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(a.requests(now).unwrap_or_default(), vec![0]);
        assert_eq!(b.requests(now).unwrap_or_default(), vec![0]);
        assert!(b.requests(now + HEDGE_DELAY).unwrap_or_default().is_empty());
        assert!(c.requests(now + HEDGE_DELAY).unwrap_or_default().is_empty());
        feed(&mut b, &data, &[0], now + HEDGE_DELAY);
        assert!(pool.completed().is_some());
    }
    #[test]
    fn unknown_size_probes_and_wrong_size_does_not_poison_honest_peer() {
        let data = vec![7; 100];
        let pool = pool(&data);
        let now = Instant::now();
        let _bad = pool
            .attach(1, [1; 20], Some(MAX_METADATA_SIZE))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut honest = pool
            .attach(2, [2; 20], None)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(honest.requests(now).unwrap_or_default(), vec![0]);
        feed(&mut honest, &data, &[0], now);
        assert_eq!(pool.completed().as_deref(), Some(data.as_slice()));
    }
    #[test]
    fn mixed_bad_hash_recovers_on_existing_honest_connection() {
        let data = vec![7; METADATA_PIECE_SIZE * 8];
        let pool = pool(&data);
        let now = Instant::now();
        let mut bad = pool
            .attach(1, [1; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let mut good = pool
            .attach(2, [2; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let bad_blocks = bad.requests(now).unwrap_or_default();
        let good_blocks = good.requests(now).unwrap_or_default();
        feed(&mut bad, &vec![8; data.len()], &bad_blocks, now);
        let outcomes = feed(&mut good, &data, &good_blocks, now);
        assert!(
            !outcomes
                .iter()
                .any(|outcome| matches!(outcome, DataOutcome::Complete { .. }))
        );
        for _ in 0..4 {
            let blocks = good.requests(now).unwrap_or_default();
            feed(&mut good, &data, &blocks, now);
            if pool.completed().is_some() {
                break;
            }
        }
        assert_eq!(pool.completed().as_deref(), Some(data.as_slice()));
    }
    #[test]
    fn selective_rejections_reassign_only_missing_blocks() {
        let data = vec![7; METADATA_PIECE_SIZE * 16];
        let pool = pool(&data);
        let now = Instant::now();
        let mut peers = [
            pool.attach(1, [1; 20], Some(data.len()))
                .unwrap_or_else(|e| panic!("{e}")),
            pool.attach(2, [2; 20], Some(data.len()))
                .unwrap_or_else(|e| panic!("{e}")),
        ];
        for _ in 0..32 {
            for (parity, peer) in peers.iter_mut().enumerate() {
                for index in peer.requests(now).unwrap_or_default() {
                    if index % 2 == parity {
                        feed(peer, &data, &[index], now);
                    } else {
                        peer.reject(index, now);
                    }
                }
            }
            if pool.completed().is_some() {
                break;
            }
        }
        assert_eq!(pool.completed().as_deref(), Some(data.as_slice()));
    }
    #[test]
    fn bogus_size_advertisements_cannot_exclude_a_later_honest_source() {
        let data = vec![1; 100];
        let pool = pool(&data);
        let now = Instant::now();
        let _bad: Vec<_> = (1..=MAX_SIZES)
            .map(|id| {
                pool.attach(id as u64, [id as u8; 20], Some(id * 1000))
                    .unwrap_or_else(|e| panic!("{e}"))
            })
            .collect();
        let mut good = pool
            .attach(100, [100; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let blocks = good.requests(now).unwrap_or_default();
        feed(&mut good, &data, &blocks, now);
        assert!(pool.completed().is_some());
    }

    #[test]
    fn bad_hash_is_rejected_and_single_source_retry_recovers() {
        let data = vec![7; METADATA_PIECE_SIZE * 5];
        let pool = pool(&data);
        let now = Instant::now();
        let mut bad = pool
            .attach(1, [1; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        let chunks = bad.requests(now).unwrap_or_default();
        feed(&mut bad, &vec![8; data.len()], &chunks, now);
        let chunks = bad.requests(now).unwrap_or_default();
        let mut rejected = false;
        for chunk in chunks {
            rejected |= bad
                .data(chunk, data.len(), &vec![8; METADATA_PIECE_SIZE], now)
                .is_err();
        }
        assert!(
            rejected,
            "a completed corrupt info dictionary must be rejected"
        );
        drop(bad);
        assert!(pool.attach(3, [1; 20], Some(data.len())).is_err());
        let mut good = pool
            .attach(2, [2; 20], Some(data.len()))
            .unwrap_or_else(|e| panic!("{e}"));
        while pool.completed().is_none() {
            let chunks = good.requests(now).unwrap_or_default();
            assert!(!chunks.is_empty());
            feed(&mut good, &data, &chunks, now);
        }
        assert_eq!(pool.completed().as_deref(), Some(data.as_slice()));
    }
}

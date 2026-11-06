//! criterion micro-benchmark: DHT routing table.
//!
//! Pure-function segments of the K-bucket table: saturation feed
//! (`add_contacted_node`, the inbound-contact path), `get_closest_k_nodes`
//! (the find_node/get_peers hot path) and the `dht_state` BLOB roundtrip
//! (`persist::{encode_table,decode_table}`).
//!
//! Determinism: a fixed-seed XorShift generates the local id and node ids.
//! The "saturation" construction feeds 8 ids into every sibling leaf along
//! the local node's path (inverted bit + suffix counter), then repeats
//! contacts until the node count converges (the aria2-shaped table only
//! splits buckets containing local; a full non-path bucket rejects). No
//! network/clock.
//!
//! Run: `cargo bench -p taiji-bt --bench bench_dht_table` (release).

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Instant;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

use taiji_bt::dht::node::{DhtNode, NodeId};
use taiji_bt::dht::persist::{TableNode, decode_table, encode_table};
use taiji_bt::dht::routing_table::RoutingTable;

/// Fixed-seed XorShift64 (same construction as the dht_10k_perf test, for
/// reproducibility).
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

    fn id(&mut self) -> NodeId {
        let mut b = [0u8; 20];
        self.fill(&mut b);
        NodeId(b)
    }

    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Set/clear bit number `bit` (0 = most significant bit of the first byte;
/// same order as `NodeId::bit`).
fn set_bit(b: &mut [u8; 20], bit: u32, on: bool) {
    let byte = (bit / 8) as usize;
    let mask = 0x80u8 >> (bit % 8);
    if on {
        b[byte] |= mask;
    } else {
        b[byte] &= !mask;
    }
}

/// Saturation id set: for every split depth d (0..160, bit order =
/// `NodeId::bit`) generate 8 ids whose first d bits match local, bit d is
/// local inverted and the rest pseudo-random — each lands exactly inside
/// the depth-d sibling leaf of the local path. 160 x 8 = 1280 ids, never
/// equal to local (the inverted bit guarantees it).
fn saturation_ids(local: &NodeId) -> Vec<NodeId> {
    let mut rng = XorShift(0x0DEF_FACE_5EED_0001);
    let mut ids = Vec::with_capacity(160 * 8);
    for d in 0..160u32 {
        for i in 0..8u8 {
            let mut b = local.0;
            set_bit(&mut b, d, !local.bit(d));
            // remaining bits (d+1..160) are pseudo-random; the low bits
            // XOR i keep the 8 variants distinct (at d=159 only 1 bit
            // remains, the xor yields exactly two distinct variants).
            let mut suffix = [0u8; 20];
            rng.fill(&mut suffix);
            for k in 0..20u32 {
                if k * 8 > d {
                    b[k as usize] = suffix[k as usize];
                }
            }
            b[19] ^= i;
            ids.push(NodeId(b));
        }
    }
    ids
}

/// Deterministic addresses (distinct ports; no actual traffic).
fn addr_of(id: &NodeId) -> SocketAddr {
    let port = u16::from_be_bytes([id.0[18], id.0[19]]).max(1024);
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port))
}

/// Saturation feed: loop the full set until the node count converges
/// (<= 8 rounds — a full bucket stops accepting new same-leaf nodes).
fn saturate(local: &NodeId, ids: &[NodeId]) -> RoutingTable {
    let now = Instant::now();
    let mut table = RoutingTable::new(*local, now);
    let mut last = 0usize;
    for round in 0..8u32 {
        for id in ids {
            let node = DhtNode::new(*id, addr_of(id));
            table.add_contacted_node(node, now);
        }
        let n = table.num_nodes();
        if n == last {
            let _ = round;
            break;
        }
        last = n;
    }
    table
}

fn bench_dht_table(c: &mut Criterion) {
    let mut rng = XorShift(0x000D_17A7_AB1E_5EED);
    let local = rng.id();
    let ids = saturation_ids(&local);

    let mut group = c.benchmark_group("dht_table");

    group.bench_function("saturate_feed/full_saturation_set", |b| {
        b.iter(|| saturate(black_box(&local), black_box(&ids)))
    });

    let table = saturate(&local, &ids);
    let keys: Vec<NodeId> = (0..1024).map(|_| rng.id()).collect();
    group.bench_function("closest_k/1024_keys_on_saturated", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for key in black_box(&keys) {
                total += table.get_closest_k_nodes(key).len();
            }
            total
        })
    });

    group.bench_function("persist_roundtrip/full_saturated_table", |b| {
        b.iter_batched(
            || {
                let nodes: Vec<TableNode> = table
                    .buckets()
                    .iter()
                    .flat_map(|bucket| bucket.nodes())
                    .map(|n| TableNode {
                        id: *n.id(),
                        addr: n.addr(),
                        last_seen_ago_secs: 0,
                    })
                    .collect();
                nodes
            },
            |nodes| {
                let blob = encode_table(black_box(&nodes));
                match decode_table(black_box(&blob)) {
                    Ok(back) => back.len(),
                    Err(e) => panic!("roundtrip decode failed: {e:?}"),
                }
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_dht_table
}
criterion_main!(benches);

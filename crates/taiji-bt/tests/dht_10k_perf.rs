//! 10k-node DHT routing table memory check (SPEC §14.4).
//!
//! Feeds 10,000 deterministic synthetic nodes into the K-bucket routing
//! table (`add_contacted_node`, the inbound-contact path; the "saturation"
//! construction feeds 8 ids into every sibling leaf along the local node's
//! path), then round-trips the `dht_state` table BLOB
//! (`persist::{encode_table,decode_table}` + table rebuild). The criterion
//! is the process RSS delta (loaded - baseline) < 200MiB under the
//! **release profile** (a debug-profile pass is explicitly disallowed).
//!
//! Determinism: all node ids come from a fixed-seed XorShift; no network,
//! no clock dependence (`Instant::now` only stamps table entries). Run:
//!
//! ```sh
//! cargo test -p taiji-bt --release dht_10k -- --ignored --nocapture
//! ```
//!
//! In the aria2-shaped table only buckets containing the local node split
//! (`DHTBucket.cc` splitAllowed); a full non-path bucket rejects, giving a
//! structural capacity ceiling of ~160 buckets x 8.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Instant;

use taiji_bt::dht::node::{DhtNode, NodeId};
use taiji_bt::dht::persist::{TableNode, decode_table, encode_table};
use taiji_bt::dht::routing_table::RoutingTable;

/// Threshold (SPEC §14.4: 10k-node DHT routing table memory < 200MiB).
const GATE_RSS_MIB: f64 = 200.0;
/// Number of fed nodes (10,000).
const FED_TARGET: usize = 10_000;

/// Fixed-seed XorShift64 (deterministic; same construction as
/// bench_dht_table).
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

/// Saturation id set: 8 ids per sibling leaf along the local path (the
/// first d bits match local, bit d inverted, the rest pseudo-random).
/// 160 x 8 = 1280 ids.
fn saturation_ids(local: &NodeId, rng: &mut XorShift) -> Vec<NodeId> {
    let mut ids = Vec::with_capacity(160 * 8);
    for d in 0..160u32 {
        for i in 0..8u8 {
            let mut b = local.0;
            set_bit(&mut b, d, !local.bit(d));
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

/// Deterministic synthetic addresses (no actual traffic; ports derived
/// from the id, >= 1024).
fn addr_of(id: &NodeId) -> SocketAddr {
    let port = u16::from_be_bytes([id.0[18], id.0[19]]).max(1024);
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port))
}

/// Process RSS (KiB) via `ps -o rss=` (macOS/Linux). A failed measurement
/// fails the run outright (never silently passes).
fn rss_kib() -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap_or_else(|e| panic!("cannot sample RSS via ps: {e}"));
    let text = String::from_utf8_lossy(&out.stdout);
    let kib = text.split_whitespace().next().unwrap_or_default();
    kib.parse::<u64>()
        .unwrap_or_else(|_| panic!("cannot parse RSS from ps output: {text:?}"))
}

/// Export the full table as dht_state BLOB entries (isomorphic to the
/// persistence write path).
fn table_to_entries(table: &RoutingTable) -> Vec<TableNode> {
    table
        .buckets()
        .iter()
        .flat_map(|bucket| bucket.nodes())
        .map(|n| TableNode {
            id: *n.id(),
            addr: n.addr(),
            last_seen_ago_secs: 0,
        })
        .collect()
}

/// The check body. `#[ignore]` = only run explicitly via `-- --ignored`
/// (regular `cargo test` skips it — deliberate, see the module docs).
#[test]
#[ignore = "gate harness: run in release via the perf gate script (--ignored)"]
fn dht_10k_gate() {
    // A debug profile must never produce a passing verdict. cfg! is a
    // constant on purpose: on debug builds this face fails immediately.
    #[expect(
        clippy::assertions_on_constants,
        reason = "cfg!(debug_assertions) is a compile-time constant on purpose: the gate must fail fast on debug builds"
    )]
    {
        assert!(
            !cfg!(debug_assertions),
            "gate must run with --release (debug profiles may not produce a passing verdict)"
        );
    }

    let mut rng = XorShift(0xD17A_10A0_0000_0001);
    let local = rng.id();
    let sat = saturation_ids(&local, &mut rng);
    let mut all: Vec<NodeId> = sat.clone();
    // Top up to 10,000 nodes (random ids; collisions in a 20B space are
    // negligible, only local itself is excluded — hitting a full non-path
    // bucket goes to the replacement cache or is rejected per the aria2
    // semantics, all counted as contacts).
    while all.len() < FED_TARGET {
        let id = rng.id();
        if id != local {
            all.push(id);
        }
    }
    assert_eq!(all.len(), FED_TARGET);

    let rss_baseline = rss_kib();
    let now = Instant::now();

    // ---- feed + saturation convergence (repeat contacts until the node
    // count stabilizes; <= 8 rounds) ----
    let mut table = RoutingTable::new(local, now);
    let mut contact_events = 0usize;
    let mut retained = 0usize;
    for round in 0..8u32 {
        for id in &sat {
            contact_events += 1;
            table.add_contacted_node(DhtNode::new(*id, addr_of(id)), now);
        }
        if round == 0 {
            for id in &all {
                contact_events += 1;
                table.add_contacted_node(DhtNode::new(*id, addr_of(id)), now);
            }
        }
        let n = table.num_nodes();
        if n == retained {
            break;
        }
        retained = n;
    }
    let buckets = table.num_buckets();
    let retained = table.num_nodes();

    // ---- dht_state BLOB roundtrip (encode -> decode -> rebuild table) ----
    let entries = table_to_entries(&table);
    let blob = encode_table(&entries);
    let decoded = match decode_table(&blob) {
        Ok(d) => d,
        Err(e) => panic!("dht_state blob roundtrip decode failed: {e:?}"),
    };
    let mut rebuilt = RoutingTable::new(local, now);
    for node in &decoded {
        rebuilt.add_contacted_node(DhtNode::new(node.id, node.addr), now);
    }

    let rss_final = rss_kib();
    let rss_delta_mib = (rss_final.saturating_sub(rss_baseline)) as f64 / 1024.0;

    // Report line (single-line JSON; taiji-bt does not depend on
    // serde_json, so the flat numbers are formatted by hand; consumers
    // locate the `DHT10K_GATE ` prefix and json.loads the rest).
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let report = format!(
        "DHT10K_GATE {{\"gate\":\"dht_10k_rss\",\"fed_distinct_nodes\":{all_len},\
         \"contact_events\":{contact_events},\"retained_table_nodes\":{retained},\
         \"buckets\":{buckets},\"blob_bytes\":{blob_len},\
         \"decoded_entries\":{decoded_len},\"rebuilt_table_nodes\":{rebuilt_nodes},\
         \"rss_baseline_kib\":{rss_baseline},\"rss_final_kib\":{rss_final},\
         \"rss_delta_mib\":{rss_delta_mib:.2},\"gate_mib\":{GATE_RSS_MIB},\
         \"profile\":\"{profile}\"}}",
        all_len = all.len(),
        blob_len = blob.len(),
        decoded_len = decoded.len(),
        rebuilt_nodes = rebuilt.num_nodes(),
    );
    println!("{report}");

    // Verdicts (any failure fails the run):
    assert_eq!(
        decoded.len(),
        entries.len(),
        "BLOB roundtrip preserves entry count"
    );
    assert_eq!(
        rebuilt.num_nodes(),
        retained,
        "BLOB rebuild preserves node count"
    );
    assert!(
        rss_delta_mib < GATE_RSS_MIB,
        "RSS delta {rss_delta_mib:.1}MiB >= threshold {GATE_RSS_MIB}MiB"
    );
}

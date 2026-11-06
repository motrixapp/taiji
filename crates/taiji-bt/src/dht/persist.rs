//! DHT persistence: the `dht_state` own-format BLOB + aria2 `dht.dat`
//! compatible import (SPEC §5.3 `dht_state`).
//!
//! # Own BLOB (`routing_table` column; `node_id` is a separate 20B column)
//!
//! 1B version header + node list:
//!
//! ```text
//! [0] = version (currently 1)
//! [1..5] = node count, u32 big-endian
//! [5..] = entries x n: 20B node id || compact peer (6B v4 / 18B v6;
//! family inferred from the entry length, whole table one
//! family) || 8B seconds since last contact (u64 big-endian;
//! u64::MAX = never contacted)
//! ```
//!
//! Write path: emitted by DhtEngine on autosave/halt (`DhtEvent::Persist`),
//! persisted by core via the PersistWriter (SPEC §2.3 single writer — the
//! engine never touches sqlite). Read path: core reads the row at startup;
//! a [`decode_table`] failure discards the data and generates a fresh node
//! ID (mirrors `DHTSetup.cc`: deserialization failure caught, new
//! localNode).
//!
//! # aria2 `dht.dat` compatible import (`--dht-file-path[-6]`; used when
//! the table is empty and the file exists)
//!
//! Field-by-field format of `DHTRoutingTableDeserializer.cc` /
//! `DHTRoutingTableSerializer.cc`:
//!
//! ```text
//! header 8B: magic 0xa1 0xa2 || format id 0x02 || 4B zero || version 1B
//! ([6]=0; [7]=0x03 -> v3; [7]=0x02 -> v2 compatible; else bad header)
//! saved-at: v3 = 8B u64 big-endian; v2 = 4B u32 big-endian + 4B reserved
//! local node: 8B reserved || 20B ID || 4B reserved
//! node count: 4B u32 big-endian || 4B reserved
//! entries x n (56B each): 1B compact length (v4=6/v6=18; mismatch skips
//! the whole record) || 7B reserved || clen B compact peer (all zero
//! skips the record) || (24-clen) B reserved || 20B node id ||
//! 4B reserved
//! ```
//!
//! Skip rules match the reference deserializer; a bad header or truncation
//! is an error and the caller logs and skips the import (same policy as
//! `DHTSetup.cc`). Test vectors are hand-built from the serializer's byte
//! rules (the encoder is the normative source of the format; the aria2
//! repository ships no dat fixture); the magic/format-id/version bytes
//! match the deserializer verbatim.

use super::compact::{COMPACT_LEN_IPV4, COMPACT_LEN_IPV6, unpack_peer};
use super::node::{DHT_ID_LENGTH, NodeId};
use std::net::SocketAddr;

/// Current version of the own-format BLOB.
pub const TABLE_BLOB_VERSION: u8 = 1;

/// aria2 dht.dat v3 header (`DHTRoutingTableDeserializer.cc`).
const DAT_HEADER_V3: [u8; 8] = [0xa1, 0xa2, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
/// aria2 dht.dat v2 compatible header (`DHTRoutingTableDeserializer.cc`).
const DAT_HEADER_V2: [u8; 8] = [0xa1, 0xa2, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Total dht.dat record length (1 + 7 + clen + (24-clen) + 20 + 4 = 56,
/// family-independent; `DHTRoutingTableDeserializer.cc`).
const DAT_RECORD_LEN: usize = 56;

/// One node entry inside the BLOB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableNode {
    pub id: NodeId,
    pub addr: SocketAddr,
    /// Seconds since last contact (u64::MAX = never; unused on restore —
    /// imported nodes enter the table as never-contacted, like
    /// `DHTSetup.cc` addNode).
    pub last_seen_ago_secs: u64,
}

/// Own-format BLOB decode error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateBlobError {
    #[error("dht_state routing_table blob: unsupported version {0}")]
    Version(u8),
    #[error("dht_state routing_table blob: truncated (len {len}, need at least {need})")]
    Truncated { len: usize, need: usize },
    #[error("dht_state routing_table blob: entry length {entry_len} is neither {v4} nor {v6}")]
    BadEntryLength {
        entry_len: usize,
        v4: usize,
        v6: usize,
    },
    #[error("dht_state routing_table blob: node {index} has invalid compact address")]
    BadAddress { index: usize },
}

/// Encode the own-format BLOB (format in the module docs).
pub fn encode_table(nodes: &[TableNode]) -> Vec<u8> {
    let compact_len = match nodes.first() {
        Some(n) if n.addr.is_ipv6() => COMPACT_LEN_IPV6,
        _ => COMPACT_LEN_IPV4,
    };
    let entry_len = DHT_ID_LENGTH + compact_len + 8;
    let mut out = Vec::with_capacity(5 + nodes.len() * entry_len);
    out.push(TABLE_BLOB_VERSION);
    out.extend_from_slice(&(nodes.len() as u32).to_be_bytes());
    for n in nodes {
        out.extend_from_slice(&n.id.0);
        super::compact::pack_peer(n.addr, &mut out);
        out.extend_from_slice(&n.last_seen_ago_secs.to_be_bytes());
    }
    out
}

/// Decode the own-format BLOB (inverse of [`encode_table`]; any
/// inconsistency is an error — never silently truncated).
pub fn decode_table(blob: &[u8]) -> Result<Vec<TableNode>, StateBlobError> {
    if blob.is_empty() {
        return Err(StateBlobError::Truncated { len: 0, need: 1 });
    }
    if blob[0] != TABLE_BLOB_VERSION {
        return Err(StateBlobError::Version(blob[0]));
    }
    if blob.len() < 5 {
        return Err(StateBlobError::Truncated {
            len: blob.len(),
            need: 5,
        });
    }
    let count = u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]) as usize;
    let rest = &blob[5..];
    let entry_len = if count == 0 {
        if rest.is_empty() {
            return Ok(Vec::new());
        }
        return Err(StateBlobError::Truncated {
            len: rest.len(),
            need: 0,
        });
    } else {
        if !rest.len().is_multiple_of(count) {
            return Err(StateBlobError::Truncated {
                len: rest.len(),
                need: rest.len().next_multiple_of(count),
            });
        }
        rest.len() / count
    };
    let compact_len =
        entry_len
            .checked_sub(DHT_ID_LENGTH + 8)
            .ok_or(StateBlobError::BadEntryLength {
                entry_len,
                v4: DHT_ID_LENGTH + COMPACT_LEN_IPV4 + 8,
                v6: DHT_ID_LENGTH + COMPACT_LEN_IPV6 + 8,
            })?;
    if compact_len != COMPACT_LEN_IPV4 && compact_len != COMPACT_LEN_IPV6 {
        return Err(StateBlobError::BadEntryLength {
            entry_len,
            v4: DHT_ID_LENGTH + COMPACT_LEN_IPV4 + 8,
            v6: DHT_ID_LENGTH + COMPACT_LEN_IPV6 + 8,
        });
    }
    let mut out = Vec::with_capacity(count);
    for (index, chunk) in rest.chunks_exact(entry_len).enumerate() {
        let mut id = [0u8; DHT_ID_LENGTH];
        id.copy_from_slice(&chunk[..DHT_ID_LENGTH]);
        let addr = unpack_peer(&chunk[DHT_ID_LENGTH..DHT_ID_LENGTH + compact_len])
            .map_err(|_| StateBlobError::BadAddress { index })?;
        let ago_bytes: [u8; 8] =
            chunk[entry_len - 8..]
                .try_into()
                .map_err(|_| StateBlobError::Truncated {
                    len: chunk.len(),
                    need: entry_len,
                })?;
        out.push(TableNode {
            id: NodeId(id),
            addr,
            last_seen_ago_secs: u64::from_be_bytes(ago_bytes),
        });
    }
    Ok(out)
}

/// aria2 `dht.dat` parse errors (mirrors the error paths of
/// `DHTRoutingTableDeserializer.cc`: bad header / READ_CHECK truncation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DhtDatError {
    #[error("dht.dat: bad header (expected magic 0xa1 0xa2, format id 0x02, version 0x02/0x03)")]
    BadHeader,
    #[error("dht.dat: truncated at byte {offset} (need {need} more)")]
    Truncated { offset: usize, need: usize },
    #[error("dht.dat: node record {index} has invalid compact length byte")]
    BadRecord { index: usize },
}

/// Parsed dht.dat contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtDat {
    /// Local node ID (deserializer localnode ID).
    pub node_id: NodeId,
    /// Node list (survivors of the skip rules, per the deserializer).
    pub nodes: Vec<(NodeId, SocketAddr)>,
    /// Save time (unix seconds; carried by both the v2/v3 headers).
    pub serialized_at_unix: u64,
}

/// Address family (v4/v6): shared by the dht.dat compact-length field
/// (6/18, `DHTRoutingTableDeserializer.cc` getCompactLength(family)) and
/// the DhtEngine instance dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhtFamily {
    V4,
    V6,
}

impl DhtFamily {
    fn compact_len(self) -> usize {
        match self {
            DhtFamily::V4 => COMPACT_LEN_IPV4,
            DhtFamily::V6 => COMPACT_LEN_IPV6,
        }
    }
}

/// Parse an aria2 `dht.dat` (v3 main format + v2 compatible header; rules
/// in the module docs).
pub fn parse_dht_dat(family: DhtFamily, data: &[u8]) -> Result<DhtDat, DhtDatError> {
    let need = |offset: usize, n: usize| -> Result<(), DhtDatError> {
        if data.len() < offset + n {
            Err(DhtDatError::Truncated {
                offset,
                need: offset + n - data.len(),
            })
        } else {
            Ok(())
        }
    };

    // Header.
    need(0, 8)?;
    let version = if data[..8] == DAT_HEADER_V3 {
        3
    } else if data[..8] == DAT_HEADER_V2 {
        2
    } else {
        return Err(DhtDatError::BadHeader);
    };

    // Save time.
    let mut offset = 8;
    let serialized_at_unix = if version == 2 {
        need(offset, 4)?;
        let t = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 8; // 4B time + 4B reserved
        u64::from(t)
    } else {
        need(offset, 8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;
        u64::from_be_bytes(b)
    };

    // Local node: 8B reserved + 20B ID + 4B reserved.
    need(offset, 8 + DHT_ID_LENGTH + 4)?;
    let mut id = [0u8; DHT_ID_LENGTH];
    id.copy_from_slice(&data[offset + 8..offset + 8 + DHT_ID_LENGTH]);
    offset += 8 + DHT_ID_LENGTH + 4;

    // Node count + 4B reserved.
    need(offset, 8)?;
    let num_nodes = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    offset += 8;

    // Entries: fixed 56B per record, filtered by the reference skip rules.
    let clen = family.compact_len();
    let mut nodes = Vec::with_capacity(num_nodes.min(4096));
    for _index in 0..num_nodes {
        need(offset, DAT_RECORD_LEN)?;
        let rec = &data[offset..offset + DAT_RECORD_LEN];
        offset += DAT_RECORD_LEN;
        // Compact length byte mismatch -> skip the whole record.
        let rec_len = rec[0] as usize;
        if rec_len != clen {
            continue;
        }
        let compact = &rec[8..8 + clen];
        // All-zero compact -> skip.
        if compact.iter().all(|&b| b == 0) {
            continue;
        }
        // Decode failure (unreachable after the all-zero check; still
        // defensive) -> skip.
        let Ok(addr) = unpack_peer(compact) else {
            continue;
        };
        // The 20B node id sits at offset 8 + clen + (24 - clen) = 32.
        let mut nid = [0u8; DHT_ID_LENGTH];
        nid.copy_from_slice(&rec[32..32 + DHT_ID_LENGTH]);
        nodes.push((NodeId(nid), addr));
    }

    Ok(DhtDat {
        node_id: NodeId(id),
        nodes,
        serialized_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Test-only Result unwrap (the workspace lint forbids unwrap/expect).
    fn t<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn v4(oct: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(oct), port))
    }

    // ===== Own BLOB roundtrip =====

    #[test]
    fn table_blob_roundtrip_v4_v6_empty() {
        let v4_nodes = vec![
            TableNode {
                id: NodeId([1; 20]),
                addr: v4([192, 168, 1, 5], 6881),
                last_seen_ago_secs: 42,
            },
            TableNode {
                id: NodeId([2; 20]),
                addr: v4([10, 0, 0, 9], 7741),
                last_seen_ago_secs: u64::MAX,
            },
        ];
        assert_eq!(
            t(decode_table(&encode_table(&v4_nodes)), "v4 roundtrip"),
            v4_nodes
        );
        assert_eq!(t(decode_table(&encode_table(&[])), "empty"), Vec::new());

        let v6_addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            6881,
            0,
            0,
        ));
        let v6_nodes = vec![TableNode {
            id: NodeId([9; 20]),
            addr: v6_addr,
            last_seen_ago_secs: 7,
        }];
        assert_eq!(
            t(decode_table(&encode_table(&v6_nodes)), "v6 roundtrip"),
            v6_nodes
        );
    }

    #[test]
    fn table_blob_rejects_bad_input() {
        // Version mismatch.
        assert_eq!(
            decode_table(&[0x02, 0, 0, 0, 0]),
            Err(StateBlobError::Version(0x02))
        );
        // Truncated (header shorter than 5B).
        assert_eq!(
            decode_table(&[0x01, 0, 0]),
            Err(StateBlobError::Truncated { len: 3, need: 5 })
        );
        // count=2 with 35 remaining bytes: not divisible -> truncated.
        let mut blob = vec![0x01u8, 0, 0, 0, 2];
        blob.extend_from_slice(&[0u8; 35]);
        assert_eq!(
            decode_table(&blob),
            Err(StateBlobError::Truncated { len: 35, need: 36 })
        );
        // Divisible remainder but the entry cannot hold id+compact+ago ->
        // BadEntryLength.
        let mut blob2 = vec![0x01u8, 0, 0, 0, 2];
        blob2.extend_from_slice(&[0u8; 34]); // entry_len = 17 < 20+6+8
        assert_eq!(
            decode_table(&blob2),
            Err(StateBlobError::BadEntryLength {
                entry_len: 17,
                v4: 34,
                v6: 46
            })
        );
        // Empty input.
        assert_eq!(
            decode_table(&[]),
            Err(StateBlobError::Truncated { len: 0, need: 1 })
        );
    }

    // ===== proptest: arbitrary node list roundtrip =====

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(512))]

        #[test]
        fn blob_roundtrip_arbitrary(nodes in prop::collection::vec(
            (any::<[u8; 20]>(), any::<[u8; 4]>(), any::<u16>(), any::<u64>()),
            0..32,
        )) {
            let table: Vec<TableNode> = nodes
                .into_iter()
                .map(|(id, oct, port, ago)| TableNode {
                    id: NodeId(id),
                    addr: v4(oct, port.max(1)),
                    last_seen_ago_secs: ago,
                })
                .collect();
            prop_assert_eq!(t(decode_table(&encode_table(&table)), "roundtrip"), table);
        }
    }

    // ===== aria2 dht.dat import vectors =====
    //
    // Vector construction rules = DHTRoutingTableSerializer.cc (the encoder
    // is the normative source): header[0]=0xa1 [1]=0xa2 [2]=0x02 [6]=0
    // [7]=0x03; 8B time; 8B reserved + 20B localnode + 4B reserved; u32
    // node count + 4B reserved; each record 56B = 1B clen || 7B reserved ||
    // clen compact || (24-clen) reserved || 20B id || 4B reserved.

    /// Assemble one v4 record byte-by-byte per the serializer rules.
    fn dat_v4_record(compact: &[u8; 6], id: [u8; 20]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(DAT_RECORD_LEN);
        rec.push(COMPACT_LEN_IPV4 as u8); // 1B clen
        rec.extend_from_slice(&[0u8; 7]); // 7B reserved
        rec.extend_from_slice(compact); // 6B compact peer
        rec.extend_from_slice(&[0u8; 24 - COMPACT_LEN_IPV4]); // 18B reserved
        rec.extend_from_slice(&id); // 20B node id
        rec.extend_from_slice(&[0u8; 4]); // 4B reserved
        assert_eq!(rec.len(), DAT_RECORD_LEN);
        rec
    }

    fn dat_v3_header(time_unix: u64, local_id: [u8; 20], num_nodes: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&DAT_HEADER_V3);
        out.extend_from_slice(&time_unix.to_be_bytes());
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&local_id);
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&num_nodes.to_be_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    /// v3 main format: 2 nodes + local ID + time (hand-built byte-by-byte
    /// from the serializer rules; values are fixed test constants).
    #[test]
    fn parses_dht_dat_v3_with_two_nodes() {
        let local_id = [0xABu8; 20];
        let mut data = dat_v3_header(0x00_00_00_00_65_A1_B2_C3, local_id, 2);
        data.extend_from_slice(&dat_v4_record(
            &[192, 168, 1, 5, 0x1A, 0xE1], // 192.168.1.5:6881 (BittorrentHelperTest vector shape)
            [0x11; 20],
        ));
        data.extend_from_slice(&dat_v4_record(
            &[10, 0, 0, 9, 0x1E, 0x3D], // 10.0.0.9:7741
            [0x22; 20],
        ));

        let parsed = t(parse_dht_dat(DhtFamily::V4, &data), "parse v3");
        assert_eq!(parsed.node_id, NodeId(local_id));
        assert_eq!(parsed.serialized_at_unix, 0x65A1B2C3);
        assert_eq!(
            parsed.nodes,
            vec![
                (NodeId([0x11; 20]), v4([192, 168, 1, 5], 6881)),
                (NodeId([0x22; 20]), v4([10, 0, 0, 9], 7741)),
            ]
        );
    }

    /// v2 compatible header (version 0x02): time is 4B + 4B reserved
    /// (deserializer).
    #[test]
    fn parses_dht_dat_v2_compat_header() {
        let local_id = [0xCDu8; 20];
        let mut data = Vec::new();
        data.extend_from_slice(&DAT_HEADER_V2);
        data.extend_from_slice(&0x5F5E_1000u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 4]); // v2's 4B reserved
        data.extend_from_slice(&[0u8; 8]);
        data.extend_from_slice(&local_id);
        data.extend_from_slice(&[0u8; 4]);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&[0u8; 4]);
        data.extend_from_slice(&dat_v4_record(&[127, 0, 0, 1, 0x1A, 0xE1], [7; 20]));

        let parsed = t(parse_dht_dat(DhtFamily::V4, &data), "parse v2");
        assert_eq!(parsed.node_id, NodeId(local_id));
        assert_eq!(parsed.serialized_at_unix, 0x5F5E_1000);
        assert_eq!(
            parsed.nodes,
            vec![(NodeId([7; 20]), v4([127, 0, 0, 1], 6881))]
        );
    }

    /// Skip rules (deserializer): wrong clen skips the record, all-zero
    /// compact skips the record — after both skips the node list is empty.
    #[test]
    fn skips_records_with_wrong_clen_or_zero_compact() {
        let mut data = dat_v3_header(1, [9; 20], 3);
        // clen=18 (the v6 length) inside a v4 file -> skipped.
        let mut bad_clen = vec![COMPACT_LEN_IPV6 as u8];
        bad_clen.extend_from_slice(&[0u8; 7 + 18 + (24 - 18) + 20 + 4]);
        assert_eq!(bad_clen.len(), DAT_RECORD_LEN);
        data.extend_from_slice(&bad_clen);
        // Valid clen but all-zero compact -> skipped.
        data.extend_from_slice(&dat_v4_record(&[0u8; 6], [8; 20]));
        // One survivor.
        data.extend_from_slice(&dat_v4_record(&[172, 16, 0, 1, 0x1A, 0xE0], [3; 20]));

        let parsed = t(parse_dht_dat(DhtFamily::V4, &data), "parse skips");
        assert_eq!(
            parsed.nodes,
            vec![(NodeId([3; 20]), v4([172, 16, 0, 1], 6880))]
        );
    }

    /// v6 family: clen field = 18, compact = 16B IPv6 + 2B port.
    #[test]
    fn parses_dht_dat_v6_family() {
        let mut data = dat_v3_header(42, [5; 20], 1);
        let mut rec = Vec::new();
        rec.push(COMPACT_LEN_IPV6 as u8);
        rec.extend_from_slice(&[0u8; 7]);
        // 2001:db8::1:6881 (BittorrentHelperTest v6 vector shape).
        let mut octets = [0u8; 16];
        octets[0] = 0x20;
        octets[1] = 0x01;
        octets[2] = 0x0d;
        octets[3] = 0xb8;
        octets[15] = 1;
        rec.extend_from_slice(&octets);
        rec.extend_from_slice(&6881u16.to_be_bytes());
        rec.extend_from_slice(&[0u8; 24 - COMPACT_LEN_IPV6]);
        rec.extend_from_slice(&[0x77; 20]);
        rec.extend_from_slice(&[0u8; 4]);
        data.extend_from_slice(&rec);

        let parsed = t(parse_dht_dat(DhtFamily::V6, &data), "parse v6");
        let expect_addr = SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            6881,
            0,
            0,
        ));
        assert_eq!(parsed.nodes, vec![(NodeId([0x77; 20]), expect_addr)]);
    }

    /// Error paths: bad header / truncation (deserializer and READ_CHECK).
    #[test]
    fn rejects_bad_header_and_truncation() {
        let mut bad = dat_v3_header(1, [1; 20], 0);
        bad[0] = 0xb1;
        assert_eq!(
            parse_dht_dat(DhtFamily::V4, &bad),
            Err(DhtDatError::BadHeader)
        );

        let ok = dat_v3_header(1, [1; 20], 1);
        let cut = &ok[..ok.len() - 10];
        assert!(matches!(
            parse_dht_dat(DhtFamily::V4, cut),
            Err(DhtDatError::Truncated { .. })
        ));
        // Empty input = truncation (READ_CHECK precedes header validation).
        assert_eq!(
            parse_dht_dat(DhtFamily::V4, &[]),
            Err(DhtDatError::Truncated { offset: 0, need: 8 })
        );
    }
}

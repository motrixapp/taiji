//! Compact peer / compact node info codecs (BEP5).
//!
//! # Format facts
//!
//! - compact peer: 4B (IPv4) or 16B (IPv6) network-byte-order address +
//!   2B network-byte-order port; the length constants match aria2
//!   `src/BtConstants.h` (`COMPACT_LEN_IPV4 = 6` / `COMPACT_LEN_IPV6 = 18`).
//!   Byte layout matches the `BittorrentHelperTest.cc` vectors:
//!   `192.168.0.1:6881` -> `c0a800011ae1`,
//!   `1002:1035:4527:3546:7854:1237:3247:3217:6881` ->
//!   `100210354527354678541237324732171ae1`.
//! - compact node info: 20B node ID + compact peer, unit length
//!   `20 + COMPACT_LEN` (26B/38B); aria2 assembles it in
//!   `DHTFindNodeReplyMessage.cc` and parses it in
//!   `DHTMessageFactoryImpl.cc` (`extractNodes`: the string length must be
//!   a multiple of `unit = getCompactLength(family) + 20` or it errors; a
//!   single address that fails to unpack is skipped).
//! - BEP5 "compact node info" text: `<id>` (20B) + network-byte-order
//!   ip:port.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use super::{DhtError, NodeId};

/// Compact peer length (IPv4). aria2 `src/BtConstants.h`.
pub const COMPACT_LEN_IPV4: usize = 6;
/// Compact peer length (IPv6). aria2 `src/BtConstants.h`.
pub const COMPACT_LEN_IPV6: usize = 18;
/// Compact node info unit length (IPv4) = 20 + 6 (BEP5; aria2
/// `DHTMessageFactoryImpl.cc` `unit = getCompactLength + DHT_ID_LENGTH`).
pub const NODE_INFO_LEN_V4: usize = super::node::DHT_ID_LENGTH + COMPACT_LEN_IPV4;
/// Compact node info unit length (IPv6) = 20 + 18.
pub const NODE_INFO_LEN_V6: usize = super::node::DHT_ID_LENGTH + COMPACT_LEN_IPV6;

/// Routing table node entry (a unit of the response `nodes`/`nodes6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
}

/// Append a compact peer (4B/16B network-byte-order IP + 2B port;
/// byte-identical to aria2 `bittorrent::packcompact`, vectors in the
/// module docs).
pub fn pack_peer(addr: SocketAddr, out: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(a) => {
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
}

/// Append compact node info (20B id + compact peer, BEP5).
pub fn pack_node_info(info: &NodeInfo, out: &mut Vec<u8>) {
    out.extend_from_slice(&info.id.0);
    pack_peer(info.addr, out);
}

/// Decode one compact peer: auto-detects v4 (6B)/v6 (18B) by length,
/// other lengths error.
///
/// Note: aria2's `unpackcompact` takes the family from its caller
/// (AF_INET/AF_INET6, `DHTMessageFactoryImpl.cc`); this codec has no
/// family context and discriminates by length (the KRPC `nodes`/`nodes6`
/// key already implies the family; semantically equivalent).
pub fn unpack_peer(bytes: &[u8]) -> Result<SocketAddr, DhtError> {
    match bytes.len() {
        COMPACT_LEN_IPV4 => {
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        COMPACT_LEN_IPV6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            let ip = Ipv6Addr::from(octets);
            // The length is already constrained to 18 by the match arm;
            // indexing is safe.
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        n => Err(DhtError::CompactPeerLength { got: n }),
    }
}

/// Decode a compact node info string (concatenated 26B/38B units); the
/// unit length is given by the caller per key (`nodes` ->
/// [`NODE_INFO_LEN_V4`], `nodes6` -> [`NODE_INFO_LEN_V6`]).
///
/// Mirrors aria2 `DHTMessageFactoryImpl.cc` extractNodes: a string length
/// that is not a multiple of the unit length is an error; the address
/// part of a unit always parses as 4B/16B (like aria2, a zero port is not
/// rejected). No length auto-detection: 26 and 38 share multiples (494),
/// so auto-detection without family context would be ambiguous.
pub fn unpack_node_infos_with_unit(bytes: &[u8], unit: usize) -> Result<Vec<NodeInfo>, DhtError> {
    if unit != NODE_INFO_LEN_V4 && unit != NODE_INFO_LEN_V6 {
        return Err(DhtError::NodesLength {
            len: bytes.len(),
            unit,
        });
    }
    if !bytes.len().is_multiple_of(unit) {
        return Err(DhtError::NodesLength {
            len: bytes.len(),
            unit,
        });
    }
    let mut out = Vec::with_capacity(bytes.len() / unit);
    for chunk in bytes.chunks_exact(unit) {
        let mut id = [0u8; super::node::DHT_ID_LENGTH];
        id.copy_from_slice(&chunk[..super::node::DHT_ID_LENGTH]);
        let addr = unpack_peer(&chunk[super::node::DHT_ID_LENGTH..])?;
        out.push(NodeInfo {
            id: NodeId(id),
            addr,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0))
    }

    // Vector source: aria2 test/BittorrentHelperTest.cc.

    /// BittorrentHelperTest.cc packcompact vectors: v6
    /// `1002:1035:4527:3546:7854:1237:3247:3217:6881` ->
    /// `100210354527354678541237324732171ae1`; v4 `192.168.0.1:6881` ->
    /// `c0a800011ae1`.
    #[test]
    fn pack_peer_matches_aria2_vectors() {
        let ip = match "1002:1035:4527:3546:7854:1237:3247:3217".parse::<Ipv6Addr>() {
            Ok(ip) => ip,
            Err(e) => panic!("bad literal: {e}"),
        };
        let v6 = SocketAddr::V6(SocketAddrV6::new(ip, 6881, 0, 0));
        let mut out = Vec::new();
        pack_peer(v6, &mut out);
        assert_eq!(out.len(), COMPACT_LEN_IPV6);
        assert_eq!(
            out,
            [
                0x10, 0x02, 0x10, 0x35, 0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47,
                0x32, 0x17, 0x1a, 0xe1
            ]
        );

        let mut out = Vec::new();
        pack_peer(v4(6881), &mut out);
        assert_eq!(out.len(), COMPACT_LEN_IPV4);
        assert_eq!(out, [0xc0, 0xa8, 0x00, 0x01, 0x1a, 0xe1]);
    }

    /// BittorrentHelperTest.cc unpackcompact vectors (bytes -> address/
    /// port round trip).
    #[test]
    fn unpack_peer_matches_aria2_vectors() {
        let c6 = [
            0x10u8, 0x02, 0x10, 0x35, 0x45, 0x27, 0x35, 0x46, 0x78, 0x54, 0x12, 0x37, 0x32, 0x47,
            0x32, 0x17, 0x1a, 0xe1,
        ];
        let addr = match unpack_peer(&c6) {
            Ok(a) => a,
            Err(e) => panic!("unpack v6 failed: {e:?}"),
        };
        assert_eq!(addr.port(), 6881);
        assert!(addr.is_ipv6());
        assert_eq!(
            addr.ip().to_string(),
            "1002:1035:4527:3546:7854:1237:3247:3217"
        );

        let addr = match unpack_peer(&[0xc0, 0xa8, 0x00, 0x01, 0x1a, 0xe1]) {
            Ok(a) => a,
            Err(e) => panic!("unpack v4 failed: {e:?}"),
        };
        assert_eq!(
            addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 6881))
        );
    }

    /// pack/unpack round trip (v4/v6) + invalid-length rejection.
    #[test]
    fn pack_unpack_roundtrip_and_length_guard() {
        for addr in [v4(6881), v4(0), v6(1), v6(65535)] {
            let mut buf = Vec::new();
            pack_peer(addr, &mut buf);
            assert_eq!(
                match unpack_peer(&buf) {
                    Ok(a) => a,
                    Err(e) => panic!("unpack failed for {addr}: {e:?}"),
                },
                addr
            );
        }
        assert!(matches!(
            unpack_peer(&[0u8; 5]),
            Err(DhtError::CompactPeerLength { got: 5 })
        ));
        assert!(matches!(
            unpack_peer(&[0u8; 7]),
            Err(DhtError::CompactPeerLength { got: 7 })
        ));
        assert!(matches!(
            unpack_peer(&[0u8; 17]),
            Err(DhtError::CompactPeerLength { got: 17 })
        ));
    }

    /// Compact node info parsing (extractNodes, aria2
    /// DHTMessageFactoryImpl.cc): 26B/38B units, non-multiples error.
    #[test]
    fn node_infos_unit_parsing() {
        let mut v4units = Vec::new();
        for i in 0u8..3 {
            let mut id = [0u8; 20];
            id[19] = i;
            v4units.extend_from_slice(&id);
            v4units.extend_from_slice(&[10, 0, 0, i]);
            v4units.extend_from_slice(&6881u16.to_be_bytes());
        }
        let nodes = match unpack_node_infos_with_unit(&v4units, NODE_INFO_LEN_V4) {
            Ok(n) => n,
            Err(e) => panic!("v4 parse failed: {e:?}"),
        };
        assert_eq!(nodes.len(), 3);
        let mut expect_id = [0u8; 20];
        expect_id[19] = 2;
        assert_eq!(nodes[2].id, NodeId(expect_id));
        assert_eq!(
            nodes[2].addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 6881))
        );

        // Wrong unit length (a 79B string parsed as 26) -> NodesLength.
        let mut bad = v4units.clone();
        bad.push(0);
        assert!(matches!(
            unpack_node_infos_with_unit(&bad, NODE_INFO_LEN_V4),
            Err(DhtError::NodesLength { len: 79, unit: 26 })
        ));

        // Empty string: 0 units (extractNodes loops zero times; legal).
        assert!(match unpack_node_infos_with_unit(&[], NODE_INFO_LEN_V4) {
            Ok(n) => n.is_empty(),
            Err(e) => panic!("empty parse failed: {e:?}"),
        });
    }
}

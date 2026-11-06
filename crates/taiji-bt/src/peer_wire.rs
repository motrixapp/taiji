//! Peer wire frame layer: v1 handshake + message codec.
//!
//! Handshake: pstrlen=19 + "BitTorrent protocol", 68B fixed; reserved-bit
//! predicates follow aria2 `BtHandshakeMessage.cc` (fast = [7]&0x04,
//! extended messaging = [5]&0x10, DHT = [7]&0x01) plus the BEP-52 v2
//! upgrade bit [7]&0x10. Messages: the BEP-3 set + BEP-5
//! port(9) + BEP-10 extended(20) + BEP-6 fast ext + BEP-52 hash
//! request/hashes/reject; structure rules and negative cases follow the
//! aria2 `test/Bt*MessageTest.cc` rules (payload length or id mismatch
//! must be rejected). All wire integers are big-endian (v1/v2);
//! `bitfield`/`piece`/`extended` payloads are held zero-copy as
//! `bytes::Bytes`. Upstream anchors: docs/design/peer-protocol.md.
//! Request scheduling / disk writes / PeerTask wiring are out of scope
//! here.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

/// "BitTorrent protocol" (BEP-3, fixed 19 bytes; anchor BtHandshakeMessage.cc).
pub const PSTR: &[u8] = b"BitTorrent protocol";

/// Full handshake length: 1 + 19 + 8 + 20 + 20 (BEP-3).
pub const HANDSHAKE_LEN: usize = 1 + PSTR.len() + 8 + 20 + 20;

/// Per-frame length-prefix guard: the largest piece frame = 9 + 16KiB
/// (block cap), so the headroom is 64KiB. An over-limit frame is a
/// disconnect (defense against malicious length prefixes).
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Reserved bits (BEP-3/BEP-5/BEP-10/BEP-52 bit predicates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reserved([u8; 8]);

impl Reserved {
    pub fn empty() -> Self {
        Reserved([0u8; 8])
    }

    /// aria2 default outbound bits: fast + extended messaging
    /// (BtHandshakeMessage.cc). The DHT bit and BEP-52 upgrade bit are
    /// layered on by the caller per session capability.
    pub fn aria2_default() -> Self {
        let mut r = [0u8; 8];
        r[7] |= 0x04; // fast extension
        r[5] |= 0x10; // extended messaging (BEP10)
        Reserved(r)
    }

    pub fn supports_fast(self) -> bool {
        self.0[7] & 0x04 != 0
    }

    pub fn supports_extended(self) -> bool {
        self.0[5] & 0x10 != 0
    }

    pub fn supports_dht(self) -> bool {
        self.0[7] & 0x01 != 0
    }

    /// Peer declares BTv2 support (BEP-52 upgrade path).
    pub fn supports_v2(self) -> bool {
        self.0[7] & 0x10 != 0
    }

    /// Set the BTv2 capability bit (BEP-52 upgrade path section: "a peer
    /// can set the 4th most significant bit in the last byte of the
    /// reserved bitfield to indicate that it also supports the new format",
    /// i.e. reserved[7] & 0x10). Outbound handshakes must set this when the
    /// local side has a v2 face (hybrid/v2-only).
    pub fn with_v2(mut self) -> Self {
        self.0[7] |= 0x10;
        Reserved(self.0)
    }

    /// Set the DHT support bit (BEP-5 "transmission of the port number"
    /// section: handshake reserved[7] & 0x01 declares DHT capability). The
    /// engine sets it before spawn when the session enables DHT; peers use
    /// it to decide whether to send us PORT messages (same bit as aria2
    /// `Peer.cc` `isDHTEnabled`).
    pub fn with_dht(mut self) -> Self {
        self.0[7] |= 0x01;
        Reserved(self.0)
    }

    /// Clear the DHT support bit (runtime hot-disable handshake face: new
    /// outbound handshakes no longer declare DHT, so peers stop sending
    /// PORT. Dual of [`Self::with_dht`]; existing connections keep their
    /// negotiated state for the connection's lifetime).
    pub fn without_dht(mut self) -> Self {
        self.0[7] &= !0x01;
        Reserved(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerWireError> {
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| PeerWireError::InvalidHandshake("reserved must be 8 bytes".into()))?;
        Ok(Reserved(arr))
    }
}

/// The 68B fixed-length handshake (BEP-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub reserved: Reserved,
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

impl Handshake {
    pub fn encode(&self) -> [u8; HANDSHAKE_LEN] {
        let mut out = [0u8; HANDSHAKE_LEN];
        out[0] = PSTR.len() as u8;
        out[1..1 + PSTR.len()].copy_from_slice(PSTR);
        out[20..28].copy_from_slice(self.reserved.as_bytes());
        out[28..48].copy_from_slice(&self.info_hash);
        out[48..68].copy_from_slice(&self.peer_id);
        out
    }

    /// Strict decode: total length, prefix and pstr are all validated
    /// (aria2 create() copies by offset only; here pstr must match —
    /// non-BT traffic is dropped early, with no interop cost).
    pub fn decode(bytes: &[u8]) -> Result<Self, PeerWireError> {
        if bytes.len() != HANDSHAKE_LEN {
            return Err(PeerWireError::InvalidHandshake(format!(
                "handshake must be {HANDSHAKE_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        if bytes[0] as usize != PSTR.len() || &bytes[1..1 + PSTR.len()] != PSTR {
            return Err(PeerWireError::InvalidHandshake("bad pstrlen/pstr".into()));
        }
        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&bytes[28..48]);
        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&bytes[48..68]);
        Ok(Handshake {
            reserved: Reserved::from_bytes(&bytes[20..28])?,
            info_hash,
            peer_id,
        })
    }
}

/// Peer messages (full BEP-3 set + BEP-5 port(9) + BEP-10 extended(20);
/// BEP-3 id table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// length=0 frame (BEP-3 keepalive).
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have {
        index: u32,
    },
    /// BEP-6 fast ext: the peer has every piece (no bitfield needs to follow).
    HaveAll,
    /// BEP-6 fast ext: the peer has no pieces.
    HaveNone,
    /// BEP-6 fast ext: pieces the peer suggests downloading first
    /// ("suggest").
    Suggest {
        index: u32,
    },
    /// BEP-6 fast ext: pieces we may request even while choked.
    AllowedFast {
        index: u32,
    },
    /// Payload >= 1 byte (anchor BtBitfieldMessage::create).
    Bitfield {
        bits: Bytes,
    },
    /// BEP-52 hash request (id 21): `pieces root` (32B) + `base layer`/
    /// `index`/`length`/`proof layers` (4B big-endian each — BEP-52 "All
    /// later integers sent in the protocol are encoded as four bytes
    /// big-endian"). MUSTs: index is a multiple of length (0 included);
    /// length >= 2 and a power of two (SHOULD <= 512 — not enforced). The
    /// codec enforces the MUSTs (violation = disconnect).
    HashRequest {
        root: [u8; 32],
        base: u32,
        index: u32,
        length: u32,
        proof: u32,
    },
    /// BEP-52 hashes (id 22): same header as the request plus `length`
    /// base-layer hashes and sibling proof hashes (32B each). Count =
    /// length + max(0, proof - (log2(length)-1)) (BEP-52: proof layers
    /// that cover an entire subtree — the first log2(length)-1 — are
    /// omitted but still counted). The codec enforces the exact count.
    Hashes {
        root: [u8; 32],
        base: u32,
        index: u32,
        length: u32,
        proof: u32,
        hashes: Vec<[u8; 32]>,
    },
    /// BEP-52 hash reject (id 23): same payload as hash request.
    HashReject {
        root: [u8; 32],
        base: u32,
        index: u32,
        length: u32,
        proof: u32,
    },
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Bytes,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    /// Fast-extension reject (BEP-6; a fast-negotiating peer must answer
    /// unservable requests — rejected while choked or not servable).
    Reject {
        index: u32,
        begin: u32,
        length: u32,
    },
    Port {
        port: u16,
    },
    /// BEP-10: ext_id=0 is the extended handshake (dict), others are
    /// registered extension messages.
    Extended {
        ext_id: u8,
        payload: Bytes,
    },
}

/// Message ids (BEP-3/BEP-5/BEP-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageId {
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
    Port = 9,
    /// BEP-6 fast extension: reject request (id 0x10; payload same as
    /// request).
    Reject = 16,
    /// BEP-6 fast extension: suggest piece (id 0x0D; payload = 4B index).
    Suggest = 13,
    /// BEP-6 fast extension: peer has all pieces (id 0x0E; no payload).
    HaveAll = 14,
    /// BEP-6 fast extension: peer has no pieces (id 0x0F; no payload).
    HaveNone = 15,
    /// BEP-6 fast extension: allowed-while-choked pieces (id 0x11; 4B
    /// index).
    AllowedFast = 17,
    /// BEP-52 hash request (id 21; 49B payload, see [`Message::HashRequest`]).
    HashRequest = 21,
    /// BEP-52 hashes (id 22).
    Hashes = 22,
    /// BEP-52 hash reject (id 23).
    HashReject = 23,
    Extended = 20,
}

impl Message {
    pub fn id(&self) -> Option<MessageId> {
        match self {
            Message::KeepAlive => None,
            Message::Choke => Some(MessageId::Choke),
            Message::Unchoke => Some(MessageId::Unchoke),
            Message::Interested => Some(MessageId::Interested),
            Message::NotInterested => Some(MessageId::NotInterested),
            Message::Have { .. } => Some(MessageId::Have),
            Message::Bitfield { .. } => Some(MessageId::Bitfield),
            Message::Request { .. } => Some(MessageId::Request),
            Message::Piece { .. } => Some(MessageId::Piece),
            Message::Cancel { .. } => Some(MessageId::Cancel),
            Message::Port { .. } => Some(MessageId::Port),
            Message::Reject { .. } => Some(MessageId::Reject),
            Message::Suggest { .. } => Some(MessageId::Suggest),
            Message::HaveAll => Some(MessageId::HaveAll),
            Message::HaveNone => Some(MessageId::HaveNone),
            Message::AllowedFast { .. } => Some(MessageId::AllowedFast),
            Message::HashRequest { .. } => Some(MessageId::HashRequest),
            Message::Hashes { .. } => Some(MessageId::Hashes),
            Message::HashReject { .. } => Some(MessageId::HashReject),
            Message::Extended { .. } => Some(MessageId::Extended),
        }
    }

    /// Exact encoded frame size (variable bodies by payload length). The
    /// capacity source for [`Self::encode`] — replaces a constant
    /// `MAX_FRAME_LEN` preallocation: small frames like 17B request/reject
    /// no longer take a transient 64KiB allocation, and large frames
    /// allocate exactly.
    fn encoded_len(&self) -> usize {
        // Common frame header = 4B length prefix + 1B id (keepalive = 4B
        // only).
        const HEAD: usize = 5;
        match self {
            Message::KeepAlive => 4,
            Message::Choke
            | Message::Unchoke
            | Message::Interested
            | Message::NotInterested
            | Message::HaveAll
            | Message::HaveNone => HEAD,
            Message::Have { .. } | Message::Suggest { .. } | Message::AllowedFast { .. } => {
                HEAD + 4
            }
            Message::Request { .. } | Message::Cancel { .. } | Message::Reject { .. } => HEAD + 12,
            Message::Port { .. } => HEAD + 2,
            Message::Bitfield { bits } => HEAD + bits.len(),
            Message::Piece { block, .. } => HEAD + 8 + block.len(),
            Message::HashRequest { .. } | Message::HashReject { .. } => HEAD + 32 + 16,
            Message::Hashes { hashes, .. } => HEAD + 32 + 16 + hashes.len() * 32,
            Message::Extended { payload, .. } => HEAD + 1 + payload.len(),
        }
    }

    /// Encode a full frame (4B big-endian length prefix + id + payload;
    /// keepalive = 0).
    pub fn encode(&self) -> Bytes {
        // The wire prefix is 4B: a payload past u32::MAX is
        // unrepresentable, and the per-arm `as u32` casts below would
        // silently wrap (lossy). encoded_len() - 4 is exactly the prefix
        // value each arm writes (HEAD = prefix + 1B id; keepalive = 4B
        // total, prefix 0). Debug-only tripwire — release bytes unchanged.
        let len = self.encoded_len();
        debug_assert!(
            u32::try_from(len - 4).is_ok(),
            "frame payload {} exceeds the u32::MAX length prefix",
            len - 4
        );
        let mut out = BytesMut::with_capacity(len);
        match self {
            Message::KeepAlive => {
                out.put_u32(0);
            }
            Message::Choke => {
                out.put_u32(1);
                out.put_u8(MessageId::Choke as u8);
            }
            Message::Reject {
                index,
                begin,
                length,
            } => {
                out.put_u32(13);
                out.put_u8(MessageId::Reject as u8);
                out.put_u32(*index);
                out.put_u32(*begin);
                out.put_u32(*length);
            }
            Message::Unchoke => {
                out.put_u32(1);
                out.put_u8(MessageId::Unchoke as u8);
            }
            Message::Interested => {
                out.put_u32(1);
                out.put_u8(MessageId::Interested as u8);
            }
            Message::NotInterested => {
                out.put_u32(1);
                out.put_u8(MessageId::NotInterested as u8);
            }
            Message::Have { index } => {
                out.put_u32(5);
                out.put_u8(MessageId::Have as u8);
                out.put_u32(*index);
            }
            Message::Bitfield { bits } => {
                out.put_u32(1 + bits.len() as u32);
                out.put_u8(MessageId::Bitfield as u8);
                out.extend_from_slice(bits);
            }
            Message::Request {
                index,
                begin,
                length,
            }
            | Message::Cancel {
                index,
                begin,
                length,
            } => {
                let id = match self {
                    Message::Request { .. } => MessageId::Request as u8,
                    _ => MessageId::Cancel as u8,
                };
                out.put_u32(13);
                out.put_u8(id);
                out.put_u32(*index);
                out.put_u32(*begin);
                out.put_u32(*length);
            }
            Message::Piece {
                index,
                begin,
                block,
            } => {
                out.put_u32(9 + block.len() as u32);
                out.put_u8(MessageId::Piece as u8);
                out.put_u32(*index);
                out.put_u32(*begin);
                out.extend_from_slice(block);
            }
            Message::Port { port } => {
                out.put_u32(3);
                out.put_u8(MessageId::Port as u8);
                out.put_u16(*port);
            }
            Message::Suggest { index } | Message::AllowedFast { index } => {
                let id = match self {
                    Message::Suggest { .. } => MessageId::Suggest as u8,
                    _ => MessageId::AllowedFast as u8,
                };
                out.put_u32(5);
                out.put_u8(id);
                out.put_u32(*index);
            }
            Message::HaveAll | Message::HaveNone => {
                let id = match self {
                    Message::HaveAll => MessageId::HaveAll as u8,
                    _ => MessageId::HaveNone as u8,
                };
                out.put_u32(1);
                out.put_u8(id);
            }
            Message::HashRequest {
                root,
                base,
                index,
                length,
                proof,
            }
            | Message::HashReject {
                root,
                base,
                index,
                length,
                proof,
            } => {
                let id = match self {
                    Message::HashRequest { .. } => MessageId::HashRequest as u8,
                    _ => MessageId::HashReject as u8,
                };
                out.put_u32(49);
                out.put_u8(id);
                out.extend_from_slice(root);
                out.put_u32(*base);
                out.put_u32(*index);
                out.put_u32(*length);
                out.put_u32(*proof);
            }
            Message::Hashes {
                root,
                base,
                index,
                length,
                proof,
                hashes,
            } => {
                out.put_u32(49 + 32 * hashes.len() as u32);
                out.put_u8(MessageId::Hashes as u8);
                out.extend_from_slice(root);
                out.put_u32(*base);
                out.put_u32(*index);
                out.put_u32(*length);
                out.put_u32(*proof);
                for h in hashes {
                    out.extend_from_slice(h);
                }
            }
            Message::Extended { ext_id, payload } => {
                out.put_u32(1 + 1 + payload.len() as u32);
                out.put_u8(MessageId::Extended as u8);
                out.put_u8(*ext_id);
                out.extend_from_slice(payload);
            }
        }
        out.freeze()
    }

    /// Decode a message body (without the 4B length prefix; `bytes` = id +
    /// payload). Structure rules follow aria2 test/Bt*MessageTest.cc
    /// (payload length mismatch / unknown ids must be rejected).
    pub fn decode_body(bytes: &[u8]) -> Result<Self, PeerWireError> {
        // Copies into Bytes then runs the zero-copy core (payload slices =
        // `Bytes::slice`). This form is for tests/non-hot paths — the wire
        // read loop uses [`Self::decode_body_from`] (frame body already a
        // frozen `Bytes`).
        Self::decode_body_from(Bytes::copy_from_slice(bytes))
    }

    /// Decode a message body (zero-copy form): `body` = frozen `Bytes` of
    /// id + payload (the frame layer's `split_to(need).freeze()` output).
    /// Large piece/bitfield/extended payloads are held as `Bytes::slice` —
    /// no byte copies, sharing the frame read buffer's allocation by
    /// reference count. The `decode_body(&[u8])` form forced a
    /// `copy_from_slice` per 16KiB block (plus a second copy in the
    /// transit layer) — needless memcpy on the hot path.
    ///
    /// Structure rules are identical to [`Self::decode_body`] (same
    /// dispatch body).
    pub fn decode_body_from(body: Bytes) -> Result<Self, PeerWireError> {
        let Some(&id) = body.first() else {
            return Ok(Message::KeepAlive); // an empty body only arrives with length=0 (guaranteed by the frame layer)
        };
        let msg = match id {
            0 => {
                expect_len(&body[1..], 0, id)?;
                Message::Choke
            }
            1 => {
                expect_len(&body[1..], 0, id)?;
                Message::Unchoke
            }
            2 => {
                expect_len(&body[1..], 0, id)?;
                Message::Interested
            }
            3 => {
                expect_len(&body[1..], 0, id)?;
                Message::NotInterested
            }
            4 => {
                expect_len(&body[1..], 4, id)?;
                Message::Have {
                    index: be32(&body[1..]),
                }
            }
            5 => {
                if body.len() < 2 {
                    return Err(PeerWireError::InvalidPayload {
                        id,
                        reason: "bitfield must be at least 1 byte".into(),
                    });
                }
                Message::Bitfield {
                    bits: body.slice(1..),
                }
            }
            6 | 8 => {
                expect_len(&body[1..], 12, id)?;
                let (index, begin, length) = three_u32(&body[1..])?;
                if id == 6 {
                    Message::Request {
                        index,
                        begin,
                        length,
                    }
                } else {
                    Message::Cancel {
                        index,
                        begin,
                        length,
                    }
                }
            }
            16 => {
                expect_len(&body[1..], 12, id)?;
                let (index, begin, length) = three_u32(&body[1..])?;
                Message::Reject {
                    index,
                    begin,
                    length,
                }
            }
            13 | 17 => {
                expect_len(&body[1..], 4, id)?;
                let msg = Message::Suggest {
                    index: be32(&body[1..]),
                };
                if id == 17 {
                    Message::AllowedFast {
                        index: be32(&body[1..]),
                    }
                } else {
                    msg
                }
            }
            14 => {
                expect_len(&body[1..], 0, id)?;
                Message::HaveAll
            }
            15 => {
                expect_len(&body[1..], 0, id)?;
                Message::HaveNone
            }
            21 | 23 => {
                expect_len(&body[1..], 48, id)?;
                let h = hash_msg_fields(id, &body[1..])?;
                if id == 23 {
                    Message::HashReject {
                        root: h.root,
                        base: h.base,
                        index: h.index,
                        length: h.length,
                        proof: h.proof,
                    }
                } else {
                    Message::HashRequest {
                        root: h.root,
                        base: h.base,
                        index: h.index,
                        length: h.length,
                        proof: h.proof,
                    }
                }
            }
            22 => {
                let payload_len = body.len() - 1;
                if payload_len < 48 || !(payload_len - 48).is_multiple_of(32) {
                    return Err(PeerWireError::InvalidPayload {
                        id,
                        reason: format!(
                            "hashes payload must be 48 + 32*n bytes, got {}",
                            payload_len
                        ),
                    });
                }
                let h = hash_msg_fields(id, &body[1..])?;
                let count = (payload_len - 48) / 32;
                // BEP-52: length base-layer hashes + proof layers (the
                // first log2(length)-1 omitted but still counted) -> the
                // exact count is derivable; a mismatch = malformed frame.
                let want = hashes_count(h.length, h.proof);
                if count as u32 != want {
                    return Err(PeerWireError::InvalidPayload {
                        id,
                        reason: format!(
                            "hashes count {count} != length+proofs {want} (length {}, proof {})",
                            h.length, h.proof
                        ),
                    });
                }
                let mut hashes = Vec::with_capacity(count);
                for i in 0..count {
                    let off = 1 + 48 + i * 32;
                    let mut one = [0u8; 32];
                    one.copy_from_slice(&body[off..off + 32]);
                    hashes.push(one);
                }
                Message::Hashes {
                    root: h.root,
                    base: h.base,
                    index: h.index,
                    length: h.length,
                    proof: h.proof,
                    hashes,
                }
            }
            7 => {
                if body.len() < 9 {
                    return Err(PeerWireError::InvalidPayload {
                        id,
                        reason: format!("piece payload must be >= 8, got {}", body.len() - 1),
                    });
                }
                let (index, begin) = two_u32(&body[1..])?;
                Message::Piece {
                    index,
                    begin,
                    // zero copy: block payload = frame body slice
                    // (refcounted shared read buffer).
                    block: body.slice(9..),
                }
            }
            9 => {
                expect_len(&body[1..], 2, id)?;
                Message::Port {
                    port: u16::from_be_bytes([body[1], body[2]]),
                }
            }
            20 => {
                if body.len() < 2 {
                    return Err(PeerWireError::InvalidPayload {
                        id,
                        reason: "extended must carry ext_id".into(),
                    });
                }
                Message::Extended {
                    ext_id: body[1],
                    payload: body.slice(2..),
                }
            }
            other => return Err(PeerWireError::UnknownMessageId(other)),
        };
        Ok(msg)
    }
}

/// Common hash-message fields (payload[0..49]): root(32) +
/// base/index/length/proof (4B big-endian each). Enforces the BEP-52
/// MUSTs: length >= 2 and a power of two; index a multiple of length
/// (including 0); proof <= [`MAX_PROOF_LAYERS`] (hardening: a proof beyond
/// the u32-length-domain tree depth is a malformed frame — oversized
/// proofs overflowed [`hashes_count`]). `id` = the message id of the frame
/// the payload came from (for error classification).
fn hash_msg_fields(id: u8, payload: &[u8]) -> Result<HashMsgFields, PeerWireError> {
    let mut root = [0u8; 32];
    root.copy_from_slice(&payload[..32]);
    let base = be32(&payload[32..]);
    let index = be32(&payload[36..]);
    let length = be32(&payload[40..]);
    let proof = be32(&payload[44..]);
    if length < 2 || !length.is_power_of_two() {
        return Err(PeerWireError::InvalidPayload {
            id,
            reason: format!("hash length {length} must be >= 2 and a power of two (BEP52)"),
        });
    }
    if !index.is_multiple_of(length) {
        return Err(PeerWireError::InvalidPayload {
            id,
            reason: format!("hash index {index} must be a multiple of length {length} (BEP52)"),
        });
    }
    if proof > MAX_PROOF_LAYERS {
        return Err(PeerWireError::InvalidPayload {
            id,
            reason: format!(
                "hash proof {proof} exceeds protocol max {MAX_PROOF_LAYERS} (u32 length domain tree depth)"
            ),
        });
    }
    Ok(HashMsgFields {
        root,
        base,
        index,
        length,
        proof,
    })
}

/// Canonical derivation of the `hashes` message hash count: length
/// base-layer hashes + max(0, proof - (log2(length)-1)) proof hashes (the
/// first log2(length)-1 proof layers, which cover whole subtrees, are
/// omitted but still counted — BEP-52). Public form of [`hashes_count`]
/// (for defensive checks on the peer-serving side).
pub fn hashes_count_for(length: u32, proof: u32) -> u32 {
    hashes_count(length, proof)
}

/// Protocol cap for the `proof` field: a u32 length domain bounds the
/// Merkle tree depth at 31 (log2(u32::MAX)), so more than 32 proof layers
/// cannot correspond to a legal subtree. Local defensive cap (hardening:
/// BEP-52 does not explicitly bound the proof domain — a malicious large
/// proof used to overflow `length + ...` in [`hashes_count`], panicking
/// the connection task on debug builds and silently wrapping past the
/// BEP-52 count MUST on release builds).
pub const MAX_PROOF_LAYERS: u32 = 32;

fn hashes_count(length: u32, proof: u32) -> u32 {
    let omitted = u32::BITS - 1 - length.leading_zeros(); // log2(length)
    let omitted = omitted.saturating_sub(1);
    // Hardening: saturating add — length=2 with proof=0xFFFFFFFF used to
    // overflow here (release wraparound bypassed the count check). The
    // proof domain cap is enforced decoder-side by [`hash_msg_fields`]
    // (> [`MAX_PROOF_LAYERS`] = malformed); this function stays total for
    // any input (reused by peer-serving defensive checks).
    length.saturating_add(proof.saturating_sub(omitted))
}

struct HashMsgFields {
    root: [u8; 32],
    base: u32,
    index: u32,
    length: u32,
    proof: u32,
}

fn expect_len(payload: &[u8], want: usize, id: u8) -> Result<(), PeerWireError> {
    if payload.len() != want {
        return Err(PeerWireError::InvalidPayload {
            id,
            reason: format!("payload must be {want} bytes, got {}", payload.len()),
        });
    }
    Ok(())
}

/// Big-endian read (length pre-validated by the caller's `expect_len`).
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn two_u32(payload: &[u8]) -> Result<(u32, u32), PeerWireError> {
    Ok((be32(payload), be32(&payload[4..])))
}

fn three_u32(payload: &[u8]) -> Result<(u32, u32, u32), PeerWireError> {
    Ok((be32(payload), be32(&payload[4..]), be32(&payload[8..])))
}

/// Frame-layer errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PeerWireError {
    /// The frame layer requires `From<io::Error>`; transport IO errors
    /// pass through here (connection-level failures). `kind` is extracted
    /// from the underlying `io::Error` so reconnect/backoff logic can
    /// classify by kind (ConnectionReset/TimedOut/ConnectionRefused) and
    /// must not depend on error-text substrings.
    #[error("transport io: {message}")]
    Io {
        kind: std::io::ErrorKind,
        message: String,
    },
    #[error("invalid handshake: {0}")]
    InvalidHandshake(String),
    #[error("unknown message id {0}")]
    UnknownMessageId(u8),
    #[error("invalid payload for id {id}: {reason}")]
    InvalidPayload { id: u8, reason: String },
    #[error("frame too large: {size} > {cap}")]
    FrameTooLarge { size: usize, cap: usize },
    #[error("truncated frame: need {need} more bytes")]
    Truncated { need: usize },
}

impl From<std::io::Error> for PeerWireError {
    fn from(e: std::io::Error) -> Self {
        PeerWireError::Io {
            kind: e.kind(),
            message: e.to_string(),
        }
    }
}

/// BEP-10 extended handshake dict (samples per aria2
/// HandshakeExtensionMessageTest.cc and the ExtensionMessageRegistry name
/// table).
///
/// Shape per aria2 `HandshakeExtensionMessage`: `m` dict (extension name
/// -> msg id), `p` (listen port), `v` (client version), `metadata_size`,
/// `reqq`. Semantics (metadata exchange/PEX) live elsewhere; this layer
/// only does dict structure codec.
///
/// # `upload_only` (BEP-21, additive key — existing key semantics
/// untouched)
///
/// BEP-21: "A peer that is a partial seed SHOULD include an extra header
/// in the extension handshake ... Setting the value of this key to 1
/// indicates that this peer is not interested in downloading anything."
/// Encoding: true -> integer 1; false omits the key entirely (BEP-21 only
/// defines the value 1; never send 0 — same rule as libtorrent
/// `bt_peer_connection.cpp`, which writes the key only when it holds).
/// Decoding: a non-zero integer = true (libtorrent
/// `dict_find_int_value("upload_only", 0)` truthiness), missing = false.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtHandshake {
    /// Decoded m-dict extension ids: a value of 0 = disabled and is
    /// filtered to None (BEP-10 "Setting an extension number to zero means
    /// that the extension is not supported / disabled."; 0 is also the
    /// handshake's own reserved id). Encoding is unrestricted (only tests
    /// construct Some(0) to simulate a disabled advertisement).
    pub m_ut_metadata: Option<u8>,
    pub m_ut_pex: Option<u8>,
    /// Outbound ut_holepunch advertisement id: Some = advertise
    /// `m.ut_holepunch` and consume inbound frames (gated by
    /// [`crate::peer::PeerConfig::holepunch`]); None = neither advertise
    /// nor consume. Customary value 0x20 (uTorrent convention; libtorrent
    /// itself advertises 4 — BEP-10 ids are local, interop does not depend
    /// on the value; see the `crate::holepunch` module docs).
    pub m_ut_holepunch: Option<u8>,
    pub p: Option<u16>,
    pub v: Option<String>,
    pub metadata_size: Option<u32>,
    pub reqq: Option<u32>,
    /// BEP-21 seed/partial-seed announcement (true = no longer interested
    /// in downloading anything).
    pub upload_only: bool,
}

impl ExtHandshake {
    pub fn encode(&self) -> Result<Bytes, PeerWireError> {
        use crate::bencode::{Value, encode};
        let mut dict: Vec<(Vec<u8>, Value)> = Vec::new();
        let mut m_dict: Vec<(Vec<u8>, Value)> = Vec::new();
        // m-dict keys also ascending (encode rejects unordered dicts):
        // ut_holepunch < ut_metadata < ut_pex.
        if let Some(id) = self.m_ut_holepunch {
            m_dict.push((b"ut_holepunch".to_vec(), Value::Int(id as i64)));
        }
        if let Some(id) = self.m_ut_metadata {
            m_dict.push((b"ut_metadata".to_vec(), Value::Int(id as i64)));
        }
        if let Some(id) = self.m_ut_pex {
            m_dict.push((b"ut_pex".to_vec(), Value::Int(id as i64)));
        }
        if !m_dict.is_empty() {
            dict.push((b"m".to_vec(), Value::Dict(m_dict)));
        }
        if let Some(p) = self.p {
            dict.push((b"p".to_vec(), Value::Int(p as i64)));
        }
        if let Some(v) = &self.v {
            dict.push((b"v".to_vec(), Value::Bytes(v.as_bytes().to_vec())));
        }
        if let Some(sz) = self.metadata_size {
            dict.push((b"metadata_size".to_vec(), Value::Int(sz as i64)));
        }
        if let Some(rq) = self.reqq {
            dict.push((b"reqq".to_vec(), Value::Int(rq as i64)));
        }
        // BEP-21 upload_only: write the key only when true (value always 1
        // — BEP-21 defines only the value 1; libtorrent
        // bt_peer_connection.cpp same rule).
        if self.upload_only {
            dict.push((b"upload_only".to_vec(), Value::Int(1)));
        }
        // Canonical bencode requires ascending keys; sort uniformly (b"m"
        // is a prefix of b"metadata_size"; prefix sorts first bytewise).
        dict.sort_by(|a, b| a.0.cmp(&b.0));
        let value = Value::Dict(dict);
        encode(&value)
            .map(Bytes::from)
            .map_err(|e| PeerWireError::InvalidHandshake(format!("bencode encode: {e}")))
    }

    /// Parse the extended handshake dict (strict bencode; unknown keys
    /// ignored — BEP-10 allows extension fields, required for interop).
    pub fn decode(payload: &[u8]) -> Result<Self, PeerWireError> {
        use crate::bencode::{Value, decode_permissive};
        // The BEP-10 handshake is a peer dict: unordered keys are allowed
        // (aria2 itself emits unordered; metainfo paths are unaffected).
        let value = decode_permissive(payload)
            .map_err(|e| PeerWireError::InvalidHandshake(format!("dict: {e}")))?;
        let Value::Dict(dict) = &value else {
            return Err(PeerWireError::InvalidHandshake(
                "top level must be dict".into(),
            ));
        };
        let mut out = ExtHandshake::default();
        for (key, val) in dict {
            match (key.as_slice(), val) {
                (b"m", Value::Dict(m)) => {
                    for (name, id) in m {
                        match (name.as_slice(), id) {
                            // Hardening: bencode integers pass `try_from`
                            // domain checks first — negatives/out-of-range
                            // values used to be silently truncated to the
                            // bit width (i-1 -> 255, i300 -> 44), forging
                            // wrong extension ids/ports. Invalid values are
                            // treated as a missing field (None; BEP-10
                            // interop semantics). A value of 0 is also
                            // treated as missing — BEP-10: "Setting an
                            // extension number to zero means that the
                            // extension is not supported / disabled." (0 is
                            // also the ext handshake's own reserved id:
                            // "0 = handshake, >0 = extended message").
                            // Filtered once at the decode source so the
                            // three consumers (pex outbound sender /
                            // holepunch negotiation mirror / metadata fetch
                            // session) never see 0 as a valid advertise id
                            // (libtorrent same rule — supports_holepunch()
                            // is m_holepunch_id != 0,
                            // bt_peer_connection.cpp).
                            (b"ut_metadata", Value::Int(i)) => {
                                out.m_ut_metadata = u8::try_from(*i).ok().filter(|id| *id != 0);
                            }
                            (b"ut_pex", Value::Int(i)) => {
                                out.m_ut_pex = u8::try_from(*i).ok().filter(|id| *id != 0);
                            }
                            (b"ut_holepunch", Value::Int(i)) => {
                                out.m_ut_holepunch = u8::try_from(*i).ok().filter(|id| *id != 0);
                            }
                            _ => {} // unknown extension names ignored (BEP-10 interop)
                        }
                    }
                }
                (b"p", Value::Int(i)) => out.p = u16::try_from(*i).ok(),
                (b"v", Value::Bytes(b)) => out.v = Some(String::from_utf8_lossy(b).into_owned()),
                (b"metadata_size", Value::Int(i)) => out.metadata_size = u32::try_from(*i).ok(),
                (b"reqq", Value::Int(i)) => out.reqq = u32::try_from(*i).ok(),
                // BEP-21: non-zero = upload_only holds (libtorrent
                // bt_peer_connection.cpp truthiness rule).
                (b"upload_only", Value::Int(i)) => out.upload_only = *i != 0,
                _ => {} // unknown keys ignored (BEP-10 interop)
            }
        }
        Ok(out)
    }
}

/// Extension message registry (shape per ExtensionMessageRegistry: name
/// table + name->msg-id mapping; default outbound ids `ut_metadata=2,
/// ut_pex=1` per the HandshakeExtensionMessageTest sample).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtRegistry {
    ut_metadata: Option<u8>,
    ut_pex: Option<u8>,
    ut_holepunch: Option<u8>,
}

impl ExtRegistry {
    /// aria2 outbound defaults: ut_pex=1, ut_metadata=2 (aria2 has no
    /// ut_holepunch — the extension is not in its name table, so it is not
    /// advertised by default; the engine sets it explicitly behind its
    /// gate).
    pub fn aria2_default() -> Self {
        ExtRegistry {
            ut_metadata: Some(2),
            ut_pex: Some(1),
            ut_holepunch: None,
        }
    }

    pub fn empty() -> Self {
        ExtRegistry {
            ut_metadata: None,
            ut_pex: None,
            ut_holepunch: None,
        }
    }

    pub fn set(&mut self, name: &str, id: u8) {
        match name {
            "ut_metadata" => self.ut_metadata = Some(id),
            "ut_pex" => self.ut_pex = Some(id),
            // A local extension beyond aria2's name table (not covered by
            // the ExtensionMessageRegistry filter — registered dynamically
            // here, BEP-10 m-dict semantics).
            "ut_holepunch" => self.ut_holepunch = Some(id),
            _ => {} // unknown names not registered (aria2 strBtExtension name table)
        }
    }

    pub fn remove(&mut self, name: &str) {
        match name {
            "ut_metadata" => self.ut_metadata = None,
            "ut_pex" => self.ut_pex = None,
            "ut_holepunch" => self.ut_holepunch = None,
            _ => {}
        }
    }

    pub fn get(&self, name: &str) -> Option<u8> {
        match name {
            "ut_metadata" => self.ut_metadata,
            "ut_pex" => self.ut_pex,
            "ut_holepunch" => self.ut_holepunch,
            _ => None,
        }
    }
}

/// tokio_util frame codec: message state (the handshake preamble is
/// handled by the connection layer, see `Handshake::decode`). Send and
/// receive halves are independent (the PeerTask row model).
///
/// When `arena` is present the frame body no longer freezes a shared read
/// buffer (the freeze pins the Framed BytesMut and forces it to rotate its
/// allocation every batch): instead a block is leased from the face-level
/// [`BlockArena`], copied in, and `advance` releases the shared buffer; the
/// returned `Bytes` hands the block back to the pool when its reference
/// count reaches zero (`Bytes::from_owner`). The default `None` keeps the
/// frozen-shared path unchanged (fallback switch `BH_BLOCK_ARENA=0` /
/// tests).
#[derive(Debug, Default)]
pub struct FrameCodec {
    state: FrameState,
    arena: Option<std::sync::Arc<taiji_io::block_arena::BlockArena>>,
}

impl FrameCodec {
    /// Pooled decode form: frame bodies lease arena blocks (<=16KiB main
    /// bucket; over-bucket frames fall back to the frozen-shared path —
    /// rare, once per connection).
    pub fn with_arena(arena: std::sync::Arc<taiji_io::block_arena::BlockArena>) -> FrameCodec {
        FrameCodec {
            state: FrameState::default(),
            arena: Some(arena),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum FrameState {
    #[default]
    /// Waiting for the length prefix.
    Idle,
    /// Prefix read, waiting for the body (`usize` = remaining bytes).
    Body(usize),
}

impl tokio_util::codec::Decoder for FrameCodec {
    type Item = Message;
    type Error = PeerWireError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                FrameState::Idle => {
                    if src.len() < 4 {
                        return Ok(None);
                    }
                    let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
                    if len > MAX_FRAME_LEN {
                        return Err(PeerWireError::FrameTooLarge {
                            size: len,
                            cap: MAX_FRAME_LEN,
                        });
                    }
                    src.advance(4);
                    if len == 0 {
                        return Ok(Some(Message::KeepAlive));
                    }
                    // One-shot exact reservation for the announced body
                    // (read-buffer face): without it the FramedRead
                    // pre-read `reserve(1)` grows the shared buffer by
                    // doubling per poll — a 16KiB piece body costs ~9
                    // grow-copy steps and as many short read syscalls.
                    // `reserve(len)` here is a no-op once capacity covers
                    // the frame (active-connection steady state), and a
                    // single exact growth otherwise; it never shrinks below
                    // need. Pure buffer-policy change inside the codec:
                    // frame boundaries, ordering and every decode verdict
                    // are untouched (the decode loop below consumes the
                    // same bytes either way).
                    src.reserve(len);
                    self.state = FrameState::Body(len);
                }
                FrameState::Body(need) => {
                    if src.len() < need {
                        return Ok(None);
                    }
                    // Pooled path: the frame body is copied into an arena
                    // lease (1KiB/16KiB buckets; pool-full/over-bucket
                    // falls back to direct allocation inside lease), and
                    // advance immediately releases the Framed shared buffer
                    // (no freeze pinning -> constant read-buffer reuse).
                    // Blocks return to the pool when message refcounts drop
                    // to zero. Same buffer-reuse theme as libtorrent
                    // chained_buffer (src/chained_buffer.cpp) and
                    // packet_pool acquire/release sizing
                    // (include/libtorrent/aux_/packet_pool.hpp).
                    if let Some(arena) = &self.arena {
                        // Piece-frame special case: a full-size
                        // piece body is 9B (id+index+begin) + ≤16KiB block
                        // = ≤16,393B — 9 bytes OVER the 16,384 main bucket,
                        // so the whole-body lease below would take the
                        // unbudgeted heap fallback on the dominant wire
                        // shape; downstream cell adoption then holds
                        // that malloc allocation until the piece writes out
                        // (musl mallocng never returns the size class — the
                        // RSS retention the adversarial review flagged).
                        // Leasing ONLY the block payload restores the
                        // budgeted pooled mmap block (the block-arena
                        // semantics)
                        // with zero placement copies kept: the 9-byte
                        // header parses straight from the read buffer and
                        // never enters a lease. Oversized blocks (hostile /
                        // non-standard, rejected by the store layer anyway)
                        // keep the generic path below.
                        if need >= 9
                            && src[0] == MessageId::Piece as u8
                            && need - 9 <= taiji_io::block_arena::BLOCK_SIZE
                        {
                            let index = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
                            let begin = u32::from_be_bytes([src[5], src[6], src[7], src[8]]);
                            let block_len = need - 9;
                            let mut lease = arena.lease(block_len);
                            lease.as_mut_slice()[..block_len].copy_from_slice(&src[9..need]);
                            src.advance(need);
                            self.state = FrameState::Idle;
                            let block = lease.freeze(block_len);
                            return Ok(Some(Message::Piece {
                                index,
                                begin,
                                block,
                            }));
                        }
                        let mut lease = arena.lease(need);
                        lease.as_mut_slice()[..need].copy_from_slice(&src[..need]);
                        src.advance(need);
                        self.state = FrameState::Idle;
                        let body = lease.freeze(need);
                        return Message::decode_body_from(body).map(Some);
                    }
                    // Frozen-body zero-copy decode: piece/bitfield/extended
                    // payloads held as Bytes::slice, the read buffer shared
                    // with the message by refcount (the old borrowed-&body
                    // form forced a copy_from_slice per 16KiB block). Kept
                    // when the pool is off (default FrameCodec::default /
                    // BH_BLOCK_ARENA=0).
                    let body = src.split_to(need).freeze();
                    self.state = FrameState::Idle;
                    return Message::decode_body_from(body).map(Some);
                }
            }
        }
    }
}

impl tokio_util::codec::Encoder<Message> for FrameCodec {
    type Error = PeerWireError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item.encode());
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod ext_frame_tests {
    use super::*;
    use tokio_util::codec::Decoder as _;

    /// BEP-6 fast ext frames: exact byte vectors + roundtrip.
    #[test]
    fn fast_ext_frames() {
        // suggest(0x0D): len=5, id, index.
        let sug = Message::Suggest { index: 7 };
        let enc = sug.encode();
        assert_eq!(
            enc.as_ref(),
            &[0, 0, 0, 5, 0x0D, 0, 0, 0, 7],
            "suggest exact bytes (BEP6)"
        );
        assert_eq!(
            Message::decode_body(&enc[4..]).unwrap_or_else(|e| panic!("{e:?}")),
            sug
        );
        // have-all(0x0E) / have-none(0x0F): len=1, no payload.
        assert_eq!(Message::HaveAll.encode().as_ref(), &[0, 0, 0, 1, 0x0E]);
        assert_eq!(Message::HaveNone.encode().as_ref(), &[0, 0, 0, 1, 0x0F]);
        // allowed-fast(0x11): len=5, id, index.
        let af = Message::AllowedFast { index: 0xDEAD };
        assert_eq!(af.encode().as_ref(), &[0, 0, 0, 5, 0x11, 0, 0, 0xDE, 0xAD]);
        assert_eq!(
            Message::decode_body(&af.encode()[4..]).unwrap_or_else(|e| panic!("{e:?}")),
            af
        );
        // wrong payload length -> reject.
        assert!(Message::decode_body(&[0x0D, 0, 0]).is_err());
        assert!(Message::decode_body(&[0x0E, 1]).is_err());
    }

    /// BEP-52 hash request: 49B payload (root 32 + four 4B big-endian
    /// fields) + MUST checks.
    #[test]
    fn hash_request_frame_and_musts() {
        let root = [0xABu8; 32];
        let req = Message::HashRequest {
            root,
            base: 0,
            index: 8,
            length: 4,
            proof: 2,
        };
        let enc = req.encode();
        assert_eq!(enc.len(), 4 + 49, "frame length = 4 + (1 + 32 + 4*4) = 53");
        assert_eq!(&enc[4..5], &[21]);
        assert_eq!(&enc[5..37], &root[..]);
        // index is a multiple of length (8 = 2*4); fields big-endian
        // (payload from id).
        assert_eq!(&enc[41..45], &[0, 0, 0, 8], "index big-endian");
        assert_eq!(&enc[45..49], &[0, 0, 0, 4], "length big-endian");
        let back = Message::decode_body(&enc[4..]).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(back, req);

        let req_of = |index: u32, length: u32| Message::HashRequest {
            root,
            base: 0,
            index,
            length,
            proof: 0,
        };
        // MUST: length < 2 rejects.
        assert!(
            Message::decode_body(&strip(&req_of(8, 1))).is_err(),
            "length=1 violates the MUST"
        );
        // MUST: non-power-of-two length rejects.
        assert!(
            Message::decode_body(&strip(&req_of(0, 3))).is_err(),
            "length=3 is not a power of 2"
        );
        // MUST: index not a multiple of length rejects.
        assert!(
            Message::decode_body(&strip(&req_of(3, 4))).is_err(),
            "index=3 is not a multiple of 4"
        );
        // wrong payload length rejects.
        assert!(Message::decode_body(&[21; 20]).is_err());
        // SHOULD <=512 not enforced (nothing beyond MUSTs rejects).
        assert!(
            Message::decode_body(&strip(&req_of(0, 1024))).is_ok(),
            "length=1024 is SHOULD-only, admitted"
        );
    }

    /// BEP-52 hashes: count = length + max(0, proof-(log2(length)-1)).
    #[test]
    fn hashes_frame_count_rule() {
        let root = [0x11u8; 32];
        // length=4, proof=2 -> log2(4)-1=1 layer omitted -> count 4+1=5.
        let hashes = vec![[1u8; 32]; 5];
        let m = Message::Hashes {
            root,
            base: 0,
            index: 0,
            length: 4,
            proof: 2,
            hashes: hashes.clone(),
        };
        let enc = m.encode();
        assert_eq!(enc.len(), 4 + 49 + 32 * 5, "prefix = 1 + 48 + 32n");
        assert_eq!(
            Message::decode_body(&enc[4..]).unwrap_or_else(|e| panic!("{e:?}")),
            m,
            "roundtrip (including the proof-omission rule count)"
        );
        // count mismatch -> malformed reject (6 hashes sent, spec says 5).
        let mut bad = enc[4..].to_vec();
        bad.extend_from_slice(&[0u8; 32]);
        assert!(
            Message::decode_body(&bad).is_err(),
            "one extra hash must be rejected"
        );
        // length=2, proof=0 -> nothing omitted -> count 2.
        let two = Message::Hashes {
            root,
            base: 1,
            index: 2,
            length: 2,
            proof: 0,
            hashes: vec![[2u8; 32]; 2],
        };
        assert!(Message::decode_body(&two.encode()[4..]).is_ok());
    }

    /// hash reject: payload same as request (BEP-52).
    #[test]
    fn hash_reject_frame() {
        let r = Message::HashReject {
            root: [9u8; 32],
            base: 1,
            index: 4,
            length: 2,
            proof: 1,
        };
        let enc = r.encode();
        assert_eq!(enc[4], 23);
        assert_eq!(enc.len(), 4 + 49);
        assert_eq!(
            Message::decode_body(&enc[4..]).unwrap_or_else(|e| panic!("{e:?}")),
            r
        );
        // reject also gets the MUST checks (malformed length rejects).
        let bad = Message::HashReject {
            root: [9u8; 32],
            base: 1,
            index: 4,
            length: 5,
            proof: 1,
        };
        assert!(Message::decode_body(&strip(&bad)).is_err());
    }

    /// Hardening regression: u32 arithmetic overflow in `hashes_count` —
    /// with length=2 and proof=0xFFFFFFFF, `length +
    /// proof.saturating_sub(omitted)` used to overflow: a remote panic on
    /// debug builds (one 80-byte frame killed the connection task) and a
    /// silent wraparound past the BEP-52 count MUST on release. Now proof >
    /// 32 is rejected decoder-side; the derivation saturates for any
    /// input.
    #[test]
    fn hashes_count_overflow_and_proof_domain() {
        // decoder side: proof domain cap (u32 length domain tree depth
        // <=31, cap 32).
        let fields = |proof: u32| {
            let mut payload = [0u8; 48];
            payload[..32].fill(0xAB);
            payload[40..44].copy_from_slice(&2u32.to_be_bytes()); // length
            payload[44..48].copy_from_slice(&proof.to_be_bytes());
            payload
        };
        let mut ok_frame = vec![22u8];
        ok_frame.extend_from_slice(&fields(32));
        ok_frame.extend_from_slice(&[[7u8; 32]; 34].concat());
        assert!(
            Message::decode_body(&ok_frame).is_ok(),
            "proof=32 (at the cap) must be admitted"
        );
        let mut bad_frame = vec![22u8];
        bad_frame.extend_from_slice(&fields(u32::MAX));
        bad_frame.extend_from_slice(&[[7u8; 32]; 8].concat());
        assert!(
            matches!(
                Message::decode_body(&bad_frame),
                Err(PeerWireError::InvalidPayload { id: 22, .. })
            ),
            "proof=u32::MAX must be rejected as a malformed frame (never enters the count derivation)"
        );
        // request/reject get the same proof-domain check.
        let mut req = vec![21u8];
        req.extend_from_slice(&fields(u32::MAX));
        assert!(Message::decode_body(&req).is_err());
        // derivation: total for any input, saturating, never wrapping
        // (public form, reused by peer-serving defensive checks).
        assert_eq!(
            hashes_count_for(2, u32::MAX),
            u32::MAX,
            "length=2, proof=u32::MAX: saturates (used to debug-panic / release-wrap)"
        );
        assert_eq!(
            hashes_count_for(2, 32),
            34,
            "normal in-cap derivation: 2 + 32"
        );
        assert_eq!(
            hashes_count_for(u32::MAX / 2 + 1, u32::MAX),
            u32::MAX,
            "large length (2^31) + large proof: saturates"
        );
    }

    /// Zero-copy decode entry: `decode_body_from` equals `decode_body` for
    /// all ids (same dispatch body; `decode_body` = copy + delegate). Piece
    /// frame payload content is byte-identical — block data flows onward
    /// via refcounted `Bytes::slice` (frame decode -> peer -> engine
    /// transit -> pipeline zero-copy chain).
    #[test]
    fn decode_body_from_equivalent_to_decode_body() {
        // piece (hot-path id): payload >= 8B with block data.
        let piece = Message::Piece {
            index: 3,
            begin: 16384,
            block: Bytes::from(vec![0xA5u8; 4096]),
        };
        // bitfield / extended (the two sliced-payload kinds).
        let bitfield = Message::Bitfield {
            bits: Bytes::from(vec![0b1010_0000, 0b0000_0011]),
        };
        let extended = Message::Extended {
            ext_id: 1,
            payload: Bytes::from(b"d1:md11:ut_metadatai2eee".to_vec()),
        };
        for msg in [piece, bitfield, extended] {
            let frame = msg.encode();
            let body = frame[4..].to_vec();
            let by_ref = Message::decode_body(&body).unwrap_or_else(|e| panic!("{e:?}"));
            let by_owned =
                Message::decode_body_from(Bytes::from(body)).unwrap_or_else(|e| panic!("{e:?}"));
            assert_eq!(by_ref, by_owned, "all ids equivalent ({:?})", msg.id());
            assert_eq!(by_owned, msg, "roundtrip ({:?})", msg.id());
        }
        // malformed cases equal too: piece payload < 8B rejects.
        let short = vec![7u8, 0, 0, 0, 1];
        assert!(Message::decode_body(&short).is_err());
        assert!(Message::decode_body_from(Bytes::from(short)).is_err());
    }

    /// Pooled decode path: with an arena the frame body is copied into a
    /// leased block and decodes byte-identically to the frozen-shared path;
    /// after the message is dropped (refcount zero) the block returns to
    /// the pool — pool levels are conserved and re-decodes hit the free
    /// list (reuse works). Over-main-bucket frames (bitfield > 16KiB) fall
    /// back to direct allocation without panicking, with an observable
    /// counter.
    #[test]
    fn arena_decode_equivalent_and_returns_blocks_to_pool() {
        let arena = std::sync::Arc::new(taiji_io::block_arena::BlockArena::new(64 * 1024));
        let mut codec = FrameCodec::with_arena(std::sync::Arc::clone(&arena));
        let piece = Message::Piece {
            index: 3,
            begin: 16384,
            block: Bytes::from(vec![0xA5u8; 4096]),
        };
        let frame = piece.encode();
        let mut src = BytesMut::from(&frame[..]);
        let decoded = codec.decode(&mut src).unwrap_or_else(|e| panic!("{e:?}"));
        let msg = decoded.unwrap_or_else(|| panic!("frame ready"));
        assert_eq!(
            msg, piece,
            "the pooled path decodes byte-identically to the original message"
        );
        assert!(
            src.is_empty(),
            "the frame body was consumed by advance (no frozen shared buffer)"
        );
        // while the message lives its block is leased; drop returns it.
        assert_eq!(arena.readout().outstanding_blocks, 1);
        drop(msg);
        assert_eq!(arena.readout().outstanding_blocks, 0);
        // re-decode: hits the free list (reuse works).
        let mut src = BytesMut::from(&frame[..]);
        let msg = codec
            .decode(&mut src)
            .unwrap_or_else(|e| panic!("{e:?}"))
            .unwrap_or_else(|| panic!("frame ready"));
        assert_eq!(msg, piece);
        assert_eq!(arena.readout().lease_hits_total, 1);
        // control frames use the 1KiB side bucket (have).
        let have = Message::Have { index: 7 };
        let mut src = BytesMut::from(&have.encode()[..]);
        let msg = codec
            .decode(&mut src)
            .unwrap_or_else(|e| panic!("{e:?}"))
            .unwrap_or_else(|| panic!("frame ready"));
        assert_eq!(msg, have);
        // over-main-bucket frame: direct-allocation fallback, equivalent
        // decode.
        let big = Message::Bitfield {
            bits: Bytes::from(vec![0xFFu8; 20 * 1024]),
        };
        let mut src = BytesMut::from(&big.encode()[..]);
        let msg = codec
            .decode(&mut src)
            .unwrap_or_else(|e| panic!("{e:?}"))
            .unwrap_or_else(|| panic!("frame ready"));
        assert_eq!(msg, big);
        assert_eq!(
            arena.readout().alloc_fallback_total,
            1,
            "over-bucket frames counted as direct allocation"
        );
        drop(msg);
    }

    fn strip(m: &Message) -> Vec<u8> {
        let e = m.encode();
        e[4..].to_vec()
    }

    /// The DOMINANT wire shape: a full-size piece frame (9B id+index+begin
    /// + 16,384B block = 16,393B body) must decode through a budgeted
    /// pooled block, not the unbudgeted over-bucket heap fallback. Pre-fix
    /// the whole-body lease (16,393 > the 16,384 main bucket) fell to
    /// `fallback_lease`'s Heap form, and the cell adoption then held that
    /// malloc allocation until the piece wrote out (musl mallocng never
    /// returns the size class — the RSS retention the review flagged).
    /// Post-fix the block payload leases the main bucket directly (pooled
    /// mmap, budget-accounted) and the 9-byte header parses from the read
    /// buffer.
    #[test]
    fn full_size_piece_frame_decodes_through_pooled_block() {
        let arena = std::sync::Arc::new(taiji_io::block_arena::BlockArena::new(1 << 20));
        let mut codec = FrameCodec::with_arena(std::sync::Arc::clone(&arena));
        let piece = Message::Piece {
            index: 3021,
            begin: 16384,
            block: Bytes::from(vec![0x5Au8; taiji_io::block_arena::BLOCK_SIZE]),
        };
        let frame = piece.encode();
        let mut src = BytesMut::from(&frame[..]);
        let decoded = codec
            .decode(&mut src)
            .unwrap_or_else(|e| panic!("{e:?}"))
            .unwrap_or_else(|| panic!("frame ready"));
        assert_eq!(
            decoded, piece,
            "the dedicated path decodes byte-identically to the original message"
        );
        assert!(src.is_empty(), "the frame body was consumed by advance");
        let r = arena.readout();
        assert_eq!(
            r.alloc_fallback_total, 0,
            "a full-size piece must not take the heap fallback (regression anchor: this count was 1 pre-fix)"
        );
        assert!(
            r.lease_hits_total + r.alloc_fresh_total >= 1,
            "the block payload rides a pool lease"
        );
        assert_eq!(r.outstanding_blocks, 1, "leased while the message is held");
        drop(decoded);
        assert_eq!(arena.readout().outstanding_blocks, 0, "return guard");
        // A short piece (sub-block tail) rides the same special path.
        let tail = Message::Piece {
            index: 3023,
            begin: 0,
            block: Bytes::from(vec![0xC3u8; 1000]),
        };
        let mut src = BytesMut::from(&tail.encode()[..]);
        let decoded = codec
            .decode(&mut src)
            .unwrap_or_else(|e| panic!("{e:?}"))
            .unwrap_or_else(|| panic!("frame ready"));
        assert_eq!(decoded, tail);
        assert_eq!(
            arena.readout().alloc_fallback_total,
            0,
            "the sub-block tail likewise skips the heap fallback"
        );
    }
}

#[cfg(test)]
mod bt_frame_capacity {
    use super::*;

    /// `encoded_len` matches `encode` bit-for-bit (exact-allocation anchor
    /// — variable bodies (bitfield/piece/hashes/extended) and all fixed
    /// small frames).
    #[test]
    fn encoded_len_matches_encode_exactly() {
        let cases: Vec<Message> = vec![
            Message::KeepAlive,
            Message::Choke,
            Message::HaveAll,
            Message::Have { index: 7 },
            Message::Suggest { index: 9 },
            Message::AllowedFast { index: 3 },
            Message::Request {
                index: 1,
                begin: 2,
                length: 16 * 1024,
            },
            Message::Cancel {
                index: 1,
                begin: 2,
                length: 3,
            },
            Message::Reject {
                index: 1,
                begin: 2,
                length: 3,
            },
            Message::Port { port: 6881 },
            Message::Bitfield {
                bits: Bytes::from_static(&[0b1010_0001, 0x00, 0xFF]),
            },
            Message::Piece {
                index: 4,
                begin: 0,
                block: Bytes::from(vec![0u8; 16 * 1024]),
            },
            Message::HashRequest {
                root: [1u8; 32],
                base: 0,
                index: 0,
                length: 2,
                proof: 1,
            },
            Message::Hashes {
                root: [2u8; 32],
                base: 0,
                index: 0,
                length: 2,
                proof: 1,
                hashes: vec![[3u8; 32]; 5],
            },
            Message::HashReject {
                root: [1u8; 32],
                base: 0,
                index: 0,
                length: 2,
                proof: 1,
            },
            Message::Extended {
                ext_id: 0,
                payload: Bytes::from_static(b"d1:md11:ut_metadatai1ee1:pi6881ee"),
            },
        ];
        for (i, m) in cases.iter().enumerate() {
            assert_eq!(
                m.encoded_len(),
                m.encode().len(),
                "case #{i} estimated capacity must match bit-for-bit"
            );
        }
    }
}

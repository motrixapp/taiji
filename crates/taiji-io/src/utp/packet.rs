//! uTP (BEP-29) v1 packet header and extension codec.
//!
//! Big-endian 20-byte v1 header encode/decode, the extension chain
//! (`{next, len}` entries; unknown extensions are skipped by advancing len
//! bytes), and the Selective ACK bitmap. Type occupies the high nibble and
//! version the low nibble of byte 0 (the current layout after the BEP-29
//! Post-History "type and version were swapped" fix). All protocol facts
//! cite BEP-29 section names — aria2 has no uTP implementation, so BEP-29
//! is the sole reference. The Selective ACK extension type value 1 is the
//! de-facto libutp value (BEP-29 names the extension but gives no number).
//!
//! Hard invariants: `decode` returns Ok or Err for any input (never panics);
//! Selective ACK len must be >= 4 and a multiple of 4; the bitmap is in
//! reverse byte order within bytes and bit i covers ack_nr + 2 + i.
//!
//! Upstream anchor mapping (BEP-29 quotes and header diagram):
//! docs/design/io.md
//!
use bytes::{BufMut, BytesMut};

use super::UtpError;

/// v1 header length (BEP-29 "header format": 20-byte layout).
pub const HEADER_LEN: usize = 20;
/// Protocol version (BEP-29 "version": "The current version is 1.").
pub const VERSION: u8 = 1;
/// Selective ACK extension type value (see the module doc endnote: BEP-29
/// gives no number; 1 is the de-facto libutp value).
pub const EXT_SELECTIVE_ACK: u8 = 1;

/// Packet type (the five BEP-29 "type" values, quoted per variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// ST_DATA = 0: "regular data packet... An ST_DATA packet always has a
    /// data payload."
    Data = 0,
    /// ST_FIN = 1: "Finalize the connection... The socket records this
    /// sequence number as eof_pkt."
    Fin = 1,
    /// ST_STATE = 2: "Used to transmit an ACK with no data. Packets that
    /// don't include any payload do not increase the seq_nr."
    State = 2,
    /// ST_RESET = 3: "Terminate connection forcefully... The remote host does
    /// not have any state for this connection."
    Reset = 3,
    /// ST_SYN = 4: "Connect SYN... The sequence number is initialized to 1...
    /// all subsequent packets... are sent with the connection ID + 1."
    Syn = 4,
}

impl PacketType {
    /// High-nibble value (BEP-29 "header format": type is the high 4 bits of byte 0).
    pub fn to_nibble(self) -> u8 {
        self as u8
    }

    /// Decode from the high nibble (only 0-4 legal; BEP-29 "type" is exhaustive).
    pub fn from_nibble(n: u8) -> Option<Self> {
        match n {
            0 => Some(PacketType::Data),
            1 => Some(PacketType::Fin),
            2 => Some(PacketType::State),
            3 => Some(PacketType::Reset),
            4 => Some(PacketType::Syn),
            _ => None,
        }
    }
}

/// v1 header (fields map one-to-one to BEP-29 "header format" and its subsections).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Packet type (BEP-29 "type").
    pub packet_type: PacketType,
    /// First extension type, 0 = none (BEP-29 "extension").
    pub extension: u8,
    /// Connection ID. One per socket per direction; the initiator picks the
    /// ID, "the return path has the same ID + 1" (BEP-29 "connection_id").
    pub connection_id: u16,
    /// Microsecond part of the send instant (BEP-29 "timestamp_microseconds").
    pub timestamp_micros: u32,
    /// Peer-echoed latest one-way delay measurement; with no sample it
    /// "must be set to 0" (BEP-29 "timestamp_difference_microseconds").
    pub timestamp_diff_micros: u32,
    /// Peer-advertised receive window in bytes (BEP-29 "wnd_size": "This is
    /// 32 bits wide and specified in bytes.").
    pub wnd_size: u32,
    /// This packet's sequence number, counted per packet not per byte (BEP-29 "seq_nr").
    pub seq_nr: u16,
    /// Last sequence number the sender received in the other direction (BEP-29 "ack_nr").
    pub ack_nr: u16,
}

impl Header {
    /// Big-endian encode into `out` (BEP-29 "header format": "All fields are
    /// in network byte order (big endian).").
    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u8((self.packet_type.to_nibble() << 4) | VERSION);
        out.put_u8(self.extension);
        out.put_u16(self.connection_id);
        out.put_u32(self.timestamp_micros);
        out.put_u32(self.timestamp_diff_micros);
        out.put_u32(self.wnd_size);
        out.put_u16(self.seq_nr);
        out.put_u16(self.ack_nr);
    }

    /// Encode into a standalone `BytesMut`.
    pub fn to_bytes(&self) -> BytesMut {
        let mut out = BytesMut::with_capacity(HEADER_LEN);
        self.encode(&mut out);
        out
    }
}

/// Selective ACK bitmap view (BEP-29 "Selective ACK").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sack<'a> {
    /// ack_nr of the packet carrying this extension (bitmap base: first bit = ack_nr + 2).
    pub base_ack_nr: u16,
    /// Raw bitmap bytes (length >= 4 and a multiple of 4, validated at decode).
    pub mask: &'a [u8],
}

impl Sack<'_> {
    /// Whether the bitmap acknowledges sequence number `seq`. Bit i (from
    /// the first mask bit) covers `base_ack_nr + 2 + i`; bit i lives in byte
    /// `i/8` at bit `i%8` counting from the LSB (BEP-29 "Selective ACK"
    /// "reverse byte order" layout). Sequence numbers beyond the bitmap
    /// count as unacknowledged (BEP-29: "Bits that are outside of the send
    /// window are ignored" — consumers treat this as false).
    pub fn acked(&self, seq: u16) -> bool {
        // Bit 0 <-> ack_nr + 2, so bit index = seq - (ack_nr + 2)
        // (seq_offset yields seq - base - 1, hence base ack_nr + 1).
        let Some(idx) = seq_offset(self.base_ack_nr.wrapping_add(1), seq) else {
            return false;
        };
        let byte = idx / 8;
        if byte >= self.mask.len() {
            return false;
        }
        self.mask[byte] & (1 << (idx % 8)) != 0
    }
}

/// `seq - base` as a mod-2^16 distance; returns `Some` only while `seq`
/// stays in the forward wrap window after `base` (i16 signed distance).
/// uTP seq_nr is a u16 wraparound space (BEP-29 "seq_nr"); ordering uses
/// the i16 signed distance.
fn seq_offset(base: u16, seq: u16) -> Option<usize> {
    let d = seq.wrapping_sub(base) as i16;
    if d > 0 { Some((d - 1) as usize) } else { None }
}

/// Wraparound compare: is `a` strictly after `b` (u16 space, BEP-29 "seq_nr").
pub fn seq_gt(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) > 0
}

/// Wraparound compare: is `a` after or equal to `b`.
pub fn seq_ge(a: u16, b: u16) -> bool {
    a == b || seq_gt(a, b)
}

/// Wraparound compare: is `a` strictly before `b`.
pub fn seq_lt(a: u16, b: u16) -> bool {
    seq_gt(b, a)
}

/// Wraparound compare: is `a` before or equal to `b`.
pub fn seq_le(a: u16, b: u16) -> bool {
    seq_ge(b, a)
}

/// Decoded packet: header + sack extension (if present) + payload slice.
#[derive(Debug)]
pub struct Packet<'a> {
    /// v1 header (20 bytes, BEP-29 "header format").
    pub header: Header,
    /// Recognized Selective ACK extension; unknown extensions are skipped
    /// per BEP-29 and not surfaced.
    pub sack: Option<Sack<'a>>,
    /// Empty for packet types other than ST_DATA/ST_FIN.
    pub payload: &'a [u8],
}

/// Decode a v1 packet (header + extension chain + payload). Total function:
///
/// any input yields Ok or Err, never a panic.
///
/// Validation (all per BEP-29):
/// - length >= 20 ("header format");
/// - version == 1 ("version"); type in 0-4 ("type");
/// - extension chain: each entry is `{next, len}` (two bytes) plus len
///   body bytes; Selective ACK len "must be at least 4, and in multiples
///   of 4" ("Selective ACK"); unknown extensions are skipped ("extension").
pub fn decode(buf: &[u8]) -> Result<Packet<'_>, UtpError> {
    if buf.len() < HEADER_LEN {
        return Err(super::UtpError::Truncated);
    }
    let packet_type =
        PacketType::from_nibble(buf[0] >> 4).ok_or(super::UtpError::Type(buf[0] >> 4))?;
    let version = buf[0] & 0x0f;
    if version != VERSION {
        return Err(super::UtpError::Version(version));
    }
    let header = Header {
        packet_type,
        extension: buf[1],
        connection_id: u16::from_be_bytes([buf[2], buf[3]]),
        timestamp_micros: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        timestamp_diff_micros: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        wnd_size: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
        seq_nr: u16::from_be_bytes([buf[16], buf[17]]),
        ack_nr: u16::from_be_bytes([buf[18], buf[19]]),
    };

    // Extension chain walk (BEP-29 "extension"): next==0 terminates; the
    // iteration cap defends against crafted self-referencing chains (fuzz
    // surface); over the cap is malformed.
    let mut ext = header.extension;
    let mut off = HEADER_LEN;
    let mut sack: Option<Sack<'_>> = None;
    let mut hops = 0u8;
    while ext != 0 {
        hops += 1;
        if hops > 32 || off + 2 > buf.len() {
            return Err(super::UtpError::Extension);
        }
        let next = buf[off];
        let len = buf[off + 1] as usize;
        let body = off + 2;
        if body + len > buf.len() {
            return Err(super::UtpError::Truncated);
        }
        if ext == EXT_SELECTIVE_ACK {
            // len >= 4 and a multiple of 4 (BEP-29 "Selective ACK", see module doc).
            if len < 4 || !len.is_multiple_of(4) {
                return Err(super::UtpError::Extension);
            }
            sack = Some(Sack {
                base_ack_nr: header.ack_nr,
                mask: &buf[body..body + len],
            });
        }
        // Unknown extension: advance len bytes only (BEP-29 "extension":
        // "Unknown extensions can be skipped by simply advancing len
        // bytes.").
        off = body + len;
        ext = next;
    }

    Ok(Packet {
        header,
        sack,
        payload: &buf[off..],
    })
}

/// Assemble a packet: header + extension + payload (the inverse of
/// [`decode`]).
///
/// A non-empty `sack_mask` writes the Selective ACK extension (len = mask
/// byte count, must be >= 4 and a multiple of 4 — caller's obligation; see
/// [`build_sack_mask`] for a conforming constructor.
pub fn encode(header: &Header, sack_mask: Option<&[u8]>, payload: &[u8]) -> BytesMut {
    let mut out =
        BytesMut::with_capacity(HEADER_LEN + 2 + sack_mask.map_or(0, <[u8]>::len) + payload.len());
    let ext = if sack_mask.is_some() {
        EXT_SELECTIVE_ACK
    } else {
        0
    };
    Header {
        extension: ext,
        ..*header
    }
    .encode(&mut out);
    if let Some(mask) = sack_mask {
        // First chain entry (the header extension field is already 1):
        // next=0 terminates the chain, then len (BEP-29 "extension" two-byte
        // layout). The len field is one byte: a mask longer than 255 would
        // be silently truncated by the `as u8` cast and desync the peer's
        // extension walk — pinned here (the local `sack_max_bytes` cap
        // keeps production masks far below it).
        debug_assert!(
            mask.len() <= 255,
            "SACK mask {} bytes exceeds the u8 len field",
            mask.len()
        );
        out.put_u8(0);
        out.put_u8(mask.len() as u8);
        out.put_slice(mask);
    }
    out.put_slice(payload);
    out
}

/// Build a Selective ACK bitmap from the set of out-of-order received sequence numbers.
///
/// Bit i <-> `ack_nr + 2 + i` (BEP-29 "Selective ACK": "The first bit in the
/// mask therefore represents ack_nr + 2."). Bitmap length is >= 4 bytes and
/// a multiple of 4 (same section: "at least 32 bits, in multiples of 32
/// bits"), capped at `max_bytes` (local parameter; BEP-29: "The bitmask is
/// not limited to 32 bits but can be of any size."). Returns `None` when no
/// bit is set (same section: "The selective ACK is only sent when at least
/// one sequence number was skipped in the received stream.").
pub fn build_sack_mask(ack_nr: u16, received: &[u16], max_bytes: usize) -> Option<Vec<u8>> {
    debug_assert!(max_bytes >= 4 && max_bytes.is_multiple_of(4));
    let cap_bits = max_bytes.saturating_mul(8);
    let mut mask = vec![0u8; max_bytes];
    for &seq in received {
        if !seq_gt(seq, ack_nr) {
            continue;
        }
        // Bit index = seq - (ack_nr + 2) (forward mod-2^16 distance - 1).
        let Some(idx) = seq_offset(ack_nr.wrapping_add(1), seq) else {
            continue;
        };
        if idx >= cap_bits {
            continue;
        }
        mask[idx / 8] |= 1 << (idx % 8);
    }
    // Never send an all-zero bitmap (BEP-29: only on skipped numbers).
    if mask.iter().all(|&b| b == 0) {
        return None;
    }
    // Truncate to the smallest multiple of 4 bytes covering set bits (BEP-29: >=4, multiples of 4).
    let mut len = max_bytes;
    while len > 4 && mask[len - 4..len].iter().all(|&b| b == 0) {
        len -= 4;
    }
    mask.truncate(len);
    Some(mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ---- Vector tests: each cites its BEP-29 clause ----

    /// BEP-29 "header format" layout vector: field offsets laid out by hand.
    #[test]
    fn header_layout_vector() {
        let h = Header {
            packet_type: PacketType::Data,
            extension: 0,
            connection_id: 0x0102,
            timestamp_micros: 0x0304_0506,
            timestamp_diff_micros: 0x0708_090a,
            wnd_size: 0x0b0c_0d0e,
            seq_nr: 0x1112,
            ack_nr: 0x1314,
        };
        let b = h.to_bytes();
        // b0: type high nibble | ver low nibble (current layout after the
        // BEP-29 Post-History "type and version were swapped" fix).
        assert_eq!(b[0], 0x01);
        assert_eq!(b[1], 0x00, "extension=0：BEP29 '0 means no extension'");
        assert_eq!(&b[2..4], &[0x01, 0x02], "connection_id big-endian u16");
        assert_eq!(
            &b[4..8],
            &[0x03, 0x04, 0x05, 0x06],
            "timestamp_micros big-endian u32"
        );
        assert_eq!(
            &b[8..12],
            &[0x07, 0x08, 0x09, 0x0a],
            "timestamp_difference_microseconds big-endian u32"
        );
        assert_eq!(
            &b[12..16],
            &[0x0b, 0x0c, 0x0d, 0x0e],
            "wnd_size big-endian u32 ('32 bits wide and specified in bytes')"
        );
        assert_eq!(&b[16..18], &[0x11, 0x12], "seq_nr big-endian u16");
        assert_eq!(&b[18..20], &[0x13, 0x14], "ack_nr big-endian u16");
        assert_eq!(b.len(), HEADER_LEN, "BEP29 header format: 20 bytes");
    }

    /// Encode/decode roundtrip ("All fields are in network byte order (big endian)").
    #[test]
    fn header_roundtrip() {
        let h = Header {
            packet_type: PacketType::Syn,
            extension: 0,
            connection_id: 0xabcd,
            timestamp_micros: 0x1234_5678,
            timestamp_diff_micros: 0,
            wnd_size: 0x0001_0000,
            seq_nr: 1,
            ack_nr: 0xf0f0,
        };
        let wire = h.to_bytes();
        let p = decode(&wire).ok_or_fail();
        assert_eq!(p.header, h);
        assert!(p.sack.is_none());
        assert!(p.payload.is_empty());
    }

    /// Nibble encoding of the five packet types (BEP-29 "type": ST_DATA=0..ST_SYN=4).
    #[test]
    fn packet_type_values() {
        for (n, ty) in [
            (0u8, PacketType::Data),
            (1, PacketType::Fin),
            (2, PacketType::State),
            (3, PacketType::Reset),
            (4, PacketType::Syn),
        ] {
            let h = Header {
                packet_type: ty,
                extension: 0,
                connection_id: 0,
                timestamp_micros: 0,
                timestamp_diff_micros: 0,
                wnd_size: 0,
                seq_nr: 0,
                ack_nr: 0,
            };
            let b = h.to_bytes();
            assert_eq!(
                b[0],
                (n << 4) | 1,
                "type={n} in the high nibble, ver=1 in the low nibble"
            );
            assert_eq!(decode(&b).ok_or_fail().header.packet_type, ty);
        }
    }

    /// Truncated packets rejected (BEP-29 "header format": fixed 20B header).
    #[test]
    fn truncated_rejected() {
        let h = Header {
            packet_type: PacketType::Data,
            extension: 0,
            connection_id: 0,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: 0,
            seq_nr: 0,
            ack_nr: 0,
        };
        let full = h.to_bytes();
        for n in 0..HEADER_LEN {
            assert!(
                matches!(decode(&full[..n]), Err(UtpError::Truncated)),
                "{n} bytes must be judged truncated"
            );
        }
    }

    /// Version must be 1 (BEP-29 "version": "The current version is 1.").
    #[test]
    fn version_must_be_1() {
        let mut b = vec![0u8; HEADER_LEN];
        b[0] = 0x02; // ST_DATA | ver=2
        assert!(matches!(decode(&b), Err(UtpError::Version(2))));
        b[0] = 0x00; // ver=0
        assert!(matches!(decode(&b), Err(UtpError::Version(0))));
    }

    /// Undefined types rejected (BEP-29 "type" defines only 0-4).
    #[test]
    fn undefined_type_rejected() {
        let mut b = vec![0u8; HEADER_LEN];
        b[0] = 0x51; // type=5 | ver=1
        assert!(matches!(decode(&b), Err(UtpError::Type(5))));
        b[0] = 0xf1; // type=15
        assert!(matches!(decode(&b), Err(UtpError::Type(15))));
    }

    /// Selective ACK extension roundtrip (BEP-29 "Selective ACK" layout:
    /// after the header {next=0, len} + bitmap; len >= 4 and a multiple of 4).
    #[test]
    fn sack_extension_roundtrip() {
        let h = Header {
            packet_type: PacketType::State,
            extension: EXT_SELECTIVE_ACK,
            connection_id: 7,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: 0,
            seq_nr: 9,
            ack_nr: 100,
        };
        let mask = [0b0000_0101u8, 0, 0, 0b1000_0000]; // bits 0, 2, and 31 (bit7 of byte3)
        let mut wire = h.to_bytes();
        wire.extend_from_slice(&[0, 4]);
        wire.extend_from_slice(&mask);
        let p = decode(&wire).ok_or_fail();
        let sack = p.sack.ok_or_fail();
        assert_eq!(
            sack.base_ack_nr, 100,
            "bitmap base = the carrying packet's ack_nr"
        );
        // Bit i <-> ack_nr + 2 + i (BEP-29: "The first bit ... represents ack_nr + 2").
        assert!(sack.acked(102), "bit0 = ack_nr+2");
        assert!(sack.acked(104), "bit2 = ack_nr+4");
        assert!(!sack.acked(103), "bit1 not set");
        assert!(sack.acked(133), "bit31 = ack_nr+33 (across bytes)");
        assert!(!sack.acked(134), "beyond the bitmap = unacknowledged");
        assert!(
            !sack.acked(100),
            "ack_nr itself is outside the bitmap semantics (covered cumulatively)"
        );
        assert!(p.payload.is_empty());
    }

    /// Reverse byte order of the bitmap (BEP-29 "Selective ACK" layout
    /// diagram: "| 9 8 ... 3 2 | 17 ... 10 | 25 ... 18 | 33 ... 26 |" — the
    /// numbers are offsets added to ack_nr).
    #[test]
    fn sack_reverse_byte_order_diagram() {
        // BEP-29 diagram: first byte LSB=offset2 -> MSB=offset9; second byte
        // LSB=offset10 ...; fourth byte MSB=offset33.
        let mask = [0b1111_1111u8, 0b0000_0011, 0, 0b1000_0000];
        let sack = Sack {
            base_ack_nr: 50,
            mask: &mask,
        };
        for off in 2..=9 {
            assert!(
                sack.acked(50 + off),
                "first byte all ones: offset {off} (ack_nr+{off})"
            );
        }
        assert!(sack.acked(50 + 10), "second byte bit0 = offset 10");
        assert!(sack.acked(50 + 11), "second byte bit1 = offset 11");
        assert!(!sack.acked(50 + 12), "second byte bit2 not set");
        assert!(sack.acked(50 + 33), "fourth byte MSB = offset 33");
        assert!(!sack.acked(50 + 26), "fourth byte bit0 = offset 26 not set");
    }

    /// sack len validation: >= 4 and a multiple of 4 (BEP-29 "Selective ACK":
    /// "must be at least 4, and in multiples of 4").
    #[test]
    fn sack_len_validation() {
        let head = {
            let mut b = vec![0x21u8, 1]; // ST_STATE | ver1, ext=1
            b.extend_from_slice(&[0u8; 18]);
            b
        };
        // len=3: invalid.
        let mut b3 = head.clone();
        b3.extend_from_slice(&[0, 3, 0, 0, 0]);
        assert!(matches!(decode(&b3), Err(UtpError::Extension)));
        // len=5: not a multiple of 4.
        let mut b5 = head.clone();
        b5.extend_from_slice(&[0, 5, 0, 0, 0, 0, 0]);
        assert!(matches!(decode(&b5), Err(UtpError::Extension)));
        // len=8: legal and consumed.
        let mut b8 = head.clone();
        b8.extend_from_slice(&[0, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(decode(&b8).ok_or_fail().sack.is_some());
    }

    /// Unknown extension skipped + chain termination (BEP-29 "extension":
    /// "0 terminates the list", "Unknown extensions can be skipped by simply
    /// advancing len bytes.").
    #[test]
    fn unknown_extension_skipped() {
        // Chain: header ext=42 -> {next=1, len=3} -> {next=0, len=4}=sack terminates.
        let mut b = vec![0x21u8, 42]; // ST_STATE, ext=42 (undefined type)
        b.extend_from_slice(&[0u8; 18]); // ack_nr = 0 (sack base)
        b.extend_from_slice(&[1, 3, 0xde, 0xad, 0xbe]); // ext42: next=1, len=3
        b.extend_from_slice(&[0, 4, 0, 0, 0, 0x20]); // ext1(sack): next=0 ends, len=4, bit29 (bit5 of byte3)
        b.extend_from_slice(b"DATA"); // payload (ST_STATE shouldn't carry one, but the parser doesn't care)
        let p = decode(&b).ok_or_fail();
        let sack = p.sack.ok_or_fail();
        assert!(
            sack.acked(2 + 29),
            "sack extension recognized (bit29 <-> ack_nr(0)+2+29)"
        );
        assert!(!sack.acked(31 + 1), "adjacent bit not set");
        assert_eq!(p.payload, b"DATA", "unknown extension 42 skipped whole");
    }

    /// Extension chain truncation/malformation rejected.
    #[test]
    fn extension_chain_malformed() {
        // ext declares sack but the body is out of bounds.
        let mut b = vec![0x21u8, 1];
        b.extend_from_slice(&[0u8; 18]);
        b.extend_from_slice(&[0, 4, 0, 0]);
        assert!(matches!(decode(&b), Err(UtpError::Truncated)));
        // Self-referencing chain with len=0 and next!=0 -> caught by the iteration cap.
        let mut c = vec![0x21u8, 9];
        c.extend_from_slice(&[0u8; 18]);
        c.extend_from_slice(&[9, 0]);
        assert!(matches!(decode(&c), Err(UtpError::Extension)));
    }

    /// build_sack_mask: covers only out-of-order hits; all-zero is not sent;
    /// length is a multiple of 4.
    #[test]
    fn build_sack_mask_semantics() {
        // ack_nr=10, received 13, 14, 17 -> bits 1, 2, 5 (13=10+2+1 ...).
        let mask = build_sack_mask(10, &[13, 14, 17], 16).ok_or_fail();
        assert_eq!(
            mask.len(),
            4,
            "BEP29：at least 32 bits, multiples of 32 bits"
        );
        assert_eq!(mask[0], 0b0010_0110, "bit1(13), bit2(14), bit5(17)");
        let s = Sack {
            base_ack_nr: 10,
            mask: &mask,
        };
        assert!(s.acked(13) && s.acked(14) && s.acked(17));
        assert!(!s.acked(12), "gap bits (dropped packets) must not be set");
        // No skips (nothing out of order) -> not sent (BEP-29: "only sent
        // when at least one sequence number was skipped").
        assert!(build_sack_mask(10, &[], 16).is_none());
        assert!(
            build_sack_mask(10, &[11], 16).is_none(),
            "11 = the next in-order packet, not a skip"
        );
    }

    /// build_sack_mask: sequence wraparound (u16 wrap; BEP-29 "seq_nr" counts packets).
    #[test]
    fn build_sack_mask_wrapping() {
        let mask = build_sack_mask(0xfffe, &[0x0001, 0x0002], 16).ok_or_fail();
        let s = Sack {
            base_ack_nr: 0xfffe,
            mask: &mask,
        };
        assert!(s.acked(0x0001), "offset 1 after wrap");
        assert!(s.acked(0x0002), "offset 2 after wrap");
        assert!(!s.acked(0x0003));
    }

    /// Wraparound compare helpers form a total order (seq_gt/lt/ge/le agree across 0).
    #[test]
    fn seq_compare_wrapping_total_order() {
        assert!(seq_gt(1, 0) && seq_gt(0, 0xffff) && seq_gt(0x8000, 0x7fff));
        assert!(seq_lt(0xffff, 0) && seq_lt(0x7fff, 0x8000));
        assert!(seq_ge(5, 5) && seq_le(5, 5));
        assert!(seq_gt(5, 4) && !seq_gt(4, 5));
        // Consistent within the radius (+/-32767); the 0x8000-distance point
        // is undefined (i16 sign flip) and not asserted.
        assert!(seq_gt(0x7fff, 0) && seq_lt(0, 0x7fff));
    }

    /// Encode/decode with payload and sack together (encode and decode are inverses).
    #[test]
    fn encode_with_sack_and_payload_roundtrip() {
        let h = Header {
            packet_type: PacketType::State,
            extension: 0, // encode overwrites to 1
            connection_id: 3,
            timestamp_micros: 9,
            timestamp_diff_micros: 7,
            wnd_size: 1024,
            seq_nr: 4,
            ack_nr: 2,
        };
        let mask = build_sack_mask(2, &[5, 6], 16).ok_or_fail();
        let wire = encode(&h, Some(&mask), &[]);
        let p = decode(&wire).ok_or_fail();
        assert_eq!(p.header.extension, EXT_SELECTIVE_ACK);
        assert_eq!(p.header.connection_id, 3);
        assert_eq!(p.header.seq_nr, 4);
        assert!(p.sack.ok_or_fail().acked(5));
    }

    // proptest: encode/decode roundtrip identity for arbitrary field values
    // (BEP-29 "header format" inverse property; u16 wrap semantics covers
    // the wrap corners).
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1024))]

        #[test]
        fn header_roundtrip_arbitrary(
            ty_n in 0u8..=4,
            conn in any::<u16>(),
            ts in any::<u32>(),
            tsdiff in any::<u32>(),
            wnd in any::<u32>(),
            seq in any::<u16>(),
            ack in any::<u16>(),
        ) {
            let h = Header {
                packet_type: PacketType::from_nibble(ty_n).unwrap_or(PacketType::Data),
                extension: 0,
                connection_id: conn,
                timestamp_micros: ts,
                timestamp_diff_micros: tsdiff,
                wnd_size: wnd,
                seq_nr: seq,
                ack_nr: ack,
            };
            let wire = h.to_bytes();
            prop_assert_eq!(wire.len(), HEADER_LEN);
            let p = decode(&wire).ok_or_fail();
            prop_assert_eq!(p.header, h);
        }
    }

    // Test helper: Result -> value (equivalent under the clippy::unwrap_used
    // ban; panics with context on failure).
    trait UnwrapOk {
        type T;
        fn ok_or_fail(self) -> Self::T;
    }
    impl<T> UnwrapOk for Result<T, super::super::UtpError> {
        type T = T;
        fn ok_or_fail(self) -> T {
            match self {
                Ok(v) => v,
                Err(e) => panic!("decode failed: {e}"),
            }
        }
    }
    impl<T> UnwrapOk for Option<T> {
        type T = T;
        fn ok_or_fail(self) -> T {
            match self {
                Some(v) => v,
                None => panic!("expected Some"),
            }
        }
    }
}

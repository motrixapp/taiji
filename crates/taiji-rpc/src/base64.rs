//! base64 decoding for RPC addTorrent/addMetalink (hand-rolled parsing
//! surface — avoids taking on a base64-crate dependency; fuzz target
//! `rpc_base64`, fuzz/ is a separate workspace).
//!
//! Shape cross-checked against the read-only aria2 reference: the
//! JSON-RPC branch decodes the addTorrent first parameter with
//! `base64::decode` (RpcMethodImpl.cc); standard alphabet + '=' padding
//! (RFC 4648 §4). Strict decode: illegal character/length/padding ->
//! None (the caller maps it to an explicit execution error; aria2
//! throws DECODE_FAILURE with the same semantics).
//!
//! # Registered difference
//!
//! - **Non-canonical trailing bits accepted**: input whose final group
//!   has non-zero leftover bits (e.g. `Zh==` — the canonical form would
//!   be `Zg==`) decodes by its value. RFC 4648 §4 says SHOULD reject;
//!   aria2 `base64::decode` is likewise lenient at the bit level, and
//!   rejecting would break interop with ecosystem encoders that carry
//!   noisy trailing bits. A test pins this acceptance.

#[cfg(test)]
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value_of(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard base64 decode (with padding). Whitespace is not tolerated
/// (aria2 decode does not tolerate it either — no bare whitespace
/// belongs inside a JSON string); empty input -> Some(empty).
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    // Padding shape: the length must be a multiple of 4; at most two
    // '=' and only at the tail.
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let pad = bytes.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 || bytes[..bytes.len() - pad].contains(&b'=') {
        return None;
    }
    let stripped = &bytes[..bytes.len() - pad];
    let mut out = Vec::with_capacity(stripped.len() * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in stripped {
        let v = value_of(c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rfc4648_vectors() {
        assert_eq!(decode("").as_deref(), Some(&b""[..]));
        assert_eq!(decode("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(decode("Zm8=").as_deref(), Some(&b"fo"[..]));
        assert_eq!(decode("Zm9v").as_deref(), Some(&b"foo"[..]));
        assert_eq!(decode("Zm9vYg==").as_deref(), Some(&b"foob"[..]));
        assert_eq!(decode("Zm9vYmE=").as_deref(), Some(&b"fooba"[..]));
        assert_eq!(decode("Zm9vYmFy").as_deref(), Some(&b"foobar"[..]));
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(decode("A").is_none(), "length % 4 != 0");
        assert!(decode("AAAA=").is_none(), "stray padding");
        assert!(decode("A===").is_none(), "padding > 2");
        assert!(decode("Zg==\n").is_none(), "trailing noise");
        assert!(decode("Zm9*").is_none(), "non-alphabet char");
    }

    /// Registered difference (module doc): non-canonical trailing bits
    /// (non-zero leftover bits in the final group) decode by value —
    /// the lenient bit surface (aria2 the same); the divergence from
    /// the canonical form is pinned here.
    #[test]
    fn non_canonical_trailing_bits_are_accepted_declared_difference() {
        // `Zg==` -> "f" (canonical); `Zh==` carries 0b01 noise in the
        // trailing bits -> also decodes to "f".
        assert_eq!(decode("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(decode("Zh==").as_deref(), Some(&b"f"[..]));
    }

    #[test]
    fn roundtrips_binary_torrent_like_payload() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        // The encoding side is computed within the test (the rpc layer
        // only consumes decoding).
        let mut enc = String::new();
        for chunk in payload.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            let quad = [
                ALPHABET[(n >> 18) as usize & 63],
                ALPHABET[(n >> 12) as usize & 63],
                if chunk.len() > 1 {
                    ALPHABET[(n >> 6) as usize & 63]
                } else {
                    b'='
                },
                if chunk.len() > 2 {
                    ALPHABET[n as usize & 63]
                } else {
                    b'='
                },
            ];
            enc.push_str(std::str::from_utf8(&quad).unwrap_or_else(|_| panic!("utf8")));
        }
        assert_eq!(decode(&enc).as_deref(), Some(&payload[..]));
    }
}

/// Standard padded encoding for returning verified torrent metadata.
pub fn encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            out.push(if index > chunk.len() {
                '='
            } else {
                char::from(ALPHABET[((bits >> (18 - index * 6)) & 63) as usize])
            });
        }
    }
    out
}

#[cfg(test)]
#[test]
fn metadata_encoding_round_trips_binary_and_padding() {
    for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v")] {
        assert_eq!(encode(plain.as_bytes()), encoded);
    }
    let bytes: Vec<u8> = (0..=255).collect();
    for size in 0..=bytes.len() {
        assert_eq!(
            decode(&encode(&bytes[..size])),
            Some(bytes[..size].to_vec())
        );
    }
}

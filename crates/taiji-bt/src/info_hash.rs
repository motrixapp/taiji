//! The transport-layer unified info-hash handle (the BEP52 upgrade path).
//!
//! BEP52 (beps/bep_0052.rst, "Upgrade Path" section): implementations
//! supporting both formats "can join both swarms by calculating the new
//! and old infohashes"; a handshake initiated with the v1 sha1 may set
//! reserved[7] & 0x10 to declare v2 capability. Wherever a 20-byte
//! transport identity is needed (handshake/tracker/DHT), the v2 identity
//! is always the **first 20 bytes of the SHA-256, truncated**; the full
//! 32-byte value is used only for the magnet `btmh` and metadata identity
//! surfaces, never on the wire.

/// v2 identity -> the transport-layer 20-byte handle: the first 20 bytes
/// of SHA-256, truncated (always 20B; widening is explicitly forbidden).
pub fn truncated_v2(hash: &[u8; 32]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[..20]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Truncation = the first 20 bytes verbatim; the trailing 12 bytes do
    /// not participate.
    #[test]
    fn truncation_takes_first_20_bytes() {
        let full = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let t = truncated_v2(&full);
        assert_eq!(&t[..], &full[..20]);
        assert_eq!(
            sha2_hex_head(&t),
            "000102030405060708090a0b0c0d0e0f10111213"
        );
    }

    fn sha2_hex_head(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

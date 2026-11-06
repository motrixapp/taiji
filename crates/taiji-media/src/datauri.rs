//! `data:` URI parsing for inline AES-128 keys (per the product spec:
//! direct inline `data:` parsing — 64KiB cap, key exactly 16
//! bytes; the parse-surface fuzz red line inherits to this parser).
//!
//! Grammar (RFC 2397, lenient media posture):
//!
//! ```text
//! data:[<mediatype>][;base64],<data>
//! ```
//!
//! * The mediatype is accepted and ignored (key material is judged by
//! its decoded length, not its declared type).
//! * `;base64` switches the payload to base64 (RFC 4648 §4 with
//! padding; **whitespace is rejected** — a key URI is not
//! pretty-printed prose, and silently skipping embedded newlines is
//! an injection surface).
//! * Without `;base64` the payload is percent-decoded (RFC 3986 §2.1);
//! stray non-percent `%` bytes are a parse error. Bytes that are not
//! US-ASCII pass through as their UTF-8 encoding (browser-aligned
//! leniency — the key-length check is the real gate).
//! * The **decoded** size is capped at [`MAX_DATA_URI_BYTES`] (64KiB):
//! a larger payload is refused before any allocation-heavy work
//! beyond the URI text itself (which is itself bounded by the
//! manifest's 16MiB cap upstream).
//!
//! Errors are [`MediaError::KeyInvalid`] — the key-material face.

use crate::error::MediaError;

/// Decoded-payload cap for `data:` key URIs (the 64KiB cap).
pub const MAX_DATA_URI_BYTES: usize = 64 * 1024;

/// The expected AES-128 key length carried by a data: (or fetched) key
/// (exactly 16B).
pub const EXPECTED_KEY_LEN: usize = 16;

/// Parse a `data:` URI into its decoded payload bytes.
pub fn parse_data_uri(uri: &str) -> Result<Vec<u8>, MediaError> {
    let invalid = |why: &str| MediaError::KeyInvalid(format!("data: URI: {why}"));
    let Some(rest) = uri.strip_prefix("data:") else {
        return Err(invalid("missing data: scheme prefix"));
    };
    let Some((header, payload)) = rest.split_once(',') else {
        return Err(invalid("missing ',' separator"));
    };
    let base64 = header.split(';').any(|s| s.eq_ignore_ascii_case("base64"));
    let decoded = if base64 {
        decode_base64_strict(payload).map_err(|e| invalid(&e))?
    } else {
        percent_decode(payload).map_err(|e| invalid(&e))?
    };
    if decoded.len() > MAX_DATA_URI_BYTES {
        return Err(invalid(&format!(
            "decoded payload {} bytes exceeds the {} cap",
            decoded.len(),
            MAX_DATA_URI_BYTES
        )));
    }
    Ok(decoded)
}

/// Decode the key material from a `data:` URI payload, enforcing the
/// 16-byte key length (wrong length = explicit rejection, never
/// truncation or padding).
pub fn parse_key_data_uri(uri: &str) -> Result<[u8; EXPECTED_KEY_LEN], MediaError> {
    let bytes = parse_data_uri(uri)?;
    let Ok(key) = <[u8; EXPECTED_KEY_LEN]>::try_from(bytes.as_slice()) else {
        return Err(MediaError::KeyInvalid(format!(
            "key body is {} bytes, expected exactly {EXPECTED_KEY_LEN}",
            bytes.len()
        )));
    };
    Ok(key)
}

/// RFC 4648 §4 base64 with mandatory padding and no whitespace
/// tolerance. Returns the error text (the caller wraps the code).
fn decode_base64_strict(payload: &str) -> Result<Vec<u8>, String> {
    let b64 = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let bytes = payload.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(format!(
            "base64 length {} is not a multiple of 4",
            bytes.len()
        ));
    }
    // Reject embedded whitespace outright (see module docs).
    if bytes.iter().any(|c| c.is_ascii_whitespace()) {
        return Err("base64 payload contains whitespace".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for quad in bytes.chunks_exact(4) {
        let pad = quad.iter().filter(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && quad[3..].iter().any(|c| *c != b'=')) {
            return Err("base64 padding only allowed in the last two positions".to_string());
        }
        if quad[..4 - pad].contains(&b'=') {
            return Err("base64 pad byte before the final quad positions".to_string());
        }
        let mut vals = [0u8; 4];
        for i in 0..4 {
            let c = quad[i];
            if c == b'=' {
                vals[i] = 0;
            } else {
                vals[i] = b64(c).ok_or_else(|| format!("base64 character {:?}", c as char))?;
            }
        }
        let n = (vals[0] << 2) | (vals[1] >> 4);
        out.push(n);
        if pad < 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if pad < 1 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Ok(out)
}

/// Percent-decoding per RFC 3986 §2.1: `%XX` hex pairs decode to one
/// byte; a stray `%` or a non-hex escape is an error; everything else
/// passes through as-is (UTF-8 bytes included).
fn percent_decode(payload: &str) -> Result<Vec<u8>, String> {
    let bytes = payload.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or_else(|| "truncated percent escape at end of payload".to_string())?;
            let hi = (hex[0] as char)
                .to_digit(16)
                .ok_or_else(|| format!("non-hex percent escape %{}", hex[0] as char))?;
            let lo = (hex[1] as char).to_digit(16).ok_or_else(|| {
                format!(
                    "non-hex percent escape %{}{}",
                    hex[0] as char, hex[1] as char
                )
            })?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key16() -> [u8; 16] {
        (0..16u8).collect::<Vec<_>>().try_into().unwrap_or([0; 16])
    }

    /// RFC 2397 forms: base64 and percent-encoded payloads decode to
    /// the key; mediatype prefixes are tolerated and ignored.
    #[test]
    fn data_uri_forms() {
        let key = key16();
        // base64, no mediatype.
        let b64 = {
            // 16 bytes → 24 base64 chars with padding (last byte 0x0F
            // → "...Dw==").
            const TAB: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for quad in key.chunks(3) {
                let b = [
                    quad[0],
                    quad.get(1).copied().unwrap_or(0),
                    quad.get(2).copied().unwrap_or(0),
                ];
                let n = (quad.len() * 4).div_ceil(3);
                let units = [
                    b[0] >> 2,
                    ((b[0] & 0x03) << 4) | (b[1] >> 4),
                    ((b[1] & 0x0F) << 2) | (b[2] >> 6),
                    b[2] & 0x3F,
                ];
                for (i, u) in units.iter().enumerate() {
                    if i < n {
                        s.push(TAB[*u as usize] as char);
                    } else {
                        s.push('=');
                    }
                }
            }
            s
        };
        let uri = format!("data:application/octet-stream;base64,{b64}");
        assert_eq!(parse_key_data_uri(&uri).ok(), Some(key));

        // Percent-encoded form.
        let pct: String = key.iter().map(|b| format!("%{b:02X}")).collect();
        assert_eq!(
            parse_key_data_uri(&format!("data:,{pct}")).ok(),
            Some(key),
            "percent-encoded form"
        );
        // Bare ASCII bytes (a 16-byte printable key) pass through.
        assert_eq!(
            parse_key_data_uri("data:,0123456789abcdef").ok(),
            Some(*b"0123456789abcdef")
        );
    }

    /// Negative matrix: wrong key length, malformed structure, bad
    /// base64, stray percent, oversize payload — all `key_invalid`,
    /// never a panic, never a silent truncate.
    #[test]
    fn data_uri_negative_matrix() {
        // Wrong length (15 bytes decoded).
        let e = parse_key_data_uri("data:,0123456789abcde")
            .err()
            .unwrap_or_else(|| panic!("15B key must be refused"));
        assert_eq!(e.code(), "taiji.media.key_invalid");
        assert!(e.to_string().contains("15 bytes"));
        // 17 bytes.
        assert!(parse_key_data_uri("data:,0123456789abcdefg").is_err());
        // Structural.
        for bad in [
            "http://x/k",
            "data:nocomma",
            "data:;base64,####",
            "data:;base64,Zm9=whitespace",
        ] {
            assert!(parse_data_uri(bad).is_err(), "{bad:?} must be refused");
        }
        // An empty payload parses (0 bytes) but fails the key-length
        // face — the two levels are distinct by design.
        assert_eq!(parse_data_uri("data:,").ok(), Some(Vec::new()));
        assert!(parse_key_data_uri("data:,").is_err());
        // Base64 whitespace injection refused.
        assert!(parse_data_uri("data:;base64,AA BB").is_err());
        // Base64 bad length.
        assert!(parse_data_uri("data:;base64,AAA").is_err());
        // Stray percent.
        assert!(parse_data_uri("data:,%G1").is_err());
        assert!(parse_data_uri("data:,100%").is_err());
        // Oversize payload: 64KiB + 1 printable bytes.
        let big = "X".repeat(MAX_DATA_URI_BYTES + 1);
        let e = parse_data_uri(&format!("data:,{big}"))
            .err()
            .unwrap_or_else(|| panic!("oversize must be refused"));
        assert_eq!(e.code(), "taiji.media.key_invalid");
        assert!(e.to_string().contains("exceeds"));
        // Exactly 64KiB passes the parser (the key-length check is a
        // separate face).
        let at_cap = "X".repeat(MAX_DATA_URI_BYTES);
        assert!(parse_data_uri(&format!("data:,{at_cap}")).is_ok());
    }

    /// Round-trip against the same encoder the e2e uses: a 16-byte key
    /// through standard base64.
    #[test]
    fn base64_known_vector() {
        // "3q2+7w==" ≡ { 0xDE, 0xAD, 0xBE, 0xEF }.
        assert_eq!(
            decode_base64_strict("3q2+7w==").unwrap_or_default(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        // "" decodes to empty.
        assert_eq!(
            decode_base64_strict("").unwrap_or_default(),
            Vec::<u8>::new()
        );
        // "TWFu" ≡ "Man".
        assert_eq!(
            decode_base64_strict("TWFu").unwrap_or_default(),
            b"Man".to_vec()
        );
    }
}

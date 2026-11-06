//! `<hash>` / `<pieces type=…>` checksum consumption.
//!
//! Type names are the IANA "Hash Function Textual Names" registry names
//! referenced by RFC 5854 §2.3.1 (`md5`/`sha-1`/`sha-256`…). Known types
//! = md5 + the full SHA-2 family (sha1/sha2/md-5 all come from the
//! RustCrypto digest 0.11 family); other types are kept verbatim under
//! "unknown tag is ignored, not fatal" — verifiability is explicitly
//! absent rather than faked.

use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

/// Checksum kind (RFC 5854 `hash@type`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashKind {
    /// MD5 (16-byte digest).
    Md5,
    /// SHA-1 (20-byte digest).
    Sha1,
    /// SHA-224 (28-byte digest).
    Sha224,
    /// SHA-256 (32-byte digest).
    Sha256,
    /// SHA-384 (48-byte digest).
    Sha384,
    /// SHA-512 (64-byte digest).
    Sha512,
    /// Unsupported kind (document text kept; verification is explicitly
    /// unavailable and reports an error instead of faking success).
    Other(String),
}

impl HashKind {
    /// IANA textual name → [`HashKind`] (case-insensitive; RFC 5854 §2.3.1
    /// compares type names ASCII case-insensitively).
    pub fn from_type_name(name: &str) -> HashKind {
        match name.to_ascii_lowercase().as_str() {
            "md5" => HashKind::Md5,
            "sha-1" => HashKind::Sha1,
            "sha-224" => HashKind::Sha224,
            "sha-256" => HashKind::Sha256,
            "sha-384" => HashKind::Sha384,
            "sha-512" => HashKind::Sha512,
            _ => HashKind::Other(name.to_string()),
        }
    }

    /// Canonical type name (IANA textual name; unknown kinds return the
    /// document text).
    pub fn type_name(&self) -> &str {
        match self {
            HashKind::Md5 => "md5",
            HashKind::Sha1 => "sha-1",
            HashKind::Sha224 => "sha-224",
            HashKind::Sha256 => "sha-256",
            HashKind::Sha384 => "sha-384",
            HashKind::Sha512 => "sha-512",
            HashKind::Other(s) => s,
        }
    }

    /// Digest byte length for known kinds; unknown kinds = None.
    pub fn digest_len(&self) -> Option<usize> {
        match self {
            HashKind::Md5 => Some(16),
            HashKind::Sha1 => Some(20),
            HashKind::Sha224 => Some(28),
            HashKind::Sha256 => Some(32),
            HashKind::Sha384 => Some(48),
            HashKind::Sha512 => Some(64),
            HashKind::Other(_) => None,
        }
    }
}

impl HashKind {
    /// Digest computation (known kinds); unknown kinds have no digest
    /// surface.
    pub fn compute(&self, data: &[u8]) -> Option<Vec<u8>> {
        let out = match self {
            HashKind::Md5 => Md5::digest(data).to_vec(),
            HashKind::Sha1 => Sha1::digest(data).to_vec(),
            HashKind::Sha224 => Sha224::digest(data).to_vec(),
            HashKind::Sha256 => Sha256::digest(data).to_vec(),
            HashKind::Sha384 => Sha384::digest(data).to_vec(),
            HashKind::Sha512 => Sha512::digest(data).to_vec(),
            HashKind::Other(_) => return None,
        };
        Some(out)
    }
}

/// A single checksum claim (a `<hash>` element or a piece hash entry).
///
/// The parser has already validated the hex (even length + legal hex
/// characters; known kinds additionally get their digest length checked —
/// a mismatch drops the element with a warning, matching the aria2
/// consumer rule); [`Hash::hex`] is the normalized lowercase text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    kind: HashKind,
    hex: String,
}

impl Hash {
    pub(crate) fn new(kind: HashKind, hex: String) -> Hash {
        Hash { kind, hex }
    }

    /// Checksum kind.
    pub fn kind(&self) -> &HashKind {
        &self.kind
    }

    /// Normalized lowercase hex text.
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Decoded digest bytes (parser-validated, always `Some`).
    pub fn decode(&self) -> Option<Vec<u8>> {
        decode_hex(&self.hex)
    }

    /// Digest verification over given bytes (the data-layer primitive of
    /// whole-file verification; task-layer scheduling and on-disk checks
    /// live in taiji-http/core).
    ///
    /// Known kinds (md5/sha-1/SHA-2 family) return the digest comparison
    /// result; unknown kinds explicitly report
    /// [`VerifyError::UnsupportedKind`] (no faked always-true).
    pub fn verify(&self, data: &[u8]) -> Result<bool, VerifyError> {
        let digest = self
            .kind
            .compute(data)
            .ok_or_else(|| VerifyError::UnsupportedKind(self.kind.type_name().to_string()))?;
        // Constant-time fold comparison (digests are public data; this is a
        // defensive posture, not a secret surface).
        let expect = self.decode().unwrap_or_default();
        Ok(expect.len() == digest.len()
            && digest
                .iter()
                .zip(&expect)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0)
    }
}

/// Checksum verification error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Unknown/unsupported checksum kind (document text kept; no faked
    /// verification).
    #[error("unsupported hash kind: {0}")]
    UnsupportedKind(String),
}

/// Hex decoding (requires even length + legal hex characters, both cases
/// accepted — lowercase normalization happens in the parser).
pub(crate) fn decode_hex(s: &str) -> Option<Vec<u8>> {
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = nib(pair[0])?;
        let lo = nib(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Hex validity check (even length + legal characters), no copy produced.
pub(crate) fn is_valid_hex(s: &str) -> bool {
    decode_hex(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iana_type_names_map() {
        assert_eq!(HashKind::from_type_name("md5"), HashKind::Md5);
        assert_eq!(HashKind::from_type_name("MD5"), HashKind::Md5);
        assert_eq!(HashKind::from_type_name("sha-1"), HashKind::Sha1);
        assert_eq!(HashKind::from_type_name("SHA-256"), HashKind::Sha256);
        assert_eq!(HashKind::from_type_name("sha-224"), HashKind::Sha224);
        assert_eq!(HashKind::from_type_name("sha-384"), HashKind::Sha384);
        assert_eq!(HashKind::from_type_name("sha-512"), HashKind::Sha512);
        assert_eq!(
            HashKind::from_type_name("sha3-512"),
            HashKind::Other("sha3-512".to_string())
        );
        assert_eq!(HashKind::Other("x".to_string()).type_name(), "x");
    }

    #[test]
    fn digest_lens() {
        assert_eq!(HashKind::Md5.digest_len(), Some(16));
        assert_eq!(HashKind::Sha1.digest_len(), Some(20));
        assert_eq!(HashKind::Sha224.digest_len(), Some(28));
        assert_eq!(HashKind::Sha256.digest_len(), Some(32));
        assert_eq!(HashKind::Sha384.digest_len(), Some(48));
        assert_eq!(HashKind::Sha512.digest_len(), Some(64));
        assert_eq!(HashKind::Other("z".to_string()).digest_len(), None);
    }

    #[test]
    fn verify_known_vectors() {
        // Classic vectors (widely accepted values from the RFC 1321/RFC
        // 3174 family).
        let md5 = Hash::new(
            HashKind::Md5,
            "acbd18db4cc2f85cedef654fccc4a4d8".to_string(),
        );
        assert!(md5.verify(b"foo").unwrap_or(false));
        assert!(!md5.verify(b"bar").unwrap_or(false));

        let sha1 = Hash::new(
            HashKind::Sha1,
            "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33".to_string(),
        );
        assert!(sha1.verify(b"foo").unwrap_or(false));

        let sha256 = Hash::new(
            HashKind::Sha256,
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae".to_string(),
        );
        assert!(sha256.verify(b"foo").unwrap_or(false));

        // Full SHA-2 family (224/384/512) comes free with the sha2 crate.
        let sha512 = Hash::new(
            HashKind::Sha512,
            "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7".to_string(),
        );
        assert!(sha512.verify(b"foo").unwrap_or(false));

        // Uppercase hex text is normalized to lowercase by the parser;
        // decode is verified here.
        let upper = Hash::new(
            HashKind::Sha1,
            "0BEEC7B5EA3F0FDBC95D0DD47F3C5BC275DA8A33".to_string(),
        );
        assert_eq!(upper.decode().map(|b| b.len()), Some(20));
    }

    #[test]
    fn unsupported_kind_errors_explicitly() {
        let other = Hash::new(HashKind::Other("sha3-512".to_string()), "ab".to_string());
        assert_eq!(
            other.verify(b"foo"),
            Err(VerifyError::UnsupportedKind("sha3-512".to_string()))
        );
    }

    #[test]
    fn hex_decode_cases() {
        assert_eq!(decode_hex(""), Some(Vec::new()));
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert!(is_valid_hex("deadbeef"));
        assert!(!is_valid_hex("deadbee"));
    }
}

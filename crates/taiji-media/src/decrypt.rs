//! AES-128 segment decryption core (per the product spec's key
//! section, inherited via the media spec's checklist —
//! implementation details follow that spec + the
//! segment-identity keying, checked against
//! its review red lines).
//!
//! Pure functions, no I/O, platform-independent:
//!
//! * **Segment-whole CBC** ([`decrypt_segment`]): the cipher chain is
//!   opened and closed inside one media segment — a segment is the
//!   decryption unit, never a transport merge run ("transport merge is
//!   not decryption merge": the ≤8-sub-segment wire merge is a transport optimization;
//!   decryption splits strictly at segment boundaries, each sub-segment
//!   with its own IV).
//! * **PKCS7 unpad** on every segment; a pad value of exactly 16 (a
//!   whole pad block) is legal and yields an empty plaintext.
//! * **IV derivation** ([`iv_from_sequence`]): explicit IV wins; when
//!   the EXT-X-KEY omits it, the IV is the big-endian 128-bit form of
//!   the segment's **absolute media sequence** (the product spec's
//!   segment identity = absolute media sequence — the bitmap and the
//!   IV key on
//!   the same value; non-zero starting sequences are golden vectors).
//! * **Length discipline**: a ciphertext whose length is not a
//!   non-zero multiple of the 16-byte block size cannot be valid
//!   AES-CBC — the error names `segment_decrypt_failed` (the driver's
//!   retry-once-then-fail face lives above this core; a truncated fetch
//!   can produce such a length, which is why the driver retries the
//!   fetch once before surfacing the error).
//!
//! Errors are [`MediaError::SegmentDecryptFailed`] (the inherited
//! `taiji.media.segment_decrypt_failed` code wired here — no
//! new error vocabulary here).

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

use crate::error::MediaError;

/// AES-128 key length in bytes.
pub const KEY_LEN: usize = 16;
/// AES block size in bytes (the CBC block / IV width).
pub const BLOCK_LEN: usize = 16;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Default IV for one media segment: the absolute media sequence as a
/// big-endian 128-bit value (RFC 8216 §4.3.2.3's missing-IV rule for
/// AES-128; per the product spec).
pub fn iv_from_sequence(sequence: u64) -> [u8; BLOCK_LEN] {
    let mut iv = [0u8; BLOCK_LEN];
    iv[8..].copy_from_slice(&sequence.to_be_bytes());
    iv
}

/// Decrypt one whole media segment: AES-128-CBC over the full segment
/// body + PKCS7 unpad. The CBC chain starts at `iv` and ends at the
/// segment end — callers never feed a transport merge run in here
/// unsplit (see [`decrypt_merged_span`] for the split face).
pub fn decrypt_segment(
    key: &[u8; KEY_LEN],
    iv: &[u8; BLOCK_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MediaError> {
    if ciphertext.is_empty() {
        return Err(MediaError::SegmentDecryptFailed(
            "empty ciphertext (a segment must carry at least one block)".to_string(),
        ));
    }
    if ciphertext.len() % BLOCK_LEN != 0 {
        return Err(MediaError::SegmentDecryptFailed(format!(
            "ciphertext length {} is not a multiple of the {}-byte block",
            ciphertext.len(),
            BLOCK_LEN
        )));
    }
    Aes128CbcDec::new(&(*key).into(), &(*iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| MediaError::SegmentDecryptFailed(format!("pkcs7 unpad rejected: {e:?}")))
}

/// Split-and-decrypt face for merged transport payloads: one wire body
/// covering `boundaries.len()` sub-segments, each decrypted
/// independently with its own IV (the ≤8 merge is a
/// transport form only). `sub_ivs` carries one IV per sub-segment
/// (explicit or sequence-derived; same length as `boundaries`).
///
/// `boundaries` are the sub-segment lengths in order; their sum must
/// equal `body.len()` (a layout/delivery mismatch is an explicit error,
/// never a partial decrypt).
pub fn decrypt_merged_span(
    key: &[u8; KEY_LEN],
    body: &[u8],
    boundaries: &[u64],
    sub_ivs: &[[u8; BLOCK_LEN]],
) -> Result<Vec<u8>, MediaError> {
    if boundaries.len() != sub_ivs.len() {
        return Err(MediaError::SegmentDecryptFailed(format!(
            "merged span shape mismatch: {} boundaries vs {} IVs",
            boundaries.len(),
            sub_ivs.len()
        )));
    }
    let total: u64 = boundaries.iter().try_fold(0u64, |acc, b| {
        acc.checked_add(*b)
            .ok_or_else(|| MediaError::SegmentDecryptFailed("boundary sum overflow".to_string()))
    })?;
    if total != body.len() as u64 {
        return Err(MediaError::SegmentDecryptFailed(format!(
            "merged span length mismatch: boundaries sum {total} vs body {}",
            body.len()
        )));
    }
    let mut out = Vec::with_capacity(body.len());
    let mut off = 0usize;
    for (len, iv) in boundaries.iter().zip(sub_ivs.iter()) {
        let end = off + *len as usize;
        let slice = body
            .get(off..end)
            .ok_or_else(|| MediaError::SegmentDecryptFailed("span slice OOB".to_string()))?;
        out.extend_from_slice(&decrypt_segment(key, iv, slice)?);
        off = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip helper for the pad-matrix vectors (local encrypt over
    /// the same RustCrypto stack — the production face stays decrypt-only).
    fn encrypt(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        use aes::cipher::BlockEncryptMut;
        type Enc = cbc::Encryptor<aes::Aes128>;
        Enc::new(&(*key).into(), &(*iv).into()).encrypt_padded_vec_mut::<Pkcs7>(plain)
    }
    fn key() -> [u8; 16] {
        [0x2b; 16]
    }

    /// NIST SP 800-38A F.2.1 (CBC-AES128) vectors: decrypting each
    /// ciphertext prefix with the fixed IV reproduces the matching
    /// plaintext prefix (the CBC chain inside one segment).
    #[test]
    fn nist_sp800_38a_f21_vectors() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt: [&[u8]; 4] = [
            &[
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
                0x17, 0x2a,
            ],
            &[
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                0x8e, 0x51,
            ],
            &[
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a,
                0x52, 0xef,
            ],
            &[
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c,
                0x37, 0x10,
            ],
        ];
        let ct: [&[u8]; 4] = [
            &[
                0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
                0x19, 0x7d,
            ],
            &[
                0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76,
                0x78, 0xb2,
            ],
            &[
                0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22,
                0x95, 0x16,
            ],
            &[
                0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86,
                0xe1, 0xa7,
            ],
        ];
        // Cumulative prefixes: raw-CBC decrypt(CT[0..=k]) == PT[0..=k]
        // (the NIST vectors carry no PKCS7 pad — the chain check runs
        // through the NoPadding face of the same Decryptor type; the
        // padded production path is covered by the pad-matrix vectors
        // below).
        for k in 0..4 {
            use aes::cipher::block_padding::NoPadding;
            let mut cipher = Vec::new();
            let mut plain = Vec::new();
            for i in 0..=k {
                cipher.extend_from_slice(ct[i]);
                plain.extend_from_slice(pt[i]);
            }
            let got = Aes128CbcDec::new(&key.into(), &iv.into())
                .decrypt_padded_vec_mut::<NoPadding>(&cipher)
                .unwrap_or_else(|e| panic!("prefix {k}: {e:?}"));
            assert_eq!(got, plain, "prefix {k}");
        }
        // A wrong IV corrupts the first block (chain anchor sanity).
        let mut bad_iv = iv;
        bad_iv[0] ^= 0xFF;
        let got = Aes128CbcDec::new(&key.into(), &bad_iv.into())
            .decrypt_padded_vec_mut::<aes::cipher::block_padding::NoPadding>(ct[0])
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert_ne!(got, pt[0]);
    }

    /// PKCS7 pad matrix: every pad value 1..=16 round-trips, including
    /// the whole-pad-block form (16 → empty plaintext) and the no-pad
    /// needed form (a multiple of 16 that still appends a full block).
    #[test]
    fn pkcs7_all_pad_values_round_trip() {
        let iv = [7u8; 16];
        for pad in 1usize..=16 {
            // A plaintext whose length ≡ 16 - pad (mod 16) receives
            // exactly `pad` bytes of padding.
            let plain_len = 48 - pad; // 47..=32 → pads 1..=16
            let plain: Vec<u8> = (0..plain_len).map(|i| i as u8).collect();
            let cipher = encrypt(&key(), &iv, &plain);
            assert_eq!(cipher.len(), plain.len() + pad);
            let got =
                decrypt_segment(&key(), &iv, &cipher).unwrap_or_else(|e| panic!("pad {pad}: {e}"));
            assert_eq!(got, plain, "pad {pad}");
        }
        // pad == 16 (empty plaintext): ciphertext is exactly one block.
        let cipher = encrypt(&key(), &iv, b"");
        assert_eq!(cipher.len(), 16);
        let got = decrypt_segment(&key(), &iv, &cipher).unwrap_or_else(|e| panic!("pad 16: {e}"));
        assert!(got.is_empty(), "whole-pad-block decrypts to empty");
    }

    /// Length discipline: empty and non-16-multiple ciphertexts are
    /// `segment_decrypt_failed` (the retry-once driver face above this
    /// core re-fetches once before surfacing; the pure core refuses
    /// immediately).
    #[test]
    fn non_multiple_and_empty_ciphertext_refused() {
        let iv = [0u8; 16];
        for bad_len in [0usize, 1, 15, 17, 31, 100] {
            let body = vec![0xABu8; bad_len];
            let err = decrypt_segment(&key(), &iv, &body)
                .err()
                .unwrap_or_else(|| panic!("len {bad_len} must be refused"));
            assert_eq!(err.code(), "taiji.media.segment_decrypt_failed");
        }
        // Corrupted padding inside a well-formed length also refuses.
        let mut cipher = encrypt(&key(), &iv, b"0123456789abcdef");
        let last = cipher.len() - 1;
        cipher[last] ^= 0x01;
        let err = decrypt_segment(&key(), &iv, &cipher)
            .err()
            .unwrap_or_else(|| panic!("corrupted pad must be refused"));
        assert_eq!(err.code(), "taiji.media.segment_decrypt_failed");
    }

    /// IV derivation: the sequence occupies the low 64 bits, big-endian;
    /// non-zero and >32-bit sequences land in the right bytes.
    #[test]
    fn iv_from_sequence_layout() {
        assert_eq!(iv_from_sequence(0), [0u8; 16]);
        let iv = iv_from_sequence(1);
        assert_eq!(iv[14], 0);
        assert_eq!(iv[15], 1);
        // Sequence 700 (a golden non-zero form): 700 = 0x02BC.
        let iv = iv_from_sequence(700);
        assert_eq!(iv[14], 0x02);
        assert_eq!(iv[15], 0xBC);
        assert_eq!(
            u64::from_be_bytes(iv[8..16].try_into().unwrap_or([0; 8])),
            700
        );
        // A >32-bit sequence uses bytes 8..=12 too.
        let big = 0x0102_0304_0506_0708u64;
        let iv = iv_from_sequence(big);
        assert_eq!(
            u64::from_be_bytes(iv[8..16].try_into().unwrap_or([0; 8])),
            big
        );
        assert!(iv[..8].iter().all(|b| *b == 0));
    }

    /// Merged-span split: one wire body of three sub-segments decrypts
    /// per sub-segment IV — concatenation equals the independent
    /// per-segment decrypts; a boundary/IV shape mismatch or a length
    /// disagreement is an explicit error.
    #[test]
    fn merged_span_splits_per_subsegment_iv() {
        let key = key();
        let ivs: Vec<[u8; 16]> = (0..3u64).map(iv_from_sequence).collect();
        let plains: Vec<Vec<u8>> = vec![
            (0..32u8).collect(),
            (0..48u8).collect(),
            (0..17u8).collect(),
        ];
        let ciphers: Vec<Vec<u8>> = plains
            .iter()
            .zip(ivs.iter())
            .map(|(p, iv)| encrypt(&key, iv, p))
            .collect();
        let mut body = Vec::new();
        for c in &ciphers {
            body.extend_from_slice(c);
        }
        let boundaries: Vec<u64> = ciphers.iter().map(|c| c.len() as u64).collect();

        // The split decrypt equals the independent decrypts glued.
        let got =
            decrypt_merged_span(&key, &body, &boundaries, &ivs).unwrap_or_else(|e| panic!("{e}"));
        let expect: Vec<u8> = plains.concat();
        assert_eq!(got, expect);

        // Boundary sum disagreement is explicit.
        let err = decrypt_merged_span(&key, &body, &[10, 10], &ivs[..2])
            .err()
            .unwrap_or_else(|| panic!("shape mismatch must refuse"));
        assert_eq!(err.code(), "taiji.media.segment_decrypt_failed");
        // Boundary/IV count disagreement is explicit.
        assert!(decrypt_merged_span(&key, &body, &boundaries, &ivs[..2]).is_err());
    }
}

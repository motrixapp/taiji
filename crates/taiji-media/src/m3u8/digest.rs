//! Normalized digest + variant identity (the product spec's
//! playlist-consistency face, adopted for the recovery surface and the
//! 0.4 signature-refresh structure diff, per the media spec's
//! errata).
//!
//! **Normalized digest**: a SHA-256 over a canonical serialization of
//! the *parsed* structure with every URI's query string stripped — a
//! re-fetched manifest whose segment/key URIs only carry fresh CDN
//! signature parameters digests identically, while any structural
//! change (segment count, path sequence, duration sequence, byte
//! ranges, key rotation, init-section layout) changes the digest.
//! The spec names the compared substance as segment count / path
//! set / duration sequence; this serialization keeps the segment
//! **order** (stronger than
//! a set: a reorder is a structural change, not a cosmetic one) and
//! adds the boundary facts that change download behavior.
//!
//! **Variant identity**: normalized path (query stripped) +
//! BANDWIDTH + RESOLUTION — the stable key a 0.4 signature refresh
//! re-matches variants against after a re-fetch (CDN token expiry
//! rewrites every query; the identity must not notice).
//!
//! Hash primitive: an in-tree SHA-256 (FIPS 180-4). The workspace
//! registry carries `sha2`, but wiring it into this crate would touch
//! the frozen root `Cargo.lock` (a shared file on this track's
//! contract), and the digest here is a consistency fingerprint, not a
//! cryptographic boundary — a compact, NIST-vector-tested in-tree
//! implementation keeps the dependency graph untouched.

use std::fmt::Write as _;

use super::model::{MasterPlaylist, MediaPlaylist, Variant};

/// SHA-256 of the canonical media-playlist structure (hex, lowercase).
pub fn media_playlist_digest(playlist: &MediaPlaylist) -> String {
    let mut text = String::new();
    // Identity anchors: sequence bases + terminator presence.
    text.push_str("hls-media/1\n");
    let _ = write!(
        &mut text,
        "media_sequence={}\ndiscontinuity_sequence={}\ntarget_duration=",
        playlist.media_sequence, playlist.discontinuity_sequence
    );
    match playlist.target_duration {
        Some(td) => {
            let _ = write!(&mut text, "{td:.6}");
        }
        None => text.push('-'),
    }
    text.push('\n');
    let _ = writeln!(
        &mut text,
        "endlist={}\nindependent_segments={}",
        playlist.endlist as u8, playlist.independent_segments as u8
    );
    for section in &playlist.init_sections {
        let _ = writeln!(
            &mut text,
            "init\t{}\t{}\t{}\t{}",
            section.index,
            strip_query(&section.uri),
            range_digest(section.byte_range.map(|br| (br.offset, br.length))),
            key_digest(section.key.as_ref())
        );
    }
    for seg in &playlist.segments {
        let _ = writeln!(
            &mut text,
            "seg\t{}\t{}\t{:.6}\t{}\t{}\t{}\t{}",
            seg.sequence,
            strip_query(&seg.uri),
            seg.duration,
            seg.discontinuity as u8,
            range_digest(seg.byte_range.map(|br| (br.offset, br.length))),
            key_digest(seg.key.as_ref()),
            match seg.map {
                Some(idx) => idx.to_string(),
                None => "-".to_owned(),
            }
        );
    }
    hex(&sha256(text.as_bytes()))
}

/// SHA-256 of the canonical master-playlist structure (hex,
/// lowercase).
pub fn master_playlist_digest(playlist: &MasterPlaylist) -> String {
    let mut text = String::new();
    text.push_str("hls-master/1\n");
    let _ = writeln!(
        &mut text,
        "independent_segments={}",
        playlist.independent_segments as u8
    );
    for (kind, variants) in [
        ("variant", &playlist.variants),
        ("iframe", &playlist.iframe_variants),
    ] {
        for v in variants.iter() {
            let _ = writeln!(
                &mut text,
                "{kind}\t{}\t{}\t{}\t{}\t{}\t{}",
                strip_query(&v.uri),
                v.bandwidth,
                v.average_bandwidth
                    .map_or("-".to_owned(), |b| b.to_string()),
                v.resolution
                    .map_or("-".to_owned(), |(w, h)| format!("{w}x{h}")),
                v.codecs.as_deref().unwrap_or("-"),
                v.audio_group.as_deref().unwrap_or("-"),
            );
        }
    }
    for t in &playlist.tracks {
        let _ = writeln!(
            &mut text,
            "track\t{:?}\t{}\t{}\t{}\t{}\t{}",
            t.track_type,
            t.group_id.as_deref().unwrap_or("-"),
            t.name.as_deref().unwrap_or("-"),
            t.language.as_deref().unwrap_or("-"),
            t.default_track as u8,
            t.uri.as_deref().map(strip_query).unwrap_or("-"),
        );
    }
    hex(&sha256(text.as_bytes()))
}

/// Strip the query string from a URI reference: everything from the
/// first `?` (inclusive) is dropped — a fragment riding after the
/// query goes with it. Path-only normalization is deliberate —
/// the specs name exactly "strip query".
pub fn strip_query(uri: &str) -> &str {
    match uri.find('?') {
        Some(pos) => &uri[..pos],
        None => uri,
    }
}

/// Stable identity of a variant: normalized path + bandwidth +
/// resolution (per the media spec's errata, the three-level re-match
/// reference). Display form is the canonical comparable string
/// (`<path>|<bandwidth>|<WxH|->`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariantIdentity {
    /// Variant URI path with the query stripped.
    pub path: String,
    /// BANDWIDTH.
    pub bandwidth: u64,
    /// RESOLUTION as `WxH` when present.
    pub resolution: Option<(u32, u32)>,
}

impl std::fmt::Display for VariantIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let res = self
            .resolution
            .map_or_else(|| "-".to_owned(), |(w, h)| format!("{w}x{h}"));
        write!(f, "{}|{}|{}", self.path, self.bandwidth, res)
    }
}

/// Build the variant identity from raw facts.
pub fn variant_identity(
    uri: &str,
    bandwidth: u64,
    resolution: Option<(u32, u32)>,
) -> VariantIdentity {
    VariantIdentity {
        path: strip_query(uri).to_owned(),
        bandwidth,
        resolution,
    }
}

impl Variant {
    /// Identity of this variant row.
    pub fn identity(&self) -> VariantIdentity {
        variant_identity(&self.uri, self.bandwidth, self.resolution)
    }
}

fn range_digest(range: Option<(u64, u64)>) -> String {
    match range {
        Some((offset, length)) => format!("{offset}+{length}"),
        None => "-".to_owned(),
    }
}

fn key_digest(key: Option<&super::model::Key>) -> String {
    match key {
        None => "-".to_owned(),
        Some(k) => {
            let iv = k.iv.map_or_else(
                || "-".to_owned(),
                |iv| iv.iter().map(|b| format!("{b:02x}")).collect(),
            );
            let uri = k.uri.as_deref().map(strip_query).unwrap_or("-");
            format!(
                "{:?}\t{}\t{}\t{}",
                k.method,
                uri,
                iv,
                k.keyformat.as_deref().unwrap_or("-")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). In-tree to keep the crate dependency-free (see
// the module docs); pinned by the NIST vectors below.
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 digest of `data` (32 bytes).
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // Padding: 0x80, zeros, 64-bit big-endian bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // One million 'a' — the multi-block boundary vector.
        let million = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&sha256(&million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn strip_query_is_prefix_cut() {
        assert_eq!(
            strip_query("https://cdn.example/v/a.mp4?token=1&x=2"),
            "https://cdn.example/v/a.mp4"
        );
        assert_eq!(
            strip_query("https://cdn.example/v/a.mp4"),
            "https://cdn.example/v/a.mp4"
        );
        assert_eq!(strip_query(""), "");
    }

    #[test]
    fn variant_identity_display() {
        let id = variant_identity("h/a.m3u8?sig=zz", 500_000, Some((1280, 720)));
        assert_eq!(id.to_string(), "h/a.m3u8|500000|1280x720");
        let bare = variant_identity("h/a.m3u8", 1, None);
        assert_eq!(bare.to_string(), "h/a.m3u8|1|-");
    }
}

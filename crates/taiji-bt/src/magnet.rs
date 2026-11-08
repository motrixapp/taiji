//! magnet URI parsing (BEP9).
//!
//! Mechanism mirrors aria2 `src/magnet.cc` + `src/bittorrent_helper.cc`:
//! the `magnet:?` prefix is case-sensitive; parameters are split on `&` and
//! each is divided at its **first** `=` (no `=` means key + empty value);
//! values go through a lenient percent-decode (invalid `%` sequences kept
//! verbatim, `+` is not turned into a space); same-name parameters
//! accumulate into multi-value lists; `xt` is required and scanned for the
//! first valid btih / btmh; `tr` entries keep their order.
//!
//! `x.pe` syntax follows libtorrent `src/magnet_uri.cpp` +
//! `src/socket_io.cpp parse_endpoint`: IP literals only, no DNS, invalid
//! entries skipped leniently. Upstream anchors and the deliberate
//! tightenings over the references (single `x.pe` address, all-numeric
//! port, strict `so=`) are documented in `docs/design/peer-protocol.md`.

use std::collections::BTreeMap;
use thiserror::Error;

/// Parse error (mirrors aria2's explicit `MAGNET_PARSE_ERROR` branches;
/// BEP53 adds an `so=` syntax branch).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MagnetError {
    #[error("not a magnet URI (must start with `magnet:?`, case-sensitive; magnet.cc)")]
    NotMagnetUri,
    #[error("missing `xt` parameter (bittorrent_helper.cc)")]
    MissingXt,
    #[error("no valid btih/btmh found in `xt` (bittorrent_helper.cc)")]
    NoValidInfoHash,
    /// BEP53 `so=` syntax is invalid (explicitly rejected — the design
    /// forbids silent skipping).
    #[error("invalid `so=` parameter (BEP53): {0}")]
    InvalidSo(String),
}

/// Parsed magnet URI. Binary safe: `dn`/`tr` hold raw percent-decoded bytes
/// with no UTF-8 assumption (aria2 preserves invalid bytes via
/// encodeNonUtf8 — same semantics).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Magnet {
    /// `urn:btih:` (40 hex or 32 base32 chars; first valid value).
    pub btih: Option<[u8; 20]>,
    /// `urn:btmh:1220` + 64 hex (BEP52 multihash; first valid value).
    pub btmh: Option<[u8; 32]>,
    /// `dn` display name (first occurrence).
    pub dn: Option<Vec<u8>>,
    /// `xl` exact length (BEP9; first parseable value, ignored if
    /// unparseable — aria2 does not read this parameter).
    pub xl: Option<u64>,
    /// `tr` tracker URLs, in order of appearance.
    pub tr: Vec<Vec<u8>>,
    /// `x.pe` direct-connect peer endpoint; first valid value (same
    /// first-valid rule as the btih/btmh scan; invalid entries are skipped
    /// leniently — see the module docs).
    pub xpe: Option<std::net::SocketAddr>,
    /// `so=` BEP53 file selection: ranges expanded into a **strictly
    /// ascending**, zero-based index sequence (BEP53: "Files are
    /// zero-indexed"). The first `so` parameter wins (first value among
    /// same-name parameters, same rule as `dn`).
    pub so: Option<Vec<u32>>,
}

/// Parse a magnet URI (BEP9).
pub fn parse(input: &str) -> Result<Magnet, MagnetError> {
    let rest = input
        .strip_prefix("magnet:?")
        .ok_or(MagnetError::NotMagnetUri)?;

    // Multi-value collection: keys stay raw bytes (the reference does not
    // percent-decode keys).
    let mut params: BTreeMap<&[u8], Vec<Vec<u8>>> = BTreeMap::new();
    for part in rest.split('&') {
        let (key, value) = match part.find('=') {
            Some(i) => (&part.as_bytes()[..i], &part.as_bytes()[i + 1..]),
            None => (part.as_bytes(), &[] as &[u8]), // no `=` = empty value (reference divide semantics)
        };
        params.entry(key).or_default().push(percent_decode(value));
    }

    let xts = params.get(b"xt".as_slice()).ok_or(MagnetError::MissingXt)?;

    // Scan the xt values for the first valid btih / btmh (btih mirrors the
    // aria2 scan; btmh is the BEP52 extension, also first valid).
    let mut btih = None;
    let mut btmh = None;
    for xt in xts {
        if btih.is_none()
            && let Some(h) = parse_btih(xt)
        {
            btih = Some(h);
        }
        if btmh.is_none()
            && let Some(h) = parse_btmh(xt)
        {
            btmh = Some(h);
        }
    }
    if btih.is_none() && btmh.is_none() {
        return Err(MagnetError::NoValidInfoHash);
    }

    let dn = params
        .get(b"dn".as_slice())
        .and_then(|v| v.first().cloned());
    let xl = params
        .get(b"xl".as_slice())
        .and_then(|v| v.first())
        .and_then(|raw| std::str::from_utf8(raw).ok())
        .and_then(|s| s.parse::<u64>().ok());
    let tr = params.get(b"tr".as_slice()).cloned().unwrap_or_default();
    // `x.pe`: scan values for the first valid one; invalid entries are
    // skipped leniently; all invalid = None (no failure — same shape as
    // libtorrent magnet_uri.cpp).
    let xpe = params
        .get(b"x.pe".as_slice())
        .and_then(|vals| vals.iter().find_map(|raw| parse_xpe(raw)));
    // BEP53 `so=`: parsed strictly when present (syntax errors are explicit
    // — BEP53 itself defines no error surface, so the design tightens this
    // to "reject invalid explicitly"; silent skipping is forbidden). Ranges
    // are expanded to per-file indices here (BEP53: "Dashes mean inclusive
    // ranges").
    let so = match params.get(b"so".as_slice()).and_then(|v| v.first()) {
        Some(raw) => {
            let text =
                std::str::from_utf8(raw).map_err(|_| MagnetError::InvalidSo("not UTF-8".into()))?;
            Some(parse_so(text)?)
        }
        None => None,
    };

    Ok(Magnet {
        btih,
        btmh,
        dn,
        xl,
        tr,
        xpe,
        so,
    })
}

/// Upper bound on the expanded `so=` sequence (BEP53 file selection).
///
/// Provenance: BEP53 defines no length limit, but `so=` arrives inside a
/// magnet URI — semi-trusted input (any web page can hand the client a
/// magnet link) — and a 20-character `so=0-4294967295` would otherwise
/// eagerly expand to ~16 GiB of `u32` indices. This cap is a taiji-local
/// DoS bound (design tightening, documented in
/// `docs/design/peer-protocol.md` "Strict `so=`"): 2^20 entries ≈ 1M files
/// (far beyond any real torrent's file count) and 4 MiB of `u32` — the
/// same magnitude as the announce/mirror transfer-tier cap
/// [`crate::tracker::http::MAX_BODY_BYTES`]. Over-cap input is an explicit
/// [`MagnetError::InvalidSo`], never a silent truncation.
const MAX_SO_ENTRIES: u64 = 1 << 20;

/// BEP53 `so=` syntax.
///
/// # Syntax (BEP53)
///
/// Comma-separated file index items; each item is a decimal index
/// (zero-based) or an `N-M` **inclusive** range ("Dashes mean inclusive
/// ranges"); example `0,2,4,6-8`.
///
/// # Validation (design tightening: ascending check + explicit rejection)
///
/// - the expanded sequence must be **strictly ascending**: out of order
///   (`2,1`), duplicates (`0,0`), and overlapping or touching ranges
///   (`0-2,1-3`, `0-2,2-4`) are all rejected;
/// - empty strings/items (`0,,2`, trailing comma), non-decimal characters,
///   whitespace, signs, u32 overflow, and inverted ranges (`8-6`) are all
///   explicit errors;
/// - expansion is capped at [`MAX_SO_ENTRIES`] entries: a range that would
///   push the sequence past the cap is rejected **before** allocating.
///
/// BEP53 defines no ordering or error surface; this function tightens it by
/// design. The "append download to existing indices" behavior (BEP53 §3)
/// belongs to the session/task layer and is out of scope for this parser.
pub fn parse_so(input: &str) -> Result<Vec<u32>, MagnetError> {
    if input.is_empty() {
        return Err(MagnetError::InvalidSo("empty value".into()));
    }
    let mut out: Vec<u32> = Vec::new();
    for part in input.split(',') {
        let (start, end) = match part.split_once('-') {
            Some((a, b)) => (parse_index(a)?, Some(parse_index(b)?)),
            None => (parse_index(part)?, None),
        };
        if let Some(end) = end {
            if end < start {
                return Err(MagnetError::InvalidSo(format!(
                    "descending range {start}-{end}"
                )));
            }
            // Semi-trusted input: bound the eager expansion before
            // allocating (see MAX_SO_ENTRIES; the descending branch above
            // keeps its own error regardless of span).
            let span = u64::from(end) - u64::from(start) + 1;
            if out.len() as u64 + span > MAX_SO_ENTRIES {
                return Err(MagnetError::InvalidSo(format!(
                    "range {start}-{end} expands to {} entries over the {MAX_SO_ENTRIES} cap",
                    out.len() as u64 + span
                )));
            }
            for i in start..=end {
                push_ascending(&mut out, i)?;
            }
        } else {
            push_ascending(&mut out, start)?;
        }
    }
    Ok(out)
}

/// Single decimal index item (no whitespace, no sign, no leading `+`;
/// `u32::from_str` domain).
fn parse_index(s: &str) -> Result<u32, MagnetError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MagnetError::InvalidSo(format!("bad index {s:?}")));
    }
    s.parse::<u32>()
        .map_err(|e| MagnetError::InvalidSo(format!("index out of range: {e}")))
}

/// Strictly-ascending append (core of the order check; duplicates are
/// non-ascending and rejected too).
fn push_ascending(out: &mut Vec<u32>, index: u32) -> Result<(), MagnetError> {
    if out.last().is_some_and(|&last| index <= last) {
        return Err(MagnetError::InvalidSo(format!(
            "sequence not strictly ascending at {index}"
        )));
    }
    out.push(index);
    Ok(())
}

/// After `urn:btih:`: 40 hex chars (either case, util::fromHex semantics)
/// or 32 base32 chars (must decode to exactly 20 bytes).
fn parse_btih(xt: &[u8]) -> Option<[u8; 20]> {
    let tail = xt.strip_prefix(b"urn:btih:")?;
    if tail.len() == 40 {
        return hex_decode::<20>(tail);
    }
    if tail.len() == 32 {
        return base32_decode_20(tail);
    }
    None
}

/// `urn:btmh:` + multihash: 0x12 (sha256) 0x20 (32B) + 32 bytes (BEP52;
/// 68 hex chars; a wrong prefix is invalid).
fn parse_btmh(xt: &[u8]) -> Option<[u8; 32]> {
    let tail = xt.strip_prefix(b"urn:btmh:")?;
    let mh = hex_decode::<34>(tail)?;
    if mh[0] != 0x12 || mh[1] != 0x20 {
        return None;
    }
    // mh[2..] is always 32 bytes; the TryFromSliceError branch only avoids a
    // panicking conversion.
    mh[2..].try_into().ok()
}

/// Hex decode (either case; invalid characters/length -> None).
fn hex_decode<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = hex_val(s[2 * i])?;
        let lo = hex_val(s[2 * i + 1])?;
        *b = hi << 4 | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Base32 decode (RFC4648 alphabet A-Z2-7; for btih: exactly 32 chars ->
/// 20 bytes, length checked before decoding).
fn base32_decode_20(s: &[u8]) -> Option<[u8; 20]> {
    if s.len() != 32 {
        return None;
    }
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = [0u8; 20];
    let mut o = 0usize;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'2'..=b'7' => (c - b'2') as u32 + 26,
            _ => return None,
        };
        bits = bits << 5 | v;
        nbits += 5;
        if nbits >= 8 {
            out[o] = (bits >> (nbits - 8)) as u8;
            o += 1;
            nbits -= 8;
        }
    }
    debug_assert_eq!(o, 20, "32 base32 chars = 160 bits = 20 bytes");
    Some(out)
}

/// `x.pe` endpoint parsing (syntax follows libtorrent `socket_io.cpp
/// parse_endpoint`; see the module docs):
///
/// - the value has already been percent-decoded (magnet.cc decodes all
///   values); parsed here as UTF-8 text (non-UTF-8 = invalid, lenient
///   None);
/// - leading/trailing ASCII whitespace is trimmed;
/// - `[` prefix = IPv6: a `]` must close the bracket (missing = invalid),
///   followed immediately by `:port`; the address is parsed strictly as an
///   IPv6 literal;
/// - otherwise IPv4: the first `:` splits host/port; the address is parsed
///   strictly as an IPv4 literal — hosts are IP literals only, **no DNS**
///   (direct-connect semantics, same as the reference);
/// - the port must be all-decimal and in 1..=65535. One deliberate
///   tightening vs the reference: `atoi` accepts truncated trailing garbage
///   (`6881x` -> 6881); here the whole string must be numeric (direct
///   addresses do not tolerate dirty data).
fn parse_xpe(raw: &[u8]) -> Option<std::net::SocketAddr> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.trim_matches(|c: char| c.is_ascii_whitespace());
    if s.is_empty() {
        return None;
    }
    let (ip, port) = if let Some(rest) = s.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        (
            std::net::IpAddr::V6(addr.parse::<std::net::Ipv6Addr>().ok()?),
            parse_xpe_port(port)?,
        )
    } else {
        let (addr, port) = s.split_once(':')?;
        (
            std::net::IpAddr::V4(addr.parse::<std::net::Ipv4Addr>().ok()?),
            parse_xpe_port(port)?,
        )
    };
    Some(std::net::SocketAddr::new(ip, port))
}

/// `x.pe` port part: all-decimal digits, 1..=65535 (all-digits is this
/// parser's tightening, see [`parse_xpe`]).
fn parse_xpe_port(s: &str) -> Option<u16> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = s.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

/// Lenient percent-decode (util::percentDecode semantics): valid `%XX` is
/// decoded, invalid `%` sequences are kept verbatim, `+` is not turned into
/// a space.
fn percent_decode(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%'
            && i + 2 < raw.len()
            && let (Some(hi), Some(lo)) = (hex_val(raw[i + 1]), hex_val(raw[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex_literal<const N: usize>(b: [u8; N]) -> [u8; N] {
        b
    }

    /// Conformance vectors; provenance noted per case.
    #[test]
    fn conformance_vectors() {
        // Source: aria2 test/MagnetTest.cc testParse (xt / dn /
        // percent-encoded tr / multiple tr).
        let m = parse(
            "magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&dn=aria2\
             &tr=http%3A%2F%2Ftracker1&tr=http://tracker2",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            m.btih,
            Some(hex_literal([
                0x24, 0x8d, 0x0a, 0x1c, 0xd0, 0x82, 0x84, 0x29, 0x9d, 0xe7, 0x8d, 0x5c, 0x1e, 0xd3,
                0x59, 0xbb, 0x46, 0x71, 0x7d, 0x8c
            ]))
        );
        assert_eq!(m.dn.as_deref(), Some(b"aria2".as_slice()));
        assert_eq!(
            m.tr,
            vec![b"http://tracker1".to_vec(), b"http://tracker2".to_vec()]
        );

        // Source: aria2 test/MagnetTest.cc (non-magnet prefix -> parse
        // fails).
        assert!(matches!(
            parse("http://localhost"),
            Err(MagnetError::NotMagnetUri)
        ));
        // Case-sensitive prefix (magnet.cc startsWith).
        assert!(matches!(
            parse("MAGNET:?xt=urn:btih:"),
            Err(MagnetError::NotMagnetUri)
        ));
        // Bare "magnet:?" with no parameters -> missing xt.
        assert!(matches!(parse("magnet:?"), Err(MagnetError::MissingXt)));
        // xt missing while other parameters exist (bittorrent_helper.cc).
        assert!(matches!(
            parse("magnet:?dn=x&tr=http://t"),
            Err(MagnetError::MissingXt)
        ));
        // xt present but no valid hash.
        assert!(matches!(
            parse("magnet:?xt=urn:btih:zzzz&dn=x"),
            Err(MagnetError::NoValidInfoHash)
        ));
        // Parameter without `=` = key + empty value (xt="" -> no valid
        // hash).
        assert!(matches!(
            parse("magnet:?xt"),
            Err(MagnetError::NoValidInfoHash)
        ));

        // btih length boundaries: 39/41 hex are invalid (only 32/40 pass).
        assert!(matches!(
            parse("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d"),
            Err(MagnetError::NoValidInfoHash)
        ));
        assert!(matches!(
            parse("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8cff"),
            Err(MagnetError::NoValidInfoHash)
        ));
        // Uppercase hex accepted (util::fromHex semantics).
        let up = parse("magnet:?xt=urn:btih:248D0A1CD08284299DE78D5C1ED359BB46717D8C")
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(up.btih.is_some());

        // Source: BEP9 + hand samples — btmh (multihash 1220 = sha256/32B).
        let m2 = parse(
            "magnet:?xt=urn:btmh:12203da388b8b84c2a5be2af96f9a2de039f258a9ed45bdf1a219b4fcfc9c8a5885f",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            m2.btmh,
            Some(hex_literal([
                0x3d, 0xa3, 0x88, 0xb8, 0xb8, 0x4c, 0x2a, 0x5b, 0xe2, 0xaf, 0x96, 0xf9, 0xa2, 0xde,
                0x03, 0x9f, 0x25, 0x8a, 0x9e, 0xd4, 0x5b, 0xdf, 0x1a, 0x21, 0x9b, 0x4f, 0xcf, 0xc9,
                0xc8, 0xa5, 0x88, 0x5f
            ]))
        );
        // Wrong multihash code (1221 = sha2-512) -> invalid.
        assert!(matches!(
            parse(
                "magnet:?xt=urn:btmh:12213da388b8b84c2a5be2af96f9a2de039f258a9ed45bdf1a219b4fcfc9c8a5885f"
            ),
            Err(MagnetError::NoValidInfoHash)
        ));
        // Wrong length (1220 prefix but 63 hex chars).
        assert!(matches!(
            parse(
                "magnet:?xt=urn:btmh:12203da388b8b84c2a5be2af96f9a2de039f258a9ed45bdf1a219b4fcfc9c8a5885"
            ),
            Err(MagnetError::NoValidInfoHash)
        ));

        // Hybrid magnet: btih and btmh coexist.
        let hy = parse(
            "magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c\
             &xt=urn:btmh:12203da388b8b84c2a5be2af96f9a2de039f258a9ed45bdf1a219b4fcfc9c8a5885f",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(hy.btih.is_some() && hy.btmh.is_some());

        // Invalid first, then valid: the scan stops at the first valid
        // value.
        let mv =
            parse("magnet:?xt=urn:btih:bad&xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c")
                .unwrap_or_else(|e| panic!("{e}"));
        assert!(mv.btih.is_some());

        // Hand sample (implied by the reference semantics): a
        // percent-encoded xt value is decoded before URN matching
        // (magnet.cc percent-decodes values).
        let pe = parse("magnet:?xt=urn%3Abtih%3A248d0a1cd08284299de78d5c1ed359bb46717d8c")
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(pe.btih.is_some());

        // Hand sample — lenient percent-decode (util::percentDecode): `+`
        // is not a space; invalid % sequences kept verbatim.
        let len =
            parse("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&dn=a+b%zz100%20")
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(len.dn.as_deref(), Some(b"a+b%zz100 ".as_slice()));

        // xl: used when parseable; garbage ignored leniently (aria2 does
        // not read xl).
        let x1 = parse("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&xl=12345")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(x1.xl, Some(12345));
        let x2 = parse("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&xl=abc")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(x2.xl, None);

        // Empty tr value kept (value collection does no trimming).
        let e1 = parse("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&tr=")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(e1.tr, vec![Vec::<u8>::new()]);

        // Value containing `=`: split at the first `=` (magnet.cc divide).
        let q =
            parse("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&tr=http://t?x=1")
                .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(q.tr, vec![b"http://t?x=1".to_vec()]);

        // base32 form (BEP9; 32 chars -> 20B): base32 encoding of the same
        // hash as the 40-hex case (the encoder is test-side, the decoder is
        // the code under test -> equivalence check).
        let b32 = base32_encode_20(&hex_literal([
            0x24, 0x8d, 0x0a, 0x1c, 0xd0, 0x82, 0x84, 0x29, 0x9d, 0xe7, 0x8d, 0x5c, 0x1e, 0xd3,
            0x59, 0xbb, 0x46, 0x71, 0x7d, 0x8c,
        ]));
        let mb = parse(&format!("magnet:?xt=urn:btih:{b32}")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            mb.btih,
            Some(hex_literal([
                0x24, 0x8d, 0x0a, 0x1c, 0xd0, 0x82, 0x84, 0x29, 0x9d, 0xe7, 0x8d, 0x5c, 0x1e, 0xd3,
                0x59, 0xbb, 0x46, 0x71, 0x7d, 0x8c
            ]))
        );
        // Invalid base32 character ('1' is not in the alphabet) -> invalid.
        assert!(matches!(
            parse("magnet:?xt=urn:btih:1111111111111111111111111111111a"),
            Err(MagnetError::NoValidInfoHash)
        ));

        // Multiple dn -> first one (the reference takes list[0]).
        let md = parse(
            "magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&dn=first&dn=second",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(md.dn.as_deref(), Some(b"first".as_slice()));
    }

    // ---- BEP53 `so=` file selection vectors ----

    /// Valid forms: single index / inclusive range / mixed (BEP53 example
    /// `0,2,4,6-8`).
    #[test]
    fn bep53_so_valid_vectors() {
        let btih = "magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c";
        // (name, so= value, expected expanded sequence).
        let rows: Vec<(&str, &str, Vec<u32>)> = vec![
            ("single index", "0", vec![0]),
            ("single non-zero", "3", vec![3]),
            ("range", "2-4", vec![2, 3, 4]),
            ("inclusive single-range", "6-6", vec![6]),
            ("bep53 doc example", "0,2,4,6-8", vec![0, 2, 4, 6, 7, 8]),
            ("adjacent ranges", "0-1,3-4", vec![0, 1, 3, 4]),
        ];
        for (name, so, expect) in rows {
            let m = parse(&format!("{btih}&so={so}")).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(m.so, Some(expect), "{name}");
        }
        // No so= -> None.
        let m = parse(btih).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(m.so, None);
        // percent-decode leaves all-digit values intact (same value-decode
        // path).
        let m = parse(&format!("{btih}&so=%30%2C1")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(m.so, Some(vec![0, 1]));
        // First value among same-name parameters wins (same rule as dn).
        let m = parse(&format!("{btih}&so=0&so=1")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(m.so, Some(vec![0]));
    }

    /// Invalid forms: all **explicitly rejected** (design: silent skipping
    /// is forbidden).
    #[test]
    fn bep53_so_invalid_vectors() {
        let btih = "magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c";
        let rows: Vec<(&str, &str)> = vec![
            ("empty value", ""),
            ("empty item", "0,,2"),
            ("trailing comma", "0,1,"),
            ("leading comma", ",1"),
            ("whitespace", "0, 2"),
            ("negative", "-1"),
            ("plus sign", "+1"),
            ("non-digit", "a"),
            ("hex digit rejected", "0x2"),
            ("descending range", "8-6"),
            ("descending sequence", "2,1"),
            ("duplicate index", "0,0"),
            ("overlapping ranges", "0-2,1-3"),
            ("touching ranges (not ascending)", "0-2,2-4"),
            ("u32 overflow", "4294967296"),
            ("range with overflow", "0-99999999999"),
            ("range missing end", "1-"),
            ("range missing start", "-3"),
        ];
        for (name, so) in rows {
            let uri = format!("{btih}&so={so}");
            match parse(&uri) {
                Err(MagnetError::InvalidSo(reason)) => {
                    assert!(!reason.is_empty(), "{name}: empty reason");
                }
                other => panic!("{name}: expected InvalidSo, got {other:?}"),
            }
        }
    }

    /// Expansion cap ([`MAX_SO_ENTRIES`]): a range pushing the sequence
    /// past the cap is rejected before allocating — a 20-char
    /// `so=0-4294967295` would otherwise eagerly expand to ~16 GiB
    /// (magnet is semi-trusted input). Covers the single-range case, the
    /// cumulative across-ranges case, and the ordering contract that the
    /// descending-range error still wins over the cap.
    #[test]
    fn bep53_so_over_cap_range_rejected() {
        // Single range one entry over the cap (0..=cap is cap+1 entries).
        let over = format!("0-{MAX_SO_ENTRIES}");
        let Err(err) = parse_so(&over) else {
            panic!("one entry over the cap must be rejected");
        };
        assert!(
            matches!(err, MagnetError::InvalidSo(ref m) if m.contains("cap")),
            "got {err:?}"
        );
        // Cumulative: two individually legal ranges summing over the cap
        // (each half is <= cap, only the total crosses it).
        let half = MAX_SO_ENTRIES / 2;
        let Err(err) = parse_so(&format!("0-{},{half}-{MAX_SO_ENTRIES}", half - 1)) else {
            panic!("cumulative total over the cap must be rejected");
        };
        assert!(
            matches!(err, MagnetError::InvalidSo(ref m) if m.contains("cap")),
            "got {err:?}"
        );
        // Descending ranges keep their own error even at full span (the
        // descending branch precedes the cap check).
        let Err(err) = parse_so("4294967295-0") else {
            panic!("descending range must be rejected");
        };
        assert!(
            matches!(err, MagnetError::InvalidSo(ref m) if m.contains("descending")),
            "got {err:?}"
        );
        // The cap rejection surfaces through the full magnet parse too.
        let uri = format!("magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c&so={over}");
        assert!(matches!(parse(&uri), Err(MagnetError::InvalidSo(_))));
    }

    /// Expansion cap boundary: exactly [`MAX_SO_ENTRIES`] entries passes
    /// (the check is strictly `>`); the sequence is fully expanded and
    /// strictly ascending.
    #[test]
    fn bep53_so_cap_boundary_exact_passes() {
        assert_eq!(MAX_SO_ENTRIES, 1 << 20, "cap value pinned");
        let top = u32::try_from(MAX_SO_ENTRIES - 1).unwrap_or_else(|e| panic!("{e}"));
        let so = parse_so(&format!("0-{top}")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(so.len() as u64, MAX_SO_ENTRIES);
        assert_eq!(so[0], 0);
        assert_eq!(so[so.len() - 1], top);
        // Ascending spot checks (ends and around the middle).
        assert!(so[0] < so[1]);
        let mid = so.len() / 2;
        assert!(so[mid] < so[mid + 1]);
        // Two ranges summing to exactly the cap also pass (the boundary
        // holds under cumulative accounting: half-1 + (cap - half + 1)
        // = cap).
        let half = MAX_SO_ENTRIES / 2;
        let so2 = parse_so(&format!("0-{},{}-{top}", half - 2, half - 1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(so2.len() as u64, MAX_SO_ENTRIES);
    }

    // ---- `x.pe` direct endpoint vectors ----

    /// Valid forms: v4 / v6 (plain and percent-encoded) / trim / first
    /// valid of multiple values.
    #[test]
    fn xpe_parse_valid_vectors() {
        let btih = "magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c";
        // (name, x.pe value, expected endpoint). v6 expectations are built
        // from literals (parsing is the surface under test).
        let rows: Vec<(&str, &str, std::net::SocketAddr)> = vec![
            (
                "v4 host:port",
                "192.168.1.10:6881",
                "192.168.1.10:6881"
                    .parse()
                    .unwrap_or_else(|e| panic!("{e}")),
            ),
            (
                "v6 [addr]:port",
                "[2001:db8::1]:6881",
                "[2001:db8::1]:6881"
                    .parse()
                    .unwrap_or_else(|e| panic!("{e}")),
            ),
            (
                "v6 full-form address",
                "[2001:0db8:0000:0000:0000:0000:0000:0001]:51413",
                "[2001:db8::1]:51413"
                    .parse()
                    .unwrap_or_else(|e| panic!("{e}")),
            ),
            (
                "percent-encoded v4",
                "10.0.0.7%3A6882",
                "10.0.0.7:6882".parse().unwrap_or_else(|e| panic!("{e}")),
            ),
            (
                "percent-encoded v6 brackets",
                "%5Bfe80::1%5D:6883",
                "[fe80::1]:6883".parse().unwrap_or_else(|e| panic!("{e}")),
            ),
            (
                "trimmed whitespace (socket_io.cpp)",
                "  192.168.1.1:6881\t",
                "192.168.1.1:6881".parse().unwrap_or_else(|e| panic!("{e}")),
            ),
            (
                "port 65535 boundary",
                "1.2.3.4:65535",
                "1.2.3.4:65535".parse().unwrap_or_else(|e| panic!("{e}")),
            ),
        ];
        for (name, xpe, expect) in rows {
            let m = parse(&format!("{btih}&x.pe={xpe}")).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(m.xpe, Some(expect), "{name}");
        }

        // Multiple values, all valid -> first (same first-valid rule as the
        // btih scan).
        let m = parse(&format!("{btih}&x.pe=1.2.3.4:1&x.pe=5.6.7.8:2"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            m.xpe,
            Some("1.2.3.4:1".parse().unwrap_or_else(|e| panic!("{e}")))
        );
        // Multiple values, first invalid -> skipped leniently, next valid
        // wins.
        let m = parse(&format!("{btih}&x.pe=nope&x.pe=5.6.7.8:2&x.pe=9.9.9.9:x"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            m.xpe,
            Some("5.6.7.8:2".parse().unwrap_or_else(|e| panic!("{e}")))
        );
        // Empty x.pe and missing x.pe both yield None.
        let m = parse(&format!("{btih}&x.pe=")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(m.xpe, None);
        let m = parse(btih).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(m.xpe, None);
    }

    /// Invalid forms: all ignored leniently (None, no failure — same as
    /// libtorrent magnet_uri.cpp parse_endpoint continuing past failures).
    #[test]
    fn xpe_parse_invalid_lenient() {
        let btih = "magnet:?xt=urn:btih:248d0a1cd08284299de78d5c1ed359bb46717d8c";
        let rows: Vec<(&str, &str)> = vec![
            ("no port (v4)", "1.2.3.4"),
            ("no port (v6)", "[::1]"),
            ("v6 missing close bracket", "[::1:6881"),
            ("v6 nothing after bracket", "[::1]"),
            ("v6 missing colon before port", "[::1]6881"),
            ("port 0 (reference :148 port_num <= 0)", "1.2.3.4:0"),
            ("port overflow u16", "1.2.3.4:65536"),
            ("port non-numeric", "1.2.3.4:abc"),
            ("port empty", "1.2.3.4:"),
            // This parser's tightening: atoi-style trailing-garbage
            // truncation is not accepted (see parse_xpe).
            ("port trailing garbage", "1.2.3.4:6881x"),
            // Hosts are IP literals only: DNS names rejected (same as
            // make_address_v4/v6).
            ("dns hostname", "tracker.example.com:6881"),
            // Strict literals: IPv4 leading-zero octets rejected (inet_pton
            // semantics).
            ("leading-zero octet", "010.0.0.1:6881"),
            ("v4 host with garbage", "1.2.3.256:6881"),
            ("bare port only", ":6881"),
        ];
        for (name, xpe) in rows {
            let m = parse(&format!("{btih}&x.pe={xpe}")).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(m.xpe, None, "{name}: expected lenient None");
        }
        // All x.pe values invalid -> None but the parse still succeeds (a
        // valid xt is enough).
        let m = parse(&format!("{btih}&x.pe=a&x.pe=b")).unwrap_or_else(|e| panic!("{e}"));
        assert!(m.btih.is_some() && m.xpe.is_none());
    }

    // base32/hex form equivalence (BEP9): for any 20B hash, both forms
    // parse identically.
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(512))]

        #[test]
        fn base32_hex_equivalence(bytes in prop::collection::vec(any::<u8>(), 20)) {
            let hexs: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let b32 = base32_encode_20(&bytes);
            let a = parse(&format!("magnet:?xt=urn:btih:{hexs}"))
                .unwrap_or_else(|e| panic!("hex form: {e}"));
            let b = parse(&format!("magnet:?xt=urn:btih:{b32}"))
                .unwrap_or_else(|e| panic!("base32 form: {e}"));
            prop_assert_eq!(a.btih, b.btih, "hex {} vs base32 {}", hexs, b32);
        }
    }

    fn base32_encode_20(bytes: &[u8]) -> String {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        for chunk in bytes.chunks(5) {
            let mut buf = [0u8; 5];
            buf[..chunk.len()].copy_from_slice(chunk);
            let v = u64::from(buf[0]) << 32
                | u64::from(buf[1]) << 24
                | u64::from(buf[2]) << 16
                | u64::from(buf[3]) << 8
                | u64::from(buf[4]);
            for i in 0..8 {
                out.push(alphabet[(v >> (35 - 5 * i)) as usize & 0x1f] as char);
            }
        }
        out
    }
}

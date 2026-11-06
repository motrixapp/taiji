//! HTTP authentication challenge/response surface (Basic/Digest).
//!
//! Credentials from [`crate::traits::AuthScheme`] serve both schemes:
//! Basic is preset at the client layer and the 401 `WWW-Authenticate`
//! Digest challenge is answered here (mirroring aria2 `DigestAuth.cc`).
//! Digest per RFC 7616 §3.3: MD5 (legacy-server baseline) and SHA-256;
//! `-sess` variants, `userhash`, and `auth-int` are rejected explicitly,
//! never silently downgraded. qop="auth" (with nc/cnonce) and RFC 2069
//! legacy (no qop) are both supported. MD5 is hand-rolled (RFC 1321,
//! pinned test vectors) and used only for Digest responses.
//!
//! Upstream anchor mapping: docs/design/http.md

use std::fmt::Write as _;

use crate::error::HttpError;

/// Authentication credentials (`--http-user/--http-passwd`; shared by Basic/Digest).
///
/// `Debug` is hand-written and redacting: the `passwd` never enters the
/// diagnostic face (logs, panic messages), only the `user` is printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub user: String,
    pub passwd: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("passwd", &"REDACTED")
            .finish()
    }
}

impl Credentials {
    /// Extract from [`crate::traits::AuthScheme`] (both variants equal —
    /// aria2 serves both challenges from the same option; `DigestAuth.cc`).
    pub fn from_scheme(scheme: &crate::traits::AuthScheme) -> Credentials {
        use crate::traits::AuthScheme as A;
        match scheme {
            A::Basic { user, passwd } | A::Digest { user, passwd } => Credentials {
                user: user.clone(),
                passwd: passwd.clone(),
            },
        }
    }
}

/// Parsed 401 `WWW-Authenticate` challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Challenge {
    /// `Basic` scheme recognized (a Basic challenge's `realm` auth-param
    /// is **not** recorded — this is a unit variant carrying no data;
    /// Basic answers are preset from `--http-user/--http-passwd` and
    /// never consult the realm. Only the Digest variant carries
    /// parameters).
    Basic,
    /// Digest challenge parameters (missing required items = `None`; error at response time).
    Digest(DigestChallenge),
}

/// Digest challenge parameters (RFC 7616 §3.3 `WWW-Authenticate` fields).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DigestChallenge {
    pub realm: Option<String>,
    pub nonce: Option<String>,
    /// qop option list (the server may send several, `"auth,auth-int"`).
    pub qop: Option<Vec<String>>,
    pub opaque: Option<String>,
    /// `algorithm` token (default MD5, the RFC 7616 §3.3 backward-compatible default).
    pub algorithm: Option<String>,
    /// `stale=true`: only the nonce expired (credentials verified — just respond again).
    pub stale: bool,
    /// `userhash` (RFC 7616 §3.4.4) unsupported — explicitly rejected.
    pub userhash: bool,
}

/// Parse a `WWW-Authenticate` header value into a challenge list
/// (RFC 9110 §11.6.1 `#challenge` list grammar: one header may carry
/// several challenges, e.g. `Basic realm="a", Newauth realm="b"`).
/// Order of appearance is preserved; unrecognized scheme segments are
/// dropped (all unrecognized = empty list; the caller treats that as
/// no challenge).
pub fn parse_www_authenticate(value: &str) -> Vec<Challenge> {
    split_challenge_list(value)
        .into_iter()
        .filter_map(parse_challenge_segment)
        .collect()
}

/// Split the challenge list: a comma separates challenges and
/// auth-params alike (RFC 9110 §11.6.1 + §11.2), so the boundary
/// heuristic is "a comma followed by a bare token NOT followed by
/// `=`" — `token=` is a parameter name (its value may be a
/// quoted-string whose commas/quotes do not participate in the
/// split); a bare token followed by whitespace/`,`/end starts a new
/// auth-scheme (challenge = auth-scheme [ 1*SP ( token68 /
/// #auth-param ) ] — the scheme form carries no `=`).
fn split_challenge_list(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut in_quotes = false;
    while i < bytes.len() {
        match bytes[i] {
            // quoted-pair (RFC 9110 §5.6.4): escaped characters
            // (including `"`/`,`) do not participate in the split.
            b'\\' if in_quotes && i + 1 < bytes.len() => {
                i += 2;
                continue;
            }
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes && starts_new_challenge(&bytes[i + 1..]) => {
                segments.push(value[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = value[start..].trim();
    if !tail.is_empty() {
        segments.push(tail);
    }
    segments
}

/// Whether the text after a comma starts a new challenge: skip OWS,
/// take the first token; if it is not followed (after BWS) by `=` it
/// is an auth-scheme — an auth-param is always `token BWS "="`.
fn starts_new_challenge(rest: &[u8]) -> bool {
    let mut i = 0;
    while i < rest.len() && (rest[i] as char).is_whitespace() {
        i += 1;
    }
    // `=`/`,`/`"` cannot start a token: empty or malformed suffixes
    // are treated as not-a-new-challenge (the param parser tolerates
    // them).
    if i >= rest.len() || matches!(rest[i], b'=' | b',' | b'"') {
        return false;
    }
    while i < rest.len()
        && !matches!(rest[i], b'=' | b',' | b'"')
        && !(rest[i] as char).is_whitespace()
    {
        i += 1;
    }
    while i < rest.len() && (rest[i] as char).is_whitespace() {
        i += 1;
    }
    !matches!(rest.get(i), Some(b'='))
}

/// Parse one challenge segment: `scheme` / `scheme 1*SP auth-params`
/// (the token68 form carries no params for Basic/Digest and is
/// treated as a parameterless challenge). Unrecognized scheme → None.
fn parse_challenge_segment(segment: &str) -> Option<Challenge> {
    let (scheme, rest) = match segment.split_once(' ') {
        Some((s, r)) => (s, r.trim_start()),
        None => (segment, ""),
    };
    match scheme.trim().to_ascii_lowercase().as_str() {
        "basic" => Some(Challenge::Basic),
        "digest" => {
            let mut c = DigestChallenge::default();
            for (k, v) in parse_auth_params(rest) {
                match k.to_ascii_lowercase().as_str() {
                    "realm" => c.realm = Some(v),
                    "nonce" => c.nonce = Some(v),
                    "qop" => {
                        // The qop value may be a quoted "auth,auth-int" list.
                        c.qop = Some(v.split(',').map(|s| s.trim().to_string()).collect());
                    }
                    "opaque" => c.opaque = Some(v),
                    "algorithm" => c.algorithm = Some(v),
                    "stale" => c.stale = v.eq_ignore_ascii_case("true"),
                    "userhash" => c.userhash = v.eq_ignore_ascii_case("true"),
                    _ => {} // Unknown params ignored (RFC 7616 §3.3 forward compatibility).
                }
            }
            Some(Challenge::Digest(c))
        }
        _ => None,
    }
}

/// auth-param list parsing (RFC 9110 §11.2): `token "=" (token |
/// quoted-string)`, comma-separated; quoted-string supports
/// backslash escape pairs. Quoted values are decoded as UTF-8 (lossy)
/// — the header layer already handed over lossy UTF-8 (client.rs
/// `on_unauthorized`), so a byte-by-byte `u8 as char` Latin-1 misread
/// (e.g. `café` -> `cafÃ©`) must not corrupt realm/nonce.
fn parse_auth_params(rest: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Parameter name (token: up to ',' or '=').
        let name_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        let name = rest[name_start..i].trim().to_string();
        if i >= bytes.len() || bytes[i] == b',' {
            if !name.is_empty() {
                out.push((name, String::new()));
            }
            i += 1;
            continue;
        }
        i += 1; // '='
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        let value = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            // Collect quoted-string bytes raw and decode once at the
            // end: `u8 as char` would Latin-1-misread multi-byte UTF-8
            // (realm="café" -> "cafÃ©" mojibake) and the Digest
            // response would echo a realm the server never sent. A
            // quoted-pair keeps the escaped byte verbatim (RFC 9110
            // §5.6.4), so escapes stay ASCII-transparent.
            let mut v = Vec::new();
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' if i + 1 < bytes.len() => {
                        v.push(bytes[i + 1]);
                        i += 2;
                    }
                    b'"' => {
                        i += 1;
                        break;
                    }
                    b => {
                        v.push(b);
                        i += 1;
                    }
                }
            }
            String::from_utf8_lossy(&v).into_owned()
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            rest[start..i].trim().to_string()
        };
        if !name.is_empty() {
            out.push((name, value));
        }
        while i < bytes.len() && bytes[i] != b',' {
            i += 1;
        }
        i += 1; // skip comma
    }
    out
}

/// Digest algorithm values (the `algorithm` parameter; default MD5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestHash {
    Md5,
    Sha256,
}

impl DigestHash {
    fn parse(v: Option<&str>) -> Result<DigestHash, HttpError> {
        match v.map(|s| s.trim().to_ascii_uppercase()) {
            None => Ok(DigestHash::Md5), // RFC 7616: default MD5 (backward compatible)
            Some(a) if a == "MD5" => Ok(DigestHash::Md5),
            Some(a) if a == "SHA-256" => Ok(DigestHash::Sha256),
            Some(other) => Err(HttpError::AuthFailed(format!(
                "unsupported digest algorithm {other:?} (MD5|SHA-256; -sess variants rejected)"
            ))),
        }
    }

    fn h(self, data: &[u8]) -> String {
        match self {
            DigestHash::Md5 => md5_hex(data),
            DigestHash::Sha256 => {
                use sha2::Digest as _;
                let mut h = sha2::Sha256::new();
                sha2::Digest::update(&mut h, data);
                hex_lower(&sha2::Digest::finalize(h))
            }
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Assemble the RFC 7616 §3.4 Digest `Authorization` value.
///
/// `nc` = request counter for the nonce (1-based, 8 hex digits);
/// `cnonce` is caller-supplied randomness. `uri` = the request-target
/// path (with query, matching the request line).
pub fn respond_digest(
    challenge: &DigestChallenge,
    creds: &Credentials,
    uri: &str,
    nc: u32,
    cnonce: &str,
) -> Result<String, HttpError> {
    let hash = DigestHash::parse(challenge.algorithm.as_deref())?;
    let nonce = challenge
        .nonce
        .clone()
        .ok_or_else(|| HttpError::AuthFailed("digest challenge without nonce".into()))?;
    if challenge.userhash {
        return Err(HttpError::AuthFailed(
            "digest userhash=true challenges are not supported".into(),
        ));
    }
    let realm = challenge.realm.as_deref().unwrap_or("");
    let ha1_src = format!("{}:{}:{}", creds.user, realm, creds.passwd);
    let ha2_src = format!("GET:{uri}");
    let qop_opt = challenge.qop.as_ref().map(|list| {
        list.iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });
    let nc_hex = format!("{nc:08x}");

    // qop selection: auth preferred; auth-int explicitly rejected;
    // no qop = RFC 2069 legacy.
    let (response, qop_field) = match qop_opt.as_deref() {
        None | Some([]) => {
            let src = format!(
                "{}:{}:{}",
                hash.h(ha1_src.as_bytes()),
                nonce,
                hash.h(ha2_src.as_bytes())
            );
            (hash.h(src.as_bytes()), None)
        }
        Some(list) => {
            // auth-int only (no auth option) = needs body re-hashing →
            // explicit reject; a mixed list is answered as auth
            // (RFC 7616 §3.4 client choice).
            if list.iter().any(|q| q.eq_ignore_ascii_case("auth-int"))
                && !list.iter().any(|q| q.eq_ignore_ascii_case("auth"))
            {
                return Err(HttpError::AuthFailed(
                    "digest qop=auth-int requires body hashing; not supported".into(),
                ));
            }
            let src = format!(
                "{}:{}:{}:{}:auth:{}",
                hash.h(ha1_src.as_bytes()),
                nonce,
                nc_hex,
                cnonce,
                hash.h(ha2_src.as_bytes())
            );
            (hash.h(src.as_bytes()), Some("auth"))
        }
    };

    // Assemble (RFC 7616 §3.4 field order; opaque passed through verbatim).
    let mut out = String::from("Digest ");
    let _ = write!(out, "username=\"{}\"", quote(creds.user.as_str()));
    let _ = write!(out, ", realm=\"{}\"", quote(realm));
    let _ = write!(out, ", nonce=\"{}\"", quote(nonce.as_str()));
    let _ = write!(out, ", uri=\"{}\"", quote(uri));
    if let Some(qop) = qop_field {
        let _ = write!(out, ", qop={qop}");
        let _ = write!(out, ", nc={nc_hex}");
        let _ = write!(out, ", cnonce=\"{}\"", quote(cnonce));
    }
    let _ = write!(out, ", response=\"{response}\"");
    let alg = match hash {
        DigestHash::Md5 => "MD5",
        DigestHash::Sha256 => "SHA-256",
    };
    let _ = write!(out, ", algorithm={alg}");
    if let Some(opaque) = &challenge.opaque {
        let _ = write!(out, ", opaque=\"{}\"", quote(opaque));
    }
    Ok(out)
}

/// Client nonce (Digest `cnonce`, RFC 7616 §3.3 client-challenge).
/// OS entropy (rand thread_rng) mixed with a monotonic counter, 32
/// hex chars — unpredictability comes from the OS entropy; the
/// counter only resolves same-nanosecond collisions.
pub fn fresh_cnonce() -> String {
    // rand 0.10: fill_bytes is a default method of `Rng` (the root
    // `RngCore` re-export was removed).
    use rand::Rng as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut rng = rand::rng();
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    rng.fill_bytes(&mut a);
    rng.fill_bytes(&mut b);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let (x, y) = (u64::from_le_bytes(a) ^ seq, u64::from_le_bytes(b));
    format!("{x:016x}{y:016x}")
}

/// quoted-string escaping (only `"` and `\`; RFC 9110 §5.6.4).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ---- RFC 1321 MD5 (hand-rolled; used only for Digest auth responses) ----

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// RFC 1321 §3.4 T table: `floor(abs(sin(i+1)) * 2^32)` (i = 0..64).
const K: [u32; 64] = {
    let mut k = [0u32; 64];
    let mut i = 0;
    while i < 64 {
        // A compile-time f64 approximation would drift the vectors —
        // use the precomputed table (RFC verbatim values).
        k[i] = T[i];
        i += 1;
    }
    k
};

/// RFC 1321 T table, verbatim values (same source as the Appendix
/// 5.4 reference implementation).
#[rustfmt::skip]
const T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// MD5 digest (16 bytes). Algorithm per RFC 1321 §3.4
/// (Merkle-Damgård, little-endian word encoding).
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Padding: 0x80 + zeros to a 56 mod 64 length + the original bit
    // length (u64 LE).
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f2 = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f2.rotate_left(S[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// MD5 lowercase hex (for the Digest response field).
pub fn md5_hex(data: &[u8]) -> String {
    hex_lower(&md5(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1321 §A.5 test vectors (pin the hand-rolled implementation
    /// byte for byte).
    #[test]
    fn md5_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    /// auth-param parsing: quoted escapes, token values, valueless
    /// params, empty segments.
    #[test]
    fn auth_params_parse_matrix() {
        let ps = parse_auth_params(
            r#"realm="t\", x", nonce="abc", qop="auth, auth-int", opaque=OP, stale=true"#,
        );
        assert_eq!(
            ps,
            vec![
                ("realm".to_string(), "t\", x".to_string()),
                ("nonce".to_string(), "abc".to_string()),
                ("qop".to_string(), "auth, auth-int".to_string()),
                ("opaque".to_string(), "OP".to_string()),
                ("stale".to_string(), "true".to_string()),
            ]
        );
    }

    /// Non-ASCII quoted-string values (P0.5): the 401 header reaches
    /// `parse_auth_params` as lossy UTF-8 (client.rs `on_unauthorized`),
    /// so quoted content must be decoded as UTF-8 — a byte-wise
    /// `u8 as char` would Latin-1-misread it (`café` -> `cafÃ©`) and
    /// the Digest response would echo a realm the server never sent.
    #[test]
    fn auth_params_quoted_string_utf8_roundtrip() {
        let ps = parse_auth_params(r#"realm="café", nonce="n1""#);
        assert_eq!(
            ps,
            vec![
                ("realm".to_string(), "café".to_string()),
                ("nonce".to_string(), "n1".to_string()),
            ]
        );
        // Round trip through the full challenge -> response surface:
        // escaped multi-byte quoted-pairs stay verbatim (`\é` -> `é`),
        // and the response header echoes the server's realm bytes.
        let cs = parse_www_authenticate(r#"Digest realm="caf\é", nonce="naïve", qop="auth""#);
        match cs.as_slice() {
            [Challenge::Digest(c)] => {
                assert_eq!(c.realm.as_deref(), Some("café"));
                assert_eq!(c.nonce.as_deref(), Some("naïve"));
                let creds = Credentials {
                    user: "u".into(),
                    passwd: "p".into(),
                };
                let header =
                    respond_digest(c, &creds, "/f", 1, "cn").unwrap_or_else(|e| panic!("{e}"));
                assert!(header.contains(r#"realm="café""#), "{header}");
            }
            other => panic!("expected digest: {other:?}"),
        }
    }

    /// Challenge parsing: Basic / full Digest params / unknown scheme.
    #[test]
    fn www_authenticate_parse_matrix() {
        assert_eq!(
            parse_www_authenticate("Basic realm=\"walled garden\""),
            vec![Challenge::Basic]
        );
        let d = parse_www_authenticate(
            r#"Digest realm="t", nonce="n1", qop="auth", algorithm=SHA-256, opaque="o", stale=TRUE"#,
        );
        match d.as_slice() {
            [Challenge::Digest(c)] => {
                assert_eq!(c.realm.as_deref(), Some("t"));
                assert_eq!(c.nonce.as_deref(), Some("n1"));
                assert_eq!(c.qop, Some(vec!["auth".to_string()]));
                assert_eq!(c.algorithm.as_deref(), Some("SHA-256"));
                assert_eq!(c.opaque.as_deref(), Some("o"));
                assert!(c.stale);
            }
            other => panic!("expected digest: {other:?}"),
        }
        assert_eq!(parse_www_authenticate("Negotiate xyz"), Vec::new());
    }

    /// Multiple challenges in one header (RFC 9110 §11.6.1 `#challenge`
    /// list and its example): a bare token after a comma (not followed
    /// by `=`) starts a new scheme; `token=` is a parameter name;
    /// commas/escaped quotes inside quoted-strings do not delimit.
    #[test]
    fn www_authenticate_multi_challenge_single_header() {
        // Both challenges of a single header must parse, even with
        // Digest last.
        let cs = parse_www_authenticate(
            "Basic realm=\"a\", Digest realm=\"b\", nonce=\"n\", qop=\"auth\"",
        );
        match cs.as_slice() {
            [Challenge::Basic, Challenge::Digest(c)] => {
                assert_eq!(c.realm.as_deref(), Some("b"));
                assert_eq!(c.nonce.as_deref(), Some("n"));
                assert_eq!(c.qop, Some(vec!["auth".to_string()]));
            }
            other => panic!("expected [basic, digest]: {other:?}"),
        }
        // RFC 9110 §11.6.1 example verbatim: the unknown scheme's
        // param list (type=1, title with escaped quotes and a comma)
        // must not be mis-split; Basic parses in the second segment.
        let cs = parse_www_authenticate(
            "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\", ok\", Basic realm=\"simple\"",
        );
        assert_eq!(cs, vec![Challenge::Basic]);
        // A quoted Digest param value containing a comma must not be
        // mis-split into a new challenge.
        let cs = parse_www_authenticate("Digest realm=\"r, x\", nonce=\"n\"");
        match cs.as_slice() {
            [Challenge::Digest(c)] => assert_eq!(c.realm.as_deref(), Some("r, x")),
            other => panic!("expected single digest: {other:?}"),
        }
        // Bare scheme (no params): recognized schemes still form
        // challenges; unknown ones are dropped.
        assert_eq!(parse_www_authenticate("Basic"), vec![Challenge::Basic]);
        assert_eq!(parse_www_authenticate("Negotiate"), Vec::new());
        // BWS tolerance: `token BWS "="` (space after the param name)
        // is still a param, not a new scheme.
        let cs = parse_www_authenticate("Digest realm=\"t\", nonce = \"n\"");
        match cs.as_slice() {
            [Challenge::Digest(c)] => assert_eq!(c.nonce.as_deref(), Some("n")),
            other => panic!("expected single digest with bws: {other:?}"),
        }
    }

    /// Digest response value: cross-validation against the RFC 7616
    /// §3.9.1 example formula — MD5/auth, intermediates recomputed
    /// independently.
    #[test]
    fn digest_response_matches_reference_formula() {
        let challenge = DigestChallenge {
            realm: Some("http-auth@example.org".into()),
            nonce: Some("7ypf/xlj9XXwfDPEoM4QURQ==".into()),
            qop: Some(vec!["auth".into()]),
            opaque: None,
            algorithm: Some("MD5".into()),
            stale: false,
            userhash: false,
        };
        let creds = Credentials {
            user: "Mufasa".into(),
            passwd: "Circle Of Life".into(),
        };
        let uri = "/dir/index.html";
        let nc = 1;
        let cnonce = "f2/wE4q74E6zIJktWaCkhQ==";
        let header =
            respond_digest(&challenge, &creds, uri, nc, cnonce).unwrap_or_else(|e| panic!("{e}"));
        // Reference (same formula as the RFC 7616 §3.9.1 MD5 example):
        // HA1 = H(user:realm:pass), HA2 = H(GET:uri),
        // response = H(HA1:nonce:nc:cnonce:qop:HA2).
        let ha1 = md5_hex(b"Mufasa:http-auth@example.org:Circle Of Life");
        let ha2 = md5_hex(b"GET:/dir/index.html");
        let expected = md5_hex(
            format!("{ha1}:7ypf/xlj9XXwfDPEoM4QURQ==:00000001:{cnonce}:auth:{ha2}").as_bytes(),
        );
        assert!(
            header.contains(&format!("response=\"{expected}\"")),
            "header: {header}"
        );
        assert!(header.contains("qop=auth"), "{header}");
        assert!(header.contains("nc=00000001"), "{header}");
        assert!(header.contains("algorithm=MD5"), "{header}");
    }

    /// RFC 2069 legacy (no qop): response = H(HA1:nonce:HA2), no
    /// qop/nc/cnonce fields in the header.
    #[test]
    fn digest_response_rfc2069_legacy_shape() {
        let challenge = DigestChallenge {
            realm: Some("r".into()),
            nonce: Some("n".into()),
            qop: None,
            opaque: None,
            algorithm: None, // default = MD5
            stale: false,
            userhash: false,
        };
        let creds = Credentials {
            user: "u".into(),
            passwd: "p".into(),
        };
        let header =
            respond_digest(&challenge, &creds, "/f.bin", 1, "c").unwrap_or_else(|e| panic!("{e}"));
        let ha1 = md5_hex(b"u:r:p");
        let ha2 = md5_hex(b"GET:/f.bin");
        let expected = md5_hex(format!("{ha1}:n:{ha2}").as_bytes());
        assert!(
            header.contains(&format!("response=\"{expected}\"")),
            "{header}"
        );
        assert!(!header.contains("qop="), "{header}");
        assert!(!header.contains("nc="), "{header}");
    }

    /// Explicit rejection of unsupported features: -sess algorithms,
    /// auth-int-only qop, userhash, missing nonce.
    #[test]
    fn digest_unsupported_faces_rejected() {
        let creds = Credentials {
            user: "u".into(),
            passwd: "p".into(),
        };
        let mut c = DigestChallenge {
            realm: Some("r".into()),
            nonce: Some("n".into()),
            qop: None,
            opaque: None,
            algorithm: Some("MD5-sess".into()),
            stale: false,
            userhash: false,
        };
        assert!(respond_digest(&c, &creds, "/f", 1, "cn").is_err());
        c.algorithm = Some("SHA-256-sess".into());
        assert!(respond_digest(&c, &creds, "/f", 1, "cn").is_err());
        c.algorithm = Some("MD5".into());
        c.qop = Some(vec!["auth-int".into()]);
        assert!(respond_digest(&c, &creds, "/f", 1, "cn").is_err());
        c.qop = Some(vec!["auth".into()]);
        c.userhash = true;
        assert!(respond_digest(&c, &creds, "/f", 1, "cn").is_err());
        c.userhash = false;
        c.nonce = None;
        assert!(respond_digest(&c, &creds, "/f", 1, "cn").is_err());
    }

    /// SHA-256 spot check: the header carries algorithm=SHA-256 and
    /// the response matches an independent sha2 recomputation (same
    /// formula, RFC 7616 §3.4.2).
    #[test]
    fn digest_response_sha256() {
        use sha2::Digest as _;
        let challenge = DigestChallenge {
            realm: Some("r".into()),
            nonce: Some("n".into()),
            qop: Some(vec!["auth".into()]),
            opaque: None,
            algorithm: Some("SHA-256".into()),
            stale: false,
            userhash: false,
        };
        let creds = Credentials {
            user: "u".into(),
            passwd: "p".into(),
        };
        let header =
            respond_digest(&challenge, &creds, "/f.bin", 7, "cn").unwrap_or_else(|e| panic!("{e}"));
        let h = |b: &[u8]| {
            let mut d = sha2::Sha256::new();
            sha2::Digest::update(&mut d, b);
            hex_lower(&sha2::Digest::finalize(d))
        };
        let ha1 = h(b"u:r:p");
        let ha2 = h(b"GET:/f.bin");
        let expected = h(format!("{ha1}:n:00000007:cn:auth:{ha2}").as_bytes());
        assert!(header.contains("algorithm=SHA-256"), "{header}");
        assert!(
            header.contains(&format!("response=\"{expected}\"")),
            "{header}"
        );
    }
}

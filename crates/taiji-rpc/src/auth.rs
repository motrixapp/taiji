//! RPC authentication surface: the `token:` first parameter and HTTP
//! Basic.
//!
//! Mechanism: token stripping/validation mirrors aria2; Basic folds
//! secrets into HMAC tags at construction and compares constant-time.
//! Upstream anchor mapping: docs/design/rpc.md
//!
//! Hard invariants: plaintext secrets never linger (Basic stores only
//! HMAC tags); secrets never appear in logs or Debug output; secret
//! comparison is constant-time over fixed-length digests.

use serde_json::Value;
// sha1::Digest and sha2::Digest are both RustCrypto `digest::Digest` —
// one import enables chain_update/finalize/digest for both hashes.
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::base64;

/// HMAC-SHA1 input block length (RFC 2104; same value as aria2
/// `getBlockSize("sha-1")`).
const HMAC_BLOCK: usize = 64;
/// SHA-1 digest length (same source as the util_security.cc random key
/// length).
const TAG_LEN: usize = 20;
/// SHA-256 digest length (the fixed-length folding surface for the
/// token constant-time compare, see [`validate`]).
const DIGEST_LEN: usize = 32;

/// In-process random-key HMAC-SHA1. The instance holds only ipad/opad
/// (key XOR constants); the raw random key is dropped immediately —
/// same shape as util_security.cc.
pub(crate) struct RandomHmac {
    ipad: [u8; HMAC_BLOCK],
    opad: [u8; HMAC_BLOCK],
}

impl RandomHmac {
    /// Random key = digest length (createRandom, util_security.cc);
    /// key <= block length, so the direct-fill branch applies
    /// (util_security.cc).
    pub(crate) fn new() -> Self {
        let key: [u8; TAG_LEN] = rand::random();
        let mut ipad = [0x36u8; HMAC_BLOCK];
        let mut opad = [0x5cu8; HMAC_BLOCK];
        for (i, &k) in key.iter().enumerate() {
            ipad[i] ^= k;
            opad[i] ^= k;
        }
        RandomHmac { ipad, opad }
    }

    /// HMAC(ipad||data) then HMAC(opad||inner) (RFC 2104; aria2 uses the
    /// same shape via the reset/update/getResult chain,
    /// util_security.cc).
    pub(crate) fn tag(&self, data: &[u8]) -> [u8; TAG_LEN] {
        let inner: [u8; TAG_LEN] = Sha1::new()
            .chain_update(self.ipad)
            .chain_update(data)
            .finalize()
            .into();
        Sha1::new()
            .chain_update(self.opad)
            .chain_update(inner)
            .finalize()
            .into()
    }
}

/// Constant-time compare of fixed-length tags (byte XOR fold, aria2
/// util_security.h util::compare; equal tag lengths are guaranteed by
/// the types — the reference's throw-on-mismatched-length defense for
/// HMACResult does not apply here). Generalized fixed-length: shared by
/// the HMAC tag (TAG_LEN) and the token digest (DIGEST_LEN).
fn ct_eq<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// HTTP Basic authentication. After construction, plaintext
/// user/passwd never lingers in this struct.
pub struct BasicAuth {
    hmac: RandomHmac,
    username_tag: [u8; TAG_LEN],
    /// None = no --rpc-passwd set: the password is not checked (aria2
    /// HttpServer.cc `!password_ ||`).
    password_tag: Option<[u8; TAG_LEN]>,
}

impl std::fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets never enter Debug/logs: only the configuration shape
        // is exposed.
        f.debug_struct("BasicAuth")
            .field("password_checked", &self.password_tag.is_some())
            .finish_non_exhaustive()
    }
}

impl BasicAuth {
    /// Same shape as setUsernamePassword (aria2 HttpServer.cc): empty
    /// string = unset (the reference `option->get` returns "" when
    /// undefined; the empty-string reset branch); user empty/unset ->
    /// Basic auth disabled entirely (None; the reference
    /// `username_.reset()`, authenticate() `if (!username_) return
    /// true`).
    pub fn new(user: Option<&str>, passwd: Option<&str>) -> Option<Self> {
        let user = user.filter(|s| !s.is_empty())?;
        let hmac = RandomHmac::new();
        let username_tag = hmac.tag(user.as_bytes());
        let password_tag = passwd
            .filter(|p| !p.is_empty())
            .map(|p| hmac.tag(p.as_bytes()));
        Some(BasicAuth {
            hmac,
            username_tag,
            password_tag,
        })
    }

    /// Whether the password slot is set (server composition guard
    /// decision surface): user-only Basic (--rpc-user set, --rpc-passwd
    /// unset) does not check the password (aria2 HttpServer.cc
    /// `!password_ ||`) — knowing just the username passes the Basic
    /// gate, which must not count as a valid credential under
    /// listen_all.
    pub(crate) fn password_is_set(&self) -> bool {
        self.password_tag.is_some()
    }

    /// Direct translation of authenticate() (aria2 HttpServer.cc).
    /// `header` = the Authorization header value (None = header missing
    /// -> always false).
    pub fn authorize(&self, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        // divide(header, ' ') (default strip=true, util.h): split at the
        // first space and trim both sides; no space -> the whole text is
        // the scheme, credentials empty.
        let header = header.trim();
        let (scheme, cred) = match header.find(' ') {
            Some(i) => (&header[..i], header[i + 1..].trim()),
            None => (header, ""),
        };
        // streq(.., "Basic") is case-sensitive (util.h,
        // character-by-character including length).
        if scheme != "Basic" {
            return false;
        }
        // base64::decode strictness: invalid credentials = auth failure
        // (with aria2's lenient decode the garbage would equally fail
        // the tag compare — semantically equivalent).
        let Some(userpass) = base64::decode(cred) else {
            return false;
        };
        // divide(userpass, ':', false): first colon, no whitespace
        // trimming; no colon -> (whole text, empty) (util.h).
        let (user, pass) = match userpass.iter().position(|&b| b == b':') {
            Some(i) => (&userpass[..i], &userpass[i + 1..]),
            None => (&userpass[..], &userpass[userpass.len()..]),
        };
        // HttpServer.cc: the user tag is always checked; the passwd tag
        // only when set.
        ct_eq(&self.hmac.tag(user), &self.username_tag)
            && self
                .password_tag
                .is_none_or(|t| ct_eq(&self.hmac.tag(pass), &t))
    }
}

/// Basic entry gate (same shape as HttpServer.cc `if (!username_) return
/// true`): with --rpc-user not configured (`basic` = None) -> always
/// true, the transport layer does no Basic checking.
pub fn basic_authorized(basic: Option<&BasicAuth>, header: Option<&str>) -> bool {
    match basic {
        None => true,
        Some(b) => b.authorize(header),
    }
}

/// Strip and return the token from the first parameter (same shape as
/// aria2 RpcMethod.cc).
pub fn strip_token(params: &mut Vec<Value>) -> Option<String> {
    match params.first() {
        Some(Value::String(s)) if s.starts_with("token:") => {
            let token = s["token:".len()..].to_string();
            params.remove(0);
            Some(token)
        }
        _ => None,
    }
}

/// validateToken (aria2 DownloadEngine.cc): no secret set -> always
/// true; set -> the token must equal the secret. The secret never
/// appears in any log or echo.
///
/// Security fix: no `==` on plaintext — string equality compares length
/// first and short-circuits per byte, so a remote peer can brute-force
/// the token byte-by-byte by timing (prefix-match progress leak). Here
/// both sides are first folded to fixed-length SHA-256 digests (computed
/// on the fly, never stored), then compared with the [`ct_eq`] XOR-fold
/// constant-time compare: comparison time is independent of how many
/// bytes matched.
pub fn validate(secret: Option<&str>, token: Option<&str>) -> bool {
    let Some(expected) = secret else {
        return true;
    };
    let expected: [u8; DIGEST_LEN] = Sha256::digest(expected.as_bytes()).into();
    // A missing token folds as the empty string: the comparison surface
    // stays fixed-length and constant-time, and the result is always
    // unequal.
    let given: [u8; DIGEST_LEN] = Sha256::digest(token.unwrap_or_default().as_bytes()).into();
    ct_eq(&expected, &given)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test-local standard base64 computation (the rpc layer only
    /// consumes decoding, same rule as the base64.rs tests).
    fn b64(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn basic(user: &str, pass: &str) -> String {
        format!("Basic {}", b64(format!("{user}:{pass}").as_bytes()))
    }

    #[test]
    fn strips_only_first_string_token_prefixed_param() {
        let mut params = vec![json!("token:sekrit"), json!("extra")];
        let token = strip_token(&mut params);
        assert_eq!(token.as_deref(), Some("sekrit"));
        assert_eq!(params, vec![json!("extra")]);
    }

    #[test]
    fn leaves_non_token_first_param_untouched() {
        // A string without the `token:` prefix (RpcMethod.cc pops only
        // on a startsWith hit).
        let mut params = vec![json!("gid://x"), json!("token:y")];
        assert_eq!(strip_token(&mut params), None);
        assert_eq!(params.len(), 2);

        // A non-string first parameter is not stripped.
        let mut numeric = vec![json!(1)];
        assert_eq!(strip_token(&mut numeric), None);
        assert_eq!(numeric, vec![json!(1)]);

        let mut empty: Vec<Value> = vec![];
        assert_eq!(strip_token(&mut empty), None);
    }

    #[test]
    fn validate_mirrors_validate_token() {
        // No secret set: always true (DownloadEngine.cc).
        assert!(validate(None, None));
        assert!(validate(None, Some("anything")));

        // Secret set: must match.
        assert!(validate(Some("s"), Some("s")));
        assert!(!validate(Some("s"), None));
        assert!(!validate(Some("s"), Some("wrong")));
    }

    /// Security-fix regression: the comparison surface is a fixed-length
    /// digest folded constant-time — any non-equal input (prefix match /
    /// extension / length-only difference) is false; semantics match the
    /// old equality compare but without per-byte short-circuiting.
    #[test]
    fn validate_hash_compare_rejects_all_prefix_and_length_variants() {
        let secret = "sekrit-token-value";
        // All prefixes / all extensions / single-char difference / empty
        // string.
        for guess in [
            "",
            "s",
            "sekrit",
            "sekrit-token",
            "sekrit-token-valu",
            "sekrit-token-valuex",
            "sekrit-token-values",
            "SEKRIT-TOKEN-VALUE",
        ] {
            assert!(
                !validate(Some(secret), Some(guess)),
                "prefix/length variant must not match: {guess:?}"
            );
        }
        assert!(validate(Some(secret), Some(secret)));
        // Overlong token (after hash folding the comparison surface is
        // always 32B; the length itself does not crash, only compares
        // unequal).
        let long = "x".repeat(4096);
        assert!(validate(Some(&long), Some(&long)));
        assert!(!validate(Some(&long), Some(&format!("{long}!"))));
        assert!(!validate(Some(&long), Some(&long[..100])));
        // Digest folding preserves equality semantics: non-ASCII token.
        let unicode = "sécret-\u{1F32B}";
        assert!(validate(Some(unicode), Some(unicode)));
        assert!(!validate(Some(unicode), Some("sécret-")));
    }

    #[test]
    fn random_hmac_differs_across_instances_and_matches_within() {
        // In-process random key: stable within an instance, different
        // across instances (createRandom semantics).
        let a = RandomHmac::new();
        let b = RandomHmac::new();
        assert_eq!(a.tag(b"user"), a.tag(b"user"));
        assert_ne!(a.tag(b"user"), b.tag(b"user"), "2^-160 collision");
    }

    #[test]
    fn basic_auth_positive_and_negative_matrix() {
        let auth = BasicAuth::new(Some("user"), Some("pass"));

        // Positive: standard "Basic base64(user:pass)".
        let auth = auth.unwrap_or_else(|| panic!("user set → Some"));
        assert!(auth.authorize(Some(&basic("user", "pass"))));
        // Whitespace tolerated on both sides (divide strip=true, util.h).
        assert!(auth.authorize(Some(&format!("  Basic  {}  ", b64(b"user:pass")))));

        // Negative: no header / wrong user / wrong pass / case-sensitive
        // scheme / non-Basic / invalid base64 / missing colon.
        assert!(!auth.authorize(None), "header missing → HttpServer.cc");
        assert!(!auth.authorize(Some(&basic("who", "pass"))));
        assert!(!auth.authorize(Some(&basic("user", "nope"))));
        assert!(
            !auth.authorize(Some(&format!("basic {}", b64(b"user:pass")))),
            "scheme compare is case-sensitive (streq, util.h)"
        );
        assert!(!auth.authorize(Some(&format!("Bearer {}", b64(b"user:pass")))));
        assert!(!auth.authorize(Some("Basic !!!not-base64")));
        assert!(
            !auth.authorize(Some(&format!("Basic {}", b64(b"user-without-colon")))),
            "no ':' → empty password, must still match required password"
        );
        // The user is split at the first colon (divide ':' once): with
        // user="a:b", incoming "a:b:c"/"a:b" both split to username="a"
        // != "a:b" -> rejected (same limitation as the reference).
        let colon = BasicAuth::new(Some("a:b"), None).unwrap_or_else(|| panic!("set"));
        assert!(!colon.authorize(Some(&format!("Basic {}", b64(b"a:b:c")))));
        assert!(!colon.authorize(Some(&format!("Basic {}", b64(b"a:b")))));
    }

    #[test]
    fn password_unset_accepts_any_password_and_empty_means_unset() {
        // user-only: the password is not checked (HttpServer.cc
        // `!password_ ||`).
        let no_pass = BasicAuth::new(Some("user"), None).unwrap_or_else(|| panic!("set"));
        assert!(no_pass.authorize(Some(&format!("Basic {}", b64(b"user")))));
        assert!(no_pass.authorize(Some(&format!("Basic {}", b64(b"user:anything")))));

        // Empty string = unset (HttpServer.cc empty-string reset
        // semantics).
        assert!(BasicAuth::new(Some(""), Some("x")).is_none());
        assert!(BasicAuth::new(Some("user"), Some("")).is_some_and(|a| a.password_tag.is_none()));
    }

    #[test]
    fn entry_gate_is_true_only_when_basic_disabled() {
        // --rpc-user not configured: always true (HttpServer.cc).
        assert!(basic_authorized(None, None));
        assert!(basic_authorized(None, Some("garbage")));
        // Configured: delegated to the authorize decision.
        let auth = BasicAuth::new(Some("u"), Some("p")).unwrap_or_else(|| panic!("set"));
        assert!(basic_authorized(Some(&auth), Some(&basic("u", "p"))));
        assert!(!basic_authorized(Some(&auth), None));
    }

    #[test]
    fn debug_never_contains_secrets() {
        let auth =
            BasicAuth::new(Some("alice"), Some("s3cret-value")).unwrap_or_else(|| panic!("set"));
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("alice"), "leaked: {rendered}");
        assert!(!rendered.contains("s3cret-value"), "leaked: {rendered}");
    }
}

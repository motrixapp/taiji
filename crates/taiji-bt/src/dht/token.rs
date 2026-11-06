//! Announce token generation/validation (BEP5 token clause; mirrors aria2
//! `DHTTokenTracker.{h,cc}`).
//!
//! # Protocol facts
//!
//! - The secret is 4 random bytes kept as two generations:
//! `secret_[2][SECRET_SIZE=4]` (aria2 `DHTTokenTracker.h`); generation
//! uses the current generation, validation accepts either generation
//! (`DHTTokenTracker.cc`);
//! - Rotation: current generation -> previous, a fresh secret becomes
//! current (`DHTTokenTracker.cc`); the rotation window is 10min
//! (`DHTConstants.h` `DHT_TOKEN_UPDATE_INTERVAL`); the engine drives it
//! on a timer, this module only provides [`TokenTracker::update_secret`];
//! - A token is a 20B SHA-1 digest (`DHTTokenTracker.cc`).
//!
//! # Token formula: SPEC §6.7 (intentional divergence from aria2)
//!
//! This implementation follows SPEC §6.7 / BEP5:
//! `SHA1(secret || ip || port)` with ip 4B (IPv4) / 16B (IPv6) network
//! byte order and port 2B network byte order. aria2 actually computes
//! `SHA1(infoHash || compact(ip,port) || secret)` (`DHTTokenTracker.cc`).
//! A token is opaque: only the generating side validates it (BEP5 token
//! clause), so the formula is not an interoperability surface.
//!
//! Validation uses a constant-time comparison (no early return on token
//! byte mismatch).

use std::net::SocketAddr;
use std::time::Duration;

// rand 0.10: the `&mut impl Rng` signature keeps Rng (the base trait);
// `fill` sampling lives in RngExt (the old Rng, renamed).
use rand::{Rng, RngExt};
use sha1::{Digest, Sha1};

/// Token secret rotation window. aria2 `src/DHTConstants.h`.
pub const DHT_TOKEN_UPDATE_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Token byte length (SHA-1 digest; aria2 `DHTTokenTracker.cc`).
pub const TOKEN_LENGTH: usize = 20;
/// Secret byte length. aria2 `src/DHTTokenTracker.h` (`SECRET_SIZE = 4`).
pub const SECRET_SIZE: usize = 4;

/// Two-generation secret token manager (mirrors DHTTokenTracker).
#[derive(Clone, Debug)]
pub struct TokenTracker {
    /// [0] = current generation (used to generate), [1] = previous
    /// (validation). Mirrors `DHTTokenTracker.h`
    /// `unsigned char secret_[2][SECRET_SIZE]`.
    secrets: [[u8; SECRET_SIZE]; 2],
}

impl TokenTracker {
    /// Random init, both generations equal (mirrors `DHTTokenTracker.cc`).
    pub fn new(rng: &mut impl Rng) -> Self {
        let secret = random_secret(rng);
        TokenTracker {
            secrets: [secret, secret],
        }
    }

    /// Init with fixed secrets (tests / persistence restore; mirrors the
    /// single-secret constructor in `DHTTokenTracker.cc`: both generations
    /// equal; current/previous is this implementation's extension).
    pub fn from_secrets(current: [u8; SECRET_SIZE], previous: [u8; SECRET_SIZE]) -> Self {
        TokenTracker {
            secrets: [current, previous],
        }
    }

    /// Generate a token: `SHA1(secret[0] || ip || port)` (formula source
    /// in the module docs; aria2 generates with secret_[0],
    /// `DHTTokenTracker.cc`).
    pub fn generate(&self, addr: SocketAddr) -> [u8; TOKEN_LENGTH] {
        digest(&self.secrets[0], addr)
    }

    /// Validate a token: current or previous generation matching passes
    /// (mirrors `DHTTokenTracker.cc` validateToken's two-generation loop;
    /// constant-time comparison).
    pub fn validate(&self, token: &[u8], addr: SocketAddr) -> bool {
        token.len() == TOKEN_LENGTH
            && (ct_eq(token, &digest(&self.secrets[0], addr))
                || ct_eq(token, &digest(&self.secrets[1], addr)))
    }

    /// Rotate the secret: previous = current, current = fresh random
    /// (mirrors `DHTTokenTracker.cc` updateTokenSecret).
    pub fn update_secret(&mut self, rng: &mut impl Rng) {
        self.secrets[1] = self.secrets[0];
        self.secrets[0] = random_secret(rng);
    }

    /// Current-generation secrets (for dht_state persistence).
    pub fn secrets(&self) -> [[u8; SECRET_SIZE]; 2] {
        self.secrets
    }
}

fn random_secret(rng: &mut impl RngExt) -> [u8; SECRET_SIZE] {
    let mut s = [0u8; SECRET_SIZE];
    rng.fill(&mut s);
    s
}

/// `SHA1(secret || ip || port)`: ip 4B/16B network byte order, port 2B
/// network byte order (SPEC §6.7; the field-order difference from aria2
/// in the module docs).
fn digest(secret: &[u8; SECRET_SIZE], addr: SocketAddr) -> [u8; TOKEN_LENGTH] {
    let mut hasher = Sha1::new();
    hasher.update(secret);
    match addr {
        SocketAddr::V4(a) => hasher.update(a.ip().octets()),
        SocketAddr::V6(a) => hasher.update(a.ip().octets()),
    }
    hasher.update(addr.port().to_be_bytes());
    let out = hasher.finalize();
    let mut token = [0u8; TOKEN_LENGTH];
    token.copy_from_slice(&out);
    token
}

/// Constant-time byte comparison (the length is always 20B).
fn ct_eq(a: &[u8], b: &[u8; TOKEN_LENGTH]) -> bool {
    let mut diff = 0u8;
    for i in 0..TOKEN_LENGTH {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    /// Deterministic xorshift RNG (matches the repo test convention,
    /// tracker/udp.rs).
    struct XorShift(u64);

    impl XorShift {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    // rand 0.10: a custom RNG implementing TryRng (Error = Infallible)
    // gets Rng/RngExt via the blanket impl (same as tracker/udp.rs).
    impl rand::rand_core::TryRng for XorShift {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next_u64() as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next_u64())
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            port,
            0,
            0,
        ))
    }

    /// Port of test/DHTTokenTrackerTest.cc: generate -> validates; after
    /// one rotation the old token still validates (two-generation check);
    /// after a second rotation the old token fails and the new one passes.
    #[test]
    fn token_survives_one_rotation_only() {
        let mut rng = XorShift(0x5eed_1234_abcd_ef01);
        let mut tracker = TokenTracker::new(&mut rng);
        let addr = v4(6881);
        let token = tracker.generate(addr);
        assert!(tracker.validate(&token, addr));

        tracker.update_secret(&mut rng);
        assert!(tracker.validate(&token, addr));
        let new_token = tracker.generate(addr);

        tracker.update_secret(&mut rng);
        assert!(!tracker.validate(&token, addr));
        assert!(tracker.validate(&new_token, addr));
    }

    /// A token is bound to (ip, port): changing the address/port fails
    /// validation (the formula includes ip/port — this side's reading of
    /// the BEP5 clause "keyed to the info_hash and IP address").
    #[test]
    fn token_is_bound_to_addr() {
        let mut rng = XorShift(42);
        let tracker = TokenTracker::new(&mut rng);
        let token = tracker.generate(v4(6881));
        assert!(!tracker.validate(&token, v4(6882)));
        assert!(!tracker.validate(&token, v6(6881)));
    }

    /// Table test: byte-level assertion of the SHA1(secret || ip || port)
    /// field order (SPEC §6.7 formula; secret first, ip in the middle,
    /// port big-endian last).
    #[test]
    fn digest_follows_secret_ip_port_layout() {
        // Compute SHA-1 over a hand-assembled concatenation and compare
        // with digest().
        use sha1::{Digest, Sha1};
        let addr = v4(6881);
        let secret = [0xde, 0xad, 0xbe, 0xef];
        let mut expect = Sha1::new();
        expect.update(secret);
        expect.update([192u8, 168, 0, 1]);
        expect.update(6881u16.to_be_bytes());
        let expect = expect.finalize();

        let tracker = TokenTracker::from_secrets(secret, [0; SECRET_SIZE]);
        assert_eq!(tracker.generate(addr).as_slice(), expect.as_slice());
        // A different previous secret -> validation only accepts the
        // current one (the other generation is 0 in from_secrets).
        assert!(tracker.validate(&expect, addr));
    }

    /// Tokens not 20 bytes long are always rejected.
    #[test]
    fn rejects_wrong_token_length() {
        let mut rng = XorShift(7);
        let tracker = TokenTracker::new(&mut rng);
        assert!(!tracker.validate(&[], v4(6881)));
        assert!(!tracker.validate(&[0u8; 19], v4(6881)));
        assert!(!tracker.validate(&[0u8; 21], v4(6881)));
    }

    /// from_secrets: the current generation generates, both validate;
    /// secrets() returns the original values.
    #[test]
    fn from_secrets_roundtrip() {
        let tracker = TokenTracker::from_secrets([1, 2, 3, 4], [9, 9, 9, 9]);
        assert_eq!(tracker.secrets(), [[1, 2, 3, 4], [9, 9, 9, 9]]);
        let addr = v4(1);
        let token = tracker.generate(addr);
        assert!(tracker.validate(&token, addr));
        // A token hand-generated with the previous secret also passes
        // (two-generation validation).
        let prev_token = {
            use sha1::{Digest, Sha1};
            let mut h = Sha1::new();
            h.update([9u8, 9, 9, 9]);
            h.update([192u8, 168, 0, 1]);
            h.update(1u16.to_be_bytes());
            let d = h.finalize();
            let mut t = [0u8; 20];
            t.copy_from_slice(&d);
            t
        };
        assert!(tracker.validate(&prev_token, addr));
    }
}

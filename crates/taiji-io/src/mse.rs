//! MSE/PE protocol encryption (Message Stream Encryption / Protocol
//! Encryption, SPEC §6.4/§6.1).
//!
//! Mechanism: DH-768 key exchange (768-bit group, 160-bit random
//! private key, 96B big-endian fixed-width keys), per-direction ARC4
//! with the first 1024B of keystream dropped, req1/req2/req3 hash
//! markers for synchronization, and a PLAIN/ARC4 crypto negotiation.
//! The handshake tail parsers ([`ReceiverParser`]/[`InitiatorParser`])
//! are pure state machines shared by the async drivers and the fuzz
//! targets (no behavioral drift); [`Encrypted`] wraps the negotiated
//! stream as `AsyncRead + AsyncWrite`, an added impl at the frozen
//! `PeerTransport` seam; sniffing ([`identify`] + [`peek_sniff`])
//! takes the legacy prefix from the caller, and the dispatch decision
//! lives in bt::mse (protocol knowledge stays in bt).
//!
//! All constants and flows are cross-checked against upstream aria2;
//! the full anchor mapping and the one deliberate divergence (the
//! software-DH fallback defect, intentionally not copied) are in
//! docs/design/io.md (`mse.rs`). Test vectors: `mse/tests.rs` — the
//! IETF RFC 6229 §2 ARC4 KATs plus golden vectors from the independent
//! `scripts/gen_mse_vectors.py` implementation.
//!
//! Concurrency discipline: no locks, no channels, no blocking calls;
//! modpow and key generation run on `spawn_blocking` (the negotiation
//! path never blocks the runtime).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use num_bigint_dig::BigUint;
// rand 0.10: fill_bytes is a default method of `Rng` (rand_core 0.10
// split RngCore into TryRng/Rng; ThreadRng implements Rng); the root
// re-export of RngCore is gone.
use rand::Rng as _;
use sha1::{Digest, Sha1};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

/// tracing target.
const LOG_TARGET: &str = "taiji::io::mse";

// ---------------------------------------------------------------------------
// Constants (each carries its upstream source; changes must re-anchor)
// ---------------------------------------------------------------------------

/// MSE group modulus bit length (`MSEHandshake.h PRIME_BITS = 768`).
pub const PRIME_BITS: u32 = 768;
/// Public key / shared secret byte length = (768+7)/8
/// (`MSEHandshake.h KEY_LENGTH`).
pub const KEY_LENGTH: usize = 96;
/// DH private key bit length (`MSEHandshake.cc dh_->init(..., 160)`).
pub const PRIVATE_KEY_BITS: usize = 160;
/// VC length (`MSEHandshake.h VC_LENGTH = 8`); the content is always
/// 8B of zeros (`MSEHandshake.cc`).
pub const VC_LENGTH: usize = 8;
/// Pad length cap (`MSEHandshake.cc MAX_PAD_LENGTH = 512`).
pub const MAX_PAD_LENGTH: usize = 512;
/// crypto_provide/select bitmap byte length (`MSEHandshake.cc`).
pub const CRYPTO_BITFIELD_LENGTH: usize = 4;
/// Crypto bitmap: plain bit (`MSEHandshake.h`).
pub const CRYPTO_PLAIN_TEXT: u8 = 0x01;
/// Crypto bitmap: ARC4 bit (`MSEHandshake.h`).
pub const CRYPTO_ARC4: u8 = 0x02;
/// ARC4 drops the first 1024B of keystream (`MSEHandshake.cc`).
pub const ARC4_DROP_N: usize = 1024;
/// IA length cap = the 68B BT handshake (`MSEHandshake.cc` vs
/// `BtHandshakeMessage.cc MESSAGE_LENGTH`).
pub const IA_MAX_LENGTH: usize = 68;
/// Initiator VC-marker search sync window (`MSEHandshake.cc`:
/// 616 - 96).
const INITIATOR_SYNC_WINDOW: usize = 616 - KEY_LENGTH;
/// Receiver req1-marker search sync window (`MSEHandshake.cc`:
/// 628 - 96).
const RECEIVER_SYNC_WINDOW: usize = 628 - KEY_LENGTH;

/// MSE 768-bit group prime, big-endian hex (copied character by
/// character from `MSEHandshake.cc`).
const PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B",
    "139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485",
    "B576625E7EC6F44C42E9A63A36210000000000090563",
);
/// Generator (`MSEHandshake.cc`).
const GENERATOR: u64 = 2;

/// Prime raw bytes (big-endian 96B; decoded at const time, errors
/// surface at compile time).
const PRIME_BYTES: [u8; KEY_LENGTH] = decode_hex_96(PRIME_HEX);

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        // const-context panic = compile-time error (constants are
        // validated during compilation).
        _ => panic!("MSE prime hex invalid"),
    }
}

const fn decode_hex_96(hex: &str) -> [u8; KEY_LENGTH] {
    let bytes = hex.as_bytes();
    // PRIME_HEX must be 192 hex chars (const panic = compile-time
    // assertion).
    assert!(bytes.len() == KEY_LENGTH * 2, "MSE prime hex length");
    let mut out = [0u8; KEY_LENGTH];
    let mut i = 0;
    while i < KEY_LENGTH {
        out[i] = (hex_nibble(bytes[2 * i]) << 4) | hex_nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// MSE handshake/transport errors (connection-scoped; never propagates
/// to the torrent).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MseError {
    /// `kind` is extracted from the underlying `io::Error`: upstream
    /// redial/backoff can classify by kind
    /// (ConnectionReset/TimedOut/ConnectionRefused) and must not depend
    /// on error-text substrings.
    #[error("io error: {message}")]
    Io {
        kind: std::io::ErrorKind,
        message: String,
    },
    #[error("peer closed connection during MSE handshake")]
    Eof,
    #[error("MSE handshake timeout")]
    Timeout,
    #[error("failed to find {marker} marker within sync window")]
    MarkerNotFound {
        /// "req1" (receiver) / "VC" (initiator).
        marker: &'static str,
    },
    #[error("unknown info hash (req2/req3 mismatch)")]
    UnknownInfoHash,
    #[error("invalid VC after decryption")]
    InvalidVc,
    #[error("{pad} length {length} > {max}")]
    PadTooLarge {
        pad: &'static str,
        length: u16,
        max: u16,
    },
    /// IA length cap = [`IA_MAX_LENGTH`] (68B, the fixed BT handshake
    /// length).
    #[error("IA length {0} > 68")]
    IaTooLarge(u16),
    #[error("no crypto type agreed (no acceptable bit in provide/select)")]
    NoCryptoAgreed,
    #[error("spawn_blocking join failed: {0}")]
    Blocking(String),
}

impl From<std::io::Error> for MseError {
    fn from(e: std::io::Error) -> Self {
        MseError::Io {
            kind: e.kind(),
            message: e.to_string(),
        }
    }
}

/// Wraps a single IO wait with a timeout (peer-connection-timeout
/// semantics; `InitiatorMSEHandshakeCommand.cc` /
/// `ReceiverMSEHandshakeCommand.cc`).
async fn timeout_io<T, E>(
    timeout: Duration,
    fut: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, MseError>
where
    MseError: From<E>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(MseError::from(e)),
        Err(_) => Err(MseError::Timeout),
    }
}

// ---------------------------------------------------------------------------
// Policy (--bt-require-crypto / --bt-min-crypto-level, SPEC §6.4/§11)
// ---------------------------------------------------------------------------

/// Negotiated crypto level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoLevel {
    /// CRYPTO_PLAIN_TEXT: the post-handshake stream is plaintext (step2
    /// still goes through ARC4, see the module docs).
    Plain,
    /// CRYPTO_ARC4: the post-handshake stream stays under ARC4.
    Arc4,
}

impl CryptoLevel {
    /// Bitmap bit (`MSEHandshake.h`).
    pub fn bit(self) -> u8 {
        match self {
            CryptoLevel::Plain => CRYPTO_PLAIN_TEXT,
            CryptoLevel::Arc4 => CRYPTO_ARC4,
        }
    }
}

/// Crypto policy: `--bt-require-crypto` + `--bt-min-crypto-level`
/// (SPEC §6.4/§11; require-crypto shares its value with
/// bt-force-encryption — SPEC §11 declares the alias, and aria2's
/// `PREF_BT_FORCE_ENCRYPTION || PREF_BT_REQUIRE_CRYPTO` appears as OR
/// semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoPolicy {
    /// Reject legacy inbound + exclude plain from provide (aria2
    /// `InitiatorMSEHandshakeCommand.cc`,
    /// `ReceiverMSEHandshakeCommand.cc`).
    pub require_crypto: bool,
    /// Minimum crypto level (`--bt-min-crypto-level=plain|arc4`).
    pub min_level: CryptoLevel,
}

impl CryptoPolicy {
    /// aria2 defaults: optional encryption, plain acceptable (SPEC §11
    /// defaults of the two options).
    pub fn optional() -> Self {
        CryptoPolicy {
            require_crypto: false,
            min_level: CryptoLevel::Plain,
        }
    }

    /// crypto_provide bitmap (`MSEHandshake.cc`): ARC4 is always
    /// offered; plain only when !require && min==plain.
    pub fn provide(self) -> u8 {
        let mut bits = CRYPTO_ARC4;
        if !self.require_crypto && self.min_level == CryptoLevel::Plain {
            bits |= CRYPTO_PLAIN_TEXT;
        }
        bits
    }

    /// Receiver-side pick from the peer's provide (`MSEHandshake.cc`):
    /// plain provided and (!require && min==plain) -> plain; else arc4
    /// provided -> arc4; else None (-> [`MseError::NoCryptoAgreed`]
    /// disconnect).
    pub fn select_from_provide(self, provide: u8) -> Option<CryptoLevel> {
        if provide & CRYPTO_PLAIN_TEXT != 0
            && !self.require_crypto
            && self.min_level == CryptoLevel::Plain
        {
            Some(CryptoLevel::Plain)
        } else if provide & CRYPTO_ARC4 != 0 {
            Some(CryptoLevel::Arc4)
        } else {
            None
        }
    }

    /// Initiator-side pick from the peer's crypto_select
    /// (`MSEHandshake.cc`): plain first when selectable, then the ARC4
    /// bit **overwrites** to arc4 (aria2 uses two independent ifs; the
    /// later arc4 write wins).
    pub fn select_from_select(self, select: u8) -> Option<CryptoLevel> {
        let mut chosen = None;
        if select & CRYPTO_PLAIN_TEXT != 0
            && !self.require_crypto
            && self.min_level == CryptoLevel::Plain
        {
            chosen = Some(CryptoLevel::Plain);
        }
        if select & CRYPTO_ARC4 != 0 {
            chosen = Some(CryptoLevel::Arc4);
        }
        chosen
    }
}

// ---------------------------------------------------------------------------
// ARC4 (aria2 InternalARC4Encryptor.cc)
// ---------------------------------------------------------------------------

/// RC4 (ARC4 in MSE terms): encryption and decryption are the same
/// operation (keystream XOR).
///
/// Debug is hand-written and redacting: the 256B `state` IS the keystream
/// generator (printing it would leak every future keystream byte), so it
/// renders as `<redacted>`; only the harmless `i`/`j` counters are shown.
#[derive(Clone)]
pub struct Arc4 {
    i: u8,
    j: u8,
    state: [u8; 256],
}

impl std::fmt::Debug for Arc4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Arc4")
            .field("i", &self.i)
            .field("j", &self.j)
            .field("state", &"<redacted>")
            .finish()
    }
}

impl Arc4 {
    /// KSA (line for line from `InternalARC4Encryptor.cc`).
    ///
    /// # Panics
    ///
    /// On an empty `key`: the KSA indexes `key[i % key.len()]`, so an empty
    /// key would be a division by zero — asserted up front with the length
    /// in the message instead of surfacing as an arithmetic panic. The only
    /// production caller (`dropped_arc4`) passes a 20B HASH-derived key.
    pub fn new(key: &[u8]) -> Self {
        assert!(
            !key.is_empty(),
            "Arc4 KSA requires a non-empty key (got {} bytes)",
            key.len()
        );
        let mut state = [0u8; 256];
        for (idx, c) in state.iter_mut().enumerate() {
            *c = idx as u8;
        }
        let mut j: usize = 0;
        for i in 0..state.len() {
            j = (j + state[i] as usize + key[i % key.len()] as usize) & 0xff;
            state.swap(i, j);
        }
        Arc4 { i: 0, j: 0, state }
    }

    /// Returns the next keystream byte and advances the state
    /// (`InternalARC4Encryptor.cc`).
    fn next_keystream(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        let si = self.state[self.i as usize];
        let sj = self.state[self.j as usize];
        self.state[self.i as usize] = sj;
        self.state[self.j as usize] = si;
        self.state[usize::from(si.wrapping_add(sj))]
    }

    /// In-place encrypt/decrypt (`InternalARC4Encryptor.cc`; encrypt ==
    /// decrypt).
    pub fn apply(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b ^= self.next_keystream();
        }
    }

    /// Drops n bytes of keystream (MSE uses n=1024, `MSEHandshake.cc`).
    pub fn discard(&mut self, n: usize) {
        for _ in 0..n {
            let _ = self.next_keystream();
        }
    }
}

/// Builds the dropped-1024B ARC4 for a direction key (`MSEHandshake.cc`).
fn dropped_arc4(key: &[u8; 20]) -> Arc4 {
    let mut c = Arc4::new(key);
    c.discard(ARC4_DROP_N);
    c
}

// ---------------------------------------------------------------------------
// DH-768 (modpow; see the documented divergence in docs/design/io.md)
// ---------------------------------------------------------------------------

/// MSE DH key exchange: 768-bit group, 160-bit random private key, 96B
/// big-endian fixed-width encoding.
///
/// Once per connection (SPEC §6.4: num-bigint-dig modpow takes tens of
/// µs); the async side enters `spawn_blocking` via
/// [`DhKeyExchange::generate`] / [`DhKeyExchange::compute_secret_async`].
///
/// Debug is hand-written and redacting: `private_key` IS the connection
/// secret's root (S = peer^x mod p derives straight from it), so it
/// renders as `<redacted>`; the public key is freely observable on the
/// wire and is shown.
#[derive(Clone)]
pub struct DhKeyExchange {
    private_key: BigUint,
    public_key: BigUint,
}

impl std::fmt::Debug for DhKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhKeyExchange")
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl DhKeyExchange {
    fn prime() -> BigUint {
        BigUint::from_bytes_be(&PRIME_BYTES)
    }

    /// Builds from private-key bytes (big-endian); for deterministic
    /// test injection.
    pub fn from_private_key(private_key: &[u8]) -> Self {
        let private_key = BigUint::from_bytes_be(private_key);
        // modpow: aria2 LibgmpDHKeyExchange.cc generatePublicKey
        // (mpz_powm).
        let public_key = BigUint::from(GENERATOR).modpow(&private_key, &Self::prime());
        DhKeyExchange {
            private_key,
            public_key,
        }
    }

    /// 160-bit random private key (`MSEHandshake.cc` key bit length;
    /// `InternalDHKeyExchange.cc` random byte count = bits/8).
    pub fn random() -> Self {
        let mut key = [0u8; PRIVATE_KEY_BITS / 8];
        rand::rng().fill_bytes(&mut key);
        Self::from_private_key(&key)
    }

    /// Generation on `spawn_blocking` (never blocks the runtime on the
    /// negotiation path).
    pub async fn generate() -> Result<Self, MseError> {
        tokio::task::spawn_blocking(Self::random)
            .await
            .map_err(|e| MseError::Blocking(e.to_string()))
    }

    /// Public key as 96B big-endian fixed width (left zero-padded,
    /// aria2 LibgmpDHKeyExchange.cc getPublicKey).
    pub fn public_key_bytes(&self) -> [u8; KEY_LENGTH] {
        to_key_bytes(&self.public_key)
    }

    /// Shared secret S = peer^x mod p (sync version; 96B big-endian
    /// fixed width).
    pub fn compute_secret(&self, peer_public: &[u8; KEY_LENGTH]) -> [u8; KEY_LENGTH] {
        let peer = BigUint::from_bytes_be(peer_public);
        // aria2 LibgmpDHKeyExchange.cc computeSecret (mpz_powm).
        let secret = peer.modpow(&self.private_key, &Self::prime());
        to_key_bytes(&secret)
    }

    /// Shared secret on `spawn_blocking` (consumes and returns self).
    pub async fn compute_secret_async(
        self,
        peer_public: [u8; KEY_LENGTH],
    ) -> Result<(Self, [u8; KEY_LENGTH]), MseError> {
        tokio::task::spawn_blocking(move || {
            let secret = self.compute_secret(&peer_public);
            (self, secret)
        })
        .await
        .map_err(|e| MseError::Blocking(e.to_string()))
    }
}

/// BigUint -> 96B big-endian fixed width (left zero-padded; the value
/// is < the group prime, so <=96B always holds).
fn to_key_bytes(v: &BigUint) -> [u8; KEY_LENGTH] {
    let mut out = [0u8; KEY_LENGTH];
    let be = v.to_bytes_be();
    // Defensively keep the low bytes (a mod-p result is always < 2^768).
    let skip = be.len().saturating_sub(KEY_LENGTH);
    let start = KEY_LENGTH - (be.len() - skip);
    out[start..].copy_from_slice(&be[skip..]);
    out
}

// ---------------------------------------------------------------------------
// Key derivation (formulas from MSEHandshake.cc)
// ---------------------------------------------------------------------------

/// req1 = SHA1("req1" || S) (`MSEHandshake.cc`).
pub fn req1_hash(secret: &[u8; KEY_LENGTH]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(b"req1");
    h.update(secret);
    h.finalize().into()
}

/// SHA1("req2" || infohash) XOR SHA1("req3" || S) (`MSEHandshake.cc`).
pub fn req23_hash(secret: &[u8; KEY_LENGTH], info_hash: &[u8; 20]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(b"req2");
    h.update(info_hash);
    let xh: [u8; 20] = h.finalize().into();
    let mut h = Sha1::new();
    h.update(b"req3");
    h.update(secret);
    let yh: [u8; 20] = h.finalize().into();
    let mut md = [0u8; 20];
    for i in 0..20 {
        md[i] = xh[i] ^ yh[i];
    }
    md
}

/// MSE handshake direction (who sent the first crypto step; the
/// `MSEHandshake.cc` role): decides the keyA/keyB prefix split of
/// [`cipher_keys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We produced handshake step 1: local key prefix "keyA", peer
    /// prefix "keyB".
    Initiator,
    /// We answered with step 2: local key prefix "keyB", peer prefix
    /// "keyA" (the receiver swaps the initiator's split).
    Receiver,
}

/// Direction keys: `(local send direction, peer send direction)` 20B
/// ARC4 keys (`MSEHandshake.cc`: the initiator's local prefix is "keyA"
/// / peer "keyB"; the receiver swaps them).
pub fn cipher_keys(
    secret: &[u8; KEY_LENGTH],
    info_hash: &[u8; 20],
    direction: Direction,
) -> ([u8; 20], [u8; 20]) {
    let (local_prefix, peer_prefix) = match direction {
        Direction::Initiator => (b"keyA" as &[u8], b"keyB" as &[u8]),
        Direction::Receiver => (b"keyB" as &[u8], b"keyA" as &[u8]),
    };
    let mut h = Sha1::new();
    h.update(local_prefix);
    h.update(secret);
    h.update(info_hash);
    let local: [u8; 20] = h.finalize().into();
    let mut h = Sha1::new();
    h.update(peer_prefix);
    h.update(secret);
    h.update(info_hash);
    let peer: [u8; 20] = h.finalize().into();
    (local, peer)
}

/// Random pad length 0..=512 (`MSEHandshake.cc`
/// `getRandomNumber(MAX_PAD_LENGTH + 1)`).
fn random_pad_len() -> usize {
    rand::random_range(0..=MAX_PAD_LENGTH)
}

// ---------------------------------------------------------------------------
// Sniffing (identifyHandshakeType, MSEHandshake.cc)
// ---------------------------------------------------------------------------

/// Sniff verdict (`MSEHandshake.cc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniff {
    /// First byte = pstrlen and pstr matches -> legacy BT handshake.
    Legacy,
    /// Anything else -> MSE encrypted.
    Encrypted,
    /// Fewer than `1 + legacy_pstr.len()` bytes -> need more data.
    NeedMore,
}

/// Pure-function sniff: `head` is the bytes arrived at the head of the
/// stream, `legacy_pstr` comes from the caller (the bt layer passes
/// `"BitTorrent protocol"`; io stays protocol-agnostic).
pub fn identify(head: &[u8], legacy_pstr: &[u8]) -> Sniff {
    let want = 1 + legacy_pstr.len();
    if head.len() < want {
        return Sniff::NeedMore;
    }
    if head[0] as usize == legacy_pstr.len() && &head[1..want] == legacy_pstr {
        Sniff::Legacy
    } else {
        Sniff::Encrypted
    }
}

/// Prefixed wrapper stream: replays the bytes read while sniffing, then
/// passes through (the legacy path hands the 20B prefix back to the
/// handshake read; the MSE path hands the pubkey's first 20B back to
/// [`receive`]).
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    served: usize,
    inner: S,
}

impl<S> std::fmt::Debug for Prefixed<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (stateful wrapper; the inner stream is omitted —
        // no `S: Debug` bound is imposed).
        f.debug_struct("Prefixed")
            .field(
                "prefix_remaining",
                &self.prefix.len().saturating_sub(self.served),
            )
            .finish()
    }
}

impl<S> Prefixed<S> {
    /// Returns the inner stream (an unreplayed prefix remainder is
    /// dropped — the caller has consumed it by then).
    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.served < this.prefix.len() {
            let n = (this.prefix.len() - this.served).min(out.remaining());
            let end = this.served + n;
            out.put_slice(&this.prefix[this.served..end]);
            this.served = end;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Sniff read: reads exactly `1 + legacy_pstr.len()` bytes from the
/// stream (with timeout), returns (replay stream, verdict). EOF before
/// the threshold -> [`MseError::Eof`] (the same reading as aria2
/// `MSEHandshake.cc`, which throws on a zero read).
pub async fn peek_sniff<S>(
    mut stream: S,
    legacy_pstr: &[u8],
    timeout: Duration,
) -> Result<(Prefixed<S>, Sniff), MseError>
where
    S: AsyncRead + Unpin,
{
    let want = 1 + legacy_pstr.len();
    let mut head = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        let n = timeout_io(timeout, stream.read(&mut head[filled..])).await?;
        if n == 0 {
            return Err(MseError::Eof);
        }
        filled += n;
    }
    let sniff = identify(&head, legacy_pstr);
    Ok((
        Prefixed {
            prefix: head,
            served: 0,
            inner: stream,
        },
        sniff,
    ))
}

// ---------------------------------------------------------------------------
// step2 payload assembly (shared by the drivers and the golden-vector
// tests; no drift)
// ---------------------------------------------------------------------------

/// step2 plaintext payload: VC(8B zero) + 4B bitmap + 2B pad length +
/// pad (all-zero content, `MSEHandshake.cc`; the caller injects the
/// pad-length randomness).
fn step2_payload(bits: u8, pad_len: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(VC_LENGTH + CRYPTO_BITFIELD_LENGTH + 2 + pad_len);
    p.extend_from_slice(&[0u8; VC_LENGTH]);
    let mut bitmap = [0u8; CRYPTO_BITFIELD_LENGTH];
    bitmap[3] = bits;
    p.extend_from_slice(&bitmap);
    // The caller guarantees pad length <= MAX_PAD_LENGTH; u16 always
    // suffices.
    p.extend_from_slice(&(pad_len as u16).to_be_bytes());
    p.resize(p.len() + pad_len, 0);
    p
}

/// Initiator step2 full bytes: req1 || req23 || enc(VC+provide+padC+
/// len(IA)=0) (`MSEHandshake.cc`; IA is always empty — "currently, IA
/// is zero-length"). Encryption uses `encryptor` (held by the caller to
/// continue into [`Encrypted`]).
pub(crate) fn compose_initiator_step2(
    secret: &[u8; KEY_LENGTH],
    info_hash: &[u8; 20],
    provide: u8,
    pad_len: usize,
    encryptor: &mut Arc4,
) -> Vec<u8> {
    let mut payload = step2_payload(provide, pad_len);
    // len(IA) (`MSEHandshake.cc`: currently always zero-length).
    payload.extend_from_slice(&0u16.to_be_bytes());
    encryptor.apply(&mut payload);
    let mut out = Vec::with_capacity(40 + payload.len());
    out.extend_from_slice(&req1_hash(secret));
    out.extend_from_slice(&req23_hash(secret, info_hash));
    out.extend_from_slice(&payload);
    out
}

/// Receiver step2 full bytes: enc(VC+select+padD) (`MSEHandshake.cc`).
pub(crate) fn compose_receiver_step2(select: u8, pad_len: usize, encryptor: &mut Arc4) -> Vec<u8> {
    let mut payload = step2_payload(select, pad_len);
    encryptor.apply(&mut payload);
    payload
}

// ---------------------------------------------------------------------------
// Pure state machines (one implementation shared by the async drivers
// and the fuzz targets)
// ---------------------------------------------------------------------------

/// Overlap-aware marker search (window <= 628B; a naive scan suffices).
fn find_marker(buf: &[u8], marker: &[u8]) -> Option<usize> {
    if buf.len() < marker.len() {
        return None;
    }
    (0..=buf.len() - marker.len()).find(|&i| &buf[i..i + marker.len()] == marker)
}

/// Parse advance result.
enum Progress {
    /// Needs more bytes.
    NeedMore,
    /// Completed the next stage.
    Advanced,
}

/// Receiver parse outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverOutcome {
    /// Index of the matched candidate infohash.
    pub matched: usize,
    /// Peer crypto_provide bitmap (lowest byte of the 4B big-endian
    /// bitmap).
    pub provide: u8,
    /// Decrypted IA (possibly empty — the aria2 initiator always sends
    /// an empty IA, `MSEHandshake.cc`).
    pub ia: Vec<u8>,
}

/// Decrypted tail after the req1 marker hit (padC/IA and the subsequent
/// stream share one decryptor state).
struct RxTail {
    d: Arc4,
    matched: usize,
    provide: u8,
    /// Remaining padC bytes.
    pad_c: usize,
    /// IA length (0 = not yet read).
    ia_len: usize,
    ia: Vec<u8>,
    stage: RxStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxStage {
    /// padC consumption (`MSEHandshake.cc receivePad`).
    PadC,
    /// len(IA) (`MSEHandshake.cc`).
    IaLen,
    /// IA payload (`MSEHandshake.cc`).
    Ia,
    Done,
}

/// Receiver handshake-tail parse state machine (no IO; shared by the
/// [`receive`] driver and the fuzz targets).
///
/// Fed the raw bytes **after the peer public key**; consumed stage by
/// stage, and every fatal input (sync window exhausted / unknown
/// infohash / bad VC / pad > 512 / IA > 68) -> [`MseError`].
pub struct ReceiverParser {
    info_hashes: Vec<[u8; 20]>,
    secret: [u8; KEY_LENGTH],
    req1: [u8; 20],
    /// The marker-search/decrypt head stages (the intermediate state
    /// after req1 is consumed but before the tail exists must persist,
    /// otherwise a fragmented arrival would re-search the consumed
    /// req1).
    lead: RxLead,
    tail: Option<RxTail>,
    buf: Vec<u8>,
}

impl std::fmt::Debug for ReceiverParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (stateful): `secret` is the DH shared secret and
        // `req1` its direct hash — both render as `<redacted>`; the
        // accepted infohash list shows as a count only (session
        // torrent-interest is not diagnostics payload).
        f.debug_struct("ReceiverParser")
            .field("info_hashes", &self.info_hashes.len())
            .field("secret", &"<redacted>")
            .field("req1", &"<redacted>")
            .field("lead", &self.lead)
            .field("tail_active", &self.tail.is_some())
            .field("buf_len", &self.buf.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RxLead {
    FindReq1,
    HashVcProvide,
}

impl ReceiverParser {
    /// One per candidate infohash (multi-swarm listening: v1 sha1
    /// alongside v2 truncated).
    pub fn new(info_hashes: Vec<[u8; 20]>, secret: [u8; KEY_LENGTH]) -> Self {
        ReceiverParser {
            req1: req1_hash(&secret),
            info_hashes,
            secret,
            lead: RxLead::FindReq1,
            tail: None,
            buf: Vec::new(),
        }
    }

    /// Feeds raw bytes and advances; `Ok(true)` = done
    /// ([`Self::outcome`] is available).
    pub fn push(&mut self, data: &[u8]) -> Result<bool, MseError> {
        if self.is_done() {
            return Ok(true);
        }
        self.buf.extend_from_slice(data);
        loop {
            match self.phase()? {
                Progress::Advanced => {}
                Progress::NeedMore => return Ok(self.is_done()),
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(
            self.tail.as_ref(),
            Some(t) if matches!(t.stage, RxStage::Done)
        )
    }

    /// Outcome snapshot (valid once done).
    pub fn outcome(&self) -> Option<ReceiverOutcome> {
        let t = self.tail.as_ref()?;
        Some(ReceiverOutcome {
            matched: t.matched,
            provide: t.provide,
            ia: t.ia.clone(),
        })
    }

    /// Finish: outcome + the receiver decryptor (state advanced to the
    /// IA end; feeds [`Encrypted`]) + remaining raw bytes (post-IA;
    /// decrypt or pass through per the negotiated level, then preset).
    pub fn finish(mut self) -> (Option<ReceiverOutcome>, Option<Arc4>, Vec<u8>) {
        match self.tail.take() {
            Some(t) => {
                let outcome = ReceiverOutcome {
                    matched: t.matched,
                    provide: t.provide,
                    ia: t.ia,
                };
                (Some(outcome), Some(t.d), self.buf)
            }
            None => (None, None, self.buf),
        }
    }

    fn progress(advanced: bool) -> Progress {
        if advanced {
            Progress::Advanced
        } else {
            Progress::NeedMore
        }
    }

    fn phase(&mut self) -> Result<Progress, MseError> {
        match self.lead {
            RxLead::FindReq1 => self.phase_find_req1(),
            RxLead::HashVcProvide => match self.tail.as_ref() {
                Some(t) if matches!(t.stage, RxStage::Done) => Ok(Progress::NeedMore),
                Some(_) => self.phase_tail(),
                None => self.phase_hash_vc_provide(),
            },
        }
    }

    /// req1 plaintext marker search (`MSEHandshake.cc
    /// findReceiverHashMarker`) -> req23 match + VC/provide/padC-length
    /// decryption.
    fn phase_find_req1(&mut self) -> Result<Progress, MseError> {
        if let Some(pos) = find_marker(&self.buf, &self.req1) {
            self.buf.drain(..pos + 20);
            self.lead = RxLead::HashVcProvide;
            return Ok(Progress::Advanced);
        }
        // Sync window: buffer >= 628-96 with no marker -> disconnect
        // (`MSEHandshake.cc`).
        if self.buf.len() >= RECEIVER_SYNC_WINDOW {
            return Err(MseError::MarkerNotFound { marker: "req1" });
        }
        Ok(Progress::NeedMore)
    }

    fn phase_hash_vc_provide(&mut self) -> Result<Progress, MseError> {
        const NEED: usize = 20 + VC_LENGTH + CRYPTO_BITFIELD_LENGTH + 2;
        if self.buf.len() < NEED {
            return Ok(Progress::NeedMore);
        }
        // Candidate req23 match (`MSEHandshake.cc`).
        let mut head = [0u8; 20];
        head.copy_from_slice(&self.buf[..20]);
        let secret = self.secret;
        let matched = self
            .info_hashes
            .iter()
            .position(|ih| req23_hash(&secret, ih) == head)
            .ok_or(MseError::UnknownInfoHash)?;
        // initCipher — the receiver decryptor uses the peer's
        // send-direction key.
        let (_, peer_key) = cipher_keys(&secret, &self.info_hashes[matched], Direction::Receiver);
        let mut d = dropped_arc4(&peer_key);
        // VC decrypted and checked for 8B of zeros (`verifyVC`).
        let mut vc = [0u8; VC_LENGTH];
        vc.copy_from_slice(&self.buf[20..20 + VC_LENGTH]);
        d.apply(&mut vc);
        if vc != [0u8; VC_LENGTH] {
            return Err(MseError::InvalidVc);
        }
        // crypto_provide (4B big-endian bitmap; lowest byte).
        let mut bitmap = [0u8; CRYPTO_BITFIELD_LENGTH];
        bitmap.copy_from_slice(&self.buf[28..32]);
        d.apply(&mut bitmap);
        let provide = bitmap[3];
        // len(padC) (2B big-endian + <=512 check).
        let mut pad_len_buf = [0u8; 2];
        pad_len_buf.copy_from_slice(&self.buf[32..34]);
        d.apply(&mut pad_len_buf);
        let pad_c = u16::from_be_bytes(pad_len_buf);
        if u32::from(pad_c) > MAX_PAD_LENGTH as u32 {
            return Err(MseError::PadTooLarge {
                pad: "PadC",
                length: pad_c,
                max: MAX_PAD_LENGTH as u16,
            });
        }
        self.buf.drain(..NEED);
        self.tail = Some(RxTail {
            d,
            matched,
            provide,
            pad_c: pad_c as usize,
            ia_len: 0,
            ia: Vec::new(),
            stage: if pad_c > 0 {
                RxStage::PadC
            } else {
                RxStage::IaLen
            },
        });
        Ok(Progress::Advanced)
    }

    /// padC consumption (`MSEHandshake.cc`) -> len(IA) -> IA payload.
    fn phase_tail(&mut self) -> Result<Progress, MseError> {
        let mut advanced = false;
        loop {
            let Some(tail) = self.tail.as_mut() else {
                return Ok(Self::progress(advanced));
            };
            match tail.stage {
                RxStage::PadC => {
                    if self.buf.len() < tail.pad_c {
                        return Ok(Self::progress(advanced));
                    }
                    // Decrypt and discard (`MSEHandshake.cc`).
                    let mut chunk: Vec<u8> = self.buf.drain(..tail.pad_c).collect();
                    tail.d.apply(&mut chunk);
                    tail.pad_c = 0;
                    tail.stage = RxStage::IaLen;
                }
                RxStage::IaLen => {
                    if self.buf.len() < 2 {
                        return Ok(Self::progress(advanced));
                    }
                    let mut b = [0u8; 2];
                    b.copy_from_slice(&self.buf[..2]);
                    tail.d.apply(&mut b);
                    self.buf.drain(..2);
                    let len = u16::from_be_bytes(b) as usize;
                    if len > IA_MAX_LENGTH {
                        return Err(MseError::IaTooLarge(len as u16));
                    }
                    tail.ia_len = len;
                    tail.stage = if len > 0 { RxStage::Ia } else { RxStage::Done };
                }
                RxStage::Ia => {
                    if self.buf.len() < tail.ia_len {
                        return Ok(Self::progress(advanced));
                    }
                    let mut chunk: Vec<u8> = self.buf.drain(..tail.ia_len).collect();
                    tail.d.apply(&mut chunk);
                    tail.ia = chunk;
                    tail.stage = RxStage::Done;
                }
                RxStage::Done => return Ok(Self::progress(advanced)),
            }
            advanced = true;
        }
    }
}

/// Initiator parse stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IxStage {
    /// VC marker search (`MSEHandshake.cc findInitiatorVCMarker`).
    FindVc,
    /// crypto_select + len(padD) decryption.
    SelectPad,
    /// Remaining padD bytes.
    PadD(usize),
    Done,
}

/// Initiator handshake-tail parse state machine (no IO; shared by the
/// [`initiate`] driver and the fuzz targets).
///
/// The peer VC marker and the decryptor share a source: the decryptor
/// uses the peer-direction key (1024B dropped) and the VC marker is its
/// first 8B of keystream XOR the zero VC (`MSEHandshake.cc`).
pub struct InitiatorParser {
    d: Arc4,
    vc_marker: [u8; VC_LENGTH],
    select: u8,
    stage: IxStage,
    buf: Vec<u8>,
}

impl std::fmt::Debug for InitiatorParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (stateful): `d` renders via Arc4's redacting
        // Debug; `vc_marker` is omitted (derived from the peer-direction
        // keystream — kept out of diagnostics on principle).
        f.debug_struct("InitiatorParser")
            .field("d", &self.d)
            .field("select", &self.select)
            .field("stage", &self.stage)
            .field("buf_len", &self.buf.len())
            .finish()
    }
}

impl InitiatorParser {
    /// `peer_key` = the peer's send-direction key
    /// (`cipher_keys(.., Direction::Initiator).1`).
    pub fn new(peer_key: [u8; 20]) -> Self {
        // Initiator VC probe marker: the first 8B of keystream from an
        // independent fresh ARC4 (same key, same drop) —
        // `MSEHandshake.cc` (aria2 uses a separate `ARC4Encryptor enc`).
        let mut marker_arc = dropped_arc4(&peer_key);
        let mut vc_marker = [0u8; VC_LENGTH];
        marker_arc.apply(&mut vc_marker);
        InitiatorParser {
            d: dropped_arc4(&peer_key),
            vc_marker,
            select: 0,
            stage: IxStage::FindVc,
            buf: Vec::new(),
        }
    }

    /// Feeds raw bytes and advances; `Ok(true)` = done.
    pub fn push(&mut self, data: &[u8]) -> Result<bool, MseError> {
        if self.is_done() {
            return Ok(true);
        }
        self.buf.extend_from_slice(data);
        loop {
            match self.phase()? {
                Progress::Advanced => {}
                Progress::NeedMore => return Ok(self.is_done()),
            }
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.stage, IxStage::Done)
    }

    /// Peer crypto_select bitmap (lowest byte of the 4B big-endian
    /// bitmap; valid once done).
    pub fn select(&self) -> Option<u8> {
        if self.is_done() {
            Some(self.select)
        } else {
            None
        }
    }

    /// Finish: the select bitmap + the initiator decryptor (state
    /// advanced to the padD end) + remaining raw bytes (post-padD;
    /// decrypt or pass through per the negotiated level, then preset).
    pub fn finish(self) -> (Option<u8>, Arc4, Vec<u8>) {
        (self.select(), self.d, self.buf)
    }

    fn progress(advanced: bool) -> Progress {
        if advanced {
            Progress::Advanced
        } else {
            Progress::NeedMore
        }
    }

    fn phase(&mut self) -> Result<Progress, MseError> {
        let mut advanced = false;
        loop {
            match self.stage {
                IxStage::FindVc => {
                    match find_marker(&self.buf, &self.vc_marker) {
                        Some(pos) => {
                            // verifyVC: the marker bytes feed the
                            // decryptor to advance its state (same
                            // reading as `verifyVC` before
                            // `shiftBuffer` — the marker itself is
                            // keystream).
                            let end = pos + VC_LENGTH;
                            let mut marker = self.buf[pos..end].to_vec();
                            self.d.apply(&mut marker);
                            self.buf.drain(..end);
                            self.stage = IxStage::SelectPad;
                        }
                        None => {
                            // Sync window: buffer >= 616-96 with no
                            // marker -> disconnect (`MSEHandshake.cc`).
                            if self.buf.len() >= INITIATOR_SYNC_WINDOW {
                                return Err(MseError::MarkerNotFound { marker: "VC" });
                            }
                            return Ok(Self::progress(advanced));
                        }
                    }
                }
                IxStage::SelectPad => {
                    const NEED: usize = CRYPTO_BITFIELD_LENGTH + 2;
                    if self.buf.len() < NEED {
                        return Ok(Self::progress(advanced));
                    }
                    let mut chunk = self.buf.drain(..NEED).collect::<Vec<u8>>();
                    self.d.apply(&mut chunk);
                    self.select = chunk[3];
                    let pad_d = u16::from_be_bytes([chunk[4], chunk[5]]);
                    if u32::from(pad_d) > MAX_PAD_LENGTH as u32 {
                        return Err(MseError::PadTooLarge {
                            pad: "PadD",
                            length: pad_d,
                            max: MAX_PAD_LENGTH as u16,
                        });
                    }
                    self.stage = if pad_d > 0 {
                        IxStage::PadD(pad_d as usize)
                    } else {
                        IxStage::Done
                    };
                }
                IxStage::PadD(n) => {
                    if self.buf.len() < n {
                        return Ok(Self::progress(advanced));
                    }
                    // Decrypt and discard (`MSEHandshake.cc`).
                    let mut chunk = self.buf.drain(..n).collect::<Vec<u8>>();
                    self.d.apply(&mut chunk);
                    self.stage = IxStage::Done;
                }
                IxStage::Done => return Ok(Self::progress(advanced)),
            }
            advanced = true;
        }
    }
}

// ---------------------------------------------------------------------------
// Encrypted<S>: the post-negotiation wrapper stream (an added impl at
// the frozen PeerTransport seam; the seam shape is unchanged)
// ---------------------------------------------------------------------------

/// Wrapper stream that decrypts reads and encrypts writes. With
/// `encryptor`/`decryptor` = `None` (negotiation result = PLAIN) it
/// passes bytes through unchanged.
pub struct Encrypted<S> {
    inner: S,
    encryptor: Option<Arc4>,
    decryptor: Option<Arc4>,
    /// Preset plaintext (IA / leftover bytes over-read during the
    /// handshake), replayed first on the read path.
    preset: Vec<u8>,
    preset_pos: usize,
    /// Read scratch buffer (avoids an allocation per poll).
    scratch: Vec<u8>,
    /// Write path: ciphertext encrypted but not fully written (ARC4 is a
    /// stream cipher — a given plaintext may advance the keystream only
    /// once; a `Pending` retry must never re-encrypt the caller's same
    /// buffer).
    pending: Vec<u8>,
    pending_pos: usize,
    /// Staged-write progress reported to the caller (`pending_pos` as of
    /// the last `Ready` return). The `AsyncWrite` retry contract makes
    /// the caller's outstanding window `pending.len() - reported_pos`;
    /// the gap `pending_pos - reported_pos` is ciphertext drained inside
    /// the flush loop before a `Pending`/error return — accepted by the
    /// inner writer but invisible to the caller. Drives the flush-mode
    /// retry-buffer validation in `poll_write`.
    reported_pos: usize,
}

impl<S> std::fmt::Debug for Encrypted<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (stateful wrapper): the Arc4 fields render via
        // Arc4's redacting Debug; byte buffers show as lengths only (the
        // pending buffer is ciphertext, the preset is plaintext — the
        // payload does not belong in diagnostics). The inner stream is
        // omitted (no `S: Debug` bound is imposed).
        f.debug_struct("Encrypted")
            .field("encryptor", &self.encryptor)
            .field("decryptor", &self.decryptor)
            .field(
                "preset_remaining",
                &self.preset.len().saturating_sub(self.preset_pos),
            )
            .field("pending_len", &self.pending.len())
            .field("pending_pos", &self.pending_pos)
            .field("reported_pos", &self.reported_pos)
            .finish()
    }
}

impl<S> Encrypted<S> {
    const SCRATCH_LEN: usize = 16 * 1024;

    fn new(inner: S, encryptor: Option<Arc4>, decryptor: Option<Arc4>) -> Self {
        Encrypted {
            inner,
            encryptor,
            decryptor,
            preset: Vec::new(),
            preset_pos: 0,
            scratch: vec![0u8; Self::SCRATCH_LEN],
            pending: Vec::new(),
            pending_pos: 0,
            reported_pos: 0,
        }
    }

    /// Presets plaintext bytes (IA + handshake leftovers; replayed first
    /// in subsequent reads).
    pub fn preset_plaintext(&mut self, data: &[u8]) {
        self.preset.extend_from_slice(data);
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Returns the inner stream (unconsumed preset plaintext is dropped
    /// — the caller should have consumed it).
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Encrypted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // 1) Replay preset plaintext.
        if this.preset_pos < this.preset.len() {
            let n = (this.preset.len() - this.preset_pos).min(out.remaining());
            let end = this.preset_pos + n;
            out.put_slice(&this.preset[this.preset_pos..end]);
            this.preset_pos = end;
            if this.preset_pos == this.preset.len() {
                this.preset.clear();
                this.preset_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        // 2) Read ciphertext -> decrypt in place -> copy out (the part
        // beyond `out`'s capacity returns to the preset buffer).
        let n = {
            let mut rbuf = ReadBuf::new(&mut this.scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rbuf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => rbuf.filled().len(),
            }
        };
        if n == 0 {
            return Poll::Ready(Ok(())); // EOF
        }
        if let Some(d) = this.decryptor.as_mut() {
            d.apply(&mut this.scratch[..n]);
        }
        let copy = n.min(out.remaining());
        out.put_slice(&this.scratch[..copy]);
        if copy < n {
            this.preset.clear();
            this.preset_pos = 0;
            this.preset.extend_from_slice(&this.scratch[copy..n]);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Encrypted<S> {
    /// Write path (ciphertext-staging semantics):
    /// - `pending` non-empty <=> the previous call returned
    ///   `Pending`/partial write; the staged ciphertext must be retried
    ///   with exactly the caller's outstanding window: the staged
    ///   plaintext minus the bytes already reported as accepted, i.e.
    ///   `buf.len() == pending.len() - reported_pos` (`write_all`
    ///   retries `&buf[n..]` of what was reported; ARC4 is a stream
    ///   cipher so ciphertext:plaintext align 1:1). A different length
    ///   is rejected with `InvalidInput` — accepting it would drain the
    ///   old ciphertext while the new bytes go out unencrypted and
    ///   permanently desync the ARC4 keystream. Flush only, never
    ///   re-encrypt (ARC4 keystream: one plaintext once; re-encrypting
    ///   corrupts); an inner `Ok(0)` reports `WriteZero` instead of
    ///   spinning forever;
    /// - `pending` empty: encrypt the whole `buf` (exactly once) ->
    ///   flush immediately -> fully written = `Ok(buf.len())`; a partial
    ///   write stages the remainder and reports the accepted byte count
    ///   (ciphertext/plaintext align 1:1); `Pending` stages the whole
    ///   thing and returns `Pending` (0 bytes accepted; the retry takes
    ///   the flush branch).
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let Some(e) = this.encryptor.as_mut() else {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        };
        if this.pending_pos < this.pending.len() {
            // Flush mode: the retry buffer must be the caller's
            // outstanding window (`pending_pos - reported_pos` may have
            // drained inside a previous `Pending` return and is
            // invisible to the caller); anything else would corrupt the
            // stream (see the doc above).
            if buf.len() != this.pending.len() - this.reported_pos {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "MSE retry buffer must be the unaccepted remainder of the staged write",
                )));
            }
            // Flush mode: write the existing ciphertext only.
            loop {
                match Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_pos..]) {
                    Poll::Ready(Ok(0)) => {
                        // The inner writer accepts nothing: retrying
                        // would spin forever (a write of a non-empty
                        // buffer must never surface Ok(0)).
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "MSE inner writer stopped accepting ciphertext",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        this.pending_pos += n;
                        if this.pending_pos == this.pending.len() {
                            // All staged ciphertext accepted by the peer
                            // = the caller's outstanding window (which
                            // may exceed the remainder by the progress
                            // made inside this loop) fully accepted.
                            this.pending.clear();
                            this.pending_pos = 0;
                            this.reported_pos = 0;
                            return Poll::Ready(Ok(buf.len()));
                        }
                    }
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }
        }
        // First sighting of this buf: encrypt once and try to write.
        this.pending.clear();
        this.pending.extend_from_slice(buf);
        e.apply(&mut this.pending);
        this.pending_pos = 0;
        this.reported_pos = 0;
        match Pin::new(&mut this.inner).poll_write(cx, &this.pending[..]) {
            Poll::Ready(Ok(n)) => {
                this.pending_pos += n;
                if this.pending_pos == this.pending.len() {
                    this.pending.clear();
                    this.pending_pos = 0;
                    Poll::Ready(Ok(buf.len()))
                } else {
                    // Partial write: stage the ciphertext remainder and
                    // report the accepted byte count.
                    this.reported_pos = this.pending_pos;
                    Poll::Ready(Ok(this.pending_pos))
                }
            }
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    /// Flushes the staged ciphertext first, then forwards flush (must
    /// run before `poll_shutdown`; tokio `AsyncWriteExt::shutdown`
    /// flushes internally first).
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.pending_pos < this.pending.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_pos..]) {
                Poll::Ready(Ok(0)) => {
                    // The inner writer accepts nothing: the drain loop
                    // would never terminate (same guard as `poll_write`).
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "MSE inner writer stopped accepting ciphertext",
                    )));
                }
                Poll::Ready(Ok(n)) => this.pending_pos += n,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }
        this.pending.clear();
        this.pending_pos = 0;
        this.reported_pos = 0;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

// ---------------------------------------------------------------------------
// Negotiation drivers (initiator / receiver, both directions)
// ---------------------------------------------------------------------------

/// Negotiation result.
pub struct Negotiated<S> {
    /// The encrypted stream, transparent to upper layers (IA / leftover
    /// bytes preset as plaintext).
    pub stream: Encrypted<S>,
    /// Negotiated crypto level.
    pub crypto: CryptoLevel,
}

impl<S> std::fmt::Debug for Negotiated<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written (wraps the stateful [`Encrypted`]; the stream
        // field renders via its own redacting Debug — no `S: Debug`
        // bound is imposed).
        f.debug_struct("Negotiated")
            .field("stream", &self.stream)
            .field("crypto", &self.crypto)
            .finish()
    }
}

/// Sends "96B public key + random pad" (`MSEHandshake.cc
/// sendPublicKey`: pad length random 0..=512, content random).
async fn send_public_key<S>(stream: &mut S, public_key: [u8; KEY_LENGTH]) -> Result<(), MseError>
where
    S: AsyncWrite + Unpin,
{
    let pad_len: u16 = rand::random_range(0..=MAX_PAD_LENGTH as u16);
    let mut msg = Vec::with_capacity(KEY_LENGTH + pad_len as usize);
    msg.extend_from_slice(&public_key);
    let pad_start = msg.len();
    msg.resize(pad_start + pad_len as usize, 0);
    rand::rng().fill_bytes(&mut msg[pad_start..]);
    Ok(stream.write_all(&msg).await?)
}

/// Initiator MSE handshake (aria2 `InitiatorMSEHandshakeCommand.cc`
/// sequence): pubkey -> peer pubkey -> S/key derivation ->
/// req1+req23+step2 -> VC marker probe -> select/padD. On success
/// [`Encrypted`] can directly carry the legacy BT handshake
/// (`handshake_exchange`). require-crypto semantics act through
/// [`CryptoPolicy::provide`] (plain absent = ARC4 forced, no silent
/// fallback).
pub async fn initiate<S>(
    mut stream: S,
    info_hash: [u8; 20],
    policy: CryptoPolicy,
    timeout: Duration,
) -> Result<Negotiated<S>, MseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. DH keygen (spawn_blocking; once per connection, SPEC §6.4).
    let dh = DhKeyExchange::generate().await?;
    let my_pub = dh.public_key_bytes();
    // 2. pubkey + pad (INITIATOR_SEND_KEY).
    timeout_io(timeout, send_public_key(&mut stream, my_pub)).await?;
    // 3. Peer pubkey -> S (INITIATOR_WAIT_KEY, `receivePublicKey`).
    let mut peer_pub = [0u8; KEY_LENGTH];
    timeout_io(timeout, stream.read_exact(&mut peer_pub)).await?;
    let (_, secret) = dh.compute_secret_async(peer_pub).await?;
    // 4. initCipher + step2 (INITIATOR_SEND_STEP2; IA always empty).
    let (local_key, peer_key) = cipher_keys(&secret, &info_hash, Direction::Initiator);
    let mut encryptor = dropped_arc4(&local_key);
    let step2 = compose_initiator_step2(
        &secret,
        &info_hash,
        policy.provide(),
        random_pad_len(),
        &mut encryptor,
    );
    timeout_io(timeout, stream.write_all(&step2)).await?;
    // 5. VC marker search + select/padD (INITIATOR_FIND_VC_MARKER..).
    let mut parser = InitiatorParser::new(peer_key);
    let mut chunk = [0u8; 512];
    loop {
        if parser.push(&[])? {
            break;
        }
        let n = timeout_io(timeout, stream.read(&mut chunk)).await?;
        if n == 0 {
            return Err(MseError::Eof);
        }
        if parser.push(&chunk[..n])? {
            break;
        }
    }
    let (select, decryptor, leftover_raw) = parser.finish();
    let select = select.ok_or(MseError::NoCryptoAgreed)?;
    let crypto = policy
        .select_from_select(select)
        .ok_or(MseError::NoCryptoAgreed)?;
    debug!(target: LOG_TARGET, ?crypto, "MSE initiated");
    // PLAIN: the post-handshake stream is plaintext — neither direction
    // installs a cipher (the encryptor continues only under ARC4;
    // `MSEHandshake.cc`'s plain branch skips enableEncryption).
    let mut stream = Encrypted::new(
        stream,
        if crypto == CryptoLevel::Arc4 {
            Some(encryptor)
        } else {
            None
        },
        if crypto == CryptoLevel::Arc4 {
            Some(decryptor)
        } else {
            None
        },
    );
    // Leftover bytes over-read during the handshake: ARC4 -> preset
    // decrypted; PLAIN -> preset as-is (aria2
    // `InitiatorMSEHandshakeCommand.cc` presetBuffer).
    let mut leftover = leftover_raw;
    if crypto == CryptoLevel::Arc4
        && let Some(d) = stream.decryptor.as_mut()
    {
        d.apply(&mut leftover);
    }
    stream.preset_plaintext(&leftover);
    Ok(Negotiated { stream, crypto })
}

/// Receiver MSE handshake (aria2 `ReceiverMSEHandshakeCommand.cc`
/// sequence): peer pubkey -> S -> reply pubkey -> req1 search ->
/// req23 candidate match -> VC/provide/padC/IA -> reply step2.
/// `info_hashes` = local candidates (hybrid dual infohash side by
/// side); returns the matched candidate index. IA and the leftover
/// handshake bytes are preset as plaintext, so the caller can go
/// straight into `handshake_accept_any`.
pub async fn receive<S>(
    mut stream: S,
    info_hashes: &[[u8; 20]],
    policy: CryptoPolicy,
    timeout: Duration,
) -> Result<(Negotiated<S>, usize), MseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Peer pubkey (RECEIVER_WAIT_KEY; the 20B over-read while
    // sniffing belongs to the pubkey, replayed by the caller via
    // Prefixed).
    let mut peer_pub = [0u8; KEY_LENGTH];
    timeout_io(timeout, stream.read_exact(&mut peer_pub)).await?;
    // 2. Local keypair + S (initEncryptionFacility generates right
    // after identify, `ReceiverMSEHandshakeCommand.cc`; merged here,
    // timing equivalent).
    let dh = DhKeyExchange::generate().await?;
    let (dh, secret) = dh.compute_secret_async(peer_pub).await?;
    // 3. Reply pubkey + pad (RECEIVER_SEND_KEY_PENDING).
    let my_pub = dh.public_key_bytes();
    timeout_io(timeout, send_public_key(&mut stream, my_pub)).await?;
    // 4. req1 search -> req23 match -> VC/provide/padC/IA
    // (RECEIVER_FIND_HASH_MARKER..).
    let mut parser = ReceiverParser::new(info_hashes.to_vec(), secret);
    let mut chunk = [0u8; 512];
    loop {
        let n = timeout_io(timeout, stream.read(&mut chunk)).await?;
        if n == 0 {
            return Err(MseError::Eof);
        }
        if parser.push(&chunk[..n])? {
            break;
        }
    }
    let (outcome, decryptor, leftover_raw) = parser.finish();
    let outcome = outcome.ok_or(MseError::UnknownInfoHash)?;
    let crypto = policy
        .select_from_provide(outcome.provide)
        .ok_or(MseError::NoCryptoAgreed)?;
    let info_hash = info_hashes[outcome.matched];
    // 5. Reply step2 (RECEIVER_RECEIVE_IA -> sendReceiverStep2).
    let (local_key, _) = cipher_keys(&secret, &info_hash, Direction::Receiver);
    let mut encryptor = dropped_arc4(&local_key);
    let step2 = compose_receiver_step2(crypto.bit(), random_pad_len(), &mut encryptor);
    timeout_io(timeout, stream.write_all(&step2)).await?;
    debug!(target: LOG_TARGET, ?crypto, matched = outcome.matched, "MSE accepted");
    let mut stream = Encrypted::new(
        stream,
        if crypto == CryptoLevel::Arc4 {
            Some(encryptor)
        } else {
            None
        },
        if crypto == CryptoLevel::Arc4 {
            decryptor
        } else {
            None
        },
    );
    // IA (plaintext) + remaining raw bytes (ARC4 -> decrypt; PLAIN ->
    // pass through) preset (aria2 `ReceiverMSEHandshakeCommand.cc`
    // presetBuffer(IA)).
    let mut preset = outcome.ia;
    let mut leftover = leftover_raw;
    if crypto == CryptoLevel::Arc4
        && let Some(d) = stream.decryptor.as_mut()
    {
        d.apply(&mut leftover);
    }
    preset.extend_from_slice(&leftover);
    stream.preset_plaintext(&preset);
    Ok((Negotiated { stream, crypto }, outcome.matched))
}

#[cfg(test)]
mod tests;

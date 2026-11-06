//! bt-layer MSE integration:
//! inbound sniff-and-split (legacy/MSE), require-crypto rejection of
//! legacy inbound, the min-crypto-level provide set, outbound initiation,
//! and the announce parameter.
//!
//! The crypto primitives and handshake state machine live in
//! [`taiji_io::mse`] (an IO leaf crate, protocol-agnostic — the sniff pure
//! function receives the legacy prefix from this layer); this module holds
//! only protocol knowledge and split decisions (the decision surface of
//! the reference `ReceiverMSEHandshakeCommand.cc`).
//!
//! # Wiring points
//!
//! - The engine accept path currently calls
//! [`crate::peer::handshake_accept_any`] directly; wiring it up means
//! swapping that call for this module's [`accept_any`] (the
//! `PeerTransport` seam shape is unchanged). Core-side file ownership is
//! separate; this module does not reach across it.
//! - The announce `requirecrypto=1` landing point is in the tracker;
//! [`announce_crypto_param`] is its parameter surface, with semantics
//! matching `DefaultBtAnnounce.cc`.
//!
//! # Tests
//!
//! See the `tests` module in this file: the legacy zero-delay path (no MSE
//! triggered), require-crypto rejecting legacy, MSE at both levels
//! inbound + carrying a full BT handshake, and sniff boundaries (0x13 but
//! mismatching pstr -> MSE).

use std::time::Duration;

use taiji_io::mse::{self, MseError, Prefixed, Sniff};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::peer::handshake_accept_any;
use crate::peer_wire::{Handshake, PeerWireError, Reserved};

// Policy/transport types are re-exported with this module's public
// signatures (accept_any/connect take or return them; the engine wiring
// gets them via bt::mse — core need not depend on io directly).
pub use taiji_io::mse::{CryptoLevel, CryptoPolicy, Encrypted};

/// tracing target.
const LOG_TARGET: &str = "taiji::bt::mse";

/// The legacy handshake pstr (matches `BtHandshakeMessage.cc BT_PSTR`).
/// io::mse stays protocol-agnostic; this layer passes it in at split time.
pub fn legacy_pstr() -> &'static [u8] {
    crate::peer_wire::PSTR
}

/// The announce URL crypto parameter (reference `DefaultBtAnnounce.cc`:
/// require/force -> `requirecrypto=1`, otherwise `supportcrypto=1` —
/// aria2 sends one of the two).
pub fn announce_crypto_param(policy: CryptoPolicy) -> &'static str {
    if policy.require_crypto {
        "requirecrypto=1"
    } else {
        "supportcrypto=1"
    }
}

/// Inbound split error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AcceptError {
    /// A legacy inbound is rejected under require-crypto (reference
    /// `ReceiverMSEHandshakeCommand.cc`).
    #[error("legacy handshake rejected: bt-require-crypto is enabled")]
    LegacyRejected,
    #[error(transparent)]
    Mse(#[from] MseError),
    #[error(transparent)]
    Wire(#[from] PeerWireError),
}

/// The connection stream after splitting: a unified
/// `AsyncRead + AsyncWrite` surface (the frozen `PeerTransport` seam
/// semantics — the caller/PeerTask is oblivious to transport and crypto
/// shape).
#[derive(Debug)]
pub enum PeerStream<S> {
    /// Legacy direct connection (the pre-read prefix has been replayed).
    Legacy(Prefixed<S>),
    /// The decrypted stream after MSE negotiation (the IA is pre-seeded
    /// with plaintext; Box flattens the enum size gap — `Encrypted`
    /// contains 2x256B of ARC4 state + a read scratch buffer).
    Encrypted(Box<Encrypted<Prefixed<S>>>),
}

impl<S: AsyncRead + Unpin> AsyncRead for PeerStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            PeerStream::Legacy(s) => std::pin::pin!(s).poll_read(cx, out),
            PeerStream::Encrypted(s) => std::pin::pin!(s.as_mut()).poll_read(cx, out),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeerStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            PeerStream::Legacy(s) => std::pin::pin!(s).poll_write(cx, buf),
            PeerStream::Encrypted(s) => std::pin::pin!(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            PeerStream::Legacy(s) => std::pin::pin!(s).poll_flush(cx),
            PeerStream::Encrypted(s) => std::pin::pin!(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            PeerStream::Legacy(s) => std::pin::pin!(s).poll_shutdown(cx),
            PeerStream::Encrypted(s) => std::pin::pin!(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// An inbound connection after splitting.
#[derive(Debug)]
pub struct Accepted<S> {
    /// A connection that can already transparently carry the legacy BT
    /// message stream.
    pub stream: PeerStream<S>,
    /// The index of the matched candidate infohash (hybrid dual-swarm
    /// shared listen).
    pub matched: usize,
    /// The peer's BT handshake.
    pub handshake: Handshake,
    /// This connection's crypto level (the legacy path = Plain; the
    /// getPeers `crypto` field vocabulary).
    pub crypto: CryptoLevel,
}

/// Inbound sniff-and-split (mirrors `ReceiverMSEHandshakeCommand.cc`):
/// peek 20B -> `0x13 + "BitTorrent protocol"` -> legacy (rejected when
/// require-crypto is on); otherwise run the MSE receive handshake
/// (multi-candidate req2/req3 matching) -> complete the legacy BT
/// handshake over the negotiated transparent stream. The legacy path pays
/// no MSE cost (a 20B read plus one memcmp-shaped check, `MSEHandshake.cc`).
pub async fn accept_any<S>(
    stream: S,
    my_peer_id: &[u8; 20],
    candidates: &[([u8; 20], Reserved)],
    policy: CryptoPolicy,
    timeout: Duration,
) -> Result<Accepted<S>, AcceptError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (stream, sniff) = mse::peek_sniff(stream, legacy_pstr(), timeout).await?;
    match sniff {
        Sniff::Legacy => {
            if policy.require_crypto {
                tracing::debug!(target: LOG_TARGET, "rejecting legacy handshake (require-crypto)");
                return Err(AcceptError::LegacyRejected);
            }
            let (stream, matched, handshake) =
                handshake_accept_any(stream, my_peer_id, candidates, timeout).await?;
            Ok(Accepted {
                stream: PeerStream::Legacy(stream),
                matched,
                handshake,
                crypto: CryptoLevel::Plain,
            })
        }
        Sniff::Encrypted => {
            let hashes: Vec<[u8; 20]> = candidates.iter().map(|(ih, _)| *ih).collect();
            let (negotiated, _) = mse::receive(stream, &hashes, policy, timeout).await?;
            // The BT handshake inside the MSE payload: the IA is already
            // pre-seeded with plaintext, so reuse the multi-candidate
            // accept.
            let (stream, matched, handshake) =
                handshake_accept_any(negotiated.stream, my_peer_id, candidates, timeout).await?;
            tracing::debug!(target: LOG_TARGET, crypto = ?negotiated.crypto, "accepted encrypted peer");
            Ok(Accepted {
                stream: PeerStream::Encrypted(Box::new(stream)),
                matched,
                handshake,
                crypto: negotiated.crypto,
            })
        }
        // peek_sniff only returns after reading 1+pstr.len() bytes, so
        // NeedMore is unreachable; defensively mapped to EOF.
        Sniff::NeedMore => Err(MseError::Eof.into()),
    }
}

/// Outbound MSE connection (mirrors `InitiatorMSEHandshakeCommand.cc`).
/// The require-crypto semantics take effect through
/// [`CryptoPolicy::provide`] (a missing plain entry forces ARC4, with no
/// silent fallback — a design-forbidden outcome). Returns the wrapped
/// stream and the negotiated level; the caller then runs
/// [`crate::peer::handshake_exchange`] on top.
pub async fn connect<S>(
    stream: S,
    info_hash: [u8; 20],
    policy: CryptoPolicy,
    timeout: Duration,
) -> Result<(Encrypted<S>, CryptoLevel), MseError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let negotiated = mse::initiate(stream, info_hash, policy, timeout).await?;
    Ok((negotiated.stream, negotiated.crypto))
}

#[cfg(test)]
mod tests;

//! Peer wire handshake exchange surface (BEP3): outbound
//! [`handshake_exchange`] (write our 68-byte handshake, read the peer's 68
//! bytes, verify pstr and info_hash), inbound multi-candidate
//! [`handshake_accept_any`] (hybrid dual swarm sharing one listen port:
//! match the peer's info_hash against the candidates and answer as the
//! matched candidate), and the single-swarm convenience form
//! [`handshake_accept`]. Pure frame send/recv; timeouts are injected by the
//! caller. Once MSE sniffing has routed the stream, `crate::mse`'s accept
//! path calls directly into this module.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

/// Outbound handshake exchange: write our 68-byte handshake, read the
/// peer's 68 bytes, verify pstr and info_hash (BEP3; an info_hash mismatch
/// means the wrong swarm — disconnect). Returns the peer's handshake.
/// `reserved` is assembled by the caller from swarm capabilities
/// (fast/ext plus the BEP-52 v2 bit, [`crate::peer_wire::Reserved::with_v2`]).
pub async fn handshake_exchange<S>(
    mut stream: S,
    my_info_hash: &[u8; 20],
    my_peer_id: &[u8; 20],
    reserved: crate::peer_wire::Reserved,
    timeout: Duration,
) -> Result<(S, crate::peer_wire::Handshake), crate::peer_wire::PeerWireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use crate::peer_wire::{Handshake, PeerWireError};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mine = Handshake {
        reserved,
        info_hash: *my_info_hash,
        peer_id: *my_peer_id,
    };
    let encoded = mine.encode();
    let write = stream.write_all(&encoded);
    tokio::time::timeout(timeout, write)
        .await
        .map_err(|_| PeerWireError::InvalidHandshake("handshake write timeout".into()))?
        .map_err(PeerWireError::from)?;
    let mut buf = [0u8; crate::peer_wire::HANDSHAKE_LEN];
    let read = stream.read_exact(&mut buf);
    tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| PeerWireError::InvalidHandshake("handshake read timeout".into()))?
        .map_err(PeerWireError::from)?;
    let theirs = Handshake::decode(&buf)?;
    if theirs.info_hash != *my_info_hash {
        return Err(PeerWireError::InvalidHandshake(
            "info_hash mismatch (wrong swarm)".into(),
        ));
    }
    Ok((stream, theirs))
}

/// Inbound server-side handshake with multi-candidate dispatch: read the
/// peer's 68 bytes, match its info_hash against `candidates` (hybrid dual
/// swarm sharing one listen port: v1 sha1 and v2 truncated sha256 are
/// separate candidates), then answer with our 68-byte handshake keyed to
/// the matched candidate's (info_hash, reserved). Returns the matched
/// candidate index and the peer's handshake; no match means the wrong
/// swarm — close without answering (BEP3).
pub async fn handshake_accept_any<S>(
    mut stream: S,
    my_peer_id: &[u8; 20],
    candidates: &[([u8; 20], crate::peer_wire::Reserved)],
    timeout: Duration,
) -> Result<(S, usize, crate::peer_wire::Handshake), crate::peer_wire::PeerWireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use crate::peer_wire::{Handshake, PeerWireError};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; crate::peer_wire::HANDSHAKE_LEN];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf))
        .await
        .map_err(|_| PeerWireError::InvalidHandshake("handshake read timeout".into()))?
        .map_err(PeerWireError::from)?;
    let theirs = Handshake::decode(&buf)?;
    let matched = candidates
        .iter()
        .position(|(ih, _)| *ih == theirs.info_hash)
        .ok_or(PeerWireError::InvalidHandshake(
            "info_hash mismatch (wrong swarm)".into(),
        ))?;
    let (my_info_hash, reserved) = candidates[matched];
    let mine = Handshake {
        reserved,
        info_hash: my_info_hash,
        peer_id: *my_peer_id,
    };
    let encoded = mine.encode();
    tokio::time::timeout(timeout, stream.write_all(&encoded))
        .await
        .map_err(|_| PeerWireError::InvalidHandshake("handshake write timeout".into()))?
        .map_err(PeerWireError::from)?;
    Ok((stream, matched, theirs))
}

/// Inbound server-side handshake for a single swarm (convenience form):
/// read the peer's 68 bytes, verify pstr/info_hash, answer with our 68
/// bytes (BEP3; the accept side is entered from the listener). Returns the
/// peer's handshake.
pub async fn handshake_accept<S>(
    stream: S,
    my_info_hash: &[u8; 20],
    my_peer_id: &[u8; 20],
    reserved: crate::peer_wire::Reserved,
    timeout: Duration,
) -> Result<(S, crate::peer_wire::Handshake), crate::peer_wire::PeerWireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (stream, _matched, theirs) =
        handshake_accept_any(stream, my_peer_id, &[(*my_info_hash, reserved)], timeout).await?;
    Ok((stream, theirs))
}

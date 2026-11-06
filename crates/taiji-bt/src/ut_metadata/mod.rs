//! ut_metadata metadata exchange (BEP9). The request timeout follows the
//! reference's **20s** (the "1s" in the design spec was a typo).
//!
//! # Scope
//!
//! Protocol half only, no network IO (requester/responder are wired by
//! PeerTask's BEP10 extension surface — `crate::peer::ExtConfig`; this
//! module provides fully testable state machines and codecs):
//!
//! - [`message`]: request(0)/data(1)/reject(2) message codec + responder
//! decision (holds the metadata -> data / reject / out-of-range error);
//! - [`tracker`]: request bookkeeping `RequestTracker` (in-flight cap 1,
//! 20s sweep);
//! - [`fetcher`]: requester driver (piece request scheduling, data
//! assembly, infohash verification) and resource limits
//! (metadata_size <= 8MiB). Also carries the V2 (btmh) expected identity:
//! SHA-256(info) == btmh (a BEP52-aligned local extension; aria2 has no
//! btmh magnet form).
//!
//! # Protocol-fact provenance (aria2)
//!
//! Piece size 16KiB (`BtConstants.h` METADATA_PIECE_SIZE); request timeout
//! sweep 20s (`UTMetadataRequestTracker.cc` TIMEOUT), timeout check
//! `elapsed >= TIMEOUT` (boundary inclusive, `UTMetadataRequestTracker.h`);
//! in-flight cap 1 (`MAX_OUTSTANDING_REQUEST`); extension name
//! `"ut_metadata"`; responder: no metadata -> reject, out-of-range index ->
//! disconnect-level error (`UTMetadataRequestExtensionMessage.cc`);
//! requester: untracked data ignored, on assembly SHA-1 over the info
//! bytes vs infohash — mismatch resets all pieces + explicit error
//! (`UTMetadataDataExtensionMessage.cc`); reject -> disconnect-level error
//! ("peer didn't offer metadata", `UTMetadataRejectExtensionMessage.cc`);
//! accepted metadata_size domain `0 < size <= 8MiB` (silently not started
//! when larger, `HandshakeExtensionMessage.cc`). The full table and the
//! message sequence walkthrough: `docs/design/peer-protocol.md`.
//!
//! The infohash check works on BEP9's metadata = the info dict's **raw
//! bytes**: assembled pieces are hashed directly (same as
//! `UTMetadataDataExtensionMessage.cc`), with no decode->re-encode
//! round-trip.
//!
//! # Intentional divergences from the reference (no interop impact)
//!
//! 1. **Piece-length precheck**: before a data write, enforce "non-final
//! pieces exactly 16KiB / final piece exactly the remainder"; aria2 does
//! not check lengths and only surfaces bad pieces via the eventual
//! infohash failure (`UTMetadataDataExtensionMessage.cc`). This only
//! changes when the error is exposed; the final verdict (infohash) is
//! identical.
//! 2. **Piece scheduling order**: missing pieces are requested in ascending
//! order (aria2 picks via `getMissingPiece` with an unspecified order,
//! `UTMetadataRequestFactory.cc`).

use thiserror::Error;

pub mod fetcher;
pub mod message;
pub mod tracker;

#[cfg(test)]
mod tests;

pub use fetcher::{
    DataOutcome, FetchError, MAX_METADATA_SIZE, MetadataAssembler, MetadataError, MetadataFetcher,
    verify_infohash,
};
pub use message::{ServeError, ServeOutcome, UtMetadata, serve_request};
pub use tracker::RequestTracker;

/// Piece size 16KiB (aria2 `BtConstants.h`).
pub const METADATA_PIECE_SIZE: usize = 16 * 1024;

/// Request timeout (aria2 `UTMetadataRequestTracker.cc`). **Correction**:
/// the design spec's "1s timeout sweep" was a typo; the reference is
/// `20_s`, and this implementation follows the reference.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Extension name (BEP9; `UTMetadataExtensionMessage.cc`).
pub const EXTENSION_NAME: &str = "ut_metadata";

/// Error surface shared across the module (the tracker side has no errors
/// of its own; everything is carried by [`MetadataError`] /
/// [`UtMetadataError`]).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UtMetadataError {
    #[error("ut_metadata payload too small: must be non-empty (DefaultExtensionMessageFactory.cc)")]
    TooSmall,
    #[error("ut_metadata bencode dict: {0}")]
    Bencode(#[from] crate::bencode::BencodeError),
    #[error("bad ut_metadata: dictionary not found (DefaultExtensionMessageFactory.cc)")]
    NotDict,
    #[error("bad ut_metadata: malformed bencode structure (reference bencode2::decode throw)")]
    Malformed,
    #[error("bad ut_metadata: msg_type not found (DefaultExtensionMessageFactory.cc)")]
    MissingMsgType,
    #[error("bad ut_metadata: piece not found or negative (DefaultExtensionMessageFactory.cc)")]
    BadPiece,
    #[error(
        "bad ut_metadata data: total_size not found or negative (DefaultExtensionMessageFactory.cc)"
    )]
    MissingTotalSize,
    #[error("bad ut_metadata data: data not found (DefaultExtensionMessageFactory.cc)")]
    DataMissing,
    #[error("bad ut_metadata: unknown msg_type={0} (DefaultExtensionMessageFactory.cc)")]
    UnknownMsgType(i64),
}

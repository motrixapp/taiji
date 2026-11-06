//! m3u8 (HLS) self-built parser, variant selection and normalized
//! digest — the media spec's parse/parse-gate sections are the spec of
//! record; the product spec's caps and playlist-consistency face are
//! superseded by them, the verdict table
//! included.
//!
//! Everything here is a pure function `bytes → structure | error` —
//! platform-independent, no I/O, no workspace-crate dependency, no
//! fetch/decrypt/staging (frozen seams: transport, keys,
//! option registration).
//!
//! Layout:
//! * [`sniff`] — entry classification, content > extension >
//! Content-Type → `not_media`;
//! * [`parse_manifest`] — line-oriented state machine; media vs
//! master classification on tag presence (RFC 8216 §4); the
//! pinned semantics (BYTERANGE per-URI omitted-offset accumulation,
//! METHOD=NONE explicit reset, positional MAP/KEY boundary) live in
//! [`parse`];
//! * [`policy`] — `--media-variant-policy` value parsing + selection;
//! * [`digest`] — query-stripped normalized manifest digest and the
//! variant identity pure function;
//! * [`model`] — the data structures (segment identity = absolute
//! media sequence; byte-range merge runs ≤8 for the transport
//! wiring).
//!
//! Fuzz surface: `m3u8_parse` (fuzz workspace, the parser
//! roster); vectors in `fuzz/seeds/m3u8_parse/` = RFC 8216 §8 modeled
//! examples + Apple-public-stream patterns + the self-built matrix +
//! the parse-gate's three vectors.

pub mod attrs;
pub mod digest;
pub mod model;
pub mod parse;
pub mod policy;
pub mod sniff;

pub use digest::{
    VariantIdentity, master_playlist_digest, media_playlist_digest, strip_query, variant_identity,
};
pub use model::{
    ByteRange, ByteRangeRun, InitSection, Key, KeyMethod, MAX_MERGE_RUN_SEGMENTS, MasterPlaylist,
    MediaPlaylist, MediaSegment, MediaTrack, Playlist, TrackType, Variant, byterange_runs,
    init_section_filename,
};
pub use parse::{MAX_MANIFEST_BYTES, MAX_MEDIA_SEGMENTS, parse_manifest};
pub use policy::{VariantPolicy, select_variant};
pub use sniff::{ManifestFlavor, sniff};

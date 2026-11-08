//! MPD (DASH) self-built parser + track-model expansion (the DASH
//! line; ISO/IEC 23009-1 static-VOD subset; the media spec's verdict
//! table and layer declaration of record; the product spec is the
//! reference line).
//!
//! Everything here is a pure function `bytes → structure | error`
//! (the m3u8 posture — platform-independent, no I/O, no
//! workspace-crate fetch/staging inside; URL joins are the only
//! outside touch, through the base's `Url`).
//!
//! Layout:
//! * [`model`] — the declared-structure data model (periods →
//!   adaptation sets → representations + the four addressing forms);
//! * [`parse`] — quick-xml streaming parse (namespace-tolerant
//!   local-name matching, DTD/entities disabled, unknown
//!   elements/attributes ignored whole-subtree);
//! * [`template`] — the `$…$` URL-template grammar (`$$`,
//!   `$RepresentationID$`, `$Bandwidth$`, `$Number$`, `$Time$`,
//!   width format tags; unknown identifiers are errors);
//! * [`expand`] — the consumption mapping: per-representation
//!   cross-period segment sequences onto the HLS track model (the
//!   rulings of record live in that module's docs), the sidx
//!   materialization half, the normalized digest and the variant
//!   identity (both = the parser-line pure functions applied to DASH
//!   facts).
//!
//! Judgment-table rows wired across parse+expand:
//! `type="dynamic"` → `live_unsupported`; `<ContentProtection>` any
//! scheme → `drm_unsupported`; nested sidx (`reference_type=1`) →
//! `sidx_unsupported`; caps (≤16MiB body, ≤100k segments) →
//! `manifest_too_large`; everything else malformed →
//! `manifest_parse`. Unknown elements/attributes are ignored
//! (forward compatibility).
//!
//! Fuzz surface: `mpd_parse` (fuzz workspace, the parser-roster DASH
//! row; vectors in `fuzz/seeds/mpd_parse/`); the
//! sidx arm rides the `bmff` target's extension
//! ([`crate::bmff::read_sidx`]).

pub mod expand;
pub mod model;
pub mod parse;
pub mod template;

pub use expand::{
    DashInit, DashPick, DashSelection, DashTrackPlan, Expanded, ExpandedTrack, SidxPlan,
    expand_representation, materialize_sidx, mpd_content_digest, mpd_digest, plan_dash_tracks,
    plan_dash_tracks_selected, representation_identity, resolve_rep_base,
    select_representation_idx,
};
pub use model::{
    AdaptationSet, InitRef, Mpd, MpdDescriptor, MpdType, Period, Representation, SegmentBase,
    SegmentList, SegmentTemplate, SegmentTimelineEntry, SegmentUrl, THUMBNAIL_SCHEME,
};
pub use parse::{MAX_LIST_SEGMENTS, parse_mpd};
pub use template::{
    FormatTag, MAX_EXPANDED_URL_BYTES, MAX_FORMAT_WIDTH, TemplateValues, expand_url_template,
};

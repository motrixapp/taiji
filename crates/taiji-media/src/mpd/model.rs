//! MPD (DASH) data model (ISO/IEC 23009-1 static-VOD subset,
//! the media spec's verdict table of record).
//!
//! The model keeps the **declared** MPD structure verbatim (periods →
//! adaptation sets → representations + the four addressing forms);
//! segment materialization is the derived product of
//! [`super::expand`]. Facts pinned here (module of record):
//!
//! * **type="dynamic" → `live_unsupported`** at parse (verdict-table
//! row; 0.4 owns the sliding window). `@type` absent =
//! static (ISO 23009-1 default).
//! * **ContentProtection — any scheme, any level (MPD/Period/
//! AdaptationSet/Representation) → `drm_unsupported`** at parse
//! (never supported; the 0.3 DASH key/decrypt consumption face is
//! exactly this refusal — ClearKey is a 0.4+ question).
//! * **single-level sidx only**: SegmentBase@indexRange addressing is
//! carried as a descriptor; a sidx whose references set
//! `reference_type=1` (a referenced sidx — the hierarchical index)
//! materializes as `sidx_unsupported` at expansion.
//! * byte-range values are `(begin, end)` **inclusive** pairs, the
//! MPD's own `@range`/"indexRange" spelling, converted to the
//! `(offset, length)` form only at expansion.
//! * URIs (BaseURL/media/initialization/SegmentURL@media) are kept
//! verbatim; resolution is [`super::expand`]'s job.

/// Whole parsed MPD (static only — dynamic is refused at parse).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Mpd {
    /// `@type` (`static` — `dynamic` never reaches the model).
    pub mpd_type: MpdType,
    /// `@mediaPresentationDuration` in seconds (XS-Duration parsed).
    pub media_presentation_duration: Option<f64>,
    /// The first `<ProgramInformation><Title>` text (manifest-level
    /// metadata): the only ProgramInformation child the 0.3
    /// face consumes (`Source`/`Copyright` stay ignored — the known-
    /// element narrowing never turns an ignored element into an
    /// error, zero-regression verdict semantics).
    pub title: Option<String>,
    /// MPD-level `<SupplementalProperty>`/`<EssentialProperty>`
    /// descriptors in declaration order (the manifest-obtainable
    /// URI face; unknown schemes ride inertly — consumption is the
    /// [`Mpd::thumbnail_uri`] ruling).
    pub descriptors: Vec<MpdDescriptor>,
    /// MPD-level `<BaseURL>` values in declaration order.
    pub base_urls: Vec<String>,
    /// `<Period>` elements in declaration order.
    pub periods: Vec<Period>,
}

/// One MPD-level descriptor element (`SupplementalProperty` /
/// `EssentialProperty`): the `@schemeIdUri` + `@value` pair, kept
/// verbatim (case as written — scheme comparison for consumption is
/// ASCII-case-insensitive, the DASH-IF convention).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MpdDescriptor {
    /// `@schemeIdUri` as written.
    pub scheme_id_uri: String,
    /// `@value` as written.
    pub value: String,
}

/// The 0.3 thumbnail scheme anchor (C26, card's in-card ruling):
/// `urn:mpeg:dash:thumbnail:2016` — the DASH-IF thumbnail/trick-play
/// scheme ID. The 0.3 consumed form is its **URI-value shape**: a
/// descriptor with this scheme whose `@value` is an image URI. The
/// tiled trick-play-representation shape (the property marking an
/// image AdaptationSet) is the 0.5 bridge's rich-cover face, not
/// consumed here; HLS has no standard thumbnail source (None, never
/// synthesized).
pub const THUMBNAIL_SCHEME: &str = "urn:mpeg:dash:thumbnail:2016";

impl Mpd {
    /// The manifest-obtainable thumbnail URI (C26): the first
    /// [`THUMBNAIL_SCHEME`]-carrying descriptor whose `@value` looks
    /// like an http(s) URI (scheme-insensitive comparison); None when
    /// the manifest carries no such descriptor.
    pub fn thumbnail_uri(&self) -> Option<&str> {
        self.descriptors
            .iter()
            .filter(|d| d.scheme_id_uri.eq_ignore_ascii_case(THUMBNAIL_SCHEME))
            .map(|d| d.value.trim())
            .find(|v| v.starts_with("http://") || v.starts_with("https://"))
    }
}

/// MPD `@type` vocabulary (dynamic is a parse-time refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MpdType {
    /// `static` (VOD — the supported subset).
    #[default]
    Static,
}

/// One `<Period>`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Period {
    /// `@id` (informational).
    pub id: Option<String>,
    /// `@start` in seconds.
    pub start: Option<f64>,
    /// `@duration` in seconds.
    pub duration: Option<f64>,
    /// Period-level `<BaseURL>` values in declaration order.
    pub base_urls: Vec<String>,
    /// Period-level `<SegmentTemplate>` (the inheritance chain's
    /// first tier — attributes inherit into set/representation
    /// templates, child-wins).
    pub segment_template: Option<SegmentTemplate>,
    /// Period-level `<SegmentList>` (wholesale replacement chain).
    pub segment_list: Option<SegmentList>,
    /// `<AdaptationSet>` elements in declaration order.
    pub adaptation_sets: Vec<AdaptationSet>,
}

/// One `<AdaptationSet>`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdaptationSet {
    /// `@id`.
    pub id: Option<String>,
    /// `@lang` (RFC 5646 as written).
    pub lang: Option<String>,
    /// `@contentType` (video|audio|text|…).
    pub content_type: Option<String>,
    /// `@mimeType`.
    pub mime_type: Option<String>,
    /// `@codecs`.
    pub codecs: Option<String>,
    /// `@maxWidth`/`@maxHeight`.
    pub max_width: Option<u32>,
    pub max_height: Option<u32>,
    /// Set-level `<BaseURL>` values.
    pub base_urls: Vec<String>,
    /// Set-level `<SegmentTemplate>` (attribute-inherited by
    /// representations that declare their own, child-wins — the
    /// documented ruling in [`super::parse`]).
    pub segment_template: Option<SegmentTemplate>,
    /// Set-level `<SegmentList>`.
    pub segment_list: Option<SegmentList>,
    /// `<Representation>` children in declaration order.
    pub representations: Vec<Representation>,
}

/// One `<Representation>`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Representation {
    /// `@id` (required by the spec; empty when absent).
    pub id: String,
    /// `@bandwidth` (bits per second; 0 when absent).
    pub bandwidth: u64,
    /// `@width`/`@height`.
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// `@frameRate` verbatim (e.g. `30`, `30000/1001`).
    pub frame_rate: Option<String>,
    /// `@codecs`.
    pub codecs: Option<String>,
    /// `@mimeType`.
    pub mime_type: Option<String>,
    /// `@audioSamplingRate`.
    pub audio_sampling_rate: Option<u32>,
    /// Representation-level `<BaseURL>` values.
    pub base_urls: Vec<String>,
    /// Representation-level `<SegmentTemplate>` (merged over the
    /// set-level one, child-wins per attribute).
    pub segment_template: Option<SegmentTemplate>,
    /// Representation-level `<SegmentList>`.
    pub segment_list: Option<SegmentList>,
    /// Representation-level `<SegmentBase>` (single-resource sidx
    /// addressing).
    pub segment_base: Option<SegmentBase>,
}

/// `<SegmentTemplate>` (template addressing: `$Number$` over
/// `@duration`, or `$Time$`/`$Number$` over `<SegmentTimeline>`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SegmentTemplate {
    /// `@timescale` (ticks per second; default 1).
    pub timescale: Option<u64>,
    /// `@duration` (ticks).
    pub duration: Option<u64>,
    /// `@startNumber` (default 1).
    pub start_number: Option<u64>,
    /// `@presentationTimeOffset` (ticks).
    pub presentation_time_offset: Option<u64>,
    /// `@initialization` (URL template).
    pub initialization: Option<String>,
    /// `@media` (URL template — required for template addressing).
    pub media: Option<String>,
    /// `<SegmentTimeline>` `<S>` entries in declaration order (empty =
    /// the `@duration` form).
    pub timeline: Vec<SegmentTimelineEntry>,
}

/// One `<S>` row of a `<SegmentTimeline>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentTimelineEntry {
    /// `@t` (ticks; `None` = continue from the previous entry's end).
    pub t: Option<u64>,
    /// `@d` (ticks; required).
    pub d: u64,
    /// `@r` (repeat count; default 0; −1 = "until the period end" —
    /// resolved against the period duration at expansion).
    pub r: i64,
}

/// `<SegmentList>` (explicit-addressing form).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SegmentList {
    /// `@timescale`.
    pub timescale: Option<u64>,
    /// `@duration` (ticks).
    pub duration: Option<u64>,
    /// `<Initialization>` child (sourceURL + optional range).
    pub initialization: Option<InitRef>,
    /// `<SegmentURL>` children in declaration order.
    pub segment_urls: Vec<SegmentUrl>,
}

/// `<Initialization>` reference (shared by SegmentList and
/// SegmentBase forms).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitRef {
    /// `@sourceURL` (`None` = the representation base itself).
    pub source_url: Option<String>,
    /// `@range` (`"begin-end"`, inclusive).
    pub range: Option<(u64, u64)>,
}

/// One `<SegmentURL>`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SegmentUrl {
    /// `@media` (relative or absolute URI).
    pub media: Option<String>,
    /// `@mediaRange` (`"begin-end"`, inclusive).
    pub media_range: Option<(u64, u64)>,
}

/// `<SegmentBase>` (single-resource sidx addressing).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SegmentBase {
    /// `@timescale`.
    pub timescale: Option<u64>,
    /// `@indexRange` (`"begin-end"`, inclusive — where the sidx
    /// lives inside the representation resource).
    pub index_range: Option<(u64, u64)>,
    /// `<Initialization>@range` child (init bytes inside the same
    /// resource).
    pub initialization_range: Option<(u64, u64)>,
}

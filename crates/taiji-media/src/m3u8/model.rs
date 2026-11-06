//! m3u8 data model (RFC 8216 + the media spec's verdict table).
//!
//! Design facts pinned here (module of record for the structure the
//! transport/decrypt consumers use):
//!
//! * **Segment identity = absolute media sequence** (per the product
//! spec): every
//! `MediaSegment::sequence` is `media_sequence + appearance index`;
//! IV derivation and per-segment bitmaps key on it, never on
//! the array index.
//! * **BYTERANGE offsets are stored resolved** — an omitted offset is
//! already accumulated per-URI by the parser (RFC 8216 §4.3.2.2
//! semantics, the adopted per-URI appearance-order form),
//! with `offset_omitted` keeping the provenance for golden asserts.
//! All accumulation arithmetic is checked; overflow is a parse error.
//! * **Key state is per-segment and materialized** (`MediaSegment::key`
//! = the effective key at that segment). METHOD=NONE is an explicit
//! reset: segments after it are plaintext (`key == None`) even when a
//! key was active before — the m3u8-rs degradation
//! (per the media spec's errata) cannot recur because no ambient
//! state survives
//! into the model.
//! * **Init-section encryption is positional** (the media spec's
//! boundary): an `InitSection::key` comes either from the `KEY=`
//! attribute on the EXT-X-MAP itself, or from the ambient EXT-X-KEY
//! active where the MAP is declared (RFC 8216 §4.3.2.5: a KEY
//! covers "every Media Initialization Section declared by an
//! EXT-X-MAP tag that appears between it and the next EXT-X-KEY
//! tag"); a KEY declared after the MAP never covers it. The
//! MAP-level `KEY=` attribute is a **taiji custom extension**
//! (an erratum of record: not a clause of RFC 8216 or any rfc8216bis
//! revision). The init IV resolves at decrypt time: the
//! key's explicit IV, else the first following segment's absolute
//! media sequence — a **practical taiji relaxation, not a spec
//! clause** (RFC 8216 §4.3.2.5's spec-correct behavior on a
//! missing init IV is to reject; taiji attempts the sequence
//! derivation and reports an honest decrypt error when it cannot
//! resolve one).
//! * URIs are kept verbatim (query strings included). Base-URL
//! resolution is a transport concern; the digest/identity
//! faces in [`super::digest`] do the query-stripping.

/// A whole parsed playlist — media or master (RFC 8216 §4: a playlist
/// containing EXT-X-STREAM-INF (or EXT-X-MEDIA/I-FRAME-STREAM-INF) is a
/// Master Playlist; classification happens on tag presence, mixed
/// inputs resolve as master with the segment scratch discarded).
#[derive(Debug, Clone, PartialEq)]
pub enum Playlist {
    /// Media playlist (VOD only at this card: no ENDLIST is a
    /// `live_unsupported` refusal before the struct is ever returned).
    Media(MediaPlaylist),
    /// Master playlist (variant + rendition tables).
    Master(MasterPlaylist),
}

impl Playlist {
    /// `true` when the input classified as a master playlist.
    pub fn is_master(&self) -> bool {
        matches!(self, Self::Master(_))
    }
}

/// Media playlist structure (RFC 8216 §4.3.3 level tags + segments).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MediaPlaylist {
    /// EXT-X-VERSION (protocol compatibility version).
    pub version: Option<u32>,
    /// EXT-X-TARGETDURATION, seconds (tolerated as float: draft-era
    /// playlists carry fractional values).
    pub target_duration: Option<f64>,
    /// EXT-X-MEDIA-SEQUENCE of the **first** segment (identity anchor;
    /// 0 when the tag is absent).
    pub media_sequence: u64,
    /// EXT-X-DISCONTINUITY-SEQUENCE.
    pub discontinuity_sequence: u64,
    /// EXT-X-PLAYLIST-TYPE (VOD/EVENT carried verbatim otherwise).
    pub playlist_type: Option<String>,
    /// EXT-X-INDEPENDENT-SEGMENTS present.
    pub independent_segments: bool,
    /// EXT-X-ENDLIST present. Always `true` for playlists this parser
    /// returns (its absence is a `live_unsupported` error).
    pub endlist: bool,
    /// EXT-X-MAP declarations in appearance order; segments reference
    /// them by index (deduplication is a staging concern).
    pub init_sections: Vec<InitSection>,
    /// Media segments in playlist order; `segments[i].sequence ==
    /// media_sequence + i` (checked arithmetic at parse time).
    pub segments: Vec<MediaSegment>,
    /// Names of unrecognized `#EXT-*` tags (forward compatibility,
    /// RFC 8216 §4.3.4 / the "unknown manifest tags ignored" rule).
    pub unknown_tags: Vec<String>,
}

/// One media segment: an EXTINF + URI pair with the state that applied
/// at its position.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaSegment {
    /// Absolute media sequence number (identity/IV/bitmap key).
    pub sequence: u64,
    /// Segment URI, verbatim from the playlist (query included).
    pub uri: String,
    /// EXTINF duration in seconds (finite, non-negative).
    pub duration: f64,
    /// EXTINF title (informational, quotes stripped when present).
    pub title: Option<String>,
    /// EXT-X-BYTERANGE resolved against the per-URI accumulation
    /// chain; `None` = whole resource.
    pub byte_range: Option<ByteRange>,
    /// An EXT-X-DISCONTINUITY tag directly preceded this segment
    /// (preserved bit, handed to the demuxer at merge time).
    pub discontinuity: bool,
    /// Effective EXT-X-KEY at this segment; `None` = plaintext
    /// (including the explicit METHOD=NONE reset case).
    pub key: Option<Key>,
    /// Index into [`MediaPlaylist::init_sections`] of the EXT-X-MAP in
    /// force at this segment.
    pub map: Option<usize>,
}

/// A resolved byte range (`length` bytes at `offset` inside the
/// resource named by the segment URI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Sub-range length in bytes.
    pub length: u64,
    /// Sub-range start offset in bytes (already accumulated when the
    /// manifest omitted it).
    pub offset: u64,
    /// `true` when the manifest omitted the offset and the parser
    /// accumulated it per-URI (provenance for the v0.3.1 vector).
    pub offset_omitted: bool,
}

/// EXT-X-MAP declaration (media initialization section), numbered by
/// appearance order.
#[derive(Debug, Clone, PartialEq)]
pub struct InitSection {
    /// Appearance-order index (0-based) — the `<n>` of the
    /// `init-<track>-<n>.mp4` staging name.
    pub index: usize,
    /// Init-section URI, verbatim.
    pub uri: String,
    /// `BYTERANGE` attribute, resolved (the whole resource when the
    /// attribute is absent).
    pub byte_range: Option<ByteRange>,
    /// Key covering **this init section only** — the MAP's own `KEY=`
    /// attribute is a taiji custom extension, an erratum of record: not an
    /// RFC 8216 / rfc8216bis clause), else the ambient EXT-X-KEY
    /// active at the MAP's position. See the module docs for the
    /// positional boundary; `None` = plaintext.
    pub key: Option<Key>,
}

impl InitSection {
    /// Staging file name face (per the product spec): appearance order + track
    /// label, e.g. `init-video-0.mp4`. Pure naming function — the
    /// staging module owns the directory layout that consumes it.
    pub fn filename(&self, track: &str) -> String {
        init_section_filename(track, self.index)
    }
}

/// Staging name for init section `<index>` of `<track>`
/// (`init-<track>-<n>.mp4`, 0-based appearance order).
pub fn init_section_filename(track: &str, index: usize) -> String {
    format!("init-{track}-{index}.mp4")
}

/// An EXT-X-KEY declaration (structured key reference — fetching and
/// decryption live in their own modules; this parser only references).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    /// Encryption method. SAMPLE-AES is refused at parse time
    /// (`sample_aes_unsupported`); METHOD=NONE parses as
    /// [`KeyMethod::None`] when it appears on an EXT-X-MAP `KEY=`
    /// attribute (explicit unencrypted init section).
    pub method: KeyMethod,
    /// Key URI (verbatim). Required for AES-128 on EXT-X-KEY; on a
    /// MAP `KEY=` attribute (the taiji custom extension) a bare
    /// `METHOD=NONE` carries none.
    pub uri: Option<String>,
    /// Explicit IV (`IV=0x…`, 16 bytes). When this key covers an init
    /// section the chain is: this IV, else the first following
    /// segment's absolute media sequence (decrypt-time resolution,
    /// `keys::build_track_crypto` — the sequence fallback is a
    /// practical taiji relaxation of RFC 8216 §4.3.2.5's explicit-IV
    /// requirement, not a spec clause); for media segments the
    /// default is the segment's own absolute sequence.
    pub iv: Option<[u8; 16]>,
    /// KEYFORMAT, verbatim (defaults to `identity` per RFC — the
    /// default is applied by the consumer, the model keeps the
    /// manifest's word).
    pub keyformat: Option<String>,
    /// KEYFORMATVERSIONS, verbatim.
    pub keyformat_versions: Option<String>,
}

/// EXT-X-KEY METHOD vocabulary this card accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMethod {
    /// METHOD=NONE — explicit reset/plaintext.
    None,
    /// METHOD=AES-128.
    Aes128,
}

/// Master playlist structure (RFC 8216 §4.3.4).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MasterPlaylist {
    /// EXT-X-VERSION.
    pub version: Option<u32>,
    /// EXT-X-INDEPENDENT-SEGMENTS present.
    pub independent_segments: bool,
    /// EXT-X-STREAM-INF variants (selectable; ordered as declared).
    pub variants: Vec<Variant>,
    /// EXT-X-I-FRAME-STREAM-INF renditions (trick-play only,
    /// **excluded from selection** — RFC 8216 §4.3.4.3).
    pub iframe_variants: Vec<Variant>,
    /// EXT-X-MEDIA rendition rows (audio/subtitle/… track table).
    pub tracks: Vec<MediaTrack>,
    /// Unrecognized `#EXT-*` tag names (ignored, recorded).
    pub unknown_tags: Vec<String>,
}

/// One EXT-X-STREAM-INF / EXT-X-I-FRAME-STREAM-INF variant row.
#[derive(Debug, Clone, PartialEq)]
pub struct Variant {
    /// Variant URI (the media playlist it names), verbatim.
    pub uri: String,
    /// BANDWIDTH (peak, bits per second; RFC REQUIRED).
    pub bandwidth: u64,
    /// AVERAGE-BANDWIDTH.
    pub average_bandwidth: Option<u64>,
    /// RESOLUTION as (width, height).
    pub resolution: Option<(u32, u32)>,
    /// CODECS, verbatim quoted-string content.
    pub codecs: Option<String>,
    /// FRAME-RATE.
    pub frame_rate: Option<f64>,
    /// VIDEO-RANGE (SDR/PQ/HLG), verbatim.
    pub video_range: Option<String>,
    /// AUDIO rendition-group reference.
    pub audio_group: Option<String>,
    /// VIDEO rendition-group reference.
    pub video_group: Option<String>,
    /// SUBTITLES rendition-group reference.
    pub subtitles_group: Option<String>,
    /// CLOSED-CAPTIONS group reference or the `NONE` enum, verbatim.
    pub closed_captions: Option<String>,
}

/// EXT-X-MEDIA TYPE vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackType {
    /// TYPE=AUDIO.
    Audio,
    /// TYPE=VIDEO.
    Video,
    /// TYPE=SUBTITLES.
    Subtitles,
    /// TYPE=CLOSED-CAPTIONS.
    ClosedCaptions,
}

/// One EXT-X-MEDIA rendition row (the attribute subset the card names:
/// TYPE/GROUP-ID/LANGUAGE/NAME/DEFAULT/URI).
#[derive(Debug, Clone, PartialEq)]
pub struct MediaTrack {
    /// TYPE (required).
    pub track_type: TrackType,
    /// GROUP-ID.
    pub group_id: Option<String>,
    /// NAME.
    pub name: Option<String>,
    /// LANGUAGE (RFC 5646 primary tag as written).
    pub language: Option<String>,
    /// DEFAULT=YES (defaults to NO per RFC).
    pub default_track: bool,
    /// Rendition playlist URI (absent = rendition embedded in the
    /// variant stream; CLOSED-CAPTIONS rows have none).
    pub uri: Option<String>,
}

/// One transport merge run computed over a media playlist (the ≤8
/// adjacent-sub-segment merge data structure; the transport wiring
/// consumes it, this module delivers the pure grouping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteRangeRun {
    /// Index of the first [`MediaSegment`] in the run.
    pub first_segment: usize,
    /// Number of segments in the run (1..=8).
    pub segments: usize,
    /// Shared resource URI of the run.
    pub uri: String,
    /// Byte offset the single Range GET starts at.
    pub offset: u64,
    /// Total bytes covered (`sum of segment lengths`; one checked sum,
    /// u64-overflow-free by construction).
    pub length: u64,
}

/// Upper bound on sub-segments merged into one transport request
/// (per the product spec: "adjacent sub-segments merged into one Range GET
/// (≤8 segments)").
pub const MAX_MERGE_RUN_SEGMENTS: usize = 8;

/// Group adjacent byterange sub-segments that may be fetched with one
/// Range request: same URI, byte-contiguous, and with no boundary event
/// in between (a discontinuity, an EXT-X-MAP or EXT-X-KEY change breaks
/// the run — the merge is a transport optimization, never a semantic
/// one). Runs never exceed [`MAX_MERGE_RUN_SEGMENTS`] segments.
pub fn byterange_runs(playlist: &MediaPlaylist) -> Vec<ByteRangeRun> {
    let mut runs = Vec::new();
    let mut open: Option<ByteRangeRun> = None;
    for (idx, seg) in playlist.segments.iter().enumerate() {
        let Some(br) = seg.byte_range else {
            // Whole-resource segment: flush the open run (never joins).
            if let Some(run) = open.take() {
                runs.push(run);
            }
            continue;
        };
        let extends = match open.as_ref() {
            Some(run) => {
                run.segments < MAX_MERGE_RUN_SEGMENTS
                    && run.uri == seg.uri
                    && run.offset.checked_add(run.length) == Some(br.offset)
                    && !seg.discontinuity
                    && seg.key == playlist.segments[idx.saturating_sub(1)].key
                    && seg.map == playlist.segments[idx.saturating_sub(1)].map
            }
            None => false,
        };
        if extends {
            if let Some(run) = open.as_mut() {
                run.segments += 1;
                // Contiguity (checked at parse time) keeps this sum
                // inside u64; saturate rather than panic on a logic
                // bug.
                run.length = run.length.saturating_add(br.length);
            }
        } else {
            if let Some(run) = open.take() {
                runs.push(run);
            }
            open = Some(ByteRangeRun {
                first_segment: idx,
                segments: 1,
                uri: seg.uri.clone(),
                offset: br.offset,
                length: br.length,
            });
        }
    }
    if let Some(run) = open.take() {
        runs.push(run);
    }
    runs
}

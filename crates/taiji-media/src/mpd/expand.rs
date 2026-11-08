//! MPD → track-model expansion (the "full consumption wiring" — the
//! pure half; the driver half lives in
//! [`crate::mediadl`]).
//!
//! # Rulings of record (settled and canonicalized)
//!
//! * **Segment identity = the cross-period monotonic ordinal** (0,
//!   1, 2, … across the whole representation, periods in declaration
//!   order). DASH carries no media-sequence anchor; the synthetic
//!   playlist's `media_sequence = 0` and every segment's `sequence` =
//!   its ordinal — the `media_segment.media_sequence` column stores
//!   the ordinal (the schema comment's "DASH NULL" is superseded by
//!   this of-record spelling; the column is reused, never widened).
//! * **One representation = one track** (one archive, one ledger
//!   row per period-spanning representation). Multi-period source
//!   consumption = the single track archive appending across periods
//!   in order; a period boundary carries the **discontinuity bit on
//!   the first segment of every period after the first** (each period
//!   owns an independent media timeline — the native fold rebuilds
//!   sample timing from per-fragment durations and the ffmpeg
//!   fallback resets its demuxer at the DISCONTINUITY), and a period
//!   whose addressing declares a distinct Initialization opens a new
//!   init section (multi-MAP bookkeeping rides the existing
//!   faces unchanged).
//! * **Cross-period representation matching**: the selection names
//!   `(set_idx, rep_idx)` in the first period; later periods match
//!   the set by `@id` when the first period's set carried one, else
//!   by position, and the representation by `@id`, else by position.
//!   A period with no addressable match is a `manifest_parse` error
//!   (an honest refusal, never a silent skip).
//! * **BaseURL resolution order**: manifest URL ← MPD ← Period ←
//!   AdaptationSet ← Representation (each level's **first** BaseURL;
//!   the multiple-BaseURL failover list is a mirror-source question
//!   this line does not open — one base, documented). Segment/init
//!   URIs resolve against that base and are stored **absolute** in
//!   the synthetic playlist.
//! * **Addressing precedence** per representation (ISO 23009-1
//!   §5.3.9.2): SegmentTemplate > SegmentList > SegmentBase > plain
//!   BaseURL (one whole-resource segment; the sidx form below when
//!   `@indexRange` is present).
//! * **Layer judgment = the existing pure function over the synthetic
//!   playlist** ([`crate::trackdl::classify_track`]): a SegmentList
//!   with `@mediaRange` on every row (or the sidx-derived
//!   single-resource form) yields known byte ranges → the **(a)
//!   layer** (extent-grid reuse; same-URI touching ranges fold into
//!   spans); SegmentTemplate/SegmentTimeline/plain forms carry no
//!   byte information in the MPD attributes → the **(b) layer**
//!   (ordered segment fetch, `seg_bitmap` checkpoints). Semantics note
//!   for the coordination face: the media spec writes "DASH
//!   SegmentTemplate sizes are derivable" — the MPD attribute reality is that a
//!   SegmentTemplate exposes **duration**, never byte size; the
//!   (b)-layer landing here is the honest reading (a spec-errata
//!   suggestion rides the report, not a silent
//!   deviation).
//! * **Expansion output budget** (the review-block guard): every
//!   expanded URI ≤ [`MAX_SEGMENT_URI_BYTES`] (64KiB) and the whole
//!   expansion's URI bytes ≤ [`MAX_EXPANSION_OUTPUT_BYTES`] (128MiB,
//!   enforced at the `push_segment`/`ensure_init` chokepoints with an
//!   allocation-free product pre-check in the `@duration` arm) — a
//!   ≤16MiB input never drives unbounded allocation; over-budget =
//!   `manifest_too_large` (width-tag padding abuse additionally
//!   refuses at parse in [`crate::mpd::template`]). The 100k ×
//!   ~1KiB-URL legit face stays inside; the 4MiB-template × 100k
//!   class (400GiB) refuses at the first URI.
//! * **Variant policy scope**: `--media-variant-policy`
//!   (highest|resolution=<H>|bandwidth=<B>) caps the **primary
//!   ladder** — the video set when one exists, else the audio-only
//!   set (the HLS `select_variant` mirror, the policy's semantics with
//!   equivalent effect; see [`plan_dash_tracks`]); a side audio set
//!   rides Highest (audio renditions join by the language chain,
//!   never by the video policy — the HLS posture).
//! * **`$Time$` under the `@duration` form** = `(number −
//! startNumber) × @duration` (media time in timescale ticks — the
//!   value packagers emit); under SegmentTimeline = the running `S`
//!   media time. `$Number$` under timeline addressing = the running
//!   segment number from `@startNumber`.
//! * **Segment count** per template form = `ceil(period_duration ÷
//! segment_duration)`; a period without `@duration` falls back to
//!   the `MPD@mediaPresentationDuration` remainder after the
//!   explicitly-durated predecessors. Not derivable =
//!   `manifest_parse`.
//! * **Caps**: the cross-period task-level segment count ≤ 100 000
//!   (`manifest_too_large`); every counter is checked arithmetic.
//! * **sidx addressing is deferred-I/O**: the pure parse yields a
//!   [`SidxPlan`]; the driver fetches `indexRange`, and
//!   [`materialize_sidx`] (pure, fuzzed) derives the segment byte
//!   ranges — any `reference_type=1` row (a nested sidx) is
//!   `sidx_unsupported` (verdict-table row). The sidx form is
//!   single-period by construction (one resource per representation;
//!   a multi-period sidx MPD is an honest parse refusal).

use crate::bmff;
use crate::error::MediaError;
use crate::m3u8::digest::sha256;
use crate::m3u8::model::{ByteRange, InitSection, MediaPlaylist, MediaSegment};
use crate::m3u8::{
    MAX_MEDIA_SEGMENTS, VariantIdentity, VariantPolicy, strip_query, variant_identity,
};
use crate::mpd::model::{AdaptationSet, Mpd, Period, Representation, SegmentList, SegmentTemplate};
use crate::mpd::template::{TemplateValues, expand_url_template};
use crate::trackset::{PlannedTrack, TrackKind, TrackRole, TrackSetConfig};

/// One planned DASH track's source coordinates (the parallel of
/// [`PlannedTrack`]: where in the MPD the representation lives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashPick {
    /// Period-0 adaptation-set index.
    pub set: usize,
    /// Period-0 representation index.
    pub rep: usize,
}

/// The DASH track plan (the `plan_track_set` parallel).
#[derive(Debug, Clone, PartialEq)]
pub struct DashTrackPlan {
    /// Planned tracks (the shared vocabulary: labels/kinds/roles).
    pub tracks: Vec<PlannedTrack>,
    /// `(set, rep)` pick per track (parallel index).
    pub picks: Vec<DashPick>,
}

/// A DASH init section (absolute URI + optional byte range inside
/// the named resource).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashInit {
    pub uri: String,
    pub range: Option<ByteRange>,
}

impl DashInit {
    fn to_init_section(&self, index: usize) -> InitSection {
        InitSection {
            index,
            uri: self.uri.clone(),
            byte_range: self.range,
            key: None,
        }
    }
}

/// The expansion product of one representation: the synthetic
/// playlist, ready for the track drivers.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpandedTrack {
    /// The synthetic playlist (absolute URIs, cross-period ordinals).
    pub playlist: MediaPlaylist,
    /// The representation's resolved base URL (display identity; the
    /// driver never fetches it as a playlist).
    pub rep_base: String,
}

/// The deferred sidx form (the driver fetches, then
/// [`materialize_sidx`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidxPlan {
    /// The representation's single resource URL (absolute).
    pub base: String,
    /// `@indexRange` (inclusive begin/end).
    pub index_range: (u64, u64),
    /// The init section (Initialization@range inside the same
    /// resource), when declared.
    pub init: Option<DashInit>,
    /// The form's `@timescale` (default 1).
    pub timescale: u64,
}

/// One expansion's outcome (the sidx form defers to a fetch).
#[derive(Debug, Clone, PartialEq)]
pub enum Expanded {
    /// Fully materialized.
    Ready(ExpandedTrack),
    /// Awaiting the indexRange fetch.
    DeferredSidx(SidxPlan),
}

// ---------------------------------------------------------------------------
// track-set planning
// ---------------------------------------------------------------------------

/// How one adaptation set classifies for 0.3 planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetKind {
    Video,
    Audio,
    Text,
}

/// One segment/init URI's byte bound (defense in depth behind the
/// template-expansion guard of [`super::template`]: SegmentList
/// `@media` values and resolved base URLs ride THIS check — the
/// 16MiB input cap must never become the URI budget). Over =
/// `manifest_too_large`.
pub const MAX_SEGMENT_URI_BYTES: usize = 64 * 1024;

/// The whole expansion's URI budget: the sum of every expanded
/// segment-URI byte plus each distinct init-URI byte. The
/// amplification bound for the template × segment-count product
/// (the review-block PoC: a ≤16MiB @media template × the 100k
/// segment cap = the 400GiB class). 128MiB keeps a legit 100k
/// × ~1KiB-URL face inside while capping the hostile class well
/// under the parse gate's 200MiB allocation envelope.
pub const MAX_EXPANSION_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;

fn set_kind(set: &AdaptationSet) -> SetKind {
    let ct = set.content_type.as_deref().map(str::to_ascii_lowercase);
    let mt = set.mime_type.as_deref().map(str::to_ascii_lowercase);
    let media = ct.clone().or(mt).unwrap_or_default();
    if media.starts_with("video") {
        return SetKind::Video;
    }
    if media.starts_with("audio") {
        return SetKind::Audio;
    }
    if media.starts_with("text") || (media == "application/mp4" && ct.is_some()) {
        return SetKind::Text;
    }
    // Fallback signal: a representation carrying @width/@height marks
    // a video set; anything else is unplanned in 0.3 (text).
    if set
        .representations
        .iter()
        .any(|r| r.width.is_some() || r.height.is_some())
    {
        SetKind::Video
    } else {
        SetKind::Text
    }
}

/// Select the best representation index of a set under the
/// policy semantics applied to DASH representations (the
/// "`--media-variant-policy` takes equivalent effect over DASH
/// representations" ruling): Highest = max
/// @bandwidth, `resolution=<H>` = height ≤ H cap, `bandwidth=<B>` =
/// bandwidth ≤ B cap; ties by resolution height then declaration
/// order — the same ordering the m3u8 face documents).
pub fn select_representation_idx(
    set: &AdaptationSet,
    policy: &VariantPolicy,
) -> Result<usize, MediaError> {
    let eligible = |rep: &Representation| -> bool {
        match *policy {
            VariantPolicy::Highest => true,
            VariantPolicy::Resolution { height } => rep.height.is_some_and(|h| h <= height),
            VariantPolicy::Bandwidth {
                bits_per_second: cap,
            } => rep.bandwidth <= cap,
        }
    };
    let mut best: Option<usize> = None;
    for (idx, rep) in set.representations.iter().enumerate() {
        if !eligible(rep) {
            continue;
        }
        // min_by-keep-first semantics: replace only on a strictly
        // greater rank (declaration-order tiebreak).
        if best.is_none_or(|b| rep_rank(rep) > rep_rank(&set.representations[b])) {
            best = Some(idx);
        }
    }
    best.ok_or_else(|| {
        MediaError::VariantPolicy(match *policy {
            VariantPolicy::Highest => "adaptation set declares no representation".to_owned(),
            VariantPolicy::Resolution { .. } => {
                "no representation satisfies the resolution cap".to_owned()
            }
            VariantPolicy::Bandwidth { .. } => {
                "no representation satisfies the bandwidth cap".to_owned()
            }
        })
    })
}

fn rep_rank(r: &Representation) -> (u64, u32) {
    (r.bandwidth, r.height.unwrap_or(0))
}

/// Plan the DASH track set (the `plan_track_set` parallel over MPD
/// structure): the selected video representation (Required, label
/// `v`) plus the independent audio set's best representation
/// (Required, label `a`; `v` when audio-only) when the language
/// chain picks one; text sets are ignored (0.3 — "subtitles
/// ignored in 0.3").
///
/// `policy` = the `--media-variant-policy` semantics applied to the
/// DASH representations (the plan's scope item 2 — the policy's
/// equivalent effect): the policy caps the **primary ladder** — the
/// video adaptation set when one exists, else the audio-only set
/// (the variant face, the HLS `select_variant` mirror: a
/// resolution cap on an audio-only MPD finds no measurable-height
/// representation and refuses `variant_policy`, exactly as an
/// audio-only HLS master without RESOLUTION does). A **side audio
/// set** (video present) rides `Highest` — the HLS posture where
/// audio renditions join by language chain, never by the video
/// policy.
///
/// Language chain (the HLS policy's DASH spelling): requested
/// RFC 5646 prefix match on `AdaptationSet@lang` → `en` → the first
/// audio set in declaration order (DASH has no DEFAULT=YES tier;
/// documented ruling).
pub fn plan_dash_tracks(
    mpd: &Mpd,
    manifest_url: &str,
    cfg: &TrackSetConfig,
    policy: &VariantPolicy,
) -> Result<DashTrackPlan, MediaError> {
    let Some(first) = mpd.periods.first() else {
        return Err(MediaError::ManifestParse(
            "MPD declares no period".to_string(),
        ));
    };
    let video_set = first
        .adaptation_sets
        .iter()
        .position(|s| set_kind(s) == SetKind::Video);
    let audio_set = pick_audio_set(first, cfg.audio_lang.as_deref());
    if video_set.is_none() && audio_set.is_none() {
        return Err(MediaError::ManifestParse(
            "no video or audio adaptation set to plan".to_string(),
        ));
    }
    let mut tracks = Vec::new();
    let mut picks = Vec::new();
    let mut idx = 0usize;
    if let Some(si) = video_set {
        let set = &first.adaptation_sets[si];
        let ri = select_representation_idx(set, policy)?;
        let rep_base = resolve_rep_base(mpd, manifest_url, 0, si, ri)?;
        tracks.push(PlannedTrack {
            track_idx: idx,
            label: "v".to_string(),
            kind: TrackKind::Video,
            role: TrackRole::Required,
            playlist_uri: rep_base,
            language: set.lang.clone(),
        });
        picks.push(DashPick { set: si, rep: ri });
        idx += 1;
    }
    if let Some(si) = audio_set {
        let set = &first.adaptation_sets[si];
        // A side audio set (video present) rides Highest — the HLS
        // posture (audio renditions join by language chain, never by
        // the video policy); an audio-only MPD's set IS the variant
        // face, so the policy applies to it.
        let audio_policy = if video_set.is_some() {
            &VariantPolicy::Highest
        } else {
            policy
        };
        let ri = select_representation_idx(set, audio_policy)?;
        let rep_base = resolve_rep_base(mpd, manifest_url, 0, si, ri)?;
        tracks.push(PlannedTrack {
            track_idx: idx,
            label: if video_set.is_none() {
                "v".to_string()
            } else {
                "a".to_string()
            },
            kind: TrackKind::Audio,
            role: TrackRole::Required,
            playlist_uri: rep_base,
            language: set.lang.clone(),
        });
        picks.push(DashPick { set: si, rep: ri });
    }
    Ok(DashTrackPlan { tracks, picks })
}

/// The audio-set pick under the language chain.
fn pick_audio_set(period: &Period, want: Option<&str>) -> Option<usize> {
    let audio: Vec<usize> = period
        .adaptation_sets
        .iter()
        .enumerate()
        .filter(|(_, s)| set_kind(s) == SetKind::Audio)
        .map(|(i, _)| i)
        .collect();
    if audio.is_empty() {
        return None;
    }
    if let Some(want) = want {
        let want = want.to_ascii_lowercase();
        if let Some(i) = audio.iter().copied().find(|i| {
            period.adaptation_sets[*i]
                .lang
                .as_deref()
                .is_some_and(|l| l.to_ascii_lowercase().starts_with(&want))
        }) {
            return Some(i);
        }
    }
    if let Some(i) = audio.iter().copied().find(|i| {
        period.adaptation_sets[*i]
            .lang
            .as_deref()
            .is_some_and(|l| l.to_ascii_lowercase().starts_with("en"))
    }) {
        return Some(i);
    }
    Some(audio[0])
}

// ---------------------------------------------------------------------------
// selector-resolved planning (the unified three-layer selector
// over the DASH tree)
// ---------------------------------------------------------------------------

/// The selector's resolved DASH picks (the driver face of
/// [`crate::selector::resolve_selection`] over a `dash`-kind tree):
/// `primary` = the chosen primary representation's id, `attached` =
/// the explicitly attached side-stream representation ids (the
/// `format_id=` multi-value form — the necessity grading applies: an
/// attached failure degrades, never fails the task).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DashSelection {
    /// The primary representation's `@id` (a video rung, or the audio
    /// rep on an audio-only selection).
    pub primary: String,
    /// The attached side-stream representations' `@id`s (audio reps
    /// attach as `x-aN` sidecar tracks).
    pub attached: Vec<String>,
}

/// Find one representation by its `@id` across period-0's sets:
/// video sets searched first, then audio sets (a spec-unique id makes
/// the order moot; a hostile duplicate resolves find-first
/// deterministically — the same ruling the tree build documents).
fn find_rep_by_id<'a>(
    first: &'a Period,
    id: &str,
    kinds: &[SetKind],
) -> Option<(usize, usize, &'a Representation)> {
    for (si, set) in first.adaptation_sets.iter().enumerate() {
        if !kinds.contains(&set_kind(set)) {
            continue;
        }
        for (ri, rep) in set.representations.iter().enumerate() {
            if rep.id == id {
                return Some((si, ri, rep));
            }
        }
    }
    None
}

/// Plan the DASH track set under a **selector-resolved** choice
/// (the mirror of the HLS `chosen` face): the primary
/// representation is addressed by its `@id` (the escape hatch /
/// predicate pick), overriding the `--media-variant-policy` ladder
/// cap for the primary (single selection source — the HLS posture).
///
/// Rulings of record:
/// * primary in a video set (**any** video set — the face is the
///   pick's own set kind, not the first video set's index; a
///   multi-codec ladder's set-2 rung is as much the video face as
///   set-1's) → track 0 is that rung (Required `v`); the side audio
///   set still rides the language chain under Highest (audio joins by
///   chain, never by the video pick — `plan_dash_tracks` posture
///   unchanged);
/// * primary in an audio set (audio-only selection, or an audio-only
///   MPD whose set is the variant face) → track 0 IS that audio rep
///   (Required `v`, kind Audio — the audio-only-MPD precedent; no
///   language-chain track joins it: the selection named its audio);
/// * attached ids resolve to their reps and join as Sidecar `x-aN`
///   audio tracks, deduped by `(set, rep)` against the planned picks;
/// * an id absent from the fresh MPD = the `variant_policy` refusal
///   (the same code the tree-face resolution errors carry — a
///   manifest that changed between Resolving and the driver's
///   re-fetch lands the honest selection error, never a silent
///   fallback).
pub fn plan_dash_tracks_selected(
    mpd: &Mpd,
    manifest_url: &str,
    cfg: &TrackSetConfig,
    selection: &DashSelection,
) -> Result<DashTrackPlan, MediaError> {
    let Some(first) = mpd.periods.first() else {
        return Err(MediaError::ManifestParse(
            "MPD declares no period".to_string(),
        ));
    };
    let missing =
        |id: &str| MediaError::VariantPolicy(format!("format_id {id:?} not in the DASH tree"));
    // The primary: a video rung when one exists, else the audio face.
    let (psi, pri, _rep) = match find_rep_by_id(first, &selection.primary, &[SetKind::Video]) {
        Some(found) => found,
        None => find_rep_by_id(first, &selection.primary, &[SetKind::Audio])
            .ok_or_else(|| missing(&selection.primary))?,
    };
    let mut tracks = Vec::new();
    let mut picks = Vec::new();
    // The face is the primary's OWN set kind (a review-pass fix):
    // the tree exposes every video set's rungs and the selector
    // reaches them all (a multi-codec ladder is the common shape), so
    // a pick in the second-or-later video set is still the video face
    // — never index-compared against the FIRST video set's position
    // (that misroute planned a video archive under `kind=audio` with
    // the language chain silently skipped).
    let primary_is_video = set_kind(&first.adaptation_sets[psi]) == SetKind::Video;
    let rep_base = resolve_rep_base(mpd, manifest_url, 0, psi, pri)?;
    if primary_is_video {
        tracks.push(PlannedTrack {
            track_idx: 0,
            label: "v".to_string(),
            kind: TrackKind::Video,
            role: TrackRole::Required,
            playlist_uri: rep_base,
            language: first.adaptation_sets[psi].lang.clone(),
        });
        picks.push(DashPick { set: psi, rep: pri });
        // The side audio chain (language chain under Highest — the
        // plan_dash_tracks posture).
        if let Some(si) = pick_audio_set(first, cfg.audio_lang.as_deref()) {
            let set = &first.adaptation_sets[si];
            let ri = select_representation_idx(set, &VariantPolicy::Highest)?;
            let rep_base = resolve_rep_base(mpd, manifest_url, 0, si, ri)?;
            tracks.push(PlannedTrack {
                track_idx: 1,
                label: "a".to_string(),
                kind: TrackKind::Audio,
                role: TrackRole::Required,
                playlist_uri: rep_base,
                language: set.lang.clone(),
            });
            picks.push(DashPick { set: si, rep: ri });
        }
    } else {
        // Audio-only selection: the named audio rep IS the variant
        // face (Required `v`, kind Audio — the audio-only-MPD
        // precedent); no language-chain track joins it.
        tracks.push(PlannedTrack {
            track_idx: 0,
            label: "v".to_string(),
            kind: TrackKind::Audio,
            role: TrackRole::Required,
            playlist_uri: rep_base,
            language: first.adaptation_sets[psi].lang.clone(),
        });
        picks.push(DashPick { set: psi, rep: pri });
    }
    // The explicitly attached side streams (the grading: sidecar).
    let mut idx = tracks.len();
    let mut aud = 0usize;
    for id in &selection.attached {
        let (si, ri, _) = find_rep_by_id(first, id, &[SetKind::Video, SetKind::Audio])
            .ok_or_else(|| missing(id))?;
        if picks.iter().any(|p| p.set == si && p.rep == ri) {
            continue;
        }
        let rep_base = resolve_rep_base(mpd, manifest_url, 0, si, ri)?;
        let label = format!("x-a{aud}");
        aud += 1;
        tracks.push(PlannedTrack {
            track_idx: idx,
            label,
            kind: TrackKind::Audio,
            role: TrackRole::Sidecar,
            playlist_uri: rep_base,
            language: first.adaptation_sets[si].lang.clone(),
        });
        picks.push(DashPick { set: si, rep: ri });
        idx += 1;
    }
    Ok(DashTrackPlan { tracks, picks })
}

// ---------------------------------------------------------------------------
// base-URL resolution
// ---------------------------------------------------------------------------

/// Resolve a representation's addressing base across the BaseURL
/// chain (manifest URL ← MPD ← Period ← AdaptationSet ←
/// Representation; first BaseURL per level).
pub fn resolve_rep_base(
    mpd: &Mpd,
    manifest_url: &str,
    period_idx: usize,
    set_idx: usize,
    rep_idx: usize,
) -> Result<String, MediaError> {
    let mut base = parse_url(manifest_url)?;
    let levels = [
        mpd.base_urls.first().cloned(),
        mpd.periods
            .get(period_idx)
            .and_then(|p| p.base_urls.first().cloned()),
        mpd.periods
            .get(period_idx)
            .and_then(|p| p.adaptation_sets.get(set_idx))
            .and_then(|s| s.base_urls.first().cloned()),
        mpd.periods
            .get(period_idx)
            .and_then(|p| p.adaptation_sets.get(set_idx))
            .and_then(|s| s.representations.get(rep_idx))
            .and_then(|r| r.base_urls.first().cloned()),
    ];
    for level in levels.into_iter().flatten() {
        base = join(&base, &level)?;
    }
    Ok(base.to_string())
}

fn parse_url(url: &str) -> Result<taiji_http::reqwest::Url, MediaError> {
    taiji_http::reqwest::Url::parse(url)
        .map_err(|e| MediaError::ManifestParse(format!("manifest url {url:?}: {e}")))
}

fn join(
    base: &taiji_http::reqwest::Url,
    rel: &str,
) -> Result<taiji_http::reqwest::Url, MediaError> {
    base.join(rel)
        .map_err(|e| MediaError::ManifestParse(format!("resolve {rel:?}: {e}")))
}

/// The effective addressing of one representation inside one period
/// (inheritance already applied at parse).
enum Addressing<'a> {
    Template(&'a SegmentTemplate),
    List(&'a SegmentList),
    /// Single-resource sidx form — `indexRange` present.
    Sidx {
        base: String,
        index_range: (u64, u64),
        init_range: Option<(u64, u64)>,
        timescale: u64,
    },
    /// SegmentBase without indexRange = the plain single-segment form.
    SingleFile,
    /// Plain BaseURL: one whole-resource segment.
    PlainBase,
}

fn addressing_of<'a>(
    mpd: &'a Mpd,
    period_idx: usize,
    set_idx: usize,
    rep_idx: usize,
    base: &str,
) -> Result<Addressing<'a>, MediaError> {
    let period = mpd
        .periods
        .get(period_idx)
        .ok_or_else(|| MediaError::ManifestParse("period index out of range".to_string()))?;
    let set = period.adaptation_sets.get(set_idx).ok_or_else(|| {
        MediaError::ManifestParse("adaptation set index out of range".to_string())
    })?;
    let rep = set.representations.get(rep_idx).ok_or_else(|| {
        MediaError::ManifestParse("representation index out of range".to_string())
    })?;
    // Effective addressing walks the inheritance chain: a
    // representation that declares nothing inherits the set's (which
    // the parse already merged over the period's); a representation
    // that declares its own carries the merge folded in at parse.
    if let Some(t) = rep
        .segment_template
        .as_ref()
        .or(set.segment_template.as_ref())
        .or(period.segment_template.as_ref())
    {
        return Ok(Addressing::Template(t));
    }
    if let Some(l) = rep
        .segment_list
        .as_ref()
        .or(set.segment_list.as_ref())
        .or(period.segment_list.as_ref())
    {
        return Ok(Addressing::List(l));
    }
    if let Some(b) = &rep.segment_base {
        if let Some((begin, end)) = b.index_range {
            return Ok(Addressing::Sidx {
                base: base.to_string(),
                index_range: (begin, end),
                init_range: b.initialization_range,
                timescale: b.timescale.unwrap_or(1),
            });
        }
        return Ok(Addressing::SingleFile);
    }
    Ok(Addressing::PlainBase)
}

/// Expand one representation across all periods into the synthetic
/// track playlist. Pure (URL joins only). The sidx form defers to
/// a fetch ([`Expanded::DeferredSidx`]).
pub fn expand_representation(
    mpd: &Mpd,
    manifest_url: &str,
    pick: &DashPick,
) -> Result<Expanded, MediaError> {
    let rep_base = resolve_rep_base(mpd, manifest_url, 0, pick.set, pick.rep)?;
    let mut segments: Vec<MediaSegment> = Vec::new();
    let mut init_sections: Vec<DashInit> = Vec::new();
    let mut segment_count = 0usize;
    // The URI budget accumulator (every push/init site threads it).
    let mut expanded_bytes = 0u64;

    // Cross-period matching coordinates (the of-record
    // ruling: identity is id-based; the positional clamp is removed).
    let first_set = &mpd.periods[0].adaptation_sets[pick.set];
    let set_id = first_set.id.clone();
    let rep_id = first_set.representations[pick.rep].id.clone();

    for (pi, period) in mpd.periods.iter().enumerate() {
        let (set_idx, rep_idx) = if pi == 0 {
            (pick.set, pick.rep)
        } else {
            match_period_track(period, pi, &set_id, &rep_id)?
        };
        let base = if pi == 0 {
            rep_base.clone()
        } else {
            resolve_rep_base(mpd, manifest_url, pi, set_idx, rep_idx)?
        };
        match addressing_of(mpd, pi, set_idx, rep_idx, &base)? {
            Addressing::Template(template) => {
                let rep = &mpd.periods[pi].adaptation_sets[set_idx].representations[rep_idx];
                expand_template_period(
                    mpd,
                    pi,
                    template,
                    rep,
                    &base,
                    &mut init_sections,
                    &mut segments,
                    &mut segment_count,
                    &mut expanded_bytes,
                )?;
            }
            Addressing::List(list) => {
                expand_list_period(
                    list,
                    &base,
                    pi,
                    &mut init_sections,
                    &mut segments,
                    &mut segment_count,
                    &mut expanded_bytes,
                )?;
            }
            Addressing::Sidx {
                base,
                index_range,
                init_range,
                timescale,
            } => {
                if mpd.periods.len() > 1 {
                    return Err(MediaError::ManifestParse(
                        "sidx addressing inside a multi-period MPD: one resource per \
                         representation per period is not expressible in the single-resource \
                         SegmentBase form; declare one Period or use \
                         SegmentTemplate/SegmentList"
                            .to_string(),
                    ));
                }
                let init = init_range
                    .map(|(begin, end)| {
                        Ok::<DashInit, MediaError>(DashInit {
                            uri: base.clone(),
                            range: Some(inclusive_to_range(begin, end)?),
                        })
                    })
                    .transpose()?;
                return Ok(Expanded::DeferredSidx(SidxPlan {
                    base,
                    index_range,
                    init,
                    timescale,
                }));
            }
            Addressing::SingleFile | Addressing::PlainBase => {
                // One whole-resource segment = the base itself; a
                // plain single file carries no init knowledge.
                let first_of_period = segment_count;
                push_segment(
                    &mut segments,
                    &mut segment_count,
                    &mut expanded_bytes,
                    MediaSegment {
                        sequence: 0,
                        uri: base.clone(),
                        duration: period
                            .duration
                            .or(mpd.media_presentation_duration)
                            .unwrap_or(0.0),
                        title: None,
                        byte_range: None,
                        discontinuity: pi > 0,
                        key: None,
                        map: None,
                    },
                )?;
                let _ = first_of_period;
            }
        }
    }
    let init_files = init_sections
        .iter()
        .enumerate()
        .map(|(i, init)| init.to_init_section(i))
        .collect();
    Ok(Expanded::Ready(ExpandedTrack {
        playlist: MediaPlaylist {
            endlist: true,
            independent_segments: true,
            init_sections: init_files,
            segments,
            ..MediaPlaylist::default()
        },
        rep_base,
    }))
}

/// Match the selected track's set + representation in a **later**
/// period: cross-period identity is strictly id-based.
/// The first period's `AdaptationSet@id` and the picked
/// `Representation@id` must recur verbatim; a first-period set
/// without `@id`, a later period whose set-id set lacks it, or a
/// changed rep id is an explicit `manifest_parse` error. The
/// pre-fix positional clamp silently expanded whatever happened to
/// sit at the old coordinates — a per-period rendition mix-up the
/// stream would decode as data (the wrong-data risk); refusing the
/// manifest is the honest face. Period 0 needs no matching (its own
/// pick is already resolved).
fn match_period_track(
    period: &Period,
    pi: usize,
    set_id: &Option<String>,
    rep_id: &str,
) -> Result<(usize, usize), MediaError> {
    let Some(id) = set_id.as_deref() else {
        return Err(MediaError::ManifestParse(format!(
            "period {pi}: the selected adaptation set carries no @id in the first period — \
             cross-period identity is unmatchable (positional matching was removed \
             by the erratum of record: it silently expanded whatever sat at the old coordinates)"
        )));
    };
    let Some(set_idx) = period
        .adaptation_sets
        .iter()
        .position(|s| s.id.as_deref() == Some(id))
    else {
        return Err(MediaError::ManifestParse(format!(
            "period {pi}: no adaptation set with @id {id:?} (the first period's selected \
             set) — cross-period set identity must recur (positional matching was removed \
             by the erratum of record)"
        )));
    };
    let set = &period.adaptation_sets[set_idx];
    let Some(rep_idx) = set.representations.iter().position(|r| r.id == rep_id) else {
        return Err(MediaError::ManifestParse(format!(
            "period {pi}: adaptation set {id:?} carries no representation @id {rep_id:?} — \
             cross-period representation identity must recur (positional matching was \
             removed by the erratum of record)"
        )));
    };
    Ok((set_idx, rep_idx))
}

/// Period duration in seconds for the template count arithmetic
/// (`Period@duration`, else the presentation-duration remainder
/// after the explicitly-durated predecessors).
fn period_duration(mpd: &Mpd, pi: usize) -> Result<f64, MediaError> {
    let period = &mpd.periods[pi];
    if let Some(d) = period.duration {
        return Ok(d);
    }
    if let Some(total) = mpd.media_presentation_duration {
        let mut used = 0.0;
        for p in &mpd.periods[..pi] {
            used += p.duration.unwrap_or(0.0);
        }
        let rest = total - used;
        if rest > 0.0 {
            return Ok(rest);
        }
    }
    Err(MediaError::ManifestParse(format!(
        "period {pi} duration not derivable (no @duration, no @mediaPresentationDuration \
         remainder)"
    )))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the period expanders thread the accumulator set explicitly (single-pass face)"
)]
fn expand_template_period(
    mpd: &Mpd,
    pi: usize,
    template: &SegmentTemplate,
    rep: &Representation,
    base: &str,
    init_sections: &mut Vec<DashInit>,
    segments: &mut Vec<MediaSegment>,
    segment_count: &mut usize,
    expanded_bytes: &mut u64,
) -> Result<(), MediaError> {
    let timescale = template.timescale.unwrap_or(1).max(1);
    let start_number = template.start_number.unwrap_or(1);
    let base_url = parse_url(base)?;

    // This period's init (template form): expansion with the
    // representation-wide values only.
    let init_uri = match &template.initialization {
        Some(t) => {
            let expanded = expand_url_template(
                t,
                &TemplateValues {
                    representation_id: &rep.id,
                    bandwidth: rep.bandwidth,
                    number: None,
                    time: None,
                },
            )?;
            Some(join(&base_url, &expanded)?.to_string())
        }
        None => None,
    };

    let first_of_period = *segment_count;
    let media = template.media.as_deref().ok_or_else(|| {
        MediaError::ManifestParse(
            "SegmentTemplate without @media (no segment addressing)".to_string(),
        )
    })?;
    let push_one = |number: u64,
                    time: u64,
                    dur_ticks: u64,
                    segments: &mut Vec<MediaSegment>,
                    segment_count: &mut usize,
                    expanded_bytes: &mut u64|
     -> Result<(), MediaError> {
        let expanded = expand_url_template(
            media,
            &TemplateValues {
                representation_id: &rep.id,
                bandwidth: rep.bandwidth,
                number: Some(number),
                time: Some(time),
            },
        )?;
        let uri = join(&base_url, &expanded)?.to_string();
        push_segment(
            segments,
            segment_count,
            expanded_bytes,
            MediaSegment {
                sequence: 0,
                uri,
                duration: dur_ticks as f64 / timescale as f64,
                title: None,
                byte_range: None,
                discontinuity: false,
                key: None,
                map: None,
            },
        )
    };

    if template.timeline.is_empty() {
        // @duration form: count = ceil(period_duration / seg_dur).
        let seg_dur = template.duration.ok_or_else(|| {
            MediaError::ManifestParse(
                "SegmentTemplate without @duration or <SegmentTimeline>".to_string(),
            )
        })?;
        let period_s = period_duration(mpd, pi)?;
        let total_ticks = period_s * timescale as f64;
        let count = (total_ticks / seg_dur as f64).ceil();
        if !count.is_finite() || count < 0.0 || count > MAX_MEDIA_SEGMENTS as f64 {
            return Err(MediaError::ManifestTooLarge(format!(
                "template expands to {count} segments (cap {MAX_MEDIA_SEGMENTS})"
            )));
        }
        // Allocation-free product pre-check (the accumulator in
        // [`push_segment`] is the exact bound; this refuses the
        // hostile template-bytes × segment-count product before the
        // first string is built — the review-block amplification
        // class). The timeline arm below rides the accumulator alone
        // (its transient is thereby bounded at the budget + one URI).
        if count as u64 * media.len() as u64 > MAX_EXPANSION_OUTPUT_BYTES {
            return Err(MediaError::ManifestTooLarge(format!(
                "template product {count} segments x {} template bytes over the {} byte                  expansion budget",
                media.len(),
                MAX_EXPANSION_OUTPUT_BYTES
            )));
        }
        for i in 0..count as u64 {
            let number = start_number
                .checked_add(i)
                .ok_or_else(|| MediaError::ManifestParse("$Number$ overflow".to_string()))?;
            let time = number
                .checked_sub(start_number)
                .and_then(|n| n.checked_mul(seg_dur))
                .ok_or_else(|| {
                    MediaError::ManifestParse("$Time$ arithmetic overflow".to_string())
                })?;
            push_one(
                number,
                time,
                seg_dur,
                segments,
                segment_count,
                expanded_bytes,
            )?;
            if let Some(seg) = segments.last_mut() {
                seg.discontinuity = pi > 0 && *segment_count == first_of_period + 1;
            }
        }
    } else {
        // SegmentTimeline form: running (number, time) over S@t/d/r.
        let mut number = start_number;
        let mut time: Option<u64> = None;
        for entry in &template.timeline {
            let Some(mut t) = entry.t.or(time) else {
                return Err(MediaError::ManifestParse(
                    "first <S> without @t (no timeline anchor)".to_string(),
                ));
            };
            let repeat = if entry.r < 0 {
                // r = -1: repeat until the period end — the segment
                // count is ceil(remaining / d) (starts strictly below
                // the end; an exact multiple ends on the boundary),
                // so the repeat count is one less.
                let period_s = period_duration(mpd, pi)?;
                let end_ticks = period_s * timescale as f64;
                if end_ticks <= t as f64 {
                    0u64
                } else {
                    let count = ((end_ticks - t as f64) / entry.d as f64).ceil();
                    if !count.is_finite() || count < 0.0 || count > MAX_MEDIA_SEGMENTS as f64 {
                        return Err(MediaError::ManifestTooLarge(format!(
                            "<S @r=-1> expands to {count} segments (cap {MAX_MEDIA_SEGMENTS})"
                        )));
                    }
                    count as u64 - 1
                }
            } else {
                entry.r as u64
            };
            for _ in 0..=repeat {
                push_one(number, t, entry.d, segments, segment_count, expanded_bytes)?;
                if let Some(seg) = segments.last_mut() {
                    seg.discontinuity = pi > 0 && *segment_count == first_of_period + 1;
                }
                t = t.checked_add(entry.d).ok_or_else(|| {
                    MediaError::ManifestParse("timeline time overflow".to_string())
                })?;
                number = number
                    .checked_add(1)
                    .ok_or_else(|| MediaError::ManifestParse("$Number$ overflow".to_string()))?;
            }
            time = Some(t);
        }
    }

    // This period's map ordinal (find-or-append by URI identity).
    if let Some(uri) = init_uri {
        let map = ensure_init(
            init_sections,
            &DashInit { uri, range: None },
            expanded_bytes,
        )?;
        for seg in segments.iter_mut().skip(first_of_period) {
            seg.map = Some(map);
        }
    }
    Ok(())
}

fn expand_list_period(
    list: &SegmentList,
    base: &str,
    pi: usize,
    init_sections: &mut Vec<DashInit>,
    segments: &mut Vec<MediaSegment>,
    segment_count: &mut usize,
    expanded_bytes: &mut u64,
) -> Result<(), MediaError> {
    let timescale = list.timescale.unwrap_or(1).max(1) as f64;
    let base_url = parse_url(base)?;
    let init = match &list.initialization {
        Some(init) => {
            let uri = match &init.source_url {
                Some(u) => join(&base_url, u)?.to_string(),
                None => base.to_string(),
            };
            Some(DashInit {
                uri,
                range: init
                    .range
                    .map(|(b, e)| inclusive_to_range(b, e))
                    .transpose()?,
            })
        }
        None => None,
    };
    let first_of_period = *segment_count;
    for url in &list.segment_urls {
        let uri = match &url.media {
            Some(m) => join(&base_url, m)?.to_string(),
            None => base.to_string(),
        };
        let duration = list.duration.map(|d| d as f64 / timescale).unwrap_or(0.0);
        push_segment(
            segments,
            segment_count,
            expanded_bytes,
            MediaSegment {
                sequence: 0,
                uri,
                duration,
                title: None,
                byte_range: url
                    .media_range
                    .map(|(b, e)| inclusive_to_range(b, e))
                    .transpose()?,
                discontinuity: false,
                key: None,
                map: None,
            },
        )?;
        if let Some(seg) = segments.last_mut() {
            seg.discontinuity = pi > 0 && *segment_count == first_of_period + 1;
        }
    }
    if let Some(init) = &init {
        let map = ensure_init(init_sections, init, expanded_bytes)?;
        for seg in segments.iter_mut().skip(first_of_period) {
            seg.map = Some(map);
        }
    }
    Ok(())
}

/// Push one segment with the cross-period monotonic ordinal. The
/// URI budgets ride this chokepoint (every addressing form lands
/// here): one URI over [`MAX_SEGMENT_URI_BYTES`] or the accumulated
/// [`MAX_EXPANSION_OUTPUT_BYTES`] over is `manifest_too_large` —
/// hostile manifests refuse, never allocate to OOM.
fn push_segment(
    segments: &mut Vec<MediaSegment>,
    segment_count: &mut usize,
    expanded_bytes: &mut u64,
    mut seg: MediaSegment,
) -> Result<(), MediaError> {
    if seg.uri.len() > MAX_SEGMENT_URI_BYTES {
        return Err(MediaError::ManifestTooLarge(format!(
            "expanded segment URI {} bytes over the {} byte bound",
            seg.uri.len(),
            MAX_SEGMENT_URI_BYTES
        )));
    }
    *expanded_bytes = expanded_bytes
        .checked_add(seg.uri.len() as u64)
        .ok_or_else(|| MediaError::ManifestParse("expansion budget overflow".to_string()))?;
    if *expanded_bytes > MAX_EXPANSION_OUTPUT_BYTES {
        return Err(MediaError::ManifestTooLarge(format!(
            "task expansion output {} bytes over the {} byte budget",
            expanded_bytes, MAX_EXPANSION_OUTPUT_BYTES
        )));
    }
    seg.sequence = *segment_count as u64;
    *segment_count = segment_count
        .checked_add(1)
        .ok_or_else(|| MediaError::ManifestParse("segment count overflow".to_string()))?;
    if *segment_count > MAX_MEDIA_SEGMENTS {
        return Err(MediaError::ManifestTooLarge(format!(
            "task expands over {MAX_MEDIA_SEGMENTS} segments"
        )));
    }
    segments.push(seg);
    Ok(())
}

/// Find-or-append an init section; returns its ordinal. A newly
/// appended init rides the same URI budgets as segments (counted
/// once per distinct init; the dedup face keeps repeated inits free).
fn ensure_init(
    init_sections: &mut Vec<DashInit>,
    init: &DashInit,
    expanded_bytes: &mut u64,
) -> Result<usize, MediaError> {
    if let Some(pos) = init_sections.iter().position(|i| i == init) {
        return Ok(pos);
    }
    if init.uri.len() > MAX_SEGMENT_URI_BYTES {
        return Err(MediaError::ManifestTooLarge(format!(
            "expanded init URI {} bytes over the {} byte bound",
            init.uri.len(),
            MAX_SEGMENT_URI_BYTES
        )));
    }
    *expanded_bytes = expanded_bytes
        .checked_add(init.uri.len() as u64)
        .ok_or_else(|| MediaError::ManifestParse("expansion budget overflow".to_string()))?;
    if *expanded_bytes > MAX_EXPANSION_OUTPUT_BYTES {
        return Err(MediaError::ManifestTooLarge(format!(
            "task expansion output {} bytes over the {} byte budget",
            expanded_bytes, MAX_EXPANSION_OUTPUT_BYTES
        )));
    }
    init_sections.push(init.clone());
    Ok(init_sections.len() - 1)
}

/// `"begin-end"` inclusive pair → the parser's `ByteRange` shape.
fn inclusive_to_range(begin: u64, end: u64) -> Result<ByteRange, MediaError> {
    let length = end
        .checked_add(1)
        .and_then(|e| e.checked_sub(begin))
        .ok_or_else(|| {
            MediaError::ManifestParse(format!("byte range {begin}-{end}: length overflow"))
        })?;
    Ok(ByteRange {
        length,
        offset: begin,
        offset_omitted: false,
    })
}

// ---------------------------------------------------------------------------
// sidx materialization (pure half of the deferred fetch)
// ---------------------------------------------------------------------------

/// Materialize the sidx-addressed segments from the fetched
/// `indexRange` bytes: the bytes may carry init data + the sidx box
/// (+ trailing index data); the first `sidx` is parsed and its media
/// references become known byte ranges inside the base resource —
/// the first at `indexRange.begin + <sidx box end within the fetched
/// bytes> + first_offset`, each subsequent at the previous end. A
/// `reference_type=1` row (nested sidx) is `sidx_unsupported`.
pub fn materialize_sidx(plan: &SidxPlan, fetched: &[u8]) -> Result<ExpandedTrack, MediaError> {
    // The indexRange bytes are manifest-addressed remote content, not
    // local staging: a bad box structure surfaces as manifest_parse
    // (the bmff reader's own `staging` vocabulary stays inside that
    // module's local-disk face).
    let bmff_err = |e: crate::error::MediaError| {
        MediaError::ManifestParse(format!("indexRange box structure: {e}"))
    };
    let boxes = bmff::iter_boxes(fetched).map_err(bmff_err)?;
    let sidx_box = boxes.iter().find(|b| b.typ == *b"sidx").ok_or_else(|| {
        MediaError::ManifestParse("SegmentBase indexRange carries no sidx box".to_string())
    })?;
    let info = bmff::read_sidx(sidx_box.payload).map_err(bmff_err)?;
    if info.has_nested_sidx() {
        return Err(MediaError::SidxUnsupported(format!(
            "sidx at indexRange {}-{} carries reference_type=1 rows (nested/hierarchical \
             sidx); single-level sidx only",
            plan.index_range.0, plan.index_range.1
        )));
    }
    if info.references.is_empty() {
        return Err(MediaError::ManifestParse(
            "sidx declares zero references (no segments)".to_string(),
        ));
    }
    let timescale = if info.timescale > 0 {
        u64::from(info.timescale)
    } else {
        plan.timescale.max(1)
    };
    // Anchor: the first referenced subsegment sits first_offset bytes
    // past the END of the sidx box, in resource coordinates.
    let anchor = plan
        .index_range
        .0
        .checked_add(sidx_box.end)
        .and_then(|v| v.checked_add(info.first_offset))
        .ok_or_else(|| MediaError::ManifestParse("sidx anchor arithmetic overflow".to_string()))?;
    let mut playlist = MediaPlaylist {
        endlist: true,
        independent_segments: true,
        ..MediaPlaylist::default()
    };
    if let Some(init) = &plan.init {
        playlist.init_sections.push(init.to_init_section(0));
    }
    let map = (!playlist.init_sections.is_empty()).then_some(0);
    let mut offset = anchor;
    let mut segment_count = 0usize;
    // The same URI budget over the sidx-derived references (the base
    // is input-bounded but the reference table multiplies it).
    let mut expanded_bytes = 0u64;
    for reference in &info.references {
        let length = u64::from(reference.reference_size);
        let end = offset.checked_add(length).ok_or_else(|| {
            MediaError::ManifestParse("sidx reference range overflow".to_string())
        })?;
        push_segment(
            &mut playlist.segments,
            &mut segment_count,
            &mut expanded_bytes,
            MediaSegment {
                sequence: 0,
                uri: plan.base.clone(),
                duration: f64::from(reference.subsegment_duration) / timescale as f64,
                title: None,
                byte_range: Some(ByteRange {
                    length,
                    offset,
                    offset_omitted: false,
                }),
                discontinuity: false,
                key: None,
                map,
            },
        )?;
        offset = end;
    }
    Ok(ExpandedTrack {
        playlist,
        rep_base: plan.base.clone(),
    })
}

// ---------------------------------------------------------------------------
// normalized digest + variant identity (the shared semantics)
// ---------------------------------------------------------------------------

/// The canonical declared-structure body (the shared text under both
/// digest forms below: every URI's query stripped; **no** header and
/// **no** manifest-URL line — the callers prepend their own domain
/// header and, for [`mpd_digest`], append the entry-URL line).
fn mpd_canonical_body(mpd: &Mpd) -> String {
    use std::fmt::Write as _;
    let mut text = String::new();
    let _ = writeln!(
        text,
        "mpd_duration={}",
        match mpd.media_presentation_duration {
            Some(d) => format!("{d:.6}"),
            None => "-".to_string(),
        }
    );
    for b in &mpd.base_urls {
        let _ = writeln!(text, "baseurl\t{}", strip_query(b));
    }
    for (pi, period) in mpd.periods.iter().enumerate() {
        let _ = writeln!(
            text,
            "period\t{pi}\t{}\t{}\t{}",
            period.id.as_deref().unwrap_or("-"),
            match period.start {
                Some(s) => format!("{s:.6}"),
                None => "-".to_string(),
            },
            match period.duration {
                Some(d) => format!("{d:.6}"),
                None => "-".to_string(),
            },
        );
        for b in &period.base_urls {
            let _ = writeln!(text, "pbaseurl\t{pi}\t{}", strip_query(b));
        }
        for (si, set) in period.adaptation_sets.iter().enumerate() {
            let _ = writeln!(
                text,
                "set\t{pi}\t{si}\t{}\t{}\t{}\t{}\t{}",
                set.id.as_deref().unwrap_or("-"),
                set.lang.as_deref().unwrap_or("-"),
                set.content_type.as_deref().unwrap_or("-"),
                set.codecs.as_deref().unwrap_or("-"),
                set.mime_type.as_deref().unwrap_or("-"),
            );
            digest_template(
                &mut text,
                &format!("settpl\t{pi}\t{si}"),
                set.segment_template.as_ref(),
            );
            if let Some(list) = &set.segment_list {
                digest_list(&mut text, &format!("setlist\t{pi}\t{si}"), list);
            }
            for (ri, rep) in set.representations.iter().enumerate() {
                let _ = writeln!(
                    text,
                    "rep\t{pi}\t{si}\t{ri}\t{}\t{}\t{}\t{}\t{}",
                    rep.id,
                    rep.bandwidth,
                    rep.width.map_or("-".to_string(), |w| w.to_string()),
                    rep.height.map_or("-".to_string(), |h| h.to_string()),
                    rep.codecs.as_deref().unwrap_or("-"),
                );
                for b in &rep.base_urls {
                    let _ = writeln!(text, "repbaseurl\t{pi}\t{si}\t{ri}\t{}", strip_query(b));
                }
                digest_template(
                    &mut text,
                    &format!("reptpl\t{pi}\t{si}\t{ri}"),
                    rep.segment_template.as_ref(),
                );
                if let Some(list) = &rep.segment_list {
                    digest_list(&mut text, &format!("replist\t{pi}\t{si}\t{ri}"), list);
                }
                if let Some(base) = &rep.segment_base {
                    let _ = writeln!(
                        text,
                        "repbase\t{pi}\t{si}\t{ri}\t{}\t{}\t{}",
                        base.timescale.map_or("-".to_string(), |t| t.to_string()),
                        base.index_range
                            .map_or("-".to_string(), |(b, e)| format!("{b}-{e}")),
                        base.initialization_range
                            .map_or("-".to_string(), |(b, e)| format!("{b}-{e}")),
                    );
                }
            }
        }
    }
    text
}

/// Normalized MPD digest (the m3u8 digest semantics on the DASH side: a
/// SHA-256 over the canonical **declared** structure with every URI's
/// query stripped — a re-fetched MPD whose URLs only carry fresh CDN
/// signatures digests identically; any structural change does not).
/// The canonical text **binds the entry URL** (query-stripped path):
/// the recovery/structure-diff consumers want the fetch location in
/// the identity — the same bytes from a different mirror are a
/// different row digest by design.
pub fn mpd_digest(mpd: &Mpd, manifest_url: &str) -> String {
    use std::fmt::Write as _;
    let mut text = String::from("dash-mpd/1\n");
    text.push_str(&mpd_canonical_body(mpd));
    let _ = writeln!(text, "manifest\t{}", strip_query(manifest_url));
    hex(&sha256(text.as_bytes()))
}

/// URL-free MPD content digest: the same canonical body under a
/// distinct domain header, with **no** manifest-URL line — identical
/// declared structure digests identically regardless of where it was
/// fetched from (the download-archive's checkpoint-② compartment —
/// the same MPD served by a switched CDN/mirror must
/// hit; [`mpd_digest`]'s URL binding is wrong for that purpose). A
/// structural change flips this digest exactly as it flips
/// [`mpd_digest`].
pub fn mpd_content_digest(mpd: &Mpd) -> String {
    let mut text = String::from("dash-mpd-content/1\n");
    text.push_str(&mpd_canonical_body(mpd));
    hex(&sha256(text.as_bytes()))
}

fn digest_template(text: &mut String, label: &str, template: Option<&SegmentTemplate>) {
    use std::fmt::Write as _;
    let Some(t) = template else {
        return;
    };
    let _ = writeln!(
        text,
        "{label}\t{}\t{}\t{}\t{}\t{}\t{}",
        t.timescale.map_or("-".to_string(), |v| v.to_string()),
        t.duration.map_or("-".to_string(), |v| v.to_string()),
        t.start_number.map_or("-".to_string(), |v| v.to_string()),
        t.presentation_time_offset
            .map_or("-".to_string(), |v| v.to_string()),
        t.initialization.as_deref().map(strip_query).unwrap_or("-"),
        t.media.as_deref().map(strip_query).unwrap_or("-"),
    );
    for entry in &t.timeline {
        let _ = writeln!(
            text,
            "{label}s\t{}\t{}\t{}",
            entry.t.map_or("-".to_string(), |v| v.to_string()),
            entry.d,
            entry.r,
        );
    }
}

fn digest_list(text: &mut String, label: &str, list: &SegmentList) {
    use std::fmt::Write as _;
    let _ = writeln!(
        text,
        "{label}\t{}\t{}",
        list.timescale.map_or("-".to_string(), |v| v.to_string()),
        list.duration.map_or("-".to_string(), |v| v.to_string()),
    );
    if let Some(init) = &list.initialization {
        let _ = writeln!(
            text,
            "{label}init\t{}\t{}",
            init.source_url.as_deref().map(strip_query).unwrap_or("-"),
            init.range
                .map_or("-".to_string(), |(b, e)| format!("{b}-{e}")),
        );
    }
    for url in &list.segment_urls {
        let _ = writeln!(
            text,
            "{label}u\t{}\t{}",
            url.media.as_deref().map(strip_query).unwrap_or("-"),
            url.media_range
                .map_or("-".to_string(), |(b, e)| format!("{b}-{e}")),
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// DASH representation identity = the shared pure function applied to
/// the representation facts (normalized path + bandwidth +
/// resolution — the shared-semantics note; the MPD side
/// spells the same semantics,
/// same [`VariantIdentity`] type).
pub fn representation_identity(rep_base: &str, rep: &Representation) -> VariantIdentity {
    variant_identity(
        rep_base,
        rep.bandwidth,
        match (rep.width, rep.height) {
            (Some(w), Some(h)) => Some((w, h)),
            _ => None,
        },
    )
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    const MPD_A: &[u8] = br#"<MPD type="static" mediaPresentationDuration="PT1S">
  <Period duration="PT1S">
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate timescale="1000" duration="500" startNumber="1"
        initialization="init.mp4" media="seg-$Number$.m4s"/>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
</MPD>"#;

    fn parse(input: &[u8]) -> Mpd {
        super::super::parse::parse_mpd(input).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The two digest forms' URL posture (the review
    /// blocker's pin): mpd_digest binds the entry URL (its
    /// recovery/structure-diff purpose); mpd_content_digest is
    /// URL-free (the download-archive's cross-URL compartment) — the
    /// same structure from a switched mirror digests identically
    /// there, and never collides with the URL-bound domain.
    #[test]
    fn content_digest_is_url_free_digest_binds_url() {
        let mpd = parse(MPD_A);
        // mpd_digest: the entry URL is part of the identity.
        assert_ne!(
            mpd_digest(&mpd, "https://cdn-a.test/v.mpd"),
            mpd_digest(&mpd, "https://mirror-b.test/v.mpd"),
            "the URL-bound form differs across mirrors (existing semantics)"
        );
        assert_eq!(
            mpd_digest(&mpd, "https://cdn-a.test/v.mpd?sig=1"),
            mpd_digest(&mpd, "https://cdn-a.test/v.mpd?sig=2"),
            "query rotation stays invisible (existing semantics)"
        );
        // mpd_content_digest: URL-free — the archive hit face.
        assert_eq!(
            mpd_content_digest(&mpd),
            mpd_content_digest(&mpd),
            "deterministic"
        );
        let same_elsewhere = parse(MPD_A);
        assert_eq!(
            mpd_content_digest(&mpd),
            mpd_content_digest(&same_elsewhere),
            "the content form carries no fetch location"
        );
        // The two domains never collide (distinct headers).
        assert_ne!(mpd_digest(&mpd, "-"), mpd_content_digest(&mpd));
        // A structural change flips both forms.
        let changed: &[u8] = br#"<MPD type="static" mediaPresentationDuration="PT2S">
  <Period duration="PT2S">
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate timescale="1000" duration="500" startNumber="1"
        initialization="init.mp4" media="seg-$Number$.m4s"/>
      <Representation id="v" bandwidth="500000" width="320" height="240"/>
    </AdaptationSet>
  </Period>
</MPD>"#;
        assert_ne!(
            mpd_content_digest(&mpd),
            mpd_content_digest(&parse(changed)),
            "structure changes flip the content form"
        );
        assert_ne!(
            mpd_digest(&mpd, "https://x.test/v.mpd"),
            mpd_digest(&parse(changed), "https://x.test/v.mpd"),
            "structure changes flip the URL-bound form"
        );
    }
}

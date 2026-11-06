//! Multi-track model + track necessity grading (the media spec's
//! track line — the spec of record; the product spec's language
//! policy inherited via the media spec's checklist).
//!
//! Input: the parser's selection products (a parsed master playlist + the
//! selected variant row). Output: the **track set** — one entry per
//! media playlist that will actually be downloaded:
//!
//! * the selected variant's own playlist — [`TrackRole::Required`];
//! * the independent audio rendition of the variant's AUDIO group
//! (when it carries its own URI) — [`TrackRole::Required`]
//! ("selected means required": a selected track failing fails the set);
//! * subtitle renditions of the variant's SUBTITLES group when
//! `--media-subtitles=sidecar` — [`TrackRole::Sidecar`]:
//! explicitly-attached side tracks degrade to completion + warning
//! on failure (never selected-by-default content).
//!
//! Unselected variant/rendition rows are **not downloaded** (the
//! grading rule: unselected backup tracks are not downloaded).
//!
//! Audio language policy (inherited per the media spec's checklist):
//! RFC 5646
//! prefix match on the requested tag → `DEFAULT=YES` → `en` →
//! declaration order (the spec names "highest bandwidth" as the final
//! tier — EXT-X-MEDIA rows carry no BANDWIDTH attribute, so the tier
//! is vacuous at the HLS face and declaration order is the
//! deterministic tiebreak; documented ruling).
//!
//! Cross-track concurrency off by default (the N_m3u8DL-RE `-mt` contrast):
//! the track-set driver runs tracks **sequentially**; parallelism
//! lives inside a track (segment concurrency).

use crate::m3u8::{MasterPlaylist, MediaTrack, TrackType};
use crate::options::{DEFAULT_SEGMENT_CONCURRENCY, SubtitleMode};

/// Track kind (the `media_track.kind` column domain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackKind {
    /// The selected variant's presentation (video or A/V).
    Video,
    /// An independent audio rendition playlist.
    Audio,
    /// A subtitle rendition playlist (sidecar).
    Subtitle,
}

impl TrackKind {
    /// Column text (`media_track.kind`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Subtitle => "subtitle",
        }
    }
}

/// Track necessity grading (the media spec's track line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackRole {
    /// Selected content: failure fails the track set (task error).
    Required,
    /// Explicitly attached side track: failure degrades the set to
    /// completion + warning event (the warning emission face is the
    /// session's; this module records the degraded track state).
    Sidecar,
}

/// One planned track (one media playlist to download, one archive).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedTrack {
    /// 0-based track ordinal (the `media_track.track_idx` key).
    pub track_idx: usize,
    /// Short label used in staging names (`v`, `a`, `s0`, …).
    pub label: String,
    /// Kind (video/audio/subtitle).
    pub kind: TrackKind,
    /// Necessity role.
    pub role: TrackRole,
    /// The rendition playlist URI (verbatim from the master).
    pub playlist_uri: String,
    /// EXT-X-MEDIA LANGUAGE when declared (subtitle sidecar product
    /// naming `<out>.<lang>.vtt`; recorded now).
    pub language: Option<String>,
}

/// Track-set planning configuration (the wired flag faces; defaults
/// per the product spec).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackSetConfig {
    /// `--media-audio-lang` (normalized lowercase RFC 5646 tag;
    /// `None` = the policy chain runs without the language tier).
    pub audio_lang: Option<String>,
    /// `--media-subtitles` (`sidecar` default).
    pub subtitles: SubtitleMode,
    /// `--media-segment-concurrency` (default 8, domain 1..=64).
    pub segment_concurrency: u32,
}

impl Default for TrackSetConfig {
    fn default() -> Self {
        Self {
            audio_lang: None,
            subtitles: SubtitleMode::default(),
            segment_concurrency: DEFAULT_SEGMENT_CONCURRENCY,
        }
    }
}

/// Resolve the track set from the master playlist + selected variant
/// (pure; URI resolution against the manifest base URL is the
/// caller's transport concern — URIs stay verbatim here).
pub fn plan_track_set(
    master: &MasterPlaylist,
    variant_uri: &str,
    cfg: &TrackSetConfig,
) -> Vec<PlannedTrack> {
    let mut tracks = Vec::new();
    // Track 0: the selected variant (required).
    let selected = master.variants.iter().find(|v| v.uri == variant_uri);
    tracks.push(PlannedTrack {
        track_idx: 0,
        label: "v".to_string(),
        kind: TrackKind::Video,
        role: TrackRole::Required,
        playlist_uri: variant_uri.to_string(),
        language: None,
    });
    let Some(variant) = selected else {
        // The caller passes a URI that came from this master; a miss
        // means an assembly bug — return the video track alone rather
        // than guessing (the audio/subtitle rows key off the variant
        // row's group references, absent here).
        return tracks;
    };
    let mut idx = 1usize;
    // Independent audio: the variant's AUDIO group rendition with its
    // own URI (required — selected by policy).
    if let Some(group) = variant.audio_group.as_deref()
        && let Some(audio) =
            select_audio_track(&master.tracks, Some(group), cfg.audio_lang.as_deref())
    {
        tracks.push(PlannedTrack {
            track_idx: idx,
            label: "a".to_string(),
            kind: TrackKind::Audio,
            role: TrackRole::Required,
            playlist_uri: audio.uri.clone().unwrap_or_default(),
            language: audio.language.clone(),
        });
        idx += 1;
    }
    // Subtitle sidecars: the variant's SUBTITLES group renditions
    // (sidecar role; `none` skips them all).
    if cfg.subtitles == SubtitleMode::Sidecar
        && let Some(group) = variant.subtitles_group.as_deref()
    {
        let mut sub = 0usize;
        for track in &master.tracks {
            if track.track_type != TrackType::Subtitles
                || track.group_id.as_deref() != Some(group)
                || track.uri.is_none()
            {
                continue;
            }
            tracks.push(PlannedTrack {
                track_idx: idx,
                label: format!("s{sub}"),
                kind: TrackKind::Subtitle,
                role: TrackRole::Sidecar,
                playlist_uri: track.uri.clone().unwrap_or_default(),
                language: track.language.clone(),
            });
            idx += 1;
            sub += 1;
        }
    }
    tracks
}

/// Audio selection policy (the product spec's chain): RFC 5646 prefix match
/// → `DEFAULT=YES` → `en` → declaration order. Candidates = TYPE=AUDIO
/// renditions with a URI, restricted to `group` when given.
pub fn select_audio_track<'a>(
    tracks: &'a [MediaTrack],
    group: Option<&str>,
    lang: Option<&str>,
) -> Option<&'a MediaTrack> {
    let candidates: Vec<&MediaTrack> = tracks
        .iter()
        .filter(|t| {
            t.track_type == TrackType::Audio
                && t.uri.is_some()
                && group.is_none_or(|g| t.group_id.as_deref() == Some(g))
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    // Tier 1: requested language prefix (case-insensitive; "en"
    // matches "en-US"; "zh-hans" matches "zh-Hans-CN").
    if let Some(want) = lang {
        let want = want.to_ascii_lowercase();
        if let Some(hit) = candidates.iter().find(|t| {
            t.language
                .as_deref()
                .is_some_and(|l| l.to_ascii_lowercase().starts_with(&want))
        }) {
            return Some(hit);
        }
    }
    // Tier 2: DEFAULT=YES.
    if let Some(hit) = candidates.iter().find(|t| t.default_track) {
        return Some(hit);
    }
    // Tier 3: English.
    if let Some(hit) = candidates.iter().find(|t| {
        t.language
            .as_deref()
            .is_some_and(|l| l.to_ascii_lowercase().starts_with("en"))
    }) {
        return Some(hit);
    }
    // Tier 4: declaration order (the "highest bandwidth" tier is
    // vacuous — EXT-X-MEDIA rows carry no BANDWIDTH).
    candidates.first().copied()
}

/// A track's terminal state after its download attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrackState {
    /// Every segment delivered; archive consistent.
    Done,
    /// Sidecar track failed: the set completes degraded (warning
    /// recorded; the payload is the redacted failure text).
    Degraded(String),
    /// Required track failed (or a staging-level failure): the set
    /// fails. The payload is the redacted failure text (an error-code
    /// face for segment-fetch failures is pending a
    /// future error-code annotation).
    Failed(String),
}

/// Track-set convergence verdict (the convergence decision function).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrackSetVerdict {
    /// All required tracks done; sidecars done or degraded (the
    /// degraded labels + warning payloads ride along — the emission
    /// face is the session's).
    Complete {
        /// `(label, warning)` per degraded sidecar.
        degraded: Vec<(String, String)>,
    },
    /// A required track failed; the set fails (first failure by
    /// track ordinal wins — tracks run sequentially, so ordinal and
    /// time order agree).
    Failed {
        /// The failing track's label.
        required: String,
        /// Redacted failure text.
        error: String,
    },
}

/// Track-set convergence (pure): required failed → `Failed`; else
/// `Complete` with the degraded sidecar list. A `Failed` state on a
/// **sidecar** is the degraded form (explicit attached side-track
/// failure = degraded completion + warning) — mapped here too so no
/// terminal state can vanish from the verdict regardless of how the
/// caller graded it. An empty input is
/// `Complete` vacuously (the driver always plans at least the video
/// track).
pub fn track_set_verdict(results: &[(PlannedTrack, TrackState)]) -> TrackSetVerdict {
    for (track, state) in results {
        if track.role == TrackRole::Required && matches!(state, TrackState::Failed(_)) {
            if let TrackState::Failed(err) = state {
                return TrackSetVerdict::Failed {
                    required: track.label.clone(),
                    error: err.clone(),
                };
            }
        }
    }
    let degraded = results
        .iter()
        .filter_map(|(track, state)| match state {
            TrackState::Degraded(w) => Some((track.label.clone(), w.clone())),
            // Defense at the convergence point: a sidecar's terminal
            // failure degrades the set (with the failure text as the
            // warning), never disappears.
            TrackState::Failed(w) if track.role != TrackRole::Required => {
                Some((track.label.clone(), w.clone()))
            }
            _ => None,
        })
        .collect();
    TrackSetVerdict::Complete { degraded }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m3u8::{VariantPolicy, parse_manifest, select_variant};

    fn master(text: &str) -> MasterPlaylist {
        match parse_manifest(text.as_bytes()).unwrap_or_else(|e| panic!("parse: {e}")) {
            crate::m3u8::Playlist::Master(m) => m,
            other => panic!("expected master, got {other:?}"),
        }
    }

    const MASTER: &str = "#EXTM3U\n\
        #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"fr\",NAME=\"Français\",DEFAULT=YES,URI=\"audio/fr.m3u8\"\n\
        #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en-US\",NAME=\"English\",DEFAULT=NO,URI=\"audio/en.m3u8\"\n\
        #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"de\",NAME=\"Deutsch\",DEFAULT=NO\n\
        #EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"sub\",LANGUAGE=\"en\",NAME=\"EN\",URI=\"sub/en.m3u8\"\n\
        #EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"sub\",LANGUAGE=\"fr\",NAME=\"FR\",DEFAULT=YES,URI=\"sub/fr.m3u8\"\n\
        #EXT-X-MEDIA:TYPE=CLOSED-CAPTIONS,GROUP-ID=\"cc\",LANGUAGE=\"en\",NAME=\"CC\"\n\
        #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=1280x720,AUDIO=\"aud\",SUBTITLES=\"sub\"\n\
        v720.m3u8\n\
        #EXT-X-STREAM-INF:BANDWIDTH=500000,RESOLUTION=640x360,AUDIO=\"aud\"\n\
        v360.m3u8\n";

    #[test]
    fn audio_language_policy_chain() {
        let m = master(MASTER);
        // Tier 1: requested language prefix (fr requested, fr row).
        let fr = select_audio_track(&m.tracks, Some("aud"), Some("fr"))
            .unwrap_or_else(|| panic!("fr hit"));
        assert_eq!(fr.uri.as_deref(), Some("audio/fr.m3u8"));
        // Prefix: "en" matches "en-US".
        let en = select_audio_track(&m.tracks, Some("aud"), Some("en"))
            .unwrap_or_else(|| panic!("en hit"));
        assert_eq!(en.uri.as_deref(), Some("audio/en.m3u8"));
        // No language requested -> DEFAULT=YES (fr row).
        let def = select_audio_track(&m.tracks, Some("aud"), None)
            .unwrap_or_else(|| panic!("default hit"));
        assert_eq!(def.uri.as_deref(), Some("audio/fr.m3u8"));
        // Unknown language falls to DEFAULT tier, not to failure.
        let ja = select_audio_track(&m.tracks, Some("aud"), Some("ja"))
            .unwrap_or_else(|| panic!("fallback hit"));
        assert_eq!(ja.uri.as_deref(), Some("audio/fr.m3u8"));
        // URI-less rows never win (de row has no URI): remove fr+en
        // and the group yields nothing.
        let only_uriless: Vec<MediaTrack> = m
            .tracks
            .iter()
            .filter(|t| t.track_type == TrackType::Audio && t.uri.is_none())
            .cloned()
            .collect();
        assert!(select_audio_track(&only_uriless, Some("aud"), None).is_none());
    }

    #[test]
    fn en_tier_beats_declaration_when_no_default() {
        // DEFAULT absent everywhere: tier 3 (en) wins over the first
        // declared row (fr).
        let text = "#EXTM3U\n\
            #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",LANGUAGE=\"fr\",NAME=\"F\",URI=\"f.m3u8\"\n\
            #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",LANGUAGE=\"en\",NAME=\"E\",URI=\"e.m3u8\"\n\
            #EXT-X-STREAM-INF:BANDWIDTH=1,AUDIO=\"a\"\nv.m3u8\n";
        let m = master(text);
        let hit =
            select_audio_track(&m.tracks, Some("a"), None).unwrap_or_else(|| panic!("en tier hit"));
        assert_eq!(hit.uri.as_deref(), Some("e.m3u8"));
    }

    #[test]
    fn plan_grades_roles_and_skips_unselected() {
        let m = master(MASTER);
        let variant =
            select_variant(&m, &VariantPolicy::Highest).unwrap_or_else(|e| panic!("variant: {e}"));
        let cfg = TrackSetConfig::default();
        let tracks = plan_track_set(&m, &variant.uri, &cfg);
        assert_eq!(tracks.len(), 4, "v + audio + 2 subtitles");
        assert_eq!(tracks[0].label, "v");
        assert_eq!(tracks[0].role, TrackRole::Required);
        assert_eq!(tracks[1].label, "a");
        assert_eq!(
            tracks[1].role,
            TrackRole::Required,
            "independent audio track = required"
        );
        assert_eq!(tracks[1].playlist_uri, "audio/fr.m3u8");
        assert_eq!(tracks[2].label, "s0");
        assert_eq!(
            tracks[2].role,
            TrackRole::Sidecar,
            "subtitle sidecar = side track"
        );
        assert_eq!(tracks[3].label, "s1");
        // The unselected variant (v360) appears nowhere.
        assert!(tracks.iter().all(|t| t.playlist_uri != "v360.m3u8"));
        // Subtitles off: only v + a.
        let cfg_none = TrackSetConfig {
            subtitles: SubtitleMode::None,
            ..cfg.clone()
        };
        let tracks = plan_track_set(&m, &variant.uri, &cfg_none);
        assert_eq!(tracks.len(), 2);
        // Language steering changes the audio row.
        let cfg_ja = TrackSetConfig {
            audio_lang: Some("en".into()),
            ..cfg
        };
        let tracks = plan_track_set(&m, &variant.uri, &cfg_ja);
        assert_eq!(tracks[1].playlist_uri, "audio/en.m3u8");
    }

    fn planned(label: &str, role: TrackRole) -> (PlannedTrack, ()) {
        (
            PlannedTrack {
                track_idx: 0,
                label: label.to_string(),
                kind: if role == TrackRole::Required {
                    TrackKind::Video
                } else {
                    TrackKind::Subtitle
                },
                role,
                playlist_uri: format!("{label}.m3u8"),
                language: None,
            },
            (),
        )
    }

    #[test]
    fn convergence_positive_and_negative() {
        let (v, _) = planned("v", TrackRole::Required);
        let (a, _) = planned("a", TrackRole::Required);
        let (s0, _) = planned("s0", TrackRole::Sidecar);
        // All done.
        let set = vec![
            (v.clone(), TrackState::Done),
            (a.clone(), TrackState::Done),
            (s0.clone(), TrackState::Done),
        ];
        assert_eq!(
            track_set_verdict(&set),
            TrackSetVerdict::Complete { degraded: vec![] }
        );
        // Sidecar degraded -> Complete + degraded ledger.
        let set = vec![
            (v.clone(), TrackState::Done),
            (a.clone(), TrackState::Done),
            (s0.clone(), TrackState::Degraded("HTTP 500".into())),
        ];
        match track_set_verdict(&set) {
            TrackSetVerdict::Complete { degraded } => {
                assert_eq!(degraded, vec![("s0".to_string(), "HTTP 500".to_string())]);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        // Required failed -> Failed (even with everything else done).
        let set = vec![
            (v.clone(), TrackState::Done),
            (a.clone(), TrackState::Failed("HTTP 404".into())),
            (s0, TrackState::Done),
        ];
        assert_eq!(
            track_set_verdict(&set),
            TrackSetVerdict::Failed {
                required: "a".to_string(),
                error: "HTTP 404".to_string()
            }
        );
        // First required failure wins.
        let set = vec![
            (v, TrackState::Failed("x".into())),
            (a, TrackState::Failed("y".into())),
        ];
        match track_set_verdict(&set) {
            TrackSetVerdict::Failed { required, error } => {
                assert_eq!(required, "v");
                assert_eq!(error, "x");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    /// A `Failed` state on a sidecar degrades the set (with the
    /// failure text as the warning) — a terminal state can never
    /// vanish from the verdict regardless of how the caller graded it.
    #[test]
    fn sidecar_failed_state_degrades_never_vanishes() {
        let (v, _) = planned("v", TrackRole::Required);
        let (s0, _) = planned("s0", TrackRole::Sidecar);
        let set = vec![
            (v, TrackState::Done),
            (s0, TrackState::Failed("staging quota exceeded".into())),
        ];
        match track_set_verdict(&set) {
            TrackSetVerdict::Complete { degraded } => {
                assert_eq!(
                    degraded,
                    vec![("s0".to_string(), "staging quota exceeded".to_string())],
                    "sidecar Failed -> degraded with the failure text as warning"
                );
            }
            other => panic!("expected degraded Complete, got {other:?}"),
        }
    }
}

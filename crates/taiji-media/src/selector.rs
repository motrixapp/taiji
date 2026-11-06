//! The three-layer media selector (per the media spec's selection
//! face; it resolves over DASH trees too): the `taiji.addMedia`
//! options' selection entry — the RPC face of the download line's
//! attached-side-track semantics.
//!
//! Layers (exactly one layer per selector expression):
//! 1. **presets** — `best` / `best-combined` / `audio-only`;
//! 2. **predicate subset** — `res<=1080`, `codec!=h264`, `lang=en`,
//! `ext=mp4` (space/comma-joined; every predicate must hold);
//! 3. **escape hatch** — `format_id=v0,a1` (multi-value = an
//! **explicit multi-stream** download: the first id picks the
//! primary variant, the rest are attached side tracks, the
//! necessity grading applies).
//!
//! Resolution output ([`Selection`]): the primary variant URI + the
//! explicit attached renditions (audio/subtitle URIs) + the
//! resolved-language hint for the track-set planner's chain. Pure —
//! the planner and download live in their own modules.
//!
//! # Source domains (dual-source end-to-end)
//!
//! [`resolve_selection`] is source-agnostic: the same expression
//! space resolves over an `hls`-kind tree (format ids = the master
//! ordinals `v0`/`a0`/`s0`) and a `dash`-kind tree (format ids = the
//! **DASH Representation `@id`s** verbatim — the escape hatch's DASH
//! address domain; a rep id containing a comma or space cannot be
//! addressed by the multi-value syntax, a documented limit). The
//! media spec's default sort stays the 0.3 approximation documented on
//! [`resolve_selection`] (within one source the protocol / stream-split
//! tiers are degenerate — every node shares the protocol and the
//! video/audio split; the rich mixed-tree tiers unlock with the 0.5
//! bridge).

use crate::error::MediaError;
use crate::format::FormatTree;

/// The parsed selector.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MediaSelector {
    /// The raw expression (the selector snapshot persisted with the
    /// task; `None`/empty = the `best` default).
    pub raw: Option<String>,
    /// The concrete layer.
    pub layer: SelectorLayer,
}

/// The selector's concrete layer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SelectorLayer {
    /// `best` (the default): highest-bandwidth video variant + the
    /// language-policy audio chain.
    #[default]
    Best,
    /// `best-combined`: highest-bandwidth variant that itself carries
    /// audio (no separate audio track).
    BestCombined,
    /// `audio-only`: an audio rendition (the language-policy pick).
    AudioOnly,
    /// The predicate subset (every predicate must hold).
    Predicates(Vec<Predicate>),
    /// The `format_id=` escape hatch; multi-value = explicit
    /// multi-stream.
    FormatIds(Vec<String>),
}

/// One predicate-subset clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    /// `res<=H`: the variant's height must be ≤ H.
    ResMax(u32),
    /// `codec!=X`: the variant's codecs must not contain X
    /// (case-insensitive substring).
    CodecNot(String),
    /// `lang=TAG`: the rendition's language matches (RFC 5646 prefix,
    /// case-insensitive).
    Lang(String),
    /// `ext=EXT`: the container extension equals EXT.
    Ext(String),
}

impl Predicate {
    fn as_str(&self) -> String {
        match self {
            Predicate::ResMax(h) => format!("res<={h}"),
            Predicate::CodecNot(c) => format!("codec!={c}"),
            Predicate::Lang(l) => format!("lang={l}"),
            Predicate::Ext(e) => format!("ext={e}"),
        }
    }
}

/// Parse a selector expression (empty/None = the `best` default).
/// Mixed layers are an explicit error (one layer per expression — a
/// preset cannot be conjuncted with predicates; the escape hatch
/// names renditions directly).
pub fn parse_selector(raw: Option<&str>) -> Result<MediaSelector, MediaError> {
    let Some(text) = raw.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(MediaSelector {
            raw: None,
            layer: SelectorLayer::Best,
        });
    };
    let invalid = |what: &str| {
        MediaError::OptionInvalid(format!("--media-selector {text:?}: expected {what}"))
    };
    if let Some(ids) = text.strip_prefix("format_id=") {
        let ids: Vec<String> = ids
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if ids.is_empty() || ids.iter().any(|i| i.contains('=')) {
            return Err(invalid("format_id=<id>[,<id>] (bare rendition ids)"));
        }
        return Ok(MediaSelector {
            raw: Some(text.to_string()),
            layer: SelectorLayer::FormatIds(ids),
        });
    }
    match text {
        "best" => {
            return Ok(MediaSelector {
                raw: Some(text.to_string()),
                layer: SelectorLayer::Best,
            });
        }
        "best-combined" => {
            return Ok(MediaSelector {
                raw: Some(text.to_string()),
                layer: SelectorLayer::BestCombined,
            });
        }
        "audio-only" => {
            return Ok(MediaSelector {
                raw: Some(text.to_string()),
                layer: SelectorLayer::AudioOnly,
            });
        }
        _ => {}
    }
    // Predicate subset: space/comma-joined clauses.
    let mut predicates = Vec::new();
    for clause in text
        .split([',', ' '])
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        let pred = if let Some(v) = clause.strip_prefix("res<=") {
            let h = v
                .parse::<u32>()
                .map_err(|_| invalid("res<=<height> with an integer height"))?;
            Predicate::ResMax(h)
        } else if let Some(v) = clause.strip_prefix("codec!=") {
            if v.is_empty() {
                return Err(invalid("codec!=<codec> with a codec name"));
            }
            Predicate::CodecNot(v.to_ascii_lowercase())
        } else if let Some(v) = clause.strip_prefix("lang=") {
            if v.is_empty() {
                return Err(invalid("lang=<tag> with an RFC 5646 tag"));
            }
            Predicate::Lang(v.to_ascii_lowercase())
        } else if let Some(v) = clause.strip_prefix("ext=") {
            if v.is_empty() {
                return Err(invalid("ext=<ext> with a container extension"));
            }
            Predicate::Ext(v.to_ascii_lowercase())
        } else {
            return Err(invalid(
                "best|best-combined|audio-only | predicates res<=/codec!=/lang=/ext= | \
                 format_id=<ids>",
            ));
        };
        predicates.push(pred);
    }
    if predicates.is_empty() {
        return Err(invalid("at least one predicate clause"));
    }
    Ok(MediaSelector {
        raw: Some(text.to_string()),
        layer: SelectorLayer::Predicates(predicates),
    })
}

/// The selector's resolution product.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selection {
    /// The primary variant's playlist URI (empty for `audio-only`).
    pub primary_uri: String,
    /// Explicitly attached side renditions (audio first, subtitles
    /// after — the multi-stream escape hatch; empty otherwise).
    pub attached_uris: Vec<String>,
    /// The resolved audio language (a `lang=` predicate or a
    /// format_id-pointed audio rendition; feeds the planner's chain).
    pub audio_lang: Option<String>,
    /// `true` when the primary is an audio-only form.
    pub audio_only: bool,
    /// The chosen format ids (diagnostics / media sub-dict).
    pub chosen_ids: Vec<String>,
}

fn height_of(res: &str) -> u32 {
    res.split('x')
        .nth(1)
        .and_then(|h| h.parse().ok())
        .unwrap_or(0)
}

/// Does one node satisfy every predicate?
fn satisfies(node: &crate::format::FormatNode, preds: &[Predicate]) -> bool {
    preds.iter().all(|p| match p {
        Predicate::ResMax(h) => height_of(&node.resolution) <= *h,
        Predicate::CodecNot(c) => {
            let hay = format!("{}/{}", node.vcodec, node.acodec).to_ascii_lowercase();
            !hay.contains(c.as_str())
        }
        Predicate::Lang(l) => node.language.to_ascii_lowercase().starts_with(l.as_str()),
        Predicate::Ext(e) => node.ext.eq_ignore_ascii_case(e),
    })
}

/// Resolve the selector against a format tree (the media spec's default sort
/// for the
/// preset/predicate layers: protocol > stream-split > resolution > fps > hdr
/// > codec > bitrate — the 0.3 HLS approximation: video-bearing first,
/// > then resolution, then fps, then bandwidth).
pub fn resolve_selection(tree: &FormatTree, sel: &MediaSelector) -> Result<Selection, MediaError> {
    let find = |id: &str| tree.formats.iter().find(|f| f.format_id == id);
    let invalid = |msg: String| MediaError::VariantPolicy(msg);
    match &sel.layer {
        SelectorLayer::Best => {
            let best = tree
                .formats
                .iter()
                .filter(|f| f.has_video)
                .max_by_key(|f| (height_of(&f.resolution), f.fps as u64, f.tbr))
                .ok_or_else(|| invalid("no video variant in the format tree".into()))?;
            Ok(Selection {
                primary_uri: best.uri.clone(),
                attached_uris: Vec::new(),
                audio_lang: None,
                audio_only: false,
                chosen_ids: vec![best.format_id.clone()],
            })
        }
        SelectorLayer::BestCombined => {
            let best = tree
                .formats
                .iter()
                .filter(|f| f.has_video && f.has_audio)
                .max_by_key(|f| (height_of(&f.resolution), f.fps as u64, f.tbr))
                .ok_or_else(|| invalid("no combined video+audio variant".into()))?;
            Ok(Selection {
                primary_uri: best.uri.clone(),
                attached_uris: Vec::new(),
                audio_lang: None,
                audio_only: false,
                chosen_ids: vec![best.format_id.clone()],
            })
        }
        SelectorLayer::AudioOnly => {
            // The language-policy pick is the planner's; here take the
            // first audio rendition (policy chain DEFAULT → en →
            // order applies downstream on EXT-X-MEDIA rows).
            let audio = tree
                .formats
                .iter()
                .find(|f| f.has_audio && !f.has_video)
                .ok_or_else(|| invalid("no audio rendition in the format tree".into()))?;
            Ok(Selection {
                primary_uri: audio.uri.clone(),
                attached_uris: Vec::new(),
                audio_lang: (!audio.language.is_empty()).then(|| audio.language.clone()),
                audio_only: true,
                chosen_ids: vec![audio.format_id.clone()],
            })
        }
        SelectorLayer::Predicates(preds) => {
            let best = tree
                .formats
                .iter()
                .filter(|f| f.has_video && satisfies(f, preds))
                .max_by_key(|f| (height_of(&f.resolution), f.fps as u64, f.tbr))
                .ok_or_else(|| {
                    invalid(format!(
                        "no variant satisfies the predicates [{}]",
                        preds
                            .iter()
                            .map(|p| p.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    ))
                })?;
            let lang = preds.iter().find_map(|p| match p {
                Predicate::Lang(l) => Some(l.clone()),
                _ => None,
            });
            Ok(Selection {
                primary_uri: best.uri.clone(),
                attached_uris: Vec::new(),
                audio_lang: lang,
                audio_only: false,
                chosen_ids: vec![best.format_id.clone()],
            })
        }
        SelectorLayer::FormatIds(ids) => {
            // The multi-stream escape hatch (attached side tracks):
            // the first id must be the primary variant; the rest attach
            // as side renditions.
            let mut chosen = Vec::new();
            for id in ids {
                let node = find(id)
                    .ok_or_else(|| invalid(format!("format_id {id:?} not in the format tree")))?;
                chosen.push(node);
            }
            let primary = chosen[0].clone();
            let attached: Vec<String> = chosen[1..].iter().map(|n| n.uri.clone()).collect();
            let audio_lang = chosen[1..]
                .iter()
                .find(|n| n.has_audio && !n.has_video)
                .filter(|n| !n.language.is_empty())
                .map(|n| n.language.clone());
            Ok(Selection {
                primary_uri: primary.uri.clone(),
                attached_uris: attached,
                audio_lang,
                audio_only: primary.has_audio && !primary.has_video,
                chosen_ids: ids.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::FormatNode;

    fn tree() -> FormatTree {
        let f =
            |id: &str, res: &str, br: u64, codec: &str, combined: bool, lang: &str| FormatNode {
                format_id: id.into(),
                protocol: "hls".into(),
                ext: if id.starts_with('s') { "vtt" } else { "mp4" }.into(),
                resolution: res.into(),
                fps: 30.0,
                hdr: "SDR".into(),
                vcodec: if combined {
                    codec.split(',').next().unwrap_or("").into()
                } else {
                    codec.into()
                },
                acodec: if combined {
                    "mp4a.40.2".into()
                } else {
                    String::new()
                },
                tbr: br,
                abr: 0,
                vbr: 0,
                filesize: 0,
                language: lang.into(),
                has_video: !id.starts_with(['a', 's']),
                has_audio: combined || id.starts_with('a'),
                uri: format!("https://x.test/{id}.m3u8"),
            };
        FormatTree {
            url: "https://x.test/master.m3u8".into(),
            kind: "hls".into(),
            formats: vec![
                f("v0", "1920x1080", 5_000_000, "avc1", false, ""),
                f("v1", "1280x720", 2_000_000, "hvc1", true, ""),
                f("a0", "", 128_000, "", false, "en"),
                f("s0", "", 0, "", false, "de"),
            ],
        }
    }

    #[test]
    fn layer_parse_domain() {
        assert_eq!(
            parse_selector(None).unwrap_or_else(|e| panic!("{e}")).layer,
            SelectorLayer::Best
        );
        assert_eq!(
            parse_selector(Some(""))
                .unwrap_or_else(|e| panic!("{e}"))
                .layer,
            SelectorLayer::Best
        );
        assert_eq!(
            parse_selector(Some("best-combined"))
                .unwrap_or_else(|e| panic!("{e}"))
                .layer,
            SelectorLayer::BestCombined
        );
        assert_eq!(
            parse_selector(Some("audio-only"))
                .unwrap_or_else(|e| panic!("{e}"))
                .layer,
            SelectorLayer::AudioOnly
        );
        assert_eq!(
            parse_selector(Some("res<=720 codec!=hvc1"))
                .unwrap_or_else(|e| panic!("{e}"))
                .layer,
            SelectorLayer::Predicates(vec![
                Predicate::ResMax(720),
                Predicate::CodecNot("hvc1".into())
            ])
        );
        assert_eq!(
            parse_selector(Some("format_id=v0,a0"))
                .unwrap_or_else(|e| panic!("{e}"))
                .layer,
            SelectorLayer::FormatIds(vec!["v0".into(), "a0".into()])
        );
        for bad in [
            "best,res<=720",
            "format_id=",
            "res<=abc",
            "codec!=",
            "lang=",
            "ext=",
            "res<=720,wat=1",
            "format_id=v0,res<=720",
        ] {
            assert!(
                parse_selector(Some(bad)).is_err(),
                "{bad:?} must be rejected (single layer, strict clauses)"
            );
        }
    }

    #[test]
    fn resolution_layers() {
        let t = tree();
        // best = highest resolution variant (v0), separate audio chain
        // left to the planner.
        let s = resolve_selection(&t, &parse_selector(None).unwrap_or_else(|e| panic!("{e}")))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.primary_uri, "https://x.test/v0.m3u8");
        assert!(s.attached_uris.is_empty());
        // best-combined picks the variant carrying its own audio.
        let s = resolve_selection(
            &t,
            &parse_selector(Some("best-combined")).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.primary_uri, "https://x.test/v1.m3u8");
        // audio-only picks the audio rendition.
        let s = resolve_selection(
            &t,
            &parse_selector(Some("audio-only")).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(s.audio_only);
        assert_eq!(s.primary_uri, "https://x.test/a0.m3u8");
        // Predicates: res<=720 + codec!=hvc1 → no variant survives.
        let sel = parse_selector(Some("res<=720 codec!=hvc1")).unwrap_or_else(|e| panic!("{e}"));
        let err = resolve_selection(&t, &sel)
            .err()
            .unwrap_or_else(|| panic!("the predicates must leave no candidate"));
        assert!(err.to_string().contains("no variant satisfies"));
        // res<=1080 codec!=hvc1 → v0.
        let sel = parse_selector(Some("res<=1080 codec!=hvc1")).unwrap_or_else(|e| panic!("{e}"));
        let s = resolve_selection(&t, &sel).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.primary_uri, "https://x.test/v0.m3u8");
        // lang predicate over renditions: lang=de has no video variant
        // → error; ext=vtt likewise (no video-bearing vtt node).
        assert!(
            resolve_selection(
                &t,
                &parse_selector(Some("lang=de")).unwrap_or_else(|e| panic!("{e}"))
            )
            .is_err()
        );
    }

    /// The escape hatch: multi-value = explicit multi-stream (the
    /// first id is primary, the rest attach as side tracks).
    #[test]
    fn escape_hatch_multi_stream() {
        let t = tree();
        let sel = parse_selector(Some("format_id=v1,a0,s0")).unwrap_or_else(|e| panic!("{e}"));
        let s = resolve_selection(&t, &sel).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.primary_uri, "https://x.test/v1.m3u8");
        assert_eq!(
            s.attached_uris,
            vec![
                "https://x.test/a0.m3u8".to_string(),
                "https://x.test/s0.m3u8".to_string()
            ]
        );
        assert_eq!(s.audio_lang.as_deref(), Some("en"));
        assert_eq!(s.chosen_ids, vec!["v1", "a0", "s0"]);
        // Unknown id = an explicit error.
        let sel = parse_selector(Some("format_id=v9")).unwrap_or_else(|e| panic!("{e}"));
        assert!(resolve_selection(&t, &sel).is_err());
    }

    /// Dual-source equivalence: the same expression space resolves over a
    /// `dash`-kind tree — format ids are the DASH Representation
    /// `@id`s; presets/predicates/escape behave exactly as over HLS
    /// (the regression of record: before dual-source support the core
    /// face refused every
    /// genuine expression on a DASH entry with `variant_policy`).
    #[test]
    fn dash_tree_resolution_equivalent() {
        let f = |id: &str, res: &str, br: u64, codec: &str, lang: &str, ext: &str| FormatNode {
            format_id: id.into(),
            protocol: "dash".into(),
            ext: ext.into(),
            resolution: res.into(),
            fps: 30.0,
            hdr: String::new(),
            vcodec: codec.into(),
            acodec: String::new(),
            tbr: br,
            abr: 0,
            vbr: 0,
            filesize: 0,
            language: lang.into(),
            has_video: id.starts_with("video"),
            has_audio: id.starts_with("audio"),
            uri: format!("https://cdn.test/rep/{id}"),
        };
        let t = FormatTree {
            url: "https://cdn.test/v.mpd".into(),
            kind: "dash".into(),
            formats: vec![
                f("video-2160p", "3840x2160", 4_000_000, "hvc1", "", "mp4"),
                f("video-360p", "640x360", 400_000, "avc1", "", "mp4"),
                f("audio-en", "", 96_000, "mp4a", "en", "mp4"),
                f("audio-fr", "", 64_000, "mp4a", "fr", "mp4"),
            ],
        };
        // best = the highest (resolution, fps, tbr) video rung.
        let s = resolve_selection(&t, &parse_selector(None).unwrap_or_else(|e| panic!("{e}")))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.chosen_ids, vec!["video-2160p".to_string()]);
        assert_eq!(s.primary_uri, "https://cdn.test/rep/video-2160p");
        // audio-only = the first audio rendition (the planner's chain
        // refines downstream).
        let s = resolve_selection(
            &t,
            &parse_selector(Some("audio-only")).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.chosen_ids, vec!["audio-en".to_string()]);
        // The predicate cluster over DASH facts.
        let s = resolve_selection(
            &t,
            &parse_selector(Some("res<=720 codec!=hvc1")).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.chosen_ids, vec!["video-360p".to_string()]);
        let sel = parse_selector(Some("lang=fr")).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            resolve_selection(&t, &sel).is_err(),
            "no video-bearing node carries lang=fr — the HLS-equivalent refusal"
        );
        let s = resolve_selection(
            &t,
            &parse_selector(Some("ext=mp4 res<=720")).unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.chosen_ids, vec!["video-360p".to_string()]);
        // The escape hatch over Representation ids, multi-value = the
        // explicit multi-stream (video rung + the French audio rep).
        let s = resolve_selection(
            &t,
            &parse_selector(Some("format_id=video-360p,audio-fr"))
                .unwrap_or_else(|e| panic!("{e}")),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            s.chosen_ids,
            vec!["video-360p".to_string(), "audio-fr".to_string()]
        );
        assert_eq!(
            s.attached_uris,
            vec!["https://cdn.test/rep/audio-fr".to_string()]
        );
        assert_eq!(s.audio_lang.as_deref(), Some("fr"));
        // Unknown rep id = the explicit refusal.
        let sel = parse_selector(Some("format_id=nope")).unwrap_or_else(|e| panic!("{e}"));
        assert!(resolve_selection(&t, &sel).is_err());
    }
}

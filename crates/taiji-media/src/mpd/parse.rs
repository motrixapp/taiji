//! MPD streaming parser (quick-xml 0.42, the workspace
//! registry row — DTD/entities disabled, `check_end_names` on).
//!
//! Pure function `bytes → structure | error`, the m3u8 posture
//! (platform-independent, no I/O, no fetch inside the parse).
//! **Namespace handling = local-name matching** (documented ruling):
//! DASH documents in the wild bind the MPD namespace as the default
//! namespace, under a prefix, or — in broken-but-playable exports —
//! under none; the vocabulary this parser consumes (`MPD/Period/
//! AdaptationSet/Representation/BaseURL/SegmentTemplate/
//! SegmentTimeline/S/SegmentList/Initialization/SegmentURL/
//! SegmentBase/ContentProtection/ProgramInformation/Title/
//! SupplementalProperty/EssentialProperty`) is unambiguous across
//! those spellings, so the prefix is ignored.
//!
//! Known-element narrowing: `ProgramInformation`
//! (its `Title` text child consumed; `Source`/`Copyright` stay
//! ignored) and the `SupplementalProperty`/`EssentialProperty`
//! descriptor pair are consumed **at the MPD level only** — at any
//! other placement they remain the ignored unknown (the zero-regression
//! verdict-semantics red line: narrowing the ignore face must never mint a new
//! error for a previously-ignored shape).
//!
//! Refusals wired here (the media spec's verdict-table rows):
//! * `@type="dynamic"` → `live_unsupported` (0.3 row; 0.4 owns
//! the sliding window);
//! * `<ContentProtection>` — **any level, any scheme** →
//! `drm_unsupported` (never supported; the 0.3 DASH
//! key/decrypt consumption face is this refusal);
//! * body over 16MiB → `manifest_too_large` (defense in depth — the
//! fetch face already caps; a direct library call cannot bypass);
//! * a `<SegmentList>` over 100 000 `<SegmentURL>` rows →
//! `manifest_too_large` (a single list past the cap can never
//! produce an in-cap task; the cross-period task-level cap is
//! [`super::expand`]'s);
//! * every other malformed shape → `manifest_parse` (bad XML, a
//! DOCTYPE present, no root `MPD`, no `<Period>`, a period with no
//! `<AdaptationSet>`, unparseable numbers/durations/ranges, a
//! wrongly-placed known element…).
//!
//! Unknown elements and unknown attributes are **ignored** (verdict
//! table "unknown manifest tags ignored" — forward compatibility), **whole subtrees
//! included**: an unknown container's children never re-enter the
//! known vocabulary (a `<Role>` containing `<SegmentURL>`-shaped
//! text stays ignored).
//!
//! SegmentTemplate inheritance (documented ruling, ISO 23009-1
//! §5.3.9.1.4 "supplemented"): attributes inherit **per attribute,
//! child level wins** across Period → AdaptationSet → Representation
//! (the set-level template supplying `@media`/`@initialization` with
//! `$Bandwidth$` while the representation overrides only `@duration`
//! is the canonical shape). SegmentList does **not** merge (a child
//! element replaces the parent wholesale — the spec defines no
//! per-attribute inheritance for the list form and real manifests do
//! not rely on one).

use quick_xml::Reader;
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event};

use crate::error::MediaError;
use crate::m3u8::MAX_MANIFEST_BYTES;

use super::model::{
    AdaptationSet, InitRef, Mpd, MpdDescriptor, MpdType, Period, Representation, SegmentBase,
    SegmentList, SegmentTemplate, SegmentTimelineEntry, SegmentUrl,
};

/// Parse-time single-list segment bound (the media spec's
/// ≤100k segments/task line — the m3u8 face's constant, applied to one
/// explicit list here; the task-level cross-period cap is the
/// expansion's).
pub const MAX_LIST_SEGMENTS: usize = crate::m3u8::MAX_MEDIA_SEGMENTS;

/// Parse MPD bytes (static VOD subset). See the module docs for the
/// refusal vocabulary.
pub fn parse_mpd(input: &[u8]) -> Result<Mpd, MediaError> {
    if input.len() > MAX_MANIFEST_BYTES {
        return Err(MediaError::ManifestTooLarge(format!(
            "MPD body {} bytes over the {} byte cap",
            input.len(),
            MAX_MANIFEST_BYTES
        )));
    }
    let mut reader = Reader::from_reader(input);
    reader.config_mut().check_end_names = true;
    let mut buf = Vec::with_capacity(4096);

    let mut doc = Mpd {
        mpd_type: MpdType::Static,
        ..Mpd::default()
    };
    let mut stack: Vec<Frame> = Vec::new();
    let mut saw_root = false;
    let mut base_target: Option<BaseTarget> = None;
    let mut base_text = String::new();
    // The open `<Title>` accumulator (C14: ProgramInformation's text
    // child; consumed at its close).
    let mut title_open = false;
    let mut title_text = String::new();
    // Depth inside an unknown element (the whole subtree is ignored).
    let mut skip_depth = 0usize;

    loop {
        let event = reader
            .read_event_into(&mut buf)
            .map_err(|e| MediaError::ManifestParse(format!("XML: {e}")))?;
        match event {
            Event::Start(e) => {
                if skip_depth > 0 {
                    skip_depth += 1;
                    continue;
                }
                let name = local_name(e.name().as_ref()).to_string();
                open_element(
                    &mut doc,
                    &mut stack,
                    &mut saw_root,
                    &mut base_target,
                    &mut base_text,
                    &mut skip_depth,
                    &mut title_open,
                    &mut title_text,
                    &name,
                    &e,
                )?;
            }
            Event::Empty(e) => {
                if skip_depth > 0 {
                    continue;
                }
                let name = local_name(e.name().as_ref()).to_string();
                // An empty element opens and closes at once (expat
                // semantics; the metalink parser's precedent). Only
                // frame-pushing elements need the close half.
                let pushed = open_element(
                    &mut doc,
                    &mut stack,
                    &mut saw_root,
                    &mut base_target,
                    &mut base_text,
                    &mut skip_depth,
                    &mut title_open,
                    &mut title_text,
                    &name,
                    &e,
                )?;
                if skip_depth == 1 {
                    // Self-closing unknown element: no children ever
                    // arrive — the skip window closes here.
                    skip_depth = 0;
                }
                if name == "BaseURL"
                    && let Some(target) = base_target.take()
                {
                    apply_base_url(&mut doc, &target, std::mem::take(&mut base_text))?;
                }
                if name == "Title" && title_open {
                    close_title(&mut doc, std::mem::take(&mut title_text));
                    title_open = false;
                }
                if pushed {
                    close_element(&mut stack, &name)?;
                }
            }
            Event::End(e) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                    continue;
                }
                let name = local_name(e.name().as_ref()).to_string();
                if name == "BaseURL"
                    && let Some(target) = base_target.take()
                {
                    apply_base_url(&mut doc, &target, std::mem::take(&mut base_text))?;
                }
                if name == "Title" && title_open {
                    // C14: the first ProgramInformation Title wins;
                    // later ones (multi-ProgramInformation documents)
                    // are ignored, matching the "first declared"
                    // convention of the other MPD-level facts.
                    close_title(&mut doc, std::mem::take(&mut title_text));
                    title_open = false;
                }
                close_element(&mut stack, &name)?;
            }
            Event::Text(t) => {
                if skip_depth == 0 {
                    if base_target.is_some() {
                        base_text.push_str(&t.xml10_content());
                    } else if title_open {
                        title_text.push_str(&t.xml10_content());
                    }
                }
            }
            Event::CData(t) => {
                if skip_depth == 0 {
                    if base_target.is_some() {
                        base_text.push_str(t.as_ref());
                    } else if title_open {
                        title_text.push_str(t.as_ref());
                    }
                }
            }
            Event::GeneralRef(t) => {
                // quick-xml 0.42 emits every entity reference as an
                // event (payload = the name). The XML-predefined set
                // and numeric character references resolve into the
                // open text targets (the metalink parser's posture);
                // anything else has no DTD to define it (DOCTYPE is
                // rejected below) — malformed. (Note: before
                // the Title face, no text target consumed
                // entities and every reference hit this error arm.)
                let ch = resolve_entity(t.as_bytes())?;
                if skip_depth == 0 {
                    if base_target.is_some() {
                        base_text.push(ch);
                    } else if title_open {
                        title_text.push(ch);
                    }
                }
            }
            Event::DocType(_) => {
                return Err(MediaError::ManifestParse(
                    "DOCTYPE is not allowed (DTD/entities disabled)".to_string(),
                ));
            }
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
        buf.clear();
    }
    if !saw_root {
        return Err(MediaError::ManifestParse(
            "no <MPD> root element".to_string(),
        ));
    }
    if let Some(frame) = stack.last() {
        return Err(MediaError::ManifestParse(format!(
            "unclosed element <{}>",
            frame.name()
        )));
    }
    if doc.periods.is_empty() {
        return Err(MediaError::ManifestParse(
            "MPD declares no <Period>".to_string(),
        ));
    }
    for (pi, period) in doc.periods.iter().enumerate() {
        if period.adaptation_sets.is_empty() {
            return Err(MediaError::ManifestParse(format!(
                "period {pi} declares no <AdaptationSet>"
            )));
        }
    }
    Ok(doc)
}

/// Parser frame kinds (the container elements this parser models).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    Mpd,
    /// An open `<ProgramInformation>` (the Title container;
    /// `Source`/`Copyright` children stay ignored).
    ProgramInformation,
    Period(usize),
    Set(usize, usize),
    Rep(usize, usize, usize),
    PeriodTemplate(usize),
    SetTemplate(usize, usize),
    RepTemplate(usize, usize, usize),
    Timeline,
    PeriodList(usize),
    SetList(usize, usize),
    RepList(usize, usize, usize),
    SegmentBase(usize, usize, usize),
    /// An open `<BaseURL>` (carries its accumulation target).
    BaseUrl(BaseTarget),
    /// An open non-container leaf (`<S>`/`<SegmentURL>`/
    /// `<Initialization>`/`<Title>` — bookkeeping happened at open).
    Leaf,
}

impl Frame {
    fn name(self) -> &'static str {
        match self {
            Self::Mpd => "MPD",
            Self::ProgramInformation => "ProgramInformation",
            Self::Period(_) => "Period",
            Self::Set(..) => "AdaptationSet",
            Self::Rep(..) => "Representation",
            Self::PeriodTemplate(_) | Self::SetTemplate(..) | Self::RepTemplate(..) => {
                "SegmentTemplate"
            }
            Self::Timeline => "SegmentTimeline",
            Self::PeriodList(_) | Self::SetList(..) | Self::RepList(..) => "SegmentList",
            Self::SegmentBase(..) => "SegmentBase",
            Self::BaseUrl(_) => "BaseURL",
            Self::Leaf => "(leaf)",
        }
    }
}

/// Where an open `<BaseURL>`'s text lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseTarget {
    Mpd,
    Period(usize),
    Set(usize, usize),
    Rep(usize, usize, usize),
}

/// Resolve one entity reference name: the XML-predefined five +
/// numeric character references; anything else = malformed (no DTD
/// can exist — DOCTYPE is refused above).
fn resolve_entity(name: &[u8]) -> Result<char, MediaError> {
    let ch = match name {
        b"amp" => '&',
        b"lt" => '<',
        b"gt" => '>',
        b"quot" => '"',
        b"apos" => '\'',
        _ => {
            let parsed = if let Some(hex) = name.strip_prefix(b"#x").or(name.strip_prefix(b"#X")) {
                std::str::from_utf8(hex)
                    .ok()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
            } else if let Some(dec) = name.strip_prefix(b"#") {
                std::str::from_utf8(dec)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
            } else {
                None
            };
            return match parsed.and_then(char::from_u32) {
                Some(c) if !c.is_control() || matches!(c, '\t' | '\n' | '\r') => Ok(c),
                _ => Err(MediaError::ManifestParse(format!(
                    "entity reference &{}; is undefined or invalid",
                    String::from_utf8_lossy(name)
                ))),
            };
        }
    };
    Ok(ch)
}

fn local_name(raw: &str) -> &str {
    // Namespace-tolerant local-name matching (the module's ruling):
    // the prefix is everything before the first ':'.
    match raw.find(':') {
        Some(pos) => &raw[pos + 1..],
        None => raw,
    }
}

fn attr(e: &BytesStart, key: &str) -> Option<String> {
    for a in e.attributes().flatten() {
        if local_name(a.key.as_ref()).eq_ignore_ascii_case(key) {
            // 0.42: unescape takes the raw Cow<[u8]> value (predefined
            // entities + numeric refs, no whitespace folding — the
            // metalink parser's exact posture).
            return unescape(&a.value).ok().map(|s| s.into_owned());
        }
    }
    None
}

fn attr_u64(e: &BytesStart, key: &str) -> Result<Option<u64>, MediaError> {
    match attr(e, key) {
        None => Ok(None),
        Some(text) => text
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|err| MediaError::ManifestParse(format!("@{key} {text:?}: {err}"))),
    }
}

fn attr_i64(e: &BytesStart, key: &str) -> Result<Option<i64>, MediaError> {
    match attr(e, key) {
        None => Ok(None),
        Some(text) => text
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|err| MediaError::ManifestParse(format!("@{key} {text:?}: {err}"))),
    }
}

fn attr_u32(e: &BytesStart, key: &str) -> Result<Option<u32>, MediaError> {
    attr_u64(e, key)?
        .map(|v| {
            u32::try_from(v).map_err(|_| MediaError::ManifestParse(format!("@{key} {v} over u32")))
        })
        .transpose()
}

/// `@range`-family attribute: `"begin-end"` inclusive → `(begin, end)`.
fn attr_range(e: &BytesStart, key: &str) -> Result<Option<(u64, u64)>, MediaError> {
    let Some(text) = attr(e, key) else {
        return Ok(None);
    };
    parse_range_text(&text, key)
}

fn parse_range_text(text: &str, key: &str) -> Result<Option<(u64, u64)>, MediaError> {
    let Some((begin, end)) = text.split_once('-') else {
        return Err(MediaError::ManifestParse(format!(
            "@{key} {text:?}: expected \"begin-end\""
        )));
    };
    let parse = |s: &str| {
        s.trim()
            .parse::<u64>()
            .map_err(|err| MediaError::ManifestParse(format!("@{key} {text:?}: {err}")))
    };
    let begin = parse(begin)?;
    let end = parse(end)?;
    if end < begin {
        return Err(MediaError::ManifestParse(format!(
            "@{key} {text:?}: end before begin"
        )));
    }
    Ok(Some((begin, end)))
}

/// XS-Duration → seconds (ISO 8601 `P[nD][T[nH][nM][n[.f]S]]`;
/// fractions tolerated on any component — the spec's
/// last-component-only rule is met by every real value and the
/// tolerant read cannot misorder anything).
fn parse_xs_duration(text: &str) -> Result<f64, MediaError> {
    let bad = || {
        MediaError::ManifestParse(format!(
            "XS-Duration {text:?}: expected P[nD][T[nH][nM][nS]]"
        ))
    };
    let Some(rest) = text.strip_prefix('P') else {
        return Err(bad());
    };
    let mut seconds = 0f64;
    let mut rest = rest;
    let mut saw_component = false;
    // Date part: days only (weeks/months/years are not the MPD
    // vocabulary and carry no useful precision here).
    if let Some(pos) = rest.find('D') {
        let (days, tail) = rest.split_at(pos);
        seconds += parse_duration_number(days, text)? * 86_400.0;
        rest = &tail[1..];
        saw_component = true;
    }
    if let Some(tail) = rest.strip_prefix('T') {
        rest = tail;
        while let Some(pos) = rest.find(['H', 'M', 'S']) {
            let (num, tail) = rest.split_at(pos);
            let value = parse_duration_number(num, text)?;
            seconds += match tail.as_bytes()[0] {
                b'H' => value * 3_600.0,
                b'M' => value * 60.0,
                _ => value,
            };
            rest = &tail[1..];
            saw_component = true;
        }
        if !rest.is_empty() {
            return Err(bad());
        }
    } else if !rest.is_empty() {
        return Err(bad());
    }
    if !saw_component {
        return Err(bad());
    }
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(bad());
    }
    Ok(seconds)
}

fn parse_duration_number(num: &str, whole: &str) -> Result<f64, MediaError> {
    if num.is_empty() {
        return Err(MediaError::ManifestParse(format!(
            "XS-Duration {whole:?}: empty component"
        )));
    }
    num.trim().parse::<f64>().map_err(|_| {
        MediaError::ManifestParse(format!("XS-Duration {whole:?}: bad number {num:?}"))
    })
}

/// The C14 Title application (single point): first non-empty wins,
/// the text trimmed.
fn close_title(doc: &mut Mpd, text: String) {
    let text = text.trim().to_string();
    if !text.is_empty() && doc.title.is_none() {
        doc.title = Some(text);
    }
}

/// Open one element. Returns whether a frame was pushed (the Empty
/// half of the caller closes it then). Sets `skip_depth = 1` for
/// unknown elements (their whole subtree is ignored).
#[expect(
    clippy::too_many_arguments,
    reason = "the open helper carries the single-pass parser state explicitly"
)]
fn open_element(
    doc: &mut Mpd,
    stack: &mut Vec<Frame>,
    saw_root: &mut bool,
    base_target: &mut Option<BaseTarget>,
    base_text: &mut String,
    skip_depth: &mut usize,
    title_open: &mut bool,
    title_text: &mut String,
    name: &str,
    e: &BytesStart,
) -> Result<bool, MediaError> {
    match name {
        "MPD" => {
            if *saw_root || !stack.is_empty() {
                return Err(MediaError::ManifestParse("nested <MPD>".to_string()));
            }
            if let Some(kind) = attr(e, "type") {
                if kind.eq_ignore_ascii_case("dynamic") {
                    return Err(MediaError::LiveUnsupported(
                        "MPD @type=\"dynamic\" (DASH live): 0.3 static VOD only — the 0.4 \
                         sliding window owns live"
                            .to_string(),
                    ));
                }
                if !kind.eq_ignore_ascii_case("static") {
                    return Err(MediaError::ManifestParse(format!(
                        "@type {kind:?}: expected static or dynamic"
                    )));
                }
            }
            if let Some(text) = attr(e, "mediaPresentationDuration") {
                doc.media_presentation_duration = Some(parse_xs_duration(&text)?);
            }
            *saw_root = true;
            stack.push(Frame::Mpd);
            Ok(true)
        }
        "Period" => {
            if stack.last() != Some(&Frame::Mpd) {
                return Err(unknown_placement("Period", stack));
            }
            let idx = doc.periods.len();
            doc.periods.push(Period {
                id: attr(e, "id"),
                start: attr(e, "start")
                    .map(|t| parse_xs_duration(&t))
                    .transpose()?,
                duration: attr(e, "duration")
                    .map(|t| parse_xs_duration(&t))
                    .transpose()?,
                ..Period::default()
            });
            stack.push(Frame::Period(idx));
            Ok(true)
        }
        "AdaptationSet" => {
            let Some(Frame::Period(pi)) = stack.last().copied() else {
                return Err(unknown_placement("AdaptationSet", stack));
            };
            let si = doc.periods[pi].adaptation_sets.len();
            doc.periods[pi].adaptation_sets.push(AdaptationSet {
                id: attr(e, "id"),
                lang: attr(e, "lang"),
                content_type: attr(e, "contentType"),
                mime_type: attr(e, "mimeType"),
                codecs: attr(e, "codecs"),
                max_width: attr_u32(e, "maxWidth")?,
                max_height: attr_u32(e, "maxHeight")?,
                ..AdaptationSet::default()
            });
            stack.push(Frame::Set(pi, si));
            Ok(true)
        }
        "Representation" => {
            let Some(Frame::Set(pi, si)) = stack.last().copied() else {
                return Err(unknown_placement("Representation", stack));
            };
            let set = &mut doc.periods[pi].adaptation_sets[si];
            let ri = set.representations.len();
            set.representations.push(Representation {
                id: attr(e, "id").unwrap_or_default(),
                bandwidth: attr_u64(e, "bandwidth")?.unwrap_or(0),
                width: attr_u32(e, "width")?,
                height: attr_u32(e, "height")?,
                frame_rate: attr(e, "frameRate"),
                codecs: attr(e, "codecs"),
                mime_type: attr(e, "mimeType"),
                audio_sampling_rate: attr_u32(e, "audioSamplingRate")?,
                ..Representation::default()
            });
            stack.push(Frame::Rep(pi, si, ri));
            Ok(true)
        }
        "BaseURL" => {
            let target = match stack.last().copied() {
                Some(Frame::Mpd) => BaseTarget::Mpd,
                Some(Frame::Period(pi)) => BaseTarget::Period(pi),
                Some(Frame::Set(pi, si)) => BaseTarget::Set(pi, si),
                Some(Frame::Rep(pi, si, ri)) => BaseTarget::Rep(pi, si, ri),
                // A BaseURL in an unsupported container placement (or
                // nested inside itself) accumulates nowhere — the
                // frame records the MPD-level sentinel and the close
                // discards the text.
                _ => BaseTarget::Mpd,
            };
            *base_target = Some(target);
            base_text.clear();
            stack.push(Frame::BaseUrl(target));
            Ok(true)
        }
        "ProgramInformation" => {
            // A known element ONLY in its legal MPD
            // placement — consumed for <Title>; anywhere else it
            // stays the ignored unknown (the zero-regression
            // verdict-semantics posture:
            // narrowing the ignore face never adds an error).
            if stack.last() == Some(&Frame::Mpd) {
                stack.push(Frame::ProgramInformation);
                Ok(true)
            } else {
                *skip_depth = 1;
                Ok(false)
            }
        }
        "Title" => {
            // The text child of ProgramInformation (the manifest
            // title face); a Title anywhere else stays the ignored unknown.
            if stack.last() == Some(&Frame::ProgramInformation) {
                *title_open = true;
                title_text.clear();
                stack.push(Frame::Leaf);
                Ok(true)
            } else {
                *skip_depth = 1;
                Ok(false)
            }
        }
        "SupplementalProperty" | "EssentialProperty" => {
            // Descriptor elements known at the MPD
            // level only (the URI-value thumbnail ruling,
            // [`THUMBNAIL_SCHEME`]); at every other level they stay
            // the ignored unknown (real manifests legally carry them
            // under Period/AdaptationSet/Representation for schemes
            // this parser does not consume — erroring would be a
            // judgment-semantics change).
            if stack.last() == Some(&Frame::Mpd) {
                doc.descriptors.push(MpdDescriptor {
                    scheme_id_uri: attr(e, "schemeIdUri").unwrap_or_default(),
                    value: attr(e, "value").unwrap_or_default(),
                });
                stack.push(Frame::Leaf);
                Ok(true)
            } else {
                *skip_depth = 1;
                Ok(false)
            }
        }
        "ContentProtection" => {
            // Any level, any scheme (verdict-table row; never supported).
            let scheme = attr(e, "schemeIdUri")
                .map(|s| format!(" schemeIdUri={s:?}"))
                .unwrap_or_default();
            Err(MediaError::DrmUnsupported(format!(
                "<ContentProtection{scheme}> — DRM is never supported; the 0.3 \
                 DASH key/decrypt consumption face is this refusal"
            )))
        }
        "SegmentTemplate" => {
            let template = read_segment_template(e)?;
            match stack.last().copied() {
                Some(Frame::Period(pi)) => {
                    let slot = doc.periods[pi]
                        .segment_template
                        .get_or_insert_with(SegmentTemplate::default);
                    merge_template(slot, &template);
                    stack.push(Frame::PeriodTemplate(pi));
                }
                Some(Frame::Set(pi, si)) => {
                    let inherited = doc.periods[pi].segment_template.clone().unwrap_or_default();
                    let slot = doc.periods[pi].adaptation_sets[si]
                        .segment_template
                        .get_or_insert(inherited);
                    merge_template(slot, &template);
                    stack.push(Frame::SetTemplate(pi, si));
                }
                Some(Frame::Rep(pi, si, ri)) => {
                    let inherited = doc.periods[pi].adaptation_sets[si]
                        .segment_template
                        .clone()
                        .or_else(|| doc.periods[pi].segment_template.clone())
                        .unwrap_or_default();
                    let slot = doc.periods[pi].adaptation_sets[si].representations[ri]
                        .segment_template
                        .get_or_insert(inherited);
                    merge_template(slot, &template);
                    stack.push(Frame::RepTemplate(pi, si, ri));
                }
                _ => return Err(unknown_placement("SegmentTemplate", stack)),
            }
            Ok(true)
        }
        "SegmentTimeline" => {
            if !matches!(
                stack.last(),
                Some(Frame::PeriodTemplate(_))
                    | Some(Frame::SetTemplate(..))
                    | Some(Frame::RepTemplate(..))
            ) {
                return Err(unknown_placement("SegmentTimeline", stack));
            }
            stack.push(Frame::Timeline);
            Ok(true)
        }
        "S" => {
            if stack.last() != Some(&Frame::Timeline) {
                return Err(unknown_placement("S (SegmentTimeline entry)", stack));
            }
            let entry = SegmentTimelineEntry {
                t: attr_u64(e, "t")?,
                d: attr_u64(e, "d")?.unwrap_or(0),
                r: attr_i64(e, "r")?.unwrap_or(0),
            };
            if entry.d == 0 {
                return Err(MediaError::ManifestParse(
                    "<S> without @d (segment duration)".to_string(),
                ));
            }
            if entry.r < -1 {
                return Err(MediaError::ManifestParse(format!(
                    "<S @r={}>: repeat must be ≥ -1",
                    entry.r
                )));
            }
            innermost_template_mut(doc, stack)?.timeline.push(entry);
            stack.push(Frame::Leaf);
            Ok(true)
        }
        "SegmentList" => {
            let list = read_segment_list_head(e)?;
            match stack.last().copied() {
                Some(Frame::Period(pi)) => {
                    doc.periods[pi].segment_list = Some(list);
                    stack.push(Frame::PeriodList(pi));
                }
                Some(Frame::Set(pi, si)) => {
                    doc.periods[pi].adaptation_sets[si].segment_list = Some(list);
                    stack.push(Frame::SetList(pi, si));
                }
                Some(Frame::Rep(pi, si, ri)) => {
                    doc.periods[pi].adaptation_sets[si].representations[ri].segment_list =
                        Some(list);
                    stack.push(Frame::RepList(pi, si, ri));
                }
                _ => return Err(unknown_placement("SegmentList", stack)),
            }
            Ok(true)
        }
        "Initialization" => {
            let init = InitRef {
                source_url: attr(e, "sourceURL"),
                range: attr_range(e, "range")?,
            };
            match stack.last().copied() {
                Some(Frame::PeriodList(_))
                | Some(Frame::SetList(..))
                | Some(Frame::RepList(..)) => {
                    innermost_list_mut(doc, stack)?.initialization = Some(init);
                }
                Some(Frame::SegmentBase(pi, si, ri)) => {
                    // SegmentBase's Initialization is a byte range
                    // inside the representation resource itself.
                    doc.periods[pi].adaptation_sets[si].representations[ri]
                        .segment_base
                        .as_mut()
                        .ok_or_else(|| {
                            MediaError::ManifestParse(
                                "<Initialization> outside its <SegmentBase>".to_string(),
                            )
                        })?
                        .initialization_range = init.range;
                }
                _ => return Err(unknown_placement("Initialization", stack)),
            }
            stack.push(Frame::Leaf);
            Ok(true)
        }
        "SegmentURL" => {
            match stack.last().copied() {
                Some(Frame::PeriodList(_))
                | Some(Frame::SetList(..))
                | Some(Frame::RepList(..)) => {}
                _ => return Err(unknown_placement("SegmentURL", stack)),
            }
            let list = innermost_list_mut(doc, stack)?;
            if list.segment_urls.len() >= MAX_LIST_SEGMENTS {
                return Err(MediaError::ManifestTooLarge(format!(
                    "<SegmentList> over {MAX_LIST_SEGMENTS} <SegmentURL> rows"
                )));
            }
            list.segment_urls.push(SegmentUrl {
                media: attr(e, "media"),
                media_range: attr_range(e, "mediaRange")?,
            });
            stack.push(Frame::Leaf);
            Ok(true)
        }
        "SegmentBase" => {
            let Some(Frame::Rep(pi, si, ri)) = stack.last().copied() else {
                return Err(unknown_placement("SegmentBase", stack));
            };
            let base = SegmentBase {
                timescale: attr_u64(e, "timescale")?,
                index_range: attr_range(e, "indexRange")?,
                initialization_range: None,
            };
            doc.periods[pi].adaptation_sets[si].representations[ri].segment_base = Some(base);
            stack.push(Frame::SegmentBase(pi, si, ri));
            Ok(true)
        }
        // Unknown element: the whole subtree is ignored (skip window).
        _ => {
            *skip_depth = 1;
            Ok(false)
        }
    }
}

fn close_element(stack: &mut Vec<Frame>, name: &str) -> Result<(), MediaError> {
    if stack.is_empty() {
        return Err(MediaError::ManifestParse(format!(
            "closing </{name}> with an empty stack"
        )));
    }
    // check_end_names guarantees the tokenizer saw the matching open
    // tag; the frame stack placement was validated at open time —
    // the pop is the close.
    stack.pop();
    Ok(())
}

fn apply_base_url(doc: &mut Mpd, target: &BaseTarget, text: String) -> Result<(), MediaError> {
    let url = text.trim().to_string();
    if url.is_empty() {
        return Ok(());
    }
    match *target {
        BaseTarget::Mpd => doc.base_urls.push(url),
        BaseTarget::Period(pi) => doc.periods[pi].base_urls.push(url),
        BaseTarget::Set(pi, si) => doc.periods[pi].adaptation_sets[si].base_urls.push(url),
        BaseTarget::Rep(pi, si, ri) => doc.periods[pi].adaptation_sets[si].representations[ri]
            .base_urls
            .push(url),
    }
    Ok(())
}

fn read_segment_template(e: &BytesStart) -> Result<SegmentTemplate, MediaError> {
    Ok(SegmentTemplate {
        timescale: attr_u64(e, "timescale")?,
        duration: attr_u64(e, "duration")?,
        start_number: attr_u64(e, "startNumber")?,
        presentation_time_offset: attr_u64(e, "presentationTimeOffset")?,
        initialization: attr(e, "initialization"),
        media: attr(e, "media"),
        timeline: Vec::new(),
    })
}

fn read_segment_list_head(e: &BytesStart) -> Result<SegmentList, MediaError> {
    Ok(SegmentList {
        timescale: attr_u64(e, "timescale")?,
        duration: attr_u64(e, "duration")?,
        initialization: None,
        segment_urls: Vec::new(),
    })
}

/// Per-attribute merge, child values win (the documented inheritance
/// ruling); the timeline is the child's own (never merged — a child
/// timeline replaces, per the spec's timeline semantics).
fn merge_template(base: &mut SegmentTemplate, child: &SegmentTemplate) {
    if child.timescale.is_some() {
        base.timescale = child.timescale;
    }
    if child.duration.is_some() {
        base.duration = child.duration;
    }
    if child.start_number.is_some() {
        base.start_number = child.start_number;
    }
    if child.presentation_time_offset.is_some() {
        base.presentation_time_offset = child.presentation_time_offset;
    }
    if child.initialization.is_some() {
        base.initialization = child.initialization.clone();
    }
    if child.media.is_some() {
        base.media = child.media.clone();
    }
    if !child.timeline.is_empty() {
        base.timeline = child.timeline.clone();
    }
}

/// The innermost open template (the frame directly below a Timeline
/// frame) — mutable.
fn innermost_template_mut<'a>(
    doc: &'a mut Mpd,
    stack: &[Frame],
) -> Result<&'a mut SegmentTemplate, MediaError> {
    // Walk down past the Timeline frame to the template frame.
    let mut idx = stack.len();
    while idx > 0 {
        idx -= 1;
        match stack[idx] {
            Frame::Timeline => continue,
            Frame::PeriodTemplate(pi) => {
                return doc.periods[pi]
                    .segment_template
                    .as_mut()
                    .ok_or_else(|| MediaError::ManifestParse("timeline frame mismatch".into()));
            }
            Frame::SetTemplate(pi, si) => {
                return doc.periods[pi].adaptation_sets[si]
                    .segment_template
                    .as_mut()
                    .ok_or_else(|| MediaError::ManifestParse("timeline frame mismatch".into()));
            }
            Frame::RepTemplate(pi, si, ri) => {
                return doc.periods[pi].adaptation_sets[si].representations[ri]
                    .segment_template
                    .as_mut()
                    .ok_or_else(|| MediaError::ManifestParse("timeline frame mismatch".into()));
            }
            _ => break,
        }
    }
    Err(MediaError::ManifestParse(
        "<S> outside a <SegmentTemplate>".to_string(),
    ))
}

/// The innermost open SegmentList — mutable.
fn innermost_list_mut<'a>(
    doc: &'a mut Mpd,
    stack: &[Frame],
) -> Result<&'a mut SegmentList, MediaError> {
    let frame = stack
        .last()
        .copied()
        .ok_or_else(|| MediaError::ManifestParse("empty stack".into()))?;
    match frame {
        Frame::PeriodList(pi) => doc.periods[pi]
            .segment_list
            .as_mut()
            .ok_or_else(|| MediaError::ManifestParse("list frame mismatch".into())),
        Frame::SetList(pi, si) => doc.periods[pi].adaptation_sets[si]
            .segment_list
            .as_mut()
            .ok_or_else(|| MediaError::ManifestParse("list frame mismatch".into())),
        Frame::RepList(pi, si, ri) => doc.periods[pi].adaptation_sets[si].representations[ri]
            .segment_list
            .as_mut()
            .ok_or_else(|| MediaError::ManifestParse("list frame mismatch".into())),
        _ => Err(MediaError::ManifestParse(
            "<Initialization>/<SegmentURL> outside a <SegmentList>".to_string(),
        )),
    }
}

fn unknown_placement(element: &str, stack: &[Frame]) -> MediaError {
    let top = stack
        .last()
        .map(|f| f.name().to_string())
        .unwrap_or_else(|| "(root)".to_string());
    MediaError::ManifestParse(format!("<{element}> inside <{top}>: wrong placement"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xs_duration_shapes() {
        assert_eq!(
            parse_xs_duration("PT30S").unwrap_or_else(|e| panic!("{e}")),
            30.0
        );
        assert_eq!(
            parse_xs_duration("PT1M30S").unwrap_or_else(|e| panic!("{e}")),
            90.0
        );
        assert_eq!(
            parse_xs_duration("PT2.5S").unwrap_or_else(|e| panic!("{e}")),
            2.5
        );
        assert_eq!(
            parse_xs_duration("P1DT2H").unwrap_or_else(|e| panic!("{e}")),
            93_600.0
        );
        assert_eq!(
            parse_xs_duration("PT1H").unwrap_or_else(|e| panic!("{e}")),
            3_600.0
        );
        assert!(parse_xs_duration("30S").is_err());
        assert!(parse_xs_duration("P").is_err());
        assert!(parse_xs_duration("PT").is_err());
        assert!(parse_xs_duration("P1X").is_err());
        assert!(parse_xs_duration("PT1H2").is_err());
    }

    #[test]
    fn range_shapes() {
        assert_eq!(
            parse_range_text("100-399", "indexRange").unwrap_or_else(|e| panic!("{e}")),
            Some((100, 399))
        );
        assert!(parse_range_text("400-100", "indexRange").is_err());
        assert!(parse_range_text("abc", "indexRange").is_err());
        assert!(parse_range_text("10-", "indexRange").is_err());
    }

    /// ProgramInformation/Title extraction — first
    /// non-empty wins, escaped entities resolve, empty/multiple
    /// Titles tolerated; Source/Copyright inside stay ignored; a
    /// Title outside ProgramInformation stays the ignored unknown
    /// (the zero-regression verdict-semantics posture).
    #[test]
    fn program_information_title_extracted() {
        let doc = br#"<MPD>
            <ProgramInformation>
              <Title>Big &amp; Buck Bunny</Title>
              <Source>some source</Source>
              <Copyright>x</Copyright>
            </ProgramInformation>
            <Period><AdaptationSet>
              <Representation id="r1" bandwidth="1"/>
            </AdaptationSet></Period>
        </MPD>"#;
        let mpd = parse_mpd(doc).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(mpd.title.as_deref(), Some("Big & Buck Bunny"));
        // Multiple ProgramInformation blocks: the first non-empty
        // Title wins (the "first declared" convention).
        let doc = br#"<MPD>
            <ProgramInformation><Title></Title></ProgramInformation>
            <ProgramInformation><Title>Second</Title></ProgramInformation>
            <Period><AdaptationSet><Representation id="r" bandwidth="1"/></AdaptationSet></Period>
        </MPD>"#;
        let mpd = parse_mpd(doc).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(mpd.title.as_deref(), Some("Second"));
        // A bare Title with no ProgramInformation container: ignored
        // (never an error — the ignore-face narrowing red line).
        let doc = br#"<MPD>
            <Period><AdaptationSet><Title>rogue</Title>
              <Representation id="r" bandwidth="1"/>
            </AdaptationSet></Period>
        </MPD>"#;
        let mpd = parse_mpd(doc).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(mpd.title, None);
        assert!(mpd.thumbnail_uri().is_none());
    }

    /// The MPD-level descriptor pair is consumed;
    /// other placements stay ignored (real manifests legally carry
    /// them under Period/Representation for schemes we do not
    /// consume — that must not error); the thumbnail ruling picks
    /// the anchored scheme's URI-value form.
    #[test]
    fn descriptor_elements_narrowed_at_mpd_level_only() {
        let doc = br#"<MPD>
            <SupplementalProperty schemeIdUri="urn:mpeg:dash:thumbnail:2016" value="https://c.example/cover.jpg"/>
            <EssentialProperty schemeIdUri="urn:example:other" value="1"/>
            <Period>
              <SupplementalProperty schemeIdUri="urn:mpeg:dash:thumbnail:2016" value="https://ignored.example/p.jpg"/>
              <AdaptationSet><Representation id="r" bandwidth="1"/></AdaptationSet>
            </Period>
        </MPD>"#;
        let mpd = parse_mpd(doc).unwrap_or_else(|e| panic!("{e}"));
        // Only the MPD-level descriptors land; the Period-level ones
        // stay ignored (never an error).
        assert_eq!(mpd.descriptors.len(), 2);
        assert_eq!(
            mpd.thumbnail_uri(),
            Some("https://c.example/cover.jpg"),
            "the anchored scheme's URI value wins"
        );
        // A non-URI value under the anchored scheme: not a thumbnail
        // face (the tiled trick-play form is 0.5's).
        let doc = br#"<MPD>
            <EssentialProperty schemeIdUri="URN:MPEG:DASH:THUMBNAIL:2016" value="1"/>
            <Period><AdaptationSet><Representation id="r" bandwidth="1"/></AdaptationSet></Period>
        </MPD>"#;
        let mpd = parse_mpd(doc).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            mpd.thumbnail_uri().is_none(),
            "scheme match is case-insensitive but the value must be an http(s) URI"
        );
        // No descriptors: honest None.
        let doc = br#"<MPD><Period><AdaptationSet>
            <Representation id="r" bandwidth="1"/>
        </AdaptationSet></Period></MPD>"#;
        let mpd = parse_mpd(doc).unwrap_or_else(|e| panic!("{e}"));
        assert!(mpd.descriptors.is_empty());
        assert!(mpd.thumbnail_uri().is_none());
    }

    #[test]
    fn minimal_mpd_parses_with_defaults() {
        let doc = br#"<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
            <Period><AdaptationSet>
              <Representation id="r1" bandwidth="500000" mimeType="video/mp4">
                <BaseURL>v1/</BaseURL>
              </Representation>
            </AdaptationSet></Period>
        </MPD>"#;
        let mpd = parse_mpd(doc).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(mpd.mpd_type, MpdType::Static);
        assert_eq!(mpd.periods.len(), 1);
        let rep = &mpd.periods[0].adaptation_sets[0].representations[0];
        assert_eq!(rep.id, "r1");
        assert_eq!(rep.bandwidth, 500_000);
        assert_eq!(rep.base_urls, vec!["v1/".to_string()]);
    }
}

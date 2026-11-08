//! m3u8 parser — line-oriented state machine, pure function
//! `bytes → structure | MediaError`
//! (RFC 8216 + the media spec's verdict table / pinned semantics).
//!
//! Frozen-seam posture: parsing only. No fetching, no base-URL
//! resolution (URIs kept verbatim for the driver), no key retrieval or
//! decryption, no staging.
//!
//! Line handling (hostile-input posture shared with the progress
//! parser): the body is converted to UTF-8 **lossily** (a mangled byte
//! never kills the parse), `\n` terminates lines with a trailing `\r`
//! stripped, a leading BOM is tolerated, blank lines and non-`EXT`
//! comments are skipped. The first significant line MUST be `#EXTM3U`.
//!
//! Explicit refusals (the media spec's verdict table; the product
//! spec's explicit-refusal rule): no
//! EXT-X-ENDLIST → `live_unsupported`; METHOD=SAMPLE-AES →
//! `sample_aes_unsupported`; EXT-X-SESSION-KEY →
//! `session_key_unsupported`; EXT-X-I-FRAMES-ONLY (media playlist) →
//! `iframes_unsupported`; body > 16MiB or > 100k segments →
//! `manifest_too_large`. Unknown `#EXT-*` tags are ignored (recorded
//! by name); EXT-X-PROGRAM-DATE-TIME is ignored by ruling.
//!
//! Pinned playlist semantics (the media spec's errata):
//!
//! * **BYTERANGE omitted offset** accumulates **per URI in appearance
//!   order** (`HashMap<uri, next_offset>`); a sub-range with an
//!   explicit offset (re)seats that URI's cursor, a **whole-resource
//!   segment forgets it** (its length is unknowable at manifest-parse
//!   time, so the chain is broken), and all seat/accumulate arithmetic
//!   is `checked_*` — overflow is a parse error, never a wrap.
//!   EXT-X-MAP `BYTERANGE` sub-ranges join the same per-URI chain.
//! * **METHOD=NONE is an explicit reset**: the ambient key becomes
//!   plaintext and no later segment inherits the retired key — the
//!   model materializes the effective key per segment, so the
//!   m3u8-rs "plaintext segment reuses the stale key" degradation
//!   cannot occur by construction.
//! * **MAP-after-KEY boundary**: the init section's key is the
//!   `KEY=` attribute on the EXT-X-MAP when present (a taiji custom
//!   extension, an erratum of record: not an RFC 8216 / rfc8216bis
//!   clause), else the ambient EXT-X-KEY at the MAP's position (a KEY
//!   declared after the MAP never covers it). An encrypted init
//!   section's IV resolves at decrypt time: the key's explicit IV,
//!   else the first following segment's sequence — a practical taiji
//!   relaxation (the original parse-time explicit-IV rejection was
//!   relaxed by the decrypt line), not a spec clause; RFC 8216
//!   §4.3.2.5's spec-correct behavior
//!   on a missing init IV is to reject.

use std::collections::HashMap;

use super::attrs::{attr, parse_attr_list, parse_byterange, parse_hex_iv, parse_resolution};
use super::model::{
    ByteRange, InitSection, Key, KeyMethod, MasterPlaylist, MediaPlaylist, MediaSegment,
    MediaTrack, Playlist, TrackType, Variant,
};
use crate::error::MediaError;

/// Manifest body cap: 16MiB (the product spec's cap, carried by the media spec).
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

/// Media-segment count cap per playlist (100k, per the product spec).
pub const MAX_MEDIA_SEGMENTS: usize = 100_000;

/// Parse a whole manifest body into a media or master playlist
/// structure. The 16MiB cap is checked before any allocation-heavy
/// work; the segment cap is enforced as segments are appended.
pub fn parse_manifest(bytes: &[u8]) -> Result<Playlist, MediaError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(MediaError::ManifestTooLarge(format!(
            "manifest body {} bytes exceeds the {}MiB cap",
            bytes.len(),
            MAX_MANIFEST_BYTES / (1024 * 1024)
        )));
    }
    let text = String::from_utf8_lossy(bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);

    let mut state = ParseState::default();
    for (idx, raw_line) in text.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if !state.saw_header {
            if line == "#EXTM3U" {
                state.saw_header = true;
                continue;
            }
            return Err(parse_err(idx, "first line must be #EXTM3U"));
        }
        if !line.starts_with('#') {
            state.on_uri(idx, line)?;
        } else if let Some(body) = line
            .strip_prefix("#EXT-")
            .or_else(|| line.strip_prefix("#EXT"))
        {
            state.on_tag(idx, body)?;
            state.last_line = idx;
        }
        // Bare `#`-comments: ignored entirely.
    }
    state.finish()
}

fn parse_err(line: usize, msg: &str) -> MediaError {
    MediaError::ManifestParse(format!("line {}: {msg}", line + 1))
}

#[derive(Default)]
struct ParseState {
    saw_header: bool,
    version: Option<u32>,
    independent_segments: bool,
    // Media playlist scratch (segment table + playlist-level tags).
    media: MediaPlaylist,
    // Master playlist scratch (variant + rendition tables).
    master: MasterPlaylist,
    // A master-only tag was seen → classify master even with no rows.
    saw_master_tag: bool,
    iframes_only: bool,
    unknown_tags: Vec<String>,
    // Pending per-line state, consumed by the next URI line.
    pending_extinf: Option<(f64, Option<String>)>,
    pending_byterange: Option<(u64, Option<u64>)>,
    pending_stream_inf: Option<StreamInfAttrs>,
    pending_discontinuity: bool,
    // Ambient key / init section in force (None = plaintext / none).
    current_key: Option<Key>,
    current_map: Option<usize>,
    // Per-URI next-offset cursor for omitted BYTERANGE offsets.
    cursors: HashMap<String, u64>,
    // Line index of the last significant tag (truncation reporting).
    last_line: usize,
}

#[derive(Default)]
struct StreamInfAttrs {
    bandwidth: u64,
    average_bandwidth: Option<u64>,
    resolution: Option<(u32, u32)>,
    codecs: Option<String>,
    frame_rate: Option<f64>,
    video_range: Option<String>,
    audio_group: Option<String>,
    video_group: Option<String>,
    subtitles_group: Option<String>,
    closed_captions: Option<String>,
}

impl ParseState {
    fn on_uri(&mut self, line: usize, uri: &str) -> Result<(), MediaError> {
        if let Some(attrs) = self.pending_stream_inf.take() {
            self.master.variants.push(Variant {
                uri: uri.to_owned(),
                bandwidth: attrs.bandwidth,
                average_bandwidth: attrs.average_bandwidth,
                resolution: attrs.resolution,
                codecs: attrs.codecs,
                frame_rate: attrs.frame_rate,
                video_range: attrs.video_range,
                audio_group: attrs.audio_group,
                video_group: attrs.video_group,
                subtitles_group: attrs.subtitles_group,
                closed_captions: attrs.closed_captions,
            });
            // A URI under STREAM-INF is a variant line; co-pending
            // media-segment state was malformed input — drop it.
            self.pending_extinf = None;
            self.pending_byterange = None;
            self.pending_discontinuity = false;
            return Ok(());
        }
        let Some((duration, title)) = self.pending_extinf.take() else {
            return Err(parse_err(line, "URI line without a preceding EXTINF"));
        };
        if self.media.segments.len() == MAX_MEDIA_SEGMENTS {
            return Err(MediaError::ManifestTooLarge(format!(
                "media segment count exceeds the {MAX_MEDIA_SEGMENTS} cap"
            )));
        }
        let sequence = self
            .media
            .media_sequence
            .checked_add(self.media.segments.len() as u64)
            .ok_or_else(|| parse_err(line, "media sequence overflow"))?;
        let spec = self.pending_byterange.take();
        let byte_range = self.resolve_range_spec(line, uri, spec)?;
        let key = self.current_key.clone();
        self.media.segments.push(MediaSegment {
            sequence,
            uri: uri.to_owned(),
            duration,
            title,
            byte_range,
            discontinuity: self.pending_discontinuity,
            key,
            map: self.current_map,
        });
        self.pending_discontinuity = false;
        Ok(())
    }

    /// Resolve a byte-range specification against the per-URI
    /// appearance-order cursor: an explicit offset seats the cursor,
    /// an omitted offset consumes it (error when the URI has no prior
    /// sub-range), a `None` spec (whole resource) breaks the chain.
    /// All arithmetic is checked; overflow is a parse error.
    fn resolve_range_spec(
        &mut self,
        line: usize,
        uri: &str,
        spec: Option<(u64, Option<u64>)>,
    ) -> Result<Option<ByteRange>, MediaError> {
        let Some((length, explicit)) = spec else {
            self.cursors.remove(uri);
            return Ok(None);
        };
        let (offset, offset_omitted) = match explicit {
            Some(offset) => (offset, false),
            None => (
                self.cursors.get(uri).copied().ok_or_else(|| {
                    parse_err(
                        line,
                        "EXT-X-BYTERANGE omitted offset but no prior sub-range of the same URI",
                    )
                })?,
                true,
            ),
        };
        let next = offset
            .checked_add(length)
            .ok_or_else(|| parse_err(line, "EXT-X-BYTERANGE offset overflow"))?;
        self.cursors.insert(uri.to_owned(), next);
        Ok(Some(ByteRange {
            length,
            offset,
            offset_omitted,
        }))
    }

    fn on_tag(&mut self, line: usize, body: &str) -> Result<(), MediaError> {
        let (name, value) = match body.split_once(':') {
            Some((n, v)) => (n, v.trim()),
            None => (body, ""),
        };
        match name {
            // ---- shared header tags ----
            "X-VERSION" => {
                self.version = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| parse_err(line, "malformed EXT-X-VERSION"))?,
                );
            }
            "X-INDEPENDENT-SEGMENTS" => self.independent_segments = true,

            // ---- media playlist tags ----
            "X-TARGETDURATION" => {
                self.media.target_duration = Some(
                    value
                        .parse::<f64>()
                        .map_err(|_| parse_err(line, "malformed EXT-X-TARGETDURATION"))?,
                );
            }
            "X-MEDIA-SEQUENCE" => {
                // RFC 8216 §4.3.3.2: MUST precede the first segment —
                // a late tag would silently re-key every identity
                // already assigned (fuzz-found splice case).
                if !self.media.segments.is_empty() {
                    return Err(parse_err(
                        line,
                        "EXT-X-MEDIA-SEQUENCE must precede the first segment",
                    ));
                }
                self.media.media_sequence = value
                    .parse::<u64>()
                    .map_err(|_| parse_err(line, "malformed EXT-X-MEDIA-SEQUENCE"))?;
            }
            "X-DISCONTINUITY-SEQUENCE" => {
                // Same §4.3.3.3 placement rule.
                if !self.media.segments.is_empty() {
                    return Err(parse_err(
                        line,
                        "EXT-X-DISCONTINUITY-SEQUENCE must precede the first segment",
                    ));
                }
                self.media.discontinuity_sequence = value
                    .parse::<u64>()
                    .map_err(|_| parse_err(line, "malformed EXT-X-DISCONTINUITY-SEQUENCE"))?;
            }
            "X-ENDLIST" => self.media.endlist = true,
            "X-PLAYLIST-TYPE" => {
                self.media.playlist_type = Some(value.to_ascii_uppercase());
            }
            "X-I-FRAMES-ONLY" => self.iframes_only = true,

            // ---- media segment tags ----
            "INF" => {
                let (dur_s, title) = value
                    .split_once(',')
                    .ok_or_else(|| parse_err(line, "malformed EXTINF (duration,title)"))?;
                let duration = dur_s
                    .trim()
                    .trim_matches('"')
                    .parse::<f64>()
                    .map_err(|_| parse_err(line, "malformed EXTINF duration"))?;
                if !(duration.is_finite() && duration >= 0.0) {
                    return Err(parse_err(line, "EXTINF duration must be finite and >= 0"));
                }
                let title = title.trim();
                self.pending_extinf = Some((
                    duration,
                    (!title.is_empty()).then(|| title.trim_matches('"').to_owned()),
                ));
            }
            "X-BYTERANGE" => {
                self.pending_byterange = Some(
                    parse_byterange(value)
                        .ok_or_else(|| parse_err(line, "malformed EXT-X-BYTERANGE"))?,
                );
            }
            "X-DISCONTINUITY" => self.pending_discontinuity = true,
            "X-PROGRAM-DATE-TIME" => {} // ignored per the card
            "X-KEY" => {
                let list = parse_attr_list(value);
                let key = parse_key(line, &list)?;
                // METHOD=NONE is an explicit reset to plaintext — the
                // ambient key is dropped, never carried across.
                self.current_key = (key.method == KeyMethod::Aes128).then_some(key);
            }
            "X-MAP" => self.on_map(line, value)?,

            // ---- master playlist tags ----
            "X-MEDIA" => {
                self.saw_master_tag = true;
                self.on_media_tag(line, value)?;
            }
            "X-STREAM-INF" => {
                self.saw_master_tag = true;
                self.pending_stream_inf = Some(parse_stream_inf(line, value)?);
            }
            "X-I-FRAME-STREAM-INF" => {
                self.saw_master_tag = true;
                let list = parse_attr_list(value);
                let attrs = parse_stream_inf(line, value)?;
                let uri = attr(&list, "URI")
                    .ok_or_else(|| parse_err(line, "EXT-X-I-FRAME-STREAM-INF without URI"))?
                    .to_owned();
                let StreamInfAttrs {
                    bandwidth,
                    average_bandwidth,
                    resolution,
                    codecs,
                    frame_rate,
                    video_range,
                    audio_group,
                    video_group,
                    subtitles_group,
                    closed_captions,
                } = attrs;
                self.master.iframe_variants.push(Variant {
                    uri,
                    bandwidth,
                    average_bandwidth,
                    resolution,
                    codecs,
                    frame_rate,
                    video_range,
                    audio_group,
                    video_group,
                    subtitles_group,
                    closed_captions,
                });
            }
            "X-SESSION-KEY" => {
                return Err(MediaError::SessionKeyUnsupported(format!(
                    "line {}: EXT-X-SESSION-KEY is not supported",
                    line + 1
                )));
            }
            // Known but out-of-scope tags, ignored without recording:
            // SESSION-DATA / START / ALLOW-CACHE (deprecated).
            "X-SESSION-DATA" | "X-START" | "X-ALLOW-CACHE" => {}

            // ---- forward compatibility ----
            _ => self.unknown_tags.push(format!("EXT-{name}")),
        }
        Ok(())
    }

    /// EXT-X-MAP: init section in appearance order. Key resolution is
    /// positional (module docs): the MAP's own `KEY=` attribute wins,
    /// else the ambient EXT-X-KEY declared before this MAP.
    fn on_map(&mut self, line: usize, value: &str) -> Result<(), MediaError> {
        let list = parse_attr_list(value);
        let uri = attr(&list, "URI")
            .ok_or_else(|| parse_err(line, "EXT-X-MAP without URI"))?
            .to_owned();
        let spec = match attr(&list, "BYTERANGE") {
            Some(range) => Some(
                parse_byterange(range)
                    .ok_or_else(|| parse_err(line, "malformed EXT-X-MAP BYTERANGE"))?,
            ),
            None => None,
        };
        let byte_range = self.resolve_range_spec(line, &uri, spec)?;
        let key = match attr(&list, "KEY") {
            // Attribution erratum of record (comment-only): the
            // `KEY=` attribute on EXT-X-MAP is a **taiji custom
            // extension** — not a clause of RFC 8216 or any rfc8216bis
            // revision. Accepted as a quoted-string (or bare)
            // attribute list of an EXT-X-KEY for the init section
            // alone; peers that do not know it simply ignore it.
            Some(inner) => {
                let inner_list = parse_attr_list(inner);
                Some(parse_key(line, &inner_list)?)
            }
            None => self.current_key.clone(),
        };
        // IV chain for an encrypted init section (resolved at decrypt
        // time by `keys::build_track_crypto`): the key's explicit IV
        // (the MAP `KEY=` attribute's IV, or the ambient EXT-X-KEY's
        // IV), else the sequence of the first segment following the
        // MAP. Attribution erratum of record (comment-only): that
        // missing-IV sequence fallback is a **practical taiji
        // relaxation, not a spec clause** — RFC 8216 §4.3.2.5 requires
        // an explicit IV for an encrypted EXT-X-MAP, and the
        // spec-correct behavior on its absence is to reject; taiji
        // (since the decrypt-line relaxation of the original parse-time
        // rejection) attempts the sequence derivation instead and
        // reports an honest decrypt error when it cannot resolve one.
        // METHOD=NONE normalizes to plaintext (`None` in the model).
        let key = match key {
            Some(k) if k.method == KeyMethod::None => None,
            k => k,
        };
        let index = self.media.init_sections.len();
        self.media.init_sections.push(InitSection {
            index,
            uri,
            byte_range,
            key,
        });
        self.current_map = Some(index);
        Ok(())
    }

    fn on_media_tag(&mut self, line: usize, value: &str) -> Result<(), MediaError> {
        let list = parse_attr_list(value);
        let track_type = match attr(&list, "TYPE").unwrap_or_default() {
            "AUDIO" => TrackType::Audio,
            "VIDEO" => TrackType::Video,
            "SUBTITLES" => TrackType::Subtitles,
            "CLOSED-CAPTIONS" => TrackType::ClosedCaptions,
            other => {
                return Err(parse_err(
                    line,
                    &format!("EXT-X-MEDIA TYPE {other:?} is not a rendition type"),
                ));
            }
        };
        self.master.tracks.push(MediaTrack {
            track_type,
            group_id: attr(&list, "GROUP-ID").map(str::to_owned),
            name: attr(&list, "NAME").map(str::to_owned),
            language: attr(&list, "LANGUAGE").map(str::to_owned),
            default_track: attr(&list, "DEFAULT") == Some("YES"),
            uri: attr(&list, "URI").map(str::to_owned),
        });
        Ok(())
    }

    fn finish(mut self) -> Result<Playlist, MediaError> {
        // Truncation: a pending tag with no following URI line means
        // the playlist was cut mid-pair. All dangling tags are named.
        let mut dangling: Vec<&str> = Vec::new();
        if self.pending_extinf.is_some() {
            dangling.push("EXTINF");
        }
        if self.pending_byterange.is_some() {
            dangling.push("EXT-X-BYTERANGE");
        }
        if self.pending_stream_inf.is_some() {
            dangling.push("EXT-X-STREAM-INF");
        }
        if self.pending_discontinuity {
            dangling.push("EXT-X-DISCONTINUITY");
        }
        if !dangling.is_empty() {
            return Err(parse_err(
                self.last_line,
                &format!("truncated playlist: dangling {}", dangling.join(", ")),
            ));
        }

        let is_master = self.saw_master_tag
            || !self.master.variants.is_empty()
            || !self.master.iframe_variants.is_empty()
            || !self.master.tracks.is_empty();
        if is_master {
            // A media-playlist-level I-FRAMES-ONLY line inside a
            // master (real-world legacy form) carries provenance the
            // variant rows don't — record it as a foreign tag.
            if self.iframes_only {
                self.unknown_tags.push("EXT-X-I-FRAMES-ONLY".to_owned());
            }
            self.master.version = self.version;
            self.master.independent_segments = self.independent_segments;
            self.master.unknown_tags = self.unknown_tags;
            // Media-segment scratch (if any) was invalid mixed input;
            // the master tables win the classification.
            return Ok(Playlist::Master(self.master));
        }

        if self.iframes_only {
            return Err(MediaError::IframesUnsupported(
                "media playlist carries EXT-X-I-FRAMES-ONLY (trick-play rendition)".to_owned(),
            ));
        }
        if !self.media.endlist {
            return Err(MediaError::LiveUnsupported(format!(
                "media playlist has no EXT-X-ENDLIST ({} segments); LIVE/EVENT lands in 0.4",
                self.media.segments.len()
            )));
        }
        self.media.version = self.version;
        self.media.independent_segments = self.independent_segments;
        self.media.unknown_tags = self.unknown_tags;
        Ok(Playlist::Media(self.media))
    }
}

/// Shared EXT-X-STREAM-INF / EXT-X-I-FRAME-STREAM-INF attribute
/// parsing (BANDWIDTH is REQUIRED; typed attributes are strict).
fn parse_stream_inf(line: usize, value: &str) -> Result<StreamInfAttrs, MediaError> {
    let list = parse_attr_list(value);
    let bandwidth = match attr(&list, "BANDWIDTH") {
        None => return Err(parse_err(line, "EXT-X-STREAM-INF without BANDWIDTH")),
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| parse_err(line, "malformed BANDWIDTH"))?,
    };
    let num = |name: &str| -> Result<Option<u64>, MediaError> {
        match attr(&list, name) {
            None => Ok(None),
            Some(v) => v
                .parse::<u64>()
                .map(Some)
                .map_err(|_| parse_err(line, &format!("malformed {name}"))),
        }
    };
    let resolution = match attr(&list, "RESOLUTION") {
        None => None,
        Some(v) => {
            Some(parse_resolution(v).ok_or_else(|| parse_err(line, "malformed RESOLUTION"))?)
        }
    };
    let frame_rate = match attr(&list, "FRAME-RATE") {
        None => None,
        Some(v) => Some(
            v.parse::<f64>()
                .map_err(|_| parse_err(line, "malformed FRAME-RATE"))?,
        ),
    };
    Ok(StreamInfAttrs {
        bandwidth,
        average_bandwidth: num("AVERAGE-BANDWIDTH")?,
        resolution,
        codecs: attr(&list, "CODECS").map(str::to_owned),
        frame_rate,
        video_range: attr(&list, "VIDEO-RANGE").map(str::to_owned),
        audio_group: attr(&list, "AUDIO").map(str::to_owned),
        video_group: attr(&list, "VIDEO").map(str::to_owned),
        subtitles_group: attr(&list, "SUBTITLES").map(str::to_owned),
        closed_captions: attr(&list, "CLOSED-CAPTIONS").map(str::to_owned),
    })
}

/// Parse an EXT-X-KEY attribute list (shared by the tag and the
/// EXT-X-MAP `KEY=` attribute — the taiji custom extension, an
/// erratum of record; unquoted values tolerated in the latter's nested
/// form).
fn parse_key(line: usize, list: &[super::attrs::Attr<'_>]) -> Result<Key, MediaError> {
    let method = attr(list, "METHOD").unwrap_or_default();
    match method {
        "NONE" => Ok(Key {
            method: KeyMethod::None,
            uri: None,
            iv: None,
            keyformat: None,
            keyformat_versions: None,
        }),
        "AES-128" => {
            let uri = attr(list, "URI")
                .ok_or_else(|| parse_err(line, "EXT-X-KEY METHOD=AES-128 without URI"))?
                .to_owned();
            let iv = match attr(list, "IV") {
                None => None,
                Some(v) => {
                    Some(parse_hex_iv(v).ok_or_else(|| parse_err(line, "malformed EXT-X-KEY IV"))?)
                }
            };
            Ok(Key {
                method: KeyMethod::Aes128,
                uri: Some(uri),
                iv,
                keyformat: attr(list, "KEYFORMAT").map(str::to_owned),
                keyformat_versions: attr(list, "KEYFORMATVERSIONS").map(str::to_owned),
            })
        }
        "SAMPLE-AES" => Err(MediaError::SampleAesUnsupported(format!(
            "line {}: EXT-X-KEY METHOD=SAMPLE-AES (decryption sidecar lands in 0.4)",
            line + 1
        ))),
        other => Err(parse_err(
            line,
            &format!("EXT-X-KEY METHOD {other:?} is not supported"),
        )),
    }
}

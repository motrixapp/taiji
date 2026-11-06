//! Unified format tree + entry classification (per the media spec's
//! entry-classification and format-tree sections; dual-source
//! completion): the probe/build/persist
//! faces the RPC line consumes.
//!
//! * [`classify_entry`] — the sniff-order entry classification
//! (content > extension > Content-Type) with the third outcome
//! beyond manifest/not-media: a **direct media file** routes to the
//! existing HTTP task family (zero new surface);
//! * [`FormatNode`]/[`FormatTree`] — the unified format-tree node
//! (0.3 value domain: what an HLS/DASH manifest makes available;
//! rich fields unlock via the 0.5 bridge) and the tree snapshot —
//! the `media_format` persisted payload and the `getMediaFormats`
//! reply basis (serde: the row stores the tree verbatim);
//! * the probe snapshot identity helpers ([`probe_token`],
//! [`snapshot_url_key`]) — the server-side anti-forgery face: the
//! token is opaque and server-minted; clients can only *name* a
//! token, never hand back a format-tree blob.
//!
//! Everything here is a pure function; fetching is the caller's
//! business.
//!
//! # Node contract (cross-validation of record)
//!
//! The contract spells the node as `{format_id, protocol, ext, resolution, fps,
//! hdr, vcodec, acodec, abr/vbr/tbr, filesize, language, has_audio,
//! has_video}`; [`FormatNode`] carries every one of those (the
//! abr/vbr/tbr triple since `vbr` was added — a serde-default
//! additive, so older `media_format` rows still deserialize) plus
//! one implementation field `uri` (the rendition's resolved playlist/
//! base URL — the download driver's target; the enumeration contract
//! has no need to name it, the pipeline does).
//!
//! **Value domains (canonicalized)**: `protocol`/`kind` ∈ `direct` | `hls` |
//! `dash` (0.3; the 0.5 bridge may add more — the tree itself is
//! source-agnostic, see below); `ext` ∈ the direct-face file
//! extensions (`mp4`, `ts`, …), `vtt` (HLS subtitle renditions), the
//! DASH mimeType-derived containers (`mp4`, `webm`, `ts`), or empty
//! (unknown); `format_id` = the HLS master ordinals (`v0`/`a0`/`s0`)
//! or the **DASH Representation `@id`** verbatim (the
//! `format_id=` escape hatch addresses DASH representations by their
//! own ids; a rep id containing a comma/space cannot be so addressed,
//! a documented limit of the multi-value syntax).
//!
//! # 0.5 bridge seams (seams canonicalized, not implemented here)
//!
//! * **Source-agnostic node**: [`FormatTree`] carries no HLS- or
//! DASH-private fields — every fact rides the node vocabulary
//! above. A bridge's `formats[]` therefore projects onto the same
//! node contract without a tree-shaped fork.
//! * **Sniff-order fourth slot**: after content > extension >
//! Content-Type, the 0.5 feature-gated extractor bridge takes the
//! fourth slot (page-shaped entries → `taiji-ytdlp` trial parse).
//! The seam is this module's [`EntryKind`] — a fourth variant (or a
//! page classification) lands there; `classify_entry`'s three-signal
//! order itself is frozen for 0.3.
//! * **Bridge token/snapshot consumption**: a bridge-produced tree
//! goes through the same server-side `store`/`consume` cache —
//! never a client-supplied blob ("no client-returned format tree"
//! holds for the bridge era too; one anti-forgery posture, one token face).

use serde::{Deserialize, Serialize};

use crate::error::MediaError;
use crate::m3u8::{self, ManifestFlavor, Playlist};

/// Entry classification (the media spec's sniff order): what a URL
/// *is*, decided by the sniff order over the three signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// A manifest (HLS and — since DASH support — DASH: an MPD entry
    /// routes into the DASH line; the per-row judgment-table
    /// refusals [dynamic/DRM/nested sidx] are the parser's explicit
    /// codes, not an entry refusal).
    Manifest(ManifestFlavor),
    /// A direct media file (a media extension or a media Content-Type
    /// with no manifest signature): routes to the existing HTTP task
    /// family — the zero-new-surface rule.
    DirectFile,
    /// No media signature on any signal: `taiji.media.not_media`.
    NotMedia,
}

/// Media file extensions (the direct-link signal; case-insensitive).
const DIRECT_FILE_EXTENSIONS: &[&str] = &[
    "mp4", "m4v", "mov", "ts", "m2ts", "mkv", "webm", "avi", "flv", "m4a", "mp3", "aac", "ogg",
    "opus", "wav", "flac",
];

/// Media Content-Type families (base type, lowercase).
const DIRECT_CONTENT_TYPES: &[&str] = &["video", "audio"];

/// Classify an entry per the sniff order: content signature first, then
/// extension, then Content-Type. A manifest signature wins over any
/// weaker signal; a *media* extension/Content-Type without a manifest
/// signature is a direct file; anything else is not-media.
pub fn classify_entry(
    content: Option<&[u8]>,
    extension: Option<&str>,
    content_type: Option<&str>,
) -> EntryKind {
    // 1. Content: a recognized manifest signature is authoritative.
    if let Some(bytes) = content
        && let Ok(flavor) = m3u8::sniff(Some(bytes), None, None)
    {
        return EntryKind::Manifest(flavor);
    }
    // 2/3. Extension, then Content-Type — but each signal can now say
    // either "manifest" or "direct media file"; the manifest opinion
    // still outranks the direct-file one only when both apply to the
    // *same* signal rank (an .m3u8 extension with an octet-stream
    // Content-Type is a manifest; an .mp4 extension with an mpegurl
    // Content-Type is also a manifest — Content-Type agrees).
    let ext = extension.map(|e| e.rsplit('/').next().unwrap_or(e).to_ascii_lowercase());
    let ctype_base = content_type.map(|c| {
        c.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    });
    let ext_manifest = ext
        .as_deref()
        .and_then(|e| match e.rsplit('.').next().unwrap_or("") {
            "m3u8" | "m3u" => Some(ManifestFlavor::Hls),
            "mpd" => Some(ManifestFlavor::Dash),
            _ => None,
        });
    let type_manifest = ctype_base.as_deref().and_then(|t| match t {
        "application/vnd.apple.mpegurl"
        | "application/x-mpegurl"
        | "audio/mpegurl"
        | "audio/x-mpegurl" => Some(ManifestFlavor::Hls),
        "application/dash+xml" => Some(ManifestFlavor::Dash),
        _ => None,
    });
    match (ext_manifest, type_manifest) {
        (Some(f), _) | (None, Some(f)) => {
            // An extension/type mismatch (mpd ext + mpegurl type) keeps
            // the manifest classification — the content signal (if
            // fetched) already settled it above; here both weak signals
            // point at manifests, the flavor of the stronger (ext) one.
            EntryKind::Manifest(f)
        }
        _ => {
            let direct_ext = ext
                .as_deref()
                .map(|e| DIRECT_FILE_EXTENSIONS.contains(&e.rsplit('.').next().unwrap_or("")))
                .unwrap_or(false);
            let direct_type = ctype_base
                .as_deref()
                .map(|t| {
                    DIRECT_CONTENT_TYPES
                        .iter()
                        .any(|f| t == *f || t.starts_with(&format!("{f}/")))
                })
                .unwrap_or(false);
            if direct_ext || direct_type {
                EntryKind::DirectFile
            } else {
                EntryKind::NotMedia
            }
        }
    }
}

/// One unified format-tree node. 0.3 value domain: the fields an
/// HLS/DASH manifest makes available (filesize/vbr estimates absent —
/// never fabricated; rich metadata unlocks via the 0.5 bridge).
/// `vbr` (the abr/vbr/tbr triple's missing member)
/// is a serde-default addition — older `media_format` rows
/// deserialize with it at 0.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FormatNode {
    /// Stable rendition id. HLS: master ordinals (`v0`, `a0`, `s0` …);
    /// DASH: the Representation `@id` verbatim (the
    /// `format_id=` escape hatch addresses these).
    pub format_id: String,
    /// Transport protocol (`hls`/`dash` 0.3; `direct` on the direct
    /// single-node tree; ism later, bridge sources later still).
    pub protocol: String,
    /// Container/file extension when known (the rendition's dominant
    /// form; unknown = empty).
    pub ext: String,
    /// `WxH` resolution string (video variants; audio = empty).
    pub resolution: String,
    /// Frames per second (unknown = 0).
    pub fps: f64,
    /// VIDEO-RANGE (SDR/PQ/HLG; unknown = empty).
    pub hdr: String,
    /// Video codec (from CODECS; unknown = empty).
    pub vcodec: String,
    /// Audio codec (from CODECS; unknown = empty).
    pub acodec: String,
    /// Peak bitrate bps (BANDWIDTH / @bandwidth; unknown = 0).
    pub tbr: u64,
    /// Average bitrate bps (AVERAGE-BANDWIDTH; unknown = 0).
    pub abr: u64,
    /// Video stream's average bitrate bps (the abr/vbr/tbr triple;
    /// 0.3 manifests carry no per-stream split — 0, never fabricated;
    /// the 0.5 bridge unlocks it). Serde-default additive.
    #[serde(default)]
    pub vbr: u64,
    /// Declared filesize when computable (0.3 HLS/DASH: never — 0).
    pub filesize: u64,
    /// Rendition language (EXT-X-MEDIA LANGUAGE / AdaptationSet@lang;
    /// empty when absent).
    pub language: String,
    /// Carries video.
    pub has_video: bool,
    /// Carries audio.
    pub has_audio: bool,
    /// The rendition's playlist URI (absolute when the manifest URL
    /// resolves it; the download driver's target).
    pub uri: String,
}

/// The resolved format tree snapshot (the probe product / the
/// persisted `media_format` payload). This is what the server caches under a
/// probe token and what `getMediaFormats` returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FormatTree {
    /// The (request) manifest URL, verbatim.
    pub url: String,
    /// Manifest kind (`hls`/`dash`; `direct` on the direct-file
    /// single-node tree — the 0.3 domain of record).
    pub kind: String,
    /// The tree nodes (master-declared order; a plain media-playlist
    /// entry yields the single implicit node).
    pub formats: Vec<FormatNode>,
}

/// Resolution string helper (`320x240`; None stays empty).
fn res_str(res: Option<(u32, u32)>) -> String {
    res.map(|(w, h)| format!("{w}x{h}")).unwrap_or_default()
}

/// Split a CODECS list into (first-video-ish, first-audio-ish). The
/// 0.3 heuristic: `avc`/`hev`/`hvc`/`vp`/`av0` prefixes are video,
/// `mp4a`/`ac-3`/`ec-3`/`opus`/`flac` are audio.
fn split_codecs(codecs: Option<&str>) -> (String, String) {
    let Some(list) = codecs else {
        return (String::new(), String::new());
    };
    let mut v = String::new();
    let mut a = String::new();
    for codec in list.split(',') {
        let c = codec.trim().to_ascii_lowercase();
        if c.starts_with("avc")
            || c.starts_with("hvc")
            || c.starts_with("hev")
            || c.starts_with("vp")
            || c.starts_with("av0")
        {
            if v.is_empty() {
                v = codec.trim().to_string();
            }
        } else if c.starts_with("mp4a")
            || c.starts_with("ac-3")
            || c.starts_with("ec-3")
            || c.starts_with("opus")
            || c.starts_with("flac")
        {
            if a.is_empty() {
                a = codec.trim().to_string();
            }
        }
    }
    (v, a)
}

/// Build the format tree from a parsed manifest (the probe product).
///
/// * master → one node per EXT-X-STREAM-INF variant (video, ordinal
/// ids `vN`) + one node per EXT-X-MEDIA AUDIO rendition (`aN`) and
/// SUBTITLES rendition (`sN`) that carries its own URI;
/// * media playlist → the single implicit node (`v0`).
///
/// `manifest_url` resolves relative rendition URIs (RFC 3986 join).
pub fn build_format_tree(
    manifest_url: &str,
    playlist: &Playlist,
) -> Result<FormatTree, MediaError> {
    let base = taiji_http::reqwest::Url::parse(manifest_url)
        .map_err(|e| MediaError::ManifestParse(format!("manifest url: {e}")))?;
    let resolve = |uri: &str| -> String {
        base.join(uri)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| uri.to_string())
    };
    let mut formats = Vec::new();
    match playlist {
        Playlist::Master(master) => {
            for (i, v) in master.variants.iter().enumerate() {
                let (vcodec, acodec) = split_codecs(v.codecs.as_deref());
                formats.push(FormatNode {
                    format_id: format!("v{i}"),
                    protocol: "hls".into(),
                    ext: String::new(),
                    resolution: res_str(v.resolution),
                    fps: v.frame_rate.unwrap_or(0.0),
                    hdr: v.video_range.clone().unwrap_or_default(),
                    vcodec,
                    acodec,
                    tbr: v.bandwidth,
                    abr: v.average_bandwidth.unwrap_or(0),
                    vbr: 0,
                    filesize: 0,
                    language: String::new(),
                    // A STREAM-INF rendition with an explicit AUDIO
                    // group may be video-only; without one it is
                    // combined (the conservative default: audio
                    // presumed present, the default sort's premise).
                    has_video: true,
                    has_audio: v.audio_group.is_none(),
                    uri: resolve(&v.uri),
                });
            }
            let mut a = 0usize;
            let mut s = 0usize;
            for t in &master.tracks {
                let Some(uri) = &t.uri else {
                    continue;
                };
                match t.track_type {
                    m3u8::TrackType::Audio => {
                        formats.push(FormatNode {
                            format_id: format!("a{a}"),
                            protocol: "hls".into(),
                            ext: String::new(),
                            resolution: String::new(),
                            fps: 0.0,
                            hdr: String::new(),
                            vcodec: String::new(),
                            acodec: String::new(),
                            tbr: 0,
                            abr: 0,
                            vbr: 0,
                            filesize: 0,
                            language: t.language.clone().unwrap_or_default(),
                            has_video: false,
                            has_audio: true,
                            uri: resolve(uri),
                        });
                        a += 1;
                    }
                    m3u8::TrackType::Subtitles => {
                        formats.push(FormatNode {
                            format_id: format!("s{s}"),
                            protocol: "hls".into(),
                            ext: "vtt".into(),
                            resolution: String::new(),
                            fps: 0.0,
                            hdr: String::new(),
                            vcodec: String::new(),
                            acodec: String::new(),
                            tbr: 0,
                            abr: 0,
                            vbr: 0,
                            filesize: 0,
                            language: t.language.clone().unwrap_or_default(),
                            has_video: false,
                            has_audio: false,
                            uri: resolve(uri),
                        });
                        s += 1;
                    }
                    _ => {}
                }
            }
        }
        Playlist::Media(_) => {
            formats.push(FormatNode {
                format_id: "v0".into(),
                protocol: "hls".into(),
                ext: String::new(),
                resolution: String::new(),
                fps: 0.0,
                hdr: String::new(),
                vcodec: String::new(),
                acodec: String::new(),
                tbr: 0,
                abr: 0,
                vbr: 0,
                filesize: 0,
                language: String::new(),
                has_video: true,
                has_audio: true,
                uri: manifest_url.to_string(),
            });
        }
    }
    Ok(FormatTree {
        url: manifest_url.to_string(),
        kind: "hls".into(),
        formats,
    })
}

/// Build the format tree from a parsed MPD (the DASH face
/// of the probe product; the unified three-layer
/// selector resolves over it): period-0 video representations +
/// audio representations as nodes, in declaration order
/// (highest-bandwidth-first remains the policy's runtime pick — the
/// tree keeps declaration order); `format_id` = the Representation
/// `@id` verbatim (the `format_id=` escape hatch's DASH address
/// domain); `ext` = the mimeType-derived container. Text sets are
/// not tree nodes in 0.3 (subtitles ignored in 0.3).
/// `protocol` = `dash`.
pub fn build_format_tree_dash(
    manifest_url: &str,
    mpd: &crate::mpd::Mpd,
) -> Result<FormatTree, MediaError> {
    let base = taiji_http::reqwest::Url::parse(manifest_url)
        .map_err(|e| MediaError::ManifestParse(format!("manifest url: {e}")))?;
    let first = mpd
        .periods
        .first()
        .ok_or_else(|| MediaError::ManifestParse("MPD declares no period".to_string()))?;
    let mut formats = Vec::new();
    for (si, set) in first.adaptation_sets.iter().enumerate() {
        let is_video = set
            .content_type
            .as_deref()
            .or(set.mime_type.as_deref())
            .map(|m| m.to_ascii_lowercase().starts_with("video"))
            .unwrap_or_else(|| {
                set.representations
                    .iter()
                    .any(|r| r.width.is_some() || r.height.is_some())
            });
        let is_audio = !is_video
            && set
                .content_type
                .as_deref()
                .or(set.mime_type.as_deref())
                .map(|m| m.to_ascii_lowercase().starts_with("audio"))
                .unwrap_or(false);
        if !is_video && !is_audio {
            continue;
        }
        for (ri, rep) in set.representations.iter().enumerate() {
            let rep_base = crate::mpd::resolve_rep_base(mpd, manifest_url, 0, si, ri)?;
            let _ = &base;
            let (vcodec, acodec) = split_codecs(rep.codecs.as_deref().or(set.codecs.as_deref()));
            formats.push(FormatNode {
                // The DASH Representation `@id` verbatim (the
                // escape hatch's DASH address domain; ids are
                // spec-unique within a period, a hostile duplicate
                // resolves find-first deterministically).
                format_id: rep.id.clone(),
                protocol: "dash".into(),
                ext: dash_ext_of(rep.mime_type.as_deref().or(set.mime_type.as_deref())),
                resolution: match (rep.width, rep.height) {
                    (Some(w), Some(h)) => format!("{w}x{h}"),
                    (Some(_), None) | (None, Some(_)) => String::new(),
                    _ => match (set.max_width, set.max_height) {
                        (Some(w), Some(h)) => format!("{w}x{h}"),
                        _ => String::new(),
                    },
                },
                fps: rep
                    .frame_rate
                    .as_deref()
                    .and_then(parse_frame_rate)
                    .unwrap_or(0.0),
                hdr: String::new(),
                vcodec,
                acodec,
                tbr: rep.bandwidth,
                abr: 0,
                vbr: 0,
                filesize: 0,
                language: set.lang.clone().unwrap_or_default(),
                has_video: is_video,
                has_audio: is_audio,
                uri: rep_base,
            });
        }
    }
    Ok(FormatTree {
        url: manifest_url.to_string(),
        kind: "dash".into(),
        formats,
    })
}

/// The DASH node's `ext` derivation: the (representation- or set-level)
/// `@mimeType` subtype when it names a known container (`video/mp4` →
/// `mp4`, `video/webm` → `webm`, `video/mp2t` → `ts`); anything else =
/// empty (unknown, never fabricated — the `ext=` predicate only fires
/// on honestly derived values).
fn dash_ext_of(mime: Option<&str>) -> String {
    let Some((_, subtype)) = mime.and_then(|m| m.split_once('/')) else {
        return String::new();
    };
    match subtype.trim().to_ascii_lowercase().as_str() {
        "mp4" => "mp4".to_string(),
        "webm" => "webm".to_string(),
        "mp2t" => "ts".to_string(),
        _ => String::new(),
    }
}

/// `@frameRate` ("30", "30000/1001") → fps.
fn parse_frame_rate(text: &str) -> Option<f64> {
    match text.split_once('/') {
        Some((num, den)) => {
            let n: f64 = num.trim().parse().ok()?;
            let d: f64 = den.trim().parse().ok()?;
            if d == 0.0 {
                return None;
            }
            Some(n / d)
        }
        None => text.trim().parse().ok(),
    }
}

/// Mint an opaque probe token (server-side). The token embeds
/// nothing decodable — 32 hex chars of process randomness. The server
/// maps token → snapshot; a client presenting an unknown token gets
/// the unknown-token face and can never smuggle a format-tree blob in
/// its place.
pub fn probe_token() -> String {
    let mut bytes = [0u8; 16];
    for b in bytes.iter_mut() {
        *b = rand_value();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn rand_value() -> u8 {
    // xorshift over a per-call nanosecond seed + a process counter —
    // token unpredictability only needs server-side uniqueness (the
    // token is a cache key, not a credential: consuming it drives a
    // download the caller already controls via addMedia's URL anyway).
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut x = STATE.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    x ^= std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x2545_F491_4F6C_DD1D);
    x ^= u64::from(std::process::id()) << 32;
    let mut s = if x == 0 { 0x853C_49E6_748F_EA9B } else { x };
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    (s & 0xFF) as u8
}

/// The per-source rate-limit key for the probe face: the
/// URL's scheme://host:port — probes against one origin share one
/// budget. Unparseable URLs (rejected earlier by the fetch face)
/// return the verbatim string (fail-closed: they share the default
/// bucket).
pub fn snapshot_url_key(url: &str) -> String {
    taiji_http::reqwest::Url::parse(url)
        .ok()
        .map(|u| match u.port() {
            Some(p) => format!("{}://{}:{p}", u.scheme(), u.host_str().unwrap_or("")),
            None => format!("{}://{}", u.scheme(), u.host_str().unwrap_or("")),
        })
        .unwrap_or_else(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master(bytes: &str) -> Playlist {
        m3u8::parse_manifest(bytes.as_bytes()).unwrap_or_else(|e| panic!("master parses: {e}"))
    }

    /// Content beats the weaker signals; a direct file routes to the
    /// HTTP family; a no-signal entry is not_media.
    #[test]
    fn entry_classification_order() {
        use ManifestFlavor::Hls;
        // Content wins.
        assert_eq!(
            classify_entry(
                Some(b"#EXTM3U\n#EXT-X-ENDLIST\n"),
                Some("a.mp4"),
                Some("video/mp4")
            ),
            EntryKind::Manifest(Hls)
        );
        // Extension second.
        assert_eq!(
            classify_entry(
                Some(b"<html>hi</html>"),
                Some("list.m3u8"),
                Some("text/html")
            ),
            EntryKind::Manifest(Hls)
        );
        // Content-Type third.
        assert_eq!(
            classify_entry(None, Some("rendition"), Some("application/x-mpegurl")),
            EntryKind::Manifest(Hls)
        );
        // Direct media file (C1 → the HTTP task family).
        assert_eq!(
            classify_entry(Some(b"\x00\x00\x00 ftypisom"), Some("movie.mp4"), None),
            EntryKind::DirectFile
        );
        assert_eq!(
            classify_entry(None, None, Some("audio/mpeg")),
            EntryKind::DirectFile
        );
        // Nothing media-shaped.
        assert_eq!(
            classify_entry(
                Some(b"<html>hi</html>"),
                Some("page.html"),
                Some("text/html")
            ),
            EntryKind::NotMedia
        );
        assert_eq!(classify_entry(None, None, None), EntryKind::NotMedia);
    }

    /// The format tree: video variants + audio/subtitle renditions,
    /// ids stable, URIs resolved against the manifest URL.
    #[test]
    fn master_tree_shape() {
        let pl = master(
            "#EXTM3U\n\
             #EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud\",LANGUAGE=\"en\",NAME=\"EN\",DEFAULT=YES,URI=\"audio/en.m3u8\"\n\
             #EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"sub\",LANGUAGE=\"de\",NAME=\"DE\",URI=\"sub/de.m3u8\"\n\
             #EXT-X-STREAM-INF:BANDWIDTH=2000000,RESOLUTION=1280x720,CODECS=\"avc1.64001f,mp4a.40.2\",FRAME-RATE=30.0,AUDIO=\"aud\"\n\
             hi.m3u8\n\
             #EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=640x360,CODECS=\"avc1.42e00d\"\n\
             lo.m3u8\n",
        );
        let tree = build_format_tree("https://cdn.test/live/master.m3u8?tok=1", &pl)
            .unwrap_or_else(|e| panic!("tree builds: {e}"));
        assert_eq!(tree.kind, "hls");
        assert_eq!(tree.formats.len(), 4, "2 variants + 1 audio + 1 subtitle");
        let v0 = &tree.formats[0];
        assert_eq!(
            (
                v0.format_id.as_str(),
                v0.resolution.as_str(),
                v0.tbr,
                v0.fps
            ),
            ("v0", "1280x720", 2_000_000, 30.0)
        );
        assert_eq!(v0.vcodec, "avc1.64001f");
        assert_eq!(v0.acodec, "mp4a.40.2");
        // An AUDIO-group variant is not presumed combined.
        assert!(v0.has_video && !v0.has_audio);
        assert_eq!(v0.uri, "https://cdn.test/live/hi.m3u8");
        let v1 = &tree.formats[1];
        assert!(v1.has_video && v1.has_audio, "no AUDIO group = combined");
        let a0 = &tree.formats[2];
        assert_eq!((a0.format_id.as_str(), a0.language.as_str()), ("a0", "en"));
        assert_eq!(a0.uri, "https://cdn.test/live/audio/en.m3u8");
        let s0 = &tree.formats[3];
        assert_eq!((s0.format_id.as_str(), s0.ext.as_str()), ("s0", "vtt"));
        // Snapshot round-trips through its serde payload (the
        // media_format row face).
        let json = serde_json::to_string(&tree).unwrap_or_else(|e| panic!("serialize: {e}"));
        let back: FormatTree =
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("deserialize: {e}"));
        assert_eq!(back, tree);
    }

    /// A plain media-playlist entry: the single implicit node.
    #[test]
    fn media_playlist_tree_shape() {
        let pl = master("#EXTM3U\n#EXT-X-TARGETDURATION:1\n#EXTINF:1.0,\ns0.ts\n#EXT-X-ENDLIST\n");
        let tree = build_format_tree("http://x.test/v.m3u8", &pl)
            .unwrap_or_else(|e| panic!("tree builds: {e}"));
        assert_eq!(tree.formats.len(), 1);
        assert_eq!(tree.formats[0].format_id, "v0");
        assert_eq!(tree.formats[0].uri, "http://x.test/v.m3u8");
    }

    /// Tokens are opaque, 32-hex, and unique per mint.
    #[test]
    fn probe_tokens_are_opaque_and_unique() {
        let a = probe_token();
        let b = probe_token();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "server-side cache keys must not collide");
    }

    /// The rate-limit key is origin-scoped (scheme+host+port).
    #[test]
    fn rate_limit_key_is_origin() {
        assert_eq!(
            snapshot_url_key("https://a.test:8443/m.m3u8?x=1"),
            "https://a.test:8443"
        );
        assert_eq!(snapshot_url_key("http://b.test/m.m3u8"), "http://b.test");
    }
}

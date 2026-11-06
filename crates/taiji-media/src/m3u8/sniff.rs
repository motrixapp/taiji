//! Manifest entry sniffing (the media spec's
//! sniff order: content signature > extension > Content-Type).
//!
//! Pure classification — no fetch, no I/O. Each signal independently
//! yields an opinion; the first opinion in the precedence order wins
//! and "no opinion from any signal" is `taiji.media.not_media`.
//! Consequences of the order, as the spec intends:
//!
//! * content that opens with `#EXTM3U` classifies HLS even when the
//! extension/content-type say DASH;
//! * content that carries a `<MPD` root classifies DASH likewise;
//! * content with **no** recognizable signature (an HTML error page,
//! a binary blob) falls through to the weaker signals — an `.m3u8`
//! extension still classifies HLS and the **parser** then rejects a
//! page without an `#EXTM3U` header with `manifest_parse`. The
//! sniffer never guesses a flavor from non-signature bytes.
//!
//! Signature bounds: `#EXTM3U` must be the playlist's first
//! non-BOM line (RFC 8216 §4.3.1.1); `<MPD` is searched within the
//! first 1 KiB behind an optional `<?xml …?>` prolog.

use crate::error::MediaError;

/// Classified manifest flavor (ISM joins in 0.4; until then anything
/// else is not-media).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestFlavor {
    /// HLS (`#EXTM3U` / `.m3u8` / mpegurl Content-Type family).
    Hls,
    /// DASH (`<MPD` / `.mpd` / `application/dash+xml`).
    Dash,
}

/// HLS Content-Type values (parameters stripped, lowercased before
/// comparison — `application/x-mpegurl; charset=utf-8` matches).
const HLS_CONTENT_TYPES: [&str; 4] = [
    "application/vnd.apple.mpegurl",
    "application/x-mpegurl",
    "audio/mpegurl",
    "audio/x-mpegurl",
];

/// DASH Content-Type values.
const DASH_CONTENT_TYPES: [&str; 1] = ["application/dash+xml"];

/// Bytes of leading manifest body the content probe may inspect.
const CONTENT_PROBE_LIMIT: usize = 1024;

/// Classify by the media spec's precedence order.
///
/// * `content` — manifest bytes when already fetched (`None` = not
/// available yet, e.g. a filename-only entry);
/// * `extension` — file extension or a filename (`m3u8`, `.mpd`,
/// `index.m3u8` all work; compared case-insensitively);
/// * `content_type` — raw Content-Type header value.
pub fn sniff(
    content: Option<&[u8]>,
    extension: Option<&str>,
    content_type: Option<&str>,
) -> Result<ManifestFlavor, MediaError> {
    if let Some(bytes) = content {
        if let Some(flavor) = sniff_content(bytes) {
            return Ok(flavor);
        }
    }
    if let Some(flavor) = extension.and_then(flavor_of_extension) {
        return Ok(flavor);
    }
    if let Some(flavor) = content_type.and_then(flavor_of_content_type) {
        return Ok(flavor);
    }
    Err(MediaError::NotMedia(
        "no media signature in content, extension or Content-Type".to_owned(),
    ))
}

/// Content signal: `Some` only on a recognized signature.
fn sniff_content(bytes: &[u8]) -> Option<ManifestFlavor> {
    let probe = &bytes[..bytes.len().min(CONTENT_PROBE_LIMIT)];
    let head = String::from_utf8_lossy(probe);
    let head = head.strip_prefix('\u{feff}').unwrap_or(&head);
    let trimmed = head.trim_start();
    if trimmed.starts_with('#') {
        // HLS signature: first line must be exactly #EXTM3U.
        let first_line = trimmed.lines().next().unwrap_or_default();
        let first_line = first_line.trim_end();
        return (first_line == "#EXTM3U").then_some(ManifestFlavor::Hls);
    }
    if trimmed.starts_with("<MPD") || trimmed.starts_with("<MPD/") {
        return Some(ManifestFlavor::Dash);
    }
    if trimmed.starts_with("<?xml") {
        return head.contains("<MPD").then_some(ManifestFlavor::Dash);
    }
    None
}

/// Extension signal (rightmost dot-segment, lowercased).
fn flavor_of_extension(input: &str) -> Option<ManifestFlavor> {
    let ext = input.rsplit('.').next().unwrap_or_default();
    match ext.to_ascii_lowercase().as_str() {
        "m3u8" | "m3u" => Some(ManifestFlavor::Hls),
        "mpd" => Some(ManifestFlavor::Dash),
        _ => None,
    }
}

/// Content-Type signal (parameters stripped, lowercased).
fn flavor_of_content_type(input: &str) -> Option<ManifestFlavor> {
    let base = input.split(';').next().unwrap_or_default().trim();
    let base = base.to_ascii_lowercase();
    if HLS_CONTENT_TYPES.contains(&base.as_str()) {
        Some(ManifestFlavor::Hls)
    } else if DASH_CONTENT_TYPES.contains(&base.as_str()) {
        Some(ManifestFlavor::Dash)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_content_beats_extension_and_type() {
        let mpd = b"<?xml version=\"1.0\"?>\n<MPD type=\"static\">";
        assert_eq!(
            sniff(Some(mpd), Some("index.m3u8"), Some("application/x-mpegurl")),
            Ok(ManifestFlavor::Dash)
        );
        let hls = b"#EXTM3U\n#EXT-X-ENDLIST\n";
        assert_eq!(
            sniff(Some(hls), Some("list.mpd"), Some("application/dash+xml")),
            Ok(ManifestFlavor::Hls)
        );
    }

    #[test]
    fn fallbacks_and_not_media() {
        assert_eq!(sniff(None, Some("a.M3U8"), None), Ok(ManifestFlavor::Hls));
        assert_eq!(
            sniff(None, None, Some("audio/mpegurl; charset=utf-8")),
            Ok(ManifestFlavor::Hls)
        );
        // A non-signature body falls through to the extension signal.
        assert_eq!(
            sniff(Some(b"<html><body>hi</body></html>"), Some("x.m3u8"), None),
            Ok(ManifestFlavor::Hls)
        );
        assert_eq!(
            sniff(
                Some(b"<html>hi</html>"),
                Some("file.bin"),
                Some("text/html")
            ),
            Err(MediaError::NotMedia(
                "no media signature in content, extension or Content-Type".to_owned()
            ))
        );
    }

    #[test]
    fn signature_shapes() {
        // EXTM3U not on the first line = no content opinion.
        assert_eq!(sniff_content(b"junk\n#EXTM3U\n"), None);
        // BOM-tolerant.
        assert_eq!(
            sniff_content("\u{feff}#EXTM3U\n".as_bytes()),
            Some(ManifestFlavor::Hls)
        );
        // XML prolog further out than the probe window = no opinion.
        let mut long = vec![b' '; CONTENT_PROBE_LIMIT + 8];
        long.extend_from_slice(b"<?xml version=\"1.0\"?><MPD>");
        assert_eq!(sniff_content(&long), None);
    }
}

//! m3u8 negative matrix (the parser's test contract): every explicit
//! refusal named by the parse face — live / SAMPLE-AES / no ENDLIST /
//! not-media / over-limit — plus the structural error paths
//! (truncation, malformed attributes, BYTERANGE chain violations,
//! overflow, key boundary) and the policy error face. Each case
//! asserts the canonical `taiji.media.*` code, not just failure.

use std::fmt::Write as _;

use taiji_media::MediaError;
use taiji_media::m3u8::{
    MAX_MANIFEST_BYTES, MAX_MEDIA_SEGMENTS, Playlist, VariantPolicy, parse_manifest,
    select_variant, sniff,
};

fn err_code(bytes: &[u8]) -> (String, String) {
    match parse_manifest(bytes) {
        Ok(p) => panic!("expected a refusal, parsed {p:?}"),
        Err(e) => (e.code().to_owned(), e.to_string()),
    }
}

/// No EXT-X-ENDLIST → `live_unsupported` (0.3 transitional refusal).
#[test]
fn live_playlist_refused() {
    let text =
        "#EXTM3U\n#EXT-X-TARGETDURATION:10\n#EXT-X-PLAYLIST-TYPE:EVENT\n#EXTINF:10,\ns1.ts\n";
    let (code, msg) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.live_unsupported");
    assert!(msg.contains("EXT-X-ENDLIST"), "{msg}");
}

/// EVENT type without ENDLIST is the same live refusal.
#[test]
fn event_playlist_refused() {
    let text = "#EXTM3U\n#EXT-X-TARGETDURATION:10\n#EXT-X-PLAYLIST-TYPE:EVENT\n#EXTINF:10,\ns1.ts\n#EXTINF:10,\ns2.ts\n";
    let (code, _) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.live_unsupported");
}

/// SAMPLE-AES → `sample_aes_unsupported` (decryption sidecar 0.4).
#[test]
fn sample_aes_refused() {
    let text = "#EXTM3U\n#EXT-X-TARGETDURATION:10\n\
#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"https://k.example/sk\",IV=0x0102030405060708090a0b0c0d0e0f10\n\
#EXTINF:10,\ns1.ts\n#EXT-X-ENDLIST\n";
    let (code, msg) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.sample_aes_unsupported");
    assert!(msg.contains("SAMPLE-AES"), "{msg}");
}

/// EXT-X-SESSION-KEY in a master → `session_key_unsupported`.
#[test]
fn session_key_refused() {
    let text = "#EXTM3U\n\
#EXT-X-SESSION-KEY:METHOD=AES-128,URI=\"https://k.example/session\"\n\
#EXT-X-STREAM-INF:BANDWIDTH=1000\nv1.m3u8\n";
    let (code, _) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.session_key_unsupported");
}

/// EXT-X-I-FRAMES-ONLY in a media playlist → `iframes_unsupported`
/// (the "selected variant contains it" surface: only the selected
/// variant's media playlist is ever parsed).
#[test]
fn iframes_only_media_playlist_refused() {
    let text = "#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-TARGETDURATION:10\n#EXT-X-I-FRAMES-ONLY\n\
#EXTINF:10,\niframe1.ts\n#EXT-X-ENDLIST\n";
    let (code, msg) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.iframes_unsupported");
    assert!(msg.contains("I-FRAMES-ONLY"), "{msg}");
}

/// Sniff with no signal → `not_media` (the sniff order).
#[test]
fn not_media_sniff() {
    let e = match sniff(
        Some(b"<html><body>404</body></html>"),
        Some("page.html"),
        Some("text/html"),
    ) {
        Err(e) => e,
        Ok(f) => panic!("expected not_media, got {f:?}"),
    };
    assert_eq!(e.code(), "taiji.media.not_media");
}

/// 16MiB+1 body → `manifest_too_large` before parsing.
#[test]
fn manifest_body_cap() {
    let oversized = vec![b'#'; MAX_MANIFEST_BYTES + 1];
    let (code, msg) = err_code(&oversized);
    assert_eq!(code, "taiji.media.manifest_too_large");
    assert!(msg.contains("16MiB"), "{msg}");
}

/// 100_001st segment → `manifest_too_large`.
#[test]
fn segment_count_cap() {
    let mut text = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
    for i in 0..=MAX_MEDIA_SEGMENTS {
        let _ = write!(text, "#EXTINF:2,\ns{i}.ts\n");
    }
    text.push_str("#EXT-X-ENDLIST\n");
    let (code, _) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.manifest_too_large");
}

/// Missing #EXTM3U header.
#[test]
fn missing_header() {
    let (code, _) = err_code(b"#EXT-X-TARGETDURATION:10\n#EXTINF:9,\ns1.ts\n#EXT-X-ENDLIST\n");
    assert_eq!(code, "taiji.media.manifest_parse");
}

/// URI line with no preceding EXTINF (and no STREAM-INF).
#[test]
fn uri_without_extinf() {
    let (code, msg) = err_code(b"#EXTM3U\n#EXT-X-TARGETDURATION:10\ns1.ts\n#EXT-X-ENDLIST\n");
    assert_eq!(code, "taiji.media.manifest_parse");
    assert!(msg.contains("EXTINF"), "{msg}");
}

/// Truncation vectors: a pending tag with no following URI.
#[test]
fn truncated_playlists() {
    for (text, needle) in [
        ("#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\n", "EXTINF"),
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\n#EXT-X-BYTERANGE:100\n",
            "EXT-X-BYTERANGE",
        ),
        (
            "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1000\n",
            "EXT-X-STREAM-INF",
        ),
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-DISCONTINUITY\n",
            "EXT-X-DISCONTINUITY",
        ),
    ] {
        let (code, msg) = err_code(text.as_bytes());
        assert_eq!(code, "taiji.media.manifest_parse", "{text}");
        assert!(msg.contains("truncated") && msg.contains(needle), "{msg}");
    }
}

/// BYTERANGE chain: omitted offset with no prior sub-range of the URI.
#[test]
fn byterange_omitted_offset_without_predecessor() {
    let (code, msg) = err_code(
        b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\n#EXT-X-BYTERANGE:100\nfile.ts\n#EXT-X-ENDLIST\n",
    );
    assert_eq!(code, "taiji.media.manifest_parse");
    assert!(msg.contains("no prior sub-range"), "{msg}");
}

/// BYTERANGE chain broken by a whole-resource fetch of the same URI:
/// the next omitted offset has nothing to accumulate from.
#[test]
fn byterange_chain_broken_by_whole_resource() {
    let text = "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
#EXTINF:2,\n#EXT-X-BYTERANGE:100@0\nfile.ts\n\
#EXTINF:2,\nfile.ts\n\
#EXTINF:2,\n#EXT-X-BYTERANGE:100\nfile.ts\n\
#EXT-X-ENDLIST\n";
    let (code, _) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.manifest_parse");
}

/// Checked arithmetic: explicit offsets overflowing u64, and
/// accumulated next-offset overflow — both are parse errors.
#[test]
fn byterange_overflow_is_checked() {
    let over = format!(
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\n#EXT-X-BYTERANGE:2@{}\nfile.ts\n#EXT-X-ENDLIST\n",
        u64::MAX
    );
    let (code, msg) = err_code(over.as_bytes());
    assert_eq!(code, "taiji.media.manifest_parse");
    assert!(msg.contains("overflow"), "{msg}");

    // Accumulation path: seat the cursor at MAX-0… then omit.
    let seat = format!(
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
#EXTINF:2,\n#EXT-X-BYTERANGE:2@{}\nfile.ts\n\
#EXTINF:2,\n#EXT-X-BYTERANGE:1\nfile.ts\n\
#EXT-X-ENDLIST\n",
        u64::MAX - 1
    );
    let (code, msg) = err_code(seat.as_bytes());
    assert_eq!(code, "taiji.media.manifest_parse");
    assert!(msg.contains("overflow"), "{msg}");
}

/// Media-sequence arithmetic near u64::MAX.
#[test]
fn media_sequence_overflow() {
    let text = format!(
        "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:{}\n#EXTINF:2,\ns1.ts\n#EXTINF:2,\ns2.ts\n#EXT-X-ENDLIST\n",
        u64::MAX
    );
    let (code, _) = err_code(text.as_bytes());
    assert_eq!(code, "taiji.media.manifest_parse");
}

/// KEY attribute errors: AES-128 without URI, unknown METHOD,
/// malformed IV.
#[test]
fn key_attribute_errors() {
    for (text, why) in [
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-KEY:METHOD=AES-128\n#EXTINF:2,\ns1.ts\n#EXT-X-ENDLIST\n",
            "AES-128 without URI",
        ),
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-KEY:METHOD=WIDEVINE,URI=\"x\"\n#EXTINF:2,\ns1.ts\n#EXT-X-ENDLIST\n",
            "unknown METHOD",
        ),
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-KEY:METHOD=AES-128,URI=\"k\",IV=0x1234\n#EXTINF:2,\ns1.ts\n#EXT-X-ENDLIST\n",
            "short IV",
        ),
    ] {
        let (code, msg) = err_code(text.as_bytes());
        assert_eq!(code, "taiji.media.manifest_parse", "{why}: {msg}");
    }
}

/// The no-IV half of the MAP-after-KEY boundary: **accepted** since
/// the decrypt line — an ambient AES-128 key with no IV covering a MAP parses,
/// and the IV resolves at decrypt time through the living-draft
/// fallback (the first following segment's absolute sequence; the
/// parse-time rejection was relaxed to admit the draft's third chain
/// form — `keys::build_track_crypto` owns the chain, tested there).
#[test]
fn map_covered_by_key_without_iv_parses_for_the_draft_fallback() {
    let text = "#EXTM3U\n#EXT-X-TARGETDURATION:6\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/mk\"\n\
#EXT-X-MAP:URI=\"init.mp4\"\n\
#EXTINF:6,\nseg1.m4s\n#EXT-X-ENDLIST\n";
    match parse_manifest(text.as_bytes()).unwrap_or_else(|e| panic!("parse: {e}")) {
        Playlist::Media(p) => {
            let key = p
                .init_sections
                .first()
                .and_then(|i| i.key.clone())
                .unwrap_or_else(|| panic!("the ambient key covers the init section"));
            assert_eq!(key.uri.as_deref(), Some("https://k.example/mk"));
            assert_eq!(key.iv, None, "no explicit IV: decrypt-time fallback");
        }
        other => panic!("expected media, got {other:?}"),
    }
}

/// STREAM-INF / MEDIA attribute errors.
#[test]
fn master_attribute_errors() {
    for (text, why) in [
        (
            "#EXTM3U\n#EXT-X-STREAM-INF:RESOLUTION=960x540\nv1.m3u8\n",
            "STREAM-INF without BANDWIDTH",
        ),
        (
            "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=abc\nv1.m3u8\n",
            "malformed BANDWIDTH",
        ),
        (
            "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100,RESOLUTION=960\nv1.m3u8\n",
            "malformed RESOLUTION",
        ),
        (
            "#EXTM3U\n#EXT-X-I-FRAME-STREAM-INF:BANDWIDTH=100\n",
            "I-FRAME-STREAM-INF without URI",
        ),
        (
            "#EXTM3U\n#EXT-X-MEDIA:GROUP-ID=\"a\",NAME=\"n\"\n#EXT-X-STREAM-INF:BANDWIDTH=100\nv1.m3u8\n",
            "EXT-X-MEDIA without TYPE",
        ),
        (
            "#EXTM3U\n#EXT-X-MEDIA:TYPE=SMELL-O-VISION\n#EXT-X-STREAM-INF:BANDWIDTH=100\nv1.m3u8\n",
            "unknown TYPE",
        ),
    ] {
        let (code, msg) = err_code(text.as_bytes());
        assert_eq!(code, "taiji.media.manifest_parse", "{why}: {msg}");
    }
}

/// EXTINF shape errors: no comma, non-numeric, negative duration.
#[test]
fn extinf_errors() {
    for (text, why) in [
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2\ns1.ts\n#EXT-X-ENDLIST\n",
            "no comma",
        ),
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:two,\ns1.ts\n#EXT-X-ENDLIST\n",
            "non-numeric",
        ),
        (
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:-2,\ns1.ts\n#EXT-X-ENDLIST\n",
            "negative",
        ),
    ] {
        let (code, msg) = err_code(text.as_bytes());
        assert_eq!(code, "taiji.media.manifest_parse", "{why}: {msg}");
    }
}

/// Policy face: bad values and empty candidate sets.
#[test]
fn policy_errors() {
    for bad in [
        "best",
        "resolution=",
        "resolution=721.5",
        "bandwidth=1.5x",
        "",
    ] {
        let e = match VariantPolicy::parse(bad) {
            Err(e) => e,
            Ok(p) => panic!("{bad:?} must not parse, got {p:?}"),
        };
        assert_eq!(e.code(), "taiji.media.variant_policy", "{bad:?}");
    }

    // No variant satisfies the cap.
    let master_text = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=6293700,RESOLUTION=1920x1080\nv9.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=2323700,RESOLUTION=960x540\nv5.m3u8\n";
    let m = match parse_manifest(master_text.as_bytes()) {
        Ok(Playlist::Master(m)) => m,
        other => panic!("expected a master, got {other:?}"),
    };
    let e = match select_variant(
        &m,
        &VariantPolicy::parse("resolution=100").unwrap_or_default(),
    ) {
        Err(e) => e,
        Ok(v) => panic!("must refuse, chose {}", v.uri),
    };
    assert_eq!(e.code(), "taiji.media.variant_policy");
    let e = match select_variant(
        &m,
        &VariantPolicy::parse("bandwidth=100").unwrap_or_default(),
    ) {
        Err(e) => e,
        Ok(v) => panic!("must refuse, chose {}", v.uri),
    };
    assert_eq!(e.code(), "taiji.media.variant_policy");

    // Master with rendition rows but no variant: nothing selectable.
    let audio_only = "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"a\",NAME=\"n\",URI=\"a.m3u8\"\n";
    let m = match parse_manifest(audio_only.as_bytes()) {
        Ok(Playlist::Master(m)) => m,
        other => panic!("expected a master, got {other:?}"),
    };
    let e = match select_variant(&m, &VariantPolicy::Highest) {
        Err(e) => e,
        Ok(v) => panic!("must refuse, chose {}", v.uri),
    };
    assert_eq!(e.code(), "taiji.media.variant_policy");
}

/// Unknown METHOD keeps its explicit-error posture under the error
/// type's canonical code map (spot check the full vocabulary landed).
#[test]
fn error_code_vocabulary() {
    let cases = [
        (
            MediaError::NotMedia("x".into()).code(),
            "taiji.media.not_media",
        ),
        (
            MediaError::ManifestTooLarge("x".into()).code(),
            "taiji.media.manifest_too_large",
        ),
        (
            MediaError::LiveUnsupported("x".into()).code(),
            "taiji.media.live_unsupported",
        ),
        (
            MediaError::SampleAesUnsupported("x".into()).code(),
            "taiji.media.sample_aes_unsupported",
        ),
        (
            MediaError::SessionKeyUnsupported("x".into()).code(),
            "taiji.media.session_key_unsupported",
        ),
        (
            MediaError::IframesUnsupported("x".into()).code(),
            "taiji.media.iframes_unsupported",
        ),
        (
            MediaError::ManifestParse("x".into()).code(),
            "taiji.media.manifest_parse",
        ),
        (
            MediaError::VariantPolicy("x".into()).code(),
            "taiji.media.variant_policy",
        ),
    ];
    for (got, want) in cases {
        assert_eq!(got, want);
    }
}

/// RFC 8216 §4.3.3.2/§4.3.3.3 placement: the sequence tags must
/// precede the first segment (a late tag would re-key identities
/// already assigned — the fuzz-found splice case).
#[test]
fn late_sequence_tags_refused() {
    let (code, msg) = err_code(
        b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\ns1.ts\n#EXT-X-MEDIA-SEQUENCE:2680\n#EXT-X-ENDLIST\n",
    );
    assert_eq!(code, "taiji.media.manifest_parse");
    assert!(msg.contains("precede"), "{msg}");
    let (code, _) = err_code(
        b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\ns1.ts\n#EXT-X-DISCONTINUITY-SEQUENCE:5\n#EXT-X-ENDLIST\n",
    );
    assert_eq!(code, "taiji.media.manifest_parse");
}

/// A zero-length BYTERANGE sub-range names no bytes — malformed
/// (fuzz-found degenerate form).
#[test]
fn zero_length_byterange_refused() {
    let (code, msg) = err_code(
        b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\n#EXT-X-BYTERANGE:0@0\nfile.ts\n#EXT-X-ENDLIST\n",
    );
    assert_eq!(code, "taiji.media.manifest_parse");
    assert!(msg.contains("malformed EXT-X-BYTERANGE"), "{msg}");
}

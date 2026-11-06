//! m3u8 golden matrix (the parser's test contract): parse-structure
//! field-by-field assertions over positive vectors — RFC 8216 §8
//! example patterns, Apple public-stream patterns (both modeled, own
//! hosts/durations), the self-built matrix and the parse gate's
//! three vectors. Pure parse tests, runnable on every
//! platform, no network and no ffmpeg.

use std::fmt::Write as _;

use taiji_media::m3u8::{
    ByteRange, KeyMethod, MasterPlaylist, MediaPlaylist, Playlist, TrackType, VariantPolicy,
    byterange_runs, init_section_filename, master_playlist_digest, media_playlist_digest,
    parse_manifest, select_variant, variant_identity,
};

fn media(bytes: &[u8]) -> MediaPlaylist {
    match parse_manifest(bytes) {
        Ok(Playlist::Media(m)) => m,
        other => panic!("expected a media playlist, got {other:?}"),
    }
}

fn master(bytes: &[u8]) -> MasterPlaylist {
    match parse_manifest(bytes) {
        Ok(Playlist::Master(m)) => m,
        other => panic!("expected a master playlist, got {other:?}"),
    }
}

/// RFC 8216 §8.1 pattern: a simple VOD media playlist.
const SIMPLE_VOD: &[u8] = b"#EXTM3U\n\
#EXT-X-TARGETDURATION:10\n\
#EXT-X-VERSION:3\n\
#EXTINF:9.009,\n\
http://media.example.com/first.ts\n\
#EXTINF:9.009,\n\
http://media.example.com/second.ts\n\
#EXTINF:3.003,\n\
http://media.example.com/third.ts\n\
#EXT-X-ENDLIST\n";

#[test]
fn simple_vod_field_by_field() {
    let p = media(SIMPLE_VOD);
    assert_eq!(p.version, Some(3));
    assert_eq!(p.target_duration, Some(10.0));
    assert_eq!(p.media_sequence, 0);
    assert_eq!(p.discontinuity_sequence, 0);
    assert_eq!(p.playlist_type, None);
    assert!(p.endlist, "ENDLIST present");
    assert_eq!(p.segments.len(), 3);
    assert!(p.init_sections.is_empty());
    assert!(p.unknown_tags.is_empty());

    let expect = [
        (0u64, 9.009f64, "http://media.example.com/first.ts"),
        (1, 9.009, "http://media.example.com/second.ts"),
        (2, 3.003, "http://media.example.com/third.ts"),
    ];
    for (seg, (sequence, duration, uri)) in p.segments.iter().zip(expect) {
        assert_eq!(seg.sequence, sequence, "absolute media sequence identity");
        assert_eq!(seg.duration, duration);
        assert_eq!(seg.uri, uri);
        assert_eq!(seg.title, None);
        assert_eq!(seg.byte_range, None);
        assert!(!seg.discontinuity);
        assert_eq!(seg.key, None, "plaintext");
        assert_eq!(seg.map, None);
    }
}

/// RFC 8216 §8.2 pattern (modeled): AES-128 with a non-zero starting
/// media sequence — the segment identity anchor.
const NONZERO_SEQ_AES: &[u8] = b"#EXTM3U\n\
#EXT-X-VERSION:3\n\
#EXT-X-TARGETDURATION:8\n\
#EXT-X-MEDIA-SEQUENCE:2680\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://priv.example.com/key.php?r=52\"\n\
#EXTINF:7.975,\n\
https://priv.example.com/fileSequence2680.ts\n\
#EXTINF:7.941,\n\
https://priv.example.com/fileSequence2681.ts\n\
#EXT-X-ENDLIST\n";

#[test]
fn nonzero_media_sequence_and_key_reference() {
    let p = media(NONZERO_SEQ_AES);
    assert_eq!(p.media_sequence, 2680);
    assert_eq!(p.segments.len(), 2);
    assert_eq!(p.segments[0].sequence, 2680, "identity = absolute value");
    assert_eq!(p.segments[1].sequence, 2681);
    for seg in &p.segments {
        let key = match &seg.key {
            Some(k) => k,
            None => panic!("segment {} must carry the key", seg.sequence),
        };
        assert_eq!(key.method, KeyMethod::Aes128);
        assert_eq!(
            key.uri.as_deref(),
            Some("https://priv.example.com/key.php?r=52"),
            "URI verbatim, query included"
        );
        assert_eq!(key.iv, None, "no explicit IV: derived at decrypt time");
    }
}

/// Vector #2: EXT-X-BYTERANGE omitted offset accumulates per
/// URI in appearance order (RFC 8216 §4.3.2.2; the media spec's
/// errata).
const BYTERANGE_OMITTED: &[u8] = b"#EXTM3U\n\
#EXT-X-VERSION:4\n\
#EXT-X-TARGETDURATION:10\n\
#EXTINF:10,\n\
#EXT-X-BYTERANGE:720@0\n\
file.ts\n\
#EXTINF:10,\n\
#EXT-X-BYTERANGE:720\n\
file.ts\n\
#EXTINF:10,\n\
#EXT-X-BYTERANGE:720\n\
file.ts\n\
#EXT-X-ENDLIST\n";

#[test]
fn byterange_omitted_offset_accumulates() {
    let p = media(BYTERANGE_OMITTED);
    let expect = [
        ByteRange {
            length: 720,
            offset: 0,
            offset_omitted: false,
        },
        ByteRange {
            length: 720,
            offset: 720,
            offset_omitted: true,
        },
        ByteRange {
            length: 720,
            offset: 1440,
            offset_omitted: true,
        },
    ];
    for (seg, want) in p.segments.iter().zip(expect) {
        assert_eq!(seg.byte_range, Some(want), "segment {}", seg.sequence);
    }
}

/// Per-URI accumulation survives an interleaved sub-range of a
/// different resource (the adopted appearance-order form —
/// the stricter RFC reading would forbid it, this form is pinned
/// as the of-record behavior).
#[test]
fn byterange_omitted_offset_accumulates_per_uri_across_interleaves() {
    let text = "#EXTM3U\n#EXT-X-TARGETDURATION:10\n\
#EXTINF:10,\n#EXT-X-BYTERANGE:100@0\na.ts\n\
#EXTINF:10,\n#EXT-X-BYTERANGE:200@500\nb.ts\n\
#EXTINF:10,\n#EXT-X-BYTERANGE:100\na.ts\n\
#EXTINF:10,\n#EXT-X-BYTERANGE:50\nb.ts\n\
#EXT-X-ENDLIST\n";
    let p = media(text.as_bytes());
    let got: Vec<(u64, u64, bool)> = p
        .segments
        .iter()
        .map(|s| match s.byte_range {
            Some(br) => (br.offset, br.length, br.offset_omitted),
            None => panic!("expected a range"),
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (0, 100, false),
            (500, 200, false),
            (100, 100, true),
            (700, 50, true)
        ]
    );
}

/// Vector #1: METHOD=NONE is an explicit reset — after the
/// reset, segments are plaintext (never the retired key), and a later
/// key re-arm applies from its position only (the media spec's
/// errata).
const KEY_NONE_RESET: &[u8] = b"#EXTM3U\n\
#EXT-X-TARGETDURATION:2\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/k1\",IV=0x00000000000000000000000000000001\n\
#EXTINF:2,\ns1.ts\n\
#EXT-X-KEY:METHOD=NONE\n\
#EXTINF:2,\ns2.ts\n\
#EXTINF:2,\ns3.ts\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/k2\",IV=0x00000000000000000000000000000002\n\
#EXTINF:2,\ns4.ts\n\
#EXT-X-ENDLIST\n";

#[test]
fn method_none_is_an_explicit_reset() {
    let p = media(KEY_NONE_RESET);
    assert_eq!(p.segments.len(), 4);
    let key_of = |i: usize| {
        p.segments[i]
            .key
            .as_ref()
            .map(|k| (k.method, k.uri.clone(), k.iv))
    };
    let iv1 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let iv2 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    assert_eq!(
        key_of(0),
        Some((
            KeyMethod::Aes128,
            Some("https://k.example/k1".to_owned()),
            Some(iv1)
        ))
    );
    assert_eq!(
        key_of(1),
        None,
        "explicit reset: plaintext, not the retired key"
    );
    assert_eq!(key_of(2), None, "reset persists until the next KEY");
    assert_eq!(
        key_of(3),
        Some((
            KeyMethod::Aes128,
            Some("https://k.example/k2".to_owned()),
            Some(iv2)
        ))
    );
}

/// Vector #3: the MAP-after-KEY encryption boundary
/// (the media spec's errata). The init section's key is positional: the v8
/// `KEY=` attribute on the MAP, else the ambient EXT-X-KEY at the
/// MAP's position; a KEY declared after the MAP never covers it.
const MAP_AFTER_KEY_AMBIENT: &[u8] = b"#EXTM3U\n\
#EXT-X-VERSION:6\n\
#EXT-X-TARGETDURATION:6\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/mk\",IV=0x0102030405060708090a0b0c0d0e0f10\n\
#EXT-X-MAP:URI=\"init.mp4\"\n\
#EXTINF:6,\nseg1.m4s\n\
#EXT-X-ENDLIST\n";

#[test]
fn map_after_key_is_covered_by_the_ambient_key() {
    let p = media(MAP_AFTER_KEY_AMBIENT);
    assert_eq!(p.init_sections.len(), 1);
    let init = &p.init_sections[0];
    assert_eq!(init.index, 0);
    assert_eq!(init.uri, "init.mp4");
    let key = match &init.key {
        Some(k) => k,
        None => panic!("the ambient AES-128 key declared before the MAP covers the init section"),
    };
    assert_eq!(key.method, KeyMethod::Aes128);
    assert_eq!(key.uri.as_deref(), Some("https://k.example/mk"));
    // Segments under the same ambient key.
    assert_eq!(
        p.segments[0].key.as_ref().map(|k| k.method),
        Some(KeyMethod::Aes128)
    );
    assert_eq!(
        p.segments[0].map,
        Some(0),
        "segment references the init section"
    );
    assert_eq!(init.filename("video"), "init-video-0.mp4");
    assert_eq!(init_section_filename("audio", 2), "init-audio-2.mp4");
}

/// The boundary cuts the other way too: a MAP declared **before** the
/// KEY stays plaintext — the KEY applies to segments from its
/// position, never retroactively to an earlier MAP.
#[test]
fn map_before_key_stays_plaintext() {
    let text = "#EXTM3U\n\
#EXT-X-VERSION:6\n\
#EXT-X-TARGETDURATION:6\n\
#EXT-X-MAP:URI=\"init.mp4\"\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/mk\",IV=0x0102030405060708090a0b0c0d0e0f10\n\
#EXTINF:6,\nseg1.m4s\n\
#EXT-X-ENDLIST\n";
    let p = media(text.as_bytes());
    assert_eq!(
        p.init_sections[0].key, None,
        "positional boundary: plaintext init"
    );
    assert_eq!(
        p.segments[0].key.as_ref().map(|k| k.method),
        Some(KeyMethod::Aes128),
        "segments after the KEY are encrypted"
    );
}

/// v8 `KEY=` attribute on the MAP: the init section carries its own
/// key (here distinct from the ambient media-segment key).
#[test]
fn map_with_own_v8_key_attribute() {
    let text = "#EXTM3U\n\
#EXT-X-VERSION:8\n\
#EXT-X-TARGETDURATION:6\n\
#EXT-X-MAP:URI=\"init.mp4\",BYTERANGE=\"720@0\",KEY=\"METHOD=AES-128,URI=https://k.example/init-key,IV=0x0102030405060708090a0b0c0d0e0f10\"\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/seg-key\",IV=0x0102030405060708090a0b0c0d0e0f11\n\
#EXTINF:6,\nseg1.m4s\n\
#EXT-X-ENDLIST\n";
    let p = media(text.as_bytes());
    let init = &p.init_sections[0];
    assert_eq!(
        init.key.as_ref().map(|k| k.uri.as_deref()),
        Some(Some("https://k.example/init-key"))
    );
    assert_eq!(
        init.byte_range,
        Some(ByteRange {
            length: 720,
            offset: 0,
            offset_omitted: false,
        })
    );
    assert_eq!(
        p.segments[0].key.as_ref().map(|k| k.uri.as_deref()),
        Some(Some("https://k.example/seg-key")),
        "ambient media key is independent of the init key"
    );
}

/// Two MAPs under key rotation: each init section is keyed by the
/// ambient EXT-X-KEY at its own position.
#[test]
fn map_key_boundary_under_rotation() {
    let text = "#EXTM3U\n\
#EXT-X-VERSION:6\n\
#EXT-X-TARGETDURATION:6\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/a\",IV=0x0102030405060708090a0b0c0d0e0f10\n\
#EXT-X-MAP:URI=\"init-a.mp4\"\n\
#EXTINF:6,\nseg-a1.m4s\n\
#EXT-X-DISCONTINUITY\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://k.example/b\",IV=0x0102030405060708090a0b0c0d0e0f11\n\
#EXT-X-MAP:URI=\"init-b.mp4\"\n\
#EXTINF:6,\nseg-b1.m4s\n\
#EXT-X-ENDLIST\n";
    let p = media(text.as_bytes());
    assert_eq!(p.init_sections.len(), 2);
    assert_eq!(p.init_sections[0].index, 0);
    assert_eq!(p.init_sections[1].index, 1, "appearance-order numbering");
    assert_eq!(
        p.init_sections[0].key.as_ref().map(|k| k.uri.as_deref()),
        Some(Some("https://k.example/a"))
    );
    assert_eq!(
        p.init_sections[1].key.as_ref().map(|k| k.uri.as_deref()),
        Some(Some("https://k.example/b"))
    );
    assert_eq!(p.segments[0].map, Some(0));
    assert!(p.segments[1].discontinuity, "discontinuity preserved");
    assert_eq!(p.segments[1].map, Some(1));
}

/// DISCONTINUITY-SEQUENCE, ignored PROGRAM-DATE-TIME, unknown tags
/// recorded by name, CRLF line endings, quoted EXTINF titles, and an
/// unterminated final line.
#[test]
fn discontinuity_unknown_tags_and_line_postures() {
    let text = "#EXTM3U\r\n\
#EXT-X-DISCONTINUITY-SEQUENCE:5\r\n\
#EXT-X-TARGETDURATION:10\r\n\
#EXT-X-PLAYLIST-TYPE:VOD\r\n\
#EXT-X-PROGRAM-DATE-TIME:2026-10-28T10:00:00.000+00:00\r\n\
#EXTINF:9.5,\"title, with comma\"\r\n\
s1.ts\r\n\
#EXT-X-DISCONTINUITY\r\n\
#EXTINF:9.5,\r\n\
s2.ts\n\
#EXT-X-SOME-FUTURE-TAG:x=1\r\n\
#EXTINF:4,\r\n\
s3.ts\n\
#EXT-X-ANOTHER\r\n\
#EXT-X-ENDLIST";
    let p = media(text.as_bytes());
    assert_eq!(p.discontinuity_sequence, 5);
    assert_eq!(p.playlist_type.as_deref(), Some("VOD"));
    assert_eq!(p.segments.len(), 3);
    assert_eq!(p.segments[0].title.as_deref(), Some("title, with comma"));
    assert!(!p.segments[0].discontinuity);
    assert!(p.segments[1].discontinuity, "preserved bit");
    assert!(!p.segments[2].discontinuity);
    assert_eq!(
        p.unknown_tags,
        vec![
            "EXT-X-SOME-FUTURE-TAG".to_owned(),
            "EXT-X-ANOTHER".to_owned()
        ],
        "unknown tags: ignored, recorded by name"
    );
    assert!(p.endlist, "unterminated final ENDLIST line still applies");
}

/// Invalid UTF-8 in a URI: lossy conversion, parse survives.
#[test]
fn lossy_utf8_uri() {
    let mut bytes = b"#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXTINF:2,\nseg".to_vec();
    bytes.extend_from_slice(&[0xff, 0xfe]); // invalid UTF-8 tail
    bytes.extend_from_slice(b".ts\n#EXT-X-ENDLIST\n");
    let p = media(&bytes);
    assert_eq!(p.segments.len(), 1);
    assert_eq!(p.segments[0].uri, "seg\u{fffd}\u{fffd}.ts");
}

/// Master playlist patterned after Apple's public bipbop stream:
/// rendition table + variant table, every recorded field asserted.
const MASTER_APPLE_PATTERN: &[u8] = b"#EXTM3U\n\
#EXT-X-VERSION:6\n\
#EXT-X-INDEPENDENT-SEGMENTS\n\
#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud1\",LANGUAGE=\"eng\",NAME=\"English\",DEFAULT=YES,URI=\"a1/prog_index.m3u8\"\n\
#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID=\"aud1\",LANGUAGE=\"fra\",NAME=\"Francais\"\n\
#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID=\"sub1\",LANGUAGE=\"sp\",NAME=\"Espanol\",URI=\"s1/prog_index.m3u8\"\n\
#EXT-X-STREAM-INF:BANDWIDTH=2323700,AVERAGE-BANDWIDTH=2100000,RESOLUTION=960x540,CODECS=\"mp4a.40.2,avc1.4d401f\",FRAME-RATE=29.970,AUDIO=\"aud1\",SUBTITLES=\"sub1\",CLOSED-CAPTIONS=NONE\n\
v5/prog_index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=6293700,CODECS=\"mp4a.40.2,avc1.640028\",AUDIO=\"aud1\"\n\
v9/prog_index.m3u8\n";

#[test]
fn master_variant_and_rendition_tables() {
    let m = master(MASTER_APPLE_PATTERN);
    assert_eq!(m.version, Some(6));
    assert!(m.independent_segments);
    assert_eq!(m.variants.len(), 2);
    let v5 = &m.variants[0];
    assert_eq!(v5.uri, "v5/prog_index.m3u8");
    assert_eq!(v5.bandwidth, 2_323_700);
    assert_eq!(v5.average_bandwidth, Some(2_100_000));
    assert_eq!(v5.resolution, Some((960, 540)));
    assert_eq!(v5.codecs.as_deref(), Some("mp4a.40.2,avc1.4d401f"));
    assert_eq!(v5.frame_rate, Some(29.97));
    assert_eq!(v5.audio_group.as_deref(), Some("aud1"));
    assert_eq!(v5.subtitles_group.as_deref(), Some("sub1"));
    assert_eq!(v5.closed_captions.as_deref(), Some("NONE"));
    let v9 = &m.variants[1];
    assert_eq!(v9.bandwidth, 6_293_700);
    assert_eq!(v9.resolution, None);

    assert_eq!(m.tracks.len(), 3);
    let eng = &m.tracks[0];
    assert_eq!(eng.track_type, TrackType::Audio);
    assert_eq!(eng.group_id.as_deref(), Some("aud1"));
    assert_eq!(eng.language.as_deref(), Some("eng"));
    assert_eq!(eng.name.as_deref(), Some("English"));
    assert!(eng.default_track);
    assert_eq!(eng.uri.as_deref(), Some("a1/prog_index.m3u8"));
    let fra = &m.tracks[1];
    assert!(!fra.default_track, "DEFAULT absent = NO");
    assert_eq!(fra.uri, None, "rendition without URI = embedded");
    assert_eq!(m.tracks[2].track_type, TrackType::Subtitles);
}

/// Master with an i-frame rendition table (EXT-X-I-FRAME-STREAM-INF,
/// RFC 8216 §4.3.4.3) plus a legacy bare EXT-X-I-FRAMES-ONLY line:
/// the former is a recorded-but-unselectable table, the latter an
/// unknown tag at master level.
#[test]
fn master_with_iframe_renditions() {
    let text = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=1280000\nlow.m3u8\n\
#EXT-X-I-FRAME-STREAM-INF:BANDWIDTH=86000,CODECS=\"avc1.4d401e\",URI=\"iframe-low.m3u8\"\n\
#EXT-X-I-FRAMES-ONLY\n";
    let m = master(text.as_bytes());
    assert_eq!(m.variants.len(), 1, "iframe renditions are not variants");
    assert_eq!(m.iframe_variants.len(), 1);
    assert_eq!(m.iframe_variants[0].uri, "iframe-low.m3u8");
    assert_eq!(m.iframe_variants[0].bandwidth, 86_000);
    assert_eq!(
        m.unknown_tags,
        vec!["EXT-X-I-FRAMES-ONLY".to_owned()],
        "master-level I-FRAMES-ONLY (real-world legacy form) is ignored"
    );
    // The policy never returns an iframe rendition.
    let chosen = match select_variant(&m, &VariantPolicy::Highest) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(chosen.uri, "low.m3u8");
}

/// Mixed malformed input: master tags win the classification, the
/// segment scratch is discarded (documented posture).
#[test]
fn mixed_input_classifies_as_master() {
    let text = "#EXTM3U\n\
#EXT-X-TARGETDURATION:10\n\
#EXTINF:9,\nstray.ts\n\
#EXT-X-STREAM-INF:BANDWIDTH=1000\nv1.m3u8\n";
    let parsed = match parse_manifest(text.as_bytes()) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    };
    assert!(parsed.is_master());
}

/// Transport merge runs (the ≤8 data structure): contiguous same-URI
/// sub-ranges group into one Range-GET run; discontinuity and key
/// rotation break runs; the cap holds.
#[test]
fn byterange_runs_group_and_break() {
    let mut text = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
    text.push_str("#EXT-X-BYTERANGE:100@0\n#EXTINF:2,\nfile.ts\n");
    for i in 1..10u32 {
        let _ = write!(text, "#EXT-X-BYTERANGE:100\n#EXTINF:2,\nfile.ts\n");
        if i == 4 {
            text.push_str("#EXT-X-DISCONTINUITY\n");
        }
        if i == 7 {
            text.push_str(
                "#EXT-X-KEY:METHOD=AES-128,URI=\"k\",IV=0x0102030405060708090a0b0c0d0e0f10\n",
            );
        }
    }
    text.push_str("#EXT-X-ENDLIST\n");
    let p = media(text.as_bytes());
    let runs = byterange_runs(&p);
    assert!(runs.iter().all(|r| r.segments <= 8), "cap holds");
    assert!(
        runs.len() > 1,
        "discontinuity and key rotation must break runs: {runs:?}"
    );
    for run in &runs {
        assert_eq!(run.uri, "file.ts");
        let mut expect_offset = run.offset;
        for i in run.first_segment..run.first_segment + run.segments {
            match p.segments[i].byte_range {
                Some(br) => {
                    assert_eq!(br.offset, expect_offset);
                    expect_offset += br.length;
                }
                None => panic!("run covers a whole-resource segment"),
            }
        }
        assert_eq!(run.length, expect_offset - run.offset);
    }
    let covered: usize = runs.iter().map(|r| r.segments).sum();
    assert_eq!(covered, 10);
    assert_eq!(runs[0].first_segment, 0);
}

/// A URI change or a byte gap breaks runs; whole-resource segments
/// never join a run.
#[test]
fn byterange_runs_break_on_uri_and_gap() {
    let text = "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
#EXT-X-BYTERANGE:100@0\n#EXTINF:2,\na.ts\n\
#EXT-X-BYTERANGE:100\n#EXTINF:2,\na.ts\n\
#EXT-X-BYTERANGE:100@0\n#EXTINF:2,\nb.ts\n\
#EXTINF:2,\nwhole.ts\n\
#EXT-X-BYTERANGE:100@1000\n#EXTINF:2,\na.ts\n\
#EXT-X-BYTERANGE:100@0\n#EXTINF:2,\na.ts\n\
#EXT-X-ENDLIST\n";
    let p = media(text.as_bytes());
    let runs = byterange_runs(&p);
    let shape: Vec<(usize, usize, &str)> = runs
        .iter()
        .map(|r| (r.first_segment, r.segments, r.uri.as_str()))
        .collect();
    assert_eq!(
        shape,
        vec![
            (0, 2, "a.ts"),
            (2, 1, "b.ts"),
            (4, 1, "a.ts"),
            (5, 1, "a.ts")
        ],
        "URI change breaks; gap 200→1000 breaks; whole-resource segment never joins"
    );
}

/// Digest invariance face: query rotation is invisible, structure is
/// not (the recovery surface's foundation).
#[test]
fn digest_query_rotation_invariance() {
    let base = "#EXTM3U\n\
#EXT-X-TARGETDURATION:8\n\
#EXT-X-MEDIA-SEQUENCE:2680\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://priv.example.com/key.php?r=52\"\n\
#EXTINF:7.975,\nhttps://priv.example.com/fileSequence2680.ts?token=aaa\n\
#EXTINF:7.941,\nhttps://priv.example.com/fileSequence2681.ts?token=aaa\n\
#EXT-X-ENDLIST\n";
    let rotated = "#EXTM3U\n\
#EXT-X-TARGETDURATION:8\n\
#EXT-X-MEDIA-SEQUENCE:2680\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"https://priv.example.com/key.php?r=99\"\n\
#EXTINF:7.975,\nhttps://priv.example.com/fileSequence2680.ts?token=zzz&exp=1700000000\n\
#EXTINF:7.941,\nhttps://priv.example.com/fileSequence2681.ts?token=zzz&exp=1700000000\n\
#EXT-X-ENDLIST\n";
    let d1 = media_playlist_digest(&media(base.as_bytes()));
    let d2 = media_playlist_digest(&media(rotated.as_bytes()));
    assert_eq!(d1, d2, "fresh CDN signatures must not change the digest");
    assert_eq!(d1.len(), 64, "SHA-256 hex");

    // Duration sequence change → digest change.
    let retimed = base.replace("7.941", "7.942");
    assert_ne!(d1, media_playlist_digest(&media(retimed.as_bytes())));

    // Segment count change → digest change.
    let grown = base.replacen(
        "#EXT-X-ENDLIST",
        "#EXTINF:2,\nhttps://priv.example.com/fileSequence2682.ts\n#EXT-X-ENDLIST",
        1,
    );
    assert_ne!(d1, media_playlist_digest(&media(grown.as_bytes())));

    // Key dropped (rotation to plaintext) → digest change.
    let plain = base.replace(
        "#EXT-X-KEY:METHOD=AES-128,URI=\"https://priv.example.com/key.php?r=52\"\n",
        "",
    );
    let p = media(plain.as_bytes());
    assert!(p.segments.iter().all(|s| s.key.is_none()));
    assert_ne!(d1, media_playlist_digest(&p));
}

/// Variant identity: path+bandwidth+resolution stable across query
/// rotation, distinct across facts (the media spec's errata).
#[test]
fn variant_identity_face() {
    let a = variant_identity(
        "https://cdn.example/gear5/index.m3u8?sig=aaa",
        2_323_700,
        Some((960, 540)),
    );
    let b = variant_identity(
        "https://cdn.example/gear5/index.m3u8?sig=zzz",
        2_323_700,
        Some((960, 540)),
    );
    assert_eq!(a, b, "signature expiry must not change variant identity");
    assert_eq!(
        a.to_string(),
        "https://cdn.example/gear5/index.m3u8|2323700|960x540"
    );
    let other_bw = variant_identity(
        "https://cdn.example/gear5/index.m3u8",
        6_293_700,
        Some((960, 540)),
    );
    assert_ne!(a, other_bw);
    // The master rows expose the same face.
    let m = master(MASTER_APPLE_PATTERN);
    let id = m.variants[0].identity();
    assert_eq!(id.bandwidth, 2_323_700);
    assert_eq!(id.resolution, Some((960, 540)));
    assert_eq!(id.path, "v5/prog_index.m3u8");
    // Master digest is query-blind: identical structure, re-signed URI.
    let base = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=2323700,RESOLUTION=960x540\nv5/prog_index.m3u8\n\
#EXT-X-STREAM-INF:BANDWIDTH=6293700,RESOLUTION=1920x1080\nv9/prog_index.m3u8\n";
    let re_signed = "#EXTM3U\n\
#EXT-X-STREAM-INF:BANDWIDTH=2323700,RESOLUTION=960x540\nv5/prog_index.m3u8?sig=zz\n\
#EXT-X-STREAM-INF:BANDWIDTH=6293700,RESOLUTION=1920x1080\nv9/prog_index.m3u8?sig=zz\n";
    let d1 = master_playlist_digest(&master(base.as_bytes()));
    let d2 = master_playlist_digest(&master(re_signed.as_bytes()));
    assert_eq!(d1, d2, "master digest is query-blind");
    // And the rich master still digests distinctly from the bare one.
    assert_ne!(d1, master_playlist_digest(&m));
}

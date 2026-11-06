//! DASH golden matrix — the full consumption spectrum (the media
//! spec's verdict table + parse gate): every addressing form expanded field-exact, the
//! template URL cross-check face, the layer judgment, the BaseURL
//! resolution order,
//! the multi-period track model, and the judgment-table negatives
//! (dynamic / DRM any-level / nested sidx / caps / truncated /
//! unknown-element forward compatibility).

use taiji_media::MediaError;
use taiji_media::m3u8::ByteRange;
use taiji_media::mpd;
use taiji_media::trackdl::{TrackLayer, classify_track, layout_known_length};

const URL: &str = "https://cdn.test/v/manifest.mpd";

fn parse(text: &str) -> mpd::Mpd {
    mpd::parse_mpd(text.as_bytes()).unwrap_or_else(|e| panic!("parse: {e}"))
}

fn plan_one(mpd_doc: &mpd::Mpd) -> (mpd::DashPick, mpd::ExpandedTrack) {
    let plan = mpd::plan_dash_tracks(mpd_doc, URL, &Default::default(), &Default::default())
        .unwrap_or_else(|e| panic!("plan: {e}"));
    assert_eq!(plan.tracks.len(), 1, "one video track");
    let pick = plan.picks[0].clone();
    let track = match mpd::expand_representation(mpd_doc, URL, &pick)
        .unwrap_or_else(|e| panic!("expand: {e}"))
    {
        mpd::Expanded::Ready(t) => t,
        mpd::Expanded::DeferredSidx(_) => panic!("expected a ready expansion"),
    };
    (pick, track)
}

// ---------------------------------------------------------------------------
// ① SegmentTemplate $Number$ (@duration form)
// ---------------------------------------------------------------------------

#[test]
fn template_number_duration_golden() {
    let doc = parse(
        r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT6S" profiles="urn:mpeg:dash:profile:isoff-live:2011">
  <Period duration="PT2S">
    <AdaptationSet mimeType="video/mp4" codecs="avc1.64001f">
      <SegmentTemplate timescale="1000" duration="500" startNumber="1"
        initialization="$RepresentationID$/init.mp4"
        media="$RepresentationID$/$Number%05d$.m4s"/>
      <Representation id="v720" bandwidth="750000" width="1280" height="720"/>
      <Representation id="v360" bandwidth="300000" width="640" height="360"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    // Highest-bandwidth policy picks v720 (the policy semantics applied
    // to representations).
    let plan = mpd::plan_dash_tracks(&doc, URL, &Default::default(), &Default::default())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        doc.periods[0].adaptation_sets[plan.picks[0].set].representations[plan.picks[0].rep].id,
        "v720"
    );
    let (_, track) = plan_one(&doc);
    let p = &track.playlist;
    // count = ceil(2s / 0.5s) = 4.
    assert_eq!(p.segments.len(), 4, "4 segments");
    assert_eq!(p.init_sections.len(), 1);
    assert_eq!(
        p.init_sections[0].uri, "https://cdn.test/v/v720/init.mp4",
        "init template cross-check"
    );
    let want = [
        "https://cdn.test/v/v720/00001.m4s",
        "https://cdn.test/v/v720/00002.m4s",
        "https://cdn.test/v/v720/00003.m4s",
        "https://cdn.test/v/v720/00004.m4s",
    ];
    for (i, seg) in p.segments.iter().enumerate() {
        assert_eq!(seg.uri, want[i], "segment {i} URL cross-check");
        assert_eq!(seg.sequence, i as u64, "cross-period ordinal");
        assert!((seg.duration - 0.5).abs() < 1e-9, "duration 0.5s");
        assert_eq!(seg.map, Some(0), "map ordinal 0");
        assert!(!seg.discontinuity);
        assert!(seg.byte_range.is_none(), "no byte info → (b) layer");
    }
    // Layer judgment: Template form → UnknownLength ((b) layer; the
    // "sizes are derivable" errata note rides the module docs).
    assert_eq!(classify_track(p), TrackLayer::UnknownLength);
    // Identity: normalized path + bandwidth + resolution (the shared fn).
    let id = mpd::representation_identity(
        &track.rep_base,
        &doc.periods[0].adaptation_sets[plan.picks[0].set].representations[plan.picks[0].rep],
    );
    assert_eq!(
        id.to_string(),
        "https://cdn.test/v/manifest.mpd|750000|1280x720"
    );
}

#[test]
fn template_nonzero_start_number_and_last_period_remainder() {
    // startNumber=100; the last period without @duration falls back to
    // the presentation-duration remainder (PT10S − PT8S = PT2S → 2
    // segments at 1s).
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT10S">
  <Period duration="PT8S">
    <AdaptationSet id="vid" mimeType="video/mp4">
      <SegmentTemplate timescale="1" duration="1" startNumber="100"
        media="a$Number$.m4s" initialization="i.mp4"/>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
  <Period>
    <AdaptationSet id="vid" mimeType="video/mp4">
      <SegmentTemplate timescale="1" duration="1"
        media="b$Number$.m4s"/>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc);
    assert_eq!(track.playlist.segments.len(), 10, "8 + remainder 2");
    assert_eq!(
        track.playlist.segments[0].uri,
        "https://cdn.test/v/a100.m4s"
    );
    assert_eq!(
        track.playlist.segments[7].uri,
        "https://cdn.test/v/a107.m4s"
    );
    assert_eq!(track.playlist.segments[8].uri, "https://cdn.test/v/b1.m4s");
    assert_eq!(track.playlist.segments[9].uri, "https://cdn.test/v/b2.m4s");
    assert!(track.playlist.segments[8].discontinuity, "period boundary");
}

// ---------------------------------------------------------------------------
// ② SegmentTemplate $Time$ (SegmentTimeline form)
// ---------------------------------------------------------------------------

#[test]
fn template_time_timeline_golden() {
    let doc = parse(
        r#"<MPD type="static">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate timescale="90000" media="t-$Time$.m4s" initialization="init.mp4">
        <SegmentTimeline>
          <S t="0" d="90000" r="2"/>
          <S d="45000"/>
          <S t="270000" d="45000" r="-1"/>
        </SegmentTimeline>
      </SegmentTemplate>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    // r=2 → 3 segments at 90000; the @t-omitted S continues at 270000
    // (90000×3) for one 45000 segment; r=-1 until the period end —
    // no period duration derivable → parse refusal? The last period
    // falls back to mediaPresentationDuration; absent here = an
    // honest error.
    match mpd::expand_representation(&doc, URL, &pick_of(&doc)) {
        Err(e) => assert_eq!(e.code(), "taiji.media.manifest_parse", "{e}"),
        other => panic!("expected the not-derivable refusal, got {other:?}"),
    }

    // Same document with the period duration pinned: r=-1 resolves.
    let doc2 = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT4S">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate timescale="90000" media="t-$Time$.m4s" initialization="init.mp4">
        <SegmentTimeline>
          <S t="0" d="90000" r="2"/>
          <S t="270000" d="45000" r="-1"/>
        </SegmentTimeline>
      </SegmentTemplate>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc2);
    let p = &track.playlist;
    // 3 × 90000 + repeats of 45000 until 360000 (= 4s × 90000): t=270000,
    // 315000 → 2 more; total 5.
    assert_eq!(p.segments.len(), 5);
    let want_times = ["0", "90000", "180000", "270000", "315000"];
    for (i, seg) in p.segments.iter().enumerate() {
        assert!(
            seg.uri.ends_with(&format!("t-{}.m4s", want_times[i])),
            "segment {i}: {}",
            seg.uri
        );
    }
    // $Number$ under timeline addressing = running number from
    // startNumber (verified through the media template below).
    let doc3 = parse(
        r#"<MPD type="static">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate timescale="1" media="n$Number$-t$Time$.m4s">
        <SegmentTimeline><S t="7" d="1" r="1"/></SegmentTimeline>
      </SegmentTemplate>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    let (_, track3) = plan_one(&doc3);
    assert_eq!(track3.playlist.segments.len(), 2);
    assert!(track3.playlist.segments[0].uri.ends_with("n1-t7.m4s"));
    assert!(track3.playlist.segments[1].uri.ends_with("n2-t8.m4s"));
}

fn pick_of(doc: &mpd::Mpd) -> mpd::DashPick {
    mpd::plan_dash_tracks(doc, URL, &Default::default(), &Default::default())
        .unwrap_or_else(|e| panic!("{e}"))
        .picks[0]
        .clone()
}

// ---------------------------------------------------------------------------
// ③ SegmentList + mediaRange → the (a) layer
// ---------------------------------------------------------------------------

#[test]
fn segment_list_media_range_golden() {
    let doc = parse(
        r#"<MPD type="static">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentList timescale="1000" duration="1000">
        <Initialization sourceURL="media.mp4" range="0-999"/>
        <SegmentURL media="media.mp4" mediaRange="1000-1999"/>
        <SegmentURL media="media.mp4" mediaRange="2000-2999"/>
        <SegmentURL media="media.mp4" mediaRange="3000-3999"/>
      </SegmentList>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc);
    let p = &track.playlist;
    assert_eq!(p.segments.len(), 3);
    assert_eq!(p.init_sections.len(), 1);
    assert_eq!(p.init_sections[0].uri, "https://cdn.test/v/media.mp4");
    assert_eq!(
        p.init_sections[0].byte_range,
        Some(ByteRange {
            length: 1000,
            offset: 0,
            offset_omitted: false,
        })
    );
    for (i, seg) in p.segments.iter().enumerate() {
        let offset = 1000 + i as u64 * 1000;
        assert_eq!(
            seg.byte_range,
            Some(ByteRange {
                length: 1000,
                offset,
                offset_omitted: false,
            }),
            "segment {i} mediaRange → length@offset"
        );
        assert_eq!(seg.uri, "https://cdn.test/v/media.mp4");
    }
    // Layer judgment: all byte ranges → the (a) layer; the layout
    // folds the touching same-URI ranges into ONE maximal span.
    assert_eq!(classify_track(p), TrackLayer::KnownLength);
    let layout = layout_known_length(p).unwrap_or_else(|e| panic!("layout: {e}"));
    assert_eq!(layout.total, 3000);
    assert_eq!(layout.spans.len(), 1, "one maximal span");
    assert_eq!(layout.spans[0].offset_if_present(), Some(1000));
    assert_eq!(layout.spans[0].len, 3000);
}

trait SpanOffset {
    fn offset_if_present(&self) -> Option<u64>;
}
impl SpanOffset for taiji_media::FetchSpan {
    fn offset_if_present(&self) -> Option<u64> {
        Some(self.res_offset)
    }
}

// ---------------------------------------------------------------------------
// ④ SegmentBase + single-level sidx
// ---------------------------------------------------------------------------

/// Build a version-0 sidx box (the fixture face shared with the bmff
/// unit tests' layout).
fn sidx_box(timescale: u32, first_offset: u64, refs: &[(bool, u32, u32)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_be_bytes()); // version/flags
    payload.extend_from_slice(&1u32.to_be_bytes()); // reference_ID
    payload.extend_from_slice(&timescale.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes()); // ept
    payload.extend_from_slice(&(first_offset as u32).to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes()); // reserved
    payload.extend_from_slice(&(refs.len() as u16).to_be_bytes());
    for (nested, size, dur) in refs {
        let word = if *nested { 1u32 << 31 } else { 0 } | size;
        payload.extend_from_slice(&word.to_be_bytes());
        payload.extend_from_slice(&dur.to_be_bytes());
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes());
    }
    taiji_media::bmff::box_bytes(b"sidx", payload)
}

#[test]
fn sidx_single_level_materialize_golden() {
    // indexRange 700-…: the fetched bytes carry 100 padding bytes then
    // the sidx (its own length), first_offset 0 → the first media
    // reference starts right past the sidx.
    let sidx = sidx_box(
        1000,
        0,
        &[(false, 1000, 1000), (false, 1500, 1000), (false, 750, 500)],
    );
    // The fetched indexRange typically carries the init section
    // (boxes) then the sidx — model it with a 100-byte free box.
    let mut fetched = taiji_media::bmff::box_bytes(b"free", vec![0u8; 92]);
    assert_eq!(fetched.len(), 100);
    fetched.extend_from_slice(&sidx);
    let sidx_end_in_fetch = fetched.len() as u64;
    let plan = mpd::SidxPlan {
        base: "https://cdn.test/v/media.mp4".to_string(),
        index_range: (700, 700 + fetched.len() as u64 - 1),
        init: Some(mpd::DashInit {
            uri: "https://cdn.test/v/media.mp4".to_string(),
            range: Some(ByteRange {
                length: 700,
                offset: 0,
                offset_omitted: false,
            }),
        }),
        timescale: 1,
    };
    let track =
        mpd::materialize_sidx(&plan, &fetched).unwrap_or_else(|e| panic!("materialize: {e}"));
    let p = &track.playlist;
    assert_eq!(p.segments.len(), 3);
    assert_eq!(p.init_sections.len(), 1);
    assert_eq!(p.init_sections[0].byte_range.map(|b| b.length), Some(700));
    let anchor = 700 + sidx_end_in_fetch;
    let want = [(anchor, 1000), (anchor + 1000, 1500), (anchor + 2500, 750)];
    for (i, seg) in p.segments.iter().enumerate() {
        let br = seg.byte_range.unwrap_or_else(|| panic!("seg {i} range"));
        assert_eq!((br.offset, br.length), want[i], "segment {i} sidx range");
        assert_eq!(seg.uri, plan.base, "single-resource addressing");
        assert_eq!(seg.map, Some(0));
    }
    assert!((p.segments[0].duration - 1.0).abs() < 1e-9);
    assert!((p.segments[2].duration - 0.5).abs() < 1e-9);
    // (a) layer: all ranges known.
    assert_eq!(classify_track(p), TrackLayer::KnownLength);
}

#[test]
fn sidx_nested_reference_type_one_refused() {
    let sidx = sidx_box(1000, 0, &[(true, 100, 1000)]);
    let plan = mpd::SidxPlan {
        base: "https://cdn.test/v/media.mp4".to_string(),
        index_range: (0, sidx.len() as u64 - 1),
        init: None,
        timescale: 1,
    };
    match mpd::materialize_sidx(&plan, &sidx) {
        Err(e) => {
            assert_eq!(e.code(), "taiji.media.sidx_unsupported", "{e}");
            assert!(
                e.to_string().contains("reference_type=1"),
                "the message names the nested form: {e}"
            );
        }
        Ok(_) => panic!("nested sidx must refuse"),
    }
}

#[test]
fn sidx_multi_period_refused_and_no_sidx_refused() {
    // The sidx form inside a multi-period MPD = honest parse refusal.
    let doc = parse(
        r#"<MPD type="static">
  <Period><AdaptationSet mimeType="video/mp4">
    <Representation id="v" bandwidth="1">
      <BaseURL>a.mp4</BaseURL>
      <SegmentBase indexRange="10-99"><Initialization range="0-9"/></SegmentBase>
    </Representation>
  </AdaptationSet></Period>
  <Period><AdaptationSet mimeType="video/mp4">
    <Representation id="v" bandwidth="1"><BaseURL>b.mp4</BaseURL>
      <SegmentBase indexRange="10-99"/></Representation>
  </AdaptationSet></Period>
</MPD>"#,
    );
    match mpd::expand_representation(&doc, URL, &pick_of(&doc)) {
        Err(e) => assert_eq!(e.code(), "taiji.media.manifest_parse", "{e}"),
        Ok(_) => panic!("multi-period sidx must refuse"),
    }
    // indexRange bytes without a sidx box → manifest_parse.
    let plan = mpd::SidxPlan {
        base: "https://cdn.test/v/x.mp4".to_string(),
        index_range: (0, 7),
        init: None,
        timescale: 1,
    };
    assert!(mpd::materialize_sidx(&plan, b"notabox").is_err());
}

// ---------------------------------------------------------------------------
// ⑤ Multi-Period track model
// ---------------------------------------------------------------------------

#[test]
fn multi_period_template_two_inits_golden() {
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT8S">
  <Period id="p1" duration="PT4S">
    <AdaptationSet id="vid" mimeType="video/mp4">
      <SegmentTemplate timescale="1" duration="4" media="p1-$Number$.m4s"
        initialization="p1-init.mp4"/>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
  <Period id="p2" duration="PT4S">
    <AdaptationSet id="vid" mimeType="video/mp4">
      <SegmentTemplate timescale="1" duration="2" media="p2-$Number$.m4s"
        initialization="p2-init.mp4"/>
      <Representation id="v" bandwidth="1"/>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc);
    let p = &track.playlist;
    // Period 1: 1 segment; period 2: 2 segments → 3 total, ordinals
    // 0..3 across periods, $Number$ restarts per period (startNumber
    // default 1 in each period's own template).
    assert_eq!(p.segments.len(), 3);
    assert_eq!(p.segments[0].uri, "https://cdn.test/v/p1-1.m4s");
    assert_eq!(p.segments[1].uri, "https://cdn.test/v/p2-1.m4s");
    assert_eq!(p.segments[2].uri, "https://cdn.test/v/p2-2.m4s");
    // Cross-period ordinals are monotonic; discontinuity exactly on
    // the first segment of the second period.
    assert_eq!(p.segments[0].sequence, 0);
    assert_eq!(p.segments[2].sequence, 2);
    assert!(!p.segments[0].discontinuity);
    assert!(p.segments[1].discontinuity, "period boundary");
    assert!(!p.segments[2].discontinuity);
    // Two init sections in period order; maps follow the boundary.
    assert_eq!(p.init_sections.len(), 2);
    assert_eq!(p.init_sections[0].uri, "https://cdn.test/v/p1-init.mp4");
    assert_eq!(p.init_sections[1].uri, "https://cdn.test/v/p2-init.mp4");
    assert_eq!(p.segments[0].map, Some(0));
    assert_eq!(p.segments[1].map, Some(1));
    assert_eq!(p.segments[2].map, Some(1));
}

#[test]
fn multi_period_shared_init_dedup_id_matching() {
    // Cross-period identity is id-based — the sets carry
    // @id (positional matching was removed: it silently expanded
    // whatever sat at the old coordinates). The SAME initialization
    // URI in both periods dedups to one init section (the find-or-
    // append rule) with no map change at the boundary (the
    // discontinuity bit still marks it).
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT4S">
  <Period duration="PT2S"><AdaptationSet id="vid" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="a-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
  <Period duration="PT2S"><AdaptationSet id="vid" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="b-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc);
    let p = &track.playlist;
    assert_eq!(p.segments.len(), 2);
    assert_eq!(p.init_sections.len(), 1, "shared init deduped");
    assert!(p.segments[1].discontinuity);
    assert_eq!(p.segments[0].map, Some(0));
    assert_eq!(p.segments[1].map, Some(0));
}

/// Cross-period identity negatives: cross-period identity is **id-based** — the
/// positional clamp is gone. A later period whose AdaptationSet @id
/// set differs from the first period's selected set (a different id
/// set, a first-period set with no @id, or a changed Representation
/// @id) is an explicit `manifest_parse` refusal. The pre-fix code
/// silently expanded whatever happened to sit at the old coordinates
/// — the wrong-data risk this tightening removes.
#[test]
fn multi_period_identity_mismatch_refused() {
    // ① The later period's set-id set differs ("vid2"/"aud" where
    // the first period selected "vid") → explicit refusal, never a
    // positional fallback onto the unrelated set.
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT6S">
  <Period duration="PT2S"><AdaptationSet id="vid" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="a-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
  <Period duration="PT2S"><AdaptationSet id="aud" mimeType="audio/mp4">
    <SegmentTemplate timescale="1" duration="2" media="x-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="a" bandwidth="1"/></AdaptationSet></Period>
  <Period duration="PT2S"><AdaptationSet id="vid2" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="b-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
</MPD>"#,
    );
    match mpd::expand_representation(&doc, URL, &pick_of(&doc)) {
        Err(e) => assert_eq!(e.code(), "taiji.media.manifest_parse", "{e}"),
        Ok(_) => panic!("a changed set-id set must refuse, not clamp"),
    }

    // ② The first period's set carries no @id at all — cross-period
    // identity is unmatchable → refusal.
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT4S">
  <Period duration="PT2S"><AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="a-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
  <Period duration="PT2S"><AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="b-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
</MPD>"#,
    );
    match mpd::expand_representation(&doc, URL, &pick_of(&doc)) {
        Err(e) => assert_eq!(e.code(), "taiji.media.manifest_parse", "{e}"),
        Ok(_) => panic!("an id-less first-period set must refuse across periods"),
    }

    // ③ The set recurs but the representation @id changed → refusal.
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT4S">
  <Period duration="PT2S"><AdaptationSet id="vid" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="a-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
  <Period duration="PT2S"><AdaptationSet id="vid" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="b-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="w" bandwidth="1"/></AdaptationSet></Period>
</MPD>"#,
    );
    match mpd::expand_representation(&doc, URL, &pick_of(&doc)) {
        Err(e) => assert_eq!(e.code(), "taiji.media.manifest_parse", "{e}"),
        Ok(_) => panic!("a changed rep id must refuse, not clamp"),
    }

    // ④ The well-formed face stays green: both ids recur verbatim →
    // the expansion proceeds (two segments, boundary discontinuity,
    // the second period's own template).
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT4S">
  <Period duration="PT2S"><AdaptationSet id="vid" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="a-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
  <Period duration="PT2S"><AdaptationSet id="vid" mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="b-$Number$.m4s" initialization="init.mp4"/>
    <Representation id="v" bandwidth="1"/></AdaptationSet></Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc);
    let p = &track.playlist;
    assert_eq!(p.segments.len(), 2);
    assert!(p.segments[1].discontinuity);
    assert_eq!(p.segments[1].uri, "https://cdn.test/v/b-1.m4s");
}

// ---------------------------------------------------------------------------
// ⑥ BaseURL resolution order + plain single-file form
// ---------------------------------------------------------------------------

#[test]
fn baseurl_resolution_order_golden() {
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT2S"><BaseURL>https://mpd.test/root/</BaseURL>
  <Period duration="PT2S"><BaseURL>p/</BaseURL>
    <AdaptationSet mimeType="video/mp4"><BaseURL>set/</BaseURL>
      <SegmentTemplate timescale="1" duration="1" media="seg-$Number$.ts" initialization="init.ts"/>
      <Representation id="v" bandwidth="1"><BaseURL>rep1/</BaseURL></Representation>
      <Representation id="v2" bandwidth="2"><BaseURL>https://abs.test/x/</BaseURL></Representation>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    // rep1: MPD → Period → Set → Representation chain.
    let base = mpd::resolve_rep_base(&doc, URL, 0, 0, 0).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(base, "https://mpd.test/root/p/set/rep1/");
    // An absolute representation BaseURL resets the chain.
    let base2 = mpd::resolve_rep_base(&doc, URL, 0, 0, 1).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(base2, "https://abs.test/x/");
    // The segment URIs ride the resolved base.
    let (_, track) = plan_one(&doc);
    assert_eq!(
        track.playlist.segments[0].uri,
        "https://abs.test/x/seg-1.ts"
    );
}

#[test]
fn plain_baseurl_single_segment() {
    let doc = parse(
        r#"<MPD type="static">
  <Period duration="PT4S"><AdaptationSet mimeType="video/mp4">
    <Representation id="v" bandwidth="1"><BaseURL>movie.mp4</BaseURL></Representation>
  </AdaptationSet></Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc);
    let p = &track.playlist;
    assert_eq!(p.segments.len(), 1, "one whole-resource segment");
    assert_eq!(p.segments[0].uri, "https://cdn.test/v/movie.mp4");
    assert_eq!(p.segments[0].byte_range, None);
    assert!(p.init_sections.is_empty(), "no init knowledge");
    assert_eq!(classify_track(p), TrackLayer::UnknownLength);
}

// ---------------------------------------------------------------------------
// ⑦ Judgment-table negatives at the parse/materialize faces
// ---------------------------------------------------------------------------

#[test]
fn negative_dynamic_refuses() {
    let err = mpd::parse_mpd(
        br#"<MPD type="dynamic"><Period><AdaptationSet mimeType="video/mp4">
        <Representation id="v" bandwidth="1"/></AdaptationSet></Period></MPD>"#,
    )
    .err()
    .unwrap_or_else(|| panic!("expected a refusal"));
    assert_eq!(err.code(), "taiji.media.live_unsupported", "{err}");
    // @type absent = static (the spec default).
    assert!(
        mpd::parse_mpd(
            br#"<MPD><Period><AdaptationSet mimeType="video/mp4">
        <Representation id="v" bandwidth="1"/></AdaptationSet></Period></MPD>"#,
        )
        .is_ok()
    );
}

#[test]
fn negative_content_protection_any_level_any_scheme() {
    for level in ["mpd", "period", "set", "rep"] {
        let (mpd_attr, period_tag, set_tag, rep_tag) = match level {
            "mpd" => ("<ContentProtection/>", "", "", ""),
            "period" => ("", "<ContentProtection cenc:default_KID=\"x\"/>", "", ""),
            "set" => ("", "", "<ContentProtection schemeIdUri=\"urn:x\"/>", ""),
            _ => ("", "", "", "<ContentProtection/>"),
        };
        let text = format!(
            r#"<MPD type="static">{mpd_attr}<Period>{period_tag}<AdaptationSet \
             mimeType="video/mp4">{set_tag}<Representation id="v" bandwidth="1">{rep_tag}\
             </Representation></AdaptationSet></Period></MPD>"#
        );
        match mpd::parse_mpd(text.as_bytes()) {
            Err(e) => assert_eq!(
                e.code(),
                "taiji.media.drm_unsupported",
                "level {level}: {e}"
            ),
            Ok(_) => panic!("level {level} must refuse"),
        }
    }
}

#[test]
fn negative_caps_and_truncated() {
    // Template expansion past the 100k cap → manifest_too_large.
    let doc = String::from(
        r#"<MPD type="static" mediaPresentationDuration="PT100001S"><Period>
  <AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="1" media="s$Number$.m4s" initialization="i.mp4"/>
    <Representation id="v" bandwidth="1"/>
  </AdaptationSet></Period></MPD>"#,
    );
    let parsed = parse(&doc);
    match mpd::expand_representation(&parsed, URL, &pick_of(&parsed)) {
        Err(e) => assert_eq!(e.code(), "taiji.media.manifest_too_large", "{e}"),
        Ok(_) => panic!("over-cap expansion must refuse"),
    }
    // Truncated XML → manifest_parse.
    let err = mpd::parse_mpd(b"<MPD><Period><AdaptationSet>")
        .err()
        .unwrap_or_else(|| panic!("expected a refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_parse", "{err}");
    // Truncated (trailing partial tag) input — fuzz-shaped truncation.
    let text = r#"<MPD type="static"><Period><AdaptationSet mimeType="video/mp4"><SegmentTemplate media="s$"#;
    let err = mpd::parse_mpd(text.as_bytes())
        .err()
        .unwrap_or_else(|| panic!("expected a refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_parse", "{err}");
    // A body over 16MiB refuses at the parse face (defense in depth).
    let mut big = Vec::with_capacity(16 * 1024 * 1024 + 64);
    big.extend_from_slice(b"<MPD>");
    big.extend(std::iter::repeat_n(b' ', 16 * 1024 * 1024));
    big.extend_from_slice(b"</MPD>");
    let err = mpd::parse_mpd(&big)
        .err()
        .unwrap_or_else(|| panic!("expected a refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
}

#[test]
fn negative_doctype_and_unknown_ignored() {
    // DOCTYPE → refused (DTD/entities disabled).
    let err = mpd::parse_mpd(
        b"<!DOCTYPE MPD SYSTEM \"mpd.dtd\"><MPD><Period><AdaptationSet \
          mimeType=\"video/mp4\"><Representation id=\"v\" bandwidth=\"1\"/>\
          </AdaptationSet></Period></MPD>",
    )
    .err()
    .unwrap_or_else(|| panic!("expected a refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_parse", "{err}");
    assert!(err.to_string().contains("DOCTYPE"), "{err}");

    // Unknown elements (whole subtrees) + unknown attributes ignored —
    // forward compatibility; the known vocabulary inside an unknown
    // container stays ignored too.
    let doc = parse(
        r#"<MPD type="static" profiles="urn:unknown" availabilityStartTime="2020-01-01T00:00:00Z">
  <UTCTiming schemeIdUri="urn:mpeg:dash:utc:http-iso:2014" value="https://time.test/t"/>
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <EssentialProperty schemeIdUri="urn:x" value="ignored"><SegmentURL media="never.m4s"/></EssentialProperty>
      <Role value="main"/>
      <SegmentTemplate timescale="1" duration="1" media="s$Number$.m4s" initialization="i.mp4">
        <SegmentTimeline><S t="0" d="1"/><S d="1"/></SegmentTimeline>
      </SegmentTemplate>
      <Representation id="v" bandwidth="1">
        <AudioChannelConfiguration schemeIdUri="urn:mpeg:dash:23003:3:audio_channel_configuration:2011" value="2"/>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>"#,
    );
    let (_, track) = plan_one(&doc);
    assert_eq!(track.playlist.segments.len(), 2, "timeline r default 0");
    assert!(
        track
            .playlist
            .segments
            .iter()
            .all(|s| s.uri.ends_with("s1.m4s") || s.uri.ends_with("s2.m4s")),
        "unknown subtrees never leak addressing: {:?}",
        track.playlist.segments
    );
}

#[test]
fn negative_template_grammar_errors() {
    // Unknown identifier / unpaired $ / bad format tag — parse-class
    // errors naming the token (the template unit tests cover the
    // full grammar; this pins them through the parse face).
    let bad_media = |media: &str| {
        format!(
            r#"<MPD type="static" mediaPresentationDuration="PT2S"><Period>
  <AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="1" media="{media}"/>
    <Representation id="v" bandwidth="1"/>
  </AdaptationSet></Period></MPD>"#
        )
    };
    for media in [
        "$Unknown$",
        "s$Number",
        "$Number%5s$",
        "$RepresentationID%03d$",
    ] {
        let parsed = parse(&bad_media(media));
        match mpd::expand_representation(&parsed, URL, &pick_of(&parsed)) {
            Err(e) => assert_eq!(e.code(), "taiji.media.manifest_parse", "{media}: {e}"),
            Ok(_) => panic!("{media} must refuse"),
        }
    }
    // $$ escape is legal through the parse+expand face.
    let parsed = parse(&bad_media("a$$b-$Number$.m4s"));
    let track = match mpd::expand_representation(&parsed, URL, &pick_of(&parsed))
        .unwrap_or_else(|e| panic!("{e}"))
    {
        mpd::Expanded::Ready(t) => t,
        _ => panic!("ready"),
    };
    assert_eq!(
        track.playlist.segments[0].uri,
        "https://cdn.test/v/a$b-1.m4s"
    );
}

// ---------------------------------------------------------------------------
// ⑧ Digest + policy + plan shapes
// ---------------------------------------------------------------------------

#[test]
fn mpd_digest_query_insensitive_structurally_sensitive() {
    let base = r#"<MPD type="static"><Period><AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="1" media="s$Number$.m4s"/>
    <Representation id="v" bandwidth="1"><BaseURL>rep/?sig=OLD</BaseURL></Representation>
  </AdaptationSet></Period></MPD>"#;
    let fresh = r#"<MPD type="static"><Period><AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="1" media="s$Number$.m4s"/>
    <Representation id="v" bandwidth="1"><BaseURL>rep/?sig=NEW</BaseURL></Representation>
  </AdaptationSet></Period></MPD>"#;
    let d1 = mpd::mpd_digest(&parse(base), URL);
    let d2 = mpd::mpd_digest(&parse(fresh), URL);
    assert_eq!(d1, d2, "a signature rewrite digests identically");
    let changed = r#"<MPD type="static"><Period><AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="2" media="s$Number$.m4s"/>
    <Representation id="v" bandwidth="1"><BaseURL>rep/?sig=NEW</BaseURL></Representation>
  </AdaptationSet></Period></MPD>"#;
    let d3 = mpd::mpd_digest(&parse(changed), URL);
    assert_ne!(d1, d3, "a structural change re-digests");
    assert_eq!(d1.len(), 64, "sha256 hex");
}

#[test]
fn plan_policy_and_audio_chain() {
    let doc_text = || {
        r#"<MPD type="static"><Period>
  <AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="1" media="v$Number$.m4s"/>
    <Representation id="lo" bandwidth="100" height="360"/>
    <Representation id="hi" bandwidth="900" height="1080"/>
  </AdaptationSet>
  <AdaptationSet mimeType="audio/mp4" lang="de">
    <SegmentTemplate timescale="1" duration="1" media="de$Number$.m4s"/>
    <Representation id="a-de" bandwidth="64"/>
  </AdaptationSet>
  <AdaptationSet mimeType="audio/mp4" lang="en">
    <SegmentTemplate timescale="1" duration="1" media="en$Number$.m4s"/>
    <Representation id="a-en" bandwidth="96"/>
  </AdaptationSet>
</Period></MPD>"#
    };
    let doc = parse(doc_text());
    // No language preference → the `en` tier of the chain.
    let plan = mpd::plan_dash_tracks(
        &doc,
        URL,
        &taiji_media::TrackSetConfig {
            audio_lang: None,
            ..Default::default()
        },
        &Default::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.tracks.len(), 2);
    assert_eq!(plan.tracks[0].label, "v");
    assert_eq!(plan.tracks[1].label, "a");
    assert_eq!(plan.tracks[1].language.as_deref(), Some("en"));
    // Requested de → prefix match picks the German set.
    let plan_de = mpd::plan_dash_tracks(
        &doc,
        URL,
        &taiji_media::TrackSetConfig {
            audio_lang: Some("de".to_string()),
            ..Default::default()
        },
        &Default::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan_de.tracks[1].language.as_deref(), Some("de"));
    // Highest-bandwidth video policy picked `hi`.
    let hi = &doc.periods[0].adaptation_sets[plan.picks[0].set].representations[plan.picks[0].rep];
    assert_eq!(hi.id, "hi");
    // Resolution/bandwidth caps apply equivalently (the policy semantics).
    let set = &doc.periods[0].adaptation_sets[0];
    assert_eq!(
        mpd::select_representation_idx(
            set,
            &taiji_media::VariantPolicy::Resolution { height: 720 }
        )
        .unwrap_or_else(|e| panic!("{e}")),
        0,
        "under a 720 cap only `lo` is eligible"
    );
    assert_eq!(
        mpd::select_representation_idx(
            set,
            &taiji_media::VariantPolicy::Bandwidth {
                bits_per_second: 500
            }
        )
        .unwrap_or_else(|e| panic!("{e}")),
        0
    );
    // An empty eligible set is the variant_policy error.
    let err = mpd::select_representation_idx(
        set,
        &taiji_media::VariantPolicy::Bandwidth { bits_per_second: 1 },
    )
    .err()
    .unwrap_or_else(|| panic!("expected a refusal"));
    assert_eq!(err.code(), "taiji.media.variant_policy", "{err}");
}

/// Scope item 2, plan level: the `--media-variant-policy` value a
/// real pipeline threads into `plan_dash_tracks` selects the primary
/// ladder with equivalent effect (highest|resolution=<H>|
/// bandwidth=<B>); a side audio set rides Highest under every
/// policy; an audio-only MPD's set IS the variant face (a
/// resolution cap refuses there exactly as an audio-only HLS master
/// without RESOLUTION does).
#[test]
fn plan_policy_threads_to_the_primary_ladder() {
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT2S"><Period>
  <AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="lo" bandwidth="400000" height="360"/>
    <Representation id="hi" bandwidth="4000000" height="2160"/>
  </AdaptationSet>
  <AdaptationSet mimeType="audio/mp4" lang="en">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="a-lo" bandwidth="64000"/>
    <Representation id="a-hi" bandwidth="320000"/>
  </AdaptationSet>
</Period></MPD>"#,
    );
    let video_pick = |policy: &taiji_media::VariantPolicy| {
        mpd::plan_dash_tracks(&doc, URL, &Default::default(), policy)
            .unwrap_or_else(|e| panic!("plan {policy:?}: {e}"))
    };
    let rep_id = |plan: &mpd::DashTrackPlan, pick: usize| {
        doc.periods[0].adaptation_sets[plan.picks[pick].set].representations[plan.picks[pick].rep]
            .id
            .clone()
    };
    // Highest (default) → the max-bandwidth video rep.
    let plan = video_pick(&taiji_media::VariantPolicy::Highest);
    assert_eq!(rep_id(&plan, 0), "hi");
    // The side audio set rides Highest under every policy.
    assert_eq!(rep_id(&plan, 1), "a-hi");
    // resolution=720 → the 360p rep (the 2160p row is over the cap).
    let plan = video_pick(&taiji_media::VariantPolicy::Resolution { height: 720 });
    assert_eq!(
        rep_id(&plan, 0),
        "lo",
        "the resolution cap picks the 360p rep"
    );
    assert_eq!(
        rep_id(&plan, 1),
        "a-hi",
        "side audio unaffected by the video cap"
    );
    // The expanded track addresses the capped representation.
    let track = match mpd::expand_representation(&doc, URL, &plan.picks[0])
        .unwrap_or_else(|e| panic!("expand: {e}"))
    {
        mpd::Expanded::Ready(t) => t,
        _ => panic!("ready expansion"),
    };
    assert!(
        track.playlist.segments[0].uri.contains("/lo/"),
        "{}",
        track.playlist.segments[0].uri
    );
    // bandwidth=500000 → the 400000 rep (max under the cap).
    let plan = video_pick(&taiji_media::VariantPolicy::Bandwidth {
        bits_per_second: 500_000,
    });
    assert_eq!(rep_id(&plan, 0), "lo");
    // An empty eligible video set is the plan-level variant_policy
    // refusal (never a silent fallback to Highest).
    let err = mpd::plan_dash_tracks(
        &doc,
        URL,
        &Default::default(),
        &taiji_media::VariantPolicy::Bandwidth { bits_per_second: 1 },
    )
    .err()
    .unwrap_or_else(|| panic!("expected a refusal"));
    assert_eq!(err.code(), "taiji.media.variant_policy", "{err}");

    // Audio-only MPD: the audio set is the variant face — a
    // resolution cap finds no measurable-height representation and
    // refuses (the audio-only HLS master mirror).
    let audio_only = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT2S"><Period>
  <AdaptationSet mimeType="audio/mp4" lang="en">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="a-lo" bandwidth="64000"/>
    <Representation id="a-hi" bandwidth="320000"/>
  </AdaptationSet>
</Period></MPD>"#,
    );
    let plan = mpd::plan_dash_tracks(
        &audio_only,
        URL,
        &Default::default(),
        &taiji_media::VariantPolicy::Highest,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        audio_only.periods[0].adaptation_sets[plan.picks[0].set].representations[plan.picks[0].rep]
            .id,
        "a-hi",
        "audio-only Highest picks the top audio rep"
    );
    let err = mpd::plan_dash_tracks(
        &audio_only,
        URL,
        &Default::default(),
        &taiji_media::VariantPolicy::Resolution { height: 720 },
    )
    .err()
    .unwrap_or_else(|| panic!("expected the audio-only resolution refusal"));
    assert_eq!(err.code(), "taiji.media.variant_policy", "{err}");
}

/// The review-block amplification regressions (the standalone-PoC
/// shapes, pinned end to end): a ≤16MiB input must never drive
/// unbounded expansion output — the width cap, the per-URL expansion
/// bound, the per-URI chokepoint bound, the @duration product
/// pre-check and the whole-expansion accumulator each refuse with
/// their canonical code.
#[test]
fn template_amplification_bounds_refuse() {
    let expand_first = |doc: &mpd::Mpd| mpd::expand_representation(doc, URL, &pick_of(doc));
    let mpd_with_media = |media: &str, duration_attr: &str| {
        format!(
            r#"<MPD type="static" {duration_attr}><Period><AdaptationSet \
mimeType="video/mp4"><SegmentTemplate timescale="1" duration="1" media="{media}"/>\
<Representation id="v" bandwidth="1"/></AdaptationSet></Period></MPD>"#
        )
    };

    // (1) The hostile width tag (PoC ①): parse-class refusal — the
    // 9-digit width is padding abuse, refused before any string.
    let doc = parse(&mpd_with_media(
        "seg-$Number%100000000d$.m4s",
        r#"mediaPresentationDuration="PT2S""#,
    ));
    let err = expand_first(&doc)
        .err()
        .unwrap_or_else(|| panic!("expected the width-cap refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_parse", "{err}");
    assert!(err.to_string().contains("over the 64 cap"), "{err}");

    // (2) The long literal @media (PoC ②): the per-URL expansion
    // bound refuses at zero allocation.
    let mut long = String::with_capacity(100 * 1024);
    while long.len() < 100 * 1024 {
        long.push('a');
    }
    let doc = parse(&mpd_with_media(
        &long,
        r#"mediaPresentationDuration="PT2S""#,
    ));
    let err = expand_first(&doc)
        .err()
        .unwrap_or_else(|| panic!("expected the expansion-bound refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
    assert!(
        err.to_string().contains("65536 byte expansion bound"),
        "{err}"
    );

    // (3) The @duration product pre-check: 100k declared segments × a
    // ~1.5KiB template (150MB > the 128MiB budget) refuses at zero
    // allocation — the 400GiB-class product never starts.
    let mut kb = String::new();
    while kb.len() < 1500 {
        kb.push('b');
    }
    let doc = parse(&mpd_with_media(
        &kb,
        r#"mediaPresentationDuration="PT100000S""#,
    ));
    let err = expand_first(&doc)
        .err()
        .unwrap_or_else(|| panic!("expected the product-budget refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
    assert!(err.to_string().contains("expansion budget"), "{err}");

    // (4) The whole-expansion accumulator (the timeline arm rides it
    // alone): 2200 declared S rows × a ~60KiB template = ~132MB of
    // sub-bound URIs — over the budget, refused mid-accumulation.
    let mut tpl = String::with_capacity(60 * 1024);
    while tpl.len() < 60 * 1024 {
        tpl.push('c');
    }
    let mut text = format!(
        r#"<MPD type="static"><Period><AdaptationSet mimeType="video/mp4">\
<SegmentTemplate timescale="1" media="{tpl}.m4s"><SegmentTimeline>"#
    );
    for t in 0..2200u64 {
        text.push_str(&format!(r#"<S t="{}" d="1"/>"#, t * 2));
    }
    text.push_str("</SegmentTimeline></SegmentTemplate>");
    text.push_str(r#"<Representation id="v" bandwidth="1"/></AdaptationSet></Period></MPD>"#);
    let doc = parse(&text);
    let err = expand_first(&doc)
        .err()
        .unwrap_or_else(|| panic!("expected the accumulated-budget refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
    assert!(
        err.to_string().contains("byte budget"),
        "the accumulated budget names the budget: {err}"
    );

    // (5) The per-URI chokepoint behind the template guard: a
    // SegmentList @media URI over the bound (no template involved).
    let mut wide_uri = String::with_capacity(70 * 1024);
    while wide_uri.len() < 70 * 1024 {
        wide_uri.push('d');
    }
    let doc = parse(&format!(
        r#"<MPD type="static"><Period><AdaptationSet mimeType="video/mp4">\
<SegmentList timescale="1" duration="1"><SegmentURL media="{wide_uri}.m4s"/></SegmentList>\
<Representation id="v" bandwidth="1"/></AdaptationSet></Period></MPD>"#
    ));
    let err = expand_first(&doc)
        .err()
        .unwrap_or_else(|| panic!("expected the per-URI bound refusal"));
    assert_eq!(err.code(), "taiji.media.manifest_too_large", "{err}");
    assert!(err.to_string().contains("65536 byte bound"), "{err}");

    // The legit face stays green: the 100k × small-URL carrier is the
    // parse gate's own shape (100000 × ~16B URIs, far under budget).
    let doc = parse(&mpd_with_media(
        "v/$Number%08d$.m4s",
        r#"mediaPresentationDuration="PT100000S""#,
    ));
    match expand_first(&doc).unwrap_or_else(|e| panic!("{e}")) {
        mpd::Expanded::Ready(t) => assert_eq!(t.playlist.segments.len(), 100_000),
        _ => panic!("ready expansion"),
    }
}

#[test]
fn format_tree_dash_shape() {
    let doc = parse(
        r#"<MPD type="static"><Period>
  <AdaptationSet mimeType="video/mp4" codecs="avc1.64001f" lang="en">
    <Representation id="v1" bandwidth="500000" width="640" height="360" frameRate="30"/>
    <Representation id="v2" bandwidth="2000000" width="1920" height="1080" frameRate="30000/1001"/>
  </AdaptationSet>
  <AdaptationSet mimeType="audio/mp4" lang="fr">
    <Representation id="a1" bandwidth="128000" codecs="mp4a.40.2"/>
  </AdaptationSet>
</Period></MPD>"#,
    );
    let tree = taiji_media::build_format_tree_dash(URL, &doc).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(tree.kind, "dash");
    assert_eq!(tree.formats.len(), 3);
    // Format ids are the DASH Representation @ids verbatim
    // (previously they were the `v0`/`a0` ordinals — the escape hatch's
    // DASH address domain drove the change).
    assert_eq!(tree.formats[0].format_id, "v1");
    assert_eq!(tree.formats[0].protocol, "dash");
    assert_eq!(tree.formats[0].ext, "mp4", "mimeType-derived container");
    assert_eq!(tree.formats[0].tbr, 500_000);
    assert_eq!(tree.formats[0].resolution, "640x360");
    assert!((tree.formats[0].fps - 30.0).abs() < 1e-9);
    assert!(
        (tree.formats[1].fps - 30000.0 / 1001.0).abs() < 1e-9,
        "30000/1001"
    );
    assert_eq!(tree.formats[1].vcodec, "avc1.64001f");
    assert_eq!(tree.formats[2].format_id, "a1");
    assert_eq!(tree.formats[2].language, "fr");
    assert!(tree.formats[2].has_audio && !tree.formats[2].has_video);
    // The snapshot round-trips (the media_format row face).
    let json = serde_json::to_string(&tree).unwrap_or_else(|e| panic!("{e}"));
    let back: taiji_media::FormatTree =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, tree);
    // The serde-default vbr seam: an older row (no vbr key)
    // deserializes with vbr = 0 (the media_format row compatibility
    // discipline).
    let legacy = json.replace(",\"vbr\":0", "").replace("\"vbr\":0,", "");
    let legacy_back: Result<taiji_media::FormatTree, _> = serde_json::from_str(&legacy);
    match legacy_back {
        Ok(t) => assert!(t.formats.iter().all(|f| f.vbr == 0)),
        Err(e) => panic!("an older row must still deserialize: {e}"),
    }
}

/// Dual-source field-by-field golden: one logical ladder expressed as an HLS
/// master and as a DASH MPD projects onto the same node facts — the
/// field contract holds per source with the documented
/// source-specific spellings (format_id domain, ext derivation,
/// tbr source), and the three-layer selector resolves equivalently
/// over both trees (the same rung chosen, the same refusal when the
/// predicates empty the set).
#[test]
fn dual_source_tree_and_selector_golden() {
    let hls = r#"#EXTM3U
#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="aud",LANGUAGE="en",NAME="EN",URI="audio/en.m3u8"
#EXT-X-STREAM-INF:BANDWIDTH=400000,RESOLUTION=640x360,CODECS="avc1.64001f",FRAME-RATE=30.0,AUDIO="aud"
lo.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=4000000,RESOLUTION=3840x2160,CODECS="hvc1.640030",FRAME-RATE=30.0,AUDIO="aud"
hi.m3u8
"#
    .to_string();
    let dash = r#"<MPD type="static"><Period>
  <AdaptationSet mimeType="video/mp4" codecs="avc1.64001f">
    <Representation id="lo" bandwidth="400000" width="640" height="360" frameRate="30"/>
    <Representation id="hi" bandwidth="4000000" width="3840" height="2160" frameRate="30"
      codecs="hvc1.640030"/>
  </AdaptationSet>
</Period></MPD>"#
        .to_string();
    let hls_tree = {
        let pl = taiji_media::parse_manifest(hls.as_bytes())
            .unwrap_or_else(|e| panic!("hls parse: {e}"));
        taiji_media::build_format_tree("https://cdn.test/v/master.m3u8", &pl)
            .unwrap_or_else(|e| panic!("hls tree: {e}"))
    };
    let dash_tree = {
        let mpd_doc = mpd::parse_mpd(dash.as_bytes()).unwrap_or_else(|e| panic!("dash parse: {e}"));
        taiji_media::build_format_tree_dash("https://cdn.test/v/manifest.mpd", &mpd_doc)
            .unwrap_or_else(|e| panic!("dash tree: {e}"))
    };
    // The HLS face adds the audio-group rendition as a third node
    // (`a0`); the DASH face here declares no audio set — the ladder
    // rungs are the comparable set.
    assert_eq!(hls_tree.formats.len(), 3);
    assert_eq!(dash_tree.formats.len(), 2);
    for tree in [&hls_tree, &dash_tree] {
        // The 13-field coverage: every video rung populates the
        // whole vocabulary (0.3-unknown members = their zero value,
        // never fabricated).
        for f in tree.formats.iter().filter(|f| f.has_video) {
            assert!(!f.format_id.is_empty());
            assert!(!f.protocol.is_empty());
            assert!(!f.resolution.is_empty());
            assert!(f.fps > 0.0);
            assert!(!f.vcodec.is_empty());
            assert!(f.tbr > 0);
            assert!(f.abr == 0 && f.vbr == 0 && f.filesize == 0);
            assert!(f.has_video);
            assert!(!f.uri.is_empty());
        }
    }
    // The shared ladder facts agree field-for-field (tbr/resolution/
    // fps/vcodec in declaration order).
    for (h, d) in hls_tree.formats.iter().zip(dash_tree.formats.iter()) {
        assert_eq!(h.resolution, d.resolution);
        assert!((h.fps - d.fps).abs() < 1e-9);
        assert_eq!(h.vcodec, d.vcodec);
        assert_eq!(h.tbr, d.tbr);
        assert_eq!(h.has_video, d.has_video);
        assert_eq!(h.has_audio, d.has_audio, "separated video on both sources");
    }
    // The selector resolves equivalently over both sources.
    use taiji_media::selector::{parse_selector, resolve_selection};
    let pick = |tree: &taiji_media::FormatTree, expr: &str| {
        let sel = parse_selector(Some(expr)).unwrap_or_else(|e| panic!("{e}"));
        resolve_selection(tree, &sel)
    };
    for tree in [&hls_tree, &dash_tree] {
        // best = the 2160p rung on both sources.
        let s = pick(tree, "best").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.primary_uri, tree.formats[1].uri);
        // res<=720 caps to the 360p rung on both sources.
        let s = pick(tree, "res<=720").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.primary_uri, tree.formats[0].uri);
        // An empty eligible set refuses with the same face.
        let err = pick(tree, "res<=100")
            .err()
            .unwrap_or_else(|| panic!("the cap must empty the set"));
        assert!(err.to_string().contains("no variant satisfies"), "{err}");
        // The escape hatch addresses each source's own id domain.
        let target = &tree.formats[0].format_id;
        let s = pick(tree, &format!("format_id={target}")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.primary_uri, tree.formats[0].uri);
    }
}

/// Plan level: the selector-resolved DASH plan names the
/// representations by `@id` — the primary overrides the policy ladder,
/// the side audio chain still joins by language, the attached ids
/// become sidecar tracks (deduped by (set, rep)), and an absent id is
/// the honest `variant_policy` refusal.
#[test]
fn plan_dash_tracks_selected_shape() {
    let doc = parse(
        r#"<MPD type="static"><Period>
  <AdaptationSet mimeType="video/mp4">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="lo" bandwidth="400000" height="360"/>
    <Representation id="hi" bandwidth="4000000" height="2160"/>
  </AdaptationSet>
  <AdaptationSet mimeType="audio/mp4" lang="en">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="a-en" bandwidth="64000"/>
  </AdaptationSet>
  <AdaptationSet mimeType="audio/mp4" lang="fr">
    <Representation id="a-fr" bandwidth="96000"/>
  </AdaptationSet>
</Period></MPD>"#,
    );
    let rep_id = |plan: &mpd::DashTrackPlan, i: usize| {
        doc.periods[0].adaptation_sets[plan.picks[i].set].representations[plan.picks[i].rep]
            .id
            .clone()
    };
    // Primary = the named video rung (the policy ladder steps aside).
    let plan = mpd::plan_dash_tracks_selected(
        &doc,
        URL,
        &Default::default(),
        &mpd::DashSelection {
            primary: "lo".into(),
            attached: vec![],
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        plan.tracks.len(),
        2,
        "video rung + the language-chain audio"
    );
    assert_eq!(rep_id(&plan, 0), "lo");
    assert_eq!(plan.tracks[0].label, "v");
    assert_eq!(
        plan.tracks[0].role,
        taiji_media::trackset::TrackRole::Required
    );
    assert_eq!(rep_id(&plan, 1), "a-en", "the side audio rides the chain");
    // An attached second audio rep joins as a sidecar (dedup keeps
    // the chain's own pick out).
    let plan = mpd::plan_dash_tracks_selected(
        &doc,
        URL,
        &Default::default(),
        &mpd::DashSelection {
            primary: "hi".into(),
            attached: vec!["a-fr".into()],
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.tracks.len(), 3);
    assert_eq!(rep_id(&plan, 0), "hi");
    assert_eq!(rep_id(&plan, 1), "a-en");
    assert_eq!(rep_id(&plan, 2), "a-fr");
    assert_eq!(plan.tracks[2].label, "x-a0");
    assert_eq!(
        plan.tracks[2].role,
        taiji_media::trackset::TrackRole::Sidecar,
        "the grading rule: the explicitly attached side stream degrades, never fails"
    );
    // Attaching the rep the chain already picked dedups (no x-a twin).
    let plan = mpd::plan_dash_tracks_selected(
        &doc,
        URL,
        &Default::default(),
        &mpd::DashSelection {
            primary: "hi".into(),
            attached: vec!["a-en".into()],
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        plan.tracks.len(),
        2,
        "the a-en attachment deduped onto the chain pick"
    );
    // Audio-only selection: the named audio rep IS the variant face.
    let plan = mpd::plan_dash_tracks_selected(
        &doc,
        URL,
        &Default::default(),
        &mpd::DashSelection {
            primary: "a-fr".into(),
            attached: vec![],
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.tracks.len(), 1);
    assert_eq!(rep_id(&plan, 0), "a-fr");
    assert_eq!(plan.tracks[0].label, "v");
    assert_eq!(plan.tracks[0].kind.as_str(), "audio");
    // An absent id = the honest refusal (the tree-face resolution
    // error's code; never a silent policy fallback).
    for bad in [
        mpd::DashSelection {
            primary: "nope".into(),
            attached: vec![],
        },
        mpd::DashSelection {
            primary: "lo".into(),
            attached: vec!["nope".into()],
        },
    ] {
        let err = mpd::plan_dash_tracks_selected(&doc, URL, &Default::default(), &bad)
            .err()
            .unwrap_or_else(|| panic!("an absent id must refuse: {:?}", bad));
        assert_eq!(err.code(), "taiji.media.variant_policy", "{err}");
    }
}

#[test]
fn error_display_carries_codes_verbatim() {
    // The three judgment-table codes: code() and Display agree (the
    // core/rpc legs pin the same strings).
    for (err, code) in [
        (
            MediaError::LiveUnsupported("dynamic".to_string()),
            "taiji.media.live_unsupported",
        ),
        (
            MediaError::DrmUnsupported("cp".to_string()),
            "taiji.media.drm_unsupported",
        ),
        (
            MediaError::SidxUnsupported("nested".to_string()),
            "taiji.media.sidx_unsupported",
        ),
    ] {
        assert_eq!(err.code(), code);
        assert!(
            err.to_string().starts_with(&format!("{code}:")),
            "Display embeds the code: {err}"
        );
    }
}

/// A review-pass addition: a **multi-video-set** MPD (the common
/// multi-codec ladder — one AdaptationSet per codec family) routes by
/// the primary's OWN set kind. The tree exposes every video set's
/// reps as selectable nodes and `find_rep_by_id` searches all video
/// sets, so `best` / `codec!=` / `format_id=` all reach set-2 picks.
/// Red form of record (pre-fix): `primary_is_video` compared the
/// pick's set index against the FIRST video set's `position()` — a
/// set-2 pick planned as `kind=audio` (a video archive under an audio
/// label) with the language-chain audio silently skipped.
#[test]
fn plan_dash_tracks_selected_multi_video_set() {
    let doc = parse(
        r#"<MPD type="static" mediaPresentationDuration="PT1.45S"><Period>
  <AdaptationSet mimeType="video/mp4" codecs="avc1.64001f">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="av-lo" bandwidth="400000" width="640" height="360"/>
  </AdaptationSet>
  <AdaptationSet mimeType="video/mp4" codecs="hvc1.640030">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="hev-lo" bandwidth="800000" width="1280" height="720"/>
  </AdaptationSet>
  <AdaptationSet mimeType="audio/mp4" lang="en">
    <SegmentTemplate timescale="1" duration="1"
      initialization="$RepresentationID$/init.mp4" media="$RepresentationID$/$Number$.m4s"/>
    <Representation id="a-en" bandwidth="64000"/>
  </AdaptationSet>
</Period></MPD>"#,
    );
    let rep_id = |plan: &mpd::DashTrackPlan, i: usize| {
        doc.periods[0].adaptation_sets[plan.picks[i].set].representations[plan.picks[i].rep]
            .id
            .clone()
    };
    // The escape hatch naming the SECOND video set's rung: a video
    // face — track 0 kind video + the language-chain audio joins.
    let plan = mpd::plan_dash_tracks_selected(
        &doc,
        URL,
        &Default::default(),
        &mpd::DashSelection {
            primary: "hev-lo".into(),
            attached: vec![],
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(plan.tracks.len(), 2, "the video face + the audio chain");
    assert_eq!(rep_id(&plan, 0), "hev-lo");
    assert_eq!(plan.tracks[0].label, "v");
    assert_eq!(plan.tracks[0].kind.as_str(), "video");
    assert_eq!(
        rep_id(&plan, 1),
        "a-en",
        "the audio chain joins a set-2 pick"
    );

    // The whole selector space reaches set-2 picks over the tree:
    // `best` (the hevc rung outranks the avc one) and `codec!=avc1`
    // both resolve into the same video-face plan.
    use taiji_media::selector::{parse_selector, resolve_selection};
    let tree =
        taiji_media::build_format_tree_dash(URL, &doc).unwrap_or_else(|e| panic!("tree: {e}"));
    for expr in ["best", "codec!=avc1", "format_id=hev-lo"] {
        let sel = parse_selector(Some(expr)).unwrap_or_else(|e| panic!("{expr}: {e}"));
        let s = resolve_selection(&tree, &sel).unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert_eq!(s.chosen_ids, vec!["hev-lo".to_string()], "{expr}");
        let plan = mpd::plan_dash_tracks_selected(
            &doc,
            URL,
            &Default::default(),
            &mpd::DashSelection {
                primary: s.chosen_ids[0].clone(),
                attached: vec![],
            },
        )
        .unwrap_or_else(|e| panic!("{expr}: {e}"));
        assert_eq!(plan.tracks.len(), 2, "{expr}: the video face");
        assert_eq!(plan.tracks[0].kind.as_str(), "video", "{expr}");
        assert_eq!(rep_id(&plan, 1), "a-en", "{expr}: the audio chain joins");
    }
}

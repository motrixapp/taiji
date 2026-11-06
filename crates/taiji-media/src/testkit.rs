//! Test-kit: the shared fMP4 source-builder fixtures (the synthesis
//! qualification matrix + the e2e mock faces). This is a **test
//! fixture face, not a product API** — published so the cross-crate
//! integration tests (taiji-core's media task e2e) consume
//! the same wire-form builders as taiji-media's own tests; the
//! `tests/common` module re-exports it unchanged.

#![allow(dead_code)]

pub fn u16b(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
pub fn u32b(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
pub fn u64b(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
pub fn i32b(v: i32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// One box: size + type + payload.
pub fn bxf(typ: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&u32b((8 + payload.len()) as u32));
    out.extend_from_slice(typ);
    out.extend_from_slice(payload);
    out
}

fn fullbox(verflags: u32, rest: &[u8]) -> Vec<u8> {
    let mut v = u32b(verflags);
    v.extend_from_slice(rest);
    v
}

/// A real baseline 320x240 H.264 SPS/PPS pair (well-known bytes —
/// keeps ffprobe's codec face honest on the dual-run).
pub const SPS: &[u8] = &[
    0x67, 0x42, 0xC0, 0x1E, 0xDA, 0x01, 0x40, 0x16, 0xEC, 0x04, 0x40, 0x00, 0x00, 0x03, 0x00, 0x40,
    0x00, 0x00, 0x0C, 0xA3, 0xC5, 0x8B, 0xA8,
];
pub const PPS: &[u8] = &[0x68, 0xCE, 0x3C, 0x80];

/// `avcC` box from SPS/PPS.
pub fn avcc() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x01, 0x42, 0xC0, 0x1E, 0xFF, 0xE1]); // cfg + sps len hi/lo placeholder
    let sps_len = SPS.len() as u16;
    p.extend_from_slice(&u16b(sps_len));
    p.extend_from_slice(SPS);
    p.push(0x01);
    p.extend_from_slice(&u16b(PPS.len() as u16));
    p.extend_from_slice(PPS);
    bxf(b"avcC", &p)
}

/// An `avc1` sample entry (width/height in pixels).
pub fn avc1_entry(width: u16, height: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0u8; 6]); // reserved
    p.extend_from_slice(&u16b(1)); // data_reference_index
    p.extend_from_slice(&u16b(0)); // pre_defined
    p.extend_from_slice(&[0u8; 12]); // reserved
    p.extend_from_slice(&u16b(width));
    p.extend_from_slice(&u16b(height));
    p.extend_from_slice(&u32b(0x0048_0000)); // horiz 72 dpi
    p.extend_from_slice(&u32b(0x0048_0000)); // vert
    p.extend_from_slice(&[0u8; 4]); // reserved
    p.extend_from_slice(&u16b(1)); // frame count
    p.extend_from_slice(&[0u8; 32]); // compressor name
    p.extend_from_slice(&u16b(0x0018)); // depth
    p.extend_from_slice(&i32b(-1)); // pre_defined
    p.extend_from_slice(&avcc());
    bxf(b"avc1", &p)
}

/// A minimal AAC-LC `esds` payload (44.1 kHz stereo, ASC 0x1210).
pub fn esds() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&fullbox(0, &[])); // esds fullbox
    // ES_Descriptor (0x03) len 0x20+... minimal form
    p.extend_from_slice(&[0x03, 0x19, 0x00, 0x00, 0x00]); // tag, len, ES_ID+flags
    p.extend_from_slice(&[0x04, 0x11, 0x40, 0x15]); // DecoderConfigDescriptor
    p.extend_from_slice(&u32b(5000)); // avg bitrate
    p.extend_from_slice(&[0x05, 0x02, 0x12, 0x10]); // ASC 0x1210
    p.extend_from_slice(&[0x06, 0x01, 0x02]); // SLConfig
    bxf(b"esds", &p)
}

/// An `mp4a` sample entry (channels / sample rate).
pub fn mp4a_entry(channels: u16, rate: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0u8; 6]);
    p.extend_from_slice(&u16b(1)); // data_reference_index
    p.extend_from_slice(&[0u8; 8]); // reserved
    p.extend_from_slice(&u16b(channels));
    p.extend_from_slice(&u16b(16)); // sample size
    p.extend_from_slice(&u16b(0)); // pre_defined
    p.extend_from_slice(&u16b(0)); // reserved
    p.extend_from_slice(&u32b((rate as u32) << 16));
    p.extend_from_slice(&esds());
    bxf(b"mp4a", &p)
}

/// Which kind of init to build.
pub struct InitSpec {
    pub handler: [u8; 4],
    pub stsd_entry: Vec<u8>,
    pub timescale: u32,
    pub track_id: u32,
    pub width_height: Option<(u16, u16)>,
}

/// Build an init segment (ftyp + moov: single trak + mvex/trex).
pub fn build_init(spec: &InitSpec) -> Vec<u8> {
    let mut moov_payload = Vec::new();
    // mvhd v0.
    let mut mvhd = Vec::new();
    mvhd.extend_from_slice(&fullbox(0, &[]));
    mvhd.extend_from_slice(&u32b(0)); // ctime
    mvhd.extend_from_slice(&u32b(0)); // mtime
    mvhd.extend_from_slice(&u32b(1000)); // timescale
    mvhd.extend_from_slice(&u32b(0)); // duration
    mvhd.extend_from_slice(&u32b(0x0001_0000)); // rate
    mvhd.extend_from_slice(&u16b(0x0100)); // volume
    mvhd.extend_from_slice(&u16b(0));
    mvhd.extend_from_slice(&[0u8; 8]);
    mvhd.extend_from_slice(&unity_matrix());
    mvhd.extend_from_slice(&[0u8; 24]);
    mvhd.extend_from_slice(&u32b(2)); // next_track_id
    moov_payload.extend_from_slice(&bxf(b"mvhd", &mvhd));
    // trak.
    let mut trak = Vec::new();
    let mut tkhd = Vec::new();
    tkhd.extend_from_slice(&fullbox(0x0000_0003, &[]));
    tkhd.extend_from_slice(&u32b(0));
    tkhd.extend_from_slice(&u32b(0));
    tkhd.extend_from_slice(&u32b(spec.track_id));
    tkhd.extend_from_slice(&u32b(0));
    tkhd.extend_from_slice(&u32b(0)); // duration
    tkhd.extend_from_slice(&[0u8; 8]);
    tkhd.extend_from_slice(&u16b(0));
    tkhd.extend_from_slice(&u16b(0));
    tkhd.extend_from_slice(&u16b(0));
    tkhd.extend_from_slice(&u16b(0));
    tkhd.extend_from_slice(&unity_matrix());
    let (w, h) = spec.width_height.unwrap_or((0, 0));
    tkhd.extend_from_slice(&u32b((w as u32) << 16));
    tkhd.extend_from_slice(&u32b((h as u32) << 16));
    trak.extend_from_slice(&bxf(b"tkhd", &tkhd));
    // mdia.
    let mut mdia = Vec::new();
    let mut mdhd = Vec::new();
    mdhd.extend_from_slice(&fullbox(0, &[]));
    mdhd.extend_from_slice(&u32b(0));
    mdhd.extend_from_slice(&u32b(0));
    mdhd.extend_from_slice(&u32b(spec.timescale));
    mdhd.extend_from_slice(&u32b(0));
    mdhd.extend_from_slice(&u16b(0x55c4));
    mdhd.extend_from_slice(&u16b(0));
    mdia.extend_from_slice(&bxf(b"mdhd", &mdhd));
    let mut hdlr = Vec::new();
    hdlr.extend_from_slice(&fullbox(0, &[]));
    hdlr.extend_from_slice(&u32b(0));
    hdlr.extend_from_slice(&spec.handler);
    hdlr.extend_from_slice(&[0u8; 12]);
    mdia.extend_from_slice(&bxf(b"hdlr", &hdlr));
    // minf: vmhd|smhd + dinf + stbl.
    let mut minf = Vec::new();
    if spec.handler == *b"vide" {
        minf.extend_from_slice(&bxf(b"vmhd", &fullbox(1, &[0u8; 8])));
    } else {
        let mut smhd = fullbox(0, &u16b(0));
        smhd.extend_from_slice(&u16b(0));
        minf.extend_from_slice(&bxf(b"smhd", &smhd));
    }
    let url = bxf(b"url ", &fullbox(1, &[]));
    let mut dref = fullbox(0, &[]);
    dref.extend_from_slice(&u32b(1));
    dref.extend_from_slice(&url);
    minf.extend_from_slice(&bxf(b"dinf", &bxf(b"dref", &dref)));
    // stbl: stsd + empty tables (the fragment line fills them).
    let mut stsd = fullbox(0, &[]);
    stsd.extend_from_slice(&u32b(1));
    stsd.extend_from_slice(&spec.stsd_entry);
    let mut stbl = Vec::new();
    stbl.extend_from_slice(&bxf(b"stsd", &stsd));
    stbl.extend_from_slice(&bxf(b"stts", &fullbox(0, &u32b(0))));
    // stsc with zero entries.
    let mut stsc = fullbox(0, &[]);
    stsc.extend_from_slice(&u32b(0));
    stbl.extend_from_slice(&bxf(b"stsc", &stsc));
    let mut stsz = fullbox(0, &[]);
    stsz.extend_from_slice(&u32b(0));
    stsz.extend_from_slice(&u32b(0));
    stbl.extend_from_slice(&bxf(b"stsz", &stsz));
    stbl.extend_from_slice(&bxf(b"stco", &fullbox(0, &u32b(0))));
    minf.extend_from_slice(&bxf(b"stbl", &stbl));
    mdia.extend_from_slice(&bxf(b"minf", &minf));
    trak.extend_from_slice(&bxf(b"mdia", &mdia));
    moov_payload.extend_from_slice(&bxf(b"trak", &trak));
    // mvex/trex.
    let mut trex = Vec::new();
    trex.extend_from_slice(&fullbox(0, &[]));
    trex.extend_from_slice(&u32b(spec.track_id));
    trex.extend_from_slice(&u32b(1)); // default_sample_description_index
    trex.extend_from_slice(&u32b(0));
    trex.extend_from_slice(&u32b(0));
    trex.extend_from_slice(&u32b(0));
    let mvex = bxf(b"mvex", &bxf(b"trex", &trex));
    moov_payload.extend_from_slice(&mvex);

    let mut out = Vec::new();
    out.extend_from_slice(&bxf(
        b"ftyp",
        &[b"isom".as_slice(), &u32b(1), b"isom", b"mp41"].concat(),
    ));
    out.extend_from_slice(&bxf(b"moov", &moov_payload));
    out
}

fn unity_matrix() -> Vec<u8> {
    [
        u32b(0x0001_0000),
        u32b(0),
        u32b(0),
        u32b(0),
        u32b(0x0001_0000),
        u32b(0),
        u32b(0),
        u32b(0),
        u32b(0x4000_0000),
    ]
    .concat()
}

/// One sample's trun fields.
pub struct FixtureSample {
    pub duration: u32,
    pub size: u32,
    pub sync: bool,
    pub cts: i32,
}

/// Build one media segment (moof + mdat). `data_offset` resolves with
/// default-base-is-moof semantics: samples start right after the moof.
pub fn build_segment(
    track_id: u32,
    seq: u32,
    base_decode_time: u64,
    samples: &[FixtureSample],
    payload: &[u8],
) -> Vec<u8> {
    let mut traf = Vec::new();
    // tfhd: default-base-is-moof (flags bit 17 → fullbox word
    // 0x0002_0000 with version 0 — corrected in review to match
    // ISO/IEC 14496-12 §8.8.7; the pre-fix word 0x0020_0000 set bit
    // 21 and made every fixture internally consistent with the
    // reader's same-wrong constant, blinding the suite to real
    // encoder output) + track_id.
    let mut tfhd = fullbox(0x0002_0000, &[]);
    tfhd.extend_from_slice(&u32b(track_id));
    traf.extend_from_slice(&bxf(b"tfhd", &tfhd));
    // tfdt v1.
    let mut tfdt = fullbox(0x0100_0000, &[]);
    tfdt.extend_from_slice(&u64b(base_decode_time));
    traf.extend_from_slice(&bxf(b"tfdt", &tfdt));
    // trun: data-offset + per-sample duration/size/flags/cts.
    let flags = 0x001 | 0x100 | 0x200 | 0x400 | 0x800;
    let mut trun = fullbox(flags, &[]);
    trun.extend_from_slice(&u32b(samples.len() as u32));
    trun.extend_from_slice(&i32b(0)); // data_offset placeholder
    for s in samples {
        trun.extend_from_slice(&u32b(s.duration));
        trun.extend_from_slice(&u32b(s.size));
        let sample_flags: u32 = if s.sync { 0x0200_0000 } else { 0x0101_0000 };
        trun.extend_from_slice(&u32b(sample_flags));
        trun.extend_from_slice(&u32b(s.cts as u32));
    }
    traf.extend_from_slice(&bxf(b"trun", &trun));
    // mfhd + moof.
    let mfhd = bxf(b"mfhd", &fullbox(0, &u32b(seq)));
    let moof_len = 8 + mfhd.len() + 8 + traf.len();
    // Patch the trun data_offset (moof-relative): samples begin after
    // the mdat header that follows the moof (moof size + 8).
    let patched = {
        let mut t = trun.clone();
        let pos = t.len() - samples.len() * 16 - 4;
        t[pos..pos + 4].copy_from_slice(&i32b((moof_len + 8) as i32));
        t
    };
    let mut traf_final = Vec::new();
    traf_final.extend_from_slice(&bxf(b"tfhd", &tfhd));
    traf_final.extend_from_slice(&bxf(b"tfdt", &tfdt));
    traf_final.extend_from_slice(&bxf(b"trun", &patched));
    let moof = bxf(
        b"moof",
        &[mfhd.as_slice(), bxf(b"traf", &traf_final).as_slice()].concat(),
    );
    assert_eq!(moof.len(), moof_len, "moof length prediction");
    let mdat = bxf(b"mdat", payload);
    [moof, mdat].concat()
}

/// The tfhd anchor form a fixture segment uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TfhdBase {
    /// `default-base-is-moof` (the dominant real-world per-segment
    /// form; every pre-existing fixture uses it).
    DefaultBaseIsMoof,
    /// An explicit `base-data-offset` whose value is the
    /// segment-**file**-relative offset of the segment's own mdat
    /// payload (ISO/IEC 14496-12 §8.8.7 — file-absolute, not
    /// archive-absolute once segments are concatenated). `styp`
    /// prefixes the file when set (pinned file-boundary form: the
    /// file start precedes the moof).
    ExplicitBase { styp: bool },
}

/// Build one media segment with a chosen tfhd anchor form (see
/// [`build_segment`] for the default-base-is-moof form).
pub fn build_segment_base(
    track_id: u32,
    seq: u32,
    base_decode_time: u64,
    samples: &[FixtureSample],
    payload: &[u8],
    anchor: TfhdBase,
) -> Vec<u8> {
    match anchor {
        TfhdBase::DefaultBaseIsMoof => {
            build_segment(track_id, seq, base_decode_time, samples, payload)
        }
        TfhdBase::ExplicitBase { styp } => {
            // tfhd flags 0x1 = base-data-offset present (u64 follows
            // track_id); trun data_offset 0 (base == first sample).
            let build = |base_value: u64| -> Vec<u8> {
                let mut traf = Vec::new();
                let mut tfhd = fullbox(0x1, &[]);
                tfhd.extend_from_slice(&u32b(track_id));
                tfhd.extend_from_slice(&u64b(base_value));
                traf.extend_from_slice(&bxf(b"tfhd", &tfhd));
                let mut tfdt = fullbox(0x0100_0000, &[]);
                tfdt.extend_from_slice(&u64b(base_decode_time));
                traf.extend_from_slice(&bxf(b"tfdt", &tfdt));
                let flags = 0x001 | 0x100 | 0x200 | 0x400 | 0x800;
                let mut trun = fullbox(flags, &[]);
                trun.extend_from_slice(&u32b(samples.len() as u32));
                trun.extend_from_slice(&i32b(0)); // data_offset: base-relative
                for s in samples {
                    trun.extend_from_slice(&u32b(s.duration));
                    trun.extend_from_slice(&u32b(s.size));
                    let sample_flags: u32 = if s.sync { 0x0200_0000 } else { 0x0101_0000 };
                    trun.extend_from_slice(&u32b(sample_flags));
                    trun.extend_from_slice(&u32b(s.cts as u32));
                }
                traf.extend_from_slice(&bxf(b"trun", &trun));
                let mfhd = bxf(b"mfhd", &fullbox(0, &u32b(seq)));
                let moof = bxf(
                    b"moof",
                    &[mfhd.as_slice(), bxf(b"traf", &traf).as_slice()].concat(),
                );
                let mdat = bxf(b"mdat", payload);
                let mut out = Vec::new();
                if styp {
                    // Segment-type box: brand list isom/mp41.
                    out.extend_from_slice(&bxf(
                        b"styp",
                        &[b"isom".as_slice(), &u32b(0), b"mp41"].concat(),
                    ));
                }
                out.extend_from_slice(&moof);
                out.extend_from_slice(&mdat);
                out
            };
            // Measure with a placeholder base (the u64 field keeps the
            // length stable), then rebuild with the file-relative mdat
            // payload offset (the mdat is the last box, so its payload
            // starts at len - payload.len()).
            let probe = build(0);
            let mdat_payload_off_in_file = probe.len() - payload.len();
            build(mdat_payload_off_in_file as u64)
        }
    }
}

/// A video init spec (avc1 320x240, 1000 timescale).
pub fn video_init_spec() -> InitSpec {
    InitSpec {
        handler: *b"vide",
        stsd_entry: avc1_entry(320, 240),
        timescale: 1000,
        track_id: 1,
        width_height: Some((320, 240)),
    }
}

/// An audio init spec (mp4a stereo 44.1k, 44100 timescale).
pub fn audio_init_spec() -> InitSpec {
    InitSpec {
        handler: *b"soun",
        stsd_entry: mp4a_entry(2, 44_100),
        timescale: 44_100,
        track_id: 1,
        width_height: None,
    }
}

/// Deterministic fake sample payloads (opaque bytes; fine for
/// audio/native faces).
pub fn sample_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add(i as u8).wrapping_mul(3))
        .collect()
}

/// A structurally valid AVCC H.264 sample: 4-byte NAL length prefix
/// (avcC lengthSizeMinusOne=3) + one NAL unit (keyframe header 0x65 /
/// inter 0x41; filler bytes avoid 00 00 0x start-code emulation). The
/// ffmpeg fallback's `-c copy` parses NAL framing even without
/// decodable frames — opaque garbage bytes would drop the stream.
pub fn avcc_sample(keyframe: bool, size: usize) -> Vec<u8> {
    let nal_len = size.saturating_sub(4).max(8);
    let mut out = Vec::with_capacity(nal_len + 4);
    out.extend_from_slice(&(nal_len as u32).to_be_bytes());
    out.push(if keyframe { 0x65 } else { 0x41 });
    for i in 0..nal_len.saturating_sub(1) {
        out.push(0x40 | ((i % 32) as u8));
    }
    out
}

/// Build a whole track (init + archive of N moof/mdat segments).
pub fn build_track(
    spec: &InitSpec,
    segment_count: usize,
    samples_per_segment: usize,
) -> (Vec<u8>, Vec<u8>) {
    let (init, archive, _spans) = build_track_spans(spec, segment_count, samples_per_segment);
    (init, archive)
}

/// [`build_track`] plus the **exact per-segment spans** inside the
/// archive (the caller-side ledger shape the fold consumes).
pub fn build_track_spans(
    spec: &InitSpec,
    segment_count: usize,
    samples_per_segment: usize,
) -> (Vec<u8>, Vec<u8>, Vec<crate::bmff::SegmentSpan>) {
    let init = build_init(spec);
    let per_sample = if spec.handler == *b"vide" { 33 } else { 1024 };
    let mut archive = Vec::new();
    let mut spans = Vec::new();
    let mut decode_time = 0u64;
    for seq in 0..segment_count as u32 {
        let samples: Vec<FixtureSample> = (0..samples_per_segment)
            .map(|i| FixtureSample {
                duration: per_sample,
                size: 512,
                sync: i == 0,
                cts: if spec.handler == *b"vide" && i == 1 {
                    33
                } else {
                    0
                },
            })
            .collect();
        let payload: Vec<u8> = samples
            .iter()
            .enumerate()
            .flat_map(|(i, s)| {
                if spec.handler == *b"vide" {
                    // Valid AVCC packets (per-sample keyframe parity).
                    avcc_sample(i == 0, s.size as usize)
                } else {
                    sample_bytes(seq as u8 + i as u8, s.size as usize)
                }
            })
            .collect();
        let segment = build_segment(spec.track_id, seq, decode_time, &samples, &payload);
        spans.push(crate::bmff::SegmentSpan {
            archive_offset: archive.len() as u64,
            archive_len: segment.len() as u64,
        });
        archive.extend_from_slice(&segment);
        decode_time += u64::from(per_sample) * samples_per_segment as u64;
    }
    (init, archive, spans)
}

/// ONE legal multi-fragment segment FILE — a movie-fragment sequence
/// `(moof, mdat)+` inside a single file, every tfhd carrying an
/// explicit **file-absolute** base pointing at its own mdat's payload
/// start (the final-review round-3 residual shape). `fragments`:
/// (sequence, base_decode_time, samples, payload) per moof+mdat
/// pair; returns the file bytes.
pub fn build_multi_fragment_file(
    track_id: u32,
    fragments: &[(u32, u64, Vec<FixtureSample>, Vec<u8>)],
) -> Vec<u8> {
    let build_moof = |seq: u32, bdt: u64, samples: &[FixtureSample], base: u64| -> Vec<u8> {
        let mut traf = Vec::new();
        // tfhd flags 0x1 = base-data-offset present (u64 after
        // track_id); trun data_offset 0 (base == first sample).
        let mut tfhd = fullbox(0x1, &[]);
        tfhd.extend_from_slice(&u32b(track_id));
        tfhd.extend_from_slice(&u64b(base));
        traf.extend_from_slice(&bxf(b"tfhd", &tfhd));
        let mut tfdt = fullbox(0x0100_0000, &[]);
        tfdt.extend_from_slice(&u64b(bdt));
        traf.extend_from_slice(&bxf(b"tfdt", &tfdt));
        let flags = 0x001 | 0x100 | 0x200 | 0x400 | 0x800;
        let mut trun = fullbox(flags, &[]);
        trun.extend_from_slice(&u32b(samples.len() as u32));
        trun.extend_from_slice(&i32b(0));
        for s in samples {
            trun.extend_from_slice(&u32b(s.duration));
            trun.extend_from_slice(&u32b(s.size));
            let sample_flags: u32 = if s.sync { 0x0200_0000 } else { 0x0101_0000 };
            trun.extend_from_slice(&u32b(sample_flags));
            trun.extend_from_slice(&u32b(s.cts as u32));
        }
        traf.extend_from_slice(&bxf(b"trun", &trun));
        let mfhd = bxf(b"mfhd", &fullbox(0, &u32b(seq)));
        bxf(
            b"moof",
            &[mfhd.as_slice(), bxf(b"traf", &traf).as_slice()].concat(),
        )
    };
    // Measure every moof with a placeholder base (the u64 field keeps
    // lengths stable), then compute each mdat payload's file-absolute
    // offset over the moof1/mdat1/moof2/mdat2… layout.
    let probes: Vec<Vec<u8>> = fragments
        .iter()
        .map(|(seq, bdt, samples, _)| build_moof(*seq, *bdt, samples, 0))
        .collect();
    let mut cursor = 0u64;
    let mut bases = Vec::with_capacity(fragments.len());
    for (i, probe) in probes.iter().enumerate() {
        let mdat_payload_at = cursor + probe.len() as u64 + 8;
        bases.push(mdat_payload_at);
        cursor = mdat_payload_at + fragments[i].3.len() as u64;
    }
    let mut out = Vec::new();
    for ((seq, bdt, samples, payload), base) in fragments.iter().zip(bases) {
        out.extend_from_slice(&build_moof(*seq, *bdt, samples, base));
        out.extend_from_slice(&bxf(b"mdat", payload));
    }
    out
}

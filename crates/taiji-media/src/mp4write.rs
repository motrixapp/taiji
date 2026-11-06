//! Minimal progressive-MP4 writer — the write half of the self-built
//! native carrier (the carrier decision as amended 2026-10-28: the
//! named `mp4ff` is a Go library, the
//! Rust carrier is in-house with **zero new dependencies**).
//!
//! Capability face (the kickoff-gate matrix is measured against exactly
//! this writer; docs/design/media-synthesis.md carries the matrix):
//!
//! * **any-codec stsd passthrough** — the source init's sample
//! description bytes are copied verbatim (no codec whitelist: the
//! disqualifier of the crates.io `mp4` candidate);
//! * **faststart by construction** — `ftyp, moov, mdat` layout with
//! the moov's `stco`/`co64` chunk offsets resolved against the
//! known post-moov mdat position (two-pass serialize);
//! * **multi-track merge** — N [`TrackSpec`]s become N traks over one
//! shared mdat (one chunk per track);
//! * **tx3g subtitle tracks** — [`tx3g_track_spec`] builds a tx3g trak
//! from cue windows (VTT/SRT conversion lives in [`crate::vtt`]);
//! * **covr cover art** — [`covr_udta`] (iTunes `meta.ilst.covr` (a udta child)
//! with the jpeg/png well-known data type);
//! * **©nam title** — `meta.ilst.©nam.data` (the title embed,
//! the product wiring; the same ilst family as covr — one
//! `meta.ilst` carries every present item);
//! * **chpl chapters** — [`chpl_box`] (Nero-style, timestamps in
//! 100 ns units — the unit convention is documented per the matrix
//! annotation; not a product face yet);
//! * **multi-Period concat** — the caller concatenates same-codec
//! sample streams into one [`TrackSpec`] (the matrix entry measures
//! exactly that composition);
//! * **MKV is out of scope by verdict** — the writer only emits the
//! MP4 family; MKV routes to the ffmpeg fallback channel.
//!
//! The output is a byte vector (the pipeline writes it to
//! `<out>.part` then atomically renames); the
//! in-memory posture note lives in bmff.rs module docs.

use crate::bmff::{self, FourCC, HANDLER_AUDIO, HANDLER_SUBTITLE, HANDLER_VIDEO, box_bytes};
use crate::error::MediaError;

/// Movie timescale the writer uses for `mvhd`/`tkhd` (ms units).
pub const MOVIE_TIMESCALE: u32 = 1000;

/// A byte sink for box serialization.
#[derive(Default)]
struct Sink {
    buf: Vec<u8>,
}

impl Sink {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn i8(&mut self, v: i8) {
        self.buf.push(v as u8);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
}

/// One output track's fully-resolved description + samples.
#[derive(Debug, Clone)]
pub struct TrackSpec {
    /// hdlr type: vide/soun/subt.
    pub handler: FourCC,
    /// mdhd timescale (media units).
    pub timescale: u32,
    /// stsd entry, **verbatim** source bytes (see module docs).
    pub stsd_entry: Vec<u8>,
    /// minf media-header box bytes (vmhd/smhd/nmhd; verbatim or
    /// synthesized by the fold).
    pub media_header: Vec<u8>,
    /// dinf box bytes (verbatim; `None` = the self-contained dref).
    pub dinf: Option<Vec<u8>>,
    /// tkhd 16.16 width/height (visual tracks).
    pub tkhd_width_height: Option<(u32, u32)>,
    /// tkhd 8.8 volume (audio tracks).
    pub tkhd_volume: u16,
    /// Samples in decode order (timing/sync metadata).
    pub samples: Vec<SampleOut>,
    /// Per-sample byte lengths (parallel to `samples`).
    pub sample_sizes: Vec<u32>,
    /// The concatenated sample payload.
    pub media_data: Vec<u8>,
}

/// One output sample's timing metadata.
#[derive(Debug, Clone, Copy)]
pub struct SampleOut {
    pub duration: u32,
    /// Composition offset, signed (ctts v1 when negative values
    /// appear; v0 otherwise).
    pub cts: i32,
    /// Sync-sample bit (drives stss; ignored for non-visual tracks).
    pub sync: bool,
}

/// A chapter marker (chpl input face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chapter {
    /// Chapter start on the movie timeline, movie-timescale units
    /// (converted to the chpl 100 ns convention at serialization).
    pub start: u64,
    /// Chapter title.
    pub title: String,
}

/// Metadata faces the writer can attach to the moov (all optional;
/// the covr/chpl faces exist since the matrix, the title face is
/// wired with the product — `MovieMeta` is the product-wiring vehicle).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MovieMeta {
    /// Title: written as `meta.ilst.©nam.data` (the iTunes
    /// title atom, the same ilst family as covr — the
    /// in-carrier ruling; a udta-chpl-style plain box would be a
    /// second, non-interoperable convention).
    pub title: Option<String>,
    /// Cover art payload + it-is-png discriminator.
    pub covr: Option<(Vec<u8>, bool)>,
    /// Chapters (chpl box).
    pub chapters: Vec<Chapter>,
}

/// `ftyp` for the writer output (isom family).
pub fn ftyp_box() -> Vec<u8> {
    let mut p = Sink::default();
    p.raw(b"isom"); // major brand
    p.u32(512); // minor version
    p.raw(b"isom");
    p.raw(b"iso2");
    p.raw(b"mp41");
    box_bytes(b"ftyp", std::mem::take(&mut p.buf))
}

/// Self-contained `dinf`+`dref` (`url ` flags=1).
pub fn default_dinf() -> Vec<u8> {
    let url = box_bytes(b"url ", {
        let mut p = Sink::default();
        p.u32(1); // fullbox version 0, flags 1 (self-contained)
        std::mem::take(&mut p.buf)
    });
    let dref = box_bytes(b"dref", {
        let mut p = Sink::default();
        p.u32(0); // version/flags
        p.u32(1); // entry_count
        p.raw(&url);
        std::mem::take(&mut p.buf)
    });
    box_bytes(b"dinf", dref)
}

/// The self-contained dinf as static bytes (the default when the
/// source init carries no dinf).
fn default_dinf_bytes() -> &'static [u8] {
    static DINF: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    DINF.get_or_init(default_dinf)
}

fn unity_matrix(s: &mut Sink) {
    s.u32(0x0001_0000);
    s.u32(0);
    s.u32(0);
    s.u32(0);
    s.u32(0x0001_0000);
    s.u32(0);
    s.u32(0);
    s.u32(0);
    s.u32(0x4000_0000);
}

/// `hdlr` box for a handler kind (standard names).
fn hdlr_box(handler: &FourCC) -> Vec<u8> {
    let mut p = Sink::default();
    p.u32(0); // version/flags
    p.u32(0); // pre_defined
    p.raw(handler);
    p.u32(0);
    p.u32(0);
    p.u32(0);
    let name = match *handler {
        HANDLER_VIDEO => &b"VideoHandler"[..],
        HANDLER_AUDIO => &b"SoundHandler"[..],
        HANDLER_SUBTITLE => &b"SubtHandler"[..],
        _ => &b"MediaHandler"[..],
    };
    p.raw(name);
    p.u8(0);
    box_bytes(b"hdlr", std::mem::take(&mut p.buf))
}

/// Serialize the whole movie.
///
/// Layout: `ftyp, moov, mdat` (faststart by construction). Chunk
/// layout: one chunk per track, tracks in spec order. The moov's
/// chunk offsets are movie-file-absolute, so the moov is serialized
/// twice: once with placeholder offsets to measure its size, then
/// with the real mdat position (entry counts are fixed, so the size
/// is stable; the stco→co64 switch grows it by 4 bytes per chunk and
/// is measured through one extra pass).
pub fn write_progressive(tracks: &[TrackSpec], meta: &MovieMeta, out: &mut Vec<u8>) {
    out.clear();
    let ftyp = ftyp_box();
    let payload_len: u64 = tracks.iter().map(|t| t.media_data.len() as u64).sum();
    // Pass 1: measure (placeholder offsets, stco form).
    let moov_probe = serialize_moov(tracks, meta, 0, false);
    let end_probe = ftyp.len() as u64 + moov_probe.len() as u64 + 8 + payload_len;
    let use_co64 = end_probe > u32::MAX as u64;
    // Pass 2: real offsets (re-measure once when co64 flipped the
    // moov size).
    let mut mdat_start = ftyp.len() as u64 + moov_probe.len() as u64 + 8;
    let mut moov = serialize_moov(tracks, meta, mdat_start, use_co64);
    if use_co64 {
        mdat_start = ftyp.len() as u64 + moov.len() as u64 + 8;
        moov = serialize_moov(tracks, meta, mdat_start, use_co64);
    }
    out.extend_from_slice(&ftyp);
    out.extend_from_slice(&moov);
    // mdat header: 32-bit size, largesize escape above 4 GiB.
    if payload_len + 8 > u32::MAX as u64 {
        let mut hdr = Sink::default();
        hdr.u32(1);
        hdr.raw(b"mdat");
        hdr.u64(payload_len + 16);
        out.extend_from_slice(&hdr.buf);
    } else {
        let mut hdr = Sink::default();
        hdr.u32((payload_len + 8) as u32);
        hdr.raw(b"mdat");
        out.extend_from_slice(&hdr.buf);
    }
    for t in tracks {
        out.extend_from_slice(&t.media_data);
    }
}

fn serialize_moov(
    tracks: &[TrackSpec],
    meta: &MovieMeta,
    mdat_start: u64,
    use_co64: bool,
) -> Vec<u8> {
    let mut s = Sink::default();
    // mvhd (v0; v1 when the duration overflows u32).
    let movie_duration = tracks
        .iter()
        .map(|t| {
            let media: u64 = t.samples.iter().map(|x| u64::from(x.duration)).sum();
            scale_units(media, t.timescale, MOVIE_TIMESCALE)
        })
        .max()
        .unwrap_or(0);
    {
        let mut m = Sink::default();
        if movie_duration > u32::MAX as u64 {
            m.u32(0x0100_0000); // version 1, flags 0
            m.u64(0); // creation_time
            m.u64(0); // modification_time
            m.u32(MOVIE_TIMESCALE);
            m.u64(movie_duration);
        } else {
            m.u32(0); // version 0, flags 0
            m.u32(0);
            m.u32(0);
            m.u32(MOVIE_TIMESCALE);
            m.u32(movie_duration as u32);
        }
        m.u32(0x0001_0000); // rate
        m.u16(0x0100); // volume
        m.u16(0);
        m.raw(&[0u8; 8]);
        unity_matrix(&mut m);
        m.raw(&[0u8; 24]); // pre_defined
        m.u32(tracks.len() as u32 + 1); // next_track_id
        s.raw(&box_bytes(b"mvhd", std::mem::take(&mut m.buf)));
    }
    // Chunk i = track i's media_data; chunks follow the mdat header.
    let mut chunk_offsets: Vec<u64> = Vec::with_capacity(tracks.len());
    let mut cursor = mdat_start;
    for t in tracks {
        chunk_offsets.push(cursor);
        cursor = cursor.saturating_add(t.media_data.len() as u64);
    }
    for (idx, t) in tracks.iter().enumerate() {
        s.raw(&serialize_trak(
            t,
            (idx + 1) as u32,
            movie_duration,
            chunk_offsets[idx],
            use_co64,
        ));
    }
    // udta faces (©nam/covr/chpl).
    let mut udta_payload = Vec::new();
    if meta.title.is_some() || meta.covr.is_some() {
        // One meta.ilst carries every present iTunes-style item
        // (©nam first, covr second — the declaration order).
        let mut ilst_items = Vec::new();
        if let Some(title) = &meta.title {
            ilst_items.extend_from_slice(&nam_item(title));
        }
        if let Some((bytes, is_png)) = &meta.covr {
            ilst_items.extend_from_slice(&covr_item(bytes, *is_png));
        }
        let ilst = box_bytes(b"ilst", ilst_items);
        udta_payload.extend_from_slice(&meta_box(ilst));
    }
    if !meta.chapters.is_empty() {
        udta_payload.extend_from_slice(&chpl_box(&meta.chapters));
    }
    if !udta_payload.is_empty() {
        s.raw(&box_bytes(b"udta", udta_payload));
    }
    box_bytes(b"moov", std::mem::take(&mut s.buf))
}

/// Media-duration units → movie-timescale units (rounded).
fn scale_units(value: u64, from: u32, to: u32) -> u64 {
    if from == 0 || to == 0 {
        return 0;
    }
    (value.saturating_mul(u64::from(to)) + u64::from(from) / 2) / u64::from(from)
}

fn serialize_trak(
    t: &TrackSpec,
    track_id: u32,
    movie_duration: u64,
    chunk_offset: u64,
    use_co64: bool,
) -> Vec<u8> {
    let mut s = Sink::default();
    // tkhd (v0; flags enabled | in_movie).
    {
        let mut k = Sink::default();
        k.u32(0x0000_0003); // version 0, flags 3
        k.u32(0); // creation_time
        k.u32(0); // modification_time
        k.u32(track_id);
        k.u32(0); // reserved
        k.u32(movie_duration.min(u32::MAX as u64) as u32);
        k.raw(&[0u8; 8]); // reserved
        k.u16(0); // layer
        // Alternate group 1 for visual tracks (rendition grouping
        // convention), 0 otherwise.
        k.u16(u16::from(t.handler == HANDLER_VIDEO));
        k.u16(t.tkhd_volume);
        k.u16(0); // reserved
        unity_matrix(&mut k);
        let (w, h) = t.tkhd_width_height.unwrap_or((0, 0));
        k.u32(w);
        k.u32(h);
        s.raw(&box_bytes(b"tkhd", std::mem::take(&mut k.buf)));
    }
    // mdia: mdhd + hdlr + minf.
    {
        let mut d = Sink::default();
        let media_duration: u64 = t.samples.iter().map(|x| u64::from(x.duration)).sum();
        let mut h = Sink::default();
        h.u32(0); // version 0, flags 0
        h.u32(0); // creation_time
        h.u32(0); // modification_time
        h.u32(t.timescale);
        h.u32(media_duration.min(u32::MAX as u64) as u32);
        h.u16(0x55c4); // language 'und'
        h.u16(0); // pre_defined
        d.raw(&box_bytes(b"mdhd", std::mem::take(&mut h.buf)));
        d.raw(&hdlr_box(&t.handler));
        {
            let mut f = Sink::default();
            f.raw(&t.media_header);
            f.raw(match t.dinf.as_deref() {
                Some(bytes) => bytes,
                None => default_dinf_bytes(),
            });
            f.raw(&serialize_stbl(t, chunk_offset, use_co64));
            d.raw(&box_bytes(b"minf", std::mem::take(&mut f.buf)));
        }
        s.raw(&box_bytes(b"mdia", std::mem::take(&mut d.buf)));
    }
    box_bytes(b"trak", std::mem::take(&mut s.buf))
}

fn serialize_stbl(t: &TrackSpec, chunk_offset: u64, use_co64: bool) -> Vec<u8> {
    let mut s = Sink::default();
    // stsd: verbatim entry bytes.
    {
        let mut d = Sink::default();
        d.u32(0); // version/flags
        d.u32(1); // entry_count
        d.raw(&t.stsd_entry);
        s.raw(&box_bytes(b"stsd", std::mem::take(&mut d.buf)));
    }
    // stts run-length over durations.
    {
        let mut runs: Vec<(u32, u32)> = Vec::new(); // (count, delta)
        for sample in &t.samples {
            match runs.last_mut() {
                Some(last) if last.1 == sample.duration => last.0 += 1,
                _ => runs.push((1, sample.duration)),
            }
        }
        let mut d = Sink::default();
        d.u32(0);
        d.u32(runs.len() as u32);
        for (count, delta) in runs {
            d.u32(count);
            d.u32(delta);
        }
        s.raw(&box_bytes(b"stts", std::mem::take(&mut d.buf)));
    }
    // ctts when any composition offset is non-zero (v1 signed when a
    // negative offset appears; v0 otherwise).
    if t.samples.iter().any(|x| x.cts != 0) {
        let signed = t.samples.iter().any(|x| x.cts < 0);
        let mut runs: Vec<(u32, i32)> = Vec::new(); // (count, offset)
        for sample in &t.samples {
            match runs.last_mut() {
                Some(last) if last.1 == sample.cts => last.0 += 1,
                _ => runs.push((1, sample.cts)),
            }
        }
        let mut d = Sink::default();
        d.u32(if signed { 0x0100_0000 } else { 0 });
        d.u32(runs.len() as u32);
        for (count, offset) in runs {
            d.u32(count);
            if signed {
                d.i32(offset);
            } else {
                d.u32(offset as u32);
            }
        }
        s.raw(&box_bytes(b"ctts", std::mem::take(&mut d.buf)));
    }
    // stsc: one chunk holding every sample.
    {
        let mut d = Sink::default();
        d.u32(0);
        d.u32(1); // entry_count
        d.u32(1); // first_chunk
        d.u32(t.samples.len() as u32);
        d.u32(1); // sample_description_index
        s.raw(&box_bytes(b"stsc", std::mem::take(&mut d.buf)));
    }
    // stsz table form (per-sample byte lengths).
    {
        let mut d = Sink::default();
        d.u32(0);
        d.u32(0); // sample_size = 0 → per-sample table
        d.u32(t.samples.len() as u32);
        for size in &t.sample_sizes {
            d.u32(*size);
        }
        s.raw(&box_bytes(b"stsz", std::mem::take(&mut d.buf)));
    }
    // stco / co64: one entry (one chunk).
    {
        let mut d = Sink::default();
        d.u32(0);
        d.u32(1);
        if use_co64 {
            d.u64(chunk_offset);
            s.raw(&box_bytes(b"co64", std::mem::take(&mut d.buf)));
        } else {
            d.u32(chunk_offset.min(u32::MAX as u64) as u32);
            s.raw(&box_bytes(b"stco", std::mem::take(&mut d.buf)));
        }
    }
    // stss for visual tracks with a sync mix (absent stss = all sync).
    if t.handler == HANDLER_VIDEO && t.samples.iter().any(|x| !x.sync) {
        let entries: Vec<u32> = t
            .samples
            .iter()
            .enumerate()
            .filter(|(_, x)| x.sync)
            .map(|(i, _)| i as u32 + 1)
            .collect();
        let mut d = Sink::default();
        d.u32(0);
        d.u32(entries.len() as u32);
        for e in entries {
            d.u32(e);
        }
        s.raw(&box_bytes(b"stss", std::mem::take(&mut d.buf)));
    }
    box_bytes(b"stbl", std::mem::take(&mut s.buf))
}

// ---------------------------------------------------------------------------
// tx3g / covr / chpl faces (matrix items)
// ---------------------------------------------------------------------------

/// A tx3g text sample: 2-byte BE length + UTF-8 text, inner line
/// breaks as CR (0x0D; the MPEG-4 Part 17 single-string form ffmpeg's
/// mov_text reads).
pub fn tx3g_sample(text: &str) -> Vec<u8> {
    let normalized: Vec<u8> = text.replace("\r\n", "\n").replace('\n', "\r").into_bytes();
    let mut out = Vec::with_capacity(2 + normalized.len());
    out.extend_from_slice(&(normalized.len() as u16).to_be_bytes());
    out.extend_from_slice(&normalized);
    out
}

/// The `tx3g` stsd entry (default display/style records — the widely
/// interoperable shape: 6 reserved + data_reference_index 1 + the
/// 32-byte display/style block).
pub fn tx3g_stsd_entry() -> Vec<u8> {
    let mut p = Sink::default();
    p.raw(&[0u8; 6]); // reserved
    p.u16(1); // data_reference_index
    p.u32(0); // display_flags
    p.i8(1); // horizontal_justification (center)
    p.i8(-1); // vertical_justification (bottom)
    p.u8(0); // bg_color rgba (black, opaque)
    p.u8(0);
    p.u8(0);
    p.u8(0xFF);
    p.i16(0); // box_record (top/left/bottom/right)
    p.i16(0);
    p.i16(0);
    p.i16(0);
    // style_record: startChar(2) endChar(2) fontID(2)
    // faceStyleFlags(2) fontSize(2) rgba(4).
    p.u16(0);
    p.u16(0);
    p.u16(1); // font id 1 (the implicit default font)
    p.u16(0); // face flags plain
    p.u16(0x12); // 18pt
    p.u8(0xFF);
    p.u8(0xFF);
    p.u8(0xFF);
    p.u8(0xFF);
    box_bytes(b"tx3g", std::mem::take(&mut p.buf))
}

/// Build a tx3g subtitle [`TrackSpec`] from cue windows.
///
/// `cues`: (start_ms, end_ms, plain_text). Gaps between cues carry
/// empty filler samples so the track timeline stays continuous (the
/// ffmpeg mov_text event-track shape; players surface text only on
/// non-empty samples).
pub fn tx3g_track_spec(cues: &[(u64, u64, String)]) -> TrackSpec {
    let mut samples: Vec<SampleOut> = Vec::new();
    let mut sample_sizes: Vec<u32> = Vec::new();
    let mut media_data: Vec<u8> = Vec::new();
    let mut cursor = 0u64; // ms
    for &(start, end, ref text) in cues {
        if start > cursor {
            let filler = tx3g_sample("");
            sample_sizes.push(filler.len() as u32);
            samples.push(SampleOut {
                duration: (start - cursor) as u32,
                cts: 0,
                sync: true,
            });
            media_data.extend_from_slice(&filler);
        }
        let body = tx3g_sample(text);
        sample_sizes.push(body.len() as u32);
        samples.push(SampleOut {
            duration: end.max(start).saturating_sub(start) as u32,
            cts: 0,
            sync: true,
        });
        media_data.extend_from_slice(&body);
        cursor = end.max(start);
    }
    TrackSpec {
        handler: HANDLER_SUBTITLE,
        timescale: 1000,
        stsd_entry: tx3g_stsd_entry(),
        media_header: bmff::synth_media_header(&HANDLER_SUBTITLE),
        dinf: None,
        tkhd_width_height: None,
        tkhd_volume: 0,
        samples,
        sample_sizes,
        media_data,
    }
}

/// The iTunes `meta` box: fullbox + a real `hdlr` box (handler
/// `mdir`, the iTunes reserved word `appl`) + the inner (ilst).
fn meta_box(inner: Vec<u8>) -> Vec<u8> {
    let mut h = Sink::default();
    h.u32(0); // hdlr version/flags
    h.u32(0); // pre_defined
    h.raw(b"mdir");
    h.raw(b"appl"); // reserved[0] — the iTunes convention
    h.u32(0);
    h.u32(0);
    h.u8(0); // empty name
    let hdlr = box_bytes(b"hdlr", std::mem::take(&mut h.buf));
    let mut p = Sink::default();
    p.u32(0); // meta fullbox version/flags
    p.raw(&hdlr);
    p.raw(&inner);
    box_bytes(b"meta", std::mem::take(&mut p.buf))
}

/// One iTunes ilst item: `<fourcc>(data)` where the data box carries
/// the well-known type (1 = UTF-8 text, 13 = JPEG, 14 = PNG) + a
/// zero locale + the payload.
fn ilst_item(fourcc: &[u8; 4], well_known_type: u32, payload: &[u8]) -> Vec<u8> {
    let mut data = Sink::default();
    data.u32(well_known_type);
    data.u32(0); // locale
    data.raw(payload);
    box_bytes(fourcc, box_bytes(b"data", std::mem::take(&mut data.buf)))
}

/// The `©nam` title item (`meta.ilst.©nam.data`, well-known type 1 =
/// UTF-8 text — the title embed face).
fn nam_item(title: &str) -> Vec<u8> {
    ilst_item(&[0xA9, b'n', b'a', b'm'], 1, title.as_bytes())
}

/// The `covr` item (well-known type 13 = JPEG, 14 = PNG).
fn covr_item(image: &[u8], is_png: bool) -> Vec<u8> {
    ilst_item(b"covr", if is_png { 14 } else { 13 }, image)
}

/// Backward-compatible whole-meta builder for a bare cover (the
/// matrix face's public entry; one item inside the same ilst walk).
pub fn covr_udta(image: &[u8], is_png: bool) -> Vec<u8> {
    let ilst = box_bytes(b"ilst", covr_item(image, is_png));
    meta_box(ilst)
}

/// The Nero-style `chpl` box: version byte 1, flags 0, reserved u32,
/// count u8, then per chapter a u64 timestamp in **100 ns units**, a
/// u8 title length and the title bytes.
///
/// The unit convention is the GPAC/Nero form; documented in
/// docs/design/media-synthesis.md (matrix capability face — not a
/// product face in this card).
pub fn chpl_box(chapters: &[Chapter]) -> Vec<u8> {
    let mut p = Sink::default();
    p.u32(0x0100_0000); // version 1, flags 0
    p.u32(0); // reserved
    let count = chapters.len().min(255);
    p.u8(count as u8);
    for ch in chapters.iter().take(count) {
        // movie-timescale (1000 = ms) → 100 ns units.
        p.u64(ch.start.saturating_mul(10_000));
        let bytes = ch.title.as_bytes();
        let len = bytes.len().min(255);
        p.u8(len as u8);
        p.raw(&bytes[..len]);
    }
    box_bytes(b"chpl", std::mem::take(&mut p.buf))
}

/// Convert an [`bmff::FoldedTrack`] + its archive into a writer
/// [`TrackSpec`] — the transmux step (sample bytes copied from the
/// archive at their folded offsets; stsd passthrough verbatim).
pub fn track_spec_from_fold(
    fold: &bmff::FoldedTrack,
    archive: &[u8],
) -> Result<TrackSpec, MediaError> {
    let mut sample_sizes = Vec::with_capacity(fold.samples.len());
    let mut samples = Vec::with_capacity(fold.samples.len());
    let mut media_data = Vec::new();
    for s in &fold.samples {
        let start = s.offset as usize;
        let end = start
            .checked_add(s.len as usize)
            .ok_or_else(|| MediaError::Staging("folded sample span overflows usize".to_string()))?;
        let bytes = archive.get(start..end).ok_or_else(|| {
            MediaError::Staging(format!(
                "folded sample {start}..{end} outside the {}-byte archive",
                archive.len()
            ))
        })?;
        media_data.extend_from_slice(bytes);
        sample_sizes.push(s.len);
        samples.push(SampleOut {
            duration: s.duration,
            cts: s.cts,
            sync: s.sync,
        });
    }
    Ok(TrackSpec {
        handler: fold.handler,
        timescale: fold.timescale,
        stsd_entry: fold
            .stsd_entries
            .first()
            .map(|e| e.bytes.clone())
            .unwrap_or_default(),
        media_header: fold.media_header.clone(),
        dinf: fold.dinf.clone(),
        tkhd_width_height: fold.tkhd_width_height,
        tkhd_volume: fold.tkhd_volume,
        samples,
        sample_sizes,
        media_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// tx3g sample encoding: length prefix + CR line normalization.
    #[test]
    fn tx3g_sample_shape() {
        let s = tx3g_sample("hello\r\nworld");
        assert_eq!(&s[..2], &11u16.to_be_bytes());
        assert_eq!(&s[2..], b"hello\rworld");
        assert_eq!(tx3g_sample("").len(), 2);
    }

    /// chpl: 100 ns unit conversion + count/length bytes.
    #[test]
    fn chpl_units_and_layout() {
        let chapters = vec![Chapter {
            start: 1000, // 1 s in ms units
            title: "Intro".to_string(),
        }];
        let b = chpl_box(&chapters);
        assert_eq!(&b[4..8], b"chpl");
        let p = &b[8..];
        assert_eq!(&p[0..4], &0x0100_0000u32.to_be_bytes());
        assert_eq!(&p[4..8], &0u32.to_be_bytes()); // reserved
        assert_eq!(p[8], 1); // count
        // 1 s = 10,000,000 × 100 ns.
        assert_eq!(&p[9..17], &10_000_000u64.to_be_bytes());
        assert_eq!(p[17], 5);
        assert_eq!(&p[18..23], b"Intro");
    }

    /// covr: the meta box (udta child) walks meta > hdlr + ilst >
    /// covr > data; type codes per jpeg/png.
    #[test]
    fn covr_type_codes() {
        for (is_png, code) in [(false, 13u32), (true, 14u32)] {
            let meta = covr_udta(b"\x89PNG-ish", is_png);
            assert_eq!(&meta[4..8], b"meta");
            let inner = bmff::iter_boxes(&meta[8 + 4..]).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(inner[0].typ, *b"hdlr");
            assert_eq!(inner[1].typ, *b"ilst");
            let covr = bmff::iter_boxes(inner[1].payload)
                .unwrap_or_else(|e| panic!("{e}"))
                .remove(0);
            assert_eq!(covr.typ, *b"covr");
            let data = bmff::iter_boxes(covr.payload)
                .unwrap_or_else(|e| panic!("{e}"))
                .remove(0);
            assert_eq!(data.typ, *b"data");
            assert_eq!(&data.payload[0..4], &code.to_be_bytes());
            assert_eq!(&data.payload[8..], b"\x89PNG-ish");
        }
    }

    /// The ©nam title item: meta > hdlr + ilst > ©nam > data with
    /// well-known type 1 (UTF-8) and the payload verbatim; the same
    /// meta.ilst carries covr alongside when both are present.
    #[test]
    fn nam_item_shape_and_shared_ilst() {
        let item = nam_item("Big Buck Bunny");
        assert_eq!(&item[4..8], &[0xA9, b'n', b'a', b'm']);
        let data = bmff::iter_boxes(&item[8..])
            .unwrap_or_else(|e| panic!("{e}"))
            .remove(0);
        assert_eq!(data.typ, *b"data");
        assert_eq!(&data.payload[0..4], &1u32.to_be_bytes());
        assert_eq!(&data.payload[8..], b"Big Buck Bunny");
        // Whole-movie shape: title + cover ride ONE meta.ilst inside
        // the moov's udta.
        let track = TrackSpec {
            handler: HANDLER_VIDEO,
            timescale: 1000,
            stsd_entry: box_bytes(b"avc1", vec![0; 40]),
            media_header: bmff::synth_media_header(&HANDLER_VIDEO),
            dinf: None,
            tkhd_width_height: None,
            tkhd_volume: 0,
            samples: vec![SampleOut {
                duration: 1000,
                cts: 0,
                sync: true,
            }],
            sample_sizes: vec![4],
            media_data: b"AAAA".to_vec(),
        };
        let meta = MovieMeta {
            title: Some("T".into()),
            covr: Some((b"jpegbytes".to_vec(), false)),
            chapters: Vec::new(),
        };
        let mut out = Vec::new();
        write_progressive(&[track], &meta, &mut out);
        let moov = bmff::iter_boxes(&out)
            .unwrap_or_else(|e| panic!("{e}"))
            .into_iter()
            .find(|b| b.typ == *b"moov")
            .unwrap_or_else(|| panic!("moov"));
        let udta = bmff::iter_boxes(moov.payload)
            .unwrap_or_else(|e| panic!("{e}"))
            .into_iter()
            .find(|b| b.typ == *b"udta")
            .unwrap_or_else(|| panic!("udta"));
        // Exactly one meta box (the shared ilst vehicle).
        let metas: Vec<_> = bmff::iter_boxes(udta.payload)
            .unwrap_or_else(|e| panic!("{e}"))
            .into_iter()
            .filter(|b| b.typ == *b"meta")
            .collect();
        assert_eq!(metas.len(), 1);
        let inner = bmff::iter_boxes(&metas[0].payload[4..])
            .unwrap_or_else(|e| panic!("{e}"))
            .into_iter()
            .find(|b| b.typ == *b"ilst")
            .unwrap_or_else(|| panic!("ilst"));
        let items = bmff::iter_boxes(inner.payload).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(items.len(), 2, "©nam + covr share one ilst");
        assert_eq!(items[0].typ, [0xA9, b'n', b'a', b'm']);
        assert_eq!(items[1].typ, *b"covr");
    }

    /// A minimal one-track movie: ftyp/moov/mdat layout (faststart),
    /// mdat payload packed, mvhd duration scaled.
    #[test]
    fn minimal_movie_layout() {
        let track = TrackSpec {
            handler: HANDLER_VIDEO,
            timescale: 1000,
            stsd_entry: box_bytes(b"avc1", vec![0; 40]),
            media_header: bmff::synth_media_header(&HANDLER_VIDEO),
            dinf: None,
            tkhd_width_height: Some((320 << 16, 240 << 16)),
            tkhd_volume: 0,
            samples: vec![
                SampleOut {
                    duration: 1000,
                    cts: 0,
                    sync: true,
                },
                SampleOut {
                    duration: 1000,
                    cts: 0,
                    sync: false,
                },
            ],
            sample_sizes: vec![4, 6],
            media_data: b"AAAABBBBBB".to_vec(),
        };
        let mut out = Vec::new();
        write_progressive(&[track], &MovieMeta::default(), &mut out);
        let boxes = bmff::iter_boxes(&out).unwrap_or_else(|e| panic!("{e}"));
        let types: Vec<[u8; 4]> = boxes.iter().map(|b| b.typ).collect();
        assert_eq!(types, vec![*b"ftyp", *b"moov", *b"mdat"]);
        let (moov, mdat) = (&boxes[1], &boxes[2]);
        assert!(moov.start < mdat.start, "moov before mdat = faststart");
        assert_eq!(mdat.payload, b"AAAABBBBBB");
        let moov_boxes = bmff::iter_boxes(moov.payload).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(moov_boxes[0].typ, *b"mvhd");
        let mvhd = bmff::read_mvhd(moov_boxes[0].payload).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(mvhd.timescale, 1000);
        assert_eq!(mvhd.duration, 2000);
        assert_eq!(moov_boxes[1].typ, *b"trak");
    }

    /// Timescale scaling is rounded, not truncated.
    #[test]
    fn scale_units_rounding() {
        assert_eq!(scale_units(1000, 1000, 1000), 1000);
        // 90000-unit media: 90000 units = 1000 ms; half-way rounds up.
        assert_eq!(scale_units(45_000, 90_000, 1000), 500);
        assert_eq!(scale_units(45_045, 90_000, 1000), 501);
        assert_eq!(scale_units(10, 0, 1000), 0, "zero timescale guards");
    }
}

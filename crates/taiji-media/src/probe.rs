//! Native probe — the independent key assertions over a synthesized
//! product (per the media spec's synthesis line: "native probe makes
//! independent key assertions (box structure verified layer by layer,
//! not only stream sets/durations)").
//!
//! The probe parses the product **layer by layer** and checks the
//! structural invariants the writer owes; it shares the read side
//! with the transmux but is an independent code path over the
//! product bytes (write → read-back, not write-time assertions).
//!
//! Assertions (a violation collects a text line; the pipeline maps a
//! non-empty violation set to `taiji.media.remux_verify_failed`):
//!
//! * top level: exactly `ftyp, moov, mdat` in that order — moov
//! before mdat = **faststart**;
//! * `moov.mvhd`: timescale > 0; duration within the remux-verification tolerance
//! (±2 %) of the expected ΣEXTINF;
//! * per expected track: a `trak` whose `tkhd` track_id is 1..=N and
//! flags carry enabled|in_movie; `mdia.hdlr` equals the expected
//! handler; `mdhd.timescale` equals the source; `stsd` entry bytes
//! **equal the source stsd verbatim** (the passthrough proof);
//! * `stbl` internal consistency: `stsz` sample count == Σ`stts`
//! counts == `stsc`-implied count; the single-chunk `stco`/`co64`
//! offset falls inside the `mdat` payload; Σ sample sizes == the
//! `mdat` payload length (exact byte accounting across all tracks);
//! * `stss` (when present): ascending, within 1..=sample_count,
//! starts at 1 for visual tracks;
//! * optional metadata faces when expected: `udta.meta.ilst.©nam`
//! title byte-equality + `udta.meta.ilst.covr` payload
//! byte-equality; `udta.chpl` round-trip; tx3g `stsd` type
//! + sample-count/timeline equality for embedded subtitle tracks.

use crate::bmff::{self, FourCC, HANDLER_SUBTITLE, iter_boxes};

/// ±2 % duration tolerance (the product spec's remux-verification
/// tolerance, carried by the media spec's checklist).
pub const DURATION_TOLERANCE: f64 = 0.02;

/// What the probe expects one output track to be.
#[derive(Debug, Clone)]
pub struct ExpectedTrack {
    /// hdlr type.
    pub handler: FourCC,
    /// Source mdhd timescale.
    pub timescale: u32,
    /// Source stsd entry bytes (verbatim equality proof).
    pub stsd_entry: Vec<u8>,
    /// Expected sample count.
    pub sample_count: usize,
}

/// Optional metadata expectations.
#[derive(Debug, Clone, Default)]
pub struct ExpectedMeta {
    /// Expected title text (the ©nam item — the embed verification
    /// face).
    pub title: Option<String>,
    /// Cover bytes + is-png.
    pub covr: Option<(Vec<u8>, bool)>,
    /// Expected chapters (start-ms, title).
    pub chapters: Vec<(u64, String)>,
}

/// Probe verdict: the violation list (empty = pass).
pub struct ProbeReport {
    pub violations: Vec<String>,
    /// Parsed movie duration in ms (for callers composing reports).
    pub duration_ms: u64,
}

impl ProbeReport {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Which invariant set the probe applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// The native channel's own products: the passthrough proofs
    /// (stsd byte-equality, mdhd timescale equality, the writer's
    /// single-chunk layout).
    Native,
    /// Fallback-channel products (ffmpeg rebuilds stsd/stbl in its
    /// own shape): the structural set — layout/faststart, duration
    /// tolerance, per-track kinds, table consistency, offset bounds
    /// (the passthrough proofs are native-only by definition).
    Structural,
}

/// Run the probe over the product bytes.
pub fn probe_product(
    product: &[u8],
    expected_tracks: &[ExpectedTrack],
    expected_duration_ms: u64,
    meta: &ExpectedMeta,
) -> ProbeReport {
    probe_product_mode(
        product,
        expected_tracks,
        expected_duration_ms,
        meta,
        ProbeMode::Native,
    )
}

/// Run the probe with an explicit invariant mode.
pub fn probe_product_mode(
    product: &[u8],
    expected_tracks: &[ExpectedTrack],
    expected_duration_ms: u64,
    meta: &ExpectedMeta,
    mode: ProbeMode,
) -> ProbeReport {
    let mut v: Vec<String> = Vec::new();
    let boxes = match iter_boxes(product) {
        Ok(b) => b,
        Err(e) => {
            return ProbeReport {
                violations: vec![format!("top-level box walk: {e}")],
                duration_ms: 0,
            };
        }
    };
    // Top-level layout: ftyp first, moov present, mdat last — `free`
    // boxes are legal fillers anywhere (ffmpeg's +faststart leaves
    // one where the moov used to be).
    let meaningful: Vec<FourCC> = boxes
        .iter()
        .filter(|b| b.typ != *b"free" && b.typ != *b"skip")
        .map(|b| b.typ)
        .collect();
    if meaningful != vec![*b"ftyp", *b"moov", *b"mdat"] {
        v.push(format!(
            "top-level layout is {:?} (expected ftyp, moov, mdat — faststart)",
            meaningful
                .iter()
                .map(|t| String::from_utf8_lossy(t).into_owned())
                .collect::<Vec<_>>()
        ));
    }
    let Some(moov) = boxes.iter().find(|b| b.typ == *b"moov") else {
        return ProbeReport {
            violations: [v, vec!["no moov".to_string()]].concat(),
            duration_ms: 0,
        };
    };
    let Some(mdat) = boxes.iter().find(|b| b.typ == *b"mdat") else {
        return ProbeReport {
            violations: [v, vec!["no mdat".to_string()]].concat(),
            duration_ms: 0,
        };
    };
    if moov.start >= mdat.start {
        v.push("moov sits after mdat (faststart violated)".to_string());
    }
    let mdat_payload_start = mdat.start + (mdat.end - mdat.start - mdat.payload.len() as u64);
    let mdat_payload_end = mdat.end;

    let moov_boxes = match iter_boxes(moov.payload) {
        Ok(b) => b,
        Err(e) => {
            return ProbeReport {
                violations: [v, vec![format!("moov walk: {e}")]].concat(),
                duration_ms: 0,
            };
        }
    };
    // mvhd + duration tolerance.
    let mut duration_ms = 0u64;
    if let Some(mvhd) = moov_boxes.iter().find(|b| b.typ == *b"mvhd") {
        match bmff::read_mvhd(mvhd.payload) {
            Ok(info) => {
                if info.timescale == 0 {
                    v.push("mvhd timescale is 0".to_string());
                }
                duration_ms = if info.timescale == 0 {
                    0
                } else {
                    info.duration * 1000 / u64::from(info.timescale)
                };
                let expected = expected_duration_ms as f64;
                if expected > 0.0 {
                    let lo = expected * (1.0 - DURATION_TOLERANCE);
                    let hi = expected * (1.0 + DURATION_TOLERANCE);
                    let actual = duration_ms as f64;
                    if !(lo..=hi).contains(&actual) {
                        v.push(format!(
                            "duration {actual} ms outside [{lo:.0}, {hi:.0}] \
                             (expected {expected} ms ±2%)"
                        ));
                    }
                }
            }
            Err(e) => v.push(format!("mvhd parse: {e}")),
        }
    } else {
        v.push("moov carries no mvhd".to_string());
    }

    // Traks.
    let traks: Vec<_> = moov_boxes.iter().filter(|b| b.typ == *b"trak").collect();
    if traks.len() != expected_tracks.len() {
        v.push(format!(
            "{} traks (expected {})",
            traks.len(),
            expected_tracks.len()
        ));
    }
    let mut sample_bytes_total = 0u64;
    for (i, expect) in expected_tracks.iter().enumerate() {
        let Some(trak) = traks.get(i) else {
            v.push(format!("track {i}: missing trak"));
            continue;
        };
        probe_trak(
            trak,
            i,
            expect,
            mdat_payload_start,
            mdat_payload_end,
            &mut v,
            &mut sample_bytes_total,
            mode,
        );
    }
    if sample_bytes_total != mdat.payload.len() as u64 {
        v.push(format!(
            "Σ sample sizes {sample_bytes_total} != mdat payload {}",
            mdat.payload.len()
        ));
    }

    // Metadata faces.
    probe_meta(moov, meta, &mut v);

    ProbeReport {
        violations: v,
        duration_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn probe_trak(
    trak: &bmff::RawBox<'_>,
    idx: usize,
    expect: &ExpectedTrack,
    mdat_payload_start: u64,
    mdat_payload_end: u64,
    v: &mut Vec<String>,
    sample_bytes_total: &mut u64,
    mode: ProbeMode,
) {
    let name = format!("track {idx}");
    let children = match iter_boxes(trak.payload) {
        Ok(c) => c,
        Err(e) => {
            v.push(format!("{name}: trak walk: {e}"));
            return;
        }
    };
    // tkhd.
    let track_id = match children.iter().find(|b| b.typ == *b"tkhd") {
        Some(tkhd) => match bmff::read_tkhd(tkhd.payload) {
            Ok(info) => {
                if info.track_id != idx as u32 + 1 {
                    v.push(format!(
                        "{name}: tkhd track_id {} (expected {})",
                        info.track_id,
                        idx + 1
                    ));
                }
                if info.flags & 0x1 == 0 || info.flags & 0x2 == 0 {
                    v.push(format!(
                        "{name}: tkhd flags {:#x} missing enabled|in_movie",
                        info.flags
                    ));
                }
                Some(info.track_id)
            }
            Err(e) => {
                v.push(format!("{name}: tkhd parse: {e}"));
                None
            }
        },
        None => {
            v.push(format!("{name}: no tkhd"));
            None
        }
    };
    let _ = track_id;
    // mdia → mdhd/hdlr/minf → stbl → stsd.
    let Some(mdia) = children.iter().find(|b| b.typ == *b"mdia") else {
        v.push(format!("{name}: no mdia"));
        return;
    };
    let mdia_children = match iter_boxes(mdia.payload) {
        Ok(c) => c,
        Err(e) => {
            v.push(format!("{name}: mdia walk: {e}"));
            return;
        }
    };
    if let Some(mdhd) = mdia_children.iter().find(|b| b.typ == *b"mdhd") {
        match bmff::read_mdhd(mdhd.payload) {
            Ok(info) => {
                // Timescale equality is the native passthrough proof —
                // ffmpeg products carry their own rescale.
                if mode == ProbeMode::Native && info.timescale != expect.timescale {
                    v.push(format!(
                        "{name}: mdhd timescale {} (expected {})",
                        info.timescale, expect.timescale
                    ));
                }
            }
            Err(e) => v.push(format!("{name}: mdhd parse: {e}")),
        }
    } else {
        v.push(format!("{name}: no mdhd"));
    }
    if let Some(hdlr) = mdia_children.iter().find(|b| b.typ == *b"hdlr") {
        match bmff::read_hdlr(hdlr.payload) {
            Ok(h) if h != expect.handler => {
                v.push(format!(
                    "{name}: hdlr {} (expected {})",
                    String::from_utf8_lossy(&h),
                    String::from_utf8_lossy(&expect.handler)
                ));
            }
            Err(e) => v.push(format!("{name}: hdlr parse: {e}")),
            _ => {}
        }
    } else {
        v.push(format!("{name}: no hdlr"));
    }
    let Some(minf) = mdia_children.iter().find(|b| b.typ == *b"minf") else {
        v.push(format!("{name}: no minf"));
        return;
    };
    let minf_children = match iter_boxes(minf.payload) {
        Ok(c) => c,
        Err(e) => {
            v.push(format!("{name}: minf walk: {e}"));
            return;
        }
    };
    if !minf_children
        .iter()
        .any(|b| matches!(&b.typ, t if t == b"vmhd" || t == b"smhd" || t == b"nmhd" || t == b"hmhd" || t == b"gmhd"))
    {
        v.push(format!("{name}: minf carries no media-header (vmhd/smhd/nmhd…)"));
    }
    let Some(stbl) = minf_children.iter().find(|b| b.typ == *b"stbl") else {
        v.push(format!("{name}: no stbl"));
        return;
    };
    let stbl_children = match iter_boxes(stbl.payload) {
        Ok(c) => c,
        Err(e) => {
            v.push(format!("{name}: stbl walk: {e}"));
            return;
        }
    };
    // stsd verbatim equality (the passthrough proof) — tx3g tracks
    // compare against the tx3g entry the writer builds.
    let expected_entry = if expect.handler == HANDLER_SUBTITLE && expect.stsd_entry.is_empty() {
        crate::mp4write::tx3g_stsd_entry()
    } else {
        expect.stsd_entry.clone()
    };
    match stbl_children.iter().find(|b| b.typ == *b"stsd") {
        Some(stsd) => match bmff::read_stsd(stsd.payload) {
            Ok(entries) => {
                if entries.len() != 1 {
                    v.push(format!(
                        "{name}: stsd carries {} entries (expected 1)",
                        entries.len()
                    ));
                } else if expect.handler == HANDLER_SUBTITLE && entries[0].fourcc != *b"tx3g" {
                    v.push(format!(
                        "{name}: subtitle stsd type {} (expected tx3g)",
                        String::from_utf8_lossy(&entries[0].fourcc)
                    ));
                } else if mode == ProbeMode::Native && entries[0].bytes != expected_entry {
                    v.push(format!(
                        "{name}: stsd entry bytes differ from the source \
                         (passthrough violated; type {})",
                        String::from_utf8_lossy(&entries[0].fourcc)
                    ));
                }
            }
            Err(e) => v.push(format!("{name}: stsd parse: {e}")),
        },
        None => v.push(format!("{name}: no stsd")),
    }
    // stsz.
    let mut sample_count = 0usize;
    let mut size_sum = 0u64;
    match stbl_children.iter().find(|b| b.typ == *b"stsz") {
        Some(stsz) => {
            // fullbox(4) + sample_size(4) + count(4) + table.
            let p = stsz.payload;
            if p.len() >= 12 {
                let count = u32::from_be_bytes([p[8], p[9], p[10], p[11]]) as usize;
                let fixed = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
                if fixed == 0 {
                    if p.len() != 12 + count * 4 {
                        v.push(format!(
                            "{name}: stsz table length {} ≠ 12 + {count}×4",
                            p.len()
                        ));
                    } else {
                        for i in 0..count {
                            let s = u32::from_be_bytes([
                                p[12 + i * 4],
                                p[13 + i * 4],
                                p[14 + i * 4],
                                p[15 + i * 4],
                            ]);
                            if s == 0 {
                                v.push(format!("{name}: stsz entry {i} is zero"));
                            }
                            size_sum += u64::from(s);
                        }
                    }
                } else {
                    size_sum = u64::from(fixed) * count as u64;
                }
                sample_count = count;
                if count != expect.sample_count {
                    v.push(format!(
                        "{name}: {count} samples (expected {})",
                        expect.sample_count
                    ));
                }
            } else {
                v.push(format!("{name}: stsz truncated"));
            }
        }
        None => v.push(format!("{name}: no stsz")),
    }
    // stts.
    match stbl_children.iter().find(|b| b.typ == *b"stts") {
        Some(stts) => {
            let p = stts.payload;
            if p.len() >= 8 {
                let entries = u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as usize;
                if p.len() != 8 + entries * 8 {
                    v.push(format!("{name}: stts table length mismatch"));
                } else {
                    let mut total = 0usize;
                    for i in 0..entries {
                        total += u32::from_be_bytes([
                            p[8 + i * 8],
                            p[9 + i * 8],
                            p[10 + i * 8],
                            p[11 + i * 8],
                        ]) as usize;
                    }
                    if total != sample_count {
                        v.push(format!(
                            "{name}: stts counts Σ{total} ≠ stsz count {sample_count}"
                        ));
                    }
                }
            } else {
                v.push(format!("{name}: stts truncated"));
            }
        }
        None => v.push(format!("{name}: no stts")),
    }
    // stsc: general consistency (Σ per-chunk sample counts over the
    // first chunk run == sample count); the single-chunk form is the
    // native writer's own layout.
    match stbl_children.iter().find(|b| b.typ == *b"stsc") {
        Some(stsc) => {
            let p = stsc.payload;
            if p.len() >= 8 {
                let entries = u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as usize;
                if p.len() != 8 + entries * 12 {
                    v.push(format!("{name}: stsc table length mismatch"));
                } else if entries == 0 {
                    v.push(format!("{name}: stsc carries no entry"));
                } else {
                    let first_per_chunk = u32::from_be_bytes([p[12], p[13], p[14], p[15]]) as usize;
                    let first_chunk = u32::from_be_bytes([p[8], p[9], p[10], p[11]]) as usize;
                    if first_chunk != 1 {
                        v.push(format!("{name}: stsc first chunk {first_chunk} ≠ 1"));
                    }
                    if mode == ProbeMode::Native && first_per_chunk != sample_count {
                        v.push(format!(
                            "{name}: stsc {first_per_chunk} samples/chunk ≠ {sample_count} \
                             (native single-chunk form)"
                        ));
                    } else if first_per_chunk > sample_count {
                        v.push(format!(
                            "{name}: stsc {first_per_chunk} samples/chunk exceeds the \
                             sample count {sample_count}"
                        ));
                    }
                }
            } else {
                v.push(format!("{name}: stsc truncated"));
            }
        }
        None => v.push(format!("{name}: no stsc")),
    }
    // stco/co64: every chunk offset must fall inside the mdat
    // payload. Under the native mode the writer emits exactly one
    // entry (one chunk per track) whose span must cover the track's
    // whole size sum; structural products may carry many chunks.
    let chunk_offsets: Vec<u64> = match stbl_children.iter().find(|b| b.typ == *b"stco") {
        Some(stco) => {
            let p = stco.payload;
            if p.len() >= 8 && p.len() % 4 == 0 && (p.len() - 8) % 4 == 0 {
                let n = u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as usize;
                if p.len() != 8 + n * 4 {
                    v.push(format!("{name}: stco table length mismatch"));
                    Vec::new()
                } else {
                    (0..n)
                        .map(|i| {
                            u32::from_be_bytes([
                                p[8 + i * 4],
                                p[9 + i * 4],
                                p[10 + i * 4],
                                p[11 + i * 4],
                            ]) as u64
                        })
                        .collect()
                }
            } else {
                v.push(format!("{name}: stco length {}", p.len()));
                Vec::new()
            }
        }
        None => match stbl_children.iter().find(|b| b.typ == *b"co64") {
            Some(co64) => {
                let p = co64.payload;
                if p.len() >= 8 && (p.len() - 8) % 8 == 0 {
                    let n = u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as usize;
                    if p.len() != 8 + n * 8 {
                        v.push(format!("{name}: co64 table length mismatch"));
                        Vec::new()
                    } else {
                        (0..n)
                            .map(|i| {
                                u64::from_be_bytes([
                                    p[8 + i * 8],
                                    p[9 + i * 8],
                                    p[10 + i * 8],
                                    p[11 + i * 8],
                                    p[12 + i * 8],
                                    p[13 + i * 8],
                                    p[14 + i * 8],
                                    p[15 + i * 8],
                                ])
                            })
                            .collect()
                    }
                } else {
                    v.push(format!("{name}: co64 length {}", p.len()));
                    Vec::new()
                }
            }
            None => {
                v.push(format!("{name}: no stco/co64"));
                Vec::new()
            }
        },
    };
    for off in &chunk_offsets {
        if *off < mdat_payload_start || *off > mdat_payload_end {
            v.push(format!(
                "{name}: chunk offset {off} outside the mdat payload \
                 [{mdat_payload_start}, {mdat_payload_end}]"
            ));
        }
    }
    if let Some(off) = chunk_offsets.first() {
        if mode == ProbeMode::Native
            && chunk_offsets.len() == 1
            && off
                .checked_add(size_sum)
                .is_none_or(|end| end > mdat_payload_end)
        {
            v.push(format!(
                "{name}: chunk span {off}+{size_sum} overruns the mdat payload"
            ));
        }
    }
    *sample_bytes_total = sample_bytes_total.saturating_add(size_sum);
    // stss sanity (visual tracks).
    if let Some(stss) = stbl_children.iter().find(|b| b.typ == *b"stss") {
        let p = stss.payload;
        if p.len() >= 8 {
            let entries = u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as usize;
            if p.len() != 8 + entries * 4 {
                v.push(format!("{name}: stss table length mismatch"));
            } else {
                let mut prev = 0u32;
                for i in 0..entries {
                    let e = u32::from_be_bytes([
                        p[8 + i * 4],
                        p[9 + i * 4],
                        p[10 + i * 4],
                        p[11 + i * 4],
                    ]);
                    if e <= prev || e as usize > sample_count.max(1) {
                        v.push(format!("{name}: stss entry {e} out of order/range"));
                        break;
                    }
                    if i == 0 && expect.handler == *b"vide" && e != 1 {
                        v.push(format!("{name}: first stss entry {e} (video expects 1)"));
                    }
                    prev = e;
                }
            }
        }
    }
}

fn probe_meta(moov: &bmff::RawBox<'_>, meta: &ExpectedMeta, v: &mut Vec<String>) {
    let Some(udta) = iter_boxes(moov.payload)
        .ok()
        .and_then(|c| c.into_iter().find(|b| b.typ == *b"udta"))
    else {
        if meta.title.is_some() || meta.covr.is_some() || !meta.chapters.is_empty() {
            v.push("expected metadata faces but the moov carries no udta".to_string());
        }
        return;
    };
    let children = match iter_boxes(udta.payload) {
        Ok(c) => c,
        Err(e) => {
            v.push(format!("udta walk: {e}"));
            return;
        }
    };
    // ilst items: udta > meta(fullbox) > ilst > <item> > data (the
    // ©nam/covr pair shares the walk).
    let ilst_item_payload = |want: &[u8; 4]| -> Option<&[u8]> {
        for c in &children {
            if c.typ != *b"meta" {
                continue;
            }
            if let Ok(inner) = iter_boxes(&c.payload[4.min(c.payload.len())..]) {
                for m in inner {
                    if m.typ != *b"ilst" {
                        continue;
                    }
                    if let Ok(items) = iter_boxes(m.payload) {
                        for item in items {
                            if item.typ != *want {
                                continue;
                            }
                            if let Ok(datas) = iter_boxes(item.payload) {
                                for d in datas {
                                    if d.typ == *b"data" && d.payload.len() >= 8 {
                                        return Some(&d.payload[8..]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    };
    // ©nam: the title text round-trips byte-for-byte.
    if let Some(title) = &meta.title {
        match ilst_item_payload(&[0xA9, b'n', b'a', b'm']) {
            Some(payload) if payload == title.as_bytes() => {}
            Some(other) => v.push(format!(
                "©nam payload differs ({} bytes vs expected {})",
                other.len(),
                title.len()
            )),
            None => v.push("expected a ©nam face, none present".to_string()),
        }
    }
    // covr: udta > meta(fullbox) > ilst > covr > data.
    if let Some((bytes, is_png)) = &meta.covr {
        match ilst_item_payload(b"covr") {
            Some(payload) if payload == bytes.as_slice() => {}
            Some(other) => v.push(format!(
                "covr payload differs ({} bytes vs expected {})",
                other.len(),
                bytes.len()
            )),
            None => v.push("expected a covr face, none present".to_string()),
        }
        let _ = is_png;
    }
    // chpl round-trip.
    if !meta.chapters.is_empty() {
        let chpl = children.iter().find(|b| b.typ == *b"chpl");
        let Some(chpl) = chpl else {
            v.push("expected a chpl face, none present".to_string());
            return;
        };
        let p = chpl.payload;
        if p.len() < 14 {
            v.push(format!("chpl payload truncated ({} bytes)", p.len()));
            return;
        }
        let count = p[8] as usize;
        let mut pos = 9usize;
        let mut read = Vec::new();
        for _ in 0..count {
            if pos + 9 > p.len() {
                v.push("chpl chapter entry truncated".to_string());
                break;
            }
            let t = u64::from_be_bytes([
                p[pos],
                p[pos + 1],
                p[pos + 2],
                p[pos + 3],
                p[pos + 4],
                p[pos + 5],
                p[pos + 6],
                p[pos + 7],
            ]);
            let len = p[pos + 8] as usize;
            if pos + 9 + len > p.len() {
                v.push("chpl title truncated".to_string());
                break;
            }
            let title = String::from_utf8_lossy(&p[pos + 9..pos + 9 + len]).into_owned();
            read.push((t / 10_000, title));
            pos += 9 + len;
        }
        if read != meta.chapters {
            v.push(format!("chpl round-trip mismatch: {read:?} vs expected"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bmff::{HANDLER_VIDEO, box_bytes};
    use crate::mp4write::{MovieMeta, SampleOut, TrackSpec, write_progressive};

    /// A clean single-track movie passes every layer assertion; a
    /// corrupted stsz fails the accounting.
    #[test]
    fn probe_pass_and_fail() {
        let entry = box_bytes(b"avc1", vec![1, 2, 3, 4]);
        let track = TrackSpec {
            handler: HANDLER_VIDEO,
            timescale: 1000,
            stsd_entry: entry.clone(),
            media_header: crate::bmff::synth_media_header(&HANDLER_VIDEO),
            dinf: None,
            tkhd_width_height: Some((640 << 16, 360 << 16)),
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
                    sync: true,
                },
            ],
            sample_sizes: vec![8, 8],
            media_data: vec![7u8; 16],
        };
        let expect = vec![ExpectedTrack {
            handler: HANDLER_VIDEO,
            timescale: 1000,
            stsd_entry: entry,
            sample_count: 2,
        }];
        let mut out = Vec::new();
        write_progressive(&[track], &MovieMeta::default(), &mut out);
        let report = probe_product(&out, &expect, 2000, &ExpectedMeta::default());
        assert!(report.ok(), "violations: {:?}", report.violations);
        assert_eq!(report.duration_ms, 2000);
        // Corruption: flip a stsz byte → accounting mismatch surfaces.
        let mut corrupted = out.clone();
        // Find the stsz table's last size byte (8 → 9): naive scan for
        // the stsz box then bump one table entry.
        let pos = find_sub(&corrupted, b"stsz")
            .unwrap_or_else(|| panic!("stsz present in the writer output"));
        // payload: 4 verflags + 4 fixed + 4 count + 4*n entries; bump
        // the first entry's last byte.
        let entry_byte = pos + 4 + 8 + 4 + 3;
        corrupted[entry_byte] = 9;
        let report = probe_product(&corrupted, &expect, 2000, &ExpectedMeta::default());
        assert!(!report.ok(), "corrupted stsz must fail");
        assert!(
            report
                .violations
                .iter()
                .any(|x| x.contains("Σ sample sizes") || x.contains("overruns")),
            "accounting violation surfaced: {:?}",
            report.violations
        );
    }

    fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}

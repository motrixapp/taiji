//! Minimal ISO-BMFF (MP4) reader + fragment fold — the read half of
//! the **self-built native write side** (the carrier decision as
//! amended 2026-10-28: the originally named carrier `mp4ff` is a Go library
//! and does not exist in the Rust ecosystem — crates.io unpublished,
//! docs.rs 404 — the native carrier is in-house, zero new
//! dependencies).
//!
//! Scope of the read side (exactly what the transmux + probe consume,
//! nothing more):
//!
//! * generic box iteration ([`iter_boxes`]) with 32-bit size, the
//! `size == 0` "extends to end" form and the `size == 1` 64-bit
//! largesize escape;
//! * typed readers for the boxes the fold and the probe must
//! understand: `mvhd`/`tkhd`/`mdhd`/`hdlr`/`stsd` (+ `stbl` children
//! for the probe: `stts`/`stsc`/`stsz`/`stco`/`co64`/`stss`/`ctts`);
//! `moof`/`mfhd`/`traf`/`tfhd`/`tfdt`/`trun` for the fragment fold;
//! * [`fold_track`]: the per-track fMP4 fold — one init segment (its
//! `moov.trak` codec description passes through **verbatim**, the
//! amended carrier property: any codec, not a whitelist) plus
//! the segment archive (a `moof`/`mdat` stream) folded into one
//! flat sample table ([`FoldedTrack`]).
//!
//! Malformed staging content is an explicit `taiji.media.staging`
//! error (the media spec's error-code annotation's local-disk face) — never a
//! panic; every length is bounds-checked against the slice.
//!
//! Memory posture (0.3): archives are read whole (`&[u8]`) — bounded
//! by the staging quota semantics; a streamed fold is a perf-gate
//! follow-up if the remux-throughput gate demands it (recorded in
//! docs/design/media-synthesis.md).

/// Four-character box type.
pub type FourCC = [u8; 4];

/// `vide`
pub const HANDLER_VIDEO: FourCC = *b"vide";
/// `soun`
pub const HANDLER_AUDIO: FourCC = *b"soun";
/// `subt` (tx3g subtitle tracks carry `subt` in `mdia.hdlr`)
pub const HANDLER_SUBTITLE: FourCC = *b"subt";

/// One raw box: type + payload slice (header excluded).
#[derive(Debug, Clone, Copy)]
pub struct RawBox<'a> {
    /// Box type (verbatim).
    pub typ: FourCC,
    /// Payload after the (8- or 16-byte) header.
    pub payload: &'a [u8],
    /// Absolute byte offset of the box start in the source slice.
    pub start: u64,
    /// Absolute byte offset one past the box end.
    pub end: u64,
}

impl RawBox<'_> {
    /// Type as a lossy string (diagnostics).
    pub fn type_str(&self) -> String {
        self.typ.iter().map(|b| *b as char).collect()
    }
}

/// Iterate the top-level boxes of a byte slice. `size == 0` (box
/// extends to the end) and `size == 1` (largescale 64-bit form) are
/// honored; a size that overruns the slice is a staging error.
pub fn iter_boxes(buf: &[u8]) -> Result<Vec<RawBox<'_>>, crate::error::MediaError> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let rem = &buf[off..];
        if rem.len() < 8 {
            return Err(bad(&format!(
                "trailing {} bytes at offset {off} cannot hold a box header",
                rem.len()
            )));
        }
        let size32 = u32::from_be_bytes([rem[0], rem[1], rem[2], rem[3]]) as u64;
        let typ: FourCC = [rem[4], rem[5], rem[6], rem[7]];
        let (size, hdr) = if size32 == 1 {
            if rem.len() < 16 {
                return Err(bad("largesize box header truncated"));
            }
            let large = u64::from_be_bytes([
                rem[8], rem[9], rem[10], rem[11], rem[12], rem[13], rem[14], rem[15],
            ]);
            (large, 16u64)
        } else if size32 == 0 {
            // Extends to the end of the buffer (mdat convention).
            ((buf.len() - off) as u64, 8u64)
        } else {
            (size32, 8u64)
        };
        // Box-end arithmetic is checked: a crafted
        // largesize near u64::MAX used to wrap `off + size` to a small
        // value that passed the bounds check and then panicked on the
        // payload slice — hostile bytes are a staging error, never a
        // panic (the "no unwrap in non-test code" discipline's
        // arithmetic sibling).
        let end = (off as u64).checked_add(size).ok_or_else(|| {
            bad(&format!(
                "box '{}' at {off} declares size {size} wrapping the address space",
                typ.iter().map(|b| *b as char).collect::<String>()
            ))
        })?;
        if size < hdr || end > buf.len() as u64 {
            return Err(bad(&format!(
                "box '{}' at {off} declares size {size} beyond the buffer",
                typ.iter().map(|b| *b as char).collect::<String>()
            )));
        }
        out.push(RawBox {
            typ,
            payload: &buf[off + hdr as usize..end as usize],
            start: off as u64,
            end,
        });
        off = end as usize;
    }
    Ok(out)
}

fn bad(text: &str) -> crate::error::MediaError {
    crate::error::MediaError::Staging(format!("bmff: {text}"))
}

/// Find the first child box of the given type (payload = parent
/// payload). Containers whose first 4 bytes are a fullbox version/
/// flags word (moov is not; meta is) are handled by the caller picking
/// the right payload slice.
fn child<'a>(
    payload: &'a [u8],
    typ: &FourCC,
) -> Result<Option<RawBox<'a>>, crate::error::MediaError> {
    for b in iter_boxes(payload)? {
        if &b.typ == typ {
            return Ok(Some(b));
        }
    }
    Ok(None)
}

/// First child of a type, erroring when absent.
fn need<'a>(
    payload: &'a [u8],
    typ: &FourCC,
    parent: &str,
) -> Result<RawBox<'a>, crate::error::MediaError> {
    child(payload, typ)?.ok_or_else(|| {
        bad(&format!(
            "{parent} carries no '{}' child",
            typ.iter().map(|b| *b as char).collect::<String>()
        ))
    })
}

// ---------------------------------------------------------------------------
// typed readers (little struct, big honesty: every field bounds-checked)
// ---------------------------------------------------------------------------

/// A cursor over a box payload (bounds-checked big-endian reads).
struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], crate::error::MediaError> {
        if self.pos + n > self.buf.len() {
            return Err(bad(&format!(
                "read of {n} bytes at {} overruns a {}-byte payload",
                self.pos,
                self.buf.len()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, crate::error::MediaError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, crate::error::MediaError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, crate::error::MediaError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    /// Fullbox version/flags word.
    fn version_flags(&mut self) -> Result<(u8, u32), crate::error::MediaError> {
        let w = self.u32()?;
        Ok(((w >> 24) as u8, w & 0x00ff_ffff))
    }
    /// Bytes not yet consumed (the payload-derived bound source for
    /// count-carrying boxes).
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// `mvhd` fields the fold/probe consume.
#[derive(Debug, Clone, Copy)]
pub struct MvhdInfo {
    pub timescale: u32,
    pub duration: u64,
    pub next_track_id: u32,
}

/// Read `mvhd` (v0/v1).
pub fn read_mvhd(payload: &[u8]) -> Result<MvhdInfo, crate::error::MediaError> {
    let mut c = Cur::new(payload);
    let (version, _) = c.version_flags()?;
    if version == 1 {
        let _ = c.u64()?; // creation_time
        let _ = c.u64()?; // modification_time
    } else {
        let _ = c.u32()?;
        let _ = c.u32()?;
    }
    let timescale = c.u32()?;
    let duration = if version == 1 {
        c.u64()?
    } else {
        c.u32()? as u64
    };
    // rate(4) + volume(2) + reserved(2) + reserved(8) + matrix(36) +
    // pre_defined(24), then next_track_id.
    c.take(4 + 2 + 2 + 8 + 36 + 24)?;
    let next_track_id = c.u32()?;
    Ok(MvhdInfo {
        timescale,
        duration,
        next_track_id,
    })
}

/// `tkhd` fields the fold/probe consume.
#[derive(Debug, Clone, Copy)]
pub struct TkhdInfo {
    pub flags: u32,
    pub track_id: u32,
    pub duration: u64,
    /// Fixed 16.16 width (0 for non-visual tracks).
    pub width: u32,
    /// Fixed 16.16 height.
    pub height: u32,
    /// Volume fixed 8.8 (0x0100 = full, audio only).
    pub volume: u16,
}

/// Read `tkhd` (v0/v1).
pub fn read_tkhd(payload: &[u8]) -> Result<TkhdInfo, crate::error::MediaError> {
    let mut c = Cur::new(payload);
    let (version, flags) = c.version_flags()?;
    let _ctime = if version == 1 {
        c.u64()?
    } else {
        u64::from(c.u32()?)
    };
    let _mtime = if version == 1 {
        c.u64()?
    } else {
        u64::from(c.u32()?)
    };
    let track_id = c.u32()?;
    let _reserved = c.u32()?;
    let duration = if version == 1 {
        c.u64()?
    } else {
        c.u32()? as u64
    };
    c.take(8)?; // reserved
    let _layer = c.u16()?;
    let _alt_group = c.u16()?;
    let volume = c.u16()?;
    c.take(2)?; // reserved
    c.take(36)?; // matrix
    let width = c.u32()?;
    let height = c.u32()?;
    Ok(TkhdInfo {
        flags,
        track_id,
        duration,
        width,
        height,
        volume,
    })
}

/// `mdhd` fields.
#[derive(Debug, Clone, Copy)]
pub struct MdhdInfo {
    pub timescale: u32,
    pub duration: u64,
}

/// Read `mdhd` (v0/v1).
pub fn read_mdhd(payload: &[u8]) -> Result<MdhdInfo, crate::error::MediaError> {
    let mut c = Cur::new(payload);
    let (version, _) = c.version_flags()?;
    let _ctime = if version == 1 {
        c.u64()?
    } else {
        u64::from(c.u32()?)
    };
    let _mtime = if version == 1 {
        c.u64()?
    } else {
        u64::from(c.u32()?)
    };
    let timescale = c.u32()?;
    let duration = if version == 1 {
        c.u64()?
    } else {
        c.u32()? as u64
    };
    Ok(MdhdInfo {
        timescale,
        duration,
    })
}

/// `hdlr` handler type.
pub fn read_hdlr(payload: &[u8]) -> Result<FourCC, crate::error::MediaError> {
    let mut c = Cur::new(payload);
    let _ = c.version_flags()?;
    let _pre = c.u32()?;
    let handler: FourCC = {
        let b = c.take(4)?;
        [b[0], b[1], b[2], b[3]]
    };
    Ok(handler)
}

/// One `stsd` sample entry, **verbatim bytes including its box header**
/// (the amended passthrough property: the entry is copied
/// byte-for-byte into the output, codec whitelist-free).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsdEntry {
    pub fourcc: FourCC,
    /// Whole entry box (size+type+payload).
    pub bytes: Vec<u8>,
}

/// Read `stsd` entries.
pub fn read_stsd(payload: &[u8]) -> Result<Vec<StsdEntry>, crate::error::MediaError> {
    let mut c = Cur::new(payload);
    let _ = c.version_flags()?;
    let entry_count = c.u32()? as usize;
    let rest = &payload[c.pos..];
    let boxes = iter_boxes(rest)?;
    if boxes.len() != entry_count {
        return Err(bad(&format!(
            "stsd declares {entry_count} entries but holds {}",
            boxes.len()
        )));
    }
    let mut out = Vec::with_capacity(entry_count);
    for b in boxes {
        let s = b.start as usize;
        let e = b.end as usize;
        out.push(StsdEntry {
            fourcc: b.typ,
            bytes: rest[s..e].to_vec(),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// fragment fold: moof / traf / tfhd / tfdt / trun
// ---------------------------------------------------------------------------

/// tfhd flag bits (ISO/IEC 14496-12 §8.8.7). Corrected in review:
/// default-base-is-moof is bit **17** (`0x020000` = 131072) — the
/// pre-fix `0x020_0000` (bit 21) was a 16× error that rejected every
/// real-encoder moof (ffmpeg writes tfhd flags 0x00020038 =
/// 0x020000 | default duration/size/flags).
const TFHD_BASE_DATA_OFFSET: u32 = 0x001;
const TFHD_SAMPLE_DESC_INDEX: u32 = 0x002;
const TFHD_DEFAULT_DURATION: u32 = 0x008;
const TFHD_DEFAULT_SIZE: u32 = 0x010;
const TFHD_DEFAULT_FLAGS: u32 = 0x020;
const TFHD_DEFAULT_BASE_IS_MOOF: u32 = 0x020000;

/// trun flag bits (ISO/IEC 14496-12 §8.8.8).
const TRUN_DATA_OFFSET: u32 = 0x001;
const TRUN_FIRST_SAMPLE_FLAGS: u32 = 0x004;
const TRUN_SAMPLE_DURATION: u32 = 0x100;
const TRUN_SAMPLE_SIZE: u32 = 0x200;
const TRUN_SAMPLE_FLAGS: u32 = 0x400;
const TRUN_SAMPLE_CTS: u32 = 0x800;

/// sample_flags bit: sample_is_non_sync_sample (§8.8.8 semantics; the
/// stss derivation uses the inverse).
const SAMPLE_NON_SYNC: u32 = 0x0100_0000;

/// One trun sample's resolved fields (`None` inherits defaults).
#[derive(Debug, Clone, Copy, Default)]
pub struct TrunSample {
    pub duration: Option<u32>,
    pub size: Option<u32>,
    pub flags: Option<u32>,
    pub cts: Option<i32>,
}

/// One parsed trun.
#[derive(Debug, Clone)]
pub struct TrunInfo {
    pub data_offset: Option<i64>,
    pub first_sample_flags: Option<u32>,
    pub samples: Vec<TrunSample>,
}

/// One parsed traf (defaults resolved where the flags say so).
#[derive(Debug, Clone)]
pub struct TrafInfo {
    pub track_id: u32,
    pub base_data_offset: Option<u64>,
    pub default_base_is_moof: bool,
    pub default_sample_description_index: Option<u32>,
    pub default_sample_duration: Option<u32>,
    pub default_sample_size: Option<u32>,
    pub default_sample_flags: Option<u32>,
    pub base_decode_time: Option<u64>,
    pub truns: Vec<TrunInfo>,
}

/// Parse one `moof` payload (payload = moof box payload; `moof_start` =
/// the moof box's absolute start offset — the default base when
/// default-base-is-moof applies).
pub fn read_moof(payload: &[u8]) -> Result<Vec<TrafInfo>, crate::error::MediaError> {
    let mut trafs = Vec::new();
    for b in iter_boxes(payload)? {
        if &b.typ == b"traf" {
            trafs.push(read_traf(b.payload)?);
        }
    }
    if trafs.is_empty() {
        return Err(bad("moof carries no traf"));
    }
    Ok(trafs)
}

fn read_traf(payload: &[u8]) -> Result<TrafInfo, crate::error::MediaError> {
    let mut info = TrafInfo {
        track_id: 0,
        base_data_offset: None,
        default_base_is_moof: false,
        default_sample_description_index: None,
        default_sample_duration: None,
        default_sample_size: None,
        default_sample_flags: None,
        base_decode_time: None,
        truns: Vec::new(),
    };
    for b in iter_boxes(payload)? {
        match &b.typ {
            b"tfhd" => {
                let mut c = Cur::new(b.payload);
                let (_, flags) = c.version_flags()?;
                info.track_id = c.u32()?;
                if flags & TFHD_BASE_DATA_OFFSET != 0 {
                    info.base_data_offset = Some(c.u64()?);
                }
                if flags & TFHD_SAMPLE_DESC_INDEX != 0 {
                    info.default_sample_description_index = Some(c.u32()?);
                }
                if flags & TFHD_DEFAULT_DURATION != 0 {
                    info.default_sample_duration = Some(c.u32()?);
                }
                if flags & TFHD_DEFAULT_SIZE != 0 {
                    info.default_sample_size = Some(c.u32()?);
                }
                if flags & TFHD_DEFAULT_FLAGS != 0 {
                    info.default_sample_flags = Some(c.u32()?);
                }
                if flags & TFHD_DEFAULT_BASE_IS_MOOF != 0 {
                    info.default_base_is_moof = true;
                }
                if info.base_data_offset.is_none() && !info.default_base_is_moof {
                    return Err(bad(
                        "tfhd carries neither base-data-offset nor default-base-is-moof \
                         (unsupported anchor form)",
                    ));
                }
            }
            b"tfdt" => {
                let mut c = Cur::new(b.payload);
                let (version, _) = c.version_flags()?;
                info.base_decode_time = Some(if version == 1 {
                    c.u64()?
                } else {
                    c.u32()? as u64
                });
            }
            b"trun" => {
                let mut c = Cur::new(b.payload);
                let (_, flags) = c.version_flags()?;
                let sample_count = c.u32()? as usize;
                // data_offset: signed 32-bit (ISO/IEC 14496-12
                // §8.8.8), widened for the base arithmetic.
                let data_offset = if flags & TRUN_DATA_OFFSET != 0 {
                    Some(i64::from(c.u32()? as i32))
                } else {
                    None
                };
                let first_sample_flags = (flags & TRUN_FIRST_SAMPLE_FLAGS != 0)
                    .then(|| c.u32())
                    .transpose()?;
                // The declared sample count is bounded by the
                // payload that declares it. Each present per-sample field
                // is one u32; a flags=0 run carries no per-sample bytes,
                // so the payload must still vouch for the count at a 1
                // byte/sample floor (a 48-byte remote moof declaring
                // 0xFFFF_FFFF default samples used to demand a ~137 GiB
                // `with_capacity` reservation — allocation failure abort
                // or an unbounded push loop, either way a remote DoS).
                let per_sample_bytes = 4usize
                    * ((flags & TRUN_SAMPLE_DURATION != 0) as usize
                        + (flags & TRUN_SAMPLE_SIZE != 0) as usize
                        + (flags & TRUN_SAMPLE_FLAGS != 0) as usize
                        + (flags & TRUN_SAMPLE_CTS != 0) as usize);
                let per_sample_floor = per_sample_bytes.max(1);
                let remaining = c.remaining();
                let declared_bytes = (sample_count as u64).saturating_mul(per_sample_floor as u64);
                if declared_bytes > remaining as u64 {
                    return Err(bad(&format!(
                        "trun declares {sample_count} samples needing ≥{declared_bytes} bytes \
                         but only {remaining} remain in the payload"
                    )));
                }
                let mut samples = Vec::with_capacity(sample_count);
                for _ in 0..sample_count {
                    samples.push(TrunSample {
                        duration: (flags & TRUN_SAMPLE_DURATION != 0)
                            .then(|| c.u32())
                            .transpose()?,
                        size: (flags & TRUN_SAMPLE_SIZE != 0)
                            .then(|| c.u32())
                            .transpose()?,
                        flags: (flags & TRUN_SAMPLE_FLAGS != 0)
                            .then(|| c.u32())
                            .transpose()?,
                        cts: (flags & TRUN_SAMPLE_CTS != 0)
                            .then(|| Ok(c.u32()? as i32))
                            .transpose()?,
                    });
                }
                // trun sample caps: the payload-derived bound above makes
                // a count/payload mismatch an upfront error, so the loop
                // can no longer overrun (the bound is exact arithmetic:
                // count × per-sample field bytes ≤ remaining).
                info.truns.push(TrunInfo {
                    data_offset,
                    first_sample_flags,
                    samples,
                });
            }
            _ => {}
        }
    }
    if info.track_id == 0 {
        return Err(bad("traf carries no usable tfhd track_id"));
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// the fold: init + archive → flat sample table
// ---------------------------------------------------------------------------

/// One folded sample: absolute offset inside the **archive** slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldedSample {
    /// Byte offset in the archive.
    pub offset: u64,
    pub len: u32,
    /// Duration in media timescale units.
    pub duration: u32,
    /// Composition offset (signed; B-frame reordering).
    pub cts: i32,
    /// Sync-sample bit (derived from sample_flags).
    pub sync: bool,
}

/// A folded track: init description + flat sample table.
#[derive(Debug, Clone)]
pub struct FoldedTrack {
    /// mdhd timescale.
    pub timescale: u32,
    /// hdlr type (vide/soun/subt).
    pub handler: FourCC,
    /// stsd entries, verbatim (the carrier passthrough property).
    pub stsd_entries: Vec<StsdEntry>,
    /// minf's media-header child (`vmhd`/`smhd`/`nmhd`/…), whole raw
    /// box bytes for verbatim passthrough; synthesized when absent.
    pub media_header: Vec<u8>,
    /// `dinf` whole raw box bytes (verbatim) when present.
    pub dinf: Option<Vec<u8>>,
    /// tkhd width/height (fixed 16.16), passthrough.
    pub tkhd_width_height: Option<(u32, u32)>,
    /// tkhd volume (fixed 8.8).
    pub tkhd_volume: u16,
    /// Samples in decode order.
    pub samples: Vec<FoldedSample>,
    /// Σ durations in media units.
    pub total_duration: u64,
    /// Last fragment's base decode time + its span (continuity
    /// diagnostics; `None` when no tfdt present anywhere).
    pub timeline_end: Option<u64>,
}

/// A raw media-header box for handler kinds whose source init carries
/// none (defensive — an fMP4 init without vmhd/smhd is non-conformant
/// but appears in the wild).
pub fn synth_media_header(handler: &FourCC) -> Vec<u8> {
    match *handler {
        HANDLER_VIDEO => box_bytes(b"vmhd", {
            // fullbox v0 flags=1 + graphicsmode 0 + opcolor 0,0,0
            let mut p = Vec::new();
            p.extend_from_slice(&0x0000_0001u32.to_be_bytes());
            p.extend_from_slice(&[0u8; 8]);
            p
        }),
        HANDLER_AUDIO => box_bytes(b"smhd", {
            let mut p = Vec::new();
            p.extend_from_slice(&0u32.to_be_bytes());
            p.extend_from_slice(&0u16.to_be_bytes());
            p.extend_from_slice(&0u16.to_be_bytes()); // reserved
            p
        }),
        _ => box_bytes(b"nmhd", 0u32.to_be_bytes().to_vec()),
    }
}

/// One segment file's placement inside the archive — the **exact
/// span** the caller's ledger/rewrite bookkeeping already carries
/// (`TrackRewrite.entries`: `archive_offset`/`archive_len`). The fold
/// takes these from the caller instead of inferring file boundaries
/// from the box stream: the final-review round proved any
/// stream-shape heuristic is defeatable by legal inputs (a
/// multi-fragment single file — moof1/mdat1/moof2/mdat2 with
/// explicit bases — defeats "new file after each mdat").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSpan {
    /// Archive offset of the segment file's first byte.
    pub archive_offset: u64,
    /// Segment file length in bytes.
    pub archive_len: u64,
}

impl SegmentSpan {
    /// End offset (exclusive), checked.
    fn end(&self) -> Result<u64, crate::error::MediaError> {
        self.archive_offset
            .checked_add(self.archive_len)
            .ok_or_else(|| bad("segment span overflows the archive address space"))
    }

    /// Whether an archive offset falls inside this span.
    fn contains(&self, offset: u64) -> bool {
        offset >= self.archive_offset && offset - self.archive_offset < self.archive_len
    }
}

/// Fold one track: `init` (the EXT-X-MAP payload, ftyp+moov) plus
/// `archive` (the concatenated segment files, the per-track download
/// layout) and the
/// **exact per-segment-file spans** inside it.
///
/// Rules (documented in docs/design/media-synthesis.md):
/// * the init must carry exactly one `trak` (the HLS per-track form —
/// this convenience face refuses a multi-trak init; the muxed A/V
/// form folds through [`parse_init_tracks`] +
/// [`fold_track_for`]);
/// * every span must be non-empty, inside the archive and **aligned
/// with the box structure** (its start is a box start, its end a
/// box end — a span cutting a box in half contradicts the archive
/// and is an explicit error);
/// * **sample base resolution** (ISO/IEC 14496-12 §8.8.7): a tfhd
/// `default-base-is-moof` anchors at the moof's own archive offset;
/// an **explicit `base-data-offset` is absolute within its segment
/// file** — the archive-absolute base = the enclosing span's
/// `archive_offset` plus the file-relative value. trun data-offset
/// is signed and relative to the base; contiguous samples follow;
/// * every sample byte range must fall inside one `mdat` payload
/// **within the traf's own segment span** — a range landing in
/// another segment's mdat, or outside any mdat, fails loudly;
/// * a moof outside every span is an explicit error (the ledger and
/// the archive disagree);
/// * per-sample durations come from trun/tfhd defaults; a sample with
/// no derivable duration is an unsupported native input (the caller
/// degrades to the ffmpeg channel);
/// * sync = sample_flags without the non-sync bit (first-sample-flags
/// honored for the first sample of each trun).
pub fn fold_track(
    init: &[u8],
    archive: &[u8],
    segments: &[SegmentSpan],
) -> Result<FoldedTrack, crate::error::MediaError> {
    let desc = parse_init(init)?;
    fold_track_for(&desc, archive, segments)
}

/// The selected-track fold: a muxed A/V init carries ≥2
/// traks and its segment files carry interleaved traf pairs — the
/// fold consumes the **selected** track's description (handler-picked
/// by the caller via [`select_init_track`]) and filters the archive's
/// trafs by `track_id`, skipping the other track's fragments. A fold
/// that consumes zero samples off a non-empty archive is an explicit
/// error (the init/archive pairing is wrong), not a silent empty
/// track.
pub fn fold_track_for(
    desc: &InitDescription,
    archive: &[u8],
    segments: &[SegmentSpan],
) -> Result<FoldedTrack, crate::error::MediaError> {
    let mut samples: Vec<FoldedSample> = Vec::new();
    let mut timeline_end: Option<u64> = None;
    // mdat payload ranges in archive order + the box-boundary sets
    // the span-alignment defense checks against.
    let mut mdats: Vec<(u64, u64)> = Vec::new();
    let mut box_starts = std::collections::BTreeSet::new();
    let mut box_ends = std::collections::BTreeSet::new();
    let archive_boxes = iter_boxes(archive)?;
    for b in &archive_boxes {
        box_starts.insert(b.start);
        box_ends.insert(b.end);
        if &b.typ == b"mdat" {
            // Header length via sizes (pointer arithmetic would mix an
            // absolute address with the slice-relative offsets).
            let hdr = (b.end - b.start) - b.payload.len() as u64;
            mdats.push((b.start + hdr, b.start + hdr + b.payload.len() as u64));
        }
    }
    // Span validation: exact data, but it must agree with the bytes.
    for span in segments {
        if span.archive_len == 0 {
            return Err(bad(&format!(
                "segment span at {} carries zero length",
                span.archive_offset
            )));
        }
        let end = span.end()?;
        if end > archive.len() as u64 {
            return Err(bad(&format!(
                "segment span [{}, {end}) exceeds the {}-byte archive",
                span.archive_offset,
                archive.len()
            )));
        }
        if !box_starts.contains(&span.archive_offset) || !box_ends.contains(&end) {
            return Err(bad(&format!(
                "segment span [{}, {end}) does not align with box boundaries \
                 (span/box structure contradiction)",
                span.archive_offset
            )));
        }
    }
    for b in &archive_boxes {
        if &b.typ != b"moof" {
            continue;
        }
        // The enclosing span: exact caller data, first containing span
        // in slice order (the ledger's order).
        let Some(span) = segments.iter().find(|s| s.contains(b.start)) else {
            return Err(bad(&format!(
                "moof at {} lies outside every segment span (ledger/archive disagreement)",
                b.start
            )));
        };
        let span_start = span.archive_offset;
        let span_end = span.end()?;
        let trafs = read_moof(b.payload)?;
        for traf in trafs {
            if traf.track_id != desc.track_id {
                // Muxed A/V archives interleave the other track's
                // fragments in the same moof — the selected-track
                // fold skips them; a zero-sample fold
                // over a non-empty archive is caught below as the
                // pairing error it is.
                continue;
            }
            // §8.8.7: explicit base-data-offset is segment-file
            // absolute; default-base-is-moof anchors at the moof.
            let base = match traf.base_data_offset {
                Some(file_relative) => span_start.checked_add(file_relative),
                None => Some(b.start),
            }
            .ok_or_else(|| bad("base_data_offset overflows the archive address space"))?;
            if let Some(t) = traf.base_decode_time {
                let span: u64 = traf
                    .truns
                    .iter()
                    .flat_map(|tr| {
                        tr.samples.iter().map(|s| {
                            u64::from(s.duration.or(traf.default_sample_duration).unwrap_or(0))
                        })
                    })
                    .sum();
                timeline_end = Some(t + span);
            }
            let mut run_cursor: Option<u64> = None;
            for trun in &traf.truns {
                let mut pos = match (trun.data_offset, run_cursor) {
                    (Some(d), _) => {
                        let b64 = base as i64 + d;
                        if b64 < 0 {
                            return Err(bad("trun data_offset resolves before the archive start"));
                        }
                        b64 as u64
                    }
                    (None, Some(c)) => c,
                    (None, None) => {
                        return Err(bad(
                            "first trun of a traf carries no data_offset (anchor unknown)",
                        ));
                    }
                };
                for (i, s) in trun.samples.iter().enumerate() {
                    let Some(len) = s.size.or(traf.default_sample_size) else {
                        return Err(bad(
                            "trun sample size not derivable (native unsupported input)",
                        ));
                    };
                    let Some(duration) = s.duration.or(traf.default_sample_duration) else {
                        return Err(bad(
                            "trun sample duration not derivable (native unsupported input)",
                        ));
                    };
                    let flags = if i == 0 {
                        s.flags
                            .or(trun.first_sample_flags)
                            .or(traf.default_sample_flags)
                            .unwrap_or(0)
                    } else {
                        s.flags.or(traf.default_sample_flags).unwrap_or(0)
                    };
                    let end = pos
                        .checked_add(len as u64)
                        .ok_or_else(|| bad("sample span overflow"))?;
                    // Own-span containment: the sample range must sit
                    // inside an mdat payload that lies within the
                    // traf's own segment span. Landing in another
                    // segment's mdat (the misresolution shapes the
                    // review rounds reproduced) refuses loudly —
                    // never silently wrong bytes.
                    if !mdats.iter().any(|&(ms, me)| {
                        ms >= span_start && me <= span_end && pos >= ms && end <= me
                    }) {
                        return Err(bad(&format!(
                            "folded sample at {pos}..{end} does not fall inside an mdat \
                             payload of its own segment span [{span_start}, {span_end})"
                        )));
                    }
                    samples.push(FoldedSample {
                        offset: pos,
                        len,
                        duration,
                        cts: s.cts.unwrap_or(0),
                        sync: flags & SAMPLE_NON_SYNC == 0,
                    });
                    pos = end;
                }
                run_cursor = Some(pos);
            }
        }
    }
    let total_duration = samples
        .iter()
        .map(|s| u64::from(s.duration))
        .fold(0u64, |a, b| a.saturating_add(b));
    if samples.is_empty() && !segments.is_empty() {
        return Err(bad(&format!(
            "no archive traf matches the selected track (track_id {}) — the \
             init/archive pairing is wrong",
            desc.track_id
        )));
    }
    Ok(FoldedTrack {
        timescale: desc.timescale,
        handler: desc.handler,
        stsd_entries: desc.stsd_entries.clone(),
        media_header: desc.media_header.clone(),
        dinf: desc.dinf.clone(),
        tkhd_width_height: desc.tkhd_width_height,
        tkhd_volume: desc.tkhd_volume,
        samples,
        total_duration,
        timeline_end,
    })
}

/// The single-trak init description.
#[derive(Debug, Clone)]
pub struct InitDescription {
    pub track_id: u32,
    pub tkhd_width_height: Option<(u32, u32)>,
    pub tkhd_volume: u16,
    pub timescale: u32,
    pub handler: FourCC,
    pub stsd_entries: Vec<StsdEntry>,
    pub media_header: Vec<u8>,
    pub dinf: Option<Vec<u8>>,
}

/// Parse an init segment (ftyp + moov): extracts the single trak's
/// description. Returns the description with stsd entries verbatim.
///
/// Single-trak convenience face: the HLS per-track form;
/// a muxed A/V init (≥2 traks, the dominant single-file BYTERANGE
/// shape) parses through [`parse_init_tracks`] and folds through
/// [`fold_track_for`] — this face refuses it rather than guessing
/// which trak "the" trak is.
pub fn parse_init(init: &[u8]) -> Result<InitDescription, crate::error::MediaError> {
    let tracks = parse_init_tracks(init)?;
    if tracks.len() != 1 {
        return Err(bad(&format!(
            "init carries {} traks (the single-trak convenience face; a muxed A/V \
             init selects per kind — parse_init_tracks + fold_track_for)",
            tracks.len()
        )));
    }
    tracks
        .into_iter()
        .next()
        .ok_or_else(|| bad("no trak (unreachable after the count check)"))
}

/// Parse **every** trak of an init segment: the parse
/// face accepts multi-trak inits (muxed A/V) and returns one
/// description per trak, each keyed by its own `track_id` (the
/// selected-track fold's traf filter). An init with zero traks is an
/// explicit error.
pub fn parse_init_tracks(init: &[u8]) -> Result<Vec<InitDescription>, crate::error::MediaError> {
    let boxes = iter_boxes(init)?;
    let Some(moov) = boxes.iter().find(|b| &b.typ == b"moov") else {
        return Err(bad("init segment carries no moov"));
    };
    let traks = boxes_of(moov.payload, b"trak")?;
    if traks.is_empty() {
        return Err(bad("init carries no trak"));
    }
    traks.iter().map(parse_one_trak).collect()
}

/// Handler-kind selection over a parsed init: `"video"`
/// picks the `vide` trak, `"audio"` the `soun` trak (subtitle tracks
/// never reach the fold). Falls back to the first trak when no
/// handler matches — the fold's zero-sample refusal then names the
/// pairing error.
pub fn select_init_track<'a>(
    tracks: &'a [InitDescription],
    kind: &str,
) -> Option<&'a InitDescription> {
    let want = if kind == "audio" {
        HANDLER_AUDIO
    } else {
        HANDLER_VIDEO
    };
    tracks
        .iter()
        .find(|t| t.handler == want)
        .or_else(|| tracks.first())
}

fn parse_one_trak(trak: &RawBox<'_>) -> Result<InitDescription, crate::error::MediaError> {
    let tkhd = need(trak.payload, b"tkhd", "trak")?;
    let tkhd_info = read_tkhd(tkhd.payload)?;
    let mdia = need(trak.payload, b"mdia", "trak")?;
    let mdhd = need(mdia.payload, b"mdhd", "mdia")?;
    let mdhd_info = read_mdhd(mdhd.payload)?;
    let hdlr = need(mdia.payload, b"hdlr", "mdia")?;
    let handler = read_hdlr(hdlr.payload)?;
    let minf = need(mdia.payload, b"minf", "mdia")?;
    let stbl = need(minf.payload, b"stbl", "minf")?;
    let stsd = need(stbl.payload, b"stsd", "stbl")?;
    let stsd_entries = read_stsd(stsd.payload)?;
    if stsd_entries.is_empty() {
        return Err(bad("stsd carries no entries"));
    }
    // minf's media-header child (vmhd/smhd/…): verbatim, or synthesized.
    let mut media_header: Option<Vec<u8>> = None;
    for b in iter_boxes(minf.payload)? {
        let t = &b.typ;
        if t == b"vmhd" || t == b"smhd" || t == b"hmhd" || t == b"nmhd" || t == b"gmhd" {
            media_header = Some(minf.payload[b.start as usize..b.end as usize].to_vec());
            break;
        }
    }
    let dinf = child(minf.payload, b"dinf")?
        .map(|b| minf.payload[b.start as usize..b.end as usize].to_vec());
    Ok(InitDescription {
        track_id: tkhd_info.track_id,
        tkhd_width_height: if tkhd_info.width != 0 || tkhd_info.height != 0 {
            Some((tkhd_info.width, tkhd_info.height))
        } else {
            None
        },
        tkhd_volume: tkhd_info.volume,
        timescale: mdhd_info.timescale,
        handler,
        stsd_entries,
        media_header: media_header.unwrap_or_else(|| synth_media_header(&handler)),
        dinf,
    })
}

/// Children of a container payload with the given type.
pub fn boxes_of<'a>(
    payload: &'a [u8],
    typ: &FourCC,
) -> Result<Vec<RawBox<'a>>, crate::error::MediaError> {
    let mut out = Vec::new();
    for b in iter_boxes(payload)? {
        if &b.typ == typ {
            out.push(b);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// sidx (segment index) — the DASH single-level addressing face
// ---------------------------------------------------------------------------

/// One `sidx` reference row (ISO/IEC 14496-12 §8.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidxRef {
    /// `reference_type`: `false` = media subsegment, `true` = a
    /// referenced **sidx** (the hierarchical/nested index — the
    /// caller refuses it as `sidx_unsupported`).
    pub reference_type: bool,
    /// `reference_size` (31 bits; media bytes for a media reference).
    pub reference_size: u32,
    /// `subsegment_duration` (in the sidx's timescale).
    pub subsegment_duration: u32,
    /// `starts_with_SAP`.
    pub starts_with_sap: bool,
    /// SAP type (1..=6) when `starts_with_sap`.
    pub sap_type: u8,
}

/// The parsed `sidx` fields the DASH addressing consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidxInfo {
    /// Fullbox version (0 = 32-bit times, 1 = 64-bit).
    pub version: u8,
    /// `reference_ID`.
    pub reference_id: u32,
    /// `timescale` (ticks per second for `subsegment_duration`).
    pub timescale: u32,
    /// `earliest_presentation_time` (u64 in both versions — the
    /// version-0 32-bit value widens losslessly).
    pub earliest_presentation_time: u64,
    /// `first_offset` (byte distance from the **end of this sidx
    /// box** to the first referenced subsegment).
    pub first_offset: u64,
    /// Reference rows in box order.
    pub references: Vec<SidxRef>,
}

impl SidxInfo {
    /// Whether any reference names a nested sidx (reference_type=1).
    pub fn has_nested_sidx(&self) -> bool {
        self.references.iter().any(|r| r.reference_type)
    }
}

/// Parse a `sidx` box **payload** (the bytes after the 8-byte box
/// header — pass [`RawBox::payload`]). Every read is bounds-checked
/// (the bounds-check discipline: hostile bytes are a staging error,
/// never a panic); a truncated reference table or a version outside
/// {0, 1} refuses.
pub fn read_sidx(payload: &[u8]) -> Result<SidxInfo, crate::error::MediaError> {
    let mut cur = Cur::new(payload);
    let (version, _) = cur.version_flags()?;
    let reference_id = cur.u32()?;
    let timescale = cur.u32()?;
    let (ept, first_offset) = match version {
        0 => (u64::from(cur.u32()?), u64::from(cur.u32()?)),
        1 => (cur.u64()?, cur.u64()?),
        v => {
            return Err(bad(&format!("sidx version {v} (expected 0 or 1)")));
        }
    };
    let _reserved = cur.u16()?;
    let reference_count = cur.u16()?;
    let mut references = Vec::with_capacity(reference_count.min(4096) as usize);
    for i in 0..reference_count {
        let word = cur.u32()?;
        let reference_type = (word >> 31) & 1 == 1;
        let reference_size = word & 0x7FFF_FFFF;
        let subsegment_duration = cur.u32()?;
        let sap_word = cur.u32()?;
        let starts_with_sap = (sap_word >> 31) & 1 == 1;
        let sap_type = ((sap_word >> 28) & 0x7) as u8;
        references.push(SidxRef {
            reference_type,
            reference_size,
            subsegment_duration,
            starts_with_sap,
            sap_type,
        });
        let _ = i;
    }
    Ok(SidxInfo {
        version,
        reference_id,
        timescale,
        earliest_presentation_time: ept,
        first_offset,
        references,
    })
}

// ---------------------------------------------------------------------------
// tiny box writer (shared with mp4write/probe fixtures on the read side)
// ---------------------------------------------------------------------------

/// Serialize one box (`size + type + payload`).
pub fn box_bytes(typ: &FourCC, payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
    out.extend_from_slice(typ);
    out.extend_from_slice(&payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Box iteration: 32-bit sizes, the extends-to-end form, the
    /// largesize escape, and the overrun refusal.
    #[test]
    fn iter_boxes_shapes() {
        let a = box_bytes(b"ftyp", vec![1, 2, 3, 4]);
        let b = box_bytes(b"moov", vec![9; 12]);
        let mut buf = a.clone();
        buf.extend_from_slice(&b);
        let boxes = iter_boxes(&buf).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(boxes.len(), 2);
        assert_eq!(boxes[0].typ, *b"ftyp");
        assert_eq!(boxes[0].payload, &[1, 2, 3, 4]);
        assert_eq!(boxes[1].start, 12);
        assert_eq!(boxes[1].end, 32);
        // size == 0: extends to the end.
        let mut c = Vec::new();
        c.extend_from_slice(&0u32.to_be_bytes());
        c.extend_from_slice(b"mdat");
        c.extend_from_slice(&[7; 5]);
        let boxes = iter_boxes(&c).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].payload.len(), 5);
        // largesize.
        let mut d = Vec::new();
        d.extend_from_slice(&1u32.to_be_bytes());
        d.extend_from_slice(b"mdat");
        d.extend_from_slice(&(16 + 10u64).to_be_bytes());
        d.extend_from_slice(&[0; 10]);
        let boxes = iter_boxes(&d).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(boxes.len(), 1);
        assert_eq!(boxes[0].payload.len(), 10);
        // Overrun refused.
        let mut e = Vec::new();
        e.extend_from_slice(&100u32.to_be_bytes());
        e.extend_from_slice(b"mdats");
        assert!(iter_boxes(&e).is_err());
        // Trailing garbage refused.
        assert!(iter_boxes(&[0, 0, 0]).is_err());
    }

    /// stsd entries keep their whole-box bytes verbatim.
    #[test]
    fn stsd_entry_verbatim_bytes() {
        let entry = box_bytes(b"avc1", vec![0xA5; 30]);
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_be_bytes()); // version/flags
        payload.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        payload.extend_from_slice(&entry);
        let stsd = box_bytes(b"stsd", payload);
        let entries = read_stsd(&stsd[8..]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].fourcc, *b"avc1");
        assert_eq!(entries[0].bytes, entry, "whole-entry passthrough bytes");
    }

    /// Integer-wraparound regression (the crafted-largesize
    /// finding): a box at offset 8 declaring `largesize = 2^64 - 8`
    /// makes the unchecked `off as u64 + size` wrap to 0, which then
    /// passes the `> buf.len()` bounds check and panics on the payload
    /// slice (`slice index starts at 24 but ends at 0`) — in release
    /// builds too. The wrap must be an explicit staging error, never a
    /// panic; the same crafted shape must refuse through every
    /// consumer entry point (parse_init / fold_track).
    #[test]
    fn iter_boxes_u64_wraparound_is_an_error() {
        let mut buf = Vec::new();
        // Box 0: 8-byte free box.
        buf.extend_from_slice(&8u32.to_be_bytes());
        buf.extend_from_slice(b"free");
        // Box 1 at offset 8: size32 == 1 (largesize form), largesize
        // = 2^64 - 8 → off(8) + size wraps to 0.
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(b"mdat");
        buf.extend_from_slice(&(u64::MAX - 7).to_be_bytes());
        match iter_boxes(&buf) {
            Ok(boxes) => panic!("wraparound size accepted: {boxes:?}"),
            Err(e) => assert_eq!(e.code(), "taiji.media.staging"),
        }
        // The consumer entry points refuse the same shape (a crafted
        // ftyp-less init / archive), not panic.
        assert!(parse_init(&buf).is_err());
        assert!(fold_track(&buf, &buf, &[]).is_err());
    }

    /// Near-wraparound neighbors stay honest: a largesize that merely
    /// overruns the buffer is the pre-existing explicit error (no
    /// regression in the ordinary bounds path), and a legal largesize
    /// form still parses.
    #[test]
    fn iter_boxes_largesize_bounds_unchanged() {
        // Legal largesize (16-byte header + 10 payload) still parses.
        let mut ok = Vec::new();
        ok.extend_from_slice(&1u32.to_be_bytes());
        ok.extend_from_slice(b"mdat");
        ok.extend_from_slice(&(16 + 10u64).to_be_bytes());
        ok.extend_from_slice(&[0; 10]);
        let boxes = iter_boxes(&ok).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(boxes[0].payload.len(), 10);
        // Plain overrun stays an explicit error.
        let mut over = Vec::new();
        over.extend_from_slice(&100u32.to_be_bytes());
        over.extend_from_slice(b"mdat");
        assert!(iter_boxes(&over).is_err());
        // largesize = u64::MAX (off 0 + MAX wraps to MAX-… no wrap, but
        // > len) is refused too.
        let mut big = Vec::new();
        big.extend_from_slice(&1u32.to_be_bytes());
        big.extend_from_slice(b"mdat");
        big.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(iter_boxes(&big).is_err());
    }

    /// sidx round-trip: a version-0 box with three media
    /// references and a version-1 box with a nested (reference_type=1)
    /// row both parse field-exact; truncated payloads and unknown
    /// versions refuse.
    #[test]
    fn sidx_shapes() {
        // version 0, timescale 1000, ept 0, first_offset 0, 3 refs.
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_be_bytes()); // version/flags
        payload.extend_from_slice(&1u32.to_be_bytes()); // reference_ID
        payload.extend_from_slice(&1000u32.to_be_bytes()); // timescale
        payload.extend_from_slice(&0u32.to_be_bytes()); // ept
        payload.extend_from_slice(&0u32.to_be_bytes()); // first_offset
        payload.extend_from_slice(&0u16.to_be_bytes()); // reserved
        payload.extend_from_slice(&3u16.to_be_bytes()); // reference_count
        for (i, size) in [1000u32, 1010, 990].iter().enumerate() {
            let type_bit = if i == 1 { 1u32 << 31 } else { 0 };
            payload.extend_from_slice(&(type_bit | size).to_be_bytes());
            payload.extend_from_slice(&((i as u32 + 1) * 1000).to_be_bytes());
            payload.extend_from_slice(&(0x8000_0000u32 | (1 << 28)).to_be_bytes());
        }
        let info = read_sidx(&payload).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(info.version, 0);
        assert_eq!(info.timescale, 1000);
        assert_eq!(info.references.len(), 3);
        assert_eq!(info.references[0].reference_size, 1000);
        assert!(!info.references[0].reference_type);
        assert!(info.references[1].reference_type, "row 1 is a nested sidx");
        assert!(info.has_nested_sidx());
        assert!(info.references[0].starts_with_sap);
        assert_eq!(info.references[0].sap_type, 1);

        // version 1 widens the time fields.
        let mut v1 = Vec::new();
        v1.extend_from_slice(&0x0100_0000u32.to_be_bytes()); // version 1
        v1.extend_from_slice(&7u32.to_be_bytes());
        v1.extend_from_slice(&90000u32.to_be_bytes());
        v1.extend_from_slice(&123456789012u64.to_be_bytes()); // ept 64
        v1.extend_from_slice(&64u64.to_be_bytes()); // first_offset 64
        v1.extend_from_slice(&0u16.to_be_bytes()); // reserved
        v1.extend_from_slice(&1u16.to_be_bytes()); // reference_count
        v1.extend_from_slice(&(4096u32).to_be_bytes());
        v1.extend_from_slice(&90000u32.to_be_bytes());
        v1.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        let info = read_sidx(&v1).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(info.earliest_presentation_time, 123_456_789_012);
        assert_eq!(info.first_offset, 64);
        assert!(!info.has_nested_sidx());

        // Truncated / bad version refuse.
        assert!(read_sidx(&payload[..20]).is_err());
        let mut v2 = payload.clone();
        v2[0] = 2; // version 2
        assert!(read_sidx(&v2).is_err());
    }

    /// Build the 48-byte attack moof: a traf carrying the
    /// minimal default-base-is-moof tfhd plus a trun with `flags = 0`
    /// (no per-sample fields) and an attacker-chosen `sample_count`.
    /// With flags = 0 each sample consumes zero payload bytes, so the
    /// pre-fix `Vec::with_capacity(sample_count)` trusted the count
    /// alone — a remote 48-byte moof declaring `0xFFFF_FFFF` samples
    /// demanded a ~137 GiB reservation (4 bytes of count × 32 bytes of
    /// `TrunSample`).
    fn attack_moof_48b(sample_count: u32) -> Vec<u8> {
        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&0u32.to_be_bytes()); // version 0, flags 0
        trun_payload.extend_from_slice(&sample_count.to_be_bytes());
        let trun = box_bytes(b"trun", trun_payload);
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&TFHD_DEFAULT_BASE_IS_MOOF.to_be_bytes());
        tfhd_payload.extend_from_slice(&7u32.to_be_bytes()); // track_id
        let tfhd = box_bytes(b"tfhd", tfhd_payload);
        let traf = box_bytes(b"traf", [tfhd, trun].concat());
        let moof = box_bytes(b"moof", traf);
        assert_eq!(moof.len(), 48, "the attack shape is exactly 48 bytes");
        moof
    }

    /// The declared trun sample count is bounded by the
    /// payload that declares it — the 48-byte moof with
    /// `sample_count = 0xFFFF_FFFF` (flags = 0) must be an explicit
    /// staging error, never a ~137 GiB reservation (the pre-fix
    /// `with_capacity` aborted the process on allocation failure).
    #[test]
    fn trun_sample_count_bounded_by_payload() {
        let moof = attack_moof_48b(u32::MAX);
        match read_moof(&moof[8..]) {
            Ok(trafs) => panic!("huge sample_count accepted: {trafs:?}"),
            Err(e) => assert_eq!(e.code(), "taiji.media.staging"),
        }
        // The same crafted shape refuses through the archive entry
        // point (the fuzz face), not just the direct moof read.
        assert!(fold_track(&moof, &moof, &[]).is_err());
    }

    /// H1 neighbors stay green: a count that fits the payload parses
    /// (flags = 0 with a small count), and a fields-carrying trun
    /// whose count overruns the payload is rejected by the same
    /// payload-derived bound (previously by the first overrunning
    /// read — same error code, earlier and without the reservation).
    #[test]
    fn trun_sample_count_bound_neighbors() {
        // flags = 0, count 3, 3 trailing payload bytes vouch for it.
        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&0u32.to_be_bytes());
        trun_payload.extend_from_slice(&3u32.to_be_bytes());
        trun_payload.extend_from_slice(&[0; 3]);
        let trun = box_bytes(b"trun", trun_payload);
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&TFHD_DEFAULT_BASE_IS_MOOF.to_be_bytes());
        tfhd_payload.extend_from_slice(&7u32.to_be_bytes());
        let tfhd = box_bytes(b"tfhd", tfhd_payload);
        let traf = box_bytes(b"traf", [tfhd.clone(), trun].concat());
        let moof = box_bytes(b"moof", traf);
        let trafs = read_moof(&moof[8..]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(trafs[0].truns[0].samples.len(), 3);

        // flags = duration|size (8 bytes/sample), count 3 needs 24
        // payload bytes but only 8 remain → explicit staging error.
        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&(TRUN_SAMPLE_DURATION | TRUN_SAMPLE_SIZE).to_be_bytes());
        trun_payload.extend_from_slice(&3u32.to_be_bytes());
        trun_payload.extend_from_slice(&[0; 8]);
        let trun = box_bytes(b"trun", trun_payload);
        let traf = box_bytes(b"traf", [tfhd, trun].concat());
        let moof = box_bytes(b"moof", traf);
        match read_moof(&moof[8..]) {
            Ok(trafs) => panic!("overrunning sample table accepted: {trafs:?}"),
            Err(e) => assert_eq!(e.code(), "taiji.media.staging"),
        }
    }
}

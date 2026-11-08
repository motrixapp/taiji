//! WebVTT sidecar line (per the product spec's subtitle face,
//! inherited via the media spec's checklist + track-necessity grading).
//!
//! The subtitle track's staging archive (concatenated WebVTT
//! segment bodies) is spliced into one `.vtt` product:
//!
//! * **cue-level parse** ([`parse_vtt`]): header line, cue ids,
//!   `hh:mm:ss.mmm --> hh:mm:ss.mmm` timestamps (both `.` and `,`
//!   millisecond separators, the SRT-compatible tolerance), payload
//!   lines; NOTE/STYLE blocks skipped. Pure and total — arbitrary
//!   bytes are a `vtt_parse` text error or a bounded best-effort
//!   skip, never a panic (the fuzz target pins this).
//! * **timeline continuity rule** (documented, deterministic): within
//!   one segment, cues whose minimum start sits at or below the
//!   accumulated timeline position + 1 s are treated as
//!   **relative to the segment start** and shift by the accumulated
//!   position; cues already beyond that are treated as **absolute**
//!   and pass through unshifted (the yt-dlp detection form). The
//!   accumulated position = Σ previous segments' EXTINF durations.
//! * **DISCONTINUITY**: does not reset the sidecar timeline — the gap
//!   is bridged by the following segment's EXTINF accumulation (the
//!   one-product-face ruling; a discontinuity gap that drops subtitle
//!   continuity is a degraded-sidecar matter, not a splice error).
//! * **splice failure** = a segment whose body is not parseable
//!   WebVTT: the sidecar degrades ([`SpliceOutcome::Degraded`]) with
//!   the offending segment named — per the sidecar grading an explicitly
//!   attached side track never fails the task and never triggers the
//!   both-channels terminal state.
//! * **tx3g conversion** ([`cues_to_tx3g`]): plain-text cue windows
//!   for [`crate::mp4write::tx3g_track_spec`] — VTT markup stripped
//!   (tags/`<c>` classes/inline timestamps), the kickoff-gate matrix item.

use crate::error::MediaError;

/// Hard cap on cues per segment and text per cue (the resource
/// posture for a remote-influenced parse face).
pub const MAX_CUES_PER_SEGMENT: usize = 10_000;
/// Cue payload cap per cue (bytes, after decode).
pub const MAX_CUE_BYTES: usize = 64 * 1024;
/// Document (spliced product) cue cap.
pub const MAX_TOTAL_CUES: usize = 200_000;

/// Hours ceiling for one timestamp: the WebVTT grammar
/// allows arbitrary-digit hours, but a u64 hours field overflows the
/// ms multiply long before any legitimate subtitle horizon; 999 h
/// (≈41 days) is the accepted ceiling, beyond which the timestamp is
/// an explicit parse error.
const MAX_TIMESTAMP_HOURS: u64 = 999;

/// One parsed cue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cue {
    /// Cue identifier line (when present).
    pub id: Option<String>,
    /// Start time, milliseconds.
    pub start_ms: u64,
    /// End time, milliseconds.
    pub end_ms: u64,
    /// Payload lines (markup preserved at parse; stripped at tx3g
    /// conversion).
    pub lines: Vec<String>,
}

impl Cue {
    /// Payload joined with LF.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }
}

/// Parse one WebVTT document (a segment body or a sidecar). NOTE and
/// STYLE blocks are skipped; header metadata lines before the first
/// cue are ignored (X-TIMESTAMP-MAP included — see the module docs:
/// MPEGTS-mapped timelines are not remapped in 0.3).
pub fn parse_vtt(body: &str) -> Result<Vec<Cue>, MediaError> {
    let mut cues = Vec::new();
    let mut lines = body.lines().peekable();
    // Header: the WEBVTT signature (with or without trailing text).
    match lines.next() {
        Some(first) if first.starts_with("WEBVTT") => {}
        Some(_) if body.trim().is_empty() => return Ok(cues),
        _ => {
            return Err(MediaError::Parse(
                "vtt: missing WEBVTT signature".to_string(),
            ));
        }
    }
    // Skip header metadata until a blank line.
    while let Some(line) = lines.peek() {
        if line.trim().is_empty() {
            let _ = lines.next();
            break;
        }
        let _ = lines.next();
    }
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "NOTE" || trimmed.starts_with("NOTE ") {
            // Comment block: skip to a blank line.
            for l in lines.by_ref() {
                if l.trim().is_empty() {
                    break;
                }
            }
            continue;
        }
        if trimmed == "STYLE" {
            for l in lines.by_ref() {
                if l.trim().is_empty() {
                    break;
                }
            }
            continue;
        }
        // A cue: optional id line, then the timing line, then payload.
        let (id, timing_line) = if trimmed.contains("-->") {
            (None, trimmed.to_string())
        } else {
            let id = trimmed.to_string();
            match lines.next() {
                Some(t) if t.trim().contains("-->") => (Some(id), t.trim().to_string()),
                _ => {
                    return Err(MediaError::Parse(format!(
                        "vtt: cue id {id:?} not followed by a timing line"
                    )));
                }
            }
        };
        let (start_ms, end_ms) = parse_timing(&timing_line)?;
        let mut payload: Vec<String> = Vec::new();
        let mut payload_bytes = 0usize;
        for peek in lines.by_ref() {
            if peek.trim().is_empty() {
                break;
            }
            payload_bytes = payload_bytes.saturating_add(peek.len());
            if payload_bytes > MAX_CUE_BYTES {
                return Err(MediaError::Parse("vtt: cue payload over cap".to_string()));
            }
            payload.push(peek.trim_end().to_string());
        }
        if payload.is_empty() {
            return Err(MediaError::Parse(format!("vtt: cue {id:?} has no payload")));
        }
        if cues.len() >= MAX_CUES_PER_SEGMENT {
            return Err(MediaError::Parse("vtt: cue count over cap".to_string()));
        }
        cues.push(Cue {
            id,
            start_ms,
            end_ms,
            lines: payload,
        });
    }
    Ok(cues)
}

/// Parse `hh:mm:ss.mmm --> hh:mm:ss.mmm` (also `mm:ss.mmm` and the
/// `,` millisecond separator). Cue settings after the end timestamp
/// are ignored (forward compatibility).
fn parse_timing(line: &str) -> Result<(u64, u64), MediaError> {
    let Some((left, right)) = line.split_once("-->") else {
        return Err(MediaError::Parse(format!(
            "vtt: not a timing line: {line:?}"
        )));
    };
    let start = parse_timestamp(left.trim())?;
    let end_str = right.split_whitespace().next().unwrap_or("");
    let end = parse_timestamp(end_str)?;
    if end < start {
        return Err(MediaError::Parse(format!(
            "vtt: cue end {end} before start {start}"
        )));
    }
    Ok((start, end))
}

/// Parse one timestamp (hours optional; `.`/`,` before ms).
fn parse_timestamp(text: &str) -> Result<u64, MediaError> {
    let bad = || MediaError::Parse(format!("vtt: bad timestamp {text:?}"));
    let (clock, millis) = match text.rsplit_once(['.', ',']) {
        Some((clock, ms)) => (clock, ms),
        None => (text, ""),
    };
    let ms: u64 = if millis.is_empty() {
        0
    } else {
        if millis.len() > 3 || !millis.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let value = millis.parse::<u64>().map_err(|_| bad())?;
        // ".5" = 500 ms (right-aligned fractional).
        value * 10u64.pow(3 - millis.len() as u32)
    };
    let parts: Vec<&str> = clock.split(':').collect();
    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(bad());
    }
    if parts.iter().any(|p| !p.bytes().all(|b| b.is_ascii_digit())) {
        return Err(bad());
    }
    let seconds = parts[parts.len() - 1].parse::<u64>().map_err(|_| bad())?;
    let minutes = parts
        .get(parts.len() - 2)
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .unwrap_or(0);
    let hours = if parts.len() == 3 {
        parts[0].parse::<u64>().unwrap_or(0)
    } else {
        0
    };
    if minutes > 59 {
        return Err(bad());
    }
    // The ms arithmetic is checked (a u64-scale hours or
    // seconds field used to overflow the multiply — a debug panic, a
    // silently wrapped timeline in release), and hours carry an
    // explicit 999-hour ceiling (~41 days, far past any subtitle
    // horizon) so the remaining adds cannot overflow u64.
    if hours > MAX_TIMESTAMP_HOURS {
        return Err(bad());
    }
    hours
        .checked_mul(3_600_000)
        .and_then(|h| h.checked_add(minutes * 60_000))
        .and_then(|hm| hm.checked_add(seconds.checked_mul(1000)?))
        .and_then(|total| total.checked_add(ms))
        .ok_or_else(bad)
}

/// The spliced sidecar product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpliceOutcome {
    /// All segments parsed; the product text is carried.
    Complete(Vec<Cue>),
    /// A segment failed the parse: the sidecar degrades — the
    /// payload names the failing segment index and reason.
    Degraded {
        failed_segment: usize,
        reason: String,
    },
}

/// Splice per-segment cue lists into one timeline.
///
/// `segments`: (segment_index, segment_cues, segment_duration_ms) —
/// the cues as parsed from that segment's archive slice; the duration
/// from the ledger's EXTINF accounting. The relative/absolute rule
/// (module docs): a segment whose minimum cue start ≤ accumulated
/// position + 1 s shifts by the accumulated position; otherwise its
/// cues pass through (absolute timeline already).
pub fn splice_timeline(segments: &[(usize, Vec<Cue>, u64)]) -> Result<SpliceOutcome, MediaError> {
    let mut out: Vec<Cue> = Vec::new();
    let mut position = 0u64;
    for &(_idx, ref cues, duration_ms) in segments {
        let relative = cues
            .iter()
            .map(|c| c.start_ms)
            .min()
            .is_none_or(|m| m <= position.saturating_add(1000));
        for cue in cues {
            let shifted = if relative {
                Cue {
                    id: cue.id.clone(),
                    start_ms: cue.start_ms.saturating_add(position),
                    end_ms: cue.end_ms.saturating_add(position),
                    lines: cue.lines.clone(),
                }
            } else {
                cue.clone()
            };
            out.push(shifted);
            if out.len() >= MAX_TOTAL_CUES {
                return Err(MediaError::Parse(
                    "vtt: total cue count over cap".to_string(),
                ));
            }
        }
        position = position.saturating_add(duration_ms);
    }
    // Sort by start (segment-internal order preserved otherwise).
    out.sort_by_key(|c| c.start_ms);
    Ok(SpliceOutcome::Complete(out))
}

/// Splice the raw segment bodies: parse each, then [`splice_timeline`].
/// The first unparseable segment degrades the whole sidecar
/// (degraded completion + warning — never the both-channels terminal state).
pub fn splice_segments(bodies: &[(usize, &str, u64)]) -> Result<SpliceOutcome, MediaError> {
    let mut parsed: Vec<(usize, Vec<Cue>, u64)> = Vec::with_capacity(bodies.len());
    for &(idx, body, duration_ms) in bodies {
        match parse_vtt(body) {
            Ok(cues) => parsed.push((idx, cues, duration_ms)),
            Err(e) => {
                return Ok(SpliceOutcome::Degraded {
                    failed_segment: idx,
                    reason: e.to_string(),
                });
            }
        }
    }
    splice_timeline(&parsed)
}

/// Format one cue for the product file (settings-free, `.` ms).
fn format_timestamp(ms: u64) -> String {
    let h = ms / 3_600_000;
    let m = (ms % 3_600_000) / 60_000;
    let s = (ms % 60_000) / 1000;
    let milli = ms % 1000;
    format!("{h:02}:{m:02}:{s:02}.{milli:03}")
}

/// Render the spliced product file text (header + cues).
pub fn render_sidecar(cues: &[Cue]) -> String {
    let mut out = String::from("WEBVTT\n\n");
    for cue in cues {
        if let Some(id) = &cue.id {
            out.push_str(id);
            out.push('\n');
        }
        out.push_str(&format_timestamp(cue.start_ms));
        out.push_str(" --> ");
        out.push_str(&format_timestamp(cue.end_ms));
        out.push('\n');
        for line in &cue.lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

/// Strip VTT inline markup (tags, inline timestamp voices, class
/// spans) to plain text — the tx3g conversion's text face. HTML
/// entities are preserved verbatim (0.3 does not decode them; noted
/// in docs/design/media-synthesis.md).
pub fn strip_vtt_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '<' {
            // Skip to the matching '>'; an unterminated tag consumes
            // to the end (tolerant).
            for inner in chars.by_ref() {
                if inner == '>' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Cue windows for the tx3g track (start_ms, end_ms, plain text).
pub fn cues_to_tx3g(cues: &[Cue]) -> Vec<(u64, u64, String)> {
    cues.iter()
        .map(|c| {
            let text = strip_vtt_markup(&c.text());
            (c.start_ms, c.end_ms, text.trim().to_string())
        })
        .filter(|(_, _, t)| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEG0: &str = "WEBVTT\n\n00:00:00.000 --> 00:00:02.000\nhello world\n";
    const SEG1: &str =
        "WEBVTT\n\n1\n00:00:00.500 --> 00:00:02.500\nsecond <c.yellow>cue</c>\nline two\n";

    #[test]
    fn parse_cues_shapes() {
        let cues = parse_vtt(SEG0).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cues.len(), 1);
        assert_eq!(cues[0].start_ms, 0);
        assert_eq!(cues[0].end_ms, 2000);
        assert_eq!(cues[0].text(), "hello world");
        // Id line + multi-line payload + markup preserved.
        let cues = parse_vtt(SEG1).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cues[0].id.as_deref(), Some("1"));
        assert_eq!(cues[0].lines.len(), 2);
        assert_eq!(cues[0].end_ms, 2500);
        // `,` separator + mm:ss form + hours-omitted.
        let cues =
            parse_vtt("WEBVTT\n\n00:02.500 --> 00:04.000\nx\n").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((cues[0].start_ms, cues[0].end_ms), (2500, 4000));
        let cues = parse_vtt("WEBVTT\n\n01:02:03,250 --> 01:02:03.750\nx\n")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((cues[0].start_ms, cues[0].end_ms), (3_723_250, 3_723_750));
        // Fraction right-alignment: ".5" = 500 ms.
        let cues =
            parse_vtt("WEBVTT\n\n00:00:01.5 --> 00:00:02.5\nx\n").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cues[0].start_ms, 1500);
        // NOTE blocks skipped; settings after end ignored.
        let cues = parse_vtt(
            "WEBVTT\n\nNOTE\nthis is a comment\n\n00:00:00.000 --> 00:00:01.000 align:start\nx\n",
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cues.len(), 1);
        // Empty body = zero cues (not an error).
        assert!(
            parse_vtt("   ")
                .unwrap_or_else(|e| panic!("{e}"))
                .is_empty()
        );
    }

    #[test]
    fn parse_rejections() {
        // No signature.
        assert!(parse_vtt("00:00:00.000 --> 00:00:01.000\nx\n").is_err());
        // Timing without payload.
        assert!(parse_vtt("WEBVTT\n\n00:00:00.000 --> 00:00:01.000\n\n").is_err());
        // End before start.
        assert!(parse_vtt("WEBVTT\n\n00:00:05.000 --> 00:00:01.000\nx\n").is_err());
        // Bad timestamp shapes.
        for bad in [
            "WEBVTT\n\nxx --> 00:00:01.000\nx\n",
            "WEBVTT\n\n00:00:00.000 --> yy\nx\n",
        ] {
            assert!(parse_vtt(bad).is_err(), "{bad:?}");
        }
    }

    /// Timestamp arithmetic must not overflow. The
    /// pre-fix `hours * 3_600_000` panicked in debug builds (and
    /// wrapped to a bogus timeline in release) on a u64-scale hours
    /// field; seconds had the same multiply-overflow face. Both are
    /// explicit parse errors now, with hours additionally capped at
    /// 999 (the practical subtitle horizon).
    #[test]
    fn timestamp_overflow_is_an_error() {
        for attack in [
            // u64::MAX hours: hours * 3_600_000 overflows.
            "WEBVTT\n\n18446744073709551615:00:00.000 --> 00:00:01.000\nx\n",
            // u64::MAX seconds: seconds * 1000 overflows.
            "WEBVTT\n\n00:00:18446744073709551615.000 --> 00:00:01.000\nx\n",
        ] {
            assert!(parse_vtt(attack).is_err(), "{attack:?}");
        }
        // The hours cap: 999:59:59.999 is the accepted ceiling …
        let cues = parse_vtt("WEBVTT\n\n999:59:59.999 --> 999:59:59.999\nx\n")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cues[0].start_ms, 999 * 3_600_000 + 59 * 60_000 + 59_999);
        // … and 1000 hours is an explicit refusal.
        assert!(
            parse_vtt("WEBVTT\n\n1000:00:00.000 --> 1000:00:00.000\nx\n").is_err(),
            "hours over the 999 cap refuse"
        );
    }

    /// Relative segments shift by the accumulated EXTINF position;
    /// absolute-looking segments pass through.
    #[test]
    fn splice_relative_and_absolute() {
        let seg0 = parse_vtt(SEG0).unwrap_or_else(|e| panic!("{e}"));
        let seg1 = parse_vtt(SEG1).unwrap_or_else(|e| panic!("{e}"));
        // Both relative: durations 2000/2000.
        let out = match splice_timeline(&[(0, seg0.clone(), 2000), (1, seg1.clone(), 2000)])
            .unwrap_or_else(|e| panic!("{e}"))
        {
            SpliceOutcome::Complete(c) => c,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].start_ms, 0);
        assert_eq!(out[1].start_ms, 2500, "second segment shifted by 2000");
        // An absolute-timeline segment (starts at 60 s): no shift.
        let abs = vec![Cue {
            id: None,
            start_ms: 60_000,
            end_ms: 61_000,
            lines: vec!["late".to_string()],
        }];
        let out = match splice_timeline(&[(0, seg0, 2000), (1, abs, 2000)])
            .unwrap_or_else(|e| panic!("{e}"))
        {
            SpliceOutcome::Complete(c) => c,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(out[1].start_ms, 60_000, "absolute cues pass through");
    }

    /// First unparseable segment degrades the splice (sidecar
    /// grading), naming the segment.
    #[test]
    fn splice_degrades_on_bad_segment() {
        let out = splice_segments(&[(0, SEG0, 2000), (1, "not vtt", 2000)])
            .unwrap_or_else(|e| panic!("{e}"));
        match out {
            SpliceOutcome::Degraded {
                failed_segment,
                reason,
            } => {
                assert_eq!(failed_segment, 1);
                assert!(reason.contains("vtt"), "{reason}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Round-trip: parse → splice → render → parse again.
    #[test]
    fn render_roundtrip() {
        let out = match splice_segments(&[(0, SEG0, 2000), (1, SEG1, 2000)])
            .unwrap_or_else(|e| panic!("{e}"))
        {
            SpliceOutcome::Complete(c) => c,
            other => panic!("unexpected {other:?}"),
        };
        let text = render_sidecar(&out);
        assert!(text.starts_with("WEBVTT\n"));
        let reparsed = parse_vtt(&text).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(reparsed.len(), 2);
        assert_eq!(reparsed[1].start_ms, 2500);
    }

    /// Markup stripping for tx3g.
    #[test]
    fn markup_strip() {
        assert_eq!(strip_vtt_markup("a <c.b>c</c> d"), "a c d");
        assert_eq!(strip_vtt_markup("<v Roger>hi"), "hi");
        assert_eq!(strip_vtt_markup("plain"), "plain");
        let cues = parse_vtt(SEG1).unwrap_or_else(|e| panic!("{e}"));
        let windows = cues_to_tx3g(&cues);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].2, "second cue\nline two");
    }
}

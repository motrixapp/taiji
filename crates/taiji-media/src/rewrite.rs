//! Local per-track playlist rewrite (the product spec's rewrite face
//! via the media spec's checklist — the parse-gate golden face
//! "local playlist rewrite").
//!
//! Input: the parsed [`MediaPlaylist`] (structural tags + BYTERANGE/MAP
//! bookkeeping) + the ledger rows ([`SegmentRecord`], the
//! **plaintext** `seg_len` semantics). Output per track: the rewritten
//! `local-<label>.m3u8` text (staging file) plus the typed
//! [`TrackRewrite`] the native channel consumes.
//!
//! # Rewrite semantics (settled, on record here + the design doc)
//!
//! * **segment URI → the archive file**: every segment line names the
//!   track's one archive file (`archive-<label>.<ext>`), addressing
//!   its bytes with an explicit
//!   `#EXT-X-BYTERANGE:<seg_len>@<archive_offset>` — whole-resource
//!   source segments get an explicit range too (the archive-interval
//!   form; offsets = cumulative Σ plaintext seg_len in playlist
//!   order, the decrypted-archive semantics);
//! * **plaintext form**: **no `EXT-X-KEY` lines at all** (not even
//!   `METHOD=NONE`) — the archive holds decrypted bytes
//!   (decrypt-as-consume), so the rewritten playlist is semantically
//!   METHOD=NONE for every segment; key material lives only in the
//!   DB (`media_key` discipline);
//! * **init sections**: `EXT-X-MAP` rewritten to the staging file
//!   `init-<label>-<n>.mp4` (the parser name face); the MAP's own
//!   `BYTERANGE` attribute is dropped (the file holds exactly the
//!   init bytes) — a MAP line is (re)emitted whenever the segment's
//!   MAP ordinal changes, including the first segment;
//! * **structural tags preserved**: `EXTM3U`/`VERSION`/
//!   `TARGETDURATION`/`MEDIA-SEQUENCE` (identity anchor)/
//!   `PLAYLIST-TYPE`/`INDEPENDENT-SEGMENTS`/`DISCONTINUITY-SEQUENCE`
//!   at their positions; `EXT-X-DISCONTINUITY` before exactly the
//!   segments that carried it; `ENDLIST` last. Unknown tags are
//!   dropped (the rewrite is a closed form — the unknown-tag
//!   forward-compat face belongs to the *source* parser);
//! * `source.m3u8` is untouched (the download already archived it).
//!
//! # Consumption faces (settled and canonicalized)
//!
//! 1. **native**: the typed [`TrackRewrite`] feeds the transmux
//!    directly (archive + init files + per-segment archive spans) —
//!    the m3u8 text is a product, not a native input;
//! 2. **ffmpeg fallback**: the rewritten `local-<label>.m3u8` **is**
//!    the ffmpeg HLS-demuxer input (`-protocol_whitelist file
//! -allowed_extensions ALL -i local-<label>.m3u8`);
//! 3. **ffprobe dual-run**: probes the synthesized **product** (not
//!    the playlist): duration ∈ ΣEXTINF × [0.98, 1.02] + stream set
//!    = the selected track set (the remux verification face).

use crate::error::MediaError;
use crate::m3u8::model::{MediaPlaylist, init_section_filename};
use crate::trackdl::SegmentRecord;

/// One rewritten segment entry (typed native input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteEntry {
    /// 0-based playlist index.
    pub seg_idx: usize,
    /// Byte offset inside the track archive.
    pub archive_offset: u64,
    /// Plaintext byte length in the archive.
    pub archive_len: u64,
    /// EXTINF duration, ms (the verification Σ basis).
    pub duration_ms: u64,
    /// EXT-X-DISCONTINUITY precedes this segment.
    pub discontinuity: bool,
    /// EXT-X-MAP ordinal in force (`None` = no MAP).
    pub map: Option<usize>,
}

/// One track's rewrite product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackRewrite {
    /// Track label (`v`, `a`, `s0`).
    pub label: String,
    /// Archive file name inside staging (all segments address it).
    pub archive: String,
    /// Init-section staging file names in appearance order.
    pub init_files: Vec<String>,
    /// Per-segment entries in playlist order.
    pub entries: Vec<RewriteEntry>,
    /// Σ EXTINF (ms) — the verification expectation.
    pub total_duration_ms: u64,
    /// The rewritten playlist text (the `local-<label>.m3u8` product).
    pub text: String,
}

/// Build one track's rewrite. `segments` = the ledger rows in
/// playlist order (seg_len already the plaintext semantics — a zero length
/// on a delivered position is refused: the track is incomplete and
/// synthesis may not start).
pub fn rewrite_track(
    playlist: &MediaPlaylist,
    segments: &[SegmentRecord],
    label: &str,
    archive: &str,
) -> Result<TrackRewrite, MediaError> {
    rewrite_track_with_cancel(playlist, segments, label, archive, &|| false)
}

/// The cancel-aware form: the per-segment loop polls
/// `should_cancel` every [`CANCEL_POLL_SEGMENTS`] entries — the rewrite
/// rides a blocking thread and tokio cancellation cannot reach inside
/// it, so the check is explicit (a cancelled task returns
/// [`MediaError::Cancelled`] instead of finishing the remaining
/// segments; the staging product of a cancelled track is never
/// referenced — the caller aborts the whole synthesis face).
pub fn rewrite_track_with_cancel(
    playlist: &MediaPlaylist,
    segments: &[SegmentRecord],
    label: &str,
    archive: &str,
    should_cancel: &dyn Fn() -> bool,
) -> Result<TrackRewrite, MediaError> {
    if playlist.segments.len() != segments.len() {
        return Err(MediaError::Staging(format!(
            "rewrite: playlist carries {} segments but the ledger has {}",
            playlist.segments.len(),
            segments.len()
        )));
    }
    let mut entries = Vec::with_capacity(segments.len());
    let mut offset = 0u64;
    let mut total_duration_ms = 0u64;
    for (idx, (seg, row)) in playlist.segments.iter().zip(segments).enumerate() {
        if idx % CANCEL_POLL_SEGMENTS == 0 && should_cancel() {
            return Err(MediaError::Cancelled);
        }
        if row.seg_idx != idx {
            return Err(MediaError::Staging(format!(
                "rewrite: ledger row {} out of order at {idx}",
                row.seg_idx
            )));
        }
        if row.seg_len == 0 {
            return Err(MediaError::Staging(format!(
                "rewrite: segment {idx} has zero archived bytes (track incomplete)"
            )));
        }
        entries.push(RewriteEntry {
            seg_idx: idx,
            archive_offset: offset,
            archive_len: row.seg_len,
            duration_ms: row.duration_ms,
            discontinuity: seg.discontinuity,
            map: seg.map,
        });
        offset = offset.saturating_add(row.seg_len);
        total_duration_ms = total_duration_ms.saturating_add(row.duration_ms);
    }
    // Init files in appearance order.
    let init_files: Vec<String> = playlist
        .init_sections
        .iter()
        .map(|init| init_section_filename(label, init.index))
        .collect();
    let text = render_text(playlist, &entries, archive, label);
    Ok(TrackRewrite {
        label: label.to_string(),
        archive: archive.to_string(),
        init_files,
        entries,
        total_duration_ms,
        text,
    })
}

/// Cancel-poll cadence inside [`rewrite_track_with_cancel`] (every 64
/// segments — a poll per segment would dwarf the entry-build cost, a
/// poll per track would leave a fully-built playlist unreferenced
/// after cancellation on very long tracks).
const CANCEL_POLL_SEGMENTS: usize = 64;

/// Render the rewritten playlist text (the exact form asserted by the
/// golden tests).
fn render_text(
    playlist: &MediaPlaylist,
    entries: &[RewriteEntry],
    archive: &str,
    label: &str,
) -> String {
    let mut t = String::from("#EXTM3U\n");
    if let Some(v) = playlist.version {
        t.push_str(&format!("#EXT-X-VERSION:{v}\n"));
    }
    if let Some(d) = playlist.target_duration {
        // Rendered as an integer ceiling (the tag's declared semantic).
        t.push_str(&format!("#EXT-X-TARGETDURATION:{}\n", d.ceil() as u64));
    }
    t.push_str(&format!(
        "#EXT-X-MEDIA-SEQUENCE:{}\n",
        playlist.media_sequence
    ));
    if playlist.discontinuity_sequence != 0 {
        t.push_str(&format!(
            "#EXT-X-DISCONTINUITY-SEQUENCE:{}\n",
            playlist.discontinuity_sequence
        ));
    }
    if let Some(kind) = &playlist.playlist_type {
        t.push_str(&format!("#EXT-X-PLAYLIST-TYPE:{kind}\n"));
    }
    if playlist.independent_segments {
        t.push_str("#EXT-X-INDEPENDENT-SEGMENTS\n");
    }
    let mut last_map: Option<usize> = None;
    let mut first = true;
    for e in entries {
        if e.discontinuity && !first {
            t.push_str("#EXT-X-DISCONTINUITY\n");
        }
        if e.map != last_map || first {
            if let Some(m) = e.map {
                t.push_str(&format!(
                    "#EXT-X-MAP:URI=\"{}\"\n",
                    init_section_filename(label, m)
                ));
            }
            last_map = e.map;
        }
        t.push_str(&format!("#EXTINF:{},\n", duration_text(e.duration_ms)));
        t.push_str(&format!(
            "#EXT-X-BYTERANGE:{}@{}\n",
            e.archive_len, e.archive_offset
        ));
        t.push_str(archive);
        t.push('\n');
        first = false;
    }
    t.push_str("#EXT-X-ENDLIST\n");
    t
}

/// EXTINF text for a millisecond duration (3-decimal seconds).
fn duration_text(ms: u64) -> String {
    format!("{}.{:03}", ms / 1000, ms % 1000)
}

/// Staging file name for the rewritten playlist
/// (`local-<label>.m3u8`, the product-spec naming face).
pub fn local_playlist_name(label: &str) -> String {
    format!("local-{label}.m3u8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m3u8::parse_manifest;

    fn media(text: &str) -> MediaPlaylist {
        match parse_manifest(text.as_bytes()).unwrap_or_else(|e| panic!("parse: {e}")) {
            crate::m3u8::Playlist::Media(m) => m,
            other => panic!("expected media, got {other:?}"),
        }
    }

    /// The golden form: encrypted multi-MAP BYTERANGE track rewrites
    /// to a plaintext, archive-addressed, init-referencing playlist.
    #[test]
    fn rewrite_golden_form() {
        let text = "#EXTM3U\n\
            #EXT-X-VERSION:7\n\
            #EXT-X-TARGETDURATION:2\n\
            #EXT-X-MEDIA-SEQUENCE:500\n\
            #EXT-X-KEY:METHOD=AES-128,URI=\"key.php\"\n\
            #EXT-X-MAP:URI=\"init0.mp4\"\n\
            #EXTINF:1.0,\n#EXT-X-BYTERANGE:100@0\nr.m4s\n\
            #EXTINF:1.0,\n#EXT-X-BYTERANGE:96@100\nr.m4s\n\
            #EXT-X-DISCONTINUITY\n\
            #EXT-X-MAP:URI=\"init1.mp4\"\n\
            #EXTINF:1.5,\n#EXT-X-BYTERANGE:120@196\nr.m4s\n\
            #EXT-X-ENDLIST\n";
        let pl = media(text);
        // Ledger rows: decrypted lengths differ from the wire ranges
        // (PKCS7 strips ≥1 byte/16).
        let rows: Vec<SegmentRecord> = pl
            .segments
            .iter()
            .enumerate()
            .map(|(i, s)| SegmentRecord {
                seg_idx: i,
                media_sequence: s.sequence,
                uri: s.uri.clone(),
                byte_range: s.byte_range.map(|b| format!("{}@{}", b.length, b.offset)),
                key_id: Some(1),
                seg_len: 96 - i as u64 * 4,
                duration_ms: (s.duration * 1000.0).round() as u64,
                map: s.map,
                validator_digest: Vec::new(),
            })
            .collect();
        let rw = rewrite_track(&pl, &rows, "v", "archive-v.m4s")
            .unwrap_or_else(|e| panic!("rewrite: {e}"));
        assert_eq!(rw.total_duration_ms, 3500);
        assert_eq!(rw.init_files, vec!["init-v-0.mp4", "init-v-1.mp4"]);
        // Archive spans are cumulative plaintext lengths.
        assert_eq!(rw.entries[0].archive_offset, 0);
        assert_eq!(rw.entries[0].archive_len, 96);
        assert_eq!(rw.entries[1].archive_offset, 96);
        assert_eq!(rw.entries[1].archive_len, 92);
        assert_eq!(rw.entries[2].archive_offset, 188);
        assert!(rw.entries[2].discontinuity);
        assert_eq!(rw.entries[2].map, Some(1));
        // Text form: no KEY lines, local names, BYTERANGE spans.
        assert!(!rw.text.contains("EXT-X-KEY"), "plaintext form");
        assert!(!rw.text.contains("METHOD=NONE"), "no synthetic NONE either");
        assert!(rw.text.contains("#EXT-X-MAP:URI=\"init-v-0.mp4\"\n"));
        assert!(rw.text.contains("#EXT-X-MAP:URI=\"init-v-1.mp4\"\n"));
        assert!(rw.text.contains("#EXT-X-BYTERANGE:96@0\narchive-v.m4s"));
        assert!(rw.text.contains("#EXT-X-BYTERANGE:92@96\narchive-v.m4s"));
        assert!(rw.text.contains("#EXT-X-BYTERANGE:88@188\narchive-v.m4s"));
        assert!(rw.text.contains("#EXT-X-DISCONTINUITY\n"));
        assert!(rw.text.trim_end().ends_with("#EXT-X-ENDLIST"));
        assert!(rw.text.starts_with("#EXTM3U\n#EXT-X-VERSION:7\n"));
        assert!(rw.text.contains("#EXT-X-MEDIA-SEQUENCE:500\n"));
    }

    /// A no-MAP whole-resource (b)-layer track still gets explicit
    /// archive BYTERANGEs; TARGETDURATION ceiling.
    #[test]
    fn rewrite_whole_resource_track() {
        let text = "#EXTM3U\n#EXT-X-TARGETDURATION:1.5\n\
            #EXTINF:1.2,\ns0.ts\n#EXTINF:1.2,\ns1.ts\n#EXT-X-ENDLIST\n";
        let pl = media(text);
        let rows: Vec<SegmentRecord> = pl
            .segments
            .iter()
            .enumerate()
            .map(|(i, s)| SegmentRecord {
                seg_idx: i,
                media_sequence: s.sequence,
                uri: s.uri.clone(),
                byte_range: None,
                key_id: None,
                seg_len: 1024 + i as u64,
                duration_ms: 1200,
                map: None,
                validator_digest: Vec::new(),
            })
            .collect();
        let rw = rewrite_track(&pl, &rows, "a", "archive-a.ts")
            .unwrap_or_else(|e| panic!("rewrite: {e}"));
        assert!(rw.init_files.is_empty());
        assert!(rw.text.contains("#EXT-X-TARGETDURATION:2\n"));
        assert!(rw.text.contains("#EXT-X-BYTERANGE:1024@0\narchive-a.ts"));
        assert!(rw.text.contains("#EXT-X-BYTERANGE:1025@1024\narchive-a.ts"));
        assert!(!rw.text.contains("EXT-X-MAP"));
    }

    /// Incomplete tracks refuse the rewrite (zero-length ledger row).
    #[test]
    fn rewrite_refuses_incomplete() {
        let text = "#EXTM3U\n#EXTINF:1,\na.ts\n#EXTINF:1,\nb.ts\n#EXT-X-ENDLIST\n";
        let pl = media(text);
        let rows: Vec<SegmentRecord> = pl
            .segments
            .iter()
            .enumerate()
            .map(|(i, s)| SegmentRecord {
                seg_idx: i,
                media_sequence: s.sequence,
                uri: s.uri.clone(),
                byte_range: None,
                key_id: None,
                seg_len: if i == 1 { 0 } else { 10 },
                duration_ms: 1000,
                map: None,
                validator_digest: Vec::new(),
            })
            .collect();
        let err = rewrite_track(&pl, &rows, "v", "archive-v.ts")
            .err()
            .unwrap_or_else(|| panic!("must refuse"));
        assert_eq!(err.code(), "taiji.media.staging");
    }

    /// Cancel poll: a cancelled token aborts the loop at the
    /// next 64-segment boundary (never past it), and a live token
    /// produces output identical to the plain form (the poll is
    /// observation-free otherwise).
    #[test]
    fn rewrite_cancel_polls_at_segment_boundaries() {
        // 150 segments (> two poll boundaries, < three).
        let mut text = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:1\n");
        for _ in 0..150 {
            text.push_str("#EXTINF:1.0,\ns.ts\n");
        }
        text.push_str("#EXT-X-ENDLIST\n");
        let pl = media(&text);
        let rows: Vec<SegmentRecord> = (0..150)
            .map(|i| SegmentRecord {
                seg_idx: i,
                media_sequence: i as u64,
                uri: "s.ts".into(),
                byte_range: None,
                key_id: None,
                seg_len: 10,
                duration_ms: 1000,
                map: None,
                validator_digest: Vec::new(),
            })
            .collect();
        // Live token: identical to the plain form.
        let plain = rewrite_track(&pl, &rows, "v", "a.ts").unwrap_or_else(|e| panic!("plain: {e}"));
        let live = rewrite_track_with_cancel(&pl, &rows, "v", "a.ts", &|| false)
            .unwrap_or_else(|e| panic!("live: {e}"));
        assert_eq!(plain, live, "cancel polling does not change the output");
        // Cancelled from the start: Cancelled before any entry work.
        let err = rewrite_track_with_cancel(&pl, &rows, "v", "a.ts", &|| true)
            .err()
            .unwrap_or_else(|| panic!("must cancel"));
        assert_eq!(err.code(), "taiji.media.ffmpeg_cancelled");
        // A token flipping mid-loop (after the first boundary): the
        // same terminal — the poll point, not the flip point, decides.
        let polled = std::cell::Cell::new(0usize);
        let err2 = rewrite_track_with_cancel(&pl, &rows, "v", "a.ts", &|| {
            polled.set(polled.get() + 1);
            polled.get() > 1
        })
        .err()
        .unwrap_or_else(|| panic!("must cancel mid-loop"));
        assert_eq!(err2.code(), "taiji.media.ffmpeg_cancelled");
        // Boundary discipline: exactly ceil polls happened (idx 0, 64,
        // 128 — the flip at the second poll lands mid-rewrite).
        let n = polled.get();
        assert!((2..=3).contains(&n), "poll count {n}");
    }
}

//! `-progress pipe:1` line-protocol parser (the product spec's
//! progress face and fuzz roster).
//!
//! Protocol (one block per ffmpeg flush, key=value lines):
//!
//! ```text
//! frame=31
//! fps=0.00
//! stream_0_0_q=-1.0
//! bitrate= 6.7kbits/s <- '=' may be followed by whitespace
//! total_size=876
//! out_time_us=1044898
//! out_time_ms=1044898 <- same value as out_time_us (upstream
//! quirk kept verbatim, not reconciled)
//! out_time=00:00:01.044898
//! dup_frames=0
//! drop_frames=0
//! speed=2.05x <- may be scientific: 6.49e+03x
//! progress=continue|end <- block terminator
//! ```
//!
//! Hostile-input posture (the fuzz target holds these invariants): the
//! parser never errors and never panics — unknown keys are carried
//! verbatim, unparseable values degrade to `None` on the typed
//! accessors, and invalid UTF-8 is converted lossily per line (UTF-8
//! lossiness tolerated: a mangled byte never kills the progress stream). Snapshots
//! are emitted only on `progress=` terminators (the upstream flush
//! point).

use std::collections::BTreeMap;

/// One complete progress block (fields accumulated since the previous
/// `progress=` terminator).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProgressSnapshot {
    /// frame (u64; `None` = absent/`N/A`).
    pub frame: Option<u64>,
    /// fps (f64).
    pub fps: Option<f64>,
    /// total_size in bytes (u64).
    pub total_size: Option<u64>,
    /// out_time_us (u64; the authoritative machine-readable time).
    pub out_time_us: Option<u64>,
    /// speed multiplier (f64; the trailing `x` stripped).
    pub speed_x: Option<f64>,
    /// dup_frames (u64).
    pub dup_frames: Option<u64>,
    /// drop_frames (u64).
    pub drop_frames: Option<u64>,
    /// bitrate raw string (unit-bearing: `860.2kbits/s`; not typed).
    pub bitrate: Option<String>,
    /// out_time raw string (`HH:MM:SS.ffffff`).
    pub out_time: Option<String>,
    /// Terminating marker: `true` for `progress=end`.
    pub end: bool,
    /// Every key seen in the block (unknown keys included, values
    /// verbatim) — forward compatibility: new upstream fields stay
    /// observable without a parser bump.
    pub fields: BTreeMap<String, String>,
}

/// Watchdog advance key: a snapshot counts as heartbeating iff `frame`
/// or `total_size` moved versus the previous beat (frame
/// or total_size not advancing -> stall).
pub fn snapshot_advances(prev: &ProgressSnapshot, next: &ProgressSnapshot) -> bool {
    prev.frame != next.frame || prev.total_size != next.total_size
}

/// Incremental line-protocol parser: feed stdout chunks, receive
/// completed snapshots.
///
/// Partial lines are buffered across feeds; `\r\n` and `\n` both
/// terminate a line. Any byte sequence is accepted (lossy UTF-8 per
/// line; non-`key=value` lines are ignored).
#[derive(Debug, Default)]
pub struct ProgressParser {
    buffer: Vec<u8>,
    current: ProgressSnapshot,
}

impl ProgressParser {
    /// New parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw stdout bytes; returns snapshots completed by this feed.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<ProgressSnapshot> {
        self.buffer.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.buffer.drain(..=pos).collect();
            line.pop(); // '\n'
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = String::from_utf8_lossy(&line).into_owned();
            if self.apply_line(&line) {
                let done = std::mem::take(&mut self.current);
                out.push(done);
            }
        }
        out
    }

    /// Flush a trailing partial line at stream EOF (an unterminated
    /// `progress=end` still yields its snapshot; anything else is
    /// dropped — upstream always terminates blocks).
    pub fn finish(&mut self) -> Vec<ProgressSnapshot> {
        let mut out = Vec::new();
        if self.buffer.is_empty() {
            return out;
        }
        let line = String::from_utf8_lossy(&self.buffer).into_owned();
        self.buffer.clear();
        if self.apply_line(&line) {
            out.push(std::mem::take(&mut self.current));
        }
        out
    }

    /// Apply one line; `true` = a block terminated on this line.
    fn apply_line(&mut self, line: &str) -> bool {
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            return false;
        }
        self.current
            .fields
            .insert(key.to_string(), value.to_string());
        match key {
            "frame" => self.current.frame = parse_u64(value),
            "fps" => self.current.fps = parse_f64(value),
            "total_size" => self.current.total_size = parse_u64(value),
            "out_time_us" => self.current.out_time_us = parse_u64(value),
            "out_time_ms" => {
                // Upstream writes microseconds into out_time_ms; only
                // fill out_time_us when the authoritative key is absent.
                if self.current.out_time_us.is_none() {
                    self.current.out_time_us = parse_u64(value);
                }
            }
            "speed" => self.current.speed_x = parse_speed(value),
            "dup_frames" => self.current.dup_frames = parse_u64(value),
            "drop_frames" => self.current.drop_frames = parse_u64(value),
            "bitrate" => self.current.bitrate = Some(value.to_string()),
            "out_time" => self.current.out_time = Some(value.to_string()),
            "progress" => {
                self.current.end = value == "end";
                return true;
            }
            _ => {}
        }
        false
    }
}

/// u64 with `N/A`/sign tolerance (negative/absent → None).
fn parse_u64(value: &str) -> Option<u64> {
    value.parse::<u64>().ok()
}

/// f64 with `N/A` tolerance.
fn parse_f64(value: &str) -> Option<f64> {
    value.parse::<f64>().ok()
}

/// `2.05x` / `6.49e+03x` → multiplier.
fn parse_speed(value: &str) -> Option<f64> {
    value.strip_suffix('x').and_then(parse_f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKS: &str = "\
frame=31
fps=0.00
stream_0_0_q=-1.0
bitrate=   6.7kbits/s
total_size=876
out_time_us=1044898
out_time_ms=1044898
out_time=00:00:01.044898
dup_frames=0
drop_frames=0
speed=2.05x
progress=continue
frame=180
total_size=215061
out_time_us=6000000
speed=6.49e+03x
progress=end
";

    #[test]
    fn parses_blocks_with_terminators() {
        let mut p = ProgressParser::new();
        let snaps = p.feed(BLOCKS.as_bytes());
        assert_eq!(snaps.len(), 2);
        assert!(!snaps[0].end);
        assert_eq!(snaps[0].frame, Some(31));
        assert_eq!(snaps[0].total_size, Some(876));
        assert_eq!(snaps[0].out_time_us, Some(1044898));
        assert_eq!(snaps[0].speed_x, Some(2.05));
        assert_eq!(snaps[0].bitrate.as_deref(), Some("6.7kbits/s"));
        assert!(snaps[1].end);
        assert_eq!(snaps[1].frame, Some(180));
        assert_eq!(snaps[1].speed_x, Some(6490.0));
        // Unknown keys ride along verbatim.
        assert_eq!(
            snaps[0].fields.get("stream_0_0_q").map(String::as_str),
            Some("-1.0")
        );
    }

    #[test]
    fn chunks_split_mid_line_and_crlf() {
        let mut p = ProgressParser::new();
        // Partial line buffered across feeds; CRLF terminator.
        assert!(p.feed(b"frame=4").is_empty());
        let snaps = p.feed(b"2\r\nprogress=end\r\n");
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].frame, Some(42));
        assert!(snaps[0].end);
    }

    #[test]
    fn invalid_utf8_is_lossy_and_never_panics() {
        let mut p = ProgressParser::new();
        let snaps = p.feed(b"\xff\xfe=junk\nframe=7\nprogress=end\n");
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].frame, Some(7));
        // Lossy key survives into fields (replacement chars), typed
        // accessors unaffected.
        assert!(snaps[0].fields.contains_key("\u{fffd}\u{fffd}"));
    }

    #[test]
    fn na_and_negative_values_degrade_to_none() {
        let mut p = ProgressParser::new();
        let snaps = p.feed(b"fps=N/A\nframe=-1\nprogress=continue\n");
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].fps, None);
        assert_eq!(snaps[0].frame, None);
    }

    #[test]
    fn finish_flushes_unterminated_end_block() {
        let mut p = ProgressParser::new();
        assert!(p.feed(b"frame=9\nprogress=end").is_empty());
        let snaps = p.finish();
        assert_eq!(snaps.len(), 1);
        assert!(snaps[0].end);
        assert_eq!(snaps[0].frame, Some(9));
    }

    #[test]
    fn advance_predicate_tracks_frame_or_bytes() {
        let a = ProgressSnapshot {
            frame: Some(1),
            total_size: Some(10),
            ..ProgressSnapshot::default()
        };
        let mut b = a.clone();
        assert!(!snapshot_advances(&a, &b));
        b.frame = Some(2);
        assert!(snapshot_advances(&a, &b));
        b.frame = Some(1);
        b.total_size = Some(11);
        assert!(snapshot_advances(&a, &b));
    }
}

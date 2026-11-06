//! `-demuxers` / `-muxers` output parsing and the capability table.
//!
//! Recorded shape (ffmpeg 9, `-hide_banner`; the banner variant is
//! tolerated by skipping to the `---` separator):
//!
//! ```text
//! Formats:
//! D.. = Demuxing supported
//! .E. = Muxing supported
//! ..d = Is a device
//! ---
//! D 3dostr 3DO STR
//! D matroska,webm Matroska / WebM
//! D mov,mp4,m4a,3gp,3g2,mj2 QuickTime / MOV
//! ```
//!
//! Name cells are comma-separated alias lists (one registered
//! demuxer/muxer under several names) — the table expands them so a
//! `webm` lookup hits the `matroska,webm` row.
//!
//! Required sets (per the product spec): demuxers cover the segment formats of
//! the HLS/DASH VOD subset (hls/mpegts/matroska/webm/mp4/mov) plus the
//! concat demuxer (multi-period merge); muxers cover the two remux
//! outputs (`-f mp4` / `-f matroska`).

use std::collections::BTreeSet;

use crate::error::MediaError;

/// Demuxer names the media pipeline depends on (the product spec's demux face).
pub const REQUIRED_DEMUXERS: &[&str] =
    &["concat", "hls", "matroska", "mov", "mp4", "mpegts", "webm"];

/// Muxer names the media pipeline depends on (the product spec's `-f
/// mp4|matroska` outputs).
pub const REQUIRED_MUXERS: &[&str] = &["matroska", "mp4"];

/// One direction of the capability table (alias-expanded name set).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    names: BTreeSet<String>,
}

impl CapabilitySet {
    /// Membership after alias expansion happened at parse time.
    pub fn has(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Sorted name list (doctor renders it verbatim).
    pub fn names(&self) -> Vec<&str> {
        self.names.iter().map(String::as_str).collect()
    }

    fn insert_row(&mut self, name_cell: &str) {
        for alias in name_cell.split(',') {
            let alias = alias.trim();
            if !alias.is_empty() {
                self.names.insert(alias.to_string());
            }
        }
    }

    /// Parse one direction's listing (`-demuxers` or `-muxers` stdout).
    /// Rows after the `---` separator: three flag characters (`D..` /
    /// `.E.` / `..d` legend — demux rows read ` D `, mux rows ` E`),
    /// whitespace, the name cell (comma aliases), optional description.
    /// Lines that do not shape up are skipped (forward compatibility
    /// with new columns), but an output with no `---` separator at all
    /// is a `Parse` error (wrong command output fed in).
    pub fn parse_listing(stdout: &str, direction: Direction) -> Result<Self, MediaError> {
        let mut set = CapabilitySet::default();
        let mut past_separator = false;
        for line in stdout.lines() {
            if !past_separator {
                if line.trim() == "---" {
                    past_separator = true;
                }
                continue;
            }
            let line = line.trim_end();
            if line.len() < 5 {
                continue;
            }
            let (flags, rest) = line.split_at(3);
            if !flags
                .chars()
                .all(|c| c == ' ' || c == 'D' || c == 'E' || c == '.' || c == 'd')
            {
                continue;
            }
            let rest = rest.trim_start();
            let name_cell = rest.split_whitespace().next().unwrap_or_default();
            if name_cell.is_empty() {
                continue;
            }
            set.insert_row(name_cell);
        }
        if !past_separator {
            return Err(MediaError::Parse(format!(
                "no `---` separator in -{} output",
                direction.as_str()
            )));
        }
        Ok(set)
    }
}

/// Parsed `-demuxers` + `-muxers` capability table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capabilities {
    /// Registered demuxer names (alias-expanded).
    pub demuxers: CapabilitySet,
    /// Registered muxer names (alias-expanded).
    pub muxers: CapabilitySet,
}

impl Capabilities {
    /// Parse both listings into the table.
    pub fn parse(demuxer_stdout: &str, muxer_stdout: &str) -> Result<Self, MediaError> {
        Ok(Self {
            demuxers: CapabilitySet::parse_listing(demuxer_stdout, Direction::Demuxers)?,
            muxers: CapabilitySet::parse_listing(muxer_stdout, Direction::Muxers)?,
        })
    }

    /// Missing required names per direction (empty vecs = complete).
    pub fn missing_required(&self) -> (Vec<&'static str>, Vec<&'static str>) {
        let missing_demuxers = REQUIRED_DEMUXERS
            .iter()
            .copied()
            .filter(|n| !self.demuxers.has(n))
            .collect();
        let missing_muxers = REQUIRED_MUXERS
            .iter()
            .copied()
            .filter(|n| !self.muxers.has(n))
            .collect();
        (missing_demuxers, missing_muxers)
    }

    /// True iff no required name is missing.
    pub fn is_complete(&self) -> bool {
        let (d, m) = self.missing_required();
        d.is_empty() && m.is_empty()
    }
}

/// Listing direction (error text + argv).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Demuxers,
    Muxers,
}

impl Direction {
    /// Lowercase name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Demuxers => "demuxers",
            Self::Muxers => "muxers",
        }
    }

    /// argv for the probe (`-hide_banner` keeps the listing stable
    /// across banner-carrying builds; the parser tolerates the banner
    /// anyway).
    pub fn args(&self) -> Vec<String> {
        vec!["-hide_banner".to_string(), format!("-{}", self.as_str())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMUXERS: &str = "\
Formats:
 D.. = Demuxing supported
 .E. = Muxing supported
 ..d = Is a device
 ---
 D   3dostr          3DO STR
 D   concat          Virtual concatenation script
 D   hls             Apple HTTP Live Streaming
 D   matroska,webm   Matroska / WebM
 D   mov,mp4,m4a,3gp,3g2,mj2 QuickTime / MOV
 D   mpegts          MPEG-TS (MPEG-2 Transport Stream)
";

    #[test]
    fn expands_alias_rows() {
        let set = match CapabilitySet::parse_listing(DEMUXERS, Direction::Demuxers) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
        for name in ["hls", "matroska", "webm", "mp4", "mov", "mpegts", "concat"] {
            assert!(set.has(name), "missing {name}");
        }
        assert!(!set.has("m4a_alias_guard")); // absent alias stays absent
    }

    #[test]
    fn rejects_listing_without_separator() {
        match CapabilitySet::parse_listing("noise", Direction::Muxers) {
            Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_parse"),
            Ok(s) => panic!("unexpected success: {:?}", s.names()),
        }
    }

    #[test]
    fn required_check_reports_missing() {
        let caps = match Capabilities::parse(DEMUXERS, "Formats:\n ---\n  E  adts  x\n") {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
        let (d, m) = caps.missing_required();
        assert!(d.is_empty());
        assert_eq!(m, vec!["matroska", "mp4"]);
        assert!(!caps.is_complete());
    }
}

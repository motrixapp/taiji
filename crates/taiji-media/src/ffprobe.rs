//! ffprobe JSON structuring (the product spec's ffprobe-json
//! fuzz roster row).
//!
//! Consumes the output of
//! `ffprobe -v error -print_format json -show_format -show_streams
//! <file>` into typed structures: the stream collection (index /
//! codec_name / codec_type / picture size / audio geometry) and the
//! format block (duration / format_name / nb_streams / size). The
//! remux verification (duration ∈ Σsegments×[0.98,1.02], stream
//! set = selected tracks) is a consumer of these structures — this
//! module delivers the parse + accessors only.
//!
//! Hostile-input posture (fuzz roster): `parse` accepts arbitrary
//! bytes; non-JSON or wrong-shaped input is an explicit `Parse` error,
//! never a panic. All ffprobe fields are optional (codec_name can be
//! absent for data streams, duration for live-ish inputs) — accessors
//! return `Option`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::MediaError;

/// Root document of a `-show_format -show_streams` probe.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FfprobeReport {
    /// Media streams in file order.
    #[serde(default)]
    pub streams: Vec<FfprobeStream>,
    /// Container-level block.
    #[serde(default)]
    pub format: Option<FfprobeFormat>,
}

/// One stream entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FfprobeStream {
    /// Stream index within the file.
    #[serde(default)]
    pub index: u32,
    /// Short codec name (`h264`, `aac`); absent on unidentified/data
    /// streams.
    #[serde(default)]
    pub codec_name: Option<String>,
    /// Long codec name (diagnostics).
    #[serde(default)]
    pub codec_long_name: Option<String>,
    /// `video` / `audio` / `subtitle` / `data` / `attachment`.
    #[serde(default)]
    pub codec_type: Option<String>,
    /// Coded picture width (video only).
    #[serde(default)]
    pub width: Option<u32>,
    /// Coded picture height (video only).
    #[serde(default)]
    pub height: Option<u32>,
    /// Audio sample rate (string-typed upstream).
    #[serde(default)]
    pub sample_rate: Option<String>,
    /// Audio channel count.
    #[serde(default)]
    pub channels: Option<u32>,
    /// Stream duration in seconds (string-typed upstream).
    #[serde(default)]
    pub duration: Option<String>,
}

/// Container format block.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FfprobeFormat {
    /// Probed path as echoed back.
    #[serde(default)]
    pub filename: Option<String>,
    /// Stream count.
    #[serde(default)]
    pub nb_streams: Option<u32>,
    /// Format name list (`mov,mp4,m4a,3gp,3g2,mj2`).
    #[serde(default)]
    pub format_name: Option<String>,
    /// Container duration in seconds (string-typed upstream).
    #[serde(default)]
    pub duration: Option<String>,
    /// File size in bytes (string-typed upstream).
    #[serde(default)]
    pub size: Option<String>,
    /// Aggregate bitrate (string-typed upstream).
    #[serde(default)]
    pub bit_rate: Option<String>,
}

impl FfprobeReport {
    /// Parse a probe document (arbitrary bytes; explicit error on
    /// non-JSON/wrong shape).
    ///
    /// Top-level shape gate: ffprobe emits a JSON
    /// **object**; serde's derived struct deserialization would also
    /// accept the sequence (positional-field) form, which the 25h
    /// soak crashed on (`[[],["xx",6,"","<400+ digits>"]]` parsed OK
    /// and propagated a `+inf` duration). The gate first parses to a
    /// `serde_json::Value` and refuses every non-map top level with
    /// the explicit `taiji.media.ffmpeg_parse` error — the module's
    /// declared hostile-input invariant, now actually enforced.
    pub fn parse(json: &[u8]) -> Result<Self, MediaError> {
        let value = serde_json::from_slice::<serde_json::Value>(json)
            .map_err(|e| MediaError::Parse(format!("ffprobe json: {e}")))?;
        if !value.is_object() {
            let kind = match &value {
                serde_json::Value::Array(_) => "array (sequence form)",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Null => "null",
                _ => "non-map",
            };
            return Err(MediaError::Parse(format!(
                "ffprobe json: top-level {kind} document (an object is required)"
            )));
        }
        serde_json::from_value::<Self>(value)
            .map_err(|e| MediaError::Parse(format!("ffprobe json: {e}")))
    }

    /// Container duration in seconds.
    ///
    /// Finiteness + sign gate (extended by the soak's
    /// second crash shape): `"inf"`/`"NaN"`/overlong-digit strings
    /// parse as non-finite f64 values and a hostile `"-.01…"` parses
    /// as a **negative** one — ffprobe never emits either, so both
    /// are error shapes routed to the accessor's `None` path: a
    /// `Some` duration is always finite and non-negative (the fuzz
    /// invariants), non-physical values are never propagated.
    pub fn duration_seconds(&self) -> Option<f64> {
        self.format
            .as_ref()
            .and_then(|f| f.duration.as_deref())
            .and_then(|d| d.parse::<f64>().ok())
            .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
    }

    /// Stream codec summary (`index:codec_name(codec_type)`) in file
    /// order — the remux verification's "stream set" comparison basis.
    pub fn stream_summary(&self) -> Vec<String> {
        self.streams
            .iter()
            .map(|s| {
                let codec = s.codec_name.as_deref().unwrap_or("unknown");
                let kind = s.codec_type.as_deref().unwrap_or("unknown");
                format!("{}:{codec}({kind})", s.index)
            })
            .collect()
    }

    /// Count of streams of one codec_type.
    pub fn count_codec_type(&self, codec_type: &str) -> usize {
        self.streams
            .iter()
            .filter(|s| s.codec_type.as_deref() == Some(codec_type))
            .count()
    }
}

/// argv for a probe run (the single ffprobe invocation face; `-v error`
/// keeps stderr empty unless genuinely broken, `pipe` stdout is JSON).
pub fn probe_args(path: &Path) -> Vec<std::ffi::OsString> {
    [
        "-v",
        "error",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
    ]
    .into_iter()
    .map(std::ffi::OsString::from)
    .chain([path.as_os_str().to_os_string()])
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_streams_and_format() {
        let json = br#"{
            "streams": [
                {"index": 0, "codec_name": "h264", "codec_type": "video",
                 "width": 320, "height": 240, "duration": "6.000000"},
                {"index": 1, "codec_name": "aac", "codec_type": "audio",
                 "sample_rate": "44100", "channels": 2}
            ],
            "format": {"filename": "out.mkv", "nb_streams": 2,
                       "format_name": "matroska,webm",
                       "duration": "6.014000", "size": "215061"}
        }"#;
        let r = match FfprobeReport::parse(json) {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(r.streams.len(), 2);
        assert_eq!(r.streams[0].codec_name.as_deref(), Some("h264"));
        assert_eq!(r.streams[0].width, Some(320));
        assert_eq!(r.streams[1].channels, Some(2));
        assert_eq!(r.duration_seconds(), Some(6.014));
        assert_eq!(
            r.stream_summary(),
            vec!["0:h264(video)".to_string(), "1:aac(audio)".to_string()]
        );
        assert_eq!(r.count_codec_type("video"), 1);
    }

    #[test]
    fn all_optional_fields_default() {
        // Streams with no codec_name (data streams) and a missing
        // format block must parse (ffprobe emits per-stream optionals).
        let r = match FfprobeReport::parse(br#"{"streams":[{"index":3}]}"#) {
            Ok(r) => r,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(r.streams.len(), 1);
        assert_eq!(r.streams[0].codec_name, None);
        assert_eq!(r.duration_seconds(), None);
        assert_eq!(r.stream_summary(), vec!["3:unknown(unknown)".to_string()]);
    }

    #[test]
    fn rejects_non_json() {
        match FfprobeReport::parse(b"\xff not json") {
            Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_parse"),
            Ok(r) => panic!("unexpected success: {r:?}"),
        }
    }

    /// Regression (the 25h soak's crash pair): serde's
    /// derived struct deserialization accepts the **sequence**
    /// (positional) form, so an array-shaped document parsed OK and
    /// `duration_seconds()` propagated `+inf` (a 400-digit number
    /// overflows f64) — violating the module's own hostile-input
    /// invariant. The top-level shape is now gated (map form only)
    /// and non-finite durations never leave the accessor.
    #[test]
    fn rejects_sequence_form_and_nonfinite_duration() {
        // The exact crash shape from the soak artifacts
        // (the 25h fuzz-run crash pair): top-level array.
        let huge_digits = "9".repeat(400);
        let seq_form = format!(r#"[[],["xx",6,"","{huge_digits}"]]"#);
        match FfprobeReport::parse(seq_form.as_bytes()) {
            Err(e) => assert_eq!(
                e.code(),
                "taiji.media.ffmpeg_parse",
                "sequence form rejected: {e}"
            ),
            Ok(r) => panic!(
                "array-shaped input must be an explicit parse error (the \
                 hostile-input invariant), got {r:?}"
            ),
        }
        // Scalar and null top-levels refuse the same way.
        assert!(FfprobeReport::parse(b"42").is_err());
        assert!(FfprobeReport::parse(b"null").is_err());
        assert!(FfprobeReport::parse(b"\"text\"").is_err());
        // Map form still parses (the happy face is unchanged).
        assert!(FfprobeReport::parse(br#"{"streams":[]}"#).is_ok());
        // Non-finite duration strings never propagate: the accessor's
        // error path is `None` (a present duration is then always a
        // finite f64 — the fuzz invariant 2).
        let mk = |d: &str| {
            FfprobeReport::parse(format!(r#"{{"format":{{"duration":"{d}"}}}}"#).as_bytes())
                .unwrap_or_else(|e| panic!("map form parses: {e}"))
        };
        assert_eq!(mk("inf").duration_seconds(), None);
        assert_eq!(mk("-inf").duration_seconds(), None);
        assert_eq!(mk("NaN").duration_seconds(), None);
        assert_eq!(
            mk(&huge_digits).duration_seconds(),
            None,
            "a 400-digit number overflows f64 to +inf — not propagated"
        );
        // Negative finite values are error shapes too (ffprobe never
        // emits one; the soak's second crash — a hostile
        // \"-.01000\" tripping the fuzz non-negative invariant).
        assert_eq!(mk("-.01000").duration_seconds(), None);
        assert_eq!(mk("-6.0").duration_seconds(), None);
        assert_eq!(mk("6.014000").duration_seconds(), Some(6.014));
        assert_eq!(mk("0").duration_seconds(), Some(0.0));
    }
}

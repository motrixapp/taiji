//! The ffmpeg fallback channel (per the media spec's synthesis line
//! + the product spec's process face, checked against its
//! red-line checklist).
//!
//! **A consumer of the discovery infrastructure, not a second
//! process-governance line**: discovery ([`crate::discover`]), the
//! `-version` license gate and the capability table
//! ([`crate::version`]/[`crate::capability`]), and the whole child
//! orchestration ([`crate::process::MediaCommand`] — argv array,
//! absolute paths, explicit `-f`, piped trio, watchdog, resource limits)
//! are reused verbatim.
//!
//! Trigger conditions (the verdict lives in [`crate::synth`]):
//! native-unsupported forms — TS-source line pre-0.4, MKV output,
//! matrix-degraded items, user-explicit — plus the native channel's
//! own failure (the dual-channel safety net).
//!
//! **`--media-ffmpeg-path=auto` probe failure × degraded item
//! behavior (canonicalized)**: when a form needs this channel (verdict
//! Required) and discovery/assertion fails, the pipeline refuses with
//! `taiji.media.ffmpeg_missing` — before any synthesis work; when the
//! channel is merely the safety net (Optional), its absence degrades
//! to native-only with a warning (the dual-channel net is absent,
//! surfaced in the report). Both faces are exercised in the e2e.
//!
//! argv (the product spec's verbatim shape — built through the
//! [`fallback_args`] pure face and mounted onto [`MediaCommand`], so
//! the explicit `-f` + absolute-output guards stay enforced):
//!
//! ```text
//! ffmpeg -nostdin -y -hide_banner -nostats -loglevel error
//! -progress pipe:1 -protocol_whitelist file
//! -max_alloc <MAX_ALLOC_BYTES> -allowed_extensions ALL
//! -i <local-v.m3u8> [-i <local-a.m3u8>]
//! -map 0:v:0 [-map 1:a:0] -c copy
//! -f mp4|matroska [-movflags +faststart] -max_muxing_queue_size 1024
//! <absolute .part output>
//! ```

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::error::MediaError;
use crate::process::{DEFAULT_STALL_TIMEOUT, MAX_ALLOC_BYTES, MediaBin, MediaChild, MediaCommand};

/// The output container the fallback writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackFormat {
    /// `-f mp4` with `+faststart`.
    Mp4,
    /// `-f matroska` (no faststart).
    Mkv,
}

impl FallbackFormat {
    /// The `-f` argument.
    pub fn as_arg(self) -> &'static str {
        match self {
            Self::Mp4 => "mp4",
            Self::Mkv => "matroska",
        }
    }
}

/// The pre-input flag prefix (the spec's verbatim form).
fn flag_prefix() -> Vec<OsString> {
    let mut argv: Vec<OsString> = [
        "-nostdin",
        "-y",
        "-hide_banner",
        "-nostats",
        "-loglevel",
        "error",
        "-progress",
        "pipe:1",
        "-protocol_whitelist",
        "file",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    // -max_alloc takes the decimal byte count (process.rs's spec-text
    // deviation note: ffmpeg 9 rejects the `512M` spelling).
    argv.push(OsString::from("-max_alloc"));
    argv.push(OsString::from(MAX_ALLOC_BYTES.to_string()));
    argv.push(OsString::from("-allowed_extensions"));
    argv.push(OsString::from("ALL"));
    argv
}

/// Build the fallback argv body (everything except the final output
/// path — the output mounts through [`MediaCommand::output`] so its
/// guards stay in force). Inputs are the rewritten local playlists
/// (the HLS demuxer input face, see [`crate::rewrite`]); the video
/// playlist is input 0, the audio (when present) input 1.
pub fn fallback_args(
    video_playlist: &Path,
    audio_playlist: Option<&Path>,
    fmt: FallbackFormat,
) -> Result<Vec<OsString>, MediaError> {
    if !video_playlist.is_absolute() {
        return Err(MediaError::NotAbsolute(format!(
            "fallback video playlist must be absolute: {}",
            video_playlist.display()
        )));
    }
    if let Some(a) = audio_playlist
        && !a.is_absolute()
    {
        return Err(MediaError::NotAbsolute(format!(
            "fallback audio playlist must be absolute: {}",
            a.display()
        )));
    }
    let mut argv = flag_prefix();
    argv.push(OsString::from("-i"));
    argv.push(video_playlist.as_os_str().to_os_string());
    if let Some(audio) = audio_playlist {
        argv.push(OsString::from("-i"));
        argv.push(audio.as_os_str().to_os_string());
    }
    argv.push(OsString::from("-map"));
    argv.push(OsString::from("0:v:0"));
    if audio_playlist.is_some() {
        argv.push(OsString::from("-map"));
        argv.push(OsString::from("1:a:0"));
    }
    argv.push(OsString::from("-c"));
    argv.push(OsString::from("copy"));
    // The explicit -f: MediaCommand::format records it and unlocks
    // the output face.
    argv.push(OsString::from("-f"));
    argv.push(OsString::from(fmt.as_arg()));
    if fmt == FallbackFormat::Mp4 {
        argv.push(OsString::from("-movflags"));
        argv.push(OsString::from("+faststart"));
    }
    argv.push(OsString::from("-max_muxing_queue_size"));
    argv.push(OsString::from("1024"));
    Ok(argv)
}

/// A resolved, asserted ffmpeg pair for fallback runs (the product
/// spec's discovery + assertion face).
#[derive(Debug, Clone)]
pub struct FfmpegRuntime {
    /// Discovered pair.
    pub pair: crate::discover::FfmpegPair,
    /// Parsed `-version` info.
    pub version: crate::version::VersionInfo,
    /// Exec-shim host override (test seam; production leaves
    /// `current_exe`).
    pub shim_program: Option<PathBuf>,
}

impl FfmpegRuntime {
    /// Discover + assert the pair: `-version` parse, the LGPL
    /// configuration gate (gpl/nonfree both zero), version-token agreement
    /// between the two binaries (the same-origin pairing contract), and the
    /// demuxer/muxer capability set covering the fallback face.
    pub async fn discover_asserted(
        request: &crate::discover::DiscoveryRequest,
        shim_program: Option<PathBuf>,
    ) -> Result<Self, MediaError> {
        let pair = crate::discover::discover(request)?;
        // Version + license gate.
        let version_out = run_capture(
            &pair.ffmpeg,
            crate::version::VersionInfo::version_args(),
            shim_program.as_deref(),
        )
        .await?;
        let info = crate::version::VersionInfo::parse(&String::from_utf8_lossy(&version_out))?;
        let audit = crate::version::LicenseAudit::audit(&info.configuration);
        if !audit.is_clean() {
            return Err(MediaError::LicenseGate(format!(
                "ffmpeg configuration carries {:?}",
                audit.offending_flags()
            )));
        }
        // ffprobe side must agree on the version token.
        let probe_out = run_capture(
            &pair.ffprobe,
            crate::version::VersionInfo::version_args(),
            shim_program.as_deref(),
        )
        .await?;
        let probe_info = crate::version::VersionInfo::parse(&String::from_utf8_lossy(&probe_out))?;
        if !crate::version::versions_agree(&info, &probe_info) {
            return Err(MediaError::OriginMismatch(format!(
                "ffmpeg/ffprobe version tokens disagree: {} vs {}",
                info.version, probe_info.version
            )));
        }
        // Capability table: hls demuxer + mp4/matroska muxers.
        let demux_args = crate::capability::Direction::Demuxers.args();
        let demux_refs: Vec<&str> = demux_args.iter().map(String::as_str).collect();
        let demuxers = run_capture(&pair.ffmpeg, &demux_refs, shim_program.as_deref()).await?;
        let mux_args = crate::capability::Direction::Muxers.args();
        let mux_refs: Vec<&str> = mux_args.iter().map(String::as_str).collect();
        let muxers = run_capture(&pair.ffmpeg, &mux_refs, shim_program.as_deref()).await?;
        let caps = crate::capability::Capabilities::parse(
            &String::from_utf8_lossy(&demuxers),
            &String::from_utf8_lossy(&muxers),
        )?;
        if !caps.demuxers.has("hls") {
            return Err(MediaError::Missing(
                "ffmpeg build lacks the hls demuxer".to_string(),
            ));
        }
        if !caps.muxers.has("mp4") || !caps.muxers.has("matroska") {
            return Err(MediaError::Missing(
                "ffmpeg build lacks the mp4/matroska muxers".to_string(),
            ));
        }
        Ok(Self {
            pair,
            version: info,
            shim_program,
        })
    }

    /// Run one fallback remux (progress-watched, cancellable). The
    /// caller owns the `.part` output lifecycle. argv order: the spec's
    /// flags → inputs → maps → `-c copy` → explicit `-f` (+faststart
    /// for mp4) → queue size → the guarded output face.
    pub async fn run_remux(
        &self,
        video_playlist: &Path,
        audio_playlist: Option<&Path>,
        output: &Path,
        fmt: FallbackFormat,
        stall_timeout: Option<Duration>,
        token: CancellationToken,
    ) -> Result<MediaChild, MediaError> {
        let args = fallback_args(video_playlist, audio_playlist, fmt)?;
        let mut cmd = MediaCommand::new(MediaBin::Ffmpeg, &self.pair.ffmpeg)?;
        cmd = cmd.args(args);
        // Explicit format + guarded absolute output (MediaCommand's
        // own contract face).
        cmd = cmd.format(fmt.as_arg());
        cmd = cmd.output(output)?;
        cmd = cmd
            .shim_program(self.shim_program.clone())
            .stdout_progress(stall_timeout.or(Some(DEFAULT_STALL_TIMEOUT)))
            .cancellation(token);
        cmd.spawn()
    }
}

/// Run a capture-mode child (`-version`/`-demuxers`/`-muxers`) to
/// completion, returning stdout.
async fn run_capture(
    program: &Path,
    args: &[&str],
    shim_program: Option<&Path>,
) -> Result<Vec<u8>, MediaError> {
    let cmd = MediaCommand::new(MediaBin::Ffmpeg, program)?
        .args(args.iter().copied())
        .shim_program(shim_program.map(PathBuf::from));
    let child = cmd.spawn()?;
    let output = child.wait().await?;
    if !output.success {
        let excerpt = {
            let stderr = &output.stderr;
            let start = stderr.len().saturating_sub(512);
            String::from_utf8_lossy(&stderr[start..]).into_owned()
        };
        return Err(MediaError::Exit(format!(
            "probe exit {:?}: {excerpt}",
            output.code
        )));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The argv shape: the spec's flags verbatim, single video input,
    /// video+audio mapping, explicit `-f`, faststart only for mp4.
    #[test]
    fn argv_shapes() {
        let video = PathBuf::from("/tmp/x/.taiji-b/g/local-v.m3u8");
        let out = PathBuf::from("/tmp/x/out.mp4.part");
        let _ = out;
        let args =
            fallback_args(&video, None, FallbackFormat::Mp4).unwrap_or_else(|e| panic!("{e}"));
        let j: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(j[0], "-nostdin");
        for needle in [
            "-nostats",
            "-loglevel",
            "-progress",
            "-protocol_whitelist",
            "file",
            "-max_alloc",
            "-allowed_extensions",
            "ALL",
            "-movflags",
            "+faststart",
            "-map",
            "0:v:0",
            "-max_muxing_queue_size",
        ] {
            assert!(j.contains(&needle.to_string()), "missing {needle}: {j:?}");
        }
        assert!(
            !j.contains(&"1:a:0".to_string()),
            "no audio input → no audio map"
        );
        assert!(
            !j.iter().any(|a| a.ends_with(".part")),
            "output not in the body args"
        );

        let audio = PathBuf::from("/tmp/x/.taiji-b/g/local-a.m3u8");
        let args = fallback_args(&video, Some(&audio), FallbackFormat::Mkv)
            .unwrap_or_else(|e| panic!("{e}"));
        let j: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(j.contains(&"1:a:0".to_string()));
        assert!(j.iter().any(|a| a.ends_with("local-a.m3u8")));
        assert!(!j.contains(&"+faststart".to_string()), "mkv: no faststart");
        let fmt_pos = j
            .iter()
            .position(|a| a == "-f")
            .unwrap_or_else(|| panic!("-f present in {j:?}"));
        assert_eq!(j[fmt_pos + 1], "matroska");
        // Relative paths refused.
        assert!(fallback_args(Path::new("local-v.m3u8"), None, FallbackFormat::Mp4).is_err());
        assert!(fallback_args(&video, Some(Path::new("a.m3u8")), FallbackFormat::Mp4).is_err());
    }
}

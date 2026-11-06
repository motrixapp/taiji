//! The synthesis pipeline — Processing → Verifying (the media spec's
//! task phases and synthesis line). The programmatic face the session
//! orchestration will mount; the e2e drives it directly (the download
//! line's precedent).
//!
//! Flow (one idempotent run; the amended interruption semantics —
//! the native channel is in-process computation, so an interrupted
//! run simply re-runs over the same staging):
//!
//! ```text
//! rewrite manifests (per track, staging local-<label>.m3u8)
//! → prechecks (disk ①, sidecar start ③)
//! → Processing: channel choice → run → (on failure) the other
//! channel → both failed = task Error (staging retained) ②
//! → Verifying: native probe box assertions + ffprobe dual-run (when
//! the fallback face is present) → failure = remux_verify_failed
//! → VTT sidecar (every failure = degraded completion + warning, the
//! sidecar grading — computed **before** the rename so no sidecar
//! state can contradict a delivered product)
//! → product: <out>.part → atomic rename
//! ```
//!
//! **Channel choice** ([`choose_channel`]): the user preference
//! (`--media-muxer`, `native|ffmpeg|auto` — the user-explicit trigger
//! face) crossed with the native support verdict ([`native_support`])
//! and the fallback presence:
//!
//! * native unsupported (TS source pre-0.4, MKV output, multi-MAP
//! codec change, non-fMP4 init, multi-trak init) → fallback
//! Required;
//! * fallback absent + required → `taiji.media.ffmpeg_missing` (start
//! precheck ③ — before any of this runs the task activation chain
//! applies the same verdict to avoid downloading a whole track for
//! nothing);
//! * native primary, fallback = safety net when present.
//!
//! **Both-channels terminal state** (②): the compound error embeds
//! **both** channel failure texts under the `taiji.media.staging`
//! annotation face (the no-more-precise-inherited-code local face; a
//! dedicated `synthesis_failed` code is a candidate for a future
//! error-code annotation — new error codes stay out of this module);
//! staging and the staged
//! archives are **retained** (the pipeline never deletes staging on
//! failure; the failed `.part` is removed so a re-run starts clean).
//!
//! **Phases**: the report records the phase transitions ([`Phase`])
//! for the session's `phaseChanged` face (extension events — not
//! emitted here).

use std::path::{Path, PathBuf};

use tokio_util::sync::CancellationToken;

use crate::bmff;
use crate::error::MediaError;
use crate::ffmpegmux::{FallbackFormat, FfmpegRuntime};
use crate::mp4write::{self, MovieMeta, TrackSpec};
use crate::precheck::{self, DiskVerdict, FallbackNeed};
use crate::probe::{self, ExpectedMeta, ExpectedTrack};
use crate::rewrite::TrackRewrite;
use crate::vtt;

/// Output container choice (`--media-output-format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// MP4 family (the 0.3 native face).
    #[default]
    Mp4,
    /// MKV — fallback channel only (native never writes it).
    Mkv,
}

/// Muxer preference (`--media-muxer=native|ffmpeg|auto`): `auto` =
/// native primary with the fallback net; `ffmpeg` = the user-explicit
/// trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MuxerPreference {
    /// Native first, fallback as the safety net.
    #[default]
    Auto,
    /// Native only (the fallback never runs).
    Native,
    /// User-explicit ffmpeg (the native channel never runs).
    Ffmpeg,
}

/// One track's synthesis input (all paths inside the task's staging
/// tree).
#[derive(Debug, Clone)]
pub struct TrackInput {
    /// Track label (`v`, `a`, `s0`).
    pub label: String,
    /// video|audio|subtitle (the media_track.kind domain).
    pub kind: String,
    /// Staging archive path (absolute).
    pub archive: PathBuf,
    /// Staging init-section paths in appearance order (absolute).
    pub inits: Vec<PathBuf>,
    /// Ledger rows in playlist order (plaintext seg_len).
    pub segments: Vec<crate::trackdl::SegmentRecord>,
    /// The parsed playlist (structural bookkeeping).
    pub playlist: crate::m3u8::MediaPlaylist,
    /// Archive file name (staging-relative).
    pub archive_name: String,
}

/// Pipeline configuration.
#[derive(Clone)]
pub struct SynthesisConfig {
    /// Phase-transition observer (the session's phaseChanged wiring): the
    /// Processing/Verifying/Done transitions invoke this sink when
    /// present (the session publishes the extension event; `None` =
    /// no observer — the legacy direct-call shape).
    pub phase_sink: Option<std::sync::Arc<dyn Fn(Phase) + Send + Sync>>,
    /// Output format.
    pub format: OutputFormat,
    /// Muxer preference.
    pub muxer: MuxerPreference,
    /// Final product path (absolute).
    pub output: PathBuf,
    /// The task's staging directory (rewrite products land here).
    pub staging_dir: PathBuf,
    /// Asserted ffmpeg runtime (None = fallback absent).
    pub ffmpeg: Option<FfmpegRuntime>,
    /// Subtitle embed face (matrix product face OFF by default —
    /// tx3g embedding is the kickoff-gate capability, not a 0.3 product
    /// wiring).
    pub embed_subtitles: bool,
    /// Metadata attach face (the product wiring): the
    /// native channel writes ©nam/covr from this; `--no-meta` passes
    /// the empty default. The ffmpeg fallback channel does not
    /// attach metadata in 0.3 (its own `-metadata` argv face is a
    /// later addition) — the config still rides so the expectation
    /// face knows what was *asked for*.
    pub meta: MovieMeta,
    /// Explicit free-bytes override (tests); None = the real volume
    /// face (unix) / optimistic elsewhere.
    pub free_bytes_override: Option<Option<u64>>,
}

impl SynthesisConfig {
    /// The `.part` staging output (verified success renames).
    pub fn part_path(&self) -> PathBuf {
        let mut name = self
            .output
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| self.output.as_os_str().to_os_string());
        name.push(".part");
        let mut p = self.output.clone();
        p.set_file_name(name);
        p
    }
}

/// Phase transitions (the session's `phaseChanged` payload basis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Rewrite + prechecks + synthesis started.
    Processing { channel: &'static str },
    /// Product verification started.
    Verifying,
    /// Done (product renamed into place).
    Done,
}

/// One pipeline run's report.
#[derive(Debug, Clone)]
pub struct SynthesisReport {
    pub phases: Vec<Phase>,
    /// The final product path.
    pub product: PathBuf,
    /// The VTT sidecar outcome (`Ok(path)` = written; `Err(text)` =
    /// degraded with warning; `None` = no subtitle track).
    pub sidecar: Option<Result<PathBuf, String>>,
    /// Degradation warnings (sidecar splice failure, native-only
    /// fallback absence…): the session's warning-event payloads.
    pub warnings: Vec<String>,
    /// Per-track rewrite products.
    pub rewrites: Vec<TrackRewrite>,
    /// Which channel produced the file.
    pub channel_used: &'static str,
}

/// Native-support verdict (the native-carrier gate's runtime face).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeSupport {
    /// Native synthesis applies.
    Supported,
    /// Not applicable — the reason routes to the fallback channel.
    Unsupported { reason: String },
}

/// The native-support decision function (pure): MP4 output, every
/// content track fMP4 (init sections present), one stsd shape per
/// selected track across MAPs (a mid-stream codec change cannot live
/// in one progressive stsd), and no user-explicit ffmpeg. Multi-trak
/// inits are accepted (the muxed A/V form): the
/// verdict selects each init's trak by track kind and judges the
/// selected trak's stsd.
pub fn native_support(inputs: &[TrackInput], cfg: &SynthesisConfig) -> NativeSupport {
    if cfg.muxer == MuxerPreference::Ffmpeg {
        return NativeSupport::Unsupported {
            reason: "user-explicit ffmpeg muxer".to_string(),
        };
    }
    if cfg.format == OutputFormat::Mkv {
        return NativeSupport::Unsupported {
            reason: "MKV output is fallback-channel territory".to_string(),
        };
    }
    for track in inputs {
        if track.kind == "subtitle" {
            continue;
        }
        if track.inits.is_empty() {
            return NativeSupport::Unsupported {
                reason: format!(
                    "track {} has no init section (TS/raw line — native fMP4 face only)",
                    track.label
                ),
            };
        }
        for init in &track.inits {
            match std::fs::read(init) {
                Ok(bytes) => match bmff::parse_init_tracks(&bytes) {
                    Ok(tracks) => {
                        let Some(desc) = bmff::select_init_track(&tracks, &track.kind) else {
                            return NativeSupport::Unsupported {
                                reason: format!(
                                    "track {} init carries no selectable trak",
                                    track.label
                                ),
                            };
                        };
                        if desc.stsd_entries.len() != 1 {
                            return NativeSupport::Unsupported {
                                reason: format!(
                                    "track {} init carries {} stsd entries",
                                    track.label,
                                    desc.stsd_entries.len()
                                ),
                            };
                        }
                    }
                    Err(e) => {
                        return NativeSupport::Unsupported {
                            reason: format!("track {} init parse: {e}", track.label),
                        };
                    }
                },
                Err(e) => {
                    return NativeSupport::Unsupported {
                        reason: format!("track {} init read {}: {e}", track.label, init.display()),
                    };
                }
            }
        }
        // One stsd shape across MAPs: the SELECTED trak's entry bytes
        // must agree pairwise (the per-kind selection keeps muxed inits on
        // the same rule).
        if track.inits.len() > 1 {
            let mut shapes: Vec<Vec<u8>> = Vec::new();
            for init in &track.inits {
                if let Ok(bytes) = std::fs::read(init)
                    && let Ok(tracks) = bmff::parse_init_tracks(&bytes)
                    && let Some(desc) = bmff::select_init_track(&tracks, &track.kind)
                    && let Some(first) = desc.stsd_entries.first()
                {
                    shapes.push(first.bytes.clone());
                }
            }
            let all_equal = shapes.windows(2).all(|w| w[0] == w[1]);
            if !all_equal {
                return NativeSupport::Unsupported {
                    reason: format!(
                        "track {} changes codec across MAPs (multi-stsd progressive \
                         output unsupported natively)",
                        track.label
                    ),
                };
            }
        }
    }
    NativeSupport::Supported
}

/// The fallback-need decision for the **start precheck** (③): same
/// inputs as [`native_support`] — a Required form with no runtime
/// pair is `ffmpeg_missing` before any traffic; Optional without a
/// pair proceeds native-only with the warning.
pub fn fallback_need(inputs: &[TrackInput], cfg: &SynthesisConfig) -> FallbackNeed {
    match native_support(inputs, cfg) {
        NativeSupport::Unsupported { reason } => FallbackNeed::Required { reason },
        NativeSupport::Supported => {
            if cfg.muxer == MuxerPreference::Native {
                // Native-only preference: the net is explicitly off.
                FallbackNeed::None
            } else {
                FallbackNeed::Optional
            }
        }
    }
}

/// Which channel runs first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Native,
    Ffmpeg,
}

impl Channel {
    fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Ffmpeg => "ffmpeg",
        }
    }
}

/// Channel choice (pure).
pub fn choose_channel(
    support: &NativeSupport,
    preference: MuxerPreference,
    ffmpeg_present: bool,
) -> Result<Channel, MediaError> {
    match support {
        NativeSupport::Unsupported { reason } => {
            if ffmpeg_present {
                Ok(Channel::Ffmpeg)
            } else {
                Err(MediaError::Missing(format!(
                    "form requires the ffmpeg channel ({reason}) but no pair is available"
                )))
            }
        }
        NativeSupport::Supported => match preference {
            MuxerPreference::Ffmpeg if ffmpeg_present => Ok(Channel::Ffmpeg),
            MuxerPreference::Ffmpeg => Err(MediaError::Missing(
                "user-explicit ffmpeg muxer but no pair is available".to_string(),
            )),
            _ => Ok(Channel::Native),
        },
    }
}

/// Per-track rewrites on blocking threads: one
/// `spawn_blocking` per track, joined under cancellation — a cancel
/// (pause/remove/shutdown) aborts the set and surfaces
/// [`MediaError::Cancelled`]; each task also polls the token inside
/// the rewrite loop (every 64 segments, see
/// [`crate::rewrite::rewrite_track_with_cancel`]) so a long track
/// stops mid-rewrite instead of running to completion unreferenced.
/// Results land in indexed slots — `rewrites` stays 1:1 with `inputs`
/// (playlist order; the join order is nondeterministic, the merge
/// phase's order is not).
///
/// rayon deferral note (2026-11-05 deep-analysis revision): a rayon
/// pool was rejected for this face — a new dependency (+~1.5MB,
/// countering the binary-size slimming) with no async-cancel story for a
/// lane whose typical track count is 1-2; revisit only when track
/// counts reach ≥5 (the post yt-dlp-bridge multi-format shape) AND
/// measured Processing walls exceed ~5s.
async fn run_rewrites_parallel(
    inputs: &[TrackInput],
    cfg: &SynthesisConfig,
    cancel: &CancellationToken,
) -> Result<Vec<TrackRewrite>, MediaError> {
    let mut set: tokio::task::JoinSet<Result<(usize, TrackRewrite), MediaError>> =
        tokio::task::JoinSet::new();
    for (i, track) in inputs.iter().enumerate() {
        // Owned clones per task (the borrow cannot cross the blocking
        // boundary); playlist/segments are the rewrite inputs, the
        // staging path is the write target.
        let playlist = track.playlist.clone();
        let segments = track.segments.clone();
        let label = track.label.clone();
        let archive = track.archive_name.clone();
        let staging_path = cfg
            .staging_dir
            .join(crate::rewrite::local_playlist_name(&track.label));
        let cancel = cancel.clone();
        set.spawn_blocking(move || {
            if cancel.is_cancelled() {
                return Err(MediaError::Cancelled);
            }
            let t0 = std::time::Instant::now();
            let rw = crate::rewrite::rewrite_track_with_cancel(
                &playlist,
                &segments,
                &label,
                &archive,
                &|| cancel.is_cancelled(),
            )?;
            crate::staging::write_file(&staging_path, rw.text.as_bytes())?;
            tracing::info!(
                target: "taiji::media::synth",
                track = %label,
                segments = segments.len(),
                wall_ms = t0.elapsed().as_millis() as u64,
                "processing: track rewrite done"
            );
            Ok((i, rw))
        });
    }
    let mut slots: Vec<Option<TrackRewrite>> = (0..inputs.len()).map(|_| None).collect();
    while let Some(joined) = tokio::select! {
        j = set.join_next() => j,
        _ = cancel.cancelled() => {
            set.abort_all();
            return Err(MediaError::Cancelled);
        }
    } {
        let (i, rw) = joined
            .map_err(|e| MediaError::Staging(format!("rewrite join: {e}")))
            .and_then(|inner| inner)?;
        slots[i] = Some(rw);
    }
    slots
        .into_iter()
        .map(|s| s.ok_or_else(|| MediaError::Staging("rewrite slot unfilled".into())))
        .collect()
}

/// Run the pipeline.
///
/// `Err` = the task's terminal Error face (precheck refusal, both
/// channels failed, verification failed). Staging is never removed on
/// `Err` (②); the `.part` is.
pub async fn run_synthesis(
    inputs: &[TrackInput],
    cfg: &SynthesisConfig,
    cancel: CancellationToken,
) -> Result<SynthesisReport, MediaError> {
    let mut phases = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // 1. Per-track rewrites (staging products; subtitle tracks get a
    // VTT splice later, but their playlist rewrite is produced
    // too — one closed form). One blocking thread per
    // track (`JoinSet::spawn_blocking`) — the former serial loop
    // ran the CPU-bound rewrite on the async worker, blocking the
    // runtime for the sum of all tracks; the tracks are
    // independent, so they rewrite in parallel and the runtime
    // stays free (the merge phase's ordering is preserved by
    // indexed slot collection — `rewrites` stays 1:1 with
    // `inputs`, playlist order).
    let rewrite_t0 = std::time::Instant::now();
    let rewrites = run_rewrites_parallel(inputs, cfg, &cancel).await?;
    tracing::info!(
        target: "taiji::media::synth",
        tracks = inputs.len(),
        wall_ms = rewrite_t0.elapsed().as_millis() as u64,
        "processing: per-track rewrites done"
    );

    // 2. Precheck ③ (start): required-form fallback absence refuses
    // before any synthesis work (the download-side application is
    // session's activation chain; here it guards Processing entry).
    let need = fallback_need(inputs, cfg);
    let pair_present = cfg.ffmpeg.is_some();
    match precheck::sidecar_start_precheck(&need, pair_present) {
        precheck::StartVerdict::Proceed => {}
        precheck::StartVerdict::FfmpegMissing(e) => return Err(e),
        precheck::StartVerdict::NativeOnlyWarning(w) => warnings.push(w),
    }

    // 3. Precheck ① (disk): peak = 2× product estimate + margin.
    let product_estimate: u64 = inputs
        .iter()
        .filter(|t| t.kind != "subtitle")
        .map(|t| std::fs::metadata(&t.archive).map(|m| m.len()).unwrap_or(0))
        .sum();
    let free = match cfg.free_bytes_override {
        Some(explicit) => explicit,
        None => precheck::volume_free_bytes(&cfg.staging_dir),
    };
    match precheck::disk_precheck(free, product_estimate) {
        DiskVerdict::Pass | DiskVerdict::UnknownOptimistic => {}
        DiskVerdict::Insufficient { need, free } => {
            return Err(MediaError::Staging(format!(
                "synthesis disk precheck: need {need} bytes (2×{product_estimate} + margin), \
                 free {free} — refusing to enter Processing"
            )));
        }
    }

    // 4. Processing: channel choice → run → fallback net.
    let support = native_support(inputs, cfg);
    let primary = choose_channel(&support, cfg.muxer, cfg.ffmpeg.is_some())?;
    let phase_note = |phase: Phase| {
        if let Some(sink) = &cfg.phase_sink {
            sink(phase);
        }
    };
    let processing_phase = Phase::Processing {
        channel: primary.name(),
    };
    phase_note(processing_phase.clone());
    phases.push(processing_phase);
    let part = cfg.part_path();
    let fmt = match cfg.format {
        OutputFormat::Mp4 => FallbackFormat::Mp4,
        OutputFormat::Mkv => FallbackFormat::Mkv,
    };
    let content: Vec<&TrackInput> = inputs.iter().collect();
    let content: &[&TrackInput] = &content;
    let mut native_error: Option<MediaError> = None;
    let mut ffmpeg_error: Option<MediaError> = None;
    let mut channel_used = primary.name();

    let produced = match primary {
        Channel::Native => {
            match run_native(content, cfg, &part, &rewrites, cancel.clone()).await {
                Ok(()) => true,
                // A cancellation (pause/remove/shutdown) is not a
                // channel failure — no fallback net, no both-channels
                // terminal; the caller's cancel face owns the teardown
                // (the task-phase memory rides it).
                Err(e) if matches!(e, MediaError::Cancelled) => {
                    let _ = std::fs::remove_file(&part);
                    return Err(e);
                }
                Err(e) => {
                    native_error = Some(e);
                    // Dual-channel net: the fallback runs when present
                    // and the form is not native-only.
                    match &cfg.ffmpeg {
                        Some(rt) if cfg.muxer != MuxerPreference::Native => {
                            channel_used = "ffmpeg";
                            match run_fallback(rt, content, cfg, &part, fmt, cancel.clone()).await {
                                Ok(()) => true,
                                Err(e2) => {
                                    ffmpeg_error = Some(e2);
                                    false
                                }
                            }
                        }
                        _ => false,
                    }
                }
            }
        }
        Channel::Ffmpeg => {
            let Some(rt) = &cfg.ffmpeg else {
                // choose_channel already gated this; unreachable
                // defense.
                return Err(MediaError::Missing(
                    "ffmpeg channel chosen without a runtime".to_string(),
                ));
            };
            match run_fallback(rt, content, cfg, &part, fmt, cancel.clone()).await {
                Ok(()) => true,
                Err(e) if matches!(e, MediaError::Cancelled) => {
                    let _ = std::fs::remove_file(&part);
                    return Err(e);
                }
                Err(e) => {
                    ffmpeg_error = Some(e);
                    // The net in the other direction: native runs only
                    // when the form actually supports it.
                    if support == NativeSupport::Supported {
                        channel_used = "native";
                        match run_native(content, cfg, &part, &rewrites, cancel.clone()).await {
                            Ok(()) => true,
                            Err(e2) => {
                                native_error = Some(e2);
                                false
                            }
                        }
                    } else {
                        false
                    }
                }
            }
        }
    };

    if !produced {
        // ② Both channels failed (or the single available one did):
        // task Error, staging retained, `.part` cleaned for the
        // idempotent re-run. The compound state carries **both**
        // channel failure texts; the error code is the `staging`
        // annotation face (the no-more-precise-inherited-code local
        // face — a dedicated `synthesis_failed` code is a candidate
        // for a future error-code annotation, not this
        // module's).
        let _ = std::fs::remove_file(&part);
        let native_text = native_error
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "not attempted".to_string());
        let ffmpeg_text = ffmpeg_error
            .as_ref()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "not attempted".to_string());
        return Err(MediaError::Staging(format!(
            "both synthesis channels failed — native: {native_text}; ffmpeg: {ffmpeg_text} \
             (staging retained; re-run Processing to retry)"
        )));
    }

    // 5. Verifying: native probe always; ffprobe dual-run when the
    // fallback face is present.
    phase_note(Phase::Verifying);
    phases.push(Phase::Verifying);
    let product_bytes = std::fs::read(&part)
        .map_err(|e| MediaError::Staging(format!("read product {}: {e}", part.display())))?;
    let expectation = build_expectation(content, &rewrites)?;
    let expected_ms: u64 = content
        .iter()
        .filter(|t| t.kind != "subtitle")
        .map(|t| {
            t.segments
                .iter()
                .map(|s| s.duration_ms)
                .fold(0u64, |a, b| a.saturating_add(b))
        })
        .max()
        .unwrap_or(0);
    // Metadata embed verification: the native product must carry the
    // attached faces (©nam/covr byte-equality); an ffmpeg-channel
    // product is remuxed under ffmpeg's own authorship and carries
    // none of our items (structural mode below already relaxes the
    // passthrough proofs for it).
    let meta = if channel_used == "native" {
        ExpectedMeta {
            title: cfg.meta.title.clone(),
            covr: cfg.meta.covr.clone(),
            chapters: cfg
                .meta
                .chapters
                .iter()
                .map(|c| (c.start, c.title.clone()))
                .collect(),
        }
    } else {
        ExpectedMeta::default()
    };
    let mode = if channel_used == "native" {
        probe::ProbeMode::Native
    } else {
        // Fallback products: ffmpeg rebuilds stsd/stbl in its own
        // shape — the structural invariant set (the passthrough
        // proofs are native-only by definition).
        probe::ProbeMode::Structural
    };
    let report = probe::probe_product_mode(&product_bytes, &expectation, expected_ms, &meta, mode);
    if !report.ok() {
        let _ = std::fs::remove_file(&part);
        return Err(MediaError::RemuxVerifyFailed(format!(
            "native probe violations: {:?}",
            report.violations
        )));
    }
    // ffprobe dual-run (the fallback face present): duration within
    // ±2 % and the stream count = the content track count.
    if let Some(rt) = &cfg.ffmpeg {
        dual_run_probe(rt, &part, content, expected_ms).await?;
    }

    // 6. VTT sidecar (subtitle tracks) — **before** the product
    // rename: every sidecar failure degrades (an explicitly
    // attached side track = degraded completion + warning, never
    // the both-channels state), so a "renamed product + task
    // Error" state cannot arise. Subtitle archive bytes are wholly
    // source-controlled (the download stores them verbatim, zero
    // download-time validation): a non-UTF-8 body, a span outside
    // the archive (truncated staging), an unparseable segment or a
    // sidecar write failure all degrade.
    let mut sidecar = None;
    for (track, rw) in inputs.iter().zip(&rewrites) {
        if track.kind != "subtitle" {
            continue;
        }
        let archive = match std::fs::read(&track.archive) {
            Ok(bytes) => bytes,
            Err(e) => {
                degrade_sidecar(
                    &mut sidecar,
                    &mut warnings,
                    format!("read subtitle archive: {e}"),
                );
                continue;
            }
        };
        // WebVTT is a text format; a non-UTF-8 archive is malformed
        // staging content → degrade.
        let archive = match String::from_utf8(archive) {
            Ok(text) => text,
            Err(e) => {
                degrade_sidecar(
                    &mut sidecar,
                    &mut warnings,
                    format!("subtitle archive is not UTF-8: {e}"),
                );
                continue;
            }
        };
        // Segment bodies: the archive is a concatenation of VTT
        // documents whose boundaries are the ledger rows' spans —
        // splice by spans, reusing the rewrite entries' offsets
        // (bounds-checked: a truncated archive degrades, the content
        // tracks' rewrite_total==archive.len() cross-check has no
        // subtitle equivalent at the channel layer).
        let mut bodies: Vec<(usize, &str, u64)> = Vec::new();
        let mut spans_ok = true;
        for e in &rw.entries {
            let start = e.archive_offset as usize;
            let end = (e.archive_offset + e.archive_len) as usize;
            match archive.get(start..end) {
                Some(span) => bodies.push((e.seg_idx, span, e.duration_ms)),
                None => {
                    degrade_sidecar(
                        &mut sidecar,
                        &mut warnings,
                        format!(
                            "subtitle archive span {start}..{end} outside the {}-byte \
                             archive (truncated staging?)",
                            archive.len()
                        ),
                    );
                    spans_ok = false;
                    break;
                }
            }
        }
        if !spans_ok {
            continue;
        }
        let out_name = subtitle_sidecar_name(&cfg.output, track);
        let path = cfg
            .output
            .parent()
            .unwrap_or(Path::new("."))
            .join(&out_name);
        match vtt::splice_segments(&bodies) {
            Ok(vtt::SpliceOutcome::Complete(cues)) => {
                match crate::staging::write_file(&path, vtt::render_sidecar(&cues).as_bytes()) {
                    Ok(()) => sidecar = Some(Ok(path)),
                    Err(e) => degrade_sidecar(
                        &mut sidecar,
                        &mut warnings,
                        format!("write sidecar {}: {e}", path.display()),
                    ),
                }
            }
            Ok(vtt::SpliceOutcome::Degraded {
                failed_segment,
                reason,
            }) => {
                warnings.push(format!(
                    "subtitle sidecar degraded: segment {failed_segment} ({reason})"
                ));
                sidecar = Some(Err(format!("segment {failed_segment}: {reason}")));
            }
            Err(e) => {
                warnings.push(format!("subtitle sidecar degraded: {e}"));
                sidecar = Some(Err(e.to_string()));
            }
        }
    }

    // 7. Atomic product rename (same-directory rename; the
    // DB-journal completion face is the session's mount). The sidecar step
    // above has already resolved every degradable face, so nothing
    // past this point can contradict a delivered product.
    std::fs::rename(&part, &cfg.output).map_err(|e| {
        MediaError::Staging(format!(
            "rename {} -> {}: {e}",
            part.display(),
            cfg.output.display()
        ))
    })?;
    phase_note(Phase::Done);
    phases.push(Phase::Done);

    Ok(SynthesisReport {
        phases,
        product: cfg.output.clone(),
        sidecar,
        warnings,
        rewrites,
        channel_used,
    })
}

/// `<out>.<label>.vtt` — the sidecar product name (the language-tag
/// form lands with the session's options face; the label keeps it unambiguous).
fn subtitle_sidecar_name(output: &Path, track: &TrackInput) -> String {
    let stem = output
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_string());
    format!("{stem}.{}.vtt", track.label)
}

/// Record one degraded-sidecar outcome (warning + sidecar Err —
/// never a task error, never the both-channels state).
fn degrade_sidecar(
    sidecar: &mut Option<Result<PathBuf, String>>,
    warnings: &mut Vec<String>,
    reason: String,
) {
    warnings.push(format!("subtitle sidecar degraded: {reason}"));
    *sidecar = Some(Err(reason));
}

/// Expected probe tracks from the content inputs (subtitle embed off
/// in 0.3 — the tx3g capability walks the matrix tests, not the
/// product path). `rewrites` is 1:1 with `content` (playlist order)
/// and supplies the **exact segment spans** the fold consumes.
/// Public for the fixture-matrix product sweep, which consumes
/// the same expectation face for its box-probe dual run (the
/// pre-fix sweep never reached this path — its fMP4 legs were
/// defect-pinned).
pub fn build_expectation(
    content: &[&TrackInput],
    rewrites: &[TrackRewrite],
) -> Result<Vec<ExpectedTrack>, MediaError> {
    let mut expect = Vec::with_capacity(content.len());
    for (track, rw) in content
        .iter()
        .zip(rewrites)
        .filter(|(t, _)| t.kind != "subtitle")
    {
        let init_path = track
            .inits
            .first()
            .ok_or_else(|| MediaError::Staging(format!("track {} lost its init", track.label)))?;
        let init = std::fs::read(init_path)
            .map_err(|e| MediaError::Staging(format!("read init {}: {e}", init_path.display())))?;
        // Per-kind selection: a muxed A/V init folds the track-kind-selected
        // trak (single-trak inits keep the same verdict — the selector
        // picks their only trak).
        let tracks = bmff::parse_init_tracks(&init)?;
        let desc = bmff::select_init_track(&tracks, &track.kind).ok_or_else(|| {
            MediaError::Staging(format!(
                "track {} init carries no selectable trak",
                track.label
            ))
        })?;
        let archive = std::fs::read(&track.archive).map_err(|e| {
            MediaError::Staging(format!("read archive {}: {e}", track.archive.display()))
        })?;
        let fold = bmff::fold_track_for(desc, &archive, &rewrite_spans(rw))?;
        expect.push(ExpectedTrack {
            handler: fold.handler,
            timescale: fold.timescale,
            stsd_entry: desc
                .stsd_entries
                .first()
                .map(|e| e.bytes.clone())
                .unwrap_or_default(),
            sample_count: fold.samples.len(),
        });
    }
    Ok(expect)
}

/// The rewrite entries' exact archive spans (the fold's segment-file
/// placement input — no boundary heuristics).
fn rewrite_spans(rw: &TrackRewrite) -> Vec<bmff::SegmentSpan> {
    rw.entries
        .iter()
        .map(|e| bmff::SegmentSpan {
            archive_offset: e.archive_offset,
            archive_len: e.archive_len,
        })
        .collect()
}

/// The native channel: fold → transmux → progressive write. The
/// amended interruption semantics: in-process computation — a
/// cancelled/ interrupted run re-runs whole over the same staging
/// (the token gates entry and between-track boundaries only; there
/// is no child to kill on this channel).
async fn run_native(
    content: &[&TrackInput],
    cfg: &SynthesisConfig,
    part: &Path,
    rewrites: &[TrackRewrite],
    cancel: CancellationToken,
) -> Result<(), MediaError> {
    if cancel.is_cancelled() {
        return Err(MediaError::Cancelled);
    }
    let mut specs: Vec<TrackSpec> = Vec::new();
    for (track, rw) in content.iter().zip(rewrites) {
        if track.kind == "subtitle" {
            continue;
        }
        let init_path = track
            .inits
            .first()
            .ok_or_else(|| MediaError::Staging(format!("track {} lost its init", track.label)))?;
        let init = std::fs::read(init_path)
            .map_err(|e| MediaError::Staging(format!("read init {}: {e}", init_path.display())))?;
        let archive = std::fs::read(&track.archive).map_err(|e| {
            MediaError::Staging(format!("read archive {}: {e}", track.archive.display()))
        })?;
        // Per-kind selection: fold the track-kind-selected trak of the init
        // (muxed A/V archives skip the other track's trafs inside
        // fold_track_for).
        let tracks = bmff::parse_init_tracks(&init)?;
        let desc = bmff::select_init_track(&tracks, &track.kind).ok_or_else(|| {
            MediaError::Staging(format!(
                "track {} init carries no selectable trak",
                track.label
            ))
        })?;
        let fold = bmff::fold_track_for(desc, &archive, &rewrite_spans(rw))?;
        let spec = mp4write::track_spec_from_fold(&fold, &archive)?;
        // Cross-check: the rewrite's archive accounting agrees with
        // the fold (Σ seg spans == sample byte span bookkeeping).
        let rewrite_total: u64 = rw.entries.iter().map(|e| e.archive_len).sum();
        if rewrite_total != archive.len() as u64 {
            return Err(MediaError::Staging(format!(
                "track {}: rewrite accounting {} ≠ archive {}",
                track.label,
                rewrite_total,
                archive.len()
            )));
        }
        specs.push(spec);
    }
    if specs.is_empty() {
        return Err(MediaError::Staging(
            "no content tracks for the native channel".to_string(),
        ));
    }
    let mut out = Vec::new();
    // Metadata vehicle: the metadata rides the config (an empty
    // MovieMeta = the --no-meta / nothing-available face).
    mp4write::write_progressive(&specs, &cfg.meta, &mut out);
    crate::staging::write_file(part, &out)
}

/// The fallback channel: run the discovery-orchestrated remux.
async fn run_fallback(
    rt: &FfmpegRuntime,
    content: &[&TrackInput],
    _cfg: &SynthesisConfig,
    part: &Path,
    fmt: FallbackFormat,
    cancel: CancellationToken,
) -> Result<(), MediaError> {
    let video = content
        .iter()
        .find(|t| t.kind == "video")
        .ok_or_else(|| MediaError::Staging("no video track for the fallback input".to_string()))?;
    let audio = content.iter().find(|t| t.kind == "audio");
    let video_playlist = _cfg
        .staging_dir
        .join(crate::rewrite::local_playlist_name(&video.label));
    let audio_playlist = audio.map(|a| {
        _cfg.staging_dir
            .join(crate::rewrite::local_playlist_name(&a.label))
    });
    let child = rt
        .run_remux(
            &video_playlist,
            audio_playlist.as_deref(),
            part,
            fmt,
            None,
            cancel,
        )
        .await?;
    let output = child.wait().await?;
    output.into_ok().map(|_| ())
}

/// ffprobe dual-run: duration tolerance + stream count (the remux
/// verification face over the real product).
async fn dual_run_probe(
    rt: &FfmpegRuntime,
    part: &Path,
    content: &[&TrackInput],
    expected_ms: u64,
) -> Result<(), MediaError> {
    use crate::ffprobe::probe_args;
    let args: Vec<String> = probe_args(part)
        .into_iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let cmd =
        crate::process::MediaCommand::new(crate::process::MediaBin::Ffprobe, &rt.pair.ffprobe)?
            .args(refs.iter().copied())
            .shim_program(rt.shim_program.clone());
    let child = cmd.spawn()?;
    let out = child.wait().await?;
    if !out.success {
        return Err(MediaError::RemuxVerifyFailed(format!(
            "ffprobe dual-run exit {:?}: {}",
            out.code,
            String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(1024)])
        )));
    }
    let report = crate::ffprobe::FfprobeReport::parse(&out.stdout)?;
    let expected_streams = content.iter().filter(|t| t.kind != "subtitle").count();
    let actual_streams = report
        .streams
        .iter()
        .filter(|s| matches!(s.codec_type.as_deref(), Some("video") | Some("audio")))
        .count();
    if actual_streams != expected_streams {
        return Err(MediaError::RemuxVerifyFailed(format!(
            "ffprobe dual-run: {actual_streams} media streams, expected {expected_streams}"
        )));
    }
    if expected_ms > 0
        && let Some(duration) = report.duration_seconds()
        && !(expected_ms as f64 / 1000.0 * 0.98..=expected_ms as f64 / 1000.0 * 1.02)
            .contains(&duration)
    {
        return Err(MediaError::RemuxVerifyFailed(format!(
            "ffprobe dual-run duration {duration}s outside ±2 % of {} ms",
            expected_ms
        )));
    }
    Ok(())
}

#[cfg(test)]
mod rewrite_parallel_timing {
    use super::*;

    /// Timing harness: two synthetic wide tracks (5,000
    /// segments each — a long-VOD shape) through the parallel
    /// rewrite face vs the serial reference (the pre-parallel loop's
    /// per-track sum). Asserts the structural faces (order
    /// preservation, cancel) and prints the timing pair for the
    /// bench record — the parallel wall vs the serial sum is the
    /// parallelization's own effect, unconfounded by network/BMFF.
    #[test]
    fn parallel_rewrite_timing_and_order() {
        let track = |label: &str, n: usize| {
            let mut text = String::from("#EXTM3U\n#EXT-X-TARGETDURATION:2\n");
            for _ in 0..n {
                text.push_str("#EXTINF:1.0,\ns.m4s\n");
            }
            text.push_str("#EXT-X-ENDLIST\n");
            let playlist = match crate::m3u8::parse_manifest(text.as_bytes())
                .unwrap_or_else(|e| panic!("parse: {e}"))
            {
                crate::m3u8::Playlist::Media(m) => m,
                other => panic!("expected media, got {other:?}"),
            };
            let segments: Vec<crate::trackdl::SegmentRecord> = (0..n)
                .map(|i| crate::trackdl::SegmentRecord {
                    seg_idx: i,
                    media_sequence: i as u64,
                    uri: "s.m4s".into(),
                    byte_range: None,
                    key_id: None,
                    seg_len: 4_000,
                    duration_ms: 1_000,
                    map: None,
                    validator_digest: Vec::new(),
                })
                .collect();
            TrackInput {
                label: label.to_string(),
                kind: "video".into(),
                archive: std::path::PathBuf::from("/nonexistent"),
                inits: Vec::new(),
                segments,
                playlist,
                archive_name: format!("archive-{label}.m4s"),
            }
        };
        let inputs = vec![track("v", 5_000), track("a", 5_000)];
        let cfg = SynthesisConfig {
            phase_sink: None,
            format: OutputFormat::Mp4,
            muxer: MuxerPreference::Native,
            output: std::path::PathBuf::from("/nonexistent/out.mp4"),
            staging_dir: std::env::temp_dir(),
            ffmpeg: None,
            embed_subtitles: false,
            meta: Default::default(),
            free_bytes_override: Some(None),
        };
        let cancel = CancellationToken::new();
        // Parallel face (order-preserving by slot index).
        let t0 = std::time::Instant::now();
        let rt = tokio::runtime::Runtime::new().unwrap_or_else(|e| panic!("tokio runtime: {e}"));
        let rewrites = rt
            .block_on(run_rewrites_parallel(&inputs, &cfg, &cancel))
            .unwrap_or_else(|e| panic!("parallel: {e}"));
        let parallel_ms = t0.elapsed().as_millis() as u64;
        assert_eq!(
            rewrites
                .iter()
                .map(|r| r.label.as_str())
                .collect::<Vec<_>>(),
            vec!["v", "a"],
            "slot indexes keep playlist order"
        );
        // Serial reference (the pre-parallel loop's shape, same per-track
        // work minus the staging write — measured separately below).
        let t1 = std::time::Instant::now();
        let serial: Vec<TrackRewrite> = inputs
            .iter()
            .map(|tr| {
                crate::rewrite::rewrite_track(
                    &tr.playlist,
                    &tr.segments,
                    &tr.label,
                    &tr.archive_name,
                )
                .unwrap_or_else(|e| panic!("serial: {e}"))
            })
            .collect();
        let serial_ms = t1.elapsed().as_millis() as u64;
        // Byte-level identity: the parallel products equal the serial
        // products (same inputs -> same outputs, the frozen seam).
        assert_eq!(rewrites.len(), serial.len());
        for (p, s) in rewrites.iter().zip(&serial) {
            assert_eq!(p.text, s.text);
            assert_eq!(p.entries, s.entries);
        }
        println!(
            "rewrite timing: parallel={parallel_ms}ms serial_sum={serial_ms}ms tracks=2 segments=5000x2"
        );
        // Single-track degenerate face: unchanged product.
        let one = vec![track("v", 64)];
        let r1 = rt
            .block_on(run_rewrites_parallel(&one, &cfg, &cancel))
            .unwrap_or_else(|e| panic!("single: {e}"));
        let s1 = crate::rewrite::rewrite_track(
            &one[0].playlist,
            &one[0].segments,
            &one[0].label,
            &one[0].archive_name,
        )
        .unwrap_or_else(|e| panic!("single serial: {e}"));
        assert_eq!(
            r1[0].text, s1.text,
            "single track no fallback (byte-identical)"
        );
    }
}

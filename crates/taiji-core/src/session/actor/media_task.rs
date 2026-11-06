//! MediaTask actor glue: the waiting-queue payload
//! ([`MediaJob`]), the driver spawn, and the addMedia option-parse
//! face. The pipeline itself lives in [`crate::session::media`] (the
//! reusable module the CLI also drives); this file is the SessionActor
//! integration — the third task family alongside Job::Torrent/
//! Magnet/TorrentUrl/Http, following the HTTP task's shape (the
//! `TaskBackend` enum's minimal-intrusion third arm; the family's
//! surfaces are stated explicitly in the BackendContract —
//! [`crate::session::backend_contract`]): the
//! media verification position = segment-boundary accounting +
//! synthesis-time final ruling).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicBool;

use tokio_util::sync::CancellationToken;

use taiji_media::MediaPhase;
use taiji_media::options::{FfmpegPathSpec, MuxerSpec, OutputFormat, SubtitleMode};

use crate::session::media::{MediaLive, MediaNote, MediaNoteSink, MediaRunConfig};
use crate::session::options::{TaskOptionPatch, parse_task_options};

use super::SessionActor;
use crate::gid::Gid;
use crate::session::command::TaskCookieSpec;
use crate::session::events::{MediaEvent, MediaWarning};

/// The media waiting-queue payload (consumed repeatedly across
/// reorders/restarts — rebuilt from the row at bootstrap).
pub(crate) struct MediaJob {
    /// The pipeline configuration (everything the driver needs; the
    /// `restore` row rides for the phase re-entry).
    pub cfg: MediaRunConfig,
    /// The structured cookie specs (the DirectLink conversion's
    /// HTTP-family payload source; the media pipeline consumes the
    /// converted pairs from `cfg`).
    pub cookie_specs: Vec<TaskCookieSpec>,
}

/// The accepted media option keys (the addMedia options face — the
/// unified registration's per-task parse set; unknown keys fail
/// explicitly through the shared option face).
pub(crate) const MEDIA_OPTION_KEYS: &[&str] = &[
    "dir",
    "out",
    "media-selector",
    "media-audio-lang",
    "sub-lang",
    "media-subtitles",
    "media-template",
    "no-meta",
    "media-archive",
    "media-info-json",
    "media-segment-concurrency",
    "media-staging-quota-gib",
    "media-staging-dir",
    "media-allow-private-key-url",
    "media-ffmpeg-path",
    "media-muxer",
    "media-output-format",
    "media-variant-policy",
    "probe-token",
    "pause",
];

/// The global-defaults merge: a per-task value present in the payload
/// wins; an absent key falls back to the session global's value; an
/// empty/whitespace value counts as absent on both faces.
fn merge_global_or<'a>(per_task: Option<&'a str>, global_value: &'a str) -> Option<&'a str> {
    let per = per_task.filter(|v| !v.trim().is_empty());
    per.or_else(|| {
        let g = global_value.trim();
        (!g.is_empty()).then_some(g)
    })
}

/// Parse the addMedia options dict into a run configuration skeleton
/// (no gid/persist yet — the caller fills those). An unknown key or a
/// domain violation is `taiji.option.invalid` (the honest face, no
/// silent defaults).
pub(super) fn media_cfg_from_options(
    url: &str,
    options: &BTreeMap<String, String>,
    cookies: &[TaskCookieSpec],
    global: &crate::session::options::GlobalOptions,
) -> Result<MediaRunConfig, crate::session::SessionError> {
    use crate::session::SessionError;
    let invalid = |msg: String| SessionError::failed(format!("taiji.option.invalid: {msg}"));
    for key in options.keys() {
        if !MEDIA_OPTION_KEYS.contains(&key.as_str()) {
            return Err(invalid(format!(
                "unknown media option {key:?} (accepted: {MEDIA_OPTION_KEYS:?})"
            )));
        }
    }
    // The session globals are the **defaults face**: a per-task option
    // present in the payload wins; an absent key falls back to the
    // global value (changeGlobalOption media-* is live for tasks
    // added afterwards — the wired consumption the GLOBAL_PATCH rows
    // declare); the globals themselves default to the taiji-media
    // constants, so a default session is a zero change.
    let global_or = merge_global_or;
    let get = |k: &str| options.get(k).map(|s| s.trim()).filter(|s| !s.is_empty());
    let patch: TaskOptionPatch = parse_task_options(options);
    let output_dir = patch.dir.clone().unwrap_or_else(|| PathBuf::from("."));
    let subtitles = match global_or(get("media-subtitles"), &global.media_subtitles) {
        None => SubtitleMode::Sidecar,
        Some(v) => taiji_media::parse_subtitles(v)
            .map_err(|e| invalid(format!("--media-subtitles: {e}")))?,
    };
    let audio_lang = match global_or(
        get("media-audio-lang"),
        global.media_audio_lang.as_deref().unwrap_or(""),
    ) {
        None => None,
        Some(v) => taiji_media::parse_audio_lang(v)
            .map_err(|e| invalid(format!("--media-audio-lang: {e}")))?,
    };
    let subtitle_lang = match get("sub-lang") {
        None => None,
        Some(v) => taiji_media::parse_audio_lang(v).map_err(|e| invalid(format!("--sub: {e}")))?,
    };
    // Selection-source precedence (the exclusivity check is
    // per-task-only: a session-global variant policy never conflicts
    // with a per-task selector — the global is the absent-key
    // default, not a second selection source):
    // per-task media-selector > per-task media-variant-policy >
    // the session global's variant policy.
    let per_task_policy = get("media-variant-policy");
    let policy_source = merge_global_or(per_task_policy, &global.media_variant_policy);
    // The policy rides BOTH faces (the DASH scope item): the parsed
    // value threads to `MediaRunConfig::variant_policy`, where the
    // DASH representations select under it with equivalent effect
    // (highest|resolution=<H>|bandwidth=<B> — the full policy semantics,
    // including the bandwidth cap the selector projection cannot
    // spell); the projection string below keeps serving the HLS
    // tree face (unchanged).
    let variant_policy = match policy_source {
        Some(p) => taiji_media::VariantPolicy::parse(p)
            .map_err(|e| invalid(format!("--media-variant-policy: {e}")))?,
        None => taiji_media::VariantPolicy::Highest,
    };
    let selector = if let Some(s) = get("media-selector") {
        if per_task_policy.is_some() {
            return Err(invalid(
                "media-selector and media-variant-policy are exclusive (one selection source)"
                    .to_string(),
            ));
        }
        Some(s.to_string())
    } else if policy_source.is_some() {
        // The policy flag face projects into the selector's preset/
        // predicate layer: highest → `best`; resolution=H →
        // `res<=H`; bandwidth=B has no predicate form (the
        // selector's layer-3 escape hatch names ids, not caps) —
        // the flag's own parse still validates the value and the
        // full policy rides `variant_policy` above (the DASH line
        // consumes it directly; the HLS face falls to `best` — the
        // honest projection limit for that face, noted for the
        // unified-registration report).
        Some(match variant_policy {
            taiji_media::VariantPolicy::Highest => "best".to_string(),
            taiji_media::VariantPolicy::Resolution { height } => format!("res<={height}"),
            taiji_media::VariantPolicy::Bandwidth { .. } => "best".to_string(),
        })
    } else {
        None
    };
    let segment_concurrency = match global_or(
        get("media-segment-concurrency"),
        &global.media_segment_concurrency.to_string(),
    ) {
        None => taiji_media::DEFAULT_SEGMENT_CONCURRENCY,
        Some(v) => taiji_media::parse_segment_concurrency(v)
            .map_err(|e| invalid(format!("--media-segment-concurrency: {e}")))?,
    };
    let staging_quota_gib = match global_or(
        get("media-staging-quota-gib"),
        &global.media_staging_quota_gib.to_string(),
    ) {
        None => taiji_media::DEFAULT_STAGING_QUOTA_GIB,
        Some(v) => taiji_media::parse_staging_quota_gib(v)
            .map_err(|e| invalid(format!("--media-staging-quota-gib: {e}")))?,
    };
    let staging_dir = match global_or(
        get("media-staging-dir"),
        global.media_staging_dir.as_deref().unwrap_or(""),
    ) {
        None => None,
        Some(v) => Some(
            taiji_media::parse_staging_dir(v)
                .map_err(|e| invalid(format!("--media-staging-dir: {e}")))?,
        ),
    };
    let allow_private_key_url = match global_or(
        get("media-allow-private-key-url"),
        &global.media_allow_private_key_url.to_string(),
    ) {
        None => false,
        Some(v) => taiji_media::parse_allow_private_key_url(v)
            .map_err(|e| invalid(format!("--media-allow-private-key-url: {e}")))?,
    };
    let ffmpeg_path = match global_or(get("media-ffmpeg-path"), &global.media_ffmpeg_path) {
        None => FfmpegPathSpec::Auto,
        Some(v) => taiji_media::parse_ffmpeg_path(v)
            .map_err(|e| invalid(format!("--media-ffmpeg-path: {e}")))?,
    };
    let muxer = match get("media-muxer") {
        None => MuxerSpec::Auto,
        Some(v) => {
            taiji_media::parse_muxer(v).map_err(|e| invalid(format!("--media-muxer: {e}")))?
        }
    };
    let output_format = match get("media-output-format") {
        None => OutputFormat::Mp4,
        Some(v) => taiji_media::parse_output_format(v)
            .map_err(|e| invalid(format!("--media-output-format: {e}")))?,
    };
    let no_metadata = match get("no-meta") {
        None => false,
        Some(v) => v
            .parse::<bool>()
            .map_err(|_| invalid("--no-meta expects true|false".to_string()))?,
    };
    // The product faces' task flags: session-global defaults,
    // per-task values win (the family's merge rule).
    let archive = match global_or(get("media-archive"), &global.media_archive.to_string()) {
        None => false,
        Some(v) => taiji_media::parse_media_archive(v)
            .map_err(|e| invalid(format!("--media-archive: {e}")))?,
    };
    let info_json = match global_or(get("media-info-json"), &global.media_info_json.to_string()) {
        None => false,
        Some(v) => taiji_media::parse_media_info_json(v)
            .map_err(|e| invalid(format!("--media-info-json: {e}")))?,
    };
    Ok(MediaRunConfig {
        gid: String::new(),
        url: url.to_string(),
        output_dir,
        out: get("out").map(str::to_string),
        selector,
        variant_policy,
        audio_lang,
        subtitles,
        subtitle_lang,
        template: get("media-template").map(str::to_string),
        no_metadata,
        archive,
        info_json,
        cookies: cookies
            .iter()
            .map(|c| (c.name.clone(), c.value.clone()))
            .collect(),
        allow_private_key_url,
        segment_concurrency,
        staging_quota_gib,
        staging_dir,
        ffmpeg_path,
        muxer,
        output_format,
        restore: None,
        probe_snapshot: None,
        persist: None,
        ffmpeg: None,
        resolver: None,
        recovered_tree: None,
        // The synthesis gate is a runtime injection (spawn_media_driver
        // pairs it with the actor's permit map); the parse face passes
        // None (the bare-run passthrough shape).
        gate: None,
    })
}

impl SessionActor {
    /// The media task's event sink: publishes phase/warning notes to
    /// the media extension bus (`taiji.media.phaseChanged`, the
    /// bypass face) with the task's gid stamped. A phase tracker cell rides
    /// along so warning payloads carry the task's current phase (an
    /// alarm is not a transition — the payload's `warning` face
    /// distinguishes the two).
    pub(super) fn media_note_sink(
        &self,
        gid: Gid,
        tracker: Arc<StdMutex<MediaPhase>>,
    ) -> MediaNoteSink {
        let bus = self.media_bus.clone();
        Arc::new(move |note: &MediaNote| {
            let event = match note {
                MediaNote::Phase(p) => {
                    if let Ok(mut t) = tracker.lock() {
                        *t = *p;
                    }
                    MediaEvent {
                        gid,
                        phase: *p,
                        phase_detail: None,
                        warning: None,
                    }
                }
                MediaNote::PausedWithMemory(p) => {
                    if let Ok(mut t) = tracker.lock() {
                        *t = MediaPhase::Paused;
                    }
                    MediaEvent {
                        gid,
                        phase: MediaPhase::Paused,
                        phase_detail: Some(p.as_str().to_string()),
                        warning: None,
                    }
                }
                MediaNote::Warning { code, message } => {
                    let phase = tracker.lock().map(|t| *t).unwrap_or(MediaPhase::Queued);
                    MediaEvent {
                        gid,
                        phase,
                        phase_detail: None,
                        warning: Some(MediaWarning {
                            code: code.to_string(),
                            message: message.clone(),
                        }),
                    }
                }
            };
            let _ = bus.send(event);
        })
    }

    /// Spawn the media driver (the `Job::Media` activation face):
    /// runs the pipeline on the task token, publishing notes to the
    /// media bus; the watcher maps the terminal outcome to a
    /// TaskNotice. Returns the live-state handle + the abort handle.
    /// Async: the session's ffmpeg discovery cache resolution awaits
    /// (one discovery per session — the discovery assertion face is
    /// expensive; a miss caches as absent until restart).
    ///
    /// Runtime injections (the cfg is otherwise the job payload's):
    /// the persist handle, the session ffmpeg cache, and — since
    /// the four-pool work — the **synthesis gate**: the actor
    /// pairs a gate here (the wait end rides `cfg.gate` into the
    /// driver; the permit end lands in the actor's gate map, consumed
    /// by pump_all's budget-gated synthesis segment). The gate's
    /// arrival notice enqueues `TaskNotice::SynthesisGate` on the
    /// actor's private notice channel (the pipeline → TaskNotice link
    /// shape the card fixes; zero new channels — the same mpsc the
    /// watcher and the hook relay share).
    pub(super) async fn spawn_media_driver(
        &self,
        gid: Gid,
        mut cfg: MediaRunConfig,
        token: CancellationToken,
        pause: Arc<AtomicBool>,
    ) -> (
        Arc<StdMutex<crate::session::media::MediaLiveState>>,
        tokio::task::AbortHandle,
        crate::session::media::SynthesisGatePermit,
    ) {
        cfg.gid = gid.to_string();
        cfg.persist = self.persist.clone();
        // The synthesis gate pair: the driver holds the
        // wait end; the caller stores the permit end in the actor's
        // gate map (returned alongside — the map insert needs &mut
        // self, so the caller wires it after this &self spawn).
        let notice_events = self.events.clone();
        let (gate_permit, gate_wait) =
            crate::session::media::SynthesisGate::pair(Arc::new(move || {
                let events = notice_events.clone();
                Box::pin(async move {
                    // The arrival notice (the Downloading → Processing
                    // boundary): the actor releases the download slot
                    // and parks the task into proc_wait, then pumps —
                    // the permit fires from the synthesis segment
                    // within budget. A full channel waits here (the
                    // actor drains promptly; dropping a gate notice
                    // would hang the task, so never try_send).
                    let _ = events.send(super::TaskNotice::SynthesisGate { gid }).await;
                }) as futures::future::BoxFuture<'static, ()>
            }));
        cfg.gate = Some(gate_wait);
        if cfg.ffmpeg.is_none() {
            let cached = {
                let cache = crate::lock(&self.media_ffmpeg);
                cache.clone()
            };
            cfg.ffmpeg = match cached {
                Some(hit) => hit,
                None => {
                    let discovered = crate::session::media::discover_runtime(&cfg.ffmpeg_path)
                        .await
                        .ok();
                    crate::lock(&self.media_ffmpeg).clone_from(&Some(discovered.clone()));
                    discovered
                }
            };
        }
        let live = MediaLive::new();
        let live_state = live.share();
        let tracker = Arc::new(StdMutex::new(MediaPhase::Resolving));
        let notes = self.media_note_sink(gid, tracker);
        let events = self.events.clone();
        // The panic gate: the driver JoinHandle is consumed
        // here — never dropped bare — and the pipeline future runs
        // under catch_unwind. Pre-fix, a panic inside the driver task
        // (e.g. the bmff box-arithmetic wrap) killed the task silently:
        // TaskNotice::Ended never fired, the task zombie'd in the
        // running set with its row stuck mid-phase and only a stderr
        // print. Now the panic maps to the task-level Error terminal
        // (media_panic_terminal) and the Ended notice always fires.
        let cfg_for_panic = cfg.clone();
        let live_for_panic = live.share();
        let join = tokio::spawn(async move {
            let pipeline =
                crate::session::media::run_media_task(cfg, live_state, notes, token, pause);
            let end = match futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(pipeline))
                .await
            {
                Ok(end) => end,
                Err(panic) => {
                    crate::session::media::media_panic_terminal(
                        &cfg_for_panic,
                        &live_for_panic,
                        panic_text(&panic),
                    )
                    .await
                }
            };
            let _ = events
                .send(super::TaskNotice::Ended {
                    gid,
                    outcome: super::TaskOutcome::Media(end),
                })
                .await;
        });
        (live.share(), join.abort_handle(), gate_permit)
    }
}

/// Best-effort panic-payload → text (the driver gate's message face;
/// non-string payloads degrade to a type name).
fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The global-defaults merge is live (the changeGlobalOption face
    /// is consumed, not just echoed): absent per-task keys fall back
    /// to the session globals; a present per-task key wins; a default
    /// session keeps the taiji-media constants (zero change).
    #[test]
    fn media_options_merge_global_defaults() {
        let global = crate::session::options::GlobalOptions {
            media_variant_policy: "resolution=720".into(),
            media_audio_lang: Some("zh-Hans".into()),
            media_subtitles: "none".into(),
            media_segment_concurrency: 16,
            media_staging_quota_gib: 10,
            media_staging_dir: Some("/tmp/stage".into()),
            media_allow_private_key_url: true,
            media_ffmpeg_path: "path:/opt/ff".into(),
            ..Default::default()
        };
        // Absent per-task keys: every field takes the global.
        let cfg = media_cfg_from_options("https://x.test/m.m3u8", &BTreeMap::new(), &[], &global)
            .unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(cfg.selector.as_deref(), Some("res<=720"));
        assert_eq!(cfg.audio_lang.as_deref(), Some("zh-hans"));
        assert_eq!(cfg.subtitles, SubtitleMode::None);
        assert_eq!(cfg.segment_concurrency, 16);
        assert_eq!(cfg.staging_quota_gib, 10);
        assert_eq!(
            cfg.staging_dir.as_ref().and_then(|p| p.to_str()),
            Some("/tmp/stage")
        );
        assert!(cfg.allow_private_key_url);
        assert_eq!(
            cfg.ffmpeg_path,
            FfmpegPathSpec::PathOptIn(PathBuf::from("/opt/ff"))
        );
        // A present per-task key wins over the global.
        let per_task = BTreeMap::from([
            ("media-subtitles".to_string(), "sidecar".to_string()),
            ("media-segment-concurrency".to_string(), "4".to_string()),
        ]);
        let cfg = media_cfg_from_options("https://x.test/m.m3u8", &per_task, &[], &global)
            .unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(cfg.subtitles, SubtitleMode::Sidecar, "per-task wins");
        assert_eq!(cfg.segment_concurrency, 4, "per-task wins");
        assert_eq!(cfg.audio_lang.as_deref(), Some("zh-hans"), "global fills");
        // A default session: the taiji-media constants (zero change —
        // the default global policy `highest` materializes as the
        // `best` preset, the same selection the absent-selector
        // default always meant).
        let cfg = media_cfg_from_options(
            "https://x.test/m.m3u8",
            &BTreeMap::new(),
            &[],
            &Default::default(),
        )
        .unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(cfg.selector.as_deref(), Some("best"));
        assert_eq!(
            cfg.segment_concurrency,
            taiji_media::DEFAULT_SEGMENT_CONCURRENCY
        );
        assert_eq!(cfg.subtitles, SubtitleMode::Sidecar);
        assert!(!cfg.allow_private_key_url);
    }

    /// Panic-gate unit: a panicking pipeline future maps
    /// to the task-level Error terminal (inherited
    /// `taiji.media.staging` code, message carrying the panic text)
    /// and flips the live phase to Error — the actor's Ended notice
    /// therefore always lands on a terminal state, never a zombie.
    /// (The end-to-end shape — crafted media bytes reaching the
    /// synthesis fold — is pinned by taiji-core's
    /// `media_negative::crafted_bmff_bytes_error_not_zombie`.)
    #[tokio::test]
    async fn panic_gate_maps_panic_to_error_terminal() {
        use crate::session::media::{MediaLive, media_panic_terminal};
        use taiji_media::MediaPhase;
        let cfg = media_cfg_from_options(
            "https://x.test/m.m3u8",
            &BTreeMap::new(),
            &[],
            &Default::default(),
        )
        .unwrap_or_else(|e| panic!("parse: {e}"));
        let live = MediaLive::new();
        let live_state = live.share();
        let panic_payload = Box::new("boom: crafted box arithmetic");
        let payload_ref: &(dyn std::any::Any + Send) = panic_payload.as_ref();
        let end = media_panic_terminal(&cfg, &live_state, panic_text(payload_ref)).await;
        match end {
            crate::session::media::MediaEnd::Failed { code, message } => {
                assert_eq!(code, "taiji.media.staging", "inherited code, no new mint");
                assert!(
                    message.contains("panicked") && message.contains("boom"),
                    "message carries the panic text: {message}"
                );
            }
            other => panic!("unexpected terminal {other:?}"),
        }
        assert_eq!(
            live_state
                .lock()
                .map(|st| st.phase)
                .unwrap_or(MediaPhase::Queued),
            MediaPhase::Error,
            "the live phase flips to Error"
        );
    }
}

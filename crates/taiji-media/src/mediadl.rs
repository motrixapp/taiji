//! The multi-track media download driver (the programmatic
//! face — the RPC/session orchestration that mounts it lives in the
//! session; the e2e tests drive this directly, no RPC).
//!
//! Flow: fetch + parse the manifest (the m3u8 parser, or — since
//! DASH support — the MPD line: sniff routes an MPD body to
//! [`crate::mpd`]'s parse + plan + per-representation expansion onto
//! the same track model) → variant selection policy →
//! track-set planning + necessity grading (the media spec) →
//! staging admission (same-volume, 0700 create-new,
//! quota) → **sequential** per-track downloads (cross-track concurrency
//! off by default — the N_m3u8DL-RE `-mt` contrast) through the (a)/(b)
//! layer drivers → per-track ledger persistence
//! (media_track/media_segment, validator digests written from day
//! one) → track-set convergence ([`TrackSetVerdict`]; degraded
//! sidecars carry their warning payloads — the emission face is the
//! session's, this module records the state).
//!
//! Runtime watermark: a 30s watchdog
//! ([`crate::staging::WATERMARK_INTERVAL`]) samples staging usage
//! against the quota and flips a violation flag; the driver also
//! rechecks deterministically at every track boundary. A violation is
//! a **task error** (`taiji.media.staging_quota_exceeded` out of
//! `run` — the graceful-stop form is the LIVE-only
//! branch): tracks already completed have durable ledger
//! rows, so the prefix resumes after the quota is raised.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use taiji_http::client::{ClientConfig, HttpClient};
use taiji_segment::traits::RequestCtx;

use crate::error::MediaError;
use crate::keys::{
    KeyTable, TrackCrypto, build_track_crypto, collect_key_specs, expand_track_keys,
};
use crate::m3u8::{self, Playlist, VariantPolicy, parse_manifest, select_variant};
use crate::ssrf::{HostVerdictCache, SsrfPolicy, SsrfResolver, check_uri, default_resolver};
use crate::staging::{
    StagingQuota, archive_name, create_staging_dir, ensure_same_volume, guess_archive_ext,
    source_manifest_path, staging_gid_dir, staging_usage_bytes,
};
use crate::trackdl::{
    MediaLedger, MediaTaskRecord, TrackFetchConfig, TrackLayer, TrackRecord, TrackRunResult,
    classify_track, download_known_length_track, download_unknown_length_track,
    layout_known_length, unpack_bitmap_prefix,
};
use crate::trackset::{
    PlannedTrack, TrackRole, TrackSetConfig, TrackSetVerdict, TrackState, plan_track_set,
    track_set_verdict,
};

/// Driver configuration (the wired flag faces assembled).
#[derive(Clone)]
pub struct MediaDownloadConfig {
    /// Track-set planning face (audio lang / subtitles / segment
    /// concurrency).
    pub track_set: TrackSetConfig,
    /// Per-track fetch face (concurrency/retry).
    pub fetch: TrackFetchConfig,
    /// `--media-variant-policy` (selection face; default `highest`).
    pub variant_policy: VariantPolicy,
    /// The selector's resolved choice: when present the
    /// variant-policy selection is skipped — the primary variant is
    /// the named URI and the attached renditions join the plan as
    /// sidecar-role tracks (the necessity grading applies: a
    /// sidecar failure degrades, never fails the task).
    pub chosen: Option<ChosenVariant>,
    /// The selector's resolved **DASH** picks (the same
    /// semantics for the DASH line): when present the policy-based
    /// `plan_dash_tracks` selection is skipped — the primary
    /// representation is the named `@id` and the attached ids join
    /// as sidecar tracks (see [`crate::mpd::DashSelection`]).
    pub dash_selection: Option<crate::mpd::DashSelection>,
    /// Subtitle-language preference (the `--sub <lang>` face):
    /// when set, planned subtitle sidecar tracks filter to the
    /// RFC 5646 prefix match (no match = no subtitle track — an
    /// explicit preference that finds nothing downloads nothing,
    /// rather than silently falling back to all renditions).
    pub subtitle_lang: Option<String>,
    /// `--media-staging-quota-gib` (default 50).
    pub staging_quota_gib: u64,
    /// `--media-staging-dir` (default: `<output_dir>/.taiji-b`).
    pub staging_dir: Option<PathBuf>,
    /// `--media-allow-private-key-url` (default false = SSRF default
    /// deny; governs both the key-URI face and the
    /// media-segment/init-URL face — see [`crate::ssrf`]).
    pub allow_private_key_url: bool,
    /// Output directory (the synthesis destination face; the native
    /// channel mounts the product naming).
    pub output_dir: PathBuf,
    /// Progress sink (the session orchestration face): invoked at track
    /// boundaries (track start/finish) — the session's MediaLive and
    /// the CLI's reporter consume the same notes. `None` = no
    /// observer (pure library use).
    pub progress: Option<std::sync::Arc<dyn Fn(MediaProgressNote) + Send + Sync>>,
}

/// The selector's resolved choice (see
/// [`MediaDownloadConfig::chosen`]).
#[derive(Clone, Debug)]
pub struct ChosenVariant {
    /// The primary variant's playlist URI (resolved absolute).
    pub variant_uri: String,
    /// Explicitly attached side renditions (audio/subtitle URIs from
    /// the `format_id=` escape hatch's multi-value form; deduped
    /// against the planned set by URI).
    pub attached: Vec<AttachedRendition>,
}

/// One explicitly attached side rendition.
#[derive(Clone, Debug)]
pub struct AttachedRendition {
    pub uri: String,
    /// audio|subtitle.
    pub kind: &'static str,
    pub language: Option<String>,
}

/// The per-track source the driver loop feeds [`MediaDownload::run_track`]:
/// the HLS line fetches its playlist URI; the DASH line
/// expands the planned representation from the already-parsed MPD
/// (the optional sidx form fetches its indexRange here — the only
/// second-order GET the DASH preparation adds).
#[derive(Clone)]
enum TrackSource<'a> {
    /// Fetch + parse `planned.playlist_uri` (the HLS line).
    Hls,
    /// Expand this representation of the parsed MPD.
    Dash {
        mpd: &'a crate::mpd::Mpd,
        pick: crate::mpd::DashPick,
        manifest_url: &'a str,
    },
}

/// A progress note at a track boundary (the orchestration observer
/// face; byte-level granularity lives inside the track drivers — this
/// is the task-level rollup the session projects).
#[derive(Clone, Debug)]
pub struct MediaProgressNote {
    /// Track label (`v`, `a`, `s0`).
    pub label: String,
    /// video|audio|subtitle.
    pub kind: &'static str,
    /// True = the track started; false = it finished.
    pub started: bool,
    /// Delivered plaintext bytes of this track (at finish = the whole
    /// track; at start = the resumed prefix's bytes).
    pub delivered_bytes: u64,
    /// Segments done / total of this track (at start = the resumed
    /// prefix).
    pub segments_done: usize,
    pub segments_total: usize,
}

impl Default for MediaDownloadConfig {
    fn default() -> Self {
        Self {
            track_set: TrackSetConfig::default(),
            fetch: TrackFetchConfig::default(),
            variant_policy: VariantPolicy::default(),
            chosen: None,
            dash_selection: None,
            subtitle_lang: None,
            staging_quota_gib: crate::options::DEFAULT_STAGING_QUOTA_GIB,
            staging_dir: None,
            allow_private_key_url: false,
            output_dir: PathBuf::from("."),
            progress: None,
        }
    }
}

/// One completed run's report.
#[derive(Clone, Debug)]
pub struct MediaRunReport {
    /// Track-set convergence (degraded sidecar warnings ride the
    /// `Complete` verdict).
    pub verdict: TrackSetVerdict,
    /// Per-track terminal states (label ↔ state).
    pub tracks: Vec<(PlannedTrack, TrackState)>,
    /// The task's staging directory.
    pub staging_dir: PathBuf,
    /// Staged archive names per track label.
    pub archives: Vec<(String, String)>,
}

/// The multi-track driver.
pub struct MediaDownload {
    /// 16-hex task gid.
    pub gid: String,
    client: HttpClient,
    ctx: RequestCtx,
    cfg: MediaDownloadConfig,
    /// The pinned fetch client (rebuilt whenever the SSRF judgment
    /// table grows — see [`Self::fetch_client`]).
    pinned: std::sync::Mutex<Option<(usize, HttpClient)>>,
    /// SSRF resolver injection face (`None` = the production shared
    /// resolver; tests inject stubs — the taiji-io test-DNS ban).
    pub resolver: Option<Arc<dyn SsrfResolver>>,
    /// Watchdog spawn observer (test-only injection face; the
    /// leak regression observes the sampler's JoinHandle termination
    /// through it — `None` in production).
    pub watchdog_observer: Option<WatchdogObserver>,
}

/// Receives the spawned watchdog sampler's JoinHandle at spawn time
/// (the leak regression's probe face; production = `None`).
pub type WatchdogObserver = Arc<dyn Fn(tokio::task::JoinHandle<()>) + Send + Sync>;

/// The 30s watermark sampler's RAII owner (leak fix): drop
/// aborts the spawned loop, so **every** exit from `run` — the `?`
/// early returns between spawn and the old explicit abort sites
/// (manifest-URL parse, `save_track` ledger writes, …), the driver
/// future being dropped mid-track (outer cancel: the session's
/// `tokio::select!` cancels the run future), and the normal returns —
/// terminates the sampler. Pre-fix the loop only died at four explicit
/// `abort()` calls; every other path leaked a detached 30s poller per
/// task (long sessions accumulated them).
struct WatchdogGuard(Option<tokio::task::AbortHandle>);

impl WatchdogGuard {
    fn spawn(
        root: PathBuf,
        flag: Arc<AtomicBool>,
        quota: StagingQuota,
        observer: Option<&WatchdogObserver>,
    ) -> Self {
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(crate::staging::WATERMARK_INTERVAL).await;
                if quota.check(staging_usage_bytes(&root), 0).is_err() {
                    flag.store(true, Ordering::Release);
                }
            }
        });
        let abort = handle.abort_handle();
        // The observer takes the JoinHandle (the leak regression's
        // probe face: it can await / is_finished it); the guard keeps
        // the AbortHandle for the drop-time termination.
        if let Some(sink) = observer {
            sink(handle);
        }
        Self(Some(abort))
    }
}

impl Drop for WatchdogGuard {
    fn drop(&mut self) {
        if let Some(abort) = self.0.take() {
            abort.abort();
        }
    }
}

impl MediaDownload {
    /// Assemble (client + request context + configuration).
    pub fn new(gid: &str, client: HttpClient, ctx: RequestCtx, cfg: MediaDownloadConfig) -> Self {
        Self {
            gid: gid.to_string(),
            client,
            ctx,
            cfg,
            pinned: std::sync::Mutex::new(None),
            resolver: None,
            watchdog_observer: None,
        }
    }

    /// The fetch client for second-order URLs (the
    /// DNS-rebinding connection pin): every host the SSRF judgment
    /// resolved is pinned to the address the judgment saw — the fetch
    /// transport then connects to the judged address (Host/SNI keep
    /// the URL's name), so a rebinding DNS cannot answer the connect
    /// query with an address the judgment never saw. Literal-IP /
    /// flag paths resolve nothing and pin nothing (the base client,
    /// unchanged behavior). The variant rebuilds only when the pin
    /// table grows (one rebuild per distinct judged host).
    fn fetch_client(&self, host_cache: &HostVerdictCache) -> Result<HttpClient, MediaError> {
        let pins: Vec<(String, std::net::SocketAddr)> = host_cache
            .iter()
            .filter_map(|(host, verdict)| verdict.pin.map(|addr| (host.to_ascii_lowercase(), addr)))
            .collect();
        if pins.is_empty() {
            return Ok(self.client.clone());
        }
        let mut guard = self.pinned.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((n, cached)) = guard.as_ref()
            && *n == pins.len()
        {
            return Ok(cached.clone());
        }
        let built = self
            .client
            .with_pinned_resolve(&pins)
            .map_err(|e| MediaError::Staging(format!("pinned client build: {e}")))?;
        *guard = Some((pins.len(), built.clone()));
        Ok(built)
    }

    /// The active fetch client's pin table (probe face; the rebinding
    /// regression asserts the judged address landed here).
    pub fn active_pins(&self) -> Vec<(String, std::net::SocketAddr)> {
        let guard = self.pinned.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some((_, client)) => client.pinned_resolve().to_vec(),
            None => self.client.pinned_resolve().to_vec(),
        }
    }

    /// Build a default client for a driver (tests pass their own).
    pub fn default_client() -> Result<HttpClient, MediaError> {
        HttpClient::new(ClientConfig::default())
            .map_err(|e| MediaError::Staging(format!("client build: {e}")))
    }

    /// Run the whole download (see module docs for the flow). `Err`
    /// = a staging/assembly-level failure; a required-track fetch
    /// failure comes back as [`TrackSetVerdict::Failed`] inside the
    /// report (the track-level error face), not as `Err`.
    ///
    /// The entry sniff routes the flavor: an MPD body
    /// takes the DASH line — parse ([`crate::mpd::parse_mpd`]),
    /// plan ([`crate::mpd::plan_dash_tracks`]), then per-track
    /// expansion ([`crate::mpd::expand_representation`]) onto the
    /// synthetic HLS track model and the same (a)/(b) drivers. The
    /// judgment-table refusals (dynamic/DRM/caps) surface here as
    /// their canonical codes; the HLS line is untouched.
    pub async fn run(
        &self,
        manifest_url: &str,
        ledger: &dyn MediaLedger,
    ) -> Result<MediaRunReport, MediaError> {
        // 1. Manifest fetch + parse (sniff order = content first; the
        // parser classifies master/media).
        let manifest_bytes = http_get_bytes(&self.client, manifest_url, &self.ctx).await?;
        // Flavor routing: an MPD body takes the DASH line —
        // the same driver loop and bookkeeping below, with a DASH
        // per-track source (expansion + the optional sidx fetch
        // inside run_track); the HLS line is unchanged.
        let dash = if let Ok(crate::m3u8::ManifestFlavor::Dash) =
            crate::m3u8::sniff(Some(&manifest_bytes), None, None)
        {
            Some(crate::mpd::parse_mpd(&manifest_bytes)?)
        } else {
            None
        };
        let playlist = if dash.is_none() {
            Some(parse_manifest(&manifest_bytes)?)
        } else {
            None
        };
        let (mut tracks, mut sources, norm_digest, kind) = match (&dash, &playlist) {
            (Some(mpd), _) => {
                let plan = match &self.cfg.dash_selection {
                    // A selector-resolved DASH choice names
                    // the representations by `@id` — the policy
                    // ladder cap steps aside (single selection
                    // source, the HLS `chosen` posture).
                    Some(selection) => crate::mpd::plan_dash_tracks_selected(
                        mpd,
                        manifest_url,
                        &self.cfg.track_set,
                        selection,
                    )?,
                    None => crate::mpd::plan_dash_tracks(
                        mpd,
                        manifest_url,
                        &self.cfg.track_set,
                        // The variant-policy semantics select the DASH
                        // representations (plan scope item 2): the
                        // config's `--media-variant-policy` threads
                        // here — highest/resolution/bandwidth apply to
                        // the primary ladder (see plan_dash_tracks).
                        &self.cfg.variant_policy,
                    )?,
                };
                (
                    plan.tracks.clone(),
                    plan.picks
                        .iter()
                        .map(|pick| TrackSource::Dash {
                            mpd,
                            pick: pick.clone(),
                            manifest_url,
                        })
                        .collect(),
                    crate::mpd::mpd_digest(mpd, manifest_url),
                    "dash",
                )
            }
            (None, Some(playlist)) => match playlist {
                Playlist::Master(master) => {
                    let planned = match &self.cfg.chosen {
                        Some(chosen) => {
                            // The selector's resolved choice: the
                            // named variant + the explicitly attached side
                            // renditions (deduped by URI against the
                            // policy-planned set).
                            let mut planned =
                                plan_track_set(master, &chosen.variant_uri, &self.cfg.track_set);
                            let mut idx = planned.len();
                            let mut sub = planned
                                .iter()
                                .filter(|t| t.kind == crate::trackset::TrackKind::Subtitle)
                                .count();
                            let mut aud = planned
                                .iter()
                                .filter(|t| t.kind == crate::trackset::TrackKind::Audio)
                                .count();
                            for att in &chosen.attached {
                                if planned.iter().any(|t| t.playlist_uri == att.uri) {
                                    continue;
                                }
                                let (kind, label) = match att.kind {
                                    "audio" => {
                                        let l = format!("x-a{aud}");
                                        aud += 1;
                                        (crate::trackset::TrackKind::Audio, l)
                                    }
                                    _ => {
                                        let l = format!("x-s{sub}");
                                        sub += 1;
                                        (crate::trackset::TrackKind::Subtitle, l)
                                    }
                                };
                                planned.push(PlannedTrack {
                                    track_idx: idx,
                                    label,
                                    kind,
                                    role: TrackRole::Sidecar,
                                    playlist_uri: att.uri.clone(),
                                    language: att.language.clone(),
                                });
                                idx += 1;
                            }
                            planned
                        }
                        None => {
                            let variant = select_variant(master, &self.cfg.variant_policy)?;
                            plan_track_set(master, &variant.uri, &self.cfg.track_set)
                        }
                    };
                    (
                        planned.clone(),
                        (0..planned.len()).map(|_| TrackSource::Hls).collect(),
                        m3u8::master_playlist_digest(master),
                        "hls",
                    )
                }
                Playlist::Media(_) => {
                    // Direct media-playlist entry: the single video track.
                    (
                        vec![PlannedTrack {
                            track_idx: 0,
                            label: "v".to_string(),
                            kind: crate::trackset::TrackKind::Video,
                            role: TrackRole::Required,
                            playlist_uri: manifest_url.to_string(),
                            language: None,
                        }],
                        vec![TrackSource::Hls],
                        match playlist {
                            Playlist::Media(m) => m3u8::media_playlist_digest(m),
                            Playlist::Master(_) => unreachable!(),
                        },
                        "hls",
                    )
                }
            },
            (None, None) => unreachable!("one flavor always parses"),
        };

        // Subtitle-language filter (the `--sub <lang>` face): planned
        // subtitle sidecars filter to the prefix match; no match = no
        // subtitle track (explicit preference, no silent fallback).
        // (DASH plans no text track in 0.3 — the retain is a no-op.)
        if let Some(want) = &self.cfg.subtitle_lang {
            let want = want.to_ascii_lowercase();
            let mut keep = Vec::new();
            for (track, source) in tracks.iter().zip(sources.iter()) {
                let retained = track.kind != crate::trackset::TrackKind::Subtitle
                    || track
                        .language
                        .as_deref()
                        .is_some_and(|l| l.to_ascii_lowercase().starts_with(&want));
                if retained {
                    keep.push((track.clone(), source.clone()));
                }
            }
            tracks = keep.iter().map(|(t, _)| t.clone()).collect();
            sources = keep.into_iter().map(|(_, s)| s).collect();
        }

        // 2. Staging admission: same-volume + 0700 create-new +
        // quota. The raw manifest is archived right away.
        let (staging_root, gid_dir) = match &self.cfg.staging_dir {
            Some(root) => (root.clone(), root.join(&self.gid)),
            None => {
                let root = self.cfg.output_dir.join(crate::staging::STAGING_DIR_NAME);
                let gid = staging_gid_dir(&self.cfg.output_dir, &self.gid);
                (root, gid)
            }
        };
        ensure_same_volume(&gid_dir, &self.cfg.output_dir)?;
        create_staging_dir(&gid_dir)?;
        let quota = StagingQuota::from_gib(self.cfg.staging_quota_gib);
        quota.admit(staging_usage_bytes(&staging_root))?;
        // The staged source manifest keeps its format's file
        // convention (source.m3u8 / source.mpd), not
        // the row's kind spelling.
        let source_ext = if kind == "dash" { "mpd" } else { "m3u8" };
        crate::staging::write_file(&source_manifest_path(&gid_dir, source_ext), &manifest_bytes)?;

        // 3. Parent row (FK anchor for track/segment rows).
        let config_json = serde_json::to_string(&serde_json::json!({
            "segment_concurrency": self.cfg.track_set.segment_concurrency,
            "subtitles": if self.cfg.track_set.subtitles == crate::options::SubtitleMode::Sidecar { "sidecar" } else { "none" },
            "audio_lang": self.cfg.track_set.audio_lang,
            "staging_quota_gib": self.cfg.staging_quota_gib,
            "allow_private_key_url": self.cfg.allow_private_key_url,
        }))
        .unwrap_or_default();
        ledger
            .ensure_task(&MediaTaskRecord {
                gid: self.gid.clone(),
                kind: kind.to_string(),
                manifest_url: manifest_url.to_string(),
                state: "downloading".to_string(),
                staging_dir: gid_dir.display().to_string(),
                output_path: self.cfg.output_dir.display().to_string(),
                manifest_norm_digest: norm_digest.into_bytes(),
                config_json,
            })
            .await?;

        // 3b. Task-wide key cache seed: key rows already in the DB are
        // never re-fetched across restarts (recovery face —
        // the restart happens with a fresh driver over the same
        // ledger; the rows land here before any track runs).
        let ledger_seed_table = KeyTable::from_rows(ledger.load_media_keys(&self.gid).await?);

        // 4. Watermark watchdog (30s cadence; violation flips the
        // flag the driver consumes). A VOD quota violation is a
        // **task error** (the graceful-stop form is
        // the LIVE-only branch) — it surfaces as `Err`
        // from `run` and can never be swallowed into a track state.
        // The RAII guard owns the sampler: any exit from
        // `run` (early `?`, outer cancel, normal return) aborts it.
        let violated = Arc::new(AtomicBool::new(false));
        let _watchdog = WatchdogGuard::spawn(
            staging_root.clone(),
            Arc::clone(&violated),
            quota,
            self.watchdog_observer.as_ref(),
        );
        let watermark_violation = |phase: &str| -> MediaError {
            let usage = staging_usage_bytes(&staging_root);
            MediaError::StagingQuotaExceeded(format!(
                "staging watermark: usage {usage} exceeds quota {} ({phase})",
                quota.limit_bytes
            ))
        };

        // 5. Tracks run sequentially (cross-track concurrency off by
        // default). The key table is
        // task-wide: seeded from the DB rows above (restart =
        // already-stored keys are never re-fetched) and grown by
        // each track's pre-expand; later tracks share the cache.
        let ssrf_policy = SsrfPolicy {
            allow_private: self.cfg.allow_private_key_url,
        };
        let resolver = self.resolver.clone().unwrap_or_else(default_resolver);
        // The in-track watermark probe: the (a)/(b)
        // drivers consume it at their segment boundaries — a
        // mid-track violation fails the track immediately (the
        // escalated task-level `Err` below follows at the boundary),
        // instead of after a whole forged-big track lands.
        let probe =
            crate::trackdl::WatermarkProbe::new(Arc::clone(&violated), quota, staging_root.clone());
        let mut track_cfg = self.cfg.fetch.clone();
        track_cfg.watermark = Some(probe.clone());
        let mut key_table = ledger_seed_table;
        let mut host_cache = HostVerdictCache::new();
        let mut results: Vec<(PlannedTrack, TrackState)> = Vec::new();
        let mut archives: Vec<(String, String)> = Vec::new();
        let base_url = taiji_http::reqwest::Url::parse(manifest_url)
            .map_err(|e| MediaError::Staging(format!("manifest url: {e}")))?;
        for (track_pos, planned) in tracks.iter().enumerate() {
            let source = sources.get(track_pos).cloned().unwrap_or(TrackSource::Hls);
            // Progress note: track start (with the resumed prefix, one
            // ledger read for both faces).
            if let Some(sink) = &self.cfg.progress {
                let resumed = ledger
                    .load_track(&self.gid, planned.track_idx)
                    .await
                    .ok()
                    .flatten();
                let (bytes, done, total) = match &resumed {
                    Some((t, segs)) => (
                        segs.iter().map(|s| s.seg_len).sum::<u64>(),
                        unpack_bitmap_prefix(&t.seg_bitmap),
                        t.seg_count.max(segs.len()),
                    ),
                    None => (0, 0, 0),
                };
                sink(MediaProgressNote {
                    label: planned.label.clone(),
                    kind: planned.kind.as_str(),
                    started: true,
                    delivered_bytes: bytes,
                    segments_done: done,
                    segments_total: total,
                });
            }
            // Mid-track watchdog sample (flag form).
            if violated.load(Ordering::Acquire) {
                return Err(watermark_violation("mid-track sample"));
            }
            match self
                .run_track(
                    planned,
                    source,
                    &base_url,
                    &gid_dir,
                    ledger,
                    &ssrf_policy,
                    resolver.as_ref(),
                    &mut key_table,
                    &mut host_cache,
                    &track_cfg,
                )
                .await
            {
                Ok((run, archive_file)) => {
                    archives.push((planned.label.clone(), archive_file.clone()));
                    // Ledger: track row + whole segment set — on BOTH
                    // outcomes (a failed track persists its delivered
                    // prefix so a retry resumes from the segment
                    // bitmap).
                    let track_row = TrackRecord {
                        track_idx: planned.track_idx,
                        kind: planned.kind.as_str().to_string(),
                        playlist_uri: planned.playlist_uri.clone(),
                        local_name: archive_file,
                        init_files: run.init_files.clone(),
                        seg_bitmap: run.seg_bitmap.clone(),
                        seg_count: run.segments.len(),
                    };
                    ledger
                        .save_track(&self.gid, &track_row, &run.segments)
                        .await?;
                    // Progress note: track finish (delivered bytes +
                    // segment counts from the persisted rows).
                    if let Some(sink) = &self.cfg.progress {
                        sink(MediaProgressNote {
                            label: planned.label.clone(),
                            kind: planned.kind.as_str(),
                            started: false,
                            delivered_bytes: run.segments.iter().map(|s| s.seg_len).sum::<u64>(),
                            segments_done: unpack_bitmap_prefix(&run.seg_bitmap),
                            segments_total: run.segments.len(),
                        });
                    }
                    let state = match &run.error {
                        None => TrackState::Done,
                        Some(text) => {
                            let text = redact(text);
                            if planned.role == TrackRole::Required {
                                TrackState::Failed(text)
                            } else {
                                TrackState::Degraded(text)
                            }
                        }
                    };
                    results.push((planned.clone(), state));
                }
                Err(e) => {
                    // Staging/assembly-level failure: no run result to
                    // persist (nothing landed on disk this round).
                    let text = redact(&e.to_string());
                    let state = if planned.role == TrackRole::Required {
                        TrackState::Failed(text)
                    } else {
                        TrackState::Degraded(text)
                    };
                    results.push((planned.clone(), state));
                }
            }
            // In-track escalation: a violation the track
            // drivers caught mid-track (segment-boundary probes)
            // surfaces as the task-level watermark error here — the
            // same task-error posture as the boundary recheck below,
            // reached mid-track instead of after a whole track lands.
            if probe.violated_now() {
                return Err(watermark_violation("in-track watermark"));
            }
            // Deterministic boundary recheck: a track completing between
            // watchdog samples still faces the quota at its boundary —
            // the completed track's ledger row is already durable, so
            // the error is the honest task state and the prefix
            // resumes.
            if quota.check(staging_usage_bytes(&staging_root), 0).is_err() {
                return Err(watermark_violation("track boundary"));
            }
        }
        // In-flight final sample: a violation raised while the last
        // track ran surfaces here (the loop is past its pre-check).
        if violated.load(Ordering::Acquire) {
            return Err(watermark_violation("final sample"));
        }

        let verdict = track_set_verdict(&results);
        Ok(MediaRunReport {
            verdict,
            tracks: results,
            staging_dir: gid_dir,
            archives,
        })
    }

    /// One track: prepare its playlist (the HLS line fetches +
    /// parses the playlist URI; the DASH line expands the
    /// representation — [`crate::mpd`], fetching only a deferred
    /// sidx indexRange), walk the SSRF line over its segment/init
    /// URLs, pre-expand its keys (HLS: task cache + DB rows + fetch,
    /// then persist + id load-back; DASH: plaintext plan — DRM is
    /// refused at parse), build the crypto plan, resume from the
    /// ledger, drive the (a)/(b) layer with decrypt-as-consume.
    /// Returns the run result + archive file name.
    #[allow(clippy::too_many_arguments)]
    async fn run_track(
        &self,
        planned: &PlannedTrack,
        source: TrackSource<'_>,
        base_url: &taiji_http::reqwest::Url,
        gid_dir: &std::path::Path,
        ledger: &dyn MediaLedger,
        ssrf_policy: &SsrfPolicy,
        resolver: &dyn SsrfResolver,
        key_table: &mut KeyTable,
        host_cache: &mut HostVerdictCache,
        track_cfg: &TrackFetchConfig,
    ) -> Result<(TrackRunResult, String), MediaError> {
        let (media, track_base, crypto) = match source {
            TrackSource::Hls => {
                let (m, c, t) = self
                    .prepare_hls_track(
                        planned,
                        base_url,
                        ledger,
                        ssrf_policy,
                        resolver,
                        key_table,
                        host_cache,
                    )
                    .await?;
                (m, c, t)
            }
            TrackSource::Dash {
                mpd,
                pick,
                manifest_url,
            } => {
                let (m, t) = self
                    .prepare_dash_track(mpd, &pick, manifest_url, ssrf_policy, resolver, host_cache)
                    .await?;
                // 0.3 DASH keys = none: ContentProtection was refused at
                // parse; the crypto plan is plaintext by construction.
                let crypto = TrackCrypto::plain(m.segments.len(), m.init_sections.len());
                (m, t, crypto)
            }
        };
        self.drive_track(
            planned,
            &media,
            &track_base,
            crypto,
            ssrf_policy,
            resolver,
            host_cache,
            track_cfg,
            ledger,
            gid_dir,
        )
        .await
    }

    /// The HLS preparation half: playlist fetch (+ the
    /// SSRF check before the GET) + parse + key pre-expand.
    #[allow(clippy::too_many_arguments)]
    async fn prepare_hls_track(
        &self,
        planned: &PlannedTrack,
        base_url: &taiji_http::reqwest::Url,
        ledger: &dyn MediaLedger,
        ssrf_policy: &SsrfPolicy,
        resolver: &dyn SsrfResolver,
        key_table: &mut KeyTable,
        host_cache: &mut HostVerdictCache,
    ) -> Result<
        (
            crate::m3u8::MediaPlaylist,
            taiji_http::reqwest::Url,
            TrackCrypto,
        ),
        MediaError,
    > {
        let url = resolve_uri(base_url, &planned.playlist_uri)?;
        let track_base = taiji_http::reqwest::Url::parse(url.as_str())
            .map_err(|e| MediaError::Staging(format!("track url: {e}")))?;
        // SSRF line over the playlist fetch itself: the
        // planned URI is second-order manifest content (a forged
        // master's EXT-X-STREAM-INF/EXT-X-MEDIA target, or a
        // selector-resolved primary) — exactly the ssrf module's
        // declared threat ("a forged manifest driving intranet
        // fetches"). Pre-fix this GET went out unchecked; the
        // segment/init/key faces below were already covered.
        check_uri(url.as_str(), ssrf_policy, resolver, host_cache).await?;
        // Pinned transport: the playlist GET rides the pinned client (the
        // judgment's resolved address is pinned onto the transport —
        // the connection cannot land on a rebinding answer).
        let client = self.fetch_client(host_cache)?;
        let bytes = http_get_bytes(&client, url.as_str(), &self.ctx).await?;
        let media = match parse_manifest(&bytes)? {
            Playlist::Media(m) => m,
            Playlist::Master(_) => {
                return Err(MediaError::ManifestParse(
                    "track playlist classified as master".to_string(),
                ));
            }
        };
        let resolved =
            |uri: &str| resolve_uri(&track_base, uri).unwrap_or_else(|_| uri.to_string());

        // Key pre-expand (per the product spec): distinct KEY tags (segments +
        // inits) → SSRF check → data:/http fetch → task table; then
        // persist + load back the stable row ids (media_segment.key_id
        // references).
        let specs = collect_key_specs(&media, &resolved)?;
        let client = self.fetch_client(host_cache)?;
        expand_track_keys(
            &client,
            &self.ctx,
            &specs,
            key_table,
            ssrf_policy,
            resolver,
            host_cache,
            &self.cfg.fetch,
        )
        .await?;
        ledger
            .upsert_media_keys(&self.gid, key_table.records())
            .await?;
        let rows = ledger.load_media_keys(&self.gid).await?;
        key_table.adopt_ids(&rows);
        let crypto = build_track_crypto(&media, &resolved, key_table)?;
        Ok((media, track_base, crypto))
    }

    /// The DASH preparation half: expand the planned
    /// representation onto the synthetic HLS track model; the
    /// deferred sidx form SSRF-checks the representation resource,
    /// fetches its indexRange and materializes the byte-range
    /// segments ([`crate::mpd::materialize_sidx`] — nested sidx is
    /// `sidx_unsupported` here). The track base is the manifest URL
    /// (the synthetic playlist carries absolute URIs; the join is the
    /// identity).
    async fn prepare_dash_track(
        &self,
        mpd: &crate::mpd::Mpd,
        pick: &crate::mpd::DashPick,
        manifest_url: &str,
        ssrf_policy: &SsrfPolicy,
        resolver: &dyn SsrfResolver,
        host_cache: &mut HostVerdictCache,
    ) -> Result<(crate::m3u8::MediaPlaylist, taiji_http::reqwest::Url), MediaError> {
        let track_base = taiji_http::reqwest::Url::parse(manifest_url)
            .map_err(|e| MediaError::Staging(format!("manifest url: {e}")))?;
        let expanded = crate::mpd::expand_representation(mpd, manifest_url, pick)?;
        let product = match expanded {
            crate::mpd::Expanded::Ready(track) => track,
            crate::mpd::Expanded::DeferredSidx(plan) => {
                // SSRF line over the representation resource (the
                // second-order face: the MPD named it).
                check_uri(&plan.base, ssrf_policy, resolver, host_cache).await?;
                let length = plan
                    .index_range
                    .1
                    .checked_add(1)
                    .and_then(|e| e.checked_sub(plan.index_range.0))
                    .ok_or_else(|| {
                        MediaError::ManifestParse("indexRange length overflow".to_string())
                    })?;
                let client = self.fetch_client(host_cache)?;
                let fetched = crate::trackdl::fetch_whole_or_range(
                    &client,
                    &self.ctx,
                    &plan.base,
                    Some(crate::m3u8::ByteRange {
                        length,
                        offset: plan.index_range.0,
                        offset_omitted: false,
                    }),
                )
                .await?;
                crate::mpd::materialize_sidx(&plan, &fetched)?
            }
        };
        Ok((product.playlist, track_base))
    }

    /// The shared per-track drive (the zero-private-implementation
    /// face): the SSRF walk over every second-order segment/init URL,
    /// the (a)/(b) layer dispatch ([`classify_track`] — the layer
    /// judgment of record for DASH too), the resume face and both
    /// layer drivers. `track_base` resolves relative URIs; a DASH
    /// synthetic playlist carries absolute URIs, so the base is the
    /// manifest URL and the join is the identity.
    #[expect(
        clippy::too_many_arguments,
        reason = "the track-driver face carries the whole per-track surface explicitly (base precedent: launch_worker)"
    )]
    async fn drive_track(
        &self,
        planned: &PlannedTrack,
        media: &crate::m3u8::MediaPlaylist,
        track_base: &taiji_http::reqwest::Url,
        crypto: TrackCrypto,
        ssrf_policy: &SsrfPolicy,
        resolver: &dyn SsrfResolver,
        host_cache: &mut HostVerdictCache,
        track_cfg: &TrackFetchConfig,
        ledger: &dyn MediaLedger,
        gid_dir: &std::path::Path,
    ) -> Result<(TrackRunResult, String), MediaError> {
        let resolved = |uri: &str| resolve_uri(track_base, uri).unwrap_or_else(|_| uri.to_string());

        // SSRF line over the second-order URLs of this track: every
        // media-segment URI and every init-section URI (the per-host
        // verdict cache dedups resolution — a forged
        // manifest must not drive intranet fetches).
        for seg in &media.segments {
            check_uri(&resolved(&seg.uri), ssrf_policy, resolver, host_cache).await?;
        }
        for init in &media.init_sections {
            check_uri(&resolved(&init.uri), ssrf_policy, resolver, host_cache).await?;
        }

        let ext = guess_archive_ext(media);
        let archive_file = archive_name(&planned.label, ext);
        let archive_path = gid_dir.join(&archive_file);

        // Resume face: ledger rows back into a TrackRunResult.
        let resume = match ledger.load_track(&self.gid, planned.track_idx).await? {
            Some((track, segments)) if track.seg_count == segments.len() => Some(TrackRunResult {
                archive_len: segments.iter().map(|s| s.seg_len).sum(),
                segments,
                seg_bitmap: track.seg_bitmap,
                init_files: track.init_files,
                error: None,
            }),
            _ => None,
        };

        let run = match classify_track(media) {
            TrackLayer::KnownLength => {
                let layout = layout_known_length(media)?;
                let client = self.fetch_client(host_cache)?;
                download_known_length_track(
                    &self.gid,
                    &client,
                    &self.ctx,
                    media,
                    &layout,
                    &resolved,
                    &crypto,
                    &archive_path,
                    gid_dir,
                    &planned.label,
                    track_cfg,
                    resume,
                )
                .await?
            }
            TrackLayer::UnknownLength => {
                let client = self.fetch_client(host_cache)?;
                download_unknown_length_track(
                    &client,
                    &self.ctx,
                    media,
                    &resolved,
                    &crypto,
                    &archive_path,
                    gid_dir,
                    &planned.label,
                    track_cfg,
                    resume,
                )
                .await?
            }
        };
        Ok((run, archive_file))
    }
}

/// Minimal redact (query strings stripped) for failure texts carried
/// in track states (the full unified redact face belongs to the RPC
/// boundary; track payloads keep to the same shape).
fn redact(text: &str) -> String {
    // Strip anything that looks like a query on a URL inside the text.
    let mut out = String::with_capacity(text.len());
    for line in text.split_whitespace() {
        if line.contains("://") {
            out.push_str(crate::m3u8::strip_query(line));
        } else {
            out.push_str(line);
        }
        out.push(' ');
    }
    out.trim_end().to_string()
}

/// RFC 3986 join against a base URL.
pub fn resolve_uri(base: &taiji_http::reqwest::Url, uri: &str) -> Result<String, MediaError> {
    base.join(uri)
        .map(|u| u.to_string())
        .map_err(|e| MediaError::ManifestParse(format!("resolve {uri:?} against base: {e}")))
}

/// Fetch a manifest-sized body (cap = the parser's manifest bound; the
/// 16MiB manifest red line). Public so the session-side probe /
/// classification faces fetch through the same bound.
pub async fn http_get_bytes(
    client: &HttpClient,
    url: &str,
    ctx: &RequestCtx,
) -> Result<Vec<u8>, MediaError> {
    let followed = client
        .get(url, ctx)
        .await
        .map_err(|e| MediaError::Staging(format!("fetch manifest: {e}")))?;
    let status = followed.response.status();
    if !status.is_success() {
        return Err(MediaError::Staging(format!(
            "fetch manifest {url}: HTTP {}",
            status.as_u16()
        )));
    }
    let mut body = Vec::new();
    let mut resp = followed.response;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| MediaError::Staging(format!("manifest read: {e}")))?
    {
        if body.len() + chunk.len() > m3u8::MAX_MANIFEST_BYTES {
            return Err(MediaError::ManifestTooLarge(format!(
                "manifest over {} bytes",
                m3u8::MAX_MANIFEST_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

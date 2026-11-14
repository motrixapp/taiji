//! The media task pipeline: the
//! session's third task family's Resolving → Downloading →
//! Processing → Verifying → Done orchestration across the
//! driver/pipeline faces, plus the probe action face's pure half.
//!
//! Layering: everything media-semantic lives in `taiji-media`; this
//! module assembles and drives it with the session's persistence
//! ([`StoreMediaLedger`] — the `MediaLedger` trait over the single
//! `PersistWriter`), cancellation (pause/remove/shutdown through the
//! per-task token + the pause flag), phase memory (§3.2), the
//! `media_task`/`media_format` row lifecycle, and the phaseChanged /
//! warning event emission (the bypass design — the sink is injected,
//! the actor publishes to the media bus, the CLI logs).
//!
//! Phase semantics (§3.2):
//! * Resolving — fetch + classify (§4 sniff order) + format tree +
//! selector + template expansion + **forced sanitization** (§10 #1);
//! a **direct media file** classification converts to the existing
//! HTTP task family (zero new surface — the actor arm rebuilds
//! a Job::Http from the returned URL); `not_media` is the explicit
//! error;
//! * Downloading — the media download driver with its SSRF/keys/
//! rotation red lines and the track-resume ledger;
//! * Processing/Verifying — the synthesis pipeline (native +
//! ffmpeg fallback, box probe + ffprobe dual-run); **pause phase
//! memory**: a pause here cancels the idempotent synthesis and
//! persists `paused` + `phase_detail`; unpause re-runs (Processing
//! is restart-safe by construction — the download step re-verifies
//! the all-complete track set and skips);
//! * Done — the sanitized product is already at its final path (the
//! synthesis verified-rename); the success cleanup face removes the
//! staging tree.
//!
//! Cookie posture (the structured-cookie design): the structured direct
//! pass is accepted at addMedia/setTaskCookies and consumed at the
//! transport face (the request context's cookie pairs —
//! manifest/segment/key fetches all carry it); persistence rides the
//! unified `task_cookie` table (task_kind=media) — cookies land at
//! creation, the activation seed reads the table back, restarts replay
//! from the rows, and the **full terminal set** (done and error)
//! clears them (the actor's close-out; the error clear raises the
//! `taiji.task.cookiesClearedOnError` alert). The pipeline itself
//! keeps consuming `cfg.cookies` pairs only — the store faces stay in
//! the actor/store layers.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use taiji_http::client::{ClientConfig, HttpClient};
use taiji_media::ffmpegmux::FfmpegRuntime;
use taiji_media::mediadl::http_get_bytes;
use taiji_media::options::{FfmpegPathSpec, MuxerSpec, OutputFormat, SubtitleMode};
use taiji_media::ssrf::SsrfResolver;
use taiji_media::staging::{
    STAGING_DIR_NAME, StagingQuota, create_staging_dir, ensure_same_volume, staging_gid_dir,
    staging_usage_bytes,
};
use taiji_media::trackdl::MediaLedger;
use taiji_media::trackset::{TrackSetVerdict, TrackState};
use taiji_media::{
    AttachedRendition, ChosenVariant, EntryKind, FormatTree, MediaDownload, MediaDownloadConfig,
    MediaError, MediaInfoRecord, MediaPhase, MediaProgressNote, Playlist, Selection,
    TemplateContext, archive_url_digest, classify_entry, expand_template, parse_manifest,
    parse_selector, probe_token, redact_payload_text, render_info_json, resolve_selection,
    sanitize_output_name, snapshot_url_key, synth,
};
use taiji_segment::traits::RequestCtx;

// Re-exports: the RPC reply payloads carry the format-tree types; the
// session module is their public path (taiji-rpc does not depend on
// taiji-media directly).
pub use taiji_media::FormatNode;

/// Probe snapshot TTL (§4: 10 minutes; expired tokens answer
/// `probe_expired`).
pub const PROBE_TTL: Duration = Duration::from_secs(600);

/// Probe global in-flight cap (§10 #7: 2 concurrent probes process-
/// wide; a third is refused while two are live).
pub const PROBE_INFLIGHT_CAP: usize = 2;

/// Probe per-origin rate limit (§10 #7 per-origin rate limiting: one admitted
/// probe per origin per second — a client hammering one origin is
/// throttled before the fetch face, distinct origins are not).
pub const PROBE_ORIGIN_INTERVAL: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// live state (the tellStatus media sub-dictionary data source)
// ---------------------------------------------------------------------------

/// One track's live rollup.
#[derive(Debug, Clone)]
pub struct MediaTrackLive {
    pub label: String,
    pub kind: &'static str,
    /// Track liveness (the kernel enum; wire words rendered by the rpc
    /// adapter's word table).
    pub state: super::view::MediaTrackState,
    pub segments_done: usize,
    pub segments_total: usize,
    pub bytes: u64,
}

/// The media task's live state (the `media` sub-dictionary source;
/// a small mutex — reads never span await, writes come from the
/// driver task and phase transitions).
#[derive(Debug, Default)]
pub struct MediaLiveState {
    pub phase: MediaPhase,
    pub phase_detail: Option<String>,
    pub tracks: Vec<MediaTrackLive>,
    pub bytes_done: u64,
    pub staging_dir: String,
    pub output_name: Option<String>,
    pub selector: Option<String>,
    pub variant: Option<String>,
    pub kind: &'static str,
    pub manifest_url: String,
    /// Rough whole-task rate (bytes/sec, updated at progress notes —
    /// the honest rollup face for getGlobalStat aggregation).
    pub rate: u64,
    rate_base: Option<(Instant, u64)>,
}

/// Shared live handle (the actor's RunningTask face).
#[derive(Debug, Default)]
pub struct MediaLive(pub Arc<StdMutex<MediaLiveState>>);

impl MediaLive {
    pub fn new() -> Self {
        Self(Arc::new(StdMutex::new(MediaLiveState {
            phase: MediaPhase::Queued,
            ..MediaLiveState::default()
        })))
    }

    pub fn share(&self) -> Arc<StdMutex<MediaLiveState>> {
        Arc::clone(&self.0)
    }
}

// ---------------------------------------------------------------------------
// event sink
// ---------------------------------------------------------------------------

/// A phase/warning note from the pipeline (the publish face is
/// injected: the actor routes to the media event bus; the CLI logs).
#[derive(Debug, Clone)]
pub enum MediaNote {
    Phase(MediaPhase),
    /// Pause phase memory (the remembered live phase).
    PausedWithMemory(MediaPhase),
    Warning {
        code: &'static str,
        message: String,
    },
}

/// The sink type (sync — publishing to a broadcast channel never
/// blocks; slow subscribers lag per the bus policy).
pub type MediaNoteSink = Arc<dyn Fn(&MediaNote) + Send + Sync>;

// ---------------------------------------------------------------------------
// terminal outcome
// ---------------------------------------------------------------------------

/// The pipeline's terminal outcome (the actor's TaskNotice payload).
#[derive(Debug)]
pub enum MediaEnd {
    /// Done: the verified product is at its final path (bytes = the
    /// product size; the staging tree is already cleaned).
    Done { bytes: u64 },
    /// Failed: the canonical `taiji.*`/`taiji.media.*` code + the
    /// redacted message (persisted to the row's error columns).
    Failed { code: String, message: String },
    /// Paused (the pause face): `memory` = the interrupted live phase
    /// when the §3.2 memory applies (Processing/Verifying); None = a
    /// Downloading-phase pause (the bitmaps carry the resume state).
    Paused { memory: Option<MediaPhase> },
    /// Cancelled without pause intent (shutdown / remove): the row
    /// keeps its last phase — the restart bootstrap re-enters by
    /// phase (§3.2), a remove deletes the row. The actor's teardown
    /// classification decides the result-table fate.
    Cancelled { memory: Option<MediaPhase> },
    /// Entry classification says direct media file: convert to the
    /// existing HTTP task family (the actor arm rebuilds a Job::Http
    /// with the same GID; zero new surface).
    DirectLink,
    /// The download-archive duplicate skip: one of the
    /// two checkpoints hit — **zero segment traffic**, the done row +
    /// the `taiji.media.archive_duplicate` warning already emitted;
    /// `output_name` = the archived product name (the skip row's).
    ArchiveHit { output_name: String },
}

// ---------------------------------------------------------------------------
// synthesis gate
// ---------------------------------------------------------------------------

/// The gate arrival notice face (the pipeline → actor TaskNotice link
/// shape fixed by the card): a boxed future per call so the actor-side
/// constructor can clone its notice sender into the closure without
/// this module naming the actor's private notice type. One call per
/// task run — fired at the Downloading → Processing boundary, before
/// Processing truly begins.
pub type SynthesisGateNotice =
    Arc<dyn Fn() -> futures::future::BoxFuture<'static, ()> + Send + Sync>;

/// The synthesis gate's permit end (the actor-side half of the pair):
/// pump_all's synthesis segment holds these and fires one per
/// budget-gated promotion (`proc_wait → processing`). A grant into a
/// dropped receiver (the driver gone — remove raced the promotion) is
/// a silent no-op (the oneshot send's error is the driver's absence).
pub struct SynthesisGatePermit {
    tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl SynthesisGatePermit {
    /// Fire the permit (consumes the end — one grant per gate).
    pub fn grant(mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

/// The synthesis gate's waiting end (rides [`MediaRunConfig::gate`]
/// into the driver; shareable because `MediaRunConfig` is `Clone` —
/// the panic-gate's config clone never awaits, the first take wins).
/// The channel is a oneshot: the actor's promotion grants once, the
/// driver wakes once. Zero new polling faces — the driver
/// hangs on the receive, the actor fires on its own pump ticks.
#[derive(Clone)]
pub struct SynthesisGate {
    arrive: SynthesisGateNotice,
    wait: Arc<StdMutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
}

impl std::fmt::Debug for SynthesisGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynthesisGate").finish_non_exhaustive()
    }
}

impl SynthesisGate {
    /// Pair up (the actor-side construction face, the
    /// persist/ffmpeg runtime-injection precedent): `notice` enqueues
    /// the arrival TaskNotice (the actor releases the download slot
    /// and parks the task into proc_wait); the returned permit end
    /// goes into the actor's per-gid gate map for the budget-gated
    /// promotions. `None` = no gate (the bare-run shape: the boundary
    /// passes straight through, zero behavior change).
    pub fn pair(notice: SynthesisGateNotice) -> (SynthesisGatePermit, SynthesisGate) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (
            SynthesisGatePermit { tx: Some(tx) },
            SynthesisGate {
                arrive: notice,
                wait: Arc::new(StdMutex::new(Some(rx))),
            },
        )
    }

    /// Fire the arrival notice (one call at the boundary; the await
    /// spans the actor-side enqueue — the notice channel is an mpsc,
    /// a full channel waits for the actor to drain instead of
    /// dropping the gate).
    pub(crate) async fn arrive(&self) {
        (self.arrive)().await;
    }

    /// Await the permit. `Ok(())` = granted (Processing may begin);
    /// `Err` = the permit end dropped without a grant (the actor died
    /// mid-park — the callers race this against the task token, so a
    /// session teardown resolves through the cancel arm, never this
    /// error alone).
    pub(crate) async fn acquire(&self) -> Result<(), tokio::sync::oneshot::error::RecvError> {
        let rx = self.wait.lock().ok().and_then(|mut w| w.take());
        match rx {
            Some(rx) => rx.await,
            // The receiver was already taken (a defensive shape that
            // cannot occur in the single-acquire pipeline): treat as
            // granted rather than wedge the task.
            None => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// run configuration
// ---------------------------------------------------------------------------

/// Everything the pipeline needs (the actor's MediaJob and the CLI
/// face assemble one of these).
#[derive(Clone)]
pub struct MediaRunConfig {
    /// 16-hex GID.
    pub gid: String,
    /// The entry URL (manifest or direct file — classification
    /// decides).
    pub url: String,
    /// Output directory (absolute).
    pub output_dir: PathBuf,
    /// Explicit `--out` base name (pre-template; None = derived from
    /// the URL).
    pub out: Option<String>,
    /// Selector expression (None = `best`).
    pub selector: Option<String>,
    /// The `--media-variant-policy` value (the original media semantics,
    /// parsed at the option face): selects the DASH representations with
    /// equivalent effect (a scope item of the DASH line — the primary
    /// ladder caps under it; see `taiji_media::mpd::plan_dash_tracks`).
    /// Since the unified three-layer selector landed it also resolves
    /// over DASH trees: a genuine selector expression threads
    /// `MediaDownloadConfig::dash_selection` and this policy stands
    /// down for the primary pick (the projection spellings
    /// `best`/`res<=<H>` and the no-selector form still ride this
    /// field — see the resolution ruling in `run_media_task`). The
    /// HLS face is unchanged: the selector projection resolves over
    /// the HLS tree and the chosen variant rides that path (this
    /// field is the driver's no-chosen fallback there).
    pub variant_policy: taiji_media::VariantPolicy,
    /// `--media-audio-lang` (None = policy chain unchanged).
    pub audio_lang: Option<String>,
    /// `--media-subtitles`.
    pub subtitles: SubtitleMode,
    /// Subtitle-language preference (the `--sub <lang>` face): planned
    /// subtitle sidecars filter to the RFC 5646 prefix match.
    pub subtitle_lang: Option<String>,
    /// Output template (None = `{id}.{ext}`).
    pub template: Option<String>,
    /// `--no-meta` (metadata embedding face off; 0.3's value domain
    /// is manifest-only anyway — the flag rides for the bridge era).
    pub no_metadata: bool,
    /// `--media-archive` (default off): the Done
    /// close-out records the task's fingerprints into media_archive
    /// and the two duplicate checkpoints run (① the normalized URL
    /// digest at activation — zero outbound; ② the manifest digest in
    /// Resolving — the same-content/switched-CDN face). A hit
    /// terminalizes the task Done-shaped with the
    /// `taiji.media.archive_duplicate` warning (not
    /// an Error — a fast skip close-out).
    pub archive: bool,
    /// `--media-info-json` (default off): write the
    /// whitelisted + redacted `<product>.info.json` sidecar at the
    /// Done close-out (§10 #5: the fixed field record — no map
    /// passthrough, no http_headers/cookies/token, every string value
    /// through the shared payload redact; orthogonal to `no_metadata`
    /// — the embed face is no-meta's, the export face is this one's).
    pub info_json: bool,
    /// Structured cookie pass: name=value pairs applied to
    /// every fetch of this task (manifest/segments/keys).
    pub cookies: Vec<(String, String)>,
    /// `--media-allow-private-key-url` (the widened private-key scope).
    pub allow_private_key_url: bool,
    /// `--media-segment-concurrency`.
    pub segment_concurrency: u32,
    /// `--media-staging-quota-gib`.
    pub staging_quota_gib: u64,
    /// `--media-staging-dir` override (None = `<output_dir>/.taiji-b`).
    pub staging_dir: Option<PathBuf>,
    /// `--media-ffmpeg-path`.
    pub ffmpeg_path: FfmpegPathSpec,
    /// `--media-muxer`.
    pub muxer: MuxerSpec,
    /// `--media-output-format`.
    pub output_format: OutputFormat,
    /// The startup-restore row (resume by phase; None on the add
    /// path).
    pub restore: Option<taiji_store::persist::MediaTaskRow>,
    /// A pre-resolved probe snapshot (addMedia's probe-token face:
    /// the classification + format tree are **taken from the server
    /// cache**, never re-fetched or client-supplied). 0.5 bridge
    /// seam (a bridge note, not implemented here): a bridge-produced
    /// tree rides this same snapshot/token path — server-side
    /// `store`/`consume` cache, never a client-supplied blob (§4's
    /// anti-forgery posture holds for the bridge era; one token
    /// face, one snapshot lifecycle).
    pub probe_snapshot: Option<ProbeSnapshot>,
    /// Persistence injection (None = nothing persisted — the CLI
    /// one-shot shape still passes a writer; pure tests run without).
    pub persist: Option<taiji_store::persist::PersistHandle>,
    /// ffmpeg runtime override (tests / an already-discovered session
    /// cache; None = discover at start per `ffmpeg_path`).
    pub ffmpeg: Option<FfmpegRuntime>,
    /// SSRF resolver injection (tests; None = the production shared
    /// resolver).
    pub resolver: Option<Arc<dyn SsrfResolver>>,
    /// The resolved format tree from a previous run (recovery re-run
    /// seed; the media_format row's product).
    pub recovered_tree: Option<FormatTree>,
    /// The synthesis gate: `Some` on the
    /// session-actor injection face (the driver parks at the
    /// Downloading → Processing boundary awaiting the budget-gated
    /// permit; the arrival notice releases the download slot), `None`
    /// on the bare-run shape (the boundary passes straight through —
    /// zero behavior change). Runtime-injected like `persist`/`ffmpeg`
    /// (spawn_media_driver), never parsed from options.
    pub gate: Option<SynthesisGate>,
}

impl MediaRunConfig {
    /// The task's staging directory (the original layout).
    pub fn staging_gid_dir(&self) -> PathBuf {
        match &self.staging_dir {
            Some(root) => root.join(&self.gid),
            None => staging_gid_dir(&self.output_dir, &self.gid),
        }
    }

    /// The staging root (the quota/GC face's scan scope).
    pub fn staging_root(&self) -> PathBuf {
        match &self.staging_dir {
            Some(root) => root.clone(),
            None => self.output_dir.join(STAGING_DIR_NAME),
        }
    }
}

// ---------------------------------------------------------------------------
// persistence adapter
// ---------------------------------------------------------------------------

/// The `MediaLedger` trait over the session's single `PersistWriter`
/// (the same adapter shape as the taiji-media e2e tests; the row
/// mapping is the store's, no interpretation).
#[derive(Clone)]
pub struct StoreMediaLedger {
    handle: taiji_store::persist::PersistHandle,
}

impl StoreMediaLedger {
    pub fn new(handle: taiji_store::persist::PersistHandle) -> Self {
        Self { handle }
    }
}

fn ledger_err(e: taiji_store::error::StoreError) -> MediaError {
    MediaError::Staging(format!("ledger write failed: {e}"))
}

impl MediaLedger for StoreMediaLedger {
    fn ensure_task<'a>(
        &'a self,
        row: &'a taiji_media::trackdl::MediaTaskRecord,
    ) -> futures::future::BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            // The parent-row write is an **ensure**, not an overwrite of
            // the orchestration's snapshot columns: the pipeline wrote
            // the full row first (state/selector_json/output_name/
            // phase_detail/config_json — the §8 recovery replay
            // payload); the driver only anchors the FK facts (kind/
            // manifest/staging/digest/state). Merging keeps the
            // existing snapshot columns when the row is present — the
            // driver's minimal config_json and NULL selectors must
            // never clobber them (a restart would silently lose the
            // task's options).
            let mut store_row = taiji_store::persist::MediaTaskRow {
                gid: row.gid.clone(),
                kind: row.kind.clone(),
                manifest_url: row.manifest_url.clone(),
                state: row.state.clone(),
                phase_detail_json: None,
                variant_json: None,
                selector_json: None,
                output_name: None,
                bridge_json: None,
                staging_dir: row.staging_dir.clone(),
                output_path: row.output_path.clone(),
                manifest_norm_digest: row.manifest_norm_digest.clone(),
                total_done: 0,
                config_json: row.config_json.clone(),
                error_code: None,
                error_msg: None,
                created_at: 0,
                updated_at: 0,
            };
            match self.handle.load_media_task(&row.gid).await {
                Ok(Some(existing)) => {
                    store_row.phase_detail_json = existing.phase_detail_json;
                    store_row.variant_json = existing.variant_json;
                    store_row.selector_json = existing.selector_json;
                    store_row.output_name = existing.output_name;
                    store_row.bridge_json = existing.bridge_json;
                    store_row.total_done = existing.total_done;
                    store_row.config_json = existing.config_json;
                    store_row.error_code = existing.error_code;
                    store_row.error_msg = existing.error_msg;
                    store_row.created_at = existing.created_at;
                    store_row.updated_at = existing.updated_at;
                }
                // A read failure is not a reason to refuse the anchor
                // write (the FK facts must exist before track rows) —
                // degrade to the plain upsert and warn.
                Err(e) => {
                    tracing::warn!(target: "taiji::core::session", gid = %row.gid, %e,
                        "media parent-row read back failed; ensure_task degrades to the \
                         plain upsert");
                }
                Ok(None) => {}
            }
            self.handle
                .upsert_media_task(store_row)
                .await
                .map_err(ledger_err)?;
            Ok(())
        })
    }

    fn save_track<'a>(
        &'a self,
        gid: &'a str,
        track: &'a taiji_media::trackdl::TrackRecord,
        segments: &'a [taiji_media::trackdl::SegmentRecord],
    ) -> futures::future::BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            let store_track = taiji_store::persist::MediaTrackRow {
                gid: gid.to_string(),
                track_idx: track.track_idx as i64,
                kind: track.kind.clone(),
                playlist_uri: track.playlist_uri.clone(),
                local_name: track.local_name.clone(),
                init_files_json: Some(
                    serde_json::to_string(&track.init_files).unwrap_or_else(|_| "[]".into()),
                ),
                seg_bitmap: Some(track.seg_bitmap.clone()),
                seg_count: Some(track.seg_count as i64),
            };
            let store_segments: Vec<taiji_store::persist::MediaSegmentRow> = segments
                .iter()
                .map(|s| taiji_store::persist::MediaSegmentRow {
                    gid: gid.to_string(),
                    track_idx: track.track_idx as i64,
                    seg_idx: s.seg_idx as i64,
                    media_sequence: Some(s.media_sequence as i64),
                    uri: s.uri.clone(),
                    byte_range: s.byte_range.clone(),
                    key_id: s.key_id,
                    seg_len: s.seg_len as i64,
                    duration_ms: Some(s.duration_ms as i64),
                    validator_digest: Some(s.validator_digest.clone()),
                    map_idx: s.map.map(|m| m as i64),
                })
                .collect();
            self.handle
                .replace_media_track(store_track, store_segments)
                .await
                .map_err(ledger_err)?;
            Ok(())
        })
    }

    fn load_track<'a>(
        &'a self,
        gid: &'a str,
        track_idx: usize,
    ) -> futures::future::BoxFuture<
        'a,
        Result<
            Option<(
                taiji_media::trackdl::TrackRecord,
                Vec<taiji_media::trackdl::SegmentRecord>,
            )>,
            MediaError,
        >,
    > {
        Box::pin(async move {
            let all = self
                .handle
                .load_media_tracks(gid)
                .await
                .map_err(ledger_err)?;
            let Some((t, segs)) = all
                .into_iter()
                .find(|(t, _)| t.track_idx as usize == track_idx)
            else {
                return Ok(None);
            };
            let track = taiji_media::trackdl::TrackRecord {
                track_idx: t.track_idx as usize,
                kind: t.kind,
                playlist_uri: t.playlist_uri,
                local_name: t.local_name,
                init_files: t
                    .init_files_json
                    .and_then(|j| serde_json::from_str(&j).ok())
                    .unwrap_or_default(),
                seg_bitmap: t.seg_bitmap.unwrap_or_default(),
                seg_count: t.seg_count.unwrap_or(0) as usize,
            };
            let segments = segs
                .into_iter()
                .map(|s| taiji_media::trackdl::SegmentRecord {
                    seg_idx: s.seg_idx as usize,
                    media_sequence: s.media_sequence.unwrap_or(0) as u64,
                    uri: s.uri,
                    byte_range: s.byte_range,
                    key_id: s.key_id,
                    seg_len: s.seg_len as u64,
                    duration_ms: s.duration_ms.unwrap_or(0) as u64,
                    map: s.map_idx.map(|m| m as usize),
                    validator_digest: s.validator_digest.unwrap_or_default(),
                })
                .collect();
            Ok(Some((track, segments)))
        })
    }

    fn upsert_media_keys<'a>(
        &'a self,
        gid: &'a str,
        keys: &'a [taiji_media::keys::KeyRecord],
    ) -> futures::future::BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            let rows: Vec<taiji_store::persist::MediaKeyRow> = keys
                .iter()
                .map(|k| taiji_store::persist::MediaKeyRow {
                    id: k.db_id,
                    gid: gid.to_string(),
                    key_id: k.key_id.clone(),
                    uri: k.uri.clone(),
                    iv: k.iv.map(|iv| iv.to_vec()),
                    key: k.key.to_vec(),
                })
                .collect();
            self.handle
                .upsert_media_keys(gid, rows)
                .await
                .map_err(ledger_err)?;
            Ok(())
        })
    }

    fn load_media_keys<'a>(
        &'a self,
        gid: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Vec<taiji_media::keys::KeyRecord>, MediaError>> {
        Box::pin(async move {
            let rows = self.handle.load_media_keys(gid).await.map_err(ledger_err)?;
            Ok(rows
                .into_iter()
                .map(|r| taiji_media::keys::KeyRecord {
                    db_id: r.id,
                    key_id: r.key_id,
                    uri: r.uri,
                    iv: r.iv.and_then(|iv| <[u8; 16]>::try_from(iv.as_slice()).ok()),
                    key: r.key.try_into().unwrap_or([0; 16]),
                })
                .collect())
        })
    }
}

// ---------------------------------------------------------------------------
// row lifecycle helpers
// ---------------------------------------------------------------------------

/// The row's config_json payload (the selector/template/flag snapshot
/// the restart recovery replays). Key names and value literals are the
/// **canonical option-face forms** (the addMedia option keys and the
/// taiji-media parse-face domains) — [`media_config_from_row`] reads
/// them back through the same parse faces, so the snapshot round-trips
/// member-for-member (pinned by the `media_config_round_trip_all_fields`
/// test; the Debug-string forms once broke this).
pub fn media_config_json(cfg: &MediaRunConfig) -> String {
    serde_json::to_string(&serde_json::json!({
        "selector": cfg.selector,
        // The `--media-variant-policy` flag's canonical form (the
        // same domain `VariantPolicy::parse` accepts — additive key;
        // legacy rows without it recover as the default).
        "variant_policy": variant_policy_canonical(&cfg.variant_policy),
        // The addMedia option key (`sub-lang`), not an invented alias.
        "sub-lang": cfg.subtitle_lang,
        "audio_lang": cfg.audio_lang,
        "subtitles": if cfg.subtitles == SubtitleMode::Sidecar { "sidecar" } else { "none" },
        "template": cfg.template,
        "no_metadata": cfg.no_metadata,
        "media_archive": cfg.archive,
        "media_info_json": cfg.info_json,
        "segment_concurrency": cfg.segment_concurrency,
        "staging_quota_gib": cfg.staging_quota_gib,
        "staging_dir": cfg.staging_dir.as_ref().map(|p| p.display().to_string()),
        "allow_private_key_url": cfg.allow_private_key_url,
        // Canonical spec strings (the taiji-media parse-face domains),
        // never Debug renderings.
        "ffmpeg_path": ffmpeg_path_canonical(&cfg.ffmpeg_path),
        "muxer": match cfg.muxer {
            MuxerSpec::Auto => "auto",
            MuxerSpec::Native => "native",
            MuxerSpec::Ffmpeg => "ffmpeg",
        },
        "output_format": match cfg.output_format {
            OutputFormat::Mp4 => "mp4",
            OutputFormat::Mkv => "mkv",
        },
        "out": cfg.out,
        "cookies": cfg.cookies.len(),
    }))
    .unwrap_or_default()
}

/// The ffmpeg-path spec's canonical string (the `--media-ffmpeg-path`
/// domain: `auto | <dir> | path:<dir>`).
fn ffmpeg_path_canonical(spec: &FfmpegPathSpec) -> String {
    match spec {
        FfmpegPathSpec::Auto => "auto".to_string(),
        FfmpegPathSpec::Explicit(dir) => dir.display().to_string(),
        FfmpegPathSpec::PathOptIn(dir) => format!("path:{}", dir.display()),
    }
}

/// The variant policy's canonical string (the `--media-variant-policy`
/// domain: `highest | resolution=<H> | bandwidth=<B>` — the same forms
/// `VariantPolicy::parse` accepts, for the config snapshot round-trip).
fn variant_policy_canonical(policy: &taiji_media::VariantPolicy) -> String {
    match *policy {
        taiji_media::VariantPolicy::Highest => "highest".to_string(),
        taiji_media::VariantPolicy::Resolution { height } => format!("resolution={height}"),
        taiji_media::VariantPolicy::Bandwidth { bits_per_second } => {
            format!("bandwidth={bits_per_second}")
        }
    }
}

/// The policy's selector-projection spelling (the media_task face's
/// projection vocabulary — `best` / `res<=<H>`): the DASH entry arm
/// accepts exactly this spelling (or its absence) as "the policy rides
/// the policy field, not a selector expression".
fn variant_policy_projection(policy: &taiji_media::VariantPolicy) -> String {
    match *policy {
        taiji_media::VariantPolicy::Highest | taiji_media::VariantPolicy::Bandwidth { .. } => {
            "best".to_string()
        }
        taiji_media::VariantPolicy::Resolution { height } => format!("res<={height}"),
    }
}

/// Rebuild the media run configuration from a persisted row (the
/// restart-recovery face; unknown config keys degrade to defaults —
/// a row written by this code always round-trips).
pub fn media_config_from_row(row: &taiji_store::persist::MediaTaskRow) -> MediaRunConfig {
    let c: serde_json::Value =
        serde_json::from_str(&row.config_json).unwrap_or(serde_json::Value::Null);
    let get_s = |k: &str| {
        c.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty())
    };
    let subtitles = match get_s("subtitles").as_deref() {
        Some("none") => SubtitleMode::None,
        _ => SubtitleMode::Sidecar,
    };
    MediaRunConfig {
        gid: row.gid.clone(),
        url: row.manifest_url.clone(),
        output_dir: PathBuf::from(&row.output_path),
        out: get_s("out"),
        selector: row.selector_json.clone().or_else(|| get_s("selector")),
        // The policy snapshot round-trips through the same parse face
        // that accepted it (absent/legacy rows degrade to the default
        // — never a rejected recovery).
        variant_policy: get_s("variant_policy")
            .and_then(|v| taiji_media::VariantPolicy::parse(&v).ok())
            .unwrap_or_default(),
        audio_lang: get_s("audio_lang"),
        subtitles,
        subtitle_lang: get_s("sub-lang"),
        template: get_s("template"),
        no_metadata: c
            .get("no_metadata")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        archive: c
            .get("media_archive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        info_json: c
            .get("media_info_json")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        // Cookies are not carried in config_json — the activation seed
        // reads the unified task_cookie table back,
        // so a restart replays the persisted set instead of whatever
        // this row snapshot happened to freeze.
        cookies: Vec::new(),
        allow_private_key_url: c
            .get("allow_private_key_url")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        segment_concurrency: c
            .get("segment_concurrency")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::from(taiji_media::DEFAULT_SEGMENT_CONCURRENCY))
            as u32,
        staging_quota_gib: c
            .get("staging_quota_gib")
            .and_then(|v| v.as_u64())
            .unwrap_or(taiji_media::DEFAULT_STAGING_QUOTA_GIB),
        staging_dir: get_s("staging_dir").map(PathBuf::from),
        // The spec strings round-trip through the same taiji-media
        // parse faces that accepted them (a malformed/legacy payload
        // degrades to the default — never a rejected recovery).
        ffmpeg_path: get_s("ffmpeg_path")
            .and_then(|v| taiji_media::parse_ffmpeg_path(&v).ok())
            .unwrap_or(FfmpegPathSpec::Auto),
        muxer: get_s("muxer")
            .and_then(|v| taiji_media::parse_muxer(&v).ok())
            .unwrap_or(MuxerSpec::Auto),
        output_format: get_s("output_format")
            .and_then(|v| taiji_media::parse_output_format(&v).ok())
            .unwrap_or(OutputFormat::Mp4),
        restore: Some(row.clone()),
        probe_snapshot: None,
        persist: None,
        ffmpeg: None,
        resolver: None,
        recovered_tree: None,
        // The gate is a runtime injection (spawn_media_driver), never a
        // row fact — a rebuilt (restart) run passes None and re-gates at
        // the same boundary.
        gate: None,
    }
}

/// Write the task row through a phase transition (state = the phase's
/// persisted string; observational columns keep the writer's
/// skip-write semantics).
async fn write_row(
    persist: &Option<taiji_store::persist::PersistHandle>,
    gid: &str,
    base: &taiji_store::persist::MediaTaskRow,
    state: MediaPhase,
    phase_detail: Option<String>,
    error: Option<(String, String)>,
) {
    let Some(p) = persist else {
        return;
    };
    let mut row = base.clone();
    row.gid = gid.to_string();
    row.state = state.as_str().to_string();
    row.phase_detail_json = phase_detail;
    row.error_code = error.as_ref().map(|(c, _)| c.clone());
    row.error_msg = error.as_ref().map(|(_, m)| m.clone());
    row.updated_at = now_epoch();
    if let Err(e) = p.upsert_media_task(row).await {
        tracing::warn!(target: "taiji::core::session", gid, %e, "media row phase write failed");
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Extract the canonical failure code from a pipeline error (§14's
/// domain: the MediaError Display texts embed their codes; a bare
/// transport text falls back to the transport code — the numeric
/// mapping's row, never a fabricated new code).
pub fn failure_code_of(text: &str) -> &'static str {
    const KNOWN: &[&str] = &[
        "taiji.media.ffmpeg_missing",
        "taiji.media.not_media",
        "taiji.media.manifest_too_large",
        "taiji.media.live_unsupported",
        "taiji.media.sample_aes_unsupported",
        "taiji.media.session_key_unsupported",
        "taiji.media.iframes_unsupported",
        "taiji.media.drm_unsupported",
        "taiji.media.sidx_unsupported",
        "taiji.media.manifest_parse",
        "taiji.media.variant_policy",
        "taiji.media.cross_volume",
        "taiji.media.staging_quota_exceeded",
        "taiji.media.segment_decrypt_failed",
        "taiji.media.ssrf_blocked",
        "taiji.media.key_invalid",
        "taiji.media.staging",
        "taiji.media.remux_verify_failed",
        "taiji.option.invalid",
        "taiji.http.transport",
        "taiji.http.unexpected_response",
        "taiji.http.disk",
    ];
    for code in KNOWN {
        if text.starts_with(code) {
            return code;
        }
    }
    "taiji.http.transport"
}

/// Redact for row/error payloads — the **single implementation**
/// shared with the info.json export (field
/// whitelist and redact share one implementation): the taiji-media
/// payload face `redact_payload_text`, token-wise query stripping
/// plus control dropping.
///
/// Deliberately not the taiji-io `redact_url_for_log` face — that one
/// honors the process-wide `--log-verbatim-urls` switch, and a payload
/// that reaches disk (error_msg rows, info.json) must never leak
/// because a *log* knob was flipped.
fn redact(text: &str) -> String {
    redact_payload_text(text)
}

// ---------------------------------------------------------------------------
// probe face (§4/§10 #7)
// ---------------------------------------------------------------------------

/// One cached probe snapshot.
#[derive(Debug, Clone)]
pub struct ProbeSnapshot {
    /// The probed URL (addMedia's token consumption checks the match
    /// — a token minted for another URL does not transfer).
    pub url: String,
    pub tree: FormatTree,
    pub born: Instant,
    /// Direct-file classification (addMedia converts to the HTTP
    /// family instead of running the media pipeline).
    pub direct: bool,
}

/// The probe action face's state (§4/§10 #7): the token cache (TTL
/// 10min), the global in-flight ledger (cap 2), and the per-origin
/// rate ledger. Shared between the actor arm (spawned probe tasks)
/// and the addMedia token-consumption face.
#[derive(Debug, Default)]
pub struct ProbeFace {
    /// token → snapshot (lazy GC on admission: expired entries drop).
    cache: StdMutex<BTreeMap<String, ProbeSnapshot>>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
    /// origin → next-admit instant.
    rate: StdMutex<BTreeMap<String, Instant>>,
}

impl ProbeFace {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rate-limit admission (per origin, one per
    /// [`PROBE_ORIGIN_INTERVAL`]). `Ok(())` = admitted (the caller
    /// proceeds); `Err(wait)` = throttled (the origin's next slot is
    /// `wait` away — an honest busy reply, no queue).
    pub fn admit_rate(&self, url: &str, now: Instant) -> Result<(), Duration> {
        let key = snapshot_url_key(url);
        let mut rate = self
            .rate
            .lock()
            .unwrap_or_else(|e| panic!("probe rate ledger: {e}"));
        match rate.get(&key) {
            Some(next) if *next > now => Err(*next - now),
            _ => {
                rate.insert(key, now + PROBE_ORIGIN_INTERVAL);
                Ok(())
            }
        }
    }

    /// In-flight slot acquire (§10 #7's cap 2; the guard releases on
    /// drop).
    /// `Some` = the slot (releases on drop); `None` = the cap is
    /// fully occupied (the honest busy face).
    pub fn acquire_inflight(&self) -> Option<ProbeInflightGuard> {
        let n = self.in_flight.fetch_add(1, Ordering::SeqCst);
        if n >= PROBE_INFLIGHT_CAP {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ProbeInflightGuard {
            slot: Arc::clone(&self.in_flight),
        })
    }

    /// Store a fresh snapshot under a new opaque token; returns the
    /// token.
    pub fn store(&self, url: &str, tree: FormatTree, direct: bool) -> String {
        let token = probe_token();
        let mut cache = crate::lock(&self.cache);
        let now = Instant::now();
        // Lazy GC: expired entries drop on every store (bounded map).
        cache.retain(|_, s| s.born + PROBE_TTL > now);
        cache.insert(
            token.clone(),
            ProbeSnapshot {
                url: url.to_string(),
                tree,
                born: now,
                direct,
            },
        );
        token
    }

    /// Consume a token (addMedia's face): the snapshot must exist,
    /// match the addMedia URL, and be within the TTL — otherwise the
    /// explicit `probe_expired` / unknown-token error (§4's
    /// anti-forgery posture: the client can name a token, never hand
    /// back a format tree).
    pub fn consume(&self, token: &str, url: &str) -> Result<ProbeSnapshot, MediaError> {
        let mut cache = crate::lock(&self.cache);
        let expired_or_missing =
            |code: &str, detail: &str| MediaError::OptionInvalid(format!("{code}: {detail}"));
        let Some(snap) = cache.get(token) else {
            // The RPC-error face: an unknown token presents the
            // probe_expired shape (the server never saw it / it aged
            // out of the lazily-GCed map — one honest error face).
            return Err(expired_or_missing(
                "taiji.media.probe_expired",
                "probe token is unknown or expired (probe again)",
            ));
        };
        if snap.born + PROBE_TTL <= Instant::now() {
            cache.remove(token);
            return Err(expired_or_missing(
                "taiji.media.probe_expired",
                "probe token expired (TTL 10min); probe again",
            ));
        }
        if snap.url != url {
            return Err(expired_or_missing(
                "taiji.media.probe_expired",
                "probe token was minted for a different URL; probe again",
            ));
        }
        Ok(snap.clone())
    }
}

/// The in-flight cap guard.
pub struct ProbeInflightGuard {
    slot: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for ProbeInflightGuard {
    fn drop(&mut self) {
        self.slot.fetch_sub(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------

/// The template context's 0.3 value domain: what the manifest face
/// knows (title = None until the 0.5 bridge; id = the manifest's last
/// path segment, query-stripped — an explicit `out` wins).
fn template_id_of(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let last = path.rsplit('/').next().unwrap_or_default();
    let stem = last
        .strip_suffix(".m3u8")
        .or_else(|| last.strip_suffix(".m3u"))?;
    Some(stem.to_string())
}

/// Discover + assert the ffmpeg runtime per the configured spec (the
/// caller may cache the product — the actor keeps a session cache).
pub async fn discover_runtime(spec: &FfmpegPathSpec) -> Result<FfmpegRuntime, MediaError> {
    use taiji_media::discover::DiscoveryRequest;
    let request = match spec {
        FfmpegPathSpec::Auto => DiscoveryRequest::default(),
        FfmpegPathSpec::Explicit(dir) => DiscoveryRequest {
            explicit_dir: Some(dir.clone()),
        },
        // `path:` explicit opt-in (the PATH posture): discovery
        // runs against the live environment; the opt-in warning is
        // the caller's (the CLI logs it at flag-parse time).
        FfmpegPathSpec::PathOptIn(_) => DiscoveryRequest::default(),
    };
    FfmpegRuntime::discover_asserted(&request, None).await
}

/// Publish a phase note + update the live state (the single
/// transition point).
fn emit_phase(notes: &MediaNoteSink, live: &Arc<StdMutex<MediaLiveState>>, phase: MediaPhase) {
    notes(&MediaNote::Phase(phase));
    if let Ok(mut st) = live.lock() {
        st.phase = phase;
    }
}

/// URL extension signal (the §4 weak signal for classification when
/// the content is in hand; no synthetic Content-Type — the fetch's
/// real headers are not surfaced by the manifest-capped GET).
fn url_extension_of(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.rsplit('/').next().map(str::to_string)
}

/// Run the whole media task pipeline. See the module docs for the
/// phase semantics; `live`/`notes` are the projection faces (never
/// Option — the CLI passes logging sinks).
pub async fn run_media_task(
    cfg: MediaRunConfig,
    live: Arc<StdMutex<MediaLiveState>>,
    notes: MediaNoteSink,
    cancel: CancellationToken,
    pause: Arc<AtomicBool>,
) -> MediaEnd {
    emit_phase(&notes, &live, MediaPhase::Resolving);

    // archive checkpoint 1 (the intake/activation-phase
    // face): the normalized-URL digest lookup runs **before any
    // outbound** — a hit means this exact resource was downloaded
    // before, so the task terminalizes Done-shaped with the
    // archive_duplicate warning and zero traffic of any kind.
    if cfg.archive
        && let Some(p) = &cfg.persist
        && let Ok(Some(hit)) = p
            .load_media_archive_by_url(&archive_url_digest(&cfg.url))
            .await
    {
        return archive_skip(&cfg, &live, &notes, &hit, "normalized-URL digest", None).await;
    }

    // Client + request context (the structured cookie pass rides the
    // transport face — manifest/segment/key fetches all carry it).
    let ctx = RequestCtx {
        cookies: cfg.cookies.clone(),
        ..RequestCtx::default()
    };
    let client = match HttpClient::new(ClientConfig::default()) {
        Ok(c) => c,
        Err(e) => {
            return media_fail(
                &cfg,
                live,
                "taiji.media.staging",
                format!("client build: {e}"),
            )
            .await;
        }
    };

    // ---- Resolving: classification + format tree + selection ----
    // The probe-snapshot face: a token-bearing add skips the fetch —
    // the tree comes from the server cache (§4: no client blob).
    let input = if let Some(snapshot) = &cfg.probe_snapshot {
        if snapshot.direct {
            return MediaEnd::DirectLink;
        }
        match fetch_manifest_input(&client, &cfg.url, &ctx).await {
            Ok(p) => p,
            Err(e) => {
                return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string())
                    .await;
            }
        }
    } else {
        let bytes = match http_get_bytes(&client, &cfg.url, &ctx).await {
            Ok(b) => b,
            Err(e) => {
                return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string())
                    .await;
            }
        };
        // §4 sniff order over the live signals (content first).
        let ext = url_extension_of(&cfg.url);
        match classify_entry(Some(&bytes), ext.as_deref(), None) {
            EntryKind::Manifest(taiji_media::ManifestFlavor::Hls) => match parse_manifest(&bytes) {
                Ok(p) => ManifestInput::Hls(p),
                Err(e) => {
                    return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string())
                        .await;
                }
            },
            // The DASH line: an MPD entry parses and
            // drives the pipeline — the verdict-table refusals (dynamic →
            // live_unsupported, ContentProtection → drm_unsupported,
            // caps → manifest_too_large) are the parser's explicit
            // codes through the same failure_code_of face; bad XML
            // keeps the manifest_parse semantics.
            EntryKind::Manifest(taiji_media::ManifestFlavor::Dash) => {
                match taiji_media::parse_mpd(&bytes) {
                    Ok(mpd) => ManifestInput::Dash(mpd),
                    Err(e) => {
                        return media_fail(
                            &cfg,
                            live,
                            failure_code_of(&e.to_string()),
                            e.to_string(),
                        )
                        .await;
                    }
                }
            }
            EntryKind::DirectFile => return MediaEnd::DirectLink,
            EntryKind::NotMedia => {
                return media_fail(
                    &cfg,
                    live,
                    "taiji.media.not_media",
                    "no media signature in content, extension or Content-Type",
                )
                .await;
            }
        }
    };
    // The classification's kind lands on the live state
    // **here** — the earliest moment it is knowable — so every later
    // failure face (the `row_for_fail` fresh-row fallback included,
    // which previously hardcoded `hls`) reads the actual kind instead
    // of the placeholder. The views' empty-kind default is unchanged
    // (the status face keeps its `hls` presentation fallback).
    if let Ok(mut st) = live.lock() {
        st.kind = input.kind();
    }

    // Selector resolution (§5's three layers) against the tree (the
    // probe snapshot's tree when token-bearing, else freshly built).
    let tree = match &cfg.probe_snapshot {
        Some(snapshot) => snapshot.tree.clone(),
        None => match &input {
            ManifestInput::Hls(playlist) => {
                match taiji_media::build_format_tree(&cfg.url, playlist) {
                    Ok(t) => t,
                    Err(e) => {
                        return media_fail(
                            &cfg,
                            live,
                            failure_code_of(&e.to_string()),
                            e.to_string(),
                        )
                        .await;
                    }
                }
            }
            ManifestInput::Dash(mpd) => match taiji_media::build_format_tree_dash(&cfg.url, mpd) {
                Ok(t) => t,
                Err(e) => {
                    return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string())
                        .await;
                }
            },
        },
    };
    let selector = match parse_selector(cfg.selector.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string()).await;
        }
    };
    // The three-layer selector resolves over the tree (HLS /
    // DASH alike — the unified face). The `--media-variant-policy`
    // relationship ruling of record (the in-task kickoff step; equivalent mappings coexist):
    // the policy stays the CLI/RPC ladder-cap face — its projection
    // spellings (`best` / `res<=<H>`) and the no-selector form ride
    // the policy into the driver (unchanged; notably
    // `bandwidth=<B>` projects to `best`, so resolving the
    // projection through the selector would silently DROP the cap —
    // the policy must keep driving those). A **genuine selector
    // expression** (predicates / escape hatch / the non-default
    // presets) is the finer-grained face: it resolves over the DASH
    // tree exactly as over HLS (the red anchor this unified face
    // flips — before it, a genuine expression was refused with
    // `variant_policy`), and the policy
    // steps aside for the primary pick (one selection source — the
    // same posture the HLS `chosen` face documents; a user-visible
    // merge of the two faces would be a spec change, raised as a
    // recommendation draft only).
    let selection = if tree.kind == "dash" {
        let projected = variant_policy_projection(&cfg.variant_policy);
        let is_projection = match selector.raw.as_deref() {
            None | Some("best") => true,
            Some(raw) => raw == projected,
        };
        if is_projection {
            None
        } else {
            match resolve_selection(&tree, &selector) {
                Ok(s) => Some(s),
                Err(e) => {
                    return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string())
                        .await;
                }
            }
        }
    } else {
        match resolve_selection(&tree, &selector) {
            Ok(s) => Some(s),
            Err(e) => {
                return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string())
                    .await;
            }
        }
    };
    // The DASH driver face of a resolved selection: the chosen ids
    // ARE the DASH Representation `@id`s (the tree's address
    // domain) — threaded as explicit picks, the policy ladder
    // stands down.
    let dash_selection = if tree.kind == "dash" {
        selection
            .as_ref()
            .map(|sel| taiji_media::mpd::DashSelection {
                primary: sel.chosen_ids.first().cloned().unwrap_or_default(),
                attached: sel.chosen_ids.iter().skip(1).cloned().collect(),
            })
    } else {
        None
    };

    // Template expansion + the §10 #1 red line (forced sanitization;
    // a rewrite raises the template_unsafe warning through the bypass).
    let primary_node = selection.as_ref().and_then(|sel| {
        sel.chosen_ids
            .first()
            .and_then(|id| tree.formats.iter().find(|f| &f.format_id == id))
    });
    // The DASH ProgramInformation/Title fills the
    // template's {title} (the 0.3 manifest-available value domain);
    // HLS carries no standard title source — None stays the honest
    // face (a non-standard source is not synthesized; rich fields
    // unlock via the 0.5 bridge).
    let manifest_title = match &input {
        ManifestInput::Dash(mpd) => mpd.title.clone(),
        ManifestInput::Hls(_) => None,
    };
    let tmpl_ctx = TemplateContext {
        title: manifest_title.clone(),
        id: cfg
            .out
            .clone()
            .or_else(|| template_id_of(&cfg.url))
            .or_else(|| Some(cfg.gid.clone())),
        ext: Some(
            match cfg.output_format {
                OutputFormat::Mp4 => "mp4",
                OutputFormat::Mkv => "mkv",
            }
            .to_string(),
        ),
        res: primary_node
            .map(|f| f.resolution.clone())
            .filter(|r| !r.is_empty()),
        lang: selection
            .as_ref()
            .and_then(|sel| sel.audio_lang.clone())
            .or_else(|| cfg.audio_lang.clone()),
        playlist_index: None,
    };
    let expanded = match expand_template(cfg.template.as_deref(), &tmpl_ctx) {
        Ok(name) => name,
        Err(e) => {
            return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string()).await;
        }
    };
    let sanitized = sanitize_output_name(&expanded);
    if sanitized.rewritten {
        notes(&MediaNote::Warning {
            code: "taiji.media.template_unsafe",
            message: format!(
                "output template expanded to {:?} and was sanitized ({}); the sanitized \
                 name is used",
                expanded,
                sanitized.reasons.join(", ")
            ),
        });
    }
    let output_name = sanitized.name;
    let output_path = cfg.output_dir.join(&output_name);

    // The manifest's canonical digest (the normalized form — the
    // media_task row's identity; URL-bound on the DASH side by
    // design) and, alongside it, the **archive compartment** form: a
    // URL-free digest of the same canonical structure (the HLS
    // playlist digests are already pure content; DASH takes
    // mpd_content_digest — see taiji-media `archive`'s ruling of
    // record). Both are computed here (before any further outbound)
    // so the checkpoint ② below and the row/archive faces later
    // share one value each.
    let norm_digest = match &input {
        ManifestInput::Hls(Playlist::Master(m)) => {
            taiji_media::m3u8::master_playlist_digest(m).into_bytes()
        }
        ManifestInput::Hls(Playlist::Media(m)) => {
            taiji_media::m3u8::media_playlist_digest(m).into_bytes()
        }
        ManifestInput::Dash(mpd) => taiji_media::mpd_digest(mpd, &cfg.url).into_bytes(),
    };
    let archive_manifest_digest = match &input {
        // The HLS digests carry no URL — the archive compartment
        // is the same string.
        ManifestInput::Hls(_) => String::from_utf8_lossy(&norm_digest).to_string(),
        ManifestInput::Dash(mpd) => taiji_media::mpd_content_digest(mpd),
    };
    // Archive checkpoint ② (the Resolving face): the fetched manifest's
    // **URL-free** digest against the archive's manifest compartment
    // — the same content under a different URL/CDN/mirror hits here
    // (checkpoint ① cannot; the URL-bound row-digest form would miss it on
    // the DASH side, which is exactly why the compartment is
    // URL-free). The skip lands **before the thumbnail fetch and the
    // staging admission**: a known duplicate spends nothing beyond
    // the manifest GET.
    if cfg.archive
        && let Some(p) = &cfg.persist
        && let Ok(Some(hit)) = p
            .load_media_archive_by_manifest(&archive_manifest_digest)
            .await
    {
        return archive_skip(
            &cfg,
            &live,
            &notes,
            &hit,
            "manifest digest",
            Some(norm_digest.clone()),
        )
        .await;
    }

    // The manifest-obtainable thumbnail — the DASH
    // descriptor face's URI (the anchored-scheme ruling,
    // `THUMBNAIL_SCHEME`), resolved against the manifest, **through
    // the same SSRF line** the playlist/segment faces ride (second-
    // order manifest content), fetched over the bounded base-client
    // GET, sniffed by magic. An enhancement face (the media-track
    // necessity-grading semantics — nothing here is a selected track): every
    // failure degrades to a coverless product + the
    // `taiji.media.metadata_degraded` warning, never a task Error.
    // HLS carries no standard thumbnail source — None, honestly.
    let mut thumbnail: Option<(Vec<u8>, bool)> = None;
    if !cfg.no_metadata
        && let ManifestInput::Dash(mpd) = &input
        && let Some(uri) = mpd.thumbnail_uri()
    {
        match thumbnail_fetch(&cfg, &client, &ctx, &cfg.url, uri).await {
            Ok(covr) => thumbnail = Some(covr),
            Err(text) => notes(&MediaNote::Warning {
                code: "taiji.media.metadata_degraded",
                message: format!("thumbnail unavailable, embedding skipped: {text}"),
            }),
        }
    }

    // Staging admission (the staging face: same volume + 0700 create-new
    // + quota).
    let gid_dir = cfg.staging_gid_dir();
    let staging_root = cfg.staging_root();
    let quota = StagingQuota::from_gib(cfg.staging_quota_gib);
    for step in [
        ensure_same_volume(&gid_dir, &cfg.output_dir).map_err(|e| e.to_string()),
        create_staging_dir(&gid_dir).map_err(|e| e.to_string()),
        quota
            .admit(staging_usage_bytes(&staging_root))
            .map_err(|e| e.to_string()),
    ] {
        if let Err(text) = step {
            return media_fail(&cfg, live, failure_code_of(&text), text).await;
        }
    }

    // The media_task row (state downloading from here; the selector /
    // sanitized-name / staging columns land now — the recovery's
    // phase re-entry reads them) + the media_format snapshot (the
    // probe cache's durable counterpart).
    let base_row = taiji_store::persist::MediaTaskRow {
        gid: cfg.gid.clone(),
        kind: input.kind().to_string(),
        manifest_url: cfg.url.clone(),
        state: MediaPhase::Downloading.as_str().to_string(),
        phase_detail_json: None,
        variant_json: selection.as_ref().and_then(|sel| {
            sel.chosen_ids
                .first()
                .map(|id| serde_json::json!({ "format_id": id }).to_string())
        }),
        selector_json: selector.raw.clone(),
        output_name: Some(output_name.clone()),
        bridge_json: None,
        staging_dir: gid_dir.display().to_string(),
        output_path: cfg.output_dir.display().to_string(),
        manifest_norm_digest: norm_digest,
        total_done: 0,
        config_json: media_config_json(&cfg),
        error_code: None,
        error_msg: None,
        created_at: now_epoch(),
        updated_at: now_epoch(),
    };
    write_row(
        &cfg.persist,
        &cfg.gid,
        &base_row,
        MediaPhase::Downloading,
        None,
        None,
    )
    .await;
    if let Some(p) = &cfg.persist
        && let Ok(json) = serde_json::to_string(&tree)
    {
        let _ = p
            .upsert_media_format(taiji_store::persist::MediaFormatRow {
                gid: cfg.gid.clone(),
                formats_json: json,
                created_at: now_epoch(),
                updated_at: now_epoch(),
            })
            .await;
    }
    if let Ok(mut st) = live.lock() {
        st.staging_dir = gid_dir.display().to_string();
        st.output_name = Some(output_name.clone());
        st.selector = selector.raw.clone();
        st.kind = input.kind();
        st.manifest_url = cfg.url.clone();
        st.variant = primary_node
            .map(|f| f.resolution.clone())
            .filter(|r| !r.is_empty());
    }

    // ---- sidecar start precheck (the synthesis decision functions +
    // this pipeline's orchestration): a form the native channel cannot
    // serve (TS-shaped variant / user-explicit ffmpeg) requires the
    // fallback — ffmpeg absent at **start** = ffmpeg_missing with
    // zero segment traffic. ----
    let precheck_outcome = match &input {
        ManifestInput::Hls(_) => match &selection {
            Some(sel) => start_precheck(&cfg, &client, &ctx, sel).await,
            None => unreachable!("an HLS entry always resolves a selection"),
        },
        // DASH start precheck (a pure form): the
        // MPD declares no playlist-shaped TS-variant question; the
        // only zero-traffic refusals are the muxer preference and
        // the MKV output (native-channel territory, the synthesis
        // verdict).
        ManifestInput::Dash(_) => start_precheck_dash(&cfg),
    };
    let ffmpeg = match precheck_outcome {
        PrecheckOutcome::NativeOptional => cfg.ffmpeg.clone(),
        PrecheckOutcome::FallbackRequired => {
            let runtime = match &cfg.ffmpeg {
                Some(rt) => Some(rt.clone()),
                None => discover_runtime(&cfg.ffmpeg_path).await.ok(),
            };
            if runtime.is_none() {
                return media_fail(
                    &cfg,
                    live,
                    "taiji.media.ffmpeg_missing",
                    "the selected form requires the ffmpeg fallback channel but no usable \
                     pair is available (start precheck — zero segment traffic)",
                )
                .await;
            }
            runtime
        }
        PrecheckOutcome::FetchFailed(e) => {
            return media_fail(&cfg, live, failure_code_of(&e.to_string()), e.to_string()).await;
        }
    };

    // ---- Downloading (the media download driver, chosen-variant face;
    // the DASH line threads the selector-resolved `DashSelection` when a
    // genuine expression resolved — else the driver's variant-policy
    // semantics select the representations) ----
    emit_phase(&notes, &live, MediaPhase::Downloading);
    let chosen = if tree.kind == "dash" {
        None
    } else {
        selection.as_ref().map(|selection| ChosenVariant {
            variant_uri: selection.primary_uri.clone(),
            attached: tree
                .formats
                .iter()
                .filter(|f| selection.attached_uris.contains(&f.uri))
                .map(|f| AttachedRendition {
                    uri: f.uri.clone(),
                    kind: if f.has_audio && !f.has_video {
                        "audio"
                    } else {
                        "subtitle"
                    },
                    language: (!f.language.is_empty()).then(|| f.language.clone()),
                })
                .collect(),
        })
    };
    let live_for_progress = Arc::clone(&live);
    let dl_cfg = MediaDownloadConfig {
        track_set: taiji_media::TrackSetConfig {
            audio_lang: selection
                .as_ref()
                .and_then(|sel| sel.audio_lang.clone())
                .or_else(|| cfg.audio_lang.clone()),
            subtitles: cfg.subtitles,
            segment_concurrency: cfg.segment_concurrency,
        },
        fetch: Default::default(),
        // Selection routing: the DASH line takes `dash_selection`
        // when a genuine selector expression resolved (the policy
        // ladder stands down — one selection source); otherwise the
        // variant policy rides the driver (the primary-ladder cap;
        // unchanged). The HLS face is
        // untouched: a resolved selection always supplies `chosen`
        // there, so the policy is the driver's no-chosen fallback —
        // never a second selection source.
        variant_policy: cfg.variant_policy,
        // Cloned, not moved: the synthesis re-plan (build_track_inputs)
        // consumes the same ruling — one selection source from the
        // download through the synthesis (pinned by a review block).
        dash_selection: dash_selection.clone(),
        chosen,
        staging_quota_gib: cfg.staging_quota_gib,
        staging_dir: cfg.staging_dir.clone(),
        allow_private_key_url: cfg.allow_private_key_url,
        output_dir: cfg.output_dir.clone(),
        subtitle_lang: cfg.subtitle_lang.clone(),
        progress: Some(Arc::new(move |note: MediaProgressNote| {
            progress_note(&live_for_progress, &note);
        })),
    };
    let mut dl = MediaDownload::new(&cfg.gid, client.clone(), ctx.clone(), dl_cfg);
    dl.resolver = cfg.resolver.clone();
    let Some(handle) = cfg.persist.clone() else {
        return media_fail(
            &cfg,
            live,
            "taiji.media.staging",
            "no persistence injection (media tasks require the store ledger)",
        )
        .await;
    };
    let ledger = StoreMediaLedger::new(handle);
    let report = {
        let run = dl.run(&cfg.url, &ledger);
        tokio::select! {
            r = run => r,
            _ = cancel.cancelled() => {
                return cancel_teardown(
                    &cfg,
                    &base_row,
                    &live,
                    &pause,
                    MediaPhase::Downloading,
                    &notes,
                )
                .await
            }
        }
    };
    let report = match report {
        Ok(r) => r,
        Err(e) => {
            let text = e.to_string();
            return media_fail(&cfg, live, failure_code_of(&text), text).await;
        }
    };
    match &report.verdict {
        TrackSetVerdict::Complete { degraded } => {
            // Degraded sidecars → the download-driver warning payloads (the
            // phaseChanged bypass face).
            for (label, text) in degraded {
                notes(&MediaNote::Warning {
                    code: "taiji.media.staging",
                    message: format!("attached side track {label} degraded: {text}"),
                });
            }
        }
        TrackSetVerdict::Failed { required, error } => {
            let text = format!("{required}: {error}");
            let code = failure_code_of(&text);
            return media_fail(&cfg, live, code, text).await;
        }
    }

    // ---- Synthesis gate: the Downloading →
    // Processing boundary parks here under the session's
    // media-synthesis-concurrency budget. The arrival notice fires
    // first (the actor releases this task's download slot and parks it
    // into proc_wait), then the permit await races the task token — a
    // pause/remove/shutdown cancellation lands the normal teardown
    // paths (Paused with the §3.2 phase memory / Cancelled), never an
    // error. The live phase flips to Processing while parked: the hang
    // sits at the synthesis boundary, so a pause there must remember
    // Processing (§4.3's Paused{memory: Processing} for proc_wait and
    // processing alike). The persisted row is untouched — the
    // Processing row write below happens only after the permit, so a
    // non-pause cancellation (shutdown/remove) leaves the row at its
    // download-phase value: the restart re-walks Resolving → Downloading
    // (idempotent, bitmap full) → gate, and the proc_wait position
    // never crosses a restart. A None gate (the bare-run shape) passes
    // straight through.
    if let Some(gate) = &cfg.gate {
        if let Ok(mut st) = live.lock() {
            st.phase = MediaPhase::Processing;
        }
        gate.arrive().await;
        tokio::select! {
            _ = gate.acquire() => {}
            _ = cancel.cancelled() => {
                return cancel_teardown(
                    &cfg,
                    &base_row,
                    &live,
                    &pause,
                    MediaPhase::Processing,
                    &notes,
                )
                .await
            }
        }
    }

    // ---- Processing + Verifying (the synthesis pipeline; the phase sink
    // publishes Processing/Verifying transitions live) ----
    emit_phase(&notes, &live, MediaPhase::Processing);
    // The phase entry persists at its true start (the §8 recovery
    // read face re-enters by phase; the sink's later Processing write
    // is the row-compare-idempotent echo from inside the synthesis).
    write_row(
        &cfg.persist,
        &cfg.gid,
        &base_row,
        MediaPhase::Processing,
        None,
        None,
    )
    .await;
    let inputs = match build_track_inputs(
        &client,
        &ctx,
        &cfg,
        &report,
        &ledger,
        dash_selection.as_ref(),
    )
    .await
    {
        Ok(inputs) => inputs,
        Err(e) => {
            let text = e.to_string();
            return media_fail(&cfg, live, failure_code_of(&text), text).await;
        }
    };
    let synth_cfg = synth::SynthesisConfig {
        // The metadata vehicle — title + cover ride
        // the native channel's ©nam/covr faces; `--no-meta` (or a
        // degraded thumbnail fetch) lands the empty default. Chapters
        // stay empty: 0.3 manifests carry no chapter source (the
        // chpl write face is a synthesis-matrix item; a 0.5 bridge unlock).
        meta: taiji_media::mp4write::MovieMeta {
            title: (!cfg.no_metadata).then(|| manifest_title.clone()).flatten(),
            covr: if cfg.no_metadata {
                None
            } else {
                thumbnail.clone()
            },
            chapters: Vec::new(),
        },
        format: match cfg.output_format {
            OutputFormat::Mp4 => synth::OutputFormat::Mp4,
            OutputFormat::Mkv => synth::OutputFormat::Mkv,
        },
        muxer: match cfg.muxer {
            MuxerSpec::Auto => synth::MuxerPreference::Auto,
            MuxerSpec::Native => synth::MuxerPreference::Native,
            MuxerSpec::Ffmpeg => synth::MuxerPreference::Ffmpeg,
        },
        output: output_path.clone(),
        staging_dir: gid_dir.clone(),
        ffmpeg,
        // The tx3g embed face is the kickoff-gate capability — the 0.3
        // product face is the VTT sidecar (the synthesis default posture).
        embed_subtitles: false,
        free_bytes_override: None,
        phase_sink: {
            let notes = Arc::clone(&notes);
            let live = Arc::clone(&live);
            // The phase transitions also persist (the §8 recovery read
            // face re-enters by phase): Processing/Verifying write the
            // row state so a kill mid-synthesis restarts into the
            // idempotent re-run; Done's row write stays with the main
            // flow (the verified-rename precedes it there — the row
            // never claims Done before the product exists).
            let persist = cfg.persist.clone();
            let gid_for_row = cfg.gid.clone();
            let base_for_row = base_row.clone();
            Some(Arc::new(move |phase: synth::Phase| {
                let media_phase = match phase {
                    synth::Phase::Processing { .. } => MediaPhase::Processing,
                    synth::Phase::Verifying => MediaPhase::Verifying,
                    synth::Phase::Done => MediaPhase::Done,
                };
                notes(&MediaNote::Phase(media_phase));
                if let Ok(mut st) = live.lock() {
                    st.phase = media_phase;
                    if media_phase.pauses_with_memory() {
                        st.phase_detail = Some(media_phase.as_str().to_string());
                    }
                }
                if media_phase.pauses_with_memory()
                    && let Some(p) = persist.clone()
                {
                    let row_state = media_phase;
                    let gid = gid_for_row.clone();
                    let row = base_for_row.clone();
                    // Fire-and-forget on the single-writer channel: the
                    // write is ordered behind the phase entry, and the
                    // re-entry semantics tolerate either ordering on a
                    // kill (downloading/processing/verifying all re-enter
                    // the same idempotent pipeline).
                    tokio::spawn(async move {
                        write_row(&Some(p), &gid, &row, row_state, None, None).await;
                    });
                }
            }))
        },
    };
    let synth_report = {
        let run = synth::run_synthesis(&inputs, &synth_cfg, cancel.clone());
        tokio::select! {
            r = run => r,
            _ = cancel.cancelled() => {
                // §3.2 phase memory: a Processing/Verifying pause
                // remembers the interrupted phase (unpause re-runs —
                // idempotent by construction).
                return cancel_teardown(
                    &cfg,
                    &base_row,
                    &live,
                    &pause,
                    MediaPhase::Processing,
                    &notes,
                )
                .await
            }
        }
    };
    let synth_report = match synth_report {
        Ok(r) => r,
        // A cancelled synthesis = the pause/remove face (the token was
        // raised while the pipeline was between awaits) — the cancel
        // teardown owns it (the §3.2 phase memory), never an error.
        Err(MediaError::Cancelled) => {
            return cancel_teardown(
                &cfg,
                &base_row,
                &live,
                &pause,
                MediaPhase::Processing,
                &notes,
            )
            .await;
        }
        Err(e) => {
            let text = e.to_string();
            return media_fail(&cfg, live, failure_code_of(&text), text).await;
        }
    };
    // The synthesis degradation warnings (sidecar splice failure, native-
    // only fallback absence…) ride the bypass.
    for warning in &synth_report.warnings {
        notes(&MediaNote::Warning {
            code: "taiji.media.staging",
            message: warning.clone(),
        });
    }

    // ---- Done: the verified product is at its final path (the
    // synthesis rename); the success cleanup face removes the staging
    // tree. ----
    let bytes = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);
    emit_phase(&notes, &live, MediaPhase::Done);
    write_row(
        &cfg.persist,
        &cfg.gid,
        &base_row,
        MediaPhase::Done,
        None,
        None,
    )
    .await;
    // The Done close-out records the archive fingerprints —
    // both compartments land in one row (the normalized URL digest +
    // the fetched manifest's canonical digest), the later duplicate
    // checkpoints read them. A write failure degrades to a log line
    // (the download itself already succeeded; the next re-add simply
    // re-downloads — the honest degraded posture, the row-write
    // family's discipline).
    if cfg.archive
        && let Some(p) = &cfg.persist
    {
        let manifest_digest = archive_manifest_digest.clone();
        let row = taiji_store::persist::MediaArchiveRow {
            url_digest: archive_url_digest(&cfg.url),
            manifest_digest,
            kind: base_row.kind.clone(),
            title: manifest_title.clone(),
            output_name: output_name.clone(),
            gid: cfg.gid.clone(),
            created_at: now_epoch(),
            updated_at: now_epoch(),
        };
        if let Err(e) = p.upsert_media_archive(row).await {
            tracing::warn!(target: "taiji::core::session", gid = %cfg.gid, %e,
                "media archive row write failed (the task completed; a re-add \
                 will re-download)");
        }
    }
    // The info.json sidecar — the whitelisted record
    // rendered through the shared payload redact (§10 #5's fixed
    // field set; forbidden keys are structurally absent). The export
    // answers to its own flag alone: `--no-meta` governs the *embed*
    // face (title/covr inside the product), never this one.
    if cfg.info_json {
        // The export's manifest_digest = the archive compartment form
        // (the archive fingerprint a future checkpoint compares against —
        // the same string the media_archive row holds).
        let manifest_digest = archive_manifest_digest.clone();
        let record = MediaInfoRecord {
            gid: cfg.gid.clone(),
            kind: base_row.kind.clone(),
            title: manifest_title.clone(),
            id: tmpl_ctx.id.clone(),
            ext: tmpl_ctx.ext.clone().unwrap_or_else(|| "mp4".into()),
            res: tmpl_ctx.res.clone(),
            lang: tmpl_ctx.lang.clone(),
            manifest_url: cfg.url.clone(),
            output_name: output_name.clone(),
            url_digest: archive_url_digest(&cfg.url),
            manifest_digest,
            bytes,
            completed_at: now_epoch(),
        };
        // The yt-dlp naming convention: the product's stem + the
        // .info.json suffix (two products in one dir never collide;
        // the container extension is not part of the metadata name).
        let stem = output_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(output_name.as_str());
        let sidecar = output_path.with_file_name(format!("{stem}.info.json"));
        // The close-out's small-file write, the same fs posture as the
        // sibling close-out faces (metadata/remove_staging).
        if let Err(e) = std::fs::write(&sidecar, render_info_json(&record)) {
            tracing::warn!(target: "taiji::core::session", gid = %cfg.gid, %e,
                "info.json export write failed (the task completed)");
        }
    }
    let _ = taiji_media::remove_staging(&gid_dir);
    if let Ok(mut st) = live.lock() {
        st.rate = 0;
    }
    MediaEnd::Done { bytes }
}

/// The cancellation teardown (pause / remove / shutdown): a pause
/// lands the `paused` row (with the §3.2 phase memory when the
/// interrupted phase qualifies); a non-pause cancellation leaves the
/// row at its last phase — the restart bootstrap re-enters by phase,
/// a remove deletes the row (the actor's dispatch).
async fn cancel_teardown(
    cfg: &MediaRunConfig,
    base_row: &taiji_store::persist::MediaTaskRow,
    live: &Arc<StdMutex<MediaLiveState>>,
    pause: &AtomicBool,
    interrupted: MediaPhase,
    notes: &MediaNoteSink,
) -> MediaEnd {
    let st_phase = live.lock().map(|st| st.phase).unwrap_or(interrupted);
    let memory = if st_phase.pauses_with_memory() {
        Some(st_phase)
    } else {
        None
    };
    if pause.load(Ordering::Relaxed) {
        write_row(
            &cfg.persist,
            &cfg.gid,
            base_row,
            MediaPhase::Paused,
            memory.map(|m| m.as_str().to_string()),
            None,
        )
        .await;
        // The phaseChanged paused payload (the §3.2 memory rides
        // phaseDetail).
        notes(&MediaNote::PausedWithMemory(
            memory.unwrap_or(MediaPhase::Downloading),
        ));
        if let Ok(mut st) = live.lock() {
            st.phase = MediaPhase::Paused;
            st.phase_detail = memory.map(|m| m.as_str().to_string());
        }
        MediaEnd::Paused { memory }
    } else {
        MediaEnd::Cancelled { memory }
    }
}

/// The §7 start-precheck verdict.
enum PrecheckOutcome {
    /// The native channel applies (fallback optional).
    NativeOptional,
    /// The form requires the ffmpeg fallback channel.
    FallbackRequired,
    /// The precheck fetch itself failed (fail the task honestly).
    FetchFailed(MediaError),
}

/// The §7 start precheck: fetch the selected variant playlist (one
/// bounded GET, zero segment traffic) and decide whether the form
/// **requires** the ffmpeg fallback — the native channel is
/// fMP4-only (`native_support`), so a video variant with no
/// init sections (the TS line) or a user-explicit ffmpeg preference
/// requires the pair before any download starts.
///
/// The fetch rides the SSRF line: the selection's
/// primary URI is second-order manifest content (probe-tree /
/// selector resolved), refused by default posture before any GET.
async fn start_precheck(
    cfg: &MediaRunConfig,
    client: &HttpClient,
    ctx: &RequestCtx,
    selection: &Selection,
) -> PrecheckOutcome {
    if cfg.muxer == MuxerSpec::Ffmpeg {
        return PrecheckOutcome::FallbackRequired;
    }
    if let Err(e) = check_playlist_uri(cfg, &selection.primary_uri).await {
        return PrecheckOutcome::FetchFailed(e);
    }
    match fetch_manifest_input(client, &selection.primary_uri, ctx).await {
        Ok(ManifestInput::Hls(Playlist::Media(m))) => {
            if m.init_sections.is_empty() && !m.segments.is_empty() {
                PrecheckOutcome::FallbackRequired
            } else {
                PrecheckOutcome::NativeOptional
            }
        }
        Ok(_) => PrecheckOutcome::NativeOptional,
        Err(e) => PrecheckOutcome::FetchFailed(e),
    }
}

/// The DASH start precheck: a pure, fetch-free
/// form — an MPD entry declares no playlist-shaped TS-variant
/// question (the addressing is structural); the zero-traffic
/// refusals are exactly the user-explicit ffmpeg preference and the
/// MKV output (native-channel territory, `native_support`).
fn start_precheck_dash(cfg: &MediaRunConfig) -> PrecheckOutcome {
    if cfg.muxer == MuxerSpec::Ffmpeg {
        return PrecheckOutcome::FallbackRequired;
    }
    if matches!(cfg.output_format, OutputFormat::Mkv) {
        return PrecheckOutcome::FallbackRequired;
    }
    PrecheckOutcome::NativeOptional
}

/// The playlist-fetch SSRF verdict: one fresh per-host
/// cache per call site (these faces fetch at most a handful of
/// playlists; the segment/init/key faces keep the driver's shared
/// cache). Same policy, same resolver, same redirect-endpoint
/// coverage as the key/segment line — one threat model, no playlist-shaped
/// hole.
async fn check_playlist_uri(cfg: &MediaRunConfig, uri: &str) -> Result<(), MediaError> {
    let policy = taiji_media::ssrf::SsrfPolicy {
        allow_private: cfg.allow_private_key_url,
    };
    let resolver = cfg
        .resolver
        .clone()
        .unwrap_or_else(taiji_media::ssrf::default_resolver);
    let mut cache = taiji_media::ssrf::HostVerdictCache::new();
    taiji_media::ssrf::check_uri(uri, &policy, resolver.as_ref(), &mut cache).await
}

/// The terminal-failure helper: persists the error row (durable
/// before the task teardown — the actor's result-table dispatch
/// follows) + flips the live phase to Error.
///
/// The row write is a **partial-column** UPDATE first
/// (state/error/updated_at only — the row's kind, output_name,
/// variant/selector snapshots and manifest_norm_digest stay exactly
/// as the run wrote them; the pre-fix whole-row template stamped
/// `kind = hls` over a DASH task's row and blanked the product
/// name/digest). The full-row [`row_for_fail`] insert remains only
/// as the fallback for a gid with **no row yet** (a task failing
/// before its first anchor write — nothing existed to preserve).
async fn media_fail(
    cfg: &MediaRunConfig,
    live: Arc<StdMutex<MediaLiveState>>,
    code: &str,
    message: impl Into<String>,
) -> MediaEnd {
    let message = redact(&message.into());
    let kind = fail_row_kind(cfg, &live);
    let mut row = row_for_fail(cfg, &kind);
    row.error_code = Some(code.to_string());
    row.error_msg = Some(message.clone());
    if let Ok(mut st) = live.lock() {
        st.phase = MediaPhase::Error;
    }
    if let Some(p) = &cfg.persist {
        match p.fail_media_task(&cfg.gid, code, &message).await {
            Ok(taiji_store::persist::PersistOutcome::Written) => {}
            // No row (or the writer face unavailable): the fresh-row
            // form makes the error state durable anyway.
            _ => {
                let _ = p.upsert_media_task(row).await;
            }
        }
    }
    MediaEnd::Failed {
        code: code.to_string(),
        message,
    }
}

/// The fresh-row fallback's kind: the **actual** task
/// kind from whatever context already knows it, never a hardcoded
/// flavor. Resolution order: ① the live state's classification stamp
/// (set the moment the sniff decides — covers every failure from
/// classification onward, the mid-run panic terminal included);
/// ② the cfg-carried hints (the probe snapshot's tree, the recovery
/// seed tree, the restore row — the token-bearing add that fails
/// before any classification still names its kind); ③ the historical
/// `hls` default, honest only for a pre-classification failure on the
/// fresh-fetch shape (nothing better is knowable — the same default
/// the status views present).
fn fail_row_kind(cfg: &MediaRunConfig, live: &Arc<StdMutex<MediaLiveState>>) -> String {
    if let Ok(st) = live.lock()
        && matches!(st.kind, "hls" | "dash")
    {
        return st.kind.to_string();
    }
    for hint in [
        cfg.probe_snapshot.as_ref().map(|s| s.tree.kind.as_str()),
        cfg.recovered_tree.as_ref().map(|t| t.kind.as_str()),
        cfg.restore.as_ref().map(|r| r.kind.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if matches!(hint, "hls" | "dash") {
            return hint.to_string();
        }
    }
    "hls".to_string()
}

fn row_for_fail(cfg: &MediaRunConfig, kind: &str) -> taiji_store::persist::MediaTaskRow {
    taiji_store::persist::MediaTaskRow {
        gid: cfg.gid.clone(),
        kind: kind.to_string(),
        manifest_url: cfg.url.clone(),
        state: MediaPhase::Error.as_str().to_string(),
        phase_detail_json: None,
        variant_json: None,
        selector_json: cfg.selector.clone(),
        output_name: None,
        bridge_json: None,
        staging_dir: cfg.staging_gid_dir().display().to_string(),
        output_path: cfg.output_dir.display().to_string(),
        manifest_norm_digest: Vec::new(),
        total_done: 0,
        config_json: media_config_json(cfg),
        error_code: None,
        error_msg: None,
        created_at: now_epoch(),
        updated_at: now_epoch(),
    }
}

/// The driver's panic terminal: a panic inside the media
/// pipeline maps to the task-level Error face — the row flips to
/// Error and the live phase follows, so the actor's `TaskNotice::Ended`
/// (emitted by the catch_unwind driver wrapper) lands on a terminal
/// state instead of a zombie. The code reuses the inherited
/// `taiji.media.staging` face (no new code is minted here);
/// the message is redacted like every failure text.
pub(crate) async fn media_panic_terminal(
    cfg: &MediaRunConfig,
    live: &Arc<StdMutex<MediaLiveState>>,
    panic_text: String,
) -> MediaEnd {
    media_fail(
        cfg,
        Arc::clone(live),
        "taiji.media.staging",
        format!("media driver panicked (caught at the driver gate): {panic_text}"),
    )
    .await
}

/// Progress-note → live-state rollup (track table + a rough
/// whole-task rate: bytes delta over the wall time between notes —
/// the honest rollup granularity wired here).
fn progress_note(live: &Arc<StdMutex<MediaLiveState>>, note: &MediaProgressNote) {
    if let Ok(mut st) = live.lock() {
        let state = if note.started {
            super::view::MediaTrackState::Active
        } else {
            super::view::MediaTrackState::Done
        };
        match st.tracks.iter_mut().find(|t| t.label == note.label) {
            Some(t) => {
                t.state = state;
                t.segments_done = note.segments_done;
                t.segments_total = note.segments_total;
                t.bytes = note.delivered_bytes;
            }
            None => st.tracks.push(MediaTrackLive {
                label: note.label.clone(),
                kind: note.kind,
                state,
                segments_done: note.segments_done,
                segments_total: note.segments_total,
                bytes: note.delivered_bytes,
            }),
        }
        let total: u64 = st.tracks.iter().map(|t| t.bytes).sum();
        let now = Instant::now();
        if let Some((at, base)) = st.rate_base {
            let elapsed = now.saturating_duration_since(at).as_secs_f64();
            if elapsed >= 0.5 && total >= base {
                st.rate = ((total - base) as f64 / elapsed) as u64;
            }
        }
        st.bytes_done = total;
        st.rate_base = Some((now, total));
    }
}

/// The archive duplicate-skip close-out: a checkpoint hit —
/// zero segment traffic, the task terminalizes **Done-shaped** (the
/// fast-close ruling, not an Error): the
/// `taiji.media.archive_duplicate` warning rides the bypass,
/// the done row lands with the archived identity (kind/output name/
/// digest — the read-back face), and the terminal carries the
/// archived product name. `which` names the winning checkpoint for
/// the warning text.
async fn archive_skip(
    cfg: &MediaRunConfig,
    live: &Arc<StdMutex<MediaLiveState>>,
    notes: &MediaNoteSink,
    hit: &taiji_store::persist::MediaArchiveRow,
    which: &str,
    norm_digest_known: Option<Vec<u8>>,
) -> MediaEnd {
    notes(&MediaNote::Warning {
        code: "taiji.media.archive_duplicate",
        message: format!(
            "already in the download archive ({which} hit; recorded by task {} at {}); \
             skipping — zero segment traffic",
            hit.gid, hit.created_at
        ),
    });
    // The skip row's manifest_norm_digest: the actually-fetched row
    // digest when checkpoint ② won (we have it in hand); checkpoint ①
    // never fetched, so the archived compartment form is the best
    // available record (for HLS the two coincide — the playlist
    // digests are URL-free).
    let digest_bytes =
        norm_digest_known.unwrap_or_else(|| hit.manifest_digest.clone().into_bytes());
    let row = taiji_store::persist::MediaTaskRow {
        gid: cfg.gid.clone(),
        kind: hit.kind.clone(),
        manifest_url: cfg.url.clone(),
        state: MediaPhase::Done.as_str().to_string(),
        phase_detail_json: None,
        variant_json: None,
        selector_json: cfg.selector.clone(),
        output_name: Some(hit.output_name.clone()),
        bridge_json: None,
        staging_dir: cfg.staging_gid_dir().display().to_string(),
        output_path: cfg.output_dir.display().to_string(),
        manifest_norm_digest: digest_bytes,
        total_done: 0,
        config_json: media_config_json(cfg),
        error_code: None,
        error_msg: None,
        created_at: now_epoch(),
        updated_at: now_epoch(),
    };
    if let Some(p) = &cfg.persist {
        let _ = p.upsert_media_task(row).await;
    }
    emit_phase(notes, live, MediaPhase::Done);
    if let Ok(mut st) = live.lock() {
        st.output_name = Some(hit.output_name.clone());
        st.kind = match hit.kind.as_str() {
            "dash" => "dash",
            _ => "hls",
        };
        st.manifest_url = cfg.url.clone();
    }
    MediaEnd::ArchiveHit {
        output_name: hit.output_name.clone(),
    }
}

/// The thumbnail fetch: resolve the descriptor URI against the
/// manifest, cross the SSRF line (the same policy/resolver/cache face
/// as the playlist checks — second-order manifest content), fetch
/// bounded, sniff the magic bytes (JPEG/PNG — the covr faces' two
/// well-known types). Every failure is the caller's degrade face.
async fn thumbnail_fetch(
    cfg: &MediaRunConfig,
    client: &HttpClient,
    ctx: &RequestCtx,
    manifest_url: &str,
    uri: &str,
) -> Result<(Vec<u8>, bool), String> {
    let absolute = match taiji_http::reqwest::Url::parse(manifest_url)
        .map_err(|e| format!("manifest URL: {e}"))
        .and_then(|base| {
            taiji_media::mediadl::resolve_uri(&base, uri).map_err(|e| format!("resolve: {e}"))
        }) {
        Ok(u) => u,
        Err(text) => return Err(redact(&text)),
    };
    // The SSRF line (one threat model across the key/segment/
    // playlist/thumbnail faces; the
    // thumbnail URI is manifest-sourced second-order content).
    if let Err(e) = check_playlist_uri(cfg, &absolute).await {
        return Err(e.to_string());
    }
    let bytes = http_get_bytes(client, &absolute, ctx)
        .await
        .map_err(|e| e.to_string())?;
    // Magic sniff: JPEG (FF D8 FF) / PNG (89 50 4E 47).
    let is_jpeg = bytes.len() >= 3 && bytes[..3] == [0xFF, 0xD8, 0xFF];
    let is_png = bytes.len() >= 4 && bytes[..4] == [0x89, 0x50, 0x4E, 0x47];
    if !is_jpeg && !is_png {
        return Err(format!(
            "thumbnail payload is neither JPEG nor PNG ({} bytes)",
            bytes.len()
        ));
    }
    Ok((bytes, is_png))
}

/// Fetch + parse a manifest (bounded by the 16MiB red line).
/// The parsed entry manifest — the two flavors the 0.3 line drives
/// (HLS and DASH).
enum ManifestInput {
    Hls(Playlist),
    Dash(taiji_media::mpd::Mpd),
}

impl ManifestInput {
    /// The `media_task.kind` spelling.
    fn kind(&self) -> &'static str {
        match self {
            Self::Hls(_) => "hls",
            Self::Dash(_) => "dash",
        }
    }
}

/// Fetch + classify + parse into [`ManifestInput`] (the probe-snapshot
/// re-fetch path; the content sniff routes the flavor).
async fn fetch_manifest_input(
    client: &HttpClient,
    url: &str,
    ctx: &RequestCtx,
) -> Result<ManifestInput, MediaError> {
    let bytes = http_get_bytes(client, url, ctx).await?;
    if let Ok(taiji_media::ManifestFlavor::Dash) =
        taiji_media::m3u8::sniff(Some(&bytes), None, None)
    {
        return taiji_media::parse_mpd(&bytes).map(ManifestInput::Dash);
    }
    parse_manifest(&bytes).map(ManifestInput::Hls)
}

/// Fetch + re-plan the MPD for the synthesis inputs (the DASH half
/// of [`build_track_inputs`]); `Ok(None)` = the entry is HLS.
///
/// `dash_selection` = the selector ruling the **download** planned
/// under (the resolved [`DashSelection`] threaded from
/// `run_media_task` — not a re-derivation: the
/// download and the synthesis share one selection source by
/// construction). `Some` re-plans via
/// [`plan_dash_tracks_selected`] (the named representations);
/// `None` (the projection spellings / the no-selector form) keeps the
/// `--media-variant-policy` plan — the same ruling of record the
/// Resolving phase applied.
async fn dash_plan_for_synth(
    cfg: &MediaRunConfig,
    client: &HttpClient,
    ctx: &RequestCtx,
    dash_selection: Option<&taiji_media::mpd::DashSelection>,
) -> Result<Option<(taiji_media::mpd::Mpd, taiji_media::DashTrackPlan)>, MediaError> {
    // The MPD re-fetch rides the same SSRF face the manifest entry
    // did (the URL is first-order user input; no second-order walk
    // needed here — the expansion's absolute URIs are re-checked at
    // nothing: synthesis touches only staging).
    let bytes = http_get_bytes(client, &cfg.url, ctx).await?;
    if let Ok(taiji_media::ManifestFlavor::Dash) =
        taiji_media::m3u8::sniff(Some(&bytes), None, None)
    {
        let mpd = taiji_media::parse_mpd(&bytes)?;
        let track_set = taiji_media::TrackSetConfig {
            audio_lang: cfg.audio_lang.clone(),
            subtitles: cfg.subtitles,
            segment_concurrency: cfg.segment_concurrency,
        };
        let plan = match dash_selection {
            // The same selection the download planned under (a
            // different pick here would synthesize a representation
            // the archive never downloaded — the invariant this
            // threading exists to hold).
            Some(selection) => {
                taiji_media::mpd::plan_dash_tracks_selected(&mpd, &cfg.url, &track_set, selection)?
            }
            None => taiji_media::plan_dash_tracks(&mpd, &cfg.url, &track_set, &cfg.variant_policy)?,
        };
        return Ok(Some((mpd, plan)));
    }
    Ok(None)
}

/// Build the synthesis inputs (the synthesis `TrackInput` set) from the
/// download report + per-track ledger rows + a playlist re-fetch (the
/// e2e bridge shape: staging keeps archives + init sections; playlist
/// text re-reads from the source). `dash_selection` = the ruling the
/// download planned under (threaded so the DASH re-plan cannot pick a
/// different representation than the archive holds — a review-block
/// pin).
async fn build_track_inputs(
    client: &HttpClient,
    ctx: &RequestCtx,
    cfg: &MediaRunConfig,
    report: &taiji_media::MediaRunReport,
    ledger: &StoreMediaLedger,
    dash_selection: Option<&taiji_media::mpd::DashSelection>,
) -> Result<Vec<synth::TrackInput>, MediaError> {
    let staging = cfg.staging_gid_dir();
    let mut inputs = Vec::new();
    for (planned, state) in &report.tracks {
        if matches!(state, TrackState::Failed(_) | TrackState::Degraded(_)) {
            // A failed **or degraded** sidecar has no reliable
            // archive — synthesis runs on the delivered tracks
            // (degraded completion per the media spec). A review
            // round fixed this: the filter previously caught only
            // `Failed`, letting a
            // degraded sidecar's zero-byte archive reach
            // `rewrite_track` and terminalize the task as Error —
            // the wiring gap the flipped negative row pins. The
            // task's own terminal state follows the track-set
            // convergence verdict (degraded sidecars complete with
            // the warning events; the warning payloads already ride
            // the verdict's degraded list).
            continue;
        }
        // Track playlist: the HLS line re-fetches the rendition URI
        // (SSRF check first); the DASH line re-fetches the
        // MPD itself and re-expands the planned representation under
        // the SAME selection ruling the download used (the synthetic
        // playlist is derived, never fetched — its URIs are already
        // absolute; the sidx form cannot appear here: an incomplete
        // sidx track is Failed above).
        let playlist = match dash_plan_for_synth(cfg, client, ctx, dash_selection).await? {
            Some((mpd, plan)) => {
                let Some(pick) = plan.picks.get(planned.track_idx.min(plan.picks.len() - 1)) else {
                    return Err(MediaError::Staging(format!(
                        "dash plan carries no pick for track {}",
                        planned.label
                    )));
                };
                match taiji_media::expand_representation(&mpd, &cfg.url, pick)? {
                    taiji_media::Expanded::Ready(track) => track.playlist,
                    taiji_media::Expanded::DeferredSidx(_) => {
                        return Err(MediaError::Staging(format!(
                            "track {} reaches synthesis with an unmaterialized sidx",
                            planned.label
                        )));
                    }
                }
            }
            None => {
                check_playlist_uri(cfg, &planned.playlist_uri).await?;
                let bytes = http_get_bytes(client, &planned.playlist_uri, ctx).await?;
                match parse_manifest(&bytes)? {
                    Playlist::Media(m) => m,
                    Playlist::Master(_) => {
                        return Err(MediaError::ManifestParse(
                            "track playlist classified as master".to_string(),
                        ));
                    }
                }
            }
        };
        let Some((track, segments)) = ledger.load_track(&cfg.gid, planned.track_idx).await? else {
            return Err(MediaError::Staging(format!(
                "track {} missing from the ledger",
                planned.label
            )));
        };
        inputs.push(synth::TrackInput {
            label: planned.label.clone(),
            kind: planned.kind.as_str().to_string(),
            archive: staging.join(&track.local_name),
            inits: track.init_files.iter().map(|n| staging.join(n)).collect(),
            segments,
            playlist,
            archive_name: track.local_name.clone(),
        });
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SynthesisGate pair mechanics: the arrival notice fires
    /// once per call, a permit granted before the acquire resolves it
    /// immediately, an acquire-before-grant waits for the grant, and a
    /// dropped permit end surfaces as `Err` (the actor-gone defensive
    /// face the token race covers). Zero polling faces.
    #[tokio::test]
    async fn synthesis_gate_pair_grant_and_arrive() {
        let arrived = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let arrived_for_closure = Arc::clone(&arrived);
        let notice: SynthesisGateNotice = Arc::new(move || {
            let arrived = Arc::clone(&arrived_for_closure);
            Box::pin(async move {
                arrived.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        });
        let (permit, gate) = SynthesisGate::pair(notice);
        // Grant-before-acquire: the await resolves immediately.
        permit.grant();
        gate.arrive().await;
        assert_eq!(
            arrived.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the arrival notification fires exactly once"
        );
        gate.acquire()
            .await
            .unwrap_or_else(|e| panic!("granted permit resolves: {e}"));
        // The config-clone shape: a clone shares the same (now-taken)
        // wait end — the defensive re-acquire resolves granted, never
        // wedges.
        let clone = gate.clone();
        clone
            .acquire()
            .await
            .unwrap_or_else(|e| panic!("clone acquire resolves: {e}"));
        // Dropped permit end (no grant): the acquire errors.
        let (_permit, gate2) = SynthesisGate::pair(Arc::new(|| {
            Box::pin(async move {}) as futures::future::BoxFuture<'static, ()>
        }));
        drop(_permit);
        assert!(
            gate2.acquire().await.is_err(),
            "no grantee = Err (the actor-absence defense face)"
        );
    }

    /// The sample_aes spelling reconciliation's
    /// parse→core consistency pin (the rpc numeric leg rides the §14
    /// row list test in taiji-rpc/src/aria2/error.rs, which pins the same
    /// string verbatim): one SAMPLE-AES playlist drives the chain and
    /// every layer reports the SAME code string (the 0.3.0 wording —
    /// the spec's `sample_aes_pending` row takes the errata via the
    /// coordination face). A respelling at any layer breaks this test.
    #[test]
    fn sample_aes_spelling_consistent_from_parse_to_core() {
        let playlist = b"#EXTM3U\n\
#EXT-X-VERSION:3\n\
#EXT-X-TARGETDURATION:2\n\
#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"https://k.example/k\"\n\
#EXTINF:1.0,\n\
https://x.example/seg0.ts\n\
#EXT-X-ENDLIST\n";
        // Parse face: SAMPLE-AES is refused at parse time.
        let err = parse_manifest(playlist)
            .err()
            .unwrap_or_else(|| panic!("SAMPLE-AES must be refused at parse time"));
        // Media layer: code() and the Display text agree on the
        // string of record.
        assert_eq!(err.code(), "taiji.media.sample_aes_unsupported");
        assert!(
            err.to_string()
                .starts_with("taiji.media.sample_aes_unsupported:"),
            "the Display text embeds the code verbatim: {err}"
        );
        // Core layer: failure_code_of extracts the same code from the
        // pipeline error text (and its KNOWN table carries it — a
        // missing row would fall back to a transport code).
        assert_eq!(
            failure_code_of(&err.to_string()),
            "taiji.media.sample_aes_unsupported",
            "core's failure_code_of extracts the media code, not a fallback"
        );
    }

    /// The in-flight cap (§10 #7): the third concurrent admission is
    /// refused while two are live; the slot frees on drop.
    #[test]
    fn probe_inflight_cap_is_two() {
        let face = ProbeFace::new();
        let g1 = face
            .acquire_inflight()
            .unwrap_or_else(|| panic!("the first slot is free"));
        let g2 = face
            .acquire_inflight()
            .unwrap_or_else(|| panic!("the second slot is free"));
        assert!(
            face.acquire_inflight().is_none(),
            "the global in-flight cap is 2 — a third probe is refused"
        );
        drop(g2);
        let g3 = face
            .acquire_inflight()
            .unwrap_or_else(|| panic!("the slot frees on drop"));
        drop(g1);
        drop(g3);
    }

    /// The per-origin rate limit: one admission per origin per second;
    /// a distinct origin is not throttled by another's window.
    #[test]
    fn probe_rate_limit_is_per_origin() {
        let face = ProbeFace::new();
        let now = Instant::now();
        assert!(face.admit_rate("https://a.test/m.m3u8", now).is_ok());
        assert!(face.admit_rate("https://a.test/other.m3u8", now).is_err());
        assert!(
            face.admit_rate("https://b.test/m.m3u8", now).is_ok(),
            "distinct origins are independent"
        );
        // After the window the origin is admitted again.
        assert!(
            face.admit_rate(
                "https://a.test/m.m3u8",
                now + PROBE_ORIGIN_INTERVAL + Duration::from_millis(1)
            )
            .is_ok()
        );
    }

    /// The token cache's TTL + anti-forgery posture: unknown token /
    /// expired token / URL-mismatched token all present the
    /// `probe_expired` face (§4 — a client can name a token, never
    /// hand back a format tree; the OptionInvalid carrier keeps the
    /// canonical code in the text).
    #[test]
    fn probe_token_cache_ttl_and_antiforgery() {
        let face = ProbeFace::new();
        let tree = FormatTree {
            url: "https://a.test/m.m3u8".into(),
            kind: "hls".into(),
            formats: Vec::new(),
        };
        let token = face.store("https://a.test/m.m3u8", tree.clone(), false);
        let snap = face
            .consume(&token, "https://a.test/m.m3u8")
            .unwrap_or_else(|e| panic!("consumes: {e}"));
        assert_eq!(snap.url, tree.url);
        // Unknown token.
        let err = face
            .consume("ffffffffffffffffffffffffffffffff", "https://a.test/m.m3u8")
            .err()
            .unwrap_or_else(|| panic!("an unknown token never consumes"));
        assert!(err.to_string().contains("taiji.media.probe_expired"));
        // URL mismatch.
        let err = face
            .consume(&token, "https://other.test/m.m3u8")
            .err()
            .unwrap_or_else(|| panic!("a cross-URL token never consumes"));
        assert!(err.to_string().contains("taiji.media.probe_expired"));
        // TTL expiry: a snapshot born past the TTL is dropped at
        // consume (the lazy-GC face).
        let mut cache = face
            .cache
            .lock()
            .unwrap_or_else(|e| panic!("probe cache: {e}"));
        let key = cache
            .keys()
            .next()
            .cloned()
            .unwrap_or_else(|| panic!("the token is cached"));
        if let Some(s) = cache.get_mut(&key) {
            s.born = Instant::now() - PROBE_TTL - Duration::from_secs(1);
        }
        drop(cache);
        let err = face
            .consume(&key, "https://a.test/m.m3u8")
            .err()
            .unwrap_or_else(|| panic!("an expired token never consumes"));
        assert!(err.to_string().contains("taiji.media.probe_expired"));
    }

    /// The config_json snapshot round-trips field-for-field (the §8
    /// recovery replay contract: a kill + restart or an Error→unpause
    /// re-resolve must not silently drop task options). Regression
    /// face for the key-name drift class: the write side once used
    /// `sub_lang` while the read side looked for `sub-lang`
    /// (subtitle_lang silently lost → the language filter degraded to
    /// the full subtitle set), and `ffmpeg_path` was written as a
    /// Debug string while the read side kept `Auto` — both pinned
    /// here member-for-member.
    #[test]
    fn media_config_round_trip_all_fields() {
        let mk_row = |cfg: &MediaRunConfig| taiji_store::persist::MediaTaskRow {
            gid: cfg.gid.clone(),
            kind: "hls".into(),
            manifest_url: cfg.url.clone(),
            state: "downloading".into(),
            phase_detail_json: None,
            variant_json: None,
            selector_json: cfg.selector.clone(),
            output_name: None,
            bridge_json: None,
            staging_dir: cfg.staging_gid_dir().display().to_string(),
            output_path: cfg.output_dir.display().to_string(),
            manifest_norm_digest: Vec::new(),
            total_done: 0,
            config_json: media_config_json(cfg),
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        };
        for ffmpeg_path in [
            FfmpegPathSpec::Auto,
            FfmpegPathSpec::Explicit(PathBuf::from("/opt/ff")),
            FfmpegPathSpec::PathOptIn(PathBuf::from("/usr/local/bin")),
        ] {
            for (muxer, output_format, subtitles) in [
                (MuxerSpec::Auto, OutputFormat::Mp4, SubtitleMode::Sidecar),
                (MuxerSpec::Native, OutputFormat::Mkv, SubtitleMode::None),
                (MuxerSpec::Ffmpeg, OutputFormat::Mp4, SubtitleMode::Sidecar),
            ] {
                for variant_policy in [
                    taiji_media::VariantPolicy::Highest,
                    taiji_media::VariantPolicy::Resolution { height: 720 },
                    taiji_media::VariantPolicy::Bandwidth {
                        bits_per_second: 5_000_000,
                    },
                ] {
                    let cfg = MediaRunConfig {
                        gid: "80000000000000b1".into(),
                        url: "https://x.test/m.m3u8".into(),
                        output_dir: PathBuf::from("/dl"),
                        out: Some("clip".into()),
                        selector: Some("res<=720 codec!=hvc1".into()),
                        variant_policy,
                        audio_lang: Some("zh-hans".into()),
                        subtitles,
                        subtitle_lang: Some("de".into()),
                        template: Some("{id}-{res}.{ext}".into()),
                        no_metadata: true,
                        archive: true,
                        info_json: true,
                        cookies: Vec::new(),
                        allow_private_key_url: true,
                        segment_concurrency: 16,
                        staging_quota_gib: 9,
                        staging_dir: Some(PathBuf::from("/stage")),
                        ffmpeg_path: ffmpeg_path.clone(),
                        muxer,
                        output_format,
                        restore: None,
                        probe_snapshot: None,
                        persist: None,
                        ffmpeg: None,
                        resolver: None,
                        recovered_tree: None,
                        gate: None,
                    };
                    let back = media_config_from_row(&mk_row(&cfg));
                    assert_eq!(back.out, cfg.out, "out");
                    assert_eq!(back.selector, cfg.selector, "selector");
                    assert_eq!(back.audio_lang, cfg.audio_lang, "audio_lang");
                    assert_eq!(back.subtitles, cfg.subtitles, "subtitles");
                    assert_eq!(
                        back.subtitle_lang, cfg.subtitle_lang,
                        "sub-lang round-trips (the key-drift regression face)"
                    );
                    assert_eq!(back.template, cfg.template, "template");
                    assert_eq!(back.no_metadata, cfg.no_metadata, "no_metadata");
                    assert_eq!(back.archive, cfg.archive, "media_archive");
                    assert_eq!(back.info_json, cfg.info_json, "media_info_json");
                    assert_eq!(
                        back.variant_policy, cfg.variant_policy,
                        "variant_policy round-trips in all three flag shapes"
                    );
                    assert_eq!(
                        back.allow_private_key_url, cfg.allow_private_key_url,
                        "allow_private_key_url"
                    );
                    assert_eq!(back.segment_concurrency, cfg.segment_concurrency);
                    assert_eq!(back.staging_quota_gib, cfg.staging_quota_gib);
                    assert_eq!(back.staging_dir, cfg.staging_dir, "staging_dir");
                    assert_eq!(
                        back.ffmpeg_path, cfg.ffmpeg_path,
                        "ffmpeg_path round-trips in all three spec shapes"
                    );
                    assert_eq!(back.muxer, cfg.muxer, "muxer");
                    assert_eq!(back.output_format, cfg.output_format, "output_format");
                }
            }
        }
    }

    /// The failure-code table: known canonical codes pass through; a
    /// bare transport text falls back to the transport code (never a
    /// fabricated code).
    #[test]
    fn failure_code_table() {
        assert_eq!(
            failure_code_of("taiji.media.ssrf_blocked: refused"),
            "taiji.media.ssrf_blocked"
        );
        assert_eq!(
            failure_code_of("taiji.media.staging_quota_exceeded: x"),
            "taiji.media.staging_quota_exceeded"
        );
        assert_eq!(
            failure_code_of("connection reset by peer"),
            "taiji.http.transport"
        );
    }
}

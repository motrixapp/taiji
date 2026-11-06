//! Per-track download drivers — the (a)/(b) transport layers
//! (the media spec's download line, layers (a) and (b); LIVE
//! (c) is out of scope).
//!
//! Both layers are **pure consumers of the 0.2 foundation crate**:
//! no private scheduler/transport implementation lives here —
//! the consumption list and the mismatch path are on record in
//! `docs/design/media-base-consumption.md`.
//!
//! * **(a) known-length tracks** (every segment carries an explicit
//! BYTERANGE): the segments map onto one virtual byte space
//! ([`layout_known_length`]), the base's block grid +
//! ExtentCoordinator (guided scheduling, stall-window config, AIMD
//! book) + HttpRangeTransport carry it — full grid/bitmap resume
//! reuse. Adjacent sub-segment merging is enabled here through the
//! parser's runs data structure: the layout folds the ≤8 runs into **maximal
//! same-URI contiguous spans**, and each span∩extent piece is
//! exactly one Range GET (the wire-level merge, ≤8 sub-segments per
//! GET by construction of the runs).
//! * **(b) unknown-length tracks**: no grid — the base's
//! [`SequenceEngine`](taiji_http::sequence) takes the URIs in
//! order with bounded out-of-order lookahead; the checkpoint unit
//! is the segment (`seg_bitmap`), no offset resume inside a
//! segment (the no-range degraded precedent).
//!
//! Init sections (EXT-X-MAP) are fetched before the track body into
//! their own staging files (the `init-<track>-<n>.mp4` name face);
//! per-segment MAP bookkeeping lands in the ledger rows (multi-MAP
//! boundaries are the rewrite step's input).
//!
//! Upstream anchor mapping: docs/design/media-base-consumption.md

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use bytes::Bytes;
use futures::future::BoxFuture;

use taiji_http::client::HttpClient;
use taiji_http::coordinator::{self, CoordinatorHandle};
use taiji_http::error::HttpError;
use taiji_http::grid::BlockGrid;
use taiji_http::limiter::{HttpLimiter, ThrottledSink};
use taiji_http::partfile::{FileAllocation, PartFile, PartOpenPolicy};
use taiji_http::pool::WorkerPool;
use taiji_http::scheduler::{GuidedConfig, GuidedPlan};
use taiji_http::sequence::{self, SequenceConfig, SequenceSink, TransportFor};
use taiji_http::transport::{HttpBodyTransport, HttpRangeTransport};
use taiji_io::metrics::registry_default;
use taiji_segment::traits::{Extent, RequestCtx, SegId, SegmentSink, SegmentTransport};

use crate::error::MediaError;
use crate::keys::{InitCrypto, SegCrypto, TrackCrypto};
use crate::m3u8::model::{ByteRange, MediaPlaylist, MediaSegment};
use crate::m3u8::strip_query;
use crate::staging::{TrackArchive, init_section_path, reconcile_boundary};

/// Per-track fetch configuration (the wired flag faces + the base's
/// per-extent retry semantics).
#[derive(Clone, Debug)]
pub struct TrackFetchConfig {
    /// `--media-segment-concurrency` (workers per track; the AIMD
    /// growth cap for (a), the worker count for (b)).
    pub concurrency: u32,
    /// Per-segment / per-extent failure budget (the base's
    /// `--max-tries` semantics).
    pub max_tries: u32,
    /// Retry backoff between attempts.
    pub retry_wait: Duration,
    /// In-track staging-quota probe: the 30s watchdog's
    /// violated flag + an on-demand watermark query, consumed at the
    /// (a)/(b) drivers' segment boundaries — a violation mid-track
    /// fails the track (and the driver escalates it to the task-level
    /// `taiji.media.staging_quota_exceeded` terminal) instead of
    /// waiting for the whole track to finish. `None` = no probe
    /// (pure library use; the pre-probe behavior).
    pub watermark: Option<WatermarkProbe>,
}

/// The in-track watermark probe: consults the
/// watchdog-flipped `violated` flag **and** the live watermark
/// (`staging_usage_bytes` vs the quota — a sparse `set_len` or a big
/// BYTERANGE trips it without waiting for the 30s tick). Granularity
/// /cost semantics: one probe per delivered segment at the (b)-layer
/// delivery boundary, one per ~100ms driver tick at the (a)-layer
/// supervisor loop — a staging-tree metadata walk each (a handful of
/// files), never per byte.
#[derive(Clone, Debug)]
pub struct WatermarkProbe {
    violated: Arc<std::sync::atomic::AtomicBool>,
    quota: crate::staging::StagingQuota,
    root: std::path::PathBuf,
}

impl WatermarkProbe {
    /// Assemble from the driver's watchdog flag + quota + staging
    /// root.
    pub fn new(
        violated: Arc<std::sync::atomic::AtomicBool>,
        quota: crate::staging::StagingQuota,
        root: std::path::PathBuf,
    ) -> Self {
        Self {
            violated,
            quota,
            root,
        }
    }

    /// Whether the staging watermark is violated right now.
    pub fn violated_now(&self) -> bool {
        self.violated.load(std::sync::atomic::Ordering::Acquire)
            || self
                .quota
                .check(crate::staging::staging_usage_bytes(&self.root), 0)
                .is_err()
    }

    /// The canonical failure text (the inherited
    /// `taiji.media.staging_quota_exceeded` face; the sequence-sink
    /// variant is `HttpError`-shaped, the (a)-loop variant String).
    fn err_text(&self) -> String {
        let usage = crate::staging::staging_usage_bytes(&self.root);
        format!(
            "taiji.media.staging_quota_exceeded: in-track staging watermark: usage \
             {usage} exceeds quota {}",
            self.quota.limit_bytes
        )
    }
}

impl Default for TrackFetchConfig {
    fn default() -> Self {
        Self {
            concurrency: crate::options::DEFAULT_SEGMENT_CONCURRENCY,
            max_tries: 5,
            retry_wait: Duration::from_millis(250),
            watermark: None,
        }
    }
}

/// One segment's ledger record (the `media_segment` row payload;
/// `validator_digest` = SHA-256 over the normalized source identity —
/// query-stripped URI + resolved byte range + absolute media
/// sequence, the 0.4 signature-refresh/structure-diff consumption
/// face written from day one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRecord {
    /// 0-based index within the track (playlist order).
    pub seg_idx: usize,
    /// Absolute media sequence (the identity/IV key; HLS always
    /// carries it — `media_sequence + seg_idx`).
    pub media_sequence: u64,
    /// Segment URI verbatim.
    pub uri: String,
    /// Resolved `length@offset` text when BYTERANGE applies.
    pub byte_range: Option<String>,
    /// `media_key.id` of the segment's key (`None` = plaintext
    /// — no key or the explicit METHOD=NONE reset).
    pub key_id: Option<i64>,
    /// Effective length on disk (**plaintext** length — the archive
    /// holds decrypted bytes; 0 until an unknown-length segment is
    /// delivered).
    pub seg_len: u64,
    /// EXTINF duration, milliseconds.
    pub duration_ms: u64,
    /// EXT-X-MAP init-section ordinal in force (`None` = no MAP).
    pub map: Option<usize>,
    /// Normalized-identity digest (see type docs).
    pub validator_digest: Vec<u8>,
}

/// Track ledger record (the `media_track` row payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackRecord {
    /// 0-based track ordinal (the persistence key).
    pub track_idx: usize,
    /// video|audio|subtitle.
    pub kind: String,
    /// Rendition playlist URI.
    pub playlist_uri: String,
    /// Archive file name inside staging.
    pub local_name: String,
    /// Init-section file names (appearance order).
    pub init_files: Vec<String>,
    /// Segment bitmap (bit per segment, packed LSB-first; prefix
    /// domain).
    pub seg_bitmap: Vec<u8>,
    /// Segment count.
    pub seg_count: usize,
}

/// Minimal media-task parent record (the `media_task` row payload —
/// the FK anchor for track/segment rows; the orchestration state
/// machine on top is the session's, the driver writes the row so children can
/// reference it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaTaskRecord {
    pub gid: String,
    /// `hls` / `dash`.
    pub kind: String,
    pub manifest_url: String,
    /// Row state text (queued|resolving|downloading|…; the driver
    /// writes `downloading` while tracks run).
    pub state: String,
    pub staging_dir: String,
    pub output_path: String,
    /// Normalized manifest digest (parser face).
    pub manifest_norm_digest: Vec<u8>,
    pub config_json: String,
}

/// A loaded track's rows (the recovery read reply shape).
pub type LoadedTrack = Option<(TrackRecord, Vec<SegmentRecord>)>;

/// The persistence face the drivers consume (implemented by the
/// store-side writer; the production assembly is the session's mount, the
/// e2e wires the real sqlite writer).
pub trait MediaLedger: Send + Sync {
    /// Insert/refresh the parent task row (FK anchor; called before
    /// any track row).
    fn ensure_task<'a>(&'a self, row: &'a MediaTaskRecord)
    -> BoxFuture<'a, Result<(), MediaError>>;
    /// Persist one track row + its whole segment set (single-call
    /// replace semantics; bitmap updates included).
    fn save_track<'a>(
        &'a self,
        gid: &'a str,
        track: &'a TrackRecord,
        segments: &'a [SegmentRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>>;
    /// Load one track's rows back (recovery face).
    fn load_track<'a>(
        &'a self,
        gid: &'a str,
        track_idx: usize,
    ) -> BoxFuture<'a, Result<LoadedTrack, MediaError>>;
    /// Upsert the task's key rows (the media_key face; stable row
    /// ids — `media_segment.key_id` references them).
    fn upsert_media_keys<'a>(
        &'a self,
        gid: &'a str,
        keys: &'a [crate::keys::KeyRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>>;
    /// Load the task's key rows back (the restart face: keys already
    /// in the DB are never re-fetched).
    fn load_media_keys<'a>(
        &'a self,
        gid: &'a str,
    ) -> BoxFuture<'a, Result<Vec<crate::keys::KeyRecord>, MediaError>>;
}

/// A maximal same-URI contiguous fetch span (the ≤8 merge runs folded
/// together: two runs of the same URI whose resource bytes touch are
/// one GET — the merge cap limits *runs*, never the GET).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchSpan {
    /// Resource URI.
    pub uri: String,
    /// Byte offset inside the resource.
    pub res_offset: u64,
    /// Span length in bytes.
    pub len: u64,
    /// Virtual-space start (the archive offset).
    pub virt_start: u64,
    /// First segment index (playlist order).
    pub first_seg: usize,
    /// Segment count (≥1; may exceed the run cap when runs folded).
    pub segments: usize,
}

/// The (a)-layer virtual layout: all segments concatenated in
/// playlist order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanLayout {
    /// Total virtual length (== archive length).
    pub total: u64,
    /// Per-segment virtual offsets (lengths by difference).
    pub seg_offsets: Vec<u64>,
    /// Per-segment byte ranges (as resolved).
    pub seg_ranges: Vec<ByteRange>,
    /// Maximal fetch spans.
    pub spans: Vec<FetchSpan>,
}

/// Verdict: does the playlist qualify for the (a) layer?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackLayer {
    /// All segments carry explicit BYTERANGE → known total length.
    KnownLength,
    /// At least one segment is whole-resource → the (b) layer.
    UnknownLength,
}

/// Classify: (a) iff every segment has an explicit byte range.
pub fn classify_track(playlist: &MediaPlaylist) -> TrackLayer {
    if playlist.segments.iter().all(|s| s.byte_range.is_some()) {
        TrackLayer::KnownLength
    } else {
        TrackLayer::UnknownLength
    }
}

/// Build the virtual layout for a known-length track. Segments are
/// laid out in playlist order; adjacent segments of the same URI with
/// touching resource bytes fold into one maximal span (the ≤8
/// runs merged at the transport face).
pub fn layout_known_length(playlist: &MediaPlaylist) -> Result<SpanLayout, MediaError> {
    let mut seg_offsets = Vec::with_capacity(playlist.segments.len());
    let mut seg_ranges = Vec::with_capacity(playlist.segments.len());
    let mut spans: Vec<FetchSpan> = Vec::new();
    let mut total = 0u64;
    for (idx, seg) in playlist.segments.iter().enumerate() {
        let Some(br) = seg.byte_range else {
            return Err(MediaError::Staging(format!(
                "known-length layout on a whole-resource segment at index {idx}"
            )));
        };
        seg_offsets.push(total);
        seg_ranges.push(br);
        let extends = matches!(spans.last(), Some(last)
            if last.uri == seg.uri
                && last.res_offset.checked_add(last.len) == Some(br.offset));
        if extends && let Some(last) = spans.last_mut() {
            last.len = last.len.saturating_add(br.length);
            last.segments += 1;
        } else {
            spans.push(FetchSpan {
                uri: seg.uri.clone(),
                res_offset: br.offset,
                len: br.length,
                virt_start: total,
                first_seg: idx,
                segments: 1,
            });
        }
        total = total.saturating_add(br.length);
    }
    Ok(SpanLayout {
        total,
        seg_offsets,
        seg_ranges,
        spans,
    })
}

/// Segment ledger rows for a playlist (plan-time build; the
/// validator digest uses the normalized identity — query stripped).
pub fn segment_records(playlist: &MediaPlaylist) -> Vec<SegmentRecord> {
    playlist
        .segments
        .iter()
        .map(|seg| SegmentRecord {
            seg_idx: seg_index_of(playlist, seg),
            media_sequence: seg.sequence,
            uri: seg.uri.clone(),
            byte_range: seg
                .byte_range
                .map(|br| format!("{}@{}", br.length, br.offset)),
            key_id: None,
            seg_len: seg.byte_range.map_or(0, |br| br.length),
            duration_ms: duration_ms(seg),
            map: seg.map,
            validator_digest: validator_digest(seg),
        })
        .collect()
}

fn seg_index_of(playlist: &MediaPlaylist, seg: &MediaSegment) -> usize {
    // The parser guarantees sequence == media_sequence + appearance
    // index; recover the index arithmetically (avoid a linear scan).
    seg.sequence
        .checked_sub(playlist.media_sequence)
        .map(|i| i as usize)
        .unwrap_or(0)
}

fn duration_ms(seg: &MediaSegment) -> u64 {
    (seg.duration * 1000.0).round() as u64
}

/// Normalized-identity digest (SHA-256 over
/// `hls-segment/1 \n path \n length@offset \n sequence`; the
/// query-stripped path makes CDN signature rewrites digest-stable —
/// the 0.4 structure-diff face).
fn validator_digest(seg: &MediaSegment) -> Vec<u8> {
    let mut text = String::from("hls-segment/1\n");
    text.push_str(strip_query(&seg.uri));
    text.push('\n');
    if let Some(br) = seg.byte_range {
        text.push_str(&format!("{}@{}\n", br.length, br.offset));
    } else {
        text.push_str("*\n");
    }
    text.push_str(&seg.sequence.to_string());
    crate::m3u8::digest::sha256(text.as_bytes()).to_vec()
}

/// A track run's outcome (always produced — a failed fetch still
/// reports the delivered prefix so the ledger persists resumable
/// progress; `error` carries the failure text when the run did not
/// complete).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackRunResult {
    /// Archive length on disk.
    pub archive_len: u64,
    /// Per-segment ledger rows (seg_len filled).
    pub segments: Vec<SegmentRecord>,
    /// Segment bitmap bytes (packed LSB-first prefix).
    pub seg_bitmap: Vec<u8>,
    /// Init files written (staging names).
    pub init_files: Vec<String>,
    /// `Some(text)` = the run failed after its retry budget; the
    /// bitmap/lengths above are the durable prefix.
    pub error: Option<String>,
}

/// Pack a done-prefix bitmap (bit per segment, LSB-first).
pub fn pack_bitmap(done: usize, total: usize) -> Vec<u8> {
    let bytes = total.div_ceil(8);
    let mut v = vec![0u8; bytes];
    for i in 0..done.min(total) {
        v[i / 8] |= 1 << (i % 8);
    }
    v
}

/// Unpack a bitmap's done-prefix length (counts the leading set-bit
/// run; a cleared bit ends the prefix — resume domains are prefixes).
pub fn unpack_bitmap_prefix(bitmap: &[u8]) -> usize {
    let mut done = 0usize;
    for (i, byte) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if byte & (1 << bit) != 0 {
                done += 1;
            } else {
                return done;
            }
            let _ = i;
        }
    }
    done
}

// ---------------------------------------------------------------------------
// (b) unknown-length track: the base sequence engine + ordered append
// ---------------------------------------------------------------------------

/// Decrypt one delivered body under its segment descriptor
/// (decrypt-as-consume — the archive only ever receives
/// plaintext). A decrypt failure maps to the transport error face
/// carrying the canonical `taiji.media.segment_decrypt_failed` text so
/// the sequence engine's retry budget covers the re-fetch (the card's
/// "retry once" face — a truncated delivery can produce a
/// non-block-length body that a re-fetch repairs).
///
/// Zero-copy on the plaintext arm: the delivered `Bytes` passes through
/// untouched (reference-counted hand-off to the archive write); only
/// the AES arm allocates (the decrypt output — inherent).
fn decrypt_body(index: u64, body: Bytes, crypto: &[SegCrypto]) -> Result<Bytes, HttpError> {
    match crypto.get(index as usize) {
        Some(SegCrypto::Aes { key, iv, .. }) => crate::decrypt::decrypt_segment(key, iv, &body)
            .map(Bytes::from)
            .map_err(|e| HttpError::Transport(format!("segment {index}: {e}"))),
        _ => Ok(body),
    }
}

/// The sequence-engine sink: ordered delivery → decrypt → archive
/// append + ledger fill + bitmap advance. One instance per track; the
/// engine's drain lock serializes `segment_complete` calls, so the
/// inner state needs no extra lock (the async mutex only bridges the
/// async write face).
struct ArchiveSeqSink {
    archive: tokio::sync::Mutex<TrackArchive>,
    state: StdMutex<SeqState>,
    crypto: Vec<SegCrypto>,
    /// In-track watermark probe: consulted at every
    /// segment-delivery boundary — the (b)-layer's segment
    /// checkpoint.
    watermark: Option<WatermarkProbe>,
}

struct SeqState {
    /// Delivered count (prefix).
    delivered: usize,
    /// Per-segment lengths (filled on delivery).
    lens: Vec<u64>,
    /// Delivered bytes so far (watermark feed).
    bytes: u64,
}

impl ArchiveSeqSink {
    /// `initial_lens` seeds the per-segment length bookkeeping with the
    /// ledger's lengths — the resumed prefix keeps its persisted
    /// values (zero only for the undelivered tail), so the post-run
    /// ledger writeback never zeroes the resumed prefix. The unseeded
    /// form violated the acceptance-① invariant in the resume shape:
    /// Σseg_len collapsed to this-run bytes, and the zeroed prefix
    /// rows then demoted a full bitmap to keep_count=0 at the next
    /// reconcile — truncating a completed archive and re-fetching
    /// every segment.
    fn new(
        archive: TrackArchive,
        initial_lens: Vec<u64>,
        crypto: Vec<SegCrypto>,
        watermark: Option<WatermarkProbe>,
    ) -> Self {
        let delivered = archive.next_index() as usize;
        Self {
            archive: tokio::sync::Mutex::new(archive),
            state: StdMutex::new(SeqState {
                delivered,
                lens: initial_lens,
                bytes: 0,
            }),
            crypto,
            watermark,
        }
    }

    fn delivered(&self) -> usize {
        crate_lock_state(&self.state).delivered
    }

    fn lens(&self) -> Vec<u64> {
        crate_lock_state(&self.state).lens.clone()
    }

    /// Archive length = bytes on disk (the append cursor), independent
    /// of the lens bookkeeping — the field's documented meaning.
    async fn archive_len(&self) -> u64 {
        self.archive.lock().await.len()
    }
}

fn crate_lock_state(s: &StdMutex<SeqState>) -> std::sync::MutexGuard<'_, SeqState> {
    // Small, held-nanos-at-a-time guard; poisoning is unreachable
    // (no panic paths inside) — recover via into_inner for the read
    // faces only.
    s.lock().unwrap_or_else(|e| e.into_inner())
}

impl SequenceSink for ArchiveSeqSink {
    fn segment_complete(&self, index: u64, body: Bytes) -> BoxFuture<'_, Result<(), HttpError>> {
        Box::pin(async move {
            // In-track watermark checkpoint: the
            // delivery boundary is the (b)-layer's segment-granular
            // consumption point — a violated staging quota fails the
            // delivery (the engine's deliver-error face ends the run;
            // the driver escalates to the task-level terminal). The
            // text carries the canonical inherited code.
            if let Some(probe) = &self.watermark
                && probe.violated_now()
            {
                return Err(HttpError::Transport(probe.err_text()));
            }
            // Decrypt-as-consume: the plaintext is what lands
            // in the archive and the ledger lengths — a decrypt failure
            // fails the delivery (the engine re-fetches under its
            // budget; the final failure text carries the canonical
            // segment_decrypt_failed code). The plaintext hand-off is
            // zero-copy end to end (Bytes in, Bytes out, archive write
            // consumes the same buffer).
            let plain = decrypt_body(index, body, &self.crypto)?;
            let plain_len = plain.len();
            let mut archive = self.archive.lock().await;
            archive
                .append_bytes(index, plain)
                .await
                .map_err(|e| HttpError::Transport(format!("archive append: {e}")))?;
            let mut st = crate_lock_state(&self.state);
            if (index as usize) < st.lens.len() {
                st.lens[index as usize] = plain_len as u64;
            }
            st.delivered = (index as usize) + 1;
            st.bytes += plain_len as u64;
            Ok(())
        })
    }
}

/// Fetch one init section and decrypt it when its crypto descriptor
/// says so (MAP-covered init sections decrypt before staging —
/// the `init-<track>-<n>.mp4` files hold plaintext; MAP-after-KEY =
/// encrypted init, MAP-before-KEY = plaintext, resolved by the
/// parser's positional boundary). Decrypt failures retry the fetch
/// once (a truncated delivery can corrupt the last block — the same
/// retry-once face as media segments).
async fn fetch_init_section(
    client: &HttpClient,
    ctx: &RequestCtx,
    uri: &str,
    range: Option<ByteRange>,
    crypto: Option<&InitCrypto>,
) -> Result<Vec<u8>, MediaError> {
    let body = fetch_whole_or_range(client, ctx, uri, range).await?;
    match crypto {
        None => Ok(body),
        Some(c) => match crate::decrypt::decrypt_segment(&c.key, &c.iv, &body) {
            Ok(plain) => Ok(plain),
            Err(first) => {
                let retried = fetch_whole_or_range(client, ctx, uri, range).await?;
                crate::decrypt::decrypt_segment(&c.key, &c.iv, &retried).map_err(|_| {
                    MediaError::SegmentDecryptFailed(format!(
                        "init section {} (first attempt: {first})",
                        strip_query(uri)
                    ))
                })
            }
        },
    }
}

/// Run one unknown-length track (the (b) layer): fetch init sections,
/// then the sequence engine over the segment URIs; whole-resource
/// segments ride the base body transport, BYTERANGE sub-ranges the
/// base Range transport (per-segment choice, resolved URIs). Segment
/// bodies decrypt at the delivery boundary ([`ArchiveSeqSink`] — the
/// archive is plaintext from the first byte).
#[expect(
    clippy::too_many_arguments,
    reason = "the track-driver face carries the whole per-track surface explicitly (base precedent: launch_worker)"
)]
pub async fn download_unknown_length_track(
    client: &HttpClient,
    ctx: &RequestCtx,
    playlist: &MediaPlaylist,
    resolved: &(dyn Fn(&str) -> String + Send + Sync),
    crypto: &TrackCrypto,
    archive_path: &Path,
    init_dir: &Path,
    track_label: &str,
    cfg: &TrackFetchConfig,
    resume: Option<TrackRunResult>,
) -> Result<TrackRunResult, MediaError> {
    // Init sections first (the name face; their failure fails the
    // track — the init section is part of the selected presentation).
    let mut init_files = Vec::new();
    for init in &playlist.init_sections {
        let path = init_section_path(init_dir, track_label, init.index);
        let uri = resolved(&init.uri);
        let body = fetch_init_section(
            client,
            ctx,
            &uri,
            init.byte_range,
            crypto.inits.get(init.index).and_then(|c| c.as_ref()),
        )
        .await?;
        crate::staging::write_file(&path, &body)?;
        init_files.push(crate::m3u8::init_section_filename(track_label, init.index));
    }

    let mut segments = segment_records(playlist);
    // Ledger key references (media_segment.key_id).
    for (i, seg) in segments.iter_mut().enumerate() {
        seg.key_id = crypto.segments.get(i).and_then(|c| c.db_id());
    }
    let mut resume_prefix = 0usize;
    let mut archive_resume = None;
    if let Some(prev) = &resume {
        // Recovery invariant: reconcile the persisted bitmap against
        // the archive length, truncate to the boundary. The persisted
        // lengths are already plaintext (one semantics with the archive).
        let lens: Vec<u64> = prev.segments.iter().map(|s| s.seg_len).collect();
        let bitmap_prefix = unpack_bitmap_prefix(&prev.seg_bitmap);
        let archive_len = std::fs::metadata(archive_path).map_or(0, |m| m.len());
        let rec = reconcile_boundary(archive_len, bitmap_prefix, &lens);
        resume_prefix = rec.keep_count;
        archive_resume = Some(rec);
        // Adopt the known lengths from the ledger (the tail keeps 0).
        for (i, seg) in prev.segments.iter().enumerate() {
            if let Some(dst) = segments.get_mut(i) {
                dst.seg_len = seg.seg_len;
            }
        }
    }
    let archive = TrackArchive::open(archive_path.to_path_buf(), archive_resume).await?;
    let seg_count = playlist.segments.len();
    // Seed the sink's length bookkeeping with the ledger-adopted
    // lengths (the resumed prefix's persisted values; zero for the
    // undelivered tail) — see ArchiveSeqSink::new.
    let sink = Arc::new(ArchiveSeqSink::new(
        archive,
        segments.iter().map(|s| s.seg_len).collect(),
        crypto.segments.clone(),
        cfg.watermark.clone(),
    ));

    // Per-index transport: whole-resource → body transport;
    // BYTERANGE → Range transport at the sub-range (base faces both
    // ways; the collector body is exactly the segment bytes).
    let metrics = registry_default();
    let uris_and_ranges: Vec<(String, Option<ByteRange>)> = playlist
        .segments
        .iter()
        .map(|s| (resolved(&s.uri), s.byte_range))
        .collect();
    let client_c = client.clone();
    let transport_for: TransportFor = Arc::new(move |index: u64| {
        let (uri, range) = uris_and_ranges
            .get(index as usize)
            .cloned()
            .unwrap_or_default();
        match range {
            Some(br) => {
                let t = HttpRangeTransport::new(client_c.clone(), uri, None, 0, registry_default());
                let _ = &metrics;
                Arc::new(RangeOnceTransport {
                    inner: t,
                    range: br,
                }) as Arc<dyn SegmentTransport>
            }
            None => Arc::new(HttpBodyTransport::new(
                client_c.clone(),
                uri,
                registry_default(),
            )) as Arc<dyn SegmentTransport>,
        }
    });

    let seq_cfg = SequenceConfig {
        workers: cfg.concurrency.max(1),
        max_tries: cfg.max_tries,
        retry_wait: cfg.retry_wait,
        // The download-line anchors (the shared in-flight window budget
        // + the per-segment valve; the engine defaults).
        ..SequenceConfig::default()
    };
    let is_done = |i: u64| (i as usize) < resume_prefix;
    let run_outcome = sequence::run_sequence(
        playlist.segments.iter().map(|s| s.uri.clone()).collect(),
        &seq_cfg,
        &is_done,
        transport_for,
        ctx,
        sink.clone(),
    )
    .await;
    let error = run_outcome.err().map(|e| format!("segment fetch: {e}"));

    // Durability before the ledger record (the carried-over ordering
    // discipline: the bitmap never runs ahead of data) —
    // on the failed path too, so the durable prefix is resumable.
    {
        let archive = sink.archive.lock().await;
        archive
            .sync()
            .await
            .map_err(|e| MediaError::Staging(format!("archive fsync: {e}")))?;
    }
    let lens = sink.lens();
    // With the sink seeded from the ledger, this writeback preserves
    // the resumed prefix's lengths and fills only this run's tail (a
    // failed tail keeps the zero-length placeholder convention).
    for (i, seg) in segments.iter_mut().enumerate() {
        if let Some(len) = lens.get(i) {
            seg.seg_len = *len;
        }
    }
    let delivered = sink.delivered();
    let archive_len = sink.archive_len().await;
    Ok(TrackRunResult {
        archive_len,
        segments,
        seg_bitmap: pack_bitmap(delivered, seg_count),
        init_files,
        error,
    })
}

/// A Range transport pinned to one sub-range: the fetch face receives
/// the sequence engine's EOF-sentinel extent; this wrapper rewrites
/// it to the segment's real byte range before the base transport
/// sees it (the base transport stays untouched — the rewrite is a
/// media-side adapter, not a fork).
struct RangeOnceTransport {
    inner: HttpRangeTransport,
    range: ByteRange,
}

impl SegmentTransport for RangeOnceTransport {
    fn fetch<'a>(
        &'a self,
        _seg: &'a Extent,
        ctx: &'a RequestCtx,
        sink: &'a dyn SegmentSink,
    ) -> BoxFuture<'a, Result<(), HttpError>> {
        let real = Extent {
            start: self.range.offset,
            len: self.range.length,
        };
        Box::pin(async move { self.inner.fetch(&real, ctx, sink).await })
    }
}

/// Fetch a whole URI or an explicit sub-range of it into memory (the
/// init-section face; bounded by the base's stream caps).
pub async fn fetch_whole_or_range(
    client: &HttpClient,
    ctx: &RequestCtx,
    uri: &str,
    range: Option<ByteRange>,
) -> Result<Vec<u8>, MediaError> {
    let collector = CollectBytes::default();
    let res = match range {
        Some(br) => {
            let t = HttpRangeTransport::new(
                client.clone(),
                uri.to_string(),
                None,
                0,
                registry_default(),
            );
            let extent = Extent {
                start: br.offset,
                len: br.length,
            };
            t.fetch(&extent, ctx, &collector).await
        }
        None => {
            let t = HttpBodyTransport::new(client.clone(), uri.to_string(), registry_default());
            let extent = Extent {
                start: 0,
                len: u64::MAX - 1,
            };
            t.fetch(&extent, ctx, &collector).await
        }
    };
    res.map_err(|e| MediaError::Staging(format!("init fetch {uri}: {e}")))?;
    Ok(collector.take())
}

/// In-memory collecting sink (init sections only — bounded by the
/// manifest's init shapes; large bodies ride the archive path).
#[derive(Default)]
pub(crate) struct CollectBytes {
    buf: StdMutex<Vec<u8>>,
}

impl CollectBytes {
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.buf.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl SegmentSink for CollectBytes {
    fn write_at(
        &self,
        _seg: SegId,
        _off: u64,
        bytes: Bytes,
    ) -> BoxFuture<'_, Result<(), HttpError>> {
        Box::pin(async move {
            const INIT_CAP: u64 = 64 * 1024 * 1024;
            let mut buf = self.buf.lock().unwrap_or_else(|e| e.into_inner());
            if buf.len() as u64 + bytes.len() as u64 > INIT_CAP {
                return Err(HttpError::Transport(
                    "init section exceeds the 64MiB in-memory cap".to_string(),
                ));
            }
            buf.extend_from_slice(&bytes);
            Ok(())
        })
    }

    fn complete_block(&self, _block: u64) -> BoxFuture<'_, Result<(), HttpError>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

// ---------------------------------------------------------------------------
// (a) known-length track: grid + ExtentCoordinator + span-mapped GETs
// ---------------------------------------------------------------------------

/// Live completion bookkeeping for one (a)-layer track (the base's
/// `HttpLive::is_complete` pattern: the sink's `complete_block`
/// counter vs the block total; seeded with the resumed blocks).
#[derive(Debug, Default)]
struct LiveTrack {
    blocks_done: std::sync::atomic::AtomicU64,
    blocks_total: std::sync::atomic::AtomicU64,
}

impl LiveTrack {
    fn is_complete(&self) -> bool {
        let (done, total) = (
            self.blocks_done.load(std::sync::atomic::Ordering::Relaxed),
            self.blocks_total.load(std::sync::atomic::Ordering::Relaxed),
        );
        total > 0 && done >= total
    }

    fn note_done(&self, n: u64) {
        self.blocks_done
            .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Sink for the (a) layer: positional archive writes + the
/// adjudicated block-completion counter (the coordinator's single
/// decision point calls `complete_block`; first-report-wins is the
/// base's own discipline — this side only counts).
struct GridArchiveSink {
    part: PartFile,
    live: Arc<LiveTrack>,
}

impl SegmentSink for GridArchiveSink {
    fn write_at(
        &self,
        _seg: SegId,
        off: u64,
        bytes: Bytes,
    ) -> BoxFuture<'_, Result<(), HttpError>> {
        Box::pin(async move { self.part.write_all_at(off, bytes).await })
    }

    fn complete_block(&self, _block: u64) -> BoxFuture<'_, Result<(), HttpError>> {
        self.live.note_done(1);
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Rewrite sink: shifts resource-space writes into virtual archive
/// space (span mapping — `virt_start - res_offset` per span).
struct ShiftSink<'a> {
    inner: &'a dyn SegmentSink,
    shift: i64,
}

impl SegmentSink for ShiftSink<'_> {
    fn write_at(&self, seg: SegId, off: u64, bytes: Bytes) -> BoxFuture<'_, Result<(), HttpError>> {
        let shifted = if self.shift >= 0 {
            off + (self.shift as u64)
        } else {
            off.checked_sub((-self.shift) as u64).unwrap_or(off)
        };
        self.inner.write_at(seg, shifted, bytes)
    }

    fn complete_block(&self, _block: u64) -> BoxFuture<'_, Result<(), HttpError>> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Block-size choice (single source for the layout and its workers):
/// the base default 4MiB, floored at the grid domain minimum for
/// small tracks (block > total collapses to a single-block grid —
/// the wire merge stays span-granular).
fn track_block_size(total: u64) -> u64 {
    if total >= taiji_http::grid::DEFAULT_BLOCK_SIZE {
        taiji_http::grid::DEFAULT_BLOCK_SIZE
    } else {
        taiji_http::grid::MIN_BLOCK_SIZE
    }
}

/// Run one known-length track (the (a) layer): the virtual layout is
/// downloaded through the base's grid + coordinator + range transport
/// — grid bitmap resume included (`resume` carries the persisted
/// segment bitmap; blocks whose segments are all done are seeded into
/// the grid like the core's resume face).
///
/// Encrypted (a) tracks: the wire path is unchanged — the
/// grid fetches **ciphertext** positionally (the ≤8 wire merge stays a
/// transport form). After the fetch converges, a decrypt pass rewrites
/// the archive in place: each segment's ciphertext slice is read at
/// its virtual offset, decrypted **strictly at its own boundary with
/// its own IV** (transport merge is not decryption merge) and appended at
/// the plaintext cursor; the file is truncated to Σ plaintext. Ledger
/// lengths take the plaintext semantics — consistent with the (b) layer and
/// the recovery reconcile.
///
/// **Completed-resume short circuit** (a review fix): a full
/// persisted bitmap plus an on-disk archive length equal to the
/// persisted Σseg_len (the plaintext reading — mediadl reconstructs
/// exactly that value into [`TrackRunResult::archive_len`]) proves the
/// track already finished. The decrypt pass leaves the archive at
/// Σplaintext ≠ the ciphertext `total`, so the length-based
/// `.part`-reuse decision below would classify the completed archive
/// as stale, `Restart` would zero it, the fully-seeded grid would
/// fetch nothing, and the unconditional decrypt pass would then
/// re-fetch every segment slice-by-slice (or destroy the completed
/// track outright when the source is unreachable). The short circuit
/// returns the durable completion before any file is opened.
#[allow(clippy::too_many_arguments)]
pub async fn download_known_length_track(
    gid: &str,
    client: &HttpClient,
    ctx: &RequestCtx,
    playlist: &MediaPlaylist,
    layout: &SpanLayout,
    resolved: &(dyn Fn(&str) -> String + Send + Sync),
    crypto: &TrackCrypto,
    archive_path: &Path,
    init_dir: &Path,
    track_label: &str,
    cfg: &TrackFetchConfig,
    resume: Option<TrackRunResult>,
) -> Result<TrackRunResult, MediaError> {
    // Completed-resume short circuit — BEFORE the init-section fetch
    // loop (a dead source must not fail a provably finished track)
    // and before any archive open. `prev.init_files` presence is part
    // of the completeness proof; a wiped staging tree falls through
    // to the normal repair path.
    if let Some(prev) = &resume {
        let seg_count = playlist.segments.len();
        let done = unpack_bitmap_prefix(&prev.seg_bitmap);
        let persisted_len_sum: u64 = prev.segments.iter().map(|s| s.seg_len).sum();
        let existing_len =
            std::fs::metadata(taiji_io::winpath::to_fs_path(archive_path)).map_or(0, |m| m.len());
        let inits_present = prev
            .init_files
            .iter()
            .all(|name| init_dir.join(name).is_file());
        if seg_count > 0 && done == seg_count && existing_len == persisted_len_sum && inits_present
        {
            let mut segments = segment_records(playlist);
            for (i, seg) in segments.iter_mut().enumerate() {
                seg.key_id = crypto.segments.get(i).and_then(|c| c.db_id());
                // Adopt the persisted (plaintext) lengths — the ledger
                // rows must keep the completed run's semantics.
                if let Some(prev_seg) = prev.segments.get(i) {
                    seg.seg_len = prev_seg.seg_len;
                }
            }
            tracing::debug!(
                target: "taiji::media::track",
                gid = %gid,
                archive_len = existing_len,
                "completed (a)-track resume short circuit (zero refetch)"
            );
            return Ok(TrackRunResult {
                archive_len: existing_len,
                segments,
                seg_bitmap: pack_bitmap(done, seg_count),
                init_files: prev.init_files.clone(),
                error: None,
            });
        }
    }

    // Init sections first (same face as (b), decryption included).
    let mut init_files = Vec::new();
    for init in &playlist.init_sections {
        let path = init_section_path(init_dir, track_label, init.index);
        let uri = resolved(&init.uri);
        let body = fetch_init_section(
            client,
            ctx,
            &uri,
            init.byte_range,
            crypto.inits.get(init.index).and_then(|c| c.as_ref()),
        )
        .await?;
        crate::staging::write_file(&path, &body)?;
        init_files.push(crate::m3u8::init_section_filename(track_label, init.index));
    }

    let mut segments = segment_records(playlist);
    for (i, seg) in segments.iter_mut().enumerate() {
        seg.key_id = crypto.segments.get(i).and_then(|c| c.db_id());
    }
    let total = layout.total;
    let block_size = track_block_size(total);
    let block_count = total.div_ceil(block_size).max(1);

    // Resume: persisted segment prefix → block-done predicate (a
    // block is done iff every segment overlapping it is in the done
    // prefix — conservative at boundaries, whole-block re-download on
    // doubt, the conservative re-download semantics).
    let seg_done: Vec<bool> = match &resume {
        Some(prev) => {
            let prefix = unpack_bitmap_prefix(&prev.seg_bitmap);
            (0..playlist.segments.len()).map(|i| i < prefix).collect()
        }
        None => vec![false; playlist.segments.len()],
    };
    let block_done = |block: u64| -> bool {
        let b_start = block * block_size;
        let b_end = b_start + block_size;
        for (i, off) in layout.seg_offsets.iter().enumerate() {
            let s_start = *off;
            let s_end = s_start + layout.seg_ranges[i].length;
            if s_end <= b_start {
                continue;
            }
            if s_start >= b_end {
                break;
            }
            if !seg_done[i] {
                return false;
            }
        }
        true
    };

    // Archive file: reuse decision by length (the `.part` face
    // semantics — a length mismatch restarts; the grid keeps the
    // byte-truth either way). The provably-completed shape never
    // reaches this point (the short circuit above); a mismatch here
    // means the on-disk bytes are not the layout this run expects, so
    // Restart discards them.
    let existing_len = std::fs::metadata(archive_path).map_or(0, |m| m.len());
    let policy = if existing_len == total {
        PartOpenPolicy::Resume
    } else {
        PartOpenPolicy::Restart
    };
    let part = PartFile::open(
        archive_path.to_path_buf(),
        Some(total),
        policy,
        FileAllocation::Prealloc,
    )
    .await
    .map_err(|e| MediaError::Staging(format!("open archive: {e}")))?;

    // Grid (resumed bitmap preloaded — done blocks are not refetched;
    // the core's resume face pattern). **Seeding gate** (a review
    // fix): a Restart above discarded the prior archive bytes, so no
    // block may be seeded from the persisted bitmap in that branch —
    // the bitmap must never run ahead of the data (the ledger
    // ordering discipline; a seeded-but-wiped grid would converge with
    // zero fetches and report Done over a zeroed file).
    let seed_from_bitmap = matches!(policy, PartOpenPolicy::Resume);
    let mut grid = BlockGrid::new(block_size, total)
        .map_err(|e| MediaError::Staging(format!("grid build: {e}")))?;
    let mut seeded = 0u64;
    for b in 0..block_count {
        if seed_from_bitmap
            && block_done(b)
            && grid
                .record(b)
                .map_err(|e| MediaError::Staging(format!("grid record: {e}")))?
        {
            seeded += 1;
        }
    }
    let live = Arc::new(LiveTrack::default());
    live.blocks_total
        .store(block_count, std::sync::atomic::Ordering::Relaxed);
    live.blocks_done
        .store(seeded, std::sync::atomic::Ordering::Relaxed);
    let sink = Arc::new(GridArchiveSink {
        part: part.clone(),
        live: Arc::clone(&live),
    });

    // Base assembly: guided plan over the resume predicate +
    // coordinator actor with the AIMD book + the throttled wrapper
    // feeding rate samples (the base's own EWMA input face).
    let guided_cfg = GuidedConfig {
        block_size,
        ..GuidedConfig::default()
    };
    guided_cfg
        .validate()
        .map_err(|e| MediaError::Staging(format!("guided config: {e}")))?;
    let plan = GuidedPlan::build(total, &guided_cfg, &|b| grid.is_recorded(b))
        .map_err(|e| MediaError::Staging(format!("plan: {e}")))?;
    let workers = cfg.concurrency.max(1) as usize;
    let stall_window = Duration::from_secs(15);
    let aimd =
        taiji_http::aimd::AimdConfig::with_start(cfg.concurrency.max(1), cfg.concurrency.max(1));
    let (coord, coord_join) = coordinator::spawn_dynamic(
        gid,
        grid,
        plan,
        Arc::clone(&sink) as Arc<dyn SegmentSink>,
        workers,
        stall_window,
        aimd,
    );
    let pool = Arc::new(WorkerPool::with_start(
        1,
        cfg.concurrency.max(1),
        cfg.concurrency.max(1),
    ));
    let token = tokio_util::sync::CancellationToken::new();
    let throttled: Arc<dyn SegmentSink> = Arc::new(ThrottledSink::with_rate_reporter(
        Arc::clone(&sink) as Arc<dyn SegmentSink>,
        HttpLimiter::new(None),
        Arc::new(coord.clone()),
    ));

    let layout = Arc::new(layout.clone());
    let span_uris = resolved_span_uris(&layout, resolved);
    let mut set: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
    let directives = pool.apply(&[], &[]);
    for &(source, n) in &directives {
        for _ in 0..n {
            launch_grid_worker(
                client.clone(),
                ctx.clone(),
                Arc::clone(&layout),
                Arc::clone(&span_uris),
                coord.clone(),
                Arc::clone(&throttled),
                Arc::clone(&pool),
                token.clone(),
                cfg.clone(),
                &mut set,
                source,
            );
        }
        pool.note_spawn(source, n);
    }

    // Driver loop: completion by live counter; supervisor ring keeps
    // the AIMD execution face running (grow/shrink directives).
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut first_err: Option<String> = None;
    loop {
        if live.is_complete() || first_err.is_some() {
            token.cancel();
            break;
        }
        tokio::select! {
            _ = token.cancelled() => break,
            _ = ticker.tick() => {
                // In-track watermark checkpoint: the
                // supervisor tick is the (a)-layer's consumption point
                // (~100ms granularity — block/segment scale, a staging
                // metadata walk each tick). A violation cancels the
                // workers and fails the track with the canonical
                // inherited code; the driver escalates to the
                // task-level terminal.
                if let Some(probe) = &cfg.watermark
                    && probe.violated_now()
                    && first_err.is_none()
                {
                    first_err = Some(probe.err_text());
                    token.cancel();
                }
                if let Ok(stats) = coord.runtime_stats().await {
                    for (source, n) in taiji_http::worker::supervisor_directives(&pool, &stats) {
                        for _ in 0..n {
                            launch_grid_worker(
                                client.clone(),
                                ctx.clone(),
                                Arc::clone(&layout),
                                Arc::clone(&span_uris),
                                coord.clone(),
                                Arc::clone(&throttled),
                                Arc::clone(&pool),
                                token.clone(),
                                cfg.clone(),
                                &mut set,
                                source,
                            );
                        }
                        pool.note_spawn(source, n);
                    }
                }
            }
            joined = set.join_next(), if !set.is_empty() => {
                match joined {
                    Some(Ok(Err(e))) => {
                        if first_err.is_none() {
                            first_err = Some(e);
                            token.cancel();
                        }
                    }
                    Some(Err(e)) if first_err.is_none() => {
                        first_err = Some(format!("worker join: {e}"));
                        token.cancel();
                    }
                    Some(Err(_)) => {}
                    _ => {}
                }
            }
        }
    }
    while let Some(done) = set.join_next().await {
        if let Ok(Err(e)) = done
            && first_err.is_none()
        {
            first_err = Some(e);
        }
    }
    drop(coord);
    drop(throttled);
    coord_join
        .await
        .map_err(|e| MediaError::Staging(format!("coordinator join: {e}")))?
        .map_err(|e| MediaError::Staging(format!("coordinator: {e}")))?;
    let error = match (first_err, live.is_complete()) {
        (Some(e), _) => Some(format!("track fetch: {e}")),
        (None, true) => None,
        (None, false) => Some("track ended incomplete without an error face".to_string()),
    };

    // Durability, then the ledger bitmap (never ahead of data).
    part.sync_all()
        .await
        .map_err(|e| MediaError::Staging(format!("archive fsync: {e}")))?;

    // Decrypt pass (encrypted (a) tracks only): rewrite the
    // ciphertext archive as plaintext, segment-whole with per-segment
    // IVs, truncate to Σ plaintext; ledger lengths take the plaintext
    // semantics.
    let encrypted = crypto
        .segments
        .iter()
        .any(|c| !matches!(c, SegCrypto::Plain));
    let mut archive_len = total;
    let mut decrypt_error: Option<String> = None;
    if encrypted && error.is_none() {
        match decrypt_rewrite_archive(
            client,
            ctx,
            playlist,
            &layout,
            resolved,
            crypto,
            archive_path,
            &part,
        )
        .await
        {
            Ok(plain_lens) => {
                for (i, seg) in segments.iter_mut().enumerate() {
                    if let Some(len) = plain_lens.get(i) {
                        seg.seg_len = *len;
                    }
                }
                archive_len = plain_lens.iter().sum();
            }
            Err(e) => {
                decrypt_error = Some(e.to_string());
            }
        }
    }
    let error = error
        .or(decrypt_error)
        .map(|text| format!("track fetch: {text}"));
    // Post-pass durability: the plaintext rewrite is the state the
    // ledger will describe — fsync it before the ledger write (the
    // ledger ordering discipline).
    if encrypted && error.is_none() {
        part.sync_all()
            .await
            .map_err(|e| MediaError::Staging(format!("archive fsync: {e}")))?;
    }

    let seg_count = segments.len();
    // Failure face note: the (a) layer's authoritative block bitmap
    // lives inside the coordinator (consumed at teardown), so a
    // failed run persists a **zero** segment bitmap — the retry
    // re-downloads over the same positional archive (safe, not
    // optimal; the (b) layer's ordered append carries the partial
    // prefix). A decrypt-pass failure follows the same convention.
    // Recorded in the base-consumption note
    // (docs/design/media-base-consumption.md).
    let done_count = if error.is_none() { seg_count } else { 0 };
    Ok(TrackRunResult {
        archive_len,
        segments,
        seg_bitmap: pack_bitmap(done_count, seg_count),
        init_files,
        error,
    })
}

/// The (a)-layer decrypt pass (see [`download_known_length_track`]):
/// read each segment's ciphertext slice at its virtual offset,
/// decrypt with the segment's own IV (retry the fetch once on decrypt
/// failure — the media-segment retry-once face), write the plaintext
/// at the running plaintext cursor (always ≤ the read cursor: PKCS7
/// strips ≥ 1 byte per 16), truncate to the plaintext total. Returns
/// the per-segment plaintext lengths.
#[allow(clippy::too_many_arguments)]
async fn decrypt_rewrite_archive(
    client: &HttpClient,
    ctx: &RequestCtx,
    playlist: &MediaPlaylist,
    layout: &SpanLayout,
    resolved: &(dyn Fn(&str) -> String + Send + Sync),
    crypto: &TrackCrypto,
    archive_path: &Path,
    part: &PartFile,
) -> Result<Vec<u64>, MediaError> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let fs_path = taiji_io::winpath::to_fs_path(archive_path);
    let mut reader = std::fs::File::open(&fs_path).map_err(|e| {
        MediaError::Staging(format!("open decrypt pass {}: {e}", archive_path.display()))
    })?;
    let mut plain_lens: Vec<u64> = Vec::with_capacity(playlist.segments.len());
    let mut plain_cursor = 0u64;
    for (i, seg) in playlist.segments.iter().enumerate() {
        let off = *layout
            .seg_offsets
            .get(i)
            .ok_or_else(|| MediaError::Staging("layout offset missing".to_string()))?;
        let len = layout.seg_ranges[i].length as usize;
        // RAM valve: this pass buffers one segment's bytes
        // whole, so a seg_len beyond the (b) layer's
        // [`MAX_SEGMENT_BUFFER_BYTES`] is refused before any
        // allocation — the pre-fix `vec![0u8; len]` trusted the
        // layout length directly (a hostile/absurd playlist sized the
        // resident set). Ruling recorded: same 256MiB value as the
        // (b) layer, no new configuration face; a segment that large
        // fails honestly (the caller's decrypt-pass error path). The
        // chunked-streaming decrypt (16B AES alignment, rolling IV)
        // is the eventual shape if real workloads ever hit the cap.
        if len as u64 > sequence::MAX_SEGMENT_BUFFER_BYTES {
            return Err(MediaError::SegmentDecryptFailed(format!(
                "segment {i} length {len} exceeds the {}-byte decrypt-pass valve \
                 (same as the (b) layer's whole-body cap)",
                sequence::MAX_SEGMENT_BUFFER_BYTES
            )));
        }
        let mut cipher = vec![0u8; len];
        let plain: Vec<u8> = {
            reader
                .seek(SeekFrom::Start(off))
                .and_then(|_| reader.read_exact(&mut cipher))
                .map_err(|e| MediaError::Staging(format!("decrypt pass read segment {i}: {e}")))?;
            match crypto.segments.get(i) {
                Some(SegCrypto::Aes { key, iv, .. }) => {
                    match crate::decrypt::decrypt_segment(key, iv, &cipher) {
                        Ok(plain) => plain,
                        Err(first) => {
                            // Retry-once: re-fetch the segment's bytes
                            // and decrypt again (a truncated delivery
                            // is the repairable cause).
                            let uri = resolved(&seg.uri);
                            let retry_body = fetch_whole_or_range(
                                client,
                                ctx,
                                &uri,
                                seg.byte_range,
                            )
                            .await
                            .map_err(|e| {
                                MediaError::SegmentDecryptFailed(format!(
                                    "segment {i} refetch after decrypt failure ({first}; {e})"
                                ))
                            })?;
                            crate::decrypt::decrypt_segment(key, iv, &retry_body).map_err(|_| {
                                MediaError::SegmentDecryptFailed(format!(
                                    "segment {i} (seq {}) decrypt failed after one refetch (first: {first})",
                                    seg.sequence
                                ))
                            })?
                        }
                    }
                }
                _ => cipher,
            }
        };
        part.write_all_at(plain_cursor, bytes::Bytes::from(plain.clone()))
            .await
            .map_err(|e| MediaError::Staging(format!("decrypt pass write segment {i}: {e}")))?;
        plain_cursor += plain.len() as u64;
        plain_lens.push(plain.len() as u64);
    }
    // Truncate to the plaintext total (the preallocated tail falls
    // away); the caller's post-pass fsync flushes the final state
    // before the ledger write.
    {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&fs_path)
            .map_err(|e| {
                MediaError::Staging(format!("open truncate {}: {e}", archive_path.display()))
            })?;
        file.set_len(plain_cursor).map_err(|e| {
            MediaError::Staging(format!("truncate {}: {e}", archive_path.display()))
        })?;
    }
    Ok(plain_lens)
}

fn resolved_span_uris(
    layout: &SpanLayout,
    resolved: &(dyn Fn(&str) -> String + Send + Sync),
) -> Arc<Vec<String>> {
    Arc::new(
        layout
            .spans
            .iter()
            .map(|s| resolved(&s.uri))
            .collect::<Vec<_>>(),
    )
}

/// Launch one (a)-layer worker: acquire → span-split fetch → block
/// completion (the base's acquire/complete/abandon protocol; steal
/// requests are not issued — without the heartbeat ring there is no
/// stall evidence to grant one, and liveness rides the failure
/// abandon/retry path; the base-consumption note records this).
#[allow(clippy::too_many_arguments)]
fn launch_grid_worker(
    client: HttpClient,
    ctx: RequestCtx,
    layout: Arc<SpanLayout>,
    span_uris: Arc<Vec<String>>,
    coord: CoordinatorHandle,
    sink: Arc<dyn SegmentSink>,
    pool: Arc<WorkerPool>,
    token: tokio_util::sync::CancellationToken,
    cfg: TrackFetchConfig,
    set: &mut tokio::task::JoinSet<Result<(), String>>,
    source: u32,
) {
    set.spawn(async move {
        let mut failures: u32 = 0;
        loop {
            if token.is_cancelled() {
                return Ok(());
            }
            if pool.should_stop(source) {
                return Ok(());
            }
            let alloc = match coord.acquire(source).await {
                Ok(Some(a)) => a,
                Ok(None) => {
                    tokio::select! {
                        _ = token.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                    continue;
                }
                Err(_) => return Ok(()), // coordinator stopped (completion/teardown)
            };
            // Split the extent at span boundaries; one Range GET per
            // (span ∩ extent) piece — maximal contiguous merge.
            let mut pieces: Vec<(usize, u64, u64)> = Vec::new(); // (span idx, res_off, len)
            for (si, span) in layout.spans.iter().enumerate() {
                let s = span.virt_start.max(alloc.extent.start);
                let e = (span.virt_start + span.len).min(alloc.extent.end());
                if s < e {
                    pieces.push((si, span.res_offset + (s - span.virt_start), e - s));
                }
            }
            let mut piece_err: Option<HttpError> = None;
            for (si, res_off, len) in pieces {
                let uri = span_uris.get(si).cloned().unwrap_or_default();
                let transport =
                    HttpRangeTransport::new(client.clone(), uri, None, source, registry_default());
                transport.arm(alloc.seg);
                let shift = layout.spans[si].virt_start as i64 - layout.spans[si].res_offset as i64;
                let shift_sink = ShiftSink {
                    inner: sink.as_ref(),
                    shift,
                };
                let extent = Extent {
                    start: res_off,
                    len,
                };
                if let Err(e) = transport.fetch(&extent, &ctx, &shift_sink).await {
                    piece_err = Some(e);
                    break;
                }
            }
            match piece_err {
                None => {
                    failures = 0;
                    let _ = coord.extent_succeeded(source).await;
                    // Whole-block completion (block-aligned extents;
                    // the tail partial block counts by total length —
                    // the base worker's static-baseline catch-up).
                    let block_size = track_block_size(layout.total);
                    let count = layout.total.div_ceil(block_size).max(1);
                    let last_complete = taiji_http::worker::last_complete_block(
                        alloc.extent.end(),
                        layout.total,
                        block_size,
                        count,
                    );
                    let first = alloc.extent.start / block_size;
                    for b in first..=last_complete {
                        if coord.complete_block(b).await.is_err() {
                            break;
                        }
                    }
                }
                Some(e) => {
                    let _ = coord.abandon(alloc).await;
                    failures += 1;
                    if failures >= cfg.max_tries.max(1) {
                        tracing::warn!(
                            target: "taiji::media::track",
                            source = source,
                            error = %e,
                            "segment extent exhausted its retry budget"
                        );
                        return Err(e.to_string());
                    }
                    tokio::select! {
                        _ = token.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(cfg.retry_wait) => {}
                    }
                }
            }
        }
    });
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

    /// Classification: all-BYTERANGE → (a); any whole-resource → (b).
    #[test]
    fn layer_classification() {
        let a = media(
            "#EXTM3U\n#EXT-X-ENDLIST\n#EXTINF:4,\n#EXT-X-BYTERANGE:1000@0\nr.ts\n\
             #EXTINF:4,\n#EXT-X-BYTERANGE:1000@1000\nr.ts\n",
        );
        assert_eq!(classify_track(&a), TrackLayer::KnownLength);
        let b = media("#EXTM3U\n#EXT-X-ENDLIST\n#EXTINF:4,\ns0.ts\n");
        assert_eq!(classify_track(&b), TrackLayer::UnknownLength);
        let mixed = media(
            "#EXTM3U\n#EXT-X-ENDLIST\n#EXTINF:4,\n#EXT-X-BYTERANGE:1000@0\nr.ts\n#EXTINF:4,\ns1.ts\n",
        );
        assert_eq!(classify_track(&mixed), TrackLayer::UnknownLength);
    }

    /// Layout: ≤8 runs fold into maximal same-URI contiguous spans
    /// (the wire-merge face); different URIs break spans.
    #[test]
    fn layout_folds_runs_into_maximal_spans() {
        // 16 sub-segments × 1KiB over one resource: the parser caps runs at
        // 8 segments, the layout folds them into ONE span (one GET).
        let mut text = String::from("#EXTM3U\n#EXT-X-ENDLIST\n");
        for i in 0..16u64 {
            text.push_str(&format!(
                "#EXTINF:1,\n#EXT-X-BYTERANGE:1024@{}\nblob.bin\n",
                i * 1024
            ));
        }
        let pl = media(&text);
        let runs = crate::m3u8::byterange_runs(&pl);
        assert_eq!(runs.len(), 2, "runs cap at 8");
        let layout = layout_known_length(&pl).unwrap_or_else(|e| panic!("layout: {e}"));
        assert_eq!(layout.spans.len(), 1, "maximal span folds the two runs");
        assert_eq!(layout.spans[0].segments, 16);
        assert_eq!(layout.spans[0].len, 16 * 1024);
        assert_eq!(layout.total, 16 * 1024);
        // A gap in the resource breaks the span.
        let mut text = String::from("#EXTM3U\n#EXT-X-ENDLIST\n");
        text.push_str("#EXTINF:1,\n#EXT-X-BYTERANGE:1024@0\nblob.bin\n");
        text.push_str("#EXTINF:1,\n#EXT-X-BYTERANGE:1024@4096\nblob.bin\n");
        let pl = media(&text);
        let layout = layout_known_length(&pl).unwrap_or_else(|e| panic!("layout: {e}"));
        assert_eq!(layout.spans.len(), 2, "byte gap breaks the span");
        // Different URIs break the span.
        let mut text = String::from("#EXTM3U\n#EXT-X-ENDLIST\n");
        text.push_str("#EXTINF:1,\n#EXT-X-BYTERANGE:1024@0\na.bin\n");
        text.push_str("#EXTINF:1,\n#EXT-X-BYTERANGE:1024@1024\nb.bin\n");
        let pl = media(&text);
        let layout = layout_known_length(&pl).unwrap_or_else(|e| panic!("layout: {e}"));
        assert_eq!(layout.spans.len(), 2);
    }

    /// Bitmap packing round-trip + prefix unpack (partial bitmaps
    /// unpack to their leading run only).
    #[test]
    fn bitmap_pack_unpack() {
        assert_eq!(unpack_bitmap_prefix(&pack_bitmap(0, 10)), 0);
        assert_eq!(unpack_bitmap_prefix(&pack_bitmap(3, 10)), 3);
        assert_eq!(unpack_bitmap_prefix(&pack_bitmap(10, 10)), 10);
        assert_eq!(pack_bitmap(0, 0).len(), 0);
        assert_eq!(pack_bitmap(1, 8).len(), 1);
        assert_eq!(pack_bitmap(9, 9).len(), 2);
        // A hole ends the prefix.
        let mut bm = pack_bitmap(3, 10);
        bm[0] = 0b0000_0111; // bits 0,1,2
        bm[1] = 0b1000_0000; // bit 15 only — prefix still 3
        assert_eq!(unpack_bitmap_prefix(&bm), 3);
    }

    /// Validator digest: stable under query rewrites, sensitive to
    /// byte-range and sequence changes.
    #[test]
    fn validator_digest_normalization() {
        let mut text = String::from("#EXTM3U\n#EXT-X-ENDLIST\n");
        text.push_str("#EXTINF:1,\n#EXT-X-BYTERANGE:100@0\nhttp://cdn.test/a.ts?sig=1\n");
        let pl1 = media(&text);
        let mut text2 = String::from("#EXTM3U\n#EXT-X-ENDLIST\n");
        text2.push_str("#EXTINF:1,\n#EXT-X-BYTERANGE:100@0\nhttp://cdn.test/a.ts?sig=9999\n");
        let pl2 = media(&text2);
        assert_eq!(
            segment_records(&pl1)[0].validator_digest,
            segment_records(&pl2)[0].validator_digest,
            "query rewrite digest-stable"
        );
        let mut text3 = String::from("#EXTM3U\n#EXT-X-ENDLIST\n");
        text3.push_str("#EXTINF:1,\n#EXT-X-BYTERANGE:200@0\nhttp://cdn.test/a.ts\n");
        let pl3 = media(&text3);
        assert_ne!(
            segment_records(&pl1)[0].validator_digest,
            segment_records(&pl3)[0].validator_digest,
            "length change digests differently"
        );
    }

    /// Segment records: identity = absolute media sequence (non-zero
    /// base included); duration in ms; MAP index recorded.
    #[test]
    fn segment_records_identity() {
        let text = "#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:500\n#EXT-X-ENDLIST\n\
                    #EXT-X-MAP:URI=\"init.mp4\"\n\
                    #EXTINF:2.5,\n#EXT-X-BYTERANGE:10@0\nr.ts\n\
                    #EXTINF:3,\n#EXT-X-BYTERANGE:10@10\nr.ts\n";
        let pl = media(text);
        let recs = segment_records(&pl);
        assert_eq!(recs[0].media_sequence, 500);
        assert_eq!(recs[1].media_sequence, 501);
        assert_eq!(recs[0].seg_idx, 0);
        assert_eq!(recs[0].duration_ms, 2500);
        assert_eq!(recs[0].map, Some(0));
        assert_eq!(recs[0].byte_range.as_deref(), Some("10@0"));
        assert_eq!(recs[0].seg_len, 10);
    }

    /// The (a)-layer decrypt pass buffers one segment
    /// whole, so a seg_len beyond the (b) layer's whole-body valve
    /// ([`taiji_http::sequence::MAX_SEGMENT_BUFFER_BYTES`]) is an
    /// explicit `segment_decrypt_failed` error **before any
    /// allocation** — the pre-fix `vec![0u8; len]` trusted the
    /// layout's length, letting a hostile playlist size the resident
    /// set directly (the (b) layer already valved its own fetches).
    #[tokio::test]
    async fn decrypt_pass_valves_segment_buffer() {
        use crate::keys::{SegCrypto, TrackCrypto};
        let len = sequence::MAX_SEGMENT_BUFFER_BYTES + 16;
        let text = format!("#EXTM3U\n#EXT-X-ENDLIST\n#EXTINF:4,\n#EXT-X-BYTERANGE:{len}@0\nr.ts\n");
        let pl = media(&text);
        let layout = layout_known_length(&pl).unwrap_or_else(|e| panic!("layout: {e}"));
        assert_eq!(layout.seg_ranges[0].length, len);
        let crypto = TrackCrypto {
            segments: vec![SegCrypto::Aes {
                key: [1; 16],
                iv: [2; 16],
                db_id: None,
            }],
            inits: Vec::new(),
        };
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        // The ciphertext archive: a sparse file of the declared shape
        // (the valve must fire before any of it is buffered).
        let archive = dir.path().join("archive.ts");
        std::fs::File::create(&archive)
            .and_then(|f| f.set_len(len))
            .unwrap_or_else(|e| panic!("sparse archive: {e}"));
        // The part handle is only touched after a successful decrypt;
        // a separate dummy path keeps it out of the valve's way.
        let part = PartFile::open(
            dir.path().join("dummy.part"),
            Some(0),
            PartOpenPolicy::Restart,
            FileAllocation::None,
        )
        .await
        .unwrap_or_else(|e| panic!("part: {e}"));
        let client = HttpClient::new(Default::default()).unwrap_or_else(|e| panic!("client: {e}"));
        let ctx = RequestCtx::default();
        let resolved = |s: &str| s.to_string();
        match decrypt_rewrite_archive(
            &client, &ctx, &pl, &layout, &resolved, &crypto, &archive, &part,
        )
        .await
        {
            Ok(lens) => panic!("over-valve segment length accepted: {lens:?}"),
            Err(e) => {
                assert_eq!(e.code(), "taiji.media.segment_decrypt_failed");
                assert!(e.to_string().contains("valve"), "names the valve: {e}");
            }
        }
    }
}

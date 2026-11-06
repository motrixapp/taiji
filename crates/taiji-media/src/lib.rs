//! `taiji-media` — media layer skeleton + ffmpeg infrastructure
//! (0.3.0, per the product spec) + the m3u8 parser line
//! (per the media spec's parse/parse-gate sections) + the track
//! transport/staging line (per the media spec's download/staging
//! sections).
//!
//! Initial scope: ffmpeg/ffprobe discovery (precedence: explicit param >
//! `TAIJI_FFMPEG_PATH` > packaged constant > PATH, same-origin
//! pairing), `-version` parsing + the LGPL configuration-string gate,
//! `-demuxers`/`-muxers` capability table, child orchestration
//! (argv-array/absolute/explicit `-f`/piped trio/kill-on-drop/cancel/
//! watchdog/resource limits), the `-progress pipe:1` line-protocol parser,
//! ffprobe JSON structuring, and the `taiji media doctor` aggregation.
//!
//! m3u8 parser scope: the self-built m3u8 parser (sniff order,
//! media/master playlists, the pinned first-release semantics),
//! variant selection
//! policy, normalized digest + variant identity — pure functions, see
//! [`m3u8`].
//!
//! Track transport scope: the multi-track model + necessity grading
//! ([`trackset`]), per-track staging ([`staging`]), the (a)/(b)
//! transport layers over the 0.2 foundation crate ([`trackdl`],
//! consumption list on record in `docs/design/media-base-consumption.md`),
//! the multi-track driver ([`mediadl`]) and the wired flag faces
//! ([`options`]).
//!
//! Decryption scope: AES-128 segment decryption ([`decrypt`] —
//! segment-whole CBC + PKCS7, the chain never crosses a segment), the
//! key acquisition/rotation face ([`keys`] — data: inline, base-client
//! fetch, task-wide cache, per-track crypto plan), the `data:` URI
//! parser ([`datauri`]) and the SSRF defense line ([`ssrf`] — key URIs
//! and media-segment/init URLs, pure decision + injected resolver).
//!
//! Synthesis scope: local per-track playlist rewrite ([`rewrite`]
//! — the parse-gate golden face), the self-built native MP4 write side
//! ([`bmff`] read/fold + [`mp4write`] progressive writer with
//! tx3g/covr/chpl/faststart faces — the amended any-codec carrier;
//! `mp4ff` is a Go library, the Rust
//! carrier is in-house, zero new dependencies), the VTT sidecar line
//! ([`vtt`]), the ffmpeg fallback channel ([`ffmpegmux`] — a
//! discovery-infrastructure consumer), the three prechecks ([`precheck`]),
//! the native probe
//! ([`probe`]) and the Processing→Verifying pipeline ([`synth`]).
//!
//! DASH scope: the self-built MPD (DASH static-VOD) line —
//! [`mpd`] (quick-xml streaming parse + URL-template expansion + the
//! track-model mapping onto the HLS faces + the sidx single-level
//! addressing half in [`bmff`]), the driver's DASH arm
//! ([`mediadl`]), and the judgment-table codes (dynamic →
//! `live_unsupported`, ContentProtection → `drm_unsupported`, nested
//! sidx → `sidx_unsupported`; the media spec's verdict table).
//!
//! Out of scope (later work): the unified three-layer selector and
//! probe face over DASH trees, DASH dynamic support itself
//! (0.4, sliding window), DRM decryption (never),
//! ISM (0.4), LIVE (0.4).
//!
//! Frozen-seam posture: this crate's only workspace edges are
//! `taiji-http` (the planned product topology edge, first actual
//! wiring here) and `taiji-io` (nameability of the shared faces
//! the base exposes by type); option-surface registration goes
//! through the unified option surface.

pub mod archive;
pub mod bmff;
pub mod capability;
pub mod datauri;
pub mod decrypt;
pub mod discover;
pub mod doctor;
pub mod error;
pub mod exec_shim;
pub mod ffmpegmux;
pub mod ffprobe;
pub mod format;
pub mod keys;
pub mod m3u8;
pub mod mediadl;
pub mod mp4write;
pub mod mpd;
pub mod options;
pub mod phase;
pub mod precheck;
pub mod probe;
pub mod process;
pub mod progress;
pub mod rewrite;
pub mod selector;
pub mod ssrf;
pub mod staging;
pub mod synth;
pub mod template;
/// Test-kit (shared fMP4 fixture builders — a test fixture face, not a
/// product API; see the module doc).
pub mod testkit;
pub mod trackdl;
pub mod trackset;
pub mod version;
pub mod vtt;

pub use archive::{
    INFO_JSON_KEYS, INFO_JSON_SCHEMA_VERSION, MediaInfoRecord, archive_url_digest,
    normalize_archive_url, redact_payload_text, render_info_json,
};
pub use capability::{Capabilities, Direction, REQUIRED_DEMUXERS, REQUIRED_MUXERS};
pub use datauri::{MAX_DATA_URI_BYTES, parse_data_uri, parse_key_data_uri};
pub use decrypt::{BLOCK_LEN, KEY_LEN, decrypt_merged_span, decrypt_segment, iv_from_sequence};
pub use discover::{DiscoveryRequest, DiscoverySource, FfmpegPair, discover, discover_with_env};
pub use doctor::{DoctorOptions, DoctorReport, run_doctor};
pub use error::MediaError;
pub use ffmpegmux::{FallbackFormat, FfmpegRuntime, fallback_args};
pub use ffprobe::{FfprobeFormat, FfprobeReport, FfprobeStream, probe_args};
pub use format::{
    EntryKind, FormatNode, FormatTree, build_format_tree, build_format_tree_dash, classify_entry,
    probe_token, snapshot_url_key,
};
pub use keys::{
    InitCrypto, KeyRecord, KeySpec, KeyTable, SegCrypto, TrackCrypto, build_track_crypto,
    collect_key_specs, expand_track_keys, key_identity,
};
pub use m3u8::{
    ManifestFlavor, Playlist, VariantPolicy, byterange_runs, parse_manifest, select_variant, sniff,
    strip_query, variant_identity,
};
pub use mediadl::{
    AttachedRendition, ChosenVariant, MediaDownload, MediaDownloadConfig, MediaProgressNote,
    MediaRunReport,
};
pub use mpd::{
    DashPick, DashTrackPlan, Expanded, ExpandedTrack, Mpd, MpdDescriptor, MpdType, SidxPlan,
    THUMBNAIL_SCHEME, expand_representation, expand_url_template, materialize_sidx,
    mpd_content_digest, mpd_digest, parse_mpd, plan_dash_tracks, representation_identity,
    resolve_rep_base, select_representation_idx,
};
pub use options::{
    DEFAULT_SEGMENT_CONCURRENCY, DEFAULT_STAGING_QUOTA_GIB, FfmpegPathSpec, MuxerSpec,
    OutputFormat as OutputFormatOption, SubtitleMode, parse_allow_private_key_url,
    parse_audio_lang, parse_ffmpeg_path, parse_media_archive, parse_media_archive_clear,
    parse_media_info_json, parse_muxer, parse_output_format, parse_segment_concurrency,
    parse_staging_dir, parse_staging_quota_gib, parse_subtitles,
};
pub use phase::MediaPhase;
pub use precheck::{
    DiskVerdict, FallbackNeed, PRECHECK_MARGIN_BYTES, StartVerdict, disk_precheck, peak_need,
    sidecar_start_precheck, volume_free_bytes,
};
pub use probe::{DURATION_TOLERANCE, ExpectedMeta, ExpectedTrack, ProbeReport, probe_product};
pub use process::{
    DEFAULT_STALL_TIMEOUT, FFMPEG_LIMITS, FFPROBE_LIMITS, MAX_ALLOC_BYTES, MediaBin, MediaChild,
    MediaCommand, MediaOutput,
};
pub use progress::{ProgressParser, ProgressSnapshot, snapshot_advances};
pub use rewrite::{RewriteEntry, TrackRewrite, local_playlist_name, rewrite_track};
pub use selector::{
    MediaSelector, Predicate, Selection, SelectorLayer, parse_selector, resolve_selection,
};
pub use ssrf::{
    AddrClass, SsrfPolicy, SsrfResolver, check_uri, classify_addr, classify_host_literal,
    decide_resolved, decide_uri,
};
pub use staging::{
    STAGING_DIR_NAME, WATERMARK_INTERVAL, archive_name, create_staging_dir, ensure_same_volume,
    gc_orphan_gids, reconcile_boundary, remove_staging, same_volume, staging_gid_dir,
    staging_permissions_ok, staging_usage_bytes,
};
pub use synth::{
    Channel, MuxerPreference, NativeSupport, OutputFormat, Phase, SynthesisConfig, SynthesisReport,
    TrackInput, choose_channel, fallback_need, native_support, run_synthesis,
};
pub use template::{
    MAX_OUTPUT_NAME_BYTES, SanitizedName, TEMPLATE_FIELDS, TemplateContext, expand_template,
    sanitize_output_name,
};
pub use trackdl::{
    FetchSpan, MediaLedger, MediaTaskRecord, SegmentRecord, SpanLayout, TrackFetchConfig,
    TrackLayer, TrackRecord, TrackRunResult, classify_track, layout_known_length, pack_bitmap,
    segment_records, unpack_bitmap_prefix,
};
pub use trackset::{
    PlannedTrack, TrackKind, TrackRole, TrackSetConfig, TrackSetVerdict, TrackState,
    plan_track_set, select_audio_track, track_set_verdict,
};
pub use version::{LicenseAudit, LicenseStrictness, VersionInfo, license_verdict};

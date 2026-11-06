//! Media-layer error skeleton (thiserror per crate; product-spec
//! vocabulary).
//!
//! Codes are canonical `taiji.media.*` strings. `ffmpeg_missing` and
//! `ffmpeg_stalled` are product-spec-named codes; the initial
//! (discovery-era) variants name orchestration diagnostics (origin
//! pairing, license gate, spawn/exit). The parser-line variants carry
//! the manifest-line vocabulary (the media spec's verdict table plus
//! its "known-unsupported features must error explicitly" rule:
//! not_media / manifest_too_large / live_unsupported /
//! sample_aes_unsupported / session_key_unsupported / iframes_unsupported
//! / manifest_parse / variant_policy) — additive vocabulary inside this
//! crate, pending option-face registration on the unified CLI surface
//! (frozen-seam note).

/// Media-layer (ffmpeg/ffprobe orchestration) error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MediaError {
    /// Discovery found no usable ffmpeg/ffprobe pair (the product
    /// spec's `ffmpeg_missing`).
    #[error("taiji.media.ffmpeg_missing: {0}")]
    Missing(String),

    /// ffmpeg and ffprobe resolve to different origins (the two binaries
    /// must be a same-source pair — the discovery contract).
    #[error("taiji.media.ffmpeg_origin_mismatch: {0}")]
    OriginMismatch(String),

    /// `-version` configuration carries `--enable-gpl`/`--enable-nonfree`
    /// (LGPL-2.1+ packaging face, per the product spec) under `gate`
    /// strictness.
    #[error("taiji.media.ffmpeg_license_gate: {0}")]
    LicenseGate(String),

    /// Spawn refused: binary path is not absolute (outputs and
    /// executables must be absolute; no PATH lookup at spawn
    /// time).
    #[error("taiji.media.ffmpeg_not_absolute: {0}")]
    NotAbsolute(String),

    /// Output argument recorded without an explicit `-f <fmt>` ahead of
    /// it (the orchestration contract: format is always explicit,
    /// never container-guessed).
    #[error("taiji.media.ffmpeg_missing_format: output {0:?} without an explicit -f")]
    MissingFormat(String),

    /// Spawn failed (OS-level).
    #[error("taiji.media.ffmpeg_spawn: {0}")]
    Spawn(String),

    /// Child was cancelled through the cancel token before completion.
    #[error("taiji.media.ffmpeg_cancelled: child cancelled before completion")]
    Cancelled,

    /// Watchdog fired: no progress advance (frame or total_size) within
    /// the stall window; the child went through the TERM(5s)-KILL
    /// escalation (the product spec's `ffmpeg_stalled`).
    #[error("taiji.media.ffmpeg_stalled: {0}")]
    Stalled(String),

    /// Child exited nonzero (stderr excerpt included, byte-capped).
    #[error("taiji.media.ffmpeg_exit: {0}")]
    Exit(String),

    /// `-version`/`-demuxers`/`-muxers`/progress output outside the
    /// expected shape.
    #[error("taiji.media.ffmpeg_parse: {0}")]
    Parse(String),

    /// Entry classification found no media signature on content,
    /// extension or Content-Type (the media spec's sniff order;
    /// `taiji.media.not_media`).
    #[error("taiji.media.not_media: {0}")]
    NotMedia(String),

    /// Manifest outside the accepted bounds: >16MiB of body or more
    /// than 100k media segments (product-spec caps carry over to
    /// the media spec; `taiji.media.manifest_too_large`).
    #[error("taiji.media.manifest_too_large: {0}")]
    ManifestTooLarge(String),

    /// Media playlist carries no EXT-X-ENDLIST (LIVE/EVENT without a
    /// terminator): 0.3 transitional refusal, 0.4 removes the code
    /// (media-spec verdict-table row;
    /// `taiji.media.live_unsupported`).
    #[error("taiji.media.live_unsupported: {0}")]
    LiveUnsupported(String),

    /// EXT-X-KEY METHOD=SAMPLE-AES (decryption sidecar lands in 0.4).
    /// Spelling of record =
    /// `taiji.media.sample_aes_unsupported` (the parser's
    /// judgment-table wording, shipped in 0.3.0; the media spec's
    /// verdict-table row spells the transition `sample_aes_pending` —
    /// since reconciled: the code string of record stands and the
    /// verdict-table row takes the errata; any future code-string
    /// change rides the error-code PR face, never a silent
    /// respelling).
    #[error("taiji.media.sample_aes_unsupported: {0}")]
    SampleAesUnsupported(String),

    /// EXT-X-SESSION-KEY in a master playlist (media-spec verdict
    /// table; `taiji.media.session_key_unsupported`).
    #[error("taiji.media.session_key_unsupported: {0}")]
    SessionKeyUnsupported(String),

    /// Media playlist carries EXT-X-I-FRAMES-ONLY — i-frame renditions
    /// are trick-play only, not a downloadable presentation (the tag is
    /// a media-playlist tag, RFC 8216 §4.3.3.6, so "selected variant
    /// contains it" surfaces as this parse refusal;
    /// `taiji.media.iframes_unsupported`).
    #[error("taiji.media.iframes_unsupported: {0}")]
    IframesUnsupported(String),

    /// DASH `<ContentProtection>` — any level, any scheme (media-spec
    /// verdict-table row; `taiji.media.drm_unsupported`). DRM is **never
    /// supported**; the 0.3 DASH key/decrypt consumption face
    /// is exactly this refusal — ClearKey is a 0.4+ question, and any
    /// future change rides the error-code PR face, never a silent
    /// respelling. Landed with the DASH parser line; the inherited
    /// code already sits on the product-spec error-code line.
    #[error("taiji.media.drm_unsupported: {0}")]
    DrmUnsupported(String),

    /// A nested (hierarchical) sidx — a DASH `SegmentBase`-addressed
    /// index whose sidx carries `reference_type=1` references
    /// (media-spec verdict-table row; `taiji.media.sidx_unsupported`;
    /// single-level sidx only). The inherited code already sits on
    /// the product-spec error-code line.
    #[error("taiji.media.sidx_unsupported: {0}")]
    SidxUnsupported(String),

    /// Structurally invalid manifest (missing #EXTM3U header, URI
    /// without EXTINF, malformed attribute, dangling tag at EOF,
    /// BYTERANGE omission without a prior sub-range, overflow …).
    #[error("taiji.media.manifest_parse: {0}")]
    ManifestParse(String),

    /// `--media-variant-policy` value or selection outcome is invalid
    /// (unknown policy form, no candidate under the cap). The CLI flag
    /// itself registers on the unified option surface; this is the
    /// pure-function face.
    #[error("taiji.media.variant_policy: {0}")]
    VariantPolicy(String),

    /// Staging directory and output are on different volumes (the
    /// product-spec same-volume constraint; inherited code
    /// `taiji.media.cross_volume`).
    #[error("taiji.media.cross_volume: {0}")]
    CrossVolume(String),

    /// Staging quota exceeded (product-spec admission + runtime
    /// watermark; inherited code
    /// `taiji.media.staging_quota_exceeded`).
    #[error("taiji.media.staging_quota_exceeded: {0}")]
    StagingQuotaExceeded(String),

    /// Option value out of domain (the shared generic option face,
    /// `taiji.option.invalid` — the flag names are the media ones
    /// wired here; unified-surface registration pending).
    #[error("taiji.option.invalid: {0}")]
    OptionInvalid(String),

    /// AES-128 segment decryption failed (inherited code
    /// `taiji.media.segment_decrypt_failed`, per the product spec —
    /// wired after the driver's single re-fetch retry; causes: a
    /// ciphertext length that is not a whole number of blocks, a PKCS7
    /// pad the cipher rejects, or a key/IV that does not fit the
    /// segment).
    #[error("taiji.media.segment_decrypt_failed: {0}")]
    SegmentDecryptFailed(String),

    /// The SSRF defense line refused a second-order URL (key URI or
    /// media-segment/init URL; per the media spec — scheme outside
    /// the http/https/data: whitelist, or a loopback/private/link-local
    /// literal/resolved target under the default-deny posture).
    /// Inherited via the media spec's error-code annotation
    /// (2026-10-28 — registered before merge per the frozen-seam
    /// routing).
    #[error("taiji.media.ssrf_blocked: {0}")]
    SsrfBlocked(String),

    /// Key-material face rejection (per the product spec: `data:`
    /// inline bodies over the 64KiB cap, malformed data: URIs, fetched
    /// key bodies not exactly 16 bytes, unsupported KEYFORMAT, a MAP
    /// with no following segment for the sequence-IV fallback).
    /// Inherited via the media spec's error-code annotation
    /// (2026-10-28 — registered before merge per the frozen-seam
    /// routing).
    #[error("taiji.media.key_invalid: {0}")]
    KeyInvalid(String),

    /// Staging I/O or layout failure (directory creation/archive
    /// write/recovery truncation). Inherited code via the media
    /// spec's error-code annotation (2026-10-28: no more precise
    /// inherited code covers the local-disk staging face —
    /// `staging_quota_exceeded`/`cross_volume` each have their precise
    /// meanings; the annotation registered this code before merge).
    /// Use extension under the same annotation (no new code): the
    /// native channel's malformed-staging-content refusals and the
    /// both-channels-failed compound terminal state ride this variant
    /// (see synth.rs module docs; a dedicated `synthesis_failed` code
    /// is a candidate for a future error-code annotation).
    #[error("taiji.media.staging: {0}")]
    Staging(String),

    /// Synthesis verification failed: the native probe's box-structure
    /// assertions or the ffprobe dual-run rejected the product
    /// (inherited code `taiji.media.remux_verify_failed`, per the
    /// product spec — the product `.part` is removed, staging
    /// retained with a summary).
    #[error("taiji.media.remux_verify_failed: {0}")]
    RemuxVerifyFailed(String),
}

impl MediaError {
    /// Canonical `taiji.media.*` code (single source for the RPC/doctor
    /// faces; the string is also the discriminant persisted in logs).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing(_) => "taiji.media.ffmpeg_missing",
            Self::OriginMismatch(_) => "taiji.media.ffmpeg_origin_mismatch",
            Self::LicenseGate(_) => "taiji.media.ffmpeg_license_gate",
            Self::NotAbsolute(_) => "taiji.media.ffmpeg_not_absolute",
            Self::MissingFormat(_) => "taiji.media.ffmpeg_missing_format",
            Self::Spawn(_) => "taiji.media.ffmpeg_spawn",
            Self::Cancelled => "taiji.media.ffmpeg_cancelled",
            Self::Stalled(_) => "taiji.media.ffmpeg_stalled",
            Self::Exit(_) => "taiji.media.ffmpeg_exit",
            Self::Parse(_) => "taiji.media.ffmpeg_parse",
            Self::NotMedia(_) => "taiji.media.not_media",
            Self::ManifestTooLarge(_) => "taiji.media.manifest_too_large",
            Self::LiveUnsupported(_) => "taiji.media.live_unsupported",
            Self::SampleAesUnsupported(_) => "taiji.media.sample_aes_unsupported",
            Self::SessionKeyUnsupported(_) => "taiji.media.session_key_unsupported",
            Self::IframesUnsupported(_) => "taiji.media.iframes_unsupported",
            Self::DrmUnsupported(_) => "taiji.media.drm_unsupported",
            Self::SidxUnsupported(_) => "taiji.media.sidx_unsupported",
            Self::ManifestParse(_) => "taiji.media.manifest_parse",
            Self::VariantPolicy(_) => "taiji.media.variant_policy",
            Self::CrossVolume(_) => "taiji.media.cross_volume",
            Self::StagingQuotaExceeded(_) => "taiji.media.staging_quota_exceeded",
            Self::OptionInvalid(_) => "taiji.option.invalid",
            Self::SegmentDecryptFailed(_) => "taiji.media.segment_decrypt_failed",
            Self::SsrfBlocked(_) => "taiji.media.ssrf_blocked",
            Self::KeyInvalid(_) => "taiji.media.key_invalid",
            Self::Staging(_) => "taiji.media.staging",
            Self::RemuxVerifyFailed(_) => "taiji.media.remux_verify_failed",
        }
    }
}

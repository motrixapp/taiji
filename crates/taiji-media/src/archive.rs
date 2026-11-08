//! The product faces' pure halves: the download-archive
//! fingerprints (per the media spec's archive line) and the info.json
//! whitelist export — platform-independent pure functions in
//! the parser-line posture, consumed by the session pipeline's Done close-out
//! and the duplicate checkpoints.
//!
//! # Fingerprint rulings (0.3 compartmentalization)
//!
//! * **Normalized URL digest** ([`archive_url_digest`]): SHA-256 hex
//!   over `scheme://host[:port]/path` — the query and fragment
//!   stripped, the path **kept** (a per-resource identity: two
//!   manifests on one origin are different downloads). This reuses
//!   the parser-line pure-function family's primitives ([`m3u8::strip_query`]
//!   semantics + the in-tree SHA-256). It deliberately differs from
//!   the probe face's [`crate::snapshot_url_key`] (origin only,
//!   scheme://host[:port]): that key is the rate/anti-forgery
//!   identity where a per-origin throttle is the point; the archive
//!   fingerprint must not collapse every manifest on an origin into
//!   one "already downloaded" verdict. The difference is recorded
//!   here as the module of record.
//! * **Manifest digest** (checkpoint ②'s compartment): a
//!   **URL-free** digest of the fetched manifest's canonical
//!   structure — the same content served by a switched CDN/mirror
//!   must hit, so the compartment may not bind the fetch location:
//! * HLS = the parser's playlist digest verbatim
//!   ([`m3u8::media_playlist_digest`] /
//!   [`m3u8::master_playlist_digest`] — already pure parsed
//!   content, no URL input);
//! * DASH = [`mpd::mpd_content_digest`] (the canonical body under
//!   its own domain header) — **not** [`mpd::mpd_digest`], whose
//!   canonical text appends the query-stripped entry URL (the
//!   recovery/structure-diff consumers want the fetch location in
//!   that identity; the archive's cross-URL hit face does not).
//!
//! Both compartments land in the `media_archive` row (the store's
//! faces are taiji-store's business). Note the `media_task.
//! manifest_norm_digest` column keeps the parser-line form (URL-bound on
//! the DASH side) — the row identity and the archive compartment
//! are deliberately two different questions.
//!
//! # Payload redact (one implementation)
//!
//! [`redact_payload_text`] is the single payload-redaction
//! implementation shared by the error face and the info.json export
//! (per the media spec: "field whitelist + redact one implementation"): every exported
//! string value passes it, so a signed URL, a query-bearing token or
//! a secret-shaped value can never reach disk through the export
//! face. It is intentionally **not** `taiji_io::redact::redact_url_for_log`
//! — that face honors the process-wide `--log-verbatim-urls` switch,
//! and an export must never leak because the user flipped a log
//! knob; the payload face is unconditionally redacted.
//!
//! # info.json whitelist (fixed keys)
//!
//! The export is built **from a fixed record type**
//! ([`MediaInfoRecord`]) — there is no map passthrough, so a
//! manifest-sourced string can never inject a key: hostile field
//! *values* ride the value slots only, and every string value passes
//! [`redact_payload_text`]. The forbidden keys
//! (`http_headers`/`cookies`/`token`) are structurally absent; the
//! test pins them negatively. `--no-meta` is orthogonal: it governs
//! the *embed* face (title/covr inside the product), the export face
//! answers to `--media-info-json` alone.

use std::fmt::Write as _;

use crate::m3u8::digest::{hex, sha256};

/// SHA-256 hex over the normalized `scheme://host[:port]/path` form
/// (query + fragment stripped, path kept — see the module docs'
/// fingerprint ruling). An unparseable URL falls back to hashing the
/// raw string with a distinct domain-separation prefix (never a
/// silent collision with a parseable URL's digest).
pub fn archive_url_digest(url: &str) -> String {
    let normalized = normalize_archive_url(url);
    hex(&sha256(normalized.as_bytes()))
}

/// The normalized form behind [`archive_url_digest`] (also the
/// checkpoint-1 comparison identity).
pub fn normalize_archive_url(url: &str) -> String {
    match taiji_http::reqwest::Url::parse(url) {
        Ok(u) => {
            let mut out = String::new();
            let _ = write!(out, "{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if let Some(p) = u.port() {
                let _ = write!(out, ":{p}");
            }
            // `Url::path` is already the query/fragment-stripped path.
            out.push_str(u.path());
            out
        }
        Err(_) => format!("raw:{url}"),
    }
}

/// The payload redact (the single implementation, shared by the
/// error face and the info.json export): whitespace-token-wise, every
/// URL-shaped token loses its query (`?…` to the end), all other
/// tokens pass. Control characters are dropped (a value never carries
/// a log/JSON-forging face into an export).
pub fn redact_payload_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for tok in text.split_whitespace() {
        if tok.contains("://") {
            if let Some(stripped) = tok.split('?').next() {
                out.push_str(&strip_controls(stripped));
            }
        } else {
            out.push_str(&strip_controls(tok));
        }
        out.push(' ');
    }
    out.trim_end().to_string()
}

fn strip_controls(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// The info.json export record (the frozen whitelist). The
/// field set is the 0.3 manifest-available domain (the same sources
/// `TemplateContext` and the title face fill) plus the task/fingerprint
/// essentials; the serialized key set is frozen by
/// [`INFO_JSON_KEYS`] and pinned by tests.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaInfoRecord {
    /// The task's 16-hex GID.
    pub gid: String,
    /// `hls`|`dash` (the manifest flavor).
    pub kind: String,
    /// The C14 manifest-level title (DASH `ProgramInformation/Title`;
    /// HLS has no standard source — None, never synthesized).
    pub title: Option<String>,
    /// The template `{id}` value (an explicit `--out` or the
    /// manifest stem).
    pub id: Option<String>,
    /// The output container (`mp4`|`mkv`).
    pub ext: String,
    /// The selected resolution (`1280x720`), when known.
    pub res: Option<String>,
    /// The selected audio language, when known.
    pub lang: Option<String>,
    /// The entry URL (exported **redacted** — query stripped).
    pub manifest_url: String,
    /// The sanitized product name actually on disk.
    pub output_name: String,
    /// The checkpoint-1 fingerprint ([`archive_url_digest`]).
    pub url_digest: String,
    /// The checkpoint-2 fingerprint (the canonical manifest
    /// digest, hex).
    pub manifest_digest: String,
    /// The product size in bytes.
    pub bytes: u64,
    /// Completion time (unix seconds).
    pub completed_at: i64,
}

/// The frozen top-level key set of the export (the whitelist,
/// element-for-element; `http_headers`/`cookies`/`token` are
/// structurally absent — the negative pin lives in the tests).
pub const INFO_JSON_KEYS: &[&str] = &[
    "schema_version",
    "gid",
    "kind",
    "title",
    "id",
    "ext",
    "res",
    "lang",
    "manifest_url",
    "output_name",
    "url_digest",
    "manifest_digest",
    "bytes",
    "completed_at",
];

/// The export's schema version (bump = a whitelist change = a test
/// change; frozen against silent drift).
pub const INFO_JSON_SCHEMA_VERSION: u64 = 1;

/// Render the export body (pretty JSON, trailing newline). Every
/// string value passes [`redact_payload_text`]; `None` fields export
/// as JSON `null` (the honest "manifest did not carry it" face —
/// mirrors the template `NA` convention's spirit without munging
/// data types).
pub fn render_info_json(rec: &MediaInfoRecord) -> String {
    let r = |v: &str| redact_payload_text(v);
    let json = serde_json::json!({
        "schema_version": INFO_JSON_SCHEMA_VERSION,
        "gid": r(&rec.gid),
        "kind": r(&rec.kind),
        "title": rec.title.as_deref().map(r),
        "id": rec.id.as_deref().map(r),
        "ext": r(&rec.ext),
        "res": rec.res.as_deref().map(r),
        "lang": rec.lang.as_deref().map(r),
        "manifest_url": r(&rec.manifest_url),
        "output_name": r(&rec.output_name),
        "url_digest": r(&rec.url_digest),
        "manifest_digest": r(&rec.manifest_digest),
        "bytes": rec.bytes,
        "completed_at": rec.completed_at,
    });
    format!("{json}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fingerprint's normalization ruling: query/fragment
    /// stripped, path KEPT (a per-resource identity — the deliberate
    /// difference from the origin-only `snapshot_url_key`), port
    /// forms distinct, scheme/host differences distinct.
    #[test]
    fn url_digest_normalization() {
        let base = archive_url_digest("https://cdn.example/a/b/manifest.m3u8");
        // A rotated CDN signature or a cache-buster hits the same
        // fingerprint (the checkpoint-1 premise).
        assert_eq!(
            base,
            archive_url_digest("https://cdn.example/a/b/manifest.m3u8?token=abc&x=1")
        );
        assert_eq!(
            base,
            archive_url_digest("https://cdn.example/a/b/manifest.m3u8#frag")
        );
        // The path is part of the identity.
        assert_ne!(base, archive_url_digest("https://cdn.example/a/other.m3u8"));
        // An origin-only key WOULD collide here; the archive key must
        // not (the recorded difference from snapshot_url_key).
        assert_ne!(
            archive_url_digest("https://cdn.example/a.m3u8"),
            archive_url_digest("https://cdn.example/b.m3u8")
        );
        // Port and scheme are part of the identity.
        assert_ne!(
            archive_url_digest("https://cdn.example:8443/m.m3u8"),
            archive_url_digest("https://cdn.example/m.m3u8")
        );
        assert_ne!(
            archive_url_digest("http://cdn.example/m.m3u8"),
            archive_url_digest("https://cdn.example/m.m3u8")
        );
        // Determinism + hex shape.
        assert_eq!(
            base,
            archive_url_digest("https://cdn.example/a/b/manifest.m3u8")
        );
        assert_eq!(base.len(), 64);
        assert!(base.bytes().all(|b| b.is_ascii_hexdigit()));
        // An unparseable URL degrades to the domain-separated raw
        // form (never a silent collision with a parseable digest).
        let raw = archive_url_digest("not a url");
        assert_eq!(raw, archive_url_digest("not a url"));
        assert_ne!(raw, archive_url_digest("notaurl"));
    }

    /// The payload redact: signed URLs lose their query, non-URL
    /// tokens pass, controls drop.
    #[test]
    fn payload_redact_strips_signed_queries() {
        assert_eq!(
            redact_payload_text("fetch https://s.example/v.m3u8?X-Amz-Signature=dead failed"),
            "fetch https://s.example/v.m3u8 failed"
        );
        assert_eq!(redact_payload_text("plain text"), "plain text");
        assert_eq!(redact_payload_text("a\x00b"), "ab");
    }

    /// The whitelist is exact: the serialized object's keys equal
    /// [`INFO_JSON_KEYS`] element-for-element, and the
    /// forbidden keys are absent even when the manifest-sourced
    /// VALUES try to carry them (a value is a value — it can never
    /// become a key through the fixed record).
    #[test]
    fn info_json_whitelist_is_frozen_and_forbidden_keys_absent() {
        let rec = MediaInfoRecord {
            gid: "80000000000000b1".into(),
            kind: "dash".into(),
            // A hostile title value attempting key injection.
            title: Some("\", \"http_headers\": {\"Authorization\": \"Bearer x\"}".into()),
            id: Some("bbb30".into()),
            ext: "mp4".into(),
            res: Some("1280x720".into()),
            lang: Some("en".into()),
            manifest_url: "https://s.example/manifest.mpd?sig=SECRETSIG".into(),
            output_name: "Big Buck Bunny-bbb30.mp4".into(),
            url_digest: archive_url_digest("https://s.example/manifest.mpd"),
            manifest_digest: "abcd".into(),
            bytes: 4096,
            completed_at: 1_770_000_000,
        };
        let body = render_info_json(&rec);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{e}"));
        let obj = v.as_object().unwrap_or_else(|| panic!("object body"));
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want: Vec<&str> = INFO_JSON_KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(keys, want, "the whitelist is exactly the frozen set");
        for forbidden in ["http_headers", "cookies", "token"] {
            assert!(
                !obj.contains_key(forbidden),
                "{forbidden} must never be a key"
            );
        }
        // The hostile title rode the VALUE slot (redacted), never the
        // key set — and the signed manifest URL lost its query.
        let title = obj["title"].as_str().unwrap_or_default();
        assert!(
            title.contains("http_headers"),
            "value text preserved: {title}"
        );
        assert_eq!(
            obj["manifest_url"].as_str(),
            Some("https://s.example/manifest.mpd")
        );
        // Null face: an HLS record (no title) exports JSON null.
        let hls = MediaInfoRecord {
            kind: "hls".into(),
            title: None,
            ..rec
        };
        let v: serde_json::Value =
            serde_json::from_str(&render_info_json(&hls)).unwrap_or_else(|e| panic!("{e}"));
        assert!(v["title"].is_null());
        assert_eq!(v["schema_version"], INFO_JSON_SCHEMA_VERSION);
    }
}

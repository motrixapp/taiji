//! AES-128 key acquisition, rotation and the per-track crypto plan
//! (per the product spec's key section + the media spec's verdict
//! table, download line and playlist red lines).
//!
//! # Faces
//!
//! * [`collect_key_specs`] — pre-expand the distinct key tags of one
//! playlist (segments **and** init sections, first-appearance order;
//! rotation = several specs, `METHOD=NONE` never enters — the parser
//! already materialized the reset as plaintext segments).
//! * [`KeyTable`] — the task-wide key cache: seeded from the
//! `media_key` rows at run start (a restarted task never re-fetches
//! a key already in the DB — the recovery face), grown by
//! [`expand_track_keys`]. Material caches by resolved URI; row
//! identity = (resolved URI, IV) — one `media_key` row per KEY tag
//! identity ("multiple key_id rows + IV sequence semantics").
//! * [`expand_track_keys`] — fetch the misses: `data:` inline
//! (64KiB/16B discipline, zero outbound) or `http(s)` through the
//! task's `RequestCtx` on the base `HttpClient`, behind the
//! SSRF line, with the per-attempt retry budget of the track fetch
//! config (key-fetch failures close through the existing HTTP
//! retry/failure face). KEYFORMAT is
//! gated to `identity`/absent (RFC 8216 §4.3.2.4: unrecognized
//! formats MUST NOT be used).
//! * [`build_track_crypto`] — the per-segment/per-init decryption
//! descriptors with **resolved** IVs: explicit IV first; missing →
//! big-endian absolute media sequence of the segment; an init
//! section walks the chain MAP/KEY@IV → the **first following
//! segment's** sequence. An attribution erratum of record
//! (comment-only): the MAP-level `KEY=` attribute and the
//! missing-IV sequence fallback for an init section are **taiji
//! custom extensions/relaxations, not clauses of RFC 8216 or any
//! rfc8216bis revision** — RFC 8216 §4.3.2.5's spec-correct behavior on a
//! missing init IV is to reject; taiji attempts the derivation and
//! fails honestly (a decrypt error) when it cannot resolve one.
//!
//! # At-rest (pre-release posture)
//!
//! Key values never land in staging — only the `media_key` rows
//! (plaintext under the local-machine threat model; static encryption
//! at rest is an open question, the secure_delete discipline follows
//! the chosen erase-on-retire shape). URIs entering error faces are
//! query-stripped (signed key URLs).

use std::collections::HashMap;

use taiji_http::client::HttpClient;
use taiji_segment::traits::RequestCtx;

use crate::datauri::{EXPECTED_KEY_LEN, MAX_DATA_URI_BYTES, parse_key_data_uri};
use crate::decrypt::{KEY_LEN, iv_from_sequence};
use crate::error::MediaError;
use crate::m3u8::model::{Key, MediaPlaylist};
use crate::ssrf::{HostVerdictCache, SsrfPolicy, SsrfResolver, check_uri};
use crate::trackdl::TrackFetchConfig;

/// One distinct KEY-tag identity of a playlist (resolved URI + IV).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySpec {
    /// Key URI resolved against the playlist base (a `data:` URI stays
    /// absolute under RFC 3986 joining).
    pub uri: String,
    /// Explicit IV (`None` ⇒ per-segment sequence derivation).
    pub iv: Option<[u8; 16]>,
}

/// media-side `media_key` row payload (the store row mirrors it; `db_id`
/// is the row id handed back by the ledger — `media_segment.key_id`
/// references it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    /// Row id once persisted (None until the ledger load-back).
    pub db_id: Option<i64>,
    /// Row identity text (see [`key_identity`]).
    pub key_id: String,
    /// Resolved key URI.
    pub uri: String,
    /// Explicit IV or None.
    pub iv: Option<[u8; 16]>,
    /// Key material (exactly 16 bytes).
    pub key: [u8; KEY_LEN],
}

/// Stable row identity for one KEY tag: 16 hex chars of SHA-256 over
/// the domain-tagged (resolved URI, IV) pair — deterministic across
/// runs, distinct per IV under rotation.
pub fn key_identity(uri: &str, iv: Option<&[u8; 16]>) -> String {
    let mut text = String::from("hls-key/1\n");
    text.push_str(uri);
    text.push('\n');
    match iv {
        Some(iv) => {
            for b in iv {
                text.push_str(&format!("{b:02x}"));
            }
        }
        None => text.push('*'),
    }
    let digest = crate::m3u8::digest::sha256(text.as_bytes());
    let mut out = String::from("k");
    for b in &digest[..8] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The task-wide key cache (DB-seeded + fetch-grown; the media spec's
/// task-wide key cache pre-expanded at run start).
#[derive(Default)]
pub struct KeyTable {
    entries: Vec<KeyRecord>,
    index: HashMap<(String, Option<[u8; 16]>), usize>,
}

impl KeyTable {
    /// Seed from persisted rows (the restart-no-refetch face).
    pub fn from_rows(rows: impl IntoIterator<Item = KeyRecord>) -> Self {
        let mut table = Self::default();
        for row in rows {
            table.insert(row);
        }
        table
    }

    fn insert(&mut self, record: KeyRecord) {
        let key = (record.uri.clone(), record.iv);
        self.index.insert(key, self.entries.len());
        self.entries.push(record);
    }

    /// Row lookup by KEY-tag identity.
    pub fn lookup(&self, uri: &str, iv: Option<[u8; 16]>) -> Option<&KeyRecord> {
        self.index
            .get(&(uri.to_owned(), iv))
            .map(|i| &self.entries[*i])
    }

    /// All rows (persist order; the ledger upsert face).
    pub fn records(&self) -> &[KeyRecord] {
        &self.entries
    }

    /// Adopt persisted ids from a ledger load-back (rows keep their
    /// identity → the same db row, stable `media_segment.key_id`
    /// references across resumes).
    pub fn adopt_ids(&mut self, rows: &[KeyRecord]) {
        for row in rows {
            if let Some(entry) = self
                .index
                .get(&(row.uri.clone(), row.iv))
                .copied()
                .map(|i| &mut self.entries[i])
            {
                entry.db_id = row.db_id;
            }
        }
    }
}

/// The distinct key specs of one playlist: segment keys + init-section
/// keys, first-appearance order, `(resolved URI, IV)`-deduplicated.
pub fn collect_key_specs(
    playlist: &MediaPlaylist,
    resolve: &(dyn Fn(&str) -> String + Send + Sync),
) -> Result<Vec<KeySpec>, MediaError> {
    let mut specs: Vec<KeySpec> = Vec::new();
    let mut push = |key: &Key| -> Result<(), MediaError> {
        gate_keyformat(key)?;
        let Some(uri) = &key.uri else {
            return Err(MediaError::KeyInvalid(
                "AES-128 key without a URI".to_string(),
            ));
        };
        let spec = KeySpec {
            uri: resolve(uri),
            iv: key.iv,
        };
        if !specs.contains(&spec) {
            specs.push(spec);
        }
        Ok(())
    };
    for seg in &playlist.segments {
        if let Some(key) = &seg.key {
            push(key)?;
        }
    }
    for init in &playlist.init_sections {
        if let Some(key) = &init.key {
            push(key)?;
        }
    }
    Ok(specs)
}

/// RFC 8216 §4.3.2.4: keys with an unrecognized KEYFORMAT MUST NOT be
/// used — only absent (defaults to `identity`) or `identity` pass.
fn gate_keyformat(key: &Key) -> Result<(), MediaError> {
    let ok = match &key.keyformat {
        None => true,
        Some(fmt) => fmt.eq_ignore_ascii_case("identity"),
    };
    if ok {
        Ok(())
    } else {
        Err(MediaError::KeyInvalid(format!(
            "KEYFORMAT {:?} is not usable for AES-128 (only identity)",
            crate::m3u8::strip_query(key.keyformat.as_deref().unwrap_or_default())
        )))
    }
}

/// Expand the table for one playlist: every missing spec is
/// SSRF-checked then fetched (`data:` inline or base-client GET with
/// the retry budget); existing rows (memory or DB seed) are never
/// re-fetched.
#[expect(
    clippy::too_many_arguments,
    reason = "the key-expand face carries the fetch and defense surfaces explicitly (the track-driver precedent)"
)]
pub async fn expand_track_keys(
    client: &HttpClient,
    ctx: &RequestCtx,
    specs: &[KeySpec],
    table: &mut KeyTable,
    policy: &SsrfPolicy,
    resolver: &dyn SsrfResolver,
    host_cache: &mut HostVerdictCache,
    fetch_cfg: &TrackFetchConfig,
) -> Result<(), MediaError> {
    for spec in specs {
        if table.lookup(&spec.uri, spec.iv).is_some() {
            continue;
        }
        check_uri(&spec.uri, policy, resolver, host_cache).await?;
        let key = fetch_key(client, ctx, &spec.uri, fetch_cfg).await?;
        table.insert(KeyRecord {
            db_id: None,
            key_id: key_identity(&spec.uri, spec.iv.as_ref()),
            uri: spec.uri.clone(),
            iv: spec.iv,
            key,
        });
    }
    Ok(())
}

/// Fetch one key body: `data:` inline direct-decode (zero outbound) or
/// `http(s)` GET through the base client (RequestCtx inherited), body
/// capped at the data: face's 64KiB bound and required to be exactly
/// 16 bytes. Retries follow the track fetch budget (per-attempt loop;
/// the client itself never retries implicitly).
async fn fetch_key(
    client: &HttpClient,
    ctx: &RequestCtx,
    uri: &str,
    cfg: &TrackFetchConfig,
) -> Result<[u8; KEY_LEN], MediaError> {
    let attempts = cfg.max_tries.max(1);
    let mut last: Option<MediaError> = None;
    for attempt in 0..attempts {
        if attempt > 0 {
            tokio::time::sleep(cfg.retry_wait).await;
        }
        match fetch_key_once(client, ctx, uri).await {
            Ok(key) => return Ok(key),
            Err(e) => {
                tracing::debug!(target: "taiji::media::keys", error = %e, "key fetch attempt failed");
                last = Some(e);
            }
        }
    }
    // Signed key URLs never leave the error face unredacted.
    let redacted = crate::m3u8::strip_query(uri);
    Err(last.unwrap_or_else(|| MediaError::KeyInvalid(format!("key fetch: {redacted}"))))
}

async fn fetch_key_once(
    client: &HttpClient,
    ctx: &RequestCtx,
    uri: &str,
) -> Result<[u8; KEY_LEN], MediaError> {
    if uri.starts_with("data:") {
        return parse_key_data_uri(uri);
    }
    let followed = client
        .get(uri, ctx)
        .await
        .map_err(|e| MediaError::KeyInvalid(format!("key fetch: {e}")))?;
    let status = followed.response.status();
    if !status.is_success() {
        return Err(MediaError::KeyInvalid(format!(
            "key fetch {}: HTTP {}",
            crate::m3u8::strip_query(uri),
            status.as_u16()
        )));
    }
    let mut body: Vec<u8> = Vec::with_capacity(KEY_LEN);
    let mut resp = followed.response;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| MediaError::KeyInvalid(format!("key read: {e}")))?
    {
        // Bound the read at the data: face's cap: one extra byte is
        // enough to detect an oversize body.
        if body.len() + chunk.len() > MAX_DATA_URI_BYTES {
            return Err(MediaError::KeyInvalid(format!(
                "key body exceeds the {} byte cap",
                MAX_DATA_URI_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }
    if body.len() != EXPECTED_KEY_LEN {
        return Err(MediaError::KeyInvalid(format!(
            "key body is {} bytes, expected exactly {EXPECTED_KEY_LEN}",
            body.len()
        )));
    }
    let Ok(key) = <[u8; KEY_LEN]>::try_from(body.as_slice()) else {
        return Err(MediaError::KeyInvalid(format!(
            "key body reshape: {} bytes",
            body.len()
        )));
    };
    Ok(key)
}

/// The per-segment/per-init decryption descriptors (IVs already
/// resolved; db ids attached for the ledger rows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegCrypto {
    /// Plaintext segment (no key, or the explicit METHOD=NONE reset).
    Plain,
    /// AES-128 segment: whole-segment CBC with the resolved IV.
    Aes {
        key: [u8; KEY_LEN],
        iv: [u8; 16],
        /// media_key row id (media_segment.key_id).
        db_id: Option<i64>,
    },
}

impl SegCrypto {
    /// The media_key row id when this segment is encrypted.
    pub fn db_id(&self) -> Option<i64> {
        match self {
            Self::Plain => None,
            Self::Aes { db_id, .. } => *db_id,
        }
    }
}

/// Init-section decryption descriptor (the chain in the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitCrypto {
    pub key: [u8; KEY_LEN],
    pub iv: [u8; 16],
    pub db_id: Option<i64>,
}

/// The whole track's crypto plan (aligned by playlist index).
#[derive(Clone, Debug, Default)]
pub struct TrackCrypto {
    /// One entry per media segment (playlist order).
    pub segments: Vec<SegCrypto>,
    /// One entry per init section (`None` = plaintext init).
    pub inits: Vec<Option<InitCrypto>>,
}

impl TrackCrypto {
    /// A plaintext plan (no keys anywhere).
    pub fn plain(segment_count: usize, init_count: usize) -> Self {
        Self {
            segments: vec![SegCrypto::Plain; segment_count],
            inits: vec![None; init_count],
        }
    }
}

/// Build the crypto plan for one playlist against the (already
/// expanded) key table. IV resolution: explicit first, else the
/// segment's absolute media sequence; init sections walk the
/// MAP/KEY@IV → first-following-segment-sequence chain.
pub fn build_track_crypto(
    playlist: &MediaPlaylist,
    resolve: &(dyn Fn(&str) -> String + Send + Sync),
    table: &KeyTable,
) -> Result<TrackCrypto, MediaError> {
    // One key-tag lookup shared by the segment and init walks.
    let lookup = |key: &Key| -> Result<&KeyRecord, MediaError> {
        gate_keyformat(key)?;
        let Some(uri) = &key.uri else {
            return Err(MediaError::KeyInvalid(
                "AES-128 key without a URI".to_string(),
            ));
        };
        let resolved = resolve(uri);
        table.lookup(&resolved, key.iv).ok_or_else(|| {
            MediaError::KeyInvalid(format!(
                "key {} was not pre-expanded",
                crate::m3u8::strip_query(&resolved)
            ))
        })
    };
    // Segments: the IV resolves per segment (default = own sequence).
    let mut segments = Vec::with_capacity(playlist.segments.len());
    for seg in &playlist.segments {
        let Some(key) = &seg.key else {
            segments.push(SegCrypto::Plain);
            continue;
        };
        let record = lookup(key)?;
        let iv = key.iv.unwrap_or_else(|| iv_from_sequence(seg.sequence));
        segments.push(SegCrypto::Aes {
            key: record.key,
            iv,
            db_id: record.db_id,
        });
    }
    // Init sections: MAP/KEY@IV → first-following-segment sequence.
    let mut inits = Vec::with_capacity(playlist.init_sections.len());
    for (idx, init) in playlist.init_sections.iter().enumerate() {
        let Some(key) = &init.key else {
            inits.push(None);
            continue;
        };
        let record = lookup(key)?;
        let iv = match key.iv {
            Some(iv) => iv,
            None => {
                // The taiji relaxation (an erratum of record: not a spec
                // clause — RFC 8216 §4.3.2.5 would reject here): the
                // sequence of the first segment this MAP applies to.
                let first = playlist
                    .segments
                    .iter()
                    .find(|s| s.map == Some(idx))
                    .ok_or_else(|| {
                        MediaError::KeyInvalid(format!(
                            "init section {idx} has no following segment for the sequence-IV fallback"
                        ))
                    })?;
                iv_from_sequence(first.sequence)
            }
        };
        inits.push(Some(InitCrypto {
            key: record.key,
            iv,
            db_id: record.db_id,
        }));
    }
    Ok(TrackCrypto { segments, inits })
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

    fn absolute(uri: &str) -> String {
        uri.to_string()
    }

    /// Spec collection: rotation entries in first-appearance order,
    /// deduplicated, METHOD=NONE absent.
    #[test]
    fn collect_specs_rotation_and_dedup() {
        let text = "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"k1\",IV=0x00000000000000000000000000000001\n\
#EXTINF:1,\ns0.ts\n#EXTINF:1,\ns1.ts\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"k1\",IV=0x00000000000000000000000000000001\n\
#EXTINF:1,\ns2.ts\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"k2\"\n\
#EXTINF:1,\ns3.ts\n\
#EXT-X-KEY:METHOD=NONE\n\
#EXTINF:1,\ns4.ts\n#EXT-X-ENDLIST\n";
        let pl = media(text);
        let specs = collect_key_specs(&pl, &absolute).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(specs.len(), 2, "dedup + NONE absent: {specs:?}");
        assert_eq!(specs[0].uri, "k1");
        assert_eq!(
            specs[0].iv,
            Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(specs[1].uri, "k2");
        assert_eq!(specs[1].iv, None);
    }

    /// Crypto plan: explicit IV wins, default = own absolute sequence
    /// (non-zero base), METHOD=NONE resets to plaintext, init sections
    /// walk the explicit → first-following-sequence chain.
    #[test]
    fn build_crypto_plan_forms() {
        let iv1: [u8; 16] = [0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let text = format!(
            "#EXTM3U\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:700\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"k1\",IV=0x{}\n\
#EXT-X-MAP:URI=\"init0.mp4\"\n\
#EXTINF:1,\ns0.ts\n#EXTINF:1,\ns1.ts\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"k2\"\n\
#EXT-X-MAP:URI=\"init1.mp4\"\n\
#EXTINF:1,\ns2.ts\n\
#EXT-X-KEY:METHOD=NONE\n\
#EXTINF:1,\ns3.ts\n#EXT-X-ENDLIST\n",
            iv1.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let pl = media(&text);
        let mut table = KeyTable::default();
        for spec in collect_key_specs(&pl, &absolute).unwrap_or_default() {
            table.insert(KeyRecord {
                db_id: Some(match spec.uri.as_str() {
                    "k1" => 10,
                    _ => 11,
                }),
                key_id: key_identity(&spec.uri, spec.iv.as_ref()),
                uri: spec.uri.clone(),
                iv: spec.iv,
                key: if spec.uri == "k1" {
                    [1u8; 16]
                } else {
                    [2u8; 16]
                },
            });
        }
        let plan = build_track_crypto(&pl, &absolute, &table).unwrap_or_else(|e| panic!("{e}"));
        // s0/s1: explicit IV.
        assert!(matches!(
            &plan.segments[0],
            SegCrypto::Aes { key, iv, db_id } if *key == [1u8; 16] && *iv == iv1 && *db_id == Some(10)
        ));
        // s2 under k2 (no explicit IV): sequence 702.
        assert!(matches!(
            &plan.segments[2],
            SegCrypto::Aes { key, iv, db_id } if *key == [2u8; 16] && *iv == iv_from_sequence(702) && *db_id == Some(11)
        ));
        // s3 after METHOD=NONE: plaintext, no stale key.
        assert_eq!(plan.segments[3], SegCrypto::Plain);
        // init0 covered by k1@IV (the ambient key's explicit IV).
        assert!(matches!(
            &plan.inits[0],
            Some(InitCrypto { iv, .. }) if *iv == iv1
        ));
        // init1 covered by k2 without IV → first following segment's
        // sequence (702 — the segment that uses init1).
        assert!(matches!(
            &plan.inits[1],
            Some(InitCrypto { iv, .. }) if *iv == iv_from_sequence(702)
        ));
    }

    /// KEYFORMAT gating: `identity` and absent pass; anything else is
    /// `key_invalid`.
    #[test]
    fn keyformat_gate() {
        let text = "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"k\",KEYFORMAT=\"com.example.widevine\"\n\
#EXTINF:1,\ns.ts\n#EXT-X-ENDLIST\n";
        let pl = media(text);
        let e = collect_key_specs(&pl, &absolute)
            .err()
            .unwrap_or_else(|| panic!("unknown KEYFORMAT must be refused"));
        assert_eq!(e.code(), "taiji.media.key_invalid");
        let ok = "#EXTM3U\n#EXT-X-TARGETDURATION:2\n\
#EXT-X-KEY:METHOD=AES-128,URI=\"k\",KEYFORMAT=\"identity\"\n\
#EXTINF:1,\ns.ts\n#EXT-X-ENDLIST\n";
        assert!(collect_key_specs(&media(ok), &absolute).is_ok());
    }

    /// Row identity: same URI different IV = two rows; deterministic
    /// across runs.
    #[test]
    fn key_identity_iv_sequence() {
        let a = key_identity("https://x/k", None);
        let b = key_identity("https://x/k", Some(&[9u8; 16]));
        assert_ne!(a, b);
        assert_eq!(a, key_identity("https://x/k", None));
        assert!(a.starts_with('k') && a.len() == 17, "{a}");
    }
}

//! HTTP metadata mirror sources (a fourth discovery route for magnet
//! metadata; core-only, zero changes to the bt protocol face).
//!
//! Motivation: a cold-start magnet relies on DHT/tracker/LSD discovery +
//! a BEP9 fetch, which can take tens of seconds; public cache sites
//! (itorrents/btcache class) offer `GET /torrent/<hex>.torrent` by v1
//! infohash, so popular content can hit in one RTT. Races the three P2P
//! routes — first verified wins. The default empty template list = the
//! feature is off, zero outbound HTTP.
//!
//! Trust boundary: a mirror response is untrusted input — the info
//! segment is hashed from the **raw byte slice** (decode->re-encode
//! forbidden) and its sha1 must equal the magnet btih; the piece layers
//! needed by hybrid/v2 are Merkle-validated layer by layer down to the
//! pieces root (SPEC §2.1.8, validate before writing to disk). Any
//! failed check voids the response (treated as a miss, silently falling
//! back to P2P) without penalizing network health (the site is up; it
//! just does not have / serves the wrong torrent).
//!
//! Privacy (mirrored in the options note): configuring mirrors sends
//! infohashes to third-party sites, exposing download intent — the
//! reason the default is off.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use taiji_bt::bencode::{self, Value};
use taiji_bt::tracker::{HttpAnnounce, TrackerOptions};
use taiji_store::merkle;

use crate::session::persist::import::hex_lower;

use super::layers::scan_layers_needed;
use super::{MagnetTaskConfig, MetaFace, check_identity};

/// URL template placeholder (= the lowercase hex40 of the v1 btih; the
/// public-site index ecosystem is v1).
pub const WEB_MIRROR_PLACEHOLDER: &str = "{INFOHASH}";

/// Response body cap: an info dict is far smaller than this; guards
/// against malicious sites feeding large bodies (a local policy value).
const WEB_MIRROR_BODY_CAP: usize = 4 * 1024 * 1024;

/// Mirror template parsing: only legal http(s) URLs containing
/// [`WEB_MIRROR_PLACEHOLDER`] are kept; invalid entries are dropped with
/// a warn (never fails the task — the remaining mirrors work on; SPEC
/// §2.6 honesty).
pub fn parse_web_mirror_templates(raw: &[String]) -> Vec<String> {
    raw.iter()
        .filter_map(|t| {
            let t = t.trim();
            let ok = t.starts_with("http://") || t.starts_with("https://");
            if !ok || !t.contains(WEB_MIRROR_PLACEHOLDER) {
                warn!(target: "taiji::core::magnet", template = t,
                    "web mirror template dropped (need http(s) URL + {{INFOHASH}} placeholder)");
                return None;
            }
            Some(t.to_string())
        })
        .collect()
}

/// Per-mirror health state (network-failure count + cooldown deadline;
/// content voids are not counted).
#[derive(Default)]
struct MirrorState {
    consecutive_failures: u32,
    cooldown_until: Option<Instant>,
}

/// Session-level mirror health table (shared across magnet tasks; not
/// persisted — one retry round after a restart is cheap). Policy: N
/// consecutive network failures (connect failure/timeout/non-200) ->
/// skip during cooldown; any success clears the count. Key = template
/// string (after a hot update of the template list, health state
/// continues by string).
pub struct WebMirrorHealth {
    threshold: u32,
    cooldown: Duration,
    map: std::sync::Mutex<HashMap<String, MirrorState>>,
}

impl WebMirrorHealth {
    pub fn new() -> Self {
        Self::with_policy(3, Duration::from_secs(600))
    }

    /// Test injection (a short cooldown guards against timing jitter).
    fn with_policy(threshold: u32, cooldown: Duration) -> Self {
        WebMirrorHealth {
            threshold,
            cooldown,
            map: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn note_success(&self, key: &str) {
        let mut map = self.lock();
        map.remove(key);
    }

    fn note_failure(&self, key: &str) {
        let mut map = self.lock();
        let st = map.entry(key.to_string()).or_default();
        st.consecutive_failures += 1;
        if st.consecutive_failures >= self.threshold {
            st.cooldown_until = Some(Instant::now() + self.cooldown);
        }
    }

    /// Within cooldown = tripped (the mirror is skipped this phase).
    fn blocked(&self, key: &str) -> bool {
        let mut map = self.lock();
        match map.get_mut(key) {
            Some(st) => match st.cooldown_until {
                Some(until) if Instant::now() < until => true,
                Some(_) => {
                    // Cooldown expired: leave the tripped state and
                    // reset the count (one full round of attempts).
                    st.cooldown_until = None;
                    st.consecutive_failures = 0;
                    false
                }
                None => false,
            },
            None => false,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, MirrorState>> {
        crate::lock(&self.map)
    }
}

impl Default for WebMirrorHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// The metadata-phase mirror set: the template list (parsed from
/// session-global options) + the shared health table.
pub struct WebMirrors {
    pub templates: Vec<String>,
    pub health: Arc<WebMirrorHealth>,
}

impl WebMirrors {
    /// Template strings have passed [`parse_web_mirror_templates`]
    /// (parsed once at config injection).
    pub fn new(templates: Vec<String>, health: Arc<WebMirrorHealth>) -> Self {
        WebMirrors { templates, health }
    }
}

/// Mirror fetch product: the raw info-segment bytes + validated piece
/// layers (for hybrid/v2; v1-only = empty). `pub(super)`: magnet.rs's
/// discover_and_fetch reads the fields when consuming the volley result
/// channel (the type name need not be named).
pub(super) struct WebMetadata {
    pub(super) info: Bytes,
    pub(super) layers: Vec<([u8; 32], Vec<u8>)>,
}

/// Single-mirror fetch outcome classes: network failure (counted for
/// health) vs content void (not counted).
enum WebFetchOutcome {
    Ok(WebMetadata),
    Network(String),
    Miss(&'static str),
}

/// Single-mirror fetch + full validation. The timeout reuses the
/// tracker frozen defaults (bt-tracker-timeout/connect-timeout = 60s,
/// SPEC §11; no new constants).
async fn fetch_from_mirror(
    client: &HttpAnnounce,
    template: &str,
    btih: Option<[u8; 20]>,
    btmh: Option<[u8; 32]>,
) -> WebFetchOutcome {
    let url = template.replace(
        WEB_MIRROR_PLACEHOLDER,
        &btih.map(|hash| hex_lower(&hash)).unwrap_or_default(),
    );
    let body = match client.get_body(&url).await {
        Ok(b) => b,
        Err(_) => return WebFetchOutcome::Network("metadata source request failed".into()),
    };
    if body.len() > WEB_MIRROR_BODY_CAP {
        return WebFetchOutcome::Miss("response body over cap");
    }
    // Parse + validate (the >1MiB rule uniformly goes through
    // spawn_blocking).
    let parsed = {
        let body = body.clone();
        tokio::task::spawn_blocking(move || verify_web_torrent(&body, btih, btmh)).await
    };
    match parsed {
        Ok(Ok(m)) => WebFetchOutcome::Ok(m),
        Ok(Err(reason)) => WebFetchOutcome::Miss(reason),
        Err(e) => WebFetchOutcome::Network(format!("verify task join failed: {e}")),
    }
}

/// Mirror .torrent validation: strict bencode decode -> raw info-slice
/// identity comparison (same shape as check_identity) -> piece-layer
/// completeness + Merkle validation. Returning Err = content void (the
/// void reason, a static string for log dedup).
fn verify_web_torrent(
    body: &[u8],
    btih: Option<[u8; 20]>,
    btmh: Option<[u8; 32]>,
) -> Result<WebMetadata, &'static str> {
    let (value, span) =
        bencode::decode_with_info_span(body).map_err(|_| "response not a bencode torrent")?;
    if span.start >= span.end {
        return Err("response has no info dict");
    }
    let info = body[span.start..span.end].to_vec();
    // Identity comparison (SPEC §2.1.7: raw-slice hashing; hybrid
    // verifies both identities).
    check_identity(&info, btih, btmh).map_err(|_| "infohash mismatch")?;
    if btmh.is_some() {
        let decoded = bencode::decode(&info).map_err(|_| "invalid v2 info dictionary")?;
        if decoded.get(b"meta version").and_then(Value::as_int) != Some(2) {
            return Err("v2 identity requires BEP52 metadata");
        }
    }
    let bytes = Bytes::from(info);
    // Piece-layer completeness: the layers hybrid/v2 needs must come
    // with the response and validate down to the pieces roots —
    // missing/mismatched = the whole response is void (after an HTTP
    // hit the peer pool may be empty; the prefetch fallback cannot be
    // relied on — see finalize).
    let (piece_len, wanted) = scan_layers_needed(&bytes).map_err(|_| "info dict unusable")?;
    if wanted.is_empty() {
        return Ok(WebMetadata {
            info: bytes,
            layers: Vec::new(),
        });
    }
    let Some(Value::Dict(layers_dict)) = value.get(b"piece layers") else {
        return Err("piece layers missing for v2/hybrid info dict");
    };
    let mut layers = Vec::with_capacity(wanted.len());
    for (root, length) in wanted {
        let Some(Value::Bytes(layer)) = layers_dict
            .iter()
            .find(|(k, _)| k.as_slice() == root)
            .map(|(_, v)| v)
        else {
            return Err("piece layers incomplete (root missing)");
        };
        if merkle::validate_piece_layer(&root, layer, length, piece_len).is_err() {
            return Err("piece layer failed merkle root check");
        }
        layers.push((root, layer.clone()));
    }
    Ok(WebMetadata {
        info: bytes,
        layers,
    })
}

/// Concurrently spin up the non-tripped mirrors (a single volley;
/// returning None = no usable face). One task per mirror; outcomes in
/// three classes — Ok delivered over the bounded channel (capacity =
/// mirror count, first win, the rest cancelled by md_token), Network
/// recorded for health, Miss only debugged.
pub(super) fn spawn_web_mirrors(
    cfg: &MagnetTaskConfig,
    _faces: &[MetaFace],
    md_token: &CancellationToken,
) -> Option<mpsc::Receiver<WebMetadata>> {
    const LOG_TARGET: &str = "taiji::core::magnet";
    let magnet = taiji_bt::magnet::parse(&cfg.magnet_uri).ok()?;
    let btih = magnet.btih;
    let btmh = magnet.btmh;
    let health = cfg
        .web
        .as_ref()
        .map(|mirrors| mirrors.health.clone())
        .unwrap_or_else(|| Arc::new(WebMirrorHealth::new()));
    let mut eligible = magnet.metadata_sources;
    if btih.is_some() {
        if let Some(mirrors) = &cfg.web {
            for template in mirrors
                .templates
                .iter()
                .filter(|template| !mirrors.health.blocked(template))
            {
                if !eligible.contains(template) {
                    eligible.push(template.clone());
                }
            }
        }
    }
    if eligible.is_empty() {
        return None;
    }
    // Client build failure = abandon the whole route (reqwest builder
    // face; rare).
    let client = match HttpAnnounce::new(&TrackerOptions::default()) {
        Ok(c) => c,
        Err(e) => {
            warn!(target: LOG_TARGET, %e, "web mirror http client build failed; path disabled");
            return None;
        }
    };
    let (tx, rx) = mpsc::channel::<WebMetadata>(4);
    let token = md_token.child_token();
    tokio::spawn(async move {
        use futures::StreamExt;
        futures::stream::iter(eligible.into_iter().enumerate()).for_each_concurrent(3,|(index,template)|{
            let client=client.clone();let health=health.clone();let tx=tx.clone();let token=token.clone();
            async move {tokio::select! {
                _=token.cancelled()=>{},
                outcome=fetch_from_mirror(&client,&template,btih,btmh)=>match outcome {
                    WebFetchOutcome::Ok(metadata)=>{health.note_success(&template);let _=tx.send(metadata).await;}
                    WebFetchOutcome::Network(reason)=>{health.note_failure(&template);debug!(target:LOG_TARGET,index,%reason,"metadata source unavailable");}
                    WebFetchOutcome::Miss(reason)=>{debug!(target:LOG_TARGET,index,reason,"metadata source failed identity validation");}
                }
            }}
        }).await;
    });
    Some(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use sha1::{Digest as _, Sha1};

    // Shared test infrastructure (`pub(crate)` inside magnet.rs tests;
    // the cross-submodule reuse face after the split).
    use crate::magnet::tests::{gid, web_mirror_torrent};
    use crate::magnet::{
        MagnetEnd, MagnetEngine, MagnetOptions, MagnetTaskConfig, MetadataPhaseConfig,
    };
    use crate::seed::SeedPolicy;

    #[test]
    fn web_mirror_template_parse_drops_invalid() {
        let raw = vec![
            "https://a.example/torrent/{INFOHASH}.torrent".to_string(),
            "ftp://b.example/{INFOHASH}".to_string(), // illegal scheme
            "https://c.example/torrent/constant".to_string(), // no placeholder
            "  https://d.example/{INFOHASH}  ".to_string(), // legal after trim
        ];
        let out = parse_web_mirror_templates(&raw);
        assert_eq!(
            out,
            vec![
                "https://a.example/torrent/{INFOHASH}.torrent".to_string(),
                "https://d.example/{INFOHASH}".to_string(),
            ]
        );
    }

    #[test]
    fn web_mirror_health_cooldown_and_reset() {
        let h = WebMirrorHealth::with_policy(3, Duration::from_millis(50));
        let key = "https://m/{INFOHASH}";
        h.note_failure(key);
        h.note_failure(key);
        assert!(!h.blocked(key), "two failures do not trip");
        // Content voids do not enter the network account (no note
        // interface — the Miss path never calls note_*).
        h.note_failure(key);
        assert!(
            h.blocked(key),
            "3 consecutive network failures trip the breaker"
        );
        // Cooldown expired: the blocked query itself ends the trip and
        // resets the count.
        std::thread::sleep(Duration::from_millis(60));
        assert!(!h.blocked(key), "cooldown expiry clears the trip");
        // After the reset, two more failures do not trip (the count was
        // cleared).
        h.note_failure(key);
        h.note_failure(key);
        assert!(!h.blocked(key));
        // A success clears the count: two failures + success + two
        // failures -> no trip.
        h.note_failure(key);
        h.note_success(key);
        h.note_failure(key);
        h.note_failure(key);
        assert!(!h.blocked(key));
    }

    #[test]
    fn verify_web_torrent_accepts_valid_and_rejects_forgeries() {
        let (torrent, btih, info) = web_mirror_torrent();
        // The genuine body: identity + structure all pass.
        let got = verify_web_torrent(&torrent, Some(btih), None)
            .unwrap_or_else(|e| panic!("valid torrent rejected: {e}"));
        assert_eq!(got.info.as_ref(), info.as_slice(), "raw info-section bytes");
        assert!(got.layers.is_empty(), "v1-only carries no layers");
        // Forged identity: wrong btih -> void.
        let wrong: [u8; 20] = Sha1::digest(b"wrong").into();
        assert!(
            matches!(
                verify_web_torrent(&torrent, Some(wrong), None),
                Err("infohash mismatch")
            ),
            "identity forgery must be rejected"
        );
        // Non-bencode response (an HTML error page) -> void.
        assert!(
            matches!(
                verify_web_torrent(b"<html>not found</html>", Some(btih), None),
                Err("response not a bencode torrent")
            ),
            "error page must be rejected"
        );
        // An over-cap body is voided at the fetch layer (the
        // fetch_from_mirror verdict; here only the structural face is
        // exercised: an empty body has no info dict -> void).
        assert!(
            verify_web_torrent(b"de", Some(btih), None).is_err(),
            "empty dict has no info"
        );
    }

    /// Integration: a loopback HTTP mirror (a native TcpListener).
    /// `mode`: 0 = a genuine .torrent; 1 = an HTML error page (content
    /// void). Returns (addr, request count).
    async fn web_mirror_server(
        mode: u8,
        body: Vec<u8>,
    ) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let (body, counter) = (body.clone(), Arc::clone(&counter));
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    if sock.read(&mut buf).await.is_err() {
                        return;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    let status = if mode == 1 { "404 Not Found" } else { "200 OK" };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                });
            }
        });
        (addr, hits)
    }

    /// Integration common face: run MagnetEngine with a magnet (tr =
    /// unreachable tracker) + a mirror template set, to the
    /// bt-metadata-only terminal state. A 15s deadline backstop.
    async fn run_with_web_mirrors(
        btih: [u8; 20],
        templates: Vec<String>,
        deadline: Duration,
    ) -> MagnetEnd {
        let cfg = MagnetTaskConfig {
            services: None,
            dht_entry_point_v6_override: None,
            dht_message_timeout: Duration::from_secs(10),
            dht_ipv6_enabled: false,
            tracker_updates: None,
            nat: None,
            dht_entry_point_override: None,
            gid: gid(),
            magnet_uri: format!(
                "magnet:?xt=urn:btih:{}&tr=http://127.0.0.1:1/ann",
                hex_lower(&btih)
            ),
            dest: PathBuf::from("/tmp/taiji-magnet-web-test"),
            peer_id: [0u8; 20],
            options: MagnetOptions {
                bt_metadata_only: true,
                ..MagnetOptions::default()
            },
            phase: MetadataPhaseConfig {
                listen_port: 0,
                discovery_round: Duration::from_millis(200),
                metadata_deadline: Some(deadline),
                ..MetadataPhaseConfig::default()
            },
            dht: None,
            dht_entry_points: vec![],
            dht_enabled: false,
            // Test face: webseeding on by default (the BEP19 face is
            // not exercised here).
            webseeding_enabled: true,
            lsd: None,
            seed: SeedPolicy::default(),
            seed_after_complete: false,
            persist: None,
            select_file: None,
            limiter: None,
            hook: None,
            web: Some(Arc::new(WebMirrors::new(
                templates,
                Arc::new(WebMirrorHealth::new()),
            ))),
            stats: None,
            // Existing cases carry no ban face (None = no gate, zero
            // behavior change); ban-gate-specific cases inject their
            // own snapshot.
            ip_guard: None,
        };
        let root = CancellationToken::new();
        MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[tokio::test]
    async fn explicit_magnet_source_works_without_trackers_or_implicit_mirrors() {
        let (torrent, btih, _) = crate::magnet::tests::web_mirror_torrent();
        let (address, hits) = web_mirror_server(0, torrent).await;
        let dir = std::env::temp_dir().join(format!("taiji-xs-{}", rand::random::<u64>()));
        let mut cfg = crate::magnet::tests::metadata_fixture_config(btih, dir.clone());
        cfg.magnet_uri = format!(
            "magnet:?xt=urn:btih:{}&xs=http%3A%2F%2F{}%2Fmetadata.torrent",
            hex_lower(&btih),
            address
        );
        cfg.web = None;
        cfg.dht_enabled = false;
        let root = CancellationToken::new();
        let end = super::super::MagnetEngine::spawn(cfg, &root)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            matches!(end, super::super::MagnetEnd::MetadataFetched { .. }),
            "{end:?}"
        );
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        std::fs::remove_dir_all(dir).unwrap_or_else(|e| panic!("{e}"));
    }

    #[tokio::test]
    async fn web_mirror_hit_fetches_verified_metadata() {
        let (torrent, btih, info) = web_mirror_torrent();
        let (addr, hits) = web_mirror_server(0, torrent.clone()).await;
        let template = format!("http://{addr}/torrent/{{INFOHASH}}.torrent");
        let end = run_with_web_mirrors(btih, vec![template], Duration::from_secs(15)).await;
        let MagnetEnd::MetadataFetched { metadata, .. } = end else {
            panic!("expected MetadataFetched, got {end:?}")
        };
        assert_eq!(
            metadata.as_ref(),
            info.as_slice(),
            "info section byte-identical"
        );
        assert_eq!(hits.load(Ordering::Relaxed), 1, "one volley = one request");
    }

    #[tokio::test]
    async fn web_mirror_bad_mirror_does_not_block_good_one() {
        let (torrent, btih, _info) = web_mirror_torrent();
        let (bad_addr, _bad_hits) = web_mirror_server(1, b"<html>not found</html>".to_vec()).await;
        let (good_addr, _good_hits) = web_mirror_server(0, torrent).await;
        let templates = vec![
            format!("http://{bad_addr}/torrent/{{INFOHASH}}.torrent"),
            format!("http://{good_addr}/torrent/{{INFOHASH}}.torrent"),
        ];
        let end = run_with_web_mirrors(btih, templates, Duration::from_secs(15)).await;
        assert!(
            matches!(end, MagnetEnd::MetadataFetched { .. }),
            "a bad mirror (error page) must not block a good one: {end:?}"
        );
    }

    #[tokio::test]
    async fn web_mirror_forged_identity_falls_back_to_honest_failure() {
        // The mirror serves **a different torrent** (infohash
        // mismatch): the response is void and P2P has no peers (tr
        // unreachable / DHT / LSD off) -> an honest deadline failure; a
        // forged torrent is never forced in.
        let (torrent, btih, _info) = web_mirror_torrent();
        let wrong_btih: [u8; 20] = Sha1::digest(b"someone else").into();
        let (addr, hits) = web_mirror_server(0, torrent).await;
        let template = format!("http://{addr}/torrent/{{INFOHASH}}.torrent");
        let end = run_with_web_mirrors(wrong_btih, vec![template], Duration::from_secs(3)).await;
        let MagnetEnd::Failed(reason) = &end else {
            panic!("expected honest failure, got {end:?}")
        };
        assert!(reason.contains("deadline"), "{reason}");
        let _ = btih;
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "forged response never re-enters the retry loop"
        );
    }
}

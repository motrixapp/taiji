//! HTTP tracker scrape (BEP48) with a seeds/leechers cache.
//!
//! aria2 has no scrape implementation (its only reference to SCRAPE is
//! `UDPTrackerClient.cc` discarding scrape replies as "unexpected scrape
//! action reply"), so the protocol facts here cite the BEP48 text directly.
//! Quoted rules and anchors: docs/design/tracker.md.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::bencode::{self, Value};

use super::{TrackerError, percent_encode};

/// Per-swarm scrape statistics (BEP48: complete/downloaded/incomplete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrapeStats {
    /// `complete`: active peers that finished downloading (seeders).
    pub complete: u64,
    /// `downloaded`: historical completions (BEP48 "have ever completed").
    pub downloaded: u64,
    /// `incomplete`: active peers still downloading (leechers).
    pub incomplete: u64,
}

/// Derive the scrape URL from an announce URL and append batched
/// info_hashes (BEP48: path segment `announce` -> `scrape`; each
/// `info_hash` parameter is percent-encoded and appended).
///
/// Returns [`TrackerError::InvalidUrl`] when the path segment (before `?`)
/// does not contain `/announce` (BEP48: URLs not derived this way are out
/// of spec).
pub fn build_scrape_url(
    announce_url: &str,
    info_hashes: &[[u8; 20]],
) -> Result<String, TrackerError> {
    let path_end = announce_url.find('?').unwrap_or(announce_url.len());
    let (path, rest) = announce_url.split_at(path_end);
    let pos = path
        .rfind("/announce")
        .ok_or_else(|| TrackerError::InvalidUrl(format!("no /announce in path: {announce_url}")))?;
    let mut url = String::with_capacity(announce_url.len() + info_hashes.len() * 60);
    url.push_str(&path[..pos]);
    url.push_str("/scrape");
    url.push_str(&path[pos + "/announce".len()..]);
    url.push_str(rest);
    // BEP48: the info_hash key may repeat, batching multiple swarms in one
    // request.
    url.push_str(if rest.is_empty() { "?" } else { "&" });
    for (i, hash) in info_hashes.iter().enumerate() {
        if i > 0 {
            url.push('&');
        }
        url.push_str("info_hash=");
        url.push_str(&percent_encode(hash));
    }
    Ok(url)
}

/// Parse a scrape response (BEP48 `files` dict; `failure reason` present
/// means an error; keys are the raw 20-byte info_hashes). Hashes missing
/// from the response do not appear in the return value.
pub fn parse_scrape_response(body: &[u8]) -> Result<Vec<([u8; 20], ScrapeStats)>, TrackerError> {
    let top = bencode::decode(body).map_err(|e| TrackerError::Malformed(e.to_string()))?;
    if let Some(reason) = top.get(b"failure reason").and_then(Value::as_bytes) {
        return Err(TrackerError::Failed(
            String::from_utf8_lossy(reason).into_owned(),
        ));
    }
    let files = top
        .get(b"files")
        .ok_or_else(|| TrackerError::Malformed("missing `files`".into()))?;
    let mut out = Vec::new();
    if let Some(entries) = files.as_dict() {
        for (key, val) in entries {
            if key.len() != 20 {
                return Err(TrackerError::Malformed(format!(
                    "files key length {} != 20",
                    key.len()
                )));
            }
            let mut hash = [0u8; 20];
            hash.copy_from_slice(key);
            let get_u64 = |name: &[u8]| -> u64 {
                val.get(name)
                    .and_then(Value::as_int)
                    .map(|v| v.max(0) as u64)
                    .unwrap_or(0)
            };
            out.push((
                hash,
                ScrapeStats {
                    complete: get_u64(b"complete"),
                    downloaded: get_u64(b"downloaded"),
                    incomplete: get_u64(b"incomplete"),
                },
            ));
        }
        return Ok(out);
    }
    Err(TrackerError::Malformed("`files` is not a dict".into()))
}

/// Seeds/leechers cache (the in-memory side of the tracker table's
/// seeds/leechers; sqlite persistence goes through PersistWriter). The TTL
/// is a taiji-local policy (no upstream basis, not a protocol constant);
/// the default 15min matches the periodic announce cadence.
#[derive(Debug)]
pub struct ScrapeCache {
    ttl: Duration,
    entries: HashMap<[u8; 20], (ScrapeStats, Instant)>,
}

impl ScrapeCache {
    pub fn new(ttl: Duration) -> Self {
        ScrapeCache {
            ttl,
            entries: HashMap::new(),
        }
    }

    /// Insert or refresh one stats entry.
    pub fn insert(&mut self, info_hash: [u8; 20], stats: ScrapeStats, now: Instant) {
        self.entries.insert(info_hash, (stats, now));
    }

    /// Get unexpired stats; expired entries are dropped lazily.
    pub fn get(&mut self, info_hash: &[u8; 20], now: Instant) -> Option<ScrapeStats> {
        match self.entries.get(info_hash) {
            Some((stats, at)) if now.duration_since(*at) < self.ttl => Some(*stats),
            Some(_) => {
                self.entries.remove(info_hash);
                None
            }
            None => None,
        }
    }

    /// Remove all expired entries; returns the number kept.
    pub fn prune(&mut self, now: Instant) -> usize {
        self.entries
            .retain(|_, (_, at)| now.duration_since(*at) < self.ttl);
        self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built vector (adapted from the BEP48 example): two hashes plus
    /// the failure-reason branch.
    #[test]
    fn parse_scrape_files_vector() {
        // BEP48 example: d5:filesd20:<hash1>d8:completei11e10:downloadedi13772e
        // 10:incompletei19e20:<hash2>d8:completei21e10:downloadedi206e
        // 10:incompletei20eeee
        let h1 = [0x11u8; 20];
        let h2 = [0x22u8; 20];
        let mut body = Vec::from(&b"d5:filesd"[..]);
        body.extend_from_slice(b"20:");
        body.extend_from_slice(&h1);
        body.extend_from_slice(b"d8:completei11e10:downloadedi13772e10:incompletei19ee");
        body.extend_from_slice(b"20:");
        body.extend_from_slice(&h2);
        body.extend_from_slice(b"d8:completei21e10:downloadedi206e10:incompletei20eee");
        body.extend_from_slice(b"e");
        let out = parse_scrape_response(&body).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0],
            (
                h1,
                ScrapeStats {
                    complete: 11,
                    downloaded: 13772,
                    incomplete: 19
                }
            )
        );
        assert_eq!(
            out[1],
            (
                h2,
                ScrapeStats {
                    complete: 21,
                    downloaded: 206,
                    incomplete: 20
                }
            )
        );
        // failure reason -> Failed (BEP48).
        assert!(matches!(
            parse_scrape_response(b"d14:failure reason9:no scrapee"),
            Err(TrackerError::Failed(m)) if m == "no scrape"
        ));
        // Missing files -> Malformed.
        assert!(matches!(
            parse_scrape_response(b"d8:intervali60ee"),
            Err(TrackerError::Malformed(_))
        ));
    }

    /// Scrape URL derivation vectors (BEP48: path segment announce ->
    /// scrape; batched info_hash; existing query preserved).
    #[test]
    fn scrape_url_vectors() {
        let h = [0xabu8; 20];
        let enc = percent_encode(&h);
        // Plain path.
        assert_eq!(
            build_scrape_url("http://t.example:8080/announce", &[h])
                .unwrap_or_else(|e| panic!("{e}")),
            format!("http://t.example:8080/scrape?info_hash={enc}")
        );
        // Two hashes batched.
        let h2 = [0xcdu8; 20];
        assert_eq!(
            build_scrape_url("http://t.example/announce", &[h, h2])
                .unwrap_or_else(|e| panic!("{e}")),
            format!(
                "http://t.example/scrape?info_hash={enc}&info_hash={}",
                percent_encode(&h2)
            )
        );
        // Path with a passkey (no heuristic for /announce/ sub-segment
        // forms: only the last /announce segment is replaced); the query is
        // kept after scrape.
        assert_eq!(
            build_scrape_url("http://t.example/announce?passkey=k", &[h])
                .unwrap_or_else(|e| panic!("{e}")),
            format!("http://t.example/scrape?passkey=k&info_hash={enc}")
        );
        // No /announce -> invalid (outside the BEP48 spec).
        assert!(matches!(
            build_scrape_url("http://t.example/foo", &[h]),
            Err(TrackerError::InvalidUrl(_))
        ));
    }

    /// Cache: readable within TTL, expired entries dropped, prune counting.
    #[test]
    fn scrape_cache_ttl() {
        let mut cache = ScrapeCache::new(Duration::from_secs(15 * 60));
        let t0 = Instant::now();
        let h1 = [1u8; 20];
        let h2 = [2u8; 20];
        cache.insert(
            h1,
            ScrapeStats {
                complete: 3,
                downloaded: 5,
                incomplete: 7,
            },
            t0,
        );
        cache.insert(
            h2,
            ScrapeStats {
                complete: 1,
                downloaded: 1,
                incomplete: 1,
            },
            t0 + Duration::from_secs(600),
        );
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&h1, t0).map(|s| s.complete), Some(3));
        // Within TTL (t0+10min).
        assert!(cache.get(&h2, t0 + Duration::from_secs(600)).is_some());
        // Beyond TTL (t0+20min): h1 expired and dropped.
        let t1 = t0 + Duration::from_secs(20 * 60);
        assert!(cache.get(&h1, t1).is_none());
        assert_eq!(
            cache.prune(t1),
            1,
            "h2 written at t0+600; at t1 14min < 15min"
        );
    }
}

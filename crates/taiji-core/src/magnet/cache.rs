//! Verified metadata cache shared across jobs and process restarts.
use std::sync::Mutex;

use bytes::Bytes;
use taiji_store::persist::{MetadataCacheIdentity, PersistHandle};
use tracing::warn;

use crate::metainfo::Metainfo;

const MEMORY_BYTES: usize = 16 * 1024 * 1024;
const MEMORY_ENTRIES: usize = 128;

pub(super) struct CacheHit {
    pub bytes: Bytes,
    pub origin: super::CacheOrigin,
}
impl std::ops::Deref for CacheHit {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

type Entry = (MetadataCacheIdentity, Bytes);

pub(super) struct MetadataCache {
    entries: Mutex<Vec<Entry>>,
    persist: Option<PersistHandle>,
}

impl MetadataCache {
    pub fn new(persist: Option<PersistHandle>) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            persist,
        }
    }

    pub async fn load(&self, v1: Option<[u8; 20]>, v2: Option<[u8; 32]>) -> Option<CacheHit> {
        let identity = MetadataCacheIdentity { v1, v2 };
        {
            let mut entries = crate::lock(&self.entries);
            if let Some(index) = entries.iter().position(|(key, _)| matches(*key, identity)) {
                let entry = entries.remove(index);
                let bytes = entry.1.clone();
                entries.push(entry);
                return Some(CacheHit {
                    bytes,
                    origin: super::CacheOrigin::Memory,
                });
            }
        }
        let persist = self.persist.as_ref()?;
        let bytes = match persist.load_metadata(identity).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return None,
            Err(error) => {
                warn!(target:"taiji::core::magnet", %error, "metadata cache read failed; using discovery");
                return None;
            }
        };
        let entry = tokio::task::spawn_blocking(move || canonical(&bytes, identity)).await;
        match entry {
            Ok(Some(entry)) => {
                let bytes = entry.1.clone();
                self.insert(entry);
                Some(CacheHit {
                    bytes,
                    origin: super::CacheOrigin::Persistent,
                })
            }
            Ok(None) => {
                if let Err(error) = persist.evict_metadata(Some(identity)).await {
                    warn!(target:"taiji::core::magnet", %error, "invalid metadata cache eviction failed");
                }
                None
            }
            Err(error) => {
                warn!(target:"taiji::core::magnet", %error, "metadata cache verification failed");
                None
            }
        }
    }

    pub async fn remember(&self, v1: Option<[u8; 20]>, v2: Option<[u8; 32]>, bytes: &[u8]) {
        if bytes.len() > MEMORY_BYTES {
            return;
        }
        let bytes = bytes.to_vec();
        let identity = MetadataCacheIdentity { v1, v2 };
        let entry = match tokio::task::spawn_blocking(move || canonical(&bytes, identity)).await {
            Ok(Some(entry)) => entry,
            Ok(None) => return,
            Err(error) => {
                warn!(target:"taiji::core::magnet", %error, "metadata cache verification failed");
                return;
            }
        };
        if let Some(persist) = &self.persist {
            if let Err(error) = persist.cache_metadata(entry.0, entry.1.to_vec()).await {
                warn!(target:"taiji::core::magnet", %error, "metadata cache write failed");
            }
        }
        self.insert(entry);
    }

    fn insert(&self, entry: Entry) {
        let mut entries = crate::lock(&self.entries);
        entries.retain(|(key, _)| {
            !(entry.0.v1.is_some() && key.v1 == entry.0.v1
                || entry.0.v2.is_some() && key.v2 == entry.0.v2)
        });
        while !entries.is_empty()
            && (entries.len() >= MEMORY_ENTRIES
                || entries.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() + entry.1.len()
                    > MEMORY_BYTES)
        {
            entries.remove(0);
        }
        entries.push(entry);
    }
}

fn matches(key: MetadataCacheIdentity, requested: MetadataCacheIdentity) -> bool {
    (requested.v1.is_some() || requested.v2.is_some())
        && requested.v1.is_none_or(|hash| key.v1 == Some(hash))
        && requested.v2.is_none_or(|hash| key.v2 == Some(hash))
}

fn canonical(bytes: &[u8], expected: MetadataCacheIdentity) -> Option<Entry> {
    if bytes.len() > MEMORY_BYTES || (expected.v1.is_none() && expected.v2.is_none()) {
        return None;
    }
    let (_, span) = taiji_bt::bencode::decode_with_info_span(bytes).ok()?;
    super::check_identity(&bytes[span.clone()], expected.v1, expected.v2).ok()?;
    let meta = Metainfo::parse(bytes).ok()?;
    let canonical =
        super::metadata2torrent(&bytes[span], &[], &super::services::cached_layers(bytes));
    if canonical.len() > MEMORY_BYTES {
        return None;
    }
    Some((
        MetadataCacheIdentity {
            v1: meta.meta.identity.v1,
            v2: meta.meta.identity.v2,
        },
        Bytes::from(canonical),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_store::persist::PersistWriter;

    #[tokio::test]
    async fn persistent_hybrid_cache_preserves_layers_and_rejects_corrupt_proofs() {
        let torrent = include_bytes!("../../../taiji-bt/tests/fixtures/hybrid_16k.torrent");
        let original = Metainfo::parse(torrent).unwrap_or_else(|e| panic!("{e}"));
        let identity = original.meta.identity;
        assert!(identity.v1.is_some() && identity.v2.is_some());
        let path = std::env::temp_dir().join(format!(
            "taiji-hybrid-cache-{}.sqlite3",
            rand::random::<u64>()
        ));
        let (writer, join) = PersistWriter::spawn(path.clone())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let cache = MetadataCache::new(Some(writer.clone()));
        cache.remember(identity.v1, identity.v2, torrent).await;
        drop(cache);
        drop(writer);
        join.await.unwrap_or_else(|e| panic!("{e}"));
        let (writer, join) = PersistWriter::spawn(path.clone())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let cache = MetadataCache::new(Some(writer.clone()));
        let cached = cache
            .load(None, identity.v2)
            .await
            .unwrap_or_else(|| panic!("v2 disk cache miss"));
        assert_eq!(
            Metainfo::parse(&cached)
                .unwrap_or_else(|e| panic!("{e}"))
                .meta
                .identity,
            identity
        );
        assert_eq!(super::super::services::cached_layers(&cached).len(), 2);
        drop(cache);

        use taiji_bt::bencode::{self, Value};
        let mut corrupt = bencode::decode(torrent).unwrap_or_else(|e| panic!("{e}"));
        let Value::Dict(top) = &mut corrupt else {
            panic!("top dictionary")
        };
        let Some((_, Value::Dict(layers))) = top
            .iter_mut()
            .find(|(key, _)| key.as_slice() == b"piece layers")
        else {
            panic!("piece layers")
        };
        let Some((_, Value::Bytes(layer))) = layers.first_mut() else {
            panic!("layer")
        };
        let first = layer
            .first_mut()
            .unwrap_or_else(|| panic!("non-empty proof"));
        *first ^= 1;
        let corrupt = bencode::encode(&corrupt).unwrap_or_else(|e| panic!("{e}"));
        let (_, span) = bencode::decode_with_info_span(&corrupt).unwrap_or_else(|e| panic!("{e}"));
        assert!(super::super::check_identity(&corrupt[span], identity.v1, identity.v2).is_ok());
        let key = MetadataCacheIdentity {
            v1: identity.v1,
            v2: identity.v2,
        };
        writer
            .cache_metadata(key, corrupt)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let cache = MetadataCache::new(Some(writer.clone()));
        assert!(cache.load(None, identity.v2).await.is_none());
        assert!(
            writer
                .load_metadata(key)
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .is_none()
        );
        drop(cache);
        drop(writer);
        join.await.unwrap_or_else(|e| panic!("{e}"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn persistent_cache_revalidates_identity_and_strips_previous_discovery_policy() {
        let (torrent, hash, _) = crate::magnet::tests::web_mirror_torrent();
        let path = std::env::temp_dir().join(format!(
            "taiji-verified-cache-{}.sqlite3",
            rand::random::<u64>()
        ));
        let (writer, join) = PersistWriter::spawn(path.clone())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let cache = MetadataCache::new(Some(writer.clone()));
        cache.remember(Some(hash), None, &torrent).await;
        drop(cache);
        drop(writer);
        join.await.unwrap_or_else(|e| panic!("{e}"));

        let (writer, join) = PersistWriter::spawn(path.clone())
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let cache = MetadataCache::new(Some(writer.clone()));
        let cached = cache
            .load(Some(hash), None)
            .await
            .unwrap_or_else(|| panic!("persistent hit"));
        let parsed = Metainfo::parse(&cached).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.meta.identity.v1, Some(hash));
        assert!(parsed.announce.is_empty());
        assert!(parsed.url_list.is_empty());
        assert!(cache.load(Some(hash), Some([9; 32])).await.is_none());
        drop(cache);

        // The database may contain malformed or externally modified cache bytes.
        writer
            .cache_metadata(
                MetadataCacheIdentity {
                    v1: Some(hash),
                    v2: None,
                },
                b"corrupt".to_vec(),
            )
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let cache = MetadataCache::new(Some(writer.clone()));
        assert!(cache.load(Some(hash), None).await.is_none());
        assert!(
            writer
                .load_metadata(MetadataCacheIdentity {
                    v1: Some(hash),
                    v2: None
                })
                .await
                .unwrap_or_else(|e| panic!("{e}"))
                .is_none()
        );
        cache.remember(Some(hash), None, &torrent).await;
        assert!(cache.load(Some(hash), None).await.is_some());
        drop(cache);
        drop(writer);
        join.await.unwrap_or_else(|e| panic!("{e}"));
        let _ = std::fs::remove_file(path);
    }
}

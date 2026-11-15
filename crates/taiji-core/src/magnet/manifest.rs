//! Park verified info for selection before waiting for v2 piece-layer proofs.
use std::sync::Arc;

use bytes::Bytes;
use taiji_bt::peer::{PeerCommand, PeerHandle as _};

use super::cache::VerifiedCacheEntry;
use super::{
    MagnetEnd, MagnetResolution, MagnetTaskConfig, MetadataChain, MetadataPhase,
    ResolutionMilestone, metadata2torrent, services,
};
use crate::metainfo::Metainfo;

/// A single admission result shared by parking, caching and native reads.
/// Original info bytes and paths are never replaced by output mappings.
pub(super) struct VerifiedInfo {
    pub meta: Metainfo,
    pub bytes: Vec<u8>,
    cache: Option<VerifiedCacheEntry>,
    verification_ready: bool,
}

pub(super) async fn park_selection(
    cfg: &MagnetTaskConfig,
    verified: VerifiedInfo,
    phase: Option<MetadataPhase>,
    chain: MetadataChain,
    resolution: Option<&Arc<MagnetResolution>>,
) -> MagnetEnd {
    if let Some(phase) = phase {
        phase.token.cancel();
    }
    if verified.verification_ready {
        if let Some(resolution) = resolution {
            resolution.mark(ResolutionMilestone::VerificationReady);
        }
    }
    if let (Some(services), Some(cache)) = (&cfg.services, verified.cache) {
        services.remember_verified(cache).await;
    }
    MagnetEnd::UpgradedPaused {
        chain,
        meta: Arc::new(verified.meta),
        torrent: verified.bytes,
    }
}

pub(super) fn selection_preview(cfg: &MagnetTaskConfig) -> bool {
    cfg.options.pause_metadata
        && cfg.options.follow_torrent
        && !cfg.options.bt_metadata_only
        && !cfg.options.bt_save_metadata
}

pub(super) async fn prepare_verified_info(
    cfg: &MagnetTaskConfig,
    magnet: &taiji_bt::magnet::Magnet,
    metadata: &Bytes,
    trackers: &mut Vec<String>,
    tiers: &mut Vec<(usize, String)>,
    cached: Option<(Metainfo, Vec<u8>)>,
    phase: Option<&MetadataPhase>,
) -> Result<VerifiedInfo, String> {
    let park = selection_preview(cfg);
    let fetched = cached.is_none();
    let metadata = metadata.clone();
    let current_trackers = trackers.clone();
    let layers = phase.and_then(|p| p.web_layers.clone()).unwrap_or_default();
    let private_trackers = cfg.options.task_trackers.clone().unwrap_or_else(|| {
        magnet
            .tr
            .iter()
            .map(|url| String::from_utf8_lossy(url).into_owned())
            .collect()
    });
    let selected = cfg.select_file.clone().or_else(|| magnet.so.clone());
    let normalized_private_trackers = private_trackers.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let (mut meta, mut bytes) = match cached {
            Some(cached) => cached,
            None => {
                let bytes = metadata2torrent(&metadata, &current_trackers, &layers);
                (Metainfo::parse(&bytes).map_err(|e| e.to_string())?, bytes)
            }
        };
        if fetched && meta.private {
            bytes = metadata2torrent(
                &meta.info_bytes,
                &private_trackers,
                &services::cached_layers(&bytes),
            );
            meta = Metainfo::parse(&bytes).map_err(|e| e.to_string())?;
        }
        taiji_engine::metainfo_admission::validate(&meta).map_err(|e| e.to_string())?;
        if park {
            let selectable = meta.meta.files.iter().filter(|f| !f.padding).count();
            if selectable == 0 {
                return Err("torrent has no selectable files".into());
            }
            if selected
                .as_ref()
                .is_some_and(|files| files.iter().any(|index| *index as usize >= selectable))
            {
                return Err("select-file/so= file index out of range".into());
            }
        }
        let verification_ready = !meta
            .meta
            .files
            .iter()
            .any(|f| f.layer_missing(meta.meta.piece_length));
        let cache = if park {
            VerifiedCacheEntry::from_admitted(&meta)
        } else {
            None
        };
        Ok::<_, String>(VerifiedInfo {
            meta,
            bytes,
            cache,
            verification_ready,
        })
    })
    .await
    .map_err(|e| format!("metadata parse task join failed: {e}"))?
    .map_err(|e| format!("verified info structure rejected: {e}"))?;
    if verified.meta.private {
        if let Some(phase) = phase {
            for peer in crate::lock(&phase.peers).iter() {
                if peer.handle.command(PeerCommand::DisableDiscovery).is_err() {
                    peer.token.cancel();
                }
            }
        }
        if fetched || cfg.options.known_private {
            *trackers = normalized_private_trackers;
            *tiers = trackers.iter().cloned().enumerate().collect();
        }
    }
    Ok(verified)
}

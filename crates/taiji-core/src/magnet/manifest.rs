//! Park verified info for selection before waiting for v2 piece-layer proofs.
use std::sync::Arc;

use super::services;
use bytes::Bytes;
use taiji_bt::peer::{PeerCommand, PeerHandle as _};
use taiji_domain::torrent_manifest::TorrentManifest;

use super::{
    MagnetEnd, MagnetResolution, MagnetTaskConfig, MetadataChain, MetadataPhase,
    ResolutionMilestone, metadata2torrent,
};
use crate::metainfo::Metainfo;

pub(super) async fn park_selection(
    cfg: &MagnetTaskConfig,
    metadata: &Bytes,
    trackers: &[String],
    cached: Option<(Metainfo, Vec<u8>)>,
    phase: Option<MetadataPhase>,
    chain: MetadataChain,
    resolution: Option<&Arc<MagnetResolution>>,
) -> MagnetEnd {
    let metadata = metadata.clone();
    let trackers = trackers.to_vec();
    let layers = phase
        .as_ref()
        .and_then(|phase| phase.web_layers.clone())
        .unwrap_or_default();
    let selected = cfg.select_file.clone().or_else(|| {
        taiji_bt::magnet::parse(&cfg.magnet_uri)
            .ok()
            .and_then(|magnet| magnet.so)
    });
    let artifact = tokio::task::spawn_blocking(move || {
        let (meta, bytes) = match cached {
            Some(cached) => cached,
            None => {
                let bytes = metadata2torrent(&metadata, &trackers, &layers);
                let meta = Metainfo::parse(&bytes).map_err(|error| error.to_string())?;
                (meta, bytes)
            }
        };
        taiji_engine::metainfo_admission::validate(&meta).map_err(|error| error.to_string())?;
        let selectable = meta.meta.files.iter().filter(|file| !file.padding).count();
        if selectable == 0 {
            return Err("torrent has no selectable files".to_string());
        }
        if selected
            .as_ref()
            .is_some_and(|files| files.iter().any(|index| *index as usize >= selectable))
        {
            return Err("select-file/so= file index out of range".to_string());
        }
        Ok((meta, bytes))
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|result| result);
    if let Some(phase) = phase {
        phase.token.cancel();
    }
    let (meta, torrent) = match artifact {
        Ok(artifact) => artifact,
        Err(error) => {
            return MagnetEnd::Failed(format!("verified info structure rejected: {error}"));
        }
    };
    if TorrentManifest::from_metainfo(&meta).verification_ready {
        if let Some(resolution) = resolution {
            resolution.mark(ResolutionMilestone::VerificationReady);
        }
    }
    // The content cache preserves verified info and any verified supplied layers.
    // Missing proof readiness is always derived from the metainfo model.
    if let Some(services) = &cfg.services {
        services
            .remember(meta.meta.identity.v1, meta.meta.identity.v2, &torrent)
            .await;
    }
    MagnetEnd::UpgradedPaused {
        chain,
        meta: Arc::new(meta),
        torrent,
    }
}

pub(super) async fn prepare_verified_info(
    cfg: &MagnetTaskConfig,
    magnet: &taiji_bt::magnet::Magnet,
    metadata: &Bytes,
    trackers: &mut Vec<String>,
    tiers: &mut Vec<(usize, String)>,
    metainfo: &mut Option<(Metainfo, Vec<u8>)>,
    phase: Option<&MetadataPhase>,
) -> Result<(), String> {
    let fetched = metainfo.is_none();
    if fetched {
        let bytes = metadata2torrent(
            metadata,
            trackers,
            &phase
                .as_ref()
                .and_then(|p| p.web_layers.clone())
                .unwrap_or_default(),
        );
        let private_trackers = cfg.options.task_trackers.clone().unwrap_or_else(|| {
            magnet
                .tr
                .iter()
                .map(|url| String::from_utf8_lossy(url).into_owned())
                .collect()
        });
        let parsed = tokio::task::spawn_blocking(move || {
            let meta = Metainfo::parse(&bytes).map_err(|e| e.to_string())?;
            taiji_engine::metainfo_admission::validate(&meta).map_err(|e| e.to_string())?;
            if meta.private {
                let bytes = metadata2torrent(
                    &meta.info_bytes,
                    &private_trackers,
                    &services::cached_layers(&bytes),
                );
                Ok::<_, String>((Metainfo::parse(&bytes).map_err(|e| e.to_string())?, bytes))
            } else {
                Ok((meta, bytes))
            }
        })
        .await;
        *metainfo = match parsed {
            Ok(Ok(value)) => Some(value),
            Ok(Err(error)) => {
                return Err(format!("verified info structure rejected: {error}"));
            }
            Err(error) => {
                return Err(format!("metadata parse task join failed: {error}"));
            }
        };
    }
    if metainfo.as_ref().is_some_and(|(meta, _)| meta.private) {
        // Stop PEX and holepunch immediately after learning the info privacy bit.
        if let Some(phase) = &phase {
            for peer in crate::lock(&phase.peers).iter() {
                if peer.handle.command(PeerCommand::DisableDiscovery).is_err() {
                    peer.token.cancel();
                }
            }
        }
        if fetched || cfg.options.known_private {
            *trackers = cfg.options.task_trackers.clone().unwrap_or_else(|| {
                magnet
                    .tr
                    .iter()
                    .map(|url| String::from_utf8_lossy(url).into_owned())
                    .collect()
            });
            *tiers = trackers.iter().cloned().enumerate().collect();
        }
    }
    Ok(())
}

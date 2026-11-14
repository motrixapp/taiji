//! magnet-face helpers: `magnet:` select parameter extraction
//! (magnet_selected_files), MagnetOptions merging with the option patch
//! (magnet_options_from_patch/apply_magnet_patch), single-tier
//! assembly, and the bittorrent dict view.
//!
//! Owns: magnet task payload shaping.
//! Does not own: the MagnetEngine full chain (crate::magnet) or the
//! activation control flow (tasks).

use super::*;

/// BEP53: the projection of a magnet URI's `so=` selection face
/// (None = not selected / parse failed — caller input already passed
/// strict parsing at add time, so failure here is only a defensive
/// path). Shared by the upgrade chain (magnet.rs) and the residency /
/// persistence projections. Note: the effective `select-file` option
/// value (`MagnetJob.selected_files`) takes priority over the URI
/// `so=` (None = the truth source falls back to re-parsing so=) — this
/// function is the selection-face merge single point, shared by the
/// persistence / residency / upgrade-chain projections.
pub(super) fn magnet_selected_files(magnet_uri: &str) -> Option<Vec<u32>> {
    taiji_bt::magnet::parse(magnet_uri).ok().and_then(|m| m.so)
}

/// A magnet task's effective selection face (**0-based**, the merge
/// single point): the `select-file` option value (the job mirror) wins,
/// falling back to re-parsing the magnet URI's `so=` when absent.
/// Consumers = the config_json persistence projection (job_config) and
/// upgrade residency — the two sources are mutually exclusive on the
/// add/changeOption faces (coexistence is an explicit conflict
/// rejection), and the recovery-chain backfill and the URI re-parse
/// share one source and value, so the merge is defensively sound.
pub(super) fn effective_magnet_selection(mj: &MagnetJob) -> Option<Vec<u32>> {
    mj.selected_files
        .clone()
        .or_else(|| magnet_selected_files(&mj.magnet_uri))
}

pub(super) fn magnet_options_from_patch(
    patch: &TaskOptionPatch,
    conn_type: taiji_bt::utp::PeerConnectionType,
) -> MagnetOptions {
    MagnetOptions {
        holepunch: true,
        known_private: false,
        task_trackers: None,
        bt_save_metadata: patch.bt_save_metadata.unwrap_or(false),
        bt_metadata_only: patch.bt_metadata_only.unwrap_or(false),
        follow_torrent: patch.follow_torrent.unwrap_or(true),
        // pause-metadata pass-through — the upgrade product reaches
        // session residency as a paused task via MagnetEnd::UpgradedPaused
        // (the same recovery semantics as an ordinary torrent row).
        pause_metadata: patch.pause_metadata.unwrap_or(false),
        bt_load_saved_metadata: patch.bt_load_saved_metadata.unwrap_or(false),
        // The outbound transport plan follows the global option
        // (consumed by the engine after upgrade).
        bt_peer_connection_type: conn_type,
    }
}

pub(super) fn apply_magnet_patch(options: &mut MagnetOptions, patch: &TaskOptionPatch) {
    if let Some(v) = patch.bt_save_metadata {
        options.bt_save_metadata = v;
    }
    if let Some(v) = patch.bt_metadata_only {
        options.bt_metadata_only = v;
    }
    if let Some(v) = patch.follow_torrent {
        options.follow_torrent = v;
    }
    if let Some(v) = patch.bt_load_saved_metadata {
        options.bt_load_saved_metadata = v;
    }
}

/// The metainfo only carries a single announce (the parse face stores no
/// announce-list) -> a single tier-0 table (magnet `tr` ordering
/// semantics: one tier per tr; tier numbers compact to 0..n).
pub(super) fn single_tier_from_announce(announce: &str) -> Vec<(usize, String)> {
    if announce.is_empty() {
        Vec::new()
    } else {
        vec![(0, announce.to_string())]
    }
}

/// The bittorrent sub-dict of a magnet (metadata-phase) task:
/// announceList = the magnet trs; comment/creation/name/mode default to
/// absent (metadata not ready, same as aria2 — the info dict is only
/// given when metadata is non-empty). private/metaVersion unknown ->
/// None (never over-reported; the value-range narrowing is noted).
pub(super) fn magnet_bittorrent_view(mj: &MagnetJob) -> BittorrentView {
    BittorrentView {
        v1_info_hash: mj.btih,
        comment: None,
        creation_date: None,
        mode: None,
        announce_list: group_tiers(&mj.tiers),
        name: None,
        meta_version: None,
        v2_info_hash: mj.btmh,
        private: None,
    }
}

//! Native verified file-list encoding; proof readiness remains explicit.
use serde_json::{Value, json};
use taiji_core::torrent_manifest::TorrentManifest;

pub(super) fn encode(manifest: TorrentManifest) -> Value {
    let files: Vec<_> = manifest
        .files
        .into_iter()
        .map(|file| {
            json!({
                "index": file.index, "components": file.components,
                "length": file.length, "padding": file.padding,
            })
        })
        .collect();
    json!({
        "infoHash": manifest.info_hash, "v1": manifest.v1, "v2": manifest.v2,
        "name": manifest.name, "multiFile": manifest.multi_file,
        "isPrivate": manifest.is_private, "verificationReady": manifest.verification_ready,
        "files": files,
    })
}

//! Bounded BEP52 piece-layer retrieval, authenticated to each file root.
use std::collections::BTreeMap;

use taiji_bt::peer::{ExpectedInfoHash, HashFetch, PeerCommand, PeerHandle as _, PeerTaskHandle};
use taiji_store::merkle;

use super::{MetaFace, MetadataPhase, metadata2torrent};
use crate::hash_fetch::HASH_FETCH_TIMEOUT;
use crate::metainfo::Metainfo;

const CHUNK_HASHES: u32 = 512;
const MAX_LAYER_BYTES: u64 = 16 * 1024 * 1024;

type WantedLayers = Vec<([u8; 32], u64)>;

pub(super) fn scan_layers_needed(metadata: &[u8]) -> Result<(u32, WantedLayers), String> {
    let meta = Metainfo::parse(&metadata2torrent(metadata, &[], &[])).map_err(|e| e.to_string())?;
    let length = meta.meta.piece_length;
    let files = meta
        .meta
        .files
        .iter()
        .filter_map(|file| {
            file.layer_missing(length)
                .then_some(file.pieces_root.map(|root| (root, file.length)))
                .flatten()
        })
        .collect();
    Ok((length, files))
}

#[derive(Clone, Copy, Debug)]
struct Request {
    base: u32,
    index: u32,
    length: u32,
    proof: u32,
}

fn requests(pieces: u64, piece_len: u32) -> Result<Vec<Request>, String> {
    merkle::validate_piece_len(piece_len).map_err(|e| e.to_string())?;
    if !(2..=MAX_LAYER_BYTES / 32).contains(&pieces) {
        return Err("piece-layer size exceeds the retrieval budget".into());
    }
    let width = (pieces as u32).next_power_of_two();
    let length = width.min(CHUNK_HASHES);
    let base = (piece_len / merkle::BLOCK_SIZE).ilog2();
    Ok((0..pieces as u32)
        .step_by(length as usize)
        .map(|index| Request {
            base,
            index,
            length,
            proof: width.ilog2().saturating_sub(1),
        })
        .collect())
}

/// Fold the returned subtree, then its ordered sibling proof to the info root.
/// No hash is admitted based only on a matching message header.
fn verified(request: Request, hashes: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if hashes.len() != taiji_bt::peer_wire::hashes_count_for(request.length, request.proof) as usize
    {
        return false;
    }
    let mut nodes = hashes[..request.length as usize].to_vec();
    while nodes.len() > 1 {
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| merkle::node_hash(&pair[0], &pair[1]))
            .collect();
    }
    let mut value = nodes[0];
    let mut index = request.index / request.length;
    for sibling in &hashes[request.length as usize..] {
        value = if index.is_multiple_of(2) {
            merkle::node_hash(&value, sibling)
        } else {
            merkle::node_hash(sibling, &value)
        };
        index /= 2;
    }
    index == 0 && &value == root
}

async fn fetch(
    request: Request,
    root: [u8; 32],
    peers: &[PeerTaskHandle],
    phase: &MetadataPhase,
) -> Result<Vec<[u8; 32]>, String> {
    for handle in peers {
        let (reply, receive) = tokio::sync::oneshot::channel();
        if handle
            .command(PeerCommand::RequestHashes {
                root,
                base: request.base,
                index: request.index,
                length: request.length,
                proof: request.proof,
                reply,
            })
            .is_err()
        {
            continue;
        }
        let response = tokio::select! {
            _ = phase.token.cancelled() => return Err("piece-layer retrieval cancelled".into()),
            response = tokio::time::timeout(HASH_FETCH_TIMEOUT, receive) => response,
        };
        if let Ok(Ok(Ok(HashFetch::Hashes(hashes)))) = response {
            if verified(request, &hashes, &root) {
                return Ok(hashes[..request.length as usize].to_vec());
            }
        }
    }
    Err("piece layer fetch failed on all peers (reject/timeout/root mismatch)".into())
}

pub(super) async fn prefetch_piece_layers(
    metadata: &[u8],
    phase: &MetadataPhase,
    faces: &[MetaFace],
) -> Result<Vec<([u8; 32], Vec<u8>)>, String> {
    // Reuse the complete structure/identity parser; missing layers are explicit
    // in its model, while malformed provided layers remain a hard rejection.
    let torrent = metadata2torrent(metadata, &[], &[]);
    let meta = tokio::task::spawn_blocking(move || Metainfo::parse(&torrent))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let piece_len = meta.meta.piece_length;
    let mut wanted = BTreeMap::new();
    let mut bytes = 0u64;
    for file in &meta.meta.files {
        if file.layer_missing(piece_len) {
            let root = file.pieces_root.ok_or("missing file root")?;
            if wanted.insert(root, file.length).is_none() {
                bytes = bytes.saturating_add(file.length.div_ceil(u64::from(piece_len)) * 32);
            }
        }
    }
    if bytes > MAX_LAYER_BYTES {
        return Err("piece layers exceed the 16 MiB retrieval budget".into());
    }
    let mut peers: Vec<_> = crate::lock(&phase.peers)
        .iter()
        .filter(|peer| !peer.token.is_cancelled())
        .map(|peer| {
            let v2 = faces
                .get(peer.face)
                .is_some_and(|face| matches!(face.expected, ExpectedInfoHash::V2(_)));
            (!v2, peer.handle.clone())
        })
        .collect();
    peers.sort_by_key(|(priority, _)| *priority);
    let peers: Vec<_> = peers.into_iter().map(|(_, handle)| handle).collect();
    let mut out = Vec::with_capacity(wanted.len());
    for (root, length) in wanted {
        let pieces = length.div_ceil(u64::from(piece_len));
        let mut layer = Vec::with_capacity(pieces as usize * 32);
        for request in requests(pieces, piece_len)? {
            let hashes = fetch(request, root, &peers, phase).await?;
            let take = (pieces - u64::from(request.index)).min(u64::from(request.length));
            for hash in &hashes[..take as usize] {
                layer.extend_from_slice(hash);
            }
        }
        merkle::validate_piece_layer(&root, &layer, length, piece_len)
            .map_err(|e| e.to_string())?;
        out.push((root, layer));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segmented_layers_authenticate_non_power_of_two_files_and_reject_bad_proofs() {
        for piece_len in [16384, 32768, 262144, 1048576] {
            for pieces in [2u64, 3, 511, 512, 513, 1025] {
                let pad = merkle::empty_piece_root((piece_len / merkle::BLOCK_SIZE) as usize);
                let leaves: Vec<_> = (0..pieces)
                    .map(|index| merkle::block_hash(&index.to_be_bytes()))
                    .collect();
                let mut tree = leaves.clone();
                tree.resize(tree.len().next_power_of_two(), pad);
                let mut layers = vec![tree];
                while layers.last().is_some_and(|layer| layer.len() > 1) {
                    let parent = layers
                        .last()
                        .unwrap_or_else(|| panic!("missing Merkle layer"))
                        .chunks_exact(2)
                        .map(|pair| merkle::node_hash(&pair[0], &pair[1]))
                        .collect();
                    layers.push(parent);
                }
                let root = layers
                    .last()
                    .unwrap_or_else(|| panic!("missing Merkle layer"))[0];
                let mut received = Vec::new();
                for request in requests(pieces, piece_len).unwrap_or_else(|e| panic!("{e}")) {
                    assert_eq!(request.base, (piece_len / merkle::BLOCK_SIZE).ilog2());
                    assert!(request.length <= 512);
                    let start = request.index as usize;
                    let mut response = layers[0][start..start + request.length as usize].to_vec();
                    let mut index = start / request.length as usize;
                    for layer in &layers[request.length.ilog2() as usize..layers.len() - 1] {
                        response.push(layer[index ^ 1]);
                        index /= 2;
                    }
                    assert!(verified(request, &response, &root));
                    received.extend_from_slice(&response[..request.length as usize]);
                    let last = response.len() - 1;
                    response[last][0] ^= 1;
                    assert!(!verified(request, &response, &root));
                }
                received.truncate(pieces as usize);
                assert_eq!(received, leaves);
            }
        }
    }
}

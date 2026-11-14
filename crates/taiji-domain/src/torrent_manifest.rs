//! Verified info projection, independent of download verification readiness.

use crate::metainfo::Metainfo;
use std::collections::BTreeMap;
use taiji_bt::bencode::{self, Value};
use taiji_store::persist::RecoveredLayerRow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorrentManifest {
    pub info_hash: String,
    pub v1: Option<String>,
    pub v2: Option<String>,
    pub name: String,
    pub multi_file: bool,
    pub is_private: bool,
    pub verification_ready: bool,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFile {
    pub index: usize,
    /// Full relative display path, with explicit component boundaries.
    pub components: Vec<String>,
    pub length: u64,
    pub padding: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl TorrentManifest {
    pub fn from_metainfo(meta: &Metainfo) -> Self {
        let v1 = meta.meta.identity.v1.map(|hash| hex(&hash));
        let v2 = meta.meta.identity.v2.map(|hash| hex(&hash));
        let info_hash = v1.as_ref().or(v2.as_ref()).cloned().unwrap_or_default();
        let mut paths: Vec<Vec<String>> = meta
            .meta
            .files
            .iter()
            .map(|file| {
                file.path
                    .iter()
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect()
            })
            .collect();
        let first = paths.first().and_then(|path| path.first()).cloned();
        let name = if meta.multi_file {
            meta.name
                .clone()
                .unwrap_or_else(|| format!("torrent-{info_hash}"))
        } else {
            first.unwrap_or_else(|| format!("torrent-{info_hash}"))
        };
        let multi_file = meta.multi_file || paths.first().is_some_and(|path| path.len() > 1);
        if meta.multi_file {
            for path in &mut paths {
                path.insert(0, name.clone());
            }
        }
        let files = meta
            .meta
            .files
            .iter()
            .zip(paths)
            .enumerate()
            .map(|(index, (file, components))| ManifestFile {
                index,
                components,
                length: file.length,
                padding: file.padding,
            })
            .collect();
        Self {
            info_hash,
            v1,
            v2,
            name,
            multi_file,
            is_private: meta.private,
            verification_ready: !meta
                .meta
                .files
                .iter()
                .any(|file| file.layer_missing(meta.meta.piece_length)),
            files,
        }
    }
}

/// Upgrade a portable artifact with revalidated runtime proofs. The info slice
/// is copied verbatim, including noncanonical v1 encodings and all identities.
pub fn enrich(
    bytes: Vec<u8>,
    recovered: Vec<RecoveredLayerRow>,
) -> Result<(Metainfo, Vec<u8>), String> {
    let mut meta = Metainfo::parse(&bytes).map_err(|e| e.to_string())?;
    let mut changed = false;
    let mut resident: usize = meta
        .meta
        .files
        .iter()
        .filter_map(|f| f.piece_layer.as_ref())
        .map(|layer| layer.len())
        .sum();
    for row in recovered {
        let Some(file) = meta.meta.files.get_mut(row.file_index as usize) else {
            continue;
        };
        let Some(root) = file.pieces_root else {
            continue;
        };
        if row.piece_length != i64::from(meta.meta.piece_length)
            || u64::try_from(row.file_length).ok() != Some(file.length)
            || row.pieces_root.as_slice() != root.as_slice()
            || file.piece_layer.is_some()
            || resident.saturating_add(row.layer.len()) > 16 * 1024 * 1024
            || taiji_store::merkle::validate_piece_layer(
                &root,
                &row.layer,
                file.length,
                meta.meta.piece_length,
            )
            .is_err()
        {
            continue;
        }
        resident += row.layer.len();
        file.piece_layer = Some(bytes::Bytes::from(row.layer));
        changed = true;
    }
    if !changed {
        return Ok((meta, bytes));
    }
    let (Value::Dict(mut entries), span) =
        bencode::decode_with_info_span(&bytes).map_err(|e| e.to_string())?
    else {
        return Err("torrent envelope is not a dictionary".into());
    };
    let layers: BTreeMap<_, _> = meta
        .meta
        .files
        .iter()
        .filter_map(|file| {
            file.pieces_root
                .zip(file.piece_layer.as_ref())
                .map(|(root, layer)| (root.to_vec(), Value::Bytes(layer.to_vec())))
        })
        .collect();
    entries.retain(|(key, _)| key.as_slice() != b"piece layers");
    entries.push((
        b"piece layers".to_vec(),
        Value::Dict(layers.into_iter().collect()),
    ));
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut output = vec![b'd'];
    for (key, value) in entries {
        output.extend(bencode::encode(&Value::Bytes(key.clone())).map_err(|e| e.to_string())?);
        if key == b"info" {
            output.extend_from_slice(&bytes[span.clone()]);
        } else {
            output.extend(bencode::encode(&value).map_err(|e| e.to_string())?);
        }
    }
    output.push(b'e');
    Ok((meta, output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use taiji_store::merkle;
    fn dict(entries: Vec<(&str, Value)>) -> Value {
        let mut entries: Vec<_> = entries
            .into_iter()
            .map(|(key, value)| (key.as_bytes().to_vec(), value))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Value::Dict(entries)
    }
    #[test]
    fn recovered_proofs_preserve_info_identity_and_outer_metadata() {
        let roots = [
            merkle::block_hash(b"piece one"),
            merkle::block_hash(b"piece two"),
        ];
        let root = merkle::node_hash(&roots[0], &roots[1]);
        let leaf = dict(vec![
            ("length", Value::Int(65536)),
            ("pieces root", Value::Bytes(root.to_vec())),
        ]);
        let info = dict(vec![
            (
                "file tree",
                dict(vec![("file.bin", dict(vec![("", leaf)]))]),
            ),
            ("meta version", Value::Int(2)),
            ("name", Value::Bytes(b"file.bin".to_vec())),
            ("piece length", Value::Int(32768)),
        ]);
        let bytes = bencode::encode(&dict(vec![
            ("comment", Value::Bytes(b"preserved".to_vec())),
            ("info", info),
        ]))
        .unwrap_or_else(|e| panic!("{e}"));
        let original = Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert!(!TorrentManifest::from_metainfo(&original).verification_ready);
        let row = RecoveredLayerRow {
            gid: "task".into(),
            file_index: 0,
            piece_length: 32768,
            file_length: 65536,
            pieces_root: root.to_vec(),
            layer: roots.concat(),
        };
        let mut bad = row.clone();
        bad.layer[0] ^= 1;
        let (rejected, unchanged) =
            enrich(bytes.clone(), vec![bad]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(unchanged, bytes);
        assert!(!TorrentManifest::from_metainfo(&rejected).verification_ready);
        let (meta, complete) = enrich(bytes, vec![row]).unwrap_or_else(|e| panic!("{e}"));
        assert!(TorrentManifest::from_metainfo(&meta).verification_ready);
        let parsed = Metainfo::parse(&complete).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed.info_bytes, original.info_bytes);
        assert_eq!(parsed.meta.identity, original.meta.identity);
        let decoded = bencode::decode(&complete).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            decoded.get(b"comment"),
            Some(&Value::Bytes(b"preserved".to_vec()))
        );
    }
}

//! Host-authorized relative BT output paths. Content identities and raw
//! metainfo bytes remain unchanged; only the disk layout paths are mapped.
use super::*;
use std::path::Component;

pub(super) fn parse(
    options: &BTreeMap<String, String>,
    files: usize,
) -> Result<BTreeMap<usize, PathBuf>, SessionError> {
    let Some(raw) = options.get("motrix-output-paths") else {
        return Ok(BTreeMap::new());
    };
    let paths: BTreeMap<usize, PathBuf> = serde_json::from_str(raw)
        .map_err(|_| SessionError::failed("invalid torrent output paths"))?;
    validate(&paths, files, false)?;
    Ok(paths)
}
fn validate(
    paths: &BTreeMap<usize, PathBuf>,
    files: usize,
    collisions: bool,
) -> Result<(), SessionError> {
    let mut seen = std::collections::BTreeSet::new();
    for (&index, path) in paths {
        if index >= files
            || path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
            || path.to_string_lossy().contains(['\\', ':', '\0'])
            || (collisions && !seen.insert(path.clone()))
        {
            return Err(SessionError::failed("unsafe torrent output mapping"));
        }
    }
    for path in &seen {
        for ancestor in path.ancestors().skip(1) {
            if seen.contains(ancestor) {
                return Err(SessionError::failed("overlapping torrent output mapping"));
            }
        }
    }
    Ok(())
}
pub(crate) fn apply(
    meta: &mut Metainfo,
    paths: &BTreeMap<usize, PathBuf>,
) -> Result<(), SessionError> {
    validate(paths, meta.meta.files.len(), false)?;
    if !paths.is_empty() && meta.multi_file {
        // Mappings are relative to the host's output root and already include
        // any desired root directory. Flatten the disk prefix exactly once;
        // preserve untouched file paths in the same coordinate system.
        if let Some(root) = &meta.name {
            for file in &mut meta.meta.files {
                file.path = PathBuf::from(root).join(&file.path);
            }
        }
        meta.multi_file = false;
    }
    for (&index, path) in paths {
        meta.meta.files[index].path = path.clone();
    }
    // Validate the combined mapped and untouched layout as well.
    let combined = meta
        .meta
        .files
        .iter()
        .enumerate()
        .filter(|(_, file)| !file.padding)
        .map(|(index, file)| (index, file.path.clone()))
        .collect();
    validate(&combined, meta.meta.files.len(), true)
}

pub(crate) fn legacy(
    meta: &mut Metainfo,
    values: &[String],
    fallback: &str,
) -> Result<(String, BTreeMap<usize, PathBuf>), String> {
    let mut absolute = BTreeMap::new();
    for value in values {
        let (index, raw) = value
            .split_once('=')
            .ok_or("invalid legacy output mapping")?;
        let index = index
            .parse::<usize>()
            .ok()
            .and_then(|v| v.checked_sub(1))
            .ok_or("invalid legacy file index")?;
        let path = PathBuf::from(raw);
        let path = if path.is_absolute() {
            path
        } else {
            PathBuf::from(fallback).join(path)
        };
        if absolute.insert(index, path).is_some() {
            return Err("duplicate legacy file index".into());
        }
    }
    if absolute.is_empty() {
        return Ok((fallback.into(), BTreeMap::new()));
    }
    let mut root = absolute
        .values()
        .next()
        .and_then(|p| p.parent())
        .ok_or("invalid legacy output path")?
        .to_path_buf();
    while !absolute.values().all(|p| p.starts_with(&root)) {
        if !root.pop() {
            return Err("legacy outputs have no common root".into());
        }
    }
    let mut paths = BTreeMap::new();
    // Include untouched paths so changing the common directory never moves them.
    for (index, file) in meta.meta.files.iter().enumerate() {
        let original = PathBuf::from(fallback).join(&file.path);
        let absolute = absolute.get(&index).unwrap_or(&original);
        let relative = absolute
            .strip_prefix(&root)
            .map_err(|_| "legacy output lies outside common root")?;
        paths.insert(index, relative.to_path_buf());
    }
    apply(meta, &paths).map_err(|e| e.to_string())?;
    Ok((root.display().to_string(), paths))
}

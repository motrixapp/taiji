//! Structural admission shared by early manifests and payload assembly.
use taiji_bt::filetree::SwarmKind;
use taiji_domain::metainfo::{Metainfo, MetainfoError};
use taiji_store::layout::Layout;

pub fn validate(meta: &Metainfo) -> Result<(), MetainfoError> {
    layouts(meta).map(|_| ())
}

pub(crate) fn layouts(meta: &Metainfo) -> Result<(Layout, Layout), MetainfoError> {
    let wire = meta.meta.layout()?;
    let disk = meta.disk_layout()?;
    let length = u64::from(meta.meta.piece_length);
    let v1 = wire.total().div_ceil(length);
    let v2 = meta
        .meta
        .files
        .iter()
        .map(|file| file.length.div_ceil(length))
        .fold(0, u64::saturating_add);
    if meta.meta.kind != SwarmKind::V2Only {
        crate::config::ensure_piece_budget(v1)?;
        if meta.meta.identity.v1.is_none() {
            return Err(MetainfoError::NoV1Pieces);
        }
        if meta.v1_pieces.len() as u64 != v1 {
            return Err(MetainfoError::PiecesCountMismatch {
                got: meta.v1_pieces.len(),
                expected: v1 as usize,
            });
        }
    }
    if meta.meta.kind != SwarmKind::V1Only {
        crate::config::ensure_piece_budget(v2)?;
        if meta.meta.identity.v2.is_none() {
            return Err(MetainfoError::NoV2Identity);
        }
    }
    if meta.meta.kind == SwarmKind::Hybrid && v1 != v2 {
        return Err(MetainfoError::FacePieceCountMismatch {
            v1: v1 as usize,
            v2: v2 as usize,
        });
    }
    if meta.meta.kind == SwarmKind::Hybrid {
        for file in &meta.meta.files {
            if file.length > 0
                && !file
                    .v1_offset
                    .is_some_and(|offset| offset.is_multiple_of(length))
            {
                return Err(MetainfoError::MisalignedHybridLayout {
                    index: file.v1_offset.unwrap_or(0),
                });
            }
        }
    }
    Ok((wire, disk))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn early_admission_rejects_a_hash_count_that_cannot_cover_the_file() {
        let bytes=b"d4:infod6:lengthi32768e4:name1:x12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaaee";
        let meta = Metainfo::parse(bytes).unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            validate(&meta),
            Err(MetainfoError::PiecesCountMismatch {
                got: 1,
                expected: 2
            })
        ));
    }
}

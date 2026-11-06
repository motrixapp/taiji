//! The shared store-backed `MediaLedger` for the fixture test binaries
//! (the download/decrypt e2e suites each carry an identical private copy; this
//! module factors that shape for the new suites without touching the
//! already-merged files — test-support only).

#![allow(dead_code)]

use futures::future::BoxFuture;

use taiji_media::MediaError;
use taiji_media::keys::KeyRecord;
use taiji_media::trackdl::{MediaLedger, MediaTaskRecord, SegmentRecord, TrackRecord};
use taiji_store::persist::writer::{
    MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow, PersistWriter,
};

pub struct StoreLedger {
    pub handle: taiji_store::persist::writer::PersistHandle,
}

impl MediaLedger for StoreLedger {
    fn ensure_task<'a>(
        &'a self,
        row: &'a MediaTaskRecord,
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            let store_row = MediaTaskRow {
                gid: row.gid.clone(),
                kind: row.kind.clone(),
                manifest_url: row.manifest_url.clone(),
                state: row.state.clone(),
                phase_detail_json: None,
                variant_json: None,
                selector_json: None,
                output_name: None,
                bridge_json: None,
                staging_dir: row.staging_dir.clone(),
                output_path: row.output_path.clone(),
                manifest_norm_digest: row.manifest_norm_digest.clone(),
                total_done: 0,
                config_json: row.config_json.clone(),
                error_code: None,
                error_msg: None,
                created_at: 0,
                updated_at: 0,
            };
            self.handle
                .upsert_media_task(store_row)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(())
        })
    }

    fn save_track<'a>(
        &'a self,
        gid: &'a str,
        track: &'a TrackRecord,
        segments: &'a [SegmentRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            let store_track = MediaTrackRow {
                gid: gid.to_string(),
                track_idx: track.track_idx as i64,
                kind: track.kind.clone(),
                playlist_uri: track.playlist_uri.clone(),
                local_name: track.local_name.clone(),
                init_files_json: Some(
                    serde_json::to_string(&track.init_files).unwrap_or_else(|_| "[]".into()),
                ),
                seg_bitmap: Some(track.seg_bitmap.clone()),
                seg_count: Some(track.seg_count as i64),
            };
            let store_segments: Vec<MediaSegmentRow> = segments
                .iter()
                .map(|s| MediaSegmentRow {
                    gid: gid.to_string(),
                    track_idx: track.track_idx as i64,
                    seg_idx: s.seg_idx as i64,
                    media_sequence: Some(s.media_sequence as i64),
                    uri: s.uri.clone(),
                    byte_range: s.byte_range.clone(),
                    key_id: s.key_id,
                    seg_len: s.seg_len as i64,
                    duration_ms: Some(s.duration_ms as i64),
                    validator_digest: Some(s.validator_digest.clone()),
                    map_idx: s.map.map(|m| m as i64),
                })
                .collect();
            self.handle
                .replace_media_track(store_track, store_segments)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(())
        })
    }

    fn load_track<'a>(
        &'a self,
        gid: &'a str,
        track_idx: usize,
    ) -> BoxFuture<'a, Result<Option<(TrackRecord, Vec<SegmentRecord>)>, MediaError>> {
        Box::pin(async move {
            let all = self
                .handle
                .load_media_tracks(gid)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            let Some((t, segs)) = all
                .into_iter()
                .find(|(t, _)| t.track_idx as usize == track_idx)
            else {
                return Ok(None);
            };
            let track = TrackRecord {
                track_idx: t.track_idx as usize,
                kind: t.kind,
                playlist_uri: t.playlist_uri,
                local_name: t.local_name,
                init_files: t
                    .init_files_json
                    .and_then(|j| serde_json::from_str(&j).ok())
                    .unwrap_or_default(),
                seg_bitmap: t.seg_bitmap.unwrap_or_default(),
                seg_count: t.seg_count.unwrap_or(0) as usize,
            };
            let segments = segs
                .into_iter()
                .map(|s| SegmentRecord {
                    seg_idx: s.seg_idx as usize,
                    media_sequence: s.media_sequence.unwrap_or(0) as u64,
                    uri: s.uri,
                    byte_range: s.byte_range,
                    key_id: s.key_id,
                    seg_len: s.seg_len as u64,
                    duration_ms: s.duration_ms.unwrap_or(0) as u64,
                    map: s.map_idx.map(|m| m as usize),
                    validator_digest: s.validator_digest.unwrap_or_default(),
                })
                .collect();
            Ok(Some((track, segments)))
        })
    }

    fn upsert_media_keys<'a>(
        &'a self,
        gid: &'a str,
        keys: &'a [KeyRecord],
    ) -> BoxFuture<'a, Result<(), MediaError>> {
        Box::pin(async move {
            let rows: Vec<MediaKeyRow> = keys
                .iter()
                .map(|k| MediaKeyRow {
                    id: None,
                    gid: gid.to_string(),
                    key_id: k.key_id.clone(),
                    uri: k.uri.clone(),
                    iv: k.iv.map(|iv| iv.to_vec()),
                    key: k.key.to_vec(),
                })
                .collect();
            self.handle
                .upsert_media_keys(gid, rows)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(())
        })
    }

    fn load_media_keys<'a>(
        &'a self,
        gid: &'a str,
    ) -> BoxFuture<'a, Result<Vec<KeyRecord>, MediaError>> {
        Box::pin(async move {
            let rows = self
                .handle
                .load_media_keys(gid)
                .await
                .map_err(|e| MediaError::Staging(format!("ledger: {e}")))?;
            Ok(rows
                .into_iter()
                .map(|r| KeyRecord {
                    db_id: r.id,
                    key_id: r.key_id,
                    uri: r.uri,
                    iv: r.iv.and_then(|iv| <[u8; 16]>::try_from(iv.as_slice()).ok()),
                    key: r.key.try_into().unwrap_or([0; 16]),
                })
                .collect())
        })
    }
}

/// Spawn a ledger over a fresh sqlite file (db dir = caller's).
pub async fn spawn_ledger(db_path: &std::path::Path) -> (StoreLedger, tokio::task::JoinHandle<()>) {
    let (handle, join) = PersistWriter::spawn(db_path.to_path_buf())
        .await
        .unwrap_or_else(|e| panic!("writer spawn: {e}"));
    (StoreLedger { handle }, join)
}

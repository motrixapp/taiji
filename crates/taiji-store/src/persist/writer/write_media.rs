//! media business-row write/read faces: media_track/
//! media_segment write enablement + the minimal media_task parent row
//! that anchors their FKs; the task-row *orchestration* state machine
//! stays on the media mount — this face persists rows, it does not
//! drive phases.
//!
//! Semantics mirror the sibling faces: row-comparison skip-write
//! (observational created_at/updated_at excluded), whole-set
//! replacement for a track's segments inside one transaction, an
//! explicit error on a dangling FK (a track row must not exist
//! without its task row), and the recovery read face (per-task tracks
//! + segments, deterministic order).
//!
//! Pre-release discipline: the DDL (including this face's
//! `validator_digest` column) is settled-as-written until the first
//! external release freezes the migration baseline; dev databases
//! rebuild.

use rusqlite::{Connection, OptionalExtension, params};
use tracing::warn;

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::{
    MediaArchiveRow, MediaFormatRow, MediaKeyRow, MediaSegmentRow, MediaTaskRow, MediaTrackRow,
};
use super::task_phase::{TaskFamily, TaskPhase};

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const MEDIA_TASK_READ_COLS: &str = "gid, kind, manifest_url, state, phase_detail_json, \
     variant_json, selector_json, output_name, bridge_json, staging_dir, output_path, \
     manifest_norm_digest, total_done, config_json, error_code, error_msg, created_at, updated_at";

fn read_media_task_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MediaTaskRow> {
    Ok(MediaTaskRow {
        gid: r.get(0)?,
        kind: r.get(1)?,
        manifest_url: r.get(2)?,
        state: r.get(3)?,
        phase_detail_json: r.get(4)?,
        variant_json: r.get(5)?,
        selector_json: r.get(6)?,
        output_name: r.get(7)?,
        bridge_json: r.get(8)?,
        staging_dir: r.get(9)?,
        output_path: r.get(10)?,
        manifest_norm_digest: r.get(11)?,
        total_done: r.get(12)?,
        config_json: r.get(13)?,
        error_code: r.get(14)?,
        error_msg: r.get(15)?,
        created_at: r.get(16)?,
        updated_at: r.get(17)?,
    })
}

/// Upsert one media_task row (row-comparison skip; created_at keeps
/// its initial value, updated_at = writer-side now).
/// The error-terminal **partial-column** update — state,
/// error fields, updated_at only. The row's facts (kind,
/// manifest_url, the variant/selector snapshots, output_name,
/// manifest_norm_digest, progress, created_at) stay exactly as the
/// run wrote them; the pre-fix whole-row fail path clobbered them
/// with template placeholders (a DASH task's row read back `hls`
/// with no product name). Hit = `Written`; no row for the gid =
/// `SkippedUnchanged` (the caller falls back to the fresh-row
/// insert — nothing existed to preserve). Routed explicitly (like
/// [`unpause_media_task`]/[`reopen_media_task`]) because the plain
/// upsert is whole-row by contract.
pub(super) fn fail_media_task(
    conn: &mut Connection,
    gid: &str,
    error_code: &str,
    error_msg: &str,
) -> Result<PersistOutcome, StoreError> {
    // The error-terminal word binds as a parameter (the vocabulary's
    // emission face — no quoted state literal rides the SQL text).
    let error_state = TaskPhase::Error.as_v1_str();
    let n = conn.execute(
        "UPDATE media_task SET state = ?5, error_code = ?2, error_msg = ?3, updated_at = ?4 \
         WHERE gid = ?1",
        params![gid, error_code, error_msg, now_epoch_secs(), error_state],
    )?;
    Ok(if n > 0 {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

pub(super) fn upsert_media_task(
    conn: &mut Connection,
    row: &MediaTaskRow,
) -> Result<PersistOutcome, StoreError> {
    // Write-point validation: the payload `state` must parse in the
    // unified vocabulary and belong to the media family
    // ([`super::validate_task_state`]) — an unknown or cross-family
    // word is an explicit error, never a silent row.
    let phase = super::validate_task_state(&row.state, TaskFamily::Media, "media_task")?;
    let existing: Option<MediaTaskRow> = conn
        .query_row(
            &format!("SELECT {MEDIA_TASK_READ_COLS} FROM media_task WHERE gid = ?1"),
            params![row.gid],
            read_media_task_row,
        )
        .optional()?;
    let same = match existing.as_ref() {
        Some(cur) => {
            let mut next = row.clone();
            next.created_at = cur.created_at;
            next.updated_at = cur.updated_at;
            cur == &next
        }
        None => false,
    };
    if same {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    // Guarded-state guard (the http_task upsert's discipline): a
    // live-phase state never overwrites a guarded row (paused/
    // error/done — the vocabulary's guarded derivation,
    // [`TaskPhase::is_guarded`]; `paused` is not
    // terminal: restart recovery resumes it, hence it sits in the
    // active set too). Real race this closes (found in review): the
    // media pipeline's phase writes are partly detached tasks — a
    // stale `processing`/`verifying` write landing after the
    // teardown's `paused` (or after `done`) must not resurrect a
    // live phase. Leaving a guarded state goes through the explicit
    // faces (reopen_media_task for error/done; the paused→queued
    // unpause job) — never the plain upsert.
    //
    // The stored value comes from a single-row SELECT with no word-set
    // filter, so a hand-poisoned row is reachable here. Parse it:
    // Ok -> classify by variant; Err -> warn (gid + the raw value) and
    // keep the old contains=false reading — not guarded, the upsert
    // overwrites and repairs the poison. No silent else.
    if let Some(cur) = existing.as_ref() {
        let guarded = match TaskPhase::parse_v1(&cur.state) {
            Ok(p) => p.is_guarded(),
            Err(_) => {
                warn!(
                    gid = %row.gid,
                    raw_state = %cur.state,
                    "media_task stored state is outside the unified vocabulary; the guarded-state \
                     guard reads it as unguarded and lets the upsert overwrite (poisoned-row \
                     repair)"
                );
                false
            }
        };
        if guarded && !phase.is_guarded() {
            return Ok(PersistOutcome::SkippedUnchanged);
        }
    }
    let updated_at = now_epoch_secs();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO media_task (
            gid, kind, manifest_url, state, phase_detail_json, variant_json,
            selector_json, output_name, bridge_json,
            staging_dir, output_path, manifest_norm_digest, total_done, config_json,
            error_code, error_msg, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                  COALESCE((SELECT created_at FROM media_task WHERE gid = ?1), ?17), ?18)
        ON CONFLICT(gid) DO UPDATE SET
            kind = excluded.kind,
            manifest_url = excluded.manifest_url,
            state = excluded.state,
            phase_detail_json = excluded.phase_detail_json,
            variant_json = excluded.variant_json,
            selector_json = excluded.selector_json,
            output_name = excluded.output_name,
            bridge_json = excluded.bridge_json,
            staging_dir = excluded.staging_dir,
            output_path = excluded.output_path,
            manifest_norm_digest = excluded.manifest_norm_digest,
            total_done = excluded.total_done,
            config_json = excluded.config_json,
            error_code = excluded.error_code,
            error_msg = excluded.error_msg,
            updated_at = excluded.updated_at",
        params![
            row.gid,
            row.kind,
            row.manifest_url,
            row.state,
            row.phase_detail_json,
            row.variant_json,
            row.selector_json,
            row.output_name,
            row.bridge_json,
            row.staging_dir,
            row.output_path,
            row.manifest_norm_digest,
            row.total_done,
            row.config_json,
            row.error_code,
            row.error_msg,
            row.created_at,
            updated_at,
        ],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

fn read_media_track_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MediaTrackRow> {
    Ok(MediaTrackRow {
        gid: r.get(0)?,
        track_idx: r.get(1)?,
        kind: r.get(2)?,
        playlist_uri: r.get(3)?,
        local_name: r.get(4)?,
        init_files_json: r.get(5)?,
        seg_bitmap: r.get(6)?,
        seg_count: r.get(7)?,
    })
}

fn read_media_segment_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MediaSegmentRow> {
    Ok(MediaSegmentRow {
        gid: r.get(0)?,
        track_idx: r.get(1)?,
        seg_idx: r.get(2)?,
        media_sequence: r.get(3)?,
        uri: r.get(4)?,
        byte_range: r.get(5)?,
        key_id: r.get(6)?,
        seg_len: r.get(7)?,
        duration_ms: r.get(8)?,
        validator_digest: r.get(9)?,
        map_idx: r.get(10)?,
    })
}

/// Replace one track row + its whole segment set: a single
/// transaction (track upsert -> segment DELETE + batch INSERT, FK
/// parent first). Unchanged set -> skip. A dangling FK (no media_task
/// row for `gid`) = explicit error. Rows must share the payload `gid`
/// (writer-side defense).
pub(super) fn replace_media_track(
    conn: &mut Connection,
    track: &MediaTrackRow,
    segments: &[MediaSegmentRow],
) -> Result<PersistOutcome, StoreError> {
    if segments
        .iter()
        .any(|s| s.gid != track.gid || s.track_idx != track.track_idx)
    {
        return Err(StoreError::Internal(
            "media segment rows must share the track's (gid, track_idx)".to_string(),
        ));
    }
    let parent: Option<String> = conn
        .query_row(
            "SELECT gid FROM media_task WHERE gid = ?1",
            params![track.gid],
            |r| r.get(0),
        )
        .optional()?;
    if parent.is_none() {
        return Err(StoreError::Internal(format!(
            "media_track {}#{} has no media_task parent row",
            track.gid, track.track_idx
        )));
    }
    let existing_track: Option<MediaTrackRow> = conn
        .query_row(
            "SELECT gid, track_idx, kind, playlist_uri, local_name, init_files_json, \
             seg_bitmap, seg_count FROM media_track WHERE gid = ?1 AND track_idx = ?2",
            params![track.gid, track.track_idx],
            read_media_track_row,
        )
        .optional()?;
    let mut existing_segments: Vec<MediaSegmentRow> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT gid, track_idx, seg_idx, media_sequence, uri, byte_range, key_id, \
             seg_len, duration_ms, validator_digest, map_idx FROM media_segment \
             WHERE gid = ?1 AND track_idx = ?2 ORDER BY seg_idx",
        )?;
        let rows = stmt.query_map(params![track.gid, track.track_idx], read_media_segment_row)?;
        for row in rows {
            existing_segments.push(row?);
        }
    }
    let mut ordered = segments.to_vec();
    ordered.sort_by_key(|s| s.seg_idx);
    if existing_track.as_ref() == Some(track) && existing_segments == ordered {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO media_track (gid, track_idx, kind, playlist_uri, local_name, \
         init_files_json, seg_bitmap, seg_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(gid, track_idx) DO UPDATE SET
            kind = excluded.kind,
            playlist_uri = excluded.playlist_uri,
            local_name = excluded.local_name,
            init_files_json = excluded.init_files_json,
            seg_bitmap = excluded.seg_bitmap,
            seg_count = excluded.seg_count",
        params![
            track.gid,
            track.track_idx,
            track.kind,
            track.playlist_uri,
            track.local_name,
            track.init_files_json,
            track.seg_bitmap,
            track.seg_count,
        ],
    )?;
    tx.execute(
        "DELETE FROM media_segment WHERE gid = ?1 AND track_idx = ?2",
        params![track.gid, track.track_idx],
    )?;
    let mut stmt = tx.prepare(
        "INSERT INTO media_segment (gid, track_idx, seg_idx, media_sequence, uri, \
         byte_range, key_id, seg_len, duration_ms, validator_digest, map_idx) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for seg in &ordered {
        stmt.execute(params![
            seg.gid,
            seg.track_idx,
            seg.seg_idx,
            seg.media_sequence,
            seg.uri,
            seg.byte_range,
            seg.key_id,
            seg.seg_len,
            seg.duration_ms,
            seg.validator_digest,
            seg.map_idx,
        ])?;
    }
    drop(stmt);
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Recovery read face: all tracks of one task + their segment sets
/// (track_idx, then seg_idx order); no rows -> empty set.
pub(super) fn load_media_tracks(
    conn: &Connection,
    gid: &str,
) -> Result<Vec<(MediaTrackRow, Vec<MediaSegmentRow>)>, StoreError> {
    let mut tracks: Vec<MediaTrackRow> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT gid, track_idx, kind, playlist_uri, local_name, init_files_json, \
             seg_bitmap, seg_count FROM media_track WHERE gid = ?1 ORDER BY track_idx",
        )?;
        let rows = stmt.query_map(params![gid], read_media_track_row)?;
        for row in rows {
            tracks.push(row?);
        }
    }
    let mut out = Vec::with_capacity(tracks.len());
    for track in tracks {
        let mut segments: Vec<MediaSegmentRow> = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT gid, track_idx, seg_idx, media_sequence, uri, byte_range, key_id, \
                 seg_len, duration_ms, validator_digest, map_idx FROM media_segment \
                 WHERE gid = ?1 AND track_idx = ?2 ORDER BY seg_idx",
            )?;
            let rows = stmt.query_map(params![gid, track.track_idx], read_media_segment_row)?;
            for row in rows {
                segments.push(row?);
            }
        }
        out.push((track, segments));
    }
    Ok(out)
}

/// media_key write face: per-row upsert keyed by
/// `(gid, key_id)` with row-comparison skip, **no delete** — row ids
/// stay stable across upserts because `media_segment.key_id`
/// references them (a whole-set DELETE+INSERT would churn ids and
/// dangle the segment references). A dangling FK (no media_task row)
/// is an explicit error; key bodies must be exactly 16 bytes (the DDL
/// comment domain — a wrong-length payload is a writer-side bug,
/// refused loudly).
pub(super) fn upsert_media_keys(
    conn: &mut Connection,
    gid: &str,
    keys: &[MediaKeyRow],
) -> Result<PersistOutcome, StoreError> {
    if keys.iter().any(|k| k.gid != gid) {
        return Err(StoreError::Internal(
            "media key rows must share the payload gid".to_string(),
        ));
    }
    if keys.iter().any(|k| k.key.len() != 16) {
        return Err(StoreError::Internal(
            "media key bodies must be exactly 16 bytes".to_string(),
        ));
    }
    let parent: Option<String> = conn
        .query_row(
            "SELECT gid FROM media_task WHERE gid = ?1",
            params![gid],
            |r| r.get(0),
        )
        .optional()?;
    if parent.is_none() {
        return Err(StoreError::Internal(format!(
            "media_key rows for {gid} have no media_task parent row"
        )));
    }
    /// Existing-row shape for the row-comparison skip (id, uri, iv, key).
    type ExistingKeyRow = (i64, String, Option<Vec<u8>>, Vec<u8>);
    let mut any_written = false;
    for key in keys {
        let existing: Option<ExistingKeyRow> = conn
            .query_row(
                "SELECT id, uri, iv, key FROM media_key WHERE gid = ?1 AND key_id = ?2",
                params![gid, key.key_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let same = match existing.as_ref() {
            Some((_, uri, iv, k)) => uri == &key.uri && iv == &key.iv && k == &key.key,
            None => false,
        };
        if same {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO media_key (gid, key_id, uri, iv, key) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(gid, key_id) DO UPDATE SET
                uri = excluded.uri,
                iv = excluded.iv,
                key = excluded.key",
            params![gid, key.key_id, key.uri, key.iv, key.key],
        )?;
        tx.commit()?;
        any_written = true;
    }
    Ok(if any_written {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

/// media_key read face (ids included — the media-side restart face:
/// keys already in the DB are never re-fetched); key_id order for
/// determinism.
pub(super) fn load_media_keys(
    conn: &Connection,
    gid: &str,
) -> Result<Vec<MediaKeyRow>, StoreError> {
    let mut stmt = conn.prepare(
        "SELECT id, gid, key_id, uri, iv, key FROM media_key WHERE gid = ?1 ORDER BY key_id",
    )?;
    let rows = stmt.query_map(params![gid], |r| {
        Ok(MediaKeyRow {
            id: Some(r.get(0)?),
            gid: r.get(1)?,
            key_id: r.get(2)?,
            uri: r.get(3)?,
            iv: r.get(4)?,
            key: r.get(5)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Delete one media_task row (remove face): FK ON DELETE CASCADE
/// clears media_track/media_segment/media_key/media_format, and the
/// **paired delete** clears the gid's task_cookie rows inside the same
/// transaction (the unified cookie table carries no
/// FK, so the delete path pairs its own cookie clear; pinned by the
/// delete-face integration tests). Row existed = `Written`; no row =
/// `SkippedUnchanged`.
pub(super) fn delete_media_task(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let tx = conn.transaction()?;
    let n = tx.execute("DELETE FROM media_task WHERE gid = ?1", params![gid])?;
    if n > 0 {
        tx.execute("DELETE FROM task_cookie WHERE gid = ?1", params![gid])?;
    }
    tx.commit()?;
    Ok(if n > 0 {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

// ---- media_format + the orchestration read/reopen set ----

// The media_task state domains live in the unified vocabulary now (no
// per-file word tables): the startup recovery read face uses the
// family derivation [`TaskPhase::active_words`] (every non-terminal
// member of the declared media domain — terminal rows are not
// re-enqueued after restart), and the upsert guard's refuse set uses
// [`TaskPhase::is_guarded`] / [`TaskPhase::guarded_words`] (the two
// terminals plus `paused`; `paused` deliberately sits in BOTH sets —
// active because restart recovery resumes it, guarded because the
// teardown's `paused` row must survive a late detached phase write).
// Both are pinned word for word against frozen tables in
// task_phase.rs's tests and schema.rs's comment-consistency pin.

/// Upsert one media_format row (row-comparison skip; created_at keeps
/// its initial value). A dangling FK (no media_task row) = an
/// explicit error — a format snapshot never exists without its task.
pub(super) fn upsert_media_format(
    conn: &mut Connection,
    row: &MediaFormatRow,
) -> Result<PersistOutcome, StoreError> {
    let parent: Option<String> = conn
        .query_row(
            "SELECT gid FROM media_task WHERE gid = ?1",
            params![row.gid],
            |r| r.get(0),
        )
        .optional()?;
    if parent.is_none() {
        return Err(StoreError::Internal(format!(
            "media_format row for {} has no media_task parent row",
            row.gid
        )));
    }
    let existing: Option<String> = conn
        .query_row(
            "SELECT formats_json FROM media_format WHERE gid = ?1",
            params![row.gid],
            |r| r.get(0),
        )
        .optional()?;
    if existing.as_deref() == Some(row.formats_json.as_str()) {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let updated_at = now_epoch_secs();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO media_format (gid, formats_json, created_at, updated_at)
         VALUES (?1, ?2,
                 COALESCE((SELECT created_at FROM media_format WHERE gid = ?1), ?3), ?4)
         ON CONFLICT(gid) DO UPDATE SET
            formats_json = excluded.formats_json,
            updated_at = excluded.updated_at",
        params![row.gid, row.formats_json, row.created_at, updated_at],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// media_format read face (the `getMediaFormats` source); no row =
/// `Ok(None)`.
pub(super) fn load_media_format(
    conn: &Connection,
    gid: &str,
) -> Result<Option<MediaFormatRow>, StoreError> {
    conn.query_row(
        "SELECT gid, formats_json, created_at, updated_at FROM media_format WHERE gid = ?1",
        params![gid],
        |r| {
            Ok(MediaFormatRow {
                gid: r.get(0)?,
                formats_json: r.get(1)?,
                created_at: r.get(2)?,
                updated_at: r.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

/// Startup recovery read face: all media_task rows in the active set
/// (the media-family derivation [`TaskPhase::active_words`]; the words
/// bind as parameters — no quoted state literal rides the SQL text),
/// created_at order (the restore order anchor — media rows carry no
/// queue_pos; the arrival order is the stable key).
pub(super) fn load_media_tasks_at_startup(
    conn: &Connection,
) -> Result<Vec<MediaTaskRow>, StoreError> {
    let active_states = TaskPhase::active_words(TaskFamily::Media);
    let placeholders = active_states
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let mut stmt = conn.prepare(&format!(
        "SELECT {MEDIA_TASK_READ_COLS} FROM media_task WHERE state IN ({placeholders}) \
         ORDER BY created_at, gid"
    ))?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(active_states.iter()),
        read_media_task_row,
    )?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Single-row read (any state; the Error→unpause re-resolve arm's
/// row-fact source); no row = `Ok(None)`.
pub(super) fn load_media_task(
    conn: &Connection,
    gid: &str,
) -> Result<Option<MediaTaskRow>, StoreError> {
    conn.query_row(
        &format!("SELECT {MEDIA_TASK_READ_COLS} FROM media_task WHERE gid = ?1"),
        params![gid],
        read_media_task_row,
    )
    .optional()
    .map_err(Into::into)
}

/// Staging-GC liveness read face: **every** media_task row,
/// any state — `(gid, staging_dir)` pairs (the GC consumes the gids as
/// its liveness set and the staging parents as its scan roots; a true
/// orphan = a gid directory with no row at all). Kept separate from
/// [`load_media_tasks_at_startup`] (the active-set recovery face):
/// terminal rows are not re-enqueued, but their staged trees stay
/// (an errored task's staging is kept for the
/// Error→unpause re-run; `done` residue is the success-cleanup face's
/// business, not the GC's).
pub(super) fn load_media_task_gc_refs(
    conn: &Connection,
) -> Result<Vec<(String, String)>, StoreError> {
    let mut stmt = conn.prepare("SELECT gid, staging_dir FROM media_task ORDER BY gid")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// The paused→queued unpause transition (the reserved unpause face's
/// single exit from `paused`): state back to `queued`, the phase
/// memory cleared, progress retained. Hit = `Written`; missing row /
/// not-paused = `SkippedUnchanged` (idempotent). Routed through this
/// explicit job because the upsert's guarded-state guard refuses
/// live-phase overwrites of `paused`. The SET/WHERE words bind as
/// parameters (the vocabulary's emission face).
pub(super) fn unpause_media_task(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let queued_state = TaskPhase::Queued.as_v1_str();
    let paused_state = TaskPhase::Paused.as_v1_str();
    let n = conn.execute(
        "UPDATE media_task SET state = ?3, phase_detail_json = NULL, updated_at = ?2 \
         WHERE gid = ?1 AND state = ?4",
        params![gid, now_epoch_secs(), queued_state, paused_state],
    )?;
    Ok(if n > 0 {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

/// Explicit reopen of a terminal media row (the Error→unpause
/// re-resolve arm's single terminal exit): state back to `resolving`
/// (the re-probe semantics — the media counterpart goes
/// straight to Resolving), error fields + phase memory cleared,
/// progress retained. Hit = `Written`; missing row / non-terminal
/// state = `SkippedUnchanged` (idempotent). The SET word and the WHERE
/// terminal set both bind as parameters (words from the vocabulary's
/// emission/derivation faces).
pub(super) fn reopen_media_task(
    conn: &mut Connection,
    gid: &str,
) -> Result<PersistOutcome, StoreError> {
    let reopen_state = TaskPhase::Resolving.as_v1_str();
    let terminal_states = TaskPhase::terminal_words();
    let placeholders = terminal_states
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    // Bind order: ?1 gid, ?2 the reopen word, ?3 updated_at, ?4.. the
    // terminal words (mixed str/i64 binds — the same slice shape
    // `params!` builds).
    let updated_at = now_epoch_secs();
    let mut binds: Vec<&dyn rusqlite::ToSql> = vec![&gid, &reopen_state, &updated_at];
    for word in &terminal_states {
        binds.push(word);
    }
    let n = conn.execute(
        &format!(
            "UPDATE media_task SET state = ?2, error_code = NULL, error_msg = NULL, \
             phase_detail_json = NULL, updated_at = ?3 \
             WHERE gid = ?1 AND state IN ({placeholders})"
        ),
        binds.as_slice(),
    )?;
    Ok(if n > 0 {
        PersistOutcome::Written
    } else {
        PersistOutcome::SkippedUnchanged
    })
}

// ---- media_archive write/read/clear faces ----

/// Read one media_archive row.
fn read_media_archive_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MediaArchiveRow> {
    Ok(MediaArchiveRow {
        url_digest: r.get("url_digest")?,
        manifest_digest: r.get("manifest_digest")?,
        kind: r.get("kind")?,
        title: r.get("title")?,
        output_name: r.get("output_name")?,
        gid: r.get("gid")?,
        created_at: r.get("created_at")?,
        updated_at: r.get("updated_at")?,
    })
}

/// Upsert one media_archive row (the Done close-out): keyed by
/// url_digest; an unchanged fingerprint pair + payload (the
/// observational columns excepted) skips. The manifest digest is a
/// **non-unique** lookup compartment — the same content re-archived
/// under a second URL keeps its own row (the checkpoint 2 hit face
/// is a lookup, not a uniqueness bar; the concurrent-same-content
/// race therefore needs no conflict handling here).
pub(super) fn upsert_media_archive(
    conn: &mut Connection,
    row: &MediaArchiveRow,
) -> Result<PersistOutcome, StoreError> {
    let existing: Option<MediaArchiveRow> = conn
        .query_row(
            "SELECT url_digest, manifest_digest, kind, title, output_name, gid, \
             created_at, updated_at FROM media_archive WHERE url_digest = ?1",
            params![row.url_digest],
            read_media_archive_row,
        )
        .optional()?;
    if let Some(prev) = &existing
        && prev.manifest_digest == row.manifest_digest
        && prev.kind == row.kind
        && prev.title == row.title
        && prev.output_name == row.output_name
    {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let updated_at = now_epoch_secs();
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO media_archive
             (url_digest, manifest_digest, kind, title, output_name, gid, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(url_digest) DO UPDATE SET
            manifest_digest = excluded.manifest_digest,
            kind = excluded.kind,
            title = excluded.title,
            output_name = excluded.output_name,
            gid = excluded.gid,
            updated_at = excluded.updated_at",
        params![
            row.url_digest,
            row.manifest_digest,
            row.kind,
            row.title,
            row.output_name,
            row.gid,
            row.created_at,
            updated_at
        ],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// First checkpoint lookup (url_digest = the PK).
pub(super) fn load_media_archive_by_url(
    conn: &Connection,
    url_digest: &str,
) -> Result<Option<MediaArchiveRow>, StoreError> {
    conn.query_row(
        "SELECT url_digest, manifest_digest, kind, title, output_name, gid, \
         created_at, updated_at FROM media_archive WHERE url_digest = ?1",
        params![url_digest],
        read_media_archive_row,
    )
    .optional()
    .map_err(StoreError::from)
}

/// Second checkpoint lookup (manifest_digest = the index face; the
/// earliest row wins — deterministic under the single writer).
pub(super) fn load_media_archive_by_manifest(
    conn: &Connection,
    manifest_digest: &str,
) -> Result<Option<MediaArchiveRow>, StoreError> {
    conn.query_row(
        "SELECT url_digest, manifest_digest, kind, title, output_name, gid, \
         created_at, updated_at FROM media_archive
         WHERE manifest_digest = ?1 ORDER BY created_at, url_digest LIMIT 1",
        params![manifest_digest],
        read_media_archive_row,
    )
    .optional()
    .map_err(StoreError::from)
}

/// The destructive whole-table clear; replies with the removed row
/// count (0 = already empty, idempotent).
pub(super) fn clear_media_archive(conn: &mut Connection) -> Result<u64, StoreError> {
    let tx = conn.transaction()?;
    let n = tx.execute("DELETE FROM media_archive", [])? as u64;
    tx.commit()?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::open_and_migrate;

    fn conn() -> Connection {
        // Counter-suffixed naming (the workspace test-harness shape, e.g.
        // taiji-media's staging tests): `pid + subsec_nanos` collides when
        // parallel test threads start within the same nanosecond — two
        // connections then open one sqlite file and panic on
        // `database is locked` (observed ~1/3 of runs before the counter).
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("taiji-store-media-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        open_and_migrate(&dir.join("t.sqlite3")).unwrap_or_else(|e| panic!("open: {e}"))
    }

    fn task_row(gid: &str) -> MediaTaskRow {
        MediaTaskRow {
            gid: gid.to_string(),
            kind: "hls".into(),
            manifest_url: "http://x/m.m3u8".into(),
            state: "downloading".into(),
            phase_detail_json: None,
            variant_json: None,
            selector_json: Some("best".into()),
            output_name: Some("clip.mp4".into()),
            bridge_json: None,
            staging_dir: "/tmp/s".into(),
            output_path: "/tmp/o".into(),
            manifest_norm_digest: vec![1, 2, 3],
            total_done: 0,
            config_json: "{}".into(),
            error_code: None,
            error_msg: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn seg(gid: &str, idx: i64, len: i64) -> MediaSegmentRow {
        MediaSegmentRow {
            gid: gid.to_string(),
            track_idx: 0,
            seg_idx: idx,
            media_sequence: Some(100 + idx),
            uri: format!("http://x/s{idx}.ts"),
            byte_range: Some(format!("{len}@{}", idx * 10)),
            key_id: None,
            seg_len: len,
            duration_ms: Some(4000),
            validator_digest: Some(vec![idx as u8; 32]),
            map_idx: if idx % 2 == 0 { Some(0) } else { Some(1) },
        }
    }

    /// Parent upsert + track replace + recovery read round-trip; the
    /// validator digest column persists byte-for-byte.
    #[test]
    fn media_task_track_segment_roundtrip() {
        let mut c = conn();
        let gid = "8000000000000091";
        assert_eq!(
            upsert_media_task(&mut c, &task_row(gid)).ok(),
            Some(PersistOutcome::Written)
        );
        // Row-compare skip on the identical payload.
        assert_eq!(
            upsert_media_task(&mut c, &task_row(gid)).ok(),
            Some(PersistOutcome::SkippedUnchanged)
        );
        let track = MediaTrackRow {
            gid: gid.to_string(),
            track_idx: 0,
            kind: "video".into(),
            playlist_uri: "http://x/v.m3u8".into(),
            local_name: "archive-v.m4s".into(),
            init_files_json: Some(r#"["init-v-0.mp4"]"#.into()),
            seg_bitmap: Some(vec![0b0000_0111]),
            seg_count: Some(3),
        };
        let segments = vec![seg(gid, 0, 10), seg(gid, 1, 20), seg(gid, 2, 30)];
        assert_eq!(
            replace_media_track(&mut c, &track, &segments).ok(),
            Some(PersistOutcome::Written)
        );
        // Unchanged set -> skip.
        assert_eq!(
            replace_media_track(&mut c, &track, &segments).ok(),
            Some(PersistOutcome::SkippedUnchanged)
        );
        let loaded = load_media_tracks(&c, gid).ok().unwrap_or_default();
        assert_eq!(loaded.len(), 1);
        let (t, s) = &loaded[0];
        assert_eq!(t, &track);
        assert_eq!(s, &segments);
        assert_eq!(s[0].validator_digest, Some(vec![0u8; 32]));
        assert_eq!(s[1].media_sequence, Some(101));

        // Bitmap advance replaces the set (not appends).
        let track2 = MediaTrackRow {
            seg_bitmap: Some(vec![0b0000_1111]),
            seg_count: Some(3),
            ..track.clone()
        };
        assert_eq!(
            replace_media_track(&mut c, &track2, &segments).ok(),
            Some(PersistOutcome::Written)
        );
        let loaded = load_media_tracks(&c, gid).ok().unwrap_or_default();
        assert_eq!(loaded[0].0.seg_bitmap, Some(vec![0b0000_1111]));
        assert_eq!(loaded[0].1.len(), 3, "segment set replaced, not doubled");
    }

    /// Dangling FK: a track row without its parent task row is an
    /// explicit error, never a silent write.
    #[test]
    fn track_without_parent_is_refused() {
        let mut c = conn();
        let track = MediaTrackRow {
            gid: "8000000000000092".into(),
            track_idx: 0,
            kind: "audio".into(),
            playlist_uri: "u".into(),
            local_name: "archive-a.m4s".into(),
            init_files_json: None,
            seg_bitmap: None,
            seg_count: None,
        };
        assert!(replace_media_track(&mut c, &track, &[]).is_err());
    }

    /// The error-terminal partial-column update keeps the
    /// row's facts. A DASH row with variant/selector/output_name/
    /// digest/progress fails: state+error fields flip, everything
    /// else is byte-identical (the pre-fix whole-row fail write
    /// stamped `kind = hls` and blanked the snapshots). A gid with no
    /// row = `SkippedUnchanged` (the caller's fresh-row fallback).
    #[test]
    fn fail_media_task_preserves_row_facts() {
        let mut c = conn();
        let gid = "80000000000000a5";
        let mut dash = task_row(gid);
        dash.kind = "dash".into();
        dash.manifest_url = "http://x/m.mpd".into();
        dash.state = "downloading".into();
        dash.variant_json = Some(r#"{"format_id":"v1"}"#.into());
        dash.output_name = Some("movie.mp4".into());
        dash.manifest_norm_digest = vec![9; 32];
        dash.total_done = 4096;
        assert!(upsert_media_task(&mut c, &dash).is_ok());
        assert_eq!(
            fail_media_task(&mut c, gid, "taiji.media.staging", "boom").ok(),
            Some(PersistOutcome::Written)
        );
        let row = load_media_task(&c, gid)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("row"));
        assert_eq!(row.state, "error");
        assert_eq!(row.error_code.as_deref(), Some("taiji.media.staging"));
        assert_eq!(row.error_msg.as_deref(), Some("boom"));
        // The facts survive.
        assert_eq!(row.kind, "dash", "a failed DASH row stays dash");
        assert_eq!(row.manifest_url, "http://x/m.mpd");
        assert_eq!(row.variant_json.as_deref(), Some(r#"{"format_id":"v1"}"#));
        assert_eq!(row.selector_json.as_deref(), Some("best"));
        assert_eq!(row.output_name.as_deref(), Some("movie.mp4"));
        assert_eq!(row.manifest_norm_digest, vec![9; 32]);
        assert_eq!(row.total_done, 4096, "progress retained");
        // No row for the gid → SkippedUnchanged (the fallback face).
        assert_eq!(
            fail_media_task(&mut c, "80000000000000a6", "x", "y").ok(),
            Some(PersistOutcome::SkippedUnchanged)
        );
    }

    /// Payload gid mixing is refused (writer-side defense).
    #[test]
    fn mixed_payload_gid_refused() {
        let mut c = conn();
        let gid = "8000000000000093";
        assert!(upsert_media_task(&mut c, &task_row(gid)).is_ok());
        let track = MediaTrackRow {
            gid: gid.to_string(),
            track_idx: 0,
            kind: "video".into(),
            playlist_uri: "u".into(),
            local_name: "n".into(),
            init_files_json: None,
            seg_bitmap: None,
            seg_count: None,
        };
        assert!(replace_media_track(&mut c, &track, &[seg("8000000000000094", 0, 1)]).is_err());
    }

    /// Delete cascades the children.
    #[test]
    fn delete_cascades() {
        let mut c = conn();
        let gid = "8000000000000095";
        assert!(upsert_media_task(&mut c, &task_row(gid)).is_ok());
        let track = MediaTrackRow {
            gid: gid.to_string(),
            track_idx: 0,
            kind: "video".into(),
            playlist_uri: "u".into(),
            local_name: "n".into(),
            init_files_json: None,
            seg_bitmap: None,
            seg_count: None,
        };
        assert!(replace_media_track(&mut c, &track, &[seg(gid, 0, 5)]).is_ok());
        assert_eq!(
            delete_media_task(&mut c, gid).ok(),
            Some(PersistOutcome::Written)
        );
        assert_eq!(
            delete_media_task(&mut c, gid).ok(),
            Some(PersistOutcome::SkippedUnchanged)
        );
        assert!(
            load_media_tracks(&c, gid)
                .ok()
                .unwrap_or_default()
                .is_empty()
        );
    }

    /// The staging-GC liveness read face covers **every**
    /// state (terminal rows included — an errored task's staging must
    /// never read as a GC orphan), and pairs each gid
    /// with its staging_dir (the GC's root-set source).
    #[test]
    fn gc_refs_cover_every_state() {
        let mut c = conn();
        let active = task_row("8000000000000096");
        let mut errored = task_row("8000000000000097");
        let mut done = task_row("8000000000000098");
        for row in [&active, &errored, &done] {
            assert!(upsert_media_task(&mut c, row).is_ok());
        }
        // Walk two of them to their terminals (the error path's own
        // write shape: terminal over the live-phase row).
        errored.state = "error".into();
        errored.staging_dir = "/tmp/s-err".into();
        done.state = "done".into();
        done.staging_dir = "/tmp/s-done".into();
        for row in [&errored, &done] {
            assert!(upsert_media_task(&mut c, row).is_ok());
        }
        let refs = load_media_task_gc_refs(&c).ok().unwrap_or_default();
        let mut got: std::collections::BTreeMap<String, String> = refs.into_iter().collect();
        assert_eq!(got.remove("8000000000000096").as_deref(), Some("/tmp/s"));
        assert_eq!(
            got.remove("8000000000000097").as_deref(),
            Some("/tmp/s-err")
        );
        assert_eq!(
            got.remove("8000000000000098").as_deref(),
            Some("/tmp/s-done")
        );
        assert!(got.is_empty(), "no extra gc refs");
    }

    fn key_row(gid: &str, key_id: &str, iv: Option<Vec<u8>>) -> MediaKeyRow {
        MediaKeyRow {
            id: None,
            gid: gid.to_string(),
            key_id: key_id.to_string(),
            uri: format!("https://x/{key_id}"),
            iv,
            key: vec![0xEE; 16],
        }
    }

    /// Key rows: upsert + skip + stable ids across re-upserts (the
    /// media_segment.key_id reference face) + read-back + FK + length
    /// defenses.
    #[test]
    fn media_key_upsert_load_and_stable_ids() {
        let mut c = conn();
        let gid = "8000000000000096";
        assert!(upsert_media_task(&mut c, &task_row(gid)).is_ok());
        // Same identity, same payload twice -> second is a skip.
        let rows = vec![
            key_row(gid, "k0", None),
            key_row(gid, "k1", Some(vec![1; 16])),
        ];
        assert_eq!(
            upsert_media_keys(&mut c, gid, &rows).ok(),
            Some(PersistOutcome::Written)
        );
        assert_eq!(
            upsert_media_keys(&mut c, gid, &rows).ok(),
            Some(PersistOutcome::SkippedUnchanged)
        );
        let loaded = load_media_keys(&c, gid).ok().unwrap_or_default();
        assert_eq!(loaded.len(), 2);
        let (ids, key_ids): (Vec<i64>, Vec<String>) = loaded
            .iter()
            .map(|r| (r.id.unwrap_or(0), r.key_id.clone()))
            .unzip();
        assert!(ids.iter().all(|i| *i > 0), "ids assigned: {ids:?}");
        assert_eq!(key_ids, vec!["k0".to_string(), "k1".to_string()]);
        assert_eq!(loaded[1].iv, Some(vec![1; 16]));

        // Material rotation at the same identity: re-upsert updates the
        // row and **keeps the id** (segments reference it).
        let mut rotated = rows.clone();
        rotated[0].key = vec![0xDD; 16];
        assert_eq!(
            upsert_media_keys(&mut c, gid, &rotated).ok(),
            Some(PersistOutcome::Written)
        );
        let reloaded = load_media_keys(&c, gid).ok().unwrap_or_default();
        let k0 = reloaded.iter().find(|r| r.key_id == "k0").cloned();
        assert_eq!(k0.clone().map(|r| r.id), loaded.first().map(|r| r.id));
        assert_eq!(k0.map(|r| r.key), Some(vec![0xDD; 16]));

        // Dangling FK refused; payload-gid mixing refused; wrong key
        // length refused.
        assert!(
            upsert_media_keys(
                &mut c,
                "8000000000000097",
                &[key_row("8000000000000097", "k", None)]
            )
            .is_err()
        );
        let mut mixed = key_row(gid, "k9", None);
        mixed.gid = "8000000000000098".to_string();
        assert!(upsert_media_keys(&mut c, gid, &[mixed]).is_err());
        let mut short = key_row(gid, "k8", None);
        short.key = vec![1; 15];
        assert!(upsert_media_keys(&mut c, gid, &[short]).is_err());
    }

    /// The media_format faces: media_format round-trip + FK refusal, the
    /// startup active-set read (terminal rows excluded, paused kept),
    /// the single-row read, and the Error→resolving reopen.
    #[test]
    fn media_format_and_orchestration_faces() {
        let mut c = conn();
        let gid = "8000000000000099";
        let done_gid = "800000000000009a";
        assert!(upsert_media_task(&mut c, &task_row(gid)).is_ok());
        // media_format: dangling FK refused, then round-trip + skip.
        let fmt = MediaFormatRow {
            gid: gid.to_string(),
            formats_json: r#"{"url":"http://x/m.m3u8","kind":"hls","formats":[]}"#.into(),
            created_at: 0,
            updated_at: 0,
        };
        let orphan = MediaFormatRow {
            gid: "800000000000009b".into(),
            ..fmt.clone()
        };
        assert!(upsert_media_format(&mut c, &orphan).is_err());
        assert_eq!(
            upsert_media_format(&mut c, &fmt).ok(),
            Some(PersistOutcome::Written)
        );
        assert_eq!(
            upsert_media_format(&mut c, &fmt).ok(),
            Some(PersistOutcome::SkippedUnchanged)
        );
        let back = load_media_format(&c, gid).ok().flatten();
        assert_eq!(
            back.as_ref().map(|r| r.formats_json.clone()),
            Some(fmt.formats_json.clone())
        );
        assert!(load_media_format(&c, done_gid).ok().flatten().is_none());

        // Startup active-set read: active rows in, terminal rows out.
        let mut terminal = task_row(done_gid);
        terminal.state = "error".into();
        terminal.error_code = Some("taiji.media.not_media".into());
        assert!(upsert_media_task(&mut c, &terminal).is_ok());
        let startup = load_media_tasks_at_startup(&c).ok().unwrap_or_default();
        assert_eq!(startup.len(), 1);
        assert_eq!(startup[0].gid, gid);
        assert_eq!(startup[0].selector_json.as_deref(), Some("best"));
        assert_eq!(startup[0].output_name.as_deref(), Some("clip.mp4"));
        // Single-row read (any state).
        assert_eq!(
            load_media_task(&c, done_gid)
                .ok()
                .flatten()
                .map(|r| r.state),
            Some("error".into())
        );
        // Reopen: error → resolving, error fields cleared; a
        // non-terminal row is a no-op.
        assert_eq!(
            reopen_media_task(&mut c, done_gid).ok(),
            Some(PersistOutcome::Written)
        );
        let reopened = load_media_task(&c, done_gid)
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("the reopened row exists"));
        assert_eq!(reopened.state, "resolving");
        assert_eq!(reopened.error_code, None);
        assert_eq!(
            reopen_media_task(&mut c, gid).ok(),
            Some(PersistOutcome::SkippedUnchanged),
            "non-terminal rows are not reopened"
        );
        // Guarded-state guard: a stale live-phase write never
        // resurrects a guarded row; the explicit unpause job is the
        // single paused→queued exit.
        {
            let mut c = conn();
            let gid = "80000000000000a1";
            let mut paused = task_row(gid);
            paused.state = "paused".into();
            paused.phase_detail_json = Some("processing".into());
            assert!(upsert_media_task(&mut c, &paused).is_ok());
            // A stale `processing` write over `paused` is refused.
            let mut stale = task_row(gid);
            stale.state = "processing".into();
            assert_eq!(
                upsert_media_task(&mut c, &stale).ok(),
                Some(PersistOutcome::SkippedUnchanged)
            );
            assert_eq!(
                load_media_task(&c, gid).ok().flatten().map(|r| r.state),
                Some("paused".into()),
                "the guarded row survives the stale write"
            );
            // ...and over `done` likewise.
            let mut done = task_row(gid);
            done.state = "done".into();
            done.phase_detail_json = None;
            assert!(upsert_media_task(&mut c, &done).is_ok());
            let mut stale2 = task_row(gid);
            stale2.state = "verifying".into();
            assert_eq!(
                upsert_media_task(&mut c, &stale2).ok(),
                Some(PersistOutcome::SkippedUnchanged)
            );
            // The unpause job is the single paused→queued exit (and
            // clears the phase memory).
            let mut c2 = conn();
            let gid2 = "80000000000000a2";
            let mut p2 = task_row(gid2);
            p2.state = "paused".into();
            p2.phase_detail_json = Some("processing".into());
            assert!(upsert_media_task(&mut c2, &p2).is_ok());
            assert_eq!(
                unpause_media_task(&mut c2, gid2).ok(),
                Some(PersistOutcome::Written)
            );
            let row = load_media_task(&c2, gid2)
                .ok()
                .flatten()
                .unwrap_or_else(|| panic!("row"));
            assert_eq!(row.state, "queued");
            assert_eq!(row.phase_detail_json, None);
            // Idempotent on a non-paused row.
            assert_eq!(
                unpause_media_task(&mut c2, gid2).ok(),
                Some(PersistOutcome::SkippedUnchanged)
            );
        }

        // Delete cascades media_format too.
        assert_eq!(
            delete_media_task(&mut c, gid).ok(),
            Some(PersistOutcome::Written)
        );
        assert!(load_media_format(&c, gid).ok().flatten().is_none());
    }

    /// Write-point state validation (the upsert entry's parse_v1 +
    /// family filter): an unknown word (case drift, a projection word)
    /// and a cross-family word (torrent-only or http-only phases
    /// presented as a media row) are explicit errors that never touch
    /// the row; the error carries the offending value verbatim. The
    /// media family's own ten words — fold words are torrent-only and
    /// therefore refused here — all keep landing.
    #[test]
    fn media_task_upsert_refuses_unknown_and_cross_family_states() {
        let mut c = conn();
        let gid = "80000000000000a7";
        assert!(upsert_media_task(&mut c, &task_row(gid)).is_ok());
        for bad in [
            "Paused", "active", "metadata", "checking", "seeding", "probing",
        ] {
            let mut row = task_row(gid);
            row.state = bad.into();
            let err = match upsert_media_task(&mut c, &row) {
                Ok(_) => panic!("must refuse state {bad:?}"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains(bad),
                "the error must carry the offending value {bad:?}: {err}"
            );
        }
        // The stored row survived every refusal unchanged; the family's
        // own full domain (active words + both terminals) keeps landing.
        let loaded = load_media_task(&c, gid).ok().flatten();
        assert_eq!(
            loaded.map(|r| r.state),
            Some("downloading".into()),
            "the row is untouched by the refused payloads"
        );
        for good in [
            "queued",
            "resolving",
            "recording",
            "processing",
            "verifying",
            "finalizing",
            "paused",
            "error",
            "done",
        ] {
            let mut row = task_row(gid);
            row.state = good.into();
            assert!(
                upsert_media_task(&mut c, &row).is_ok(),
                "{good} is inside the media family's declared domain"
            );
        }
    }

    /// The guarded-state guard's poisoned-row policy under the v4 CHECK
    /// (two defense layers, pinned together): the stored value comes
    /// from a single-row SELECT with no word-set filter, so the guard
    /// must tolerate a poisoned row — an unparseable stored state reads
    /// as unguarded, the exact semantics the old word-set contains-check
    /// had (contains == false), so a live-phase upsert overwrites it
    /// (the poison is repaired, warn emitted) instead of wedging the
    /// row behind a guard. Since ledger v4 the plain SQL poison is
    /// itself refused by the database-side CHECK (the outer layer —
    /// asserted first); the guard's tolerance branch is then exercised
    /// through sqlite's `PRAGMA ignore_check_constraints` (the
    /// documented test bypass of the outer layer), standing in for the
    /// non-SQL corruption faces the CHECK cannot see. Production code
    /// never sets that pragma.
    #[test]
    fn media_task_guard_reads_poisoned_state_as_unguarded() {
        let mut c = conn();
        let gid = "80000000000000a8";
        let mut paused = task_row(gid);
        paused.state = "paused".into();
        paused.phase_detail_json = Some("processing".into());
        assert!(upsert_media_task(&mut c, &paused).is_ok());
        // Layer 1 (the v4 CHECK): the direct-SQL poison is refused by
        // the database itself — the out-of-domain word never lands.
        assert!(
            c.execute(
                "UPDATE media_task SET state = 'Paused' WHERE gid = ?1",
                [gid],
            )
            .is_err(),
            "the v4 state CHECK must refuse the out-of-domain poison word"
        );
        // Layer 2 (the guard's tolerance): bypass the CHECK with
        // sqlite's test pragma, poison the row, re-enable enforcement,
        // then verify the guard repairs rather than wedges.
        c.pragma_update(None, "ignore_check_constraints", "ON")
            .unwrap_or_else(|e| panic!("disable checks (test bypass): {e}"));
        c.execute(
            "UPDATE media_task SET state = 'Paused' WHERE gid = ?1",
            [gid],
        )
        .unwrap_or_else(|e| panic!("poison: {e}"));
        c.pragma_update(None, "ignore_check_constraints", "OFF")
            .unwrap_or_else(|e| panic!("re-enable checks: {e}"));
        // A live-phase payload over the poisoned row: the guard reads
        // the stored value as unguarded (warn + contains=false
        // semantics) and the upsert lands, repairing the row.
        let mut live = task_row(gid);
        live.state = "downloading".into();
        assert_eq!(
            upsert_media_task(&mut c, &live).ok(),
            Some(PersistOutcome::Written),
            "the poisoned row is overwritten (repaired), not wedged"
        );
        assert_eq!(
            load_media_task(&c, gid).ok().flatten().map(|r| r.state),
            Some("downloading".into())
        );
    }
}

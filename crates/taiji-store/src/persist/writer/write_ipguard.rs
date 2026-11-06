//! Engine-level defense-line row write face (SPEC §5.3): peer_ban (ip
//! primary key; re-banning the same IP overwrites with the newest
//! reason/until, aria2 badPeers overwrite semantics) + ipfilter
//! (whole-table replacement within a kind) — row-comparison skip-write; no
//! FK, independent of the torrent lifecycle.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StoreError;

use super::job::PersistOutcome;
use super::rows::{IpfilterRow, PeerBanRow};

/// peer_ban row comparison tuple (reason, until).
type PeerBanRowCmp = (String, i64);

/// Upsert a peer_ban row: full-field equality with the existing row ->
/// skip; otherwise a transactional write (primary key ip; re-banning the
/// same IP overwrites with the newest reason/until, aria2 badPeers_[ip]
/// overwrite semantics, `DefaultPeerStorage.cc`).
pub(super) fn upsert_peer_ban(
    conn: &mut Connection,
    row: &PeerBanRow,
) -> Result<PersistOutcome, StoreError> {
    let existing: Option<PeerBanRowCmp> = conn
        .query_row(
            "SELECT reason, until FROM peer_ban WHERE ip = ?1",
            params![row.ip],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if existing
        .as_ref()
        .is_some_and(|e| *e == (row.reason.clone(), row.until))
    {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO peer_ban (ip, reason, until) VALUES (?1, ?2, ?3)
         ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, until = excluded.until",
        params![row.ip, row.reason, row.until],
    )?;
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Delete a single peer_ban row (the `taiji.unbanAddr` release face):
/// exact delete by ip primary key (the target text is verbatim what was
/// stored — guaranteed by ban-side normalization). No row ->
/// `SkippedUnchanged` (idempotent).
pub(super) fn delete_peer_ban(
    conn: &mut Connection,
    ip: &str,
) -> Result<PersistOutcome, StoreError> {
    let tx = conn.transaction()?;
    let deleted = tx.execute("DELETE FROM peer_ban WHERE ip = ?1", params![ip])?;
    tx.commit()?;
    if deleted == 0 {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    Ok(PersistOutcome::Written)
}

/// Whole-table replacement of the ipfilter rows of one kind: transactional
/// DELETE of the old rows + batch INSERT; exact equality with the existing
/// row set (in id order = insertion order) -> skip (re-importing identical
/// content costs zero disk writes, the same yardstick as digest/row-level
/// dedup).
pub(super) fn replace_ipfilter(
    conn: &mut Connection,
    kind: &str,
    rows: &[IpfilterRow],
) -> Result<PersistOutcome, StoreError> {
    let existing: Vec<IpfilterRow> = load_ipfilter_by_kind(conn, kind)?;
    let same = existing.len() == rows.len()
        && existing
            .iter()
            .zip(rows)
            .all(|(a, b)| a.kind == b.kind && a.rule == b.rule && a.enabled == b.enabled);
    if same {
        return Ok(PersistOutcome::SkippedUnchanged);
    }
    let enabled_of = |b: bool| i64::from(b);
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM ipfilter WHERE kind = ?1", params![kind])?;
    for r in rows {
        tx.execute(
            "INSERT INTO ipfilter (kind, rule, enabled) VALUES (?1, ?2, ?3)",
            params![r.kind, r.rule, enabled_of(r.enabled)],
        )?;
    }
    tx.commit()?;
    Ok(PersistOutcome::Written)
}

/// Read back the effective peer_ban rows (`until > now`; expired rows are
/// left for the startup-recovery side to ignore, the write side does not
/// proactively clean — the table is written very rarely and the active set
/// is filtered by the query).
pub(super) fn load_active_peer_bans(
    conn: &Connection,
    now: i64,
) -> Result<Vec<PeerBanRow>, StoreError> {
    let mut stmt = conn.prepare("SELECT ip, reason, until FROM peer_ban WHERE until > ?1")?;
    let rows = stmt.query_map(params![now], |r| {
        Ok(PeerBanRow {
            ip: r.get(0)?,
            reason: r.get(1)?,
            until: r.get(2)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

/// Read back all ipfilter rows (id order = insertion order).
pub(super) fn load_ipfilter(conn: &Connection) -> Result<Vec<IpfilterRow>, StoreError> {
    let mut stmt = conn.prepare("SELECT kind, rule, enabled FROM ipfilter ORDER BY id")?;
    let rows = stmt.query_map([], |r| {
        Ok(IpfilterRow {
            kind: r.get(0)?,
            rule: r.get(1)?,
            enabled: r.get::<_, i64>(2)? != 0,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

/// Read back ipfilter rows by kind (the comparison face of the replacement
/// semantics).
fn load_ipfilter_by_kind(conn: &Connection, kind: &str) -> Result<Vec<IpfilterRow>, StoreError> {
    let mut stmt =
        conn.prepare("SELECT kind, rule, enabled FROM ipfilter WHERE kind = ?1 ORDER BY id")?;
    let rows = stmt.query_map(params![kind], |r| {
        Ok(IpfilterRow {
            kind: r.get(0)?,
            rule: r.get(1)?,
            enabled: r.get::<_, i64>(2)? != 0,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)
}

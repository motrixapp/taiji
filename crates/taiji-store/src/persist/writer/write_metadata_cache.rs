//! Bounded content cache on the existing writer connection. This is derived
//! data, never task state; consumers must verify raw info hashes and layers.
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::oneshot;

use super::{PersistHandle, PersistJob};
use crate::error::StoreError;

const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 1024;

/// Full content identities. A hybrid lookup requires both hashes to match.
#[derive(Clone, Copy, Debug)]
pub struct MetadataCacheIdentity {
    pub v1: Option<[u8; 20]>,
    pub v2: Option<[u8; 32]>,
}

impl PersistHandle {
    /// Save verified, credential-free metadata in the bounded derived cache.
    pub async fn cache_metadata(
        &self,
        identity: MetadataCacheIdentity,
        metadata: Vec<u8>,
    ) -> Result<(), StoreError> {
        let (reply, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::CacheMetadata {
                identity,
                metadata,
                reply,
            })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Read cached bytes or a retained task's metadata without network IO.
    /// Bytes are untrusted until the caller checks their complete identity.
    pub async fn load_metadata(
        &self,
        identity: MetadataCacheIdentity,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::LoadMetadata { identity, reply })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }

    /// Remove derived cache entries; task-owned metadata is never deleted.
    pub async fn evict_metadata(
        &self,
        identity: Option<MetadataCacheIdentity>,
    ) -> Result<(), StoreError> {
        let (reply, rx) = oneshot::channel();
        self.job_tx
            .send(PersistJob::EvictMetadata { identity, reply })
            .await
            .map_err(|_| StoreError::WriterClosed)?;
        rx.await.map_err(|_| StoreError::WriterClosed)?
    }
}

fn next_use(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row(
        "SELECT coalesce(max(last_used),0)+1 FROM metadata_cache",
        [],
        |row| row.get(0),
    )?)
}

pub(super) fn load_metadata(
    conn: &mut Connection,
    identity: MetadataCacheIdentity,
) -> Result<Option<Vec<u8>>, StoreError> {
    if identity.v1.is_none() && identity.v2.is_none() {
        return Ok(None);
    }
    let v1 = identity.v1.as_ref().map(|h| h.as_slice());
    let v2 = identity.v2.as_ref().map(|h| h.as_slice());
    let found: Option<(i64, Vec<u8>)> = conn.query_row(
        "SELECT id,metadata FROM metadata_cache WHERE (?1 IS NULL OR v1=?1) AND (?2 IS NULL OR v2=?2) AND length(metadata)<=?3 LIMIT 1",
        params![v1, v2, MAX_ENTRY_BYTES as i64], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional()?;
    if let Some((id, bytes)) = found {
        conn.execute(
            "UPDATE metadata_cache SET last_used=?1 WHERE id=?2",
            params![next_use(conn)?, id],
        )?;
        return Ok(Some(bytes));
    }
    let sql = if v1.is_some() {
        "SELECT metadata FROM torrent WHERE v1_infohash=?1 AND (?2 IS NULL OR v2_infohash=?2) AND metadata IS NOT NULL AND length(metadata)<=?3 ORDER BY updated_at DESC LIMIT 1"
    } else {
        "SELECT metadata FROM torrent WHERE v2_infohash=?2 AND metadata IS NOT NULL AND length(metadata)<=?3 ORDER BY updated_at DESC LIMIT 1"
    };
    Ok(conn
        .query_row(sql, params![v1, v2, MAX_ENTRY_BYTES as i64], |row| {
            row.get(0)
        })
        .optional()?)
}

pub(super) fn cache_metadata(
    conn: &mut Connection,
    identity: MetadataCacheIdentity,
    bytes: &[u8],
) -> Result<(), StoreError> {
    cache_with_limits(conn, identity, bytes, MAX_CACHE_BYTES, MAX_ENTRIES)
}

fn cache_with_limits(
    conn: &mut Connection,
    identity: MetadataCacheIdentity,
    bytes: &[u8],
    max_bytes: usize,
    max_entries: usize,
) -> Result<(), StoreError> {
    // Oversize content remains owned by its task, never by this acceleration cache.
    if bytes.is_empty()
        || bytes.len() > MAX_ENTRY_BYTES
        || bytes.len() > max_bytes
        || (identity.v1.is_none() && identity.v2.is_none())
    {
        return Ok(());
    }
    let v1 = identity.v1.as_ref().map(|h| h.as_slice());
    let v2 = identity.v2.as_ref().map(|h| h.as_slice());
    let existing: Option<Vec<u8>> = conn
        .query_row(
            "SELECT metadata FROM metadata_cache WHERE v1 IS ?1 AND v2 IS ?2",
            params![v1, v2],
            |row| row.get(0),
        )
        .optional()?;
    if existing.as_deref() == Some(bytes) {
        return Ok(());
    }
    let tx = conn.transaction()?;
    let used = next_use(&tx)?;
    tx.execute(
        "DELETE FROM metadata_cache WHERE v1=?1 OR v2=?2",
        params![v1, v2],
    )?;
    tx.execute(
        "INSERT INTO metadata_cache(v1,v2,metadata,last_used) VALUES(?1,?2,?3,?4)",
        params![v1, v2, bytes, used],
    )?;
    let entries = tx
        .prepare("SELECT id,length(metadata) FROM metadata_cache ORDER BY last_used DESC,id DESC")?
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut total = 0i64;
    for (index, (id, size)) in entries.into_iter().enumerate() {
        total = total.saturating_add(size);
        if index >= max_entries || total > max_bytes as i64 {
            tx.execute("DELETE FROM metadata_cache WHERE id=?1", [id])?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub(super) fn evict_metadata(
    conn: &Connection,
    identity: Option<MetadataCacheIdentity>,
) -> Result<(), StoreError> {
    if let Some(identity) = identity {
        conn.execute(
            "DELETE FROM metadata_cache WHERE v1=?1 OR v2=?2",
            params![
                identity.v1.as_ref().map(|h| h.as_slice()),
                identity.v2.as_ref().map(|h| h.as_slice())
            ],
        )?;
    } else {
        conn.execute("DELETE FROM metadata_cache", [])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> Connection {
        let conn = Connection::open_in_memory().unwrap_or_else(|e| panic!("{e}"));
        for migration in crate::persist::MIGRATIONS {
            for sql in migration.sqls {
                conn.execute_batch(sql).unwrap_or_else(|e| panic!("{e}"));
            }
        }
        conn
    }
    fn identity(n: u8) -> MetadataCacheIdentity {
        MetadataCacheIdentity {
            v1: Some([n; 20]),
            v2: Some([n; 32]),
        }
    }

    #[test]
    fn cache_enforces_identity_lru_and_byte_limits() -> Result<(), StoreError> {
        let mut conn = database();
        cache_with_limits(&mut conn, identity(1), &[1; 16], 32, 2)?;
        cache_with_limits(&mut conn, identity(2), &[2; 16], 32, 2)?;
        assert_eq!(load_metadata(&mut conn, identity(1))?, Some(vec![1; 16]));
        cache_with_limits(&mut conn, identity(3), &[3; 16], 32, 2)?;
        assert!(load_metadata(&mut conn, identity(2))?.is_none());
        assert!(
            load_metadata(
                &mut conn,
                MetadataCacheIdentity {
                    v1: Some([1; 20]),
                    v2: Some([3; 32])
                }
            )?
            .is_none()
        );
        assert_eq!(load_metadata(&mut conn, identity(1))?, Some(vec![1; 16]));
        cache_with_limits(&mut conn, identity(4), &[4; 25], 32, 2)?;
        assert!(load_metadata(&mut conn, identity(1))?.is_none());
        evict_metadata(&conn, None)?;
        assert!(load_metadata(&mut conn, identity(4))?.is_none());
        cache_with_limits(&mut conn, identity(5), &[5], 100, 1)?;
        cache_with_limits(&mut conn, identity(6), &[6], 100, 1)?;
        assert!(load_metadata(&mut conn, identity(5))?.is_none());
        assert_eq!(load_metadata(&mut conn, identity(6))?, Some(vec![6]));
        Ok(())
    }

    #[test]
    fn v5_cache_migration_preserves_existing_v4_task_metadata() -> Result<(), StoreError> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("taiji-cache-migration-{unique}.sqlite3"));
        {
            let conn = crate::persist::open_and_migrate_up_to(&path, 4)?;
            conn.execute("INSERT INTO torrent(gid,name,state,queue_pos,dir,config_json,kind,v1_infohash,metadata,created_at,updated_at) VALUES('123456789abcdef0','retained','paused',1,'/downloads','{}','v1',?1,?2,1,1)", params![[7u8;20].as_slice(), b"retained metadata".as_slice()])?;
        }
        let mut conn = crate::persist::open_and_migrate(&path)?;
        let identity = MetadataCacheIdentity {
            v1: Some([7; 20]),
            v2: None,
        };
        assert_eq!(
            load_metadata(&mut conn, identity)?,
            Some(b"retained metadata".to_vec())
        );
        cache_metadata(&mut conn, identity, b"derived metadata")?;
        evict_metadata(&conn, None)?;
        assert_eq!(
            load_metadata(&mut conn, identity)?,
            Some(b"retained metadata".to_vec())
        );
        let state: String = conn.query_row("SELECT state FROM torrent", [], |row| row.get(0))?;
        assert_eq!(state, "paused");
        drop(conn);
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn writer_cache_survives_restart_and_clear() -> Result<(), StoreError> {
        use super::super::PersistWriter;
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "taiji-cache-{}-{unique}.sqlite3",
            std::process::id()
        ));
        let (writer, join) = PersistWriter::spawn(path.clone()).await?;
        writer.cache_metadata(identity(1), vec![7; 20]).await?;
        drop(writer);
        join.await.unwrap_or_else(|e| panic!("{e}"));
        let (writer, join) = PersistWriter::spawn(path.clone()).await?;
        assert_eq!(writer.load_metadata(identity(1)).await?, Some(vec![7; 20]));
        writer.evict_metadata(None).await?;
        assert!(writer.load_metadata(identity(1)).await?.is_none());
        drop(writer);
        join.await.unwrap_or_else(|e| panic!("{e}"));
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}

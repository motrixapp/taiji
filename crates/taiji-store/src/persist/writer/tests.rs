use super::*;
use crate::persist::open_and_migrate;
use crate::persist::writer::rows::{TASK_KIND_HTTP, TaskCookieRow};
use std::time::Duration;

/// Unique tmp database path.
fn tmp_db(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "taiji-writer-{}-{}-{}.sqlite3",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ))
}

/// Test-side Result unwrap (lints bar unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

fn row(gid: &str, downloaded_total: i64) -> TorrentProgressRow {
    TorrentProgressRow {
        gid: gid.into(),
        piece_length: 16 * 1024,
        v1_bitfield: Some(vec![0b1010_1010, 0x00]),
        v2_file_bits: None,
        upload_at_startup: 0,
        downloaded_total,
        uploaded_total: 7,
        active_time_s: 1,
        seed_time_s: 0,
    }
}

/// FK fixture: `torrent_progress.gid` references `torrent(gid)`
/// (foreign_keys=ON), so a progress row needs a torrent parent
/// before it can land. Test fixture only — not business-table write
/// semantics (business assembly is a later milestone).
fn insert_fixture_torrent(conn: &Connection, gid: &str) {
    ok(
            conn.execute(
                "INSERT INTO torrent (gid, name, state, queue_pos, dir, config_json, kind, created_at, updated_at)
                 VALUES (?1, 'fixture', 'downloading', 0, '/tmp/fixture', '{}', 'v1', 0, 0)",
                params![gid],
            ),
            "fixture torrent",
        );
}

fn downloaded_total_of(conn: &Connection, gid: &str) -> i64 {
    ok(
        conn.query_row(
            "SELECT downloaded_total FROM torrent_progress WHERE gid = ?1",
            params![gid],
            |r| r.get(0),
        ),
        "read progress",
    )
}

#[tokio::test]
async fn digest_dedup_skips_unchanged_then_writes_on_change() {
    let path = tmp_db("dedup");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    {
        // FK fixture row (written on a separate connection, then closed).
        let fixture = ok(open_and_migrate(&path), "fixture conn");
        insert_fixture_torrent(&fixture, "8000000000000001");
    }

    // Two writes of identical data -> first Written, second
    // SkippedUnchanged.
    let r1 = ok(
        handle
            .upsert_torrent_progress(row("8000000000000001", 100))
            .await,
        "first write",
    );
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle
            .upsert_torrent_progress(row("8000000000000001", 100))
            .await,
        "second write",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    // Payload change -> written again.
    let r3 = ok(
        handle
            .upsert_torrent_progress(row("8000000000000001", 200))
            .await,
        "changed write",
    );
    assert_eq!(r3, PersistOutcome::Written);

    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok(), "writer must exit within 1s of handle drop");

    // Read-back check: the stored value is the last Written payload.
    let conn = ok(open_and_migrate(&path), "readback conn");
    assert_eq!(downloaded_total_of(&conn, "8000000000000001"), 200);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn writer_exits_gracefully_after_all_handles_drop() {
    let path = tmp_db("graceful");
    let (h1, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    let h2 = h1.clone();
    drop(h1);
    drop(h2);
    // All handles dropped -> exit after draining the queue (1s budget).
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(
        exited.is_ok(),
        "writer must exit within 1s of last handle drop"
    );
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn foreign_keys_enforced_on_writer_connection() {
    let path = tmp_db("fk");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    // No torrent parent -> FK constraint refusal (proof that PRAGMA
    // foreign_keys=ON is in effect).
    let refused = handle
        .upsert_torrent_progress(row("80000000000000ff", 0))
        .await;
    assert!(refused.is_err(), "FK violation must surface as StoreError");
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

/// Kill-restart simulation must preserve cross-session bases: session 1
/// writes `uploaded_total`; after restart (writer rebuilt + load) the
/// read-back matches; the new session keeps writing with the read-back
/// value as the `upload_at_startup` base — the ratio base chain never
/// breaks.
#[tokio::test]
async fn progress_roundtrip_survives_writer_restart() {
    let path = tmp_db("progress-roundtrip");
    {
        let fixture = ok(open_and_migrate(&path), "fixture conn");
        insert_fixture_torrent(&fixture, "8000000000000003");
    }
    // Session 1: write 1000 uploaded (uploaded_total),
    // upload_at_startup=0.
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn 1");
    let row1 = TorrentProgressRow {
        gid: "8000000000000003".into(),
        piece_length: 16 * 1024,
        v1_bitfield: Some(vec![0b1111_1111]),
        v2_file_bits: None,
        upload_at_startup: 0,
        downloaded_total: 32 * 1024,
        uploaded_total: 1000,
        active_time_s: 95,
        seed_time_s: 60,
    };
    assert_eq!(
        ok(handle.upsert_torrent_progress(row1).await, "write 1"),
        PersistOutcome::Written
    );
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer 1 exit",
    );

    // Kill-restart simulation: a brand-new writer object reads back the
    // previous session's totals.
    let (handle2, join2) = ok(PersistWriter::spawn(path.clone()).await, "spawn 2");
    let loaded = ok(
        handle2.load_torrent_progress("8000000000000003").await,
        "load after restart",
    );
    let base = loaded.unwrap_or_else(|| panic!("row must exist after restart"));
    assert_eq!(
        base.uploaded_total, 1000,
        "the ratio base (last session's cumulative upload)"
    );
    assert_eq!(base.downloaded_total, 32 * 1024);
    assert_eq!(base.active_time_s, 95);
    assert_eq!(base.seed_time_s, 60);
    assert_eq!(base.upload_at_startup, 0);

    // Session 2: at registration upload_at_startup := the read-back
    // uploaded_total; cumulative fields = base + this session's delta,
    // read back losslessly.
    let row2 = TorrentProgressRow {
        gid: "8000000000000003".into(),
        piece_length: 16 * 1024,
        v1_bitfield: Some(vec![0b1111_1111]),
        v2_file_bits: None,
        upload_at_startup: base.uploaded_total,
        downloaded_total: base.downloaded_total,
        uploaded_total: base.uploaded_total + 2500,
        active_time_s: base.active_time_s + 40,
        seed_time_s: base.seed_time_s + 40,
    };
    assert_eq!(
        ok(handle2.upsert_torrent_progress(row2).await, "write 2"),
        PersistOutcome::Written
    );
    let reloaded = ok(
        handle2.load_torrent_progress("8000000000000003").await,
        "load session 2",
    )
    .unwrap_or_else(|| panic!("row must exist"));
    assert_eq!(
        reloaded.upload_at_startup, 1000,
        "the session base read back"
    );
    assert_eq!(reloaded.uploaded_total, 3500);
    assert_eq!(reloaded.active_time_s, 135);
    assert_eq!(reloaded.seed_time_s, 100);

    drop(handle2);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join2).await,
        "writer 2 exit",
    );

    // Missing gid -> Ok(None) (the first task's registration face).
    let (handle3, join3) = ok(PersistWriter::spawn(path.clone()).await, "spawn 3");
    let missing = ok(
        handle3.load_torrent_progress("8000000000000009").await,
        "load missing",
    );
    assert!(missing.is_none(), "no progress row = Ok(None)");
    drop(handle3);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join3).await,
        "writer 3 exit",
    );
    let _ = std::fs::remove_file(&path);
}

/// Tracker row fixture (table fields).
fn tracker_row(gid: &str, tier: i64, url: &str, last_error: Option<String>) -> TrackerRow {
    TrackerRow {
        gid: gid.into(),
        tier,
        url: url.into(),
        enabled: true,
        last_interval: None,
        last_min_interval: None,
        next_announce_at: None,
        last_error,
        last_ok_at: None,
        seeds: None,
        leechers: None,
    }
}

fn tracker_row_of(
    conn: &Connection,
    gid: &str,
    tier: i64,
    url: &str,
) -> Option<super::TrackerRowCmp> {
    conn.query_row(
        "SELECT enabled, last_interval, last_min_interval, next_announce_at,
                    last_error, last_ok_at, seeds, leechers
             FROM tracker WHERE gid = ?1 AND tier = ?2 AND url = ?3",
        params![gid, tier, url],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        },
    )
    .optional()
    .ok()
    .flatten()
}

/// Tracker table persistence + skip-write semantics: rewriting identical
/// data produces no disk writes (row-level comparison; the behavior
/// matches digest dedup); only a changed payload writes again.
#[tokio::test]
async fn tracker_row_dedup_skips_unchanged_then_writes_on_change() {
    let path = tmp_db("tracker-dedup");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    {
        // FK fixture: tracker.gid references torrent(gid).
        let fixture = ok(open_and_migrate(&path), "fixture conn");
        insert_fixture_torrent(&fixture, "8000000000000002");
    }

    // First write -> Written; identical rewrite -> SkippedUnchanged
    // (zero disk writes).
    let r1 = ok(
        handle
            .upsert_tracker(tracker_row(
                "8000000000000002",
                0,
                "http://t0/announce",
                Some("404".into()),
            ))
            .await,
        "first tracker write",
    );
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle
            .upsert_tracker(tracker_row(
                "8000000000000002",
                0,
                "http://t0/announce",
                Some("404".into()),
            ))
            .await,
        "same tracker rewrite",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    // Payload change (success clears the error + interval fields) ->
    // written again.
    let mut ok_row = tracker_row("8000000000000002", 0, "http://t0/announce", None);
    ok_row.last_interval = Some(1800);
    ok_row.last_min_interval = Some(900);
    ok_row.next_announce_at = Some(1_700_000_000);
    ok_row.last_ok_at = Some(1_699_999_940);
    ok_row.seeds = Some(42);
    ok_row.leechers = Some(3);
    let r3 = ok(
        handle.upsert_tracker(ok_row.clone()).await,
        "changed tracker write",
    );
    assert_eq!(r3, PersistOutcome::Written);
    // Full-field read-back = the last Written payload (the skip masked
    // nothing).
    {
        let conn = ok(open_and_migrate(&path), "readback conn");
        let got = tracker_row_of(&conn, "8000000000000002", 0, "http://t0/announce");
        assert_eq!(
            got,
            Some((
                1,
                Some(1800),
                Some(900),
                Some(1_700_000_000),
                None,
                Some(1_699_999_940),
                Some(42),
                Some(3)
            ))
        );
    }
    // A different (tier, url) = a different row; they do not interfere.
    let r4 = ok(
        handle
            .upsert_tracker(tracker_row(
                "8000000000000002",
                1,
                "http://t1/announce",
                Some("timeout".into()),
            ))
            .await,
        "second row write",
    );
    assert_eq!(r4, PersistOutcome::Written);
    {
        let conn = ok(open_and_migrate(&path), "readback conn 2");
        assert!(tracker_row_of(&conn, "8000000000000002", 1, "http://t1/announce").is_some());
    }

    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok(), "writer must exit within 1s of handle drop");
    let _ = std::fs::remove_file(&path);
}

/// Tracker row FK: no torrent parent -> refusal (PRAGMA foreign_keys=ON
/// in effect).
#[tokio::test]
async fn tracker_row_foreign_keys_enforced() {
    let path = tmp_db("tracker-fk");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    let refused = handle
        .upsert_tracker(tracker_row(
            "80000000000000fe",
            0,
            "http://t/announce",
            None,
        ))
        .await;
    assert!(refused.is_err(), "FK violation must surface as StoreError");
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

fn ban_row(ip: &str, reason: &str, until: i64) -> PeerBanRow {
    PeerBanRow {
        ip: ip.into(),
        reason: reason.into(),
        until,
    }
}

fn filter_row(kind: &str, rule: &str) -> IpfilterRow {
    IpfilterRow {
        kind: kind.into(),
        rule: rule.into(),
        enabled: true,
    }
}

/// peer_ban persistence + skip-write + same-IP overwrite + an
/// until-filtered read-back (the read face that decides ban enforcement
/// after a restart).
#[tokio::test]
async fn peer_ban_upsert_dedup_and_active_readback() {
    let path = tmp_db("peer-ban");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");

    // First write -> Written; identical rewrite -> SkippedUnchanged.
    let r1 = ok(
        handle
            .upsert_peer_ban(ban_row("192.0.2.1", "unsolicited piece", 5000))
            .await,
        "first ban",
    );
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle
            .upsert_peer_ban(ban_row("192.0.2.1", "unsolicited piece", 5000))
            .await,
        "same ban",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    // Re-banning the same IP = overwrite (reason/until updated).
    let r3 = ok(
        handle
            .upsert_peer_ban(ban_row("192.0.2.1", "flooding", 9000))
            .await,
        "ban overwrite",
    );
    assert_eq!(r3, PersistOutcome::Written);

    // Read-back filter: only rows with until > now return; different IPs
    // form separate rows.
    let r4 = ok(
        handle
            .upsert_peer_ban(ban_row("192.0.2.2", "hash failures", 7000))
            .await,
        "second ip ban",
    );
    assert_eq!(r4, PersistOutcome::Written);
    let active = ok(handle.load_active_peer_bans(6000).await, "active at 6000");
    assert_eq!(
        active,
        vec![
            ban_row("192.0.2.1", "flooding", 9000),
            ban_row("192.0.2.2", "hash failures", 7000)
        ],
        "both rows active at 6000"
    );
    let active = ok(handle.load_active_peer_bans(7000).await, "active at 7000");
    assert_eq!(
        active,
        vec![ban_row("192.0.2.1", "flooding", 9000)],
        "at 7000 the until=7000 row has expired (until > now)"
    );
    let active = ok(
        handle.load_active_peer_bans(10_000).await,
        "active at 10000",
    );
    assert!(active.is_empty(), "all expired -> the empty set");

    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

/// delete_peer_ban (the taiji.unbanAddr unban face) — deleting an
/// existing row = Written; missing row = SkippedUnchanged (idempotent);
/// after deletion the read-back no longer returns it (the unban survives
/// restarts).
#[tokio::test]
async fn peer_ban_delete_is_idempotent_and_persistent() {
    let path = tmp_db("peer-ban-delete");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    ok(
        handle
            .upsert_peer_ban(ban_row("10.66.0.0/24", "manual", i64::MAX))
            .await,
        "insert manual cidr ban",
    );
    // Delete an existing row; deleting a missing row =
    // SkippedUnchanged (idempotent).
    let r1 = ok(
        handle.delete_peer_ban("10.66.0.0/24").await,
        "delete existing",
    );
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle.delete_peer_ban("10.66.0.0/24").await,
        "delete missing",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    assert!(
        ok(handle.load_active_peer_bans(0).await, "readback").is_empty(),
        "read-back is empty after deletion"
    );
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

/// ipfilter whole-table replacement semantics: full replacement within a
/// kind, an identical re-import skips, rows of other kinds are
/// untouched, read-back in insertion order.
#[tokio::test]
async fn ipfilter_replace_semantics() {
    let path = tmp_db("ipfilter");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");

    // Seed one cidr row (the manual/RPC face; verifies the replace does
    // not touch it).
    let r0 = ok(
        handle
            .replace_ipfilter("cidr", vec![filter_row("cidr", "10.0.0.0/8")])
            .await,
        "cidr seed",
    );
    assert_eq!(r0, PersistOutcome::Written);

    // First import -> Written; identical re-import -> SkippedUnchanged
    // (zero disk writes).
    let rows1 = vec![
        filter_row("p2p-blocklist", "deny,000.000.000.000,000.255.255.255"),
        filter_row("p2p-blocklist", "allow,192.168.0.1,192.168.0.255"),
        filter_row("p2p-blocklist", "deny,10.9.9.0,10.9.9.255"),
    ];
    let r1 = ok(
        handle
            .replace_ipfilter("p2p-blocklist", rows1.clone())
            .await,
        "first import",
    );
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle
            .replace_ipfilter("p2p-blocklist", rows1.clone())
            .await,
        "same import",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);

    // Second import = whole-table replace (no old rows left over).
    let rows2 = vec![filter_row("p2p-blocklist", "deny,1.2.3.4,1.2.3.4")];
    let r3 = ok(
        handle
            .replace_ipfilter("p2p-blocklist", rows2.clone())
            .await,
        "second import",
    );
    assert_eq!(r3, PersistOutcome::Written);
    let all = ok(handle.load_ipfilter().await, "readback");
    assert_eq!(
        all,
        vec![
            filter_row("cidr", "10.0.0.0/8"),
            filter_row("p2p-blocklist", "deny,1.2.3.4,1.2.3.4"),
        ],
        "the cidr row is kept, p2p-blocklist fully replaced"
    );

    // Empty import (empty row set) = delete all.
    let r4 = ok(
        handle.replace_ipfilter("p2p-blocklist", Vec::new()).await,
        "empty import",
    );
    assert_eq!(r4, PersistOutcome::Written);
    let all = ok(handle.load_ipfilter().await, "readback after empty");
    assert_eq!(all, vec![filter_row("cidr", "10.0.0.0/8")]);

    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

fn dht_row(family: &str, table_tag: u8) -> DhtStateRow {
    DhtStateRow {
        family: family.into(),
        node_id: vec![0xAA; 20],
        routing_table: vec![table_tag; 26],
        saved_at: 1_700_000_000,
    }
}

/// dht_state persistence + skip-write + family primary-key overwrite +
/// restart roundtrip (DhtEvent::Persist -> row -> LoadDhtState read-back
/// = the `DhtRestoreState` payload source; no FK, no torrent parent
/// dependency).
#[tokio::test]
async fn dht_state_upsert_dedup_and_restart_roundtrip() {
    let path = tmp_db("dht-state");
    // Session 1: autosave writes the v4 row; an identical rewrite (the
    // autosave tick) skips.
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn 1");
    let r1 = ok(handle.upsert_dht_state(dht_row("v4", 1)).await, "v4 write");
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle.upsert_dht_state(dht_row("v4", 1)).await,
        "v4 rewrite (autosave tick)",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    // The v6 family forms its own row (primary key family).
    let r3 = ok(handle.upsert_dht_state(dht_row("v6", 2)).await, "v6 write");
    assert_eq!(r3, PersistOutcome::Written);
    // Routing-table change (bucket update) -> overwrite the same row.
    let r4 = ok(handle.upsert_dht_state(dht_row("v4", 3)).await, "v4 update");
    assert_eq!(r4, PersistOutcome::Written);
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer 1 exit",
    );

    // Kill-restart simulation: a brand-new writer reads both rows back
    // losslessly (node_id + BLOB).
    let (handle2, join2) = ok(PersistWriter::spawn(path.clone()).await, "spawn 2");
    let v4 = ok(handle2.load_dht_state("v4").await, "load v4");
    assert_eq!(
        v4,
        Some(dht_row("v4", 3)),
        "the v4 row = the last Written payload"
    );
    let v6 = ok(handle2.load_dht_state("v6").await, "load v6");
    assert_eq!(v6, Some(dht_row("v6", 2)));
    // Never-saved family -> Ok(None).
    let missing = ok(handle2.load_dht_state("v4x").await, "load missing family");
    assert!(missing.is_none(), "a never-written family = Ok(None)");
    drop(handle2);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join2).await,
        "writer 2 exit",
    );
    let _ = std::fs::remove_file(&path);
}

// ---- business rows ----

/// Torrent row fixture (table fields; v2-only single file).
fn torrent_row(gid: &str, state: &str, queue_pos: i64) -> TorrentRow {
    TorrentRow {
        gid: gid.into(),
        name: "v2.bin".into(),
        state: state.into(),
        queue_pos,
        dir: "/tmp/dl".into(),
        config_json: r#"{"dir":"/tmp/dl"}"#.into(),
        kind: "v2".into(),
        v1_infohash: None,
        v2_infohash: Some(vec![0xAB; 32]),
        is_private: false,
        metadata: Some(vec![0x64; 40]),
        error_code: None,
        error_msg: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    }
}

fn torrent_file_row(gid: &str, file_index: i64, path: &str) -> TorrentFileRow {
    TorrentFileRow {
        gid: gid.into(),
        file_index,
        path: path.into(),
        length: 128 * 1024,
        attr: None,
        pieces_root: Some(vec![0x11; 32]),
        piece_layer: Some(vec![0x22; 32]),
        v1_offset: None,
        selected: true,
        priority: 0,
    }
}

fn torrent_state_of(conn: &Connection, gid: &str) -> Option<String> {
    conn.query_row(
        "SELECT state FROM torrent WHERE gid = ?1",
        params![gid],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

fn torrent_updated_at_of(conn: &Connection, gid: &str) -> Option<i64> {
    conn.query_row(
        "SELECT updated_at FROM torrent WHERE gid = ?1",
        params![gid],
        |r| r.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

/// global_tracker write/read consistency + unchanged-set skip +
/// whole-table replace + restart roundtrip (the global import set
/// recovers across sessions; no FK, independent of the torrent
/// lifecycle).
#[tokio::test]
async fn global_tracker_replace_roundtrip_and_restart() {
    let path = tmp_db("global-tracker");
    // Session 1: import 3 entries -> Written; re-importing the same set
    // -> skip.
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn 1");
    let set1 = vec![
        "udp://tracker.a:6969/announce".to_string(),
        "https://tracker.b/announce".to_string(),
        "udp://tracker.c:1337/announce".to_string(),
    ];
    let r1 = ok(
        handle.replace_global_trackers(set1.clone()).await,
        "import 1",
    );
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle.replace_global_trackers(set1.clone()).await,
        "re-import same set",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    let loaded = ok(handle.load_global_trackers().await, "readback 1");
    assert_eq!(
        loaded, set1,
        "rowid order = import order, write and read agree"
    );
    // Incremental import (the caller computes the union): replaces the
    // whole table (no old set left over).
    let set2 = vec![
        "udp://tracker.a:6969/announce".to_string(),
        "wss://tracker.d/announce".to_string(),
    ];
    let r3 = ok(
        handle.replace_global_trackers(set2.clone()).await,
        "import 2",
    );
    assert_eq!(r3, PersistOutcome::Written);
    let loaded = ok(handle.load_global_trackers().await, "readback 2");
    assert_eq!(loaded, set2);
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer 1 exit",
    );
    // Restart: a brand-new writer reads the set back intact (the
    // persisted recovery face).
    let (handle2, join2) = ok(PersistWriter::spawn(path.clone()).await, "spawn 2");
    let loaded = ok(
        handle2.load_global_trackers().await,
        "readback after restart",
    );
    assert_eq!(
        loaded, set2,
        "the global set must be restored after restart"
    );
    drop(handle2);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join2).await,
        "writer 2 exit",
    );
    let _ = std::fs::remove_file(&path);
}

/// Torrent parent row + file-set upsert with row-level-comparison
/// skip-write (a skip keeps the old observational created_at/updated_at;
/// a changed write refreshes updated_at but keeps created_at — COALESCE
/// semantics).
#[tokio::test]
async fn torrent_row_upsert_dedup_and_observed_columns() {
    let path = tmp_db("torrent-row");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");

    let files = vec![
        torrent_file_row("8000000000000010", 0, "v2.bin"),
        torrent_file_row("8000000000000010", 1, "docs/readme.md"),
    ];
    let r1 = ok(
        handle
            .upsert_torrent(torrent_row("8000000000000010", "queued", 0), files.clone())
            .await,
        "first upsert",
    );
    assert_eq!(r1, PersistOutcome::Written);
    {
        let conn = ok(open_and_migrate(&path), "readback");
        assert_eq!(
            torrent_state_of(&conn, "8000000000000010"),
            Some("queued".into())
        );
        let n: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM torrent_file WHERE gid = ?1",
                params!["8000000000000010"],
                |r| r.get(0),
            ),
            "count files",
        );
        assert_eq!(n, 2);
        let created: i64 = ok(
            conn.query_row(
                "SELECT created_at FROM torrent WHERE gid = ?1",
                params!["8000000000000010"],
                |r| r.get(0),
            ),
            "created_at",
        );
        assert_eq!(created, 1_700_000_000);
    }
    // Identical rewrite (different observational values do not trigger a
    // write either) -> skip; updated_at keeps the first write's value.
    let mut again = torrent_row("8000000000000010", "queued", 0);
    again.updated_at = 1_700_000_999;
    let r2 = ok(
        handle.upsert_torrent(again, files.clone()).await,
        "same upsert",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    let updated_after_skip = {
        let conn = ok(open_and_migrate(&path), "readback 2");
        torrent_updated_at_of(&conn, "8000000000000010")
    };
    // State transition -> written again; created_at kept, updated_at
    // refreshed to the writer-side now (two writes within the same
    // second = the same now value, so equality with the skip value is
    // legal; the key invariant is that updated_at comes from the writer
    // clock, not from the payload's observational value).
    let r3 = ok(
        handle
            .upsert_torrent(
                torrent_row("8000000000000010", "downloading", 0),
                files.clone(),
            )
            .await,
        "state change",
    );
    assert_eq!(r3, PersistOutcome::Written);
    {
        let conn = ok(open_and_migrate(&path), "readback 3");
        assert_eq!(
            torrent_state_of(&conn, "8000000000000010"),
            Some("downloading".into())
        );
        let created: i64 = ok(
            conn.query_row(
                "SELECT created_at FROM torrent WHERE gid = ?1",
                params!["8000000000000010"],
                |r| r.get(0),
            ),
            "created_at kept",
        );
        assert_eq!(
            created, 1_700_000_000,
            "created_at is an observational column, keeps its initial value"
        );
        let updated = torrent_updated_at_of(&conn, "8000000000000010");
        // Same-second writes stamp the same now value; a second-boundary
        // crossing between the two writes (the wall-clock flake family —
        // strict equality raced the 1s tick under load) at most steps one
        // second. Bounded delta, never strict equality: the invariant
        // under test is the writer-clock source (asserted below), not the
        // calendar coincidence.
        match (updated_after_skip, updated) {
            (Some(a), Some(b)) => {
                assert!(
                    b >= a,
                    "updated_at monotonic (writer-side clock, {a} -> {b})"
                );
                assert!(
                    b - a <= 1,
                    "same second, or at most one second boundary apart (writer now, {a} -> {b})"
                );
            }
            other => panic!("updated_at must exist on both reads, got {other:?}"),
        }
        assert_ne!(
            updated,
            Some(1_700_000_999),
            "updated_at = the writer-side now, not the payload's observational value"
        );
    }
    // File-set change (authoritative replacement: 2 -> 1 rows) ->
    // written again.
    let one = vec![torrent_file_row("8000000000000010", 0, "v2.bin")];
    let r4 = ok(
        handle
            .upsert_torrent(torrent_row("8000000000000010", "downloading", 0), one)
            .await,
        "files change",
    );
    assert_eq!(r4, PersistOutcome::Written);
    {
        let conn = ok(open_and_migrate(&path), "readback 4");
        let n: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM torrent_file WHERE gid = ?1",
                params!["8000000000000010"],
                |r| r.get(0),
            ),
            "count files 2",
        );
        assert_eq!(n, 1, "authoritative file-set replacement");
    }

    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok(), "writer must exit within 1s of handle drop");
    let _ = std::fs::remove_file(&path);
}

/// FK cascade: deleting the torrent parent row cascades away
/// torrent_file/torrent_progress/tracker (foreign_keys=ON).
#[tokio::test]
async fn delete_torrent_cascades_children() {
    let path = tmp_db("torrent-fk-cascade");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    let gid = "8000000000000011";
    let files = vec![torrent_file_row(gid, 0, "v2.bin")];
    assert_eq!(
        ok(
            handle
                .upsert_torrent(torrent_row(gid, "seeding", 0), files)
                .await,
            "upsert"
        ),
        PersistOutcome::Written
    );
    // Child tables: progress + tracker (FK references the parent).
    assert_eq!(
        ok(
            handle
                .upsert_torrent_progress(TorrentProgressRow {
                    gid: gid.into(),
                    piece_length: 16384,
                    v1_bitfield: Some(vec![0xFF]),
                    v2_file_bits: None,
                    upload_at_startup: 0,
                    downloaded_total: 1,
                    uploaded_total: 2,
                    active_time_s: 3,
                    seed_time_s: 4,
                })
                .await,
            "progress"
        ),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(
            handle
                .upsert_tracker(TrackerRow {
                    gid: gid.into(),
                    tier: 0,
                    url: "http://t/announce".into(),
                    enabled: true,
                    last_interval: None,
                    last_min_interval: None,
                    next_announce_at: None,
                    last_error: None,
                    last_ok_at: None,
                    seeds: None,
                    leechers: None,
                })
                .await,
            "tracker"
        ),
        PersistOutcome::Written
    );

    // Delete the parent -> all children cleared (FK cascade).
    assert_eq!(
        ok(handle.delete_torrent(gid).await, "delete"),
        PersistOutcome::Written
    );
    // Delete again -> SkippedUnchanged (no-op).
    assert_eq!(
        ok(handle.delete_torrent(gid).await, "delete again"),
        PersistOutcome::SkippedUnchanged
    );
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    {
        let conn = ok(open_and_migrate(&path), "readback");
        for (table, what) in [
            ("torrent_file", "files"),
            ("torrent_progress", "progress"),
            ("tracker", "tracker"),
            ("torrent", "parent"),
        ] {
            let n: i64 = ok(
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE gid = ?1"),
                    params![gid],
                    |r| r.get(0),
                ),
                "count",
            );
            assert_eq!(n, 0, "{what} must be cascade-deleted");
        }
    }
    let _ = std::fs::remove_file(&path);
}

/// The recovery read face returns only the active set, in queue_pos
/// order, with file sets intact; terminal (done/error) rows never
/// appear.
#[tokio::test]
async fn load_torrents_at_startup_returns_active_set_ordered() {
    let path = tmp_db("startup-load");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    let cases = [
        ("8000000000000020", "downloading", 1i64),
        ("8000000000000021", "paused", 0),
        ("8000000000000022", "done", 2),
        ("8000000000000023", "error", 3),
        ("8000000000000024", "metadata", 4),
    ];
    for (gid, state, pos) in cases {
        let files = if state == "downloading" {
            vec![torrent_file_row(gid, 0, "v2.bin")]
        } else {
            Vec::new()
        };
        assert_eq!(
            ok(
                handle
                    .upsert_torrent(torrent_row(gid, state, pos), files)
                    .await,
                "upsert"
            ),
            PersistOutcome::Written
        );
    }
    let snaps = ok(handle.load_torrents_at_startup().await, "load");
    let gids: Vec<&str> = snaps.iter().map(|s| s.row.gid.as_str()).collect();
    assert_eq!(
        gids,
        vec!["8000000000000021", "8000000000000020", "8000000000000024"],
        "the active set ordered by queue_pos; done/error rows are not rebuilt"
    );
    assert_eq!(
        snaps[1].files.len(),
        1,
        "the file set reads back with the row"
    );
    assert_eq!(snaps[1].files[0].path, "v2.bin");
    assert_eq!(snaps[0].files.len(), 0);
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

/// The `queue_pos` global-upper-bound read face (the row_seq seeding
/// source): MAX across all torrent states (terminal rows count — they
/// live in the same table) + http_task, across the two tables; an empty
/// DB = 0.
#[tokio::test]
async fn load_max_queue_pos_spans_torrent_and_http_tables() {
    let path = tmp_db("max-queue-pos");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    // Empty DB = 0 (the first session's seeding origin).
    assert_eq!(ok(handle.load_max_queue_pos().await, "empty"), 0);
    // Torrent active row + terminal row (same table; terminal keys count
    // toward the bound).
    assert_eq!(
        ok(
            handle
                .upsert_torrent(torrent_row("8000000000000040", "paused", 5), Vec::new())
                .await,
            "torrent active"
        ),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(
            handle
                .insert_download_result(torrent_row("8000000000000041", "done", 9))
                .await,
            "torrent done"
        ),
        PersistOutcome::Written
    );
    // http_task row (the second table family).
    let mut http = http_task_row("8000000000000042", "downloading", 0);
    http.queue_pos = 7;
    assert_eq!(
        ok(handle.upsert_http_task(http).await, "http upsert"),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(handle.load_max_queue_pos().await, "max"),
        9,
        "MAX across both tables (terminal rows count toward the bound)"
    );
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

/// Persisted DownloadResult semantics: only terminal rows can be
/// inserted, dedup, purge/remove reach terminal rows only, read-back.
#[tokio::test]
async fn download_result_insert_purge_remove_load() {
    let path = tmp_db("download-result");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    let done_gid = "8000000000000030";
    let live_gid = "8000000000000031";
    // Land the active row first (with a file set; the result-row write
    // face must not touch it).
    let live_files = vec![torrent_file_row(live_gid, 0, "v2.bin")];
    assert_eq!(
        ok(
            handle
                .upsert_torrent(torrent_row(live_gid, "downloading", 0), live_files)
                .await,
            "live upsert"
        ),
        PersistOutcome::Written
    );
    // Non-terminal state -> explicit refusal.
    assert!(matches!(
        handle
            .insert_download_result(torrent_row(done_gid, "downloading", 0))
            .await,
        Err(StoreError::Internal(_))
    ));
    // Terminal write -> Written; identical rewrite -> Skipped.
    assert_eq!(
        ok(
            handle
                .insert_download_result(torrent_row(done_gid, "done", 9))
                .await,
            "insert done"
        ),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(
            handle
                .insert_download_result(torrent_row(done_gid, "done", 9))
                .await,
            "insert same"
        ),
        PersistOutcome::SkippedUnchanged
    );
    // The result-row write face must not touch the file set: give the
    // done row files, then flip it to error via the result face — the
    // files must survive.
    let done_files = vec![torrent_file_row(done_gid, 0, "v2.bin")];
    assert_eq!(
        ok(
            handle
                .upsert_torrent(torrent_row(done_gid, "done", 9), done_files)
                .await,
            "files"
        ),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(
            handle
                .insert_download_result(torrent_row(done_gid, "error", 9))
                .await,
            "done -> error"
        ),
        PersistOutcome::Written
    );
    // Read-back: terminal rows hit; active rows unreadable (None).
    let loaded = ok(handle.load_download_result(done_gid).await, "load result");
    assert_eq!(loaded.map(|r| r.state), Some("error".into()));
    assert!(ok(handle.load_download_result(live_gid).await, "load live").is_none());
    // remove reaches terminal rows only: active row -> Skipped; error
    // row -> Written.
    assert_eq!(
        ok(handle.remove_download_result(live_gid).await, "remove live"),
        PersistOutcome::SkippedUnchanged
    );
    assert_eq!(
        ok(handle.remove_download_result(done_gid).await, "remove done"),
        PersistOutcome::Written
    );
    // purge: only an active row remains -> nothing terminal to clear ->
    // Skipped; insert two terminal rows -> Written.
    assert_eq!(
        ok(handle.purge_download_results().await, "purge empty"),
        PersistOutcome::SkippedUnchanged
    );
    for gid in ["8000000000000032", "8000000000000033"] {
        assert_eq!(
            ok(
                handle
                    .insert_download_result(torrent_row(gid, "done", 5))
                    .await,
                "seed result"
            ),
            PersistOutcome::Written
        );
    }
    assert_eq!(
        ok(handle.purge_download_results().await, "purge two"),
        PersistOutcome::Written
    );
    {
        let conn = ok(open_and_migrate(&path), "readback");
        let terminal: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM torrent WHERE state IN ('done','error')",
                [],
                |r| r.get(0),
            ),
            "count terminal",
        );
        assert_eq!(terminal, 0, "the purge clears all terminal rows");
        // The active row and its file set are untouched by the purge.
        assert_eq!(
            torrent_state_of(&conn, live_gid),
            Some("downloading".into())
        );
        let n: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM torrent_file WHERE gid = ?1",
                params![live_gid],
                |r| r.get(0),
            ),
            "live files kept",
        );
        assert_eq!(n, 1);
    }
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

/// Write-point state validation on the torrent face (the upsert entry's
/// parse_v1 + family filter): an unknown word (case drift, a projection
/// word) and a cross-family word (an http-only or media-only phase
/// presented as a torrent row) are explicit internal errors that never
/// touch the row, on both [`PersistJob::UpsertTorrent`] and the
/// result-row face; the torrent family's own words — fold words
/// included — keep landing.
#[tokio::test]
async fn torrent_upsert_refuses_unknown_and_cross_family_states() {
    let path = tmp_db("torrent-state-validation");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    let gid = "8000000000000043";
    assert_eq!(
        ok(
            handle
                .upsert_torrent(torrent_row(gid, "downloading", 0), Vec::new())
                .await,
            "seed"
        ),
        PersistOutcome::Written
    );
    for bad in ["Paused", "active", "probing", "resolving", "recording"] {
        let err = match handle
            .upsert_torrent(torrent_row(gid, bad, 0), Vec::new())
            .await
        {
            Ok(_) => panic!("must refuse state {bad:?}"),
            Err(e) => e,
        };
        assert!(
            matches!(err, StoreError::Internal(_)),
            "an explicit writer-side refusal for {bad:?}: {err}"
        );
        assert!(
            err.to_string().contains(bad),
            "the error must carry the offending value {bad:?}: {err}"
        );
        // The result-row face refuses the same payloads (its own
        // terminal check never even runs — the family validation is
        // upstream of it).
        assert!(
            handle
                .insert_download_result(torrent_row(gid, bad, 0))
                .await
                .is_err()
        );
    }
    // The stored row survived every refusal unchanged; the family's
    // fold words and every active word keep landing.
    assert_eq!(
        ok(handle.load_torrents_at_startup().await, "load startup")
            .iter()
            .map(|s| s.row.state.as_str())
            .collect::<Vec<_>>(),
        vec!["downloading"],
        "the row is untouched by the refused payloads"
    );
    for good in [
        "queued",
        "metadata",
        "checking",
        "allocating",
        "seeding",
        "paused",
        "error",
        "done",
    ] {
        assert_eq!(
            ok(
                handle
                    .upsert_torrent(torrent_row(gid, good, 0), Vec::new())
                    .await,
                "good state"
            ),
            PersistOutcome::Written,
            "{good} is inside the torrent family's declared domain"
        );
    }
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    let _ = std::fs::remove_file(&path);
}

/// session_kv read/write + dedup; after the Checkpoint barrier
/// everything is durable (WAL checkpoint(TRUNCATE) ran successfully).
#[tokio::test]
async fn kv_roundtrip_and_checkpoint_barrier() {
    let path = tmp_db("kv");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    assert_eq!(
        ok(handle.put_kv("imported_from", "/fork/db").await, "put"),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(handle.put_kv("imported_from", "/fork/db").await, "put same"),
        PersistOutcome::SkippedUnchanged
    );
    assert_eq!(
        ok(
            handle.put_kv("imported_from", "/other").await,
            "put changed"
        ),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(handle.get_kv("imported_from").await, "get"),
        Some("/other".into())
    );
    assert_eq!(ok(handle.get_kv("missing").await, "get missing"), None);
    // Barrier: every earlier job durable + checkpoint(TRUNCATE).
    ok(handle.checkpoint().await, "checkpoint");
    drop(handle);
    let exited = tokio::time::timeout(Duration::from_secs(1), join).await;
    assert!(exited.is_ok());
    // After the checkpoint (WAL retained), reopening reads everything
    // back intact.
    {
        let conn = ok(open_and_migrate(&path), "reopen");
        let v: String = ok(
            conn.query_row(
                "SELECT value FROM session_kv WHERE key = 'imported_from'",
                [],
                |r| r.get(0),
            ),
            "read",
        );
        assert_eq!(v, "/other");
    }
    let _ = std::fs::remove_file(&path);
}

// ---- HTTP business rows ----

/// http_task row fixture (the media data-model fields).
fn http_task_row(gid: &str, state: &str, total_done: i64) -> HttpTaskRow {
    HttpTaskRow {
        gid: gid.into(),
        url: "http://origin/big.bin".into(),
        final_url: "http://cdn/big.bin".into(),
        mirrors_json: None,
        state: state.into(),
        queue_pos: 0,
        dir: "/tmp/dl".into(),
        out: "big.bin".into(),
        config_json: r#"{"split":16,"http-incomplete-suffix":".part"}"#.into(),
        probe_json: Some(r#"{"length":16777216,"range":true}"#.into()),
        validator_digest: Some(vec![0x5A; 32]),
        block_size: 4 * 1024 * 1024,
        block_bitmap: Some(vec![0b1100_1100, 0x00]),
        block_count: Some(4),
        total_done,
        error_code: None,
        error_msg: None,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    }
}

/// http_task dedup skip-write through the single-writer job channel
/// (identical rewrite = SkippedUnchanged, zero disk writes; the behavior
/// matches digest semantics — the frozen DDL has no digest column, so it
/// is implemented as row-level comparison) + a changed payload written
/// again + a startup recovery read face returning only the active set +
/// restart roundtrip.
#[tokio::test]
async fn http_task_upsert_dedup_and_startup_readback() {
    let path = tmp_db("http-task");
    let gid = "8000000000000300";
    // Session 1: first write -> Written; identical rewrite ->
    // SkippedUnchanged.
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn 1");
    let r1 = ok(
        handle
            .upsert_http_task(http_task_row(gid, "downloading", 0))
            .await,
        "first write",
    );
    assert_eq!(r1, PersistOutcome::Written);
    let r2 = ok(
        handle
            .upsert_http_task(http_task_row(gid, "downloading", 0))
            .await,
        "same rewrite (dedup)",
    );
    assert_eq!(r2, PersistOutcome::SkippedUnchanged);
    // Payload change (bitmap advance + counter) -> written again;
    // terminal transitions likewise.
    let r3 = ok(
        handle
            .upsert_http_task(http_task_row(gid, "downloading", 4 * 1024 * 1024))
            .await,
        "progress write",
    );
    assert_eq!(r3, PersistOutcome::Written);
    let r4 = ok(
        handle
            .upsert_http_task(http_task_row(gid, "done", 16 * 1024 * 1024))
            .await,
        "terminal write",
    );
    assert_eq!(r4, PersistOutcome::Written);
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer 1 exit",
    );

    // Kill-restart simulation: the recovery read face returns only the
    // active set; terminal rows are not rebuilt.
    let (handle2, join2) = ok(PersistWriter::spawn(path.clone()).await, "spawn 2");
    let active = ok(handle2.load_http_tasks_at_startup().await, "startup load");
    assert!(
        active.iter().all(|s| s.row.gid != gid),
        "terminal rows must not enter the recovery read face"
    );
    // The paused row enters the recovery face (active set) with a
    // full-field roundtrip.
    assert_eq!(
        ok(
            handle2
                .upsert_http_task(http_task_row("8000000000000301", "paused", 1024))
                .await,
            "paused write"
        ),
        PersistOutcome::Written
    );
    let active = ok(handle2.load_http_tasks_at_startup().await, "startup load 2");
    assert_eq!(active.len(), 1, "only the paused row is rebuilt");
    // updated_at is a writer-side observational column, compared after
    // normalization; business fields equal across the board.
    let mut expected = http_task_row("8000000000000301", "paused", 1024);
    expected.updated_at = active[0].row.updated_at;
    assert_eq!(
        active[0],
        HttpTaskSnapshot {
            row: expected,
            cookies: Vec::new(),
        }
    );
    drop(handle2);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join2).await,
        "writer 2 exit",
    );
    let _ = std::fs::remove_file(&path);
}

/// Task cookies through the single-writer job channel: whole-set
/// replacement / clear / restart replay (the handle API face; direct
/// write-face semantics live in the write_http tests).
#[tokio::test]
async fn http_task_cookies_via_job_channel_lifecycle() {
    let path = tmp_db("http-cookies");
    let gid = "8000000000000302";
    let ck = |name: &str, domain: &str, value: &str| TaskCookieRow {
        gid: gid.into(),
        task_kind: TASK_KIND_HTTP.into(),
        name: name.into(),
        domain: domain.into(),
        path: "/".into(),
        value: value.into(),
        expires_utc: Some(1_800_000_000),
        secure: true,
        host_only: false,
        creation_utc: 1_700_000_000,
    };
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    assert_eq!(
        ok(
            handle
                .upsert_http_task(http_task_row(gid, "downloading", 0))
                .await,
            "task row"
        ),
        PersistOutcome::Written
    );
    // Whole-set replacement + unchanged-set skip (the job-channel
    // policy).
    let set1 = vec![
        ck("sid", "cdn.example", "v1"),
        ck("auth", "origin.example", "tok"),
    ];
    assert_eq!(
        ok(
            handle
                .upsert_task_cookies(gid, TASK_KIND_HTTP, set1.clone())
                .await,
            "cookies 1"
        ),
        PersistOutcome::Written
    );
    let mut reordered = vec![set1[1].clone(), set1[0].clone()];
    assert_eq!(
        ok(
            handle
                .upsert_task_cookies(gid, TASK_KIND_HTTP, reordered.clone())
                .await,
            "cookies same"
        ),
        PersistOutcome::SkippedUnchanged
    );
    reordered[0].value = "tok2".to_string();
    assert_eq!(
        ok(
            handle
                .upsert_task_cookies(gid, TASK_KIND_HTTP, reordered)
                .await,
            "cookies replace"
        ),
        PersistOutcome::Written
    );
    // Restart replay: the cookie set replays with the recovery read face
    // (primary-key order).
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer exit",
    );
    let (handle2, join2) = ok(PersistWriter::spawn(path.clone()).await, "spawn 2");
    let loaded = ok(handle2.load_http_tasks_at_startup().await, "replay load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(
        loaded[0].cookies,
        vec![
            ck("auth", "origin.example", "tok2"),
            ck("sid", "cdn.example", "v1")
        ],
        "cookies replay in name/domain/path order"
    );
    // Clear on completion (ClearHttpTaskCookies): nothing resurrects
    // across restart after clearing.
    assert_eq!(
        ok(handle2.clear_task_cookies(gid).await, "clear"),
        PersistOutcome::Written
    );
    drop(handle2);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join2).await,
        "writer 2 exit",
    );
    let (handle3, join3) = ok(PersistWriter::spawn(path.clone()).await, "spawn 3");
    let loaded = ok(
        handle3.load_http_tasks_at_startup().await,
        "load after clear",
    );
    assert!(
        loaded[0].cookies.is_empty(),
        "nothing resurrects after clearing"
    );
    drop(handle3);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join3).await,
        "writer 3 exit",
    );
    let _ = std::fs::remove_file(&path);
}

// ---- media_archive faces ----

/// The archive row lifecycle: Done close-out upsert → both checkpoint
/// lookups hit → unchanged rewrite skips → the destructive clear
/// reports the count and both lookups miss → clear on empty = 0
/// (idempotent) → after clear the same fingerprint re-archives (the
/// "clear then re-download" premise).
#[tokio::test]
async fn media_archive_upsert_lookup_clear_lifecycle() {
    let path = tmp_db("media-archive");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");
    let row = crate::persist::MediaArchiveRow {
        url_digest: "d1".into(),
        manifest_digest: "m1".into(),
        kind: "dash".into(),
        title: Some("Big Buck Bunny".into()),
        output_name: "Big Buck Bunny.mp4".into(),
        gid: "80000000000000b1".into(),
        created_at: 1,
        updated_at: 1,
    };
    assert_eq!(
        ok(handle.upsert_media_archive(row.clone()).await, "upsert"),
        PersistOutcome::Written
    );
    // Unchanged rewrite (the observational columns excepted) skips.
    assert_eq!(
        ok(handle.upsert_media_archive(row.clone()).await, "re-upsert"),
        PersistOutcome::SkippedUnchanged
    );
    // Both checkpoint lookups hit with the full payload back (the
    // observational updated_at is writer-derived — compare the
    // payload fields, the sibling faces' discipline).
    let assert_payload = |got: &Option<crate::persist::MediaArchiveRow>,
                          want: &crate::persist::MediaArchiveRow,
                          what: &str| {
        let got = got.as_ref().unwrap_or_else(|| panic!("{what}: no row"));
        assert_eq!(got.url_digest, want.url_digest, "{what} url_digest");
        assert_eq!(
            got.manifest_digest, want.manifest_digest,
            "{what} manifest_digest"
        );
        assert_eq!(got.kind, want.kind, "{what} kind");
        assert_eq!(got.title, want.title, "{what} title");
        assert_eq!(got.output_name, want.output_name, "{what} output_name");
        assert_eq!(got.gid, want.gid, "{what} gid");
    };
    let by_url = ok(handle.load_media_archive_by_url("d1").await, "cp1");
    assert_payload(&by_url, &row, "checkpoint 1");
    let by_manifest = ok(handle.load_media_archive_by_manifest("m1").await, "cp2");
    assert_payload(&by_manifest, &row, "checkpoint 2");
    // Misses are None.
    assert!(ok(handle.load_media_archive_by_url("nope").await, "cp1 miss").is_none());
    assert!(
        ok(
            handle.load_media_archive_by_manifest("nope").await,
            "cp2 miss"
        )
        .is_none()
    );
    // A second URL archiving the SAME manifest keeps its own row
    // (the non-unique manifest compartment: two rows, one content).
    let row2 = crate::persist::MediaArchiveRow {
        url_digest: "d2".into(),
        manifest_digest: "m1".into(),
        kind: "dash".into(),
        title: None,
        output_name: "other.mp4".into(),
        gid: "80000000000000b2".into(),
        created_at: 2,
        updated_at: 2,
    };
    assert_eq!(
        ok(handle.upsert_media_archive(row2.clone()).await, "upsert 2"),
        PersistOutcome::Written
    );
    let hit = ok(
        handle.load_media_archive_by_manifest("m1").await,
        "cp2 two rows",
    );
    assert!(
        hit.is_some(),
        "the manifest compartment stays a lookup across rows"
    );
    // The destructive clear: count = both rows, then both lookups
    // miss; clearing empty = 0 (idempotent).
    assert_eq!(ok(handle.clear_media_archive().await, "clear"), 2);
    assert!(
        ok(
            handle.load_media_archive_by_url("d1").await,
            "cp1 after clear"
        )
        .is_none()
    );
    assert!(
        ok(
            handle.load_media_archive_by_manifest("m1").await,
            "cp2 after clear"
        )
        .is_none()
    );
    assert_eq!(ok(handle.clear_media_archive().await, "clear empty"), 0);
    // Re-archive after clear works (the re-download premise).
    assert_eq!(
        ok(handle.upsert_media_archive(row2).await, "re-archive"),
        PersistOutcome::Written
    );
    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer exit",
    );
    let _ = std::fs::remove_file(&path);
}

// ---- media_task upsert guard ----

/// 18-field media_task row fixture (field order mirrors the
/// write_media.rs read face); state is the caller's axis.
fn media_task_row(gid: &str, state: &str) -> MediaTaskRow {
    MediaTaskRow {
        gid: gid.into(),
        kind: "hls".into(),
        manifest_url: "http://x/m.m3u8".into(),
        state: state.into(),
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

/// The upsert guard across the whole guarded set (paused/error/
/// done — the unified vocabulary's guarded derivation,
/// `TaskPhase::guarded_words`): a stale detached live-phase
/// write landing after the row reached a guarded state is a
/// `SkippedUnchanged` and the stored row survives, and only the
/// explicit exits (the paused→queued unpause job, the error/done
/// reopen face) let the plain upsert write again.
#[tokio::test]
async fn media_task_upsert_guard_refuses_stale_phase_overwrite_of_paused() {
    let path = tmp_db("media-task-guard");
    let (handle, join) = ok(PersistWriter::spawn(path.clone()).await, "spawn");

    // `paused`: the teardown's row survives a stale `processing`
    // write (a genuinely different payload — the guard, not the
    // row-compare, is what skips); the unpause job is the exit.
    let paused_gid = "80000000000000c1";
    assert_eq!(
        ok(
            handle
                .upsert_media_task(media_task_row(paused_gid, "paused"))
                .await,
            "paused row"
        ),
        PersistOutcome::Written
    );
    let mut stale = media_task_row(paused_gid, "processing");
    stale.total_done = 4096;
    assert_eq!(
        ok(handle.upsert_media_task(stale).await, "stale over paused"),
        PersistOutcome::SkippedUnchanged
    );
    assert_eq!(
        ok(handle.load_media_task(paused_gid).await, "load paused").map(|r| r.state),
        Some("paused".into()),
        "the paused row survives the stale write"
    );
    assert_eq!(
        ok(handle.unpause_media_task(paused_gid).await, "unpause"),
        PersistOutcome::Written
    );
    assert_eq!(
        ok(
            handle
                .upsert_media_task(media_task_row(paused_gid, "processing"))
                .await,
            "write after unpause"
        ),
        PersistOutcome::Written
    );

    // `error`/`done`: same refusal, the reopen face is the exit.
    for (gid, guarded) in [("80000000000000c2", "error"), ("80000000000000c3", "done")] {
        let mut row = media_task_row(gid, guarded);
        if guarded == "error" {
            row.error_code = Some("taiji.media.staging".into());
        }
        assert_eq!(
            ok(handle.upsert_media_task(row).await, "guarded row"),
            PersistOutcome::Written,
            "the {guarded} row lands"
        );
        assert_eq!(
            ok(
                handle
                    .upsert_media_task(media_task_row(gid, "verifying"))
                    .await,
                "stale over {guarded}"
            ),
            PersistOutcome::SkippedUnchanged
        );
        assert_eq!(
            ok(handle.reopen_media_task(gid).await, "reopen"),
            PersistOutcome::Written,
            "the {guarded} row reopens"
        );
        assert_eq!(
            ok(
                handle
                    .upsert_media_task(media_task_row(gid, "processing"))
                    .await,
                "write after reopen"
            ),
            PersistOutcome::Written
        );
    }

    drop(handle);
    let _ = ok(
        tokio::time::timeout(Duration::from_secs(1), join).await,
        "writer exit",
    );
    let _ = std::fs::remove_file(&path);
}

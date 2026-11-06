// ---- Manual ban roundtrip (persist / read-back / expiry faces) +
// list kv recovery ----

/// ban_list view unwrap (the ListBans reply -> (target, reason, source,
/// until)).
fn ban_rows(r: &CmdResult) -> Vec<(String, String, &'static str, i64)> {
    match r {
        Ok(CommandReply::Bans(rows)) => rows
            .iter()
            .map(|b| {
                (
                    b.target.clone(),
                    b.reason.clone(),
                    b.source.as_str(),
                    b.until,
                )
            })
            .collect(),
        other => panic!("expected Bans reply, got {other:?}"),
    }
}

/// Ban roundtrip: a manual ban (a permanent CIDR + a timed single IP)
/// persists peer_ban rows with reason=manual and the client-ban
/// prefixes persist into session_kv -> session restart reads them back
/// (both the bookkeeping and the list faces) -> unban deletes the row
/// (it does not resurrect after restart). The default empty-list shape
/// is covered by the listBans RPC face's empty-table assertion.
#[tokio::test]
async fn manual_ban_roundtrip_survives_restart() {
    let db = tmp_db("p79-bans");
    let now = crate::session::bans::now_epoch();

    // ---- session 1: two bans + list hot update (the changeGlobalOption
    // face) ----
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let global = GlobalOptions::default();
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    // Default empty list = ban no clients (observable as an empty
    // table).
    assert!(ban_rows(&call(&handle, SessionCommand::ListBans).await).is_empty());
    for (target, minutes) in [
        ("10.66.0.0/24".to_string(), None),
        ("192.0.2.9".to_string(), Some(30)),
    ] {
        match call(&handle, SessionCommand::BanAddr { target, minutes }).await {
            Ok(CommandReply::Accepted) => {}
            other => panic!("banAddr accepted, got {other:?}"),
        }
    }
    // List hot update (changeGlobalOption client-ban-prefixes).
    let mut patch = BTreeMap::new();
    patch.insert("client-ban-prefixes".to_string(), "-XL".to_string());
    match call(
        &handle,
        SessionCommand::ChangeGlobalOption { options: patch },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("change global accepted, got {other:?}"),
    }
    let rows = ban_rows(&call(&handle, SessionCommand::ListBans).await);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        (
            "10.66.0.0/24".to_string(),
            "manual".to_string(),
            "manual",
            i64::MAX
        ),
        "permanent CIDR ban (until = i64::MAX, the RPC face renders \"0\")"
    );
    let (ip_target, _, _, timed_until) = &rows[1];
    assert_eq!(ip_target, "192.0.2.9");
    assert!(
        *timed_until > now && *timed_until <= now + 30 * 60,
        "timed until ~= now + 30min"
    );

    // ---- restart: peer_ban reason=manual read-back + kv list recovery
    // ----
    drop(handle);
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    // Deliberately do not give the list in the option initial value —
    // the kv is the cross-restart truth.
    let (handle2, join2) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer2.clone()),
    );
    match call(&handle2, SessionCommand::GetGlobalOption).await {
        Ok(CommandReply::Options(m)) => assert_eq!(
            m.get("client-ban-prefixes").map(String::as_str),
            Some("-XL"),
            "client_ban_prefixes restored via session_kv (overrides the empty initial value)"
        ),
        other => panic!("expected Options reply, got {other:?}"),
    }
    let rows = ban_rows(&call(&handle2, SessionCommand::ListBans).await);
    assert_eq!(
        rows.len(),
        2,
        "manual bans read back (peer_ban reason=manual)"
    );
    assert_eq!(rows[0].0, "10.66.0.0/24");

    // ---- unban: bookkeeping delete + row delete -> the third session
    // does not resurrect it ----
    match call(
        &handle2,
        SessionCommand::UnbanAddr {
            target: "10.66.0.0/24".to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("unban accepted, got {other:?}"),
    }
    assert_eq!(
        ban_rows(&call(&handle2, SessionCommand::ListBans).await).len(),
        1
    );
    // A repeated unban = an explicit error.
    assert!(
        call(
            &handle2,
            SessionCommand::UnbanAddr {
                target: "10.66.0.0/24".to_string(),
            },
        )
        .await
        .is_err()
    );
    drop(handle2);
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;

    let (writer3, wjoin3) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 3");
    {
        let conn = ok(rusqlite::Connection::open(&db), "open readback");
        let n: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM peer_ban WHERE reason = 'manual'",
                [],
                |r| r.get(0),
            ),
            "count manual rows",
        );
        assert_eq!(
            n, 1,
            "the unbanned row was physically deleted; only the timed single-IP row remains"
        );
    }
    let (handle3, join3) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions::default(),
        },
        Some(writer3.clone()),
    );
    let rows = ban_rows(&call(&handle3, SessionCommand::ListBans).await);
    assert_eq!(
        rows.len(),
        1,
        "unban survives a restart (the deleted row does not resurrect)"
    );
    assert_eq!(rows[0].0, "192.0.2.9");
    drop(handle3);
    let _ = tokio::time::timeout(Duration::from_secs(2), join3).await;
    drop(writer3);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin3).await;
    let _ = std::fs::remove_file(&db);
}

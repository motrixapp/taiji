// ---- selected truth projection (RPC view face; aria2 isRequested
// semantics) ----

fn files_of(r: &CmdResult) -> Vec<FileEntryView> {
    match r {
        Ok(CommandReply::Files(v)) => v.clone(),
        other => panic!("expected Files reply, got {other:?}"),
    }
}

async fn status_of(handle: &SessionHandle, gid_hex: &str) -> TorrentStatusView {
    match call(
        handle,
        SessionCommand::TellStatus {
            gid: gid_hex.into(),
            keys: Vec::new(),
        },
    )
    .await
    {
        Ok(CommandReply::TorrentStatus(v)) => *v,
        other => panic!("expected TorrentStatus reply, got {other:?}"),
    }
}

/// Multi-file v1 metainfo (3 real files + 1 BEP47 pad entry,
/// piece-aligned; pieces = real SHA-1 over the concatenated stream —
/// the pad segment counts as zero bytes per BEP47).
/// Synthetic fixture (in-process deterministic content; not a real
/// client sample).
fn multi_file_v1_torrent_with_pad(announce: &str, name: &str) -> Vec<u8> {
    use sha1::{Digest as _, Sha1 as _Sha1};
    const P: usize = 16384;
    let part = |seed: u8| -> Vec<u8> { (0..P).map(|i| (i as u8).wrapping_add(seed)).collect() };
    let mut stream = part(0x10);
    stream.extend(std::iter::repeat_n(0u8, P));
    stream.extend(part(0x20));
    stream.extend(part(0x30));
    let mut pieces = Vec::new();
    for c in stream.chunks(P) {
        pieces.extend_from_slice(&_Sha1::digest(c));
    }
    let file_entry = |comp0: &[u8], comp1: Option<&[u8]>, len: u64, attr: Option<&[u8]>| -> Value {
        let mut path = vec![Value::Bytes(comp0.to_vec())];
        if let Some(c1) = comp1 {
            path.push(Value::Bytes(c1.to_vec()));
        }
        // dict keys in byte order: "attr" < "length" < "path".
        let mut d: Vec<(Vec<u8>, Value)> = Vec::new();
        if let Some(a) = attr {
            d.push((b"attr".to_vec(), Value::Bytes(a.to_vec())));
        }
        d.push((b"length".to_vec(), Value::Int(len as i64)));
        d.push((b"path".to_vec(), Value::List(path)));
        Value::Dict(d.into_iter().collect())
    };
    let info = Value::Dict(
        vec![
            (
                b"files".to_vec(),
                Value::List(vec![
                    file_entry(b"part0.bin", None, P as u64, None),
                    // BEP47 pad: path [".pad", "N"], attr "p".
                    file_entry(b".pad", Some(b"16384"), P as u64, Some(b"p")),
                    file_entry(b"part1.bin", None, P as u64, None),
                    file_entry(b"part2.bin", None, P as u64, None),
                ]),
            ),
            (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
            (b"piece length".to_vec(), Value::Int(P as i64)),
            (b"pieces".to_vec(), Value::Bytes(pieces)),
        ]
        .into_iter()
        .collect(),
    );
    let top = Value::Dict(
        vec![
            (
                b"announce".to_vec(),
                Value::Bytes(announce.as_bytes().to_vec()),
            ),
            (b"info".to_vec(), info),
        ]
        .into_iter()
        .collect(),
    );
    bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"))
}

/// Single-source projection matrix (data-face proof): the BEP53 index
/// is 0-based over non-pad entries (pads are not counted); None =
/// select all (pad placeholders are true along with everything else);
/// a selection-input change is reflected in the view output
/// immediately (single-source read, no cache layer).
#[test]
fn file_views_project_selection_surface_with_pad_not_counted() {
    use crate::metainfo::MetaFile;
    let mk = |path: &str, padding: bool| MetaFile {
        path: PathBuf::from(path),
        length: 16384,
        padding,
        pieces_root: None,
        piece_layer: None,
        v1_offset: None,
    };
    let meta = TorrentMeta {
        identity: TorrentIdentity { v1: None, v2: None },
        kind: taiji_bt::filetree::SwarmKind::V1Only,
        piece_length: 16384,
        files: vec![
            mk("part0.bin", false),
            mk(".pad/16384", true),
            mk("part1.bin", false),
            mk("part2.bin", false),
        ],
    };
    let sel_of = |selection: Option<&[u32]>| -> Vec<bool> {
        file_views(&meta, None, selection, None)
            .iter()
            .map(|f| f.selected)
            .collect()
    };
    // The index field = 1-based order over all files (pads included;
    // existing convention unchanged).
    let index: Vec<u64> = file_views(&meta, None, None, None)
        .iter()
        .map(|f| f.index)
        .collect();
    assert_eq!(index, vec![1, 2, 3, 4]);
    // None = select all.
    assert_eq!(sel_of(None), vec![true, true, true, true]);
    // Some([0, 2]): the client list is part0(0)/part1(1)/part2(2); the
    // pad entry is not in the list -> false.
    assert_eq!(sel_of(Some(&[0, 2])), vec![true, false, false, true]);
    // Some([1]): part1 only.
    assert_eq!(sel_of(Some(&[1])), vec![false, false, true, false]);
    // Data-face changes are reflected immediately (same meta, different
    // selection -> output follows).
    assert_ne!(sel_of(Some(&[0, 2])), sel_of(Some(&[1])));
}

/// Full-shape assembly of a restored row (torrent_row +
/// fill_torrent_identity + the file row set — isomorphic to the
/// production write face; the test writes rows directly to simulate
/// the eve of a restart).
fn seeded_row(
    hex: &str,
    bytes: &[u8],
    cfg: &PersistedTaskConfig,
    pos: i64,
) -> (StoreTorrentRow, Vec<TorrentFileRow>) {
    let meta = Metainfo::parse(bytes).unwrap_or_else(|e| panic!("fixture parse: {e}"));
    let mut row = super::super::persist::torrent_row(
        hex,
        taiji_store::persist::TaskPhase::Paused,
        pos,
        &derive_name(&meta.meta),
        cfg,
    );
    super::super::persist::fill_torrent_identity(&mut row, &meta, bytes.to_vec());
    (row, file_rows(hex, &meta.meta.files))
}

/// selected truth projection end-to-end: waiting (restored rows ->
/// jobs cfg) / live (activated task) / stopped (forceRemove result
/// entry snapshot) all project from the same source + the so= upgrade
/// product row shape (magnet_uri `so=` and config_json.selected_files
/// share one source, reused by the recovery channel) + a select-all
/// control; after a data-face rewrite (injecting selected_files into
/// config_json) the view follows after a restart.
#[tokio::test]
async fn selected_truth_projection_waiting_live_stopped_and_restore() {
    let db = tmp_db("selected-proj");
    let dir = temp_dir("selected-proj");

    // ---- eve of restart: three rows written directly to the store
    // (full metadata BLOB -> the recovery face rebuilds TorrentJob via
    // Rebuilt::Torrent, selected_files lands in the payload) ----
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let bytes_a = multi_file_v1_torrent_with_pad(&dead_tracker(), "sel-a");
    let bytes_b = multi_file_v1_torrent_with_pad(&dead_tracker(), "sel-b");
    let bytes_c = multi_file_v1_torrent_with_pad(&dead_tracker(), "sel-c");
    let cfg_base = || PersistedTaskConfig {
        magnet_flags: None,
        dir: dir.display().to_string(),
        ..PersistedTaskConfig::default()
    };
    // Construct cfg.selected_files = Some(..) directly (partial
    // selection).
    let cfg_a = PersistedTaskConfig {
        magnet_flags: None,
        selected_files: Some(vec![0, 2]),
        file_priorities: None,
        ..cfg_base()
    };
    // so= upgrade product row shape (the job_config(MagnetJob) write
    // face: magnet_uri and selected_files are exported from one source
    // via magnet_selected_files — a single recovery-channel truth).
    let btih_b = Metainfo::parse(&bytes_b)
        .unwrap_or_else(|e| panic!("{e}"))
        .meta
        .identity
        .v1
        .map(|h| h.iter().map(|b| format!("{b:02x}")).collect::<String>())
        .unwrap_or_default();
    let uri_b = format!("magnet:?xt=urn:btih:{btih_b}&so=1");
    let sel_b = magnet_selected_files(&uri_b);
    assert_eq!(
        sel_b,
        Some(vec![1]),
        "the so= parse channel's single-source anchor"
    );
    let cfg_b = PersistedTaskConfig {
        magnet_flags: None,
        magnet_uri: Some(uri_b),
        selected_files: sel_b,
        file_priorities: None,
        ..cfg_base()
    };
    // Select-all control (no selected_files bytes).
    let cfg_c = cfg_base();
    for (hex, bytes, cfg, pos) in [
        ("80000000000000a1", &bytes_a, &cfg_a, 1i64),
        ("80000000000000a2", &bytes_b, &cfg_b, 2),
        ("80000000000000a3", &bytes_c, &cfg_c, 3),
    ] {
        let (row, files) = seeded_row(hex, bytes, cfg, pos);
        ok(writer.upsert_torrent(row, files).await, "seed row");
    }
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;

    // ---- session 2: bootstrap recovery -> waiting-face projection ----
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer2.clone()));
    let mut restored = 0;
    for _ in 0..100 {
        let waiting = status_list(
            &call(
                &handle,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        restored = waiting.len();
        if restored == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        restored, 3,
        "all three rows must be restored as waiting tasks"
    );
    let selected_vec = async |hex: &str| -> Vec<bool> {
        files_of(&call(&handle, SessionCommand::GetFiles { gid: hex.into() }).await)
            .iter()
            .map(|f| f.selected)
            .collect()
    };
    // A (direct Some([0,2])): the 1-based index includes the pad;
    // selected = the client-list projection over non-pad files (pads
    // are not counted).
    let files_a = files_of(
        &call(
            &handle,
            SessionCommand::GetFiles {
                gid: "80000000000000a1".into(),
            },
        )
        .await,
    );
    assert_eq!(
        files_a.iter().map(|f| f.index).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(
        files_a.iter().map(|f| f.padding).collect::<Vec<_>>(),
        vec![false, true, false, false]
    );
    assert_eq!(
        files_a.iter().map(|f| f.selected).collect::<Vec<_>>(),
        vec![true, false, false, true]
    );
    // tellStatus and getFiles project from the same source.
    let st = status_of(&handle, "80000000000000a1").await;
    assert_eq!(
        st.files.iter().map(|f| f.selected).collect::<Vec<_>>(),
        vec![true, false, false, true]
    );
    // B (so= upgrade product row): part1 only.
    assert_eq!(
        selected_vec("80000000000000a2").await,
        vec![false, false, true, false]
    );
    // C (select-all control): None = all true (pad placeholders follow
    // the select-all face).
    assert_eq!(
        selected_vec("80000000000000a3").await,
        vec![true, true, true, true]
    );

    // ---- live face: unpause activates (the dead tracker still lets
    // the engine run); the view reads jobs cfg -> projection unchanged ----
    assert_eq!(
        call(
            &handle,
            SessionCommand::Unpause {
                gid: "80000000000000a1".into()
            }
        )
        .await,
        Ok(CommandReply::Gid(Gid::from_u64(0x8000_0000_0000_00a1)))
    );
    let mut live = false;
    for _ in 0..150 {
        let active =
            status_list(&call(&handle, SessionCommand::TellActive { keys: Vec::new() }).await);
        if active
            .iter()
            .any(|v| v.gid.to_string() == "80000000000000a1")
        {
            live = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(live, "the task activates after unpause");
    assert_eq!(
        selected_vec("80000000000000a1").await,
        vec![true, false, false, true],
        "the live face's selected projection"
    );

    // ---- stopped face: forceRemove -> Removed result entry (jobs are
    // still present at teardown -> build_result_entry projects from the
    // same source) ----
    assert_eq!(
        call(
            &handle,
            SessionCommand::ForceRemove {
                gid: "80000000000000a1".into()
            }
        )
        .await,
        Ok(CommandReply::Gid(Gid::from_u64(0x8000_0000_0000_00a1)))
    );
    let mut stopped_sel: Option<Vec<bool>> = None;
    for _ in 0..100 {
        let stopped = status_list(
            &call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        if let Some(v) = stopped
            .iter()
            .find(|v| v.gid.to_string() == "80000000000000a1")
        {
            stopped_sel = Some(v.files.iter().map(|f| f.selected).collect());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        stopped_sel,
        Some(vec![true, false, false, true]),
        "the result entry's selected projection"
    );

    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;

    // ---- data-face change (rewrite the row's config_json directly to
    // inject selected_files — this branch has no select-file option
    // entry, so the data face is authoritative) -> the session-3 view
    // follows after restart and matches the persistence ----
    {
        let conn = ok(rusqlite::Connection::open(&db), "open for cfg rewrite");
        let cfg_c2 = PersistedTaskConfig {
            magnet_flags: None,
            selected_files: Some(vec![2]),
            file_priorities: None,
            ..cfg_base()
        };
        ok(
            conn.execute(
                "UPDATE torrent SET config_json = ?1 WHERE gid = '80000000000000a3'",
                params![cfg_c2.to_json()],
            ),
            "rewrite cfg",
        );
    }
    let (writer3, wjoin3) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 3");
    let (handle3, join3) = SessionActor::spawn_with_persist(
        SessionOptions {
            global: GlobalOptions {
                dir: dir.clone(),
                ..Default::default()
            },
        },
        Some(writer3.clone()),
    );
    let mut restored3 = 0;
    for _ in 0..100 {
        let waiting = status_list(
            &call(
                &handle3,
                SessionCommand::TellWaiting {
                    offset: 0,
                    num: u32::MAX,
                    keys: Vec::new(),
                },
            )
            .await,
        );
        restored3 = waiting
            .iter()
            .filter(|v| v.status == StatusKind::Paused)
            .count();
        if restored3 == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(restored3, 2, "A was removed; B/C restored as paused");
    let sel3 = async |hex: &str| -> Vec<bool> {
        files_of(&call(&handle3, SessionCommand::GetFiles { gid: hex.into() }).await)
            .iter()
            .map(|f| f.selected)
            .collect()
    };
    assert_eq!(
        sel3("80000000000000a2").await,
        vec![false, false, true, false],
        "the so= selection stays consistent across restart"
    );
    assert_eq!(
        sel3("80000000000000a3").await,
        vec![false, false, false, true],
        "the view follows the data-face change"
    );
    handle3.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join3).await;
    drop(writer3);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin3).await;
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&db);
}

// ---- select-file ----

/// v1 multi-file metainfo containing a BEP47 pad (synthetic fixture,
/// assembled in-process): `a.bin` (piece 0) + `.pad/16384` (piece 1,
/// attr `p`) + `b.bin` (piece 2), piece-aligned; the client file list
/// (non-pad) = 2 entries. Varying `seed` varies the content ->
/// independent infohashes (each negative-vector iteration is a fresh
/// add that must not trip the duplicate check).
fn padded_v1_torrent(announce: &str, seed: u8) -> Vec<u8> {
    use sha1::{Digest as _, Sha1 as _Sha1};
    const P: usize = 16 * 1024;
    let a = (0..P)
        .map(|i| ((i % 251) + seed as usize) as u8)
        .collect::<Vec<u8>>();
    let b = (0..P)
        .map(|i| ((i % 199) + seed as usize) as u8)
        .collect::<Vec<u8>>();
    let pad = vec![0u8; P];
    let mut pieces = Vec::new();
    for part in [&a, &pad, &b] {
        pieces.extend_from_slice(&_Sha1::digest(part));
    }
    let file = |path: Vec<&[u8]>, length: usize, attr: Option<&str>| {
        // bencode dict keys in strictly ascending order:
        // attr < length < path.
        let mut e = Vec::new();
        if let Some(attr) = attr {
            e.push((b"attr".to_vec(), Value::Bytes(attr.as_bytes().to_vec())));
        }
        e.push((b"length".to_vec(), Value::Int(length as i64)));
        e.push((
            b"path".to_vec(),
            Value::List(path.iter().map(|c| Value::Bytes(c.to_vec())).collect()),
        ));
        Value::Dict(e.into_iter().collect())
    };
    let info = Value::Dict(
        vec![
            (
                b"files".to_vec(),
                Value::List(vec![
                    file(vec![b"a.bin"], P, None),
                    file(vec![b".pad", b"16384"], P, Some("p")),
                    file(vec![b"b.bin"], P, None),
                ]),
            ),
            (b"name".to_vec(), Value::Bytes(b"p100-pad-pkg".to_vec())),
            (b"piece length".to_vec(), Value::Int(P as i64)),
            (b"pieces".to_vec(), Value::Bytes(pieces)),
        ]
        .into_iter()
        .collect(),
    );
    let top = Value::Dict(
        vec![
            (
                b"announce".to_vec(),
                Value::Bytes(announce.as_bytes().to_vec()),
            ),
            (b"info".to_vec(), info),
        ]
        .into_iter()
        .collect(),
    );
    bencode::encode(&top).unwrap_or_else(|e| panic!("{e}"))
}

/// Pad-anchor e2e + the addTorrent acceptance face: the non-pad file
/// count anchors the selection-face range
/// (BEP53 client file list convention — BEP47 pad placeholder entries
/// are not counted); a valid value persists in the row's config_json
/// (0-based); the negative vector (out-of-range/zero/unordered
/// included) is rejected wholesale at add time and no row is written.
#[tokio::test]
async fn add_torrent_select_file_pads_do_not_count_and_negatives_reject() {
    let db = tmp_db("p100-pad");
    let dir = temp_dir("p100-pad");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let bytes = padded_v1_torrent(&dead_tracker(), 0);
    let opts = |sel: &str| {
        BTreeMap::from([
            ("dir".to_string(), dir.display().to_string()),
            ("pause".to_string(), "true".to_string()),
            ("select-file".to_string(), sel.to_string()),
        ])
    };
    // Positive case: 1-based "2" -> 0-based [1] (= b.bin, the second
    // client-list entry).
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes.clone(),
                options: opts("2"),
                position: None,
            },
        )
        .await,
    );
    let cfg_json = read_config_json(&db, &gid);
    assert!(
        cfg_json.contains("\"selected_files\":[1]"),
        "1-based to 0-based conversion lands in config_json: {cfg_json}"
    );
    // Pad anchor: the client file count = 2 (a.bin/b.bin; the .pad
    // entry is not counted) — 1-based "3" points at the pad placeholder
    // -> out-of-range rejection; the rest of the negative vector is
    // rejected the same way; a rejected add fails wholesale and writes
    // no row (acceptance that takes no effect would be a disguise;
    // each case uses an independent seed -> independent infohash, so
    // the duplicate check does not intercept first).
    for (i, bad_sel) in ["3", "0", "2,1", "1-2,2", "", "5-3"].iter().enumerate() {
        let torrent = padded_v1_torrent(&dead_tracker(), (i + 1) as u8);
        let before = count_rows(&db);
        match call(
            &handle,
            SessionCommand::AddTorrent {
                torrent,
                options: opts(bad_sel),
                position: None,
            },
        )
        .await
        {
            Err(SessionError::Failed { message }) => {
                assert!(message.contains("taiji.option.invalid"), "{message}");
            }
            other => panic!("select-file {bad_sel:?} must reject, got {other:?}"),
        }
        assert_eq!(
            count_rows(&db),
            before,
            "a rejected add must not write a row"
        );
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_file(&db);
}

/// magnet `so=` together with `select-file` = explicit
/// conflict rejection (a single selection-face source; the error
/// message names both source keys); select-file alone -> the 0-based
/// selection face lands in config_json (the same persistence channel
/// as so=); the existing so= path is regression-locked.
#[tokio::test]
async fn add_uri_magnet_select_file_persists_and_conflicts_with_so() {
    let db = tmp_db("p100-soconf");
    let dir = temp_dir("p100-soconf");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let base = "magnet:?xt=urn:btih:2222222222222222222222222222222222222222\
                    &dn=p100&tr=http%3A%2F%2F127.0.0.1%3A1%2Fann";
    // select-file alone: 1-based "1,3" -> 0-based [0,2] into
    // config_json.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![base.to_string()],
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1,3".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let cfg_json = read_config_json(&db, &gid);
    assert!(
        cfg_json.contains("\"selected_files\":[0,2]"),
        "select-file lands 0-based into config_json: {cfg_json}"
    );
    // Existing so= path regression: without select-file, so= projects
    // as before (independent btih, distinct identity from the first
    // task).
    let so_uri = "magnet:?xt=urn:btih:4444444444444444444444444444444444444444\
                     &dn=p100so&tr=http%3A%2F%2F127.0.0.1%3A1%2Fann&so=0";
    let gid_so = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![so_uri.to_string()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let cfg_so = read_config_json(&db, &gid_so);
    assert!(cfg_so.contains("\"selected_files\":[0]"), "{cfg_so}");
    // Coexistence = explicit conflict rejection (the error message
    // contains both source key names).
    match call(
        &handle,
        SessionCommand::AddUri {
            uris: vec![so_uri.to_string()],
            options: BTreeMap::from([("select-file".to_string(), "1".to_string())]),
            position: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.contains("so=") && message.contains("select-file"),
                "{message}"
            );
        }
        other => panic!("so= + select-file must conflict-reject, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_file(&db);
}

/// addUri `.torrent` URL task select-file execution face: add accepts
/// (single 1-based syntax parse point) -> the selection face lands in
/// the row's config_json (0-based, the same persistence channel as
/// magnet/addTorrent) -> getOption echoes the canonical 1-based string
/// (task_option_echo's TorrentUrl arm); invalid syntax = the add is
/// explicitly rejected wholesale (no row written). Metadata not yet
/// fetched -> range validation is deferred to the upgrade chain (same
/// convention as the magnet arm).
#[tokio::test]
async fn add_uri_torrent_url_select_file_persists_and_echoes() {
    let db = tmp_db("url-self");
    let dir = temp_dir("url-self");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    // Add acceptance: select-file "1,3" -> 0-based [0,2] persisted with
    // config_json.
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:9/meta.torrent".to_string()],
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1,3".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    let cfg_json = read_config_json(&db, &gid);
    assert!(
        cfg_json.contains("\"selected_files\":[0,2]"),
        "a URL task's select-file lands 0-based into config_json: {cfg_json}"
    );
    // getOption echo (TorrentUrl arm): canonical 1-based comma string.
    match call(
        &handle,
        SessionCommand::GetOption {
            gid: gid.to_string(),
        },
    )
    .await
    {
        Ok(CommandReply::Options(m)) => {
            assert_eq!(m.get("select-file").map(String::as_str), Some("1,3"));
        }
        other => panic!("getOption on URL task must echo, got {other:?}"),
    }
    // Invalid syntax = the add is rejected wholesale (no row written —
    // acceptance that takes no effect would be a disguise).
    match call(
        &handle,
        SessionCommand::AddUri {
            uris: vec!["http://127.0.0.1:9/bad.torrent".to_string()],
            options: BTreeMap::from([("select-file".to_string(), "1,,3".to_string())]),
            position: None,
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.contains("select-file"),
                "an invalid select-file must be explicitly rejected: {message}"
            );
        }
        other => panic!("invalid select-file must reject add, got {other:?}"),
    }
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_dir_all(&dir);
}

/// changeOption takes effect on reserved (recompute the
/// selection -> persist to config_json) + explicit rejection on Active +
/// restart-recovery roundtrip (config_json survives, the task
/// returns to the waiting queue) + rejection for non-BT tasks + magnet
/// so= conflict rejection.
#[tokio::test]
async fn change_option_select_file_reserved_active_and_restart_roundtrip() {
    let db = tmp_db("p100-chg");
    let dir = temp_dir("p100-chg");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let bytes = build_v2_torrent(&vec![0xCu8; 128 * 1024], &dead_tracker());
    // paused add -> ReservedPaused (the aria2 reserved-change
    // acceptance face).
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: bytes.clone(),
                options: BTreeMap::from([
                    ("pause".to_string(), "true".to_string()),
                    ("select-file".to_string(), "1".to_string()),
                ]),
                position: None,
            },
        )
        .await,
    );
    // Reserved acceptance: reselect "1" (the only file) -> Ok,
    // config_json synced.
    assert_eq!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: gid.to_string(),
                options: BTreeMap::from([("select-file".to_string(), "1".to_string())]),
            }
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    let cfg_json = read_config_json(&db, &gid);
    assert!(cfg_json.contains("\"selected_files\":[0]"), "{cfg_json}");
    // Out of range (single-file torrent, "2" is out of bounds) =
    // explicit rejection.
    match call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: BTreeMap::from([("select-file".to_string(), "2".to_string())]),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("out of range (1 files"), "{message}");
        }
        other => panic!("out-of-range select-file must reject, got {other:?}"),
    }
    // Non-BT task (.torrent URL metadata task) = explicit rejection
    // (acceptance that takes no effect would be a disguise).
    let url_gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec!["http://127.0.0.1:1/x.torrent".to_string()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::ChangeOption {
            gid: url_gid.to_string(),
            options: BTreeMap::from([("select-file".to_string(), "1".to_string())]),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(message.contains("BitTorrent tasks only"), "{message}");
        }
        other => panic!("non-BT select-file must reject, got {other:?}"),
    }
    // Magnet task reserved acceptance (metadata unknown -> syntax check
    // only) + so= conflict.
    let magnet = "magnet:?xt=urn:btih:3333333333333333333333333333333333333333\
                      &tr=http%3A%2F%2F127.0.0.1%3A1%2Fann";
    let m_gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![magnet.to_string()],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    assert_eq!(
        call(
            &handle,
            SessionCommand::ChangeOption {
                gid: m_gid.to_string(),
                options: BTreeMap::from([("select-file".to_string(), "1-2".to_string())]),
            }
        )
        .await,
        Ok(CommandReply::Accepted)
    );
    let m_cfg = read_config_json(&db, &m_gid);
    assert!(m_cfg.contains("\"selected_files\":[0,1]"), "{m_cfg}");
    // Magnet with so= + changeOption select-file = conflict rejection
    // (independent btih).
    let so_m_gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddUri {
                uris: vec![
                    "magnet:?xt=urn:btih:5555555555555555555555555555555555555555\
                         &tr=http%3A%2F%2F127.0.0.1%3A1%2Fann&so=1"
                        .to_string(),
                ],
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    match call(
        &handle,
        SessionCommand::ChangeOption {
            gid: so_m_gid.to_string(),
            options: BTreeMap::from([("select-file".to_string(), "2".to_string())]),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.contains("so=") && message.contains("select-file"),
                "{message}"
            );
        }
        other => panic!("magnet so= + changeOption select-file must reject, got {other:?}"),
    }
    // Explicit rejection on Active: unpause -> wait for activation ->
    // changeOption rejected -> teardown.
    assert_eq!(
        call(
            &handle,
            SessionCommand::Unpause {
                gid: gid.to_string()
            }
        )
        .await,
        Ok(CommandReply::Gid(gid))
    );
    let mut active = false;
    for _ in 0..200 {
        let list =
            status_list(&call(&handle, SessionCommand::TellActive { keys: Vec::new() }).await);
        if list.iter().any(|v| v.gid == gid) {
            active = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        active,
        "the task must reach Active (the dead-tracker engine still resides)"
    );
    match call(
        &handle,
        SessionCommand::ChangeOption {
            gid: gid.to_string(),
            options: BTreeMap::from([("select-file".to_string(), "1".to_string())]),
        },
    )
    .await
    {
        Err(SessionError::Failed { message }) => {
            assert!(
                message.contains("not changeable") && message.contains("active"),
                "{message}"
            );
        }
        other => panic!("active select-file must reject, got {other:?}"),
    }
    let _ = call(
        &handle,
        SessionCommand::Pause {
            gid: gid.to_string(),
        },
    )
    .await;
    // Restart-recovery roundtrip: the config_json selection face
    // survives and the task returns to the waiting queue.
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer2.clone()));
    let waiting = status_list(
        &call(
            &handle2,
            SessionCommand::TellWaiting {
                keys: Vec::new(),
                offset: 0,
                num: 100,
            },
        )
        .await,
    );
    assert!(
        waiting.iter().any(|v| v.gid == gid),
        "after restart the task must return to the waiting queue (paused)"
    );
    let cfg_after = read_config_json(&db, &gid);
    assert!(
        cfg_after.contains("\"selected_files\":[0]"),
        "the selection face persists after restart: {cfg_after}"
    );
    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_file(&db);
}

/// Replay evidence: a restored row carries an
/// out-of-range selection face (synthetic row — config_json
/// selected_files [99], single-file torrent) -> on restart activation,
/// SetFileSelection is rejected by the engine -> the task fails
/// explicitly ("out of range"). Proves the re-activation path really
/// does replay the selection face (the activation chain consumes
/// tj.selected_files).
#[tokio::test]
async fn restored_selection_replays_set_file_selection_on_activation() {
    let db = tmp_db("p100-replay");
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer");
    let bytes = build_v2_torrent(&vec![0xDu8; 128 * 1024], &dead_tracker());
    let cfg_json = format!(
        "{{\"dir\":{:?},\"selected_files\":[99]}}",
        std::env::temp_dir().display().to_string()
    );
    let row = StoreTorrentRow {
        gid: "80000000000000c1".into(),
        name: "p100-replay".into(),
        state: "queued".into(),
        queue_pos: 1,
        dir: std::env::temp_dir().display().to_string(),
        config_json: cfg_json,
        kind: "v2".into(),
        v1_infohash: None,
        v2_infohash: None,
        is_private: false,
        metadata: Some(bytes),
        error_code: None,
        error_msg: None,
        created_at: 0,
        updated_at: 0,
    };
    assert_eq!(
        ok(writer.upsert_torrent(row, Vec::new()).await, "row"),
        taiji_store::persist::PersistOutcome::Written
    );
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    // Restart: bootstrap rebuilds (selected_files [99] backfills the
    // TorrentJob) -> activation -> SetFileSelection rejected by the
    // engine -> the task enters the result table (Error). The assertion
    // face is the tellStopped result table (rejection during activation
    // = the task retires into a DownloadResult — aria2 task-error
    // semantics; the row state column staying untouched is the existing
    // shape of this path; this test anchors "the replay really happened
    // and was rejected by the engine").
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions::default(), Some(writer2.clone()));
    let mut errored = false;
    for _ in 0..300 {
        let stopped = status_list(
            &call(
                &handle,
                SessionCommand::TellStopped {
                    offset: 0,
                    num: u32::MAX,
                    keys: vec![],
                },
            )
            .await,
        );
        if let Some(v) = stopped
            .iter()
            .find(|v| v.gid.to_string() == "80000000000000c1")
        {
            assert_eq!(
                v.status,
                StatusKind::Error,
                "an out-of-range selection face must fail activation explicitly (the replay evidence)"
            );
            errored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        errored,
        "the task must retire into the result table (Error) — see the log above"
    );
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_file(&db);
}

/// e2e: taiji.setFilePriority gating + the -1 <=> selected interlock +
/// GetFiles echo + config_json roundtrip across restart (the row
/// projection columns follow the row).
#[tokio::test]
async fn file_priority_set_interlock_and_config_roundtrip() {
    let db = tmp_db("s03-prio");
    let dir = temp_dir("s03-prio");
    let builtin = dead_tracker();
    // ---- session 1: paused multi-file task (3 real files + 1 pad) ----
    let (writer, wjoin) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 1");
    let global = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle, join) =
        SessionActor::spawn_with_persist(SessionOptions { global }, Some(writer.clone()));
    let gid = gid_of(
        &call(
            &handle,
            SessionCommand::AddTorrent {
                torrent: multi_file_v1_torrent_with_pad(&builtin, "s03-prio"),
                options: BTreeMap::from([("pause".to_string(), "true".to_string())]),
                position: None,
            },
        )
        .await,
    );
    let g = gid.to_string();

    // Acceptance: partial update pairs (1-based indices — the
    // getFiles/select-file convention).
    match call(
        &handle,
        SessionCommand::SetFilePriority {
            gid: g.clone(),
            pairs: vec![(1, 7)],
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("set (1,7) must be accepted, got {other:?}"),
    }
    // GetFiles echo: 1-based index 1 -> real file 0 (files[0])
    // priority 7; under an explicit selection face the pad entry
    // (files[1]) is always selected=false (existing truth table).
    let files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(files.len(), 4, "3 real files + 1 pad entry");
    let prio: Vec<i8> = files.iter().map(|f| f.priority).collect();
    assert_eq!(
        prio,
        vec![7, 0, 0, 0],
        "index 1 -> real file 0 promoted to 7"
    );
    assert!(
        files[0].selected && files[2].selected && files[3].selected,
        "no -1 = all real files selected (the pad face is always false)"
    );

    // Interlock: index 2 set to -1 -> GetFiles shows selected=false and
    // priority=-1 for that file.
    match call(
        &handle,
        SessionCommand::SetFilePriority {
            gid: g.clone(),
            pairs: vec![(2, -1)],
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("set (2,-1) must be accepted, got {other:?}"),
    }
    let files = files_of(&call(&handle, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(
        files[2].priority, -1,
        "index 2 -> real file 1 (files[2]) set to -1"
    );
    assert!(!files[2].selected, "-1 <=> removed from the selection set");
    assert!(
        files[0].selected && files[3].selected,
        "the remaining real files stay selected"
    );

    // Rejection face (four arms): out-of-range index / level outside
    // the domain / duplicate index / all -1 (empty selection).
    for (pairs, tag) in [
        (vec![(4u32, 1i8)], "out-of-range index"),
        (vec![(1, 8)], "level outside the domain"),
        (vec![(1, 1), (1, 2)], "duplicate index"),
        (vec![(1, -1), (2, -1), (3, -1)], "all skip"),
    ] {
        match call(
            &handle,
            SessionCommand::SetFilePriority {
                gid: g.clone(),
                pairs,
            },
        )
        .await
        {
            Err(SessionError::Failed { .. }) => {}
            other => panic!("{tag} must be rejected, got {other:?}"),
        }
    }

    // ---- session 2: restart -> config_json recovery (priority and the
    // interlock projection survive) ----
    handle.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin).await;
    let (writer2, wjoin2) = ok(PersistWriter::spawn(db.clone()).await, "spawn writer 2");
    let global2 = GlobalOptions {
        dir: dir.clone(),
        ..Default::default()
    };
    let (handle2, join2) =
        SessionActor::spawn_with_persist(SessionOptions { global: global2 }, Some(writer2.clone()));
    let files = files_of(&call(&handle2, SessionCommand::GetFiles { gid: g.clone() }).await);
    let prio: Vec<i8> = files.iter().map(|f| f.priority).collect();
    assert_eq!(
        prio,
        vec![7, 0, -1, 0],
        "the priority face persists after restart"
    );
    assert!(
        !files[2].selected,
        "the interlock projection persists after restart"
    );
    // Reset arm: index 2 back to 0 -> rejoins the selection set
    // (restoring the remove/rejoin symmetry).
    match call(
        &handle2,
        SessionCommand::SetFilePriority {
            gid: g.clone(),
            pairs: vec![(2, 0)],
        },
    )
    .await
    {
        Ok(CommandReply::Accepted) => {}
        other => panic!("set (2,0) must be accepted, got {other:?}"),
    }
    let files = files_of(&call(&handle2, SessionCommand::GetFiles { gid: g.clone() }).await);
    assert_eq!(files[2].priority, 0, "reset to 0");
    assert!(
        files[2].selected,
        "0..7 <=> rejoined into the selection set"
    );

    handle2.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(2), join2).await;
    drop(writer2);
    let _ = tokio::time::timeout(Duration::from_secs(2), wjoin2).await;
    let _ = std::fs::remove_file(&db);
}
